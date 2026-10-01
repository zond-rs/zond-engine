// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What every raw port scan does the same way
//!
//! A raw port scan is the same machine whatever protocol it speaks: send probes
//! from one source port as fast as pacing allows, correlate what comes back,
//! resend what goes unanswered until its budget runs out, and stop when one of
//! four conditions holds. Only the packets and what they prove differ.
//!
//! `RawProbeScan` is the state a raw port scan carries and the questions it can
//! answer about itself. `drive` is the loop that asks them, and `RawPortScan` is
//! the short list of things the loop cannot work out alone: which protocol to
//! accept, what silence means, and two labels.
//!
//! [`tcp`], [`udp`] and [`sctp`] each hold a `RawProbeScan` and implement
//! `RawPortScan`, keeping only protocol knowledge: how a probe is built, how a
//! reply is recognised, what an answer proves about a port and its host, and
//! what silence means once a probe has spent its budget. [`idle`] is built
//! differently, because it reads its verdicts off a third party's counter.
//!
//! The shared half holds the four stop conditions, the subtlest code in any of
//! the scanners. Stopping on the wrong one does not fail; it returns a smaller
//! answer that looks like a quiet network, so there is one copy.
//!
//! The machine is crate-private: its state is the retry ledger, the adaptive
//! deadline and the congestion window, and publishing it would freeze each of
//! them. A scanner written outside the crate implements [`PortScanner`].

// Public as well as re-exported, because each file's module docs say what
// that protocol's probes prove.
pub mod idle;
pub mod sctp;
pub mod tcp;
pub mod udp;

pub use idle::IdlePortScanner;
pub use sctp::SctpPortScanner;
pub use tcp::TcpPortScanner;
pub use udp::UdpPortScanner;

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::config::ProbeTuning;
use crate::evasion::SegmentShaping;
use crate::journal::settle::Outcome;
use crate::model::host::{HostStatus, StatusProtocol, StatusReason};
use crate::model::port::{PortState, Protocol};
use crate::model::target::PlannedTarget;
use crate::report::ScannerKind;
use crate::report::StopReason;
use crate::scanner::audit::{Pacing, ProbeAudit};
use crate::scanner::pacing::congestion::{CongestionWindow, WindowLimits};
use crate::scanner::pacing::deadline::HeldAllowance;
use crate::scanner::pacing::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::scanner::pacing::retry::{
    Due, ProbeLedger, Resolution, RetryPolicy, SilentHostPolicy, saturating_mul,
};
use crate::scanner::session::{ProbeClaim, ScanContext};
use crate::scanner::strategy::raw::neighbors::{
    Admission, HoldDowns, NEIGHBOR_RECHECK, NeighborGates, RESOLUTION_BUDGET,
};
use crate::scanner::strategy::{PortScanner, StrategyError};
use crate::system::interface::{NoSource, SourceResolver};
use crate::transport::capture::CapturedSegment;
use crate::transport::kernel_neighbors::NeighborState;
use crate::transport::probe::{Emission, ProbeTransport, SendError};
use crate::{info, warn};

// ---------------------------------------------------------------------------
// What a raw port scan is paced and timed by
// ---------------------------------------------------------------------------
//
// The profiles a routed probe shares whatever it asks about are in `raw`.

/// How a **port scan's** probes are retransmitted.
///
/// [`RETRY_POLICY`](super::raw::RETRY_POLICY) with a steeper backoff and a wider
/// spread. A sweep's probes are lost to whatever the path is doing; a port
/// scan's are lost to its own burst at one stack, and a retry sent while that
/// burst is still going lands in the same congestion.
///
/// Measured against a Raspberry Pi: a quarter of a thousand probes went
/// unanswered, so with three independent attempts an open port should be missed
/// one time in seventy, and eleven open ports should have come back as nearly
/// eleven. Three runs found seven each: all three attempts fell inside the
/// congestion that lost the first.
///
/// So the schedule is stretched at the back and left alone at the front. The
/// first timeout stays as early as measurement allows, because it is what tells
/// [`TCP_PORT_WINDOW`] the target is struggling; the last lands far enough out
/// to sample a network the scan has stopped congesting. The jitter is wider
/// because probes admitted together time out together, and an unspread retry
/// wave rebuilds the burst.
const PORT_RETRY_POLICY: RetryPolicy = RetryPolicy::new(
    3,
    Duration::from_millis(200),
    Duration::from_millis(25),
    Duration::from_secs(2),
    3.0,
    0.3,
    Some(SilentHostPolicy::new(32, 2)),
);

/// The window a **TCP** port scan paces itself by.
///
/// A port scan aims every probe at one stack, and that stack's willingness to
/// answer bounds the result. It differs by two orders of magnitude between a
/// consumer router and a Linux server on the same switch and cannot be known in
/// advance, so the scan discovers it. See
/// [`congestion`](crate::scanner::pacing::congestion) for how, and why it grows
/// and cuts on a probe answered *on a retry*.
///
/// - **Start at 32.** Every stack in service answers a few dozen simultaneous
///   SYNs without noticing. Starting at one would spend a round trip per
///   doubling, and on a local segment the ramp would be most of the scan.
/// - **Never below 16.** The floor a target that is really being outrun is cut
///   back to; at sixteen per round-trip budget a thousand silent ports still
///   settle in a few seconds, where single digits would take a minute. An
///   unfinished scan's verdicts are indeterminate.
/// - **Never above 1024.** No stack answers a thousand outstanding questions;
///   the rate ceiling would bind first anyway.
/// - **Stop doubling at 64.** Nothing is known about a target until a probe to
///   it is answered or times out, and slow start doubles every round trip
///   meanwhile, so this is the worst overshoot before the scan has any evidence.
///   Against a Raspberry Pi, a threshold of 256 put several hundred probes in
///   the air by the first timeout. Sixty-four still empties a thousand ports in
///   a fraction of a second on a local segment, and linear growth carries it
///   further where the evidence supports it.
const TCP_PORT_WINDOW: WindowLimits = WindowLimits::new(32, 16, 1_024, 64);

/// The most probes a TCP port scan leaves unresolved at once.
///
/// [`TCP_PORT_WINDOW`] does the pacing; this bounds how far the bookkeeping may
/// run ahead of it. A probe leaves the window at its first timeout and stays on
/// the ledger until its last, so against a range that answers nothing the
/// backlog grows behind the window. That backlog is the retry schedule's length
/// over the first timeout, a multiple of what is in flight, hence several times
/// the window's ceiling; each entry is two durations and a few tokens, so the
/// memory is small.
const TCP_PORT_UNRESOLVED: usize = 8_192;

/// The fastest a TCP port scan will go regardless of what the window says.
///
/// A **backstop** so a defect in the controller cannot turn a scan into a
/// flood; [`TCP_PORT_WINDOW`] does the pacing. At this rate a thousand-port scan
/// emits in fifty milliseconds, faster than the round trips it waits on. A
/// caller wanting a real limit sets
/// [`ZondConfig::max_probe_rate`](crate::config::ZondConfig::max_probe_rate),
/// which replaces this.
const TCP_PORT_RATE_CEILING: NonZeroU32 = NonZeroU32::new(20_000).expect("a non-zero rate");

/// The fastest a **UDP** port scan puts probes on the wire, in probes per
/// second.
///
/// A real limit, two orders of magnitude below [`TCP_PORT_RATE_CEILING`],
/// because UDP has no window to pace it with: a UDP probe's ordinary outcome is
/// silence and its replies name no attempt, so neither half of the congestion
/// signal exists (see [`congestion`](crate::scanner::pacing::congestion)).
///
/// Most UDP verdicts come from an ICMP port unreachable, which Linux emits under
/// a token bucket refilling at roughly one per second. A burst that outruns it
/// manufactures [`OpenOrNoReply`](crate::model::port::PortState::OpenOrNoReply)
/// verdicts on closed ports. Spread across a shuffled scan's hosts this is
/// survivable; aimed at one host it is the whole result.
///
/// Not measured: set an order of magnitude below the sweep's measured rate
/// because the per-target load is an order of magnitude higher.
const UDP_PORT_RATE_PER_SEC: NonZeroU32 = NonZeroU32::new(400).expect("a non-zero rate");

/// How far behind its own rate a port scan's send ticker may fall before the
/// deadline stops allowing for it.
///
/// The ticker falls behind whenever the loop is busy reading replies, and a
/// missed tick is delayed, not made up. Half again the rate's own time is the
/// routed sweep's allowance for the same reason.
const SEND_SLACK: f64 = 1.5;

/// The deadline a raw port scan of `target_count` endpoints runs under:
/// `config` with its hard budget widened to what the scan's own pacing needs.
///
/// The hard deadline guarantees a scan ends; it must not end one still going
/// at an allowed pace, or unreached ports (open ones among them) come back
/// unasked. So the pace is taken from every limit, each at its slowest
/// legitimate setting:
///
/// - **The window**, cut to its floor, with every question holding its slot for
///   the longest timeout the retry policy allows, since a long-RTT path times
///   every question long.
/// - **The rate**, with every attempt at every endpoint leaving through the
///   send ticker, and [`SEND_SLACK`] for a ticker that falls behind.
/// - **The gap between probes**, the longer of the per-host and scan-wide ones,
///   with every attempt waiting its turn. Exact for the scan-wide gap; for the
///   per-host one it assumes every endpoint is one host's, since the scan is not
///   told how endpoints spread over addresses.
///
/// The slowest of the three is the pace; they bind at once, so they are not
/// added. On top comes the tail: the last probe admitted may spend its whole
/// schedule at the longest timeout.
///
/// A scan going well finishes the moment every probe settles, so the generous
/// terms cost it nothing; the deadline still bounds a scan that stopped making
/// progress. A term no clock can count saturates, and the deadline with it.
fn deadline_for(
    config: AdaptiveDeadlineConfig,
    retry: &RetryPolicy,
    window: WindowLimits,
    rate: NonZeroU32,
    gap: Option<Duration>,
    target_count: usize,
) -> AdaptiveDeadlineConfig {
    let attempts = u32::from(retry.max_attempts.max(1));
    let by_window = retry.longest_timeout() / window.floor.max(1);
    let by_rate = saturating_mul(
        Duration::from_secs(1),
        SEND_SLACK * f64::from(attempts) / f64::from(rate.get()),
    );
    let by_gap = gap.unwrap_or_default().saturating_mul(attempts);
    config
        .allowing_for(retry.longest_probe_lifetime())
        .allowing_pace_of(by_window.max(by_rate).max(by_gap), target_count)
}

/// A probe's identity within a scan: which address, which port.
pub(crate) type ProbeTarget = (IpAddr, u16);

/// The state a raw port scan carries, and everything it does that does not
/// depend on which protocol it speaks.
///
/// Generic over the correlation token `T`: a TCP probe carries a nonce its
/// answer must echo, while a UDP probe has nothing to echo, correlates on the
/// target alone, and uses `()`.
pub(crate) struct RawProbeScan<T> {
    /// Resolves the source address for each target, from on-link subnets and the
    /// kernel routing table. Cached, so many ports on one host cost one lookup.
    pub resolver: SourceResolver,
    /// Shared state (host store, event channel, abort signal) for the scan.
    pub ctx: ScanContext,
    /// Sends probes and receives replies.
    pub transport: ProbeTransport,
    /// How long this scan keeps running, adapted to observed round trips.
    pub deadline: AdaptiveDeadline,
    /// Probes sent but not yet resolved, with when each is next due to be resent
    /// or written off. The payload is each target's position in the plan, handed
    /// back when the probe retires so a resume can skip it.
    pub ledger: ProbeLedger<ProbeTarget, T, u64>,
    /// Scratch space for the probes coming due on one iteration, reused so a
    /// quiet tick allocates nothing.
    pub due: Vec<Due<ProbeTarget, u64>>,
    /// The source port every probe is sent from, and so the port replies come back
    /// to. The capture filter narrows to it; anything addressed elsewhere answered
    /// somebody else.
    pub src_port: u16,
    /// The IP-header state every probe carries: its hop limit and any evasion
    /// override. See [`Emission`].
    pub emission: Emission,
    /// The segment-level shaping every probe carries: payload padding and, on the
    /// TCP paths, the bad-checksum choice. See [`SegmentShaping`].
    pub shaping: SegmentShaping,
    /// The decoy source addresses every probe is copied from, or empty. Resolved
    /// once from the scan's [`EvasionProfile`](crate::evasion::EvasionProfile).
    pub decoys: Vec<IpAddr>,
    /// The slot claimed for the probe being sent, between the claim and
    /// [`record_send`](Self::record_send), which gives it back if the kernel
    /// refused the send. See [`ScanContext::claim_probe`].
    pub claimed: Option<ProbeClaim>,
    /// Why the first probe this host's own sender would not put on the wire
    /// failed, if any did.
    ///
    /// The first, so the report does not name whichever of thousands of identical
    /// failures happened to come last on a link that stopped accepting sends.
    ///
    /// Without it, a scan whose probes never reached the wire reports every port
    /// with its protocol's reading of silence, the same answer a firewall produces.
    ///
    /// Only this host's failures; a destination the sender says cannot be reached
    /// goes to [`unreachable`](Self::unreachable).
    pub send_failure: Option<String>,
    /// Ports recorded unasked because the sender refused their first probe for
    /// a reason on this host.
    ///
    /// Counted apart from [`retries_refused`](Self::retries_refused): a refused
    /// first attempt leaves its port with no verdict, while a refused retry leaves a
    /// verdict standing on the attempts that left.
    pub unasked_refused: u64,
    /// Retries the sender refused for a reason on this host. See
    /// [`unasked_refused`](Self::unasked_refused).
    pub retries_refused: u64,
    /// Ports settled unasked because no probe for them was ever seen leaving.
    /// The report is driven off this, not the send tally, so a run that lost sends
    /// but still resolved every port stays quiet.
    pub unasked_unsent: u64,
    /// The addresses the sender said cannot be reached from here: no route to
    /// them, or no answer from the neighbour a route leads through.
    ///
    /// Tracked per address because port by port the sender's answers contradict
    /// themselves: a kernel resolving a dead neighbour accepts the first probes
    /// while it waits and refuses the rest once it gives up, so some ports would
    /// read silent and others unasked. Every never-answered port of an address here
    /// is recorded unasked, and the address is reported as not reached, not as a
    /// scanner failure. See [`is_unreachable`](Self::is_unreachable).
    pub unreachable: std::collections::BTreeSet<IpAddr>,
    /// The hosts the kernel refused a probe to for a neighbour it gave up on
    /// lately, and until when their probes are held for it. See
    /// [`hold_down`](Self::hold_down).
    pub(crate) held_down: HoldDowns,
    /// How much of the time hold-downs and second resolutions hold probes back has
    /// been allowed to the deadline, so overlapping holds count once. See
    /// [`allow_until`](Self::allow_until).
    held_allowed: HeldAllowance,
    /// How far this scan has read the resolution of each host's neighbour,
    /// for a transport whose sends wait on one it can read. See
    /// [`admit`](Self::admit).
    pub(crate) neighbors: NeighborGates,
    /// Per-run counters, so a scan that classified fewer ports than it asked about
    /// can be attributed to loss, to its own deadline, or to correlation. Reported
    /// once when the loop exits.
    pub audit: ProbeAudit,
    /// How many questions this scan may have awaiting an answer, grown and cut
    /// from what the targets are managing to answer.
    ///
    /// This is what paces a raw port scan. Measured against a consumer router
    /// asked as fast as the socket would take: of a thousand ports it answered
    /// roughly four hundred, and the rest, including one running a service, were
    /// reported silent. The host filtered nothing; it was being asked ten times
    /// faster than it could answer.
    ///
    /// A fixed rate would be too fast for that router and far too slow for a Linux
    /// server on the same switch. With a window, probes leave as earlier ones
    /// settle, so the send rate converges on the rate the target resolves them.
    /// See [`congestion`](crate::scanner::pacing::congestion) for what occupies it,
    /// how it grows and cuts, and why UDP gets a fixed one.
    pub window: CongestionWindow,
    /// How long to wait between releases, and the most probes one release may
    /// contain.
    ///
    /// The **backstop**, so a defect in [`window`](Self::window) cannot turn a
    /// scan into a flood, and so a caller asking for a specific rate gets it. On a
    /// healthy scan the window binds far below it. `pacing_for` in the parent
    /// module derives the pair from a rate.
    pub send_tick: Duration,
    /// The most probes one tick releases. See [`send_tick`](Self::send_tick).
    pub batch: usize,
    /// The most probes this scan leaves unresolved at once.
    ///
    /// A bound on memory and correlation state, not on pace; see
    /// [`admitting`](Self::admitting). A probe leaves the [`window`](Self::window)
    /// at its first timeout and stays on the ledger until its last, so against a
    /// range that answers nothing this bounds the backlog in between.
    pub max_unresolved: usize,
    /// Probes waiting for the gap the scan keeps between two probes at one
    /// host, earliest first. Empty unless
    /// [`ZondConfig::host_probe_interval`](crate::config::ZondConfig::host_probe_interval)
    /// was set.
    ///
    /// Bounded by [`max_unresolved`](Self::max_unresolved), so the scan has one
    /// figure for how much it may hold.
    ///
    /// A full queue stops the target stream being read, so the dispatcher feels
    /// the backpressure as it feels the [`window`](Self::window). It does **not**
    /// stop the send path, the only thing that empties this.
    ///
    /// First attempts only; retries wait in [`retries`](Self::retries).
    pub held: std::collections::BinaryHeap<HeldProbe>,
    /// Retries waiting to be sent, earliest first: every retry the ledger
    /// schedules waits here for the send ticker, and for its host's next slot
    /// where the scan keeps a gap.
    ///
    /// A retry spends a tick's budget like a first attempt; sent the moment it
    /// came due, retries would ride on top of the rate ceiling, and against a
    /// silent range the wire would carry the ceiling once per attempt.
    ///
    /// Kept apart from [`held`](Self::held) because a first attempt takes a slot in
    /// the [`window`](Self::window) and waits for one, while a retry takes none (the
    /// question it repeats already gave its slot back; see
    /// [`congestion`](crate::scanner::pacing::congestion)) and must not wait behind
    /// a full window.
    ///
    /// Its probe's clock is stopped while it waits (see [`ProbeLedger::defer`]), so
    /// an unsent attempt is never overtaken by the next, and a probe never runs out
    /// of attempts it did not send. Never larger than the ledger: a probe has at
    /// most one retry waiting.
    pub(crate) retries: std::collections::BinaryHeap<HeldProbe>,
}

/// What a [`RawProbeScan`] is built from.
///
/// Both raw port scanners build the same core and differ in four values.
pub(super) struct CoreParts<'a> {
    /// Resolves the source address each target's probe leaves from.
    pub resolver: SourceResolver,
    /// The scan this prober is part of.
    pub ctx: ScanContext,
    /// Where probes go and replies come from.
    pub transport: ProbeTransport,
    /// What the caller asked for, including the evasion settings and the source
    /// port.
    pub tuning: &'a ProbeTuning,
    /// The port every probe in this scan leaves from, where `transport` fixes
    /// none; see [`ProbeTransport::reply_port`].
    pub src_port: u16,
    /// How many endpoints the scan will ask about.
    pub target_count: usize,
    /// The retry schedule, which the deadline is derived from.
    pub retry: RetryPolicy,
    /// The send rate. Non-zero because the pacing divides by it.
    pub rate: NonZeroU32,
    /// The budgets the scan runs against. A UDP scan needs a silence floor above
    /// the ICMP rate-limit interval before quiet means anything. The hard budget
    /// is widened to what the scan's pacing needs; see [`deadline_for`].
    pub deadline: AdaptiveDeadlineConfig,
    /// The in-flight window.
    pub window: WindowLimits,
    /// The most probes that may be outstanding at once.
    pub max_unresolved: usize,
}

impl<T: Copy + PartialEq> RawProbeScan<T> {
    /// The core both raw port scanners run on.
    ///
    /// Seeds its timing from what the liveness phase already learned about these
    /// hosts, so the first wave of probes is timed against a measurement.
    pub(super) fn new(parts: CoreParts<'_>) -> Self {
        let CoreParts {
            resolver,
            ctx,
            transport,
            tuning,
            src_port,
            target_count,
            retry,
            rate,
            deadline,
            window,
            max_unresolved,
        } = parts;

        // The transport's, where it has one: its capture hears no other.
        let src_port = transport.reply_port().unwrap_or(src_port);
        let (send_tick, batch) = super::raw::pacing_for(rate);
        let deadline = deadline_for(
            deadline,
            &retry,
            window,
            rate,
            ctx.probe_gap(),
            target_count,
        );

        let mut core = Self {
            resolver,
            ctx,
            transport,
            deadline: AdaptiveDeadline::new(deadline, target_count),
            ledger: ProbeLedger::new(retry, target_count.min(max_unresolved)),
            due: Vec::new(),
            src_port,
            emission: tuning.evasion.emission(),
            shaping: tuning.evasion.segment_shaping(),
            decoys: tuning.evasion.decoys.clone(),
            claimed: None,
            send_failure: None,
            unasked_refused: 0,
            retries_refused: 0,
            unasked_unsent: 0,
            unreachable: std::collections::BTreeSet::new(),
            held_down: HoldDowns::default(),
            held_allowed: HeldAllowance::default(),
            neighbors: NeighborGates::default(),
            audit: ProbeAudit::new(),
            window: CongestionWindow::new(window),
            send_tick,
            batch,
            max_unresolved,
            held: std::collections::BinaryHeap::new(),
            retries: std::collections::BinaryHeap::new(),
        };
        core.seed_timing();
        core
    }

    /// Whether the loop should keep going, and if not, why it stopped.
    ///
    /// `sending_finished` says the target stream has run dry; an empty ledger
    /// means "everything answered or written off" only once nothing is left to ask.
    ///
    /// - **Stopped.** The caller asked the scan to stop, or its wall-clock budget
    ///   ran out. Checked first, so a scan winds down promptly;
    ///   [`ScanHandle::stopped`](crate::scanner::handle::ScanHandle::stopped) says
    ///   which.
    /// - **Hard deadline.** The ceiling on the whole run, which nothing extends.
    /// - **Attempts spent.** Every probe asked as often as its budget allows, none
    ///   outstanding, and none held for the per-host gap. A held probe counts
    ///   because it has not been sent, and stopping would report a delayed port as
    ///   asked and silent. A retry waiting for the ticker does not count: its probe
    ///   is still on the ledger.
    ///
    /// Silence is not a stop condition. With targets still queued, an empty ledger
    /// means the scan has not *asked* yet, which happens when the send path fails;
    /// stopping there would report everything still queued as unreachable.
    /// Measured: a wireless host whose ARP entry went unresolved mid-scan returned
    /// `No route to host` for seven thousand probes, and a silence stop ended the
    /// scan after thirty seconds with thirty-one thousand targets never asked.
    pub fn stop_reason(&self, sending_finished: bool) -> Option<StopReason> {
        if let Some(cause) = self.ctx.handle.stopped() {
            return Some(cause.into());
        }
        if self.deadline.hard_deadline_passed() {
            return Some(StopReason::DeadlineExpired);
        }
        if sending_finished && self.ledger.is_empty() && self.held.is_empty() {
            return Some(StopReason::AttemptsSpent);
        }
        None
    }

    /// Whether another target may be admitted from the stream.
    ///
    /// False when there is nothing left to send (the stream is done and no probe
    /// is held), when the [`window`](Self::window) is full (the pacing), or when
    /// the ledger is at [`max_unresolved`](Self::max_unresolved) (a memory bound: a
    /// probe stays on the ledger long after leaving the window, and against a
    /// silent range that backlog grows without limit).
    ///
    /// The [`held`](Self::held) queue counts as something to send, so a dry stream
    /// does not close the send path while probes wait for their gap. How many may
    /// wait is bounded by [`held_is_full`](Self::held_is_full), which limits the
    /// *stream*, not this.
    pub fn admitting(&self, sending_finished: bool) -> bool {
        self.questions_left(sending_finished)
            && self.window.has_room()
            && self.ledger.len() < self.max_unresolved
    }

    /// Whether any question is still to be admitted: a target still to come
    /// off the stream, or a first attempt held for its host.
    fn questions_left(&self, sending_finished: bool) -> bool {
        !sending_finished || !self.held.is_empty()
    }

    /// Whether the queue of held probes is full.
    ///
    /// Stops the target stream being read once the gap in
    /// [`ZondConfig::host_probe_interval`](crate::config::ZondConfig::host_probe_interval)
    /// is what limits the scan, so the dispatcher feels it.
    ///
    /// Not part of [`admitting`](Self::admitting): the send path is the only thing
    /// that empties this queue, so letting it close the send path would stall the
    /// scan for good.
    pub fn held_is_full(&self) -> bool {
        self.held.len() >= self.max_unresolved
    }

    /// Whether the send ticker has anything to do: a target to admit, or a
    /// retry waiting for its turn. A retry is sent whether or not the window
    /// has room; see [`retries`](Self::retries).
    pub(crate) fn sending(&self, sending_finished: bool) -> bool {
        self.admitting(sending_finished) || !self.retries.is_empty()
    }

    /// Holds `probe` back until `ready`: a first attempt in
    /// [`held`](Self::held), a retry in [`retries`](Self::retries), told
    /// apart by whether it carries a plan position.
    ///
    /// The caller has already established the host is not ready. Callers that
    /// cannot hold a probe must not ask, since a dropped probe is a port reported
    /// silent that nobody sent anything to; see
    /// [`ScanContext::probe_ready_at`](crate::scanner::session::ScanContext::probe_ready_at).
    fn hold(&mut self, ip: IpAddr, port: u16, position: Option<u64>, ready: Instant) {
        let entry = HeldProbe {
            ip,
            port,
            position,
            ready,
        };
        match position {
            Some(_) => self.held.push(entry),
            None => self.retries.push(entry),
        }
    }

    /// The next held probe whose host may be asked now.
    ///
    /// The recorded instant is a hint and is re-checked: a retry to the same host
    /// moves its slot after an entry is queued, so an entry can reach the front
    /// early. One still early is pushed back under the fresh instant.
    ///
    /// That cannot loop: [`probe_ready_at`](crate::scanner::session::ScanContext::probe_ready_at)
    /// only returns instants strictly later than `now`, so every iteration either
    /// yields a probe or removes one entry from the queue's due prefix.
    fn take_ready(&mut self, now: Instant) -> Option<HeldProbe> {
        take_ready_from(&mut self.held, &self.ctx, now)
    }

    /// The next waiting retry whose host may be asked now, on the terms
    /// [`take_ready`](Self::take_ready) gives.
    pub(crate) fn take_ready_retry(&mut self, now: Instant) -> Option<HeldProbe> {
        take_ready_from(&mut self.retries, &self.ctx, now)
    }

    /// Records one probe leaving the wire, or failing to, and why.
    ///
    /// One call because it is one event. The audit counts every attempt so a scan
    /// that could not send can say so; the window counts only probes that reached
    /// the wire, since an unsent probe is no evidence the path is busy; and the
    /// slot [claimed](ScanContext::claim_probe) for the send is refunded on the same
    /// terms as the window.
    ///
    /// A refusal is sorted by whose fact it is, as [`SendError::is_unroutable`]
    /// draws the line, and by whether `target`'s host has ever answered. An
    /// unreachable address that never has is an absent host: it goes in
    /// [`unreachable`](Self::unreachable) and touches nothing else, so a dead
    /// neighbour among live hosts does not slow the scan of the live ones. Anything
    /// else is this host's: congestion for the window and a fault for the report.
    /// That includes a host that answered and then became unreachable, a link that
    /// stopped keeping up mid-scan. Measured: a wireless host whose neighbour entry
    /// went unresolved mid-scan was refused seven thousand probes with `No route to
    /// host`, and a window that ignored them kept offering the link as much as
    /// before.
    ///
    /// `first_attempt` decides whether the send takes a window slot. A retry does
    /// not: the slot went back when the question it repeats ran out of round-trip
    /// budget, and returning it twice would let the window over-admit. It comes
    /// from the plan position the send carries, the one fact about a probe that
    /// does not change while a retry waits. The host's probe gap applies to retries
    /// too, since it is about what the target receives.
    ///
    /// A kernel's first hold-down on `target`'s neighbour is neither: the host is
    /// held and asked again after; see [`hold_down`](Self::hold_down).
    ///
    /// Each kind of refusal is logged once: the first of this host's, and the first
    /// for each address. A link that stopped accepting sends refuses every probe
    /// after, and the report carries the count.
    pub fn record_send(
        &mut self,
        (host, port): ProbeTarget,
        sent: Result<(), &SendError>,
        first_attempt: bool,
    ) {
        self.audit.record_send(sent.is_ok());
        let claim = self.claimed.take();
        if let (Err(_), Some(claim)) = (sent, claim) {
            self.ctx.refund_probe(claim);
        }
        match (sent, first_attempt) {
            (Ok(()), first) => {
                if first {
                    self.window.record_send();
                } else {
                    self.window.record_resend();
                }
            }
            (Err(error @ SendError::HeldDown(_)), _) if self.hold_down(host) => {
                info!(
                    verbosity = 2,
                    "{host} held down by the kernel, asked again in {}s ({error:#})",
                    self.held_down.hold_down_for.as_secs()
                );
            }
            (Err(error), _) if error.is_unroutable() && !self.ledger.host_has_answered(&host) => {
                if self.unreachable.insert(host) {
                    // `{error:#}` for the operating system's own words.
                    info!(verbosity = 2, "{host} unreachable ({error:#})");
                }
            }
            (Err(error), first) => {
                // A send this machine refused is the least ambiguous signal the
                // controller gets: whatever the reason (a full interface queue, a link not
                // keeping up), sending faster cannot help. Read as congestion; the damping
                // bounds how far a permanent failure can cut.
                self.window.record_congestion();
                if first {
                    self.unasked_refused += 1;
                } else {
                    self.retries_refused += 1;
                }
                // Logged once at -vv, not as an error: the run's failure line reports
                // what the refusals cost, and a front end shows every error.
                if self.send_failure.is_none() {
                    warn!(verbosity = 2, "probe to {host}:{port} not sent ({error:#})");
                    self.send_failure = Some(format!("{error:#}"));
                }
            }
        }
    }

    /// Holds `host` out of the kernel's hold-down on its neighbour, which a
    /// probe to it was just refused for, and whether it did: `false` once the
    /// refusal is the kernel's verdict on the host. See [`HoldDowns`].
    ///
    /// A held host is not filed unreachable, and the refusal is neither
    /// congestion nor this host's fault: the kernel sent nothing. Its probes are
    /// put off for the whole hold-down, taken back unsent, and the first one after
    /// makes the kernel ask for the neighbour again.
    ///
    /// The deadline is given the held time, counted once however many hosts are
    /// held at a time; see [`allow_until`](Self::allow_until).
    pub(crate) fn hold_down(&mut self, host: IpAddr) -> bool {
        let now = Instant::now();
        let Some(until) = self.held_down.hold(host, now) else {
            return false;
        };
        self.allow_until(now, until);
        true
    }

    /// Gives the deadline the time from `now` to `until`, for which a host's
    /// probes are kept back, counted once where holds overlap; see
    /// [`HeldAllowance`] and
    /// [`allow_for_holding`](crate::scanner::pacing::deadline::AdaptiveDeadline::allow_for_holding).
    fn allow_until(&mut self, now: Instant, until: Instant) {
        let held = self.held_allowed.take(now, until);
        self.deadline.allow_for_holding(held);
    }

    /// Until when `host`'s probes are held for the kernel's hold-down on its
    /// neighbour, if they still are at `now`.
    fn held_down_until(&self, host: IpAddr, now: Instant) -> Option<Instant> {
        self.held_down.until(host, now)
    }

    /// The address a probe to `target` leaves from, or `None` with the reason
    /// filed where it belongs.
    ///
    /// No address reaching the host is a fact about the host, filed by
    /// [`record_no_route`](Self::record_no_route). A lookup this process had no
    /// descriptor for is a fact about this machine, filed through
    /// [`record_send`](Self::record_send) as a send refused for the file limit: the
    /// probe is counted unasked, the host is not filed unreachable, and its next
    /// probe asks the routing table again. A lookup the table gave no answer to is
    /// filed the same way, in the table's words, since it says nothing about the
    /// host.
    pub(crate) fn source_for(
        &mut self,
        target: ProbeTarget,
        first_attempt: bool,
    ) -> Option<IpAddr> {
        let refusal = match self.resolver.source(target.0) {
            Ok(source) => return Some(source),
            Err(NoSource::Unreached) => {
                self.record_no_route(target.0);
                return None;
            }
            Err(NoSource::Unasked(error)) => SendError::from_io(error),
            Err(NoSource::Unanswered(error)) => SendError::unanswered_route(&error),
        };
        self.record_send(target, Err(&refusal), first_attempt);
        None
    }

    /// Records that no address on this host can reach `host`, so none of its
    /// probes could be built.
    ///
    /// The source resolver's answer, reached before a probe exists, and the same
    /// fact about the destination as the sender's no route. Not a send attempt, so
    /// the audit does not count it.
    pub fn record_no_route(&mut self, host: IpAddr) {
        if self.unreachable.insert(host) {
            let why = if self.resolver.refused_by_route(host) {
                self.ctx.note_refused_by_route(host);
                "a route refuses it"
            } else {
                "no source address"
            };
            info!(verbosity = 2, "{host} unreachable ({why})");
        }
    }

    /// Files `host` as an address whose neighbour was asked for and never
    /// answered, in the resolution's word for where it stands: failed, or
    /// still pending when it was given up on or the scan ended.
    fn record_unresolved(&mut self, host: IpAddr, state: NeighborState) {
        if self.unreachable.insert(host) {
            let why = self.neighbors.unreached(host, state);
            info!(verbosity = 2, "{host} unreachable ({why})");
        }
    }

    /// Decides what becomes of a probe to `host` before it is handed to the
    /// sender: sent, held for a moment, or not sent at all.
    ///
    /// An address already known unreachable is not asked again: every further
    /// probe would meet the same answer, or on Linux be taken and never sent.
    ///
    /// For a transport whose sends wait on an address resolution the scan can
    /// read, a host that has not answered is not probed while its neighbour is
    /// being resolved, and one whose neighbour went unanswered twice is filed
    /// unreachable; see [`NeighborGates::admit`]. The deadline is given the time a
    /// second resolution takes, counted once however many run at a time.
    ///
    /// A live neighbour answers within a millisecond, so a live host with an
    /// unknown hardware address costs one short hold. A host that has answered
    /// anything is never gated on resolution, but is still held through a kernel's
    /// hold-down; see [`hold_down`](Self::hold_down).
    pub(crate) fn admit(&mut self, host: IpAddr, now: Instant) -> Admission {
        if self.is_unreachable(&host) {
            return Admission::Unreachable;
        }
        if let Some(until) = self.held_down_until(host, now) {
            return Admission::Hold(until);
        }
        if self.ledger.host_has_answered(&host) {
            return Admission::Send;
        }
        let admission =
            self.neighbors
                .admit(self.transport.neighbors(), &mut self.resolver, host, now);
        if let Some(asked) = self.neighbors.take_asked_again() {
            let until = crate::scanner::pacing::timer::later(asked, RESOLUTION_BUDGET);
            self.allow_until(now.max(asked), until);
        }
        if admission == Admission::Unreachable {
            self.record_unresolved(host, self.neighbors.given_up_in(host));
        }
        admission
    }

    /// Where the resolution of `host`'s neighbour stands, for a host this
    /// scan has been holding probes to while it runs, and `None` for any
    /// other host.
    ///
    /// Read when that probe runs out of attempts or the scan runs out of time,
    /// either of which can come before the kernel gives up: it asks three times a
    /// second apart, and a probe's schedule on a fast segment is a fraction of
    /// that. A neighbour still being resolved means the probe sat in the kernel's
    /// queue and never left, so its silence says nothing about the port. See
    /// [`service_retries`](RawPortScan::service_retries) and
    /// [`conclude_pending_neighbors`](Self::conclude_pending_neighbors).
    pub(crate) fn pending_neighbor(&mut self, host: IpAddr) -> Option<NeighborState> {
        if self.is_unreachable(&host) || self.ledger.host_has_answered(&host) {
            return None;
        }
        self.neighbors
            .pending(self.transport.neighbors(), &mut self.resolver, host)
    }

    /// Files every host whose neighbour the kernel was still resolving, or had
    /// given up on, when the scan ended.
    ///
    /// Out of time with the kernel still asking, such a host's one probe never
    /// left and nothing was heard from its neighbour, so nothing reached the
    /// address. Asked of every waiting host, not only probes still on the ledger:
    /// the probe may be back in the hold queue, having run out of attempts while
    /// the kernel asked.
    pub(crate) fn conclude_pending_neighbors(&mut self) {
        for host in self.neighbors.waiting() {
            if let Some(state) = self.pending_neighbor(host)
                && state.is_unresolved()
            {
                self.record_unresolved(host, state);
            }
        }
    }

    /// Whether `host` is an address this scan cannot reach and has never heard
    /// from, so every port of it is recorded unasked whatever its own probe met.
    ///
    /// Never true of a host that has answered anything: one that answered and then
    /// became unreachable had its route change mid-scan, and its silent ports were
    /// still asked.
    pub fn is_unreachable(&self, host: &IpAddr) -> bool {
        self.unreachable.contains(host) && !self.ledger.host_has_answered(host)
    }

    /// Reads one probe's first timeout: frees the window slot it was holding,
    /// and decides what the silence meant, given `silence`, the verdict this
    /// scan's technique reads it as.
    ///
    /// From a host answering little of what it is asked, silence says nothing
    /// about capacity: it is the host's own (a firewall, or open ports the
    /// technique leaves silent). From a host that is answering, where the
    /// technique's silence means a filter, it is a dropped probe; where silence can
    /// also mean an open port, one timeout cannot say which, so the window reads
    /// how much silence there is. See
    /// [`service_retries`](RawPortScan::service_retries) for the argument,
    /// [`host_is_answering`](ProbeLedger::host_is_answering) for where the line
    /// falls, and [`congestion`](crate::scanner::pacing::congestion) for the cost of
    /// getting each wrong.
    pub fn judge_timeout(&mut self, host: IpAddr, silence: PortState) {
        self.window.release();
        if !self.ledger.host_is_answering(&host) {
            self.window.record_progress();
        } else if silence == PortState::NoReply {
            self.window.record_loss();
        } else {
            self.window.record_ambiguous_silence();
        }
    }

    /// Folds one answered probe into everything this scan tracks about itself:
    /// the deadline, the window and the audit.
    ///
    /// The window reads which *attempt* was answered. A reply to the first says
    /// the target is keeping up; a reply to a later one says the target was willing
    /// and the first question did not survive, the only evidence a port scanner has
    /// that separates being too fast from meeting a firewall. See
    /// [`congestion`](crate::scanner::pacing::congestion).
    pub fn record_answer<P: Copy>(&mut self, resolution: &Resolution<P>) {
        self.deadline.mark_activity();
        if let Some(rtt) = resolution.rtt {
            self.deadline.record_rtt(rtt);
        }

        match (resolution.attempts, resolution.answered_attempt) {
            // Asked once and answered: the slot is still held, and the target is
            // keeping up.
            (1, _) => {
                self.window.release();
                self.window.record_answer();
            }
            // Answered only on a retry: the first ask did not survive. The slot
            // went back at that timeout, so this cuts and frees nothing.
            (_, Some(attempt)) if attempt > 1 => self.window.record_congestion(),
            // The first ask answered after its budget expired, visible through the
            // per-attempt token. The timeout already released and judged the slot.
            _ => {}
        }

        self.audit.record_host_found(resolution.answered_attempt);
    }

    /// How long the loop may sleep: until the scan's own next checkpoint, or
    /// until the next probe needs resending or retiring, whichever comes first.
    pub fn tick_delay(&self, now: Instant) -> Duration {
        let until_deadline_tick = self.deadline.time_until_next_tick();
        match self.ledger.next_due() {
            Some(due) => until_deadline_tick.min(due.saturating_duration_since(now)),
            None => until_deadline_tick,
        }
    }

    /// Seeds each host's retry timing from what an earlier phase already
    /// measured about it.
    ///
    /// The liveness pass of [`scan`](crate::scan) already timed every host that
    /// answered. Without this, each silent port would wait the unmeasured starting
    /// timeout three times before its silence meant anything.
    ///
    /// Called once at construction: the store is complete by then, and a lookup
    /// per target would repeat the same answer for every port of a host.
    ///
    /// Uses the median, because a retry schedule sized from a host's fastest
    /// sample repeats every probe that is merely typical. See
    /// [`ProbeLedger::seed_host`] for which samples.
    pub fn seed_timing(&mut self) {
        for host in self.ctx.store.iter() {
            self.ledger
                .seed_host(host.key().addr(), host.value().telemetry());
        }
    }

    /// Records that `sender` said the target named by `key` cannot be reached.
    ///
    /// A host verdict: an unreachable names the destination, not a port. The
    /// probe keeps its remaining attempts, so this does not go through the ledger's
    /// `resolve`.
    ///
    /// **`key` must name a probe this scan has outstanding, and this checks it.**
    /// [`HostStatus::Down`] means an unreachable "quoting a probe this scan sent",
    /// and the quoted source port alone does not establish that: an error quoting
    /// any destination and port would be believed. An address never probed would be
    /// created and filed down; a probed, silent host would go from `Unknown`
    /// (nothing heard) to `Down` (an intermediary answered for it), conflating a
    /// hardened host with an absent one; and a host already up would collect the
    /// unreachable as evidence on its record.
    ///
    /// `token` is checked where the quotation carried one; otherwise the key alone
    /// must name a live probe.
    ///
    /// **An unreachable from this host's own address is not a host down.** Linux
    /// answers a write queued behind a failed neighbour resolution with a host
    /// unreachable from the write's own source address, to itself, over loopback.
    /// That is this kernel failing to resolve the neighbour, and whether it is
    /// heard depends on whether the loopback capture kept up, so filing it `Down`
    /// would give identical dead neighbours different statuses. It is filed as an
    /// address unreachable from here; see [`unreachable`](Self::unreachable).
    ///
    /// Returns whether the verdict reached the host's record or the address was
    /// filed unreachable. `false` means the message named no outstanding probe
    /// (counted off-target), or an address the scan's exclusions forbid, which
    /// [`ScanContext::write_host`] drops.
    pub fn record_host_down(
        &mut self,
        key: &ProbeTarget,
        token: Option<T>,
        sender: IpAddr,
    ) -> bool {
        if !self.ledger.names_attempt(key, token.as_ref()) {
            self.audit.record_off_target();
            return false;
        }

        if self.resolver.resolve(key.0) == Some(sender) {
            self.record_unresolved(key.0, NeighborState::Failed);
            return true;
        }

        // Set by the edit, which runs exactly when the store accepts the address;
        // `update_host` returns whether the host was created.
        let mut recorded = false;
        self.ctx.update_host(key.0, |host| {
            host.record_evidence(
                HostStatus::Down,
                StatusReason::new(StatusProtocol::IcmpUnreachable, "destination unreachable")
                    .from_source(sender),
            );
            recorded = true;
        });
        recorded
    }

    /// What the report says about the probes this host's own sender refused,
    /// or `None` when it refused none.
    ///
    /// One short line with the first refusal's cause. A refused first attempt is a
    /// port recorded unasked; a refused retry is a port asked fewer times than the
    /// policy allows, whose verdict stands on the attempts that left, so it is not
    /// called unasked.
    fn refusals_failure(&self) -> Option<String> {
        let cause = self.send_failure.as_deref().unwrap_or("cause unrecorded");
        let unasked = crate::logging::counted(u128::from(self.unasked_refused), "port", "ports");
        let retries = crate::logging::counted(u128::from(self.retries_refused), "retry", "retries");
        match (self.unasked_refused, self.retries_refused) {
            (0, 0) => None,
            (_, 0) => Some(format!("{unasked} unasked, probes not sent ({cause})")),
            (0, _) => Some(format!("{retries} not sent, ports asked less ({cause})")),
            (_, _) => Some(format!("{unasked} unasked, {retries} not sent ({cause})")),
        }
    }

    /// Closes out a run: reports probes that never reached the wire, then files
    /// the audit.
    ///
    /// `silence_verdict` names what this protocol reads an unanswered probe as, so
    /// the failure message separates a scan that could not send from one that found
    /// everything unanswered; every other number a caller sees is identical for
    /// the two. `silence` is the verdict itself: the audit may read unanswered ports
    /// as possible loss where silence is plain no-reply, not where an open port
    /// answers with it.
    ///
    /// Capture counters are read here, while the transport and its capture threads
    /// are still alive.
    pub fn finish(
        &mut self,
        kind: ScannerKind,
        audit_tag: &str,
        silence_verdict: &str,
        silence: PortState,
        probes: u128,
        reason: StopReason,
    ) {
        if let Some(failure) = self.refusals_failure() {
            self.ctx.record_failure(kind, failure);
        }

        // Reported against the address, not as a failure. Only addresses never
        // heard from: one that answered was reached.
        for host in &self.unreachable {
            if !self.ledger.host_has_answered(host) {
                self.ctx.record_unroutable(*host);
            }
        }

        if self.unasked_unsent > 0 {
            // Seeing a probe leave takes the capture that would hear its answer. If
            // the capture stopped early, a probe never seen leaving says nothing
            // about whether it was sent. The ports are unasked either way; only the
            // cause differs.
            let deaf = self
                .transport
                .capture_counts()
                .is_some_and(|counts| counts.stopped_early > 0);
            let cause = if deaf {
                "a capture stopped early, so their probes may have left unseen"
            } else {
                "this machine accepted their probes and never put them on the wire"
            };
            self.ctx.record_failure(
                kind,
                format!(
                    "{} recorded unasked rather than {silence_verdict}: {cause}",
                    crate::logging::counted(u128::from(self.unasked_unsent), "port", "ports"),
                ),
            );
        }

        let capture = self.transport.capture_counts();
        self.audit.report(
            audit_tag,
            probes,
            reason,
            capture,
            Some(Pacing {
                window: self.window.summary(),
                silence,
                unasked: u128::from(self.unasked_refused) + u128::from(self.unasked_unsent),
            }),
        );
        self.ctx.record_probe_stats(self.audit.stats(
            kind,
            probes,
            reason,
            capture,
            Some(self.window.summary()),
        ));
    }
}

/// The next entry of `queue` whose host `ctx` says may be asked at `now`. See
/// [`RawProbeScan::take_ready`].
fn take_ready_from(
    queue: &mut std::collections::BinaryHeap<HeldProbe>,
    ctx: &ScanContext,
    now: Instant,
) -> Option<HeldProbe> {
    while let Some(next) = queue.peek() {
        if next.ready > now {
            return None;
        }
        let mut entry = queue.pop().expect("peeked");
        match ctx.probe_ready_at(entry.ip, now) {
            None => return Some(entry),
            Some(ready) => {
                entry.ready = ready;
                queue.push(entry);
            }
        }
    }
    None
}

/// A probe held back because its host was asked too recently, because the
/// kernel is still resolving its neighbour, or because the kernel is holding
/// its neighbour down.
///
/// Only the port scanners hold probes: they aim thousands of probes at one
/// address, so [`ZondConfig::host_probe_interval`](crate::config::ZondConfig::host_probe_interval)
/// and neighbour resolution need somewhere to park them. A sweep asks each host
/// once per attempt and moves on.
///
/// A first attempt carries a plan position and a retry does not, as in
/// [`RawPortScan::send`]; that also decides who accounts for the probe if the
/// scan ends while it is held. See [`resolve_held`](RawPortScan::resolve_held).
///
/// The fields are private: every scanner reaches the wire through
/// [`RawPortScan::send`], and a position a caller could write would tell a
/// resume a target was covered by a probe that never went out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeldProbe {
    /// The address to probe.
    ip: IpAddr,
    /// The port to probe.
    port: u16,
    /// The plan position for a first attempt, and [`None`] for a retry.
    position: Option<u64>,
    /// When the host was thought to become ready, as it stood when this was held:
    /// a hint that [`RawProbeScan::take_ready`] re-checks.
    ready: Instant,
}

/// Ordered so that [`BinaryHeap`](std::collections::BinaryHeap), a max-heap,
/// yields the *earliest* ready instant first, as [`ProbeLedger`]'s timer queue
/// does.
impl Ord for HeldProbe {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .ready
            .cmp(&self.ready)
            .then_with(|| self.port.cmp(&other.port))
    }
}

impl PartialOrd for HeldProbe {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// What a raw port scan has to supply that [`drive`] cannot work out for itself.
///
/// Everything here is protocol knowledge: which transport the scan speaks, how
/// it builds a probe and reads a reply, what a verdict proves about the host,
/// and what silence means once a probe has spent its budget. [`drive`] supplies
/// the loop those answers feed.
pub(crate) trait RawPortScan: PortScanner {
    /// The per-probe correlation token. A TCP probe carries a nonce its answer
    /// must echo; a UDP probe has nothing to echo and uses `()`.
    type Token: Copy + PartialEq;

    /// The shared machinery this scan is built around.
    fn core(&self) -> &RawProbeScan<Self::Token>;

    /// The same, mutably.
    fn core_mut(&mut self) -> &mut RawProbeScan<Self::Token>;

    /// The transport this scan probes. Targets of any other protocol are passed
    /// over.
    fn protocol(&self) -> Protocol;

    /// The verdict a probe takes once every attempt has gone unanswered.
    ///
    /// For UDP always [`PortState::OpenOrNoReply`], since an open port that did not
    /// recognise the payload is as silent as a firewall. For TCP it depends on the
    /// technique: `NoReply` where any live stack would have answered,
    /// `OpenOrNoReply` where an open port is required to ignore the probe.
    fn silence_means(&self) -> PortState;

    /// What the audit files this run under, and how its failure message names a
    /// port nobody answered for.
    ///
    /// The second half lets a scan whose probes never reached the wire use its
    /// protocol's word for silence ("unanswered" or "open|no-reply").
    fn audit_labels(&self) -> AuditLabels;

    /// Sends the first attempt at `(ip, port)`, or holds it for its host.
    /// `position` is the target's place in the plan, kept by the ledger so it comes
    /// back when the probe retires.
    ///
    /// A probe that cannot be sent is not armed, and its port is recorded
    /// unasked.
    fn probe(&mut self, ip: IpAddr, port: u16, position: u64, now: Instant) {
        match self.core_mut().admit(ip, now) {
            Admission::Send => match self.core().ctx.claim_probe(ip) {
                Ok(claim) => send_timed(self, claim, port, Some(position), now),
                // Another pass took the slot since this probe was chosen.
                Err(ready) => {
                    self.core_mut().hold(ip, port, Some(position), ready);
                    return;
                }
            },
            Admission::Hold(ready) => {
                self.core_mut().hold(ip, port, Some(position), ready);
                return;
            }
            Admission::Unreachable => {
                self.record_unasked_endpoint(ip, port);
                return;
            }
        }

        // Refused for a hold-down the kernel began before this probe asked:
        // held through it like every other probe to the host.
        if let Some(ready) = self.core().held_down_until(ip, now) {
            self.core_mut().hold(ip, port, Some(position), ready);
            return;
        }

        // `send` arms the ledger only once the segment is on the wire. An unarmed
        // probe never comes due, so without this the port would vanish from the
        // host.
        if !self.core().ledger.contains(&(ip, port)) {
            self.record_unasked_endpoint(ip, port);
        }
    }

    /// Resends a probe already outstanding. The ledger keeps its position.
    ///
    /// A retry whose probe has left the ledger is not sent: a late answer to an
    /// earlier attempt settled it while the retry waited. A retry to an address
    /// found unreachable is not sent either; the ledger retires it on schedule.
    ///
    /// The probe's clock, stopped while the retry waited, restarts here: from the
    /// send, which re-arms it, or from now for a retry that did not leave, so the
    /// charged attempt still counts. See `ProbeLedger::defer`.
    fn reprobe(&mut self, ip: IpAddr, port: u16, now: Instant) {
        if !self.core().ledger.contains(&(ip, port)) {
            return;
        }
        match self.core_mut().admit(ip, now) {
            Admission::Send => match self.core().ctx.claim_probe(ip) {
                Ok(claim) => send_timed(self, claim, port, None, now),
                Err(ready) => {
                    self.core_mut().hold(ip, port, None, ready);
                    return;
                }
            },
            Admission::Hold(ready) => {
                self.core_mut().hold(ip, port, None, ready);
                return;
            }
            Admission::Unreachable => {}
        }
        // Refused for a hold-down: its clock stays stopped, as a held retry's
        // does, and the charged attempt is spent after the hold-down.
        if let Some(ready) = self.core().held_down_until(ip, now) {
            self.core_mut().hold(ip, port, None, ready);
            return;
        }
        self.core_mut().ledger.resume(&(ip, port), now);
    }

    /// Puts one probe on the wire.
    ///
    /// `position` is the target's place in the plan for a first attempt, and
    /// [`None`] for a retry, which keeps the position the ledger already holds.
    fn send(&mut self, ip: IpAddr, port: u16, position: Option<u64>, now: Instant);

    /// Reads one captured reply and resolves whatever probe it answers.
    fn handle_reply(&mut self, reply: &CapturedSegment, now: Instant);

    /// Files a port verdict and whatever the reply that produced it proves
    /// about the host.
    ///
    /// `sender` is the address the reply came from, or `None` when the verdict
    /// came from a spent attempt budget.
    fn record_port(&mut self, ip: IpAddr, port: u16, state: PortState, sender: Option<IpAddr>);

    /// Records what became of one target, separate from the verdict
    /// [`record_port`](Self::record_port) gave it.
    ///
    /// Every target reaches `record_port`, answered, quiet or never asked, since an
    /// absent port is a shortfall a reader cannot see. Only the earned outcomes
    /// carry a position, which is what lets a resume skip a target. See
    /// [`Outcome`].
    fn settle(&mut self, outcome: Outcome) {
        self.core().ctx.record_outcome(outcome);
    }

    /// Probes `target`, if it is one this scan speaks the protocol for.
    ///
    /// A target of another protocol is passed over. The
    /// [`CompositePortScanner`](crate::scanner::strategy::composite::CompositePortScanner)
    /// should never send one; this guard keeps a routing bug from probing a UDP
    /// port with a TCP segment.
    fn send_probe(&mut self, planned: PlannedTarget) {
        if planned.protocol() == self.protocol() {
            self.probe(
                planned.ip(),
                planned.port(),
                planned.position,
                Instant::now(),
            );
        }
    }

    /// Holds `planned` back until its host may be asked again.
    ///
    /// A target of another protocol is passed over, as in
    /// [`send_probe`](Self::send_probe).
    fn hold_probe(&mut self, planned: PlannedTarget, ready: Instant) {
        if planned.protocol() == self.protocol() {
            self.core_mut()
                .hold(planned.ip(), planned.port(), Some(planned.position), ready);
        }
    }

    /// Sends a probe that was held for its host's next slot.
    ///
    /// A first attempt carries a plan position and goes through
    /// [`probe`](Self::probe), which accounts for a target the send path refuses; a
    /// retry goes through [`reprobe`](Self::reprobe), leaving the ledger's position
    /// alone.
    fn send_held(&mut self, held: HeldProbe, now: Instant) {
        match held.position {
            Some(position) => self.probe(held.ip, held.port, position, now),
            None => self.reprobe(held.ip, held.port, now),
        }
    }

    /// Accounts for every probe still held when the loop ended.
    ///
    /// A held first attempt was never armed, so without this its port would vanish
    /// from the host. A waiting retry is still on the ledger and is recorded with
    /// everything else there, so it is dropped here.
    ///
    /// Nothing is counted: these targets entered the audit's denominator when they
    /// came off the stream.
    fn resolve_held(&mut self) {
        self.core_mut().retries.clear();
        let held = std::mem::take(&mut self.core_mut().held);
        for entry in held {
            self.record_unasked_endpoint(entry.ip, entry.port);
        }
    }

    /// Resends everything due and writes off everything that has run out of
    /// attempts.
    ///
    /// Exhaustion is what makes a silent verdict mean something: nothing arrived
    /// across every attempt. Retiring probes here streams results while the scan
    /// runs and frees room under the [`window`](RawProbeScan::window) for the
    /// targets queued behind them. Running out of attempts is not activity, so it
    /// never extends the deadline.
    ///
    /// A probe's **first** timeout releases its slot in the congestion window and
    /// tells the window how the target is coping, carried by whichever event
    /// follows it: the retry, or the exhaustion when the budget was one attempt.
    ///
    /// Which signal it carries depends on the host and on what this scan's silence
    /// means. A host that has answered nothing, or a port or two in many, is
    /// filtered or absent, and its silence says nothing about capacity. A host
    /// answering some of what it is asked and dropping the rest is being outrun,
    /// the only warning a scan gets before it reports a firewall that is not there.
    /// Where an open port is silent by design, only the share of timeouts tells
    /// loss from open ports. See [`congestion`](crate::scanner::pacing::congestion).
    fn service_retries(&mut self, now: Instant) {
        let core = self.core_mut();
        core.ledger.drain_due(now, &mut core.due);

        // Taken so the sends below can borrow `self` mutably; the buffer is
        // reused.
        let due = std::mem::take(&mut self.core_mut().due);
        let silence = self.silence_means();
        for event in &due {
            match *event {
                Due::Retry {
                    key: (ip, port),
                    attempt,
                } => {
                    if attempt == 2 {
                        self.core_mut().judge_timeout(ip, silence);
                    }
                    // A retry waits for the send ticker and the host's next slot like any
                    // probe. Its clock stops while it waits, since this attempt is already
                    // charged: otherwise a held retry would be overtaken by the next, and a
                    // host spaced slower than its retry schedule would settle silent having
                    // been asked once.
                    let core = self.core_mut();
                    core.ledger.defer(&(ip, port));
                    let ready = core.ctx.probe_ready_at(ip, now).unwrap_or(now);
                    core.hold(ip, port, None, ready);
                }
                Due::Exhausted {
                    key: (ip, port),
                    payload: position,
                    attempts,
                    witnessed,
                } => {
                    if attempts == 1 {
                        self.core_mut().judge_timeout(ip, silence);
                    }
                    // A probe whose neighbour the kernel is still resolving never left, so
                    // it goes back to wait as a first attempt. So does one whose neighbour
                    // resolution failed, which is asked again once; admission decides which.
                    match self.core_mut().pending_neighbor(ip) {
                        Some(NeighborState::Resolving | NeighborState::Failed) => {
                            self.core_mut()
                                .hold(ip, port, Some(position), now + NEIGHBOR_RECHECK);
                            continue;
                        }
                        Some(NeighborState::Resolved) | None => {}
                    }
                    // Unreachable and never answered: the kernel took the write while
                    // waiting on a neighbour it then gave up on, so the port takes the
                    // address's verdict. See `RawProbeScan::unreachable`.
                    if self.core().is_unreachable(&ip) {
                        self.record_unasked_endpoint(ip, port);
                        continue;
                    }
                    // Never seen leaving: unasked, not silent. Only where the run witnesses
                    // its egress at all, or every probe would look unsent.
                    if witnessed == 0 && self.core().audit.witnesses_its_sends() {
                        self.core_mut().unasked_unsent += 1;
                        self.record_unasked_endpoint(ip, port);
                        continue;
                    }
                    self.record_port(ip, port, silence, None);
                    // Earned: asked as many times as the policy allows.
                    self.settle(Outcome::Exhausted { position });
                }
            }
        }
        let core = self.core_mut();
        core.due = due;
        core.due.clear();
    }

    /// Records every probe still outstanding as [`PortState::Unasked`]: no
    /// verdict was reached for it.
    ///
    /// [`service_retries`](Self::service_retries) retires most probes as their
    /// budgets run out; these were still mid-schedule when the scan ended. Silence
    /// is a verdict only after every attempt has had its full wait, and an answer
    /// may have been in transit, so they do not take this scan's silence verdict.
    ///
    /// Settled as interrupted, since each was asked; neither outcome carries a
    /// position, so a resume asks it again.
    fn resolve_remaining(&mut self) {
        self.core_mut().window.release_all();
        for (ip, port) in self.core_mut().ledger.drain_unresolved() {
            // Unreachable is known of the address however far this probe's own
            // schedule got. See `RawProbeScan::unreachable`.
            if self.core().is_unreachable(&ip) {
                self.record_unasked_endpoint(ip, port);
                continue;
            }
            self.record_port(ip, port, PortState::Unasked, None);
            self.settle(Outcome::Interrupted);
        }
    }

    /// Records every target still queued when the scan stopped.
    ///
    /// Without this, targets still queued at the deadline would be absent from
    /// the host, the one shortfall a reader cannot see: a truncated port list
    /// looks complete. They are recorded [`PortState::Unasked`], since the scan's
    /// silence verdict would credit them as probed.
    ///
    /// Only what is already queued. The router finds this scanner gone and records
    /// the rest of the plan unasked itself; see
    /// [`CompositePortScanner`](crate::scanner::strategy::composite::CompositePortScanner).
    fn resolve_unasked(&mut self, targets: &mut mpsc::Receiver<PlannedTarget>) -> u128 {
        let mut unasked = 0;
        while let Ok(target) = targets.try_recv() {
            unasked += 1;
            self.record_unasked(target);
        }
        unasked
    }

    /// Records one planned target no probe was sent to.
    ///
    /// A target of another protocol belongs to the other scanner and is passed
    /// over.
    fn record_unasked(&mut self, target: PlannedTarget) {
        if target.protocol() != self.protocol() {
            return;
        }
        self.record_unasked_endpoint(target.ip(), target.port());
    }

    /// The single account of an endpoint nobody asked about: still queued when
    /// the loop ended, reached after its host spent the budget in
    /// [`ZondConfig::host_timeout`](crate::config::ZondConfig::host_timeout),
    /// refused by this machine's sender, or on an address the sender says cannot
    /// be reached.
    ///
    /// All four are recorded the same way, so no port is left off the host. A port
    /// of an unreachable address is owed to a resume as [`Outcome::Unroutable`], as
    /// the sweep and the connect path settle one, and every other as
    /// [`Outcome::Unasked`].
    fn record_unasked_endpoint(&mut self, ip: IpAddr, port: u16) {
        self.record_port(ip, port, PortState::Unasked, None);
        let outcome = if self.core().is_unreachable(&ip) {
            Outcome::Unroutable
        } else {
            Outcome::Unasked
        };
        self.settle(outcome);
    }
}

/// Does what one pass of [`drive`] does with the probes due at `now`: retires
/// the spent ones and sends every retry, with no rate ceiling to wait on.
#[cfg(test)]
pub(crate) fn retry_due<S: RawPortScan>(scanner: &mut S, now: Instant) {
    scanner.service_retries(now);
    while let Some(retry) = scanner.core_mut().take_ready_retry(now) {
        scanner.send_held(retry, now);
    }
}

/// Runs every probe `scanner` has outstanding to the end of its schedule, so a
/// test reads the verdict silence earns, not the one a stop leaves.
#[cfg(test)]
pub(crate) fn run_out<S: RawPortScan>(scanner: &mut S) {
    let mut now = Instant::now();
    while !scanner.core().ledger.is_empty() {
        now += Duration::from_secs(60);
        retry_due(scanner, now);
    }
}

/// [`RawPortScan::send`] under the slot `claim` took, with the time it took
/// given back to the deadline.
///
/// A sender that frames its own probes resolves a neighbour inside the send
/// when [`RawProbeScan::admit`] could not hold the probe for it (the link would
/// not carry the resolution it asked for), blocking the loop for the whole
/// wait. See [`AdaptiveDeadline::allow_for_sending`].
///
/// The claim is left with the core for [`RawProbeScan::record_send`], which
/// refunds it for a send the kernel refused. A send that declined before
/// reaching the kernel, having no route, records nothing, and its slot is
/// refunded here.
fn send_timed<S: RawPortScan + ?Sized>(
    scanner: &mut S,
    claim: ProbeClaim,
    port: u16,
    position: Option<u64>,
    now: Instant,
) {
    scanner.core_mut().claimed = Some(claim);
    let started = Instant::now();
    scanner.send(claim.address(), port, position, now);
    let spent = started.elapsed();
    let core = scanner.core_mut();
    core.deadline.allow_for_sending(spent);
    if let Some(unspent) = core.claimed.take() {
        core.ctx.refund_probe(unspent);
    }
}

/// Reads every reply already waiting in `scanner`'s capture stream, without
/// waiting for more.
///
/// Called before the loop services its timers, so an answer that arrived
/// before its probe came due settles it. The loop can wake late to both at once
/// (a blocked send, a starved runtime, a loaded machine); servicing the timer
/// first would retire the probe as silent, and with one attempt file an open
/// port `NoReply`. A reply is timed from its own arrival, so reading it late
/// costs nothing else.
///
/// Bounded by what is queued on entry, so a fast stream cannot hold the loop
/// here.
fn read_waiting_replies<S: RawPortScan>(scanner: &mut S) {
    let waiting = scanner.core().transport.rx.len();
    for _ in 0..waiting {
        let Ok(reply) = scanner.core_mut().transport.rx.try_recv() else {
            // Empty after all, or closed, which the `select!` below reads as the
            // stream ending.
            return;
        };
        scanner.core_mut().audit.record_segment();
        let received_at = reply.received_at;
        scanner.handle_reply(&reply, received_at);
    }
}

/// How a run names itself in the audit and in its own failure messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuditLabels {
    /// The tag the audit line is filed under, such as `"tcp-port"`.
    pub tag: &'static str,
    /// How a port that nothing answered for is described, such as
    /// `"open|no-reply"`.
    pub silence: &'static str,
}

/// Drives one raw port scan from its first probe to its audit line.
///
/// The TCP, UDP and SCTP scanners share this loop. Copies would differ in four
/// expressions, and a stop condition fixed in one and missed in another
/// returns a smaller answer that looks like a quiet network.
///
/// One iteration:
///
/// 1. **Read the replies already waiting**, so an answer that arrived before
///    its probe came due settles it before the timer can; see
///    `read_waiting_replies`.
/// 2. **Service retries**, so the ledger is current when the stop conditions
///    ask whether anything is outstanding.
/// 3. **Decide whether to stop**, on the conditions
///    [`RawProbeScan::stop_reason`] holds.
/// 4. **Wait on whichever comes first**: another target to probe, a reply to
///    read, or the next probe coming due.
///
/// Anything still outstanding or queued when the loop ends is recorded
/// [`PortState::Unasked`], so a scan cut short neither leaves ports off the
/// host nor files a probe whose answer was on its way as silence. See
/// [`RawPortScan::resolve_remaining`] and [`RawPortScan::resolve_unasked`].
pub(crate) async fn drive<S: RawPortScan>(
    scanner: &mut S,
    mut targets: mpsc::Receiver<PlannedTarget>,
) -> Result<(), StrategyError> {
    // A transport whose capture cannot hear this scan's answers would read every
    // port as silence, so every target is recorded unasked instead.
    crate::fingerprint::load_corpus().await;
    let protocol = scanner.protocol();
    if let Some(kind) = scanner.core().transport.mismatched_for(protocol) {
        while let Some(target) = targets.recv().await {
            scanner.record_unasked(target);
        }
        return Err(StrategyError::MismatchedTransport { kind, protocol });
    }

    // The rate backstop; `RawProbeScan::window` paces the scan and is
    // re-checked after every send in the batch loop below.
    let mut send_tick = tokio::time::interval(scanner.core().send_tick);
    // Delay, not Burst: catching up on missed ticks would recreate the burst
    // this exists to prevent.
    send_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut sending_finished = false;
    // Counts what the scan was handed, including targets of another protocol;
    // the audit reads this as the denominator.
    let mut probes = 0u128;

    // The loop yields why it stopped, so the audit reports the reason taken.
    let reason = loop {
        // One reading per iteration; the arithmetic below only needs the instants
        // to agree with each other.
        let now = Instant::now();
        read_waiting_replies(scanner);
        // Before the timeouts are read, so those left in flight after the last
        // question are not judged as a share of what the target is doing. See
        // `CongestionWindow::stop_admitting`.
        if !scanner.core().questions_left(sending_finished) {
            scanner.core_mut().window.stop_admitting();
        }
        scanner.service_retries(now);

        if let Some(reason) = scanner.core().stop_reason(sending_finished) {
            break reason;
        }

        // Read before the `select!`, which borrows the receive half mutably.
        let sending = scanner.core().sending(sending_finished);
        let tick = scanner.core().tick_delay(now);

        tokio::select! {
            // One tick releases a batch, which expresses a rate finer than the timer's
            // resolution. Retries are released here too, under the same rate.
            _ = send_tick.tick(), if sending => {
                let now = Instant::now();
                // The batch is a budget of sends, spent only by a probe handed to the
                // sender. Otherwise probes held on a dead neighbour's resolution could
                // take every share each tick while live hosts behind them are never
                // asked. The loop still ends: each pass sends, takes a retry or held
                // probe due now (one held again is due later), or takes from the stream
                // until it is empty or the hold queue is full.
                let budget = scanner.core().audit.sends_attempted + scanner.core().batch as u64;
                while scanner.core().audit.sends_attempted < budget {
                    // A retry goes first, whether or not the window has room: it takes
                    // no slot, and its schedule is waiting on this send.
                    if let Some(retry) = scanner.core_mut().take_ready_retry(now) {
                        scanner.send_held(retry, now);
                        continue;
                    }
                    if !scanner.core().admitting(sending_finished) {
                        break;
                    }

                    // A probe held for its host's next slot goes next, so a scan with a
                    // gap does not starve hosts it already reached in favour of new
                    // ones.
                    if let Some(held) = scanner.core_mut().take_ready(now) {
                        scanner.send_held(held, now);
                        continue;
                    }

                    // Nowhere to hold another; leave the stream so the dispatcher feels
                    // it as it feels a full window.
                    if scanner.core().held_is_full() {
                        break;
                    }

                    match targets.try_recv() {
                        Ok(target) => {
                            probes += 1;
                            // A host that has spent its own budget: the target is
                            // recorded unasked.
                            if scanner.core().ctx.host_expired(target.ip()) {
                                scanner.record_unasked(target);
                            } else if let Some(ready) =
                                scanner.core().ctx.probe_ready_at(target.ip(), now)
                            {
                                // Asked too recently. Held, since this target is counted
                                // and a delayed probe must not read as a silent port.
                                scanner.hold_probe(target, ready);
                            } else {
                                scanner.send_probe(target);
                            }
                        }
                        // Nothing waiting yet; blocking here would hold the receive
                        // half across the whole batch.
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            sending_finished = true;
                            break;
                        }
                    }
                }
            }

            res = scanner.core_mut().transport.rx.recv() => {
                match res {
                    Some(reply) => {
                        scanner.core_mut().audit.record_segment();
                        // When the capture thread took the segment; see
                        // `CapturedSegment::received_at`.
                        let received_at = reply.received_at;
                        scanner.handle_reply(&reply, received_at);
                    }
                    None => break StopReason::StreamClosed,
                }
            }

            // Wakes when the next probe is due, so a retry is sent on time when
            // nothing else wakes the loop.
            _ = tokio::time::sleep(tick) => {}
        }
    };

    // First, so every port of an address the kernel never resolved takes the
    // same verdict, wherever its probe was waiting.
    scanner.core_mut().conclude_pending_neighbors();
    scanner.resolve_remaining();
    // Held probes, after the ledger: a held retry is accounted for by
    // `resolve_remaining`, a held first attempt only here.
    scanner.resolve_held();
    // Targets still in the channel, counted into `probes` so the audit's
    // denominator is what the scan was handed. Closed first, so the router
    // cannot slip a target in behind the drain; it finds this scanner gone and
    // records the target unasked itself.
    targets.close();
    probes += scanner.resolve_unasked(&mut targets);

    let kind = scanner.kind();
    let labels = scanner.audit_labels();
    let silence = scanner.silence_means();
    scanner
        .core_mut()
        .finish(kind, labels.tag, labels.silence, silence, probes, reason);
    Ok(())
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use crate::scanner::pacing::congestion::WindowLimits;
    use crate::scanner::session::ScanSession;
    use crate::transport::probe::{Emission, ProbeSender, ProbeTransport, SendError};

    /// A sender that swallows everything. These tests ask when the loop stops,
    /// which depends on the ledger and the deadline alone.
    #[derive(Default)]
    struct NullSender;

    impl ProbeSender for NullSender {
        fn send(
            &self,
            _segment: &[u8],
            _src: IpAddr,
            _dst: IpAddr,
            _zone: Option<u32>,
            _emission: Emission,
        ) -> Result<(), SendError> {
            Ok(())
        }
    }

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

    /// A core with a generous deadline and a one-attempt retry budget, so the
    /// only thing that moves a verdict is what the test puts in the ledger.
    fn core() -> (RawProbeScan<()>, ScanSession) {
        let (session, ctx) = ScanSession::new();
        let (_tx, rx) = tokio::sync::mpsc::channel(1024);
        let core = RawProbeScan {
            resolver: SourceResolver::from_links(&[]),
            ctx,
            transport: ProbeTransport::from_parts(Box::new(NullSender), rx),
            deadline: AdaptiveDeadline::new(super::super::raw::DEADLINE_CONFIG, 8),
            ledger: ProbeLedger::new(super::super::raw::RETRY_POLICY, 8),
            due: Vec::new(),
            src_port: 54_321,
            emission: Emission::routed(),
            shaping: SegmentShaping::default(),
            decoys: Vec::new(),
            claimed: None,
            send_failure: None,
            unasked_refused: 0,
            retries_refused: 0,
            unasked_unsent: 0,
            unreachable: std::collections::BTreeSet::new(),
            held_down: HoldDowns::default(),
            held_allowed: HeldAllowance::default(),
            neighbors: NeighborGates::default(),
            audit: ProbeAudit::new(),
            window: CongestionWindow::new(WindowLimits::fixed(4)),
            send_tick: Duration::from_millis(1),
            batch: 1,
            max_unresolved: 64,
            held: std::collections::BinaryHeap::new(),
            retries: std::collections::BinaryHeap::new(),
        };
        (core, session)
    }

    /// The one failure `finish` files for ports never seen leaving.
    fn unsent_failure(core: &mut RawProbeScan<()>) -> String {
        core.unasked_unsent = 2;
        core.finish(
            ScannerKind::SynPort,
            "syn-port",
            "no-reply",
            PortState::NoReply,
            2,
            StopReason::AllResponded,
        );
        let failures = core.ctx.failures_snapshot();
        assert_eq!(failures.len(), 1, "{failures:?}");
        failures[0].reason().to_owned()
    }

    /// A port scan's deadline outlasts the slowest pace each limit allows, worked
    /// out from the numbers: the window at its floor with every question at the
    /// longest timeout, every attempt through the rate ceiling, and every attempt
    /// waiting out the gap at one host.
    #[test]
    fn a_port_scan_outlasts_the_slowest_pace_each_of_its_limits_allows() {
        const PORTS: usize = 65_535;
        let retry = PORT_RETRY_POLICY;
        let attempts = f64::from(retry.max_attempts);
        let hundred = NonZeroU32::new(100).expect("non-zero");
        let gap = Duration::from_millis(25);

        for (case, rate, host_gap) in [
            ("unlimited", TCP_PORT_RATE_CEILING, None),
            ("at a hundred a second", hundred, None),
            ("with a gap at one host", TCP_PORT_RATE_CEILING, Some(gap)),
        ] {
            let given = deadline_for(
                super::super::raw::DEADLINE_CONFIG,
                &retry,
                TCP_PORT_WINDOW,
                rate,
                host_gap,
                PORTS,
            )
            .max_budget
            .for_target_count(PORTS)
            .as_secs_f64();

            // Two seconds at the ceiling, spread by up to 30%, over sixteen.
            let window = PORTS as f64 * 2.0 * 1.3 / 16.0;
            let wire = PORTS as f64 * attempts / f64::from(rate.get());
            let spacing = PORTS as f64 * attempts * host_gap.unwrap_or_default().as_secs_f64();
            for (limit, needed) in [("window", window), ("rate", wire), ("gap", spacing)] {
                assert!(
                    given >= needed,
                    "{case}: the {limit} needs {needed:.0} s and the scan is given {given:.0} s"
                );
            }
        }
    }

    /// Ports never seen leaving are blamed on this machine only where the
    /// capture that would have seen them was still listening.
    ///
    /// The capture that sees a probe leave also hears its answer. One that died
    /// sees neither, so blaming the unseen ports on sending would claim this
    /// machine swallowed probes that may have gone out.
    #[test]
    fn ports_unseen_after_a_capture_died_are_not_blamed_on_sending() {
        let (mut core, _session) = core();
        let (_tx, rx) = tokio::sync::mpsc::channel(1024);
        core.transport = ProbeTransport::from_parts_deaf(Box::new(NullSender), rx);

        let reason = unsent_failure(&mut core);
        assert!(
            reason.contains("a capture stopped early"),
            "the dead capture goes unnamed: {reason}"
        );
        assert!(!reason.contains("never put them on the wire"), "{reason}");
    }

    /// With every capture listening, a probe never seen leaving is blamed on
    /// sending, in one readable sentence.
    #[test]
    fn ports_unseen_with_every_capture_listening_are_blamed_on_sending() {
        let (mut core, _session) = core();

        let reason = unsent_failure(&mut core);
        assert!(reason.contains("never put them on the wire"), "{reason}");
        assert!(
            !reason.contains("  "),
            "the sentence carries a run of spaces from its source: {reason:?}"
        );
    }

    /// [`core`] with a gap between probes at one host, for the queue tests.
    fn spaced_core(gap: Duration) -> (RawProbeScan<()>, ScanSession) {
        let (session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(gap))
            .build();
        let (_tx, rx) = tokio::sync::mpsc::channel(1024);
        let core = RawProbeScan {
            resolver: SourceResolver::from_links(&[]),
            ctx,
            transport: ProbeTransport::from_parts(Box::new(NullSender), rx),
            deadline: AdaptiveDeadline::new(super::super::raw::DEADLINE_CONFIG, 8),
            ledger: ProbeLedger::new(super::super::raw::RETRY_POLICY, 8),
            due: Vec::new(),
            src_port: 54_321,
            emission: Emission::routed(),
            shaping: SegmentShaping::default(),
            decoys: Vec::new(),
            claimed: None,
            send_failure: None,
            unasked_refused: 0,
            retries_refused: 0,
            unasked_unsent: 0,
            unreachable: std::collections::BTreeSet::new(),
            held_down: HoldDowns::default(),
            held_allowed: HeldAllowance::default(),
            neighbors: NeighborGates::default(),
            audit: ProbeAudit::new(),
            window: CongestionWindow::new(WindowLimits::fixed(4)),
            send_tick: Duration::from_millis(1),
            batch: 1,
            max_unresolved: 64,
            held: std::collections::BinaryHeap::new(),
            retries: std::collections::BinaryHeap::new(),
        };
        (core, session)
    }

    /// The queue yields the probe whose host is ready soonest, whatever order
    /// the entries were held in.
    #[test]
    fn the_earliest_slot_comes_off_the_queue_first() {
        let (mut core, _session) = spaced_core(Duration::from_secs(3600));
        let now = Instant::now();

        // Held out of order; the heap orders them.
        core.hold(TARGET, 80, Some(0), now + Duration::from_secs(30));
        core.hold(TARGET, 22, Some(1), now + Duration::from_secs(10));
        core.hold(TARGET, 443, Some(2), now + Duration::from_secs(20));

        assert!(
            core.take_ready(now).is_none(),
            "nothing is ready yet, and nothing is handed back early"
        );

        let first = core
            .take_ready(now + Duration::from_secs(15))
            .expect("the ten-second slot has come round");
        assert_eq!(first.port, 22);
    }

    /// A recorded instant is re-checked, not trusted.
    ///
    /// A retry to the same host moves its slot after an entry is queued; trusting
    /// the stored instant would send a probe inside the gap the caller asked
    /// for.
    #[test]
    fn a_slot_that_moved_after_the_probe_was_held_is_re_checked() {
        let gap = Duration::from_secs(3600);
        let (mut core, _session) = spaced_core(gap);
        let now = Instant::now();

        // Held as though its host were ready immediately.
        core.hold(TARGET, 80, Some(0), now);
        // And then the host is probed, which moves the real slot an hour out.
        let _ = core
            .ctx
            .spacing
            .claim_with(TARGET, || now)
            .expect("a host nothing has probed");

        assert!(
            core.take_ready(now).is_none(),
            "the stored instant said now; the host says otherwise and the host wins"
        );
        assert_eq!(
            core.held.len(),
            1,
            "and the probe is still held, not dropped"
        );

        assert!(
            core.take_ready(now + gap).is_some(),
            "once the gap has really run, it is handed back"
        );
    }

    /// A held probe is still to send, so a dry stream does not conclude the scan
    /// while one is waiting; otherwise a delayed port would be reported asked and
    /// silent.
    #[test]
    fn a_held_probe_keeps_the_scan_open_after_the_stream_ends() {
        let (mut core, _session) = spaced_core(Duration::from_secs(3600));
        let now = Instant::now();

        core.hold(TARGET, 80, Some(0), now + Duration::from_secs(1));

        assert_eq!(
            core.stop_reason(true),
            None,
            "the stream is done and the ledger empty, but a probe is still owed"
        );
        assert!(
            core.admitting(true),
            "and the send path stays open, since it is the only thing that empties the queue"
        );

        let _ = core.take_ready(now + Duration::from_secs(1));
        core.held.clear();
        assert_eq!(
            core.stop_reason(true),
            Some(StopReason::AttemptsSpent),
            "with the queue empty too, waiting cannot change what this found"
        );
    }

    /// The queue bounds the stream, not the send path, since sending is what
    /// empties it.
    #[test]
    fn a_full_queue_stops_the_stream_and_not_the_sending() {
        let (mut core, _session) = spaced_core(Duration::from_secs(3600));
        let now = Instant::now();

        for port in 0..core.max_unresolved {
            core.hold(TARGET, port as u16, Some(port as u64), now);
        }

        assert!(core.held_is_full());
        assert!(
            core.admitting(false),
            "a full queue must not close the one path that drains it"
        );
    }

    /// An empty ledger means "everything answered or written off" only once
    /// nothing is left to ask. A link that stopped accepting sends leaves the
    /// ledger empty while the stream is full; stopping there abandoned thirty-one
    /// thousand queued targets in one measured run.
    #[test]
    fn an_empty_ledger_does_not_end_a_scan_that_still_has_targets_coming() {
        let (core, _session) = core();

        assert_eq!(
            core.stop_reason(false),
            None,
            "the target stream is still open, so nothing has been concluded"
        );
        assert_eq!(
            core.stop_reason(true),
            Some(StopReason::AttemptsSpent),
            "with the stream done and nothing outstanding, waiting cannot help"
        );
    }

    /// With probes still waiting on their timers, quiet is what the retry
    /// schedule expects.
    #[test]
    fn an_outstanding_probe_holds_the_scan_open_past_a_dry_target_stream() {
        let (mut core, _session) = core();
        core.ledger.arm(TARGET, (TARGET, 80), (), 0, Instant::now());

        assert_eq!(
            core.stop_reason(true),
            None,
            "a probe is still within its retry schedule"
        );
    }

    /// An abort is checked before anything else, so a scan winds down promptly.
    #[test]
    fn an_abort_outranks_every_other_reason() {
        let (mut core, _session) = core();
        core.ledger.arm(TARGET, (TARGET, 80), (), 0, Instant::now());
        core.ctx.handle.abort();

        assert_eq!(core.stop_reason(false), Some(StopReason::Aborted));
    }

    /// The window makes a scan self-pacing: probes leave as earlier ones are
    /// resolved.
    #[test]
    fn the_ledger_stops_admitting_at_the_window() {
        let (mut core, _session) = core();
        assert!(core.admitting(false), "an empty ledger admits");

        for _ in 0..core.window.capacity() {
            core.window.record_send();
        }

        assert!(
            !core.admitting(false),
            "admitting past the window grows correlation state for nothing"
        );
        assert!(
            !core.admitting(true),
            "a finished stream never admits, window or not"
        );
    }

    /// A reply to the first attempt says the target is keeping up; a reply to a
    /// later one says the first question did not survive, which separates being
    /// too fast from meeting a firewall.
    #[test]
    fn the_attempt_that_answered_is_what_moves_the_window() {
        let (mut core, _session) = core();
        core.window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));

        core.record_answer(&Resolution {
            payload: 0u64,
            rtt: None,
            attempts: 1,
            answered_attempt: Some(1),
        });
        assert!(core.window.capacity() > 64, "a clean answer buys headroom");

        let grown = core.window.capacity();
        core.record_answer(&Resolution {
            payload: 0u64,
            rtt: None,
            attempts: 2,
            answered_attempt: Some(2),
        });
        assert!(
            core.window.capacity() < grown,
            "an answer that needed a retry is loss, and loss cuts the window"
        );
    }

    /// A send the kernel refused is backpressure from this machine, whatever the
    /// cause (a full interface queue, a neighbour that stopped resolving under
    /// load). Measured: seven thousand `No route to host` failures in one run at an
    /// unchanged window, because nothing was reading them.
    #[test]
    fn a_send_the_kernel_refused_cuts_the_window() {
        let full = SendError::Refused("No buffer space available".to_string());
        let unresolved = SendError::Unresolved("192.0.2.1 did not answer".to_string());

        for (refusal, answered_before) in [(&full, false), (&unresolved, true)] {
            let (mut core, _session) = core();
            core.window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));
            if answered_before {
                answer_once(&mut core, TARGET);
            }

            core.record_send((TARGET, 80), Err(refusal), true);

            assert!(
                core.window.capacity() < 64,
                "the local stack refusing is the least ambiguous evidence there is: {refusal}"
            );
            assert_eq!(
                core.window.in_flight(),
                0,
                "and a probe that never left takes no slot"
            );
            assert!(core.send_failure.is_some(), "and it is this host's fault");
        }
    }

    /// A refused send costs the default console one short line: the run's
    /// failure, with the count and the cause. The line noticing the first refusal
    /// is at -vv only, since a front end shows every error.
    #[test]
    fn a_refused_send_is_told_once_in_one_short_line() {
        let (mut core, _session) = core();

        let said = crate::logging::logged(|| {
            core.record_send((TARGET, 80), Err(&SendError::OutOfDescriptors), true);
        });

        assert!(
            said.iter()
                .all(|line| line.level != tracing::Level::ERROR && line.verbosity >= 2),
            "{said:?}"
        );
        assert_eq!(
            core.refusals_failure().as_deref(),
            Some("1 port unasked, probes not sent (file limit reached)")
        );
    }

    /// A source lookup that failed for want of a descriptor is a probe this
    /// machine could not send. Its host was never asked about, so it is not filed
    /// unreachable; that would read a momentarily full table as a host with no
    /// route and drop every later probe to it.
    #[cfg(unix)]
    #[test]
    fn a_source_lookup_short_of_descriptors_is_a_shortage_not_an_unreachable_host() {
        use crate::system::interface::RouteAnswer;

        let (mut core, _session) = core();
        core.resolver = SourceResolver::from_links(&[]).asking_with(|_: IpAddr| {
            RouteAnswer::Unasked(std::io::Error::from_raw_os_error(libc::EMFILE))
        });

        assert_eq!(core.source_for((TARGET, 80), true), None);
        assert!(
            !core.is_unreachable(&TARGET),
            "the host was filed unreachable"
        );
        assert_eq!(
            core.refusals_failure().as_deref(),
            Some("1 port unasked, probes not sent (file limit reached)")
        );
    }

    /// A source lookup the routing table gave no answer to is a probe this
    /// machine could not send, in the lookup's words, and its host is not filed
    /// unreachable: one lookup refused with `EHOSTDOWN` would otherwise read as a
    /// route refusing a live neighbour and leave every port unasked. Nor are the
    /// words read as a send's, where `EHOSTDOWN` is a neighbour that did not
    /// answer.
    #[cfg(unix)]
    #[test]
    fn a_source_lookup_the_routing_table_did_not_answer_leaves_its_host_to_be_asked_again() {
        use crate::system::interface::{Link, LinkAddress, RouteAnswer};

        let (mut core, _session) = core();
        let segment = LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24);
        core.resolver =
            SourceResolver::from_links(&[Link::new("test0", 1).with_addresses(vec![segment])])
                .asking_with(|_: IpAddr| RouteAnswer::connect_refused(libc::EHOSTDOWN));

        assert_eq!(core.source_for((TARGET, 80), true), None);
        assert!(
            !core.is_unreachable(&TARGET),
            "the host was filed unreachable"
        );
        assert!(!core.resolver.refused_by_route(TARGET));
        let failure = core.refusals_failure().expect("the unsent probe is said");
        assert!(failure.contains("route lookup failed"), "{failure}");
    }

    /// The kernel's refusal to send to a neighbour it recently gave up on
    /// (`EHOSTDOWN` on macOS) is waited out and asked again, not filed as the
    /// host's verdict, so a neighbour that slept through one resolution does not
    /// leave every port unasked. The refusal costs nothing else: the kernel sent
    /// nothing, and not for want of room.
    #[cfg(unix)]
    #[test]
    fn a_host_the_kernel_holds_down_is_asked_again_after_the_hold_down() {
        let (mut core, _session) = core();
        core.window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));
        let refused = SendError::from_io(std::io::Error::from_raw_os_error(libc::EHOSTDOWN));

        let before = Instant::now();
        core.record_send((TARGET, 80), Err(&refused), true);

        assert!(
            !core.is_unreachable(&TARGET),
            "the host was filed unreachable on one hold-down"
        );
        match core.admit(TARGET, Instant::now()) {
            Admission::Hold(ready) => assert!(
                ready >= before + core.held_down.hold_down_for,
                "held for less than the hold-down"
            ),
            other => panic!("the host's next probe was not held: {other:?}"),
        }
        assert_eq!(core.window.capacity(), 64, "read as congestion");
        assert!(core.send_failure.is_none(), "read as this host's fault");
        assert_eq!(core.unasked_refused, 0);

        let after = before + core.held_down.hold_down_for + Duration::from_secs(1);
        assert_eq!(
            core.admit(TARGET, after),
            Admission::Send,
            "and asked again after it"
        );
    }

    /// A second hold-down, after a resolution begun once the first ended also
    /// went unanswered, is the kernel's verdict. The bound keeps an absent
    /// neighbour from holding its ports one hold-down at a time for the whole
    /// scan.
    #[cfg(unix)]
    #[test]
    fn a_host_held_down_again_after_waiting_one_out_is_unreachable() {
        let (mut core, _session) = core();
        let refused = SendError::from_io(std::io::Error::from_raw_os_error(libc::EHOSTDOWN));

        core.record_send((TARGET, 80), Err(&refused), true);
        core.held_down.lift(TARGET);
        core.record_send((TARGET, 80), Err(&refused), true);

        assert!(core.is_unreachable(&TARGET));
        assert_eq!(core.admit(TARGET, Instant::now()), Admission::Unreachable);
    }

    /// A hold-down is given to the deadline, or a scan sized in seconds would end
    /// inside macOS's twenty with the held host's every port unasked.
    #[cfg(unix)]
    #[test]
    fn a_hold_down_is_given_to_the_deadline() {
        use crate::scanner::pacing::deadline::AdaptiveDeadlineConfig;
        use crate::scanner::pacing::timer::ScanBudget;

        let (mut core, _session) = core();
        let spent = ScanBudget::new(Duration::ZERO, Duration::ZERO, Duration::ZERO);
        core.deadline = AdaptiveDeadline::new(
            AdaptiveDeadlineConfig::new(spent, spent, Duration::ZERO, Duration::ZERO, 4.0, 8),
            1,
        );
        core.held_down.hold_down_for = Duration::from_secs(3600);
        let refused = SendError::from_io(std::io::Error::from_raw_os_error(libc::EHOSTDOWN));

        core.record_send((TARGET, 80), Err(&refused), true);

        assert!(!core.deadline.hard_deadline_passed());
    }

    /// A core whose transport reads `state` as the kernel's word on
    /// [`TARGET`]'s neighbour, with [`TARGET`] on one of this host's segments,
    /// and the number of times the table was read.
    fn core_reading(
        state: std::sync::Arc<std::sync::Mutex<Option<NeighborState>>>,
    ) -> (
        RawProbeScan<()>,
        ScanSession,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use crate::system::interface::{Link, LinkAddress};
        use crate::transport::kernel_neighbors::{KernelNeighbors, NeighborTable};

        let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = std::sync::Arc::clone(&reads);
        let table = KernelNeighbors::with_reader(Box::new(move || {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let state = *state.lock().expect("the test's state");
            Ok(state
                .map(|state| NeighborTable::from([(TARGET, state)]))
                .unwrap_or_default())
        }));
        let (mut core, session) = core();
        let (_tx, rx) = tokio::sync::mpsc::channel(1024);
        core.transport =
            ProbeTransport::from_parts(Box::new(NullSender), rx).with_kernel_neighbors(table);
        core.resolver = SourceResolver::from_links(&[Link::new("test0", 1).with_addresses(vec![
            LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24),
        ])]);
        (core, session, reads)
    }

    /// A probe behind the one that started the kernel's resolution of a
    /// neighbour waits for the resolution, and goes once the neighbour answers.
    ///
    /// Linux queues a write to a neighbour it is still resolving, charged to the
    /// socket, so writing freely to a neighbour that never answers fills the send
    /// buffer and gets every write refused, the live hosts' too. A live neighbour
    /// costs one short hold.
    #[test]
    fn a_probe_behind_an_unresolved_neighbour_waits_for_the_resolution() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (mut core, _session, reads) = core_reading(std::sync::Arc::clone(&state));

        assert_eq!(
            core.admit(TARGET, Instant::now()),
            Admission::Send,
            "the first starts it"
        );

        *state.lock().unwrap() = Some(NeighborState::Resolving);
        let now = Instant::now();
        assert_eq!(
            core.admit(TARGET, now),
            Admission::Hold(now + NEIGHBOR_RECHECK),
            "the next waits on the kernel rather than queueing behind it"
        );

        *state.lock().unwrap() = Some(NeighborState::Resolved);
        std::thread::sleep(NEIGHBOR_RECHECK);
        assert_eq!(core.admit(TARGET, Instant::now()), Admission::Send);
        let read = reads.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(core.admit(TARGET, Instant::now()), Admission::Send);
        assert_eq!(
            reads.load(std::sync::atomic::Ordering::SeqCst),
            read,
            "a neighbour seen answering is not read about again"
        );
        assert!(!core.is_unreachable(&TARGET));
    }

    /// A neighbour the kernel gave up on twice is filed unreachable, sent nothing
    /// more, and is no fault of this host's. After the first failure one probe
    /// goes, since its write makes the kernel ask again.
    #[test]
    fn a_neighbour_the_kernel_gave_up_on_twice_is_filed_unreachable_without_a_send() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (mut core, _session, _reads) = core_reading(std::sync::Arc::clone(&state));
        assert_eq!(core.admit(TARGET, Instant::now()), Admission::Send);

        *state.lock().unwrap() = Some(NeighborState::Failed);
        assert_eq!(
            core.admit(TARGET, Instant::now()),
            Admission::Send,
            "one unanswered resolution was taken as the verdict"
        );
        assert!(!core.is_unreachable(&TARGET));
        assert_eq!(core.admit(TARGET, Instant::now()), Admission::Unreachable);
        assert!(core.is_unreachable(&TARGET), "the address is filed");
        assert!(
            core.send_failure.is_none(),
            "and nothing on this host failed"
        );
    }

    /// A second resolution is given to the deadline, or a scan sized in seconds
    /// would end during it with the host filed pending and every port unasked.
    #[test]
    fn a_second_resolution_is_given_to_the_deadline() {
        use crate::scanner::pacing::deadline::AdaptiveDeadlineConfig;
        use crate::scanner::pacing::timer::ScanBudget;

        let state = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (mut core, _session, _reads) = core_reading(std::sync::Arc::clone(&state));
        let spent = ScanBudget::new(Duration::ZERO, Duration::ZERO, Duration::ZERO);
        core.deadline = AdaptiveDeadline::new(
            AdaptiveDeadlineConfig::new(spent, spent, Duration::ZERO, Duration::ZERO, 4.0, 8),
            1,
        );
        assert_eq!(core.admit(TARGET, Instant::now()), Admission::Send);

        *state.lock().unwrap() = Some(NeighborState::Failed);
        assert_eq!(core.admit(TARGET, Instant::now()), Admission::Send);

        assert!(!core.deadline.hard_deadline_passed());
    }

    /// A probe that ran its whole schedule while the kernel was still resolving
    /// its neighbour never left, so it is read as pending on the resolution.
    #[test]
    fn a_probe_that_outlived_an_unanswered_resolution_is_pending_on_it() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (mut core, _session, _reads) = core_reading(std::sync::Arc::clone(&state));
        assert_eq!(core.admit(TARGET, Instant::now()), Admission::Send);

        *state.lock().unwrap() = Some(NeighborState::Resolving);
        assert_eq!(
            core.pending_neighbor(TARGET),
            Some(NeighborState::Resolving)
        );
        assert!(
            !core.is_unreachable(&TARGET),
            "the kernel has not given up, so neither has the scan"
        );
    }

    /// A host still waiting on the kernel when the scan ends is filed
    /// unreachable, even when its probe ran out of attempts and sits in the hold
    /// queue, off the ledger.
    #[test]
    fn a_host_still_waiting_on_its_neighbour_at_the_end_is_filed_unreachable() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (mut core, _session, _reads) = core_reading(std::sync::Arc::clone(&state));
        assert_eq!(core.admit(TARGET, Instant::now()), Admission::Send);
        assert!(core.ledger.is_empty(), "no probe of it is on the ledger");

        *state.lock().unwrap() = Some(NeighborState::Resolving);
        core.conclude_pending_neighbors();

        assert!(core.is_unreachable(&TARGET));
    }

    /// A host the routing table names no neighbour for has nothing to wait on,
    /// so the table is never read for it.
    #[test]
    fn a_host_with_no_neighbour_in_the_way_is_never_read_about() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(Some(NeighborState::Failed)));
        let (mut core, _session, reads) = core_reading(state);
        core.resolver = SourceResolver::from_links(&[]);

        for _ in 0..3 {
            assert_eq!(core.admit(TARGET, Instant::now()), Admission::Send);
        }
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// Hosts behind a gateway that never answers its address resolution send one
    /// probe between them per resolution, and are all filed unreachable on the
    /// gateway's verdict.
    ///
    /// A routed host's writes queue on the gateway's neighbour entry. Written
    /// freely, they are taken by the kernel, charged to the socket and dropped
    /// three seconds later, reading as silence and filling the send buffer until
    /// writes to every host are refused.
    #[test]
    fn hosts_behind_a_gateway_that_never_answers_wait_on_it_and_are_unreached() {
        const GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254));
        const ROUTED: [IpAddr; 2] = [
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)),
        ];
        use crate::transport::kernel_neighbors::{KernelNeighbors, NeighborTable};

        let state = std::sync::Arc::new(std::sync::Mutex::new(None));
        let read = std::sync::Arc::clone(&state);
        let table = KernelNeighbors::with_reader(Box::new(move || {
            let state = *read.lock().expect("the test's state");
            Ok(state
                .map(|state| NeighborTable::from([(GATEWAY, state)]))
                .unwrap_or_default())
        }))
        .routing(Box::new(|address| {
            Ok(ROUTED.contains(&address).then_some(GATEWAY))
        }));
        let (mut core, _session) = core();
        let (_tx, rx) = tokio::sync::mpsc::channel(1024);
        core.transport =
            ProbeTransport::from_parts(Box::new(NullSender), rx).with_kernel_neighbors(table);

        assert_eq!(
            core.admit(ROUTED[0], Instant::now()),
            Admission::Send,
            "the first probe through the gateway starts its resolution"
        );
        *state.lock().unwrap() = Some(NeighborState::Resolving);
        let now = Instant::now();
        assert_eq!(
            core.admit(ROUTED[1], now),
            Admission::Hold(now + NEIGHBOR_RECHECK),
            "another host behind it waits rather than queueing behind it"
        );

        *state.lock().unwrap() = Some(NeighborState::Failed);
        std::thread::sleep(NEIGHBOR_RECHECK);
        assert_eq!(
            core.admit(ROUTED[1], Instant::now()),
            Admission::Send,
            "a probe through the gateway has the kernel ask for it again"
        );
        assert_eq!(
            core.admit(ROUTED[1], Instant::now()),
            Admission::Unreachable
        );
        assert_eq!(
            core.pending_neighbor(ROUTED[0]),
            Some(NeighborState::Failed),
            "the host whose probe started it is read through the gateway too"
        );
        core.conclude_pending_neighbors();
        for host in ROUTED {
            assert!(core.is_unreachable(&host), "{host} is unreached");
        }
    }

    /// An unreachable address that has never answered is an absent host, not a
    /// busy path; a dead neighbour among live hosts must not cut the window for
    /// all of them.
    #[test]
    fn an_address_that_cannot_be_reached_is_not_congestion() {
        let (mut core, _session) = core();
        core.window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));
        let dead = SendError::Unresolved("192.0.2.1 did not answer".to_string());

        core.record_send((TARGET, 80), Err(&dead), true);

        assert_eq!(core.window.capacity(), 64, "the window is untouched");
        assert!(
            core.send_failure.is_none(),
            "and nothing on this host failed"
        );
        assert!(core.is_unreachable(&TARGET), "the address is what is filed");
    }

    /// Marks `host` as having answered one probe, the way a reply resolving it
    /// would.
    fn answer_once(core: &mut RawProbeScan<()>, host: IpAddr) {
        core.ledger.arm(host, (host, 1), (), 0, Instant::now());
        core.ledger
            .resolve(&(host, 1), Some(()), Instant::now())
            .expect("the armed probe resolves");
    }

    /// Silence from a host that has never answered is a firewall or a dead
    /// address, not congestion; slowing down would learn nothing and crawl against
    /// the hosts hardest to finish.
    #[test]
    fn silence_from_a_host_that_never_answered_opens_the_window() {
        let (mut core, _session) = core();
        core.window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));

        core.window.record_send();
        core.judge_timeout(TARGET, PortState::NoReply);

        assert!(
            core.window.capacity() >= 64,
            "nothing this host did says the path is busy"
        );
        assert_eq!(core.window.in_flight(), 0, "and the slot went back");
    }

    /// Silence from a host answering most of what it is asked means it is failing
    /// to keep up.
    ///
    /// Measured against a Raspberry Pi answering three quarters of a thousand
    /// probes: without this signal the window never cut, and the remaining quarter
    /// was reported as a firewall that did not exist, a different set of ports on
    /// every run.
    #[test]
    fn silence_from_a_host_that_is_answering_cuts_the_window() {
        let (mut core, _session) = core();
        core.window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));

        // One port answered, which makes this host's silence meaningful.
        let now = Instant::now();
        core.ledger.arm(TARGET, (TARGET, 22), (), 0, now);
        core.ledger.resolve(&(TARGET, 22), None, now);

        core.window.record_send();
        core.judge_timeout(TARGET, PortState::NoReply);

        assert!(
            core.window.capacity() < 64,
            "a host that talks and then goes quiet is being outrun"
        );
        assert_eq!(core.window.in_flight(), 0, "and the slot still went back");
    }

    /// Silence from a host answering no more than one probe in ten is its
    /// firewall, and opens the window as a host that answers nothing does.
    ///
    /// Read as loss, a Windows machine with one port open in a thousand held the
    /// scan at the window's floor for every other port and every host beside it.
    #[test]
    fn silence_from_a_firewall_that_lets_a_port_through_opens_the_window() {
        let (mut core, _session) = core();
        core.window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));
        answer_once(&mut core, TARGET);

        let now = Instant::now();
        let mut due = Vec::new();
        for port in 2..=10 {
            core.ledger.arm(TARGET, (TARGET, port), (), 0, now);
        }
        core.ledger
            .drain_due(now + Duration::from_secs(10), &mut due);
        for _ in &due {
            core.window.record_send();
            core.judge_timeout(TARGET, PortState::NoReply);
        }

        assert_eq!(due.len(), 9, "every probe's first timeout was read");
        assert!(
            core.window.capacity() > 64,
            "one answer in ten probes is a firewall, and asking it more slowly \
             would not change what it lets through"
        );
    }

    /// **A host verdict answers whether it was recorded**, and the usual case is
    /// a host already in the store, since a port scan mostly probes hosts an
    /// earlier phase found.
    #[test]
    fn a_host_down_filed_against_a_host_already_known_reports_it_was_recorded() {
        let (mut core, session) = core();
        let router: IpAddr = "198.51.100.1".parse().expect("a literal address");
        core.ctx.update_host(TARGET, |_| {});
        core.ledger.arm(TARGET, (TARGET, 80), (), 0, Instant::now());

        assert!(
            core.record_host_down(&(TARGET, 80), Some(()), router),
            "an unreachable naming a live probe is on the host's record"
        );
        assert_eq!(
            session.hosts().get(TARGET).map(|host| host.status()),
            Some(HostStatus::Down)
        );
    }

    /// A host unreachable from this host's own address is its kernel giving up on
    /// a neighbour, so the address is filed unreachable, not down.
    ///
    /// Linux sends one to itself for each write dropped with a failed resolution,
    /// and whether the loopback capture catches it is chance; read as `Down`,
    /// identical dead neighbours would get different statuses.
    #[test]
    fn a_host_unreachable_from_this_host_itself_files_the_address_unreachable() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (mut core, session, _reads) = core_reading(state);
        let own: IpAddr = "192.0.2.1".parse().expect("a literal address");
        core.ledger.arm(TARGET, (TARGET, 80), (), 0, Instant::now());

        assert!(core.record_host_down(&(TARGET, 80), Some(()), own));

        assert_ne!(
            session.hosts().get(TARGET).map(|host| host.status()),
            Some(HostStatus::Down),
            "nothing on the network answered for the address"
        );
        assert!(
            core.is_unreachable(&TARGET),
            "the address is filed unreached"
        );
    }

    /// `false` means nothing reached the store: an address the scan's exclusions
    /// forbid is dropped there, whatever probe the message names.
    #[test]
    fn a_host_down_about_an_excluded_address_reports_nothing_recorded() {
        let (mut core, _) = core();
        let mut excluded = crate::model::ip::set::IpSet::new();
        excluded.insert_range("192.0.2.0/24".parse().expect("a valid range"));
        let (session, ctx) = ScanSession::builder()
            .excluding(crate::model::exclusion::Exclusions::new(excluded))
            .build();
        core.ctx = ctx;
        let router: IpAddr = "198.51.100.1".parse().expect("a literal address");
        core.ledger.arm(TARGET, (TARGET, 80), (), 0, Instant::now());

        assert!(!core.record_host_down(&(TARGET, 80), Some(()), router));
        assert!(session.hosts().get(TARGET).is_none());
    }
}
