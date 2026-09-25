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
//! four things becomes true. Only the packets and what they prove differ.
//!
//! Two pieces make up that machine, and the division between them is the point
//! of the module. [`RawProbeScan`] is the state a raw port scan carries and the
//! questions it can answer about itself. [`drive`] is the loop that asks them,
//! and [`RawPortScan`] is the short list of things it cannot work out alone.
//!
//! [`tcp`], [`udp`] and [`sctp`] each hold a [`RawProbeScan`] and implement
//! [`RawPortScan`]. What stays with them is what is genuinely protocol
//! knowledge: how a probe is built, how a reply is recognised, what an answer
//! proves about a port and its host, and what silence means once a probe has
//! spent its budget. [`idle`] is the fourth and is not built this way, because
//! it reads its verdicts off a third party's counter rather than off a reply to
//! anything it sent.
//!
//! ## Why this line and not a different one
//!
//! The split is drawn where the TCP and UDP scanners are *identical*, not
//! merely similar. Their stop conditions, their pacing arithmetic, their
//! unreachable handling, their audit tails and the loop that drives all of it
//! would be duplicated with no difference but a label, while their probe
//! construction and their evidence mapping differ in almost every line, because
//! a RST and an ICMP port unreachable prove genuinely different things. Sharing
//! the first and not the second is what keeps this an abstraction rather than a
//! coincidence.
//!
//! Where two copies of the loop would differ, they differ in four expressions:
//! which protocol to accept, what silence means, and two labels.
//! [`RawPortScan`] is those four, written down.
//!
//! ## Why the shared half is the half worth sharing
//!
//! The four stop conditions are the subtlest code in either scanner and the
//! least visible when wrong. Each one is a claim about what silence means, and
//! stopping on the wrong one does not fail: it returns a smaller answer that
//! looks exactly like a quiet network. Two copies invite exactly that: a stop
//! condition fixed in one scanner and left standing in its twin, because
//! nothing ties the two together. One copy is what makes that class of
//! divergence impossible rather than merely unlikely.
//!
//! ## Writing a fourth one
//!
//! Everything here is public because the argument above applies to a scanner
//! this engine does not have. The SCTP INIT scan is built this way and needs
//! nothing here that TCP and UDP do not, which is the evidence the line is in
//! the right place; any other protocol needs the same stop conditions, the same
//! congestion window and the same audit tail. Implementing [`RawPortScan`]
//! gets all of it, and the only code to write is the part that is actually
//! about the protocol.

// Public rather than private-with-re-exports. A caller writing a fifth scanner
// has to be able to read the four that exist, and a module they cannot name is
// a file they have to already know about.
pub mod idle;
pub mod sctp;
pub mod tcp;
pub mod udp;

// And re-exported flat, because four scanners for one phase is exactly the case
// where a caller wants them in one list.
pub use idle::IdlePortScanner;
pub use sctp::{SctpPortScanner, SctpToken};
pub use tcp::{TcpPortScanner, TcpToken};
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
use crate::scanner::pacing::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::scanner::pacing::retry::{
    Due, ProbeLedger, Resolution, RetryPolicy, SilentHostPolicy, saturating_mul,
};
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::PortScanner;
use crate::scanner::strategy::raw::neighbors::{Admission, NEIGHBOR_RECHECK, NeighborGates};
use crate::system::interface::SourceResolver;
use crate::transport::capture::CapturedSegment;
use crate::transport::kernel_neighbors::NeighborState;
use crate::transport::probe::{Emission, ProbeTransport, SendError};
use crate::{info, logging::error};

// ---------------------------------------------------------------------------
// What a raw port scan is paced and timed by
// ---------------------------------------------------------------------------
//
// Declared here rather than beside the discovery sweep. These are what a *port
// scan* is held to, and the four scanners below are their only
// readers; the profiles a routed probe shares whatever it is asking about are
// in `raw`.

/// How a **port scan's** probes are retransmitted.
///
/// [`RETRY_POLICY`](super::raw::RETRY_POLICY) with a steeper backoff and a wider
/// spread, and the reason is specific to what a port scan's retries are
/// recovering from. A sweep's probes are lost to whatever the path is doing,
/// which is not correlated with the sweep; a port scan's are lost to the burst
/// the port scan itself is making at one stack, and a retry sent while that
/// burst is still going is a second packet into the same congested moment.
///
/// Measured, against a Raspberry Pi: a quarter of a thousand probes went
/// unanswered, and with three independent attempts at that loss rate an open
/// port should be missed one time in seventy: eleven open ports should have
/// come back as nearly eleven. Three runs found seven each. The attempts were
/// not independent; all three of them fitted inside the congestion that lost the
/// first.
///
/// So the schedule is stretched at the back and left alone at the front. The
/// first timeout stays as early as measurement allows, because it is what tells
/// [`TCP_PORT_WINDOW`] the target is struggling; the last lands far enough out
/// to sample a network state the scan has had time to stop causing. The jitter
/// is widened for the same reason one step down: probes admitted together time
/// out together, and an unspread retry wave rebuilds the burst it is escaping.
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
/// This is the answer to a question no fixed rate answers well. A port scan
/// aims every probe at one stack, and it is that stack's willingness to answer
/// that bounds the result: a number that differs by two orders of magnitude
/// between the consumer router and the Linux server on the same switch, and
/// that neither this crate nor its caller can know in advance. So the scan
/// discovers it: see [`congestion`](crate::scanner::pacing::congestion) for how,
/// and for why the signal it grows and cuts on is a probe answered *on a retry*
/// rather than a probe not answered at all.
///
/// Each of the four numbers, and what would go wrong at another value:
///
/// - **Start at 32.** Every stack in service answers a few dozen simultaneous
///   SYNs without noticing. Starting at one would spend a round trip per
///   doubling, and on a local segment the ramp would be most of the scan.
/// - **Never below 16.** The floor is what a target that is genuinely being
///   outrun gets cut back to, and it has to leave the scan able to finish: at
///   sixteen questions per round-trip budget a thousand silent ports still
///   settle in a few seconds, where single digits would take a minute. Past
///   that a scan is not being polite, it is failing, and an unfinished scan's
///   verdicts are indeterminate rather than late.
/// - **Never above 1024.** A thousand questions outstanding at one stack is
///   already more than any of them will answer; growth past it buys nothing and
///   the rate ceiling would bind first anyway.
/// - **Stop doubling at 64.** This is the number the controller is blind for.
///   Nothing can be known about a target until a probe to it has been answered
///   or has timed out, and slow start doubles every round trip in the meantime,
///   so the threshold is the worst overshoot a target can be subjected to before
///   the scan has any evidence about it at all. Measured against a Raspberry
///   Pi, a threshold of 256 puts several hundred probes in the air by the time
///   the first timeout arrives. Sixty-four outstanding still empties a
///   thousand ports in a fraction of a second on any local segment, and linear
///   growth carries it further wherever the evidence supports it.
const TCP_PORT_WINDOW: WindowLimits = WindowLimits::new(32, 16, 1_024, 64);

/// The most probes a TCP port scan leaves unresolved at once.
///
/// Not the pacing, [`TCP_PORT_WINDOW`] is, but the bound on how far the
/// bookkeeping may run ahead of it. A probe leaves the window at its first
/// timeout and stays on the ledger until its last, so against a range that
/// answers nothing the scan admits at window speed while the backlog of
/// half-finished probes grows behind it. Several times the window's ceiling,
/// because that backlog is the retry schedule's whole length divided by the
/// first timeout and is expected to be a multiple of what is in flight; far
/// below where the memory matters, because each entry is two durations and a
/// handful of tokens.
const TCP_PORT_UNRESOLVED: usize = 8_192;

/// The fastest a TCP port scan will go regardless of what the window says.
///
/// A **backstop**, not the pacing: [`TCP_PORT_WINDOW`] is the pacing. It is
/// here so that a defect in the controller cannot turn a scan into a flood, and
/// it is set far above any rate a correct scan reaches: at this rate a
/// thousand-port scan emits in fifty milliseconds, which is already faster than
/// the round trips it is waiting on. A caller who wants a real rate limit sets
/// [`ZondConfig::max_probe_rate`](crate::config::ZondConfig::max_probe_rate),
/// which replaces this.
const TCP_PORT_RATE_CEILING: NonZeroU32 = NonZeroU32::new(20_000).expect("a non-zero rate");

/// The fastest a **UDP** port scan puts probes on the wire, in probes per
/// second.
///
/// Two orders of magnitude below [`TCP_PORT_RATE_CEILING`], and it is a real
/// limit rather than a backstop, because UDP has no window to pace it with. A
/// UDP probe's ordinary outcome is silence and its replies name no attempt, so
/// neither half of the congestion signal exists (see
/// [`congestion`](crate::scanner::pacing::congestion)) and the scan is held to a
/// fixed rate instead.
///
/// The rate is set against the thing that actually answers a UDP probe. Most
/// UDP verdicts come from an ICMP port unreachable, and a Linux host emits those
/// under a token bucket that refills at roughly one per second; a burst that
/// outruns it does not merely go unanswered, it manufactures
/// [`OpenFiltered`](crate::model::port::PortState::OpenFiltered) verdicts on
/// ports that are closed. Spread across the hosts of a shuffled scan this is
/// survivable; aimed at one host it is the whole result.
///
/// This number is inherited reasoning, not a measurement. The sweep's rate
/// was measured; this is set an order of magnitude below it because the
/// per-target load is an order of magnitude higher, and that is an argument
/// rather than an experiment.
const UDP_PORT_RATE_PER_SEC: NonZeroU32 = NonZeroU32::new(400).expect("a non-zero rate");

/// How far behind its own rate a port scan's send ticker may fall before the
/// deadline stops allowing for it.
///
/// The ticker falls behind whenever the loop is busy reading replies, and a
/// missed tick is delayed rather than made up. Half again the rate's own time
/// is the allowance the routed sweep gives its ticker for the same reason, and
/// it costs a scan that finishes nothing.
const SEND_SLACK: f64 = 1.5;

/// The deadline a raw port scan of `target_count` endpoints runs under:
/// `config` with its hard budget widened to what the scan's own pacing needs.
///
/// The hard deadline is the guarantee that a scan ends, and it must not be
/// what ends one still going at a pace it was allowed. A budget shorter than
/// that stops the scan mid-plan and the ports it never reached come back
/// unasked, open ones among them: a slower scan is meant to take longer, not
/// to ask less. So the pace is taken from every limit it answers to, each at
/// the slowest it may legitimately settle:
///
/// - **The window**, cut to its floor, with every question holding its slot
///   for the longest timeout the retry policy allows. Not the shortest: a path
///   with a long round trip times every question long, and a window at its
///   floor on such a path is the pacing working as designed.
/// - **The rate**, with every attempt at every endpoint leaving through the
///   send ticker, and [`SEND_SLACK`] for a ticker that falls behind.
/// - **The gap between two probes at one host**, with every attempt at every
///   endpoint waiting its turn as though all of them were one host's, since
///   the scan is not told how its endpoints spread over addresses.
///
/// The slowest of the three is the pace, and the three are not added, since
/// they bind at once rather than in turn. On top of the pace comes the tail:
/// the last probe admitted may still spend its whole schedule with each
/// attempt at the longest timeout, which is what a host measured slow is timed
/// at.
///
/// Every term is generous for a scan that is going well, and costs it nothing,
/// since the loop stops the moment every probe is settled. What the deadline
/// still bounds is a scan that has stopped making progress. A term no clock
/// can count saturates, and the deadline with it: a gap or a timeout that long
/// is one the caller asked the scan to wait out.
fn deadline_for(
    config: AdaptiveDeadlineConfig,
    retry: &RetryPolicy,
    window: WindowLimits,
    rate: NonZeroU32,
    host_gap: Option<Duration>,
    target_count: usize,
) -> AdaptiveDeadlineConfig {
    let attempts = u32::from(retry.max_attempts.max(1));
    let by_window = retry.longest_timeout() / window.floor.max(1);
    let by_rate = saturating_mul(
        Duration::from_secs(1),
        SEND_SLACK * f64::from(attempts) / f64::from(rate.get()),
    );
    let by_gap = host_gap.unwrap_or_default().saturating_mul(attempts);
    config
        .allowing_for(retry.longest_probe_lifetime())
        .allowing_pace_of(by_window.max(by_rate).max(by_gap), target_count)
}

/// A probe's identity within a scan: which address, which port.
pub type ProbeTarget = (IpAddr, u16);

/// The state a raw port scan carries, and everything it does that does not
/// depend on which protocol it speaks.
///
/// Generic over the correlation token `T`, the one piece of per-probe state
/// whose type differs: a TCP probe carries a nonce that its answer must echo
/// back, and a UDP probe has nothing to echo, so it correlates on the target
/// alone and its token is `()`.
pub struct RawProbeScan<T> {
    /// Resolves the source address to send each target's probe from, consulting
    /// on-link subnets and the kernel routing table. Each answer is cached, so
    /// the many ports probed on one host cost a single lookup.
    pub resolver: SourceResolver,
    /// Shared state (host store, event channel, abort signal) for the scan this
    /// prober is part of.
    pub ctx: ScanContext,
    /// Sends probes and receives replies.
    pub transport: ProbeTransport,
    /// Governs how long this scan keeps running, adapting to observed
    /// round-trip times.
    pub deadline: AdaptiveDeadline,
    /// Probes sent but not yet resolved, together with when each is next due to
    /// be resent or written off.
    /// Outstanding probes. The payload is each target's position in the
    /// plan, handed back when the probe retires so a resume can skip it.
    pub ledger: ProbeLedger<ProbeTarget, T, u64>,
    /// Scratch space for the probes coming due on one iteration, reused so a
    /// quiet tick allocates nothing.
    pub due: Vec<Due<ProbeTarget, u64>>,
    /// The source port every probe in this scan is sent from, and so the port
    /// its replies come back to. It is the scan's identity on the wire: the
    /// capture filter narrows to it, and anything addressed elsewhere answered
    /// somebody else.
    pub src_port: u16,
    /// The IP-header state every probe in this scan carries: its hop limit and
    /// any evasion override of the IP header. See
    /// [`Emission`].
    pub emission: Emission,
    /// The segment-level shaping every probe in this scan carries: the payload
    /// padding and, on the TCP paths, the bad-checksum choice. See
    /// [`SegmentShaping`].
    pub shaping: SegmentShaping,
    /// The decoy source addresses every probe in this scan is copied from, or
    /// empty. Resolved once from the scan's
    /// [`EvasionProfile`](crate::evasion::EvasionProfile).
    pub decoys: Vec<IpAddr>,
    /// Why the first probe this host's own sender would not put on the wire
    /// failed, if any did.
    ///
    /// The *first*, and [`record_send`](Self::record_send) keeps it that way by
    /// only recording when this is empty. Holding the last instead, on a link
    /// that has stopped accepting sends, would make the report name whichever
    /// of seven thousand identical failures happened to finish the run.
    ///
    /// Without this a scan whose probes never reached the wire reports every
    /// port with whatever its protocol reads silence as - the same answer a
    /// firewall produces - and says nothing about the difference. That verdict
    /// is a claim about the network; a probe that was never sent is a claim
    /// about this host.
    ///
    /// Only this host's failures. A destination the sender says cannot be
    /// reached is in [`unreachable`](Self::unreachable) instead.
    pub send_failure: Option<String>,
    /// Ports recorded unasked because the sender refused their first probe for
    /// a reason on this host.
    ///
    /// Counted apart from [`retries_refused`](Self::retries_refused) because the
    /// two cost different things. A refused first attempt leaves its port with
    /// no verdict at all; a refused retry leaves one asked fewer times than the
    /// policy allows, whose verdict still stands on the attempts that left.
    pub unasked_refused: u64,
    /// Retries the sender refused for a reason on this host. See
    /// [`unasked_refused`](Self::unasked_refused).
    pub retries_refused: u64,
    /// Ports settled unasked because no probe for them was ever seen leaving.
    /// The report is driven off this, not the send tally, so a run that lost
    /// sends but still resolved every port stays quiet.
    pub unasked_unsent: u64,
    /// The addresses the sender said cannot be reached from here: no route to
    /// them, or no answer from the neighbour a route leads through.
    ///
    /// An address rather than a port, because that is what the sender's answer
    /// is about, and because read port by port it contradicts itself. A kernel
    /// resolving a dead neighbour accepts the first probes while it waits and
    /// refuses the rest once it gives up, so the accepted ones go unanswered
    /// and would read as silence beside refused ones reading unasked, with
    /// nothing about the ports to tell them apart. So every port of an address
    /// here that has never answered is recorded unasked, whichever of the two
    /// its own probe met, and the address is reported as not reached rather
    /// than as a scanner that failed. See
    /// [`is_unreachable`](Self::is_unreachable).
    pub unreachable: std::collections::BTreeSet<IpAddr>,
    /// How far this scan has read the resolution of each host's neighbour,
    /// for a transport whose sends wait on one it can read. See
    /// [`admit`](Self::admit).
    pub(crate) neighbors: NeighborGates,
    /// Per-run counters, so a scan that classified fewer ports than it asked
    /// about can be attributed to loss, to its own deadline, or to correlation
    /// rather than guessed at. Reported once when the loop exits.
    pub audit: ProbeAudit,
    /// How many questions this scan may have awaiting an answer, grown and cut
    /// from what the targets are managing to answer.
    ///
    /// This is what paces a raw port scan, and it is the answer to a
    /// question a fixed rate cannot answer. Measured, against a consumer router:
    /// asked as fast as the socket would take it, of a thousand ports it
    /// answered roughly four hundred and the rest were reported *filtered*:
    /// including one running a service. The host was not filtering anything. It
    /// was answering as fast as it could and being asked ten times faster.
    ///
    /// A rate chosen in advance is wrong in both directions at once: too fast
    /// for that router and far too slow for the Linux server on the same
    /// switch. A window is not chosen in advance. Probes leave as earlier ones
    /// are settled, so the send rate settles at the rate the target is actually
    /// resolving them. See [`congestion`](crate::scanner::pacing::congestion)
    /// for what occupies it, how it grows, what makes it cut, and why UDP is
    /// given one that does not move.
    pub window: CongestionWindow,
    /// How long to wait between releases, and the most probes one release may
    /// contain.
    ///
    /// The **backstop**, not the pacing. It exists so that a defect in
    /// [`window`](Self::window) cannot turn a scan into a flood, and so that a
    /// caller who asks for a specific rate gets one. On a healthy scan the
    /// window binds far below it and this never engages; `pacing_for` in the
    /// parent module has how the pair is derived from a rate.
    pub send_tick: Duration,
    /// The most probes one tick releases. See [`send_tick`](Self::send_tick).
    pub batch: usize,
    /// The most probes this scan leaves unresolved at once.
    ///
    /// A bound on memory and correlation state, not on pace. see
    /// [`admitting`](Self::admitting) for why the two are separate. A probe
    /// leaves the [`window`](Self::window) at its first timeout and stays on the
    /// ledger until its last, so against a range that answers nothing the
    /// backlog between those two points is what grows, and this is what bounds
    /// it.
    pub max_unresolved: usize,
    /// Probes waiting for the gap the scan keeps between two probes at one
    /// host, earliest first. Empty unless
    /// [`ZondConfig::host_probe_interval`](crate::config::ZondConfig::host_probe_interval)
    /// was set.
    ///
    /// Bounded by [`max_unresolved`](Self::max_unresolved) rather than by a
    /// number of its own. The two bound different things and both are memory a
    /// scan of a wide range would otherwise grow without limit; inventing a
    /// second figure would mean two knobs to reason about where the honest
    /// answer to "how much may this scan hold" is one.
    ///
    /// A full queue stops the target stream being read, which is where the
    /// backpressure belongs: every target pulled while it is full could only be
    /// held, so leaving them in the channel lets the dispatcher feel it exactly
    /// as it feels the [`window`](Self::window). It deliberately does **not**
    /// stop the send path, which is the only thing that empties this.
    ///
    /// First attempts only. A retry waits in a queue of its own, admitted on
    /// different terms.
    pub held: std::collections::BinaryHeap<HeldProbe>,
    /// Retries waiting to be sent, earliest first: every retry the ledger
    /// schedules waits here for the send ticker, and for its host's next slot
    /// where the scan keeps a gap.
    ///
    /// A retry is a packet on the wire like any other, and the rate ceiling is
    /// the fastest this scan may put packets there, so a retry spends a tick's
    /// budget exactly as a first attempt does. Sent the moment it came due
    /// instead, retries would ride on top of a ceiling the first attempts are
    /// already filling, and against a range that answers nothing the wire
    /// would carry the ceiling once per attempt.
    ///
    /// Kept apart from [`held`](Self::held) because the two are admitted on
    /// different terms. A first attempt takes a slot in the
    /// [`window`](Self::window) and waits for one; a retry takes none, since
    /// the question it repeats already gave its slot back (see
    /// [`congestion`](crate::scanner::pacing::congestion)), and must not
    /// wait behind a full window it does not occupy.
    ///
    /// Its probe's clock is stopped while it waits (see
    /// [`ProbeLedger::defer`]), so an attempt the ticker has not yet sent is
    /// never overtaken by the next one, and a probe never runs out of attempts
    /// it did not send. Never larger than the ledger: a probe has at most one
    /// retry waiting.
    pub(crate) retries: std::collections::BinaryHeap<HeldProbe>,
}

/// What a [`RawProbeScan`] is built from.
///
/// A plain struct rather than positional arguments. Both raw port scanners
/// build the same core and disagree about four values, and passing fourteen
/// arguments through two constructors apiece is how the two came to share a
/// hundred and fifty lines of identical setup.
pub(super) struct CoreParts<'a> {
    /// Resolves the source address each target's probe leaves from.
    pub resolver: SourceResolver,
    /// The scan this prober is part of.
    pub ctx: ScanContext,
    /// Where probes go and replies come from.
    pub transport: ProbeTransport,
    /// What the caller asked for, which is where the evasion settings and the
    /// source port come from.
    pub tuning: &'a ProbeTuning,
    /// The port every probe in this scan leaves from.
    pub src_port: u16,
    /// How many endpoints the scan will ask about.
    pub target_count: usize,
    /// The retry schedule, which the deadline is derived from.
    pub retry: RetryPolicy,
    /// The send rate. Non-zero because the pacing divides by it.
    pub rate: NonZeroU32,
    /// The budgets the scan runs against. The two scanners differ here: a UDP
    /// scan is inherently slower and needs a silence floor above the ICMP
    /// rate-limit interval before quiet means anything. Its hard budget is
    /// widened to what the scan's own pacing needs; see [`deadline_for`].
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
    /// hosts, so the first wave of probes is timed against a measurement rather
    /// than a guess.
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

        let (send_tick, batch) = super::raw::pacing_for(rate);
        let deadline = deadline_for(
            deadline,
            &retry,
            window,
            rate,
            ctx.host_probe_interval(),
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
            send_failure: None,
            unasked_refused: 0,
            retries_refused: 0,
            unasked_unsent: 0,
            unreachable: std::collections::BTreeSet::new(),
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
    /// The four conditions in the order that makes each one's answer mean
    /// something. `sending_finished` says the target stream has run dry, which
    /// two of them depend on: an empty ledger means "everything has been
    /// answered or written off" only once there is nothing left to ask.
    ///
    /// - **Stopped.** The caller asked the scan to stop, or the wall-clock
    ///   budget it was given ran out. Checked first, so a scan winds down
    ///   promptly rather than after whatever else it was in the middle of;
    ///   [`ScanHandle::stopped`](crate::scanner::handle::ScanHandle::stopped) says
    ///   which of the two it was.
    /// - **Hard deadline.** The ceiling on the whole run, which nothing extends.
    /// - **Attempts spent.** Every probe asked as many times as its budget
    ///   allows, none is still outstanding, and none is waiting for the gap the
    ///   scan keeps between two probes at one host. Waiting longer cannot change
    ///   what this found. A held probe is counted here because it has not been
    ///   sent: stopping on an empty ledger while one waited would report a port
    ///   this scan chose to delay as one it had asked about and heard nothing
    ///   from. A retry waiting for the ticker is not counted: its probe is
    ///   still on the ledger, and one whose probe has left it has nothing to
    ///   ask.
    ///
    /// Silence is not one of them. It reads as a fourth
    /// condition and it cannot be one: with targets still queued, an empty
    /// ledger does not mean the scan has heard nothing, it means the scan has
    /// not *asked* yet, and the way that happens is the send path failing. A
    /// loop that gave up there would abandon everything still queued at the
    /// moment its own machine started refusing sends, and report the remainder
    /// as ports nobody could reach. Measured: a wireless host whose ARP entry
    /// went unresolved mid-scan returned `No route to host` for seven thousand
    /// probes, and the scan concluded after thirty seconds with thirty-one
    /// thousand targets never asked about.
    ///
    /// What still bounds the run is the hard deadline, which nothing extends.
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
    /// Three conditions, and they answer different questions. There may be
    /// nothing left to send: the stream is done and no probe is waiting for its
    /// host's next slot. The [`window`](Self::window) may be full, which is the
    /// pacing: too many questions are already awaiting an answer, and asking
    /// another would cost verdicts against a target that is being outrun. Or the
    /// ledger may be at [`max_unresolved`](Self::max_unresolved), which is not
    /// pacing at all but a bound on memory: a probe stays on the ledger long
    /// after it has stopped occupying the window, waiting out a retry schedule,
    /// and against a wide scan of a silent range that backlog is what grows
    /// without limit.
    ///
    /// The [`held`](Self::held) queue counts as something to send, so a stream
    /// that ran dry does not close the send path while probes are still waiting
    /// for the gap the scan keeps. How many may wait is
    /// [`held_is_full`](Self::held_is_full), which bounds the *stream* and
    /// deliberately not this.
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
    /// What stops the target stream being read once the gap in
    /// [`ZondConfig::host_probe_interval`](crate::config::ZondConfig::host_probe_interval)
    /// is what limits the scan. Every target pulled while this is true could
    /// only be held, so leaving them in the channel is what lets the dispatcher
    /// feel it.
    ///
    /// Not part of [`admitting`](Self::admitting), and that is not an oversight.
    /// The send path is the only thing that empties this queue, so a full queue
    /// closing the send path would be a scan that stopped and never restarted.
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
    /// For a host not yet ready, the caller has already established as much.
    /// Callers that cannot hold a probe must not ask, since a probe dropped on
    /// that answer is a port reported as silent that nobody sent anything to;
    /// see
    /// [`ScanContext::host_ready_at`](crate::scanner::session::ScanContext::host_ready_at).
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
    /// The recorded instant is a hint and is re-checked here rather than
    /// trusted: a retry aimed at the same host moves its slot after an entry is
    /// queued, so an entry can reach the front before its host is actually
    /// ready. One that is still early is pushed back under the fresh instant.
    ///
    /// That cannot loop. A re-checked entry is pushed back with an instant
    /// strictly later than `now`, because that is the only kind
    /// [`host_ready_at`](crate::scanner::session::ScanContext::host_ready_at)
    /// returns, so it cannot be drawn again on this call: every iteration either
    /// yields a probe or takes one entry out of the queue's due prefix.
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
    /// All of the bookkeeping in one call because it is one event and, kept
    /// apart, drifts apart: the audit counts every attempt so a scan that could
    /// not send can say so, the window counts only the ones that reached the
    /// wire, since a probe nobody sent occupied nothing and must not be part of
    /// the evidence that the path is busy, and `target`'s host slot under
    /// [`ZondConfig::host_probe_interval`](crate::config::ZondConfig::host_probe_interval)
    /// moves on the same terms as the window, for the same reason.
    ///
    /// A refusal is sorted by whose fact it is, the way
    /// [`SendError::is_unroutable`] draws the line, and by whether `target`'s
    /// host has ever answered. An unreachable address that never has is an
    /// absent host: it is filed in [`unreachable`](Self::unreachable) and
    /// touches nothing else, since the path this scan is pacing itself against
    /// was never tried and a dead neighbour among live hosts must not slow the
    /// scan of the live ones. Anything else is this host's: congestion for the
    /// window and a fault for the report. That includes a host that answered
    /// and then could not be reached, which is a link that stopped keeping up
    /// mid-scan rather than an address with nothing at it. Measured: a wireless
    /// host whose neighbour entry went unresolved mid-scan was refused seven
    /// thousand probes with `No route to host`, and a window that ignored them
    /// went on offering the link as much as before.
    ///
    /// `first_attempt` decides whether the send takes a window slot. A retry
    /// does not: the slot went back when the question it repeats ran out of
    /// round-trip budget, and handing it back a second time would let the
    /// window admit more than it believes it has. It comes from the plan
    /// position the send carries, the one fact about a probe that does not
    /// change while a retry waits. The host's slot draws no such
    /// distinction: a retry is a packet at the target like any other, and the
    /// gap is about what the target receives rather than about what this scan
    /// is still waiting for.
    ///
    /// Each kind of refusal is logged once, at the level of a line about one
    /// target: the first of this host's, and the first for each address. A link
    /// that has stopped accepting sends refuses every probe behind the one that
    /// noticed, and the same line seven thousand times buries the count, which
    /// is the number that matters and which the report carries on its own.
    pub fn record_send(
        &mut self,
        (host, port): ProbeTarget,
        sent: Result<(), &SendError>,
        first_attempt: bool,
    ) {
        self.audit.record_send(sent.is_ok());
        match (sent, first_attempt) {
            (Ok(()), first) => {
                self.ctx.host_probed(host, Instant::now());
                if first {
                    self.window.record_send();
                } else {
                    self.window.record_resend();
                }
            }
            (Err(error), _) if error.is_unroutable() && !self.ledger.host_has_answered(&host) => {
                if self.unreachable.insert(host) {
                    // `{error:#}` for the operating system's own words, which
                    // are the part a reader asking why can act on.
                    info!(verbosity = 2, "{host} unreachable ({error:#})");
                }
            }
            (Err(error), first) => {
                // A send this machine refused is the one signal this controller
                // gets from *its own machine* rather than from the network, and
                // it is the least ambiguous one there is. Whatever the reason, a
                // full interface queue, a link that has stopped keeping up,
                // offering it more of the same faster cannot help. So it is read
                // as congestion, and the damping bounds how far a permanent
                // failure can cut.
                self.window.record_congestion();
                if first {
                    self.unasked_refused += 1;
                } else {
                    self.retries_refused += 1;
                }
                if self.send_failure.is_none() {
                    error!(
                        verbosity = 2,
                        "failed to send a probe to {host}:{port}: {error:#}"
                    );
                    self.send_failure = Some(format!("{error:#}"));
                }
            }
        }
    }

    /// Records that no address on this host can reach `host`, so none of its
    /// probes could be built.
    ///
    /// The source resolver's answer rather than the sender's, reached before a
    /// probe exists to hand over, and the same fact about the destination as
    /// the sender's no route. Not a send attempt, so the audit does not count
    /// it.
    pub fn record_no_route(&mut self, host: IpAddr) {
        if self.unreachable.insert(host) {
            info!(verbosity = 2, "{host} unreachable (no source address)");
        }
    }

    /// Files `host` as an address whose neighbour the kernel asked for and
    /// heard nothing from, in the kernel's word for where it stands.
    fn record_unresolved(&mut self, host: IpAddr, state: NeighborState) {
        if self.unreachable.insert(host) {
            let why = self.neighbors.unreached(host, state);
            info!(verbosity = 2, "{host} unreachable ({why})");
        }
    }

    /// Decides what becomes of a probe to `host` before it is handed to the
    /// sender: sent, held for a moment, or not sent at all.
    ///
    /// An address already known unreachable is not asked again. Every further
    /// probe could only meet the same answer, or on Linux be taken and never
    /// sent.
    ///
    /// The rest is for a transport whose sends wait on an address resolution
    /// the scan can read: a host that has not answered is not sent a probe
    /// while its neighbour is being asked for, and one whose neighbour went
    /// unanswered is filed unreachable. See [`NeighborGates::admit`].
    ///
    /// A live neighbour answers within a millisecond, so the cost to a live
    /// host whose hardware address was not yet known is one short hold. A host
    /// that has answered anything is never gated.
    pub(crate) fn admit(&mut self, host: IpAddr, now: Instant) -> Admission {
        if self.is_unreachable(&host) {
            return Admission::Unreachable;
        }
        if self.ledger.host_has_answered(&host) {
            return Admission::Send;
        }
        let admission =
            self.neighbors
                .admit(self.transport.neighbors(), &mut self.resolver, host, now);
        if admission == Admission::Unreachable {
            self.record_unresolved(host, NeighborState::Failed);
        }
        admission
    }

    /// Where the resolution of `host`'s neighbour stands, for a host this
    /// scan has been holding probes to while it runs, and `None` for any
    /// other host.
    ///
    /// Read when that probe runs out of attempts or the scan runs out of time,
    /// because either can come before the kernel gives up: it asks three times
    /// a second apart, and a probe's schedule against a fast segment is a
    /// fraction of that. A neighbour still being resolved then means the probe
    /// never left, sitting in the kernel's queue, and its silence says nothing
    /// about the port. What the caller makes of that depends on which of the
    /// two it was; see [`service_retries`](RawPortScan::service_retries) and
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
    /// Out of time with the kernel still asking, the one probe such a host was
    /// sent never left, and nothing was heard from its neighbour for as long
    /// as the scan ran, so the address is one nothing reached. Asked of every
    /// host still waiting rather than of the probes still on the ledger: the
    /// probe may as well be back in the hold queue, having run out of
    /// attempts while the kernel asked, and the address is the same absent
    /// host either way.
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
    /// Never true of a host that has answered anything. A host that answered
    /// and then became unreachable is one whose route changed mid-scan, and the
    /// ports it was asked about were asked: their silence is still silence.
    pub fn is_unreachable(&self, host: &IpAddr) -> bool {
        self.unreachable.contains(host) && !self.ledger.host_has_answered(host)
    }

    /// Reads one probe's first timeout: frees the window slot it was holding,
    /// and decides what the silence meant, given `silence`, the verdict this
    /// scan's technique reads it as.
    ///
    /// Silence from a host that has never answered anything says nothing about
    /// capacity. From a host that is answering, it is a dropped probe where
    /// every port would have answered, the technique's silence meaning a
    /// filter; and where it means anything else, an open port is silent by
    /// design and the one timeout cannot say which it was, so the window reads
    /// how much of it there is instead. See
    /// [`service_retries`](RawPortScan::service_retries) for the argument and
    /// [`congestion`](crate::scanner::pacing::congestion) for what each half
    /// cost to get wrong.
    pub fn judge_timeout(&mut self, host: IpAddr, silence: PortState) {
        self.window.release();
        if !self.ledger.host_has_answered(&host) {
            self.window.record_progress();
        } else if silence == PortState::Filtered {
            self.window.record_congestion();
        } else {
            self.window.record_ambiguous_silence();
        }
    }

    /// Folds one answered probe into everything this scan tracks about itself:
    /// the deadline, the window and the audit.
    ///
    /// One place rather than one per protocol, because the three would
    /// otherwise be three statements repeated in each scanner, and the window a
    /// fourth that one scanner could gain and another miss.
    ///
    /// The window reads the *attempt* that was answered, not merely that
    /// something was. A reply to the first attempt says the target is keeping
    /// up; a reply to a later one says the target was willing all along and the
    /// first question did not survive, which is the only evidence a port scanner
    /// has that distinguishes being too fast from meeting a firewall. See
    /// [`congestion`](crate::scanner::pacing::congestion).
    pub fn record_answer<P: Copy>(&mut self, resolution: &Resolution<P>) {
        self.deadline.mark_activity();
        if let Some(rtt) = resolution.rtt {
            self.deadline.record_rtt(rtt);
        }

        // Three cases, and the middle one is the reason this reads the attempt
        // rather than the fact of an answer.
        match (resolution.attempts, resolution.answered_attempt) {
            // Asked once and answered: the slot is still held, and the target is
            // keeping up.
            (1, _) => {
                self.window.release();
                self.window.record_answer();
            }
            // Answered only because it was asked again: the target was willing
            // all along and the first ask did not survive. The slot went back at
            // that timeout, so this cuts and frees nothing.
            (_, Some(attempt)) if attempt > 1 => self.window.record_congestion(),
            // Answered late: the first ask was answered after its budget had
            // already expired, which the per-attempt token is what lets us see.
            // The timeout already released the slot and already judged it, and
            // doing either again would double-count.
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
    /// A port scan almost never meets its targets cold: [`scan`](crate::scan)
    /// establishes that an address is there before spending a probe on each of
    /// its ports, and that liveness pass timed every host that answered. Without
    /// this the port scanner starts from first principles anyway, and the cost
    /// falls entirely on the ports that turn out to be filtered: each one waits
    /// the unmeasured starting timeout three times before silence is allowed to
    /// mean anything.
    ///
    /// Called once at construction rather than per probe. The store is finished
    /// being written by the time a port scanner is built, and a lookup per
    /// target would repeat the same answer for every port of a host.
    ///
    /// The median rather than the minimum, because a retry schedule sized from
    /// the fastest sample a host ever produced repeats every probe that is
    /// merely typical.
    pub fn seed_timing(&mut self) {
        for host in self.ctx.store.iter() {
            if let Some(rtt) = host.value().median_rtt() {
                self.ledger.seed_host_rtt(host.key().addr(), rtt);
            }
        }
    }

    /// Records that `sender` said the target named by `key` cannot be reached.
    ///
    /// A host verdict rather than a port one: an unreachable names the
    /// destination it refers to, and nothing about any particular port on it.
    /// The probe keeps its remaining attempts, which is why this does not go
    /// through the ledger's `resolve`.
    ///
    /// **`key` must name a probe this scan has outstanding, and this is what
    /// checks it.** [`HostStatus::Down`] is documented as an unreachable
    /// "quoting a probe this scan sent", and the quoted source port alone does
    /// not establish the second half of that sentence: gated on it, an error
    /// quoting a destination and port of the sender's choosing is believed.
    /// Three things would follow. An address the scan never probed would be
    /// *created* in the store and filed as down. A host that had been probed and
    /// stayed silent would be promoted from `Unknown`, which says nothing was
    /// heard, to `Down`, which says an intermediary answered for it — the
    /// difference between a hardened host that drops traffic and an address that
    /// is not there. And a host already proved up would keep its status, the
    /// promotion rule seeing to that, but still collect the unreachable as one of
    /// the reasons on its record, which is the evidence trail this module exists
    /// to keep honest.
    ///
    /// `token` is checked where the quotation carried one. Where it did not, the
    /// key alone is the evidence, and it has to name a live probe.
    ///
    /// **An unreachable from this host's own address is not a host down.**
    /// Linux answers a write it queued behind a neighbour resolution that
    /// failed with a host unreachable sent from the very address the write left
    /// from, to itself, over loopback. That is this host's kernel saying it
    /// could not resolve the neighbour, the fact the send path and the
    /// kernel's neighbour table carry, and not an intermediary answering for
    /// the address. Whether it is heard at all depends on whether the capture
    /// on loopback kept up, so filed as `Down` it would give identical dead
    /// neighbours different statuses by which of their messages happened to
    /// be caught. It is filed the way the other two are, as an address that
    /// cannot be reached from here. See [`unreachable`](Self::unreachable).
    ///
    /// Returns whether the verdict is now on the host's record, or the address
    /// filed as unreachable, so a caller can tell a message that became
    /// evidence from one that did not. `false` means the message named no
    /// probe this scan has outstanding, which the audit counts as off-target,
    /// or named an address the scan's exclusions forbid, which
    /// [`ScanContext::write_host`] drops. Whether the host was already in the
    /// store makes no difference to the answer.
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

        // Set by the edit rather than read off `update_host`, whose answer is
        // whether the host was created. The edit runs exactly when the store
        // accepts the address, which is the question asked here.
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
    /// It says what those refusals cost and no more. A refused first attempt is
    /// a port recorded unasked; a refused retry is a port asked fewer times than
    /// the policy allows, whose verdict stands on the attempts that did leave.
    /// Calling the second kind unasked would contradict the verdict the report
    /// holds for the port, which is the one a reader will act on.
    fn refusals_failure(&self, silence_verdict: &str) -> Option<String> {
        let cause = self.send_failure.as_deref().unwrap_or("cause unrecorded");
        let unasked = crate::logging::counted(u128::from(self.unasked_refused), "port", "ports");
        let retries = crate::logging::counted(u128::from(self.retries_refused), "retry", "retries");
        match (self.unasked_refused, self.retries_refused) {
            (0, 0) => None,
            (_, 0) => Some(format!(
                "{unasked} recorded unasked rather than {silence_verdict}: their probes \
                 could not be sent: {cause}"
            )),
            (0, _) => Some(format!(
                "{retries} could not be sent, so some ports were asked fewer times than \
                 the retry policy allows: {cause}"
            )),
            (_, _) => Some(format!(
                "{unasked} recorded unasked rather than {silence_verdict}, and {retries} \
                 lost, because probes could not be sent: {cause}"
            )),
        }
    }

    /// Closes out a run: reports probes that never reached the wire, then files
    /// the audit.
    ///
    /// `silence_verdict` is what this scan's protocol reads an unanswered probe
    /// as, named in the failure message so the two cases are distinguishable to
    /// whoever reads it. A scan that could not send is not a scan that found
    /// everything unanswered, and those are identical in every number a caller
    /// otherwise sees. `silence` is the verdict itself, which decides whether
    /// the audit may read the run's unanswered ports as possible loss: it may
    /// where silence is a filter, and not where an open port answers with it.
    ///
    /// Capture counters are read here, while the transport is still alive: they
    /// live with the capture threads it keeps running.
    pub fn finish(
        &mut self,
        kind: ScannerKind,
        audit_tag: &str,
        silence_verdict: &str,
        silence: PortState,
        probes: u128,
        reason: StopReason,
    ) {
        if let Some(failure) = self.refusals_failure(silence_verdict) {
            self.ctx.record_failure(kind, failure);
        }

        // Reported against the address, not as a failure: the scan ran, and
        // these addresses are not reachable from here. Only the ones never heard
        // from, since an address that answered was reached, and a report saying
        // otherwise would contradict the ports it holds for it.
        for host in &self.unreachable {
            if !self.ledger.host_has_answered(host) {
                self.ctx.record_unroutable(*host);
            }
        }

        if self.unasked_unsent > 0 {
            // Seeing a probe leave takes the capture that would also have heard
            // its answer. A capture that stopped early sees neither, so a probe
            // never seen leaving then says nothing about whether it was sent,
            // and blaming this machine for it would be a guess presented as a
            // finding. The ports are unasked either way; only the cause differs.
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
        match ctx.host_ready_at(entry.ip, now) {
            None => return Some(entry),
            Some(ready) => {
                entry.ready = ready;
                queue.push(entry);
            }
        }
    }
    None
}

/// A probe held back because its host was asked too recently, or because the
/// kernel is still resolving its neighbour.
///
/// What [`ZondConfig::host_probe_interval`](crate::config::ZondConfig::host_probe_interval)
/// and a neighbour the kernel is still resolving cost the port
/// scanners and cost nothing else: this is the one pass that aims thousands of
/// probes at a single address, so it is the one that needs somewhere to put a
/// probe it may not send yet. A sweep asks each host once per attempt and can
/// move on to the next.
///
/// The two kinds a scan sends are told apart the way
/// [`RawPortScan::send`] already tells them apart, by whether
/// there is a plan position: a first attempt carries one and a retry keeps the
/// one the ledger holds. That is also what decides who accounts for the probe if
/// the scan ends while it is still held. See
/// [`resolve_held`](RawPortScan::resolve_held).
///
/// Public because it names an argument of a public trait method, with private
/// fields because nothing outside needs to read one: every scanner reaches the
/// wire through [`RawPortScan::send`], and the defaulted methods above it are
/// what turn a held probe back into that call. A position a caller could write
/// is a resume told a target was covered by a probe that never went out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldProbe {
    /// The address to probe.
    ip: IpAddr,
    /// The port to probe.
    port: u16,
    /// The plan position for a first attempt, and [`None`] for a retry.
    position: Option<u64>,
    /// When the host was thought to become ready, as it stood when this was
    /// held.
    ///
    /// A hint rather than a promise. A retry aimed at the same host is sent
    /// through the gap's own accounting and moves the slot, so an entry can
    /// reach the front of the queue before its host is actually ready. That is
    /// what [`RawProbeScan::take_ready`] re-checks rather than trusts.
    ready: Instant,
}

/// Ordered so that [`BinaryHeap`](std::collections::BinaryHeap), which is a
/// max-heap, yields the *earliest* ready instant first. The same inversion
/// [`ProbeLedger`]'s own timer queue uses, and for the same reason.
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
/// Everything below is protocol knowledge: which transport this scan speaks,
/// how it builds a probe, how it reads a reply, what a verdict proves about the
/// host behind the port, and what silence means once a probe has spent its
/// budget. [`drive`] supplies the rest, which is the loop those answers are fed
/// into.
///
/// The division is the same one [`RawProbeScan`] draws and for the same reason:
/// a RST and an ICMP port unreachable prove genuinely different things, while
/// the machinery that decides when to stop asking does not know the difference
/// and should not have to.
pub trait RawPortScan: PortScanner {
    /// The per-probe correlation token. A TCP probe carries a nonce its answer
    /// must echo; a UDP probe has nothing to echo and uses `()`.
    type Token: Copy + PartialEq;

    /// The shared machinery this scan is built around.
    fn core(&self) -> &RawProbeScan<Self::Token>;

    /// The same, mutably.
    fn core_mut(&mut self) -> &mut RawProbeScan<Self::Token>;

    /// The transport this scan probes. Targets of any other protocol are not
    /// this scanner's to answer and are passed over.
    fn protocol(&self) -> Protocol;

    /// The verdict a probe takes once every attempt has gone unanswered.
    ///
    /// For UDP always [`PortState::OpenFiltered`], since an open port that did
    /// not recognise the payload is silent exactly as a firewall is. For TCP it
    /// depends on the technique: silence means a filter where any live stack
    /// would have answered, and open-or-filtered where an open port is required
    /// to ignore the probe.
    fn silence_means(&self) -> PortState;

    /// What the audit files this run under, and how its failure message names a
    /// port nobody answered for.
    ///
    /// The second half exists so a scan whose probes never reached the wire
    /// reads as what it is. Reporting "3000 ports unanswered" and "3000 ports
    /// open-filtered" describe the same silence, and only one of them is the
    /// word that scan's protocol would have used.
    fn audit_labels(&self) -> AuditLabels;

    /// Sends one probe at `(ip, port)` and arms the ledger for it.
    ///
    /// Called for the first attempt and every retry alike. A probe that cannot
    /// be sent is simply not armed: the ledger has already charged the attempt
    /// by the time a retry reaches here, so an unroutable target still runs out
    /// of attempts on schedule rather than waiting outstanding forever.
    /// Sends one probe. `position` is the target's place in the plan, kept by
    /// the ledger so it comes back when the probe retires.
    fn probe(&mut self, ip: IpAddr, port: u16, position: u64, now: Instant) {
        match self.core_mut().admit(ip, now) {
            Admission::Send => send_timed(self, ip, port, Some(position), now),
            Admission::Hold(ready) => {
                self.core_mut().hold(ip, port, Some(position), ready);
                return;
            }
            Admission::Unreachable => {
                self.record_unasked_endpoint(ip, port);
                return;
            }
        }

        // The ledger is what says whether the probe left: `send` arms it only
        // once the segment is on the wire, and declines to send at all where the
        // target has no route. Nothing comes due for a probe that was never
        // armed and nothing drains it, so without this the target is the one
        // that vanishes from the host entirely. A retry is not this case, since
        // that probe is still on the ledger with attempts left.
        if !self.core().ledger.contains(&(ip, port)) {
            self.record_unasked_endpoint(ip, port);
        }
    }

    /// Resends a probe already outstanding. The ledger keeps its position.
    ///
    /// A retry whose probe has left the ledger has nothing left to ask: a late
    /// answer to an earlier attempt settled it while the retry waited, and
    /// sending it would put a question on the wire that nothing is waiting to
    /// hear answered. A retry to an address found unreachable is not sent
    /// either, and the ledger retires it on schedule into the verdict every
    /// port of the address takes.
    ///
    /// The probe's clock stopped while the retry waited, and restarts here
    /// whatever became of it: from the send, which re-arms it, or from now for
    /// a retry that did not leave, so the attempt it was charged still counts
    /// and the probe runs out on schedule. See `ProbeLedger::defer`.
    fn reprobe(&mut self, ip: IpAddr, port: u16, now: Instant) {
        if !self.core().ledger.contains(&(ip, port)) {
            return;
        }
        match self.core_mut().admit(ip, now) {
            Admission::Send => send_timed(self, ip, port, None, now),
            Admission::Hold(ready) => {
                self.core_mut().hold(ip, port, None, ready);
                return;
            }
            Admission::Unreachable => {}
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
    /// came from a spent attempt budget rather than from a packet.
    fn record_port(&mut self, ip: IpAddr, port: u16, state: PortState, sender: Option<IpAddr>);

    /// Records what became of one target, which is a different question from
    /// the verdict [`record_port`](Self::record_port) gave it.
    ///
    /// Every target reaches `record_port`, whether it was answered, asked and
    /// left quiet, or never asked at all, since an absent port is the shortfall
    /// a reader cannot see. Only the earned outcomes carry a position, and only
    /// a position lets a resume skip a target. See [`Outcome`].
    fn settle(&mut self, outcome: Outcome) {
        self.core().ctx.record_outcome(outcome);
    }

    /// Probes `target`, if it is one this scan speaks the protocol for.
    ///
    /// A target of another protocol is passed over rather than refused. The
    /// [`CompositePortScanner`](crate::scanner::strategy::composite::CompositePortScanner)
    /// routes by protocol and so should never send one, which is exactly why
    /// this holds: a router that started making mistakes would otherwise have
    /// this scanner probe a UDP port with a TCP segment.
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
    /// A target of another protocol is passed over on the same terms
    /// [`send_probe`](Self::send_probe) passes it over: it belongs to the other
    /// scanner, and queuing it here would hold a UDP port against a TCP scan's
    /// gap and then file it under that scan's account of itself.
    fn hold_probe(&mut self, planned: PlannedTarget, ready: Instant) {
        if planned.protocol() == self.protocol() {
            self.core_mut()
                .hold(planned.ip(), planned.port(), Some(planned.position), ready);
        }
    }

    /// Sends a probe that was held for its host's next slot.
    ///
    /// The two kinds part company here, on the same distinction the ledger draws
    /// between them: a first attempt carries a plan position and goes through
    /// [`probe`](Self::probe), which accounts for a target the send path
    /// refuses, and a retry has none and goes through
    /// [`reprobe`](Self::reprobe), which leaves the position the ledger is
    /// already holding alone.
    fn send_held(&mut self, held: HeldProbe, now: Instant) {
        match held.position {
            Some(position) => self.probe(held.ip, held.port, position, now),
            None => self.reprobe(held.ip, held.port, now),
        }
    }

    /// Accounts for every probe still held when the loop ended.
    ///
    /// A held first attempt was never armed, so nothing else will account for
    /// it: without this it is the port that vanishes from the host entirely,
    /// which is the one shortfall a reader cannot see. A waiting retry is
    /// still outstanding on the ledger and is recorded with everything else
    /// there, so it is dropped rather than recorded twice.
    ///
    /// Nothing is counted. These targets were counted into the audit's
    /// denominator when they came off the stream, and counting them again would
    /// make a scan claim to have been handed more work than the plan holds.
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
    /// Exhaustion is what makes a silent verdict mean something: nothing
    /// arrived across every attempt, rather than nothing arrived once.
    /// Retiring probes here rather than at the end of the scan also streams
    /// results to the caller while it is still running, and frees room under
    /// the [`window`](RawProbeScan::window) for the targets queued behind
    /// them.
    ///
    /// Running out of attempts is not treated as activity, so it
    /// never extends the scan's own deadline. Nothing answered.
    ///
    /// A probe's **first** timeout is also what releases its slot in the
    /// congestion window and what tells the window how the target is coping:
    /// whichever event carries that timeout, the retry that follows it or the
    /// exhaustion that follows it when the budget was one attempt.
    ///
    /// Which signal it carries depends on the host and on what this scan's
    /// silence means, and not on the probe. A host that has never answered
    /// anything is behind a firewall or is not there, and its silence says
    /// nothing about capacity; a host that is answering most of what it is
    /// asked and dropping the rest is being outrun, and that is the only
    /// warning a scan gets before it starts reporting a firewall that is not
    /// there. Where an open port is silent by design, one timeout from an
    /// answering host is either, and only the share of them tells loss from a
    /// host's open ports. See [`congestion`](crate::scanner::pacing::congestion).
    fn service_retries(&mut self, now: Instant) {
        let core = self.core_mut();
        core.ledger.drain_due(now, &mut core.due);

        // Taken so the sends below can borrow `self` mutably; the buffer itself
        // is reused, so this costs no allocation.
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
                    // A retry is a probe at a host like any other, and waits
                    // for the send ticker and the host's next slot like one.
                    // Its probe's clock stops while it waits, because the
                    // ledger has already charged this attempt: left running,
                    // a retry held past its own timeout is overtaken by the
                    // next, and a host spaced slower than its retry schedule
                    // would spend every attempt that way and settle the port
                    // as silent having asked once.
                    let core = self.core_mut();
                    core.ledger.defer(&(ip, port));
                    let ready = core.ctx.host_ready_at(ip, now).unwrap_or(now);
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
                    // A probe whose neighbour the kernel is still asking for
                    // never left, so none of its attempts was spent: it goes
                    // back to wait on the resolution as a first attempt, and
                    // the kernel's own verdict decides what becomes of it. One
                    // the kernel gave up on is an address nothing reaches.
                    match self.core_mut().pending_neighbor(ip) {
                        Some(NeighborState::Resolving) => {
                            self.core_mut()
                                .hold(ip, port, Some(position), now + NEIGHBOR_RECHECK);
                            continue;
                        }
                        Some(NeighborState::Failed) => {
                            self.core_mut().record_unresolved(ip, NeighborState::Failed);
                        }
                        Some(NeighborState::Resolved) | None => {}
                    }
                    // An address the sender says cannot be reached, and which
                    // never answered: this probe's own silence is a kernel that
                    // took the write while it waited on a neighbour it then gave
                    // up on, and the port takes the verdict every other port of
                    // the address took. See `RawProbeScan::unreachable`.
                    if self.core().is_unreachable(&ip) {
                        self.record_unasked_endpoint(ip, port);
                        continue;
                    }
                    // No send ever seen leaving: unasked, not silent. Guarded on
                    // the run witnessing its egress at all, or every probe looks
                    // unsent.
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
    /// budgets run out; what reaches here are the ones still mid-schedule when
    /// the scan itself ended. Silence is a verdict only once every attempt
    /// has had its full wait, and these have not, so they do not take the
    /// verdict this scan reads silence as. The answer to one may be in transit
    /// at the stop, and an open port whose answer had not yet arrived, filed
    /// filtered, is a firewall reported where there is none.
    ///
    /// Settled as interrupted rather than unasked, since each was asked, and
    /// either way carries no position, so a resume asks it again.
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
    /// A scan that hits its deadline with targets still queued would otherwise
    /// leave them with no record whatsoever: not a filtered port, not an unknown
    /// one, simply absent from the host as though nobody had ever named it. That
    /// is the worst of the three ways a scan can fall short, because it is the
    /// only one a reader cannot see: a truncated port list and a complete one
    /// look identical, and the count in the summary agrees with itself.
    ///
    /// So they are written down and counted. Written down under whatever the
    /// scan reads silence as, they would be better than absent but credited
    /// too kindly. [`PortState::Unasked`] is the third option: the port stays on
    /// the host, and it says what happened to it rather than borrowing the
    /// verdict of a port that was probed and stayed quiet.
    ///
    /// What is already queued, and no more. The rest of the plan never reaches
    /// this scanner: the router finds it gone and records each of those
    /// targets unasked in its place. See
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
    /// over rather than recorded here, which would file a UDP port under a TCP
    /// scan's account of itself.
    fn record_unasked(&mut self, target: PlannedTarget) {
        if target.protocol() != self.protocol() {
            return;
        }
        self.record_unasked_endpoint(target.ip(), target.port());
    }

    /// The single account of an endpoint nobody asked about, shared by the four
    /// ways one arises: still queued when the loop ended, reached after its host
    /// had spent the budget in
    /// [`ZondConfig::host_timeout`](crate::config::ZondConfig::host_timeout),
    /// refused by this machine's own sender before it reached the wire, and on
    /// an address the sender says cannot be reached from here.
    ///
    /// All four were named and none was probed, so all four are written down
    /// the same way, and none leaves a port off the host. What a resume owes
    /// differs only in name: a port of an unreachable address is owed as
    /// [`Outcome::Unroutable`], the way the sweep and the connect path settle
    /// one, and every other as [`Outcome::Unasked`].
    fn record_unasked_endpoint(&mut self, ip: IpAddr, port: u16) {
        self.record_port(ip, port, PortState::Unasked, None);
        // Nothing was sent, so nothing was learned, and a resume owes this
        // target the probe this sitting did not spend on it.
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

/// Runs every probe `scanner` has outstanding to the end of its schedule, as a
/// scan left to finish does, so a test reads the verdict silence earns rather
/// than the one a stop leaves.
#[cfg(test)]
pub(crate) fn run_out<S: RawPortScan>(scanner: &mut S) {
    let mut now = Instant::now();
    while !scanner.core().ledger.is_empty() {
        now += Duration::from_secs(60);
        retry_due(scanner, now);
    }
}

/// [`RawPortScan::send`], with the time it took given back to the deadline.
///
/// A sender that frames its own probes resolves a neighbour inside the send
/// when [`RawProbeScan::admit`] could not hold the probe for it, as when the
/// link would not carry the resolution it asked for, and holds the loop for
/// the whole wait. See [`AdaptiveDeadline::allow_for_sending`].
fn send_timed<S: RawPortScan + ?Sized>(
    scanner: &mut S,
    ip: IpAddr,
    port: u16,
    position: Option<u64>,
    now: Instant,
) {
    let started = Instant::now();
    scanner.send(ip, port, position, now);
    let spent = started.elapsed();
    scanner.core_mut().deadline.allow_for_sending(spent);
}

/// Reads every reply already waiting in `scanner`'s capture stream, without
/// waiting for more.
///
/// Called before the loop services its timers, so an answer that arrived
/// before its probe came due is read as the answer rather than after the
/// probe has been written off. The loop can wake late to both at once: a
/// send that blocked, a runtime starved of its thread, a machine under load.
/// Serviced timer first, a probe with no attempts left is retired as silent
/// and the answer waiting behind it finds nothing to resolve, which with one
/// attempt files an open port filtered. Resolving is where a reply is timed
/// from its own arrival, so reading it late costs nothing else.
///
/// Reading them first is enough, and comparing an answer's arrival with its
/// probe's due time on resolving would add nothing: an answer the loop can
/// see is in this queue, and one still inside the capture has not reached
/// anything the loop could compare against. Bounded by what is queued on
/// entry, so a stream arriving as fast as it is read cannot hold the loop
/// here.
fn read_waiting_replies<S: RawPortScan>(scanner: &mut S) {
    let waiting = scanner.core().transport.rx.len();
    for _ in 0..waiting {
        let Ok(reply) = scanner.core_mut().transport.rx.try_recv() else {
            // Empty after all, or closed, which the `select!` below reads as
            // the stream ending.
            return;
        };
        scanner.core_mut().audit.record_segment();
        let received_at = reply.received_at;
        scanner.handle_reply(&reply, received_at);
    }
}

/// How a run names itself in the audit and in its own failure messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditLabels {
    /// The tag the audit line is filed under, such as `"tcp-port"`.
    pub tag: &'static str,
    /// How a port that nothing answered for is described, such as
    /// `"open-filtered"`.
    pub silence: &'static str,
}

/// Drives one raw port scan from its first probe to its audit line.
///
/// This is the whole of what the TCP and UDP scanners would otherwise each hold
/// a copy of. Two copies would differ in four expressions: which protocol to
/// accept, what silence means, and two labels. Everything around those is
/// identical, including the ordering that makes the stop conditions mean
/// anything, and that is a dangerous thing to keep two of. A stop
/// condition fixed in one copy and missed in the other does not fail; it
/// returns a smaller answer that looks exactly like a quiet network.
///
/// The shape of one iteration, and why it is that shape:
///
/// 1. **Read the replies already waiting.** An answer that arrived before
///    its probe came due has to settle it before the timer can; see
///    `read_waiting_replies`.
/// 2. **Then service retries.** Probes come due on a timer, and queuing them
///    before the stop conditions are read means the ledger is current when
///    those conditions ask whether anything is still outstanding.
/// 3. **Then decide whether to stop**, on the four conditions
///    [`RawProbeScan::stop_reason`] holds.
/// 4. **Then wait on whichever of three things happens first**: another target
///    to probe, a reply to read, or the moment the next probe is due.
///
/// Anything still outstanding when the loop ends, and anything still queued, is
/// recorded [`PortState::Unasked`], so a scan cut short reports the ports it
/// reached no verdict on instead of leaving them off the host entirely, which
/// is the one shortfall a reader cannot see, or filing a probe whose answer
/// was still on its way as silence. See [`RawPortScan::resolve_remaining`] and
/// [`RawPortScan::resolve_unasked`].
pub async fn drive<S: RawPortScan>(scanner: &mut S, mut targets: mpsc::Receiver<PlannedTarget>) {
    // The rate backstop. What paces the scan is `RawProbeScan::window`, which
    // the batch loop below re-checks after every send; this bounds how fast a
    // window's worth of probes may be released, so a defect in the controller
    // cannot become a flood and a caller asking for a specific rate gets one.
    let mut send_tick = tokio::time::interval(scanner.core().send_tick);
    // Delay rather than Burst: a tick missed while the loop was busy is time the
    // probes were not going out, and catching up by releasing several at once
    // would put back exactly the burst this exists to prevent.
    send_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut sending_finished = false;
    // Counts what the scan was handed rather than what it sent. A target of
    // another protocol is not this scanner's to probe, but it was still part of
    // the work routed here, and the audit reads this as the denominator.
    let mut probes = 0u128;

    // The loop yields why it stopped, so the audit cannot report a reason the
    // code never actually took.
    let reason = loop {
        // Read once per iteration and reused throughout it: a scan at rate
        // takes this path constantly, and the arithmetic below only needs the
        // instants to agree with each other.
        let now = Instant::now();
        read_waiting_replies(scanner);
        // Before the timeouts are read, so none of those left in flight after
        // the last question went out is judged as a share of what the target
        // is doing. See `CongestionWindow::stop_admitting`.
        if !scanner.core().questions_left(sending_finished) {
            scanner.core_mut().window.stop_admitting();
        }
        scanner.service_retries(now);

        if let Some(reason) = scanner.core().stop_reason(sending_finished) {
            break reason;
        }

        // Both are read before the `select!`, which borrows the receive half
        // mutably for the duration of the statement.
        let sending = scanner.core().sending(sending_finished);
        let tick = scanner.core().tick_delay(now);

        tokio::select! {
            // One tick releases a batch, which is how a rate faster than the
            // timer's resolution is expressed. Taken from the stream only when
            // the ledger has room: the ceiling bounds how many answers are
            // outstanding, and the rate bounds how fast they are asked for.
            // Retries are released here too, and the same rate bounds them.
            _ = send_tick.tick(), if sending => {
                let now = Instant::now();
                // The batch is a budget of sends, and only a probe handed to
                // the sender spends it. A probe held again, settled unasked or
                // turned away from an unreachable address put nothing on the
                // wire, and charging it a share would let the probes waiting
                // on a dead neighbour's resolution take every share a rate
                // ceiling allows, re-checked each tick while the live hosts
                // behind them are never asked. The loop still ends: each pass
                // sends, takes a waiting retry or a held probe due now (one
                // held again is due later), or takes from the stream until it
                // is empty or the hold queue is full.
                let budget = scanner.core().audit.sends_attempted + scanner.core().batch as u64;
                while scanner.core().audit.sends_attempted < budget {
                    // A retry goes first, whether or not the window has room:
                    // it takes no slot, and its probe is a question already
                    // asked, whose schedule is waiting on this send.
                    if let Some(retry) = scanner.core_mut().take_ready_retry(now) {
                        scanner.send_held(retry, now);
                        continue;
                    }
                    if !scanner.core().admitting(sending_finished) {
                        break;
                    }

                    // A probe already held for its host's next slot goes next.
                    // It was taken off the stream before anything still in the
                    // channel was looked at, and leaving it behind fresh targets
                    // would have a scan with a gap set starve the hosts it had
                    // already reached in favour of ones it had not.
                    if let Some(held) = scanner.core_mut().take_ready(now) {
                        scanner.send_held(held, now);
                        continue;
                    }

                    // Nowhere to put another one. Every target pulled now could
                    // only be held, so the stream is left alone and the
                    // dispatcher feels it exactly as it feels a full window.
                    if scanner.core().held_is_full() {
                        break;
                    }

                    match targets.try_recv() {
                        Ok(target) => {
                            probes += 1;
                            // A host that has spent its own budget is left
                            // where it stands. The target is written down as
                            // one nobody asked about rather than dropped, so
                            // the shortfall reads the same as any other.
                            if scanner.core().ctx.host_expired(target.ip()) {
                                scanner.record_unasked(target);
                            } else if let Some(ready) =
                                scanner.core().ctx.host_ready_at(target.ip(), now)
                            {
                                // Asked too recently. Held rather than dropped:
                                // this target has been counted and owes a
                                // verdict, and the one thing that must not
                                // happen is a probe the scan chose to delay
                                // reading afterwards as a silent port.
                                scanner.hold_probe(target, ready);
                            } else {
                                scanner.send_probe(target);
                            }
                        }
                        // Nothing waiting: the dispatcher has not caught up, and
                        // blocking here would hold the receive half across the
                        // whole batch.
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
                        // The moment the capture thread took the segment, not
                        // the moment this loop reached it. See
                        // `CapturedSegment::received_at`.
                        let received_at = reply.received_at;
                        scanner.handle_reply(&reply, received_at);
                    }
                    None => break StopReason::StreamClosed,
                }
            }

            // Wakes when the next probe is due, so a retry is sent on time even
            // though nothing is arriving to wake the loop otherwise.
            _ = tokio::time::sleep(tick) => {}
        }
    };

    // Before anything is settled, so every port of an address the kernel
    // never resolved takes the same verdict, wherever its probe was waiting.
    scanner.core_mut().conclude_pending_neighbors();
    scanner.resolve_remaining();
    // Probes still waiting for a host's next slot. Before the channel drain
    // below and after the ledger above, because a held retry is accounted for by
    // `resolve_remaining` and a held first attempt by nothing at all.
    scanner.resolve_held();
    // Targets still in the channel when the loop ended. Counted into `probes`
    // so the audit's denominator is what the scan was handed rather than what it
    // got round to. Closed first, so the router cannot slip a target in behind
    // the drain where nothing would read it: once closed, it finds this scanner
    // gone and records the target unasked itself.
    targets.close();
    probes += scanner.resolve_unasked(&mut targets);

    let kind = scanner.kind();
    let labels = scanner.audit_labels();
    let silence = scanner.silence_means();
    scanner
        .core_mut()
        .finish(kind, labels.tag, labels.silence, silence, probes, reason);
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

    /// A sender that swallows everything. These tests never look at the wire;
    /// they ask when the loop decides to stop, which is a question about the
    /// ledger and the deadline alone.
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
            send_failure: None,
            unasked_refused: 0,
            retries_refused: 0,
            unasked_unsent: 0,
            unreachable: std::collections::BTreeSet::new(),
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
            "filtered",
            PortState::Filtered,
            2,
            StopReason::AllResponded,
        );
        let failures = core.ctx.failures_snapshot();
        assert_eq!(failures.len(), 1, "{failures:?}");
        failures[0].reason().to_owned()
    }

    /// A port scan's deadline outlasts the slowest pace each of its limits
    /// allows, worked out from the numbers rather than read from the scan: the
    /// window at its floor with every question timed at the longest timeout,
    /// every attempt through the rate ceiling, and every attempt waiting out
    /// the gap at one host. A deadline shorter than any of them stops a scan
    /// that is going exactly as it was told to, with ports never asked.
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
    /// Seeing a probe leave takes the same capture that hears its answer. A
    /// reader that died sees neither, so every port after it looks unsent, and
    /// a report blaming that on sending would say this machine swallowed probes
    /// that may well have gone out: a claim about the host that the evidence
    /// cannot support.
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

    /// With every capture listening, a probe never seen leaving is one this
    /// machine did not send, and the report says so in one readable sentence.
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

    /// [`core`] with a gap between probes at one host, for the tests that are
    /// about the queue rather than the ledger.
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
            send_failure: None,
            unasked_refused: 0,
            retries_refused: 0,
            unasked_unsent: 0,
            unreachable: std::collections::BTreeSet::new(),
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

        // Held out of order on purpose: the heap's job is that this does not
        // matter.
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

    /// A recorded instant is a hint, and the queue re-checks it rather than
    /// trusting it.
    ///
    /// A retry aimed at the same host moves its slot after an entry is queued,
    /// so an entry reaches the front before its host is really ready. Trusting
    /// the stored instant would send a probe inside the gap the caller asked
    /// for, which is the one thing this feature must not do.
    #[test]
    fn a_slot_that_moved_after_the_probe_was_held_is_re_checked() {
        let gap = Duration::from_secs(3600);
        let (mut core, _session) = spaced_core(gap);
        let now = Instant::now();

        // Held as though its host were ready immediately.
        core.hold(TARGET, 80, Some(0), now);
        // And then the host is probed, which moves the real slot an hour out.
        core.ctx.host_probed(TARGET, now);

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

    /// A held probe is something still to send, so a stream that ran dry does
    /// not conclude the scan while one is waiting.
    ///
    /// Getting this wrong reports a port the scan chose to delay as one it asked
    /// about and heard nothing from, which is a verdict from a probe that was
    /// never sent.
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

    /// The queue bounds the stream and deliberately not the send path.
    ///
    /// A full queue closing the send path would be a scan that stopped and never
    /// restarted, since sending is what empties it.
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

    /// The condition the whole loop exists to get right: an empty ledger means
    /// "everything has been answered or written off" only once there is nothing
    /// left to ask. Reached before the stream runs dry it would end a scan that
    /// had not yet sent most of its probes.
    ///
    /// The way that actually happens is the send path failing. A link that has
    /// stopped accepting sends leaves the ledger empty while the stream is still
    /// full, and a loop that read the quiet as an answer would abandon every
    /// target still queued, measured at thirty-one thousand, and report them as
    /// ports nobody could reach.
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

    /// Silence is only evidence once nothing is outstanding. With probes still
    /// waiting on their timers, quiet is what the retry schedule expects.
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

    /// An abort is checked before anything else, so a scan winds down promptly
    /// rather than after whatever else it was in the middle of.
    #[test]
    fn an_abort_outranks_every_other_reason() {
        let (mut core, _session) = core();
        core.ledger.arm(TARGET, (TARGET, 80), (), 0, Instant::now());
        core.ctx.handle.abort();

        assert_eq!(core.stop_reason(false), Some(StopReason::Aborted));
    }

    /// The window is what makes a scan self-pacing: probes leave as earlier ones
    /// are resolved, rather than as fast as the socket accepts writes.
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

    /// A reply to the first attempt says the target is keeping up. A reply to a
    /// later one says it was willing all along and the first question did not
    /// survive, which is the one thing a port scanner can observe that
    /// separates being too fast from meeting a firewall.
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

    /// A send the kernel refused is backpressure from this machine, and the one
    /// signal in the controller that does not come from the network at all.
    ///
    /// Whatever refused it, a full interface queue, a neighbour that stopped
    /// resolving under load, offering more of the same faster cannot help.
    /// Measured: seven thousand `No route to host` failures in one run, at an
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
    /// neighbour waits for the resolution rather than joining its queue, and
    /// goes once the neighbour answers.
    ///
    /// Linux takes a write to a neighbour it is still asking for and queues
    /// it, charged to the socket, so a scan writing freely to a neighbour that
    /// never answers fills its own send buffer and has every write refused,
    /// the live hosts' too. A live neighbour costs one short hold.
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

    /// A neighbour the kernel gave up on is an address nothing reaches: filed
    /// unreachable, sent nothing more, and no fault of this host's.
    #[test]
    fn a_neighbour_the_kernel_gave_up_on_is_filed_unreachable_without_a_send() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (mut core, _session, _reads) = core_reading(std::sync::Arc::clone(&state));
        assert_eq!(core.admit(TARGET, Instant::now()), Admission::Send);

        *state.lock().unwrap() = Some(NeighborState::Failed);
        assert_eq!(core.admit(TARGET, Instant::now()), Admission::Unreachable);
        assert!(core.is_unreachable(&TARGET), "the address is filed");
        assert!(
            core.send_failure.is_none(),
            "and nothing on this host failed"
        );
    }

    /// A probe that ran its whole schedule while the kernel was still asking
    /// for its neighbour never left, so the scan reads it as waiting on the
    /// resolution rather than as a port that stayed silent.
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
    /// unreachable, wherever its one probe was: a probe that ran out of
    /// attempts while the kernel asked is back in the hold queue, off the
    /// ledger that the scan's end otherwise reads.
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
    /// so the table is never read for it and its probes go as they always did.
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

    /// Hosts behind a gateway that never answers its address resolution send
    /// one probe between them, and are filed unreachable on the gateway's
    /// verdict, every one of them.
    ///
    /// A host behind a gateway has no neighbour entry of its own: its writes
    /// queue on the gateway's. Written freely, every host's probes behind a
    /// dead gateway are taken by the kernel, charged to the socket and thrown
    /// away three seconds later, which read as silence and fill the send
    /// buffer until the kernel refuses the socket's writes to every host.
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

    /// An address the sender says cannot be reached, and which has never
    /// answered, is an absent host rather than a busy path. The window paces
    /// the scan against what its targets manage to answer, and a dead neighbour
    /// among live hosts would otherwise cut it for every one of them, while
    /// nothing a slower pace did could change the answer.
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

    /// Silence from a host that has never said anything is not congestion. It is
    /// what a firewall and a dead address both produce, and a controller that
    /// read it as congestion would crawl against exactly the hosts that are
    /// hardest to finish, while learning nothing, because nothing it did would
    /// change the answer.
    #[test]
    fn silence_from_a_host_that_never_answered_opens_the_window() {
        let (mut core, _session) = core();
        core.window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));

        core.window.record_send();
        core.judge_timeout(TARGET, PortState::Filtered);

        assert!(
            core.window.capacity() >= 64,
            "nothing this host did says the path is busy"
        );
        assert_eq!(core.window.in_flight(), 0, "and the slot went back");
    }

    /// Silence from a host that is answering most of what it is asked is the
    /// opposite: it is not running a block list, it is failing to keep up.
    ///
    /// A controller without this signal fails measurably. Against a Raspberry Pi
    /// answering three quarters of a thousand probes, its window never cut once
    /// and the remaining quarter was reported as a firewall that did not exist:
    /// a different set of ports on every run.
    #[test]
    fn silence_from_a_host_that_is_answering_cuts_the_window() {
        let (mut core, _session) = core();
        core.window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));

        // One port answered, which is what makes this host's silence mean
        // something.
        let now = Instant::now();
        core.ledger.arm(TARGET, (TARGET, 22), (), 0, now);
        core.ledger.resolve(&(TARGET, 22), None, now);

        core.window.record_send();
        core.judge_timeout(TARGET, PortState::Filtered);

        assert!(
            core.window.capacity() < 64,
            "a host that talks and then goes quiet is being outrun"
        );
        assert_eq!(core.window.in_flight(), 0, "and the slot still went back");
    }

    /// **A host verdict answers whether it was recorded**, and the usual case
    /// is a host already in the store.
    ///
    /// A port scan mostly probes hosts an earlier phase found, so the host an
    /// unreachable names is ordinarily there before the unreachable arrives.
    /// Whether this call happened to create it is a fact about the store's
    /// history, and answering that would report the ordinary case as a message
    /// that went nowhere.
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

    /// A host unreachable from this host's own address is its kernel giving
    /// up on a neighbour, and the address is filed unreachable rather than
    /// down, as the neighbour table would file it.
    ///
    /// Linux sends one to itself for each write it threw away with a failed
    /// resolution, and whether the capture on loopback catches it is chance.
    /// Read as `Down`, identical dead neighbours would come back with two
    /// statuses by which of those messages were caught.
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

    /// And `false` means nothing reached the store: an address the scan's
    /// exclusions forbid is dropped there, whatever probe the message names.
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
