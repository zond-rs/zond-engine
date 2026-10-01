// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Probe Retransmission
//!
//! The bookkeeping behind sending a probe more than once.
//!
//! A probe that is never answered looks the same as one that never arrived, and
//! reading the first as evidence reports a firewall where a packet was dropped. The
//! only way to tell them apart is to ask again, which makes each probe a small state
//! machine: how many times it has been asked, when to ask again, and when silence
//! finally means something.
//!
//! [`ProbeLedger`] is that state machine, shared by the SYN, UDP and link-layer
//! paths. It holds no packets: a scanner tells it what left the wire and asks it what
//! to do next.
//!
//! # The three questions
//!
//! - *Is this reply an answer to something I sent?* [`ProbeLedger::resolve`]
//! - *What should I resend, and what has run out of attempts?*
//!   [`ProbeLedger::drain_due`]
//! - *How long may I sleep?* [`ProbeLedger::next_due`]
//!
//! # Why attempts are tracked individually
//!
//! A record keeps a token per attempt. In a SYN scan, attempt one carries sequence
//! number A, attempt two carries B, and then a `SYN+ACK` acknowledging A arrives. A
//! scanner holding only B would report that open port silent, so retransmission
//! would make the scan less accurate on the lossy paths it exists for.
//!
//! Keeping every live token also avoids Karn's problem. TCP must discard round-trip
//! samples from retransmitted segments because it cannot tell which transmission an
//! acknowledgement answers. A scanner picks a fresh sequence number per attempt, so
//! when the caller can name the attempt that answered, the sample is kept. Where the
//! wire carries nothing to distinguish attempts (a UDP probe from a fixed source
//! port, an ARP request) the caller passes no token and [`ProbeLedger`] applies
//! Karn's rule.
//!
//! # Cost
//!
//! Expiry is driven by a deadline-ordered queue, so a tick with nothing due costs one
//! comparison and arming or retiring a probe costs `O(log n)`. Stale queue entries
//! are discarded when they surface.

use super::timer::later;
use crate::config::{RetryConfig, ScanEffort};
use crate::model::host::telemetry::HostTelemetry;
use std::collections::{BinaryHeap, HashMap};
use std::hash::Hash;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// How many attempt tokens one probe retains.
///
/// A reply older than the last few attempts would have outlived several
/// round-trip timeouts, and its probe has usually been retired. The bound keeps a
/// record a fixed size, with no allocation per probe.
const MAX_TRACKED_ATTEMPTS: usize = 4;

/// How the budget is cut for a host that has never said anything.
///
/// A full budget on every port of an address that answers nothing is the largest
/// source of wasted traffic in a wide scan: three attempts across 65 535 ports is
/// nearly 200 000 packets.
///
/// *Any* reply counts as life (a `RST`, an ICMP error, an ARP reply), so a
/// firewalled host that refuses even one port never triggers it, and the budget is
/// reduced, not abandoned. It can still miss an open port behind a path lossy enough
/// to drop consecutive probes, on a host that answered nothing else, which is why
/// this is optional.
///
/// `#[non_exhaustive]`: build it with [`new`](Self::new).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SilentHostPolicy {
    /// Probes to one host that must exhaust their full budget, with no reply of
    /// any kind ever seen from it, before the budget is cut.
    pub threshold: u16,
    /// The budget applied to that host's subsequent probes.
    pub reduced_attempts: u8,
}

impl SilentHostPolicy {
    /// Cuts a host to `reduced_attempts` once `threshold` of its probes have
    /// spent their whole budget without it ever answering anything.
    pub const fn new(threshold: u16, reduced_attempts: u8) -> Self {
        Self {
            threshold,
            reduced_attempts,
        }
    }
}

/// The fixed parameters a [`ProbeLedger`] runs on.
///
/// Declared per scanner beside its deadline profile, since a reasonable wait
/// depends on the protocol: a SYN is answered as fast as the path allows, while an
/// ICMP error is rate-limited to roughly one per second by the host that sends it.
///
/// `#[non_exhaustive]`: build it with [`new`](Self::new) and the builders beside it.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Total sends per probe, initial attempt included. One disables
    /// retransmission, as an internet-scale sweep will want.
    pub max_attempts: u8,
    /// The timeout used before anything has been measured.
    ///
    /// Distinct from [`min_rto`](Self::min_rto): with no samples the network is
    /// unknown, and starting at the floor would triple the traffic of a scan whose
    /// first probes cross an ocean. Only measurement pushes the timeout toward the
    /// floor.
    pub initial_rto: Duration,
    /// The shortest timeout measurement may justify.
    pub min_rto: Duration,
    /// The longest timeout, applied to the backed-off value as well. Also caps
    /// [`initial_rto`](Self::initial_rto).
    pub max_rto: Duration,
    /// Multiplier applied per attempt, so a path that is losing packets is asked
    /// less often.
    pub backoff: f64,
    /// Fractional spread applied to every deadline, as a proportion of it.
    ///
    /// Probes admitted together time out together, and unjittered retries would
    /// leave as a synchronized burst when the path is least able to absorb one.
    ///
    /// Upward only: a deadline is drawn between itself and itself lengthened by
    /// this fraction. Spread below, it could land under the floor or under the
    /// host's measured round trip: with one attempt behind a 20 ms path, a 30%
    /// spread down from a 25 ms floor read about one open port in five as silent.
    pub jitter: f64,
    /// How the budget is cut for hosts that never answer, if at all.
    pub silent_host: Option<SilentHostPolicy>,
    /// Whether one host's round trip is evidence about another's, which decides
    /// if a target with no measurement of its own inherits the scan's.
    ///
    /// True where timing is dominated by the path: on a routed scan every probe
    /// crosses the same links, so the first host to answer says roughly what the
    /// rest will cost.
    ///
    /// False where timing is dominated by the responder. In neighbour discovery a
    /// mains-powered router answers in five milliseconds and a phone asleep on
    /// wifi in four hundred, over the same link. Inheriting the fast estimate
    /// retransmits to the slow host before it could answer, and for a probe whose
    /// attempts are indistinguishable on the wire that destroys the measurement.
    pub cross_host_estimate: bool,
}

impl RetryPolicy {
    /// A schedule of at most `max_attempts` sends per probe: the first timed at
    /// `initial_rto`, each later one backed off by `backoff`, every deadline
    /// held within `min_rto` and `max_rto` and spread by `jitter`. Pass a
    /// `silent_host` policy to cut the budget of an address that answers
    /// nothing at all.
    ///
    /// A target with no measurement of its own inherits the scan's. Where the
    /// responder decides the timing, chain
    /// [`without_cross_host_estimate`](Self::without_cross_host_estimate).
    pub const fn new(
        max_attempts: u8,
        initial_rto: Duration,
        min_rto: Duration,
        max_rto: Duration,
        backoff: f64,
        jitter: f64,
        silent_host: Option<SilentHostPolicy>,
    ) -> Self {
        Self {
            max_attempts,
            initial_rto,
            min_rto,
            max_rto,
            backoff,
            jitter,
            silent_host,
            cross_host_estimate: true,
        }
    }

    /// This policy with each target timed on its own evidence only.
    ///
    /// See [`cross_host_estimate`](Self::cross_host_estimate).
    pub const fn without_cross_host_estimate(self) -> Self {
        Self {
            cross_host_estimate: false,
            ..self
        }
    }

    /// Sends each probe exactly once.
    ///
    /// What an address-space-scale sweep wants, where per-probe state cannot be
    /// afforded and coverage comes from a second pass.
    #[cfg(test)]
    pub const fn none() -> Self {
        Self::new(
            1,
            Duration::from_millis(200),
            Duration::from_millis(25),
            Duration::from_secs(2),
            2.0,
            0.2,
            None,
        )
    }

    /// This policy as `config` asks for it.
    ///
    /// The scanner's own numbers are the starting point. The effort level and
    /// scale factor move how long the scan is willing to wait, but not the floor.
    pub fn configured(self, config: RetryConfig) -> Self {
        let mut policy = match config.effort {
            ScanEffort::Single => Self {
                max_attempts: 1,
                ..self
            },
            ScanEffort::Fast => Self {
                max_attempts: self.max_attempts.saturating_sub(1).max(1),
                ..self
            }
            .scaled(0.6),
            ScanEffort::Balanced => self,
            ScanEffort::Thorough => Self {
                max_attempts: self.max_attempts.saturating_add(2),
                ..self
            }
            .scaled(1.5),
        };

        if config.effort == ScanEffort::Thorough || !config.dampen_silent_hosts {
            policy.silent_host = None;
        }
        if let Some(max_attempts) = config.max_attempts {
            policy.max_attempts = max_attempts.get();
        }
        if let Some(scale) = config.timeout_scale {
            policy = policy.scaled(scale.get());
        }

        policy
    }

    /// This policy with its patience multiplied by `factor`.
    ///
    /// [`min_rto`](Self::min_rto) is untouched: it is the shortest wait that can
    /// still produce an answer, a property of the protocol.
    ///
    /// `factor` is positive and finite, because
    /// [`TimeoutScale`](crate::config::TimeoutScale) refuses anything else.
    fn scaled(self, factor: f64) -> Self {
        debug_assert!(
            factor.is_finite() && factor > 0.0,
            "a scale that cannot build a schedule is refused at `TimeoutScale`, \
             and the effort levels below pass their own literals"
        );

        Self {
            initial_rto: saturating_mul(self.initial_rto, factor),
            // The floor wins over a ceiling scaled below it, since the protocol
            // imposes it.
            max_rto: saturating_mul(self.max_rto, factor).max(self.min_rto),
            ..self
        }
    }

    /// The longest a probe can occupy the ledger: every attempt's timeout at
    /// its most generous, with no measurement to shorten it.
    ///
    /// A scan's hard budget must be at least this, or probes are written off
    /// before they are fully asked.
    #[cfg(test)]
    pub fn worst_case_probe_lifetime(&self) -> Duration {
        let mut total = Duration::ZERO;
        for attempt in 1..=self.max_attempts {
            let scaled = scale(self.initial_rto, self.backoff, attempt, self.max_rto);
            total = total.saturating_add(saturating_mul(scaled, 1.0 + self.jitter.max(0.0)));
        }
        total
    }

    /// The longest any one attempt may wait for its answer: the ceiling, spread
    /// as far as the jitter reaches.
    ///
    /// Longer than the first timeout of `worst_case_probe_lifetime`, which assumes
    /// nothing has been measured: a host measured slow is timed at up to this on
    /// every attempt, the first included.
    pub(crate) fn longest_timeout(&self) -> Duration {
        let ceiling = self.max_rto.max(self.min_rto);
        saturating_mul(ceiling, 1.0 + self.jitter.clamp(0.0, 1.0))
    }

    /// The longest a probe can occupy the ledger whatever was measured: every
    /// attempt at [`longest_timeout`](Self::longest_timeout).
    pub(crate) fn longest_probe_lifetime(&self) -> Duration {
        self.longest_timeout()
            .saturating_mul(u32::from(self.max_attempts.max(1)))
    }

    /// [`longest_probe_lifetime`](Self::longest_probe_lifetime) for a scan
    /// keeping `gap` between two probes at one host: every attempt waits the
    /// longer of its timeout and the gap before the next can leave.
    ///
    /// For a caller whose retries are held for the gap with their clocks stopped
    /// (see [`ProbeLedger::defer`]).
    pub(crate) fn longest_spaced_probe_lifetime(&self, gap: Option<Duration>) -> Duration {
        self.longest_timeout()
            .max(gap.unwrap_or_default())
            .saturating_mul(u32::from(self.max_attempts.max(1)))
    }

    /// The budget for a probe to `host`, after any silent-host reduction.
    fn budget_for(&self, host: Option<&HostState>) -> u8 {
        let Some(rule) = self.silent_host else {
            return self.max_attempts;
        };
        let Some(host) = host else {
            return self.max_attempts;
        };

        if host.answers == 0 && host.exhausted_silently >= rule.threshold {
            return rule.reduced_attempts.min(self.max_attempts);
        }
        self.max_attempts
    }
}

/// One in how many of the probes put to a host it has to answer before its
/// silence is read as loss; see [`ProbeLedger::host_is_answering`].
///
/// A tenth of the ports asked is the most a scan promises to find open without
/// reading their silence as loss (see [`congestion`](super::congestion)). A host
/// answering no more than that is a firewall letting those ports through; a host
/// being outrun answers most of what reaches it, three quarters in the case
/// measured.
const ANSWERING_ONE_IN: u32 = 10;

/// The smallest headroom a measured timeout keeps over the smoothed round
/// trip, as that round trip divided by this. See [`RttEstimator::timeout`].
const MIN_HEADROOM_DIVISOR: u32 = 4;

/// A smoothed round-trip estimate and its variability, as RFC 6298 computes
/// them for TCP.
///
/// Kept per host, so it is two durations updated in place. The scan-wide deadline
/// uses a sample window instead, [`RttWindow`](super::rtt_window::RttWindow).
#[derive(Debug, Clone, Copy, Default)]
pub struct RttEstimator {
    smoothed: Option<Duration>,
    variation: Duration,
    /// Whether the estimate came from [`seed`](Self::seed), so the first
    /// measurement replaces it.
    seeded: bool,
}

impl RttEstimator {
    /// Folds in one round-trip measurement.
    ///
    /// The first sample becomes the estimate outright and sets the variation at
    /// half of itself (RFC 6298), so one fast sample cannot produce a timeout too
    /// tight for the second. A [seeded](Self::seed) estimate is discarded first.
    pub fn record(&mut self, sample: Duration) {
        if std::mem::take(&mut self.seeded) {
            self.smoothed = None;
        }
        match self.smoothed {
            None => {
                self.smoothed = Some(sample);
                self.variation = sample / 2;
            }
            Some(smoothed) => {
                // |smoothed - sample| weighted 1/4 against 3/4 of the old
                // variation, then the estimate itself weighted 1/8 to 7/8.
                let deviation = smoothed.abs_diff(sample);
                self.variation = (self.variation * 3 + deviation) / 4;
                self.smoothed = Some((smoothed * 7 + sample) / 8);
            }
        }
    }

    /// The timeout these samples justify, or `None` while there are none.
    ///
    /// Four variations of headroom, the margin TCP allows itself.
    ///
    /// The headroom is at least a quarter of the smoothed round trip. On a path
    /// whose replies mostly agree the variation decays towards nothing, leaving a
    /// timeout equal to the round trip that every slightly slow reply misses: with
    /// one reply in twenty ten percent slow, a steady 100 ms path read a fifth to
    /// two fifths of those as silent on one attempt. TCP's floor of one clock tick
    /// (RFC 6298's G) is meaningless at this clock resolution; a steady path strays
    /// by a share of its own round trip, so the floor is a share too. A quarter
    /// clears the measured ten percent, and below about 20 ms the policy's own floor
    /// is larger anyway.
    pub fn timeout(&self) -> Option<Duration> {
        self.smoothed.map(|smoothed| {
            let headroom = (self.variation * 4).max(smoothed / MIN_HEADROOM_DIVISOR);
            smoothed.saturating_add(headroom)
        })
    }

    /// Whether nothing has been recorded yet, in which case
    /// [`timeout`](Self::timeout) returns `None`.
    pub fn is_empty(&self) -> bool {
        self.smoothed.is_none()
    }

    /// Starts an empty estimate from `rtt`, a round trip something other than
    /// this estimate's own probes measured, and keeps it only until the first
    /// [`record`](Self::record), which replaces it.
    ///
    /// Until then it times probes as one sample would. It is then dropped, not
    /// smoothed against: under RFC 6298's weights each later sample moves the
    /// estimate only an eighth, so a seed well above the path's round trip would
    /// dominate the timeout of a host that answers once. Linux does the same with
    /// its per-destination metrics, which set a new connection's first timeout and
    /// leave the smoothed estimate to its first measurement.
    ///
    /// Does nothing to an estimate that holds anything already.
    pub(crate) fn seed(&mut self, rtt: Duration) {
        if self.is_empty() {
            self.record(rtt);
            self.seeded = true;
        }
    }
}

/// One attempt as it left the wire.
#[derive(Debug, Clone, Copy)]
struct Attempt<T> {
    token: T,
    sent_at: Instant,
    /// Whether this attempt was seen leaving on the wire, which a successful
    /// `sendto` does not establish (macOS accepts writes it then drops). A flag so
    /// the same frame seen twice counts once.
    witnessed: bool,
}

/// An outstanding probe.
struct Record<T, P> {
    /// Caller data handed over at [`ProbeLedger::arm`] and given back when the
    /// probe retires. The ledger never reads it.
    payload: P,
    host: IpAddr,
    /// The live attempts, oldest first, capped at [`MAX_TRACKED_ATTEMPTS`].
    attempts: [Option<Attempt<T>>; MAX_TRACKED_ATTEMPTS],
    /// How many sends this probe has had, which may exceed the number of
    /// tokens retained.
    sends: u8,
    /// How many of this probe's attempts were seen leaving on the wire. Zero
    /// when every send was accepted and dropped. See [`Attempt::witnessed`].
    witnessed: u8,
    /// How many sends actually reached the wire and were recorded here.
    ///
    /// Separate from [`sends`](Self::sends), which is charged when a retry is
    /// scheduled so that a probe nobody manages to send still exhausts on time.
    /// Attempt numbering follows this count.
    recorded: u8,
    /// The budget in force, resolved when the probe was first armed and again
    /// on every retry, so a host that comes to life mid-scan lifts the
    /// restriction on probes still outstanding against it.
    budget: u8,
    /// Identifies this record's live queue entry. An entry carrying a different
    /// value has been superseded and is discarded on sight, which cancels a timer
    /// without searching for it.
    generation: u32,
    /// Whether the retry this probe was last scheduled for is still waiting to
    /// be sent, with its clock stopped. See [`ProbeLedger::defer`].
    deferred: bool,
}

impl<T: Copy, P> Record<T, P> {
    /// A record for a probe whose first attempt is going out now.
    fn new(host: IpAddr, budget: u8, generation: u32, payload: P) -> Self {
        Self {
            payload,
            host,
            attempts: [None; MAX_TRACKED_ATTEMPTS],
            sends: 1,
            recorded: 0,
            witnessed: 0,
            budget,
            generation,
            deferred: false,
        }
    }

    /// Stores the token one attempt was sent with, evicting the oldest when the
    /// array is full.
    ///
    /// The attempt count is charged by [`ProbeLedger::drain_due`] when it
    /// schedules a retry, so a retry that is never emitted still exhausts on
    /// schedule.
    fn record_attempt(&mut self, token: T, sent_at: Instant) {
        self.recorded = self.recorded.saturating_add(1);

        let fresh = Attempt {
            token,
            sent_at,
            witnessed: false,
        };

        if self.attempts[MAX_TRACKED_ATTEMPTS - 1].is_some() {
            self.attempts.rotate_left(1);
            self.attempts[MAX_TRACKED_ATTEMPTS - 1] = Some(fresh);
            return;
        }

        let slot = self
            .attempts
            .iter()
            .position(Option::is_none)
            .unwrap_or(MAX_TRACKED_ATTEMPTS - 1);
        self.attempts[slot] = Some(fresh);
    }

    /// Marks the attempt carrying `token` as seen on the wire, returning whether
    /// this was its first sighting. False for a token this record does not hold
    /// or one already witnessed.
    fn witness(&mut self, token: &T) -> bool
    where
        T: PartialEq,
    {
        let Some(attempt) = self
            .attempts
            .iter_mut()
            .flatten()
            .find(|attempt| attempt.token == *token)
        else {
            return false;
        };
        if attempt.witnessed {
            return false;
        }
        attempt.witnessed = true;
        self.witnessed = self.witnessed.saturating_add(1);
        true
    }

    /// The attempt carrying `token`: which send it was, counting the first as
    /// 1, and when it left.
    ///
    /// Only the last few attempts are tracked, so the ordinal is counted back from
    /// the newest. A probe retried more than [`MAX_TRACKED_ATTEMPTS`] times has
    /// forgotten its earliest tokens, and a reply to one of those is unrecognized.
    fn attempt_of(&self, token: &T) -> Option<(u8, Instant)>
    where
        T: PartialEq,
    {
        let tracked = self.attempts.iter().flatten().count();

        self.attempts
            .iter()
            .flatten()
            .enumerate()
            .find(|(_, attempt)| attempt.token == *token)
            .map(|(slot, attempt)| {
                let back_from_newest = (tracked - 1 - slot) as u8;
                (
                    self.recorded.saturating_sub(back_from_newest),
                    attempt.sent_at,
                )
            })
    }

    /// The only tracked attempt's send time, or `None` if there is more than
    /// one (Karn's rule).
    fn unambiguous_sent_at(&self) -> Option<Instant> {
        if self.sends != 1 {
            return None;
        }
        self.attempts
            .iter()
            .flatten()
            .next()
            .map(|attempt| attempt.sent_at)
    }
}

/// What is known about one host across every probe aimed at it.
#[derive(Debug, Clone, Copy, Default)]
struct HostState {
    estimator: RttEstimator,
    /// Probes currently outstanding against this host.
    outstanding: u32,
    /// Probes to it a reply resolved, whichever attempt it answered.
    answers: u32,
    /// Probes to it whose first attempt went unanswered for its whole
    /// timeout, answered later or not.
    silences: u32,
    /// Probes that spent their whole budget while it stayed silent.
    exhausted_silently: u16,
}

/// A queue entry: when a probe next needs attention.
///
/// Ordered so that [`BinaryHeap`], which is a max-heap, yields the *earliest*
/// deadline first.
struct Timer<K> {
    due: Instant,
    key: K,
    generation: u32,
}

impl<K> PartialEq for Timer<K> {
    fn eq(&self, other: &Self) -> bool {
        self.due == other.due
    }
}
impl<K> Eq for Timer<K> {}
impl<K> Ord for Timer<K> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.due.cmp(&self.due)
    }
}
impl<K> PartialOrd for Timer<K> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// What a probe needs once its timer has fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Due<K, P = ()> {
    /// Send this again. The probe stays outstanding and the ledger has already
    /// counted the attempt, so a caller that cannot send (no route, a refused
    /// socket) may do nothing and let it exhaust.
    Retry {
        /// Which probe to send again.
        key: K,
        /// Which attempt this is, counting the first send as one.
        attempt: u8,
    },
    /// The budget is spent and the probe is no longer outstanding. Only now is a
    /// "no-reply" verdict earned.
    Exhausted {
        /// The probe being retired.
        key: K,
        /// Whatever the caller armed this probe with.
        payload: P,
        /// How many times it was sent. A pacing controller needs this: a probe's
        /// first timeout is the one that says something about the path, and with a
        /// budget of one attempt this event is that first timeout.
        attempts: u8,
        /// How many of those sends were seen leaving. Zero here while the run
        /// witnessed others is a probe never asked; always zero for a caller
        /// that does not witness its sends.
        witnessed: u8,
    },
}

/// What resolving a probe revealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolution<P = ()> {
    /// Whatever the caller armed this probe with.
    pub payload: P,
    /// The measured round trip, or `None` when the reply could not be
    /// attributed to one attempt.
    pub rtt: Option<Duration>,
    /// How many times the probe had been sent.
    pub attempts: u8,
    /// Which send the reply answered, the first being 1, or `None` where
    /// nothing in the reply named one.
    ///
    /// Separates a probe that needed repeating from one that needed waiting for:
    /// a host credited after three attempts may have answered the third, or the
    /// first over a slow path. That decides whether coverage is bought with more
    /// packets or with more patience.
    pub answered_attempt: Option<u8>,
}

/// The outstanding probes of one scanner, and the schedule on which they are
/// resent and retired.
///
/// `K` identifies a probe: `(IpAddr, u16)` for a port scan, `IpAddr` for host
/// discovery. `T` is the per-attempt token a reply can be matched against, such
/// as a TCP sequence number; where the wire carries no such thing, use `()`.
///
/// The caller supplies the time at every entry point, so a scan loop reads the
/// clock once per iteration and the structure is testable without sleeping.
pub struct ProbeLedger<K, T, P = ()> {
    policy: RetryPolicy,
    records: HashMap<K, Record<T, P>>,
    timers: BinaryHeap<Timer<K>>,
    hosts: HashMap<IpAddr, HostState>,
    /// Fallback timing for a host that has not answered yet.
    global: RttEstimator,
    next_generation: u32,
    jitter: Jitter,
}

impl<K, T, P> ProbeLedger<K, T, P>
where
    K: Copy + Eq + Hash,
    T: Copy + PartialEq,
    P: Copy,
{
    /// An empty ledger with room for `capacity` outstanding probes.
    pub fn new(policy: RetryPolicy, capacity: usize) -> Self {
        Self::seeded(policy, capacity, rand::random())
    }

    /// [`new`](Self::new) with the jitter sequence pinned, for tests.
    pub fn seeded(policy: RetryPolicy, capacity: usize, seed: u64) -> Self {
        Self {
            policy,
            records: HashMap::with_capacity(capacity),
            timers: BinaryHeap::with_capacity(capacity),
            hosts: HashMap::new(),
            global: RttEstimator::default(),
            next_generation: 0,
            jitter: Jitter::new(seed),
        }
    }

    /// Records that a probe for `key` just left the wire carrying `token`.
    ///
    /// Called after the first send and after every retry; the ledger counts the
    /// attempts itself. Arming supersedes any timer the probe already had, so the
    /// timeout runs from when the packet actually left.
    pub fn arm(&mut self, host: IpAddr, key: K, token: T, payload: P, now: Instant) {
        self.arm_inner(host, key, token, Some(payload), now);
    }

    /// Records a *retry* for a probe already outstanding, keeping the payload it
    /// was armed with.
    ///
    /// A retry is driven from [`Due::Retry`], which names the probe but carries no
    /// payload.
    pub fn rearm(&mut self, host: IpAddr, key: K, token: T, now: Instant) {
        self.arm_inner(host, key, token, None, now);
    }

    fn arm_inner(&mut self, host: IpAddr, key: K, token: T, payload: Option<P>, now: Instant) {
        let generation = self.take_generation();

        let host_state = self.hosts.entry(host).or_default();
        let budget = self.policy.budget_for(Some(host_state));

        let record = match self.records.get_mut(&key) {
            Some(record) => {
                // Re-read, so a host that has since answered lifts any
                // restriction on its outstanding probes.
                record.budget = budget;
                record.generation = generation;
                record.deferred = false;
                if let Some(payload) = payload {
                    record.payload = payload;
                }
                record
            }
            None => {
                // A `rearm` for a probe resolved or retired between the retry
                // being scheduled and the send: dropped, like a stale timer.
                let Some(payload) = payload else {
                    return;
                };
                host_state.outstanding += 1;
                self.records
                    .entry(key)
                    .or_insert_with(|| Record::new(host, budget, generation, payload))
            }
        };

        record.record_attempt(token, now);
        let attempt = record.sends;

        let due = later(now, self.timeout_for(host, attempt));
        self.timers.push(Timer {
            due,
            key,
            generation,
        });
    }

    /// Resolves the probe `key` if it is outstanding, returning what the reply
    /// revealed.
    ///
    /// `token` names the attempt that was answered. Passing `None` means the
    /// caller cannot tell, in which case a round trip is reported only for a
    /// probe that was sent once and so has nothing to be ambiguous about.
    ///
    /// Returns `None` for a duplicate, a reply to a probe already resolved or
    /// retired, and a token matching no live attempt; the caller drops all of
    /// these. Resolution is exactly-once.
    pub fn resolve(&mut self, key: &K, token: Option<T>, now: Instant) -> Option<Resolution<P>> {
        let record = self.records.get(key)?;
        let payload = record.payload;

        let attributed = match token {
            // A token naming no attempt we made is someone else's packet; the
            // probe stays outstanding.
            Some(token) => Some(record.attempt_of(&token)?),
            // A probe sent once can only have been answered by its first
            // attempt.
            None => record.unambiguous_sent_at().map(|sent_at| (1, sent_at)),
        };

        let answered_attempt = attributed.map(|(ordinal, _)| ordinal);
        let sent_at = attributed.map(|(_, sent_at)| sent_at);

        let attempts = record.sends;
        let host = record.host;
        self.records.remove(key);

        let rtt = sent_at.map(|sent_at| now.saturating_duration_since(sent_at));

        let host_state = self.hosts.entry(host).or_default();
        host_state.outstanding = host_state.outstanding.saturating_sub(1);
        host_state.answers = host_state.answers.saturating_add(1);
        if let Some(rtt) = rtt {
            host_state.estimator.record(rtt);
            self.global.record(rtt);
        }

        Some(Resolution {
            payload,
            rtt,
            attempts,
            answered_attempt,
        })
    }

    /// Appends every probe whose timer has fired to `out`.
    ///
    /// A [`Due::Retry`] leaves the probe outstanding with its attempt already
    /// counted; a [`Due::Exhausted`] has removed it. The caller supplies the
    /// buffer, so it can send while the ledger is borrowed and a tick with nothing
    /// due allocates nothing.
    pub fn drain_due(&mut self, now: Instant, out: &mut Vec<Due<K, P>>) {
        while let Some(timer) = self.timers.peek() {
            if timer.due > now {
                break;
            }

            let timer = self.timers.pop().expect("peeked");
            let Some(record) = self.records.get_mut(&timer.key) else {
                continue; // Resolved since; the entry is stale.
            };
            if record.generation != timer.generation {
                continue; // Superseded by a later arm.
            }

            // The first attempt's timeout, at most once per probe: what
            // `host_is_answering` weighs against the answers.
            if record.sends == 1 {
                let state = self.hosts.entry(record.host).or_default();
                state.silences = state.silences.saturating_add(1);
            }
            if record.sends >= record.budget {
                let host = record.host;
                let attempts = record.sends;
                let witnessed = record.witnessed;
                let payload = record.payload;
                self.records.remove(&timer.key);
                self.retire(host);
                out.push(Due::Exhausted {
                    key: timer.key,
                    payload,
                    attempts,
                    witnessed,
                });
                continue;
            }

            // Counted here, so a probe whose retry is never emitted still
            // exhausts on schedule.
            record.sends += 1;
            let attempt = record.sends;
            let host = record.host;
            let generation = self.take_generation();
            self.records
                .get_mut(&timer.key)
                .expect("record present")
                .generation = generation;

            let due = later(now, self.timeout_for(host, attempt));
            self.timers.push(Timer {
                due,
                key: timer.key,
                generation,
            });

            out.push(Due::Retry {
                key: timer.key,
                attempt,
            });
        }
    }

    /// When the next timer fires, or `None` while nothing is outstanding.
    ///
    /// What a scan loop sleeps on. It may name a superseded entry's deadline and
    /// wake the loop early, at the cost of one extra iteration.
    pub fn next_due(&self) -> Option<Instant> {
        self.timers.peek().map(|timer| timer.due)
    }

    /// Stops `key`'s clock while the retry [`drain_due`](Self::drain_due) just
    /// scheduled for it waits for the caller's admission.
    ///
    /// For a caller that sends a retry when its own pacing allows. The attempt is
    /// already charged; what stops is the timer that would charge the next one or
    /// retire the probe. Left running, a held retry could be overtaken by the next,
    /// and the probe could retire as silent having been asked fewer times than its
    /// budget.
    ///
    /// The clock restarts at [`rearm`](Self::rearm) when the retry is sent, or at
    /// [`resume`](Self::resume) if it is not. A caller that defers must do one or
    /// the other, or the probe stays outstanding until the scan ends.
    pub(crate) fn defer(&mut self, key: &K) {
        let generation = self.take_generation();
        if let Some(record) = self.records.get_mut(key) {
            record.generation = generation;
            record.deferred = true;
        }
    }

    /// Restarts `key`'s clock from `now`, for a deferred retry that was not
    /// sent after all: refused by the sender, or aimed at an address that
    /// cannot be reached. The attempt stays charged, so the probe still runs
    /// out of attempts on schedule.
    ///
    /// Does nothing for a probe that is not deferred, which includes one whose
    /// retry was sent and re-armed.
    pub(crate) fn resume(&mut self, key: &K, now: Instant) {
        let Some(record) = self.records.get(key) else {
            return;
        };
        if !record.deferred {
            return;
        }
        let (host, attempt) = (record.host, record.sends);
        let due = later(now, self.timeout_for(host, attempt));
        let generation = self.take_generation();
        let record = self.records.get_mut(key).expect("present above");
        record.deferred = false;
        record.generation = generation;
        self.timers.push(Timer {
            due,
            key: *key,
            generation,
        });
    }

    /// Removes every outstanding probe, yielding their keys, for a scan that is
    /// stopping early.
    pub fn drain_unresolved(&mut self) -> Vec<K> {
        self.timers.clear();
        let keys: Vec<K> = self.records.keys().copied().collect();
        self.records.clear();
        for host in self.hosts.values_mut() {
            host.outstanding = 0;
        }
        keys
    }

    /// How many probes are outstanding. A scanner reads this to decide whether
    /// to admit another target.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no probe is outstanding. After the last admission, this tells the
    /// loop there is nothing left to wait for.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Marks the attempt of `key` carrying `token` as seen on the wire,
    /// returning whether that was its first sighting. The counterpart of
    /// [`arm`](Self::arm): armed says handed to the OS, witnessed says watched
    /// leaving.
    pub fn witness(&mut self, key: &K, token: &T) -> bool
    where
        T: PartialEq,
    {
        self.records
            .get_mut(key)
            .is_some_and(|record| record.witness(token))
    }

    /// Whether `key` is currently outstanding.
    pub fn contains(&self, key: &K) -> bool {
        self.records.contains_key(key)
    }

    /// Whether `key` is outstanding and, where `token` is given, whether it
    /// names one of that probe's live attempts.
    ///
    /// The non-destructive half of [`resolve`](Self::resolve), for a message that
    /// reports on the host, such as an ICMP host unreachable. It must not retire the
    /// probe, whose port is still undecided, but it must be shown to concern a
    /// probe this scan sent.
    ///
    /// `None` for the token means the quotation was too short to carry one, which
    /// leaves the key as weaker evidence.
    pub fn names_attempt(&self, key: &K, token: Option<&T>) -> bool {
        let Some(record) = self.records.get(key) else {
            return false;
        };
        match token {
            Some(token) => record.attempt_of(token).is_some(),
            None => true,
        }
    }

    /// Whether anything has ever come back from `host`: a SYN+ACK, a reset, an
    /// ICMP error, any reply at all.
    ///
    /// Whether the scan reaches the address at all. Whether its silence is loss is
    /// [`host_is_answering`](Self::host_is_answering)'s question.
    ///
    /// A reply that could not be attributed to an attempt counts, though it gives
    /// no round trip.
    pub fn host_has_answered(&self, host: &IpAddr) -> bool {
        self.hosts.get(host).is_some_and(|state| state.answers > 0)
    }

    /// Whether `host` has answered more than one in
    /// [`ANSWERING_ONE_IN`] of the probes put to it. A pacing controller reads
    /// silence from such a host as loss.
    ///
    /// Stricter than [`host_has_answered`](Self::host_has_answered): a firewall
    /// that lets one port through has answered, but its silence is still the
    /// firewall. Read as loss, a Windows machine with one port open in a thousand
    /// held a scan at its window's floor. A probe answered only on a retry counts
    /// on both sides, a silence and then an answer.
    pub(crate) fn host_is_answering(&self, host: &IpAddr) -> bool {
        self.hosts.get(host).is_some_and(|state| {
            let (answers, silences) = (u64::from(state.answers), u64::from(state.silences));
            answers * u64::from(ANSWERING_ONE_IN) > answers + silences
        })
    }

    /// The smoothed round trip observed for `host`, if it has answered.
    #[cfg(test)]
    pub fn host_rtt(&self, host: &IpAddr) -> Option<Duration> {
        self.hosts.get(host)?.estimator.smoothed
    }

    /// Seeds `host`'s round-trip estimate from a measurement this ledger did not
    /// take.
    ///
    /// A port scan reaches hosts a liveness phase already timed. Starting from
    /// [`initial_rto`](RetryPolicy::initial_rto) instead, probes to a host answering
    /// in five milliseconds wait two hundred before repeating, and every silent
    /// port pays that three times.
    ///
    /// Seeding too low is safe with per-attempt tokens: an early retransmission
    /// does not mislabel the reply to the first attempt, so the round trip is
    /// measured correctly. It costs an extra packet, bounded by
    /// [`min_rto`](RetryPolicy::min_rto).
    ///
    /// Does nothing for a host already measured or seeded. The seed times the
    /// host's probes only until the ledger's first round trip to it, which replaces
    /// it (see [`RttEstimator::seed`]). A seed can carry more than the path: a
    /// neighbour that answered a broadcast ARP request in 98 ms answered SYNs in
    /// 10, and a firewalled host answers a port scan about once, so a smoothed seed
    /// would time all its silent ports at a third of a second. The scan-wide
    /// fallback is seeded and replaced on the same terms.
    pub fn seed_host_rtt(&mut self, host: IpAddr, rtt: Duration) {
        self.hosts.entry(host).or_default().estimator.seed(rtt);
        if self.policy.cross_host_estimate {
            self.global.seed(rtt);
        }
    }

    /// Seeds `host` from `telemetry`, what the phases before this ledger's
    /// scan measured of it, as [`seed_host_rtt`](Self::seed_host_rtt) does, from
    /// the median of the round trips a wait on its path is sized from.
    ///
    /// Where those are only answers to address resolutions, the seed is taken only
    /// if it is shorter than the unmeasured starting timeout: a resolution can show
    /// a neighbour near but not far. Its lateness is the link delivering a
    /// broadcast and the neighbour waking for it (see
    /// [`HostTelemetry::round_trips`]), which later probes do not wait on. A
    /// neighbour that answered ARP in 196 ms answered SYNs in 8; seeded from the
    /// ARP answer, the scan took nearly twice as long as unseeded.
    pub(crate) fn seed_host(&mut self, host: IpAddr, telemetry: &HostTelemetry) {
        let Some(rtt) = telemetry.median_round_trip() else {
            return;
        };
        if telemetry.round_trips_resolve_the_link() {
            let mut resolution = RttEstimator::default();
            resolution.record(rtt);
            if resolution
                .timeout()
                .is_none_or(|timeout| timeout >= self.policy.initial_rto)
            {
                return;
            }
        }
        self.seed_host_rtt(host, rtt);
    }

    /// Accounts for a probe that spent its entire budget in silence.
    fn retire(&mut self, host: IpAddr) {
        let state = self.hosts.entry(host).or_default();
        state.outstanding = state.outstanding.saturating_sub(1);
        if state.answers == 0 {
            state.exhausted_silently = state.exhausted_silently.saturating_add(1);
        }
    }

    /// The timeout for `attempt` against `host`: what has been measured, backed
    /// off for the attempt number, bounded, and spread upward.
    fn timeout_for(&mut self, host: IpAddr, attempt: u8) -> Duration {
        let measured = self
            .hosts
            .get(&host)
            .and_then(|state| state.estimator.timeout())
            .or_else(|| {
                self.policy
                    .cross_host_estimate
                    .then(|| self.global.timeout())
                    .flatten()
            });

        // Held to the floor whichever it came from: a probe repeated sooner
        // than the protocol can reply is a wasted packet. The ceiling is at
        // least the floor, so crossed bounds still describe a real range.
        let ceiling = self.policy.max_rto.max(self.policy.min_rto);
        let base = match measured {
            Some(measured) => measured,
            None => self.policy.initial_rto,
        };
        let base = base.clamp(self.policy.min_rto, ceiling);

        let scaled = scale(base, self.policy.backoff, attempt, ceiling);
        self.jitter.spread(scaled, self.policy.jitter)
    }

    fn take_generation(&mut self) -> u32 {
        self.next_generation = self.next_generation.wrapping_add(1);
        self.next_generation
    }
}

/// `base` multiplied by `backoff` once per attempt beyond the first, and held
/// to `ceiling`.
///
/// Clamped inside the multiplication: an attempt budget can reach 255, and three
/// to the 254th overflows any duration.
fn scale(base: Duration, backoff: f64, attempt: u8, ceiling: Duration) -> Duration {
    if attempt <= 1 || backoff <= 1.0 {
        return base.min(ceiling);
    }
    saturating_mul(base, backoff.powi(i32::from(attempt - 1))).min(ceiling)
}

/// `duration` scaled by `factor`, saturating at [`Duration::MAX`] where
/// [`Duration::mul_f64`] would panic.
///
/// A caller can make any schedule factor as large as they like (a backoff raised
/// to the attempt number, a [`TimeoutScale`](crate::config::TimeoutScale)). A
/// factor that is NaN or not above zero gives zero.
pub(crate) fn saturating_mul(duration: Duration, factor: f64) -> Duration {
    let seconds = duration.as_secs_f64() * factor;
    Duration::try_from_secs_f64(seconds).unwrap_or(if seconds > 0.0 {
        Duration::MAX
    } else {
        Duration::ZERO
    })
}

/// The jitter source: SplitMix64, inlined for a fixed, documented output sequence,
/// so a seeded ledger schedules identically across releases.
struct Jitter(u64);

impl Jitter {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform draw from `[0, 1)`, over the 53 bits an `f64` holds exactly.
    fn next_unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// `base` scaled by a factor drawn uniformly from `[1, 1 + spread]`.
    ///
    /// Never below `base`; see [`RetryPolicy::jitter`].
    fn spread(&mut self, base: Duration, spread: f64) -> Duration {
        if spread <= 0.0 {
            return base;
        }
        let spread = spread.min(1.0);
        let factor = 1.0 + self.next_unit() * spread;
        saturating_mul(base, factor)
    }
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
    use crate::config::TimeoutScale;
    use std::net::Ipv4Addr;
    use std::num::NonZeroU8;

    const HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));
    const OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 201));

    /// Three attempts, no jitter and no backoff, so tests can assert on exact
    /// instants.
    fn policy() -> RetryPolicy {
        RetryPolicy::new(
            3,
            Duration::from_millis(100),
            Duration::from_millis(10),
            Duration::from_secs(2),
            1.0,
            0.0,
            None,
        )
    }

    /// Arms one probe under `policy` and runs it to the end of its schedule,
    /// sending every retry. Returns how many attempts it was given.
    fn schedule_to_the_end(policy: RetryPolicy) -> u8 {
        let _ = (
            policy.worst_case_probe_lifetime(),
            policy.longest_probe_lifetime(),
        );
        let mut ledger = ledger(policy);
        ledger.arm(HOST, (HOST, 80), 0, (), Instant::now());
        while let Some(now) = ledger.next_due() {
            for event in due_at(&mut ledger, now) {
                match event {
                    Due::Retry { key, attempt } => {
                        ledger.rearm(HOST, key, u32::from(attempt), now);
                    }
                    Due::Exhausted { attempts, .. } => return attempts,
                }
            }
        }
        0
    }

    /// Every attempt budget the configuration accepts schedules to its end.
    ///
    /// A budget of 255 raises a backoff of three to the 254th, which no duration
    /// holds. Unclamped, it panicked for any budget from 43 at a port scan's
    /// backoff and from 68 at a sweep's.
    #[test]
    fn every_attempt_budget_a_caller_can_ask_for_schedules_without_panicking() {
        for backoff in [2.0, 3.0] {
            let policy = RetryPolicy {
                backoff,
                ..policy()
            }
            .configured(RetryConfig {
                max_attempts: std::num::NonZeroU8::new(u8::MAX),
                ..RetryConfig::default()
            });
            assert_eq!(schedule_to_the_end(policy), u8::MAX, "backoff {backoff}");
        }
    }

    /// The largest timeout scale the configuration accepts schedules too, without
    /// panicking.
    #[test]
    fn the_largest_timeout_scale_schedules_without_panicking() {
        let policy = policy().configured(RetryConfig {
            timeout_scale: TimeoutScale::new(f64::MAX),
            ..RetryConfig::default()
        });
        assert!(policy.max_rto >= Duration::from_secs(u64::from(u32::MAX)));

        let now = Instant::now();
        let mut ledger = ledger(policy);
        ledger.arm(HOST, (HOST, 80), 0, (), now);
        assert!(
            due_at(&mut ledger, now + Duration::from_secs(3600)).is_empty(),
            "a timeout that long is not due within the hour"
        );
    }

    fn ledger(policy: RetryPolicy) -> ProbeLedger<(IpAddr, u16), u32> {
        ProbeLedger::seeded(policy, 8, 0x5EED)
    }

    /// A seeded host is timed from the seed. Unseeded, every silent port waits
    /// out the unmeasured guess three times.
    #[test]
    fn a_seeded_host_is_timed_from_the_measurement_rather_than_the_guess() {
        let mut ledger = ledger(policy());

        let unseeded = ledger.timeout_for(OTHER, 1);
        assert_eq!(
            unseeded,
            Duration::from_millis(100),
            "with nothing measured, the policy's starting timeout stands"
        );

        ledger.seed_host_rtt(HOST, Duration::from_millis(5));

        assert!(
            ledger.timeout_for(HOST, 1) < unseeded,
            "a host already known to answer in five milliseconds is not worth \
             a hundred of patience"
        );
    }

    /// A conversation with a service on a measured path allows the path what a
    /// probe is given after the same round trips, one or many, steady or
    /// wandering, so service passes wait on a slow path as the port scans did.
    ///
    /// The exception is a lone round trip past a second, which a conversation holds
    /// to the path-finding wait: it waits on the path several times in a row, so a
    /// first sample that carried more than the path costs it each time. See
    /// [`PathAllowance::of_round_trips`](crate::transport::dial::PathAllowance::of_round_trips).
    #[test]
    fn a_conversation_allows_for_a_path_what_a_probe_after_the_same_replies_is_given() {
        use crate::transport::dial::PathAllowance;

        let steady = [1_900; 10];
        let wandering = [900, 2_900, 1_000, 2_800, 1_100, 2_700];
        let slowing = [5, 7, 40, 140, 600, 1_900];
        let mut runs: Vec<Vec<u64>> = [1, 5, 140, 1_000].map(|millis| vec![millis]).into();
        runs.extend([steady.to_vec(), wandering.to_vec(), slowing.to_vec()]);
        for run in runs {
            let round_trips: Vec<Duration> =
                run.iter().copied().map(Duration::from_millis).collect();
            let mut estimate = RttEstimator::default();
            for round_trip in &round_trips {
                estimate.record(*round_trip);
            }
            assert_eq!(
                PathAllowance::of_round_trips(round_trips).over(Duration::ZERO),
                estimate.timeout().expect("a sample"),
                "after {run:?} ms"
            );
        }
    }

    /// A sample this ledger took itself beats a seed.
    #[test]
    fn seeding_does_not_overwrite_what_the_scan_has_measured() {
        let mut ledger = ledger(policy());
        let start = Instant::now();

        ledger.arm(HOST, (HOST, 80), 1, (), start);
        ledger.resolve(&(HOST, 80), Some(1), start + Duration::from_millis(40));
        let measured = ledger.host_rtt(&HOST);

        ledger.seed_host_rtt(HOST, Duration::from_millis(1));

        assert_eq!(ledger.host_rtt(&HOST), measured);
    }

    /// **A seed times a host only until the host answers the scan itself.**
    ///
    /// Measured case: a neighbour answered a sweep's ARP request in 98 ms and SYNs
    /// in 10. Smoothed as a first sample, the seed would time the next probe at
    /// 322 ms, and a firewalled host answers a port scan about once. Replaced, the
    /// host and the scan-wide estimate are timed from the 10 ms measured.
    #[test]
    fn a_seed_gives_way_to_the_first_round_trip_the_scan_measures() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());
        ledger.seed_host_rtt(HOST, Duration::from_millis(98));

        ledger.arm(HOST, (HOST, 80), 1, (), t0);
        ledger.resolve(&(HOST, 80), Some(1), t0 + Duration::from_millis(10));

        // 10 ms smoothed, 5 ms variation: 10 + 4 * 5.
        let own = Duration::from_millis(30);
        assert_eq!(ledger.timeout_for(HOST, 1), own, "the host's own reply");
        assert_eq!(
            ledger.timeout_for(OTHER, 1),
            own,
            "and the scan's reply times a host with none of its own"
        );
    }

    /// **An address resolution's answer seeds a host only sooner than the
    /// unmeasured guess, and an answer across its IP stack seeds it either
    /// way.**
    ///
    /// A neighbour that answered ARP in 196 ms answered SYNs in 8; seeded from the
    /// ARP answer, the scan took nearly twice as long as unseeded. A fast
    /// resolution is still worth taking over the unmeasured guess.
    #[test]
    fn a_resolution_seeds_a_host_only_sooner_than_the_unmeasured_guess() {
        use crate::model::host::StatusProtocol;
        use crate::model::host::telemetry::HostTelemetry;

        let answered = |samples: &[(u64, StatusProtocol)]| {
            let mut telemetry = HostTelemetry::default();
            for (millis, protocol) in samples {
                telemetry.add_rtt_from(Duration::from_millis(*millis), protocol.clone());
            }
            telemetry
        };
        let seeded = |telemetry: HostTelemetry| {
            let mut ledger = ledger(policy());
            ledger.seed_host(HOST, &telemetry);
            ledger.timeout_for(HOST, 1)
        };
        let guess = policy().initial_rto;

        assert_eq!(
            seeded(answered(&[(196, StatusProtocol::Arp)])),
            guess,
            "a slow resolution leaves the guess standing"
        );
        assert_eq!(
            seeded(answered(&[(5, StatusProtocol::Arp)])),
            Duration::from_millis(15),
            "a fast one times the host from it"
        );
        assert_eq!(
            seeded(answered(&[
                (196, StatusProtocol::Arp),
                (8, StatusProtocol::TcpSyn)
            ])),
            Duration::from_millis(24),
            "a SYN's round trip outranks the resolution's"
        );
        assert_eq!(
            seeded(answered(&[(196, StatusProtocol::TcpSyn)])),
            Duration::from_millis(588),
            "and a slow path measured across the IP stack is waited on for"
        );
    }

    /// **A host answering one probe in ten or fewer is not answering what it
    /// is asked**, and its silence is not read as dropped probes.
    ///
    /// First timeouts are counted once per probe, so a retry's does not count
    /// twice.
    #[test]
    fn a_host_answering_one_probe_in_ten_or_fewer_is_not_answering() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());
        let mut due = Vec::new();

        ledger.arm(HOST, (HOST, 1), 1, (), t0);
        ledger.resolve(&(HOST, 1), Some(1), t0);
        assert!(
            ledger.host_is_answering(&HOST),
            "one answer and nothing else"
        );

        for port in 2..=10 {
            ledger.arm(HOST, (HOST, port), 1, (), t0);
        }
        // Past every probe's first timeout, then its second, which is not
        // another silence.
        ledger.drain_due(t0 + Duration::from_secs(1), &mut due);
        ledger.drain_due(t0 + Duration::from_secs(2), &mut due);
        assert!(
            !ledger.host_is_answering(&HOST),
            "one answer to ten probes is a firewall letting a port through"
        );

        ledger.arm(HOST, (HOST, 11), 1, (), t0);
        ledger.resolve(&(HOST, 11), Some(1), t0);
        assert!(
            ledger.host_is_answering(&HOST),
            "two in eleven is answering"
        );
        assert!(
            !ledger.host_is_answering(&OTHER),
            "and a host never asked is not"
        );
    }

    /// A fast answer from one host must not shorten an unmeasured host's first
    /// timeout when the policy says the two are unrelated.
    ///
    /// Otherwise one fast neighbour seeds the scan-wide estimate, which is clamped
    /// up to [`min_rto`](RetryPolicy::min_rto), and the scan runs on the floor
    /// instead of the declared timeout. On a segment with both mains-powered and
    /// sleeping devices, that retransmits to the slow ones before they can reply.
    #[test]
    fn one_hosts_round_trip_does_not_time_another_when_the_policy_forbids_it() {
        let policy = RetryPolicy::new(
            2,
            Duration::from_millis(800),
            Duration::from_millis(50),
            Duration::from_secs(3),
            1.5,
            0.0,
            None,
        )
        .without_cross_host_estimate();

        let fast: IpAddr = "192.0.2.1".parse().unwrap();
        let unmeasured: IpAddr = "192.0.2.2".parse().unwrap();
        let start = Instant::now();

        let mut ledger = ledger(policy);
        ledger.arm(fast, (fast, 0), 1, (), start);
        // The fast neighbour answers in six milliseconds.
        let resolved = ledger
            .resolve(&(fast, 0), Some(1), start + Duration::from_millis(6))
            .expect("the fast host resolves");
        assert_eq!(resolved.rtt, Some(Duration::from_millis(6)));

        ledger.arm(unmeasured, (unmeasured, 0), 1, (), start);
        let due = ledger.next_due().expect("a timer for the unmeasured host");

        assert_eq!(
            due.saturating_duration_since(start),
            Duration::from_millis(800),
            "the unmeasured host must be timed by the policy's own initial              timeout, not by what a different host happened to answer in"
        );
    }

    /// By default an unmeasured host inherits the scan-wide estimate.
    #[test]
    fn one_hosts_round_trip_times_another_by_default() {
        let policy = RetryPolicy::new(
            2,
            Duration::from_millis(800),
            Duration::from_millis(50),
            Duration::from_secs(3),
            1.5,
            0.0,
            None,
        );

        let fast: IpAddr = "192.0.2.1".parse().unwrap();
        let unmeasured: IpAddr = "192.0.2.2".parse().unwrap();
        let start = Instant::now();

        let mut ledger = ledger(policy);
        ledger.arm(fast, (fast, 0), 1, (), start);
        ledger.resolve(&(fast, 0), Some(1), start + Duration::from_millis(6));

        ledger.arm(unmeasured, (unmeasured, 0), 1, (), start);
        let due = ledger.next_due().expect("a timer for the unmeasured host");

        assert!(
            due.saturating_duration_since(start) < Duration::from_millis(800),
            "a measured path should shorten the wait for a target that has not              answered yet"
        );
    }

    /// The keys due at `now`.
    fn due_at(
        ledger: &mut ProbeLedger<(IpAddr, u16), u32>,
        now: Instant,
    ) -> Vec<Due<(IpAddr, u16)>> {
        let mut out = Vec::new();
        ledger.drain_due(now, &mut out);
        out
    }

    // ── Attributing a reply to an attempt ──────────────────────────────────

    /// A host found after three sends may have answered the third, or the first
    /// over a path slow enough that two more went out meanwhile. Only the token
    /// tells them apart.
    #[test]
    fn a_reply_names_the_attempt_it_answers_not_the_number_sent() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());

        ledger.arm(HOST, (HOST, 80), 1, (), t0);
        let t1 = t0 + Duration::from_millis(100);
        due_at(&mut ledger, t1);
        ledger.arm(HOST, (HOST, 80), 2, (), t1);
        let t2 = t1 + Duration::from_millis(100);
        due_at(&mut ledger, t2);
        ledger.arm(HOST, (HOST, 80), 3, (), t2);

        // The first attempt's token, answered long after two more went out.
        let resolution = ledger
            .resolve(&(HOST, 80), Some(1), t2 + Duration::from_millis(50))
            .expect("a live token resolves");

        assert_eq!(resolution.answered_attempt, Some(1));
        assert_eq!(resolution.attempts, 3, "three sends had been charged");
        assert_eq!(resolution.rtt, Some(Duration::from_millis(250)));
    }

    /// A round trip is measured from the attempt that was answered, never from
    /// when the probe was first armed and never from when the scan began.
    ///
    /// The three coincide only for a probe sent once. Otherwise a fast host
    /// recovered by a late retry would read as slow to the adaptive deadline and
    /// the retry schedule.
    #[test]
    fn a_reply_to_the_latest_attempt_is_numbered_and_measured_by_it() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());

        ledger.arm(HOST, (HOST, 80), 1, (), t0);
        let t1 = t0 + Duration::from_millis(100);
        due_at(&mut ledger, t1);
        ledger.arm(HOST, (HOST, 80), 2, (), t1);

        let resolution = ledger
            .resolve(&(HOST, 80), Some(2), t1 + Duration::from_millis(5))
            .expect("a live token resolves");

        assert_eq!(resolution.answered_attempt, Some(2));
        assert_eq!(
            resolution.rtt,
            Some(Duration::from_millis(5)),
            "measured from the second attempt, not the 105ms since the first"
        );
    }

    /// An untokened reply to a probe sent once answers the first attempt. With
    /// several outstanding, Karn's rule applies and nothing is claimed.
    #[test]
    fn an_untokened_reply_is_attributed_only_when_one_send_has_happened() {
        let t0 = Instant::now();
        let mut once = ledger(policy());
        once.arm(HOST, (HOST, 80), 1, (), t0);

        let single = once
            .resolve(&(HOST, 80), None, t0 + Duration::from_millis(10))
            .expect("resolves");
        assert_eq!(single.answered_attempt, Some(1));

        let mut twice = ledger(policy());
        twice.arm(OTHER, (OTHER, 80), 1, (), t0);
        let t1 = t0 + Duration::from_millis(100);
        due_at(&mut twice, t1);
        twice.arm(OTHER, (OTHER, 80), 2, (), t1);

        let retried = twice
            .resolve(&(OTHER, 80), None, t1 + Duration::from_millis(10))
            .expect("resolves");
        assert_eq!(retried.answered_attempt, None);
        assert_eq!(retried.rtt, None);
    }

    /// A probe that has outlived its earliest tokens still numbers the surviving
    /// ones correctly.
    #[test]
    fn attempts_stay_correctly_numbered_after_the_oldest_tokens_are_evicted() {
        // Six sends against four retained tokens, so attempts 1 and 2 have been
        // forgotten and 3 through 6 survive.
        let sends = 6;
        let t0 = Instant::now();
        let generous = RetryPolicy::new(
            8,
            Duration::from_millis(100),
            Duration::from_millis(10),
            Duration::from_secs(2),
            1.0,
            0.0,
            None,
        );

        let sent_six = |t0: Instant| {
            let mut ledger = ledger(generous);
            ledger.arm(HOST, (HOST, 80), 1, (), t0);
            let mut now = t0;
            for token in 2..=sends {
                now += Duration::from_millis(100);
                due_at(&mut ledger, now);
                ledger.arm(HOST, (HOST, 80), token, (), now);
            }
            (ledger, now)
        };

        let (mut ledger, now) = sent_six(t0);
        let newest = ledger
            .resolve(&(HOST, 80), Some(sends), now + Duration::from_millis(5))
            .expect("resolves");
        assert_eq!(newest.answered_attempt, Some(6));

        let (mut ledger, now) = sent_six(t0);
        let oldest_retained = ledger
            .resolve(&(HOST, 80), Some(3), now + Duration::from_millis(5))
            .expect("resolves");
        assert_eq!(
            oldest_retained.answered_attempt,
            Some(3),
            "numbering counts back from the newest, not from the first slot"
        );

        // An evicted token names no attempt, so the probe stays outstanding.
        let (mut ledger, now) = sent_six(t0);
        assert!(
            ledger
                .resolve(&(HOST, 80), Some(1), now + Duration::from_millis(5))
                .is_none()
        );
    }

    // ── The schedule ───────────────────────────────────────────────────────

    #[test]
    fn an_armed_probe_is_not_due_before_its_timeout() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());
        ledger.arm(HOST, (HOST, 80), 1, (), t0);

        assert!(due_at(&mut ledger, t0 + Duration::from_millis(99)).is_empty());
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn a_probe_is_retried_when_its_timeout_passes() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());
        ledger.arm(HOST, (HOST, 80), 1, (), t0);

        let due = due_at(&mut ledger, t0 + Duration::from_millis(100));
        assert_eq!(
            due,
            vec![Due::Retry {
                key: (HOST, 80),
                attempt: 2
            }]
        );
        assert_eq!(ledger.len(), 1, "a retried probe is still outstanding");
    }

    /// A retry waiting to be sent holds its probe's clock, so the probe is neither
    /// retried again nor retired until it leaves, and its next attempt is timed
    /// from then.
    #[test]
    fn a_deferred_retry_stops_its_probes_clock_until_it_is_sent() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());
        ledger.arm(HOST, (HOST, 80), 1, (), t0);
        assert_eq!(
            due_at(&mut ledger, t0 + Duration::from_millis(100)).len(),
            1
        );
        ledger.defer(&(HOST, 80));

        assert!(
            due_at(&mut ledger, t0 + Duration::from_secs(3600)).is_empty(),
            "nothing comes due while the retry waits"
        );
        assert!(ledger.contains(&(HOST, 80)));

        let sent = t0 + Duration::from_secs(3600);
        ledger.rearm(HOST, (HOST, 80), 2, sent);
        ledger.resume(&(HOST, 80), sent);
        assert_eq!(
            due_at(&mut ledger, sent + Duration::from_secs(10)),
            vec![Due::Retry {
                key: (HOST, 80),
                attempt: 3
            }],
            "the next attempt is timed from the send, and only once"
        );
    }

    /// A deferred retry that never leaves restarts its probe's clock at
    /// `resume`, so the charged attempt still counts and the probe runs out on
    /// schedule.
    #[test]
    fn a_deferred_retry_that_is_not_sent_still_runs_its_probe_out() {
        let t0 = Instant::now();
        let mut ledger = ledger(RetryPolicy {
            max_attempts: 2,
            ..policy()
        });
        ledger.arm(HOST, (HOST, 80), 1, (), t0);
        assert_eq!(
            due_at(&mut ledger, t0 + Duration::from_millis(100)).len(),
            1
        );
        ledger.defer(&(HOST, 80));

        let refused = t0 + Duration::from_secs(1);
        ledger.resume(&(HOST, 80), refused);

        assert!(matches!(
            due_at(&mut ledger, refused + Duration::from_secs(10))[..],
            [Due::Exhausted { attempts: 2, .. }]
        ));
    }

    /// The budget is a total: three attempts means two resends and then a verdict.
    #[test]
    fn a_probe_exhausts_after_exactly_its_budget() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());
        ledger.arm(HOST, (HOST, 80), 1, (), t0);

        let mut sends = 1;
        let mut exhausted = None;
        for step in 1..10 {
            let now = t0 + Duration::from_millis(100 * step);
            for event in due_at(&mut ledger, now) {
                match event {
                    Due::Retry { key, attempt } => {
                        sends += 1;
                        assert_eq!(attempt, sends);
                        ledger.rearm(HOST, key, attempt.into(), now);
                    }
                    Due::Exhausted { key, .. } => exhausted = Some(key),
                }
            }
        }

        assert_eq!(sends, 3, "one initial attempt plus two retries");
        assert_eq!(exhausted, Some((HOST, 80)));
        assert!(ledger.is_empty());
    }

    /// With no retries configured, the first timeout is the verdict.
    #[test]
    fn a_single_attempt_policy_exhausts_without_ever_retrying() {
        let t0 = Instant::now();
        let mut ledger = ledger(RetryPolicy::none());
        ledger.arm(HOST, (HOST, 80), 1, (), t0);

        let due = due_at(&mut ledger, t0 + Duration::from_secs(5));
        assert_eq!(
            due,
            vec![Due::Exhausted {
                key: (HOST, 80),
                payload: (),
                // With no retry, this event is the probe's first timeout.
                attempts: 1,
                // This test witnesses nothing.
                witnessed: 0,
            }]
        );
    }

    #[test]
    fn backoff_lengthens_each_successive_timeout() {
        let t0 = Instant::now();
        let policy = RetryPolicy::new(
            4,
            Duration::from_millis(100),
            Duration::from_millis(10),
            Duration::from_secs(10),
            2.0,
            0.0,
            None,
        );
        let mut ledger = ledger(policy);

        ledger.arm(HOST, (HOST, 80), 1, (), t0);
        let first = ledger.next_due().unwrap();

        // The retry must wait twice as long as the attempt before it.
        let due = due_at(&mut ledger, first);
        assert!(matches!(due.as_slice(), [Due::Retry { .. }]));
        let second = ledger.next_due().unwrap();

        assert_eq!(
            first.saturating_duration_since(t0),
            Duration::from_millis(100)
        );
        assert_eq!(
            second.saturating_duration_since(first),
            Duration::from_millis(200)
        );
    }

    #[test]
    fn nothing_is_due_and_no_deadline_exists_on_an_empty_ledger() {
        let mut ledger = ledger(policy());
        assert!(ledger.next_due().is_none());
        assert!(due_at(&mut ledger, Instant::now()).is_empty());
        assert!(ledger.is_empty());
    }

    // ── Resolution ─────────────────────────────────────────────────────────

    #[test]
    fn a_matching_token_resolves_the_probe_and_measures_it() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());
        ledger.arm(HOST, (HOST, 80), 7, (), t0);

        let resolved = ledger
            .resolve(&(HOST, 80), Some(7), t0 + Duration::from_millis(12))
            .expect("outstanding probe resolves");

        assert_eq!(resolved.rtt, Some(Duration::from_millis(12)));
        assert_eq!(resolved.attempts, 1);
        assert!(ledger.is_empty());
    }

    /// A probe resolves once, however many answers arrive.
    #[test]
    fn a_second_reply_resolves_nothing() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());
        ledger.arm(HOST, (HOST, 80), 7, (), t0);

        assert!(ledger.resolve(&(HOST, 80), Some(7), t0).is_some());
        assert!(ledger.resolve(&(HOST, 80), Some(7), t0).is_none());
    }

    #[test]
    fn a_token_matching_no_attempt_leaves_the_probe_outstanding() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());
        ledger.arm(HOST, (HOST, 80), 7, (), t0);

        assert!(ledger.resolve(&(HOST, 80), Some(999), t0).is_none());
        assert_eq!(ledger.len(), 1, "someone else's packet resolves nothing");
    }

    /// Attempt one carries token 7, attempt two carries 8, and the answer to the
    /// first arrives afterwards. A ledger holding only the newest token would
    /// report the target silent.
    #[test]
    fn a_late_reply_to_an_earlier_attempt_still_resolves_the_probe() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());

        ledger.arm(HOST, (HOST, 80), 7, (), t0);
        let retry = t0 + Duration::from_millis(100);
        assert!(!due_at(&mut ledger, retry).is_empty());
        ledger.arm(HOST, (HOST, 80), 8, (), retry);

        let resolved = ledger
            .resolve(&(HOST, 80), Some(7), t0 + Duration::from_millis(140))
            .expect("the first attempt's answer is still an answer");

        assert_eq!(
            resolved.rtt,
            Some(Duration::from_millis(140)),
            "measured against the attempt that was actually answered"
        );
        assert_eq!(resolved.attempts, 2);
    }

    /// Karn's rule: with no token and more than one attempt in flight, no sample
    /// is taken, but the probe still resolves.
    #[test]
    fn an_unattributable_reply_resolves_without_measuring() {
        let t0 = Instant::now();
        let mut ledger: ProbeLedger<(IpAddr, u16), ()> = ProbeLedger::seeded(policy(), 8, 1);

        ledger.arm(HOST, (HOST, 53), (), (), t0);
        let retry = t0 + Duration::from_millis(100);
        let mut out = Vec::new();
        ledger.drain_due(retry, &mut out);
        ledger.arm(HOST, (HOST, 53), (), (), retry);

        let resolved = ledger
            .resolve(&(HOST, 53), None, retry + Duration::from_millis(5))
            .expect("resolves");

        assert_eq!(resolved.rtt, None, "which attempt did it answer?");
        assert_eq!(resolved.attempts, 2);
    }

    /// The same reply on a probe sent only once is unambiguous, so it counts.
    #[test]
    fn an_unattributable_reply_to_a_single_attempt_is_still_measured() {
        let t0 = Instant::now();
        let mut ledger: ProbeLedger<(IpAddr, u16), ()> = ProbeLedger::seeded(policy(), 8, 1);
        ledger.arm(HOST, (HOST, 53), (), (), t0);

        let resolved = ledger
            .resolve(&(HOST, 53), None, t0 + Duration::from_millis(9))
            .expect("resolves");

        assert_eq!(resolved.rtt, Some(Duration::from_millis(9)));
    }

    /// An answered probe is not resent: its timer is still queued, and generation
    /// matching keeps it from firing.
    #[test]
    fn a_resolved_probe_is_never_due_again() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());
        ledger.arm(HOST, (HOST, 80), 7, (), t0);
        ledger.resolve(&(HOST, 80), Some(7), t0 + Duration::from_millis(5));

        assert!(due_at(&mut ledger, t0 + Duration::from_secs(10)).is_empty());
    }

    /// Re-arming supersedes the previous timer, so a probe cannot be retried twice
    /// for one attempt.
    #[test]
    fn re_arming_supersedes_the_previous_timer() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());

        ledger.arm(HOST, (HOST, 80), 1, (), t0);
        let retry = t0 + Duration::from_millis(100);
        assert_eq!(due_at(&mut ledger, retry).len(), 1);
        ledger.arm(HOST, (HOST, 80), 2, (), retry);

        // The superseded entry's deadline has passed; it produces nothing.
        let due = due_at(&mut ledger, retry + Duration::from_millis(1));
        assert!(due.is_empty(), "stale timer fired: {due:?}");
    }

    // ── Timing ─────────────────────────────────────────────────────────────

    #[test]
    fn the_first_timeout_uses_the_initial_value_not_the_floor() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());
        ledger.arm(HOST, (HOST, 80), 1, (), t0);

        assert_eq!(
            ledger.next_due().unwrap().saturating_duration_since(t0),
            Duration::from_millis(100),
            "an unmeasured path is unknown, not known to be fast"
        );
    }

    /// Once a host has answered, its own round trip drives the timeout.
    #[test]
    fn a_measured_host_gets_a_timeout_derived_from_its_own_round_trip() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());

        ledger.arm(HOST, (HOST, 80), 1, (), t0);
        ledger.resolve(&(HOST, 80), Some(1), t0 + Duration::from_millis(4));

        ledger.arm(HOST, (HOST, 81), 2, (), t0);
        let measured = ledger.next_due().unwrap().saturating_duration_since(t0);

        // 4 ms smoothed, 2 ms variation: 4 + 4 * 2 = 12 ms, under the initial 100 ms.
        assert_eq!(measured, Duration::from_millis(12));
        assert_eq!(ledger.host_rtt(&HOST), Some(Duration::from_millis(4)));
    }

    /// On a steady path the timeout keeps headroom over the round trip for
    /// the reply that comes back a little slower than the rest.
    ///
    /// On such a path the variation decays towards nothing, and with one attempt
    /// every straggler would be an open port read silent. Here one reply in twenty
    /// is ten percent slow.
    #[test]
    fn a_steady_path_keeps_headroom_for_a_reply_a_little_slower_than_most() {
        let usual = Duration::from_millis(100);
        let slow = Duration::from_millis(110);
        let mut estimator = RttEstimator::default();
        for n in 0..400 {
            let sample = if n % 20 == 19 { slow } else { usual };
            if n >= 40 {
                let timeout = estimator.timeout().expect("measured");
                assert!(
                    sample < timeout,
                    "sample {n}: a {sample:?} reply against a {timeout:?} timeout"
                );
            }
            estimator.record(sample);
        }
    }

    /// One host's measurements do not decide another's timeout.
    #[test]
    fn a_fast_host_does_not_shorten_a_different_hosts_timeout() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());

        ledger.arm(HOST, (HOST, 80), 1, (), t0);
        ledger.resolve(&(HOST, 80), Some(1), t0 + Duration::from_millis(1));

        ledger.arm(OTHER, (OTHER, 80), 2, (), t0);
        let other = ledger.next_due().unwrap().saturating_duration_since(t0);

        assert!(
            other >= Duration::from_millis(3),
            "an unmeasured host inherited a fast host's timing: {other:?}"
        );
        assert!(ledger.host_rtt(&OTHER).is_none());
    }

    #[test]
    fn a_measured_timeout_is_held_above_the_floor() {
        let t0 = Instant::now();
        let mut policy = policy();
        policy.min_rto = Duration::from_millis(50);
        let mut ledger = ledger(policy);

        ledger.arm(HOST, (HOST, 80), 1, (), t0);
        ledger.resolve(&(HOST, 80), Some(1), t0 + Duration::from_micros(100));

        ledger.arm(HOST, (HOST, 81), 2, (), t0);
        assert_eq!(
            ledger.next_due().unwrap().saturating_duration_since(t0),
            Duration::from_millis(50)
        );
    }

    #[test]
    fn backed_off_timeouts_are_capped() {
        let t0 = Instant::now();
        let policy = RetryPolicy::new(
            5,
            Duration::from_millis(100),
            Duration::from_millis(10),
            Duration::from_millis(150),
            10.0,
            0.0,
            None,
        );
        let mut ledger = ledger(policy);
        ledger.arm(HOST, (HOST, 80), 1, (), t0);

        let first = ledger.next_due().unwrap();
        due_at(&mut ledger, first);
        let second = ledger.next_due().unwrap();

        assert_eq!(
            second.saturating_duration_since(first),
            Duration::from_millis(150),
            "backoff must not escape the ceiling"
        );
    }

    #[test]
    fn jitter_stays_within_its_stated_fraction() {
        let policy = RetryPolicy::new(
            2,
            Duration::from_millis(100),
            Duration::from_millis(10),
            Duration::from_secs(2),
            1.0,
            0.25,
            None,
        );

        for seed in 0..64u64 {
            let t0 = Instant::now();
            let mut ledger: ProbeLedger<(IpAddr, u16), u32> = ProbeLedger::seeded(policy, 4, seed);
            ledger.arm(HOST, (HOST, 80), 1, (), t0);

            let due = ledger.next_due().unwrap().saturating_duration_since(t0);
            assert!(
                due >= Duration::from_millis(100) && due <= Duration::from_millis(125),
                "seed {seed} produced {due:?}"
            );
        }
    }

    /// A ledger whose `HOST` has answered forty probes, each in exactly `rtt`,
    /// seeded with `seed`, and the instant it was left at with nothing
    /// outstanding and no stale timer queued.
    ///
    /// Forty identical samples leave the variation at nothing: the tightest
    /// schedule measurement can produce.
    fn measured_at(
        policy: RetryPolicy,
        seed: u64,
        rtt: Duration,
    ) -> (ProbeLedger<(IpAddr, u16), u32>, Instant) {
        let mut ledger: ProbeLedger<(IpAddr, u16), u32> = ProbeLedger::seeded(policy, 64, seed);
        let mut now = Instant::now();
        for port in 0..40u16 {
            ledger.arm(HOST, (HOST, port), u32::from(port), (), now);
            ledger
                .resolve(&(HOST, port), Some(u32::from(port)), now + rtt)
                .expect("the answer names the attempt");
            now += Duration::from_secs(10);
        }
        due_at(&mut ledger, now);
        (ledger, now)
    }

    /// Jitter only lengthens a timeout: no probe is timed below the floor, or
    /// below its host's measured round trip. Behind a 20 ms path with one attempt,
    /// a spread both ways from the 25 ms floor read 56 of 300 open ports silent.
    #[test]
    fn jitter_never_times_a_probe_below_the_floor_or_what_was_measured() {
        // The port scan's own numbers: a 25 ms floor and a 30% spread.
        let policy = RetryPolicy::new(
            1,
            Duration::from_millis(200),
            Duration::from_millis(25),
            Duration::from_secs(2),
            3.0,
            0.3,
            None,
        );

        for (rtt, least) in [
            // Measured below the floor: the floor holds.
            (Duration::from_millis(20), Duration::from_millis(25)),
            // Measured above it: the measurement holds.
            (Duration::from_millis(100), Duration::from_millis(100)),
        ] {
            for seed in 0..64u64 {
                let (mut ledger, now) = measured_at(policy, seed, rtt);
                let needed = ledger.hosts[&HOST].estimator.timeout().expect("measured");
                assert!(needed >= rtt, "test premise: {needed:?} for {rtt:?}");

                ledger.arm(HOST, (HOST, 1_000), 1_000, (), now);
                let timeout = ledger
                    .next_due()
                    .expect("one probe outstanding")
                    .saturating_duration_since(now);
                assert!(
                    timeout >= least && timeout >= needed,
                    "seed {seed}: timed at {timeout:?} against a {rtt:?} path \
                     that needs {needed:?}, floor 25ms"
                );
            }
        }
    }

    /// Probes armed together do not all come due at the same instant.
    #[test]
    fn jitter_decorrelates_probes_armed_together() {
        let t0 = Instant::now();
        let policy = RetryPolicy::new(
            2,
            Duration::from_millis(100),
            Duration::from_millis(10),
            Duration::from_secs(2),
            1.0,
            0.25,
            None,
        );
        let mut ledger = ledger(policy);

        for port in 0..64u16 {
            ledger.arm(HOST, (HOST, port), u32::from(port), (), t0);
        }

        // Far fewer than all 64 should be due halfway through the spread.
        let due = due_at(&mut ledger, t0 + Duration::from_millis(112));
        assert!(
            due.len() < 64,
            "every probe came due at once despite jitter"
        );
        assert!(
            !due.is_empty(),
            "jitter delayed everything past its own bound"
        );
    }

    // ── The silent-host rule ───────────────────────────────────────────────

    fn silent_policy() -> RetryPolicy {
        RetryPolicy::new(
            3,
            Duration::from_millis(100),
            Duration::from_millis(10),
            Duration::from_secs(2),
            1.0,
            0.0,
            Some(SilentHostPolicy::new(2, 1)),
        )
    }

    /// Drives one probe to exhaustion and reports how many times it was sent.
    fn spend(ledger: &mut ProbeLedger<(IpAddr, u16), u32>, host: IpAddr, port: u16) -> u8 {
        let mut now = Instant::now();
        ledger.arm(host, (host, port), 1, (), now);

        let mut sends = 1;
        for _ in 0..10 {
            now += Duration::from_secs(1);
            for event in due_at(ledger, now) {
                match event {
                    Due::Retry { key, .. } => {
                        sends += 1;
                        ledger.arm(host, key, u32::from(sends), (), now);
                    }
                    Due::Exhausted { .. } => return sends,
                }
            }
        }
        panic!("probe never exhausted");
    }

    #[test]
    fn a_host_that_never_answers_has_its_budget_cut_after_the_threshold() {
        let mut ledger = ledger(silent_policy());

        assert_eq!(spend(&mut ledger, HOST, 80), 3);
        assert_eq!(spend(&mut ledger, HOST, 81), 3);
        assert_eq!(
            spend(&mut ledger, HOST, 82),
            1,
            "two probes spent in silence is the declared threshold"
        );
    }

    /// Any reply is evidence of life, including a closed port, so a firewalled
    /// host keeps its full budget.
    #[test]
    fn one_answer_of_any_kind_preserves_the_full_budget() {
        let t0 = Instant::now();
        let mut ledger = ledger(silent_policy());

        assert_eq!(spend(&mut ledger, HOST, 80), 3);
        assert_eq!(spend(&mut ledger, HOST, 81), 3);

        ledger.arm(HOST, (HOST, 22), 9, (), t0);
        ledger.resolve(&(HOST, 22), Some(9), t0 + Duration::from_millis(3));

        assert_eq!(
            spend(&mut ledger, HOST, 82),
            3,
            "the host proved it is there"
        );
    }

    #[test]
    fn one_silent_host_does_not_cut_another_hosts_budget() {
        let mut ledger = ledger(silent_policy());

        assert_eq!(spend(&mut ledger, HOST, 80), 3);
        assert_eq!(spend(&mut ledger, HOST, 81), 3);
        assert_eq!(spend(&mut ledger, HOST, 82), 1);
        assert_eq!(spend(&mut ledger, OTHER, 80), 3);
    }

    #[test]
    fn without_the_rule_a_silent_host_keeps_its_full_budget_forever() {
        let mut ledger = ledger(policy());
        for port in 80..90 {
            assert_eq!(spend(&mut ledger, HOST, port), 3);
        }
    }

    // ── Bulk behaviour ─────────────────────────────────────────────────────

    #[test]
    fn draining_the_unresolved_empties_the_ledger() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());
        for port in 0..5u16 {
            ledger.arm(HOST, (HOST, port), u32::from(port), (), t0);
        }

        let mut remaining = ledger.drain_unresolved();
        remaining.sort_unstable();

        assert_eq!(remaining.len(), 5);
        assert!(ledger.is_empty());
        assert!(ledger.next_due().is_none());
        assert!(due_at(&mut ledger, t0 + Duration::from_secs(10)).is_empty());
    }

    #[test]
    fn the_earliest_deadline_is_the_one_reported() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());

        ledger.arm(HOST, (HOST, 80), 1, (), t0 + Duration::from_millis(50));
        ledger.arm(HOST, (HOST, 81), 2, (), t0);

        assert_eq!(
            ledger.next_due().unwrap().saturating_duration_since(t0),
            Duration::from_millis(100),
            "the probe armed first comes due first"
        );
    }

    /// More attempts than tokens retained keeps the recent ones without
    /// panicking.
    #[test]
    fn a_budget_beyond_the_tracked_attempts_keeps_the_newest_tokens() {
        let t0 = Instant::now();
        let policy = RetryPolicy::new(
            8,
            Duration::from_millis(100),
            Duration::from_millis(10),
            Duration::from_secs(2),
            1.0,
            0.0,
            None,
        );
        let mut ledger = ledger(policy);

        let mut now = t0;
        ledger.arm(HOST, (HOST, 80), 1, (), now);
        for token in 2..=7u32 {
            now += Duration::from_millis(100);
            assert!(!due_at(&mut ledger, now).is_empty());
            ledger.arm(HOST, (HOST, 80), token, (), now);
        }

        assert!(
            ledger.resolve(&(HOST, 80), Some(7), now).is_some(),
            "the newest attempt must always be matchable"
        );
    }

    #[test]
    fn worst_case_lifetime_covers_every_attempt() {
        let policy = RetryPolicy::new(
            3,
            Duration::from_millis(200),
            Duration::from_millis(25),
            Duration::from_secs(2),
            2.0,
            0.0,
            None,
        );

        // 200 + 400 + 800
        assert_eq!(
            policy.worst_case_probe_lifetime(),
            Duration::from_millis(1_400)
        );
        assert_eq!(
            RetryPolicy::none().worst_case_probe_lifetime(),
            Duration::from_millis(240),
            "one attempt, jittered upward"
        );
    }

    // ── Configuration ──────────────────────────────────────────────────────

    /// A profile shaped like the UDP scanner's, whose floor the protocol imposes.
    fn rate_limited_policy() -> RetryPolicy {
        RetryPolicy::new(
            2,
            Duration::from_millis(1_500),
            Duration::from_millis(1_200),
            Duration::from_secs(5),
            1.5,
            0.0,
            Some(SilentHostPolicy::new(32, 1)),
        )
    }

    fn effort(effort: ScanEffort) -> RetryConfig {
        RetryConfig {
            effort,
            ..Default::default()
        }
    }

    #[test]
    fn the_default_configuration_changes_nothing() {
        let base = policy();
        let configured = base.configured(RetryConfig::default());

        assert_eq!(configured.max_attempts, base.max_attempts);
        assert_eq!(configured.initial_rto, base.initial_rto);
        assert_eq!(configured.min_rto, base.min_rto);
        assert_eq!(configured.max_rto, base.max_rto);
        assert!(configured.silent_host.is_none(), "as the base had none");
    }

    #[test]
    fn a_single_attempt_effort_disables_retransmission() {
        let configured = policy().configured(effort(ScanEffort::Single));
        assert_eq!(configured.max_attempts, 1);
    }

    #[test]
    fn effort_moves_the_budget_in_the_direction_it_says() {
        let base = policy();
        let fast = base.configured(effort(ScanEffort::Fast));
        let thorough = base.configured(effort(ScanEffort::Thorough));

        assert!(fast.max_attempts < base.max_attempts);
        assert!(thorough.max_attempts > base.max_attempts);
        assert!(fast.initial_rto < base.initial_rto);
        assert!(thorough.initial_rto > base.initial_rto);
    }

    /// Even at the lowest effort a probe is still sent once.
    #[test]
    fn effort_never_reduces_the_budget_below_one_attempt() {
        let base = RetryPolicy::none();
        assert_eq!(base.max_attempts, 1);
        assert_eq!(
            base.configured(effort(ScanEffort::Fast)).max_attempts,
            1,
            "there is no such thing as sending a probe zero times"
        );
    }

    /// Hurrying the scan does not shorten the wait below what the protocol needs
    /// to answer.
    #[test]
    fn hurrying_a_scan_never_lowers_the_protocol_floor() {
        let base = rate_limited_policy();

        for config in [
            effort(ScanEffort::Fast),
            RetryConfig {
                timeout_scale: TimeoutScale::new(0.1),
                ..Default::default()
            },
            RetryConfig {
                effort: ScanEffort::Fast,
                timeout_scale: TimeoutScale::new(0.01),
                ..Default::default()
            },
        ] {
            let configured = base.configured(config);
            assert_eq!(
                configured.min_rto, base.min_rto,
                "the floor is what the protocol costs, not a preference"
            );
        }
    }

    /// A scale small enough to push the ceiling under the floor leaves a usable
    /// policy, without panicking.
    #[test]
    fn scaling_never_leaves_the_ceiling_below_the_floor() {
        let configured = rate_limited_policy().configured(RetryConfig {
            timeout_scale: TimeoutScale::new(0.01),
            ..Default::default()
        });

        assert!(configured.max_rto >= configured.min_rto);
        assert!(configured.worst_case_probe_lifetime() > Duration::ZERO);
    }

    /// A starting timeout scaled below the floor is not used.
    #[test]
    fn a_scaled_down_start_is_still_held_above_the_floor() {
        let t0 = Instant::now();
        let base = rate_limited_policy();
        let configured = base.configured(RetryConfig {
            timeout_scale: TimeoutScale::new(0.1),
            ..Default::default()
        });
        assert!(configured.initial_rto < configured.min_rto, "test premise");

        let mut ledger: ProbeLedger<(IpAddr, u16), ()> = ProbeLedger::seeded(configured, 4, 3);
        ledger.arm(HOST, (HOST, 53), (), (), t0);

        assert_eq!(
            ledger.next_due().unwrap().saturating_duration_since(t0),
            base.min_rto
        );
    }

    #[test]
    fn an_explicit_budget_overrides_the_effort_level() {
        let configured = policy().configured(RetryConfig {
            effort: ScanEffort::Thorough,
            max_attempts: NonZeroU8::new(2),
            ..Default::default()
        });

        assert_eq!(configured.max_attempts, 2);
    }

    /// A sighting counts once however many times the same frame is captured.
    #[test]
    fn one_attempt_seen_twice_is_witnessed_once() {
        let mut ledger: ProbeLedger<(IpAddr, u16), u32> =
            ProbeLedger::new(rate_limited_policy(), 8);
        let t0 = Instant::now();
        ledger.arm(HOST, (HOST, 80), 7, (), t0);

        assert!(ledger.witness(&(HOST, 80), &7), "the first sighting counts");
        assert!(
            !ledger.witness(&(HOST, 80), &7),
            "the second is the same one"
        );
    }

    /// A nonce the ledger never issued, or a key it no longer holds, witnesses
    /// nothing.
    #[test]
    fn a_sighting_of_something_else_witnesses_nothing() {
        let mut ledger: ProbeLedger<(IpAddr, u16), u32> =
            ProbeLedger::new(rate_limited_policy(), 8);
        let t0 = Instant::now();
        ledger.arm(HOST, (HOST, 80), 7, (), t0);

        assert!(!ledger.witness(&(HOST, 80), &9), "a nonce nobody sent");
        assert!(
            !ledger.witness(&(HOST, 81), &7),
            "a port nothing is armed on"
        );
    }

    /// The witnessed count rides out on the [`Due::Exhausted`] event, where the
    /// verdict is decided.
    #[test]
    fn an_exhausted_probe_reports_how_many_of_its_sends_were_seen() {
        let mut ledger: ProbeLedger<(IpAddr, u16), u32> =
            ProbeLedger::new(rate_limited_policy(), 8);
        let t0 = Instant::now();
        ledger.arm(HOST, (HOST, 80), 1, (), t0);
        assert!(ledger.witness(&(HOST, 80), &1));

        let mut seen = None;
        for step in 1..20 {
            let due = due_at(&mut ledger, t0 + Duration::from_secs(step));
            for event in due {
                match event {
                    Due::Retry { key, attempt } => ledger.rearm(HOST, key, attempt.into(), t0),
                    Due::Exhausted { witnessed, .. } => seen = Some(witnessed),
                }
            }
            if seen.is_some() {
                break;
            }
        }

        assert_eq!(
            seen,
            Some(1),
            "one send of several was watched leaving, and the caller is told so"
        );
    }

    #[test]
    fn the_silent_host_rule_can_be_turned_off() {
        let base = rate_limited_policy();
        assert!(base.silent_host.is_some(), "test premise");

        let kept = base.configured(RetryConfig::default());
        assert!(kept.silent_host.is_some());

        let off = base.configured(RetryConfig {
            dampen_silent_hosts: false,
            ..Default::default()
        });
        assert!(off.silent_host.is_none());
    }

    /// Thorough effort does not cut the budget on a silent host.
    #[test]
    fn a_thorough_scan_takes_no_shortcut_on_silent_hosts() {
        let configured = rate_limited_policy().configured(effort(ScanEffort::Thorough));
        assert!(configured.silent_host.is_none());
    }

    /// A scale no schedule can be built from cannot be written into a
    /// [`RetryConfig`]. The guard sits at
    /// [`TimeoutScale`](crate::config::TimeoutScale) so the report records only
    /// scales that applied.
    #[test]
    fn a_scale_no_schedule_can_be_built_from_never_reaches_a_policy() {
        for scale in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert_eq!(TimeoutScale::new(scale), None, "scale {scale}");
        }

        // A valid one is applied.
        let base = policy();
        let configured = base.configured(RetryConfig {
            timeout_scale: TimeoutScale::new(2.0),
            ..Default::default()
        });
        assert_eq!(configured.initial_rto, base.initial_rto * 2);
    }

    // ── Properties ─────────────────────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        /// However a scan is driven, a probe is never sent more times than its
        /// budget allows and always ends in exactly one verdict.
        #[test]
        fn a_probe_never_exceeds_its_budget(
            max_attempts in 1u8..6,
            steps in 1usize..40,
        ) {
            let policy = RetryPolicy::new(
                max_attempts,
                Duration::from_millis(10),
                Duration::from_millis(1),
                Duration::from_secs(1),
                1.0,
                0.0,
                None,
            );
            let mut ledger = ledger(policy);

            let t0 = Instant::now();
            ledger.arm(HOST, (HOST, 80), 0, (), t0);

            let mut sends = 1u8;
            let mut exhausted = 0;
            for step in 1..=steps {
                let now = t0 + Duration::from_millis(10 * step as u64);
                for event in due_at(&mut ledger, now) {
                    match event {
                        Due::Retry { key, attempt } => {
                            sends += 1;
                            prop_assert_eq!(attempt, sends);
                            ledger.arm(HOST, key, u32::from(attempt), (), now);
                        }
                        Due::Exhausted { .. } => exhausted += 1,
                    }
                }
                prop_assert!(sends <= max_attempts);
            }

            prop_assert!(exhausted <= 1, "a probe may only be retired once");
            if exhausted == 1 {
                prop_assert_eq!(sends, max_attempts);
                prop_assert!(ledger.is_empty());
            }
        }

        /// A probe resolved at any point stays resolved: it is not retried,
        /// retired, or resolved again.
        #[test]
        fn resolving_at_any_point_is_final(resolve_after in 0u64..60) {
            let policy = RetryPolicy::new(
                4,
                Duration::from_millis(10),
                Duration::from_millis(1),
                Duration::from_secs(1),
                1.0,
                0.0,
                None,
            );
            let mut ledger = ledger(policy);

            let t0 = Instant::now();
            ledger.arm(HOST, (HOST, 80), 1, (), t0);

            let resolve_at = t0 + Duration::from_millis(resolve_after);
            let mut resolved = false;
            let mut token = 1u32;

            for step in 1..=8u64 {
                let now = t0 + Duration::from_millis(10 * step);

                if !resolved && resolve_at <= now {
                    resolved = ledger.resolve(&(HOST, 80), Some(token), resolve_at).is_some();
                }

                for event in due_at(&mut ledger, now) {
                    prop_assert!(!resolved, "a resolved probe produced {:?}", event);
                    if let Due::Retry { key, attempt } = event {
                        token = u32::from(attempt);
                        ledger.arm(HOST, key, token, (), now);
                    }
                }
            }

            if resolved {
                prop_assert!(ledger.resolve(&(HOST, 80), Some(token), resolve_at).is_none());
            }
        }
    }
}
