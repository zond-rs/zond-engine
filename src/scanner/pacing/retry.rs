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
//! Every probing strategy in the engine faces the same problem: a probe that is
//! never answered is indistinguishable from a probe that never arrived. Treating
//! the first as evidence produces a confident, plausible, wrong answer - a
//! firewall where there was a dropped packet. The only way to tell them apart is
//! to ask again, which turns a one-shot send into a small state machine per
//! probe: how many times has this been asked, when is it worth asking again, and
//! when has enough been asked that silence finally means something.
//!
//! [`ProbeLedger`] is that state machine, kept in one place so the SYN, UDP and
//! link-layer paths cannot drift apart. It knows nothing about packets. It holds
//! no bytes, builds nothing, and sends nothing; a scanner tells it what left the
//! wire and asks it what to do next.
//!
//! # The three questions
//!
//! A scan loop asks exactly three things, and they map onto the API directly:
//!
//! - *Is this reply an answer to something I sent?* - [`ProbeLedger::resolve`]
//! - *What should I resend, and what has run out of attempts?* -
//!   [`ProbeLedger::drain_due`]
//! - *How long may I sleep?* - [`ProbeLedger::next_due`]
//!
//! # Why attempts are tracked individually
//!
//! A record keeps a token per attempt rather than only the most recent one, and
//! that is the detail the whole design turns on. Consider a SYN scan: attempt
//! one goes out carrying sequence number A, attempt two carries B, and then a
//! `SYN+ACK` acknowledging A arrives. It is a genuine answer from an open port,
//! but a scanner holding only B has no way to recognize it and reports the port
//! filtered. Retransmission would have made the scan *less* accurate on exactly
//! the lossy paths it was added for.
//!
//! Keeping every live token also buys something TCP itself cannot have. Karn's
//! algorithm exists because an endpoint cannot tell which transmission an
//! acknowledgement answers, so it must throw away round-trip samples from
//! retransmitted segments. A scanner picks a fresh sequence number per attempt,
//! so when the caller can name the attempt that answered, the sample is
//! unambiguous and is kept. Where the wire carries nothing to distinguish
//! attempts - a UDP probe from a fixed source port, an ARP request - the caller
//! passes no token and [`ProbeLedger`] applies Karn's rule on its behalf.
//!
//! # Cost
//!
//! Expiry is driven by a deadline-ordered queue rather than by rescanning the
//! outstanding set, so a tick with nothing due costs one comparison and arming
//! or retiring a probe costs `O(log n)`. Stale queue entries are discarded when
//! they surface rather than searched for and removed.

use crate::config::{RetryConfig, ScanEffort};
use std::collections::{BinaryHeap, HashMap};
use std::hash::Hash;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// How many attempt tokens one probe retains.
///
/// A reply older than the last few attempts is of no practical use: it would
/// have to have outlived several round-trip timeouts, and the probe it answers
/// has usually been retired by then anyway. Bounding this keeps a record a
/// fixed size, so the outstanding set costs no allocation per probe.
const MAX_TRACKED_ATTEMPTS: usize = 4;

/// How the budget is cut for a host that has never said anything.
///
/// Spending a full budget on every port of an address that answers nothing at
/// all is the single largest source of wasted traffic in a wide scan: three
/// attempts across 65 535 ports is nearly 200 000 packets to learn one fact.
///
/// The rule is deliberately conservative. *Any* reply counts as life - a `RST`,
/// an ICMP error, an ARP reply - so an ordinary firewalled-but-alive host that
/// refuses even one port never triggers it, and the budget is reduced rather
/// than abandoned. What it can still cost is a port that is open, behind a path
/// lossy enough to drop consecutive probes, on a host that answered nothing
/// else; that is the trade, and it is why this is optional.
///
/// `#[non_exhaustive]`: built through [`new`](Self::new). See
/// [`WindowLimits`](super::congestion::WindowLimits) for the argument.
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
/// Declared per scanner beside its deadline profile, since what counts as a
/// reasonable wait differs by protocol far more than by network: a SYN is
/// answered as fast as the path allows, while an ICMP error is rate-limited to
/// roughly one per second by the host that would send it.
///
/// `#[non_exhaustive]`: built through [`new`](Self::new) and the builders beside
/// it. See [`WindowLimits`](super::congestion::WindowLimits) for the argument.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Total sends per probe, initial attempt included. One disables
    /// retransmission, which is a supported configuration rather than a
    /// degenerate one: an internet-scale sweep will want it.
    pub max_attempts: u8,
    /// The timeout used before anything has been measured.
    ///
    /// Deliberately distinct from [`min_rto`](Self::min_rto). With no samples
    /// the network is unknown, not known to be fast, and starting at the floor
    /// would triple the traffic of a scan whose first probes cross an ocean.
    /// Only measurement is allowed to push the timeout down toward the floor.
    pub initial_rto: Duration,
    /// The shortest timeout measurement may justify.
    pub min_rto: Duration,
    /// The longest timeout, applied to the backed-off value as well. Also the
    /// ceiling on [`initial_rto`](Self::initial_rto), so a policy whose numbers
    /// disagree resolves in favour of the bound rather than the guess.
    pub max_rto: Duration,
    /// Multiplier applied per attempt, so a path that is losing packets is
    /// asked less often rather than more.
    pub backoff: f64,
    /// Fractional spread applied to every deadline, as a proportion of it.
    ///
    /// Load-bearing rather than decorative. Probes admitted together time out
    /// together, and an unjittered retry turns that into a synchronized burst
    /// at the moment the path is least able to absorb one.
    pub jitter: f64,
    /// How the budget is cut for hosts that never answer, if at all.
    pub silent_host: Option<SilentHostPolicy>,
    /// Whether one host's round trip is evidence about another's, which decides
    /// if a target with no measurement of its own inherits the scan's.
    ///
    /// True for anything whose timing is dominated by the *path*: on a routed
    /// scan every probe crosses the same links, so the first host to answer has
    /// told the scan roughly what the rest will cost, and starting a fresh
    /// target from first principles wastes the knowledge.
    ///
    /// False where the timing is dominated by the *responder*. Neighbor
    /// discovery on a segment is the case that forced this: a mains-powered
    /// router answers a solicitation in five milliseconds and a phone asleep on
    /// wifi takes four hundred, over the same link at the same moment. One
    /// number does not describe both populations, and inheriting the fast one
    /// retransmits to the slow one before it could possibly have answered -
    /// which, for a probe whose attempts are indistinguishable on the wire,
    /// destroys the measurement rather than merely wasting a packet.
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
    /// responder rather than the path decides the timing, chain
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
    /// A builder rather than an eighth argument, so the protocols for which one
    /// neighbour predicts the next - which is most of them - keep declaring
    /// themselves in one call, and the exception says why it is one.
    /// See [`cross_host_estimate`](Self::cross_host_estimate).
    pub const fn without_cross_host_estimate(self) -> Self {
        Self {
            cross_host_estimate: false,
            ..self
        }
    }

    /// Sends each probe exactly once.
    ///
    /// Not a disabled feature but a working configuration: it is what an
    /// address-space-scale sweep wants, where per-probe state cannot be
    /// afforded and coverage is bought with a second pass instead.
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
    /// The scanner's own numbers are the starting point and the protocol's
    /// constraints survive: the effort level and the scale factor move what the
    /// scan is *willing* to wait, never the floor below which waiting less is
    /// simply wrong.
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
    /// [`min_rto`](Self::min_rto) is untouched on purpose. It is the shortest
    /// wait that can still produce an answer, which is a property of the
    /// protocol rather than of how much hurry the caller is in.
    ///
    /// `factor` is positive and finite. It used to be guarded here instead, and
    /// a caller's zero or NaN was discarded without a word and then written into
    /// the report as though it had applied;
    /// [`TimeoutScale`](crate::config::TimeoutScale) is where that is refused
    /// now.
    fn scaled(self, factor: f64) -> Self {
        debug_assert!(
            factor.is_finite() && factor > 0.0,
            "a scale that cannot build a schedule is refused at `TimeoutScale`, \
             and the effort levels below pass their own literals"
        );

        Self {
            initial_rto: self.initial_rto.mul_f64(factor),
            // Scaling the ceiling below the floor would leave the policy
            // describing an empty range. The floor wins, since it is the one of
            // the two that the protocol imposes.
            max_rto: self.max_rto.mul_f64(factor).max(self.min_rto),
            ..self
        }
    }

    /// The longest a probe can occupy the ledger: every attempt's timeout at
    /// its most generous, with no measurement to shorten it.
    ///
    /// This is what a scan's own deadline has to accommodate. A hard budget
    /// shorter than this expires the scan between one attempt and the next, so
    /// probes are written off as unanswered having never been fully asked.
    pub fn worst_case_probe_lifetime(&self) -> Duration {
        let mut total = Duration::ZERO;
        for attempt in 1..=self.max_attempts {
            let scaled = scale(self.initial_rto, self.backoff, attempt).min(self.max_rto);
            total = total.saturating_add(scaled.mul_f64(1.0 + self.jitter.max(0.0)));
        }
        total
    }

    /// The budget for a probe to `host`, after any silent-host reduction.
    fn budget_for(&self, host: Option<&HostState>) -> u8 {
        let Some(rule) = self.silent_host else {
            return self.max_attempts;
        };
        let Some(host) = host else {
            return self.max_attempts;
        };

        if !host.answered && host.exhausted_silently >= rule.threshold {
            return rule.reduced_attempts.min(self.max_attempts);
        }
        self.max_attempts
    }
}

/// A smoothed round-trip estimate and its variability, as RFC 6298 computes
/// them for TCP.
///
/// Chosen over the sample window that steers the scan deadline
/// ([`RttWindow`](super::rtt_window::RttWindow)) because this one is kept *per
/// host*, where the cost per entry decides whether per-host timing is
/// affordable at all: two durations updated in place, rather than a queue of
/// twenty.
#[derive(Debug, Clone, Copy, Default)]
pub struct RttEstimator {
    smoothed: Option<Duration>,
    variation: Duration,
}

impl RttEstimator {
    /// Folds in one round-trip measurement.
    ///
    /// The first sample has nothing to smooth against, so it becomes the
    /// estimate outright and seeds the variation at half of itself, which is
    /// what keeps a single fast sample from producing a timeout too tight to
    /// survive the second.
    pub fn record(&mut self, sample: Duration) {
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
    /// Four variations of headroom is the margin TCP allows itself, and the
    /// reasoning carries over unchanged: it is wide enough that ordinary
    /// variance does not trip it, and narrow enough that a genuinely lost packet
    /// is noticed in the same order of magnitude as the round trip.
    pub fn timeout(&self) -> Option<Duration> {
        self.smoothed
            .map(|smoothed| smoothed.saturating_add(self.variation * 4))
    }

    /// Whether nothing has been recorded yet, which is when
    /// [`timeout`](Self::timeout) has no answer to give.
    pub fn is_empty(&self) -> bool {
        self.smoothed.is_none()
    }
}

/// One attempt as it left the wire.
#[derive(Debug, Clone, Copy)]
struct Attempt<T> {
    token: T,
    sent_at: Instant,
}

/// An outstanding probe.
struct Record<T, P> {
    /// Caller data handed over at [`ProbeLedger::arm`] and given back when the
    /// probe retires. The ledger never reads it.
    ///
    /// Held here rather than in a map beside the ledger so its lifetime is the
    /// record's: it cannot outlive the probe, and it cannot go missing while the
    /// probe is live.
    payload: P,
    host: IpAddr,
    /// The live attempts, oldest first, capped at [`MAX_TRACKED_ATTEMPTS`].
    attempts: [Option<Attempt<T>>; MAX_TRACKED_ATTEMPTS],
    /// How many sends this probe has had, which may exceed the number of
    /// tokens retained.
    sends: u8,
    /// How many sends actually reached the wire and were recorded here.
    ///
    /// Deliberately separate from [`sends`](Self::sends), which is charged when
    /// a retry is *scheduled* so that a probe nobody manages to send still
    /// exhausts on time. Numbering the tracked attempts off that count would
    /// misname them by however many were charged and never emitted, so the
    /// numbering follows the wire instead.
    recorded: u8,
    /// The budget in force, resolved when the probe was first armed and again
    /// on every retry, so a host that comes to life mid-scan lifts the
    /// restriction on probes still outstanding against it.
    budget: u8,
    /// Identifies this record's live queue entry. Any entry carrying a
    /// different value has been superseded and is discarded on sight, which is
    /// how a timer is cancelled without being found.
    generation: u32,
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
            budget,
            generation,
        }
    }

    /// Stores the token one attempt was sent with, evicting the oldest when the
    /// array is full.
    ///
    /// The attempt *count* is deliberately not touched here. It belongs to
    /// [`ProbeLedger::drain_due`], which charges an attempt when it schedules a
    /// retry rather than when the caller gets around to sending it, so a retry
    /// that is never actually emitted still exhausts on schedule.
    fn record_attempt(&mut self, token: T, sent_at: Instant) {
        self.recorded = self.recorded.saturating_add(1);

        if self.attempts[MAX_TRACKED_ATTEMPTS - 1].is_some() {
            self.attempts.rotate_left(1);
            self.attempts[MAX_TRACKED_ATTEMPTS - 1] = Some(Attempt { token, sent_at });
            return;
        }

        let slot = self
            .attempts
            .iter()
            .position(Option::is_none)
            .unwrap_or(MAX_TRACKED_ATTEMPTS - 1);
        self.attempts[slot] = Some(Attempt { token, sent_at });
    }

    /// The attempt carrying `token`: which send it was, counting the first as
    /// 1, and when it left.
    ///
    /// Only the last few attempts are tracked, so the ordinal is counted back
    /// from the newest rather than read off the slot. A probe retried more than
    /// [`MAX_TRACKED_ATTEMPTS`] times has forgotten its earliest tokens
    /// entirely, and a reply to one of those is unrecognizable rather than
    /// misnumbered.
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
    /// one. This is Karn's rule: with several attempts outstanding and nothing
    /// in the reply to tell them apart, no sample can honestly be taken.
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
    /// Whether anything has ever come back from it.
    answered: bool,
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
    /// Send this again. The probe stays outstanding, and the ledger has already
    /// counted the attempt, so a caller that cannot send - no route, a refused
    /// socket - may simply do nothing and let it exhaust on its own.
    Retry {
        /// Which probe to send again.
        key: K,
        /// Which attempt this is, counting the first send as one.
        attempt: u8,
    },
    /// The budget is spent and the probe is no longer outstanding. This is the
    /// moment a verdict of "filtered" is earned rather than assumed.
    Exhausted {
        /// The probe being retired.
        key: K,
        /// Whatever the caller armed this probe with.
        payload: P,
        /// How many times it was sent, so a caller can tell the probe that was
        /// asked once from the one that was asked three times. A pacing
        /// controller needs the difference: the first of a probe's timeouts is
        /// the one that says something about the path, and with a budget of one
        /// attempt this event *is* that first timeout.
        attempts: u8,
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
    /// This is what separates a probe that needed repeating from one that
    /// merely needed waiting for. Both look identical in a count of hosts
    /// found: a host credited after three attempts may have answered the third,
    /// or answered the first from a path slow enough that two more went out
    /// meanwhile. Only the token says which, and the difference decides whether
    /// coverage is bought with more packets or with more patience.
    pub answered_attempt: Option<u8>,
}

/// The outstanding probes of one scanner, and the schedule on which they are
/// resent and retired.
///
/// `K` identifies a probe - `(IpAddr, u16)` for a port scan, `IpAddr` for host
/// discovery. `T` is the per-attempt token a reply can be matched against, such
/// as a TCP sequence number; where the wire carries no such thing, use `()`.
///
/// Time is supplied by the caller at every entry point rather than read from the
/// clock internally, so a scan loop reads it once per iteration and the whole
/// structure is testable without sleeping.
pub struct ProbeLedger<K, T, P = ()> {
    policy: RetryPolicy,
    records: HashMap<K, Record<T, P>>,
    timers: BinaryHeap<Timer<K>>,
    hosts: HashMap<IpAddr, HostState>,
    /// Fallback timing for a host that has not answered yet, so a fresh target
    /// on a known-slow network does not start from first principles.
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

    /// [`new`](Self::new) with the jitter sequence pinned, so a test observes
    /// one schedule rather than a family of them.
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
    /// Called after the first send and after every retry alike; the ledger
    /// counts the attempts itself. Arming supersedes any timer the probe
    /// already had, so the timeout runs from when the packet actually left
    /// rather than from when the retry was suggested.
    pub fn arm(&mut self, host: IpAddr, key: K, token: T, payload: P, now: Instant) {
        self.arm_inner(host, key, token, Some(payload), now);
    }

    /// Records a *retry* for a probe already outstanding, keeping the payload it
    /// was armed with.
    ///
    /// Separate from [`arm`](Self::arm) because a retry is driven from
    /// [`Due::Retry`], which names the probe and not what the caller knew about
    /// it when it first went out. Re-supplying the payload there would mean
    /// carrying it through the retry path for no reason, and inventing one would
    /// silently replace it.
    pub fn rearm(&mut self, host: IpAddr, key: K, token: T, now: Instant) {
        self.arm_inner(host, key, token, None, now);
    }

    fn arm_inner(&mut self, host: IpAddr, key: K, token: T, payload: Option<P>, now: Instant) {
        let generation = self.take_generation();

        let host_state = self.hosts.entry(host).or_default();
        let budget = self.policy.budget_for(Some(host_state));

        let record = match self.records.get_mut(&key) {
            Some(record) => {
                // A retry: the budget is re-read so a host that has since
                // answered lifts any restriction on its outstanding probes.
                record.budget = budget;
                record.generation = generation;
                if let Some(payload) = payload {
                    record.payload = payload;
                }
                record
            }
            None => {
                // A `rearm` for a probe that is no longer outstanding: it was
                // resolved or retired between the retry being scheduled and the
                // send. There is nothing to arm and no payload to invent, so it
                // is dropped, as a stale timer already is.
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

        let due = now + self.timeout_for(host, attempt);
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
    /// `None` comes back for a duplicate, for a reply to a probe already
    /// resolved or retired, and for a token matching no live attempt - all of
    /// which are to be dropped. That is what makes resolution exactly-once: a
    /// second reply finds nothing to resolve.
    pub fn resolve(&mut self, key: &K, token: Option<T>, now: Instant) -> Option<Resolution<P>> {
        let record = self.records.get(key)?;
        let payload = record.payload;

        let attributed = match token {
            // A token naming no attempt we made is someone else's packet, so
            // the probe is left outstanding rather than resolved by it.
            Some(token) => Some(record.attempt_of(&token)?),
            // Karn's rule leaves the sample unusable with several sends
            // outstanding, but a probe sent once has nothing to confuse its
            // reply with: it answered the first attempt by elimination.
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
        host_state.answered = true;
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
    /// counted; a [`Due::Exhausted`] has removed it. The buffer is supplied by
    /// the caller so a scanner can send while the ledger is mutably borrowed,
    /// and so a tick with nothing due allocates nothing.
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

            if record.sends >= record.budget {
                let host = record.host;
                let attempts = record.sends;
                let payload = record.payload;
                self.records.remove(&timer.key);
                self.retire(host);
                out.push(Due::Exhausted {
                    key: timer.key,
                    payload,
                    attempts,
                });
                continue;
            }

            // The attempt is counted here rather than when the caller sends, so
            // a probe whose retry is never actually emitted still exhausts on
            // schedule instead of waiting outstanding forever.
            record.sends += 1;
            let attempt = record.sends;
            let host = record.host;
            let generation = self.take_generation();
            self.records
                .get_mut(&timer.key)
                .expect("record present")
                .generation = generation;

            let due = now + self.timeout_for(host, attempt);
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
    /// This is what a scan loop sleeps on. It may name a deadline belonging to a
    /// superseded entry and so wake the loop early; the cost is one extra
    /// iteration, which is cheaper than keeping the queue exactly pruned.
    pub fn next_due(&self) -> Option<Instant> {
        self.timers.peek().map(|timer| timer.due)
    }

    /// Removes every outstanding probe, yielding their keys, for a scan that is
    /// stopping before they could be resolved on their own.
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

    /// Whether no probe is outstanding. Once a scan has admitted its last
    /// target, this is what tells its loop there is nothing left to wait for.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Whether `key` is currently outstanding.
    pub fn contains(&self, key: &K) -> bool {
        self.records.contains_key(key)
    }

    /// Whether anything has ever come back from `host`: a SYN+ACK, a reset, an
    /// ICMP error, any reply at all.
    ///
    /// The question a pacing controller asks about a probe that went unanswered,
    /// and the one that decides what the silence means. A host that answers
    /// nothing is behind a firewall or is not there, and neither is a reason to
    /// ask more slowly; a host that answers most things and drops the rest is
    /// failing to keep up, and that is exactly a reason to. See
    /// [`congestion`](super::congestion).
    ///
    /// Deliberately not "has a round trip", which
    /// [`host_rtt`](Self::host_rtt) answers: a reply that could not be
    /// attributed to an attempt still proves the host is talking, and a host
    /// whose every reply arrived ambiguously would otherwise look silent.
    pub fn host_has_answered(&self, host: &IpAddr) -> bool {
        self.hosts.get(host).is_some_and(|state| state.answered)
    }

    /// The smoothed round trip observed for `host`, if it has answered.
    pub fn host_rtt(&self, host: &IpAddr) -> Option<Duration> {
        self.hosts.get(host)?.estimator.smoothed
    }

    /// Seeds `host`'s round-trip estimate from a measurement this ledger did not
    /// take.
    ///
    /// A port scan reaches a host that a liveness phase has already timed, and
    /// starting from [`initial_rto`](RetryPolicy::initial_rto) throws that away:
    /// the first wave of probes to a host answering in five milliseconds waits
    /// two hundred before repeating, and every genuinely filtered port pays that
    /// wait three times over. Seeded, the same tail is settled in a fraction of
    /// the time.
    ///
    /// Seeding *down* is safe in a way it would not be without per-attempt
    /// tokens. An estimate too tight retransmits early, and the reply to the
    /// first attempt still names the first attempt when it arrives, so the
    /// round trip is measured correctly and, for a caller reading the answered
    /// attempt as a loss signal, an early retry is not mistaken for one. What it
    /// costs is the extra packet, bounded by [`min_rto`](RetryPolicy::min_rto).
    ///
    /// Does nothing for a host this ledger has already measured for itself: a
    /// sample it took beats one it was handed.
    pub fn seed_host_rtt(&mut self, host: IpAddr, rtt: Duration) {
        let state = self.hosts.entry(host).or_default();
        if state.estimator.is_empty() {
            state.estimator.record(rtt);
        }
        if self.policy.cross_host_estimate && self.global.is_empty() {
            self.global.record(rtt);
        }
    }

    /// Accounts for a probe that spent its entire budget in silence.
    fn retire(&mut self, host: IpAddr) {
        let state = self.hosts.entry(host).or_default();
        state.outstanding = state.outstanding.saturating_sub(1);
        if !state.answered {
            state.exhausted_silently = state.exhausted_silently.saturating_add(1);
        }
    }

    /// The timeout for `attempt` against `host`: what has been measured, backed
    /// off for the attempt number, bounded, and spread.
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

        // Held to the floor whichever it came from. The starting value is a
        // guess about an unknown path and may be tuned down freely, but not
        // below the point where an answer could not have arrived yet - a probe
        // repeated sooner than the protocol can reply is a wasted packet, not a
        // faster scan.
        //
        // The ceiling is taken as at least the floor so a policy whose bounds
        // have been configured into disagreeing still describes a real range
        // rather than an empty one.
        let ceiling = self.policy.max_rto.max(self.policy.min_rto);
        let base = match measured {
            Some(measured) => measured,
            None => self.policy.initial_rto,
        };
        let base = base.clamp(self.policy.min_rto, ceiling);

        let scaled = scale(base, self.policy.backoff, attempt).min(ceiling);
        self.jitter.spread(scaled, self.policy.jitter)
    }

    fn take_generation(&mut self) -> u32 {
        self.next_generation = self.next_generation.wrapping_add(1);
        self.next_generation
    }
}

/// `base` multiplied by `backoff` once per attempt beyond the first.
fn scale(base: Duration, backoff: f64, attempt: u8) -> Duration {
    if attempt <= 1 || backoff <= 1.0 {
        return base;
    }
    base.mul_f64(backoff.powi(i32::from(attempt - 1)))
}

/// The jitter source: SplitMix64, small enough to inline and with a fixed,
/// documented output sequence, so a seeded ledger schedules identically
/// forever. Borrowing a generator whose stream is not stable across releases
/// would make a reproducible schedule quietly stop reproducing.
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

    /// `base` scaled by a factor drawn uniformly from `[1 - spread, 1 + spread]`.
    fn spread(&mut self, base: Duration, spread: f64) -> Duration {
        if spread <= 0.0 {
            return base;
        }
        let spread = spread.min(1.0);
        let factor = 1.0 + (self.next_unit() * 2.0 - 1.0) * spread;
        base.mul_f64(factor.max(0.0))
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

    const HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
    const OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 201));

    /// Three attempts, no jitter and no backoff, so a schedule is exactly
    /// predictable and a test can assert on instants rather than ranges.
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

    fn ledger(policy: RetryPolicy) -> ProbeLedger<(IpAddr, u16), u32> {
        ProbeLedger::seeded(policy, 8, 0x5EED)
    }

    /// A port scan meets hosts a liveness phase already timed, and starting
    /// from the unmeasured guess throws that away: the cost lands entirely on
    /// the ports that turn out to be filtered, each of which then waits the full
    /// guess three times before silence is allowed to mean anything.
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

    /// A sample this ledger took itself beats one it was handed: the seed is a
    /// starting point for a host nothing has asked yet, not a correction to what
    /// the scan is currently observing.
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

    /// A fast answer from one host must not shorten an unmeasured host's first
    /// timeout when the policy says the two are unrelated.
    ///
    /// This is the defect that can hide an entire retry schedule: one fast
    /// neighbour seeds the scan-wide estimate, the estimate is clamped up to
    /// [`min_rto`](RetryPolicy::min_rto), and the floor rather than the declared
    /// timeout becomes what the scan actually runs on.
    ///
    /// It matters most where the two populations differ by orders of magnitude,
    /// as they do on a segment carrying both mains-powered and sleeping devices.
    /// Retransmitting to the slow one before it could have replied does not just
    /// waste a packet: where a protocol's attempts are indistinguishable on the
    /// wire, it discards the measurement.
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

        let fast: IpAddr = "10.0.0.1".parse().unwrap();
        let unmeasured: IpAddr = "10.0.0.2".parse().unwrap();
        let start = Instant::now();

        let mut ledger = ledger(policy);
        ledger.arm(fast, (fast, 0), 1, (), start);
        // The fast neighbour answers in six milliseconds, seeding whatever
        // scan-wide estimate the ledger keeps.
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

    /// The default is the opposite, and deliberately so: where every probe
    /// crosses the same path, the first host to answer has told the scan what
    /// the rest will cost, and a fresh target should not start from first
    /// principles.
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

        let fast: IpAddr = "10.0.0.1".parse().unwrap();
        let unmeasured: IpAddr = "10.0.0.2".parse().unwrap();
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

    /// The keys due at `now`, for the tests that only care about which probes
    /// came back and not about the buffer plumbing.
    fn due_at(
        ledger: &mut ProbeLedger<(IpAddr, u16), u32>,
        now: Instant,
    ) -> Vec<Due<(IpAddr, u16)>> {
        let mut out = Vec::new();
        ledger.drain_due(now, &mut out);
        out
    }

    // ── Attributing a reply to an attempt ──────────────────────────────────

    /// The distinction the whole attribution exists for. A host found after
    /// three sends may have answered the third - retransmission earning its
    /// traffic - or answered the first from a path slow enough that two more
    /// went out while the reply was in flight. Only the token tells them apart,
    /// and they call for opposite fixes.
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
    /// The three coincide only for a probe sent once, which is why the error is
    /// easy to introduce and invisible afterwards: it would report a fast host
    /// recovered by a late retry as a slow one, and feed that invented latency
    /// to every estimator downstream - the adaptive deadline and the retry
    /// schedule both.
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

    /// A probe sent once has nothing its reply could be confused with, so an
    /// untokened reply answers the first attempt by elimination. With several
    /// outstanding, Karn's rule applies and nothing may be claimed.
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

    /// Only the last few attempts keep their tokens, and the ordinal is counted
    /// back from the newest rather than read off the slot - so a probe that has
    /// outlived its earliest tokens still numbers the surviving ones correctly
    /// rather than restarting at one.
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

        // A token evicted along the way names no attempt, so the probe stays
        // outstanding rather than being resolved by an unrecognizable reply.
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

    /// The budget is a total, not a count of retries: three attempts means two
    /// resends and then a verdict.
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
                // One, and the number matters to whoever reads it: with no
                // retry, this event *is* the probe's first timeout.
                attempts: 1,
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

        // Nothing is due yet at the first deadline minus a hair, and the retry
        // that follows must wait twice as long as the attempt before it.
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

    /// The invariant a duplicate reply must not break: a probe resolves once,
    /// however many answers arrive.
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

    /// The regression this design exists to prevent. Attempt one goes out
    /// carrying token 7, attempt two carries 8, and the answer to the *first*
    /// arrives afterwards. A ledger holding only the newest token would discard
    /// a genuine reply and report the target filtered.
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

    /// Karn's rule. With no token to name the attempt and more than one in
    /// flight, there is no honest sample to take - but the probe still resolves.
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

    /// An answered probe must never be resent: the timer it was armed with is
    /// still in the queue, and only generation matching keeps it from firing.
    #[test]
    fn a_resolved_probe_is_never_due_again() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());
        ledger.arm(HOST, (HOST, 80), 7, (), t0);
        ledger.resolve(&(HOST, 80), Some(7), t0 + Duration::from_millis(5));

        assert!(due_at(&mut ledger, t0 + Duration::from_secs(10)).is_empty());
    }

    /// Re-arming supersedes the previous timer rather than adding a second one,
    /// so a probe cannot be retried twice for one attempt.
    #[test]
    fn re_arming_supersedes_the_previous_timer() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());

        ledger.arm(HOST, (HOST, 80), 1, (), t0);
        let retry = t0 + Duration::from_millis(100);
        assert_eq!(due_at(&mut ledger, retry).len(), 1);
        ledger.arm(HOST, (HOST, 80), 2, (), retry);

        // The superseded entry is still in the queue and its deadline has
        // passed; it must produce nothing.
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

    /// Once a host has answered, its own round trip drives the timeout rather
    /// than the conservative starting value.
    #[test]
    fn a_measured_host_gets_a_timeout_derived_from_its_own_round_trip() {
        let t0 = Instant::now();
        let mut ledger = ledger(policy());

        ledger.arm(HOST, (HOST, 80), 1, (), t0);
        ledger.resolve(&(HOST, 80), Some(1), t0 + Duration::from_millis(4));

        ledger.arm(HOST, (HOST, 81), 2, (), t0);
        let measured = ledger.next_due().unwrap().saturating_duration_since(t0);

        // 4ms smoothed, 2ms variation, so 4 + 4*2 = 12ms, well under the
        // 100ms this scan started out assuming.
        assert_eq!(measured, Duration::from_millis(12));
        assert_eq!(ledger.host_rtt(&HOST), Some(Duration::from_millis(4)));
    }

    /// One host's measurements must not decide another's timeout, which is the
    /// whole reason the estimate is per host.
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
                due >= Duration::from_millis(75) && due <= Duration::from_millis(125),
                "seed {seed} produced {due:?}"
            );
        }
    }

    /// Probes armed together must not all come due at the same instant, which
    /// is the entire purpose of jitter.
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

        // Far fewer than all 64 should be due at the unjittered deadline.
        let due = due_at(&mut ledger, t0 + Duration::from_millis(100));
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

    /// Any reply at all is evidence of life, including one that says the port
    /// is closed. A firewalled-but-alive host must keep its full budget.
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

    /// More attempts than tokens retained must not lose the recent ones, and
    /// must not panic.
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

    /// A profile shaped like the UDP scanner's, where the floor exists because
    /// the protocol imposes it rather than because it seemed about right.
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

    /// The rule that keeps a global knob from producing a locally nonsensical
    /// schedule: hurrying the scan must not shorten the wait below what the
    /// protocol needs to answer at all.
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

    /// A scale small enough to push the ceiling under the floor must leave a
    /// usable policy rather than an empty range, and must not panic.
    #[test]
    fn scaling_never_leaves_the_ceiling_below_the_floor() {
        let configured = rate_limited_policy().configured(RetryConfig {
            timeout_scale: TimeoutScale::new(0.01),
            ..Default::default()
        });

        assert!(configured.max_rto >= configured.min_rto);
        assert!(configured.worst_case_probe_lifetime() > Duration::ZERO);
    }

    /// And the floor genuinely binds: a starting timeout scaled below it is
    /// still not used, so no probe is repeated sooner than it could be answered.
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

    /// Thorough means no shortcuts, and cutting the budget on a silent host is
    /// the one shortcut this policy takes.
    #[test]
    fn a_thorough_scan_takes_no_shortcut_on_silent_hosts() {
        let configured = rate_limited_policy().configured(effort(ScanEffort::Thorough));
        assert!(configured.silent_host.is_none());
    }

    /// A scale no schedule can be built from never reaches this policy, because
    /// it cannot be written into a [`RetryConfig`] at all.
    ///
    /// It used to be accepted there, silently discarded here, and then written
    /// into the report as though it had applied. Guarding it at the point of use
    /// fixed the schedule and left the record wrong, which is why the guard
    /// moved to [`TimeoutScale`](crate::config::TimeoutScale) and this asserts
    /// the refusal rather than the shrug.
    #[test]
    fn a_scale_no_schedule_can_be_built_from_never_reaches_a_policy() {
        for scale in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert_eq!(TimeoutScale::new(scale), None, "scale {scale}");
        }

        // And one that can is applied rather than merely accepted.
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

        /// A probe resolved at any point in its life stays resolved: it is
        /// never retried, never retired, and never resolves a second time.
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
