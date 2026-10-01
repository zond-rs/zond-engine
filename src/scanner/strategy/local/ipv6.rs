// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Finding the IPv6 half of a segment
//!
//! An IPv6 `/64` has too many addresses to walk, so a neighbour is found in one
//! of three ways, each with its own state:
//!
//! - **The all-nodes solicitation.** One multicast echo the whole segment may
//!   answer. No reply retires it, so it is repeated a fixed number of times and
//!   then listened for. It is the only probe here that can be attributed,
//!   because an echo reply names the request it answers.
//! - **A solicitation put to one address** already known from the target list,
//!   the host's neighbour table, or a lead overheard on the segment. Retransmitted
//!   through a ledger on its own schedule.
//! - **A confirmation**, the single solicitation an overheard address gets.
//!
//! This module holds state and timing: what has been asked, when, what is still
//! owed, and how long an answer could still arrive. Building and sending frames
//! stays in [`LocalScanner`](super::LocalScanner). Every decision here is a
//! function of a clock and a few collections, so it is testable without a
//! simulated segment.
//!
//! Two solicitations for one address are identical on the wire and an
//! advertisement carries no identifier, so Karn's rule discards a reply that
//! could answer either. A round trip is measurable only when the first attempt
//! is answered, which makes every timeout here load-bearing and is why a
//! confirmation is never retried.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::scanner::pacing::retry::{ProbeLedger, Resolution, RetryPolicy};

/// Outstanding per-address solicitations and the schedule they are retried on.
///
/// The attempt token is `()`: consecutive solicitations for one address are
/// indistinguishable, so the ledger declines to measure a retried one.
type Ledger = ProbeLedger<IpAddr, ()>;

/// How a neighbor solicitation is retransmitted.
///
/// Under Karn's rule (see the module docs) only an answered first attempt yields
/// a round trip, so the first timeout must outlast the replies. The second
/// attempt recovers a lost probe and gives up the measurement.
///
/// Measured one solicitation per address on a wireless segment, neighbours
/// answer in single-digit milliseconds when mains-powered and up to about 400 ms
/// when asleep; 800 ms covers the worst case.
///
/// [`without_cross_host_estimate`](RetryPolicy::without_cross_host_estimate)
/// keeps one fast neighbour from pulling every unmeasured neighbour's first
/// timeout down to [`min_rto`](RetryPolicy::min_rto). A per-host estimate cannot
/// help, since an address is asked once per sweep.
///
/// Slack here is charged to every scan:
/// [`DEADLINE_CONFIG`](super::DEADLINE_CONFIG) is widened to outlive the
/// longest probe, whether or not any IPv6 neighbour is slow.
pub(super) const NDP_RETRY_POLICY: RetryPolicy = RetryPolicy::new(
    2,
    Duration::from_millis(800),
    Duration::from_millis(400),
    Duration::from_secs(3),
    1.5,
    0.2,
    None,
)
.without_cross_host_estimate();

/// How many times the all-nodes solicitation is sent.
///
/// Every neighbour with no address in the scanned IPv4 range is found through
/// this probe alone. Measured with a single solicitation, a segment's IPv4 hosts
/// came back identically on every run while the IPv6-only ones came and went.
pub(super) const SOLICITATION_ATTEMPTS: u8 = 3;

/// How long to leave between solicitations.
pub(super) const SOLICITATION_INTERVAL: Duration = Duration::from_millis(600);

/// How long after the final solicitation the sweep keeps listening.
///
/// Longer than a round trip: implementations spread their replies to a
/// multicast probe, and a device asleep on wifi answers when it next wakes.
/// Observed on a live segment, replies landed 0.9 to 1.9 s after the request,
/// varying by a second between runs for the same host. That was measured with
/// the sweep broadcasting at full rate, so part of it may be congestion; the
/// echo's recorded timings can correct it. Erring long costs the tail of a
/// sweep; erring short discards a host that did answer.
pub(super) const SOLICITATION_WINDOW: Duration = Duration::from_millis(1_500);

/// The all-nodes solicitation's schedule: which requests have gone out and
/// when, when the next is owed, and how long the last one is still worth
/// waiting on.
///
/// Outside the [`Ledger`] because no single reply resolves it and there is
/// nothing to give up on.
///
/// An echo reply carries the identifier and sequence number of the request it
/// answers, so every attempt's send time is kept: measuring against the wrong
/// request would report a neighbour's sleep schedule as latency.
#[derive(Debug)]
pub(super) struct Solicitation {
    /// Identifies this scan's echo requests among other pings. One value for
    /// the whole run; the sequence number separates the attempts.
    pub(super) identifier: u16,
    /// When each request left, indexed by the sequence number it carried.
    pub(super) sent_at: Vec<Instant>,
    next_due: Option<Instant>,
    last_sent_at: Option<Instant>,
}

impl Default for Solicitation {
    fn default() -> Self {
        Self {
            identifier: rand::random(),
            sent_at: Vec::with_capacity(SOLICITATION_ATTEMPTS as usize),
            next_due: None,
            last_sent_at: None,
        }
    }
}

impl Solicitation {
    /// The sequence number the next request should carry.
    pub(super) fn next_sequence(&self) -> u16 {
        self.sent_at.len() as u16
    }

    /// When the request carrying `identifier` and `sequence` left, or `None` if
    /// this scan never sent it.
    ///
    /// A foreign identifier or an unsent sequence comes back unmeasured. The
    /// frame still carries the neighbour's MAC, which proves it is there.
    pub(super) fn sent_at(&self, identifier: u16, sequence: u16) -> Option<Instant> {
        if identifier != self.identifier {
            return None;
        }
        self.sent_at.get(sequence as usize).copied()
    }

    /// Makes the first request due now.
    ///
    /// A run that must not sweep the segment, or has no link-local address to
    /// ask from, never arms this and never owes a probe.
    pub(super) fn arm(&mut self, now: Instant) {
        self.next_due = Some(now);
    }

    /// Records one going out and schedules the next, if any are still owed.
    pub(super) fn record_sent(&mut self, now: Instant) {
        self.sent_at.push(now);
        self.last_sent_at = Some(now);
        self.next_due = (self.sent_at.len() < SOLICITATION_ATTEMPTS as usize)
            .then(|| now + SOLICITATION_INTERVAL);
    }

    /// Whether another one is owed now.
    pub(super) fn is_due(&self, now: Instant) -> bool {
        self.next_due.is_some_and(|due| due <= now)
    }

    /// Whether a reply could still legitimately arrive: another solicitation is
    /// owed, or the last one is still inside its response window.
    pub(super) fn window_open(&self, now: Instant) -> bool {
        if self.next_due.is_some() {
            return true;
        }
        self.last_sent_at
            .is_some_and(|sent_at| now < sent_at + SOLICITATION_WINDOW)
    }

    /// Whether nothing has gone out yet, in which case no reply can be one of
    /// ours.
    pub(super) fn nothing_sent(&self) -> bool {
        self.sent_at.is_empty()
    }

    /// When this next needs the loop's attention.
    pub(super) fn next_wakeup(&self) -> Option<Instant> {
        self.next_due.or_else(|| {
            self.last_sent_at
                .map(|sent_at| sent_at + SOLICITATION_WINDOW)
        })
    }
}

/// What a local sweep has asked the IPv6 half of its segment, and what it is
/// still waiting to hear back.
///
/// The scanner it belongs to builds and sends the frames.
pub(super) struct Ipv6Discovery {
    /// The all-nodes solicitation's schedule.
    solicitation: Solicitation,
    /// Outstanding per-address solicitations.
    ///
    /// Separate from ARP's ledger because the ledger keeps a round-trip
    /// estimate: mixing ARP's single-digit milliseconds with NDP's hundreds
    /// would mis-time whichever protocol answered less often.
    ledger: Ledger,
    /// Every address this sweep has put a solicitation on the wire for.
    ///
    /// Bounds [`note_overheard`](Self::note_overheard), so a neighbour
    /// advertising repeatedly earns one probe.
    solicited: HashSet<IpAddr>,
    /// Overheard addresses waiting to be asked about.
    ///
    /// Queued so a confirmation leaves through the same paced ticker as every
    /// other probe.
    confirming: VecDeque<IpAddr>,
    /// When each confirmation was sent, so its answer can be timed.
    ///
    /// Outside the [`Ledger`]: the host is already known to be there, so only
    /// the measurement is at stake, and a retry destroys it. On a live wifi
    /// segment a retry timer sized from ARP replies fired before every sleeping
    /// device answered.
    confirmed_at: HashMap<IpAddr, Instant>,
    /// When each address was *first* asked about.
    ///
    /// Diagnostic only: how long a neighbour actually takes to answer, which
    /// solicitation pacing depends on and host counts cannot reveal.
    first_asked_at: HashMap<IpAddr, Instant>,
}

impl Ipv6Discovery {
    /// State for a sweep expecting up to `capacity` outstanding solicitations.
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            solicitation: Solicitation::default(),
            ledger: Ledger::new(NDP_RETRY_POLICY, capacity),
            solicited: HashSet::new(),
            confirming: VecDeque::new(),
            confirmed_at: HashMap::new(),
            first_asked_at: HashMap::new(),
        }
    }

    /// The all-nodes solicitation's schedule, for the scanner that sends it.
    pub(super) fn solicitation(&self) -> &Solicitation {
        &self.solicitation
    }

    /// Makes the first all-nodes solicitation due now.
    pub(super) fn arm_solicitation(&mut self, now: Instant) {
        self.solicitation.arm(now);
    }

    /// Records one all-nodes solicitation going out and schedules the next.
    pub(super) fn record_solicitation_sent(&mut self, now: Instant) {
        self.solicitation.record_sent(now);
    }

    /// Takes an overheard address as a lead, returning whether it is a new one.
    ///
    /// A lead may be stale, so it is queued for one confirmation and reported
    /// only if it answers. `false` means the address is already spoken for and
    /// nothing was queued.
    pub(super) fn note_overheard(&mut self, address: IpAddr) -> bool {
        if !self.solicited.insert(address) {
            return false;
        }
        self.confirming.push_back(address);
        true
    }

    /// Whether this address has already had a solicitation put on the wire.
    pub(super) fn is_solicited(&self, address: &IpAddr) -> bool {
        self.solicited.contains(address)
    }

    /// The first overheard address owed a confirmation that `ready` allows,
    /// taken off the queue. Those it declines stay queued, in order.
    pub(super) fn next_confirmation(&mut self, ready: impl Fn(IpAddr) -> bool) -> Option<IpAddr> {
        let index = self.confirming.iter().position(|address| ready(*address))?;
        self.confirming.remove(index)
    }

    /// Puts back a confirmation that was taken and could not be sent, at the
    /// back of the queue, still owed.
    pub(super) fn requeue_confirmation(&mut self, address: IpAddr) {
        self.confirming.push_back(address);
    }

    /// Whether any address is still queued for its confirmation.
    pub(super) fn confirmations_pending(&self) -> bool {
        !self.confirming.is_empty()
    }

    /// Records that a confirmation went out, so its answer can be timed.
    pub(super) fn record_confirmation_sent(&mut self, address: IpAddr, now: Instant) {
        self.confirmed_at.insert(address, now);
    }

    /// The round trip for a confirmation `address` has just answered, if it was
    /// awaiting one.
    ///
    /// Unambiguous: an address gets exactly one confirmation.
    pub(super) fn take_confirmation_rtt(
        &mut self,
        address: &IpAddr,
        now: Instant,
    ) -> Option<Duration> {
        self.confirmed_at
            .remove(address)
            .map(|sent_at| now.saturating_duration_since(sent_at))
    }

    /// How many confirmations went out and were never answered.
    ///
    /// Separates "none were sent" from "none came back", which look identical
    /// in the host count.
    pub(super) fn unanswered_confirmations(&self) -> usize {
        self.confirmed_at.len()
    }

    /// Arms a per-address solicitation, noting when the address was first asked.
    ///
    /// Marks the address spoken for, so
    /// [`note_overheard`](Self::note_overheard) does not also queue a
    /// confirmation: the same packet twice makes the answer unattributable.
    pub(super) fn record_asked(&mut self, address: IpAddr, now: Instant) {
        self.solicited.insert(address);
        self.first_asked_at.entry(address).or_insert(now);
        self.ledger.arm(address, address, (), (), now);
    }

    /// Retires the solicitation for `address`, if one was outstanding.
    pub(super) fn resolve(&mut self, address: &IpAddr, now: Instant) -> Option<Resolution> {
        self.ledger.resolve(address, None, now)
    }

    /// The solicitation ledger, for the sweep that services both ledgers in
    /// one place. See
    /// [`HostSweep::service_second_ledger`](crate::scanner::strategy::sweep::HostSweep::service_second_ledger).
    pub(super) fn ledger_mut(&mut self) -> &mut Ledger {
        &mut self.ledger
    }

    /// How long ago `address` was first asked about, rendered for a log line, or
    /// nothing if it was never asked.
    ///
    /// A reply inside the first attempt's timeout could have been timed; one
    /// after it is a neighbour slower than the policy expects.
    pub(super) fn since_first_asked(&self, address: &IpAddr, now: Instant) -> String {
        match self.first_asked_at.get(address) {
            Some(asked) => format!(
                " ({}ms after it was first asked)",
                now.saturating_duration_since(*asked).as_millis()
            ),
            None => String::new(),
        }
    }

    /// Whether nothing is outstanding and no answer could still arrive.
    ///
    /// Includes the confirmation window, since a confirmation sits outside the
    /// ledger.
    pub(super) fn is_idle(&self, now: Instant) -> bool {
        self.confirming.is_empty()
            && self.ledger.is_empty()
            && !self.solicitation.window_open(now)
            && !self.confirmation_window_open(now)
    }

    /// Whether an answer to a confirmation could still legitimately arrive.
    ///
    /// Uses the all-nodes echo's window: a direct question does not wake a
    /// sleeping device any sooner.
    fn confirmation_window_open(&self, now: Instant) -> bool {
        self.confirmed_at
            .values()
            .any(|sent_at| now < *sent_at + SOLICITATION_WINDOW)
    }

    /// When this half of the sweep next needs the loop's attention.
    pub(super) fn next_wakeup(&self) -> Option<Instant> {
        let confirmation = self
            .confirmed_at
            .values()
            .map(|sent_at| *sent_at + SOLICITATION_WINDOW)
            .min();

        [
            self.ledger.next_due(),
            self.solicitation.next_wakeup(),
            confirmation,
        ]
        .into_iter()
        .flatten()
        .min()
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
    use crate::scanner::pacing::retry::ProbeLedger;

    /// The slowest answer to a first solicitation measured on a wireless
    /// segment, one address at a time. The schedule is sized from it.
    const SLOWEST_MEASURED_ANSWER: Duration = Duration::from_millis(408);

    /// The solicitation schedule outlasts the replies without the sweep paying
    /// for the slack.
    ///
    /// Too short, and the retransmit makes the round trip unattributable. Too
    /// long, and every sweep pays, because [`DEADLINE_CONFIG`] is widened to
    /// outlive the longest probe.
    #[test]
    fn the_solicitation_schedule_outlasts_the_replies_without_the_sweep_paying_for_it() {
        assert!(
            NDP_RETRY_POLICY.initial_rto > SLOWEST_MEASURED_ANSWER,
            "a first attempt must outlast the slowest answer measured, or the \
             retry lands first and Karn's rule discards the sample"
        );
        assert!(
            NDP_RETRY_POLICY.min_rto >= SLOWEST_MEASURED_ANSWER / 2,
            "the floor is the schedule for every neighbour with no measurement \
             of its own, so it cannot sit far below where the answers are"
        );
        assert!(
            NDP_RETRY_POLICY.worst_case_probe_lifetime() < Duration::from_secs(3),
            "the sweep's deadline is sized from this, so slack here is charged \
             to every scan whether or not any IPv6 neighbour is slow"
        );
    }

    /// A neighbour with no measurement of its own is timed by the policy, not
    /// by another neighbour's answer.
    ///
    /// Mains-powered and sleeping devices on one wireless link differ by orders
    /// of magnitude, so a scan-wide estimate describes neither.
    #[test]
    fn a_neighbours_schedule_is_not_inherited_from_a_faster_one() {
        let router: IpAddr = "fe80::1".parse().unwrap();
        let sleeper: IpAddr = "fe80::2".parse().unwrap();

        // The largest wait the floor could produce. At or below it, the
        // router's fast answer was applied to the sleeper.
        let floor = NDP_RETRY_POLICY
            .min_rto
            .mul_f64(1.0 + NDP_RETRY_POLICY.jitter);

        // Across seeds, because the schedule is jittered.
        for seed in [1, 0x5EED, 0xC0FFEE, u64::MAX] {
            let mut ledger: Ledger = ProbeLedger::seeded(NDP_RETRY_POLICY, 4, seed);
            let start = Instant::now();

            ledger.arm(router, router, (), (), start);
            ledger.resolve(&router, None, start + Duration::from_millis(5));

            ledger.arm(sleeper, sleeper, (), (), start);
            let due = ledger.next_due().expect("the sleeper has a timer");

            assert!(
                due.saturating_duration_since(start) > floor,
                "a router answering in 5 ms must not schedule the retry for a \
                 neighbour that has not answered at all (seed {seed})"
            );
            assert!(
                due.saturating_duration_since(start) > SLOWEST_MEASURED_ANSWER,
                "and the wait must still outlast the slowest answer measured \
                 (seed {seed})"
            );
        }
    }

    fn v6(last: u16) -> IpAddr {
        IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, last))
    }

    /// An address the sweep asks directly is never also queued for a
    /// confirmation. The same packet twice makes the answer unattributable, and
    /// the host is reported with no latency.
    #[test]
    fn an_address_asked_directly_is_never_also_confirmed() {
        let mut ipv6 = Ipv6Discovery::new(4);
        let target = v6(0xAA);

        ipv6.record_asked(target, Instant::now());

        assert!(
            !ipv6.note_overheard(target),
            "the address is already spoken for"
        );
        assert!(
            !ipv6.confirmations_pending(),
            "queueing a confirmation here sends a second identical solicitation"
        );
    }

    /// A neighbour advertising constantly earns one probe.
    #[test]
    fn an_overheard_address_is_confirmed_exactly_once() {
        let mut ipv6 = Ipv6Discovery::new(4);
        let neighbour = v6(0xBB);

        assert!(
            ipv6.note_overheard(neighbour),
            "the first sighting queues it"
        );
        for _ in 0..5 {
            assert!(
                !ipv6.note_overheard(neighbour),
                "every later sighting is the same address"
            );
        }

        assert_eq!(ipv6.next_confirmation(|_| true), Some(neighbour));
        assert_eq!(ipv6.next_confirmation(|_| true), None, "one probe, not six");
    }

    /// A confirmation yields its round trip once.
    #[test]
    fn a_confirmations_round_trip_is_taken_once() {
        let mut ipv6 = Ipv6Discovery::new(4);
        let neighbour = v6(0xCC);
        let sent = Instant::now();

        ipv6.record_confirmation_sent(neighbour, sent);

        let rtt = ipv6.take_confirmation_rtt(&neighbour, sent + Duration::from_millis(120));
        assert_eq!(rtt, Some(Duration::from_millis(120)));
        assert_eq!(
            ipv6.take_confirmation_rtt(&neighbour, sent + Duration::from_millis(300)),
            None,
            "the probe it measured is already resolved"
        );
    }

    /// A confirmation sits outside the ledger, so only its window holds the
    /// sweep open for the reply.
    #[test]
    fn a_sweep_is_not_idle_while_a_confirmation_could_still_be_answered() {
        let mut ipv6 = Ipv6Discovery::new(4);
        let sent = Instant::now();
        ipv6.record_confirmation_sent(v6(0xDD), sent);

        assert!(
            !ipv6.is_idle(sent + SOLICITATION_WINDOW / 2),
            "the answer is still within its window"
        );
        assert!(
            ipv6.is_idle(sent + SOLICITATION_WINDOW + Duration::from_millis(1)),
            "past the window there is nothing left to wait for"
        );
    }

    /// The loop sleeps until the earliest thing that needs attention, or the
    /// segment-wide probe goes out late.
    #[test]
    fn the_next_wakeup_is_the_earliest_of_the_three_schedules() {
        let mut ipv6 = Ipv6Discovery::new(4);
        let now = Instant::now();

        assert_eq!(ipv6.next_wakeup(), None, "nothing has been asked yet");

        ipv6.record_confirmation_sent(v6(0xEE), now);
        let confirmation_due = now + SOLICITATION_WINDOW;
        assert_eq!(ipv6.next_wakeup(), Some(confirmation_due));

        ipv6.arm_solicitation(now);
        assert_eq!(
            ipv6.next_wakeup(),
            Some(now),
            "a probe that is owed now outranks a window that closes later"
        );
    }
}
