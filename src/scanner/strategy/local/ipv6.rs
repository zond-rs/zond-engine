// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Finding the IPv6 half of a segment
//!
//! IPv4 discovery walks a range: every address in it gets an ARP request, and
//! the ones that answer are the hosts. An IPv6 `/64` cannot be walked — there
//! are more addresses on one link than probes in a lifetime — so nothing about
//! the IPv4 half carries over. A neighbour is found here in one of three ways,
//! and each keeps its own state because each is answered on its own terms:
//!
//! - **The all-nodes solicitation.** One multicast echo the whole segment may
//!   answer. It is never retired by a reply, so it is repeated a fixed number of
//!   times and then listened for; and it is the only probe here that can be
//!   attributed, because an echo reply names the request it answers.
//! - **A solicitation put to one address**, for a neighbour whose address is
//!   already known — from the target list, the host's own neighbour table, or a
//!   lead overheard on the segment. Retransmitted through a ledger, on a
//!   schedule nothing like ARP's.
//! - **A confirmation**, the single solicitation an overheard address gets. Sent
//!   once and simply waited on.
//!
//! ## Why this is separate from the scanner that sends it
//!
//! What this module holds is *state and timing*: what has been asked, when, what
//! is still owed, and how long an answer could still legitimately arrive.
//! Building the frames and putting them on the wire stays in
//! [`LocalScanner`](super::LocalScanner), which owns the interface identity and
//! the channel.
//!
//! Drawing the line there is what makes any of this testable. Every decision
//! below is a function of a clock and a few collections, so it can be checked
//! directly — where the same logic reachable only through a scanner needs a
//! simulated Ethernet segment to ask a question about a timer.
//!
//! ## The rule that shapes all of it
//!
//! **Two solicitations for one address are identical on the wire.** An
//! advertisement carries no identifier, so a reply answering the second cannot
//! be told from one answering the first, and Karn's rule says an unattributable
//! sample must be discarded rather than guessed at. A round trip is therefore
//! measurable only when the *first* attempt is the one answered — which makes
//! every timeout here load-bearing in a way ARP's are not, and is why a
//! confirmation is sent exactly once and never retried.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::scanner::pacing::retry::{Due, ProbeLedger, Resolution, RetryPolicy};

/// Outstanding per-address solicitations and the schedule they are retried on.
///
/// The attempt token is `()`, for the reason the module documentation gives:
/// consecutive solicitations for one address are indistinguishable, so the
/// ledger applies Karn's rule and declines to measure what it cannot attribute.
type Ledger = ProbeLedger<IpAddr, ()>;

/// How a neighbor solicitation is retransmitted, which is nothing like how an
/// ARP request is.
///
/// The constraint that shapes this is Karn's rule. Two solicitations for one
/// address are identical on the wire and an advertisement carries no identifier,
/// so a reply answering the second cannot be told from one answering the first.
/// **A round trip is only measurable if the first attempt is the one answered**,
/// which makes the first timeout the load-bearing number: it has to outlast the
/// replies rather than merely be generous. The second attempt exists for a lost
/// probe and knowingly gives up the measurement to recover the host.
///
/// A separate ledger from ARP's, because the schedule is driven by a round-trip
/// estimate the ledger keeps: mixing ARP's single-digit milliseconds with an
/// IPv6 neighbour's hundreds pulls the estimate to whichever protocol answered
/// more often and mis-times the other.
///
/// Sizing it needs solicitations sent **one per address**, since any other kind
/// cannot say which attempt was answered. Measured that way on a wireless
/// segment (`benches/ndp_pace.rs`), neighbours answer in single-digit
/// milliseconds when mains-powered and up to roughly 400 ms when asleep, so
/// 800 ms covers the worst case with room to spare.
///
/// [`without_cross_host_estimate`](RetryPolicy::without_cross_host_estimate) is
/// what makes those numbers mean anything. Without it, one fast neighbour seeds
/// the scan-wide estimate, an unmeasured neighbour's first timeout is pulled
/// down to [`min_rto`](RetryPolicy::min_rto), and the floor silently becomes the
/// real schedule. A per-host estimate cannot fill the gap either: an address is
/// asked once per sweep, so its own estimate exists only after the probe it
/// would have timed has already resolved.
///
/// **Slack here is charged to every scan**, not just to a retransmit:
/// [`DEADLINE_CONFIG`] is widened to outlive the longest probe, so a first
/// timeout set too generously holds every sweep open whether or not any IPv6
/// neighbour is slow.
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
/// It is one packet standing in for the entire IPv6 half of a sweep: every
/// neighbour that has no address in the scanned IPv4 range is found through this
/// and nothing else. Sending it once made IPv6 discovery the only part of the
/// engine with no retransmission at all, and it showed - the IPv4 hosts of a
/// segment came back identically on every run while the IPv6-only ones came and
/// went.
pub(super) const SOLICITATION_ATTEMPTS: u8 = 3;

/// How long to leave between solicitations.
pub(super) const SOLICITATION_INTERVAL: Duration = Duration::from_millis(600);

/// How long after the final solicitation the sweep keeps listening.
///
/// Longer than a segment's round trip, because a neighbour answers a multicast
/// probe on a schedule of its own: implementations spread their replies to keep
/// the whole segment from answering at once, and a device asleep on wifi answers
/// when it next wakes. Observed on a live segment, replies land between roughly
/// 0.9 and 1.9 seconds after the request, varying by a second between runs for
/// the same host.
///
/// That figure was taken while the sweep was still broadcasting at full rate,
/// so part of it is congestion rather than the neighbour. It stands until the
/// echo's own timing says otherwise, which is now recorded rather than
/// guessed at, since a reply names the request it answers. Erring long costs
/// the tail of a sweep; erring short discards a host that did answer.
pub(super) const SOLICITATION_WINDOW: Duration = Duration::from_millis(1_500);

/// The all-nodes solicitation's schedule: which requests have gone out and
/// when, when the next is owed, and how long the last one is still worth
/// waiting on.
///
/// Kept separately from the [`Ledger`] rather than as an entry in it, because it
/// is a different kind of thing. Every other probe is a question put to one
/// address, answered once, and retired by that answer. This is a question put to
/// the whole segment: no single reply resolves it, no reply means the next one
/// is not coming, and there is nothing to give up on.
///
/// It is nonetheless *timed*, which the per-address solicitation is not. An echo
/// reply carries back the identifier and sequence number of the request it
/// answers, so a neighbour's reply names which of these probes it belongs to
/// however many have gone out. That is why every attempt's send time is kept
/// rather than only the most recent: on a segment where one device answers in
/// six milliseconds and another wakes two requests later, measuring against the
/// wrong request reports the neighbour's sleep schedule as latency.
#[derive(Debug)]
pub(super) struct Solicitation {
    /// Identifies this scan's echo requests, so somebody else's ping is not
    /// mistaken for an answer to ours. One value for the whole run: the
    /// sequence number is what separates the attempts.
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
    /// A foreign identifier belongs to somebody else's ping, and a sequence
    /// beyond what has been sent is not ours either. Both come back unmeasured
    /// rather than rejected: the frame still arrived carrying a neighbour's own
    /// MAC, which proves the neighbour is there whatever provoked it.
    pub(super) fn sent_at(&self, identifier: u16, sequence: u16) -> Option<Instant> {
        if identifier != self.identifier {
            return None;
        }
        self.sent_at.get(sequence as usize).copied()
    }

    /// Makes the first request due now.
    ///
    /// Kept apart from construction so a run that must not sweep the segment -
    /// or has no link-local address to ask from - simply never arms this and
    /// never owes a probe, rather than carrying a schedule that has to be
    /// checked against the scope everywhere it is read.
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
/// Holds the state and answers the timing questions; the scanner it belongs to
/// builds the frames and sends them. Every method here is a function of a clock
/// and these collections, which is what lets the schedule be checked without a
/// segment to run it against.
pub(super) struct Ipv6Discovery {
    /// The all-nodes solicitation's own schedule, which every IPv6-only
    /// neighbour on the segment is found through.
    solicitation: Solicitation,
    /// Outstanding per-address solicitations, on their own schedule.
    ///
    /// A separate ledger from ARP's rather than a separate policy inside one,
    /// because the retry timing is driven by a round-trip estimate the ledger
    /// keeps: mixing ARP's single-digit milliseconds with NDP's hundreds would
    /// pull the shared estimate to whichever protocol answered more often and
    /// mis-time the other.
    ledger: Ledger,
    /// Every address this sweep has put a solicitation on the wire for.
    ///
    /// Bounds [`note_overheard`](Self::note_overheard): a neighbour may advertise
    /// an address many times over a scan, and without this each advertisement
    /// would earn it another probe.
    solicited: HashSet<IpAddr>,
    /// Overheard addresses waiting to be asked about.
    ///
    /// Queued rather than sent on the spot so a confirmation leaves through the
    /// same paced ticker every other probe does.
    confirming: VecDeque<IpAddr>,
    /// When each confirmation was sent, so its answer can be timed.
    ///
    /// Deliberately outside the [`Ledger`], which exists to decide when to give
    /// up on an address nobody has answered for. A confirmation asks a different
    /// question: the host is already known to be there, so the only thing at
    /// stake is the measurement, and a retry destroys exactly that. Measured on a
    /// live segment, that is what happened to every neighbour on wifi — the retry
    /// timer, sized from ARP replies arriving in single-digit milliseconds, fired
    /// long before a sleeping device got round to answering.
    confirmed_at: HashMap<IpAddr, Instant>,
    /// When each address was *first* asked about.
    ///
    /// Diagnostic only, and kept because the number it yields is the one thing
    /// that cannot be reasoned out from the outside: how long a neighbour
    /// actually takes to answer. Everything about pacing solicitation depends on
    /// it, and three rounds of inference from host counts got it wrong before a
    /// packet capture settled it.
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
    /// A lead is a claim somebody else made, possibly some time ago and possibly
    /// about an address that has since moved. It earns its place in the report
    /// the same way a neighbour-table entry does — by answering a solicitation
    /// now — so it is queued for one confirmation rather than recorded as a host.
    ///
    /// `false` means the address is already spoken for and nothing was queued.
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

    /// The next overheard address owed a confirmation.
    pub(super) fn next_confirmation(&mut self) -> Option<IpAddr> {
        self.confirming.pop_front()
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
    /// Unambiguous where a retried probe's would not be: an address gets exactly
    /// one confirmation, so an advertisement answering it can only be answering
    /// that one.
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
    /// Worth reporting because "none were sent" and "none came back" look
    /// identical from the host count, and they are the difference between a bug
    /// here and a segment full of devices that decline to answer a direct
    /// question.
    pub(super) fn unanswered_confirmations(&self) -> usize {
        self.confirmed_at.len()
    }

    /// Arms a per-address solicitation, noting when the address was first asked.
    ///
    /// Marks the address spoken for, which is what stops
    /// [`note_overheard`](Self::note_overheard) queueing a *confirmation* for an
    /// address this sweep is already asking about directly. The two are the same
    /// packet on the wire, and sending both makes the answer unattributable —
    /// exactly the sample Karn's rule then discards.
    pub(super) fn record_asked(&mut self, address: IpAddr, now: Instant) {
        self.solicited.insert(address);
        self.first_asked_at.entry(address).or_insert(now);
        self.ledger.arm(address, address, (), (), now);
    }

    /// Retires the solicitation for `address`, if one was outstanding.
    pub(super) fn resolve(&mut self, address: &IpAddr, now: Instant) -> Option<Resolution> {
        self.ledger.resolve(address, None, now)
    }

    /// Moves everything due into `buf`, which the caller drains.
    pub(super) fn drain_due(&mut self, now: Instant, buf: &mut Vec<Due<IpAddr>>) {
        self.ledger.drain_due(now, buf);
    }

    /// How long ago `address` was first asked about, rendered for a log line, or
    /// nothing if it was never asked.
    ///
    /// The measurement that decides how solicitation should be paced. A reply
    /// arriving inside the first attempt's timeout is one the schedule could have
    /// timed; one arriving after it is a neighbour genuinely slower than the
    /// policy expects, and the two call for different changes.
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
    /// The confirmation window is checked as well as the ledger, and that is the
    /// point of having it: a confirmation sits outside the ledger, so without
    /// this the sweep would send a solicitation and immediately stop listening
    /// for its reply, which is a strange thing to spend a packet on.
    pub(super) fn is_idle(&self, now: Instant) -> bool {
        self.confirming.is_empty()
            && self.ledger.is_empty()
            && !self.solicitation.window_open(now)
            && !self.confirmation_window_open(now)
    }

    /// Whether an answer to a confirmation could still legitimately arrive.
    ///
    /// The window is the one the all-nodes echo already uses, for the same
    /// reason and on the same evidence: a neighbour answers when it next wakes,
    /// and on this segment that was measured at up to one and a half seconds. A
    /// direct question does not make a sleeping device answer any sooner.
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

    /// The slowest answer to a *first* solicitation measured on a wireless
    /// segment, asking one address at a time so the attribution is certain
    /// (`benches/ndp_pace.rs`). The schedule is sized from it, so it is stated
    /// once here rather than left implied by the constants.
    const SLOWEST_MEASURED_ANSWER: Duration = Duration::from_millis(408);

    /// The solicitation schedule has to outlast the replies without the sweep
    /// paying for the slack, and both halves of that are easy to lose.
    ///
    /// Too short and a first attempt is retransmitted before the neighbour
    /// could have answered, which does not merely waste a packet: two
    /// solicitations are identical on the wire, so the round trip is discarded
    /// rather than delayed. Too long and every sweep pays for it, because
    /// [`DEADLINE_CONFIG`] is widened to outlive the longest probe whether or
    /// not any IPv6 neighbour turns out to be slow.
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

    /// A neighbour with no measurement of its own must be timed by the policy,
    /// never by what some other neighbour on the segment answered in.
    ///
    /// The two populations on one wireless link differ by orders of magnitude —
    /// a mains-powered device against a sleeping one — so a scan-wide estimate
    /// describes neither, and inheriting the fast one silently replaces the
    /// declared schedule with the floor.
    #[test]
    fn a_neighbours_schedule_is_not_inherited_from_a_faster_one() {
        let router: IpAddr = "fe80::1".parse().unwrap();
        let sleeper: IpAddr = "fe80::2".parse().unwrap();

        // The largest wait the floor could ever produce. Anything at or below
        // it means the scan's own fast answer was applied to a neighbour that
        // has told it nothing, which is the whole defect.
        let floor = NDP_RETRY_POLICY
            .min_rto
            .mul_f64(1.0 + NDP_RETRY_POLICY.jitter);

        // Across seeds, because the schedule is jittered and one draw is not
        // evidence about the rule.
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

    /// An address the sweep is already asking about directly must never also be
    /// queued for a confirmation.
    ///
    /// The two are the same packet on the wire. Sending both means the
    /// advertisement that comes back cannot say which it answers, so Karn's rule
    /// discards the sample - and the host is reported with no latency beside it,
    /// which looks exactly like a neighbour that was never timed rather than one
    /// that was asked twice.
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

    /// A neighbour advertises constantly. Each advertisement must not earn it
    /// another probe.
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

        assert_eq!(ipv6.next_confirmation(), Some(neighbour));
        assert_eq!(ipv6.next_confirmation(), None, "one probe, not six");
    }

    /// A confirmation yields its round trip once. A second advertisement from
    /// the same neighbour is not a second measurement of the same probe.
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

    /// A confirmation sits outside the ledger, so nothing else holds the sweep
    /// open for its reply. Stopping while one could still arrive is spending a
    /// packet and then declining to listen for the answer.
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

    /// The loop sleeps until the *earliest* thing that needs attention. Taking
    /// any later one oversleeps whichever schedule was due first, and on the
    /// solicitation that means the segment-wide probe goes out late.
    #[test]
    fn the_next_wakeup_is_the_earliest_of_the_three_schedules() {
        let mut ipv6 = Ipv6Discovery::new(4);
        let now = Instant::now();

        assert_eq!(ipv6.next_wakeup(), None, "nothing has been asked yet");

        ipv6.record_confirmation_sent(v6(0xEE), now);
        let confirmation_due = now + SOLICITATION_WINDOW;
        assert_eq!(ipv6.next_wakeup(), Some(confirmation_due));

        // An armed solicitation is owed immediately, which is earlier than any
        // window that has just opened.
        ipv6.arm_solicitation(now);
        assert_eq!(
            ipv6.next_wakeup(),
            Some(now),
            "a probe that is owed now outranks a window that closes later"
        );
    }
}
