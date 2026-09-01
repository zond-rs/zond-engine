// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What every probing sweep keeps track of
//!
//! The state three strategies carry in common and the bookkeeping that goes
//! with it: which probes are outstanding, which are owed another attempt, which
//! targets have answered, and what the run is going to report about itself.
//!
//! [`local`](super::local) sweeps a segment, [`routed`](super::routed) sweeps
//! through a gateway, and [`identify::echo`](super::identify::echo) pings the
//! hosts nothing else could name. All three send a probe per target, retry it on
//! a schedule, and file an audit when they stop.
//!
//! ## Why the loop is not here, when [`ports::drive`](super::ports::drive) is
//!
//! Because these three are not identical and the port scanners were, which is
//! the same test `ports` applied to itself: share where two things are the same,
//! not where they resemble each other.
//!
//! The receive source is the difference that settles it. A routed sweep and the
//! echo probe both read [`CapturedSegment`](crate::transport::capture::CapturedSegment)s
//! off a [`ProbeTransport`](crate::transport::probe::ProbeTransport); a local
//! sweep reads Ethernet frames off a link-layer channel, because ARP and
//! neighbour discovery have no IP layer to be captured at. One `select!` cannot
//! await both without the receive type becoming a further parameter, and a loop
//! generic over what it receives is a loop that has stopped describing anything.
//!
//! Their stop conditions differ too, and honestly. A routed sweep can finish
//! early on [`AllResponded`](crate::report::StopReason::AllResponded) because it
//! knows how many addresses it was given; the echo probe cannot, because the
//! hosts it was handed may answer no ping at all and that is an ordinary result.
//! A local sweep is the only one that lets *silence* end it, since it is the
//! only one whose targets share a segment and so a common expectation of how
//! fast an answer arrives.
//!
//! What is here is everything underneath that: three copies of `service_retries`
//! that had already begun to say one thing in two wordings, three
//! calculations of how long to sleep, and three audit tails.

use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::journal::settle::Settled;
use crate::model::capture::CaptureCounts;
use crate::report::{ScannerKind, StopReason};
use crate::scanner::audit::ProbeAudit;
use crate::scanner::pacing::deadline::AdaptiveDeadline;
use crate::scanner::pacing::retry::{Due, ProbeLedger};
use crate::scanner::session::ScanContext;

/// The outstanding probes of one sweep, what it has heard, and what it will
/// report.
///
/// Generic over the correlation token for the reason
/// [`RawProbeScan`](super::ports::RawProbeScan) is: an ARP request has nothing
/// on the wire to tell one attempt from the next and uses `()`, a SYN carries a
/// sequence number, and an echo request carries its own.
///
/// The [`ScanContext`] is *not* held here and is passed to the two methods that
/// need one. It is already a field on all three scanners and used on nearly
/// every line of them, so moving it would have turned `self.ctx` into
/// `self.sweep.ctx` throughout for no gain: this type exists to hold the
/// bookkeeping nobody reads directly, not to become the scanner.
pub struct HostSweep<T> {
    /// Probes sent and not yet resolved, and the schedule they are repeated on.
    pub ledger: ProbeLedger<IpAddr, T>,
    /// Scratch for the probes coming due on one pass, reused so a quiet tick
    /// allocates nothing.
    pub due: Vec<Due<IpAddr>>,
    /// Targets owed another attempt, released by the sender ahead of anything
    /// unprobed.
    ///
    /// A retry is an obligation the sweep already owns, where the next unprobed
    /// address is only work it intends to do. Draining these first is also what
    /// keeps the schedule honest: a retry queued behind thousands of first
    /// attempts would leave long after the moment it was scheduled for.
    pub retries: VecDeque<IpAddr>,
    /// The targets *this sweep* has heard from.
    ///
    /// A set rather than a counter, and kept here rather than read off the
    /// store, because the two answer different questions.
    /// [`write_host`](ScanContext::write_host) reports whether the **store**
    /// gained a host, which in a discovery-only phase is the same thing and in a
    /// port-scan phase is not: discovery runs there as enrichment beside the
    /// port scanner, the host almost always exists already, and every one of
    /// this sweep's own answers would report "not new".
    ///
    /// Not taken from the [`ProbeLedger`] either, though it is the obvious
    /// source. `resolve` retires a probe, so a duplicate reply correctly reports
    /// nothing, but an exhausted probe is drained out of the ledger entirely and
    /// a reply arriving after that would go uncredited.
    pub responded: HashSet<IpAddr>,
    /// Per-run counters, so a sweep that finds fewer hosts than it should can be
    /// attributed to loss, to its own deadline, or to correlation rather than
    /// guessed at.
    pub audit: ProbeAudit,
}

impl<T: Copy + PartialEq> HostSweep<T> {
    /// An empty sweep running `ledger`'s schedule.
    pub fn new(ledger: ProbeLedger<IpAddr, T>) -> Self {
        Self {
            ledger,
            due: Vec::new(),
            retries: VecDeque::new(),
            responded: HashSet::new(),
            audit: ProbeAudit::new(),
        }
    }

    /// Moves every probe whose timer has fired onto the retry queue, and
    /// settles the ones that have run out of attempts.
    ///
    /// For a **sweep**, which was asked whether an address is there and has now
    /// asked as many times as the policy allows: a spent budget is the moment
    /// silence stops being provisional and becomes a verdict a resume may skip.
    /// [`service_retries_without_settling`](Self::service_retries_without_settling)
    /// is the other case, and they are two methods rather than one taking a
    /// flag because a bare `true` at a call site says nothing about which of
    /// the two a reader is looking at.
    ///
    /// Written once because it was written three times, and two of those had
    /// already drifted into stating one claim about the ledger in two different
    /// wordings.
    pub fn service_retries(&mut self, ctx: &ScanContext, now: Instant) {
        self.drain_into_retries(ctx, now, true);
    }

    /// [`service_retries`](Self::service_retries) for a probe that earns no
    /// address a verdict.
    ///
    /// For the probes that revisit hosts the scan has already found. A spent
    /// budget there means only that the host would not say what it runs, which
    /// is not an answer to the question the plan is counted in, and marking a
    /// position for it would tell a resume that an address had been covered by
    /// a probe that never asked.
    pub fn service_retries_without_settling(&mut self, ctx: &ScanContext, now: Instant) {
        self.drain_into_retries(ctx, now, false);
    }

    fn drain_into_retries(&mut self, ctx: &ScanContext, now: Instant, settles: bool) {
        // Taken so the ledger can borrow `self` mutably; the buffer itself is
        // reused, so this costs no allocation.
        let mut due = std::mem::take(&mut self.due);
        self.ledger.drain_due(now, &mut due);
        self.absorb_due(ctx, &mut due, settles);
        self.due = due;
    }

    /// [`service_retries`](Self::service_retries) over a second ledger, for a
    /// sweep that runs two schedules at once.
    ///
    /// The local sweep is the one: ARP and neighbour discovery are retried on
    /// their own policies, because a mains-powered router answers a
    /// solicitation in five milliseconds and a phone asleep on wifi takes four
    /// hundred.
    pub fn service_second_ledger<U: Copy + PartialEq>(
        &mut self,
        ctx: &ScanContext,
        other: &mut ProbeLedger<IpAddr, U>,
        now: Instant,
    ) {
        let settles = true;
        let mut due = std::mem::take(&mut self.due);
        other.drain_due(now, &mut due);
        self.absorb_due(ctx, &mut due, settles);
        self.due = due;
    }

    /// Queues the retries and settles the exhausted, for whichever ledger
    /// produced them.
    fn absorb_due(&mut self, ctx: &ScanContext, due: &mut Vec<Due<IpAddr>>, settles: bool) {
        for event in due.drain(..) {
            match event {
                Due::Retry { key, .. } => self.retries.push_back(key),
                // The budget is spent, which is the moment silence stops being
                // provisional and becomes a verdict the sweep earned. Only a
                // probe that actually left is armed, so nothing settled here
                // went unasked.
                Due::Exhausted { key, .. } => {
                    if settles {
                        ctx.settle_address(key, Settled::Exhausted);
                    }
                }
            }
        }
    }

    /// How long the loop may sleep while it has nothing to send: until the
    /// deadline wants looking at again, or until the next probe is due,
    /// whichever comes first.
    ///
    /// The ledger's deadline is the one that matters here. Sleeping past it
    /// would leave a retry queued late by however long the deadline's own tick
    /// happened to be.
    pub fn idle_delay(&self, deadline: &AdaptiveDeadline, now: Instant) -> Duration {
        let until_deadline_tick = deadline.time_until_next_tick();
        match self.ledger.next_due() {
            Some(due) => until_deadline_tick.min(due.saturating_duration_since(now)),
            None => until_deadline_tick,
        }
    }

    /// Whether every target has been heard from, given how many there were.
    pub fn all_responded(&self, target_count: u128) -> bool {
        self.responded.len() as u128 >= target_count
    }

    /// Records that `target` answered, reporting whether this sweep had heard
    /// from it before.
    pub fn note_answered(&mut self, target: IpAddr) -> bool {
        self.responded.insert(target)
    }

    /// Files what the run observed, to the log and to the report.
    ///
    /// Both, and in that order, because they answer to different readers: the
    /// line is for somebody watching a scan, and the record is for whatever
    /// computes against the report afterwards. Three scanners wrote this pair
    /// out by hand and one of them passed a bare string where the other two had
    /// a label.
    pub fn report(
        &mut self,
        ctx: &ScanContext,
        label: &str,
        kind: ScannerKind,
        targets: u128,
        reason: StopReason,
        capture: Option<CaptureCounts>,
    ) {
        self.audit.report(label, targets, reason, capture, None);
        ctx.record_probe_stats(self.audit.stats(kind, targets, reason, capture, None));
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
    use crate::journal::settle::Outcome;
    use crate::model::ip::set::IpSet;
    use crate::scanner::pacing::retry::RetryPolicy;
    use crate::scanner::session::ScanSession;
    use std::str::FromStr;

    /// One attempt, so a probe exhausts the moment its first timeout fires.
    const ONE_SHOT: RetryPolicy = RetryPolicy::new(
        1,
        Duration::from_millis(10),
        Duration::from_millis(1),
        Duration::from_millis(20),
        1.0,
        0.0,
        None,
    );

    /// A context numbering `written`, so an exhausted probe has a position to
    /// settle at.
    fn counting(written: &str) -> (crate::scanner::session::ScanContext, IpAddr) {
        let plan = IpSet::from_str(written).expect("a range");
        let first = plan.iter().next().expect("at least one address");
        let (_session, ctx) = ScanSession::builder().counting(plan.positions()).build();
        // The session is dropped; the context holds every Arc that matters and
        // nothing here reads the event stream.
        (ctx, first)
    }

    /// The verdict a sweep earns. Its budget is spent and the address answered
    /// nothing, which is the moment silence stops being provisional.
    #[test]
    fn an_exhausted_probe_settles_the_address_when_the_sweep_settles() {
        let (ctx, host) = counting("127.0.0.1");
        let mut sweep: HostSweep<()> = HostSweep::new(ProbeLedger::new(ONE_SHOT, 4));
        let now = Instant::now();

        sweep.ledger.arm(host, host, (), (), now);
        sweep.service_retries(&ctx, now + Duration::from_millis(50));

        assert_eq!(
            ctx.settlements().count(Outcome::Answered { position: 0 }),
            0
        );
        assert_eq!(
            ctx.settlements().checkpoint().watermark,
            1,
            "the one position in the plan, earned by a spent budget"
        );
    }

    /// The echo probe's contract, and the reason there are two names. It revisits
    /// hosts the scan already found, so a spent budget means only that the host
    /// would not say what it runs. Settling there would mark a position no
    /// probe of this plan had asked about.
    #[test]
    fn an_exhausted_probe_settles_nothing_when_the_sweep_does_not() {
        let (ctx, host) = counting("127.0.0.1");
        let mut sweep: HostSweep<()> = HostSweep::new(ProbeLedger::new(ONE_SHOT, 4));
        let now = Instant::now();

        sweep.ledger.arm(host, host, (), (), now);
        sweep.service_retries_without_settling(&ctx, now + Duration::from_millis(50));

        assert_eq!(
            ctx.settlements().checkpoint().watermark,
            0,
            "nothing was earned, so nothing is skipped on a resume"
        );
        assert_eq!(ctx.settlements().settled_count(), 0);
    }

    /// A probe with budget left goes back on the queue instead, and settles
    /// nothing: silence is still provisional while an attempt is owed.
    #[test]
    fn a_probe_with_budget_left_is_queued_rather_than_settled() {
        let (ctx, host) = counting("127.0.0.1");
        let policy = RetryPolicy::new(
            3,
            Duration::from_millis(10),
            Duration::from_millis(1),
            Duration::from_millis(20),
            1.0,
            0.0,
            None,
        );
        let mut sweep: HostSweep<()> = HostSweep::new(ProbeLedger::new(policy, 4));
        let now = Instant::now();

        sweep.ledger.arm(host, host, (), (), now);
        sweep.service_retries(&ctx, now + Duration::from_millis(50));

        assert_eq!(sweep.retries.front(), Some(&host), "owed another attempt");
        assert_eq!(ctx.settlements().settled_count(), 0);
    }

    /// The local sweep's case: two schedules over one link, because a
    /// mains-powered router answers a solicitation in five milliseconds and a
    /// phone asleep on wifi takes four hundred. Both must reach the same
    /// queueing and the same settling, which is what this asserts and what
    /// three separate copies of the loop could not.
    #[test]
    fn a_second_ledger_queues_and_settles_through_the_same_path() {
        let (ctx, host) = counting("127.0.0.1");
        let mut sweep: HostSweep<()> = HostSweep::new(ProbeLedger::new(ONE_SHOT, 4));
        let mut other: ProbeLedger<IpAddr, ()> = ProbeLedger::new(ONE_SHOT, 4);
        let now = Instant::now();

        other.arm(host, host, (), (), now);
        sweep.service_second_ledger(&ctx, &mut other, now + Duration::from_millis(50));

        assert_eq!(
            ctx.settlements().checkpoint().watermark,
            1,
            "the second schedule settles exactly as the first does"
        );
    }

    /// The count a sweep stops on. Kept here rather than read off the store,
    /// because in a port scan's liveness pass the store almost always holds the
    /// host already and every one of this sweep's own answers would report
    /// "not new".
    #[test]
    fn a_sweep_knows_when_every_target_has_answered() {
        let mut sweep: HostSweep<()> = HostSweep::new(ProbeLedger::new(ONE_SHOT, 4));
        let one: IpAddr = "192.0.2.1".parse().expect("literal");
        let two: IpAddr = "192.0.2.2".parse().expect("literal");

        assert!(sweep.note_answered(one), "the first sighting is news");
        assert!(!sweep.note_answered(one), "the second is not");
        assert!(!sweep.all_responded(2));

        sweep.note_answered(two);
        assert!(sweep.all_responded(2));
    }
}
