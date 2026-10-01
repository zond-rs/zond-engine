// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What every probing sweep keeps track of
//!
//! The state three strategies carry in common: which probes are outstanding,
//! which are owed another attempt, which targets have answered, and what the run
//! will report about itself.
//!
//! [`local`](super::local) sweeps a segment, [`routed`](super::routed) sweeps
//! through a gateway, and [`identify::echo`](super::identify::echo) pings the
//! hosts nothing else could name. All three send a probe per target, retry it on
//! a schedule, and file an audit when they stop.
//!
//! Each keeps its own loop, unlike the port scanners'
//! [`ports::drive`](super::ports::drive), because they differ. A routed sweep
//! and the echo probe read
//! [`CapturedSegment`](crate::transport::capture::CapturedSegment)s off a
//! [`ProbeTransport`](crate::transport::probe::ProbeTransport); a local sweep
//! reads Ethernet frames off a link-layer channel, since ARP and neighbour
//! discovery have no IP layer to capture at. Their stop conditions differ too:
//! a routed sweep can finish on
//! [`AllResponded`](crate::report::StopReason::AllResponded) because it knows
//! its target count, the echo probe cannot because its hosts may answer no ping,
//! and only a local sweep lets silence end it, since its targets share a segment
//! and so an expected answer time.

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
/// Generic over the correlation token, as
/// [`RawProbeScan`](super::ports::RawProbeScan) is: an ARP request has nothing
/// on the wire to tell one attempt from the next and uses `()`, a SYN carries a
/// sequence number, and an echo request carries its own.
///
/// The [`ScanContext`] stays on the scanners and is passed to the two methods
/// that need it.
pub struct HostSweep<T> {
    /// Probes sent and not yet resolved, and the schedule they are repeated on.
    pub ledger: ProbeLedger<IpAddr, T>,
    /// Scratch for the probes coming due on one pass, reused so a quiet tick
    /// allocates nothing.
    pub due: Vec<Due<IpAddr>>,
    /// Targets owed another attempt, released by the sender ahead of anything
    /// unprobed.
    ///
    /// A retry is an obligation the sweep already owns; draining these first also
    /// keeps a retry from leaving long after its scheduled moment behind thousands
    /// of first attempts.
    ///
    /// Every address here has its probe's clock stopped on the ledger that
    /// scheduled it (see `ProbeLedger::defer`), so a retry held behind the send
    /// ticker or a host's probe gap is neither overtaken by the next attempt nor
    /// retired unsent. Whoever takes one owes that ledger either
    /// [`rearm`](ProbeLedger::rearm) once it has left, or `resume` when it did not.
    /// An address whose probe is no longer on its ledger was answered while it
    /// waited, and is dropped unsent.
    pub retries: VecDeque<IpAddr>,
    /// The targets *this sweep* has heard from.
    ///
    /// Kept here because [`write_host`](ScanContext::write_host) reports whether the
    /// **store** gained a host, and in a port-scan phase the host almost always
    /// exists already, so every answer would report "not new". The [`ProbeLedger`]
    /// cannot supply it either: an exhausted probe is drained out of it, and a
    /// reply arriving after that would go uncredited.
    pub responded: HashSet<IpAddr>,
    /// Per-run counters, so a sweep that finds fewer hosts than it should can be
    /// attributed to loss, to its own deadline, or to correlation.
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
    /// For a **sweep**, which asked whether an address is there: a spent budget
    /// turns silence into a verdict a resume may skip.
    /// [`service_retries_without_settling`](Self::service_retries_without_settling)
    /// is the other case.
    pub fn service_retries(&mut self, ctx: &ScanContext, now: Instant) {
        self.drain_into_retries(ctx, now, true);
    }

    /// [`service_retries`](Self::service_retries) for a probe that earns no
    /// address a verdict.
    ///
    /// For the probes that revisit hosts the scan has already found. A spent
    /// budget there means only that the host would not say what it runs, so
    /// settling would tell a resume that a probe covered an address it never asked
    /// about.
    pub fn service_retries_without_settling(&mut self, ctx: &ScanContext, now: Instant) {
        self.drain_into_retries(ctx, now, false);
    }

    fn drain_into_retries(&mut self, ctx: &ScanContext, now: Instant, settles: bool) {
        // Taken so the ledger can borrow `self` mutably; the buffer is reused.
        let mut due = std::mem::take(&mut self.due);
        self.ledger.drain_due(now, &mut due);
        defer_retries(&mut self.ledger, &due);
        self.absorb_due(ctx, &mut due, settles);
        self.due = due;
    }

    /// [`service_retries`](Self::service_retries) over a second ledger, for a
    /// sweep that runs two schedules at once.
    ///
    /// The local sweep retries ARP and neighbour discovery on separate policies,
    /// because a mains-powered router answers a solicitation in five milliseconds
    /// and a phone asleep on wifi takes four hundred.
    pub fn service_second_ledger<U: Copy + PartialEq>(
        &mut self,
        ctx: &ScanContext,
        other: &mut ProbeLedger<IpAddr, U>,
        now: Instant,
    ) {
        let settles = true;
        let mut due = std::mem::take(&mut self.due);
        other.drain_due(now, &mut due);
        defer_retries(other, &due);
        self.absorb_due(ctx, &mut due, settles);
        self.due = due;
    }

    /// Queues the retries and settles the exhausted, for whichever ledger
    /// produced them.
    fn absorb_due(&mut self, ctx: &ScanContext, due: &mut Vec<Due<IpAddr>>, settles: bool) {
        for event in due.drain(..) {
            match event {
                Due::Retry { key, .. } => self.retries.push_back(key),
                // A spent budget turns silence into a verdict. Only a probe that left is
                // armed, so nothing settled here went unasked.
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
    /// Sleeping past the ledger's deadline tick would leave a retry queued late by
    /// up to that tick.
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
    #[cfg(test)]
    pub fn note_answered(&mut self, target: IpAddr) -> bool {
        self.responded.insert(target)
    }

    /// Files what the run observed, to the log and to the report.
    ///
    /// The line is for somebody watching the scan, the record for whatever reads
    /// the report afterwards.
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

/// Stops the clock of every probe `due` schedules a retry for, on the ledger
/// that scheduled it, until the retry is sent or given up on. See
/// [`HostSweep::retries`].
fn defer_retries<U: Copy + PartialEq>(ledger: &mut ProbeLedger<IpAddr, U>, due: &[Due<IpAddr>]) {
    for event in due {
        if let Due::Retry { key, .. } = event {
            ledger.defer(key);
        }
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
        // The context holds every Arc that matters; nothing here reads events.
        (ctx, first)
    }

    /// A sweep's spent budget on a silent address settles it.
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

    /// The echo probe revisits hosts the scan already found, so a spent budget
    /// settles nothing: no probe of this plan asked about that position.
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

    /// A queued retry stops its probe's clock, on whichever ledger scheduled
    /// it, until it is sent or given up on.
    ///
    /// With the clock left running, a wait in the queue longer than the timeout
    /// would charge the next attempt, and the one after would retire the probe
    /// unsent: an address settled silent having been asked once.
    #[test]
    fn a_queued_retry_holds_its_probe_until_it_is_sent() {
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
        let mut second: ProbeLedger<IpAddr, ()> = ProbeLedger::new(policy, 4);
        let other: IpAddr = "127.0.0.2".parse().expect("an address");
        let now = Instant::now();
        sweep.ledger.arm(host, host, (), (), now);
        second.arm(other, other, (), (), now);

        // Due, and then left queued far longer than the whole schedule.
        for later in [Duration::from_millis(50), Duration::from_secs(3600)] {
            sweep.service_retries(&ctx, now + later);
            sweep.service_second_ledger(&ctx, &mut second, now + later);
        }

        assert_eq!(
            sweep.retries,
            [host, other],
            "each probe queued once, and neither charged again while it waited"
        );
        assert!(sweep.ledger.contains(&host) && second.contains(&other));
        assert_eq!(
            ctx.settlements().settled_count(),
            0,
            "an address whose retry never left has earned no verdict"
        );

        // Sent, the clock restarts from the send.
        let sent = now + Duration::from_secs(3601);
        sweep.ledger.rearm(host, host, (), sent);
        sweep.retries.pop_front();
        sweep.service_retries(&ctx, sent + Duration::from_millis(50));
        assert_eq!(
            sweep.retries,
            [other, host],
            "and the next attempt comes due"
        );
    }

    /// A probe with budget left is queued and settles nothing.
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

    /// The local sweep's case: a second schedule queues and settles through the
    /// same path as the first.
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

    /// The count a sweep stops on, kept apart from the store, which in a port
    /// scan's liveness pass almost always holds the host already.
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
