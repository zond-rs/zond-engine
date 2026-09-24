// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Stopping a scan
//!
//! One flag, one deadline, and the reading of both. A scan spawns strategies
//! that outlive the call that started them, so something has to reach across
//! into all of them at once, and that something has to be cheap enough to read
//! on every pass of every probing loop.
//!
//! [`ScanHandle`] is that reach. Everything else about stopping a scan follows
//! from what it is not: it does not cancel tasks, it does not discard findings,
//! and it cannot be undone. The type's own documentation has the argument for
//! each.
//!
//! ## Two ways a scan stops early, and why they are one type
//!
//! A caller can ask for it, and a caller-set wall-clock budget can run out. Both
//! wind the same strategies down through the same check, so both live here, and
//! [`StopCause`] is what keeps them apart afterwards. A report that called an
//! expired budget an abort would say somebody stopped a scan that stopped
//! itself, which is a claim about a person that nothing observed.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::report::StopReason;
use crate::scanner::pacing::timer::later;

/// Why a scan is winding down.
///
/// Answered by [`ScanHandle::stopped`], and read by the probing loops to name
/// their own stop. Not a verdict about the findings: a scan stopped either way
/// keeps what it had already learned.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopCause {
    /// The caller asked the scan to stop, through [`ScanHandle::abort`].
    Aborted,
    /// The wall-clock budget the scan was given ran out. See
    /// [`ZondConfig::scan_timeout`](crate::config::ZondConfig::scan_timeout).
    TimedOut,
}

/// The means to stop a running scan, and the budget that stops it unasked.
///
/// One flag and one deadline, shared by every strategy a scan spawned. Each of
/// them reads this on every pass of its own loop rather than only between
/// targets, so a scan of a large range stops promptly instead of after the
/// address it is on.
///
/// Stopping is not cancelling. The scan winds down and still produces its
/// [`ScanReport`](crate::report::ScanReport), describing however far it
/// got: the hosts already found are findings, and discarding them because the
/// caller ran out of patience would throw away the work the scan had done. The
/// report's [`StopReason`] says which of the two stops happened, so nobody
/// mistakes a shortened scan for a complete one.
///
/// Cloneable and shareable: the copy on a [`ScanSession`](crate::scanner::session::ScanSession)
/// and the copies held by the strategies are the same flag and the same
/// deadline.
#[derive(Debug, Clone)]
pub struct ScanHandle {
    stop: Arc<Stop>,
}

/// The shared half: what every clone of a handle reads.
#[derive(Debug)]
struct Stop {
    aborted: AtomicBool,
    /// When this scan's own budget runs out, for one that was given a budget.
    ///
    /// An [`Instant`] rather than a [`Duration`] and a start, so a reader does
    /// no arithmetic and nothing has to agree about when the scan began.
    /// Monotonic, so a clock stepped mid-scan cannot end one early or leave one
    /// running.
    deadline: Option<Instant>,
}

impl Default for ScanHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanHandle {
    /// A handle for a scan with no budget, which stops only when asked.
    pub fn new() -> Self {
        Self::bounded(None)
    }

    /// A handle for a scan that stops on its own after `budget`, and `None` for
    /// one that does not.
    ///
    /// The clock starts here, which is where the scan is assembled, so the
    /// budget covers the whole call rather than the probing part of it.
    pub fn bounded(budget: Option<Duration>) -> Self {
        let deadline = budget.map(|budget| later(Instant::now(), budget));
        Self {
            stop: Arc::new(Stop {
                aborted: AtomicBool::new(false),
                deadline,
            }),
        }
    }

    /// Asks the scan to stop.
    ///
    /// Returns immediately; the strategies notice on their next pass. Await the
    /// [`ScanTask`](crate::scanner::ScanTask) to know when they have all
    /// finished and to collect the report.
    ///
    /// Idempotent, and there is no way to undo it. A scan that
    /// resumed after being stopped would have a gap in the middle that nothing
    /// in the report could describe.
    pub fn abort(&self) {
        self.stop.aborted.store(true, Ordering::SeqCst);
    }

    /// Whether the scan has been asked to stop, or has outlived its budget.
    ///
    /// Every probing loop in the engine calls this each time round. A scan with
    /// no budget reads one atomic and nothing else.
    pub fn should_stop(&self) -> bool {
        self.stopped().is_some()
    }

    /// Why the scan is stopping, or `None` while it is still running.
    ///
    /// The budget is read first. A scan whose budget expired was going to stop
    /// whatever the caller did next, so an abort arriving after the fact does
    /// not rename what happened; the other order would report a scheduled scan
    /// as one somebody interrupted.
    pub fn stopped(&self) -> Option<StopCause> {
        if self
            .stop
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Some(StopCause::TimedOut);
        }
        if self.stop.aborted.load(Ordering::SeqCst) {
            return Some(StopCause::Aborted);
        }
        None
    }

    /// When this scan's budget runs out, or `None` for a scan without one.
    ///
    /// The clock starts inside the call that assembles the scan, so a caller
    /// holding the budget it asked for still cannot say when the scan will
    /// stop. This is that answer, for a front end showing how long is left.
    pub fn deadline(&self) -> Option<Instant> {
        self.stop.deadline
    }
}

impl From<StopCause> for StopReason {
    /// What the shared stop signal means to a scanner writing down why it
    /// stopped.
    ///
    /// Here rather than beside [`StopReason`] because a report knows nothing
    /// about a running scan, and here rather than at each probing loop because
    /// the several that read the signal must not disagree about what an expired
    /// budget is called.
    fn from(cause: StopCause) -> Self {
        match cause {
            StopCause::Aborted => StopReason::Aborted,
            StopCause::TimedOut => StopReason::TimedOut,
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

    /// The behaviour every scan had before there was a budget, unchanged.
    #[test]
    fn a_handle_with_no_budget_stops_only_when_asked() {
        let handle = ScanHandle::new();
        assert_eq!(handle.stopped(), None);
        handle.abort();
        assert_eq!(handle.stopped(), Some(StopCause::Aborted));
    }

    /// What the budget is for: a scan that stops with nobody watching it.
    #[test]
    fn an_expired_budget_stops_a_scan_nobody_touched() {
        let handle = ScanHandle::bounded(Some(Duration::ZERO));
        assert_eq!(handle.stopped(), Some(StopCause::TimedOut));
        assert!(handle.should_stop());
    }

    /// A budget that has not run out yet leaves the scan running, and the
    /// clones read the same deadline.
    #[test]
    fn a_budget_still_running_stops_nothing() {
        let handle = ScanHandle::bounded(Some(Duration::from_secs(3600)));
        let clone = handle.clone();
        assert_eq!(handle.stopped(), None);
        assert_eq!(clone.deadline(), handle.deadline());
    }

    /// The longest budget a caller can write is a scan that runs until it is
    /// stopped, not a panic: `Duration::MAX` is past what a clock can count
    /// to from now.
    #[test]
    fn the_longest_budget_is_one_that_never_runs_out() {
        let handle = ScanHandle::bounded(Some(Duration::MAX));
        assert_eq!(handle.stopped(), None);
        assert!(handle.deadline().is_some());
    }

    /// An abort that arrives after the budget expired does not rename what
    /// happened. The scan had already stopped.
    #[test]
    fn a_late_abort_does_not_rename_an_expired_budget() {
        let handle = ScanHandle::bounded(Some(Duration::ZERO));
        handle.abort();
        assert_eq!(handle.stopped(), Some(StopCause::TimedOut));
    }
}
