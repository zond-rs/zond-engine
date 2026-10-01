// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Stopping a scan
//!
//! A scan spawns strategies that outlive the call that started them.
//! [`ScanHandle`] is one flag and one deadline shared by all of them, cheap
//! enough to read on every pass of every probing loop.
//!
//! A scan stops early when the caller asks or when its wall-clock budget runs
//! out. Both wind the strategies down through the same check, and [`StopCause`]
//! tells them apart in the report.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use crate::report::StopReason;
use crate::scanner::pacing::timer::later;

/// Why a scan is winding down.
///
/// Answered by [`ScanHandle::stopped`] and read by the probing loops to name
/// their own stop. A scan stopped either way keeps what it had already learned.
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
/// Every strategy a scan spawned reads this on every pass of its loop, so a scan
/// of a large range stops promptly.
///
/// Stopping does not cancel. The scan winds down and still produces its
/// [`ScanReport`](crate::report::ScanReport), with the hosts found so far, and
/// the report's [`StopReason`] marks it as shortened.
///
/// Clones share the same flag and deadline, including the copy on a
/// [`ScanSession`](crate::scanner::session::ScanSession).
#[derive(Debug, Clone)]
pub struct ScanHandle {
    stop: Arc<Stop>,
}

/// The shared half: what every clone of a handle reads.
#[derive(Debug)]
struct Stop {
    aborted: AtomicBool,
    /// Wakes whatever is waiting in [`ScanHandle::stopping`] when the scan is
    /// aborted. The deadline needs no waking: a waiter sleeps until it.
    woken: Notify,
    /// When this scan's budget runs out, for one that was given a budget.
    /// Monotonic, so a clock stepped mid-scan cannot end it early or late.
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
    /// The clock starts here, where the scan is assembled, so the budget covers
    /// the whole call and not only the probing.
    pub fn bounded(budget: Option<Duration>) -> Self {
        let deadline = budget.map(|budget| later(Instant::now(), budget));
        Self {
            stop: Arc::new(Stop {
                aborted: AtomicBool::new(false),
                woken: Notify::new(),
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
    /// Idempotent and permanent.
    pub fn abort(&self) {
        self.stop.aborted.store(true, Ordering::SeqCst);
        self.stop.woken.notify_waiters();
    }

    /// Resolves once the scan is asked to stop or outlives its budget, and at
    /// once for one that already has.
    ///
    /// For one long wait on a peer that the probing loops cannot interrupt, such
    /// as identifying a service on a port that accepts and says nothing (up to
    /// half a minute). Raced against this, the wait ends when the scan does. See
    /// [`or_stopped`](Self::or_stopped).
    pub(crate) async fn stopping(&self) {
        loop {
            // Registered before the flag is read, so an abort in between still
            // wakes this one.
            let woken = self.stop.woken.notified();
            tokio::pin!(woken);
            woken.as_mut().enable();
            if self.should_stop() {
                return;
            }
            match self.stop.deadline {
                Some(deadline) => tokio::select! {
                    () = woken => {}
                    () = tokio::time::sleep_until(deadline.into()) => return,
                },
                None => woken.await,
            }
        }
    }

    /// Runs `work` to its end unless the scan stops first, and `None` where it
    /// did.
    ///
    /// The race favours the work, so an answer and a stop landing together keep
    /// the answer.
    pub(crate) async fn or_stopped<T>(&self, work: impl Future<Output = T>) -> Option<T> {
        tokio::select! {
            biased;
            done = work => Some(done),
            () = self.stopping() => None,
        }
    }

    /// Whether the scan has been asked to stop, or has outlived its budget.
    ///
    /// Called by every probing loop each time round. Without a budget it reads one
    /// atomic.
    pub fn should_stop(&self) -> bool {
        self.stopped().is_some()
    }

    /// Why the scan is stopping, or `None` while it is still running.
    ///
    /// The budget is read first, so an abort arriving after it expired does not
    /// turn a timed-out scan into an aborted one.
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
    /// The clock starts inside the call that assembles the scan, so a front end
    /// showing the time left needs this and not the budget it asked for.
    pub fn deadline(&self) -> Option<Instant> {
        self.stop.deadline
    }
}

impl From<StopCause> for StopReason {
    /// The one mapping every probing loop uses to record why it stopped.
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

    /// Without a budget only an abort stops the scan.
    #[test]
    fn a_handle_with_no_budget_stops_only_when_asked() {
        let handle = ScanHandle::new();
        assert_eq!(handle.stopped(), None);
        handle.abort();
        assert_eq!(handle.stopped(), Some(StopCause::Aborted));
    }

    /// An expired budget stops the scan with nobody asking.
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

    /// `Duration::MAX` is past what the clock can count to, and must not panic.
    #[test]
    fn the_longest_budget_is_one_that_never_runs_out() {
        let handle = ScanHandle::bounded(Some(Duration::MAX));
        assert_eq!(handle.stopped(), None);
        assert!(handle.deadline().is_some());
    }

    /// An in-flight identification ends with the scan, not after its own ceiling.
    #[tokio::test]
    async fn a_wait_raced_against_the_stop_ends_when_the_scan_is_aborted() {
        let handle = ScanHandle::new();
        let aborter = handle.clone();
        let waiting =
            tokio::spawn(async move { handle.or_stopped(std::future::pending::<()>()).await });
        tokio::task::yield_now().await;
        aborter.abort();

        assert_eq!(waiting.await.expect("the wait ends"), None);
    }

    /// The budget ends the wait the same way, with nobody asking.
    #[tokio::test]
    async fn a_wait_raced_against_the_stop_ends_when_the_budget_runs_out() {
        let handle = ScanHandle::bounded(Some(Duration::from_millis(10)));

        let raced = handle.or_stopped(std::future::pending::<()>()).await;

        assert_eq!(raced, None);
        assert!(handle.should_stop());
    }

    /// Work that finishes is kept, even on a stopped scan: the race favours the
    /// answer.
    #[tokio::test]
    async fn work_that_finishes_is_kept() {
        let handle = ScanHandle::new();
        assert_eq!(handle.or_stopped(async { 7 }).await, Some(7));
        handle.abort();
        assert_eq!(handle.or_stopped(async { 7 }).await, Some(7));
        assert_eq!(handle.or_stopped(std::future::pending::<u8>()).await, None);
    }

    /// An abort after the budget expired leaves the cause as `TimedOut`.
    #[test]
    fn a_late_abort_does_not_rename_an_expired_budget() {
        let handle = ScanHandle::bounded(Some(Duration::ZERO));
        handle.abort();
        assert_eq!(handle.stopped(), Some(StopCause::TimedOut));
    }
}
