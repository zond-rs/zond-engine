// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// The means to stop a running scan.
///
/// One flag, shared by every strategy a scan spawned. Each of them checks it on
/// every pass of its own loop rather than only between targets, so a scan of a
/// large range stops promptly instead of after the address it is on.
///
/// **Stopping is not cancelling.** The scan winds down and still produces its
/// [`ScanReport`](crate::scanner::report::ScanReport), describing however far it
/// got — the hosts already found are findings, and discarding them because the
/// caller ran out of patience would throw away the work the scan had done. The
/// report's [`StopReason`](crate::scanner::report::StopReason) says
/// `Aborted` so nobody mistakes a shortened scan for a complete one.
///
/// Cloneable and shareable: the copy on a [`ScanSession`](crate::scanner::session::ScanSession)
/// and the copies held by the strategies are the same flag.
#[derive(Debug, Clone)]
pub struct ScanHandle {
    abort: Arc<AtomicBool>,
}

impl Default for ScanHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanHandle {
    /// A handle for a scan that has not been asked to stop.
    pub fn new() -> Self {
        let abort = Arc::new(AtomicBool::new(false));
        Self { abort }
    }

    /// Asks the scan to stop.
    ///
    /// Returns immediately; the strategies notice on their next pass. Await the
    /// [`ScanTask`](crate::scanner::ScanTask) to know when they have all
    /// finished and to collect the report.
    ///
    /// Idempotent, and there is deliberately no way to undo it. A scan that
    /// resumed after being stopped would have a gap in the middle that nothing
    /// in the report could describe.
    pub fn abort(&self) {
        self.abort.store(true, Ordering::SeqCst);
    }

    /// Whether the scan has been asked to stop.
    ///
    /// Every probing loop in the engine calls this each time round.
    pub fn should_stop(&self) -> bool {
        self.abort.load(Ordering::SeqCst)
    }
}
