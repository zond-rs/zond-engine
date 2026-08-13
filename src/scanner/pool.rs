// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Bounded probe concurrency
//!
//! One reusable driver for the pattern every fan-out scan shares: spawn a probe
//! task per target, cap how many run at once, and fold each result as it
//! finishes. The connect port scan, the connect discovery sweep, and the
//! service-detection pass all need exactly this. Each used to repeat the same
//! fiddly [`JoinSet`] bookkeeping inline: make room before admitting a probe,
//! drain the stragglers at the end, and drop a panicked task rather than let it
//! abort the sweep.
//!
//! [`ProbePool`] owns that bookkeeping in one place. A caller keeps its own source
//! loop, since the sources differ (an async [`mpsc`](tokio::sync::mpsc) receiver
//! for the dispatched scans, a plain iterator for service detection) even though
//! the concurrency management does not, and hands each unit of work to
//! [`ProbePool::admit`].

use tokio::task::JoinSet;

use crate::error;
use crate::scanner::audit::ProbeAudit;

/// A bounded pool of in-flight probe tasks.
///
/// Holds at most `limit` tasks in a [`JoinSet`]. [`admit`](ProbePool::admit)
/// spawns one, first reaping finished tasks so the cap is never exceeded, and
/// blocks only when the pool is already full. [`drain`](ProbePool::drain) awaits
/// whatever remains once the caller's source runs dry. Every finished task's
/// output is passed to the `fold` closure the pool was built with. A task that
/// panicked is dropped, which matches a scan's best-effort contract: one lost
/// probe must not sink the whole sweep.
///
/// The pool also owns the run's [`ProbeAudit`], and hands it to `fold` alongside
/// each result. It has to be here rather than beside the pool at the call site:
/// `fold` runs inside the pool and the caller's own loop runs outside it, so two
/// separate borrows of one audit would not compile, and the alternative is
/// interior mutability in three call sites to work around a structure that could
/// simply hold it. A caller that has no use for it ignores the argument.
pub struct ProbePool<R, F: FnMut(R, &mut ProbeAudit)> {
    set: JoinSet<R>,
    limit: usize,
    fold: F,
    audit: ProbeAudit,
}

impl<R, F> ProbePool<R, F>
where
    R: Send + 'static,
    F: FnMut(R, &mut ProbeAudit),
{
    /// Builds an empty pool that keeps at most `limit` probes in flight and
    /// applies `fold` to each finished probe's output.
    pub fn new(limit: usize, fold: F) -> Self {
        Self {
            set: JoinSet::new(),
            limit,
            fold,
            audit: ProbeAudit::new(),
        }
    }

    /// The counters for this run, for a caller that records something the fold
    /// cannot see - a probe admitted, say, which happens in the source loop.
    pub fn audit(&mut self) -> &mut ProbeAudit {
        &mut self.audit
    }

    /// Takes the counters once the run is over.
    pub fn into_audit(self) -> ProbeAudit {
        self.audit
    }

    /// Spawns `task`, first reaping finished probes until the pool has room, so
    /// the concurrency cap always holds. Awaits only when the pool is full.
    pub async fn admit(&mut self, task: impl Future<Output = R> + Send + 'static) {
        while self.set.len() >= self.limit {
            self.reap().await;
        }
        self.set.spawn(task);
    }

    /// Awaits every probe still in flight, folding each result. Call once the
    /// source is exhausted so no finished work is dropped.
    pub async fn drain(&mut self) {
        while !self.set.is_empty() {
            self.reap().await;
        }
    }

    /// Awaits the next finished probe and folds its output. Does nothing if the
    /// pool is empty.
    ///
    /// A probe task that panicked surfaces here as a
    /// [`JoinError`](tokio::task::JoinError). The pool never aborts its tasks, so
    /// this only ever means a genuine panic in probe code, which is a bug. It is
    /// logged and the sweep continues rather than propagating the error, so one
    /// defective probe cannot sink the whole scan while still not vanishing unseen.
    async fn reap(&mut self) {
        match self.set.join_next().await {
            Some(Ok(output)) => (self.fold)(output, &mut self.audit),
            Some(Err(e)) => error!("probe task panicked: {e}"),
            None => {}
        }
    }
}
