// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Bounded probe concurrency
//!
//! One reusable driver for the pattern every fan-out scan shares: spawn a probe
//! task per target, cap how many run at once, and fold each result as it
//! finishes. The connect port scan, the connect discovery sweep, and the
//! service-detection pass all need exactly this, and each used to re-spell the
//! same fiddly [`JoinSet`] bookkeeping - make room before admitting a probe,
//! drain the stragglers at the end, drop a panicked task rather than let it abort
//! the sweep - inline.
//!
//! [`ProbePool`] owns that bookkeeping once. A caller keeps its own source loop,
//! because sources differ (an async [`mpsc`](tokio::sync::mpsc) receiver for the
//! dispatched scans, a plain iterator for service detection) even though the
//! concurrency management doesn't, and hands each unit of work to
//! [`ProbePool::admit`].

use tokio::task::JoinSet;

/// A bounded pool of in-flight probe tasks.
///
/// Holds at most `limit` tasks in a [`JoinSet`]. [`admit`](ProbePool::admit)
/// spawns one, first reaping finished tasks - blocking only when the pool is
/// already full - so the cap is never exceeded; [`drain`](ProbePool::drain)
/// awaits whatever remains once the caller's source runs dry. Every finished
/// task's output is passed to the `fold` closure the pool was built with; a task
/// that panicked is dropped, which matches a scan's best-effort contract: one lost
/// probe must not sink the whole sweep.
pub(in crate::scanner) struct ProbePool<R, F: FnMut(R)> {
    set: JoinSet<R>,
    limit: usize,
    fold: F,
}

impl<R, F> ProbePool<R, F>
where
    R: Send + 'static,
    F: FnMut(R),
{
    /// Builds an empty pool that keeps at most `limit` probes in flight and
    /// applies `fold` to each finished probe's output.
    pub(in crate::scanner) fn new(limit: usize, fold: F) -> Self {
        Self {
            set: JoinSet::new(),
            limit,
            fold,
        }
    }

    /// Spawns `task`, first reaping finished probes until the pool has room, so
    /// the concurrency cap always holds. Awaits only when the pool is full.
    pub(in crate::scanner) async fn admit(
        &mut self,
        task: impl Future<Output = R> + Send + 'static,
    ) {
        while self.set.len() >= self.limit {
            self.reap().await;
        }
        self.set.spawn(task);
    }

    /// Awaits every probe still in flight, folding each result. Call once the
    /// source is exhausted so no finished work is dropped.
    pub(in crate::scanner) async fn drain(&mut self) {
        while !self.set.is_empty() {
            self.reap().await;
        }
    }

    /// Awaits the next finished probe and folds its output. A task that panicked
    /// (a [`JoinError`](tokio::task::JoinError)) is dropped rather than
    /// propagated. Does nothing if the pool is empty.
    async fn reap(&mut self) {
        if let Some(joined) = self.set.join_next().await
            && let Ok(output) = joined
        {
            (self.fold)(output);
        }
    }
}
