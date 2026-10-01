// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Bounded probe concurrency
//!
//! The driver every fan-out scan shares (the connect port scan, the connect
//! discovery sweep, service detection): spawn a probe task per target, cap how
//! many run at once, and fold each result as it finishes.
//!
//! [`ProbePool`] owns the [`JoinSet`] bookkeeping: making room before admitting a
//! probe, draining the stragglers at the end, and dropping a panicked task. A
//! caller keeps its own source loop (an async [`mpsc`](tokio::sync::mpsc)
//! receiver, or a plain iterator) and hands each unit of work to
//! [`ProbePool::admit`].

use tokio::task::JoinSet;

use crate::counted;
use crate::logging::error;
use crate::report::ScannerKind;
use crate::scanner::audit::ProbeAudit;
use crate::scanner::session::ScanContext;

/// A bounded pool of in-flight probe tasks.
///
/// Holds at most `limit` tasks in a [`JoinSet`]. [`admit`](ProbePool::admit)
/// spawns one, first reaping finished tasks so the cap holds, and blocks only
/// when the pool is full. [`drain`](ProbePool::drain) awaits whatever remains once
/// the caller's source runs dry. Every finished task's output is passed to the
/// `fold` closure. A task that panicked is dropped, so one lost probe does not
/// sink the sweep.
///
/// The pool also owns the run's [`ProbeAudit`] and hands it to `fold` with each
/// result, because `fold` runs inside the pool and the caller's loop outside it,
/// and two borrows of one audit would not compile. A caller with no use for it
/// ignores the argument.
pub struct ProbePool<R, F: FnMut(R, &mut ProbeAudit)> {
    set: JoinSet<R>,
    limit: usize,
    fold: F,
    audit: ProbeAudit,
    /// Where a panicked probe is reported. A panicked task takes its target's
    /// verdict with it, so the scan covers less than asked, and that is recorded
    /// in the report like any other narrowing; a log line would never reach a
    /// library consumer.
    ctx: ScanContext,
    /// Which strategy a panic is attributed to.
    kind: ScannerKind,
    panicked: usize,
}

impl<R, F> ProbePool<R, F>
where
    R: Send + 'static,
    F: FnMut(R, &mut ProbeAudit),
{
    /// Builds an empty pool that keeps at most `limit` probes in flight and
    /// applies `fold` to each finished probe's output.
    ///
    /// `kind` names the strategy this pool is probing for, so a panic can be
    /// attributed to it in the report.
    ///
    /// A limit of zero is read as one, as `rate_within` reads a rate of zero.
    /// Taken literally, the admission loop would spin on an empty set without
    /// ever yielding, hanging a current-thread runtime where no `timeout` can
    /// fire.
    pub fn new(limit: usize, ctx: ScanContext, kind: ScannerKind, fold: F) -> Self {
        Self {
            set: JoinSet::new(),
            limit: limit.max(1),
            fold,
            audit: ProbeAudit::new(),
            ctx,
            kind,
            panicked: 0,
        }
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

    /// Awaits every probe still in flight, folding each result, then reports
    /// any that panicked.
    ///
    /// Call once the source is exhausted, so no finished work is dropped. Panics
    /// are reported as one count, since a defect that takes down one probe
    /// usually takes down every probe like it. A pool drained again reports only
    /// the panics since the last drain.
    pub async fn drain(&mut self) {
        while !self.set.is_empty() {
            self.reap().await;
        }

        if self.panicked > 0 {
            self.ctx.record_failure(
                self.kind,
                format!(
                    "{} panicked and their targets have no verdict; this is a \
                     defect in the engine rather than a fact about the network",
                    counted(self.panicked as u128, "probe", "probes")
                ),
            );
            self.panicked = 0;
        }
    }

    /// Awaits the next finished probe and folds its output. Does nothing if the
    /// pool is empty.
    ///
    /// A panicked probe surfaces here as a [`JoinError`](tokio::task::JoinError);
    /// the pool never aborts its tasks, so that always means a bug in probe code.
    /// It is counted and the sweep continues; [`drain`](Self::drain) reports the
    /// total.
    async fn reap(&mut self) {
        match self.set.join_next().await {
            Some(Ok(output)) => (self.fold)(output, &mut self.audit),
            Some(Err(e)) => {
                self.panicked += 1;
                error!("probe task panicked: {e}");
            }
            None => {}
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
    use crate::scanner::session::ScanSession;

    /// Runs on a current-thread runtime, so it hangs if a zero limit ever spins
    /// the admission loop.
    #[tokio::test]
    async fn a_zero_limit_admits_one_probe_rather_than_spinning() {
        let (_session, ctx) = ScanSession::new();
        let mut done = 0usize;
        let mut pool = ProbePool::new(0, ctx, ScannerKind::Connect, |_: (), _| done += 1);

        pool.admit(async {}).await;
        pool.admit(async {}).await;
        pool.drain().await;

        assert_eq!(done, 2, "both probes ran and both were folded");
    }

    /// Any nonzero limit is the cap.
    #[tokio::test]
    async fn the_pool_never_exceeds_its_limit() {
        let (_session, ctx) = ScanSession::new();
        let mut pool = ProbePool::new(2, ctx, ScannerKind::Connect, |_: (), _| {});

        for _ in 0..8 {
            pool.admit(async {}).await;
            assert!(pool.set.len() <= 2, "the cap held while admitting");
        }
        pool.drain().await;
    }
}
