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
use crate::report::ScannerKind;
use crate::scanner::audit::ProbeAudit;
use crate::scanner::session::ScanContext;

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
    /// Where a probe that panicked is reported, and how many did.
    ///
    /// A panicked task takes its target's verdict with it, so the scan covers
    /// less than it was asked to. That is the same kind of narrowing every
    /// other one in the engine records, and it has to reach the same place: a
    /// log line is the one channel a library consumer never sees.
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
    /// **A limit of zero is a caller error rather than an instruction to run
    /// nothing**, and is read as one probe, on the same terms `rate_or` reads a
    /// configured rate of zero. Honouring it is not an option: the admission
    /// loop below would spin on an empty set, and because it never awaits
    /// anything it never returns to the runtime: on a current-thread runtime
    /// the scan hangs with no diagnostic, and a `timeout` wrapped around it
    /// cannot fire.
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

    /// Awaits every probe still in flight, folding each result, then reports
    /// any that panicked.
    ///
    /// Call once the source is exhausted, so no finished work is dropped. The
    /// panic count is filed here rather than as each one happens: a defect that
    /// takes down one probe usually takes down every probe like it, and a
    /// report carrying that same entry a thousand times says nothing the first
    /// one did not.
    pub async fn drain(&mut self) {
        while !self.set.is_empty() {
            self.reap().await;
        }

        if self.panicked > 0 {
            self.ctx.record_failure(
                self.kind,
                format!(
                    "{} probe(s) panicked and their targets have no verdict; this is a \
                     defect in the engine rather than a fact about the network",
                    self.panicked
                ),
            );
        }
    }

    /// Awaits the next finished probe and folds its output. Does nothing if the
    /// pool is empty.
    ///
    /// A probe task that panicked surfaces here as a
    /// [`JoinError`](tokio::task::JoinError). The pool never aborts its tasks,
    /// so this only ever means a genuine panic in probe code, which is a bug.
    /// It is counted and the sweep continues rather than propagating the error,
    /// so one defective probe cannot sink the whole scan; [`drain`](Self::drain)
    /// reports the total, which is what keeps it from vanishing unseen.
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

    /// A limit of zero spun the admission loop on an empty set forever, and
    /// because the loop never awaited anything it never returned to the
    /// runtime: on a current-thread runtime the scan hung with no diagnostic,
    /// and a `timeout` around it could not fire. This test runs on exactly such
    /// a runtime, so it would not have completed at all before the fix.
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

    /// And the cap it was given is still the cap, for every other value.
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
