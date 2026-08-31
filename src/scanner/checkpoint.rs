// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Writing a running scan down as it runs
//!
//! The timer that carries what a scan has found into its
//! [`Journal`](crate::journal::store::Journal), and the
//! handle that stops it.
//!
//! ## Why this is the scanner's and not the journal's
//!
//! It reads a [`ScanProgress`](crate::scanner::session::ScanProgress) and writes
//! a [`Journal`](crate::journal::store::Journal), and only one of those
//! is something the journal knows about. Living beside the journal meant a
//! public signature there naming a scanner type, which inverts the order
//! `src/lib.rs` sets out and put the two modules in a cycle: `scanner` needs a
//! journal to write, and `journal` needed a scan to read. Here the dependency
//! runs one way, which is what it always was in substance.
//!
//! The journal keeps everything about *how* a scan is written down. What is here
//! is when.

use crate::journal::Journal;
use crate::report::{ScanPhase, ScannerKind};
use crate::scanner::session::ScanProgress;

/// How often a running scan writes down how far it got.
///
/// The cost of a crash is one interval of replayed work, and the cost of the
/// interval is one rename of a small file — so this is chosen for the first,
/// not the second. Three seconds of a six-hour scan is not a tradeoff worth
/// exposing.
pub const CHECKPOINT_EVERY: std::time::Duration = std::time::Duration::from_secs(3);

/// A running scan's journal, checkpointed on a timer by a task of its own.
///
/// The journal is owned by that task rather than shared with the scan: a
/// checkpoint is the only thing that writes it, so there is nothing to
/// synchronise and no lock for a scan to hold while it does I/O.
#[derive(Debug)]
pub struct Checkpointing {
    done: tokio::sync::oneshot::Sender<Vec<ScanPhase>>,
    task: tokio::task::JoinHandle<()>,
}

impl Checkpointing {
    /// Writes the last checkpoint and releases the lock.
    ///
    /// Call once the scan has finished and every strategy has reported, so the
    /// final cursor covers the whole sitting.
    pub async fn finish(self, phases: &[ScanPhase]) {
        // The stop signal carries what the sitting did, because those are one
        // fact: the scan is over, and this is what it turned out to be. A send
        // failure means the writer has already stopped.
        let _ = self.done.send(phases.to_vec());
        let _ = self.task.await;
    }
}

/// Starts checkpointing `journal` from `ctx`'s progress until told to stop.
pub fn spawn_checkpoints(mut journal: Journal, ctx: ScanProgress) -> Checkpointing {
    let (done, mut stop) = tokio::sync::oneshot::channel::<Vec<ScanPhase>>();

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(CHECKPOINT_EVERY) => {
                    // A checkpoint that cannot be written is not worth ending a
                    // scan over: the previous one still stands, and the scan is
                    // still producing results. Reported through the same channel
                    // every other narrowing uses.
                    let changed = ctx.take_changed_hosts();
                    let outcome = if journal.should_compact(ctx.host_count()) {
                        // The snapshot covers `changed` as well, so nothing is
                        // lost by not appending them.
                        journal.compact(&ctx.hosts_snapshot())
                    } else {
                        journal.record_hosts(&changed)
                    }
                    .and_then(|()| journal.checkpoint(ctx.settlements()));

                    if let Err(e) = outcome {
                        ctx.record_failure(
                            ScannerKind::Composite,
                            format!("journal checkpoint failed, so a resume would replay further back than it should: {e}"),
                        );
                    }

                    // Tapes are additive: they settle nothing, so a failed write
                    // does not disturb the checkpoint and is not folded above.
                    let _ = journal.record_detections(&ctx.take_tapes());
                }
                // A dropped signal is a task nobody joined: there are no phases
                // to record, and what has been settled so far still is.
                finished = &mut stop => {
                    let _ = journal.record_phases(&finished.unwrap_or_default());
                    break;
                }
            }
        }

        let _ = journal.record(&ctx.take_changed_hosts(), ctx.settlements());
        let _ = journal.record_detections(&ctx.take_tapes());
        let _ = journal.close();
    });

    Checkpointing { done, task }
}
