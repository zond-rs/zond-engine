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
//! is when, and in what order.
//!
//! ## The cursor is read before the findings are taken
//!
//! A checkpoint writes two things a running scan goes on changing while it
//! reads them: the hosts whose findings changed, and the cursor saying which
//! targets are settled. A resume skips what the cursor names and restores what
//! the findings file holds, so a position the cursor names whose finding the
//! file lacks is a target the resumed scan neither asks nor reports.
//!
//! Every strategy records a finding in the store before it settles the
//! target that produced it; see
//! [`ScanContext::record_outcome`](crate::scanner::session::ScanContext::record_outcome).
//! So a checkpoint reads the cursor first and takes the changed hosts after:
//! whatever the cursor it read names as settled was stored before it was read,
//! and so before the hosts were taken. A target settled between the two
//! readings has its finding written and its position left out, and costs one
//! probe on a resume rather than a finding.

use crate::journal::Journal;
use crate::journal::cursor::Checkpoint;
use crate::journal::format::JournalError;
use crate::model::host::Host;
use crate::report::{ScanPhase, ScannerKind, Unheard};
use crate::scanner::session::ScanProgress;

/// How often a running scan writes down how far it got.
///
/// The cost of a crash is one interval of replayed work, and the cost of the
/// interval is one rename of a small file, so this is chosen for the first,
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

    /// Ends the writer where it stands, without its last write: what a
    /// process killed outright leaves on disk.
    #[cfg(test)]
    pub(crate) async fn kill(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

/// Starts checkpointing `journal` from `ctx`'s progress until told to stop.
pub fn spawn_checkpoints(journal: Journal, ctx: ScanProgress) -> Checkpointing {
    let (done, mut stop) = tokio::sync::oneshot::channel::<Vec<ScanPhase>>();

    let task = tokio::spawn(async move {
        let mut writer = Writer::new(journal);
        let phases = loop {
            tokio::select! {
                _ = tokio::time::sleep(CHECKPOINT_EVERY) => writer.checkpoint(&ctx),
                // A dropped signal is a task nobody joined: there are no phases
                // to record, and what has been settled so far still is.
                finished = &mut stop => {
                    let phases = finished.unwrap_or_default();
                    let _ = writer.journal.record_phases(&phases);
                    break phases;
                }
            }
        };
        writer.close(&ctx, &phases);
    });

    Checkpointing { done, task }
}

/// The journal a checkpoint task writes, and whether its last checkpoint
/// failed.
struct Writer {
    journal: Journal,
    /// Whether the last checkpoint failed, so a failure is told when
    /// checkpointing stops working rather than at every checkpoint after.
    ///
    /// Whatever stops one checkpoint, a full disk or a descriptor table with
    /// no room, stops the next one too, and one is due every few seconds: told
    /// each time, a scan's console fills with one fact. Cleared by a
    /// checkpoint that is written, so a failure that returns after that is
    /// told again, being news again.
    failing: bool,
}

impl Writer {
    fn new(journal: Journal) -> Self {
        Self {
            journal,
            failing: false,
        }
    }

    /// Writes down what has changed and how far the scan got.
    ///
    /// A checkpoint that cannot be written is not worth ending a scan over:
    /// the previous one still stands, and the scan is still producing results.
    /// Reported through the same channel every other narrowing uses.
    fn checkpoint(&mut self, ctx: &ScanProgress) {
        let cut = Cut::take(ctx);
        self.write(ctx, cut);
    }

    /// Writes `cut`: the findings first and the cursor after, so a cursor is
    /// never on disk beside a findings file missing what it settled.
    fn write(&mut self, ctx: &ScanProgress, cut: Cut) {
        let journal = &mut self.journal;
        let outcome = if journal.should_compact() {
            // Taken after the cursor was read, as `cut.changed` was, so it
            // covers everything that cursor settled and nothing is lost by not
            // appending `cut.changed`. A compaction that fails leaves the file
            // as it was, which appending to still brings up to date.
            journal
                .compact(&ctx.findings_snapshot())
                .or_else(|_| journal.record_hosts(&cut.changed))
        } else {
            journal.record_hosts(&cut.changed)
        }
        .and_then(|()| journal.write_cursor(&cut.cursor));

        // What this checkpoint took is written by the next one that can write,
        // or a later cursor would settle the targets behind it with nothing on
        // file to show for them.
        if outcome.is_err() {
            ctx.hand_back(&cut.changed);
        }

        match outcome {
            Err(error) if !self.failing => {
                self.failing = true;
                ctx.record_failure(
                    ScannerKind::Journal,
                    format!(
                        "checkpoint failed: {} (resume replays more)",
                        reason(&error)
                    ),
                );
            }
            Err(_) => {}
            Ok(()) => self.failing = false,
        }

        // Tapes are additive: they settle nothing, so a failed write does not
        // disturb the checkpoint and is not folded above.
        let _ = self.journal.record_detections(&ctx.take_tapes());
    }

    /// Writes the sitting's last checkpoint and closes the journal.
    ///
    /// A job whose phases heard nothing from an address has its findings
    /// written whole, less every record at one. A checkpoint wrote the
    /// scanners' records of such an address down before the phase decided it
    /// was silent, and the phase forgot them only in memory; appended to, the
    /// file would keep what the job's report drops. See `Unheard`.
    fn close(mut self, ctx: &ScanProgress, phases: &[ScanPhase]) {
        let journal = &mut self.journal;
        let unheard = Unheard::of(journal.earlier_phases().iter().chain(phases));
        let cut = Cut::take(ctx);
        let _ = if unheard.is_empty() {
            journal.record_hosts(&cut.changed)
        } else {
            let mut kept = ctx.findings_snapshot();
            kept.retain(|host| !unheard.drops(host));
            journal.compact(&kept)
        }
        .and_then(|()| journal.write_cursor(&cut.cursor));
        let _ = journal.record_detections(&ctx.take_tapes());
        let _ = self.journal.close();
    }
}

/// What one checkpoint writes down: how far the scan got, and the findings
/// that changed on the way there.
struct Cut {
    cursor: Checkpoint,
    /// Findings only: a record a port phase may yet forget as heard nothing
    /// from waits for its verdict. See `ScanContext::await_verdicts`.
    changed: Vec<Host>,
}

impl Cut {
    /// Reads the cursor, then takes the hosts that changed, in that order.
    /// See the module documentation for why the order is the whole point.
    fn take(ctx: &ScanProgress) -> Self {
        Self::taking(ctx, || {})
    }

    /// [`take`](Self::take), running `between` after the cursor is read and
    /// before the hosts are taken: the moment a test has to reach to show a
    /// target settling there costs no finding.
    fn taking(ctx: &ScanProgress, between: impl FnOnce()) -> Self {
        let cursor = ctx.settlements().checkpoint();
        between();
        let changed = ctx.take_changed_findings();
        Self { cursor, changed }
    }
}

/// Why a journal could not be written, in the words a console line ends on.
///
/// An operating system's refusal is told as the refusal alone, in lower case
/// and without its error number: the line already says it is the journal's, so
/// the journal error's own prefix and the number add length and nothing to act
/// on.
fn reason(error: &JournalError) -> String {
    let JournalError::Io(io) = error else {
        return error.to_string();
    };
    let said = io.to_string();
    let words = match io.raw_os_error() {
        Some(code) => said
            .strip_suffix(&format!(" (os error {code})"))
            .unwrap_or(&said),
        None => &said,
    };
    let mut letters = words.chars();
    letters.next().map_or_else(String::new, |first| {
        first.to_lowercase().chain(letters).collect()
    })
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
    use crate::journal::manifest::Plan;
    use crate::model::exclusion::Exclusions;
    use crate::model::target::{TargetMap, TargetSet};
    use crate::model::technique::TcpScanTechnique;
    use crate::system::privilege::Privilege;

    /// A scratch root for one test's journals, emptied first.
    fn scratch(name: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("zond-checkpoint-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch root");
        root
    }

    /// A port scan of one address on port 80: one target, at position 0.
    fn one_target() -> Plan {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "192.0.2.1".parse().expect("an address"),
            "80".parse().expect("ports"),
        ));
        Plan::port_scan(&map, &Exclusions::none(), TcpScanTechnique::Syn)
    }

    /// Whether `hosts` hold port 80 open.
    fn holds_the_open_port(hosts: &[Host]) -> bool {
        hosts.iter().any(|host| {
            host.ports().any(|port| {
                port.number() == 80 && port.state() == crate::model::port::PortState::Open
            })
        })
    }

    /// A target that settles while a checkpoint is being cut is either written
    /// with its finding or left for a resume to ask again, never skipped
    /// without it.
    ///
    /// A checkpoint reads two things a running scan goes on changing: the
    /// hosts that changed and the cursor. Read hosts-first, a port found and
    /// settled between the two readings is named settled by the cursor while
    /// its finding waits for the next checkpoint, and a scan killed before that
    /// one resumes past a port it never reports. The kill is the writer dropped
    /// without its closing write, which is what a process killed outright
    /// leaves.
    #[test]
    fn a_target_settled_while_a_checkpoint_is_cut_is_not_skipped_without_its_finding() {
        use crate::journal::settle::Outcome;
        use crate::model::port::{Port, PortState, Protocol};

        let root = scratch("cut");
        let plan = one_target();
        let journal = Journal::create(&root, &plan, Privilege::Raw, "test").expect("creates");
        let directory = journal.directory().to_path_buf();
        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let progress = ctx.progress();
        let ip: std::net::IpAddr = "192.0.2.1".parse().expect("an address");

        let mut writer = Writer::new(journal);
        // A strategy finds the port open and settles it, in the order every
        // strategy keeps, at the one moment a checkpoint is exposed to.
        let cut = Cut::taking(&progress, || {
            ctx.update_host(ip, |host| {
                host.add_port(Port::new(80, Protocol::Tcp, PortState::Open));
            });
            ctx.record_outcome(Outcome::Answered { position: 0 });
        });
        writer.write(&progress, cut);
        drop(writer);

        let (resumed, checkpoint) =
            Journal::resume(&directory, &plan, Privilege::Raw).expect("resumes");
        assert!(
            holds_the_open_port(resumed.restored()) || !checkpoint.is_settled(0),
            "the resume skips port 80 and restores no finding for it: {checkpoint:?}"
        );
        drop(resumed);
        std::fs::remove_dir_all(&root).ok();
    }

    /// Findings a checkpoint could not write are written by the next one that
    /// can.
    ///
    /// A checkpoint takes the hosts that changed before it writes them. Lost
    /// with a failed write, they would be on record nowhere, and the next
    /// checkpoint that succeeds writes a cursor settling the targets that
    /// found them: a scan killed after that resumes past them and never
    /// reports them. The findings file is moved aside for one checkpoint,
    /// which fails that write the way a full disk or a revoked permission
    /// does.
    #[test]
    fn findings_a_failed_checkpoint_took_are_written_by_the_next_one() {
        use crate::journal::settle::Outcome;
        use crate::model::port::{Port, PortState, Protocol};

        let root = scratch("handed-back");
        let plan = one_target();
        let journal = Journal::create(&root, &plan, Privilege::Raw, "test").expect("creates");
        let directory = journal.directory().to_path_buf();
        let findings = directory.join("hosts.jsonl");
        let aside = directory.join("hosts.jsonl-aside");
        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let progress = ctx.progress();
        let ip: std::net::IpAddr = "192.0.2.1".parse().expect("an address");

        ctx.update_host(ip, |host| {
            host.add_port(Port::new(80, Protocol::Tcp, PortState::Open));
        });
        ctx.record_outcome(Outcome::Answered { position: 0 });

        let mut writer = Writer::new(journal);
        std::fs::rename(&findings, &aside).expect("moves the findings aside");
        writer.checkpoint(&progress);
        std::fs::rename(&aside, &findings).expect("puts them back");
        writer.checkpoint(&progress);
        drop(writer);

        let (resumed, checkpoint) =
            Journal::resume(&directory, &plan, Privilege::Raw).expect("resumes");
        assert!(
            holds_the_open_port(resumed.restored()) || !checkpoint.is_settled(0),
            "the resume skips port 80 and restores no finding for it: {checkpoint:?}"
        );
        drop(resumed);
        std::fs::remove_dir_all(&root).ok();
    }

    /// A journal that cannot be written is told once, in one short line, however
    /// many checkpoints fail after it.
    ///
    /// A checkpoint is due every few seconds, and what stops one, a full disk
    /// or a descriptor table with no room, stops the next one too. Told every
    /// time, a scan's console fills with the same failure, and a long line
    /// repeated is the one a reader stops reading.
    #[test]
    fn a_journal_that_cannot_be_written_is_told_once_and_short() {
        let root = scratch("told-once");
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "192.0.2.1-192.0.2.4".parse().expect("a range"),
            "80".parse().expect("ports"),
        ));
        let plan = Plan::port_scan(&map, &Exclusions::none(), TcpScanTechnique::Syn);
        let journal = Journal::create(&root, &plan, Privilege::Raw, "test").expect("creates");
        // Every checkpoint after this has nowhere to go.
        std::fs::remove_dir_all(journal.directory()).expect("removes");
        let (_session, ctx) = crate::scanner::session::ScanSession::new();

        let mut writer = Writer::new(journal);
        for _ in 0..3 {
            writer.checkpoint(&ctx.progress());
        }

        let told: Vec<_> = ctx
            .failures_snapshot()
            .into_iter()
            .filter(|failure| failure.scanner() == ScannerKind::Journal)
            .map(|failure| failure.reason().to_owned())
            .collect();
        assert_eq!(told.len(), 1, "{told:#?}");
        assert!(
            told[0].len() <= 80,
            "{:?} is {} long",
            told[0],
            told[0].len()
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
