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
use crate::model::ip::range::IpRange;
use crate::report::{ScanKind, ScanPhase, ScannerKind, Unheard};
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
///
/// The task only keeps time. Each write is handed to the runtime's blocking
/// pool, since a checkpoint is file I/O and the serialising of every host that
/// changed, which for a host scanned on every port is tens of thousands of
/// records: run on a worker, it held that worker for the length of the write,
/// and the reply handling queued behind it stalled with every checkpoint.
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
                _ = tokio::time::sleep(CHECKPOINT_EVERY) => {
                    let ctx = ctx.clone();
                    let written = tokio::task::spawn_blocking(move || {
                        writer.checkpoint(&ctx);
                        writer
                    });
                    // A checkpoint that panicked took the journal down with it,
                    // releasing its lock, and there is nothing left to write.
                    let Ok(returned) = written.await else {
                        return;
                    };
                    writer = returned;
                }
                // A dropped signal is a task nobody joined: there are no phases
                // to record, and what has been settled so far still is.
                finished = &mut stop => break finished.unwrap_or_default(),
            }
        };
        let _ = tokio::task::spawn_blocking(move || {
            let _ = writer.journal.end_sitting(&phases);
            writer.close(&ctx, &phases);
        })
        .await;
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
    /// The addresses the open phase heard nothing from, as named beside the
    /// last cursor written; see [`Cut::silent`].
    silent: Vec<IpRange>,
}

impl Writer {
    fn new(journal: Journal) -> Self {
        Self {
            journal,
            failing: false,
            silent: Vec::new(),
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

        // Named beside the cursor that settles them, and so only once that
        // cursor is written: named while their targets are not settled on
        // disk, a resume would ask them again and find what the record
        // already said it had not heard.
        if outcome.is_ok() {
            self.silent = cut.silent;
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
        // disturb the checkpoint and is not folded above. Nor does the
        // sitting's standing record, which the next checkpoint rewrites whole.
        // Tapes are handed back as findings are, since nothing captures them
        // again.
        let tapes = ctx.take_tapes();
        if self.journal.record_detections(&tapes).is_err() {
            ctx.hand_back_tapes(tapes);
        }
        let _ = self
            .journal
            .record_standing(&ctx.standing_phases(&self.silent));
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
        let _ = journal.record_finished(finished_hosts(ctx, phases));
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
    /// The addresses of the records held back that the phase has already
    /// heard nothing from on every target, each settled in `cursor`. See
    /// [`ScanProgress::heard_nothing_so_far`].
    silent: Vec<IpRange>,
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
        let silent = ctx.heard_nothing_so_far(&cursor);
        Self {
            cursor,
            changed,
            silent,
        }
    }
}

/// The hosts a sitting that ran as `phases` did finished every pass over, as
/// [`Journal::record_finished`] names them: none for one that was stopped,
/// which may not have reached its passes, and otherwise every host it held but
/// those a host's own budget ran out on, which a pass passed over.
///
/// `phases` are this sitting's own, as it closes, and never what the journal
/// holds of it: a checkpoint writes the phase still open as one nothing has
/// stopped, so a killed sitting read back from disk looks like one that ran to
/// its end. Only a sitting that reaches its close can say it did.
fn finished_hosts(ctx: &ScanProgress, phases: &[ScanPhase]) -> Vec<String> {
    let ran_to_its_end = !phases.is_empty()
        && phases
            .iter()
            .all(|phase| phase.kind() != ScanKind::Listen && phase.stopped().is_none());
    if !ran_to_its_end {
        return Vec::new();
    }

    let timed_out: std::collections::HashSet<std::net::IpAddr> = phases
        .iter()
        .flat_map(|phase| phase.timed_out().iter().copied())
        .collect();
    ctx.host_keys()
        .into_iter()
        .filter(|key| !timed_out.contains(&key.addr()))
        .map(|key| key.to_string())
        .collect()
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

    /// A pass over a host that changed nothing costs the journal no record.
    ///
    /// Every write-back pass, correlation, posture, the passive OS reading,
    /// edits hosts through the store and marks each one changed whether or
    /// not the edit moved anything. Written regardless, each such pass over a
    /// host is a record of it in the findings file, and a wide scan's file
    /// grows with passes that learned nothing.
    #[test]
    fn a_pass_that_changed_nothing_writes_no_record() {
        use crate::model::port::{Port, PortState, Protocol};

        let root = scratch("unchanged");
        let journal =
            Journal::create(&root, &one_target(), Privilege::Raw, "test").expect("creates");
        let findings = journal.directory().join("hosts.jsonl");
        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let progress = ctx.progress();
        let ip: std::net::IpAddr = "192.0.2.1".parse().expect("an address");

        ctx.update_host(ip, |host| {
            host.add_port(Port::new(80, Protocol::Tcp, PortState::Open));
        });
        let mut writer = Writer::new(journal);
        writer.checkpoint(&progress);
        let written = std::fs::metadata(&findings).expect("written").len();

        // A pass that looked the host over and found nothing to add.
        ctx.write_host(ip, |_| false);
        writer.checkpoint(&progress);

        assert_eq!(
            std::fs::metadata(&findings).expect("written").len(),
            written,
            "the findings file grew for a pass that changed nothing"
        );
        drop(writer);
        std::fs::remove_dir_all(&root).ok();
    }

    /// What a checkpoint takes of a wide host is the ports that changed, and
    /// what it writes of them reads back as the whole host.
    ///
    /// A host scanned on every port holds tens of thousands of them, and each
    /// pass that follows the port scan touches a few: taken whole, each
    /// checkpoint copied every port under the lock the scan writes that host
    /// through and serialised each one to learn which had changed, half a
    /// second a checkpoint on a debug build for one service identified.
    #[test]
    fn a_checkpoint_takes_the_ports_that_changed_and_not_the_whole_host() {
        use crate::model::port::{Port, PortState, Protocol};

        const WIDE: u16 = 2_000;
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "192.0.2.1".parse().expect("an address"),
            format!("1-{WIDE}").parse().expect("ports"),
        ));
        let plan = Plan::port_scan(&map, &Exclusions::none(), TcpScanTechnique::Syn);
        let root = scratch("touched");
        let journal = Journal::create(&root, &plan, Privilege::Raw, "test").expect("creates");
        let directory = journal.directory().to_path_buf();
        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let progress = ctx.progress();
        let ip: std::net::IpAddr = "192.0.2.1".parse().expect("an address");

        ctx.update_host(ip, |host| {
            for number in 1..=WIDE {
                host.add_port(Port::new(number, Protocol::Tcp, PortState::Closed));
            }
        });
        let mut writer = Writer::new(journal);
        writer.checkpoint(&progress);

        // One port answers later, as a re-probe or an identification would
        // move it.
        ctx.update_host(ip, |host| {
            host.add_port(Port::new(80, Protocol::Tcp, PortState::Open));
        });
        let taken = progress.take_changed_findings();
        assert_eq!(taken.len(), 1);
        assert_eq!(
            taken[0].port_count(),
            1,
            "a checkpoint copied every port of a host one port of which changed"
        );
        progress.hand_back(&taken);
        writer.checkpoint(&progress);
        drop(writer);

        let (resumed, _) = Journal::resume(&directory, &plan, Privilege::Raw).expect("resumes");
        let host = &resumed.restored()[0];
        assert_eq!(
            host.port_count(),
            usize::from(WIDE),
            "every port reads back"
        );
        assert!(
            holds_the_open_port(resumed.restored()),
            "with the one that changed"
        );
        drop(resumed);
        std::fs::remove_dir_all(&root).ok();
    }

    /// Detection tapes a checkpoint could not write are written by the next
    /// one that can.
    ///
    /// A checkpoint takes the tapes captured since the last one before it
    /// writes them, and nothing captures them again: lost with a failed write,
    /// the runs they record can never be replayed. A directory standing at the
    /// tapes' file name fails that write for one checkpoint, the way a full
    /// disk or a revoked permission does.
    #[test]
    fn tapes_a_failed_checkpoint_took_are_written_by_the_next_one() {
        use crate::detect::compute::{CapTape, CapTapeRecord, DetectionRunRecord};
        use crate::record::DetectionIdRecord;

        let root = scratch("tapes-handed-back");
        let journal =
            Journal::create(&root, &one_target(), Privilege::Raw, "test").expect("creates");
        let directory = journal.directory().to_path_buf();
        let tapes = directory.join("detections.jsonl");
        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let progress = ctx.progress();
        let run = |detection: &str| DetectionRunRecord {
            host: "192.0.2.1".to_string(),
            port: 80,
            protocol: "tcp".to_string(),
            detection: DetectionIdRecord {
                id: detection.to_string(),
                version: "1.0.0".to_string(),
                content_hash: "0".repeat(64),
            },
            responses: vec!["HTTP/1.1 200 OK\r\n\r\n".to_string()],
            tape: CapTapeRecord::from(&CapTape::default()),
        };

        ctx.tapes.record(|| run("first"));
        let mut writer = Writer::new(journal);
        std::fs::create_dir(&tapes).expect("stands a directory in the way");
        writer.checkpoint(&progress);
        std::fs::remove_dir(&tapes).expect("clears the way");
        ctx.tapes.record(|| run("second"));
        writer.checkpoint(&progress);
        drop(writer);

        let written: Vec<String> = crate::journal::store::read_detections(&directory)
            .expect("reads")
            .into_iter()
            .map(|run| run.detection.id)
            .collect();
        assert_eq!(written, ["first", "second"], "in the order they ran");
        std::fs::remove_dir_all(&root).ok();
    }

    /// A checkpoint whose write blocks holds none of the runtime's workers
    /// while it waits.
    ///
    /// A checkpoint is file I/O and the serialising of every host that changed,
    /// and a host scanned on every port is tens of thousands of records. Run
    /// on a worker, it held that worker for as long as the write took, and
    /// on a runtime with one worker nothing else ran: replies queued unread
    /// and timers fired late with every checkpoint. The findings file is a
    /// named pipe here, whose opening for writing blocks until something reads
    /// it, which makes the write take as long as the test decides. The runtime
    /// is the one worker `tokio::test` gives, so a timer running across the
    /// checkpoint is late by as long as the write if the write holds it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_checkpoint_that_blocks_does_not_hold_the_runtime() {
        use std::io::Read;
        use std::os::unix::ffi::OsStrExt;
        use std::time::{Duration, Instant};

        /// How long a stuck writer is left before the pipe is read anyway, so
        /// a regression fails the assertion below rather than hanging.
        const RELEASED_AFTER: Duration = Duration::from_secs(20);

        let root = scratch("blocking");
        let plan = one_target();
        let journal = Journal::create(&root, &plan, Privilege::Raw, "test").expect("creates");
        let findings = journal.directory().join("hosts.jsonl");
        std::fs::remove_file(&findings).expect("removes the findings file");
        let name = std::ffi::CString::new(findings.as_os_str().as_bytes()).expect("a path");
        // SAFETY: `name` is a live, NUL-terminated path, which is all `mkfifo`
        // reads.
        assert_eq!(
            unsafe { libc::mkfifo(name.as_ptr(), 0o600) },
            0,
            "makes a pipe"
        );

        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let ip: std::net::IpAddr = "192.0.2.1".parse().expect("an address");
        ctx.update_host(ip, |host| {
            host.set_status(crate::model::host::HostStatus::Up);
        });

        let (release, released) = std::sync::mpsc::channel::<()>();
        let reader = std::thread::spawn(move || {
            let _ = released.recv_timeout(RELEASED_AFTER);
            let mut read = Vec::new();
            std::fs::File::open(&findings)
                .and_then(|mut pipe| pipe.read_to_end(&mut read))
                .expect("reads the pipe");
            read
        });

        let ticker = spawn_checkpoints(journal, ctx.progress());
        let started = Instant::now();
        let across = CHECKPOINT_EVERY + Duration::from_millis(500);
        tokio::time::sleep(across).await;
        let late = started.elapsed() - across;

        let _ = release.send(());
        let read = tokio::task::spawn_blocking(move || reader.join().expect("the reader"))
            .await
            .expect("joins");
        ticker.kill().await;
        std::fs::remove_dir_all(&root).ok();

        assert!(
            String::from_utf8_lossy(&read).contains("192.0.2.1"),
            "the checkpoint never reached the pipe, so it proves nothing"
        );
        assert!(
            late < RELEASED_AFTER / 2,
            "a timer across the checkpoint ran {late:?} late"
        );
    }

    /// A phase `ctx` has open, as a scan opens one.
    fn open_a_port_phase(
        ctx: &crate::scanner::session::ScanContext,
    ) -> crate::scanner::recorder::PhaseRecorder {
        use crate::report::{ScanKind, TargetScope};

        let mut addresses: crate::model::ip::set::IpSet = "192.0.2.1".parse().expect("an address");
        let scope = TargetScope::from_ip_set(&mut addresses, &Exclusions::none());
        crate::scanner::recorder::PhaseRecorder::start(
            ScanKind::PortScan,
            Privilege::Raw,
            scope,
            &crate::config::ZondConfig::default(),
        )
        .opening_in(ctx)
    }

    /// A sitting killed outright leaves a record of its phase: what it was
    /// asked to cover and under what, how long it ran, and what failed.
    ///
    /// A sitting's phases are written when it stops, and a killed one never
    /// stops. Without this the job's report, read back or resumed, described
    /// only the sittings that ended, and a failure that may be why the first
    /// one was killed went with it.
    #[test]
    fn a_killed_sitting_leaves_a_record_of_its_phase() {
        let root = scratch("killed-phase");
        let plan = one_target();
        let journal = Journal::create(&root, &plan, Privilege::Raw, "test").expect("creates");
        let directory = journal.directory().to_path_buf();
        let (_session, ctx) = crate::scanner::session::ScanSession::new();

        let _recorder = open_a_port_phase(&ctx);
        ctx.record_failure(ScannerKind::SynPort, "the capture closed".to_string());
        let mut writer = Writer::new(journal);
        writer.checkpoint(&ctx.progress());
        drop(writer);

        let report = crate::journal::store::report(&directory).expect("reads");
        assert_eq!(report.phases().len(), 1, "the killed sitting's phase");
        assert_eq!(report.phases()[0].kind(), crate::report::ScanKind::PortScan);
        assert_eq!(report.failures().count(), 1, "and what failed in it");

        let (resumed, _) = Journal::resume(&directory, &plan, Privilege::Raw).expect("resumes");
        assert_eq!(resumed.earlier_phases().len(), 1, "a resume carries it too");
        drop(resumed);
        std::fs::remove_dir_all(&root).ok();
    }

    /// A sitting that ends has its phases recorded once, and nothing of them
    /// left standing.
    ///
    /// Its standing record and its ending both describe the same phases, and
    /// a report holding both would describe the sitting twice.
    #[test]
    fn a_sitting_that_ends_is_recorded_once() {
        let root = scratch("ended-phase");
        let plan = one_target();
        let journal = Journal::create(&root, &plan, Privilege::Raw, "test").expect("creates");
        let directory = journal.directory().to_path_buf();
        let (_session, ctx) = crate::scanner::session::ScanSession::new();

        let recorder = open_a_port_phase(&ctx);
        let mut writer = Writer::new(journal);
        writer.checkpoint(&ctx.progress());
        let report = recorder.finish(&ctx);
        writer
            .journal
            .end_sitting(report.phases())
            .expect("records");
        writer.close(&ctx.progress(), report.phases());

        let phases = crate::journal::store::report(&directory).expect("reads");
        assert_eq!(phases.phases().len(), 1);
        let standing = std::fs::read_dir(&directory)
            .expect("lists")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("sitting-"))
            .count();
        assert_eq!(standing, 0, "the standing record outlived the sitting");
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
