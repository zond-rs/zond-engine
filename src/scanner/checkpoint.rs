// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Writing a running scan down as it runs
//!
//! The timer that writes what a scan has found into its
//! [`Journal`](crate::journal::store::Journal), and the handle that stops it.
//!
//! It lives in the scanner because it reads a
//! [`ScanProgress`](crate::scanner::session::ScanProgress), which the journal
//! must not depend on. The journal decides how a scan is written down; this
//! module decides when, and in what order.
//!
//! ## The cursor is read before the findings are taken
//!
//! A checkpoint writes the hosts whose findings changed and the cursor saying
//! which targets are settled, both of which the scan keeps changing. A resume
//! skips what the cursor names and restores what the findings file holds, so a
//! settled position whose finding is missing from the file is lost.
//!
//! Every strategy stores a finding before settling its target (see
//! [`ScanContext::record_outcome`](crate::scanner::session::ScanContext::record_outcome)),
//! so reading the cursor first and taking the changed hosts after guarantees
//! every settled target's finding is included. A target settled between the two
//! reads is written without its position and costs one repeated probe on resume.

use crate::journal::Journal;
use crate::journal::cursor::Checkpoint;
use crate::journal::format::JournalError;
use crate::model::host::Host;
use crate::model::ip::set::IpSet;
use crate::report::{ScanKind, ScanPhase, ScannerKind, Unheard};
use crate::scanner::session::{ScanProgress, SoFar};

/// How often a running scan writes down how far it got.
///
/// A crash replays at most one interval of work, and each checkpoint costs one
/// rename of a small file, so the interval is short and not configurable.
pub const CHECKPOINT_EVERY: std::time::Duration = std::time::Duration::from_secs(3);

/// A running scan's journal, checkpointed on a timer by a task of its own.
///
/// The task owns the journal, so the scan holds no lock while it does I/O.
///
/// The task only keeps time. Each write runs on the blocking pool: a checkpoint
/// serialises every changed host, which for a host scanned on every port is tens
/// of thousands of records, and would stall reply handling on a worker.
#[derive(Debug)]
pub struct Checkpointing {
    done: tokio::sync::oneshot::Sender<Vec<ScanPhase>>,
    task: tokio::task::JoinHandle<()>,
    /// How many checkpoints the writer has written; see
    /// [`checkpointed`](Self::checkpointed).
    #[cfg(test)]
    written: tokio::sync::watch::Receiver<usize>,
}

impl Checkpointing {
    /// Writes the last checkpoint and releases the lock.
    ///
    /// Call once the scan has finished and every strategy has reported, so the
    /// final cursor covers the whole sitting.
    pub async fn finish(self, phases: &[ScanPhase]) {
        // The stop signal carries the sitting's phases. A send failure means the
        // writer has already stopped.
        let _ = self.done.send(phases.to_vec());
        let _ = self.task.await;
    }

    /// Ends the writer without its last write, as a process killed outright
    /// would.
    #[cfg(test)]
    pub(crate) async fn kill(self) {
        self.task.abort();
        let _ = self.task.await;
    }

    /// Waits until the writer has written a checkpoint this has not already
    /// waited for, and has the journal back from the thread that wrote it.
    ///
    /// For a test that needs a checkpoint on disk. Sleeping past
    /// [`CHECKPOINT_EVERY`] is unreliable on a loaded machine, and a kill that
    /// lands mid-write leaves the journal locked. After this returns, a kill
    /// leaves exactly what that checkpoint wrote.
    #[cfg(test)]
    pub(crate) async fn checkpointed(&mut self) {
        self.written
            .changed()
            .await
            .expect("the writer is still running");
    }
}

/// Starts checkpointing `journal` from `ctx`'s progress until told to stop.
pub fn spawn_checkpoints(journal: Journal, ctx: ScanProgress) -> Checkpointing {
    let (done, mut stop) = tokio::sync::oneshot::channel::<Vec<ScanPhase>>();
    #[cfg(test)]
    let (counted, written) = tokio::sync::watch::channel(0usize);

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
                    // A panicked checkpoint dropped the journal and its lock;
                    // there is nothing left to write.
                    let Ok(returned) = written.await else {
                        return;
                    };
                    writer = returned;
                    #[cfg(test)]
                    counted.send_modify(|count| *count += 1);
                }
                // A dropped signal means nobody joined the task: no phases to
                // record, but what is settled stays settled.
                finished = &mut stop => break finished.unwrap_or_default(),
            }
        };
        let _ = tokio::task::spawn_blocking(move || {
            let _ = writer.journal.end_sitting(&phases);
            writer.close(&ctx, &phases);
        })
        .await;
    });

    Checkpointing {
        done,
        task,
        #[cfg(test)]
        written,
    }
}

/// The journal a checkpoint task writes, and whether its last checkpoint
/// failed.
struct Writer {
    journal: Journal,
    /// Whether the last checkpoint failed, so a run of failures (a full disk,
    /// say) is reported once. Cleared by a successful checkpoint, so a later
    /// failure is reported again.
    failing: bool,
    /// What the open phase has concluded, as named beside the last cursor
    /// written; see [`Cut::so_far`].
    so_far: SoFar,
}

impl Writer {
    fn new(journal: Journal) -> Self {
        Self {
            journal,
            failing: false,
            so_far: SoFar::default(),
        }
    }

    /// Writes down what has changed and how far the scan got.
    ///
    /// A failed checkpoint does not end the scan, since the previous one still
    /// stands. It is recorded as a scan failure.
    fn checkpoint(&mut self, ctx: &ScanProgress) {
        let cut = Cut::take(ctx);
        self.write(ctx, cut);
    }

    /// Writes `cut`: the findings first and the cursor after, so a cursor is
    /// never on disk beside a findings file missing what it settled.
    fn write(&mut self, ctx: &ScanProgress, cut: Cut) {
        let journal = &mut self.journal;
        let outcome = if journal.should_compact() {
            // Taken after the cursor was read, so it covers everything the
            // cursor settled. A failed compaction leaves the file intact, and
            // appending still brings it up to date.
            journal
                .compact(&ctx.findings_snapshot())
                .or_else(|_| journal.record_hosts(&cut.changed))
        } else {
            journal.record_hosts(&cut.changed)
        }
        .and_then(|()| journal.write_cursor(&cut.cursor));

        // Hand the findings back for the next checkpoint, or a later cursor
        // would settle their targets with nothing on file.
        if outcome.is_err() {
            ctx.hand_back(&cut.changed);
        }

        // Silent addresses are named only once the cursor settling them is
        // written, or a resume would ask them again. Every other record awaiting
        // a verdict is named undecided, so none on disk counts as a host in the
        // job's report.
        let mut awaiting = cut.so_far.awaiting;
        if outcome.is_ok() {
            self.so_far = SoFar {
                awaiting: IpSet::new(),
                ..cut.so_far
            };
        }
        let mut named = IpSet::new();
        for range in &self.so_far.silent {
            named.insert_range(*range);
        }
        named.canonicalize();
        awaiting.subtract(&named);
        let standing = SoFar {
            awaiting,
            ..self.so_far.clone()
        };

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

        // Tapes and the standing record settle nothing, so their failures are
        // not folded into the outcome above. Tapes are handed back on failure,
        // since nothing captures them again; the standing record is rewritten
        // whole next time.
        let tapes = ctx.take_tapes();
        if self.journal.record_detections(&tapes).is_err() {
            ctx.hand_back_tapes(tapes);
        }
        let _ = self
            .journal
            .record_standing(&ctx.standing_phases(&standing));
    }

    /// Writes the sitting's last checkpoint and closes the journal.
    ///
    /// Where the job's phases heard nothing from some addresses, the findings
    /// are rewritten whole without them: an earlier checkpoint may have written
    /// their records before the phase decided they were silent. See `Unheard`.
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

/// What one checkpoint writes: the cursor, and the findings that changed.
struct Cut {
    cursor: Checkpoint,
    changed: Vec<Host>,
    /// What the open phase has concluded of records nothing answered at, with
    /// its silent addresses each settled in `cursor`. See
    /// [`ScanProgress::verdicts_so_far`].
    so_far: SoFar,
}

impl Cut {
    /// Reads the cursor, then takes the hosts that changed. The order matters;
    /// see the module documentation.
    fn take(ctx: &ScanProgress) -> Self {
        Self::taking(ctx, || {})
    }

    /// [`take`](Self::take), running `between` after the cursor is read and
    /// before the hosts are taken, for tests.
    fn taking(ctx: &ScanProgress, between: impl FnOnce()) -> Self {
        let cursor = ctx.settlements().checkpoint();
        between();
        let changed = ctx.take_changed_findings();
        let so_far = ctx.verdicts_so_far(&cursor);
        Self {
            cursor,
            changed,
            so_far,
        }
    }
}

/// The hosts this sitting finished every pass over, for
/// [`Journal::record_finished`]: none if it was stopped, otherwise every host
/// except those whose own budget ran out.
///
/// `phases` must be the sitting's phases as it closes. What a checkpoint wrote
/// of an open phase cannot say which passes finished.
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
/// An I/O error is reduced to its message, lower-cased and without the OS error
/// number, since the line already names the journal.
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
    /// with its finding or left for a resume to ask again. Dropping the writer
    /// without its closing write stands in for a killed process.
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
        // A strategy stores and settles the port between the two reads.
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
    /// can, or a later cursor would settle their targets with no record. Moving
    /// the findings file aside fails one write.
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

    /// A pass over a host that changed nothing writes no record. Write-back
    /// passes (correlation, posture, passive OS) touch every host, and a wide
    /// scan's file would grow with each.
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

    /// A checkpoint takes only a wide host's changed ports, and they read back as
    /// the whole host. Copying every port under the host's lock costs about half
    /// a second per checkpoint on a debug build.
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

        // One port changes later, as a re-probe or identification would.
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

    /// Detection tapes a checkpoint could not write are written by the next one
    /// that can, since nothing captures them again. A directory at the tapes'
    /// file name fails one write.
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
            host_name: None,
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

    /// A checkpoint whose write blocks holds none of the runtime's workers.
    ///
    /// The findings file is a named pipe, whose opening for writing blocks until
    /// something reads it, so the test decides how long the write takes. On the
    /// single worker `tokio::test` gives, a timer across the checkpoint would be
    /// late by that long if the write held the worker.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_checkpoint_that_blocks_does_not_hold_the_runtime() {
        use std::io::Read;
        use std::os::unix::ffi::OsStrExt;
        use std::time::{Duration, Instant};

        /// How long a stuck writer is left before the pipe is read anyway, so a
        /// regression fails the assertion below and does not hang.
        const RELEASED_AFTER: Duration = Duration::from_secs(20);

        let root = scratch("blocking");
        let plan = one_target();
        let journal = Journal::create(&root, &plan, Privilege::Raw, "test").expect("creates");
        let findings = journal.directory().join("hosts.jsonl");
        std::fs::remove_file(&findings).expect("removes the findings file");
        let name = std::ffi::CString::new(findings.as_os_str().as_bytes()).expect("a path");
        // SAFETY: `name` is a live, NUL-terminated path.
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

    /// A sitting killed outright leaves a record of its phase: its scope, how
    /// long it ran, and what failed. A killed sitting never reaches the point
    /// where phases are normally written.
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

    /// A killed sitting leaves its phase marked open and the job's report
    /// partial until a later sitting closes a phase of its kind. Unmarked, the
    /// phase would read as one that ran to its end.
    #[test]
    fn a_killed_sitting_marks_its_open_phase_and_the_report_partial() {
        let root = scratch("killed-open");
        let plan = one_target();
        let journal = Journal::create(&root, &plan, Privilege::Raw, "test").expect("creates");
        let directory = journal.directory().to_path_buf();
        let (_session, ctx) = crate::scanner::session::ScanSession::new();

        let _recorder = open_a_port_phase(&ctx);
        let mut writer = Writer::new(journal);
        writer.checkpoint(&ctx.progress());
        drop(writer);

        let report = crate::journal::store::report(&directory).expect("reads");
        assert!(
            report.phases()[0].is_open(),
            "the killed phase never closed"
        );
        assert!(
            report.is_partial(),
            "a job whose only sitting was killed reads as complete"
        );

        // A later sitting closes a phase of the same kind.
        let (mut resumed, _) = Journal::resume(&directory, &plan, Privilege::Raw).expect("resumes");
        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let closed = open_a_port_phase(&ctx).finish(&ctx);
        resumed.end_sitting(closed.phases()).expect("records");
        drop(resumed);

        let report = crate::journal::store::report(&directory).expect("reads");
        let open: Vec<bool> = report.phases().iter().map(ScanPhase::is_open).collect();
        assert_eq!(open, [true, false], "each sitting's phase as it ended");
        assert!(
            !report.is_partial(),
            "the resume finished what the kill left"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// A sitting that ends has its phases recorded once, and its standing record
    /// removed.
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

    /// A journal that cannot be written is reported once, in one short line,
    /// however many checkpoints fail after it.
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
