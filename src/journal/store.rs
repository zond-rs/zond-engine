// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # One scan's journal on disk
//!
//! ```text
//! <root>/<id>/
//!     manifest.json   the plan, written as the job begins
//!     cursor.json     how far the scan got, rewritten on a timer
//!     hosts.jsonl     what it found, appended as it finds it
//!     phases.jsonl    what each sitting did, appended as each one ends
//!     sitting-*.jsonl what a sitting has done so far, until it ends
//!     LOCK            who is writing, if anyone
//! ```
//!
//! The cursor is rewritten because it describes one state; the findings are appended
//! because they accumulate. A host that changes appears more than once and the records fold
//! together on reading, later over earlier, so a torn tail costs at most one host's latest
//! update.
//!
//! ## A host is written by what changed in it
//!
//! A record carries the whole host but only the ports that differ from what the file
//! already holds. A host scanned on every port holds tens of thousands of them, and writing
//! it whole on every change would be megabytes per checkpoint. Folding makes this safe: a
//! port's later record merges over its earlier one, and a port a record leaves out keeps
//! what the file says. What the file holds of each port is remembered as a digest, so
//! finding what changed costs no copy of the host.
//!
//! ## A sitting is written down before it ends
//!
//! A sitting's phases are appended to `phases.jsonl` when it stops, and a sitting killed
//! outright never stops. So each sitting also keeps its own file, named for when it started,
//! holding its phases as they stand: those closed and the open one so far. It is rewritten
//! whole at every checkpoint and removed once the phases are appended. One still present
//! when the journal is read is a sitting that never ended, and its phases are read with the
//! rest. A phase that never closed reports what it opened with, how long it ran and what
//! failed, claims nothing only its close could establish, and is marked open. A phase found
//! in both files, left by a sitting stopped between the append and the removal, is read
//! once.
//!
//! [`Journal::create`] begins one, [`Journal::resume`] continues one, and [`list`]
//! enumerates them for a caller offering a choice.
//!
//! A journal holds the addresses an engagement was pointed at, so everything is `0600`
//! under a `0700` directory, and a scan that runs elevated leaves it owned by the user who
//! invoked it. See [`paths`](super::paths).

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::cursor::Checkpoint;
use super::file::{
    append_existing, claim_directory_for_invoking_user, create_private as create_private_file,
    create_private_directory, exists, kinds, names, open_existing, open_to_read,
    remove as remove_file, remove_directory, replace,
};
use super::format::JournalError;
use super::lock::{Lock, LockRefused, LockState};
use super::manifest::{JobOptions, JournalManifest, Plan, PlanChanged};
use super::ownership::Kind;
use super::settle::Settlements;
use crate::detect::compute::{DetectionLine, DetectionRunRecord, PortRunsRecord};
use crate::model::host::Host;
use crate::model::ip::scoped::ScopedIp;
use crate::model::port::Protocol;
use crate::record::{HostRecord, PhaseRecord};
use crate::report::{ScanKind, ScanPhase, ScanReport, Unheard};
use crate::system::privilege::Privilege;

const MANIFEST: &str = "manifest.json";
const CURSOR: &str = "cursor.json";
const HOSTS: &str = "hosts.jsonl";
const PHASES: &str = "phases.jsonl";
const DETECTIONS: &str = "detections.jsonl";
/// The hosts each sitting that ran to its end had run every pass over. See
/// [`Journal::record_finished`].
const FINISHED: &str = "finished.jsonl";
const LOCK: &str = "LOCK";
/// Prefix of a sitting's own phases file, followed by when it started.
const SITTING: &str = "sitting-";
/// What the job runs under, written once, when its first sitting starts. See
/// [`Journal::options`].
const OPTIONS: &str = "options.json";

/// Why a journal could not be opened for writing.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The plan offered is not the plan this journal's positions are counted in.
    #[error("{0}")]
    PlanChanged(#[from] PlanChanged),

    /// The journal records the other phase of a scan.
    ///
    /// A sweep's positions count addresses and a port scan's count address-and-port
    /// pairs, so one continued as the other would skip targets nothing probed.
    #[error("this journal records a {held} and cannot be continued as a {asked}")]
    WrongPhase {
        /// The phase the journal holds.
        held: &'static str,
        /// The phase it was asked to continue as.
        asked: &'static str,
    },

    /// Somebody else holds it, or might.
    #[error("{0}")]
    Locked(LockRefused),

    /// The journal could not be read or written.
    #[error("{0}")]
    Journal(#[from] JournalError),
}

impl From<LockRefused> for OpenError {
    fn from(refused: LockRefused) -> Self {
        OpenError::Locked(refused)
    }
}

/// A journal open for writing.
///
/// Releases its lock on drop.
#[derive(Debug)]
pub struct Journal {
    directory: PathBuf,
    manifest: JournalManifest,
    lock: Lock,
    resume_point: Checkpoint,
    restored: Vec<Host>,
    earlier: Vec<ScanPhase>,
    /// Whether this handle made the journal or reopened one. See
    /// [`withdraw`](Journal::withdraw).
    created: bool,
    options: Option<JobOptions>,
    /// What the findings file holds of each host, and how much of it later records
    /// superseded. See [`record_hosts`](Journal::record_hosts).
    written: Written,
    /// How long the findings file is.
    length: u64,
    /// How much has to be superseded before a compaction is tried again after one
    /// failed. See [`compact`](Journal::compact).
    compact_after: u64,
    /// Where this sitting writes its phases as they stand. See the module
    /// documentation.
    sitting: PathBuf,
}

impl Journal {
    /// Begins a journal for `plan` under `root`, minting an id for it.
    ///
    /// The plan carries its phase, so a sweep and a port scan both come through here and
    /// neither can be read back as the other.
    pub fn create(
        root: &Path,
        plan: &Plan,
        privilege: Privilege,
        summary: impl Into<String>,
    ) -> Result<Self, OpenError> {
        let (id, directory) = claim_directory(root)?;
        let manifest = JournalManifest::new(id, plan, privilege, summary);

        // A scan that never started leaves no trace, whichever step failed, so every
        // failure past the claim is caught here. A leftover directory would list as a scan that
        // found nothing, or not list at all.
        match Self::furnish(&directory, manifest) {
            Ok(journal) => Ok(journal),
            Err(error) => {
                let _ = remove_directory(&directory);
                Err(error)
            }
        }
    }

    /// Everything [`create`](Self::create) does once the directory is claimed.
    ///
    /// Split out so a failure past the claim is caught in one place.
    fn furnish(directory: &Path, manifest: JournalManifest) -> Result<Self, OpenError> {
        write_private(
            &directory.join(MANIFEST),
            &serde_json::to_vec(&manifest).map_err(JournalError::json)?,
        )?;

        let lock = Lock::acquire(&directory.join(LOCK))?;
        let sitting = sitting_file(directory, &lock);

        let mut journal = Self {
            directory: directory.to_path_buf(),
            manifest,
            lock,
            resume_point: Checkpoint::default(),
            restored: Vec::new(),
            earlier: Vec::new(),
            created: true,
            options: None,
            written: Written::default(),
            length: 0,
            compact_after: 0,
            sitting,
        };
        journal.open_findings()?;
        journal.length = findings_length(directory)?;
        Ok(journal)
    }

    /// Continues the journal at `directory`, refusing a plan that has moved or a
    /// scan somebody else is running.
    ///
    /// Returns the checkpoint to subtract from the plan; feed it to
    /// [`Checkpoint::remaining`] and to [`Settlements::resuming`].
    pub fn resume(
        directory: &Path,
        plan: &Plan,
        privilege: Privilege,
    ) -> Result<(Self, Checkpoint), OpenError> {
        Self::resume_locking(directory, plan, privilege, Lock::acquire)
    }

    /// [`resume`](Self::resume), taking the lock by `lock`.
    fn resume_locking(
        directory: &Path,
        plan: &Plan,
        privilege: Privilege,
        lock: fn(&Path) -> Result<Lock, LockRefused>,
    ) -> Result<(Self, Checkpoint), OpenError> {
        let manifest = read_manifest(directory)?;
        // The phase before the fingerprint, so continuing a sweep as a port scan is named
        // as such and not reported as a moved plan.
        if manifest.kind() != plan.kind() {
            return Err(OpenError::WrongPhase {
                held: phase_name(manifest.kind()),
                asked: phase_name(plan.kind()),
            });
        }
        // The plan next, before taking the lock, so a mistaken resume disturbs nothing.
        manifest.covers(plan, privilege)?;

        let lock = lock(&directory.join(LOCK))?;
        let sitting = sitting_file(directory, &lock);
        let checkpoint = read_checkpoint(directory)?;
        let earlier = read_phases(directory)?;
        // Drop the records earlier sittings heard nothing from, as a report of the job
        // does, except those a sitting killed before its verdicts left for this one to decide;
        // see `Unheard::decided`.
        let unheard = Unheard::decided(&earlier);
        let mut restored = read_findings(directory)?;
        restored.retain(|host| !unheard.drops(host));
        // What the file already holds, so a restored host this sitting changes is written
        // by its changes. Anything in the file beyond what those fold to is superseded records. An
        // empty file left by an earlier sitting counts as no length.
        let length = findings_length(directory)?;
        let written = Written::holding(&restored, length)?;

        Ok((
            Self {
                directory: directory.to_path_buf(),
                manifest,
                lock,
                resume_point: checkpoint.clone(),
                restored,
                earlier,
                created: false,
                options: read_options(directory)?,
                written,
                length,
                compact_after: 0,
                sitting,
            },
            checkpoint,
        ))
    }

    /// Continues the journal at `directory`, scanning the plan it recorded.
    ///
    /// The counterpart of [`resume`](Self::resume) for a caller who has only the
    /// scan's id. The plan comes back as recorded, phase included, so a hostname that has moved
    /// does not change what is continued, and a caller can see which phase it has before
    /// starting.
    ///
    /// Refused if this process holds different privileges than the scan did: the connect
    /// fallback asks a different question than a raw technique.
    pub fn reopen(
        directory: &Path,
        privilege: Privilege,
    ) -> Result<(Self, Checkpoint, Plan), OpenError> {
        let plan = read_manifest(directory)?.recorded();
        let (journal, checkpoint) = Self::resume(directory, &plan, privilege)?;
        Ok((journal, checkpoint, plan))
    }

    /// [`reopen`](Self::reopen), taking over a lock whose holder has stopped
    /// checkpointing.
    ///
    /// For the refusal [`LockState::Stale`] names: a live process holds the recorded
    /// number, and nothing here can tell whether it is the hung scan or an unrelated process the
    /// number was reissued to. A caller who knows can continue the job here without removing
    /// the lock by hand. A lock whose holder is checkpointing now is still refused. See
    /// [`Lock::take_over`].
    pub fn take_over(
        directory: &Path,
        privilege: Privilege,
    ) -> Result<(Self, Checkpoint, Plan), OpenError> {
        let plan = read_manifest(directory)?.recorded();
        let (journal, checkpoint) =
            Self::resume_locking(directory, &plan, privilege, Lock::take_over)?;
        Ok((journal, checkpoint, plan))
    }

    /// What earlier sittings of this scan found.
    ///
    /// Empty for a journal just created. A scan seeds its store with these, so its
    /// report describes the whole job.
    ///
    /// A record of an address an earlier sitting went on to hear nothing from is left out, as
    /// the job's report leaves it out. One that a sitting killed before its port phase's
    /// verdicts had yet to decide is included (the report leaves it out too): this sitting asks
    /// what is left at the address and decides it.
    pub fn restored(&self) -> &[Host] {
        &self.restored
    }

    /// Appends what `hosts` currently hold that the file does not.
    ///
    /// Called with what
    /// [`take_changed_hosts`](crate::scanner::session::ScanContext::take_changed_hosts) yields,
    /// so a host is written once per change. Each record carries the host's own fields and only
    /// the ports that changed since the file last held them; see the module documentation. A
    /// host may carry only some of its ports, and those it leaves out stand as the file holds
    /// them. A host the file already holds unchanged gets no record.
    ///
    /// What was written is remembered only after the write succeeds, so a failed write leaves
    /// every port it carried to be written again.
    pub fn record_hosts(&mut self, hosts: &[Host]) -> Result<(), JournalError> {
        let mut records = Vec::with_capacity(hosts.len());
        for host in hosts {
            records.extend(self.written.delta(host)?);
        }
        if records.is_empty() {
            return Ok(());
        }

        let file = open_for_append(&self.directory.join(HOSTS))?;
        // Measured on the handle, as a compaction measures what it wrote.
        let measured = file.try_clone()?;

        let mut deltas = Vec::with_capacity(records.len());
        let mut writer = crate::journal::format::Writer::append(std::io::BufWriter::new(file));
        for (record, delta) in records {
            writer.write(&record)?;
            deltas.push(delta);
        }
        writer.flush()?;
        drop(writer);

        for delta in deltas {
            self.written.update(delta);
        }
        self.length = measured.metadata()?.len();
        Ok(())
    }

    /// Appends the tapes of detection runs, each recording what one detection read from
    /// its capabilities so the run can be replayed offline.
    ///
    /// One port per line, the responses the port's runs read held once for all of them; see
    /// `PortRunsRecord`. [`read_detections`] hands each run back whole.
    ///
    /// Its own file, created on the first run. The resume path never reads it: a tape is
    /// evidence for later analysis, not a settled verdict.
    ///
    /// All or nothing: a write that fails part way is cut back to where it began, so a caller
    /// that retries the same runs records each once.
    pub fn record_detections(&mut self, runs: &[DetectionRunRecord]) -> Result<(), JournalError> {
        if runs.is_empty() {
            return Ok(());
        }

        // Append first and create only on `NotFound`. `create_private` refuses an existing
        // name, so losing a race between two writers is reported, not a truncation.
        let path = self.directory.join(DETECTIONS);
        let (file, mut writer) = match open_for_append(&path) {
            Ok(file) => {
                let written = file.try_clone()?;
                let writer =
                    crate::journal::format::Writer::append(std::io::BufWriter::new(written));
                (file, writer)
            }
            Err(JournalError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let file = create_private_file(&path)?;
                let written = file.try_clone()?;
                let writer =
                    crate::journal::format::Writer::create(std::io::BufWriter::new(written))?;
                (file, writer)
            }
            Err(error) => return Err(error),
        };
        // Where this write begins: past the header a new file was just given, which a
        // cut-back write keeps.
        writer.flush()?;
        let began = file.metadata()?.len();
        let outcome = PortRunsRecord::grouping(runs)
            .iter()
            .try_for_each(|line| writer.write(line))
            .and_then(|()| writer.flush());
        if outcome.is_err() {
            // Dropped first, since dropping flushes the buffer, then everything past the start
            // is cut. A failed cut leaves a torn tail, which the next append mends.
            drop(writer);
            let _ = file.set_len(began);
        }
        outcome
    }

    /// Appends that a sitting ran every pass that follows its probes over
    /// `hosts`, each named as its address and link are written.
    ///
    /// For a sitting that ran to its end, whose passes each finished over every host it
    /// held. A later sitting reads these through [`finished_hosts`](Self::finished_hosts) and
    /// reruns those passes only over what it asks something new of. Without this, a job resumed
    /// after it was done would redo service identification, detection, TLS and route tracing
    /// for every host.
    ///
    /// Its own file, created on the first record, so a journal from an older engine reads as one
    /// no sitting finished, and an older engine ignores it.
    pub(crate) fn record_finished(
        &mut self,
        hosts: impl IntoIterator<Item = String>,
    ) -> Result<(), JournalError> {
        let record = FinishedRecord {
            hosts: hosts.into_iter().collect(),
        };
        if record.hosts.is_empty() {
            return Ok(());
        }

        // Created on `NotFound`, as in `record_detections`.
        let path = self.directory.join(FINISHED);
        let mut writer = match open_for_append(&path) {
            Ok(file) => crate::journal::format::Writer::append(std::io::BufWriter::new(file)),
            Err(JournalError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let file = create_private_file(&path)?;
                crate::journal::format::Writer::create(std::io::BufWriter::new(file))?
            }
            Err(error) => return Err(error),
        };
        writer.write(&record)?;
        writer.flush()
    }

    /// Every host an earlier sitting that ran to its end had finished every pass over,
    /// named as [`record_finished`](Self::record_finished) wrote it.
    ///
    /// Empty for a journal no sitting finished or one without the record, which a resume reads
    /// as owing every pass to every host.
    pub(crate) fn finished_hosts(&self) -> Result<HashSet<String>, JournalError> {
        let file = match open_to_read(&self.directory.join(FINISHED)) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
            Err(e) => return Err(e.into()),
        };
        let mut reader = match crate::journal::format::Reader::open(std::io::BufReader::new(file)) {
            Ok(reader) => reader,
            Err(JournalError::NotAJournal) => return Ok(HashSet::new()),
            Err(e) => return Err(e),
        };

        let mut hosts = HashSet::new();
        while let Some(record) = reader.read::<FinishedRecord>()? {
            hosts.extend(record.hosts);
        }
        Ok(hosts)
    }

    /// Whether the findings file holds enough superseded records to be worth rewriting.
    ///
    /// The dispatcher shuffles targets across the whole plan, so on a long scan most hosts
    /// change in most intervals. Ports are written only as they change, but each record repeats
    /// the host's own fields, so the file grows with the scan's duration. Compaction bounds it.
    ///
    /// Counted in bytes of superseded records, since that is what a rewrite costs and recovers;
    /// a file growing by new findings holds nothing a rewrite would drop. The file is rewritten
    /// once the superseded part outgrows the rest, so it stays under twice its live size and
    /// each compaction is paid for by at least as much superseded since the last. Below a floor
    /// it is never worth rewriting.
    pub fn should_compact(&self) -> bool {
        outgrown(self.length, self.written.superseded)
            && self.written.superseded >= self.compact_after
    }

    /// Writes the findings file whole, replacing everything superseded.
    ///
    /// `all` must be every host the scan has found, since this replaces the file.
    /// Written to a sibling and renamed over, so an interrupted compaction leaves the previous
    /// file untouched.
    ///
    /// A failed compaction removes its sibling, and [`should_compact`](Self::should_compact)
    /// does not ask again until as much again has been superseded. The usual cause, a disk with
    /// no room for a second copy, would otherwise recur every checkpoint, rewriting the live
    /// findings every few seconds into whatever room was left.
    pub fn compact(&mut self, all: &[Host]) -> Result<(), JournalError> {
        let compacted = self.write_whole(all);
        if compacted.is_err() {
            let superseded = self.written.superseded;
            let live = self.length.saturating_sub(superseded);
            self.compact_after = superseded.saturating_add(COMPACT_FLOOR.max(live));
        }
        compacted
    }

    /// [`compact`](Self::compact)'s writing, through a staged sibling that a
    /// failure removes.
    fn write_whole(&mut self, all: &[Host]) -> Result<(), JournalError> {
        let destination = self.directory.join(HOSTS);
        let (written, length) = replace(
            &destination,
            &destination.with_extension("jsonl-tmp"),
            |file| {
                // Measured on the handle, so the length is the written file's and not whatever
                // the name holds by then.
                let measured = file.try_clone()?;
                let mut written = Written::default();
                let mut writer =
                    crate::journal::format::Writer::create(std::io::BufWriter::new(file))?;
                for host in all {
                    // Measured against nothing written, so the record is the whole host.
                    if let Some((record, delta)) = Written::default().delta(host)? {
                        writer.write(&record)?;
                        written.update(delta);
                    }
                }
                writer.flush()?;
                drop(writer);
                Ok::<_, JournalError>((written, measured.metadata()?.len()))
            },
        )?;
        self.written = written;
        self.length = length;
        self.compact_after = 0;
        Ok(())
    }

    /// What earlier sittings of this scan did.
    ///
    /// A resumed report carries these alongside its own, so it describes a job that ran
    /// in several sittings.
    pub fn earlier_phases(&self) -> &[ScanPhase] {
        &self.earlier
    }

    /// Appends what one sitting did, once it has finished doing it.
    pub fn record_phases(&mut self, phases: &[ScanPhase]) -> Result<(), JournalError> {
        if phases.is_empty() {
            return Ok(());
        }

        let file = open_for_append(&self.directory.join(PHASES))?;

        let mut writer = crate::journal::format::Writer::append(std::io::BufWriter::new(file));
        for phase in phases {
            writer.write(&PhaseRecord::from(phase))?;
        }
        writer.flush()
    }

    /// Writes down this sitting's phases as they stand, over what it wrote last. See
    /// the module documentation.
    ///
    /// Written to a sibling and renamed over, as the cursor is, so a sitting killed part way
    /// leaves the previous record whole.
    pub(crate) fn record_standing(&mut self, phases: &[ScanPhase]) -> Result<(), JournalError> {
        if phases.is_empty() {
            return Ok(());
        }
        replace(
            &self.sitting,
            &self.sitting.with_extension("jsonl-tmp"),
            |file| {
                let mut writer =
                    crate::journal::format::Writer::create(std::io::BufWriter::new(file))?;
                for phase in phases {
                    writer.write(&PhaseRecord::from(phase))?;
                }
                writer.flush()
            },
        )
    }

    /// Appends what one sitting did once it has finished, and removes its standing
    /// record of its phases.
    ///
    /// The removal waits for the append to land, since until then the standing record is the
    /// only one.
    pub(crate) fn end_sitting(&mut self, phases: &[ScanPhase]) -> Result<(), JournalError> {
        if phases.is_empty() {
            return Ok(());
        }
        self.record_phases(phases)?;
        match remove_file(&self.sitting) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Writes the appended files' headers, so each is self-describing before
    /// anything is added to it.
    fn open_findings(&mut self) -> Result<(), JournalError> {
        for name in [HOSTS, PHASES] {
            let path = self.directory.join(name);
            let file = create_private_file(&path)?;
            crate::journal::format::Writer::create(std::io::BufWriter::new(file))?.flush()?;
        }
        Ok(())
    }

    /// What an earlier sitting settled, and this one may skip.
    ///
    /// Empty for a journal just created. A scan seeds both its dispatcher and its
    /// settlements from this, so the second sitting's cursor continues the first's.
    pub fn resume_point(&self) -> &Checkpoint {
        &self.resume_point
    }

    /// Writes how far the scan has got, and reports the writer is alive.
    ///
    /// Cheap enough to call on a timer: the cursor is small however large the scan,
    /// and the write is a rename over a small file. See [`Checkpoint::write_atomically`].
    pub fn checkpoint(&mut self, settlements: &Settlements) -> Result<(), JournalError> {
        self.write_cursor(&settlements.checkpoint())
    }

    /// Writes `cursor` as how far the scan has got, and reports the writer is alive.
    ///
    /// For a writer that read the cursor before taking the findings it writes beside it, the
    /// order a running scan needs; see [`checkpoint`](crate::scanner::checkpoint).
    pub(crate) fn write_cursor(&mut self, cursor: &Checkpoint) -> Result<(), JournalError> {
        cursor.write_atomically(&self.directory.join(CURSOR))?;
        self.lock.beat()
    }

    /// Writes down what the scan has found and how far it has got.
    ///
    /// Findings first: a cursor claiming a target settled beside a file missing its
    /// finding loses that finding, while the other way round only probes a target twice.
    ///
    /// The cursor is read here, after `hosts` were taken, which suits a scan that has stopped
    /// settling targets. While one is running a target can settle between the two readings
    /// with its finding in neither, so the scanner's own checkpoints read the cursor first.
    pub fn record(
        &mut self,
        hosts: &[Host],
        settlements: &Settlements,
    ) -> Result<(), JournalError> {
        self.record_hosts(hosts)?;
        self.checkpoint(settlements)
    }

    /// The options the job runs under, or `None` where they were never recorded.
    ///
    /// Recorded when the journal's first sitting starts, from its configuration, and never
    /// rewritten. A later sitting is held to them, and a caller continuing a job by its id
    /// restores them with [`JobOptions::apply_to`]; the type says which options those are.
    ///
    /// `None` for a journal whose first sitting ran on an engine that did not record them
    /// (continued under whatever the caller passes), for one no sitting has started, and for a
    /// watch, which has nothing for them to decide.
    pub fn options(&self) -> Option<&JobOptions> {
        self.options.as_ref()
    }

    /// Records the options the job runs under, if this is its first sitting.
    ///
    /// A journal an earlier sitting ran against without recording options ran under unknown
    /// ones, and recording this sitting's would misdescribe it.
    ///
    /// Every sitting numbers the plan without the excluded ports, so the manifest's total,
    /// written before they were known, is recounted here. Counted in, they would be a remainder
    /// nothing reaches: a finished job would stay unfinished and a resume would announce probes
    /// it will not send. Only rewritten in a manifest this handle wrote, since rewriting another
    /// build's would drop fields this one does not know.
    pub(crate) fn record_options(&mut self, options: JobOptions) -> Result<(), JournalError> {
        if self.options.is_some() || !self.is_untouched() {
            return Ok(());
        }

        write_private(
            &self.directory.join(OPTIONS),
            &serde_json::to_vec(&options).map_err(JournalError::json)?,
        )?;
        let numbered = self
            .manifest
            .recorded()
            .numbered_targets(&options.excluded_ports());
        self.options = Some(options);
        if self.created && numbered != self.manifest.total_targets {
            self.manifest.total_targets = numbered;
            write_private(
                &self.directory.join(MANIFEST),
                &serde_json::to_vec(&self.manifest).map_err(JournalError::json)?,
            )?;
        }
        Ok(())
    }

    /// Whether no sitting has run against this journal: no cursor written, no phase
    /// and no finding recorded.
    ///
    /// A cursor that cannot be looked for counts as present. This decides whether to write the
    /// job's options and whether to remove the journal, and wrongly calling it touched costs
    /// only the options record, while wrongly calling it untouched could lose a sitting's
    /// work.
    fn is_untouched(&self) -> bool {
        self.earlier.is_empty()
            && self.restored.is_empty()
            && !exists(&self.directory.join(CURSOR)).unwrap_or(true)
    }

    /// What this journal is a journal of.
    pub fn manifest(&self) -> &JournalManifest {
        &self.manifest
    }

    /// Where it lives.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Gives up a journal handed to a scan that refused before it started, and removes
    /// it if no sitting ever ran against it.
    ///
    /// A scan that never started leaves no trace, as in [`create`](Self::create). Kept, the
    /// record would list as a resumable job with nothing done and count against a front end's
    /// record limit, and the caller cannot tidy it since the journal was handed over by value.
    ///
    /// Only a journal this handle made and no sitting has touched (no cursor, phase or finding)
    /// is removed. One an earlier sitting ran against holds its work, and one reopened was kept
    /// by whoever made it; either is released for the next sitting.
    ///
    /// Removed while the lock is held, so nothing takes the journal up in between. The lock
    /// file goes with the directory, and the following drop tolerates finding nothing.
    pub(crate) fn withdraw(self) {
        if self.created && self.is_untouched() {
            // Best effort, as in `create`.
            let _ = remove_directory(&self.directory);
        }
    }

    /// Releases the lock, reporting a failure the drop would swallow.
    pub fn close(self) -> Result<(), JournalError> {
        self.lock.release()
    }
}

/// Whether a findings file `length` bytes long, `superseded` of them superseded, is
/// due to be rewritten. See [`Journal::should_compact`].
fn outgrown(length: u64, superseded: u64) -> bool {
    superseded > COMPACT_FLOOR.max(length.saturating_sub(superseded))
}

/// The size below which a findings file is not worth rewriting.
const COMPACT_FLOOR: u64 = 4 * 1024 * 1024;

/// What a journal's findings file holds of each host, and how many of its
/// bytes later records superseded.
///
/// Each port is remembered as a digest of the record last written for it, a few
/// bytes a port. Kept in memory only, so the hasher need not be stable across builds.
///
/// Sizes are of each piece as serialised, within a separator of the line; they feed a
/// threshold, not an account.
#[derive(Debug, Default)]
struct Written {
    hosts: std::collections::HashMap<ScopedIp, HeldHost>,
    /// How many of the file's bytes hold what a later record superseded.
    superseded: u64,
}

/// What the findings file holds of one host.
#[derive(Debug, Default)]
struct HeldHost {
    /// Its last record, less its ports.
    rest: Option<Mark>,
    ports: std::collections::HashMap<PortKey, Mark>,
}

/// A port as a host keys it: its number and its transport.
type PortKey = (u16, Protocol);

/// A record as written: a digest of it, and how long it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mark {
    digest: u64,
    length: u32,
}

/// What one record wrote of one host, to remember once the write succeeds.
#[derive(Debug)]
struct Delta {
    key: ScopedIp,
    rest: Mark,
    ports: Vec<(PortKey, Mark)>,
}

impl Delta {
    /// How many bytes the record holds, near enough.
    fn length(&self) -> u64 {
        u64::from(self.rest.length)
            + self
                .ports
                .iter()
                .map(|(_, mark)| u64::from(mark.length))
                .sum::<u64>()
    }
}

impl Written {
    /// What a file `length` bytes long holds, where `hosts` are what it folds to: those
    /// whole, and the rest superseded.
    fn holding(hosts: &[Host], length: u64) -> Result<Self, JournalError> {
        let mut written = Self::default();
        let mut live = 0;
        for host in hosts {
            // Against nothing written, the record is the whole host.
            if let Some((_, delta)) = Self::default().delta(host)? {
                live += delta.length();
                written.update(delta);
            }
        }
        written.superseded = length.saturating_sub(live);
        Ok(written)
    }

    /// `host` as a record carrying only the ports whose record differs from what was last
    /// written of them, with what writing it would hold; `None` where the file already holds
    /// all of it.
    ///
    /// Compared, not trusted: a host is marked changed by whatever edited it, and an edit that
    /// confirmed what was on record (a finding reached again, a service named as before)
    /// changes nothing a record would carry.
    fn delta(&self, host: &Host) -> Result<Option<(HostRecord, Delta)>, JournalError> {
        let held = self.hosts.get(&host.scoped_ip());
        let mut record = HostRecord::from(host);
        // `HostRecord` lists the ports in the order the host yields them, so the two zip.
        let ports = std::mem::take(&mut record.ports);
        let rest = mark(&record)?;
        let mut changed = Vec::new();
        for (port, written) in host.ports().zip(ports) {
            debug_assert_eq!(
                port.number(),
                written.port,
                "a record lists its host's ports"
            );
            let key = (port.number(), port.protocol());
            let mark = mark(&written)?;
            let unchanged = held
                .and_then(|held| held.ports.get(&key))
                .is_some_and(|was| was.digest == mark.digest);
            if !unchanged {
                changed.push((key, mark));
                record.ports.push(written);
            }
        }
        let unchanged = changed.is_empty()
            && held.and_then(|held| held.rest).map(|was| was.digest) == Some(rest.digest);
        if unchanged {
            return Ok(None);
        }
        let delta = Delta {
            key: host.scoped_ip(),
            rest,
            ports: changed,
        };
        Ok(Some((record, delta)))
    }

    /// Records that the file holds what `delta` wrote over that host, and counts what it
    /// superseded.
    fn update(&mut self, delta: Delta) {
        let held = match self.hosts.entry(delta.key) {
            std::collections::hash_map::Entry::Occupied(slot) => {
                let held = slot.into_mut();
                self.superseded += held.rest.map_or(0, |was| u64::from(was.length));
                held
            }
            std::collections::hash_map::Entry::Vacant(slot) => slot.insert(HeldHost::default()),
        };
        held.rest = Some(delta.rest);
        for (key, mark) in delta.ports {
            if let Some(was) = held.ports.insert(key, mark) {
                self.superseded += u64::from(was.length);
            }
        }
    }
}

/// A digest and length of `record` as serialised, the same bytes the file gets, fed
/// to a hasher.
fn mark(record: &impl serde::Serialize) -> Result<Mark, JournalError> {
    use std::hash::Hasher;

    struct Hashing {
        hasher: std::collections::hash_map::DefaultHasher,
        length: u64,
    }
    impl std::io::Write for Hashing {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.hasher.write(bytes);
            self.length += bytes.len() as u64;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut hashing = Hashing {
        hasher: std::collections::hash_map::DefaultHasher::new(),
        length: 0,
    };
    serde_json::to_writer(&mut hashing, record).map_err(JournalError::json)?;
    Ok(Mark {
        digest: hashing.hasher.finish(),
        // Plus a separator or newline; saturated past four gigabytes, beyond what a
        // journal line is read in.
        length: u32::try_from(hashing.length + 1).unwrap_or(u32::MAX),
    })
}

/// A journal as it appears to a caller choosing between them. Read without taking
/// the lock, so listing never disturbs a running scan.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Entry {
    /// Where it lives.
    pub directory: PathBuf,
    /// What it is a journal of.
    pub manifest: JournalManifest,
    /// How far it got, or `None` where that could not be read.
    ///
    /// A journal that never checkpointed carries a fresh cursor. `None` means the file
    /// is there and this process cannot read it, usually because the scan ran under `sudo`; it
    /// must not read as no progress, or a listing would offer to continue finished work.
    pub checkpoint: Option<Checkpoint>,
    /// Whether anything is writing it.
    pub lock: LockState,
}

impl Entry {
    /// A listing entry from its parts, for a caller rendering one it did not read off
    /// disk.
    pub fn new(
        directory: PathBuf,
        manifest: JournalManifest,
        checkpoint: Option<Checkpoint>,
        lock: LockState,
    ) -> Self {
        Self {
            directory,
            manifest,
            checkpoint,
            lock,
        }
    }

    /// Whether this journal has anything left to do.
    ///
    /// A journal whose cursor covers the whole plan is finished; one that never
    /// checkpointed has everything left. One whose cursor cannot be read is not finished, which
    /// keeps a retention sweep from deleting it.
    pub fn is_complete(&self) -> bool {
        // A watch is never finished: its total is zero, so by the arithmetic below it would
        // be complete when created. Another sitting can always be appended.
        if self.kind() == ScanKind::Listen {
            return false;
        }

        self.settled()
            .is_some_and(|settled| settled >= self.manifest.total_targets)
    }

    /// Which phase this journal records.
    ///
    /// A sweep and a port scan count in different units, so a caller reporting progress
    /// needs to know which this is.
    pub fn kind(&self) -> ScanKind {
        self.manifest.kind()
    }

    /// How many targets are settled, or `None` where the cursor could not be
    /// read.
    ///
    /// [`Checkpoint::settled_count`], which counts a listed position a watermark has
    /// passed once, as [`Cursor::from_checkpoint`](super::cursor::Cursor::from_checkpoint)
    /// does. `Checkpoint::read` keeps such entries, so without that a damaged list would be
    /// double-counted here, and [`is_complete`](Self::is_complete) could tip to `true`, which is
    /// what a retention sweep deletes on.
    pub fn settled(&self) -> Option<u128> {
        self.checkpoint
            .as_ref()
            .map(|checkpoint| u128::from(checkpoint.settled_count()))
    }
}

/// Creates the directory journals are kept in, and gives it to the user who
/// invoked an elevated run.
///
/// Call this before [`Journal::create`].
///
/// Raw strategies need root, so the first run on a machine is usually under `sudo`, and
/// [`paths::root`](super::paths::root) resolves the invoking user's home. The two
/// directories above each scan's directory are then created by root, and claiming a scan's
/// directory does not give them away. Left to root, every later unprivileged run, such as a
/// listening phase, finds a directory it cannot write to and silently records nothing.
///
/// The two directories are claimed whether or not this call created them, so an existing
/// installation left to root is repaired too. Claiming an already correct directory is a
/// `chown` to its current owner.
///
/// Above those two, what this call created is given too: a first run with no
/// `~/.local/state` creates it and `~/.local`. One already there belongs to whoever made it,
/// unless root owns it, the sign of an elevated run that gave nothing back; see the
/// `ownership` module.
///
/// Nothing outside the invoking user's home is given: a state root kept through `sudo`
/// that points elsewhere stays root's.
///
/// Best effort: a directory that cannot be given away is not worth failing a scan over, and
/// an unprivileged run has nobody to give it to.
pub fn prepare_root(root: &Path) -> std::io::Result<()> {
    let own = super::paths::root().as_deref() == Some(root);
    #[cfg(unix)]
    let home = super::ownership::invoking().map(|user| user.home.as_path());
    #[cfg(not(unix))]
    let home = None;
    prepare_root_with(root, own, home, |path, hand| match hand {
        Hand::Give => claim_directory_for_invoking_user(path),
        Hand::Reclaim => super::ownership::reclaim(path),
    })
}

/// What [`prepare_root`] does with one directory on the way to a root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hand {
    /// Gives it to the invoking user, whoever owns it now.
    Give,
    /// Gives it back only if root owns it.
    Reclaim,
}

/// [`prepare_root`] with the claim passed in, so a test can see what would be given
/// without an elevated process.
///
/// `own` says `root` is this crate's own location, the one case where what lies above it
/// may have been created by this engine on the user's behalf. A location a caller named
/// says where to write, not what lies above it.
///
/// `home` is the invoking user's, `None` for a run on nobody else's behalf; the directories
/// between it and the root are the ones a repair looks at.
fn prepare_root_with(
    root: &Path,
    own: bool,
    home: Option<&Path>,
    mut claim: impl FnMut(&Path, Hand),
) -> std::io::Result<()> {
    let created = super::ownership::create_missing(root, None)?;

    if own && let Some(above) = root.parent() {
        // Outermost first, as they were created.
        let mut between: Vec<&Path> = above
            .ancestors()
            .skip(1)
            .take_while(|directory| {
                home.is_some_and(|home| *directory != home && directory.starts_with(home))
            })
            .collect();
        between.reverse();
        for directory in between {
            let hand = if created.iter().any(|made| made == directory) {
                Hand::Give
            } else {
                Hand::Reclaim
            };
            claim(directory, hand);
        }
        claim(above, Hand::Give);
    }
    claim(root, Hand::Give);

    Ok(())
}

/// Every journal under a root, and everything standing there that could not be
/// listed.
///
/// What was passed over is returned as data so the caller decides how to report it: a
/// listing a person reads wants one line for ninety journals a newer build wrote, and a
/// prune wants their directories.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct Listing {
    /// The journals this build can read, newest first.
    pub entries: Vec<Entry>,
    /// What stands in the root as a journal would but could not be read as one.
    pub passed_over: Vec<PassedOver>,
}

/// Something in a root of journals that [`list`] could not list, and why.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassedOver {
    /// Its name in the root, which for a journal is its id.
    pub name: String,
    /// Where it stands.
    pub directory: PathBuf,
    /// Why it could not be listed.
    pub why: Unlisted,
}

impl PassedOver {
    /// A passed-over entry from its parts, for a caller rendering one it did not read
    /// off disk.
    pub fn new(name: impl Into<String>, directory: PathBuf, why: Unlisted) -> Self {
        Self {
            name: name.into(),
            directory,
            why,
        }
    }
}

/// Why [`list`] passed something over.
///
/// A kind, so a caller can report it once for a whole root: a machine that ran a
/// newer build has every journal it wrote passed over for the same reason.
/// [`fmt::Display`](std::fmt::Display) gives the sentence for one.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unlisted {
    /// A link, not a directory.
    ///
    /// Every journal is a directory this crate made, so a link is none, and [`prune`] never
    /// removes one: under `sudo` a removal that followed it would be root's.
    Link,
    /// A journal whose manifest names a format newer than this build's.
    NewerFormat {
        /// The format the manifest names.
        found: u32,
    },
    /// A manifest that could not be read or parsed, in the failure's words: a missing
    /// permission, a file cut short.
    Unreadable(String),
}

impl std::fmt::Display for Unlisted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Link => f.write_str("a link, not a journal (not followed)"),
            Self::NewerFormat { found } => write!(
                f,
                "journal format {found} is newer than this build's ({})",
                super::JOURNAL_VERSION
            ),
            Self::Unreadable(reason) => f.write_str(reason),
        }
    }
}

/// Every journal under `root`, newest first, and what was passed over.
///
/// One unreadable journal does not hide the rest: it is returned in
/// [`Listing::passed_over`] with the reason (a newer format, a link where a journal should
/// be, a read failure), which its owner has to act on. A directory holding no manifest is
/// skipped silently, as one a scan starting now has yet to write.
///
/// An empty listing for a root that does not exist yet.
pub fn list(root: &Path) -> Result<Listing, JournalError> {
    let held = match kinds(root) {
        Ok(held) => held,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Listing::default()),
        Err(e) => return Err(e.into()),
    };

    let mut listing = Listing::default();
    for (name, kind) in held {
        let directory = root.join(&name);
        let name = name.to_string_lossy().into_owned();
        match kind {
            Kind::Directory => {}
            Kind::Link => {
                listing.passed_over.push(PassedOver {
                    name,
                    directory,
                    why: Unlisted::Link,
                });
                continue;
            }
            Kind::Other => continue,
        }
        let manifest = match read_manifest(&directory) {
            Ok(manifest) => manifest,
            Err(JournalError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                let why = match e {
                    JournalError::VersionTooNew { found, .. } => Unlisted::NewerFormat { found },
                    // The system's words alone; whoever renders this says whose they are.
                    JournalError::Io(e) => Unlisted::Unreadable(e.to_string()),
                    other => Unlisted::Unreadable(other.to_string()),
                };
                listing.passed_over.push(PassedOver {
                    name,
                    directory,
                    why,
                });
                continue;
            }
        };
        listing.entries.push(Entry {
            // `Err` is a cursor that exists and could not be read, recorded as `None`. A
            // journal that never checkpointed gets a fresh cursor from `read_checkpoint`.
            checkpoint: read_checkpoint(&directory).ok(),
            lock: super::lock::inspect(&directory.join(LOCK)),
            manifest,
            directory,
        });
    }

    listing
        .entries
        .sort_by_key(|entry| std::cmp::Reverse(entry.manifest.created_at));
    listing.passed_over.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(listing)
}

/// The scan at `directory`, as the report it would have produced.
///
/// A journal holds everything a report is made of, so a finished scan can be read
/// back as it was when it ended: the hosts, the phases in the order they ran, and the engine
/// version from the manifest, so a scan run by an older engine still says so.
///
/// Read without the lock, like [`list`], so it is safe on a running scan; the result is then
/// a checkpoint behind the live one.
///
/// A journal missing its findings or phases reads as a scan that recorded none, since a
/// sitting can end before its first checkpoint.
pub fn report(directory: &Path) -> Result<ScanReport, JournalError> {
    let manifest = read_manifest(directory)?;

    Ok(ScanReport::recorded(
        manifest.engine_version,
        read_phases(directory)?,
        read_findings(directory)?,
    ))
}

/// How a phase is named in a refusal, in prose, since this reaches a person.
fn phase_name(kind: ScanKind) -> &'static str {
    match kind {
        ScanKind::Discovery => "host-discovery sweep",
        ScanKind::PortScan => "port scan",
        // A watch's journal is resumed by appending a sitting, but it is still one this
        // build writes.
        ScanKind::Listen => "listening phase",
    }
}

/// Deletes the journal at `directory`.
///
/// Refuses one a live scan is writing. A caller pruning by age should read
/// [`Entry::lock`] and skip what is held, so the sweep can report what it left alone.
///
/// The refusal is a check, not an exclusion: a scan that takes the lock between the
/// inspection and the removal has its journal deleted under it and keeps writing to
/// unlinked files. Both parties are the same user's processes and the window is one lock
/// against one removal; closing it would need the lock held across the removal.
pub fn remove(directory: &Path) -> Result<(), OpenError> {
    let state = super::lock::inspect(&directory.join(LOCK));
    if !state.is_resumable() {
        return Err(OpenError::Locked(LockRefused::Held(state)));
    }

    remove_directory(directory).map_err(JournalError::from)?;
    Ok(())
}

/// One line of the record [`Journal::record_finished`] keeps: the hosts one
/// sitting finished every pass over.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct FinishedRecord {
    hosts: Vec<String>,
}

/// Reads back what a journal's earlier sittings found.
///
/// Records are folded together, each as a later account of the host, so a host
/// written once when it answered and again when its ports were classified comes back whole;
/// see [`Host::merge_later_account`].
///
/// Two records are the same host when they share any address. Local discovery promotes a
/// host's primary address when a better one turns up (a link-local giving way to a global),
/// so the same machine can be written under two primaries.
///
/// An address is the one [`ScopedIp::scoped`] makes of it with the record's zone, so two
/// machines answering to `fe80::1` on two links stay two hosts. That is the identity the
/// report and a diff key hosts by. A record that names no zone joins only others that name
/// none.
///
/// A missing file is no findings, since a journal can be read before its first host is
/// written.
fn read_findings(directory: &Path) -> Result<Vec<Host>, JournalError> {
    let file = match open_to_read(&directory.join(HOSTS)) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    let mut reader = match crate::journal::format::Reader::open(std::io::BufReader::new(file)) {
        Ok(reader) => reader,
        // No header means the file was never opened for writing: a journal that stopped
        // before it found anything.
        Err(JournalError::NotAJournal) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    // Slots, not a map: a record can join two hosts that were separate until then, and
    // the one it merges into keeps its slot while the other empties.
    let mut hosts: Vec<Option<Host>> = Vec::new();
    let mut slot_of: std::collections::BTreeMap<ScopedIp, usize> =
        std::collections::BTreeMap::new();

    while let Some(record) = reader.read::<HostRecord>()? {
        let host = Host::from(&record);

        let mut matched: Vec<usize> = scoped_ips(&host)
            .filter_map(|ip| slot_of.get(&ip).copied())
            .collect();
        matched.sort_unstable();
        matched.dedup();

        let slot = match matched.split_first() {
            Some((&keep, absorb)) => {
                // Every host sharing an address with this record is the same machine.
                for &other in absorb {
                    if let Some(other) = hosts[other].take() {
                        merge_into(&mut hosts, keep, other, Host::merge);
                    }
                }
                merge_into(&mut hosts, keep, host, Host::merge_later_account);
                keep
            }
            None => {
                hosts.push(Some(host));
                hosts.len() - 1
            }
        };

        let Some(settled) = hosts[slot].as_ref() else {
            continue;
        };
        for ip in scoped_ips(settled) {
            slot_of.insert(ip, slot);
        }
    }

    Ok(hosts.into_iter().flatten().collect())
}

/// Every address of `host`, each carrying the host's zone where the address
/// needs one to name a machine.
fn scoped_ips(host: &Host) -> impl Iterator<Item = ScopedIp> + '_ {
    host.ips().iter().map(|ip| match host.zone() {
        Some(zone) => ScopedIp::scoped(*ip, zone.clone()),
        None => ScopedIp::unscoped(*ip),
    })
}

/// Folds `host` into the one at `slot` by `fold`, or puts it there if the
/// slot is empty.
///
/// A record folds in as a later account of what the slot holds, since the file is
/// appended in write order; see [`Host::merge_later_account`]. Two slots a record shows to
/// be one machine fold as any two accounts of a host do.
fn merge_into(hosts: &mut [Option<Host>], slot: usize, host: Host, fold: fn(&mut Host, Host)) {
    match hosts[slot].as_mut() {
        Some(existing) => fold(existing, host),
        None => hosts[slot] = Some(host),
    }
}

/// How long the findings file in `directory` is, measured on the opened file since
/// nothing here looks up a journal's names by path. A missing file has length 0.
fn findings_length(directory: &Path) -> Result<u64, JournalError> {
    match open_to_read(&directory.join(HOSTS)) {
        Ok(file) => Ok(file.metadata()?.len()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e.into()),
    }
}

/// Reads back what a journal's earlier sittings did, oldest first.
fn read_phases(directory: &Path) -> Result<Vec<ScanPhase>, JournalError> {
    let file = match open_to_read(&directory.join(PHASES)) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    let mut reader = match crate::journal::format::Reader::open(std::io::BufReader::new(file)) {
        Ok(reader) => reader,
        Err(JournalError::NotAJournal) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut phases = Vec::new();
    while let Some(record) = reader.read::<PhaseRecord>()? {
        phases.push(ScanPhase::from(&record));
    }

    // Sittings that never ended. A phase already appended was left by a sitting
    // stopped between the append and the removal, and is read once.
    for standing in standing_phases(directory) {
        let recorded = phases.iter().any(|phase| {
            phase.kind() == standing.kind() && phase.started_at() == standing.started_at()
        });
        if !recorded {
            phases.push(standing);
        }
    }
    // Oldest first; a sitting that never ended ran before whatever was appended after
    // it.
    phases.sort_by_key(ScanPhase::started_at);
    Ok(phases)
}

/// Where the sitting holding `lock` writes its phases as they stand, named by start
/// time so name order is run order.
fn sitting_file(directory: &Path, lock: &Lock) -> PathBuf {
    let started = lock
        .record()
        .started_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    directory.join(format!("{SITTING}{started:020}.jsonl"))
}

/// The phases of every sitting in `directory` that never ended, oldest first.
///
/// A standing record is written whole by rename, so one that cannot be read is
/// something else at the name, such as a link, and is skipped.
fn standing_phases(directory: &Path) -> Vec<ScanPhase> {
    let Ok(held) = names(directory) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = held
        .into_iter()
        .filter(|name| {
            name.to_str()
                .is_some_and(|name| name.starts_with(SITTING) && name.ends_with(".jsonl"))
        })
        .map(|name| directory.join(name))
        .collect();
    files.sort();

    let mut phases = Vec::new();
    for path in files {
        let Ok(file) = open_to_read(&path) else {
            continue;
        };
        let Ok(mut reader) = crate::journal::format::Reader::open(std::io::BufReader::new(file))
        else {
            continue;
        };
        while let Ok(Some(record)) = reader.read::<PhaseRecord>() {
            phases.push(ScanPhase::from(&record));
        }
    }
    phases
}

/// Reads back the detection-run tapes a journal holds, for offline replay.
///
/// A missing file is no runs, as for a journal read before any detection ran.
pub fn read_detections(directory: &Path) -> Result<Vec<DetectionRunRecord>, JournalError> {
    let file = match open_to_read(&directory.join(DETECTIONS)) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    let mut reader = match crate::journal::format::Reader::open(std::io::BufReader::new(file)) {
        Ok(reader) => reader,
        Err(JournalError::NotAJournal) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut runs = Vec::new();
    while let Some(line) = reader.read::<DetectionLine>()? {
        runs.extend(line.into_runs());
    }
    Ok(runs)
}

/// Opens a findings file to add to it, making it whole first.
///
/// Establishes the precondition
/// [`format::Writer::append`](super::format::Writer::append) states, for all three append
/// sites: an `O_APPEND` descriptor cannot see what it appends to.
///
/// A torn tail stops being discardable once anything follows it.
/// [`format::Reader`](super::format::Reader) discards a torn line only while it is last. A
/// resumed sitting appending after the torn bytes would make the tear the prefix of a
/// newline-terminated line, which is corruption by the reader's rule, and the file could
/// then be neither read nor resumed. Truncating to the last newline discards exactly what
/// the reader would have.
///
/// A file with no header is mended or refused. [`Journal::open_findings`] creates the file
/// and writes its header in two steps, so a process killed between them leaves a
/// zero-length file; appending into it would write records under no header, which every
/// later read treats as no findings while the cursor advances. An empty file is mended by
/// writing the header. A non-empty file without one is somebody else's file at this name
/// and is refused, since prepending a header would claim its lines as this engine's
/// records.
fn open_for_append(path: &Path) -> Result<fs::File, JournalError> {
    mend(path)?;
    Ok(append_existing(path)?)
}

/// Gives a findings file a header if it has none and no torn tail if it has one.
///
/// The header is checked through [`format::Reader::open`](super::format::Reader),
/// so the rule is the reader's own, version refusal included.
///
/// The header is validated before anything is truncated, so a stranger's file at this name
/// is refused intact.
fn mend(path: &Path) -> Result<(), JournalError> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = open_existing(path)?;
    let length = file.metadata()?.len();

    // The header write that did not finish, between `open_findings`' create and its
    // write.
    if length == 0 {
        super::format::Writer::create(&mut file)?.flush()?;
        return Ok(());
    }

    super::format::Reader::open(std::io::BufReader::new(&file))?;

    file.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(());
    }

    let keep = last_whole_line(&mut file, length)?;
    file.set_len(keep)?;

    // No whole line anywhere, so the header line is the torn one. It parsed, so the
    // file is this engine's with nothing in it to keep; rewrite the header as for an empty
    // file.
    if keep == 0 {
        file.seek(SeekFrom::Start(0))?;
        super::format::Writer::create(&mut file)?.flush()?;
    }

    Ok(())
}

/// The offset just past the file's last newline: where a whole record last ended.
///
/// Read backwards a window at a time. This runs on every append, and a findings file
/// grows with the scan's duration, so reading it forwards would cost more every
/// checkpoint.
fn last_whole_line(file: &mut fs::File, length: u64) -> Result<u64, JournalError> {
    use std::io::{Read, Seek, SeekFrom};

    /// Comfortably more than a record, so the answer is almost always one read.
    ///
    /// A `u64` to match the file length's width. As a `usize` on a 32-bit target, a length that
    /// is an exact multiple of 4 GiB would truncate to a zero window and the loop would hang
    /// holding the journal's lock.
    const WINDOW: u64 = 8 * 1024;

    let mut end = length;
    while end > 0 {
        let size = WINDOW.min(end);
        let start = end - size;

        file.seek(SeekFrom::Start(start))?;
        // Lossless: `size` is at most `WINDOW`.
        let mut window = vec![0u8; size as usize];
        file.read_exact(&mut window)?;

        if let Some(at) = window.iter().rposition(|byte| *byte == b'\n') {
            return Ok(start + at as u64 + 1);
        }

        end = start;
    }

    Ok(0)
}

/// The options a journal's job runs under, or `None` where none were recorded.
fn read_options(directory: &Path) -> Result<Option<JobOptions>, JournalError> {
    let text = match read_bounded(&directory.join(OPTIONS), "a journal's options") {
        Ok(text) => text,
        Err(JournalError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(Some(
        serde_json::from_str(&text).map_err(JournalError::json)?,
    ))
}

/// Reads a journal's manifest, refusing one written in a newer format than this
/// build understands.
fn read_manifest(directory: &Path) -> Result<JournalManifest, JournalError> {
    let text = read_bounded(&directory.join(MANIFEST), "a journal manifest")?;
    let manifest: JournalManifest = serde_json::from_str(&text).map_err(JournalError::json)?;

    if manifest.journal_version > super::JOURNAL_VERSION {
        return Err(JournalError::VersionTooNew {
            found: manifest.journal_version,
            understood: super::JOURNAL_VERSION,
        });
    }

    Ok(manifest)
}

/// Reads how far a scan got, which is where a resume starts.
fn read_checkpoint(directory: &Path) -> Result<Checkpoint, JournalError> {
    match Checkpoint::read(&directory.join(CURSOR)) {
        Ok(checkpoint) => Ok(checkpoint),
        // A journal that stopped before its first checkpoint has settled nothing: a fresh
        // cursor.
        Err(JournalError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(Checkpoint::default())
        }
        Err(e) => Err(e),
    }
}

/// The characters an id is written in: Crockford base32, which has no letters a
/// reader can mistake for digits.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// How many characters an id is.
///
/// Sixteen: the millisecond the scan started, then randomness. Shorter than a
/// ULID's twenty-six so a listing of ids fits a terminal and an id can be typed.
///
/// The ten characters saved all come off the random half. Millisecond timing keeps ids
/// sorted in run order and distinguishes scans close together in time. That leaves 32
/// random bits for scans started in the same millisecond, and a collision just mints
/// another id; see [`claim_directory`].
const ID_CHARS: usize = 16;

/// Milliseconds, as a ULID counts them, reaching the year 10 889.
const ID_TIME_BITS: u32 = 48;

/// A sortable id: the millisecond the scan started, then randomness, in
/// Crockford base32.
///
/// Sorts by creation time as text, so a listing can be ordered without reading every
/// manifest.
fn mint_id() -> String {
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis())
        & ((1u128 << ID_TIME_BITS) - 1);

    let random_bits = ID_CHARS as u32 * 5 - ID_TIME_BITS;
    let entropy = u128::from(rand::random::<u64>()) & ((1u128 << random_bits) - 1);
    let mut value = (millis << random_bits) | entropy;

    let mut out = [b'0'; ID_CHARS];
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(value & 0x1F) as usize];
        value >>= 5;
    }

    // Every byte came from `ALPHABET`, which is ASCII.
    String::from_utf8(out.to_vec()).expect("base32 alphabet is ASCII")
}

/// Takes a directory under `root` that nothing else holds, and its id.
///
/// `create_dir`, which fails on an existing directory, so two scans that minted the
/// same id never share one. A collision mints another id, since ids carry enough randomness
/// that this should almost never repeat.
fn claim_directory(root: &Path) -> Result<(String, PathBuf), JournalError> {
    /// Exhausting these means something other than chance: a root that is not a
    /// directory, or one nothing may write to.
    const ATTEMPTS: usize = 8;

    for _ in 0..ATTEMPTS {
        let id = mint_id();
        let directory = root.join(&id);

        match create_private_directory(&directory) {
            Ok(()) => {
                claim_directory_for_invoking_user(&directory);
                return Ok((id, directory));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not find an unused id for this scan",
    )
    .into())
}

/// Reads a whole journal file, refusing one past
/// [`MAX_READ_BYTES`](super::format::MAX_READ_BYTES).
///
/// The ceiling is applied through `take` before the read. The manifest and cursor
/// live in a directory belonging to a user while the reader is often root; see
/// [`MAX_READ_BYTES`](super::format::MAX_READ_BYTES). A link at the name is refused; see
/// [`open_to_read`].
pub(super) fn read_bounded(path: &Path, what: &str) -> Result<String, JournalError> {
    use std::io::Read;

    let mut text = String::new();
    let read = open_to_read(path)?
        .take(super::format::MAX_READ_BYTES + 1)
        .read_to_string(&mut text)?;

    if read as u64 > super::format::MAX_READ_BYTES {
        return Err(super::format::too_large(what));
    }

    Ok(text)
}

/// Writes a whole file at a journal's own mode and ownership, for files written once.
///
/// Staged and renamed, like [`Checkpoint::write_atomically`], so the name holds the whole
/// file or nothing. Used for the manifest, which every other read starts from: a torn
/// manifest would fail to parse and [`list`] would treat the journal as absent.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), JournalError> {
    use std::io::Write;

    replace(path, &path.with_extension("tmp"), |mut file| {
        file.write_all(bytes)
    })?;
    Ok(())
}

/// How long journals are kept.
///
/// A journal holds the addresses an engagement was pointed at, so it should not pile
/// up unseen; it is also evidence, so it should not vanish unasked. The defaults favour
/// keeping.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retention {
    /// How long a finished journal is kept, or `None` to keep it indefinitely.
    pub completed_for: Option<Duration>,
    /// How long an unfinished one is kept, or `None` to keep it indefinitely.
    pub incomplete_for: Option<Duration>,
    /// The most journals to keep, or `None` for no cap.
    ///
    /// Applied after the ages above, removing finished journals before unfinished
    /// ones, since an unfinished journal may still be wanted.
    pub keep_at_most: Option<usize>,
    /// Whether journals this build cannot read go too.
    ///
    /// Off by default. A journal passed over is usually a newer build's, which that build
    /// still reads. Links are never removed either way; see [`Unlisted::Link`].
    pub unreadable: bool,
}

impl Default for Retention {
    /// A month for finished journals, indefinitely for unfinished ones, and a cap of
    /// two hundred. A finished scan has a report, so its journal is a duplicate; an unfinished
    /// one is the only copy of work somebody may mean to continue.
    fn default() -> Self {
        Self {
            completed_for: Some(Duration::from_secs(30 * 24 * 60 * 60)),
            incomplete_for: None,
            keep_at_most: Some(200),
            unreadable: false,
        }
    }
}

impl Retention {
    /// Removes nothing. For a caller who prunes on their own terms.
    pub fn keep_everything() -> Self {
        Self {
            completed_for: None,
            incomplete_for: None,
            keep_at_most: None,
            unreadable: false,
        }
    }

    /// Which of `entries` this policy would remove, newest-first as [`list`]
    /// yields them.
    ///
    /// Pure, and separate from [`prune`] as
    /// [`lock::classify`](crate::journal::lock::classify) is, so the policy can be tested
    /// without building a real directory of journals.
    ///
    /// A journal something is writing is never selected, whatever its age.
    pub fn expired(&self, entries: &[Entry], now: SystemTime) -> Vec<usize> {
        let age_of = |entry: &Entry| {
            now.duration_since(entry.manifest.created_at)
                .unwrap_or_default()
        };

        let mut removing: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.lock.is_resumable())
            .filter(|(_, entry)| {
                let limit = if entry.is_complete() {
                    self.completed_for
                } else {
                    self.incomplete_for
                };
                limit.is_some_and(|limit| age_of(entry) > limit)
            })
            .map(|(index, _)| index)
            .collect();

        let Some(cap) = self.keep_at_most else {
            return removing;
        };

        // What the ages left, oldest last, since `list` is newest first.
        let mut surviving: Vec<usize> = (0..entries.len())
            .filter(|index| !removing.contains(index))
            .collect();

        // Most worth keeping first: unfinished before finished, newer before older. The cap
        // drops from the end, so the oldest finished journal goes first.
        surviving.sort_by_key(|&index| {
            let entry = &entries[index];
            (
                entry.is_complete(),
                std::cmp::Reverse(entry.manifest.created_at),
            )
        });

        while surviving.len() > cap {
            let Some(index) = surviving.pop() else { break };
            if entries[index].lock.is_resumable() {
                removing.push(index);
            }
        }

        removing.sort_unstable();
        removing
    }
}

/// What a prune did, and what it left alone.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pruned {
    /// The journals removed, by id.
    pub removed: Vec<String>,
    /// The journals a policy selected that could not be removed, each with why, so a
    /// sweep that stopped working is visible.
    pub held: Vec<Held>,
}

/// A journal a prune could not remove.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// Which journal.
    pub id: String,
    /// Why it is still there.
    pub reason: String,
}

impl Held {
    /// The journal `id`, kept for `reason`.
    pub fn new(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            reason: reason.into(),
        }
    }
}

/// Removes the journals under `root` that `retention` no longer keeps.
///
/// Journals a scan is writing are never selected, so they are neither removed nor
/// reported as held. [`Pruned::held`] lists journals the policy chose and the filesystem
/// refused.
///
/// A journal this build cannot read is removed only under [`Retention::unreadable`], by its
/// directory name, after the usual lock check (a newer build may be writing it). A link is
/// never selected; [`list`] reports it.
pub fn prune(root: &Path, retention: &Retention) -> Result<Pruned, JournalError> {
    let listing = list(root)?;
    let mut pruned = Pruned::default();

    for index in retention.expired(&listing.entries, SystemTime::now()) {
        let entry = &listing.entries[index];
        match remove(&entry.directory) {
            Ok(()) => pruned.removed.push(entry.manifest.id.clone()),
            Err(error) => pruned.held.push(Held {
                id: entry.manifest.id.clone(),
                reason: error.to_string(),
            }),
        }
    }

    if retention.unreadable {
        let journals = listing
            .passed_over
            .iter()
            .filter(|passed| passed.why != Unlisted::Link);
        for passed in journals {
            match remove(&passed.directory) {
                Ok(()) => pruned.removed.push(passed.name.clone()),
                Err(error) => pruned
                    .held
                    .push(Held::new(passed.name.clone(), error.to_string())),
            }
        }
    }

    Ok(pruned)
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
    use crate::journal::settle::Outcome;
    // Two tests here use the checkpoint ticker from `scanner`, since what they assert
    // is what a checkpointed scan leaves in the journal.
    use crate::model::exclusion::Exclusions;
    use crate::model::ip::set::IpSet;
    use crate::model::port::PortSet;
    use crate::model::target::{TargetMap, TargetSet};
    use crate::model::technique::TcpScanTechnique;
    use crate::scanner::checkpoint::spawn_checkpoints;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zond-store-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch root");
        dir
    }

    fn plan(range: &str, ports: &str) -> TargetMap {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            range.parse::<IpSet>().expect("a range"),
            ports.parse::<PortSet>().expect("ports"),
        ));
        map
    }

    fn ports(map: &TargetMap) -> Plan {
        Plan::port_scan(map, &Exclusions::none(), TcpScanTechnique::Syn)
    }

    fn begin(root: &Path, map: &TargetMap) -> Journal {
        Journal::create(root, &ports(map), Privilege::Raw, "test").expect("creates")
    }

    /// A port phase that stood in for a liveness pass, naming `silent` the addresses
    /// it asked on every port and heard nothing from.
    fn standing_in(silent: &str) -> ScanPhase {
        use crate::config::ZondConfig;
        use crate::model::ip::range::IpRange;
        use crate::report::{LivenessSkip, PhaseParts, ScanSettings, TargetScope};

        let silent: IpSet = silent.parse().expect("a range");
        ScanPhase::from_parts(PhaseParts {
            open: false,
            attachments: Vec::new(),
            kind: ScanKind::PortScan,
            started_at: SystemTime::UNIX_EPOCH,
            elapsed: Duration::from_secs(1),
            privilege: Some(Privilege::Raw),
            targets: TargetScope::from_ip_set(&mut IpSet::new(), &Exclusions::none()),
            settings: ScanSettings::from(&ZondConfig::default()),
            failures: Vec::new(),
            refusals: Vec::new(),
            unroutable: Vec::new(),
            refused_by_route: Vec::new(),
            timed_out: Vec::new(),
            icmp_rate_limited: Vec::new(),
            reached_by_connect: Vec::new(),
            undecided: Vec::new(),
            liveness_skipped: Some(LivenessSkip::PortsNoDearer),
            silent: silent.v4().iter().copied().map(IpRange::V4).collect(),
            stopped: None,
            passes_cut: Vec::new(),
            unreached: 0,
            unheard_probes: 0,
            probes: Vec::new(),
            origin: None,
        })
    }

    /// A record a port scanner files at an address before hearing from it, as a
    /// checkpoint writes it mid-sitting.
    fn unheard(address: &str) -> Host {
        use crate::model::port::{Port, PortState, Protocol};

        let mut host = Host::new(address.parse().expect("an address"));
        host.add_port(Port::new(80, Protocol::Tcp, PortState::NoReply));
        host
    }

    /// A host that answered.
    fn heard(address: &str) -> Host {
        let mut host = Host::new(address.parse().expect("an address"));
        host.set_status(crate::model::host::HostStatus::Up);
        host
    }

    /// A record an earlier sitting heard nothing from is not restored. The findings
    /// file can hold one written before the phase decided the address was silent; restored, it
    /// would sit among the resumed sitting's hosts though the report does not list it.
    #[test]
    fn a_record_an_earlier_sitting_heard_nothing_from_is_not_restored() {
        let root = scratch("unheard-restore");
        let map = plan("192.0.2.1-192.0.2.8", "80");

        let directory = {
            let mut journal = begin(&root, &map);
            journal
                .record_hosts(&[heard("192.0.2.1"), unheard("192.0.2.5")])
                .expect("records");
            journal
                .record_phases(&[standing_in("192.0.2.5")])
                .expect("records");
            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        let (journal, _) =
            Journal::resume(&directory, &ports(&map), Privilege::Raw).expect("resumes");
        let restored: Vec<_> = journal.restored().iter().map(Host::primary_ip).collect();

        assert_eq!(
            restored,
            ["192.0.2.1".parse::<std::net::IpAddr>().expect("an address")]
        );
        journal.close().expect("closes");
        std::fs::remove_dir_all(&root).ok();
    }

    /// A sitting that heard nothing from an address leaves no record of it on disk. A
    /// checkpoint writes the record before the phase decides the address is silent, and the
    /// phase forgets it only in memory, so the close must rewrite the file.
    #[tokio::test]
    async fn a_sitting_that_heard_nothing_from_an_address_leaves_no_record_of_it() {
        let root = scratch("unheard-close");
        let map = plan("192.0.2.1-192.0.2.8", "80");
        let mut journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();

        // Written mid-sitting and since forgotten by the phase: the live store holds only
        // the host that answered.
        journal
            .record_hosts(&[heard("192.0.2.1"), unheard("192.0.2.5")])
            .expect("records");
        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        ctx.restore_hosts(&[heard("192.0.2.1")]);

        spawn_checkpoints(journal, ctx.progress())
            .finish(&[standing_in("192.0.2.5")])
            .await;

        let file = fs::read_to_string(directory.join(HOSTS)).expect("reads");
        assert!(
            !file.contains("192.0.2.5"),
            "a record of the silent address is still on disk:\n{file}"
        );
        let kept: Vec<_> = read_findings(&directory)
            .expect("reads")
            .iter()
            .map(Host::primary_ip)
            .collect();
        assert_eq!(
            kept,
            ["192.0.2.1".parse::<std::net::IpAddr>().expect("an address")]
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// A sitting killed before its port phase decides what it heard nothing from leaves
    /// each undecided record to the next sitting, and out of the job's report.
    ///
    /// A phase standing in for a liveness pass decides its unanswered records only at its end,
    /// while a target is settled as its answer or silence is stored. If the record stayed off
    /// disk until a verdict the killed sitting never reaches, its ports would be settled with
    /// nothing on file. Its probes at an address silent on every target are counted, being
    /// decided.
    #[tokio::test]
    async fn a_sitting_killed_before_its_verdicts_leaves_its_undecided_records_to_the_next() {
        use crate::config::ZondConfig;
        use crate::journal::settle::Outcome;
        use crate::model::port::{Port, PortState, Protocol};
        use crate::model::target::TargetIndex;
        use crate::report::{LivenessSkip, TargetScope};
        use crate::scanner::recorder::PhaseRecorder;

        let root = scratch("unheard-killed");
        let map = plan("192.0.2.1-192.0.2.8", "80,443");
        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();
        let address = |address: &str| address.parse::<std::net::IpAddr>().expect("an address");
        let position = |at: &str, port: u16| {
            map.iter()
                .position(|target| target.ip == address(at) && target.port == port)
                .expect("a planned target") as u64
        };

        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        ctx.number_targets(TargetIndex::of(&map));
        let _phase = PhaseRecorder::start(
            ScanKind::PortScan,
            Privilege::Raw,
            TargetScope::from_ip_set(
                &mut "192.0.2.1-192.0.2.8".parse().expect("a range"),
                &Exclusions::none(),
            ),
            &ZondConfig::default(),
        )
        .skipping_liveness(LivenessSkip::PortsNoDearer)
        .opening_in(&ctx);
        ctx.await_verdicts();
        // A host; an address asked on one of its ports so far; and one asked on both and
        // heard from on neither.
        ctx.update_host(address("192.0.2.1"), |host| {
            host.set_status(crate::model::host::HostStatus::Up);
        });
        ctx.write_host(address("192.0.2.5"), |host| {
            *host = unheard("192.0.2.5");
            true
        });
        ctx.record_outcome(Outcome::Exhausted {
            position: position("192.0.2.5", 80),
        });
        ctx.write_host(address("192.0.2.6"), |host| {
            *host = unheard("192.0.2.6");
            host.add_port(Port::new(443, Protocol::Tcp, PortState::NoReply));
            true
        });
        for port in [80, 443] {
            ctx.record_outcome(Outcome::Exhausted {
                position: position("192.0.2.6", port),
            });
        }

        // One checkpoint lands, and the process dies before the phase ends.
        let mut ticker = spawn_checkpoints(journal, ctx.progress());
        ticker.checkpointed().await;
        ticker.kill().await;

        let hosts = report(&directory)
            .expect("reads")
            .hosts()
            .map(Host::primary_ip)
            .collect::<Vec<_>>();
        assert_eq!(
            hosts,
            [address("192.0.2.1")],
            "the report lists an undecided address"
        );

        let (journal, _) =
            Journal::resume(&directory, &ports(&map), Privilege::Raw).expect("resumes");
        let restored: Vec<_> = journal
            .restored()
            .iter()
            .map(|host| (host.primary_ip(), host.ports().count()))
            .collect();
        assert_eq!(
            restored,
            [(address("192.0.2.1"), 0), (address("192.0.2.5"), 1)],
            "the undecided record, and only it beside the host, is the next sitting's"
        );
        let unheard: u128 = journal
            .earlier_phases()
            .iter()
            .map(ScanPhase::unheard_probes)
            .sum();
        assert_eq!(unheard, 2, "the silent address's probes went uncounted");
        journal.close().expect("closes");
        std::fs::remove_dir_all(&root).ok();
    }

    /// A sitting killed before its verdicts still names the addresses it heard nothing
    /// from on every target. Their targets are settled on disk, so a resume asks nothing more
    /// of them; named only at the phase's end, they would be in no list of the job.
    #[tokio::test]
    async fn a_sitting_killed_before_its_verdicts_still_names_what_it_heard_nothing_from() {
        use crate::config::ZondConfig;
        use crate::journal::settle::Outcome;
        use crate::model::target::TargetIndex;
        use crate::report::TargetScope;
        use crate::scanner::recorder::PhaseRecorder;

        let root = scratch("unheard-named");
        let map = plan("192.0.2.1-192.0.2.8", "80");
        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();

        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        ctx.number_targets(TargetIndex::of(&map));
        let _phase = PhaseRecorder::start(
            ScanKind::PortScan,
            Privilege::Raw,
            TargetScope::from_ip_set(&mut IpSet::new(), &Exclusions::none()),
            &ZondConfig::default(),
        )
        .opening_in(&ctx);
        ctx.await_verdicts();
        // Asked and settled silent, and asked with its answer still owed.
        for address in ["192.0.2.5", "192.0.2.6"] {
            ctx.write_host(
                address.parse::<std::net::IpAddr>().expect("an address"),
                |host| {
                    *host = unheard(address);
                    true
                },
            );
        }
        ctx.record_outcome(Outcome::Exhausted { position: 4 });

        let mut ticker = spawn_checkpoints(journal, ctx.progress());
        ticker.checkpointed().await;
        ticker.kill().await;

        let (journal, _) =
            Journal::resume(&directory, &ports(&map), Privilege::Raw).expect("resumes");
        let silent: Vec<_> = journal
            .earlier_phases()
            .iter()
            .flat_map(|phase| phase.silent().iter().copied())
            .collect();
        let named: IpSet = "192.0.2.5".parse().expect("an address");
        assert_eq!(
            silent,
            named
                .v4()
                .iter()
                .copied()
                .map(crate::model::ip::range::IpRange::V4)
                .collect::<Vec<_>>(),
            "the settled silent address is named, and only it"
        );
        journal.close().expect("closes");
        std::fs::remove_dir_all(&root).ok();
    }

    /// A record awaiting its verdict is in the findings once the phase keeps it: an
    /// address the phase neither forgot nor heard from, one no route led to.
    #[tokio::test]
    async fn a_record_held_for_its_verdict_is_written_once_the_phase_keeps_it() {
        let root = scratch("unheard-kept");
        let map = plan("192.0.2.1-192.0.2.8", "80");
        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();

        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        ctx.await_verdicts();
        ctx.write_host(
            "192.0.2.5".parse::<std::net::IpAddr>().expect("an address"),
            |host| {
                *host = unheard("192.0.2.5");
                true
            },
        );
        let mut ticker = spawn_checkpoints(journal, ctx.progress());
        ticker.checkpointed().await;
        ctx.verdicts_reached();
        ticker.finish(&[]).await;

        let kept: Vec<_> = read_findings(&directory)
            .expect("reads")
            .iter()
            .map(Host::primary_ip)
            .collect();
        assert_eq!(
            kept,
            ["192.0.2.5".parse::<std::net::IpAddr>().expect("an address")]
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// Begin a scan, settle part of it, and continue from exactly where it stopped.
    #[test]
    fn a_scan_resumes_from_where_it_stopped() {
        let root = scratch("resume");
        let map = plan("192.0.2.1-192.0.2.4", "80,443");

        let directory = {
            let mut journal = begin(&root, &map);
            let settlements = Settlements::default();
            for position in [0, 1, 2, 5] {
                settlements.record(Outcome::Answered { position });
            }
            journal.checkpoint(&settlements).expect("checkpoints");

            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        let (_journal, checkpoint) =
            Journal::resume(&directory, &ports(&map), Privilege::Raw).expect("resumes");

        assert_eq!(checkpoint.watermark, 3);
        let remaining: Vec<_> = checkpoint.remaining(map.iter()).collect();
        assert_eq!(remaining.len(), 4, "eight targets, four settled");
    }

    /// A job's options are written by its first sitting and read back by every later
    /// one, and nothing a later sitting runs under replaces them. Otherwise a sitting that
    /// changed its pace would become the record of what the job asked.
    #[test]
    fn a_jobs_options_are_written_by_its_first_sitting_and_kept() {
        use crate::config::ZondConfig;

        let root = scratch("options");
        let map = plan("192.0.2.1-192.0.2.4", "80,443");
        let first = ZondConfig {
            assume_up: true,
            traceroute: true,
            ..ZondConfig::default()
        };

        let directory = {
            let mut journal = begin(&root, &map);
            assert!(journal.options().is_none(), "no sitting has started");
            journal
                .record_options(JobOptions::of(&first))
                .expect("records");
            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        let (mut journal, _) =
            Journal::resume(&directory, &ports(&map), Privilege::Raw).expect("resumes");
        assert_eq!(journal.options(), Some(&JobOptions::of(&first)));

        journal
            .record_options(JobOptions::of(&ZondConfig::default()))
            .expect("a second record is a no-op");
        journal.close().expect("closes");
        let (journal, _) =
            Journal::resume(&directory, &ports(&map), Privilege::Raw).expect("resumes");
        assert_eq!(journal.options(), Some(&JobOptions::of(&first)));
    }

    /// A journal an earlier sitting ran against without recording options is continued
    /// without any, since this sitting's are not what that one ran under.
    #[test]
    fn a_journal_older_than_its_options_is_left_without_them() {
        use crate::config::ZondConfig;

        let root = scratch("options-older");
        let map = plan("192.0.2.1-192.0.2.4", "80,443");

        let directory = {
            let mut journal = begin(&root, &map);
            let settlements = Settlements::default();
            settlements.record(Outcome::Answered { position: 0 });
            journal.checkpoint(&settlements).expect("checkpoints");
            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        let (mut journal, checkpoint) = Journal::resume(&directory, &ports(&map), Privilege::Raw)
            .expect("an older journal resumes");
        assert_eq!(checkpoint.watermark, 1);
        journal
            .record_options(JobOptions::of(&ZondConfig::default()))
            .expect("records nothing");
        assert!(journal.options().is_none());
        assert!(!directory.join(OPTIONS).exists());
    }

    /// A plan edited between sittings renumbers positions past the edit, so the resume is
    /// refused.
    #[test]
    fn a_changed_plan_is_refused() {
        let root = scratch("changed-plan");
        let map = plan("192.0.2.1-192.0.2.4", "80,443");

        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let widened = plan("192.0.2.1-192.0.2.9", "80,443");
        let refused = Journal::resume(&directory, &ports(&widened), Privilege::Raw)
            .expect_err("the plan moved");

        assert!(matches!(refused, OpenError::PlanChanged(_)), "{refused:?}");
    }

    /// A journal being written is not resumed underneath its writer. A lock naming a live
    /// process that stopped checkpointing is refused as it stands and can be taken over when
    /// asked. This process stands in for a reissued pid.
    #[test]
    fn a_journal_whose_lock_went_stale_can_be_taken_over() {
        let root = scratch("stale-lock");
        let map = plan("192.0.2.1", "80");
        let directory = {
            let journal = begin(&root, &map);
            journal.directory().to_path_buf()
        };
        let stale = super::super::lock::LockRecord {
            pid: std::process::id(),
            boot: super::super::lock::boot_identity(),
            started_at: SystemTime::now() - Duration::from_secs(3_600),
            heartbeat: SystemTime::now() - Duration::from_secs(600),
        };
        fs::write(
            directory.join(LOCK),
            serde_json::to_string(&stale).expect("json"),
        )
        .expect("writes");

        assert!(matches!(
            Journal::reopen(&directory, Privilege::Raw),
            Err(OpenError::Locked(LockRefused::Held(
                LockState::Stale { .. }
            )))
        ));
        let (journal, _, _) =
            Journal::take_over(&directory, Privilege::Raw).expect("takes the journal over");
        journal.close().expect("closes");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_live_journal_is_not_resumable() {
        let root = scratch("live");
        let map = plan("192.0.2.1", "80");

        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();

        let refused =
            Journal::resume(&directory, &ports(&map), Privilege::Raw).expect_err("it is held");
        assert!(matches!(refused, OpenError::Locked(_)), "{refused:?}");

        // Once released, it opens.
        journal.close().expect("closes");
        Journal::resume(&directory, &ports(&map), Privilege::Raw).expect("now free");
    }

    /// Listing reports progress and liveness without taking the lock.
    #[test]
    fn listing_describes_journals_without_locking_them() {
        let root = scratch("list");
        let map = plan("192.0.2.1-192.0.2.4", "80,443");

        let mut journal = begin(&root, &map);
        let settlements = Settlements::default();
        for position in 0..4 {
            settlements.record(Outcome::Answered { position });
        }
        journal.checkpoint(&settlements).expect("checkpoints");

        let listed = list(&root).expect("lists").entries;
        assert_eq!(listed.len(), 1);

        let entry = &listed[0];
        assert_eq!(entry.manifest.total_targets, 8);
        assert_eq!(entry.settled(), Some(4));
        assert!(!entry.is_complete());
        assert!(
            matches!(entry.lock, LockState::Held { .. }),
            "the scan is still running: {:?}",
            entry.lock
        );

        // Still writable, so the listing took nothing.
        journal
            .checkpoint(&settlements)
            .expect("still holds its lock");
    }

    /// A journal that covered its plan reads as complete.
    #[test]
    fn a_finished_journal_reads_as_complete() {
        let root = scratch("complete");
        let map = plan("192.0.2.1-192.0.2.4", "80,443");

        let mut journal = begin(&root, &map);
        let settlements = Settlements::default();
        for position in 0..8 {
            settlements.record(Outcome::Answered { position });
        }
        journal.checkpoint(&settlements).expect("checkpoints");
        journal.close().expect("closes");

        let listed = list(&root).expect("lists").entries;
        assert!(listed[0].is_complete());
        assert_eq!(listed[0].settled(), Some(8));
    }

    /// A journal that stopped before its first checkpoint reads as a fresh cursor, not an
    /// unreadable journal.
    #[test]
    fn a_journal_with_no_checkpoint_resumes_from_the_beginning() {
        let root = scratch("no-checkpoint");
        let map = plan("192.0.2.1-192.0.2.4", "80,443");

        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let (_journal, checkpoint) =
            Journal::resume(&directory, &ports(&map), Privilege::Raw).expect("resumes");

        assert_eq!(checkpoint, Checkpoint::default());
        assert_eq!(checkpoint.remaining(map.iter()).count(), 8);
    }

    /// Ids sort by creation time as text, including ids minted one after another.
    #[test]
    fn ids_are_sortable_and_distinct() {
        let mut ids: Vec<String> = (0..64).map(|_| mint_id()).collect();

        assert!(ids.iter().all(|id| id.len() == ID_CHARS));
        let distinct: std::collections::BTreeSet<&String> = ids.iter().collect();
        assert_eq!(distinct.len(), ids.len(), "ids collided");

        let sorted = {
            ids.sort();
            ids.clone()
        };
        assert_eq!(ids, sorted, "ids minted in one burst lost their order");

        // And across milliseconds, where the clock decides.
        let first = mint_id();
        std::thread::sleep(std::time::Duration::from_millis(3));
        let second = mint_id();
        assert!(first < second, "{first} should sort before {second}");
    }

    /// A listing skips what it cannot read, so one damaged journal does not hide the
    /// rest.
    #[test]
    fn an_unreadable_journal_does_not_hide_the_others() {
        let root = scratch("damaged");
        let map = plan("192.0.2.1", "80");
        begin(&root, &map).close().expect("closes");

        let damaged = root.join("01JUNREADABLEJUNREADABLE00");
        fs::create_dir_all(&damaged).expect("directory");
        fs::write(damaged.join(MANIFEST), "{not json").expect("writes");

        let listed = list(&root).expect("lists").entries;
        assert_eq!(listed.len(), 1, "the readable one is still there");
    }

    /// Pruning removes a journal nobody is writing and refuses one somebody is.
    #[test]
    fn pruning_refuses_a_journal_that_is_being_written() {
        let root = scratch("prune");
        let map = plan("192.0.2.1", "80");

        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();

        assert!(matches!(remove(&directory), Err(OpenError::Locked(_))));

        journal.close().expect("closes");
        remove(&directory).expect("removes a free journal");
        assert!(list(&root).expect("lists").entries.is_empty());
    }

    /// The ticker writes a final checkpoint and releases the lock, so a scan that
    /// finishes between two ticks still records what it did.
    #[tokio::test]
    async fn the_checkpoint_task_writes_a_final_cursor_and_releases() {
        let root = scratch("ticker");
        let map = plan("192.0.2.1-192.0.2.4", "80,443");
        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();

        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        for position in 0..5 {
            ctx.record_outcome(Outcome::Answered { position });
        }

        // Finishes well inside one tick.
        spawn_checkpoints(journal, ctx.progress()).finish(&[]).await;

        let checkpoint = Checkpoint::read(&directory.join(CURSOR)).expect("a cursor was written");
        assert_eq!(checkpoint.watermark, 5);
        assert_eq!(
            super::super::lock::inspect(&directory.join(LOCK)),
            LockState::Free,
            "the lock outlived the scan and was then released"
        );
    }

    /// A resumed sitting that settles nothing still writes a cursor covering the first
    /// sitting's work. Without seeding the live cursor from the resume point, the second
    /// sitting's checkpoint would erase the first's progress.
    #[test]
    fn a_resumed_cursor_carries_the_earlier_sittings_progress() {
        let root = scratch("carry-forward");
        let map = plan("192.0.2.1-192.0.2.4", "80,443");

        let directory = {
            let mut journal = begin(&root, &map);
            let settlements = Settlements::default();
            for position in 0..3 {
                settlements.record(Outcome::Answered { position });
            }
            journal.checkpoint(&settlements).expect("checkpoints");
            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        let (mut journal, checkpoint) =
            Journal::resume(&directory, &ports(&map), Privilege::Raw).expect("resumes");

        // Seeded from the resume point, as a scan does.
        let settlements = Settlements::resuming(&checkpoint);
        journal
            .checkpoint(&settlements)
            .expect("checkpoints having settled nothing new");
        journal.close().expect("closes");

        let carried = Checkpoint::read(&directory.join(CURSOR)).expect("reads");
        assert_eq!(
            carried.watermark, 3,
            "the second sitting must not roll the cursor back"
        );
    }

    /// Findings survive the journal.
    #[test]
    fn what_a_sitting_found_comes_back() {
        use crate::model::host::HostStatus;
        use crate::model::port::{Port, PortState, Protocol};

        let root = scratch("findings");
        let map = plan("192.0.2.1-192.0.2.4", "80,443");

        let directory = {
            let mut journal = begin(&root, &map);

            let mut host = Host::new("192.0.2.1".parse().expect("an address"));
            host.set_status(HostStatus::Up);
            host.set_hostname(Some("router.example".to_string()));
            host.add_port(Port::new(80, Protocol::Tcp, PortState::Open));

            journal.record_hosts(&[host]).expect("records");

            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        let (journal, _) =
            Journal::resume(&directory, &ports(&map), Privilege::Raw).expect("resumes");

        let restored = journal.restored();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].hostname(), Some("router.example"));
        assert_eq!(restored[0].port_count(), 1);
        assert!(restored[0].is_alive());
    }

    /// A detection run's tape survives the round trip, so a recorded scan can be
    /// replayed offline. Its own file, so it never disturbs the hosts a resume reads.
    #[test]
    fn detection_run_tapes_survive_a_journal_round_trip() {
        use crate::detect::compute::{CapTape, CapTapeRecord, DetectionRunRecord, SpeakExchange};
        use crate::model::finding::{DetectionId, Version};
        use crate::record::DetectionIdRecord;

        let root = scratch("detections");
        let map = plan("192.0.2.1", "80");

        let tape = CapTape {
            speaks: vec![SpeakExchange {
                sent: b"PING\r\n".to_vec(),
                reply: Ok(b"+PONG\r\n".to_vec()),
            }],
            nows: vec![7],
            ..CapTape::default()
        };
        let detection = DetectionId::new("redis-unauth", Version::new(1, 0, 0), "abc").unwrap();
        let run = DetectionRunRecord {
            host: "192.0.2.1".to_string(),
            host_name: None,
            port: 80,
            protocol: "tcp".to_string(),
            detection: DetectionIdRecord::from(&detection),
            responses: vec!["+PONG\r\n".to_string()],
            tape: CapTapeRecord::from(&tape),
        };

        let directory = {
            let mut journal = begin(&root, &map);
            journal
                .record_detections(std::slice::from_ref(&run))
                .expect("records the run");
            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        let read = read_detections(&directory).expect("reads the runs back");
        assert_eq!(
            read,
            vec![run],
            "a detection run did not survive the journal"
        );
        assert_eq!(
            read[0].tape.rebuild(),
            tape,
            "the tape did not rebuild to what was recorded"
        );
    }

    /// A run over `port` of 192.0.2.1 by the passive detection `id`, which read
    /// `responses` and sent nothing.
    fn passive_run(
        id: &str,
        port: u16,
        responses: &[&str],
    ) -> crate::detect::compute::DetectionRunRecord {
        use crate::detect::compute::{CapTape, CapTapeRecord, DetectionRunRecord};
        use crate::model::finding::{DetectionId, Version};
        use crate::record::DetectionIdRecord;

        let detection = DetectionId::new(id, Version::new(1, 0, 0), "abc").expect("an id");
        DetectionRunRecord {
            host: "192.0.2.1".to_string(),
            host_name: None,
            port,
            protocol: "tcp".to_string(),
            detection: DetectionIdRecord::from(&detection),
            responses: responses
                .iter()
                .map(|response| response.to_string())
                .collect(),
            tape: CapTapeRecord::from(&CapTape::default()),
        }
    }

    /// Every passive detection matching a service reads the same responses gathered at
    /// its port, a dozen for any HTTP port, so a port's responses are written once and every
    /// run over it reads them back.
    #[test]
    fn a_ports_responses_are_written_once_however_many_runs_read_them() {
        let root = scratch("tapes-once");
        let map = plan("192.0.2.1", "80");
        let page = "HTTP/1.1 200 OK\r\nServer: a-distinctive-server\r\n\r\n";

        let runs: Vec<_> = (0..13)
            .map(|n| passive_run(&format!("http-{n}"), 80, &[page]))
            .chain([passive_run("ssh-banner", 22, &["SSH-2.0-x\r\n"])])
            .collect();

        let directory = {
            let mut journal = begin(&root, &map);
            journal.record_detections(&runs).expect("records the runs");
            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        let written = fs::read_to_string(directory.join(DETECTIONS)).expect("reads the file");
        assert_eq!(written.matches("a-distinctive-server").count(), 1);
        assert_eq!(read_detections(&directory).expect("reads back"), runs);
    }

    /// A journal written one run per line, each with its own copy of what it read, is
    /// still replayed beside runs written one port per line.
    #[test]
    fn tapes_written_one_run_to_a_line_still_read_back() {
        use std::io::Write;

        let root = scratch("tapes-legacy");
        let map = plan("192.0.2.1", "80");
        let grouped = passive_run("http-title", 80, &["HTTP/1.1 200 OK\r\n\r\n"]);
        let alone = passive_run("ssh-banner", 22, &["SSH-2.0-x\r\n"]);

        let directory = {
            let mut journal = begin(&root, &map);
            journal
                .record_detections(std::slice::from_ref(&grouped))
                .expect("records the run");
            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(directory.join(DETECTIONS))
            .expect("opens the file");
        let line = serde_json::to_string(&alone).expect("serialises");
        writeln!(file, "{line}").expect("appends a run on its own");

        assert_eq!(
            read_detections(&directory).expect("reads back"),
            [grouped, alone]
        );
    }

    /// A host written more than once comes back whole: the scan that found it and the
    /// scan that classified its ports both wrote.
    #[test]
    fn repeated_records_for_one_host_are_folded_together() {
        use crate::model::host::HostStatus;
        use crate::model::port::{Port, PortState, Protocol};

        let root = scratch("folded");
        let map = plan("192.0.2.1", "80");
        let ip: std::net::IpAddr = "192.0.2.1".parse().expect("an address");

        let directory = {
            let mut journal = begin(&root, &map);

            let mut found = Host::new(ip);
            found.set_status(HostStatus::Up);
            journal.record_hosts(&[found]).expect("the host answered");

            let mut classified = Host::new(ip);
            classified.add_port(Port::new(80, Protocol::Tcp, PortState::Open));
            journal
                .record_hosts(&[classified])
                .expect("and then its ports");

            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        let (journal, _) =
            Journal::resume(&directory, &ports(&map), Privilege::Raw).expect("resumes");

        let restored = journal.restored();
        assert_eq!(restored.len(), 1, "one address is one host");
        assert!(restored[0].is_alive(), "the first record's status survived");
        assert_eq!(restored[0].port_count(), 1, "the second record's port too");
    }

    /// `fe80::1` is a different machine on every link, so two gateways found under that
    /// number on two interfaces stay two hosts, as in the live report and a diff.
    #[test]
    fn link_locals_on_two_interfaces_come_back_as_two_hosts() {
        use crate::model::host::HostStatus;
        use crate::model::ip::scoped::Zone;

        let root = scratch("zones");
        let map = plan("192.0.2.1", "80");
        let ip: std::net::IpAddr = "fe80::1".parse().expect("an address");

        let directory = {
            let mut journal = begin(&root, &map);
            let hosts: Vec<Host> = [Zone::new(4, "en0"), Zone::new(9, "en7")]
                .into_iter()
                .map(|zone| {
                    let mut host = Host::new(ip);
                    host.set_status(HostStatus::Up);
                    host.set_zone(zone);
                    host
                })
                .collect();
            journal.record_hosts(&hosts).expect("records both");

            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        assert_eq!(report(&directory).expect("reads").host_count(), 2);

        let (journal, _) =
            Journal::resume(&directory, &ports(&map), Privilege::Raw).expect("resumes");
        let mut zones: Vec<&str> = journal
            .restored()
            .iter()
            .filter_map(|host| host.zone().map(Zone::name))
            .collect();
        zones.sort_unstable();
        assert_eq!(zones, ["en0", "en7"], "each restored on its own link");
    }

    /// A journal that stopped before it found anything reads as no findings.
    #[test]
    fn a_journal_with_no_findings_restores_nothing() {
        let root = scratch("no-findings");
        let map = plan("192.0.2.1", "80");

        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let (journal, _) =
            Journal::resume(&directory, &ports(&map), Privilege::Raw).expect("resumes");
        assert!(journal.restored().is_empty());
    }

    /// A finished scan comes back out of its journal as the report it produced:
    /// everything the end of a run prints is drawn from the hosts and the phases.
    #[test]
    fn a_journal_reads_back_as_the_report_its_scan_produced() {
        let root = scratch("replay");
        let map = plan("192.0.2.1-192.0.2.4", "80,443");
        let original = crate::export::fixture::report();

        let directory = {
            let mut journal = begin(&root, &map);
            let hosts: Vec<Host> = original.hosts().cloned().collect();
            journal.record_hosts(&hosts).expect("records hosts");
            journal
                .record_phases(original.phases())
                .expect("records phases");

            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        let replayed = report(&directory).expect("reads");

        assert_eq!(replayed.host_count(), original.host_count());
        assert_eq!(replayed.phases().len(), original.phases().len());
        assert_eq!(
            replayed.summary().hosts_alive,
            original.summary().hosts_alive
        );
        assert_eq!(replayed.summary().ports_open, original.summary().ports_open);

        // A phase carries what the run covered and how it went.
        let (before, after) = (&original.phases()[0], &replayed.phases()[0]);
        assert_eq!(after.kind(), before.kind());
        assert_eq!(after.privilege(), before.privilege());
        assert_eq!(after.failures().len(), before.failures().len());
        assert_eq!(
            replayed.is_partial(),
            original.is_partial(),
            "a scan that left ground uncovered has to still say so"
        );
    }

    /// A report read back names the engine that ran the scan, not the one reading it.
    #[test]
    fn a_replayed_report_names_the_engine_that_ran_the_scan() {
        let root = scratch("replay-version");
        let map = plan("192.0.2.1", "80");

        let directory = {
            let journal = begin(&root, &map);
            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        // The manifest as an earlier build would have left it.
        let path = directory.join(MANIFEST);
        let mut manifest: JournalManifest =
            serde_json::from_str(&fs::read_to_string(&path).expect("reads")).expect("parses");
        manifest.engine_version = "0.1.0".to_string();
        fs::write(&path, serde_json::to_vec(&manifest).expect("encodes")).expect("writes");

        let replayed = report(&directory).expect("reads");

        assert_eq!(replayed.engine_version(), "0.1.0");
        assert_ne!(
            replayed.engine_version(),
            crate::report::ENGINE_VERSION,
            "this build's version must not have been stamped over the record's"
        );
    }

    /// A cursor that exists and cannot be read is not a scan that settled nothing.
    ///
    /// A `sudo` scan whose cursor was not handed over leaves exactly this. Reported as zero,
    /// every finished scan would list as untouched; reported as unknown, a reader is told to go
    /// and look.
    #[cfg(unix)]
    #[test]
    fn a_cursor_that_cannot_be_read_is_not_a_scan_that_settled_nothing() {
        use std::os::unix::fs::PermissionsExt;

        let root = scratch("unreadable-cursor");
        let map = plan("192.0.2.1-192.0.2.4", "80");

        let directory = {
            let mut journal = begin(&root, &map);
            let settlements = Settlements::default();
            settlements.record(Outcome::Answered { position: 0 });
            journal.checkpoint(&settlements).expect("checkpoints");

            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        // Readable first, so the difference below is the permission, not the contents.
        let listed = list(&root).expect("lists").entries;
        assert_eq!(listed[0].settled(), Some(1));

        fs::set_permissions(directory.join(CURSOR), fs::Permissions::from_mode(0o000))
            .expect("removes every permission");

        let listed = list(&root)
            .expect("a journal it cannot read must not hide the rest")
            .entries;
        assert_eq!(listed.len(), 1, "the journal still lists");
        assert_eq!(
            listed[0].settled(),
            None,
            "unreadable is not zero: zero is a claim about the scan"
        );
        assert!(
            !listed[0].is_complete(),
            "and nothing that cannot be read may be called finished"
        );

        // Left readable, so a failure here leaves a file the next run can clean up.
        let _ = fs::set_permissions(directory.join(CURSOR), fs::Permissions::from_mode(0o600));
    }

    /// What a scan learns after its last checkpoint reaches the file.
    ///
    /// The enrichment passes (OS identification, the echo probe, traceroute) run at the end,
    /// often after the last timer checkpoint. If the closing write missed them, a replayed
    /// report would silently lack them.
    #[tokio::test]
    async fn what_a_scan_learns_after_a_checkpoint_still_reaches_the_file() {
        use crate::model::host::{HostStatus, StatusProtocol, StatusReason};

        let root = scratch("late-findings");
        let map = plan("192.0.2.1", "80");
        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();

        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let mut ticker = spawn_checkpoints(journal, ctx.progress());

        // What the liveness pass found.
        let ip: std::net::IpAddr = "192.0.2.1".parse().expect("an address");
        ctx.update_host(ip, |host| {
            host.set_status(HostStatus::Up);
            host.record_evidence(
                HostStatus::Up,
                StatusReason::new(StatusProtocol::Arp, "answered"),
            );
        });

        // A checkpoint lands, taking that and leaving nothing behind.
        ticker.checkpointed().await;

        // Then the enrichment finds something else.
        ctx.update_host(ip, |host| {
            host.record_evidence(
                HostStatus::Up,
                StatusReason::new(StatusProtocol::IcmpEcho, "echo answered"),
            );
        });

        ticker.finish(&[]).await;

        let restored = read_findings(&directory).expect("reads");
        assert_eq!(restored.len(), 1, "one host was scanned");

        let protocols: Vec<_> = restored[0]
            .reasons()
            .iter()
            .map(|reason| reason.protocol.clone())
            .collect();
        assert!(
            protocols.contains(&StatusProtocol::IcmpEcho),
            "what the scan learned last was lost: {protocols:?}"
        );
    }

    fn aged(id: &str, created_at: SystemTime, settled: u64, total: u128) -> Entry {
        Entry {
            directory: PathBuf::from(id),
            manifest: JournalManifest {
                links: Vec::new(),
                journal_version: crate::journal::JOURNAL_VERSION,
                id: id.to_string(),
                engine_version: "0.0.0".to_string(),
                created_at,
                kind: crate::record::wire::scan_kind_name(ScanKind::PortScan).to_owned(),
                plan: crate::journal::manifest::PlanFingerprint::of(
                    &ports(&plan("192.0.2.1", "80")),
                    Privilege::Raw,
                ),
                targets: crate::record::PlanRecord::from(&plan("192.0.2.1", "80")),
                technique: TcpScanTechnique::Syn.name().to_owned(),
                sweep: false,
                privilege: Privilege::Raw,
                total_targets: total,
                order_seed: None,
                summary: String::new(),
            },
            checkpoint: Some(Checkpoint {
                watermark: settled,
                settled_above: Vec::new(),
                walked: None,
            }),
            lock: LockState::Free,
        }
    }

    fn ago(seconds: u64) -> SystemTime {
        now() - Duration::from_secs(seconds)
    }

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
    }

    /// Finished journals age out; unfinished ones do not.
    #[test]
    fn age_removes_finished_journals_and_keeps_unfinished_ones() {
        let entries = vec![
            aged("finished-old", ago(100), 1, 1),
            aged("unfinished-old", ago(100), 0, 1),
            aged("finished-new", ago(1), 1, 1),
        ];

        let retention = Retention {
            completed_for: Some(Duration::from_secs(50)),
            incomplete_for: None,
            keep_at_most: None,
            unreadable: false,
        };

        assert_eq!(retention.expired(&entries, now()), vec![0]);
    }

    /// A journal something is writing is never selected, however old.
    #[test]
    fn a_live_journal_is_never_pruned() {
        let mut entries = vec![aged("held", ago(10_000), 1, 1)];
        entries[0].lock = LockState::Held {
            pid: 1,
            last_beat: Duration::from_secs(1),
        };

        let retention = Retention {
            completed_for: Some(Duration::from_secs(1)),
            incomplete_for: Some(Duration::from_secs(1)),
            keep_at_most: Some(0),
            unreadable: false,
        };

        assert!(retention.expired(&entries, now()).is_empty());
    }

    /// The cap takes finished journals before unfinished ones, and the oldest first within
    /// each.
    #[test]
    fn the_cap_removes_duplicates_before_unfinished_work() {
        // `list` yields newest first.
        let entries = vec![
            aged("finished-new", ago(1), 1, 1),
            aged("unfinished-mid", ago(2), 0, 1),
            aged("finished-old", ago(3), 1, 1),
        ];

        let retention = Retention {
            completed_for: None,
            incomplete_for: None,
            keep_at_most: Some(2),
            unreadable: false,
        };

        let removed = retention.expired(&entries, now());
        assert_eq!(removed, vec![2], "the older of the two finished ones");

        // Tighter still, and the unfinished one is the last to go.
        let retention = Retention {
            keep_at_most: Some(1),
            ..retention
        };
        let removed = retention.expired(&entries, now());
        assert_eq!(
            removed,
            vec![0, 2],
            "both finished ones, the unfinished kept"
        );
    }

    /// Keeping everything keeps everything.
    #[test]
    fn keeping_everything_removes_nothing() {
        let entries = vec![
            aged("ancient", ago(900_000), 1, 1),
            aged("also-ancient", ago(900_000), 0, 1),
        ];

        assert!(
            Retention::keep_everything()
                .expired(&entries, now())
                .is_empty()
        );
    }

    /// The default keeps an unfinished scan whatever its age, and lets a finished one go
    /// after a month.
    #[test]
    fn the_default_favours_unfinished_work() {
        let two_months = Duration::from_secs(60 * 24 * 60 * 60);
        let created = now() - two_months;

        let entries = vec![
            aged("finished", created, 1, 1),
            aged("unfinished", created, 0, 1),
        ];

        assert_eq!(Retention::default().expired(&entries, now()), vec![0]);
    }

    /// End to end: a prune removes what the policy chose and names it.
    #[test]
    fn pruning_removes_what_the_policy_selected() {
        let root = scratch("retention");
        let map = plan("192.0.2.1", "80");

        // Finished, so the default lets it go once it is old enough.
        let mut journal = begin(&root, &map);
        let settlements = Settlements::default();
        settlements.record(Outcome::Answered { position: 0 });
        journal.checkpoint(&settlements).expect("checkpoints");
        let id = journal.manifest().id.clone();
        journal.close().expect("closes");

        // Nothing is old enough for the default yet.
        let untouched = prune(&root, &Retention::default()).expect("prunes");
        assert!(untouched.removed.is_empty());
        assert_eq!(list(&root).expect("lists").entries.len(), 1);

        // A policy that keeps nothing finished takes it, and names it.
        let swept = prune(
            &root,
            &Retention {
                completed_for: Some(Duration::ZERO),
                ..Retention::default()
            },
        )
        .expect("prunes");

        assert_eq!(swept.removed, vec![id]);
        assert!(swept.held.is_empty());
        assert!(list(&root).expect("lists").entries.is_empty());

        std::fs::remove_dir_all(&root).ok();
    }

    /// A host whose primary address is promoted mid-scan is still one host.
    ///
    /// Local discovery calls `Host::consider_primary_ip` when a better address turns up, so the
    /// same machine can be written under a link-local address and then a global one.
    #[test]
    fn a_host_written_under_two_addresses_comes_back_as_one() {
        use crate::model::host::HostStatus;

        let root = scratch("promoted");
        let map = plan("192.0.2.1", "80");
        let link_local: std::net::IpAddr = "fe80::1".parse().expect("an address");
        let global: std::net::IpAddr = "2001:db8::1".parse().expect("an address");

        let directory = {
            let mut journal = begin(&root, &map);

            // Found over its link-local address first.
            let mut early = Host::new(link_local);
            early.set_status(HostStatus::Up);
            journal.record_hosts(&[early]).expect("records");

            // Then a global address takes the primary slot.
            let mut promoted = Host::new(link_local);
            promoted.add_ip(global);
            assert!(
                promoted.consider_primary_ip(global),
                "the global address should lead"
            );
            promoted.set_hostname(Some("router.example".to_string()));
            journal.record_hosts(&[promoted]).expect("records again");

            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        let (journal, _) =
            Journal::resume(&directory, &ports(&map), Privilege::Raw).expect("resumes");

        let restored = journal.restored();
        assert_eq!(
            restored.len(),
            1,
            "one machine, written twice: {:?}",
            restored.iter().map(Host::primary_ip).collect::<Vec<_>>()
        );
        assert!(restored[0].is_alive(), "the first record's status survived");
        assert_eq!(restored[0].hostname(), Some("router.example"));
    }

    /// Journal files are private to their owner.
    #[cfg(unix)]
    #[test]
    fn every_file_a_journal_writes_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = scratch("modes");
        let map = plan("192.0.2.1", "80");

        let mut journal = begin(&root, &map);
        let settlements = Settlements::default();
        settlements.record(Outcome::Answered { position: 0 });
        journal
            .record(
                &[Host::new("192.0.2.1".parse().expect("an address"))],
                &settlements,
            )
            .expect("records");
        let directory = journal.directory().to_path_buf();

        let mode_of = |path: &Path| {
            fs::metadata(path)
                .unwrap_or_else(|e| panic!("{path:?}: {e}"))
                .permissions()
                .mode()
                & 0o777
        };

        assert_eq!(mode_of(&directory), 0o700, "the directory");
        for name in [MANIFEST, CURSOR, HOSTS, PHASES, LOCK] {
            assert_eq!(mode_of(&directory.join(name)), 0o600, "{name}");
        }

        // And again after a heartbeat, which replaces the lock file.
        journal.checkpoint(&settlements).expect("beats");
        assert_eq!(mode_of(&directory.join(LOCK)), 0o600, "after a heartbeat");

        journal.close().expect("closes");
        std::fs::remove_dir_all(&root).ok();
    }

    /// The two append-only files refuse a link where the file should be, like every other
    /// journal file. The directory belongs to the invoking user and the writer is usually root,
    /// so a planted link would have root append an engagement's addresses wherever it
    /// points.
    #[cfg(unix)]
    #[test]
    fn appending_refuses_a_link_where_a_journal_file_should_be() {
        let root = scratch("nofollow");
        let map = plan("192.0.2.1", "80");
        let mut journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();

        let elsewhere = root.join("not-the-journals-to-touch");
        fs::write(&elsewhere, b"untouched").expect("writes");

        for name in [HOSTS, PHASES] {
            fs::remove_file(directory.join(name)).expect("removes");
            std::os::unix::fs::symlink(&elsewhere, directory.join(name)).expect("links");
        }

        let phases = crate::export::fixture::report().phases().to_vec();
        assert!(
            journal
                .record_hosts(&[Host::new("192.0.2.1".parse().expect("an address"))])
                .is_err(),
            "a link was appended to as the findings file"
        );
        assert!(
            journal.record_phases(&phases).is_err(),
            "a link was appended to as the phases file"
        );
        assert_eq!(
            fs::read(&elsewhere).expect("reads"),
            b"untouched",
            "the file behind the link was written through"
        );

        journal.close().expect("closes");
        std::fs::remove_dir_all(&root).ok();
    }

    /// A host recorded more than once reads back with the round trips its last record
    /// holds, not every record's added together. Each record carries the whole window as it
    /// stood, so folding them as new samples would count early round trips twice and skew the
    /// average.
    #[test]
    fn a_host_recorded_twice_keeps_the_round_trips_its_last_record_holds() {
        use std::time::Duration;

        let root = scratch("latency");
        let mut journal = begin(&root, &plan("192.0.2.1", "80"));
        let mut host = Host::new("192.0.2.1".parse().expect("an address"));
        host.add_rtts([Duration::from_millis(1), Duration::from_millis(2)]);
        journal.record_hosts(&[host.clone()]).expect("records");
        host.add_rtts([Duration::from_millis(6), Duration::from_millis(7)]);
        journal
            .record_hosts(&[host.clone()])
            .expect("records again");
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let read = report(&directory).expect("reads");
        std::fs::remove_dir_all(&root).ok();
        let [restored] = read.hosts().collect::<Vec<_>>()[..] else {
            panic!("one host on record");
        };
        let figures = |host: &Host| (host.min_rtt(), host.average_rtt(), host.max_rtt());
        assert_eq!(figures(restored), figures(&host), "min, average, max");
        assert_eq!(
            restored.telemetry().history().len(),
            host.telemetry().history().len(),
            "round trips held"
        );
    }

    /// A host written at every checkpoint reads back as the host it is, every field of
    /// it. Each record repeats its host's fields, so a field folded as though each record were
    /// new would count the repeats. Checked over everything a record keeps, for the richest
    /// hosts the schema describes, grown between checkpoints with a port changing at each.
    #[test]
    fn a_host_recorded_at_every_checkpoint_reads_back_as_the_host_it_is() {
        use crate::model::confidence::Confidence;
        use crate::model::finding::{DetectionClass, DetectionId, Finding, Severity, Version};
        use crate::model::host::{OsEvidence, OsSource};

        let root = scratch("repeated");
        let mut journal = begin(&root, &plan("203.0.113.1-203.0.113.9", "22,80,443,445"));
        let mut hosts: Vec<Host> = crate::export::fixture::report().hosts().cloned().collect();
        for checkpoint in 0..3u64 {
            let finding = Finding::new(
                DetectionId::new(format!("check-{checkpoint}"), Version::new(1, 0, 0), "")
                    .expect("an id"),
                "A check",
                Severity::Low,
                Confidence::Certain,
                DetectionClass::Passive,
            )
            .expect("a finding");
            for host in &mut hosts {
                host.add_rtt(Duration::from_micros(700 + 100 * checkpoint));
                host.record_os_evidence(OsEvidence {
                    source: OsSource::ServiceBanner,
                    family: Some("Linux".to_string()),
                    device: None,
                    vendor: None,
                    product: None,
                    version: None,
                    kernel: None,
                    arch: None,
                    cpe: None,
                    confidence: 0.5,
                    evidence: format!("banner read at checkpoint {checkpoint}"),
                });
                host.add_finding(finding.clone());
                let first = host
                    .ports()
                    .next()
                    .map(|port| (port.number(), port.protocol()));
                if let Some((number, protocol)) = first {
                    host.add_port_finding(number, protocol, finding.clone());
                }
            }
            journal.record_hosts(&hosts).expect("records");
        }
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let mut read = read_findings(&directory).expect("reads");
        std::fs::remove_dir_all(&root).ok();
        read.sort_by_key(Host::primary_ip);
        hosts.sort_by_key(Host::primary_ip);
        let as_recorded = |hosts: &[Host]| {
            hosts
                .iter()
                .map(|host| serde_json::to_value(HostRecord::from(host)).expect("serialises"))
                .collect::<Vec<_>>()
        };
        assert_eq!(as_recorded(&read), as_recorded(&hosts));
    }

    /// A journal from a newer format is passed over by name and with why: the listing
    /// still holds every journal it can read.
    #[test]
    fn a_journal_from_a_newer_format_is_passed_over_by_name() {
        let root = scratch("passed-over");
        let map = plan("192.0.2.1", "80");
        let readable = begin(&root, &map);
        readable.close().expect("closes");
        let newer = begin(&root, &map);
        let newer_dir = newer.directory().to_path_buf();
        newer.close().expect("closes");
        age_forward(&newer_dir);

        let listing = list(&root).expect("lists");
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(listing.entries.len(), 1, "the readable journal lists");
        let [passed] = listing.passed_over.as_slice() else {
            panic!("one passed over: {:?}", listing.passed_over);
        };
        assert_eq!(passed.directory, newer_dir);
        assert_eq!(
            Some(passed.name.as_str()),
            newer_dir.file_name().and_then(|name| name.to_str())
        );
        assert_eq!(
            passed.why,
            Unlisted::NewerFormat {
                found: super::super::JOURNAL_VERSION + 1
            }
        );
    }

    /// A prune takes an unreadable journal only when asked to, by directory name, and
    /// never a link. Such a journal is usually a newer build's, which still reads it.
    #[cfg(unix)]
    #[test]
    fn a_prune_takes_unreadable_journals_only_when_asked_and_never_a_link() {
        let root = scratch("prune-unreadable");
        let elsewhere = scratch("prune-unreadable-elsewhere");
        let map = plan("192.0.2.1", "80");
        let newer = begin(&root, &map);
        let newer_dir = newer.directory().to_path_buf();
        newer.close().expect("closes");
        age_forward(&newer_dir);
        let target = begin(&elsewhere, &map);
        let target_dir = target.directory().to_path_buf();
        target.close().expect("closes");
        std::os::unix::fs::symlink(&target_dir, root.join("06LINKED00000000")).expect("links");

        let ordinary = prune(&root, &Retention::default()).expect("prunes");
        assert!(ordinary.removed.is_empty() && ordinary.held.is_empty());
        assert!(newer_dir.exists(), "an ordinary sweep leaves it");

        let mut asked = Retention::keep_everything();
        asked.unreadable = true;
        let pruned = prune(&root, &asked).expect("prunes");
        let newer_gone = !newer_dir.exists();
        let target_kept = target_dir.exists();
        let link_kept = root.join("06LINKED00000000").symlink_metadata().is_ok();
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&elsewhere).ok();

        assert!(newer_gone, "asked for, it goes");
        assert_eq!(pruned.removed.len(), 1, "{pruned:?}");
        assert!(pruned.held.is_empty(), "a link is not selected: {pruned:?}");
        assert!(
            link_kept && target_kept,
            "neither the link nor what it names goes"
        );
    }

    /// Rewrites a journal's manifest to claim the next format, as a newer build would.
    fn age_forward(directory: &Path) {
        let path = directory.join(MANIFEST);
        let mut manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("reads")).expect("parses");
        manifest["journal_version"] = serde_json::json!(super::super::JOURNAL_VERSION + 1);
        fs::write(&path, serde_json::to_vec(&manifest).expect("encodes")).expect("writes");
    }

    /// A link in a root of journals is not listed as a journal. Followed, it would list
    /// a record from somewhere else, and under `sudo` have root look wherever it leads.
    #[cfg(unix)]
    #[test]
    fn a_link_in_a_root_of_journals_is_not_listed() {
        let root = scratch("listed-link");
        let elsewhere = scratch("listed-link-elsewhere");
        let journal = begin(&elsewhere, &plan("192.0.2.1", "80"));
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");
        std::os::unix::fs::symlink(&directory, root.join("06LINKED00000000")).expect("links");

        let listed = list(&root).expect("lists").entries.len();
        let where_it_is = list(&elsewhere).expect("lists").entries.len();
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&elsewhere).ok();
        assert_eq!(listed, 0, "the link was listed as a journal");
        assert_eq!(where_it_is, 1, "the journal itself lists");
    }

    /// Reading a journal refuses a link where one of its files should be, and says so.
    ///
    /// The directory is the invoking user's and the reader is usually root, so a planted link
    /// would have root read whatever the user chose, such as another job's plan or a root-only
    /// file.
    #[cfg(unix)]
    #[test]
    fn reading_refuses_a_link_where_a_journal_file_should_be() {
        let root = scratch("read-nofollow");
        let mut ours = begin(&root, &plan("192.0.2.1", "80"));
        ours.record_hosts(&[Host::new("192.0.2.1".parse().expect("an address"))])
            .expect("records");
        ours.write_cursor(&Checkpoint::default())
            .expect("checkpoints");
        let directory = ours.directory().to_path_buf();
        ours.close().expect("closes");

        let mut theirs = begin(&root, &plan("198.51.100.7", "80"));
        theirs
            .record_hosts(&[Host::new("198.51.100.7".parse().expect("an address"))])
            .expect("records");
        theirs
            .write_cursor(&Checkpoint::new(1, []))
            .expect("checkpoints");
        let elsewhere = theirs.directory().to_path_buf();
        theirs.close().expect("closes");
        let text = root.join("not-a-journal-file");
        fs::write(&text, b"somebody else's bytes").expect("writes");

        let refused = |name: &str, error: String| {
            assert!(
                error.contains("is a link"),
                "{name}: refused, but not as a link: {error}"
            );
        };
        for name in [MANIFEST, CURSOR, HOSTS, PHASES] {
            let kept = directory.join(format!("{name}.kept"));
            fs::rename(directory.join(name), &kept).expect("moves aside");
            std::os::unix::fs::symlink(elsewhere.join(name), directory.join(name)).expect("links");

            match Journal::reopen(&directory, Privilege::Raw) {
                Ok(_) => panic!("{name}: resumed through a link"),
                Err(error) => refused(name, error.to_string()),
            }
            if matches!(name, MANIFEST | HOSTS | PHASES) {
                match report(&directory) {
                    Ok(_) => panic!("{name}: reported through a link"),
                    Err(error) => refused(name, error.to_string()),
                }
            }

            fs::remove_file(directory.join(name)).expect("removes the link");
            fs::rename(&kept, directory.join(name)).expect("restores");
        }

        // Files read after a job's start are refused the same way.
        let journal = begin(&root, &plan("192.0.2.2", "80"));
        for name in [DETECTIONS, FINISHED] {
            std::os::unix::fs::symlink(&text, journal.directory().join(name)).expect("links");
        }
        match read_detections(journal.directory()) {
            Ok(runs) => panic!("detections read through a link: {runs:?}"),
            Err(error) => refused(DETECTIONS, error.to_string()),
        }
        match journal.finished_hosts() {
            Ok(hosts) => panic!("finished hosts read through a link: {hosts:?}"),
            Err(error) => refused(FINISHED, error.to_string()),
        }
        journal.close().expect("closes");

        std::fs::remove_dir_all(&root).ok();
    }

    /// A cursor naming positions the watermark already passed does not make the scan look
    /// more finished. `Checkpoint::read` keeps such entries and `Cursor::from_checkpoint`
    /// filters them, so the listing must count the same way: `is_complete` is what a retention
    /// sweep deletes on.
    #[test]
    fn a_cursor_repeating_settled_positions_does_not_inflate_the_count() {
        let root = scratch("inflated-cursor");
        let map = plan("192.0.2.1-192.0.2.4", "80,443");

        let directory = {
            let journal = begin(&root, &map);
            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        // Four of the eight targets settled, and a list naming three of them again, as only
        // a damaged file would.
        let checkpoint = Checkpoint {
            watermark: 4,
            settled_above: vec![0, 1, 2, 6],
            walked: None,
        };
        checkpoint
            .write_atomically(&directory.join(CURSOR))
            .expect("writes");

        let entry = list(&root)
            .expect("lists")
            .entries
            .into_iter()
            .next()
            .expect("one journal");

        assert_eq!(
            entry.settled(),
            Some(5),
            "the watermark plus the one position genuinely above it"
        );
        assert!(
            !entry.is_complete(),
            "eight targets, five settled: a retention sweep must not take this"
        );
    }

    /// A torn tail followed by another append. The reader discards a torn line only while
    /// it is last; under `O_APPEND` the tear would become the prefix of a newline-terminated
    /// line, and every later read would fail with `Malformed`. `format`'s
    /// `a_torn_final_line_ends_the_journal_without_an_error` covers reading a tear; this covers
    /// appending past one.
    #[test]
    fn an_append_after_a_torn_tail_leaves_the_journal_readable() {
        let root = scratch("torn-tail-append");
        let map = plan("192.0.2.1-192.0.2.4", "80");
        let first: std::net::IpAddr = "192.0.2.1".parse().expect("an address");
        let second: std::net::IpAddr = "192.0.2.2".parse().expect("an address");

        let directory = {
            let mut journal = begin(&root, &map);
            journal.record_hosts(&[Host::new(first)]).expect("records");
            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        // The crash: a record that reached the file without its newline.
        {
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .append(true)
                .open(directory.join(HOSTS))
                .expect("opens");
            file.write_all(br#"{"ip":"192.0.2.9","stat"#)
                .expect("tears");
        }

        let (mut journal, _) = Journal::resume(&directory, &ports(&map), Privilege::Raw)
            .expect("resumes past the tear");
        journal.record_hosts(&[Host::new(second)]).expect("records");
        journal.close().expect("closes");

        let restored = read_findings(&directory).expect("the journal still reads");
        let addresses: Vec<_> = restored.iter().map(Host::primary_ip).collect();
        assert_eq!(
            addresses,
            vec![first, second],
            "the whole record before the tear and the one after it both survive"
        );
    }

    /// A header write that did not land. `open_findings` creates the file and writes its
    /// header in two steps, so a kill between them leaves a zero-length file. Appending into it
    /// would write records under no header, which every later read treats as no findings while
    /// the cursor advances.
    #[test]
    fn an_append_to_a_findings_file_whose_header_never_landed_mends_it() {
        let root = scratch("headerless-append");
        let map = plan("192.0.2.1", "80");
        let address: std::net::IpAddr = "192.0.2.1".parse().expect("an address");

        let mut journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();

        fs::write(directory.join(HOSTS), b"").expect("empties");

        journal
            .record_hosts(&[Host::new(address)])
            .expect("records");
        journal.close().expect("closes");

        let restored = read_findings(&directory).expect("reads");
        assert_eq!(
            restored.len(),
            1,
            "a record appended under no header is a record nothing reads back"
        );
    }

    /// A file this engine did not write is refused, not given a header, and left exactly
    /// as it was, which is why the header is checked before anything is truncated.
    #[test]
    fn an_append_to_a_file_this_engine_did_not_write_is_refused() {
        let root = scratch("foreign-append");
        let map = plan("192.0.2.1", "80");

        let mut journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();

        // Complete lines, so nothing here is a torn tail, just not a journal.
        let foreign: &[u8] = b"{\"not\":\"a journal\"}\n{\"still\":\"not\"}";
        fs::write(directory.join(HOSTS), foreign).expect("plants");

        assert!(
            journal
                .record_hosts(&[Host::new("192.0.2.1".parse().expect("an address"))])
                .is_err(),
            "a file with no header was appended to"
        );
        assert_eq!(
            fs::read(directory.join(HOSTS)).expect("reads"),
            foreign,
            "the file was edited before it was refused"
        );

        journal.close().expect("closes");
    }

    /// A journal that could not take its lock leaves nothing behind.
    #[test]
    fn a_journal_that_cannot_be_locked_leaves_no_directory() {
        let root = scratch("unlockable");
        let map = plan("192.0.2.1", "80");

        // A file where the scan directory would go: the create cannot proceed, and what it
        // did get to is undone.
        let before = list(&root).expect("lists").entries.len();
        assert_eq!(before, 0);

        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();

        // Held by this process, so a second journal over the same directory is refused the
        // way real contention is.
        assert!(matches!(
            Journal::resume(&directory, &ports(&map), Privilege::Raw),
            Err(OpenError::Locked(_))
        ));
        assert!(directory.exists(), "the held journal is untouched");

        journal.close().expect("closes");
        std::fs::remove_dir_all(&root).ok();
    }

    /// A host written again carries only the ports that changed, and reads back whole.
    #[test]
    fn a_host_written_again_carries_only_what_changed_in_it() {
        use crate::model::port::{Port, PortState, Protocol};

        let root = scratch("delta");
        let map = plan("192.0.2.1", "1-400");
        let mut journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();
        let length = || fs::metadata(directory.join(HOSTS)).expect("stats").len();

        let ip: std::net::IpAddr = "192.0.2.1".parse().expect("an address");
        let mut host = Host::new(ip);
        for number in 1..=400 {
            host.add_port(Port::new(number, Protocol::Tcp, PortState::Closed));
        }
        let before = length();
        journal
            .record_hosts(std::slice::from_ref(&host))
            .expect("records");
        let first = length() - before;

        host.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
        let before = length();
        journal
            .record_hosts(std::slice::from_ref(&host))
            .expect("records");
        let second = length() - before;

        assert!(
            second * 20 < first,
            "one port opening appended {second} bytes against the host's {first}"
        );
        journal.close().expect("closes");

        let restored = read_findings(&directory).expect("reads");
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].port_count(), 400, "every port read back");
        let open: Vec<u16> = restored[0]
            .ports()
            .filter(|port| port.state() == PortState::Open)
            .map(|port| port.number())
            .collect();
        assert_eq!(open, [22], "the change read back over what it changed");
        std::fs::remove_dir_all(&root).ok();
    }

    /// What a record supersedes is counted: the previous record's host fields and the
    /// earlier record of each port it rewrites, and nothing for a port's first record. The count
    /// decides compaction, so missing superseded bytes would let the file grow without bound
    /// and counting new findings would rewrite a file with nothing to drop.
    #[test]
    fn a_record_counts_what_it_supersedes_and_not_what_it_adds() {
        use crate::model::port::{Port, PortState, Protocol};

        let ip: std::net::IpAddr = "192.0.2.1".parse().expect("an address");
        let mut host = Host::new(ip);
        host.add_port(Port::new(22, Protocol::Tcp, PortState::Closed));
        let mut written = Written::default();

        let (_, first) = written.delta(&host).expect("measures").expect("new");
        let (rest, port) = (
            u64::from(first.rest.length),
            u64::from(first.ports[0].1.length),
        );
        written.update(first);
        assert_eq!(written.superseded, 0, "a first record supersedes nothing");

        host.add_port(Port::new(80, Protocol::Tcp, PortState::Closed));
        let (_, second) = written.delta(&host).expect("measures").expect("a new port");
        assert_eq!(second.ports.len(), 1, "only the new port is written");
        written.update(second);
        assert_eq!(written.superseded, rest, "the host's own fields, again");

        host.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
        let (_, third) = written
            .delta(&host)
            .expect("measures")
            .expect("a moved port");
        let rest_again = written.hosts[&host.scoped_ip()]
            .rest
            .map_or(0, |mark| u64::from(mark.length));
        written.update(third);
        assert_eq!(
            written.superseded,
            rest + rest_again + port,
            "and port 22's closed record under its open one"
        );
    }

    /// A failed compaction leaves no partial copy and is not retried at the next
    /// checkpoint, since what stopped it (usually a full disk) would stop the next. Here the
    /// rename is refused by a directory standing where the findings file goes.
    #[test]
    fn a_failed_compaction_leaves_nothing_behind_and_waits_before_trying_again() {
        let root = scratch("failed-compaction");
        let map = plan("192.0.2.1", "80");
        let mut journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();
        let host = Host::new("192.0.2.1".parse().expect("an address"));
        journal
            .record_hosts(std::slice::from_ref(&host))
            .expect("records");

        // As if the file had grown mostly superseded.
        journal.written.superseded = 3 * COMPACT_FLOOR;
        journal.length = 4 * COMPACT_FLOOR;
        assert!(journal.should_compact());

        fs::remove_file(directory.join(HOSTS)).expect("removes the findings");
        fs::create_dir_all(directory.join(HOSTS).join("occupied")).expect("blocks the name");
        assert!(journal.compact(std::slice::from_ref(&host)).is_err());

        assert!(
            !directory.join(HOSTS).with_extension("jsonl-tmp").exists(),
            "the partial copy is left holding the disk's room"
        );
        assert!(
            !journal.should_compact(),
            "a compaction that just failed is due again at once"
        );
        journal.written.superseded += 2 * COMPACT_FLOOR;
        assert!(
            journal.should_compact(),
            "and again once as much is superseded"
        );

        drop(journal);
        std::fs::remove_dir_all(&root).ok();
    }

    /// A findings file is rewritten once its superseded bytes outgrow the rest, and not
    /// while it is small or growing only by new findings.
    #[test]
    fn a_findings_file_is_compacted_by_what_it_superseded() {
        const MIB: u64 = 1024 * 1024;

        assert!(
            !outgrown(60 * MIB, 0),
            "a file that grew by what the scan found holds nothing to drop"
        );
        assert!(!outgrown(6 * MIB, 3 * MIB), "a small file is left alone");
        assert!(outgrown(9 * MIB, 5 * MIB), "past the floor it is rewritten");
        assert!(
            !outgrown(50 * MIB, 20 * MIB),
            "twenty superseded beside thirty live is not yet worth it"
        );
        assert!(
            outgrown(50 * MIB, 26 * MIB),
            "twenty-six beside twenty-four is"
        );
    }

    /// A long scan's findings file grows with its duration. Compaction bounds it and loses
    /// nothing.
    #[test]
    fn compaction_bounds_the_findings_file_without_losing_a_host() {
        use crate::model::host::HostStatus;
        use crate::model::port::{Port, PortState, Protocol};

        let root = scratch("compaction");
        let map = plan("192.0.2.1-192.0.2.4", "80");
        let addresses: Vec<std::net::IpAddr> = (1..=4)
            .map(|last| format!("192.0.2.{last}").parse().expect("an address"))
            .collect();

        let directory = {
            let mut journal = begin(&root, &map);

            // Four hosts, rewritten many times over, as a long scan does.
            let mut live: Vec<Host> = addresses.iter().map(|ip| Host::new(*ip)).collect();
            for round in 0..70 {
                for host in &mut live {
                    host.set_status(HostStatus::Up);
                    host.add_port(Port::new(1000 + round, Protocol::Tcp, PortState::Open));
                }
                journal.record_hosts(&live).expect("records");
            }

            journal.compact(&live).expect("compacts");
            assert!(!journal.should_compact(), "a file just written whole");

            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        // The file now holds one record per host.
        let lines = std::fs::read_to_string(directory.join(HOSTS))
            .expect("reads")
            .lines()
            .count();
        assert_eq!(lines, 1 + 4, "a header and one record each");

        // And nothing was lost.
        let (journal, _) =
            Journal::resume(&directory, &ports(&map), Privilege::Raw).expect("resumes");

        let restored = journal.restored();
        assert_eq!(restored.len(), 4);
        for host in restored {
            assert!(host.is_alive());
            assert_eq!(host.port_count(), 70, "every round's port survived");
        }

        std::fs::remove_dir_all(&root).ok();
    }

    /// A scan can be continued knowing only its id: the plan comes back as recorded, so
    /// nothing has to be retyped differently from what ran first.
    #[test]
    fn a_journal_gives_back_the_plan_it_recorded() {
        let root = scratch("reopen");
        let map = plan("192.0.2.1-192.0.2.4", "80,443,u:53");

        let directory = {
            let journal = Journal::create(
                &root,
                &Plan::port_scan(&map, &Exclusions::none(), TcpScanTechnique::Fin),
                Privilege::Raw,
                "test",
            )
            .expect("creates");
            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        let (journal, _checkpoint, recovered) =
            Journal::reopen(&directory, Privilege::Raw).expect("reopens");

        let recovered = recovered.targets().expect("a port scan's plan");
        assert_eq!(
            recovered.iter().collect::<Vec<_>>(),
            map.iter().collect::<Vec<_>>(),
            "the same targets, in the same order, so positions still mean what they did"
        );
        assert_eq!(journal.manifest().technique(), TcpScanTechnique::Fin);
    }

    /// Continuing a scan under different privileges is refused.
    #[test]
    fn a_journal_will_not_be_continued_under_different_privileges() {
        let root = scratch("reopen-privilege");
        let map = plan("192.0.2.1", "80");

        let journal =
            Journal::create(&root, &ports(&map), Privilege::Raw, "test").expect("creates");
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let refused =
            Journal::reopen(&directory, Privilege::Connect).expect_err("privileges differ");
        assert!(matches!(refused, OpenError::PlanChanged(_)), "{refused:?}");
    }

    /// The root is created. The chown needs a real elevated process and is a no-op
    /// without one; this pins that the call produces a directory `Journal::create` can claim
    /// inside.
    #[test]
    fn preparing_a_root_creates_the_whole_path_to_it() {
        let root = scratch("prepare-root")
            .join("state")
            .join("zond")
            .join("journals");
        assert!(!root.exists());

        prepare_root(&root).expect("the path is created");
        assert!(root.is_dir());

        // And again on an existing root, the repair path, which must not fail.
        prepare_root(&root).expect("an existing root is not an error");

        let plan = Plan::listen(vec![crate::model::ip::scoped::Zone::new(3, "en0")]);
        Journal::create(&root, &plan, Privilege::Connect, "listening")
            .expect("a journal is created inside it")
            .close()
            .expect("it closes");
    }

    /// Everything a first run under `sudo` creates on the way to its journals is given to
    /// the user who ran it, not only the last two directories, so `~/.local` and
    /// `~/.local/state` are not left to root.
    ///
    /// A directory on the way that already existed is given back only if root owns it. The
    /// home itself, and anything above it, is never given.
    #[test]
    fn preparing_a_root_gives_away_what_it_created_and_repairs_what_root_left() {
        use Hand::{Give, Reclaim};

        let home = scratch("prepare-root-home");
        let root = home.join(".local/state/zond/journals");
        let prepared = |root: &Path, own: bool, home: Option<&Path>| {
            let mut claimed = Vec::new();
            prepare_root_with(root, own, home, |path, hand| {
                claimed.push((path.to_path_buf(), hand));
            })
            .expect("the path is created");
            claimed
        };
        let under = |pairs: &[(&str, Hand)]| -> Vec<(PathBuf, Hand)> {
            pairs
                .iter()
                .map(|(below, hand)| (home.join(below), *hand))
                .collect()
        };

        assert_eq!(
            prepared(&root, true, Some(&home)),
            under(&[
                (".local", Give),
                (".local/state", Give),
                (".local/state/zond", Give),
                (".local/state/zond/journals", Give),
            ]),
            "a directory created for the journal was left to root"
        );

        // With `~/.local/state` already there, it and `~/.local` are looked at for repair,
        // and the two directories this crate owns are given regardless.
        fs::remove_dir_all(home.join(".local/state/zond")).expect("removes");
        assert_eq!(
            prepared(&root, true, Some(&home)),
            under(&[
                (".local", Reclaim),
                (".local/state", Reclaim),
                (".local/state/zond", Give),
                (".local/state/zond/journals", Give),
            ])
        );

        // A run on nobody else's behalf has no home to repair up to.
        assert_eq!(
            prepared(&root, true, None),
            under(&[
                (".local/state/zond", Give),
                (".local/state/zond/journals", Give)
            ])
        );

        // A location the caller named is where to write: only the root itself is claimed.
        let named = home.join("elsewhere/journals");
        assert_eq!(
            prepared(&named, false, Some(&home)),
            [(named.clone(), Give)]
        );

        let _ = fs::remove_dir_all(&home);
    }

    /// A watch is never finished, so its journal always offers a resume and a retention
    /// sweep never takes it as done, although its total is zero.
    #[test]
    fn a_watch_is_never_complete_however_long_it_ran() {
        use crate::model::ip::scoped::Zone;

        let root = scratch("watch-never-complete");
        let plan = Plan::listen(vec![Zone::new(3, "en0")]);
        let journal = Journal::create(&root, &plan, Privilege::Raw, "listening on en0")
            .expect("a journal is created");
        journal.close().expect("it closes");

        let entries = list(&root).expect("the root lists").entries;
        let entry = entries.first().expect("the watch is there");

        assert_eq!(entry.kind(), ScanKind::Listen);
        assert!(
            !entry.is_complete(),
            "another sitting can always be appended to a watch"
        );
    }
}
