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
//!     manifest.json   the plan, written once
//!     cursor.json     how far the scan got, rewritten on a timer
//!     LOCK            who is writing, if anyone
//! ```
//!
//! [`Journal::create`] begins one, [`Journal::resume`] continues one, and
//! [`list`] enumerates them for a caller offering a choice.
//!
//! A journal holds the addresses an engagement was pointed at, so everything is
//! `0600` under a `0700` directory — and when a scan runs elevated, owned by the
//! user who invoked it rather than by root. See [`paths`](super::paths).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::cursor::Checkpoint;
use super::format::JournalError;
use super::lock::{Lock, LockRefused, LockState};
use super::manifest::{Manifest, PlanChanged};
use super::settle::Settlements;
use crate::model::target::TargetMap;
use crate::model::technique::TcpScanTechnique;

const MANIFEST: &str = "manifest.json";
const CURSOR: &str = "cursor.json";
const LOCK: &str = "LOCK";

/// Why a journal could not be opened for writing.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The plan offered is not the plan this journal's positions are counted in.
    #[error("{0}")]
    PlanChanged(#[from] PlanChanged),

    /// Somebody else holds it, or might.
    #[error("{0}")]
    Locked(LockRefused),

    /// The journal could not be read or written.
    #[error("{0}")]
    Journal(#[from] JournalError),
}

impl From<serde_json::Error> for OpenError {
    fn from(error: serde_json::Error) -> Self {
        OpenError::Journal(error.into())
    }
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
    manifest: Manifest,
    lock: Lock,
    resume_point: Checkpoint,
}

impl Journal {
    /// Begins a journal for `plan` under `root`, minting an id for it.
    pub fn create(
        root: &Path,
        plan: &TargetMap,
        technique: TcpScanTechnique,
        privileged: bool,
        summary: impl Into<String>,
    ) -> Result<Self, OpenError> {
        let id = mint_id();
        let directory = root.join(&id);
        create_private_dir(&directory)?;

        let manifest = Manifest::new(id, plan, technique, privileged, summary);
        write_private(&directory.join(MANIFEST), &serde_json::to_vec(&manifest)?)?;

        let lock = Lock::acquire(&directory.join(LOCK))?;
        Ok(Self {
            directory,
            manifest,
            lock,
            resume_point: Checkpoint::default(),
        })
    }

    /// Continues the journal at `directory`, refusing a plan that has moved or a
    /// scan somebody else is running.
    ///
    /// Returns the checkpoint to subtract from the plan; feed it to
    /// [`Checkpoint::remaining`] and to [`Settlements::resuming`].
    pub fn resume(
        directory: &Path,
        plan: &TargetMap,
        technique: TcpScanTechnique,
        privileged: bool,
    ) -> Result<(Self, Checkpoint), OpenError> {
        let manifest = read_manifest(directory)?;
        // The plan first: a refusal here is about the caller's arguments, and
        // reporting it before taking a lock means a mistaken resume disturbs
        // nothing.
        manifest.covers(plan, technique, privileged)?;

        let lock = Lock::acquire(&directory.join(LOCK))?;
        let checkpoint = read_checkpoint(directory)?;

        Ok((
            Self {
                directory: directory.to_path_buf(),
                manifest,
                lock,
                resume_point: checkpoint.clone(),
            },
            checkpoint,
        ))
    }

    /// What an earlier sitting settled, and this one may skip.
    ///
    /// Empty for a journal that was just created. A scan reads this to seed both
    /// its dispatcher and its settlements, so the second sitting's cursor
    /// continues the first's rather than starting over.
    pub fn resume_point(&self) -> &Checkpoint {
        &self.resume_point
    }

    /// Writes how far the scan has got, and reports the writer is alive.
    ///
    /// Cheap enough to call on a timer: the cursor is a watermark and a short
    /// list however large the scan is, and the write is a rename over a small
    /// file. See [`Checkpoint::write_atomically`].
    pub fn checkpoint(&mut self, settlements: &Settlements) -> Result<(), JournalError> {
        settlements
            .checkpoint()
            .write_atomically(&self.directory.join(CURSOR))?;
        self.lock.beat()
    }

    /// What this journal is a journal of.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Where it lives.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Releases the lock, reporting a failure the drop would swallow.
    pub fn close(self) -> Result<(), JournalError> {
        self.lock.release()
    }
}

/// A journal as it appears to a caller choosing between them. Read without
/// taking the lock, so listing never disturbs a running scan.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Where it lives.
    pub directory: PathBuf,
    /// What it is a journal of.
    pub manifest: Manifest,
    /// How far it got. Absent if it never checkpointed.
    pub checkpoint: Option<Checkpoint>,
    /// Whether anything is writing it.
    pub lock: LockState,
}

impl Entry {
    /// Whether this journal has anything left to do.
    ///
    /// A journal whose cursor covers the whole plan is finished; one that never
    /// checkpointed has everything left.
    pub fn is_complete(&self) -> bool {
        self.settled() >= self.manifest.total_targets
    }

    /// How many targets are settled.
    pub fn settled(&self) -> u128 {
        match &self.checkpoint {
            Some(checkpoint) => {
                u128::from(checkpoint.watermark) + checkpoint.settled_above.len() as u128
            }
            None => 0,
        }
    }
}

/// Every journal under `root`, newest first.
///
/// A directory that cannot be read, or holds no readable manifest, is skipped
/// rather than failing the listing: one unreadable journal must not hide the
/// rest. `Ok(vec![])` for a root that does not exist yet.
pub fn list(root: &Path) -> Result<Vec<Entry>, JournalError> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    let mut found: Vec<Entry> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .filter_map(|directory| {
            let manifest = read_manifest(&directory).ok()?;
            Some(Entry {
                checkpoint: read_checkpoint(&directory).ok(),
                lock: super::lock::inspect(&directory.join(LOCK)),
                manifest,
                directory,
            })
        })
        .collect();

    found.sort_by_key(|entry| std::cmp::Reverse(entry.manifest.created_at));
    Ok(found)
}

/// Deletes the journal at `directory`.
///
/// Refuses one a live scan is writing. A caller pruning by age should read
/// [`Entry::lock`] and skip what is held rather than relying on this, so a
/// sweep reports what it left alone.
pub fn remove(directory: &Path) -> Result<(), OpenError> {
    let state = super::lock::inspect(&directory.join(LOCK));
    if !state.is_resumable() {
        return Err(OpenError::Locked(LockRefused::Held(state)));
    }

    fs::remove_dir_all(directory).map_err(JournalError::from)?;
    Ok(())
}

fn read_manifest(directory: &Path) -> Result<Manifest, JournalError> {
    let text = fs::read_to_string(directory.join(MANIFEST))?;
    let manifest: Manifest = serde_json::from_str(&text)?;

    if manifest.journal_version > super::JOURNAL_VERSION {
        return Err(JournalError::VersionTooNew {
            found: manifest.journal_version,
            understood: super::JOURNAL_VERSION,
        });
    }

    Ok(manifest)
}

fn read_checkpoint(directory: &Path) -> Result<Checkpoint, JournalError> {
    match Checkpoint::read(&directory.join(CURSOR)) {
        Ok(checkpoint) => Ok(checkpoint),
        // A journal that stopped before its first checkpoint has settled
        // nothing, which is a fresh cursor rather than a failure.
        Err(JournalError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(Checkpoint::default())
        }
        Err(e) => Err(e),
    }
}

/// A sortable, collision-free id: 48 bits of millisecond timestamp then 80 bits
/// of randomness, in Crockford base32. A ULID, which is 26 characters and sorts
/// by creation time as text.
///
/// Written out rather than pulled in: it is twenty lines against a dependency,
/// and the crate already declines a crate per format for the same reason.
fn mint_id() -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|since| since.as_millis())
        .unwrap_or_default() as u64
        & 0x0000_FFFF_FFFF_FFFF;

    const RANDOM_BITS: u32 = 80;
    let entropy = rand::random::<u128>() & ((1u128 << RANDOM_BITS) - 1);
    let mut value = (u128::from(millis) << RANDOM_BITS) | entropy;

    let mut out = [b'0'; 26];
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(value & 0x1F) as usize];
        value >>= 5;
    }

    // Every byte came from `ALPHABET`, which is ASCII.
    String::from_utf8(out.to_vec()).expect("base32 alphabet is ASCII")
}

fn create_private_dir(path: &Path) -> Result<(), JournalError> {
    fs::create_dir_all(path)?;
    restrict(path, 0o700)?;
    claim_for_invoking_user(path);
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), JournalError> {
    fs::write(path, bytes)?;
    restrict(path, 0o600)?;
    claim_for_invoking_user(path);
    Ok(())
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<(), JournalError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<(), JournalError> {
    Ok(())
}

/// Gives a journal written under `sudo` to the user who invoked it.
///
/// Best effort: a journal left owned by root is one they cannot prune, which is
/// worth trying to avoid and not worth failing a scan over.
#[cfg(unix)]
fn claim_for_invoking_user(path: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let Some(user) = super::paths::invoking_user() else {
        return;
    };
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };

    // SAFETY: `c_path` is a live NUL-terminated string for the call's duration,
    // and `chown` reads it and nothing else.
    unsafe {
        libc::chown(c_path.as_ptr(), user.uid, user.gid);
    }
}

#[cfg(not(unix))]
fn claim_for_invoking_user(_path: &Path) {}

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
    done: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Checkpointing {
    /// Writes the last checkpoint and releases the lock.
    ///
    /// Call once the scan has finished and every strategy has reported, so the
    /// final cursor covers the whole sitting.
    pub async fn finish(self) {
        // The receiver ends the loop; a send failure means it already has.
        let _ = self.done.send(());
        let _ = self.task.await;
    }
}

/// Starts checkpointing `journal` from `ctx`'s progress until told to stop.
pub fn spawn_checkpoints(
    mut journal: Journal,
    ctx: crate::scanner::session::ScanContext,
) -> Checkpointing {
    let (done, mut stop) = tokio::sync::oneshot::channel();

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(CHECKPOINT_EVERY) => {
                    // A checkpoint that cannot be written is not worth ending a
                    // scan over: the previous one still stands, and the scan is
                    // still producing results. Reported through the same channel
                    // every other narrowing uses.
                    if let Err(e) = journal.checkpoint(ctx.settlements()) {
                        ctx.record_failure(
                            crate::scanner::session::ScannerKind::Composite,
                            format!("journal checkpoint failed, so a resume would replay further back than it should: {e}"),
                        );
                    }
                }
                _ = &mut stop => break,
            }
        }

        let _ = journal.checkpoint(ctx.settlements());
        let _ = journal.close();
    });

    Checkpointing { done, task }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚═╝     ╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::settle::Outcome;
    use crate::model::ip::set::IpSet;
    use crate::model::port::PortSet;
    use crate::model::target::TargetSet;

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

    fn begin(root: &Path, map: &TargetMap) -> Journal {
        Journal::create(root, map, TcpScanTechnique::Syn, true, "test").expect("creates")
    }

    /// The whole cycle: begin a scan, settle part of it, come back and continue
    /// from exactly where it stopped.
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
            Journal::resume(&directory, &map, TcpScanTechnique::Syn, true).expect("resumes");

        assert_eq!(checkpoint.watermark, 3);
        let remaining: Vec<_> = checkpoint.remaining(map.iter()).collect();
        assert_eq!(remaining.len(), 4, "eight targets, four settled");
    }

    /// A plan edited between sittings renumbers every position past the edit, so
    /// the resume is refused rather than scanning the wrong targets.
    #[test]
    fn a_changed_plan_is_refused() {
        let root = scratch("changed-plan");
        let map = plan("192.0.2.1-192.0.2.4", "80,443");

        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let widened = plan("192.0.2.1-192.0.2.9", "80,443");
        let refused = Journal::resume(&directory, &widened, TcpScanTechnique::Syn, true)
            .expect_err("the plan moved");

        assert!(matches!(refused, OpenError::PlanChanged(_)), "{refused:?}");
    }

    /// A journal being written must not be resumed underneath its writer.
    #[test]
    fn a_live_journal_is_not_resumable() {
        let root = scratch("live");
        let map = plan("192.0.2.1", "80");

        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();

        let refused =
            Journal::resume(&directory, &map, TcpScanTechnique::Syn, true).expect_err("it is held");
        assert!(matches!(refused, OpenError::Locked(_)), "{refused:?}");

        // And released, it opens.
        journal.close().expect("closes");
        Journal::resume(&directory, &map, TcpScanTechnique::Syn, true).expect("now free");
    }

    /// Listing reports progress and liveness without taking the lock, so it
    /// never disturbs a running scan.
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

        let listed = list(&root).expect("lists");
        assert_eq!(listed.len(), 1);

        let entry = &listed[0];
        assert_eq!(entry.manifest.total_targets, 8);
        assert_eq!(entry.settled(), 4);
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

        let listed = list(&root).expect("lists");
        assert!(listed[0].is_complete());
        assert_eq!(listed[0].settled(), 8);
    }

    /// A journal that stopped before its first checkpoint has settled nothing,
    /// which is a fresh cursor rather than an unreadable journal.
    #[test]
    fn a_journal_with_no_checkpoint_resumes_from_the_beginning() {
        let root = scratch("no-checkpoint");
        let map = plan("192.0.2.1-192.0.2.4", "80,443");

        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let (_journal, checkpoint) =
            Journal::resume(&directory, &map, TcpScanTechnique::Syn, true).expect("resumes");

        assert_eq!(checkpoint, Checkpoint::default());
        assert_eq!(checkpoint.remaining(map.iter()).count(), 8);
    }

    /// Ids sort by creation time as text, which is what makes a listing orderable
    /// without reading every manifest.
    #[test]
    fn ids_are_sortable_and_distinct() {
        let mut ids: Vec<String> = (0..64).map(|_| mint_id()).collect();

        assert!(ids.iter().all(|id| id.len() == 26));
        let distinct: std::collections::BTreeSet<&String> = ids.iter().collect();
        assert_eq!(distinct.len(), ids.len(), "ids collided");

        let sorted = {
            ids.sort();
            ids.clone()
        };
        assert_eq!(ids, sorted);
    }

    /// A listing skips what it cannot read rather than failing, so one damaged
    /// journal never hides the rest.
    #[test]
    fn an_unreadable_journal_does_not_hide_the_others() {
        let root = scratch("damaged");
        let map = plan("192.0.2.1", "80");
        begin(&root, &map).close().expect("closes");

        let damaged = root.join("01JUNREADABLEJUNREADABLE00");
        fs::create_dir_all(&damaged).expect("directory");
        fs::write(damaged.join(MANIFEST), "{not json").expect("writes");

        let listed = list(&root).expect("lists");
        assert_eq!(listed.len(), 1, "the readable one is still there");
    }

    /// Pruning removes a journal nobody is writing, and refuses one somebody is.
    #[test]
    fn pruning_refuses_a_journal_that_is_being_written() {
        let root = scratch("prune");
        let map = plan("192.0.2.1", "80");

        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();

        assert!(matches!(remove(&directory), Err(OpenError::Locked(_))));

        journal.close().expect("closes");
        remove(&directory).expect("removes a free journal");
        assert!(list(&root).expect("lists").is_empty());
    }

    /// The ticker writes a final checkpoint and releases the lock, so a scan
    /// that finishes between two ticks still records what it did.
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

        // Finishes immediately, well inside one tick.
        spawn_checkpoints(journal, ctx).finish().await;

        let checkpoint = Checkpoint::read(&directory.join(CURSOR)).expect("a cursor was written");
        assert_eq!(checkpoint.watermark, 5);
        assert_eq!(
            super::super::lock::inspect(&directory.join(LOCK)),
            LockState::Free,
            "the lock outlived the scan and was then released"
        );
    }

    /// A resumed sitting that settles nothing must still write a cursor covering
    /// the first sitting's work.
    ///
    /// The failure this guards is silent: forget to seed the live cursor from
    /// the resume point and the second sitting's checkpoint erases the first's
    /// progress, so a third would re-scan everything while reporting success.
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
            Journal::resume(&directory, &map, TcpScanTechnique::Syn, true).expect("resumes");

        // Seeded from the resume point, exactly as a scan does.
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
}
