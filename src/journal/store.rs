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
//!     hosts.jsonl     what it found, appended as it finds it
//!     phases.jsonl    what each sitting did, appended as each one ends
//!     LOCK            who is writing, if anyone
//! ```
//!
//! The cursor is rewritten because it describes one state; the findings are
//! appended because they accumulate. A host that changes appears more than once,
//! and the later record supersedes the earlier — which is what makes a torn tail
//! survivable, since the worst it costs is one host's most recent update.
//!
//! [`Journal::create`] begins one, [`Journal::resume`] continues one, and
//! [`list`] enumerates them for a caller offering a choice.
//!
//! A journal holds the addresses an engagement was pointed at, so everything is
//! `0600` under a `0700` directory — and when a scan runs elevated, owned by the
//! user who invoked it rather than by root. See [`paths`](super::paths).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::cursor::Checkpoint;
use super::file::{claim_for_invoking_user, create_private as create_private_file};
use super::format::JournalError;
use super::lock::{Lock, LockRefused, LockState};
use super::manifest::{Manifest, Plan, PlanChanged};
use super::settle::Settlements;
use crate::model::host::Host;
use crate::record::{HostRecord, PhaseRecord};
use crate::scanner::report::{ScanKind, ScanPhase, ScanReport};

const MANIFEST: &str = "manifest.json";
const CURSOR: &str = "cursor.json";
const HOSTS: &str = "hosts.jsonl";
const PHASES: &str = "phases.jsonl";
const LOCK: &str = "LOCK";

/// Why a journal could not be opened for writing.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The plan offered is not the plan this journal's positions are counted in.
    #[error("{0}")]
    PlanChanged(#[from] PlanChanged),

    /// The journal records the other phase of a scan.
    ///
    /// A sweep's positions count addresses and a port scan's count
    /// address-and-port pairs, so one continued as the other would skip targets
    /// nothing ever probed.
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
    restored: Vec<Host>,
    earlier: Vec<ScanPhase>,
    /// How many host records have been appended since the file was last written
    /// whole. See [`should_compact`](Journal::should_compact).
    appended: usize,
}

impl Journal {
    /// Begins a journal for `plan` under `root`, minting an id for it.
    ///
    /// The plan carries which phase it belongs to, so a sweep and a port scan
    /// both come through here and neither can be read back as the other.
    pub fn create(
        root: &Path,
        plan: &Plan,
        privileged: bool,
        summary: impl Into<String>,
    ) -> Result<Self, OpenError> {
        let (id, directory) = claim_directory(root)?;
        let manifest = Manifest::new(id, plan, privileged, summary);
        write_private(&directory.join(MANIFEST), &serde_json::to_vec(&manifest)?)?;

        let lock = match Lock::acquire(&directory.join(LOCK)) {
            Ok(lock) => lock,
            Err(refused) => {
                // Nothing has been written but the manifest, and a directory
                // holding one of those and no lock reads as a journal that
                // found nothing. Cleaner to leave no trace of a scan that never
                // started.
                let _ = fs::remove_dir_all(&directory);
                return Err(refused.into());
            }
        };

        let mut journal = Self {
            directory,
            manifest,
            lock,
            resume_point: Checkpoint::default(),
            restored: Vec::new(),
            earlier: Vec::new(),
            appended: 0,
        };
        journal.open_findings()?;
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
        privileged: bool,
    ) -> Result<(Self, Checkpoint), OpenError> {
        let manifest = read_manifest(directory)?;
        // The phase before the fingerprint, so continuing a sweep as a port scan
        // is named for what it is rather than reported as a plan that moved.
        if manifest.kind() != plan.kind() {
            return Err(OpenError::WrongPhase {
                held: phase_name(manifest.kind()),
                asked: phase_name(plan.kind()),
            });
        }
        // The plan next: a refusal here is about the caller's arguments, and
        // reporting it before taking a lock means a mistaken resume disturbs
        // nothing.
        manifest.covers(plan, privileged)?;

        let lock = Lock::acquire(&directory.join(LOCK))?;
        let checkpoint = read_checkpoint(directory)?;

        Ok((
            Self {
                directory: directory.to_path_buf(),
                manifest,
                lock,
                resume_point: checkpoint.clone(),
                restored: read_findings(directory)?,
                earlier: read_phases(directory)?,
                appended: 0,
            },
            checkpoint,
        ))
    }

    /// Continues the journal at `directory`, scanning the plan it recorded.
    ///
    /// The counterpart of [`resume`](Self::resume) for a caller who has nothing
    /// to describe the scan with but its id. The plan comes back as it was
    /// written down — including which phase it belongs to — so a hostname that
    /// has moved since does not quietly change what is being continued, and a
    /// caller that can only continue one of the two phases can see which it has
    /// before it starts.
    ///
    /// Refused if this process holds different privileges than the scan did: the
    /// connect fallback asks a different question than a raw technique does, and
    /// a journal half of each would be counting two things.
    pub fn reopen(
        directory: &Path,
        privileged: bool,
    ) -> Result<(Self, Checkpoint, Plan), OpenError> {
        let plan = read_manifest(directory)?.recorded();
        let (journal, checkpoint) = Self::resume(directory, &plan, privileged)?;
        Ok((journal, checkpoint, plan))
    }

    /// What earlier sittings of this scan found.
    ///
    /// Empty for a journal just created. A scan seeds its store with these, so
    /// the report it produces describes the whole job rather than the last
    /// sitting of it.
    pub fn restored(&self) -> &[Host] {
        &self.restored
    }

    /// Appends what `hosts` currently hold.
    ///
    /// Called with whatever
    /// [`take_changed_hosts`](crate::scanner::session::ScanContext::take_changed_hosts)
    /// yields, so a host is written once per change rather than once per
    /// checkpoint for the rest of the run.
    pub fn record_hosts(&mut self, hosts: &[Host]) -> Result<(), JournalError> {
        if hosts.is_empty() {
            return Ok(());
        }

        let file = fs::OpenOptions::new()
            .append(true)
            .open(self.directory.join(HOSTS))?;

        let mut writer = crate::journal::format::Writer::append(std::io::BufWriter::new(file));
        for host in hosts {
            writer.write(&HostRecord::from(host))?;
        }
        writer.flush()?;

        self.appended += hosts.len();
        Ok(())
    }

    /// Whether the findings file holds enough superseded records to be worth
    /// writing whole again.
    ///
    /// A host is appended each interval in which anything about it changed, and
    /// the dispatcher shuffles targets across the whole plan — so on a long scan
    /// most hosts change in most intervals, and the file grows with the scan's
    /// *duration* rather than with what it found. Compaction bounds it to a
    /// small multiple of the live state.
    ///
    /// `live` is how many hosts the scan has found. The threshold is generous
    /// because rewriting is O(hosts) and appending is not: compaction should be
    /// rare enough that its cost disappears against the scan.
    pub fn should_compact(&self, live: usize) -> bool {
        const FLOOR: usize = 256;
        const MULTIPLE: usize = 8;

        self.appended > FLOOR.max(live.saturating_mul(MULTIPLE))
    }

    /// Writes the findings file whole, replacing everything superseded.
    ///
    /// `all` must be every host the scan has found, not just the recent ones:
    /// this replaces the file rather than adding to it. Written to a sibling and
    /// renamed over, so a compaction interrupted part way leaves the previous
    /// file untouched.
    pub fn compact(&mut self, all: &[Host]) -> Result<(), JournalError> {
        let destination = self.directory.join(HOSTS);
        let temporary = destination.with_extension("jsonl-tmp");

        {
            let file = create_private_file(&temporary)?;
            let mut writer = crate::journal::format::Writer::create(std::io::BufWriter::new(file))?;
            for host in all {
                writer.write(&HostRecord::from(host))?;
            }
            writer.flush()?;
        }

        fs::rename(&temporary, &destination)?;
        claim_for_invoking_user(&destination);
        self.appended = all.len();
        Ok(())
    }

    /// What earlier sittings of this scan did.
    ///
    /// A resumed report carries these alongside its own, so it describes a job
    /// that ran in several sittings rather than presenting the last one as the
    /// whole of it.
    pub fn earlier_phases(&self) -> &[ScanPhase] {
        &self.earlier
    }

    /// Appends what one sitting did, once it has finished doing it.
    pub fn record_phases(&mut self, phases: &[ScanPhase]) -> Result<(), JournalError> {
        if phases.is_empty() {
            return Ok(());
        }

        let file = fs::OpenOptions::new()
            .append(true)
            .open(self.directory.join(PHASES))?;

        let mut writer = crate::journal::format::Writer::append(std::io::BufWriter::new(file));
        for phase in phases {
            writer.write(&PhaseRecord::from(phase))?;
        }
        writer.flush()
    }

    /// Writes the appended files' headers, so each is self-describing before
    /// anything is added to it.
    fn open_findings(&mut self) -> Result<(), JournalError> {
        for name in [HOSTS, PHASES] {
            let path = self.directory.join(name);
            let file = create_private_file(&path)?;
            crate::journal::format::Writer::create(std::io::BufWriter::new(file))?.flush()?;
            claim_for_invoking_user(&path);
        }
        Ok(())
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

    /// Writes down what the scan has found and how far it has got.
    ///
    /// Findings first: a cursor claiming a target is settled, beside a file
    /// missing what settling it produced, is the one ordering that loses a
    /// finding. The other way round costs a target being probed twice.
    pub fn record(
        &mut self,
        hosts: &[Host],
        settlements: &Settlements,
    ) -> Result<(), JournalError> {
        self.record_hosts(hosts)?;
        self.checkpoint(settlements)
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
    /// How far it got, or `None` where that could not be read.
    ///
    /// A journal that never checkpointed carries a fresh cursor rather than
    /// nothing: it settled no targets, which is a fact about the scan. `None`
    /// is the different case — the file is there and this process cannot read
    /// it, usually because the scan ran under `sudo` and left it behind. That
    /// must not read as no progress, or a listing reports every such scan as
    /// untouched and offers to continue work that is already done.
    pub checkpoint: Option<Checkpoint>,
    /// Whether anything is writing it.
    pub lock: LockState,
}

impl Entry {
    /// Whether this journal has anything left to do.
    ///
    /// A journal whose cursor covers the whole plan is finished; one that never
    /// checkpointed has everything left. One whose cursor cannot be read is not
    /// finished as far as anything here can tell, which is the answer that keeps
    /// a retention sweep from deleting it.
    pub fn is_complete(&self) -> bool {
        self.settled()
            .is_some_and(|settled| settled >= self.manifest.total_targets)
    }

    /// Which phase this journal records.
    ///
    /// A sweep and a port scan are counted in different units, so a caller
    /// reporting progress or offering to continue one has to know which it is
    /// looking at.
    pub fn kind(&self) -> ScanKind {
        self.manifest.kind()
    }

    /// How many targets are settled, or `None` where the cursor could not be
    /// read.
    pub fn settled(&self) -> Option<u128> {
        self.checkpoint.as_ref().map(|checkpoint| {
            u128::from(checkpoint.watermark) + checkpoint.settled_above.len() as u128
        })
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
                // `Err` here is a cursor that exists and could not be read,
                // which `Entry::checkpoint` records as `None` rather than as a
                // scan that settled nothing. A journal that never checkpointed
                // comes back as a fresh cursor from `read_checkpoint` itself.
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

/// The scan at `directory`, as the report it would have produced.
///
/// A journal holds everything a report is made of — what each sitting covered
/// and under which settings, and every host it found — so a scan that is over
/// can be read back and rendered exactly as it was when it ended. That is what
/// this returns: the hosts, the phases in the order they ran, and the engine
/// version taken from the manifest rather than from this build, so a scan run
/// by an older engine still says so.
///
/// Read without the lock, like [`list`], so it is safe to call on a scan that is
/// still running. What comes back is then a report of everything written down so
/// far, which is a checkpoint behind the live one.
///
/// A journal missing its findings or its phases reads as a scan that recorded
/// none, rather than as a failure: a sitting can end before its first
/// checkpoint, and a report of nothing is the truthful account of that.
pub fn report(directory: &Path) -> Result<ScanReport, JournalError> {
    let manifest = read_manifest(directory)?;

    Ok(ScanReport::recorded(
        manifest.engine_version,
        read_phases(directory)?,
        read_findings(directory)?,
    ))
}

/// How a phase is named in a refusal. Prose rather than the wire name, since
/// this reaches a person.
fn phase_name(kind: ScanKind) -> &'static str {
    match kind {
        ScanKind::Discovery => "host-discovery sweep",
        ScanKind::PortScan => "port scan",
    }
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

/// Reads back what a journal's earlier sittings found.
///
/// Records are folded together with [`Host::merge`], so a host written once when
/// it answered and again when its ports were classified comes back whole.
///
/// **Two records are the same host when they share any address**, not when their
/// primary addresses match. Local discovery promotes a host's primary address
/// when a better one turns up — a link-local giving way to a global — so the
/// same machine is written under one address and then another. Keyed on the
/// primary alone it would come back as two hosts that were never two.
///
/// A missing file is no findings rather than a failure: a journal can be read
/// before its first host is written.
fn read_findings(directory: &Path) -> Result<Vec<Host>, JournalError> {
    let file = match fs::File::open(directory.join(HOSTS)) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    let mut reader = match crate::journal::format::Reader::open(std::io::BufReader::new(file)) {
        Ok(reader) => reader,
        // A findings file with no header was never opened for writing, which
        // is a journal that stopped before it found anything.
        Err(JournalError::NotAJournal) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    // Slots rather than a map: a record can join two hosts that were separate
    // until it arrived, and the one it merges into keeps its slot while the
    // other empties.
    let mut hosts: Vec<Option<Host>> = Vec::new();
    let mut slot_of: std::collections::BTreeMap<std::net::IpAddr, usize> =
        std::collections::BTreeMap::new();

    while let Some(record) = reader.read::<HostRecord>()? {
        let host = Host::from(&record);

        let mut matched: Vec<usize> = host
            .ips()
            .iter()
            .filter_map(|ip| slot_of.get(ip).copied())
            .collect();
        matched.sort_unstable();
        matched.dedup();

        let slot = match matched.split_first() {
            Some((&keep, absorb)) => {
                // Every host this record has an address in common with is the
                // same machine, so they fold into one another as well.
                for &other in absorb {
                    if let Some(other) = hosts[other].take() {
                        merge_into(&mut hosts, keep, other);
                    }
                }
                merge_into(&mut hosts, keep, host);
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
        for ip in settled.ips() {
            slot_of.insert(*ip, slot);
        }
    }

    Ok(hosts.into_iter().flatten().collect())
}

/// Folds `host` into the one at `slot`, or puts it there if the slot is empty.
fn merge_into(hosts: &mut [Option<Host>], slot: usize, host: Host) {
    match hosts[slot].as_mut() {
        Some(existing) => existing.merge(host),
        None => hosts[slot] = Some(host),
    }
}

/// Reads back what a journal's earlier sittings did, oldest first.
fn read_phases(directory: &Path) -> Result<Vec<ScanPhase>, JournalError> {
    let file = match fs::File::open(directory.join(PHASES)) {
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
    Ok(phases)
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

/// The characters an id is written in: Crockford base32, which has no letters a
/// reader can mistake for digits.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// How many characters an id is.
///
/// Sixteen: the millisecond the scan started, then randomness. Shorter than a
/// ULID's twenty-six because an id is printed in a listing and typed at a
/// prompt, and a line of them should fit a terminal beside what it describes.
///
/// **All ten characters of width come off the random half**, none off the clock.
/// Timing to the millisecond is what makes ids sort into the order the scans ran
/// in, and two scans a fifth of a second apart are exactly the pair a reader
/// most needs told apart. What is left is thirty-two bits — four billion — for
/// scans that started in the same millisecond, and a collision is answered by
/// minting another id rather than by overwriting anything, so the cost of one is
/// a retry rather than a lost journal. See [`claim_directory`].
const ID_CHARS: usize = 16;

/// Milliseconds, as a ULID counts them, reaching the year 10 889.
const ID_TIME_BITS: u32 = 48;

/// A sortable id: the millisecond the scan started, then randomness, in
/// Crockford base32.
///
/// Sorts by creation time as text, which is what lets a listing be ordered
/// without reading every manifest. Written out rather than pulled in: it is
/// twenty lines against a dependency, and the crate already declines a crate per
/// format for the same reason.
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
/// `create_dir` rather than `create_dir_all`, deliberately: the second succeeds
/// on a directory that is already there, so two scans that minted the same id
/// would share one — the later overwriting the earlier's manifest and, once the
/// earlier had finished and released its lock, its findings too.
///
/// A collision is answered by minting another id rather than by failing. Ids
/// carry enough randomness that this should never run twice, and a scan is not
/// worth abandoning over a coincidence.
fn claim_directory(root: &Path) -> Result<(String, PathBuf), JournalError> {
    /// Enough that exhausting them means something other than chance is wrong —
    /// a root that is not a directory, or one nothing may write to.
    const ATTEMPTS: usize = 8;

    for _ in 0..ATTEMPTS {
        let id = mint_id();
        let directory = root.join(&id);

        match fs::create_dir(&directory) {
            Ok(()) => {
                restrict(&directory, 0o700)?;
                claim_for_invoking_user(&directory);
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

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), JournalError> {
    use std::io::Write;

    let mut file = create_private_file(path)?;
    file.write_all(bytes)?;
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

/// How long journals are kept.
///
/// A journal holds the addresses an engagement was pointed at, so it should not
/// accumulate in a state directory nobody looks at. It is also evidence, so it
/// should not vanish at a moment nobody chose. The defaults below take the
/// second more seriously than the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retention {
    /// How long a finished journal is kept, or `None` to keep it indefinitely.
    pub completed_for: Option<Duration>,
    /// How long an unfinished one is kept, or `None` to keep it indefinitely.
    pub incomplete_for: Option<Duration>,
    /// The most journals to keep, or `None` for no cap.
    ///
    /// Applied after the ages above, and it removes finished journals before
    /// unfinished ones: a cap exists to bound a directory, and an unfinished
    /// journal is the one thing there somebody may still want.
    pub keep_at_most: Option<usize>,
}

impl Default for Retention {
    /// A month for finished journals, indefinitely for unfinished ones, and a
    /// cap of two hundred.
    ///
    /// The asymmetry is the point. A finished scan has a report; its journal is
    /// a duplicate that ages out. An unfinished one is the only copy of work
    /// somebody may still mean to continue, so nothing but the cap removes it.
    fn default() -> Self {
        Self {
            completed_for: Some(Duration::from_secs(30 * 24 * 60 * 60)),
            incomplete_for: None,
            keep_at_most: Some(200),
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
        }
    }

    /// Which of `entries` this policy would remove, newest-first as [`list`]
    /// yields them.
    ///
    /// Pure, and separate from [`prune`] for the reason
    /// [`lock::classify`](crate::journal::lock::classify) is: the interesting
    /// cases are a directory full of journals of different ages and states, and
    /// arranging those on a real filesystem to test the policy would test the
    /// filesystem.
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

        // What the ages left behind, oldest last, since `list` is newest first.
        let mut surviving: Vec<usize> = (0..entries.len())
            .filter(|index| !removing.contains(index))
            .collect();

        // Ordered by how much a journal is worth keeping, most first: unfinished
        // before finished, and newer before older. The cap is then applied by
        // dropping from the end, so what goes is the oldest duplicate of work
        // that already has a report.
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pruned {
    /// The journals removed, by id.
    pub removed: Vec<String>,
    /// The journals a policy selected but that could not be removed, each with
    /// why.
    ///
    /// Reported rather than swallowed: a sweep that quietly leaves things behind
    /// is one nobody can tell has stopped working.
    pub held: Vec<Held>,
}

/// A journal a prune could not remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// Which journal.
    pub id: String,
    /// Why it is still there.
    pub reason: String,
}

/// Removes the journals under `root` that `retention` no longer keeps.
///
/// Journals a scan is writing are never removed, and are not reported as held
/// either: they were never selected. What reaches [`Pruned::held`] is a journal
/// the policy chose and the filesystem refused.
pub fn prune(root: &Path, retention: &Retention) -> Result<Pruned, JournalError> {
    let entries = list(root)?;
    let mut pruned = Pruned::default();

    for index in retention.expired(&entries, SystemTime::now()) {
        let entry = &entries[index];
        match remove(&entry.directory) {
            Ok(()) => pruned.removed.push(entry.manifest.id.clone()),
            Err(error) => pruned.held.push(Held {
                id: entry.manifest.id.clone(),
                reason: error.to_string(),
            }),
        }
    }

    Ok(pruned)
}

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
pub fn spawn_checkpoints(
    mut journal: Journal,
    ctx: crate::scanner::session::ScanProgress,
) -> Checkpointing {
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
                            crate::scanner::session::ScannerKind::Composite,
                            format!("journal checkpoint failed, so a resume would replay further back than it should: {e}"),
                        );
                    }
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
    use crate::model::exclusion::Exclusions;
    use crate::model::ip::set::IpSet;
    use crate::model::port::PortSet;
    use crate::model::target::{TargetMap, TargetSet};
    use crate::model::technique::TcpScanTechnique;

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
        Journal::create(root, &ports(map), true, "test").expect("creates")
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
            Journal::resume(&directory, &ports(&map), true).expect("resumes");

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
        let refused =
            Journal::resume(&directory, &ports(&widened), true).expect_err("the plan moved");

        assert!(matches!(refused, OpenError::PlanChanged(_)), "{refused:?}");
    }

    /// A journal being written must not be resumed underneath its writer.
    #[test]
    fn a_live_journal_is_not_resumable() {
        let root = scratch("live");
        let map = plan("192.0.2.1", "80");

        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();

        let refused = Journal::resume(&directory, &ports(&map), true).expect_err("it is held");
        assert!(matches!(refused, OpenError::Locked(_)), "{refused:?}");

        // And released, it opens.
        journal.close().expect("closes");
        Journal::resume(&directory, &ports(&map), true).expect("now free");
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

        let listed = list(&root).expect("lists");
        assert!(listed[0].is_complete());
        assert_eq!(listed[0].settled(), Some(8));
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
            Journal::resume(&directory, &ports(&map), true).expect("resumes");

        assert_eq!(checkpoint, Checkpoint::default());
        assert_eq!(checkpoint.remaining(map.iter()).count(), 8);
    }

    /// Ids sort by creation time as text, which is what makes a listing orderable
    /// without reading every manifest.
    ///
    /// Timing to the millisecond is what buys that: minted a fifth of a second
    /// apart — which is to say, one after another — they still sort into the
    /// order they were made, and that is exactly the pair a reader most needs
    /// told apart.
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

        // And across milliseconds, where the clock rather than chance decides.
        let first = mint_id();
        std::thread::sleep(std::time::Duration::from_millis(3));
        let second = mint_id();
        assert!(first < second, "{first} should sort before {second}");
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
        spawn_checkpoints(journal, ctx.progress()).finish(&[]).await;

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
            Journal::resume(&directory, &ports(&map), true).expect("resumes");

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

    /// Findings survive the journal, which is the point of writing them down.
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

        let (journal, _) = Journal::resume(&directory, &ports(&map), true).expect("resumes");

        let restored = journal.restored();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].hostname(), Some("router.example"));
        assert_eq!(restored[0].port_count(), 1);
        assert!(restored[0].is_alive());
    }

    /// A host written more than once comes back whole rather than as its last
    /// record alone: the scan that found it and the scan that classified its
    /// ports both wrote, and both readings matter.
    #[test]
    fn repeated_records_for_one_host_are_folded_together() {
        use crate::model::host::HostStatus;
        use crate::model::port::{Port, PortState, Protocol};

        let root = scratch("folded");
        let map = plan("192.0.2.1", "80");
        let ip = "192.0.2.1".parse().expect("an address");

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

        let (journal, _) = Journal::resume(&directory, &ports(&map), true).expect("resumes");

        let restored = journal.restored();
        assert_eq!(restored.len(), 1, "one address is one host");
        assert!(restored[0].is_alive(), "the first record's status survived");
        assert_eq!(restored[0].port_count(), 1, "the second record's port too");
    }

    /// A journal that stopped before it found anything reads as no findings, not
    /// as a failure.
    #[test]
    fn a_journal_with_no_findings_restores_nothing() {
        let root = scratch("no-findings");
        let map = plan("192.0.2.1", "80");

        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let (journal, _) = Journal::resume(&directory, &ports(&map), true).expect("resumes");
        assert!(journal.restored().is_empty());
    }

    /// The whole of `zond journal report`: a finished scan comes back out of
    /// its journal as the report it produced. Everything the end of a run
    /// prints is drawn from the hosts and the phases, so if either fails to
    /// survive the round trip the record is a summary rather than the scan.
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

        // A phase carries what the run covered and how it went, which is what
        // the closing lines of a run are drawn from.
        let (before, after) = (&original.phases()[0], &replayed.phases()[0]);
        assert_eq!(after.kind(), before.kind());
        assert_eq!(after.privileged(), before.privileged());
        assert_eq!(after.failures().len(), before.failures().len());
        assert_eq!(
            replayed.is_partial(),
            original.is_partial(),
            "a scan that left ground uncovered has to still say so"
        );
    }

    /// A report read back names the engine that ran the scan, not the one
    /// reading it. The two differ the moment somebody upgrades, and a record
    /// that quietly restamps itself is a record of the wrong thing.
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

        // The manifest as a build before this one would have left it.
        let path = directory.join(MANIFEST);
        let mut manifest: Manifest =
            serde_json::from_str(&fs::read_to_string(&path).expect("reads")).expect("parses");
        manifest.engine_version = "0.1.0".to_string();
        fs::write(&path, serde_json::to_vec(&manifest).expect("encodes")).expect("writes");

        let replayed = report(&directory).expect("reads");

        assert_eq!(replayed.engine_version(), "0.1.0");
        assert_ne!(
            replayed.engine_version(),
            crate::scanner::report::ENGINE_VERSION,
            "this build's version must not have been stamped over the record's"
        );
    }

    /// A cursor that exists and cannot be read is not a scan that settled
    /// nothing.
    ///
    /// This is what a `sudo` scan used to leave behind: a journal in the
    /// invoking user's home whose cursor stayed root's. Reported as zero, every
    /// finished scan listed as untouched and offered itself to be continued.
    /// Reported as unknown, a reader is told to go and look.
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

        // Readable first, so the difference below is about the permission and
        // not about the file's contents.
        let listed = list(&root).expect("lists");
        assert_eq!(listed[0].settled(), Some(1));

        fs::set_permissions(directory.join(CURSOR), fs::Permissions::from_mode(0o000))
            .expect("removes every permission");

        let listed = list(&root).expect("a journal it cannot read must not hide the rest");
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

        // Left readable, so a failure here does not leave a file the next run
        // of this test cannot clean up.
        let _ = fs::set_permissions(directory.join(CURSOR), fs::Permissions::from_mode(0o600));
    }

    /// **What a scan learns after its last checkpoint has to reach the file.**
    ///
    /// The enrichment passes — OS identification, the echo probe, traceroute —
    /// run at the very end of a scan, often after the last timer checkpoint has
    /// already drained what changed. If the closing write misses them, a
    /// replayed report is quieter than the run that made it: a protocol missing
    /// from the evidence, a round trip with no spread. Nothing errors, so only a
    /// test comparing the two would notice.
    #[tokio::test]
    async fn what_a_scan_learns_after_a_checkpoint_still_reaches_the_file() {
        use crate::model::host::{HostStatus, StatusProtocol, StatusReason};

        let root = scratch("late-findings");
        let map = plan("192.0.2.1", "80");
        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();

        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let ticker = spawn_checkpoints(journal, ctx.progress());

        // What the liveness pass found.
        let ip = "192.0.2.1".parse().expect("an address");
        ctx.update_host(ip, |host| {
            host.set_status(HostStatus::Up);
            host.record_evidence(
                HostStatus::Up,
                StatusReason::new(StatusProtocol::Arp, "answered"),
            );
        });

        // A checkpoint lands, taking that and leaving nothing behind. Real
        // time rather than a paused clock, which would need `tokio/test-util`
        // for one test — and the interval is three seconds, not three minutes.
        tokio::time::sleep(CHECKPOINT_EVERY + Duration::from_millis(200)).await;

        // And then the enrichment finds something else, as it does.
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
            manifest: Manifest {
                journal_version: crate::journal::JOURNAL_VERSION,
                id: id.to_string(),
                engine_version: "0.0.0".to_string(),
                created_at,
                kind: crate::record::wire::scan_kind_name(ScanKind::PortScan).to_owned(),
                plan: crate::journal::manifest::PlanFingerprint::of(
                    &ports(&plan("192.0.2.1", "80")),
                    true,
                ),
                targets: crate::record::PlanRecord::from(&plan("192.0.2.1", "80")),
                technique: TcpScanTechnique::Syn.name().to_owned(),
                sweep: false,
                privileged: true,
                total_targets: total,
                summary: String::new(),
            },
            checkpoint: Some(Checkpoint {
                watermark: settled,
                settled_above: Vec::new(),
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

    /// Finished journals age out; unfinished ones do not, because they are the
    /// only copy of work somebody may still mean to continue.
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
        };

        assert!(retention.expired(&entries, now()).is_empty());
    }

    /// The cap takes finished journals before unfinished ones, and the oldest
    /// first within each — a directory is bounded without losing the work
    /// somebody has not finished.
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

    /// The default keeps an unfinished scan whatever its age, and lets a
    /// finished one go after a month.
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

    /// End to end: a prune removes what the policy chose and says which.
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
        assert_eq!(list(&root).expect("lists").len(), 1);

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
        assert!(list(&root).expect("lists").is_empty());

        std::fs::remove_dir_all(&root).ok();
    }

    /// A host whose primary address is promoted mid-scan is still one host.
    ///
    /// Local discovery calls `Host::consider_primary_ip` when a better address
    /// turns up, so the same machine can be written once under a link-local
    /// address and again under a global one. Keyed on the primary alone, those
    /// come back as two hosts that were never two.
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

            // Then a global address arrives and takes the primary slot.
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

        let (journal, _) = Journal::resume(&directory, &ports(&map), true).expect("resumes");

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

    /// A journal holds the addresses an engagement was pointed at and what was
    /// found there. Nobody else on the machine has business reading it.
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

    /// A journal that could not take its lock leaves nothing behind, rather than
    /// a directory that reads as a scan which found nothing.
    #[test]
    fn a_journal_that_cannot_be_locked_leaves_no_directory() {
        let root = scratch("unlockable");
        let map = plan("192.0.2.1", "80");

        // A file where the scan directory would go: the create cannot proceed,
        // and whatever it did get to must be undone.
        let before = list(&root).expect("lists").len();
        assert_eq!(before, 0);

        let journal = begin(&root, &map);
        let directory = journal.directory().to_path_buf();

        // Held by this process, so a second journal over the same directory is
        // refused — the same path a real contention takes.
        assert!(matches!(
            Journal::resume(&directory, &ports(&map), true),
            Err(OpenError::Locked(_))
        ));
        assert!(directory.exists(), "the held journal is untouched");

        journal.close().expect("closes");
        std::fs::remove_dir_all(&root).ok();
    }

    /// A long scan appends a host each interval anything about it changes, so
    /// the findings file grows with the scan's duration rather than with what it
    /// found. Compaction bounds it, and must lose nothing doing so.
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

            assert!(
                journal.should_compact(live.len()),
                "280 records for four hosts is what compaction is for"
            );
            journal.compact(&live).expect("compacts");
            assert!(!journal.should_compact(live.len()));

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
        let (journal, _) = Journal::resume(&directory, &ports(&map), true).expect("resumes");

        let restored = journal.restored();
        assert_eq!(restored.len(), 4);
        for host in restored {
            assert!(host.is_alive());
            assert_eq!(host.port_count(), 70, "every round's port survived");
        }

        std::fs::remove_dir_all(&root).ok();
    }

    /// A scan can be continued knowing nothing but its id.
    ///
    /// The plan comes back as it was written down. Without this a resume has to
    /// be told the targets and ports again, which is both a chore and a trap:
    /// what somebody types the second time is not necessarily what ran the
    /// first.
    #[test]
    fn a_journal_gives_back_the_plan_it_recorded() {
        let root = scratch("reopen");
        let map = plan("192.0.2.1-192.0.2.4", "80,443,u:53");

        let directory = {
            let journal = Journal::create(
                &root,
                &Plan::port_scan(&map, &Exclusions::none(), TcpScanTechnique::Fin),
                true,
                "test",
            )
            .expect("creates");
            let directory = journal.directory().to_path_buf();
            journal.close().expect("closes");
            directory
        };

        let (journal, _checkpoint, recovered) = Journal::reopen(&directory, true).expect("reopens");

        let recovered = recovered.targets().expect("a port scan's plan");
        assert_eq!(
            recovered.iter().collect::<Vec<_>>(),
            map.iter().collect::<Vec<_>>(),
            "the same targets, in the same order, so positions still mean what they did"
        );
        assert_eq!(journal.manifest().technique(), TcpScanTechnique::Fin);
    }

    /// Continuing a scan under different privileges is refused: the raw and
    /// connect paths answer different questions, and a journal half of each
    /// would be counting two things.
    #[test]
    fn a_journal_will_not_be_continued_under_different_privileges() {
        let root = scratch("reopen-privilege");
        let map = plan("192.0.2.1", "80");

        let journal = Journal::create(&root, &ports(&map), true, "test").expect("creates");
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let refused = Journal::reopen(&directory, false).expect_err("privileges differ");
        assert!(matches!(refused, OpenError::PlanChanged(_)), "{refused:?}");
    }
}
