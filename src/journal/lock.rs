// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Telling a running scan from a crashed one
//!
//! A journal that is being written to must not be resumed, and a journal whose
//! writer died must not stay locked forever. Both mistakes are easy and neither
//! announces itself: resuming a live scan corrupts both sittings' cursors, and a
//! lock nobody can clear turns a crash into a scan that can never be continued.
//!
//! ## Three facts, because no two of them are enough
//!
//! The lock file records a process id, a boot identity, and a heartbeat. Each
//! covers a case the others cannot:
//!
//! - **The pid alone lies after a reboot.** Process ids restart from a low
//!   number, so the pid in a lock written before a crash-and-reboot very often
//!   belongs to something live and unrelated — `launchd`, `systemd`, a shell.
//!   Reading it as "still running" would leave every journal from before a
//!   reboot permanently locked.
//! - **The boot identity alone lies within one boot.** A pid freed by a crash
//!   can be reissued to an unrelated process minutes later.
//! - **The heartbeat alone lies about a slow scan.** A scan legitimately doing
//!   nothing for a while — a long silence tolerance, a stalled tarpit — is not a
//!   dead one, so staleness on its own is not evidence of death.
//!
//! Together they decide. The boot identity rules out everything before the last
//! boot; within one boot the pid says whether *something* holds that number, and
//! the heartbeat says whether it is still this scan.
//!
//! ## The policy is a pure function
//!
//! [`classify`] takes the record, the current boot identity, whether the pid is
//! alive and what the time is, and returns a [`LockState`]. It calls nothing.
//! That is deliberate: the interesting cases are a reboot, a reused pid and a
//! hung writer, and a test that had to arrange those for real could not run in
//! CI. The syscalls live in [`inspect`], which is a thin wrapper over the same
//! function.
//!
//! ## What is refused and what is not
//!
//! A scan that is or might be running is refused; a scan that certainly is not
//! may be resumed. The ambiguous case — the pid is alive but has stopped
//! touching the lock — is refused rather than assumed, because it is
//! indistinguishable from a hung writer that will wake up, and two writers on
//! one journal is the failure this file exists to prevent.
//!
//! **A refusal must always be overridable.** A stale lock left by a defect this
//! engine has not thought of would otherwise make a journal unusable forever,
//! which is a worse outcome than the risk of forcing one.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// How long a heartbeat may go untouched before the writer holding a lock is
/// treated as no longer obviously alive.
///
/// Generous against the checkpoint interval: a scan writes one every few
/// seconds, so a minute of silence is many missed beats rather than one late
/// one. The cost of being wrong in this direction is a refusal a user can
/// override; the cost in the other direction is two writers on one journal.
pub const HEARTBEAT_STALE_AFTER: Duration = Duration::from_secs(60);

/// What a lock file says about the process that wrote it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockRecord {
    /// The process holding the journal.
    pub pid: u32,
    /// Which boot that pid belongs to. A pid is only meaningful within one.
    pub boot: String,
    /// When the scan started, so a caller listing journals can say how old
    /// each one is.
    pub started_at: SystemTime,
    /// Last touched by the writer, once per checkpoint.
    pub heartbeat: SystemTime,
}

impl LockRecord {
    /// The record this process would write now.
    pub fn current() -> Self {
        let now = SystemTime::now();
        Self {
            pid: std::process::id(),
            boot: boot_identity(),
            started_at: now,
            heartbeat: now,
        }
    }

    /// The same record with its heartbeat moved to `now`.
    pub fn beating_at(&self, now: SystemTime) -> Self {
        Self {
            heartbeat: now,
            ..self.clone()
        }
    }
}

/// What is known about a journal's writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockState {
    /// No lock file. The journal is free.
    Free,

    /// A live process is writing this journal now. **Refuse.**
    Held {
        /// The process holding it, so a refusal can name it.
        pid: u32,
        /// How long ago it last checkpointed.
        last_beat: Duration,
    },

    /// The pid is gone. The writer died without releasing. **Resume**, and say
    /// that the last checkpoint interval may be missing.
    Crashed {
        /// The process that held it, for the note.
        pid: u32,
    },

    /// The machine rebooted while this journal was locked, so whatever pid the
    /// file names is not the writer whatever it is doing now. **Resume**, and
    /// warn that a reboot loses more than a crash does: anything the page cache
    /// had not flushed went with it.
    RebootedUnder {
        /// The process that held it, before the reboot.
        pid: u32,
    },

    /// Something holds that pid and it has stopped touching the lock. Either the
    /// writer is hung, or it died and the number was reissued — and nothing here
    /// can tell those apart. **Refuse, overridably.**
    Stale {
        /// The process that number now belongs to, whoever that is.
        pid: u32,
        /// How long the heartbeat has been untouched.
        last_beat: Duration,
    },
}

impl LockState {
    /// Whether the journal may be resumed without the user overriding anything.
    pub fn is_resumable(&self) -> bool {
        matches!(
            self,
            LockState::Free | LockState::Crashed { .. } | LockState::RebootedUnder { .. }
        )
    }

    /// Whether resuming loses more than one checkpoint interval.
    ///
    /// True only after a reboot: every other stop this engine survives is a
    /// process death, and the page cache outlives a process. See
    /// [`journal`](crate::journal) for the whole survival table.
    pub fn may_have_lost_the_tail(&self) -> bool {
        matches!(self, LockState::RebootedUnder { .. })
    }

    /// Why a resume was refused, phrased for a user who has to decide what to do
    /// about it. `None` where nothing was refused.
    pub fn refusal(&self) -> Option<String> {
        match self {
            LockState::Free | LockState::Crashed { .. } | LockState::RebootedUnder { .. } => None,
            LockState::Held { pid, last_beat } => Some(format!(
                "process {pid} is scanning this journal now (last checkpoint {}s ago); \
                 wait for it to finish, or stop it first",
                last_beat.as_secs()
            )),
            LockState::Stale { pid, last_beat } => Some(format!(
                "this journal is locked by process {pid}, which has not checkpointed for {}s — \
                 it is either hung or the number was reissued to something else. \
                 Stop it, or take the lock forcibly if you are sure it is not scanning",
                last_beat.as_secs()
            )),
        }
    }
}

/// Decides what a lock record means, given everything that has to be observed to
/// judge it.
///
/// Pure. See the module documentation for why the policy is separated from the
/// syscalls that feed it.
///
/// The order of the checks is the argument: **the boot identity is read first**,
/// because a pid from a previous boot says nothing at all, and asking whether it
/// is alive before ruling that out is how a reboot leaves every journal locked
/// behind an unrelated process.
pub fn classify(
    record: &LockRecord,
    boot: &str,
    pid_is_alive: bool,
    now: SystemTime,
    stale_after: Duration,
) -> LockState {
    if record.boot != boot {
        return LockState::RebootedUnder { pid: record.pid };
    }

    if !pid_is_alive {
        return LockState::Crashed { pid: record.pid };
    }

    // A clock that went backwards between the write and this read yields no
    // elapsed time. Treated as a fresh beat rather than an ancient one, because
    // the safe reading of "I cannot tell how old this is" is that the writer is
    // alive.
    let last_beat = now.duration_since(record.heartbeat).unwrap_or_default();

    if last_beat > stale_after {
        LockState::Stale {
            pid: record.pid,
            last_beat,
        }
    } else {
        LockState::Held {
            pid: record.pid,
            last_beat,
        }
    }
}

/// Something that changes every boot, so a pid from before one can be
/// disregarded.
///
/// Linux has a value for exactly this. macOS and the BSDs have the boot *time*,
/// which serves the same purpose: it is constant for a boot and differs across
/// them. Where neither can be read the identity is empty, which compares unequal
/// to any recorded one and so degrades to "assume a reboot" — the conservative
/// direction, since it releases a lock rather than holding one.
pub fn boot_identity() -> String {
    imp::boot_identity()
}

/// Whether any process currently holds `pid`.
///
/// Says nothing about *which* process. Within one boot that is enough, because
/// the heartbeat is what distinguishes this scan from a reused number.
pub fn pid_is_alive(pid: u32) -> bool {
    imp::pid_is_alive(pid)
}

#[cfg(unix)]
mod imp {
    pub fn boot_identity() -> String {
        // Linux: a UUID minted per boot, which is precisely the question.
        if let Ok(id) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
            return id.trim().to_string();
        }

        // macOS and the BSDs: the boot instant, via the same sysctl `uptime`
        // reads. Constant within a boot and different across boots, which is all
        // this has to be.
        #[cfg(any(target_os = "macos", target_os = "ios", target_vendor = "apple"))]
        {
            let mut boot = libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            };
            let mut size = std::mem::size_of::<libc::timeval>();
            let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];

            // SAFETY: `mib` is a live array of the length passed, `boot` is a
            // live `timeval` and `size` names its exact size, which is what
            // `KERN_BOOTTIME` writes. The call reads and writes only those.
            let code = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as libc::c_uint,
                    (&raw mut boot).cast::<libc::c_void>(),
                    &mut size,
                    std::ptr::null_mut(),
                    0,
                )
            };

            if code == 0 {
                return format!("{}.{}", boot.tv_sec, boot.tv_usec);
            }
        }

        String::new()
    }

    pub fn pid_is_alive(pid: u32) -> bool {
        if pid == 0 {
            return false;
        }

        // SAFETY: `kill` with signal 0 sends nothing. It performs the existence
        // and permission checks and returns, dereferencing nothing.
        let code = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if code == 0 {
            return true;
        }

        // `EPERM` means the process exists and belongs to somebody else — which
        // is the ordinary case for a scan started under `sudo` and inspected
        // without it, so reading it as "dead" would let a user resume a journal
        // their own root process is writing.
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

#[cfg(windows)]
mod imp {
    pub fn boot_identity() -> String {
        // Milliseconds since boot, subtracted from now: constant within a boot
        // to the resolution of the tick counter, and different across boots.
        // SAFETY: takes no arguments and dereferences nothing.
        let uptime_ms = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() };
        match std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
        {
            Some(now) => format!(
                "{}",
                now.as_millis().saturating_sub(uptime_ms as u128) / 1000
            ),
            None => String::new(),
        }
    }

    pub fn pid_is_alive(_pid: u32) -> bool {
        // Not yet implemented: Windows is not a supported scanning host, so no
        // journal is written there to lock. Reported as alive, which refuses a
        // resume rather than permitting a second writer — the safe direction for
        // a stub.
        true
    }
}

#[cfg(feature = "journal-format")]
mod persistence {
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::SystemTime;

    use super::{HEARTBEAT_STALE_AFTER, LockRecord, LockState, boot_identity, classify};
    use crate::journal::format::JournalError;

    /// Reads a lock file and says what it means.
    ///
    /// A missing file is [`LockState::Free`]. **A file that cannot be parsed is
    /// also `Free`**, deliberately: a truncated or corrupt lock is one a crashed
    /// writer left mid-write, and treating it as a permanent refusal would make
    /// a crash unrecoverable — the opposite of what this file is for. The
    /// journal is protected by the heartbeat of whoever holds it next, not by a
    /// file nobody can read.
    pub fn inspect(path: &Path) -> LockState {
        let Ok(text) = fs::read_to_string(path) else {
            return LockState::Free;
        };

        let Ok(record) = serde_json::from_str::<LockRecord>(&text) else {
            return LockState::Free;
        };

        classify(
            &record,
            &boot_identity(),
            super::pid_is_alive(record.pid),
            SystemTime::now(),
            HEARTBEAT_STALE_AFTER,
        )
    }

    /// A held lock, which releases itself when dropped.
    #[derive(Debug)]
    pub struct Lock {
        path: PathBuf,
        record: LockRecord,
        /// Set by [`Lock::release`] so the `Drop` path does not try again.
        ///
        /// A flag rather than `mem::forget`, which would suppress the drop by
        /// leaking the path and the record with it. One leak per scan is small
        /// enough to be tempting and still the wrong thing to write down.
        released: bool,
    }

    impl Lock {
        /// Takes the lock, or explains why it could not be taken.
        ///
        /// Creating the file is the exclusion: `create_new` fails if anything is
        /// there, so two processes racing for one journal cannot both succeed
        /// however close together they arrive. The state is inspected only after
        /// that fails, to decide whether the existing lock is one that may be
        /// broken.
        pub fn acquire(path: &Path) -> Result<Self, LockRefused> {
            Self::acquire_inner(path, false)
        }

        /// [`acquire`](Self::acquire), overriding a refusal.
        ///
        /// For the case the module documentation names: a lock left by a defect
        /// nothing here anticipated, which would otherwise make the journal
        /// unusable forever.
        pub fn force(path: &Path) -> Result<Self, LockRefused> {
            Self::acquire_inner(path, true)
        }

        fn acquire_inner(path: &Path, force: bool) -> Result<Self, LockRefused> {
            let record = LockRecord::current();

            match Self::create_exclusively(path, &record) {
                Ok(()) => {
                    return Ok(Self {
                        path: path.to_path_buf(),
                        record,
                        released: false,
                    });
                }
                Err(error) if error.kind() != std::io::ErrorKind::AlreadyExists => {
                    return Err(LockRefused::Io(error.to_string()));
                }
                Err(_) => {}
            }

            let state = inspect(path);
            if !force && !state.is_resumable() {
                return Err(LockRefused::Held(state));
            }

            // Breaking a lock is a replacement, not a second creation, so the
            // exclusive create above cannot be reused here.
            Self::write(path, &record).map_err(|e| LockRefused::Io(e.to_string()))?;
            Ok(Self {
                path: path.to_path_buf(),
                record,
                released: false,
            })
        }

        /// Moves the heartbeat forward. Called once per checkpoint.
        pub fn beat(&mut self) -> Result<(), JournalError> {
            self.record = self.record.beating_at(SystemTime::now());
            Self::write(&self.path, &self.record)?;
            Ok(())
        }

        /// What this lock claims, as written.
        pub fn record(&self) -> &LockRecord {
            &self.record
        }

        /// Releases the lock, reporting a failure the `Drop` path would swallow.
        pub fn release(mut self) -> Result<(), JournalError> {
            self.released = true;
            fs::remove_file(&self.path)?;
            Ok(())
        }

        fn create_exclusively(path: &Path, record: &LockRecord) -> std::io::Result<()> {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                // The lock names a pid and a scan, in a directory holding an
                // engagement's targets. It is nobody else's business.
                options.mode(0o600);
            }

            let mut file = options.open(path)?;
            file.write_all(
                serde_json::to_string(record)
                    .map_err(std::io::Error::other)?
                    .as_bytes(),
            )
        }

        fn write(path: &Path, record: &LockRecord) -> std::io::Result<()> {
            let temporary = path.with_extension("lock-tmp");
            {
                // Private from creation, as `create_exclusively` makes the
                // original: a heartbeat replaces the file, and a replacement
                // that widened its mode would undo that.
                let mut file = create_private(&temporary)?;
                file.write_all(
                    serde_json::to_string(record)
                        .map_err(std::io::Error::other)?
                        .as_bytes(),
                )?;
            }
            fs::rename(&temporary, path)
        }
    }

    /// Creates or truncates a file only this user can read.
    ///
    /// The mode is set as the file is created rather than after, so there is no
    /// moment where what a scan is recording can be read by anyone else.
    fn create_private(path: &Path) -> std::io::Result<fs::File> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        options.open(path)
    }

    impl Drop for Lock {
        fn drop(&mut self) {
            if self.released {
                return;
            }

            // Best effort. A lock left behind by a failed removal is a
            // `Crashed` state to the next reader, which is resumable — so the
            // failure mode of this line is a note in the output, not a journal
            // nobody can open.
            let _ = fs::remove_file(&self.path);
        }
    }

    /// Why a lock could not be taken.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum LockRefused {
        /// Somebody else has it. Carries the state so a caller can render
        /// [`LockState::refusal`].
        Held(LockState),
        /// The lock file could not be written.
        Io(String),
    }

    impl std::fmt::Display for LockRefused {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                LockRefused::Held(state) => match state.refusal() {
                    Some(reason) => write!(f, "{reason}"),
                    None => write!(f, "the journal is locked"),
                },
                LockRefused::Io(error) => write!(f, "could not write the lock: {error}"),
            }
        }
    }

    impl std::error::Error for LockRefused {}
}

#[cfg(feature = "journal-format")]
pub use persistence::{Lock, LockRefused, inspect};

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

    const BOOT: &str = "boot-a";
    const OTHER_BOOT: &str = "boot-b";

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn record(boot: &str, beat: u64) -> LockRecord {
        LockRecord {
            pid: 4_242,
            boot: boot.to_string(),
            started_at: at(0),
            heartbeat: at(beat),
        }
    }

    /// A live writer checkpointing normally. The one case that must always be
    /// refused.
    #[test]
    fn a_beating_lock_on_a_live_pid_is_held() {
        let state = classify(
            &record(BOOT, 100),
            BOOT,
            true,
            at(105),
            HEARTBEAT_STALE_AFTER,
        );

        assert!(matches!(state, LockState::Held { pid: 4_242, .. }));
        assert!(!state.is_resumable());
        assert!(state.refusal().is_some_and(|r| r.contains("4242")));
    }

    /// The ordinary crash: the process is gone and the journal is free.
    #[test]
    fn a_lock_whose_pid_is_gone_is_a_crash() {
        let state = classify(
            &record(BOOT, 100),
            BOOT,
            false,
            at(105),
            HEARTBEAT_STALE_AFTER,
        );

        assert_eq!(state, LockState::Crashed { pid: 4_242 });
        assert!(state.is_resumable());
        assert!(!state.may_have_lost_the_tail());
        assert_eq!(state.refusal(), None);
    }

    /// **The case the pid alone gets wrong.**
    ///
    /// After a reboot, low pids are reissued to init and its children, so the
    /// pid in an old lock is very often alive and entirely unrelated. Checking
    /// liveness before the boot identity would leave every journal written
    /// before a reboot locked behind `launchd`.
    #[test]
    fn a_lock_from_a_previous_boot_is_released_even_though_its_pid_is_alive() {
        let state = classify(
            &record(OTHER_BOOT, 100),
            BOOT,
            true, // alive, and irrelevant: it is not the same process.
            at(105),
            HEARTBEAT_STALE_AFTER,
        );

        assert_eq!(state, LockState::RebootedUnder { pid: 4_242 });
        assert!(state.is_resumable());
        assert!(
            state.may_have_lost_the_tail(),
            "a reboot loses what the page cache had not flushed"
        );
    }

    /// **The case the boot identity alone gets wrong.**
    ///
    /// Within one boot a freed pid can be reissued. The heartbeat is the only
    /// thing that distinguishes the scan that took the lock from whatever holds
    /// that number now, and the two are indistinguishable from here — so it is
    /// refused rather than guessed.
    #[test]
    fn a_live_pid_that_stopped_beating_is_stale_and_refused() {
        let state = classify(
            &record(BOOT, 100),
            BOOT,
            true,
            at(100 + HEARTBEAT_STALE_AFTER.as_secs() + 1),
            HEARTBEAT_STALE_AFTER,
        );

        assert!(matches!(state, LockState::Stale { pid: 4_242, .. }));
        assert!(!state.is_resumable(), "hung and reused look the same here");
        assert!(state.refusal().is_some_and(|r| r.contains("forcibly")));
    }

    /// A beat exactly at the threshold is not yet stale. Asserted because the
    /// boundary decides between refusing a live scan and permitting a second
    /// writer, and an off-by-one there is invisible in every other test.
    #[test]
    fn the_staleness_boundary_is_exclusive() {
        let held = classify(
            &record(BOOT, 100),
            BOOT,
            true,
            at(100) + HEARTBEAT_STALE_AFTER,
            HEARTBEAT_STALE_AFTER,
        );
        assert!(matches!(held, LockState::Held { .. }), "{held:?}");

        let stale = classify(
            &record(BOOT, 100),
            BOOT,
            true,
            at(100) + HEARTBEAT_STALE_AFTER + Duration::from_nanos(1),
            HEARTBEAT_STALE_AFTER,
        );
        assert!(matches!(stale, LockState::Stale { .. }), "{stale:?}");
    }

    /// A clock that moved backwards between the write and the read must not turn
    /// a live scan into a stale one. "I cannot tell how old this is" reads as
    /// alive, which refuses rather than permitting a second writer.
    #[test]
    fn a_heartbeat_from_the_future_reads_as_fresh() {
        let state = classify(
            &record(BOOT, 500),
            BOOT,
            true,
            at(100),
            HEARTBEAT_STALE_AFTER,
        );

        assert!(matches!(state, LockState::Held { .. }), "{state:?}");
    }

    /// An unreadable boot identity compares unequal to any recorded one, so it
    /// releases locks rather than holding them. The conservative direction for a
    /// value this engine may fail to obtain on a platform it has not met.
    #[test]
    fn an_unknown_boot_identity_releases_rather_than_holds() {
        let state = classify(&record(BOOT, 100), "", true, at(105), HEARTBEAT_STALE_AFTER);

        assert!(state.is_resumable(), "{state:?}");
    }

    /// This host can say which boot it is on, and says the same thing twice.
    #[test]
    fn the_boot_identity_is_readable_and_stable() {
        let first = boot_identity();
        assert!(!first.is_empty(), "no boot identity on this platform");
        assert_eq!(first, boot_identity(), "it must not change while running");
    }

    /// The liveness check answers correctly for the one process a test can be
    /// certain about: itself.
    #[test]
    fn this_process_is_alive() {
        assert!(pid_is_alive(std::process::id()));
        assert!(!pid_is_alive(0), "pid 0 is not a process this can signal");
    }
}

#[cfg(all(test, feature = "journal-format"))]
mod file_tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zond-lock-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        dir
    }

    /// Taking, holding and releasing, and what each looks like from outside.
    #[test]
    fn a_lock_is_visible_while_held_and_gone_once_released() {
        let dir = scratch("lifecycle");
        let path = dir.join("LOCK");

        assert_eq!(inspect(&path), LockState::Free, "nothing has it yet");

        let lock = Lock::acquire(&path).expect("takes a free lock");
        assert_eq!(lock.record().pid, std::process::id());
        assert!(
            matches!(inspect(&path), LockState::Held { .. }),
            "this process is alive and has just beaten"
        );

        lock.release().expect("releases");
        assert_eq!(inspect(&path), LockState::Free);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Two scans racing for one journal: the second must be refused, and told
    /// which process has it.
    #[test]
    fn a_second_acquisition_is_refused_while_the_first_holds_it() {
        let dir = scratch("contended");
        let path = dir.join("LOCK");

        let first = Lock::acquire(&path).expect("takes it");

        match Lock::acquire(&path) {
            Err(LockRefused::Held(state)) => {
                assert!(!state.is_resumable());
                assert!(
                    state
                        .refusal()
                        .is_some_and(|r| r.contains(&std::process::id().to_string())),
                    "a refusal has to name who holds it"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }

        // And forcing is the documented way past it.
        let forced = Lock::force(&path).expect("force overrides");
        drop(forced);
        drop(first);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A lock left half-written by a crash must not lock the journal forever.
    /// Unreadable reads as free, because a permanent refusal is the worse of the
    /// two failures.
    #[test]
    fn a_corrupt_lock_does_not_wedge_the_journal() {
        let dir = scratch("corrupt");
        let path = dir.join("LOCK");

        std::fs::write(&path, "{\"pid\":42,\"bo").expect("writes a torn lock");
        assert_eq!(inspect(&path), LockState::Free);

        Lock::acquire(&path).expect("a torn lock can be taken over");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A crashed writer's lock is taken over without a force, and the heartbeat
    /// written by the new holder replaces it.
    #[test]
    fn a_dead_writers_lock_is_taken_over() {
        let dir = scratch("crashed");
        let path = dir.join("LOCK");

        // pid 0 is never a signalable process, so this stands in for a writer
        // that is definitely gone without needing one to be killed.
        let dead = LockRecord {
            pid: 0,
            boot: boot_identity(),
            started_at: SystemTime::now(),
            heartbeat: SystemTime::now(),
        };
        std::fs::write(&path, serde_json::to_string(&dead).expect("json")).expect("writes");

        assert_eq!(inspect(&path), LockState::Crashed { pid: 0 });

        let lock = Lock::acquire(&path).expect("a crashed lock needs no force");
        assert_eq!(lock.record().pid, std::process::id());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The heartbeat moves, and leaves no temporary file behind.
    #[test]
    fn beating_moves_the_heartbeat_forward() {
        let dir = scratch("heartbeat");
        let path = dir.join("LOCK");

        let mut lock = Lock::acquire(&path).expect("takes it");
        let before = lock.record().heartbeat;

        std::thread::sleep(Duration::from_millis(5));
        lock.beat().expect("beats");

        assert!(lock.record().heartbeat > before);
        assert!(
            !dir.join("LOCK.lock-tmp").exists(),
            "the temporary must not survive the rename"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
