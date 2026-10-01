// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Telling a running scan from a crashed one
//!
//! A journal that is being written to must not be resumed, and a journal whose writer
//! died must not stay locked forever. Resuming a live scan corrupts both sittings' cursors;
//! a lock nobody can clear makes a crashed scan impossible to continue.
//!
//! ## Three facts
//!
//! The lock file records a process id, a boot identity and a heartbeat, because each alone
//! is wrong in some case:
//!
//! - **The pid alone is wrong after a reboot.** Process ids restart from a low number, so
//!   the pid in a lock written before a crash-and-reboot often belongs to something live
//!   and unrelated, such as `launchd` or a shell.
//! - **The boot identity alone is wrong within one boot.** A pid freed by a crash can be
//!   reissued to an unrelated process minutes later.
//! - **The heartbeat alone is wrong about a slow scan.** A scan may legitimately do
//!   nothing for a while, under a long silence tolerance or against a tarpit.
//!
//! The boot identity rules out everything before the last boot; within one boot the pid
//! says whether something holds that number, and the heartbeat says whether it is still
//! this scan.
//!
//! ## The policy is a pure function
//!
//! [`classify`] takes the record, the current boot identity, whether the pid is alive and
//! the time, and returns a [`LockState`], so a reboot, a reused pid and a hung writer can be
//! tested in CI. The syscalls live in [`inspect`], a thin wrapper over it.
//!
//! ## What is refused
//!
//! A scan that is or might be running is refused; one that certainly is not may be
//! resumed. A live pid that has stopped touching the lock is refused, since it may be a hung
//! writer that will wake up, and two writers on one journal is what this module prevents.
//!
//! Every refusal is overridable, so a stale lock left by an unforeseen defect cannot make a
//! journal unusable forever. [`Lock::take_over`] overrides only that ambiguous case, where
//! the user can judge whether the process holding the number is the scan.
//! [`Lock::force`] also overrides a writer that is checkpointing now.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// How long a heartbeat may go untouched before the writer holding a lock is
/// treated as no longer obviously alive.
///
/// A scan checkpoints every few seconds, so a minute of silence is many missed beats.
/// Erring long costs an overridable refusal; erring short costs two writers on one
/// journal.
pub const HEARTBEAT_STALE_AFTER: Duration = Duration::from_secs(60);

/// What a lock file says about the process that wrote it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockRecord {
    /// The process holding the journal.
    pub pid: u32,
    /// Which boot that pid belongs to. A pid is only meaningful within one.
    pub boot: String,
    /// When the scan started, so a listing can say how old each journal is.
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
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockState {
    /// No lock file. The journal is free.
    Free,

    /// A live process is writing this journal now. Refuse.
    Held {
        /// The process holding it, so a refusal can name it.
        pid: u32,
        /// How long ago it last checkpointed.
        last_beat: Duration,
    },

    /// The pid is gone and the writer died without releasing. Resume, noting that the
    /// last checkpoint interval may be missing.
    Crashed {
        /// The process that held it, for the note.
        pid: u32,
    },

    /// The machine rebooted while this journal was locked, so the pid in the file is not
    /// the writer. Resume, and warn that a reboot loses more than a crash: anything the page
    /// cache had not flushed is gone.
    RebootedUnder {
        /// The process that held it, before the reboot.
        pid: u32,
    },

    /// Something holds that pid and it has stopped touching the lock: either the writer
    /// is hung or it died and the number was reissued. Refused, overridably.
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
    /// True only after a reboot: every other stop is a process death, and the page cache
    /// outlives a process. See [`journal`](crate::journal) for the survival table.
    pub fn may_have_lost_the_tail(&self) -> bool {
        matches!(self, LockState::RebootedUnder { .. })
    }

    /// Why a resume was refused, phrased for a user deciding what to do about it. `None`
    /// where nothing was refused.
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
                 Stop it, or take the journal over if you are sure it is not scanning",
                last_beat.as_secs()
            )),
        }
    }
}

/// Decides what a lock record means, given everything observed about it. Pure.
///
/// The boot identity is checked first: a pid from a previous boot says nothing, and asking
/// whether it is alive first would leave every journal locked behind an unrelated process
/// after a reboot.
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

    // A clock that went backwards yields no elapsed time, read as a fresh beat: the safe
    // reading of an unknowable age is that the writer is alive.
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

/// A value that changes every boot, so a pid from before one can be disregarded.
///
/// Linux has a boot id; macOS and the BSDs use the boot time. Where neither can be read the
/// identity is empty, which differs from any recorded one and so reads as a reboot,
/// releasing the lock.
pub fn boot_identity() -> String {
    imp::boot_identity()
}

/// Whether any process currently holds `pid`.
///
/// Says nothing about which process. Within one boot the heartbeat distinguishes this
/// scan from a reused number.
pub fn pid_is_alive(pid: u32) -> bool {
    imp::pid_is_alive(pid)
}

#[cfg(unix)]
mod imp {
    pub fn boot_identity() -> String {
        // Linux: a UUID minted per boot.
        if let Ok(id) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
            return id.trim().to_string();
        }

        // macOS and the BSDs: the boot instant from `KERN_BOOTTIME`.
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
        // `pid_t` is signed and `kill` reads a negative argument as a process group:
        // `u32::MAX` casts to `-1`, which asks about every process the caller may signal and is
        // always answered yes. A lock naming it would then be refused forever.
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        if pid <= 0 {
            return false;
        }

        // SAFETY: `kill` with signal 0 sends nothing. It performs the existence
        // and permission checks and returns, dereferencing nothing.
        let code = unsafe { libc::kill(pid, 0) };
        if code == 0 {
            return true;
        }

        // `EPERM` means the process exists and belongs to somebody else, the ordinary case
        // for a scan started under `sudo` and inspected without it.
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

#[cfg(windows)]
mod imp {
    /// Empty on Windows, so the process id alone decides.
    ///
    /// Wall clock minus `GetTickCount64` is not constant within a boot: the two are read at
    /// different instants, the tick counter has about 15 ms resolution, and it stops across
    /// some suspend states. A value that moved within a boot would read every lock as
    /// `RebootedUnder`, which is resumable.
    ///
    /// Two empty identities compare equal, so [`pid_is_alive`] decides every lock. The cost is
    /// that a lock left by a crash before a reboot, whose number another process has taken
    /// since, reads as held and is refused.
    pub fn boot_identity() -> String {
        String::new()
    }

    /// Whether a process with this id is running, as the unix arm asks it.
    ///
    /// Access denied means the process exists and belongs to somebody else, as `EPERM`
    /// does on unix, so it reads as alive. A query that fails after the process was opened also
    /// reads as alive: a refused resume only waits, while a resume under a live writer
    /// corrupts its journal.
    pub fn pid_is_alive(pid: u32) -> bool {
        use windows_sys::Win32::Foundation::{
            CloseHandle, ERROR_ACCESS_DENIED, GetLastError, STILL_ACTIVE,
        };
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        // Zero is the idle process, which no scan runs as.
        if pid == 0 {
            return false;
        }

        // SAFETY: `OpenProcess` takes no pointers and returns a null handle
        // on failure, which is checked before any use.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            // SAFETY: reads the calling thread's last-error value.
            return unsafe { GetLastError() } == ERROR_ACCESS_DENIED;
        }

        let mut code = 0u32;
        // SAFETY: `handle` was opened above with the right to query, and `code`
        // is a live `u32` the call writes the exit code into.
        let answered = unsafe { GetExitCodeProcess(handle, &mut code) } != 0;
        // SAFETY: `handle` was opened above and is not used again.
        unsafe { CloseHandle(handle) };

        !answered || code == STILL_ACTIVE as u32
    }
}

#[cfg(feature = "journal-format")]
mod persistence {
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::SystemTime;

    use super::{HEARTBEAT_STALE_AFTER, LockRecord, LockState, boot_identity, classify};
    use crate::journal::file::{link_new, open_or_create_private, open_to_read, remove, replace};
    use crate::journal::format::JournalError;

    /// Reads a lock file and says what it means.
    ///
    /// A missing file is [`LockState::Free`], and so is a file that cannot be parsed or a
    /// link at the name, which is not followed: nothing that takes a lock leaves one there. A
    /// truncated or corrupt lock was left by a writer that crashed mid-write, and refusing it
    /// would make the crash unrecoverable. The next holder's heartbeat protects the journal.
    pub fn inspect(path: &Path) -> LockState {
        let text = open_to_read(path).and_then(|mut file| {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut file, &mut text).map(|_| text)
        });
        let Ok(text) = text else {
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
        /// Set by [`Lock::release`] so the `Drop` path does not try again. A flag, since
        /// `mem::forget` would leak the path and the record.
        released: bool,
    }

    impl Lock {
        /// Takes the lock, or explains why it could not be taken.
        ///
        /// Creating the file is the exclusion: it fails if anything is there, so two
        /// processes racing for one journal cannot both succeed. The existing lock is inspected
        /// only after that fails, to decide whether it may be broken.
        pub fn acquire(path: &Path) -> Result<Self, LockRefused> {
            Self::acquire_inner(path, Breaks::Dead)
        }

        /// [`acquire`](Self::acquire), breaking a [`Stale`](LockState::Stale) lock as well
        /// as a dead one.
        ///
        /// For a caller who has judged that the process holding the number in a lock that stopped
        /// beating is not the scan, usually because the number was reissued after a crash. A lock
        /// whose writer is checkpointing now is still refused.
        pub fn take_over(path: &Path) -> Result<Self, LockRefused> {
            Self::acquire_inner(path, Breaks::Stale)
        }

        /// [`acquire`](Self::acquire), overriding any refusal.
        ///
        /// For a lock left by a defect nothing here anticipated, which would otherwise make the
        /// journal unusable forever.
        pub fn force(path: &Path) -> Result<Self, LockRefused> {
            Self::acquire_inner(path, Breaks::Anything)
        }

        /// How many times a break is retried before giving up.
        ///
        /// A retry happens only when another process won the create between this one removing a
        /// dead lock and replacing it; the winner's lock is live, so the next round refuses. More
        /// rounds than that means two processes are breaking each other's locks in a loop.
        const BREAK_ATTEMPTS: usize = 3;

        fn acquire_inner(path: &Path, breaks: Breaks) -> Result<Self, LockRefused> {
            // Built only after the create succeeds: `Lock` removes its file on drop, so one
            // dropped after losing the create would delete the winner's lock.
            let held = |record| Self {
                path: path.to_path_buf(),
                record,
                released: false,
            };
            let mut refusal = None;

            for _ in 0..Self::BREAK_ATTEMPTS {
                let record = LockRecord::current();
                match Self::create_exclusively(path, &record) {
                    Ok(()) => return Ok(held(record)),
                    Err(error) if error.kind() != std::io::ErrorKind::AlreadyExists => {
                        return Err(LockRefused::Io(error.to_string()));
                    }
                    Err(_) => {}
                }

                // Deciding a lock is dead and replacing it must be one operation. `create_new`
                // only excludes racers for a free journal. Replacing a dead lock by rename
                // bypasses the create, and removing it first lets every racer remove whatever is
                // at the name, including the lock the last winner just created: eight processes
                // on one crashed journal yielded two to four holders.
                //
                // So the inspect, removal and create run under an advisory lock on a sibling
                // file, held only for those three steps. The kernel drops it when its holder
                // exits, so it cannot go stale and `force` never needs to clear it.
                let _breaking = Breaking::take(path).map_err(|e| LockRefused::Io(e.to_string()))?;

                // Asked again under the guard: the previous guard holder may have taken the
                // journal in the meantime.
                let state = inspect(path);
                if !breaks.permits(&state) {
                    return Err(LockRefused::Held(state));
                }

                match remove(path) {
                    Ok(()) => {}
                    // Removed between the two inspections; the create below decides either way.
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(LockRefused::Io(error.to_string())),
                }

                let record = LockRecord::current();
                match Self::create_exclusively(path, &record) {
                    Ok(()) => return Ok(held(record)),
                    Err(error) if error.kind() != std::io::ErrorKind::AlreadyExists => {
                        return Err(LockRefused::Io(error.to_string()));
                    }
                    // A process arriving after this one removed the lock sees nothing to break,
                    // takes no guard, and can win the create in that gap. The next round then
                    // finds a beating lock and refuses by name.
                    Err(_) => refusal = Some(state),
                }
            }

            Err(match refusal {
                Some(state) => LockRefused::Held(state),
                None => LockRefused::Io("the lock could not be taken".to_string()),
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
            remove(&self.path)?;
            Ok(())
        }

        /// Takes the lock, or fails with
        /// [`AlreadyExists`](std::io::ErrorKind::AlreadyExists) if somebody has it.
        ///
        /// The name appears already holding the record. Creating then writing would let a racer
        /// read an empty lock between the two steps, which [`inspect`] reports as `Free` (that is
        /// what a writer killed mid-write leaves), and delete a lock taken a microsecond earlier.
        /// So the record is written to a staged file and linked into place: `link` refuses an
        /// existing name, as `create_new` does, over a file that already has its contents.
        ///
        /// Created like every other journal file, so under `sudo` it belongs to whoever invoked the
        /// scan and they can release it.
        ///
        /// The staged name carries a counter as well as the pid, because this is a library and two
        /// threads of one caller may take the same journal. With the pid alone they would share the
        /// staged name, and since [`link_new`] removes a staged name it finds occupied, one thread
        /// could delete the other's file (failing its link with `NotFound`) or link an empty file
        /// that [`inspect`] reads as `Free`. Either way the lock would get two holders.
        fn create_exclusively(path: &Path, record: &LockRecord) -> std::io::Result<()> {
            static STAGING: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let staged = path.with_extension(format!(
                "lock-{}-{}",
                std::process::id(),
                STAGING.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));

            let text = serde_json::to_string(record).map_err(std::io::Error::other)?;
            // Staged with a retry, since a reused pid can find a staged file left by a run
            // that died between the create and the link.
            link_new(path, &staged, |mut file| file.write_all(text.as_bytes()))
        }

        /// Replaces the lock file in place, for the holder moving its own heartbeat forward.
        /// Taking a lock goes through [`create_exclusively`](Self::create_exclusively).
        fn write(path: &Path, record: &LockRecord) -> std::io::Result<()> {
            let text = serde_json::to_string(record).map_err(std::io::Error::other)?;
            // Private from creation like the original, so a heartbeat never widens the mode.
            // The lock becomes the staged file's inode, ownership included.
            replace(path, &path.with_extension("lock-tmp"), |mut file| {
                file.write_all(text.as_bytes())
            })
        }
    }

    /// Which locks an attempt to take one may break.
    #[derive(Debug, Clone, Copy)]
    enum Breaks {
        /// Only one nothing holds: free, crashed, or from before a reboot.
        Dead,
        /// Those, and one whose holder stopped checkpointing.
        Stale,
        /// Whatever is there.
        Anything,
    }

    impl Breaks {
        fn permits(self, state: &LockState) -> bool {
            match self {
                Breaks::Dead => state.is_resumable(),
                Breaks::Stale => state.is_resumable() || matches!(state, LockState::Stale { .. }),
                Breaks::Anything => true,
            }
        }
    }

    /// Serialises deciding that a lock is dead and replacing it.
    ///
    /// See the comment at the call site. Dropped as soon as the three steps are done.
    struct Breaking {
        /// Held only for the handle: the lock lives on the open file and is released when
        /// it closes.
        _file: fs::File,
    }

    impl Breaking {
        fn take(lock: &Path) -> std::io::Result<Self> {
            // A sibling file, because the lock file is about to be removed and an advisory
            // lock follows the open file, not the name. Opened, not created, so every racer reaches
            // the same file.
            let file = open_or_create_private(&lock.with_extension("break"))?;

            // Blocks for the exclusive lock: `flock` on unix, `LockFileEx` on Windows.
            file.lock()?;
            Ok(Self { _file: file })
        }
    }

    impl Drop for Lock {
        fn drop(&mut self) {
            if self.released {
                return;
            }

            // Best effort. A lock left by a failed removal reads as `Crashed` to the next
            // reader, which is resumable.
            let _ = remove(&self.path);
        }
    }

    /// Why a lock could not be taken.
    #[non_exhaustive]
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
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
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

    /// A live writer checkpointing normally is always refused.
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

    /// The case the pid alone gets wrong. After a reboot low pids go to init and its
    /// children, so the pid in an old lock is often alive and unrelated.
    #[test]
    fn a_lock_from_a_previous_boot_is_released_even_though_its_pid_is_alive() {
        let state = classify(
            &record(OTHER_BOOT, 100),
            BOOT,
            true, // alive, but not the same process
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

    /// The case the boot identity alone gets wrong. Within one boot a freed pid can be
    /// reissued, and only the heartbeat tells the two apart, so a stale beat is refused.
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
        assert!(
            state
                .refusal()
                .is_some_and(|r| r.contains("take the journal over"))
        );
    }

    /// A beat exactly at the threshold is not yet stale. The boundary decides between
    /// refusing a live scan and permitting a second writer.
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

    /// A clock that moved backwards does not turn a live scan into a stale one.
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

    /// An unreadable boot identity compares unequal to any recorded one, so it releases
    /// locks.
    #[test]
    fn an_unknown_boot_identity_releases_rather_than_holds() {
        let state = classify(&record(BOOT, 100), "", true, at(105), HEARTBEAT_STALE_AFTER);

        assert!(state.is_resumable(), "{state:?}");
    }

    /// This host reports its boot identity, and the same one twice.
    #[test]
    fn the_boot_identity_is_readable_and_stable() {
        let first = boot_identity();
        assert!(!first.is_empty(), "no boot identity on this platform");
        assert_eq!(first, boot_identity(), "it must not change while running");
    }

    /// The liveness check is right about the one process a test can be sure of:
    /// itself.
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

    /// Two scans racing for one journal: the second is refused and told which process
    /// has it.
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

        // Forcing gets past it.
        let forced = Lock::force(&path).expect("force overrides");
        drop(forced);
        drop(first);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A lock whose holder stopped beating can be taken over, and one whose holder is
    /// beating cannot. This process stands in for a reissued pid.
    #[test]
    fn a_stale_lock_can_be_taken_over_and_a_beating_one_cannot() {
        let dir = scratch("stale");
        let path = dir.join("LOCK");

        let stale = LockRecord {
            pid: std::process::id(),
            boot: boot_identity(),
            started_at: SystemTime::now() - Duration::from_secs(3_600),
            heartbeat: SystemTime::now() - Duration::from_secs(600),
        };
        std::fs::write(&path, serde_json::to_string(&stale).expect("json")).expect("writes");
        assert!(matches!(inspect(&path), LockState::Stale { .. }));
        assert!(
            Lock::acquire(&path).is_err(),
            "a stale lock is refused unasked"
        );

        let taken = Lock::take_over(&path).expect("a stale lock is taken over");
        assert!(
            matches!(
                Lock::take_over(&path),
                Err(LockRefused::Held(LockState::Held { .. }))
            ),
            "a lock beating now is not taken over"
        );
        drop(taken);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A lock left half-written by a crash reads as free, so it does not lock the
    /// journal forever.
    #[test]
    fn a_corrupt_lock_does_not_wedge_the_journal() {
        let dir = scratch("corrupt");
        let path = dir.join("LOCK");

        std::fs::write(&path, "{\"pid\":42,\"bo").expect("writes a torn lock");
        assert_eq!(inspect(&path), LockState::Free);

        Lock::acquire(&path).expect("a torn lock can be taken over");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A crashed writer's lock is taken without a force, and the new holder's heartbeat
    /// replaces it.
    #[test]
    fn a_dead_writers_lock_is_taken_over() {
        let dir = scratch("crashed");
        let path = dir.join("LOCK");

        // pid 0 is never a signalable process, so it stands in for a writer that is gone.
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

    /// Several racers finding the same crashed journal: exactly one takes it.
    ///
    /// The racers are threads in one process, so this also covers the staged-name counter in
    /// `create_exclusively`. Without the guard or the counter the count came out at two about
    /// one run in twenty, so the racers start on a barrier and the race runs in rounds.
    #[test]
    fn only_one_of_several_racers_breaks_a_crashed_lock() {
        for round in 0..16 {
            let dir = scratch(&format!("break-race-{round}"));
            let path = dir.join("LOCK");

            // A lock from before a reboot, resumable whatever its pid is doing. A test
            // cannot name a pid it is certain nothing holds.
            let stale = LockRecord {
                pid: std::process::id(),
                boot: "a boot that is over".to_string(),
                started_at: SystemTime::UNIX_EPOCH,
                heartbeat: SystemTime::UNIX_EPOCH,
            };
            std::fs::write(&path, serde_json::to_string(&stale).expect("json")).expect("writes");
            assert!(matches!(inspect(&path), LockState::RebootedUnder { .. }));

            let taken = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            // Racers start together; without the barrier the first thread usually finished
            // before the last began.
            let start = std::sync::Arc::new(std::sync::Barrier::new(8));
            std::thread::scope(|scope| {
                for _ in 0..8 {
                    let path = path.clone();
                    let taken = std::sync::Arc::clone(&taken);
                    let start = std::sync::Arc::clone(&start);
                    scope.spawn(move || {
                        start.wait();
                        if let Ok(lock) = Lock::acquire(&path) {
                            taken.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            // Held for the rest of the scope, so a later racer is refused.
                            std::thread::sleep(std::time::Duration::from_millis(20));
                            std::mem::forget(lock);
                        }
                    });
                }
            });

            assert_eq!(
                taken.load(std::sync::atomic::Ordering::Relaxed),
                1,
                "round {round}: this many racers believed they held the journal"
            );

            std::fs::remove_dir_all(&dir).ok();
        }
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
