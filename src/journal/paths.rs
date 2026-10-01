// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Where a scan's journal lives
//!
//! The sibling of `import::settings::paths`, which sits behind the `import-settings`
//! feature, and a different directory.
//!
//! ## State, not configuration
//!
//! A settings file is hand-edited and lives under `~/.config`. A journal is machine-written,
//! machine-read and disposable once a scan completes, so it goes in the XDG state directory.
//!
//! | | Journal root |
//! |---|---|
//! | Unix (incl. macOS) | `$XDG_STATE_HOME/zond/journals`, else `$HOME/.local/state/zond/journals` |
//! | Windows | `%LOCALAPPDATA%\zond\journals` |
//!
//! On Windows it is `%LOCALAPPDATA%`, not the `%APPDATA%` the settings module uses:
//! `%APPDATA%` roams between machines on a domain profile, and a journal holds the addresses
//! an engagement was pointed at.
//!
//! ## Under `sudo`
//!
//! Raw strategies need root, so most scans run under `sudo`, where `$HOME` is root's.
//! Journals would land in `/root/.local/state/zond/journals`, while anything that lists them
//! runs unprivileged and reads the invoking user's directory. So when this process is
//! elevated and the environment names the user who invoked it, [`root`] resolves that
//! user's home and [`invoking_user`] reports the ownership a caller should write with. The
//! caller does the `chown`.
//!
//! ## Purity
//!
//! Every function here is pure computation over the environment, except that
//! [`invoking_user`] consults the password database to turn a uid into a home directory.
//! That opens no path and creates nothing. Building `/home/<name>` by hand would be wrong on
//! macOS and for directory-service or relocated homes.
//!
//! Nothing here creates a directory. A caller that means to write asks [`root`] where and
//! creates it with the modes the journal requires.

use std::path::PathBuf;

/// The vendor directory within the state root. The settings module uses the same name
/// under its own root.
const DIRECTORY: &str = "zond";

/// The subdirectory holding one journal per scan.
///
/// Named so the state root can take other neighbours later, a fingerprint submission
/// queue say. `journals` matches the `Journal` type.
const JOURNALS: &str = "journals";

/// Who invoked a process that is now running elevated.
///
/// Carried whole because a caller that uses the home directory must apply the
/// ownership too: a journal left owned by root in somebody's home is one they cannot
/// prune.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokingUser {
    /// The uid to give the journal.
    pub uid: u32,
    /// The gid to give the journal.
    pub gid: u32,
    /// That user's home directory, as the password database records it.
    pub home: PathBuf,
}

impl InvokingUser {
    /// The user `uid` in group `gid`, whose home is `home`.
    pub fn new(uid: u32, gid: u32, home: PathBuf) -> Self {
        Self { uid, gid, home }
    }
}

/// The root directory holding one subdirectory per scan.
///
/// `None` when the environment names no home at all, as in a container or a daemon
/// with a cleared environment. A caller getting `None` should carry on without a journal
/// and not invent a location.
///
/// Under `sudo`, this is the invoking user's directory. See the module documentation.
pub fn root() -> Option<PathBuf> {
    state_root().map(|root| root.join(DIRECTORY).join(JOURNALS))
}

/// Where one scan's directory would be, given its id.
///
/// The id is joined as a single component and is expected to be one, a ULID as the
/// journal writes. Validating it is the job of whoever mints or parses the id.
pub fn scan(id: &str) -> Option<PathBuf> {
    root().map(|root| root.join(id))
}

/// The state root this crate's directory sits under, before `zond/` is joined.
///
/// Windows needs no `sudo` handling: an elevated process keeps the invoking user's profile,
/// so `%LOCALAPPDATA%` already points at the right place.
///
/// Two whole `cfg` functions, because one function with two `cfg` blocks needs a `return`
/// that clippy flags on the platform where the second block is compiled out.
#[cfg(windows)]
fn state_root() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

/// Where journals live on this platform, by the XDG state specification.
#[cfg(not(windows))]
fn state_root() -> Option<PathBuf> {
    base_directory("XDG_STATE_HOME", std::path::Path::new(".local/state"))
}

/// A per-user base directory by the XDG rule, for whoever this run is on behalf of:
/// `$variable` where it names an absolute path, else `fallback` under the invoking user's
/// home, else under this process's own.
///
/// Shared with the settings module (`XDG_CONFIG_HOME`, `.config`) so a settings file and a
/// journal agree under `sudo` about whose home a run belongs to.
#[cfg(not(windows))]
pub(crate) fn base_directory(variable: &str, fallback: &std::path::Path) -> Option<PathBuf> {
    // Only an absolute value counts, as the specification requires. A relative one
    // would resolve against wherever the process started.
    let absolute = |name| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|path: &PathBuf| path.is_absolute())
    };

    choose(
        absolute(variable),
        invoking_user().map(|user| user.home),
        absolute("HOME"),
        fallback,
    )
}

/// Picks a base directory from the three places it can come from.
///
/// Pure, so the precedence can be tested without touching the process environment,
/// which is shared with every other test.
///
/// The configured directory leads, including under `sudo`, where it survives only if
/// somebody preserved it. Honouring it makes an elevated run and an unelevated listing agree.
/// After that the invoking user comes before this process's own `HOME`, which under `sudo`
/// is root's.
#[cfg(not(windows))]
pub(crate) fn choose(
    configured: Option<PathBuf>,
    invoking_home: Option<PathBuf>,
    home: Option<PathBuf>,
    fallback: &std::path::Path,
) -> Option<PathBuf> {
    configured.or_else(|| invoking_home.or(home).map(|home| home.join(fallback)))
}

/// The user who invoked this process, when it is running elevated on their
/// behalf and they can be identified.
///
/// `None`, the ordinary case, when any of these holds:
///
/// - the process is not running as root;
/// - `SUDO_UID` is absent, unparseable, or names root itself;
/// - the password database has no entry for that uid, or the entry names no home or a
///   relative one.
///
/// ## Trusting `SUDO_UID`
///
/// `sudo` sets it after clearing the environment, so it is `sudo`'s own value. It is used
/// only to narrow privilege: the worst a wrong value can do is put the journal in the wrong
/// user's home. The home comes from the password database, so a `SUDO_HOME` is ignored.
#[cfg(not(windows))]
pub fn invoking_user() -> Option<InvokingUser> {
    if !crate::system::privilege::is_elevated() {
        return None;
    }

    let uid: u32 = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    if uid == 0 {
        return None;
    }

    // `SUDO_GID` where `sudo` set it, else the primary group from the password
    // database.
    let entry = passwd_home_and_gid(uid)?;
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|gid| gid.parse().ok())
        .unwrap_or(entry.1);

    Some(InvokingUser {
        uid,
        gid,
        home: entry.0,
    })
}

/// Windows has no `sudo`: an elevated process keeps the invoking user's profile.
#[cfg(windows)]
pub fn invoking_user() -> Option<InvokingUser> {
    None
}

/// The home directory and primary gid the password database records for `uid`.
///
/// The one impure function in this module; see the module documentation.
#[cfg(not(windows))]
fn passwd_home_and_gid(uid: u32) -> Option<(PathBuf, u32)> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    /// Initial buffer size. `sysconf(_SC_GETPW_R_SIZE_MAX)` returns -1 on some
    /// platforms, so the buffer has to grow anyway.
    const INITIAL: usize = 1024;
    /// Where growing stops. An entry past this is a corrupt database.
    const MAX: usize = 64 * 1024;

    let mut buffer = vec![0 as libc::c_char; INITIAL];

    loop {
        // SAFETY: `passwd` is a plain C struct with no invalid bit patterns, so
        // a zeroed one is a valid uninitialised value for `getpwuid_r` to fill.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();

        // SAFETY: `entry` and `found` are live for the call, and `buffer` is a live
        // allocation of exactly the length passed. `getpwuid_r` writes only within them and
        // returns `ERANGE` when the buffer is too small.
        let code = unsafe {
            libc::getpwuid_r(
                uid as libc::uid_t,
                &mut entry,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut found,
            )
        };

        match code {
            0 if found.is_null() => return None, // No such user.
            0 => {
                if entry.pw_dir.is_null() {
                    return None;
                }

                // SAFETY: `pw_dir` points into `buffer`, which is still live
                // here, and `getpwuid_r` leaves it NUL-terminated. The bytes are
                // copied into an owned `PathBuf` before `buffer` is dropped.
                let home = unsafe { CStr::from_ptr(entry.pw_dir) };
                let home = PathBuf::from(OsStr::from_bytes(home.to_bytes()));

                // A relative home is refused, as a relative `XDG_STATE_HOME` is above.
                return home.is_absolute().then_some((home, entry.pw_gid as u32));
            }
            libc::ERANGE if buffer.len() < MAX => buffer.resize(buffer.len() * 2, 0),
            _ => return None,
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

    /// The journal lands under one vendor directory and one subdirectory.
    #[test]
    fn the_root_ends_in_the_expected_directories() {
        if let Some(path) = root() {
            assert!(path.is_absolute(), "{path:?}");
            assert!(
                path.ends_with(format!("{DIRECTORY}/{JOURNALS}")),
                "{path:?}"
            );
        }
    }

    /// A scan directory is the root plus exactly one component.
    #[test]
    fn a_scan_directory_is_one_component_under_the_root() {
        let (Some(root), Some(scan)) = (root(), scan("01J8Z5Q7VN")) else {
            return;
        };

        assert_eq!(scan.parent(), Some(root.as_path()));
        assert!(scan.ends_with("01J8Z5Q7VN"), "{scan:?}");
    }

    /// Asking where the journal is creates no part of the path.
    #[test]
    fn computing_a_path_creates_nothing() {
        let existed = root().map(|path| path.exists());

        let _ = root();
        let _ = scan("01J8Z5Q7VN");
        let _ = invoking_user();

        assert_eq!(
            existed,
            root().map(|path| path.exists()),
            "asking where the journal is created it"
        );
    }

    /// The journal does not land beside the settings file.
    #[cfg(feature = "import-settings")]
    #[test]
    fn the_journal_is_not_in_the_configuration_directory() {
        let (Some(journal), Some(settings)) = (root(), crate::import::settings::paths::user())
        else {
            return;
        };

        let Some(settings) = settings.parent() else {
            return;
        };

        assert_ne!(journal, settings);
        assert!(
            !journal.starts_with(settings),
            "journal {journal:?} is inside the settings directory {settings:?}"
        );
    }

    /// An unprivileged process has no invoking user, whatever the environment says.
    #[cfg(not(windows))]
    #[test]
    fn an_unprivileged_process_has_no_invoking_user() {
        if crate::system::privilege::is_elevated() {
            return;
        }

        assert_eq!(invoking_user(), None);
    }

    /// A lookup that succeeds yields an absolute home, and a lookup for any uid answers
    /// without faulting.
    ///
    /// The absent case is asserted only as not panicking, since no uid can be assumed
    /// unassigned: `u32::MAX - 1` is `nobody` on macOS, with `/var/empty` for a home. That is
    /// also why [`invoking_user`] checks elevation and a non-root uid before trusting
    /// `SUDO_UID`.
    #[cfg(not(windows))]
    #[test]
    fn a_password_entry_resolves_to_an_absolute_home() {
        // SAFETY: `getuid` takes no arguments and dereferences nothing.
        let own = unsafe { libc::getuid() } as u32;

        for uid in [own, 0, u32::MAX - 1, u32::MAX] {
            if let Some((home, _)) = passwd_home_and_gid(uid) {
                assert!(home.is_absolute(), "uid {uid} resolved to {home:?}");
            }
        }
    }

    /// An elevated scan and an unelevated listing look in the same place.
    ///
    /// With `XDG_STATE_HOME` set, a `sudo` scan resolving the invoking user's home while an
    /// unprivileged listing resolves the variable would leave the listing finding no scans.
    #[cfg(not(windows))]
    #[test]
    fn a_configured_root_wins_however_the_scan_was_run() {
        let configured = PathBuf::from("/state");
        let user = PathBuf::from("/home/user");
        let root = PathBuf::from("/root");
        let choose = |configured, invoking, home| {
            choose(
                configured,
                invoking,
                home,
                std::path::Path::new(".local/state"),
            )
        };

        // Under `sudo -E`, where the variable survived: both agree.
        assert_eq!(
            choose(Some(configured.clone()), Some(user.clone()), Some(root)),
            choose(Some(configured.clone()), None, Some(user.clone())),
            "an elevated run and an unelevated one disagreed"
        );

        // Under plain `sudo`, where it did not: the invoking user, not root.
        assert_eq!(
            choose(None, Some(user.clone()), Some(PathBuf::from("/root"))),
            Some(user.join(".local").join("state")),
            "a journal was written to root's home"
        );

        // And with nothing elevated, this process's own home.
        assert_eq!(
            choose(None, None, Some(user.clone())),
            Some(user.join(".local").join("state"))
        );
    }

    /// An environment naming nowhere yields `None`.
    #[cfg(not(windows))]
    #[test]
    fn an_empty_environment_names_no_root() {
        assert_eq!(
            choose(None, None, None, std::path::Path::new(".local/state")),
            None
        );
    }
}
