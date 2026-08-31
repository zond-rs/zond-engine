// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Where a scan's journal lives
//!
//! The sibling of `import::settings::paths`, which sits behind the
//! `import-settings` feature and so is not linked here, and not the same
//! directory.
//!
//! ## State is not configuration
//!
//! A settings file is hand-written: somebody opens it, edits it, and expects to
//! find it where every other command-line tool keeps one. That is the whole
//! argument the settings module makes for putting it under `~/.config` even on
//! macOS, where the platform convention says otherwise.
//!
//! That argument inverts here. Nobody hand-edits a checkpoint bitmap. A journal
//! is machine-written, machine-read, disposable once a scan completes, and of no
//! interest to a person except through whatever lists them. The specification has
//! a directory for that, and it is not the configuration one.
//!
//! | | Journal root |
//! |---|---|
//! | Unix (incl. macOS) | `$XDG_STATE_HOME/zond/journals`, else `$HOME/.local/state/zond/journals` |
//! | Windows | `%LOCALAPPDATA%\zond\journals` |
//!
//! `%LOCALAPPDATA%` rather than the `%APPDATA%` the settings module uses.
//! `%APPDATA%` roams between machines on a domain profile, and a journal holds
//! the addresses an engagement was pointed at, so carrying those to another
//! workstation is a data-handling incident rather than a convenience.
//!
//! ## `sudo` is the case this module exists for
//!
//! Every raw strategy needs root, so most scans are run under `sudo`, where
//! `$HOME` is root's. Left alone, journals would be written to
//! `/root/.local/state/zond/journals`, while anything that lists them needs no
//! privilege, is not normally run under `sudo`, and reads the invoking user's
//! directory to find nothing there.
//!
//! So when this process is running elevated and the environment names the user
//! who invoked it, [`root`] resolves that user's home rather than root's and
//! [`invoking_user`] reports the ownership a caller should write with. The caller
//! does the `chown`; this module says who.
//!
//! ## What is pure and what is not
//!
//! Every function here is pure computation over the environment, with one
//! exception: [`invoking_user`] consults the password database to turn a uid into
//! a home directory. That is a lookup rather than a filesystem traversal, opening
//! no path, testing none for existence and creating nothing, which are the
//! properties the settings module's purity rule protects. Constructing
//! `/home/<name>` by hand would be pure and wrong, since it is not where macOS
//! puts homes nor where a directory-service or relocated home lives on either
//! platform.
//!
//! Nothing here creates a directory. A caller that means to write asks
//! [`root`] where, and creates it with the modes the journal requires.

use std::path::PathBuf;

/// The directory this crate's state lives under, within whatever state root
/// applies. Shared with the settings module by name and not by location: one
/// vendor directory, two roots, so `zond/` means the same thing in both.
const DIRECTORY: &str = "zond";

/// The subdirectory holding one journal per scan.
///
/// Named rather than implied, since the state root will acquire neighbours, a
/// fingerprint submission queue being the obvious next one, and
/// journals that had claimed the root would have to move when it did.
///
/// `journals` rather than `scans`, so that everything from this module to
/// whatever a front end calls its subcommand uses one word for one thing. A
/// directory of `scans` beside a `Journal` type invites the reader to wonder
/// what the difference is.
const JOURNALS: &str = "journals";

/// Who invoked a process that is now running elevated.
///
/// Returned by [`invoking_user`], and carried whole rather than as three loose
/// values because a caller that uses the home directory has to apply the
/// ownership too. A journal written into somebody's home and left owned by root
/// is a directory they cannot prune, which is worse than not having written it
/// there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokingUser {
    /// The uid to give the journal.
    pub uid: u32,
    /// The gid to give the journal.
    pub gid: u32,
    /// That user's home directory, as the password database records it.
    pub home: PathBuf,
}

/// The root directory holding one subdirectory per scan.
///
/// `None` when the environment names no home at all, which happens in a container
/// or a daemon with a cleared environment. A caller getting `None` should carry on
/// without a journal rather than invent a location. A scan that cannot be resumed
/// is a smaller failure than a scan that writes an
/// engagement's targets somewhere nobody chose.
///
/// Under `sudo`, this is the *invoking* user's directory. See the module
/// documentation.
pub fn root() -> Option<PathBuf> {
    state_root().map(|root| root.join(DIRECTORY).join(JOURNALS))
}

/// Where one scan's directory would be, given its id.
///
/// The id is joined as a single component and is expected to be one, a ULID as
/// the journal writes. Validating that belongs to the caller that mints or parses
/// an id rather than to a path.
pub fn scan(id: &str) -> Option<PathBuf> {
    root().map(|root| root.join(id))
}

/// The state root this crate's directory sits under, before `zond/` is joined.
///
/// Split out from [`root`] so the platform rules and the `sudo` rule are one
/// expression each rather than one nested expression.
/// No `sudo` equivalent to work around: an elevated process on Windows keeps the
/// invoking user's profile, so `%LOCALAPPDATA%` already points where the Unix
/// arm has to go looking to arrive.
///
/// Two whole functions rather than one with two `cfg` blocks inside it. The block
/// form needs a `return` in the first arm to skip the second, and on the platform
/// where the second does not exist that `return` is the function's last
/// expression, which is a clippy warning nobody sees until the day
/// somebody lints for that platform.
#[cfg(windows)]
fn state_root() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

#[cfg(not(windows))]
fn state_root() -> Option<PathBuf> {
    // Only an absolute value counts, as the specification requires. A relative
    // one would put the journal wherever the process started, which for a tool
    // run with `sudo` from an arbitrary shell is not a location anybody
    // chose.
    let absolute = |name| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|path: &PathBuf| path.is_absolute())
    };

    choose(
        absolute("XDG_STATE_HOME"),
        invoking_user().map(|user| user.home),
        absolute("HOME"),
    )
}

/// Picks the state root from the three places it can come from.
///
/// Pure, so the precedence can be tested without a process's environment, which
/// is shared and which a test cannot change without changing it for every other
/// test running beside it.
///
/// `XDG_STATE_HOME` leads, including under `sudo`. It reaches an elevated process
/// only if somebody preserved it deliberately, and honouring it is what makes an
/// elevated scan and an unelevated listing agree. Reading the invoking user first
/// meant a scan run with `sudo` wrote under `~/.local/state` while a
/// listing read `$XDG_STATE_HOME`, and the listing reported no scans at all.
///
/// After that the invoking user comes before this process's own `HOME`, which
/// under `sudo` is root's and is not who asked.
#[cfg(not(windows))]
fn choose(
    configured: Option<PathBuf>,
    invoking_home: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Option<PathBuf> {
    configured.or_else(|| {
        invoking_home
            .or(home)
            .map(|home| home.join(".local").join("state"))
    })
}

/// The user who invoked this process, when it is running elevated on their
/// behalf and they can be identified.
///
/// `None`, which is the ordinary case, when any of the following holds. Each is a
/// reason to use this process's own environment instead:
///
/// - the process is not running as root, so nothing was elevated;
/// - `SUDO_UID` is absent, unparseable, or names root itself, so either this is
///   not a `sudo` invocation or root invoked it directly;
/// - the password database has no entry for that uid, or the entry names no
///   home directory, or names a relative one.
///
/// ## On trusting `SUDO_UID`
///
/// `sudo` sets it after clearing the environment, so under the invocation this is
/// written for it is `sudo`'s own value rather than the caller's. It is consulted
/// only to narrow privilege: the worst a wrong value can do is put the journal in
/// the wrong user's home, never widen what the scan may do. The home directory
/// comes from the password database rather than the environment, so a `SUDO_HOME`
/// pointing anywhere is not consulted.
#[cfg(not(windows))]
pub fn invoking_user() -> Option<InvokingUser> {
    if !crate::system::privilege::is_elevated() {
        return None;
    }

    let uid: u32 = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    if uid == 0 {
        return None;
    }

    // The gid is read from the environment where `sudo` set it, falling back to
    // the password database: a user whose primary group `sudo` did not record is
    // still a user whose home this is.
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

/// Windows has no `sudo`: an elevated process keeps the invoking user's
/// profile, so there is never a different user to resolve.
#[cfg(windows)]
pub fn invoking_user() -> Option<InvokingUser> {
    None
}

/// The home directory and primary gid the password database records for `uid`.
///
/// The one impure function in this module; see the module documentation for why
/// the alternative is worse.
#[cfg(not(windows))]
fn passwd_home_and_gid(uid: u32) -> Option<(PathBuf, u32)> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    /// Where the buffer starts. `sysconf(_SC_GETPW_R_SIZE_MAX)` is the blessed
    /// way to ask, and it returns -1 on platforms that decline to answer, so a
    /// growing buffer is needed regardless and asking first buys nothing.
    const INITIAL: usize = 1024;
    /// Where growing stops. A password entry past this is not a long home
    /// directory, it is a corrupt database, and doubling forever to read one is
    /// how a lookup becomes an allocation failure.
    const MAX: usize = 64 * 1024;

    let mut buffer = vec![0 as libc::c_char; INITIAL];

    loop {
        // SAFETY: `passwd` is a plain C struct with no invalid bit patterns, so
        // a zeroed one is a valid uninitialised value for `getpwuid_r` to fill.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();

        // SAFETY: `entry` and `found` are live for the call, and `buffer` is a
        // live allocation of exactly the length passed. `getpwuid_r` writes only
        // within them and returns an error rather than writing past the buffer.
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

                // A relative home is not one this can join a journal onto, for
                // the same reason a relative `XDG_STATE_HOME` is refused above.
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

    /// Whatever root applies, the journal lands under one vendor directory and
    /// one subdirectory, so a front end and a user can both predict it.
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

    /// A scan directory is the root plus exactly one component, so an id never
    /// silently becomes two.
    #[test]
    fn a_scan_directory_is_one_component_under_the_root() {
        let (Some(root), Some(scan)) = (root(), scan("01J8Z5Q7VN")) else {
            return;
        };

        assert_eq!(scan.parent(), Some(root.as_path()));
        assert!(scan.ends_with("01J8Z5Q7VN"), "{scan:?}");
    }

    /// Asking where the journal is must not create it, or any part of the path
    /// to it. A caller asking has not asked for a side effect, and this is the
    /// module a caller reaches through to report where it *would* write.
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

    /// The journal must not land beside the settings file. They have different
    /// lifetimes, different audiences and different sensitivity, and the whole
    /// reason this module exists is that the settings module's location
    /// argument does not apply to state.
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

    /// An unprivileged process has nobody to resolve: `sudo` handling must never
    /// engage for a scan that was not elevated, whatever the environment says.
    #[cfg(not(windows))]
    #[test]
    fn an_unprivileged_process_has_no_invoking_user() {
        if crate::system::privilege::is_elevated() {
            return;
        }

        assert_eq!(invoking_user(), None);
    }

    /// A lookup that succeeds yields an absolute home, and a lookup for any uid
    /// at all answers rather than faulting.
    ///
    /// The absent case is asserted as not panicking rather than as `None`, since
    /// there is no uid a test may assume is unassigned. `u32::MAX - 1` looked
    /// like one and is `nobody` on macOS, with `/var/empty` for a home. That is
    /// also why [`invoking_user`] guards on elevation and on a non-root uid
    /// before trusting `SUDO_UID`: a stray value that resolves resolves to
    /// somewhere real.
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

    /// An elevated scan and an unelevated listing must look in the same place.
    ///
    /// The bug this guards: with `XDG_STATE_HOME` set, `sudo zond scan` resolved
    /// the invoking user's home while `zond journal` resolved the variable, so
    /// the second reported no scans at all.
    #[cfg(not(windows))]
    #[test]
    fn a_configured_root_wins_however_the_scan_was_run() {
        let configured = PathBuf::from("/state");
        let erik = PathBuf::from("/home/erik");
        let root = PathBuf::from("/root");

        // Under `sudo -E`, where the variable survived: both agree.
        assert_eq!(
            choose(Some(configured.clone()), Some(erik.clone()), Some(root)),
            choose(Some(configured.clone()), None, Some(erik.clone())),
            "an elevated run and an unelevated one disagreed"
        );

        // Under plain `sudo`, where it did not: the invoking user, never root.
        assert_eq!(
            choose(None, Some(erik.clone()), Some(PathBuf::from("/root"))),
            Some(erik.join(".local").join("state")),
            "a journal was written to root's home"
        );

        // And with nothing elevated, this process's own home.
        assert_eq!(
            choose(None, None, Some(erik.clone())),
            Some(erik.join(".local").join("state"))
        );
    }

    /// An environment naming nowhere yields nowhere, rather than a guess.
    #[cfg(not(windows))]
    #[test]
    fn an_empty_environment_names_no_root() {
        assert_eq!(choose(None, None, None), None);
    }
}
