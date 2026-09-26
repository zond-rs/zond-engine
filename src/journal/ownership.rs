// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Creating things in the invoking user's home
//!
//! An elevated run writes into the home of the user who invoked it: journals
//! under `~/.local/state`, a first settings file under `~/.config`. Whatever it
//! creates there is root's unless it is given back, and a directory left to
//! root in somebody's home breaks more than this crate: `~/.local/state` owned
//! by root is one no other program of theirs can keep its state in.
//!
//! So creating is split from giving. [`create_missing`] makes a path the way
//! `create_dir_all` does and says which directories it made, since only those
//! are this run's to give: a directory that was already there belongs to
//! whoever made it. The caller then gives what it made.
//!
//! ## One boundary: the invoking user's home
//!
//! Everything given here, a journal's files and directories and the settings
//! files alike, goes to the invoking user only when it lies strictly inside
//! their home. A path outside it is one somebody with root chose: an
//! administrator's `/etc/zond`, or a state or configuration root kept through
//! `sudo` on purpose, which may be shared, or sit in a directory the user
//! should not come to own a piece of. Root keeps what it makes there, as it
//! would for any other program, and the user's own runs are refused there
//! until somebody with root decides otherwise. Two rules, one per writer,
//! would hand the same user a journal directory outside their home and refuse
//! them a settings directory beside it.
//!
//! Compiled for either of the two things that create there, the journal and
//! the settings files, neither of which needs the other.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use super::paths::InvokingUser;

/// Creates `path` and every directory missing above it, and returns the ones
/// this call created, outermost first.
///
/// On Unix each is created with `mode` where one is given, and with the
/// process's default otherwise, as `create_dir_all` would.
///
/// A directory another process creates between the check and the creation is
/// not reported, since it is not this call's. A link standing where a
/// directory is expected counts as the directory, as it does for
/// `create_dir_all`: a home whose `~/.local` is a link elsewhere is a home
/// somebody arranged.
pub(crate) fn create_missing(path: &Path, mode: Option<u32>) -> io::Result<Vec<PathBuf>> {
    let mut missing = Vec::new();
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::NotFound => missing.push(ancestor),
            Err(e) => return Err(e),
        }
    }

    let mut created = Vec::new();
    for directory in missing.into_iter().rev() {
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            if let Some(mode) = mode {
                builder.mode(mode);
            }
            builder
        };
        #[cfg(not(unix))]
        let builder = {
            let _ = mode;
            fs::DirBuilder::new()
        };

        match builder.create(directory) {
            Ok(()) => created.push(directory.to_path_buf()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }

    // What `create_dir_all` would say about a path that exists and is not a
    // directory, or one a racing process left as something else.
    fs::create_dir_all(path)?;

    Ok(created)
}

/// The user an elevated run is on behalf of, or `None` when it is on nobody
/// else's.
///
/// Resolved once. Who invoked this process cannot change while it runs, and
/// the lookup goes to the password database, which a journal checkpointing
/// every three seconds has no reason to ask again.
#[cfg(unix)]
pub(crate) fn invoking() -> Option<&'static InvokingUser> {
    static INVOKING: std::sync::OnceLock<Option<InvokingUser>> = std::sync::OnceLock::new();
    INVOKING.get_or_init(super::paths::invoking_user).as_ref()
}

/// Gives something this run created to the user who invoked it, when it lies
/// in that user's home.
///
/// Best effort. Something left to root is worth trying to avoid and not worth
/// failing a run over, and an unelevated run has nobody to give it to.
#[cfg(unix)]
pub(crate) fn give(path: &Path) {
    use std::os::unix::io::AsRawFd;

    let Some(user) = invoking() else { return };
    let Ok(opened) = open_in_home(user, path) else {
        return;
    };

    // SAFETY: the descriptor is owned by `opened` and open for the call, and
    // `fchown` reads it and nothing else.
    unsafe {
        libc::fchown(opened.as_raw_fd(), user.uid, user.gid);
    }
}

/// [`give`], through a handle already open on `path`, so the name is not
/// looked up a second time between opening it and changing its owner.
#[cfg(all(unix, feature = "journal-format"))]
pub(crate) fn give_open(opened: &fs::File, path: &Path) {
    use std::os::unix::io::AsRawFd;

    let Some((uid, gid)) = owner_for(invoking(), path) else {
        return;
    };

    // SAFETY: the descriptor is owned by `opened` and open for the call, and
    // `fchown` reads it and nothing else.
    unsafe {
        libc::fchown(opened.as_raw_fd(), uid, gid);
    }
}

/// Opens what `path` names to change its owner, when it lies strictly inside
/// `user`'s home, without following a link the user could have planted on the
/// way.
///
/// Everything below the home is the user's to rearrange, so opening the path
/// by name would let them point it anywhere: `~/.config` made a link to `/etc`
/// turns `~/.config/zond` into `/etc/zond`, and a root process changing its
/// owner hands them the host-wide settings. So the path is resolved once, to
/// decide whether it lies in the home at all, which keeps a home whose
/// dotfiles link elsewhere inside it working; and the resolved path is then
/// walked from the home one name at a time, each opened relative to the last
/// and refusing a link, so a name repointed after the check fails the walk
/// rather than redirecting it.
#[cfg(unix)]
fn open_in_home(user: &InvokingUser, path: &Path) -> io::Result<fs::File> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let outside = || io::Error::other("outside the invoking user's home");
    if !inside_home(user, path) {
        return Err(outside());
    }
    let home = fs::canonicalize(&user.home)?;
    let resolved = fs::canonicalize(path)?;
    let below = resolved
        .strip_prefix(&home)
        .ok()
        .filter(|below| !below.as_os_str().is_empty())
        .ok_or_else(outside)?;

    let mut current = fs::File::open(&home)?;
    for component in below.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(outside());
        };
        let name = std::ffi::CString::new(name.as_bytes()).map_err(io::Error::other)?;
        // SAFETY: `current` is an open descriptor for the call and `name` a
        // NUL-terminated string that outlives it; the descriptor returned is
        // owned by the `File` built from it and by nothing else.
        let next = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `next` is a descriptor just opened and owned by nothing else.
        current = unsafe { fs::File::from_raw_fd(next) };
    }
    Ok(current)
}

/// The platforms with no `sudo`, where what a run creates is already the
/// invoking user's.
#[cfg(not(unix))]
pub(crate) fn give(_path: &Path) {}

/// [`give`]'s handle form, inert for the same reason.
#[cfg(all(not(unix), feature = "journal-format"))]
pub(crate) fn give_open(_opened: &fs::File, _path: &Path) {}

/// Who `path` should be given to: the invoking user, when there is one and
/// the path lies strictly inside their home.
///
/// Strictly inside, because the home itself is theirs already and was not
/// this run's to create. A path that climbs out with `..` is refused rather
/// than resolved, since what it reaches is not decided by how it is spelled.
#[cfg(all(unix, any(test, feature = "journal-format")))]
fn owner_for(invoking: Option<&InvokingUser>, path: &Path) -> Option<(u32, u32)> {
    let user = invoking?;
    inside_home(user, path).then_some((user.uid, user.gid))
}

/// Whether `path` lies strictly inside `user`'s home, spelled without `..`.
#[cfg(unix)]
pub(crate) fn inside_home(user: &InvokingUser, path: &Path) -> bool {
    let climbs = path
        .components()
        .any(|part| part == std::path::Component::ParentDir);

    !climbs && path != user.home && path.starts_with(&user.home)
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

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("zond-ownership-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch root");
        dir
    }

    /// Only what was made is reported, because only that is the run's to
    /// give; a directory already there is left to whoever made it.
    #[test]
    fn creating_reports_exactly_the_directories_it_made() {
        let home = scratch("create");
        fs::create_dir(home.join(".local")).expect("an existing directory");

        let target = home.join(".local/state/zond");
        let created = create_missing(&target, Some(0o700)).expect("creates");

        assert_eq!(
            created,
            [home.join(".local/state"), home.join(".local/state/zond")]
        );
        assert!(target.is_dir());

        // A second call has made nothing, and says so rather than failing.
        assert_eq!(
            create_missing(&target, None).expect("exists"),
            Vec::<PathBuf>::new()
        );

        // A file where the directory should be is refused, as by
        // `create_dir_all`.
        let file = home.join("file");
        fs::write(&file, b"").expect("writes");
        assert!(create_missing(&file, None).is_err());

        let _ = fs::remove_dir_all(&home);
    }

    /// What an elevated run creates goes to the user who invoked it only
    /// inside their home. A settings directory an administrator keeps, or one
    /// named past the home with `..`, stays root's.
    #[cfg(unix)]
    #[test]
    fn only_what_lies_inside_the_invoking_users_home_is_given_to_them() {
        let erik = InvokingUser {
            uid: 1000,
            gid: 1000,
            home: PathBuf::from("/home/erik"),
        };

        for inside in ["/home/erik/.local", "/home/erik/.config/zond/engine.toml"] {
            assert_eq!(
                owner_for(Some(&erik), Path::new(inside)),
                Some((1000, 1000)),
                "{inside}"
            );
        }
        for outside in [
            "/etc/zond",
            "/home/erik",
            "/home/erikb/.config",
            "/home/erik/../root/.config",
        ] {
            assert_eq!(
                owner_for(Some(&erik), Path::new(outside)),
                None,
                "{outside}"
            );
        }

        // Nothing elevated: nobody to give anything to.
        assert_eq!(owner_for(None, Path::new("/home/erik/.local")), None);
    }

    /// What is given is reached from the home without following a link the
    /// user could have planted: `~/.config` made a link to `/etc` would
    /// otherwise turn `~/.config/zond` into `/etc/zond`, and an elevated run
    /// would hand the user the host-wide settings. A link that stays inside
    /// the home, as a dotfiles checkout makes, still leads somewhere the
    /// user's own.
    #[cfg(unix)]
    #[test]
    fn nothing_is_reached_through_a_link_out_of_the_home() {
        let scratch = scratch("links");
        let home = scratch.join("home");
        let elsewhere = scratch.join("etc");
        fs::create_dir_all(elsewhere.join("zond")).expect("a directory outside");
        fs::create_dir_all(home.join("dotfiles/config/zond")).expect("a directory inside");
        std::os::unix::fs::symlink(&elsewhere, home.join(".config")).expect("links out");
        std::os::unix::fs::symlink(home.join("dotfiles/config"), home.join(".cfg"))
            .expect("links within");
        let user = InvokingUser {
            uid: 1000,
            gid: 1000,
            home: home.clone(),
        };

        assert!(open_in_home(&user, &home.join(".config/zond")).is_err());
        assert!(open_in_home(&user, &home.join(".cfg/zond")).is_ok());
        assert!(open_in_home(&user, &home.join("dotfiles/config/zond")).is_ok());
        assert!(
            open_in_home(&user, &home).is_err(),
            "the home is never given"
        );

        let _ = fs::remove_dir_all(&scratch);
    }
}
