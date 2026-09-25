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
//! whoever made it. The caller then gives what it made, and [`give`] refuses
//! anything outside the invoking user's home, so a path an administrator named,
//! `/etc/zond` say, stays root's however it was created.
//!
//! Compiled for either of the two things that create there, the journal and
//! the settings files, neither of which needs the other. Only the settings
//! files give through [`give`]: the journal's own directories are claimed
//! whatever their location, for the reasons `store::prepare_root` gives.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(all(unix, feature = "import-settings"))]
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

/// Gives something this run created to the user who invoked it, when it lies
/// in that user's home.
///
/// Best effort. Something left to root is worth trying to avoid and not worth
/// failing a run over, and an unelevated run has nobody to give it to.
#[cfg(all(unix, feature = "import-settings"))]
pub(crate) fn give(path: &Path) {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let invoking = super::paths::invoking_user();
    let Some((uid, gid)) = owner_for(invoking.as_ref(), path) else {
        return;
    };

    // Through a handle rather than by name, refusing a link in the last
    // position, so the name cannot be repointed between the check above and
    // the change of owner.
    let Ok(opened) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    else {
        return;
    };

    // SAFETY: the descriptor is owned by `opened` and open for the call, and
    // `fchown` reads it and nothing else.
    unsafe {
        libc::fchown(opened.as_raw_fd(), uid, gid);
    }
}

/// The platforms with no `sudo`, where what a run creates is already the
/// invoking user's.
#[cfg(all(not(unix), feature = "import-settings"))]
pub(crate) fn give(_path: &Path) {}

/// Who `path` should be given to: the invoking user, when there is one and
/// the path lies strictly inside their home.
///
/// Strictly inside, because the home itself is theirs already and was not
/// this run's to create. A path that climbs out with `..` is refused rather
/// than resolved, since what it reaches is not decided by how it is spelled.
#[cfg(all(unix, feature = "import-settings"))]
fn owner_for(invoking: Option<&InvokingUser>, path: &Path) -> Option<(u32, u32)> {
    let user = invoking?;

    let climbs = path
        .components()
        .any(|part| part == std::path::Component::ParentDir);

    (!climbs && path != user.home && path.starts_with(&user.home)).then_some((user.uid, user.gid))
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
    #[cfg(all(unix, feature = "import-settings"))]
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
}
