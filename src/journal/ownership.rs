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
//! under `~/.local/state`. Whatever it creates there is root's unless it is
//! given back, and a directory left to root in somebody's home breaks more than
//! this crate: `~/.local/state` owned by root is one no other program of theirs
//! can keep its state in.
//!
//! So creating is split from giving. [`create_missing`] makes a path the way
//! `create_dir_all` does and says which directories it made, since only those
//! are this run's to give: a directory that was already there belongs to
//! whoever made it. The caller then gives what it made.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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
}
