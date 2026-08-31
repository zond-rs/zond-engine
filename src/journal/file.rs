// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Creating a file inside a journal
//!
//! Three things that must not be separated: the mode it is created with, who it
//! then belongs to, and that it is the file this crate meant rather than a link
//! standing where one should be.
//!
//! A journal holds the addresses an engagement was pointed at, so every file is
//! `0600` from creation rather than chmod'd after, and when the scan ran under
//! `sudo` it is given to the user who invoked it rather than left to root.
//! [`paths`](super::paths) explains why the journal goes to the invoking user's
//! home; this is the other half of that answer, without which it goes to their
//! home and stays unreadable to them.
//!
//! **They live together because separating them cost exactly that.** The cursor
//! had its own copy of the mode and none of the ownership, so a sweep run with
//! `sudo` left `cursor.json` owned by root beside a manifest and findings owned
//! by the user. An unprivileged listing could read the plan and not the
//! progress, and reported every scan as untouched.
//!
//! ## Why nothing here takes a path twice
//!
//! Giving the journal to the invoking user means the directory it sits in
//! belongs to them, and the names inside it are fixed. A root process opening
//! `cursor.json.tmp` by path, truncating it, and then chowning that path is a
//! root process doing both of those to whatever the user pointed the name at.
//! `O_NOFOLLOW` refuses a link where a journal file should be, and every
//! ownership change goes through the descriptor already open rather than
//! through the name, so there is no second lookup to redirect between them.
//!
//! Taking a lock is the one file this does not open. It has to appear at its
//! name already holding its record, or a racer reads a lock mid-creation and
//! finds it empty — see `lock::Lock::create_exclusively`, which stages the
//! content through [`create_private`] here and links it into place.
//!
//! Directories are opened the same way for the same reason.

use std::fs;
use std::path::Path;

/// Creates or truncates a file in a journal: private, and the invoking user's.
///
/// The mode is set as the file is created rather than after, so there is no
/// moment where what a scan is recording can be read by anyone else. The
/// directory is `0700` as well, which would cover it either way; this is the
/// belt to that pair of braces, and it costs one flag.
pub(super) fn create_private(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    private(&mut options);

    let file = options.open(path)?;
    claim(&file);
    Ok(file)
}

/// Opens an existing journal file to add to it, keeping what is already there.
///
/// [`create_private`] for the files written a record at a time. The mode is not
/// set, because the file exists and the one that created it set it.
pub(super) fn append_existing(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }

    options.open(path)
}

/// The mode and the refusal every journal file is opened under.
#[cfg(unix)]
fn private(options: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn private(_options: &mut fs::OpenOptions) {}

/// Gives a directory a journal created under `sudo` to the user who invoked it.
///
/// The file cases claim through the handle they already hold. A directory has
/// none, so one is opened for it, refusing a link in the same position for the
/// same reason.
#[cfg(unix)]
pub(super) fn claim_directory_for_invoking_user(path: &Path) {
    use std::os::unix::fs::OpenOptionsExt;

    let opened = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path);

    if let Ok(directory) = opened {
        claim(&directory);
    }
}

#[cfg(not(unix))]
pub(super) fn claim_directory_for_invoking_user(_path: &Path) {}

/// Gives something a journal wrote under `sudo` to the user who invoked it.
///
/// Best effort: a journal left owned by root is one they can neither read nor
/// prune, which is worth trying to avoid and not worth failing a scan over.
#[cfg(unix)]
fn claim(file: &fs::File) {
    use std::os::unix::io::AsRawFd;

    let Some(user) = super::paths::invoking_user() else {
        return;
    };

    // SAFETY: the descriptor is owned by `file` and open for the call, and
    // `fchown` reads it and nothing else. Taking the descriptor rather than the
    // path is what stops the name being repointed between the open and here.
    unsafe {
        libc::fchown(file.as_raw_fd(), user.uid, user.gid);
    }
}

#[cfg(not(unix))]
fn claim(_file: &fs::File) {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("zond-file-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    /// The journal lives in a directory this engine gives to the invoking user,
    /// under fixed names, and is written by a process that is usually root. A
    /// link standing where a journal file should be is the one thing that turns
    /// that arrangement into somebody else's file being truncated.
    #[test]
    fn a_link_where_a_journal_file_should_be_is_refused() {
        let dir = scratch("nofollow");
        let elsewhere = dir.join("elsewhere");
        fs::write(&elsewhere, b"not the journal's to touch").expect("writes");

        let planted = dir.join("cursor.json.tmp");
        std::os::unix::fs::symlink(&elsewhere, &planted).expect("links");

        for opened in [
            create_private(&planted).err(),
            append_existing(&planted).err(),
        ] {
            assert!(opened.is_some(), "a link was opened as a journal file");
        }

        assert_eq!(
            fs::read(&elsewhere).expect("reads"),
            b"not the journal's to touch",
            "the file behind the link was written through"
        );

        fs::remove_dir_all(&dir).ok();
    }

    /// And an ordinary file still opens, both ways.
    #[test]
    fn an_ordinary_journal_file_opens_and_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("ordinary");
        let path = dir.join("findings");

        create_private(&path)
            .expect("creates")
            .write_all(b"one")
            .expect("writes");
        append_existing(&path)
            .expect("appends")
            .write_all(b"two")
            .expect("writes");

        assert_eq!(fs::read(&path).expect("reads"), b"onetwo");
        assert_eq!(
            fs::metadata(&path).expect("stats").permissions().mode() & 0o777,
            0o600
        );

        fs::remove_dir_all(&dir).ok();
    }
}
