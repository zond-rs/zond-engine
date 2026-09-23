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
//! [`paths`](crate::journal::paths) explains why the journal goes to the
//! invoking user's home; this is the other half of that answer, without which
//! it goes to their home and stays unreadable to them.
//!
//! They live together because separating them costs exactly that. A cursor
//! writer with its own copy of the mode and none of the ownership would leave
//! `cursor.json` owned by root after a sweep run with `sudo`, beside a manifest
//! and findings owned by the user. An unprivileged listing would read the plan
//! and not the progress, and report every scan as untouched.
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
//! Taking a lock is the one file this does not open. It has to appear at its name
//! already holding its record, or a racer reads a lock mid-creation and finds it
//! empty. See `lock::Lock::create_exclusively`, which stages the content through
//! [`create_private`](crate::journal::file::create_private) here and links it
//! into place.
//!
//! Directories are opened the same way for the same reason.

use std::fs;
use std::path::Path;

/// Creates a file in a journal: private, the invoking user's, and new.
///
/// The mode is set as the file is created rather than after, so there is no
/// moment where what a scan is recording can be read by anyone else. The
/// directory is `0700` as well, which would cover it either way.
///
/// Create-only, which is what every caller means. Create *or truncate* would
/// mean a root process truncating and then chowning whatever the directory's
/// owner had put at the name. `O_NOFOLLOW` already refuses a symlink there, so
/// the residual case is a planted regular file: narrow, since the directory is
/// `0700` and the planter would be its owner, but narrow is not the same as
/// closed. `create_new` closes it: a name that already exists is refused rather
/// than emptied.
///
/// The two callers that stage through a temporary want a name that may be left
/// over from an interrupted run; they use [`create_staged`], which is this with
/// one deliberate retry.
pub(super) fn create_private(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    private(&mut options);

    let file = options.open(path)?;
    claim(&file);
    Ok(file)
}

/// Creates a staging file, discarding one an interrupted run left behind.
///
/// [`create_private`] refuses a name that exists, which is right for the files
/// a journal creates once and wrong for the two it re-creates every time it
/// writes atomically: `cursor.json.tmp` on every checkpoint, `hosts.jsonl-tmp`
/// on every compaction. Both are renamed away on success, so a leftover means a
/// previous run died between the create and the rename, and refusing forever
/// after that would wedge the journal, trading the defect `create_new` closes
/// for a failure of its own.
///
/// The removal is safe in the way truncation is not. `remove_file` unlinks
/// the name, so a symlink planted there loses the link rather than the target,
/// and the retry is still `create_new` under `O_NOFOLLOW`: if something wins the
/// race and plants a file between the two calls, this fails rather than opening
/// it. A refused checkpoint is a cost; a truncated stranger is a defect.
pub(super) fn create_staged(path: &Path) -> std::io::Result<fs::File> {
    match create_private(path) {
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(path)?;
            create_private(path)
        }
        other => other,
    }
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

/// Opens an existing journal file for reading and writing, to inspect and mend
/// it before anything is added to it.
///
/// [`append_existing`] can only add to the end, which is what makes it cheap and
/// what makes it blind: an append-only descriptor cannot see whether the file
/// carries a header or whether its last line ever finished. `store`'s
/// `open_for_append` asks both questions through this handle first.
///
/// Neither creates and neither truncates, so a name that is not there is still
/// an error and what is in the file is still whatever was written. The mode is
/// not set for the same reason [`append_existing`] does not set it: the file
/// exists, and the call that created it set it.
pub(super) fn open_existing(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }

    options.open(path)
}

/// Opens a journal's rendezvous file, creating it if it is not there yet.
///
/// The one shape neither [`create_private`] nor [`create_staged`] fits: a file
/// every racer must be able to *open*, where creating it is incidental and
/// winning the create decides nothing. `journal::lock`'s `break` file is the
/// only one: the lock taken on it lives on the open file, so what matters is
/// that every process ends up on the same one.
///
/// No truncate, because there is nothing in it to empty and a truncate would be
/// one more thing a racer could do to a file another racer holds. The mode and
/// `O_NOFOLLOW` are the same as everywhere else here.
pub(super) fn open_or_create_private(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    private(&mut options);

    let file = options.open(path)?;
    claim(&file);
    Ok(file)
}

/// The mode and the refusal every journal file is opened under.
#[cfg(unix)]
fn private(options: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
}

/// The platforms with no mode to set at open. Nothing is promised about who else
/// can read a journal there, which is one of the reasons the crate does not claim
/// to support them.
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

/// The platforms with no `sudo` to have been invoked through, where a journal is
/// already the invoking user's.
#[cfg(not(unix))]
pub(super) fn claim_directory_for_invoking_user(_path: &Path) {}

/// Gives something a journal wrote under `sudo` to the user who invoked it.
///
/// Best effort: a journal left owned by root is one they can neither read nor
/// prune, which is worth trying to avoid and not worth failing a scan over.
#[cfg(unix)]
fn claim(file: &fs::File) {
    use std::os::unix::io::AsRawFd;
    use std::sync::OnceLock;

    /// Resolved once. Who invoked this process cannot change while it runs, and
    /// the lookup goes to the password database, which a checkpoint every three
    /// seconds has no reason to ask again.
    static INVOKING: OnceLock<Option<super::paths::InvokingUser>> = OnceLock::new();

    let Some(user) = INVOKING.get_or_init(super::paths::invoking_user) else {
        return;
    };

    // SAFETY: the descriptor is owned by `file` and open for the call, and
    // `fchown` reads it and nothing else. Taking the descriptor rather than the
    // path is what stops the name being repointed between the open and here.
    unsafe {
        libc::fchown(file.as_raw_fd(), user.uid, user.gid);
    }
}

/// [`claim_directory_for_invoking_user`]'s file half, and inert for the same
/// reason.
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

    /// `O_NOFOLLOW` covers a link planted at a journal's name; it says nothing
    /// about an ordinary file planted there. Opened with truncation, that one
    /// would be emptied and then chowned to the invoking user by a process that
    /// is usually root.
    #[test]
    fn a_file_already_at_a_journal_name_is_refused_rather_than_emptied() {
        let dir = scratch("create-only");
        let planted = dir.join("manifest.json");
        fs::write(&planted, b"somebody else's bytes").expect("writes");

        let refusal = create_private(&planted).expect_err("a name that exists was created over");
        assert_eq!(refusal.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(&planted).expect("reads"),
            b"somebody else's bytes",
            "the planted file was truncated"
        );

        fs::remove_dir_all(&dir).ok();
    }

    /// And the staging names, which a crashed run does leave behind, are the
    /// one place that refusal has to lift, or a journal wedges for good.
    #[test]
    fn a_staged_name_left_by_a_crashed_run_is_discarded_rather_than_wedging() {
        let dir = scratch("staged");
        let temporary = dir.join("cursor.json.tmp");
        fs::write(&temporary, b"a checkpoint that never got renamed").expect("writes");

        create_staged(&temporary)
            .expect("a leftover staging file is discarded")
            .write_all(b"the next one")
            .expect("writes");

        assert_eq!(fs::read(&temporary).expect("reads"), b"the next one");

        // And it is still a link that cannot be followed: the removal unlinks the
        // name, and the create behind it is the same refusing one.
        let elsewhere = dir.join("elsewhere");
        fs::write(&elsewhere, b"not the journal's to touch").expect("writes");
        let linked = dir.join("hosts.jsonl-tmp");
        std::os::unix::fs::symlink(&elsewhere, &linked).expect("links");

        create_staged(&linked).expect("the link is unlinked and a real file created");
        assert_eq!(
            fs::read(&elsewhere).expect("reads"),
            b"not the journal's to touch",
            "the file behind the link was written through"
        );

        fs::remove_dir_all(&dir).ok();
    }
}
