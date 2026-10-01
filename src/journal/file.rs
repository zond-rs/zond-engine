// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Creating a file inside a journal
//!
//! Three things kept together: the mode a file is created with, who it then belongs to,
//! and that it is the file this crate meant and not a link standing at its name.
//!
//! A journal holds the addresses an engagement was pointed at, so every file is `0600` from
//! creation, and when the scan ran under `sudo` it is given to the user who invoked it.
//! [`paths`](crate::journal::paths) puts the journal in that user's home; this makes it
//! readable to them there. Split apart, a cursor writer that set the mode but not the owner
//! would leave `cursor.json` owned by root beside a manifest owned by the user, and an
//! unprivileged listing would report every scan as untouched.
//!
//! ## No path is looked up twice
//!
//! The journal's directory belongs to the invoking user and the names inside it are fixed.
//! A root process that opened `cursor.json.tmp` by path, truncated it and then chowned that
//! path would do both to whatever the user pointed the name at. `O_NOFOLLOW` refuses a link
//! at a journal file's name, and every ownership change goes through the open descriptor.
//!
//! The lock is the exception to opening a file in place: it has to appear at its name
//! already holding its record, or a racer finds it empty. `lock::Lock::create_exclusively`
//! stages the content through [`link_new`](crate::journal::file::link_new) and links it into
//! place.
//!
//! Directories and reads are opened the same way. A root process resuming a scan reads the
//! manifest, cursor and findings out of the user's directory, and a link at one of those
//! names would have it read whatever the user chose; see
//! [`open_to_read`](crate::journal::file::open_to_read).
//!
//! ## No link above the name is followed either
//!
//! Every name above the last is the invoking user's to place as well. Under `sudo` a
//! journal's files and directories are reached from that user's home without following a
//! link out of it; see [`ownership::Place`](crate::journal::ownership::Place), which also
//! explains why a link that stays inside the home still works. Renames, links and removals
//! go through the same walk: [`replace`](crate::journal::file::replace),
//! [`link_new`](crate::journal::file::link_new), [`remove`](crate::journal::file::remove)
//! and [`remove_directory`](crate::journal::file::remove_directory) are how a journal
//! changes a name, never by path.

use std::fs;
use std::path::Path;

use super::ownership::{Directory, Kind, Place};

/// Creates a file in a journal: private, the invoking user's, and new.
///
/// The mode is set at creation, so there is no moment when the file is readable by
/// anyone else.
///
/// Create-only: a name that already exists is refused. Create-or-truncate would have a root
/// process empty and then chown whatever the directory's owner had planted at the name;
/// `O_NOFOLLOW` covers a symlink but not a planted regular file.
///
/// Files written whole through a staged sibling may find a name left over from an
/// interrupted run; [`replace`] and [`link_new`] stage them with one retry.
pub(super) fn create_private(path: &Path) -> std::io::Result<fs::File> {
    create_in(&Place::of(path)?, path)
}

/// [`create_private`] at a name already reached; `path` is what it is called.
fn create_in(place: &Place, path: &Path) -> std::io::Result<fs::File> {
    let file = open_in(place, path, Access::CreateNew)?;
    claim(&file, path);
    Ok(file)
}

/// Creates a staging file, discarding one an interrupted run left behind.
///
/// [`create_private`] refuses a name that exists, which is wrong for the files a
/// journal re-creates on every whole write: `cursor.json.tmp` on every checkpoint,
/// `hosts.jsonl-tmp` on every compaction. A leftover means a previous run died between the
/// create and the rename, and refusing it would wedge the journal.
///
/// Removing it is safe where truncation is not: unlinking a planted symlink removes the
/// link, not its target, and the retry is still `create_new` under `O_NOFOLLOW`, so a file
/// planted between the two calls makes this fail without opening it.
fn stage(place: &Place, path: &Path) -> std::io::Result<fs::File> {
    match create_in(place, path) {
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            place.remove()?;
            create_in(place, path)
        }
        other => other,
    }
}

/// Writes a journal file whole: `write` fills a file staged at `staged`, which is
/// then renamed over `destination`, so the name holds either all of the old contents or all
/// of the new.
///
/// `staged` lies in the same directory as `destination` and both are reached through one
/// walk; see [`Place::beside`]. The staged file is closed before the rename (`write` takes
/// it), since renaming over an open file is a hazard on some platforms. The destination
/// becomes the staged inode, which already has the mode and owner [`create_private`] gives.
///
/// A failed write or rename removes what it staged.
pub(super) fn replace<T, E: From<std::io::Error>>(
    destination: &Path,
    staged: &Path,
    write: impl FnOnce(fs::File) -> Result<T, E>,
) -> Result<T, E> {
    replace_at(&Place::of(destination)?, destination, staged, write)
}

/// [`replace`] at a destination already reached.
fn replace_at<T, E: From<std::io::Error>>(
    target: &Place,
    destination: &Path,
    staged: &Path,
    write: impl FnOnce(fs::File) -> Result<T, E>,
) -> Result<T, E> {
    let staging = target.beside(sibling(destination, staged)?)?;
    let file = stage(&staging, staged)?;
    let replaced = write(file).and_then(|written| {
        staging.rename_over(target)?;
        Ok(written)
    });
    if replaced.is_err() {
        let _ = staging.remove();
    }
    replaced
}

/// Puts a file at `destination` holding what `write` wrote, refusing a name that
/// exists there.
///
/// For a file that must appear at its name already whole, where a reader must never find it
/// empty: the lock. Staged as [`replace`] stages, then linked into place, since a link
/// refuses an existing name the way `create_new` does. The staged name is removed either
/// way.
pub(super) fn link_new(
    destination: &Path,
    staged: &Path,
    write: impl FnOnce(fs::File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    link_new_at(&Place::of(destination)?, destination, staged, write)
}

/// [`link_new`] at a destination already reached.
fn link_new_at(
    target: &Place,
    destination: &Path,
    staged: &Path,
    write: impl FnOnce(fs::File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let staging = target.beside(sibling(destination, staged)?)?;
    let file = stage(&staging, staged)?;
    let linked = write(file).and_then(|()| staging.link_as(target));
    let _ = staging.remove();
    linked
}

/// `staged`'s name, where it lies beside `destination`.
fn sibling<'a>(destination: &Path, staged: &'a Path) -> std::io::Result<&'a std::ffi::OsStr> {
    debug_assert_eq!(
        destination.parent(),
        staged.parent(),
        "a file is staged beside its destination"
    );
    staged.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} names no file", staged.display()),
        )
    })
}

/// Opens an existing journal file to add to it, keeping what is already there.
///
/// For the files written a record at a time. The mode is not set: whoever created
/// the file set it.
pub(super) fn append_existing(path: &Path) -> std::io::Result<fs::File> {
    open(path, Access::Append)
}

/// Opens an existing journal file for reading and writing, to inspect and mend it
/// before anything is added.
///
/// An append-only descriptor cannot see whether the file has a header or whether its last
/// line finished; `store`'s `open_for_append` checks both through this handle first. Neither
/// creates nor truncates, and the mode is not set.
pub(super) fn open_existing(path: &Path) -> std::io::Result<fs::File> {
    open(path, Access::ReadWrite)
}

/// Opens a journal's rendezvous file, creating it if it is not there yet.
///
/// For a file every racer must be able to open, where winning the create decides nothing:
/// `journal::lock`'s `break` file, whose lock lives on the open file. No truncate, since
/// that would be one more thing a racer could do to a file another holds. Same mode and
/// `O_NOFOLLOW` as everywhere here.
pub(super) fn open_or_create_private(path: &Path) -> std::io::Result<fs::File> {
    let file = open(path, Access::CreateOrOpen)?;
    claim(&file, path);
    Ok(file)
}

/// Removes a journal file's name (a link at it, not what the link points to),
/// relative to the directory holding it, reached as every opener here reaches a name.
pub(super) fn remove(path: &Path) -> std::io::Result<()> {
    Place::of(path)?.remove()
}

/// Removes a journal's directory and everything in it, each name looked up
/// relative to the directory holding it; see [`Place::remove_tree`].
///
/// Under `sudo` the pruner is root in a directory the invoking user controls. By
/// path, a link placed above the journal between the decision and the removal would have
/// root remove whatever the link leads to.
pub(super) fn remove_directory(path: &Path) -> std::io::Result<()> {
    Place::of(path)?.remove_tree()
}

/// Creates one scan's directory, private from the moment it exists.
///
/// The mode is set at creation for the same reasons as the files inside it: no
/// window in which the addresses are world-readable, and no privileged `chmod` by path in a
/// directory just given to an unprivileged user.
///
/// Fails with [`AlreadyExists`](std::io::ErrorKind::AlreadyExists) if the directory exists,
/// so a colliding minted id is retried and two scans never share a journal.
#[cfg(unix)]
pub(super) fn create_private_directory(path: &Path) -> std::io::Result<()> {
    Place::of(path)?.create_directory(0o700)
}

/// Platforms with no mode to set at creation; nothing is promised about the
/// directory's permissions.
#[cfg(not(unix))]
pub(super) fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

/// Opens a journal file to read it, refusing a link standing at its name.
///
/// No opener here leaves a link at a journal's name, so one there makes the job
/// unreadable, and the error says a link is why. Read as damaged, the job would list as a
/// scan that found nothing; followed, a root process would read whatever the directory's
/// owner pointed it at as the job's own.
///
/// Under `sudo` a link above it that leads out of the invoking user's home is refused as
/// well.
pub(super) fn open_to_read(path: &Path) -> std::io::Result<fs::File> {
    open(path, Access::Read)
}

/// The names in the directory at `path`, reached as every opener here reaches a
/// name; see [`Directory`].
pub(super) fn names(path: &Path) -> std::io::Result<Vec<std::ffi::OsString>> {
    Directory::of(path)?.names()
}

/// The names in the directory at `path`, each with what stands at it (a link counts
/// as a link), looked up relative to that directory; see [`Directory`]. A name gone by the
/// time it is looked at is skipped.
pub(super) fn kinds(path: &Path) -> std::io::Result<Vec<(std::ffi::OsString, Kind)>> {
    let directory = Directory::of(path)?;
    Ok(directory
        .names()?
        .into_iter()
        .filter_map(|name| {
            let kind = directory.entry(&name).and_then(|entry| entry.kind()).ok()?;
            Some((name, kind))
        })
        .collect())
}

/// Whether anything stands at `path`, a link included, asked of the name itself and
/// reached as every opener here reaches a name. A missing directory above it counts as
/// nothing there.
pub(super) fn exists(path: &Path) -> std::io::Result<bool> {
    match Place::of(path) {
        Ok(place) => place.exists(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// The five ways a journal file is opened.
#[derive(Clone, Copy)]
enum Access {
    /// Created, and refused if the name exists.
    CreateNew,
    /// Created if missing, opened for reading and writing either way.
    CreateOrOpen,
    /// Opened to add to its end.
    Append,
    /// Opened for reading and writing.
    ReadWrite,
    /// Opened for reading.
    Read,
}

/// Opens a journal file private, refusing a link at its name, reached the way
/// [`Place`] reaches it.
fn open(path: &Path, how: Access) -> std::io::Result<fs::File> {
    open_in(&Place::of(path)?, path, how)
}

/// [`open`] at a name already reached; `path` is what it is called.
///
/// A link refused at the name is reported as one; the system's own error is a loop
/// of links, which sends the reader looking for a cycle that is not there.
#[cfg(unix)]
fn open_in(place: &Place, path: &Path, how: Access) -> std::io::Result<fs::File> {
    let flags = match how {
        Access::CreateNew => libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        Access::CreateOrOpen => libc::O_RDWR | libc::O_CREAT,
        Access::Append => libc::O_WRONLY | libc::O_APPEND,
        Access::ReadWrite => libc::O_RDWR,
        Access::Read => libc::O_RDONLY,
    };
    place.open(flags, 0o600).map_err(|error| {
        // Asked of the name itself, to tell a link at it from a loop further up, which
        // fails the same way.
        let linked = error.raw_os_error() == Some(libc::ELOOP)
            && place.kind().is_ok_and(|kind| kind == Kind::Link);
        if linked {
            std::io::Error::other(format!(
                "{} is a link, not a journal file (not followed)",
                path.display()
            ))
        } else {
            error
        }
    })
}

/// Platforms with no mode to set at open. Nothing is promised about who else can
/// read a journal there, one reason the crate does not claim to support them.
#[cfg(not(unix))]
fn open_in(place: &Place, _path: &Path, how: Access) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    match how {
        Access::CreateNew => options.write(true).create_new(true),
        Access::CreateOrOpen => options.read(true).write(true).create(true),
        Access::Append => options.append(true),
        Access::ReadWrite => options.read(true).write(true),
        Access::Read => options.read(true),
    };
    options.open(place.path())
}

/// Gives a directory a journal created under `sudo` to the user who invoked it, when
/// it lies in their home.
///
/// A directory has no handle to claim through, so one is opened for it, refusing a link at
/// the name. The boundary is shared with every other give; see
/// [`ownership`](super::ownership).
pub(super) fn claim_directory_for_invoking_user(path: &Path) {
    super::ownership::give(path);
}

/// Gives a file a journal wrote under `sudo` to the user who invoked it, when
/// it lies in their home.
///
/// Best effort: a journal left owned by root is one the user can neither read nor
/// prune, which is worth avoiding but not worth failing a scan over. Taking the descriptor
/// stops the name being repointed between the open and the change of owner.
fn claim(file: &fs::File, path: &Path) {
    super::ownership::give_open(file, path);
}

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

    /// A link where a journal file should be is refused, so a root process never writes
    /// through it.
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

    /// An ordinary file opens both ways and is private.
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

    /// `O_NOFOLLOW` covers a planted link but not a planted regular file. Opened with
    /// truncation, that file would be emptied and then chowned by a process that is usually
    /// root.
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

    /// Under `sudo` a file written whole is staged and then renamed or linked into place
    /// in the directory the walk from the invoking user's home reached. A rename, link or
    /// removal looked up by path afterwards would follow a link placed above it in the
    /// meantime.
    #[test]
    fn a_staged_file_is_put_in_place_where_it_was_staged_whatever_moves_above_it() {
        use crate::journal::paths::InvokingUser;

        let dir = scratch("walked");
        let home = dir.join("home");
        let elsewhere = dir.join("elsewhere");
        fs::create_dir_all(home.join("state/journal")).expect("a journal");
        fs::create_dir_all(elsewhere.join("journal")).expect("a directory outside");
        for name in ["cursor.tmp", "LOCK.lock-1"] {
            fs::write(elsewhere.join("journal").join(name), b"bait").expect("writes");
        }
        // SAFETY: neither call has any precondition.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let user = InvokingUser::new(uid, gid, home.clone());

        // Leads `state` out of the home, the journal kept aside, and back.
        let redirect = || -> std::io::Result<()> {
            fs::rename(home.join("state"), home.join("kept"))?;
            std::os::unix::fs::symlink(&elsewhere, home.join("state"))
        };
        let restore = || {
            fs::remove_file(home.join("state")).expect("removes the link");
            fs::rename(home.join("kept"), home.join("state")).expect("restores");
        };

        let cursor = home.join("state/journal/cursor.json");
        let target = Place::of_as(Some(&user), &cursor).expect("reached");
        replace_at(
            &target,
            &cursor,
            &cursor.with_extension("tmp"),
            |mut file| {
                file.write_all(b"the journal's")?;
                redirect()
            },
        )
        .expect("replaces");
        restore();
        assert_eq!(fs::read(&cursor).expect("reads"), b"the journal's");

        let lock = home.join("state/journal/LOCK");
        let target = Place::of_as(Some(&user), &lock).expect("reached");
        link_new_at(
            &target,
            &lock,
            &lock.with_extension("lock-1"),
            |mut file| {
                file.write_all(b"held")?;
                redirect()
            },
        )
        .expect("links");
        restore();
        assert_eq!(fs::read(&lock).expect("reads"), b"held");

        let outside: Vec<_> = fs::read_dir(elsewhere.join("journal"))
            .expect("lists")
            .map(|entry| entry.expect("an entry").file_name())
            .collect();
        assert_eq!(
            outside.len(),
            2,
            "renamed or linked out of the home: {outside:?}"
        );
        for name in ["cursor.tmp", "LOCK.lock-1"] {
            assert_eq!(
                fs::read(elsewhere.join("journal").join(name)).expect("reads"),
                b"bait",
                "{name} was changed out of the home"
            );
        }

        fs::remove_dir_all(&dir).ok();
    }

    /// A staging name left by a crashed run is discarded so the journal does not wedge.
    #[test]
    fn a_staged_name_left_by_a_crashed_run_is_discarded_rather_than_wedging() {
        let dir = scratch("staged");
        let temporary = dir.join("cursor.json.tmp");
        fs::write(&temporary, b"a checkpoint that never got renamed").expect("writes");

        let destination = dir.join("cursor.json");
        replace(&destination, &temporary, |mut file| {
            file.write_all(b"the next one")
        })
        .expect("a leftover staging file is discarded");

        assert_eq!(fs::read(&destination).expect("reads"), b"the next one");
        assert!(!temporary.exists(), "the staged name was renamed away");

        // Still not followed when it is a link: the removal unlinks the name, and the
        // create after it refuses a link.
        let elsewhere = dir.join("elsewhere");
        fs::write(&elsewhere, b"not the journal's to touch").expect("writes");
        let linked = dir.join("hosts.jsonl-tmp");
        std::os::unix::fs::symlink(&elsewhere, &linked).expect("links");

        replace(&dir.join("hosts.jsonl"), &linked, |mut file| {
            file.write_all(b"compacted")
        })
        .expect("the link is unlinked and a real file created");
        assert_eq!(
            fs::read(&elsewhere).expect("reads"),
            b"not the journal's to touch",
            "the file behind the link was written through"
        );

        fs::remove_dir_all(&dir).ok();
    }
}
