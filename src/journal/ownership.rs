// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Creating things in the invoking user's home
//!
//! An elevated run writes into the home of the user who invoked it: journals under
//! `~/.local/state`, a first settings file under `~/.config`. Whatever it creates there is
//! root's unless given back, and a root-owned `~/.local/state` breaks every other program
//! that keeps state there.
//!
//! [`create_missing`] makes a path like `create_dir_all` and returns the directories it
//! made, since only those are this run's to give. The caller then gives them.
//!
//! ## One boundary: the invoking user's home
//!
//! Everything given here, journal files and settings files alike, goes to the invoking user
//! only when it lies strictly inside their home. A path outside it was chosen by somebody
//! with root (an administrator's `/etc/zond`, or a state or configuration root kept through
//! `sudo` on purpose) and may be shared, so root keeps what it makes there and the user's
//! own runs are refused there.
//!
//! The same boundary decides how names inside the home are reached. Under `sudo`
//! everything created, read, renamed, linked or removed there is reached relative to a
//! directory walked to from the home without following a link out of it, so a link the user
//! placed cannot lead root to act where only root could; see [`Place`].
//!
//! ## Repairing what an elevated run left to root
//!
//! A directory inside the invoking user's home that root owns was made by an elevated
//! process that did not give it back. [`reclaim`] and its file forms give such a directory or
//! file back on the way to this crate's own locations, and leave alone one owned by any other
//! user.
//!
//! Nothing is given whose handle shows a file another link also names, since that link may
//! be a system file's; see [`refusal`].
//!
//! Compiled for either of the two writers, the journal and the settings files.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use super::paths::InvokingUser;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// Creates `path` and every directory missing above it, and returns the ones
/// this call created, outermost first.
///
/// On Unix each is created with `mode` where one is given, else the process default,
/// as `create_dir_all` would.
///
/// A directory another process creates meanwhile is not reported. A link where a directory
/// is expected counts as the directory, as for `create_dir_all`: a home whose `~/.local`
/// links elsewhere is one somebody arranged. Under `sudo`, for a path inside the invoking
/// user's home, that holds only while the link stays inside the home; see [`Place`].
pub(crate) fn create_missing(path: &Path, mode: Option<u32>) -> io::Result<Vec<PathBuf>> {
    #[cfg(unix)]
    if let Some(user) = invoking().filter(|user| inside_home(user, path)) {
        return create_missing_in_home(user, path, mode);
    }

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

    // Reports a path that exists and is not a directory, or that a racing process
    // left as something else, as `create_dir_all` would.
    fs::create_dir_all(path)?;

    Ok(created)
}

/// [`create_missing`] for a path inside `user`'s home, from an elevated run.
///
/// The existing directory is reached by the walk giving uses, so a link leading out
/// of the home fails it. Each missing directory is then made relative to the one above and
/// opened refusing a link, so a name repointed between the two fails.
#[cfg(unix)]
fn create_missing_in_home(
    user: &InvokingUser,
    path: &Path,
    mode: Option<u32>,
) -> io::Result<Vec<PathBuf>> {
    let mut existing = path;
    let mut missing = Vec::new();
    loop {
        match fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let (Some(parent), Some(name)) = (existing.parent(), existing.file_name()) else {
                    return Err(e);
                };
                missing.push((existing, name));
                existing = parent;
            }
            Err(e) => return Err(e),
        }
    }

    // The process default, as `create_dir_all` uses; the umask applies.
    let mode = mode.unwrap_or(0o777) as libc::mode_t;
    let mut current = walk_from_home(user, existing, true)?;
    let mut created = Vec::new();
    for (directory, name) in missing.into_iter().rev() {
        let name = c_name(name)?;
        // SAFETY: `current` is an open descriptor for the call and `name` a
        // NUL-terminated string that outlives it.
        if unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), mode) } == 0 {
            created.push(directory.to_path_buf());
        } else {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        current = open_at(&current, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    }

    // Reports a path that exists and is not a directory, asked of the handle the walk
    // ended on.
    if !current.metadata()?.is_dir() {
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    Ok(created)
}

/// A name to create, open, rename, link or remove, reached so that an elevated run
/// cannot be led out of the invoking user's home by a link on the way.
///
/// `O_NOFOLLOW` guards only the last name. A root process creating
/// `~/.local/state/zond/<id>/manifest.json` by path follows every link above it, each the
/// user's to place: `~/.local` linked to `/etc` would have root create the journal under
/// `/etc/state` and keep it as root's. So under `sudo`, for a path inside the invoking
/// user's home, the directory holding the name is resolved once to check it lies inside the
/// home (so dotfiles linked elsewhere in the home still work), then opened from the home one
/// name at a time, refusing a link. The name is then created relative to that directory, so
/// nothing is looked up by path between the check and the creation. A link leading out of
/// the home is refused.
///
/// Elsewhere, or in a run on nobody else's behalf, the name is the path itself: a location
/// outside the home was chosen by somebody with root, and an unprivileged run following its
/// own user's links goes nowhere that user could not.
///
/// Renames and hard links between two names in one directory go through the one descriptor
/// [`beside`](Place::beside) shares, and removals, of a file or a whole journal, are made
/// relative to the directory holding the name. By path, a link placed above between a file's
/// staging and its rename would redirect them.
///
/// Each name is reached by its own walk from the home. A walk costs some tens of
/// microseconds and a journal reaches a handful of names per checkpoint, only under `sudo`,
/// so holding a directory descriptor through every path-taking function would save nothing
/// measurable.
#[cfg(unix)]
pub(crate) struct Place {
    /// The directory `name` is looked up in, or `None` for the working directory, where
    /// `name` is the whole path.
    directory: Option<fs::File>,
    name: std::ffi::CString,
}

#[cfg(unix)]
impl Place {
    /// Where `path` is, for the run this process is.
    pub(crate) fn of(path: &Path) -> io::Result<Self> {
        Self::of_as(invoking(), path)
    }

    /// [`Place::of`] on behalf of `user`, so a test can take an elevated run's route
    /// without being one.
    pub(crate) fn of_as(user: Option<&InvokingUser>, path: &Path) -> io::Result<Self> {
        if let Some(user) = user.filter(|user| inside_home(user, path)) {
            let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
                return Err(outside(path));
            };
            return Ok(Self {
                directory: Some(walk_from_home(user, parent, true)?),
                name: c_name(name)?,
            });
        }
        Ok(Self {
            directory: None,
            name: c_name(path.as_os_str())?,
        })
    }

    /// Opens the name with `flags`, and `mode` where they create it, never following a
    /// link at it.
    pub(crate) fn open(&self, flags: libc::c_int, mode: libc::mode_t) -> io::Result<fs::File> {
        match &self.directory {
            Some(directory) => open_at(directory, &self.name, flags, mode),
            None => open_at_raw(libc::AT_FDCWD, &self.name, flags, mode),
        }
    }

    /// Opens the name for reading and writing, creating it with `mode` where it is
    /// missing, and says whether this call created it.
    ///
    /// For a file every racer opens, such as a lock: what this call created is the run's
    /// to give, what it found is not; see [`give_open`] and [`reclaim_open`].
    #[cfg(feature = "journal-format")]
    pub(crate) fn open_or_create(&self, mode: libc::mode_t) -> io::Result<(fs::File, bool)> {
        /// Each miss is a racer removing the name between the two opens.
        const ATTEMPTS: usize = 8;

        let mut missed = None;
        for _ in 0..ATTEMPTS {
            match self.open(libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, mode) {
                Ok(created) => return Ok((created, true)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
            match self.open(libc::O_RDWR, 0) {
                Ok(found) => return Ok((found, false)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => missed = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(missed.unwrap_or_else(|| io::Error::from(io::ErrorKind::NotFound)))
    }

    /// The name `sibling` in the directory this name was reached in, through the same
    /// descriptor.
    ///
    /// For a file staged beside another and then renamed or linked over it: the two stay names
    /// in one directory whatever is rearranged above it.
    #[cfg(feature = "journal-format")]
    pub(crate) fn beside(&self, sibling: &std::ffi::OsStr) -> io::Result<Self> {
        match &self.directory {
            Some(directory) => Ok(Self {
                directory: Some(directory.try_clone()?),
                name: c_name(sibling)?,
            }),
            None => {
                use std::os::unix::ffi::OsStrExt;
                let path = Path::new(std::ffi::OsStr::from_bytes(self.name.as_bytes()));
                Ok(Self {
                    directory: None,
                    name: c_name(path.with_file_name(sibling).as_os_str())?,
                })
            }
        }
    }

    /// Creates a directory at the name, with `mode`.
    #[cfg(feature = "journal-format")]
    pub(crate) fn create_directory(&self, mode: libc::mode_t) -> io::Result<()> {
        // SAFETY: the descriptor is open for the call (or is `AT_FDCWD`), and `name` is a
        // NUL-terminated string that outlives it.
        done(unsafe { libc::mkdirat(self.descriptor(), self.name.as_ptr(), mode) })
    }

    /// Removes the name; a link is removed, not what it points to.
    #[cfg(feature = "journal-format")]
    pub(crate) fn remove(&self) -> io::Result<()> {
        // SAFETY: as in `create_directory`.
        done(unsafe { libc::unlinkat(self.descriptor(), self.name.as_ptr(), 0) })
    }

    /// Renames the name over `destination`, replacing what stands there.
    #[cfg(feature = "journal-format")]
    pub(crate) fn rename_over(&self, destination: &Self) -> io::Result<()> {
        // SAFETY: both descriptors are open for the call (or are `AT_FDCWD`), and both
        // names are NUL-terminated strings that outlive it.
        done(unsafe {
            libc::renameat(
                self.descriptor(),
                self.name.as_ptr(),
                destination.descriptor(),
                destination.name.as_ptr(),
            )
        })
    }

    /// Links what stands at the name at `destination` as well, refusing a name that
    /// exists there.
    #[cfg(feature = "journal-format")]
    pub(crate) fn link_as(&self, destination: &Self) -> io::Result<()> {
        // SAFETY: as in `rename_over`. Flags 0: a link at the name is not followed.
        done(unsafe {
            libc::linkat(
                self.descriptor(),
                self.name.as_ptr(),
                destination.descriptor(),
                destination.name.as_ptr(),
                0,
            )
        })
    }

    /// Removes the directory at the name and everything in it, as `remove_dir_all`
    /// does, with every name looked up relative to the directory holding it.
    ///
    /// A link, at the name or inside, is removed as a link. A name changed meanwhile fails the
    /// removal: a file that became a directory is refused by the unlink, a directory that became
    /// a link by the open. An entry another process removed first is not a failure.
    #[cfg(feature = "journal-format")]
    pub(crate) fn remove_tree(&self) -> io::Result<()> {
        if !self.is_directory()? {
            return self.remove();
        }
        let directory = self.open(libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        for name in entries(&directory)? {
            let entry = Self {
                directory: Some(directory.try_clone()?),
                name,
            };
            match entry.remove_tree() {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        }
        // SAFETY: as in `create_directory`.
        done(unsafe { libc::unlinkat(self.descriptor(), self.name.as_ptr(), libc::AT_REMOVEDIR) })
    }

    /// Whether the name is a directory, asked of the name itself.
    #[cfg(feature = "journal-format")]
    pub(crate) fn is_directory(&self) -> io::Result<bool> {
        Ok(self.kind()? == Kind::Directory)
    }

    /// What stands at the name; a link counts as a link.
    #[cfg(feature = "journal-format")]
    pub(crate) fn kind(&self) -> io::Result<Kind> {
        Ok(match self.stat()?.st_mode & libc::S_IFMT {
            libc::S_IFDIR => Kind::Directory,
            libc::S_IFLNK => Kind::Link,
            _ => Kind::Other,
        })
    }

    /// Whether anything stands at the name, a link included.
    #[cfg(feature = "journal-format")]
    pub(crate) fn exists(&self) -> io::Result<bool> {
        match self.stat() {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// What stands at the name, without following a link.
    #[cfg(feature = "journal-format")]
    fn stat(&self) -> io::Result<libc::stat> {
        let mut held = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: as in `create_directory`; a successful call writes `held` whole.
        done(unsafe {
            libc::fstatat(
                self.descriptor(),
                self.name.as_ptr(),
                held.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })?;
        // SAFETY: the call succeeded, so the structure is initialised.
        Ok(unsafe { held.assume_init() })
    }

    /// The directory to look the name up in, as the C calls take it.
    #[cfg(feature = "journal-format")]
    fn descriptor(&self) -> libc::c_int {
        self.directory
            .as_ref()
            .map_or(libc::AT_FDCWD, |directory| directory.as_raw_fd())
    }
}

/// What stands at a name, as [`Place::kind`] tells it.
#[cfg(feature = "journal-format")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A directory.
    Directory,
    /// A link, whatever it points to.
    Link,
    /// Anything else: a file, or something stranger.
    Other,
}

/// A directory whose names are listed and each looked at, reached as [`Place`]
/// reaches the directory a name is in.
///
/// For a listing of a journal root or a journal: which names there are and what stands at
/// each. By path under `sudo`, a link the invoking user placed would have root list
/// wherever it leads, and even with every open refused, what the listing printed would
/// reveal what stands somewhere only root can look. Reached this way, the directory is the
/// one the walk from the home arrives at, and each name is looked at relative to it.
///
/// Elsewhere, or in a run on nobody else's behalf, it is the path itself.
#[cfg(all(unix, feature = "journal-format"))]
pub(crate) struct Directory {
    /// The directory walked to from the home, or `None` where it is reached by path.
    walked: Option<fs::File>,
    path: PathBuf,
}

#[cfg(all(unix, feature = "journal-format"))]
impl Directory {
    /// The directory at `path`, for the run this process is.
    pub(crate) fn of(path: &Path) -> io::Result<Self> {
        Self::of_as(invoking(), path)
    }

    /// [`Directory::of`] on behalf of `user`, so a test can take an elevated run's route
    /// without being one.
    pub(crate) fn of_as(user: Option<&InvokingUser>, path: &Path) -> io::Result<Self> {
        let walked = match user.filter(|user| inside_home(user, path)) {
            Some(user) => Some(walk_from_home(user, path, false)?),
            None => None,
        };
        Ok(Self {
            walked,
            path: path.to_path_buf(),
        })
    }

    /// The names it holds, less `.` and `..`.
    pub(crate) fn names(&self) -> io::Result<Vec<std::ffi::OsString>> {
        use std::os::unix::ffi::OsStringExt;

        match &self.walked {
            Some(directory) => Ok(entries(directory)?
                .into_iter()
                .map(|name| std::ffi::OsString::from_vec(name.into_bytes()))
                .collect()),
            None => fs::read_dir(&self.path)?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect(),
        }
    }

    /// The name `name` in it.
    pub(crate) fn entry(&self, name: &std::ffi::OsStr) -> io::Result<Place> {
        match &self.walked {
            Some(directory) => Ok(Place {
                directory: Some(directory.try_clone()?),
                name: c_name(name)?,
            }),
            None => Ok(Place {
                directory: None,
                name: c_name(self.path.join(name).as_os_str())?,
            }),
        }
    }
}

/// A name inside a journal where there is no `sudo`: the path itself.
#[cfg(all(not(unix), feature = "journal-format"))]
pub(crate) struct Place {
    path: PathBuf,
}

#[cfg(all(not(unix), feature = "journal-format"))]
impl Place {
    /// Where `path` is.
    pub(crate) fn of(path: &Path) -> io::Result<Self> {
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// The path, for the opener that takes one.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The name `sibling` beside this one.
    pub(crate) fn beside(&self, sibling: &std::ffi::OsStr) -> io::Result<Self> {
        Ok(Self {
            path: self.path.with_file_name(sibling),
        })
    }

    /// Removes the name.
    pub(crate) fn remove(&self) -> io::Result<()> {
        fs::remove_file(&self.path)
    }

    /// Renames the name over `destination`.
    pub(crate) fn rename_over(&self, destination: &Self) -> io::Result<()> {
        fs::rename(&self.path, &destination.path)
    }

    /// Links what stands at the name at `destination` as well.
    pub(crate) fn link_as(&self, destination: &Self) -> io::Result<()> {
        fs::hard_link(&self.path, &destination.path)
    }

    /// Removes the directory at the name and everything in it.
    pub(crate) fn remove_tree(&self) -> io::Result<()> {
        fs::remove_dir_all(&self.path)
    }

    /// What stands at the name, a link being a link.
    pub(crate) fn kind(&self) -> io::Result<Kind> {
        let held = fs::symlink_metadata(&self.path)?.file_type();
        Ok(if held.is_symlink() {
            Kind::Link
        } else if held.is_dir() {
            Kind::Directory
        } else {
            Kind::Other
        })
    }

    /// Whether anything stands at the name, a link included.
    pub(crate) fn exists(&self) -> io::Result<bool> {
        match fs::symlink_metadata(&self.path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// A directory whose names are listed, where there is no `sudo`: the path itself.
#[cfg(all(not(unix), feature = "journal-format"))]
pub(crate) struct Directory {
    path: PathBuf,
}

#[cfg(all(not(unix), feature = "journal-format"))]
impl Directory {
    /// The directory at `path`.
    pub(crate) fn of(path: &Path) -> io::Result<Self> {
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// The names it holds.
    pub(crate) fn names(&self) -> io::Result<Vec<std::ffi::OsString>> {
        fs::read_dir(&self.path)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect()
    }

    /// The name `name` in it.
    pub(crate) fn entry(&self, name: &std::ffi::OsStr) -> io::Result<Place> {
        Ok(Place {
            path: self.path.join(name),
        })
    }
}

/// The user an elevated run is on behalf of, or `None` when it is on nobody else's.
///
/// Resolved once, since it cannot change while the process runs and the lookup goes to the
/// password database.
#[cfg(unix)]
pub(crate) fn invoking() -> Option<&'static InvokingUser> {
    static INVOKING: std::sync::OnceLock<Option<InvokingUser>> = std::sync::OnceLock::new();
    INVOKING.get_or_init(super::paths::invoking_user).as_ref()
}

/// Gives a directory this run created to the user who invoked it, when it lies
/// in that user's home.
///
/// Best effort: worth avoiding leaving things to root, not worth failing a run over.
/// An unelevated run has nobody to give it to.
#[cfg(unix)]
pub(crate) fn give(path: &Path) {
    let Some(user) = invoking() else { return };
    if let Some(opened) = open_directory_in_home(user, path) {
        hand(user, &opened, path, Offer::Made);
    }
}

/// Gives the invoking user every directory from their home down to `leaf`:
/// those in `created` because this run made them, and the others where root
/// owns them (see [`reclaim`]).
///
/// For a writer creating on the way to its own location, the one case where what
/// lies above it is known to have been made by an elevated run of this crate.
#[cfg(all(unix, any(feature = "import-settings", feature = "fetch")))]
pub(crate) fn hand_over(leaf: &Path, created: &[PathBuf]) {
    let Some(user) = invoking() else { return };
    let mut on_the_way: Vec<&Path> = leaf
        .ancestors()
        .take_while(|directory| inside_home(user, directory))
        .collect();
    on_the_way.reverse();
    for directory in on_the_way {
        if created.iter().any(|made| made == directory) {
            give(directory);
        } else {
            reclaim(directory);
        }
    }
}

/// Gives a file this run created, through its handle, so the name is not looked up
/// again between creating it and changing its owner.
#[cfg(all(unix, any(feature = "journal-format", feature = "import-settings")))]
pub(crate) fn give_open(opened: &fs::File, path: &Path) {
    if let Some(user) = recipient(invoking(), path) {
        hand(user, opened, path, Offer::Made);
    }
}

/// Gives a file this run found, through its handle, back to the invoking user when
/// root owns it, as [`reclaim`] does for a directory.
#[cfg(all(unix, feature = "journal-format"))]
pub(crate) fn reclaim_open(opened: &fs::File, path: &Path) {
    if let Some(user) = recipient(invoking(), path) {
        hand(user, opened, path, Offer::LeftToRoot);
    }
}

/// [`reclaim_open`] for the file at `path`, reached as [`Place`] reaches a name.
///
/// Opened without blocking, since a pipe planted at the name would otherwise hold the
/// open until something writes to it.
#[cfg(all(unix, feature = "import-settings"))]
pub(crate) fn reclaim_file(path: &Path) {
    let Some(user) = recipient(invoking(), path) else {
        return;
    };
    let opened = Place::of_as(Some(user), path)
        .and_then(|place| place.open(libc::O_RDONLY | libc::O_NONBLOCK, 0));
    if let Ok(opened) = opened {
        hand(user, &opened, path, Offer::LeftToRoot);
    }
}

/// Gives a directory `path` back to the invoking user when it lies in their home and
/// root owns it, and says so at the first verbosity.
///
/// For what already exists on the way to this crate's locations; see the module
/// documentation.
#[cfg(unix)]
pub(crate) fn reclaim(path: &Path) {
    let Some(user) = invoking() else { return };
    if let Some(opened) = open_directory_in_home(user, path) {
        hand(user, &opened, path, Offer::LeftToRoot);
    }
}

/// Why something is offered to the invoking user.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Offer {
    /// This run made it, so it is the user's whoever owns it now.
    Made,
    /// It was found, so it is given only where root owns it, the sign of an elevated
    /// run that gave nothing back.
    LeftToRoot,
}

/// What [`hand`] did.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Handed {
    /// Its owner is now the user.
    Given,
    /// Found owned by somebody other than root, so left as it is.
    NotRoots,
    /// Refused, for the reason given; see [`refusal`].
    Refused(&'static str),
    /// It could not be looked at or its owner could not be changed.
    Failed,
}

/// Gives `opened` to `user` as `offer` allows, checked on the handle so what is
/// checked is what is changed.
#[cfg(unix)]
fn hand(user: &InvokingUser, opened: &fs::File, path: &Path, offer: Offer) -> Handed {
    use std::os::unix::fs::MetadataExt;

    let Ok(held) = opened.metadata() else {
        return Handed::Failed;
    };
    if let Some(why) = refusal(&held) {
        crate::info!(
            verbosity = 1,
            "{} not given to its user ({why})",
            path.display()
        );
        return Handed::Refused(why);
    }
    if offer == Offer::LeftToRoot && held.uid() != 0 {
        return Handed::NotRoots;
    }

    // SAFETY: the descriptor is owned by `opened` and open for the call; `fchown` reads
    // only it.
    if unsafe { libc::fchown(opened.as_raw_fd(), user.uid, user.gid) } != 0 {
        return Handed::Failed;
    }
    if offer == Offer::LeftToRoot {
        crate::info!(
            verbosity = 1,
            "{} given back to its user (left to root)",
            path.display()
        );
    }
    Handed::Given
}

/// Why what `held` describes may not be given away, or `None` where it may.
///
/// A file with a second link may be a name for something outside the home: `ln` needs no
/// say over its target, so where a system allows it a user can link a root-owned
/// system file into their own state directory, and changing the owner through that name
/// would give them the original. A directory cannot be hard-linked. Nothing but a file or a
/// directory is this crate's to make.
#[cfg(unix)]
fn refusal(held: &fs::Metadata) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;

    let kind = held.file_type();
    if kind.is_dir() {
        None
    } else if !kind.is_file() {
        Some("not a file or directory")
    } else if held.nlink() > 1 {
        Some("another link names it")
    } else {
        None
    }
}

/// [`open_in_home`] for a directory to give, saying at the first verbosity when
/// something else stands at the name.
#[cfg(unix)]
fn open_directory_in_home(user: &InvokingUser, path: &Path) -> Option<fs::File> {
    match open_in_home(user, path) {
        Ok(opened) => Some(opened),
        Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {
            crate::info!(
                verbosity = 1,
                "{} not given to its user (not a directory)",
                path.display()
            );
            None
        }
        Err(_) => None,
    }
}

/// Opens the directory `path` names to change its owner, when it lies strictly inside
/// `user`'s home, without following a link the user could have planted on the way.
///
/// By name, `~/.config` linked to `/etc` would turn `~/.config/zond` into `/etc/zond`, and
/// root changing its owner would hand the user the host-wide settings. See
/// [`walk_from_home`]. The home itself is never given.
#[cfg(unix)]
fn open_in_home(user: &InvokingUser, path: &Path) -> io::Result<fs::File> {
    walk_from_home(user, path, false)
}

/// Opens the directory `path`, which must lie inside `user`'s home or, where
/// `home_itself` allows, be the home, without following a link that leads out of it.
///
/// The path is resolved once to decide whether it lies in the home, so dotfiles linked
/// elsewhere inside the home keep working. The resolved path is then walked from the home
/// one name at a time, each opened relative to the last and refusing a link, so a name
/// repointed after the check fails the walk.
#[cfg(unix)]
fn walk_from_home(user: &InvokingUser, path: &Path, home_itself: bool) -> io::Result<fs::File> {
    let spelled_inside = inside_home(user, path) || (home_itself && path == user.home);
    if !spelled_inside {
        return Err(outside(path));
    }
    let home = fs::canonicalize(&user.home)?;
    let resolved = fs::canonicalize(path)?;
    let below = resolved
        .strip_prefix(&home)
        .ok()
        .filter(|below| home_itself || !below.as_os_str().is_empty())
        .ok_or_else(|| outside(path))?;

    let mut current = fs::File::open(&home)?;
    for component in below.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(outside(path));
        };
        current = open_at(
            &current,
            &c_name(name)?,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
    }
    Ok(current)
}

/// The refusal of `path`, which is not, or does not stay, inside the invoking user's
/// home. Names the path so the reader can find the link.
#[cfg(unix)]
fn outside(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{} leads out of the invoking user's home", path.display()),
    )
}

/// A name as the C calls take it.
#[cfg(unix)]
fn c_name(name: &std::ffi::OsStr) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes()).map_err(io::Error::other)
}

/// A C call's `0` or `-1` as a result.
#[cfg(all(unix, feature = "journal-format"))]
fn done(returned: libc::c_int) -> io::Result<()> {
    if returned == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The names in `directory`, less `.` and `..`, from its first.
///
/// A read that fails part way ends the list early. A removal then fails on the directory
/// not being empty, and a listing passes over what it could not read.
#[cfg(all(unix, feature = "journal-format"))]
fn entries(directory: &fs::File) -> io::Result<Vec<std::ffi::CString>> {
    use std::os::unix::io::IntoRawFd;

    // A duplicate, since the stream takes ownership of the descriptor and closes it.
    let descriptor = directory.try_clone()?.into_raw_fd();
    // SAFETY: `descriptor` is open and owned by nothing else.
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: the stream was not made, so the descriptor is still ours to close.
        unsafe { libc::close(descriptor) };
        return Err(error);
    }
    // A duplicate shares its read position with the original, so rewind.
    // SAFETY: `stream` is open until the `closedir` below.
    unsafe { libc::rewinddir(stream) };

    let mut names = Vec::new();
    loop {
        // SAFETY: `stream` is open until the `closedir` below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: a non-null entry holds a NUL-terminated name, valid until the next call
        // on the stream; it is copied before that.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if !matches!(name.to_bytes(), b"." | b"..") {
            names.push(name.to_owned());
        }
    }
    // SAFETY: `stream` is open, and closing it closes `descriptor` with it.
    unsafe { libc::closedir(stream) };
    Ok(names)
}

/// Opens `name` relative to `directory`, never following a link at it.
#[cfg(unix)]
fn open_at(
    directory: &fs::File,
    name: &std::ffi::CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> io::Result<fs::File> {
    open_at_raw(directory.as_raw_fd(), name, flags, mode)
}

/// [`open_at`] on a raw descriptor, which may be `AT_FDCWD`.
#[cfg(unix)]
fn open_at_raw(
    directory: libc::c_int,
    name: &std::ffi::CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> io::Result<fs::File> {
    use std::os::unix::io::FromRawFd;

    // SAFETY: `directory` is open for the call or `AT_FDCWD`, and `name` is a
    // NUL-terminated string that outlives it; the returned descriptor is owned only by the
    // `File` built from it.
    let opened = unsafe {
        libc::openat(
            directory,
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            // `mode_t` is narrower than the variadic `c_uint` on some
            // platforms and the same type on others.
            mode as libc::c_uint,
        )
    };
    if opened < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `opened` was just opened and is owned by nothing else.
    Ok(unsafe { fs::File::from_raw_fd(opened) })
}

/// Platforms with no `sudo`, where what a run creates is already the invoking user's.
#[cfg(not(unix))]
pub(crate) fn give(_path: &Path) {}

/// [`hand_over`], inert for the same reason.
#[cfg(all(not(unix), any(feature = "import-settings", feature = "fetch")))]
pub(crate) fn hand_over(_leaf: &Path, _created: &[PathBuf]) {}

/// [`give`] for a file, inert for the same reason.
#[cfg(all(
    not(unix),
    any(feature = "journal-format", feature = "import-settings")
))]
pub(crate) fn give_open(_opened: &fs::File, _path: &Path) {}

/// Nothing is ever left to root on a platform with no `sudo`.
#[cfg(not(unix))]
pub(crate) fn reclaim(_path: &Path) {}

/// [`reclaim`] for a file, inert for the same reason.
#[cfg(all(not(unix), feature = "import-settings"))]
pub(crate) fn reclaim_file(_path: &Path) {}

/// Who `path` should be given to: the invoking user, when there is one and the path
/// lies strictly inside their home.
///
/// Strictly inside, because the home itself was not this run's to create. A path that climbs
/// out with `..` is refused, not resolved.
#[cfg(all(
    unix,
    any(test, feature = "journal-format", feature = "import-settings")
))]
fn recipient<'a>(invoking: Option<&'a InvokingUser>, path: &Path) -> Option<&'a InvokingUser> {
    invoking.filter(|user| inside_home(user, path))
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

    /// Only what was made is reported, since only that is the run's to give.
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

        // A second call has made nothing, and does not fail.
        assert_eq!(
            create_missing(&target, None).expect("exists"),
            Vec::<PathBuf>::new()
        );

        // A file where the directory should be is refused, as by `create_dir_all`.
        let file = home.join("file");
        fs::write(&file, b"").expect("writes");
        assert!(create_missing(&file, None).is_err());

        let _ = fs::remove_dir_all(&home);
    }

    /// An elevated run gives the invoking user only what lies inside their home. A
    /// settings directory an administrator keeps, or one named past the home with `..`, stays
    /// root's.
    #[cfg(unix)]
    #[test]
    fn only_what_lies_inside_the_invoking_users_home_is_given_to_them() {
        let user = InvokingUser {
            uid: 1000,
            gid: 1000,
            home: PathBuf::from("/home/user"),
        };

        for inside in ["/home/user/.local", "/home/user/.config/zond/engine.toml"] {
            assert_eq!(
                recipient(Some(&user), Path::new(inside)).map(|user| (user.uid, user.gid)),
                Some((1000, 1000)),
                "{inside}"
            );
        }
        for outside in [
            "/etc/zond",
            "/home/user",
            "/home/user2/.config",
            "/home/user/../root/.config",
        ] {
            assert_eq!(
                recipient(Some(&user), Path::new(outside)).map(|user| user.uid),
                None,
                "{outside}"
            );
        }

        // Nothing elevated: nobody to give anything to.
        assert!(recipient(None, Path::new("/home/user/.local")).is_none());
    }

    /// What is given is reached from the home without following a planted link that
    /// leads out of it (`~/.config` linked to `/etc` would otherwise hand the user `/etc/zond`).
    /// A link that stays inside the home, as a dotfiles checkout makes, is still followed.
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

    /// The user this test process is, as an elevated run's invoking user, so a give
    /// is a `chown` to the owner a file already has and needs no privilege.
    #[cfg(unix)]
    fn this_user(home: &Path) -> InvokingUser {
        // SAFETY: neither call can fail or touches memory.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        InvokingUser {
            uid,
            gid,
            home: home.to_path_buf(),
        }
    }

    /// A file with a second link is never given, made or found: the other link may be a
    /// system file's, linked into the home by the user. One with no other link is, and so is
    /// a directory, whose link count only counts what is in it.
    #[cfg(unix)]
    #[test]
    fn a_file_another_link_names_is_never_given() {
        let home = scratch("hard-links");
        let user = this_user(&home);
        let sole = home.join("sole");
        let linked = home.join("linked");
        fs::write(&sole, b"").expect("writes");
        fs::write(home.join("system-file"), b"").expect("writes");
        fs::hard_link(home.join("system-file"), &linked).expect("links");
        fs::create_dir(home.join("directory")).expect("a directory");
        fs::create_dir(home.join("directory/inner")).expect("a directory");

        for offer in [Offer::Made, Offer::LeftToRoot] {
            let opened = fs::File::open(&linked).expect("opens");
            assert_eq!(
                hand(&user, &opened, &linked, offer),
                Handed::Refused("another link names it"),
                "a file with a second link was handed over ({offer:?})"
            );
        }
        let opened = fs::File::open(&sole).expect("opens");
        assert_eq!(hand(&user, &opened, &sole, Offer::Made), Handed::Given);
        assert_eq!(
            hand(&user, &opened, &sole, Offer::LeftToRoot),
            Handed::NotRoots
        );
        let directory = home.join("directory");
        let opened = open_in_home(&user, &directory).expect("opens");
        assert_eq!(hand(&user, &opened, &directory, Offer::Made), Handed::Given);

        let _ = fs::remove_dir_all(&home);
    }

    /// What is given as a directory is opened as one, so a file planted at a directory's
    /// name is not reached, and a pipe opened as a file is refused.
    #[cfg(unix)]
    #[test]
    fn only_a_directory_is_given_as_one() {
        let scratch = scratch("kinds");
        let home = scratch.join("home");
        fs::create_dir_all(&home).expect("a home");
        fs::write(home.join("state"), b"").expect("writes");
        let user = this_user(&home);

        assert_eq!(
            open_in_home(&user, &home.join("state"))
                .map(drop)
                .map_err(|e| e.raw_os_error()),
            Err(Some(libc::ENOTDIR)),
            "a file was opened as a directory to give"
        );

        let pipe = home.join("pipe");
        let name = c_name(pipe.as_os_str()).expect("a name");
        // SAFETY: `name` is a NUL-terminated string that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0, "a pipe");
        let opened = Place::of_as(Some(&user), &pipe)
            .and_then(|place| place.open(libc::O_RDONLY | libc::O_NONBLOCK, 0))
            .expect("opens without blocking");
        assert_eq!(
            hand(&user, &opened, &pipe, Offer::LeftToRoot),
            Handed::Refused("not a file or directory")
        );

        let _ = fs::remove_dir_all(&scratch);
    }

    /// Opening a file every racer shares says whether this call made it, since only
    /// what it made is the run's to give.
    #[cfg(all(unix, feature = "journal-format"))]
    #[test]
    fn opening_or_creating_says_whether_it_created() {
        let home = scratch("open-or-create");
        let user = this_user(&home);
        let lock = Place::of_as(Some(&user), &home.join("update.lock")).expect("reached");

        let (_, created) = lock.open_or_create(0o600).expect("creates");
        assert!(created, "the first open did not create");
        let (_, created) = lock.open_or_create(0o600).expect("opens");
        assert!(!created, "a file already there was reported as made");

        let _ = fs::remove_dir_all(&home);
    }

    /// A listing under `sudo` is not led out of the home by a link, and reports a link
    /// at a name as a link. Even with every open refused, what a listing says reveals what it
    /// found.
    #[cfg(all(unix, feature = "journal-format"))]
    #[test]
    fn a_listing_is_not_led_out_of_the_home_by_a_link() {
        let scratch = scratch("lists");
        let home = scratch.join("home");
        let elsewhere = scratch.join("elsewhere");
        fs::create_dir_all(elsewhere.join("state/zond/01ID")).expect("a journal outside");
        fs::create_dir_all(home.join("kept/zond/02ID")).expect("a journal inside");
        std::os::unix::fs::symlink(&elsewhere, home.join(".local")).expect("links out");
        std::os::unix::fs::symlink(&elsewhere, home.join("kept/zond/03ID")).expect("links in");
        let user = InvokingUser {
            uid: 1000,
            gid: 1000,
            home: home.clone(),
        };

        let led_out = Directory::of_as(Some(&user), &home.join(".local/state/zond"))
            .and_then(|directory| directory.names());
        assert_eq!(
            led_out.map_err(|e| e.kind()),
            Err(io::ErrorKind::PermissionDenied),
            "listed a directory behind a link out of the home"
        );

        let kept = Directory::of_as(Some(&user), &home.join("kept/zond")).expect("reached");
        let mut names = kept.names().expect("lists");
        names.sort();
        assert_eq!(names, ["02ID", "03ID"]);
        let journal = kept.entry("02ID".as_ref()).expect("an entry");
        let link = kept.entry("03ID".as_ref()).expect("an entry");
        assert!(journal.is_directory().expect("looks"));
        assert!(link.exists().expect("looks"), "the link is there");
        assert!(
            !link.is_directory().expect("looks"),
            "a link to a directory was looked at as the directory"
        );
        let _ = fs::remove_dir_all(&scratch);
    }

    /// Under `sudo`, a link on the way out of the home is refused for a directory and
    /// for a file, and nothing appears behind it. Followed, it would have root create
    /// and keep directories and files where only root can write.
    #[cfg(all(unix, feature = "journal-format"))]
    #[test]
    fn nothing_is_created_through_a_link_out_of_the_home() {
        let scratch = scratch("creates");
        let home = scratch.join("home");
        let elsewhere = scratch.join("elsewhere");
        fs::create_dir_all(elsewhere.join("journal")).expect("a directory outside");
        fs::create_dir_all(&home).expect("a home");
        std::os::unix::fs::symlink(&elsewhere, home.join(".local")).expect("links out");
        let user = InvokingUser {
            uid: 1000,
            gid: 1000,
            home: home.clone(),
        };

        let directories = create_missing_in_home(&user, &home.join(".local/state/zond"), None);
        assert!(
            directories.is_err(),
            "created through the link: {directories:?}"
        );

        let file = Place::of_as(Some(&user), &home.join(".local/journal/manifest.json"))
            .and_then(|place| place.open(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600));
        assert!(file.is_err(), "a file was created through the link");

        let directory = Place::of_as(Some(&user), &home.join(".local/journal/01ID"))
            .and_then(|place| place.create_directory(0o700));
        assert!(
            directory.is_err(),
            "a directory was created through the link"
        );

        let behind: Vec<_> = fs::read_dir(&elsewhere)
            .expect("lists")
            .chain(fs::read_dir(elsewhere.join("journal")).expect("lists"))
            .map(|entry| entry.expect("an entry").file_name())
            .collect();
        assert_eq!(behind, ["journal"], "something appeared behind the link");

        let _ = fs::remove_dir_all(&scratch);
    }

    /// Removing a journal under `sudo` removes only the directory the walk reached and
    /// its contents, never what a link inside it points to or what a link placed above it after
    /// the walk leads to.
    #[cfg(all(unix, feature = "journal-format"))]
    #[test]
    fn removing_a_journal_removes_only_what_the_walk_reached() {
        let scratch = scratch("removes");
        let home = scratch.join("home");
        let elsewhere = scratch.join("elsewhere");
        let journal = home.join("state/01ID");
        fs::create_dir_all(journal.join("inner")).expect("a journal");
        fs::write(journal.join("manifest.json"), b"{}").expect("writes");
        fs::write(journal.join("inner/stray"), b"").expect("writes");
        fs::create_dir_all(elsewhere.join("01ID")).expect("a directory outside");
        fs::write(elsewhere.join("01ID/precious"), b"kept").expect("writes");
        std::os::unix::fs::symlink(elsewhere.join("01ID"), journal.join("linked"))
            .expect("links out from inside");
        let user = InvokingUser {
            uid: 1000,
            gid: 1000,
            home: home.clone(),
        };

        let place = Place::of_as(Some(&user), &journal).expect("reached");
        fs::rename(home.join("state"), home.join("kept")).expect("moves aside");
        std::os::unix::fs::symlink(&elsewhere, home.join("state")).expect("links out above");
        place.remove_tree().expect("removes");

        assert!(
            !home.join("kept/01ID").exists(),
            "the journal the walk reached is still there"
        );
        assert_eq!(
            fs::read(elsewhere.join("01ID/precious")).expect("still there"),
            b"kept"
        );

        // A link standing at the name is removed as a link.
        fs::remove_file(home.join("state")).expect("removes the link");
        fs::create_dir(home.join("state")).expect("a directory");
        std::os::unix::fs::symlink(elsewhere.join("01ID"), &journal).expect("links");
        Place::of_as(None, &journal)
            .and_then(|place| place.remove_tree())
            .expect("removes the link");
        assert!(
            fs::symlink_metadata(&journal).is_err(),
            "the link is still there"
        );
        assert!(elsewhere.join("01ID/precious").is_file());

        let _ = fs::remove_dir_all(&scratch);
    }

    /// Only leaving the home is refused: a link that stays inside it is followed, and a
    /// run on nobody else's behalf follows its own user's links as any program would.
    #[cfg(unix)]
    #[test]
    fn a_link_that_stays_in_the_home_is_created_through() {
        let scratch = scratch("creates-within");
        let home = scratch.join("home");
        fs::create_dir_all(home.join("dotfiles/local")).expect("a directory inside");
        std::os::unix::fs::symlink(home.join("dotfiles/local"), home.join(".local"))
            .expect("links within");
        let user = InvokingUser {
            uid: 1000,
            gid: 1000,
            home: home.clone(),
        };

        let created = create_missing_in_home(&user, &home.join(".local/state/zond"), Some(0o700))
            .expect("creates through a link inside the home");
        assert_eq!(
            created,
            [home.join(".local/state"), home.join(".local/state/zond")]
        );
        assert!(home.join("dotfiles/local/state/zond").is_dir());

        let manifest = home.join(".local/state/zond/manifest.json");
        Place::of_as(Some(&user), &manifest)
            .and_then(|place| place.open(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600))
            .expect("creates a file through a link inside the home");
        assert!(
            home.join("dotfiles/local/state/zond/manifest.json")
                .is_file()
        );

        // A second call makes nothing, and a file where a directory should be is refused,
        // as by `create_dir_all`.
        assert_eq!(
            create_missing_in_home(&user, &home.join(".local/state/zond"), None).expect("exists"),
            Vec::<PathBuf>::new()
        );
        assert!(create_missing_in_home(&user, &manifest, None).is_err());

        // Unelevated, the name is the path, links and all.
        let elsewhere = scratch.join("elsewhere");
        fs::create_dir_all(&elsewhere).expect("a directory outside");
        std::os::unix::fs::symlink(&elsewhere, home.join(".cache")).expect("links out");
        Place::of_as(None, &home.join(".cache/file"))
            .and_then(|place| place.open(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600))
            .expect("an unelevated run follows its own user's link");
        assert!(elsewhere.join("file").is_file());

        let _ = fs::remove_dir_all(&scratch);
    }
}
