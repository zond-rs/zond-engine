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
//! The same boundary decides how names inside the home are reached. Under
//! `sudo` everything created there is created relative to a directory walked
//! to from the home without following a link out of it, so a link the user
//! placed cannot lead root to create somewhere only root could; see [`Place`].
//!
//! ## Repairing what an elevated run left to root
//!
//! A directory already there belongs to whoever made it, with one exception:
//! one inside the invoking user's home that root owns. Nothing a user does
//! makes root the owner of a directory in their own home: an elevated process
//! made it and did not give it back, and it stays where no other program of
//! theirs can write. [`reclaim`] gives such a directory, or file, back on the
//! way to this crate's own locations, and leaves one any other user owns
//! alone, since that is a choice somebody made.
//!
//! Compiled for either of the two things that create there, the journal and
//! the settings files, neither of which needs the other.

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
/// On Unix each is created with `mode` where one is given, and with the
/// process's default otherwise, as `create_dir_all` would.
///
/// A directory another process creates between the check and the creation is
/// not reported, since it is not this call's. A link standing where a
/// directory is expected counts as the directory, as it does for
/// `create_dir_all`: a home whose `~/.local` is a link elsewhere is a home
/// somebody arranged. Under `sudo`, and for a path inside the invoking user's
/// home, that holds only while the link leads somewhere else in the same home;
/// see [`Place`] for why one leading out of it is refused.
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

    // What `create_dir_all` would say about a path that exists and is not a
    // directory, or one a racing process left as something else.
    fs::create_dir_all(path)?;

    Ok(created)
}

/// [`create_missing`] for a path inside `user`'s home, from an elevated run.
///
/// The directory that already exists is reached by the same walk that giving
/// uses, so a link on the way that leads out of the home fails it, and each
/// missing directory is then made relative to the one above it and opened
/// refusing a link, so a name repointed between the two fails rather than
/// leading the next one somewhere else.
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

    // The process's default, as `create_dir_all` would use: the mask applies.
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

    // What `create_dir_all` would say about a path that exists and is not a
    // directory, asked of the handle the walk ended on.
    if !current.metadata()?.is_dir() {
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    Ok(created)
}

/// A name to create or open for writing, reached so that an elevated run
/// cannot be led out of the invoking user's home by a link on the way.
///
/// `O_NOFOLLOW` guards the last name only. A root process creating
/// `~/.local/state/zond/<id>/manifest.json` by path follows every link above
/// it, and every one of those is the user's to place: `~/.local` made a link
/// to `/etc` has root create the journal under `/etc/state`, and leave it
/// there as root's, since nothing outside the home is given. So under `sudo`,
/// for a path spelled inside the invoking user's home, the directory holding
/// the name is reached by the walk giving uses: resolved once to decide it
/// lies inside the home, which keeps a home whose dotfiles link elsewhere in
/// it working, and then opened from the home one name at a time, refusing a
/// link. What is created is then created relative to that directory, so
/// nothing is looked up by path between the check and the creation.
///
/// Refusing is the answer for a link that leads out of the home, not
/// following it and keeping what is made there as root's. The user placing
/// the link and the process following it are different users, and a root
/// process that creates wherever an unprivileged one points it is one that
/// makes directories and files appear in places only root could.
///
/// Anywhere else, and in a run on nobody else's behalf, the name is the path
/// itself: a location outside the home is one somebody with root chose, and
/// an unprivileged run following its own user's links goes nowhere that user
/// could not go already.
///
/// Renames, and the removal of a whole journal, still go by path. Through a
/// redirected directory they can reach only names already there, and it is
/// this that keeps an elevated run from having made any outside the home.
#[cfg(unix)]
pub(crate) struct Place {
    /// The directory `name` is looked up in, or `None` for the working
    /// directory, where `name` is the whole path.
    directory: Option<fs::File>,
    name: std::ffi::CString,
}

#[cfg(unix)]
impl Place {
    /// Where `path` is, for the run this process is.
    pub(crate) fn of(path: &Path) -> io::Result<Self> {
        Self::of_as(invoking(), path)
    }

    /// [`Place::of`] on behalf of `user`, so a test can take an elevated run's
    /// route without being one.
    fn of_as(user: Option<&InvokingUser>, path: &Path) -> io::Result<Self> {
        if let Some(user) = user.filter(|user| inside_home(user, path)) {
            let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
                return Err(outside());
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

    /// Opens the name with `flags`, and `mode` where they create it, never
    /// following a link standing at it.
    pub(crate) fn open(&self, flags: libc::c_int, mode: libc::mode_t) -> io::Result<fs::File> {
        match &self.directory {
            Some(directory) => open_at(directory, &self.name, flags, mode),
            None => open_at_raw(libc::AT_FDCWD, &self.name, flags, mode),
        }
    }

    /// Creates a directory at the name, with `mode`.
    #[cfg(feature = "journal-format")]
    pub(crate) fn create_directory(&self, mode: libc::mode_t) -> io::Result<()> {
        // SAFETY: the descriptor is open for the call, or the working
        // directory's marker, and `name` is a NUL-terminated string that
        // outlives it.
        let made = unsafe { libc::mkdirat(self.descriptor(), self.name.as_ptr(), mode) };
        if made == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Removes the name, a link at it rather than what the link points to.
    #[cfg(feature = "journal-format")]
    pub(crate) fn remove(&self) -> io::Result<()> {
        // SAFETY: as in `create_directory`.
        let removed = unsafe { libc::unlinkat(self.descriptor(), self.name.as_ptr(), 0) };
        if removed == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// The directory to look the name up in, as the C calls take it.
    #[cfg(feature = "journal-format")]
    fn descriptor(&self) -> libc::c_int {
        self.directory
            .as_ref()
            .map_or(libc::AT_FDCWD, |directory| directory.as_raw_fd())
    }
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

/// Gives the invoking user every directory from their home down to `leaf`:
/// those in `created` because this run made them, and the others where root
/// owns them (see [`reclaim`]).
///
/// For a writer creating on the way to its own location, which is the one
/// case where what lies above it is known to be somewhere an elevated run of
/// this crate made on the user's behalf.
#[cfg(all(unix, feature = "import-settings"))]
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

/// [`give`], through a handle already open on `path`, so the name is not
/// looked up a second time between opening it and changing its owner.
#[cfg(all(unix, feature = "journal-format"))]
pub(crate) fn give_open(opened: &fs::File, path: &Path) {
    let Some((uid, gid)) = owner_for(invoking(), path) else {
        return;
    };

    // SAFETY: the descriptor is owned by `opened` and open for the call, and
    // `fchown` reads it and nothing else.
    unsafe {
        libc::fchown(opened.as_raw_fd(), uid, gid);
    }
}

/// Gives `path` back to the invoking user when it lies in their home and root
/// owns it, and says so at the first verbosity.
///
/// For what already exists on the way to this crate's locations; see the
/// module documentation for why a root-owned directory there is one an
/// elevated run left, and why one somebody else owns is left alone.
#[cfg(unix)]
pub(crate) fn reclaim(path: &Path) {
    use std::os::unix::fs::MetadataExt;

    let Some(user) = invoking() else { return };
    let Ok(opened) = open_in_home(user, path) else {
        return;
    };
    // Asked of the handle, so what is checked is what is changed.
    if !opened.metadata().is_ok_and(|held| held.uid() == 0) {
        return;
    }

    // SAFETY: as in `give`.
    let changed = unsafe { libc::fchown(opened.as_raw_fd(), user.uid, user.gid) } == 0;
    if changed {
        crate::info!(
            verbosity = 1,
            "{} given back to its user (left to root)",
            path.display()
        );
    }
}

/// Opens what `path` names to change its owner, when it lies strictly inside
/// `user`'s home, without following a link the user could have planted on the
/// way.
///
/// Everything below the home is the user's to rearrange, so opening the path
/// by name would let them point it anywhere: `~/.config` made a link to `/etc`
/// turns `~/.config/zond` into `/etc/zond`, and a root process changing its
/// owner hands them the host-wide settings. See [`walk_from_home`] for how
/// that is prevented; the home itself is never given.
#[cfg(unix)]
fn open_in_home(user: &InvokingUser, path: &Path) -> io::Result<fs::File> {
    walk_from_home(user, path, false)
}

/// Opens `path`, which must lie inside `user`'s home or, where `home_itself`
/// allows it, be the home, without following a link that leads out of it.
///
/// The path is resolved once, to decide whether it lies in the home at all,
/// which keeps a home whose dotfiles link elsewhere inside it working; and the
/// resolved path is then walked from the home one name at a time, each opened
/// relative to the last and refusing a link, so a name repointed after the
/// check fails the walk rather than redirecting it.
#[cfg(unix)]
fn walk_from_home(user: &InvokingUser, path: &Path, home_itself: bool) -> io::Result<fs::File> {
    let spelled_inside = inside_home(user, path) || (home_itself && path == user.home);
    if !spelled_inside {
        return Err(outside());
    }
    let home = fs::canonicalize(&user.home)?;
    let resolved = fs::canonicalize(path)?;
    let below = resolved
        .strip_prefix(&home)
        .ok()
        .filter(|below| home_itself || !below.as_os_str().is_empty())
        .ok_or_else(outside)?;

    let mut current = fs::File::open(&home)?;
    for component in below.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(outside());
        };
        current = open_at(&current, &c_name(name)?, libc::O_RDONLY, 0)?;
    }
    Ok(current)
}

/// The refusal of a path that is not, or does not stay, inside the invoking
/// user's home.
#[cfg(unix)]
fn outside() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "leads out of the invoking user's home",
    )
}

/// A name as the C calls take it.
#[cfg(unix)]
fn c_name(name: &std::ffi::OsStr) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes()).map_err(io::Error::other)
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

    // SAFETY: `directory` is open for the call or `AT_FDCWD`, and `name` a
    // NUL-terminated string that outlives it; the descriptor returned is owned
    // by the `File` built from it and by nothing else.
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
    // SAFETY: `opened` is a descriptor just opened and owned by nothing else.
    Ok(unsafe { fs::File::from_raw_fd(opened) })
}

/// The platforms with no `sudo`, where what a run creates is already the
/// invoking user's.
#[cfg(not(unix))]
pub(crate) fn give(_path: &Path) {}

/// [`hand_over`], inert for the same reason.
#[cfg(all(not(unix), feature = "import-settings"))]
pub(crate) fn hand_over(_leaf: &Path, _created: &[PathBuf]) {}

/// [`give`]'s handle form, inert for the same reason.
#[cfg(all(not(unix), feature = "journal-format"))]
pub(crate) fn give_open(_opened: &fs::File, _path: &Path) {}

/// Nothing is ever left to root on a platform with no `sudo`.
#[cfg(not(unix))]
pub(crate) fn reclaim(_path: &Path) {}

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

    /// An elevated run creates its journal and settings in the invoking
    /// user's home, whose every name is theirs to place. `~/.local` made a
    /// link to somewhere only root can write would otherwise have root make
    /// directories and files there, and keep them, since nothing outside the
    /// home is given. So a link on the way out of the home is refused, for a
    /// directory and for a file, and nothing appears behind it.
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

    /// The refusal is of leaving the home, not of links: one that stays
    /// inside it, as a dotfiles checkout makes, is followed, and a run on
    /// nobody else's behalf follows its own user's links as any program would.
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

        // A second call has made nothing, and a file where a directory should
        // be is refused, as by `create_dir_all`.
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
