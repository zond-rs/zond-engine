// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Where a settings file lives
//!
//! Pure computation. Every function here reads environment variables and returns
//! a path; none of them opens anything, checks whether anything exists, or
//! creates anything. A caller can ask where its settings would be without the
//! asking having a side effect, and the engine never touches a filesystem it was
//! not pointed at.
//!
//! ## The locations
//!
//! | | User | System |
//! |---|---|---|
//! | Unix | `$XDG_CONFIG_HOME/zond/engine.toml`, else `$HOME/.config/zond/engine.toml` | `/etc/zond/engine.toml` |
//! | Windows | `%APPDATA%\zond\engine.toml` | `%PROGRAMDATA%\zond\engine.toml` |
//!
//! `zond/` rather than `zond-engine/` because the engine is not the only thing
//! that will want a file there: a front end belongs beside it as `cli.toml` or
//! whatever it calls itself, in one directory a user can find and back up.
//!
//! macOS follows the Unix path rather than `~/Library/Application Support`. The
//! people who write these files reach for `~/.config`, and a scanner's
//! configuration sitting where every other command-line tool's sits is worth more
//! than matching a convention aimed at bundled applications.
//!
//! ## `$XDG_CONFIG_HOME` is only honoured when it is absolute
//!
//! The specification requires it, and it matters more here than elsewhere. A
//! relative value would put a settings file under whatever directory the process
//! happens to be running in, which for a tool run with `sudo` from an arbitrary
//! shell is not a location anybody chose.

use std::path::PathBuf;

use super::FILE_NAME;

/// The directory this crate's configuration lives in, under whatever
/// configuration root applies.
const DIRECTORY: &str = "zond";

/// Where this user's settings file would be.
///
/// `None` when the environment names no home at all, which happens in a
/// container or a daemon with a cleared environment. A caller getting `None`
/// should carry on without a settings file rather than invent a location.
pub fn user() -> Option<PathBuf> {
    user_directory().map(|directory| directory.join(FILE_NAME))
}

/// Where this user's settings *directory* would be.
///
/// `%APPDATA%` is the roaming one: settings are what a person chose and should
/// follow them between machines on a domain, unlike the journal in
/// `%LOCALAPPDATA%`, which is a record of what one machine did.
///
/// Written as two whole functions rather than one with two `cfg` blocks, for the
/// reason `journal::paths::state_root` gives.
#[cfg(windows)]
pub fn user_directory() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .map(|path| path.join(DIRECTORY))
}

/// Where this user's settings *directory* would be: `$XDG_CONFIG_HOME/zond`
/// where that variable names an absolute path, and `$HOME/.config/zond`
/// otherwise.
///
/// `None` when neither variable holds an absolute path, which is what a
/// container or a daemon with a cleared environment looks like. macOS lands
/// here rather than under `~/Library/Application Support`; the module note says
/// why.
#[cfg(not(windows))]
pub fn user_directory() -> Option<PathBuf> {
    // Only an absolute value counts, as the specification requires. A relative
    // one would put the file wherever the process was started.
    if let Some(configured) = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    {
        return Some(configured.join(DIRECTORY));
    }

    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .map(|home| home.join(".config").join(DIRECTORY))
}

/// Where a host-wide settings file would be.
///
/// Read before the user's, so an administrator can set a floor that a user then
/// adjusts. `None` on a platform with no such location named in the
/// environment.
#[cfg(windows)]
pub fn system() -> Option<PathBuf> {
    std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .map(|path| path.join(DIRECTORY).join(FILE_NAME))
}

/// Where a host-wide settings file would be: `/etc/zond/engine.toml`.
///
/// Read before the user's file, so an administrator can set a floor a user then
/// adjusts. Never `None` here; the [`Option`] is for Windows, where the
/// location comes from `%PROGRAMDATA%` and that can be unset.
#[cfg(not(windows))]
pub fn system() -> Option<PathBuf> {
    Some(PathBuf::from("/etc").join(DIRECTORY).join(FILE_NAME))
}

/// Every settings file that may apply, in the order they layer.
///
/// System first, user second, so the user's file has the last word. Paths that
/// could not be computed are absent; nothing here says whether any of them
/// exists.
pub fn layered() -> Vec<PathBuf> {
    [system(), user()].into_iter().flatten().collect()
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

    /// The file is named consistently wherever it lands, and it lands under a
    /// directory a front end can share.
    #[test]
    fn a_computed_path_ends_in_the_expected_directory_and_file() {
        if let Some(path) = user() {
            assert!(path.is_absolute(), "{path:?}");
            assert!(
                path.ends_with(format!("{DIRECTORY}/{FILE_NAME}")),
                "{path:?}"
            );
        }

        if let Some(path) = system() {
            assert!(path.is_absolute(), "{path:?}");
            assert!(
                path.ends_with(format!("{DIRECTORY}/{FILE_NAME}")),
                "{path:?}"
            );
        }
    }

    /// System first, user last, because the user's file has the final word over
    /// an administrator's floor.
    #[test]
    fn the_user_file_layers_after_the_system_one() {
        let paths = layered();

        if let (Some(system), Some(user)) = (system(), user()) {
            let system_at = paths.iter().position(|path| *path == system);
            let user_at = paths.iter().position(|path| *path == user);
            assert!(system_at < user_at, "{paths:?}");
        }
    }

    /// Computing a path must not create, check or open anything. A caller
    /// asking where its settings would be has not asked for a side effect.
    #[test]
    fn computing_a_path_touches_no_filesystem() {
        let before = user().and_then(|path| path.parent().map(std::path::Path::exists));

        let _ = user();
        let _ = user_directory();
        let _ = system();
        let _ = layered();

        let after = user().and_then(|path| path.parent().map(std::path::Path::exists));
        assert_eq!(before, after, "asking where the settings are created them");
    }
}
