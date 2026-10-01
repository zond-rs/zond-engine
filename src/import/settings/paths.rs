// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Where a settings file lives
//!
//! Pure computation. Every function here reads environment variables, and under
//! `sudo` the password database, and returns a path. Nothing is opened, checked
//! for existence or created.
//!
//! ## The locations
//!
//! | | User | System |
//! |---|---|---|
//! | Unix | `$XDG_CONFIG_HOME/zond/engine.toml`, else `~/.config/zond/engine.toml` | `/etc/zond/engine.toml` |
//! | Windows | `%APPDATA%\zond\engine.toml` | `%PROGRAMDATA%\zond\engine.toml` |
//!
//! The directory is `zond/` so a front end can keep its own file (`cli.toml`,
//! say) beside the engine's.
//!
//! macOS uses the Unix path, where command-line tools keep their configuration,
//! and not `~/Library/Application Support`.
//!
//! ## Under `sudo`, the settings are the invoking user's
//!
//! `~` is the home of the user a run is on behalf of. Most scans run under
//! `sudo`, which on Linux points `HOME` at root's home, and since a missing
//! settings file is not an error, every exclusion and profile the user wrote
//! would silently vanish. So an elevated process reads the invoking user's
//! file, found from `SUDO_UID` and the password database the same way
//! `journal::paths` finds that user's journals.
//!
//! This hands the user nothing the command line did not already give them: the
//! file's vocabulary names no path and no command, and `sudo` sets `SUDO_UID`
//! itself, so a user cannot point an elevated run at somebody else's file.
//!
//! A configuration root that survived into the elevated process still wins, as
//! it does for the journal: somebody kept it on purpose, and an unelevated run
//! reads it too.
//!
//! ## `$XDG_CONFIG_HOME` is only honoured when it is absolute
//!
//! The XDG specification requires this. A relative value would resolve against
//! whatever directory the process happens to run in.

use std::path::PathBuf;

use super::FILE_NAME;

/// The directory this crate's configuration lives in, under the configuration
/// root.
const DIRECTORY: &str = "zond";

/// Where this user's settings file would be.
///
/// `None` when the environment names no home at all, as in a container or a
/// daemon with a cleared environment. A caller getting `None` should carry on
/// without a settings file.
pub fn user() -> Option<PathBuf> {
    user_directory().map(|directory| directory.join(FILE_NAME))
}

/// Where this user's settings *directory* would be.
///
/// `%APPDATA%` is the roaming one, so settings follow a person between machines
/// on a domain. The journal, a record of what one machine did, lives in
/// `%LOCALAPPDATA%`.
///
/// Two whole functions per platform, for the reason `journal::paths::state_root`
/// gives.
#[cfg(windows)]
pub fn user_directory() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .map(|path| path.join(DIRECTORY))
}

/// Where this user's settings *directory* would be: `$XDG_CONFIG_HOME/zond`
/// where that variable names an absolute path, otherwise `.config/zond` under
/// the home directory (the invoking user's under `sudo`, `$HOME` otherwise).
///
/// `None` when no home can be found, as in a container or a daemon with a
/// cleared environment. macOS uses this path too.
#[cfg(not(windows))]
pub fn user_directory() -> Option<PathBuf> {
    crate::journal::paths::base_directory("XDG_CONFIG_HOME", std::path::Path::new(".config"))
        .map(|root| root.join(DIRECTORY))
}

/// [`user_directory`]'s choice from explicit values, so a test can put it under
/// `sudo`.
#[cfg(all(test, not(windows)))]
fn choose(
    configured: Option<PathBuf>,
    invoking_home: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Option<PathBuf> {
    crate::journal::paths::choose(
        configured,
        invoking_home,
        home,
        std::path::Path::new(".config"),
    )
    .map(|root| root.join(DIRECTORY))
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
/// adjusts. Always `Some` on Unix; the [`Option`] is for Windows, where
/// `%PROGRAMDATA%` can be unset.
#[cfg(not(windows))]
pub fn system() -> Option<PathBuf> {
    Some(PathBuf::from("/etc").join(DIRECTORY).join(FILE_NAME))
}

/// Every settings file that may apply, in the order they layer.
///
/// System first, user second, so the user's file has the last word. Paths that
/// could not be computed are absent; the rest may or may not exist.
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

    /// The file lands under the shared `zond` directory.
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

    /// The user's file has the final word over an administrator's floor.
    #[test]
    fn the_user_file_layers_after_the_system_one() {
        let paths = layered();

        if let (Some(system), Some(user)) = (system(), user()) {
            let system_at = paths.iter().position(|path| *path == system);
            let user_at = paths.iter().position(|path| *path == user);
            assert!(system_at < user_at, "{paths:?}");
        }
    }

    /// Computing a path must not create, check or open anything.
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

    /// Under `sudo` the invoking user's settings apply, not those in root's
    /// home, where a plain `sudo` on Linux points `HOME`.
    #[cfg(not(windows))]
    #[test]
    fn under_sudo_the_invoking_users_settings_are_the_ones_found() {
        let user = PathBuf::from("/home/user");
        let root = PathBuf::from("/root");
        let configured = PathBuf::from("/config");

        assert_eq!(
            choose(None, Some(user.clone()), Some(root.clone())),
            Some(user.join(".config").join(DIRECTORY)),
            "an elevated run read root's settings"
        );

        // A configuration root that survived elevation was kept on purpose.
        assert_eq!(
            choose(Some(configured.clone()), Some(user.clone()), Some(root)),
            Some(configured.join(DIRECTORY))
        );

        // Nothing elevated: this process's own home.
        assert_eq!(
            choose(None, None, Some(user.clone())),
            Some(user.join(".config").join(DIRECTORY))
        );
        assert_eq!(choose(None, None, None), None);
    }
}
