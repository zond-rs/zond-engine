// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Creating a file inside a journal
//!
//! Two things that must not be separated: the mode it is created with, and who
//! it then belongs to.
//!
//! A journal holds the addresses an engagement was pointed at, so every file is
//! `0600` from creation rather than chmod'd after — and when the scan ran under
//! `sudo`, it is given to the user who invoked it rather than left to root.
//! [`paths`](super::paths) explains why the journal goes to the invoking user's
//! home; this is the other half of that answer, without which it goes to their
//! home and stays unreadable to them.
//!
//! **They live together because separating them cost exactly that.** The cursor
//! had its own copy of the mode and none of the ownership, so a sweep run with
//! `sudo` left `cursor.json` owned by root beside a manifest and findings owned
//! by the user. An unprivileged listing could read the plan and not the
//! progress, and reported every scan as untouched.

use std::fs;
use std::path::Path;

/// Creates or truncates a file in a journal: private, and the invoking user's.
///
/// The mode is set as the file is created rather than after, so there is no
/// moment where what a scan is recording can be read by anyone else. The
/// directory is `0700` as well, which would cover it either way — this is the
/// belt to that pair of braces, and it costs one flag.
pub(super) fn create_private(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let file = options.open(path)?;
    claim_for_invoking_user(path);
    Ok(file)
}

/// Creates a file that must not already exist: private, and the invoking
/// user's.
///
/// [`create_private`] for the case where existing is the failure rather than
/// something to truncate — a lock, whose whole job is to be refused when
/// somebody else got there first.
pub(super) fn create_exclusive(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let file = options.open(path)?;
    claim_for_invoking_user(path);
    Ok(file)
}

/// Gives something a journal wrote under `sudo` to the user who invoked it.
///
/// Best effort: a journal left owned by root is one they can neither read nor
/// prune, which is worth trying to avoid and not worth failing a scan over.
///
/// Called for directories too, which is why it is separate from
/// [`create_private`] as well as inside it.
#[cfg(unix)]
pub(super) fn claim_for_invoking_user(path: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let Some(user) = super::paths::invoking_user() else {
        return;
    };
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };

    // SAFETY: `c_path` is a live NUL-terminated string for the call's duration,
    // and `chown` reads it and nothing else.
    unsafe {
        libc::chown(c_path.as_ptr(), user.uid, user.gid);
    }
}

#[cfg(not(unix))]
pub(super) fn claim_for_invoking_user(_path: &Path) {}
