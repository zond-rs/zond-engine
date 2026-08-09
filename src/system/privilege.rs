// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process privilege detection across target Operating Systems.
//!
//! Raw sockets, packet capture, and ARP injection all require elevated rights.
//! This module answers whether the current process holds them, so callers can
//! pick a privileged strategy or fall back to an unprivileged one.

/// Returns `true` when the current process holds the privileges required to
/// open raw sockets.
///
/// On unix this is an effective UID of 0, matching the check the kernel itself
/// applies. On Windows it is an elevated process token. Any other platform
/// reports `false`.
#[must_use]
pub fn is_elevated() -> bool {
    imp::is_elevated()
}

#[cfg(unix)]
mod imp {
    pub fn is_elevated() -> bool {
        // SAFETY: `geteuid` takes no arguments, dereferences nothing, and is
        // specified as always succeeding.
        unsafe { libc::geteuid() == 0 }
    }
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub fn is_elevated() -> bool {
        let mut token: HANDLE = std::ptr::null_mut();

        // SAFETY: `GetCurrentProcess` returns a pseudo-handle needing no cleanup,
        // and `token` is a valid out-pointer left untouched on failure.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;

        // SAFETY: `token` is a live handle opened with TOKEN_QUERY, and the
        // buffer matches the size and layout expected for `TokenElevation`.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                (&raw mut elevation).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        } != 0;

        // SAFETY: `token` was opened successfully above and is not used again.
        unsafe { CloseHandle(token) };

        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub fn is_elevated() -> bool {
        false
    }
}
