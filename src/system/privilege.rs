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
//!
//! [`is_elevated`] is the bit the operating system reports. [`Privilege`] is
//! what that bit means for a scan, and it is the form the rest of the crate
//! carries: a journal records it and refuses to continue a scan of one kind as
//! a scan of the other.

/// Which kind of probe a scan could send, which is what its privileges decide.
///
/// The same finding means different things under the two, so anything that
/// records what a scan did records this beside it. A raw scan chooses its own
/// packets and reads the answers off the wire; a connect scan can only ask the
/// local stack to complete a handshake, and what it does not get back is
/// weaker evidence about the target.
///
/// Deliberately two variants and no more. This is one question with two
/// answers, and a caller that matches on it has covered the whole of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    /// Raw sockets were available, so the scan sent the packets it chose: ARP
    /// and ICMPv6 on the local segment, raw TCP and UDP beyond it.
    ///
    /// A result recorded under this is about the target. The scan set its own
    /// flags, so a port that answered and a port that did not are two different
    /// findings rather than two ways of failing to connect.
    Raw,
    /// Raw sockets were not available, so the scan fell back to ordinary TCP
    /// connect attempts.
    ///
    /// A result recorded under this saw less and was more visible to the
    /// target. Only a completed handshake proves anything, so the states a raw
    /// technique distinguishes collapse, and a scan that reports nothing on a
    /// port may have been told nothing by its own stack.
    Connect,
}

impl Privilege {
    /// What this process holds, as [`is_elevated`] reports it.
    ///
    /// The one place the bit becomes the distinction, so the code choosing how
    /// to scan and the code reading the result back cannot disagree about which
    /// answer is which.
    #[must_use]
    pub fn current() -> Self {
        if is_elevated() {
            Self::Raw
        } else {
            Self::Connect
        }
    }

    /// Whether raw sockets were held.
    ///
    /// For the formats that record this as a boolean, which a journal's
    /// manifest does and cannot stop doing without invalidating what is already
    /// written.
    #[must_use]
    pub fn is_raw(self) -> bool {
        matches!(self, Self::Raw)
    }

    /// The privilege a `true` or `false` on the wire stands for.
    ///
    /// The inverse of [`is_raw`](Self::is_raw), for the two formats that write
    /// this as a boolean: the journal's manifest and the published report
    /// schema, both of which promised a boolean before this type existed and go
    /// on doing so.
    pub fn from_raw(raw: bool) -> Self {
        if raw { Self::Raw } else { Self::Connect }
    }
}

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
