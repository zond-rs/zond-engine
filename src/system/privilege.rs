// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What this process is allowed to send
//!
//! Raw sockets, packet capture and ARP injection all need rights an ordinary
//! process does not have. This module answers whether the current one holds
//! them, so a caller can pick a privileged strategy or fall back to an
//! unprivileged one.
//!
//! ## Two questions, and they are not the same question
//!
//! [`can_send_raw`] asks the operating system for a raw socket and reports
//! whether it got one. [`Privilege`] is what that answer means for a scan, and
//! it is the form the rest of the crate carries: a journal records it and
//! refuses to continue a scan of one kind as a scan of the other.
//!
//! [`is_elevated`] asks something narrower, whether this process is root or
//! holds an elevated token, and it exists for the one caller that needs exactly
//! that: [`journal::paths`](crate::journal::paths), deciding whose home a
//! journal written under `sudo` belongs in.
//!
//! **Asking the second where the first was meant is how a scan degrades for no
//! reason.** Linux gates a raw socket on `CAP_NET_RAW`, which root has and which
//! a binary given `setcap cap_net_raw+ep` also has without being root. That is
//! how a scanner is deployed without handing it the whole machine, and a uid
//! check reports every such run as unprivileged while it would have scanned
//! perfectly well. [`listen`](crate::listen) already answers from the open for
//! the same reason; this is the other two phases doing it.

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
    /// What this process holds, as [`can_send_raw`] reports it.
    ///
    /// The one place the answer becomes the distinction, so the code choosing
    /// how to scan and the code reading the result back cannot disagree about
    /// which answer is which.
    #[must_use]
    pub fn current() -> Self {
        if can_send_raw() {
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

/// Whether this process can open a raw socket, asked by opening one.
///
/// The question every scan phase actually has, and the only way to answer it
/// that is right on both supported platforms. Linux gates raw sockets on
/// `CAP_NET_RAW` rather than on being root, so a binary carrying the capability
/// answers `true` here and `false` to [`is_elevated`]; macOS grants them to root
/// alone, where the two agree.
///
/// Costs one socket, opened and closed. Not cached, because a process that drops
/// its privileges mid-run has changed the answer and should be believed.
#[must_use]
pub fn can_send_raw() -> bool {
    imp::can_send_raw()
}

/// Whether this process is root, or holds an elevated token on Windows.
///
/// Narrower than [`can_send_raw`] and not a substitute for it: this is the
/// question about *who* the process is, which is what deciding whose home a
/// journal belongs in needs. Deciding how to scan needs the other one.
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

    pub fn can_send_raw() -> bool {
        // The exact socket the raw TCP paths open, so what is tested here is
        // what they will be granted rather than a proxy for it.
        //
        // SAFETY: `socket` takes three integers, dereferences nothing, and
        // returns a descriptor or -1.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
        if fd < 0 {
            return false;
        }

        // SAFETY: `fd` was just opened by the call above and is not used again.
        unsafe { libc::close(fd) };
        true
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

    /// Windows has no capability to hold short of elevation, so the two
    /// questions have one answer here.
    pub fn can_send_raw() -> bool {
        is_elevated()
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub fn is_elevated() -> bool {
        false
    }

    pub fn can_send_raw() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two questions are asked separately because they have different
    /// answers, and root is the case where they agree. A run that is root must
    /// see both `true`; a run that is not may still hold the capability, which
    /// is the whole reason `current` no longer asks about the uid.
    #[test]
    fn being_root_answers_both_questions_the_same_way() {
        if is_elevated() {
            assert!(can_send_raw(), "root is granted a raw socket");
            assert_eq!(Privilege::current(), Privilege::Raw);
        } else {
            assert_eq!(
                Privilege::current(),
                Privilege::from_raw(can_send_raw()),
                "the distinction is made in one place"
            );
        }
    }

    /// Opening a socket to answer means the answer must not depend on how often
    /// it is asked.
    #[test]
    fn asking_repeatedly_gives_one_answer() {
        let first = can_send_raw();
        for _ in 0..64 {
            assert_eq!(can_send_raw(), first);
        }
    }
}
