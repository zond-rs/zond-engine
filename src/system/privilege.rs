// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What this process is allowed to send
//!
//! Raw sockets, packet capture and ARP injection need rights an ordinary process
//! does not have. This module answers whether the current one holds them, so a
//! caller can pick a privileged strategy or fall back to an unprivileged one.
//!
//! [`can_send_raw`] and [`can_inject_frames`] ask whether this process can put a
//! packet of its own on the wire, through a raw socket or through the link-layer
//! handle libpcap opens. [`Privilege`] is what those answers mean for a scan; a
//! journal records it and refuses to continue a scan of one kind as the other.
//!
//! The two routes differ on macOS. Raw sockets belong to root, while the BPF
//! devices libpcap opens are often given to a group (Wireshark's ChmodBPF does
//! this). A process in that group can send every frame a scan needs without being
//! able to open a raw socket.
//!
//! [`is_elevated`] asks whether this process is root or holds an elevated token.
//! Its one caller is [`journal::paths`](crate::journal::paths), deciding whose
//! home a journal written under `sudo` belongs in. Do not use it to decide how to
//! scan: Linux gates raw sockets on `CAP_NET_RAW`, which a binary given `setcap
//! cap_net_raw+ep` holds without being root.

/// Which kind of probe a scan could send, as its privileges decide.
///
/// The same finding means different things under the two, so anything that
/// records what a scan did records this beside it. A raw scan chooses its own
/// packets and reads the answers off the wire; a connect scan can only ask the
/// local stack to complete a handshake, and what it does not get back is weaker
/// evidence about the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    /// The scan sent the packets it chose: ARP and ICMPv6 on the local
    /// segment, raw TCP and UDP beyond it, through a raw socket or a link-layer
    /// handle (the packets are the same either way).
    ///
    /// The scan set its own flags, so a port that answered and a port that did
    /// not are distinct findings about the target.
    Raw,
    /// Neither route was open, so the scan fell back to ordinary TCP connect
    /// attempts.
    ///
    /// A result recorded under this saw less and was more visible to the
    /// target. Only a completed handshake proves anything, so the states a raw
    /// technique distinguishes collapse, and silence on a port may come from the
    /// local stack.
    Connect,
}

impl Privilege {
    /// What this process holds, as [`can_send_raw`] and [`can_inject_frames`]
    /// report it. Either route is enough for [`Raw`](Self::Raw).
    #[must_use]
    pub fn current() -> Self {
        if can_send_raw() || can_inject_frames() {
            Self::Raw
        } else {
            Self::Connect
        }
    }

    /// Whether raw sockets were held, for formats that record this as a boolean
    /// (a journal's manifest).
    #[must_use]
    pub fn is_raw(self) -> bool {
        matches!(self, Self::Raw)
    }

    /// The inverse of [`is_raw`](Self::is_raw), for the formats that write this
    /// as a boolean: the journal's manifest and the published report schema.
    pub fn from_raw(raw: bool) -> Self {
        if raw { Self::Raw } else { Self::Connect }
    }
}

/// Whether this process can open a raw socket, asked by opening one.
///
/// Linux gates raw sockets on `CAP_NET_RAW`, so a binary carrying the capability
/// answers `true` here and `false` to [`is_elevated`]; macOS grants them to root
/// alone.
///
/// Costs one socket, opened and closed. Not cached, so a process that drops its
/// privileges mid-run gets the new answer.
#[must_use]
pub fn can_send_raw() -> bool {
    imp::can_send_raw()
}

/// Whether this process can open a link-layer handle and inject frames.
///
/// A scan that cannot open a raw socket can still build its own Ethernet frames
/// and send them; macOS prefers this path and Windows has no other.
///
/// Frames cannot reach a destination with no Ethernet in front of it, so
/// tunnel-only addresses still need a raw socket, as does loopback everywhere but
/// macOS.
#[must_use]
pub fn can_inject_frames() -> bool {
    imp::can_inject_frames()
}

/// Whether this process is root, or holds an elevated token on Windows.
///
/// This is about *who* the process is, for deciding whose home a journal belongs
/// in. Use [`can_send_raw`] to decide how to scan.
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

    /// How many `/dev/bpf` devices to try before giving up.
    ///
    /// They share an owner and a mode, so the first one that exists answers for
    /// all of them. A low-numbered device can be missing on a host that clones
    /// them on demand.
    #[cfg(target_os = "macos")]
    const BPF_DEVICES_TO_TRY: u8 = 4;

    /// Asks the BPF devices the same question libpcap's open will.
    ///
    /// `EBUSY` means permitted (whoever holds the device passed the same
    /// permission check) and `EACCES` means not.
    #[cfg(target_os = "macos")]
    pub fn can_inject_frames() -> bool {
        (0..BPF_DEVICES_TO_TRY).any(|n| {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(format!("/dev/bpf{n}"))
            {
                Ok(_) => true,
                Err(error) => error.kind() == std::io::ErrorKind::ResourceBusy,
            }
        })
    }

    /// Everywhere else the two routes are one permission.
    ///
    /// The packet socket libpcap opens on Linux is gated on the same
    /// `CAP_NET_RAW` as the raw socket.
    #[cfg(not(target_os = "macos"))]
    pub fn can_inject_frames() -> bool {
        can_send_raw()
    }

    pub fn can_send_raw() -> bool {
        // The exact socket the raw TCP paths open.
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

    /// Follows elevation, even where Npcap lets non-administrators capture, so an
    /// unelevated run takes the connect path on every Windows machine.
    pub fn can_inject_frames() -> bool {
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

    pub fn can_inject_frames() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Root must see both `true`; a non-root run may still hold the capability.
    #[test]
    fn being_root_answers_both_questions_the_same_way() {
        if is_elevated() {
            assert!(can_send_raw(), "root is granted a raw socket");
            assert_eq!(Privilege::current(), Privilege::Raw);
        } else {
            assert_eq!(
                Privilege::current(),
                Privilege::from_raw(can_send_raw() || can_inject_frames()),
                "the distinction is made in one place"
            );
        }
    }

    /// A raw socket implies the link-layer handle everywhere the two are one
    /// permission, and on macOS because root may open anything. The converse
    /// does not hold.
    #[test]
    fn a_raw_socket_implies_frame_injection() {
        if can_send_raw() {
            assert!(can_inject_frames());
        }
    }

    /// Either route answering yes is enough to scan with chosen packets.
    #[test]
    fn either_route_is_privilege_enough() {
        if can_inject_frames() {
            assert_eq!(Privilege::current(), Privilege::Raw);
        }
    }

    /// The answer must not depend on how often it is asked.
    #[test]
    fn asking_repeatedly_gives_one_answer() {
        let first = can_send_raw();
        for _ in 0..64 {
            assert_eq!(can_send_raw(), first);
        }
    }
}
