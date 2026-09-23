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
//! [`can_send_raw`] and [`can_inject_frames`] ask whether this process can put
//! a packet of its own on the wire, by the two routes there are: a raw socket,
//! or the link-layer handle libpcap opens. [`Privilege`] is what those answers
//! mean for a scan, and it is the form the rest of the crate carries: a journal
//! records it and refuses to continue a scan of one kind as a scan of the
//! other.
//!
//! The two routes come apart on macOS. A raw socket there belongs to root and
//! there is no capability to hand one out, while the BPF devices libpcap opens
//! are routinely given to a group instead, which is what Wireshark's ChmodBPF
//! installs. A process in that group can build and send every frame a scan
//! needs and still cannot open a raw socket, so asking only the first question
//! calls that run unprivileged and drops it to connect scanning with the whole
//! link-layer path sitting unused beside it.
//!
//! [`is_elevated`] asks something narrower, whether this process is root or
//! holds an elevated token, and it exists for the one caller that needs exactly
//! that: [`journal::paths`](crate::journal::paths), deciding whose home a
//! journal written under `sudo` belongs in.
//!
//! Asking the second where the first was meant is how a scan degrades for no
//! reason. Linux gates a raw socket on `CAP_NET_RAW`, which root has and which
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
    /// The scan sent the packets it chose: ARP and ICMPv6 on the local
    /// segment, raw TCP and UDP beyond it. A raw socket or a link-layer handle
    /// carried them, which a result does not distinguish because the packets
    /// are the same either way.
    ///
    /// A result recorded under this is about the target. The scan set its own
    /// flags, so a port that answered and a port that did not are two different
    /// findings rather than two ways of failing to connect.
    Raw,
    /// Neither route was open, so the scan fell back to ordinary TCP connect
    /// attempts.
    ///
    /// A result recorded under this saw less and was more visible to the
    /// target. Only a completed handshake proves anything, so the states a raw
    /// technique distinguishes collapse, and a scan that reports nothing on a
    /// port may have been told nothing by its own stack.
    Connect,
}

impl Privilege {
    /// What this process holds, as [`can_send_raw`] and [`can_inject_frames`]
    /// report it.
    ///
    /// The one place the answer becomes the distinction, so the code choosing
    /// how to scan and the code reading the result back cannot disagree about
    /// which answer is which. Either route is enough, because what the rest of
    /// the crate asks this is whether a scan may choose its own packets.
    #[must_use]
    pub fn current() -> Self {
        if can_send_raw() || can_inject_frames() {
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

/// Whether this process can open a link-layer handle and inject frames.
///
/// The other half of [`can_send_raw`]: a scan that cannot open a raw socket can
/// still build its own Ethernet frames and put them on the wire, which is the
/// path macOS takes by preference and Windows takes by necessity.
///
/// What it cannot carry is a destination with no Ethernet in front of it, so
/// loopback and tunnel-only addresses still want a raw socket.
#[must_use]
pub fn can_inject_frames() -> bool {
    imp::can_inject_frames()
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

    /// How many `/dev/bpf` devices to try before giving up.
    ///
    /// They share an owner and a mode, so the first one that exists answers the
    /// permission question for all of them. The range is here only because a
    /// low-numbered device can be missing on a host that clones them on demand.
    #[cfg(target_os = "macos")]
    const BPF_DEVICES_TO_TRY: u8 = 4;

    /// Asks the BPF devices the same question libpcap's open will.
    ///
    /// A busy device answers it as well as a free one: whoever holds it got
    /// through the same permission check this process is being measured
    /// against, so `EBUSY` means permitted and `EACCES` means not.
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
    /// The packet socket libpcap opens on Linux is gated on the `CAP_NET_RAW`
    /// that gates the raw socket, so a process holding one holds the other and
    /// a separate probe would only cost an open to learn what is already known.
    #[cfg(not(target_os = "macos"))]
    pub fn can_inject_frames() -> bool {
        can_send_raw()
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

    /// Follows elevation with the rest. Npcap can be installed so that
    /// non-administrators may capture, and whether a run takes the frame path
    /// should not depend on how it was: an unelevated run takes the connect
    /// path on every Windows machine.
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

    /// The two questions are asked separately because they have different
    /// answers, and root is the case where they agree. A run that is root must
    /// see both `true`; a run that is not may still hold the capability, which
    /// is the whole reason `current` does not ask about the uid.
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
    /// permission, and on macOS it implies it because root may open anything.
    /// The converse does not hold, which is the whole reason both are asked.
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
