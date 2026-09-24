// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How often Windows may resend a connection's SYN
//!
//! A connect probe reads a closed port from the refusal its connect returns,
//! and on Unix that refusal comes back with the first reset. Windows does not
//! take a reset to a SYN as final: it resends the SYN, about every half second,
//! until its SYN retransmissions run out, and reports the refusal only after
//! the last one is reset too. With the stack's default count that is around two
//! seconds per closed port, past
//! [`CONNECT_PROBE_TIMEOUT`](crate::config::limits::CONNECT_PROBE_TIMEOUT), so
//! every closed port would be recorded as a silent, filtered one.
//!
//! Every other connection the engine makes waits on a budget of the same size
//! and reads a refusal the same way. The service pass dials ports the scan
//! found open, and one that closed in between has to read as refused rather
//! than as silence; a TLS enumeration and a detection's exchange end a walk on
//! a refusal they would otherwise wait out. So the limit goes on every TCP
//! socket the engine opens, which is why it is set where they are all built.
//!
//! The count is the one thing to change, and `SIO_TCP_INITIAL_RTO` sets it per
//! socket, before the connect, without privilege. The same count also governs
//! a SYN that is genuinely lost, and that retransmission is the one the
//! connect budget exists to wait for. So each connection keeps exactly one
//! retransmission:
//! a lost SYN is resent at the stack's first retransmission timeout as it
//! would be on Unix, the retransmissions given up would all have left after
//! the budget had expired, and a refusal comes back at the second reset rather
//! than the last. Only loopback gives the one up, because loopback has no
//! medium to lose a SYN on: there a retransmission can only ever be answered by
//! the reset the first one got, so the refusal is taken at once.
//!
//! The round trip estimate the retransmission timeout is computed from is left
//! as the host's administrator configured it, since that timeout is the one the
//! connect budget is set against.
//!
//! `TCP_MAXRT`, the other per-socket knob, is the wrong tool: it caps the
//! connect attempt in whole seconds and ends it as a timeout, so a refused port
//! would still fail as silence, only sooner.

use std::net::IpAddr;

/// The `MaxSynRetransmissions` value that asks for no SYN retransmission at
/// all, `TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS` in `mstcpip.h`.
///
/// The header spells it as a 16-bit `-2` while the field it goes in is a byte,
/// so what reaches the stack is its low byte. Zero cannot say "none": to the
/// stack a zero asks for the system default.
const NO_SYN_RETRANSMISSIONS: u8 = 0xFE;

/// How many times the stack may resend a connection's SYN to `target` before
/// it gives the connect up.
fn syn_retransmissions(target: IpAddr) -> u8 {
    if target.to_canonical().is_loopback() {
        0
    } else {
        1
    }
}

/// The `MaxSynRetransmissions` value that asks for `count` retransmissions.
fn max_syn_retransmissions(count: u8) -> u8 {
    match count {
        0 => NO_SYN_RETRANSMISSIONS,
        count => count,
    }
}

/// Limits the SYN retransmissions of `socket`, about to connect to `target`,
/// to the count [`syn_retransmissions`] gives.
///
/// A stack that refuses the request leaves the socket as it was, and the
/// connection goes ahead on the stack's own count: a connect that reports
/// closed ports as filtered is still a better answer than none. That is said
/// once per process, as a decision behind the result, since every connection
/// after the first would only repeat it.
#[cfg(windows)]
pub(super) fn limit(socket: &socket2::Socket, target: IpAddr) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        SIO_TCP_INITIAL_RTO, SOCKET, SOCKET_ERROR, TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS,
        TCP_INITIAL_RTO_PARAMETERS, WSAIoctl,
    };

    const _: () = assert!(TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS & 0xFF == 0xFE);

    /// `TCP_INITIAL_RTO_UNSPECIFIED_RTT`: leave the round trip estimate to the
    /// administrator's setting. `windows-sys` does not carry it.
    const UNSPECIFIED_RTT: u16 = u16::MAX;

    let parameters = TCP_INITIAL_RTO_PARAMETERS {
        Rtt: UNSPECIFIED_RTT,
        MaxSynRetransmissions: max_syn_retransmissions(syn_retransmissions(target)),
    };
    let mut returned = 0u32;

    // SAFETY: the socket is live for the call, the input buffer is a local of
    // the layout the control code expects and its size is passed with it, the
    // output buffer is empty as the control code requires, and `returned` is a
    // valid out-pointer. No overlapped structure is passed, so the call
    // completes before it returns and nothing outlives it.
    let result = unsafe {
        WSAIoctl(
            socket.as_raw_socket() as SOCKET,
            SIO_TCP_INITIAL_RTO,
            (&raw const parameters).cast(),
            size_of::<TCP_INITIAL_RTO_PARAMETERS>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if result == SOCKET_ERROR {
        let error = std::io::Error::last_os_error();
        static SAID: std::sync::Once = std::sync::Once::new();
        SAID.call_once(|| {
            crate::logging::warn!(
                verbosity = 1,
                "SYN retransmissions left at the system default ({error}), so closed ports may read as filtered"
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Loopback cannot lose a SYN, so a retransmission there only buys a
    /// second reset and delays a closed port's refusal past the probe budget.
    #[test]
    fn a_loopback_probe_takes_its_refusal_from_the_first_reset() {
        for target in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
        ] {
            assert_eq!(syn_retransmissions(target), 0, "{target}");
        }
    }

    /// Across a real link the first SYN can be lost, and the probe budget is
    /// set to wait for exactly one retransmission of it. Zero would report
    /// every briefly slow host as filtered; more would only delay a refusal.
    #[test]
    fn a_remote_probe_keeps_one_retransmission() {
        for target in [
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ] {
            assert_eq!(syn_retransmissions(target), 1, "{target}");
        }
    }

    /// The stack reads a zero as "the system default", which on Windows means
    /// several retransmissions; asking for none takes the dedicated value.
    #[test]
    fn no_retransmission_is_asked_for_by_its_own_value_rather_than_zero() {
        assert_eq!(max_syn_retransmissions(0), NO_SYN_RETRANSMISSIONS);
        assert_eq!(max_syn_retransmissions(1), 1);
    }
}
