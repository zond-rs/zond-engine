// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How often Windows may resend a connection's SYN
//!
//! A connect probe reads a closed port from the refusal its connect returns, and on
//! Unix that comes with the first reset. Windows resends a SYN that drew a reset,
//! about every half second, until its SYN retransmissions run out, and reports the
//! refusal only after the last one is reset too. With the default count that is about
//! two seconds per closed port, past
//! [`CONNECT_PROBE_TIMEOUT`](crate::config::limits::CONNECT_PROBE_TIMEOUT), so every
//! closed port would be recorded as `NoReply`.
//!
//! Every other connection the engine makes waits on a budget of the same size and
//! reads a refusal the same way: the service pass dials ports found open, which may
//! have closed since, and a TLS enumeration or a detection's exchange ends a walk on a
//! refusal. So the limit is set on every TCP socket the engine opens, where they are
//! all built.
//!
//! `SIO_TCP_INITIAL_RTO` sets the count per socket, before the connect, without
//! privilege. The count also governs a SYN that is really lost, which is the
//! retransmission the connect budget waits for, so each connection keeps exactly one:
//! a lost SYN is resent at the first retransmission timeout as on Unix, the dropped
//! retransmissions would all have left after the budget expired, and a refusal comes
//! back at the second reset. Loopback keeps none, since it cannot lose a SYN: a
//! retransmission there can only draw another reset.
//!
//! The round trip estimate the retransmission timeout is computed from stays as the
//! administrator configured it, since the connect budget is set against that timeout.
//!
//! `TCP_MAXRT`, the other per-socket knob, caps the connect in whole seconds and ends
//! it as a timeout, so a refused port would still read as silence, only sooner.

use std::net::IpAddr;

/// The `MaxSynRetransmissions` value that asks for no SYN retransmission,
/// `TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS` in `mstcpip.h`.
///
/// The header spells it as a 16-bit `-2` while the field is a byte, so the stack sees
/// its low byte. Zero would ask for the system default.
const NO_SYN_RETRANSMISSIONS: u8 = 0xFE;

/// How many times the stack may resend a connection's SYN to `target` before it gives
/// up the connect.
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

/// Limits the SYN retransmissions of `socket`, about to connect to `target`, to the
/// count [`syn_retransmissions`] gives.
///
/// If the stack refuses, the connection goes ahead on its own count: a connect that
/// reports closed ports as silent is better than none. Logged once per process.
#[cfg(windows)]
pub(super) fn limit(socket: &socket2::Socket, target: IpAddr) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        SIO_TCP_INITIAL_RTO, SOCKET, SOCKET_ERROR, TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS,
        TCP_INITIAL_RTO_PARAMETERS, WSAIoctl,
    };

    const _: () = assert!(TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS & 0xFF == 0xFE);

    /// `TCP_INITIAL_RTO_UNSPECIFIED_RTT`: leave the round trip estimate to the
    /// administrator's setting. Missing from `windows-sys`.
    const UNSPECIFIED_RTT: u16 = u16::MAX;

    let parameters = TCP_INITIAL_RTO_PARAMETERS {
        Rtt: UNSPECIFIED_RTT,
        MaxSynRetransmissions: max_syn_retransmissions(syn_retransmissions(target)),
    };
    let mut returned = 0u32;

    // SAFETY: the socket is live for the call, the input buffer is a local with the
    // layout the control code expects and its size is passed with it, the output
    // buffer is empty as required, and `returned` is a valid out-pointer. No
    // overlapped structure is passed, so the call completes before it returns.
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
                "SYN retransmissions left at the system default ({error}), so closed ports may read as no reply"
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Loopback cannot lose a SYN, so a retransmission there only buys a second reset
    /// and delays a closed port's refusal past the probe budget.
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

    /// Across a real link the first SYN can be lost, and the probe budget waits for
    /// exactly one retransmission. Zero would report every briefly slow host as
    /// silent; more would only delay a refusal.
    #[test]
    fn a_remote_probe_keeps_one_retransmission() {
        for target in [
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ] {
            assert_eq!(syn_retransmissions(target), 1, "{target}");
        }
    }

    /// The stack reads zero as the system default, which on Windows means several
    /// retransmissions; asking for none takes the dedicated value.
    #[test]
    fn no_retransmission_is_asked_for_by_its_own_value_rather_than_zero() {
        assert_eq!(max_syn_retransmissions(0), NO_SYN_RETRANSMISSIONS);
        assert_eq!(max_syn_retransmissions(1), 1);
    }
}
