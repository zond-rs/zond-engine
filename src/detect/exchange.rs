// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # One request and its reply, over a socket to the scanned port
//!
//! What both detection tiers reach the network through. A flow's
//! [`Probe`](super::flow::Probe) hands back a bare absence and a compute module's
//! [`Capabilities`](super::compute::Capabilities) hands back a typed error the
//! module may catch, and those are two seams over the same exchange: connect,
//! wrap the socket in the transport the port answered inside, send, read until
//! the port stops or the byte cap is reached.
//!
//! The budgets are spent by the callers rather than here. This opens one socket,
//! bounded by the deadline and the cap it is given, and the tier above it decides
//! what a spent budget means.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::config::limits::CONNECT_PROBE_TIMEOUT;
use crate::fingerprint::Tunnel;

/// The largest datagram a UDP reply is read into, the theoretical maximum
/// payload of one.
const LARGEST_DATAGRAM: u64 = 65_535;

/// What a port said, and whether that is the whole of it.
pub(crate) struct Reply {
    /// The bytes read back. Empty when the port stayed silent.
    pub(crate) bytes: Vec<u8>,
    /// Whether the reply reached a self-terminating end, a TCP peer that closed
    /// the connection or a whole datagram, rather than being cut short by the
    /// byte cap or a read timeout. Only a complete reply is safe to hand to a
    /// second caller that sent the same request.
    pub(crate) complete: bool,
}

/// Why an exchange produced nothing.
///
/// Kept apart from [`CapError`](super::compute::CapError) so that this module
/// owes nothing to either tier's seam. The compute tier converts; the flow tier
/// discards, because a flow's probe reports absence rather than cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExchangeError {
    /// The deadline passed, or a read waited out what was left of it.
    TimedOut,
    /// The port answered a connection attempt with a refusal.
    ConnectionRefused,
    /// The connection failed, or a TLS handshake could not be set up over it.
    Reset,
}

impl ExchangeError {
    /// Which error an I/O failure surfaces as.
    fn of(error: &std::io::Error) -> Self {
        match error.kind() {
            ErrorKind::TimedOut | ErrorKind::WouldBlock => Self::TimedOut,
            ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            _ => Self::Reset,
        }
    }
}

/// The time left before `deadline`, or [`None`] once it has passed.
///
/// Every socket timeout is drawn from this, so no exchange outlives the budget
/// of whatever asked for it.
pub(crate) fn remaining(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

/// Connects, sends `bytes`, and reads the reply until the port falls silent, the
/// connection closes, or `cap` bytes have been read.
///
/// A `tunnel` wraps the connected socket in the transport the port answered
/// inside before a byte of the probe is sent, so an `ssl/*` service is reached
/// through a handshake and every other port in the clear. A handshake that
/// cannot be set up is a reset; one that fails to complete surfaces as the first
/// read or write erroring, like any other broken port.
///
/// A silent port is an empty reply rather than an error. What that means belongs
/// to the caller.
pub(crate) fn tcp(
    addr: SocketAddr,
    tunnel: Option<Tunnel>,
    bytes: &[u8],
    deadline: Instant,
    cap: u64,
) -> Result<Reply, ExchangeError> {
    let timeout = remaining(deadline).ok_or(ExchangeError::TimedOut)?;
    let tcp = TcpStream::connect_timeout(&addr, timeout.min(CONNECT_PROBE_TIMEOUT))
        .map_err(|error| ExchangeError::of(&error))?;
    tcp.set_read_timeout(Some(remaining(deadline).ok_or(ExchangeError::TimedOut)?))
        .map_err(|error| ExchangeError::of(&error))?;
    let mut stream = super::tls::wrap(tcp, addr.ip(), tunnel).ok_or(ExchangeError::Reset)?;
    stream
        .write_all(bytes)
        .map_err(|error| ExchangeError::of(&error))?;

    let mut reply = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut closed = false;
    while (reply.len() as u64) < cap {
        let want = ((cap - reply.len() as u64) as usize).min(buffer.len());
        match stream.read(&mut buffer[..want]) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(read) => reply.extend_from_slice(&buffer[..read]),
            // A read timeout is the ordinary end of a reply that does not close
            // the connection; any other error ends it too.
            Err(_) => break,
        }
    }

    Ok(Reply {
        bytes: reply,
        complete: closed,
    })
}

/// Sends one datagram and reads one reply, capped at `cap` bytes.
///
/// A datagram is one whole message, so a reply that arrives is complete. Silence
/// is an empty reply, as it is over TCP.
pub(crate) fn udp(
    addr: SocketAddr,
    bytes: &[u8],
    deadline: Instant,
    cap: u64,
) -> Result<Reply, ExchangeError> {
    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind).map_err(|error| ExchangeError::of(&error))?;
    socket
        .connect(addr)
        .map_err(|error| ExchangeError::of(&error))?;
    socket
        .set_read_timeout(Some(remaining(deadline).ok_or(ExchangeError::TimedOut)?))
        .map_err(|error| ExchangeError::of(&error))?;
    socket
        .send(bytes)
        .map_err(|error| ExchangeError::of(&error))?;

    let mut buffer = vec![0u8; cap.min(LARGEST_DATAGRAM) as usize];
    match socket.recv(&mut buffer) {
        Ok(read) => {
            buffer.truncate(read);
            Ok(Reply {
                bytes: buffer,
                complete: true,
            })
        }
        Err(error)
            if error.kind() == ErrorKind::TimedOut || error.kind() == ErrorKind::WouldBlock =>
        {
            Ok(Reply {
                bytes: Vec::new(),
                complete: true,
            })
        }
        Err(error) => Err(ExchangeError::of(&error)),
    }
}
