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
//! the reply is whole, the port stops, or the byte cap is reached.
//!
//! The budgets are spent by the callers rather than here. This opens one socket,
//! bounded by the deadline and the cap it is given, and the tier above it decides
//! what a spent budget means.
//!
//! ## When a reply is whole
//!
//! Most of what the corpus speaks is HTTP, and an HTTP response says where it
//! ends: a `Content-Length`, or a chunked body's closing chunk. A reply read to
//! that point is over, whatever the connection then does, so the read stops
//! there. Anything else is read until the peer closes or falls silent, because
//! the bytes alone cannot say whether more is coming.
//!
//! Stopping at the message's own end is what keeps a detection's time budget
//! paying for the target's answers rather than for its idle connections. A
//! server that holds the connection open after replying, whether it ignores the
//! request's `Connection: close` or keeps every connection alive until an idle
//! timeout, would otherwise have each exchange wait out that timeout, or the
//! rest of the detection's budget, for bytes that are never sent. A detection
//! asking four questions of such a server spends its budget on the first few
//! and leaves the rest unasked.

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
    /// the connection, an HTTP message read to the length it declared, or a
    /// whole datagram, rather than being cut short by the byte cap or a read
    /// timeout. Only a complete reply is safe to hand to a second caller that
    /// sent the same request.
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

/// Connects, sends `bytes`, and reads the reply until it is whole, the port
/// falls silent, the connection closes, or `cap` bytes have been read.
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
    let mut whole = false;
    while (reply.len() as u64) < cap {
        let want = ((cap - reply.len() as u64) as usize).min(buffer.len());
        match stream.read(&mut buffer[..want]) {
            Ok(0) => {
                whole = true;
                break;
            }
            Ok(read) => {
                reply.extend_from_slice(&buffer[..read]);
                // A message that has said where it ends and got there is over,
                // whether or not the server lets the connection go.
                if http_message_end(&reply).is_some() {
                    whole = true;
                    break;
                }
            }
            // A read timeout is the ordinary end of a reply that does not close
            // the connection; any other error ends it too.
            Err(_) => break,
        }
    }

    Ok(Reply {
        bytes: reply,
        complete: whole,
    })
}

/// Where the HTTP/1.x response at the start of `reply` ends, once all of it has
/// arrived: [`None`] while it is still arriving, and for anything that does not
/// say where it ends.
///
/// A response ends where its own framing says (RFC 9112 §6.3): after the header
/// block for a status that carries no body, after the closing chunk and its
/// trailers for a chunked body, which takes precedence over any length, and
/// after `Content-Length` bytes otherwise. A response that says none of these
/// is delimited by the connection closing, and so is anything that is not an
/// HTTP response at all; both are left to the caller's read-to-close.
///
/// An interim `1xx` response is not the answer, so it ends nothing here. A
/// `Content-Length` that does not parse, or two that disagree, is a message
/// whose length is not known, and is read to close like one that gave none.
///
/// Bounded by its input: every loop consumes `reply` and stops at its end.
fn http_message_end(reply: &[u8]) -> Option<usize> {
    if !reply.starts_with(b"HTTP/1.") {
        return None;
    }
    let body = find(reply, b"\r\n\r\n")? + 4;
    let head = &reply[..body - 4];

    let status: u16 = std::str::from_utf8(head.get(9..12)?).ok()?.parse().ok()?;
    if status < 200 {
        return None;
    }
    if status == 204 || status == 304 {
        return Some(body);
    }

    let mut length: Option<usize> = None;
    let mut chunked = false;
    for line in head.split(|&byte| byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            continue;
        };
        let (name, value) = (&line[..colon], line[colon + 1..].trim_ascii());
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            // Chunked is the final coding when it is named at all: a sender may
            // not apply another after it.
            chunked = value
                .rsplit(|&byte| byte == b',')
                .next()
                .is_some_and(|last| last.trim_ascii().eq_ignore_ascii_case(b"chunked"));
        } else if name.eq_ignore_ascii_case(b"content-length") {
            let declared: usize = std::str::from_utf8(value).ok()?.parse().ok()?;
            if length.is_some_and(|earlier| earlier != declared) {
                return None;
            }
            length = Some(declared);
        }
    }

    if chunked {
        return chunked_end(&reply[body..]).map(|end| body + end);
    }
    let end = body.checked_add(length?)?;
    (reply.len() >= end).then_some(end)
}

/// Where a chunked body at the start of `body` ends, past its closing
/// zero-length chunk and whatever trailer fields follow it, or [`None`] until
/// that much has arrived.
fn chunked_end(body: &[u8]) -> Option<usize> {
    let mut at = 0;
    loop {
        let line_end = at + find(&body[at..], b"\r\n")?;
        let size_field = &body[at..line_end];
        // A chunk extension follows the size after a `;` and changes nothing
        // about where the chunk ends.
        let digits = size_field.split(|&byte| byte == b';').next()?.trim_ascii();
        let size = usize::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()?;
        at = line_end + 2;
        if size == 0 {
            // The trailer section: fields, if any, then an empty line.
            if body[at..].starts_with(b"\r\n") {
                return Some(at + 2);
            }
            return find(&body[at..], b"\r\n\r\n").map(|end| at + end + 4);
        }
        at = at.checked_add(size)?.checked_add(2)?;
        if at > body.len() {
            return None;
        }
    }
}

/// The offset of the first `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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

#[cfg(test)]
mod tests {
    use super::http_message_end;

    #[test]
    fn a_response_with_a_length_ends_once_that_many_body_bytes_are_in() {
        let whole = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found";
        assert_eq!(http_message_end(whole), Some(whole.len()));
        assert_eq!(http_message_end(&whole[..whole.len() - 1]), None);
        // Before the header block is over nothing is known yet.
        assert_eq!(
            http_message_end(b"HTTP/1.1 404 Not Found\r\nContent-Le"),
            None
        );
    }

    #[test]
    fn header_names_are_matched_whatever_their_case() {
        let whole = b"HTTP/1.0 200 OK\r\ncontent-length:2\r\n\r\nok";
        assert_eq!(http_message_end(whole), Some(whole.len()));
    }

    #[test]
    fn a_chunked_response_ends_after_its_closing_chunk_and_trailers() {
        let whole =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;x=y\r\nwiki\r\n0\r\n\r\n";
        assert_eq!(http_message_end(whole), Some(whole.len()));
        assert_eq!(http_message_end(&whole[..whole.len() - 2]), None);

        let trailed = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-T: 1\r\n\r\n";
        assert_eq!(http_message_end(trailed), Some(trailed.len()));
    }

    /// Chunked framing is the one a recipient follows when a sender gives
    /// both, so a length beside it does not end the message early.
    #[test]
    fn chunked_framing_outranks_a_length_given_beside_it() {
        let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n";
        assert_eq!(http_message_end(reply), None);
    }

    #[test]
    fn a_status_that_carries_no_body_ends_with_its_headers() {
        let reply = b"HTTP/1.1 304 Not Modified\r\nContent-Length: 1234\r\n\r\n";
        assert_eq!(http_message_end(reply), Some(reply.len()));
    }

    /// Each of these is delimited by the connection closing, or is no answer
    /// yet, so the read goes on.
    #[test]
    fn a_reply_that_does_not_say_where_it_ends_is_left_to_the_close() {
        for reply in [
            &b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nbody until close"[..],
            b"HTTP/1.1 100 Continue\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd",
            b"HTTP/1.1 200 OK\r\nContent-Length: many\r\n\r\nabcd",
            b"+OK redis\r\n\r\n",
            b"SSH-2.0-OpenSSH_9.6\r\n",
        ] {
            assert_eq!(
                http_message_end(reply),
                None,
                "{:?}",
                String::from_utf8_lossy(reply)
            );
        }
    }
}
