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
//! there. Anything else is read until the peer closes, or, once it has said
//! something, until it has been quiet for an [idle gap](idle_gap): the bytes
//! alone cannot say whether more is coming, but a port that answered and then
//! went quiet has, for any purpose a detection has, finished answering.
//!
//! Stopping at the message's own end is what keeps a detection's time budget
//! paying for the target's answers rather than for its idle connections. A
//! server that holds the connection open after replying, whether it ignores the
//! request's `Connection: close`, keeps every connection alive until an idle
//! timeout, or, like redis and memcached, waits on the same connection for the
//! next command, would otherwise have each exchange wait out that timeout, or
//! the rest of the detection's budget, for bytes that are never sent. A
//! detection asking four questions of such a server spends its budget on the
//! first few and leaves the rest unasked.

use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::config::limits::CONNECT_PROBE_TIMEOUT;
use crate::fingerprint::Tunnel;
use crate::system::dial::Egress;

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

/// Connects by `egress`, sends `bytes`, and reads the reply until it is whole,
/// the connection closes, the port falls silent, or `cap` bytes have been read.
/// Silent means no first byte before the deadline, or no further byte for the
/// [idle gap](idle_gap) once the port has begun to answer.
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
    egress: Egress,
    tunnel: Option<Tunnel>,
    bytes: &[u8],
    deadline: Instant,
    cap: u64,
) -> Result<Reply, ExchangeError> {
    let timeout = remaining(deadline).ok_or(ExchangeError::TimedOut)?;
    let tcp = egress
        .connect_within(addr, timeout.min(CONNECT_PROBE_TIMEOUT))
        .map_err(|error| ExchangeError::of(&error))?;
    tcp.set_read_timeout(Some(remaining(deadline).ok_or(ExchangeError::TimedOut)?))
        .map_err(|error| ExchangeError::of(&error))?;
    // A second handle on the same socket, kept to shorten the read timeout
    // once the reply has begun: a timeout is the socket's, so it holds under a
    // TLS session as it does in the clear.
    let socket = tcp.try_clone().map_err(|error| ExchangeError::of(&error))?;
    let mut stream = super::tls::wrap(tcp, addr.ip(), tunnel).ok_or(ExchangeError::Reset)?;
    let sent = Instant::now();
    stream
        .write_all(bytes)
        .map_err(|error| ExchangeError::of(&error))?;

    let mut reply = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut whole = false;
    let mut gap = None;
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
                // Once the port has begun to answer, it has only as long as the
                // idle gap to go on doing so, and never past the deadline.
                let Some(left) = remaining(deadline) else {
                    break;
                };
                let gap = *gap.get_or_insert_with(|| idle_gap(sent.elapsed(), left));
                if socket.set_read_timeout(Some(gap.min(left))).is_err() {
                    break;
                }
            }
            // A read timeout is the ordinary end of a reply that does not close
            // the connection, whether the port went quiet after answering or the
            // deadline came first; any other error ends it too. Neither is a
            // self-terminating end, so the reply is not whole.
            Err(_) => break,
        }
    }

    Ok(Reply {
        bytes: reply,
        complete: whole,
    })
}

/// How long a port that has begun to answer may go quiet before its reply is
/// taken as over, given how long it took to begin and how much of the deadline
/// was left when it did.
///
/// Only a reply that neither closes the connection nor says where it ends
/// relies on this, and the gap has to outlast the pauses a live service makes
/// in the middle of one, while leaving the rest of the caller's budget for its
/// next question. Each of the three terms answers one of those:
///
/// - Twice the wait for the first byte. A reply larger than the sender's first
///   flight pauses one round trip for acknowledgements, and a server that
///   writes in pieces pauses on its own work between them. The first byte's
///   wait held both, the round trip and the server's thought, so twice it
///   covers a pause of either kind with a margin of one more.
/// - A quarter of the time left. A speak-first service greets before it has
///   read the request, so its first byte says nothing about how long the
///   answer to the request takes; this lets that answer take a good share of
///   what the caller can spare. A quarter, because a caller asking question
///   after question of a port that holds every connection open keeps three
///   quarters of what was left each time, so no question is left unasked for
///   want of time.
/// - 300 ms at least, above the stalls a fast link's replies still show: a
///   small second write held by Nagle's algorithm until the client's delayed
///   acknowledgement, up to 200 ms on common stacks, and a busy host's
///   scheduling on top.
///
/// The gap never outlasts the deadline, which the read loop holds it to.
fn idle_gap(first_byte: Duration, left: Duration) -> Duration {
    const FLOOR: Duration = Duration::from_millis(300);
    first_byte.saturating_mul(2).max(left / 4).max(FLOOR)
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

/// Sends one datagram by `egress` and reads one reply, capped at `cap` bytes.
///
/// A datagram is one whole message, so a reply that arrives is complete. Silence
/// is an empty reply, as it is over TCP.
pub(crate) fn udp(
    addr: SocketAddr,
    egress: Egress,
    bytes: &[u8],
    deadline: Instant,
    cap: u64,
) -> Result<Reply, ExchangeError> {
    let socket = egress
        .udp_blocking(addr.ip())
        .map_err(|error| ExchangeError::of(&error))?;
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
    use super::{http_message_end, idle_gap};
    use std::time::Duration;

    /// The gap a quiet port is allowed covers a pause as long again as its
    /// first byte took, lets a speak-first service take a good share of the
    /// budget over its answer, and never drops to a stall a fast link shows.
    /// Each term is the one that governs somewhere.
    #[test]
    fn the_idle_gap_is_the_largest_of_its_three_terms() {
        let ms = Duration::from_millis;
        // A slow first byte: twice its wait.
        assert_eq!(idle_gap(ms(900), ms(2_000)), ms(1_800));
        // A prompt port with time to spare: a quarter of what is left.
        assert_eq!(idle_gap(ms(1), ms(3_000)), ms(750));
        // Little time left and a prompt port: the floor.
        assert_eq!(idle_gap(ms(1), ms(400)), ms(300));
    }

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
