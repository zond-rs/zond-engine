// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # One request and its reply, over a socket to the scanned port
//!
//! Both detection tiers reach the network through this: connect, wrap the
//! socket in the port's transport, send, and read until the reply is whole, the
//! port stops, or the byte cap is reached. A flow's
//! [`Probe`](super::flow::Probe) reports a failure as absence; a compute
//! module's [`Capabilities`](super::compute::Capabilities) as a typed error.
//!
//! The callers own the budgets; this opens one socket within the deadline and
//! cap it is given.
//!
//! ## When a reply is whole
//!
//! An HTTP response ends at its `Content-Length` or closing chunk, whatever the
//! connection then does. Anything else is read until the peer closes or, once
//! it has spoken, falls quiet for an [idle gap](idle_gap).
//!
//! Otherwise a server that holds the connection open after replying (ignoring
//! `Connection: close`, or waiting for the next command as redis and memcached
//! do) would make each exchange wait out the detection's budget.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use super::patterns::KeptPattern;
use crate::config::limits::CONNECT_PROBE_TIMEOUT;
use crate::fingerprint::Tunnel;
use crate::fingerprint::authority::Authority;
use crate::protocols::http::message_end as http_message_end;
use crate::system::descriptors;
use crate::transport::dial::{Egress, Slot};

/// The pattern a step declares its reply ends at, compiled once.
///
/// For a service that greets and then pauses before answering a pipelined
/// command (an FTP server's failed-login delay): the read waits through the
/// pause for the line the answer closes with.
pub(crate) struct ReplyEnd(KeptPattern);

impl ReplyEnd {
    /// `pattern`, or [`None`] where it will not compile, which leaves the reply
    /// to end as with none set.
    ///
    /// Compiled once for the process and matched on the flow-matching thread;
    /// see [`patterns`](super::patterns).
    pub(crate) fn compile(pattern: &str) -> Option<Self> {
        KeptPattern::of(pattern).map(Self)
    }

    /// Whether `reply` has reached the line the flow named as its end.
    fn reached(&self, reply: &[u8]) -> bool {
        let reply = latin1(reply);
        self.0
            .matching(|compiled| compiled.identify(&reply, None).is_some())
    }
}

/// Decodes bytes as Latin-1, each byte its own code point, as a flow's matcher
/// does; see [`super::flow`].
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| byte as char).collect()
}

/// The largest datagram a UDP reply is read into, the theoretical maximum
/// payload of one.
const LARGEST_DATAGRAM: u64 = 65_535;

/// What a port said, and whether that is the whole of it.
pub(crate) struct Reply {
    /// The bytes read back. Empty when the port stayed silent.
    pub(crate) bytes: Vec<u8>,
    /// Whether the reply reached a self-terminating end (a close, a declared
    /// HTTP length, a whole datagram) rather than the byte cap or a timeout. Only
    /// a complete reply may be shared with a second caller sending the same
    /// request.
    pub(crate) complete: bool,
}

/// Why an exchange produced nothing.
///
/// Independent of [`CapError`](super::compute::CapError): the compute tier
/// converts it, the flow tier discards it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExchangeError {
    /// The deadline passed, or a read waited out what was left of it.
    TimedOut,
    /// The port answered a connection attempt with a refusal.
    ConnectionRefused,
    /// The connection failed, or a TLS handshake could not be set up over it.
    Reset,
    /// No descriptor was available in the caller's time, so nothing was sent.
    /// This machine's shortfall, not the port's answer.
    Starved,
    /// The scan stopped, or the host's time ran out, while the exchange waited
    /// for its slot; nothing was sent.
    Withheld,
}

impl ExchangeError {
    /// Which error an I/O failure surfaces as.
    fn of(error: &std::io::Error) -> Self {
        if descriptors::exhausted(error) {
            return Self::Starved;
        }
        match error.kind() {
            ErrorKind::TimedOut | ErrorKind::WouldBlock => Self::TimedOut,
            ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            _ => Self::Reset,
        }
    }
}

/// Waits for the slot of the coming exchange with `peer`, which the scan's
/// pacing gives out by `egress`, and says how long the wait took.
///
/// Taken before the exchange's clock starts; the caller adds the wait to its
/// deadline, since pacing gaps are the scan's time. The same wait is counted by
/// [`held_here`](crate::transport::dial::pacing::held_here) for clocks a caller
/// cannot move.
pub(crate) fn slot(egress: &Egress, peer: IpAddr) -> Result<(Slot, Duration), ExchangeError> {
    let asked = Instant::now();
    let slot = egress
        .slot_blocking(peer)
        .map_err(|_withheld| ExchangeError::Withheld)?;
    Ok((slot, asked.elapsed()))
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
/// A `tunnel` wraps the socket before anything is sent, so an `ssl/*` service is
/// reached through a handshake naming `peer`'s site. A handshake that cannot be
/// set up is a reset; one that fails surfaces as the first read or write error.
///
/// A silent port is an empty reply, not an error.
///
/// The exchange holds one descriptor, its socket. A full table is waited out
/// until the deadline, then reported as [`ExchangeError::Starved`].
///
/// `until` makes the read wait up to the deadline for the reply's closing line
/// instead of ending at an idle gap. [`None`] ends at the idle gap.
///
/// The connection is the probe `slot` was given; see [`slot`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn tcp(
    peer: &Authority,
    egress: &Egress,
    slot: Slot,
    tunnel: Option<Tunnel>,
    bytes: &[u8],
    deadline: Instant,
    cap: u64,
    until: Option<&ReplyEnd>,
) -> Result<Reply, ExchangeError> {
    let Some(left) = remaining(deadline) else {
        slot.refund();
        return Err(ExchangeError::TimedOut);
    };
    let tcp = egress
        .connect_within(slot, peer.socket(), left.min(CONNECT_PROBE_TIMEOUT), left)
        .map_err(|error| ExchangeError::of(&error))?;
    tcp.set_read_timeout(Some(remaining(deadline).ok_or(ExchangeError::TimedOut)?))
        .map_err(|error| ExchangeError::of(&error))?;
    let mut stream =
        super::tls::wrap(tcp, peer.server_name(), tunnel).ok_or(ExchangeError::Reset)?;
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
                // A message read to its declared end, or to the flow's `until`.
                if http_message_end(&reply).is_some()
                    || until.is_some_and(|end| end.reached(&reply))
                {
                    whole = true;
                    break;
                }
                let Some(left) = remaining(deadline) else {
                    break;
                };
                // With `until`, wait to the deadline; otherwise the idle gap.
                let wait = match until {
                    Some(_) => left,
                    None => (*gap.get_or_insert_with(|| idle_gap(sent.elapsed(), left))).min(left),
                };
                if stream.socket().set_read_timeout(Some(wait)).is_err() {
                    break;
                }
            }
            // A timeout or error ends the read; the reply is not complete.
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
/// For a reply that neither closes nor declares its end. The gap is the largest
/// of:
///
/// - Twice the wait for the first byte, which held a round trip and the
///   server's work, covering a mid-reply pause of either kind.
/// - A quarter of the time left, since a speak-first service's greeting says
///   nothing about how long its answer takes; three quarters stay for later
///   questions.
/// - 300 ms, above a Nagle-delayed second write (up to 200 ms) plus scheduling.
///
/// The gap never outlasts the deadline, which the read loop holds it to.
fn idle_gap(first_byte: Duration, left: Duration) -> Duration {
    const FLOOR: Duration = Duration::from_millis(300);
    first_byte.saturating_mul(2).max(left / 4).max(FLOOR)
}

/// Sends one datagram by `egress` and reads one reply, capped at `cap` bytes.
///
/// A datagram is one whole message, so a reply that arrives is complete. Silence
/// is an empty reply, as it is over TCP.
///
/// The datagram is the probe `slot` was given; the slot is returned if this
/// machine could not send it.
pub(crate) fn udp(
    addr: SocketAddr,
    egress: &Egress,
    slot: Slot,
    bytes: &[u8],
    deadline: Instant,
    cap: u64,
) -> Result<Reply, ExchangeError> {
    let Some(left) = remaining(deadline) else {
        slot.refund();
        return Err(ExchangeError::TimedOut);
    };
    let socket = match egress.udp_blocking(&slot, addr.ip(), left) {
        Ok(socket) => socket,
        Err(error) => {
            slot.refund();
            return Err(ExchangeError::of(&error));
        }
    };
    let Some(wait) = remaining(deadline) else {
        slot.refund();
        return Err(ExchangeError::TimedOut);
    };
    let sent = socket
        .connect(addr)
        .and_then(|()| socket.set_read_timeout(Some(wait)))
        .and_then(|()| socket.send(bytes));
    slot.settle(&sent);
    sent.map_err(|error| ExchangeError::of(&error))?;

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
    use super::{ReplyEnd, http_message_end, idle_gap};
    use std::time::Duration;

    /// **The `until` pattern is compiled once for the process**, since it is
    /// checked after every chunk.
    #[test]
    fn a_reply_s_end_is_matched_on_the_kept_pattern() {
        const END: &str = "(?m)^226 kept-end";
        let end = ReplyEnd::compile(END).expect("compiles");

        assert!(end.reached(b"150 sending\r\n226 kept-end\r\n"));
        assert!(
            crate::detect::patterns::matched_as_kept(END),
            "the reply's end was matched on a copy of its own"
        );
    }

    /// An exchange holds one descriptor, its socket, and nothing beside it, so
    /// a table with room for that socket carries the exchange through.
    ///
    /// A second descriptor would exceed the flow's share and, on a full table,
    /// be read as the port resetting. Here the table has room for two (the
    /// socket and the listener's accepted end) and no third.
    #[cfg(unix)]
    #[test]
    fn an_exchange_holds_one_descriptor_and_goes_through_on_a_table_with_room_for_it() {
        use crate::system::descriptors::testing::{exhaust, in_a_process_of_its_own};
        use std::io::{Read, Write};
        use std::time::Instant;

        if !in_a_process_of_its_own(
            module_path!(),
            "an_exchange_holds_one_descriptor_and_goes_through_on_a_table_with_room_for_it",
        ) {
            return;
        }
        const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let addr = listener.local_addr().expect("its address");
        // Keeps the connection open, so the reply ends at its declared length.
        let server = std::thread::spawn(move || {
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            };
            let mut request = Vec::new();
            let mut buffer = [0u8; 256];
            while !request.ends_with(b"\r\n\r\n") {
                match stream.read(&mut buffer) {
                    Ok(0) | Err(_) => return,
                    Ok(read) => request.extend_from_slice(&buffer[..read]),
                }
            }
            let _ = stream.write_all(REPLY);
            std::thread::sleep(Duration::from_secs(2));
        });

        let mut held = exhaust(64);
        held.truncate(held.len() - 2);

        let reply = super::tcp(
            &super::Authority::new(addr),
            &crate::transport::dial::Egress::KERNEL,
            crate::transport::dial::Slot::unpaced(),
            None,
            b"GET / HTTP/1.1\r\n\r\n",
            Instant::now() + Duration::from_secs(5),
            4096,
            None,
        )
        .map(|reply| reply.bytes);
        assert_eq!(
            reply.as_deref(),
            Ok(REPLY),
            "the exchange needed more than its one socket"
        );
        drop(held);
        let _ = server.join();
    }

    /// Each of the three terms governs somewhere.
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
        // Headers incomplete: unknown.
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

    /// Chunked framing takes precedence over a `Content-Length`.
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

    /// None of these declares an end, so the read goes on.
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
