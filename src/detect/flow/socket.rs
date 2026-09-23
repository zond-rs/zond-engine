// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Running a flow against a real port
//!
//! [`run`](super::run) takes a [`Probe`], and this is the one that opens
//! sockets. A scan builds it for every flow it runs; a caller driving a single
//! detection outside a scan builds it the same way.

use std::net::SocketAddr;
use std::time::Instant;

use crate::detect::compute::Budget;
use crate::detect::exchange;
use crate::fingerprint::Tunnel;
use crate::model::port::Protocol;

use super::{Probe, ProbeRefusal};

/// A blocking [`Probe`] over a fresh connection to one port, holding a budget
/// and debiting it as it goes.
///
/// Each [`speak`](Probe::speak) is one request and its reply, which is what the
/// corpus's stateless exchanges need. It is bound to the address it was built
/// for and reaches nothing else.
///
/// The budget is enforced here, which is what makes a detection's declaration
/// mean something: an exchange the budget cannot pay for is refused before a
/// packet leaves, and a reply is capped at the bytes still available.
///
/// ```no_run
/// use std::time::Duration;
/// use zond_engine::detect::compute::Budget;
/// use zond_engine::detect::flow::{self, FlowSeed, SocketProbe};
/// use zond_engine::model::port::Protocol;
///
/// # fn example(detection: &zond_engine::detect::flow::schema::FlowDetection) {
/// let addr = "192.0.2.10:6379".parse().expect("a socket address");
/// let budget = Budget::new(0, Duration::from_secs(5));
/// let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget);
///
/// let seed = FlowSeed::new("192.0.2.10", 6379);
/// let findings = flow::run(detection, "redis", &seed, &mut probe);
/// # let _ = findings;
/// # }
/// ```
pub struct SocketProbe {
    addr: SocketAddr,
    protocol: Protocol,
    /// The tunnel the port answered inside, if any: a flow speaks TLS to an
    /// `ssl/*` service and plaintext to the rest, over the same exchange.
    tunnel: Option<Tunnel>,
    /// Bytes still available across this flow's remaining sends and replies.
    bytes_left: u64,
    /// When the flow's time budget runs out.
    deadline: Instant,
    /// Connections still available to this flow.
    connections_left: u32,
    /// Why the last `speak` refused, if a budget did rather than the port going
    /// silent.
    last_refusal: Option<ProbeRefusal>,
    /// Whether the last `speak` read its reply to a self-terminating end: the
    /// peer closing, or an HTTP message reaching the length it declared.
    last_complete: bool,
}

impl SocketProbe {
    /// A probe bound to `addr`, held to `budget`.
    ///
    /// `tunnel` is the transport the port answered inside, so a flow reaches an
    /// `ssl/*` service through a handshake and every other port in the clear.
    /// The clock starts here rather than at the first exchange, so time spent
    /// waiting to build one does not come out of the flow's budget.
    ///
    /// Of the five ceilings a [`Budget`] carries, a flow spends the three that
    /// reach the network: bytes, wall clock, and connections. `fuel` and
    /// `max_memory` bound a compute module's execution and a flow executes
    /// nothing, so they are ignored here as they are in
    /// [`LiveCapabilities`](crate::detect::compute::LiveCapabilities).
    pub fn new(
        addr: SocketAddr,
        protocol: Protocol,
        tunnel: Option<Tunnel>,
        budget: &Budget,
    ) -> Self {
        Self {
            addr,
            protocol,
            tunnel,
            bytes_left: budget.max_bytes,
            deadline: Instant::now() + budget.deadline,
            connections_left: budget.max_connections,
            last_refusal: None,
            last_complete: false,
        }
    }
}

impl Probe for SocketProbe {
    fn speak(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
        // Refuse the exchange the budget cannot pay for, before any packet leaves,
        // recording which budget so a silent port and a spent one stay distinct.
        self.last_refusal = None;
        if self.connections_left == 0 {
            self.last_refusal = Some(ProbeRefusal::Connections);
            return None;
        }
        if exchange::remaining(self.deadline).is_none() {
            self.last_refusal = Some(ProbeRefusal::Deadline);
            return None;
        }
        let sent = bytes.len() as u64;
        if sent > self.bytes_left {
            self.last_refusal = Some(ProbeRefusal::Bytes);
            return None;
        }
        self.bytes_left -= sent;
        self.connections_left -= 1;

        // The reply may consume at most what the byte budget has left. A silent or
        // unreachable port is not a refusal, so `last_refusal` stays clear, unless
        // it was the flow's clock that ended the wait.
        let reply = match self.protocol {
            Protocol::Tcp => exchange::tcp(
                self.addr,
                self.tunnel,
                bytes,
                self.deadline,
                self.bytes_left,
            ),
            Protocol::Udp => exchange::udp(self.addr, bytes, self.deadline, self.bytes_left),
            // An SCTP port is scanned without a client stack, so there is
            // nothing here for a detection to hold a conversation over.
            Protocol::Sctp => return None,
        }
        .ok()
        .filter(|reply| !reply.bytes.is_empty());

        let Some(reply) = reply else {
            // Every wait in an exchange is drawn from what is left of the flow's
            // time, so one that came back empty with none of it left was ended
            // by the budget, not by the port: the question was still open when
            // the clock stopped it. Refused, so the flow's report says a budget
            // left it unanswered rather than that the port had nothing to say.
            // A port that refused the connection or reset it did so with time
            // to spare, and stays silence.
            if exchange::remaining(self.deadline).is_none() {
                self.last_refusal = Some(ProbeRefusal::Deadline);
            }
            return None;
        };

        self.bytes_left -= reply.bytes.len() as u64;
        self.last_complete = reply.complete;
        Some(reply.bytes)
    }

    fn last_refusal(&self) -> Option<ProbeRefusal> {
        self.last_refusal
    }

    fn reply_complete(&self) -> bool {
        self.last_complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A budget with the ceilings this file is about, and nothing spent on the
    /// two a flow never touches.
    fn budget(max_bytes: u64, millis: u64, max_connections: u32) -> Budget {
        Budget::new(0, Duration::from_millis(millis))
            .with_max_bytes(max_bytes)
            .with_max_connections(max_connections)
    }

    #[test]
    fn a_reply_is_capped_at_the_flows_byte_budget() {
        use std::io::{Read as _, Write as _};

        // A loopback that floods the probe with far more than the budget allows.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = sock.read(&mut [0u8; 64]);
                let _ = sock.write_all(&vec![b'A'; 4096]);
            }
        });

        // 20-byte budget, one of which the `x` send spends: the reply gets 19.
        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(20, 5_000, 8));
        let reply = probe.speak(b"x").expect("a reply within budget");
        assert!(
            reply.len() <= 19,
            "reply was not capped, got {}",
            reply.len()
        );
    }

    #[test]
    fn a_flow_cannot_open_more_connections_than_its_budget() {
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            // Answer the one connection the budget permits, and no more.
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = sock.write_all(b"ok");
            }
        });

        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4096, 5_000, 1));
        assert!(
            probe.speak(b"a").is_some(),
            "the one permitted exchange failed"
        );
        assert!(
            probe.speak(b"b").is_none(),
            "a second connection was opened past the budget"
        );
        assert_eq!(probe.last_refusal(), Some(ProbeRefusal::Connections));
    }

    #[test]
    fn an_expired_time_budget_refuses_the_exchange() {
        // A zero-millisecond budget is spent the instant it is granted, so no
        // packet leaves; the unreachable address is never dialed.
        let addr: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4096, 0, 8));

        assert!(probe.speak(b"anything").is_none());
        assert_eq!(probe.last_refusal(), Some(ProbeRefusal::Deadline));
    }

    /// A send larger than what is left is refused rather than truncated, and the
    /// refusal says which budget stopped it.
    #[test]
    fn a_send_past_the_byte_budget_is_refused_and_names_the_budget() {
        let addr: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4, 5_000, 8));

        assert!(probe.speak(b"far too long").is_none());
        assert_eq!(probe.last_refusal(), Some(ProbeRefusal::Bytes));
    }

    /// A web server that keeps the connection open after its reply, whatever
    /// `Connection: close` asked, as some embedded servers do. The reply says
    /// how long it is, so the exchange is over when that much has arrived: a
    /// flow asking three questions of such a server gets three whole answers
    /// inside a budget one idle connection would otherwise have spent.
    #[test]
    fn a_reply_that_says_how_long_it_is_ends_there_rather_than_when_the_server_hangs_up() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for sock in listener.incoming().take(3) {
                let Ok(mut sock) = sock else { return };
                std::thread::spawn(move || {
                    let _ = sock.read(&mut [0u8; 512]);
                    let _ = sock
                        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found");
                    // Held until the client lets go, which is what a server
                    // ignoring `Connection: close` looks like from this side.
                    let _ = sock.read(&mut [0u8; 1]);
                });
            }
        });

        let budget_ms = 1_500;
        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4096, budget_ms, 3));
        let started = Instant::now();
        for path in ["/a", "/b", "/c"] {
            let request = format!("GET {path} HTTP/1.1\r\nConnection: close\r\n\r\n");
            let reply = probe.speak(request.as_bytes());
            assert!(
                reply
                    .as_deref()
                    .is_some_and(|reply| reply.ends_with(b"not found")),
                "{path} went unanswered: {reply:?}, refused on {:?}",
                probe.last_refusal()
            );
            assert!(
                probe.reply_complete(),
                "{path}'s reply was whole but not taken as such"
            );
        }
        assert!(
            started.elapsed() < Duration::from_millis(budget_ms / 2),
            "three exchanges with an idle server took {:?}",
            started.elapsed()
        );
    }

    /// An exchange the flow's clock ran out on is a question the budget left
    /// unanswered, and says so: a flow whose last request was still waiting
    /// when its time was up must not read the same as one the port declined.
    #[test]
    fn an_exchange_its_time_budget_ran_out_on_is_refused_rather_than_unanswered() {
        use std::io::Read as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                // Takes the request and answers nothing until the client leaves.
                let _ = sock.read(&mut [0u8; 512]);
                let _ = sock.read(&mut [0u8; 1]);
            }
        });

        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4096, 300, 8));
        assert!(probe.speak(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert_eq!(probe.last_refusal(), Some(ProbeRefusal::Deadline));
    }

    /// A port that turns the connection away has answered, with a refusal of
    /// its own, before the budget had any say: that is silence, not a cut.
    #[test]
    fn a_port_that_refuses_the_connection_is_unanswered_rather_than_refused() {
        // Bound and dropped, so the port is closed and the kernel resets.
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let mut probe = SocketProbe::new(addr, Protocol::Tcp, None, &budget(4096, 5_000, 8));

        assert!(probe.speak(b"anything").is_none());
        assert_eq!(probe.last_refusal(), None);
    }

    /// An SCTP port has no client stack behind it here, so a flow aimed at one
    /// goes unanswered rather than refused: nothing about the budget stopped it.
    #[test]
    fn an_sctp_port_is_unanswered_rather_than_refused() {
        let addr: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let mut probe = SocketProbe::new(addr, Protocol::Sctp, None, &budget(4096, 5_000, 8));

        assert!(probe.speak(b"anything").is_none());
        assert_eq!(probe.last_refusal(), None);
    }
}
