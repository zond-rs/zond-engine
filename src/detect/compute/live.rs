// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Serving the capabilities from a live socket
//!
//! The [`Capabilities`] a module is served during a scan: [`speak`](Capabilities::speak)
//! over a fresh connection to the one scanned port, in the clear or wrapped in
//! TLS when the port answered inside a tunnel, and [`now`](Capabilities::now) off
//! a run-relative clock. It is the live counterpart to the recorded capabilities
//! a test or a replay serves, and a module cannot tell which it holds, which is
//! what the seam is for.
//!
//! ## The budget is enforced here
//!
//! The byte and connection budgets are spent at this boundary, so a module cannot
//! exceed them: an exchange the budget cannot pay for is refused before a packet
//! leaves, and a reply is capped at the bytes still available. The Tier-1
//! [socket probe](crate::detect::flow::SocketProbe) a flow speaks through spends
//! the same budgets over the same [exchange]; what
//! differs is the seam, so a module's `speak` returns a typed [`CapError`] it may
//! catch where a flow's probe reports a bare absence.
//!
//! ## What it does not resolve
//!
//! [`resolve`](Capabilities::resolve) is declined: no detection is granted it yet,
//! so a socket-scoped module never reaches it. When one is, this is where a
//! resolver is served, bounded the way `speak` is.

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::detect::exchange::{self, ExchangeError};
use crate::fingerprint::Tunnel;
use crate::fingerprint::authority::Authority;
use crate::model::port::Protocol;
use crate::transport::dial::Egress;

use super::budget::Budget;
use super::capability::{CapError, Capabilities, ScanInstant};

/// The capabilities a module is served against a live port, holding the budget
/// and debiting it as it goes. Bound to the one address it was built for, so a
/// module can reach nothing else. An HTTP request whose `Host` stands for that
/// address, as `localhost` or the address itself, is sent naming the port the
/// way a browser would.
pub struct LiveCapabilities {
    /// The port, as a request to it and a handshake with it name it.
    peer: Authority,
    protocol: Protocol,
    /// The tunnel the port answered inside, if any: a module speaks TLS to an
    /// `ssl/*` service and plaintext to the rest, over the same `speak`.
    tunnel: Option<Tunnel>,
    /// Where each of the run's connections leaves from.
    egress: Egress,
    /// Bytes still available across this run's remaining exchanges.
    bytes_left: u64,
    /// When the run's time budget runs out.
    deadline: Instant,
    /// Connections still available to this run.
    connections_left: u32,
    /// The origin the injected clock counts from.
    clock: Instant,
}

/// The least a module's datagram is waited on for its reply, whatever share of
/// the run's time an even split would give it.
///
/// Half a second holds an intercontinental round trip and an agent's work on
/// the request. A share below it is no time for any reply to arrive, so a
/// datagram given less is a guess silently not tried; the floor keeps the split
/// from starving the datagrams of the time to be answered. The same figure the
/// Tier-1 [socket probe](crate::detect::flow::SocketProbe) floors a flow's
/// datagram wait at, and for the same reason.
const DATAGRAM_WAIT_FLOOR: Duration = Duration::from_millis(500);

impl LiveCapabilities {
    /// Capabilities bound to `addr`, held to `budget`. `tunnel` is the transport
    /// the port answered inside, so a module's `speak` reaches an `ssl/*` service
    /// through a handshake. The clock starts now, so [`now`](Capabilities::now)
    /// reports the time since the run began.
    ///
    /// Its connections go where the routing table sends them. A scan forced to
    /// a source builds its own with every connection pinned there.
    pub fn new(
        addr: SocketAddr,
        protocol: Protocol,
        tunnel: Option<Tunnel>,
        budget: &Budget,
    ) -> Self {
        Self {
            peer: Authority::for_tunnel(addr, tunnel),
            protocol,
            tunnel,
            egress: Egress::KERNEL,
            bytes_left: budget.max_bytes,
            deadline: Instant::now() + budget.deadline,
            connections_left: budget.max_connections,
            clock: Instant::now(),
        }
    }

    /// The same capabilities, with every connection leaving by `egress`: the
    /// way the scan reached the port, so a module speaks to it from where the
    /// probe did.
    pub(crate) fn via(mut self, egress: Egress) -> Self {
        self.egress = egress;
        self
    }

    /// The same capabilities, asking for the port by `name` where a target
    /// reached its address by one: the site the target named, in the handshake
    /// and in the `Host` of a request that stands for the port. See
    /// [`Authority::readdressed`].
    pub(crate) fn named(mut self, name: Option<Arc<str>>) -> Self {
        self.peer = self.peer.named(name);
        self
    }

    /// When to stop waiting for the coming datagram's reply: an even share of
    /// the time left among the datagrams the connection budget still permits,
    /// never below [`DATAGRAM_WAIT_FLOOR`] or past the run's deadline.
    ///
    /// Silence is an ordinary answer over UDP, and a module guessing over it,
    /// one datagram per guess, draws one from every wrong guess. Given the
    /// whole of what is left, the first unanswered guess would spend it and the
    /// rest would go unsent; an even share hears each out and leaves the last
    /// its turn. A module's loop is its own, so how many datagrams follow is not
    /// known ahead as a flow's are; the connection budget is the count instead,
    /// the most datagrams the run may yet send, `connections` including the one
    /// about to go. A module that sends one datagram, its budget one connection,
    /// waits the whole of what is left, as it did.
    fn datagram_deadline(&self, connections: u32, left: Duration) -> Instant {
        let share = (left / connections.max(1)).max(DATAGRAM_WAIT_FLOOR);
        (Instant::now() + share).min(self.deadline)
    }
}

impl Capabilities for LiveCapabilities {
    fn speak(&mut self, bytes: &[u8]) -> Result<Vec<u8>, CapError> {
        // Addressed before the budget is asked, which pays for what is sent.
        let bytes = match self.protocol {
            Protocol::Tcp => self.peer.readdressed(bytes),
            _ => Cow::Borrowed(bytes),
        };
        let bytes = &*bytes;
        // Refuse before a packet leaves what the budget cannot pay for.
        if self.connections_left == 0 {
            return Err(CapError::ConnectionBudgetExhausted);
        }
        let Some(left) = exchange::remaining(self.deadline) else {
            return Err(CapError::TimedOut);
        };
        let sent = bytes.len() as u64;
        if sent > self.bytes_left {
            return Err(CapError::ByteBudgetExhausted);
        }
        self.bytes_left -= sent;
        // The datagram's wait is a share of the time left among the datagrams
        // the budget still permits, this one counted in before it is spent.
        let datagram_until = self.datagram_deadline(self.connections_left, left);
        self.connections_left -= 1;

        // The reply may consume at most what the byte budget has left.
        let reply = match self.protocol {
            Protocol::Tcp => exchange::tcp(
                &self.peer,
                self.egress,
                self.tunnel,
                bytes,
                self.deadline,
                self.bytes_left,
                // A module reads its reply with its own logic and declares no
                // end-of-reply line; its reply ends at the idle gap or a close.
                None,
            )
            .map_err(CapError::from),
            // A datagram unanswered is silence, the ordinary answer over UDP, so
            // it waits only its share of the time rather than the run's whole
            // budget: a module trying guess after guess hears each out and still
            // reaches the last. See [`datagram_deadline`](Self::datagram_deadline).
            Protocol::Udp => exchange::udp(
                self.peer.socket(),
                self.egress,
                bytes,
                datagram_until,
                self.bytes_left,
            )
            .map_err(CapError::from),
            Protocol::Sctp => Err(CapError::Denied(
                "a detection cannot speak to an SCTP port: the engine scans SCTP without a client \
                 stack to hold an association open"
                    .to_string(),
            )),
        }?
        .bytes;
        self.bytes_left -= reply.len() as u64;
        Ok(reply)
    }

    fn resolve(&mut self, _name: &str) -> Result<Vec<IpAddr>, CapError> {
        Err(CapError::Denied(
            "name resolution is not served to a socket-scoped detection".to_string(),
        ))
    }

    fn now(&mut self) -> ScanInstant {
        ScanInstant::from_millis(
            u64::try_from(self.clock.elapsed().as_millis()).unwrap_or(u64::MAX),
        )
    }
}

/// What an exchange's failure looks like at this seam.
///
/// The distinctions are the same ones; only the vocabulary changes, since a
/// module catches these the way a network client catches an I/O error.
impl From<ExchangeError> for CapError {
    fn from(error: ExchangeError) -> Self {
        match error {
            ExchangeError::TimedOut => CapError::TimedOut,
            ExchangeError::ConnectionRefused => CapError::ConnectionRefused,
            ExchangeError::Reset => CapError::Reset,
            // Denied rather than handed back as an I/O failure: the socket was
            // never opened, so a module that caught it would read this
            // machine's shortfall as the port's answer, and one that retried
            // would find the table no emptier. Ending the run files it with
            // the reason, and the remedy is the operator's.
            ExchangeError::Starved => CapError::Denied(format!(
                "no socket to speak through: {}",
                crate::system::descriptors::starved_while("in the time the detection had")
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::compute::{Budget, ComputeRuntime, Grant, ModuleBody, RhaiRuntime};
    use crate::fingerprint::PortContext;
    use crate::model::finding::{DetectionClass, DetectionId, Severity, Version};
    use crate::testing::loopback::from_this_process;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    /// A module's exchange the process had no socket for ends its run with a
    /// reason, rather than coming back as a reset the module would catch and
    /// read as the port's answer.
    #[test]
    fn a_speak_refused_a_socket_ends_the_run_with_the_reason() {
        let error = CapError::from(ExchangeError::Starved);
        assert!(error.is_fatal(), "handed back to the module: {error:?}");
        assert!(
            matches!(&error, CapError::Denied(reason) if reason.contains("file descriptor limit")),
            "{error:?}"
        );
    }

    /// A module's request reaches the site a target named on a port that
    /// holds its sites by name: the handshake names it, and the `Host` the
    /// module wrote as a stand-in is sent naming it. Unnamed, the handshake is
    /// refused and the module reads a reset.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_module_speaks_to_a_named_port_as_the_site_it_was_named() {
        let addr =
            crate::testing::loopback::https_site("box.example", |_| Some("the named site")).await;

        let reply = tokio::task::spawn_blocking(move || {
            let mut caps = LiveCapabilities::new(addr, Protocol::Tcp, Some(Tunnel::Tls), &budget())
                .named(Some(std::sync::Arc::from("box.example")));
            caps.speak(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        })
        .await
        .expect("the exchange ran");

        let reply = reply.expect("the named site answered");
        assert!(
            reply.starts_with(b"HTTP/1.1 200 OK") && reply.ends_with(b"the named site"),
            "{}",
            String::from_utf8_lossy(&reply)
        );
    }

    fn budget() -> Budget {
        Budget {
            fuel: 1_000_000,
            deadline: Duration::from_secs(2),
            max_memory: 65_536,
            max_bytes: 8_192,
            max_connections: 4,
        }
    }

    #[test]
    fn a_module_speaks_to_a_live_socket_through_the_seam() {
        // A loopback that answers the module's probe with a banner, standing in
        // for the service a detection is written against.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Some(mut sock) = from_this_process(&listener).next() {
                let mut probe = [0u8; 64];
                let _ = sock.read(&mut probe);
                let _ = sock.write_all(b"# Server\r\nredis_version:7.2.4\r\n");
            }
        });

        let source = r#"
            fn analyze(ctx, responses) {
                let reply = speak(blob(6, 0x41));
                if reply.len() > 0 {
                    [ #{ severity: "high", summary: "the live port answered" } ]
                } else {
                    []
                }
            }
        "#;

        let runtime = RhaiRuntime::new();
        let module = runtime
            .load(&ModuleBody::Rhai(source.to_string()))
            .expect("the module compiles");
        let grant = Grant {
            detection: DetectionId::new("live-test", Version::new(1, 0, 0), "hash").unwrap(),
            class: DetectionClass::ActiveBenign,
            budget: budget(),
            speak: true,
            resolve: false,
        };
        let mut instance = runtime.instantiate(&module, &grant).expect("instantiates");
        let mut caps = LiveCapabilities::new(addr, Protocol::Tcp, None, &budget());
        let ctx = PortContext {
            port: addr.port(),
            protocol: Protocol::Tcp,
            addr: Some(addr),
            tunnel: None,
            speaks_http: false,
            detection: crate::config::ServiceDetection::default(),
            host_name: None,
        };

        let findings = runtime
            .run(&mut instance, &ctx, &[], &mut caps)
            .expect("a clean run against the live port");
        assert_eq!(findings.len(), 1, "the module read the live reply");
        assert_eq!(findings[0].severity(), Severity::High);
    }

    #[test]
    fn the_byte_budget_caps_a_reply_from_the_live_socket() {
        // A loopback that floods far more than the budget allows.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Some(mut sock) = from_this_process(&listener).next() {
                let _ = sock.read(&mut [0u8; 64]);
                let _ = sock.write_all(&vec![b'A'; 4096]);
            }
        });

        // A 20-byte budget, six spent by the send: the reply gets at most 14.
        let mut caps = LiveCapabilities::new(
            addr,
            Protocol::Tcp,
            None,
            &Budget {
                max_bytes: 20,
                ..budget()
            },
        );
        let reply = caps.speak(b"ABCDEF").expect("a reply within budget");
        assert!(
            reply.len() <= 14,
            "the reply was not capped: {}",
            reply.len()
        );
    }

    /// A module's UDP guesses each wait only their share of the time left, so a
    /// first guess that draws silence does not spend the whole budget and leave
    /// the rest unsent. The share comes from the connection budget, the most
    /// datagrams the run may yet send, because a module's loop count is its own
    /// and not known ahead as a flow's is.
    #[test]
    fn an_unanswered_datagram_waits_its_share_and_not_the_whole_budget() {
        // A responder that answers only the third guess, as an agent answers a
        // request it accepts and ignores the ones it does not.
        let agent = std::net::UdpSocket::bind("127.0.0.1:0").expect("a UDP socket");
        agent
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("a read timeout");
        let addr = agent.local_addr().expect("its address");
        let answered = std::thread::spawn(move || {
            let mut buffer = [0u8; 64];
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if let Ok((read, from)) = agent.recv_from(&mut buffer)
                    && &buffer[..read] == b"third"
                {
                    let _ = agent.send_to(b"accepted", from);
                    return;
                }
            }
        });

        // Three datagrams' worth of connection budget, and a whole-run deadline
        // that a single unanswered datagram waiting it all out would exhaust
        // before the third guess. The floor holds each guess's own wait well
        // inside a loopback round trip.
        let mut caps = LiveCapabilities::new(
            addr,
            Protocol::Udp,
            None,
            &Budget {
                max_connections: 3,
                deadline: Duration::from_millis(1_500),
                ..budget()
            },
        );

        assert_eq!(caps.speak(b"first").expect("silence is a reply"), b"");
        assert_eq!(caps.speak(b"second").expect("silence is a reply"), b"");
        assert_eq!(
            caps.speak(b"third").expect("the accepted guess answers"),
            b"accepted",
            "the third guess was cut short: the first two spent the budget"
        );

        answered.join().expect("the responder finishes");
    }

    #[test]
    fn an_exhausted_connection_budget_refuses_before_dialing() {
        // One connection permitted; the second is refused with a typed cause and
        // never dials. The port is a closed one on loopback, so the one dial
        // there is refused at once and nothing leaves the machine.
        let addr: SocketAddr =
            crate::testing::loopback::refused_port(std::net::IpAddr::from([127, 0, 0, 1]));
        let mut caps = LiveCapabilities::new(
            addr,
            Protocol::Tcp,
            None,
            &Budget {
                max_connections: 1,
                deadline: Duration::from_secs(5),
                ..budget()
            },
        );
        // The first exchange dials the closed port and fails on connect; that
        // spends the one connection.
        assert_eq!(
            caps.speak(b"x"),
            Err(CapError::ConnectionRefused),
            "the first exchange did not dial the closed port"
        );
        assert_eq!(
            caps.speak(b"y"),
            Err(CapError::ConnectionBudgetExhausted),
            "a second connection was allowed past the budget"
        );
    }
}
