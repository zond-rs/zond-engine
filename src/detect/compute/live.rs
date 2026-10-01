// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Serving the capabilities from a live socket
//!
//! The [`Capabilities`] a module is served during a scan:
//! [`speak`](Capabilities::speak) over a fresh connection to the scanned port, in
//! the clear or through TLS, and [`now`](Capabilities::now) off a run-relative
//! clock. A module cannot tell it from the recorded capabilities a replay serves.
//!
//! ## Budgets
//!
//! An exchange the byte or connection budget cannot pay for is refused before
//! anything is sent, and a reply is capped at the bytes left. A flow's
//! [socket probe](crate::detect::flow::SocketProbe) spends the same budgets
//! over the same [exchange], but reports absence where this returns a typed
//! [`CapError`].
//!
//! ## `resolve`
//!
//! [`resolve`](Capabilities::resolve) is declined; no detection is granted it.

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
/// and debiting it as it goes. Bound to the one address it was built for. An HTTP
/// request whose `Host` is a stand-in (`localhost` or the address) is sent naming
/// the port, as a browser would.
pub struct LiveCapabilities {
    /// The port, as a request to it and a handshake with it name it.
    peer: Authority,
    protocol: Protocol,
    /// The tunnel the port answered inside, if any.
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
/// Half a second covers an intercontinental round trip and the agent's work.
/// The same floor as a flow's [socket probe](crate::detect::flow::SocketProbe).
const DATAGRAM_WAIT_FLOOR: Duration = Duration::from_millis(500);

impl LiveCapabilities {
    /// Capabilities bound to `addr`, held to `budget`. `tunnel` is the transport
    /// the port answered inside, so a module's `speak` reaches an `ssl/*` service
    /// through a handshake. The clock starts now, so [`now`](Capabilities::now)
    /// reports the time since the run began.
    ///
    /// Connections follow the routing table.
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

    /// The same capabilities, with every connection leaving by `egress`, as the
    /// scan reached the port.
    pub(crate) fn via(mut self, egress: Egress) -> Self {
        self.egress = egress;
        self
    }

    /// The same capabilities, asking for the port by `name`, the host name its
    /// address was reached by.
    ///
    /// The handshake with an `ssl/*` service carries it as SNI, and a stand-in
    /// `Host` (`localhost` or the address) is replaced by it. A `Host` naming
    /// another site is sent as written. A name SNI cannot carry, such as an
    /// address, is left off the handshake.
    pub fn named(mut self, name: impl Into<Arc<str>>) -> Self {
        self.peer = self.peer.named(Some(name.into()));
        self
    }

    /// When to stop waiting for the coming datagram's reply: an even share of
    /// the time left among the datagrams the connection budget still permits,
    /// never below [`DATAGRAM_WAIT_FLOOR`] or past the run's deadline.
    ///
    /// A module guessing over UDP draws silence from every wrong guess; an even
    /// share keeps the first from spending the whole budget. The connection
    /// budget (`connections`, including this one) stands for the number of
    /// datagrams still to come. With a budget of one, the datagram gets all that
    /// is left.
    fn datagram_deadline(&self, connections: u32, left: Duration) -> Instant {
        let share = (left / connections.max(1)).max(DATAGRAM_WAIT_FLOOR);
        (Instant::now() + share).min(self.deadline)
    }
}

impl Capabilities for LiveCapabilities {
    fn speak(&mut self, bytes: &[u8]) -> Result<Vec<u8>, CapError> {
        // Addressed first, since the budget pays for what is actually sent.
        let bytes = match self.protocol {
            Protocol::Tcp => self.peer.readdressed(bytes),
            _ => Cow::Borrowed(bytes),
        };
        let bytes = &*bytes;
        // Refuse what the budget cannot pay for.
        if self.connections_left == 0 {
            return Err(CapError::ConnectionBudgetExhausted);
        }
        if exchange::remaining(self.deadline).is_none() {
            return Err(CapError::TimedOut);
        }
        let sent = bytes.len() as u64;
        if sent > self.bytes_left {
            return Err(CapError::ByteBudgetExhausted);
        }
        if self.protocol == Protocol::Sctp {
            return Err(CapError::Denied(
                "a detection cannot speak to an SCTP port: the engine scans SCTP without a client \
                 stack to hold an association open"
                    .to_string(),
            ));
        }
        // The pacing slot; the wait extends the run's deadline (see `held_here`).
        let (slot, waited) = exchange::slot(&self.egress, self.peer.socket().ip())?;
        self.deadline += waited;
        let Some(left) = exchange::remaining(self.deadline) else {
            slot.refund();
            return Err(CapError::TimedOut);
        };
        self.bytes_left -= sent;
        // A share of the time left; see `datagram_deadline`.
        let datagram_until = self.datagram_deadline(self.connections_left, left);
        self.connections_left -= 1;

        // The reply is capped at the bytes left.
        let reply = match self.protocol {
            Protocol::Tcp => exchange::tcp(
                &self.peer,
                &self.egress,
                slot,
                self.tunnel,
                bytes,
                self.deadline,
                self.bytes_left,
                // No `until`: the reply ends at the idle gap or a close.
                None,
            )
            .map_err(CapError::from),
            // Waits only its share; see `datagram_deadline`.
            Protocol::Udp => exchange::udp(
                self.peer.socket(),
                &self.egress,
                slot,
                bytes,
                datagram_until,
                self.bytes_left,
            )
            .map_err(CapError::from),
            Protocol::Sctp => unreachable!("an SCTP port is refused before its slot"),
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
/// The same distinctions, in the vocabulary a module catches.
impl From<ExchangeError> for CapError {
    fn from(error: ExchangeError) -> Self {
        match error {
            ExchangeError::TimedOut => CapError::TimedOut,
            ExchangeError::ConnectionRefused => CapError::ConnectionRefused,
            ExchangeError::Reset => CapError::Reset,
            ExchangeError::Starved => CapError::OutOfDescriptors,
            ExchangeError::Withheld => CapError::Withheld,
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

    /// No socket available ends the run as out of descriptors, not as a reset or
    /// a denial.
    #[test]
    fn a_speak_refused_a_socket_ends_the_run_as_out_of_descriptors() {
        let error = CapError::from(ExchangeError::Starved);
        assert!(error.is_fatal(), "handed back to the module: {error:?}");
        assert_eq!(error, CapError::OutOfDescriptors);
    }

    /// The handshake and a stand-in `Host` carry the target's name; unnamed, the
    /// handshake is refused and the module reads a reset.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_module_speaks_to_a_named_port_as_the_site_it_was_named() {
        let addr =
            crate::testing::loopback::https_site("box.example", |_| Some("the named site")).await;

        let reply = tokio::task::spawn_blocking(move || {
            let mut caps = LiveCapabilities::new(addr, Protocol::Tcp, Some(Tunnel::Tls), &budget())
                .named("box.example");
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
        // A loopback that answers with a banner.
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
            group: None,
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

    /// Each UDP guess waits only its share of the time left.
    #[test]
    fn an_unanswered_datagram_waits_its_share_and_not_the_whole_budget() {
        // A responder that answers only the third guess.
        let agent = std::net::UdpSocket::bind("127.0.0.1:0").expect("a UDP socket");
        agent
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("a read timeout");
        let addr = agent.local_addr().expect("its address");
        let answered = std::thread::spawn(move || {
            let mut buffer = [0u8; 64];
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if let Ok((read, from)) =
                    crate::testing::loopback::recv_from_this_process_blocking(&agent, &mut buffer)
                    && &buffer[..read] == b"third"
                {
                    let _ = agent.send_to(b"accepted", from);
                    return;
                }
            }
        });

        // Three connections, and a deadline one datagram waiting it all out would
        // exhaust before the third guess.
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
        // One connection permitted; the second is refused without dialling. The
        // port is closed on loopback.
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
        // The first dial fails on connect and spends the connection.
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
