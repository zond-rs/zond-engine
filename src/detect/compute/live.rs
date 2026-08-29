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
//! over a fresh connection to the one scanned port, [`now`](Capabilities::now)
//! off a scan-relative clock. It is the live counterpart to the recorded
//! capabilities a test or a replay serves, and a module cannot tell which it
//! holds — the whole point of the seam.
//!
//! ## The budget is enforced here
//!
//! The byte and connection budgets are spent at this boundary, so a module cannot
//! exceed them: an exchange the budget cannot pay for is refused before a packet
//! leaves, and a reply is capped at the bytes still available. This mirrors the
//! Tier-1 [socket probe](crate::scanner::detect) a flow speaks through — the
//! difference is only the seam it satisfies, so a module's `speak` returns a
//! typed [`CapError`] the module may catch rather than a bare absence.
//!
//! ## What it does not resolve
//!
//! [`resolve`](Capabilities::resolve) is declined: no detection is granted it yet,
//! so a socket-scoped module never reaches it. When one is, this is where a
//! resolver is served, bounded the way `speak` is.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::config::limits::CONNECT_PROBE_TIMEOUT;
use crate::model::port::Protocol;

use super::budget::Budget;
use super::capability::{CapError, Capabilities, ScanInstant};

/// The capabilities a module is served against a live port, holding the budget
/// and debiting it as it goes. Bound to the one address it was built for, so a
/// module can reach nothing else.
pub struct LiveCapabilities {
    addr: SocketAddr,
    protocol: Protocol,
    /// Bytes still available across this run's remaining exchanges.
    bytes_left: u64,
    /// When the run's time budget runs out.
    deadline: Instant,
    /// Connections still available to this run.
    connections_left: u32,
    /// The origin the injected clock counts from.
    clock: Instant,
}

impl LiveCapabilities {
    /// Capabilities bound to `addr`, held to `budget`. The clock starts now, so
    /// [`now`](Capabilities::now) reports the time since the run began.
    pub fn new(addr: SocketAddr, protocol: Protocol, budget: &Budget) -> Self {
        Self {
            addr,
            protocol,
            bytes_left: budget.max_bytes,
            deadline: Instant::now() + budget.deadline,
            connections_left: budget.max_connections,
            clock: Instant::now(),
        }
    }
}

impl Capabilities for LiveCapabilities {
    fn speak(&mut self, bytes: &[u8]) -> Result<Vec<u8>, CapError> {
        // Refuse before a packet leaves what the budget cannot pay for.
        if self.connections_left == 0 {
            return Err(CapError::ConnectionBudgetExhausted);
        }
        if remaining(self.deadline).is_none() {
            return Err(CapError::TimedOut);
        }
        let sent = bytes.len() as u64;
        if sent > self.bytes_left {
            return Err(CapError::ByteBudgetExhausted);
        }
        self.bytes_left -= sent;
        self.connections_left -= 1;

        // The reply may consume at most what the byte budget has left.
        let reply = match self.protocol {
            Protocol::Tcp => tcp_exchange(self.addr, bytes, self.deadline, self.bytes_left),
            Protocol::Udp => udp_exchange(self.addr, bytes, self.deadline, self.bytes_left),
        }?;
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

/// The time left before `deadline`, or [`None`] if it has passed.
fn remaining(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

/// Which capability error an I/O failure surfaces as. The module may catch any of
/// these and try another approach, the way a network client does.
fn io_error(error: &std::io::Error) -> CapError {
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => CapError::TimedOut,
        ErrorKind::ConnectionRefused => CapError::ConnectionRefused,
        _ => CapError::Reset,
    }
}

/// Connects, sends `bytes`, and reads the reply until the port falls silent, the
/// byte budget `cap` is spent, or the connection closes. A silent port is an
/// empty reply, not an error — the module decides what that means.
fn tcp_exchange(
    addr: SocketAddr,
    bytes: &[u8],
    deadline: Instant,
    cap: u64,
) -> Result<Vec<u8>, CapError> {
    let timeout = remaining(deadline).ok_or(CapError::TimedOut)?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout.min(CONNECT_PROBE_TIMEOUT))
        .map_err(|error| io_error(&error))?;
    stream
        .set_read_timeout(Some(remaining(deadline).ok_or(CapError::TimedOut)?))
        .map_err(|error| io_error(&error))?;
    stream.write_all(bytes).map_err(|error| io_error(&error))?;

    let mut reply = Vec::new();
    let mut buffer = [0u8; 4096];
    while (reply.len() as u64) < cap {
        let want = ((cap - reply.len() as u64) as usize).min(buffer.len());
        match stream.read(&mut buffer[..want]) {
            Ok(0) => break,
            Ok(read) => reply.extend_from_slice(&buffer[..read]),
            // A read timeout is the ordinary end of a reply that does not close;
            // any other error ends it too.
            Err(_) => break,
        }
    }
    Ok(reply)
}

/// Sends one datagram and reads one reply, capped at `cap` bytes.
fn udp_exchange(
    addr: SocketAddr,
    bytes: &[u8],
    deadline: Instant,
    cap: u64,
) -> Result<Vec<u8>, CapError> {
    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind).map_err(|error| io_error(&error))?;
    socket.connect(addr).map_err(|error| io_error(&error))?;
    socket
        .set_read_timeout(Some(remaining(deadline).ok_or(CapError::TimedOut)?))
        .map_err(|error| io_error(&error))?;
    socket.send(bytes).map_err(|error| io_error(&error))?;

    let mut buffer = vec![0u8; cap.min(65535) as usize];
    match socket.recv(&mut buffer) {
        Ok(read) => {
            buffer.truncate(read);
            Ok(buffer)
        }
        // Silence is an empty reply; a real failure is the error.
        Err(error)
            if error.kind() == ErrorKind::TimedOut || error.kind() == ErrorKind::WouldBlock =>
        {
            Ok(Vec::new())
        }
        Err(error) => Err(io_error(&error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::compute::{Budget, ComputeRuntime, Grant, ModuleBody, RhaiRuntime};
    use crate::fingerprint::PortContext;
    use crate::model::finding::{DetectionClass, DetectionId, Severity, Version};
    use std::net::TcpListener;
    use std::thread;

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
            if let Ok((mut sock, _)) = listener.accept() {
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
        let mut caps = LiveCapabilities::new(addr, Protocol::Tcp, &budget());
        let ctx = PortContext {
            port: addr.port(),
            protocol: Protocol::Tcp,
            addr: Some(addr),
            tunnel: None,
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
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = sock.read(&mut [0u8; 64]);
                let _ = sock.write_all(&vec![b'A'; 4096]);
            }
        });

        // A 20-byte budget, six spent by the send: the reply gets at most 14.
        let mut caps = LiveCapabilities::new(
            addr,
            Protocol::Tcp,
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

    #[test]
    fn an_exhausted_connection_budget_refuses_before_dialing() {
        // One connection permitted; the second is refused with a typed cause and
        // never dials the unreachable address.
        let addr: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let mut caps = LiveCapabilities::new(
            addr,
            Protocol::Tcp,
            &Budget {
                max_connections: 1,
                deadline: Duration::from_millis(50),
                ..budget()
            },
        );
        // The first exchange dials the unreachable host and fails on connect; that
        // spends the one connection.
        let _ = caps.speak(b"x");
        assert_eq!(
            caps.speak(b"y"),
            Err(CapError::ConnectionBudgetExhausted),
            "a second connection was allowed past the budget"
        );
    }
}
