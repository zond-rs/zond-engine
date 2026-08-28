// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Detection phase
//!
//! Runs the Tier-1 [flow](crate::detect::flow) corpus against the open ports a
//! scan has already found and identified, recording a [`Finding`] wherever a flow
//! fires. It is the active counterpart to the [CVE correlator](crate::cve): the
//! correlator reads the service versions the scan gathered and joins them against
//! known vulnerabilities without touching the target, while this opens a fresh
//! connection to a port and exchanges bytes to decide.
//!
//! ## The socket a flow speaks through
//!
//! The flow interpreter is synchronous and interleaves I/O with its own logic (a
//! conditional step sends only after an earlier one matched), so it does not fit
//! the reactor's collect-then-analyse shape. It runs instead on the blocking pool
//! ([`spawn_blocking`](tokio::task::spawn_blocking)), where a blocking
//! `SocketProbe` serves its `speak`. The connection is a plain one to the
//! scanned address, as [service detection](crate::scanner::service) makes: the
//! probe is bound to the one port it was built for, so a flow can reach nothing
//! else.
//!
//! ## The budget is enforced here
//!
//! A flow's declared `max_bytes`, `max_millis`, and `max_connections` bound the
//! `SocketProbe` that serves it: it refuses an exchange the budget cannot pay
//! for, and caps a reply at the bytes left. A flow that declares none falls back
//! to a default ceiling. What is *not* here yet is provenance — the report does
//! not yet record which envelope the scan ran under.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::config::ServiceDetection;
use crate::detect::DetectionEnvelope;
use crate::detect::flow::db::FlowDb;
use crate::detect::flow::schema::Capabilities;
use crate::detect::flow::{Probe, stage};
use crate::model::finding::Finding;
use crate::model::ip::scoped::ScopedIp;
use crate::model::port::{PortState, Protocol};
use crate::scanner::pacing::limits::{CONNECT_CONCURRENCY, CONNECT_PROBE_TIMEOUT};
use crate::scanner::pool::ProbePool;
use crate::scanner::session::{ScanContext, ScannerKind};

/// The reply-byte budget a flow that declares none is held to.
const DEFAULT_MAX_BYTES: u64 = 64 * 1024;

/// The time budget a flow that declares none is held to.
const DEFAULT_MAX_MILLIS: u64 = 2000;

/// The connection budget a flow that declares none is held to. A flow's step and
/// loop ceilings already bound how many exchanges it can attempt; this caps the
/// sockets an undeclared one opens at the widest a single loop can be.
const DEFAULT_MAX_CONNECTIONS: u32 = 64;

/// Runs the flow corpus against every open port a flow is interested in,
/// recording the findings it produces.
///
/// Gated on a service pass having run: a flow's `when` selects a port by its
/// service, so with nothing identified there is nothing to select, and the flow
/// probes are the same kind of active connection service detection already made.
/// `envelope` decides which detection classes the operator permits.
pub async fn detect(ctx: &ScanContext, detection: ServiceDetection, envelope: DetectionEnvelope) {
    if detection == ServiceDetection::Off {
        return;
    }

    let corpus = FlowDb::global();
    let targets = interested_ports(ctx, corpus, envelope);
    if targets.is_empty() {
        return;
    }

    let mut pool = ProbePool::new(
        CONNECT_CONCURRENCY,
        ctx.clone(),
        ScannerKind::Connect,
        |result, _audit| {
            if let Some((key, number, protocol, findings)) = result {
                record(ctx, key, number, protocol, findings);
            }
        },
    );

    for (target, number, protocol, service) in targets {
        if ctx.handle.should_stop() {
            break;
        }
        pool.admit(detect_one(
            target, number, protocol, service, corpus, envelope,
        ))
        .await;
    }

    pool.drain().await;
}

/// Every open `(address, port, protocol, service)` some flow would probe,
/// snapshotted so the store is not borrowed across the exchanges that follow.
///
/// Pre-filtered by [`stage::interested`] so a port no flow gates onto costs
/// nothing here rather than a blocking task that opens no socket.
fn interested_ports(
    ctx: &ScanContext,
    corpus: &FlowDb,
    envelope: DetectionEnvelope,
) -> Vec<(ScopedIp, u16, Protocol, Option<String>)> {
    let mut targets = Vec::new();
    for host in ctx.store.iter() {
        let address = host.value().scoped_ip();
        for port in host.value().ports() {
            if port.state() != PortState::Open {
                continue;
            }
            let service = port.service().map(|service| service.name().to_string());
            if stage::interested(
                corpus,
                &envelope,
                service.as_deref(),
                port.number(),
                port.protocol(),
            ) {
                targets.push((address.clone(), port.number(), port.protocol(), service));
            }
        }
    }
    targets
}

/// Runs one port's flows on the blocking pool and returns the findings, or
/// [`None`] if the port yielded nothing or has no reachable address.
async fn detect_one(
    target: ScopedIp,
    number: u16,
    protocol: Protocol,
    service: Option<String>,
    corpus: &'static FlowDb,
    envelope: DetectionEnvelope,
) -> Option<(ScopedIp, u16, Protocol, Vec<Finding>)> {
    let addr = target.to_socket_addr(number)?;

    // The interpreter is synchronous and the socket blocks, so it runs off the
    // reactor. `spawn_blocking` fails only if the runtime is shutting down.
    let findings = tokio::task::spawn_blocking(move || {
        stage::detect_port(
            corpus,
            &envelope,
            service.as_deref(),
            number,
            protocol,
            |caps| Some(Box::new(SocketProbe::new(addr, protocol, caps)) as Box<dyn Probe>),
        )
    })
    .await
    .ok()?;

    (!findings.is_empty()).then_some((target, number, protocol, findings))
}

/// Folds one port's findings back into its host.
fn record(
    ctx: &ScanContext,
    key: ScopedIp,
    number: u16,
    protocol: Protocol,
    findings: Vec<Finding>,
) {
    ctx.update_host(key, |host| {
        for finding in findings {
            host.add_port_finding(number, protocol, finding);
        }
    });
}

/// A blocking [`Probe`] over a fresh connection to one scanned port, holding the
/// flow's budget and debiting it as it goes. Each `speak` is one request and its
/// reply, which is enough for the corpus's stateless exchanges; it is bound to
/// the address it was built for and reaches nothing else.
///
/// The budget is enforced at this boundary, which is the point: a flow cannot
/// spend more bytes, time, or connections than it declared, because the thing
/// that would spend them refuses to. An undeclared budget falls back to a default
/// ceiling rather than to no ceiling at all.
struct SocketProbe {
    addr: SocketAddr,
    protocol: Protocol,
    /// Bytes still available across this flow's remaining sends and replies.
    bytes_left: u64,
    /// When the flow's time budget runs out.
    deadline: Instant,
    /// Connections still available to this flow.
    connections_left: u32,
}

impl SocketProbe {
    fn new(addr: SocketAddr, protocol: Protocol, caps: &Capabilities) -> Self {
        let millis = caps.max_millis.map_or(DEFAULT_MAX_MILLIS, u64::from);
        Self {
            addr,
            protocol,
            bytes_left: caps.max_bytes.map_or(DEFAULT_MAX_BYTES, u64::from),
            deadline: Instant::now() + Duration::from_millis(millis),
            connections_left: caps
                .max_connections
                .map_or(DEFAULT_MAX_CONNECTIONS, u32::from),
        }
    }
}

impl Probe for SocketProbe {
    fn speak(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
        // Refuse the exchange the budget cannot pay for, before any packet leaves.
        if self.connections_left == 0 || remaining(self.deadline).is_none() {
            return None;
        }
        let sent = bytes.len() as u64;
        if sent > self.bytes_left {
            return None;
        }
        self.bytes_left -= sent;
        self.connections_left -= 1;

        // The reply may consume at most what the byte budget has left.
        let reply = match self.protocol {
            Protocol::Tcp => tcp_exchange(self.addr, bytes, self.deadline, self.bytes_left),
            Protocol::Udp => udp_exchange(self.addr, bytes, self.deadline, self.bytes_left),
        }?;
        self.bytes_left -= reply.len() as u64;
        Some(reply)
    }
}

/// The time left before `deadline`, or [`None`] if it has passed. Used for every
/// socket timeout so no exchange outlives the flow's time budget.
fn remaining(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

/// Connects, sends `bytes`, and reads the reply until the port falls silent, the
/// byte budget `cap` is spent, or the connection closes. [`None`] on any failure,
/// an expired deadline, or an empty reply.
fn tcp_exchange(addr: SocketAddr, bytes: &[u8], deadline: Instant, cap: u64) -> Option<Vec<u8>> {
    let mut stream =
        TcpStream::connect_timeout(&addr, remaining(deadline)?.min(CONNECT_PROBE_TIMEOUT)).ok()?;
    stream.set_read_timeout(Some(remaining(deadline)?)).ok()?;
    stream.write_all(bytes).ok()?;

    let mut reply = Vec::new();
    let mut buffer = [0u8; 4096];
    while (reply.len() as u64) < cap {
        let want = ((cap - reply.len() as u64) as usize).min(buffer.len());
        match stream.read(&mut buffer[..want]) {
            Ok(0) => break,
            Ok(read) => reply.extend_from_slice(&buffer[..read]),
            // A read timeout is the ordinary end of a reply that does not close
            // the connection; any other error ends it too.
            Err(_) => break,
        }
    }
    (!reply.is_empty()).then_some(reply)
}

/// Sends one datagram and reads one reply, capped at `cap` bytes. [`None`] on
/// failure, an expired deadline, or silence.
fn udp_exchange(addr: SocketAddr, bytes: &[u8], deadline: Instant, cap: u64) -> Option<Vec<u8>> {
    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(addr).ok()?;
    socket.set_read_timeout(Some(remaining(deadline)?)).ok()?;
    socket.send(bytes).ok()?;

    let mut buffer = vec![0u8; cap.min(65535) as usize];
    let read = socket.recv(&mut buffer).ok()?;
    buffer.truncate(read);
    (!buffer.is_empty()).then_some(buffer)
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::flow::schema::{Class, Speak};
    use crate::model::host::Host;
    use crate::model::port::{Port, Service};
    use crate::scanner::session::ScanSession;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// An `active-benign` capability set with the given budgets, for building a
    /// `SocketProbe` a budget test can drive.
    fn caps(
        max_bytes: Option<u32>,
        max_millis: Option<u32>,
        max_connections: Option<u16>,
    ) -> Capabilities {
        Capabilities {
            class: Class::ActiveBenign,
            speak: Some(Speak::Target),
            resolve: false,
            max_bytes,
            max_millis,
            max_connections,
        }
    }

    #[tokio::test]
    async fn detect_runs_a_flow_against_a_live_port_and_records_its_finding() {
        // A loopback "redis" that answers the flow's INFO probe with a version
        // banner, standing in for the real service the flow is written against.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut probe = [0u8; 64];
                let _ = sock.read(&mut probe).await;
                let _ = sock.write_all(b"# Server\r\nredis_version:7.2.4\r\n").await;
            }
        });

        // Seed the store as the earlier phases would: the port is open and
        // identified as redis, so the flow's `when` service gate fits.
        let (session, ctx) = ScanSession::new();
        let ip = addr.ip();
        let mut host = Host::new(ip);
        host.add_port(
            Port::new(addr.port(), Protocol::Tcp, PortState::Open)
                .with_service(Service::new("redis", 100)),
        );
        session.hosts().insert(ip, host);

        detect(
            &ctx,
            ServiceDetection::default(),
            DetectionEnvelope::default(),
        )
        .await;

        let host = session.hosts().get(ip).unwrap();
        let port = host
            .ports()
            .find(|port| port.number() == addr.port())
            .unwrap();
        let findings: Vec<_> = port.findings().collect();
        assert_eq!(
            findings.len(),
            1,
            "the redis flow fired against the live port"
        );
        assert_eq!(findings[0].detection().id(), "redis-unauth-access");
        // Its provenance is the flow's real content hash.
        assert_eq!(findings[0].detection().content_hash().len(), 64);
    }

    #[tokio::test]
    async fn detection_off_connects_to_nothing() {
        let (session, ctx) = ScanSession::new();
        // An open, identified port on an address nothing is listening at:
        // reaching the network would take the connect timeout, so a prompt
        // return is the observable form of "no connection was attempted".
        let unreachable: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        ctx.update_host(unreachable, |host| {
            host.add_port(
                Port::new(6379, Protocol::Tcp, PortState::Open)
                    .with_service(Service::new("redis", 100)),
            );
        });

        let started = std::time::Instant::now();
        detect(&ctx, ServiceDetection::Off, DetectionEnvelope::default()).await;

        assert!(
            started.elapsed() < CONNECT_PROBE_TIMEOUT,
            "a detection turned off cannot have waited on a connection"
        );
        drop(session);
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
        let mut probe = SocketProbe::new(addr, Protocol::Tcp, &caps(Some(20), None, None));
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

        let mut probe = SocketProbe::new(addr, Protocol::Tcp, &caps(None, None, Some(1)));
        assert!(
            probe.speak(b"a").is_some(),
            "the one permitted exchange failed"
        );
        assert!(
            probe.speak(b"b").is_none(),
            "a second connection was opened past the budget"
        );
    }

    #[test]
    fn an_expired_time_budget_refuses_the_exchange() {
        // A zero-millisecond budget is spent the instant it is granted, so no
        // packet leaves; the unreachable address is never dialed.
        let addr: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let mut probe = SocketProbe::new(addr, Protocol::Tcp, &caps(None, Some(0), None));
        assert!(
            probe.speak(b"x").is_none(),
            "an exchange ran past the time budget"
        );
    }
}
