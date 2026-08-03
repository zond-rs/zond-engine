// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Service detection phase
//!
//! The second phase of a port scan: given ports whose *state* discovery already
//! classified, identify *what is running* behind the open ones.
//!
//! ## Why it is a separate phase
//!
//! The unprivileged [`connect`](super::connect) scanner already holds a live
//! `TcpStream` the moment it finds a port open, so it fingerprints inline. The
//! privileged [`SynPortScanner`](super::routed::SynPortScanner) never completes
//! a handshake — it classifies each port from a single raw SYN/SYN-ACK/RST
//! exchange — so it has no connection to fingerprint through. Fingerprinting
//! does not need raw sockets; it needs a real TCP connection. This phase opens
//! one to each open TCP port and runs the same engine, so a fast privileged scan
//! reports the same service detail as the connect fallback instead of a bare
//! port→name guess.
//!
//! Discovery and identification are deliberately separate: finding which ports
//! are open is cheap and wants raw-packet speed, while identifying what runs on
//! them needs a real conversation with the service. Keeping them apart lets each
//! use the transport that suits it.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::core::models::port::{Port, PortState, Protocol};
use crate::core::session::ScanContext;
use crate::scanner::pool::ProbePool;

/// How long to wait for the fingerprint connection to establish before giving
/// up on a port. Matches the connect scanner's probe budget.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1_000);

/// How many ports to fingerprint at once. Fingerprinting is I/O-bound (a
/// connection plus banner/probe round-trips per port), so a bounded fan-out
/// keeps a wide scan fast without exhausting sockets.
const CONCURRENCY: usize = 50;

/// Fingerprints every open TCP port currently in the store, upgrading each
/// port's service in place.
///
/// Intended to run once, after a discovery phase that established port *state*
/// but not service identity — i.e. the SYN path. Ports already carrying a
/// fingerprint (from the connect scanner) are re-identified harmlessly, but the
/// caller runs this only where it is needed.
pub async fn detect(ctx: &ScanContext) {
    // Snapshot the targets up front so no DashMap guard is held across an await.
    let targets = open_tcp_ports(ctx);
    if targets.is_empty() {
        return;
    }

    let mut pool = ProbePool::new(CONCURRENCY, |fingerprinted| {
        if let Some((ip, port)) = fingerprinted {
            write_back(ctx, ip, port);
        }
    });

    for (ip, port) in targets {
        if ctx.handle.should_stop() {
            break;
        }
        pool.admit(fingerprint_one(ip, port)).await;
    }

    pool.drain().await;
}

/// Every open TCP `(ip, port)` in the store, snapshotted so the DashMap is not
/// borrowed across the connections that follow.
fn open_tcp_ports(ctx: &ScanContext) -> Vec<(IpAddr, u16)> {
    let mut targets = Vec::new();
    for host in ctx.store.iter() {
        let ip = *host.key();
        for port in host.value().ports() {
            if port.protocol() == Protocol::Tcp && port.state() == PortState::Open {
                targets.push((ip, port.number()));
            }
        }
    }
    targets
}

/// Connects to one open port and fingerprints it, returning the upgraded [`Port`]
/// or `None` if the connection could not be established (the port keeps whatever
/// the discovery phase already recorded).
async fn fingerprint_one(ip: IpAddr, port_number: u16) -> Option<(IpAddr, Port)> {
    let addr = SocketAddr::new(ip, port_number);
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // Seed the same baseline the connect scanner uses, then let the engine
    // refine it over the live connection.
    let port = crate::fingerprinting::baseline_port(port_number, Protocol::Tcp, PortState::Open);
    let port = crate::fingerprinting::fingerprint_tcp(stream, port).await;
    Some((ip, port))
}

/// Folds a freshly fingerprinted port back into its host and announces the
/// update. [`Port::merge`] is confidence-driven, so the fingerprint overwrites
/// the discovery phase's name-only baseline.
fn write_back(ctx: &ScanContext, ip: IpAddr, port: Port) {
    ctx.update_host(ip, |host| host.add_port(port));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::host::Host;
    use crate::core::session::ScanSession;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn detect_fingerprints_an_open_tcp_port_end_to_end() {
        // A loopback "service" that greets on connect with an SSH banner — the
        // stand-in for what a SYN-discovered open port would say once we connect.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n").await;
            }
        });

        // Seed the store as the SYN scanner would: the port is Open, but its
        // service is only the port→name baseline (confidence 0), not identified.
        let (session, ctx) = ScanSession::new();
        let ip = addr.ip();
        let mut host = Host::new(ip);
        host.add_port(Port::new(addr.port(), Protocol::Tcp, PortState::Open));
        session.store.insert(ip, host);

        detect(&ctx).await;

        let host = session.store.get(&ip).unwrap();
        let port = host
            .ports()
            .find(|p| p.number() == addr.port())
            .expect("port present");
        let service = port.service().expect("service identified");
        // The banner was fingerprinted, not left as a bare port→name guess.
        assert_eq!(service.name(), "ssh");
        assert_eq!(service.product(), Some("OpenSSH"));
        assert_eq!(service.version(), Some("9.6p1"));
    }

    #[tokio::test]
    async fn detect_is_a_no_op_with_no_open_ports() {
        let (session, ctx) = ScanSession::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let mut host = Host::new(ip);
        // A closed port must not be probed.
        host.add_port(Port::new(9, Protocol::Tcp, PortState::Closed));
        session.store.insert(ip, host);

        detect(&ctx).await; // must return promptly without connecting anywhere

        let host = session.store.get(&ip).unwrap();
        let port = host.ports().find(|p| p.number() == 9).unwrap();
        // Untouched: no service was attached by the phase.
        assert!(port.service().is_none());
    }
}
