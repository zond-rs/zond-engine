// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Service detection phase
//!
//! The second phase of a port scan: given ports whose *state* discovery already
//! classified, identify *what is running* behind the open ones.
//!
//! ## Why it is a separate phase
//!
//! The unprivileged [`connect`](crate::scanner::strategy::connect) scanner already holds a live
//! `TcpStream` the moment it finds a port open, so it fingerprints inline. The
//! privileged [`TcpPortScanner`](crate::scanner::strategy::routed::TcpPortScanner) never completes a
//! handshake, since it classifies each port from a single raw SYN/SYN-ACK/RST
//! exchange, and so it has no connection to fingerprint through. Fingerprinting
//! does not need raw sockets, it needs a real TCP connection. This phase opens one
//! to each open TCP port and runs the same engine, so a fast privileged scan
//! reports the same service detail as the connect fallback instead of a bare
//! port-to-name guess.
//!
//! Discovery and identification are kept separate on purpose. Finding which ports
//! are open is cheap and benefits from raw-packet speed, while identifying what
//! runs on them needs a real conversation with the service. Splitting the two lets
//! each use the transport that suits it.

use std::net::IpAddr;

use tokio::net::TcpStream;

use crate::model::ip::scoped::ScopedIp;
use crate::warn;
use tokio::time::timeout;

use crate::model::port::{Port, PortState, Protocol};
use crate::scanner::pacing::limits::{CONNECT_CONCURRENCY, CONNECT_PROBE_TIMEOUT};
use crate::scanner::pool::ProbePool;
use crate::scanner::session::{ScanContext, ScannerKind};

/// Fingerprints every open TCP port currently in the store, upgrading each
/// port's service in place.
///
/// Intended to run once, after a discovery phase that established port *state* but
/// not service identity, which is the SYN path. Ports that already carry a
/// fingerprint from the connect scanner would be re-identified harmlessly, but the
/// caller only runs this where it is actually needed.
pub async fn detect(ctx: &ScanContext) {
    // Snapshot the targets up front so no DashMap guard is held across an await.
    let targets = open_tcp_ports(ctx);
    if targets.is_empty() {
        return;
    }

    let mut pool = ProbePool::new(
        CONNECT_CONCURRENCY,
        ctx.clone(),
        ScannerKind::Connect,
        |fingerprinted, _audit| {
            if let Some((ip, port)) = fingerprinted {
                write_back(ctx, ip, port);
            }
        },
    );

    for (target, port) in targets {
        if ctx.handle.should_stop() {
            break;
        }
        pool.admit(fingerprint_one(target, port)).await;
    }

    pool.drain().await;
}

/// Every open TCP `(address, port)` in the store, snapshotted so the DashMap is
/// not borrowed across the connections that follow.
///
/// The address is taken from the host rather than from the store key, because
/// the key is only the address and a link-local one cannot be connected to
/// without the interface it was seen on. The host carries that; see
/// [`Host::scoped_ip`](crate::model::host::Host::scoped_ip).
fn open_tcp_ports(ctx: &ScanContext) -> Vec<(ScopedIp, u16)> {
    let mut targets = Vec::new();
    for host in ctx.store.iter() {
        let address = host.value().scoped_ip();
        for port in host.value().ports() {
            if port.protocol() == Protocol::Tcp && port.state() == PortState::Open {
                targets.push((address.clone(), port.number()));
            }
        }
    }
    targets
}

/// Connects to one open port and fingerprints it, returning the upgraded [`Port`]
/// or `None` if the connection could not be established (the port keeps whatever
/// the discovery phase already recorded).
///
/// A link-local address with no interface recorded against it yields no socket
/// address at all, and is skipped with a word about why. Attempting the
/// connection anyway would fail with an error describing the network, which is a
/// claim about the neighbour rather than about what this host knows.
async fn fingerprint_one(target: ScopedIp, port_number: u16) -> Option<(IpAddr, Port)> {
    let Some(addr) = target.to_socket_addr(port_number) else {
        warn!(
            verbosity = 1,
            "Cannot fingerprint {target}:{port_number}: no interface recorded for a link-local address"
        );
        return None;
    };
    let ip = target.addr();
    let stream = timeout(CONNECT_PROBE_TIMEOUT, TcpStream::connect(addr))
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
    ctx.update_host(ip, |host| {
        host.add_port(port);
    });
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
    use crate::model::host::Host;
    use crate::scanner::session::ScanSession;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn detect_fingerprints_an_open_tcp_port_end_to_end() {
        // A loopback "service" that greets on connect with an SSH banner, standing
        // in for what a SYN-discovered open port would say once we connect.
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
        session.hosts().insert(ip, host);

        detect(&ctx).await;

        let host = session.hosts().get(&ip).unwrap();
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
        session.hosts().insert(ip, host);

        detect(&ctx).await; // must return promptly without connecting anywhere

        let host = session.hosts().get(&ip).unwrap();
        let port = host.ports().find(|p| p.number() == 9).unwrap();
        // Untouched: no service was attached by the phase.
        assert!(port.service().is_none());
    }
}
