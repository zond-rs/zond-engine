// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Unprivileged TCP Connect Scanning
//!
//! The fallback strategy for when raw sockets are not available, whether because
//! the process is not root, no usable interface exists, or the OS could not route
//! a target. Everything here is built on ordinary [`TcpStream`] connects, so it
//! needs no special privileges and works anywhere the async runtime does.
//!
//! It answers both scan phases. [`discover`] establishes host presence by probing
//! a small set of common infrastructure ports and treating any TCP-layer response,
//! an accept or even a refusal, as proof the host is alive. [`scan`] takes known
//! targets and classifies each port from a full connect handshake. Both consume a
//! randomized [`Dispatcher`] stream and cap their in-flight connections with a
//! [`ProbePool`](super::pool::ProbePool) to avoid exhausting OS sockets, and both
//! record findings through the shared [`ScanContext`] like every other strategy.

use super::dispatcher::Dispatcher;
use super::pool::ProbePool;
use super::{NetworkExplorer, PortScanner, tuning};
use crate::core::models::host::Host;
use crate::core::models::ip::set::IpSet;
use crate::core::models::port::{Port, PortSet, PortState, Protocol};
use crate::core::models::target::{Target, TargetMap, TargetSet};
use crate::core::session::{ScanContext, ScannerKind};
use crate::error;
use async_trait::async_trait;
use dashmap::DashSet;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Most common ports across Linux, Windows, and Networking gear.
const DISCOVERY_PORTS: &[u16] = &[22, 80, 443, 445, 3389];

/// Adapts the unprivileged [`discover`] strategy to [`NetworkExplorer`], so it can
/// be spawned alongside [`LocalScanner`](super::local::LocalScanner) and
/// [`RoutedScanner`](super::routed::RoutedScanner) from a single explorer list.
pub struct ConnectScanner {
    /// The addresses being probed for aliveness.
    ips: IpSet,
    /// Shared state (host store, event channel, abort signal) for the scan
    /// this explorer is part of.
    ctx: ScanContext,
}

impl ConnectScanner {
    pub fn new(ips: IpSet, ctx: ScanContext) -> Self {
        Self { ips, ctx }
    }
}

#[async_trait]
impl NetworkExplorer for ConnectScanner {
    async fn discover_hosts(self: Box<Self>) -> anyhow::Result<()> {
        // A discovery run is single-shot, so it consumes the scanner: `ips` and
        // `ctx` move straight into `discover`, no `mem::take` placeholder needed.
        discover(self.ips, self.ctx).await
    }
}

/// The outcome of one finished [`port_prober`] task: the port it classified, or
/// `None` when the port was closed or the target was not probed at all. A probe
/// never fails, since every network outcome maps to a port state or to `None`, so
/// this is a plain [`Option`] rather than a `Result`.
type ProbedPort = Option<(IpAddr, Port)>;

/// Adapts the unprivileged [`scan`] engine to [`PortScanner`], so
/// [`crate::scanner::scan`] can drive it through the same path as the privileged
/// [`SynPortScanner`](super::routed::SynPortScanner).
///
/// It carries no [`detect_services`](PortScanner::detect_services) override,
/// because the connect engine fingerprints each port inline over the live stream
/// it already holds (see [`port_prober`]), so a second identification pass would
/// be wasted work. This is the reason service detection lives on the trait rather
/// than in the caller: the fact that connect needs no second pass is expressed
/// here by its absence, instead of as a branch at the call site.
pub struct ConnectPortScanner {
    /// Shared state (host store, event channel, abort signal) for the scan this
    /// strategy is part of.
    ctx: ScanContext,
    /// The ceiling on in-flight connect probes.
    concurrency: usize,
}

impl ConnectPortScanner {
    pub fn new(ctx: ScanContext, concurrency: usize) -> Self {
        Self { ctx, concurrency }
    }
}

#[async_trait]
impl PortScanner for ConnectPortScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::Connect
    }

    fn supported_protocols(&self) -> Vec<Protocol> {
        vec![Protocol::Tcp]
    }

    async fn scan(&mut self, rx: mpsc::Receiver<Target>) -> anyhow::Result<()> {
        scan(rx, self.concurrency, self.ctx.clone()).await
    }
}

/// Unprivileged UDP port scanner.
pub struct ConnectUdpPortScanner {
    ctx: ScanContext,
    concurrency: usize,
}

impl ConnectUdpPortScanner {
    pub fn new(ctx: ScanContext, concurrency: usize) -> Self {
        Self { ctx, concurrency }
    }
}

#[async_trait]
impl PortScanner for ConnectUdpPortScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::Connect // or add a new one if preferred, but Connect covers unprivileged
    }

    fn supported_protocols(&self) -> Vec<Protocol> {
        vec![Protocol::Udp]
    }

    async fn scan(&mut self, mut rx: mpsc::Receiver<Target>) -> anyhow::Result<()> {
        let mut pool = ProbePool::new(self.concurrency, |probed| absorb_probe(&self.ctx, probed));

        while let Some(target) = rx.recv().await {
            if self.ctx.handle.should_stop() {
                break;
            }
            pool.admit(udp_port_prober(target)).await;
        }

        pool.drain().await;
        Ok(())
    }
}

/// Performs a high-concurrency, unprivileged port scan.
///
/// This is the primary scanning strategy for callers without root privileges. It
/// consumes a randomized stream of [`Target`]s from a [`Dispatcher`], holding the
/// number of in-flight connections at or below `concurrency_limit` to avoid
/// exhausting OS sockets, and records every non-closed port it finds into the
/// shared [`ScanContext`] store.
pub async fn scan(
    mut rx: mpsc::Receiver<Target>,
    concurrency_limit: usize,
    ctx: ScanContext,
) -> anyhow::Result<()> {
    let mut pool = ProbePool::new(concurrency_limit, |probed| absorb_probe(&ctx, probed));

    while let Some(target) = rx.recv().await {
        if ctx.handle.should_stop() {
            break;
        }
        pool.admit(port_prober(target)).await;
    }

    // Every target dispatched; wait out the probes still in flight.
    pool.drain().await;
    Ok(())
}

/// Folds one finished probe into the store, if it classified a non-closed port.
fn absorb_probe(ctx: &ScanContext, probed: ProbedPort) {
    if let Some((ip, port)) = probed {
        ctx.update_host(ip, |host| host.add_port(port));
    }
}

/// Probes a single [`Target`] over a full TCP connect handshake and classifies
/// its port. Returns `Some(..)` for a non-closed port and `None` for a closed
/// port or a target this strategy doesn't handle.
///
/// An accepted connection is `Open` and gets fingerprinted over the live stream,
/// and a refusal is `Closed`. Anything else is `Filtered`, including a timeout,
/// which is the usual signature of a firewall drop. Only TCP is supported, so UDP
/// targets are skipped.
async fn port_prober(target: Target) -> ProbedPort {
    if target.protocol == Protocol::Udp {
        // UDP can't be probed through a TCP stream; skip rather than misreport.
        return None;
    }

    let socket_addr = SocketAddr::new(target.ip, target.port);

    match timeout(
        tuning::CONNECT_PROBE_TIMEOUT,
        TcpStream::connect(socket_addr),
    )
    .await
    {
        Ok(Ok(stream)) => {
            let port =
                crate::fingerprinting::baseline_port(target.port, Protocol::Tcp, PortState::Open);
            let port = crate::fingerprinting::fingerprint_tcp(stream, port).await;
            Some((target.ip, port))
        }
        Ok(Err(e)) => {
            use std::io::ErrorKind;
            match e.kind() {
                // A refusal is a definite "closed"; report nothing to record.
                ErrorKind::ConnectionRefused => None,
                // Anything else reached the host but didn't complete: filtered.
                _ => Some((
                    target.ip,
                    crate::fingerprinting::baseline_port(
                        target.port,
                        Protocol::Tcp,
                        PortState::Filtered,
                    ),
                )),
            }
        }
        // Timeout: the probe was silently dropped, the classic firewall signature.
        Err(_) => Some((
            target.ip,
            crate::fingerprinting::baseline_port(target.port, Protocol::Tcp, PortState::Filtered),
        )),
    }
}

/// The wildcard address a probe socket for `target` must bind to.
///
/// A socket bound to `0.0.0.0` cannot reach an IPv6 destination - the connect
/// fails outright - so binding the family the target belongs to is what makes
/// v6 targets reachable at all rather than silently unprobed.
fn wildcard_for(target: IpAddr) -> SocketAddr {
    match target {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

/// Probes a single [`Target`] for UDP using a standard OS `UdpSocket`, the
/// unprivileged counterpart of [`UdpPortScanner`](super::routed::UdpPortScanner).
///
/// UDP has no handshake to read a verdict from, so this leans on what the local
/// kernel reports about the datagram it sent. The socket is *connected*, which
/// is what makes that possible: a connected UDP socket has a known peer, so the
/// kernel can attribute an inbound ICMP error to it and surface it as
/// `ConnectionRefused` on a subsequent operation. An unconnected socket
/// discards the same error with nowhere to deliver it.
///
/// A reply is `Open`, a refusal is `Closed`, and silence is `OpenFiltered` -
/// the same three verdicts the raw scanner reaches, by a different route.
/// Errors that say nothing about the target (no local socket, no route) are
/// logged and yield no record rather than a guess.
async fn udp_port_prober(target: Target) -> ProbedPort {
    if target.protocol != Protocol::Udp {
        return None;
    }

    let socket_addr = SocketAddr::new(target.ip, target.port);
    let record = |state| {
        Some((
            target.ip,
            crate::fingerprinting::baseline_port(target.port, Protocol::Udp, state),
        ))
    };

    let socket = match tokio::net::UdpSocket::bind(wildcard_for(target.ip)).await {
        Ok(socket) => socket,
        Err(e) => {
            error!(
                verbosity = 2,
                "No UDP socket for probing {socket_addr}: {e}"
            );
            return None;
        }
    };

    if let Err(e) = socket.connect(socket_addr).await {
        error!(
            verbosity = 2,
            "Cannot address UDP probe to {socket_addr}: {e}"
        );
        return None;
    }

    if let Err(e) = socket.send(b"").await {
        // A refusal can surface here rather than on the receive: the kernel
        // reports a queued ICMP error on whichever operation comes next.
        return match e.kind() {
            ErrorKind::ConnectionRefused => record(PortState::Closed),
            _ => {
                error!(
                    verbosity = 2,
                    "Failed to send UDP probe to {socket_addr}: {e}"
                );
                None
            }
        };
    }

    let mut buf = [0u8; 1024];
    match timeout(tuning::CONNECT_PROBE_TIMEOUT, socket.recv(&mut buf)).await {
        // Something answered, so something is listening.
        Ok(Ok(_)) => record(PortState::Open),
        // An ICMP Port Unreachable, surfaced against the connected peer.
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => record(PortState::Closed),
        // Any other failure leaves the port as unknown as silence does.
        Ok(Err(e)) => {
            error!(
                verbosity = 2,
                "UDP probe to {socket_addr} failed after sending: {e}"
            );
            record(PortState::OpenFiltered)
        }
        // No error and no reply: open but silent, or filtered. UDP cannot tell.
        Err(_) => record(PortState::OpenFiltered),
    }
}

/// Multi-port host discovery for unprivileged environments.
///
/// Sweeps the target networks by probing a small set of common infrastructure
/// ports: SSH (22), HTTP (80), HTTPS (443), SMB (445), and RDP (3389). Spreading
/// the probe across several ports catches hosts that only expose one of them,
/// which improves the odds of finding Linux, Windows, and embedded targets alike.
///
/// Once any port confirms a host is alive, the remaining probes for that IP are
/// skipped, so a host is recorded once rather than once per open port. Targets
/// are drawn from a shuffling [`Dispatcher`] to spread load across the network
/// instead of hammering one subnet at a time, and each probe waits out the
/// [`CONNECT_PROBE_TIMEOUT`](tuning::CONNECT_PROBE_TIMEOUT) so that hosts on slow
/// or distant links still register.
pub async fn discover(ips: IpSet, ctx: ScanContext) -> anyhow::Result<()> {
    let mut target_map = TargetMap::new();
    let port_set = PortSet::try_from(
        DISCOVERY_PORTS
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
            .as_str(),
    )?;
    target_map.add_unit(TargetSet::new(ips, port_set));

    let dispatcher = Dispatcher::new(target_map).with_batch_size(1024);
    let mut rx = dispatcher.run_shuffled(&ctx.handle);
    let found_hosts = Arc::new(DashSet::new());
    let mut pool = ProbePool::new(tuning::DISCOVERY_CONCURRENCY, |probed| {
        absorb_host(&ctx, probed)
    });

    while let Some(target) = rx.recv().await {
        if ctx.handle.should_stop() {
            break;
        }
        let found = Arc::clone(&found_hosts);
        pool.admit(prober(target, found)).await;
    }

    // Every target dispatched; wait out the probes still in flight.
    pool.drain().await;
    Ok(())
}

/// The outcome of one finished [`prober`] task: a live [`Host`], or `None` when
/// the target stayed silent or was already claimed by a parallel probe. A probe
/// never fails, so this is a plain [`Option`] rather than a `Result`.
type ProbedHost = Option<Host>;

/// Merges one finished discovery probe's host into the store. A freshly created
/// entry starts from [`Host::new`] and absorbs the probe's findings (RTT, any
/// extra IPs), so the recorded result is the same whether or not the host was
/// seen before.
fn absorb_host(ctx: &ScanContext, probed: ProbedHost) {
    if let Some(host) = probed {
        let ip = host.primary_ip();
        ctx.update_host(ip, |existing| existing.merge(host));
    }
}

/// Probes a single [`Target`] for host presence over a TCP connect.
///
/// To avoid needless traffic and wasted sockets, it exits early when the host has
/// already been identified by a parallel probe, for example when SSH responded
/// before HTTP finished.
///
/// `found_set` is a sharded [`DashSet`] rather than a `Mutex<HashSet>`, so the
/// many concurrent probes contend per shard instead of on one global lock.
/// `insert` returning `false` is what makes exactly the first prober to reach a
/// host emit it, while the rest fold to `None`.
async fn prober(target: Target, found_set: Arc<DashSet<IpAddr>>) -> ProbedHost {
    // Skip the connect entirely if another probe already found this host.
    if found_set.contains(&target.ip) {
        return None;
    }

    let socket_addr: SocketAddr = SocketAddr::new(target.ip, target.port);

    let start: Instant = Instant::now();
    let alive = match timeout(
        tuning::CONNECT_PROBE_TIMEOUT,
        TcpStream::connect(socket_addr),
    )
    .await
    {
        // A completed handshake means the host is alive.
        Ok(Ok(_)) => true,
        // Only these TCP errors imply the host answered at the IP/TCP layer. Any
        // other error (no route, permission denied, timeout) says nothing.
        Ok(Err(e)) => {
            use std::io::ErrorKind;
            matches!(
                e.kind(),
                ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
            )
        }
        Err(_elapsed) => false,
    };

    // `insert` returns false if a parallel probe already claimed this host, so
    // exactly the first prober to reach it emits the record; the rest fold to None.
    if alive && found_set.insert(target.ip) {
        Some(Host::new(target.ip).with_rtt(start.elapsed()))
    } else {
        None
    }
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
    use tokio::net::UdpSocket;

    fn udp_target(ip: IpAddr, port: u16) -> Target {
        Target {
            ip,
            port,
            protocol: Protocol::Udp,
        }
    }

    /// Reserves a loopback UDP port and releases it, yielding a number nothing
    /// is listening on - so the kernel answers a probe with an ICMP error.
    async fn closed_loopback_udp_port(ip: IpAddr) -> u16 {
        let socket = UdpSocket::bind((ip, 0)).await.expect("bind to reserve");
        let port = socket.local_addr().expect("reserved addr").port();
        drop(socket);
        port
    }

    #[test]
    fn probe_socket_binds_the_target_family() {
        assert!(wildcard_for(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_ipv4());
        assert!(wildcard_for(IpAddr::V6(Ipv6Addr::LOCALHOST)).is_ipv6());
    }

    /// The regression guard for the IPv4-only bind: a v6 target used to fail at
    /// `connect` and vanish without a record or a log. Loopback only, and no
    /// privileges required, so this runs everywhere the suite does.
    #[tokio::test]
    async fn closed_ipv6_port_is_classified_not_dropped() {
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let port = closed_loopback_udp_port(ip).await;

        let probed = udp_port_prober(udp_target(ip, port)).await;

        let (probed_ip, probed_port) = probed.expect("an IPv6 target must produce a verdict");
        assert_eq!(probed_ip, ip);
        assert_eq!(probed_port.number(), port);
        assert_eq!(probed_port.state(), PortState::Closed);
    }

    #[tokio::test]
    async fn closed_ipv4_port_is_closed() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let port = closed_loopback_udp_port(ip).await;

        let probed = udp_port_prober(udp_target(ip, port)).await;

        assert_eq!(probed.expect("a verdict").1.state(), PortState::Closed);
    }

    /// A listener that answers is `Open` over either family.
    #[tokio::test]
    async fn a_listener_that_answers_is_open() {
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let service = UdpSocket::bind((ip, 0)).await.expect("bind service");
            let port = service.local_addr().unwrap().port();
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                if let Ok((_, from)) = service.recv_from(&mut buf).await {
                    let _ = service.send_to(b"pong", from).await;
                }
            });

            let probed = udp_port_prober(udp_target(ip, port)).await;

            assert_eq!(
                probed.expect("a verdict").1.state(),
                PortState::Open,
                "a live {ip} listener must read as open"
            );
        }
    }

    /// TCP targets belong to the connect scanner next door; this prober must
    /// leave them alone rather than misreport them over the wrong protocol.
    #[tokio::test]
    async fn tcp_targets_are_skipped() {
        let target = Target {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 80,
            protocol: Protocol::Tcp,
        };
        assert!(udp_port_prober(target).await.is_none());
    }
}
