// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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
//! [`ProbePool`] to avoid exhausting OS sockets, and both
//! record findings through the shared [`ScanContext`] like every other strategy.

use crate::error;
use crate::model::host::{Host, HostStatus, StatusProtocol, StatusReason};
use crate::model::ip::set::IpSet;
use crate::model::port::{Port, PortSet, PortState, Protocol};
use crate::model::target::{Target, TargetMap, TargetSet};
use crate::scanner::audit::ProbeAudit;
use crate::scanner::dispatcher::Dispatcher;
use crate::scanner::pacing::limits::{CONNECT_PROBE_TIMEOUT, DISCOVERY_CONCURRENCY};
use crate::scanner::payload;
use crate::scanner::pool::ProbePool;
use crate::scanner::report::StopReason;
use crate::scanner::session::{ScanContext, ScannerKind};
use crate::scanner::strategy::{HostScanner, PortScanner, StrategyError};
use async_trait::async_trait;
use dashmap::DashSet;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Adapts the unprivileged [`discover`] strategy to [`HostScanner`], so it can
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
impl HostScanner for ConnectScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::Connect
    }

    async fn discover_hosts(&mut self) -> Result<(), StrategyError> {
        // The targets are taken rather than cloned. A sweep asks each address
        // once, so a second call has nothing left to probe and correctly does
        // nothing, where a clone would silently re-probe the whole set.
        discover(std::mem::take(&mut self.ips), self.ctx.clone()).await
    }
}

/// What one finished prober task learned. A probe never fails, since every
/// network outcome maps to some combination of the fields below, so this is a
/// plain [`Option`] rather than a `Result`.
///
/// `None` means the target was not probed at all.
struct Probed {
    /// The address probed.
    ip: IpAddr,
    /// The port verdict, where the probe produced one.
    ///
    /// Separate from [`Probed::answered`] because the two say different things:
    /// a timeout yields a `Filtered` port and proves nothing about the host,
    /// while a refusal yields a `Closed` port *and* proves the host is up. Only
    /// a target that was never probed - UDP through a TCP prober - carries
    /// `None`.
    port: Option<Port>,
    /// Whether the host answered. The kernel hands back a completed handshake or
    /// a `ConnectionRefused` only when a segment came back from the target, so
    /// either one proves a live stack - a refusal is a RST the kernel
    /// translated. A timeout proves nothing and never sets this.
    answered: bool,
}

/// The outcome of one finished [`port_prober`] task.
type ProbedPort = Option<Probed>;

/// Adapts the unprivileged [`scan`] engine to [`PortScanner`], so
/// [`crate::scanner::scan`] can drive it through the same path as the privileged
/// [`TcpPortScanner`](super::routed::TcpPortScanner).
///
/// It carries no [`detect_services`](PortScanner::detect_services) override,
/// because the connect engine fingerprints each port inline over the live stream
/// it already holds (see this module's port prober), so a second identification pass would
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

    async fn scan(&mut self, rx: mpsc::Receiver<Target>) -> Result<(), StrategyError> {
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
        ScannerKind::ConnectUdp
    }

    fn supported_protocols(&self) -> Vec<Protocol> {
        vec![Protocol::Udp]
    }

    async fn scan(&mut self, mut rx: mpsc::Receiver<Target>) -> Result<(), StrategyError> {
        let ctx = self.ctx.clone();
        let mut pool = ProbePool::new(
            self.concurrency,
            self.ctx.clone(),
            self.kind(),
            |probed, audit: &mut ProbeAudit| absorb_probe(&ctx, probed, audit),
        );

        let mut probes = 0u128;
        let mut reason = StopReason::AttemptsSpent;
        while let Some(target) = rx.recv().await {
            if self.ctx.handle.should_stop() {
                reason = StopReason::Aborted;
                break;
            }
            probes += 1;
            pool.audit().record_send(true);
            pool.admit(udp_port_prober(target)).await;
        }

        pool.drain().await;
        finish(&self.ctx, pool.into_audit(), self.kind(), probes, reason);
        Ok(())
    }
}

/// Performs a high-concurrency, unprivileged port scan.
///
/// This is the primary scanning strategy for callers without root privileges. It
/// consumes a randomized stream of [`Target`]s from a [`Dispatcher`], holding the
/// number of in-flight connections at or below `concurrency_limit` to avoid
/// exhausting OS sockets, and records every port it probed into the shared
/// [`ScanContext`] store - open, closed and filtered alike, so the list does not
/// depend on whether the caller had root.
pub async fn scan(
    mut rx: mpsc::Receiver<Target>,
    concurrency_limit: usize,
    ctx: ScanContext,
) -> Result<(), StrategyError> {
    let folder = ctx.clone();
    let mut pool = ProbePool::new(
        concurrency_limit,
        ctx.clone(),
        ScannerKind::Connect,
        |probed, audit: &mut ProbeAudit| absorb_probe(&folder, probed, audit),
    );

    let mut probes = 0u128;
    let mut reason = StopReason::AttemptsSpent;
    while let Some(target) = rx.recv().await {
        if ctx.handle.should_stop() {
            reason = StopReason::Aborted;
            break;
        }
        probes += 1;
        pool.audit().record_send(true);
        pool.admit(port_prober(target)).await;
    }

    // Every target dispatched; wait out the probes still in flight.
    pool.drain().await;
    finish(
        &ctx,
        pool.into_audit(),
        ScannerKind::Connect,
        probes,
        reason,
    );
    Ok(())
}

/// Folds one finished probe into the store: the port it classified, if it
/// classified one worth keeping, and what the exchange proved about the host.
///
/// A refused connection reaches here with no port and `answered` set, which is
/// the case worth noticing: this strategy declines to file closed ports, but the
/// RST behind the refusal still proves the host is there, and that evidence
/// would otherwise be dropped along with the port verdict.
fn absorb_probe(ctx: &ScanContext, probed: ProbedPort, audit: &mut ProbeAudit) {
    let Some(probed) = probed else {
        return;
    };
    if probed.answered {
        // A connect probe carries no attempt token: the retransmission that may
        // have produced this answer was the host stack's, on its own schedule
        // (see `CONNECT_PROBE_TIMEOUT`), so which attempt was answered is
        // not knowable from here.
        audit.record_host_found(None);
    }
    if probed.port.is_none() && !probed.answered {
        return;
    }

    ctx.update_host(probed.ip, |host| {
        if let Some(port) = probed.port.clone() {
            host.add_port(port);
        }
        if probed.answered {
            host.record_evidence(
                HostStatus::Up,
                StatusReason::new(StatusProtocol::TcpSyn, "tcp connect answered by the host"),
            );
        }
    });
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

    match timeout(CONNECT_PROBE_TIMEOUT, TcpStream::connect(socket_addr)).await {
        Ok(Ok(stream)) => {
            let port =
                crate::fingerprint::baseline_port(target.port, Protocol::Tcp, PortState::Open);
            let port = crate::fingerprint::fingerprint_tcp(stream, port).await;
            Some(Probed {
                ip: target.ip,
                port: Some(port),
                answered: true,
            })
        }
        Ok(Err(e)) => {
            match e.kind() {
                // A refusal is the clearest verdict this scanner ever gets, and
                // it is filed as one. The RST the kernel translated into it
                // proves two things at once: the port has nothing listening, and
                // something is there to say so.
                //
                // Recorded rather than dropped because a port list that changes
                // with the caller's privilege level is not a smaller answer, it
                // is a different one. The raw path files `Closed` here, so
                // omitting it left an unprivileged report with no `Closed` entry
                // in its `ports_by_state` however many refusals it collected -
                // a summary that was structurally wrong rather than merely
                // incomplete, and exactly the kind of difference somebody
                // diffing two scans would read as a change in the network.
                ErrorKind::ConnectionRefused => Some(Probed {
                    ip: target.ip,
                    port: Some(crate::fingerprint::baseline_port(
                        target.port,
                        Protocol::Tcp,
                        PortState::Closed,
                    )),
                    answered: true,
                }),
                // Anything else failed without the target having answered - a
                // local routing failure, an exhausted resource - so the port is
                // filtered and the host has proved nothing.
                _ => Some(Probed {
                    ip: target.ip,
                    port: Some(crate::fingerprint::baseline_port(
                        target.port,
                        Protocol::Tcp,
                        PortState::Filtered,
                    )),
                    answered: false,
                }),
            }
        }
        // Timeout: the probe was silently dropped, the classic firewall signature.
        Err(_) => Some(Probed {
            ip: target.ip,
            port: Some(crate::fingerprint::baseline_port(
                target.port,
                Protocol::Tcp,
                PortState::Filtered,
            )),
            answered: false,
        }),
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
    // `answered` is set only where the kernel vouches for who sent the packet.
    // A datagram arriving on a connected socket came from the peer, so `Open`
    // proves the host. A refusal does not: it is an ICMP error the kernel
    // matched to this socket by the datagram it quotes, and the error's own
    // source address - a router's, or the target's - is not surfaced through
    // this API at all. The privileged scanner reads that address and can tell
    // the two apart; here the port verdict stands on its own and no claim is
    // made about the host.
    let record = |state, answered| {
        Some(Probed {
            ip: target.ip,
            port: Some(crate::fingerprint::baseline_port(
                target.port,
                Protocol::Udp,
                state,
            )),
            answered,
        })
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

    if let Err(e) = socket.send(payload::for_port(target.port)).await {
        // A refusal can surface here rather than on the receive: the kernel
        // reports a queued ICMP error on whichever operation comes next.
        return match e.kind() {
            ErrorKind::ConnectionRefused => record(PortState::Closed, false),
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
    match timeout(CONNECT_PROBE_TIMEOUT, socket.recv(&mut buf)).await {
        // Something answered, so something is listening.
        Ok(Ok(_)) => record(PortState::Open, true),
        // An ICMP Port Unreachable, surfaced against the connected peer.
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => record(PortState::Closed, false),
        // Any other failure leaves the port as unknown as silence does.
        Ok(Err(e)) => {
            error!(
                verbosity = 2,
                "UDP probe to {socket_addr} failed after sending: {e}"
            );
            record(PortState::OpenFiltered, false)
        }
        // No error and no reply: open but silent, or filtered. UDP cannot tell.
        Err(_) => record(PortState::OpenFiltered, false),
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
/// [`CONNECT_PROBE_TIMEOUT`] so that hosts on slow
/// or distant links still register.
pub async fn discover(ips: IpSet, ctx: ScanContext) -> Result<(), StrategyError> {
    let mut target_map = TargetMap::new();
    // The same list `PortSet::common_discovery` names, taken from there rather
    // than spelled again here. Two copies of five port numbers is two copies to
    // keep in step, and nothing would have reported them drifting apart.
    target_map.add_unit(TargetSet::new(ips, PortSet::common_discovery()));

    let dispatcher = Dispatcher::new(target_map).with_batch_size(1024);
    let mut rx = dispatcher.run_shuffled(&ctx.handle);
    let found_hosts = Arc::new(DashSet::new());
    let folder = ctx.clone();
    let mut pool = ProbePool::new(
        DISCOVERY_CONCURRENCY,
        ctx.clone(),
        ScannerKind::Connect,
        |probed, audit: &mut ProbeAudit| absorb_host(&folder, probed, audit),
    );

    let mut probes = 0u128;
    let mut reason = StopReason::AttemptsSpent;
    while let Some(target) = rx.recv().await {
        if ctx.handle.should_stop() {
            reason = StopReason::Aborted;
            break;
        }
        probes += 1;
        pool.audit().record_send(true);
        let found = Arc::clone(&found_hosts);
        pool.admit(prober(target, found)).await;
    }

    // Every target dispatched; wait out the probes still in flight.
    pool.drain().await;
    finish(
        &ctx,
        pool.into_audit(),
        ScannerKind::Connect,
        probes,
        reason,
    );
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
fn absorb_host(ctx: &ScanContext, probed: ProbedHost, audit: &mut ProbeAudit) {
    if let Some(host) = probed {
        let ip = host.primary_ip();
        // See `absorb_probe`: this path has no attempt to attribute the answer
        // to, so every host it finds is counted as unattributed.
        audit.record_host_found(None);
        ctx.update_host(ip, |existing| existing.merge(host));
    }
}

/// Files what one connect run observed about itself.
///
/// Shared by all three, because they differ only in what they probe for. There
/// is no capture to report: a connect probe is a socket, so what the kernel
/// discarded is not knowable here rather than being zero, and `None` says so.
///
/// The counters this path can honestly fill are the ones about *the run* -
/// how many probes it started, how many answered, when, and why it stopped.
/// `segments_seen` and `answered_on` stay empty because a connect probe sees no
/// segments and names no attempt; see [`absorb_probe`].
fn finish(
    ctx: &ScanContext,
    audit: ProbeAudit,
    scanner: ScannerKind,
    probes: u128,
    reason: StopReason,
) {
    audit.report("connect", probes, reason, None);
    ctx.record_probe_stats(audit.stats(scanner, probes, reason, None));
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
    let alive = match timeout(CONNECT_PROBE_TIMEOUT, TcpStream::connect(socket_addr)).await {
        // A completed handshake means the host is alive.
        Ok(Ok(_)) => true,
        // Only these TCP errors imply the host answered at the IP/TCP layer. Any
        // other error (no route, permission denied, timeout) says nothing.
        Ok(Err(e)) => {
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
        let mut host = Host::new(target.ip).with_rtt(start.elapsed());
        // Every outcome that reaches here with `alive` set required a segment
        // from the target: a completed handshake, or a reset the kernel surfaced
        // as one of the connection errors above. `Host::merge` keeps the
        // stronger status, so this survives being folded into an entry another
        // strategy created first.
        host.record_evidence(
            HostStatus::Up,
            StatusReason::new(StatusProtocol::TcpSyn, "tcp connect answered by the host"),
        );
        Some(host)
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

        let probed = probed.expect("an IPv6 target must produce a verdict");
        let probed_port = probed.port.expect("a closed port is still a verdict");
        assert_eq!(probed.ip, ip);
        assert_eq!(probed_port.number(), port);
        assert_eq!(probed_port.state(), PortState::Closed);
    }

    #[tokio::test]
    async fn closed_ipv4_port_is_closed() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let port = closed_loopback_udp_port(ip).await;

        let probed = udp_port_prober(udp_target(ip, port)).await;

        assert_eq!(
            probed
                .and_then(|probed| probed.port)
                .expect("a verdict")
                .state(),
            PortState::Closed
        );
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
                probed
                    .and_then(|probed| probed.port)
                    .expect("a verdict")
                    .state(),
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
