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
//! targets and classifies each port from a full connect handshake.
//!
//! Both draw their work in shuffled batches and cap their in-flight connections
//! with a [`ProbePool`] to avoid exhausting OS sockets, and both record findings
//! through the shared [`ScanContext`] like every other strategy. What they draw
//! differs with the phase: a sweep asks about an address and a port scan about
//! an address paired with a port, which is the unit each of them settles.

use crate::config::ServiceDetection;
use crate::config::limits::{CONNECT_PROBE_TIMEOUT, DISCOVERY_CONCURRENCY};
use crate::error;
use crate::evasion::EvasionProfile;
use crate::fingerprint::os;
use crate::journal::settle::{Outcome, Settled};
use crate::model::host::{Host, HostStatus, NetworkRole, OsEvidence, StatusProtocol, StatusReason};
use crate::model::ip::set::IpSet;
use crate::model::port::discovery::{Discovery, ScanResponse};
use crate::model::port::{Port, PortSet, PortState, Protocol};
use crate::model::target::PlannedTarget;
use crate::report::ScannerKind;
use crate::report::StopReason;
use crate::scanner::audit::ProbeAudit;
use crate::scanner::dispatcher::shuffled_addresses;
use crate::scanner::handle::ScanHandle;
use crate::scanner::payload;
use crate::scanner::pool::ProbePool;
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::{HostScanner, PortScanner, StrategyError};
use async_trait::async_trait;
use socket2::{Domain, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// The evasion an unprivileged connect probe can honour: a source port to leave
/// from and a hop limit to carry.
///
/// Both are ordinary socket options that need no privilege, so they belong on
/// this path as much as on the raw one: a hop limit a filter keys on should be
/// the chosen value on *every* probe, the connect fallback included, or the
/// fallback would leak the real one. The framing techniques — a spoofed hardware
/// address, fragmentation, decoys — are absent here because they need a
/// self-built frame this path never touches; a profile that asks for one opens
/// the Ethernet path and never reaches this scanner. The segment shapers —
/// padding, a corrupt checksum — are absent for a different reason: the kernel
/// builds the segment a connect sends, so there is nothing here to shape.
#[derive(Debug, Clone, Copy, Default)]
struct ConnectShaping {
    /// The source port every probe binds to, or `None` to let the OS choose one.
    source_port: Option<u16>,
    /// The hop limit every probe carries, or `None` to leave the OS default.
    hop_limit: Option<u8>,
}

impl ConnectShaping {
    /// Whether either field departs from what the OS would pick, so a plain
    /// connect can be taken when it does not.
    fn is_active(self) -> bool {
        self.source_port.is_some() || self.hop_limit.is_some()
    }
}

impl From<&EvasionProfile> for ConnectShaping {
    fn from(evasion: &EvasionProfile) -> Self {
        Self {
            source_port: evasion.source_port,
            hop_limit: evasion.ttl,
        }
    }
}

/// Adapts the unprivileged [`discover`] strategy to [`HostScanner`], so it can
/// be spawned alongside [`LocalScanner`](super::local::LocalScanner) and
/// [`RoutedScanner`](super::routed::RoutedScanner) from a single explorer list.
pub struct ConnectScanner {
    /// The addresses being probed for aliveness.
    ips: IpSet,
    /// Shared state (host store, event channel, abort signal) for the scan
    /// this explorer is part of.
    ctx: ScanContext,
    /// What each liveness probe changes about the packet it sends. Only the
    /// source port and hop limit reach the wire from here (see [`ConnectShaping`]).
    evasion: EvasionProfile,
}

impl ConnectScanner {
    /// Checks each of `ips` for a pulse, connecting to a handful of common
    /// infrastructure ports and taking any TCP-layer answer, an accept or a
    /// refusal alike, as proof that something is there.
    ///
    /// Hosts are filed through `ctx`. Of `evasion`, only the source port and
    /// the hop limit reach the wire; the kernel builds the rest of what a
    /// connect sends.
    pub fn new(ips: IpSet, ctx: ScanContext, evasion: &EvasionProfile) -> Self {
        Self {
            ips,
            ctx,
            evasion: evasion.clone(),
        }
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
        discover(
            std::mem::take(&mut self.ips),
            self.ctx.clone(),
            &self.evasion,
        )
        .await
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
    /// What the port said while it was being fingerprinted, carried out of the
    /// probe for the detection phase to hand a passive detection.
    ///
    /// This scanner holds the only connection an unprivileged scan makes to the
    /// port, so bytes dropped here are bytes no later phase can read without
    /// dialling again. Empty for every probe that drew nothing.
    responses: Vec<String>,

    /// What those same bytes said about the *machine*, carried out for the same
    /// reason and filed in a different place: the service belongs to the port,
    /// the operating system to the host.
    ///
    /// Empty for every probe that drew nothing, and for every verdict that came
    /// from the kernel rather than from a conversation.
    about_the_host: Vec<OsEvidence>,
    /// Whether the host answered. The kernel hands back a completed handshake or
    /// a `ConnectionRefused` only when a segment came back from the target, so
    /// either one proves a live stack - a refusal is a RST the kernel
    /// translated. A timeout proves nothing and never sets this.
    answered: bool,
    /// What became of this target, for a resume.
    ///
    /// Distinct from [`answered`](Self::answered), which is about the *host*: a
    /// timeout proves nothing about the host and still settles the target,
    /// because the connect made its one and only attempt.
    outcome: Outcome,
    /// What the reply proved the host *is*, where its protocol says so.
    ///
    /// A claim about the host rather than about the port, and carried alongside
    /// the verdict rather than folded into it for that reason: a name server
    /// and a socket bound to 53 produce the same `Open`, and only one of them
    /// is a name server. See [`payload::declared_role`].
    role: Option<NetworkRole>,
}

/// The outcome of one finished [`port_prober`] task.
type ProbedPort = Option<Probed>;

/// Adapts the unprivileged [`scan`] engine to [`PortScanner`], so
/// [`crate::scanner::scan`] can drive it through the same path as the privileged
/// [`TcpPortScanner`](super::ports::TcpPortScanner).
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
    /// How far each probe may go to name what answered.
    ///
    /// [`ServiceDetection::Off`] means something slightly different here than it
    /// does on the privileged path, and the difference is worth knowing: this
    /// scanner's connection *is* how the port's state is established, so turning
    /// identification off skips the conversation, never the connection. A caller
    /// who needs the target's application logs to stay clean needs raw sockets;
    /// without them, being seen is the price of the answer.
    detection: ServiceDetection,
    /// What each probe changes about the packet it sends. Only the source port
    /// and hop limit reach the wire from here (see [`ConnectShaping`]).
    evasion: EvasionProfile,
}

impl ConnectPortScanner {
    /// Settles each `(address, port)` it is fed with a full handshake, holding
    /// at most `concurrency` connections open and recording verdicts through
    /// `ctx`.
    ///
    /// `detection` decides how far the conversation goes once a port answers,
    /// not whether the connection is made: the connection is what establishes
    /// the state. `evasion` contributes the source port and the hop limit.
    pub fn new(
        ctx: ScanContext,
        concurrency: usize,
        detection: ServiceDetection,
        evasion: &EvasionProfile,
    ) -> Self {
        Self {
            ctx,
            concurrency,
            detection,
            evasion: evasion.clone(),
        }
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

    async fn scan(&mut self, rx: mpsc::Receiver<PlannedTarget>) -> Result<(), StrategyError> {
        scan(
            rx,
            self.concurrency,
            self.ctx.clone(),
            self.detection,
            &self.evasion,
        )
        .await
    }
}

/// Unprivileged UDP port scanner.
pub struct ConnectUdpPortScanner {
    ctx: ScanContext,
    concurrency: usize,
    /// What each probe changes about the packet it sends. Only the source port
    /// and hop limit reach the wire from here (see [`ConnectShaping`]).
    evasion: EvasionProfile,
}

impl ConnectUdpPortScanner {
    /// Sends one datagram per `(address, port)` it is fed, `concurrency` of
    /// them in flight at a time, and files what came back through `ctx`. As on
    /// the TCP path, `evasion` reaches the wire as a source port and a hop
    /// limit and no further.
    ///
    /// A closed verdict here proves nothing about the host. It comes from an
    /// ICMP error the kernel matched to the socket, and the error's own source,
    /// a router as easily as the target, is not surfaced through this API. Only
    /// a datagram coming back proves the port and the host at once.
    pub fn new(ctx: ScanContext, concurrency: usize, evasion: &EvasionProfile) -> Self {
        Self {
            ctx,
            concurrency,
            evasion: evasion.clone(),
        }
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

    async fn scan(&mut self, mut rx: mpsc::Receiver<PlannedTarget>) -> Result<(), StrategyError> {
        let ctx = self.ctx.clone();
        let shaping = ConnectShaping::from(&self.evasion);
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
            pool.admit(udp_port_prober(target, shaping)).await;
        }

        pool.drain().await;
        finish(&self.ctx, pool.into_audit(), self.kind(), probes, reason);
        Ok(())
    }
}

/// Performs a high-concurrency, unprivileged port scan.
///
/// This is the primary scanning strategy for callers without root privileges. It
/// consumes the randomized stream of targets a
/// [`Dispatcher`](crate::scanner::dispatcher::Dispatcher) produces, holding the
/// number of in-flight connections at or below `concurrency_limit` to avoid
/// exhausting OS sockets, and records every port it probed into the shared
/// [`ScanContext`] store - open, closed and filtered alike, so the list does not
/// depend on whether the caller had root.
pub async fn scan(
    mut rx: mpsc::Receiver<PlannedTarget>,
    concurrency_limit: usize,
    ctx: ScanContext,
    detection: ServiceDetection,
    evasion: &EvasionProfile,
) -> Result<(), StrategyError> {
    let shaping = ConnectShaping::from(evasion);
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
            // This one was taken off the queue and never asked, so it counts
            // with the rest still waiting behind it.
            ctx.record_outcome(Outcome::Unasked);
            break;
        }
        probes += 1;
        pool.audit().record_send(true);
        pool.admit(port_prober(target, detection, shaping)).await;
    }

    // Anything still queued was never sent, and carries no position to settle.
    while rx.try_recv().is_ok() {
        ctx.record_outcome(Outcome::Unasked);
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
///
/// The responses the inline fingerprint drew are kept here too. They belong to
/// no host record, so they go to the context the
/// [detection phase](crate::scanner::detect) reads them from, which is the same
/// place [`service::detect`](crate::scanner::service::detect) puts the ones a
/// raw scan draws in its second pass.
fn absorb_probe(ctx: &ScanContext, probed: ProbedPort, audit: &mut ProbeAudit) {
    let Some(probed) = probed else {
        return;
    };
    ctx.record_outcome(probed.outcome);
    if probed.answered {
        // A connect probe carries no attempt token: the retransmission that may
        // have produced this answer was the host stack's, on its own schedule
        // (see `CONNECT_PROBE_TIMEOUT`), so which attempt was answered is
        // not knowable from here.
        audit.record_host_found(None);
    }
    if probed.port.is_none() && !probed.answered && probed.role.is_none() {
        return;
    }

    // Filed under the same key the port is, which is the key the detection
    // phase looks the responses up by: a host's zone comes from the key it was
    // stored under, so the two cannot disagree.
    if let Some((number, protocol)) = probed
        .port
        .as_ref()
        .map(|port| (port.number(), port.protocol()))
    {
        ctx.record_responses(probed.ip.into(), number, protocol, probed.responses);
    }

    ctx.update_host(probed.ip, |host| {
        if let Some(port) = probed.port.clone() {
            host.add_port(port);
        }
        if let Some(role) = probed.role {
            host.add_network_role(role);
        }
        if probed.answered {
            host.record_evidence(
                HostStatus::Up,
                StatusReason::new(StatusProtocol::TcpSyn, "tcp connect answered by the host"),
            );
        }
        if !probed.about_the_host.is_empty() {
            // The same call the service phase makes on the privileged path.
            // What a banner says about the machine is worth the same whichever
            // scanner happened to draw it, and this scanner is the only one
            // that draws it without a raw socket.
            os::identify(host, probed.about_the_host.clone());
        }
    });
}

/// A port in `state`, carrying the packet that settled it where one did.
///
/// This scanner never sees a segment — the kernel does the handshake and hands
/// back an outcome — but the outcome names the packet exactly: a completed
/// connection is a SYN/ACK, a refusal is the RST the kernel translated into it,
/// and a timeout is silence. Recorded so an unprivileged report can say what its
/// verdicts rest on, which is the one thing separating a port a firewall dropped
/// from a port nothing was listening on.
///
/// `None` where no packet is implied: a local failure — no route, no socket
/// left — is this host giving up, and crediting the target with a silence it was
/// never asked for would be evidence of the wrong thing.
fn settled(number: u16, state: PortState, reason: Option<ScanResponse>) -> Port {
    let port = crate::fingerprint::baseline_port(number, Protocol::Tcp, state);

    match reason {
        Some(reason) => port.with_discovery(Discovery::new(reason)),
        None => port,
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
async fn port_prober(
    planned: PlannedTarget,
    detection: ServiceDetection,
    shaping: ConnectShaping,
) -> ProbedPort {
    let target = planned.target;
    if target.protocol == Protocol::Udp {
        // UDP can't be probed through a TCP stream; skip rather than misreport.
        // No outcome: unreported is re-probed, which is what a routing mistake
        // deserves.
        return None;
    }

    let position = planned.position;
    let socket_addr = SocketAddr::new(target.ip, target.port);

    match timeout(CONNECT_PROBE_TIMEOUT, connect_shaped(socket_addr, shaping)).await {
        Ok(Ok(stream)) => {
            let port = settled(target.port, PortState::Open, Some(ScanResponse::TcpSynAck));
            // The detailed form, for the second and third values. This
            // handshake is the only conversation an unprivileged scan has with
            // the port, so what it draws here is everything any later phase can
            // read without dialling again: the responses a passive detection
            // needs, and what the same bytes said about the machine.
            let (port, about_the_host, responses) =
                crate::fingerprint::fingerprint_tcp_detailed(stream, port, detection).await;
            Some(Probed {
                ip: target.ip,
                port: Some(port),
                responses,
                about_the_host,
                answered: true,
                outcome: Outcome::Answered { position },
                // A TCP handshake proves a service, and the service is the
                // port's to name. No role is read from one.
                role: None,
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
                    port: Some(settled(
                        target.port,
                        PortState::Closed,
                        Some(ScanResponse::TcpRst),
                    )),
                    responses: Vec::new(),
                    about_the_host: Vec::new(),
                    answered: true,
                    outcome: Outcome::Answered { position },
                    role: None,
                }),
                // Anything else failed without the target having answered - a
                // local routing failure, an exhausted resource - so the port is
                // filtered and the host has proved nothing.
                // A local failure — no route, no socket left — says nothing
                // about the target, and the next sitting may well get further.
                // No evidence recorded: nothing was sent and nothing answered,
                // so there is no packet to name. A port carrying `no reply`
                // here would credit the target with a silence it was never
                // asked for.
                _ => Some(Probed {
                    ip: target.ip,
                    port: Some(settled(target.port, PortState::Filtered, None)),
                    responses: Vec::new(),
                    about_the_host: Vec::new(),
                    answered: false,
                    outcome: Outcome::Unroutable,
                    role: None,
                }),
            }
        }
        // Timeout: the probe was silently dropped, the classic firewall
        // signature. Settled, because a connect gets one attempt and this was
        // it — the whole budget, spent.
        Err(_) => Some(Probed {
            ip: target.ip,
            port: Some(settled(
                target.port,
                PortState::Filtered,
                Some(ScanResponse::NoResponse),
            )),
            responses: Vec::new(),
            about_the_host: Vec::new(),
            answered: false,
            outcome: Outcome::Exhausted { position },
            role: None,
        }),
    }
}

/// The address a probe socket for a destination in `family`'s address family
/// binds its source to, carrying `port` (`0` lets the OS pick one).
///
/// A socket bound to `0.0.0.0` cannot reach an IPv6 destination - the connect
/// fails outright - so binding the family the target belongs to is what makes
/// v6 targets reachable at all rather than silently unprobed.
fn source_bind(family: IpAddr, port: u16) -> SocketAddr {
    match family {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
    }
}

/// The wildcard, ephemeral-port address a probe socket for `target` binds to
/// when nothing about its source is being chosen.
fn wildcard_for(target: IpAddr) -> SocketAddr {
    source_bind(target, 0)
}

/// Sets `shaping`'s hop limit on a fresh socket, and — where a source port is
/// pinned — the address reuse a pinned port needs.
///
/// The hop limit goes on with the option the address family uses (`IP_TTL` or
/// `IPV6_UNICAST_HOPS`), so it is in force before the first byte leaves. Address
/// reuse is what lets the many probes a scan runs at once each bind the one
/// pinned source port: every probe still carries a distinct four-tuple through
/// its destination, so the kernel keeps their replies apart. The bind itself is
/// left to the caller, because TCP binds only to pin a port while UDP must bind
/// before it can send at all.
fn configure_shaping(
    socket: &Socket,
    family: IpAddr,
    shaping: ConnectShaping,
) -> std::io::Result<()> {
    if let Some(hops) = shaping.hop_limit {
        match family {
            IpAddr::V4(_) => socket.set_ttl_v4(hops.into())?,
            IpAddr::V6(_) => socket.set_unicast_hops_v6(hops.into())?,
        }
    }
    if shaping.source_port.is_some() {
        socket.set_reuse_address(true)?;
        // Unix only, and both supported platforms are: without it a second
        // socket on the pinned port is refused rather than bound alongside.
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
    }
    Ok(())
}

/// A TCP socket set up to honour `shaping`, ready to connect to a peer in
/// `family`'s address family. Only reached when `shaping` is active.
fn shaped_tcp_socket(family: IpAddr, shaping: ConnectShaping) -> std::io::Result<TcpSocket> {
    let domain = match family {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(socket2::Protocol::TCP))?;
    configure_shaping(&socket, family, shaping)?;
    if let Some(port) = shaping.source_port {
        socket.bind(&source_bind(family, port).into())?;
    }
    socket.set_nonblocking(true)?;
    Ok(TcpSocket::from_std_stream(std::net::TcpStream::from(
        socket,
    )))
}

/// Connects to `addr`, honouring `shaping`.
///
/// With inert shaping this is exactly a plain [`TcpStream::connect`], so a scan
/// that chose neither a source port nor a hop limit sends the SYN it always has,
/// byte for byte.
async fn connect_shaped(addr: SocketAddr, shaping: ConnectShaping) -> std::io::Result<TcpStream> {
    if !shaping.is_active() {
        return TcpStream::connect(addr).await;
    }
    shaped_tcp_socket(addr.ip(), shaping)?.connect(addr).await
}

/// A UDP socket bound to `family`'s wildcard and honouring `shaping`, ready to
/// be connected to a peer.
///
/// With inert shaping this is the plain ephemeral bind the scanner has always
/// used. Otherwise the socket carries the chosen hop limit and binds the chosen
/// source port (or an ephemeral one, so a hop-limit-only scan still has a socket
/// to send from).
async fn shaped_udp_socket(
    family: IpAddr,
    shaping: ConnectShaping,
) -> std::io::Result<tokio::net::UdpSocket> {
    if !shaping.is_active() {
        return tokio::net::UdpSocket::bind(wildcard_for(family)).await;
    }
    let domain = match family {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(socket2::Protocol::UDP))?;
    configure_shaping(&socket, family, shaping)?;
    socket.bind(&source_bind(family, shaping.source_port.unwrap_or(0)).into())?;
    socket.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(socket))
}

/// Probes a single [`Target`] for UDP using a standard OS `UdpSocket`, the
/// unprivileged counterpart of [`UdpPortScanner`](super::ports::UdpPortScanner).
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
async fn udp_port_prober(planned: PlannedTarget, shaping: ConnectShaping) -> ProbedPort {
    let target = planned.target;
    if target.protocol != Protocol::Udp {
        return None;
    }

    let position = planned.position;
    let socket_addr = SocketAddr::new(target.ip, target.port);
    // `answered` is set only where the kernel vouches for who sent the packet.
    // A datagram arriving on a connected socket came from the peer, so `Open`
    // proves the host. A refusal does not: it is an ICMP error the kernel
    // matched to this socket by the datagram it quotes, and the error's own
    // source address - a router's, or the target's - is not surfaced through
    // this API at all. The privileged scanner reads that address and can tell
    // the two apart; here the port verdict stands on its own and no claim is
    // made about the host.
    let record = |state, answered, outcome| {
        Some(Probed {
            ip: target.ip,
            port: Some(crate::fingerprint::baseline_port(
                target.port,
                Protocol::Udp,
                state,
            )),
            // Nothing on this path turns a datagram into the text a detection
            // reads: the reply is read for the role it declares and no more.
            responses: Vec::new(),
            about_the_host: Vec::new(),
            answered,
            outcome,
            // Filled in by the one arm that has a reply to read it from.
            role: None,
        })
    };

    let socket = match shaped_udp_socket(target.ip, shaping).await {
        Ok(socket) => socket,
        Err(e) => {
            error!(
                verbosity = 2,
                "no UDP socket for probing {socket_addr}: {e}"
            );
            return None;
        }
    };

    if let Err(e) = socket.connect(socket_addr).await {
        error!(
            verbosity = 2,
            "cannot address UDP probe to {socket_addr}: {e}"
        );
        return None;
    }

    if let Err(e) = socket.send(payload::for_port(target.port)).await {
        // A refusal can surface here rather than on the receive: the kernel
        // reports a queued ICMP error on whichever operation comes next.
        return match e.kind() {
            ErrorKind::ConnectionRefused => {
                record(PortState::Closed, false, Outcome::Answered { position })
            }
            _ => {
                error!(
                    verbosity = 2,
                    "failed to send UDP probe to {socket_addr}: {e}"
                );
                None
            }
        };
    }

    let mut buf = [0u8; 1024];
    match timeout(CONNECT_PROBE_TIMEOUT, socket.recv(&mut buf)).await {
        // Something answered, so something is listening — and what it said may
        // prove what the host is, which is a claim no port verdict can make.
        // Read here rather than left to the privileged path, so a scan without
        // root reaches the same conclusions about the network.
        Ok(Ok(read)) => {
            record(PortState::Open, true, Outcome::Answered { position }).map(|probed| Probed {
                role: payload::declared_role(target.port, &buf[..read]),
                ..probed
            })
        }
        // An ICMP Port Unreachable, surfaced against the connected peer.
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => {
            record(PortState::Closed, false, Outcome::Answered { position })
        }
        // Any other failure leaves the port as unknown as silence does.
        Ok(Err(e)) => {
            error!(
                verbosity = 2,
                "UDP probe to {socket_addr} failed after sending: {e}"
            );
            // A local read failure, not a fact about the target.
            record(PortState::OpenFiltered, false, Outcome::Unroutable)
        }
        // No error and no reply: open but silent, or filtered. UDP cannot tell.
        // Settled either way — this probe had one attempt and spent it.
        Err(_) => record(
            PortState::OpenFiltered,
            false,
            Outcome::Exhausted { position },
        ),
    }
}

/// Files what a finished sweep or scan measured.
///
/// Both halves of this strategy report the same way, so the audit line and the
/// recorded counters cannot drift between them.
fn finish(
    ctx: &ScanContext,
    audit: ProbeAudit,
    scanner: ScannerKind,
    probes: u128,
    reason: StopReason,
) {
    audit.report("connect", probes, reason, None, None);
    ctx.record_probe_stats(audit.stats(scanner, probes, reason, None, None));
}

/// Multi-port host discovery for unprivileged environments.
///
/// Sweeps the target networks by probing a small set of common infrastructure
/// ports: SSH (22), HTTP (80), HTTPS (443), SMB (445), and RDP (3389). Spreading
/// the probe across several ports catches hosts that only expose one of them,
/// which improves the odds of finding Linux, Windows, and embedded targets alike.
///
/// **One task per address, not per port.** Its ports are tried in turn and the
/// first TCP-layer answer ends the address, so a host that answers on SSH costs
/// one connect rather than five. A silent address costs all five, which is what
/// it took before as well: the same socket budget, spent on fewer addresses at a
/// time rather than on more ports of each.
///
/// That shape is also what lets a sweep be continued. An address is the unit a
/// journal counts, so its verdict has to be earned as a whole — answered, or
/// every port asked once and none of them answering. Interleaving the ports of
/// many addresses gave neither, because nothing knew when an address was
/// finished with.
///
/// Addresses are drawn from
/// [`shuffled_addresses`] to
/// spread load across the network instead of hammering one subnet at a time, and
/// each connect waits out the [`CONNECT_PROBE_TIMEOUT`] so that hosts on slow or
/// distant links still register.
pub async fn discover(
    ips: IpSet,
    ctx: ScanContext,
    evasion: &EvasionProfile,
) -> Result<(), StrategyError> {
    let shaping = ConnectShaping::from(evasion);
    // The same list `PortSet::common_discovery` names, taken from there rather
    // than spelled again here. Two copies of five port numbers is two copies to
    // keep in step, and nothing would have reported them drifting apart.
    let ports: Arc<[u16]> = PortSet::common_discovery()
        .iter()
        .map(|(port, _)| port)
        .collect::<Vec<_>>()
        .into();

    let mut rx = shuffled_addresses(ips, 1024, &ctx.handle);
    let folder = ctx.clone();
    let mut pool = ProbePool::new(
        DISCOVERY_CONCURRENCY,
        ctx.clone(),
        ScannerKind::Connect,
        |probed, audit: &mut ProbeAudit| absorb_host(&folder, probed, audit),
    );

    let mut probes = 0u128;
    let mut reason = StopReason::AttemptsSpent;
    while let Some(ip) = rx.recv().await {
        if ctx.handle.should_stop() {
            reason = StopReason::Aborted;
            // Taken off the queue and never asked, so it counts with the rest
            // still waiting behind it.
            ctx.record_outcome(Outcome::Unasked);
            break;
        }
        probes += 1;
        pool.audit().record_send(true);
        pool.admit(prober(ip, Arc::clone(&ports), ctx.handle.clone(), shaping))
            .await;
    }

    // Anything still queued was never asked, and carries no position to settle.
    while rx.try_recv().is_ok() {
        ctx.record_outcome(Outcome::Unasked);
    }

    // Every address dispatched; wait out the probes still in flight.
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

/// What one address's liveness probe came to.
struct ProbedHost {
    /// The address asked about, which is the unit a sweep settles.
    ip: IpAddr,
    /// What became of it.
    fate: Fate,
}

/// The four things a sweep can honestly say about an address, before anything
/// knows where in the plan it sits.
///
/// Only the first two are verdicts the sweep earned. The others say the address
/// was not asked, or not finished with, and a resume must ask again — see
/// [`settle`](crate::journal::settle).
enum Fate {
    /// It answered, and this is what the answer proved.
    ///
    /// Boxed because a [`Host`] is by far the largest thing a fate can carry and
    /// four of the five variants carry nothing: unboxed, every probe that found
    /// silence would still move a host-sized value through the sweep.
    Answered(Box<Host>),
    /// Every port was asked once and not one of them answered. **Settled**: a
    /// connect gets one attempt per port and those were all of them.
    Exhausted,
    /// Nothing this probe sent left the host — no route, no socket left — so
    /// the address proved nothing and the next sitting may get further.
    Unroutable,
    /// The scan stopped while the address's ports were still being tried.
    Interrupted,
    /// The scan stopped before any of them were.
    Unasked,
}

/// Merges one finished discovery probe into the store, and settles the address
/// it asked about.
///
/// A freshly created entry starts from [`Host::new`] and absorbs the probe's
/// findings, so the recorded result is the same whether or not the host was seen
/// before.
///
/// The three cases are the three things a sweep can honestly say about an
/// address: it answered, it was asked as many times as it is going to be and
/// stayed silent, or it could not be asked from here at all. Only the first two
/// are settled — see [`settle`](crate::journal::settle).
fn absorb_host(ctx: &ScanContext, probed: ProbedHost, audit: &mut ProbeAudit) {
    match probed.fate {
        Fate::Answered(host) => {
            let ip = host.primary_ip();
            // See `absorb_probe`: this path has no attempt to attribute the
            // answer to, so every host it finds is counted as unattributed.
            audit.record_host_found(None);
            ctx.settle_address(probed.ip, Settled::Answered);
            ctx.update_host(ip, |existing| existing.merge(*host));
        }
        Fate::Exhausted => ctx.settle_address(probed.ip, Settled::Exhausted),
        Fate::Unroutable => ctx.record_outcome(Outcome::Unroutable),
        Fate::Interrupted => ctx.record_outcome(Outcome::Interrupted),
        Fate::Unasked => ctx.record_outcome(Outcome::Unasked),
    }
}

/// Probes one address for presence, over each of `ports` in turn.
///
/// Returns as soon as one of them answers at the TCP layer: a completed
/// handshake, or a reset the kernel surfaced as a connection error. Any other
/// failure says nothing about the address — only that this connect did not
/// finish — so the next port is tried.
///
/// **The stop signal is checked between ports, not only between addresses.**
/// One task now covers up to five connects, and a sweep that only looked once
/// per address would take five timeouts to wind down rather than one. What has
/// been asked so far decides how the address is filed: cut off part way through
/// is not the same as asked and silent, and only the second is a verdict.
async fn prober(
    ip: IpAddr,
    ports: Arc<[u16]>,
    handle: ScanHandle,
    shaping: ConnectShaping,
) -> ProbedHost {
    let start = Instant::now();
    let mut asked = false;

    for &port in ports.iter() {
        if handle.should_stop() {
            return ProbedHost {
                ip,
                fate: if asked {
                    Fate::Interrupted
                } else {
                    Fate::Unasked
                },
            };
        }

        let attempt = timeout(
            CONNECT_PROBE_TIMEOUT,
            connect_shaped(SocketAddr::new(ip, port), shaping),
        )
        .await;

        match attempt {
            // A completed handshake means the host is alive.
            Ok(Ok(_)) => return answered(ip, start),
            // Only these TCP errors imply the host answered at the IP/TCP layer.
            // Any other is a local failure — no route, permission denied — and
            // the probe never reached the wire.
            Ok(Err(e))
                if matches!(
                    e.kind(),
                    ErrorKind::ConnectionRefused
                        | ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                ) =>
            {
                return answered(ip, start);
            }
            Ok(Err(_)) => {}
            // A timeout is the probe going out and nothing coming back, which is
            // the address being asked and declining to answer.
            Err(_elapsed) => asked = true,
        }
    }

    ProbedHost {
        ip,
        fate: if asked {
            Fate::Exhausted
        } else {
            Fate::Unroutable
        },
    }
}

/// The record an address earns by answering.
fn answered(ip: IpAddr, start: Instant) -> ProbedHost {
    let mut host = Host::new(ip).with_rtt(start.elapsed());
    // Every outcome that reaches here required a segment from the target: a
    // completed handshake, or a reset the kernel surfaced as a connection error.
    // `Host::merge` keeps the stronger status, so this survives being folded
    // into an entry another strategy created first.
    host.record_evidence(
        HostStatus::Up,
        StatusReason::new(StatusProtocol::TcpSyn, "tcp connect answered by the host"),
    );

    ProbedHost {
        ip,
        fate: Fate::Answered(Box::new(host)),
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
    use crate::model::target::Target;
    use tokio::net::UdpSocket;

    fn udp_target(ip: IpAddr, port: u16) -> PlannedTarget {
        PlannedTarget::new(
            u64::from(port),
            Target {
                ip,
                port,
                protocol: Protocol::Udp,
            },
        )
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

        let probed = udp_port_prober(udp_target(ip, port), ConnectShaping::default()).await;

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

        let probed = udp_port_prober(udp_target(ip, port), ConnectShaping::default()).await;

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

            let probed = udp_port_prober(udp_target(ip, port), ConnectShaping::default()).await;

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
        let target = PlannedTarget::new(
            0,
            Target {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 80,
                protocol: Protocol::Tcp,
            },
        );
        assert!(
            udp_port_prober(target, ConnectShaping::default())
                .await
                .is_none()
        );
    }

    /// The two fields a connect can carry cross over from the profile, and a
    /// default profile stays inert so the scanner takes its plain path.
    ///
    /// The guard is the mapping itself: a version that dropped either field, or
    /// reported an inert profile as active, would send the wrong packet while
    /// every higher-level test still passed.
    #[test]
    fn the_profile_maps_onto_what_a_connect_can_carry() {
        let profile = EvasionProfile {
            source_port: Some(53),
            ttl: Some(12),
            ..Default::default()
        };
        let shaping = ConnectShaping::from(&profile);

        assert_eq!(shaping.source_port, Some(53));
        assert_eq!(shaping.hop_limit, Some(12));
        assert!(shaping.is_active());
        assert!(!ConnectShaping::from(&EvasionProfile::default()).is_active());
    }

    /// A shaped connect leaves from the chosen source port and carries the chosen
    /// hop limit — proven where it counts, on the wire, against a peer that reads
    /// both back.
    ///
    /// The peer's view of the source port is the whole chain end to end: profile
    /// to [`ConnectShaping`] to the bind. A version that ignored the source port
    /// would show an ephemeral one here; one that skipped the hop limit would
    /// show the OS default, not `9`.
    #[tokio::test]
    async fn a_shaped_connect_pins_its_source_port_and_hop_limit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback listener");
        let addr = listener.local_addr().expect("its address");

        const PINNED: u16 = 40_517;
        const HOPS: u8 = 9;
        let shaping = ConnectShaping {
            source_port: Some(PINNED),
            hop_limit: Some(HOPS),
        };

        let accept = tokio::spawn(async move { listener.accept().await });
        let stream = connect_shaped(addr, shaping)
            .await
            .expect("the shaped connect completes");
        let (_accepted, peer) = accept
            .await
            .expect("the accept task joins")
            .expect("an accept");

        assert_eq!(
            peer.port(),
            PINNED,
            "the SYN left from the pinned source port"
        );
        assert_eq!(
            stream.ttl().expect("the socket's hop limit"),
            u32::from(HOPS),
            "the SYN carried the chosen hop limit"
        );
    }

    /// A shaped UDP probe leaves from the chosen source port, read back off the
    /// datagram the far side receives.
    ///
    /// The UDP socket is built by its own path, so it earns its own guard: one
    /// that bound an ephemeral port instead of the pinned one would show a
    /// different source port to the receiver.
    #[tokio::test]
    async fn a_shaped_udp_probe_pins_its_source_port() {
        let server = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a loopback server");
        let server_addr = server.local_addr().expect("its address");

        const PINNED: u16 = 40_619;
        let shaping = ConnectShaping {
            source_port: Some(PINNED),
            hop_limit: None,
        };
        let socket = shaped_udp_socket(IpAddr::V4(Ipv4Addr::LOCALHOST), shaping)
            .await
            .expect("a shaped UDP socket");
        socket
            .connect(server_addr)
            .await
            .expect("addressing the peer");
        socket.send(b"probe").await.expect("sending the probe");

        let mut buf = [0u8; 8];
        let (_read, from) = server
            .recv_from(&mut buf)
            .await
            .expect("the datagram arrives");
        assert_eq!(
            from.port(),
            PINNED,
            "the datagram left from the pinned source port"
        );
    }
}
