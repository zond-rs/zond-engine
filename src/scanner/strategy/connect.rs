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
//! a target. Everything here is built on ordinary
//! [`TcpStream`] connects, so it needs no special
//! privileges and works anywhere the async runtime does.
//!
//! It answers both scan phases. [`discover`] establishes host presence by probing
//! a small set of common infrastructure ports and treating any TCP-layer response,
//! an accept or even a refusal, as proof the host is alive. [`scan`] takes known
//! targets and classifies each port from a full connect handshake.
//!
//! Both draw their work in shuffled batches and cap their in-flight connections
//! with a [`ProbePool`], and both record findings through the shared
//! [`ScanContext`] like every other strategy. What they draw differs with the
//! phase: a sweep asks about an address and a port scan about an address paired
//! with a port, which is the unit each of them settles.
//!
//! Every probe takes its socket from the process's descriptor budget first
//! (see `dial`), and a probe the process has no socket for waits for one.
//! A shell's file limit therefore slows a scan and never narrows it: a socket
//! the process could not open is a question nobody asked, not an answer.

use crate::config::ServiceDetection;
use crate::config::limits::{CONNECT_PROBE_TIMEOUT, DESCRIPTOR_PATIENCE, DISCOVERY_CONCURRENCY};
use crate::counted;
use crate::evasion::EvasionProfile;
use crate::journal::settle::{Outcome, Settled};
use crate::logging::error;
use crate::model::host::{Host, HostStatus, NetworkRole, StatusProtocol, StatusReason};
use crate::model::ip::scoped::ZoneMap;
use crate::model::ip::set::IpSet;
use crate::model::port::discovery::{Discovery, ScanResponse};
use crate::model::port::{Port, PortSet, PortState, Protocol};
use crate::model::target::PlannedTarget;
use crate::report::ScannerKind;
use crate::report::StopReason;
use crate::scanner::audit::ProbeAudit;
use crate::scanner::dispatcher::dispatch_addresses;
use crate::scanner::handle::ScanHandle;
use crate::scanner::payload;
use crate::scanner::pool::ProbePool;
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::{HostScanner, PortScanner, StrategyError};
use crate::system::descriptors::{self, Descriptor};
use crate::system::dial::{Egress, Shaping};
use async_trait::async_trait;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// The evasion an unprivileged connect probe can honour: a source port to leave
/// from and a hop limit to carry.
///
/// Both are ordinary socket options that need no privilege, so they belong on
/// this path as much as on the raw one: a hop limit a filter keys on should be
/// the chosen value on *every* probe, the connect fallback included, or the
/// fallback would leak the real one. The framing techniques, a spoofed hardware
/// address, fragmentation, decoys, are absent here because they need a
/// self-built frame this path never touches; a profile that asks for one opens
/// the Ethernet path and never reaches this scanner. The segment shapers,
/// padding, a corrupt checksum, are absent for a different reason: the kernel
/// builds the segment a connect sends, so there is nothing here to shape.
impl From<&EvasionProfile> for Shaping {
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
    /// source port and hop limit reach the wire from here (see `dial::Shaping`).
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
    about_the_host: crate::fingerprint::AboutTheHost,
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
    /// Whether a send was made, as the run's audit counts it.
    attempt: Attempt,
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

/// Whether a port probe put anything on the wire, which is what the run's
/// `sends_attempted` and `sends_failed` count.
///
/// Carried by the probe rather than counted when it is admitted, because only
/// the probe knows: a probe admitted can still find no socket, no route, or a
/// scan that stopped before it asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attempt {
    /// The probe was sent.
    Sent,
    /// This machine refused the send before anything left it: no route, no
    /// source to send from.
    Refused,
    /// The process had no socket to give the probe for as long as it would
    /// wait, which the scan reports once it has drained.
    Starved,
    /// Nothing was attempted: the scan stopped before the probe asked.
    Unmade,
}

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
    /// and hop limit reach the wire from here (see `dial::Shaping`).
    evasion: EvasionProfile,
    /// The interface each link-local target was named on, empty for a scan that
    /// named none. A `SocketAddrV6` with a zero scope id will not connect to a
    /// neighbour however close it is, so the scope id is carried per target and
    /// applied where the endpoint is built.
    zones: ZoneMap,
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
            zones: ZoneMap::new(),
        }
    }

    /// Names the interface each of the scan's link-local targets was given on.
    ///
    /// Without it a link-local endpoint is built with a zero scope id, which the
    /// kernel refuses to connect however reachable the neighbour is.
    pub fn with_zones(mut self, zones: ZoneMap) -> Self {
        self.zones = zones;
        self
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
            &self.zones,
        )
        .await
    }
}

/// Unprivileged UDP port scanner.
pub struct ConnectUdpPortScanner {
    ctx: ScanContext,
    concurrency: usize,
    /// What each probe changes about the packet it sends. Only the source port
    /// and hop limit reach the wire from here (see `dial::Shaping`).
    evasion: EvasionProfile,
    /// How far the second pass may go to name what answered.
    ///
    /// Unlike [`ConnectPortScanner`] beside it, this one cannot identify a
    /// service inline: there is no connection to hold, and the datagram that
    /// establishes the port is open is not the one that identifies what is
    /// behind it. So it runs the second pass, and holds the level to run it at.
    service_detection: ServiceDetection,
    /// The interface each link-local target was named on, empty for a scan that
    /// named none. A `SocketAddrV6` with a zero scope id will not connect to a
    /// neighbour however close it is, so the scope id is carried per target and
    /// applied where the endpoint is built.
    zones: ZoneMap,
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
        Self::with_detection(ctx, concurrency, evasion, ServiceDetection::default())
    }

    /// The same scanner, told how far the second pass may go.
    ///
    /// [`new`](Self::new) is the ordinary way in and takes the default level;
    /// this is for a caller carrying a level of its own, which is every caller
    /// that read one from a configuration.
    pub fn with_detection(
        ctx: ScanContext,
        concurrency: usize,
        evasion: &EvasionProfile,
        service_detection: ServiceDetection,
    ) -> Self {
        Self {
            ctx,
            concurrency,
            evasion: evasion.clone(),
            service_detection,
            zones: ZoneMap::new(),
        }
    }

    /// Names the interface each of the scan's link-local targets was given on,
    /// as on the TCP scanner beside it.
    pub fn with_zones(mut self, zones: ZoneMap) -> Self {
        self.zones = zones;
        self
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

    /// Identifies the UDP services this scanner found open.
    ///
    /// [`ConnectPortScanner`] needs no such pass because it fingerprints over
    /// the stream it already holds. There is no equivalent here: a UDP probe is
    /// one datagram, sent to establish that the port is open, and the question
    /// that identifies what answered is a second one. So the phase runs, scoped
    /// to [`Protocol::Udp`] so a composite's TCP member keeps its own half.
    async fn detect_services(&mut self, ctx: &ScanContext) {
        crate::scanner::service::detect(ctx, self.service_detection, Protocol::Udp).await;
    }

    async fn scan(&mut self, mut rx: mpsc::Receiver<PlannedTarget>) -> Result<(), StrategyError> {
        let ctx = self.ctx.clone();
        let shaping = Shaping::from(&self.evasion);
        let mut starved = 0u128;
        let mut pool = ProbePool::new(
            self.concurrency,
            self.ctx.clone(),
            self.kind(),
            |probed, audit: &mut ProbeAudit| absorb_probe(&ctx, probed, audit, &mut starved),
        );

        let mut probes = 0u128;
        let mut reason = StopReason::AttemptsSpent;
        while let Some(target) = rx.recv().await {
            if let Some(cause) = self.ctx.handle.stopped() {
                reason = cause.into();
                record_unasked(&self.ctx, &target);
                break;
            }
            probes += 1;
            // A host past its own budget is left alone. Counted with the
            // probes, because it was work routed here, and recorded unasked so a
            // resume asks about it rather than trusting a verdict nobody earned.
            if self.ctx.host_expired(target.ip()) {
                record_unasked(&self.ctx, &target);
                continue;
            }
            let endpoint = self.zones.endpoint(target.ip(), target.port());
            let egress = self.ctx.egress_toward(target.ip());
            let handle = self.ctx.handle.clone();
            pool.admit(udp_port_prober(target, shaping, egress, endpoint, handle))
                .await;
        }

        // Anything still queued was never sent, and carries no position to
        // settle. The TCP scan above does the same; leaving it out here would
        // both lose the ports and leave the sitting's settlement counts short
        // of the targets it was handed.
        while let Ok(target) = rx.try_recv() {
            record_unasked(&self.ctx, &target);
        }

        pool.drain().await;
        let audit = pool.into_audit();
        if starved > 0 {
            let unasked = counted(starved, "port", "ports");
            report_starved(&self.ctx, self.kind(), unasked, DESCRIPTOR_PATIENCE);
        }
        finish(&self.ctx, audit, self.kind(), probes, reason);
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
    zones: &ZoneMap,
) -> Result<(), StrategyError> {
    let shaping = Shaping::from(evasion);
    let folder = ctx.clone();
    let mut starved = 0u128;
    let mut pool = ProbePool::new(
        concurrency_limit,
        ctx.clone(),
        ScannerKind::Connect,
        |probed, audit: &mut ProbeAudit| absorb_probe(&folder, probed, audit, &mut starved),
    );

    let mut probes = 0u128;
    let mut reason = StopReason::AttemptsSpent;
    while let Some(target) = rx.recv().await {
        if let Some(cause) = ctx.handle.stopped() {
            reason = cause.into();
            // This one was taken off the queue and never asked, so it is
            // recorded with the rest still waiting behind it.
            record_unasked(&ctx, &target);
            break;
        }
        probes += 1;
        // A host past its own budget is left alone, and its remaining ports are
        // recorded unasked rather than given a verdict nothing earned.
        if ctx.host_expired(target.ip()) {
            record_unasked(&ctx, &target);
            continue;
        }
        let endpoint = zones.endpoint(target.ip(), target.port());
        let egress = ctx.egress_toward(target.ip());
        // Identified over the connection that finds the port open, so the
        // port's own cap applies here rather than in a pass of its own.
        let identify = ctx.service_detection_on(detection, target.port(), target.protocol());
        pool.admit(port_prober(
            target,
            identify,
            shaping,
            egress,
            endpoint,
            ctx.handle.clone(),
        ))
        .await;
    }

    // Anything still queued was never sent, and carries no position to settle.
    while let Ok(target) = rx.try_recv() {
        record_unasked(&ctx, &target);
    }

    // Every target dispatched; wait out the probes still in flight.
    pool.drain().await;
    let audit = pool.into_audit();
    if starved > 0 {
        let unasked = counted(starved, "port", "ports");
        report_starved(&ctx, ScannerKind::Connect, unasked, DESCRIPTOR_PATIENCE);
    }
    finish(&ctx, audit, ScannerKind::Connect, probes, reason);
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
/// [detection phase](crate::scanner::detection) reads them from, which is the same
/// place [`service::detect`](crate::scanner::service::detect) puts the ones a
/// raw scan draws in its second pass.
///
/// The send is counted here, from the probe's own [`Attempt`], and a probe
/// starved of a socket is also counted into `starved`, which the scan reports
/// once it has drained.
fn absorb_probe(ctx: &ScanContext, probed: ProbedPort, audit: &mut ProbeAudit, starved: &mut u128) {
    let Some(probed) = probed else {
        return;
    };
    match probed.attempt {
        Attempt::Sent => audit.record_send(true),
        Attempt::Refused => audit.record_send(false),
        Attempt::Starved => {
            audit.record_send(false);
            *starved += 1;
        }
        Attempt::Unmade => {}
    }
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
            probed.about_the_host.clone().apply(host);
        }
    });
}

/// A port in `state`, carrying the packet that settled it where one did.
///
/// This scanner never sees a segment, the kernel does the handshake and hands
/// back an outcome, but the outcome names the packet exactly: a completed
/// connection is a SYN/ACK, a refusal is the RST the kernel translated into it,
/// and a timeout is silence. Recorded so an unprivileged report can say what its
/// verdicts rest on, which is the one thing separating a port a firewall dropped
/// from a port nothing was listening on.
///
/// `None` where no packet is implied: a local failure, no route, no socket
/// left, is this host giving up, and crediting the target with a silence it was
/// never asked for would be evidence of the wrong thing.
fn settled(number: u16, state: PortState, reason: Option<ScanResponse>) -> Port {
    let port = crate::fingerprint::baseline_port(number, Protocol::Tcp, state);

    match reason {
        Some(reason) => port.with_discovery(Discovery::new(reason)),
        None => port,
    }
}

/// Records a planned target no probe was ever sent to.
///
/// Three ways one arises in this strategy: the scan stopped with targets still
/// queued, the target's host had already spent
/// [`ZondConfig::host_timeout`](crate::config::ZondConfig::host_timeout), and
/// this machine failed the connect locally before anything left it.
///
/// All three leave the port on the host rather than off it, for the reason
/// [`port_prober`]'s refusal branch gives about `Closed`: a port list whose shape
/// depends on how a run ended is a different answer rather than a smaller one,
/// and a comparison of two scans reads the difference as the network moving.
/// What the port says is [`PortState::Unasked`], which is the whole of what this
/// run established about it, and the outcome carries no position, so a resume
/// asks the question this sitting did not.
fn record_unasked(ctx: &ScanContext, target: &PlannedTarget) {
    let port =
        crate::fingerprint::baseline_port(target.port(), target.protocol(), PortState::Unasked);
    ctx.update_host(target.ip(), |host| {
        host.add_port(port);
    });
    ctx.record_outcome(Outcome::Unasked);
}

/// Probes a single [`PlannedTarget`] over a full TCP connect handshake and
/// classifies its port. Returns `None` only for a target this strategy doesn't
/// handle.
///
/// An accepted connection is `Open` and gets fingerprinted over the live stream,
/// a refusal is `Closed`, and a timeout is `Filtered`, the usual signature of a
/// firewall drop. A connect that fails before anything leaves this machine is
/// `Unasked`. Only TCP is supported, so UDP targets are skipped.
///
/// The connection, and every one the fingerprint makes after it, leaves by
/// `egress`. Its socket comes from the process's budget and is held until the
/// fingerprint is done with it; a port the process has no socket for, or that
/// the scan stopped before asking, is `Unasked` too.
async fn port_prober(
    planned: PlannedTarget,
    detection: ServiceDetection,
    shaping: Shaping,
    egress: Egress,
    socket_addr: SocketAddr,
    handle: ScanHandle,
) -> ProbedPort {
    let target = planned.target;
    if target.protocol == Protocol::Udp {
        // UDP can't be probed through a TCP stream; skip rather than misreport.
        // No outcome: unreported is re-probed, which is what a routing mistake
        // deserves.
        return None;
    }

    let position = planned.position;
    let unasked = |outcome, attempt| {
        Some(Probed {
            ip: target.ip,
            port: Some(settled(target.port, PortState::Unasked, None)),
            responses: Vec::new(),
            about_the_host: crate::fingerprint::AboutTheHost::default(),
            answered: false,
            outcome,
            attempt,
            role: None,
        })
    };

    let (result, _descriptor) = match dial(&handle, DESCRIPTOR_PATIENCE, || {
        connect(egress, socket_addr, shaping)
    })
    .await
    {
        Dialled::Ran {
            result, descriptor, ..
        } => (result, descriptor),
        // Not a local failure: the scan ended first, as for a target still
        // queued (see `record_unasked`).
        Dialled::Stopped => return unasked(Outcome::Unasked, Attempt::Unmade),
        Dialled::Starved => return unasked(Outcome::Unroutable, Attempt::Starved),
    };

    match result {
        Ok(stream) => {
            let port = settled(target.port, PortState::Open, Some(ScanResponse::TcpSynAck));
            // The detailed form, for the second and third values. This
            // handshake is the only conversation an unprivileged scan has with
            // the port, so what it draws here is everything any later phase can
            // read without dialling again: the responses a passive detection
            // needs, and what the same bytes said about the machine.
            let (port, about_the_host, responses) =
                crate::fingerprint::fingerprint_tcp_via(stream, port, detection, egress).await;
            Some(Probed {
                ip: target.ip,
                port: Some(port),
                responses,
                about_the_host,
                answered: true,
                outcome: Outcome::Answered { position },
                attempt: Attempt::Sent,
                // A TCP handshake proves a service, and the service is the
                // port's to name. No role is read from one.
                role: None,
            })
        }
        Err(e) => {
            match e.kind() {
                // A refusal is the clearest verdict this scanner ever gets, and
                // it is filed as one. The RST the kernel translated into it
                // proves two things at once: the port has nothing listening, and
                // something is there to say so.
                //
                // Recorded rather than dropped because a port list that changes
                // with the caller's privilege level is not a smaller answer, it
                // is a different one. The raw path files `Closed` here, so
                // omitting it would leave an unprivileged report with no
                // `Closed` entry in its `ports_by_state` however many refusals
                // it collected - a summary structurally wrong rather than merely
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
                    about_the_host: crate::fingerprint::AboutTheHost::default(),
                    answered: true,
                    outcome: Outcome::Answered { position },
                    attempt: Attempt::Sent,
                    role: None,
                }),
                // Silence: the probe was dropped, the classic firewall
                // signature. Settled, because a connect gets one attempt and
                // this was it. The budget running out and the stack giving up
                // first are the same outcome, a SYN out and nothing back, and
                // the second can come first on Windows, where a probe keeps a
                // single retransmission.
                ErrorKind::TimedOut => Some(Probed {
                    ip: target.ip,
                    port: Some(settled(
                        target.port,
                        PortState::Filtered,
                        Some(ScanResponse::NoResponse),
                    )),
                    responses: Vec::new(),
                    about_the_host: crate::fingerprint::AboutTheHost::default(),
                    answered: false,
                    outcome: Outcome::Exhausted { position },
                    attempt: Attempt::Sent,
                    role: None,
                }),
                // Anything else failed without a segment leaving this machine -
                // a local routing failure, a source not held here - so nothing
                // was asked and the host has proved nothing. The next sitting
                // may well get further.
                //
                // No evidence recorded, since there is no packet to name, and
                // no verdict either: filing `Filtered` would credit the target
                // with a silence it was never asked for in the one field a
                // reader takes for a finding.
                _ => unasked(Outcome::Unroutable, Attempt::Refused),
            }
        }
    }
}

/// Probes a single [`PlannedTarget`] for UDP using a standard OS `UdpSocket`,
/// the unprivileged counterpart of
/// [`UdpPortScanner`](super::ports::UdpPortScanner).
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
///
/// The datagram leaves by `egress`, from a socket out of the process's budget,
/// and a port the process has no socket for is recorded unasked.
async fn udp_port_prober(
    planned: PlannedTarget,
    shaping: Shaping,
    egress: Egress,
    socket_addr: SocketAddr,
    handle: ScanHandle,
) -> ProbedPort {
    let target = planned.target;
    if target.protocol != Protocol::Udp {
        return None;
    }

    let position = planned.position;
    // `answered` is set only where the kernel vouches for who sent the packet.
    // A datagram arriving on a connected socket came from the peer, so `Open`
    // proves the host. A refusal does not: it is an ICMP error the kernel
    // matched to this socket by the datagram it quotes, and the error's own
    // source address - a router's, or the target's - is not surfaced through
    // this API at all. The privileged scanner reads that address and can tell
    // the two apart; here the port verdict stands on its own and no claim is
    // made about the host.
    let record = |state, answered, outcome, attempt| {
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
            about_the_host: crate::fingerprint::AboutTheHost::default(),
            answered,
            outcome,
            attempt,
            // Filled in by the one arm that has a reply to read it from.
            role: None,
        })
    };

    // Three ways this machine can fail before a datagram leaves it, below, and
    // each records the port unasked rather than dropping it. The target was
    // named by the plan, and a port that disappears from the host when the
    // scanner runs out of sockets is the shortfall a reader cannot see. The
    // outcome is `Unroutable` rather than `Unasked` for the reason the TCP
    // prober gives: this host gave up, which the next sitting may not.
    let refused = Attempt::Refused;
    let (socket, _descriptor) = match dial(&handle, DESCRIPTOR_PATIENCE, || {
        egress.udp_shaped(target.ip, shaping)
    })
    .await
    {
        Dialled::Ran {
            result: Ok(socket),
            descriptor,
            ..
        } => (socket, descriptor),
        Dialled::Ran { result: Err(e), .. } => {
            error!(
                verbosity = 2,
                "no UDP socket for probing {socket_addr}: {e}"
            );
            return record(PortState::Unasked, false, Outcome::Unroutable, refused);
        }
        Dialled::Stopped => {
            return record(PortState::Unasked, false, Outcome::Unasked, Attempt::Unmade);
        }
        Dialled::Starved => {
            return record(
                PortState::Unasked,
                false,
                Outcome::Unroutable,
                Attempt::Starved,
            );
        }
    };

    if let Err(e) = socket.connect(socket_addr).await {
        error!(
            verbosity = 2,
            "cannot address UDP probe to {socket_addr}: {e}"
        );
        return record(PortState::Unasked, false, Outcome::Unroutable, refused);
    }

    if let Err(e) = socket.send(payload::for_port(target.port)).await {
        // A refusal can surface here rather than on the receive: the kernel
        // reports a queued ICMP error on whichever operation comes next.
        return match e.kind() {
            ErrorKind::ConnectionRefused => record(
                PortState::Closed,
                false,
                Outcome::Answered { position },
                Attempt::Sent,
            ),
            _ => {
                error!(
                    verbosity = 2,
                    "failed to send UDP probe to {socket_addr}: {e}"
                );
                record(PortState::Unasked, false, Outcome::Unroutable, refused)
            }
        };
    }

    let mut buf = [0u8; 1024];
    match timeout(CONNECT_PROBE_TIMEOUT, socket.recv(&mut buf)).await {
        // Something answered, so something is listening, and what it said may
        // prove what the host is, which is a claim no port verdict can make.
        // Read here rather than left to the privileged path, so a scan without
        // root reaches the same conclusions about the network.
        Ok(Ok(read)) => record(
            PortState::Open,
            true,
            Outcome::Answered { position },
            Attempt::Sent,
        )
        .map(|probed| Probed {
            role: payload::declared_role(target.port, &buf[..read]),
            ..probed
        }),
        // An ICMP Port Unreachable, surfaced against the connected peer.
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => record(
            PortState::Closed,
            false,
            Outcome::Answered { position },
            Attempt::Sent,
        ),
        // Any other failure leaves the port as unknown as silence does.
        Ok(Err(e)) => {
            error!(
                verbosity = 2,
                "UDP probe to {socket_addr} failed after sending: {e}"
            );
            // A local read failure, not a fact about the target, and after
            // the datagram left, so the send itself was made.
            record(
                PortState::OpenFiltered,
                false,
                Outcome::Unroutable,
                Attempt::Sent,
            )
        }
        // No error and no reply: open but silent, or filtered. UDP cannot tell.
        // Settled either way: this probe had one attempt and spent it.
        Err(_) => record(
            PortState::OpenFiltered,
            false,
            Outcome::Exhausted { position },
            Attempt::Sent,
        ),
    }
}

/// The first pause before a probe refused a socket asks for one again. Short,
/// because the descriptor it waits for is freed by whichever probe finishes
/// next, which on a busy sweep is a matter of milliseconds.
const FIRST_PAUSE: Duration = Duration::from_millis(10);

/// The longest pause between two asks, so a probe notices a freed descriptor
/// within a fraction of a connect's own budget however long it has waited.
const LONGEST_PAUSE: Duration = Duration::from_millis(250);

/// What asking the process for a socket, and then using it, came to.
enum Dialled<T> {
    /// A socket was had and the attempt ran.
    Ran {
        /// What the attempt came to. Never the process running out of
        /// sockets, which is waited out rather than returned.
        result: io::Result<T>,
        /// When the attempt that ran began, after any wait for a socket, so a
        /// round trip timed from it is the target's and not the queue's.
        began: Instant,
        /// The socket's share of the process's budget, given back when it is
        /// dropped. Kept for as long as what `result` holds is, or the budget
        /// would count a socket as closed while it is still open.
        descriptor: Descriptor,
    },
    /// The scan stopped before a socket could be had.
    Stopped,
    /// The process had no socket to give for as long as the probe would wait.
    Starved,
}

/// Runs `attempt` on a socket from the process's descriptor budget.
///
/// The budget is taken first, so a sweep never asks for more sockets than
/// [`descriptors`] allows it. The attempt can still be refused a socket, when
/// something else in the process has filled the table, and that refusal is
/// never passed on: it is raised before anything is sent, so it says nothing
/// about the target, and read as an answer it becomes an address passed over
/// as silent or a port filed as asked. The attempt is made again once a
/// descriptor may have come free, for as long as `patience` allows from the
/// first refusal, and then given up as [`Dialled::Starved`].
///
/// Each attempt's own time budget starts only once it has its socket, so no
/// part of the wait is ever read as a target's silence.
async fn dial<T, F, Fut>(handle: &ScanHandle, patience: Duration, mut attempt: F) -> Dialled<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut refused_since: Option<Instant> = None;
    let mut pause = FIRST_PAUSE;
    loop {
        let descriptor = descriptors::gate()
            .acquire()
            .await
            .expect("the descriptor gate is never closed");
        if handle.should_stop() {
            return Dialled::Stopped;
        }
        let began = Instant::now();
        match attempt().await {
            Err(e) if descriptors::exhausted(&e) => {
                drop(descriptor);
                if refused_since.get_or_insert(began).elapsed() >= patience {
                    return Dialled::Starved;
                }
                tokio::time::sleep(pause).await;
                pause = (pause * 2).min(LONGEST_PAUSE);
            }
            result => {
                return Dialled::Ran {
                    result,
                    began,
                    descriptor,
                };
            }
        }
    }
}

/// One connect to `addr`, given [`CONNECT_PROBE_TIMEOUT`] to be answered.
///
/// The budget running out and the stack giving up first are the same outcome,
/// a SYN out and nothing back, so both come back as [`ErrorKind::TimedOut`].
async fn connect(egress: Egress, addr: SocketAddr, shaping: Shaping) -> io::Result<TcpStream> {
    timeout(CONNECT_PROBE_TIMEOUT, egress.connect_shaped(addr, shaping))
        .await
        .unwrap_or_else(|_elapsed| Err(ErrorKind::TimedOut.into()))
}

/// Files the targets a run left unasked because the process had no socket to
/// give them, once, as the failure it is. `patience` is how long each waited.
///
/// A failure rather than a log line because it narrows the result: those
/// targets have no verdict, and a report that did not say why would read as
/// a network that did not answer. The remedy is the caller's, not the
/// engine's, which reads the file limit and does not raise it.
/// `unasked` names what was left, counted.
fn report_starved(ctx: &ScanContext, scanner: ScannerKind, unasked: String, patience: Duration) {
    let limit = descriptors::soft_limit()
        .map(|limit| format!(" of {limit}"))
        .unwrap_or_default();
    ctx.record_failure(
        scanner,
        format!(
            "{unasked} left unasked: the process reached its file descriptor \
             limit{limit} and no socket came free within {patience:?}; raise \
             the limit and scan again"
        ),
    );
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
/// One task per address, not per port. Its ports are tried in turn and the
/// first TCP-layer answer ends the address, so a host that answers on SSH costs
/// one connect rather than five. A silent address costs all five, as it would
/// with a task per port: the same socket budget, spent on fewer addresses at a
/// time rather than on more ports of each.
///
/// That shape is also what lets a sweep be continued. An address is the unit a
/// journal counts, so its verdict has to be earned as a whole: answered, or
/// every port asked once and none of them answering. Interleaving the ports of
/// many addresses would give neither, because nothing would know when an
/// address was finished with.
///
/// Addresses are drawn from
/// [`dispatch_addresses`] to
/// spread load across the network instead of hammering one subnet at a time, and
/// each connect waits out the [`CONNECT_PROBE_TIMEOUT`] so that hosts on slow or
/// distant links still register.
pub async fn discover(
    ips: IpSet,
    ctx: ScanContext,
    evasion: &EvasionProfile,
) -> Result<(), StrategyError> {
    sweep(ips, ctx, evasion, DESCRIPTOR_PATIENCE).await
}

/// [`discover`], waiting at most `patience` for a socket the process has none
/// of before leaving an address unasked.
async fn sweep(
    ips: IpSet,
    ctx: ScanContext,
    evasion: &EvasionProfile,
    patience: Duration,
) -> Result<(), StrategyError> {
    let shaping = Shaping::from(evasion);
    // The same list `PortSet::common_discovery` names, taken from there rather
    // than spelled again here. Two copies of five port numbers is two copies to
    // keep in step, and nothing would have reported them drifting apart.
    let ports: Arc<[u16]> = PortSet::common_discovery()
        .iter()
        .map(|(port, _)| port)
        .collect::<Vec<_>>()
        .into();

    let mut rx = dispatch_addresses(ips, 1024, ctx.order_seed, &ctx.handle);
    let folder = ctx.clone();
    let mut starved = 0u128;
    // No more probes than the process has sockets for: past the budget a
    // probe would only queue at the gate, holding a task and nothing else.
    let mut pool = ProbePool::new(
        DISCOVERY_CONCURRENCY.min(descriptors::budget()),
        ctx.clone(),
        ScannerKind::Connect,
        |probed, audit: &mut ProbeAudit| absorb_host(&folder, probed, audit, &mut starved),
    );

    let mut probes = 0u128;
    let mut reason = StopReason::AttemptsSpent;
    while let Some(ip) = rx.recv().await {
        if let Some(cause) = ctx.handle.stopped() {
            reason = cause.into();
            // Taken off the queue and never asked, so it counts with the rest
            // still waiting behind it.
            ctx.record_outcome(Outcome::Unasked);
            break;
        }
        probes += 1;
        let egress = ctx.egress_toward(ip);
        pool.admit(prober(
            ip,
            Arc::clone(&ports),
            ctx.handle.clone(),
            shaping,
            egress,
            patience,
        ))
        .await;
    }

    // Anything still queued was never asked, and carries no position to settle.
    while rx.try_recv().is_ok() {
        ctx.record_outcome(Outcome::Unasked);
    }

    // Every address dispatched; wait out the probes still in flight.
    pool.drain().await;
    let audit = pool.into_audit();
    if starved > 0 {
        let unasked = counted(starved, "address", "addresses");
        report_starved(&ctx, ScannerKind::Connect, unasked, patience);
    }
    finish(&ctx, audit, ScannerKind::Connect, probes, reason);
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
/// was not asked, or not finished with, and a resume must ask again. see
/// [`settle`](crate::journal::settle).
///
/// Each also says whether a send was made, which is what the sweep's
/// `sends_attempted` and `sends_failed` count: an address the process could not
/// open a socket for, or had no route to, was a send that failed, and one the
/// scan stopped before asking was no send at all.
enum Fate {
    /// It answered, and this is what the answer proved.
    ///
    /// Boxed because a [`Host`] is by far the largest thing a fate can carry and
    /// five of the six variants carry nothing: unboxed, every probe that found
    /// silence would still move a host-sized value through the sweep.
    Answered(Box<Host>),
    /// Every port was asked once and not one of them answered. **Settled**: a
    /// connect gets one attempt per port and those were all of them.
    Exhausted,
    /// Nothing this probe sent left the host, no route or no source to send
    /// from, so the address proved nothing and the next sitting may get
    /// further.
    Unroutable,
    /// The process had no socket to give the probe, for longer than it was
    /// willing to wait, so the address was never asked. Unsettled for the same
    /// reason as [`Unroutable`](Self::Unroutable), and told apart from it
    /// because the cause is this process's file limit, which the scan reports.
    Starved,
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
/// are settled. see [`settle`](crate::journal::settle).
///
/// An address starved of a socket is counted into `starved`, which the sweep
/// reports once it has drained.
fn absorb_host(ctx: &ScanContext, probed: ProbedHost, audit: &mut ProbeAudit, starved: &mut u128) {
    match probed.fate {
        Fate::Answered(host) => {
            let ip = host.primary_ip();
            audit.record_send(true);
            // See `absorb_probe`: this path has no attempt to attribute the
            // answer to, so every host it finds is counted as unattributed.
            audit.record_host_found(None);
            ctx.settle_address(probed.ip, Settled::Answered);
            ctx.update_host(ip, |existing| existing.merge(*host));
        }
        Fate::Exhausted => {
            audit.record_send(true);
            ctx.settle_address(probed.ip, Settled::Exhausted);
        }
        Fate::Unroutable => {
            audit.record_send(false);
            ctx.record_outcome(Outcome::Unroutable);
        }
        Fate::Starved => {
            audit.record_send(false);
            *starved += 1;
            ctx.record_outcome(Outcome::Unroutable);
        }
        Fate::Interrupted => {
            audit.record_send(true);
            ctx.record_outcome(Outcome::Interrupted);
        }
        Fate::Unasked => ctx.record_outcome(Outcome::Unasked),
    }
}

/// Probes one address for presence, over each of `ports` in turn.
///
/// Returns as soon as one of them answers at the TCP layer: a completed
/// handshake, or a reset the kernel surfaced as a connection error. Any other
/// failure says nothing about the address, only that this connect did not
/// finish, so the next port is tried.
///
/// The stop signal is checked between ports, not only between addresses.
/// One task covers up to five connects, and a sweep that only looked once
/// per address would take five timeouts to wind down rather than one. What has
/// been asked so far decides how the address is filed: cut off part way through
/// is not the same as asked and silent, and only the second is a verdict.
///
/// Every connect leaves by `egress`, on a socket from the process's budget,
/// and waits at most `patience` for one the process has none of.
async fn prober(
    ip: IpAddr,
    ports: Arc<[u16]>,
    handle: ScanHandle,
    shaping: Shaping,
    egress: Egress,
    patience: Duration,
) -> ProbedHost {
    let mut asked = false;
    let cut_short = |asked| ProbedHost {
        ip,
        fate: if asked {
            Fate::Interrupted
        } else {
            Fate::Unasked
        },
    };

    for &port in ports.iter() {
        if handle.should_stop() {
            return cut_short(asked);
        }

        let addr = SocketAddr::new(ip, port);
        // The descriptor is held until the attempt's socket is dropped, at the
        // end of this pass, so the budget counts every socket still open.
        let (attempt, start, _descriptor) =
            match dial(&handle, patience, || connect(egress, addr, shaping)).await {
                Dialled::Ran {
                    result,
                    began,
                    descriptor,
                } => (result, began, descriptor),
                Dialled::Stopped => return cut_short(asked),
                Dialled::Starved => {
                    return ProbedHost {
                        ip,
                        fate: Fate::Starved,
                    };
                }
            };

        match attempt {
            // A completed handshake means the host is alive.
            Ok(_) => return answered(ip, start),
            Err(e) => match e.kind() {
                // Only these TCP errors imply the host answered at the IP/TCP
                // layer.
                ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted => return answered(ip, start),
                // A timeout, the budget's or the stack's, is the probe going
                // out and nothing coming back, which is the address being
                // asked and declining to answer.
                ErrorKind::TimedOut => asked = true,
                // Any other is a local failure, no route, permission denied,
                // and the probe never reached the wire.
                _ => {}
            },
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

/// The record an address earns by answering, timed from `start`, when the
/// connect that was answered began: after any wait for a socket and any port
/// asked before it, so the round trip is that connect's alone.
fn answered(ip: IpAddr, start: Instant) -> ProbedHost {
    let mut host = Host::new(ip);
    host.add_rtt_from(start.elapsed(), StatusProtocol::TcpSyn);
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
    use std::net::{Ipv4Addr, Ipv6Addr};
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

    /// A socket bound IPv4-only would make a v6 target fail at `connect` and
    /// vanish without a record or a log. Loopback only, and no privileges
    /// required, so this runs everywhere the suite does.
    #[tokio::test]
    async fn closed_ipv6_port_is_classified_not_dropped() {
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let port = closed_loopback_udp_port(ip).await;

        let probed = udp_port_prober(
            udp_target(ip, port),
            Shaping::default(),
            Egress::KERNEL,
            SocketAddr::new(ip, port),
            ScanHandle::new(),
        )
        .await;

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

        let probed = udp_port_prober(
            udp_target(ip, port),
            Shaping::default(),
            Egress::KERNEL,
            SocketAddr::new(ip, port),
            ScanHandle::new(),
        )
        .await;

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

            let probed = udp_port_prober(
                udp_target(ip, port),
                Shaping::default(),
                Egress::KERNEL,
                SocketAddr::new(ip, port),
                ScanHandle::new(),
            )
            .await;

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
            udp_port_prober(
                target,
                Shaping::default(),
                Egress::KERNEL,
                SocketAddr::new(target.ip(), target.port()),
                ScanHandle::new(),
            )
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
        let shaping = Shaping::from(&profile);

        assert_eq!(shaping.source_port, Some(53));
        assert_eq!(shaping.hop_limit, Some(12));
        assert!(shaping.is_active());
        assert!(!Shaping::from(&EvasionProfile::default()).is_active());
    }

    /// The variable a re-run of one of the tests below finds itself under,
    /// naming the test it is.
    #[cfg(unix)]
    const OWN_PROCESS: &str = "ZOND_TEST_IN_OWN_PROCESS";

    /// Whether this is the process `name` should run its body in.
    ///
    /// A test that runs this process out of descriptors would take every test
    /// running beside it down too, so it runs its body in a process of its
    /// own: the first call re-runs this binary on that one test and fails if
    /// the re-run does, and the re-run is the call that answers `true`.
    #[cfg(unix)]
    fn in_a_process_of_its_own(name: &str) -> bool {
        if std::env::var(OWN_PROCESS).is_ok_and(|running| running == name) {
            return true;
        }
        let path = format!(
            "{}::{name}",
            module_path!().split_once("::").expect("a crate path").1
        );
        let run = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args([path.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(OWN_PROCESS, name)
            .output()
            .expect("re-running the test in a process of its own");
        let stdout = String::from_utf8_lossy(&run.stdout);
        assert!(
            run.status.success(),
            "{name} failed in its own process:\n{stdout}{}",
            String::from_utf8_lossy(&run.stderr),
        );
        // A filter that matched nothing exits cleanly too.
        assert!(
            stdout.contains("1 passed"),
            "{name} did not run in its own process:\n{stdout}"
        );
        false
    }

    /// Lowers this process's descriptor limit to `limit` and opens files until
    /// it is reached, so the next socket anything asks for is refused. The
    /// files are handed back, and dropping them is what frees the table.
    #[cfg(unix)]
    fn exhaust_descriptors(limit: libc::rlim_t) -> Vec<std::fs::File> {
        let mut bounds = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `getrlimit` writes one `rlimit` through a pointer to a live
        // local of that type, and `setrlimit` reads one the same way.
        unsafe {
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut bounds), 0);
            bounds.rlim_cur = limit;
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &bounds), 0);
        }
        let mut held = Vec::new();
        loop {
            match std::fs::File::open("/dev/null") {
                Ok(file) => held.push(file),
                Err(e) if e.raw_os_error() == Some(libc::EMFILE) => return held,
                Err(e) => panic!("filling the descriptor table: {e}"),
            }
        }
    }

    /// A sweep that cannot have a socket waits for one, and finds the host
    /// the moment the table has room, rather than passing the address over
    /// as if it had been asked.
    ///
    /// The address is this machine's own, which answers every connect on
    /// every platform, and the only thing standing between the sweep and that
    /// answer is a full descriptor table that empties a moment after the
    /// sweep starts.
    #[cfg(unix)]
    #[test]
    fn a_sweep_short_of_descriptors_waits_for_one_rather_than_passing_the_address_over() {
        if !in_a_process_of_its_own(
            "a_sweep_short_of_descriptors_waits_for_one_rather_than_passing_the_address_over",
        ) {
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime, built while descriptors remain");
        let held = exhaust_descriptors(64);
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);

        runtime.block_on(async {
            let (session, ctx) = crate::scanner::session::ScanSession::new();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                drop(held);
            });
            discover(IpSet::from(local), ctx.clone(), &EvasionProfile::default())
                .await
                .expect("the sweep runs");

            assert!(
                session.hosts().contains(local),
                "this machine answers every connect, so a sweep that missed it \
                 passed the address over for want of a socket"
            );
            let stats = &ctx.probe_stats_snapshot()[0];
            assert_eq!(
                (stats.sends_attempted(), stats.sends_failed()),
                (1, 0),
                "one address, asked once it had a socket"
            );
        });
    }

    /// A sweep that never gets a socket says so: the address is left
    /// unsettled for a resume to ask, the send is counted as failed rather
    /// than made, and the report names the file limit as the reason, so a
    /// sweep that found nothing cannot be read as a network that answered
    /// nothing.
    #[cfg(unix)]
    #[test]
    fn a_sweep_that_never_gets_a_socket_reports_it_rather_than_an_empty_network() {
        if !in_a_process_of_its_own(
            "a_sweep_that_never_gets_a_socket_reports_it_rather_than_an_empty_network",
        ) {
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime, built while descriptors remain");
        let _held = exhaust_descriptors(64);
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);

        runtime.block_on(async {
            let (session, ctx) = crate::scanner::session::ScanSession::new();
            let patience = std::time::Duration::from_millis(200);
            sweep(
                IpSet::from(local),
                ctx.clone(),
                &EvasionProfile::default(),
                patience,
            )
            .await
            .expect("the sweep runs");

            assert!(!session.hosts().contains(local), "no socket, no answer");
            assert_eq!(
                ctx.settlements().settled_count(),
                0,
                "an address never asked is not settled"
            );
            let stats = &ctx.probe_stats_snapshot()[0];
            assert_eq!(
                (stats.sends_attempted(), stats.sends_failed()),
                (1, 1),
                "the send was attempted and the process refused it"
            );
            let failures = ctx.failures_snapshot();
            assert!(
                failures
                    .iter()
                    .any(|failure| failure.reason().contains("file descriptor limit of 64")),
                "the report names the limit the sweep ran into, and has {failures:?}"
            );
        });
    }
}
