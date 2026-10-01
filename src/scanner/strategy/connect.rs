// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Unprivileged TCP Connect Scanning
//!
//! The fallback strategy when raw sockets are unavailable: the process is not root,
//! no usable interface exists, or the OS could not route a target. Everything is
//! built on ordinary [`TcpStream`] connects, so it needs no privileges.
//!
//! [`discover`] finds live hosts by connecting to a few common infrastructure ports
//! and taking any TCP-layer answer, an accept or a refusal, as proof of life.
//! [`scan`] classifies each known target port from a full connect handshake.
//!
//! Both draw work in shuffled batches, cap in-flight connections with a
//! `ProbePool`, and record findings through the shared [`ScanContext`]. A sweep
//! settles an address; a port scan settles an address and port.
//!
//! Every probe takes its socket from the process's descriptor budget first (see
//! `dial`) and waits if none is free, so a low file limit slows a scan without
//! narrowing it.
//!
//! ## What a socket cannot see
//!
//! The kernel returns an outcome, never the packet, so two readings the raw path
//! makes are out of reach. A refused connect is a reset or an ICMP port unreachable,
//! reported alike, and the latter is what a firewall rejecting on a host's behalf
//! sends by default: a filter in front of an empty address reads here as a host up
//! with a closed port. And a UDP port is asked once, so a host rate-limiting its
//! ICMP errors (most closed ports then read `OpenOrNoReply` on either path) is never
//! identified as such; only a late answer to a retry shows it.

use crate::config::ServiceDetection;
use crate::config::limits::{
    CONNECT_PROBE_TIMEOUT, DISCOVERY_CONCURRENCY, HOST_SYN_RETRANSMIT,
    NEIGHBOUR_PATH_FINDING_TIMEOUT, PATH_FINDING_TIMEOUT,
};
use crate::counted;
use crate::evasion::EvasionProfile;
use crate::journal::settle::{Outcome, Settled};
use crate::logging::{error, info};
use crate::model::host::{Host, HostStatus, NetworkRole, StatusProtocol, StatusReason};
use crate::model::ip::scoped::ZoneMap;
use crate::model::ip::set::IpSet;
use crate::model::port::discovery::{Discovery, ScanResponse};
use crate::model::port::{Port, PortState, Protocol};
use crate::model::target::PlannedTarget;
use crate::report::StopReason;
use crate::report::{Pass, ScannerKind};
use crate::scanner::audit::ProbeAudit;
use crate::scanner::dispatcher::dispatch_addresses_of;
use crate::scanner::handle::ScanHandle;
use crate::scanner::payload;
use crate::scanner::pool::ProbePool;
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::routed::SynPorts;
use crate::scanner::strategy::{HostScanner, PortScanner, StrategyError, record_unasked};
use crate::system::descriptors::{self, Descriptor};
use crate::system::interface::{OnLinkTable, refuses_neighbour};
use crate::transport::dial::PathAllowance;
use crate::transport::dial::{Connecting, Egress, Holder, Shaping, Slot, SourcePortHeld};
use async_trait::async_trait;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

mod neighbours;

use neighbours::{Held, HeldConnects, Neighbours};

/// The evasion an unprivileged connect probe can honour: a source port to leave
/// from and a hop limit to carry.
///
/// Both are unprivileged socket options, so the connect fallback applies them too
/// and does not leak the real hop limit. Framing techniques (spoofed hardware
/// address, fragmentation, decoys) need a self-built frame; a profile asking for one
/// opens the Ethernet path and never reaches this scanner. Segment shapers (padding,
/// a corrupt checksum) do not apply because the kernel builds the segment.
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
    /// Shared scan state: host store, event channel, abort signal.
    ctx: ScanContext,
    /// Only the source port and hop limit reach the wire (see `dial::Shaping`).
    evasion: EvasionProfile,
    /// The ports every address is asked about.
    ports: SynPorts,
}

impl ConnectScanner {
    /// Checks each of `ips` for life by connecting to a few common infrastructure
    /// ports; an accept or a refusal both count.
    ///
    /// Hosts are filed through `ctx`. Of `evasion`, only the source port and hop
    /// limit reach the wire.
    pub fn new(ips: IpSet, ctx: ScanContext, evasion: &EvasionProfile) -> Self {
        Self::asking(ips, ctx, evasion, SynPorts::common())
    }

    /// [`new`](Self::new), asking `ports` in place of the common five: the set a
    /// routed sweep of the same addresses would ask. See [`discover_on`].
    pub fn asking(ips: IpSet, ctx: ScanContext, evasion: &EvasionProfile, ports: SynPorts) -> Self {
        Self {
            ips,
            ctx,
            evasion: evasion.clone(),
            ports,
        }
    }
}

#[async_trait]
impl HostScanner for ConnectScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::Connect
    }

    async fn discover_hosts(&mut self) -> Result<(), StrategyError> {
        // Taken, so a second call has nothing left to probe.
        discover_on(
            std::mem::take(&mut self.ips),
            self.ctx.clone(),
            &self.evasion,
            self.ports,
        )
        .await
    }
}

/// What one finished prober task learned. Every network outcome maps to some
/// combination of these fields, so a probe never fails.
struct Probed {
    /// The address probed.
    ip: IpAddr,
    /// The port verdict. `None` only for a target never probed (UDP through a TCP
    /// prober).
    ///
    /// Separate from [`Probed::answered`]: a timeout gives a `NoReply` port and
    /// proves nothing about the host, while a refusal gives a `Closed` port and
    /// proves the host is up.
    port: Option<Port>,
    /// What the port said while being fingerprinted, for the detection phase to
    /// hand a passive detection. This is the only connection an unprivileged scan
    /// makes to the port. Empty when the probe drew nothing.
    responses: Vec<String>,

    /// What those same bytes said about the host's operating system. Empty when
    /// the probe drew nothing or the verdict came from the kernel.
    about_the_host: crate::fingerprint::AboutTheHost,
    /// Whether identifying the port lost a later connection for want of a socket,
    /// so what it names is a floor; see
    /// [`Fingerprinted::starved`](crate::fingerprint::Fingerprinted::starved).
    identified_in_part: bool,
    /// Whether the host answered. A completed handshake or `ConnectionRefused`
    /// means something came back; a refusal is almost always the target's own RST,
    /// and a port unreachable in its place usually comes from a filter on the host
    /// itself. A timeout or any other unreachable never sets this.
    answered: bool,
    /// What became of this target, for a resume. A timeout settles the target
    /// (the connect made its one attempt) without proving the host up.
    outcome: Outcome,
    /// Whether a send was made, as the run's audit counts it.
    attempt: Attempt,
    /// One round trip to the host: to the SYN/ACK or the RST, timed from the
    /// attempt's start, excluding any wait for a socket. `None` for a timeout or a
    /// probe that never left.
    rtt: Option<Duration>,
    /// What the reply proved the host *is*, where its protocol says so. Kept
    /// apart from the verdict: a name server and any socket bound to 53 are both
    /// `Open`. See [`payload::declared_role`].
    role: Option<NetworkRole>,
    /// For a port filed `NoReply` because its connect timed out: the connect and
    /// how long it waited; see [`SlowPaths`].
    silence: Option<Silence>,
    /// Set when the kernel refused the connect for a neighbour hold-down: nothing
    /// is filed and the port is asked again after it. See [`HeldPorts`].
    held_down: Option<HeldPort>,
    /// Whether this outcome settles its target. A second asking's does not; it
    /// only revises what the first filed.
    settles: bool,
}

/// The outcome of one finished [`port_prober`] task; `None` when the target was
/// not probed.
type ProbedPort = Option<Probed>;

/// Whether a port probe put anything on the wire, for the run's `sends_attempted`
/// and `sends_failed`. Only the probe knows: an admitted probe can still find no
/// socket, no route, or a stopped scan.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Attempt {
    /// The probe was sent.
    Sent,
    /// This machine refused the send; reported once the scan has drained.
    Refused(Refusal),
    /// No socket became free in time; reported once the scan has drained.
    Starved,
    /// Nothing was attempted: the scan stopped before the probe asked.
    Unmade,
}

/// Why this machine refused to send a probe, sorted as the raw path sorts them:
/// by whose fact it is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Refusal {
    /// No route leads to the address. Reported against the address.
    NoRoute,
    /// A `prohibit` or `blackhole` route (Linux) refuses the address; see
    /// [`Egress::start_connect`]. Reported against the address like
    /// [`NoRoute`](Self::NoRoute), and named as a route refusal since the fix is
    /// in this machine's routing table.
    Forbidden,
    /// The source port every probe is pinned to was held; see [`SourcePortHeld`].
    /// Kept apart from [`Local`](Self::Local) because the OS error names neither
    /// the port nor the holder.
    PortHeld(u16, Holder),
    /// The next-hop neighbour did not answer address resolution, asked twice, so
    /// the kernel never sent the SYN. Reported against the address like
    /// [`NoRoute`](Self::NoRoute); see [`neighbours`].
    Unresolved,
    /// Anything else (no source address, no local port, a probe that met itself
    /// on every try): this machine's failure, in the OS's words.
    Local(String),
}

impl Refusal {
    /// Classifies `error`, raised before anything left this machine.
    ///
    /// A `prohibit` or `blackhole` route arrives as a host unreachable; see
    /// [`Egress::start_connect`].
    fn of(error: &io::Error) -> Self {
        if let Some(held) = SourcePortHeld::of(error) {
            return Self::PortHeld(held.port, held.holder);
        }
        match error.kind() {
            ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable
                if refused_by_policy(error) =>
            {
                Self::Forbidden
            }
            ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => Self::NoRoute,
            _ => Self::Local(error.to_string()),
        }
    }
}

/// Whether `error`, a host this machine cannot reach, is a route refusing in
/// its policy's words: the permission denied a `prohibit` route answers, or
/// the invalid argument of a `blackhole` one, carried inside it.
fn refused_by_policy(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<io::Error>())
        .is_some_and(|inner| {
            matches!(
                inner.kind(),
                ErrorKind::PermissionDenied | ErrorKind::InvalidInput
            )
        })
}

/// What a scan's probes could not ask, and why, reported once it has drained.
///
/// Each is a port or address left unasked, which a resume asks again. The report
/// names each cause, so a scan that could not send does not read as a silent
/// network.
#[derive(Debug, Default)]
struct Shortfall {
    /// Targets the process had no socket for.
    starved: u128,
    /// Ports identified in part because a later connection got no socket.
    identified_in_part: u128,
    /// Addresses no route led to.
    unroutable: std::collections::BTreeSet<IpAddr>,
    /// The ones among them a route refused.
    forbidden: std::collections::BTreeSet<IpAddr>,
    /// Targets the pinned source port was held for.
    port_held: u128,
    /// The pinned port, and what held it the first time.
    held: Option<(u16, Holder)>,
    /// Targets this machine refused for any other reason.
    refused: u128,
    /// The first of those refusals, in the operating system's words.
    first_refusal: Option<String>,
}

impl Shortfall {
    /// Counts one probe's `attempt` for `ip`, if it fell short.
    fn count(&mut self, ip: IpAddr, attempt: &Attempt) {
        match attempt {
            Attempt::Starved => self.starved += 1,
            Attempt::Refused(Refusal::NoRoute | Refusal::Unresolved) => {
                self.unroutable.insert(ip);
            }
            Attempt::Refused(Refusal::Forbidden) => {
                self.unroutable.insert(ip);
                self.forbidden.insert(ip);
            }
            Attempt::Refused(Refusal::PortHeld(port, holder)) => {
                self.port_held += 1;
                self.held.get_or_insert((*port, *holder));
            }
            Attempt::Refused(Refusal::Local(why)) => {
                self.refused += 1;
                self.first_refusal.get_or_insert_with(|| why.clone());
            }
            Attempt::Sent | Attempt::Unmade => {}
        }
    }

    /// Files what fell short, counting targets as `unit` and `units`.
    ///
    /// An address no route led to is filed against the address, as the raw path
    /// does, unless it answered something else and so was reached.
    ///
    /// An address on one of this host's own segments that the routing table
    /// refuses is named refused by a route, as in the raw path's plan; see
    /// [`refuses_neighbour`]. A connected segment is always routed, so a refusal
    /// there is an override; a `prohibit` route says so in its error, but an
    /// `unreachable` one looks like a missing route, and only the address's
    /// segment tells them apart. The segment's network and broadcast addresses
    /// are excluded, since the kernel refuses those for its own reasons.
    fn report(self, ctx: &ScanContext, scanner: ScannerKind, unit: &str, units: &str) {
        // Rarely needed, so read only when it is.
        let segments = if self.unroutable.is_empty() {
            OnLinkTable::from_links(&[])
        } else {
            OnLinkTable::of_segments()
        };
        self.file(ctx, scanner, unit, units, &segments, refuses_neighbour);
    }

    /// [`report`](Self::report), with this host's `segments` and the routing
    /// table's answer for one of them, `refuses`, handed in.
    fn file(
        self,
        ctx: &ScanContext,
        scanner: ScannerKind,
        unit: &str,
        units: &str,
        segments: &OnLinkTable,
        refuses: fn(IpAddr) -> bool,
    ) {
        if self.starved > 0 {
            let unasked = counted(self.starved, unit, units);
            report_starved(ctx, scanner, unasked, descriptors::PATIENCE);
        }
        if self.identified_in_part > 0 {
            let ports = counted(self.identified_in_part, "port", "ports");
            crate::warn!(
                "{ports} identified in part ({})",
                descriptors::starved_briefly()
            );
            ctx.file_cut_short(
                scanner,
                format!(
                    "{ports} identified in part: {}",
                    descriptors::starved(descriptors::PATIENCE)
                ),
            );
        }
        for address in self.unroutable {
            let reached = ctx
                .read_host(address, |host| host.status() == HostStatus::Up)
                .unwrap_or(false);
            if !reached {
                let overrides_segment = || {
                    segments.source_for(address).is_some()
                        && !segments.is_segment_edge(address)
                        && refuses(address)
                };
                if self.forbidden.contains(&address) || overrides_segment() {
                    ctx.note_refused_by_route(address);
                }
                ctx.record_unroutable(address);
            }
        }
        // Filed, since those targets have no verdict, but only a short warning:
        // nothing broke. The pinned port is still closing or held by another
        // socket; the fix is to wait or pin another.
        if let Some((port, holder)) = self.held {
            let by = match holder {
                Holder::Closing => "still closing",
                Holder::Socket => "held elsewhere",
            };
            let unasked = counted(self.port_held, unit, units);
            crate::warn!("{unasked} unasked (source port {port} {by})");
            ctx.file_cut_short(
                scanner,
                format!("{unasked} left unasked: source port {port} {by}"),
            );
        }
        if self.refused > 0 {
            let cause = self.first_refusal.as_deref().unwrap_or("cause unrecorded");
            ctx.record_failure(
                scanner,
                format!(
                    "{} left unasked: this machine refused to send them: {cause}",
                    counted(self.refused, unit, units)
                ),
            );
        }
    }
}

/// Adapts the unprivileged [`scan`] engine to [`PortScanner`], so
/// [`crate::scanner::scan`] can drive it through the same path as the privileged
/// [`TcpPortScanner`](super::ports::TcpPortScanner).
///
/// Each port is fingerprinted inline over the stream that found it (see the port
/// prober), so the scan itself needs no second identification pass.
pub struct ConnectPortScanner {
    /// Shared scan state: host store, event channel, abort signal.
    ctx: ScanContext,
    /// The ceiling on in-flight connect probes.
    concurrency: usize,
    /// How far each probe may go to name what answered.
    ///
    /// The connection is what establishes the port's state, so
    /// [`ServiceDetection::Off`] skips the conversation but never the connection.
    /// Keeping the target's application logs clean needs raw sockets.
    detection: ServiceDetection,
    /// Only the source port and hop limit reach the wire (see `dial::Shaping`).
    evasion: EvasionProfile,
    /// The interface each link-local target was named on; empty if none. A
    /// `SocketAddrV6` with a zero scope id will not connect to a neighbour, so the
    /// scope id is applied per target where the endpoint is built.
    zones: ZoneMap,
}

impl ConnectPortScanner {
    /// Settles each `(address, port)` it is fed with a full handshake, holding at
    /// most `concurrency` connections open and recording verdicts through `ctx`.
    ///
    /// `detection` decides how far the conversation goes once a port answers; the
    /// connection is always made. `evasion` contributes the source port and hop
    /// limit.
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

    /// Names the interface each link-local target was given on. Without it the
    /// endpoint has a zero scope id, which the kernel refuses to connect.
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

    /// Identifies open ports settled by an earlier sitting of the job, whose
    /// responses were lost with it. Ports found in this sitting were already
    /// identified over the connection that found them.
    async fn detect_services(&mut self, ctx: &ScanContext) {
        crate::scanner::service::detect_inherited(ctx, self.detection, Protocol::Tcp).await;
    }
}

/// Unprivileged UDP port scanner.
pub struct ConnectUdpPortScanner {
    ctx: ScanContext,
    concurrency: usize,
    /// Only the source port and hop limit reach the wire (see `dial::Shaping`).
    evasion: EvasionProfile,
    /// How far the service identification pass may go. UDP has no connection to
    /// identify over, so this scanner runs a separate pass.
    service_detection: ServiceDetection,
    /// The interface each link-local target was named on; empty if none. A
    /// `SocketAddrV6` with a zero scope id will not connect to a neighbour, so the
    /// scope id is applied per target where the endpoint is built.
    zones: ZoneMap,
}

impl ConnectUdpPortScanner {
    /// Sends one datagram per `(address, port)` it is fed, `concurrency` at a
    /// time, and files what came back through `ctx`. `evasion` contributes the
    /// source port and hop limit.
    ///
    /// A closed verdict proves nothing about the host: it comes from an ICMP error
    /// the kernel matched to the socket, whose source (a router as easily as the
    /// target) this API does not expose. Only a datagram back proves both the port
    /// and the host.
    pub fn new(ctx: ScanContext, concurrency: usize, evasion: &EvasionProfile) -> Self {
        Self::with_detection(ctx, concurrency, evasion, ServiceDetection::default())
    }

    /// [`new`](Self::new) with an explicit service detection level.
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

    /// Names the interface each link-local target was given on, as on the TCP
    /// scanner.
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

    /// Identifies the UDP services this scanner found open. Scoped to
    /// [`Protocol::Udp`] so a composite's TCP member keeps its own half.
    async fn detect_services(&mut self, ctx: &ScanContext) {
        crate::scanner::service::detect(ctx, self.service_detection, Protocol::Udp).await;
    }

    async fn scan(&mut self, mut rx: mpsc::Receiver<PlannedTarget>) -> Result<(), StrategyError> {
        crate::fingerprint::load_corpus().await;
        let ctx = self.ctx.clone();
        let shaping = Shaping::from(&self.evasion);
        let mut shortfall = Shortfall::default();
        let mut pool = ProbePool::new(
            self.concurrency,
            self.ctx.clone(),
            self.kind(),
            |probed, audit: &mut ProbeAudit| absorb_probe(&ctx, probed, audit, &mut shortfall),
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
            // A host past its own budget is skipped: counted as work routed here,
            // and recorded unasked so a resume asks it.
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

        // Anything still queued was never sent: record it unasked so the ports
        // and the sitting's settlement counts stay whole. Closed first, as in
        // the TCP scan.
        rx.close();
        while let Ok(target) = rx.try_recv() {
            record_unasked(&self.ctx, &target);
        }

        pool.drain().await;
        let audit = pool.into_audit();
        shortfall.report(&self.ctx, self.kind(), "port", "ports");
        finish(&self.ctx, audit, self.kind(), probes, reason);
        Ok(())
    }
}

/// Performs a high-concurrency, unprivileged port scan.
///
/// The primary strategy for callers without root. Consumes the randomized target
/// stream a [`Dispatcher`](crate::scanner::dispatcher::Dispatcher) produces, keeps
/// at most `concurrency_limit` ports in flight within the process's descriptor
/// budget, and records every probed port (open, closed, blocked and silent) in the
/// shared [`ScanContext`] store.
pub async fn scan(
    rx: mpsc::Receiver<PlannedTarget>,
    concurrency_limit: usize,
    ctx: ScanContext,
    detection: ServiceDetection,
    evasion: &EvasionProfile,
    zones: &ZoneMap,
) -> Result<(), StrategyError> {
    let neighbours = Neighbours::of_system();
    // Boxed: the walk's state is too large for a caller's stack.
    Box::pin(scan_among(
        rx,
        concurrency_limit,
        ctx,
        detection,
        evasion,
        zones,
        neighbours,
    ))
    .await
}

/// [`scan`], reading the neighbours its connects wait on from `neighbours`.
async fn scan_among(
    mut rx: mpsc::Receiver<PlannedTarget>,
    concurrency_limit: usize,
    ctx: ScanContext,
    detection: ServiceDetection,
    evasion: &EvasionProfile,
    zones: &ZoneMap,
    neighbours: Neighbours,
) -> Result<(), StrategyError> {
    crate::fingerprint::load_corpus().await;
    let shaping = Shaping::from(evasion);
    let folder = ctx.clone();
    let mut shortfall = Shortfall::default();
    // Ports are identified over the connection that finds them open, grouped by
    // host so a host answering on every port is noticed; see
    // [`Crowd`](crate::scanner::service::Crowd).
    let crowds = crate::scanner::service::Crowds::default();
    let tarpits = crate::scanner::service::Tarpits::default();
    let slow = SlowPaths::default();
    let held = HeldPorts::default();
    let finding = PathFinding::of(OnLinkTable::of_segments());
    let neighbours = Arc::new(neighbours);
    let mut pool = ProbePool::new(
        concurrency_limit,
        ctx.clone(),
        ScannerKind::Connect,
        |probed: ProbedPort, audit: &mut ProbeAudit| {
            if let Some(port) = probed.as_ref().and_then(|probed| probed.held_down) {
                held.note(port);
                return;
            }
            if let Some(silence) = probed.as_ref().and_then(|probed| probed.silence) {
                slow.note(silence);
            }
            absorb_probe(&folder, probed, audit, &mut shortfall);
        },
    );
    let asking = Asking {
        ctx: &ctx,
        detection,
        shaping,
        zones,
        crowds: &crowds,
        tarpits: &tarpits,
        neighbours: &neighbours,
    };

    let mut probes = 0u128;
    let mut reason = StopReason::AttemptsSpent;
    while let Some(target) = rx.recv().await {
        if let Some(cause) = ctx.handle.stopped() {
            reason = cause.into();
            record_unasked(&ctx, &target);
            break;
        }
        probes += 1;
        // A host past its own budget has its remaining ports recorded unasked.
        if ctx.host_expired(target.ip()) {
            record_unasked(&ctx, &target);
            continue;
        }
        pool.admit(asking.first(target, &finding)).await;
    }

    // Anything still queued was never sent. Closed first: otherwise a router
    // handing over a target while the in-flight probes drain below would put it
    // in a queue nothing reads. Closed, the router records it unasked itself.
    rx.close();
    while let Ok(target) = rx.try_recv() {
        record_unasked(&ctx, &target);
    }

    // Drain the in-flight probes, then the second askings they left owed: ports
    // a hold-down kept back, then slow-path ports, which may leave more held.
    pool.drain().await;
    held.ask_again(&asking, &mut pool).await;
    slow.ask_again(&asking, &mut pool).await;
    held.ask_again(&asking, &mut pool).await;
    let audit = pool.into_audit();
    // Identification runs inside this walk, so a stop also cut it short. Name
    // the services pass as stopped when it was on and something was open.
    if detection.connects()
        && ctx.handle.should_stop()
        && ctx.store.iter().any(|host| {
            host.value()
                .ports()
                .any(|port| port.protocol() == Protocol::Tcp && port.state() == PortState::Open)
        })
    {
        ctx.stopping_before(Pass::Services);
    }
    shortfall.identified_in_part +=
        crowds.ask_again(&ctx, ScannerKind::Connect).await.len() as u128;
    crowds.report_silence();
    // Reported under the identification pass, as on the raw path: every port
    // has its verdict, only some services went unidentified.
    tarpits.report(&ctx, ScannerKind::Service);
    shortfall.report(&ctx, ScannerKind::Connect, "port", "ports");
    finish(&ctx, audit, ScannerKind::Connect, probes, reason);
    Ok(())
}

/// How long a connect across `path` waits for its answer (`path` is
/// [`PathAllowance::NONE`] for an unmeasured host).
///
/// [`CONNECT_PROBE_TIMEOUT`] when that covers the path: any round trip under a
/// sixth of a second measured once, or two fifths measured steadily. Beyond that,
/// the wait is the host stack's SYN retransmission plus the answer across the
/// path, with the headroom the measured round trips earn (see [`PathAllowance`]),
/// so an open port behind a slow path does not read `NoReply`.
fn connect_patience(path: PathAllowance) -> Duration {
    path.over(HOST_SYN_RETRANSMIT).max(CONNECT_PROBE_TIMEOUT)
}

/// What the path to `ip`, as measured so far, adds to every wait on it;
/// [`PathAllowance::NONE`] if unmeasured.
fn measured_path(ctx: &ScanContext, ip: IpAddr) -> PathAllowance {
    ctx.read_host(ip, |host| {
        PathAllowance::of_round_trips(host.telemetry().round_trips())
    })
    .unwrap_or(PathAllowance::NONE)
}

/// What a connect port scan asks each port with, so a second asking matches the
/// first.
struct Asking<'a> {
    ctx: &'a ScanContext,
    detection: ServiceDetection,
    shaping: Shaping,
    zones: &'a ZoneMap,
    crowds: &'a crate::scanner::service::Crowds,
    tarpits: &'a crate::scanner::service::Tarpits,
    neighbours: &'a Arc<Neighbours>,
}

impl Asking<'_> {
    /// The first asking of `target`, its connect's wait decided by `finding` when
    /// the probe starts, so it uses whatever the probes ahead of it measured while
    /// it waited for a pool slot.
    fn first(
        &self,
        target: PlannedTarget,
        finding: &PathFinding,
    ) -> impl Future<Output = ProbedPort> + Send + 'static {
        let (ctx, finding, ip) = (self.ctx.clone(), finding.clone(), target.ip());
        self.port_waiting(target, move || {
            finding.patience(measured_path(&ctx, ip), ip)
        })
    }

    /// The probe of `target`, its connect waiting `patience`.
    fn port(
        &self,
        target: PlannedTarget,
        patience: Duration,
    ) -> impl Future<Output = ProbedPort> + Send + 'static {
        self.port_waiting(target, move || patience)
    }

    /// The probe of `target`, its connect waiting what `patience` returns when the
    /// probe starts.
    fn port_waiting(
        &self,
        target: PlannedTarget,
        patience: impl FnOnce() -> Duration + Send + 'static,
    ) -> impl Future<Output = ProbedPort> + Send + 'static {
        let ctx = self.ctx;
        let endpoint = self.zones.endpoint(target.ip(), target.port());
        let egress = ctx.egress_toward(target.ip());
        // Identification happens on this connection, so the port's cap applies here.
        let identify = ctx.service_detection_on(self.detection, target.port(), target.protocol());
        // A host that answers on every port has only its likeliest identified;
        // see `Tarpits`. It is recognised once enough ports answered, or enough
        // identified ports said nothing.
        let crowd = self.crowds.of(target.ip(), ctx.target_name(target.ip()));
        let identify = match ctx.read_host(target.ip(), |host| {
            self.tarpits
                .identifies(host, Some(&crowd), target.port(), target.protocol())
        }) {
            Some(false) => ServiceDetection::Off,
            _ => identify,
        };
        let (shaping, ctx) = (self.shaping, ctx.clone());
        let neighbours = Arc::clone(self.neighbours);
        async move {
            port_prober(
                target,
                identify,
                shaping,
                egress,
                endpoint,
                patience(),
                ctx,
                crowd,
                neighbours,
            )
            .await
        }
    }

    /// [`port`](Self::port), asked a second time: it revises the port's record
    /// and settles nothing, since the first asking did.
    ///
    /// If it draws no verdict (stopped, or refused by this machine), the first
    /// asking's verdict stands. Its send is still counted.
    fn again(
        &self,
        target: PlannedTarget,
        patience: Duration,
    ) -> impl Future<Output = ProbedPort> + Send + 'static {
        let asked = self.port(target, patience);
        async move {
            asked.await.map(|probed| Probed {
                settles: false,
                port: probed
                    .port
                    .filter(|port| port.state() != PortState::Unasked),
                ..probed
            })
        }
    }
}

/// A port whose connect the kernel refused for a hold-down on its host's
/// neighbour, and when the hold-down is over.
#[derive(Debug, Clone, Copy)]
struct HeldPort {
    target: PlannedTarget,
    until: Instant,
}

/// Ports refused for the kernel's hold-down on their host's neighbour, each asked
/// again once it is over.
///
/// macOS refuses a connect to a neighbour it recently gave up on with
/// `EHOSTDOWN`, for twenty seconds by default, and sends nothing. The first such
/// refusal is no verdict on the host (see
/// [`HoldDowns`](crate::scanner::strategy::raw::neighbors::HoldDowns)). The refused
/// port, and every port of the host that comes up during the hold-down, releases
/// its pool slot at once so other hosts are not blocked for twenty seconds. It is
/// asked again once the first askings are done and the hold-down has passed; that
/// connect makes the kernel resolve the neighbour afresh and waits as a
/// neighbour's first connect does. A host held down a second time is filed
/// unreachable with every port unasked.
#[derive(Debug, Default)]
struct HeldPorts {
    held: std::sync::Mutex<Vec<HeldPort>>,
}

impl HeldPorts {
    /// Notes a port held for a hold-down.
    fn note(&self, port: HeldPort) {
        self.held
            .lock()
            .unwrap_or_else(|held| held.into_inner())
            .push(port);
    }

    /// Asks again, through `pool`, every held port once the latest hold-down among
    /// them has passed, until none is left. If the scan stops while waiting, or a
    /// host is past its budget, the held ports are recorded unasked.
    async fn ask_again<F>(&self, asking: &Asking<'_>, pool: &mut ProbePool<ProbedPort, F>)
    where
        F: FnMut(ProbedPort, &mut ProbeAudit),
    {
        let ctx = asking.ctx;
        loop {
            let held =
                std::mem::take(&mut *self.held.lock().unwrap_or_else(|held| held.into_inner()));
            let Some(until) = held.iter().map(|port| port.until).max() else {
                return;
            };
            let waited = ctx
                .handle
                .or_stopped(tokio::time::sleep_until(until.into()))
                .await;
            for port in held {
                let ip = port.target.ip();
                if waited.is_none() || ctx.handle.should_stop() || ctx.host_expired(ip) {
                    record_unasked(ctx, &port.target);
                    continue;
                }
                let patience =
                    NEIGHBOUR_PATH_FINDING_TIMEOUT.max(connect_patience(measured_path(ctx, ip)));
                pool.admit(asking.port(port.target, patience)).await;
            }
            pool.drain().await;
        }
    }
}

/// A port whose connect heard nothing, and how long it waited.
#[derive(Debug, Clone, Copy)]
struct Silence {
    target: PlannedTarget,
    waited: Duration,
}

/// Ports filed `NoReply` on a wait shorter than their host's path needs, each
/// owed a second asking.
///
/// A connect's wait is sized from the host's path as measured when the port was
/// asked; an unmeasured host gets an ordinary path's wait, which gives up on every
/// answer across a slower one. Two cases reach here once the first askings are
/// done.
///
/// A host measured since (some port answered) has each port that waited less than
/// the measured path needs asked again with that wait; see [`connect_patience`].
/// On an ordinary path that is no port at all.
///
/// A host that answered nothing may be silent or may be far away. So the first
/// port asked of an unmeasured host finds the path: it waits as a liveness
/// sweep's first connect does, [`path_finding_wait`], and its measurement sizes
/// the wait of every later port of the host; see [`PathFinding`]. On a slow path
/// only the ports that started before that answer are owed a second asking.
/// Across a 1.9 s path, a scan of 200 ports at [`CONNECT_CONCURRENCY`] asks 98
/// twice (finding the path afterwards would ask all 200), taking 15.7 to 18.3 s
/// against 17.8 to 22.5 s. On a silent host it costs one connect of that wait,
/// spent at the start.
///
/// [`CONNECT_CONCURRENCY`]: crate::config::limits::CONNECT_CONCURRENCY
///
/// Ports that start while the path is being found wait as on an ordinary path.
/// Holding them would idle their pool slots for the path-finding wait on every
/// host whose first port is silent, which is most hosts in a wide scan.
///
/// If the path-finding connect was cut short (by a stop or by this machine) and
/// the host answered nothing else, its port likeliest to be listening is asked
/// again with that wait once the first askings are done. If it answers, the host
/// is measured and the rest follow as above. Nothing else is asked twice.
#[derive(Debug, Default)]
struct SlowPaths {
    silent: std::sync::Mutex<std::collections::HashMap<IpAddr, Vec<Silence>>>,
}

/// Which hosts have had a path-finding connect, and how long each first asking
/// waits; see [`SlowPaths`].
#[derive(Clone)]
struct PathFinding {
    /// This host's segments, whose addresses are resolved before the first SYN
    /// leaves; see [`path_finding_wait`].
    segments: Arc<OnLinkTable>,
    /// The hosts a path-finding connect has been sent to.
    sent: Arc<std::sync::Mutex<std::collections::HashSet<IpAddr>>>,
}

impl PathFinding {
    /// Nothing sent yet, with `segments` marking which addresses are on-link.
    fn of(segments: OnLinkTable) -> Self {
        Self {
            segments: Arc::new(segments),
            sent: Arc::default(),
        }
    }

    /// How long the first asking of a port on `ip` waits, given `path` as measured
    /// so far: the [path-finding wait](path_finding_wait) for the first port of an
    /// unmeasured host, [`connect_patience`] otherwise.
    fn patience(&self, path: PathAllowance, ip: IpAddr) -> Duration {
        let finds_the_path = path == PathAllowance::NONE
            && self
                .sent
                .lock()
                .unwrap_or_else(|held| held.into_inner())
                .insert(ip);
        if finds_the_path {
            path_finding_wait(is_neighbour(&self.segments, ip))
        } else {
            connect_patience(path)
        }
    }
}

impl SlowPaths {
    /// Notes a port whose connect heard nothing.
    fn note(&self, silence: Silence) {
        self.silent
            .lock()
            .unwrap_or_else(|held| held.into_inner())
            .entry(silence.target.ip())
            .or_default()
            .push(silence);
    }

    /// Takes every silence noted so far.
    fn take(&self) -> std::collections::HashMap<IpAddr, Vec<Silence>> {
        std::mem::take(&mut *self.silent.lock().unwrap_or_else(|held| held.into_inner()))
    }

    /// Asks again, through `pool`, every port owed a second asking, first finding
    /// the path to each host that answered nothing; see [`SlowPaths`]. Asks nothing
    /// once stopped, and skips hosts past their budget.
    async fn ask_again<F>(&self, asking: &Asking<'_>, pool: &mut ProbePool<ProbedPort, F>)
    where
        F: FnMut(ProbedPort, &mut ProbeAudit),
    {
        let ctx = asking.ctx;
        let owed = self.take();
        let open = |ip: &IpAddr| ctx.handle.stopped().is_none() && !ctx.host_expired(*ip);

        let mut finders = std::collections::HashSet::new();
        for (ip, ports) in &owed {
            // A port that already waited the path-finding wait needs no repeat.
            let found = ports
                .iter()
                .any(|silence| silence.waited >= PATH_FINDING_TIMEOUT);
            if found || !open(ip) || measured_path(ctx, *ip) != PathAllowance::NONE {
                continue;
            }
            let Some(likeliest) = ports.iter().min_by_key(|silence| {
                let number = silence.target.port();
                let rank = crate::model::port::TCP_BY_PREVALENCE
                    .iter()
                    .position(|&listed| listed == number);
                (rank.is_none(), rank, number)
            }) else {
                continue;
            };
            finders.insert(likeliest.target);
            pool.admit(asking.again(likeliest.target, PATH_FINDING_TIMEOUT))
                .await;
        }
        pool.drain().await;

        let mut asked = finders.len() as u128;
        for (ip, ports) in &owed {
            let path = measured_path(ctx, *ip);
            if path == PathAllowance::NONE || !open(ip) {
                continue;
            }
            let patience = connect_patience(path);
            for silence in ports {
                if silence.waited < patience && !finders.contains(&silence.target) {
                    asked += 1;
                    pool.admit(asking.again(silence.target, patience)).await;
                }
            }
        }
        pool.drain().await;

        // Silent second askings already waited as long as the path needs.
        self.take();
        if asked > 0 {
            info!(
                verbosity = 1,
                "{} asked again, waiting for a slower path",
                counted(asked, "silent port", "silent ports")
            );
        }
    }
}

/// Folds one finished probe into the store: the port it classified, if any, and
/// what the exchange proved about the host.
///
/// The responses the inline fingerprint drew go to the context the
/// [detection phase](crate::scanner::detection) reads, where
/// [`service::detect`](crate::scanner::service::detect) puts a raw scan's.
///
/// The send is counted from the probe's [`Attempt`], and a probe that could not
/// ask is counted into `shortfall`, reported once the scan has drained.
fn absorb_probe(
    ctx: &ScanContext,
    probed: ProbedPort,
    audit: &mut ProbeAudit,
    shortfall: &mut Shortfall,
) {
    let Some(probed) = probed else {
        return;
    };
    match probed.attempt {
        Attempt::Sent => audit.record_send(true),
        Attempt::Refused(_) | Attempt::Starved => audit.record_send(false),
        Attempt::Unmade => {}
    }
    shortfall.count(probed.ip, &probed.attempt);
    shortfall.identified_in_part += u128::from(probed.identified_in_part);
    if probed.answered {
        // No attempt token: the host stack retransmits on its own schedule (see
        // `CONNECT_PROBE_TIMEOUT`), so which attempt was answered is unknowable.
        audit.record_host_found(None);
    }
    // Settled once what it found is stored; see `ScanContext::record_outcome`.
    let (outcome, settles) = (probed.outcome, probed.settles);
    file_probe(ctx, probed);
    if settles {
        ctx.record_outcome(outcome);
    }
}

/// The store's half of [`absorb_probe`]: the port, the responses and what the
/// exchange proved about the host.
fn file_probe(ctx: &ScanContext, probed: Probed) {
    if probed.port.is_none() && !probed.answered && probed.role.is_none() {
        return;
    }

    // Filed under the port's key, which the detection phase looks up by; the
    // host's zone comes from that key, so the two cannot disagree.
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
                StatusReason::new(
                    StatusProtocol::TcpConnect,
                    "tcp connect answered by the host",
                ),
            );
        }
        // Without a liveness pass, this is the host's only round trip here.
        if let Some(rtt) = probed.rtt {
            host.add_rtt_from(rtt, StatusProtocol::TcpConnect);
        }
        if !probed.about_the_host.is_empty() {
            // The same call the service phase makes on the privileged path.
            probed.about_the_host.clone().apply(host);
        }
    });
}

/// A port in `state`, carrying the packet that settled it where one did.
///
/// The kernel does the handshake, but its outcome implies the packet: a completed
/// connection is a SYN/ACK, a timeout is silence, an unreachable is an ICMP error,
/// and a refusal is a RST or an ICMP port unreachable (reported alike, so named as
/// a refusal). Recorded so an unprivileged report says what each verdict rests on.
///
/// `None` when no packet is implied: a local failure, no route or no socket is
/// this host giving up, not the target's silence.
fn settled(number: u16, state: PortState, reason: Option<ScanResponse>) -> Port {
    settled_over(Protocol::Tcp, number, state, reason)
}

/// [`settled`], for a port of `protocol`.
fn settled_over(
    protocol: Protocol,
    number: u16,
    state: PortState,
    reason: Option<ScanResponse>,
) -> Port {
    let port = crate::fingerprint::baseline_port(number, protocol, state);

    match reason {
        Some(reason) => port.with_discovery(Discovery::new(reason)),
        None => port,
    }
}

/// Which packet settled a UDP port, in the raw scanner's vocabulary.
///
/// A reply read off the socket is the port's own answer. A refusal is an ICMP port
/// unreachable, and any other error the kernel matched to the socket is an ICMP
/// error too. Its sender is not exposed, so a prohibition from the host and one
/// from the path are both named unreachable.
///
/// `None` for `OpenOrNoReply` (silence is UDP's ordinary outcome, as the raw
/// scanner records it) and for a port no datagram was sent to.
fn udp_evidence(state: PortState) -> Option<ScanResponse> {
    match state {
        PortState::Open => Some(ScanResponse::UdpResponse),
        PortState::Closed | PortState::Blocked => Some(ScanResponse::IcmpUnreachable),
        _ => None,
    }
}

/// Files a completed handshake with the host it reached: the host is up, and
/// the handshake's round trip is a sample of its path.
fn note_handshake(ctx: &ScanContext, ip: IpAddr, rtt: Duration) {
    ctx.update_host(ip, |host| {
        host.record_evidence(
            HostStatus::Up,
            StatusReason::new(
                StatusProtocol::TcpConnect,
                "tcp connect answered by the host",
            ),
        );
        host.add_rtt_from(rtt, StatusProtocol::TcpConnect);
    });
}

/// Probes a single [`PlannedTarget`] with a full TCP connect and classifies its
/// port. Returns `None` only for a UDP target, which is skipped.
///
/// Accepted is `Open` and fingerprinted over the live stream, refused is
/// `Closed`, an ICMP error is `Blocked`, a timeout is `NoReply`, and a connect this
/// machine refused before sending is `Unasked`; see [`Handshake`]. A connect that
/// met itself is retried from a fresh socket, up to [`SELF_MEETINGS`] times.
///
/// The connection, and every one the fingerprint makes after it, leaves by
/// `egress` in a slot of the scan's pacing; see [`dial`]. Its socket comes from
/// the process's budget and is held until the fingerprint is done. A port with no
/// socket, stopped before asking, or whose host ran out of budget while waiting
/// for its slot is `Unasked` too.
///
/// The handshake gets `patience`, sized from the path to the host; see
/// [`connect_patience`]. An open port is identified in its host's `crowd`. The
/// handshake is filed with the host first ([`note_handshake`]) so the
/// identification's waits allow for the path including this round trip.
///
/// A connect the kernel held for an unresolved neighbour sent nothing, however
/// it ended, and is retried as `neighbours` says; once the neighbour is given up,
/// the port is unasked. See [`neighbours`].
#[allow(clippy::too_many_arguments)]
async fn port_prober(
    planned: PlannedTarget,
    detection: ServiceDetection,
    shaping: Shaping,
    egress: Egress,
    socket_addr: SocketAddr,
    mut patience: Duration,
    ctx: ScanContext,
    crowd: std::sync::Arc<crate::scanner::service::Crowd>,
    neighbours: Arc<Neighbours>,
) -> ProbedPort {
    let handle = &ctx.handle;
    let target = planned.target;
    if target.protocol == Protocol::Udp {
        // No outcome, so a resume probes it again.
        return None;
    }

    let position = planned.position;
    let verdict = |state, reason, answered, rtt, outcome| {
        Some(Probed {
            ip: target.ip,
            port: Some(settled(target.port, state, reason)),
            responses: Vec::new(),
            about_the_host: crate::fingerprint::AboutTheHost::default(),
            identified_in_part: false,
            answered,
            rtt,
            outcome,
            attempt: Attempt::Sent,
            role: None,
            silence: None,
            held_down: None,
            settles: true,
        })
    };
    let unasked = |outcome, attempt| {
        Some(Probed {
            ip: target.ip,
            port: Some(settled(target.port, PortState::Unasked, None)),
            responses: Vec::new(),
            about_the_host: crate::fingerprint::AboutTheHost::default(),
            identified_in_part: false,
            answered: false,
            rtt: None,
            outcome,
            attempt,
            role: None,
            silence: None,
            held_down: None,
            settles: true,
        })
    };

    // Refused for a hold-down, or reached during one: the pool slot is released
    // and the port asked again after it. See `HeldPorts`.
    let held_down = |until| {
        Some(Probed {
            ip: target.ip,
            port: None,
            responses: Vec::new(),
            about_the_host: crate::fingerprint::AboutTheHost::default(),
            identified_in_part: false,
            answered: false,
            rtt: None,
            outcome: Outcome::Unasked,
            attempt: Attempt::Unmade,
            role: None,
            silence: None,
            held_down: Some(HeldPort {
                target: planned,
                until,
            }),
            settles: false,
        })
    };

    let mut met_itself = None;
    let mut meetings = 0;
    let mut held = HeldConnects::default();
    while meetings < SELF_MEETINGS {
        if neighbours.unreached(target.ip) {
            return unasked(Outcome::Unroutable, Attempt::Refused(Refusal::Unresolved));
        }
        if let Some(until) = neighbours.held_until(target.ip) {
            return held_down(until);
        }
        let (handshake, rtt, descriptor) =
            match dial(handle, &egress, target.ip, descriptors::PATIENCE, |slot| {
                std::future::ready(egress.start_connect(slot, socket_addr, shaping))
            })
            .await
            {
                Dialled::Ran {
                    result: Ok(connecting),
                    began,
                    descriptor,
                    ..
                } => {
                    // The SYN left; a stop cutting the wait leaves the port
                    // unasked for a resume, as on the raw path.
                    let Some(finished) = handshake(connecting, patience, handle).await else {
                        return unasked(Outcome::Interrupted, Attempt::Sent);
                    };
                    // Timed before the fingerprint, whose time is the service's.
                    (Handshake::sent(finished), began.elapsed(), Some(descriptor))
                }
                Dialled::Ran {
                    result: Err(e),
                    began,
                    slot,
                    ..
                } => {
                    slot.refund();
                    (Handshake::unsent(e), began.elapsed(), None)
                }
                // The scan or the host's budget ended first (see `record_unasked`).
                Dialled::Unmade => return unasked(Outcome::Unasked, Attempt::Unmade),
                Dialled::Starved => return unasked(Outcome::Unroutable, Attempt::Starved),
            };

        // If the kernel held the SYN for an unresolved neighbour, an unreachable
        // or a timeout means nothing was sent.
        let concluded = matches!(handshake, Handshake::Unreachable);
        if (concluded || matches!(handshake, Handshake::Silent))
            && let Some(state) = neighbours.holding(target.ip)
        {
            match held.after(state, concluded) {
                Held::Again(wait) => {
                    patience = patience.max(wait);
                    continue;
                }
                Held::Unreached => {
                    neighbours.give_up(target.ip);
                    return unasked(Outcome::Unroutable, Attempt::Refused(Refusal::Unresolved));
                }
            }
        }

        return match handshake {
            Handshake::Accepted(stream) => {
                let port = settled(target.port, PortState::Open, Some(ScanResponse::TcpSynAck));
                // Filed with the host now, not with the verdict (which waits for
                // identification, seconds on a silent port): other ports of the
                // host asked meanwhile size their wait from it, and on a slow
                // path an ordinary wait would read them as no reply.
                note_handshake(&ctx, target.ip, rtt);
                // Read back from the host, so an upper bound it held (a
                // neighbour's first answer) gives way to this handshake.
                let path = measured_path(&ctx, target.ip);
                // Raced against the stop: on a port that accepts and says
                // nothing, identification runs close to half a minute. Cut
                // short, the port keeps its open verdict and registered name.
                let identified = handle
                    .or_stopped(crowd.identify(
                        target.ip.into(),
                        stream,
                        port,
                        detection,
                        &egress,
                        path,
                    ))
                    .await;
                drop(descriptor);
                // The round trip is filed already; `rtt: None` avoids a duplicate.
                let Some(identified) = identified else {
                    return verdict(
                        PortState::Open,
                        Some(ScanResponse::TcpSynAck),
                        true,
                        None,
                        Outcome::Answered { position },
                    );
                };
                Some(Probed {
                    ip: target.ip,
                    port: Some(identified.port),
                    responses: identified.responses,
                    about_the_host: identified.about_the_host,
                    identified_in_part: identified.starved,
                    answered: true,
                    rtt: None,
                    outcome: Outcome::Answered { position },
                    attempt: Attempt::Sent,
                    // A TCP handshake proves a service, which the port names.
                    role: None,
                    silence: None,
                    held_down: None,
                    settles: true,
                })
            }
            // The OS reports a reset and an ICMP port unreachable alike. Most are
            // resets, so the port reads closed; a filter rejecting with a port
            // unreachable reads closed here too, where the raw path reads it
            // blocked. The recorded reason is the refusal, not a reset nobody
            // saw. Filed so an unprivileged report's ports match a privileged
            // one's.
            Handshake::Refused => verdict(
                PortState::Closed,
                Some(ScanResponse::ConnectionRefused),
                true,
                Some(rtt),
                Outcome::Answered { position },
            ),
            // An ICMP error (a firewall's reject, a router with no route): blocked,
            // as on the raw path. The host gets no credit or round trip, since
            // the sender is hidden and is as often a router as the target.
            Handshake::Unreachable => verdict(
                PortState::Blocked,
                Some(ScanResponse::IcmpUnreachable),
                false,
                None,
                Outcome::Answered { position },
            ),
            // Dropped. Settled, since a connect gets one attempt. Noted with its
            // wait, which a slower path measured later may show was too short;
            // see `SlowPaths`.
            Handshake::Silent => verdict(
                PortState::NoReply,
                Some(ScanResponse::NoResponse),
                false,
                None,
                Outcome::Exhausted { position },
            )
            .map(|probed| Probed {
                silence: Some(Silence {
                    target: planned,
                    waited: patience,
                }),
                ..probed
            }),
            Handshake::MetItself(e) => {
                meetings += 1;
                met_itself = Some(e);
                continue;
            }
            // This machine refused the connect before sending: unasked, with no
            // evidence and no verdict, for a later sitting to retry. A refusal for
            // a neighbour hold-down holds the host through it instead, giving up
            // at the second. See `HeldPorts`.
            Handshake::NotSent(e) if crate::transport::probe::host_is_down(&e) => {
                match neighbours.hold_down(target.ip, &e) {
                    Some(until) => held_down(until),
                    None => unasked(Outcome::Unroutable, Attempt::Refused(Refusal::Unresolved)),
                }
            }
            Handshake::NotSent(e) => {
                unasked(Outcome::Unroutable, Attempt::Refused(Refusal::of(&e)))
            }
            // The SYN left but the failure names no packet: the send counts, and
            // with no verdict a resume asks again.
            Handshake::Failed(e) => {
                error!(
                    verbosity = 2,
                    "connect to {socket_addr} failed after sending: {e}"
                );
                unasked(Outcome::Unroutable, Attempt::Sent)
            }
        };
    }

    // Met itself every time: only a pinned source port equal to the target's,
    // on this machine's own address, does that.
    let why = met_itself.map_or_else(String::new, |e| e.to_string());
    unasked(Outcome::Unroutable, Attempt::Refused(Refusal::Local(why)))
}

/// How many times a connect that keeps meeting itself is tried.
///
/// A connect meets itself when the kernel draws the target's own port as its
/// source; a fresh socket repeats that with odds of about one in the ephemeral
/// range's size. Three times means the probe is pinned to the port it asks about,
/// which no retry changes.
const SELF_MEETINGS: usize = 3;

/// What one connect probe's handshake came to.
///
/// The OS returns only an error code, and codes are shared between causes:
/// `EHOSTUNREACH` is a missing local route or a firewall's reject on the far side.
/// Timing separates them, so a connect is made in two halves (see
/// [`Egress::start_connect`](crate::transport::dial::Egress::start_connect)), and a
/// code from the first half is always [`NotSent`](Self::NotSent).
#[derive(Debug)]
enum Handshake {
    /// The handshake completed: a SYN/ACK.
    Accepted(TcpStream),
    /// A reset or an ICMP port unreachable, which every platform reports alike.
    Refused,
    /// Another ICMP error ended the connect after its SYN left: an administrative
    /// prohibition, an unreachable host or network, an unsupported protocol.
    ///
    /// Linux ends a connect at the first such error; macOS and the BSDs treat it
    /// as a soft error and keep retrying, so there it ends in
    /// [`Silent`](Self::Silent).
    Unreachable,
    /// Nothing came back within the connect's budget, or the stack gave up first
    /// (possible on Windows, which retransmits a SYN once).
    Silent,
    /// The connect reached its own socket; see
    /// [`met_itself`](crate::transport::dial::met_itself).
    MetItself(io::Error),
    /// This machine refused the connect before anything left it.
    NotSent(io::Error),
    /// The SYN left and the connect failed in a way that names no packet.
    Failed(io::Error),
}

impl Handshake {
    /// Classifies an error from a connect's first half, before anything left.
    ///
    /// A refusal is still a refusal here: over loopback the answer can arrive
    /// before the connect call returns.
    fn unsent(error: io::Error) -> Self {
        if crate::transport::dial::met_itself(&error) {
            Self::MetItself(error)
        } else if error.kind() == ErrorKind::ConnectionRefused {
            Self::Refused
        } else {
            Self::NotSent(error)
        }
    }

    /// Reads the outcome of a connect's second half, after its SYN left.
    fn sent(result: io::Result<TcpStream>) -> Self {
        let error = match result {
            Ok(stream) => return Self::Accepted(stream),
            Err(error) => error,
        };
        if crate::transport::dial::met_itself(&error) {
            return Self::MetItself(error);
        }
        match error.kind() {
            ErrorKind::ConnectionRefused => Self::Refused,
            ErrorKind::TimedOut => Self::Silent,
            _ if is_unreachable(&error) => Self::Unreachable,
            _ => Self::Failed(error),
        }
    }
}

/// Whether `error`, raised after a probe left, is an ICMP error other than a port
/// unreachable: an unreachable host or network, an administrative prohibition
/// (which Linux reports as host unreachable), and on Linux a protocol unreachable
/// (`ENOPROTOOPT`) or an unknown or isolated host (`EHOSTDOWN`, `ENONET`), which
/// have no standard library kind.
fn is_unreachable(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable
    ) {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        matches!(
            error.raw_os_error(),
            Some(libc::ENOPROTOOPT | libc::EHOSTDOWN | libc::ENONET)
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// The second half of a connect, given `patience` to be answered, or `None` if the
/// scan stopped first.
///
/// The budget running out and the stack giving up both come back as
/// [`ErrorKind::TimedOut`]. Raced against the stop, since a dropped SYN holds the
/// probe for all of `patience`, many seconds across a slow path.
async fn handshake(
    connecting: Connecting,
    patience: Duration,
    handle: &ScanHandle,
) -> Option<io::Result<TcpStream>> {
    handle
        .or_stopped(timeout(patience, connecting.finish()))
        .await
        .map(|finished| finished.unwrap_or_else(|_elapsed| Err(ErrorKind::TimedOut.into())))
}

/// Probes a single [`PlannedTarget`] for UDP using a standard OS `UdpSocket`,
/// the unprivileged counterpart of
/// [`UdpPortScanner`](super::ports::UdpPortScanner).
///
/// The socket is *connected*, so the kernel can attribute an inbound ICMP error to
/// its peer and surface it as `ConnectionRefused` on the next operation; an
/// unconnected socket discards it.
///
/// A reply is `Open`, a refusal `Closed`, any other ICMP error `Blocked`, and
/// silence `OpenOrNoReply`, the same verdicts the raw scanner reaches. Local
/// errors (no socket, no route) are logged and recorded unasked.
///
/// The datagram leaves by `egress` in a slot of the scan's pacing, from a socket
/// out of the process's budget. A port with no socket, or stopped before its
/// turn, is recorded unasked.
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
    // `answered` only when the kernel vouches for the sender: a datagram on a
    // connected socket came from the peer. A refusal's ICMP source (router or
    // target) is not exposed, so it makes no claim about the host.
    let record = |state, answered, outcome, attempt| {
        Some(Probed {
            ip: target.ip,
            port: Some(settled_over(
                Protocol::Udp,
                target.port,
                state,
                udp_evidence(state),
            )),
            // The reply is read only for its declared role and names.
            responses: Vec::new(),
            about_the_host: crate::fingerprint::AboutTheHost::default(),
            identified_in_part: false,
            answered,
            // A datagram's reply time includes the service's, so no round trip.
            rtt: None,
            outcome,
            attempt,
            // Set by the arm that has a reply.
            role: None,
            silence: None,
            held_down: None,
            settles: true,
        })
    };

    // Each local failure below records the port unasked, so it stays on the
    // host. The outcome is `Unroutable`, as in the TCP prober: this host gave up,
    // and the next sitting may not.
    let refused = |e: &io::Error| Attempt::Refused(Refusal::of(e));
    let (socket, _descriptor, slot) =
        match dial(&handle, &egress, target.ip, descriptors::PATIENCE, |slot| {
            std::future::ready(egress.udp_shaped(slot, target.ip, shaping))
        })
        .await
        {
            Dialled::Ran {
                result: Ok(socket),
                descriptor,
                slot,
                ..
            } => (socket, descriptor, slot),
            Dialled::Ran {
                result: Err(e),
                slot,
                ..
            } => {
                slot.refund();
                error!(
                    verbosity = 2,
                    "no UDP socket for probing {socket_addr}: {e}"
                );
                return record(PortState::Unasked, false, Outcome::Unroutable, refused(&e));
            }
            Dialled::Unmade => {
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

    // The slot is spent once the datagram leaves, refunded if this machine
    // refused to address or send it.
    if let Err(e) = socket.connect(socket_addr).await {
        slot.refund();
        error!(
            verbosity = 2,
            "cannot address UDP probe to {socket_addr}: {e}"
        );
        return record(PortState::Unasked, false, Outcome::Unroutable, refused(&e));
    }

    if let Err(e) = socket.send(payload::for_port(target.port)).await {
        // The kernel reports a queued ICMP error on the next operation, which
        // can be this send.
        return match e.kind() {
            ErrorKind::ConnectionRefused => record(
                PortState::Closed,
                false,
                Outcome::Answered { position },
                Attempt::Sent,
            ),
            _ => {
                slot.refund();
                error!(
                    verbosity = 2,
                    "failed to send UDP probe to {socket_addr}: {e}"
                );
                record(PortState::Unasked, false, Outcome::Unroutable, refused(&e))
            }
        };
    }
    drop(slot);

    let mut buf = [0u8; 1024];
    match timeout(CONNECT_PROBE_TIMEOUT, socket.recv(&mut buf)).await {
        // Something is listening, and its reply may declare what the host is.
        Ok(Ok(read)) => record(
            PortState::Open,
            true,
            Outcome::Answered { position },
            Attempt::Sent,
        )
        .map(|probed| Probed {
            role: payload::declared_role(target.port, &buf[..read]),
            about_the_host: crate::fingerprint::AboutTheHost {
                names: payload::declared_names(target.port, &buf[..read]),
                ..Default::default()
            },
            ..probed
        }),
        // An ICMP Port Unreachable, surfaced against the connected peer.
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => record(
            PortState::Closed,
            false,
            Outcome::Answered { position },
            Attempt::Sent,
        ),
        // Another ICMP error: an administrative prohibition (host unreachable on
        // Linux) or a protocol unreachable. Blocked, as on the raw path.
        Ok(Err(e)) if is_unreachable(&e) => record(
            PortState::Blocked,
            false,
            Outcome::Answered { position },
            Attempt::Sent,
        ),
        // A local read failure after the send: as unknown as silence.
        Ok(Err(e)) => {
            error!(
                verbosity = 2,
                "UDP probe to {socket_addr} failed after sending: {e}"
            );
            record(
                PortState::OpenOrNoReply,
                false,
                Outcome::Unroutable,
                Attempt::Sent,
            )
        }
        // Open but silent, or dropped. Settled: the one attempt is spent.
        Err(_) => record(
            PortState::OpenOrNoReply,
            false,
            Outcome::Exhausted { position },
            Attempt::Sent,
        ),
    }
}

/// What asking the process for a socket, and then using it, came to.
enum Dialled<T> {
    /// A slot and a socket were had and the attempt ran.
    Ran {
        /// The attempt's result; never descriptor exhaustion, which is waited
        /// out.
        result: io::Result<T>,
        /// When the attempt began, after any wait for slot or socket, so a round
        /// trip timed from it excludes queueing.
        began: Instant,
        /// The socket's share of the process's budget, returned on drop. Keep it
        /// as long as `result`'s socket lives.
        descriptor: Descriptor,
        /// The probe's slot, spent on drop. On an error in `result` nothing left,
        /// so refund it.
        slot: Slot,
    },
    /// The scan stopped, or the host's budget ran out, before the probe had a slot
    /// and a socket; nothing was sent.
    Unmade,
    /// No socket became free for as long as the probe would wait.
    Starved,
}

/// Runs `attempt`, one probe to `peer`, in the slot `egress` gives it and on a
/// socket from the process's descriptor budget.
///
/// The slot is waited for first, so the pacing gap holds no socket and none of the
/// attempt's time budget; a stop or an expired host budget during that wait gives
/// [`Dialled::Unmade`]. The descriptor budget is taken next, so a sweep never
/// exceeds what [`descriptors`] allows. If the attempt is still refused a socket
/// (something else filled the table), that is never returned as a result, since
/// nothing was sent: the attempt is retried in the same slot with backoff for up
/// to `patience` from the first refusal, then given up as [`Dialled::Starved`]
/// with its slot refunded.
///
/// Each attempt's time budget starts only once it has its slot and socket, so no
/// wait is read as the target's silence.
///
/// The same wait as [`descriptors::patiently`], in its own loop because a sweep
/// keeps thousands in flight: each returns its descriptor while it waits and
/// checks for a stop before retrying.
async fn dial<T, F, Fut>(
    handle: &ScanHandle,
    egress: &Egress,
    peer: IpAddr,
    patience: Duration,
    mut attempt: F,
) -> Dialled<T>
where
    F: FnMut(&Slot) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let Ok(slot) = egress.slot(peer).await else {
        return Dialled::Unmade;
    };
    let mut refused_since: Option<Instant> = None;
    let mut pause = descriptors::FIRST_PAUSE;
    loop {
        let descriptor = descriptors::gate()
            .acquire()
            .await
            .expect("the descriptor gate is never closed");
        if handle.should_stop() {
            slot.refund();
            return Dialled::Unmade;
        }
        let began = Instant::now();
        match attempt(&slot).await {
            Err(e) if descriptors::exhausted(&e) => {
                drop(descriptor);
                if refused_since.get_or_insert(began).elapsed() >= patience {
                    slot.refund();
                    return Dialled::Starved;
                }
                tokio::time::sleep(pause).await;
                pause = (pause * 2).min(descriptors::LONGEST_PAUSE);
            }
            result => {
                return Dialled::Ran {
                    result,
                    began,
                    descriptor,
                    slot,
                };
            }
        }
    }
}

/// Files, once, the targets a run left unasked for want of a socket. `patience` is
/// how long each waited; `unasked` is the counted description.
///
/// Filed [cut short](crate::report::ScannerFailure::is_cut_short), not failed,
/// with a one-line warning naming the limit: nothing broke, the process hit the
/// file limit it was started under, and raising it is the caller's remedy.
fn report_starved(ctx: &ScanContext, scanner: ScannerKind, unasked: String, patience: Duration) {
    crate::warn!("{unasked} unasked ({})", descriptors::starved_briefly());
    ctx.file_cut_short(
        scanner,
        format!("{unasked} left unasked: {}", descriptors::starved(patience)),
    );
}

/// Files what a finished sweep or scan measured, the same way for both.
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

/// Multi-port host discovery for unprivileged environments, asking the common
/// five ports: SSH (22), HTTP (80), HTTPS (443), SMB (445), and RDP (3389).
///
/// [`discover_on`] with [`SynPorts::common`].
pub async fn discover(
    ips: IpSet,
    ctx: ScanContext,
    evasion: &EvasionProfile,
) -> Result<(), StrategyError> {
    discover_on(ips, ctx, evasion, SynPorts::common()).await
}

/// Multi-port host discovery for unprivileged environments, asking each address
/// about every port of `ports` until one of them answers.
///
/// `ports` is the set a routed SYN sweep asks: a host behind a filter that drops
/// connects to anything it does not serve answers only on the ports it serves, so
/// a port scan's liveness pass passes [`SynPorts::for_scan`] and asks about the
/// ports about to be probed. Sharing the type keeps an unprivileged run from
/// finding fewer hosts than a privileged one. See [`SynPorts`].
///
/// One task per address. Its ports are tried in order and the first TCP-layer
/// answer ends the address, so a host answering on SSH costs one connect. A silent
/// address costs a connect per port: the first waits three seconds (six for a
/// neighbour), each later one [`CONNECT_PROBE_TIMEOUT`], so a silent range takes up
/// to nine timeouts per address where the common five take six. The first waits
/// longer because the path is still unmeasured, and a neighbour's first connect
/// also waits on hardware address resolution. Each address in flight holds one
/// descriptor, one connect at a time, so a larger set lengthens a silent sweep
/// without widening it.
///
/// The address is also the unit a journal counts, so its verdict must be earned
/// whole (answered, or every port asked once with no answer) for a sweep to be
/// resumable.
///
/// Addresses come from
/// [`dispatch_addresses`](crate::scanner::dispatcher::dispatch_addresses), which
/// spreads load across the network.
pub async fn discover_on(
    ips: IpSet,
    ctx: ScanContext,
    evasion: &EvasionProfile,
    ports: SynPorts,
) -> Result<(), StrategyError> {
    sweep(ips, ctx, evasion, ports, descriptors::PATIENCE).await
}

/// [`discover_on`], waiting at most `patience` for a free socket before leaving an
/// address unasked.
async fn sweep(
    ips: IpSet,
    ctx: ScanContext,
    evasion: &EvasionProfile,
    ports: SynPorts,
    patience: Duration,
) -> Result<(), StrategyError> {
    let shaping = Shaping::from(evasion);
    let ports: Arc<[u16]> = ports.as_slice().into();

    let mut rx = dispatch_addresses_of(
        ips,
        1024,
        ctx.order_seed,
        Some(Arc::clone(&ctx.positions)),
        &ctx.handle,
    );
    let folder = ctx.clone();
    let mut starved = 0u128;
    let mut shortfall = Shortfall::default();
    let segments = Arc::new(OnLinkTable::of_segments());
    let edges = Arc::clone(&segments);
    // Past the socket budget a probe would only queue at the gate.
    let mut pool = ProbePool::new(
        DISCOVERY_CONCURRENCY.min(descriptors::budget()),
        ctx.clone(),
        ScannerKind::Connect,
        |probed, audit: &mut ProbeAudit| {
            absorb_host(&folder, probed, audit, &mut starved, &mut shortfall, &edges)
        },
    );

    let mut probes = 0u128;
    let mut reason = StopReason::AttemptsSpent;
    while let Some(ip) = rx.recv().await {
        if let Some(cause) = ctx.handle.stopped() {
            reason = cause.into();
            ctx.record_address_outcomes(Outcome::Unasked, 1);
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
            is_neighbour(&segments, ip),
        ))
        .await;
    }

    // Anything still queued was never asked.
    while rx.try_recv().is_ok() {
        ctx.record_address_outcomes(Outcome::Unasked, 1);
    }

    pool.drain().await;
    let audit = pool.into_audit();
    if starved > 0 {
        let unasked = counted(starved, "address", "addresses");
        report_starved(&ctx, ScannerKind::Connect, unasked, patience);
    }
    shortfall.report(&ctx, ScannerKind::Connect, "address", "addresses");
    finish(&ctx, audit, ScannerKind::Connect, probes, reason);
    Ok(())
}

/// What one address's liveness probe came to.
struct ProbedHost {
    /// The address asked about, the unit a sweep settles.
    ip: IpAddr,
    /// What became of it.
    fate: Fate,
}

/// What a sweep can say about an address, before its plan position is known.
///
/// Only the first two are verdicts; the rest mean the address was not asked or not
/// finished, and a resume must ask again. See [`settle`](crate::journal::settle).
///
/// Each also says whether a send was made, for the sweep's `sends_attempted` and
/// `sends_failed`: no socket or no route is a failed send, a stop before asking is
/// no send.
enum Fate {
    /// It answered, and this is what the answer proved.
    ///
    /// Boxed: a [`Host`] is far larger than anything the other variants carry.
    Answered(Box<Host>),
    /// Every port was asked once and none answered. **Settled**: a connect gets one
    /// attempt per port.
    Exhausted,
    /// This machine refused to send a probe, so the next sitting may get further.
    /// No route is filed against the address, as on the raw path; any other
    /// refusal is reported once the sweep has drained.
    Refused(Refusal),
    /// No socket became free in time, so the address was never asked. Unsettled
    /// like [`Refused`](Self::Refused), but the cause is the process's file limit,
    /// which the scan reports.
    Starved,
    /// The scan stopped while the address's ports were still being tried.
    Interrupted,
    /// The scan stopped before any of them were.
    Unasked,
}

/// Merges one finished discovery probe into the store, and settles the address
/// it asked about.
///
/// A new entry starts from [`Host::new`] and absorbs the probe's findings, so the
/// result is the same whether or not the host was seen before. Only answered and
/// exhausted addresses are settled; see [`settle`](crate::journal::settle).
///
/// An address starved of a socket is counted into `starved`, and one this machine
/// refused to send to into `shortfall`, both reported once the sweep has drained.
///
/// The network or broadcast address of one of this host's `segments` is refused by
/// the kernel like an unrouted one. It is settled as exhausted, as the frame
/// sweep's unanswered request to it is; filed unreachable, every `/24` sweep would
/// list its broadcast address as unreachable.
fn absorb_host(
    ctx: &ScanContext,
    probed: ProbedHost,
    audit: &mut ProbeAudit,
    starved: &mut u128,
    shortfall: &mut Shortfall,
    segments: &OnLinkTable,
) {
    match probed.fate {
        Fate::Refused(Refusal::NoRoute | Refusal::Forbidden)
            if segments.is_segment_edge(probed.ip) =>
        {
            // Nothing left this machine, so no send is counted.
            ctx.settle_address(probed.ip, Settled::Exhausted);
        }
        Fate::Answered(host) => {
            let ip = host.primary_ip();
            audit.record_send(true);
            // Unattributed, as in `absorb_probe`.
            audit.record_host_found(None);
            ctx.update_host(ip, |existing| existing.merge(*host));
            ctx.settle_address(probed.ip, Settled::Answered);
        }
        Fate::Exhausted => {
            audit.record_send(true);
            ctx.settle_address(probed.ip, Settled::Exhausted);
        }
        Fate::Refused(refusal) => {
            audit.record_send(false);
            shortfall.count(probed.ip, &Attempt::Refused(refusal));
            ctx.record_address_outcomes(Outcome::Unroutable, 1);
        }
        Fate::Starved => {
            audit.record_send(false);
            *starved += 1;
            ctx.record_address_outcomes(Outcome::Unroutable, 1);
        }
        Fate::Interrupted => {
            audit.record_send(true);
            ctx.record_address_outcomes(Outcome::Interrupted, 1);
        }
        Fate::Unasked => ctx.record_address_outcomes(Outcome::Unasked, 1),
    }
}

/// Whether `ip` is a neighbour: on one of this host's `segments`, or link-local.
fn is_neighbour(segments: &OnLinkTable, ip: IpAddr) -> bool {
    let link_local = matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local());
    link_local || segments.source_for(ip).is_some()
}

/// How long the first, path-finding connect to an address waits:
/// [`NEIGHBOUR_PATH_FINDING_TIMEOUT`] for a `neighbour`, [`PATH_FINDING_TIMEOUT`]
/// otherwise.
///
/// A neighbour is resolved before the first SYN leaves, so its wait covers the
/// resolution too. Any other address's next hop is usually resolved already, and
/// once for every address behind it.
fn path_finding_wait(neighbour: bool) -> Duration {
    if neighbour {
        NEIGHBOUR_PATH_FINDING_TIMEOUT
    } else {
        PATH_FINDING_TIMEOUT
    }
}

/// Probes one address for presence, over each of `ports` in turn.
///
/// Returns as soon as one answers at the TCP layer (a completed handshake, or a
/// reset surfaced as a connection error). Anything else is read by [`Knock::of`]
/// and the next port is tried.
///
/// Each connect is made in two halves, as in the port scan (see [`Handshake`]),
/// since only the half that raised a code tells a missing local route from a
/// filter's rejection. No route reaches any port of the address, so the first
/// such refusal ends the probe and files the address unreachable.
///
/// The stop is checked between ports, so a sweep winds down within one timeout
/// even with up to eight connects per task. Cut off part way is not a verdict;
/// asked and silent is. An address with a port this machine refused to send to
/// was not fully asked and is left for the next sitting, with the reason
/// reported.
///
/// Every connect leaves by `egress` in a slot of the scan's pacing, on a socket
/// from the process's budget, waiting at most `patience` for a free one.
///
/// The first connect finds the path: it waits for the longest path a connect looks
/// for, plus resolution for a `neighbour` (see [`path_finding_wait`]); later ones
/// wait as on an ordinary path. An answer to the first connect to a neighbour
/// times path and resolution together and is kept as an upper bound; see
/// [`RttSource::FirstToNeighbour`](crate::model::host::telemetry::RttSource::FirstToNeighbour).
async fn prober(
    ip: IpAddr,
    ports: Arc<[u16]>,
    handle: ScanHandle,
    shaping: Shaping,
    egress: Egress,
    patience: Duration,
    neighbour: bool,
) -> ProbedHost {
    let mut asked = false;
    let mut refused = None;
    let mut waiting = path_finding_wait(neighbour);
    // Only the first connect to a neighbour may have waited on its resolution.
    let mut left = false;
    let cut_short = |asked| ProbedHost {
        ip,
        fate: if asked {
            Fate::Interrupted
        } else {
            Fate::Unasked
        },
    };

    for &port in ports.iter() {
        let addr = SocketAddr::new(ip, port);
        let mut met_itself = None;
        let mut knock = None;
        for _ in 0..SELF_MEETINGS {
            if handle.should_stop() {
                return cut_short(asked);
            }
            // Held until the socket drops at the end of this pass.
            let (handshake, start, _descriptor) =
                match dial(&handle, &egress, ip, patience, |slot| {
                    std::future::ready(egress.start_connect(slot, addr, shaping))
                })
                .await
                {
                    Dialled::Ran {
                        result: Ok(connecting),
                        began,
                        descriptor,
                        ..
                    } => {
                        // Asked, but the stop cut the wait.
                        let Some(finished) = handshake(connecting, waiting, &handle).await else {
                            return cut_short(true);
                        };
                        let sent = Handshake::sent(finished);
                        waiting = CONNECT_PROBE_TIMEOUT;
                        let resolving = neighbour && !std::mem::replace(&mut left, true);
                        (sent, (began, resolving), Some(descriptor))
                    }
                    Dialled::Ran {
                        result: Err(e),
                        began,
                        slot,
                        ..
                    } => {
                        slot.refund();
                        (Handshake::unsent(e), (began, false), None)
                    }
                    Dialled::Unmade => return cut_short(asked),
                    Dialled::Starved => {
                        return ProbedHost {
                            ip,
                            fate: Fate::Starved,
                        };
                    }
                };
            match Knock::of(handshake) {
                Knock::MetItself(e) => met_itself = Some(e),
                other => {
                    knock = Some((other, start));
                    break;
                }
            }
        }

        match knock {
            Some((Knock::Answered, (start, resolving))) => return answered(ip, start, resolving),
            Some((Knock::Asked, _)) => asked = true,
            Some((Knock::Refused(refusal @ (Refusal::NoRoute | Refusal::Forbidden)), _)) => {
                return ProbedHost {
                    ip,
                    fate: Fate::Refused(refusal),
                };
            }
            Some((Knock::Refused(refusal), _)) => {
                refused.get_or_insert(refusal);
            }
            // Met itself every time: a pinned source port equal to the one
            // asked, on this machine's own address.
            Some((Knock::MetItself(_), _)) | None => {
                let why = met_itself.map_or_else(String::new, |e| e.to_string());
                refused.get_or_insert(Refusal::Local(why));
            }
        }
    }

    ProbedHost {
        ip,
        fate: match refused {
            Some(refusal) => Fate::Refused(refusal),
            None if asked => Fate::Exhausted,
            None => Fate::Unasked,
        },
    }
}

/// What one connect of a liveness probe says about the address it knocked on.
#[derive(Debug)]
enum Knock {
    /// Something answered at the TCP layer: a completed handshake, a refusal
    /// (almost always the target's own reset), or a reset.
    Answered,
    /// The SYN left but nothing proving a host came back: silence, an ICMP error
    /// whose sender this path cannot see, or a failure naming no packet.
    Asked,
    /// This machine refused the connect before anything left it.
    Refused(Refusal),
    /// The connect reached its own socket; a fresh socket gets another source.
    MetItself(io::Error),
}

impl Knock {
    /// Reads `handshake` for what it says about the address.
    fn of(handshake: Handshake) -> Self {
        match handshake {
            Handshake::Accepted(_) | Handshake::Refused => Self::Answered,
            Handshake::Failed(e)
                if matches!(
                    e.kind(),
                    ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
                ) =>
            {
                Self::Answered
            }
            Handshake::Unreachable | Handshake::Silent | Handshake::Failed(_) => Self::Asked,
            Handshake::MetItself(e) => Self::MetItself(e),
            Handshake::NotSent(e) => Self::Refused(Refusal::of(&e)),
        }
    }
}

/// The record an address earns by answering. `start` is when the answered connect
/// began, after any socket wait and earlier ports, so the round trip is that
/// connect's alone; it is an upper bound when the connect was `resolving` its
/// neighbour first.
fn answered(ip: IpAddr, start: Instant, resolving: bool) -> ProbedHost {
    let mut host = Host::new(ip);
    let rtt = start.elapsed();
    if resolving {
        host.add_first_to_neighbour_rtt_from(rtt, StatusProtocol::TcpConnect);
    } else {
        host.add_rtt_from(rtt, StatusProtocol::TcpConnect);
    }
    // Every outcome here required a segment from the target. `Host::merge`
    // keeps the stronger status, so this survives merging into another
    // strategy's entry.
    host.record_evidence(
        HostStatus::Up,
        StatusReason::new(
            StatusProtocol::TcpConnect,
            "tcp connect answered by the host",
        ),
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
    use crate::testing::loopback::accept_from_this_process;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::net::UdpSocket;

    /// A connect waits [`CONNECT_PROBE_TIMEOUT`] on an ordinary or unmeasured path,
    /// and across a slow one long enough for the host stack's retransmitted SYN to
    /// be answered.
    #[test]
    fn a_connect_waits_as_ever_on_an_ordinary_path_and_longer_on_a_slow_one() {
        assert_eq!(connect_patience(PathAllowance::NONE), CONNECT_PROBE_TIMEOUT);
        assert_eq!(
            connect_patience(PathAllowance::of_round_trip(Duration::from_millis(40))),
            CONNECT_PROBE_TIMEOUT
        );
        let slow = Duration::from_millis(1_900);
        for path in [
            PathAllowance::of_round_trip(slow),
            PathAllowance::of_round_trips([slow; 10]),
        ] {
            assert!(
                connect_patience(path) > HOST_SYN_RETRANSMIT + slow,
                "a connect across {path:?} waits {:?}",
                connect_patience(path)
            );
        }
    }

    /// The first port of an unmeasured host waits long enough to find the path;
    /// every other port waits as the measurement so far allows.
    #[test]
    fn the_first_port_asked_of_an_unmeasured_host_finds_the_path() {
        use crate::system::interface::{Link, LinkAddress};

        let finding = PathFinding::of(OnLinkTable::from_links(&[Link::new("test0", 1)
            .with_addresses(vec![LinkAddress::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                24,
            )])]));
        let host = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let other = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
        let neighbour = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));

        assert_eq!(
            finding.patience(PathAllowance::NONE, host),
            PATH_FINDING_TIMEOUT
        );
        assert_eq!(
            finding.patience(PathAllowance::NONE, host),
            CONNECT_PROBE_TIMEOUT
        );
        assert_eq!(
            finding.patience(PathAllowance::NONE, other),
            PATH_FINDING_TIMEOUT
        );
        // A neighbour's first connect waits for its resolution too.
        assert_eq!(
            finding.patience(PathAllowance::NONE, neighbour),
            NEIGHBOUR_PATH_FINDING_TIMEOUT
        );

        // A measured host's first port waits as the measurement says.
        let measured = PathAllowance::of_round_trip(Duration::from_millis(1_900));
        let third = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
        assert_eq!(
            finding.patience(measured, third),
            connect_patience(measured)
        );
    }

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

    /// An IPv6 target gets a verdict. A socket bound IPv4-only would fail at
    /// `connect` and drop the target unrecorded. Loopback only, no privileges.
    #[tokio::test]
    async fn closed_ipv6_port_is_classified_not_dropped() {
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let closed = crate::testing::loopback::ClosedUdpPort::open(ip);
        let port = closed.port();

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
        let closed = crate::testing::loopback::ClosedUdpPort::open(ip);
        let port = closed.port();

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

    /// A UDP port the connect path settles records what settled it, as on the raw
    /// path: a reply is the port's answer, a refusal an ICMP port unreachable.
    #[tokio::test]
    async fn a_udp_port_the_connect_path_settles_records_what_settled_it() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let service = UdpSocket::bind((ip, 0)).await.expect("bind service");
        let open = service.local_addr().expect("bound").port();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            if let Ok((_, from)) =
                crate::testing::loopback::recv_from_this_process(&service, &mut buf).await
            {
                let _ = service.send_to(b"pong", from).await;
            }
        });
        let held = crate::testing::loopback::ClosedUdpPort::open(ip);
        let closed = held.port();

        for (port, reason) in [
            (open, ScanResponse::UdpResponse),
            (closed, ScanResponse::IcmpUnreachable),
        ] {
            let probed = udp_port_prober(
                udp_target(ip, port),
                Shaping::default(),
                Egress::KERNEL,
                SocketAddr::new(ip, port),
                ScanHandle::new(),
            )
            .await
            .and_then(|probed| probed.port)
            .expect("a verdict");
            assert_eq!(
                probed.discovery().map(|found| found.reason().clone()),
                Some(reason),
                "{port}: {probed:?}"
            );
        }
    }

    /// The names in a NetBIOS name table reach the host on the connect path, as on
    /// the raw path, and are masked where a report masks.
    ///
    /// The responder listens on its own loopback port; the target names 137, which
    /// decides how the reply is read.
    #[tokio::test]
    async fn a_name_table_names_the_machine_on_the_connect_path() {
        use crate::export::schema::HostDto;
        use crate::export::{ExportOptions, Redaction};
        use crate::model::host::Host;
        use crate::protocols::netbios::tests::response;

        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let service = UdpSocket::bind((ip, 0)).await.expect("bind service");
        let at = service.local_addr().expect("bound");
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            if let Ok((_, from)) = service.recv_from(&mut buf).await {
                let table = response(&[
                    ("FILESERVER", 0x00, false),
                    ("FILESERVER", 0x20, false),
                    ("EXAMPLEGRP", 0x00, true),
                ]);
                let _ = service.send_to(&table, from).await;
            }
        });

        let probed = udp_port_prober(
            udp_target(ip, 137),
            Shaping::default(),
            Egress::KERNEL,
            at,
            ScanHandle::new(),
        )
        .await
        .expect("a verdict");

        let mut host = Host::new(ip);
        probed.about_the_host.apply(&mut host);
        let render = |options: ExportOptions| {
            serde_json::to_value(HostDto::new(&host, &options)).expect("a host renders")
        };
        assert_eq!(
            render(ExportOptions::new())["names"],
            serde_json::json!([
                {"source": "netbios", "kind": "netbios_host", "name": "FILESERVER"},
                {"source": "netbios", "kind": "netbios_domain", "name": "EXAMPLEGRP"},
            ])
        );
        let masked = render(ExportOptions::new().with_redaction(Redaction::Standard)).to_string();
        assert!(
            !masked.contains("FILESERVER") && !masked.contains("EXAMPLEGRP"),
            "a name survived redaction: {masked}"
        );
    }

    /// A refused connect is one round trip (SYN out, RST back), credited to the
    /// host.
    #[tokio::test]
    async fn a_refused_connect_times_the_host() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let port = crate::testing::loopback::refused_port(ip).port();
        let planned = PlannedTarget::new(
            0,
            Target {
                ip,
                port,
                protocol: Protocol::Tcp,
            },
        );

        let (session, ctx) = crate::scanner::session::ScanSession::new();
        let probed = port_prober(
            planned,
            ServiceDetection::Off,
            Shaping::default(),
            Egress::KERNEL,
            SocketAddr::new(ip, port),
            CONNECT_PROBE_TIMEOUT,
            ctx.clone(),
            Default::default(),
            Default::default(),
        )
        .await;
        absorb_probe(
            &ctx,
            probed,
            &mut ProbeAudit::new(),
            &mut Shortfall::default(),
        );

        let host = session
            .hosts()
            .get(ip)
            .expect("the refusal proves the host");
        assert!(
            host.average_rtt().is_some(),
            "the connect's round trip was not recorded against the host"
        );
    }

    /// A host the connect path reaches, by port scan or sweep, is credited to
    /// `TcpConnect`, not a SYN probe: a completed connection reaches the service
    /// and its logs, which a half-open probe does not.
    #[tokio::test]
    async fn a_host_the_connect_path_reached_is_credited_to_a_handshake() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let port = crate::testing::loopback::refused_port(ip).port();
        let (session, ctx) = crate::scanner::session::ScanSession::new();
        let probed = port_prober(
            tcp_target(ip, port),
            ServiceDetection::Off,
            Shaping::default(),
            Egress::KERNEL,
            SocketAddr::new(ip, port),
            CONNECT_PROBE_TIMEOUT,
            ctx.clone(),
            Default::default(),
            Default::default(),
        )
        .await;
        absorb_probe(
            &ctx,
            probed,
            &mut ProbeAudit::new(),
            &mut Shortfall::default(),
        );
        let scanned = session
            .hosts()
            .get(ip)
            .expect("the refusal proves the host");

        let Fate::Answered(swept) = answered(ip, Instant::now(), false).fate else {
            panic!("an answered address is answered");
        };

        for (found, host) in [("a port scan", &scanned), ("a sweep", &*swept)] {
            let protocols: Vec<&StatusProtocol> = host
                .reasons()
                .iter()
                .map(|reason| &reason.protocol)
                .collect();
            assert_eq!(protocols, [&StatusProtocol::TcpConnect], "{found}");
            assert_eq!(
                host.rtt_protocol(),
                Some(StatusProtocol::TcpConnect),
                "{found}"
            );
        }
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
                if let Ok((_, from)) =
                    crate::testing::loopback::recv_from_this_process(&service, &mut buf).await
                {
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

    /// A port of a host whose neighbour was given up is not connected; it is
    /// unasked and filed against the address. On Linux each such connect would
    /// otherwise wait out its own three-second resolution and read blocked.
    #[tokio::test]
    async fn a_host_whose_neighbour_was_given_up_is_sent_nothing_more() {
        use crate::transport::kernel_neighbors::{KernelNeighbors, NeighborTable};

        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let listener = std::net::TcpListener::bind((ip, 0)).expect("bind a listener");
        listener
            .set_nonblocking(true)
            .expect("a listener that does not block");
        let port = listener.local_addr().expect("an inet address").port();
        let table = KernelNeighbors::with_reader(Box::new(|| Ok(NeighborTable::new())))
            .routing(Box::new(|address| Ok(Some(address))));
        let neighbours = Arc::new(Neighbours::reading(Some(table)));
        neighbours.give_up(ip);

        let probed = port_prober(
            tcp_target(ip, port),
            ServiceDetection::Off,
            Shaping::default(),
            Egress::KERNEL,
            SocketAddr::new(ip, port),
            CONNECT_PROBE_TIMEOUT,
            crate::scanner::session::ScanSession::new().1,
            Default::default(),
            neighbours,
        )
        .await
        .expect("a TCP target is probed");

        assert_eq!(
            probed.port.as_ref().map(Port::state),
            Some(PortState::Unasked)
        );
        assert_eq!(probed.attempt, Attempt::Refused(Refusal::Unresolved));
        assert!(listener.accept().is_err(), "the port was connected");
    }

    /// A lone round-trip sample on a slow path earns the same wait as an
    /// unmeasured path.
    #[test]
    fn a_lone_sample_is_held_to_the_path_finding_wait() {
        assert_eq!(
            crate::transport::dial::UNMEASURED_PATH_WAIT,
            PATH_FINDING_TIMEOUT
        );
    }

    /// A neighbour's path-finding connect also waits for its resolution; other
    /// addresses wait for the handshake alone. Link-local addresses are
    /// neighbours.
    #[test]
    fn a_neighbour_s_first_connect_waits_for_its_resolution_too() {
        use crate::system::interface::{Link, LinkAddress};

        let segments = OnLinkTable::from_links(&[Link::new("test0", 1).with_addresses(vec![
            LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24),
            LinkAddress::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                64,
            ),
        ])]);
        let wait =
            |ip: &str| path_finding_wait(is_neighbour(&segments, ip.parse().expect("an address")));

        for neighbour in ["192.0.2.9", "2001:db8::9", "fe80::9"] {
            assert_eq!(
                wait(neighbour),
                NEIGHBOUR_PATH_FINDING_TIMEOUT,
                "{neighbour}"
            );
        }
        for routed in ["203.0.113.9", "2001:db8:9::1"] {
            assert_eq!(wait(routed), PATH_FINDING_TIMEOUT, "{routed}");
        }
    }

    /// The answer to a sweep's first connect to a neighbour is kept as an upper
    /// bound, since it may include resolution; a later handshake replaces it for
    /// sizing waits.
    ///
    /// Across a 1.9 s path, an unresolved neighbour answered that connect in
    /// 3.8 s; kept as a plain round trip it tripled every identification wait, and
    /// scanning one silent port took 59 s.
    #[test]
    fn a_neighbour_s_first_answer_is_a_bound_a_later_handshake_retires() {
        use crate::model::host::telemetry::RttSource;

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let resolving = Instant::now()
            .checked_sub(Duration::from_millis(3_800))
            .expect("a clock that has run");
        let Fate::Answered(mut swept) = answered(ip, resolving, true).fate else {
            panic!("an answered address is answered");
        };
        assert_eq!(
            swept
                .telemetry()
                .history()
                .back()
                .map(|sample| sample.source),
            Some(RttSource::FirstToNeighbour)
        );

        let path = Duration::from_millis(1_900);
        swept.add_rtt_from(path, StatusProtocol::TcpConnect);
        assert_eq!(swept.telemetry().round_trips(), [path]);
    }

    fn tcp_target(ip: IpAddr, port: u16) -> PlannedTarget {
        PlannedTarget::new(
            u64::from(port),
            Target {
                ip,
                port,
                protocol: Protocol::Tcp,
            },
        )
    }

    /// A connect that reaches its own socket is never filed as an open port.
    ///
    /// On Linux, and on macOS over IPv6, a connect whose source port is the
    /// target's completes a handshake with itself; on macOS over IPv4 the kernel
    /// refuses it. Either way nothing was asked.
    ///
    /// Pinning the source port to the target's makes every retry meet itself too,
    /// so the port ends unasked with the reason reported.
    #[tokio::test]
    async fn a_connect_that_reaches_itself_is_never_filed_as_an_open_port() {
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let held = crate::testing::loopback::HeldTcpPort::open(ip);
            let port = held.port();
            let shaping = Shaping {
                source_port: Some(port),
                hop_limit: None,
            };

            let probed = port_prober(
                tcp_target(ip, port),
                ServiceDetection::default(),
                shaping,
                Egress::KERNEL,
                SocketAddr::new(ip, port),
                CONNECT_PROBE_TIMEOUT,
                crate::scanner::session::ScanSession::new().1,
                Default::default(),
                Default::default(),
            )
            .await
            .expect("a TCP target is probed");

            assert_eq!(
                probed.port.as_ref().map(Port::state),
                Some(PortState::Unasked),
                "{ip}: a connect that met itself was filed as {:?}",
                probed.port
            );
            assert!(
                matches!(&probed.attempt, Attempt::Refused(Refusal::Local(why))
                    if why.contains("reached itself")),
                "{ip}: the refusal says why, and has {:?}",
                probed.attempt
            );
            assert!(!probed.answered, "{ip}: nothing answered");
        }
    }

    /// A stop ends an identification in flight. On a port that accepts and says
    /// nothing, a thorough identification opens a connection per question. The
    /// stop arrives after the first connection; the probe must open no other and
    /// keep the handshake's verdict.
    #[tokio::test]
    async fn a_stop_ends_an_identification_in_flight() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("a free port");
        let port = listener.local_addr().expect("its address").port();

        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let stopper = ctx.handle.clone();
        let (returned, mut probe_done) = tokio::sync::oneshot::channel::<()>();
        // Accepts every connection silently; stops the scan after the first.
        let listening = tokio::spawn(async move {
            let mut held = Vec::new();
            let first = accept_from_this_process(&listener)
                .await
                .expect("the probe connects");
            held.push(first);
            stopper.abort();
            // Held open until the probe returns, so only the stop ends it.
            loop {
                tokio::select! {
                    accepted = accept_from_this_process(&listener) => {
                        held.push(accepted.expect("a connection"));
                    }
                    _ = &mut probe_done => break,
                }
            }
            // Collect anything else the probe opened before returning.
            while let Ok(Ok(more)) = tokio::time::timeout(
                Duration::from_millis(500),
                accept_from_this_process(&listener),
            )
            .await
            {
                held.push(more);
            }
            held.len()
        });

        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let probed = port_prober(
            tcp_target(ip, port),
            ServiceDetection::Thorough,
            Shaping::default(),
            Egress::KERNEL,
            SocketAddr::new(ip, port),
            CONNECT_PROBE_TIMEOUT,
            ctx,
            Default::default(),
            Default::default(),
        )
        .await
        .expect("a TCP target is probed");
        let _ = returned.send(());

        assert_eq!(
            listening.await.expect("the listener ends"),
            1,
            "the identification went on connecting after the stop"
        );
        assert_eq!(
            probed.port.as_ref().map(Port::state),
            Some(PortState::Open),
            "the handshake's verdict is kept"
        );
        assert!(probed.answered);
    }

    /// A loopback listener that drops every further SYN, and the connections that
    /// filled its queue, to be held as long as it is.
    ///
    /// A listener never accepted from queues connections up to its backlog, then
    /// drops further SYNs on Linux and the BSDs (Windows resets them), which looks
    /// like a firewalled port. Backlog one, since macOS reads zero as its default;
    /// filled until a connect goes unanswered, whatever the stack's backlog
    /// arithmetic.
    #[cfg(unix)]
    fn a_port_that_drops_syns() -> (socket2::Socket, Vec<std::net::TcpStream>) {
        let listener = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .expect("a socket");
        listener
            .bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())
            .expect("binds loopback");
        listener.listen(1).expect("listens");
        let addr = listener
            .local_addr()
            .expect("its address")
            .as_socket()
            .expect("an inet address");
        let mut queued = Vec::new();
        for _ in 0..64 {
            match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
                Ok(stream) => queued.push(stream),
                Err(_) => return (listener, queued),
            }
        }
        panic!("the listener's queue never filled");
    }

    /// A stop ends a handshake in flight at once and leaves its port unasked: the
    /// SYN left but the probe had not waited its full patience.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_stop_ends_a_handshake_in_flight_and_leaves_its_port_unasked() {
        let (listener, _queued) = a_port_that_drops_syns();
        let port = listener
            .local_addr()
            .expect("its address")
            .as_socket()
            .expect("an inet address")
            .port();

        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let stopper = ctx.handle.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            stopper.abort();
        });

        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        // Far longer than the timeout below, so only the stop can end it.
        let patience = Duration::from_secs(600);
        let probed = tokio::time::timeout(
            Duration::from_secs(60),
            port_prober(
                tcp_target(ip, port),
                ServiceDetection::Off,
                Shaping::default(),
                Egress::KERNEL,
                SocketAddr::new(ip, port),
                patience,
                ctx,
                Default::default(),
                Default::default(),
            ),
        )
        .await
        .expect("the stop ended the handshake")
        .expect("a TCP target is probed");

        assert_eq!(
            probed.port.as_ref().map(Port::state),
            Some(PortState::Unasked),
            "a handshake cut short has no verdict"
        );
        assert!(!probed.answered);
        assert!(
            matches!(probed.outcome, Outcome::Interrupted),
            "asked and cut short, so a resume asks again: {:?}",
            probed.outcome
        );
    }

    /// A second asking cut short by a stop files nothing, so the first asking's
    /// `NoReply` stands.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_second_asking_cut_short_revises_nothing() {
        let (listener, _queued) = a_port_that_drops_syns();
        let port = listener
            .local_addr()
            .expect("its address")
            .as_socket()
            .expect("an inet address")
            .port();
        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let stopper = ctx.handle.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            stopper.abort();
        });

        let (crowds, tarpits, neighbours) = Default::default();
        let asking = Asking {
            ctx: &ctx,
            detection: ServiceDetection::Off,
            shaping: Shaping::default(),
            zones: &ZoneMap::new(),
            crowds: &crowds,
            tarpits: &tarpits,
            neighbours: &neighbours,
        };
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let probed = tokio::time::timeout(
            Duration::from_secs(60),
            asking.again(tcp_target(ip, port), Duration::from_secs(600)),
        )
        .await
        .expect("the stop ended the handshake")
        .expect("a TCP target is probed");

        assert_eq!(probed.port, None, "the second asking filed a port");
        assert!(matches!(probed.attempt, Attempt::Sent), "its send counts");
    }

    /// A handshake's round trip is filed with the host as soon as it completes,
    /// while the port is still being identified, since other ports of the host
    /// size their waits from it meanwhile.
    #[tokio::test]
    async fn a_handshake_times_the_host_before_its_port_is_identified() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("a free port");
        let port = listener.local_addr().expect("its address").port();
        let (accepted, first) = tokio::sync::oneshot::channel();
        // Takes the connection and says nothing, so the identification waits.
        let listening = tokio::spawn(async move {
            let held = accept_from_this_process(&listener)
                .await
                .expect("the probe connects");
            let _ = accepted.send(());
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(held);
        });

        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let probing = tokio::spawn(port_prober(
            tcp_target(ip, port),
            ServiceDetection::Banner,
            Shaping::default(),
            Egress::KERNEL,
            SocketAddr::new(ip, port),
            CONNECT_PROBE_TIMEOUT,
            ctx.clone(),
            Default::default(),
            Default::default(),
        ));
        first.await.expect("the listener took the connection");

        let mut timed = None;
        for _ in 0..200 {
            timed = ctx.read_host(ip, Host::median_rtt).flatten();
            if timed.is_some() || probing.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let identifying = !probing.is_finished();
        ctx.handle.abort();
        let _ = probing.await;
        listening.abort();

        assert!(
            timed.is_some(),
            "the handshake's round trip was not the host's while its port was identified"
        );
        assert!(identifying, "the identification ended before the test read");
    }

    /// A route refusing by policy is told from a missing one. Linux answers a
    /// `prohibit` route with permission denied and a `blackhole` route with
    /// invalid argument, wrapped in a host unreachable; a missing or
    /// `unreachable` route gives plain host or network unreachable.
    #[cfg(unix)]
    #[test]
    fn a_route_refusing_by_policy_is_told_from_a_missing_one() {
        let refused_with = |code| {
            Refusal::of(&io::Error::new(
                ErrorKind::HostUnreachable,
                io::Error::from_raw_os_error(code),
            ))
        };
        assert_eq!(refused_with(libc::EACCES), Refusal::Forbidden);
        assert_eq!(refused_with(libc::EINVAL), Refusal::Forbidden);
        assert_eq!(
            Refusal::of(&io::Error::from_raw_os_error(libc::EHOSTUNREACH)),
            Refusal::NoRoute
        );
        assert_eq!(
            Refusal::of(&io::Error::from_raw_os_error(libc::ENETUNREACH)),
            Refusal::NoRoute
        );
    }

    /// The same code before the SYN left is a local failure, and after it an
    /// answer. `EHOSTUNREACH` is both a missing local route and a far firewall's
    /// administrative prohibition, which Linux reports alike.
    #[test]
    fn an_unreachable_is_an_answer_after_the_syn_left_and_a_local_failure_before() {
        for kind in [ErrorKind::HostUnreachable, ErrorKind::NetworkUnreachable] {
            assert!(
                matches!(
                    Handshake::sent(Err(io::Error::from(kind))),
                    Handshake::Unreachable
                ),
                "{kind:?} after the SYN left"
            );
            assert!(
                matches!(
                    Handshake::unsent(io::Error::from(kind)),
                    Handshake::NotSent(_)
                ),
                "{kind:?} before anything left"
            );
            assert_eq!(
                Refusal::of(&io::Error::from(kind)),
                Refusal::NoRoute,
                "{kind:?} before anything left is filed against the address"
            );
        }
        let refused = || io::Error::from(ErrorKind::ConnectionRefused);
        assert!(matches!(
            Handshake::sent(Err(refused())),
            Handshake::Refused
        ));
        assert!(matches!(Handshake::unsent(refused()), Handshake::Refused));
        assert!(matches!(
            Handshake::sent(Err(io::Error::from(ErrorKind::TimedOut))),
            Handshake::Silent
        ));
        assert!(matches!(
            Handshake::unsent(io::Error::from(ErrorKind::AddrNotAvailable)),
            Handshake::NotSent(_)
        ));
    }

    /// A port this machine refused to send to is left unasked, and the report says
    /// why in the OS's words. Connections are pinned to a source no interface
    /// holds, so the bind fails before anything is sent and the documentation
    /// address is never dialled.
    #[tokio::test]
    async fn a_port_this_machine_refused_to_send_is_unasked_and_the_report_says_why() {
        let target = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let (session, ctx) = crate::scanner::session::ScanSession::builder()
            .send_source(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 250))])
            .build();
        let (tx, rx) = mpsc::channel(2);
        tx.send(tcp_target(target, 443)).await.expect("queued");
        drop(tx);

        scan(
            rx,
            1,
            ctx.clone(),
            ServiceDetection::Off,
            &EvasionProfile::default(),
            &ZoneMap::new(),
        )
        .await
        .expect("the scan runs");

        let state = session.hosts().read(target, |host| {
            host.ports().map(Port::state).collect::<Vec<_>>()
        });
        assert_eq!(state, Some(vec![PortState::Unasked]));
        let failures = ctx.failures_snapshot();
        assert!(
            failures.iter().any(|failure| failure
                .reason()
                .starts_with("1 port left unasked: this machine refused")),
            "the report says the refusal was this machine's, and has {failures:?}"
        );
        let stats = &ctx.probe_stats_snapshot()[0];
        assert_eq!(
            (stats.sends_attempted(), stats.sends_failed()),
            (1, 1),
            "a send this machine refused is a send that failed"
        );
    }

    /// Listeners on `count` ports of `ip`, and the ports. Never accepted from;
    /// the kernel completes the handshake into the backlog.
    fn listeners(ip: IpAddr, count: usize) -> (Vec<std::net::TcpListener>, Vec<u16>) {
        (0..count)
            .map(|_| {
                let listener = std::net::TcpListener::bind((ip, 0)).expect("bind a listener");
                let port = listener.local_addr().expect("its address").port();
                (listener, port)
            })
            .unzip()
    }

    /// Asserts that this process began one connection to each of `addrs`, at
    /// least `gap` apart less a scheduling margin, in any order.
    ///
    /// Read from where every connection begins, which sees each SYN handed to the
    /// kernel whether or not it is accepted; see
    /// [`dialled`](crate::transport::dial::dialled).
    fn assert_spaced(addrs: &[SocketAddr], gap: Duration) {
        let mut times: Vec<Instant> = addrs
            .iter()
            .flat_map(|&addr| crate::transport::dial::dialled::times(addr))
            .collect();
        assert_eq!(times.len(), addrs.len(), "every port was connected to once");
        times.sort();
        let margin = gap / 3;
        for pair in times.windows(2) {
            let apart = pair[1] - pair[0];
            assert!(
                apart + margin >= gap,
                "two connections {apart:?} apart under a {gap:?} gap"
            );
        }
    }

    /// Runs a connect scan of all `targets` at once, with no identification,
    /// returning once it has drained.
    async fn scan_all(ctx: &ScanContext, targets: Vec<PlannedTarget>) {
        let (tx, rx) = mpsc::channel(targets.len());
        let concurrency = targets.len();
        for target in targets {
            tx.send(target).await.expect("queued");
        }
        drop(tx);
        // Boxed, as in `scan`: the walk's state is too large for the stack.
        Box::pin(scan(
            rx,
            concurrency,
            ctx.clone(),
            ServiceDetection::Off,
            &EvasionProfile::default(),
            &ZoneMap::new(),
        ))
        .await
        .expect("the scan runs");
    }

    /// The states the scan recorded for `ports` of `ip`, in the order given.
    fn states_of(
        session: &crate::scanner::session::ScanSession,
        ip: IpAddr,
        ports: &[u16],
    ) -> Vec<Option<PortState>> {
        ports
            .iter()
            .map(|&number| {
                session
                    .hosts()
                    .read(ip, |host| {
                        host.ports()
                            .find(|port| port.number() == number)
                            .map(Port::state)
                    })
                    .flatten()
            })
            .collect()
    }

    /// A connect scan's connections to one host keep the host's gap, however many
    /// the pool holds, and every port still gets its verdict. The pool admits all
    /// ports together; the slot each claims before its SYN is what spaces them.
    #[tokio::test]
    async fn a_connect_scan_keeps_the_host_gap_between_its_connections() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let gap = Duration::from_millis(300);
        let (_listeners, ports) = listeners(ip, 4);
        let (session, ctx) = crate::scanner::session::ScanSession::builder()
            .host_probe_interval(Some(gap))
            .build();

        scan_all(
            &ctx,
            ports.iter().map(|&port| tcp_target(ip, port)).collect(),
        )
        .await;

        assert_eq!(
            states_of(&session, ip, &ports),
            vec![Some(PortState::Open); ports.len()],
            "a port held for its slot lost its verdict"
        );
        let addrs: Vec<SocketAddr> = ports
            .iter()
            .map(|&port| SocketAddr::new(ip, port))
            .collect();
        assert_spaced(&addrs, gap);
    }

    /// A connect scan's connections keep the scan-wide gap across hosts asked
    /// side by side.
    #[tokio::test]
    async fn a_connect_scan_keeps_the_scan_wide_gap_across_hosts() {
        let gap = Duration::from_millis(300);
        let hosts = [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
        let mut held = Vec::new();
        let mut asked = Vec::new();
        for ip in hosts {
            let (listening, ports) = listeners(ip, 2);
            held.push(listening);
            asked.push((ip, ports));
        }
        let (session, ctx) = crate::scanner::session::ScanSession::builder()
            .probe_interval(Some(gap))
            .build();

        let targets = asked
            .iter()
            .flat_map(|(ip, ports)| ports.iter().map(|&port| tcp_target(*ip, port)))
            .collect();
        scan_all(&ctx, targets).await;

        for (ip, ports) in &asked {
            assert_eq!(
                states_of(&session, *ip, ports),
                vec![Some(PortState::Open); ports.len()],
                "{ip}: a port held for its slot lost its verdict"
            );
        }
        let addrs: Vec<SocketAddr> = asked
            .iter()
            .flat_map(|(ip, ports)| ports.iter().map(|&port| SocketAddr::new(*ip, port)))
            .collect();
        assert_spaced(&addrs, gap);
    }

    /// A scan stopped while connections wait for their slots ends at once, and the
    /// waiting ports are unasked. The gap is an hour, so only the stop can end the
    /// wait.
    #[tokio::test]
    async fn a_stop_ends_the_wait_for_a_slot_and_leaves_the_port_unasked() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let (_listeners, ports) = listeners(ip, 3);
        let (session, ctx) = crate::scanner::session::ScanSession::builder()
            .host_probe_interval(Some(Duration::from_secs(3600)))
            .build();
        let addrs: Vec<SocketAddr> = ports
            .iter()
            .map(|&port| SocketAddr::new(ip, port))
            .collect();
        let begun = move |addrs: &[SocketAddr]| -> usize {
            addrs
                .iter()
                .map(|&addr| crate::transport::dial::dialled::to(addr))
                .sum()
        };
        // Stop once the first connection has left and the others wait behind it.
        let stopper = ctx.handle.clone();
        let watched = addrs.clone();
        let stopped_at = tokio::spawn(async move {
            while begun(&watched) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            stopper.abort();
            Instant::now()
        });

        tokio::time::timeout(
            Duration::from_secs(60),
            scan_all(
                &ctx,
                ports.iter().map(|&port| tcp_target(ip, port)).collect(),
            ),
        )
        .await
        .expect("the stop ended the waits");
        let stopped_at = stopped_at.await.expect("the stopper joins");
        assert!(
            stopped_at.elapsed() < Duration::from_secs(2),
            "the scan outlived its stop by {:?}",
            stopped_at.elapsed()
        );

        let mut states = states_of(&session, ip, &ports);
        states.sort_by_key(|state| format!("{state:?}"));
        assert_eq!(
            states,
            vec![
                Some(PortState::Open),
                Some(PortState::Unasked),
                Some(PortState::Unasked)
            ],
            "the first port was asked and the two behind it were not"
        );
        assert_eq!(begun(&addrs), 1, "one connection left");
    }

    /// Scans `target` alone through [`scan_among`], with the kernel's
    /// hold-down on a neighbour lasting a third of a second.
    #[cfg(unix)]
    async fn scan_held_down(ctx: &ScanContext, target: PlannedTarget) {
        let (tx, rx) = mpsc::channel(1);
        tx.send(target).await.expect("queued");
        drop(tx);
        scan_among(
            rx,
            1,
            ctx.clone(),
            ServiceDetection::Off,
            &EvasionProfile::default(),
            &ZoneMap::new(),
            Neighbours::default().holding_down_for(Duration::from_millis(300)),
        )
        .await
        .expect("the scan runs");
    }

    /// A connect refused for a neighbour hold-down (`EHOSTDOWN` on macOS) is asked
    /// again once it is over, and is not reported as this machine's failure. The
    /// failed resolution may have been another process's, and a neighbour asleep
    /// through one may answer the next.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_connect_refused_for_a_hold_down_is_asked_again_after_it() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let listener = std::net::TcpListener::bind((ip, 0)).expect("bind a listener");
        let addr = listener.local_addr().expect("an inet address");
        crate::transport::dial::dialled::refuse(addr, libc::EHOSTDOWN, 1);
        let (session, ctx) = crate::scanner::session::ScanSession::new();

        scan_held_down(&ctx, tcp_target(ip, addr.port())).await;

        assert_eq!(
            crate::transport::dial::dialled::to(addr),
            2,
            "the port was not asked again"
        );
        let state = session
            .hosts()
            .read(ip, |host| host.ports().map(Port::state).collect::<Vec<_>>());
        assert_eq!(state, Some(vec![PortState::Open]));
        assert!(
            ctx.failures_snapshot().is_empty(),
            "a hold-down was blamed on this machine: {:?}",
            ctx.failures_snapshot()
        );
        assert!(!ctx.is_unroutable(ip));
    }

    /// A host held down again after the first hold-down is filed unreachable with
    /// its port unasked, still not as this machine's failure: the second refusal
    /// follows a fresh resolution and is the kernel's verdict.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_connect_refused_for_a_second_hold_down_files_its_host_unreachable() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let listener = std::net::TcpListener::bind((ip, 0)).expect("bind a listener");
        let addr = listener.local_addr().expect("an inet address");
        crate::transport::dial::dialled::refuse(addr, libc::EHOSTDOWN, 2);
        let (session, ctx) = crate::scanner::session::ScanSession::new();

        scan_held_down(&ctx, tcp_target(ip, addr.port())).await;

        assert_eq!(crate::transport::dial::dialled::to(addr), 2);
        let state = session
            .hosts()
            .read(ip, |host| host.ports().map(Port::state).collect::<Vec<_>>());
        assert_eq!(state, Some(vec![PortState::Unasked]));
        assert!(ctx.is_unroutable(ip), "the host is unreached");
        assert!(
            ctx.failures_snapshot().is_empty(),
            "a hold-down was blamed on this machine: {:?}",
            ctx.failures_snapshot()
        );
    }

    /// On a host that answers on every port, an open port outside the likeliest is
    /// not identified (on an ordinary host it is), and the report counts those.
    /// Otherwise each would cost a full conversation, hours across the port range.
    /// The host is marked a tarpit before the scan here. A closed port does not
    /// count as unidentified.
    #[tokio::test]
    async fn a_tarpits_unlikely_port_is_found_open_and_not_asked_what_it_runs() {
        use crate::scanner::service::TARPIT_PORTS_IDENTIFIED;
        use crate::testing::loopback::SilentPort;

        let mut heard = Vec::new();
        for tarpit in [true, false] {
            let silent = SilentPort::open();
            let addr = silent.addr();
            assert!(
                !crate::model::port::catalog::top_tcp(TARPIT_PORTS_IDENTIFIED)
                    .contains(&addr.port()),
                "test assumes an ephemeral port is not among the likeliest"
            );
            let (session, ctx) = crate::scanner::session::ScanSession::new();
            ctx.update_host(addr.ip(), |host| {
                if tarpit {
                    host.add_network_role(NetworkRole::Tarpit);
                }
            });
            // And a closed port, which must not count as unidentified.
            let closed = crate::testing::loopback::refused_port(addr.ip()).port();
            let (tx, rx) = mpsc::channel(2);
            for port in [addr.port(), closed] {
                tx.send(tcp_target(addr.ip(), port)).await.expect("queued");
            }
            drop(tx);

            scan(
                rx,
                1,
                ctx.clone(),
                ServiceDetection::Probe,
                &EvasionProfile::default(),
                &ZoneMap::new(),
            )
            .await
            .expect("the scan runs");

            let open = session.hosts().read(addr.ip(), |host| {
                host.ports()
                    .filter(|port| port.state() == PortState::Open)
                    .map(Port::number)
                    .collect::<Vec<_>>()
            });
            assert_eq!(open, Some(vec![addr.port()]), "tarpit: {tarpit}");
            // Filed under the service pass, as on the raw path.
            let reported = ctx.failures_snapshot().iter().any(|failure| {
                failure.scanner() == ScannerKind::Service
                    && failure.reason().starts_with(&format!(
                        "{}: 1 open ports were not fingerprinted",
                        addr.ip()
                    ))
            });
            assert_eq!(reported, tarpit, "tarpit: {tarpit}");
            heard.push(silent.heard());
        }

        assert_eq!(heard[0], 0, "the tarpit's port was asked what it runs");
        assert!(
            heard[1] > 0,
            "the same port on an ordinary host was asked nothing, so the first \
             half proves nothing"
        );
    }

    /// A port asked again from a pinned source port during the previous
    /// connection's closing wait is either asked or the report names the pinned
    /// port. The four-tuple lingers up to a minute after close, and macOS refuses
    /// the next connect with it, as Linux does beyond loopback.
    #[tokio::test]
    async fn a_pinned_source_port_still_closing_is_named_as_the_reason_a_port_went_unasked() {
        use tokio::io::AsyncReadExt;

        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let listener = tokio::net::TcpListener::bind((ip, 0)).await.expect("bind");
        let port = listener.local_addr().expect("bound").port();
        // Held until the scanner closes first, so the closing wait is the scanner's.
        tokio::spawn(async move {
            while let Ok(mut stream) = accept_from_this_process(&listener).await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 256];
                    while matches!(stream.read(&mut buf).await, Ok(read) if read > 0) {}
                });
            }
        });
        let held = crate::testing::loopback::HeldTcpPort::open(ip);
        let pinned = held.port();
        let evasion = EvasionProfile {
            source_port: Some(pinned),
            ..EvasionProfile::default()
        };

        let run = || async {
            let (session, ctx) = crate::scanner::session::ScanSession::new();
            let (tx, rx) = mpsc::channel(1);
            tx.send(tcp_target(ip, port)).await.expect("queued");
            drop(tx);
            scan(
                rx,
                1,
                ctx.clone(),
                ServiceDetection::Off,
                &evasion,
                &ZoneMap::new(),
            )
            .await
            .expect("the scan runs");
            let state = session
                .hosts()
                .read(ip, |host| host.ports().map(Port::state).next())
                .flatten();
            let reasons: Vec<String> = ctx
                .failures_snapshot()
                .iter()
                .map(|failure| failure.reason().to_string())
                .collect();
            (state, reasons)
        };

        assert_eq!(run().await.0, Some(PortState::Open), "the first run");
        match run().await {
            (Some(PortState::Open), _) => {}
            (Some(PortState::Unasked), reasons) => assert!(
                reasons.iter().any(|reason| reason
                    == &format!("1 port left unasked: source port {pinned} still closing")),
                "the report names the pinned port, and has {reasons:?}"
            ),
            other => panic!("the port was neither asked nor unasked: {other:?}"),
        }
    }

    /// A held pinned source port gives one short warning and a cut-short report
    /// entry for the unasked ports, not a scanner failure.
    #[test]
    fn a_pinned_source_port_held_is_warned_in_one_short_line_not_as_a_failure() {
        for (holder, by) in [
            (Holder::Closing, "still closing"),
            (Holder::Socket, "held elsewhere"),
        ] {
            let (_session, ctx) = crate::scanner::session::ScanSession::new();
            let mut shortfall = Shortfall::default();
            let held = Attempt::Refused(Refusal::PortHeld(40404, holder));
            shortfall.count(IpAddr::V4(Ipv4Addr::LOCALHOST), &held);
            shortfall.count(IpAddr::V4(Ipv4Addr::LOCALHOST), &held);

            let lines = crate::logging::logged(|| {
                shortfall.report(&ctx, ScannerKind::Connect, "port", "ports");
            });

            let said: Vec<&str> = lines.iter().map(|line| line.message.as_str()).collect();
            assert_eq!(said, [format!("2 ports unasked (source port 40404 {by})")]);
            let filed: Vec<(String, bool)> = ctx
                .failures_snapshot()
                .iter()
                .map(|failure| (failure.reason().to_string(), failure.is_cut_short()))
                .collect();
            assert_eq!(
                filed,
                [(
                    format!("2 ports left unasked: source port 40404 {by}"),
                    true
                )],
                "filed, and marked as cut short rather than failed"
            );
        }
    }

    /// Targets starved of a socket give one short warning naming the file limit
    /// and a cut-short report entry counting them.
    #[test]
    fn descriptor_starvation_is_warned_naming_the_limit_and_filed_as_cut_short() {
        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let mut shortfall = Shortfall::default();
        shortfall.count(IpAddr::V4(Ipv4Addr::LOCALHOST), &Attempt::Starved);
        shortfall.count(IpAddr::V4(Ipv4Addr::LOCALHOST), &Attempt::Starved);
        shortfall.identified_in_part = 1;

        let lines = crate::logging::logged(|| {
            shortfall.report(&ctx, ScannerKind::Connect, "port", "ports");
        });

        let limit = descriptors::starved_briefly();
        let said: Vec<&str> = lines.iter().map(|line| line.message.as_str()).collect();
        assert_eq!(
            said,
            [
                format!("2 ports unasked ({limit})"),
                format!("1 port identified in part ({limit})"),
            ]
        );
        let filed = ctx.failures_snapshot();
        assert_eq!(filed.len(), 2, "{filed:?}");
        assert!(
            filed.iter().all(|failure| failure.is_cut_short()
                && failure.reason().contains("file descriptor limit")),
            "{filed:?}"
        );
    }

    /// The UDP prober skips TCP targets.
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
    /// default profile stays inert.
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

    #[cfg(unix)]
    use crate::system::descriptors::testing::{
        exhaust as exhaust_descriptors, in_a_process_of_its_own,
    };

    /// A sweep short of sockets waits for one and finds the host once the table
    /// has room. The address is loopback, which answers every connect; the
    /// descriptor table empties shortly after the sweep starts.
    #[cfg(unix)]
    #[test]
    fn a_sweep_short_of_descriptors_waits_for_one_rather_than_passing_the_address_over() {
        if !in_a_process_of_its_own(
            module_path!(),
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

    /// A liveness connect that reaches its own socket finds no host. It completes
    /// a handshake with itself on Linux and on macOS over IPv6, and macOS refuses
    /// it over IPv4. Pinned to the port it asks, every attempt meets itself, so
    /// the address stays unsettled and the report says why.
    #[tokio::test]
    async fn a_sweep_connect_that_reaches_itself_finds_no_host_and_says_why() {
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let held = crate::testing::loopback::HeldTcpPort::open(ip);
            let port = held.port();
            let evasion = EvasionProfile {
                source_port: Some(port),
                ..EvasionProfile::default()
            };
            let (session, ctx) = crate::scanner::session::ScanSession::new();

            discover_on(IpSet::from(ip), ctx.clone(), &evasion, SynPorts::only(port))
                .await
                .expect("the sweep runs");

            assert!(
                !session
                    .hosts()
                    .read(ip, |host| host.status() == HostStatus::Up)
                    .unwrap_or(false),
                "{ip}: a connect that met itself proved a host"
            );
            assert_eq!(ctx.settlements().settled_count(), 0, "{ip}: nothing asked");
            let failures = ctx.failures_snapshot();
            assert!(
                failures
                    .iter()
                    .any(|failure| failure.reason().contains("reached itself")),
                "{ip}: the report says why, and has {failures:?}"
            );
        }
    }

    /// A liveness knock reads an error by where it surfaced, as for a port. No
    /// route before sending is filed against the address; the same code after the
    /// SYN left is a router or filter answering, which proves no host. A refusal
    /// proves one.
    #[test]
    fn a_liveness_knock_reads_an_unreachable_by_where_it_surfaced() {
        for kind in [ErrorKind::HostUnreachable, ErrorKind::NetworkUnreachable] {
            assert!(
                matches!(
                    Knock::of(Handshake::unsent(io::Error::from(kind))),
                    Knock::Refused(Refusal::NoRoute)
                ),
                "{kind:?} before anything left"
            );
            assert!(
                matches!(
                    Knock::of(Handshake::sent(Err(io::Error::from(kind)))),
                    Knock::Asked
                ),
                "{kind:?} after the SYN left"
            );
        }
        assert!(matches!(
            Knock::of(Handshake::sent(Err(io::Error::from(
                ErrorKind::ConnectionRefused
            )))),
            Knock::Answered
        ));
        assert!(matches!(
            Knock::of(Handshake::sent(Err(io::Error::from(ErrorKind::TimedOut)))),
            Knock::Asked
        ));
    }

    /// An address no route leads to is filed unroutable, not as a sweep failure.
    #[test]
    fn an_address_no_route_leads_to_is_filed_unroutable() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let mut audit = ProbeAudit::default();
        let mut shortfall = Shortfall::default();

        absorb_host(
            &ctx,
            ProbedHost {
                ip,
                fate: Fate::Refused(Refusal::NoRoute),
            },
            &mut audit,
            &mut 0,
            &mut shortfall,
            &OnLinkTable::from_links(&[]),
        );
        shortfall.report(&ctx, ScannerKind::Connect, "address", "addresses");

        assert!(ctx.is_unroutable(ip));
        assert!(ctx.failures_snapshot().is_empty(), "nothing broke here");
    }

    /// A neighbour the routing table refuses is named refused by a route, since
    /// only an override of the connected route can refuse it. An address off the
    /// segments, one the table does not refuse, and the broadcast address are
    /// only unreachable.
    #[test]
    fn a_neighbour_the_routing_table_refuses_is_named_refused_by_a_route() {
        use crate::system::interface::{Link, LinkAddress};

        let segments = OnLinkTable::from_links(&[Link::new("test0", 1).with_addresses(vec![
            LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24),
        ])]);
        let address = |last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last));
        let routed = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let mut shortfall = Shortfall::default();
        for ip in [address(2), address(3), address(255), routed] {
            shortfall.count(ip, &Attempt::Refused(Refusal::NoRoute));
        }
        // Like a table with an `unreachable` route over .2 and no route off the
        // segment: refuses .2, the broadcast address and anything off-segment.
        shortfall.file(
            &ctx,
            ScannerKind::Connect,
            "address",
            "addresses",
            &segments,
            |target| target != IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
        );

        for ip in [address(2), address(3), address(255), routed] {
            assert!(ctx.is_unroutable(ip), "{ip} not filed unreachable");
        }
        let refused = ctx.take_refused_by_route();
        assert_eq!(refused, [address(2)]);
    }

    /// A segment's network and broadcast addresses, which the kernel refuses like
    /// unrouted ones, are settled with no host, as the frame sweep settles them.
    /// A neighbour refused the same way is still unreachable.
    #[test]
    fn a_segment_s_own_addresses_are_settled_rather_than_filed_unreachable() {
        use crate::system::interface::{Link, LinkAddress};

        let segments = OnLinkTable::from_links(&[Link::new("test0", 1).with_addresses(vec![
            LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24),
        ])]);
        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let mut audit = ProbeAudit::default();
        let mut shortfall = Shortfall::default();
        let edges = [Ipv4Addr::new(192, 0, 2, 0), Ipv4Addr::new(192, 0, 2, 255)];
        let neighbour = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        for ip in edges.map(IpAddr::V4).into_iter().chain([neighbour]) {
            absorb_host(
                &ctx,
                ProbedHost {
                    ip,
                    fate: Fate::Refused(Refusal::NoRoute),
                },
                &mut audit,
                &mut 0,
                &mut shortfall,
                &segments,
            );
        }
        shortfall.report(&ctx, ScannerKind::Connect, "address", "addresses");

        let settled_silent = ctx.take_silent();
        for edge in edges.map(IpAddr::V4) {
            assert!(!ctx.is_unroutable(edge), "{edge} filed unreachable");
            assert!(settled_silent.contains(&edge), "{edge} left unsettled");
        }
        assert!(ctx.is_unroutable(neighbour));
        assert!(!settled_silent.contains(&neighbour));
    }

    /// A sweep that never gets a socket leaves the address unsettled, counts the
    /// send as failed, and files the file limit as the reason, cut short.
    #[cfg(unix)]
    #[test]
    fn a_sweep_that_never_gets_a_socket_reports_it_rather_than_an_empty_network() {
        if !in_a_process_of_its_own(
            module_path!(),
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
                SynPorts::common(),
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
                failures.iter().any(|failure| failure
                    .reason()
                    .contains("file descriptor limit of 64")
                    && failure.is_cut_short()),
                "the report names the limit the sweep ran into, as a limit and \
                 not a fault, and has {failures:?}"
            );
        });
    }
}
