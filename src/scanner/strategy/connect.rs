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
//! with a `ProbePool`, and both record findings through the shared
//! [`ScanContext`] like every other strategy. What they draw differs with the
//! phase: a sweep asks about an address and a port scan about an address paired
//! with a port, which is the unit each of them settles.
//!
//! Every probe takes its socket from the process's descriptor budget first
//! (see `dial`), and a probe the process has no socket for waits for one.
//! A shell's file limit therefore slows a scan and never narrows it: a socket
//! the process could not open is a question nobody asked, not an answer.
//!
//! ## What a socket cannot see
//!
//! The kernel hands back an outcome and never the packet behind it, so two
//! readings the raw path makes are out of reach here. A refused connect is a
//! reset or an ICMP port unreachable, reported alike, and the second is what a
//! firewall rejecting on a host's behalf sends by default: such a filter in
//! front of an address with nothing behind it reads here as a host up with a
//! closed port. And a UDP port is asked once, so a host rationing its ICMP
//! errors, which leaves most of its closed ports reading open|filtered on
//! either path, is never named as rationing here: only a retry answered late
//! shows the ration, and this path makes none.

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
use crate::system::interface::{OnLinkTable, ProbeSockets, refuses_neighbour};
use crate::transport::dial::PathAllowance;
use crate::transport::dial::{Connecting, Egress, Holder, Shaping, SourcePortHeld};
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
    /// The ports every address is asked about.
    ports: SynPorts,
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
        Self::asking(ips, ctx, evasion, SynPorts::common())
    }

    /// [`new`](Self::new), asking `ports` rather than the common five.
    ///
    /// The set a routed sweep of the same addresses would ask, so that which
    /// strategy reached an address decides nothing about which ports it was
    /// asked on. See [`discover_on`].
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
        // The targets are taken rather than cloned. A sweep asks each address
        // once, so a second call has nothing left to probe and correctly does
        // nothing, where a clone would silently re-probe the whole set.
        discover_on(
            std::mem::take(&mut self.ips),
            self.ctx.clone(),
            &self.evasion,
            self.ports,
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
    /// Whether identifying the port lost a later connection for want of a
    /// socket, so that what it names is a floor; see
    /// [`Fingerprinted::starved`](crate::fingerprint::Fingerprinted::starved).
    identified_in_part: bool,
    /// Whether the host answered. The kernel hands back a completed handshake or
    /// a `ConnectionRefused` only when something came back, and a refusal is
    /// almost always the target's own RST, so either is read as a live stack;
    /// a port unreachable standing in for one comes, as a rule, from a filter
    /// on the host itself. A timeout or any other unreachable proves
    /// nothing about the host, whose sender this path cannot see, and never
    /// sets this.
    answered: bool,
    /// What became of this target, for a resume.
    ///
    /// Distinct from [`answered`](Self::answered), which is about the *host*: a
    /// timeout proves nothing about the host and still settles the target,
    /// because the connect made its one and only attempt.
    outcome: Outcome,
    /// Whether a send was made, as the run's audit counts it.
    attempt: Attempt,
    /// How long the connect took to draw its answer, where it drew one.
    ///
    /// A completed handshake returns once the SYN/ACK is in and a refusal once
    /// the RST is, so either is one round trip to the host, timed from when
    /// the attempt began rather than from any wait for a socket. `None` for a
    /// timeout and for every probe that never left.
    rtt: Option<Duration>,
    /// What the reply proved the host *is*, where its protocol says so.
    ///
    /// A claim about the host rather than about the port, and carried alongside
    /// the verdict rather than folded into it for that reason: a name server
    /// and a socket bound to 53 produce the same `Open`, and only one of them
    /// is a name server. See [`payload::declared_role`].
    role: Option<NetworkRole>,
    /// The connect that heard nothing, and how long it waited, for a port
    /// filed filtered because its connect ran out of time; see [`SlowPaths`].
    silence: Option<Silence>,
    /// Whether this probe's outcome settles its target. A second asking's
    /// does not: the first asking settled the target already, and the second
    /// only revises what it was filed as.
    settles: bool,
}

/// The outcome of one finished [`port_prober`] task.
type ProbedPort = Option<Probed>;

/// Whether a port probe put anything on the wire, which is what the run's
/// `sends_attempted` and `sends_failed` count.
///
/// Carried by the probe rather than counted when it is admitted, because only
/// the probe knows: a probe admitted can still find no socket, no route, or a
/// scan that stopped before it asked.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Attempt {
    /// The probe was sent.
    Sent,
    /// This machine refused the send before anything left it, for the reason
    /// carried, which the scan reports once it has drained.
    Refused(Refusal),
    /// The process had no socket to give the probe for as long as it would
    /// wait, which the scan reports once it has drained.
    Starved,
    /// Nothing was attempted: the scan stopped before the probe asked.
    Unmade,
}

/// Why this machine refused to send a probe, sorted the way the raw path sorts
/// a send it could not make: by whose fact it is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Refusal {
    /// No route leads to the address. A fact about the address as seen from
    /// here rather than a fault, and reported against the address.
    NoRoute,
    /// A route leads to the address and refuses it, in the words only a
    /// route's policy uses: a `prohibit` or `blackhole` route where Linux has
    /// them; see [`Egress::start_connect`]. Reported against the address as
    /// [`NoRoute`](Self::NoRoute) is, and named as refused by a route, since
    /// the remedy is this machine's routing table.
    Forbidden,
    /// The source port every probe is pinned to was held; see
    /// [`SourcePortHeld`]. Named apart from [`Local`](Self::Local) because
    /// the operating system's words for it name neither the port nor the
    /// wait, and those are what a reader acts on.
    PortHeld(u16, Holder),
    /// Anything else: no source to send from, no local port, a probe that met
    /// itself on every try. This machine's failure, in the operating system's
    /// own words, which is the part a reader asking why can act on.
    Local(String),
}

impl Refusal {
    /// The refusal `error` is, raised before anything left this machine.
    ///
    /// A route that refuses by its type, `prohibit` or `blackhole`, arrives
    /// as a host this machine cannot reach; see
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
/// Each is a port or address left unasked, which a resume asks again, and
/// each has a cause the report has to name: without it, a scan that could not
/// send reads as a network that did not answer.
#[derive(Debug, Default)]
struct Shortfall {
    /// Targets the process had no socket for.
    starved: u128,
    /// Ports identified in part, a later connection of theirs refused a
    /// socket.
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
            Attempt::Refused(Refusal::NoRoute) => {
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
    /// An address no route led to is filed against the address, the way the
    /// raw path files one, unless it answered something else, since an
    /// address that answered was reached and a report saying otherwise would
    /// contradict the ports it holds for it.
    ///
    /// Among those, an address on one of this host's own segments is named
    /// refused by a route where the routing table refuses it, asked as the raw
    /// path's plan asks it; see [`refuses_neighbour`]. A segment this host
    /// holds is reached by its connected route, so a refusal there is an
    /// override: a `prohibit` route is told by its words, but an `unreachable`
    /// one refuses in a missing route's, and only where the address sits
    /// says which it is. The segment's own network and broadcast addresses
    /// are left out, since the kernel refuses a connection to them on grounds
    /// of its own.
    fn report(self, ctx: &ScanContext, scanner: ScannerKind, unit: &str, units: &str) {
        // Read only where there is something to ask it about, which is rare.
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
        refuses: fn(IpAddr, &mut ProbeSockets) -> bool,
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
        let mut sockets = ProbeSockets::default();
        for address in self.unroutable {
            let reached = ctx
                .read_host(address, |host| host.status() == HostStatus::Up)
                .unwrap_or(false);
            if !reached {
                let mut overrides_segment = || {
                    segments.source_for(address).is_some()
                        && !segments.is_segment_edge(address)
                        && refuses(address, &mut sockets)
                };
                if self.forbidden.contains(&address) || overrides_segment() {
                    ctx.note_refused_by_route(address);
                }
                ctx.record_unroutable(address);
            }
        }
        // Filed, since those targets have no verdict, but warned in one short
        // line rather than announced as a scanner that failed: nothing broke.
        // The pinned port is still closing from the connection just made, or
        // another socket holds it, and the remedy is to wait or pin another.
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

    /// Identifies the open ports an earlier sitting of the job identified,
    /// whose responses ended with it. This scanner identifies each port it
    /// finds over the connection that found it, so a port that comes back
    /// settled is one no connection of this sitting reaches, and without this
    /// pass the detections would run over it with nothing to read.
    async fn detect_services(&mut self, ctx: &ScanContext) {
        crate::scanner::service::detect_inherited(ctx, self.detection, Protocol::Tcp).await;
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
        // of the targets it was handed. Closed first, for the reason it is
        // there.
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
/// This is the primary scanning strategy for callers without root privileges. It
/// consumes the randomized stream of targets a
/// [`Dispatcher`](crate::scanner::dispatcher::Dispatcher) produces, holding the
/// number of ports in flight at or below `concurrency_limit` and each
/// connection within the process's descriptor budget, and records every port it
/// probed into the shared
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
    let mut shortfall = Shortfall::default();
    // Each port is identified over the connection that finds it open, a host's
    // ports side by side, so a host answering them in turn is seen for that;
    // see [`Crowd`](crate::scanner::service::Crowd).
    let crowds = crate::scanner::service::Crowds::default();
    let tarpits = crate::scanner::service::Tarpits::default();
    let slow = SlowPaths::default();
    let mut pool = ProbePool::new(
        concurrency_limit,
        ctx.clone(),
        ScannerKind::Connect,
        |probed: ProbedPort, audit: &mut ProbeAudit| {
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
    };

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
        let patience = connect_patience(measured_path(&ctx, target.ip()));
        pool.admit(asking.port(target, patience)).await;
    }

    // Anything still queued was never sent, and carries no position to settle.
    // Closed first: the probes still in flight are waited out below with the
    // receiver alive, and a router handing over a target meanwhile would put
    // it in a queue nothing reads, to be dropped with it. Closed, the router
    // finds this scanner gone and records the target unasked itself.
    rx.close();
    while let Ok(target) = rx.try_recv() {
        record_unasked(&ctx, &target);
    }

    // Every target dispatched; wait out the probes still in flight, then the
    // second askings they left owed.
    pool.drain().await;
    slow.ask_again(&asking, &mut pool).await;
    let audit = pool.into_audit();
    // Identification runs inside this walk rather than as a pass after it, so
    // a stop that came while it ran ended the identifications in flight and
    // left every port it had not reached unidentified. Named as the pass it
    // cut where the scan identifies what it finds and found something open.
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
    // Under the identification pass rather than this strategy: every port of
    // the host has its verdict, and only what runs behind some of them went
    // unasked, which is what a reader is told the raw path's own pass left.
    tarpits.report(&ctx, ScannerKind::Service);
    shortfall.report(&ctx, ScannerKind::Connect, "port", "ports");
    finish(&ctx, audit, ScannerKind::Connect, probes, reason);
    Ok(())
}

/// How long a connect across `path` waits for its answer, or to a host
/// nothing has measured where `path` allows nothing.
///
/// [`CONNECT_PROBE_TIMEOUT`] where that covers the path, which is every path
/// whose round trip is under a sixth of a second measured once, or two fifths
/// measured steadily, so an ordinary scan waits what it always waits. On a longer one the wait is set as that timeout is:
/// the host stack's SYN retransmission and then its answer across the path,
/// with the headroom the host's measured round trips earn (see
/// [`PathAllowance`]). A wait sized for a path that costs nothing gives up on
/// every answer that crosses a slow one, and an open port reads filtered.
fn connect_patience(path: PathAllowance) -> Duration {
    path.over(HOST_SYN_RETRANSMIT).max(CONNECT_PROBE_TIMEOUT)
}

/// What the path to `ip` adds to every wait on it, as the scan has measured
/// it so far, or nothing where it has measured nothing.
fn measured_path(ctx: &ScanContext, ip: IpAddr) -> PathAllowance {
    ctx.read_host(ip, |host| {
        PathAllowance::of_round_trips(host.telemetry().round_trips())
    })
    .unwrap_or(PathAllowance::NONE)
}

/// What a connect port scan asks each port with, so a second asking asks it
/// as the first did.
struct Asking<'a> {
    ctx: &'a ScanContext,
    detection: ServiceDetection,
    shaping: Shaping,
    zones: &'a ZoneMap,
    crowds: &'a crate::scanner::service::Crowds,
    tarpits: &'a crate::scanner::service::Tarpits,
}

impl Asking<'_> {
    /// The probe of `target`, its connect waiting `patience`.
    fn port(
        &self,
        target: PlannedTarget,
        patience: Duration,
    ) -> impl Future<Output = ProbedPort> + Send + 'static {
        let ctx = self.ctx;
        let endpoint = self.zones.endpoint(target.ip(), target.port());
        let egress = ctx.egress_toward(target.ip());
        // Identified over the connection that finds the port open, so the
        // port's own cap applies here rather than in a pass of its own.
        let identify = ctx.service_detection_on(self.detection, target.port(), target.protocol());
        // A host that answers on every port has only its likeliest identified;
        // see `Tarpits`. It is known for one once it has answered on enough,
        // or said nothing on enough of the ports identified so far.
        let crowd = self.crowds.of(target.ip(), ctx.target_name(target.ip()));
        let identify = match ctx.read_host(target.ip(), |host| {
            self.tarpits
                .identifies(host, Some(&crowd), target.port(), target.protocol())
        }) {
            Some(false) => ServiceDetection::Off,
            _ => identify,
        };
        port_prober(
            target,
            identify,
            self.shaping,
            egress,
            endpoint,
            patience,
            ctx.clone(),
            crowd,
        )
    }

    /// [`port`](Self::port), asked a second time: what it draws revises the
    /// port's record and settles nothing, since the first asking settled it.
    ///
    /// One that drew no verdict, cut short by the stop or refused by this
    /// machine, revises nothing either: the first asking's verdict stands
    /// rather than giving way to an unasked port. Its send is still counted.
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

/// A port whose connect heard nothing, and how long it waited.
#[derive(Debug, Clone, Copy)]
struct Silence {
    target: PlannedTarget,
    waited: Duration,
}

/// The ports a connect port scan filed filtered on a wait the path to their
/// host needs more than, and the second asking each is owed.
///
/// A connect's wait is sized from the path its host was measured on when the
/// port was asked, and a port asked before anything was measured waits as on
/// an ordinary path. Across a path slower than that the wait gives up on
/// every answer, and the port is filed filtered for being far away. Two cases
/// reach here once the scan's first askings are all done.
///
/// A host measured since, by a port of its that answered, has each port that
/// waited less than the measured path needs asked again with that wait; see
/// [`connect_patience`]. On an ordinary path that is no port at all, since
/// the measured path needs no more than the ordinary wait.
///
/// A host that answered nothing has no measurement to go on, and may be a
/// host whose every port is filtered or one whose every answer was given up
/// on. One of its ports, the one likeliest to be listening, is asked again
/// with [`PATH_FINDING_TIMEOUT`]. If it answers, the host is measured and the
/// rest follow as above; if it stays silent, the host is as silent as the
/// wait for the longest path a connect looks for can show, and costs one
/// connect more to know it. Nothing else is asked twice, so a filtered host
/// costs one connect and a slow one the ports it was owed.
#[derive(Debug, Default)]
struct SlowPaths {
    silent: std::sync::Mutex<std::collections::HashMap<IpAddr, Vec<Silence>>>,
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

    /// Asks again, through `pool`, every port owed a second asking, finding
    /// the path to each host that answered nothing first; see [`SlowPaths`].
    ///
    /// A scan told to stop asks nothing more, and a host past its own budget
    /// is left as it is.
    async fn ask_again<F>(&self, asking: &Asking<'_>, pool: &mut ProbePool<ProbedPort, F>)
    where
        F: FnMut(ProbedPort, &mut ProbeAudit),
    {
        let ctx = asking.ctx;
        let owed = self.take();
        let open = |ip: &IpAddr| ctx.handle.stopped().is_none() && !ctx.host_expired(*ip);

        let mut finders = std::collections::HashSet::new();
        for (ip, ports) in &owed {
            if !open(ip) || measured_path(ctx, *ip) != PathAllowance::NONE {
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

        // What the second askings heard nothing on waited as long as the path
        // needs, so nothing is owed again.
        self.take();
        if asked > 0 {
            info!(
                verbosity = 1,
                "{} asked again, waiting for a slower path",
                counted(asked, "filtered port", "filtered ports")
            );
        }
    }
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
/// that could not ask is also counted into `shortfall`, which the scan reports
/// once it has drained.
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
        // A connect probe carries no attempt token: the retransmission that may
        // have produced this answer was the host stack's, on its own schedule
        // (see `CONNECT_PROBE_TIMEOUT`), so which attempt was answered is
        // not knowable from here.
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
                StatusReason::new(
                    StatusProtocol::TcpConnect,
                    "tcp connect answered by the host",
                ),
            );
        }
        // The handshake's round trip, which is the host's as much as the
        // liveness pass's own connect is: a scan that ran no such pass has no
        // other on this path.
        if let Some(rtt) = probed.rtt {
            host.add_rtt_from(rtt, StatusProtocol::TcpConnect);
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
/// back an outcome, but the outcome names what came back: a completed
/// connection is a SYN/ACK, a timeout is silence, an unreachable is an ICMP
/// error, and a refusal is one of two packets the kernel reports alike, a RST
/// or an ICMP port unreachable, and is named as a refusal for that reason.
/// Recorded so an unprivileged report can say what its verdicts rest on,
/// which is the one thing separating a port a firewall dropped from a port
/// nothing was listening on.
///
/// `None` where no packet is implied: a local failure, no route, no socket
/// left, is this host giving up, and crediting the target with a silence it was
/// never asked for would be evidence of the wrong thing.
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

/// Which packet settled a UDP port the connected socket reported on, in the
/// vocabulary the raw scanner records the same verdicts in.
///
/// A reply read off the socket is the port's own answer. A refusal is an ICMP
/// port unreachable, since nothing else refuses a datagram, and any other error
/// the kernel matched to the socket is an ICMP error too. Its sender is not
/// surfaced here, so where the raw scanner names a prohibition from the host
/// itself apart from one from the path, this names both as unreachable.
///
/// `None` for `OpenFiltered`, silence being the protocol's ordinary outcome
/// rather than a packet, as the raw scanner records it, and for a port no
/// datagram was sent to.
fn udp_evidence(state: PortState) -> Option<ScanResponse> {
    match state {
        PortState::Open => Some(ScanResponse::UdpResponse),
        PortState::Closed | PortState::Filtered => Some(ScanResponse::IcmpUnreachable),
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

/// Probes a single [`PlannedTarget`] over a full TCP connect handshake and
/// classifies its port. Returns `None` only for a target this strategy doesn't
/// handle.
///
/// An accepted connection is `Open` and gets fingerprinted over the live stream,
/// a refusal is `Closed`, and an ICMP error or a timeout is `Filtered`. A
/// connect this machine refused before anything left it is `Unasked`; see
/// [`Handshake`] for how each is told from the others. Only TCP is supported,
/// so UDP targets are skipped.
///
/// A connect that met itself asked nothing, and is made again from a fresh
/// socket, up to [`SELF_MEETINGS`] times.
///
/// The connection, and every one the fingerprint makes after it, leaves by
/// `egress`. Its socket comes from the process's budget and is held until the
/// fingerprint is done with it; a port the process has no socket for, or that
/// the scan stopped before asking, is `Unasked` too.
///
/// The handshake is given `patience` to be answered, which the scan sizes
/// from the path to the host; see [`connect_patience`]. An open port is
/// identified in its host's `crowd`, every wait on it allowing for the path
/// as the host's round trips show it once its own handshake is among them:
/// the handshake is filed with its host in `ctx` before the identification
/// begins, see [`note_handshake`], and the path read back from the host.
#[allow(clippy::too_many_arguments)]
async fn port_prober(
    planned: PlannedTarget,
    detection: ServiceDetection,
    shaping: Shaping,
    egress: Egress,
    socket_addr: SocketAddr,
    patience: Duration,
    ctx: ScanContext,
    crowd: std::sync::Arc<crate::scanner::service::Crowd>,
) -> ProbedPort {
    let handle = &ctx.handle;
    let target = planned.target;
    if target.protocol == Protocol::Udp {
        // UDP can't be probed through a TCP stream; skip rather than misreport.
        // No outcome: unreported is re-probed, which is what a routing mistake
        // deserves.
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
            settles: true,
        })
    };

    let mut met_itself = None;
    for _ in 0..SELF_MEETINGS {
        let (handshake, rtt, descriptor) = match dial(handle, descriptors::PATIENCE, || {
            std::future::ready(egress.start_connect(socket_addr, shaping))
        })
        .await
        {
            Dialled::Ran {
                result: Ok(connecting),
                began,
                descriptor,
            } => {
                // The SYN left, so a stop that cuts the wait leaves a port
                // asked with no verdict, as the raw path files a probe whose
                // schedule the stop cut: unasked, and asked again by a resume.
                let Some(finished) = handshake(connecting, patience, handle).await else {
                    return unasked(Outcome::Interrupted, Attempt::Sent);
                };
                // Read before the fingerprint talks to the port, which is the
                // service's time rather than the path's.
                (Handshake::sent(finished), began.elapsed(), Some(descriptor))
            }
            Dialled::Ran {
                result: Err(e),
                began,
                ..
            } => (Handshake::unsent(e), began.elapsed(), None),
            // Not a local failure: the scan ended first, as for a target still
            // queued (see `record_unasked`).
            Dialled::Stopped => return unasked(Outcome::Unasked, Attempt::Unmade),
            Dialled::Starved => return unasked(Outcome::Unroutable, Attempt::Starved),
        };

        return match handshake {
            Handshake::Accepted(stream) => {
                let port = settled(target.port, PortState::Open, Some(ScanResponse::TcpSynAck));
                // The detailed form, for the second and third values. This
                // handshake is the only conversation an unprivileged scan has
                // with the port, so what it draws here is everything any later
                // phase can read without dialling again: the responses a
                // passive detection needs, and what the same bytes said about
                // the machine. The descriptor is held until it is done.
                // Filed with the host at once rather than with the verdict,
                // which the identification holds for as long as the port
                // takes to answer it, seconds on a port that says nothing:
                // every other port of the host asked meanwhile sizes its
                // wait from this, and across a path slower than an ordinary
                // wait covers, a port that waits as on an ordinary path
                // gives up on its answer and reads filtered.
                note_handshake(&ctx, target.ip, rtt);
                // The handshake is a round trip over the very path the
                // conversation that follows takes, measured a moment ago,
                // and the latest of those the scan has taken. Read back from
                // the host rather than added to what it held before, so an
                // upper bound it held, a neighbour's first answer, gives way
                // to the handshake as it does wherever else the path is read.
                let path = measured_path(&ctx, target.ip);
                // Raced against the stop, because the identification is the
                // one wait here no loop reads it between: on a port that
                // accepts and says nothing it runs the better part of half a
                // minute, and a stopped scan would wait out every one in
                // flight. One cut short keeps the verdict the handshake
                // earned, an open port with its registered name, and draws
                // nothing further.
                let identified = handle
                    .or_stopped(crowd.identify(
                        target.ip.into(),
                        stream,
                        port,
                        detection,
                        egress,
                        path,
                    ))
                    .await;
                drop(descriptor);
                // The round trip is filed already, and a second sample of the
                // same handshake would weigh it twice.
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
                    // A TCP handshake proves a service, and the service is the
                    // port's to name. No role is read from one.
                    role: None,
                    silence: None,
                    settles: true,
                })
            }
            // A refusal is the clearest verdict this scanner ever gets, and it
            // is filed as one, under the name of what it is: a refusal, which
            // the operating system hands back alike for a reset and for an
            // ICMP port unreachable. Most are resets, a stack with nothing
            // listening, and the port is read closed. A filter rejecting with
            // a port unreachable reads closed here too, where the raw path,
            // which sees the packet, reads it filtered; no error code on any
            // platform separates the two, so the reason recorded says what
            // the verdict rests on rather than naming a reset nobody saw.
            //
            // Recorded rather than dropped because a port list that changes
            // with the caller's privilege level is not a smaller answer, it is
            // a different one: omitting it would leave an unprivileged report
            // with no `Closed` entry in its `ports_by_state` however many
            // refusals it collected, which somebody diffing two scans would
            // read as a change in the network.
            Handshake::Refused => verdict(
                PortState::Closed,
                Some(ScanResponse::ConnectionRefused),
                true,
                Some(rtt),
                Outcome::Answered { position },
            ),
            // Something on the way refused the connection with an ICMP error:
            // a firewall's reject, a router with no way on. The raw path reads
            // the same packet as filtered, and so does this one. Settled,
            // because it is an answer; the host is not credited, because the
            // error's sender is not surfaced and is as often a router as the
            // target, and neither is its round trip.
            Handshake::Unreachable => verdict(
                PortState::Filtered,
                Some(ScanResponse::IcmpUnreachable),
                false,
                None,
                Outcome::Answered { position },
            ),
            // Silence: the probe was dropped, the classic firewall signature.
            // Settled, because a connect gets one attempt and this was it.
            // Noted with the wait it was given, which a path measured longer
            // later in the scan may show to have been too short; see
            // `SlowPaths`.
            Handshake::Silent => verdict(
                PortState::Filtered,
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
                met_itself = Some(e);
                continue;
            }
            // This machine refused the connect before anything left it, so
            // nothing was asked and the host has proved nothing. The next
            // sitting may well get further.
            //
            // No evidence recorded, since there is no packet to name, and no
            // verdict either: filing `Filtered` would credit the target with a
            // silence it was never asked for in the one field a reader takes
            // for a finding.
            Handshake::NotSent(e) => {
                unasked(Outcome::Unroutable, Attempt::Refused(Refusal::of(&e)))
            }
            // The SYN left and the connect failed in a way that names no
            // packet. It was asked, so the send counts, and it has no verdict,
            // so a resume asks again.
            Handshake::Failed(e) => {
                error!(
                    verbosity = 2,
                    "connect to {socket_addr} failed after sending: {e}"
                );
                unasked(Outcome::Unroutable, Attempt::Sent)
            }
        };
    }

    // Met itself every time, which only a pinned source port equal to the
    // target's, on this machine's own address, can do.
    let why = met_itself.map_or_else(String::new, |e| e.to_string());
    unasked(Outcome::Unroutable, Attempt::Refused(Refusal::Local(why)))
}

/// How many times a connect probe is made before a connect that keeps
/// meeting itself is given up.
///
/// A connect meets itself when the kernel draws the target's own port as its
/// source, which a fresh socket draws again with odds of about one in the
/// size of the ephemeral range. Three is room for that and for nothing else:
/// a probe that met itself three times is one pinned to the port it asks
/// about, which no retry changes.
const SELF_MEETINGS: usize = 3;

/// What one connect probe's handshake came to, read for what it says about
/// the port.
///
/// The operating system hands a connect back as an error code and nothing
/// else, and the codes are shared between causes that mean different things:
/// `EHOSTUNREACH` is a missing route on this machine and a firewall's reject
/// on the far side. What separates them is when the code arrived, so a
/// connect is made in two halves (see
/// [`Egress::start_connect`](crate::transport::dial::Egress::start_connect)),
/// and a code from the first half is always [`NotSent`](Self::NotSent).
#[derive(Debug)]
enum Handshake {
    /// The handshake completed: a SYN/ACK.
    Accepted(TcpStream),
    /// The connection was refused: a reset, or an ICMP port unreachable,
    /// which every platform reports alike.
    Refused,
    /// An ICMP error other than a port unreachable ended the connect after its
    /// SYN left: an administrative prohibition, a host or network the path
    /// could not reach, a protocol the far end does not speak.
    ///
    /// Linux ends a connect at the first such error; macOS and the BSDs hold
    /// it as a soft error and keep retrying, so there the same packet ends in
    /// [`Silent`](Self::Silent), which is filed as the same state.
    Unreachable,
    /// Nothing came back within the connect's budget, or the stack gave up
    /// first, which is the same outcome, a SYN out and nothing back; the
    /// second can come first on Windows, where a probe keeps a single
    /// retransmission.
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
    /// Reads a connect's first half refused, before anything left this
    /// machine.
    ///
    /// A refusal stays a refusal whichever half reported it, since no stack
    /// invents one: over loopback the answer can arrive before the connect
    /// call returns.
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

/// Whether `error`, raised after a probe left, is an ICMP error other than a
/// port unreachable: a host or network the path could not reach, an
/// administrative prohibition, which Linux reports as a host it cannot reach,
/// and on Linux a protocol unreachable (`ENOPROTOOPT`) or an unknown or
/// isolated host (`EHOSTDOWN`, `ENONET`), which the standard library has no
/// kind for.
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

/// The second half of a connect, given `patience` to be answered, or `None`
/// where the scan stopped first.
///
/// The budget running out and the stack giving up first are the same outcome,
/// a SYN out and nothing back, so both come back as [`ErrorKind::TimedOut`].
/// Raced against the stop because the wait is the longest one a probe makes
/// with nothing between to read it: a port that drops its SYN holds its
/// probe the whole of `patience`, which across a slow path is many seconds,
/// and a stopped scan would otherwise wait out every one in flight.
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
/// UDP has no handshake to read a verdict from, so this leans on what the local
/// kernel reports about the datagram it sent. The socket is *connected*, which
/// is what makes that possible: a connected UDP socket has a known peer, so the
/// kernel can attribute an inbound ICMP error to it and surface it as
/// `ConnectionRefused` on a subsequent operation. An unconnected socket
/// discards the same error with nowhere to deliver it.
///
/// A reply is `Open`, a refusal is `Closed`, any other ICMP error the kernel
/// surfaces is `Filtered`, and silence is `OpenFiltered` - the verdicts the
/// raw scanner reaches, by a different route.
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
            port: Some(settled_over(
                Protocol::Udp,
                target.port,
                state,
                udp_evidence(state),
            )),
            // Nothing on this path turns a datagram into the text a detection
            // reads: the reply is read for the role and the names it declares
            // and no more.
            responses: Vec::new(),
            about_the_host: crate::fingerprint::AboutTheHost::default(),
            identified_in_part: false,
            answered,
            // A datagram's reply is the service's as much as the path's, so no
            // round trip is read from it.
            rtt: None,
            outcome,
            attempt,
            // Filled in by the one arm that has a reply to read it from.
            role: None,
            silence: None,
            settles: true,
        })
    };

    // Three ways this machine can fail before a datagram leaves it, below, and
    // each records the port unasked rather than dropping it. The target was
    // named by the plan, and a port that disappears from the host when the
    // scanner runs out of sockets is the shortfall a reader cannot see. The
    // outcome is `Unroutable` rather than `Unasked` for the reason the TCP
    // prober gives: this host gave up, which the next sitting may not.
    let refused = |e: &io::Error| Attempt::Refused(Refusal::of(e));
    let (socket, _descriptor) = match dial(&handle, descriptors::PATIENCE, || {
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
            return record(PortState::Unasked, false, Outcome::Unroutable, refused(&e));
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
        return record(PortState::Unasked, false, Outcome::Unroutable, refused(&e));
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
                record(PortState::Unasked, false, Outcome::Unroutable, refused(&e))
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
        // Any other ICMP error the kernel surfaced: an administrative
        // prohibition, which Linux reports on a connected socket as a host it
        // cannot reach, or a protocol unreachable. The raw path reads the same
        // packet as filtered, and so does this one.
        Ok(Err(e)) if is_unreachable(&e) => record(
            PortState::Filtered,
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
///
/// The same wait as [`descriptors::patiently`], every other connection's, in a
/// loop of its own because a sweep keeps thousands of these in flight: each
/// gives its descriptor back while it waits, so a queued probe can use it, and
/// asks the scan's stop before it asks again.
async fn dial<T, F, Fut>(handle: &ScanHandle, patience: Duration, mut attempt: F) -> Dialled<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut refused_since: Option<Instant> = None;
    let mut pause = descriptors::FIRST_PAUSE;
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
                pause = (pause * 2).min(descriptors::LONGEST_PAUSE);
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

/// Files the targets a run left unasked because the process had no socket to
/// give them, once. `patience` is how long each waited, and `unasked` names
/// what was left, counted.
///
/// Filed, because it narrows the result: those targets have no verdict, and
/// a report that did not say why would read as a network that did not answer.
/// Filed [cut short](crate::report::ScannerFailure::is_cut_short) rather than
/// failed, and warned in one short line naming the limit rather than
/// announced as a scanner that failed, because nothing broke. The process
/// reached the file limit it was started under, the remedy is the caller's,
/// raising it, and a reader told the scanner failed looks for a fault in the
/// engine or the network that is not there.
fn report_starved(ctx: &ScanContext, scanner: ScannerKind, unasked: String, patience: Duration) {
    crate::warn!("{unasked} unasked ({})", descriptors::starved_briefly());
    ctx.file_cut_short(
        scanner,
        format!("{unasked} left unasked: {}", descriptors::starved(patience)),
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

/// Multi-port host discovery for unprivileged environments, asking the common
/// five ports: SSH (22), HTTP (80), HTTPS (443), SMB (445), and RDP (3389).
///
/// [`discover_on`] with [`SynPorts::common`], for a sweep that was asked about
/// no ports of its own.
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
/// `ports` is the set a routed SYN sweep asks, and for the same reason: a host
/// behind a filter that drops a connection attempt to anything it does not
/// serve answers on the ports it serves and nowhere else, so a port scan's
/// liveness pass passes [`SynPorts::for_scan`] and the host is asked about the
/// ports the scan is about to probe. Taking the one type both sweeps take is
/// what keeps an unprivileged run from finding fewer hosts than a privileged
/// one over the same ports. See [`SynPorts`] for which ports those are.
///
/// One task per address, not per port. Its ports are tried in turn, in the
/// order the set holds them, and the first TCP-layer answer ends the address,
/// so a host that answers on SSH costs one connect whatever the set's size. A
/// silent address costs a connect per port, the first waiting three seconds,
/// six for a neighbour, and each after it the [`CONNECT_PROBE_TIMEOUT`], so a
/// silent range takes up to nine timeouts an address where the common five
/// alone take six. The first waits longer because nothing has measured the
/// path to the address yet, and a host across a path slower than the ordinary
/// timeout covers is heard by that connect or by none; a neighbour's first
/// connect waits on its resolution too, since the kernel resolves a
/// neighbour's hardware address before the first SYN to it leaves. The socket
/// budget is the same either way: one descriptor per address in flight, held one connect at
/// a time, so a larger set lengthens a silent sweep and never widens it. A task
/// per port would spend the same descriptor-seconds on fewer addresses at a
/// time and answer no sooner.
///
/// That shape is also what lets a sweep be continued. An address is the unit a
/// journal counts, so its verdict has to be earned as a whole: answered, or
/// every port asked once and none of them answering. Interleaving the ports of
/// many addresses would give neither, because nothing would know when an
/// address was finished with.
///
/// Addresses are drawn from
/// [`dispatch_addresses`](crate::scanner::dispatcher::dispatch_addresses) to
/// spread load across the network instead of hammering one subnet at a time.
pub async fn discover_on(
    ips: IpSet,
    ctx: ScanContext,
    evasion: &EvasionProfile,
    ports: SynPorts,
) -> Result<(), StrategyError> {
    sweep(ips, ctx, evasion, ports, descriptors::PATIENCE).await
}

/// [`discover_on`], waiting at most `patience` for a socket the process has
/// none of before leaving an address unasked.
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
    // No more probes than the process has sockets for: past the budget a
    // probe would only queue at the gate, holding a task and nothing else.
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
            // Taken off the queue and never asked, so it counts with the rest
            // still waiting behind it.
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

    // Anything still queued was never asked, and carries no position to settle.
    while rx.try_recv().is_ok() {
        ctx.record_address_outcomes(Outcome::Unasked, 1);
    }

    // Every address dispatched; wait out the probes still in flight.
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
    /// This machine refused to send a probe, for the reason carried, so the
    /// address proved nothing and the next sitting may get further. No route
    /// leading to it is filed against the address, as the raw path files one;
    /// any other refusal is this machine's, and the sweep reports it once it
    /// has drained.
    Refused(Refusal),
    /// The process had no socket to give the probe, for longer than it was
    /// willing to wait, so the address was never asked. Unsettled for the same
    /// reason as [`Refused`](Self::Refused), and told apart from it because
    /// the cause is this process's file limit, which the scan reports.
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
/// An address starved of a socket is counted into `starved`, and one this
/// machine refused to send to into `shortfall`, both of which the sweep
/// reports once it has drained.
///
/// Except the network or broadcast address of one of this host's own
/// `segments`, which the kernel refuses a connection to as it refuses one no
/// route leads to. That refusal says the address is the segment's own rather
/// than a host's, and the address is settled with nothing there, as the frame
/// sweep's unanswered request to it is: filed unreachable, a sweep of a `/24`
/// names its broadcast address as one this machine cannot reach.
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
            // Nothing left this machine, so no send is counted either way.
            ctx.settle_address(probed.ip, Settled::Exhausted);
        }
        Fate::Answered(host) => {
            let ip = host.primary_ip();
            audit.record_send(true);
            // See `absorb_probe`: this path has no attempt to attribute the
            // answer to, so every host it finds is counted as unattributed.
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

/// Whether `ip` is a neighbour: an address on one of this host's `segments`,
/// or a link-local one, which is on a segment wherever it is.
fn is_neighbour(segments: &OnLinkTable, ip: IpAddr) -> bool {
    let link_local = matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local());
    link_local || segments.source_for(ip).is_some()
}

/// How long the first connect to an address waits, the one that finds the
/// path to it: [`NEIGHBOUR_PATH_FINDING_TIMEOUT`] for a `neighbour`, and
/// [`PATH_FINDING_TIMEOUT`] for any other.
///
/// A neighbour is resolved before the first SYN to it leaves, across the path
/// the handshake then crosses, and a wait sized for the handshake alone gives
/// up on a slow neighbour whose hardware address the kernel did not yet hold.
/// An address anywhere else has its next hop resolved already, or resolved
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
/// Returns as soon as one of them answers at the TCP layer: a completed
/// handshake, or a reset the kernel surfaced as a connection error. Anything
/// else is read as [`Knock::of`] reads it, and the next port is tried.
///
/// Each connect is made in the two halves the port scan makes it in (see
/// [`Handshake`]), because the operating system names a missing route here
/// and a filter's rejection on the far side with the same codes, and only
/// where the code surfaced tells them apart. No route leads to the address
/// from any of its ports, so the first refusal for that ends the probe and
/// the address is filed as one this host cannot reach.
///
/// The stop signal is checked between ports, not only between addresses.
/// One task covers up to eight connects, and a sweep that only looked once
/// per address would take eight timeouts to wind down rather than one. What has
/// been asked so far decides how the address is filed: cut off part way through
/// is not the same as asked and silent, and only the second is a verdict. So
/// does what was not: an address with a port this machine refused to send to
/// was not asked everything, and is left for the next sitting, with the
/// reason reported.
///
/// Every connect leaves by `egress`, on a socket from the process's budget,
/// and waits at most `patience` for one the process has none of.
///
/// The first connect to leave is how the path to the address is found, and
/// waits for the longest path a connect looks for, and for the address
/// resolution too where the address is a `neighbour`; see
/// [`path_finding_wait`]. Every one after it waits as on an ordinary path. An
/// answer to the first connect to a neighbour times the path and the
/// resolution together, and is kept as the upper bound it is; see
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
    // Whether a connect has left yet: only the first to a neighbour may have
    // waited on its resolution.
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
            // The descriptor is held until the attempt's socket is dropped,
            // at the end of this pass, so the budget counts every socket still
            // open.
            let (handshake, start, _descriptor) = match dial(&handle, patience, || {
                std::future::ready(egress.start_connect(addr, shaping))
            })
            .await
            {
                Dialled::Ran {
                    result: Ok(connecting),
                    began,
                    descriptor,
                } => {
                    // Asked, with no answer yet, where the stop cut the wait.
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
                    ..
                } => (Handshake::unsent(e), (began, false), None),
                Dialled::Stopped => return cut_short(asked),
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
            // Met itself every time, which only a pinned source port equal
            // to the one asked, on this machine's own address, can do.
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
    /// Something at the address answered at the TCP layer: a completed
    /// handshake, a refusal, or a reset. A refusal is almost always the
    /// target's own reset, as the port scan reads one.
    Answered,
    /// The SYN left and nothing that proves a host came back: silence, an
    /// ICMP error from a filter or a router on the way, whose sender this path
    /// cannot see, or a failure that names no packet.
    Asked,
    /// This machine refused the connect before anything left it.
    Refused(Refusal),
    /// The connect reached its own socket, which says nothing about the
    /// address; a fresh socket is given another source.
    MetItself(io::Error),
}

impl Knock {
    /// Reads `handshake` for what it says about the address rather than the
    /// port.
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

/// The record an address earns by answering, timed from `start`, when the
/// connect that was answered began: after any wait for a socket and any port
/// asked before it, so the round trip is that connect's alone, and an upper
/// bound on it where the connect was `resolving` its neighbour first.
fn answered(ip: IpAddr, start: Instant, resolving: bool) -> ProbedHost {
    let mut host = Host::new(ip);
    let rtt = start.elapsed();
    if resolving {
        host.add_first_to_neighbour_rtt_from(rtt, StatusProtocol::TcpConnect);
    } else {
        host.add_rtt_from(rtt, StatusProtocol::TcpConnect);
    }
    // Every outcome that reaches here required a segment from the target: a
    // completed handshake, or a reset the kernel surfaced as a connection error.
    // `Host::merge` keeps the stronger status, so this survives being folded
    // into an entry another strategy created first.
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

    /// A connect waits what it always waits on an ordinary path, and on a
    /// path nothing measured, and across a slow one long enough for the host
    /// stack's retransmitted SYN to be answered across it.
    ///
    /// The ordinary wait is what every scan pays per filtered port, so a
    /// measured path that is merely not free leaves it alone; the slow path's
    /// is what keeps an open port two seconds away from reading filtered.
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

    /// **A UDP port the connect path settles says what settled it, as the raw
    /// path's does.** A reply is the port's own answer and a refusal an ICMP
    /// port unreachable. Without the reason an unprivileged report's closed
    /// and open UDP ports rest on nothing a reader can see, and two scans of
    /// one network compare as different by privilege alone.
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
        let closed = closed_loopback_udp_port(ip).await;

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

    /// **What a NetBIOS name table calls the machine reaches the host on the
    /// connect path, masked where a report masks.** The raw path reads the
    /// same reply for the same names, so a scan without a raw socket records
    /// what one with it would.
    ///
    /// The responder answers on loopback at a port of its own, and the probe
    /// is addressed there while the target names 137, which is what decides
    /// how its reply is read.
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

    /// A TCP port that refuses a connect is a SYN out and a RST back, one round
    /// trip to the host, and the host is credited with it. Without it a scan
    /// that ran no liveness pass, the only other source of a round trip on this
    /// path, reports every host it found with none.
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

    /// A host the connect path reaches is credited to a handshake its own
    /// stack made, and not to a half-open SYN probe, both where a port scan
    /// found it and where a sweep did. The two answer the same question and
    /// differ in how visible they are: a completed connection reaches the
    /// service and its logs, a half-open probe does not, and a report
    /// naming a SYN probe for a connect tells a reader the target was asked
    /// more quietly than it was.
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

    /// What a round trip measured alone earns on a slow path is the wait a
    /// path nothing has measured is given, so a measurement never makes the
    /// scan more patient than ignorance did unless the round trip needs it.
    #[test]
    fn a_lone_sample_is_held_to_the_path_finding_wait() {
        assert_eq!(
            crate::transport::dial::UNMEASURED_PATH_WAIT,
            PATH_FINDING_TIMEOUT
        );
    }

    /// The connect that finds the path to a neighbour waits for the
    /// neighbour's resolution as well as its handshake, and one to any other
    /// address waits for the handshake alone. A link-local address is a
    /// neighbour on whichever segment its zone names.
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

    /// The answer to the first connect a sweep made to a neighbour is kept as
    /// an upper bound on the path, since the connect may have waited on the
    /// neighbour's resolution first, and a handshake timed after it is what
    /// the host's waits are sized from.
    ///
    /// Across a path of 1.9 s, a neighbour whose hardware address was not
    /// held answered that connect in 3.8 s, and kept as a round trip beside
    /// the true ones it made every wait of the port's identification three
    /// times what the path needs: the scan of one silent port took 59 s.
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
    /// On Linux, and on macOS over IPv6, a connect given its target's port as
    /// its source completes a handshake with itself, and a prober that took
    /// the completed connect for an answer filed a port nothing listened on
    /// as open and identified its service from its own questions. On macOS
    /// over IPv4 the kernel refuses it instead. Either way nothing was asked.
    ///
    /// Pinning the source port to the target's is what makes every attempt
    /// meet itself, so the prober's fresh tries meet itself too and the port
    /// ends unasked, with the reason reported, rather than with a verdict.
    #[tokio::test]
    async fn a_connect_that_reaches_itself_is_never_filed_as_an_open_port() {
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let port = {
                let reserved = std::net::TcpListener::bind((ip, 0)).expect("a free port");
                reserved.local_addr().expect("its address").port()
            };
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

    /// **A stop ends an identification in flight.** On a port that accepts
    /// and says nothing, a thorough identification asks every question it
    /// has, a connection each, and an unprivileged scan stopped with some of
    /// those in flight asked them all before it ended. The stop here arrives
    /// once the port has taken the first connection, and the probe has to
    /// make no other and keep the verdict the handshake earned.
    #[tokio::test]
    async fn a_stop_ends_an_identification_in_flight() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("a free port");
        let port = listener.local_addr().expect("its address").port();

        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let stopper = ctx.handle.clone();
        let (returned, mut probe_done) = tokio::sync::oneshot::channel::<()>();
        // Takes every connection and says nothing on any of them, and asks
        // for the stop once the first is in.
        let listening = tokio::spawn(async move {
            let mut held = Vec::new();
            let first = accept_from_this_process(&listener)
                .await
                .expect("the probe connects");
            held.push(first);
            stopper.abort();
            // Held open until the probe returns, so nothing ends its
            // identification but the stop.
            loop {
                tokio::select! {
                    accepted = accept_from_this_process(&listener) => {
                        held.push(accepted.expect("a connection"));
                    }
                    _ = &mut probe_done => break,
                }
            }
            // Whatever else the probe made before it returned is already
            // queued on the listener; this only has to take it.
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

    /// A loopback listener that drops every further SYN, and the connections
    /// that filled its queue, held for as long as it is.
    ///
    /// A listener never accepted from takes connections into its queue up to
    /// its backlog and then drops the SYNs that follow, as Linux and the BSDs
    /// do (Windows resets them instead): from outside, a port a firewall
    /// drops. A backlog of one, since
    /// macOS reads zero as its default; filled until a connect goes
    /// unanswered, so the next one is dropped whatever the stack's arithmetic
    /// on the backlog.
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

    /// **A stop ends a handshake in flight at once, and leaves its port
    /// unasked.**
    ///
    /// A connect to a port that drops its SYN waits its whole patience, which
    /// across a slow path is many seconds, and a stopped scan would wait out
    /// every one in flight before it ended. The SYN left and nothing came
    /// back yet, so the port has no verdict: filed filtered, a firewall would
    /// be reported that the probe never waited long enough to see.
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
        // Far longer than the wait below, so only the stop can end it there.
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

    /// A second asking the stop cuts short keeps the first asking's verdict.
    ///
    /// The first asking settled the port filtered, and the second is only a
    /// longer wait for the same answer. Cut short, it heard nothing yet, and
    /// filed unasked it would take back a verdict the scan earned.
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

        let (crowds, tarpits) = Default::default();
        let asking = Asking {
            ctx: &ctx,
            detection: ServiceDetection::Off,
            shaping: Shaping::default(),
            zones: &ZoneMap::new(),
            crowds: &crowds,
            tarpits: &tarpits,
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

    /// A handshake's round trip is the host's as soon as the handshake
    /// completes, while the port it opened is still being identified.
    ///
    /// Every other port of the host asked meanwhile sizes its wait from the
    /// host's measured path, and an identification on a port that says
    /// nothing runs for seconds. Filed only with the verdict, the round trip
    /// reached the host after its identification returned, and across a path
    /// slower than an ordinary wait covers every port asked in the meantime
    /// waited as on an ordinary path and read filtered.
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

    /// A route that refuses in its policy's words is told from one that is
    /// missing, so the address is named as refused by a route: Linux answers
    /// a `prohibit` route with permission denied and a `blackhole` route with
    /// an invalid argument, which the connect hands on inside a host it
    /// cannot reach, and a missing or `unreachable` route with the plain
    /// host or network unreachable.
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

    /// Where an error surfaced decides what it means: the same code before
    /// the SYN left is this machine's failure, and after it is an answer.
    ///
    /// `EHOSTUNREACH` is both a missing route here and a firewall's
    /// administrative prohibition on the far side, which Linux reports alike.
    /// Read as a local failure, a firewalled port is filed unasked and asked
    /// again on every resume; read as an answer, a port this machine could
    /// not reach would be filed filtered, a finding about a target nothing
    /// was sent to.
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

    /// A port this machine refused to send to is left unasked, and the report
    /// says why, in the operating system's words.
    ///
    /// Without the line, a scan whose every connect failed locally reads as
    /// one that asked and heard nothing: the ports are unasked, but nothing
    /// says the cause was here. The refusal is made by pinning connections to
    /// a source no interface holds, so the bind fails before anything is sent
    /// and the documentation address is never dialled.
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

    /// A port found open on a host that answers on every port is not asked
    /// what it runs unless it is one of the likeliest, where the same port on
    /// an ordinary host is, and the report says how many went unasked.
    ///
    /// Identified over the connection that finds it open, a port of such a
    /// host would each cost a conversation waited out to its end, which across
    /// the port range is hours spent on a host whose ports mean nothing. The
    /// host is marked for it once it has answered on enough ports, so here it
    /// is marked before the scan asks. A port it finds closed is no port
    /// left unidentified, though the scan decided about it before it knew.
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
            // And a port nothing listens on, which the scan decides about
            // before it finds it closed, and which is no open port left
            // unidentified.
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
            // Filed as fingerprinting left unfinished, as the raw path's pass
            // files it: this strategy gave every port its verdict.
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

    /// **A port asked again from a pinned source port inside the closing wait
    /// of the last connection to it is asked, or the report names the port.**
    /// The connection just made from that port to that port keeps its
    /// four-tuple for up to a minute after it ends, and macOS refuses the next
    /// connect with it, as Linux does beyond loopback. Filed with the system's
    /// "address in use" alone, the scan read as this machine failing for no
    /// reason the caller could act on.
    #[tokio::test]
    async fn a_pinned_source_port_still_closing_is_named_as_the_reason_a_port_went_unasked() {
        use tokio::io::AsyncReadExt;

        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let listener = tokio::net::TcpListener::bind((ip, 0)).await.expect("bind");
        let port = listener.local_addr().expect("bound").port();
        // Held until the scanner closes first, so the closing wait is its.
        tokio::spawn(async move {
            while let Ok(mut stream) = accept_from_this_process(&listener).await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 256];
                    while matches!(stream.read(&mut buf).await, Ok(read) if read > 0) {}
                });
            }
        });
        let pinned = std::net::TcpListener::bind((ip, 0))
            .and_then(|free| free.local_addr())
            .expect("a free port to pin")
            .port();
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

    /// **A pinned source port something still holds is a wait on this
    /// machine, said in one short warning rather than as a scanner that
    /// failed.** The ports it left unasked are still filed, since the result
    /// is narrower for them, but nothing broke: the connection just made from
    /// that port is closing, or another socket has it, and the remedy is to
    /// wait or pin another. A line saying the scanner failed sends a reader
    /// looking for a fault that is not there, and so does a report entry that
    /// does not say it was cut short.
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

    /// **Targets the process had no socket for are the file limit, said in
    /// one short warning naming it and filed as cut short, not as a scanner
    /// that failed.** Nothing broke: the process reached the limit it was
    /// started under, and the remedy is to raise it. The report still counts
    /// the targets, since they have no verdict.
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

    #[cfg(unix)]
    use crate::system::descriptors::testing::{
        exhaust as exhaust_descriptors, in_a_process_of_its_own,
    };

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

    /// **A liveness connect that reaches its own socket finds no host.** A
    /// connect given its target's port as its source completes a handshake
    /// with itself on Linux, and on macOS over IPv6, and a sweep that took
    /// the completed connect for an answer reported a host nothing proved was
    /// there. macOS refuses the same connect over IPv4, and a sweep that read
    /// the refusal as nothing at all left the address undecided with no reason
    /// given. Pinned to the port it asks, every attempt meets itself, so the
    /// address stays unsettled and the report says why.
    #[tokio::test]
    async fn a_sweep_connect_that_reaches_itself_finds_no_host_and_says_why() {
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let port = std::net::TcpListener::bind((ip, 0))
                .and_then(|free| free.local_addr())
                .expect("a free port")
                .port();
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

    /// What a liveness connect says about the address rests on where its
    /// error surfaced, as it does for a port.
    ///
    /// No route here is the address this machine cannot reach, filed against
    /// it. The same code after the SYN left is a router or a filter answering
    /// for the address, which asked it without proving a host. A refusal
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

    /// An address no route leads to is filed as one, against the address, and
    /// is not an address the sweep failed to decide.
    ///
    /// Filed as nothing, it was counted among the addresses without a
    /// verdict, the report called itself partial, and nothing said why.
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

    /// A neighbour refused a connect is named refused by a route where the
    /// routing table refuses it, since only an override of the segment's
    /// connected route can: an `unreachable` route refuses in the words a
    /// missing route uses, and only where the address sits tells them apart.
    /// An address off the segments, one the table does not refuse, and the
    /// segment's broadcast address are unreachable and no more.
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
        // Refuses the neighbour at .2, the broadcast address, and anything
        // off the segment, as a table with an `unreachable` route over .2
        // and no route off it does.
        shortfall.file(
            &ctx,
            ScannerKind::Connect,
            "address",
            "addresses",
            &segments,
            |target, _| target != IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
        );

        for ip in [address(2), address(3), address(255), routed] {
            assert!(ctx.is_unroutable(ip), "{ip} not filed unreachable");
        }
        let refused = ctx.take_refused_by_route();
        assert_eq!(refused, [address(2)]);
    }

    /// A segment's own addresses, which the kernel refuses a connection to as
    /// it refuses one no route leads to, are settled with no host there
    /// rather than filed unreachable, as the frame sweep's unanswered request
    /// settles them. A neighbour refused the same way is still unreachable.
    ///
    /// Filed unreachable, every sweep of a whole `/24` without raw sockets
    /// reported one address this machine cannot reach, and it was the
    /// segment's broadcast address.
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

    /// A sweep that never gets a socket says so: the address is left
    /// unsettled for a resume to ask, the send is counted as failed rather
    /// than made, and the report names the file limit as the reason, so a
    /// sweep that found nothing cannot be read as a network that answered
    /// nothing. It is filed as cut short, since the remedy is to raise the
    /// limit and there is no fault to look for.
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
