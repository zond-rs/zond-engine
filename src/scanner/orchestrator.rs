// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Assembling and running a whole scan
//!
//! What [`discover`](super::discover) and [`scan`](super::scan) do once they
//! have been called: read what this host can do, turn a plan into running
//! strategies, back the plan's intent with what actually opened, drive the port
//! scan, and wait for the hostname tail.
//!
//! Nothing here is public; the two entry points are its only callers. A consumer
//! who wants a different policy builds a [`plan`], edits it, and runs the steps
//! they want, the second of the three altitudes the [`scanner`](super) module
//! documents.
//!
//! A plan says what should run; only the attempt discovers what could.
//! [`ensure_coverage`] is the seam: it backs the plan's intent with the sockets
//! that actually opened, so no protocol is left without a strategy and silently
//! unscanned.

use crate::model::host::OsEvidence;
use crate::system::privilege::{self, Privilege};
use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use crate::config::DetectionEnvelope;
use crate::config::limits::CONNECT_CONCURRENCY;
use crate::config::{OsDetection, ProbeTuning, ServiceDetection, ZondConfig};
use crate::evasion::EvasionProfile;
use crate::fingerprint::os;
use crate::journal::cursor::Checkpoint;
use crate::logging::error;
use crate::model::ip::range::{IpRange, Ipv4Range, Ipv6Range};
use crate::model::ip::scoped::{Zone, ZoneMap};
use crate::model::{
    ip::set::IpSet,
    port::{Discovery as PortDiscovery, PortSet, PortState, Protocol, ScanResponse},
    target::{PlannedTarget, TargetIndex, TargetMap, TargetSet},
    technique::{SctpScanTechnique, TcpScanTechnique},
};
use crate::report::{Pass, ScannerKind, TargetScope};
use crate::scanner::pool::ProbePool;
use crate::scanner::rdns::HostnameResolver;
use crate::scanner::session::{ScanContext, Stage};
use crate::scanner::strategy::composite::Reach;
use crate::scanner::strategy::{HostScanner, PortScanner, StrategyError};
use crate::scanner::{plan, rdns, strategy};
use crate::system::interface;
use crate::transport::probe::SendMode;
use crate::{counted, info, success, warn};

/// The targets an unprivileged sweep can actually walk, refusing the rest.
///
/// The privileged path gets this from [`plan::DiscoveryPlan::build`]. The
/// unprivileged path has no plan and hands the set to `connect`, which would walk
/// a `/64` until the process is killed, so the same rule and constant apply here.
///
/// Filtered per range, so a set holding a `/64` and three literal addresses keeps
/// the three.
///
/// IPv4 is untouched: every IPv4 range is finite, and whether a `/8` is reasonable
/// is the caller's judgement.
pub(super) fn walkable(targets: IpSet, ctx: &ScanContext) -> IpSet {
    let refused: Vec<_> = targets
        .v6()
        .iter()
        .filter(|range| !interface::is_enumerable(range))
        .copied()
        .collect();

    if refused.is_empty() {
        return targets;
    }

    let mut kept = IpSet::new();
    for range in targets.v4() {
        kept.push_v4_range(*range);
    }
    for range in targets.v6() {
        if interface::is_enumerable(range) {
            kept.push_v6_range(*range);
        }
    }
    kept.canonicalize();

    for range in &refused {
        ctx.record_refusal(plan::RefusedStep::unprivileged_range_not_enumerable(range).into());
    }

    kept
}

/// The environment-derived facts that steer how a scan runs.
///
/// Whether the process can open raw sockets and whether it should resolve
/// hostnames, answered once so [`scan`](crate::scanner::scan) and
/// [`discover`](crate::scanner::discover) branch on the same facts.
#[derive(Clone, Copy)]
pub(super) struct ScanCapabilities {
    /// Which sockets every phase of this scan runs with. At
    /// [`Privilege::Connect`] each falls back to ordinary TCP connect attempts.
    pub(super) privilege: Privilege,
    /// Whether this scan's raw strategies put frames on the wire with nothing
    /// behind them, so that what a frame cannot reach needs another strategy.
    ///
    /// True for an unprivileged run on macOS holding the BPF devices, and for
    /// every privileged run on Windows, whose default send mode is frames alone.
    /// Such a run reaches loopback, this host's own addresses, anything routed
    /// through a tunnel and, for its port probes, an IPv6 neighbour by connect.
    /// See [`interface::beyond_frames`].
    ///
    /// False where the caller chose the link layer, by naming the send mode or
    /// by an evasion only a frame can carry. A connect honours neither choice, so
    /// what the frames miss is left unanswered.
    pub(super) frames_only: bool,
    /// Whether hostname resolution is enabled, the inverse of `cfg.no_dns`.
    dns: bool,
}

impl ScanCapabilities {
    /// Reads the runtime capabilities from the environment and config, and
    /// announces the scanning mode they imply, once.
    ///
    /// `probing` is what the run sends beyond its liveness probes, which the
    /// announcement names; `None` for a sitting an earlier one left nothing to
    /// ask, which announces nothing. `targets` is what it will probe, asked of
    /// `sender`'s frames: a frames-only run asks what no frame reaches by connect,
    /// and where that is every target, connect is the route announced.
    ///
    /// A run that sends no DNS says so at detail level: its hostnames come from
    /// the hosts file alone.
    pub(super) fn resolve(
        cfg: &ZondConfig,
        probing: Option<Probing>,
        targets: &IpSet,
        sender: interface::FrameSender,
    ) -> Self {
        let privilege = Privilege::current();
        let mode = cfg.evasion.effective_send_mode(cfg.send_mode);
        let frames_only =
            privilege.is_raw() && mode == SendMode::Auto && !mode.reaches_past_frames();

        let caps = Self {
            privilege,
            frames_only,
            dns: !cfg.no_dns,
        };
        if !caps.dns {
            info!(
                verbosity = 1,
                "hostnames from the hosts file only (DNS off)"
            );
        }
        if let Some(probing) = probing {
            let beyond = caps.beyond_frames(targets, &cfg.send_source, sender);
            let unframed = beyond.targets.len() == targets.len() && !beyond.is_empty();
            let reasons = unframed.then(|| beyond.reasons());
            caps.announce(
                probing,
                by_raw_socket(mode, privilege::can_send_raw()),
                reasons.as_deref(),
            );
        }
        caps
    }

    /// Says what the privilege this run holds lets it probe with.
    ///
    /// `raw_sockets` is which of the two routes to raw probing carries the
    /// probes; see [`by_raw_socket`]. `unframed` is why no frame reaches any
    /// target, where none does; the run then probes by connect alone, and the
    /// line says so.
    ///
    /// Without raw sockets the line carries what root would add, in brackets.
    /// This is the only place a run says so.
    fn announce(self, probing: Probing, raw_sockets: bool, unframed: Option<&str>) {
        if let (true, None, Some(why)) = (self.privilege.is_raw(), probing.zombie, unframed) {
            match probing.udp {
                true => success!("probing by TCP connect and plain UDP ({why})"),
                false => success!("probing by TCP connect ({why})"),
            }
        } else if self.privilege.is_raw() {
            let route = if raw_sockets {
                "raw sockets"
            } else {
                "link-layer frames"
            };
            match probing.zombie {
                Some(zombie) => success!("probing through zombie {zombie} ({route})"),
                None => success!("probing with {} ({route})", probing.raw_probes()),
            }
        } else if probing.zombie.is_some() {
            // Nothing: an idle scan without raw sockets is refused whole, and
            // the refusal says why.
        } else if probing.udp {
            // UDP needs no privilege, so the line names it too.
            warn!("no raw sockets: TCP by connect, plain UDP (sudo for SYN)");
        } else if probing.ports {
            warn!("no raw sockets: probing by TCP connect (sudo for SYN)");
        } else {
            warn!("no raw sockets: probing by TCP connect (sudo for ARP)");
        }
    }

    /// Which of `targets` this scan cannot reach with the packets it chose.
    ///
    /// Empty unless the raw strategies send frames alone; see
    /// [`frames_only`](Self::frames_only). `sender` is the frame builder the
    /// question is asked for, since a segment sweep resolves an IPv6 neighbour
    /// and the probe transport does not.
    pub(super) fn beyond_frames(
        self,
        targets: &IpSet,
        forced: &[IpAddr],
        sender: interface::FrameSender,
    ) -> interface::BeyondFrames {
        if !self.frames_only || targets.is_empty() {
            return interface::BeyondFrames::default();
        }
        interface::beyond_frames(targets.clone(), forced, sender)
    }
}

/// Whether a raw run's probes leave by raw socket or as frames it builds itself,
/// given its send mode and whether this process may open a raw socket.
///
/// This names the route the probes take, which can differ from the privilege
/// held either way. On macOS an unprivileged run gets the link layer alone. A root
/// run told to send its own frames, or any run on Windows, holds raw sockets but
/// sends no probe through one: it cannot reach a tunnel, or loopback except on
/// macOS, and a neighbour that never answers ARP is one it could not frame to.
fn by_raw_socket(mode: SendMode, raw_sockets: bool) -> bool {
    raw_sockets && mode.reaches_past_frames()
}

/// What a run probes its ports with, beside the ARP, ICMPv6 and SYN every
/// liveness pass and sweep sends: the part of its opening line the caller's
/// choices decide.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Probing {
    /// Whether the run probes ports, or only sweeps for hosts. Root adds ARP to a
    /// sweep and a SYN to a port scan.
    ports: bool,
    /// The zombie an idle scan probes through, which replaces every technique
    /// below: its probes are forged from that host and read through it.
    zombie: Option<IpAddr>,
    /// The technique its TCP ports are probed with, where it names one.
    tcp: Option<TcpScanTechnique>,
    /// Whether it names a UDP port.
    udp: bool,
    /// The technique its SCTP ports are probed with, where it names one.
    sctp: Option<SctpScanTechnique>,
}

impl Probing {
    /// A sweep's: it asks about addresses and never about ports.
    pub(super) fn sweep() -> Self {
        Self::default()
    }

    /// A port scan's: the protocols `map` names a port on, each with the
    /// technique `cfg` probes it with, or the zombie of an idle scan, which
    /// sends none of them.
    pub(super) fn ports(cfg: &ZondConfig, map: &TargetMap) -> Self {
        if let Some(idle) = &cfg.idle_scan {
            return Self {
                ports: true,
                zombie: Some(idle.zombie),
                ..Self::default()
            };
        }
        Self {
            ports: true,
            zombie: None,
            tcp: map.names(Protocol::Tcp).then_some(cfg.tcp_technique),
            udp: map.names(Protocol::Udp),
            sctp: map.names(Protocol::Sctp).then_some(cfg.sctp_technique),
        }
    }

    /// The probes a raw run sends, as its opening line lists them: `ARP,
    /// ICMPv6, SYN, FIN and UDP`.
    ///
    /// SYN is always among them, since the liveness probes to common ports
    /// are SYNs whichever technique the ports are probed with, and a SYN port
    /// scan is named once.
    fn raw_probes(self) -> String {
        let mut probes = vec!["ARP".to_owned(), "ICMPv6".to_owned(), "SYN".to_owned()];
        if let Some(tcp) = self.tcp
            && tcp != TcpScanTechnique::Syn
        {
            probes.push(tcp.name().to_uppercase());
        }
        if self.udp {
            probes.push("UDP".to_owned());
        }
        if let Some(sctp) = self.sctp {
            probes.push(format!("SCTP {}", sctp.name().to_uppercase()));
        }
        let last = probes.pop().expect("SYN is always listed");
        format!("{} and {last}", probes.join(", "))
    }
}

/// The hosts a pass that builds its own segments can reach, having recorded
/// once that it leaves the rest alone.
///
/// Every host, unless this scan's raw strategies send frames alone. Then hosts a
/// frame cannot reach are skipped, since these passes read what only a packet they
/// built can ask (a stack's answer to an unusual segment, the hops along a path, a
/// middlebox's reply to a bad checksum). One refusal says how many and why.
fn within_frames<T>(
    hosts: Vec<T>,
    address: impl Fn(&T) -> IpAddr,
    caps: ScanCapabilities,
    forced: &[IpAddr],
    ctx: &ScanContext,
    scanner: ScannerKind,
    pass: &str,
) -> Vec<T> {
    if !caps.frames_only || hosts.is_empty() {
        return hosts;
    }
    let mut addresses = IpSet::new();
    for host in &hosts {
        addresses.insert(address(host));
    }
    let beyond = caps.beyond_frames(&addresses, forced, interface::FrameSender::Probe);
    if beyond.is_empty() {
        return hosts;
    }
    ctx.record_refusal(
        plan::RefusedStep::pass_beyond_frames(scanner, pass, beyond.targets.len()).into(),
    );
    hosts
        .into_iter()
        .filter(|host| !beyond.targets.contains(&address(host)))
        .collect()
}

/// Records what a raw discovery `plan` reaches by connect, and names it, and
/// why, for a reader asking for detail.
///
/// Its connect step holds what no route leads to, loopback among it, whatever
/// the privilege, and `unframed`, what a frames-only run moved there. The
/// opening line names the route the raw probes take; these addresses are
/// asked by connect beside them.
pub(super) fn reached_by_connect(
    plan: &plan::DiscoveryPlan,
    unframed: interface::BeyondFrames,
    ctx: &ScanContext,
) {
    let Some(targets) = plan.steps().iter().find_map(|step| match step {
        plan::DiscoveryStep::Connect { targets, .. } => Some(targets),
        _ => None,
    }) else {
        return;
    };
    ctx.record_reached_by_connect(targets);
    announce_by_connect("sweep", &unframed.and_unmapped(targets));
}

/// Names the targets `phase` reaches by connect, and why, for a reader asking
/// for detail.
///
/// At detail level; the report's
/// [`reached_by_connect`](crate::report::ScanPhase::reached_by_connect) is the
/// record. One line, with one address named per reason.
fn announce_by_connect(phase: &str, beyond: &interface::BeyondFrames) {
    if beyond.is_empty() {
        return;
    }
    let reasons: Vec<String> = beyond
        .summary()
        .into_iter()
        .map(|(reason, first, count)| match count {
            1 => format!("{first} ({reason})"),
            more => format!("{first} +{} ({reason})", more - 1),
        })
        .collect();
    info!(verbosity = 1, "{phase} by connect: {}", reasons.join(", "));
}

/// The privileged host-identification phase, shared by
/// [`discover`](crate::scanner::discover) and [`scan`](crate::scanner::scan).
///
/// It spawns the strategies discovery uses: per-interface
/// [`LocalScanner`](strategy::local::LocalScanner)s (ARP and ICMPv6, yielding
/// MAC and RTT), a [`RoutedScanner`](strategy::routed::RoutedScanner) for
/// off-link targets (RTT), and the passive DNS and mDNS [`HostnameResolver`].
/// All of them write into the shared store. `discover` runs this alone, while
/// `scan` runs it alongside the port scan.
pub(super) struct Enrichment {
    scanners: Vec<(ScannerKind, JoinHandle<Result<(), StrategyError>>)>,
    resolver: Option<JoinHandle<Option<HostnameResolver>>>,
}

impl Enrichment {
    /// Spawns every enrichment strategy for `targets`. They begin running
    /// immediately and concurrently. Call [`Enrichment::finish`] to await them.
    pub(super) async fn spawn(
        plan: plan::DiscoveryPlan,
        ctx: &ScanContext,
        caps: ScanCapabilities,
        tuning: ProbeTuning,
    ) -> Self {
        let (dns_tx, resolver) = if caps.dns {
            // The crate's one unbounded queue. Its depth is the number of hosts,
            // each entry (17 bytes) accompanying a `Host` the store already holds
            // (480 bytes). The senders, `local::EnrichingScanner` and
            // `routed::SweepScanner`, post from synchronous reply handlers, where
            // a bounded channel would either drop hostnames on `try_send` or make
            // two hot paths async.
            let (tx, rx) = mpsc::unbounded_channel();
            (Some(tx), Some(spawn_resolver(rx, ctx.clone()).await))
        } else {
            (None, None)
        };

        let scanners = spawn_explorers(plan, ctx, dns_tx, tuning).await;
        Self { scanners, resolver }
    }

    /// Awaits every enrichment strategy, reports any that failed, then folds the
    /// resolver's collected hostnames and extra IPs into the store.
    async fn finish(self, ctx: &ScanContext) {
        for (kind, handle) in self.scanners {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => ctx.record_failure(kind, e.to_string()),
                Err(e) => ctx.record_failure(kind, format!("panicked: {e}")),
            }
        }

        if let Some(task) = self.resolver {
            match task.await {
                Ok(Some(mut resolver)) => resolver.resolve_hosts(ctx),
                // Filed where it failed to start.
                Ok(None) => {}
                Err(e) => ctx.record_failure(
                    ScannerKind::Resolver,
                    format!("panicked: {e} (hostnames lost)"),
                ),
            }
        }
    }
}

/// Records the targets that are this host's own addresses as up, without
/// probing them.
///
/// No strategy can establish one: the kernel routes traffic for an address this
/// host holds through loopback, so nothing on the link answers for it.
///
/// The evidence is the interface table, named as such since nothing was sent.
///
/// Each is also settled as answered. Otherwise a sweep counted in addresses would
/// leave this host's position unsettled, the watermark would stop behind it, and
/// every finished sweep of the scanner's own segment would read as resumable.
fn record_our_own_addresses(ours: &crate::model::ip::set::IpSet, ctx: &ScanContext) {
    let addresses: Vec<IpAddr> = ours.iter().collect();
    if addresses.is_empty() {
        return;
    }

    info!(
        verbosity = 2,
        "{} named is this host's own and is up without asking",
        counted(addresses.len() as u128, "address", "addresses")
    );

    for address in addresses {
        ctx.update_host(crate::model::ip::scoped::ScopedIp::from(address), |host| {
            host.record_evidence(
                crate::model::host::HostStatus::Up,
                crate::model::host::StatusReason::new(
                    crate::model::host::StatusProtocol::Custom("local-interface".into()),
                    "an address this host holds",
                ),
            );
        });
        ctx.settle_address(address, crate::journal::settle::Settled::Answered);
    }
}

/// Turns a [`DiscoveryPlan`](plan::DiscoveryPlan) into running tasks.
///
/// Every refusal the plan carries is recorded first. A step that cannot open what
/// it needs is recorded and skipped, and the rest proceed.
///
/// Each surviving strategy gets its own task, tagged with its [`ScannerKind`], so
/// the caller can wait on all of them and attribute failures.
pub(super) async fn spawn_explorers(
    plan: plan::DiscoveryPlan,
    ctx: &ScanContext,
    dns_tx: Option<UnboundedSender<IpAddr>>,
    tuning: ProbeTuning,
) -> Vec<(ScannerKind, JoinHandle<Result<(), StrategyError>>)> {
    for refusal in plan.refusals() {
        ctx.record_refusal(refusal.clone().into());
    }

    record_our_own_addresses(plan.ours(), ctx);

    let mut explorers: Vec<Box<dyn HostScanner>> = Vec::new();
    for step in plan.into_steps() {
        let kind = step.kind();
        info!(
            verbosity = 3,
            "spawning {kind:?} scanner for {}",
            counted(step.target_count(), "target", "targets")
        );
        match step.into_scanner(ctx.clone(), dns_tx.clone(), tuning.clone()) {
            Ok(scanner) => explorers.push(scanner),
            Err(e) => ctx.record_failure(kind, e.to_string()),
        }
    }

    explorers
        .into_iter()
        .map(|mut explorer| {
            // Read before the strategy moves into its task.
            let kind = explorer.kind();
            (
                kind,
                tokio::spawn(async move { explorer.discover_hosts().await }),
            )
        })
        .collect()
}

/// What a port phase's raw strategies can reach.
///
/// Every target, unless they send frames alone; see
/// [`ScanCapabilities::frames_only`].
pub(super) enum RawReach {
    /// Every target.
    Everything,
    /// Every target but these, which only the kernel can carry.
    AllBut(IpSet),
    /// No target: every one is out of a frame's reach. These are all of them.
    Nothing(IpSet),
}

impl RawReach {
    /// What a phase probing `probed` can reach with its raw strategies, when
    /// `beyond` is what a frame cannot.
    pub(super) fn of(probed: &IpSet, beyond: IpSet) -> Self {
        if beyond.is_empty() {
            return Self::Everything;
        }
        let mut within = probed.clone();
        within.subtract(&beyond);
        match within.is_empty() {
            true => Self::Nothing(beyond),
            false => Self::AllBut(beyond),
        }
    }

    /// The targets the raw strategies cannot reach, empty for
    /// [`Everything`](Self::Everything).
    fn beyond(&self) -> IpSet {
        match self {
            Self::Everything => IpSet::new(),
            Self::AllBut(beyond) | Self::Nothing(beyond) => beyond.clone(),
        }
    }
}

/// Turns a [`PortScanPlan`](plan::PortScanPlan) into the single strategy
/// [`run_port_scan`] drives.
///
/// Every refusal is recorded first, so a protocol nobody probed is distinguishable
/// from one with nothing open. A step that cannot open its socket is recorded and
/// dropped, and whatever built is wrapped in a
/// [`CompositePortScanner`](strategy::composite::CompositePortScanner), which
/// routes each target to a strategy that covers its protocol.
///
/// `raw` is what the raw strategies can reach. Where that is every target but
/// some, [`ensure_coverage`] finds strategies for the rest; where it is no target,
/// no raw strategy is opened.
///
/// `named` is the protocols the targets name a port on. A stand-in is found only
/// for those, since one for an unnamed protocol probes nothing but would still
/// mark addresses as reached by connect.
///
/// Every refusal, the plan's and the coverage check's, is handed to the composite
/// with its protocol and addresses, so the targets it leaves unprobed are counted
/// as refused, not lost.
pub(super) fn build_port_scanner(
    plan: plan::PortScanPlan,
    named: &[Protocol],
    ctx: &ScanContext,
    target_count: usize,
    tuning: ProbeTuning,
    zones: &ZoneMap,
    raw: &RawReach,
) -> BuiltPortScan {
    for refusal in plan.refusals() {
        ctx.record_refusal(refusal.clone().into());
    }

    let technique = plan.technique();
    // Read before the steps are consumed. A protocol the plan never intended to
    // cover was refused above and must not be refused again below.
    let intended: Vec<Protocol> = Protocol::ALL
        .iter()
        .copied()
        .filter(|protocol| plan.covers(*protocol) && named.contains(protocol))
        .collect();
    let mut refused: Vec<(Protocol, Reach)> = Protocol::ALL
        .iter()
        .copied()
        .filter(|protocol| plan.refuses(*protocol))
        .map(|protocol| (protocol, Reach::Any))
        .collect();

    let beyond = Arc::new(raw.beyond());
    let mut routes: Vec<(Box<dyn PortScanner>, Reach)> = Vec::new();
    for step in plan.into_steps() {
        // A raw strategy holds a capture on every interface for the whole scan,
        // and here it would be handed nothing. Left uncovered, the protocol gets
        // its unprivileged strategy below, for every address.
        if step.is_raw() && matches!(raw, RawReach::Nothing(_)) {
            continue;
        }
        match step.into_scanner(ctx.clone(), target_count, tuning.clone(), zones.clone()) {
            Ok(scanner) => {
                let reach = match step.is_raw() && !beyond.is_empty() {
                    true => Reach::Except(Arc::clone(&beyond)),
                    false => Reach::Any,
                };
                routes.push((scanner, reach));
            }
            Err(e) => ctx.record_failure(step.kind(), e.to_string()),
        }
    }

    let coverage = ensure_coverage(
        routes,
        ctx,
        technique,
        &intended,
        tuning.service_detection,
        &tuning.evasion,
        raw,
    );
    refused.extend(coverage.refused);

    BuiltPortScan {
        scanner: Box::new(
            strategy::composite::CompositePortScanner::with_reach(coverage.routes, ctx.clone())
                .refusing(refused),
        ),
        reached_by_connect: coverage.reached_by_connect,
    }
}

/// What a port phase probes with, and what it refused to.
pub(super) struct Coverage {
    /// Each strategy, with the addresses it is handed.
    pub(super) routes: Vec<(Box<dyn PortScanner>, Reach)>,
    /// Each protocol a refusal recorded here leaves unprobed, with the
    /// addresses the refusal covers.
    pub(super) refused: Vec<(Protocol, Reach)>,
    /// Whether a connect strategy stands in for a raw one on the addresses a
    /// frame cannot reach, which the phase records as reached by connect.
    pub(super) reached_by_connect: bool,
}

/// Backs the plan's intent with what actually opened: any protocol left without
/// a strategy gets the unprivileged one, or is refused.
///
/// A plan says a raw TCP scanner and a raw UDP scanner should run; only the
/// attempt discovers that a sandbox permitted one raw socket and not the other.
/// A protocol with no strategy would never be probed or reported, since
/// [`CompositePortScanner`](strategy::composite::CompositePortScanner) has nowhere
/// to route its targets.
///
/// A connect fallback substitutes only for a SYN scan. It cannot send a FIN, a
/// flagless segment or a bare ACK, so where the caller chose one of those and no
/// raw scanner opened, the TCP half is reported as a failure.
///
/// `intended` keeps this from repeating the plan: a protocol the plan never meant
/// to cover was already refused, in the words
/// [`plan::RefusedStep::technique_needs_raw_sockets`] supplies. This function
/// handles a protocol the plan did intend whose socket would not open.
///
/// A refusal made here comes back in [`Coverage::refused`] with its protocol and
/// addresses, so the router counts its targets as refused, not lost. See
/// [`refusing`](strategy::composite::CompositePortScanner::refusing).
///
/// ## The targets the raw strategies cannot reach
///
/// `raw` says what the raw strategies reach, every target unless they send frames
/// alone. Then they miss loopback, this host's own addresses, anything routed
/// through a tunnel, and IPv6 neighbours. For those addresses alone, a protocol
/// whose only strategies are raw gets its unprivileged one or is refused. What is
/// reached this way is recorded, since the phase's privilege reads as raw and the
/// evidence at these addresses is not.
///
/// A protocol with no strategy at all is handled once: its fallback reaches every
/// address and its refusal covers them all. The refusal distinguishes a process
/// with no raw socket from a frames-only one whose raw strategies were never opened
/// because no target was within a frame's reach; the second already holds the
/// privilege.
pub(super) fn ensure_coverage(
    mut routes: Vec<(Box<dyn PortScanner>, Reach)>,
    ctx: &ScanContext,
    technique: TcpScanTechnique,
    intended: &[Protocol],
    detection: ServiceDetection,
    evasion: &EvasionProfile,
    raw: &RawReach,
) -> Coverage {
    let beyond = &Arc::new(raw.beyond());
    // Whether the raw strategies were left unopened because every target is
    // beyond a frame's reach.
    let withheld = matches!(raw, RawReach::Nothing(_));
    let mut refused: Vec<(Protocol, Reach)> = Vec::new();
    let covered: Vec<Protocol> = routes
        .iter()
        .flat_map(|(scanner, _)| scanner.supported_protocols())
        .collect();
    // Covered only by raw routes, which miss `beyond`. Asked before anything is
    // added below, since a fallback reaching every address also covers these.
    let beyond_uncovered: Vec<Protocol> = match beyond.is_empty() {
        true => Vec::new(),
        false => covered
            .iter()
            .copied()
            .filter(|protocol| intended.contains(protocol))
            .filter(|protocol| {
                !routes.iter().any(|(scanner, reach)| {
                    !matches!(reach, Reach::Except(_))
                        && scanner.supported_protocols().contains(protocol)
                })
            })
            .collect(),
    };

    let missing = |protocol: Protocol| intended.contains(&protocol) && !covered.contains(&protocol);

    // Whether anything below stands in for a raw strategy.
    let mut connected = false;

    if missing(Protocol::Tcp) {
        if technique.has_connect_fallback() {
            routes.push((connect_tcp(ctx, detection, evasion), Reach::Any));
            connected = true;
        } else {
            let refusal = match withheld {
                true => plan::RefusedStep::technique_beyond_frames(technique, beyond.len()),
                false => plan::RefusedStep::technique_needs_raw_sockets(technique),
            };
            ctx.record_refusal(refusal.into());
            refused.push((Protocol::Tcp, Reach::Any));
        }
    }

    if missing(Protocol::Udp) {
        routes.push((connect_udp(ctx, detection, evasion), Reach::Any));
        connected = true;
    }

    // Nothing stands in for an INIT scan.
    if missing(Protocol::Sctp) {
        let refusal = match withheld {
            true => plan::RefusedStep::sctp_beyond_frames(beyond.len()),
            false => plan::RefusedStep::sctp_needs_raw_sockets(),
        };
        ctx.record_refusal(refusal.into());
        refused.push((Protocol::Sctp, Reach::Any));
    }

    let beyond_count = beyond.len();
    for protocol in beyond_uncovered {
        match protocol {
            Protocol::Tcp if technique.has_connect_fallback() => {
                routes.push((
                    connect_tcp(ctx, detection, evasion),
                    Reach::Only(Arc::clone(beyond)),
                ));
                connected = true;
            }
            Protocol::Tcp => {
                ctx.record_refusal(
                    plan::RefusedStep::technique_beyond_frames(technique, beyond_count).into(),
                );
                refused.push((Protocol::Tcp, Reach::Only(Arc::clone(beyond))));
            }
            Protocol::Udp => {
                routes.push((
                    connect_udp(ctx, detection, evasion),
                    Reach::Only(Arc::clone(beyond)),
                ));
                connected = true;
            }
            Protocol::Sctp => {
                ctx.record_refusal(plan::RefusedStep::sctp_beyond_frames(beyond_count).into());
                refused.push((Protocol::Sctp, Reach::Only(Arc::clone(beyond))));
            }
        }
    }
    let reached_by_connect = connected && !beyond.is_empty();
    if reached_by_connect {
        ctx.record_reached_by_connect(beyond);
    }

    Coverage {
        routes,
        refused,
        reached_by_connect,
    }
}

/// The unprivileged TCP strategy, as a stand-in for a raw one.
fn connect_tcp(
    ctx: &ScanContext,
    detection: ServiceDetection,
    evasion: &EvasionProfile,
) -> Box<dyn PortScanner> {
    Box::new(strategy::connect::ConnectPortScanner::new(
        ctx.clone(),
        crate::config::limits::CONNECT_CONCURRENCY,
        detection,
        evasion,
    ))
}

/// The unprivileged UDP strategy, as a stand-in for a raw one.
fn connect_udp(
    ctx: &ScanContext,
    detection: ServiceDetection,
    evasion: &EvasionProfile,
) -> Box<dyn PortScanner> {
    Box::new(strategy::connect::ConnectUdpPortScanner::with_detection(
        ctx.clone(),
        crate::config::limits::CONNECT_CONCURRENCY,
        evasion,
        detection,
    ))
}

/// A port-scan strategy, and what it says about the targets it reaches.
pub(super) struct BuiltPortScan {
    pub(super) scanner: Box<dyn PortScanner>,
    /// Whether a connect strategy stands in for a raw one on the targets a
    /// frame cannot reach.
    reached_by_connect: bool,
}

/// Whether the scan was asked to stop, or ran out of budget, before `pass`
/// began, recording the pass as cut by the stop where some host was owed it.
///
/// Every pass that sends anything asks this before announcing its stage, so a
/// stopped scan opens no sockets and sends nothing further. Passes that only read
/// the store, such as correlation, run regardless, since they contribute to the
/// partial report.
///
/// A pass is cut where a host is up and owed it; see
/// [`ScanPhase::passes_cut`](crate::report::ScanPhase::passes_cut). Asked before
/// the pass works out its targets, which for some passes files what it could not
/// reach, so a stopped scan is not charged with that.
fn stopped(ctx: &ScanContext, pass: Pass) -> bool {
    stopped_with(ctx, pass, || {
        ctx.hosts_owed_passes().into_iter().any(|key| {
            !ctx.host_expired(key.addr())
                && ctx
                    .read_host(&key, |host| host.status().is_up())
                    .unwrap_or(false)
        })
    })
}

/// [`stopped`], for a pass that knows more closely which hosts it is for:
/// `owed` says whether it had anything to ask.
fn stopped_with(ctx: &ScanContext, pass: Pass, owed: impl FnOnce() -> bool) -> bool {
    if !ctx.handle.should_stop() {
        return false;
    }
    if owed() {
        ctx.stopping_before(pass);
    }
    true
}

/// Drives one port-scan strategy to completion. It streams targets through the
/// strategy, and when the strategy succeeds, lets the strategy run its own
/// service-detection pass (a no-op for strategies that fingerprint inline) and
/// then the detections, each of which runs nothing once the scan is stopping.
///
/// A strategy failure is reported on the event stream, tagged with the
/// strategy's own [`ScannerKind`], and otherwise swallowed so the surrounding
/// scan (host enrichment and DNS) still finishes.
pub(super) async fn run_port_scan(
    mut scanner: Box<dyn PortScanner>,
    rx: mpsc::Receiver<PlannedTarget>,
    ctx: &ScanContext,
    service_detection: ServiceDetection,
    detection: DetectionEnvelope,
) {
    let kind = scanner.kind();
    match scanner.scan(rx).await {
        Ok(()) => {
            // Each pass checks the stop itself once it knows it has ports, so
            // the report names what the stop cut.
            scanner.detect_services(ctx).await;
            // Active detections over the services just identified, unless the
            // scan is stopping.
            super::detection::detect(ctx, service_detection, detection).await;
        }
        Err(e) => ctx.record_failure(kind, e.to_string()),
    }
}

/// Completes the hostname-resolution tail of a scan.
///
/// A privileged scan spawns passive DNS and mDNS resolution as part of its
/// [`Enrichment`]; awaiting that here folds the collected hostnames and extra
/// IPs into the store. A phase with no enrichment, which is every unprivileged
/// one and every port phase, falls back to active reverse lookups when DNS is
/// enabled. With DNS disabled, hosts are named from the hosts file alone.
///
/// `unheard` says whether the active lookups name hosts nothing was heard
/// from too, which only a port scan whose caller asked for every address as a
/// host does; see [`rdns::Unheard`].
pub(super) async fn finish_enrichment(
    enrichment: Option<Enrichment>,
    caps: ScanCapabilities,
    ctx: &ScanContext,
    unheard: rdns::Unheard,
) {
    match enrichment {
        Some(enrichment) => enrichment.finish(ctx).await,
        None if caps.dns => rdns::resolve(ctx, unheard).await,
        None => {}
    }
    if !caps.dns {
        rdns::name_from_hosts_file(ctx, unheard);
    }
}

/// Reads an operating system out of what the scan already knows, sending
/// nothing.
///
/// [`OsDetection::Passive`] for host discovery, which draws no segments to read a
/// stack from. It reads the hardware address's maker and a system-generated
/// hostname.
///
/// Runs after enrichment, because [`os::hostname_evidence`] reads a name that
/// arrives on the resolver's tail.
///
/// ## What it concludes
///
/// Each source alone is below the floor [`os::resolve`] reports at, so a sweep of
/// randomly-addressed phones concludes nothing. Two agreeing sources clear it: an
/// Apple address under a default `MacBook-Pro` name is a verdict.
pub(super) fn run_passive_os_identification(ctx: &ScanContext, os_detection: OsDetection) {
    // `Off` means record nothing about the stacks that answered, even though
    // this pass costs no packets.
    if matches!(os_detection, OsDetection::Off) {
        return;
    }

    let mut named = 0usize;
    for ip in ctx.hosts_owed_passes() {
        let mut identified = false;
        ctx.write_host(ip, |host| {
            identified = os::identify(host, []);
            identified
        });
        if identified {
            named += 1;
        }
    }

    if named > 0 {
        info!(
            verbosity = 1,
            "named {} from what the sweep already knew",
            counted(named as u128, "host", "hosts")
        );
    }
}

/// Runs the active operating-system series probe, where the caller asked for it
/// and a host has a TCP port worth asking again.
///
/// # Why this runs before the echo probe
///
/// This is the stronger of the two active probes where it applies. It revisits
/// ports the port scan settled, so it needs a host that answered something over
/// TCP, and reads the identifier, sequence and clock policies no single reply
/// carries. The echo probe covers hosts that answered nothing, where a hop counter
/// and an echoed code are all there is, and runs on a store the series has already
/// read.
///
/// # What each level asks for
///
/// At [`OsDetection::Active`], every host that is up, has a TCP answer, and is
/// not already named with high confidence. At [`OsDetection::Aggressive`],
/// **every** host with a TCP answer, with twice the samples: the reading a new
/// rule is authored from.
///
/// Does nothing, without failing, when there is nothing to do.
pub(super) async fn run_active_os_series(
    ctx: &ScanContext,
    os_detection: OsDetection,
    tuning: ProbeTuning,
    caps: ScanCapabilities,
) {
    if !os_detection.is_active() || stopped(ctx, Pass::Os) {
        return;
    }

    ctx.enter_stage(Stage::Os, None);
    let thorough = matches!(os_detection, OsDetection::Aggressive);

    let targets: Vec<strategy::identify::series::SeriesTarget> = ctx
        .hosts_owed_passes()
        .into_iter()
        // Read before the store is, so no host guard is held across the clock.
        .filter(|key| !ctx.host_expired(key.addr()))
        .filter_map(|key| {
            ctx.read_host(&key, |host| {
                if !host.status().is_up() {
                    return None;
                }
                // A host already named with high confidence is not worth more
                // packets at `Active`.
                let settled = host.os().is_some_and(|os| os.is_highly_confident());
                if settled && !thorough {
                    return None;
                }
                strategy::identify::series::SeriesTarget::for_host(key.clone(), host)
            })
            .flatten()
        })
        .collect();
    let targets = within_frames(
        targets,
        |target| target.address.addr(),
        caps,
        &tuning.send_source,
        ctx,
        ScannerKind::OsSeries,
        "OS series probe",
    );

    if targets.is_empty() {
        return;
    }

    // Decided before the pass is announced.
    if strategy::identify::series::OsSeriesScanner::gap_it_cannot_keep(ctx).is_some() {
        info!(verbosity = 1, "OS series skipped (scan-wide gap)");
        return;
    }

    let samples = if thorough {
        strategy::identify::series::AGGRESSIVE_SAMPLES
    } else {
        strategy::identify::series::ACTIVE_SAMPLES
    };
    info!(
        "following {} over {}",
        counted(targets.len() as u128, "host", "hosts"),
        counted(samples as u128, "sample", "samples")
    );

    match strategy::identify::series::OsSeriesScanner::new(ctx.clone(), targets, samples, tuning) {
        Ok(mut scanner) => {
            if let Err(e) = scanner.probe().await {
                ctx.record_failure(ScannerKind::OsSeries, e.to_string());
            }
        }
        // The raw TCP socket would not open, most likely for want of
        // privileges. One recorded failure; every host keeps its passive answer.
        Err(e) => ctx.record_failure(
            ScannerKind::OsSeries,
            format!("the active series probe could not open its transport: {e}"),
        ),
    }
}

/// Asks each host that has not said what kernel it runs, by SNMP.
///
/// One `GetRequest` for `sysDescr.0` per host, and on anything that answers, the
/// exact kernel, because on a Unix host `sysDescr` is the output of `uname -a`.
///
/// # Why this is a phase of its own
///
/// It is the only thing this engine can reach that states a kernel version. A TCP
/// stack's shape identifies a family: Debian 12 (kernel 6.1) and Debian 13 (kernel
/// 6.12) answer this engine's probe identically. A service banner names a
/// distribution release at best. A kernel version is what a known-vulnerability
/// lookup keys on.
///
/// An appliance answers with its own identity instead, such as `Brother
/// NC-8700w, Firmware Ver.ZL`: a make, model, firmware and device class off one
/// datagram, on a host the rest of the scan could only place by its initial hop
/// count.
///
/// The phase is driven by the OS detection level, separately from the port list:
/// adding port 161 to the list would probe a port the caller may have excluded,
/// and establishing UDP port state means waiting on rate-limited ICMP
/// unreachables. This phase needs no port state.
///
/// # It records the port
///
/// An answer proves something is listening, and an agent answering the default
/// `public` community is a finding in its own right. The port is filed with the
/// evidence that found it, [`ScanResponse::UdpResponse`], so a report can tell it
/// from one the port scan established.
///
/// # Who is asked
///
/// Every host that is up and whose kernel is still unknown. A host reported as
/// `Linux · Debian 13` is named but has no kernel version, so it is asked.
///
/// Nobody where `excluded` names the agent's port: see
/// [`ZondConfig::excluded_ports`](crate::config::ZondConfig::excluded_ports).
pub(super) async fn run_active_os_snmp(
    ctx: &ScanContext,
    os_detection: OsDetection,
    excluded: &PortSet,
) {
    if !os_detection.is_active() || stopped(ctx, Pass::Os) {
        return;
    }
    if excluded.has_udp(SNMP_PORT) {
        info!(verbosity = 1, "kernel not asked (udp {SNMP_PORT} excluded)");
        return;
    }

    ctx.enter_stage(Stage::Os, None);

    let targets: Vec<crate::model::ip::scoped::ScopedIp> = ctx
        .hosts_owed_passes()
        .into_iter()
        .filter(|ip| !ctx.host_expired(ip.addr()))
        .filter_map(|ip| {
            ctx.read_host(&ip, |host| {
                let known = host.os().is_some_and(|os| os.kernel().is_some());
                (host.status().is_up() && !known).then(|| host.scoped_ip())
            })
            .flatten()
        })
        .collect();

    if targets.is_empty() {
        return;
    }

    info!(
        "asking {} for their kernel",
        counted(targets.len() as u128, "host", "hosts")
    );

    let mut named = 0usize;
    // Hosts the process had no socket to ask, as a count and the first of
    // them, for one line: a full socket table is full for all.
    let mut unasked: Option<(String, usize)> = None;
    let mut pool = ProbePool::new(
        CONNECT_CONCURRENCY,
        ctx.clone(),
        ScannerKind::OsSnmp,
        |found: Option<(
            crate::model::ip::scoped::ScopedIp,
            crate::fingerprint::Fingerprinted,
        )>,
         _audit| {
            let Some((key, found)) = found else {
                return;
            };
            if found.starved {
                unasked
                    .get_or_insert_with(|| (key.endpoint(SNMP_PORT), 0))
                    .1 += 1;
                return;
            }
            // Recorded with what found it, so a report can tell this port from
            // one the port scan established.
            let port = found
                .port
                .with_discovery(PortDiscovery::new(ScanResponse::UdpResponse));
            ctx.update_host(key, |host| {
                host.add_port(port);
                if found.about_the_host.apply(host) {
                    named += 1;
                }
            });
        },
    );

    for target in targets {
        if ctx.stopping_before(Pass::Os) {
            break;
        }
        let egress = ctx.egress_toward(target.addr());
        pool.admit(ask_for_kernel(target, egress)).await;
    }
    pool.drain().await;
    drop(pool);

    if let Some((first, count)) = unasked {
        let hosts = match count - 1 {
            0 => first,
            rest => format!("{first} and {}", counted(rest as u128, "other", "others")),
        };
        ctx.record_failure(
            ScannerKind::OsSnmp,
            format!(
                "{hosts} not asked for a kernel: {}",
                crate::system::descriptors::starved(crate::system::descriptors::PATIENCE)
            ),
        );
    }

    if named > 0 {
        info!(
            verbosity = 1,
            "named {} by SNMP",
            counted(named as u128, "host", "hosts")
        );
    }
}

/// Asks every host that has an mDNS name what hardware it is.
///
/// A Bonjour responder publishes a device-info record under the host's own name,
/// carrying the hardware model and the Darwin release. It is the only thing this
/// engine can reach that names an Apple model outright, and a stack reading
/// cannot: macOS and iOS share a kernel and answer a probe identically.
///
/// # Who is asked
///
/// Every host that is up. The record is published under the host's own name, so a
/// host with no `.local` name is first asked what it calls itself. A host running
/// no responder leaves that unanswered and is asked nothing more, one datagram in
/// all.
///
/// That first question is a reverse-name query, and `names` says whether the scan
/// may ask one. Where it may not, only hosts already holding a `.local` name are
/// asked.
///
/// Nobody where `excluded` names the responder's port, as with
/// [`run_active_os_snmp`].
pub(super) async fn run_active_os_mdns(
    ctx: &ScanContext,
    os_detection: OsDetection,
    names: bool,
    excluded: &PortSet,
) {
    if !os_detection.is_active() || stopped(ctx, Pass::Os) {
        return;
    }
    if excluded.has_udp(MDNS_PORT) {
        info!(
            verbosity = 1,
            "hardware not asked (udp {MDNS_PORT} excluded)"
        );
        return;
    }

    ctx.enter_stage(Stage::Os, None);

    let targets = hardware_targets(ctx, names);
    if targets.is_empty() {
        return;
    }

    info!(
        "asking {} what hardware they are",
        counted(targets.len() as u128, "host", "hosts")
    );

    let mut named = 0usize;
    let mut pool = ProbePool::new(
        CONNECT_CONCURRENCY,
        ctx.clone(),
        ScannerKind::OsSnmp,
        |found: Option<(crate::model::ip::scoped::ScopedIp, Vec<OsEvidence>)>, _audit| {
            if let Some((key, evidence)) = found {
                ctx.update_host(key, |host| {
                    if os::identify(host, evidence) {
                        named += 1;
                    }
                });
            }
        },
    );

    for (target, hostname) in targets {
        if ctx.stopping_before(Pass::Os) {
            break;
        }
        let egress = ctx.egress_toward(target.addr());
        pool.admit(ask_what_hardware(target, hostname, egress))
            .await;
    }
    pool.drain().await;

    if named > 0 {
        info!(
            verbosity = 1,
            "named {} by mDNS",
            counted(named as u128, "host", "hosts")
        );
    }
}

/// The hosts [`run_active_os_mdns`] asks, each with the name it holds for
/// them: every host that is up and has not run out of time, less, where
/// `names` forbids asking one, those without a `.local` name to ask about.
fn hardware_targets(
    ctx: &ScanContext,
    names: bool,
) -> Vec<(crate::model::ip::scoped::ScopedIp, Option<String>)> {
    ctx.hosts_owed_passes()
        .into_iter()
        .filter(|ip| !ctx.host_expired(ip.addr()))
        .filter_map(|ip| {
            ctx.read_host(&ip, |host| {
                let name = host.hostname().map(str::to_string);
                host.status().is_up().then(|| (host.scoped_ip(), name))
            })
            .flatten()
        })
        .filter(|(_, name)| names || name.as_deref().and_then(device_info_query).is_some())
        .collect()
}

/// The device-info question for a host called `hostname`, or `None` where the
/// name is not one a responder publishes the record under.
fn device_info_query(hostname: &str) -> Option<Vec<u8>> {
    crate::protocols::mdns::build_device_info_query(hostname)?.ok()
}

/// The port a Bonjour responder listens on.
const MDNS_PORT: u16 = 5353;

/// Asks a host what it calls itself, by the reverse name of its own address.
///
/// One datagram, which makes the device-info query possible on a host the scan
/// reached by address. It leaves by `egress`.
async fn own_name(
    addr: std::net::SocketAddr,
    ip: IpAddr,
    egress: &crate::transport::dial::Egress,
) -> Option<String> {
    let query = crate::protocols::mdns::build_reverse_query(ip).ok()?;
    let reply = crate::fingerprint::probe_udp_raw_via(addr, &query, egress).await?;

    crate::protocols::mdns::extract_hosts(&reply)
        .ok()?
        .into_iter()
        .map(|host| host.hostname)
        .find(|name| !name.is_empty())
}

/// Asks one host for its device-info record and reads what it says about the
/// machine.
///
/// Sent to the host, not the multicast group, so the answer is attributable.
/// Both datagrams leave by `egress`.
async fn ask_what_hardware(
    target: crate::model::ip::scoped::ScopedIp,
    hostname: Option<String>,
    egress: crate::transport::dial::Egress,
) -> Option<(crate::model::ip::scoped::ScopedIp, Vec<OsEvidence>)> {
    let addr = target.to_socket_addr(MDNS_PORT)?;

    // The name the record hangs off. Asked of the host itself where nothing
    // resolved one, or a unicast resolver did (its zone publishes no record): a
    // responder answers a reverse lookup of its own address with the name it
    // publishes under.
    let query = match hostname.as_deref().and_then(device_info_query) {
        Some(query) => query,
        None => device_info_query(&own_name(addr, target.addr(), &egress).await?)?,
    };

    // Each `key=value` is its own claim; a rule reads one of them.
    let evidence: Vec<OsEvidence> = crate::fingerprint::probe_udp_with_via(addr, &query, &egress)
        .await
        .iter()
        .filter_map(|text| {
            crate::fingerprint::SignatureDb::global()
                .identify(MDNS_PORT, Protocol::Udp, text)?
                .os
        })
        .collect();

    (!evidence.is_empty()).then_some((target, evidence))
}

/// The port an SNMP agent listens on. Fixed, since trying others would be a port
/// scan.
const SNMP_PORT: u16 = 161;

/// Sends one SNMP request to `target` and returns what the answer said about the
/// machine.
///
/// A link-local address with no interface recorded against it yields no socket
/// address and is skipped.
///
/// The request leaves by `egress`.
async fn ask_for_kernel(
    target: crate::model::ip::scoped::ScopedIp,
    egress: crate::transport::dial::Egress,
) -> Option<(
    crate::model::ip::scoped::ScopedIp,
    crate::fingerprint::Fingerprinted,
)> {
    let addr = target.to_socket_addr(SNMP_PORT)?;

    let port = crate::fingerprint::baseline_port(SNMP_PORT, Protocol::Udp, PortState::Open);
    let found = crate::fingerprint::fingerprint_udp_via(addr, port, &egress).await?;

    // The key, not the address: for a link-local neighbour the bare address
    // would fork the host's record.
    Some((target, found))
}

/// Measures the route to every host the scan found alive, when asked to.
///
/// Runs last, after the ports are known, because what reaches a host decides how
/// to trace it: a host with 443 open is traced with SYNs to 443, which crosses
/// filters no ping survives.
///
/// Hosts that answered nothing are skipped. A path is measured backwards from its
/// far end, whose distance comes from a reply; see
/// [`traceroute`](crate::scanner::strategy::topology::traceroute).
pub(super) async fn run_traceroute(
    ctx: &ScanContext,
    cfg: &crate::config::ZondConfig,
    caps: ScanCapabilities,
) {
    if !cfg.traceroute || stopped(ctx, Pass::Traceroute) {
        return;
    }

    ctx.enter_stage(Stage::Traceroute, None);

    let mut alive: Vec<IpAddr> = ctx
        .hosts_owed_passes()
        .into_iter()
        .filter(|key| {
            ctx.read_host(key, |host| host.status().is_up())
                .unwrap_or(false)
        })
        .filter_map(routable)
        .collect();
    alive.sort_unstable();
    alive.dedup();
    let alive = within_frames(
        alive,
        |ip| *ip,
        caps,
        &cfg.send_source,
        ctx,
        ScannerKind::Routed,
        "route trace",
    );

    if alive.is_empty() {
        return;
    }

    info!(
        "measuring the route to {}",
        counted(alive.len() as u128, "host", "hosts")
    );
    strategy::topology::traceroute::trace(ctx, alive).await;
}

/// Joins what the scan identified against the embedded vulnerability catalogue,
/// recording a [`Finding`](crate::model::finding::Finding) on every port whose
/// software a known vulnerability names at an affected version.
///
/// [`ZondConfig`] names no dataset, since its fields change packets or timing
/// and a catalogue changes neither. A caller with their own feed runs
/// [`cve::correlate_report`](crate::cve::correlate_report) over the finished
/// report.
///
/// Sends nothing, and correlates in place in the store.
///
/// Gated on [`ServiceDetection`], because the join is on the CPE service
/// identification produces; with that pass off there is nothing to join on.
///
/// A scan runs it through [`correlate`], off the runtime's workers.
pub(super) fn run_correlation(ctx: &ScanContext, detection: ServiceDetection) {
    if detection == ServiceDetection::Off {
        return;
    }

    let catalogue = crate::cve::Catalogue::embedded();
    let correlator = crate::cve::Correlator::new(catalogue)
        .with_advisories(ctx.detections.advisories())
        .with_exploited(ctx.detections.exploited());
    let mut withdrawn = crate::cve::Withdrawn::default();
    for key in ctx.hosts_owed_passes() {
        let judged = ctx
            .read_host(&key, |host| correlator.judgements(host))
            .unwrap_or_default();
        for port in &judged {
            if port.withdrawn.total() > 0 {
                info!(
                    verbosity = 2,
                    "{key} {}/{}: {} CVEs n/a ({})",
                    port.number,
                    crate::record::wire::protocol_name(port.protocol),
                    port.withdrawn.total(),
                    withdrawn_reasons(&port.withdrawn)
                );
            }
            withdrawn.add(port.withdrawn);
        }
        record_correlations(ctx, key, catalogue.id(), judged);
    }

    // Why the findings are fewer than the catalogue's matches, once per scan,
    // for a reader comparing against another tool's count.
    if withdrawn.total() > 0 {
        info!(
            verbosity = 1,
            "{} CVEs not reported: {}",
            withdrawn.total(),
            withdrawn_reasons(&withdrawn)
        );
    }
}

/// Why correlations withdrew what they did, as the parenthetical a line ends
/// on: `18 fixed in build, 5 not affected, 4 client or local`.
fn withdrawn_reasons(withdrawn: &crate::cve::Withdrawn) -> String {
    [
        (withdrawn.fixed, "fixed in build"),
        (withdrawn.not_affected, "not affected"),
        (withdrawn.elsewhere, "client or local"),
    ]
    .into_iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, why)| format!("{count} {why}"))
    .collect::<Vec<_>>()
    .join(", ")
}

/// Records each port's correlations on the host at `key`, replacing what the
/// same catalogue drew there before, and announcing the host only where
/// something changed.
///
/// Replaced because a correlation is recomputed: a resumed sitting correlates the
/// hosts the last one did, and anything only the last computation drew has been
/// withdrawn.
fn record_correlations(
    ctx: &ScanContext,
    key: crate::model::ip::scoped::ScopedIp,
    catalogue: &str,
    judged: Vec<crate::cve::PortJudgement>,
) {
    if judged.is_empty() {
        return;
    }
    ctx.write_host(key, |host| {
        let mut news = false;
        for port in judged {
            news |= host
                .replace_port_correlations(port.number, port.protocol, catalogue, port.findings)
                .unwrap_or(false);
        }
        news
    });
}

/// [`run_correlation`] on the blocking pool, for a scan to await.
///
/// The catalogue is decoded on first use, which in a scan is this step, and takes
/// tens of milliseconds in a debug build. The runtime is the caller's and may be
/// carrying another scan, whose connections would be timed that much slower if a
/// worker were busy decoding. The join over every host is kept off the workers
/// too.
pub(super) async fn correlate(ctx: &ScanContext, detection: ServiceDetection) {
    if detection == ServiceDetection::Off {
        return;
    }
    let ctx = ctx.clone();
    let joined = tokio::task::spawn_blocking(move || run_correlation(&ctx, detection)).await;
    if let Err(failed) = joined
        && failed.is_panic()
    {
        std::panic::resume_unwind(failed.into_panic());
    }
}

/// Records `findings` on the host at `key`, where there are any, announcing it
/// only where one was news.
///
/// For passes that read the store and write back. A write is journalled and an
/// announcement makes watchers re-read the host, so a host with no findings is
/// left unwritten, and one with nothing new is written without an announcement.
fn record_port_findings(
    ctx: &ScanContext,
    key: crate::model::ip::scoped::ScopedIp,
    findings: Vec<(u16, Protocol, crate::model::finding::Finding)>,
) {
    if findings.is_empty() {
        return;
    }
    ctx.write_host(key, |host| {
        let mut news = false;
        for (number, protocol, finding) in findings {
            news |= host
                .add_port_finding(number, protocol, finding)
                .unwrap_or(false);
        }
        news
    });
}

/// Assesses each gathered certificate's own posture (expiry, self-signing, a weak
/// RSA key) and, on a host a target named, whether it answers to that name,
/// recording a finding for each problem.
///
/// Like [`run_correlation`], it sends nothing and works in place in the store,
/// from the certificates the service pass read off the handshake.
///
/// The name checked is the one the service pass's handshake sent as its server
/// name. A host reached by address was asked for no name, so a certificate naming
/// another site is no mismatch there: a server hosting several sites presents its
/// default one to a client naming none.
pub(super) fn run_cert_posture(ctx: &ScanContext) {
    let now = std::time::SystemTime::now();
    for key in ctx.hosts_owed_passes() {
        let name = ctx.target_name(key.addr());
        let hits = ctx.read_host(&key, |host| {
            host.ports()
                .flat_map(|port| {
                    let number = port.number();
                    let protocol = port.protocol();
                    let asked_for = crate::fingerprint::authority::Authority::new(
                        std::net::SocketAddr::new(key.addr(), number),
                    )
                    .named(name.clone())
                    .sni();
                    port.security()
                        .and_then(|security| security.certificate())
                        .map(|cert| {
                            let mut findings = cert.findings(now);
                            findings.extend(
                                asked_for
                                    .as_deref()
                                    .and_then(|name| cert.name_mismatch(name)),
                            );
                            findings
                        })
                        .unwrap_or_default()
                        .into_iter()
                        .map(move |finding| (number, protocol, finding))
                        .collect::<Vec<_>>()
                })
                .collect()
        });
        record_port_findings(ctx, key, hits.unwrap_or_default());
    }
}

/// Characterises the filter in front of each host that answered, if asked.
///
/// A sibling of [`run_traceroute`]: it runs last, only against hosts that
/// answered, and does nothing unless
/// [`characterise`](crate::config::ZondConfig::characterise) was set. It sends a
/// bad-checksum probe to one open TCP port of each such host and marks a
/// middlebox on those that answer one: a reply no conformant host could have
/// sent. A host with no open TCP port is skipped.
pub(super) async fn run_characterise(
    ctx: &ScanContext,
    cfg: &crate::config::ZondConfig,
    caps: ScanCapabilities,
) {
    if !cfg.characterise || stopped(ctx, Pass::Filters) {
        return;
    }

    let mut subjects: Vec<strategy::topology::characterise::Subject> = Vec::new();
    for key in ctx.hosts_owed_passes() {
        if ctx.host_expired(key.addr()) {
            continue;
        }
        // One open port for the middlebox probe, and one a SYN did not reach
        // (silent or refused, where a filter is acting) for the comparative
        // probes.
        let ports = ctx.read_host(&key, |host| {
            host.status().is_up().then(|| {
                let tcp = |wanted: &[PortState]| {
                    host.ports()
                        .find(|port| {
                            port.protocol() == Protocol::Tcp && wanted.contains(&port.state())
                        })
                        .map(|port| port.number())
                };
                (
                    tcp(&[PortState::Open]),
                    tcp(&[PortState::NoReply, PortState::Blocked]),
                )
            })
        });
        let Some(Some((open_port, unreached_port))) = ports else {
            continue;
        };
        if open_port.is_none() && unreached_port.is_none() {
            continue;
        }
        if let Some(host) = routable(key) {
            subjects.push(strategy::topology::characterise::Subject {
                host,
                open_port,
                unreached_port,
            });
        }
    }

    let subjects = within_frames(
        subjects,
        |subject| subject.host,
        caps,
        &cfg.send_source,
        ctx,
        ScannerKind::Routed,
        "filter characterisation",
    );

    if subjects.is_empty() {
        return;
    }

    ctx.enter_stage(Stage::Filters, None);
    strategy::topology::characterise::characterise(ctx, subjects).await;
}

/// Asks each host that answered which IP protocols its stack takes delivery of,
/// where the caller named any.
///
/// A sibling of [`run_characterise`]: it runs last, only against hosts that
/// answered, and does nothing unless
/// [`ip_protocols`](crate::config::ZondConfig::ip_protocols) names some. It needs
/// no open port: a tunnel endpoint or a router terminates a protocol and listens
/// on nothing.
pub(super) async fn run_ip_protocols(ctx: &ScanContext, cfg: &crate::config::ZondConfig) {
    if cfg.ip_protocols.is_empty() || stopped(ctx, Pass::IpProtocols) {
        return;
    }

    let mut targets = Vec::new();
    for key in ctx.hosts_owed_passes() {
        if ctx.host_expired(key.addr()) {
            continue;
        }
        if ctx.read_host(&key, |host| host.status().is_up()) != Some(true) {
            continue;
        }
        if let Some(host) = routable(key) {
            targets.push(host);
        }
    }

    if targets.is_empty() {
        return;
    }

    ctx.enter_stage(Stage::IpProtocols, None);
    strategy::protocols::probe(ctx, &targets, &cfg.ip_protocols).await;
}

/// Establishes what each TLS port accepts, where the caller asked for it.
///
/// Runs last among the port-level passes because it needs the ports that speak
/// TLS: those with a `security` record, written when a handshake completed during
/// service detection. With service detection off it enumerates nothing.
///
/// ## What it costs the target
///
/// One bare TCP connection per offer, each carrying a single ClientHello and torn
/// down before a handshake completes. A target's application logs stay empty, but
/// its connection log can gain dozens of entries per port, which is why the pass
/// is opt-in.
///
/// Ports are walked with the service pass's concurrency. A host that has spent
/// [`ZondConfig::host_timeout`](crate::config::ZondConfig::host_timeout) is left
/// alone, checked before every offer, so a budget that runs out mid-walk ends it
/// there.
pub(super) async fn run_tls_enumeration(ctx: &ScanContext, cfg: &crate::config::ZondConfig) {
    if !cfg.tls_enumeration || stopped_with(ctx, Pass::Tls, || !tls_ports(ctx).is_empty()) {
        return;
    }

    // Snapshotted before anything awaits, so no store guard is held across a
    // connection.
    let targets = tls_ports(ctx);
    if targets.is_empty() {
        return;
    }

    ctx.enter_stage(Stage::Tls, Some(targets.len() as u64));

    let ports = targets.len() as u128;
    let accept = if ports == 1 { "accepts" } else { "accept" };
    info!(
        "enumerating what {} {accept}",
        counted(ports, "TLS port", "TLS ports")
    );

    let mut pool = ProbePool::new(
        CONNECT_CONCURRENCY,
        ctx.clone(),
        ScannerKind::Service,
        |found: Option<(
            crate::model::ip::scoped::ScopedIp,
            u16,
            crate::model::tls::TlsSupport,
        )>,
         _audit| {
            // Counted as each walk ends, however it ended; one its host's budget
            // cut short records the versions it left unfinished.
            ctx.stage_advanced();

            if let Some((key, number, support)) = found {
                record_tls_support(ctx, key, number, support);
            }
        },
    );

    for (address, number) in targets {
        if ctx.stopping_before(Pass::Tls) {
            break;
        }
        if ctx.host_expired(address.addr()) {
            continue;
        }
        pool.admit(enumerate_one(ctx.clone(), address, number))
            .await;
    }

    pool.drain().await;
}

/// Every `(address, port)` a handshake already completed against.
///
/// Filtered by the `security` record, which is written only where a TLS
/// handshake succeeded.
fn tls_ports(ctx: &ScanContext) -> Vec<(crate::model::ip::scoped::ScopedIp, u16)> {
    let mut targets = Vec::new();
    for host in ctx.store.iter() {
        if !ctx.owes_passes(host.value()) {
            continue;
        }
        let address = host.value().scoped_ip();
        for port in host.value().ports() {
            // TCP only: a `security` record is written by a completed TLS
            // handshake, and nothing here speaks DTLS.
            if port.protocol() == Protocol::Tcp
                && port.state() == PortState::Open
                && port.security().is_some()
                // A record restored from an earlier sitting is no licence for
                // this pass's hellos. See `ScanContext::listens_only`.
                && !ctx.listens_only(port.number(), port.protocol())
            {
                targets.push((address.clone(), port.number()));
            }
        }
    }
    targets
}

/// Enumerates one endpoint, or `None` where its address cannot be dialled.
///
/// The walk is up to 80 connections per version, so before each it checks that
/// the scan is still running and the host within its budget. The scan's stop is
/// checked first, so a host is not blamed on its budget when the scan stopped; a
/// host whose budget ran out mid-walk is named by [`ScanContext::host_expired`].
async fn enumerate_one(
    ctx: ScanContext,
    address: crate::model::ip::scoped::ScopedIp,
    number: u16,
) -> Option<(
    crate::model::ip::scoped::ScopedIp,
    u16,
    crate::model::tls::TlsSupport,
)> {
    let socket = address.to_socket_addr(number)?;
    let ip = address.addr();
    // Sent the target's name, as identification's handshake was, or a server
    // hosting sites by name refuses every offer.
    let server_name = crate::fingerprint::authority::Authority::new(socket)
        .named(ctx.target_name(ip))
        .sni();
    let support = crate::fingerprint::enumerate_tls_while(
        socket,
        server_name.as_deref(),
        &ctx.egress_toward(ip),
        || !ctx.stopping_before(Pass::Tls) && !ctx.host_expired(ip),
    )
    .await;
    // An endpoint that accepted nothing and finished every walk is not written
    // back, which would announce an update with no new fact. One whose walks
    // were cut short is written back even with nothing accepted.
    (!support.is_empty()).then_some((address, number, support))
}

/// Folds what an endpoint accepts back into its port.
///
/// Through [`Host::add_port`](crate::model::host::Host::add_port), the
/// confidence-driven path every pass uses. The port carried here holds only the
/// enumeration: `Security::merge` fills what is missing, so the service pass's
/// version and certificate survive, and an enumeration restored by a resumed
/// sitting gives way, version by version, wherever this one went further.
fn record_tls_support(
    ctx: &ScanContext,
    key: crate::model::ip::scoped::ScopedIp,
    number: u16,
    support: crate::model::tls::TlsSupport,
) {
    let findings = support.findings();
    let mut carrier = crate::model::port::Port::new(number, Protocol::Tcp, PortState::Open)
        .with_security(crate::model::port::Security::new().with_support(support));
    for finding in findings {
        carrier.add_finding(finding);
    }

    ctx.update_host(key, |host| {
        host.add_port(carrier);
    });
}

/// Runs the active operating-system echo probe, where the caller asked for it
/// and the passive sources left hosts unnamed.
///
/// Targets come from the store, where the passive sources' conclusions live once
/// they have finished. A host that answered nothing a TCP rule could read (a stock
/// Windows firewall drops) may still answer an echo.
///
/// Runs after [`run_active_os_series`], which has read everything a host with a
/// TCP answer can say.
///
/// Does nothing, without failing, when there is nothing to do.
pub(super) async fn run_active_os_probe(
    ctx: &ScanContext,
    os_detection: crate::config::OsDetection,
    tuning: ProbeTuning,
    caps: ScanCapabilities,
) {
    if !os_detection.is_active() || stopped(ctx, Pass::Os) {
        return;
    }

    ctx.enter_stage(Stage::Os, None);

    // Only hosts the scan found and could not name; pinging unrecorded
    // addresses would be a discovery sweep.
    let mut unnamed: Vec<IpAddr> = ctx
        .hosts_owed_passes()
        .into_iter()
        .filter(|key| !ctx.host_expired(key.addr()))
        .filter(|key| {
            ctx.read_host(key, |host| {
                host.status().is_up() && host.os().is_none_or(|os| !os.is_highly_confident())
            })
            .unwrap_or(false)
        })
        .filter_map(routable)
        .collect();
    unnamed.sort_unstable();
    unnamed.dedup();
    let unnamed = within_frames(
        unnamed,
        |ip| *ip,
        caps,
        &tuning.send_source,
        ctx,
        ScannerKind::OsEcho,
        "OS echo probe",
    );

    if unnamed.is_empty() {
        return;
    }

    info!(
        "probing {} the passive sources could not name, by echo",
        counted(unnamed.len() as u128, "host", "hosts")
    );

    match strategy::identify::echo::OsEchoScanner::new(ctx.clone(), unnamed, tuning) {
        Ok(mut scanner) => {
            if let Err(e) = scanner.probe().await {
                ctx.record_failure(ScannerKind::OsEcho, e.to_string());
            }
        }
        // The raw ICMP socket would not open, most likely for want of
        // privileges. One recorded failure; every host keeps its passive answer.
        Err(e) => ctx.record_failure(
            ScannerKind::OsEcho,
            format!("the active echo probe could not open its transport: {e}"),
        ),
    }
}

/// The addresses of `target_map` that still have a target `settled` does not
/// account for: what a sitting of a port scan asks about host by host.
///
/// The liveness sweep and the enrichment beside the port scan are aimed here. A
/// resumed sitting probes only what an earlier one left; for a fresh sitting this
/// is every address the plan names a port at. See [`Checkpoint::remaining_hosts`].
pub(super) fn unsettled_ips(target_map: &TargetMap, settled: &Checkpoint) -> IpSet {
    settled.remaining_hosts(&TargetIndex::of(target_map))
}

/// Starts the background hostname resolver as its own task.
///
/// The resolver listens for raw DNS and mDNS traffic and answers reverse lookups
/// for any IP sent down `dns_rx`, concurrently with the scanning strategies. When
/// it fails to start, most likely because no usable socket could be opened, the
/// failure is filed against [`ScannerKind::Resolver`] and `None` is returned; the
/// scan continues without hostnames.
pub(super) async fn spawn_resolver(
    dns_rx: UnboundedReceiver<IpAddr>,
    ctx: ScanContext,
) -> JoinHandle<Option<HostnameResolver>> {
    tokio::spawn(async move {
        match HostnameResolver::capturing_on(dns_rx, &ctx.capture_links()) {
            Ok(resolver) => {
                // Routine; only the failure is worth a normal-level line.
                success!(verbosity = 3, "successfully initialized hostname resolver");
                Some(resolver.run().await)
            }
            Err(e) => {
                ctx.record_failure(
                    ScannerKind::Resolver,
                    format!("not started: {e} (no hostnames)"),
                );
                None
            }
        }
    })
}

/// The targets a port scan's plan loses before it is numbered, and the zones
/// the link-local ones it keeps were named on.
///
/// Taken out ahead of the numbering by [`withhold_unprobeable_targets`], so the
/// numbering, the progress count and the walk all describe one plan. A target
/// numbered and then withheld would give every later target two positions. What
/// is taken out depends on the targets alone, so every sitting of a job numbers
/// alike. The refusals are filed in the port phase's record.
pub(super) struct Withheld {
    /// Ranges too large to walk.
    unwalkable: Vec<Ipv6Range>,
    /// Link-local ranges that name no interface.
    unscoped: Vec<Ipv6Range>,
    /// Link-local ranges naming an address another range names on another
    /// interface.
    contested: Vec<Ipv6Range>,
    /// The interface each kept link-local range was named on.
    zones: ZoneMap,
}

impl Withheld {
    /// Files a refusal for each range withheld, against `port_scanner` where
    /// the refusal is the port strategy's to make.
    pub(super) fn refuse(&self, ctx: &ScanContext, port_scanner: ScannerKind) {
        for range in &self.unscoped {
            ctx.record_refusal(
                plan::RefusedStep::link_local_port_target_needs_an_interface(range).into(),
            );
        }
        for range in &self.contested {
            ctx.record_refusal(
                plan::RefusedStep::link_local_port_target_names_two_segments(range).into(),
            );
        }
        for range in &self.unwalkable {
            ctx.record_refusal(
                plan::RefusedStep::port_range_not_enumerable(range, port_scanner).into(),
            );
        }
    }

    /// The interface each kept link-local target was named on, for the phases
    /// that open a socket or a raw send.
    pub(super) fn zones(&self) -> &ZoneMap {
        &self.zones
    }
}

/// Takes out of `target_map` every target its port phase cannot probe, before
/// anything numbers it; see [`Withheld`].
///
/// The link-local check comes first: an unscoped `fe80::/64` is both too wide to
/// walk and on no segment, and the refusal naming the interface to write is the
/// one the caller can act on. [`TargetMap::take_unprobeable`] decides which
/// targets go, since a journal counts the job's total the same way.
///
/// # A link-local range
///
/// The routing table cannot carry a link-local address without an interface, and
/// every interface holds an `fe80::/64`. Written `fe80::1%en0` it names a segment,
/// and the returned [`ZoneMap`] carries the interface to the scanners, since the
/// zone is written on the range, not on each address. A range only partly
/// link-local, such as a hand-widened `fe80::/10`, is judged by
/// [`Ipv6Range::is_ambiguous`](crate::model::ip::range::Ipv6Range::is_ambiguous),
/// as the discovery classifier does.
///
/// Two ranges naming one address on different interfaces are refused, since a
/// verdict filed under the bare address would be about whichever answered first.
///
/// Withheld here, not at the socket, because a target dropped at the send gets no
/// verdict, no settlement and no line in the report: `resolve_unasked` accounts
/// only for what is still queued.
///
/// # A range too wide to walk
///
/// The port phase's side of the rule [`walkable`] applies to a sweep, with the
/// same constant. A port scan walks target by target whatever the privilege, so a
/// `/64` behind a port list would never finish.
pub(super) fn withhold_unprobeable_targets(target_map: &mut TargetMap) -> Withheld {
    // Read once, and only for a scan that named a zone.
    let named_a_zone = target_map
        .units
        .iter()
        .flat_map(|unit| unit.ips().v6())
        .any(|range| range.zone().is_some());
    let links = match named_a_zone {
        true => crate::system::interface::interfaces_or_none(),
        false => Vec::new(),
    };
    let names: Vec<(u32, &str)> = links
        .iter()
        .map(|link| (link.index(), link.name()))
        .collect();

    let taken = target_map.take_unprobeable(&names, interface::is_enumerable);
    Withheld {
        unwalkable: taken.unwalkable,
        unscoped: taken.unscoped,
        contested: taken.contested,
        zones: taken.zones,
    }
}

/// Probes `target_map`'s ports, and nothing else of its hosts.
///
/// Nothing is opened for an empty map: a liveness phase that found nothing is a
/// finished answer.
///
/// `stands_in` is whether these port probes stand in for a liveness pass the
/// engine dropped as no cheaper; see
/// [`LivenessSkip::PortsNoDearer`](crate::report::LivenessSkip::PortsNoDearer).
/// Then the addresses they heard nothing from are filed silent and their records
/// forgotten; see [`forget_the_silent`].
///
/// `target_map` has already had its unprobeable targets withheld, and `zones` is
/// the interface each kept link-local target was named on; see
/// [`withhold_unprobeable_targets`].
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_port_phase(
    target_map: TargetMap,
    zones: &ZoneMap,
    liveness: Option<Liveness>,
    ctx: &ScanContext,
    caps: ScanCapabilities,
    cfg: &ZondConfig,
    settled: Checkpoint,
    stands_in: bool,
) {
    if target_map.is_empty() {
        return;
    }

    // Before any verdict is recorded: a finding written under a bare `fe80::…`
    // has to reach the host the sweep already found on that interface.
    ctx.learn_zones(zones.clone());

    // A scan stopped before its ports were reached opens nothing. The walk
    // still runs, stopping at its first target, so the plan is accounted for as
    // unreached.
    if ctx.handle.should_stop() {
        let (rx, walk) = super::dispatcher::Dispatcher::new(target_map)
            .resuming(settled)
            .spawn(ctx);
        drop(rx);
        if let Err(error) = walk.await {
            error!("the target walk ended abnormally: {error}");
        }
        run_passive_os_identification(ctx, cfg.os_detection);
        return;
    }

    let target_count = target_map.gross_targets().unwrap_or(0) as usize;
    // SCTP and UDP are planned from the targets, since only the targets' ports
    // name them.
    let mut plan = super::plan::PortScanPlan::build(cfg, caps.privilege);
    if target_map.names(Protocol::Sctp) {
        plan.cover_sctp(caps.privilege);
    }
    if target_map.names(Protocol::Udp) {
        plan.cover_udp(caps.privilege);
    }

    // What this sitting will probe: addresses an earlier sitting left a target
    // at, narrowed to the hosts that answered where the liveness phase ran.
    let mut probed = unsettled_ips(&target_map, &settled);
    if let Some(liveness) = &liveness {
        probed = within(&probed, &liveness.live);
    }
    let beyond = caps.beyond_frames(&probed, &cfg.send_source, interface::FrameSender::Probe);
    let raw = RawReach::of(&probed, beyond.targets.clone());
    let named: Vec<Protocol> = Protocol::ALL
        .iter()
        .copied()
        .filter(|protocol| target_map.names(*protocol))
        .collect();
    let built = build_port_scanner(
        plan,
        &named,
        ctx,
        target_count,
        cfg.probe_tuning(),
        zones,
        &raw,
    );
    // After the build, which knows whether anything stands in for the raw
    // strategies; a technique with no connect form is refused there instead.
    if built.reached_by_connect {
        announce_by_connect("port scan", &beyond);
    }

    // No sweep beside the ports: with the liveness pass on it has already read
    // hardware addresses and names, and with it off the caller asked for ports
    // only.
    //
    // Numbered against the whole plan, then filtered to what an earlier sitting
    // left and to the hosts that answered. The numbering belongs to the job; the
    // filters belong to this sitting.
    let mut dispatcher = super::dispatcher::Dispatcher::new(target_map).resuming(settled);
    if let Some(Liveness { live, silent }) = liveness {
        dispatcher = dispatcher.screened(live, silent);
    }
    // Held from the journal until the phase has decided which records nothing
    // answered at are hosts, so a sitting killed first writes none of them.
    if stands_in {
        ctx.await_verdicts();
    }
    let (rx, walk) = dispatcher.spawn(ctx);

    run_port_scan(built.scanner, rx, ctx, cfg.service_detection, cfg.detection).await;
    // The walk settles the targets of hosts found down, and may still be
    // running after a scanner stopped early. Awaited so its settlements land
    // before the last checkpoint. It ends promptly: the receiver is gone, so its
    // next send fails, and it checks the stop between targets.
    if let Err(error) = walk.await {
        error!("the target walk ended abnormally: {error}");
    }
    // Before names are asked for, so the resolver is not queried for addresses
    // where nothing was found.
    if stands_in {
        forget_the_silent(ctx, &probed);
        ctx.verdicts_reached();
    }
    let unheard = match cfg.assume_up {
        true => rdns::Unheard::Named,
        false => rdns::Unheard::Skipped,
    };
    finish_enrichment(None, caps, ctx, unheard).await;
    // Passive first: the echo probe is aimed at the hosts it could not name.
    run_passive_os_identification(ctx, cfg.os_detection);
}

/// Files as silent every address in `probed` the port probes asked on every
/// port and drew nothing from, files as undecided every one they drew nothing
/// from without finishing asking, and forgets the records the scanners filed
/// at both.
///
/// Nothing drawn means the record is still
/// [`Unknown`](crate::model::host::HostStatus::Unknown): no open port, no closed
/// one, no ICMP error. Such an address is silent where every port was asked in
/// full. Where a port is still [`Unasked`](PortState::Unasked) (the scan stopped
/// short or cut the probe off) or the address's time budget ran out, it is
/// undecided, as a liveness pass stopped early leaves it, and asked again on a
/// resume. An address nothing could be sent to is neither, and is named in the
/// report as such. See [`ScanContext::forget_silent`] and
/// [`ScanContext::forget_undecided`].
fn forget_the_silent(ctx: &ScanContext, probed: &IpSet) {
    let mut silent = Vec::new();
    let mut undecided = Vec::new();
    for entry in ctx.store.iter() {
        let host = entry.value();
        let address = entry.key().addr();
        if host.status() != crate::model::host::HostStatus::Unknown
            || !probed.contains(&address)
            || ctx.is_unroutable(address)
        {
            continue;
        }
        let finished =
            host.ports().all(|port| port.state() != PortState::Unasked) && !ctx.left_early(address);
        match finished {
            true => silent.push(entry.key().clone()),
            false => undecided.push(entry.key().clone()),
        }
    }
    ctx.forget_silent(silent);
    ctx.forget_undecided(undecided);
}

/// The plan as the port phase actually probed it.
///
/// The dispatcher walks the whole plan, so a position means the same target in
/// every sitting (see [`live_addresses`]). This is what the phase covered, which
/// a [`TargetScope`] records so a reader can compare it against the liveness
/// phase's.
///
/// Narrows each unit separately, because a unit may carry its own ports, as
/// `192.0.2.1:8080` does.
pub(super) fn probed_subset(target_map: &TargetMap, live: &IpSet) -> TargetMap {
    // Expanded once, not per unit: `live.iter()` yields every address of every
    // host found.
    let live: Vec<IpAddr> = live.iter().collect();

    let mut kept = TargetMap::new();
    for unit in &target_map.units {
        let mut ips = IpSet::new();
        for ip in &live {
            if unit.ips().contains(ip) {
                push_single(&mut ips, *ip, None);
            }
        }
        ips.canonicalize();

        if !ips.is_empty() {
            kept.add_unit(TargetSet::new(ips, unit.ports().clone()));
        }
    }

    kept
}

/// The SCTP port a discovery sweep should ask about, or `None` where the scan
/// named no SCTP port and so wants no SCTP sweep.
///
/// Chosen from the scan's own ports, which a filter in front of an SCTP host is
/// likeliest to pass. Among them the catalogue's order decides; a port it does not
/// know loses to one it does, and with only unknown ports the lowest is taken, so
/// every run chooses alike.
pub(super) fn sctp_discovery_port(map: &TargetMap) -> Option<u16> {
    let named: Vec<u16> = map
        .units
        .iter()
        .flat_map(|unit| unit.ports().ranges(Protocol::Sctp))
        .flat_map(|range| range.clone())
        .collect();

    named.iter().copied().min_by_key(|port| {
        let rank = crate::model::port::catalog::SCTP_BY_PREVALENCE
            .iter()
            .position(|known| known == port)
            .unwrap_or(usize::MAX);
        (rank, *port)
    })
}

/// What a port scan's liveness pass found, for the port phase to act on.
pub(super) struct Liveness {
    /// Where it found a host, from [`live_addresses`].
    pub(super) live: IpSet,
    /// Where it asked as many times as its policy allows and heard nothing,
    /// from [`ScanContext::take_silent`]. An address in neither `live` nor this
    /// has no verdict.
    pub(super) silent: IpSet,
}

impl Liveness {
    /// What the pass that just ran on `ctx` found, given the silence it heard
    /// as [`ScanContext::take_silent`] handed it over.
    pub(super) fn found(ctx: &ScanContext, silent: IpSet) -> Self {
        Self {
            live: live_addresses(ctx),
            silent,
        }
    }

    /// The addresses of `scope` this pass reached no verdict on, ascending:
    /// neither found live nor asked to exhaustion, and not among `unroutable`,
    /// which the phase names apart.
    ///
    /// Computed from what the pass established, so any failure to ask lands
    /// here, recorded or not: a sweep stopped mid-send, a strategy that never
    /// built, a refused range, a host whose budget ran out.
    ///
    /// Linear in ranges, as [`IpSet::subtract`] is.
    pub(super) fn undecided(&self, scope: &TargetScope, unroutable: &[IpAddr]) -> Vec<IpRange> {
        let mut undecided = IpSet::new();
        for range in scope.ranges() {
            undecided.insert_range(*range);
        }
        undecided.subtract(&self.live);
        undecided.subtract(&self.silent);
        let mut unreachable = IpSet::new();
        for address in unroutable {
            unreachable.insert(*address);
        }
        undecided.subtract(&unreachable);
        undecided.canonicalize();

        let v4 = undecided.v4().iter().copied().map(IpRange::V4);
        let v6 = undecided.v6().iter().copied().map(IpRange::V6);
        v4.chain(v6).collect()
    }
}

/// Every address the liveness pass found a host at.
///
/// A set, not a narrowed plan: the addresses go to
/// [`Dispatcher::screened`](crate::scanner::dispatcher::Dispatcher::screened),
/// which filters after numbering, so positions do not depend on which hosts
/// answered.
///
/// Every address of a host is included, so a dual-stack machine found over IPv6
/// still matches a unit naming its IPv4 address.
pub(super) fn live_addresses(ctx: &ScanContext) -> IpSet {
    let mut live = IpSet::new();
    for entry in ctx.store.iter() {
        let host = entry.value();
        if !host.is_alive() {
            continue;
        }
        for ip in host.ips() {
            push_single(&mut live, *ip, host.zone().and_then(Zone::index));
        }
    }
    live.canonicalize();
    live
}

/// The address a raw routed probe can be aimed at, or `None` for a host it
/// cannot reach.
///
/// The one place a store key is narrowed to a bare address. The trace and the
/// echo probe reach a host over the routing table and reason in addresses: a
/// socket takes one, a reply carries one, and a hop table is keyed by one.
///
/// A host whose address needs an interface, such as `fe80::1`, is excluded: a raw
/// routed probe has nowhere to put a scope id, the same refusal
/// [`ScopedIp::to_socket_addr`](crate::model::ip::scoped::ScopedIp::to_socket_addr)
/// makes. The local scanner reaches those hosts at the link layer.
///
/// This also keeps the store consistent: a routed strategy writes its finding
/// under the address it probed, and an address that is not the whole key would
/// create a second entry for the same host.
fn routable(key: crate::model::ip::scoped::ScopedIp) -> Option<IpAddr> {
    (!crate::model::ip::scoped::ScopedIp::needs_zone(&key.addr())).then(|| key.addr())
}

/// The addresses of `set` that `of` also holds.
///
/// Two subtractions, each linear in ranges: what `set` has that `of` lacks, taken
/// back out of `set`.
fn within(set: &IpSet, of: &IpSet) -> IpSet {
    let mut outside = set.clone();
    outside.subtract(of);
    let mut inside = set.clone();
    inside.subtract(&outside);
    inside
}

/// Pushes one address into `set` as a range of itself.
///
/// The zone is kept only for the addresses that cannot be reached without one:
/// `fe80::1` names a different machine on every segment.
fn push_single(set: &mut IpSet, ip: IpAddr, zone: Option<u32>) {
    match ip {
        IpAddr::V4(v4) => {
            if let Ok(range) = Ipv4Range::new(v4, v4) {
                set.push_v4_range(range);
            }
        }
        IpAddr::V6(v6) => {
            let zone = v6.is_unicast_link_local().then_some(zone).flatten();
            if let Ok(range) = Ipv6Range::scoped(v6, v6, zone) {
                set.push_v6_range(range);
            }
        }
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
    use crate::testing::loopback::accept_from_this_process;

    /// **A pass a stop skipped is named where a host was owed it, and only
    /// there.** A scan that found no host lost nothing to the stop, and naming
    /// the pass there would call a complete scan partial.
    #[test]
    fn a_pass_a_stop_skipped_is_named_only_where_a_host_was_owed_it() {
        use crate::model::host::HostStatus;
        use crate::scanner::session::ScanSession;
        use std::net::Ipv4Addr;

        let (_session, ctx) = ScanSession::new();
        assert!(!stopped(&ctx, Pass::Traceroute), "not stopped");
        ctx.handle.abort();
        assert!(stopped(&ctx, Pass::Traceroute));
        assert!(ctx.take_passes_cut().is_empty(), "no host was owed it");

        ctx.update_host(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), |host| {
            host.set_status(HostStatus::Up);
        });
        assert!(stopped(&ctx, Pass::Traceroute));
        assert!(stopped(&ctx, Pass::Os));
        assert!(stopped(&ctx, Pass::Os));
        assert_eq!(ctx.take_passes_cut(), [Pass::Os, Pass::Traceroute]);
    }

    /// **A scan forbidden name queries asks no host its name.** It still asks for
    /// the device-info record of a host whose `.local` name it already holds.
    #[test]
    fn a_scan_forbidden_name_queries_asks_the_hardware_pass_only_of_hosts_it_has_named() {
        use crate::model::host::HostStatus;
        use crate::scanner::session::ScanSession;
        use std::net::Ipv4Addr;

        let (_session, ctx) = ScanSession::new();
        let at = |last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last));
        for (last, name) in [
            (1, None),
            (2, Some("printer.local")),
            (3, Some("host.example.com")),
        ] {
            ctx.update_host(at(last), |host| {
                host.set_status(HostStatus::Up);
                host.set_hostname(name.map(str::to_string));
            });
        }

        let asked = |names| {
            let mut asked: Vec<IpAddr> = hardware_targets(&ctx, names)
                .iter()
                .map(|(target, _)| target.addr())
                .collect();
            asked.sort_unstable();
            asked
        };
        assert_eq!(asked(true), [at(1), at(2), at(3)]);
        assert_eq!(asked(false), [at(2)], "only the host already named .local");
    }

    /// Which SCTP port a sweep asks about, when the scan named several.
    ///
    /// The catalogue's order decides, so the well-known port wins over an
    /// arbitrary one.
    #[test]
    fn the_sweep_asks_on_the_likeliest_of_the_ports_the_scan_named() {
        use crate::model::target::TargetSet;

        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "192.0.2.1".parse().expect("an address"),
            "s:9999, s:3868, s:2905".parse().expect("a specification"),
        ));

        assert_eq!(sctp_discovery_port(&map), Some(3868));
    }

    /// A scan naming nothing the catalogue knows still asks the same port every
    /// time.
    #[test]
    fn a_sweep_over_unknown_ports_still_picks_one_deterministically() {
        use crate::model::target::TargetSet;

        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "192.0.2.1".parse().expect("an address"),
            "s:9999, s:9001".parse().expect("a specification"),
        ));

        assert_eq!(sctp_discovery_port(&map), Some(9001));
    }

    /// A scan that never mentioned SCTP opens no socket for it.
    #[test]
    fn a_scan_naming_no_sctp_port_sweeps_none() {
        use crate::model::target::TargetSet;

        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "192.0.2.1".parse().expect("an address"),
            "80, u:53".parse().expect("a specification"),
        ));

        assert_eq!(sctp_discovery_port(&map), None);
    }

    /// One address, valid on the interface with index `zone`.
    fn scoped_set(addr: &str, zone: u32) -> IpSet {
        use crate::model::ip::range::IpRange;

        let addr: std::net::Ipv6Addr = addr.parse().expect("an address");
        let mut set = IpSet::new();
        set.insert_range(IpRange::V6(
            Ipv6Range::scoped(addr, addr, Some(zone)).expect("a scoped range"),
        ));
        set.canonicalize();
        set
    }

    /// `fe80::1` with no interface named is refused.
    #[test]
    fn a_bare_link_local_port_target_is_refused_rather_than_probed() {
        use crate::model::target::TargetSet;
        use crate::scanner::session::ScanSession;

        let (_session, ctx) = ScanSession::new();
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            ip_set(&["fe80::1"]),
            "80".parse().expect("a port set"),
        ));

        withhold_unprobeable_targets(&mut map).refuse(&ctx, ScannerKind::SynPort);

        assert!(map.is_empty(), "nothing is left for a scanner to probe");
        let refusals = ctx.refusals_snapshot();
        assert_eq!(refusals.len(), 1);
        assert!(
            refusals[0]
                .reason()
                .starts_with("fe80::1: link-local, name the interface"),
            "the refusal says what the caller could write instead: {}",
            refusals[0].reason()
        );
        assert!(
            ctx.failures_snapshot().is_empty(),
            "nothing went wrong; the engine declined"
        );
    }

    /// The same address written `fe80::1%en0` is kept, and its interface comes
    /// back for the phases that open a socket or a raw send.
    #[test]
    fn a_link_local_target_that_names_an_interface_is_kept_with_its_zone() {
        use crate::model::target::TargetSet;
        use crate::scanner::session::ScanSession;

        let (_session, ctx) = ScanSession::new();
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            scoped_set("fe80::1", 15),
            "80".parse().expect("a port set"),
        ));

        let withheld = withhold_unprobeable_targets(&mut map);
        withheld.refuse(&ctx, ScannerKind::SynPort);
        let zones = withheld.zones();

        assert_eq!(map.units.len(), 1, "the target is still there to probe");
        assert_eq!(
            zones.zone_of(&"fe80::1".parse().expect("an address")),
            Some(15),
            "and the send knows which interface to leave by"
        );
        assert!(ctx.refusals_snapshot().is_empty());
    }

    /// `fe80::1%en0` and `fe80::1%en1` are two machines, and a port scan files
    /// verdicts under the address, so both are refused.
    #[test]
    fn one_link_local_address_on_two_interfaces_is_refused() {
        use crate::model::target::TargetSet;
        use crate::scanner::session::ScanSession;

        let (_session, ctx) = ScanSession::new();
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            scoped_set("fe80::1", 15),
            "80".parse().expect("a port set"),
        ));
        map.add_unit(TargetSet::new(
            scoped_set("fe80::1", 16),
            "80".parse().expect("a port set"),
        ));

        let withheld = withhold_unprobeable_targets(&mut map);
        withheld.refuse(&ctx, ScannerKind::SynPort);
        let zones = withheld.zones();

        assert_eq!(map.units.len(), 1, "the first one named is still probed");
        assert_eq!(
            zones.zone_of(&"fe80::1".parse().expect("an address")),
            Some(15)
        );

        let refusals = ctx.refusals_snapshot();
        assert_eq!(refusals.len(), 1);
        assert!(
            refusals[0].reason().contains("two interfaces"),
            "the refusal says which question could not be answered: {}",
            refusals[0].reason()
        );
    }

    /// One bad address does not refuse the rest of its unit.
    #[test]
    fn the_addressable_targets_beside_it_survive() {
        use crate::model::target::TargetSet;
        use crate::scanner::session::ScanSession;

        let (_session, ctx) = ScanSession::new();
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            ip_set(&["fe80::1", "192.0.2.7", "2001:db8::1"]),
            "80".parse().expect("a port set"),
        ));

        withhold_unprobeable_targets(&mut map).refuse(&ctx, ScannerKind::SynPort);

        assert_eq!(map.units.len(), 1);
        assert_eq!(map.units[0].ips().len(), 2, "the two addressable ones");
        assert_eq!(ctx.refusals_snapshot().len(), 1);
    }

    /// A scan naming no link-local pays nothing and is told nothing.
    #[test]
    fn an_ordinary_target_map_is_left_alone() {
        use crate::model::target::TargetSet;
        use crate::scanner::session::ScanSession;

        let (_session, ctx) = ScanSession::new();
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            ip_set(&["192.0.2.0/30"]),
            "80".parse().expect("a port set"),
        ));

        withhold_unprobeable_targets(&mut map).refuse(&ctx, ScannerKind::SynPort);

        assert_eq!(map.units[0].ips().len(), 4);
        assert!(ctx.refusals_snapshot().is_empty());
    }
    use super::*;
    use crate::model::host::{Host, HostStatus};
    use crate::report::Refusal;
    use crate::scanner::session::ScanSession;
    use tokio::sync::mpsc;

    /// This host's own address, recorded up without a probe, is settled with the
    /// rest, so a finished sweep of its segment is not left resumable.
    #[test]
    fn this_hosts_own_address_is_settled_with_the_rest_of_a_sweep() {
        let plan: IpSet = "192.0.2.1-192.0.2.3".parse().expect("a range");
        let (_session, ctx) = ScanSession::builder().counting(plan.positions()).build();

        // The two neighbours answer; the middle address is this host's own.
        ctx.settle_address(
            "192.0.2.1".parse().expect("an address"),
            crate::journal::settle::Settled::Answered,
        );
        ctx.settle_address(
            "192.0.2.3".parse().expect("an address"),
            crate::journal::settle::Settled::Answered,
        );
        record_our_own_addresses(&"192.0.2.2".parse().expect("an address"), &ctx);

        assert_eq!(ctx.settlements().checkpoint().watermark, 3);
    }

    /// A scanner that claims a protocol and does nothing, standing in for a
    /// privileged strategy that was built successfully.
    struct StubScanner(Vec<Protocol>);

    #[async_trait::async_trait]
    impl PortScanner for StubScanner {
        fn kind(&self) -> ScannerKind {
            ScannerKind::SynPort
        }

        fn supported_protocols(&self) -> Vec<Protocol> {
            self.0.clone()
        }

        async fn scan(
            &mut self,
            _targets: mpsc::Receiver<PlannedTarget>,
        ) -> Result<(), StrategyError> {
            Ok(())
        }
    }

    /// A plan that meant to cover both protocols, which is every plan except
    /// the one that refused a technique its fallback cannot express.
    const BOTH: &[Protocol] = &[Protocol::Tcp, Protocol::Udp];

    fn ip_set(exprs: &[&str]) -> IpSet {
        crate::model::parse::ip::to_set(exprs, None, None).expect("hand-written targets parse")
    }

    /// The unprivileged path refuses a `/64`, as the privileged plan does.
    #[test]
    fn a_range_too_large_to_walk_is_refused_rather_than_started() {
        let (_session, ctx) = ScanSession::new();

        let kept = walkable(ip_set(&["2001:db8::/64"]), &ctx);

        assert!(kept.is_empty(), "nothing here can be walked");

        // A refusal, not a failure: nothing broke.
        assert!(ctx.failures_snapshot().is_empty(), "nothing went wrong");

        let refusals = ctx.refusals_snapshot();
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].scanner(), ScannerKind::Connect);
        assert!(
            refusals[0].reason().contains("18446744073709551616"),
            "the refusal quotes the size it is refusing: {}",
            refusals[0].reason()
        );
    }

    /// **The passes that read the store announce only what they found.** A host
    /// they match is still announced.
    #[test]
    fn the_store_passes_announce_only_the_hosts_they_found_something_on() {
        use crate::model::port::{Port, Service};
        use crate::scanner::session::ScanEvent;

        let (mut session, ctx) = ScanSession::new();
        let plain: IpAddr = "192.0.2.1".parse().expect("an address");
        let vulnerable: IpAddr = "192.0.2.2".parse().expect("an address");
        ctx.update_host(plain, |host| {
            host.set_status(HostStatus::Up);
            host.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
        });
        ctx.update_host(vulnerable, |host| {
            host.set_status(HostStatus::Up);
            host.add_port(Port::new(80, Protocol::Tcp, PortState::Open).with_service(
                Service::new("http", 90).with_cpe("cpe:/a:apache:http_server:2.4.49"),
            ));
        });
        while session.events().try_recv().is_some() {}

        run_correlation(&ctx, ServiceDetection::default());
        run_correlation(&ctx, ServiceDetection::default());
        run_cert_posture(&ctx);

        let mut announced = Vec::new();
        while let Some(event) = session.events().try_recv() {
            if let ScanEvent::HostUpdated(ip) = event {
                announced.push(ip.addr());
            }
        }
        assert_eq!(announced, [vulnerable], "announced: {announced:?}");
    }

    /// A port plan naming a range too wide to walk keeps everything else it
    /// named and hands the range back to be refused, once however many units
    /// name it.
    #[test]
    fn a_port_plan_gives_up_only_the_ranges_too_wide_to_walk() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            ip_set(&["2001:db8::/64", "192.0.2.0/30", "2001:db8:1::/126"]),
            "80".parse().expect("ports"),
        ));
        map.add_unit(TargetSet::new(
            ip_set(&["2001:db8::/64"]),
            "443".parse().expect("ports"),
        ));

        let refused = withhold_unprobeable_targets(&mut map).unwalkable;

        assert_eq!(refused.len(), 1, "one range, named twice: {refused:?}");
        assert_eq!(map.units.len(), 1, "the unit left with nothing is gone");
        assert_eq!(map.gross_targets().ok(), Some(8));
    }

    /// One unwalkable range does not refuse the rest of the set.
    #[test]
    fn the_walkable_part_of_a_mixed_set_survives() {
        let (_session, ctx) = ScanSession::new();

        let kept = walkable(
            ip_set(&["2001:db8::/64", "192.0.2.0/30", "2001:db8:1::/126"]),
            &ctx,
        );

        // Four IPv4 addresses and the four in the /126; the /64 is gone.
        assert_eq!(kept.len(), 8);
        assert_eq!(ctx.refusals_snapshot().len(), 1);
        assert!(ctx.failures_snapshot().is_empty());
    }

    /// A set that is entirely walkable is handed back untouched and files no
    /// failure, which would mark a complete scan partial.
    #[test]
    fn a_set_that_can_be_walked_is_left_alone_and_files_nothing() {
        let (_session, ctx) = ScanSession::new();

        let kept = walkable(ip_set(&["192.0.2.0/24", "2001:db8::/120"]), &ctx);

        assert_eq!(kept.len(), 512);
        assert!(ctx.failures_snapshot().is_empty());
    }

    /// IPv4 is not bounded here: a `/8` is the caller's judgement.
    #[test]
    fn a_large_ipv4_range_is_not_this_functions_business() {
        let (_session, ctx) = ScanSession::new();

        let kept = walkable(ip_set(&["10.0.0.0/8"]), &ctx);

        assert_eq!(kept.len(), 1 << 24);
        assert!(ctx.failures_snapshot().is_empty());
    }

    fn covered(scanners: Vec<Box<dyn PortScanner>>) -> Vec<Protocol> {
        let (_session, ctx) = ScanSession::new();
        ensure_coverage(
            reaching_everything(scanners),
            &ctx,
            TcpScanTechnique::Syn,
            BOTH,
            ServiceDetection::default(),
            &EvasionProfile::default(),
            &RawReach::Everything,
        )
        .routes
        .iter()
        .flat_map(|(scanner, _)| scanner.supported_protocols())
        .collect()
    }

    /// Strategies as a scan whose raw routes reach every address hands them
    /// over.
    fn reaching_everything(
        scanners: Vec<Box<dyn PortScanner>>,
    ) -> Vec<(Box<dyn PortScanner>, Reach)> {
        scanners
            .into_iter()
            .map(|scanner| (scanner, Reach::Any))
            .collect()
    }

    /// A scan whose raw strategies reach everything, independent of the machine
    /// running the tests.
    fn raw_everywhere() -> ScanCapabilities {
        ScanCapabilities {
            privilege: Privilege::Raw,
            frames_only: false,
            dns: false,
        }
    }

    /// The plan refuses what it can foresee and `ensure_coverage` catches what
    /// only the attempt reveals. A refusal the plan already made is not recorded
    /// again.
    #[test]
    fn a_refusal_the_plan_already_made_is_not_recorded_again() {
        let cfg = ZondConfig {
            tcp_technique: TcpScanTechnique::Fin,
            ..ZondConfig::default()
        };
        let (_session, ctx) = ScanSession::new();

        let _built = build_port_scanner(
            plan::PortScanPlan::build(&cfg, Privilege::Connect),
            BOTH,
            &ctx,
            0,
            cfg.probe_tuning(),
            &ZoneMap::new(),
            &RawReach::Everything,
        );

        let refusals = ctx.take_refusals();
        assert_eq!(
            refusals.len(),
            1,
            "one cause, one entry: {:?}",
            refusals.iter().map(Refusal::reason).collect::<Vec<_>>()
        );
        assert_eq!(refusals[0].scanner(), ScannerKind::TcpPort);
        assert!(refusals[0].reason().contains("fin"));
    }

    /// **An idle scan's UDP ports are refused, and not lost.**
    ///
    /// The plan holds no UDP step, so the ports reach the router with no scanner.
    /// Unless a refusal names them, the router files a failure.
    ///
    /// Run through the whole port phase, where the plan learns the targets name a
    /// UDP port. The zombie is excluded so the idle scan is refused whatever
    /// privilege runs the test, and nothing is sent.
    #[tokio::test]
    async fn an_idle_scans_udp_ports_are_refused_rather_than_lost() {
        use crate::journal::cursor::Checkpoint;
        use crate::model::exclusion::Exclusions;
        use crate::model::target::TargetSet;

        let cfg = ZondConfig {
            idle_scan: Some(crate::config::IdleScan::new(
                "192.0.2.9".parse().expect("an address"),
            )),
            exclusions: Exclusions::new(ip_set(&["192.0.2.9"])),
            ..ZondConfig::default()
        };
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            ip_set(&["192.0.2.1"]),
            "80, u:53".parse().expect("a port set"),
        ));
        let (_session, ctx) = ScanSession::new();
        let caps = ScanCapabilities {
            privilege: Privilege::Connect,
            frames_only: false,
            dns: false,
        };

        run_port_phase(
            map,
            &ZoneMap::new(),
            None,
            &ctx,
            caps,
            &cfg,
            Checkpoint::default(),
            false,
        )
        .await;

        let failures = ctx.take_failures();
        assert!(
            failures.is_empty(),
            "a port the plan chose not to probe is not one the scan lost: {failures:?}"
        );
        let refusals = ctx.take_refusals();
        let reasons: Vec<&str> = refusals.iter().map(Refusal::reason).collect();
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("udp") && reason.contains("idle scan")),
            "the refusal names UDP under an idle scan: {reasons:?}"
        );
    }

    /// Which of the three a phase is, by what its frames cannot reach against
    /// what it probes.
    #[test]
    fn raw_reach_is_everything_part_or_nothing() {
        let probed = ip_set(&["127.0.0.1", "192.0.2.8"]);

        assert!(matches!(
            RawReach::of(&probed, IpSet::new()),
            RawReach::Everything
        ));
        assert!(matches!(
            RawReach::of(&probed, ip_set(&["127.0.0.1"])),
            RawReach::AllBut(_)
        ));
        assert!(matches!(
            RawReach::of(&probed, ip_set(&["127.0.0.1", "192.0.2.8"])),
            RawReach::Nothing(_)
        ));
    }

    /// A frames-only scan of nothing but loopback, or of one box behind a VPN,
    /// opens no raw strategy. The connect strategies take every target, nothing
    /// is reported as failing, and the phase records connect evidence.
    #[test]
    fn nothing_within_a_frames_reach_opens_no_raw_strategy() {
        let cfg = ZondConfig::default();
        let (_session, ctx) = ScanSession::new();

        let mut plan = plan::PortScanPlan::build(&cfg, Privilege::Raw);
        // The targets name a UDP port, so the plan carries a UDP step to be
        // replaced by a connect stand-in.
        plan.cover_udp(Privilege::Raw);
        let built = build_port_scanner(
            plan,
            BOTH,
            &ctx,
            1,
            cfg.probe_tuning(),
            &ZoneMap::new(),
            &RawReach::Nothing(ip_set(&["127.0.0.1"])),
        );

        assert_eq!(
            built.scanner.supported_protocols(),
            vec![Protocol::Tcp, Protocol::Udp],
            "and the connect strategies cover both protocols"
        );
        assert!(ctx.take_failures().is_empty(), "declining is not failing");
        assert!(ctx.take_refusals().is_empty());
        assert_eq!(ctx.take_reached_by_connect(&[]).len(), 1);
    }

    /// **A technique refused for a target is one refusal, and not a scanner
    /// failure as well.**
    ///
    /// A FIN scan of loopback with no raw socket has no connect form, so its TCP
    /// ports are refused, at planning on the connect path and in the phase on the
    /// frames path. The targets still reach the router, unprobed and owed to a
    /// resume, but are not counted again as lost. Nothing is reached by connect.
    #[tokio::test]
    async fn a_refused_technique_is_reported_once_and_not_as_a_failure() {
        let cfg = ZondConfig {
            tcp_technique: TcpScanTechnique::Fin,
            ..ZondConfig::default()
        };
        let loopback = crate::model::target::Target {
            ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port: 80,
            protocol: Protocol::Tcp,
        };
        let paths = [
            ("connect", Privilege::Connect, RawReach::Everything),
            (
                "frames",
                Privilege::Raw,
                RawReach::Nothing(ip_set(&["127.0.0.1"])),
            ),
        ];

        for (path, privilege, raw) in paths {
            let (_session, ctx) = ScanSession::new();
            let mut built = build_port_scanner(
                plan::PortScanPlan::build(&cfg, privilege),
                &[Protocol::Tcp],
                &ctx,
                1,
                cfg.probe_tuning(),
                &ZoneMap::new(),
                &raw,
            );
            let (tx, rx) = mpsc::channel(1);
            tx.send(PlannedTarget::new(0, loopback))
                .await
                .expect("the router is listening");
            drop(tx);
            built
                .scanner
                .scan(rx)
                .await
                .expect("a refusal is not an error");

            let refusals = ctx.take_refusals();
            assert_eq!(refusals.len(), 1, "{path}: {refusals:?}");
            assert!(refusals[0].reason().contains("fin"), "{path}: {refusals:?}");
            let failures = ctx.take_failures();
            assert!(failures.is_empty(), "{path}: {failures:?}");
            assert!(
                ctx.take_reached_by_connect(&[]).is_empty(),
                "{path}: nothing was reached by connect"
            );
            assert_eq!(
                ctx.settlements()
                    .count(crate::journal::settle::Outcome::Unroutable),
                1,
                "{path}: the refused target is still owed a probe"
            );
        }
    }

    /// Every message emitted while it is the default subscriber, in order.
    ///
    /// Spans are accepted and ignored, since no line under test is inside one.
    #[derive(Clone, Default)]
    struct Heard(Arc<std::sync::Mutex<Vec<String>>>);

    impl tracing::Subscriber for Heard {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Message<'a>(&'a mut String);
            impl tracing::field::Visit for Message<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        *self.0 = format!("{value:?}");
                    }
                }
            }
            let mut message = String::new();
            event.record(&mut Message(&mut message));
            self.0.lock().expect("an unpoisoned log").push(message);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// A run without raw sockets opens with one line saying what it probes with
    /// and what root would add, which differs between a sweep and a port scan.
    /// UDP ports are named too.
    #[test]
    fn an_unprivileged_run_says_how_it_probes_and_what_root_would_add() {
        let unprivileged = ScanCapabilities {
            privilege: Privilege::Connect,
            frames_only: false,
            dns: false,
        };
        let map = |ports: &str| {
            let mut map = TargetMap::new();
            map.add_unit(crate::model::target::TargetSet::new(
                "192.0.2.1".parse().expect("an address"),
                ports.parse().expect("a specification"),
            ));
            map
        };
        let cfg = ZondConfig::default();

        for (probing, expected) in [
            (
                Probing::sweep(),
                "no raw sockets: probing by TCP connect (sudo for ARP)",
            ),
            (
                Probing::ports(&cfg, &map("22")),
                "no raw sockets: probing by TCP connect (sudo for SYN)",
            ),
            (
                Probing::ports(&cfg, &map("22, u:53")),
                "no raw sockets: TCP by connect, plain UDP (sudo for SYN)",
            ),
        ] {
            let heard = Heard::default();
            tracing::subscriber::with_default(heard.clone(), || {
                unprivileged.announce(probing, false, None);
            });

            let said = heard.0.lock().expect("an unpoisoned log").clone();
            assert_eq!(said, [expected], "{probing:?}");
        }
    }

    /// A run told to send no DNS says, once at detail level, that its hostnames
    /// come from the hosts file, whichever privilege it holds.
    #[test]
    fn a_run_without_dns_says_where_its_names_come_from_whatever_its_privilege() {
        let said = |no_dns| {
            let cfg = ZondConfig {
                no_dns,
                ..ZondConfig::default()
            };
            crate::logging::logged(|| {
                ScanCapabilities::resolve(&cfg, None, &IpSet::new(), interface::FrameSender::Probe);
            })
            .into_iter()
            .map(|line| (line.verbosity, line.message))
            .collect::<Vec<_>>()
        };

        assert_eq!(
            said(true),
            [(1, "hostnames from the hosts file only (DNS off)".to_owned())],
            "under {:?}",
            Privilege::current()
        );
        assert_eq!(said(false), [], "under {:?}", Privilege::current());
    }

    /// An idle scan's opening line names the zombie it probes through, not the
    /// TCP technique, which it never sends, nor the connect fallback, which it
    /// refuses.
    #[test]
    fn an_idle_scan_announces_its_zombie_and_no_technique() {
        let zombie: IpAddr = "192.0.2.9".parse().expect("an address");
        let cfg = ZondConfig {
            tcp_technique: TcpScanTechnique::Fin,
            idle_scan: Some(crate::config::IdleScan::new(zombie)),
            ..ZondConfig::default()
        };
        let mut map = TargetMap::new();
        map.add_unit(crate::model::target::TargetSet::new(
            "192.0.2.1".parse().expect("an address"),
            "22, u:53".parse().expect("a specification"),
        ));
        let probing = Probing::ports(&cfg, &map);

        for (privilege, expected) in [
            (
                Privilege::Raw,
                vec!["probing through zombie 192.0.2.9 (link-layer frames)"],
            ),
            // Refused, and the refusal says why; nothing is probed to announce.
            (Privilege::Connect, vec![]),
        ] {
            let caps = ScanCapabilities {
                privilege,
                frames_only: false,
                dns: false,
            };
            let heard = Heard::default();
            tracing::subscriber::with_default(heard.clone(), || {
                caps.announce(probing, false, None);
            });

            let said = heard.0.lock().expect("an unpoisoned log").clone();
            assert_eq!(said, expected, "{privilege:?}");
        }
    }

    /// A raw run's opening line names the probes its ports are sent, beside the
    /// liveness pass's SYN, each once.
    #[test]
    fn a_raw_run_names_the_technique_and_every_protocol_it_probes() {
        let raw = ScanCapabilities {
            privilege: Privilege::Raw,
            frames_only: false,
            dns: false,
        };
        let unit = |ports: &str| {
            let mut map = TargetMap::new();
            map.add_unit(crate::model::target::TargetSet::new(
                "192.0.2.1".parse().expect("an address"),
                ports.parse().expect("a specification"),
            ));
            map
        };
        let map = unit("22, u:53, s:2905");
        let fin = ZondConfig {
            tcp_technique: TcpScanTechnique::Fin,
            ..ZondConfig::default()
        };
        let udp_only = unit("u:53");

        for (probing, raw_sockets, expected) in [
            (
                Probing::sweep(),
                true,
                "probing with ARP, ICMPv6 and SYN (raw sockets)",
            ),
            (
                Probing::ports(&ZondConfig::default(), &map),
                true,
                "probing with ARP, ICMPv6, SYN, UDP and SCTP INIT (raw sockets)",
            ),
            (
                Probing::ports(&fin, &map),
                false,
                "probing with ARP, ICMPv6, SYN, FIN, UDP and SCTP INIT (link-layer frames)",
            ),
            (
                Probing::ports(&fin, &udp_only),
                true,
                "probing with ARP, ICMPv6, SYN and UDP (raw sockets)",
            ),
        ] {
            let heard = Heard::default();
            tracing::subscriber::with_default(heard.clone(), || {
                raw.announce(probing, raw_sockets, None);
            });

            let said = heard.0.lock().expect("an unpoisoned log").clone();
            assert_eq!(said, [expected], "{probing:?}");
        }
    }

    /// A frames-only run whose every target is beyond a frame's reach, such as
    /// loopback, announces the connect it probes by and why.
    #[test]
    fn a_run_whose_every_target_is_beyond_frames_announces_the_connect() {
        let frames = ScanCapabilities {
            privilege: Privilege::Raw,
            frames_only: true,
            dns: false,
        };
        let mut map = TargetMap::new();
        map.add_unit(crate::model::target::TargetSet::new(
            "127.0.0.1".parse().expect("an address"),
            "22, u:53".parse().expect("a specification"),
        ));
        let tcp_only = {
            let mut map = TargetMap::new();
            map.add_unit(crate::model::target::TargetSet::new(
                "127.0.0.1".parse().expect("an address"),
                "22".parse().expect("a specification"),
            ));
            map
        };
        let cfg = ZondConfig::default();
        for (probing, expected) in [
            (Probing::sweep(), "probing by TCP connect (loopback)"),
            (
                Probing::ports(&cfg, &tcp_only),
                "probing by TCP connect (loopback)",
            ),
            (
                Probing::ports(&cfg, &map),
                "probing by TCP connect and plain UDP (loopback)",
            ),
        ] {
            let heard = Heard::default();
            tracing::subscriber::with_default(heard.clone(), || {
                frames.announce(probing, false, Some("loopback"));
            });
            let said = heard.0.lock().expect("an unpoisoned log").clone();
            assert_eq!(said, [expected], "{probing:?}");
        }

        let beyond = frames.beyond_frames(
            &ip_set(&["127.0.0.1", "::1"]),
            &[],
            interface::FrameSender::Probe,
        );
        assert_eq!(beyond.targets.len(), 2);
        assert_eq!(beyond.reasons(), "loopback");
    }

    /// The opening line names the route the probes leave by: a root run told to
    /// build its own frames sends nothing through a raw socket.
    #[test]
    fn a_run_sending_its_own_frames_names_them_whatever_its_privilege() {
        assert!(!by_raw_socket(SendMode::Ethernet, true));
        assert!(!by_raw_socket(SendMode::Ethernet, false));
        assert!(by_raw_socket(SendMode::RawSocket, true));
        // No raw socket, whatever was asked for: frames are all the run has.
        assert!(!by_raw_socket(SendMode::RawSocket, false));
    }

    /// A raw sweep asks loopback, and whatever nothing routes to, by connect, and
    /// says which addresses and why at detail level, as the port scan does.
    #[test]
    fn a_raw_sweep_names_what_it_asks_by_connect_and_why() {
        let (_session, ctx) = ScanSession::new();
        let plan = plan::DiscoveryPlan::build(
            ip_set(&["127.0.0.1", "::1"]),
            strategy::local::Scope::Targeted,
            &crate::model::exclusion::Exclusions::default(),
            &[],
        );

        let heard = Heard::default();
        tracing::subscriber::with_default(heard.clone(), || {
            reached_by_connect(&plan, interface::BeyondFrames::default(), &ctx);
        });

        let said = heard.0.lock().expect("an unpoisoned log").clone();
        assert_eq!(said, ["sweep by connect: 127.0.0.1 +1 (loopback)"]);
        assert_eq!(ctx.take_reached_by_connect(&[]).len(), 2);
    }

    /// A frames-only run whose every target is out of a frame's reach gives that
    /// as the refusal's reason, not a missing raw socket: it already holds the
    /// link layer.
    #[test]
    fn a_frames_only_refusal_names_the_frames_reach_rather_than_privilege() {
        let cfg = ZondConfig {
            tcp_technique: TcpScanTechnique::Fin,
            ..ZondConfig::default()
        };
        let (_session, ctx) = ScanSession::new();
        let mut plan = plan::PortScanPlan::build(&cfg, Privilege::Raw);
        plan.cover_sctp(Privilege::Raw);

        let _built = build_port_scanner(
            plan,
            &[Protocol::Tcp, Protocol::Sctp],
            &ctx,
            2,
            cfg.probe_tuning(),
            &ZoneMap::new(),
            &RawReach::Nothing(ip_set(&["127.0.0.1"])),
        );

        let refusals = ctx.take_refusals();
        let reasons: Vec<&str> = refusals.iter().map(Refusal::reason).collect();
        assert_eq!(reasons.len(), 2, "one for each protocol: {reasons:?}");
        for reason in reasons {
            assert!(
                reason.contains("needs a raw socket"),
                "the frames path's reason: {reason}"
            );
            assert!(
                !reason.contains("needs raw sockets"),
                "not the connect path's: {reason}"
            );
            assert!(
                reason.contains("on 1 target:"),
                "and it counts the one target it names: {reason}"
            );
        }
    }

    /// With no privileged scanner at all, both connect fallbacks stand in.
    #[test]
    fn an_unprivileged_scan_covers_both_protocols() {
        let protocols = covered(Vec::new());
        assert!(protocols.contains(&Protocol::Tcp));
        assert!(protocols.contains(&Protocol::Udp));
    }

    /// The per-protocol fallback: a host that can build the raw UDP scanner but
    /// not the SYN one still probes TCP.
    #[test]
    fn a_protocol_without_a_privileged_scanner_still_gets_a_fallback() {
        let protocols = covered(vec![Box::new(StubScanner(vec![Protocol::Udp]))]);
        assert!(
            protocols.contains(&Protocol::Tcp),
            "TCP targets would be silently dropped"
        );
        assert!(protocols.contains(&Protocol::Udp));
    }

    /// A connect scan substitutes only for a SYN scan. For another technique, the
    /// TCP half is left undone and reported.
    ///
    /// The case is a plan that did intend TCP, whose raw socket then would not
    /// open. A plan that never intended it refused earlier; see
    /// `a_refusal_the_plan_already_made_is_not_recorded_again`.
    #[test]
    fn a_technique_the_fallback_cannot_express_is_reported_rather_than_substituted() {
        let (_session, ctx) = ScanSession::new();
        let scanners = ensure_coverage(
            Vec::new(),
            &ctx,
            TcpScanTechnique::Fin,
            BOTH,
            ServiceDetection::default(),
            &EvasionProfile::default(),
            &RawReach::Everything,
        )
        .routes;
        let protocols: Vec<Protocol> = scanners
            .iter()
            .flat_map(|(scanner, _)| scanner.supported_protocols())
            .collect();

        assert!(
            !protocols.contains(&Protocol::Tcp),
            "a connect scan cannot send a FIN and must not pretend to"
        );

        let refusals = ctx.take_refusals();
        assert_eq!(refusals.len(), 1, "the caller has to be told");
        assert_eq!(refusals[0].scanner(), ScannerKind::TcpPort);
        assert!(
            refusals[0].reason().contains("fin"),
            "the refusal has to name the technique: {}",
            refusals[0].reason()
        );
    }

    /// And the mirror case: raw TCP available, raw UDP not.
    #[test]
    fn a_privileged_tcp_only_scan_falls_back_for_udp() {
        let protocols = covered(vec![Box::new(StubScanner(vec![Protocol::Tcp]))]);
        assert!(protocols.contains(&Protocol::Tcp));
        assert!(
            protocols.contains(&Protocol::Udp),
            "UDP targets would be silently dropped"
        );
    }

    /// When the privileged scanners already cover everything, no fallback is
    /// added.
    #[test]
    fn fully_covered_protocols_gain_no_fallback() {
        let (_session, ctx) = ScanSession::new();
        let scanners = ensure_coverage(
            reaching_everything(vec![
                Box::new(StubScanner(vec![Protocol::Tcp])),
                Box::new(StubScanner(vec![Protocol::Udp])),
            ]),
            &ctx,
            TcpScanTechnique::Syn,
            BOTH,
            ServiceDetection::default(),
            &EvasionProfile::default(),
            &RawReach::Everything,
        )
        .routes;
        // Two scanners in, two out.
        assert_eq!(scanners.len(), 2);
    }

    /// What a frames-only scan's raw routes cannot reach, as the port phase
    /// hands it over: loopback.
    fn loopback_beyond() -> Arc<IpSet> {
        let mut set = IpSet::new();
        set.insert(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        Arc::new(set)
    }

    /// Raw routes that are handed everything but `beyond`, as `build_port_scanner`
    /// hands them over when the raw strategies send frames alone.
    fn raw_routes(
        beyond: &Arc<IpSet>,
        protocols: &[Protocol],
    ) -> Vec<(Box<dyn PortScanner>, Reach)> {
        protocols
            .iter()
            .map(|protocol| {
                let scanner: Box<dyn PortScanner> = Box::new(StubScanner(vec![*protocol]));
                (scanner, Reach::Except(Arc::clone(beyond)))
            })
            .collect()
    }

    /// Which protocols are covered for the addresses the raw routes are not
    /// handed.
    fn covered_beyond(routes: &[(Box<dyn PortScanner>, Reach)]) -> Vec<Protocol> {
        routes
            .iter()
            .filter(|(_, reach)| matches!(reach, Reach::Only(_)))
            .flat_map(|(scanner, _)| scanner.supported_protocols())
            .collect()
    }

    /// A frames-only scan's raw routes miss the addresses a frame cannot reach.
    /// Each protocol the raw routes cover gets a connect strategy for those
    /// alone, and the phase records that it did.
    #[test]
    fn what_frames_cannot_reach_gets_the_connect_strategies_for_itself_alone() {
        let (_session, ctx) = ScanSession::new();
        let beyond = loopback_beyond();

        let routes = ensure_coverage(
            raw_routes(&beyond, BOTH),
            &ctx,
            TcpScanTechnique::Syn,
            BOTH,
            ServiceDetection::default(),
            &EvasionProfile::default(),
            &RawReach::AllBut(IpSet::clone(&beyond)),
        )
        .routes;

        assert_eq!(covered_beyond(&routes), vec![Protocol::Tcp, Protocol::Udp]);
        assert_eq!(routes.len(), 4, "the raw routes are kept beside them");
        assert!(ctx.take_refusals().is_empty());
        assert_eq!(
            ctx.take_reached_by_connect(&[]).len(),
            1,
            "the phase has to say its loopback evidence is connect evidence"
        );
    }

    /// A connect scan cannot send a FIN, so the TCP ports beyond a frame's reach
    /// are refused. UDP still has its stand-in.
    #[test]
    fn a_technique_connect_cannot_express_is_refused_for_those_targets_alone() {
        let (_session, ctx) = ScanSession::new();
        let beyond = loopback_beyond();

        let routes = ensure_coverage(
            raw_routes(&beyond, BOTH),
            &ctx,
            TcpScanTechnique::Fin,
            BOTH,
            ServiceDetection::default(),
            &EvasionProfile::default(),
            &RawReach::AllBut(IpSet::clone(&beyond)),
        )
        .routes;

        assert_eq!(covered_beyond(&routes), vec![Protocol::Udp]);
        let refusals = ctx.take_refusals();
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].scanner(), ScannerKind::TcpPort);
        assert!(
            refusals[0].reason().contains("fin") && refusals[0].reason().contains("1 target"),
            "the refusal names the technique and how much it left: {}",
            refusals[0].reason()
        );
    }

    /// Nothing stands in for an INIT, on part of a scan as on the whole. Refused,
    /// and not recorded as reached by connect.
    #[test]
    fn sctp_on_what_frames_cannot_reach_is_refused_and_nothing_is_reached_by_connect() {
        let (_session, ctx) = ScanSession::new();
        let beyond = loopback_beyond();

        let routes = ensure_coverage(
            raw_routes(&beyond, &[Protocol::Sctp]),
            &ctx,
            TcpScanTechnique::Syn,
            &[Protocol::Sctp],
            ServiceDetection::default(),
            &EvasionProfile::default(),
            &RawReach::AllBut(IpSet::clone(&beyond)),
        )
        .routes;

        assert!(covered_beyond(&routes).is_empty());
        let refusals = ctx.take_refusals();
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].scanner(), ScannerKind::SctpPort);
        assert!(ctx.take_reached_by_connect(&[]).is_empty());
    }

    /// A protocol whose raw strategy did not open at all is refused once, for
    /// every address, including those beyond a frame's reach.
    #[test]
    fn a_protocol_with_no_strategy_is_not_refused_twice_for_part_of_the_scan() {
        let (_session, ctx) = ScanSession::new();

        let _ = ensure_coverage(
            Vec::new(),
            &ctx,
            TcpScanTechnique::Syn,
            &[Protocol::Sctp],
            ServiceDetection::default(),
            &EvasionProfile::default(),
            &RawReach::AllBut(IpSet::clone(&loopback_beyond())),
        );

        let refusals = ctx.take_refusals();
        assert_eq!(
            refusals.len(),
            1,
            "one cause, one entry: {:?}",
            refusals.iter().map(Refusal::reason).collect::<Vec<_>>()
        );
    }

    /// A plan that never intended TCP gets no connect fallback for it either.
    #[test]
    fn a_protocol_the_plan_left_out_gains_no_fallback_and_no_second_refusal() {
        let (_session, ctx) = ScanSession::new();
        let scanners = ensure_coverage(
            Vec::new(),
            &ctx,
            TcpScanTechnique::Fin,
            &[Protocol::Udp],
            ServiceDetection::default(),
            &EvasionProfile::default(),
            &RawReach::Everything,
        )
        .routes;

        let protocols: Vec<Protocol> = scanners
            .iter()
            .flat_map(|(scanner, _)| scanner.supported_protocols())
            .collect();
        assert_eq!(protocols, vec![Protocol::Udp]);
        assert!(
            ctx.take_failures().is_empty(),
            "the plan already said why, in the same words"
        );
    }

    /// A sweep that learned a host's hardware and its name concludes an OS from
    /// them.
    #[test]
    fn a_discovery_sweep_now_names_what_its_own_findings_imply() {
        let (_session, ctx) = ScanSession::new();
        let ip: IpAddr = "192.0.2.1".parse().expect("a valid address");

        ctx.update_host(ip, |host| {
            host.record_mac("a4:83:e7:00:00:01".parse().expect("an Apple address"));
            host.set_hostname(Some("MacBook-Pro".to_owned()));
        });

        run_passive_os_identification(&ctx, OsDetection::Passive);

        let named = ctx
            .read_host(ip, |host| host.os().map(ToString::to_string))
            .expect("the host is in the store");
        assert!(
            named.as_deref().is_some_and(|os| os.contains("macOS")),
            "{named:?}"
        );
    }

    /// `Off` identifies nothing, though this pass would cost no packets.
    #[test]
    fn detection_turned_off_identifies_nothing() {
        let (_session, ctx) = ScanSession::new();
        let ip: IpAddr = "192.0.2.1".parse().expect("a valid address");

        ctx.update_host(ip, |host| {
            host.record_mac("a4:83:e7:00:00:01".parse().expect("an Apple address"));
            host.set_hostname(Some("MacBook-Pro".to_owned()));
        });

        run_passive_os_identification(&ctx, OsDetection::Off);

        let named = ctx
            .read_host(ip, |host| host.os().is_some())
            .expect("the host is in the store");
        assert!(!named);
    }

    /// A host that has already said what kernel it runs is not asked again.
    ///
    /// The test is whether the kernel is known, not whether the host was named:
    /// a host reported as `Linux · Debian 13` is still asked.
    #[tokio::test(flavor = "current_thread")]
    async fn the_kernel_probe_skips_only_hosts_whose_kernel_is_known() {
        use crate::model::host::{HostStatus, OsFingerprint, StatusProtocol, StatusReason};

        let up = |host: &mut crate::model::host::Host| {
            host.record_evidence(
                HostStatus::Up,
                StatusReason::new(StatusProtocol::Arp, "an address resolution reply"),
            );
        };

        let (_session, ctx) = ScanSession::new();
        // Named, with no kernel: still asked. On loopback, so the question never
        // leaves the machine: Linux answers port-unreachable and macOS, holding
        // only `127.0.0.1`, drops it.
        let named: IpAddr = "127.0.0.2".parse().expect("a valid address");
        ctx.update_host(named, |host| {
            up(host);
            host.set_os(OsFingerprint::new("Debian", 84).with_family("Linux"));
        });
        // Kernel already known: nothing left to ask for.
        let known: IpAddr = "192.0.2.11".parse().expect("a valid address");
        ctx.update_host(known, |host| {
            up(host);
            host.set_os(
                OsFingerprint::new("Debian", 84)
                    .with_family("Linux")
                    .with_kernel("6.1.0"),
            );
        });

        // No agent answers, so nothing is recorded; this pins that the phase
        // runs without failing for this store.
        run_active_os_snmp(&ctx, OsDetection::Active, &PortSet::new()).await;

        assert!(ctx.take_failures().is_empty(), "declining is not failing");
        assert!(
            ctx.read_host(known, |host| host
                .os()
                .and_then(|os| os.kernel().map(ToOwned::to_owned)))
                .flatten()
                .as_deref()
                == Some("6.1.0"),
            "a kernel already on record is left as it was"
        );
    }

    /// A host that answers has proved a port open, and the port is recorded with
    /// the evidence that found it. The detection level requested this traffic.
    #[test]
    fn a_port_the_kernel_probe_found_is_recorded_with_what_found_it() {
        let port = crate::fingerprint::baseline_port(161, Protocol::Udp, PortState::Open)
            .with_discovery(PortDiscovery::new(ScanResponse::UdpResponse));

        assert_eq!(port.number(), 161);
        assert_eq!(port.protocol(), Protocol::Udp);
        assert_eq!(port.state(), PortState::Open);
        assert_eq!(
            port.discovery().map(|found| found.reason().clone()),
            Some(ScanResponse::UdpResponse),
            "a report has to be able to tell this from a port the scan established"
        );
    }

    /// Below `Active` this sends nothing, like every other probe of its own.
    #[tokio::test(flavor = "current_thread")]
    async fn the_kernel_probe_sends_nothing_below_the_active_level() {
        for level in [OsDetection::Off, OsDetection::Passive] {
            let (_session, ctx) = ScanSession::new();
            let ip: IpAddr = "192.0.2.12".parse().expect("a valid address");
            ctx.update_host(ip, |host| {
                host.record_evidence(
                    crate::model::host::HostStatus::Up,
                    crate::model::host::StatusReason::new(
                        crate::model::host::StatusProtocol::Arp,
                        "an address resolution reply",
                    ),
                );
            });

            run_active_os_snmp(&ctx, level, &PortSet::new()).await;

            assert!(
                ctx.take_probe_stats().is_empty(),
                "{level} put a probe on the wire"
            );
        }
    }

    /// The series probe does not open a raw socket to probe nothing. Every host
    /// here answered no TCP probe, the ordinary state after a discovery sweep,
    /// and the phase notices from the store before reaching for a transport.
    #[tokio::test(flavor = "current_thread")]
    async fn the_series_probe_declines_when_no_host_has_a_port_to_ask_again() {
        let (_session, ctx) = ScanSession::new();
        let ip: IpAddr = "192.0.2.3".parse().expect("a valid address");
        ctx.update_host(ip, |host| {
            host.record_evidence(
                crate::model::host::HostStatus::Up,
                crate::model::host::StatusReason::new(
                    crate::model::host::StatusProtocol::Arp,
                    "an address resolution reply",
                ),
            );
        });

        run_active_os_series(
            &ctx,
            OsDetection::Active,
            ProbeTuning::default(),
            raw_everywhere(),
        )
        .await;

        assert!(
            ctx.take_failures().is_empty(),
            "declining is not failing: there was nothing to follow, so nothing \
             should have been opened"
        );
        assert!(
            ctx.read_host(ip, |host| host.os().is_none())
                .expect("the host is in the store"),
            "and nothing may be concluded from probes that were never sent"
        );
    }

    /// Every level below `Active` sends nothing of its own, so a scan at the
    /// default sends exactly what one with detection off does.
    #[tokio::test(flavor = "current_thread")]
    async fn the_series_probe_sends_nothing_below_the_active_level() {
        use crate::model::port::{Port, PortState, Protocol};

        for level in [OsDetection::Off, OsDetection::Passive] {
            let (_session, ctx) = ScanSession::new();
            let ip: IpAddr = "192.0.2.4".parse().expect("a valid address");
            // A host that would be followed, so only the level declines.
            ctx.update_host(ip, |host| {
                host.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
            });

            run_active_os_series(&ctx, level, ProbeTuning::default(), raw_everywhere()).await;

            assert!(
                ctx.take_probe_stats().is_empty(),
                "{level} put a scanner on the wire"
            );
        }
    }

    /// A host with nothing to go on is left alone.
    #[test]
    fn a_host_with_nothing_to_go_on_is_left_as_it_was() {
        let (_session, ctx) = ScanSession::new();
        let ip: IpAddr = "192.0.2.2".parse().expect("a valid address");

        ctx.update_host(ip, |host| {
            host.record_mac(
                "02:00:5e:00:53:04"
                    .parse()
                    .expect("a locally administered address"),
            );
        });

        run_passive_os_identification(&ctx, OsDetection::Passive);

        let named = ctx
            .read_host(ip, |host| host.os().is_some())
            .expect("the host is in the store");
        assert!(!named);
    }

    /// A context whose store already holds `hosts`, as a finished liveness phase
    /// would have left it.
    fn store_holding(hosts: Vec<Host>) -> (ScanSession, ScanContext) {
        let (session, ctx) = ScanSession::new();
        for host in hosts {
            ctx.store.insert(host.scoped_ip(), host);
        }
        (session, ctx)
    }

    fn host_at(ip: &str, status: HostStatus) -> Host {
        let mut host = Host::new(ip.parse().expect("an address"));
        host.set_status(status);
        host
    }

    /// Port probes standing in for a liveness pass file as silent, and forget,
    /// the records heard nothing from at addresses fully asked, and as undecided
    /// those with a port never asked. One that answered is a host; one nothing
    /// could be sent to is named as such; an address outside the phase is left
    /// alone.
    #[test]
    fn the_silent_are_the_unheard_the_port_probes_finished_asking() {
        use crate::model::port::Port;

        let unheard = |ip: &str, state: PortState| {
            let mut host = host_at(ip, HostStatus::Unknown);
            host.add_port(Port::new(443, Protocol::Tcp, state));
            host
        };
        let (session, ctx) = store_holding(vec![
            host_at("192.0.2.1", HostStatus::Up),
            unheard("192.0.2.2", PortState::NoReply),
            unheard("192.0.2.3", PortState::Unasked),
            unheard("192.0.2.4", PortState::NoReply),
            unheard("192.0.2.9", PortState::NoReply),
        ]);
        ctx.record_unroutable("192.0.2.4".parse().expect("an address"));

        forget_the_silent(&ctx, &ip_set(&["192.0.2.1-192.0.2.4"]));

        let silent: Vec<IpAddr> = ctx.take_silent().iter().collect();
        assert_eq!(silent, ["192.0.2.2".parse::<IpAddr>().expect("an address")]);
        let undecided: Vec<IpAddr> = ctx.take_undecided().iter().collect();
        assert_eq!(
            undecided,
            ["192.0.2.3".parse::<IpAddr>().expect("an address")]
        );
        let kept: Vec<String> = session
            .hosts()
            .snapshot()
            .iter()
            .map(|host| host.primary_ip().to_string())
            .collect();
        assert_eq!(kept, ["192.0.2.1", "192.0.2.4", "192.0.2.9"]);
    }

    /// A record its own budget left part-asked is undecided, not silent, and
    /// named among those the budget left.
    #[test]
    fn a_host_left_early_is_undecided_rather_than_silent() {
        use crate::model::port::Port;

        let (session, ctx) = ScanSession::builder()
            .host_timeout(Some(std::time::Duration::ZERO))
            .build();
        let address: IpAddr = "192.0.2.2".parse().expect("an address");
        ctx.update_host(address, |host| {
            host.add_port(Port::new(443, Protocol::Tcp, PortState::NoReply));
        });
        assert!(
            ctx.host_expired(address),
            "the budget is spent before it is asked"
        );

        forget_the_silent(&ctx, &ip_set(&["192.0.2.2"]));

        assert!(ctx.take_silent().is_empty());
        assert!(ctx.take_undecided().contains(&address));
        assert!(!session.hosts().contains(address));
    }

    /// A host the store holds but that never answered is not a host to spend a
    /// probe per port on.
    ///
    /// A target nothing answers for usually leaves no store entry, so this
    /// filter is only reached by a host recorded but not alive.
    #[test]
    fn a_host_that_did_not_answer_is_not_live() {
        for status in [HostStatus::Down, HostStatus::Unknown] {
            let (_session, ctx) = store_holding(vec![host_at("192.0.2.1", status)]);

            assert!(
                live_addresses(&ctx).is_empty(),
                "{status:?} was treated as alive"
            );
        }
    }

    #[test]
    fn a_host_that_answered_is_live() {
        let (_session, ctx) = store_holding(vec![host_at("192.0.2.1", HostStatus::Up)]);
        let live = live_addresses(&ctx);

        assert!(live.contains(&"192.0.2.1".parse::<IpAddr>().expect("an address")));
        assert_eq!(live.len(), 1);
    }

    /// A dual-stack machine is one host filed under one address. If it answered
    /// over IPv6, its IPv4 address is still live.
    #[test]
    fn every_address_of_a_live_host_is_live() {
        let mut host = host_at("2001:db8::1", HostStatus::Up);
        host.add_ip("192.0.2.1".parse().expect("an address"));

        let (_session, ctx) = store_holding(vec![host]);
        let live = live_addresses(&ctx);

        assert!(
            live.contains(&"192.0.2.1".parse::<IpAddr>().expect("an address")),
            "the targeted address was lost because the host was filed elsewhere"
        );
        assert!(live.contains(&"2001:db8::1".parse::<IpAddr>().expect("an address")));
    }

    /// Nothing answered, so nothing is live. The plan is unchanged; every target
    /// is settled as [`Skipped`](crate::journal::settle::Outcome::Skipped).
    #[test]
    fn an_empty_store_has_nothing_live() {
        let (_session, ctx) = store_holding(Vec::new());

        assert!(live_addresses(&ctx).is_empty());
    }

    /// A scan that identified software carries the vulnerabilities that
    /// identification implies, from a step of its own.
    #[test]
    fn correlation_records_a_known_vulnerability_against_the_software_it_names() {
        use crate::model::ip::scoped::ScopedIp;
        use crate::model::port::{Port, PortState, Protocol, Service};

        let (session, ctx) = crate::scanner::session::ScanSession::new();
        let ip: std::net::IpAddr = "203.0.113.1".parse().expect("literal");
        ctx.write_host(ScopedIp::unscoped(ip), |host| {
            let service = Service::new("http", 90).with_cpe("cpe:/a:apache:http_server:2.4.49");
            host.add_port(Port::new(80, Protocol::Tcp, PortState::Open).with_service(service));
            true
        });

        run_correlation(&ctx, ServiceDetection::Probe);

        let host = session.hosts().get(ip).expect("the scanned host");
        let port = host
            .ports()
            .find(|port| port.number() == 80)
            .expect("port 80");
        assert!(
            port.findings()
                .any(|f| f.confidence() == crate::model::confidence::Confidence::Probable),
            "the vulnerable Apache build should have been correlated"
        );
        assert!(
            port.findings()
                .any(|f| f.detection().id() == "zond:cve-kev")
        );
    }

    /// **The scanme host end to end.** Its SSH and HTTP services as the banner
    /// analyzers read them off the real banners, correlated by the scan's own
    /// pass with Ubuntu's real data on the scan's detections: the OpenSSH
    /// build's upstream vulnerabilities that Ubuntu fixed in it or that never
    /// affected 14.04 are withdrawn, and the Apache build, whose banner hides
    /// its patch level, is placed by the release the SSH banner names and is
    /// never reported as surely as an upstream release.
    #[cfg(feature = "import-distro")]
    #[test]
    fn a_scan_judges_a_distribution_build_by_the_data_on_its_detections() {
        use crate::fingerprint::{
            Analyzer, BannerRegexAnalyzer, Collected, HttpHeadersAnalyzer, PortContext,
            ResponseSet, ServiceVerdict,
        };
        use crate::model::confidence::Confidence;
        use crate::model::ip::scoped::ScopedIp;
        use crate::model::port::{Port, PortState, Protocol};

        let identify = |port: u16, banner: &str| {
            let context = PortContext {
                port,
                protocol: Protocol::Tcp,
                addr: None,
                tunnel: None,
                speaks_http: port == 80,
                detection: ServiceDetection::default(),
                host_name: None,
            };
            let responses = ResponseSet::from_banners(vec![banner.to_string()]);
            let mut evidence =
                BannerRegexAnalyzer.analyze(&context, &responses, &Collected::default());
            evidence.extend(HttpHeadersAnalyzer.analyze(
                &context,
                &responses,
                &Collected::default(),
            ));
            ServiceVerdict::resolve(evidence)
                .to_service()
                .expect("the banner names a service")
        };
        let ssh = identify(22, "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13\r\n");
        let http = identify(
            80,
            "HTTP/1.1 200 OK\r\nServer: Apache/2.4.7 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n",
        );
        assert_eq!(
            ssh.build()
                .and_then(|build| build.release())
                .map(|release| release.name()),
            Some("14.04"),
            "test premise: the banner places the build"
        );

        let ubuntu = crate::import::ubuntu::read(
            &mut &include_bytes!("../../tests/data/distro/ubuntu-osv.tar.xz")[..],
            &mut &include_bytes!("../../tests/data/distro/ubuntu-vex.tar.xz")[..],
        )
        .expect("the fixture converts");
        let (session, ctx) = crate::scanner::session::ScanSession::builder()
            .detections(crate::detect::Detections::embedded().with_advisories([ubuntu]))
            .build();
        let ip: std::net::IpAddr = "203.0.113.1".parse().expect("literal");
        ctx.write_host(ScopedIp::unscoped(ip), |host| {
            host.add_port(Port::new(22, Protocol::Tcp, PortState::Open).with_service(ssh));
            host.add_port(Port::new(80, Protocol::Tcp, PortState::Open).with_service(http));
            true
        });

        run_correlation(&ctx, ServiceDetection::Probe);

        let host = session.hosts().get(ip).expect("the scanned host");
        let cited = |number: u16| -> Vec<String> {
            host.ports()
                .filter(|port| port.number() == number)
                .flat_map(|port| port.findings())
                .flat_map(|finding| finding.references())
                .filter_map(|reference| match reference {
                    crate::model::finding::Reference::Cve(id) => Some(id.clone()),
                    _ => None,
                })
                .collect()
        };
        let ssh_cited = cited(22);
        for withdrawn in [
            "CVE-2015-5600",
            "CVE-2016-10010",
            "CVE-2020-14145",
            "CVE-2023-38408",
        ] {
            assert!(
                !ssh_cited.iter().any(|cve| cve == withdrawn),
                "{withdrawn} was reported against a build that does not carry it"
            );
        }
        assert!(
            host.ports()
                .filter(|port| port.number() == 22)
                .flat_map(|port| port.findings())
                .all(|finding| finding.advised_by().is_some()),
            "every claim on the placed build names the data that judged it"
        );
        assert!(
            host.ports()
                .filter(|port| port.number() == 80)
                .flat_map(|port| port.findings())
                .filter(|finding| finding.subject().is_some_and(|s| !s.contains("/no-fix")))
                .all(|finding| finding.confidence() < Confidence::Probable),
            "a build hiding its patch level is only surely vulnerable where no fix exists"
        );
        // The Apache banner names no release, so its build is taken from the
        // SSH banner's. The fixture has no apache2 data, so the excerpt names
        // the package and release the data could not answer for.
        let http: Vec<&crate::model::finding::Finding> = host
            .ports()
            .filter(|port| port.number() == 80)
            .flat_map(|port| port.findings())
            .filter(|finding| finding.subject().is_some_and(|s| s.starts_with("apache:")))
            .collect();
        assert!(!http.is_empty(), "the Apache build draws claims");
        for finding in &http {
            assert!(
                finding
                    .subject()
                    .is_some_and(|s| s.contains("@ubuntu-14.04/")),
                "{:?}",
                finding.subject()
            );
        }
        assert!(http.iter().any(|finding| {
            finding
                .excerpt()
                .as_str()
                .contains("does not cover apache2 in release 14.04")
        }));
    }

    /// At [`ServiceDetection::Off`] the step does not run, even where a CPE is
    /// somehow present.
    #[test]
    fn correlation_does_not_run_when_no_service_pass_did() {
        use crate::model::ip::scoped::ScopedIp;
        use crate::model::port::{Port, PortState, Protocol, Service};

        let (session, ctx) = crate::scanner::session::ScanSession::new();
        let ip: std::net::IpAddr = "203.0.113.1".parse().expect("literal");
        ctx.write_host(ScopedIp::unscoped(ip), |host| {
            let service = Service::new("http", 90).with_cpe("cpe:/a:apache:http_server:2.4.49");
            host.add_port(Port::new(80, Protocol::Tcp, PortState::Open).with_service(service));
            true
        });

        run_correlation(&ctx, ServiceDetection::Off);

        let host = session.hosts().get(ip).expect("the scanned host");
        let port = host
            .ports()
            .find(|port| port.number() == 80)
            .expect("port 80");
        assert_eq!(port.findings().count(), 0);
    }

    // ── The TLS enumeration pass ─────────────────────────────────────────────

    /// A server accepting exactly one suite under TLS 1.2 and refusing
    /// everything else.
    ///
    /// It reads the offer, because the pass walks the five versions
    /// concurrently and connection order is arbitrary.
    async fn tls_endpoint(suite: u16) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("has an address");

        tokio::spawn(async move {
            while let Ok(mut stream) = accept_from_this_process(&listener).await {
                let mut hello = vec![0u8; 4096];
                let Ok(read) = stream.read(&mut hello).await else {
                    continue;
                };
                let record = answer_to(&hello[..read], |offered| offered == suite)
                    .unwrap_or_else(|| REFUSAL.to_vec());
                let _ = stream.write_all(&record).await;
            }
        });

        addr
    }

    /// A server accepting every suite TLS 1.2 can express, taking `pause` over
    /// each answer, and a count of the connections it has taken.
    ///
    /// Accepting everything makes a walk long: each answer removes one suite
    /// from the offer, one connection each. Each connection is served on its own
    /// task so the pause is paid per offer, as a slow server charges it.
    async fn slow_endpoint_accepting_everything(
        pause: std::time::Duration,
    ) -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("has an address");
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&seen);

        tokio::spawn(async move {
            while let Ok(mut stream) = accept_from_this_process(&listener).await {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut hello = vec![0u8; 4096];
                    let Ok(read) = stream.read(&mut hello).await else {
                        return;
                    };
                    tokio::time::sleep(pause).await;
                    let record =
                        answer_to(&hello[..read], |_| true).unwrap_or_else(|| REFUSAL.to_vec());
                    let _ = stream.write_all(&record).await;
                });
            }
        });

        (addr, seen)
    }

    /// A fatal handshake_failure: the terms offered are refused.
    const REFUSAL: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];

    /// A ServerHello for the first suite offered that `accepts` takes, where
    /// the hello offered TLS 1.2, and `None` otherwise. Walked by offset off the
    /// RFC layout.
    fn answer_to(hello: &[u8], accepts: impl Fn(u16) -> bool) -> Option<Vec<u8>> {
        // Record header, handshake header, then the version field.
        let version = u16::from_be_bytes([*hello.get(9)?, *hello.get(10)?]);
        if version != 0x0303 {
            return None;
        }

        // Past the random, then the session id, then the suite list.
        let after_random = 5 + 4 + 2 + 32;
        let session_len = usize::from(*hello.get(after_random)?);
        let rest = hello.get(after_random + 1 + session_len..)?;
        let len = usize::from(u16::from_be_bytes([*rest.first()?, *rest.get(1)?]));
        let suite = rest
            .get(2..2 + len)?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair))
            .find(|offered| accepts(*offered))?;

        let mut body = vec![2u8, 0, 0, 0];
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x5A; 32]);
        body.push(0);
        body.extend_from_slice(&suite.to_be_bytes());
        body.push(0);
        let length = (body.len() - 4) as u32;
        body[1..4].copy_from_slice(&length.to_be_bytes()[1..]);

        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        Some(record)
    }

    /// A context holding one host with one open TLS port at `port`, which is
    /// what the pass selects on, in a scan giving each host `host_timeout`.
    fn context_with_tls_port(
        port: u16,
        host_timeout: Option<std::time::Duration>,
    ) -> (crate::scanner::session::ScanSession, ScanContext) {
        use crate::model::host::Host;
        use crate::model::port::{Port, Security};

        let (session, ctx) = crate::scanner::session::ScanSession::builder()
            .host_timeout(host_timeout)
            .build();
        let address: IpAddr = "127.0.0.1".parse().expect("an address");

        let mut host = Host::new(address);
        host.set_status(crate::model::host::HostStatus::Up);
        // The `security` record the pass selects on.
        host.add_port(
            Port::new(port, Protocol::Tcp, PortState::Open)
                .with_security(Security::new().with_tls_version("TLSv1.2")),
        );
        ctx.store.insert(host.scoped_ip(), host);

        (session, ctx)
    }

    /// What the port carries after a pass, or `None` where it carries no
    /// enumeration.
    fn recorded_support(ctx: &ScanContext, port: u16) -> Option<crate::model::tls::TlsSupport> {
        let address: IpAddr = "127.0.0.1".parse().expect("an address");
        ctx.read_host(
            crate::model::ip::scoped::ScopedIp::unscoped(address),
            |host| {
                host.ports()
                    .find(|held| held.number() == port)
                    .and_then(|held| held.security())
                    .map(|security| security.support().clone())
            },
        )
        .flatten()
    }

    /// Off, nothing is asked and nothing is written.
    #[tokio::test]
    async fn the_pass_asks_nothing_unless_it_is_switched_on() {
        let addr = tls_endpoint(0xC02F).await;
        let (_session, ctx) = context_with_tls_port(addr.port(), None);

        let cfg = crate::config::ZondConfig::default();
        assert!(!cfg.tls_enumeration, "off by default");
        run_tls_enumeration(&ctx, &cfg).await;

        let support = recorded_support(&ctx, addr.port()).expect("the port is still there");
        assert!(
            support.is_empty(),
            "nothing was asked, so nothing is recorded"
        );
    }

    /// A port the scan only listens on is not walked, even where it carries a
    /// handshake's record, which this scan's own service pass would never have
    /// written there but a restored sitting can.
    ///
    /// On a printer's raw-print port each ClientHello is a page. The endpoint
    /// here would accept, so an enumeration that ran would be recorded.
    #[tokio::test]
    async fn the_pass_leaves_a_listen_only_port_alone() {
        use crate::model::host::Host;
        use crate::model::port::{Port, Security};

        let addr = tls_endpoint(0xC02F).await;
        let (_session, ctx) = crate::scanner::session::ScanSession::builder()
            .listening_only_to(std::collections::BTreeSet::from([addr.port()]))
            .build();
        let mut host = Host::new(addr.ip());
        host.set_status(crate::model::host::HostStatus::Up);
        host.add_port(
            Port::new(addr.port(), Protocol::Tcp, PortState::Open)
                .with_security(Security::new().with_tls_version("TLSv1.2")),
        );
        ctx.store.insert(host.scoped_ip(), host);

        let cfg = crate::config::ZondConfig {
            tls_enumeration: true,
            ..Default::default()
        };
        run_tls_enumeration(&ctx, &cfg).await;

        let support = recorded_support(&ctx, addr.port()).expect("the port is still there");
        assert!(
            support.is_empty(),
            "a listen-only port was offered hellos: {support:?}"
        );
    }

    /// Switched on, the pass reaches the endpoint, writes what it accepts back
    /// onto the port, and leaves the handshake's own record intact.
    ///
    /// The write-back folds through the confidence-driven merge every pass uses;
    /// a merge in the wrong direction would drop the enumeration silently.
    #[tokio::test]
    async fn the_pass_records_what_the_endpoint_accepts() {
        // A suite with a fault, so the findings path is exercised too.
        let addr = tls_endpoint(0x000A).await;
        let (_session, ctx) = context_with_tls_port(addr.port(), None);

        let cfg = crate::config::ZondConfig {
            tls_enumeration: true,
            ..Default::default()
        };
        run_tls_enumeration(&ctx, &cfg).await;

        let support = recorded_support(&ctx, addr.port()).expect("the port is still there");
        assert!(support.accepts(crate::model::tls::TlsVersion::Tls12));
        assert_eq!(support.suites().len(), 1);

        let address: IpAddr = "127.0.0.1".parse().expect("an address");
        ctx.read_host(
            crate::model::ip::scoped::ScopedIp::unscoped(address),
            |host| {
                let port = host
                    .ports()
                    .find(|held| held.number() == addr.port())
                    .expect("the port");

                assert_eq!(
                    port.security().and_then(|s| s.tls_version()),
                    Some("TLSv1.2"),
                    "the handshake's own record survives the fold"
                );
                assert!(
                    port.findings().count() > 0,
                    "a suite with a fault produces a finding on the port"
                );
            },
        )
        .expect("the host is recorded");
    }

    /// The pass counts each endpoint forward as its walk ends, read through the
    /// progress a front end holds.
    ///
    /// This is the slowest pass a scan runs, up to eighty connections a version,
    /// so progress must move during it.
    #[tokio::test]
    async fn the_pass_counts_each_endpoint_as_its_walk_ends() {
        use crate::model::port::{Port, Security};

        let first = tls_endpoint(0xC02F).await;
        let second = tls_endpoint(0xC030).await;
        let (session, ctx) = context_with_tls_port(first.port(), None);
        let address: IpAddr = "127.0.0.1".parse().expect("an address");
        ctx.update_host(address, |host| {
            host.add_port(
                Port::new(second.port(), Protocol::Tcp, PortState::Open)
                    .with_security(Security::new().with_tls_version("TLSv1.2")),
            );
        });

        let cfg = crate::config::ZondConfig {
            tls_enumeration: true,
            ..Default::default()
        };
        run_tls_enumeration(&ctx, &cfg).await;

        let progress = session.progress();
        assert_eq!(progress.stage(), Stage::Tls);
        assert_eq!(progress.stage_total(), Some(2), "one unit to an endpoint");
        assert_eq!(
            progress.stage_done(),
            2,
            "each endpoint counted once its walk ended"
        );
    }

    /// A walk an earlier sitting left unfinished is finished by the sitting
    /// that resumes it.
    ///
    /// The journal restores the port with the unfinished walk, and the pass asks
    /// again. The fold must let the new answer replace the restored one.
    #[tokio::test]
    async fn a_resumed_sitting_finishes_a_walk_an_earlier_one_left_unfinished() {
        use crate::model::port::{Port, Security};
        use crate::model::tls::{
            CipherSuite, Interruption, TlsSupport, TlsVersion, UnfinishedVersion, VersionSupport,
        };

        let addr = tls_endpoint(0xC02F).await;
        let (_session, ctx) = context_with_tls_port(addr.port(), None);
        let restored = TlsSupport::new().leaving_unfinished(UnfinishedVersion::new(
            TlsVersion::Tls12,
            Interruption::Stopped,
        ));
        let address: IpAddr = "127.0.0.1".parse().expect("an address");
        ctx.update_host(address, |host| {
            host.add_port(
                Port::new(addr.port(), Protocol::Tcp, PortState::Open)
                    .with_security(Security::new().with_support(restored)),
            );
        });

        let cfg = crate::config::ZondConfig {
            tls_enumeration: true,
            ..Default::default()
        };
        run_tls_enumeration(&ctx, &cfg).await;

        let accepted = CipherSuite::from_code(0xC02F).expect("a suite in the registry");
        assert_eq!(
            recorded_support(&ctx, addr.port()),
            Some(TlsSupport::new().accepting(VersionSupport::new(
                TlsVersion::Tls12,
                vec![accepted],
                vec![]
            ))),
            "the resumed walk finished, and its answer is the one on record"
        );
    }

    /// A host that has spent its budget is left alone.
    #[tokio::test]
    async fn a_host_out_of_time_is_not_enumerated() {
        let addr = tls_endpoint(0xC02F).await;
        let (_session, ctx) = context_with_tls_port(addr.port(), Some(std::time::Duration::ZERO));

        let cfg = crate::config::ZondConfig {
            tls_enumeration: true,
            ..Default::default()
        };
        run_tls_enumeration(&ctx, &cfg).await;

        let support = recorded_support(&ctx, addr.port()).expect("the port is still there");
        assert!(support.is_empty(), "a spent budget skips the endpoint");
    }

    /// A walk already under way stops when its host's budget runs out, keeps
    /// what it learned, and names the host as left early.
    ///
    /// One endpoint is up to 80 offers under TLS 1.2 alone, each allowed two
    /// seconds, so checking the budget only before an endpoint starts would hold
    /// a host minutes past it.
    #[tokio::test]
    async fn a_walk_under_way_stops_when_its_host_runs_out_of_time() {
        use crate::model::tls::{CipherSuite, Interruption, TlsVersion, UnfinishedVersion};
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        let (addr, seen) = slow_endpoint_accepting_everything(Duration::from_millis(50)).await;
        let (_session, ctx) = context_with_tls_port(addr.port(), Some(Duration::from_millis(500)));

        let cfg = crate::config::ZondConfig {
            tls_enumeration: true,
            ..Default::default()
        };
        run_tls_enumeration(&ctx, &cfg).await;

        // An unstopped walk would have asked about every one of them.
        let every = CipherSuite::offered_under(TlsVersion::Tls12).count();
        let asked = seen.load(Ordering::SeqCst);
        assert!(
            asked < every / 2,
            "the walk stops near its budget, and it went on for {asked} connections \
             against {every} suites"
        );

        let address: IpAddr = "127.0.0.1".parse().expect("an address");
        assert_eq!(
            ctx.take_timed_out(),
            vec![address],
            "a host left part way through its walk is named as left early"
        );

        let support = recorded_support(&ctx, addr.port()).expect("the port is still there");
        assert!(
            support.accepts(TlsVersion::Tls12),
            "what the walk learned before the budget ran out is kept"
        );
        assert_eq!(
            support.unfinished(),
            &[UnfinishedVersion::new(
                TlsVersion::Tls12,
                Interruption::Stopped
            )],
            "and the walk it cut short says the scan stopped it, not the endpoint"
        );
    }

    /// A walk already under way stops when the scan does.
    ///
    /// As with the host budget above: otherwise an abort, or the scan's own
    /// budget running out, would wait minutes for every walk in flight.
    #[tokio::test]
    async fn a_walk_under_way_stops_when_the_scan_stops() {
        use crate::model::tls::{CipherSuite, TlsVersion};
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        let (addr, seen) = slow_endpoint_accepting_everything(Duration::from_millis(50)).await;
        let (_session, ctx) = context_with_tls_port(addr.port(), None);

        let handle = ctx.handle.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            handle.abort();
        });

        let cfg = crate::config::ZondConfig {
            tls_enumeration: true,
            ..Default::default()
        };
        run_tls_enumeration(&ctx, &cfg).await;

        let every = CipherSuite::offered_under(TlsVersion::Tls12).count();
        let asked = seen.load(Ordering::SeqCst);
        assert!(
            asked < every / 2,
            "the walk stops soon after the scan does, and it went on for {asked} \
             connections against {every} suites"
        );
    }
}
