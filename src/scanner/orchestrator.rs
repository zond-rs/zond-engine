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
//! Nothing here is public. It is one implementation of the engine's own policy,
//! and the two entry points above are its only callers. A consumer who wants a
//! different policy does not need to reach in here: they build a
//! [`plan`], edit it, and run the steps they want, which is the
//! second of the three altitudes the [`scanner`](super) module documents.
//!
//! ## Why it is a module of its own
//!
//! The two entry points are about ninety lines between them. Everything else a
//! scan needs to be assembled is another five hundred, and read together they
//! obscure the thing a reader opens `scanner.rs` to find. Split out, the facade
//! reads as a facade and the policy reads as policy.
//!
//! ## The one decision worth knowing before reading
//!
//! A plan says what should run; only the attempt discovers what could. Those are
//! separate steps here on purpose, and the seam between them is
//! [`ensure_coverage`], which backs the plan's intent with the sockets that
//! actually opened. A protocol left with no strategy at all is not a degraded
//! scan but a silent one, since nothing would route its targets anywhere.

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
use crate::model::ip::range::{Ipv4Range, Ipv6Range};
use crate::model::ip::scoped::{Zone, ZoneMap};
use crate::model::{
    ip::set::IpSet,
    port::{Discovery as PortDiscovery, Port, PortState, Protocol, ScanResponse},
    target::{PlannedTarget, TargetIndex, TargetMap, TargetSet},
    technique::TcpScanTechnique,
};
use crate::report::ScannerKind;
use crate::scanner::pool::ProbePool;
use crate::scanner::rdns::HostnameResolver;
use crate::scanner::session::{ScanContext, Stage};
use crate::scanner::strategy::composite::Reach;
use crate::scanner::strategy::local::Scope;
use crate::scanner::strategy::{HostScanner, PortScanner, StrategyError};
use crate::scanner::{plan, rdns, strategy};
use crate::system::interface;
use crate::transport::probe::SendMode;
use crate::{counted, info, success, warn};

/// The targets an unprivileged sweep can actually walk, refusing the rest.
///
/// The privileged path gets this from [`plan::DiscoveryPlan::build`], which
/// classifies every range against this host's interfaces and refuses the ones no
/// strategy can take. The unprivileged path has no plan: it hands the whole set
/// to `connect`, which probes addresses one at a time and would keep doing so
/// until the process is killed. So the same rule is applied here, and applied to
/// the same constant, because a `/64` that is refused with root and scanned
/// forever without it is the engine giving two different answers about one
/// range.
///
/// Filtered per range rather than all-or-nothing. A set holding a `/64` and
/// three literal addresses is three quarters scannable, and refusing the whole
/// of it would throw away addresses somebody named.
///
/// IPv4 is untouched. Every IPv4 range is finite in a way a person can reason
/// about, and a `/8` is an unreasonable request rather than an impossible one,
/// which is a judgement for whoever is driving the engine, not for the engine.
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
/// Both entry points face the same two questions: can the process open raw
/// sockets, and should it resolve hostnames. Answering them once, up front,
/// lets [`scan`](crate::scanner::scan) and
/// [`discover`](crate::scanner::discover) branch on the same facts and keeps
/// the privileged-versus-unprivileged and DNS-on-versus-off policy from
/// drifting between phases.
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
    /// through a tunnel and, for its port probes, an IPv6 neighbour by connect,
    /// the way an unprivileged run would, and reaches the rest with the packets
    /// it chose. See [`interface::beyond_frames`].
    ///
    /// False where the caller chose the link layer, by naming the send mode or
    /// by an evasion only a frame can carry. A connect honours neither choice,
    /// so what the frames miss is left unanswered as the choice implies rather
    /// than answered by a different probe than the one asked for.
    pub(super) frames_only: bool,
    /// Whether hostname resolution is enabled, the inverse of `cfg.no_dns`.
    dns: bool,
}

impl ScanCapabilities {
    /// Reads the runtime capabilities from the environment and config, and
    /// announces the scanning mode they imply once, here, rather than from the
    /// code that later acts on them.
    ///
    /// `probes_udp` is whether the run names a UDP port, which only a port scan
    /// can: it is what the announcement of the unprivileged mode depends on.
    pub(super) fn resolve(cfg: &ZondConfig, probes_udp: bool) -> Self {
        let privilege = Privilege::current();
        let mode = cfg.evasion.effective_send_mode(cfg.send_mode);
        let frames_only =
            privilege.is_raw() && mode == SendMode::Auto && !mode.reaches_past_frames();

        let caps = Self {
            privilege,
            frames_only,
            dns: !cfg.no_dns,
        };
        caps.announce(probes_udp);
        caps
    }

    /// Says what the privilege this run holds lets it probe with.
    fn announce(self, probes_udp: bool) {
        if self.privilege.is_raw() {
            // Which of the two routes carried it, because on macOS the second
            // one is what an unprivileged run gets and a reader who expected to
            // need sudo should see why they did not.
            if privilege::can_send_raw() {
                success!("raw sockets available: probing with ARP, ICMPv6 and SYN");
            } else {
                success!(
                    "link-layer access: probing with ARP, ICMPv6 and SYN as self-built frames"
                );
            }
        } else if probes_udp {
            // The UDP ports go to ordinary sockets, which need no privilege, so
            // a line saying TCP connect alone would be one saying less than the
            // run does.
            warn!("no raw sockets: probing with TCP connect and plain UDP datagrams");
        } else {
            warn!("no raw sockets: probing with TCP connect only");
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

/// The hosts a pass that builds its own segments can reach, having recorded
/// once that it leaves the rest alone.
///
/// Every host, unless this scan's raw strategies send frames alone. Then a host
/// a frame cannot reach is not probed some other way: what these passes read,
/// a stack's answer to an unusual segment, the hops along a path, a middlebox's
/// reply to a bad checksum, is what only a packet they built can ask. One
/// refusal says how many were left and why, where a send per host would have
/// failed once each and said nothing about the cause.
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

/// Names the targets the port scan reaches by connect, and why, for a reader
/// asking for detail.
///
/// Detail rather than news: the scan answers these ports either way, and the
/// report's [`reached_by_connect`](crate::report::ScanPhase::reached_by_connect)
/// is the record of it. One line, with one address named per reason.
fn announce_beyond_frames(beyond: &interface::BeyondFrames) {
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
    info!(
        verbosity = 1,
        "port scan by connect: {}",
        reasons.join(", ")
    );
}

/// The privileged host-identification phase, shared by
/// [`discover`](crate::scanner::discover) and [`scan`](crate::scanner::scan).
///
/// It spawns the strategies discovery uses: per-interface
/// [`LocalScanner`](strategy::local::LocalScanner)s (ARP and ICMPv6, yielding
/// MAC and RTT), a [`RoutedScanner`](strategy::routed::RoutedScanner) for
/// off-link targets (RTT), and the passive DNS and mDNS [`HostnameResolver`].
/// All of them write into the shared store. `discover` runs this alone, while
/// `scan` runs it alongside the port scan. Keeping it in one place lets both
/// surface identical host detail without duplicating the orchestration.
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
            // **The one unbounded queue in the crate, and it is the right shape
            // here.** Everything else a scan opens is bounded because its depth is
            // set by how fast a producer runs; this one's depth is set by how many
            // hosts exist, and every entry it holds accompanies a `Host` the store
            // is already holding. An `IpAddr` is 17 bytes against that record's
            // 480, so bounding this saves under four per cent of a cost the scan
            // cannot avoid paying.
            //
            // What it would cost is worse than that. The two senders
            // (`local::EnrichingScanner` and `routed::SweepScanner`) post from
            // synchronous reply handlers, so a bounded channel is either
            // `try_send`, which drops a hostname the scan will never look for
            // again, or an `await` that makes two hot classification paths async
            // to reclaim nothing.
            let (tx, rx) = mpsc::unbounded_channel();
            (Some(tx), Some(spawn_resolver(rx).await))
        } else {
            info!("DNS resolution skipped by user flag");
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

        if let Some(task) = self.resolver
            && let Ok(Some(mut resolver)) = task.await
        {
            resolver.resolve_hosts(ctx);
        }
    }
}

/// Records the targets that are this host's own addresses as up, without
/// probing them.
///
/// No strategy can establish one. The kernel routes traffic for an address this
/// host holds through loopback, so an ARP request for it goes onto a link where
/// nothing will answer, and without this the address would be reported down
/// while `ping` to it succeeds.
///
/// The evidence is named rather than borrowed from a probe protocol, because
/// nothing was sent: the interface table is the whole of it, and it is
/// conclusive in a way no reply is.
///
/// Each is settled as answered, too. A sweep counted in addresses otherwise
/// leaves this host's own position unsettled for ever, the watermark stops
/// behind it, and every finished sweep of the segment the scanner sits on reads
/// as resumable with nothing left to ask.
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
/// Every refusal the plan carries is recorded before anything is spawned, so the
/// distinction between "nothing is there" and "nobody looked" survives into the
/// report. Then each step is asked for its strategy: a step that cannot open
/// what it needs is recorded and skipped, and the rest of the scan proceeds
/// rather than being abandoned over one bad interface.
///
/// Each surviving strategy gets its own task, tagged with its own
/// [`ScannerKind`], so the caller can wait on all of them and react to failures
/// individually.
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
            // Read before the strategy moves into its task: once it is running,
            // the only thing left to attribute a failure to is the handle.
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
/// Every refusal is recorded first, for the same reason discovery records its
/// own: a protocol nobody probed has to be distinguishable from a protocol with
/// nothing open. A step that cannot open its socket is recorded and dropped, and
/// whatever built is wrapped in a
/// [`CompositePortScanner`](strategy::composite::CompositePortScanner), which
/// routes each target to a strategy that covers its protocol. One scanner comes
/// back either way, so the fork stays confined here.
///
/// `raw` is what the raw strategies can reach. Where that is every target but
/// some, they are handed the rest and [`ensure_coverage`] finds those theirs;
/// where it is no target at all, no raw strategy is opened.
///
/// `named` is the protocols the targets name a port on. A stand-in is found
/// only for those: one for a protocol nothing names probes nothing, and the
/// phase would still record the addresses it covers as reached by connect.
///
/// Every refusal, the plan's and the coverage check's, is handed to the
/// composite with the protocol and addresses it covers, so a target it leaves
/// unprobed is counted there as refused rather than as lost.
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
    // cover has already been refused above, in the same words, and must not be
    // refused a second time by the coverage check below.
    let intended: Vec<Protocol> = Protocol::ALL
        .into_iter()
        .filter(|protocol| plan.covers(*protocol) && named.contains(protocol))
        .collect();
    let mut refused: Vec<(Protocol, Reach)> = Protocol::ALL
        .into_iter()
        .filter(|protocol| plan.refuses(*protocol))
        .map(|protocol| (protocol, Reach::Any))
        .collect();

    let beyond = Arc::new(raw.beyond());
    let mut routes: Vec<(Box<dyn PortScanner>, Reach)> = Vec::new();
    let mut opened = Vec::new();
    for step in plan.into_steps() {
        // Not opened rather than opened and starved: a raw strategy holds a
        // capture on every interface for as long as the scan runs, and here it
        // would be handed nothing. The protocol is left uncovered, which is what
        // gives it its unprivileged strategy below, for every address.
        if step.is_raw() && matches!(raw, RawReach::Nothing(_)) {
            continue;
        }
        match step.into_scanner(ctx.clone(), target_count, tuning.clone(), zones.clone()) {
            Ok(scanner) => {
                let reach = match step.is_raw() && !beyond.is_empty() {
                    true => Reach::Except(Arc::clone(&beyond)),
                    false => Reach::Any,
                };
                opened.push(step);
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
        opened,
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
/// The plan cannot do this on its own, and that is the point of separating
/// them. A plan says a raw TCP scanner and a raw UDP scanner should run. Only
/// the attempt discovers that this host permitted one raw socket and not the
/// other, a sandbox can do exactly that, and a protocol left with no strategy
/// at all is not a degraded scan but a silent one:
/// [`CompositePortScanner`](strategy::composite::CompositePortScanner) has
/// nowhere to route those targets, so they are never probed and never reported.
/// Asking what actually built, rather than assuming a privileged scan covers
/// everything, is what keeps that from happening.
///
/// A connect fallback substitutes for a SYN scan and for nothing else. It
/// completes handshakes, so it answers roughly the question a SYN scan asks; it
/// cannot send a FIN, a flagless segment or a bare ACK, and so cannot answer
/// what any of those were asked. Where the caller chose one of those and no raw
/// scanner opened, the TCP half is reported as a failure and left undone. That
/// is worse for the caller and honest, where a silent substitution would hand
/// back verdicts from a technique they did not choose - and no field in the
/// report would say so.
///
/// `intended` is what keeps this from repeating the plan. A protocol the
/// plan never meant to cover was already refused, in the words
/// [`plan::RefusedStep::technique_needs_raw_sockets`]
/// supplies, and saying it again puts one cause in the report twice. What is
/// left for this function is the narrower case the plan could not foresee: a
/// protocol it did intend, whose socket would not open.
///
/// A refusal made here comes back with the protocol and the addresses it
/// covers, in [`Coverage::refused`], because recording it is only half of what
/// it takes: its targets still reach the router, which has to count them as
/// refused rather than lost. See
/// [`refusing`](strategy::composite::CompositePortScanner::refusing).
///
/// ## The targets the raw strategies cannot reach
///
/// `raw` says what the raw strategies reach, which is every target unless they
/// send frames alone. Then what they miss is what a frame cannot reach:
/// loopback, this host's own addresses, anything routed through a tunnel, and
/// an IPv6 neighbour. The raw routes arrive already handed everything else, so
/// the same question is asked a second time over these addresses, on the same
/// terms: a protocol whose only strategies are raw gets its unprivileged one
/// for them alone, or is refused for them alone. What is reached this way is
/// recorded, since the phase's privilege reads as raw and the evidence at these
/// addresses is not.
///
/// A protocol with no strategy at all is not asked about twice. Its fallback
/// above reaches every address, these included, and its refusal already
/// covers them. Its refusal says why there is none: a process with no raw
/// socket is told so, and a frames-only one whose raw strategies were never
/// opened, because no target was within a frame's reach, is told that. The
/// two call for different things, and the second process already holds the
/// privilege the first is told it lacks.
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
    // beyond a frame's reach, rather than asked for and not had.
    let withheld = matches!(raw, RawReach::Nothing(_));
    let mut refused: Vec<(Protocol, Reach)> = Vec::new();
    let covered: Vec<Protocol> = routes
        .iter()
        .flat_map(|(scanner, _)| scanner.supported_protocols())
        .collect();
    // Covered, and by nothing that is handed the addresses the raw routes are
    // not. Asked before anything is added below, since a fallback reaching
    // every address answers this question as well as the first one.
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

    // Whether anything below stands in for a raw strategy. A stand-in reaching
    // every address reaches the ones a frame cannot as well.
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

    // Nothing stands in for an INIT scan. A protocol whose only strategy failed
    // to open is reported rather than answered by something that asked a
    // different question, which for SCTP is the whole of what is available.
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

/// A port-scan strategy, and which of the planned steps actually opened.
///
/// The second half is not decoration. Host enrichment is worth running only
/// alongside a raw scan, it is the raw paths that yield a MAC and an RTT, and
/// whether a raw scan is happening is answerable only after the sockets were
/// asked for, not from the privilege the process holds.
///
/// The steps are kept rather than their [`ScannerKind`]s, because "did this
/// need raw sockets" is the question being asked and a strategy's name is a
/// different fact about it. Answered from the name, this would silently skip
/// enriching every scan whose technique is not a SYN.
pub(super) struct BuiltPortScan {
    pub(super) scanner: Box<dyn PortScanner>,
    opened: Vec<plan::PortScanStep>,
    /// Whether a connect strategy stands in for a raw one on the targets a
    /// frame cannot reach, which is when the phase says it reached them by
    /// connect.
    reached_by_connect: bool,
}

impl BuiltPortScan {
    /// Whether any raw-socket strategy is among what opened.
    pub(super) fn opened_raw(&self) -> bool {
        self.opened.iter().any(plan::PortScanStep::is_raw)
    }
}

/// Drives one port-scan strategy to completion. It streams targets through the
/// strategy, and when the strategy succeeds and the scan was not aborted, lets
/// the strategy run its own service-detection pass (a no-op for strategies that
/// fingerprint inline).
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
            if !ctx.handle.should_stop() {
                scanner.detect_services(ctx).await;
            }
            // Active detections run over the services just identified, on the same
            // terms service detection did: after it, and only if the scan is not
            // stopping.
            if !ctx.handle.should_stop() {
                super::detection::detect(ctx, service_detection, detection).await;
            }
        }
        Err(e) => ctx.record_failure(kind, e.to_string()),
    }
}

/// Completes the hostname-resolution tail of a scan.
///
/// A privileged scan spawns passive DNS and mDNS resolution as part of its
/// [`Enrichment`]; awaiting that here folds the collected hostnames and extra
/// IPs into the store along with the rest of the enrichment strategies. An
/// unprivileged scan has no enrichment, so it falls back to active reverse
/// lookups when DNS is enabled and does nothing when it is not. This is the
/// single place the "passive when privileged, active otherwise" policy lives.
pub(super) async fn finish_enrichment(
    enrichment: Option<Enrichment>,
    caps: ScanCapabilities,
    ctx: &ScanContext,
) {
    match enrichment {
        Some(enrichment) => enrichment.finish(ctx).await,
        None if caps.dns => rdns::resolve_hosts_async(ctx).await,
        None => {}
    }
}

/// Reads an operating system out of what the scan already knows, sending
/// nothing.
///
/// This is [`OsDetection::Passive`] applied to a phase that has no other way to
/// apply it. The port scanner reads a stack off the segments it drew and the
/// echo prober reads one off a ping it sent, but host discovery draws neither,
/// so without this a discovery sweep concludes nothing about any host, however
/// much it has learned about it. A machine whose hardware address names its
/// maker and whose hostname is the one its system generated would sit in the
/// store, unread.
///
/// Runs after enrichment and not before it: [`os::hostname_evidence`] reads a
/// name, and the name arrives on the resolver's tail. Ordering this earlier
/// would consult a store that has not been told the hostnames yet.
///
/// ## What it will and will not conclude
///
/// The two sources it has are each below the floor
/// [`os::resolve`] reports at, so neither names a host alone, and a sweep of a
/// network of randomly-addressed phones concludes nothing at all. Two agreeing
/// sources clear it: an Apple address under a default `MacBook-Pro` name is a
/// verdict, where either alone is a guess. That is the intended yield and it is
/// a small one. It is not a substitute for reading a stack off the wire; it is
/// the part of passive identification that costs nothing and was simply not
/// wired up.
pub(super) fn run_passive_os_identification(ctx: &ScanContext, os_detection: OsDetection) {
    // `Off` means identify nothing and record nothing about the stacks that
    // answered. It costs no packets to disobey that, which is exactly why it
    // has to be obeyed here: a caller who asked for a report containing only
    // what they requested would otherwise find a fingerprint in it.
    if matches!(os_detection, OsDetection::Off) {
        return;
    }

    let mut named = 0usize;
    for ip in ctx.host_addresses() {
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
/// The two active probes reach different hosts and read different things, and
/// this one is the stronger of the pair wherever it applies. It revisits ports
/// whose state the port scan already settled, so it needs a host that answered
/// *something* over TCP, and for such a host it reads the identifier, sequence
/// and clock policies that no single reply carries. The echo probe is the route
/// to the host that answered nothing at all, where a hop counter and an echoed
/// code are all there is. Running the series first means the echo pass sees a
/// store in which everything reachable by TCP has already been read.
///
/// # What each level asks for
///
/// At [`OsDetection::Active`] this follows the hosts a scan could not settle:
/// every host that is up, has a TCP answer, and is not already named with high
/// confidence. At [`OsDetection::Aggressive`] it follows **every** host with a
/// TCP answer and takes twice the samples, which is what somebody measuring
/// hosts they already know the answer for wants, and is the reading a new rule
/// is authored from.
///
/// Declines quietly rather than failing when there is nothing to do.
pub(super) async fn run_active_os_series(
    ctx: &ScanContext,
    os_detection: OsDetection,
    tuning: ProbeTuning,
    caps: ScanCapabilities,
) {
    if !os_detection.is_active() {
        return;
    }

    ctx.enter_stage(Stage::Os, None);
    let thorough = matches!(os_detection, OsDetection::Aggressive);

    let targets: Vec<strategy::identify::series::SeriesTarget> = ctx
        .host_addresses()
        .into_iter()
        // Read before the store is, so no host guard is held across the clock.
        .filter(|key| !ctx.host_expired(key.addr()))
        .filter_map(|key| {
            ctx.read_host(&key, |host| {
                if !host.status().is_up() {
                    return None;
                }
                // A host already named with high confidence is not worth more
                // packets at `Active`: nothing this probe can read would change
                // the answer, and the level's whole premise is that its traffic
                // was asked for.
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
        "the OS series probe",
    );

    if targets.is_empty() {
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
        // privileges. One recorded line, not a per-host failure: every host
        // keeps the answer the passive sources gave it.
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
/// # Why this is worth a phase of its own
///
/// It is the only thing this engine can reach that states a kernel version. A
/// TCP stack's shape identifies a *family* and cannot do more: Debian 12
/// (kernel 6.1) and Debian 13 (kernel 6.12) answer this engine's probe with
/// byte-identical shapes, measured on both. A service banner names a
/// distribution release at best. An agent answering here answers outright, and a
/// kernel version is the single most actionable thing a scan can learn about a
/// Unix host, because it is what a known-vulnerability lookup keys on.
///
/// # What comes back from a box that has no kernel to name
///
/// An appliance answers with its own identity instead: `Brother NC-8700w,
/// Firmware Ver.ZL`, and that is not a failed probe. It is a make, a model, a
/// firmware and a device class off one datagram, on a host the rest of the scan
/// could only place as *something with an initial hop count of 255*. The phase
/// is named for the kernel because that is what justifies it; it is worth
/// running for either answer.
///
/// # Why it does not simply add a port to the scan
///
/// Because a detection *level* and a port *list* are different dials, and
/// crossing them would mean a scan of port 80 with active OS detection sending
/// probes to a port the caller excluded. It would also be slower for no gain:
/// establishing UDP port state means waiting on ICMP unreachables, which
/// targets rate-limit, and this phase needs no port state at all. It asks a
/// question and reads the answer.
///
/// # It does record the port
///
/// A host that answers an SNMP request has proved something is listening, more
/// directly than a SYN+ACK proves it, and a scanner that knew a port was open
/// and did not say so would be withholding a finding. An open agent answering
/// the default `public` community is also a finding in its own right: arguably
/// a more actionable one than the kernel it just disclosed.
///
/// The port is filed with the evidence that found it,
/// [`ScanResponse::UdpResponse`], so a report can distinguish it from one the
/// port scan established and never has to pretend it was asked for.
///
/// This is the *opposite* of widening the port list, not an exception to it.
/// The objection there is to sending traffic nobody requested; the traffic here
/// was requested, by the OS detection level, and what is at stake is only
/// whether the answer is reported or discarded.
///
/// # Who is asked
///
/// Every host that is up and whose kernel is still unknown, which is a
/// different and better test than "could not be named". A host already reported
/// as `Linux · Debian 13` has been named perfectly well and still has nothing to
/// say about its kernel, so it is exactly the host worth asking.
pub(super) async fn run_active_os_snmp(ctx: &ScanContext, os_detection: OsDetection) {
    if !os_detection.is_active() {
        return;
    }

    ctx.enter_stage(Stage::Os, None);

    let targets: Vec<crate::model::ip::scoped::ScopedIp> = ctx
        .host_addresses()
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
    let mut pool = ProbePool::new(
        CONNECT_CONCURRENCY,
        ctx.clone(),
        ScannerKind::OsSnmp,
        |found: Option<(
            crate::model::ip::scoped::ScopedIp,
            Port,
            crate::fingerprint::AboutTheHost,
        )>,
         _audit| {
            if let Some((key, port, about)) = found {
                ctx.update_host(key, |host| {
                    host.add_port(port);
                    if about.apply(host) {
                        named += 1;
                    }
                });
            }
        },
    );

    for target in targets {
        if ctx.handle.should_stop() {
            break;
        }
        let egress = ctx.egress_toward(target.addr());
        pool.admit(ask_for_kernel(target, egress)).await;
    }
    pool.drain().await;

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
/// Every host that is up. The record is published under the host's own name, and
/// a host that has not been named otherwise, or was named in a zone other than
/// `.local`, is asked what it calls itself first, so the pass is not confined to
/// the hosts something else happened to resolve under the right name. A host
/// running no responder leaves the first question unanswered and is asked
/// nothing more, one datagram in all.
pub(super) async fn run_active_os_mdns(ctx: &ScanContext, os_detection: OsDetection) {
    if !os_detection.is_active() {
        return;
    }

    ctx.enter_stage(Stage::Os, None);

    let targets: Vec<(crate::model::ip::scoped::ScopedIp, Option<String>)> = ctx
        .host_addresses()
        .into_iter()
        .filter(|ip| !ctx.host_expired(ip.addr()))
        .filter_map(|ip| {
            ctx.read_host(&ip, |host| {
                let name = host.hostname().map(str::to_string);
                host.status().is_up().then(|| (host.scoped_ip(), name))
            })
            .flatten()
        })
        .collect();

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
        if ctx.handle.should_stop() {
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

/// The port a Bonjour responder listens on.
const MDNS_PORT: u16 = 5353;

/// Asks a host what it calls itself, by the reverse name of its own address.
///
/// One datagram, and it is what makes the device-info query possible at all on a
/// host the scan reached by address and never resolved a name for. It leaves
/// by `egress`.
async fn own_name(
    addr: std::net::SocketAddr,
    ip: IpAddr,
    egress: crate::system::dial::Egress,
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
/// Sent to the host rather than to the multicast group: a scan is asking one host
/// about itself, and the answer is attributable only if the question was.
/// Both datagrams leave by `egress`.
async fn ask_what_hardware(
    target: crate::model::ip::scoped::ScopedIp,
    hostname: Option<String>,
    egress: crate::system::dial::Egress,
) -> Option<(crate::model::ip::scoped::ScopedIp, Vec<OsEvidence>)> {
    let addr = target.to_socket_addr(MDNS_PORT)?;

    // The name the record hangs off. Asked of the host itself where nothing
    // else resolved one, which is the ordinary case for a machine the scan
    // reached by address, and where what did resolve one was a unicast
    // resolver, whose zone publishes no record: a responder answers a reverse
    // lookup about its own address with the name it publishes under.
    let question = |name: &str| crate::protocols::mdns::build_device_info_query(name)?.ok();
    let query = match hostname.as_deref().and_then(question) {
        Some(query) => query,
        None => question(&own_name(addr, target.addr(), egress).await?)?,
    };

    // Each `key=value` is its own claim: the model and the Darwin release are
    // two facts about one machine, and a rule reads one of them.
    let evidence: Vec<OsEvidence> = crate::fingerprint::probe_udp_with_via(addr, &query, egress)
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

/// The port an SNMP agent listens on. Fixed: an agent elsewhere is one nothing
/// could have found without being told, and guessing at others would be a port
/// scan rather than a question.
const SNMP_PORT: u16 = 161;

/// Sends one SNMP request to `target` and returns what the answer said about the
/// machine.
///
/// A link-local address with no interface recorded against it yields no socket
/// address at all and is skipped: dialling it anyway would fail with an error
/// describing this host's routing rather than anything about the target.
///
/// The request leaves by `egress`.
async fn ask_for_kernel(
    target: crate::model::ip::scoped::ScopedIp,
    egress: crate::system::dial::Egress,
) -> Option<(
    crate::model::ip::scoped::ScopedIp,
    Port,
    crate::fingerprint::AboutTheHost,
)> {
    let addr = target.to_socket_addr(SNMP_PORT)?;

    let port = crate::fingerprint::baseline_port(SNMP_PORT, Protocol::Udp, PortState::Open);
    let (port, evidence, _) = crate::fingerprint::fingerprint_udp_via(addr, port, egress).await?;

    // Recorded with what found it, so a report can tell this port from one the
    // port scan established, and never has to imply it was asked for.
    let port = port.with_discovery(PortDiscovery::new(ScanResponse::UdpResponse));
    // The key, not the address: an SNMP agent on a link-local neighbour is
    // reachable here, `to_socket_addr` put the scope id on the socket, and
    // writing the answer back bare would fork the host's record.
    Some((target, port, evidence))
}

/// Measures the route to every host the scan found alive, when asked to.
///
/// Runs last, after the ports are known, and that ordering is the whole reason
/// it is a separate phase rather than part of discovery. What reaches a host
/// decides what a trace to it should be made of, and the port scan is what
/// establishes that: a host with 443 open is traced with SYNs to 443, which
/// crosses filters no ping survives. Run before the ports were known, every
/// trace would fall back to echo and most of them would stop at the first
/// firewall.
///
/// Hosts that answered nothing are skipped rather than traced. A path is
/// measured backwards from its far end and the far end's distance comes out of
/// a reply, so there is nothing to measure from; see
/// [`traceroute`](crate::scanner::strategy::topology::traceroute).
pub(super) async fn run_traceroute(
    ctx: &ScanContext,
    cfg: &crate::config::ZondConfig,
    caps: ScanCapabilities,
) {
    if !cfg.traceroute {
        return;
    }

    ctx.enter_stage(Stage::Traceroute, None);

    let mut alive: Vec<IpAddr> = ctx
        .host_addresses()
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
        "the route trace",
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
/// The embedded one because it is the only catalogue a scan has: nothing in
/// [`ZondConfig`] names a dataset, and nothing should, since the rule there is
/// that every field changes packets or timing and a catalogue changes neither.
/// A caller with their own feed runs
/// [`cve::correlate_report`](crate::cve::correlate_report) over the finished
/// report, which is what that call is for.
///
/// A sibling of the passes above and a step of its own, rather than something a
/// report builder does on the way past. It sends nothing: everything it needs
/// is already in the store, which is also why it correlates in place there
/// instead of over the copies a report is built from.
///
/// Gated on [`ServiceDetection`], because the join is on the CPE a service
/// identification produces and a scan that named no software has nothing to
/// match. That gate reads oddly at first sight, since it makes a *service*
/// setting decide whether a report carries vulnerability findings, and it is
/// the honest one: with the pass off there is no CPE anywhere to join on.
pub(super) fn run_correlation(ctx: &ScanContext, detection: ServiceDetection) {
    if detection == ServiceDetection::Off {
        return;
    }

    for key in ctx.host_addresses() {
        ctx.update_host(key, crate::cve::correlate);
    }
}

/// Assesses each gathered certificate's own posture — expiry, self-signing, a
/// weak RSA key — and records a finding for each problem.
///
/// A sibling of [`run_correlation`]: it sends nothing, deriving entirely from the
/// certificate the service pass already read off the handshake, and works in place
/// in the store. A port with no certificate, or one a clean certificate, yields
/// nothing, so this costs a walk of the store and no traffic. No gate: a scan that
/// gathered no certificate has nothing here to find.
pub(super) fn run_cert_posture(ctx: &ScanContext) {
    let now = std::time::SystemTime::now();
    for key in ctx.host_addresses() {
        ctx.update_host(key, |host| {
            // Collect first, mutate second: the read borrows the host's ports and
            // the write needs them mutably, so the two cannot overlap.
            let hits: Vec<(u16, Protocol, crate::model::finding::Finding)> = host
                .ports()
                .flat_map(|port| {
                    let number = port.number();
                    let protocol = port.protocol();
                    port.security()
                        .and_then(|security| security.certificate())
                        .map(|cert| cert.findings(now))
                        .unwrap_or_default()
                        .into_iter()
                        .map(move |finding| (number, protocol, finding))
                        .collect::<Vec<_>>()
                })
                .collect();

            for (number, protocol, finding) in hits {
                host.add_port_finding(number, protocol, finding);
            }
        });
    }
}

/// Characterises the filter in front of each host that answered, if asked.
///
/// A sibling of [`run_traceroute`]: it runs last, only against hosts that
/// answered, and does nothing unless
/// [`characterise`](crate::config::ZondConfig::characterise) was set. It sends a
/// bad-checksum probe to one open TCP port of each such host and marks a
/// middlebox on those that answer one: a reply no conformant host could have
/// sent. A host with no open TCP port is skipped: there is nowhere to aim a
/// probe whose whole point is that a listener would answer it.
pub(super) async fn run_characterise(
    ctx: &ScanContext,
    cfg: &crate::config::ZondConfig,
    caps: ScanCapabilities,
) {
    if !cfg.characterise {
        return;
    }

    let mut subjects: Vec<strategy::topology::characterise::Subject> = Vec::new();
    for key in ctx.host_addresses() {
        if ctx.host_expired(key.addr()) {
            continue;
        }
        // One open port to send the middlebox probe at, and one the scan found
        // filtered to aim the comparative probes at: a filter is doing
        // something at a filtered port, and nothing at an unfiltered one.
        let ports = ctx.read_host(&key, |host| {
            host.status().is_up().then(|| {
                let tcp = |state| {
                    host.ports()
                        .find(|port| port.protocol() == Protocol::Tcp && port.state() == state)
                        .map(|port| port.number())
                };
                (tcp(PortState::Open), tcp(PortState::Filtered))
            })
        });
        let Some(Some((open_port, filtered_port))) = ports else {
            continue;
        };
        if open_port.is_none() && filtered_port.is_none() {
            continue;
        }
        if let Some(host) = routable(key) {
            subjects.push(strategy::topology::characterise::Subject {
                host,
                open_port,
                filtered_port,
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
        "the filter characterisation",
    );

    if subjects.is_empty() {
        return;
    }

    strategy::topology::characterise::characterise(ctx, subjects).await;
}

/// Asks each host that answered which IP protocols its stack takes delivery of,
/// where the caller named any.
///
/// A sibling of [`run_characterise`]: it runs last, only against hosts that
/// answered, and does nothing unless
/// [`ip_protocols`](crate::config::ZondConfig::ip_protocols) names some. Unlike
/// that pass it needs no port to aim at, since what it asks about sits below the
/// ports; a host with nothing open is exactly the one worth asking, because a
/// tunnel endpoint or a router terminates a protocol and listens on nothing.
pub(super) async fn run_ip_protocols(ctx: &ScanContext, cfg: &crate::config::ZondConfig) {
    if cfg.ip_protocols.is_empty() {
        return;
    }

    let mut targets = Vec::new();
    for key in ctx.host_addresses() {
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

    strategy::protocols::probe(ctx, &targets, &cfg.ip_protocols).await;
}

/// Establishes what each TLS port accepts, where the caller asked for it.
///
/// A pass of its own, and it runs last among the port-level passes because what
/// it needs first is the list of ports that speak TLS at all. Service detection
/// produces that: a port with a `security` record is one a handshake completed
/// against, which is the only evidence this engine has that an endpoint is worth
/// enumerating. A port nobody handshook is skipped rather than guessed at, so a
/// scan run with service detection off enumerates nothing and says so through
/// the setting it recorded.
///
/// ## What it costs the target
///
/// One bare TCP connection per offer, each carrying a single ClientHello and
/// torn down before a handshake completes. Nothing is negotiated and no
/// application-level session exists, so a target's *application* logs stay
/// empty; its connection log does not, and on a server accepting many suites
/// this is dozens of entries against one port. That is the whole reason the
/// pass is opt-in.
///
/// Ports are walked with the same concurrency the service pass uses, and a host
/// that has spent [`ZondConfig::host_timeout`](crate::config::ZondConfig::host_timeout)
/// is left alone: this is the most expensive thing the engine does to a single
/// endpoint, and the last place to spend a budget that has already run out. The
/// question is put again before every offer of a walk, so a budget that runs
/// out part way through one ends it there.
pub(super) async fn run_tls_enumeration(ctx: &ScanContext, cfg: &crate::config::ZondConfig) {
    if !cfg.tls_enumeration {
        return;
    }

    // Snapshotted before anything awaits, so no store guard is held across a
    // connection.
    let targets = tls_ports(ctx);
    if targets.is_empty() {
        return;
    }

    ctx.enter_stage(Stage::Tls, Some(targets.len() as u64));

    info!(
        "enumerating what {} accept",
        counted(targets.len() as u128, "TLS port", "TLS ports")
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
            // Counted as each walk ends, however it ended: one its host's budget
            // cut short is written down with the versions it left unfinished,
            // and the pass has nothing more to ask of that endpoint.
            ctx.stage_advanced();

            if let Some((key, number, support)) = found {
                record_tls_support(ctx, key, number, support);
            }
        },
    );

    for (address, number) in targets {
        if ctx.handle.should_stop() {
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
/// The `security` record is the filter: it is written only where a TLS
/// handshake succeeded, so it names exactly the endpoints an enumeration has a
/// reason to ask. Guessing from the port number instead would spend a dozen
/// connections on every open port a scan happened to find.
fn tls_ports(ctx: &ScanContext) -> Vec<(crate::model::ip::scoped::ScopedIp, u16)> {
    let mut targets = Vec::new();
    for host in ctx.store.iter() {
        let address = host.value().scoped_ip();
        for port in host.value().ports() {
            // TCP only: a `security` record is written by a completed TLS
            // handshake, and nothing here speaks DTLS.
            if port.protocol() == Protocol::Tcp
                && port.state() == PortState::Open
                && port.security().is_some()
            {
                targets.push((address.clone(), port.number()));
            }
        }
    }
    targets
}

/// Enumerates one endpoint, or `None` where its address cannot be dialled.
///
/// The walk is up to 80 connections under one version, so it asks before each
/// of them what the admission loop asked before the endpoint: whether the scan
/// is still running and the host still within its budget. The scan's own stop
/// is asked first, so a host is not named as left for its budget when it was
/// the scan that stopped; a host whose budget ran out mid-walk is named by
/// [`ScanContext::host_expired`] the moment it answers true.
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
    let support = crate::fingerprint::enumerate_tls_while(socket, ctx.egress_toward(ip), || {
        !ctx.handle.should_stop() && !ctx.host_expired(ip)
    })
    .await;
    // An endpoint that accepted nothing and left no walk unfinished is left
    // alone rather than recorded as an empty enumeration: the two are the same
    // value, and writing it back would announce a host update that carries no
    // new fact. One whose walks were cut short is written back even with
    // nothing accepted, since that is a fact a reader needs.
    (!support.is_empty()).then_some((address, number, support))
}

/// Folds what an endpoint accepts back into its port.
///
/// Through [`Host::add_port`](crate::model::host::Host::add_port) rather than by
/// reaching into the recorded port, so the fold takes the same confidence-driven
/// path every other pass does. The port carried here holds nothing but the
/// enumeration: `Security::merge` fills what is missing, so the version and
/// certificate the service pass recorded survive intact, and an enumeration a
/// resumed sitting restored onto the port gives way, version by version,
/// wherever this one went further.
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
/// Target selection is from the store and not from the plan: "the
/// passive sources concluded nothing" is only true once those sources have
/// finished, and the store is where that conclusion lives. Every host that
/// answered nothing a TCP rule could read, a stock Windows firewall drops
/// rather than refuses, is here, and an echo reply is the one packet such a
/// host still gives.
///
/// Runs after [`run_active_os_series`], which has by then read everything a
/// host with an open or closed TCP port can be made to say. What is left here is
/// the machine that answered no TCP probe at all, and one ping is the cheapest
/// thing that still reaches it.
///
/// Declines quietly rather than failing when there is nothing to do: a scan
/// where every host was already named, or where none were, has not lost
/// anything by not pinging.
pub(super) async fn run_active_os_probe(
    ctx: &ScanContext,
    os_detection: crate::config::OsDetection,
    tuning: ProbeTuning,
    caps: ScanCapabilities,
) {
    if !os_detection.is_active() {
        return;
    }

    ctx.enter_stage(Stage::Os, None);

    // A host worth pinging is one the scan found and could not name. Hosts the
    // scan never recorded were never asked about, and pinging addresses nobody
    // named is a discovery sweep rather than identification.
    let mut unnamed: Vec<IpAddr> = ctx
        .host_addresses()
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
        "the OS echo probe",
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
        // privileges. One recorded line, not a per-host failure: every host
        // keeps the answer the passive sources gave it, which is the state the
        // caller was already looking at.
        Err(e) => ctx.record_failure(
            ScannerKind::OsEcho,
            format!("the active echo probe could not open its transport: {e}"),
        ),
    }
}

/// The addresses of `target_map` that still have a target `settled` does not
/// account for: what a sitting of a port scan asks about host by host.
///
/// The liveness sweep and the enrichment beside the port scan are both aimed
/// here rather than at every address in the plan. A resumed sitting probes only
/// what an earlier one left, and an address with nothing left has already been
/// swept by the sitting that settled it; asking again sends the network a
/// question the job already put. For a sitting that continues nothing, this is
/// every address the plan names a port at. See [`Checkpoint::remaining_hosts`].
pub(super) fn unsettled_ips(target_map: &TargetMap, settled: &Checkpoint) -> IpSet {
    settled.remaining_hosts(&TargetIndex::of(target_map))
}

/// Starts the background hostname resolver as its own task.
///
/// The resolver listens for raw DNS and mDNS traffic and answers reverse lookups
/// for any IP sent down `dns_rx`, independent of and concurrent with whatever
/// scanning strategies are running. When it fails to start, most likely because
/// no usable network socket could be opened, the failure is logged and `None` is
/// returned rather than propagated, since a scan without hostname resolution is
/// still useful.
pub(super) async fn spawn_resolver(
    dns_rx: UnboundedReceiver<IpAddr>,
) -> JoinHandle<Option<HostnameResolver>> {
    tokio::spawn(async move {
        match HostnameResolver::new(dns_rx) {
            Ok(resolver) => {
                // Working, not news: every run that resolves names starts one,
                // and the failure below is the case worth a line.
                success!(verbosity = 3, "successfully initialized hostname resolver");
                Some(resolver.run().await)
            }
            Err(e) => {
                error!("resolver failed to start: {e}");
                None
            }
        }
    })
}

/// Takes the link-local targets that name no interface out of `target_map`,
/// refusing each, and hands back the zones the rest were named on.
///
/// A port scan reaches its targets over the routing table, which cannot carry a
/// link-local address without an interface, and every interface holds an
/// `fe80::/64`, so an unscoped one names nothing this scan can send to. Written
/// `fe80::1%en0` it names a segment outright, and the [`ZoneMap`] returned here
/// is how the interface reaches the scanners: a target is addressed one at a
/// time, and the zone is written on the range rather than on the addresses
/// inside it.
///
/// A range only partly link-local, such as `fe80::/10` widened by hand, is
/// judged by [`Ipv6Range::is_ambiguous`](crate::model::ip::range::Ipv6Range::is_ambiguous),
/// which is the predicate the discovery classifier uses for the same question.
///
/// Two ranges naming one address on different interfaces are refused together.
/// Which segment was meant is the one thing that cannot be recovered, and a
/// verdict filed under a bare address would be a verdict about whichever of them
/// answered first.
///
/// Withheld here rather than declined at the socket, because a target dropped
/// at the send is a target with no verdict, no settlement and no line in the
/// report: `resolve_unasked` only accounts for what is still queued, and one
/// already taken off the stream is simply gone. A refusal says what was not
/// covered and why, which is what the caller can act on.
fn withhold_ambiguous_targets(target_map: &mut TargetMap, ctx: &ScanContext) -> ZoneMap {
    let mut refused: Vec<Ipv6Range> = Vec::new();
    let mut contested: Vec<Ipv6Range> = Vec::new();
    let mut zones = ZoneMap::new();

    // Read once, and only for a scan that named a zone at all: the names come
    // from the host's interface table, and every target below is looked up in
    // the same list.
    let named_a_zone = target_map
        .units
        .iter()
        .flat_map(|unit| unit.ips().v6())
        .any(|range| range.zone().is_some());
    let links = match named_a_zone {
        true => crate::system::interface::interfaces(),
        false => Vec::new(),
    };
    let names: Vec<(u32, &str)> = links
        .iter()
        .map(|link| (link.index(), link.name()))
        .collect();

    for range in target_map.units.iter().flat_map(|unit| unit.ips().v6()) {
        if range.is_ambiguous() {
            refused.push(*range);
        } else if zones.contests(range) {
            contested.push(*range);
        } else {
            zones.insert(*range, &names);
        }
    }

    let mut kept = Vec::with_capacity(target_map.units.len());
    for unit in std::mem::take(&mut target_map.units) {
        let (ips, ports) = unit.into_parts();
        let mut walkable = IpSet::new();

        for range in ips.v4() {
            walkable.push_v4_range(*range);
        }
        for range in ips.v6() {
            if !refused.contains(range) && !contested.contains(range) {
                walkable.push_v6_range(*range);
            }
        }
        walkable.canonicalize();

        if !walkable.is_empty() {
            kept.push(TargetSet::new(walkable, ports));
        }
    }
    target_map.units = kept;

    refused.sort_unstable_by_key(|range| range.start_addr());
    refused.dedup();
    for range in refused {
        ctx.record_refusal(
            plan::RefusedStep::link_local_port_target_needs_an_interface(&range).into(),
        );
    }
    for range in contested {
        ctx.record_refusal(
            plan::RefusedStep::link_local_port_target_names_two_segments(&range).into(),
        );
    }

    zones
}

/// Probes `target_map`'s ports, enriching the hosts as it goes.
///
/// Nothing is opened for an empty map. A liveness phase that found nothing is a
/// finished answer, and raw sockets held to probe no targets are a failure this
/// would report for no reason.
pub(super) async fn run_port_phase(
    mut target_map: TargetMap,
    live: Option<IpSet>,
    ctx: &ScanContext,
    caps: ScanCapabilities,
    cfg: &ZondConfig,
    settled: Checkpoint,
) {
    if target_map.is_empty() {
        return;
    }

    // Before the plan is built, so the counts a phase records describe what it
    // was actually going to probe.
    let zones = withhold_ambiguous_targets(&mut target_map, ctx);
    if target_map.is_empty() {
        return;
    }
    // Before any verdict is recorded: a finding written under a bare `fe80::…`
    // has to reach the host the sweep already found on that interface.
    ctx.learn_zones(zones.clone());

    let target_count = target_map.gross_targets().unwrap_or(0) as usize;
    // SCTP is planned from the targets rather than from the configuration,
    // since the ports are what name it and no default list holds one. UDP is
    // planned by the configuration, except under an idle scan, whose refusal of
    // it is owed only where the targets name a UDP port.
    let mut plan = super::plan::PortScanPlan::build(cfg, caps.privilege);
    if target_map.names(Protocol::Sctp) {
        plan.cover_sctp(caps.privilege);
    }
    if target_map.names(Protocol::Udp) {
        plan.cover_udp();
    }

    // Over what this sitting will probe, which is the addresses an earlier one
    // left a target at, and of those the hosts that answered where the liveness
    // phase ran: an address it found down is sent nothing here, and was reached
    // by nothing.
    let mut probed = unsettled_ips(&target_map, &settled);
    if let Some(live) = &live {
        probed = within(&probed, live);
    }
    let beyond = caps.beyond_frames(&probed, &cfg.send_source, interface::FrameSender::Probe);
    let raw = RawReach::of(&probed, beyond.targets.clone());
    let named: Vec<Protocol> = Protocol::ALL
        .into_iter()
        .filter(|protocol| target_map.names(*protocol))
        .collect();
    let built = build_port_scanner(
        plan,
        &named,
        ctx,
        target_count,
        cfg.probe_tuning(),
        &zones,
        &raw,
    );
    // After the build rather than before, since only the build knows whether
    // anything stands in for the raw strategies there: a technique with no
    // connect form is refused on those targets instead, and nothing reaches
    // them by connect.
    if built.reached_by_connect {
        announce_beyond_frames(&beyond);
    }

    // Only when nothing has enriched these hosts already. With the liveness
    // phase on, it has: the pass that established they are there is the same one
    // that reads their hardware addresses and names. And only over the hosts
    // this sitting probes, since one whose every target an earlier sitting
    // settled was enriched by that sitting, and a sitting with nothing left to
    // probe has nothing to enrich.
    let enrichment = if cfg.assume_up && built.opened_raw() && !probed.is_empty() {
        let addresses = probed.clone();
        let unframed =
            caps.beyond_frames(&addresses, &cfg.send_source, interface::FrameSender::Sweep);
        let mut plan = super::plan::DiscoveryPlan::build(
            addresses,
            Scope::Targeted,
            &cfg.exclusions,
            &cfg.send_source,
        );
        plan.withhold(&unframed.targets);
        // What enrichment is for is a hardware address and a round trip, and a
        // connect step yields neither: it would ask a handful of ports on a
        // host whose ports are being asked anyway, and ask them again on a
        // resumed sitting that has nothing left to probe.
        plan.steps_mut()
            .retain(|step| !matches!(step, super::plan::DiscoveryStep::Connect { .. }));
        Some(Enrichment::spawn(plan, ctx, caps, cfg.probe_tuning()).await)
    } else {
        None
    };

    // Numbered against the whole plan and filtered afterwards: to what an
    // earlier sitting did not settle, and to the hosts that answered. Both
    // filters run after the numbering, because both of them are properties of
    // this sitting and the numbering is a property of the job.
    let mut dispatcher = super::dispatcher::Dispatcher::new(target_map).resuming(settled);
    if let Some(live) = live {
        dispatcher = dispatcher.only_live(live);
    }
    let rx = dispatcher.run(ctx);

    run_port_scan(built.scanner, rx, ctx, cfg.service_detection, cfg.detection).await;
    finish_enrichment(enrichment, caps, ctx).await;
    // Passive first, then active: the echo probe is aimed at the hosts the
    // passive sources could not name, and it can only know which those are once
    // they have run.
    run_passive_os_identification(ctx, cfg.os_detection);
}

/// The plan as the port phase actually probed it.
///
/// Not what the dispatcher walks. That is the whole plan, so that a position
/// means the same target in every sitting. see
/// [`live_addresses`]. This is what the phase *covered*, which is a different
/// number and the one a [`TargetScope`](crate::report::TargetScope)
/// records: a reader compares it against the liveness phase's to see how much of
/// what they asked about went unprobed, and a scope that claimed the whole plan
/// would report a scan that covered ground it deliberately skipped.
///
/// Narrows every unit rather than rebuilding one set against one port list,
/// because a unit may carry ports no other one does: `192.0.2.1:8080` names its
/// own, and a subset that dropped that would answer a different question.
pub(super) fn probed_subset(target_map: &TargetMap, live: &IpSet) -> TargetMap {
    // Walked once, not once per unit. `live.iter()` expands every address of
    // every host the sweep found, so doing it inside the loop would cost that
    // walk again for each target set - and a scan naming several port lists over a
    // wide range is exactly when both numbers are large.
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
/// Chosen from the ports the scan is about, because those are the ports a
/// filter in front of an SCTP host is likeliest to pass. Among them the
/// catalogue's order decides, which is this engine's opinion about which SCTP
/// port something is actually running on; a port the catalogue has never heard
/// of loses to one it has, and a scan naming only unknown ports takes the
/// lowest of them so the choice is still the same on every run.
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

/// Every address the liveness pass found a host at.
///
/// A set rather than a narrowed plan. Were the port phase handed a `TargetMap`
/// rebuilt from these, the dispatcher would number *that*, so a position would
/// be counted in a plan that depends on which hosts happened to answer, and two
/// sittings of one job could disagree about what position 400 means. The
/// addresses travel to
/// [`Dispatcher::only_live`](crate::scanner::dispatcher::Dispatcher::only_live)
/// instead, which filters after numbering.
///
/// Every address of a host is included, not only the one it is filed under. A
/// dual-stack machine found over IPv6 is still the machine whose IPv4 address
/// was asked about, and a unit naming either of them meant this host.
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
/// This is where the store's key becomes a bare address, and the one place a
/// key may be narrowed to one. The strategies below it, the trace, the echo
/// probe, reach a host over the routing table and reason in addresses from end
/// to end: a socket takes one, a reply carries one, and a hop table is keyed by
/// one. Handing them a `ScopedIp` would key their reply matching on something no
/// reply carries.
///
/// So they are given what they can use, and a host whose address is meaningless
/// without an interface is not given at all. `fe80::1` cannot be routed: the
/// kernel needs a scope id and a raw routed probe has nowhere to put one, which
/// is the same refusal
/// [`ScopedIp::to_socket_addr`](crate::model::ip::scoped::ScopedIp::to_socket_addr)
/// makes rather than attempting a send that fails for a reason having nothing
/// to do with the target. Those hosts are the local scanner's, which reaches
/// them at the link layer and already holds them under the interface they were
/// read on.
///
/// It also keeps the store honest. A routed strategy writes its finding back
/// under the address it probed, and an address that is not the whole key would
/// land in a second entry: one host in the report becoming two, each holding
/// half of what was found.
fn routable(key: crate::model::ip::scoped::ScopedIp) -> Option<IpAddr> {
    (!crate::model::ip::scoped::ScopedIp::needs_zone(&key.addr())).then(|| key.addr())
}

/// The addresses of `set` that `of` also holds.
///
/// Two subtractions, each linear in ranges rather than in addresses: what `set`
/// has that `of` lacks, taken back out of `set`.
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

    /// Which SCTP port a sweep asks about, when the scan named several.
    ///
    /// The catalogue's order decides, so a scan naming a well-known port and an
    /// arbitrary one asks on the one something is likely to be listening on. A
    /// filter in front of an SCTP host is likeliest to pass that port, and a
    /// sweep that picked the other would report the host down.
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
    /// time, so two runs of one command sweep alike.
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

    /// `fe80::1` with no interface named. Every interface holds an `fe80::/64`,
    /// so a scan given one has no segment to send on and nothing to choose
    /// between them.
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

        withhold_ambiguous_targets(&mut map, &ctx);

        assert!(map.is_empty(), "nothing is left for a scanner to probe");
        let refusals = ctx.refusals_snapshot();
        assert_eq!(refusals.len(), 1);
        assert!(
            refusals[0].reason().contains("fe80::1%en0"),
            "the refusal says what the caller could write instead: {}",
            refusals[0].reason()
        );
        assert!(
            ctx.failures_snapshot().is_empty(),
            "nothing went wrong; the engine declined"
        );
    }

    /// The same address written `fe80::1%en0`. It names one segment, the scan
    /// can send to it, and the interface it named comes back for the phases that
    /// open a socket or a raw send.
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

        let zones = withhold_ambiguous_targets(&mut map, &ctx);

        assert_eq!(map.units.len(), 1, "the target is still there to probe");
        assert_eq!(
            zones.zone_of(&"fe80::1".parse().expect("an address")),
            Some(15),
            "and the send knows which interface to leave by"
        );
        assert!(ctx.refusals_snapshot().is_empty());
    }

    /// `fe80::1%en0` and `fe80::1%en1` are two machines, and a port scan files
    /// its verdicts under the address it probed. Both are refused rather than
    /// merged into one host holding two segments' answers.
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

        let zones = withhold_ambiguous_targets(&mut map, &ctx);

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

    /// Refusing the whole unit over one bad address in it would discard targets
    /// the caller named and the engine can reach.
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

        withhold_ambiguous_targets(&mut map, &ctx);

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

        withhold_ambiguous_targets(&mut map, &ctx);

        assert_eq!(map.units[0].ips().len(), 4);
        assert!(ctx.refusals_snapshot().is_empty());
    }
    use super::*;
    use crate::model::host::{Host, HostStatus};
    use crate::report::Refusal;
    use crate::scanner::session::ScanSession;
    use tokio::sync::mpsc;

    /// A finished sweep of the segment the scanner sits on is finished: this
    /// host's own address, recorded up without a probe, is settled with the
    /// rest, so the watermark reaches the end of the plan rather than stopping
    /// behind it and leaving the sweep resumable with nothing left to ask.
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

    /// What this function exists for. Without it a `/64` handed to the
    /// unprivileged path would be probed one address at a time until the process
    /// was killed, while the same range with root is refused in the plan before a
    /// packet is sent: one engine giving two answers about one range.
    #[test]
    fn a_range_too_large_to_walk_is_refused_rather_than_started() {
        let (_session, ctx) = ScanSession::new();

        let kept = walkable(ip_set(&["2001:db8::/64"]), &ctx);

        assert!(kept.is_empty(), "nothing here can be walked");

        // A refusal rather than a failure: nothing broke, and a reader who
        // cannot tell the two apart learns to ignore both.
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

    /// Refusing the whole set over one unwalkable range in it would discard
    /// addresses somebody named and could have had.
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

    /// A set that is entirely walkable is handed back untouched, and, the part
    /// that matters, files no failure. A report claiming a refusal that never
    /// happened marks a complete scan as partial.
    #[test]
    fn a_set_that_can_be_walked_is_left_alone_and_files_nothing() {
        let (_session, ctx) = ScanSession::new();

        let kept = walkable(ip_set(&["192.0.2.0/24", "2001:db8::/120"]), &ctx);

        assert_eq!(kept.len(), 512);
        assert!(ctx.failures_snapshot().is_empty());
    }

    /// IPv4 is not bounded here. A `/8` is sixteen million probes,
    /// which is unreasonable rather than impossible, and which of those it is is
    /// a judgement for whoever is driving the engine.
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

    /// A scan whose raw strategies reach everything, stated rather than read
    /// from the machine running the tests.
    fn raw_everywhere() -> ScanCapabilities {
        ScanCapabilities {
            privilege: Privilege::Raw,
            frames_only: false,
            dns: false,
        }
    }

    /// The plan refuses what it can foresee and `ensure_coverage` catches what
    /// only the attempt reveals. Both have the same words for the same cause, so
    /// a coverage check that did not know the plan had already spoken would
    /// record an unprivileged flag-probe scan's failure twice, once from each.
    ///
    /// A consumer counting failures would over-report, and one rendering them
    /// would show the same paragraph to a user twice.
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
    /// An idle scan reads a third party's counter, which a UDP probe gives it no
    /// way to move, and sending one directly would announce the host the
    /// technique exists to hide. So the plan holds no UDP step, and the ports
    /// reach the router with nothing to take them. Unless a refusal names them,
    /// the router files them as a scan that had no scanner for their protocol:
    /// a failure, which reads as a defect in the engine and is its own decision
    /// told as an accident.
    ///
    /// Through the whole port phase, which is where the plan learns the targets
    /// name a UDP port. The zombie is excluded so the idle scan is refused
    /// whatever privilege runs the test, and nothing is sent anywhere.
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

        run_port_phase(map, None, &ctx, caps, &cfg, Checkpoint::default()).await;

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
    /// has no target a raw strategy can reach. Opened anyway, each holds a
    /// capture on every interface and sends nothing: two audit lines of `0/0
    /// hosts` on the machine this was measured on. Not opened, the connect
    /// strategies take every target, nothing is reported as failing, and the
    /// phase still says its evidence is connect evidence.
    #[test]
    fn nothing_within_a_frames_reach_opens_no_raw_strategy() {
        let cfg = ZondConfig::default();
        let (_session, ctx) = ScanSession::new();

        let built = build_port_scanner(
            plan::PortScanPlan::build(&cfg, Privilege::Raw),
            BOTH,
            &ctx,
            1,
            cfg.probe_tuning(),
            &ZoneMap::new(),
            &RawReach::Nothing(ip_set(&["127.0.0.1"])),
        );

        assert!(!built.opened_raw(), "nothing raw was opened");
        assert_eq!(
            built.scanner.supported_protocols(),
            vec![Protocol::Tcp, Protocol::Udp],
            "and the connect strategies cover both protocols"
        );
        assert!(ctx.take_failures().is_empty(), "declining is not failing");
        assert!(ctx.take_refusals().is_empty());
        assert_eq!(ctx.take_reached_by_connect().len(), 1);
    }

    /// **A technique refused for a target is one refusal, and not a scanner
    /// failure as well.**
    ///
    /// A FIN scan of loopback with no raw socket to send it has no connect form
    /// to fall back on, so its TCP ports are refused, on the connect path at
    /// planning and on the frames path when the phase finds loopback beyond a
    /// frame. The targets still arrive at the router, which is right: they are
    /// still unprobed and a resume should still owe them. Counted there as
    /// having no scanner, they became a second entry saying the scan had lost
    /// them, which reads as an engine defect and is the same decision told
    /// twice. And nothing was reached by connect, since nothing stood in for
    /// the refused technique and the scan named no UDP port a connect could
    /// have taken.
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
                ctx.take_reached_by_connect().is_empty(),
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
    /// Enough of a subscriber to read what the engine says and nothing more:
    /// spans are accepted and ignored, since no line under test is inside one.
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

    /// The one line a run without raw sockets opens with says what it probes
    /// with, and a scan naming UDP ports probes them with plain datagrams, so
    /// "TCP connect only" is a line saying less than happened.
    #[test]
    fn an_unprivileged_run_says_it_probes_udp_when_it_does() {
        let unprivileged = ScanCapabilities {
            privilege: Privilege::Connect,
            frames_only: false,
            dns: false,
        };

        for (probes_udp, expected) in [
            (
                true,
                "no raw sockets: probing with TCP connect and plain UDP datagrams",
            ),
            (false, "no raw sockets: probing with TCP connect only"),
        ] {
            let heard = Heard::default();
            tracing::subscriber::with_default(heard.clone(), || unprivileged.announce(probes_udp));

            let said = heard.0.lock().expect("an unpoisoned log").clone();
            assert_eq!(said, [expected], "probing udp: {probes_udp}");
        }
    }

    /// A frames-only run whose every target is out of a frame's reach refuses
    /// what nothing stands in for in the words that say so. It holds the link
    /// layer, and told it has no raw sockets, which is the connect path's
    /// reason, a reader goes looking for a privilege they already have rather
    /// than at the targets, which are what no frame reaches.
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
                reason.contains("self-built frames") && reason.contains("out of a frame's reach"),
                "the frames path's reason: {reason}"
            );
            assert!(
                !reason.contains("does not have"),
                "not the connect path's: {reason}"
            );
            assert!(
                reason.contains("1 target is") && reason.contains("port on it was probed"),
                "and it counts the one target it names: {reason}"
            );
        }
    }

    /// Host enrichment is keyed on whether a raw scan is happening, and a raw
    /// scan is one whatever segment its probes carry. Read off the strategy's
    /// name instead, a FIN scan, not being called `syn_port`, would not count as
    /// raw, and every non-SYN privileged scan would quietly lose its MAC
    /// addresses and round trips.
    #[test]
    fn a_raw_scan_earns_enrichment_whichever_technique_it_carries() {
        for technique in TcpScanTechnique::ALL {
            let built = BuiltPortScan {
                scanner: Box::new(StubScanner(vec![Protocol::Tcp])),
                opened: vec![plan::PortScanStep::RawTcp { technique }],
                reached_by_connect: false,
            };
            assert!(built.opened_raw(), "a raw {technique} scan is still raw");
        }

        let unprivileged = BuiltPortScan {
            scanner: Box::new(StubScanner(vec![Protocol::Tcp])),
            opened: vec![
                plan::PortScanStep::ConnectTcp,
                plan::PortScanStep::ConnectUdp,
            ],
            reached_by_connect: false,
        };
        assert!(
            !unprivileged.opened_raw(),
            "a connect scan has no MAC or round trip to offer"
        );
    }

    /// With no privileged scanner at all, both connect fallbacks stand in.
    #[test]
    fn an_unprivileged_scan_covers_both_protocols() {
        let protocols = covered(Vec::new());
        assert!(protocols.contains(&Protocol::Tcp));
        assert!(protocols.contains(&Protocol::Udp));
    }

    /// The per-protocol fallback: a host that can build the raw UDP scanner but
    /// not the SYN one must still probe TCP. Gating on "any privileged scanner
    /// exists" would leave those targets with no route at all, so they would be
    /// dropped without a record.
    #[test]
    fn a_protocol_without_a_privileged_scanner_still_gets_a_fallback() {
        let protocols = covered(vec![Box::new(StubScanner(vec![Protocol::Udp]))]);
        assert!(
            protocols.contains(&Protocol::Tcp),
            "TCP targets would be silently dropped"
        );
        assert!(protocols.contains(&Protocol::Udp));
    }

    /// A connect scan is a substitute for a SYN scan and for nothing else. Asked
    /// for a technique it cannot express, an unprivileged scan has to leave the
    /// TCP half undone and say so - a silent substitution would hand back
    /// verdicts from a technique nobody chose.
    ///
    /// The case is a plan that *did* intend TCP, whose raw socket then would
    /// not open. A plan that never intended it refused before reaching here;
    /// see `a_refusal_the_plan_already_made_is_not_recorded_again`.
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
    /// added - a connect scanner beside them would re-probe the same ports.
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
        // Two scanners in, two scanners out: nothing was added beside them.
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

    /// What this exists for: a frames-only scan's raw routes are handed every
    /// address but the ones a frame cannot reach, so without a strategy of
    /// their own those addresses would reach no scanner at all and every port
    /// on loopback would come back unasked. Each protocol the raw routes cover
    /// gets its connect strategy for them alone, and the phase records that it
    /// did.
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
            ctx.take_reached_by_connect().len(),
            1,
            "the phase has to say its loopback evidence is connect evidence"
        );
    }

    /// The same rule the whole-scan fallback keeps, applied to the part: a
    /// connect scan cannot send a FIN, so the TCP ports on what a frame cannot
    /// reach are refused rather than answered by a different question. UDP
    /// still has its stand-in.
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

    /// Nothing stands in for an INIT, on part of a scan as on the whole of one.
    /// Refused, and not recorded as reached by connect, since nothing was.
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
        assert!(ctx.take_reached_by_connect().is_empty());
    }

    /// A protocol whose raw strategy did not open at all is refused once, for
    /// every address, and not a second time for the addresses a frame would
    /// not have reached anyway.
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

    /// The mirror of the double-record: a plan that never intended TCP gets no
    /// connect fallback for it either, however open-port-finding the technique
    /// would have been. Nothing intended it, so there is nothing to stand in
    /// for.
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

    /// The gap this pass exists to close: a sweep that learned a host's hardware
    /// and its name, and concluded nothing from either.
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

    /// `Off` means identify nothing. It costs no packets to disobey, which is
    /// exactly why obeying it has to be tested: a caller who asked for a report
    /// containing only what they requested must not find a fingerprint in it.
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
    /// The test is "is the kernel known", not "was the host named": a host
    /// reported as `Linux · Debian 13` has been named perfectly well and still
    /// has nothing on record about its kernel, so it is exactly the host worth
    /// asking. Getting this backwards would skip the population the phase exists
    /// for.
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
        // Named, with no kernel: still worth asking. On loopback, so the
        // question never leaves the machine running the suite: Linux refuses it
        // with a port-unreachable and macOS, holding `127.0.0.1` alone, drops it.
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

        // No SNMP agent answers there, so nothing is recorded. What this pins
        // is the selection: the phase must run at all, and must not fail, for a
        // store in exactly this state.
        run_active_os_snmp(&ctx, OsDetection::Active).await;

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

    /// A host that answers has proved a port open, and a scanner that knew and
    /// did not say would be withholding a finding.
    ///
    /// The other way to build it is to discard the answer, on the reasoning
    /// that 161 is not a port the caller asked to scan. That confuses two
    /// things: the objection to widening the port list is to sending traffic
    /// nobody requested, and this traffic *was* requested: by the detection
    /// level.
    /// Once it is sent, all that remains is whether the answer is reported or
    /// thrown away, and an open agent answering the default community is a
    /// finding in its own right.
    ///
    /// Recorded with the evidence that found it, so a report never has to imply
    /// it was asked for.
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

            run_active_os_snmp(&ctx, level).await;

            assert!(
                ctx.take_probe_stats().is_empty(),
                "{level} put a probe on the wire"
            );
        }
    }

    /// The series probe opens a raw socket, so it must not open one to probe
    /// nothing. Every host here answered no TCP probe, which is the ordinary
    /// state after a discovery sweep, and the phase has to notice that from the
    /// store *before* reaching for a transport it would then have to report
    /// failing to get.
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

    /// Every level below `Active` sends nothing of its own, and this phase is
    /// the whole reason `is_active` exists. A caller at the default must find
    /// their scan byte-identical to one with detection off.
    #[tokio::test(flavor = "current_thread")]
    async fn the_series_probe_sends_nothing_below_the_active_level() {
        use crate::model::port::{Port, PortState, Protocol};

        for level in [OsDetection::Off, OsDetection::Passive] {
            let (_session, ctx) = ScanSession::new();
            let ip: IpAddr = "192.0.2.4".parse().expect("a valid address");
            // A host that *would* be followed, so the only thing declining the
            // phase is the level itself.
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

    /// The pass runs over every host a sweep found, and most of them have
    /// nothing to go on. That must leave them alone rather than guess.
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

    /// A host the store holds but that never answered is not a host to spend a
    /// probe per port on.
    ///
    /// Worth testing rather than assuming: a target nothing answers for usually
    /// leaves *no* store entry at all, so this filter is only reached by a host
    /// that was recorded and still is not alive.
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
    /// over IPv6, the IPv4 address somebody actually typed is still live: it is
    /// the same machine, and it is the one that was asked about.
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

    /// Nothing answered, so nothing is live. The plan is unchanged either way:
    /// what an empty answer costs is every one of its targets being settled as
    /// [`Skipped`](crate::journal::settle::Outcome::Skipped) rather than probed.
    #[test]
    fn an_empty_store_has_nothing_live() {
        let (_session, ctx) = store_holding(Vec::new());

        assert!(live_addresses(&ctx).is_empty());
    }

    /// A scan that identified software carries the vulnerabilities that
    /// identification implies, with no second pass a caller has to remember.
    ///
    /// Performed by a named step of its own rather than as a side effect of
    /// `PhaseRecorder::finish`.
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
        assert_eq!(
            port.findings().count(),
            1,
            "the vulnerable Apache build should have been correlated"
        );
        assert!(
            port.findings()
                .any(|f| f.detection().id() == "zond:cve-kev")
        );
    }

    /// At [`ServiceDetection::Off`] nothing asked a port what it was, so there
    /// is nothing to join on, and the step does not run even where a CPE is
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
    /// It reads the offer rather than counting connections, because the pass
    /// walks the five versions concurrently: a server answering "the first
    /// connection" would answer whichever version happened to arrive first, and
    /// the walk would credit none of them.
    async fn tls_endpoint(suite: u16) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("has an address");

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
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
    /// Accepting everything is what makes a walk long: each answer removes one
    /// suite from the offer, so a walk nothing stops puts every TLS 1.2 suite
    /// to it, one connection each. Each connection is served on its own task so
    /// the pause is paid per offer, as a slow server charges it, rather than
    /// queued behind the other versions' offers.
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
            while let Ok((mut stream, _)) = listener.accept().await {
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
        // The `security` record is the filter the pass selects on: it is written
        // only where a handshake completed, so a port without one is skipped.
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

    /// The dial governs the pass. Off, nothing is asked and nothing is written,
    /// which is what keeps a default scan from paying for this.
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

    /// Switched on, the pass reaches the endpoint, writes what it accepts back
    /// onto the port, and leaves the handshake's own record intact.
    ///
    /// The write-back is the part worth testing: it folds through the same
    /// confidence-driven merge every other pass uses, and a merge in the wrong
    /// direction would drop the enumeration without a word.
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
    /// With TLS enumeration switched on this is the slowest pass a scan runs,
    /// up to eighty connections a version against an endpoint accepting
    /// everything, and a stage that announces its size and never counts
    /// towards it reads as nought for all of that time.
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
    /// The journal restores the port with the walk the scan was stopped in,
    /// and the pass asks the endpoint again. The fold that writes the answer
    /// back is where it can be lost: an account already on record that stood
    /// against any other would keep the floor and drop the whole answer the
    /// resumed sitting went back for.
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

    /// A host that has spent its budget is left alone. This is the most
    /// expensive thing the engine does to one endpoint and the last place to
    /// spend a budget that has already run out.
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
    /// seconds, so a budget asked about only before an endpoint is started
    /// bounds almost nothing: a host with a second left would be held for
    /// minutes past it, and the report would describe its enumeration as
    /// finished.
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

        // A walk nothing stopped would have asked about every one of them.
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
    /// The same shape as the budget above, from the scan's side: a caller who
    /// aborts, or a scan whose own budget runs out, is otherwise kept waiting
    /// for every walk in flight to finish, which is minutes against an
    /// endpoint that accepts everything.
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
