// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Network Scanning
//!
//! Turns a set of target addresses into scan results.
//!
//! A scan runs in two independent phases, each with its own entry point.
//! [`discover`] finds which hosts in a target range are alive. [`scan`] takes
//! a set of targets, usually ones that [`discover`] already confirmed, and
//! reports which of their ports are open. Separating the two lets a caller run
//! a cheap discovery sweep first and spend the expensive port-scanning work
//! only on hosts that are known to exist.
//!
//! # Three altitudes, and how to choose
//!
//! This module is usable at three levels of detail. They are the same code —
//! the top one is written in terms of the one below it — so moving down costs
//! only the decisions you take over, and nothing has to be reimplemented.
//!
//! **Call [`discover`] or [`scan`].** Targets and a [`ZondConfig`] in, a live
//! [`ScanSession`] and a [`ScanReport`] out. Privilege, interfaces, fallbacks,
//! retries and hostname resolution are all decided for you. This is the right
//! altitude for a CLI, a service, or anything wrapping the engine, and it is
//! where most callers should stay.
//!
//! **Build a [`plan`], edit it, run it.** A [`DiscoveryPlan`](plan::DiscoveryPlan)
//! is the set of strategies a scan intends to run, worked out from the targets
//! and this host's own configuration, with nothing opened and nothing sent.
//! Print it instead of running it and you have a dry run. Drop the steps for
//! three of your five links and run the rest. Its
//! [refusals](plan::Refusal) say what a scan will not cover before it starts.
//!
//! **Build one strategy and drive it yourself.** Everything in [`strategy`] is
//! ordinary public API: open a [`ScanSession`], construct a
//! [`LocalScanner`](strategy::local::LocalScanner) aimed at one segment or a
//! [`TcpPortScanner`](strategy::routed::TcpPortScanner) over a transport you
//! opened, run it, and read the store. Nothing here needs a cargo feature —
//! this is a supported way to use the engine, not a test hatch.
//!
//! A scan driven this way produces the same record as one the engine ran.
//! [`PhaseRecorder`](report::PhaseRecorder) takes the scope and settings before
//! the strategies start and closes into a [`ScanReport`] when they finish, so a
//! self-orchestrated scan reaches the exporters on the same terms
//! [`discover`] and [`scan`] do. What a strategy filed along the way is
//! readable before then through
//! [`ScanContext::failures_snapshot`](session::ScanContext::failures_snapshot)
//! and
//! [`probe_stats_snapshot`](session::ScanContext::probe_stats_snapshot).
//!
//! ```no_run
//! use zond_engine::config::ZondConfig;
//! use zond_engine::model::parse::ip::to_set;
//! use zond_engine::scanner::plan::DiscoveryPlan;
//! use zond_engine::scanner::session::ScanSession;
//! use zond_engine::scanner::strategy::local::Scope;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let cfg = ZondConfig::default();
//! let plan = DiscoveryPlan::build(to_set(&["192.168.1.0/24"], None, None)?, Scope::Sweep);
//!
//! // What the sweep would do, before it does any of it.
//! for step in plan.steps() {
//!     println!("{:?}: {} address(es)", step.kind(), step.target_count());
//! }
//! for refusal in plan.refusals() {
//!     println!("not covered: {}", refusal.reason);
//! }
//!
//! // And when you want to run it, a context is what a strategy is built with.
//! let (_session, ctx) = ScanSession::new();
//! for step in plan.into_steps() {
//!     let mut scanner = step.into_scanner(ctx.clone(), None, cfg.probe_tuning())?;
//!     // scanner.discover_hosts().await?;
//!     let _ = &mut scanner;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # How a scan is assembled
//!
//! Both phases adapt to whether the process holds root privileges. When it
//! does, [`discover`] groups targets by the interface that reaches them and
//! scans each with a strategy suited to it:
//! [`LocalScanner`](strategy::local::LocalScanner) (ARP and ICMPv6) for hosts on
//! the same physical segment, [`RoutedScanner`](strategy::routed::RoutedScanner)
//! (TCP SYN) for anything reached through a gateway. [`scan`] follows the same
//! pattern for ports, where a privileged caller gets
//! [`TcpPortScanner`](strategy::routed::TcpPortScanner), which classifies each
//! port from a single raw exchange rather than a completed handshake. Targets
//! that map to no usable interface, along with every target when unprivileged,
//! fall back to plain TCP connect attempts.
//!
//! Every one of those implements [`HostScanner`] or
//! [`PortScanner`], which is what lets several unrelated
//! strategies be driven through one loop. Discovered hosts land in a shared,
//! thread-safe store as they are found, and each update fires an event, so a
//! caller can watch a scan in progress instead of waiting for it to finish.
//! When DNS resolution is enabled, hostnames are looked up in the background
//! through the [`resolver`] module without blocking discovery.

use std::net::IpAddr;
use std::pin::Pin;

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use crate::config::{ProbeTuning, ZondConfig};
use crate::model::ip::range::IpRange;
use crate::model::{
    ip::set::IpSet,
    port::Protocol,
    target::{Target, TargetMap},
    technique::TcpScanTechnique,
};
use crate::scanner::report::{PhaseRecorder, ScanKind, ScanReport, TargetScope};
use crate::scanner::resolver::HostnameResolver;
use crate::scanner::session::{ScanContext, ScanSession, ScannerKind};
use crate::system::privilege::is_elevated;
use crate::{error, info, success, warn};
use strategy::local::Scope;
use strategy::{HostScanner, PortScanner, StrategyError};

// What running a scan produces, as opposed to how it is run. A caller holds a
// `ScanSession` while the scan is in flight, a `ScanHandle` to stop it, and a
// `ScanReport` once it is over; all three describe this module's work and
// nothing below it needs them, which is why they sit here rather than in the
// vocabulary the whole crate shares.
pub mod handle;
pub mod report;
pub mod session;

// The strategies themselves, and the two traits that make them
// interchangeable. Public unconditionally: a caller who wants to aim one
// scanner at one segment, rather than ask this module to plan a whole scan, is
// doing something this engine supports rather than something it tolerates.
pub mod pacing;
pub mod plan;
pub mod strategy;

// What a strategy needs and what reads its output. `dispatcher` turns a target
// map into the stream a `PortScanner` consumes, `audit` is what a raw strategy
// records about its own run, `resolver` is the hostname tail, and `pool` and
// `payload` are shared probe machinery.
pub mod audit;
pub mod dispatcher;
pub mod pool;
pub mod resolver;
pub mod service;

pub mod payload;

/// An error returned when a scan fails to run to completion.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// The scan task panicked or was aborted before it finished.
    #[error("scan task terminated abnormally")]
    TaskFailed,
}

/// A handle to a running scan.
///
/// Discovered hosts arrive live through the paired [`ScanSession`]. Await this
/// handle, or call [`ScanTask::join`], to wait for the whole scan to finish and
/// receive the [`ScanReport`] describing it. To stop a scan early, call
/// [`ScanHandle::abort`](crate::scanner::handle::ScanHandle::abort) on the
/// session's handle; the report still arrives, describing however far the scan
/// got.
pub struct ScanTask {
    handle: JoinHandle<ScanReport>,
}

impl ScanTask {
    fn new(handle: JoinHandle<ScanReport>) -> Self {
        Self { handle }
    }

    /// Waits for the scan to finish and returns its report.
    ///
    /// This fails only when the scan did not run to completion at all. A
    /// strategy that failed part way through is recorded in the report's
    /// [`failures`](ScanReport::failures) - and announced live on the
    /// [`ScanSession`] event stream - rather than returned as an error here,
    /// because the hosts the surviving strategies found are still results worth
    /// having.
    pub async fn join(self) -> Result<ScanReport, ScanError> {
        self.handle.await.map_err(|_| ScanError::TaskFailed)
    }
}

impl IntoFuture for ScanTask {
    type Output = Result<ScanReport, ScanError>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.join())
    }
}

/// Finds which hosts, among a set of target addresses, are alive.
///
/// This is the first phase of a scan: it establishes presence, not open ports.
/// With root privileges, targets are grouped by the network interface that
/// would reach them and scanned with a raw-socket strategy suited to each:
/// [`LocalScanner`](strategy::local::LocalScanner) (ARP and ICMP) for hosts on the
/// same physical segment, and [`RoutedScanner`](strategy::routed::RoutedScanner)
/// (TCP SYN) for anything reached through a gateway. Targets
/// that cannot be mapped to an interface, a loopback address for instance,
/// along with every target when running without root, fall back to plain TCP
/// connect attempts against a handful of common ports.
///
/// Hosts are written into the returned [`ScanSession`]'s store as they are
/// found, and each write fires a [`crate::scanner::session::ScanEvent`] so a
/// caller can watch a scan in progress rather than seeing only the final
/// result. Unless `cfg.no_dns` is set, discovered hosts are also resolved to
/// hostnames in the background, through passive DNS and mDNS sniffing when
/// privileged or active reverse lookups otherwise, without slowing discovery.
///
/// The returned [`ScanTask`] resolves once every scanning strategy, and the
/// resolver if one was started, has finished, and yields the [`ScanReport`] for
/// the sweep. To stop a scan early, call
/// [`crate::scanner::handle::ScanHandle::abort`] on the session's handle. Both
/// phases check for that signal regularly rather than only between targets.
pub async fn discover(
    mut targets: IpSet,
    cfg: &ZondConfig,
) -> Result<(ScanSession, ScanTask), ScanError> {
    let (session, ctx) = ScanSession::new();
    let caps = ScanCapabilities::resolve(cfg);

    // Recorded before `targets` moves into a strategy: what the sweep was asked
    // to cover is only knowable here.
    let scope = TargetScope::from_ip_set(&mut targets);
    let recorder = PhaseRecorder::start(ScanKind::Discovery, caps.privileged, scope, cfg);

    // Unprivileged discovery has no raw enrichment strategies to spawn. It runs
    // the connect-based sweep itself and then the same DNS tail. The early
    // return is needed because `targets` moves into one path or the other.
    if !caps.privileged {
        let handle = tokio::spawn(async move {
            if let Err(e) = strategy::connect::discover(targets, ctx.clone()).await {
                ctx.record_failure(ScannerKind::Connect, e.to_string());
            }
            finish_enrichment(None, caps, &ctx).await;
            recorder.finish(&ctx)
        });
        return Ok((session, ScanTask::new(handle)));
    }

    // A sweep is what the caller asked for only when they asked about a
    // network. Probing addresses nobody named is defensible for `lan` and
    // surprising for `zond <address>` - see `ZondConfig::segment_sweep`.
    let scope = if cfg.segment_sweep {
        Scope::Sweep
    } else {
        Scope::Targeted
    };
    let plan = plan::DiscoveryPlan::build(targets, scope);
    let enrichment = Enrichment::spawn(plan, &ctx, caps, cfg.probe_tuning()).await;

    let handle = tokio::spawn(async move {
        finish_enrichment(Some(enrichment), caps, &ctx).await;
        recorder.finish(&ctx)
    });

    Ok((session, ScanTask::new(handle)))
}

/// Probes a known set of targets for open ports.
///
/// This is the second phase of a scan: given targets and the ports to check on
/// each, it finds which of those ports are open. It performs no host discovery
/// of its own, so a target that is not actually alive comes back with every
/// port closed or filtered, at the cost of a wasted probe. Call [`discover`]
/// first when you do not already know which targets exist.
///
/// With root privileges, every probe is a raw TCP SYN sent from the source
/// address the host would route each target through, and
/// [`strategy::routed::TcpPortScanner`] classifies it from a single reply rather than a
/// completed handshake. Without root, or when the host has no address to probe
/// from, probes fall back to a plain TCP connect attempt per target through the
/// `connect` module.
pub async fn scan(
    target_map: TargetMap,
    cfg: &ZondConfig,
) -> Result<(ScanSession, ScanTask), ScanError> {
    let (session, ctx) = ScanSession::new();
    let caps = ScanCapabilities::resolve(cfg);
    let ips = target_ips(&target_map);
    let target_count = target_map.gross_targets().unwrap_or(0) as usize;

    // Recorded before `target_map` moves into the dispatcher. Reading it costs
    // only a shared borrow: a `TargetMap` is canonical from the moment its units
    // are built, so counting one is not a mutation.
    let scope = TargetScope::from_target_map(&target_map);
    let recorder = PhaseRecorder::start(ScanKind::PortScan, caps.privileged, scope, cfg);

    let built = build_port_scanner(
        plan::PortScanPlan::build(cfg, caps.privileged),
        &ctx,
        target_count,
        cfg.probe_tuning(),
    );

    // A privileged scan enriches hosts the same way `discover` does: ARP and
    // ICMPv6 for MAC and RTT, TCP SYN for RTT, passive DNS and mDNS for
    // hostnames and extra IPs. It runs alongside the port scan and writes into
    // the same store, so a scanned host carries the same detail a discovered one
    // does. The unprivileged fallback cannot ARP, so it settles for active
    // reverse DNS.
    //
    // Keyed on what actually opened rather than on privilege: a privileged host
    // whose raw socket was refused has no raw enrichment to offer either, and
    // takes the unprivileged tail exactly as an unprivileged host does.
    let enrichment = if built.opened_raw() {
        let plan = plan::DiscoveryPlan::build(ips, Scope::Targeted);
        Some(Enrichment::spawn(plan, &ctx, caps, cfg.probe_tuning()).await)
    } else {
        None
    };
    let scanner = built.scanner;

    let handle = tokio::spawn(async move {
        let dispatcher = dispatcher::Dispatcher::new(target_map);
        let rx = dispatcher.run_shuffled(&ctx.handle);

        run_port_scan(scanner, rx, &ctx).await;
        finish_enrichment(enrichment, caps, &ctx).await;
        recorder.finish(&ctx)
    });

    Ok((session, ScanTask::new(handle)))
}

/// The environment-derived facts that steer how a scan runs.
///
/// Both entry points face the same two questions: can the process open raw
/// sockets, and should it resolve hostnames. Answering them once, up front,
/// lets [`scan`] and [`discover`] branch on the same facts and keeps the
/// privileged-versus-unprivileged and DNS-on-versus-off policy from drifting
/// between phases.
#[derive(Clone, Copy)]
struct ScanCapabilities {
    /// Whether raw-socket scanning is available, meaning the process is root.
    /// When false, every phase falls back to unprivileged TCP connect scanning.
    privileged: bool,
    /// Whether hostname resolution is enabled, the inverse of `cfg.no_dns`.
    dns: bool,
}

impl ScanCapabilities {
    /// Reads the runtime capabilities from the environment and config, and
    /// announces the scanning mode they imply once, here, rather than from the
    /// code that later acts on them.
    fn resolve(cfg: &ZondConfig) -> Self {
        let privileged = is_elevated();
        if privileged {
            success!("Root privileges detected, raw socket scan enabled");
        } else {
            warn!("Root privileges missing, defaulting to unprivileged TCP scan");
        }
        Self {
            privileged,
            dns: !cfg.no_dns,
        }
    }
}

/// The privileged host-identification phase, shared by [`discover`] and
/// [`scan`].
///
/// It spawns the strategies discovery uses: per-interface [`LocalScanner`]s
/// (ARP and ICMPv6, yielding MAC and RTT), a [`RoutedScanner`] for off-link
/// targets (RTT), and the passive DNS and mDNS [`HostnameResolver`]. All of them
/// write into the shared store. [`discover`] runs this alone, while [`scan`]
/// runs it alongside the port scan. Keeping it in one place lets both surface
/// identical host detail without duplicating the orchestration.
struct Enrichment {
    scanners: Vec<(ScannerKind, JoinHandle<Result<(), StrategyError>>)>,
    resolver: Option<JoinHandle<Option<HostnameResolver>>>,
}

impl Enrichment {
    /// Spawns every enrichment strategy for `targets`. They begin running
    /// immediately and concurrently. Call [`Enrichment::finish`] to await them.
    async fn spawn(
        plan: plan::DiscoveryPlan,
        ctx: &ScanContext,
        caps: ScanCapabilities,
        tuning: ProbeTuning,
    ) -> Self {
        let (dns_tx, resolver) = if caps.dns {
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
            resolver.resolve_hosts(ctx.store.clone());
        }
    }
}

/// Turns a [`DiscoveryPlan`] into running tasks.
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
async fn spawn_explorers(
    plan: plan::DiscoveryPlan,
    ctx: &ScanContext,
    dns_tx: Option<UnboundedSender<IpAddr>>,
    tuning: ProbeTuning,
) -> Vec<(ScannerKind, JoinHandle<Result<(), StrategyError>>)> {
    for refusal in plan.refusals() {
        ctx.record_failure(refusal.scanner, refusal.reason.clone());
    }

    let mut explorers: Vec<Box<dyn HostScanner>> = Vec::new();
    for step in plan.into_steps() {
        let kind = step.kind();
        info!(
            verbosity = 1,
            "Spawning {:?} scanner for {} target(s)",
            kind,
            step.target_count()
        );
        match step.into_scanner(ctx.clone(), dns_tx.clone(), tuning) {
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
fn build_port_scanner(
    plan: plan::PortScanPlan,
    ctx: &ScanContext,
    target_count: usize,
    tuning: ProbeTuning,
) -> BuiltPortScan {
    for refusal in plan.refusals() {
        ctx.record_failure(refusal.scanner, refusal.reason.clone());
    }

    let technique = plan.technique();
    let mut scanners: Vec<Box<dyn PortScanner>> = Vec::new();
    let mut opened = Vec::new();
    for step in plan.into_steps() {
        match step.into_scanner(ctx.clone(), target_count, tuning) {
            Ok(scanner) => {
                opened.push(step.kind());
                scanners.push(scanner);
            }
            Err(e) => ctx.record_failure(step.kind(), e.to_string()),
        }
    }

    BuiltPortScan {
        scanner: Box::new(strategy::composite::CompositePortScanner::new(
            ensure_coverage(scanners, ctx, technique),
        )),
        opened,
    }
}

/// Backs the plan's intent with what actually opened: any protocol left without
/// a strategy gets the unprivileged one, or is refused.
///
/// **The plan cannot do this on its own, and that is the point of separating
/// them.** A plan says a raw TCP scanner and a raw UDP scanner should run. Only
/// the attempt discovers that this host permitted one raw socket and not the
/// other — a sandbox can do exactly that — and a protocol left with no strategy
/// at all is not a degraded scan but a silent one:
/// [`CompositePortScanner`](strategy::composite::CompositePortScanner) has
/// nowhere to route those targets, so they are never probed and never reported.
/// Asking what actually built, rather than assuming a privileged scan covers
/// everything, is what keeps that from happening.
///
/// **A connect fallback substitutes for a SYN scan and for nothing else.** It
/// completes handshakes, so it answers roughly the question a SYN scan asks; it
/// cannot send a FIN, a flagless segment or a bare ACK, and so cannot answer
/// what any of those were asked. Where the caller chose one of those and no raw
/// scanner opened, the TCP half is reported as a failure and left undone. That
/// is worse for the caller and honest, where a silent substitution would hand
/// back verdicts from a technique they did not choose - and no field in the
/// report would say so.
fn ensure_coverage(
    mut scanners: Vec<Box<dyn PortScanner>>,
    ctx: &ScanContext,
    technique: TcpScanTechnique,
) -> Vec<Box<dyn PortScanner>> {
    let covered: Vec<Protocol> = scanners
        .iter()
        .flat_map(|scanner| scanner.supported_protocols())
        .collect();

    if !covered.contains(&Protocol::Tcp) {
        if technique.finds_open_ports() {
            scanners.push(Box::new(strategy::connect::ConnectPortScanner::new(
                ctx.clone(),
                pacing::limits::CONNECT_CONCURRENCY,
            )));
        } else {
            ctx.record_failure(
                ScannerKind::TcpPort,
                format!(
                    "the {technique} technique needs raw sockets, which this process \
                     does not have, and a connect scan answers a different question - so \
                     no TCP port was probed",
                ),
            );
        }
    }

    if !covered.contains(&Protocol::Udp) {
        scanners.push(Box::new(strategy::connect::ConnectUdpPortScanner::new(
            ctx.clone(),
            pacing::limits::CONNECT_CONCURRENCY,
        )));
    }

    scanners
}

/// A port-scan strategy, and which of the planned steps actually opened.
///
/// The second half is not decoration. Host enrichment is worth running only
/// alongside a raw scan — it is the raw paths that yield a MAC and an RTT — and
/// whether a raw scan is happening is answerable only after the sockets were
/// asked for, not from the privilege the process holds.
struct BuiltPortScan {
    scanner: Box<dyn PortScanner>,
    opened: Vec<ScannerKind>,
}

impl BuiltPortScan {
    /// Whether any raw-socket strategy is among what opened.
    fn opened_raw(&self) -> bool {
        self.opened
            .iter()
            .any(|kind| matches!(kind, ScannerKind::SynPort | ScannerKind::UdpPort))
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
async fn run_port_scan(
    mut scanner: Box<dyn PortScanner>,
    rx: mpsc::Receiver<Target>,
    ctx: &ScanContext,
) {
    let kind = scanner.kind();
    match scanner.scan(rx).await {
        Ok(()) => {
            if !ctx.handle.should_stop() {
                scanner.detect_services(ctx).await;
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
async fn finish_enrichment(
    enrichment: Option<Enrichment>,
    caps: ScanCapabilities,
    ctx: &ScanContext,
) {
    match enrichment {
        Some(enrichment) => enrichment.finish(ctx).await,
        None if caps.dns => resolver::resolve_hosts_async(ctx.store.clone()).await,
        None => {}
    }
}

/// Collects every target address from a [`TargetMap`] into an [`IpSet`], so the
/// host-enrichment phase knows which addresses to identify.
fn target_ips(target_map: &TargetMap) -> IpSet {
    let mut ips = IpSet::new();
    for unit in &target_map.units {
        for range in unit.ips().v4() {
            ips.insert_range(IpRange::V4(*range));
        }
        for range in unit.ips().v6() {
            ips.insert_range(IpRange::V6(*range));
        }
    }
    ips.canonicalize();
    ips
}

/// Starts the background hostname resolver as its own task.
///
/// The resolver listens for raw DNS and mDNS traffic and answers reverse lookups
/// for any IP sent down `dns_rx`, independent of and concurrent with whatever
/// scanning strategies are running. When it fails to start, most likely because
/// no usable network socket could be opened, the failure is logged and `None` is
/// returned rather than propagated, since a scan without hostname resolution is
/// still useful.
async fn spawn_resolver(dns_rx: UnboundedReceiver<IpAddr>) -> JoinHandle<Option<HostnameResolver>> {
    tokio::spawn(async move {
        match HostnameResolver::new(dns_rx) {
            Ok(resolver) => {
                success!("Successfully initialized hostname resolver");
                Some(resolver.run().await)
            }
            Err(e) => {
                error!("Resolver failed to start: {e}");
                None
            }
        }
    })
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

        async fn scan(&mut self, _targets: mpsc::Receiver<Target>) -> Result<(), StrategyError> {
            Ok(())
        }
    }

    fn covered(scanners: Vec<Box<dyn PortScanner>>) -> Vec<Protocol> {
        let (_session, ctx) = ScanSession::new();
        ensure_coverage(scanners, &ctx, TcpScanTechnique::Syn)
            .iter()
            .flat_map(|scanner| scanner.supported_protocols())
            .collect()
    }

    /// With no privileged scanner at all, both connect fallbacks stand in.
    #[test]
    fn an_unprivileged_scan_covers_both_protocols() {
        let protocols = covered(Vec::new());
        assert!(protocols.contains(&Protocol::Tcp));
        assert!(protocols.contains(&Protocol::Udp));
    }

    /// The regression guard for the per-protocol fallback: a host that could
    /// build the raw UDP scanner but not the SYN one must still probe TCP.
    /// Gating on "any privileged scanner exists" left those targets with no
    /// route at all, so they were dropped without a record.
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
    #[test]
    fn a_technique_the_fallback_cannot_express_is_reported_rather_than_substituted() {
        let (_session, ctx) = ScanSession::new();
        let scanners = ensure_coverage(Vec::new(), &ctx, TcpScanTechnique::Fin);
        let protocols: Vec<Protocol> = scanners
            .iter()
            .flat_map(|scanner| scanner.supported_protocols())
            .collect();

        assert!(
            !protocols.contains(&Protocol::Tcp),
            "a connect scan cannot send a FIN and must not pretend to"
        );

        let failures = ctx.take_failures();
        assert_eq!(failures.len(), 1, "the caller has to be told");
        assert_eq!(failures[0].scanner(), ScannerKind::TcpPort);
        assert!(
            failures[0].reason().contains("fin"),
            "the failure has to name the technique: {}",
            failures[0].reason()
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
            vec![
                Box::new(StubScanner(vec![Protocol::Tcp])),
                Box::new(StubScanner(vec![Protocol::Udp])),
            ],
            &ctx,
            TcpScanTechnique::Syn,
        );
        // Two scanners in, two scanners out: nothing was added beside them.
        assert_eq!(scanners.len(), 2);
    }
}
