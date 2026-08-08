// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

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
//! Both phases adapt to whether the process holds root privileges. When it
//! does, [`discover`] groups targets by network interface and scans each one
//! with a raw-socket strategy suited to it: [`LocalScanner`] (in the [`local`]
//! module) handles hosts on the same physical segment over ARP and ICMP, while
//! [`RoutedScanner`] (in [`routed`]) handles anything reached through a gateway
//! over TCP SYN. [`scan`] follows the same pattern for ports, where a
//! privileged caller gets [`routed::SynPortScanner`]. That scanner classifies
//! each port from a single raw SYN probe rather than completing a full
//! handshake. Targets that cannot be mapped to a usable interface, along with
//! every target when running unprivileged, fall back to plain TCP connect
//! attempts through the [`connect`] module.
//!
//! Every strategy implements [`NetworkExplorer`], which lets [`discover`] spawn
//! several unrelated scanners (the per-interface local ones, the routed one,
//! and the fallback) and drive them all through one loop. Discovered hosts land
//! in a shared, thread-safe store as they are found, and each update fires a
//! lightweight event so a caller can watch a scan in progress instead of
//! waiting for it to finish. When DNS resolution is enabled, hostnames for
//! discovered hosts are looked up in the background through the [`resolver`]
//! module without blocking discovery.

use std::net::IpAddr;
use std::pin::Pin;

use async_trait::async_trait;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use crate::core::config::{SendMode, ZondConfig};
use crate::core::models::ip::range::IpRange;
use crate::core::models::{
    ip::set::IpSet,
    port::Protocol,
    target::{Target, TargetMap},
};
use crate::core::session::{ScanContext, ScanEvent, ScanSession, ScannerKind};
use crate::scanner::resolver::HostnameResolver;
use crate::system::interface;
use crate::system::privilege::is_elevated;
use crate::{error, info, success, warn};
use local::{LocalScanner, Scope};
use routed::RoutedScanner;

mod composite;
mod connect;
pub mod dispatcher;
mod local;
mod payload;
mod pool;
mod service;

// The raw scanners and the hostname resolver stay implementation details of
// [`scan`] and [`discover`] by default; under `test-support` they are reachable
// directly, which is what lets an out-of-crate test build one over a synthetic
// transport. Splitting each declaration is the only way to vary an item's
// visibility by feature, and it keeps the default public API exactly what it
// was.
#[cfg(not(feature = "test-support"))]
mod resolver;
#[cfg(feature = "test-support")]
pub mod resolver;

#[cfg(not(feature = "test-support"))]
mod routed;
#[cfg(feature = "test-support")]
pub mod routed;
mod tuning;

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
/// handle, or call [`ScanTask::join`], to wait for the whole scan to finish. To
/// stop a scan early, call
/// [`ScanHandle::abort`](crate::core::handle::ScanHandle::abort) on the
/// session's handle.
pub struct ScanTask {
    handle: JoinHandle<()>,
}

impl ScanTask {
    fn new(handle: JoinHandle<()>) -> Self {
        Self { handle }
    }

    /// Waits for the scan to finish. This fails only when the scan did not run
    /// to completion; per-target failures are reported through the
    /// [`ScanSession`] event stream instead.
    pub async fn join(self) -> Result<(), ScanError> {
        self.handle.await.map_err(|_| ScanError::TaskFailed)
    }
}

impl IntoFuture for ScanTask {
    type Output = Result<(), ScanError>;
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
/// [`LocalScanner`] (ARP and ICMP) for hosts on the same physical segment, and
/// [`RoutedScanner`] (TCP SYN) for anything reached through a gateway. Targets
/// that cannot be mapped to an interface, a loopback address for instance,
/// along with every target when running without root, fall back to plain TCP
/// connect attempts against a handful of common ports.
///
/// Hosts are written into the returned [`ScanSession`]'s store as they are
/// found, and each write fires a [`crate::core::session::ScanEvent`] so a
/// caller can watch a scan in progress rather than seeing only the final
/// result. Unless `cfg.no_dns` is set, discovered hosts are also resolved to
/// hostnames in the background, through passive DNS and mDNS sniffing when
/// privileged or active reverse lookups otherwise, without slowing discovery.
///
/// The returned [`ScanTask`] resolves once every scanning strategy, and the
/// resolver if one was started, has finished. To stop a scan early, call
/// [`crate::core::handle::ScanHandle::abort`] on the session's handle. Both
/// phases check for that signal regularly rather than only between targets.
pub async fn discover(
    targets: IpSet,
    cfg: &ZondConfig,
) -> Result<(ScanSession, ScanTask), ScanError> {
    let (session, ctx) = ScanSession::new();
    let caps = ScanCapabilities::resolve(cfg);

    // Unprivileged discovery has no raw enrichment strategies to spawn. It runs
    // the connect-based sweep itself and then the same DNS tail. The early
    // return is needed because `targets` moves into one path or the other.
    if !caps.privileged {
        let handle = tokio::spawn(async move {
            if let Err(e) = connect::discover(targets, ctx.clone()).await {
                report_scanner_failure(&ctx, ScannerKind::Connect, e.to_string());
            }
            finish_enrichment(None, caps, &ctx).await;
        });
        return Ok((session, ScanTask::new(handle)));
    }

    let enrichment = Enrichment::spawn(targets, &ctx, caps, cfg.send_mode, Scope::Sweep).await;

    let handle = tokio::spawn(async move {
        finish_enrichment(Some(enrichment), caps, &ctx).await;
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
/// [`routed::SynPortScanner`] classifies it from a single reply rather than a
/// completed handshake. Without root, or when the host has no address to probe
/// from, probes fall back to a plain TCP connect attempt per target through the
/// [`connect`] module.
pub async fn scan(
    mut target_map: TargetMap,
    cfg: &ZondConfig,
) -> Result<(ScanSession, ScanTask), ScanError> {
    let (session, ctx) = ScanSession::new();
    let caps = ScanCapabilities::resolve(cfg);
    let ips = target_ips(&target_map);
    let target_count = target_map.gross_targets().unwrap_or(0) as usize;

    let (syn_scanner, udp_scanner) = if caps.privileged {
        (
            build_syn_scanner(ctx.clone(), target_count, cfg.send_mode),
            build_udp_scanner(ctx.clone(), target_count, cfg.send_mode),
        )
    } else {
        (None, None)
    };

    // A privileged scan enriches hosts the same way `discover` does: ARP and
    // ICMPv6 for MAC and RTT, TCP SYN for RTT, passive DNS and mDNS for
    // hostnames and extra IPs. It runs alongside the port scan and writes into
    // the same store, so a scanned host carries the same detail a discovered one
    // does. The unprivileged fallback cannot ARP, so it settles for active
    // reverse DNS. Keying on `syn_scanner` rather than `caps.privileged` means a
    // privileged host that could not build a SYN scanner still takes the fallback.
    let enrichment = if syn_scanner.is_some() || udp_scanner.is_some() {
        Some(Enrichment::spawn(ips, &ctx, caps, cfg.send_mode, Scope::Targeted).await)
    } else {
        None
    };

    // Both branches of the privilege fork now sit behind one interface. Pick the
    // strategy here and drive it uniformly below.
    let mut scanners: Vec<Box<dyn PortScanner>> = Vec::new();
    if let Some(scanner) = syn_scanner {
        scanners.push(Box::new(scanner));
    }
    if let Some(scanner) = udp_scanner {
        scanners.push(Box::new(scanner));
    }
    let scanner = into_port_scanner(scanners, ctx.clone());

    let handle = tokio::spawn(async move {
        let dispatcher = dispatcher::Dispatcher::new(target_map);
        let rx = dispatcher.run_shuffled(&ctx.handle);

        run_port_scan(scanner, rx, &ctx).await;
        finish_enrichment(enrichment, caps, &ctx).await;
    });

    Ok((session, ScanTask::new(handle)))
}

/// A scanning strategy that finds which hosts, among the targets it owns, are
/// reachable.
///
/// Implementations do not return their findings. They write discovered hosts
/// directly into the shared [`ScanContext`] they were built with, and
/// `discover_hosts` reports only whether the attempt itself succeeded. This
/// keeps very different strategies (raw ARP/ICMP, raw TCP SYN, plain TCP
/// connect) interchangeable to the caller: build one, run it, move on.
/// [`spawn_explorers`] depends on that uniformity to drive several unrelated
/// scanner types through a single loop.
///
/// Running the scanner consumes it (`self: Box<Self>`). A discovery sweep
/// happens exactly once, so an implementation can move out of its own state
/// rather than pretend, through `&mut self`, that it might run again.
#[async_trait]
pub trait NetworkExplorer {
    async fn discover_hosts(self: Box<Self>) -> anyhow::Result<()>;
}

/// A scanning strategy that classifies the ports of a known set of targets.
///
/// This is the port-scan counterpart to [`NetworkExplorer`]. Where that trait
/// lets [`discover`] drive several host-discovery strategies through one loop,
/// this lets [`scan`] drive whichever port-scan strategy privilege selected,
/// either the raw [`routed::SynPortScanner`] or the unprivileged [`connect`]
/// fallback, through a single path. Implementations consume the shuffled
/// [`Target`] stream that a [`dispatcher::Dispatcher`] produces and write their
/// findings into the shared [`ScanContext`] they were built with;
/// [`PortScanner::scan`] reports only whether the run completed.
/// [`run_port_scan`] relies on that to treat both strategies identically.
#[async_trait]
pub trait PortScanner: Send {
    /// Identifies the strategy, used to tag a [`ScanEvent::ScannerFailed`] when
    /// a run fails.
    fn kind(&self) -> ScannerKind;

    /// Returns the set of transport protocols this scanner is capable of probing.
    ///
    /// [`into_port_scanner`] reads this to decide which protocols still need an
    /// unprivileged fallback, and [`composite::CompositePortScanner`] reads it
    /// to route each target, so a scanner that under-reports its coverage is
    /// simply never given that work.
    fn supported_protocols(&self) -> Vec<Protocol>;

    /// Probes every target arriving on `targets` and records each port's state
    /// in the shared store. Returns `Ok` when the run completes, including an
    /// early stop through the abort signal, and `Err` only when the strategy
    /// itself fails.
    async fn scan(&mut self, targets: mpsc::Receiver<Target>) -> anyhow::Result<()>;

    /// Second-pass service identification, run once after a successful
    /// [`scan`](PortScanner::scan) that was not aborted.
    ///
    /// The SYN strategy classifies port state from a single raw exchange and
    /// never holds a connection to fingerprint through, so it opens one here for
    /// each open port. The connect strategy fingerprints inline while it still
    /// holds the live stream, so its implementation is the default no-op.
    /// Putting this on the trait keeps the "does this strategy need a second
    /// pass?" decision in the type rather than in a branch at the call site.
    ///
    /// Takes `&mut self` to match [`scan`](PortScanner::scan): the receiver
    /// never crosses an await point as a shared reference, so the strategy types
    /// need to be [`Send`] but not [`Sync`].
    async fn detect_services(&mut self, _ctx: &ScanContext) {}
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
    scanners: Vec<(ScannerKind, JoinHandle<anyhow::Result<()>>)>,
    resolver: Option<JoinHandle<Option<HostnameResolver>>>,
}

impl Enrichment {
    /// Spawns every enrichment strategy for `targets`. They begin running
    /// immediately and concurrently. Call [`Enrichment::finish`] to await them.
    async fn spawn(
        targets: IpSet,
        ctx: &ScanContext,
        caps: ScanCapabilities,
        send_mode: SendMode,
        scope: Scope,
    ) -> Self {
        let (dns_tx, resolver) = if caps.dns {
            let (tx, rx) = mpsc::unbounded_channel();
            (Some(tx), Some(spawn_resolver(rx).await))
        } else {
            info!("DNS resolution skipped by user flag");
            (None, None)
        };

        let scanners = spawn_explorers(targets, ctx, dns_tx, send_mode, scope).await;
        Self { scanners, resolver }
    }

    /// Awaits every enrichment strategy, reports any that failed, then folds the
    /// resolver's collected hostnames and extra IPs into the store.
    async fn finish(self, ctx: &ScanContext) {
        for (kind, handle) in self.scanners {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => report_scanner_failure(ctx, kind, e.to_string()),
                Err(e) => report_scanner_failure(ctx, kind, format!("panicked: {e}")),
            }
        }

        if let Some(task) = self.resolver
            && let Ok(Some(mut resolver)) = task.await
        {
            resolver.resolve_hosts(ctx.store.clone());
        }
    }
}

/// Builds a scanning strategy for each way a target can be reached and runs them
/// all concurrently.
///
/// [`interface::map_ips_to_interfaces`] sorts the targets into three groups.
/// Those on-link to an interface's segment become a per-interface
/// [`LocalScanner`]. Those reached through a gateway, each already paired with
/// the source address to probe it from, are covered by a single
/// [`RoutedScanner`]. Those with no resolvable route go to a
/// [`connect::ConnectScanner`]. When a particular scanner cannot be constructed,
/// a capture socket that could not be opened for instance, that scanner is
/// skipped and logged while the rest of the scan proceeds.
///
/// Every constructed scanner is spawned as its own task, tagged with its
/// [`ScannerKind`], and returned, so the caller can wait on all of them and
/// react to failures individually rather than letting one bad scanner abort the
/// whole scan. A scanner that fails to start is reported through
/// [`ScanEvent::ScannerFailed`] and skipped.
async fn spawn_explorers(
    targets: IpSet,
    ctx: &ScanContext,
    dns_tx: Option<UnboundedSender<IpAddr>>,
    send_mode: SendMode,
    scope: Scope,
) -> Vec<(ScannerKind, JoinHandle<anyhow::Result<()>>)> {
    let mut explorers: Vec<(ScannerKind, Box<dyn NetworkExplorer + Send>)> = Vec::new();
    let interface::RoutedTargets {
        local,
        routed,
        unmapped,
    } = interface::map_ips_to_interfaces(targets);

    // Local scanner (ARP/ICMP) for hosts on the same physical segment.
    for (intf, local_ips) in local {
        if local_ips.is_empty() {
            continue;
        }
        info!(verbosity = 1, "Spawning local scanner for {}", intf.name);
        match LocalScanner::new(intf.clone(), local_ips, ctx.clone(), dns_tx.clone(), scope) {
            Ok(scanner) => explorers.push((ScannerKind::Local, Box::new(scanner))),
            Err(e) => {
                report_scanner_failure(ctx, ScannerKind::Local, format!("{}: {e}", intf.name))
            }
        }
    }

    // Routed scanner (TCP SYN) for targets reached through a gateway.
    if !routed.is_empty() {
        info!(
            verbosity = 1,
            "Spawning routed scanner for {} target(s)",
            routed.len()
        );
        match RoutedScanner::new(routed, ctx.clone(), dns_tx.clone(), send_mode) {
            Ok(scanner) => explorers.push((ScannerKind::Routed, Box::new(scanner))),
            Err(e) => report_scanner_failure(ctx, ScannerKind::Routed, e.to_string()),
        }
    }

    // Fallback scanner (unprivileged TCP handshake) for unmapped IPs, such as
    // localhost or targets the OS could not resolve a route or interface for.
    if !unmapped.is_empty() {
        warn!(
            verbosity = 1,
            "Spawning fallback scanner for unmapped targets"
        );
        explorers.push((
            ScannerKind::Connect,
            Box::new(connect::ConnectScanner::new(unmapped, ctx.clone())),
        ));
    }

    explorers
        .into_iter()
        .map(|(kind, explorer)| {
            (
                kind,
                tokio::spawn(async move { explorer.discover_hosts().await }),
            )
        })
        .collect()
}

/// Tries to build a privileged raw-socket SYN port scanner, resolving each
/// probe's source address per target across the host's interfaces and routing
/// table.
///
/// Called only once privilege is confirmed (see [`ScanCapabilities`]). Returns
/// `None`, meaning [`scan`] should fall back to TCP connect probes, when the
/// host has no address to probe from or when the scanner fails to initialize,
/// for instance because raw sockets could not be opened. Each case is logged
/// here rather than treated as a hard failure, since the unprivileged path is
/// always a working substitute.
fn build_syn_scanner(
    ctx: ScanContext,
    target_count: usize,
    send_mode: SendMode,
) -> Option<routed::SynPortScanner> {
    let resolver = interface::SourceResolver::from_system();
    if !resolver.has_sources() {
        warn!("No usable network interface found; using TCP connect fallback");
        return None;
    }

    match routed::SynPortScanner::new(resolver, ctx, target_count, send_mode) {
        Ok(scanner) => Some(scanner),
        Err(e) => {
            error!("Failed to initialize SYN port scanner: {e}");
            None
        }
    }
}

/// Tries to build a privileged raw-socket UDP port scanner.
fn build_udp_scanner(
    ctx: ScanContext,
    target_count: usize,
    send_mode: SendMode,
) -> Option<routed::UdpPortScanner> {
    let resolver = interface::SourceResolver::from_system();
    if !resolver.has_sources() {
        return None; // Fallback will be used
    }

    match routed::UdpPortScanner::new(resolver, ctx, target_count, send_mode) {
        Ok(scanner) => Some(scanner),
        Err(e) => {
            error!("Failed to initialize UDP port scanner: {e}");
            None
        }
    }
}

/// Assembles the port-scanning strategy behind the [`PortScanner`] interface:
/// whichever privileged scanners were built, backed by an unprivileged connect
/// fallback for every protocol none of them covers. All of them are driven
/// identically by [`run_port_scan`], so the choice stays confined to this one
/// place.
///
/// The fallback is decided **per protocol**, not per scan. A host can fail to
/// build one raw scanner and not the other - the SYN scanner needs a raw TCP
/// socket, the UDP scanner a raw UDP one, and a sandbox can permit one and
/// refuse the other - and a protocol left without any scanner is not a degraded
/// scan but a silent one: [`composite::CompositePortScanner`] has nowhere to
/// route those targets, so they would simply never be probed and never be
/// reported. Asking each scanner what it covers, rather than assuming a
/// privileged scan covers everything, is what keeps that from happening.
fn into_port_scanner(
    mut scanners: Vec<Box<dyn PortScanner>>,
    ctx: ScanContext,
) -> Box<dyn PortScanner> {
    let covered: Vec<Protocol> = scanners
        .iter()
        .flat_map(|scanner| scanner.supported_protocols())
        .collect();

    if !covered.contains(&Protocol::Tcp) {
        scanners.push(Box::new(connect::ConnectPortScanner::new(
            ctx.clone(),
            tuning::CONNECT_CONCURRENCY,
        )));
    }

    if !covered.contains(&Protocol::Udp) {
        scanners.push(Box::new(connect::ConnectUdpPortScanner::new(
            ctx,
            tuning::CONNECT_CONCURRENCY,
        )));
    }

    Box::new(composite::CompositePortScanner::new(scanners))
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
        Err(e) => report_scanner_failure(ctx, kind, e.to_string()),
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

/// Logs a scanner failure and announces it on the event stream, so a consumer
/// watching a scan can tell that it ran degraded rather than clean.
fn report_scanner_failure(ctx: &ScanContext, scanner: ScannerKind, reason: String) {
    error!("Scanner {scanner:?} failed: {reason}");
    let _ = ctx
        .events_tx
        .send(ScanEvent::ScannerFailed { scanner, reason });
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

        async fn scan(&mut self, _targets: mpsc::Receiver<Target>) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn covered(scanners: Vec<Box<dyn PortScanner>>) -> Vec<Protocol> {
        let (_session, ctx) = ScanSession::new();
        into_port_scanner(scanners, ctx).supported_protocols()
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
        let scanner = into_port_scanner(
            vec![
                Box::new(StubScanner(vec![Protocol::Tcp])),
                Box::new(StubScanner(vec![Protocol::Udp])),
            ],
            ctx,
        );
        // Two scanners in, two scanners out: `supported_protocols` deduplicates,
        // so count the routes rather than the protocols.
        assert_eq!(scanner.supported_protocols().len(), 2);
    }
}
