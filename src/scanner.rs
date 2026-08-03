// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Network Scanning
//!
//! Orchestration for turning a set of target addresses into scan results.
//!
//! A scan happens in two independent phases, exposed here as the two entry
//! points [`discover`] and [`scan`]. `discover` finds out which hosts in a
//! target range are actually alive; `scan` takes a set of targets - usually
//! ones `discover` already confirmed - and finds out which of their ports
//! are open. Splitting them this way lets a caller run a cheap discovery
//! sweep first and spend the more expensive port-scanning work only on
//! hosts that are actually there.
//!
//! Both phases adapt to whether the process has root privileges. With root,
//! `discover` partitions targets by network interface and scans each one
//! with a raw-socket strategy suited to it - [`LocalScanner`] (in the
//! [`local`] module) for hosts on the same physical segment, using
//! ARP/ICMP, and [`RoutedScanner`] (in [`routed`]) for anything reached
//! through a gateway, using TCP SYN. `scan` takes the same approach for
//! ports: privileged callers get [`routed::SynPortScanner`], which
//! classifies each port from a single raw SYN probe instead of completing
//! a full handshake. Either way, targets that can't be mapped to a usable
//! interface, along with every target when running unprivileged, fall back
//! to plain TCP connect attempts via the [`connect`] module.
//!
//! Every scanning strategy implements [`NetworkExplorer`], which is what
//! lets [`discover`] spawn several unrelated scanners - the per-interface
//! local ones, the routed one, and the fallback - and run them all through
//! the same loop rather than special-casing each one. Discovered hosts land
//! in a shared, thread-safe
//! store as they're found, and each update fires a lightweight event so a
//! caller can watch a scan in progress instead of waiting for it to finish.
//! If DNS resolution is enabled, hostnames for discovered hosts are looked
//! up in the background, via the [`resolver`] module, without blocking
//! discovery itself.

use std::net::IpAddr;
use std::pin::Pin;

use async_trait::async_trait;
use is_root::is_root;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use crate::core::config::{SendMode, ZondConfig};
use crate::core::models::ip::range::IpRange;
use crate::core::models::{
    ip::set::IpSet,
    target::{Target, TargetMap},
};
use crate::core::session::{ScanContext, ScanEvent, ScanSession, ScannerKind};
use crate::scanner::resolver::HostnameResolver;
use crate::system::interface;
use crate::{error, info, success, warn};
use local::{LocalScanner, Scope};
use routed::RoutedScanner;

mod connect;
pub mod dispatcher;
mod local;
mod pool;
mod resolver;
mod routed;
mod service;

/// How many TCP connect probes [`scan`] runs at once.
const PORT_SCAN_CONCURRENCY: usize = 50;

/// An error from a scan.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// The scan did not run to completion because its task panicked or was
    /// aborted.
    #[error("scan task terminated abnormally")]
    TaskFailed,
}

/// A handle to a running scan.
///
/// Discovered hosts arrive live through the paired [`ScanSession`]. Await this
/// handle, or call [`ScanTask::join`], to wait for the whole scan to finish.
/// To stop a scan early, call
/// [`ScanHandle::abort`](crate::core::handle::ScanHandle::abort) on the
/// session's handle.
pub struct ScanTask {
    handle: JoinHandle<()>,
}

impl ScanTask {
    fn new(handle: JoinHandle<()>) -> Self {
        Self { handle }
    }

    /// Waits for the scan to finish, failing only if it did not run to
    /// completion. Per-target scan failures are reported through the
    /// [`ScanSession`] event stream, not here.
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

/// A scanning strategy that finds which hosts, among a set of targets it
/// already owns, are actually reachable.
///
/// Implementations don't return what they find - they write discovered
/// hosts directly into the shared [`ScanContext`] they were built with, and
/// `discover_hosts` only reports whether the attempt itself succeeded. That
/// makes very different strategies (raw ARP/ICMP, raw TCP SYN, plain TCP
/// connect) interchangeable from the caller's point of view: build one, run
/// it, move on. [`spawn_explorers`] relies on exactly that to drive a
/// handful of unrelated scanner types through one shared loop.
#[async_trait]
trait NetworkExplorer {
    async fn discover_hosts(&mut self) -> anyhow::Result<()>;
}

/// A scanning strategy that classifies the ports of a known set of targets.
///
/// This is the port-scan analogue of [`NetworkExplorer`]. Where that trait lets
/// [`discover`] drive several host-discovery strategies through one loop, this
/// lets [`scan`] drive whichever port-scan strategy privilege selected - the raw
/// [`routed::SynPortScanner`] or the unprivileged [`connect`] fallback - through
/// one path, without special-casing either. Implementations consume the shuffled
/// [`Target`] stream a [`dispatcher::Dispatcher`] produces and write findings into
/// the shared [`ScanContext`] they were built with; [`PortScanner::scan`] only
/// reports whether the run itself completed. [`run_port_scan`] relies on exactly
/// that to treat both strategies identically.
#[async_trait]
trait PortScanner: Send {
    /// Which strategy this is, used to tag a [`ScanEvent::ScannerFailed`] if the
    /// run fails.
    fn kind(&self) -> ScannerKind;

    /// Probes every target arriving on `targets` and records each port's state
    /// into the shared store. Returns `Ok` if the run completed - including an
    /// early stop via the abort signal - and `Err` only if the strategy itself
    /// failed.
    async fn scan(&mut self, targets: mpsc::Receiver<Target>) -> anyhow::Result<()>;

    /// Second-pass service identification, run once after a successful
    /// [`scan`](PortScanner::scan) that was not aborted.
    ///
    /// The SYN strategy classifies port *state* from a single raw exchange and
    /// never holds a connection to fingerprint through, so it opens one here for
    /// each open port. The connect strategy already fingerprinted inline while it
    /// held the live stream, so its implementation is the default no-op. Keeping
    /// this on the trait puts the "does this strategy need a second pass?"
    /// decision in the type, rather than in a branch at the call site.
    ///
    /// Takes `&mut self` to match [`scan`](PortScanner::scan): the receiver never
    /// crosses the await as a shared reference, so the strategy types need only be
    /// [`Send`], not [`Sync`].
    async fn detect_services(&mut self, _ctx: &ScanContext) {}
}

/// The environment-derived facts that steer how a scan runs.
///
/// Both entry points face the same two questions - can we open raw sockets, and
/// should we resolve hostnames - and used to answer them in subtly different
/// shapes at each branch (`not_root()` in one layer here, `!cfg.no_dns`
/// recomputed there). Resolving them once, up front, into this value is what lets
/// [`scan`] and [`discover`] fork on the *same* facts and keeps the "privileged
/// vs. unprivileged" and "DNS on vs. off" policy from drifting between phases.
#[derive(Clone, Copy)]
struct ScanCapabilities {
    /// Whether raw-socket scanning is available, i.e. the process is root. When
    /// false, every phase falls back to unprivileged TCP connect scanning.
    privileged: bool,
    /// Whether hostname resolution is enabled (the inverse of `cfg.no_dns`).
    dns: bool,
}

impl ScanCapabilities {
    /// Resolves the runtime capabilities from the environment and config,
    /// announcing which scanning mode they imply - once, here, rather than from
    /// the code that later acts on them.
    fn resolve(cfg: &ZondConfig) -> Self {
        let privileged = is_root();
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

/// Completes the hostname-resolution tail of a scan.
///
/// A privileged scan spawned passive DNS/mDNS resolution as part of its
/// [`Enrichment`]; awaiting that here folds the collected hostnames and extra IPs
/// into the store (along with the rest of the enrichment strategies). An
/// unprivileged scan has no enrichment, so it falls back to active reverse lookups
/// when DNS is enabled, and does nothing when it isn't. This is the single place
/// the "passive when privileged, active otherwise" policy lives.
async fn finish_enrichment(enrichment: Option<Enrichment>, caps: ScanCapabilities, ctx: &ScanContext) {
    match enrichment {
        Some(enrichment) => enrichment.finish(ctx).await,
        None if caps.dns => resolver::resolve_hosts_async(ctx.store.clone()).await,
        None => {}
    }
}

/// Probes a known set of targets for open ports.
///
/// This is the second phase of a scan: given targets and the ports to check
/// on each, find out which of those ports are open. It does no host
/// discovery of its own - a target that isn't actually alive just comes
/// back with every port closed or filtered, at the cost of a wasted probe.
/// Call [`discover`] first if you don't already know which targets exist.
///
/// With root privileges, every probe is a raw TCP SYN sent from the source
/// address the host would route each target through, classified by
/// [`routed::SynPortScanner`] from a single reply rather than a completed
/// handshake. Without root, or if the host has no address to probe from,
/// probes fall back to a plain TCP connect attempt per target via the
/// [`connect`] module.
pub async fn scan(
    mut target_map: TargetMap,
    cfg: &ZondConfig,
) -> Result<(ScanSession, ScanTask), ScanError> {
    let (session, ctx) = ScanSession::new();
    let caps = ScanCapabilities::resolve(cfg);
    let ips = target_ips(&target_map);
    let target_count = target_map.gross_targets().unwrap_or(0) as usize;

    let syn_scanner = if caps.privileged {
        build_syn_scanner(ctx.clone(), target_count, cfg.send_mode)
    } else {
        None
    };

    // A privileged scan enriches hosts exactly as `discover` does - ARP/ICMPv6
    // for MAC and RTT, TCP SYN for RTT, passive DNS/mDNS for hostnames and
    // extra IPs - running concurrently with the port scan and writing into the
    // same store, so a scanned host carries the same detail a discovered one
    // does. The unprivileged fallback can't ARP, so it settles for active
    // reverse DNS. Keying on `syn_scanner` (not `caps.privileged`) means a
    // privileged host that couldn't build a SYN scanner still takes the fallback.
    let enrichment = if syn_scanner.is_some() {
        Some(Enrichment::spawn(ips, &ctx, caps, cfg.send_mode, Scope::Targeted).await)
    } else {
        None
    };

    // Both branches of the privilege fork now live behind one interface: pick the
    // strategy here, drive it uniformly below.
    let scanner = into_port_scanner(syn_scanner, ctx.clone());

    let handle = tokio::spawn(async move {
        let dispatcher = dispatcher::Dispatcher::new(target_map);
        let rx = dispatcher.run_shuffled(&ctx.handle);

        run_port_scan(scanner, rx, &ctx).await;
        finish_enrichment(enrichment, caps, &ctx).await;
    });

    Ok((session, ScanTask::new(handle)))
}

/// Collects every target address from a [`TargetMap`] into an [`IpSet`], so
/// the host-enrichment phase knows which addresses to identify.
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

/// Attempts to build a privileged, raw-socket SYN port scanner, resolving
/// each probe's source address per target across all of the host's
/// interfaces and its routing table.
///
/// Called only once privilege is confirmed (see [`ScanCapabilities`]). Returns
/// `None` - meaning [`scan`] should fall back to TCP connect probes - when the
/// host has no address to probe from, or when the scanner fails to initialize
/// (for instance, because raw sockets couldn't be opened); each is logged here
/// rather than treated as a hard failure, since the unprivileged path is always a
/// working substitute.
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

/// Selects the port-scanning strategy behind the [`PortScanner`] interface: the
/// privileged raw-SYN scanner when [`build_syn_scanner`] could construct one,
/// otherwise the unprivileged TCP-connect fallback. Both are driven identically
/// by [`run_port_scan`], so the choice of strategy is confined to this one place.
fn into_port_scanner(
    syn_scanner: Option<routed::SynPortScanner>,
    ctx: ScanContext,
) -> Box<dyn PortScanner> {
    match syn_scanner {
        Some(scanner) => Box::new(scanner),
        None => Box::new(connect::ConnectPortScanner::new(ctx, PORT_SCAN_CONCURRENCY)),
    }
}

/// Drives one port-scan strategy to completion: streams targets through it, then -
/// if it succeeded and the scan wasn't aborted - lets the strategy run its own
/// service-detection pass (a no-op for strategies that fingerprint inline).
///
/// A strategy failure is reported on the event stream, tagged with the strategy's
/// own [`ScannerKind`], and otherwise swallowed so the surrounding scan (host
/// enrichment, DNS) still finishes.
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

/// The privileged host-identification phase, shared by [`discover`] and
/// [`scan`].
///
/// It spawns the same strategies discovery uses - per-interface
/// [`LocalScanner`]s (ARP/ICMPv6, yielding MAC and RTT), a [`RoutedScanner`]
/// for off-link targets (RTT), and the passive DNS/mDNS
/// [`HostnameResolver`] - all writing into the shared store. `discover` runs
/// this alone; `scan` runs it alongside the port scan. Keeping it in one place
/// is what lets both surface identical host detail without duplicating the
/// orchestration.
struct Enrichment {
    scanners: Vec<(ScannerKind, JoinHandle<anyhow::Result<()>>)>,
    resolver: Option<JoinHandle<Option<HostnameResolver>>>,
}

impl Enrichment {
    /// Spawns every enrichment strategy for `targets`; they begin running
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

    /// Awaits every enrichment strategy, reporting any that failed, then folds
    /// the resolver's collected hostnames and extra IPs into the store.
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

/// Finds which hosts, among a set of target addresses, are actually alive.
///
/// This is the first phase of a scan: it establishes presence, not open
/// ports. With root privileges, targets are grouped by the network
/// interface that would reach them, and scanned with a raw-socket strategy
/// suited to each: [`LocalScanner`] (ARP/ICMP) for hosts on the same
/// physical segment, [`RoutedScanner`] (TCP SYN) for anything reached
/// through a gateway. Targets that can't be mapped to an interface at all -
/// a loopback address, for instance - along with every target when running
/// without root, fall back to plain TCP connect attempts against a handful
/// of common ports.
///
/// Hosts are written into the returned [`ScanSession`]'s store as they're
/// found, and each write fires a [`crate::core::session::ScanEvent`], so a
/// caller can watch a scan in progress rather than only seeing the final
/// result. Unless `cfg.no_dns` is set, discovered hosts are also resolved
/// to hostnames in the background - via passive DNS/mDNS sniffing when
/// privileged, or active reverse lookups otherwise - without blocking or
/// slowing down discovery itself.
///
/// The returned [`ScanTask`] resolves once every scanning strategy, and the
/// resolver if one was started, has finished. To stop a scan early, call
/// [`crate::core::handle::ScanHandle::abort`] on the session's handle; both
/// phases check for that signal regularly rather than only between targets.
pub async fn discover(
    targets: IpSet,
    cfg: &ZondConfig,
) -> Result<(ScanSession, ScanTask), ScanError> {
    let (session, ctx) = ScanSession::new();
    let caps = ScanCapabilities::resolve(cfg);

    // Unprivileged discovery has no raw enrichment strategies to spawn; it runs
    // the connect-based sweep itself, then the same DNS tail. Split out via an
    // early return because `targets` moves into one path or the other.
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

/// Builds a scanning strategy for each way a target can be reached, and runs
/// them all concurrently.
///
/// [`interface::map_ips_to_interfaces`] classifies the targets into three
/// groups: those on-link to an interface's segment become a per-interface
/// [`LocalScanner`]; those reached through a gateway, each already paired
/// with the source address to probe it from, are covered by a single
/// [`RoutedScanner`]; and those with no resolvable route go to a
/// [`connect::ConnectScanner`]. If constructing a particular scanner fails -
/// a capture socket that couldn't be opened, for instance - that one scanner
/// is skipped and logged; the rest of the scan proceeds without it.
///
/// Every constructed scanner is spawned as its own task, tagged with its
/// [`ScannerKind`] and returned, so the caller can wait on all of them and
/// react to failures individually rather than one bad scanner aborting the
/// whole scan. A scanner that fails to start is reported via
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

    // Local Scanner (ARP/ICMP)
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

    // Routed Scanner (TCP SYN)
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

    // Fallback Scanner (Unprivileged TCP Handshake) for unmapped IPs (e.g. localhost,
    // or targets the OS couldn't resolve a route/interface for).
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
        .map(|(kind, mut explorer)| {
            (
                kind,
                tokio::spawn(async move { explorer.discover_hosts().await }),
            )
        })
        .collect()
}

/// Logs a scanner failure and announces it on the event stream, so a consumer
/// watching a scan can tell it ran degraded rather than clean.
fn report_scanner_failure(ctx: &ScanContext, scanner: ScannerKind, reason: String) {
    error!("Scanner {scanner:?} failed: {reason}");
    let _ = ctx
        .events_tx
        .send(ScanEvent::ScannerFailed { scanner, reason });
}

/// Starts the background hostname resolver as its own task.
///
/// The resolver listens for raw DNS and mDNS traffic and answers reverse
/// lookups for any IP sent down `dns_rx`, independent of and concurrent
/// with whatever scanning strategies are running. If it fails to start -
/// most likely because no usable network socket could be opened - that
/// failure is logged and `None` is returned rather than propagated, since a
/// scan without hostname resolution is still a useful scan.
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

