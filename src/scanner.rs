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
//! Both phases adapt to whether the process holds root privileges. When it
//! does, [`discover`] groups targets by network interface and scans each one
//! with a raw-socket strategy suited to it: [`LocalScanner`] (in the [`local`]
//! module) handles hosts on the same physical segment over ARP and ICMP, while
//! [`RoutedScanner`] (in [`routed`]) handles anything reached through a gateway
//! over TCP SYN. [`scan`] follows the same pattern for ports, where a
//! privileged caller gets [`routed::TcpPortScanner`]. That scanner classifies
//! each port from a single raw SYN probe rather than completing a full
//! handshake. Targets that cannot be mapped to a usable interface, along with
//! every target when running unprivileged, fall back to plain TCP connect
//! attempts through the `connect` module.
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

use crate::core::config::{ProbeTuning, ZondConfig};
use crate::core::models::ip::range::{IpRange, Ipv6Range};
use crate::core::models::technique::TcpScanTechnique;
use crate::core::models::{
    ip::set::IpSet,
    port::Protocol,
    target::{Target, TargetMap},
};
use crate::core::report::{PhaseRecorder, ScanKind, ScanReport, TargetScope};
use crate::core::session::{ScanContext, ScanSession, ScannerKind};
use crate::scanner::resolver::HostnameResolver;
use crate::system::interface;
use crate::system::neighbors;
use crate::system::privilege::is_elevated;
use crate::{error, info, success, warn};
use local::{LocalScanner, Scope};
use routed::RoutedScanner;

mod audit;
mod composite;
mod connect;
pub mod dispatcher;
mod payload;
mod pool;
mod service;

#[cfg(not(feature = "test-support"))]
mod local;
#[cfg(feature = "test-support")]
pub mod local;

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
/// handle, or call [`ScanTask::join`], to wait for the whole scan to finish and
/// receive the [`ScanReport`] describing it. To stop a scan early, call
/// [`ScanHandle::abort`](crate::core::handle::ScanHandle::abort) on the
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
/// resolver if one was started, has finished, and yields the [`ScanReport`] for
/// the sweep. To stop a scan early, call
/// [`crate::core::handle::ScanHandle::abort`] on the session's handle. Both
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
            if let Err(e) = connect::discover(targets, ctx.clone()).await {
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
    let enrichment = Enrichment::spawn(targets, &ctx, caps, cfg.probe_tuning(), scope).await;

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
/// [`routed::TcpPortScanner`] classifies it from a single reply rather than a
/// completed handshake. Without root, or when the host has no address to probe
/// from, probes fall back to a plain TCP connect attempt per target through the
/// `connect` module.
pub async fn scan(
    mut target_map: TargetMap,
    cfg: &ZondConfig,
) -> Result<(ScanSession, ScanTask), ScanError> {
    let (session, ctx) = ScanSession::new();
    let caps = ScanCapabilities::resolve(cfg);
    let ips = target_ips(&target_map);
    let target_count = target_map.gross_targets().unwrap_or(0) as usize;

    // Recorded before `target_map` moves into the dispatcher.
    let scope = TargetScope::from_target_map(&mut target_map);
    let recorder = PhaseRecorder::start(ScanKind::PortScan, caps.privileged, scope, cfg);

    let (tcp_scanner, udp_scanner) = if caps.privileged {
        (
            build_tcp_scanner(
                ctx.clone(),
                cfg.tcp_technique,
                target_count,
                cfg.probe_tuning(),
            ),
            build_udp_scanner(ctx.clone(), target_count, cfg.probe_tuning()),
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
    let enrichment = if tcp_scanner.is_some() || udp_scanner.is_some() {
        Some(Enrichment::spawn(ips, &ctx, caps, cfg.probe_tuning(), Scope::Targeted).await)
    } else {
        None
    };

    // Both branches of the privilege fork now sit behind one interface. Pick the
    // strategy here and drive it uniformly below.
    let mut scanners: Vec<Box<dyn PortScanner>> = Vec::new();
    if let Some(scanner) = tcp_scanner {
        scanners.push(Box::new(scanner));
    }
    if let Some(scanner) = udp_scanner {
        scanners.push(Box::new(scanner));
    }
    let scanner = into_port_scanner(scanners, ctx.clone(), cfg.tcp_technique);

    let handle = tokio::spawn(async move {
        let dispatcher = dispatcher::Dispatcher::new(target_map);
        let rx = dispatcher.run_shuffled(&ctx.handle);

        run_port_scan(scanner, rx, &ctx).await;
        finish_enrichment(enrichment, caps, &ctx).await;
        recorder.finish(&ctx)
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
/// `spawn_explorers` depends on that uniformity to drive several unrelated
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
/// either the raw [`routed::TcpPortScanner`] or the unprivileged `connect`
/// fallback, through a single path. Implementations consume the shuffled
/// [`Target`] stream that a [`dispatcher::Dispatcher`] produces and write their
/// findings into the shared [`ScanContext`] they were built with;
/// [`PortScanner::scan`] reports only whether the run completed.
/// `run_port_scan` relies on that to treat both strategies identically.
#[async_trait]
pub trait PortScanner: Send {
    /// Identifies the strategy, used to tag a
    /// [`ScanEvent::ScannerFailed`](crate::core::session::ScanEvent::ScannerFailed) when
    /// a run fails.
    fn kind(&self) -> ScannerKind;

    /// Returns the set of transport protocols this scanner is capable of probing.
    ///
    /// `into_port_scanner` reads this to decide which protocols still need an
    /// unprivileged fallback, and `composite::CompositePortScanner` reads it
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
        tuning: ProbeTuning,
        scope: Scope,
    ) -> Self {
        let (dns_tx, resolver) = if caps.dns {
            let (tx, rx) = mpsc::unbounded_channel();
            (Some(tx), Some(spawn_resolver(rx).await))
        } else {
            info!("DNS resolution skipped by user flag");
            (None, None)
        };

        let scanners = spawn_explorers(targets, ctx, dns_tx, tuning, scope).await;
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
    tuning: ProbeTuning,
    scope: Scope,
) -> Vec<(ScannerKind, JoinHandle<anyhow::Result<()>>)> {
    let mut explorers: Vec<(ScannerKind, Box<dyn NetworkExplorer + Send>)> = Vec::new();
    let interface::RoutedTargets {
        local,
        routed,
        unmapped,
        ambiguous,
        unenumerable,
    } = interface::map_ips_to_interfaces(targets);

    // A link-local target naming no interface. Reported rather than guessed at:
    // every interface has an `fe80::/64`, so probing the first one that matches
    // would scan an arbitrary segment and report the address absent when it is
    // present on another.
    for range in &ambiguous {
        ctx.record_failure(
            ScannerKind::Local,
            format!(
                "{} is link-local, so it names a different machine on every \
                 segment. Say which: {}%<interface>.",
                range.start_addr, range.start_addr
            ),
        );
    }

    // Ranges no strategy can take. Reported before anything is spawned, and
    // reported as a failure rather than logged, because the distinction a caller
    // has to be able to draw is between "nothing is there" and "nobody looked" -
    // and only one of those is visible in a host count. A routed IPv6 prefix
    // cannot be walked (see `MAX_ENUMERABLE_ADDRESSES`), and until discovery
    // gains a strategy that searches a scope instead of a list, saying so is the
    // whole of what the engine can honestly do with one.
    for range in &unenumerable {
        ctx.record_failure(
            ScannerKind::Routed,
            format!(
                "{}-{} is {} addresses: too large to probe one at a time, and \
                 routed IPv6 has no other strategy yet. Give specific addresses \
                 or a smaller prefix.",
                range.start_addr,
                range.end_addr,
                range.len()
            ),
        );
    }

    // A sweep may probe addresses nobody named, so it may also take leads from
    // the host itself. A targeted run may not.
    let mut local = local;
    if matches!(scope, Scope::Sweep) {
        include_swept_link(&mut local);
        seed_from_neighbor_table(&mut local);
    }

    // Local scanner (ARP/ICMP) for hosts on the same physical segment.
    for (intf, local_ips) in local {
        // A sweep's link earns a scanner whether or not any address mapped to
        // it, because its most important probe is not addressed to anyone: the
        // all-nodes echo is one packet the whole segment may answer. A targeted
        // run has nothing to send without targets.
        if local_ips.is_empty() && matches!(scope, Scope::Targeted) {
            continue;
        }
        info!(verbosity = 1, "Spawning local scanner for {}", intf.name);
        match LocalScanner::new(
            intf.clone(),
            local_ips,
            ctx.clone(),
            dns_tx.clone(),
            scope,
            tuning.retry,
        ) {
            Ok(scanner) => explorers.push((ScannerKind::Local, Box::new(scanner))),
            Err(e) => ctx.record_failure(ScannerKind::Local, format!("{}: {e}", intf.name)),
        }
    }

    // Routed scanner (TCP SYN) for targets reached through a gateway.
    if !routed.is_empty() {
        info!(
            verbosity = 1,
            "Spawning routed scanner for {} target(s)",
            routed.len()
        );
        match RoutedScanner::new(routed, ctx.clone(), dns_tx.clone(), tuning) {
            Ok(scanner) => explorers.push((ScannerKind::Routed, Box::new(scanner))),
            Err(e) => ctx.record_failure(ScannerKind::Routed, e.to_string()),
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

/// Makes sure the link a sweep is about is among the links to be scanned, even
/// when no address mapped to it.
///
/// Mapping targets to interfaces can only ever produce interfaces some target
/// named, and the whole point of a sweep is the probe that names nobody. A link
/// addressed only in IPv6 resolves to no target list at all — a `/64` cannot be
/// enumerated and there is no IPv4 range to walk — so it mapped to nothing, no
/// scanner was built for it, and the all-nodes echo that would have found its
/// entire segment was never sent. The scan reported an empty network and looked
/// like it had worked.
///
/// Matching by name rather than by value: `map_ips_to_interfaces` and this both
/// read the platform's interface list, but a `NetworkInterface` compares on
/// every field, and being wrong here means scanning one link twice.
fn include_swept_link(
    local: &mut std::collections::HashMap<pnet::datalink::NetworkInterface, IpSet>,
) {
    let Ok(Some(link)) = interface::get_lan_link() else {
        return;
    };

    if local.keys().any(|intf| intf.name == link.interface.name) {
        return;
    }

    info!(
        verbosity = 1,
        "Sweeping {} for IPv6 neighbours; it has no IPv4 range to walk", link.interface.name
    );
    local.insert(link.interface, IpSet::new());
}

/// Adds the addresses in this host's IPv6 neighbour table to the targets of
/// whichever interface each belongs to.
///
/// This is the only source the engine has for an IPv6 address nobody named. A
/// neighbor solicitation is the mandatory probe, and it can only be aimed at an
/// address someone already holds; the all-nodes echo produces addresses but is
/// optional to answer and draws only link-local ones, since it goes out from a
/// link-local source. The operating system's own table has been accumulating
/// both for as long as the machine has been running, at no cost in packets — on
/// the segment this was written against it holds fifteen global and unique-local
/// addresses the engine could not otherwise learn at all.
///
/// Three exclusions, each for its own reason:
///
/// - **Other interfaces' entries.** A neighbour on `en1` is not reachable
///   through `en0`, and the entry says which it belongs to.
/// - **This host's own addresses.** The table lists them too, and a scan that
///   reported the machine running it as a discovered neighbour would be wrong in
///   a way nobody would think to check.
/// - **Loopback and the unspecified address**, which name nothing on a segment.
///
/// Nothing seeded here is treated as a discovered host. Every entry is an
/// address that answered *once*, from a table that goes stale, so each becomes a
/// probe like any other and earns its place in the report by answering now.
fn seed_from_neighbor_table(
    local: &mut std::collections::HashMap<pnet::datalink::NetworkInterface, IpSet>,
) {
    let table = neighbors::ipv6_neighbors();
    if !table.is_empty() {
        seed_from_neighbor_table_with(local, &table);
    }
}

/// [`seed_from_neighbor_table`] against an explicit table, so the exclusions can
/// be tested without a host that happens to have the right neighbours.
fn seed_from_neighbor_table_with(
    local: &mut std::collections::HashMap<pnet::datalink::NetworkInterface, IpSet>,
    table: &[neighbors::Neighbor],
) {
    for (intf, targets) in local.iter_mut() {
        let mut seeded = 0usize;
        for addr in candidates_for(intf, table) {
            let IpAddr::V6(addr) = addr else { continue };
            // The zone matters for exactly the addresses that cannot be probed
            // without one, and is dropped for the rest for the reason
            // `ScopedIp` drops it: the same global address through two
            // interfaces is one address, not two.
            let zone = addr.is_unicast_link_local().then_some(intf.index);
            if let Ok(range) = Ipv6Range::scoped(addr, addr, zone) {
                targets.insert_range(IpRange::V6(range));
                seeded += 1;
            }
        }

        if seeded > 0 {
            targets.canonicalize();
            info!(
                verbosity = 1,
                "Took {seeded} IPv6 address(es) from the neighbour table as candidates on {}",
                intf.name
            );
        }
    }
}

/// The neighbour-table addresses worth probing on `intf`, in table order.
fn candidates_for(
    intf: &pnet::datalink::NetworkInterface,
    table: &[neighbors::Neighbor],
) -> Vec<IpAddr> {
    let own: std::collections::HashSet<IpAddr> = intf.ips.iter().map(|net| net.ip()).collect();

    table
        .iter()
        .filter(|entry| entry.interface_index == intf.index)
        .filter(|entry| !own.contains(&entry.ip))
        .filter(|entry| match entry.ip {
            IpAddr::V6(addr) => !addr.is_loopback() && !addr.is_unspecified(),
            IpAddr::V4(_) => false,
        })
        .map(|entry| entry.ip)
        .collect()
}

/// Tries to build a privileged raw-socket TCP port scanner for `technique`,
/// resolving each probe's source address per target across the host's
/// interfaces and routing table.
///
/// Called only once privilege is confirmed (see [`ScanCapabilities`]). Returns
/// `None`, meaning [`scan`] should fall back to TCP connect probes, when the
/// host has no address to probe from or when the scanner fails to initialize,
/// for instance because raw sockets could not be opened. Each case is logged
/// here rather than treated as a hard failure, since the unprivileged path is
/// always a working substitute.
fn build_tcp_scanner(
    ctx: ScanContext,
    technique: TcpScanTechnique,
    target_count: usize,
    tuning: ProbeTuning,
) -> Option<routed::TcpPortScanner> {
    let resolver = interface::SourceResolver::from_system();
    if !resolver.has_sources() {
        warn!("No usable network interface found; using TCP connect fallback");
        return None;
    }

    match routed::TcpPortScanner::new(resolver, ctx, technique, target_count, tuning) {
        Ok(scanner) => Some(scanner),
        Err(e) => {
            error!("Failed to initialize {technique} port scanner: {e}");
            None
        }
    }
}

/// Tries to build a privileged raw-socket UDP port scanner.
fn build_udp_scanner(
    ctx: ScanContext,
    target_count: usize,
    tuning: ProbeTuning,
) -> Option<routed::UdpPortScanner> {
    let resolver = interface::SourceResolver::from_system();
    if !resolver.has_sources() {
        return None; // Fallback will be used
    }

    match routed::UdpPortScanner::new(resolver, ctx, target_count, tuning) {
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
/// build one raw scanner and not the other - the TCP scanner needs a raw TCP
/// socket, the UDP scanner a raw UDP one, and a sandbox can permit one and
/// refuse the other - and a protocol left without any scanner is not a degraded
/// scan but a silent one: [`composite::CompositePortScanner`] has nowhere to
/// route those targets, so they would simply never be probed and never be
/// reported. Asking each scanner what it covers, rather than assuming a
/// privileged scan covers everything, is what keeps that from happening.
///
/// **A connect fallback substitutes for a SYN scan and for nothing else.** It
/// completes handshakes, so it answers roughly the question a SYN scan asks;
/// it cannot send a FIN, a flagless segment or a bare ACK, and so it cannot
/// answer what any of those were asked. Where the caller chose one of them and
/// no raw scanner could be built, the TCP half of the scan is reported as a
/// failure and left undone. That is worse for the caller and honest, where a
/// silent substitution would hand back verdicts from a technique they did not
/// choose - and no field in the report would say so.
fn into_port_scanner(
    mut scanners: Vec<Box<dyn PortScanner>>,
    ctx: ScanContext,
    tcp_technique: TcpScanTechnique,
) -> Box<dyn PortScanner> {
    let covered: Vec<Protocol> = scanners
        .iter()
        .flat_map(|scanner| scanner.supported_protocols())
        .collect();

    if !covered.contains(&Protocol::Tcp) {
        if tcp_technique.finds_open_ports() {
            scanners.push(Box::new(connect::ConnectPortScanner::new(
                ctx.clone(),
                tuning::CONNECT_CONCURRENCY,
            )));
        } else {
            ctx.record_failure(
                ScannerKind::TcpPort,
                format!(
                    "the {tcp_technique} technique needs raw sockets, which this process \
                     does not have, and a connect scan answers a different question - so \
                     no TCP port was probed",
                ),
            );
        }
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

        async fn scan(&mut self, _targets: mpsc::Receiver<Target>) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn covered(scanners: Vec<Box<dyn PortScanner>>) -> Vec<Protocol> {
        let (_session, ctx) = ScanSession::new();
        into_port_scanner(scanners, ctx, TcpScanTechnique::Syn).supported_protocols()
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
        let scanner = into_port_scanner(Vec::new(), ctx.clone(), TcpScanTechnique::Fin);

        assert!(
            !scanner.supported_protocols().contains(&Protocol::Tcp),
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

    fn v6(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    fn interface_with(
        index: u32,
        name: &str,
        own: Vec<IpAddr>,
    ) -> pnet::datalink::NetworkInterface {
        use pnet::ipnetwork::{IpNetwork, Ipv6Network};
        pnet::datalink::NetworkInterface {
            name: name.to_string(),
            description: String::new(),
            index,
            mac: None,
            ips: own
                .into_iter()
                .map(|ip| match ip {
                    IpAddr::V6(v6) => IpNetwork::V6(Ipv6Network::new(v6, 64).unwrap()),
                    IpAddr::V4(_) => unreachable!("test uses v6 only"),
                })
                .collect(),
            flags: 0,
        }
    }

    fn entry(ip: &str, index: u32) -> neighbors::Neighbor {
        neighbors::Neighbor {
            ip: v6(ip),
            mac: None,
            interface_index: index,
        }
    }

    /// The three entries that must never become targets, each wrong in its own
    /// way: another interface's neighbour is not reachable through this one,
    /// this host would be reported as a discovered neighbour of itself, and
    /// loopback names nothing on a segment.
    #[test]
    fn seeding_skips_other_interfaces_our_own_addresses_and_loopback() {
        let own = v6("2001:db8::50");
        let intf = interface_with(7, "en0", vec![own]);
        let table = vec![
            entry("2001:db8::aa", 7),
            entry("fe80::bb", 7),
            entry("2001:db8::cc", 9),
            entry("2001:db8::50", 7),
            entry("::1", 7),
        ];

        let seeded = candidates_for(&intf, &table);

        assert_eq!(seeded, vec![v6("2001:db8::aa"), v6("fe80::bb")]);
    }

    /// A link-local candidate carries the interface it came from, because it
    /// cannot be probed without one. A global address does not, for the reason
    /// `ScopedIp` drops it: the same address through two interfaces is one
    /// address.
    #[test]
    fn a_seeded_link_local_keeps_its_interface_and_a_global_does_not() {
        let intf = interface_with(7, "en0", Vec::new());
        let table = vec![entry("fe80::bb", 7), entry("2001:db8::aa", 7)];
        let mut local = std::collections::HashMap::from([(intf, IpSet::new())]);

        seed_from_neighbor_table_with(&mut local, &table);

        let targets = local.into_values().next().unwrap();
        let zones: Vec<Option<u32>> = targets.v6().iter().map(|range| range.zone).collect();
        assert!(
            zones.contains(&Some(7)),
            "the link-local needs its interface"
        );
        assert!(
            zones.contains(&None),
            "the global address needs no interface"
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
            TcpScanTechnique::Syn,
        );
        // Two scanners in, two scanners out: `supported_protocols` deduplicates,
        // so count the routes rather than the protocols.
        assert_eq!(scanner.supported_protocols().len(), 2);
    }
}
