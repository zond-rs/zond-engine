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
//! through a gateway, using TCP SYN. Targets that can't be mapped to an
//! interface at all, along with every target when running unprivileged,
//! fall back to plain TCP connect attempts via the [`connect`] module.
//! `scan` currently always uses that same TCP-connect strategy regardless
//! of privilege level; a faster SYN-based probe for privileged callers is
//! planned but not wired up yet.
//!
//! Every scanning strategy implements [`NetworkExplorer`], which is what
//! lets [`discover`] spawn several unrelated scanners - one per interface,
//! plus the fallback - and run them all through the same loop rather than
//! special-casing each one. Discovered hosts land in a shared, thread-safe
//! store as they're found, and each update fires a lightweight event so a
//! caller can watch a scan in progress instead of waiting for it to finish.
//! If DNS resolution is enabled, hostnames for discovered hosts are looked
//! up in the background, via the [`resolver`] module, without blocking
//! discovery itself.

use std::net::IpAddr;

use async_trait::async_trait;
use is_root::is_root;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use crate::core::config::ZondConfig;
use crate::core::models::{ip::set::IpSet, target::TargetMap};
use crate::core::session::{ScanContext, ScanSession};
use crate::scanner::resolver::HostnameResolver;
use crate::system::interface;
use crate::{error, info, success, warn};
use local::LocalScanner;
use routed::RoutedScanner;

mod connect;
pub mod dispatcher;
mod local;
mod resolver;
mod routed;

/// How many TCP connect probes [`scan`] runs at once.
const PORT_SCAN_CONCURRENCY: usize = 50;

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

/// Probes a known set of targets for open ports.
///
/// This is the second phase of a scan: given targets and the ports to check
/// on each, find out which of those ports are open. It does no host
/// discovery of its own - a target that isn't actually alive just comes
/// back with every port closed or filtered, at the cost of a wasted probe.
/// Call [`discover`] first if you don't already know which targets exist.
///
/// Every probe currently goes through a plain TCP connect attempt,
/// regardless of privilege level. A faster SYN-based probe for privileged
/// callers, mirroring what [`discover`] already does for host discovery, is
/// planned but not implemented yet - so unlike `discover`, running this as
/// root doesn't currently buy any speed.
pub async fn scan(
    target_map: TargetMap,
) -> anyhow::Result<(ScanSession, JoinHandle<anyhow::Result<()>>)> {
    let (session, ctx) = ScanSession::new();

    if not_root() {
        // TODO: drop this once a privileged SYN-based prober exists for scan().
        warn!("Privileged port scanning (SYN) not yet implemented; using TCP connect fallback");
    }

    let join_handle = tokio::spawn(async move {
        let dispatcher = dispatcher::Dispatcher::new(target_map);
        let rx = dispatcher.run_shuffled(&ctx.handle);
        connect::scan(rx, PORT_SCAN_CONCURRENCY, ctx).await
    });

    Ok((session, join_handle))
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
/// The returned `JoinHandle` resolves once every scanning strategy, and the
/// resolver if one was started, has finished. To stop a scan early, call
/// [`crate::core::handle::ScanHandle::abort`] on the session's handle; both
/// phases check for that signal regularly rather than only between targets.
pub async fn discover(
    targets: IpSet,
    cfg: &ZondConfig,
) -> anyhow::Result<(ScanSession, JoinHandle<anyhow::Result<()>>)> {
    let with_dns: bool = !cfg.no_dns;
    let (session, ctx) = ScanSession::new();

    if not_root() {
        let join_handle = tokio::spawn(async move {
            connect::discover(targets, ctx.clone()).await?;
            if with_dns {
                resolver::resolve_hosts_async(ctx.store).await;
            }
            Ok(())
        });
        return Ok((session, join_handle));
    }

    let (dns_tx, resolver_task) = if with_dns {
        let (tx, rx) = mpsc::unbounded_channel();
        let task = spawn_resolver(rx).await;
        (Some(tx), Some(task))
    } else {
        info!("DNS resolution skipped by user flag");
        (None, None)
    };

    let scanner_handles = spawn_explorers(targets, &ctx, dns_tx).await;

    let join_handle = tokio::spawn(async move {
        for handle in scanner_handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => error!("Scanner task failed: {e}"),
                Err(e) => error!("Task panicked: {e}"),
            }
        }

        if let Some(task) = resolver_task
            && let Ok(Some(mut resolver)) = task.await
        {
            resolver.resolve_hosts(ctx.store);
        }

        Ok(())
    });

    Ok((session, join_handle))
}

/// Builds one scanning strategy per network interface a target could be
/// reached through, plus a fallback for anything that couldn't be mapped to
/// one, and runs all of them concurrently.
///
/// [`interface::map_ips_to_interfaces`] splits the targets into, for each
/// interface, the subset reachable directly on that segment versus the
/// subset that has to be routed through it - these become a
/// [`LocalScanner`] and a [`RoutedScanner`] respectively. A single
/// interface can produce both, one, or neither, depending on which targets
/// it can actually reach. Targets that map to no interface at all go to a
/// [`connect::ConnectScanner`] instead. If constructing a particular
/// scanner fails - a capture socket that couldn't be opened, an interface
/// with no usable address - that one scanner is skipped and logged; the
/// rest of the scan proceeds without it.
///
/// Every constructed scanner is spawned as its own task and its
/// `JoinHandle` returned, so the caller can wait on all of them and react
/// to failures individually rather than one bad interface aborting the
/// whole scan.
async fn spawn_explorers(
    targets: IpSet,
    ctx: &ScanContext,
    dns_tx: Option<UnboundedSender<IpAddr>>,
) -> Vec<JoinHandle<anyhow::Result<()>>> {
    let mut explorers: Vec<Box<dyn NetworkExplorer + Send>> = Vec::new();
    let (interface_map, unmapped_ips) = interface::map_ips_to_interfaces(targets);

    for (intf, (local_ips, routed_ips)) in interface_map {
        // Local Scanner (ARP/ICMP)
        if !local_ips.is_empty() {
            info!(verbosity = 1, "Spawning local scanner for {}", intf.name);
            match LocalScanner::new(intf.clone(), local_ips, ctx.clone(), dns_tx.clone()) {
                Ok(scanner) => explorers.push(Box::new(scanner)),
                Err(e) => error!("Failed to initialize local scanner for {}: {e}", intf.name),
            }
        }

        // Routed Scanner (TCP Syn Scan)
        if !routed_ips.is_empty() {
            info!(verbosity = 1, "Spawning routed scanner for {}", intf.name);
            match RoutedScanner::new(intf.clone(), routed_ips, ctx.clone(), dns_tx.clone()) {
                Ok(scanner) => explorers.push(Box::new(scanner)),
                Err(e) => error!("Failed to initialize routed scanner for {}: {e}", intf.name),
            }
        }
    }

    // Fallback Scanner (Unprivileged TCP Handshake) for unmapped IPs (e.g. localhost,
    // or targets the OS couldn't resolve a route/interface for).
    if !unmapped_ips.is_empty() {
        warn!(
            verbosity = 1,
            "Spawning fallback scanner for unmapped targets"
        );
        explorers.push(Box::new(connect::ConnectScanner::new(
            unmapped_ips,
            ctx.clone(),
        )));
    }

    explorers
        .into_iter()
        .map(|mut explorer| tokio::spawn(async move { explorer.discover_hosts().await }))
        .collect()
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

/// Checks for root privileges, logging which scanning mode this implies.
///
/// Returns `true` when *not* running as root, i.e. when the caller should
/// fall back to unprivileged, TCP-connect-based scanning rather than raw
/// sockets. The inverted name reads more sensibly at the call site -
/// `if not_root() { /* fall back */ }` - than mirroring `is_root` would.
fn not_root() -> bool {
    if !is_root() {
        warn!("Root privileges missing, defaulting to unprivileged TCP scan");
        return true;
    }

    success!("Root privileges detected, raw socket scan enabled");
    false
}
