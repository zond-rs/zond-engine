// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Orchestration logic for network discovery.
//!
//! This module coordinates the execution of various scanning strategies:
//! - **Privileged**: High-speed raw socket scans ([`LocalScanner`] for ARP/ICMP, [`RoutedScanner`] for TCP SYN).
//! - **Unprivileged**: Standard TCP handshake fallback via [`handshake`].
//!
//! It manages the lifecycle of a scan by partitioning targets by interface,
//! spawning concurrent explorers, and piping results through a background [`HostnameResolver`]

use std::net::IpAddr;

use async_trait::async_trait;
use is_root::is_root;
use tokio::sync::mpsc::{self, UnboundedReceiver};
use tokio::task::JoinHandle;

use crate::core::config::ZondConfig;
use crate::core::handle::ScanHandle;
use crate::core::models::{host::Host, ip::set::IpSet, target::TargetMap};
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

#[async_trait]
trait NetworkExplorer {
    async fn discover_hosts(&mut self) -> anyhow::Result<Vec<Host>>;
}

pub async fn scan(target_map: TargetMap, scan_handle: &ScanHandle) -> anyhow::Result<Vec<Host>> {
    if not_root() {
        // Future: Remove this fallback once SYN scanner is ready
        warn!("Privileged port scanning (SYN) not yet implemented; using TCP connect fallback");
    }

    let dispatcher = dispatcher::Dispatcher::new(target_map);
    let rx = dispatcher.run_shuffled(scan_handle);
    connect::scan(rx, scan_handle, 50).await
}

/// The primary entry point for network discovery.
///
/// ### Capabilities
/// - **Privilege Aware**: Uses raw sockets (ARP/TCP SYN) if root; falls back to standard TCP handshakes if not.
/// - **Multi-Interface**: Automatically partitions targets across available network adapters.
/// - **Parallel Resolver**: Streams found IPs to a background DNS task for zero-latency lookups.
///
/// ### Integration Notes
/// - **State**: Emits [`ScanEvent`]s and reacts to [`ScanHandle::should_stop`].
/// - **Concurrency**: Spawns multiple Tokio tasks; ensure the caller is within a multithreaded runtime.
pub async fn discover(
    targets: IpSet,
    cfg: &ZondConfig,
    scan_handle: &ScanHandle,
) -> anyhow::Result<Vec<Host>> {
    let with_dns: bool = !cfg.no_dns;
    if not_root() {
        let mut hosts = connect::discover(targets, scan_handle).await?;
        if with_dns {
            resolver::resolve_hosts_async(&mut hosts).await;
        }
        return Ok(hosts);
    }

    let (dns_tx, resolver_task) = if with_dns {
        let (tx, rx) = mpsc::unbounded_channel();
        let task = spawn_resolver(rx).await;
        (Some(tx), Some(task))
    } else {
        info!("DNS resolution skipped by user flag");
        (None, None)
    };

    let scanner_handles = spawn_explorers(targets, scan_handle, dns_tx).await;

    let mut hosts = Vec::new();
    for handle in scanner_handles {
        match handle.await {
            Ok(Ok(res)) => hosts.extend(res),
            Ok(Err(e)) => error!("Scanner task failed: {e}"),
            Err(e) => error!("Task panicked: {e}"),
        }
    }

    if let Some(task) = resolver_task
        && let Ok(Some(mut resolver)) = task.await
    {
        resolver.resolve_hosts(&mut hosts);
    }

    Ok(hosts)
}

async fn spawn_explorers(
    targets: IpSet,
    scan_handle: &ScanHandle,
    dns_tx: Option<mpsc::UnboundedSender<IpAddr>>,
) -> Vec<JoinHandle<anyhow::Result<Vec<Host>>>> {
    let mut handles = Vec::new();

    let (interface_map, unmapped_ips) = interface::map_ips_to_interfaces(targets);

    for (intf, (local_ips, routed_ips)) in interface_map {
        // Local Scanner (ARP/ICMP)
        if !local_ips.is_empty() {
            info!(verbosity = 1, "Spawning LOCAL scanner for {}", intf.name);
            let tx = dns_tx.clone();
            let intf_c = intf.clone();

            let scan_handle_clone = scan_handle.clone();
            let handle = tokio::spawn(async move {
                let mut scanner = LocalScanner::new(intf_c, local_ips, scan_handle_clone, tx)?;
                scanner.discover_hosts().await
            });
            handles.push(handle);
        }

        // Routed Scanner (TCP Syn Scan)
        if !routed_ips.is_empty() {
            info!(verbosity = 1, "Spawning ROUTED scanner for {}", intf.name);
            let tx = dns_tx.clone();
            let intf_c = intf.clone();

            let scan_handle_clone = scan_handle.clone();
            let handle = tokio::spawn(async move {
                let mut scanner = RoutedScanner::new(intf_c, routed_ips, scan_handle_clone, tx)?;
                scanner.discover_hosts().await
            });
            handles.push(handle);
        }
    }

    // Fallback Scanner (Unprivileged TCP Handshake) for unmapped IPs (e.g. localhost)
    if !unmapped_ips.is_empty() {
        info!(
            verbosity = 1,
            "Spawning FALLBACK scanner for unmapped targets"
        );
        let scan_handle_clone = scan_handle.clone();
        let handle =
            tokio::spawn(async move { connect::discover(unmapped_ips, &scan_handle_clone).await });
        handles.push(handle);
    }

    handles
}

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

fn not_root() -> bool {
    if !is_root() {
        warn!("Root privileges missing, defaulting to unprivileged TCP scan");
        return true;
    }

    success!("Root privileges detected, raw socket scan enabled");
    false
}
