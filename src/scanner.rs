// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Orchestration logic for network discovery.
//!
//! This module coordinates the execution of various scanning strategies:
//! - **Privileged**: High-speed raw socket scans ([`LocalScanner`] for ARP/ICMP, [`RoutedScanner`] for TCP SYN).
//! - **Unprivileged**: Standard TCP handshake fallback via the [`connect`] module.
//!
//! It manages the lifecycle of a scan by partitioning targets by interface,
//! spawning concurrent explorers, and piping results through a background [`HostnameResolver`]

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

const PORT_SCAN_CONCURRENCY: usize = 50;

#[async_trait]
trait NetworkExplorer {
    async fn discover_hosts(&mut self) -> anyhow::Result<()>;
}

pub async fn scan(
    target_map: TargetMap,
) -> anyhow::Result<(ScanSession, JoinHandle<anyhow::Result<()>>)> {
    let (session, ctx) = ScanSession::new();

    if not_root() {
        // Future: Remove this fallback once SYN scanner is ready
        warn!("Privileged port scanning (SYN) not yet implemented; using TCP connect fallback");
    }

    let join_handle = tokio::spawn(async move {
        let dispatcher = dispatcher::Dispatcher::new(target_map);
        let rx = dispatcher.run_shuffled(&ctx.handle);
        connect::scan(rx, PORT_SCAN_CONCURRENCY, ctx).await
    });

    Ok((session, join_handle))
}

/// The primary entry point for network discovery.
///
/// ### Capabilities
/// - **Privilege Aware**: Uses raw sockets (ARP/TCP SYN) if root; falls back to standard TCP handshakes if not.
/// - **Multi-Interface**: Automatically partitions targets across available network adapters.
/// - **Parallel Resolver**: Streams found IPs to a background DNS task for zero-latency lookups.
///
/// ### Integration Notes
/// - **State**: Emits [`ScanEvent`]s to `ScanSession` and reacts to [`ScanHandle::should_stop`].
/// - **Concurrency**: Spawns multiple Tokio tasks; ensure the caller is within a multithreaded runtime.
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
