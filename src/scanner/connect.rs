// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Unprivileged TCP Connect Scanning
//!
//! The fallback strategy when raw sockets aren't available - no root, no usable
//! interface, or a target the OS couldn't route. Everything here is built on
//! ordinary [`TcpStream`] connects, so it needs no special privileges and works
//! anywhere the async runtime does.
//!
//! It answers both scan phases. [`discover`] establishes host presence by
//! probing a small set of common infrastructure ports and treating any TCP-layer
//! response (an accept, or even a refusal) as proof the host is alive.
//! [`scan`] takes known targets and classifies each port from a full connect
//! handshake. Both consume a randomized [`Dispatcher`] stream and bound their
//! in-flight connections with a [`JoinSet`] to avoid exhausting OS sockets, and
//! both record findings through the shared [`ScanContext`] like every other
//! strategy.

use super::dispatcher::Dispatcher;
use super::pool::ProbePool;
use super::{NetworkExplorer, PortScanner};
use crate::core::models::host::Host;
use crate::core::models::ip::set::IpSet;
use crate::core::models::port::{Port, PortSet, PortState, Protocol};
use crate::core::models::target::{Target, TargetMap, TargetSet};
use crate::core::session::{ScanContext, ScannerKind};
use async_trait::async_trait;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// How long a single connect probe waits before treating silence as a drop.
const PROBE_TIMEOUT: Duration = Duration::from_millis(1000);

/// Most common ports across Linux, Windows, and Networking gear.
const DISCOVERY_PORTS: &[u16] = &[22, 80, 443, 445, 3389];

/// Adapts the unprivileged [`discover`] strategy to [`NetworkExplorer`], so it can
/// be spawned alongside [`LocalScanner`](super::local::LocalScanner) and
/// [`RoutedScanner`](super::routed::RoutedScanner) from a single explorer list.
pub struct ConnectScanner {
    /// The addresses being probed for aliveness.
    ips: IpSet,
    /// Shared state (host store, event channel, abort signal) for the scan
    /// this explorer is part of.
    ctx: ScanContext,
}

impl ConnectScanner {
    pub fn new(ips: IpSet, ctx: ScanContext) -> Self {
        Self { ips, ctx }
    }
}

#[async_trait]
impl NetworkExplorer for ConnectScanner {
    async fn discover_hosts(&mut self) -> anyhow::Result<()> {
        discover(std::mem::take(&mut self.ips), self.ctx.clone()).await
    }
}

/// The outcome of one finished [`port_prober`] task: the port it classified, or
/// `None` if the port was closed or the target wasn't probed at all. A probe never
/// fails - every network outcome maps to a port state or to `None` - so this is a
/// plain [`Option`], not a `Result`.
type ProbedPort = Option<(IpAddr, Port)>;

/// Adapts the unprivileged [`scan`] engine to [`PortScanner`], so
/// [`crate::scanner::scan`] can drive it through the same path as the privileged
/// [`SynPortScanner`](super::routed::SynPortScanner).
///
/// It carries no [`detect_services`](PortScanner::detect_services) override: the
/// connect engine fingerprints each port inline over the live stream it already
/// holds (see [`port_prober`]), so a second identification pass would be wasted
/// work. That is the whole reason service detection lives on the trait rather than
/// in the caller - the "connect needs no second pass" fact is expressed here, by
/// its absence, instead of as a branch at the call site.
pub struct ConnectPortScanner {
    /// Shared state (host store, event channel, abort signal) for the scan this
    /// strategy is part of.
    ctx: ScanContext,
    /// The ceiling on in-flight connect probes.
    concurrency: usize,
}

impl ConnectPortScanner {
    pub fn new(ctx: ScanContext, concurrency: usize) -> Self {
        Self { ctx, concurrency }
    }
}

#[async_trait]
impl PortScanner for ConnectPortScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::Connect
    }

    async fn scan(&mut self, rx: mpsc::Receiver<Target>) -> anyhow::Result<()> {
        scan(rx, self.concurrency, self.ctx.clone()).await
    }
}

/// Performs a high-concurrency, unprivileged port scan.
///
/// This is the primary scanning strategy for callers without root privileges. It
/// consumes a randomized stream of [`Target`]s from a [`Dispatcher`], holding the
/// number of in-flight connections at or below `concurrency_limit` to avoid
/// exhausting OS sockets, and records every non-closed port it finds into the
/// shared [`ScanContext`] store.
pub async fn scan(
    mut rx: mpsc::Receiver<Target>,
    concurrency_limit: usize,
    ctx: ScanContext,
) -> anyhow::Result<()> {
    let mut pool = ProbePool::new(concurrency_limit, |probed| absorb_probe(&ctx, probed));

    while let Some(target) = rx.recv().await {
        if ctx.handle.should_stop() {
            break;
        }
        pool.admit(port_prober(target)).await;
    }

    // Every target dispatched; wait out the probes still in flight.
    pool.drain().await;
    Ok(())
}

/// Folds one finished probe into the store, if it classified a non-closed port.
fn absorb_probe(ctx: &ScanContext, probed: ProbedPort) {
    if let Some((ip, port)) = probed {
        ctx.update_host(ip, |host| host.add_port(port));
    }
}

/// Probes a single [`Target`] over a full TCP connect handshake and classifies
/// its port. Returns `Some(..)` for a non-closed port and `None` for a closed
/// port or a target this strategy doesn't handle.
///
/// An accepted connection is `Open` and gets fingerprinted over the live stream;
/// a refusal is `Closed`; anything else - including a timeout, the usual
/// signature of a firewall drop - is `Filtered`. Only TCP is supported; UDP
/// targets are skipped.
async fn port_prober(target: Target) -> ProbedPort {
    if target.protocol == Protocol::Udp {
        // UDP can't be probed through a TCP stream; skip rather than misreport.
        return None;
    }

    let socket_addr = SocketAddr::new(target.ip, target.port);

    match timeout(PROBE_TIMEOUT, TcpStream::connect(socket_addr)).await {
        Ok(Ok(stream)) => {
            let port =
                crate::fingerprinting::baseline_port(target.port, Protocol::Tcp, PortState::Open);
            let port = crate::fingerprinting::fingerprint_tcp(stream, port).await;
            Some((target.ip, port))
        }
        Ok(Err(e)) => {
            use std::io::ErrorKind;
            match e.kind() {
                // A refusal is a definite "closed"; report nothing to record.
                ErrorKind::ConnectionRefused => None,
                // Anything else reached the host but didn't complete: filtered.
                _ => Some((
                    target.ip,
                    crate::fingerprinting::baseline_port(
                        target.port,
                        Protocol::Tcp,
                        PortState::Filtered,
                    ),
                )),
            }
        }
        // Timeout: the probe was silently dropped, the classic firewall signature.
        Err(_) => Some((
            target.ip,
            crate::fingerprinting::baseline_port(target.port, Protocol::Tcp, PortState::Filtered),
        )),
    }
}

/// High-fidelity, multi-port host discovery for unprivileged environments.
///
/// This engine performs a rapid sweep of target networks by probing a curated
/// set of infrastructure ports: SSH (22), HTTP (80), HTTPS (443), SMB (445),
/// and RDP (3389). This multi-port approach ensures high discovery fidelity
/// across Linux, Windows, and embedded network targets.
///
/// ### Characteristics
/// - **Early-Exit**: Probes for an IP are immediately bypassed if the host
///   has already been confirmed alive by a parallel task.
/// - **Randomized**: Target distribution is handled by a shuffling [`Dispatcher`]
///   to minimize local network congestion.
/// - **Fidelity Range**: Uses an adjustable 1000ms timeout window to capture
///   hosts on high-latency or geographically distant links.
pub async fn discover(ips: IpSet, ctx: ScanContext) -> anyhow::Result<()> {
    const CONCURRENCY_LIMIT: usize = 2048;

    let mut target_map = TargetMap::new();
    let port_set = PortSet::try_from(
        DISCOVERY_PORTS
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
            .as_str(),
    )?;
    target_map.add_unit(TargetSet::new(ips, port_set));

    let dispatcher = Dispatcher::new(target_map).with_batch_size(1024);
    let mut rx = dispatcher.run_shuffled(&ctx.handle);
    let found_hosts = Arc::new(Mutex::new(HashSet::new()));
    let mut pool = ProbePool::new(CONCURRENCY_LIMIT, |probed| absorb_host(&ctx, probed));

    while let Some(target) = rx.recv().await {
        if ctx.handle.should_stop() {
            break;
        }
        let found = Arc::clone(&found_hosts);
        pool.admit(prober(target, found)).await;
    }

    // Every target dispatched; wait out the probes still in flight.
    pool.drain().await;
    Ok(())
}

/// The outcome of one finished [`prober`] task: a live [`Host`], or `None` if the
/// target stayed silent or was already claimed by a parallel probe. A probe never
/// fails, so this is a plain [`Option`], not a `Result`.
type ProbedHost = Option<Host>;

/// Merges one finished discovery probe's host into the store. A freshly created
/// entry starts from [`Host::new`] and absorbs the probe's findings (RTT, any
/// extra IPs), so the recorded result is the same whether or not the host was
/// seen before.
fn absorb_host(ctx: &ScanContext, probed: ProbedHost) {
    if let Some(host) = probed {
        let ip = host.primary_ip();
        ctx.update_host(ip, |existing| existing.merge(host));
    }
}

/// Concurrent network host prober.
///
/// Attempts a TCP connection to a specific [`Target`]. To minimize unnecessary
/// network traffic and OS resource usage, it employs a thread-safe early-exit
/// mechanism: if the host has already been identified by a parallel probe
/// (e.g., SSH responded before HTTP), this task terminates immediately.
async fn prober(target: Target, found_set: Arc<Mutex<HashSet<IpAddr>>>) -> ProbedHost {
    // 1. Early exit if already discovered
    {
        let set = found_set.lock().unwrap();
        if set.contains(&target.ip) {
            return None;
        }
    }

    let socket_addr: SocketAddr = SocketAddr::new(target.ip, target.port);

    let start: Instant = Instant::now();
    match timeout(PROBE_TIMEOUT, TcpStream::connect(socket_addr)).await {
        Ok(Ok(_)) => {
            // 2. Successful handshake -> Host is alive
            let mut set = found_set.lock().unwrap();
            if set.insert(target.ip) {
                Some(Host::new(target.ip).with_rtt(start.elapsed()))
            } else {
                None
            }
        }
        Ok(Err(e)) => {
            use std::io::ErrorKind;
            // 3. Only specific TCP errors imply the target host responded at the IP/TCP layer
            match e.kind() {
                ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted => {
                    let mut set = found_set.lock().unwrap();
                    if set.insert(target.ip) {
                        Some(Host::new(target.ip).with_rtt(start.elapsed()))
                    } else {
                        None
                    }
                }
                _ => {
                    // Ignore local network errors (No route, Permission denied, etc.)
                    None
                }
            }
        }
        Err(_elapsed) => None,
    }
}
