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
//! [`report::PhaseRecorder`] takes the scope and settings before
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
//! Every one of those implements [`HostScanner`](strategy::HostScanner) or
//! [`PortScanner`](strategy::PortScanner), which is what lets several unrelated
//! strategies be driven through one loop. Discovered hosts land in a shared,
//! thread-safe store as they are found, and each update fires an event, so a
//! caller can watch a scan in progress instead of waiting for it to finish.
//! When DNS resolution is enabled, hostnames are looked up in the background
//! through the [`resolver`] module without blocking discovery.

use std::pin::Pin;

use tokio::task::JoinHandle;

use crate::config::ZondConfig;
use std::net::IpAddr;

use crate::model::ip::range::{Ipv4Range, Ipv6Range};
use crate::model::ip::scoped::Zone;
use crate::model::{ip::set::IpSet, target::TargetMap, target::TargetSet};
use crate::scanner::orchestrator::{
    Enrichment, ScanCapabilities, build_port_scanner, finish_enrichment, run_port_scan, target_ips,
};
use crate::scanner::report::{PhaseRecorder, ScanKind, ScanReport, TargetScope};
use crate::scanner::session::{ScanContext, ScanSession, ScannerKind};
use strategy::local::Scope;

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
// records about its own run, `resolver` is the hostname tail, `service` is the
// second pass that identifies what is behind an open port, and `pool` and
// `payload` are shared probe machinery.
pub mod audit;
pub mod dispatcher;
pub mod payload;
pub mod pool;
pub mod resolver;
pub mod service;

// How the two entry points below assemble and run a scan: what this host can
// do, which strategies to spawn, how to back the plan's intent with the sockets
// that actually opened, and how to wait for the hostname tail.
//
// Private, because it is one implementation of this engine's own policy rather
// than something a consumer composes with. A caller who wants a different
// policy does not reach in here; they build a `plan`, edit it, and run the
// steps they want.
mod orchestrator;

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

    let scope = TargetScope::from_ip_set(&mut targets);
    let recorder = PhaseRecorder::start(ScanKind::Discovery, caps.privileged, scope, cfg);

    let reach = if cfg.segment_sweep {
        Scope::Sweep
    } else {
        Scope::Targeted
    };
    let cfg = cfg.clone();

    let handle = tokio::spawn(async move {
        run_discovery(targets, reach, caps, &cfg, &ctx).await;
        recorder.finish(&ctx)
    });

    Ok((session, ScanTask::new(handle)))
}

/// Runs one discovery pass over `targets`, to completion, against an existing
/// context.
///
/// The body of [`discover`], and also the liveness phase [`scan`] runs before it
/// probes a port — so "a port scan establishes presence the way a sweep does" is
/// one piece of code rather than a promise two of them have to keep.
///
/// `reach` is what separates the two callers that matter: a sweep may go beyond
/// the addresses it was given, and a port scan's liveness check never does.
async fn run_discovery(
    targets: IpSet,
    reach: Scope,
    caps: ScanCapabilities,
    cfg: &ZondConfig,
    ctx: &ScanContext,
) {
    if caps.privileged {
        let plan = plan::DiscoveryPlan::build(targets, reach);
        let enrichment = Enrichment::spawn(plan, ctx, caps, cfg.probe_tuning()).await;
        finish_enrichment(Some(enrichment), caps, ctx).await;
    } else {
        let targets = orchestrator::walkable(targets, ctx);
        if let Err(error) = strategy::connect::discover(targets, ctx.clone()).await {
            ctx.record_failure(ScannerKind::Connect, error.to_string());
        }
        finish_enrichment(None, caps, ctx).await;
    }

    orchestrator::run_passive_os_identification(ctx, cfg.os_detection);
}

/// Probes a known set of targets for open ports.
///
/// Two phases, and the first is what stops the second being wasted. Every
/// address given is probed for liveness exactly as [`discover`] would probe it —
/// ARP on the local segment, ICMP and TCP off it, connect attempts without root
/// — and only the addresses that answered are port-scanned. An address nothing
/// lives at costs a handful of probes rather than one per port.
///
/// **The liveness phase probes the addresses it was given and nothing else.** It
/// is a [`Scope::Targeted`] pass, never a segment sweep: scanning one host does
/// not wake its neighbours, and `cfg.segment_sweep` is not consulted here.
///
/// [`ZondConfig::assume_up`] skips the phase and scans every target on trust,
/// which is what a host behind a firewall that answers no knock needs.
///
/// The returned [`ScanReport`] carries a phase for each: the liveness pass is
/// recorded as [`ScanKind::Discovery`] and the ports as
/// [`ScanKind::PortScan`], so a reader can tell how much of the run was spent
/// establishing that anything was there.
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
    let cfg = cfg.clone();

    let handle = tokio::spawn(async move {
        // Phase one: which of these addresses is anything actually at.
        let (liveness, target_map) = if cfg.assume_up {
            (None, target_map)
        } else {
            let mut ips = target_ips(&target_map);
            let scope = TargetScope::from_ip_set(&mut ips);
            let recorder = PhaseRecorder::start(ScanKind::Discovery, caps.privileged, scope, &cfg);

            // Targeted, never a sweep: `segment_sweep` says a caller asked about
            // a network, and nobody asks `zond scan` about a network.
            run_discovery(ips, Scope::Targeted, caps, &cfg, &ctx).await;

            let report = recorder.finish(&ctx);
            let live = only_live(&target_map, &ctx);
            (Some(report), live)
        };

        // Phase two: the ports, on whatever answered.
        let scope = TargetScope::from_target_map(&target_map);
        let recorder = PhaseRecorder::start(ScanKind::PortScan, caps.privileged, scope, &cfg);

        run_port_phase(target_map, &ctx, caps, &cfg).await;

        orchestrator::run_active_os_probe(&ctx, cfg.os_detection, cfg.probe_tuning()).await;
        let report = recorder.finish(&ctx);

        match liveness {
            Some(mut first) => {
                first.merge(report);
                first
            }
            None => report,
        }
    });

    Ok((session, ScanTask::new(handle)))
}

/// Probes `target_map`'s ports, enriching the hosts as it goes.
///
/// Nothing is opened for an empty map. A liveness phase that found nothing is a
/// finished answer, and raw sockets held to probe no targets are a failure this
/// would report for no reason.
async fn run_port_phase(
    target_map: TargetMap,
    ctx: &ScanContext,
    caps: ScanCapabilities,
    cfg: &ZondConfig,
) {
    if target_map.is_empty() {
        return;
    }

    let target_count = target_map.gross_targets().unwrap_or(0) as usize;
    let built = build_port_scanner(
        plan::PortScanPlan::build(cfg, caps.privileged),
        ctx,
        target_count,
        cfg.probe_tuning(),
    );

    // Only when nothing has enriched these hosts already. With the liveness
    // phase on, it has: the pass that established they are there is the same one
    // that reads their hardware addresses and names.
    let enrichment = if cfg.assume_up && built.opened_raw() {
        let plan = plan::DiscoveryPlan::build(target_ips(&target_map), Scope::Targeted);
        Some(Enrichment::spawn(plan, ctx, caps, cfg.probe_tuning()).await)
    } else {
        None
    };

    let dispatcher = dispatcher::Dispatcher::new(target_map);
    let rx = dispatcher.run_shuffled(&ctx.handle);

    run_port_scan(built.scanner, rx, ctx).await;
    finish_enrichment(enrichment, caps, ctx).await;
    // Passive first, then active: the echo probe is aimed at the hosts the
    // passive sources could not name, and it can only know which those are once
    // they have run.
    orchestrator::run_passive_os_identification(ctx, cfg.os_detection);
}

/// The targets phase one found something at, each unit keeping its own ports.
///
/// Narrows every unit rather than rebuilding one set against one port list,
/// because a unit may carry ports no other one does — `10.0.0.1:8080` names its
/// own, and a gate that dropped that would answer a different question.
///
/// A host is kept if *any* address it answers at was targeted, not only the one
/// it ended up filed under. A dual-stack machine found over IPv6 is still the
/// machine whose IPv4 address was asked about.
fn only_live(target_map: &TargetMap, ctx: &ScanContext) -> TargetMap {
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

    let mut kept = TargetMap::new();
    for unit in &target_map.units {
        let mut ips = IpSet::new();
        for ip in live.iter() {
            if unit.ips().contains(&ip) {
                push_single(&mut ips, ip, None);
            }
        }
        ips.canonicalize();

        if !ips.is_empty() {
            kept.add_unit(TargetSet::new(ips, unit.ports().clone()));
        }
    }

    kept
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
    use super::*;
    use crate::model::host::{Host, HostStatus};
    use crate::model::port::PortSet;

    /// A context whose store already holds `hosts`, as a finished liveness phase
    /// would have left it.
    fn store_holding(hosts: Vec<Host>) -> (ScanSession, ScanContext) {
        let (session, ctx) = ScanSession::new();
        for host in hosts {
            ctx.store.insert(host.primary_ip(), host);
        }
        (session, ctx)
    }

    fn host_at(ip: &str, status: HostStatus) -> Host {
        let mut host = Host::new(ip.parse().expect("an address"));
        host.set_status(status);
        host
    }

    fn unit(ip: &str, ports: &str) -> TargetSet {
        let mut ips = IpSet::new();
        ips.insert(ip.parse().expect("an address"));
        TargetSet::new(ips, PortSet::try_from(ports).expect("a port spec"))
    }

    fn map_of(units: Vec<TargetSet>) -> TargetMap {
        let mut map = TargetMap::new();
        for unit in units {
            map.add_unit(unit);
        }
        map
    }

    /// The gate's whole job. A host the store holds but that never answered is
    /// not a host to spend a probe per port on.
    ///
    /// Worth testing here rather than against a real address: a target nothing
    /// answers for usually leaves *no* store entry at all, so the filter is only
    /// reached by a host that was recorded and still is not alive.
    #[test]
    fn a_host_that_did_not_answer_is_dropped() {
        for status in [HostStatus::Down, HostStatus::Unknown] {
            let (_session, ctx) = store_holding(vec![host_at("10.0.0.1", status)]);
            let kept = only_live(&map_of(vec![unit("10.0.0.1", "22")]), &ctx);

            assert!(kept.is_empty(), "{status:?} was treated as alive");
        }
    }

    #[test]
    fn a_host_that_answered_is_kept() {
        let (_session, ctx) = store_holding(vec![host_at("10.0.0.1", HostStatus::Up)]);
        let kept = only_live(&map_of(vec![unit("10.0.0.1", "22")]), &ctx);

        assert_eq!(kept.gross_ips().expect("countable"), 1);
        assert_eq!(kept.gross_targets().expect("countable"), 1);
    }

    /// A dual-stack machine is one host filed under one address. If it answered
    /// over IPv6, the IPv4 address somebody actually typed still has to survive
    /// the gate — it is the same machine, and it is the one that was asked about.
    #[test]
    fn a_host_filed_under_another_address_keeps_the_one_that_was_targeted() {
        let mut host = host_at("2001:db8::1", HostStatus::Up);
        host.add_ip("10.0.0.1".parse().expect("an address"));

        let (_session, ctx) = store_holding(vec![host]);
        let kept = only_live(&map_of(vec![unit("10.0.0.1", "22")]), &ctx);

        assert!(
            !kept.is_empty(),
            "the targeted address was dropped because the host was filed elsewhere"
        );
    }

    /// A target may name its own ports, so the gate narrows each unit rather
    /// than rebuilding one set against one port list.
    #[test]
    fn each_unit_keeps_the_ports_it_was_given() {
        let (_session, ctx) = store_holding(vec![host_at("10.0.0.1", HostStatus::Up)]);
        let kept = only_live(
            &map_of(vec![unit("10.0.0.1", "8080"), unit("10.0.0.1", "22,443")]),
            &ctx,
        );

        let ports: Vec<usize> = kept.units.iter().map(|unit| unit.ports().len()).collect();
        assert_eq!(ports, vec![1, 2], "a unit lost or gained ports at the gate");
    }

    /// A host the liveness phase turned up but nobody asked about is not a host
    /// to scan. The store can gain entries the target list never named — a
    /// neighbour that answered, a name heard over mDNS — and port-scanning one
    /// of those would put probes on a machine the user did not name.
    #[test]
    fn a_live_host_nobody_asked_about_is_not_scanned() {
        let (_session, ctx) = store_holding(vec![
            host_at("10.0.0.1", HostStatus::Up),
            host_at("10.0.0.2", HostStatus::Up),
        ]);

        let kept = only_live(&map_of(vec![unit("10.0.0.1", "22")]), &ctx);

        assert_eq!(
            kept.gross_ips().expect("countable"),
            1,
            "an address nobody named was added to the scan"
        );
        let named = |ip: &str| {
            let wanted: IpAddr = ip.parse().expect("an address");
            kept.units.iter().any(|unit| unit.ips().contains(&wanted))
        };
        assert!(named("10.0.0.1"));
        assert!(
            !named("10.0.0.2"),
            "an address nobody named survived the gate"
        );
    }

    /// Nothing answered, so there is nothing to scan — and an empty map is what
    /// stops the port phase opening sockets it has no targets for.
    #[test]
    fn an_empty_store_keeps_nothing() {
        let (_session, ctx) = store_holding(Vec::new());
        let kept = only_live(&map_of(vec![unit("10.0.0.1", "22")]), &ctx);

        assert!(kept.is_empty());
    }
}
