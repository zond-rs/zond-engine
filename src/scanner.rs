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
use crate::model::{ip::set::IpSet, target::TargetMap};
use crate::scanner::orchestrator::{
    Enrichment, ScanCapabilities, build_port_scanner, finish_enrichment, run_port_scan, target_ips,
};
use crate::scanner::report::{PhaseRecorder, ScanKind, ScanReport, TargetScope};
use crate::scanner::session::{ScanSession, ScannerKind};
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

    if !caps.privileged {
        let targets = orchestrator::walkable(targets, &ctx);
        let handle = tokio::spawn(async move {
            if let Err(e) = strategy::connect::discover(targets, ctx.clone()).await {
                ctx.record_failure(ScannerKind::Connect, e.to_string());
            }
            finish_enrichment(None, caps, &ctx).await;
            recorder.finish(&ctx)
        });
        return Ok((session, ScanTask::new(handle)));
    }

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

    let scope = TargetScope::from_target_map(&target_map);
    let recorder = PhaseRecorder::start(ScanKind::PortScan, caps.privileged, scope, cfg);

    let built = build_port_scanner(
        plan::PortScanPlan::build(cfg, caps.privileged),
        &ctx,
        target_count,
        cfg.probe_tuning(),
    );

    let enrichment = if built.opened_raw() {
        let plan = plan::DiscoveryPlan::build(ips, Scope::Targeted);
        Some(Enrichment::spawn(plan, &ctx, caps, cfg.probe_tuning()).await)
    } else {
        None
    };
    let scanner = built.scanner;

    let (os_detection, probe_tuning) = (cfg.os_detection, cfg.probe_tuning());

    let handle = tokio::spawn(async move {
        let dispatcher = dispatcher::Dispatcher::new(target_map);
        let rx = dispatcher.run_shuffled(&ctx.handle);

        run_port_scan(scanner, rx, &ctx).await;
        finish_enrichment(enrichment, caps, &ctx).await;
        orchestrator::run_active_os_probe(&ctx, os_detection, probe_tuning).await;
        recorder.finish(&ctx)
    });

    Ok((session, ScanTask::new(handle)))
}
