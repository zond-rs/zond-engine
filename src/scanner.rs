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
//! [`discover`] finds which hosts in a target range are alive, and [`scan`]
//! takes a set of targets, usually ones [`discover`] already confirmed, and
//! reports which of their ports are open. Keeping the two apart lets a caller
//! run a cheap sweep first and spend the expensive port-scanning work only on
//! hosts known to exist.
//!
//! # Three altitudes, and how to choose
//!
//! This module works at three levels of detail. They are the same code: each
//! level is written in terms of the one below it, so moving down means taking
//! over more of the decisions, never reimplementing anything.
//!
//! Call [`discover`] or [`scan`]. Targets and a [`ZondConfig`] in, a live
//! [`ScanSession`] and a [`ScanReport`] out. Privilege, interfaces, fallbacks,
//! retries and hostname resolution are all decided by the engine. This is the right
//! altitude for anything wrapping the engine, and where most callers should
//! stay. [`scan_with_journal`] is the same scan writing down how far it got, so
//! that a run cut short can be continued, and [`discover_with_journal`] is the
//! same for a sweep. Either can be read back afterwards as the report it
//! produced, with [`store::report`](crate::journal::store::report).
//!
//! Build a [`plan`], edit it, run it. A
//! [`DiscoveryPlan`](plan::DiscoveryPlan) is the set of strategies a scan
//! intends to run, worked out from the targets and this host's configuration,
//! with nothing opened and nothing sent. Printing it instead of running it is a
//! dry run, and the steps for three links out of five can be dropped and the
//! rest run.
//! Its [refusals](plan::RefusedStep) say what a scan will not cover before it
//! starts.
//!
//! Build one strategy and drive it yourself. Everything in [`strategy`] is
//! ordinary public API: open a [`ScanSession`], construct a
//! [`LocalScanner`](strategy::local::LocalScanner) aimed at one segment or a
//! [`TcpPortScanner`](strategy::ports::TcpPortScanner) over a transport opened
//! by the caller, run it, and read the store. None of it needs a cargo feature.
//!
//! A scan driven this way produces the same record as one the engine ran.
//! [`recorder::PhaseRecorder`] takes the scope and settings before the strategies
//! start and closes into a [`ScanReport`] when they finish, so a
//! self-orchestrated scan reaches the exporters on the same terms [`discover`]
//! and [`scan`] do. Until then, what a strategy has filed is readable through
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
//! let plan = DiscoveryPlan::build(
//!     to_set(&["192.0.2.0/24"], None, None)?,
//!     Scope::Sweep,
//!     &cfg.exclusions,
//!     &cfg.send_source,
//! );
//!
//! // What the sweep would do, before it does any of it.
//! for step in plan.steps() {
//!     println!("{:?}: {} address(es)", step.kind(), step.target_count());
//! }
//! for refusal in plan.refusals() {
//!     println!("not covered: {}", refusal.reason);
//! }
//!
//! // And to run it, a context is what a strategy is built with.
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
//! gives each group a suitable strategy:
//! [`LocalScanner`](strategy::local::LocalScanner) with ARP and ICMPv6 for hosts
//! on the same physical segment, and
//! [`RoutedScanner`](strategy::routed::RoutedScanner) with TCP SYN for anything
//! behind a gateway. [`scan`] follows the same pattern for ports, where a
//! privileged caller gets [`TcpPortScanner`](strategy::ports::TcpPortScanner)
//! and each port is classified from a single raw exchange rather than a
//! completed handshake. Targets that map to no usable interface, and every
//! target when unprivileged, fall back to plain TCP connect attempts.
//!
//! All of those implement [`HostScanner`](strategy::HostScanner) or
//! [`PortScanner`](strategy::PortScanner), which is what lets unrelated
//! strategies be driven through one loop. Discovered hosts land in a shared,
//! thread-safe store as they are found, and each update fires an event, so a
//! caller can watch a scan in progress instead of waiting for it to finish. When
//! DNS resolution is enabled, the [`rdns`] module looks up hostnames in the
//! background without blocking discovery.

use std::pin::Pin;

use tokio::task::JoinHandle;

use crate::config::ZondConfig;
use crate::detect::Detections;
use crate::journal::cursor::Checkpoint;
use crate::model::{
    ip::set::{IpSet, Positions},
    target::{TargetIndex, TargetMap},
};
#[cfg(feature = "journal-format")]
use crate::report::ScanPhase;
use crate::report::ScannerKind;
use crate::report::{ScanKind, ScanReport, TargetScope};
use crate::scanner::orchestrator::{
    Enrichment, ScanCapabilities, finish_enrichment, live_addresses, probed_subset, run_port_phase,
};
use crate::scanner::recorder::PhaseRecorder;
use crate::scanner::session::{ScanContext, ScanSession, Stage};
use crate::system::interface;
use crate::system::privilege::Privilege;
use strategy::local::Scope;

// What running a scan produces: a `ScanSession` to watch it, a `ScanHandle` to
// stop it, and a `ScanReport` once it is over.
pub mod handle;
pub mod recorder;
pub mod session;

// The strategies, and the traits that make them interchangeable. Public
// unconditionally: driving one scanner yourself is a supported way to use the
// engine, not a test hatch.
pub mod pacing;
pub mod plan;
pub mod strategy;

// What a strategy needs, and what reads its output. `dispatcher` feeds targets
// to a `PortScanner`, `audit` records how a run went, `rdns` is the hostname
// tail, `service` identifies what is behind an open port, and `pool` and
// `payload` are shared probe machinery.
pub mod audit;
/// The timer that writes a running scan into its journal, and the handle that
/// stops it. Behind `journal-format` because that is what compiles a
/// [`Journal`](crate::journal::Journal) to write into.
#[cfg(feature = "journal-format")]
pub mod checkpoint;
pub mod detection;
pub mod dispatcher;
pub mod order;
pub mod payload;
pub mod pool;
pub mod rdns;
pub mod service;

// How the entry points below assemble a scan. Private, because it is one
// implementation of this engine's policy: a caller who wants a different one
// builds a `plan` and runs the steps they want. `vantage` is the part of that
// policy that sends nothing: what this machine's own interfaces and routes say
// about the hosts the scan found.
mod orchestrator;
mod vantage;

/// An error returned when a scan fails to run to completion.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// The scan task did not run to completion.
    ///
    /// Reached on a panic inside the engine or on the runtime shutting down
    /// under it. Not on a stop:
    /// [`ScanHandle::abort`](crate::scanner::handle::ScanHandle::abort) winds the
    /// scan down and still yields its report.
    ///
    /// The two are told apart, and a panic carries what it said, because this
    /// happened in the caller's process and "terminated abnormally" leaves them
    /// nothing to report upstream.
    #[error("the scan task {}: {detail}", if *.panicked { "panicked" } else { "was cancelled" })]
    TaskFailed {
        /// Whether the task panicked, as against being cancelled by the runtime.
        panicked: bool,
        /// What the panic said, or why the task was cancelled.
        detail: String,
    },

    /// The journal handed to a scan records the engine's other phase.
    ///
    /// A sweep counts addresses and a port scan counts address-and-port pairs,
    /// so one continued as the other would skip targets nothing ever probed.
    #[error("this journal records the other phase of a scan")]
    WrongPhase,

    /// This run's settings would not produce the plan the journal is counted in.
    #[cfg(feature = "journal-format")]
    #[error("{0}")]
    PlanChanged(#[from] crate::journal::manifest::PlanChanged),

    /// The evasion profile is not one a scan could put on the wire.
    ///
    /// Checked before a probe leaves rather than on each one, because every
    /// probe refusing is a scan that sends nothing and reports a network with
    /// nothing on it. See [`EvasionProfile::validate`](crate::EvasionProfile::validate)
    /// for what that check covers and what it does not.
    #[error("{0}")]
    Evasion(#[from] crate::evasion::EvasionError),
}

/// Refuses a scan whose exclusion policy is not the one its journal was counted
/// under.
///
/// The policy decides the enumeration: withhold the first half of a range and
/// every position after it names a different target. A journal's plan already
/// has the policy applied, so applying this run's policy to it and finding it
/// unchanged is the whole test: one that withholds nothing further leaves the
/// same plan, and so the same fingerprint.
///
/// A policy that withholds *less* passes, and is meant to: the recorded plan is
/// what is being continued, and widening the scope is a new scan rather than a
/// continuation of this one.
///
/// Privilege and technique come from the manifest rather than from this run, so
/// what is being tested here is the policy alone.
/// [`Journal::resume`](crate::journal::Journal::resume) has already refused a
/// mismatch in either of those.
#[cfg(feature = "journal-format")]
fn under_the_recorded_policy(
    journal: &crate::journal::Journal,
    cfg: &ZondConfig,
) -> Result<(), ScanError> {
    use crate::journal::manifest::Plan;

    let manifest = journal.manifest();
    let recorded = manifest.recorded();

    let this_run = if let Some(addresses) = recorded.addresses() {
        Plan::discovery(addresses, &cfg.exclusions, recorded.sweeps_the_segment())
    } else if let Some(targets) = recorded.targets() {
        Plan::port_scan(
            targets,
            &cfg.exclusions,
            recorded.technique().unwrap_or_default(),
        )
    } else {
        return Ok(());
    };

    manifest.covers(&this_run, manifest.privilege)?;
    Ok(())
}

/// What a `JoinError` was, in a form a consumer can act on.
///
/// `tokio` hands back the panic payload as `Box<dyn Any>`, which is where a
/// message goes to be lost. The two shapes a `panic!` produces are read out and
/// anything else is named as such rather than dropped.
fn panic_or_cancellation(error: tokio::task::JoinError) -> ScanError {
    if !error.is_panic() {
        return ScanError::TaskFailed {
            panicked: false,
            detail: "the runtime shut down before the scan finished".to_string(),
        };
    }

    let payload = error.into_panic();
    let detail = payload
        .downcast_ref::<&'static str>()
        .map(|message| (*message).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic carrying no message".to_string());

    ScanError::TaskFailed {
        panicked: true,
        detail,
    }
}

/// A handle to a running scan.
///
/// Discovered hosts arrive live through the paired [`ScanSession`]. Await this
/// handle, or call [`ScanTask::join`], to wait for the whole scan to finish and
/// receive the [`ScanReport`] describing it. To stop a scan early, call
/// [`ScanHandle::abort`](crate::scanner::handle::ScanHandle::abort) on the
/// session's handle; the report still arrives, describing however far the scan
/// got.
///
/// A scan given
/// [`ZondConfig::scan_timeout`](crate::config::ZondConfig::scan_timeout) stops
/// itself the same way when its budget runs out, which is what lets this be
/// awaited by something nobody is watching.
pub struct ScanTask {
    handle: JoinHandle<ScanReport>,
    /// The journal this scan writes to, closed once the scan ends.
    ///
    /// A journal has to write its last checkpoint and release its lock when the
    /// scan is over, and this is the type that knows when that is. Dropping the
    /// task without joining still closes the journal, though the last few
    /// settlements may go unrecorded.
    #[cfg(feature = "journal-format")]
    journal: Option<checkpoint::Checkpointing>,
    /// What earlier sittings of this job did, restored from the journal.
    ///
    /// Folded in front of this run's own phases when the task is joined, so the
    /// report describes the job rather than the last sitting of it.
    #[cfg(feature = "journal-format")]
    earlier: Vec<ScanPhase>,
}

impl ScanTask {
    fn new(handle: JoinHandle<ScanReport>) -> Self {
        Self {
            handle,
            #[cfg(feature = "journal-format")]
            journal: None,
            #[cfg(feature = "journal-format")]
            earlier: Vec::new(),
        }
    }

    /// A task that closes `journal` once the scan it describes has finished.
    #[cfg(feature = "journal-format")]
    fn journalling(
        handle: JoinHandle<ScanReport>,
        journal: checkpoint::Checkpointing,
        earlier: Vec<ScanPhase>,
    ) -> Self {
        Self {
            handle,
            journal: Some(journal),
            earlier,
        }
    }

    /// Waits for the scan to finish and returns its report.
    ///
    /// An error here means the scan never ran to completion at all. A strategy
    /// that failed part way through is not one: it is recorded in the report's
    /// [`failures`](ScanReport::failures) and announced on the [`ScanSession`]
    /// event stream, because whatever the surviving strategies found is still
    /// worth having.
    pub async fn join(self) -> Result<ScanReport, ScanError> {
        let report = self.handle.await.map_err(panic_or_cancellation);

        // After the scan, so the last checkpoint sees everything it settled, and
        // the phases recorded are this sitting's own. A scan that failed gets a
        // checkpoint too: how far it got is what a resume needs.
        #[cfg(feature = "journal-format")]
        if let Some(journal) = self.journal {
            let phases = report.as_ref().map(ScanReport::phases).unwrap_or_default();
            journal.finish(phases).await;
        }

        // Earlier sittings in front of this one, in the order they ran.
        #[cfg(feature = "journal-format")]
        if !self.earlier.is_empty() {
            return report.map(|report| {
                let mut whole = ScanReport::from_phases(self.earlier, []);
                whole.merge(report);
                whole
            });
        }

        report
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
/// This is the first phase of a scan. It establishes presence, not open ports.
///
/// With root privileges, targets are grouped by the interface that reaches them
/// and each group gets the strategy suited to it:
/// [`LocalScanner`](strategy::local::LocalScanner) uses ARP and ICMP for hosts
/// on the same physical segment, and
/// [`RoutedScanner`](strategy::routed::RoutedScanner) uses TCP SYN for anything
/// behind a gateway. Without root, and for any target that maps to no interface
/// such as a loopback address, probes fall back to plain TCP connect attempts
/// against a handful of common ports.
///
/// Hosts are written to the returned [`ScanSession`]'s store as they are found,
/// and each write fires a [`ScanEvent`](crate::scanner::session::ScanEvent), so
/// a caller can follow a scan in progress instead of waiting for the end. Unless
/// `cfg.no_dns` is set, hostnames are resolved in the background without slowing
/// discovery: by sniffing DNS and mDNS when privileged, and by reverse lookup
/// otherwise.
///
/// The returned [`ScanTask`] resolves once every strategy has finished, along
/// with the resolver if one was started, and yields the [`ScanReport`]. To stop
/// a scan early, call
/// [`ScanHandle::abort`](crate::scanner::handle::ScanHandle::abort) on the
/// session's handle; every phase checks that signal regularly, not only between
/// targets, and the same check is what ends a sweep that outlived
/// [`ZondConfig::scan_timeout`](crate::config::ZondConfig::scan_timeout).
pub async fn discover(
    targets: IpSet,
    cfg: &ZondConfig,
) -> Result<(ScanSession, ScanTask), ScanError> {
    cfg.evasion.validate()?;

    let planned = planned_addresses(&Positions::of(&targets));

    let (session, ctx) = ScanSession::builder()
        .excluding(cfg.exclusions.clone())
        .host_timeout(cfg.host_timeout)
        .scan_timeout(cfg.scan_timeout)
        .host_probe_interval(cfg.host_probe_interval)
        .send_source(cfg.send_source.clone())
        .planning(Stage::Discovery, planned)
        .staging(discovery_stages(cfg))
        // Drawn here and kept nowhere, since nothing is recording this sweep.
        // A caller who wants the order back is journalling, and that is what
        // writes the seed down.
        .ordering(Some(rand::random()))
        .build();
    let handle = spawn_discovery(targets, cfg, ctx);
    Ok((session, ScanTask::new(handle)))
}

/// [`discover`], writing down how far it got, so that a sweep cut short can be
/// continued rather than restarted.
///
/// Journalling is the caller's choice, never this crate's, on the same
/// terms as [`scan_with_journal`]: hand this a journal and the sweep is
/// recorded, call [`discover`] and nothing touches a disk.
///
/// # The numbering comes from the journal
///
/// A journal already holds the plan it is counted in, with the exclusion policy
/// applied: [`Plan`](crate::journal::manifest::Plan) applies it, and
/// [`Journal::resume`](crate::journal::Journal::resume) checks it has not moved.
/// The addresses an address settles against are read back from there, so
/// nothing this function is passed can disagree with what the first sitting
/// counted.
///
/// `targets` is what the *first* sitting sweeps, and it is the set as the caller
/// named it rather than as the plan narrowed it. The engine subtracts the
/// exclusions itself and records what that cost, which is the one number a
/// caller cannot recover afterwards; handing it a set already narrowed would
/// leave every report claiming the policy withheld nothing. A later sitting
/// ignores it and sweeps what the earlier ones did not settle, whose scope is
/// genuinely smaller and says so.
///
/// # What a sweep settles
///
/// An address, rather than an address-and-port pair. It is settled when it
/// answers, or when the probes aimed at it have been sent as many times as the
/// policy allows and none of them answered. An address whose probes never left,
/// one still mid-schedule when the sweep stopped, and one there was no route to
/// carry no position and are asked again. see
/// [`settle`](crate::journal::settle) for why that distinction is the whole of
/// the feature.
///
/// The findings and the phase are recorded alongside the progress, so a resumed
/// sweep starts from what earlier sittings found and its report describes the
/// whole job: one phase per sitting, each keeping its own timings, settings and
/// statistics.
#[cfg(feature = "journal-format")]
pub async fn discover_with_journal(
    targets: IpSet,
    cfg: &ZondConfig,
    journal: crate::journal::Journal,
) -> Result<(ScanSession, ScanTask), ScanError> {
    cfg.evasion.validate()?;

    let recorded = journal.manifest().recorded();
    let Some(addresses) = recorded.addresses() else {
        return Err(ScanError::WrongPhase);
    };
    under_the_recorded_policy(&journal, cfg)?;

    // Numbered over the whole plan, whichever part of it this sitting sweeps.
    // Numbering the remainder afresh would give position 0 to whatever happens
    // to still be there, and the two sittings would count different things.
    let positions = addresses.positions();
    let resume_point = journal.resume_point().clone();
    // The order the first sitting was going to sweep in. A later one continuing
    // in a fresh order would change the shape of the run halfway through, which
    // is a signature of its own.
    let order_seed = journal.manifest().order_seed;

    let sweep = if resume_point == Checkpoint::default() {
        targets
    } else {
        resume_point.remaining_addresses(&positions)
    };

    let planned = planned_addresses(&positions);

    let (session, ctx) = ScanSession::builder()
        .excluding(cfg.exclusions.clone())
        .host_timeout(cfg.host_timeout)
        .scan_timeout(cfg.scan_timeout)
        .host_probe_interval(cfg.host_probe_interval)
        .send_source(cfg.send_source.clone())
        .resuming(&resume_point)
        .counting(positions)
        .planning(Stage::Discovery, planned)
        .staging(discovery_stages(cfg))
        .ordering(order_seed)
        .build();

    ctx.restore_hosts(journal.restored());
    let earlier = journal.earlier_phases().to_vec();

    let ticker = checkpoint::spawn_checkpoints(journal, ctx.progress());
    let handle = spawn_discovery(sweep, cfg, ctx);

    Ok((session, ScanTask::journalling(handle, ticker, earlier)))
}

/// How many addresses a sweep plans to ask about, or `None` where they cannot
/// all be numbered.
///
/// The numbering is the same one a journal settles positions against, so a
/// fraction built from this counts what
/// [`Progress::settled`](crate::scanner::session::Progress::settled) counts. A
/// range too wide to number leaves the plan uncountable, and a scan of one
/// never finishes anyway.
fn planned_addresses(positions: &Positions) -> Option<u64> {
    positions.unnumbered().is_empty().then(|| positions.total())
}

/// The stages a sweep under `cfg` expects to run, in the order it runs them.
fn discovery_stages(cfg: &ZondConfig) -> Vec<Stage> {
    let mut stages = vec![Stage::Discovery];

    if cfg.os_detection.is_active() {
        stages.push(Stage::Os);
    }
    if cfg.traceroute {
        stages.push(Stage::Traceroute);
    }

    stages
}

/// The stages a port scan under `cfg` expects to run, in the order it runs them.
///
/// A superset, and deliberately so. Whether service detection, the detection
/// corpus and the TLS pass find anything to do depends on which ports turn out
/// to be open, which is not knowable here, so each is listed whenever the
/// settings permit it at all and stepped over if it comes to nothing.
///
/// [`Stage::Finishing`] is left out. It sends nothing and is over as soon as it
/// begins, so a run that reached it has done all the work there was to measure.
fn scan_stages(cfg: &ZondConfig) -> Vec<Stage> {
    let mut stages = Vec::new();

    if !cfg.assume_up {
        stages.push(Stage::Discovery);
    }
    stages.push(Stage::Ports);

    if cfg.service_detection.connects() {
        stages.push(Stage::Services);
    }
    if cfg.service_detection != crate::config::ServiceDetection::Off
        && cfg.detection.ceiling().is_some()
    {
        stages.push(Stage::Detections);
    }
    if cfg.tls_enumeration {
        stages.push(Stage::Tls);
    }
    if cfg.os_detection.is_active() {
        stages.push(Stage::Os);
    }
    if cfg.traceroute {
        stages.push(Stage::Traceroute);
    }

    stages
}

/// How many address-and-port pairs a port scan plans to probe, or `None` where
/// they cannot all be numbered.
///
/// [`TargetIndex`] stops numbering at the first unit it cannot count whole, so
/// its total is the plan's only where it says the numbering is complete.
fn planned_targets(map: &TargetMap) -> Option<u64> {
    let index = TargetIndex::of(map);
    index.is_complete().then(|| index.total())
}

/// Runs a discovery sweep against an existing context.
///
/// The body of [`discover`], taking a context rather than making one so that a
/// caller journalling the sweep can seed it and keep a handle on it. Nothing
/// here knows what a journal is.
fn spawn_discovery(
    mut targets: IpSet,
    cfg: &ZondConfig,
    ctx: ScanContext,
) -> JoinHandle<ScanReport> {
    let caps = ScanCapabilities::resolve(cfg);

    // Narrows `targets` as it records them, so nothing below can probe an
    // excluded address. Addresses a sweep finds for itself never pass through
    // here, and are gated on the context instead.
    let scope = TargetScope::from_ip_set(&mut targets, &cfg.exclusions);
    let recorder = PhaseRecorder::start(ScanKind::Discovery, caps.privilege, scope, cfg);

    let reach = if cfg.segment_sweep {
        Scope::Sweep
    } else {
        Scope::Targeted
    };
    let cfg = cfg.clone();

    tokio::spawn(async move {
        ctx.enter_stage(Stage::Discovery, None);
        // No SCTP sweep: `discover` is asked about addresses and never about
        // ports, so nothing has said which SCTP port would be worth asking.
        run_discovery(targets, reach, caps, &cfg, &ctx, None).await;
        // Only the echo probe. The series probe reads a port whose state is
        // already known, and a sweep establishes none.
        orchestrator::run_active_os_probe(&ctx, cfg.os_detection, cfg.probe_tuning(), caps).await;
        // A sweep knows no ports, so every trace here is made of echoes. A port
        // scan traces better, having somewhere to aim.
        orchestrator::run_traceroute(&ctx, &cfg, caps).await;
        ctx.enter_stage(Stage::Finishing, None);
        orchestrator::run_characterise(&ctx, &cfg, caps).await;
        orchestrator::run_ip_protocols(&ctx, &cfg).await;
        // Last, and after every strategy that could add an address: what this
        // machine's own interfaces and routes say about what was found.
        vantage::attribute(&ctx);
        orchestrator::run_correlation(&ctx, cfg.service_detection);
        recorder.finish(&ctx)
    })
}

/// Runs one discovery pass over `targets` to completion, against an existing
/// context.
///
/// Shared by [`discover`] and by the liveness phase of [`scan`], so that both
/// establish presence the same way rather than each keeping the same promise
/// separately.
///
/// `reach` is the difference between the two: a sweep may go beyond the
/// addresses it was given, and a port scan's liveness check never does.
///
/// `sctp_port` adds an INIT sweep beside the SYN one, for a port scan whose
/// ports name SCTP. `None` for a run that never mentioned it, which is every
/// other one: an SCTP sweep costs a second raw socket and a second capture, and
/// asks a question nobody put.
///
/// A raw sweep still reaches some targets by connect: loopback and anything
/// nothing routes to, whatever the privilege, and when frames are all it has,
/// whatever a frame cannot reach. The phase records which, since its privilege
/// reads as raw and the evidence at those addresses is not.
async fn run_discovery(
    targets: IpSet,
    reach: Scope,
    caps: ScanCapabilities,
    cfg: &ZondConfig,
    ctx: &ScanContext,
    sctp_port: Option<u16>,
) {
    if caps.privilege.is_raw() {
        let unframed =
            caps.beyond_frames(&targets, &cfg.send_source, interface::FrameSender::Sweep);
        let mut plan =
            plan::DiscoveryPlan::build(targets, reach, &cfg.exclusions, &cfg.send_source);
        plan.connect_instead(&unframed.targets);
        if let Some(port) = sctp_port {
            plan.also_over_sctp(port);
        }
        for step in plan.steps() {
            if let plan::DiscoveryStep::Connect { targets } = step {
                ctx.record_reached_by_connect(targets);
            }
        }
        let enrichment = Enrichment::spawn(plan, ctx, caps, cfg.probe_tuning()).await;
        finish_enrichment(Some(enrichment), caps, ctx).await;
    } else {
        let targets = orchestrator::walkable(targets, ctx);
        if let Err(error) = strategy::connect::discover(targets, ctx.clone(), &cfg.evasion).await {
            ctx.record_failure(ScannerKind::Connect, error.to_string());
        }
        finish_enrichment(None, caps, ctx).await;
    }

    orchestrator::run_passive_os_identification(ctx, cfg.os_detection);
}

/// What a listening phase reads, and for how long.
///
/// A listener is aimed at a **link**, not at addresses, which is the whole of
/// what makes it a different phase. It cannot narrow what it hears, so the only
/// control there is sits at the other end: what may be recorded.
///
/// Nothing here reaches into the host on its own. A caller who wants every
/// link says which links those are; see [`system::interface`](crate::system::interface)
/// for how to find them. That is the same rule that keeps the engine from
/// opening a journal nobody asked for.
#[must_use]
#[derive(Debug, Clone)]
pub struct ListenScope {
    links: Vec<crate::model::ip::scoped::Zone>,
    recording: strategy::passive::Recording,
    until: Until,
}

/// When a listening phase stops.
///
/// A scan ends when it has asked everything it meant to ask. A listener has
/// asked nothing and can never be finished, so somebody else decides, which is
/// why this is a required part of the scope rather than a setting with a
/// default.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Until {
    /// It runs until the caller stops it through
    /// [`ScanHandle::abort`](crate::scanner::handle::ScanHandle::abort).
    ///
    /// The honest default for a sensor, and the shape an embedded consumer
    /// wants: a listener is a service rather than a job.
    #[default]
    Stopped,
    /// It runs for this long and then closes.
    ///
    /// For a caller who wants a bounded sample, an inventory of what a segment
    /// says over ten minutes, without having to hold the handle and time it.
    Elapsed(std::time::Duration),
}

impl ListenScope {
    /// Listens on `links` until stopped, recording the machines attached to
    /// them.
    ///
    /// The default narrowing is deliberate and is the difference between an
    /// inventory and a transcript. A link carrying traffic to anywhere else
    /// carries evidence about everywhere else: on a mirror port, every server a
    /// laptop opens a connection to is a real host, really up, with a really
    /// open port, and on a busy uplink that is most of what an unnarrowed
    /// report would contain. [`recording_everything`](Self::recording_everything)
    /// is how a caller asks for it anyway.
    pub fn on(links: Vec<crate::model::ip::scoped::Zone>) -> Self {
        Self {
            links,
            recording: strategy::passive::Recording::Attached,
            until: Until::Stopped,
        }
    }

    /// Records every machine heard, wherever it lives.
    ///
    /// For the question a listener answers that a scan cannot: which machines
    /// elsewhere this network depends on, and what they answer. It is the wider
    /// reading of the same traffic rather than more of it: nothing extra is
    /// captured, and what changes is only what is allowed to reach the report.
    pub fn recording_everything(mut self) -> Self {
        self.recording = strategy::passive::Recording::Everything;
        self
    }

    /// Records findings only about `addresses`.
    ///
    /// Everything on the link is still *heard*, a listener cannot decline to
    /// receive, and anything outside this is dropped before it reaches the
    /// store. Which is where a passive phase's scope has to live: there is no
    /// asking to narrow.
    pub fn recording_only(mut self, addresses: IpSet) -> Self {
        self.recording = strategy::passive::Recording::Only(addresses);
        self
    }

    /// Stops after `span` rather than waiting to be told.
    pub fn for_at_most(mut self, span: std::time::Duration) -> Self {
        self.until = Until::Elapsed(span);
        self
    }

    /// The links this phase reads.
    pub fn links(&self) -> &[crate::model::ip::scoped::Zone] {
        &self.links
    }

    /// When it stops.
    pub fn until(&self) -> Until {
        self.until
    }
}

/// Reads what a link already carries, and concludes from it. Sends nothing.
///
/// The third phase, beside [`discover`] and [`scan`], and the only one that puts
/// no packet on the wire. It is for the networks the other two may not touch,
/// industrial and clinical segments where probing is forbidden, production under
/// change control, any engagement without an authorised scan window, and for
/// the findings no probe can obtain: which switch port this machine is on, which
/// VLANs a link carries, what a device says about itself while asking for an
/// address.
///
/// # What it may conclude
///
/// Only ever a positive claim. Having sent nothing it cannot time anything
/// out, so an address it never heard from may be absent, silent, behind a switch
/// that never forwarded this way, or on a VLAN this link does not carry, and
/// nothing separates those. It records a host as up and never as down, adds a
/// role and never removes one, and its phase covers **no address at all**, so a
/// [`diff`](crate::diff) cannot read a host that stayed quiet as one that went
/// away.
///
/// # What it will not see
///
/// On a switched network an unmirrored listener sees broadcast and multicast in
/// full and very little unicast: the switch forwards a conversation between two
/// other hosts out the one port that leads to it. That is enough for an asset
/// and topology inventory, ARP, DHCP, mDNS, router advertisements, LLDP and CDP
/// are all broadcast or multicast, and it is *not* enough for the endpoints and
/// flows, which need a mirror port, a tap, or a position traffic transits.
///
/// The report says how much was lost rather than leaving it to be guessed: a
/// wide filter on a busy link drops frames, and for this phase the drop count is
/// the closest thing there is to the address count the other two report.
///
/// # Stopping
///
/// [`Until::Stopped`] runs until
/// [`ScanHandle::abort`](crate::scanner::handle::ScanHandle::abort) is called on
/// the session's handle. The returned [`ScanTask`] resolves when it stops, with
/// the [`ScanReport`] describing what was heard.
///
/// [`ZondConfig::scan_timeout`](crate::config::ZondConfig::scan_timeout) bounds
/// a watch as it bounds a scan, and applies alongside whichever [`Until`] the
/// scope named: the watch ends at whichever comes first.
pub async fn listen(
    scope: ListenScope,
    cfg: &ZondConfig,
) -> Result<(ScanSession, ScanTask), ScanError> {
    let (session, ctx) = ScanSession::builder()
        .excluding(cfg.exclusions.clone())
        .host_timeout(cfg.host_timeout)
        .scan_timeout(cfg.scan_timeout)
        .host_probe_interval(cfg.host_probe_interval)
        .staging(vec![Stage::Listening])
        .build();
    let handle = spawn_listen(scope, cfg, ctx);
    Ok((session, ScanTask::new(handle)))
}

/// [`listen`], writing down what it hears, so that a watch cut short keeps what
/// it found.
///
/// Journalling is the caller's choice, never this crate's, on the same terms
/// as [`scan_with_journal`]: hand this a journal and the watch is recorded, call
/// [`listen`] and nothing touches a disk.
///
/// # Resuming a watch appends a sitting
///
/// This is the whole of how it differs from the other two, and it follows from
/// what a listener is. A sweep and a port scan enumerate: the journal's cursor,
/// watermark and total are arithmetic over that enumeration, and continuing one
/// means *skipping what is settled*. A listener enumerates nothing: it was
/// pointed at a link, the link carries what it carries, and there is no set of
/// things that could be finished.
///
/// So there is no cursor and nothing to skip. What resuming buys is the other
/// half of what a journal buys the other two: the findings of every earlier
/// sitting are restored before this one starts, and the report describes the
/// whole watch rather than its last few minutes. A listener left running for a
/// week across three restarts produces one record of the week.
///
/// [`Plan::listen`](crate::journal::manifest::Plan::listen) has the rest of the
/// argument, including why the links alone identify the job.
#[cfg(feature = "journal-format")]
pub async fn listen_with_journal(
    scope: ListenScope,
    cfg: &ZondConfig,
    journal: crate::journal::Journal,
) -> Result<(ScanSession, ScanTask), ScanError> {
    let recorded = journal.manifest().recorded();
    if recorded.kind() != ScanKind::Listen {
        return Err(ScanError::WrongPhase);
    }

    let (session, ctx) = ScanSession::builder()
        .excluding(cfg.exclusions.clone())
        .host_timeout(cfg.host_timeout)
        .scan_timeout(cfg.scan_timeout)
        .host_probe_interval(cfg.host_probe_interval)
        .staging(vec![Stage::Listening])
        .build();

    // Before the watch starts, so a caller reading the session sees every
    // earlier sitting's hosts immediately and the report describes the job.
    ctx.restore_hosts(journal.restored());
    let earlier = journal.earlier_phases().to_vec();

    let ticker = checkpoint::spawn_checkpoints(journal, ctx.progress());
    let handle = spawn_listen(scope, cfg, ctx);

    Ok((session, ScanTask::journalling(handle, ticker, earlier)))
}

/// Runs a listening phase against an existing context.
fn spawn_listen(scope: ListenScope, cfg: &ZondConfig, ctx: ScanContext) -> JoinHandle<ScanReport> {
    let cfg = cfg.clone();

    tokio::spawn(async move {
        // **Opened before the phase is opened, because opening it is the
        // question the phase's privilege field asks.** A listener holds what it
        // needs exactly when a capture came up, and that is not the same as
        // running as root: `pcap` reads a link for a user in the `access_bpf`
        // group on macOS and for a binary with `cap_net_raw` on Linux, both
        // being how anybody who is not root captures anything. Asking the
        // operating system for an effective uid instead would report those runs
        // as unprivileged while they listened perfectly well, and, worse, a
        // run that opened nothing as privileged.
        //
        // There is no fallback to record either way. Reading a link is the whole
        // capability here, where a scan can degrade to connect attempts.
        ctx.enter_stage(Stage::Listening, None);

        let opened =
            strategy::passive::PassiveListener::open(&scope.links, scope.recording, ctx.clone());

        // After the open, so the phase's clock covers the listening rather than
        // the setting up, and with the open's own answer in hand.
        let recorder = PhaseRecorder::start(
            ScanKind::Listen,
            // A listener that opened a capture held what it needed; one that
            // did not, did not. The same question the scan phases answer from
            // the process's own privileges, answered here from the open.
            Privilege::from_raw(opened.is_ok()),
            TargetScope::listening_on(scope.links.clone(), &cfg.exclusions),
            &cfg,
        );

        match opened {
            Ok(listener) => {
                let mut listener = listener.detecting_os(cfg.os_detection);
                if let Until::Elapsed(span) = scope.until {
                    // The watch ends on its own terms rather than by raising the
                    // abort signal. That signal means a *caller* asked, and a
                    // front end reads it to decide whether a run was cut short.
                    listener = listener.stopping_after(span);
                }

                if let Err(error) = listener.observe().await {
                    ctx.record_failure(ScannerKind::Passive, error.to_string());
                }
            }
            Err(error) => ctx.record_failure(ScannerKind::Passive, error.to_string()),
        }

        // What this machine's own interfaces say about what was heard. The same
        // pass a scan ends with, and it sends nothing either.
        vantage::attribute(&ctx);
        orchestrator::run_correlation(&ctx, cfg.service_detection);
        recorder.finish(&ctx)
    })
}

/// Probes a known set of targets for open ports.
///
/// Two phases, and the first keeps the second from being wasted. Every address
/// is probed for liveness exactly as [`discover`] would probe it, and only the
/// addresses that answer are port-scanned. An address with nothing at it costs a
/// handful of probes rather than one per port.
///
/// The liveness phase probes only the addresses it was given. It is a
/// [`Scope::Targeted`] pass, never a segment sweep, so scanning one host does
/// not wake its neighbours. `cfg.segment_sweep` is not consulted here.
///
/// [`ZondConfig::assume_up`] skips the phase and scans every target on trust,
/// which is what a host behind a firewall that answers no knock needs.
///
/// The [`ScanReport`] carries a phase for each: the liveness pass as
/// [`ScanKind::Discovery`] and the ports as [`ScanKind::PortScan`], so a reader
/// can tell how much of the run went on establishing that anything was there.
///
/// With root privileges, every probe is a raw TCP SYN sent from the source
/// address this host would route the target through, and
/// [`TcpPortScanner`](strategy::ports::TcpPortScanner) reads the port's state
/// from a single reply rather than a completed handshake. Without root, or with
/// no address to probe from, probes fall back to one TCP connect attempt per
/// target.
///
/// `detections` is the corpus the detection phase runs. Pass
/// [`Detections::embedded`](crate::detect::Detections::embedded) for the ones this
/// build ships, or a [`Detections::builder`](crate::detect::Detections::builder)
/// result to add your own. What each detection may do to the target is still the
/// [envelope](ZondConfig::detection)'s to decide; this is only which detections
/// exist. A [`Detections`] is cheap to clone, so one corpus serves many scans.
pub async fn scan(
    target_map: TargetMap,
    cfg: &ZondConfig,
    detections: Detections,
) -> Result<(ScanSession, ScanTask), ScanError> {
    cfg.evasion.validate()?;

    let planned = planned_targets(&target_map);

    let (session, ctx) = ScanSession::builder()
        .excluding(cfg.exclusions.clone())
        .host_timeout(cfg.host_timeout)
        .scan_timeout(cfg.scan_timeout)
        .host_probe_interval(cfg.host_probe_interval)
        .send_source(cfg.send_source.clone())
        .detections(detections)
        .planning(Stage::Ports, planned)
        .staging(scan_stages(cfg))
        // See `discover`: drawn here and kept nowhere, because nothing is
        // recording this scan.
        .ordering(Some(rand::random()))
        .build();
    let handle = spawn_scan(target_map, cfg, ctx, Checkpoint::default());
    Ok((session, ScanTask::new(handle)))
}

/// [`scan`], recording its progress so that an interrupted run can be continued.
///
/// Journalling is the caller's choice, never this crate's. The engine does
/// not touch a filesystem it was not pointed at; see
/// `import::settings`, which draws that boundary and explains it. A front end that wants every scan resumable opens a journal for
/// every scan, and that policy belongs to the front end.
///
/// A journal from [`Journal::resume`](crate::journal::Journal::resume) already
/// knows what an earlier run settled, and this scan skips it. The dispatcher
/// still walks the whole plan and keeps each target's original position,
/// emitting only what is left; renumbering the remainder would leave the two
/// runs counting different things.
///
/// Progress is checkpointed on a timer, and once more when the returned
/// [`ScanTask`] is joined, which is also when the journal's lock is released.
/// [`Checkpoint::write_atomically`](crate::journal::cursor::Checkpoint::write_atomically)
/// documents what that survives.
///
/// Findings and phases are recorded alongside the progress, so a resumed scan
/// starts from what earlier runs found and its report describes the whole job:
/// one phase per sitting, each keeping its own timings, settings and statistics,
/// rather than the last sitting presented as the whole of it.
///
/// `detections` is the corpus to run, exactly as [`scan`] takes it.
#[cfg(feature = "journal-format")]
pub async fn scan_with_journal(
    target_map: TargetMap,
    cfg: &ZondConfig,
    detections: Detections,
    journal: crate::journal::Journal,
) -> Result<(ScanSession, ScanTask), ScanError> {
    cfg.evasion.validate()?;
    under_the_recorded_policy(&journal, cfg)?;

    let (session, ctx) = ScanSession::builder()
        .excluding(cfg.exclusions.clone())
        .host_timeout(cfg.host_timeout)
        .scan_timeout(cfg.scan_timeout)
        .host_probe_interval(cfg.host_probe_interval)
        .send_source(cfg.send_source.clone())
        .resuming(journal.resume_point())
        .detections(detections)
        .planning(Stage::Ports, planned_targets(&target_map))
        .staging(scan_stages(cfg))
        // See `discover_with_journal`: the order is the job's rather than this
        // sitting's, so it comes back off the manifest.
        .ordering(journal.manifest().order_seed)
        .build();

    // Before the scan starts, so a caller watching the session sees the earlier
    // sittings' hosts immediately and the report describes the whole job.
    ctx.restore_hosts(journal.restored());

    let earlier = journal.earlier_phases().to_vec();
    let resume_point = journal.resume_point().clone();

    // The ticker takes a narrow handle rather than the context: a checkpoint
    // task holding the event sender would keep the stream open after the scan
    // ended, and a caller watching it to know when to stop would wait for a scan
    // that was already over. See `ScanContext::progress`.
    let ticker = checkpoint::spawn_checkpoints(journal, ctx.progress());
    let handle = spawn_scan(target_map, cfg, ctx, resume_point);

    Ok((session, ScanTask::journalling(handle, ticker, earlier)))
}

/// Runs both phases of a port scan against an existing context.
///
/// The body of [`scan`], taking a context rather than making one so that a
/// caller journalling the scan can seed it from an earlier run and keep a handle
/// on it. Nothing here knows what a journal is.
/// `settled` is what an earlier sitting already covered, and is empty for a scan
/// that is not continuing one.
fn spawn_scan(
    mut target_map: TargetMap,
    cfg: &ZondConfig,
    ctx: ScanContext,
    settled: Checkpoint,
) -> JoinHandle<ScanReport> {
    let caps = ScanCapabilities::resolve(cfg);
    let cfg = cfg.clone();

    tokio::spawn(async move {
        // Phase one: which of these addresses has anything at it.
        //
        // The answer narrows what is *probed*, never what is counted: the plan
        // stays whole, and the targets of a host that answered nothing are
        // settled at their own positions by the dispatcher. See
        // `Outcome::Skipped`.
        let (liveness, live) = if cfg.assume_up {
            (None, None)
        } else {
            // Over the addresses this sitting still has a target at, so a
            // resumed one asks nothing of a host an earlier sitting finished,
            // and its phase describes what it covered rather than the plan.
            let mut ips = orchestrator::unsettled_ips(&target_map, &settled);
            let scope = TargetScope::from_ip_set(&mut ips, &cfg.exclusions);
            let recorder = PhaseRecorder::start(ScanKind::Discovery, caps.privilege, scope, &cfg);

            // Targeted, never a sweep: a port scan was asked about addresses,
            // not about the network around them. It asks over SCTP as well
            // where the scan's ports named an SCTP one, since a host that
            // answers only SCTP would otherwise be called down and its ports
            // never probed.
            ctx.enter_stage(Stage::Discovery, None);
            let sctp = orchestrator::sctp_discovery_port(&target_map);
            run_discovery(ips, Scope::Targeted, caps, &cfg, &ctx, sctp).await;

            orchestrator::run_correlation(&ctx, cfg.service_detection);
            let report = recorder.finish(&ctx);
            (Some(report), Some(live_addresses(&ctx)))
        };

        // Phase two: the ports. The exclusion policy is applied again rather
        // than trusted from above, because `assume_up` skips the phase above
        // entirely.
        //
        // The scope is what this phase *covered*, so it is taken over the live
        // subset: a reader compares it against phase one's to see how much of
        // what they asked about went unprobed. The dispatcher below is handed
        // the whole plan, because that is what its positions are counted in.
        // Two questions, and they were one number until a resume needed them
        // apart.
        let mut covered = match &live {
            Some(live) => probed_subset(&target_map, live),
            None => target_map.clone(),
        };
        let scope = TargetScope::from_target_map(&mut covered, &cfg.exclusions);
        crate::model::exclusion::Exclusions::withhold_targets(&cfg.exclusions, &mut target_map);
        let recorder = PhaseRecorder::start(ScanKind::PortScan, caps.privilege, scope, &cfg);

        ctx.enter_stage(Stage::Ports, None);
        run_port_phase(target_map, live, &ctx, caps, &cfg, settled).await;

        // Straight after the ports, because what it needs is the list of ports a
        // handshake completed against and the service pass is what produces it.
        orchestrator::run_tls_enumeration(&ctx, &cfg).await;

        // Ordered by what each pass leaves the next. The series probe takes
        // every host with a TCP answer, so the echo probe is left with the
        // machines that answered nothing at all.
        orchestrator::run_active_os_series(&ctx, cfg.os_detection, cfg.probe_tuning(), caps).await;
        orchestrator::run_active_os_snmp(&ctx, cfg.os_detection).await;
        // After the two that read a stack, because it asks only hosts that have
        // a name and answers a question neither of those can: macOS and iOS
        // share a kernel and are indistinguishable to a probe, while a
        // device-info record names the model outright.
        orchestrator::run_active_os_mdns(&ctx, cfg.os_detection).await;
        orchestrator::run_active_os_probe(&ctx, cfg.os_detection, cfg.probe_tuning(), caps).await;
        // Last: the ports are what decide a trace's shape.
        orchestrator::run_traceroute(&ctx, &cfg, caps).await;
        ctx.enter_stage(Stage::Finishing, None);
        orchestrator::run_characterise(&ctx, &cfg, caps).await;
        orchestrator::run_ip_protocols(&ctx, &cfg).await;
        vantage::attribute(&ctx);
        orchestrator::run_correlation(&ctx, cfg.service_detection);
        orchestrator::run_cert_posture(&ctx);
        let report = recorder.finish(&ctx);

        match liveness {
            Some(mut first) => {
                first.merge(report);
                first
            }
            None => report,
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

    /// A panic inside the engine happened in the caller's process, so what it
    /// said is the one thing they can act on. Both shapes `panic!` produces are
    /// read, because which one a call site produces is not a choice anybody
    /// makes deliberately.
    #[tokio::test]
    async fn a_panicking_scan_reports_what_the_panic_said() {
        for spawned in [
            tokio::spawn(async { panic!("a literal message") }),
            tokio::spawn(async { panic!("a formatted {}", "message") }),
        ] {
            let error = panic_or_cancellation(spawned.await.expect_err("the task panicked"));

            let ScanError::TaskFailed { panicked, detail } = error else {
                unreachable!("a panic is a TaskFailed")
            };
            assert!(panicked);
            assert!(detail.contains("message"), "the payload was lost: {detail}");
        }
    }

    /// And a task the runtime took away is told apart from one that broke, so a
    /// consumer does not go looking for a bug in a shutdown.
    #[tokio::test]
    async fn a_cancelled_scan_is_not_reported_as_a_panic() {
        let spawned = tokio::spawn(std::future::pending::<()>());
        spawned.abort();

        let error = panic_or_cancellation(spawned.await.expect_err("the task was cancelled"));

        let ScanError::TaskFailed { panicked, .. } = error else {
            unreachable!("a cancellation is a TaskFailed")
        };
        assert!(!panicked);
    }
}
