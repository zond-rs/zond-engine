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
    port::PortSet,
    target::{TargetIndex, TargetMap},
};
#[cfg(feature = "journal-format")]
use crate::report::ScanPhase;
use crate::report::ScannerKind;
use crate::report::{LivenessSkip, ScanKind, ScanReport, TargetScope};
use crate::scanner::orchestrator::{
    Enrichment, ScanCapabilities, finish_enrichment, probed_subset, run_port_phase,
};
use crate::scanner::recorder::PhaseRecorder;
use crate::scanner::session::{ScanContext, ScanSession, Stage};
use crate::system::interface;
use crate::system::privilege::Privilege;
use strategy::local::Scope;
use strategy::routed::SynPorts;

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
/// The order a plan's targets are asked in. It lives with the plan's numbering
/// in [`model`](crate::model), where a journal counting along the same order
/// can reach it, and is named here too, where the order is taken.
pub use crate::model::order;
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

    /// This run asks for an option the job its journal records did not run
    /// under.
    ///
    /// A sitting under a different technique, retry policy or set of passes
    /// answers a different question, and its answers would stand in one report
    /// beside the earlier sittings' as though they answered the same one. See
    /// [`JobOptions`](crate::journal::manifest::JobOptions) for which options
    /// are held, and [`JobOptions::apply_to`](crate::journal::manifest::JobOptions::apply_to)
    /// for continuing a job under the ones it recorded.
    #[cfg(feature = "journal-format")]
    #[error("{0}")]
    OptionChanged(#[from] crate::journal::manifest::OptionChanged),

    /// The evasion profile is not one a scan could put on the wire.
    ///
    /// Checked before a probe leaves rather than on each one, because every
    /// probe refusing is a scan that sends nothing and reports a network with
    /// nothing on it. See [`EvasionProfile::validate`](crate::EvasionProfile::validate)
    /// for what that check covers and what it does not.
    #[error("{0}")]
    Evasion(#[from] crate::evasion::EvasionError),

    /// The process may hold too few file descriptors for a scan to keep a
    /// socket for its connections beside what the rest of the process needs.
    ///
    /// Checked before anything is sent. Run anyway, the scan's connections
    /// and the process's other files, a journal among them, would take their
    /// descriptors from the same table too small for both, and whichever came
    /// second would fail somewhere in the middle of the run. The engine reads
    /// the limit and never raises it; a caller raises its own soft limit,
    /// within the hard one, before it starts a scan.
    #[error("file descriptor limit {limit} is below the {needed} a scan needs")]
    TooFewDescriptors {
        /// The soft limit the process has.
        limit: usize,
        /// The least a scan needs.
        needed: usize,
    },
}

/// Runs a journalled phase's up-front checks, and gives the journal up if they
/// refuse, so a scan that never started leaves no record of itself.
///
/// Every check a journalled entry point makes before it starts belongs in
/// `checks`, which is what keeps a refusal added later from leaving a record
/// behind. See [`Journal::withdraw`](crate::journal::Journal::withdraw) for
/// which records go.
#[cfg(feature = "journal-format")]
fn accepted(
    journal: crate::journal::Journal,
    checks: impl FnOnce(&crate::journal::Journal) -> Result<(), ScanError>,
) -> Result<crate::journal::Journal, ScanError> {
    match checks(&journal) {
        Ok(()) => Ok(journal),
        Err(refused) => {
            journal.withdraw();
            Err(refused)
        }
    }
}

/// Refuses a sitting that asks what the job it continues did not; see
/// [`JobOptions`](crate::journal::manifest::JobOptions) for which options
/// those are.
///
/// A journal that recorded none is continued under `cfg` as it stands: its
/// first sitting ran on an engine that did not record them, and nothing says
/// what they were.
#[cfg(feature = "journal-format")]
fn under_the_recorded_options(
    journal: &crate::journal::Journal,
    cfg: &ZondConfig,
) -> Result<(), ScanError> {
    match journal.options() {
        Some(options) => Ok(options.check(cfg)?),
        None => Ok(()),
    }
}

/// Writes down the options a journal's first sitting runs under, so every
/// later sitting can be held to them.
///
/// A journal that cannot take them still scans. The sitting loses nothing it
/// found; a later one is continued under what its caller passes, as a journal
/// from before options were recorded is, and this says so.
#[cfg(feature = "journal-format")]
fn recording_options(
    mut journal: crate::journal::Journal,
    cfg: &ZondConfig,
) -> crate::journal::Journal {
    use crate::journal::manifest::JobOptions;

    if let Err(e) = journal.record_options(JobOptions::of(cfg)) {
        crate::warn!("options not recorded ({e})");
    }
    journal
}

/// Refuses a scan in a process whose descriptor limit leaves its connections
/// no socket; see [`ScanError::TooFewDescriptors`].
fn enough_descriptors() -> Result<(), ScanError> {
    match crate::system::descriptors::too_few() {
        Some((limit, needed)) => Err(ScanError::TooFewDescriptors { limit, needed }),
        None => Ok(()),
    }
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
    enough_descriptors()?;

    let planned = planned_addresses(&Positions::of(&targets));

    let (session, ctx) = ScanSession::builder()
        .excluding(cfg.exclusions.clone())
        .host_timeout(cfg.host_timeout)
        .scan_timeout(cfg.scan_timeout)
        .host_probe_interval(cfg.host_probe_interval)
        .send_source(cfg.send_source.clone())
        .listening_only_to(cfg.listen_only_ports.clone())
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
    let journal = accepted(journal, |journal| {
        cfg.evasion.validate()?;
        enough_descriptors()?;
        if journal.manifest().kind() != ScanKind::Discovery {
            return Err(ScanError::WrongPhase);
        }
        under_the_recorded_policy(journal, cfg)?;
        under_the_recorded_options(journal, cfg)
    })?;
    let journal = recording_options(journal, cfg);

    let recorded = journal.manifest().recorded();
    let Some(addresses) = recorded.addresses() else {
        return Err(ScanError::WrongPhase);
    };

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
        .listening_only_to(cfg.listen_only_ports.clone())
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
///
/// Read through [`running_under`], so the stages an idle scan lists are the
/// ones it will run: a stage kept here that the scan then declines would leave
/// a progress bar waiting for work that never comes.
///
/// `runs_liveness` is [`liveness_earns_its_place`]'s verdict, passed in rather
/// than recomputed so the plan it may build is built once for the scan.
fn scan_stages(cfg: &ZondConfig, runs_liveness: bool) -> Vec<Stage> {
    let cfg = &running_under(cfg);
    let mut stages = Vec::new();

    if runs_liveness {
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

/// Whether a port scan under `cfg` asks its targets whether they are there
/// before it probes their ports.
///
/// Not where the caller declined it with [`ZondConfig::assume_up`], and not
/// under an [idle scan](ZondConfig::idle_scan). An idle scan forges every probe
/// from its zombie so that the target never hears from this host, and a
/// liveness pass is this host asking the target directly. Refused rather than
/// run from the zombie, because a liveness probe needs its answer, and the
/// answer to a forged probe goes to the zombie.
fn asks_liveness(cfg: &ZondConfig) -> bool {
    !cfg.assume_up && cfg.idle_scan.is_none()
}

/// Whether a port scan's liveness pass earns the probes it costs, so that the
/// port phase runs behind it rather than over every target.
///
/// The pass exists to spare a port scan the cost of probing every port of an
/// address nothing lives at: a dead address costs the pass a handful of probes
/// where it would cost the port scan one per port. That only saves anything
/// when the port scan is the dearer of the two. The pass asks each address a
/// fixed set — the common five and up to a few of the scan's own ports, one
/// SCTP probe where the scan names SCTP; see
/// [`SynPorts`] — so a scan naming no more ports
/// per address than that would spend as much establishing liveness as it would
/// spend just probing them. There the pass is dropped and the port probes stand
/// in for it: an answer on any port, open or closed, is the host answering, the
/// same evidence a liveness probe reads, and an address that answers nothing is
/// left [`Unknown`](crate::model::host::HostStatus::Unknown) with its targets
/// settled by the port scan, exactly as [`ZondConfig::assume_up`] leaves them —
/// never down on evidence never gathered, never undecided as if unasked.
///
/// Three things keep the pass even for a small scan, because for them the port
/// probes cannot stand in for it or it still pays:
///
/// - **A TCP technique other than a SYN.** Only a SYN draws an answer from
///   every port a live host has, a SYN+ACK where it listens and a reset where
///   it does not. A FIN, a flagless or a Christmas-tree probe draws nothing
///   from an open port, so a host with only open ports would read as silent,
///   and those techniques have no connect form, so where no raw socket or
///   frame reaches a target they send it nothing at all.
/// - **A scan that names a UDP port.** A UDP probe to a dead address waits out
///   an ICMP unreachable a target rate-limits, or a full timeout, where the
///   pass settles the address with cheap TCP or link-layer probes first. So a
///   UDP scan, however few ports it names, keeps its liveness pass.
/// - **A target on this host's own segment.** There the pass reaches it by ARP
///   or neighbour discovery, one packet, answered by a live stack whatever it
///   filters above the link, which finds a host that a direct port scan of a
///   few filtered ports would miss and costs less than one such probe. Whether
///   any target is on-link is read from the discovery plan, which classifies
///   the targets against this host's interfaces and sends nothing.
///
/// `false` for an [idle scan](ZondConfig::idle_scan) and for
/// [`assume_up`](ZondConfig::assume_up), which decline the pass for their own
/// reasons; see [`asks_liveness`].
fn liveness_earns_its_place(cfg: &ZondConfig, map: &TargetMap) -> bool {
    use crate::model::port::Protocol;

    if !asks_liveness(cfg) {
        return false;
    }

    // Only a SYN's replies prove a host from every port; see above.
    if !cfg.tcp_technique.has_connect_fallback() {
        return true;
    }

    // A UDP probe is dear against a dead address, so the cheap liveness pass in
    // front of it pays whatever the port count.
    if map.names(Protocol::Udp) {
        return true;
    }

    let asked = SynPorts::for_scan(&tcp_ports_of(map)).len()
        + usize::from(orchestrator::sctp_discovery_port(map).is_some());
    // The dearest address to probe decides it: the pass pays as soon as one
    // unit asks more ports than the pass would, since that is where a dead
    // address would cost the port scan more than the pass.
    let per_address = map
        .units
        .iter()
        .map(crate::model::target::TargetSet::port_count)
        .max()
        .unwrap_or(0);
    if per_address > asked {
        return true;
    }

    reaches_a_local_segment(cfg, map)
}

/// Why a port scan under `cfg` runs with no liveness pass, or `None` where it
/// runs one; `runs_liveness` is [`liveness_earns_its_place`]'s verdict.
///
/// An idle scan first, since it forbids the pass whatever else was set; then
/// the caller's own [`assume_up`](ZondConfig::assume_up); and otherwise the
/// engine's decision that the port probes cost no more than asking first.
fn liveness_skip(cfg: &ZondConfig, runs_liveness: bool) -> Option<LivenessSkip> {
    if runs_liveness {
        None
    } else if cfg.idle_scan.is_some() {
        Some(LivenessSkip::IdleScan)
    } else if cfg.assume_up {
        Some(LivenessSkip::AssumeUp)
    } else {
        Some(LivenessSkip::PortsNoDearer)
    }
}

/// The most addresses a scan is checked for on-link targets across.
///
/// A local segment a host reaches at the link layer is small: a `/23` is
/// already a large one, and this leaves generous room past that. Building the
/// discovery plan classifies every address, so a scan of a wide routed range,
/// which cannot be on-link, is not made to pay that walk only to learn it has
/// no link-layer targets and skip the liveness pass anyway.
const ON_LINK_CHECK_CEILING: u128 = 1 << 13;

/// Whether the discovery plan for `map` reaches any target at the link layer,
/// where liveness is one exact ARP or neighbour-discovery packet.
///
/// Builds the plan and reads it; the plan classifies the targets against this
/// host's interfaces and sends nothing. Empty of local steps for an
/// unprivileged run, which has no link-layer strategy to reach a segment with,
/// and for one whose targets are all behind a gateway or on loopback.
///
/// A range wider than a segment could be is taken as routed without building
/// the plan, since only a segment-sized set can be on-link and the classifying
/// walk is what this call exists to avoid spending on a scan that skips the
/// pass regardless. See [`ON_LINK_CHECK_CEILING`].
fn reaches_a_local_segment(cfg: &ZondConfig, map: &TargetMap) -> bool {
    match map.gross_ips() {
        Ok(count) if count <= ON_LINK_CHECK_CEILING => {}
        _ => return false,
    }

    let mut ips = IpSet::new();
    for unit in &map.units {
        for range in unit.ips().v4() {
            ips.push_v4_range(*range);
        }
        for range in unit.ips().v6() {
            ips.push_v6_range(*range);
        }
    }
    ips.canonicalize();

    let plan = plan::DiscoveryPlan::build(ips, Scope::Targeted, &cfg.exclusions, &cfg.send_source);
    plan.steps()
        .iter()
        .any(|step| matches!(step, plan::DiscoveryStep::Local { .. }))
}

/// The configuration a scan actually runs under, given that an idle scan sends
/// the target nothing from this host.
///
/// An idle scan forges every probe from its zombie, so the passes that run
/// after the port phase are the problem the port phase solved: each of service
/// detection, the detection corpus, active operating-system probing, the route
/// trace, filter characterisation, IP-protocol probing and TLS enumeration
/// opens a connection to the target or sends it a probe from this host, which
/// is the one thing the technique exists to avoid. So under an idle scan every
/// one of them is turned down to the level that sends the target nothing:
/// service detection off, the detection ceiling and the operating-system level
/// held at what reads only gathered evidence, and the rest cleared.
///
/// The result is that an idle scan puts nothing on the wire to the target but
/// the forged probes, whatever else the caller set. What the caller asked for
/// and cannot have here is not lost quietly: [`record_idle_refusals`] files a
/// refusal for each pass this mutes that was more than a default left on, so
/// the report says the pass was declined and why. Returned unchanged for a scan
/// that is not an idle one.
fn running_under(cfg: &ZondConfig) -> ZondConfig {
    if cfg.idle_scan.is_none() {
        return cfg.clone();
    }

    let mut muted = cfg.clone();
    muted.service_detection = crate::config::ServiceDetection::Off;
    if muted.detection.ceiling() > Some(crate::model::finding::DetectionClass::Passive) {
        muted.detection =
            crate::config::DetectionEnvelope::up_to(crate::model::finding::DetectionClass::Passive);
    }
    if muted.os_detection.is_active() {
        muted.os_detection = crate::config::OsDetection::Passive;
    }
    muted.traceroute = false;
    muted.characterise = false;
    muted.ip_protocols.clear();
    muted.tls_enumeration = false;
    muted
}

/// Records, once, why each after-port pass an idle scan turns off was turned
/// off, reading `cfg` as the caller set it.
///
/// A pass the caller asked for and that would contact the target directly is
/// refused through the plan's refusal mechanism, so a reader sees it declined
/// rather than silently absent; see
/// [`RefusedStep::pass_not_in_an_idle_scan`](plan::RefusedStep::pass_not_in_an_idle_scan).
/// Service detection is the exception: it is on by default and connecting is
/// its whole purpose, and nothing here can tell a caller who set its level from
/// one who took the default, so it is turned off with a line at verbosity one
/// rather than a refusal that might misfire on a default nobody chose.
fn record_idle_refusals(cfg: &ZondConfig, ctx: &ScanContext) {
    use crate::model::finding::DetectionClass;
    use crate::report::ScannerKind;
    use plan::RefusedStep;

    if cfg.idle_scan.is_none() {
        return;
    }

    if cfg.service_detection.connects() {
        crate::info!(verbosity = 1, "service detection skipped (idle scan)");
    }
    if cfg.detection.ceiling() > Some(DetectionClass::Passive) {
        ctx.record_refusal(
            RefusedStep::pass_not_in_an_idle_scan(ScannerKind::Detection, "active detection")
                .into(),
        );
    }
    if cfg.os_detection.is_active() {
        ctx.record_refusal(
            RefusedStep::pass_not_in_an_idle_scan(
                ScannerKind::OsSeries,
                "active operating-system probing",
            )
            .into(),
        );
    }
    if cfg.traceroute {
        ctx.record_refusal(
            RefusedStep::pass_not_in_an_idle_scan(ScannerKind::Routed, "the route trace").into(),
        );
    }
    if cfg.characterise {
        ctx.record_refusal(
            RefusedStep::pass_not_in_an_idle_scan(
                ScannerKind::Routed,
                "the filter characterisation",
            )
            .into(),
        );
    }
    if !cfg.ip_protocols.is_empty() {
        ctx.record_refusal(
            RefusedStep::pass_not_in_an_idle_scan(ScannerKind::Routed, "the IP-protocol probe")
                .into(),
        );
    }
    if cfg.tls_enumeration {
        ctx.record_refusal(
            RefusedStep::pass_not_in_an_idle_scan(ScannerKind::Service, "TLS enumeration").into(),
        );
    }
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
    let caps = ScanCapabilities::resolve(cfg, orchestrator::Probing::sweep());

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
        // No SCTP sweep and no ports of its own: `discover` is asked about
        // addresses and never about ports, so nothing has said which port
        // would be worth asking beyond the ones every host is asked.
        run_discovery(targets, reach, caps, &cfg, &ctx, SynPorts::common(), None).await;
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
/// `syn_ports` is what every address a TCP probe reaches is asked about, by a
/// routed SYN sweep and a connect sweep alike: the common five for a sweep,
/// and those with some of the scan's own ports for a port scan's liveness
/// pass. See [`SynPorts`] for why a host behind a filter needs the second.
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
    syn_ports: SynPorts,
    sctp_port: Option<u16>,
) {
    if caps.privilege.is_raw() {
        let unframed =
            caps.beyond_frames(&targets, &cfg.send_source, interface::FrameSender::Sweep);
        let mut plan =
            plan::DiscoveryPlan::build(targets, reach, &cfg.exclusions, &cfg.send_source);
        plan.connect_instead(&unframed.targets);
        plan.asking_tcp(syn_ports);
        if let Some(port) = sctp_port {
            plan.also_over_sctp(port);
        }
        for step in plan.steps() {
            if let plan::DiscoveryStep::Connect { targets, .. } = step {
                ctx.record_reached_by_connect(targets);
            }
        }
        let enrichment = Enrichment::spawn(plan, ctx, caps, cfg.probe_tuning()).await;
        finish_enrichment(Some(enrichment), caps, ctx, rdns::Unheard::Skipped).await;
    } else {
        let targets = orchestrator::walkable(targets, ctx);
        if let Err(error) =
            strategy::connect::discover_on(targets, ctx.clone(), &cfg.evasion, syn_ports).await
        {
            ctx.record_failure(ScannerKind::Connect, error.to_string());
        }
        finish_enrichment(None, caps, ctx, rdns::Unheard::Skipped).await;
    }

    orchestrator::run_passive_os_identification(ctx, cfg.os_detection);
}

/// Every TCP port any unit of `map` names, as one set.
///
/// One set for the whole liveness pass rather than one per unit, because one
/// sweep asks every address the same ports: a unit's own ports are among
/// those ranked for all of them, which is the same shape the SCTP sweep's
/// port is chosen in.
fn tcp_ports_of(map: &TargetMap) -> PortSet {
    map.units
        .iter()
        .fold(PortSet::new(), |named, unit| named.union(unit.ports()))
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
    let journal = accepted(journal, |journal| {
        if journal.manifest().kind() != ScanKind::Listen {
            return Err(ScanError::WrongPhase);
        }
        Ok(())
    })?;

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
        // question the phase's privilege field asks.** Whether a capture came
        // up, and if not whether privilege is what refused it, is not the same
        // as running as root: `pcap` reads a link for a user in the
        // `access_bpf` group on macOS and for a binary with `cap_net_raw` on
        // Linux, both being how anybody who is not root captures anything. See
        // `listening_privilege`.
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
            listening_privilege(opened.as_ref().err()),
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

/// The privilege a listener held, read off what its capture was told, with
/// `refusal` being why no link could be captured on.
///
/// A listener that opened a capture held what it needed. One refused for want
/// of privilege did not. Any other refusal, a link that would not compile the
/// filter, one that is down or carries framing nothing here parses, or a
/// reader thread that would not start, comes after the platform's permission
/// check, which `libpcap` makes before it binds a link: the process held the
/// privilege and the link refused for its own reasons. Recorded as
/// unprivileged, that run would tell its reader to find a privilege it had.
/// Where no link was tried at all, nothing asked the question, and the
/// process's own answer, measured as every scan phase measures it, is the
/// only one there is.
fn listening_privilege(refusal: Option<&strategy::StrategyError>) -> Privilege {
    use crate::transport::capture::CaptureError;

    match refusal {
        None => Privilege::Raw,
        Some(strategy::StrategyError::Capture(CaptureError::NoInterface { refused }))
            if refused.is_empty() =>
        {
            Privilege::current()
        }
        Some(strategy::StrategyError::Capture(error)) if error.is_denied() => Privilege::Connect,
        Some(strategy::StrategyError::Capture(_)) => Privilege::Raw,
        Some(_) => Privilege::current(),
    }
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
/// which is what a host behind a firewall that answers no knock needs. An
/// [idle scan](ZondConfig::idle_scan) skips it too, since the phase would send
/// the target the packets from this host the technique exists to withhold. An
/// idle scan also declines every later pass that would contact the target
/// directly, service detection through TLS enumeration, so the target hears
/// nothing from this host but the forged probes; the report says which passes
/// were declined and why.
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
    enough_descriptors()?;

    let planned = planned_targets(&target_map);
    let runs_liveness = liveness_earns_its_place(cfg, &target_map);

    let (session, ctx) = ScanSession::builder()
        .excluding(cfg.exclusions.clone())
        .host_timeout(cfg.host_timeout)
        .scan_timeout(cfg.scan_timeout)
        .host_probe_interval(cfg.host_probe_interval)
        .send_source(cfg.send_source.clone())
        .listening_only_to(cfg.listen_only_ports.clone())
        .detections(detections)
        .planning(Stage::Ports, planned)
        .staging(scan_stages(cfg, runs_liveness))
        // See `discover`: drawn here and kept nowhere, because nothing is
        // recording this scan.
        .ordering(Some(rand::random()))
        .build();
    let handle = spawn_scan(target_map, cfg, ctx, Checkpoint::default(), runs_liveness);
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
    let journal = accepted(journal, |journal| {
        cfg.evasion.validate()?;
        enough_descriptors()?;
        if journal.manifest().kind() != ScanKind::PortScan {
            return Err(ScanError::WrongPhase);
        }
        under_the_recorded_policy(journal, cfg)?;
        under_the_recorded_options(journal, cfg)
    })?;
    let journal = recording_options(journal, cfg);
    let runs_liveness = liveness_earns_its_place(cfg, &target_map);

    let (session, ctx) = ScanSession::builder()
        .excluding(cfg.exclusions.clone())
        .host_timeout(cfg.host_timeout)
        .scan_timeout(cfg.scan_timeout)
        .host_probe_interval(cfg.host_probe_interval)
        .send_source(cfg.send_source.clone())
        .listening_only_to(cfg.listen_only_ports.clone())
        .resuming(journal.resume_point())
        .detections(detections)
        .planning(Stage::Ports, planned_targets(&target_map))
        .staging(scan_stages(cfg, runs_liveness))
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
    let handle = spawn_scan(target_map, cfg, ctx, resume_point, runs_liveness);

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
    runs_liveness: bool,
) -> JoinHandle<ScanReport> {
    let caps = ScanCapabilities::resolve(cfg, orchestrator::Probing::ports(cfg, &target_map));
    // What the caller set, kept so the passes an idle scan turns off can be
    // named as declined rather than dropped, and the config the scan actually
    // runs under, which an idle scan holds to what sends the target nothing.
    let requested = cfg.clone();
    let cfg = running_under(&requested);

    tokio::spawn(async move {
        // Phase one: which of these addresses has anything at it.
        //
        // The answer narrows what is *probed*, never what is counted: the plan
        // stays whole, and the targets of a host it asked and heard nothing
        // from are settled at their own positions by the dispatcher. See
        // `Outcome::Skipped`, and `Outcome::Undecided` for a host it never
        // reached a verdict on.
        let skipped = liveness_skip(&cfg, runs_liveness);
        let (liveness, live) = if let Some(why) = skipped {
            match why {
                LivenessSkip::IdleScan => {
                    crate::info!(verbosity = 1, "liveness pass skipped (idle scan)");
                }
                LivenessSkip::PortsNoDearer => {
                    crate::info!(verbosity = 1, "liveness pass skipped (port scan no dearer)");
                }
                // The caller asked for it, and a line saying so tells them
                // nothing they did not choose.
                _ => {}
            }
            (None, None)
        } else {
            // Over the addresses this sitting still has a target at, so a
            // resumed one asks nothing of a host an earlier sitting finished,
            // and its phase describes what it covered rather than the plan.
            let mut ips = orchestrator::unsettled_ips(&target_map, &settled);
            let scope = TargetScope::from_ip_set(&mut ips, &cfg.exclusions);
            let recorder = PhaseRecorder::start(ScanKind::Discovery, caps.privilege, scope, &cfg);

            // Targeted, never a sweep: a port scan was asked about addresses,
            // not about the network around them. It asks about some of the
            // scan's own TCP ports beside the common five, since a host that
            // drops a SYN to anything it does not serve answers on nothing
            // else, and over SCTP as well where the scan's ports named an SCTP
            // one, since a host that answers only SCTP would otherwise be
            // called down and its ports never probed.
            ctx.enter_stage(Stage::Discovery, None);
            let syn_ports = SynPorts::for_scan(&tcp_ports_of(&target_map));
            let sctp = orchestrator::sctp_discovery_port(&target_map);
            run_discovery(ips, Scope::Targeted, caps, &cfg, &ctx, syn_ports, sctp).await;

            orchestrator::run_correlation(&ctx, cfg.service_detection);
            let (report, liveness) = recorder.close(&ctx);
            (Some(report), liveness)
        };

        // Phase two: the ports. The exclusion policy is applied again rather
        // than trusted from above, because the phase above does not always
        // run.
        //
        // The scope is what this phase *covered*, so it is taken over the live
        // subset: a reader compares it against phase one's to see how much of
        // what they asked about went unprobed. The dispatcher below is handed
        // the whole plan, because that is what its positions are counted in.
        // Two questions, and they were one number until a resume needed them
        // apart.
        let mut covered = match &live {
            Some(live) => probed_subset(&target_map, &live.live),
            None => target_map.clone(),
        };
        let scope = TargetScope::from_target_map(&mut covered, &cfg.exclusions);
        crate::model::exclusion::Exclusions::withhold_targets(&cfg.exclusions, &mut target_map);
        let mut recorder = PhaseRecorder::start(ScanKind::PortScan, caps.privilege, scope, &cfg);
        if let Some(why) = skipped {
            recorder = recorder.skipping_liveness(why);
        }

        ctx.enter_stage(Stage::Ports, None);
        // Filed against the port phase, since that is the phase an idle scan
        // has: it runs no liveness pass, so this is where a reader looks for
        // what the scan declined to send the target from this host.
        record_idle_refusals(&requested, &ctx);
        let stands_in = skipped == Some(LivenessSkip::PortsNoDearer);
        run_port_phase(target_map, live, &ctx, caps, &cfg, settled, stands_in).await;

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

    /// A scratch journal root, removed and made again for each test that
    /// names it.
    #[cfg(feature = "journal-format")]
    fn journal_root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("zond-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a scratch root");
        root
    }

    /// A configuration every scan refuses before it sends anything.
    fn refused_up_front() -> ZondConfig {
        ZondConfig {
            evasion: crate::evasion::EvasionProfile::default().with_ttl(0),
            ..ZondConfig::default()
        }
    }

    /// **A scan refused before it starts leaves no record of itself.**
    ///
    /// A journal handed to a scan that then refuses would otherwise stay
    /// behind as a job nobody ran, listed as resumable with nothing done, and
    /// counted against however many records a front end keeps, so each refusal
    /// pushes out a record of a scan that happened. The caller cannot tidy it
    /// either: the journal was moved into the call.
    #[cfg(feature = "journal-format")]
    #[tokio::test]
    async fn a_journalled_scan_refused_up_front_leaves_no_record() {
        use crate::journal::Journal;
        use crate::journal::manifest::Plan;
        use crate::model::ip::set::IpSet;
        use crate::model::target::TargetSet;

        let root = journal_root("refused");
        let addresses: IpSet = "192.0.2.1".parse().expect("an address");
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            addresses.clone(),
            "22".parse().expect("ports"),
        ));
        let cfg = refused_up_front();

        let plan = Plan::port_scan(&map, &cfg.exclusions, cfg.tcp_technique);
        let journal = Journal::create(&root, &plan, Privilege::Connect, "").expect("creates");
        let directory = journal.directory().to_path_buf();
        let refused = scan_with_journal(map, &cfg, Detections::embedded(), journal).await;
        assert!(
            matches!(refused, Err(ScanError::Evasion(_))),
            "{:?}",
            refused.err()
        );
        assert!(
            !directory.exists(),
            "a port scan that never ran left a record"
        );

        let plan = Plan::discovery(&addresses, &cfg.exclusions, false);
        let journal = Journal::create(&root, &plan, Privilege::Connect, "").expect("creates");
        let directory = journal.directory().to_path_buf();
        let refused = discover_with_journal(addresses, &cfg, journal).await;
        assert!(
            matches!(refused, Err(ScanError::Evasion(_))),
            "{:?}",
            refused.err()
        );
        assert!(!directory.exists(), "a sweep that never ran left a record");

        std::fs::remove_dir_all(&root).ok();
    }

    /// A resumed sitting that asks something its job did not is refused by the
    /// option it changed, before anything is sent, and the record of the
    /// sitting before it is kept.
    #[cfg(feature = "journal-format")]
    #[tokio::test]
    async fn a_resume_asking_what_its_job_did_not_is_refused_and_keeps_its_record() {
        use crate::journal::Journal;
        use crate::journal::manifest::{JobOptions, OptionChanged, Plan};
        use crate::journal::settle::{Outcome, Settlements};
        use crate::model::ip::set::IpSet;

        let root = journal_root("option-changed");
        let addresses: IpSet = "192.0.2.1-192.0.2.4".parse().expect("addresses");
        let first = ZondConfig {
            traceroute: true,
            ..ZondConfig::default()
        };
        let plan = Plan::discovery(&addresses, &first.exclusions, false);

        let mut journal = Journal::create(&root, &plan, Privilege::Connect, "").expect("creates");
        journal
            .record_options(JobOptions::of(&first))
            .expect("records");
        let settlements = Settlements::default();
        settlements.record(Outcome::Answered { position: 0 });
        journal.checkpoint(&settlements).expect("checkpoints");
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let (journal, _) = Journal::resume(&directory, &plan, Privilege::Connect).expect("resumes");
        let refused = discover_with_journal(addresses, &ZondConfig::default(), journal).await;
        assert!(
            matches!(
                refused,
                Err(ScanError::OptionChanged(OptionChanged {
                    option: "traceroute"
                }))
            ),
            "{:?}",
            refused.err()
        );
        assert!(directory.join("manifest.json").exists(), "the record went");

        std::fs::remove_dir_all(&root).ok();
    }

    /// A sweep's journal handed to a port scan is refused as the other phase,
    /// and so is withdrawn with the rest of the up-front refusals.
    ///
    /// Taken, the port scan would settle address-and-port positions against a
    /// plan counted in addresses, and a resume would skip targets nothing
    /// asked about. The exclusion check alone cannot see it: it rebuilds the
    /// recorded plan in its own shape and finds it unchanged.
    #[cfg(feature = "journal-format")]
    #[tokio::test]
    async fn a_sweeps_journal_is_refused_to_a_port_scan() {
        use crate::journal::Journal;
        use crate::journal::manifest::Plan;
        use crate::model::ip::set::IpSet;
        use crate::model::target::TargetSet;

        let root = journal_root("other-phase");
        let addresses: IpSet = "127.0.0.1".parse().expect("an address");
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            addresses.clone(),
            "9".parse().expect("ports"),
        ));
        let cfg = ZondConfig::default();

        let plan = Plan::discovery(&addresses, &cfg.exclusions, false);
        let journal = Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
        let refused = scan_with_journal(map, &cfg, Detections::embedded(), journal).await;
        assert!(
            matches!(refused, Err(ScanError::WrongPhase)),
            "{:?}",
            refused.err()
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// A resume refused the same way keeps the record: an earlier sitting ran
    /// against it, and what that sitting settled is the job's.
    #[cfg(feature = "journal-format")]
    #[tokio::test]
    async fn a_refused_resume_keeps_the_record_of_the_sitting_before_it() {
        use crate::journal::Journal;
        use crate::journal::manifest::Plan;
        use crate::journal::settle::{Outcome, Settlements};
        use crate::model::ip::set::IpSet;

        let root = journal_root("refused-resume");
        let addresses: IpSet = "192.0.2.1-192.0.2.4".parse().expect("addresses");
        let cfg = refused_up_front();
        let plan = Plan::discovery(&addresses, &cfg.exclusions, false);

        let mut journal = Journal::create(&root, &plan, Privilege::Connect, "").expect("creates");
        let settlements = Settlements::default();
        settlements.record(Outcome::Answered { position: 0 });
        journal.checkpoint(&settlements).expect("checkpoints");
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let (journal, _) = Journal::resume(&directory, &plan, Privilege::Connect).expect("resumes");
        let refused = discover_with_journal(addresses, &cfg, journal).await;
        assert!(
            matches!(refused, Err(ScanError::Evasion(_))),
            "{:?}",
            refused.err()
        );
        assert!(directory.join("manifest.json").exists(), "the record went");

        std::fs::remove_dir_all(&root).ok();
    }

    /// A listener's privilege says what its capture was told. Only a refusal
    /// for want of privilege records one missing: a link that would not take
    /// the filter, or carried framing nothing here reads, was opened by a
    /// process the platform had already let capture, and recording it as
    /// unprivileged sends a reader after a privilege they hold.
    #[test]
    fn a_listener_is_recorded_unprivileged_only_where_privilege_refused_it() {
        use crate::scanner::strategy::StrategyError;
        use crate::transport::capture::CaptureError;

        let denied = |link: &str| CaptureError::Denied {
            interface: link.into(),
            source: pcap::Error::PcapError("permission denied".into()),
        };
        let filter = CaptureError::Filter {
            filter: "ip6 and ether proto 0x86dd".into(),
            source: pcap::Error::PcapError("not an ethernet link".into()),
        };
        let refused = |refused| StrategyError::Capture(CaptureError::NoInterface { refused });

        assert_eq!(
            listening_privilege(Some(&refused(vec![("en0".into(), denied("en0"))]))),
            Privilege::Connect,
            "the platform refused this process"
        );
        assert_eq!(
            listening_privilege(Some(&refused(vec![("utun4".into(), filter)]))),
            Privilege::Raw,
            "the link refused the filter, after the platform let it open"
        );
        assert_eq!(listening_privilege(None), Privilege::Raw, "it listened");
        assert_eq!(
            listening_privilege(Some(&refused(Vec::new()))),
            Privilege::current(),
            "no link was tried, so the process's own answer is all there is"
        );
    }

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
