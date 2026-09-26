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
    ip::scoped::Zone,
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
pub mod plan;
pub mod strategy;

// What a caller driving strategies itself needs beside them. `dispatcher` feeds
// targets to a `PortScanner`, `rdns` is the hostname tail, and `service` and
// `detection` are the passes run over the ports a scan found open.
/// The timer that writes a running scan into its journal, and the handle that
/// stops it. Behind `journal-format` because that is what compiles a
/// [`Journal`](crate::journal::Journal) to write into.
#[cfg(feature = "journal-format")]
pub mod checkpoint;
pub mod detection;
pub mod dispatcher;
pub mod rdns;
pub mod service;

// The machinery the strategies are built from, and nothing a caller holds:
// `pacing` decides when a probe is sent again and when silence is an answer,
// `audit` counts what a raw scanner saw of its own run, `pool` bounds a
// fan-out of connect probes, and `payload` is what a UDP probe carries. Each
// is reached through the strategy that owns it, whose constructor takes the
// settings that tune it, so none of it is a commitment to anyone outside.
pub(crate) mod audit;
pub(crate) mod pacing;
pub(crate) mod payload;
pub(crate) mod pool;

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
    /// socket for its connections beside what the rest of the process needs,
    /// counting what it holds open when the scan starts where that can be
    /// counted.
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
        /// The least limit a scan needs, beside what the process holds open.
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

/// `cfg` with the TCP technique a port scan's journal was counted under, where
/// the journal recorded no options to hold the sitting to.
///
/// The technique is part of the plan's fingerprint, so a journal that resumed
/// at all was counted under the one its manifest names, whatever `cfg` asks.
/// A job recorded with its options is held to that by
/// [`under_the_recorded_options`], which refuses another. One recorded before
/// options were has only the manifest to say what it asked, and a sitting run
/// under `cfg`'s technique would file segments of another kind as the same
/// job's answers. So it runs under the manifest's, and says so where that
/// differs from what it was given.
#[cfg(feature = "journal-format")]
fn under_the_recorded_technique(journal: &crate::journal::Journal, cfg: &ZondConfig) -> ZondConfig {
    let recorded = journal.manifest().technique();
    if journal.options().is_some() || recorded == cfg.tcp_technique {
        return cfg.clone();
    }
    crate::info!(
        verbosity = 1,
        "{recorded} scan, as the job recorded (not {})",
        cfg.tcp_technique
    );
    ZondConfig {
        tcp_technique: recorded,
        ..cfg.clone()
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

/// The links a scan probing `addresses` captures on, once it is known that
/// the process has the descriptors for them; see
/// [`capture_links_toward`](crate::transport::probe::capture_links_toward)
/// and [`enough_descriptors`].
///
/// One set for both, handed on to the context the scan's captures read, so
/// what the up-front check counts is what the scan opens: a check counting
/// every link lets through no scan a smaller need would refuse, and refuses
/// scans that need a device or two on a machine with dozens of links.
fn capture_plan(addresses: &IpSet, cfg: &ZondConfig) -> Result<Vec<Zone>, ScanError> {
    let mut addresses = addresses.clone();
    cfg.exclusions.withhold(&mut addresses);
    let links = crate::transport::probe::capture_links_toward(&addresses, &cfg.send_source);
    enough_descriptors(captures_needed(Privilege::current(), &links))?;
    Ok(links)
}

/// How many capture devices a process holding `privilege` opens for a scan
/// capturing on `links`: one a link where it may choose its own packets, and
/// none where it probes by connect.
///
/// A raw process whose every target is loopback probes it by connect and
/// opens nothing, and is counted its link all the same: the need is read
/// before the phases decide, and one device more costs such a scan nothing.
fn captures_needed(privilege: Privilege, links: &[Zone]) -> usize {
    match privilege.is_raw() {
        true => links.len(),
        false => 0,
    }
}

/// Refuses a scan in a process whose descriptor limit, or whose table as it
/// stands, leaves its connections no socket once its `captures` capture
/// devices are open; see [`ScanError::TooFewDescriptors`].
fn enough_descriptors(captures: usize) -> Result<(), ScanError> {
    match crate::system::descriptors::too_few(captures) {
        Some((limit, needed)) => Err(ScanError::TooFewDescriptors { limit, needed }),
        None => Ok(()),
    }
}

/// Every address `target_map` names a port at.
fn plan_addresses(target_map: &TargetMap) -> IpSet {
    orchestrator::unsettled_ips(target_map, &Checkpoint::default())
}

/// Refuses a sitting that would not count its targets as its journal did.
///
/// `this_run` is the plan this sitting numbers: what it was handed, less what
/// its exclusion policy withholds. A position is an index into that
/// enumeration, so a plan other than the recorded one reads every settled
/// position as a different target and skips ground nothing asked about. The
/// caller's plan is what is tested rather than the journal's, since the
/// journal's is the one thing that cannot disagree with itself. A caller
/// continuing from the recorded plan passes that, and the test is then of the
/// policy alone: one that withholds nothing further leaves the same plan, and
/// so the same fingerprint.
///
/// A policy that withholds *less* than the first sitting's passes when applied
/// to the recorded plan, and is meant to: that plan is what is being
/// continued, and widening the scope is a new scan rather than a continuation
/// of this one.
///
/// The privilege is what this process can send rather than what the journal
/// was opened with, because it decides which question the probes answer; see
/// [`PlanFingerprint::of`](crate::journal::manifest::PlanFingerprint::of). A
/// journal opened or resumed claiming another would file this sitting's
/// answers as the other kind.
#[cfg(feature = "journal-format")]
fn counted_as_recorded(
    journal: &crate::journal::Journal,
    this_run: &crate::journal::manifest::Plan,
) -> Result<(), ScanError> {
    journal.manifest().covers(this_run, Privilege::current())?;
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
///
/// # Dropping it stops the scan
///
/// This is the scan's owner, and the one way to its report. Dropped before the
/// scan has finished, or while being awaited, it stops the scan as
/// [`abort`](crate::scanner::handle::ScanHandle::abort) would: nothing could
/// read what the scan went on to find, and a scan nobody can collect would
/// keep its sockets, its captures and its probes going until it ended on its
/// own, which for a listener watching until it is stopped is never. It is a
/// stop and not a cancellation: the scan winds down through the same checks,
/// so a journal it writes gets its last checkpoint once the scan has wound
/// down, and keeps its lock until then rather than handing the job to a
/// resume while this one is still probing. That last write needs the runtime
/// the scan runs on, and a task dropped after that runtime has shut down
/// leaves the journal where its last timed checkpoint did.
///
/// The [`ScanSession`] is a view of the scan and stops nothing when dropped: a
/// caller that wants only the report may let it go and await this.
pub struct ScanTask {
    /// The scan, until it is joined or dropped.
    handle: Option<JoinHandle<ScanReport>>,
    /// The scan's stop, which dropping this pulls.
    stop: handle::ScanHandle,
    /// The journal this scan writes to, closed once the scan ends.
    ///
    /// A journal has to write its last checkpoint and release its lock when the
    /// scan is over, and this is the type that knows when that is.
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
    fn new(handle: JoinHandle<ScanReport>, stop: handle::ScanHandle) -> Self {
        Self {
            handle: Some(handle),
            stop,
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
        stop: handle::ScanHandle,
        journal: checkpoint::Checkpointing,
        earlier: Vec<ScanPhase>,
    ) -> Self {
        Self {
            handle: Some(handle),
            stop,
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
    ///
    /// Dropped while it waits, the scan is stopped; see
    /// [the type](ScanTask#dropping-it-stops-the-scan).
    pub async fn join(mut self) -> Result<ScanReport, ScanError> {
        // Awaited in place rather than taken, so a join dropped part way is a
        // task dropped with its scan still running.
        let running = self.handle.as_mut().expect("a task is joined at most once");
        let report = running.await.map_err(panic_or_cancellation);
        self.handle = None;

        // After the scan, so the last checkpoint sees everything it settled, and
        // the phases recorded are this sitting's own. A scan that failed gets a
        // checkpoint too: how far it got is what a resume needs.
        #[cfg(feature = "journal-format")]
        if let Some(journal) = self.journal.take() {
            let phases = report.as_ref().map(ScanReport::phases).unwrap_or_default();
            journal.finish(phases).await;
        }

        // Earlier sittings in front of this one, in the order they ran.
        #[cfg(feature = "journal-format")]
        if !self.earlier.is_empty() {
            let earlier = std::mem::take(&mut self.earlier);
            return report.map(|report| {
                let mut whole = ScanReport::from_phases(earlier, []);
                whole.merge(report);
                whole
            });
        }

        report
    }
}

impl Drop for ScanTask {
    fn drop(&mut self) {
        let Some(scan) = self.handle.take() else {
            return;
        };
        self.stop.abort();

        // The journal is closed once the scan has wound down, from a task of
        // its own, since a drop cannot wait. Without a runtime to run it on
        // there is no scan left to wait for either.
        #[cfg(feature = "journal-format")]
        if let Some(journal) = self.journal.take()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            runtime.spawn(async move {
                let phases = match scan.await {
                    Ok(report) => report.phases().to_vec(),
                    Err(_) => Vec::new(),
                };
                journal.finish(&phases).await;
            });
        }
        #[cfg(not(feature = "journal-format"))]
        drop(scan);
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
/// otherwise. With it set, hosts are named from the hosts file alone.
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
    let capture_links = capture_plan(&targets, cfg)?;

    // Numbered in what the exclusions leave, as a journal numbers a sweep,
    // and counted: the settlements are what the progress figures read, so a
    // sweep numbering nothing reports none of its work however far it gets.
    let mut numbered = targets.clone();
    cfg.exclusions.withhold(&mut numbered);
    numbered.canonicalize();
    let positions = numbered.positions();
    let planned = planned_addresses(&positions);

    let (session, ctx) = ScanSession::builder()
        .excluding(cfg.exclusions.clone())
        .naming(cfg.target_names.clone())
        .host_timeout(cfg.host_timeout)
        .scan_timeout(cfg.scan_timeout)
        .host_probe_interval(cfg.host_probe_interval)
        .send_source(cfg.send_source.clone())
        .listening_only_to(cfg.listen_only_ports.clone())
        .counting(positions)
        .planning(Stage::Discovery, planned)
        .staging(discovery_stages(cfg))
        .build();
    let handle = spawn_discovery(targets, capture_links, cfg, ctx);
    let stop = session.handle().clone();
    Ok((session, ScanTask::new(handle, stop)))
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
    let mut capture_links = Vec::new();
    let journal = accepted(journal, |journal| {
        cfg.evasion.validate()?;
        if journal.manifest().kind() != ScanKind::Discovery {
            return Err(ScanError::WrongPhase);
        }
        let recorded = journal.manifest().recorded();
        let Some(addresses) = recorded.addresses() else {
            return Err(ScanError::WrongPhase);
        };
        // What this sitting sweeps: the caller's set for a first sitting, and
        // what the recorded plan leaves for a later one.
        let swept = if *journal.resume_point() == Checkpoint::default() {
            &targets
        } else {
            addresses
        };
        // Over the whole of what the job sweeps, which holds whatever part
        // of it this sitting has left.
        capture_links = capture_plan(swept, cfg)?;
        let this_run = crate::journal::manifest::Plan::discovery(
            swept,
            &cfg.exclusions,
            recorded.sweeps_the_segment(),
        );
        counted_as_recorded(journal, &this_run)?;
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
    let finished = journal.finished_hosts().unwrap_or_else(|e| {
        crate::warn!("passes rerun for every host ({e})");
        Default::default()
    });

    let (session, ctx) = ScanSession::builder()
        .excluding(cfg.exclusions.clone())
        .naming(cfg.target_names.clone())
        .host_timeout(cfg.host_timeout)
        .scan_timeout(cfg.scan_timeout)
        .host_probe_interval(cfg.host_probe_interval)
        .send_source(cfg.send_source.clone())
        .listening_only_to(cfg.listen_only_ports.clone())
        .resuming(&resume_point)
        .finished(finished, sweep.clone())
        .counting(positions)
        .planning(Stage::Discovery, planned)
        .staging(discovery_stages(cfg))
        .ordering(order_seed)
        .build();

    ctx.restore_hosts(journal.restored());
    let earlier = journal.earlier_phases().to_vec();

    let ticker = checkpoint::spawn_checkpoints(journal, ctx.progress());
    let handle = spawn_discovery(sweep, capture_links, cfg, ctx);

    let stop = session.handle().clone();
    Ok((
        session,
        ScanTask::journalling(handle, stop, ticker, earlier),
    ))
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
    if cfg.characterise {
        stages.push(Stage::Filters);
    }
    if !cfg.ip_protocols.is_empty() {
        stages.push(Stage::IpProtocols);
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
    if cfg.characterise {
        stages.push(Stage::Filters);
    }
    if !cfg.ip_protocols.is_empty() {
        stages.push(Stage::IpProtocols);
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
/// reasons; see [`asks_liveness`]. `false` too where the
/// [excluded ports](ZondConfig::excluded_ports) leave the pass no port to ask:
/// it would leave every address it reaches by TCP unasked and so unscanned,
/// where the port probes standing in reach them all.
fn liveness_earns_its_place(cfg: &ZondConfig, map: &TargetMap) -> bool {
    use crate::model::port::Protocol;

    if !asks_liveness(cfg) {
        return false;
    }

    let asked = SynPorts::for_scan(&tcp_ports_of(map))
        .excluding(&cfg.excluded_ports)
        .len()
        + usize::from(orchestrator::sctp_discovery_port(map).is_some());
    // Nothing left to ask; see above.
    if asked == 0 {
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
            RefusedStep::pass_not_in_an_idle_scan(ScannerKind::OsSeries, "OS probing").into(),
        );
    }
    if cfg.traceroute {
        ctx.record_refusal(
            RefusedStep::pass_not_in_an_idle_scan(ScannerKind::Routed, "route trace").into(),
        );
    }
    if cfg.characterise {
        ctx.record_refusal(
            RefusedStep::pass_not_in_an_idle_scan(ScannerKind::Routed, "filter characterisation")
                .into(),
        );
    }
    if !cfg.ip_protocols.is_empty() {
        ctx.record_refusal(
            RefusedStep::pass_not_in_an_idle_scan(ScannerKind::Routed, "IP-protocol probe").into(),
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
    capture_links: Vec<Zone>,
    cfg: &ZondConfig,
    ctx: ScanContext,
) -> JoinHandle<ScanReport> {
    // A sitting an earlier one left no address to ask sends nothing, unless it
    // sweeps a segment, which it may with no address of its own; see
    // `sitting_probes`.
    let sends = !targets.is_empty() || cfg.segment_sweep;
    let caps = ScanCapabilities::resolve(
        cfg,
        sends.then(orchestrator::Probing::sweep),
        &targets,
        interface::FrameSender::Sweep,
    );

    // Narrows `targets` as it records them, so nothing below can probe an
    // excluded address. Addresses a sweep finds for itself never pass through
    // here, and are gated on the context instead.
    let scope = address_scope(&mut targets, &ctx);
    let recorder =
        PhaseRecorder::start(ScanKind::Discovery, caps.privilege, scope, cfg).opening_in(&ctx);

    let reach = if cfg.segment_sweep {
        Scope::Sweep
    } else {
        Scope::Targeted
    };
    let cfg = cfg.clone();
    let held_back = crate::system::descriptors::hold_back();

    tokio::spawn(async move {
        // Held for as long as the sweep runs; see `descriptors::hold_back`.
        let _held_back = held_back;
        // Before the sweep opens a capture, so each listens only where a
        // reply to it can arrive.
        ctx.capture_on(capture_links);
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
        orchestrator::run_characterise(&ctx, &cfg, caps).await;
        orchestrator::run_ip_protocols(&ctx, &cfg).await;
        ctx.enter_stage(Stage::Finishing, None);
        // Last, and after every strategy that could add an address: what this
        // machine's own interfaces and routes say about what was found.
        vantage::attribute(&ctx);
        orchestrator::run_correlation(&ctx, cfg.service_detection);
        recorder.finish_last(ctx)
    })
}

/// The exclusions `ctx` holds a phase's targets to: the addresses written,
/// and every address a machine they name answers at, as far as the scan has
/// learned it. See
/// [the machine an address names](crate::model::exclusion#an-address-names-a-machine).
fn machine_policy(ctx: &ScanContext) -> crate::model::exclusion::Exclusions {
    ctx.exclusions.widened(ctx.withheld_by_hardware())
}

/// Narrows `targets`, the addresses a phase was handed, to what the
/// exclusions let it ask, and records what that cost as the phase's scope.
///
/// Held to [`machine_policy`], so an address the neighbour tables tie to an
/// excluded machine is sent nothing and listed among the excluded. One the
/// plan numbers is settled as withheld where it stands: a sweep that dropped
/// it unsettled would owe it to every later sitting, which would drop it
/// again.
fn address_scope(targets: &mut IpSet, ctx: &ScanContext) -> TargetScope {
    let tied = ctx.withheld_by_hardware();
    for address in &tied {
        if targets.contains(address) {
            ctx.settle_withheld(*address);
        }
    }
    TargetScope::from_ip_set(targets, &ctx.exclusions.widened(tied))
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
/// Held here to [`ZondConfig::excluded_ports`], so neither caller can send a
/// liveness probe to a port the scan may not probe.
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
    let syn_ports = syn_ports.excluding(&cfg.excluded_ports);
    if caps.privilege.is_raw() {
        let unframed =
            caps.beyond_frames(&targets, &cfg.send_source, interface::FrameSender::Sweep);
        let mut plan =
            plan::DiscoveryPlan::build(targets, reach, &cfg.exclusions, &cfg.send_source);
        plan.connect_instead(&unframed.targets);
        plan.asking_tcp(syn_ports);
        for address in plan.refused_by_route().iter() {
            ctx.note_refused_by_route(address);
        }
        if let Some(port) = sctp_port {
            plan.also_over_sctp(port);
        }
        orchestrator::reached_by_connect(&plan, unframed, ctx);
        let enrichment = Enrichment::spawn(plan, ctx, caps, cfg.probe_tuning()).await;
        finish_enrichment(Some(enrichment), caps, ctx, rdns::Unheard::Skipped).await;
    } else {
        let targets = orchestrator::walkable(targets, ctx);
        if syn_ports.is_empty() {
            ctx.record_refusal(
                plan::RefusedStep::every_discovery_port_excluded(ScannerKind::Connect).into(),
            );
        } else if let Err(error) =
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
        .naming(cfg.target_names.clone())
        .host_timeout(cfg.host_timeout)
        .scan_timeout(cfg.scan_timeout)
        .host_probe_interval(cfg.host_probe_interval)
        .staging(vec![Stage::Listening])
        .build();
    let handle = spawn_listen(scope, cfg, ctx);
    let stop = session.handle().clone();
    Ok((session, ScanTask::new(handle, stop)))
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
///
/// # A watch records no options
///
/// A scan's journal records the options its first sitting ran under and holds
/// every later one to them, because a sitting asking another way would file
/// answers to another question as the same job's; see
/// [`JobOptions`](crate::journal::manifest::JobOptions). A watch asks nothing.
/// It sends no probe, so no technique, retry policy, evasion profile or
/// probing pass reaches the wire from it, and what it hears is what the link
/// carried whatever it was configured with. What its configuration does
/// decide, whether heard traffic is read for an operating system and how far
/// a service it names is correlated, is how the answers are read rather than
/// what was asked: in a scan those settings send probes of their own, and in
/// a watch they send none. Each sitting's phase records the settings it ran
/// under, so a report shows which sitting read its traffic which way. Held to
/// a scan's options, a resumed watch would be refused over settings it never
/// reads.
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
        .naming(cfg.target_names.clone())
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

    let stop = session.handle().clone();
    Ok((
        session,
        ScanTask::journalling(handle, stop, ticker, earlier),
    ))
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
        )
        .opening_in(&ctx);

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
        recorder.finish_last(ctx)
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

/// Takes out of `target_map` every target [`scan`] withholds rather than
/// probes: a link-local range that names no interface, an address two
/// link-local ranges name on two different ones, and an IPv6 range too wide
/// to walk one address at a time.
///
/// A scan takes these out before it numbers its plan and names each in its
/// report as refused, so what is left is what it asks. A caller measuring
/// what a scan will cost before starting it does this to a copy, as it does
/// [`TargetMap::withhold_ports`] with the ports it excludes.
pub fn withhold_unprobeable(target_map: &mut TargetMap) {
    target_map.take_unprobeable(&[], interface::is_enumerable);
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

    let mut target_map = target_map;
    target_map.withhold_ports(&cfg.excluded_ports);
    let withheld = orchestrator::withhold_unprobeable_targets(&mut target_map);
    let capture_links = capture_plan(&plan_addresses(&target_map), cfg)?;
    let planned = planned_targets(&target_map);
    let runs_liveness = liveness_earns_its_place(cfg, &target_map);

    let (session, ctx) = ScanSession::builder()
        .excluding(cfg.exclusions.clone())
        .naming(cfg.target_names.clone())
        .host_timeout(cfg.host_timeout)
        .scan_timeout(cfg.scan_timeout)
        .host_probe_interval(cfg.host_probe_interval)
        .send_source(cfg.send_source.clone())
        .listening_only_to(cfg.listen_only_ports.clone())
        .detections(detections)
        .planning(Stage::Ports, planned)
        .staging(scan_stages(cfg, runs_liveness))
        .build();
    let handle = spawn_scan(
        target_map,
        withheld,
        capture_links,
        cfg,
        ctx,
        Checkpoint::default(),
        runs_liveness,
    );
    let stop = session.handle().clone();
    Ok((session, ScanTask::new(handle, stop)))
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
/// So `target_map`, less what `cfg`'s exclusions withhold, has to be the plan
/// the journal was counted in, and this process has to hold the privilege it
/// was counted under. A scan handed anything else is refused as
/// [`ScanError::PlanChanged`] before it sends anything. The recorded plan,
/// [`JournalManifest::recorded`](crate::journal::manifest::JournalManifest::recorded),
/// always is.
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
    let mut capture_links = Vec::new();
    let journal = accepted(journal, |journal| {
        cfg.evasion.validate()?;
        // Over the plan as the sitting will number it, which the excluded
        // ports and the withholding below leave alike in every sitting.
        let mut probed = target_map.clone();
        probed.withhold_ports(&cfg.excluded_ports);
        orchestrator::withhold_unprobeable_targets(&mut probed);
        capture_links = capture_plan(&plan_addresses(&probed), cfg)?;
        if journal.manifest().kind() != ScanKind::PortScan {
            return Err(ScanError::WrongPhase);
        }
        let technique = journal.manifest().technique();
        let this_run =
            crate::journal::manifest::Plan::port_scan(&target_map, &cfg.exclusions, technique);
        counted_as_recorded(journal, &this_run)?;
        under_the_recorded_options(journal, cfg)
    })?;
    let cfg = &under_the_recorded_technique(&journal, cfg);
    let journal = recording_options(journal, cfg);
    // After the plan is held to the journal's, which records it as the caller
    // named it, and before anything numbers it. Numbered without the ports the
    // job excluded, so every sitting numbers what is left alike; the ones this
    // sitting adds are passed over where they stand. See `JobOptions`.
    let numbered_without = journal.options().map_or_else(
        || cfg.excluded_ports.clone(),
        crate::journal::manifest::JobOptions::excluded_ports,
    );
    let withheld_ports = cfg.excluded_ports.difference(&numbered_without);
    let mut target_map = target_map;
    target_map.withhold_ports(&numbered_without);
    let withheld = orchestrator::withhold_unprobeable_targets(&mut target_map);
    let runs_liveness = liveness_earns_its_place(cfg, &target_map);
    let finished = journal.finished_hosts().unwrap_or_else(|e| {
        crate::warn!("passes rerun for every host ({e})");
        Default::default()
    });
    // Numbered as the port phase numbers it, in what the exclusions leave.
    let mut numbered = target_map.clone();
    cfg.exclusions.withhold_targets(&mut numbered);
    let asked = orchestrator::unsettled_ips(&numbered, journal.resume_point());

    let (session, ctx) = ScanSession::builder()
        .excluding(cfg.exclusions.clone())
        .naming(cfg.target_names.clone())
        .host_timeout(cfg.host_timeout)
        .scan_timeout(cfg.scan_timeout)
        .host_probe_interval(cfg.host_probe_interval)
        .send_source(cfg.send_source.clone())
        .listening_only_to(cfg.listen_only_ports.clone())
        .withholding_ports(withheld_ports)
        .resuming(journal.resume_point())
        .finished(finished, asked)
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
    let handle = spawn_scan(
        target_map,
        withheld,
        capture_links,
        cfg,
        ctx,
        resume_point,
        runs_liveness,
    );

    let stop = session.handle().clone();
    Ok((
        session,
        ScanTask::journalling(handle, stop, ticker, earlier),
    ))
}

/// What a port scan's sitting probes with, or `None` for one an earlier
/// sitting left nothing to ask.
///
/// `numbered` is `target_map` less what the exclusions withhold, which is what
/// `settled` counts. A sitting with no target left asks no address whether it
/// is up and probes no port, so a line naming the probes it would send, or
/// the privilege it would send them with, describes a scan that is not
/// happening.
fn sitting_probes(
    cfg: &ZondConfig,
    target_map: &TargetMap,
    numbered: &TargetMap,
    settled: &Checkpoint,
) -> Option<orchestrator::Probing> {
    (!orchestrator::unsettled_ips(numbered, settled).is_empty())
        .then(|| orchestrator::Probing::ports(cfg, target_map))
}

/// Runs both phases of a port scan against an existing context.
///
/// The body of [`scan`], taking a context rather than making one so that a
/// caller journalling the scan can seed it from an earlier run and keep a handle
/// on it. Nothing here knows what a journal is.
/// `settled` is what an earlier sitting already covered, and is empty for a scan
/// that is not continuing one. `withheld` is what
/// [`orchestrator::withhold_unprobeable_targets`] took out of `target_map`,
/// refused in the port phase's record. `capture_links` is where its captures
/// listen, as [`capture_plan`] counted them.
#[allow(clippy::too_many_arguments)]
fn spawn_scan(
    target_map: TargetMap,
    withheld: orchestrator::Withheld,
    capture_links: Vec<Zone>,
    cfg: &ZondConfig,
    ctx: ScanContext,
    settled: Checkpoint,
    runs_liveness: bool,
) -> JoinHandle<ScanReport> {
    // The plan the port phase walks, numbered in what the exclusions leave of
    // it, and known before anything is announced.
    let mut numbered = target_map.clone();
    cfg.exclusions.withhold_targets(&mut numbered);
    let caps = ScanCapabilities::resolve(
        cfg,
        sitting_probes(cfg, &target_map, &numbered, &settled),
        &orchestrator::unsettled_ips(&numbered, &settled),
        interface::FrameSender::Probe,
    );
    // What the caller set, kept so the passes an idle scan turns off can be
    // named as declined rather than dropped, and the config the scan actually
    // runs under, which an idle scan holds to what sends the target nothing.
    let requested = cfg.clone();
    let cfg = running_under(&requested);
    let held_back = crate::system::descriptors::hold_back();

    tokio::spawn(async move {
        // Held for as long as the scan runs; see `descriptors::hold_back`.
        let _held_back = held_back;
        // Numbered before either phase runs, so an address either one files
        // as unreachable settles every target at it. The phases' scopes are
        // taken over what was asked, so they can say what the policy
        // withheld.
        ctx.number_targets(TargetIndex::of(&numbered));
        // Before any phase opens a capture, so each listens only where a
        // reply to this plan can arrive.
        ctx.capture_on(capture_links);

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
            // Read in the numbering the positions count, which is what the
            // policy leaves, and taken from the plan as it was asked, so the
            // scope still counts what the policy withheld.
            let unnumbered = Checkpoint::default();
            let mut finished = orchestrator::unsettled_ips(&numbered, &unnumbered);
            finished.subtract(&orchestrator::unsettled_ips(&numbered, &settled));
            let mut ips = orchestrator::unsettled_ips(&target_map, &unnumbered);
            ips.subtract(&finished);
            let scope = address_scope(&mut ips, &ctx);
            let recorder = PhaseRecorder::start(ScanKind::Discovery, caps.privilege, scope, &cfg)
                .opening_in(&ctx);

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
        // Held to the machines the policy names as well as to its addresses,
        // so the scope does not count what the walk will not ask. The plan is
        // subtracted by address alone, since it is numbered in what it keeps
        // and which addresses a machine answers at can differ between
        // sittings; the walk withholds the rest by position.
        let scope = TargetScope::from_target_map(&mut covered, &machine_policy(&ctx));
        let mut recorder = PhaseRecorder::start(ScanKind::PortScan, caps.privilege, scope, &cfg);
        if let Some(why) = skipped {
            recorder = recorder.skipping_liveness(why);
        }
        let recorder = recorder.opening_in(&ctx);

        ctx.enter_stage(Stage::Ports, None);
        // Filed against the port phase, since that is the phase an idle scan
        // has: it runs no liveness pass, so this is where a reader looks for
        // what the scan declined to send the target from this host.
        record_idle_refusals(&requested, &ctx);
        let port_scanner = match caps.privilege.is_raw() {
            true => ScannerKind::SynPort,
            false => ScannerKind::Connect,
        };
        withheld.refuse(&ctx, port_scanner);
        let stands_in = skipped == Some(LivenessSkip::PortsNoDearer);
        run_port_phase(
            numbered,
            withheld.zones(),
            live,
            &ctx,
            caps,
            &cfg,
            settled,
            stands_in,
        )
        .await;

        // Straight after the ports, because what it needs is the list of ports a
        // handshake completed against and the service pass is what produces it.
        orchestrator::run_tls_enumeration(&ctx, &cfg).await;

        // Ordered by what each pass leaves the next. The series probe takes
        // every host with a TCP answer, so the echo probe is left with the
        // machines that answered nothing at all.
        orchestrator::run_active_os_series(&ctx, cfg.os_detection, cfg.probe_tuning(), caps).await;
        orchestrator::run_active_os_snmp(&ctx, cfg.os_detection, &cfg.excluded_ports).await;
        // After the two that read a stack, because it asks only hosts that have
        // a name and answers a question neither of those can: macOS and iOS
        // share a kernel and are indistinguishable to a probe, while a
        // device-info record names the model outright.
        orchestrator::run_active_os_mdns(&ctx, cfg.os_detection, !cfg.no_dns, &cfg.excluded_ports)
            .await;
        orchestrator::run_active_os_probe(&ctx, cfg.os_detection, cfg.probe_tuning(), caps).await;
        // Last: the ports are what decide a trace's shape.
        orchestrator::run_traceroute(&ctx, &cfg, caps).await;
        orchestrator::run_characterise(&ctx, &cfg, caps).await;
        orchestrator::run_ip_protocols(&ctx, &cfg).await;
        ctx.enter_stage(Stage::Finishing, None);
        vantage::attribute(&ctx);
        orchestrator::run_correlation(&ctx, cfg.service_detection);
        orchestrator::run_cert_posture(&ctx);
        let report = recorder.finish_last(ctx);

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
    use crate::testing::loopback::accept_from_this_process;

    /// A sitting an earlier one left nothing to ask names no probes, and one
    /// with a target left names them.
    ///
    /// A resume of a finished job sends nothing. Told it probes with ARP,
    /// ICMPv6 and SYN, or that it lacks the privilege to, a reader takes it
    /// for a scan that is about to put packets on the network.
    #[test]
    fn a_sitting_with_nothing_left_to_ask_names_no_probes() {
        let mut map = TargetMap::new();
        map.add_unit(crate::model::target::TargetSet::new(
            "192.0.2.1".parse().expect("an address"),
            "80".parse().expect("a port"),
        ));
        let cfg = ZondConfig::default();

        let everything = Checkpoint::new(1, []);
        assert_eq!(sitting_probes(&cfg, &map, &map, &everything), None);
        assert!(
            sitting_probes(&cfg, &map, &map, &Checkpoint::default()).is_some(),
            "a sitting with its target left to ask probes it"
        );
    }

    /// A scratch journal root, removed and made again for each test that
    /// names it.
    #[cfg(feature = "journal-format")]
    fn journal_root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("zond-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a scratch root");
        root
    }

    /// **A named address the neighbour tables tie to an excluded machine is
    /// withheld from a sweep's targets, counted and listed as the excluded
    /// address is, and settled.** An exclusion means the machine answering at
    /// the address written, and a target named at another of its addresses
    /// otherwise reached the wire. Unsettled, it would be owed to every later
    /// sitting, which would withhold it again.
    #[test]
    fn a_named_address_of_an_excluded_machine_leaves_the_sweeps_scope() {
        use crate::journal::settle::Outcome;
        use crate::model::exclusion::Exclusions;
        use crate::model::ip::set::{IpSet, Positions};
        use crate::model::mac::MacAddr;
        use std::net::IpAddr;

        let machine = MacAddr::new(0x02, 0, 0, 0, 0, 0x30);
        let excluded: IpAddr = "192.0.2.30".parse().expect("literal");
        let other: IpAddr = "192.0.2.40".parse().expect("literal");
        let mut policy = IpSet::new();
        policy.insert(excluded);
        let mut targets: IpSet = "192.0.2.39-192.0.2.41".parse().expect("a range");
        let (_session, ctx) = ScanSession::builder()
            .excluding(Exclusions::new(policy))
            .with_neighbours(vec![(excluded, Some(machine)), (other, Some(machine))])
            .counting(Positions::of(&targets))
            .build();

        let scope = address_scope(&mut targets, &ctx);

        assert!(!targets.contains(&other), "it is still a target");
        assert_eq!(targets.len(), 2);
        assert_eq!((scope.addresses(), scope.withheld()), (2, 1));
        let excluded_starts: Vec<IpAddr> = scope
            .excluded()
            .iter()
            .map(|range| range.start_addr())
            .collect();
        assert!(excluded_starts.contains(&other), "{excluded_starts:?}");
        assert!(excluded_starts.contains(&excluded), "{excluded_starts:?}");
        assert_eq!(
            ctx.settlements().count(Outcome::Withheld { position: 0 }),
            1
        );
        assert_eq!(ctx.settlements().checkpoint().settled_count(), 1);
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
        let journal = Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
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
        let journal = Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
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

    /// **A raw scan's up-front need counts a capture device for every link it
    /// will capture on, and a scan by connect counts none.**
    ///
    /// Left out of the need, a table with room for the reserve alone lets the
    /// scan start and refuses its captures one link at a time, and what those
    /// links carry is never heard. Counted for every link of the machine
    /// instead, a scan of loopback on a machine with dozens of links is
    /// refused a limit it has plenty of room under.
    #[test]
    fn a_raw_scan_needs_a_capture_device_for_each_link_it_captures_on() {
        use crate::model::ip::scoped::Zone;

        let links = [Zone::new(1, "lo0"), Zone::new(4, "en0")];
        assert_eq!(captures_needed(Privilege::Raw, &links), 2);
        assert_eq!(captures_needed(Privilege::Connect, &links), 0);
    }

    /// A scan of loopback counts, and captures on, loopback's link and no
    /// other, whatever else the machine has up.
    #[test]
    fn a_scan_of_loopback_plans_its_captures_on_loopback_alone() {
        let cfg = ZondConfig::default();
        let links =
            capture_plan(&"127.0.0.1".parse().expect("an address"), &cfg).expect("room for it");

        let loopback: Vec<_> = crate::system::interface::interfaces()
            .expect("this machine's interfaces")
            .into_iter()
            .filter(crate::system::interface::Link::is_loopback)
            .map(|link| link.zone())
            .collect();
        assert_eq!(links, loopback);
    }

    /// A port scan of a range too wide to walk refuses it in its port phase
    /// and ends. Left in the plan, the liveness pass refuses it and leaves its
    /// targets undecided, and the walk then settles them one at a time for
    /// longer than the process lives: the task never resolves and a stop
    /// cannot end it promptly.
    #[tokio::test]
    async fn a_port_scan_of_a_range_too_wide_to_walk_refuses_it_and_ends() {
        use crate::model::target::TargetSet;

        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "2001:db8::/64".parse().expect("a prefix"),
            "80,443".parse().expect("ports"),
        ));
        let cfg = ZondConfig {
            no_dns: true,
            ..ZondConfig::default()
        };

        let (_session, task) = scan(map, &cfg, Detections::embedded())
            .await
            .expect("the scan starts");
        // Generous: the scan has nothing to send and ends at once, and the
        // failure this guards against never ends at all.
        let report = tokio::time::timeout(std::time::Duration::from_secs(120), task)
            .await
            .expect("the scan ended")
            .expect("the scan ran");

        let refused: Vec<_> = report
            .phases()
            .iter()
            .filter(|phase| phase.kind() == ScanKind::PortScan)
            .flat_map(|phase| phase.refusals().iter())
            .filter(|refusal| refusal.reason().contains("too large to walk"))
            .collect();
        assert_eq!(refused.len(), 1, "{:?}", report.phases());
    }

    /// **A job naming a link-local target with no interface ahead of others
    /// numbers its plan once, and a finished sitting leaves nothing owed.**
    ///
    /// The target is refused rather than probed, and taken out of the plan the
    /// positions count. Numbered with it and walked without it, every target
    /// after it has two positions: the walk settles one, the job owes the
    /// other, and a resume walks a plan the first sitting never finished.
    #[cfg(feature = "journal-format")]
    #[tokio::test]
    async fn a_withheld_link_local_target_leaves_one_numbering_across_sittings() {
        use crate::journal::Journal;
        use crate::journal::manifest::Plan;
        use crate::model::ip::set::IpSet;
        use crate::model::target::TargetSet;
        use crate::testing::loopback::SilentPort;

        let peer = SilentPort::open();
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "fe80::1-fe80::2".parse::<IpSet>().expect("addresses"),
            "80".parse().expect("ports"),
        ));
        map.add_unit(TargetSet::new(
            IpSet::from(peer.addr().ip()),
            peer.addr().port().to_string().parse().expect("ports"),
        ));
        let cfg = ZondConfig {
            no_dns: true,
            assume_up: true,
            service_detection: crate::config::ServiceDetection::Off,
            ..ZondConfig::default()
        };
        let plan = Plan::port_scan(&map, &cfg.exclusions, cfg.tcp_technique);
        let root = journal_root("withheld-link-local");
        let journal = Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
        let directory = journal.directory().to_path_buf();

        let (session, task) = scan_with_journal(map.clone(), &cfg, Detections::embedded(), journal)
            .await
            .expect("the first sitting starts");
        let report = task.join().await.expect("it finishes");
        assert!(
            report
                .phases()
                .iter()
                .flat_map(|phase| phase.refusals())
                .any(|refusal| refusal.reason().contains("%en0")),
            "the unscoped targets are refused: {:?}",
            report.phases()
        );
        let progress = session.progress();
        assert_eq!(progress.planned(), Some(1), "the plan walked is one target");
        assert_eq!(
            progress.remaining(),
            Some(0),
            "and a finished sitting owes none"
        );

        let (journal, settled) =
            Journal::resume(&directory, &plan, Privilege::current()).expect("resumes");
        assert_eq!(settled.settled_count(), 1, "the job recorded it settled");
        let (session, task) = scan_with_journal(map, &cfg, Detections::embedded(), journal)
            .await
            .expect("the second sitting starts");
        let _report = task.join().await.expect("it finishes");
        assert_eq!(
            session.progress().remaining(),
            Some(0),
            "a resume walks the plan the first sitting numbered"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// A sweep counts what it settles, so its progress reads its work. Left
    /// uncounted, a plain sweep reported nothing settled and no fraction for
    /// the whole of its run, however far it got.
    #[tokio::test]
    async fn a_sweep_counts_the_addresses_it_settles() {
        let cfg = ZondConfig {
            no_dns: true,
            ..ZondConfig::default()
        };
        let (session, task) = discover("127.0.0.1".parse().expect("an address"), &cfg)
            .await
            .expect("the sweep starts");
        let _report = task.await.expect("the sweep ran");

        let progress = session.progress();
        assert_eq!(progress.planned(), Some(1));
        assert_eq!(progress.settled(), 1, "the one address answered");
    }

    /// **Dropping the task stops the scan.** Nothing can read the report of a
    /// scan whose task is gone, and one left running keeps its sockets and
    /// its probes going until it ends on its own, which for a listener is
    /// never. The scan winds down rather than vanishing, so the session's
    /// stream still ends, the way it ends for any scan that is over.
    #[tokio::test]
    async fn dropping_the_task_stops_the_scan() {
        use crate::model::target::TargetSet;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free port");
        let port = listener.local_addr().expect("its address").port();
        // Takes every connection and says nothing, for as long as the test runs.
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok(stream) = accept_from_this_process(&listener).await {
                held.push(stream);
            }
        });

        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "127.0.0.1".parse().expect("an address"),
            port.to_string().parse().expect("a port"),
        ));
        let cfg = ZondConfig {
            no_dns: true,
            service_detection: crate::config::ServiceDetection::Thorough,
            ..ZondConfig::default()
        };
        let (mut session, task) = scan(map, &cfg, Detections::embedded())
            .await
            .expect("the scan starts");
        drop(task);

        assert_eq!(
            session.handle().stopped(),
            Some(handle::StopCause::Aborted),
            "the scan runs on with nobody to collect it"
        );
        while session.events().recv().await.is_some() {}
    }

    /// A scan stopped before it reached its ports starts none of the passes
    /// that follow them. Each announces its stage before it sends anything,
    /// so a stage announced after the stop is a pass that went on to open its
    /// sockets and send its first burst to a caller who asked for an end.
    #[tokio::test]
    async fn a_scan_stopped_before_its_ports_starts_no_later_pass() {
        use crate::model::target::TargetSet;
        use crate::scanner::session::ScanEvent;

        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "127.0.0.1".parse().expect("an address"),
            "1-16".parse().expect("ports"),
        ));
        let cfg = ZondConfig {
            no_dns: true,
            os_detection: crate::config::OsDetection::Active,
            traceroute: true,
            tls_enumeration: true,
            ..ZondConfig::default()
        };

        let (mut session, task) = scan(map, &cfg, Detections::embedded())
            .await
            .expect("the scan starts");
        session.handle().abort();
        let _report = task.await.expect("the scan ran");

        let mut stages = Vec::new();
        while let Some(event) = session.events().try_recv() {
            if let ScanEvent::StageChanged { stage } = event {
                stages.push(stage);
            }
        }
        assert!(
            stages
                .iter()
                .all(|stage| matches!(stage, Stage::Discovery | Stage::Ports | Stage::Finishing)),
            "a pass began after the stop: {stages:?}"
        );
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

        let mut journal = Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
        journal
            .record_options(JobOptions::of(&first))
            .expect("records");
        let settlements = Settlements::default();
        settlements.record(Outcome::Answered { position: 0 });
        journal.checkpoint(&settlements).expect("checkpoints");
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let (journal, _) =
            Journal::resume(&directory, &plan, Privilege::current()).expect("resumes");
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

    /// **A job recorded before its options were resumes under the technique
    /// its manifest names, not the one this sitting was handed.**
    ///
    /// The technique is part of what the job asks: a sitting under another
    /// files segments of another kind as the same job's answers, and nothing
    /// else refuses one that recorded no options to be held to. So a settings
    /// file edited between sittings would change what an older job asks,
    /// silently.
    #[cfg(feature = "journal-format")]
    #[tokio::test]
    async fn a_job_recorded_without_options_resumes_under_its_manifests_technique() {
        use crate::journal::Journal;
        use crate::journal::manifest::Plan;
        use crate::model::ip::set::IpSet;
        use crate::model::target::TargetSet;
        use crate::model::technique::TcpScanTechnique;

        let root = journal_root("recorded-technique");
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "127.0.0.1".parse::<IpSet>().expect("an address"),
            "9".parse().expect("ports"),
        ));
        let cfg = ZondConfig {
            no_dns: true,
            assume_up: true,
            ..ZondConfig::default()
        };
        assert_ne!(cfg.tcp_technique, TcpScanTechnique::Ack, "test premise");

        let plan = Plan::port_scan(&map, &cfg.exclusions, TcpScanTechnique::Ack);
        let journal = Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");
        let (journal, _) =
            Journal::resume(&directory, &plan, Privilege::current()).expect("resumes");
        assert!(journal.options().is_none(), "test premise: no options");

        let (_session, task) = scan_with_journal(map, &cfg, Detections::embedded(), journal)
            .await
            .expect("the sitting starts");
        let report = task.join().await.expect("it finishes");

        let ports = report
            .phases()
            .iter()
            .find(|phase| phase.kind() == ScanKind::PortScan)
            .expect("a port phase");
        assert_eq!(ports.settings().tcp_technique, TcpScanTechnique::Ack);

        std::fs::remove_dir_all(&root).ok();
    }

    /// A watch's journal records no options, so a watch resumed under other
    /// settings is continued rather than refused over options it never reads.
    #[cfg(feature = "journal-format")]
    #[tokio::test]
    async fn a_watch_records_no_options_to_hold_a_later_sitting_to() {
        use crate::journal::Journal;
        use crate::journal::manifest::Plan;
        use crate::model::ip::scoped::Zone;

        let root = journal_root("watch-options");
        // A link no machine has, so the watch ends as soon as its capture is
        // refused, having sent nothing and heard nothing.
        let links = vec![Zone::new(u32::MAX, "zond-no-such-link")];
        let plan = Plan::listen(links.clone());
        let scope =
            || ListenScope::on(links.clone()).for_at_most(std::time::Duration::from_millis(1));

        let journal = Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
        let directory = journal.directory().to_path_buf();
        let (_session, task) = listen_with_journal(scope(), &ZondConfig::default(), journal)
            .await
            .expect("the watch starts");
        let _ = task.join().await.expect("it ends");
        assert!(
            !directory.join("options.json").exists(),
            "a watch recorded options"
        );

        let (journal, _) =
            Journal::resume(&directory, &plan, Privilege::current()).expect("resumes");
        let other = ZondConfig {
            traceroute: true,
            tcp_technique: crate::model::technique::TcpScanTechnique::Fin,
            ..ZondConfig::default()
        };
        let (_session, task) = listen_with_journal(scope(), &other, journal)
            .await
            .expect("a watch resumed under other settings continues");
        let _ = task.join().await.expect("it ends");

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

    /// A resumed sitting handed the plan as it was named, beside the policy
    /// that withholds part of it, asks the liveness pass about exactly the
    /// addresses the job has a target left at.
    ///
    /// Positions count what the policy leaves, so read against the plan
    /// before the policy they name other addresses: here the pass would ask
    /// again about an address the first sitting settled.
    #[cfg(feature = "journal-format")]
    #[tokio::test]
    async fn a_resumed_liveness_pass_counts_what_the_policy_leaves() {
        use crate::journal::Journal;
        use crate::journal::manifest::Plan;
        use crate::journal::settle::{Outcome, Settlements};
        use crate::model::exclusion::Exclusions;
        use crate::model::target::TargetSet;

        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "127.0.0.1-127.0.0.4".parse().expect("addresses"),
            // More than the pass asks, so it earns its place.
            "1-100".parse().expect("ports"),
        ));
        let cfg = ZondConfig {
            no_dns: true,
            // What is asserted is the pass's scope, which is fixed before it
            // sends anything; the addresses past 127.0.0.1 answer nothing.
            scan_timeout: Some(std::time::Duration::from_secs(1)),
            exclusions: Exclusions::new("127.0.0.1".parse().expect("an address")),
            ..ZondConfig::default()
        };
        let plan = Plan::port_scan(&map, &cfg.exclusions, cfg.tcp_technique);

        let root = journal_root("liveness-numbering");
        let mut journal = Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
        // Every target at the first two addresses the policy leaves, 127.0.0.2
        // and .3, which counted before the policy are those at .1 and .2.
        let settlements = Settlements::default();
        for position in 0..200 {
            settlements.record(Outcome::Answered { position });
        }
        journal.checkpoint(&settlements).expect("checkpoints");
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let (journal, _) =
            Journal::resume(&directory, &plan, Privilege::current()).expect("resumes");
        let (_session, task) = scan_with_journal(map, &cfg, Detections::embedded(), journal)
            .await
            .expect("the sitting starts");
        let report = task.join().await.expect("the sitting ends");

        let liveness = report
            .phases()
            .iter()
            .find(|phase| phase.kind() == ScanKind::Discovery)
            .expect("a liveness pass ran");
        assert_eq!(
            liveness.targets().addresses(),
            1,
            "{:?}",
            liveness.targets().ranges()
        );
        assert_eq!(liveness.targets().withheld(), 1, "the policy's cost went");
        std::fs::remove_dir_all(&root).ok();
    }

    /// A sitting killed after a checkpoint leaves its hosts owed every pass.
    ///
    /// Its checkpoints write down its phases as they stand, and a phase still
    /// open reads as one nothing stopped, so a resume sees the killed sitting
    /// beside the finished ones. Only a sitting's own close, which a killed one
    /// never reaches, says it ran to its end; read off what stands on disk,
    /// its hosts would be taken for finished and never identified.
    #[cfg(feature = "journal-format")]
    #[tokio::test]
    async fn a_sitting_killed_after_a_checkpoint_leaves_its_hosts_owed() {
        use crate::journal::Journal;
        use crate::journal::manifest::Plan;
        use crate::model::exclusion::Exclusions;
        use crate::model::host::HostStatus;
        use crate::model::ip::set::IpSet;
        use crate::model::target::TargetSet;
        use crate::scanner::checkpoint::{CHECKPOINT_EVERY, spawn_checkpoints};

        let address: std::net::IpAddr = "127.0.0.1".parse().expect("an address");
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            IpSet::from(address),
            "80".parse().expect("ports"),
        ));
        let cfg = ZondConfig::default();
        let plan = Plan::port_scan(&map, &cfg.exclusions, cfg.tcp_technique);
        let root = journal_root("killed-owed");
        let journal = Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
        let directory = journal.directory().to_path_buf();

        // A sitting with its port phase open and a host found, killed once one
        // checkpoint has landed.
        let (_session, ctx) = ScanSession::new();
        let mut scope = IpSet::from(address);
        let _open = PhaseRecorder::start(
            ScanKind::PortScan,
            Privilege::current(),
            TargetScope::from_ip_set(&mut scope, &Exclusions::none()),
            &cfg,
        )
        .opening_in(&ctx);
        ctx.update_host(address, |host| host.set_status(HostStatus::Up));
        let ticker = spawn_checkpoints(journal, ctx.progress());
        tokio::time::sleep(CHECKPOINT_EVERY + std::time::Duration::from_millis(200)).await;
        ticker.kill().await;

        let (journal, _) =
            Journal::resume(&directory, &plan, Privilege::current()).expect("resumes");
        assert!(
            journal
                .earlier_phases()
                .iter()
                .any(|phase| phase.stopped().is_none()),
            "the killed sitting's standing phase is read back"
        );
        let finished = journal.finished_hosts().expect("reads");
        let (_resumed, resumed) = ScanSession::builder()
            .finished(finished.clone(), IpSet::new())
            .build();
        resumed.restore_hosts(journal.restored());
        let owed = resumed
            .read_host(address, |host| resumed.owes_passes(host))
            .expect("the host came back");
        assert!(
            owed,
            "a killed sitting's host was taken as finished: {finished:?}"
        );

        journal.close().expect("closes");
        std::fs::remove_dir_all(&root).ok();
    }

    /// A sitting that ran to its end writes down every host it held as
    /// finished, and one that was stopped writes down none, since its passes
    /// may not have reached them.
    #[cfg(feature = "journal-format")]
    #[tokio::test]
    async fn only_a_sitting_that_ran_to_its_end_records_its_hosts_finished() {
        use crate::journal::Journal;
        use crate::journal::manifest::Plan;
        use crate::model::target::TargetSet;

        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "127.0.0.1".parse().expect("an address"),
            "9".parse().expect("ports"),
        ));
        let cfg = ZondConfig {
            no_dns: true,
            assume_up: true,
            ..ZondConfig::default()
        };
        let plan = Plan::port_scan(&map, &cfg.exclusions, cfg.tcp_technique);

        for stopped in [false, true] {
            let root = journal_root(&format!("records-finished-{stopped}"));
            let journal = Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
            let directory = journal.directory().to_path_buf();
            let (session, task) =
                scan_with_journal(map.clone(), &cfg, Detections::embedded(), journal)
                    .await
                    .expect("the sitting starts");
            if stopped {
                session.handle().abort();
            }
            let report = task.join().await.expect("the sitting ends");
            assert!(report.host_count() > 0 || stopped, "the host was not found");

            let (journal, _) =
                Journal::resume(&directory, &plan, Privilege::current()).expect("resumes");
            let finished = journal.finished_hosts().expect("reads");
            assert_eq!(
                finished.contains("127.0.0.1"),
                !stopped,
                "stopped: {stopped}, finished: {finished:?}"
            );
            drop(journal);
            std::fs::remove_dir_all(&root).ok();
        }
    }

    /// A resumed sitting runs the passes that follow the probes, here the
    /// detections, over a host an earlier sitting ran to its end with only
    /// where it has something left to ask there, and over a host no sitting
    /// finished whatever it has left.
    ///
    /// Resuming a job that was already done would otherwise put every one of
    /// its identification questions to the network again, and a job resumed
    /// part way would ask them again of every host it had finished with, and
    /// write each of those hosts down whole again for having been asked.
    #[cfg(feature = "journal-format")]
    #[tokio::test]
    async fn a_resumed_job_asks_a_host_a_sitting_finished_nothing_it_already_asked() {
        use crate::journal::Journal;
        use crate::journal::manifest::Plan;
        use crate::journal::settle::{Outcome, Settlements};
        use crate::model::host::{Host, HostStatus};
        use crate::model::port::{Port, PortState, Protocol, Service};
        use crate::model::target::TargetSet;

        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "127.0.0.1".parse().expect("an address"),
            "80".parse().expect("ports"),
        ));
        let cfg = ZondConfig {
            no_dns: true,
            ..ZondConfig::default()
        };
        let plan = Plan::port_scan(&map, &cfg.exclusions, cfg.tcp_technique);

        // A job whose one target an earlier sitting settled, finding a web
        // server; `finished` says whether that sitting ran to its end.
        let resumed = |finished: bool| {
            let (root, map, cfg, plan) = (
                journal_root(&format!("finished-{finished}")),
                map.clone(),
                cfg.clone(),
                plan.clone(),
            );
            async move {
                let mut journal =
                    Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
                let mut host = Host::new("127.0.0.1".parse().expect("an address"));
                host.set_status(HostStatus::Up);
                host.add_port(
                    Port::new(80, Protocol::Tcp, PortState::Open)
                        .with_service(Service::new("http", 100)),
                );
                journal.record_hosts(&[host]).expect("records the host");
                let settlements = Settlements::default();
                settlements.record(Outcome::Answered { position: 0 });
                journal.checkpoint(&settlements).expect("checkpoints");
                if finished {
                    journal
                        .record_finished(["127.0.0.1".to_string()])
                        .expect("records the sitting's end");
                }
                let directory = journal.directory().to_path_buf();
                journal.close().expect("closes");

                let written = |directory: &std::path::Path| {
                    std::fs::metadata(directory.join("hosts.jsonl")).map_or(0, |file| file.len())
                };
                let before = written(&directory);
                let (journal, _) =
                    Journal::resume(&directory, &plan, Privilege::current()).expect("resumes");
                let (_session, task) =
                    scan_with_journal(map, &cfg, Detections::embedded(), journal)
                        .await
                        .expect("the sitting starts");
                let _report = task.join().await.expect("the sitting ends");

                let runs = crate::journal::store::read_detections(&directory).expect("reads");
                let rewritten = written(&directory) > before;
                std::fs::remove_dir_all(&root).ok();
                (runs.len(), rewritten)
            }
        };

        let (runs, _) = resumed(false).await;
        assert!(
            runs > 0,
            "a host no sitting finished is owed its detections"
        );
        let (runs, rewritten) = resumed(true).await;
        assert_eq!(runs, 0, "a finished host was asked its detections again");
        assert!(!rewritten, "a finished host was written down again");
    }

    /// A port an earlier sitting found open and identified, and was killed
    /// before its detections ran, is given the findings a sitting that ran to
    /// its end draws there.
    ///
    /// A passive detection reads what identifying the port drew, and a sitting
    /// keeps that in memory alone. The port's record comes back from the
    /// journal and settles its target, so the resume asks the port nothing
    /// in its probes; without the port being identified again, every
    /// detection that reads a service's own words has nothing to read, and
    /// the resumed report is short of findings with nothing to say so.
    #[cfg(feature = "journal-format")]
    #[tokio::test]
    async fn a_resume_draws_the_detections_a_killed_sitting_owed_a_port_it_settled() {
        use crate::journal::Journal;
        use crate::journal::manifest::Plan;
        use crate::journal::settle::{Outcome, Settlements};
        use crate::model::host::{Host, HostStatus};
        use crate::model::port::{Port, PortState, Protocol, Service};
        use crate::model::target::TargetSet;
        use crate::testing::loopback::accept_from_this_process;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // A web server that sends none of the headers a browser is told to
        // enforce, which a passive detection reads off its reply.
        let web_server = || async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("binds loopback");
            let addr = listener.local_addr().expect("a local address");
            tokio::spawn(async move {
                while let Ok(mut sock) = accept_from_this_process(&listener).await {
                    tokio::spawn(async move {
                        let mut buffer = [0u8; 1024];
                        if !matches!(sock.read(&mut buffer).await, Ok(n) if n > 0) {
                            return;
                        }
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\
                                  Content-Type: text/html\r\nContent-Length: 0\r\n\
                                  Connection: close\r\n\r\n",
                            )
                            .await;
                    });
                }
            });
            addr
        };
        let addr = web_server().await;
        // Another the killed sitting had not reached yet, which leaves the
        // resume a target at the address: a sitting with one there asks it as
        // a sitting mid-job does, where one with nothing left may take another
        // strategy that identifies every port again anyway.
        let unreached = web_server().await.port();
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            addr.ip().into(),
            format!("{},{unreached}", addr.port())
                .parse()
                .expect("ports"),
        ));
        let cfg = ZondConfig {
            no_dns: true,
            ..ZondConfig::default()
        };
        let plan = Plan::port_scan(&map, &cfg.exclusions, cfg.tcp_technique);
        let settled = map
            .iter()
            .position(|target| target.port == addr.port())
            .expect("the server's port is planned") as u64;
        let findings = |report: &ScanReport| {
            report
                .hosts()
                .flat_map(Host::ports)
                .flat_map(Port::findings)
                .count()
        };

        let root = journal_root("owed-detections-whole");
        let journal = Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
        let (_session, task) =
            scan_with_journal(map.clone(), &cfg, Detections::embedded(), journal)
                .await
                .expect("the sitting starts");
        let whole = findings(&task.join().await.expect("the sitting ends"));
        std::fs::remove_dir_all(&root).ok();
        assert!(whole > 0, "the server draws no finding to lose");

        // The sitting killed between identifying the port and detecting on it:
        // the port settled and on record with its service, and nothing
        // finished.
        let root = journal_root("owed-detections-killed");
        let mut journal = Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
        let mut host = Host::new(addr.ip());
        host.set_status(HostStatus::Up);
        host.add_port(
            Port::new(addr.port(), Protocol::Tcp, PortState::Open)
                .with_service(Service::new("http", 90)),
        );
        journal.record_hosts(&[host]).expect("records the host");
        let settlements = Settlements::default();
        settlements.record(Outcome::Answered { position: settled });
        journal.checkpoint(&settlements).expect("checkpoints");
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let (journal, _) =
            Journal::resume(&directory, &plan, Privilege::current()).expect("resumes");
        let (_session, task) = scan_with_journal(map, &cfg, Detections::embedded(), journal)
            .await
            .expect("the sitting starts");
        let resumed = findings(&task.join().await.expect("the sitting ends"));
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(
            resumed, whole,
            "the resume drew other findings than one sitting"
        );
    }

    /// A sitting that excludes a port the job did not is continued, sends the
    /// port nothing, neither its probe nor a pass over what an earlier sitting
    /// found open there, and still skips what the job had settled.
    ///
    /// An exclusion only narrows a scan, and it is how a device that cannot
    /// take a probe is kept from one: refused, the one way to spare the port
    /// is to give up the job. Taken into the numbering, it would move every
    /// target after the port to another position, and the sitting would ask
    /// again what an earlier one settled and skip what it had not.
    #[cfg(feature = "journal-format")]
    #[tokio::test]
    async fn a_resume_excluding_another_port_sends_it_nothing_and_keeps_the_numbering() {
        use crate::journal::Journal;
        use crate::journal::manifest::{JobOptions, Plan};
        use crate::journal::settle::{Outcome, Settlements};
        use crate::model::host::{Host, HostStatus};
        use crate::model::port::{Port, PortSet, PortState, Protocol};
        use crate::model::target::TargetSet;
        use crate::testing::loopback::SilentPort;

        let (first, second) = (SilentPort::open(), SilentPort::open());
        // The one excluded is walked first, so a numbering without it would
        // give the other its position.
        let (excluded, settled) = if first.addr().port() < second.addr().port() {
            (first, second)
        } else {
            (second, first)
        };
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "127.0.0.1".parse().expect("an address"),
            format!("{},{}", excluded.addr().port(), settled.addr().port())
                .parse()
                .expect("ports"),
        ));
        let recorded = ZondConfig {
            no_dns: true,
            assume_up: true,
            ..ZondConfig::default()
        };
        let plan = Plan::port_scan(&map, &recorded.exclusions, recorded.tcp_technique);

        let root = journal_root("added-exclusion");
        let mut journal = Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
        journal
            .record_options(JobOptions::of(&recorded))
            .expect("records the options");
        // The port to be excluded found open already, and so on record for
        // every pass after the probes to reach.
        let mut host = Host::new("127.0.0.1".parse().expect("an address"));
        host.set_status(HostStatus::Up);
        host.add_port(Port::new(
            excluded.addr().port(),
            Protocol::Tcp,
            PortState::Open,
        ));
        journal.record_hosts(&[host]).expect("records the host");
        let settlements = Settlements::default();
        settlements.record(Outcome::Answered { position: 1 });
        journal.checkpoint(&settlements).expect("checkpoints");
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let mut cfg = recorded.clone();
        cfg.excluded_ports =
            PortSet::try_from(excluded.addr().port().to_string().as_str()).expect("a port");
        let (journal, _) =
            Journal::resume(&directory, &plan, Privilege::current()).expect("resumes");
        let (_session, task) = scan_with_journal(map, &cfg, Detections::embedded(), journal)
            .await
            .expect("a sitting excluding more is continued");
        let report = task.join().await.expect("the sitting ends");
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(excluded.connections(), 0, "the excluded port was asked");
        assert_eq!(settled.connections(), 0, "a settled target was asked again");
        assert!(
            report
                .hosts()
                .flat_map(Host::ports)
                .all(|port| port.number() != excluded.addr().port()),
            "the excluded port is still reported"
        );
        assert!(
            report
                .phases()
                .last()
                .expect("the sitting's phase")
                .settings()
                .excluded_ports
                .contains(excluded.addr().port(), Protocol::Tcp),
            "the report does not say the port was excluded"
        );
    }

    /// A job that excludes a port is finished once one sitting has asked
    /// everything else, and its record says so.
    ///
    /// The ports a job excludes are never numbered, so no sitting asks or
    /// settles them. Counted in the job's total, they are a remainder nothing
    /// ever reaches: the job lists as resumable with work left for good, is
    /// kept as unfinished by a retention sweep, and a resume announces probes
    /// to ports it will not send.
    #[cfg(feature = "journal-format")]
    #[tokio::test]
    async fn a_job_excluding_a_port_is_complete_once_it_has_asked_the_rest() {
        use crate::journal::Journal;
        use crate::journal::manifest::Plan;
        use crate::model::port::PortSet;
        use crate::model::target::TargetSet;
        use crate::testing::loopback::SilentPort;

        let (excluded, asked) = (SilentPort::open(), SilentPort::open());
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "127.0.0.1".parse().expect("an address"),
            format!("{},{}", excluded.addr().port(), asked.addr().port())
                .parse()
                .expect("ports"),
        ));
        let cfg = ZondConfig {
            no_dns: true,
            assume_up: true,
            excluded_ports: PortSet::try_from(excluded.addr().port().to_string().as_str())
                .expect("a port"),
            ..ZondConfig::default()
        };
        let plan = Plan::port_scan(&map, &cfg.exclusions, cfg.tcp_technique);

        let root = journal_root("excluded-complete");
        let journal = Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
        let (_session, task) = scan_with_journal(map, &cfg, Detections::embedded(), journal)
            .await
            .expect("the sitting starts");
        let _report = task.join().await.expect("the sitting ends");
        let listed = crate::journal::store::list(&root).expect("lists");
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(excluded.connections(), 0, "the excluded port was asked");
        let [entry] = listed.as_slice() else {
            panic!("one job on record: {listed:?}");
        };
        assert_eq!(
            (entry.settled(), entry.manifest.total_targets),
            (Some(1), 1),
            "settled against the total"
        );
        assert!(entry.is_complete(), "the finished job reads as unfinished");
    }

    /// A resumed sweep with nothing left to ask runs none of the passes that
    /// follow it over a host a sitting that ran to its end finished with.
    ///
    /// The sweep sends nothing, having nothing left, but its route trace, its
    /// operating-system and filter probes and the passes that write a
    /// conclusion back take the hosts the store holds, and a resume restores
    /// every host the job found: without the finished record each of them is
    /// traced and probed again, and written down whole again for it.
    #[cfg(feature = "journal-format")]
    #[tokio::test]
    async fn a_resumed_sweep_with_nothing_left_passes_nothing_over_what_it_finished() {
        use crate::journal::Journal;
        use crate::journal::manifest::Plan;
        use crate::model::ip::set::IpSet;

        let addresses: IpSet = "127.0.0.1".parse().expect("an address");
        let cfg = ZondConfig {
            no_dns: true,
            traceroute: true,
            ..ZondConfig::default()
        };
        let plan = Plan::discovery(&addresses, &cfg.exclusions, false);
        let root = journal_root("finished-sweep");
        let journal = Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
        let directory = journal.directory().to_path_buf();
        let (_session, task) = discover_with_journal(addresses.clone(), &cfg, journal)
            .await
            .expect("the sitting starts");
        let first = task.join().await.expect("the sitting ends");
        assert!(first.host_count() > 0, "loopback was not found");

        let written =
            || std::fs::metadata(directory.join("hosts.jsonl")).map_or(0, |file| file.len());
        let before = written();
        let (journal, _) =
            Journal::resume(&directory, &plan, Privilege::current()).expect("resumes");
        let (_session, task) = discover_with_journal(addresses, &cfg, journal)
            .await
            .expect("the sitting starts");
        let resumed = task.join().await.expect("the sitting ends");
        let after = written();
        std::fs::remove_dir_all(&root).ok();

        // Where this process may not trace, a sitting that owed the pass a
        // host files the refusal; one that may, traces it.
        let traced = resumed
            .phases()
            .last()
            .expect("the sitting's phase")
            .refusals()
            .iter()
            .any(|refusal| refusal.reason().contains("route trace"));
        assert!(!traced, "the finished host was owed its route trace");
        assert_eq!(after, before, "the finished host was written down again");
    }

    /// A port scan handed a journal counted over another plan, or under
    /// another privilege than this process sends with, is refused before it
    /// sends anything.
    ///
    /// A position is an index into the plan the journal was counted in. Taken
    /// over another plan, every position an earlier sitting settled would name
    /// a different target here, and the scan would skip ground nothing asked
    /// about and report it covered. Taken under another privilege, it would
    /// file one kind of answer as the other.
    #[cfg(feature = "journal-format")]
    #[tokio::test]
    async fn a_port_scan_handed_a_journal_of_another_plan_is_refused() {
        use crate::journal::Journal;
        use crate::journal::manifest::Plan;
        use crate::model::target::TargetSet;

        let root = journal_root("other-plan");
        let map = |ports: &str| {
            let mut map = TargetMap::new();
            map.add_unit(TargetSet::new(
                "127.0.0.1".parse().expect("an address"),
                ports.parse().expect("ports"),
            ));
            map
        };
        let cfg = ZondConfig::default();
        let recorded = Plan::port_scan(&map("1-100"), &cfg.exclusions, cfg.tcp_technique);

        let journal = Journal::create(&root, &recorded, Privilege::current(), "").expect("creates");
        let refused = scan_with_journal(map("1000-1100"), &cfg, Detections::embedded(), journal)
            .await
            .err();
        assert!(
            matches!(refused, Some(ScanError::PlanChanged(_))),
            "{refused:?}"
        );

        let other = Privilege::from_raw(!Privilege::current().is_raw());
        let journal = Journal::create(&root, &recorded, other, "").expect("creates");
        let refused = scan_with_journal(map("1-100"), &cfg, Detections::embedded(), journal)
            .await
            .err();
        assert!(
            matches!(refused, Some(ScanError::PlanChanged(_))),
            "{refused:?}"
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

        let mut journal = Journal::create(&root, &plan, Privilege::current(), "").expect("creates");
        let settlements = Settlements::default();
        settlements.record(Outcome::Answered { position: 0 });
        journal.checkpoint(&settlements).expect("checkpoints");
        let directory = journal.directory().to_path_buf();
        journal.close().expect("closes");

        let (journal, _) =
            Journal::resume(&directory, &plan, Privilege::current()).expect("resumes");
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
        use crate::transport::capture::{CaptureError, LibraryError};

        let denied = |link: &str| CaptureError::Denied {
            interface: link.into(),
            source: LibraryError::new(pcap::Error::PcapError("permission denied".into())),
        };
        let filter = CaptureError::Filter {
            filter: "ip6 and ether proto 0x86dd".into(),
            source: LibraryError::new(pcap::Error::PcapError("not an ethernet link".into())),
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

    /// Each pass an idle scan declines is said once, in a line that fits.
    ///
    /// A refusal reaches the report, and a front end prints the report's
    /// refusals beside its count at every verbosity. Logged as well when it is
    /// filed, each one read twice at `-v`, in two glyphs and two places. And
    /// each is one line on a console: `not covered: ` and the reason come to
    /// about sixty characters, where a pass named `active operating-system
    /// probing` and a clause on why it contacts the target came to ninety.
    #[test]
    fn an_idle_scans_declined_passes_are_filed_once_each_in_a_short_line() {
        use crate::config::{DetectionEnvelope, OsDetection};
        use crate::model::finding::DetectionClass;

        let cfg = ZondConfig {
            idle_scan: Some(crate::config::IdleScan::new(
                "192.0.2.9".parse().expect("an address"),
            )),
            os_detection: OsDetection::Active,
            traceroute: true,
            characterise: true,
            tls_enumeration: true,
            ip_protocols: [47].into_iter().collect(),
            detection: DetectionEnvelope::up_to(DetectionClass::ActiveBenign),
            ..ZondConfig::default()
        };
        let (_session, ctx) = ScanSession::new();

        let said = crate::logging::logged(|| record_idle_refusals(&cfg, &ctx));

        let refusals = ctx.take_refusals();
        assert_eq!(refusals.len(), 6, "{refusals:?}");
        for refusal in &refusals {
            let line = format!("not covered: {}", refusal.reason());
            assert!(line.len() <= 64, "{} characters: {line}", line.len());
        }
        assert!(
            said.iter()
                .all(|line| !line.message.contains("not covered")),
            "a refusal was said on filing as well as in the report: {said:?}"
        );
    }
}
