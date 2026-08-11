// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Scan Reports
//!
//! The finished record of a scan: what was asked for, what came back, what went
//! wrong on the way, and under which settings.
//!
//! During a scan a caller watches [`ScanSession`](crate::core::session::ScanSession) -
//! a live store plus an event stream, both of which describe the present moment
//! and keep no history. A [`ScanReport`] is the other half of that pair. It is
//! produced once, when the scan is over, and it is the only thing that can
//! answer a question asked afterwards: how long the sweep took, whether a
//! strategy failed part way through, how many addresses were actually in scope,
//! which retry budget produced this particular set of hosts.
//!
//! That distinction matters because a bare list of hosts is not a result anyone
//! can act on. "Nine hosts on a /24" means one thing after a
//! [`Thorough`](crate::core::models::retry::ScanEffort::Thorough) privileged
//! sweep and quite another after an unprivileged connect fallback that lost its
//! routed scanner to a permissions error. The hosts are identical in both; only
//! the report separates them.
//!
//! ## Phases
//!
//! Discovery and port scanning are separate engine calls, and a caller that
//! runs both is describing one job, not two. A report therefore holds a list of
//! [`ScanPhase`] records rather than a single set of metadata, and
//! [`ScanReport::merge`] folds the second call into the first: hosts are
//! merged by [`Host::merge`], phases are appended in the order they ran. A
//! single-phase report is simply the common case of that shape, not a different
//! type.
//!
//! ## Findings and instrumentation
//!
//! A phase carries two different kinds of record and they must not be read as
//! one. The hosts and their ports are findings *about the network*. The
//! [`ProbeStats`] a raw scanner files are measurements *about the scan* - how
//! many probes went out, how many segments came back, why the loop stopped -
//! and they exist to bound how much the findings can be trusted. A sweep that
//! stopped on [`StopReason::DeadlineExpired`] while replies were still arriving
//! found fewer hosts than the network holds, and nothing in the host list says
//! so.
//!
//! ## What is stored and what is derived
//!
//! Only measurements are stored. Every count a consumer might want - hosts up,
//! open ports, services identified - is computed by [`ScanReport::summary`] from
//! the hosts themselves, so a summary cannot drift out of step with the data it
//! describes.
//!
//! Hosts are held in a [`BTreeMap`] keyed by primary IP, so two scans of the
//! same network serialize in the same order and their outputs can be diffed.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use crate::core::config::{SendMode, ZondConfig};
use crate::core::models::host::{Host, HostStatus};
use crate::core::models::ip::range::IpRange;
use crate::core::models::ip::set::IpSet;
use crate::core::models::port::{PortState, Protocol};
use crate::core::models::retry::RetryConfig;
use crate::core::models::target::TargetMap;
use crate::core::models::technique::TcpScanTechnique;
use crate::core::session::{ScanContext, ScannerKind};
use crate::network::capture::CaptureCounts;

/// The version of the engine that produced a report.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Which of the two scan phases a [`ScanPhase`] records.
///
/// These are the engine's two entry points, [`discover`](crate::scanner::discover)
/// and [`scan`](crate::scanner::scan), not the individual strategies each one
/// spawns. Which strategies ran is a property of the host and its privileges;
/// see [`ScannerKind`] for the granularity at which failures are reported.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScanKind {
    /// Establishing which hosts in a target range are alive.
    Discovery,
    /// Classifying the ports of a known set of hosts.
    PortScan,
}

impl fmt::Display for ScanKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanKind::Discovery => write!(f, "discovery"),
            ScanKind::PortScan => write!(f, "port scan"),
        }
    }
}

/// What a phase was asked to cover.
///
/// The ranges are the canonical, merged form the engine actually iterated, not
/// the text a user typed. Overlapping arguments have already been coalesced, so
/// `addresses` is a count of distinct addresses rather than a sum of what was
/// requested, and a report can be trusted when it says a sweep covered 254
/// hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetScope {
    ranges: Vec<IpRange>,
    addresses: u128,
    probes: Option<u128>,
    protocols: Vec<Protocol>,
}

impl TargetScope {
    /// The scope of a discovery sweep, which has no port dimension.
    ///
    /// Canonicalizes the set, so the recorded ranges are the merged ones the
    /// sweep iterates rather than the raw arguments it was built from.
    pub fn from_ip_set(ips: &mut IpSet) -> Self {
        ips.canonicalize();

        let ranges = ip_set_ranges(ips);
        let addresses = ips.len();

        Self {
            ranges,
            addresses,
            probes: None,
            protocols: Vec::new(),
        }
    }

    /// The scope of a port scan, which pairs addresses with ports.
    ///
    /// `probes` counts address/port/protocol combinations, the unit a port scan
    /// is actually billed in. It is `None` when the target map is large enough
    /// to overflow that count, which is a failure to measure and is reported as
    /// one rather than as a plausible-looking number.
    pub fn from_target_map(targets: &mut TargetMap) -> Self {
        targets.canonicalize();

        let mut ranges = Vec::new();
        let mut protocols = Vec::new();
        for unit in &targets.units {
            ranges.extend(ip_set_ranges(unit.ips()));
            for (_, protocol) in unit.ports().iter() {
                if !protocols.contains(&protocol) {
                    protocols.push(protocol);
                }
            }
        }
        ranges.sort_by_key(|range| (range.start_addr(), range.end_addr()));
        ranges.dedup();
        protocols.sort();

        let addresses = targets.gross_ips().unwrap_or(0);
        let probes = targets.gross_targets().ok();

        Self {
            ranges,
            addresses,
            probes,
            protocols,
        }
    }

    /// The address ranges covered, in ascending order.
    pub fn ranges(&self) -> &[IpRange] {
        &self.ranges
    }

    /// How many distinct addresses were in scope.
    pub fn addresses(&self) -> u128 {
        self.addresses
    }

    /// How many address/port/protocol combinations were in scope, or `None` for
    /// a discovery sweep and for a target set too large to count.
    pub fn probes(&self) -> Option<u128> {
        self.probes
    }

    /// The transport protocols in scope, in ascending order. Empty for a
    /// discovery sweep, whose probes are chosen by the strategy rather than by
    /// the caller.
    pub fn protocols(&self) -> &[Protocol] {
        &self.protocols
    }
}

/// Returns every range of a set as protocol-agnostic [`IpRange`] values.
fn ip_set_ranges(ips: &IpSet) -> Vec<IpRange> {
    let v4 = ips.v4().iter().copied().map(IpRange::V4);
    let v6 = ips.v6().iter().copied().map(IpRange::V6);
    v4.chain(v6).collect()
}

/// The settings that shaped what a phase did.
///
/// A deliberate subset of [`ZondConfig`]: the fields here are the ones that
/// change which packets went out and how long the engine waited for answers, so
/// they are the ones needed to interpret - or reproduce - a result. The rest of
/// the config drives presentation (banner, verbosity, key handling) and has no
/// bearing on the finding, so recording it would only invite a reader to treat
/// a quieter terminal as a different scan.
///
/// Keeping this separate from [`ZondConfig`] also means the two can evolve
/// independently: a new interface knob does not silently become part of every
/// exported report.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScanSettings {
    /// How raw probes were placed on the wire.
    pub send_mode: SendMode,
    /// Which segment each TCP port probe carried, and so what its answers mean.
    ///
    /// Two ports both reported `Closed` are different findings depending on
    /// this: one refused a connection attempt, the other reset a segment that
    /// was not one. A report without it cannot be read.
    pub tcp_technique: TcpScanTechnique,
    /// The retransmission budget and patience in force.
    pub retry: RetryConfig,
    /// The probe-rate ceiling, or `None` if the scanner's own default applied.
    pub max_probe_rate: Option<u32>,
    /// Whether name resolution was permitted to generate traffic.
    pub dns_enabled: bool,
    /// Whether the caller asked for identifying detail to be masked.
    pub redact: bool,
}

impl From<&ZondConfig> for ScanSettings {
    fn from(cfg: &ZondConfig) -> Self {
        Self {
            send_mode: cfg.send_mode,
            tcp_technique: cfg.tcp_technique,
            retry: cfg.retry,
            max_probe_rate: cfg.max_probe_rate,
            dns_enabled: !cfg.no_dns,
            redact: cfg.redact,
        }
    }
}

/// Upper bounds, in milliseconds, of the discovery-time histogram buckets in
/// [`ProbeStats::found_at`]. A final bucket catches everything later than the
/// last bound.
///
/// These measure how far into the run a host was first credited, **not** its
/// round trip. The two diverge exactly where it matters: a host found at 700 ms
/// because its third attempt went out at 690 ms has a 10 ms round trip, and
/// reading the bucket as latency turns a retry schedule into an imaginary slow
/// path. Round trips are reported per host, not here.
///
/// Spaced roughly logarithmically because the question being asked spans three
/// orders of magnitude: a same-segment reply lands under a millisecond, a
/// healthy internet round trip in the tens, and a host recovered by a late
/// retry in the hundreds. A linear scale would put every interesting answer in
/// one bucket.
pub const BUCKET_BOUNDS_MS: [u64; 9] = [1, 2, 5, 10, 25, 50, 100, 250, 1_000];

/// How many attempts [`ProbeStats::answered_on`] counts separately before the
/// rest are lumped together.
///
/// Sized past the largest budget any path runs (five, under
/// [`ScanEffort::Thorough`](crate::core::models::retry::ScanEffort)), so the
/// distribution is reported in full for every configuration that ships and a
/// hand-raised budget still has somewhere to land.
pub const ATTEMPTS_COUNTED: usize = 6;

/// Why a scanner's receive loop stopped.
///
/// This is the single most informative field in an audit: a run that ends in
/// [`AllResponded`](StopReason::AllResponded) was not cut short by anything, and
/// one that ends in [`DeadlineExpired`](StopReason::DeadlineExpired) with
/// replies still arriving near the end almost certainly was.
///
/// There is deliberately no "still running" variant. A scan loop yields its
/// reason as the value it breaks with, so every exit path has to name one and
/// the audit cannot report a reason the code never took.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StopReason {
    /// The caller aborted the scan through the scan handle.
    Aborted,
    /// Every target answered.
    AllResponded,
    /// Nothing is left outstanding: every target either answered or was asked
    /// as many times as the retry budget allows. Like
    /// [`AllResponded`](StopReason::AllResponded) this is a scan that finished
    /// rather than one that ran out of time, and waiting longer could not have
    /// changed what it found.
    AttemptsSpent,
    /// The adaptive deadline expired: either the hard budget ran out or the
    /// silence tolerance did.
    DeadlineExpired,
    /// The capture stream closed underneath the scanner.
    StreamClosed,
}

impl StopReason {
    /// Whether the loop stopped because it had nothing left to do, rather than
    /// because something cut it short.
    ///
    /// A run that ends complete found everything it was ever going to find;
    /// waiting longer or sending more could not have changed it. One that does
    /// not is a result with a known upper bound on its own trustworthiness.
    pub fn is_complete(&self) -> bool {
        matches!(self, StopReason::AllResponded | StopReason::AttemptsSpent)
    }
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            StopReason::Aborted => "aborted by the caller",
            StopReason::AllResponded => "every target answered",
            StopReason::AttemptsSpent => "attempts spent",
            StopReason::DeadlineExpired => "deadline expired",
            StopReason::StreamClosed => "capture stream closed",
        };
        f.write_str(text)
    }
}

/// What one raw scanner observed about its own run.
///
/// A host count on its own cannot say why a sweep came back short, and the three
/// possible answers call for opposite fixes. Probes or replies may have been
/// **lost**, which is what retransmission exists for; replies may have arrived
/// after the scan had already **stopped**, which makes the deadline wrong rather
/// than the network; or they may have arrived and gone **unrecognized**, which
/// no amount of extra time or extra packets would help.
///
/// These counters separate those. [`sends_attempted`](Self::sends_attempted)
/// against [`segments_seen`](Self::segments_seen) bounds the first,
/// [`stop_reason`](Self::stop_reason) against
/// [`last_reply`](Self::last_reply) bounds the second, and
/// [`segments_off_target`](Self::segments_off_target) with
/// [`replies_without_rtt`](Self::replies_without_rtt) bounds the third.
///
/// One bound is not measurable from inside a scanner at all: a reply the kernel
/// discards because the capture buffer was full never reaches any counter here,
/// so loss on the receive path and loss on the network read identically.
/// [`capture`](Self::capture) is carried for that reason - it is the only place
/// the difference is visible.
///
/// This is instrumentation about the scan, not a finding about the network.
/// Nothing here changes what a scan reports about a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeStats {
    // Written by `ProbeAudit`, which lives in another module and so cannot use
    // private fields. Read-only to the outside world through the accessors
    // below: a consumer must never be able to edit a measurement.
    pub(crate) scanner: ScannerKind,
    pub(crate) targets: u128,
    pub(crate) stop_reason: StopReason,
    pub(crate) elapsed: Duration,
    pub(crate) sends_attempted: u64,
    pub(crate) sends_failed: u64,
    pub(crate) segments_seen: u64,
    pub(crate) segments_off_target: u64,
    pub(crate) replies_without_rtt: u64,
    pub(crate) hosts_found: u64,
    pub(crate) answered_on: [u64; ATTEMPTS_COUNTED],
    pub(crate) answered_unattributed: u64,
    pub(crate) first_reply: Option<Duration>,
    pub(crate) last_reply: Option<Duration>,
    pub(crate) found_at: [u64; BUCKET_BOUNDS_MS.len() + 1],
    pub(crate) capture: Option<CaptureCounts>,
}

impl ProbeStats {
    /// The strategy these counters belong to.
    pub fn scanner(&self) -> ScannerKind {
        self.scanner
    }

    /// How many targets this scanner owned.
    pub fn targets(&self) -> u128 {
        self.targets
    }

    /// Why the receive loop stopped.
    pub fn stop_reason(&self) -> StopReason {
        self.stop_reason
    }

    /// How long the scanner ran.
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Probes the scanner tried to put on the wire.
    pub fn sends_attempted(&self) -> u64 {
        self.sends_attempted
    }

    /// Of those, ones the sender refused. A non-zero count means the shortfall
    /// starts at home, before the network is implicated at all.
    pub fn sends_failed(&self) -> u64 {
        self.sends_failed
    }

    /// Segments the capture handed up, before any of the scanner's own checks.
    pub fn segments_seen(&self) -> u64 {
        self.segments_seen
    }

    /// Segments from an address outside this scan's target set. Expected to be
    /// small; a large count means the capture filter is admitting other traffic.
    pub fn segments_off_target(&self) -> u64 {
        self.segments_off_target
    }

    /// In-set replies that answered no outstanding probe, so they proved a host
    /// alive but yielded no round-trip sample. Duplicates land here, and so does
    /// a correlation bug.
    pub fn replies_without_rtt(&self) -> u64 {
        self.replies_without_rtt
    }

    /// Targets credited as alive for the first time.
    pub fn hosts_found(&self) -> u64 {
        self.hosts_found
    }

    /// Found hosts by the attempt whose reply revealed them.
    ///
    /// Index `i` counts hosts answered on attempt `i + 1`; the last slot counts
    /// attempt [`ATTEMPTS_COUNTED`] *or later*, so a hand-raised retry budget
    /// still has somewhere to land.
    ///
    /// This is what says whether retransmission is earning its traffic. A host
    /// found on its first attempt needed only for the scan to still be
    /// listening; one found on its third needed the packet to be sent again.
    pub fn answered_on(&self) -> &[u64] {
        &self.answered_on
    }

    /// Found hosts whose reply named no attempt: it arrived after the probe had
    /// been written off, or carried nothing to match against.
    pub fn answered_unattributed(&self) -> u64 {
        self.answered_unattributed
    }

    /// How far into the run the first host was credited.
    pub fn first_reply(&self) -> Option<Duration> {
        self.first_reply
    }

    /// How far into the run the last host was credited. Close to
    /// [`elapsed`](Self::elapsed) on a run that stopped for
    /// [`DeadlineExpired`](StopReason::DeadlineExpired) means the scan was still
    /// finding hosts when it ran out of time.
    pub fn last_reply(&self) -> Option<Duration> {
        self.last_reply
    }

    /// Hosts by how far into the run they were credited, bucketed by
    /// [`BUCKET_BOUNDS_MS`]. Index `i` counts hosts found at or under
    /// `BUCKET_BOUNDS_MS[i]` milliseconds; the final slot counts everything
    /// later than the last bound.
    pub fn found_at(&self) -> &[u64] {
        &self.found_at
    }

    /// What the kernel capture reported, where there was one to ask. A scanner
    /// driven by a synthetic receive stream has no kernel buffer, and reports
    /// `None` rather than a clean-looking zero.
    pub fn capture(&self) -> Option<CaptureCounts> {
        self.capture
    }
}

/// A scanning strategy that did not run to completion.
///
/// A scan continues with whatever strategies remain when one of them fails, so
/// a report that carries failures still carries results - just narrower ones
/// than the caller asked for. This is the record that lets a consumer tell a
/// genuinely empty network from a sweep whose raw scanner never started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerFailure {
    scanner: ScannerKind,
    reason: String,
    at: SystemTime,
}

impl ScannerFailure {
    /// Records a failure as having happened now.
    pub fn new(scanner: ScannerKind, reason: impl Into<String>) -> Self {
        Self {
            scanner,
            reason: reason.into(),
            at: SystemTime::now(),
        }
    }

    /// The strategy that failed.
    pub fn scanner(&self) -> ScannerKind {
        self.scanner
    }

    /// A human-readable description of the failure.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// When the failure was observed.
    pub fn at(&self) -> SystemTime {
        self.at
    }
}

impl fmt::Display for ScannerFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} scanner failed: {}", self.scanner, self.reason)
    }
}

/// One completed call into the engine.
#[derive(Debug, Clone)]
pub struct ScanPhase {
    kind: ScanKind,
    started_at: SystemTime,
    elapsed: Duration,
    privileged: bool,
    targets: TargetScope,
    settings: ScanSettings,
    failures: Vec<ScannerFailure>,
    probes: Vec<ProbeStats>,
}

impl ScanPhase {
    /// Which entry point this phase records.
    pub fn kind(&self) -> ScanKind {
        self.kind
    }

    /// When the phase began.
    pub fn started_at(&self) -> SystemTime {
        self.started_at
    }

    /// How long the phase ran, measured monotonically.
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Whether the engine held the privileges its raw strategies need. An
    /// unprivileged phase reached its targets over plain TCP connect attempts,
    /// which see less and are more visible to the target.
    pub fn privileged(&self) -> bool {
        self.privileged
    }

    /// What the phase was asked to cover.
    pub fn targets(&self) -> &TargetScope {
        &self.targets
    }

    /// The settings the phase ran under.
    pub fn settings(&self) -> &ScanSettings {
        &self.settings
    }

    /// Strategies that did not run to completion.
    pub fn failures(&self) -> &[ScannerFailure] {
        &self.failures
    }

    /// What each instrumented scanner observed about its own run.
    ///
    /// Empty where no strategy in this phase carries instrumentation, which is
    /// not the same as a phase whose scanners saw nothing. Only the raw paths
    /// count packets; the TCP-connect fallback has no capture to audit.
    pub fn probe_stats(&self) -> &[ProbeStats] {
        &self.probes
    }
}

/// Carries a phase's metadata from the entry point that knows it to the task
/// that closes the record.
///
/// The scope and settings of a scan are only knowable before it starts - the
/// target set moves into the strategies that consume it - while the duration
/// and the failures are only knowable after it ends. This holds the first half
/// across the spawned task so both halves land in one [`ScanPhase`], instead of
/// leaving a half-built report somewhere for the task to find.
pub(crate) struct PhaseRecorder {
    kind: ScanKind,
    started_at: SystemTime,
    started: Instant,
    privileged: bool,
    targets: TargetScope,
    settings: ScanSettings,
}

impl PhaseRecorder {
    /// Opens a phase record, taking the clock readings that bound it.
    ///
    /// Both clocks are read because they answer different questions: the wall
    /// clock says when the scan happened, the monotonic one says how long it
    /// took. Deriving the second from the first would let an NTP correction
    /// during a long sweep report a duration that never elapsed.
    pub(crate) fn start(
        kind: ScanKind,
        privileged: bool,
        targets: TargetScope,
        cfg: &ZondConfig,
    ) -> Self {
        Self {
            kind,
            started_at: SystemTime::now(),
            started: Instant::now(),
            privileged,
            targets,
            settings: ScanSettings::from(cfg),
        }
    }

    /// Closes the record, snapshotting the hosts the scan wrote into `ctx`.
    ///
    /// Called once, from the end of the spawned scan task, so the snapshot is
    /// taken after every strategy has stopped writing.
    pub(crate) fn finish(self, ctx: &ScanContext) -> ScanReport {
        let phase = ScanPhase {
            kind: self.kind,
            started_at: self.started_at,
            // Measured monotonically rather than as the difference between two
            // wall-clock readings: a clock correction during a long sweep would
            // otherwise report a duration that never elapsed.
            elapsed: self.started.elapsed(),
            privileged: self.privileged,
            targets: self.targets,
            settings: self.settings,
            failures: ctx.take_failures(),
            probes: ctx.take_probe_stats(),
        };

        let hosts = ctx.store.iter().map(|entry| entry.value().clone());
        ScanReport::new(phase, hosts)
    }
}

/// Counts derived from a report's hosts.
///
/// Computed on demand by [`ScanReport::summary`] rather than stored, so it
/// cannot disagree with the hosts it describes.
///
/// Both headline counts are paired with a full distribution. `hosts_alive` and
/// `ports_open` are the numbers a person reads first, but collapsing the
/// remaining states into a single "not found" bucket would throw away the
/// distinction the scanner worked hardest to establish - a filtered port is
/// evidence of a firewall, a closed one is evidence of a live host, and neither
/// is silence.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanSummary {
    /// Hosts recorded, whatever their status.
    pub hosts_total: usize,
    /// Hosts confirmed to be on the network, either responding or filtered.
    pub hosts_alive: usize,
    /// How many hosts fell into each status.
    pub hosts_by_status: BTreeMap<HostStatus, usize>,
    /// Port records across all hosts.
    pub ports_total: usize,
    /// Ports found accepting connections.
    pub ports_open: usize,
    /// How many ports fell into each state.
    pub ports_by_state: BTreeMap<PortState, usize>,
    /// Ports whose service was identified by fingerprinting.
    pub services_identified: usize,
    /// How many hosts were reachable at an IPv4 address, at an IPv6 one, and at
    /// both.
    ///
    /// Counted per host rather than per address, and the three do not sum to
    /// [`hosts_total`](Self::hosts_total): a dual-stack host appears in
    /// `ipv4`, in `ipv6` and in `dual_stack`. That is what makes the numbers
    /// answer the question they are asked — "how much of this network did I see
    /// over IPv6" — where a partition into three would answer a different one.
    pub hosts_by_family: FamilyCounts,
}

/// Hosts counted by the address families they answered at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FamilyCounts {
    /// Hosts with at least one IPv4 address.
    pub ipv4: usize,
    /// Hosts with at least one IPv6 address.
    pub ipv6: usize,
    /// Hosts with both, counted again here.
    pub dual_stack: usize,
}

/// Everything known about a completed scan.
///
/// Obtained from [`ScanTask::join`](crate::scanner::ScanTask::join) once a scan
/// finishes. See the [module documentation](self) for how it relates to the
/// live [`ScanSession`](crate::core::session::ScanSession).
#[derive(Debug, Clone)]
#[must_use = "a report is the record of the scan that just ran; dropping it discards it"]
pub struct ScanReport {
    engine_version: &'static str,
    phases: Vec<ScanPhase>,
    hosts: BTreeMap<IpAddr, Host>,
}

impl ScanReport {
    /// Builds a single-phase report over the hosts a scan produced.
    ///
    /// Hosts are keyed by their primary IP, which is the same key the live store
    /// uses, so a host that gained addresses during the scan appears once rather
    /// than once per address.
    pub fn new(phase: ScanPhase, hosts: impl IntoIterator<Item = Host>) -> Self {
        let hosts = hosts
            .into_iter()
            .map(|host| (host.primary_ip(), host))
            .collect();

        Self {
            engine_version: ENGINE_VERSION,
            phases: vec![phase],
            hosts,
        }
    }

    /// The engine version that produced this report.
    pub fn engine_version(&self) -> &'static str {
        self.engine_version
    }

    /// The phases that contributed to this report, in the order they ran.
    ///
    /// Never empty: a report is only produced by a phase completing.
    pub fn phases(&self) -> &[ScanPhase] {
        &self.phases
    }

    /// Every host recorded, ordered by primary IP.
    pub fn hosts(&self) -> impl Iterator<Item = &Host> {
        self.hosts.values()
    }

    /// The number of hosts recorded.
    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    /// Looks up a host by its primary IP.
    pub fn host(&self, ip: &IpAddr) -> Option<&Host> {
        self.hosts.get(ip)
    }

    /// When the earliest phase began.
    pub fn started_at(&self) -> SystemTime {
        self.phases
            .iter()
            .map(ScanPhase::started_at)
            .min()
            .unwrap_or_else(SystemTime::now)
    }

    /// How long the engine spent scanning, summed over the phases.
    ///
    /// This is time the engine was working, not the span from the first phase
    /// starting to the last one ending. The two differ by whatever the caller
    /// did between phases - rendering a table, waiting for a confirmation - and
    /// attributing that to the scan would make the engine look slower than it
    /// is. For the wall-clock span, take the difference between
    /// [`started_at`](Self::started_at) and the last phase's end.
    pub fn elapsed(&self) -> Duration {
        self.phases.iter().map(ScanPhase::elapsed).sum()
    }

    /// Every strategy failure across all phases, in the order they were
    /// recorded.
    pub fn failures(&self) -> impl Iterator<Item = &ScannerFailure> {
        self.phases.iter().flat_map(ScanPhase::failures)
    }

    /// Every instrumented scanner's counters, across all phases.
    pub fn probe_stats(&self) -> impl Iterator<Item = &ProbeStats> {
        self.phases.iter().flat_map(ScanPhase::probe_stats)
    }

    /// Whether any strategy failed to run to completion. A `true` here means
    /// the results are narrower than the caller asked for.
    pub fn is_partial(&self) -> bool {
        self.phases.iter().any(|phase| !phase.failures.is_empty())
    }

    /// Counts derived from the recorded hosts.
    pub fn summary(&self) -> ScanSummary {
        let mut summary = ScanSummary::default();

        for host in self.hosts.values() {
            summary.hosts_total += 1;
            if host.is_alive() {
                summary.hosts_alive += 1;
            }
            *summary.hosts_by_status.entry(host.status()).or_default() += 1;

            let v4 = host.ips().iter().any(IpAddr::is_ipv4);
            let v6 = host.ips().iter().any(IpAddr::is_ipv6);
            summary.hosts_by_family.ipv4 += usize::from(v4);
            summary.hosts_by_family.ipv6 += usize::from(v6);
            summary.hosts_by_family.dual_stack += usize::from(v4 && v6);

            for port in host.ports() {
                summary.ports_total += 1;
                if port.state() == PortState::Open {
                    summary.ports_open += 1;
                }
                *summary.ports_by_state.entry(port.state()).or_default() += 1;
                if port.service().is_some() {
                    summary.services_identified += 1;
                }
            }
        }

        summary
    }

    /// Folds a later phase of the same job into this report.
    ///
    /// Hosts present in both are combined with [`Host::merge`], so a host
    /// discovered in the first phase keeps its MAC and telemetry when the second
    /// adds its ports. Phases and their failures are appended in call order.
    ///
    /// The engine version is left as this report's. Two reports from different
    /// engine builds are not part of one job, and silently averaging their
    /// provenance would be worse than keeping the first.
    pub fn merge(&mut self, other: ScanReport) {
        self.phases.extend(other.phases);

        for (ip, host) in other.hosts {
            match self.hosts.get_mut(&ip) {
                Some(existing) => existing.merge(host),
                None => {
                    self.hosts.insert(ip, host);
                }
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
    use crate::core::models::ip::range::Ipv4Range;
    use crate::core::models::port::{Port, PortSet, Service};
    use crate::core::models::target::TargetSet;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, last))
    }

    fn phase(kind: ScanKind) -> ScanPhase {
        ScanPhase {
            kind,
            started_at: SystemTime::UNIX_EPOCH,
            elapsed: Duration::from_millis(500),
            privileged: true,
            targets: TargetScope::from_ip_set(&mut IpSet::new()),
            settings: ScanSettings::from(&ZondConfig::default()),
            failures: Vec::new(),
            probes: Vec::new(),
        }
    }

    fn ip_set(spec: &str) -> IpSet {
        let mut set = IpSet::new();
        set.insert_range(IpRange::from_str(spec).expect("valid range"));
        set
    }

    #[test]
    fn scope_merges_overlapping_ranges_before_counting() {
        let mut ips = ip_set("192.168.0.0/24");
        ips.insert_range(IpRange::from_str("192.168.0.128/25").expect("valid range"));

        let scope = TargetScope::from_ip_set(&mut ips);

        // The second range is wholly inside the first, so the scope covers one
        // /24 rather than the 384 addresses the two arguments add up to.
        assert_eq!(scope.ranges().len(), 1);
        assert_eq!(scope.addresses(), 256);
        assert_eq!(scope.probes(), None);
        assert!(scope.protocols().is_empty());
    }

    #[test]
    fn port_scan_scope_counts_probes_not_addresses() {
        let ports = PortSet::from_iter([
            (80, Protocol::Tcp),
            (443, Protocol::Tcp),
            (53, Protocol::Udp),
        ]);

        let mut targets = TargetMap::new();
        targets.add_unit(TargetSet::new(ip_set("10.0.0.1-10.0.0.4"), ports));

        let scope = TargetScope::from_target_map(&mut targets);

        assert_eq!(scope.addresses(), 4);
        assert_eq!(scope.probes(), Some(12));
        assert_eq!(scope.protocols(), &[Protocol::Tcp, Protocol::Udp]);
    }

    #[test]
    fn settings_ignore_presentation_config() {
        let scanning = ZondConfig {
            no_dns: true,
            ..Default::default()
        };
        let presentation = ZondConfig {
            no_banner: true,
            quiet: 2,
            disable_input: true,
            ..Default::default()
        };

        // Two runs that differ only in how the terminal looked must record the
        // same settings; one that differs in what it put on the wire must not.
        assert_eq!(
            ScanSettings::from(&presentation),
            ScanSettings::from(&ZondConfig::default())
        );
        assert_ne!(
            ScanSettings::from(&scanning),
            ScanSettings::from(&ZondConfig::default())
        );
    }

    #[test]
    fn summary_counts_states_and_services() {
        let mut up = Host::new(ip(1));
        up.set_status(HostStatus::Up);
        up.add_port(
            Port::new(22, Protocol::Tcp, PortState::Open).with_service(Service::new("ssh", 90)),
        );
        up.add_port(Port::new(80, Protocol::Tcp, PortState::Open));
        up.add_port(Port::new(81, Protocol::Tcp, PortState::Filtered));

        let mut filtered = Host::new(ip(2));
        filtered.set_status(HostStatus::Filtered);

        let mut down = Host::new(ip(3));
        down.set_status(HostStatus::Down);

        let report = ScanReport::new(phase(ScanKind::PortScan), [up, filtered, down]);
        let summary = report.summary();

        assert_eq!(summary.hosts_total, 3);
        assert_eq!(summary.hosts_alive, 2);
        assert_eq!(summary.hosts_by_status[&HostStatus::Up], 1);
        assert_eq!(summary.hosts_by_status[&HostStatus::Down], 1);
        assert_eq!(summary.ports_total, 3);
        assert_eq!(summary.ports_open, 2);
        assert_eq!(summary.ports_by_state[&PortState::Filtered], 1);
        assert_eq!(summary.services_identified, 1);
    }

    #[test]
    fn hosts_are_ordered_by_ip_regardless_of_discovery_order() {
        let scrambled = [Host::new(ip(30)), Host::new(ip(2)), Host::new(ip(17))];
        let report = ScanReport::new(phase(ScanKind::Discovery), scrambled);

        let order: Vec<IpAddr> = report.hosts().map(Host::primary_ip).collect();
        assert_eq!(order, vec![ip(2), ip(17), ip(30)]);
    }

    #[test]
    fn merge_combines_hosts_and_keeps_phase_order() {
        let mut discovered = Host::new(ip(1));
        discovered.set_status(HostStatus::Up);
        discovered.add_rtt(Duration::from_millis(3));
        let mut first = ScanReport::new(phase(ScanKind::Discovery), [discovered]);

        let mut scanned = Host::new(ip(1));
        scanned.add_port(Port::new(443, Protocol::Tcp, PortState::Open));
        let second = ScanReport::new(phase(ScanKind::PortScan), [scanned, Host::new(ip(9))]);

        first.merge(second);

        // The port scan's record of .1 carried no status and no telemetry; the
        // merge must not let that erase what discovery established.
        let host = first.host(&ip(1)).expect("host survives the merge");
        assert_eq!(host.status(), HostStatus::Up);
        assert_eq!(host.port_count(), 1);
        assert!(host.min_rtt().is_some());

        assert_eq!(first.host_count(), 2);
        assert_eq!(
            first
                .phases()
                .iter()
                .map(ScanPhase::kind)
                .collect::<Vec<_>>(),
            vec![ScanKind::Discovery, ScanKind::PortScan]
        );
        assert_eq!(first.elapsed(), Duration::from_secs(1));
    }

    #[test]
    fn failures_are_visible_across_phases() {
        let mut failed = phase(ScanKind::Discovery);
        failed.failures.push(ScannerFailure::new(
            ScannerKind::Routed,
            "raw socket unavailable",
        ));

        let clean = ScanReport::new(phase(ScanKind::PortScan), []);
        let mut report = ScanReport::new(failed, []);
        report.merge(clean);

        assert!(report.is_partial());
        assert_eq!(report.failures().count(), 1);
    }

    /// The counters a scanner files mid-scan have to reach the phase that
    /// finishes afterwards, and reach exactly the one that was running.
    #[test]
    fn probe_stats_filed_during_a_scan_land_in_its_phase() {
        let (_session, ctx) = crate::core::session::ScanSession::new();
        let recorder = PhaseRecorder::start(
            ScanKind::Discovery,
            true,
            TargetScope::from_ip_set(&mut IpSet::new()),
            &ZondConfig::default(),
        );

        ctx.record_probe_stats(ProbeStats {
            scanner: ScannerKind::Routed,
            targets: 256,
            stop_reason: StopReason::AllResponded,
            elapsed: Duration::from_millis(40),
            sends_attempted: 300,
            sends_failed: 0,
            segments_seen: 250,
            segments_off_target: 1,
            replies_without_rtt: 2,
            hosts_found: 9,
            answered_on: [7, 2, 0, 0, 0, 0],
            answered_unattributed: 0,
            first_reply: Some(Duration::from_millis(1)),
            last_reply: Some(Duration::from_millis(30)),
            found_at: [0; BUCKET_BOUNDS_MS.len() + 1],
            capture: None,
        });

        let report = recorder.finish(&ctx);
        let stats = report.phases()[0].probe_stats();

        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].scanner(), ScannerKind::Routed);
        assert_eq!(stats[0].hosts_found(), 9);
        assert_eq!(stats[0].answered_on()[1], 2);
        assert_eq!(report.probe_stats().count(), 1);

        // Draining is what stops a second phase inheriting the first's counters.
        assert!(ctx.take_probe_stats().is_empty());
    }

    /// A phase whose scanners carry no instrumentation reports no counters,
    /// which must not be confused with a scanner that measured zero.
    #[test]
    fn an_uninstrumented_phase_reports_no_probe_stats() {
        let report = ScanReport::new(phase(ScanKind::PortScan), []);

        assert!(report.phases()[0].probe_stats().is_empty());
        assert_eq!(report.probe_stats().count(), 0);
    }

    #[test]
    fn a_stop_reason_knows_whether_the_run_finished() {
        assert!(StopReason::AllResponded.is_complete());
        assert!(StopReason::AttemptsSpent.is_complete());
        assert!(!StopReason::DeadlineExpired.is_complete());
        assert!(!StopReason::Aborted.is_complete());
        assert!(!StopReason::StreamClosed.is_complete());
    }

    #[test]
    fn a_clean_report_is_not_partial() {
        let report = ScanReport::new(phase(ScanKind::Discovery), []);

        assert!(!report.is_partial());
        assert_eq!(report.failures().count(), 0);
        assert_eq!(report.engine_version(), ENGINE_VERSION);
    }

    #[test]
    fn scope_ranges_cover_both_families() {
        let mut ips = ip_set("10.0.0.0/30");
        ips.insert_range(IpRange::from_str("fe80::/126").expect("valid range"));

        let scope = TargetScope::from_ip_set(&mut ips);

        assert_eq!(scope.addresses(), 8);
        assert!(matches!(scope.ranges()[0], IpRange::V4(_)));
        assert!(matches!(scope.ranges()[1], IpRange::V6(_)));
    }

    #[test]
    fn ipv4_range_scope_reports_its_own_bounds() {
        let mut ips = IpSet::new();
        ips.push_v4_range(
            Ipv4Range::new(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 9))
                .expect("valid range"),
        );

        let scope = TargetScope::from_ip_set(&mut ips);

        assert_eq!(scope.addresses(), 5);
        assert_eq!(
            scope.ranges()[0].start_addr(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))
        );
    }

    /// A dual-stack host is one host, counted under both families.
    ///
    /// These counts answer "how much of this network did I see over IPv6",
    /// which is a different question from "how do the hosts partition" — so
    /// they deliberately do not sum to `hosts_total`, and a test that asserted
    /// they did would be pinning the wrong contract.
    #[test]
    fn family_counts_record_a_dual_stack_host_under_both() {
        let mut dual = Host::new(ip(1));
        dual.add_ip(IpAddr::from_str("2001:db8::1").unwrap());
        let v6_only = Host::new(IpAddr::from_str("2001:db8::2").unwrap());

        let report = ScanReport::new(
            phase(ScanKind::Discovery),
            [dual, Host::new(ip(2)), v6_only],
        );

        let summary = report.summary();
        assert_eq!(summary.hosts_total, 3);
        assert_eq!(summary.hosts_by_family.ipv4, 2);
        assert_eq!(summary.hosts_by_family.ipv6, 2);
        assert_eq!(summary.hosts_by_family.dual_stack, 1);
    }
}
