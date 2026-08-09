// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

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
use crate::core::session::{ScanContext, ScannerKind};

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
            retry: cfg.retry,
            max_probe_rate: cfg.max_probe_rate,
            dns_enabled: !cfg.no_dns,
            redact: cfg.redact,
        }
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
}

impl ScanPhase {
    /// Assembles a phase record from its measurements.
    ///
    /// `elapsed` is expected to come from a monotonic clock rather than from the
    /// difference between two [`SystemTime`] readings: a wall clock that steps
    /// mid-scan would otherwise produce a duration that never happened, and on
    /// a long sweep it is exactly the kind of correction that lands mid-scan.
    pub fn new(
        kind: ScanKind,
        started_at: SystemTime,
        elapsed: Duration,
        privileged: bool,
        targets: TargetScope,
        settings: ScanSettings,
        failures: Vec<ScannerFailure>,
    ) -> Self {
        Self {
            kind,
            started_at,
            elapsed,
            privileged,
            targets,
            settings,
            failures,
        }
    }

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
        let phase = ScanPhase::new(
            self.kind,
            self.started_at,
            self.started.elapsed(),
            self.privileged,
            self.targets,
            self.settings,
            ctx.take_failures(),
        );

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
        ScanPhase::new(
            kind,
            SystemTime::UNIX_EPOCH,
            Duration::from_millis(500),
            true,
            TargetScope::from_ip_set(&mut IpSet::new()),
            ScanSettings::from(&ZondConfig::default()),
            Vec::new(),
        )
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
}
