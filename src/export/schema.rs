// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The exported document
//!
//! The data transfer objects that define what a zond report looks like on the
//! wire. Everything a consumer parses is described here, and nothing else in the
//! engine is serializable at all.
//!
//! ## Why this layer exists
//!
//! [`Host`] and its neighbours are the engine's working types. Their fields are
//! private, their layout follows what the scanners need, and they are refactored
//! whenever that changes. Deriving `Serialize` on them would publish that layout
//! as a format, and the first refactor after the first customer would be a
//! breaking change to their parser rather than a private matter.
//!
//! So the mapping is written out by hand, once, here. It costs a file. It buys
//! the freedom to move a field, rename a variant, or split a struct without
//! anyone outside noticing - and, in the other direction, it makes changing the
//! wire format a deliberate edit to a file whose whole purpose is to be stable,
//! rather than a side effect of a refactor. Every enum is mapped by an
//! exhaustive `match`, so adding a variant to a core type fails to compile until
//! somebody decides what it is called in JSON.
//!
//! ## Conventions the whole document obeys
//!
//! These hold everywhere, so a consumer learns them once:
//!
//! - **Timestamps are RFC 3339 strings in UTC**, to microsecond precision. Never
//!   epoch floats; see [`time`](super::time) for why.
//! - **Durations are integers of microseconds**, in a field whose name ends in
//!   `_us`. The unit is in the name because a bare `timeout` field is a
//!   support ticket waiting to happen.
//! - **Counts that can exceed 2^53 are decimal strings**, not numbers. An IPv6
//!   sweep's address count does not fit a JSON number as JavaScript implements
//!   one, and a count that silently rounds is worse than one that needs
//!   parsing. Everything narrow enough to be exact stays a number.
//! - **Objects have a fixed shape.** A field that has no value is present and
//!   `null`; a list with nothing in it is present and empty. A consumer never
//!   has to distinguish "absent" from "empty" from "unknown".
//! - **Order is deterministic.** Hosts sort by primary IP, ports by number, sets
//!   by their natural order. Two scans that found the same things produce
//!   documents that diff cleanly.
//! - **Unknown fields may appear.** Additive changes do not bump
//!   [`SCHEMA_VERSION`]; a consumer must ignore what it does not recognise.
//!
//! ## Streaming
//!
//! [`ReportDto`] borrows the report rather than copying it, and serializes hosts
//! from an iterator. One [`HostDto`] exists at a time, whatever the size of the
//! scan, so exporting a /16 costs a host's worth of memory rather than a
//! network's.
//!
//! [`Host`]: crate::core::models::host::Host

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use serde::Serialize;
use serde::ser::{SerializeSeq, Serializer};

use crate::core::config::SendMode;
use crate::core::models::host::{
    HardwareInfo, Host, HostStatus, HostTelemetry, NetworkRole, OsFingerprint, StatusProtocol,
    StatusReason,
};
use crate::core::models::ip::range::IpRange;
use crate::core::models::port::{
    CertificateInfo, Discovery, Port, PortState, Protocol, ScanResponse, ScriptOutput, Security,
    Service,
};
use crate::core::models::retry::{RetryConfig, ScanEffort};
use crate::core::report::{
    ATTEMPTS_COUNTED, BUCKET_BOUNDS_MS, ProbeStats, ScanKind, ScanPhase, ScanReport, ScanSettings,
    ScanSummary, ScannerFailure, StopReason, TargetScope,
};
use crate::core::session::ScannerKind;
use crate::export::ExportOptions;
use crate::export::time::rfc3339;
use crate::network::capture::CaptureCounts;

/// The version of the exported document's structure.
///
/// Bumped only when a consumer written against the previous version would
/// misread the new one: a field removed, renamed, retyped, or given a different
/// meaning. Adding a field, a new enum string, or a new optional block does not
/// bump it, because a consumer that ignores what it does not recognise is
/// unaffected - and one that does not ignore it was going to break on the next
/// scanner either way.
///
/// The engine's own version travels alongside it in `engine.version`, so a
/// report can be attributed to a build without the schema having to move every
/// time the engine does.
pub const SCHEMA_VERSION: u32 = 1;

/// The name reported in the document's `engine.name` field.
pub const ENGINE_NAME: &str = "zond-engine";

// ---------------------------------------------------------------------------
// Enum names
//
// The wire spelling of every enumerated value in the document. Public because a
// third-party exporter rendering the same data in its own format should spell
// these the same way the JSON does, and because the alternative is each
// exporter inventing its own strings.
// ---------------------------------------------------------------------------

/// The wire name of a scan phase.
pub fn scan_kind_name(kind: ScanKind) -> &'static str {
    match kind {
        ScanKind::Discovery => "discovery",
        ScanKind::PortScan => "port_scan",
    }
}

/// The wire name of a scanning strategy.
pub fn scanner_kind_name(kind: ScannerKind) -> &'static str {
    match kind {
        ScannerKind::Local => "local",
        ScannerKind::Routed => "routed",
        ScannerKind::SynPort => "syn_port",
        ScannerKind::TcpPort => "tcp_port",
        ScannerKind::Connect => "connect",
        ScannerKind::ConnectUdp => "connect_udp",
        ScannerKind::UdpPort => "udp_port",
        ScannerKind::Composite => "composite",
    }
}

/// The wire name of a host's reachability status.
pub fn host_status_name(status: HostStatus) -> &'static str {
    match status {
        HostStatus::Unknown => "unknown",
        HostStatus::Down => "down",
        HostStatus::Filtered => "filtered",
        HostStatus::Up => "up",
    }
}

/// The wire name of a port's state.
pub fn port_state_name(state: PortState) -> &'static str {
    match state {
        PortState::ClosedFiltered => "closed_filtered",
        PortState::Filtered => "filtered",
        PortState::Unfiltered => "unfiltered",
        PortState::Closed => "closed",
        PortState::OpenFiltered => "open_filtered",
        PortState::Open => "open",
    }
}

/// The wire name of a transport protocol.
pub fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Sctp => "sctp",
    }
}

/// The wire name of an inferred network role.
pub fn network_role_name(role: NetworkRole) -> &'static str {
    match role {
        NetworkRole::Gateway => "gateway",
        NetworkRole::DHCP => "dhcp",
        NetworkRole::DNS => "dns",
        NetworkRole::Tarpit => "tarpit",
    }
}

/// The wire name of a receive loop's stop reason.
pub fn stop_reason_name(reason: StopReason) -> &'static str {
    match reason {
        StopReason::Aborted => "aborted",
        StopReason::AllResponded => "all_responded",
        StopReason::AttemptsSpent => "attempts_spent",
        StopReason::DeadlineExpired => "deadline_expired",
        StopReason::StreamClosed => "stream_closed",
    }
}

/// The wire name of a send mode.
pub fn send_mode_name(mode: SendMode) -> &'static str {
    match mode {
        SendMode::Auto => "auto",
        SendMode::RawSocket => "raw_socket",
        SendMode::Ethernet => "ethernet",
    }
}

/// The wire name of a retransmission effort level.
pub fn scan_effort_name(effort: ScanEffort) -> &'static str {
    match effort {
        ScanEffort::Single => "single",
        ScanEffort::Fast => "fast",
        ScanEffort::Balanced => "balanced",
        ScanEffort::Thorough => "thorough",
    }
}

/// The wire name of the evidence behind a host's status.
///
/// A strategy-supplied name is prefixed with `custom:` so it can never be
/// mistaken for one of the names above. Without the prefix a script calling
/// itself `arp` would produce a report indistinguishable from a real ARP
/// finding.
pub fn status_protocol_name(protocol: &StatusProtocol) -> Cow<'_, str> {
    match protocol {
        StatusProtocol::Arp => Cow::Borrowed("arp"),
        StatusProtocol::Ndp => Cow::Borrowed("ndp"),
        StatusProtocol::IcmpEcho => Cow::Borrowed("icmp_echo"),
        StatusProtocol::IcmpUnreachable => Cow::Borrowed("icmp_unreachable"),
        StatusProtocol::TcpSyn => Cow::Borrowed("tcp_syn"),
        StatusProtocol::Tcp => Cow::Borrowed("tcp"),
        StatusProtocol::Udp => Cow::Borrowed("udp"),
        StatusProtocol::Custom(name) => Cow::Owned(format!("custom:{name}")),
    }
}

/// The wire name of the packet response that decided a port's state.
///
/// Custom responses are prefixed as in [`status_protocol_name`], for the same
/// reason.
pub fn scan_response_name(response: &ScanResponse) -> Cow<'_, str> {
    match response {
        ScanResponse::TcpSynAck => Cow::Borrowed("tcp_syn_ack"),
        ScanResponse::TcpRst => Cow::Borrowed("tcp_rst"),
        ScanResponse::UdpResponse => Cow::Borrowed("udp_response"),
        ScanResponse::NoResponse => Cow::Borrowed("no_response"),
        ScanResponse::IcmpUnreachable => Cow::Borrowed("icmp_unreachable"),
        ScanResponse::IcmpProhibited => Cow::Borrowed("icmp_prohibited"),
        ScanResponse::Custom(name) => Cow::Owned(format!("custom:{name}")),
    }
}

/// Renders a duration as whole microseconds.
///
/// Saturates rather than wrapping. The bound is roughly 585,000 years, so
/// nothing the engine measures approaches it; saturating is simply what a
/// measurement should do when it cannot be represented, rather than silently
/// reporting a small number.
fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// Renders an optional duration as whole microseconds.
fn micros_opt(duration: Option<Duration>) -> Option<u64> {
    duration.map(micros)
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// A whole scan report, ready to serialize.
///
/// Borrows the report it describes: constructing one is free, and serializing
/// it walks the hosts rather than materialising them. See the
/// [module documentation](self) for the conventions the output obeys.
///
/// ```no_run
/// use zond_engine::core::report::ScanReport;
/// use zond_engine::export::{ExportOptions, schema::ReportDto};
///
/// # fn example(report: &ScanReport) -> Result<(), Box<dyn std::error::Error>> {
/// let options = ExportOptions::new();
/// let document = ReportDto::new(report, &options);
/// # let _ = document;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct ReportDto<'a> {
    report: &'a ScanReport,
    options: &'a ExportOptions,
    generated_at: SystemTime,
}

impl<'a> ReportDto<'a> {
    /// Describes a report, stamped with the current time as its generation
    /// time.
    pub fn new(report: &'a ScanReport, options: &'a ExportOptions) -> Self {
        Self::generated_at(report, options, SystemTime::now())
    }

    /// Describes a report with an explicit generation time.
    ///
    /// Exists so a test can produce a document that is byte-identical across
    /// runs. Everything else in a report is determined by the scan; the
    /// generation stamp is the only field that moves on its own.
    pub fn generated_at(
        report: &'a ScanReport,
        options: &'a ExportOptions,
        generated_at: SystemTime,
    ) -> Self {
        Self {
            report,
            options,
            generated_at,
        }
    }

    /// The report being described.
    pub fn report(&self) -> &'a ScanReport {
        self.report
    }

    /// The options in force.
    pub fn options(&self) -> &'a ExportOptions {
        self.options
    }
}

impl Serialize for ReportDto<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let mut doc = serializer.serialize_struct("Report", HEADER_FIELDS + 1)?;
        write_header(&mut doc, self.report, self.generated_at)?;
        // Serialized straight from the iterator so the whole host set is never
        // resident at once.
        doc.serialize_field(
            "hosts",
            &HostsDto {
                report: self.report,
                options: self.options,
            },
        )?;
        doc.end()
    }
}

/// Everything a report says about itself, without the hosts.
///
/// The same fields [`ReportDto`] emits before its `hosts` array, and in the same
/// order. A record-per-line format writes this once and then the hosts one at a
/// time; splitting the document that way must not change what the header says,
/// so both are rendered by the same code.
#[derive(Debug)]
pub struct ReportHeaderDto<'a> {
    report: &'a ScanReport,
    generated_at: SystemTime,
}

impl<'a> ReportHeaderDto<'a> {
    /// Describes a report's header, stamped with the current time.
    pub fn new(report: &'a ScanReport) -> Self {
        Self::generated_at(report, SystemTime::now())
    }

    /// Describes a report's header with an explicit generation time.
    pub fn generated_at(report: &'a ScanReport, generated_at: SystemTime) -> Self {
        Self {
            report,
            generated_at,
        }
    }
}

impl Serialize for ReportHeaderDto<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let mut doc = serializer.serialize_struct("ReportHeader", HEADER_FIELDS)?;
        write_header(&mut doc, self.report, self.generated_at)?;
        doc.end()
    }
}

/// How long a scan took, as the document reports it.
///
/// The sum of the phases *as rendered*, not the truncation of the underlying
/// sum. Each phase's figure is truncated to whole microseconds independently, so
/// a total taken from the durations behind them can exceed the sum of the
/// numbers printed beside it - the document would then contradict itself by a
/// microsecond, which is a real question for a consumer to ask and a fraction of
/// nothing to answer it with.
///
/// Public because every rendering of a report has to agree about this number,
/// including one written outside this crate.
pub fn total_elapsed_us(phases: &[PhaseDto<'_>]) -> u64 {
    phases
        .iter()
        .fold(0u64, |total, phase| total.saturating_add(phase.elapsed_us))
}

/// How many fields [`write_header`] emits.
const HEADER_FIELDS: usize = 8;

/// Emits the fields every rendering of a report starts with.
fn write_header<S: serde::ser::SerializeStruct>(
    doc: &mut S,
    report: &ScanReport,
    generated_at: SystemTime,
) -> Result<(), S::Error> {
    let phases: Vec<PhaseDto<'_>> = report.phases().iter().map(PhaseDto::new).collect();
    let elapsed_us = total_elapsed_us(&phases);

    doc.serialize_field("schema_version", &SCHEMA_VERSION)?;
    doc.serialize_field(
        "engine",
        &EngineDto {
            name: ENGINE_NAME,
            version: report.engine_version(),
        },
    )?;
    doc.serialize_field("generated_at", &rfc3339(generated_at))?;
    doc.serialize_field("started_at", &rfc3339(report.started_at()))?;
    doc.serialize_field("elapsed_us", &elapsed_us)?;
    doc.serialize_field("partial", &report.is_partial())?;
    doc.serialize_field("summary", &SummaryDto::new(&report.summary()))?;
    doc.serialize_field("phases", &phases)?;

    Ok(())
}

/// The report's hosts, serialized one at a time.
struct HostsDto<'a> {
    report: &'a ScanReport,
    options: &'a ExportOptions,
}

impl Serialize for HostsDto<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.report.host_count()))?;
        for host in self.report.hosts() {
            seq.serialize_element(&HostDto::new(host, self.options))?;
        }
        seq.end()
    }
}

/// Which build produced a report.
#[derive(Debug, Clone, Serialize)]
pub struct EngineDto {
    /// Always [`ENGINE_NAME`]. Present so a document carrying a report can be
    /// told apart from one carrying something else.
    pub name: &'static str,
    /// The engine's crate version.
    pub version: &'static str,
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

/// Headline counts, with the full distribution behind each one.
///
/// The per-status and per-state breakdowns are structs rather than maps so that
/// every category is always present, in severity order, whether or not anything
/// landed in it. A consumer reading `filtered: 0` learns something; one that has
/// to decide what a missing key means does not.
#[derive(Debug, Clone, Serialize)]
pub struct SummaryDto {
    /// Hosts recorded, whatever their status.
    pub hosts_total: usize,
    /// Hosts confirmed present on the network: `up` or `filtered`.
    pub hosts_alive: usize,
    /// The full status distribution.
    pub hosts_by_status: HostStatusCounts,
    /// Port records across all hosts.
    pub ports_total: usize,
    /// Ports found accepting connections.
    pub ports_open: usize,
    /// The full port-state distribution.
    pub ports_by_state: PortStateCounts,
    /// Ports whose service was identified by fingerprinting.
    pub services_identified: usize,
    /// Hosts counted by the address families they answered at.
    pub hosts_by_family: FamilyCounts,
}

/// Hosts counted by the address families they answered at.
///
/// A dual-stack host is counted in all three, so these do not partition
/// `hosts_total`. The question a consumer asks of them is "how much of this
/// network did I see over IPv6", and a partition would answer something else.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct FamilyCounts {
    /// Hosts with at least one IPv4 address.
    pub ipv4: usize,
    /// Hosts with at least one IPv6 address.
    pub ipv6: usize,
    /// Hosts with both.
    pub dual_stack: usize,
}

impl SummaryDto {
    /// Renders a computed summary.
    pub fn new(summary: &ScanSummary) -> Self {
        let status = |status: HostStatus| {
            summary
                .hosts_by_status
                .get(&status)
                .copied()
                .unwrap_or_default()
        };
        let state = |state: PortState| {
            summary
                .ports_by_state
                .get(&state)
                .copied()
                .unwrap_or_default()
        };

        Self {
            hosts_total: summary.hosts_total,
            hosts_alive: summary.hosts_alive,
            hosts_by_status: HostStatusCounts {
                up: status(HostStatus::Up),
                filtered: status(HostStatus::Filtered),
                down: status(HostStatus::Down),
                unknown: status(HostStatus::Unknown),
            },
            ports_total: summary.ports_total,
            ports_open: summary.ports_open,
            ports_by_state: PortStateCounts {
                open: state(PortState::Open),
                open_filtered: state(PortState::OpenFiltered),
                closed: state(PortState::Closed),
                unfiltered: state(PortState::Unfiltered),
                filtered: state(PortState::Filtered),
                closed_filtered: state(PortState::ClosedFiltered),
            },
            services_identified: summary.services_identified,
            hosts_by_family: FamilyCounts {
                ipv4: summary.hosts_by_family.ipv4,
                ipv6: summary.hosts_by_family.ipv6,
                dual_stack: summary.hosts_by_family.dual_stack,
            },
        }
    }
}

/// How many hosts fell into each reachability status.
#[derive(Debug, Clone, Serialize)]
pub struct HostStatusCounts {
    /// Online and responding.
    pub up: usize,
    /// Present, but probes are being dropped.
    pub filtered: usize,
    /// Explicitly confirmed unreachable.
    pub down: usize,
    /// Never determined.
    pub unknown: usize,
}

/// How many ports fell into each state.
#[derive(Debug, Clone, Serialize)]
pub struct PortStateCounts {
    /// Accepting connections.
    pub open: usize,
    /// Either open or silently dropped; the usual UDP outcome.
    pub open_filtered: usize,
    /// Actively refusing connections.
    pub closed: usize,
    /// Reachable, but open or closed could not be told apart.
    pub unfiltered: usize,
    /// Probes dropped with no answer.
    pub filtered: usize,
    /// Either closed or dropped.
    pub closed_filtered: usize,
}

// ---------------------------------------------------------------------------
// Phases
// ---------------------------------------------------------------------------

/// One call into the engine: what it was asked to do, how it was configured,
/// how long it took, and what it observed about itself.
#[derive(Debug, Clone, Serialize)]
pub struct PhaseDto<'a> {
    /// `discovery` or `port_scan`.
    pub kind: &'static str,
    /// When the phase began.
    pub started_at: String,
    /// How long it ran, measured monotonically.
    pub elapsed_us: u64,
    /// Whether the engine held the privileges its raw strategies need. An
    /// unprivileged phase reached its targets over plain TCP connect attempts,
    /// which see less.
    pub privileged: bool,
    /// What the phase was asked to cover.
    pub targets: ScopeDto,
    /// The settings that shaped the packets it sent.
    pub settings: SettingsDto,
    /// Strategies that did not run to completion. A non-empty list means the
    /// findings are narrower than the caller asked for.
    pub failures: Vec<FailureDto<'a>>,
    /// What each instrumented scanner observed about its own run. Empty where
    /// no strategy in this phase carries instrumentation, which is not the same
    /// as a scanner that measured zero.
    pub probe_stats: Vec<ProbeStatsDto>,
}

impl<'a> PhaseDto<'a> {
    /// Renders a recorded phase.
    pub fn new(phase: &'a ScanPhase) -> Self {
        Self {
            kind: scan_kind_name(phase.kind()),
            started_at: rfc3339(phase.started_at()),
            elapsed_us: micros(phase.elapsed()),
            privileged: phase.privileged(),
            targets: ScopeDto::new(phase.targets()),
            settings: SettingsDto::new(phase.settings()),
            failures: phase.failures().iter().map(FailureDto::new).collect(),
            probe_stats: phase.probe_stats().iter().map(ProbeStatsDto::new).collect(),
        }
    }
}

/// What a phase was asked to cover.
#[derive(Debug, Clone, Serialize)]
pub struct ScopeDto {
    /// The merged ranges the sweep actually iterated, ascending. Overlapping
    /// arguments have already been coalesced, so these do not restate what a
    /// user typed.
    pub ranges: Vec<RangeDto>,
    /// How many distinct addresses were in scope, as a decimal string.
    pub addresses: String,
    /// How many address/port/protocol combinations were in scope, as a decimal
    /// string.
    ///
    /// `null` on a discovery phase, which has no port dimension, and on a
    /// target set too large to count - a failure to measure, reported as one
    /// rather than as a plausible-looking number. The phase `kind` tells the
    /// two apart.
    pub probes: Option<String>,
    /// The transport protocols in scope, ascending. Empty on a discovery phase,
    /// whose probes are chosen by the strategy rather than by the caller.
    pub protocols: Vec<&'static str>,
}

impl ScopeDto {
    /// Renders a recorded scope.
    pub fn new(scope: &TargetScope) -> Self {
        Self {
            ranges: scope.ranges().iter().map(RangeDto::new).collect(),
            addresses: scope.addresses().to_string(),
            probes: scope.probes().map(|count| count.to_string()),
            protocols: scope
                .protocols()
                .iter()
                .copied()
                .map(protocol_name)
                .collect(),
        }
    }
}

/// One inclusive address range.
#[derive(Debug, Clone, Serialize)]
pub struct RangeDto {
    /// `ipv4` or `ipv6`.
    pub family: &'static str,
    /// The first address in the range.
    pub start: String,
    /// The last address in the range, inclusive.
    pub end: String,
}

impl RangeDto {
    /// Renders an address range.
    pub fn new(range: &IpRange) -> Self {
        Self {
            family: match range {
                IpRange::V4(_) => "ipv4",
                IpRange::V6(_) => "ipv6",
            },
            start: range.start_addr().to_string(),
            end: range.end_addr().to_string(),
        }
    }
}

/// The settings that shaped what a phase put on the wire.
///
/// A deliberate subset of the engine's configuration: what changed the packets
/// and how long the engine waited for answers. Presentation settings are not
/// here, so a quieter terminal never reads as a different scan.
#[derive(Debug, Clone, Serialize)]
pub struct SettingsDto {
    /// How raw probes were placed on the wire.
    pub send_mode: &'static str,
    /// Which segment each TCP port probe carried: `syn`, `fin`, `null`, `xmas`,
    /// `maimon` or `ack`.
    ///
    /// Without it a port state cannot be read. `closed` from a SYN scan is a
    /// refused connection attempt; `closed` from a FIN scan is a reset drawn by
    /// a segment that was not one, and against a stack that resets everything it
    /// may be nothing at all.
    pub tcp_technique: &'static str,
    /// The retransmission budget and patience in force.
    pub retry: RetryDto,
    /// The probe-rate ceiling in probes per second, or `null` if the scanner's
    /// own default applied.
    pub max_probe_rate: Option<u32>,
    /// Whether name resolution was permitted to generate traffic.
    pub dns_enabled: bool,
    /// Whether the caller asked the *scan* to mask identifying detail. Distinct
    /// from export redaction, which is chosen when the report is written and is
    /// visible in what this document actually contains.
    pub redact: bool,
}

impl SettingsDto {
    /// Renders recorded settings.
    pub fn new(settings: &ScanSettings) -> Self {
        Self {
            send_mode: send_mode_name(settings.send_mode),
            tcp_technique: settings.tcp_technique.name(),
            retry: RetryDto::new(&settings.retry),
            max_probe_rate: settings.max_probe_rate,
            dns_enabled: settings.dns_enabled,
            redact: settings.redact,
        }
    }
}

/// The retransmission budget a phase ran under.
#[derive(Debug, Clone, Serialize)]
pub struct RetryDto {
    /// The effort level: `single`, `fast`, `balanced` or `thorough`.
    pub effort: &'static str,
    /// An attempt budget set by the caller, overriding what `effort` implies.
    pub max_attempts: Option<u8>,
    /// A multiplier on how long the scan was willing to wait.
    ///
    /// `null` when the caller set none, and also when the value set was not a
    /// finite number - a scale that cannot be written down is not a scale a
    /// report should claim two runs shared.
    pub timeout_scale: Option<f64>,
    /// Whether a host that answered nothing could have its budget cut short.
    pub dampen_silent_hosts: bool,
}

impl RetryDto {
    /// Renders a retry configuration.
    pub fn new(retry: &RetryConfig) -> Self {
        Self {
            effort: scan_effort_name(retry.effort),
            max_attempts: retry.max_attempts,
            timeout_scale: retry.timeout_scale.filter(|scale| scale.is_finite()),
            dampen_silent_hosts: retry.dampen_silent_hosts,
        }
    }
}

/// A strategy that did not run to completion.
#[derive(Debug, Clone, Serialize)]
pub struct FailureDto<'a> {
    /// The strategy that failed.
    pub scanner: &'static str,
    /// A human-readable description of the failure.
    pub reason: &'a str,
    /// When it was observed.
    pub at: String,
}

impl<'a> FailureDto<'a> {
    /// Renders a recorded failure.
    pub fn new(failure: &'a ScannerFailure) -> Self {
        Self {
            scanner: scanner_kind_name(failure.scanner()),
            reason: failure.reason(),
            at: rfc3339(failure.at()),
        }
    }
}

// ---------------------------------------------------------------------------
// Probe instrumentation
// ---------------------------------------------------------------------------

/// What one raw scanner observed about its own run.
///
/// Instrumentation about the scan, not a finding about the network. It exists
/// to bound how much the findings can be trusted: a sweep that stopped on
/// `deadline_expired` with `last_reply_us` close to `elapsed_us` was still
/// finding hosts when it ran out of time, and nothing in the host list says so.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeStatsDto {
    /// The strategy these counters belong to.
    pub scanner: &'static str,
    /// How many targets this scanner owned, as a decimal string.
    pub targets: String,
    /// Why the receive loop stopped.
    pub stop_reason: &'static str,
    /// Whether the loop stopped because it had nothing left to do, rather than
    /// because something cut it short. Derived from `stop_reason`, and carried
    /// so a consumer does not have to encode which reasons mean "finished".
    pub complete: bool,
    /// How long the scanner ran.
    pub elapsed_us: u64,
    /// Probes the scanner tried to put on the wire.
    pub sends_attempted: u64,
    /// Of those, ones the sender refused. Non-zero means the shortfall starts
    /// at home, before the network is implicated at all.
    pub sends_failed: u64,
    /// Segments the capture handed up, before any of the scanner's own checks.
    pub segments_seen: u64,
    /// Segments from an address outside this scan's target set. A large count
    /// means the capture filter is admitting other traffic.
    pub segments_off_target: u64,
    /// In-set replies that answered no outstanding probe. They proved a host
    /// alive but yielded no round-trip sample.
    pub replies_without_rtt: u64,
    /// Targets credited as alive for the first time.
    pub hosts_found: u64,
    /// Found hosts by the attempt whose reply revealed them. This is what says
    /// whether retransmission is earning its traffic.
    pub answered_on: Vec<AttemptCountDto>,
    /// Found hosts whose reply named no attempt: it arrived after the probe had
    /// been written off, or carried nothing to match against.
    pub answered_unattributed: u64,
    /// How far into the run the first host was credited.
    pub first_reply_us: Option<u64>,
    /// How far into the run the last host was credited.
    pub last_reply_us: Option<u64>,
    /// Hosts by how far into the run they were credited.
    ///
    /// This measures discovery time, not round trip. A host found at 700 ms
    /// because its third attempt went out at 690 ms has a 10 ms round trip;
    /// reading these as latency turns a retry schedule into an imaginary slow
    /// path. Round trips are per host, under `telemetry`.
    pub found_at: Vec<BucketDto>,
    /// What the kernel capture reported, where there was one to ask. `null` for
    /// a scanner driven by a synthetic receive stream, which has no kernel
    /// buffer, rather than a clean-looking zero.
    pub capture: Option<CaptureDto>,
}

impl ProbeStatsDto {
    /// Renders a scanner's counters.
    pub fn new(stats: &ProbeStats) -> Self {
        let answered_on = stats
            .answered_on()
            .iter()
            .enumerate()
            .map(|(index, &count)| AttemptCountDto {
                attempt: index as u32 + 1,
                or_later: index + 1 == ATTEMPTS_COUNTED,
                count,
            })
            .collect();

        let found_at = stats
            .found_at()
            .iter()
            .enumerate()
            .map(|(index, &count)| BucketDto {
                le_ms: BUCKET_BOUNDS_MS.get(index).copied(),
                count,
            })
            .collect();

        Self {
            scanner: scanner_kind_name(stats.scanner()),
            targets: stats.targets().to_string(),
            stop_reason: stop_reason_name(stats.stop_reason()),
            complete: stats.stop_reason().is_complete(),
            elapsed_us: micros(stats.elapsed()),
            sends_attempted: stats.sends_attempted(),
            sends_failed: stats.sends_failed(),
            segments_seen: stats.segments_seen(),
            segments_off_target: stats.segments_off_target(),
            replies_without_rtt: stats.replies_without_rtt(),
            hosts_found: stats.hosts_found(),
            answered_on,
            answered_unattributed: stats.answered_unattributed(),
            first_reply_us: micros_opt(stats.first_reply()),
            last_reply_us: micros_opt(stats.last_reply()),
            found_at,
            capture: stats.capture().map(CaptureDto::new),
        }
    }
}

/// How many hosts a given attempt revealed.
#[derive(Debug, Clone, Serialize)]
pub struct AttemptCountDto {
    /// The attempt number, counting from one.
    pub attempt: u32,
    /// Whether this entry also absorbs every later attempt. True on the last
    /// entry only, so a hand-raised retry budget still has somewhere to land.
    pub or_later: bool,
    /// Hosts first credited by this attempt's reply.
    pub count: u64,
}

/// One bucket of a discovery-time histogram.
#[derive(Debug, Clone, Serialize)]
pub struct BucketDto {
    /// The bucket's inclusive upper bound in milliseconds, or `null` for the
    /// final open-ended bucket.
    pub le_ms: Option<u64>,
    /// Hosts credited within this bucket.
    pub count: u64,
}

/// What the kernel capture reported.
///
/// The only place where loss on the receive path is distinguishable from loss
/// on the network. A reply the kernel discards because the buffer was full
/// reaches no other counter in this document.
#[derive(Debug, Clone, Serialize)]
pub struct CaptureDto {
    /// Frames the capture accepted and handed to the process.
    pub received: u64,
    /// Frames discarded because the buffer was full when they arrived.
    pub dropped: u64,
    /// Frames discarded by the interface or driver before the capture saw them.
    /// Not every platform reports this, so a zero is weaker evidence here than
    /// in `dropped`.
    pub if_dropped: u64,
}

impl CaptureDto {
    /// Renders capture counters.
    pub fn new(counts: CaptureCounts) -> Self {
        Self {
            received: counts.received,
            dropped: counts.dropped,
            if_dropped: counts.if_dropped,
        }
    }
}

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

/// Everything the scan established about one host.
#[derive(Debug, Clone, Serialize)]
pub struct HostDto<'a> {
    /// The address the host is keyed by. Stable across a merge, so two phases
    /// that both saw this host produce one record.
    pub primary_ip: String,
    /// Every address known for this host, ascending. Multi-homed and dual-stack
    /// hosts have more than one.
    pub ips: Vec<String>,
    /// The interface `primary_ip` is valid on, when the host was found at the
    /// link layer.
    ///
    /// Carried separately rather than folded into the addresses, so a consumer
    /// parsing `ips` still gets addresses. It is not decoration: an IPv6
    /// link-local names a different machine on every segment, and a socket
    /// cannot be opened to one without it — a record with `fe80::…` and no zone
    /// describes a host nothing can reach.
    pub zone: Option<&'a str>,
    /// The address families this host answered at: `ipv4`, `ipv6`, or both.
    ///
    /// Derivable from `ips`, and stated anyway, because "which half of the
    /// network did I see over IPv6" is a question consumers ask constantly and
    /// should not have to re-derive by parsing addresses.
    pub families: Vec<&'static str>,
    /// The resolved hostname, masked under redaction.
    pub hostname: Option<Cow<'a, str>>,
    /// The reachability status: `up`, `filtered`, `down` or `unknown`.
    pub status: &'static str,
    /// Whether the host is confirmed present on the network. True for `up` and
    /// `filtered`; carried so a consumer does not have to know that a filtered
    /// host is still a host.
    pub alive: bool,
    /// The evidence behind the status, sorted.
    pub reasons: Vec<ReasonDto<'a>>,
    /// Inferred roles, sorted.
    pub roles: Vec<&'static str>,
    /// The identified operating system.
    pub os: Option<OsDto<'a>>,
    /// Physical hardware identity, masked under redaction.
    pub hardware: Option<HardwareDto<'a>>,
    /// Network path measurements.
    pub telemetry: TelemetryDto,
    /// Discovered ports, ascending by number.
    pub ports: Vec<PortDto<'a>>,
    /// When this host was first seen.
    pub first_seen: String,
    /// When it was last updated.
    pub last_seen: String,
    /// Host-level script results, keyed by script name.
    pub scripts: BTreeMap<&'a str, &'a str>,
}

impl<'a> HostDto<'a> {
    /// Renders a host, applying the redaction policy in `options`.
    pub fn new(host: &'a Host, options: &ExportOptions) -> Self {
        let redaction = options.redaction;

        let mut families: Vec<&'static str> = Vec::with_capacity(2);
        if host.ips().iter().any(std::net::IpAddr::is_ipv4) {
            families.push("ipv4");
        }
        if host.ips().iter().any(std::net::IpAddr::is_ipv6) {
            families.push("ipv6");
        }

        let mut reasons: Vec<ReasonDto<'a>> = host.reasons().iter().map(ReasonDto::new).collect();
        reasons.sort_by(|a, b| {
            a.protocol
                .cmp(&b.protocol)
                .then(a.source_ip.cmp(&b.source_ip))
                .then(a.details.cmp(&b.details))
        });

        let mut roles: Vec<&'static str> = host
            .network_roles()
            .iter()
            .copied()
            .map(network_role_name)
            .collect();
        roles.sort_unstable();

        Self {
            primary_ip: host.primary_ip().to_string(),
            ips: host.ips().iter().map(IpAddr::to_string).collect(),
            zone: host.zone().map(|zone| zone.name()),
            families,
            hostname: host.hostname().map(|name| redaction.hostname(name)),
            status: host_status_name(host.status()),
            alive: host.is_alive(),
            reasons,
            roles,
            os: host.os().map(OsDto::new),
            hardware: host
                .hardware()
                .map(|hardware| HardwareDto::new(hardware, options)),
            telemetry: TelemetryDto::new(host.telemetry()),
            ports: host
                .ports()
                .map(|port| PortDto::new(port, options))
                .collect(),
            first_seen: rfc3339(host.first_seen()),
            last_seen: rfc3339(host.last_seen()),
            scripts: host
                .scripts()
                .map(|scripts| {
                    scripts
                        .iter()
                        .map(|(key, value)| (key.as_str(), value.as_str()))
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

/// One piece of evidence for a host's status.
#[derive(Debug, Clone, Serialize)]
pub struct ReasonDto<'a> {
    /// The protocol event that produced the evidence.
    pub protocol: Cow<'a, str>,
    /// The address that sent the evidence, when it was not the host itself.
    ///
    /// Present only for second-hand evidence — an ICMP error from a router or
    /// firewall about the probed address. `null` means the host answered for
    /// itself, which is the stronger claim, so a consumer weighing how much to
    /// trust a status can do it from this field alone.
    pub source_ip: Option<String>,
    /// What was observed, where the strategy recorded it.
    pub details: Option<&'a str>,
}

impl<'a> ReasonDto<'a> {
    /// Renders a status reason.
    pub fn new(reason: &'a StatusReason) -> Self {
        Self {
            protocol: status_protocol_name(&reason.protocol),
            source_ip: reason.source.map(|ip| ip.to_string()),
            details: reason.details.as_deref(),
        }
    }
}

/// An identified operating system.
#[derive(Debug, Clone, Serialize)]
pub struct OsDto<'a> {
    /// The primary OS name.
    pub name: &'a str,
    /// The broad family.
    pub family: Option<&'a str>,
    /// The version or generation.
    pub generation: Option<&'a str>,
    /// The vendor.
    pub vendor: Option<&'a str>,
    /// Confidence in this identification, 0 to 100.
    pub accuracy: u8,
    /// CPE identifiers, sorted.
    pub cpe: Vec<&'a str>,
}

impl<'a> OsDto<'a> {
    /// Renders an OS fingerprint.
    pub fn new(os: &'a OsFingerprint) -> Self {
        Self {
            name: &os.name,
            family: os.family.as_deref(),
            generation: os.generation.as_deref(),
            vendor: os.vendor.as_deref(),
            accuracy: os.accuracy,
            cpe: os.cpes().iter().map(|cpe| &**cpe).collect(),
        }
    }
}

/// Physical hardware identity.
///
/// The last-seen timestamps the engine keeps per address are not exported: they
/// are monotonic readings, which have no meaning outside the process that took
/// them.
#[derive(Debug, Clone, Serialize)]
pub struct HardwareDto<'a> {
    /// The most recently observed address, which is the one currently on the
    /// network.
    pub mac: Option<String>,
    /// Every address observed for this host, sorted. More than one means a
    /// multi-NIC host or a device rotating a randomized address.
    pub macs: Vec<String>,
    /// The vendor resolved from the address's OUI.
    ///
    /// Survives redaction: masking preserves the OUI, so naming the vendor
    /// reveals nothing the masked address does not already.
    pub vendor: Option<&'a str>,
}

impl<'a> HardwareDto<'a> {
    /// Renders hardware information, applying the redaction policy.
    pub fn new(hardware: &'a HardwareInfo, options: &ExportOptions) -> Self {
        let redaction = options.redaction;

        let mut macs: Vec<String> = hardware
            .macs()
            .keys()
            .map(|mac| redaction.mac(mac))
            .collect();
        // Masking collapses addresses that share an OUI, which would otherwise
        // list the same string twice. Consecutive deduplication suffices: the
        // source is sorted by address, and masking preserves the leading
        // octets, so collapsed entries are always neighbours.
        macs.dedup();

        Self {
            mac: hardware.most_recent_mac().map(|mac| redaction.mac(&mac)),
            macs,
            vendor: hardware.vendor.as_deref(),
        }
    }
}

/// Network path measurements for a host.
///
/// The individual samples are not exported. They are timestamped with monotonic
/// readings that mean nothing outside the scanning process, and the aggregates
/// below are what the samples were being kept for.
#[derive(Debug, Clone, Serialize)]
pub struct TelemetryDto {
    /// The fastest round trip observed.
    pub rtt_min_us: Option<u64>,
    /// The median round trip: the single best summary of typical latency,
    /// because one retransmit or scheduling hiccup barely moves it.
    pub rtt_median_us: Option<u64>,
    /// The arithmetic mean round trip.
    pub rtt_avg_us: Option<u64>,
    /// The slowest round trip observed.
    pub rtt_max_us: Option<u64>,
    /// Mean absolute difference between consecutive samples. High jitter
    /// relative to the average often means congestion or bufferbloat.
    pub jitter_us: Option<u64>,
    /// How many samples the figures above are drawn from.
    pub samples: usize,
    /// The TTL of the most recent response.
    pub ttl: Option<u8>,
    /// Network distance in hops, where it could be derived.
    pub distance_hops: Option<u8>,
}

impl TelemetryDto {
    /// Renders host telemetry.
    pub fn new(telemetry: &HostTelemetry) -> Self {
        Self {
            rtt_min_us: micros_opt(telemetry.min_rtt()),
            rtt_median_us: micros_opt(telemetry.median_rtt()),
            rtt_avg_us: micros_opt(telemetry.average_rtt()),
            rtt_max_us: micros_opt(telemetry.max_rtt()),
            jitter_us: micros_opt(telemetry.jitter()),
            samples: telemetry.history().len(),
            ttl: telemetry.ttl,
            distance_hops: telemetry.distance_hops,
        }
    }
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/// One discovered port.
#[derive(Debug, Clone, Serialize)]
pub struct PortDto<'a> {
    /// The port number.
    pub port: u16,
    /// The transport protocol.
    pub protocol: &'static str,
    /// The discovered state.
    pub state: &'static str,
    /// What is running there, where fingerprinting identified it.
    pub service: Option<ServiceDto<'a>>,
    /// Negotiated transport security, where a TLS handshake succeeded.
    pub security: Option<SecurityDto<'a>>,
    /// How the state was established.
    pub discovery: Option<DiscoveryDto<'a>>,
    /// Port-level script results, keyed by script name.
    pub scripts: BTreeMap<&'a str, ScriptValueDto<'a>>,
}

impl<'a> PortDto<'a> {
    /// Renders a port, applying the redaction policy.
    pub fn new(port: &'a Port, options: &ExportOptions) -> Self {
        Self {
            port: port.number(),
            protocol: protocol_name(port.protocol()),
            state: port_state_name(port.state()),
            service: port.service().map(ServiceDto::new),
            security: port
                .security()
                .map(|security| SecurityDto::new(security, options)),
            discovery: port.discovery().map(DiscoveryDto::new),
            scripts: port
                .scripts()
                .map(|scripts| {
                    scripts
                        .iter()
                        .map(|(key, value)| (key.as_str(), ScriptValueDto(value)))
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

/// What is running on a port.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceDto<'a> {
    /// The high-level protocol name, such as `ssh` or `http`.
    pub name: &'a str,
    /// Certainty of this identification, 0 to 100. A table lookup by port
    /// number scores near zero; a completed protocol handshake scores near 100.
    pub confidence: u8,
    /// The specific product or daemon.
    pub product: Option<&'a str>,
    /// The organization behind the product, where one could be attributed.
    pub vendor: Option<&'a str>,
    /// The version string reported or detected.
    pub version: Option<&'a str>,
    /// Additional metadata or environment hints.
    pub extrainfo: Option<&'a str>,
    /// CPE identifiers, in the order they were established.
    pub cpe: Vec<&'a str>,
}

impl<'a> ServiceDto<'a> {
    /// Renders a service identification.
    pub fn new(service: &'a Service) -> Self {
        Self {
            name: service.name(),
            confidence: service.confidence(),
            product: service.product(),
            vendor: service.vendor(),
            version: service.version(),
            extrainfo: service.extrainfo(),
            cpe: service.cpe().iter().map(String::as_str).collect(),
        }
    }
}

/// Transport security negotiated on a port.
#[derive(Debug, Clone, Serialize)]
pub struct SecurityDto<'a> {
    /// The negotiated TLS version.
    pub tls_version: Option<&'a str>,
    /// The cipher suite the server selected.
    pub cipher_suite: Option<&'a str>,
    /// ALPN protocols offered, in order.
    pub alpn: Vec<&'a str>,
    /// The presented X.509 certificate.
    pub certificate: Option<CertificateDto<'a>>,
}

impl<'a> SecurityDto<'a> {
    /// Renders security telemetry, applying the redaction policy.
    pub fn new(security: &'a Security, options: &ExportOptions) -> Self {
        Self {
            tls_version: security.tls_version(),
            cipher_suite: security.cipher_suite(),
            alpn: security.alpn().iter().map(String::as_str).collect(),
            certificate: security
                .certificate()
                .map(|cert| CertificateDto::new(cert, options)),
        }
    }
}

/// A presented X.509 certificate.
#[derive(Debug, Clone, Serialize)]
pub struct CertificateDto<'a> {
    /// The subject Common Name, masked under redaction: an internal CA issues
    /// certificates naming people and machines.
    pub common_name: Cow<'a, str>,
    /// Subject Alternative Names, masked under redaction for the same reason.
    pub sans: Vec<Cow<'a, str>>,
    /// The issuing authority.
    pub issuer: &'a str,
    /// When the certificate becomes valid.
    pub validity_start: String,
    /// When it expires.
    pub validity_end: String,
    /// The public key algorithm.
    pub pubkey_type: &'a str,
    /// The public key size in bits.
    pub pubkey_bits: u32,
    /// The SHA-256 fingerprint of the DER-encoded certificate.
    pub fingerprint_sha256: &'a str,
}

impl<'a> CertificateDto<'a> {
    /// Renders certificate information, applying the redaction policy.
    pub fn new(cert: &'a CertificateInfo, options: &ExportOptions) -> Self {
        let redaction = options.redaction;

        Self {
            common_name: redaction.hostname(cert.common_name()),
            sans: cert
                .sans()
                .iter()
                .map(|san| redaction.hostname(san))
                .collect(),
            issuer: cert.issuer(),
            validity_start: rfc3339(cert.validity_start()),
            validity_end: rfc3339(cert.validity_end()),
            pubkey_type: cert.pubkey_type(),
            pubkey_bits: cert.pubkey_bits(),
            fingerprint_sha256: cert.fingerprint_sha256(),
        }
    }
}

/// How a port's state was established.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryDto<'a> {
    /// The packet response that decided the state.
    pub reason: Cow<'a, str>,
    /// When the state was first confirmed.
    pub timestamp: String,
    /// The probe's round trip.
    pub rtt_us: Option<u64>,
    /// The TTL of the response packet.
    pub ttl: Option<u8>,
    /// The local interface address the probe was answered on. Relevant on
    /// multi-homed hosts, where port states differ by path.
    pub source_ip: Option<String>,
}

impl<'a> DiscoveryDto<'a> {
    /// Renders discovery telemetry.
    pub fn new(discovery: &'a Discovery) -> Self {
        Self {
            reason: scan_response_name(discovery.reason()),
            timestamp: rfc3339(discovery.timestamp()),
            rtt_us: micros_opt(discovery.rtt()),
            ttl: discovery.ttl(),
            source_ip: discovery.source_ip().map(|ip| ip.to_string()),
        }
    }
}

/// A structured script result, rendered as the natural JSON value.
///
/// Scripts produce arbitrary nested data, so this is the one place in the
/// document without a fixed shape. Maps are emitted in sorted key order, and a
/// non-finite float - which has no JSON representation - is emitted as `null`
/// rather than failing the whole export.
#[derive(Debug, Clone)]
pub struct ScriptValueDto<'a>(pub &'a ScriptOutput);

impl Serialize for ScriptValueDto<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        match self.0 {
            ScriptOutput::String(value) => serializer.serialize_str(value),
            ScriptOutput::Integer(value) => serializer.serialize_i64(*value),
            ScriptOutput::Float(value) if value.is_finite() => serializer.serialize_f64(*value),
            // NaN and the infinities are not JSON numbers. A script that
            // produces one must not take the rest of the report down with it.
            ScriptOutput::Float(_) => serializer.serialize_none(),
            ScriptOutput::Boolean(value) => serializer.serialize_bool(*value),
            ScriptOutput::List(values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    seq.serialize_element(&ScriptValueDto(value))?;
                }
                seq.end()
            }
            ScriptOutput::Map(entries) => {
                let sorted: BTreeMap<&str, &ScriptOutput> = entries
                    .iter()
                    .map(|(key, value)| (key.as_str(), value))
                    .collect();

                let mut map = serializer.serialize_map(Some(sorted.len()))?;
                for (key, value) in sorted {
                    map.serialize_entry(key, &ScriptValueDto(value))?;
                }
                map.end()
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
    use crate::core::models::ip::set::IpSet;
    use crate::core::models::port::PortSet;
    use crate::core::models::target::{TargetMap, TargetSet};

    /// Every enumerated value the document can carry has to be spelled the same
    /// way twice - once here, once in the schema file. Pinning the strings is
    /// what turns a rename into a failing test rather than a silent break in
    /// somebody's parser.
    #[test]
    fn wire_names_are_pinned() {
        assert_eq!(scan_kind_name(ScanKind::PortScan), "port_scan");
        assert_eq!(scanner_kind_name(ScannerKind::SynPort), "syn_port");
        assert_eq!(host_status_name(HostStatus::Filtered), "filtered");
        assert_eq!(port_state_name(PortState::OpenFiltered), "open_filtered");
        assert_eq!(protocol_name(Protocol::Udp), "udp");
        assert_eq!(network_role_name(NetworkRole::DHCP), "dhcp");
        assert_eq!(
            stop_reason_name(StopReason::AttemptsSpent),
            "attempts_spent"
        );
        assert_eq!(send_mode_name(SendMode::RawSocket), "raw_socket");
        assert_eq!(scan_effort_name(ScanEffort::Thorough), "thorough");
    }

    /// A strategy naming itself after a built-in must not produce a reason
    /// indistinguishable from the real thing.
    #[test]
    fn a_custom_name_can_never_collide_with_a_builtin() {
        let impostor = StatusProtocol::Custom("arp".into());

        assert_eq!(status_protocol_name(&StatusProtocol::Arp), "arp");
        assert_eq!(status_protocol_name(&impostor), "custom:arp");

        let response = ScanResponse::Custom("tcp_rst".into());
        assert_eq!(scan_response_name(&ScanResponse::TcpRst), "tcp_rst");
        assert_eq!(scan_response_name(&response), "custom:tcp_rst");
    }

    /// Every status and state is a key in the summary, whether or not anything
    /// landed in it, so a consumer never has to guess what a missing key means.
    #[test]
    fn the_summary_reports_categories_that_saw_nothing() {
        let summary = SummaryDto::new(&ScanSummary::default());

        assert_eq!(summary.hosts_by_status.up, 0);
        assert_eq!(summary.hosts_by_status.unknown, 0);
        assert_eq!(summary.ports_by_state.open, 0);
        assert_eq!(summary.ports_by_state.closed_filtered, 0);
    }

    /// The counts that can exceed what a JSON number holds exactly are the ones
    /// an IPv6 sweep produces. They have to survive the round trip as text.
    #[test]
    fn oversized_counts_are_rendered_as_exact_strings() {
        let mut ips = IpSet::new();
        ips.insert_range("2001:db8::/32".parse().expect("a valid range"));

        let scope = ScopeDto::new(&TargetScope::from_ip_set(&mut ips));

        // 2^96, which a JSON number as JavaScript implements one would round to
        // something else entirely.
        assert_eq!(scope.addresses, "79228162514264337593543950336");
        assert!(scope.addresses.parse::<u128>().expect("exact") > (1u128 << 53));
    }

    /// A discovery phase has no port dimension, so its probe count is absent
    /// rather than zero - zero would claim the sweep sent nothing.
    #[test]
    fn a_discovery_scope_has_no_probe_count() {
        let mut ips = IpSet::new();
        ips.insert_range("192.168.0.0/24".parse().expect("a valid range"));

        let scope = ScopeDto::new(&TargetScope::from_ip_set(&mut ips));

        assert_eq!(scope.addresses, "256");
        assert_eq!(scope.probes, None);
        assert!(scope.protocols.is_empty());
        assert_eq!(scope.ranges.len(), 1);
        assert_eq!(scope.ranges[0].family, "ipv4");
        assert_eq!(scope.ranges[0].start, "192.168.0.0");
        assert_eq!(scope.ranges[0].end, "192.168.0.255");
    }

    #[test]
    fn a_port_scan_scope_carries_the_probe_count() {
        let mut ips = IpSet::new();
        ips.insert_range("10.0.0.1-10.0.0.4".parse().expect("a valid range"));

        let mut targets = TargetMap::new();
        targets.add_unit(TargetSet::new(
            ips,
            PortSet::from_iter([(80, Protocol::Tcp), (53, Protocol::Udp)]),
        ));

        let scope = ScopeDto::new(&TargetScope::from_target_map(&mut targets));

        assert_eq!(scope.addresses, "4");
        assert_eq!(scope.probes.as_deref(), Some("8"));
        assert_eq!(scope.protocols, vec!["tcp", "udp"]);
    }

    /// A consumer that adds up the phases and compares the result to the total
    /// must get the same number, whatever the sub-microsecond remainders were.
    #[cfg(feature = "export-json")]
    #[test]
    fn the_total_duration_is_exactly_the_sum_of_the_phases() {
        let mut report = crate::export::fixture::report();
        report.merge(crate::export::fixture::report());

        let document = serde_json::to_value(ReportDto::new(&report, &ExportOptions::new()))
            .expect("the report serializes");

        let summed: u64 = document["phases"]
            .as_array()
            .expect("a phase array")
            .iter()
            .map(|phase| phase["elapsed_us"].as_u64().expect("a phase duration"))
            .sum();

        assert_eq!(document["elapsed_us"].as_u64(), Some(summed));
    }

    /// A scale nobody can write down is not a scale two runs should be claimed
    /// to share, and it is not a JSON number either.
    #[test]
    fn a_non_finite_timeout_scale_is_dropped() {
        let retry = RetryConfig {
            timeout_scale: Some(f64::NAN),
            ..Default::default()
        };
        assert_eq!(RetryDto::new(&retry).timeout_scale, None);

        let retry = RetryConfig {
            timeout_scale: Some(2.5),
            ..Default::default()
        };
        assert_eq!(RetryDto::new(&retry).timeout_scale, Some(2.5));
    }
}
