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
//! engine is serializable.
//!
//! [`Host`] and its neighbours are the engine's working types, with private
//! fields laid out for the scanners and refactored freely. The mapping to the
//! wire is written by hand here so those refactors never change the format, and
//! a format change is always an edit to this file. Every enum is mapped by an
//! exhaustive `match`, so a new variant in a core type fails to compile until it
//! is given a JSON name.
//!
//! ## Conventions
//!
//! - **Timestamps are RFC 3339 strings in UTC**, to microsecond precision; see
//!   [`time`](crate::format::time).
//! - **Durations are integers of microseconds**, in a field whose name ends in
//!   `_us`.
//! - **Counts that can exceed 2^53 are decimal strings.** An IPv6 sweep's
//!   address count does not fit a JavaScript number exactly. Everything narrow
//!   enough to be exact stays a number.
//! - **Objects have a fixed shape.** A field with no value is present and
//!   `null`, and an empty list is present and empty. The exception is a field
//!   describing something the scan did not do at all, such as an evasion
//!   profile on a scan that altered no packets or a switch on a network with no
//!   managed equipment, which is left out. A consumer reading an absent field as
//!   the empty one (`null`, `[]` or `false`) reads every document correctly.
//!   `assets/schema/zond-report-v1.schema.json` lists them: every field it does
//!   not mark `required`.
//! - **Order is deterministic.** Hosts sort by primary IP, ports by number, sets
//!   by their natural order, so two scans that found the same things diff
//!   cleanly.
//! - **Unknown fields may appear.** Additive changes do not bump
//!   [`SCHEMA_VERSION`], so a consumer must ignore what it does not recognise.
//!
//! ## Every type here is `#[non_exhaustive]`
//!
//! So adding a field does not break Rust code that builds one by name. Every
//! field stays public and readable; each type has a constructor taking the
//! engine value it describes.
//!
//! ## Streaming
//!
//! [`ReportDto`] borrows the report and serializes hosts from an iterator. One
//! [`HostDto`] exists at a time, so exporting a /16 costs a host's worth of
//! memory.
//!
//! [`Host`]: crate::model::host::Host

use std::borrow::Cow;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use serde::Serialize;
use serde::ser::{SerializeSeq, Serializer};

use crate::config::{RetryConfig, ScanEffort};
use crate::export::{ExportOptions, HostRedaction};
use crate::format::time::rfc3339;
use crate::model::capture::CaptureCounts;
use crate::model::finding::{Finding, Reference};
use crate::model::host::{
    HardwareInfo, Hop, Host, HostName, HostStatus, HostTelemetry, OsFingerprint, StatusReason,
    ip_protocol_name,
};
use crate::model::ip::range::IpRange;
use crate::model::port::{
    Build, CertificateInfo, Discovery, Port, PortSet, PortState, Security, Service,
};
use crate::model::tls::{CipherSuite, UnfinishedVersion, VersionSupport};
use crate::report::{
    ATTEMPTS_COUNTED, BUCKET_BOUNDS_MS, EvasionRecord, PortScope, ProbeStats, Refusal, ScanPhase,
    ScanReport, ScanSettings, ScanSummary, ScannerFailure, TargetScope,
};
use crate::system::privilege::Privilege;
use crate::transport::probe::SendMode;

// Defined in `crate::format` so a reader does not depend on the writer;
// re-exported so this module describes the whole document.
pub use crate::format::{ENGINE_NAME, SCHEMA_VERSION};
pub use crate::report::ENGINE_VERSION;

// ---------------------------------------------------------------------------
// Enum names
//
// The wire spelling of every enumerated value in the document. Public so a
// third-party exporter spells them the way the JSON does.
// ---------------------------------------------------------------------------

/// The wire name of a host's reachability status.
// Defined in `record::wire`, beside the parsers that read them back, so a name
// and its inverse cannot drift apart.
pub use crate::record::wire::{
    attachment_source_name, confidence_name, detection_ceiling_name, detection_class_name,
    distributor_name, filtering_name, host_status_name, ip_protocol_state_name, liveness_skip_name,
    name_kind_name, name_source_name, network_role_name, pass_name, port_scope_name,
    port_state_name, protocol_name, reference_kind_name, release_basis_name, scan_kind_name,
    scan_response_name, scanner_kind_name, severity_name, status_protocol_name, stop_reason_name,
    tcp_flags_name,
};

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

/// Renders a duration as whole microseconds.
///
/// Saturates at `u64::MAX` (about 585,000 years), so an unrepresentable
/// measurement never comes out small.
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
/// Borrows the report: constructing one is free, and serializing it walks the
/// hosts one at a time. See the [module documentation](self) for the
/// conventions the output obeys.
///
/// ```no_run
/// use zond_engine::report::ScanReport;
/// use zond_engine::export::{ExportOptions, schema::ReportDto};
///
/// # fn example(report: &ScanReport) -> Result<(), Box<dyn std::error::Error>> {
/// let options = ExportOptions::new();
/// let document = ReportDto::new(report, &options);
/// # let _ = document;
/// # Ok(())
/// # }
/// ```
#[non_exhaustive]
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
    /// For a test producing a document that is byte-identical across runs; the
    /// generation time is the only field the scan does not determine.
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
        write_header(&mut doc, self.report, self.generated_at, self.options)?;
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
/// The same fields [`ReportDto`] emits before its `hosts` array, in the same
/// order and rendered by the same code. A record-per-line format writes this
/// once and then the hosts one at a time.
#[non_exhaustive]
#[derive(Debug)]
pub struct ReportHeaderDto<'a> {
    report: &'a ScanReport,
    options: &'a ExportOptions,
    generated_at: SystemTime,
}

impl<'a> ReportHeaderDto<'a> {
    /// Describes a report's header, stamped with the current time.
    ///
    /// Takes the same options the hosts are written under: a phase carries the
    /// switch this machine was plugged into, which names a device and a
    /// hardware address.
    pub fn new(report: &'a ScanReport, options: &'a ExportOptions) -> Self {
        Self::generated_at(report, options, SystemTime::now())
    }

    /// Describes a report's header with an explicit generation time.
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
}

impl Serialize for ReportHeaderDto<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let mut doc = serializer.serialize_struct("ReportHeader", HEADER_FIELDS)?;
        write_header(&mut doc, self.report, self.generated_at, self.options)?;
        doc.end()
    }
}

/// How long a scan took, as the document reports it.
///
/// The sum of the phases' rendered figures. Each is truncated to whole
/// microseconds independently, so summing the underlying durations could exceed
/// the printed figures by a microsecond.
///
/// Public so every rendering of a report, including one outside this crate,
/// agrees on this number.
pub fn total_elapsed_us(phases: &[PhaseDto<'_>]) -> u64 {
    phases
        .iter()
        .fold(0u64, |total, phase| total.saturating_add(phase.elapsed_us))
}

/// How many fields [`write_header`] emits, at most.
const HEADER_FIELDS: usize = 12;

/// Emits the fields every rendering of a report starts with.
fn write_header<S: serde::ser::SerializeStruct>(
    doc: &mut S,
    report: &ScanReport,
    generated_at: SystemTime,
    options: &ExportOptions,
) -> Result<(), S::Error> {
    let phases: Vec<PhaseDto<'_>> = report
        .phases()
        .iter()
        .map(|phase| PhaseDto::new(phase, options))
        .collect();
    let elapsed_us = total_elapsed_us(&phases);

    doc.serialize_field("schema_version", &SCHEMA_VERSION)?;
    doc.serialize_field(
        "engine",
        &EngineDto {
            name: ENGINE_NAME,
            version: ENGINE_VERSION,
        },
    )?;
    doc.serialize_field("produced_by", report.engine_version())?;
    doc.serialize_field("generated_at", &rfc3339(generated_at))?;
    doc.serialize_field("started_at", &rfc3339(report.started_at()))?;
    doc.serialize_field("elapsed_us", &elapsed_us)?;
    doc.serialize_field("partial", &report.is_partial())?;

    // What the report as a whole left open, as `partial` reads it. A report
    // holding several accounts of the same ground (a resumed job's sittings, a
    // merge's sources) can close in one what another left open, so the phases'
    // own lists do not add up to this. Left out when empty.
    let timed_out = report.timed_out();
    if timed_out.is_empty() {
        doc.skip_field("timed_out")?;
    } else {
        let timed_out: Vec<String> = timed_out.iter().map(ToString::to_string).collect();
        doc.serialize_field("timed_out", &timed_out)?;
    }
    let undecided = report.undecided();
    if undecided.is_empty() {
        doc.skip_field("undecided")?;
    } else {
        let undecided: Vec<RangeDto> = undecided.iter().map(RangeDto::new).collect();
        doc.serialize_field("undecided", &undecided)?;
    }
    match report.unreached() {
        0 => doc.skip_field("unreached")?,
        unreached => doc.serialize_field("unreached", &unreached.to_string())?,
    }

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

/// Which build wrote a document.
///
/// Always this build, both name and version. What produced the findings is
/// `produced_by`.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct EngineDto {
    /// Always [`ENGINE_NAME`], so a reader can recognise a zond report.
    pub name: &'static str,
    /// Always [`ENGINE_VERSION`]: the crate version of the build that wrote the
    /// document.
    pub version: &'static str,
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

/// Headline counts, with the full distribution behind each one.
///
/// The per-status and per-state breakdowns are structs, so every category is
/// present, in severity order, even at zero.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct SummaryDto {
    /// Hosts recorded, whatever their status.
    pub hosts_total: usize,
    /// Hosts confirmed present on the network: `up` or `blocked`.
    pub hosts_alive: usize,
    /// The full status distribution.
    pub hosts_by_status: HostStatusCounts,
    /// Port records across all hosts.
    pub ports_total: usize,
    /// Ports found accepting connections.
    pub ports_open: usize,
    /// The full port-state distribution.
    pub ports_by_state: PortStateCounts,
    /// Ports whose service was identified by fingerprinting, not counting a
    /// name read off the port number.
    pub services_identified: usize,
    /// Hosts counted by the address families they answered at.
    pub hosts_by_family: FamilyCounts,
}

/// Hosts counted by the address families they answered at.
///
/// A dual-stack host is counted in all three, so these do not partition
/// `hosts_total`.
#[non_exhaustive]
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
                blocked: status(HostStatus::Blocked),
                down: status(HostStatus::Down),
                unknown: status(HostStatus::Unknown),
            },
            ports_total: summary.ports_total,
            ports_open: summary.ports_open,
            ports_by_state: PortStateCounts {
                open: state(PortState::Open),
                open_or_no_reply: state(PortState::OpenOrNoReply),
                closed: state(PortState::Closed),
                reachable: state(PortState::Reachable),
                blocked: state(PortState::Blocked),
                no_reply: state(PortState::NoReply),
                closed_or_no_reply: state(PortState::ClosedOrNoReply),
                unasked: state(PortState::Unasked),
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
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct HostStatusCounts {
    /// Online and responding.
    pub up: usize,
    /// Not answering for itself, but refused by policy on its behalf, so
    /// something is there enforcing a perimeter.
    pub blocked: usize,
    /// Explicitly confirmed unreachable.
    pub down: usize,
    /// Never determined.
    pub unknown: usize,
}

/// How many ports fell into each state.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct PortStateCounts {
    /// Accepting connections.
    pub open: usize,
    /// Open, or no reply: silence where an open port is silent too; the
    /// usual UDP outcome.
    pub open_or_no_reply: usize,
    /// Actively refusing connections.
    pub closed: usize,
    /// Reachable, but open or closed could not be told apart.
    pub reachable: usize,
    /// Refused by an ICMP error from the host or the path.
    pub blocked: usize,
    /// Asked on every attempt, and nothing came back.
    pub no_reply: usize,
    /// Closed, or no reply.
    pub closed_or_no_reply: usize,
    /// Named by the scan and never probed, so nothing was established. A
    /// non-zero count here is the visible half of a run that fell short; the
    /// phase's `timed_out` and `stop_reason` say why.
    pub unasked: usize,
}

// ---------------------------------------------------------------------------
// Phases
// ---------------------------------------------------------------------------

/// One call into the engine: what it was asked to do, how it was configured,
/// how long it took, and what it observed about itself.
#[non_exhaustive]
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
    ///
    /// `null` on a phase this engine did not measure, where the question is
    /// about strategies that never ran.
    pub privileged: Option<bool>,
    /// What the phase was asked to cover.
    pub targets: ScopeDto,
    /// The settings that shaped the packets it sent.
    pub settings: SettingsDto,
    /// Strategies that did not run to completion. A non-empty list means the
    /// findings are narrower than the caller asked for.
    pub failures: Vec<FailureDto<'a>>,
    /// Ground the phase declined to cover before sending anything, and why.
    ///
    /// Kept apart from `failures`: nothing broke. Part of what was asked had no
    /// strategy behind it, which is a property of the scan as written and
    /// recurs every time it runs, where a failure might not.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub refusals: Vec<RefusalDto<'a>>,
    /// Addresses this host could not reach, so no probe was sent to them,
    /// ascending: no route or source address led to them, or they are
    /// neighbours on a local segment that never answered address resolution.
    ///
    /// Not failures, and they do not make the result partial. An address here
    /// was never probed, which differs from one probed that stayed silent.
    pub unroutable: Vec<String>,
    /// The addresses among `unroutable` this host's own routing table
    /// refuses, ascending: a route an administrator added over them, or a
    /// VPN's kill switch. Left out when empty. The remedy is on the scanning
    /// machine.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub refused_by_route: Vec<String>,
    /// Addresses the phase stopped working on because their own budget ran out,
    /// ascending.
    ///
    /// Left out when empty, which is every phase that set no per-host budget.
    /// The ports an address here never reached are present with the scan's
    /// silence verdict; this list tells them from a quiet machine.
    ///
    /// The record of this phase. What the report as a whole left early, read
    /// across its phases, is the document's own `timed_out`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub timed_out: Vec<String>,
    /// Addresses whose ICMP errors the phase found rate-limited, ascending.
    ///
    /// Left out when empty. A closed UDP port is known only by the ICMP port
    /// unreachable its host sends, and a host here rationed those, so most of
    /// its closed ports read `open_or_no_reply` beside the few that read
    /// `closed`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub icmp_rate_limited: Vec<String>,
    /// Addresses this phase reached by TCP connect although it held the
    /// privilege its raw strategies need, ascending.
    ///
    /// Left out when empty, which is most phases. What the phase found at one
    /// of these is connect evidence under a phase whose `privileged` reads as
    /// true: loopback, an address nothing routes to, and, for a process that
    /// can inject frames and holds no raw socket, whatever those frames cannot
    /// reach.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reached_by_connect: Vec<RangeDto>,
    /// Addresses in this phase's scope whose presence it reached no verdict
    /// on, ascending.
    ///
    /// Left out when empty, which is every phase that finished its question
    /// and every phase that is not a discovery. An address here was neither
    /// answered nor asked as many times as the policy allows: the phase stopped
    /// first, had no strategy for it, was refused it, or ran out of time. It is
    /// not a host found down, and the lack of a port-scan record there says
    /// nothing about the network. Disjoint from `unroutable`.
    ///
    /// The record of this phase. What the report as a whole left undecided,
    /// read across its phases, is the document's own `undecided`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub undecided: Vec<RangeDto>,
    /// Why this port phase ran with no liveness pass in front of it, by name.
    ///
    /// Left out where a discovery phase preceded it, and on every phase that is
    /// not a port scan. Stated explicitly because the caller's choice, an idle
    /// scan and the engine's own decision look the same in the phase list and
    /// differ in what the findings mean.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liveness_skipped: Option<&'static str>,
    /// Addresses this port phase asked on every port and heard nothing from,
    /// ascending.
    ///
    /// Left out when empty, which is every phase but a port phase standing in
    /// for a liveness pass the engine dropped as no cheaper. There an address
    /// here drew no open port, no closed one and no ICMP error, is not listed
    /// as a host, and is not undecided: its ports were asked.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub silent: Vec<RangeDto>,
    /// Why the scan was stopped while this phase ran, `aborted` or
    /// `timed_out`.
    ///
    /// Left out for a phase that ended on its own, and for every listen phase,
    /// which a stop ends without cutting short. A marker only: what a stop cost
    /// is `unreached`, the ports on their hosts as `unasked`, `undecided` and
    /// `passes_cut`, and a phase stopped after asking everything and running
    /// every pass is complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped: Option<&'static str>,
    /// The passes over the phase's findings a stop skipped or cut short, in
    /// the order a scan runs them: `services`, `detections`, `tls`, `os`,
    /// `traceroute`, `filters`, `ip_protocols`. Only a pass the scan was asked
    /// to run and had something to run over.
    ///
    /// Left out when empty, which is every phase no stop cut.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub passes_cut: Vec<&'static str>,
    /// How many of this port phase's targets it never asked and holds on no
    /// host, as a decimal string: never reached by its walk because the scan
    /// was stopped first, passed for an address its liveness pass reached no
    /// verdict on, or left unasked at an address it names `undecided`.
    ///
    /// Left out when none were, which is every phase that asked everything it
    /// was handed and every phase that is not a port scan. A count because what
    /// a stop leaves is scattered across the plan. Every target the phase was
    /// handed is probed, on its host as `unasked`, counted here, or settled
    /// unprobed for an address its liveness pass found silent or could not
    /// reach.
    ///
    /// The record of this phase. What the job as a whole has left, read across
    /// its sittings, is the document's own `unreached`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unreached: Option<String>,
    /// How many of this port phase's targets it asked at the addresses it
    /// lists no host at, as a decimal string: every port of the ones in
    /// `silent`, and the ports it reached of the ones in `undecided`.
    ///
    /// Left out when none were, which is every phase that did not stand in
    /// for a liveness pass. Those addresses' records are dropped, so a count of
    /// probes read off the hosts comes up short by this. The scope cannot
    /// supply it where the phase gave different addresses different ports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unheard_probes: Option<String>,
    /// What each instrumented scanner observed about its own run. Empty where
    /// no strategy in this phase carries instrumentation.
    pub probe_stats: Vec<ProbeStatsDto>,
    /// Which document this phase was folded in from, for a report merged out of
    /// several.
    ///
    /// `null` on a phase the engine that wrote this document measured itself,
    /// where the report's own `engine` is the attribution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<PhaseOriginDto<'a>>,
    /// Which switch ports the machine running this phase was plugged into, as
    /// the equipment on the far end announced itself.
    ///
    /// Empty where nothing announced itself, which is every unmanaged network.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentDto<'a>>,
    /// Whether this is the phase as it stood before it closed: its sitting
    /// was killed outright, or was still running when its journal was read.
    ///
    /// Left out for a phase that closed, which is every phase but the last of
    /// a sitting that never ended. An open phase says what it opened with, how
    /// long it had run and what failed in it. Its `stopped`, `unreached` and
    /// `passes_cut` are absent because only a close establishes them, so their
    /// absence does not mean nothing cut it short.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub open: bool,
}

/// Where the machine running a phase was plugged in.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct AttachmentDto<'a> {
    /// Which of the scanning machine's interfaces the announcement arrived on.
    pub link: &'a str,
    /// Which protocol it was read from.
    pub source: &'a str,
    /// The hardware address the device identified its chassis with, masked
    /// under redaction. `null` where it named itself some other way.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_mac: Option<String>,
    /// What the device calls itself, which on managed equipment is its
    /// hostname. Masked under redaction, on the same terms a host's is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<Cow<'a, str>>,
    /// What the device calls the port this machine is plugged into.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<&'a str>,
    /// The VLAN untagged traffic on this port lands in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_vlan: Option<u16>,
    /// An address the device is managed at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub management_address: Option<String>,
    /// When the announcement arrived.
    pub observed_at: String,
}

/// Which document a phase came from, for a merged report.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct PhaseOriginDto<'a> {
    /// What the caller called the document it was read from. `null` where it
    /// gave no name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<&'a str>,
    /// What produced the phase, as that scanner attributed itself, such as
    /// `nmap 7.94` for a phase read from nmap's XML.
    pub engine_version: &'a str,
}

impl<'a> PhaseDto<'a> {
    /// Renders a recorded phase, applying the redaction policy in `options`.
    ///
    /// What a phase carries to redact is its
    /// [`attachment`](crate::report::Attachment), which names a switch and its
    /// hardware address.
    pub fn new(phase: &'a ScanPhase, options: &ExportOptions) -> Self {
        Self {
            kind: scan_kind_name(phase.kind()),
            started_at: rfc3339(phase.started_at()),
            elapsed_us: micros(phase.elapsed()),
            privileged: phase.privilege().map(Privilege::is_raw),
            targets: ScopeDto::new(phase.targets()),
            settings: SettingsDto::new(phase.settings()),
            failures: phase.failures().iter().map(FailureDto::new).collect(),
            refusals: phase.refusals().iter().map(RefusalDto::new).collect(),
            unroutable: phase
                .unroutable()
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            refused_by_route: phase
                .refused_by_route()
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            timed_out: phase
                .timed_out()
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            icmp_rate_limited: phase
                .icmp_rate_limited()
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            reached_by_connect: phase
                .reached_by_connect()
                .iter()
                .map(RangeDto::new)
                .collect(),
            undecided: phase.undecided().iter().map(RangeDto::new).collect(),
            liveness_skipped: phase.liveness_skipped().map(liveness_skip_name),
            silent: phase.silent().iter().map(RangeDto::new).collect(),
            stopped: phase.stopped().map(stop_reason_name),
            passes_cut: phase.passes_cut().iter().copied().map(pass_name).collect(),
            unreached: (phase.unreached() > 0).then(|| phase.unreached().to_string()),
            unheard_probes: (phase.unheard_probes() > 0)
                .then(|| phase.unheard_probes().to_string()),
            probe_stats: phase.probe_stats().iter().map(ProbeStatsDto::new).collect(),
            origin: phase.origin().map(|origin| PhaseOriginDto {
                label: origin.label(),
                engine_version: origin.engine_version(),
            }),
            attachments: phase
                .attachments()
                .iter()
                .map(|attachment| AttachmentDto {
                    link: attachment.link().name(),
                    source: attachment_source_name(attachment.source()),
                    device_mac: attachment
                        .device_mac()
                        .map(|mac| options.redaction.mac(&mac)),
                    device_name: attachment
                        .device_name()
                        .map(|name| options.redaction.hostname(name)),
                    port: attachment.port(),
                    native_vlan: attachment.native_vlan(),
                    management_address: attachment
                        .management_address()
                        .map(|address| address.to_string()),
                    observed_at: rfc3339(attachment.observed_at()),
                })
                .collect(),
            open: phase.is_open(),
        }
    }
}

/// What a phase was asked to cover.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct ScopeDto {
    /// The merged ranges the sweep iterated, ascending, with overlapping
    /// arguments coalesced.
    pub ranges: Vec<RangeDto>,
    /// How many distinct addresses were in scope, as a decimal string.
    pub addresses: String,
    /// How many address/port/protocol combinations were in scope, as a decimal
    /// string.
    ///
    /// `null` on a discovery phase, which has no port dimension, and on a target
    /// set too large to count. The phase `kind` tells the two apart.
    pub probes: Option<String>,
    /// The links this phase swept whole, by interface name, ascending.
    ///
    /// A sweep of a local segment reaches every host on the link, which no
    /// entry in `ranges` expresses, so a consumer checking whether a host was in
    /// scope has to read both.
    ///
    /// Empty for a phase that swept no segment. Only the interface name is
    /// written; its index means nothing on another machine.
    pub links: Vec<String>,
    /// The links this phase read traffic from without probing them.
    ///
    /// This is not coverage. A sweep's probe obliges every host on the segment
    /// to answer, so a host missing from the report was not there; listening
    /// cannot tell a machine quiet during the window from an absent one. Read
    /// it to know where a phase was standing, not to conclude what was there.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub listened: Vec<String>,
    /// Which ports the phase walked, and whether it walked the same ones for
    /// every address.
    ///
    /// `null` where the record does not say, as in a report rebuilt from another
    /// tool's output. `probes` counts these combinations; this names the ports.
    pub ports: Option<PortScopeDto>,
    /// The transport protocols in scope, ascending. Empty on a discovery phase,
    /// whose probes the strategy chooses.
    pub protocols: Vec<&'static str>,
    /// The merged ranges the phase was forbidden to probe, ascending.
    ///
    /// Empty when no exclusion policy was in force. A policy that overlapped
    /// nothing still appears in full, with `withheld` at zero.
    ///
    /// No host in this report may fall inside any of these ranges.
    pub excluded: Vec<RangeDto>,
    /// How many addresses the exclusion policy took out of this phase, as a
    /// decimal string.
    ///
    /// The overlap between the policy and what this phase was handed, measured
    /// when its scope was recorded. It is `"0"` for a policy naming ground the
    /// phase would never have walked, and for a phase whose input an earlier one
    /// had already narrowed.
    pub withheld: String,
}

/// Which ports a phase walked.
///
/// `kind` says what may be concluded from the set in `spec`.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct PortScopeDto {
    /// `none` for a phase that walked no ports, `every` where each address was
    /// walked for the same set, and `mixed` where they differed and `spec` is
    /// their union.
    ///
    /// Only `every` supports concluding that a particular endpoint of a covered
    /// address was probed. Under `mixed`, a port in the set was walked for at
    /// least one address and not necessarily for any given one, though a port
    /// absent from the set was walked for none.
    pub kind: &'static str,
    /// The ports, written as the specification a scanner takes: comma
    /// separated, `start-end` for a run, `u:` prefixing the UDP half. Empty
    /// under `none`.
    pub spec: String,
}

impl PortScopeDto {
    /// Renders a port scope, or `None` where the record does not state one.
    pub fn new(scope: &PortScope) -> Option<Self> {
        match scope {
            PortScope::Unstated => None,
            other => Some(Self {
                kind: port_scope_name(other),
                spec: other.ports().map(PortSet::to_string).unwrap_or_default(),
            }),
        }
    }
}

impl ScopeDto {
    /// Renders a recorded scope.
    pub fn new(scope: &TargetScope) -> Self {
        Self {
            ranges: scope.ranges().iter().map(RangeDto::new).collect(),
            links: {
                let mut links: Vec<String> = scope
                    .links()
                    .iter()
                    .map(|zone| zone.name().to_owned())
                    .collect();
                links.sort();
                links
            },
            listened: {
                let mut listened: Vec<String> = scope
                    .listened()
                    .iter()
                    .map(|zone| zone.name().to_owned())
                    .collect();
                listened.sort();
                listened
            },
            addresses: scope.addresses().to_string(),
            probes: scope.probes().map(|count| count.to_string()),
            ports: PortScopeDto::new(scope.ports()),
            protocols: scope
                .protocols()
                .iter()
                .copied()
                .map(protocol_name)
                .collect(),
            excluded: scope.excluded().iter().map(RangeDto::new).collect(),
            withheld: scope.withheld().to_string(),
        }
    }
}

/// One inclusive address range.
#[non_exhaustive]
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
/// The subset of the engine's configuration that changed the packets or how
/// long the engine waited for answers. Presentation settings are left out.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct SettingsDto {
    /// How raw probes were placed on the wire.
    pub send_mode: &'static str,
    /// Which segment each TCP port probe carried: `syn`, `fin`, `null`, `xmas`,
    /// `maimon` or `ack`.
    ///
    /// Needed to read a port state. `closed` from a SYN scan is a refused
    /// connection attempt; `closed` from a FIN scan is a reset drawn by a
    /// non-SYN segment, and against a stack that resets everything it may mean
    /// nothing.
    pub tcp_technique: &'static str,
    /// Which chunk each SCTP port probe carried: `init` or `cookie-echo`.
    ///
    /// An SCTP port reported `open_or_no_reply` came from a `cookie-echo` scan,
    /// which draws an answer only from a closed port and so cannot report one
    /// open at all. Under `init` the same port would have been settled either
    /// way.
    pub sctp_technique: &'static str,
    /// The retransmission budget and patience in force.
    pub retry: RetryDto,
    /// The probe-rate ceiling in probes per second, or `null` if the scanner's
    /// own default applied.
    pub max_probe_rate: Option<u32>,
    /// The probe-rate floor in probes per second, or `null` if the scan was free
    /// to settle wherever it liked.
    ///
    /// A scan that emitted more packets than its targets were answering did so
    /// to meet this floor.
    pub min_probe_rate: Option<u32>,
    /// The shortest gap kept between two probes at one host, or `null` if none
    /// was asked for.
    ///
    /// It bounds the phase's duration: a thousand probes at one host a tenth of
    /// a second apart take at least a hundred seconds.
    pub host_probe_interval_us: Option<u64>,
    /// The shortest gap kept between any two probes the scan sent, or `null`
    /// if none was asked for.
    ///
    /// It bounds the phase's pace outright: a thousand ports a second apart
    /// cannot have been asked in under a quarter of an hour.
    pub probe_interval_us: Option<u64>,
    /// The wall-clock budget each host was given, or `null` if none was set.
    ///
    /// It bounds what a host's entry can claim: three open ports out of a
    /// thousand mean something different if the rest were never asked. The
    /// phase's `timed_out` says which hosts ran out.
    pub host_timeout_us: Option<u64>,
    /// The wall-clock budget the whole phase was given, or `null` if none was
    /// set.
    ///
    /// A phase that spent it stopped where it stood, and its scanners record
    /// `timed_out` as their stop reason.
    pub scan_timeout_us: Option<u64>,
    /// Whether name resolution was permitted to generate traffic.
    pub dns_enabled: bool,
    /// Whether the caller asked the *scan* to mask identifying detail. Distinct
    /// from export redaction, which is chosen when the report is written.
    pub redact: bool,
    /// How far the phase went to identify operating systems: `off`, `passive`,
    /// `active` or `aggressive`.
    ///
    /// A host with no operating system reported reads differently at each: `off`
    /// means nothing looked. Under `off` and `passive` the engine sent no
    /// traffic for the purpose.
    pub os_detection: &'static str,

    /// How far the phase went to identify services: `off`, `banner` or `probe`.
    ///
    /// A port with no service reported reads differently at each: `off` means
    /// nothing connected to it. It also says whether the phase completed a
    /// connection to every open port, which the target would have logged.
    pub service_detection: &'static str,

    /// The intrusiveness ceiling detections ran under: `passive`,
    /// `active_benign`, `active_mutating`, `exploit` or `dos`. A finding of a
    /// given class can appear only where the scan permitted that class.
    pub detection: &'static str,

    /// Whether the phase measured the route to each host that answered.
    pub traceroute: bool,
    /// Whether the phase characterised the filter in front of each host that
    /// answered.
    pub characterise: bool,

    /// Which IP protocols the phase asked each host that answered about,
    /// ascending. Empty for a phase that ran no such pass.
    pub ip_protocols: Vec<u8>,

    /// Whether the phase established what each TLS port accepts, beyond what
    /// one handshake negotiated.
    ///
    /// A port whose `security` block lists no accepted versions is either
    /// unenumerated or refused every offer; only this tells them apart.
    pub tls_enumeration: bool,

    /// The TCP ports the phase connected to and listened on and sent nothing,
    /// ascending.
    ///
    /// An open port listed here that names no more than its number implies was
    /// left unprobed on purpose (a printer prints whatever arrives on one); it
    /// was not found to have nothing to say.
    pub listen_only_ports: Vec<u16>,
    /// The ports the phase sent nothing to on any target, written as the
    /// specification a scanner takes, omitted when it excluded none.
    ///
    /// A port written here was named and kept out; one absent from both this
    /// and the scope's `spec` was never named.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub excluded_ports: String,
    /// What the scan changed about the packets it sent, omitted when it changed
    /// nothing. See [`EvasionDto`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evasion: Option<EvasionDto>,
    /// The zombie a TCP port scan read its verdicts through, omitted for an
    /// ordinary scan. See [`IdleScanDto`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_scan: Option<IdleScanDto>,
    /// Whether the capture kept ICMP errors the technique did not need for its
    /// verdict.
    ///
    /// Decides how a `no_reply` port reads. With this set the scan listened for
    /// a refusal, which would have made the port `blocked`, and none came;
    /// without it, a refusal would not have been heard.
    pub icmp_evidence: bool,
}

/// What a scan changed about the packets it sent, as it appears in the report.
/// Each field is present only for a technique the scan used. The serialized form
/// of [`EvasionRecord`].
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct EvasionDto {
    /// The source port every probe left from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    /// The hop limit every ordinary probe carried.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u8>,
    /// The number of random bytes appended to each probe's payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub padding: Option<u16>,
    /// Whether TCP probes carried a bad checksum.
    #[serde(skip_serializing_if = "is_false")]
    pub bad_tcp_checksum: bool,
    /// The hardware address every frame claimed to come from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spoof_mac: Option<String>,
    /// The largest each IP fragment a probe was split into, in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment: Option<u16>,
    /// The addresses probes were also sent from as decoys.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub decoys: Vec<String>,
    /// The TCP flags every port probe carried in place of the technique's own,
    /// named (e.g. `fin|psh|urg`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
}

/// The zombie a TCP port scan read its verdicts through, as it appears in the
/// report. Present only for an idle scan, where the port states were inferred
/// through a third party. The serialized form of
/// [`IdleScan`](crate::config::IdleScan).
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct IdleScanDto {
    /// The zombie's address.
    pub zombie: String,
    /// The port on the zombie its counter was read from, omitted for the
    /// scanner's default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zombie_port: Option<u16>,
}

/// Omits a `false` boolean, so a field appears only for a technique the scan
/// used.
fn is_false(value: &bool) -> bool {
    !*value
}

impl EvasionDto {
    /// Renders a recorded evasion profile.
    pub fn new(record: &EvasionRecord) -> Self {
        Self {
            source_port: record.source_port,
            ttl: record.ttl,
            padding: record.padding,
            bad_tcp_checksum: record.bad_tcp_checksum,
            spoof_mac: record.spoof_mac.map(|mac| mac.to_string()),
            fragment: record.fragment,
            decoys: record.decoys.iter().map(|ip| ip.to_string()).collect(),
            flags: record.flags.map(tcp_flags_name),
        }
    }
}

impl SettingsDto {
    /// Renders recorded settings.
    pub fn new(settings: &ScanSettings) -> Self {
        Self {
            send_mode: send_mode_name(settings.send_mode),
            tcp_technique: settings.tcp_technique.name(),
            sctp_technique: settings.sctp_technique.name(),
            retry: RetryDto::new(&settings.retry),
            max_probe_rate: settings.max_probe_rate.map(std::num::NonZeroU32::get),
            min_probe_rate: settings.min_probe_rate.map(std::num::NonZeroU32::get),
            host_probe_interval_us: micros_opt(settings.host_probe_interval),
            probe_interval_us: micros_opt(settings.probe_interval),
            host_timeout_us: micros_opt(settings.host_timeout),
            scan_timeout_us: micros_opt(settings.scan_timeout),
            dns_enabled: settings.dns_enabled,
            redact: settings.redact,
            os_detection: settings.os_detection.name(),
            service_detection: settings.service_detection.name(),
            detection: detection_ceiling_name(settings.detection.ceiling()),
            traceroute: settings.traceroute,
            characterise: settings.characterise,
            ip_protocols: settings.ip_protocols.clone(),
            tls_enumeration: settings.tls_enumeration,
            listen_only_ports: settings.listen_only_ports.clone(),
            excluded_ports: settings.excluded_ports.to_string(),
            evasion: settings.evasion.as_ref().map(EvasionDto::new),
            idle_scan: settings.idle_scan.map(|idle| IdleScanDto {
                zombie: idle.zombie.to_string(),
                zombie_port: idle.zombie_port,
            }),
            icmp_evidence: settings.icmp_evidence,
        }
    }
}

/// The retransmission budget a phase ran under.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct RetryDto {
    /// The effort level: `single`, `fast`, `balanced` or `thorough`.
    pub effort: &'static str,
    /// An attempt budget set by the caller, overriding what `effort` implies.
    /// One or more, never zero.
    pub max_attempts: Option<u8>,
    /// A multiplier on how long the scan was willing to wait.
    ///
    /// `null` when the caller set none. Always positive and finite when
    /// present, as [`TimeoutScale`](crate::config::TimeoutScale) enforces.
    pub timeout_scale: Option<f64>,
    /// Whether a host that answered nothing could have its budget cut short.
    pub dampen_silent_hosts: bool,
}

impl RetryDto {
    /// Renders a retry configuration.
    pub fn new(retry: &RetryConfig) -> Self {
        Self {
            effort: scan_effort_name(retry.effort),
            max_attempts: retry.max_attempts.map(std::num::NonZeroU8::get),
            timeout_scale: retry.timeout_scale.map(crate::config::TimeoutScale::get),
            dampen_silent_hosts: retry.dampen_silent_hosts,
        }
    }
}

/// A strategy that did not run to completion.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct FailureDto<'a> {
    /// The strategy that failed.
    pub scanner: &'static str,
    /// A human-readable description of the failure.
    pub reason: &'a str,
    /// When it was observed.
    pub at: String,
    /// Whether a limit the strategy runs under cut it short; false for a fault.
    /// Left out when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub cut_short: bool,
}

impl<'a> FailureDto<'a> {
    /// Renders a recorded failure.
    pub fn new(failure: &'a ScannerFailure) -> Self {
        Self {
            scanner: scanner_kind_name(failure.scanner()),
            reason: failure.reason(),
            at: rfc3339(failure.at()),
            cut_short: failure.is_cut_short(),
        }
    }
}

/// Ground a phase declined to cover.
///
/// Has no timestamp, unlike [`FailureDto`]: a refusal is decided before the
/// phase begins.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct RefusalDto<'a> {
    /// The strategy that would have taken this work.
    pub scanner: &'static str,
    /// What was not done, and what could be asked for in its place.
    pub reason: &'a str,
}

impl<'a> RefusalDto<'a> {
    /// Renders a recorded refusal.
    pub fn new(refusal: &'a Refusal) -> Self {
        Self {
            scanner: scanner_kind_name(refusal.scanner()),
            reason: refusal.reason(),
        }
    }
}

// ---------------------------------------------------------------------------
// Probe instrumentation
// ---------------------------------------------------------------------------

/// What one raw scanner observed about its own run.
///
/// Instrumentation about the scan, which bounds how far the findings can be
/// trusted: a sweep that stopped on `deadline_expired` with `last_reply_us`
/// close to `elapsed_us` was still finding hosts when it ran out of time, and
/// nothing in the host list says so.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct ProbeStatsDto {
    /// The strategy these counters belong to.
    pub scanner: &'static str,
    /// How many targets this scanner owned, as a decimal string.
    pub targets: String,
    /// Why the receive loop stopped.
    pub stop_reason: &'static str,
    /// Whether the loop stopped because it had nothing left to do. Derived from
    /// `stop_reason`, so a consumer need not know which reasons mean finished.
    pub complete: bool,
    /// How long the scanner ran.
    pub elapsed_us: u64,
    /// Probes the scanner tried to put on the wire.
    pub sends_attempted: u64,
    /// Probes per second the scanner put on the wire over its whole run, or
    /// `null` for a run with no time to divide by. Derived from
    /// `sends_attempted` and `elapsed_us`.
    pub achieved_send_rate: Option<f64>,
    /// Of those, ones that never left this host: the sender refused them, or
    /// could not reach their address. Non-zero means the shortfall starts on
    /// the scanning machine.
    pub sends_failed: u64,
    /// Of those, ones seen leaving on the wire. The gap below `sends_attempted`
    /// is probes the OS took and dropped; zero means no egress capture.
    pub sends_witnessed: u64,
    /// Segments the capture handed up, before any of the scanner's own checks.
    pub segments_seen: u64,
    /// Segments from an address outside this scan's target set. A large count
    /// means the capture filter is admitting other traffic.
    pub segments_off_target: u64,
    /// In-set replies that answered no outstanding probe. They proved a host
    /// alive but yielded no round-trip sample.
    pub replies_without_rtt: u64,
    /// ICMP refusals among those that quoted too little of the probe to name
    /// its attempt. Not credited, since anybody who knows the source port could
    /// send one; the ports they quote keep the verdict their own retries reach.
    pub refusals_unattributed: u64,
    /// Targets credited as alive for the first time.
    pub hosts_found: u64,
    /// Found hosts by the attempt whose reply revealed them, which shows
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
    /// This measures discovery time, not round trip: a host found at 700 ms
    /// because its third attempt went out at 690 ms has a 10 ms round trip.
    /// Round trips are per host, under `telemetry`.
    pub found_at: Vec<BucketDto>,
    /// What the kernel capture reported, where there was one to ask. `null` for
    /// a scanner driven by a synthetic receive stream, which has no kernel
    /// buffer.
    pub capture: Option<CaptureDto>,
    /// What this run's congestion window did, for a scanner paced by one.
    ///
    /// Says whether the silence in this phase is a finding. A run whose window
    /// was cut back to its floor and still left most of its probes unanswered
    /// established only that it could not ask. `null` for a scanner paced some
    /// other way.
    pub window: Option<WindowDto>,
}

/// What a scan's congestion window did over one run.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct WindowDto {
    /// Probes it was willing to have outstanding when the run ended.
    pub capacity: u64,
    /// The most it was ever willing to have outstanding.
    pub peak: u64,
    /// How many times it was cut back.
    pub reductions: u32,
    /// Whether the window was allowed to move at all.
    ///
    /// A fixed window and an adaptive one that never had to move record the
    /// same `capacity`, `peak` and `reductions`; this tells them apart.
    pub adaptive: bool,
    /// Whether it ended cut back as far as it is permitted to go, which says the
    /// scan was still being outrun when it stopped.
    pub at_floor: bool,
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
            achieved_send_rate: stats.achieved_send_rate(),
            sends_failed: stats.sends_failed(),
            sends_witnessed: stats.sends_witnessed(),
            segments_seen: stats.segments_seen(),
            segments_off_target: stats.segments_off_target(),
            replies_without_rtt: stats.replies_without_rtt(),
            refusals_unattributed: stats.refusals_unattributed(),
            hosts_found: stats.hosts_found(),
            answered_on,
            answered_unattributed: stats.answered_unattributed(),
            first_reply_us: micros_opt(stats.first_reply()),
            last_reply_us: micros_opt(stats.last_reply()),
            found_at,
            capture: stats.capture().map(CaptureDto::new),
            window: stats.window().map(|window| WindowDto {
                capacity: window.capacity as u64,
                peak: window.peak as u64,
                reductions: window.reductions,
                adaptive: window.adaptive,
                at_floor: window.at_floor,
            }),
        }
    }
}

/// How many hosts a given attempt revealed.
#[non_exhaustive]
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
#[non_exhaustive]
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
/// The only place receive-path loss is distinguishable from network loss: a
/// reply the kernel discards because the buffer was full reaches no other
/// counter in this document.
#[non_exhaustive]
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
    /// How many captures ended before they were told to.
    ///
    /// Counted in captures, unlike the three above, which count frames.
    /// Non-zero means an interface stopped hearing part way through, so the
    /// counts beside it describe less of the network than they appear to.
    pub stopped_early: u64,
}

impl CaptureDto {
    /// Renders capture counters.
    pub fn new(counts: CaptureCounts) -> Self {
        Self {
            received: counts.received,
            dropped: counts.dropped,
            if_dropped: counts.if_dropped,
            stopped_early: counts.stopped_early,
        }
    }
}

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

/// Everything the scan established about one host.
#[non_exhaustive]
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
    /// Kept apart from `ips` so those still parse as addresses. An IPv6
    /// link-local is unreachable without its zone, so `fe80::…` on its own
    /// does not identify a host.
    pub zone: Option<&'a str>,
    /// The address families this host answered at: `ipv4`, `ipv6`, or both.
    ///
    /// Derivable from `ips`, stated so consumers need not parse addresses.
    pub families: Vec<&'static str>,
    /// The resolved hostname, masked under redaction.
    pub hostname: Option<Cow<'a, str>>,
    /// The names the host gave for itself through its own services, the
    /// machine's before its domain's, each masked under redaction as
    /// `hostname` is. Distinct from `hostname`, which is what name resolution
    /// answered for the address.
    pub names: Vec<NameDto<'a>>,
    /// The reachability status: `up`, `blocked`, `down` or `unknown`.
    pub status: &'static str,
    /// Whether the host is confirmed present on the network: true for `up` and
    /// `blocked`.
    pub alive: bool,
    /// The evidence behind the status, sorted.
    pub reasons: Vec<ReasonDto<'a>>,
    /// Inferred roles, sorted.
    pub roles: Vec<&'static str>,
    /// What the filter in front of the host was shown to be doing, sorted.
    pub filtering: Vec<&'static str>,
    /// What the scan concluded about each IP protocol it asked this host about,
    /// ascending by number. Empty for a scan that did not ask.
    pub ip_protocols: Vec<IpProtocolDto>,
    /// The identified operating system.
    pub os: Option<OsDto<'a>>,
    /// Physical hardware identity, masked under redaction.
    pub hardware: Option<HardwareDto<'a>>,
    /// Network path measurements.
    pub telemetry: TelemetryDto,
    /// The routers between the scanning host and this one, ascending by
    /// distance. Empty when no trace ran, which the phase's `traceroute`
    /// setting distinguishes from a trace that found nothing.
    pub path: Vec<HopDto>,
    /// Discovered ports, ascending by number.
    pub ports: Vec<PortDto<'a>>,
    /// What a detection concluded is wrong with the host as a whole, worst-first.
    /// A port's own findings are on the port.
    pub findings: Vec<FindingDto<'a>>,
    /// When this host was first seen.
    pub first_seen: String,
    /// When it was last updated.
    pub last_seen: String,
}

impl<'a> HostDto<'a> {
    /// Renders a host, applying the redaction policy in `options`.
    pub fn new(host: &'a Host, options: &ExportOptions) -> Self {
        Self::masked(host, options, &options.redaction.for_host(host))
    }

    /// Renders a host whose free text is masked by `masking`, the policy in
    /// `options` as it applies to this record and to any other that shares
    /// its text's names: a comparison masks each of a host's two records by
    /// the names either knew it by
    /// ([`Redaction::for_delta`](crate::export::Redaction::for_delta)).
    pub(crate) fn masked(host: &'a Host, options: &ExportOptions, masking: &HostRedaction) -> Self {
        let redaction = options.redaction;
        debug_assert_eq!(
            masking.redaction(),
            redaction,
            "the masking is the policy in the options"
        );

        let mut families: Vec<&'static str> = Vec::with_capacity(2);
        if host.ips().iter().any(std::net::IpAddr::is_ipv4) {
            families.push("ipv4");
        }
        if host.ips().iter().any(std::net::IpAddr::is_ipv6) {
            families.push("ipv6");
        }

        let mut reasons: Vec<ReasonDto<'a>> = host
            .reasons()
            .iter()
            .map(|reason| ReasonDto::new(reason, masking))
            .collect();
        reasons.sort_by(|a, b| {
            a.protocol
                .cmp(&b.protocol)
                .then(a.source_ip.cmp(&b.source_ip))
                .then(a.source_withheld.cmp(&b.source_withheld))
                .then(a.details.cmp(&b.details))
        });

        let mut roles: Vec<&'static str> = host
            .network_roles()
            .iter()
            .copied()
            .map(network_role_name)
            .collect();
        roles.sort_unstable();

        let mut filtering: Vec<&'static str> = host
            .filtering()
            .iter()
            .copied()
            .map(filtering_name)
            .collect();
        filtering.sort_unstable();

        Self {
            primary_ip: host.primary_ip().to_string(),
            ips: host.ips().iter().map(IpAddr::to_string).collect(),
            zone: host.zone().map(|zone| zone.name()),
            families,
            hostname: host.hostname().map(|name| redaction.hostname(name)),
            names: host
                .names()
                .map(|name| NameDto::new(name, options))
                .collect(),
            status: host_status_name(host.status()),
            alive: host.is_alive(),
            reasons,
            roles,
            filtering,
            ip_protocols: host
                .ip_protocols()
                .iter()
                .map(|(number, state)| IpProtocolDto {
                    protocol: *number,
                    name: ip_protocol_name(*number),
                    state: ip_protocol_state_name(*state),
                })
                .collect(),
            os: host.os().map(|os| OsDto::new(os, masking)),
            hardware: host
                .hardware()
                .map(|hardware| HardwareDto::new(hardware, masking)),
            telemetry: TelemetryDto::new(host.telemetry()),
            path: host.path().hops().iter().map(HopDto::new).collect(),
            ports: host
                .ports()
                .map(|port| PortDto::new(port, masking))
                .collect(),
            findings: findings_dto(host.findings(), masking),
            first_seen: rfc3339(host.first_seen()),
            last_seen: rfc3339(host.last_seen()),
        }
    }
}

/// One name a host gave for itself.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct NameDto<'a> {
    /// The protocol the host stated it in: `ntlm`, `ldap`,
    /// `kerberos`, `smb` or `netbios`.
    pub source: &'static str,
    /// What it names: `host` and `netbios_host` for the machine, `domain` and
    /// `netbios_domain` for the domain or workgroup it belongs to, `forest`
    /// for the root of that domain's forest.
    pub kind: &'static str,
    /// The name, masked under redaction.
    ///
    /// Every kind is masked, the domain and the forest as well as the machine:
    /// a domain names the organisation that runs it, which is more than a
    /// hostname says.
    pub name: Cow<'a, str>,
}

impl<'a> NameDto<'a> {
    /// Renders one name, applying the redaction policy in `options`.
    pub fn new(name: &'a HostName, options: &ExportOptions) -> Self {
        Self {
            source: name_source_name(name.source()),
            kind: name_kind_name(name.kind()),
            name: options.redaction.hostname(name.name()),
        }
    }
}

/// One router on the way to a host.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct HopDto {
    /// How many routers from the scanning host this one sits.
    ///
    /// Use this, not the array index: a router that does not answer leaves a
    /// gap, and the entries either side keep the distances they were measured
    /// at.
    pub distance: u8,
    /// The address the router answered from, or `null` where nothing answered
    /// at this distance or where the address is [`withheld`](Self::withheld).
    ///
    /// A `null` is a finding: a router is there, since the hops beyond it were
    /// reached, and unless `withheld` says otherwise it did not identify itself.
    pub address: Option<String>,
    /// The round trip to this router in microseconds, or `null`.
    ///
    /// Measured from the scanning host, so it includes every hop in front of
    /// this one, and it times a router's error generation, which most routers
    /// do at lowest priority. A hop slower than the one past it says nothing
    /// about the path.
    pub rtt_us: Option<u64>,
    /// Whether this hop was measured on the way to this host, or taken from
    /// another host's trace that passed through the same router.
    ///
    /// A scan of many hosts behind one gateway measures the shared part of the
    /// path once, assuming two paths meeting at one router at one distance
    /// agreed before it.
    pub inferred: bool,
    /// Whether a router answered here from an address the scan's exclusions
    /// forbid it to report, so `address` and `rtt_us` are `null`.
    ///
    /// The one `null` address that is not silence: the router answered, and
    /// the document keeps excluded addresses out of the report. A consumer that
    /// reads only `address` sees a silent router.
    pub withheld: bool,
}

impl HopDto {
    /// Renders one hop.
    pub fn new(hop: &Hop) -> Self {
        Self {
            distance: hop.distance(),
            address: hop.address().map(|address| address.to_string()),
            rtt_us: hop
                .rtt()
                .and_then(|rtt| u64::try_from(rtt.as_micros()).ok()),
            inferred: hop.inferred(),
            withheld: hop.is_withheld(),
        }
    }
}

/// One piece of evidence for a host's status.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct ReasonDto<'a> {
    /// The protocol event that produced the evidence.
    pub protocol: Cow<'a, str>,
    /// The address that sent the evidence, when it was not the host itself
    /// and the report may name it.
    ///
    /// Present only for second-hand evidence, such as an ICMP error from a
    /// router or firewall about the probed address. `null` means the host
    /// answered for itself, the stronger claim, unless
    /// [`source_withheld`](Self::source_withheld) says otherwise.
    pub source_ip: Option<String>,
    /// Whether the evidence came second-hand from an address the scan's
    /// exclusions forbid it to report, so `source_ip` is `null`.
    ///
    /// The one `null` source that is not the host answering for itself. A
    /// consumer reading only `source_ip` would take a middlebox's word for the
    /// host's.
    pub source_withheld: bool,
    /// What was observed, where the strategy recorded it.
    ///
    /// Free text, possibly from another tool's document, so a name the host is
    /// known by is masked in it under redaction.
    pub details: Option<Cow<'a, str>>,
}

impl<'a> ReasonDto<'a> {
    /// Renders a status reason of the host `masking` was made for.
    pub fn new(reason: &'a StatusReason, masking: &HostRedaction) -> Self {
        Self {
            protocol: status_protocol_name(&reason.protocol),
            source_ip: reason.source.address().map(|ip| ip.to_string()),
            source_withheld: reason.source.is_withheld(),
            details: reason.details.as_deref().map(|text| masking.text(text)),
        }
    }
}

/// An identified operating system.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct OsDto<'a> {
    /// The primary OS name. Free text a reply can fill, so a name the host is
    /// known by is masked in it under redaction.
    pub name: Cow<'a, str>,
    /// The broad family.
    ///
    /// This and every other string here are masked as `name` is: a rule fills
    /// each from what it captured of the reply, a CPE included.
    pub family: Option<Cow<'a, str>>,
    /// The version or generation.
    pub generation: Option<Cow<'a, str>>,
    /// The vendor.
    pub vendor: Option<Cow<'a, str>>,
    /// Confidence in this identification, 0 to 100.
    pub accuracy: u8,
    /// CPE identifiers, sorted.
    pub cpes: Vec<Cow<'a, str>>,
    /// What this identification was read off, in one line, or `null` where the
    /// technique that produced it recorded nothing.
    ///
    /// For a person to read; its format varies by technique, and a consumer
    /// should act on the named fields above. It lets a disputed finding be
    /// diagnosed, and turned into a corpus entry, without re-running the scan.
    ///
    /// Masked as `name` is under redaction, for the same reason.
    pub evidence: Option<Cow<'a, str>>,
    /// The kernel release, or `null` where nothing read one.
    ///
    /// Separate from `generation`: a distribution release and the kernel it
    /// ships are two facts about one machine. A known-vulnerability lookup keys
    /// on this for a Unix host.
    pub kernel: Option<Cow<'a, str>>,
    /// The instruction set, such as `"x86_64"` or `"mips"`, or `null` where
    /// nothing read one.
    ///
    /// Two hosts of one family on different silicon need different exploit
    /// payloads.
    pub arch: Option<Cow<'a, str>>,
    /// How well supported everything *past* the family is, or `null` where the
    /// finding stops at a family.
    ///
    /// `accuracy` describes the family, which every source can speak to. A
    /// release is usually named by only one source, so it gets its own figure.
    pub detail_accuracy: Option<u8>,
    /// What kind of box this is, such as `"Printer"` or `"Switch"`, or `null`
    /// where nothing named a class.
    ///
    /// Independent of `family`: what a machine is and what it runs are separate
    /// questions, either may be answered without the other, and both may be
    /// `null` on a finding that named only a product.
    pub device: Option<Cow<'a, str>>,
}

impl<'a> OsDto<'a> {
    /// Renders an OS fingerprint, masking the host's names in its free text.
    pub fn new(os: &'a OsFingerprint, masking: &HostRedaction) -> Self {
        let text = |field: Option<&'a str>| field.map(|text| masking.text(text));
        Self {
            name: masking.text(os.name()),
            family: text(os.family()),
            generation: text(os.generation()),
            vendor: text(os.vendor()),
            accuracy: os.accuracy(),
            cpes: os.cpes().iter().map(|cpe| masking.text(cpe)).collect(),
            evidence: text(os.evidence()),
            kernel: text(os.kernel()),
            arch: text(os.arch()),
            detail_accuracy: os.detail_accuracy(),
            device: text(os.device()),
        }
    }
}

/// One IP protocol the scan asked a host about, and what it concluded.
///
/// The number is the finding and the name a convenience. A number the IANA
/// registry has no keyword for has no name.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct IpProtocolDto {
    /// The IP protocol number.
    pub protocol: u8,
    /// Its registry keyword, where it has one worth printing.
    pub name: Option<&'static str>,
    /// `open`, `closed`, `blocked`, `open_or_no_reply` or `unasked`. What each
    /// means here is
    /// [`IpProtocolState`](crate::model::host::IpProtocolState)'s own
    /// documentation. `open` means the host takes delivery of the protocol,
    /// which differs from an open port's meaning.
    pub state: &'static str,
}

/// Physical hardware identity.
///
/// The engine's per-address last-seen timestamps are monotonic readings, so
/// they are not exported.
#[non_exhaustive]
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
    /// Survives redaction, since the masked address keeps the OUI. A rule can
    /// also fill it from the reply, so a name the host is known by is masked
    /// in it, as in `product`.
    pub vendor: Option<Cow<'a, str>>,
    /// The model, where a service named it: `PDR M800`, `Firewall-1`.
    ///
    /// Only present where something stated it. It survives redaction, since it
    /// describes the product, except that a name the host is known by is
    /// masked in it: a device can put its own name beside its model. The same
    /// holds of `family`, `model` and `version`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<Cow<'a, str>>,
    /// The line that model belongs to, where a rule distinguishes the two.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<Cow<'a, str>>,
    /// The hardware's platform identifier, separate from the operating
    /// system's. Masked as `product` is, being filled from the reply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpe23: Option<Cow<'a, str>>,
    /// The model number on its own, where the product string carried more than
    /// one thing: `4200` beside a product of `Xerox WorkCentre 4200`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<Cow<'a, str>>,
    /// The hardware revision of the board: a unit that ships in two silicon
    /// revisions under one model number is two different machines to an
    /// exploit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<Cow<'a, str>>,
    /// The serial number, where a service handed one over.
    ///
    /// Dropped under redaction: it names one machine, and even a masked prefix
    /// would within a fleet bought in a batch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<&'a str>,
}

impl<'a> HardwareDto<'a> {
    /// Renders the hardware of the host `masking` was made for, applying its
    /// redaction policy.
    pub fn new(hardware: &'a HardwareInfo, masking: &HostRedaction) -> Self {
        let redaction = masking.redaction();
        let text = |field: Option<&'a str>| field.map(|text| masking.text(text));

        let mut macs: Vec<String> = hardware
            .macs()
            .keys()
            .map(|mac| redaction.mac(mac))
            .collect();
        // Masking collapses addresses that share an OUI. The source is sorted
        // and masking keeps the leading octets, so duplicates are neighbours.
        macs.dedup();

        Self {
            mac: hardware.most_recent_mac().map(|mac| redaction.mac(&mac)),
            macs,
            vendor: text(hardware.vendor()),
            product: text(hardware.product()),
            family: text(hardware.family()),
            cpe23: text(hardware.cpe23()),
            model: text(hardware.model()),
            version: text(hardware.hardware_version()),
            serial_number: match redaction.is_active() {
                true => None,
                false => hardware.serial_number(),
            },
        }
    }
}

/// Network path measurements for a host.
///
/// The individual samples carry monotonic timestamps, so only these aggregates
/// are exported.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct TelemetryDto {
    /// The fastest round trip observed.
    pub rtt_min_us: Option<u64>,
    /// The median round trip, the best summary of typical latency.
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
        }
    }
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/// One discovered port.
#[non_exhaustive]
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
    /// What a detection concluded is wrong with what is listening here,
    /// worst-first.
    pub findings: Vec<FindingDto<'a>>,
}

impl<'a> PortDto<'a> {
    /// Renders a port of the host `masking` was made for, applying its
    /// redaction policy.
    pub fn new(port: &'a Port, masking: &HostRedaction) -> Self {
        Self {
            port: port.number(),
            protocol: protocol_name(port.protocol()),
            state: port_state_name(port.state()),
            service: port
                .service()
                .map(|service| ServiceDto::new(service, masking)),
            security: port
                .security()
                .map(|security| SecurityDto::new(security, masking)),
            discovery: port.discovery().map(DiscoveryDto::new),
            findings: findings_dto(port.findings(), masking),
        }
    }
}

/// The findings of a subject, worst-first: severity descending, then producer
/// id. (The model itself sorts by identity.)
fn findings_dto<'a>(
    findings: impl Iterator<Item = &'a Finding>,
    masking: &HostRedaction,
) -> Vec<FindingDto<'a>> {
    let mut findings: Vec<&'a Finding> = findings.collect();
    findings.sort_by(|a, b| {
        b.severity()
            .cmp(&a.severity())
            .then_with(|| a.detection().id().cmp(b.detection().id()))
    });
    findings
        .into_iter()
        .map(|finding| FindingDto::new(finding, masking))
        .collect()
}

/// One finding, for a report a consumer parses.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct FindingDto<'a> {
    /// The detection that produced it. Author-chosen and untrusted; an exporter
    /// writing to markup escapes it.
    pub id: &'a str,
    /// The detection's version, `major.minor.patch`.
    pub version: String,
    /// The content hash of the detection body, for reproducibility.
    pub content_hash: &'a str,
    /// The one-line title. Untrusted, and filled from the reply where the
    /// detection interpolated one, so a name the host is known by is masked in
    /// it under redaction.
    pub title: Cow<'a, str>,
    /// How bad it is if true: `info`, `low`, `medium`, `high` or `critical`.
    pub severity: &'static str,
    /// How sure it is true: `heuristic`, `weak`, `probable`, `strong` or
    /// `certain`. Independent of severity, so a finding can be `critical` and
    /// only `probable`.
    pub confidence: &'static str,
    /// The intrusiveness the detection ran under.
    pub class: &'static str,
    /// The bytes that justify it, for a person to read. Untrusted; absent where
    /// the detection carried none.
    ///
    /// Under redaction a name the host is known by is masked in it, and an
    /// excerpt that is not text is replaced by a note saying it was withheld.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<Cow<'a, str>>,
    /// External references: CVE, CWE and advisory links. A link is masked as
    /// `title` is.
    pub references: Vec<ReferenceDto<'a>>,
    /// Remediation advice, if the detection carried any. Untrusted, and masked
    /// as `title` is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<Cow<'a, str>>,
    /// The lowest of `cpes`, for consumers that expect one. Untrusted; absent
    /// from a finding drawn from anything but a vulnerability correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpe: Option<Cow<'a, str>>,
    /// Every platform identifier a vulnerability correlation drew it from,
    /// ascending: the claim rests on each, and stands while any is still what
    /// the service is identified as. Untrusted; absent from a finding drawn
    /// from anything else.
    ///
    /// Each is filled from the reply, so a name the host is known by is masked
    /// in it as in the service's `cpes`. The order is the unmasked one.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cpes: Vec<Cow<'a, str>>,
    /// What the claim is about, where the detection named it: for a
    /// correlation, the software, the distribution release and the kind of
    /// verdict, which stay put while the vulnerabilities behind them change
    /// with the data. Two findings with the same `id` and `subject` on the same
    /// port are the same claim. Absent where the detection named none.
    /// Untrusted, and masked as `title` is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Cow<'a, str>>,
    /// The distribution build a correlation judged, for one drawn from a
    /// service that carried one. The claim rests on it as on `cpes`: a
    /// distribution publishes fixes as new builds of the same upstream
    /// version. Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildDto<'a>>,
    /// The distributor's advisory data a correlation consulted to judge
    /// `build`, stamped as the detection itself is. Absent where none was
    /// consulted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advised_by: Option<AdvisedByDto<'a>>,
    /// Which of the vulnerabilities in `references` are known to be exploited
    /// in the wild, and whose list says so: CISA's Known Exploited
    /// Vulnerabilities catalogue unless the caller supplied another. It does
    /// not change the severity or the confidence. Absent where no list
    /// consulted names any of them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exploited: Option<ExploitedDto<'a>>,
    /// What this finding is one of, where several detections cover one
    /// weakness between them: the identity they share and the phrase they read
    /// as together, so a consumer can summarise them in one line. Absent from
    /// most findings. Untrusted, but the detection author's words, so
    /// redaction does not apply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<GroupDto<'a>>,
}

/// The group a finding belongs to: what its members share, and how they read as
/// one.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct GroupDto<'a> {
    /// The identity every member repeats, `ssh-weak-algorithms`. Two findings
    /// are of one group when they spell this the same. Untrusted.
    pub id: Cow<'a, str>,
    /// How the group reads when its findings are spoken of as one: a plural
    /// noun phrase a count can lead, `weak SSH algorithms offered`. Untrusted.
    pub summary: Cow<'a, str>,
}

/// Which snapshot of a distributor's advisory data a correlation consulted.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct AdvisedByDto<'a> {
    /// The dataset's identity, such as `ubuntu:security-notices`.
    pub id: &'a str,
    /// The dataset's version, `major.minor.patch`, read off its newest record.
    pub version: String,
    /// The content hash of the dataset, for reproducibility.
    pub content_hash: &'a str,
}

/// Which of a finding's vulnerabilities are known to be exploited, and whose
/// list says so.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct ExploitedDto<'a> {
    /// The list that names them, stamped as a detection is.
    pub by: ExploitedByDto<'a>,
    /// The CVE identifiers it names, in the order the finding cites them. Never
    /// empty.
    pub cves: Vec<&'a str>,
}

/// Which snapshot of a list of exploited vulnerabilities marked a finding.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct ExploitedByDto<'a> {
    /// The list's identity, such as `cisa:kev`. Untrusted.
    pub id: &'a str,
    /// The list's version, `major.minor.patch`, read off its publication date.
    pub version: String,
    /// The content hash of the list, for reproducibility.
    pub content_hash: &'a str,
}

impl<'a> FindingDto<'a> {
    /// Renders a finding of the host `masking` was made for.
    pub fn new(finding: &'a Finding, masking: &HostRedaction) -> Self {
        Self {
            id: finding.detection().id(),
            version: finding.detection().version().to_string(),
            content_hash: finding.detection().content_hash(),
            title: masking.text(finding.title()),
            severity: severity_name(finding.severity()),
            confidence: confidence_name(finding.confidence()),
            class: detection_class_name(finding.class()),
            excerpt: (!finding.excerpt().is_empty())
                .then(|| masking.excerpt(finding.excerpt().as_str())),
            references: finding
                .references()
                .map(|reference| ReferenceDto::new(reference, masking))
                .collect(),
            remediation: finding.remediation().map(|advice| masking.text(advice)),
            cpe: finding.cpes().next().map(|cpe| masking.text(cpe)),
            cpes: finding.cpes().map(|cpe| masking.text(cpe)).collect(),
            subject: finding.subject().map(|subject| masking.text(subject)),
            build: finding.build().map(|build| BuildDto::new(build, masking)),
            advised_by: finding.advised_by().map(|advised| AdvisedByDto {
                id: advised.id(),
                version: advised.version().to_string(),
                content_hash: advised.content_hash(),
            }),
            // Unmasked: the list's words and CVE identifiers, which no host's
            // reply reaches.
            exploited: finding.exploitation().map(|exploitation| ExploitedDto {
                by: ExploitedByDto {
                    id: exploitation.by().id(),
                    version: exploitation.by().version().to_string(),
                    content_hash: exploitation.by().content_hash(),
                },
                cves: exploitation.cves().collect(),
            }),
            // Unmasked: the detection author's words, with no template a reply
            // could fill. Still untrusted, and escaped where drawn.
            group: finding.group().map(|group| GroupDto {
                id: Cow::Borrowed(group.id()),
                summary: Cow::Borrowed(group.summary()),
            }),
        }
    }
}

/// One external reference: a typed kind and the value it carries.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct ReferenceDto<'a> {
    /// `cve`, `cwe`, or `url`.
    pub kind: &'static str,
    /// The identifier or link. A `url` value is untrusted free text, so a name
    /// the host is known by is masked in it under redaction. A CVE identifier
    /// and a CWE number have a fixed shape no name fits.
    pub value: Cow<'a, str>,
}

impl<'a> ReferenceDto<'a> {
    /// Renders a reference of a finding on the host `masking` was made for.
    pub fn new(reference: &'a Reference, masking: &HostRedaction) -> Self {
        Self {
            kind: reference_kind_name(reference),
            value: match reference {
                Reference::Cve(id) => Cow::Borrowed(id.as_str()),
                Reference::Url(url) => masking.text(url),
                Reference::Cwe(number) => Cow::Owned(number.to_string()),
            },
        }
    }
}

/// A reference as one line of text: the CVE or CWE identifier, or the URL,
/// masked as [`ReferenceDto`] masks it. Used by the nmap XML `<script output>`
/// and the CSV findings column.
#[cfg(any(feature = "export-nmap", feature = "export-csv"))]
pub(crate) fn reference_text(reference: &Reference, masking: &HostRedaction) -> String {
    match reference {
        Reference::Cve(id) => id.clone(),
        Reference::Cwe(number) => format!("CWE-{number}"),
        Reference::Url(url) => masking.text(url).into_owned(),
    }
}

/// What is running on a port.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct ServiceDto<'a> {
    /// The high-level protocol name, such as `ssh` or `http`.
    ///
    /// On a port nothing identified and no number names, the start of what
    /// the port said, as `banner: …`, with a name the host is known by masked
    /// under redaction.
    pub name: Cow<'a, str>,
    /// Certainty of this identification, 0 to 100. A table lookup by port
    /// number scores near zero; a completed protocol handshake scores near 100.
    /// A port its phase only listened to scores what it volunteered, often
    /// nothing; the phase's `listen_only_ports` lists it.
    pub confidence: u8,
    /// The specific product or daemon.
    ///
    /// This, `version` and `extrainfo` are filled from the reply, so a name the
    /// host is known by is masked in each under redaction.
    pub product: Option<Cow<'a, str>>,
    /// The organization behind the product, where one could be attributed.
    ///
    /// Masked as `product` is, as is each CPE, since a rule can fill either
    /// from the reply.
    pub vendor: Option<Cow<'a, str>>,
    /// The version string reported or detected.
    pub version: Option<Cow<'a, str>>,
    /// Additional metadata or environment hints.
    pub extrainfo: Option<Cow<'a, str>>,
    /// CPE identifiers, in the order they were established.
    pub cpes: Vec<Cow<'a, str>>,
    /// Whose build of the software this is, where the reply said. A
    /// distribution backports fixes without moving the upstream version.
    pub build: Option<BuildDto<'a>>,
}

/// A distributor's build of a service's software.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct BuildDto<'a> {
    /// Who built it: `debian`, `ubuntu`, `redhat`, ...
    pub distributor: &'static str,
    /// The package revision, where the reply stated one. Read from the reply,
    /// so masked as `extrainfo` is.
    pub revision: Option<Cow<'a, str>>,
    /// Which of the distributor's releases the build belongs to, where
    /// anything said.
    pub release: Option<ReleaseDto<'a>>,
}

/// Which release a build belongs to, and what said so.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct ReleaseDto<'a> {
    /// The release as the distributor numbers it: `14.04`, `12`. Masked as
    /// `revision` is, since a rule can fill it from the reply.
    pub name: Cow<'a, str>,
    /// `revision` where the package revision names the release outright,
    /// `banner` where a rule inferred it from what the release shipped.
    pub basis: &'static str,
}

impl<'a> BuildDto<'a> {
    /// Renders a build on the host `masking` was made for.
    pub fn new(build: &'a Build, masking: &HostRedaction) -> Self {
        Self {
            distributor: distributor_name(build.distributor()),
            revision: build.revision().map(|text| masking.text(text)),
            release: build.release().map(|release| ReleaseDto {
                name: masking.text(release.name()),
                basis: release_basis_name(release.basis()),
            }),
        }
    }
}

impl<'a> ServiceDto<'a> {
    /// Renders a service identification on the host `masking` was made for.
    pub fn new(service: &'a Service, masking: &HostRedaction) -> Self {
        Self {
            name: masking.text(service.name()),
            confidence: service.confidence(),
            product: service.product().map(|text| masking.text(text)),
            vendor: service.vendor().map(|text| masking.text(text)),
            version: service.version().map(|text| masking.text(text)),
            extrainfo: service.extrainfo().map(|text| masking.text(text)),
            cpes: service.cpes().iter().map(|cpe| masking.text(cpe)).collect(),
            build: service.build().map(|build| BuildDto::new(build, masking)),
        }
    }
}

/// Transport security negotiated on a port.
#[non_exhaustive]
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
    /// What the endpoint turned out to accept, one entry per version, oldest
    /// first. Left out where the scan did not enumerate.
    ///
    /// `tls_version` and `cipher_suite` are what one handshake settled on. A
    /// port naming `TLSv1.3` there and listing `TLSv1.0` here prefers the
    /// modern version and still accepts the withdrawn one.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub accepts: Vec<AcceptedVersionDto>,
    /// The versions whose enumeration ended before the endpoint had declined
    /// an offer, oldest first. Left out where every walk finished, and where
    /// the scan did not enumerate.
    ///
    /// A version listed here and in `accepts` accepts at least what `accepts`
    /// says; one listed only here was never settled either way.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unfinished: Vec<UnfinishedVersionDto>,
}

impl<'a> SecurityDto<'a> {
    /// Renders security telemetry on the host `masking` was made for, applying
    /// its redaction policy.
    pub fn new(security: &'a Security, masking: &HostRedaction) -> Self {
        Self {
            tls_version: security.tls_version(),
            cipher_suite: security.cipher_suite(),
            alpn: security.alpn().iter().map(AsRef::as_ref).collect(),
            certificate: security
                .certificate()
                .map(|cert| CertificateDto::new(cert, masking)),
            accepts: security
                .support()
                .versions()
                .iter()
                .map(AcceptedVersionDto::new)
                .collect(),
            unfinished: security
                .support()
                .unfinished()
                .iter()
                .map(UnfinishedVersionDto::new)
                .collect(),
        }
    }
}

/// One protocol version whose enumeration did not finish, and why.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct UnfinishedVersionDto {
    /// The version, spelled as in `accepts`.
    pub version: &'static str,
    /// `unanswered` where the endpoint stopped answering and went on not
    /// answering when asked again; `stopped` where the scan stopped asking,
    /// because the host's budget ran out, which also puts its address in the
    /// phase's `timed_out`, or because the scan itself was stopped;
    /// `file-limit` where the scanning process had no socket to put an offer
    /// on for as long as the offer would wait, so the endpoint was not asked.
    pub interruption: &'static str,
}

impl UnfinishedVersionDto {
    /// Renders one version whose walk did not finish.
    pub fn new(unfinished: &UnfinishedVersion) -> Self {
        Self {
            version: unfinished.version().name(),
            interruption: unfinished.interruption().name(),
        }
    }
}

/// One protocol version an endpoint accepted, and the suites it chose under it.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct AcceptedVersionDto {
    /// The version, spelled the way every tool prints it: `SSLv3`, `TLSv1.0`
    /// through `TLSv1.3`.
    pub version: &'static str,
    /// Whether a standards body has withdrawn it, and so whether its presence is
    /// itself the finding.
    pub deprecated: bool,
    /// The suites accepted, in the order the server chose them. The first is
    /// the server's own preference, where it has one.
    pub suites: Vec<AcceptedSuiteDto>,
    /// Suites the server chose that this build does not carry, by number,
    /// rendered as `0x` hex. Absent where there were none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unrecognised: Vec<String>,
}

impl AcceptedVersionDto {
    /// Renders one version's worth of what an endpoint accepts.
    pub fn new(support: &VersionSupport) -> Self {
        Self {
            version: support.version().name(),
            deprecated: support.version().is_deprecated(),
            suites: support.suites().iter().map(AcceptedSuiteDto::new).collect(),
            unrecognised: support
                .unrecognised()
                .iter()
                .map(|code| format!("0x{code:04X}"))
                .collect(),
        }
    }
}

/// One cipher suite an endpoint accepted, and what is wrong with it.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct AcceptedSuiteDto {
    /// The IANA name, which is what every other tool prints.
    pub name: &'static str,
    /// The wire number, as `0x` hex, for a reader matching against a registry.
    pub code: String,
    /// `strong`, `weak` or `insecure`, derived from `faults`.
    pub strength: &'static str,
    /// Everything wrong with the suite, least costly first. Empty for a suite
    /// with nothing against it.
    pub faults: Vec<&'static str>,
}

impl AcceptedSuiteDto {
    /// Renders one accepted suite.
    pub fn new(suite: &CipherSuite) -> Self {
        Self {
            name: suite.name(),
            code: format!("0x{:04X}", suite.code()),
            strength: suite.strength().name(),
            faults: suite
                .faults()
                .into_iter()
                .map(|fault| fault.name())
                .collect(),
        }
    }
}

/// A presented X.509 certificate.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub struct CertificateDto<'a> {
    /// The subject Common Name, masked under redaction: an internal CA issues
    /// certificates naming people and machines.
    pub common_name: Cow<'a, str>,
    /// Subject Alternative Names, masked under redaction for the same reason.
    pub sans: Vec<Cow<'a, str>>,
    /// The issuing authority, with the host's names masked under redaction: a
    /// directory's own certificate authority is often named for its machine.
    pub issuer: Cow<'a, str>,
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
    /// Renders certificate information on the host `masking` was made for,
    /// applying its redaction policy.
    pub fn new(cert: &'a CertificateInfo, masking: &HostRedaction) -> Self {
        let redaction = masking.redaction();

        Self {
            common_name: redaction.hostname(cert.common_name()),
            sans: cert
                .sans()
                .iter()
                .map(|san| redaction.hostname(san))
                .collect(),
            issuer: masking.text(cert.issuer()),
            validity_start: rfc3339(cert.validity_start()),
            validity_end: rfc3339(cert.validity_end()),
            pubkey_type: cert.pubkey_type(),
            pubkey_bits: cert.pubkey_bits(),
            fingerprint_sha256: cert.fingerprint_sha256(),
        }
    }
}

/// How a port's state was established.
#[non_exhaustive]
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
    /// The reply's sender, the source address in its IP header, where it was
    /// recorded; never an address of the scanning machine. Where it is not the
    /// target's, the verdict came from something on the path, such as a
    /// router's ICMP error. `null` where nothing recorded one.
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
    use crate::model::exclusion::Exclusions;
    use crate::model::host::{NetworkRole, StatusProtocol};
    use crate::model::ip::set::IpSet;
    use crate::model::port::PortSet;
    use crate::model::port::{Protocol, ScanResponse};
    use crate::model::target::{TargetMap, TargetSet};
    use crate::report::ScannerKind;
    use crate::report::{ScanKind, StopReason};

    /// Pins the wire spelling of enumerated values, so a rename fails a test.
    #[test]
    fn wire_names_are_pinned() {
        assert_eq!(scan_kind_name(ScanKind::PortScan), "port_scan");
        assert_eq!(scanner_kind_name(ScannerKind::SynPort), "syn_port");
        assert_eq!(host_status_name(HostStatus::Blocked), "blocked");
        assert_eq!(
            port_state_name(PortState::OpenOrNoReply),
            "open_or_no_reply"
        );
        assert_eq!(port_state_name(PortState::NoReply), "no_reply");
        assert_eq!(protocol_name(Protocol::Udp), "udp");
        // Every role, since this vocabulary grows.
        for (role, name) in [
            (NetworkRole::Router, "router"),
            (NetworkRole::DnsServer, "dns"),
            (NetworkRole::DhcpServer, "dhcp"),
            (NetworkRole::NtpServer, "ntp"),
            (NetworkRole::SnmpAgent, "snmp"),
            (NetworkRole::Origin, "origin"),
            (NetworkRole::Tarpit, "tarpit"),
            (NetworkRole::Truncated, "truncated"),
        ] {
            assert_eq!(network_role_name(role), name);
        }
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

    /// Every status and state is a key in the summary, even at zero.
    #[test]
    fn the_summary_reports_categories_that_saw_nothing() {
        let summary = SummaryDto::new(&ScanSummary::default());

        assert_eq!(summary.hosts_by_status.up, 0);
        assert_eq!(summary.hosts_by_status.unknown, 0);
        assert_eq!(summary.ports_by_state.open, 0);
        assert_eq!(summary.ports_by_state.closed_or_no_reply, 0);
    }

    /// An IPv6 sweep's counts exceed what a JSON number holds exactly, and
    /// survive as text.
    #[test]
    fn oversized_counts_are_rendered_as_exact_strings() {
        let mut ips = IpSet::new();
        ips.insert_range("2001:db8::/32".parse().expect("a valid range"));

        let scope = ScopeDto::new(&TargetScope::from_ip_set(&mut ips, &Exclusions::none()));

        // 2^96, which a JavaScript number would round.
        assert_eq!(scope.addresses, "79228162514264337593543950336");
        assert!(scope.addresses.parse::<u128>().expect("exact") > (1u128 << 53));
    }

    /// A discovery phase has no port dimension, so its probe count is absent;
    /// zero would claim the sweep sent nothing.
    #[test]
    fn a_discovery_scope_has_no_probe_count() {
        let mut ips = IpSet::new();
        ips.insert_range("203.0.113.0/24".parse().expect("a valid range"));

        let scope = ScopeDto::new(&TargetScope::from_ip_set(&mut ips, &Exclusions::none()));

        assert_eq!(scope.addresses, "256");
        assert_eq!(scope.probes, None);
        assert!(scope.protocols.is_empty());
        assert_eq!(scope.ranges.len(), 1);
        assert_eq!(scope.ranges[0].family, "ipv4");
        assert_eq!(scope.ranges[0].start, "203.0.113.0");
        assert_eq!(scope.ranges[0].end, "203.0.113.255");
    }

    #[test]
    fn a_port_scan_scope_carries_the_probe_count() {
        let mut ips = IpSet::new();
        ips.insert_range("198.51.100.1-198.51.100.4".parse().expect("a valid range"));

        let mut targets = TargetMap::new();
        targets.add_unit(TargetSet::new(
            ips,
            PortSet::from_iter([(80, Protocol::Tcp), (53, Protocol::Udp)]),
        ));

        let scope = ScopeDto::new(&TargetScope::from_target_map(
            &mut targets,
            &Exclusions::none(),
        ));

        assert_eq!(scope.addresses, "4");
        assert_eq!(scope.probes.as_deref(), Some("8"));
        assert_eq!(scope.protocols, vec!["tcp", "udp"]);
    }

    /// The phases add up to the total exactly, whatever the sub-microsecond
    /// remainders were.
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

    /// [`TimeoutScale`](crate::config::TimeoutScale) refuses a non-positive or
    /// non-finite scale, so what reaches the document is always a number JSON
    /// can hold.
    #[test]
    fn a_recorded_timeout_scale_is_always_a_number_json_can_hold() {
        for scale in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert_eq!(
                crate::config::TimeoutScale::new(scale),
                None,
                "a scale of {scale} would have reached a report"
            );
        }

        let retry = RetryConfig {
            timeout_scale: crate::config::TimeoutScale::new(2.5),
            ..Default::default()
        };
        let rendered = RetryDto::new(&retry).timeout_scale;
        assert_eq!(rendered, Some(2.5));
        assert!(rendered.is_some_and(f64::is_finite));
    }
}
