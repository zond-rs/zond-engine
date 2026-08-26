// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reading this engine's own report back
//!
//! The document [`export::json`](crate::export::json) writes, read back as the
//! [`ScanReport`] it was written from. An exported file is what people archive,
//! so this is what lets a comparison run against last quarter's scan without a
//! journal still being on disk.
//!
//! ## It translates a shape and nothing more
//!
//! [`record`](crate::record) is already the model as data that can be written
//! down and read back, and every one of its types already rebuilds a model value
//! through the model's own constructors — so a rebuilt host passed the same
//! checks a scanned one did. Repeating that here would be a second place that
//! knows how to assemble a [`Host`], and the two would
//! drift.
//!
//! So this module maps the *exported* shape onto the *recorded* shape and stops.
//! The two differ only in encoding: timestamps are RFC 3339 strings rather than
//! epoch pairs, durations are integers of microseconds rather than
//! [`Duration`]s, and counts too large for a JSON number are decimal strings.
//! Everything past that is `record`'s.
//!
//! ## What it promises
//!
//! The same bargain the exported document offers its consumers, from the other
//! side of it:
//!
//! - **Unknown fields are ignored.** A report from a newer engine stays readable.
//! - **An unknown enum string is an error naming it.** Not a field a reader may
//!   skip: it is the value that decides what the record *says*.
//! - **`schema_version` is required and checked**, and a document from a version
//!   past this build's is refused rather than read approximately.
//! - **`engine.name` is required and checked.** It is how a report is told apart
//!   from any other JSON that happens to have a `hosts` key.
//! - **`produced_by` is optional**, because documents written before it existed
//!   carried the same value in `engine.version`. That is what it falls back to.
//!
//! ## What the document cannot give back
//!
//! Two things, and the export is right about both.
//!
//! **Round-trip samples.** The document carries the summary statistics — least,
//! median, mean, greatest, jitter — and not the measurements they were computed
//! from, because a sample's timestamp is a monotonic
//! [`Instant`](std::time::Instant) that means nothing outside the process that
//! took it. A host read back here therefore reports no round trips at all rather
//! than a fabricated set that averages correctly.
//!
//! **Per-source operating-system evidence.** The document carries the verdict
//! and not the sources that corroborated it. A host read back keeps what it was
//! identified as and starts its evidence fresh.
//!
//! Neither is compared by [`diff`](crate::diff), which reads verdicts and not the
//! evidence behind them, so neither costs a comparison anything.
//!
//! ## Streaming
//!
//! Hosts are converted one at a time as the array is parsed, so a report of a
//! /16 costs one host's worth of document on top of the report being built — the
//! same bargain the exporter makes writing it.

use std::fmt;
use std::io::BufRead;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::config::{OsDetection, ScanEffort, SendMode, ServiceDetection};
use crate::format::time::parse_rfc3339;
use crate::format::{ENGINE_NAME, SCHEMA_VERSION};
use crate::import::report::{ReportOptions, ReportReader};
use crate::import::{ImportError, Origin};
use crate::model::host::Host;
use crate::model::port::PortSet;
use crate::model::technique::TcpScanTechnique;
use crate::record::wire;
use crate::record::{
    CaptureRecord, CertificateRecord, DiscoveryRecord, FailureRecord, HardwareRecord, HopRecord,
    HostRecord, OriginRecord, OsRecord, PhaseRecord, PortRecord, PortsRecord, ProbeStatsRecord,
    RangeRecord, ScopeRecord, SecurityRecord, ServiceRecord, SettingsRecord, StatusReasonRecord,
    TelemetryRecord, WindowRecord,
};
use crate::scanner::report::{ScanPhase, ScanReport};

/// The format's name in errors.
const FORMAT: &str = "JSON";

/// Reads this engine's exported JSON report back as the report it was written
/// from.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonReportReader {
    #[allow(dead_code)]
    options: ReportOptions,
}

impl JsonReportReader {
    /// A reader bounded by `options`.
    pub fn new(options: ReportOptions) -> Self {
        Self { options }
    }
}

impl ReportReader for JsonReportReader {
    fn read(&self, input: &mut dyn BufRead) -> Result<ScanReport, ImportError> {
        let mut deserializer = serde_json::Deserializer::from_reader(input);
        let document =
            Document::deserialize(&mut deserializer).map_err(|error| malformed(&error))?;

        document.into_report()
    }
}

/// A parse failure, placed in the file where `serde_json` says it happened.
fn malformed(error: &serde_json::Error) -> ImportError {
    ImportError::Malformed {
        format: FORMAT,
        origin: Origin::line(error.line() as u64),
        message: error.to_string(),
    }
}

// ---------------------------------------------------------------------------
// The document root
//
// Hand-written rather than derived, so that hosts are converted as the array is
// parsed rather than collected and converted afterwards.
// ---------------------------------------------------------------------------

/// The document, with its hosts already rebuilt.
struct Document {
    schema_version: u32,
    engine: EngineDto,
    /// What produced the findings, as that scanner attributed itself.
    ///
    /// Absent from a document written before this had a field of its own, where
    /// `engine.version` carried it. See [`Document::into_report`].
    produced_by: Option<String>,
    phases: Vec<PhaseDto>,
    hosts: Vec<Host>,
}

impl Document {
    /// The report this document describes.
    fn into_report(self) -> Result<ScanReport, ImportError> {
        if self.schema_version > SCHEMA_VERSION {
            return Err(refuse(format!(
                "schema version {} is past version {SCHEMA_VERSION}, which is the highest this \
                 build understands; its fields may mean something else",
                self.schema_version
            )));
        }

        if self.engine.name != ENGINE_NAME {
            return Err(refuse(format!(
                "the document names engine '{}' rather than '{ENGINE_NAME}'",
                self.engine.name
            )));
        }

        let phases: Vec<ScanPhase> = self
            .phases
            .into_iter()
            .map(|phase| phase.record().map(|record| ScanPhase::from(&record)))
            .collect::<Result<_, _>>()
            .map_err(refuse)?;

        // `produced_by` where the document has one. A document written before
        // that field existed put the same value in `engine.version`, which is
        // why the fallback is exactly right rather than merely close: back then
        // that field *was* the attribution, which is the thing this release
        // stopped it from being.
        let produced_by = self.produced_by.unwrap_or(self.engine.version);

        Ok(ScanReport::recorded(produced_by, phases, self.hosts))
    }
}

/// A refusal about the document as a whole, which has no one line to point at.
fn refuse(message: String) -> ImportError {
    ImportError::Malformed {
        format: FORMAT,
        origin: Origin::unknown(),
        message,
    }
}

impl<'de> Deserialize<'de> for Document {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(DocumentVisitor)
    }
}

struct DocumentVisitor;

impl<'de> Visitor<'de> for DocumentVisitor {
    type Value = Document;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a zond scan report")
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut schema_version = None;
        let mut engine = None;
        let mut produced_by = None;
        let mut phases = Vec::new();
        let mut hosts = Vec::new();

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "schema_version" => schema_version = Some(map.next_value()?),
                "engine" => engine = Some(map.next_value()?),
                "produced_by" => produced_by = Some(map.next_value()?),
                "phases" => phases = map.next_value()?,
                // The one array worth streaming: every other key is a handful
                // of values whatever the size of the scan.
                "hosts" => hosts = map.next_value::<Hosts>()?.0,
                // Everything else in the document is derived from what is read
                // here — the summary, the totals, whether the run was partial —
                // and a reader that trusted them could report counts its own
                // hosts disagree with.
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        Ok(Document {
            schema_version: schema_version
                .ok_or_else(|| de::Error::missing_field("schema_version"))?,
            engine: engine.ok_or_else(|| de::Error::missing_field("engine"))?,
            produced_by,
            phases,
            hosts,
        })
    }
}

/// The hosts array, rebuilt one element at a time.
struct Hosts(Vec<Host>);

impl<'de> Deserialize<'de> for Hosts {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HostsVisitor;

        impl<'de> Visitor<'de> for HostsVisitor {
            type Value = Hosts;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an array of hosts")
            }

            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                let mut hosts = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(dto) = seq.next_element::<HostDto>()? {
                    let record = dto.record().map_err(de::Error::custom)?;
                    hosts.push(Host::from(&record));
                }
                Ok(Hosts(hosts))
            }
        }

        deserializer.deserialize_seq(HostsVisitor)
    }
}

// ---------------------------------------------------------------------------
// Reading the encodings the document uses
// ---------------------------------------------------------------------------

/// An RFC 3339 timestamp, which is the only form a time takes in the document.
fn timestamp(text: &str) -> Result<SystemTime, String> {
    parse_rfc3339(text).ok_or_else(|| format!("'{text}' is not an RFC 3339 timestamp in UTC"))
}

/// A count written as a decimal string, which is what the document does for
/// anything that can exceed what a JSON number holds exactly.
fn count(text: &str) -> Result<u128, String> {
    text.parse().map_err(|_| format!("'{text}' is not a count"))
}

/// An address.
fn address(text: &str) -> Result<IpAddr, String> {
    text.parse()
        .map_err(|_| format!("'{text}' is not an IP address"))
}

/// An enumerated value this build recognises, or an error naming the one it does
/// not.
///
/// The opposite of what [`record`](crate::record) does with the same string, and
/// deliberately. A journal is a file this engine wrote, so a value it cannot read
/// there belongs to a newer build of itself and the format's version bargain
/// covers it. A document handed in from outside has made no such promise, and a
/// port state read as `filtered` because this build did not recognise the word
/// is a report claiming something the scan never established.
fn known<T>(parsed: Option<T>, what: &str, value: &str) -> Result<(), String> {
    parsed
        .map(|_| ())
        .ok_or_else(|| format!("'{value}' is not {what} this build recognises"))
}

/// A duration, which the document writes as whole microseconds.
fn micros(value: u64) -> Duration {
    Duration::from_micros(value)
}

/// Maps a fallible conversion over an optional field.
fn maybe<T, U>(
    value: Option<T>,
    f: impl FnOnce(T) -> Result<U, String>,
) -> Result<Option<U>, String> {
    value.map(f).transpose()
}

// ---------------------------------------------------------------------------
// The document's objects
//
// One per `$defs` entry in the published schema, owned and `#[serde(default)]`
// throughout so a document that omits a field this build knows about is read
// rather than refused.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct EngineDto {
    name: String,
    #[serde(default)]
    version: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PhaseDto {
    kind: String,
    started_at: String,
    elapsed_us: u64,
    privileged: Option<bool>,
    targets: ScopeDto,
    settings: SettingsDto,
    failures: Vec<FailureDto>,
    probe_stats: Vec<ProbeStatsDto>,
    unroutable: Vec<String>,
    origin: Option<OriginDto>,
}

/// Which document a phase came from, for a report merged out of several.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct OriginDto {
    label: Option<String>,
    engine_version: String,
}

impl PhaseDto {
    fn record(self) -> Result<PhaseRecord, String> {
        known(wire::scan_kind(&self.kind), "a scan phase", &self.kind)?;

        Ok(PhaseRecord {
            // Not read back: a phase somebody else's document describes was
            // not run from this machine, so where it was plugged in is not
            // something the reader can learn or has any business inventing.
            attachments: Vec::new(),
            kind: self.kind,
            started_at: timestamp(&self.started_at)?,
            elapsed: micros(self.elapsed_us),
            privileged: self.privileged,
            targets: self.targets.record()?,
            settings: self.settings.record()?,
            failures: self
                .failures
                .into_iter()
                .map(FailureDto::record)
                .collect::<Result<_, _>>()?,
            unroutable: self
                .unroutable
                .iter()
                .map(|ip| address(ip))
                .collect::<Result<_, _>>()?,
            probes: self
                .probe_stats
                .into_iter()
                .map(ProbeStatsDto::record)
                .collect::<Result<_, _>>()?,
            origin: self.origin.map(|origin| OriginRecord {
                label: origin.label,
                engine_version: origin.engine_version,
            }),
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ScopeDto {
    ranges: Vec<RangeDto>,
    links: Vec<String>,
    #[serde(default)]
    listened: Vec<String>,
    addresses: String,
    probes: Option<String>,
    ports: Option<PortScopeDto>,
    protocols: Vec<String>,
    excluded: Vec<RangeDto>,
    withheld: String,
}

impl ScopeDto {
    fn record(self) -> Result<ScopeRecord, String> {
        for protocol in &self.protocols {
            known(wire::protocol(protocol), "a transport", protocol)?;
        }

        Ok(ScopeRecord {
            ranges: self
                .ranges
                .into_iter()
                .map(RangeDto::record)
                .collect::<Result<_, _>>()?,
            // The document carries the interface name and not its index, which
            // is what an unresolved zone is: a name nothing has looked up yet.
            listened: self
                .listened
                .into_iter()
                .map(|name| crate::record::ZoneRecord { index: None, name })
                .collect(),
            links: self
                .links
                .into_iter()
                .map(|name| crate::record::ZoneRecord { index: None, name })
                .collect(),
            addresses: count(&self.addresses)?,
            probes: maybe(self.probes.as_deref(), count)?,
            ports: maybe(self.ports, PortScopeDto::record)?,
            protocols: self.protocols,
            excluded: self
                .excluded
                .into_iter()
                .map(RangeDto::record)
                .collect::<Result<_, _>>()?,
            withheld: count(&self.withheld)?,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PortScopeDto {
    kind: String,
    spec: String,
}

impl PortScopeDto {
    fn record(self) -> Result<PortsRecord, String> {
        known(
            wire::port_scope(&self.kind, None),
            "a port scope",
            &self.kind,
        )?;

        // A specification that will not parse would rebuild as a scope that
        // states nothing, which is a comparison quietly losing its ability to
        // say an endpoint was probed. Refused instead.
        if !self.spec.is_empty() {
            known(
                PortSet::try_from(self.spec.as_str()).ok(),
                "a port specification",
                &self.spec,
            )?;
        }

        Ok(PortsRecord {
            kind: self.kind,
            spec: self.spec,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RangeDto {
    start: String,
    end: String,
}

impl RangeDto {
    fn record(self) -> Result<RangeRecord, String> {
        Ok(RangeRecord {
            start: address(&self.start)?,
            end: address(&self.end)?,
            // The document does not scope a range to an interface. A range that
            // needs one is a link-local sweep, whose zone travels on the host.
            zone: None,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SettingsDto {
    send_mode: String,
    tcp_technique: String,
    retry: RetryDto,
    max_probe_rate: Option<u32>,
    dns_enabled: bool,
    redact: bool,
    os_detection: String,
    service_detection: String,
    traceroute: bool,
}

impl SettingsDto {
    fn record(self) -> Result<SettingsRecord, String> {
        known(
            self.send_mode.parse::<SendMode>().ok(),
            "a send mode",
            &self.send_mode,
        )?;
        known(
            self.tcp_technique.parse::<TcpScanTechnique>().ok(),
            "a TCP scan technique",
            &self.tcp_technique,
        )?;
        known(
            self.retry.effort.parse::<ScanEffort>().ok(),
            "a scan effort",
            &self.retry.effort,
        )?;
        known(
            self.os_detection.parse::<OsDetection>().ok(),
            "an operating-system detection level",
            &self.os_detection,
        )?;
        known(
            self.service_detection.parse::<ServiceDetection>().ok(),
            "a service detection level",
            &self.service_detection,
        )?;

        Ok(SettingsRecord {
            send_mode: self.send_mode,
            tcp_technique: self.tcp_technique,
            retry_effort: self.retry.effort,
            retry_max_attempts: self.retry.max_attempts,
            retry_timeout_scale: self.retry.timeout_scale,
            retry_dampen_silent_hosts: self.retry.dampen_silent_hosts,
            max_probe_rate: self.max_probe_rate,
            dns_enabled: self.dns_enabled,
            redact: self.redact,
            os_detection: self.os_detection,
            service_detection: self.service_detection,
            traceroute: self.traceroute,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RetryDto {
    effort: String,
    max_attempts: Option<u8>,
    timeout_scale: Option<f64>,
    dampen_silent_hosts: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FailureDto {
    scanner: String,
    reason: String,
    at: String,
}

impl FailureDto {
    fn record(self) -> Result<FailureRecord, String> {
        known(
            wire::scanner_kind(&self.scanner),
            "a scanner",
            &self.scanner,
        )?;

        Ok(FailureRecord {
            at: timestamp(&self.at)?,
            scanner: self.scanner,
            reason: self.reason,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ProbeStatsDto {
    scanner: String,
    targets: String,
    stop_reason: String,
    elapsed_us: u64,
    sends_attempted: u64,
    sends_failed: u64,
    segments_seen: u64,
    segments_off_target: u64,
    replies_without_rtt: u64,
    hosts_found: u64,
    answered_on: Vec<AttemptCountDto>,
    answered_unattributed: u64,
    first_reply_us: Option<u64>,
    last_reply_us: Option<u64>,
    found_at: Vec<BucketDto>,
    capture: Option<CaptureDto>,
    window: Option<WindowDto>,
}

impl ProbeStatsDto {
    fn record(self) -> Result<ProbeStatsRecord, String> {
        known(
            wire::scanner_kind(&self.scanner),
            "a scanner",
            &self.scanner,
        )?;
        known(
            wire::stop_reason(&self.stop_reason),
            "a stop reason",
            &self.stop_reason,
        )?;

        Ok(ProbeStatsRecord {
            scanner: self.scanner,
            targets: count(&self.targets)?,
            stop_reason: self.stop_reason,
            elapsed: micros(self.elapsed_us),
            sends_attempted: self.sends_attempted,
            sends_failed: self.sends_failed,
            segments_seen: self.segments_seen,
            window: self.window.map(WindowDto::record),
            segments_off_target: self.segments_off_target,
            replies_without_rtt: self.replies_without_rtt,
            hosts_found: self.hosts_found,
            // Both histograms are written as one object per bucket, in the order
            // the counters hold them, so the counts alone rebuild the vector.
            answered_on: self.answered_on.into_iter().map(|a| a.count).collect(),
            answered_unattributed: self.answered_unattributed,
            first_reply: self.first_reply_us.map(micros),
            last_reply: self.last_reply_us.map(micros),
            found_at: self.found_at.into_iter().map(|b| b.count).collect(),
            capture: self.capture.map(CaptureDto::record),
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AttemptCountDto {
    count: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BucketDto {
    count: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CaptureDto {
    received: u64,
    dropped: u64,
    if_dropped: u64,
}

impl CaptureDto {
    fn record(self) -> CaptureRecord {
        CaptureRecord {
            received: self.received,
            dropped: self.dropped,
            if_dropped: self.if_dropped,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct WindowDto {
    capacity: u64,
    peak: u64,
    reductions: u32,
    adaptive: bool,
    at_floor: bool,
}

impl WindowDto {
    fn record(self) -> WindowRecord {
        WindowRecord {
            capacity: self.capacity as usize,
            peak: self.peak as usize,
            reductions: self.reductions,
            adaptive: self.adaptive,
            at_floor: self.at_floor,
        }
    }
}

// ---------------------------------------------------------------------------
// One host
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct HostDto {
    primary_ip: String,
    ips: Vec<String>,
    zone: Option<String>,
    hostname: Option<String>,
    status: String,
    reasons: Vec<ReasonDto>,
    roles: Vec<String>,
    os: Option<OsDto>,
    hardware: Option<HardwareDto>,
    telemetry: TelemetryDto,
    ports: Vec<PortDto>,
    first_seen: String,
    last_seen: String,
    path: Vec<HopDto>,
}

impl HostDto {
    fn record(self) -> Result<HostRecord, String> {
        known(
            wire::host_status(&self.status),
            "a host status",
            &self.status,
        )?;
        for role in &self.roles {
            known(wire::network_role(role), "a network role", role)?;
        }

        let first_seen = timestamp(&self.first_seen)?;
        let last_seen = timestamp(&self.last_seen)?;

        Ok(HostRecord {
            primary_ip: address(&self.primary_ip)?,
            ips: self
                .ips
                .iter()
                .map(|ip| address(ip))
                .collect::<Result<_, _>>()?,
            hostname: self.hostname,
            status: self.status,
            reasons: self
                .reasons
                .into_iter()
                .map(ReasonDto::record)
                .collect::<Result<_, _>>()?,
            os: self.os.map(OsDto::record),
            // The document carries the verdict and not the sources behind it.
            // See the module documentation.
            os_evidence: Vec::new(),
            hardware: maybe(self.hardware, |hardware| hardware.record(last_seen))?,
            // The document names the interface and not its index, which is what
            // an unresolved zone is: a name nothing has looked up yet.
            zone: self
                .zone
                .map(|name| crate::record::ZoneRecord { index: None, name }),
            telemetry: self.telemetry.record(),
            path: self
                .path
                .into_iter()
                .map(HopDto::record)
                .collect::<Result<_, _>>()?,
            network_roles: self.roles,
            first_seen,
            last_seen,
            ports: self
                .ports
                .into_iter()
                .map(PortDto::record)
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ReasonDto {
    protocol: String,
    source_ip: Option<String>,
    details: Option<String>,
}

impl ReasonDto {
    fn record(self) -> Result<StatusReasonRecord, String> {
        known(
            wire::status_protocol(&self.protocol),
            "a discovery protocol",
            &self.protocol,
        )?;

        Ok(StatusReasonRecord {
            protocol: self.protocol,
            source: maybe(self.source_ip.as_deref(), address)?,
            details: self.details,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct OsDto {
    name: String,
    family: Option<String>,
    device: Option<String>,
    generation: Option<String>,
    vendor: Option<String>,
    kernel: Option<String>,
    accuracy: u8,
    detail_accuracy: Option<u8>,
    cpe: Vec<String>,
    evidence: Option<String>,
}

impl OsDto {
    fn record(self) -> OsRecord {
        OsRecord {
            name: self.name,
            accuracy: self.accuracy,
            family: self.family,
            device: self.device,
            generation: self.generation,
            vendor: self.vendor,
            kernel: self.kernel,
            detail_accuracy: self.detail_accuracy,
            evidence: self.evidence,
            cpes: self.cpe,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct HardwareDto {
    mac: Option<String>,
    macs: Vec<String>,
}

impl HardwareDto {
    /// The document records which addresses were seen and not when each was, so
    /// they are all placed at the host's last sighting — the latest moment any
    /// of them can have been seen.
    fn record(self, seen: SystemTime) -> Result<HardwareRecord, String> {
        let mut macs: Vec<String> = self.macs;
        if let Some(mac) = self.mac
            && !macs.contains(&mac)
        {
            macs.push(mac);
        }

        Ok(HardwareRecord {
            macs: macs.into_iter().map(|mac| (mac, seen)).collect(),
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TelemetryDto {}

impl TelemetryDto {
    /// The document carries round-trip *summaries* and not the samples they were
    /// computed from, so a host read back reports none. See the module
    /// documentation for why the export is right about that.
    fn record(self) -> TelemetryRecord {
        TelemetryRecord {
            rtts: Vec::new(),
            hop_counter: None,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct HopDto {
    distance: u8,
    address: Option<String>,
    rtt_us: Option<u64>,
    inferred: bool,
}

impl HopDto {
    fn record(self) -> Result<HopRecord, String> {
        Ok(HopRecord {
            distance: self.distance,
            address: maybe(self.address.as_deref(), address)?,
            rtt: self.rtt_us.map(micros),
            inferred: self.inferred,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PortDto {
    port: u16,
    protocol: String,
    state: String,
    service: Option<ServiceDto>,
    security: Option<SecurityDto>,
    discovery: Option<DiscoveryDto>,
}

impl PortDto {
    fn record(self) -> Result<PortRecord, String> {
        known(
            wire::protocol(&self.protocol),
            "a transport",
            &self.protocol,
        )?;
        known(wire::port_state(&self.state), "a port state", &self.state)?;

        Ok(PortRecord {
            number: self.port,
            protocol: self.protocol,
            state: self.state,
            service: self.service.map(ServiceDto::record),
            security: maybe(self.security, SecurityDto::record)?,
            discovery: maybe(self.discovery, DiscoveryDto::record)?,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ServiceDto {
    name: String,
    confidence: u8,
    product: Option<String>,
    vendor: Option<String>,
    version: Option<String>,
    extrainfo: Option<String>,
    cpe: Vec<String>,
}

impl ServiceDto {
    fn record(self) -> ServiceRecord {
        ServiceRecord {
            name: self.name,
            confidence: self.confidence,
            product: self.product,
            vendor: self.vendor,
            version: self.version,
            extrainfo: self.extrainfo,
            cpes: self.cpe,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SecurityDto {
    tls_version: Option<String>,
    cipher_suite: Option<String>,
    alpn: Vec<String>,
    certificate: Option<CertificateDto>,
}

impl SecurityDto {
    fn record(self) -> Result<SecurityRecord, String> {
        Ok(SecurityRecord {
            tls_version: self.tls_version,
            cipher_suite: self.cipher_suite,
            alpn: self.alpn,
            certificate: maybe(self.certificate, CertificateDto::record)?,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CertificateDto {
    common_name: String,
    sans: Vec<String>,
    issuer: String,
    validity_start: String,
    validity_end: String,
    pubkey_type: String,
    pubkey_bits: u32,
    fingerprint_sha256: String,
}

impl CertificateDto {
    fn record(self) -> Result<CertificateRecord, String> {
        Ok(CertificateRecord {
            validity_start: timestamp(&self.validity_start)?,
            validity_end: timestamp(&self.validity_end)?,
            common_name: self.common_name,
            sans: self.sans,
            issuer: self.issuer,
            fingerprint: self.fingerprint_sha256,
            pubkey_type: self.pubkey_type,
            pubkey_bits: self.pubkey_bits,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct DiscoveryDto {
    reason: String,
    timestamp: String,
    rtt_us: Option<u64>,
    ttl: Option<u8>,
    source_ip: Option<String>,
}

impl DiscoveryDto {
    fn record(self) -> Result<DiscoveryRecord, String> {
        known(
            wire::scan_response(&self.reason),
            "a probe response",
            &self.reason,
        )?;

        Ok(DiscoveryRecord {
            timestamp: timestamp(&self.timestamp)?,
            reason: self.reason,
            rtt: self.rtt_us.map(micros),
            ttl: self.ttl,
            source_ip: maybe(self.source_ip.as_deref(), address)?,
        })
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
#[cfg(all(test, feature = "export-json"))]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::diff::ScanDiff;
    use crate::export::{Exporter, JsonExporter};
    use crate::model::host::HostStatus;
    use crate::model::ip::scoped::Zone;

    /// The fixture report, written out as the document consumers parse.
    ///
    /// Every call builds a fresh fixture, whose timestamps are taken as it is
    /// built. A test comparing a report with its own round trip must therefore
    /// use [`round_trip`], which exports the very report it hands back.
    fn exported() -> String {
        write(&crate::export::fixture::report())
    }

    fn write(report: &ScanReport) -> String {
        let mut out = Vec::new();
        JsonExporter::default()
            .export(report, &mut out)
            .expect("the fixture exports");
        String::from_utf8(out).expect("valid UTF-8")
    }

    /// One report, and that same report written out and read back.
    fn round_trip() -> (ScanReport, ScanReport) {
        let original = crate::export::fixture::report();
        let document = write(&original);
        let restored = read(&document).expect("a readable document");
        (original, restored)
    }

    fn read(document: &str) -> Result<ScanReport, ImportError> {
        JsonReportReader::default().read(&mut Cursor::new(document))
    }

    /// The one property that matters: a report written out and read back
    /// describes the same network.
    ///
    /// Asserted through [`ScanDiff`] rather than field by field, because that is
    /// exactly the question the reader exists to answer — and because a field
    /// the reader drops shows up here as a change, whatever field it was.
    #[test]
    fn a_report_read_back_compares_equal_to_itself() {
        let (original, restored) = round_trip();

        let diff = ScanDiff::between(&original, &restored);
        assert!(
            diff.is_empty(),
            "the round trip changed the network it describes: {:#?}",
            diff.hosts()
        );
    }

    #[test]
    fn the_hosts_and_their_ports_survive() {
        let (original, restored) = round_trip();

        assert_eq!(restored.host_count(), original.host_count());
        assert_eq!(restored.engine_version(), original.engine_version());

        for host in original.hosts() {
            let read_back = restored
                .host(&host.primary_ip())
                .unwrap_or_else(|| panic!("{} is missing", host.primary_ip()));

            assert_eq!(read_back.status(), host.status());
            assert_eq!(read_back.hostname(), host.hostname());
            assert_eq!(read_back.mac(), host.mac());
            assert_eq!(read_back.port_count(), host.port_count());
            assert_eq!(
                read_back.os().map(|os| os.name()),
                host.os().map(|os| os.name())
            );

            for port in host.ports() {
                let restored_port = read_back
                    .ports()
                    .find(|p| p.number() == port.number() && p.protocol() == port.protocol())
                    .expect("the port survives");
                assert_eq!(restored_port.state(), port.state());
                assert_eq!(restored_port.service(), port.service());
                assert_eq!(restored_port.security(), port.security());
            }
        }
    }

    #[test]
    fn the_phases_survive_with_their_scope() {
        let (original, restored) = round_trip();

        assert_eq!(restored.phases().len(), original.phases().len());

        for (before, after) in original.phases().iter().zip(restored.phases()) {
            assert_eq!(after.kind(), before.kind());
            // The document keeps a time to whole microseconds and truncates the
            // rest, so a phase comes back within a microsecond of where it was
            // rather than on the same nanosecond. Truncation only ever moves a
            // moment earlier, which is why this subtracts in this order.
            let drift = before
                .started_at()
                .duration_since(after.started_at())
                .expect("truncation never moves a moment later");
            assert!(
                drift < Duration::from_micros(1),
                "{drift:?} is more than the format's resolution"
            );
            assert!(
                before.elapsed() - after.elapsed() < Duration::from_micros(1),
                "{:?} against {:?}",
                before.elapsed(),
                after.elapsed()
            );
            assert_eq!(after.privileged(), before.privileged());
            assert_eq!(after.targets().ranges(), before.targets().ranges());
            assert_eq!(after.targets().excluded(), before.targets().excluded());
            assert_eq!(after.targets().addresses(), before.targets().addresses());
            assert_eq!(after.targets().withheld(), before.targets().withheld());
            assert_eq!(
                after.targets().ports(),
                before.targets().ports(),
                "the port scope is what a comparison asks about endpoints"
            );

            let links: Vec<&str> = after.targets().links().iter().map(Zone::name).collect();
            let before_links: Vec<&str> = before.targets().links().iter().map(Zone::name).collect();
            assert_eq!(
                links, before_links,
                "a swept link is the only way a comparison knows a neighbour was looked for"
            );
            assert!(
                !links.is_empty(),
                "the fixture sweeps one, or this proves nothing"
            );
            assert_eq!(after.settings(), before.settings());
            assert_eq!(after.failures().len(), before.failures().len());
            assert_eq!(after.probe_stats().len(), before.probe_stats().len());
        }
    }

    #[test]
    fn a_scanners_counters_survive() {
        let (original, restored) = round_trip();

        let before: Vec<_> = original.probe_stats().collect();
        let after: Vec<_> = restored.probe_stats().collect();
        assert_eq!(before.len(), after.len(), "instrumentation is not dropped");

        for (before, after) in before.iter().zip(&after) {
            assert_eq!(after.scanner(), before.scanner());
            assert_eq!(after.stop_reason(), before.stop_reason());
            assert_eq!(after.targets(), before.targets());
            assert_eq!(after.sends_attempted(), before.sends_attempted());
            assert_eq!(after.segments_seen(), before.segments_seen());
            assert_eq!(after.hosts_found(), before.hosts_found());
            assert_eq!(after.answered_on(), before.answered_on());
            assert_eq!(after.found_at(), before.found_at());
            assert_eq!(after.capture(), before.capture());
            assert_eq!(
                after.window(),
                before.window(),
                "including whether the window was allowed to move"
            );
        }
    }

    // -----------------------------------------------------------------------
    // The bargain this side promises
    // -----------------------------------------------------------------------

    #[test]
    fn a_field_this_build_does_not_know_is_ignored() {
        let document = exported().replace(
            r#"{"schema_version""#,
            r#"{"something_from_a_later_engine":{"nested":[1,2,3]},"schema_version""#,
        );

        let restored = read(&document).expect("a newer engine's report stays readable");
        assert_eq!(restored.host_count(), 3);
    }

    #[test]
    fn a_schema_version_past_this_build_is_refused() {
        let document = exported().replace(
            &format!(r#""schema_version":{SCHEMA_VERSION}"#),
            &format!(r#""schema_version":{}"#, SCHEMA_VERSION + 1),
        );

        let error = read(&document).expect_err("refused");
        assert!(error.to_string().contains("schema version"), "{error}");
    }

    /// A foreign scanner's attribution survives the round trip, and does not
    /// land on this engine's name on the way.
    ///
    /// The failure: `engine.version` carried the attribution, so a report read
    /// out of nmap's XML exported as `engine: {name: zond-engine, version: nmap
    /// 7.94}`. Through the nmap *writer*, whose `scanner="zond"` is fixed the
    /// same way, the pair collapsed further — `zond 0.13.0` came back as the
    /// version of the next document exported from it.
    #[test]
    fn what_produced_the_findings_round_trips_apart_from_who_wrote_the_file() {
        let foreign = ScanReport::recorded(
            "nmap 7.94",
            crate::export::fixture::report().phases().to_vec(),
            Vec::new(),
        );

        let restored = read(&write(&foreign)).expect("its own document reads back");
        assert_eq!(restored.engine_version(), "nmap 7.94");
    }

    /// A document written before `produced_by` existed still reads, because back
    /// then `engine.version` was the attribution — which is exactly what the
    /// fallback takes it for.
    #[test]
    fn a_document_written_before_produced_by_falls_back_to_the_engine_version() {
        let document = write(&crate::export::fixture::report());
        let mut parsed: serde_json::Value =
            serde_json::from_str(&document).expect("its own output parses");

        let attribution = parsed["produced_by"].take();
        parsed
            .as_object_mut()
            .expect("an object")
            .remove("produced_by");
        parsed["engine"]["version"] = attribution.clone();

        let restored = read(&parsed.to_string()).expect("an older document still reads");
        assert_eq!(
            restored.engine_version(),
            attribution.as_str().expect("a string")
        );
    }

    #[test]
    fn a_document_another_engine_wrote_is_refused() {
        let document = exported().replace(ENGINE_NAME, "some-other-scanner");

        let error = read(&document).expect_err("refused");
        assert!(error.to_string().contains("some-other-scanner"), "{error}");
    }

    #[test]
    fn an_unknown_enum_value_is_refused_naming_it() {
        let document = exported().replace(r#""state":"open""#, r#""state":"ajar""#);

        let error = read(&document).expect_err("refused");
        assert!(
            error.to_string().contains("ajar"),
            "a state this build cannot read is not a field to skip: {error}"
        );
    }

    #[test]
    fn a_timestamp_that_is_not_the_documented_shape_is_refused() {
        let document =
            exported().replace(r#""first_seen":""#, r#""first_seen":"yesterday afternoon"#);

        let error = read(&document).expect_err("refused");
        assert!(error.to_string().contains("RFC 3339"), "{error}");
    }

    #[test]
    fn a_document_that_is_not_a_report_is_refused() {
        // The version is what tells a report apart from any other JSON that
        // happens to have a `hosts` key, so its absence is what is named.
        let error = read(r#"{"hosts": []}"#).expect_err("refused");
        assert!(error.to_string().contains("schema_version"), "{error}");

        let error = read(r#"{"schema_version":1,"hosts":[]}"#).expect_err("refused");
        assert!(error.to_string().contains("engine"), "{error}");
    }

    // -----------------------------------------------------------------------
    // The point of it
    // -----------------------------------------------------------------------

    #[test]
    fn an_archived_report_compares_against_a_later_scan() {
        use crate::model::port::{Port, PortState, Protocol};

        let archived = read(&exported()).expect("a readable document");

        // The same network a week later, with a port open that was not before.
        let original = crate::export::fixture::report();
        let opened = original
            .hosts()
            .next()
            .map(crate::model::host::Host::primary_ip)
            .expect("the fixture has a host");

        let hosts: Vec<_> = original
            .hosts()
            .cloned()
            .map(|mut host| {
                if host.primary_ip() == opened {
                    host.add_port(Port::new(8080, Protocol::Tcp, PortState::Open));
                }
                host
            })
            .collect();
        let later =
            ScanReport::recorded(original.engine_version(), original.phases().to_vec(), hosts);

        let diff = ScanDiff::between(&archived, &later);

        assert_eq!(diff.summary().ports_opened.total, 1);
        let delta = diff
            .hosts()
            .iter()
            .find(|host| host.address() == opened)
            .expect("the host whose port opened");
        assert_eq!(delta.ports()[0].number(), 8080);
    }

    #[test]
    fn a_host_that_answered_nothing_still_reads_back() {
        let restored = read(&exported()).expect("a readable document");
        assert!(
            restored.hosts().any(|host| host.status() != HostStatus::Up),
            "the fixture carries a host that is not up, and it survives"
        );
    }
}
