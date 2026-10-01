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
//! [`ScanReport`] it was written from, so a comparison can run against an archived
//! export without the scan's journal.
//!
//! ## Mapping onto `record`
//!
//! [`record`](crate::record) already rebuilds every model value through the
//! model's own constructors, so a rebuilt host passes the same checks a scanned
//! one does. This module only maps the exported shape onto the recorded one. The
//! two differ in encoding: timestamps are RFC 3339 strings, durations are integer
//! microseconds, and counts too large for a JSON number are decimal strings.
//!
//! ## Compatibility rules
//!
//! - **Unknown fields are ignored**, so a report from a newer engine stays
//!   readable.
//! - **An unknown enum string is an error naming it**, since that value decides
//!   what the record says.
//! - **`schema_version` is required and checked.** A document from a newer schema
//!   version is refused.
//! - **`engine.name` is required and checked.** It tells a report apart from any
//!   other JSON that happens to have a `hosts` key.
//! - **`produced_by` is optional.** Documents written before it existed carried
//!   the same value in `engine.version`, which is the fallback.
//!
//! ## What the document cannot give back
//!
//! Round-trip samples. The document carries the summary statistics (least,
//! median, mean, greatest and jitter) but not the samples, whose timestamps are
//! monotonic [`Instant`](std::time::Instant)s meaningless outside the process that
//! took them. A host read back here reports no round trips.
//!
//! Per-source operating-system evidence. The document carries the verdict only. A
//! host read back keeps what it was identified as and starts its evidence fresh.
//!
//! [`diff`](crate::diff) compares neither of these, so a comparison loses nothing.
//!
//! A phase's [`attachments`](crate::report::Attachment). They name a switch port
//! on the network the scan ran from, which means nothing on the machine reading
//! the document, so they are dropped.
//!
//! ## Streaming
//!
//! Hosts are converted one at a time as the array is parsed, so a report of a /16
//! costs one host's worth of document on top of the report being built. A host's
//! ports are converted the same way and folded by endpoint as they arrive.
//!
//! [`ImportLimits::max_addresses`](crate::import::ImportLimits::max_addresses) is
//! checked as hosts arrive, before the allocation it bounds.
//!
//! ## Both shapes, one mapping
//!
//! [`JsonReportReader`] reads the single document and [`JsonLinesReportReader`]
//! the record-per-line one. They share every record type below, since a `host`
//! line is the document's host object with a `type` field added.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::BufRead;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use std::cell::Cell;

use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::config::{OsDetection, ScanEffort, ServiceDetection};
use crate::format::time::parse_rfc3339;
use crate::format::{ENGINE_NAME, SCHEMA_VERSION};
use crate::import::report::{ReportOptions, ReportReader};
use crate::import::{ImportError, ImportOrigin};
use crate::model::host::Host;
use crate::model::mac::MacAddr;
use crate::model::port::{self, Port, PortSet, Protocol};
use crate::model::technique::{SctpScanTechnique, TcpScanTechnique};
use crate::model::tls::{Interruption, TlsVersion};
use crate::record::wire;
use crate::record::{
    AcceptedVersionRecord, BuildRecord, CaptureRecord, CertificateRecord, DetectionIdRecord,
    DiscoveryRecord, EvasionSettingsRecord, ExploitationRecord, FailureRecord, FindingGroupRecord,
    FindingRecord, HardwareRecord, HopRecord, HostRecord, IdleScanRecord, OsRecord,
    PhaseOriginRecord, PhaseRecord, PortRecord, PortsRecord, ProbeStatsRecord, RangeRecord,
    ReferenceRecord, RefusalRecord, ReleaseRecord, ScopeRecord, SecurityRecord, ServiceRecord,
    SettingsRecord, StatusReasonRecord, TelemetryRecord, UnfinishedVersionRecord, WindowRecord,
};
use crate::report::{ScanPhase, ScanReport};
use crate::transport::probe::SendMode;

/// The format's name in errors.
const FORMAT: &str = "JSON";

/// The format's name in errors, for the record-per-line reader.
const LINES_FORMAT: &str = "JSON Lines";

/// The `type` of a record-per-line document's header record.
const REPORT_RECORD: &str = "report";

/// The `type` of a host's record in a record-per-line document.
const HOST_RECORD: &str = "host";

/// Reads this engine's exported JSON report back as the report it was written
/// from.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonReportReader {
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
        let max_document_bytes = self.options.max_document_bytes;
        crate::import::bounded::within(input, max_document_bytes, |input| self.read_within(input))
    }
}

impl JsonReportReader {
    /// [`read`](ReportReader::read), over an input already cut off at the
    /// document ceiling.
    fn read_within(&self, input: &mut dyn BufRead) -> Result<ScanReport, ImportError> {
        crate::import::skip_bom(input)?;

        let max_hosts = self.options.limits.max_addresses;
        let overrun = Cell::new(false);

        let mut deserializer = serde_json::Deserializer::from_reader(input);
        let document = DocumentSeed {
            max_hosts,
            overrun: &overrun,
        }
        .deserialize(&mut deserializer);

        // The host count overrun is the real error; serde's only carried it out.
        if overrun.get() {
            return Err(ImportError::TooManyHosts { limit: max_hosts });
        }
        let document = document.map_err(|error| malformed(FORMAT, &error))?;

        document.into_report(FORMAT)
    }
}

/// Reads this engine's record-per-line export back as the report it was written
/// from.
///
/// The format exists because a JSON document is only valid when complete, and a
/// scan killed half way through should leave something readable. A file whose
/// last line is truncated is refused at that line.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonLinesReportReader {
    options: ReportOptions,
}

impl JsonLinesReportReader {
    /// A reader bounded by `options`.
    pub fn new(options: ReportOptions) -> Self {
        Self { options }
    }
}

impl ReportReader for JsonLinesReportReader {
    fn read(&self, input: &mut dyn BufRead) -> Result<ScanReport, ImportError> {
        let max_document_bytes = self.options.max_document_bytes;
        crate::import::bounded::within(input, max_document_bytes, |input| self.read_within(input))
    }
}

impl JsonLinesReportReader {
    /// [`read`](ReportReader::read), over an input already cut off at the
    /// document ceiling.
    fn read_within(&self, input: &mut dyn BufRead) -> Result<ScanReport, ImportError> {
        crate::import::skip_bom(input)?;

        let max_hosts = self.options.limits.max_addresses;
        // A host record is as long as its port list, megabytes for a full-range
        // host, so the document ceiling bounds lines. The target readers' line
        // limit would refuse any host past a few hundred ports.
        let max_line_bytes = usize::try_from(self.options.max_document_bytes).unwrap_or(usize::MAX);
        let mut buffer = Vec::new();
        let mut line_number = 0u64;
        let mut header: Option<HeaderDto> = None;
        let mut hosts: Vec<Host> = Vec::new();

        loop {
            buffer.clear();
            line_number += 1;
            let origin = ImportOrigin::line(line_number);

            if !crate::import::list::read_line(input, &mut buffer, max_line_bytes, origin)? {
                break;
            }

            let text =
                std::str::from_utf8(&buffer).map_err(|_| ImportError::InvalidUtf8 { origin })?;
            if text.trim().is_empty() {
                continue;
            }

            let record = LineRecord::parse(text).map_err(|error| ImportError::Malformed {
                format: LINES_FORMAT,
                origin,
                message: error.to_string(),
            })?;

            match record {
                // Accepted anywhere in the file, so files can be split, filtered
                // and concatenated. A second one is refused: one file is one scan.
                LineRecord::Report(next) => {
                    if header.is_some() {
                        return Err(ImportError::Malformed {
                            format: LINES_FORMAT,
                            origin,
                            message: format!(
                                "a second '{REPORT_RECORD}' record; one file describes one scan"
                            ),
                        });
                    }
                    header = Some(*next);
                }
                LineRecord::Host(dto) => {
                    if hosts.len() as u128 >= max_hosts {
                        return Err(ImportError::TooManyHosts { limit: max_hosts });
                    }
                    let host = dto.into_host().map_err(|message| ImportError::Malformed {
                        format: LINES_FORMAT,
                        origin,
                        message,
                    })?;
                    hosts.push(host);
                }
                // Skipped so a newer engine's output stays readable.
                LineRecord::Unknown => {}
            }
        }

        let Some(header) = header else {
            return Err(ImportError::Malformed {
                format: LINES_FORMAT,
                origin: ImportOrigin::unknown(),
                message: format!(
                    "no '{REPORT_RECORD}' record: this is not output {ENGINE_NAME} wrote"
                ),
            });
        };

        Document {
            schema_version: header.schema_version,
            engine: header.engine,
            produced_by: header.produced_by,
            phases: header.phases,
            hosts,
        }
        .into_report(LINES_FORMAT)
    }
}

/// One line of a record-per-line document, told apart by its `type`.
#[derive(Debug)]
enum LineRecord {
    /// The header, which carries everything the document says about the scan.
    Report(Box<HeaderDto>),
    /// One host, whose fields are the document's host object exactly.
    Host(Box<HostDto>),
    /// A record kind this build does not know.
    Unknown,
}

impl LineRecord {
    /// Reads one line: its `type` first, then the whole of it as the record
    /// that names.
    ///
    /// Two passes, because serde's derived tagged enum buffers the whole record
    /// as a generic value tree before choosing a variant. For a full-range host
    /// that costs several times the line, and repeated entries are all kept
    /// before [`PortsDto`] can fold them. The first pass keeps only the tag.
    fn parse(text: &str) -> serde_json::Result<Self> {
        let LineKind { kind } = serde_json::from_str(text)?;
        Ok(match kind.as_str() {
            REPORT_RECORD => Self::Report(serde_json::from_str(text)?),
            HOST_RECORD => Self::Host(serde_json::from_str(text)?),
            _ => Self::Unknown,
        })
    }
}

/// The one field [`LineRecord::parse`] reads before it knows what a line is.
#[derive(Deserialize)]
struct LineKind {
    #[serde(rename = "type")]
    kind: String,
}

/// What a record-per-line document states once, in its `report` record: every
/// field of the single document except the hosts.
#[derive(Debug, Deserialize)]
struct HeaderDto {
    schema_version: u32,
    engine: EngineDto,
    #[serde(default)]
    produced_by: Option<String>,
    #[serde(default)]
    phases: Vec<PhaseDto>,
}

/// A parse failure, placed in the file where `serde_json` says it happened.
fn malformed(format: &'static str, error: &serde_json::Error) -> ImportError {
    ImportError::Malformed {
        format,
        origin: ImportOrigin::line(error.line() as u64),
        message: error.to_string(),
    }
}

// ---------------------------------------------------------------------------
// The document root
//
// Hand-written so hosts are converted as the array is parsed.
// ---------------------------------------------------------------------------

/// The document, with its hosts already rebuilt.
struct Document {
    schema_version: u32,
    engine: EngineDto,
    /// What produced the findings, as that scanner attributed itself.
    ///
    /// Absent from documents written before the field existed, where
    /// `engine.version` carried it. See [`Document::into_report`].
    produced_by: Option<String>,
    phases: Vec<PhaseDto>,
    hosts: Vec<Host>,
}

impl Document {
    /// The report this document describes.
    fn into_report(self, format: &'static str) -> Result<ScanReport, ImportError> {
        if self.schema_version > SCHEMA_VERSION {
            return Err(refuse(
                format,
                format!(
                    "schema version {} is past version {SCHEMA_VERSION}, which is the highest \
                     this build understands; its fields may mean something else",
                    self.schema_version
                ),
            ));
        }

        if self.engine.name != ENGINE_NAME {
            return Err(refuse(
                format,
                format!(
                    "the document names engine '{}' rather than '{ENGINE_NAME}'",
                    self.engine.name
                ),
            ));
        }

        let phases: Vec<ScanPhase> = self
            .phases
            .into_iter()
            .map(|phase| phase.record().map(|record| ScanPhase::from(&record)))
            .collect::<Result<_, _>>()
            .map_err(|message| refuse(format, message))?;

        // In documents without `produced_by`, `engine.version` holds the
        // attribution.
        let produced_by = self.produced_by.unwrap_or(self.engine.version);

        Ok(ScanReport::recorded(produced_by, phases, self.hosts))
    }
}

/// A refusal about the document as a whole, which has no one line to point at.
fn refuse(format: &'static str, message: String) -> ImportError {
    ImportError::Malformed {
        format,
        origin: ImportOrigin::unknown(),
        message,
    }
}

/// Reads the document under a ceiling on how many hosts it may name.
///
/// A seed, since the ceiling has to reach the `hosts` array while it is being
/// walked, before the allocation it bounds.
struct DocumentSeed<'a> {
    max_hosts: u128,
    /// Set when the ceiling was passed, so the real error survives `serde`'s
    /// error type.
    overrun: &'a Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for DocumentSeed<'_> {
    type Value = Document;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Document, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for DocumentSeed<'_> {
    type Value = Document;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a zond scan report")
    }

    /// A repeated key assigns again, so the last one wins: a document carrying one
    /// host and then a second `"hosts":[]` reads back with none. This matches
    /// serde's behaviour for the derived DTOs below. JSON leaves duplicates
    /// unspecified.
    ///
    /// The XML reader's `Element::value` takes the first of a repeated attribute.
    /// Both rules are deterministic, and neither format's specification picks one.
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut schema_version = None;
        let mut engine = None;
        let mut produced_by = None;
        let mut phases = Vec::new();
        let mut hosts = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "schema_version" => schema_version = Some(map.next_value()?),
                "engine" => engine = Some(map.next_value()?),
                "produced_by" => produced_by = Some(map.next_value()?),
                "phases" => phases = map.next_value()?,
                // The only key whose size grows with the scan.
                "hosts" => {
                    hosts = Some(map.next_value_seed(HostsSeed {
                        max_hosts: self.max_hosts,
                        overrun: self.overrun,
                    })?);
                }
                // The summary, totals and partial flag are derived from what is
                // read here; trusting them could report counts the hosts disagree
                // with.
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
            // Required: a JSON lines file's first line is a complete object with
            // `schema_version` and `engine`, and defaulting `hosts` would read it
            // as an empty report. An empty scan writes `"hosts": []`.
            hosts: hosts.ok_or_else(|| de::Error::missing_field("hosts"))?,
        })
    }
}

/// The hosts array, rebuilt one element at a time and bounded as it goes.
struct HostsSeed<'a> {
    max_hosts: u128,
    overrun: &'a Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for HostsSeed<'_> {
    type Value = Vec<Host>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Vec<Host>, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for HostsSeed<'_> {
    type Value = Vec<Host>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array of hosts")
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Vec<Host>, S::Error> {
        // No `with_capacity` from the size hint, which an untrusted document
        // chooses.
        let mut hosts: Vec<Host> = Vec::new();

        while let Some(dto) = seq.next_element::<HostDto>()? {
            if hosts.len() as u128 >= self.max_hosts {
                self.overrun.set(true);
                return Err(de::Error::custom("more hosts than the limit allows"));
            }
            hosts.push(dto.into_host().map_err(de::Error::custom)?);
        }

        Ok(hosts)
    }
}

// ---------------------------------------------------------------------------
// Reading the encodings the document uses
// ---------------------------------------------------------------------------

/// An RFC 3339 timestamp, the only form a time takes in the document.
fn timestamp(text: &str) -> Result<SystemTime, String> {
    parse_rfc3339(text).ok_or_else(|| format!("'{text}' is not an RFC 3339 timestamp in UTC"))
}

/// A count written as a decimal string, as the document writes anything that can
/// exceed what a JSON number holds exactly.
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
/// [`record`](crate::record) reads an unknown value leniently, since a journal is
/// written by this engine and covered by its versioning. A document from outside
/// carries no such guarantee, and a port state read as `unasked` because the word
/// was unrecognised would claim something the scan never established.
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
// One per `$defs` entry in the published schema, `#[serde(default)]` throughout
// so a document that omits a known field is still read.
// ---------------------------------------------------------------------------

/// `engine`, which tells a report apart from other JSON with a `hosts` key.
/// `name` is required and checked; `version` is the fallback for a document
/// written before `produced_by` existed.
#[derive(Debug, Deserialize)]
struct EngineDto {
    name: String,
    #[serde(default)]
    version: String,
}

/// One `phases[]` entry: what a scan covered, under what settings, and what went
/// wrong. Everything a [`ScanReport`] knows that is not a host.
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
    refusals: Vec<RefusalDto>,
    probe_stats: Vec<ProbeStatsDto>,
    unroutable: Vec<String>,
    refused_by_route: Vec<String>,
    timed_out: Vec<String>,
    icmp_rate_limited: Vec<String>,
    reached_by_connect: Vec<RangeDto>,
    undecided: Vec<RangeDto>,
    liveness_skipped: Option<String>,
    silent: Vec<RangeDto>,
    stopped: Option<String>,
    passes_cut: Vec<String>,
    unreached: Option<String>,
    unheard_probes: Option<String>,
    origin: Option<PhaseOriginDto>,
    open: bool,
}

/// Which document a phase came from, for a report merged out of several.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PhaseOriginDto {
    label: Option<String>,
    engine_version: String,
}

impl PhaseDto {
    fn record(self) -> Result<PhaseRecord, String> {
        known(wire::scan_kind(&self.kind), "a scan phase", &self.kind)?;
        if let Some(skip) = &self.liveness_skipped {
            known(wire::liveness_skip(skip), "a liveness skip", skip)?;
        }
        if let Some(stopped) = &self.stopped {
            known(wire::stop_reason(stopped), "a stop reason", stopped)?;
        }
        for pass in &self.passes_cut {
            known(wire::pass(pass), "a pass", pass)?;
        }

        Ok(PhaseRecord {
            open: self.open,
            // Dropped: they describe the scanning machine's network, not this one.
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
            refusals: self
                .refusals
                .into_iter()
                .map(RefusalDto::record)
                .collect::<Result<_, _>>()?,
            unroutable: self
                .unroutable
                .iter()
                .map(|ip| address(ip))
                .collect::<Result<_, _>>()?,
            refused_by_route: self
                .refused_by_route
                .iter()
                .map(|ip| address(ip))
                .collect::<Result<_, _>>()?,
            timed_out: self
                .timed_out
                .iter()
                .map(|ip| address(ip))
                .collect::<Result<_, _>>()?,
            icmp_rate_limited: self
                .icmp_rate_limited
                .iter()
                .map(|ip| address(ip))
                .collect::<Result<_, _>>()?,
            reached_by_connect: self
                .reached_by_connect
                .into_iter()
                .map(RangeDto::record)
                .collect::<Result<_, _>>()?,
            undecided: self
                .undecided
                .into_iter()
                .map(RangeDto::record)
                .collect::<Result<_, _>>()?,
            liveness_skipped: self.liveness_skipped,
            silent: self
                .silent
                .into_iter()
                .map(RangeDto::record)
                .collect::<Result<_, _>>()?,
            stopped: self.stopped,
            passes_cut: self.passes_cut,
            unreached: self
                .unreached
                .as_deref()
                .map(count)
                .transpose()?
                .unwrap_or(0),
            unheard_probes: self
                .unheard_probes
                .as_deref()
                .map(count)
                .transpose()?
                .unwrap_or(0),
            probe_stats: self
                .probe_stats
                .into_iter()
                .map(ProbeStatsDto::record)
                .collect::<Result<_, _>>()?,
            origin: self.origin.map(|origin| PhaseOriginRecord {
                label: origin.label,
                engine_version: origin.engine_version,
            }),
        })
    }
}

/// `targets`, what a phase covered. A comparison needs it to tell a narrowed scan
/// from a network that emptied out.
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
            // The document carries interface names without indices, which is an
            // unresolved zone.
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

/// A phase's port coverage as written: the kind of specification and its text,
/// unexpanded. `-` stays `-`.
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

        // An unparseable specification would rebuild as an empty scope, so a
        // comparison could not say an endpoint was probed.
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

/// One address range, as its two ends. Used for both what a phase covered and
/// what it excluded.
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
            // Ranges carry no zone in the document. A link-local sweep's zone is
            // on the host.
            zone: None,
        })
    }
}

/// `settings`, the request a phase ran under.
///
/// A port reported closed by a SYN scan and by a connect scan are different
/// claims, so the settings are read too. Every named value here is checked,
/// including the two records at the end.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SettingsDto {
    send_mode: String,
    tcp_technique: String,
    sctp_technique: String,
    retry: RetryDto,
    max_probe_rate: Option<u32>,
    min_probe_rate: Option<u32>,
    host_probe_interval_us: Option<u64>,
    probe_interval_us: Option<u64>,
    host_timeout_us: Option<u64>,
    scan_timeout_us: Option<u64>,
    dns_enabled: bool,
    redact: bool,
    os_detection: String,
    service_detection: String,
    #[serde(default)]
    detection: String,
    traceroute: bool,
    characterise: bool,
    ip_protocols: Vec<u8>,
    tls_enumeration: bool,
    /// The TCP ports the scan only listened on. Absent in older documents, whose
    /// scans probed every port alike.
    listen_only_ports: Vec<u16>,
    /// The ports the scan sent nothing to, as a port specification. Absent when
    /// it excluded none, and in older documents.
    #[serde(default)]
    excluded_ports: String,
    /// What the scan changed about its packets, absent when it changed nothing.
    /// Deserialized into the journal's own record, then checked by
    /// [`checked_evasion`].
    evasion: Option<EvasionSettingsRecord>,
    /// The zombie a TCP port scan ran through, absent for an ordinary scan.
    /// Checked the same way, by [`checked_idle_scan`].
    idle_scan: Option<IdleScanRecord>,
    /// Whether the capture kept ICMP errors a technique did not need. Absent in
    /// older documents.
    #[serde(default)]
    icmp_evidence: bool,
}

/// Refuses unknown values in the evasion record, per the module's compatibility
/// rules.
///
/// The record layer reads `flags`, `spoof_mac` and `decoys` leniently: an
/// unrecognised flag name contributes nothing, an unparseable decoy is dropped,
/// and a bad `spoof_mac` becomes `None`. Unchecked, a document would silently read
/// back as claiming less than it said; `"syn|nonsense"` would read as `syn`.
fn checked_evasion(evasion: &EvasionSettingsRecord) -> Result<(), String> {
    if let Some(flags) = &evasion.flags {
        known(wire::tcp_flags_checked(flags), "a TCP flag set", flags)?;
    }
    if let Some(mac) = &evasion.spoof_mac {
        known(mac.parse::<MacAddr>().ok(), "a hardware address", mac)?;
    }
    for decoy in &evasion.decoys {
        known(decoy.parse::<IpAddr>().ok(), "an address", decoy)?;
    }
    Ok(())
}

/// [`checked_evasion`] for the idle-scan record. The record layer drops the whole
/// record on an unparseable `zombie`, so a scan that ran through a zombie would
/// read back as one that did not.
fn checked_idle_scan(idle: &IdleScanRecord) -> Result<(), String> {
    known(
        idle.zombie.parse::<IpAddr>().ok(),
        "an address",
        &idle.zombie,
    )
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
        // Empty in older documents and from scanners without an SCTP scan; read
        // as unstated.
        if !self.sctp_technique.is_empty() {
            known(
                self.sctp_technique.parse::<SctpScanTechnique>().ok(),
                "an SCTP scan technique",
                &self.sctp_technique,
            )?;
        }
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
        // Empty in older documents, and read as the default envelope. A present
        // but unrecognised value is refused: it states the ceiling on what the
        // scan was permitted to do, and the default could understate it.
        if !self.detection.is_empty() {
            known(
                wire::detection_class(&self.detection),
                "a detection class",
                &self.detection,
            )?;
        }
        if let Some(evasion) = &self.evasion {
            checked_evasion(evasion)?;
        }
        if let Some(idle) = &self.idle_scan {
            checked_idle_scan(idle)?;
        }
        // Checked like `detection`: read as empty, an unreadable value would say
        // the scan sent to ports it kept out.
        known(
            crate::model::port::PortSet::try_from(self.excluded_ports.as_str()).ok(),
            "a port specification",
            &self.excluded_ports,
        )?;

        Ok(SettingsRecord {
            send_mode: self.send_mode,
            tcp_technique: self.tcp_technique,
            sctp_technique: self.sctp_technique,
            retry_effort: self.retry.effort,
            retry_max_attempts: self.retry.max_attempts,
            retry_timeout_scale: self.retry.timeout_scale,
            retry_dampen_silent_hosts: self.retry.dampen_silent_hosts,
            max_probe_rate: self.max_probe_rate,
            min_probe_rate: self.min_probe_rate,
            host_probe_interval: self.host_probe_interval_us.map(micros),
            probe_interval: self.probe_interval_us.map(micros),
            host_timeout: self.host_timeout_us.map(micros),
            scan_timeout: self.scan_timeout_us.map(micros),
            dns_enabled: self.dns_enabled,
            redact: self.redact,
            os_detection: self.os_detection,
            service_detection: self.service_detection,
            detection: self.detection,
            traceroute: self.traceroute,
            characterise: self.characterise,
            ip_protocols: self.ip_protocols,
            tls_enumeration: self.tls_enumeration,
            listen_only_ports: self.listen_only_ports,
            excluded_ports: self.excluded_ports,
            evasion: self.evasion,
            idle_scan: self.idle_scan,
            icmp_evidence: self.icmp_evidence,
        })
    }
}

/// One entry of `host.ip_protocols`.
///
/// `name` is not read: it is the registry keyword, derived from the number, and
/// reading it would let a foreign document rename GRE.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct IpProtocolDto {
    protocol: u8,
    state: String,
}

/// One `hosts[].names[]` entry: a name the host gave for itself, and the protocol
/// it gave it in. Read as written, so a redacted document's names are its masks.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct NameDto {
    source: String,
    kind: String,
    name: String,
}

/// `settings.retry`, nested here where the record flattens it.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RetryDto {
    effort: String,
    max_attempts: Option<u8>,
    timeout_scale: Option<f64>,
    dampen_silent_hosts: bool,
}

/// One `failures[]` entry: a strategy that did not complete, and when. Tells a
/// network with nothing on it from a scan that never started.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FailureDto {
    scanner: String,
    reason: String,
    at: String,
    cut_short: bool,
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
            cut_short: self.cut_short,
        })
    }
}

/// Ground a phase declined to cover, as a document holds it.
///
/// No timestamp, unlike [`FailureDto`]: a refusal is decided before the phase
/// runs.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RefusalDto {
    scanner: String,
    reason: String,
}

impl RefusalDto {
    fn record(self) -> Result<RefusalRecord, String> {
        known(
            wire::scanner_kind(&self.scanner),
            "a scanner",
            &self.scanner,
        )?;

        Ok(RefusalRecord {
            scanner: self.scanner,
            reason: self.reason,
        })
    }
}

/// One `probe_stats[]` entry: what one scanner sent, saw and concluded.
///
/// Says whether a phase's silence is evidence: a sweep that sent ten thousand
/// probes and saw nothing differs from one whose capture dropped nine thousand
/// frames.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ProbeStatsDto {
    scanner: String,
    targets: String,
    stop_reason: String,
    elapsed_us: u64,
    sends_attempted: u64,
    sends_failed: u64,
    sends_witnessed: u64,
    segments_seen: u64,
    segments_off_target: u64,
    replies_without_rtt: u64,
    refusals_unattributed: u64,
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
            sends_witnessed: self.sends_witnessed,
            segments_seen: self.segments_seen,
            window: self.window.map(WindowDto::record),
            segments_off_target: self.segments_off_target,
            replies_without_rtt: self.replies_without_rtt,
            refusals_unattributed: self.refusals_unattributed,
            hosts_found: self.hosts_found,
            // Both histograms are written one object per bucket, in order, so the
            // counts alone rebuild the vector.
            answered_on: self.answered_on.into_iter().map(|a| a.count).collect(),
            answered_unattributed: self.answered_unattributed,
            first_reply: self.first_reply_us.map(micros),
            last_reply: self.last_reply_us.map(micros),
            found_at: self.found_at.into_iter().map(|b| b.count).collect(),
            capture: self.capture.map(CaptureDto::record),
        })
    }
}

/// One `answered_on[]` entry: how many hosts answered on this attempt number.
/// The position in the array is the attempt; only the count is carried.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AttemptCountDto {
    count: u64,
}

/// One `found_at[]` entry: how many hosts were found in this time bucket. The
/// position in the array is the bucket; only the count is carried.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BucketDto {
    count: u64,
}

/// `capture`, the kernel's account of what the capture saw and dropped.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CaptureDto {
    received: u64,
    dropped: u64,
    if_dropped: u64,
    #[serde(default)]
    stopped_early: u64,
}

impl CaptureDto {
    fn record(self) -> CaptureRecord {
        CaptureRecord {
            received: self.received,
            dropped: self.dropped,
            if_dropped: self.if_dropped,
            stopped_early: self.stopped_early,
        }
    }
}

/// `window`, the in-flight window a scanner finished at, the largest it reached,
/// and whether it backed off.
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
    /// The document carries a `usize` written as `u64`. On a 32-bit build a value
    /// that does not fit is clamped to `usize::MAX`, since truncating `2^32` would
    /// read as a closed window.
    fn record(self) -> WindowRecord {
        WindowRecord {
            capacity: usize::try_from(self.capacity).unwrap_or(usize::MAX),
            peak: usize::try_from(self.peak).unwrap_or(usize::MAX),
            reductions: self.reductions,
            adaptive: self.adaptive,
            at_floor: self.at_floor,
        }
    }
}

// ---------------------------------------------------------------------------
// One host
// ---------------------------------------------------------------------------

/// One `hosts[]` entry: everything a scan concluded about one machine.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct HostDto {
    primary_ip: String,
    ips: IpsDto,
    zone: Option<String>,
    hostname: Option<String>,
    names: Vec<NameDto>,
    status: String,
    reasons: Vec<ReasonDto>,
    roles: Vec<String>,
    filtering: Vec<String>,
    ip_protocols: Vec<IpProtocolDto>,
    os: Option<OsDto>,
    hardware: Option<HardwareDto>,
    telemetry: TelemetryDto,
    ports: PortsDto,
    first_seen: String,
    last_seen: String,
    path: Vec<HopDto>,
    findings: Vec<FindingDto>,
}

impl HostDto {
    /// The host this entry describes.
    ///
    /// Its ports and addresses were rebuilt as the arrays were parsed, so they
    /// join the host directly, bypassing the record.
    fn into_host(mut self) -> Result<Host, String> {
        let ports = std::mem::take(&mut self.ports);
        let ips = std::mem::take(&mut self.ips);
        let mut host = self.record()?.rebuild_with(ports.0.into_values());
        host.adopt_ips(ips.0);
        Ok(host)
    }

    /// Everything but the addresses and ports, which
    /// [`into_host`](Self::into_host) adds already rebuilt.
    fn record(self) -> Result<HostRecord, String> {
        known(
            wire::host_status(&self.status),
            "a host status",
            &self.status,
        )?;
        for name in &self.names {
            known(
                wire::name_source(&name.source),
                "a name source",
                &name.source,
            )?;
            known(wire::name_kind(&name.kind), "a name kind", &name.kind)?;
        }
        for role in &self.roles {
            known(wire::network_role(role), "a network role", role)?;
        }
        for filtering in &self.filtering {
            known(
                wire::filtering(filtering),
                "a filtering conclusion",
                filtering,
            )?;
        }
        for entry in &self.ip_protocols {
            known(
                wire::ip_protocol_state(&entry.state),
                "an IP protocol state",
                &entry.state,
            )?;
        }

        let first_seen = timestamp(&self.first_seen)?;
        let last_seen = timestamp(&self.last_seen)?;

        Ok(HostRecord {
            primary_ip: address(&self.primary_ip)?,
            ips: Vec::new(),
            hostname: self.hostname,
            names: self
                .names
                .into_iter()
                .map(|entry| crate::record::NameRecord {
                    source: entry.source,
                    kind: entry.kind,
                    name: entry.name,
                })
                .collect(),
            status: self.status,
            reasons: self
                .reasons
                .into_iter()
                .map(ReasonDto::record)
                .collect::<Result<_, _>>()?,
            os: self.os.map(OsDto::record),
            // The document carries the verdict only; see the module documentation.
            os_evidence: Vec::new(),
            hardware: maybe(self.hardware, |hardware| hardware.record(last_seen))?,
            // An interface name without an index: an unresolved zone.
            zone: self
                .zone
                .map(|name| crate::record::ZoneRecord { index: None, name }),
            telemetry: self.telemetry.record(),
            path: self
                .path
                .into_iter()
                .map(HopDto::record)
                .collect::<Result<_, _>>()?,
            roles: self.roles,
            filtering: self.filtering,
            // The registry keyword is dropped; it is derived from the number.
            ip_protocols: self
                .ip_protocols
                .into_iter()
                .map(|entry| crate::record::IpProtocolRecord {
                    protocol: entry.protocol,
                    state: entry.state,
                })
                .collect(),
            first_seen,
            last_seen,
            ports: Vec::new(),
            findings: self
                .findings
                .into_iter()
                .map(FindingDto::record)
                .collect::<Result<_, _>>()?,
        })
    }
}

/// `ips[]`, parsed into the set a host keeps as the array is read.
///
/// Like [`PortsDto`], this bounds memory by what the host keeps: each address is
/// parsed straight from the document's bytes into the set, so the array is never
/// held as text or as a list.
#[derive(Debug, Default)]
struct IpsDto(BTreeSet<IpAddr>);

impl<'de> Deserialize<'de> for IpsDto {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(IpsVisitor)
    }
}

/// Reads `ips[]` into an [`IpsDto`].
struct IpsVisitor;

impl<'de> Visitor<'de> for IpsVisitor {
    type Value = IpsDto;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array of addresses")
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<IpsDto, S::Error> {
        let mut ips = BTreeSet::new();
        while let Some(IpDto(ip)) = seq.next_element()? {
            ips.insert(ip);
        }
        Ok(IpsDto(ips))
    }
}

/// One address, parsed from the string the document holds it as.
struct IpDto(IpAddr);

impl<'de> Deserialize<'de> for IpDto {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(IpVisitor)
    }
}

/// Reads one address without holding it as text.
struct IpVisitor;

impl Visitor<'_> for IpVisitor {
    type Value = IpDto;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an IP address")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<IpDto, E> {
        address(text).map(IpDto).map_err(E::custom)
    }
}

/// One `reasons[]` entry: which protocol established a host's status, and from
/// where. `source_withheld` marks evidence a middlebox sent from an address the
/// writing scan was forbidden to report.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ReasonDto {
    protocol: String,
    source_ip: Option<String>,
    source_withheld: bool,
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
            source_withheld: self.source_withheld,
            details: self.details,
        })
    }
}

/// `os`, the operating-system verdict and how sure it is.
///
/// The verdict only; the document does not carry the evidence. See the module
/// documentation.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct OsDto {
    name: String,
    family: Option<String>,
    device: Option<String>,
    generation: Option<String>,
    vendor: Option<String>,
    kernel: Option<String>,
    arch: Option<String>,
    accuracy: u8,
    detail_accuracy: Option<u8>,
    cpes: Vec<String>,
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
            arch: self.arch,
            detail_accuracy: self.detail_accuracy,
            evidence: self.evidence,
            cpes: self.cpes,
        }
    }
}

/// `hardware`, the link-layer addresses a host answered from. Present only when
/// the scan was on the host's segment.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct HardwareDto {
    mac: Option<String>,
    macs: Vec<String>,
    /// A vendor a service named. One derived from the address block is not
    /// written; it is derived again on rebuild.
    vendor: Option<String>,
    product: Option<String>,
    family: Option<String>,
    cpe23: Option<String>,
    model: Option<String>,
    version: Option<String>,
    /// Absent from a redacted document.
    serial_number: Option<String>,
}

impl HardwareDto {
    /// The document does not record when each address was seen, so all are
    /// placed at the host's last sighting, the latest moment any could have been.
    fn record(self, seen: SystemTime) -> Result<HardwareRecord, String> {
        let mut macs: Vec<String> = self.macs;
        if let Some(mac) = self.mac
            && !macs.contains(&mac)
        {
            macs.push(mac);
        }

        Ok(HardwareRecord {
            macs: macs.into_iter().map(|mac| (mac, seen)).collect(),
            vendor: self.vendor,
            product: self.product,
            family: self.family,
            cpe23: self.cpe23,
            model: self.model,
            version: self.version,
            serial_number: self.serial_number,
        })
    }
}

/// `telemetry`, which the schema defines and the exporter leaves empty. Accepted
/// so a document that fills it stays readable.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TelemetryDto {}

impl TelemetryDto {
    /// The document carries round-trip summaries without the samples, so a host
    /// read back reports none. See the module documentation.
    fn record(self) -> TelemetryRecord {
        TelemetryRecord {
            rtts: Vec::new(),
            hop_counter: None,
            rtt_protocol: None,
            rtt_sources: Vec::new(),
        }
    }
}

/// One `path[]` entry: a router between the scanner and the host, at its
/// distance. `inferred` marks a hop taken from a path already measured to a
/// neighbour, and `withheld` one whose router answered from an address the
/// writing scan was forbidden to report.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct HopDto {
    distance: u8,
    address: Option<String>,
    rtt_us: Option<u64>,
    inferred: bool,
    withheld: bool,
}

impl HopDto {
    fn record(self) -> Result<HopRecord, String> {
        Ok(HopRecord {
            distance: self.distance,
            address: maybe(self.address.as_deref(), address)?,
            rtt: self.rtt_us.map(micros),
            inferred: self.inferred,
            withheld: self.withheld,
        })
    }
}

/// A host's `ports[]`, rebuilt as the array is parsed and keyed as the host
/// keys them.
///
/// Converted an entry at a time and folded by endpoint, so a repeated entry
/// updates one port. A full-range host is 65,535 entries; collecting them first
/// would hold them two or three times over. Keyed, a host costs at most the
/// endpoints it can have, however long its array runs.
#[derive(Debug, Default)]
struct PortsDto(BTreeMap<(u16, Protocol), Port>);

impl<'de> Deserialize<'de> for PortsDto {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(PortsVisitor)
    }
}

/// Reads `ports[]` into a [`PortsDto`].
struct PortsVisitor;

impl<'de> Visitor<'de> for PortsVisitor {
    type Value = PortsDto;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array of ports")
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<PortsDto, S::Error> {
        let mut ports = BTreeMap::new();
        while let Some(dto) = seq.next_element::<PortDto>()? {
            let record = dto.record().map_err(de::Error::custom)?;
            // `record` already refused the only entries `rebuild` would skip.
            if let Some(port) = record.rebuild() {
                port::fold(&mut ports, port);
            }
        }
        Ok(PortsDto(ports))
    }
}

/// One `ports[]` entry: what a port was found to be, and what is behind it.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PortDto {
    port: u16,
    protocol: String,
    state: String,
    service: Option<ServiceDto>,
    security: Option<SecurityDto>,
    discovery: Option<DiscoveryDto>,
    findings: Vec<FindingDto>,
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
            port: self.port,
            protocol: self.protocol,
            state: self.state,
            service: self.service.map(ServiceDto::record),
            security: maybe(self.security, SecurityDto::record)?,
            discovery: maybe(self.discovery, DiscoveryDto::record)?,
            findings: self
                .findings
                .into_iter()
                .map(FindingDto::record)
                .collect::<Result<_, _>>()?,
        })
    }
}

/// `service`, what the fingerprinter concluded is listening.
///
/// `confidence` separates a banner that names itself from a guess by port number.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ServiceDto {
    name: String,
    confidence: u8,
    product: Option<String>,
    vendor: Option<String>,
    version: Option<String>,
    extrainfo: Option<String>,
    cpes: Vec<String>,
    build: Option<BuildDto>,
}

/// `service.build`, which distributor's build a reply identified.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BuildDto {
    distributor: String,
    revision: Option<String>,
    release: Option<ReleaseDto>,
}

/// `service.build.release`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ReleaseDto {
    name: String,
    basis: String,
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
            cpes: self.cpes,
            build: self.build.map(BuildDto::record),
        }
    }
}

/// A finding on a host or a port.
///
/// The document flattens the detection's identity into the finding; the record
/// keeps it as a [`DetectionIdRecord`].
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FindingDto {
    id: String,
    version: String,
    content_hash: String,
    title: String,
    severity: String,
    confidence: String,
    class: String,
    excerpt: Option<String>,
    references: Vec<ReferenceDto>,
    remediation: Option<String>,
    cpe: Option<String>,
    cpes: Vec<String>,
    subject: Option<String>,
    build: Option<BuildDto>,
    advised_by: Option<StampDto>,
    exploited: Option<ExploitedDto>,
    group: Option<GroupDto>,
}

/// `finding.group`, the detections that together cover one weakness.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct GroupDto {
    id: String,
    summary: String,
}

/// A dataset's stamp: `finding.advised_by`, the advisory data a correlation
/// consulted, and the list `finding.exploited` names.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct StampDto {
    id: String,
    version: String,
    content_hash: String,
}

/// `finding.exploited`, which of its vulnerabilities a list names exploited.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ExploitedDto {
    by: StampDto,
    cves: Vec<String>,
}

impl BuildDto {
    fn record(self) -> BuildRecord {
        BuildRecord {
            distributor: self.distributor,
            revision: self.revision,
            release: self.release.map(|release| ReleaseRecord {
                name: release.name,
                basis: release.basis,
            }),
        }
    }
}

impl FindingDto {
    /// Rebuilds one finding, refusing a severity, confidence or class this build
    /// does not know.
    ///
    /// [`FindingRecord::rebuild`](crate::record::FindingRecord::rebuild) reads an
    /// unknown name in any of the three leniently, which is wrong here for the
    /// reason [`known`] gives: a `critical` finding with an unrecognised severity
    /// would arrive as `info`, and a comparison would report it as downgraded.
    fn record(self) -> Result<FindingRecord, String> {
        known(wire::severity(&self.severity), "a severity", &self.severity)?;
        known(
            wire::confidence(&self.confidence),
            "a confidence",
            &self.confidence,
        )?;
        known(
            wire::detection_class(&self.class),
            "a detection class",
            &self.class,
        )?;

        Ok(FindingRecord {
            detection: DetectionIdRecord {
                id: self.id,
                version: self.version,
                content_hash: self.content_hash,
            },
            title: self.title,
            severity: self.severity,
            confidence: self.confidence,
            class: self.class,
            excerpt: self.excerpt,
            references: self
                .references
                .into_iter()
                .map(ReferenceDto::record)
                .collect(),
            remediation: self.remediation,
            cpe: self.cpe,
            cpes: self.cpes,
            subject: self.subject,
            build: self.build.map(BuildDto::record),
            advised_by: self.advised_by.map(|advised| DetectionIdRecord {
                id: advised.id,
                version: advised.version,
                content_hash: advised.content_hash,
            }),
            exploited: self.exploited.map(|exploited| ExploitationRecord {
                by: DetectionIdRecord {
                    id: exploited.by.id,
                    version: exploited.by.version,
                    content_hash: exploited.by.content_hash,
                },
                cves: exploited.cves,
            }),
            // A group missing its id or summary is dropped, as the record layer
            // does, and the finding is kept.
            group: self.group.and_then(|group| {
                (!group.id.trim().is_empty() && !group.summary.trim().is_empty()).then_some(
                    FindingGroupRecord {
                        id: group.id,
                        summary: group.summary,
                    },
                )
            }),
        })
    }
}

/// One reference a finding cites.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ReferenceDto {
    kind: String,
    value: String,
}

impl ReferenceDto {
    /// Unlike every other named value here, a reference's kind is not checked.
    ///
    /// [`ReferenceRecord::rebuild`](crate::record::ReferenceRecord::rebuild)
    /// drops a reference it cannot rebuild and keeps the finding. Losing a citation
    /// costs one link, and dropping it makes no claim the document did not make.
    fn record(self) -> ReferenceRecord {
        ReferenceRecord {
            kind: self.kind,
            value: self.value,
        }
    }
}

/// `security`, what a TLS handshake settled on. Absent for a port that speaks no
/// TLS, which differs from one whose handshake failed.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SecurityDto {
    tls_version: Option<String>,
    cipher_suite: Option<String>,
    alpn: Vec<String>,
    certificate: Option<CertificateDto>,
    accepts: Vec<AcceptedVersionDto>,
    unfinished: Vec<UnfinishedVersionDto>,
}

impl SecurityDto {
    fn record(self) -> Result<SecurityRecord, String> {
        Ok(SecurityRecord {
            tls_version: self.tls_version,
            cipher_suite: self.cipher_suite,
            alpn: self.alpn,
            certificate: maybe(self.certificate, CertificateDto::record)?,
            accepts: self
                .accepts
                .into_iter()
                .map(AcceptedVersionDto::record)
                .collect::<Result<_, _>>()?,
            unfinished: self
                .unfinished
                .into_iter()
                .map(UnfinishedVersionDto::record)
                .collect::<Result<_, _>>()?,
        })
    }
}

/// `security.unfinished`, the versions whose enumeration did not finish.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct UnfinishedVersionDto {
    version: String,
    interruption: String,
}

impl UnfinishedVersionDto {
    fn record(self) -> Result<UnfinishedVersionRecord, String> {
        known(
            self.version.parse::<TlsVersion>().ok(),
            "a TLS version",
            &self.version,
        )?;
        known(
            Interruption::from_name(&self.interruption),
            "a reason an enumeration was interrupted",
            &self.interruption,
        )?;
        Ok(UnfinishedVersionRecord {
            version: self.version,
            interruption: self.interruption,
        })
    }
}

/// `security.accepts`, what an enumeration established the endpoint accepts.
///
/// The exported form names each suite and gives its number in hex. Only the
/// number, which is what the server sent, is read back; names can differ between
/// builds.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AcceptedVersionDto {
    version: String,
    suites: Vec<AcceptedSuiteDto>,
    unrecognised: Vec<String>,
}

impl AcceptedVersionDto {
    fn record(self) -> Result<AcceptedVersionRecord, String> {
        known(
            self.version.parse::<TlsVersion>().ok(),
            "a TLS version",
            &self.version,
        )?;
        Ok(AcceptedVersionRecord {
            version: self.version,
            suites: self
                .suites
                .into_iter()
                .map(|suite| hex_code(&suite.code))
                .collect::<Result<_, _>>()?,
            unrecognised: self
                .unrecognised
                .iter()
                .map(|code| hex_code(code))
                .collect::<Result<_, _>>()?,
        })
    }
}

/// One entry of `security.accepts[].suites`. Only the number is read; see
/// [`AcceptedVersionDto`].
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AcceptedSuiteDto {
    code: String,
}

/// A cipher suite number as the schema writes it: `0x` and four hex digits.
fn hex_code(text: &str) -> Result<u16, String> {
    text.strip_prefix("0x")
        .and_then(|digits| u16::from_str_radix(digits, 16).ok())
        .ok_or_else(|| format!("'{text}' is not a cipher suite number"))
}

/// `certificate`, the presented leaf as the scan read it.
///
/// Every string here is chosen by the scanned host. It is carried across as is;
/// the writers that render it escape it.
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
            fingerprint_sha256: self.fingerprint_sha256,
            pubkey_type: self.pubkey_type,
            pubkey_bits: self.pubkey_bits,
        })
    }
}

/// `discovery`, how a port's state was established: which probe drew the answer,
/// when, and what the reply's headers said. The per-port counterpart of a host's
/// `reasons`.
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
    /// Every call builds a fresh fixture with fresh timestamps, so a test comparing
    /// a report with its own round trip must use [`round_trip`].
    fn exported() -> String {
        write(&crate::export::fixture::report())
    }

    /// Compact, explicitly: several tests search the document for exact spellings
    /// such as `"state":"open"`, which the default indented writer spaces out.
    fn write(report: &ScanReport) -> String {
        let mut out = Vec::new();
        JsonExporter::new(crate::export::ExportOptions::new())
            .compact()
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

    fn read_lines(document: &str) -> Result<ScanReport, ImportError> {
        JsonLinesReportReader::default().read(&mut Cursor::new(document))
    }

    /// The intrusiveness ceiling the fixture's settings record, spelled as the
    /// document spells it.
    fn fixture_detection_ceiling() -> String {
        crate::record::wire::detection_ceiling_name(
            crate::export::fixture::report().phases()[0]
                .settings()
                .detection
                .ceiling(),
        )
        .to_owned()
    }

    /// Replaces one value in the exported document, asserting it was there.
    fn with_value(document: &str, from: &str, to: &str) -> String {
        assert!(document.contains(from), "the fixture does not carry {from}");
        document.replacen(from, to, 1)
    }

    // ─── A host's addresses ──────────────────────────────────────────────────

    /// A host's `ips` come back as a set, with the document's timestamps, and an
    /// entry that is no address refuses the document naming it.
    #[test]
    fn a_hosts_addresses_read_back_as_a_set_and_a_bad_one_is_named() {
        let document = |ips: &str| {
            format!(
                r#"{{"schema_version":1,"engine":{{"name":"{ENGINE_NAME}"}},"hosts":[{{"primary_ip":"192.0.2.1","ips":[{ips}],"status":"up","first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-01-02T00:00:00Z"}}]}}"#
            )
        };

        let report = read(&document(r#""192.0.2.1","2001:db8::1","192.0.2.1""#))
            .expect("a host with a repeated address reads");
        let host = report.hosts().next().expect("the host");
        let ips: Vec<String> = host.ips().iter().map(ToString::to_string).collect();
        assert_eq!(ips, ["192.0.2.1", "2001:db8::1"]);
        assert_eq!(
            host.last_seen(),
            parse_rfc3339("2026-01-02T00:00:00Z").expect("a timestamp"),
            "joining the addresses must not move when the host was last seen"
        );

        let error = read(&document(r#""192.0.2.1","192.0.2.300""#))
            .expect_err("an entry that is no address reads");
        assert!(
            error
                .to_string()
                .contains("'192.0.2.300' is not an IP address"),
            "the refusal has to name the entry, said: {error}"
        );
    }

    // ─── Names this build cannot place ───────────────────────────────────────

    /// A severity, confidence or class this build does not recognise refuses the
    /// document. See [`FindingDto::record`].
    #[test]
    fn a_finding_naming_a_severity_this_build_cannot_place_is_refused() {
        let document = exported();

        for (from, to, what) in [
            (
                r#""severity":"critical""#,
                r#""severity":"catastrophic""#,
                "a severity",
            ),
            (
                r#""confidence":"weak""#,
                r#""confidence":"settled""#,
                "a confidence",
            ),
            (
                r#""class":"passive""#,
                r#""class":"active_reckless""#,
                "a detection class",
            ),
        ] {
            let broken = with_value(&document, from, to);
            let error = read(&broken).expect_err("the name is not one this build knows");

            match error {
                ImportError::Malformed { message, .. } => assert!(
                    message.contains(what),
                    "the refusal has to say what it could not place, said: {message}"
                ),
                other => panic!("expected a malformed document, got {other:?}"),
            }
        }
    }

    /// An unrecognised detection ceiling refuses the document.
    #[test]
    fn a_phase_naming_a_detection_ceiling_this_build_cannot_place_is_refused() {
        let document = exported();
        let ceiling = fixture_detection_ceiling();
        let broken = with_value(
            &document,
            &format!(r#""detection":"{ceiling}""#),
            r#""detection":"active_reckless""#,
        );

        assert!(matches!(read(&broken), Err(ImportError::Malformed { .. })));
    }

    /// Unrecognised values in the evasion and idle-scan records refuse the
    /// document. See [`checked_evasion`] and [`checked_idle_scan`].
    #[test]
    fn an_evasion_setting_this_build_cannot_place_refuses_the_document() {
        let document = exported();

        for (from, to) in [
            (r#""flags":"syn|fin""#, r#""flags":"nonsense""#),
            (r#""flags":"syn|fin""#, r#""flags":"syn|nonsense""#),
            (
                r#""spoof_mac":"de:ad:be:ef:00:01""#,
                r#""spoof_mac":"zz:zz:zz:zz:zz:zz""#,
            ),
            (
                r#""decoys":["192.0.2.61","192.0.2.62"]"#,
                r#""decoys":["192.0.2.61","not-an-address"]"#,
            ),
            (r#""zombie":"192.0.2.9""#, r#""zombie":"not-an-address""#),
        ] {
            let broken = with_value(&document, from, to);
            assert!(
                matches!(read(&broken), Err(ImportError::Malformed { .. })),
                "{to} was read rather than refused"
            );
        }

        // The unmodified fixture still reads.
        let _ = read(&document).expect("the fixture's own evasion record is valid");
    }

    /// An absent `detection`, as in older documents, reads as the default.
    #[test]
    fn a_document_predating_the_detection_ceiling_still_reads() {
        let ceiling = fixture_detection_ceiling();
        let document = exported().replacen(&format!(r#""detection":"{ceiling}","#), "", 1);

        let _ = read(&document).expect("an older document is not a broken one");
    }

    /// A document without `cut_short` markers reads every entry as a failure.
    #[test]
    fn a_document_predating_the_cut_short_marker_reads_every_entry_as_a_failure() {
        let document = with_value(&exported(), r#","cut_short":true"#, "");

        let report = read(&document).expect("an older document is not a broken one");

        let failures: Vec<_> = report.failures().collect();
        assert_eq!(failures.len(), 2, "both entries are kept");
        assert!(failures.iter().all(|failure| !failure.is_cut_short()));
    }

    // ─── The record-per-line shape ───────────────────────────────────────────

    /// A record-per-line export read back as the report it was written from.
    #[test]
    fn a_record_per_line_export_reads_back_as_the_scan_it_records() {
        use crate::export::JsonLinesExporter;

        let original = crate::export::fixture::report();
        let mut out = Vec::new();
        JsonLinesExporter::default()
            .export(&original, &mut out)
            .expect("the fixture exports");
        let document = String::from_utf8(out).expect("valid UTF-8");

        let restored = read_lines(&document).expect("a readable document");

        assert_eq!(restored.host_count(), original.host_count());
        assert_eq!(restored.phases().len(), original.phases().len());
        assert_eq!(restored.engine_version(), original.engine_version());
        assert!(
            ScanDiff::between(&original, &restored).is_empty(),
            "a record-per-line round trip has to describe the same network"
        );
    }

    /// The single-document reader refuses a record-per-line file, whose first
    /// line alone would parse as an empty report.
    #[test]
    fn the_document_reader_refuses_a_record_per_line_file() {
        use crate::export::JsonLinesExporter;

        let mut out = Vec::new();
        JsonLinesExporter::default()
            .export(&crate::export::fixture::report(), &mut out)
            .expect("the fixture exports");
        let document = String::from_utf8(out).expect("valid UTF-8");

        match read(&document) {
            Err(ImportError::Malformed { message, .. }) => assert!(
                message.contains("hosts"),
                "the refusal should name what was missing, said: {message}"
            ),
            Ok(report) => panic!(
                "read a record-per-line file as a document of {} hosts",
                report.host_count()
            ),
            other => panic!("expected a malformed document, got {other:?}"),
        }
    }

    /// A record-per-line file without a `report` record is refused.
    #[test]
    fn a_record_per_line_file_with_no_report_record_is_refused() {
        let error = read_lines(r#"{"type":"host","primary_ip":"198.51.100.1"}"#)
            .expect_err("a file of hosts alone describes no scan");

        assert!(matches!(error, ImportError::Malformed { .. }));
    }

    /// One file describes one scan, so a second header is refused.
    #[test]
    fn a_second_report_record_is_refused() {
        use crate::export::JsonLinesExporter;

        let mut out = Vec::new();
        JsonLinesExporter::default()
            .export(&crate::export::fixture::report(), &mut out)
            .expect("the fixture exports");
        let document = String::from_utf8(out).expect("valid UTF-8");
        let header = document.lines().next().expect("a header").to_string();

        let doubled = format!("{document}{header}\n");
        let error = read_lines(&doubled).expect_err("two headers describe two scans");

        match error {
            ImportError::Malformed { message, .. } => {
                assert!(message.contains("second"), "said: {message}");
            }
            other => panic!("expected a malformed document, got {other:?}"),
        }
    }

    /// A record kind this build does not know is skipped, so a newer engine's
    /// output stays readable.
    #[test]
    fn a_record_kind_this_build_does_not_know_is_skipped() {
        use crate::export::JsonLinesExporter;

        let mut out = Vec::new();
        JsonLinesExporter::default()
            .export(&crate::export::fixture::report(), &mut out)
            .expect("the fixture exports");
        let document = String::from_utf8(out).expect("valid UTF-8");

        let extended = format!("{document}{{\"type\":\"annotation\",\"note\":\"hello\"}}\n");
        let restored = read_lines(&extended).expect("an unknown record is not a broken file");

        assert_eq!(
            restored.host_count(),
            crate::export::fixture::report().host_count()
        );
    }

    /// A report written out and read back describes the same network.
    ///
    /// Asserted through [`ScanDiff`], so any field the reader drops shows up as a
    /// change.
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
            assert!(
                read_back.names().eq(host.names()),
                "the names a host gave for itself survive"
            );
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

    /// A path reads back hop for hop, each hop the kind it was written as.
    ///
    /// A diff compares no paths, so this is checked separately. A silent hop and
    /// a withheld one both write a `null` address and differ only in the flag
    /// beside it; dropping the flag would turn a withheld router into a silent one.
    #[test]
    fn a_path_reads_back_hop_for_hop() {
        let (original, restored) = round_trip();

        for host in original.hosts() {
            let read_back = restored
                .host(&host.primary_ip())
                .unwrap_or_else(|| panic!("{} is missing", host.primary_ip()));
            assert_eq!(read_back.path(), host.path(), "{}", host.primary_ip());
        }
        assert!(
            original
                .hosts()
                .any(|host| host.path().hops().iter().any(|hop| hop.is_withheld())),
            "test premise: the fixture withholds a router"
        );
    }

    /// A host's evidence reads back reason for reason, each from the sender it
    /// was written with.
    ///
    /// Evidence the host sent and evidence from a withheld middlebox both write a
    /// `null` source and differ only in the flag beside it; dropping the flag
    /// would say the host answered where a middlebox did.
    #[test]
    fn a_hosts_evidence_reads_back_with_its_senders() {
        let (original, restored) = round_trip();

        for host in original.hosts() {
            let read_back = restored
                .host(&host.primary_ip())
                .unwrap_or_else(|| panic!("{} is missing", host.primary_ip()));
            assert_eq!(read_back.reasons(), host.reasons(), "{}", host.primary_ip());
        }
        assert!(
            original.hosts().any(|host| host
                .reasons()
                .iter()
                .any(|reason| reason.source.is_withheld())),
            "test premise: the fixture withholds a sender"
        );
    }

    #[test]
    fn the_phases_survive_with_their_scope() {
        let (original, restored) = round_trip();

        assert_eq!(restored.phases().len(), original.phases().len());

        for (before, after) in original.phases().iter().zip(restored.phases()) {
            assert_eq!(after.kind(), before.kind());
            // The document truncates times to whole microseconds, which only
            // ever moves a moment earlier; hence the order of subtraction.
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
            assert_eq!(after.privilege(), before.privilege());
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
            let failures = |phase: &crate::report::ScanPhase| -> Vec<(crate::report::ScannerKind, String, bool)> {
                phase
                    .failures()
                    .iter()
                    .map(|f| (f.scanner(), f.reason().to_owned(), f.is_cut_short()))
                    .collect()
            };
            assert_eq!(
                failures(after),
                failures(before),
                "a failure and work a limit cut short are told apart"
            );
            assert_eq!(after.probe_stats().len(), before.probe_stats().len());
            assert_eq!(
                after.passes_cut(),
                before.passes_cut(),
                "what a stop left of the passes is ground the phase did not cover"
            );
            assert_eq!(
                after.reached_by_connect(),
                before.reached_by_connect(),
                "which of a raw phase's evidence is connect evidence is part of what it covered"
            );
            assert_eq!(
                after.undecided(),
                before.undecided(),
                "what a phase never decided is what keeps it from reading as silence"
            );
            assert_eq!(
                after.liveness_skipped(),
                before.liveness_skipped(),
                "why a phase ran with no liveness pass is what says how to read its hosts"
            );
            assert_eq!(
                after.stopped(),
                before.stopped(),
                "a phase the scan was stopped in says so"
            );
            assert_eq!(
                after.unreached(),
                before.unreached(),
                "the targets a stop left unreached are on no host, only here"
            );
            assert_eq!(
                after.unheard_probes(),
                before.unheard_probes(),
                "the ports asked where nothing answered are on no host, only here"
            );
            assert_eq!(
                after.silent(),
                before.silent(),
                "an address asked and silent is accounted for, not lost"
            );
        }
        assert!(
            original
                .phases()
                .iter()
                .any(|phase| !phase.reached_by_connect().is_empty()),
            "the fixture reaches something by connect, or the check above proves nothing"
        );
        assert!(
            original
                .phases()
                .iter()
                .any(|phase| !phase.undecided().is_empty()),
            "the fixture leaves something undecided, or the check above proves nothing"
        );
        assert!(
            original
                .phases()
                .iter()
                .any(|phase| phase.liveness_skipped().is_some()),
            "the fixture skips a liveness pass, or the check above proves nothing"
        );
    }

    /// A port phase that stood in for a dropped liveness pass keeps, through a
    /// round trip, why it ran alone, the addresses it found silent and what it
    /// asked them, and no host appears at those addresses.
    #[test]
    fn a_silent_address_survives_a_round_trip_and_stays_no_host() {
        use crate::model::ip::range::{IpRange, Ipv4Range};
        use crate::model::port::{Port, PortState, Protocol};
        use crate::report::{LivenessSkip, PhaseParts, ScanKind, ScanPhase, ScanSettings};
        use std::net::{IpAddr, Ipv4Addr};

        let at = |last| Ipv4Addr::new(203, 0, 113, last);
        let mut ips =
            crate::model::parse::ip::to_set(&["203.0.113.0/29"], None, None).expect("a range");
        let phase = ScanPhase::from_parts(PhaseParts {
            open: false,
            attachments: Vec::new(),
            kind: ScanKind::PortScan,
            started_at: std::time::SystemTime::UNIX_EPOCH,
            elapsed: Duration::from_secs(1),
            privilege: Some(crate::system::privilege::Privilege::Raw),
            targets: crate::report::TargetScope::from_ip_set(
                &mut ips,
                &crate::model::exclusion::Exclusions::none(),
            ),
            settings: ScanSettings::from(&crate::ZondConfig::default()),
            failures: Vec::new(),
            refusals: Vec::new(),
            unroutable: Vec::new(),
            refused_by_route: Vec::new(),
            timed_out: Vec::new(),
            icmp_rate_limited: Vec::new(),
            reached_by_connect: Vec::new(),
            undecided: Vec::new(),
            liveness_skipped: Some(LivenessSkip::PortsNoDearer),
            silent: vec![IpRange::V4(Ipv4Range::new(at(5), at(6)).expect("a range"))],
            stopped: None,
            passes_cut: Vec::new(),
            unreached: 0,
            unheard_probes: 2,
            probes: Vec::new(),
            origin: None,
        });
        let mut up = crate::model::host::Host::new(IpAddr::V4(at(1)));
        up.set_status(HostStatus::Up);
        up.add_port(Port::new(443, Protocol::Tcp, PortState::Closed));
        let original = ScanReport::new(phase, [up]);

        let restored = read(&write(&original)).expect("a readable document");

        let phase = &restored.phases()[0];
        assert_eq!(phase.silent(), original.phases()[0].silent());
        assert_eq!(phase.liveness_skipped(), Some(LivenessSkip::PortsNoDearer));
        assert_eq!(phase.unheard_probes(), 2, "what the silent were asked");
        assert_eq!(restored.hosts().count(), 1, "only the host that answered");
    }

    /// An address refused by a route on the scanning host stays marked so through
    /// a round trip and through the journal record, alongside the unreachable
    /// list it belongs to. Without the mark, a reader cannot tell the fix is a
    /// route on the scanning machine.
    #[test]
    fn an_address_refused_by_a_route_survives_a_round_trip() {
        use crate::report::{PhaseParts, ScanKind, ScanPhase, ScanSettings};
        use std::net::{IpAddr, Ipv4Addr};

        let at = |last| IpAddr::V4(Ipv4Addr::new(203, 0, 113, last));
        let mut ips =
            crate::model::parse::ip::to_set(&["203.0.113.0/29"], None, None).expect("a range");
        let phase = ScanPhase::from_parts(PhaseParts {
            open: false,
            attachments: Vec::new(),
            kind: ScanKind::Discovery,
            started_at: std::time::SystemTime::UNIX_EPOCH,
            elapsed: Duration::from_secs(1),
            privilege: Some(crate::system::privilege::Privilege::Raw),
            targets: crate::report::TargetScope::from_ip_set(
                &mut ips,
                &crate::model::exclusion::Exclusions::none(),
            ),
            settings: ScanSettings::from(&crate::ZondConfig::default()),
            failures: Vec::new(),
            refusals: Vec::new(),
            unroutable: vec![at(2), at(3)],
            refused_by_route: vec![at(2)],
            timed_out: Vec::new(),
            icmp_rate_limited: Vec::new(),
            reached_by_connect: Vec::new(),
            undecided: Vec::new(),
            liveness_skipped: None,
            silent: Vec::new(),
            stopped: None,
            passes_cut: Vec::new(),
            unreached: 0,
            unheard_probes: 0,
            probes: Vec::new(),
            origin: None,
        });
        let original = ScanReport::new(phase, []);

        let restored = read(&write(&original)).expect("a readable document");
        assert_eq!(restored.phases()[0].unroutable(), [at(2), at(3)]);
        assert_eq!(restored.phases()[0].refused_by_route(), [at(2)]);

        let recorded = crate::record::PhaseRecord::from(&original.phases()[0]);
        let journalled = serde_json::to_string(&recorded).expect("a record");
        let recorded: crate::record::PhaseRecord =
            serde_json::from_str(&journalled).expect("the record reads back");
        assert_eq!(ScanPhase::from(&recorded).refused_by_route(), [at(2)]);
    }

    /// A phase recorded before it closed stays open through a round trip, and the
    /// report stays partial. Read back closed, it would claim a scan that covered
    /// its ground; see [`ScanPhase::is_open`](crate::report::ScanPhase::is_open).
    #[test]
    fn a_phase_that_never_closed_survives_a_round_trip_open() {
        use crate::report::{PhaseParts, ScanKind, ScanPhase, ScanSettings};

        let mut ips =
            crate::model::parse::ip::to_set(&["203.0.113.0/29"], None, None).expect("a range");
        let phase = ScanPhase::from_parts(PhaseParts {
            open: true,
            attachments: Vec::new(),
            kind: ScanKind::PortScan,
            started_at: std::time::SystemTime::UNIX_EPOCH,
            elapsed: Duration::from_secs(1),
            privilege: Some(crate::system::privilege::Privilege::Raw),
            targets: crate::report::TargetScope::from_ip_set(
                &mut ips,
                &crate::model::exclusion::Exclusions::none(),
            ),
            settings: ScanSettings::from(&crate::ZondConfig::default()),
            failures: Vec::new(),
            refusals: Vec::new(),
            unroutable: Vec::new(),
            refused_by_route: Vec::new(),
            timed_out: Vec::new(),
            icmp_rate_limited: Vec::new(),
            reached_by_connect: Vec::new(),
            undecided: Vec::new(),
            liveness_skipped: None,
            silent: Vec::new(),
            stopped: None,
            passes_cut: Vec::new(),
            unreached: 0,
            unheard_probes: 0,
            probes: Vec::new(),
            origin: None,
        });
        let original = ScanReport::new(phase, []);
        assert!(original.is_partial(), "an open phase is ground not covered");

        let restored = read(&write(&original)).expect("a readable document");
        assert!(restored.phases()[0].is_open());
        assert!(restored.is_partial());
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
    // Compatibility rules
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

    /// A foreign scanner's attribution survives the round trip in `produced_by`,
    /// separate from `engine`, which names the writer of the file.
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

    /// A document without `produced_by` reads `engine.version` as the attribution.
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
        // Missing `schema_version` is what marks other JSON with a `hosts` key.
        let error = read(r#"{"hosts": []}"#).expect_err("refused");
        assert!(error.to_string().contains("schema_version"), "{error}");

        let error = read(r#"{"schema_version":1,"hosts":[]}"#).expect_err("refused");
        assert!(error.to_string().contains("engine"), "{error}");
    }

    // -----------------------------------------------------------------------
    // Comparing against a later scan
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

    /// Findings survive the round trip.
    ///
    /// Counted directly, because [`ScanDiff`] does not compare findings and the
    /// diff-based round-trip test would miss their loss.
    #[test]
    fn every_finding_survives_the_round_trip() {
        let (original, restored) = round_trip();

        let count = |report: &ScanReport| -> (usize, usize) {
            (
                report.hosts().map(|host| host.findings().count()).sum(),
                report
                    .hosts()
                    .flat_map(|host| host.ports())
                    .map(|port| port.findings().count())
                    .sum(),
            )
        };

        let (hosts_before, ports_before) = count(&original);
        let (hosts_after, ports_after) = count(&restored);

        assert!(
            hosts_before + ports_before > 0,
            "the fixture must carry a finding for this to test anything"
        );
        assert_eq!(
            (hosts_before, ports_before),
            (hosts_after, ports_after),
            "host findings {hosts_before} -> {hosts_after}, port findings \
             {ports_before} -> {ports_after}"
        );
    }

    /// A correlation comes back naming the identifier it was drawn from.
    ///
    /// A merge uses the identifier to decide whether to carry a correlation past
    /// a newer identification. Without it, every archived correlation would
    /// outlive the service version it was drawn from.
    #[test]
    fn a_correlation_keeps_the_identifier_it_was_drawn_from() {
        let (original, restored) = round_trip();

        let identifiers = |report: &ScanReport| -> Vec<(String, String)> {
            report
                .hosts()
                .flat_map(|host| host.ports())
                .flat_map(|port| port.findings())
                .flat_map(|finding| {
                    finding
                        .cpes()
                        .map(|cpe| (finding.title().to_owned(), cpe.to_owned()))
                        .collect::<Vec<_>>()
                })
                .collect()
        };

        assert!(
            !identifiers(&original).is_empty(),
            "the fixture must carry a correlation for this to test anything"
        );
        assert_eq!(identifiers(&restored), identifiers(&original));
    }
}
