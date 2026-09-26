// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The model, as data that can be written down and read back
//!
//! [`model`](crate::model) holds the domain: types with invariants, private
//! fields, and no opinion about serialization. This module is the same
//! information in a shape that survives a file.
//!
//! ## Why the model does not do this itself
//!
//! Deriving `serde` on [`Host`] and its neighbours would be two lines a type and
//! would be wrong in four ways. It welds the on-disk format to the struct layout,
//! so renaming a field breaks every file ever written. It bypasses the invariants
//! the constructors maintain, so a rebuilt host can have an `open_port_count`
//! that disagrees with its ports. It makes `Serialize` public API that cannot be
//! withdrawn. And it does not compile:
//! [`RttSample`](crate::model::host::telemetry::RttSample) carries an
//! [`Instant`](std::time::Instant), which `serde` declines to serialize since a
//! monotonic instant means nothing outside the process that read it.
//!
//! So the conversion lives here instead. Reading uses the model's getters and
//! rebuilding uses its constructors, which means a rebuilt value passed through
//! the same checks a scanned one did.
//!
//! ## What does not survive
//!
//! - **Round-trip time samples.** Their timestamps are monotonic
//!   [`Instant`](std::time::Instant)s, comparable only within one process. A
//!   rebuilt host keeps its summary statistics through the samples' durations and
//!   starts its history fresh.
//! - **Nothing else.** Every other field round-trips, and
//!   `a_fully_populated_host_survives_a_round_trip` keeps that true as the model
//!   grows.
//!
//! ## These are not `#[non_exhaustive]`
//!
//! Almost everything else public in this crate is, and it stops here because of
//! what these types are for. A record is interchange: something builds one to
//! hand over, and a struct literal naming every field is how that is written
//! down. Sealing them would trade a compile error for a caller who adds a field
//! against a builder per type for a caller who wants to state one.
//!
//! The cost is accepted. A field added here is a breaking change, and five of the
//! ones below arrived that way. What buys it back is that the serialized shape is
//! versioned where it matters, by
//! [`JOURNAL_VERSION`](crate::journal::JOURNAL_VERSION) for a journal and
//! [`SCHEMA_VERSION`](crate::format::SCHEMA_VERSION) for a report, so a reader is
//! told when a document has moved.
//!
//! ## Who uses it
//!
//! [`journal`](crate::journal) writes findings as a scan produces them and reads
//! them back to continue one. A differ over two scans wants the same reader, and
//! so would an importer richer than [`import::json`](crate::import), which is
//! narrow on purpose. Sitting beside the model rather than inside any one of them
//! is what lets all three share it.

pub mod wire;

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::config::DetectionEnvelope;
use crate::config::{IdleScan, RetryConfig, TimeoutScale};
use crate::info;
use crate::model::capture::CaptureCounts;
use crate::model::confidence::Confidence;
use crate::model::finding::{
    DetectionClass, DetectionId, Excerpt, Finding, Reference, Severity, Version,
};
use crate::model::host::os::OsFingerprint;
use crate::model::host::path::Hop;
use crate::model::host::telemetry::HostTelemetry;
use crate::model::host::{
    EvidenceSource, HardwareInfo, Host, HostName, IpProtocolState, StatusProtocol, StatusReason,
};
use crate::model::host::{OsEvidence, OsSource};
use crate::model::ip::range::{IpRange, Ipv4Range, Ipv6Range};
use crate::model::ip::scoped::Zone;
use crate::model::ip::set::IpSet;
use crate::model::mac::MacAddr;
use crate::model::port::discovery::{Discovery, ScanResponse};
use crate::model::port::security::{CertificateInfo, Security};
use crate::model::port::{Port, PortSet, PortState, Service};
use crate::model::target::{TargetMap, TargetSet};
use crate::model::tls::{
    CipherSuite, Interruption, TlsSupport, TlsVersion, UnfinishedVersion, VersionSupport,
};
use crate::report::ScannerKind;
use crate::report::WindowSummary;
use crate::report::{
    Attachment, AttachmentSource, EvasionRecord, PhaseOrigin, PhaseParts, PortScope, ProbeStats,
    ProbeStatsParts, Refusal, ScanKind, ScanPhase, ScanSettings, ScannerFailure, ScopeParts,
    StopReason, TargetScope,
};
use crate::system::privilege::Privilege;
use std::num::{NonZeroU8, NonZeroU32};

/// One host, as a file holds it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostRecord {
    /// The address this host is reported under.
    pub primary_ip: IpAddr,
    /// Every address it is known to answer at, the primary included.
    #[serde(default)]
    pub ips: Vec<IpAddr>,
    /// Its resolved name, if one was found.
    #[serde(default)]
    pub hostname: Option<String>,
    /// The names it gave for itself, in the order the model holds them.
    #[serde(default)]
    pub names: Vec<NameRecord>,
    /// Whether it answered, by wire name.
    pub status: String,
    /// What the status rests on.
    #[serde(default)]
    pub reasons: Vec<StatusReasonRecord>,
    /// What it was identified as running.
    #[serde(default)]
    pub os: Option<OsRecord>,
    /// What each source concluded about the operating system, kept so that a
    /// later source can corroborate an earlier one.
    #[serde(default)]
    pub os_evidence: Vec<OsEvidenceRecord>,
    /// Its hardware address and vendor, where the link layer reached it.
    #[serde(default)]
    pub hardware: Option<HardwareRecord>,
    /// The interface a link-local address is valid on.
    #[serde(default)]
    pub zone: Option<ZoneRecord>,
    /// Round-trip summary and hop counter.
    #[serde(default)]
    pub telemetry: TelemetryRecord,
    /// The routers between the scanning host and this one.
    #[serde(default)]
    pub path: Vec<HopRecord>,
    /// Roles inferred from where it sits or what it runs, by wire name.
    #[serde(default)]
    pub roles: Vec<String>,
    /// What the filter in front of the host was shown to be doing, by wire name.
    #[serde(default)]
    pub filtering: Vec<String>,
    /// What a scan concluded about each IP protocol it asked this host about,
    /// ascending by number. Empty for a scan that did not ask.
    ///
    /// A list rather than a map keyed by number, so that every key in this
    /// document is a field name. A map's keys would be data wearing the shape of
    /// field names, which is a difference nothing reading the file generically
    /// can see; the report writes the same list, one field wider.
    #[serde(default)]
    pub ip_protocols: Vec<IpProtocolRecord>,
    /// When it was first seen.
    pub first_seen: SystemTime,
    /// When it was last seen.
    pub last_seen: SystemTime,
    /// Its ports, in the order the model holds them.
    #[serde(default)]
    pub ports: Vec<PortRecord>,
    /// What a detection concluded was wrong with the host as a whole, in claim
    /// order.
    #[serde(default)]
    pub findings: Vec<FindingRecord>,
}

impl From<&Host> for HostRecord {
    fn from(host: &Host) -> Self {
        Self {
            primary_ip: host.primary_ip(),
            ips: host.ips().iter().copied().collect(),
            hostname: host.hostname().map(str::to_owned),
            // Already ordered by the model's set, so two runs that heard the
            // same names write the same file.
            names: host.names().map(NameRecord::from).collect(),
            status: wire::host_status_name(host.status()).to_owned(),
            // Sorted, because the model holds these in a set: two runs that
            // found the same things must write the same file, or a journal is
            // not comparable with itself.
            reasons: {
                let mut reasons: Vec<_> = host
                    .reasons()
                    .iter()
                    .map(StatusReasonRecord::from)
                    .collect();
                reasons.sort();
                reasons
            },
            os: host.os().map(OsRecord::from),
            os_evidence: host.os_evidence().map(OsEvidenceRecord::from).collect(),
            hardware: host.hardware().map(HardwareRecord::from),
            zone: host.zone().map(ZoneRecord::from),
            telemetry: TelemetryRecord::from(host.telemetry()),
            path: host.path().hops().iter().map(HopRecord::from).collect(),
            roles: {
                let mut roles: Vec<_> = host
                    .network_roles()
                    .iter()
                    .map(|role| wire::network_role_name(*role).to_owned())
                    .collect();
                roles.sort();
                roles
            },
            filtering: {
                let mut filtering: Vec<_> = host
                    .filtering()
                    .iter()
                    .map(|f| wire::filtering_name(*f).to_owned())
                    .collect();
                filtering.sort();
                filtering
            },
            ip_protocols: host
                .ip_protocols()
                .iter()
                .map(|(number, state)| IpProtocolRecord {
                    protocol: *number,
                    state: wire::ip_protocol_state_name(*state).to_owned(),
                })
                .collect(),
            first_seen: host.first_seen(),
            last_seen: host.last_seen(),
            ports: host.ports().map(PortRecord::from).collect(),
            // Already claim-ordered by the model's map, so no sort is needed for
            // two runs to write the same file.
            findings: host.findings().map(FindingRecord::from).collect(),
        }
    }
}

impl From<&HostRecord> for Host {
    fn from(record: &HostRecord) -> Self {
        // A port under a transport this build cannot read is left out rather
        // than filed under one it can, for the reason `PortRecord::rebuild`
        // gives, and the omission is logged, since the host comes back with
        // fewer ports than the file holds.
        let ports = record.ports.iter().filter_map(|entry| {
            let port = entry.rebuild();
            if port.is_none() {
                info!(
                    verbosity = 2,
                    "port {}/{} was recorded under a protocol this build cannot read; \
                     leaving it out rather than filing it under another",
                    entry.port,
                    entry.protocol
                );
            }
            port
        });
        record.rebuild_with(ports)
    }
}

impl HostRecord {
    /// This record as a host, holding `ports` in place of the ones it lists.
    ///
    /// For a reader that rebuilt a host's ports as it parsed them, which is
    /// how a document of full-range hosts is read without holding each one's
    /// port list twice. The ports land where they would have among the rest,
    /// so a host rebuilt this way is the host its record describes.
    pub(crate) fn rebuild_with(&self, ports: impl IntoIterator<Item = Port>) -> Host {
        let mut host = Host::new(self.primary_ip);

        host.extend_ips(self.ips.iter().copied());
        if let Some(hostname) = &self.hostname {
            host.set_hostname(Some(hostname.clone()));
        }
        for name in self.names.iter().filter_map(NameRecord::rebuild) {
            host.record_name(name);
        }
        // An unrecognised name leaves the status where `Host::new` put it,
        // which is `Unknown`, the reading that claims least.
        if let Some(status) = wire::host_status(&self.status) {
            host.set_status(status);
        }
        for reason in &self.reasons {
            host.add_reason(reason.into());
        }
        if let Some(os) = &self.os {
            host.set_os(os.into());
        }
        for evidence in &self.os_evidence {
            host.record_os_evidence(evidence.into());
        }
        if let Some(hardware) = self.hardware.as_ref().and_then(HardwareRecord::rebuild) {
            host.set_hardware(hardware);
        }
        if let Some(zone) = &self.zone {
            host.set_zone(zone.into());
        }

        self.telemetry.restore(&mut host);
        for hop in &self.path {
            host.record_hop(hop.into());
        }
        for role in self.roles.iter().filter_map(|r| wire::network_role(r)) {
            host.add_network_role(role);
        }
        for filtering in self.filtering.iter().filter_map(|f| wire::filtering(f)) {
            host.add_filtering(filtering);
        }
        // A state name this build cannot read is one a later build wrote, and
        // `Unasked` is the state that claims nothing, which is the same reading
        // `PortRecord` gives an unrecognised port state.
        for entry in &self.ip_protocols {
            let state = wire::ip_protocol_state(&entry.state).unwrap_or(IpProtocolState::Unasked);
            host.record_ip_protocol(entry.protocol, state);
        }
        for port in ports {
            host.add_port(port);
        }
        for finding in self.findings.iter().filter_map(FindingRecord::rebuild) {
            host.add_finding(finding);
        }

        // Last, because everything above moves `last_seen` forward as it goes.
        host.restore_seen(self.first_seen, self.last_seen);
        host
    }
}

/// One piece of evidence for a host's reachability.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StatusReasonRecord {
    /// The protocol the finding came from, by wire name.
    pub protocol: String,
    /// The address that sent it, where that was not the host itself.
    #[serde(default)]
    pub source: Option<IpAddr>,
    /// Whether something other than the host sent it, from an address the
    /// scan's exclusions withheld. `source` is empty when it is set.
    #[serde(default)]
    pub source_withheld: bool,
    /// What was observed, in words.
    #[serde(default)]
    pub details: Option<String>,
}

impl From<&StatusReason> for StatusReasonRecord {
    fn from(reason: &StatusReason) -> Self {
        Self {
            protocol: wire::status_protocol_name(&reason.protocol).into_owned(),
            source: reason.source.address(),
            source_withheld: reason.source.is_withheld(),
            details: reason.details.as_ref().map(|d| d.to_string()),
        }
    }
}

impl From<&StatusReasonRecord> for StatusReason {
    fn from(record: &StatusReasonRecord) -> Self {
        let protocol = wire::status_protocol(&record.protocol)
            .unwrap_or_else(|| StatusProtocol::Custom(record.protocol.as_str().into()));

        let mut reason = StatusReason::new(protocol, "");
        reason.details = record.details.as_deref().map(Into::into);
        // A record claiming a withheld sender and naming one anyway is read as
        // withheld, for the reason a hop is: of its two claims, that is the one
        // that reports less.
        reason.source = match record.source {
            _ if record.source_withheld => EvidenceSource::Withheld,
            Some(address) => EvidenceSource::Intermediary(address),
            None => EvidenceSource::Host,
        };
        reason
    }
}

/// What a host was identified as running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsRecord {
    /// The name to show.
    pub name: String,
    /// How sure the identification is, out of a hundred.
    pub accuracy: u8,
    /// What kind of box it is, such as `Printer`.
    #[serde(default)]
    pub device: Option<String>,
    /// The broad family, such as `Linux`.
    #[serde(default)]
    pub family: Option<String>,
    /// The release within the family.
    #[serde(default)]
    pub generation: Option<String>,
    /// Who makes it.
    #[serde(default)]
    pub vendor: Option<String>,
    /// The kernel, where one was named separately.
    #[serde(default)]
    pub kernel: Option<String>,
    /// The instruction set, such as `x86_64`.
    #[serde(default)]
    pub arch: Option<String>,
    /// How sure the detail beyond the family is.
    #[serde(default)]
    pub detail_accuracy: Option<u8>,
    /// What the identification rests on.
    #[serde(default)]
    pub evidence: Option<String>,
    /// Platform identifiers.
    #[serde(default)]
    pub cpes: Vec<String>,
}

impl From<&OsFingerprint> for OsRecord {
    fn from(os: &OsFingerprint) -> Self {
        Self {
            name: os.name().to_owned(),
            accuracy: os.accuracy(),
            family: os.family().map(str::to_owned),
            device: os.device().map(str::to_owned),
            generation: os.generation().map(str::to_owned),
            vendor: os.vendor().map(str::to_owned),
            kernel: os.kernel().map(str::to_owned),
            arch: os.arch().map(str::to_owned),
            detail_accuracy: os.detail_accuracy(),
            evidence: os.evidence().map(str::to_owned),
            cpes: os.cpes().iter().map(|cpe| cpe.to_string()).collect(),
        }
    }
}

impl From<&OsRecord> for OsFingerprint {
    fn from(record: &OsRecord) -> Self {
        let mut os = OsFingerprint::new(record.name.clone(), record.accuracy);
        if let Some(family) = &record.family {
            os = os.with_family(family.clone());
        }
        if let Some(device) = &record.device {
            os = os.with_device(device.clone());
        }
        if let Some(generation) = &record.generation {
            os = os.with_generation(generation.clone());
        }
        if let Some(vendor) = &record.vendor {
            os = os.with_vendor(vendor.clone());
        }
        if let Some(kernel) = &record.kernel {
            os = os.with_kernel(kernel.clone());
        }
        if let Some(arch) = &record.arch {
            os = os.with_arch(arch.clone());
        }
        if let Some(accuracy) = record.detail_accuracy {
            os = os.with_detail_accuracy(accuracy);
        }
        if let Some(evidence) = &record.evidence {
            os = os.with_evidence(evidence.clone());
        }
        for cpe in &record.cpes {
            os.add_cpe(cpe.clone());
        }
        os
    }
}

/// What one source concluded about a host's operating system.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsEvidenceRecord {
    /// Which source said so, by wire name.
    pub source: String,
    /// The family it named, where it could name one.
    #[serde(default)]
    pub family: Option<String>,
    /// The device class it named, where it named one.
    #[serde(default)]
    pub device: Option<String>,
    /// The vendor, where it named one.
    #[serde(default)]
    pub vendor: Option<String>,
    /// The product, where it named one.
    #[serde(default)]
    pub product: Option<String>,
    /// The version, where it named one.
    #[serde(default)]
    pub version: Option<String>,
    /// The kernel, where it named one.
    #[serde(default)]
    pub kernel: Option<String>,
    /// The instruction set, where it named one.
    #[serde(default)]
    pub arch: Option<String>,
    /// A platform identifier, where it carried one.
    #[serde(default)]
    pub cpe: Option<String>,
    /// How sure it was, from zero to one.
    pub confidence: f32,
    /// What it read to conclude this.
    pub evidence: String,
}

impl From<&OsEvidence> for OsEvidenceRecord {
    fn from(evidence: &OsEvidence) -> Self {
        Self {
            source: wire::os_source_name(evidence.source).to_owned(),
            family: evidence.family.clone(),
            device: evidence.device.clone(),
            vendor: evidence.vendor.clone(),
            product: evidence.product.clone(),
            version: evidence.version.clone(),
            kernel: evidence.kernel.clone(),
            arch: evidence.arch.clone(),
            cpe: evidence.cpe.clone(),
            confidence: evidence.confidence,
            evidence: evidence.evidence.clone(),
        }
    }
}

impl From<&OsEvidenceRecord> for OsEvidence {
    fn from(record: &OsEvidenceRecord) -> Self {
        OsEvidence {
            // An unrecognised source reads as the weakest one, which is what a
            // reading this build cannot place is worth.
            source: wire::os_source(&record.source).unwrap_or(OsSource::Hostname),
            family: record.family.clone(),
            device: record.device.clone(),
            vendor: record.vendor.clone(),
            product: record.product.clone(),
            version: record.version.clone(),
            kernel: record.kernel.clone(),
            arch: record.arch.clone(),
            cpe: record.cpe.clone(),
            confidence: record.confidence,
            evidence: record.evidence.clone(),
        }
    }
}

/// Hardware addresses and the vendor they attribute to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareRecord {
    /// Each address and when it was last seen.
    pub macs: Vec<(String, SystemTime)>,
    /// The vendor, where something named it rather than it being read from an
    /// address block. A record rebuilt from addresses alone resolves its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// The model a service named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// The line that model belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// The hardware's platform identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpe23: Option<String>,
    /// A finer designation than the product.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The hardware revision, which is not the operating system's version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The unit's own serial number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
}

impl From<&HardwareInfo> for HardwareRecord {
    fn from(hardware: &HardwareInfo) -> Self {
        let mut macs: Vec<(String, SystemTime)> = hardware
            .macs()
            .iter()
            .map(|(mac, at)| (mac.to_string(), *at))
            .collect();

        // The vendor comes from whichever address arrived first and is never
        // revised, but the model keeps its addresses sorted rather than in
        // arrival order, so a rebuild reading them back in order would resolve
        // the vendor from a different address and reach a different answer.
        //
        // Recording the one that produced it first is what makes the rebuild
        // agree, and it keeps a vendor out of the file: it stays derived from
        // the OUI table, so a record cannot assert one the table does not
        // support.
        if let Some(vendor) = hardware.vendor() {
            let source = macs.iter().position(|(mac, _)| {
                mac.parse::<MacAddr>()
                    .ok()
                    .and_then(|mac| crate::model::mac::vendor(&mac))
                    .is_some_and(|found| found == vendor)
            });
            if let Some(source) = source {
                macs.swap(0, source);
            }
        }

        // A vendor an address block produced stays out of the file, for the
        // reason above. One a service *stated* cannot be re-derived from
        // anything, so it is recorded: without this a NETGEAR ReadyNAS named by
        // its FTP banner comes back from a journal as an unnamed box.
        let derivable = hardware.vendor().is_some_and(|vendor| {
            macs.iter().any(|(mac, _)| {
                mac.parse::<MacAddr>()
                    .ok()
                    .and_then(|mac| crate::model::mac::vendor(&mac))
                    .is_some_and(|found| found == vendor)
            })
        });

        Self {
            macs,
            vendor: (!derivable)
                .then(|| hardware.vendor().map(str::to_string))
                .flatten(),
            product: hardware.product().map(str::to_string),
            family: hardware.family().map(str::to_string),
            cpe23: hardware.cpe23().map(str::to_string),
            model: hardware.model().map(str::to_string),
            version: hardware.hardware_version().map(str::to_string),
            serial_number: hardware.serial_number().map(str::to_string),
        }
    }
}

impl HardwareRecord {
    /// Rebuilds the hardware, or `None` where the record names no address this
    /// build can read.
    ///
    /// The vendor is not carried. It is derived from the address's OUI, so a
    /// rebuild resolves it from the same table the scan used, and a file cannot
    /// assert a vendor the OUI does not support.
    pub fn rebuild(&self) -> Option<HardwareInfo> {
        let mut macs = self
            .macs
            .iter()
            .filter_map(|(mac, at)| mac.parse::<MacAddr>().ok().map(|mac| (mac, *at)));

        // A record may hold no address at all: a host reached through a gateway
        // has no MAC to read, and a banner naming `Merit LILIN PDR M800`
        // describes the box without one.
        let described = HardwareInfo::described(crate::model::host::HardwareDescription {
            vendor: self.vendor.as_deref(),
            product: self.product.as_deref(),
            family: self.family.as_deref(),
            cpe23: self.cpe23.as_deref(),
            model: self.model.as_deref(),
            version: self.version.as_deref(),
            serial_number: self.serial_number.as_deref(),
        });

        let Some((first, first_at)) = macs.next() else {
            return described;
        };

        let mut hardware = HardwareInfo::new(first);
        hardware.record_mac_seen_at(first, first_at);
        for (mac, at) in macs {
            hardware.record_mac_seen_at(mac, at);
        }
        if let Some(described) = described {
            hardware.merge(described);
        }
        Some(hardware)
    }
}

/// The interface a link-local address is valid on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneRecord {
    /// The scope id, where the host resolved one.
    #[serde(default)]
    pub index: Option<u32>,
    /// The interface's name.
    pub name: String,
}

impl From<&Zone> for ZoneRecord {
    fn from(zone: &Zone) -> Self {
        Self {
            index: zone.index(),
            name: zone.name().to_owned(),
        }
    }
}

impl From<&ZoneRecord> for Zone {
    fn from(record: &ZoneRecord) -> Self {
        match record.index {
            Some(index) => Zone::new(index, record.name.clone()),
            None => Zone::unresolved(record.name.clone()),
        }
    }
}

/// A host's round-trip summary.
///
/// The samples themselves are not carried. Each is stamped with a monotonic
/// [`Instant`](std::time::Instant), which orders a history within one process
/// and means nothing outside it, so the durations are replayed and the history
/// starts fresh.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryRecord {
    /// The measured round trips, oldest first.
    #[serde(default)]
    pub rtts: Vec<Duration>,
    /// The hop counter the most recent reply arrived with.
    #[serde(default)]
    pub hop_counter: Option<u8>,
    /// Which probe the round trips were measured from, where they agree on one.
    ///
    /// One name for the list rather than one per sample. The figures are only
    /// worth a name when they share it, and a record that carried a protocol per
    /// duration would be paying per sample for a word the reader sees once.
    ///
    /// Absent in a record written before the field existed, which reads back as
    /// a set of figures that do not say what measured them. That is what they
    /// were.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_protocol: Option<String>,
}

impl From<&HostTelemetry> for TelemetryRecord {
    fn from(telemetry: &HostTelemetry) -> Self {
        Self {
            rtts: telemetry
                .history()
                .iter()
                .map(|sample| sample.rtt)
                .collect(),
            hop_counter: telemetry.hop_counter(),
            rtt_protocol: telemetry
                .rtt_protocol()
                .map(|protocol| wire::status_protocol_name(&protocol).into_owned()),
        }
    }
}

impl TelemetryRecord {
    /// Replays the measurements onto `host`.
    fn restore(&self, host: &mut Host) {
        match self.rtt_protocol.as_deref().and_then(wire::status_protocol) {
            Some(protocol) => {
                for rtt in &self.rtts {
                    host.add_rtt_from(*rtt, protocol.clone());
                }
            }
            None => host.add_rtts(self.rtts.iter().copied()),
        }
        if let Some(arrived) = self.hop_counter {
            host.record_hop_counter(arrived);
        }
    }
}

/// One router between the scanning host and the target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopRecord {
    /// How many routers out it sits.
    pub distance: u8,
    /// Its address, where it answered.
    #[serde(default)]
    pub address: Option<IpAddr>,
    /// The measured round trip to it.
    #[serde(default)]
    pub rtt: Option<Duration>,
    /// Whether it was spliced from another host's path rather than measured.
    #[serde(default)]
    pub inferred: bool,
    /// Whether a router answered here from an address the scan's exclusions
    /// withheld. `address` and `rtt` are empty when it is set.
    #[serde(default)]
    pub withheld: bool,
}

impl From<&Hop> for HopRecord {
    fn from(hop: &Hop) -> Self {
        Self {
            distance: hop.distance(),
            address: hop.address(),
            rtt: hop.rtt(),
            inferred: hop.inferred(),
            withheld: hop.is_withheld(),
        }
    }
}

impl From<&HopRecord> for Hop {
    fn from(record: &HopRecord) -> Self {
        // A record claiming a withheld router and naming one anyway is read as
        // withheld: of its two claims, that is the one that reports less.
        let hop = match record.address {
            _ if record.withheld => Hop::withheld(record.distance),
            Some(address) => Hop::answered(record.distance, address, record.rtt),
            None => Hop::silent(record.distance),
        };

        if record.inferred {
            hop.as_inferred()
        } else {
            hop
        }
    }
}

/// One port and what was established about it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortRecord {
    /// The port number.
    pub port: u16,
    /// The transport it was reached over, by wire name.
    pub protocol: String,
    /// What a probe established, by wire name.
    pub state: String,
    /// What is listening, where it was identified.
    #[serde(default)]
    pub service: Option<ServiceRecord>,
    /// What a TLS handshake negotiated.
    #[serde(default)]
    pub security: Option<SecurityRecord>,
    /// The packet that settled the state.
    #[serde(default)]
    pub discovery: Option<DiscoveryRecord>,
    /// What a detection concluded was wrong with what is listening here, in
    /// claim order.
    #[serde(default)]
    pub findings: Vec<FindingRecord>,
}

impl From<&Port> for PortRecord {
    fn from(port: &Port) -> Self {
        Self {
            port: port.number(),
            protocol: wire::protocol_name(port.protocol()).to_owned(),
            state: wire::port_state_name(port.state()).to_owned(),
            service: port.service().map(ServiceRecord::from),
            security: port.security().map(SecurityRecord::from),
            discovery: port.discovery().map(DiscoveryRecord::from),
            // Already claim-ordered by the model's map.
            findings: port.findings().map(FindingRecord::from).collect(),
        }
    }
}

impl PortRecord {
    /// Rebuilds the port, or [`None`] where the record names a transport this
    /// build cannot read.
    ///
    /// A state this build cannot read is one a later build wrote, and it reads
    /// downward to [`PortState::Unasked`], the state that holds no verdict at
    /// all. A transport cannot read downward, because transports have no
    /// ordering: TCP is not *less* than one this build has never heard of; it
    /// is a different endpoint. And ports are keyed by number and transport, so
    /// a record filed under TCP instead collides with the real TCP port of the
    /// same number, and [`Host::add_port`] merges the two. A host holding
    /// `443/tcp` and `443/<unknown>` would come back holding one port, with the
    /// service named on the second reported as running on the first. Leaving
    /// the record out is the only reading that claims nothing.
    ///
    /// [`Protocol`](crate::model::port::Protocol) is `#[non_exhaustive]`, so a
    /// later build writing such a record is expected rather than hypothetical.
    pub fn rebuild(&self) -> Option<Port> {
        let protocol = wire::protocol(&self.protocol)?;
        let state = wire::port_state(&self.state).unwrap_or(PortState::Unasked);

        let mut port = Port::new(self.port, protocol, state);
        if let Some(service) = &self.service {
            port = port.with_service(service.into());
        }
        if let Some(security) = &self.security {
            port = port.with_security(security.into());
        }
        if let Some(discovery) = &self.discovery {
            port = port.with_discovery(discovery.into());
        }
        for finding in self.findings.iter().filter_map(FindingRecord::rebuild) {
            port.add_finding(finding);
        }
        Some(port)
    }
}

/// A name a host gave for itself, as a file holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameRecord {
    /// Which protocol it was given in, by wire name.
    pub source: String,
    /// What it names, by wire name.
    pub kind: String,
    /// The name.
    pub name: String,
}

impl From<&HostName> for NameRecord {
    fn from(name: &HostName) -> Self {
        Self {
            source: wire::name_source_name(name.source()).to_owned(),
            kind: wire::name_kind_name(name.kind()).to_owned(),
            name: name.name().to_owned(),
        }
    }
}

impl NameRecord {
    /// The name this records, or `None` where it cannot be read.
    ///
    /// A source or a kind this build does not know was written by a later
    /// one, and there is no reading of it that claims less than leaving the
    /// name out: filed under another kind, a forest would read as the host's
    /// own name, and under another source as a claim a different protocol
    /// made. The same holds for a name the model refuses, which no build
    /// writes and a hand-edited file can.
    pub fn rebuild(&self) -> Option<HostName> {
        HostName::new(
            wire::name_kind(&self.kind)?,
            wire::name_source(&self.source)?,
            &self.name,
        )
    }
}

/// What a scan concluded about one IP protocol on one host, as a file holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpProtocolRecord {
    /// The IP protocol number.
    pub protocol: u8,
    /// What the scan established, by wire name.
    pub state: String,
}

/// A finding, as a file holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingRecord {
    /// Which detection produced it, to which version, from which bytes.
    pub detection: DetectionIdRecord,
    /// Its one-line title.
    pub title: String,
    /// How bad it is if true, by wire name.
    pub severity: String,
    /// How sure it is true, by wire name.
    pub confidence: String,
    /// The intrusiveness the detection ran under, by wire name.
    pub class: String,
    /// The bytes that justify it, if any.
    #[serde(default)]
    pub excerpt: Option<String>,
    /// Its external references, in sorted order.
    #[serde(default)]
    pub references: Vec<ReferenceRecord>,
    /// Remediation advice, if any.
    ///
    /// Omitted when absent, as the report's own field is. The two documents
    /// describe the same finding and `export::conformance` holds them to
    /// spelling it the same way, so a journal writing `null` where the report
    /// writes nothing is a difference between them. Absence is the ordinary
    /// case rather than an edge: a finding from a converted feed carries no
    /// advice at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// The lowest of [`cpes`](Self::cpes), for a reader written before a
    /// finding could name more than one.
    ///
    /// Omitted when absent, for the reason `remediation` is, and absent from
    /// every finding a correlation did not draw. Read back beside `cpes`, so a
    /// record that carries only this one still names what its claim rests on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpe: Option<String>,
    /// Every platform identifier a correlation drew it from, ascending.
    ///
    /// Omitted when empty, which is every finding a correlation did not draw,
    /// and defaulted on the way in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cpes: Vec<String>,
}

impl From<&Finding> for FindingRecord {
    fn from(finding: &Finding) -> Self {
        Self {
            detection: DetectionIdRecord::from(finding.detection()),
            title: finding.title().to_owned(),
            severity: wire::severity_name(finding.severity()).to_owned(),
            confidence: wire::confidence_name(finding.confidence()).to_owned(),
            class: wire::detection_class_name(finding.class()).to_owned(),
            excerpt: (!finding.excerpt().is_empty()).then(|| finding.excerpt().as_str().to_owned()),
            references: finding.references().map(ReferenceRecord::from).collect(),
            remediation: finding.remediation().map(str::to_owned),
            cpe: finding.cpes().next().map(str::to_owned),
            cpes: finding.cpes().map(str::to_owned).collect(),
        }
    }
}

impl FindingRecord {
    /// Rebuilds the finding, or [`None`] if it names no detection or has no
    /// title, the two things a finding cannot be without.
    ///
    /// Everything softer reads downward rather than failing. An unknown severity,
    /// confidence or class reads as the least it could claim, and a reference
    /// that will not rebuild is dropped while the finding is kept, since
    /// provenance that does not parse is no reason to discard a real finding.
    pub fn rebuild(&self) -> Option<Finding> {
        let severity = wire::severity(&self.severity).unwrap_or(Severity::Info);
        let confidence = wire::confidence(&self.confidence).unwrap_or(Confidence::Heuristic);
        let class = wire::detection_class(&self.class).unwrap_or(DetectionClass::Passive);

        let mut finding = Finding::new(
            self.detection.rebuild()?,
            self.title.clone(),
            severity,
            confidence,
            class,
        )
        .ok()?;

        if let Some(excerpt) = &self.excerpt {
            finding = finding.with_excerpt(Excerpt::new(excerpt.clone()));
        }
        if let Some(remediation) = &self.remediation {
            finding = finding.with_remediation(remediation.clone());
        }
        for cpe in self.cpe.iter().chain(&self.cpes) {
            finding = finding.with_cpe(cpe.clone());
        }
        for reference in self.references.iter().filter_map(ReferenceRecord::rebuild) {
            finding = finding.with_reference(reference);
        }
        Some(finding)
    }
}

/// A detection identity, as a file holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionIdRecord {
    /// The author-chosen identifier.
    pub id: String,
    /// Its version, as `major.minor.patch`.
    pub version: String,
    /// The content hash of the detection body.
    pub content_hash: String,
}

impl From<&DetectionId> for DetectionIdRecord {
    fn from(detection: &DetectionId) -> Self {
        Self {
            id: detection.id().to_owned(),
            version: detection.version().to_string(),
            content_hash: detection.content_hash().to_owned(),
        }
    }
}

impl DetectionIdRecord {
    /// Rebuilds the identity, or [`None`] if it names nothing. A version that
    /// will not parse reads as `0.0.0`, the earliest and least trusted, rather
    /// than discarding the finding it identifies.
    pub fn rebuild(&self) -> Option<DetectionId> {
        let version = self.version.parse().unwrap_or(Version::new(0, 0, 0));
        DetectionId::new(self.id.clone(), version, self.content_hash.clone()).ok()
    }
}

/// An external reference, as a file holds it: a kind and the value it carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceRecord {
    /// Which kind of reference, by wire name.
    pub kind: String,
    /// The value it carries: a CVE id, a CWE number, or a URL.
    pub value: String,
}

impl From<&Reference> for ReferenceRecord {
    fn from(reference: &Reference) -> Self {
        Self {
            kind: wire::reference_kind_name(reference).to_owned(),
            value: match reference {
                Reference::Cve(id) | Reference::Url(id) => id.clone(),
                Reference::Cwe(number) => number.to_string(),
            },
        }
    }
}

impl ReferenceRecord {
    /// Rebuilds the reference, or [`None`] for an unknown kind or a malformed
    /// value.
    pub fn rebuild(&self) -> Option<Reference> {
        wire::reference(&self.kind, &self.value)
    }
}

/// What is listening on a port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRecord {
    /// What it is, such as `http`.
    pub name: String,
    /// How sure the identification is, out of a hundred.
    pub confidence: u8,
    /// The product behind it.
    #[serde(default)]
    pub product: Option<String>,
    /// Who makes it.
    #[serde(default)]
    pub vendor: Option<String>,
    /// Its version.
    #[serde(default)]
    pub version: Option<String>,
    /// Detail that is not the product itself.
    #[serde(default)]
    pub extrainfo: Option<String>,
    /// Platform identifiers.
    #[serde(default)]
    pub cpes: Vec<String>,
}

impl From<&Service> for ServiceRecord {
    fn from(service: &Service) -> Self {
        Self {
            name: service.name().to_owned(),
            confidence: service.confidence(),
            product: service.product().map(str::to_owned),
            vendor: service.vendor().map(str::to_owned),
            version: service.version().map(str::to_owned),
            extrainfo: service.extrainfo().map(str::to_owned),
            cpes: service.cpes().iter().map(|cpe| cpe.to_string()).collect(),
        }
    }
}

impl From<&ServiceRecord> for Service {
    fn from(record: &ServiceRecord) -> Self {
        let mut service = Service::new(record.name.clone(), record.confidence);
        if let Some(product) = &record.product {
            service = service.with_product(product.clone());
        }
        if let Some(vendor) = &record.vendor {
            service = service.with_vendor(vendor.clone());
        }
        if let Some(version) = &record.version {
            service = service.with_version(version.clone());
        }
        if let Some(extrainfo) = &record.extrainfo {
            service = service.with_extrainfo(extrainfo.clone());
        }
        for cpe in &record.cpes {
            service.add_cpe(cpe.clone());
        }
        service
    }
}

/// What a TLS handshake negotiated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityRecord {
    /// The protocol version agreed.
    #[serde(default)]
    pub tls_version: Option<String>,
    /// The cipher suite agreed.
    #[serde(default)]
    pub cipher_suite: Option<String>,
    /// The protocols offered over ALPN.
    #[serde(default)]
    pub alpn: Vec<String>,
    /// The certificate presented.
    #[serde(default)]
    pub certificate: Option<CertificateRecord>,
    /// What the endpoint accepts, one entry per version, where a scan asked.
    ///
    /// Skipped when empty, which is every sitting that did not enumerate, and
    /// defaulted on the way in so a record written before the pass existed
    /// reads back as one that did not.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepts: Vec<AcceptedVersionRecord>,
    /// The versions whose enumeration did not finish, where any did.
    ///
    /// Skipped when empty and defaulted on the way in, on the reasoning
    /// `accepts` gives.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unfinished: Vec<UnfinishedVersionRecord>,
}

/// One version whose enumeration did not finish, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnfinishedVersionRecord {
    /// The version, by the name it prints.
    pub version: String,
    /// Why the walk ended, by the name it prints.
    pub interruption: String,
}

/// One version an endpoint accepted, and the suites chosen under it.
///
/// Suites are written as their wire numbers rather than their names. A number is
/// what the server actually sent, it is half the size, and a build that has since
/// added or renamed a suite reads an old record correctly instead of matching on
/// a string it no longer uses. A number this build does not carry reads back into
/// `unrecognised`, which is where it belonged in the first place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedVersionRecord {
    /// The version, by the name it prints.
    pub version: String,
    /// The suites accepted, by wire number, in the order the server chose them.
    #[serde(default)]
    pub suites: Vec<u16>,
    /// Suites the scanning build could not name, by wire number.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unrecognised: Vec<u16>,
}

impl From<&Security> for SecurityRecord {
    fn from(security: &Security) -> Self {
        Self {
            tls_version: security.tls_version().map(str::to_owned),
            cipher_suite: security.cipher_suite().map(str::to_owned),
            alpn: security.alpn().iter().map(|p| p.to_string()).collect(),
            certificate: security.certificate().map(CertificateRecord::from),
            accepts: security
                .support()
                .versions()
                .iter()
                .map(|held| AcceptedVersionRecord {
                    version: held.version().name().to_owned(),
                    suites: held.suites().iter().map(|suite| suite.code()).collect(),
                    unrecognised: held.unrecognised().to_vec(),
                })
                .collect(),
            unfinished: security
                .support()
                .unfinished()
                .iter()
                .map(|held| UnfinishedVersionRecord {
                    version: held.version().name().to_owned(),
                    interruption: held.interruption().name().to_owned(),
                })
                .collect(),
        }
    }
}

impl From<&SecurityRecord> for Security {
    fn from(record: &SecurityRecord) -> Self {
        let mut security = Security::new();
        if let Some(version) = &record.tls_version {
            security = security.with_tls_version(version.clone());
        }
        if let Some(cipher) = &record.cipher_suite {
            security = security.with_cipher_suite(cipher.clone());
        }
        for protocol in &record.alpn {
            security.add_alpn(protocol.clone());
        }
        if let Some(certificate) = &record.certificate {
            security = security.with_certificate(certificate.into());
        }

        let mut support = TlsSupport::new();
        for held in &record.accepts {
            // A version this build cannot name is dropped rather than guessed
            // at: there is nothing to file its suites under.
            let Ok(version) = held.version.parse::<TlsVersion>() else {
                continue;
            };
            let mut suites = Vec::with_capacity(held.suites.len());
            let mut unrecognised = held.unrecognised.clone();
            for code in &held.suites {
                match CipherSuite::from_code(*code) {
                    Some(suite) => suites.push(suite),
                    // Written by a build that carried it and read by one that
                    // does not. Kept as a number, which is what it always was.
                    None => unrecognised.push(*code),
                }
            }
            support.record(VersionSupport::new(version, suites, unrecognised));
        }
        for held in &record.unfinished {
            let Ok(version) = held.version.parse::<TlsVersion>() else {
                continue;
            };
            // Read downward, as every other name here is. Dropping the entry
            // would claim the walk finished, which is the one reading the file
            // did not make; `Stopped` keeps the claim that it did not, and says
            // nothing about the endpoint.
            let interruption =
                Interruption::from_name(&held.interruption).unwrap_or(Interruption::Stopped);
            support.record_unfinished(UnfinishedVersion::new(version, interruption));
        }
        security.set_support(support);

        security
    }
}

/// The certificate a TLS endpoint presented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateRecord {
    /// Who it is for.
    pub common_name: String,
    /// The other names it covers.
    #[serde(default)]
    pub sans: Vec<String>,
    /// Who signed it.
    pub issuer: String,
    /// When it becomes valid.
    pub validity_start: SystemTime,
    /// When it stops being valid.
    pub validity_end: SystemTime,
    /// The SHA-256 of the certificate.
    pub fingerprint_sha256: String,
    /// The public key's algorithm, or `unknown` where it was not read.
    #[serde(default)]
    pub pubkey_type: String,
    /// The public key's size in bits, or zero where it was not read.
    #[serde(default)]
    pub pubkey_bits: u32,
}

impl From<&CertificateInfo> for CertificateRecord {
    fn from(certificate: &CertificateInfo) -> Self {
        Self {
            common_name: certificate.common_name().to_owned(),
            sans: certificate.sans().iter().map(|s| s.to_string()).collect(),
            issuer: certificate.issuer().to_owned(),
            validity_start: certificate.validity_start(),
            validity_end: certificate.validity_end(),
            fingerprint_sha256: certificate.fingerprint_sha256().to_owned(),
            pubkey_type: certificate.pubkey_type().to_owned(),
            pubkey_bits: certificate.pubkey_bits(),
        }
    }
}

impl From<&CertificateRecord> for CertificateInfo {
    fn from(record: &CertificateRecord) -> Self {
        CertificateInfo::new(
            record.common_name.clone(),
            record.issuer.clone(),
            record.validity_start,
            record.validity_end,
            record.fingerprint_sha256.clone(),
        )
        .with_sans(record.sans.iter().map(|s| s.as_str().into()))
        .with_public_key(record.pubkey_type.clone(), record.pubkey_bits)
    }
}

/// The packet that settled a port's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryRecord {
    /// What came back, by wire name.
    pub reason: String,
    /// When it arrived.
    pub timestamp: SystemTime,
    /// The measured round trip.
    #[serde(default)]
    pub rtt: Option<Duration>,
    /// The hop counter it carried.
    #[serde(default)]
    pub ttl: Option<u8>,
    /// Who sent it: the source address its IP header carried.
    #[serde(default)]
    pub source_ip: Option<IpAddr>,
}

impl From<&Discovery> for DiscoveryRecord {
    fn from(discovery: &Discovery) -> Self {
        Self {
            reason: wire::scan_response_name(discovery.reason()).into_owned(),
            timestamp: discovery.timestamp(),
            rtt: discovery.rtt(),
            ttl: discovery.ttl(),
            source_ip: discovery.source_ip(),
        }
    }
}

impl From<&DiscoveryRecord> for Discovery {
    fn from(record: &DiscoveryRecord) -> Self {
        let reason = wire::scan_response(&record.reason)
            .unwrap_or_else(|| ScanResponse::Custom(record.reason.clone()));

        let mut discovery = Discovery::new(reason).seen_at(record.timestamp);
        if let Some(rtt) = record.rtt {
            discovery = discovery.with_rtt(rtt);
        }
        if let Some(ttl) = record.ttl {
            discovery = discovery.with_ttl(ttl);
        }
        if let Some(source) = record.source_ip {
            discovery = discovery.with_source_ip(source);
        }
        discovery
    }
}

/// One sitting of a scan, as a file holds it.
///
/// Mirrors [`PhaseParts`], which mirrors the
/// phase. A field added to any of the three has to be added to all of them, and
/// the compiler says so.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhaseRecord {
    /// Which entry point this sitting recorded, by wire name.
    pub kind: String,
    /// When it began.
    pub started_at: SystemTime,
    /// How long it ran.
    pub elapsed: Duration,
    /// Whether it held the privileges its raw strategies need, or absent where
    /// this engine did not measure the phase and cannot say.
    pub privileged: Option<bool>,
    /// What it covered, and what it was forbidden.
    pub targets: ScopeRecord,
    /// The settings it ran under.
    pub settings: SettingsRecord,
    /// The strategies that could not do their job.
    #[serde(default)]
    pub failures: Vec<FailureRecord>,
    /// Ground the sitting declined before sending anything.
    ///
    /// Skipped when empty, which is most sittings, and defaulted on the way in,
    /// so a record written before this field existed reads back as a sitting
    /// that refused nothing. That is the honest reading: a refusal was written
    /// down as a failure then, and it stays a failure rather than being invented
    /// as a refusal now.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refusals: Vec<RefusalRecord>,
    /// Addresses the scanning host could not reach, so no probe was sent to
    /// them.
    #[serde(default)]
    pub unroutable: Vec<IpAddr>,
    /// Addresses the sitting left before it had finished with them, because
    /// their own budget ran out.
    ///
    /// Skipped when empty, which is every sitting that set no per-host budget,
    /// and defaulted on the way in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timed_out: Vec<IpAddr>,
    /// Addresses whose ICMP errors the sitting found rate-limited.
    ///
    /// Skipped when empty, which is every sitting that asked no UDP ports of a
    /// rationing host, and defaulted on the way in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icmp_rate_limited: Vec<IpAddr>,
    /// Addresses a raw sitting reached by TCP connect instead.
    ///
    /// Skipped when empty, which is most sittings, and defaulted on the way in.
    /// A record written before this field existed reads back as a sitting that
    /// reached nothing this way, which overstates it only where that sitting
    /// swept loopback with raw privileges: the one case that was already
    /// happening and not yet written down.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reached_by_connect: Vec<RangeRecord>,
    /// Addresses in scope the sitting reached no verdict on.
    ///
    /// Skipped when empty, which is every sitting that finished its liveness
    /// question, and defaulted on the way in. A record written before this
    /// field existed reads back as a sitting that decided everything, which
    /// overstates it only where that sitting stopped during discovery.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub undecided: Vec<RangeRecord>,
    /// Why a port sitting ran with no liveness pass in front of it, by its wire
    /// name.
    ///
    /// Skipped when absent, which is every sitting a liveness pass preceded and
    /// every one that is not a port scan, and defaulted on the way in. A name
    /// this build does not know reads back as absent, which claims only that
    /// the reason is not stated, where guessing one would misstate what the
    /// findings mean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness_skipped: Option<String>,
    /// Addresses a port sitting standing in for its liveness pass asked on
    /// every port and heard nothing from.
    ///
    /// Skipped when empty, which is every sitting a liveness pass preceded, and
    /// defaulted on the way in. Read back, it is what keeps a host record the
    /// sitting already journalled at such an address out of the report.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub silent: Vec<RangeRecord>,
    /// Why the scan was stopped while this sitting ran, by wire name.
    ///
    /// Skipped when absent, which is every sitting that ended on its own, and
    /// defaulted on the way in. A name this build does not know reads back as
    /// absent: the marker qualifies the findings and changes none of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped: Option<String>,
    /// The passes a stop skipped or cut short, by wire name.
    ///
    /// Skipped when empty, which is every sitting no stop cut, and defaulted
    /// on the way in. A name this build does not know is dropped as it is
    /// read back: it names a pass this build does not run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passes_cut: Vec<String>,
    /// How many of a port sitting's targets it never asked and holds on no
    /// host.
    ///
    /// Skipped when zero, and defaulted on the way in. Read back, it is what
    /// keeps a job resumed and stopped again reporting its remainder, since
    /// the targets are on no host.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unreached: u128,
    /// How many of a port sitting's targets it asked at the addresses it lists
    /// no host at.
    ///
    /// Skipped when zero, and defaulted on the way in. Read back, it is the
    /// one place those probes are counted, since the addresses' records were
    /// dropped.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unheard_probes: u128,
    /// What each strategy recorded about its own run.
    #[serde(default)]
    pub probe_stats: Vec<ProbeStatsRecord>,
    /// Which document this sitting was folded in from, for a merged report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<PhaseOriginRecord>,
    /// Which switch ports the machine running this sitting was plugged into.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentRecord>,
    /// Whether this is the sitting as it stood before it closed, as a sitting
    /// writes itself down while it runs.
    ///
    /// Skipped when false, which is every sitting that closed, and defaulted
    /// on the way in, so a record written before this field existed reads as
    /// one that closed.
    #[serde(default, skip_serializing_if = "is_false")]
    pub open: bool,
}

/// Where the machine running a sitting was plugged in, as a file holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRecord {
    /// Which of the scanning machine's interfaces the announcement arrived on.
    pub link: String,
    /// The interface index, where the reading host knew it. Absent rather than
    /// zero, since zero is what "no interface" means to a kernel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_index: Option<u32>,
    /// Which protocol the announcement was read from.
    pub source: String,
    /// The hardware address the device identified its chassis with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_mac: Option<String>,
    /// What the device calls itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    /// What the device calls the port this machine is plugged into.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    /// The VLAN untagged traffic on this port lands in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_vlan: Option<u16>,
    /// An address the device is managed at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_address: Option<IpAddr>,
    /// When the announcement arrived.
    pub observed_at: SystemTime,
}

impl From<&Attachment> for AttachmentRecord {
    fn from(attachment: &Attachment) -> Self {
        Self {
            link: attachment.link().name().to_owned(),
            link_index: attachment.link().index(),
            source: wire::attachment_source_name(attachment.source()).to_owned(),
            device_mac: attachment.device_mac().map(|mac| mac.to_string()),
            device_name: attachment.device_name().map(str::to_owned),
            port: attachment.port().map(str::to_owned),
            native_vlan: attachment.native_vlan(),
            management_address: attachment.management_address(),
            observed_at: attachment.observed_at(),
        }
    }
}

impl From<&AttachmentRecord> for Attachment {
    fn from(record: &AttachmentRecord) -> Self {
        let link = match record.link_index {
            Some(index) => Zone::new(index, record.link.as_str()),
            None => Zone::unresolved(record.link.as_str()),
        };

        // A source this build cannot place is read as LLDP: it is the standard
        // one, and the field says which protocol carried the fields rather than
        // deciding what any of them mean.
        let source = wire::attachment_source(&record.source).unwrap_or(AttachmentSource::Lldp);

        let mut attachment = Attachment::new(link, source, record.observed_at);
        if let Some(mac) = record
            .device_mac
            .as_deref()
            .and_then(|mac| mac.parse().ok())
        {
            attachment = attachment.with_device_mac(mac);
        }
        if let Some(name) = record.device_name.as_deref() {
            attachment = attachment.with_device_name(name);
        }
        if let Some(port) = record.port.as_deref() {
            attachment = attachment.with_port(port);
        }
        if let Some(vlan) = record.native_vlan {
            attachment = attachment.with_native_vlan(vlan);
        }
        if let Some(address) = record.management_address {
            attachment = attachment.with_management_address(address);
        }
        attachment
    }
}

/// Which document a sitting came from, as a file holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseOriginRecord {
    /// What the caller called the document it was read from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// What produced it, as that scanner attributed itself.
    pub engine_version: String,
}

impl From<&PhaseOrigin> for PhaseOriginRecord {
    fn from(origin: &PhaseOrigin) -> Self {
        Self {
            label: origin.label().map(str::to_owned),
            engine_version: origin.engine_version().to_owned(),
        }
    }
}

impl From<&PhaseOriginRecord> for PhaseOrigin {
    fn from(record: &PhaseOriginRecord) -> Self {
        let origin = PhaseOrigin::new(record.engine_version.as_str());
        match &record.label {
            Some(label) => origin.with_label(label.as_str()),
            None => origin,
        }
    }
}

/// Whether a count is zero, for leaving it out of a record that has nothing to
/// say with it.
fn is_zero(count: &u128) -> bool {
    *count == 0
}

impl From<&ScanPhase> for PhaseRecord {
    fn from(phase: &ScanPhase) -> Self {
        Self {
            kind: wire::scan_kind_name(phase.kind()).to_owned(),
            started_at: phase.started_at(),
            elapsed: phase.elapsed(),
            privileged: phase.privilege().map(Privilege::is_raw),
            targets: ScopeRecord::from(phase.targets()),
            settings: SettingsRecord::from(phase.settings()),
            failures: phase.failures().iter().map(FailureRecord::from).collect(),
            refusals: phase.refusals().iter().map(RefusalRecord::from).collect(),
            unroutable: phase.unroutable().to_vec(),
            timed_out: phase.timed_out().to_vec(),
            icmp_rate_limited: phase.icmp_rate_limited().to_vec(),
            reached_by_connect: phase
                .reached_by_connect()
                .iter()
                .map(RangeRecord::from)
                .collect(),
            undecided: phase.undecided().iter().map(RangeRecord::from).collect(),
            liveness_skipped: phase
                .liveness_skipped()
                .map(|skip| wire::liveness_skip_name(skip).to_owned()),
            silent: phase.silent().iter().map(RangeRecord::from).collect(),
            stopped: phase
                .stopped()
                .map(|reason| wire::stop_reason_name(reason).to_owned()),
            passes_cut: phase
                .passes_cut()
                .iter()
                .map(|pass| wire::pass_name(*pass).to_owned())
                .collect(),
            unreached: phase.unreached(),
            unheard_probes: phase.unheard_probes(),
            probe_stats: phase
                .probe_stats()
                .iter()
                .map(ProbeStatsRecord::from)
                .collect(),
            origin: phase.origin().map(PhaseOriginRecord::from),
            attachments: phase
                .attachments()
                .iter()
                .map(AttachmentRecord::from)
                .collect(),
            open: phase.is_open(),
        }
    }
}

impl From<&PhaseRecord> for ScanPhase {
    fn from(record: &PhaseRecord) -> Self {
        ScanPhase::from_parts(PhaseParts {
            // A sitting whose kind this build cannot place is read as a
            // discovery sweep. Of the kinds that exist it claims the least
            // while still claiming the addresses were walked: a reader is not
            // told ports were scanned, and is not told the sitting covered
            // nothing when its scope says it covered a range.
            kind: wire::scan_kind(&record.kind).unwrap_or(ScanKind::Discovery),
            started_at: record.started_at,
            elapsed: record.elapsed,
            privilege: record.privileged.map(Privilege::from_raw),
            targets: TargetScope::from(&record.targets),
            settings: ScanSettings::from(&record.settings),
            failures: record.failures.iter().map(ScannerFailure::from).collect(),
            refusals: record.refusals.iter().map(Refusal::from).collect(),
            unroutable: record.unroutable.clone(),
            timed_out: record.timed_out.clone(),
            icmp_rate_limited: record.icmp_rate_limited.clone(),
            // A range whose ends do not describe one is dropped rather than
            // guessed at, as `TargetScope` drops one. What remains still says
            // which addresses the sitting reached this way.
            reached_by_connect: record
                .reached_by_connect
                .iter()
                .filter_map(RangeRecord::rebuild)
                .collect(),
            // Dropped on the same terms: a range that does not describe one
            // names no address, undecided or otherwise.
            undecided: record
                .undecided
                .iter()
                .filter_map(RangeRecord::rebuild)
                .collect(),
            liveness_skipped: record
                .liveness_skipped
                .as_deref()
                .and_then(wire::liveness_skip),
            silent: record
                .silent
                .iter()
                .filter_map(RangeRecord::rebuild)
                .collect(),
            stopped: record.stopped.as_deref().and_then(wire::stop_reason),
            passes_cut: record
                .passes_cut
                .iter()
                .filter_map(|name| wire::pass(name))
                .collect(),
            unreached: record.unreached,
            unheard_probes: record.unheard_probes,
            probes: record.probe_stats.iter().map(ProbeStats::from).collect(),
            origin: record.origin.as_ref().map(PhaseOrigin::from),
            attachments: record.attachments.iter().map(Attachment::from).collect(),
            open: record.open,
        })
    }
}

/// What a sitting was asked to cover, and what it was forbidden.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRecord {
    /// The ranges walked, after exclusions, as `start-end`.
    #[serde(default)]
    pub ranges: Vec<RangeRecord>,
    /// The links swept whole, by the interface each is on. Empty for a phase that
    /// swept no segment, and for one recorded before this field existed. The two
    /// read back the same way, since neither claims a link was covered.
    #[serde(default)]
    pub links: Vec<ZoneRecord>,
    /// The links whose traffic was read without anything being probed on them.
    /// Never coverage; see `TargetScope::listened`. Empty for a phase that
    /// sent probes, and for one recorded before this field existed.
    #[serde(default)]
    pub listened: Vec<ZoneRecord>,
    /// How many distinct addresses those hold.
    pub addresses: u128,
    /// How many probes the scope implies, where ports were known.
    #[serde(default)]
    pub probes: Option<u128>,
    /// Which ports were walked, and whether uniformly. Absent for a phase that
    /// walked no ports, and for one recorded before this field existed. The two
    /// read back the same way, since neither can say which ports were probed.
    #[serde(default)]
    pub ports: Option<PortsRecord>,
    /// The transports covered, by wire name.
    #[serde(default)]
    pub protocols: Vec<String>,
    /// The ranges the policy withheld.
    #[serde(default)]
    pub excluded: Vec<RangeRecord>,
    /// How many addresses that withheld.
    pub withheld: u128,
}

impl From<&TargetScope> for ScopeRecord {
    fn from(scope: &TargetScope) -> Self {
        Self {
            ranges: scope.ranges().iter().map(RangeRecord::from).collect(),
            links: scope.links().iter().map(ZoneRecord::from).collect(),
            listened: scope.listened().iter().map(ZoneRecord::from).collect(),
            addresses: scope.addresses(),
            probes: scope.probes(),
            ports: PortsRecord::of(scope.ports()),
            protocols: scope
                .protocols()
                .iter()
                .map(|p| wire::protocol_name(*p).to_owned())
                .collect(),
            excluded: scope.excluded().iter().map(RangeRecord::from).collect(),
            withheld: scope.withheld(),
        }
    }
}

impl From<&ScopeRecord> for TargetScope {
    fn from(record: &ScopeRecord) -> Self {
        TargetScope::from_parts(ScopeParts {
            ranges: record
                .ranges
                .iter()
                .filter_map(RangeRecord::rebuild)
                .collect(),
            links: record.links.iter().map(Zone::from).collect(),
            listened: record.listened.iter().map(Zone::from).collect(),
            addresses: record.addresses,
            probes: record.probes,
            ports: record
                .ports
                .as_ref()
                .map_or(PortScope::Unstated, PortsRecord::rebuild),
            protocols: record
                .protocols
                .iter()
                .filter_map(|p| wire::protocol(p))
                .collect(),
            excluded: record
                .excluded
                .iter()
                .filter_map(RangeRecord::rebuild)
                .collect(),
            withheld: record.withheld,
        })
    }
}

/// A phase's port scope, as a file holds it.
///
/// The set is written as the specification
/// [`PortSet`] parses, so a full sweep is six bytes
/// rather than a hundred and thirty thousand entries, and a person reading the
/// file can see what was scanned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortsRecord {
    /// Which of the four things the set below is, by wire name.
    ///
    /// The single most important field here, and the reason a bare
    /// specification would not do. `every` is the only value from which a
    /// reader may conclude that one endpoint of a covered address was probed.
    pub kind: String,
    /// The ports, as the specification
    /// [`PortSet`] parses. Empty where the kind
    /// carries no set.
    #[serde(default)]
    pub spec: String,
}

impl PortsRecord {
    /// The record of a port scope, or `None` where the scope states nothing,
    /// which is what a record written before this field existed reads back as.
    pub fn of(scope: &PortScope) -> Option<Self> {
        match scope {
            PortScope::Unstated => None,
            other => Some(Self {
                kind: wire::port_scope_name(other).to_owned(),
                spec: other.ports().map(PortSet::to_string).unwrap_or_default(),
            }),
        }
    }

    /// The scope this records.
    ///
    /// A kind this build does not know, or a specification that will not parse,
    /// rebuilds as [`Unstated`](PortScope::Unstated), the reading that claims
    /// nothing. An unreadable set is not evidence that any port was walked, nor
    /// that none was.
    pub fn rebuild(&self) -> PortScope {
        let ports = PortSet::try_from(self.spec.as_str())
            .ok()
            .filter(|ports| !ports.is_empty());

        wire::port_scope(&self.kind, ports).unwrap_or(PortScope::Unstated)
    }
}

/// One address range, by its ends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeRecord {
    /// The first address in the range.
    pub start: IpAddr,
    /// The last address in the range.
    pub end: IpAddr,
    /// The interface a link-local range is valid on.
    #[serde(default)]
    pub zone: Option<u32>,
}

impl From<&IpRange> for RangeRecord {
    fn from(range: &IpRange) -> Self {
        Self {
            start: range.start_addr(),
            end: range.end_addr(),
            zone: match range {
                IpRange::V6(range) => range.zone(),
                IpRange::V4(_) => None,
            },
        }
    }
}

impl RangeRecord {
    /// Rebuilds the range, or `None` where its ends do not describe one, meaning
    /// a mixed pair or an end before its start.
    pub fn rebuild(&self) -> Option<IpRange> {
        match (self.start, self.end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                Ipv4Range::new(start, end).ok().map(IpRange::V4)
            }
            (IpAddr::V6(start), IpAddr::V6(end)) => Ipv6Range::scoped(start, end, self.zone)
                .ok()
                .map(IpRange::V6),
            _ => None,
        }
    }
}

/// Ground a sitting declined to cover.
///
/// No timestamp, unlike [`FailureRecord`], and the difference is the point: a
/// failure happened at a moment and a refusal was decided before the phase
/// began. Recording a clock reading for one would invite a reader to order it
/// against the failures, which says nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusalRecord {
    /// Which strategy would have taken the work, by wire name.
    pub scanner: String,
    /// What was not done, and what could be asked for instead.
    pub reason: String,
}

impl From<&Refusal> for RefusalRecord {
    fn from(refusal: &Refusal) -> Self {
        Self {
            scanner: wire::scanner_kind_name(refusal.scanner()).to_owned(),
            reason: refusal.reason().to_owned(),
        }
    }
}

impl From<&RefusalRecord> for Refusal {
    fn from(record: &RefusalRecord) -> Self {
        Refusal::new(
            wire::scanner_kind(&record.scanner).unwrap_or(ScannerKind::Composite),
            record.reason.clone(),
        )
    }
}

/// A strategy that could not do its job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureRecord {
    /// Which strategy, by wire name.
    pub scanner: String,
    /// What went wrong.
    pub reason: String,
    /// When it was recorded.
    pub at: SystemTime,
    /// Whether a limit cut the work short rather than a fault stopping it.
    /// Absent, and so false, in a record written before the two were told
    /// apart, which reads every entry as a failure.
    #[serde(default, skip_serializing_if = "is_false")]
    pub cut_short: bool,
}

impl From<&ScannerFailure> for FailureRecord {
    fn from(failure: &ScannerFailure) -> Self {
        Self {
            scanner: wire::scanner_kind_name(failure.scanner()).to_owned(),
            reason: failure.reason().to_owned(),
            at: failure.at(),
            cut_short: failure.is_cut_short(),
        }
    }
}

impl From<&FailureRecord> for ScannerFailure {
    fn from(record: &FailureRecord) -> Self {
        let scanner = wire::scanner_kind(&record.scanner).unwrap_or(ScannerKind::Composite);
        let reason = record.reason.clone();
        let failure = if record.cut_short {
            ScannerFailure::cut_short(scanner, reason)
        } else {
            ScannerFailure::new(scanner, reason)
        };
        failure.recorded_at(record.at)
    }
}

/// The settings one sitting ran under.
///
/// The enums here already read and write their own names, so this carries those
/// rather than restating a vocabulary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SettingsRecord {
    /// How raw probes were placed on the wire.
    pub send_mode: String,
    /// Which segment each TCP port probe carried.
    pub tcp_technique: String,
    /// Which chunk each SCTP port probe carried.
    ///
    /// Defaulted on the way in, so a record written before the technique was a
    /// choice reads back as the INIT scan it was.
    #[serde(default)]
    pub sctp_technique: String,
    /// The retransmission effort in force.
    pub retry_effort: String,
    /// A caller's override of the attempt budget.
    ///
    /// Written as a plain number, and read back through the bound the
    /// configuration enforces: a journal from a build that accepted zero is read
    /// as no override, which is what it was.
    #[serde(default)]
    pub retry_max_attempts: Option<u8>,
    /// A caller's scaling of the timeout. Read back the same way, so a scale a
    /// schedule could not have been built from reads as absent.
    #[serde(default)]
    pub retry_timeout_scale: Option<f64>,
    /// Whether silent hosts were probed less.
    pub retry_dampen_silent_hosts: bool,
    /// The probe-rate ceiling, where one applied.
    #[serde(default)]
    pub max_probe_rate: Option<u32>,
    /// The probe-rate floor, where one applied.
    ///
    /// Defaulted on the way in, so a record written before the floor existed
    /// reads back as a sitting that set none. That is what it was.
    #[serde(default)]
    pub min_probe_rate: Option<u32>,
    /// The shortest gap kept between two probes at one host, where one applied.
    #[serde(default)]
    pub host_probe_interval: Option<Duration>,
    /// The wall-clock budget each host was given, where one applied.
    ///
    /// Defaulted on the way in, so a record written before the budget existed
    /// reads back as a sitting that set none. That is what it was.
    #[serde(default)]
    pub host_timeout: Option<Duration>,
    /// The wall-clock budget the whole sitting was given, where one applied.
    #[serde(default)]
    pub scan_timeout: Option<Duration>,
    /// Whether name resolution could generate traffic.
    pub dns_enabled: bool,
    /// Whether identifying detail was masked.
    pub redact: bool,
    /// How far the sitting went to identify operating systems.
    pub os_detection: String,
    /// How far it went to identify services.
    pub service_detection: String,
    /// The intrusiveness ceiling detections ran under, by wire name. Defaults on
    /// an older journal that predates the field.
    #[serde(default)]
    pub detection: String,
    /// Whether it traced the path to each host.
    pub traceroute: bool,
    /// Whether it characterised the filter in front of each host.
    #[serde(default)]
    pub characterise: bool,

    /// Which IP protocols it asked each host about, ascending. Empty for a
    /// phase that ran no such pass, which is a phase written before there was
    /// one too.
    #[serde(default)]
    pub ip_protocols: Vec<u8>,
    /// Whether it established what each TLS port accepts.
    ///
    /// Defaulted on the way in, so a record written before the pass existed
    /// reads back as a sitting that did not enumerate. That is what it was.
    #[serde(default)]
    pub tls_enumeration: bool,
    /// The TCP ports it connected to and listened on and sent nothing,
    /// ascending.
    ///
    /// Defaulted on the way in, so a record written before a scan held any
    /// port back reads as a sitting that probed every port alike. That is what
    /// it was.
    #[serde(default)]
    pub listen_only_ports: Vec<u16>,
    /// The ports it sent nothing to on any target, as the specification
    /// [`PortSet`] parses, omitted when it excluded none.
    ///
    /// Defaulted on the way in, so a record written before a scan could exclude
    /// a port reads as a sitting that excluded none. That is what it was.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub excluded_ports: String,
    /// What the sitting changed about the packets it sent, omitted when it
    /// changed nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evasion: Option<EvasionSettingsRecord>,
    /// The zombie a TCP port scan read its verdicts through, omitted for an
    /// ordinary scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_scan: Option<IdleScanRecord>,
    /// Whether the capture kept ICMP errors a technique did not need.
    ///
    /// Defaulted on the way in, which reads a record written before the option
    /// existed as a sitting that did not keep them. That is what it was.
    #[serde(default)]
    pub icmp_evidence: bool,
}

/// The zombie an idle scan ran through, as written to the journal. The
/// serialized form of [`IdleScan`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdleScanRecord {
    /// The zombie's address.
    pub zombie: String,
    /// The port on the zombie its counter was read from, omitted for the
    /// scanner's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zombie_port: Option<u16>,
}

/// What a sitting changed about the packets it sent, as written to the journal.
/// The serialized form of
/// [`EvasionRecord`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvasionSettingsRecord {
    /// The source port every probe left from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    /// The hop limit every ordinary probe carried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u8>,
    /// The number of random bytes appended to each probe's payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub padding: Option<u16>,
    /// Whether TCP probes carried a deliberately wrong checksum.
    #[serde(default, skip_serializing_if = "is_false")]
    pub bad_tcp_checksum: bool,
    /// The hardware address every frame claimed to come from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spoof_mac: Option<String>,
    /// The largest each IP fragment a probe was split into, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment: Option<u16>,
    /// The addresses probes were also sent from as decoys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decoys: Vec<String>,
    /// The TCP flags every port probe carried in place of the technique's own,
    /// named (e.g. `fin|psh|urg`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
}

/// Omits a `false` boolean, so a recorded technique appears only when it was
/// used. The counterpart of `skip_serializing_if` on the optional fields.
fn is_false(value: &bool) -> bool {
    !*value
}

impl From<&ScanSettings> for SettingsRecord {
    fn from(settings: &ScanSettings) -> Self {
        Self {
            send_mode: settings.send_mode.name().to_owned(),
            tcp_technique: settings.tcp_technique.name().to_owned(),
            sctp_technique: settings.sctp_technique.name().to_owned(),
            retry_effort: settings.retry.effort.name().to_owned(),
            retry_max_attempts: settings.retry.max_attempts.map(NonZeroU8::get),
            retry_timeout_scale: settings.retry.timeout_scale.map(TimeoutScale::get),
            retry_dampen_silent_hosts: settings.retry.dampen_silent_hosts,
            max_probe_rate: settings.max_probe_rate.map(NonZeroU32::get),
            min_probe_rate: settings.min_probe_rate.map(NonZeroU32::get),
            host_probe_interval: settings.host_probe_interval,
            host_timeout: settings.host_timeout,
            scan_timeout: settings.scan_timeout,
            dns_enabled: settings.dns_enabled,
            redact: settings.redact,
            os_detection: settings.os_detection.name().to_owned(),
            service_detection: settings.service_detection.name().to_owned(),
            detection: wire::detection_ceiling_name(settings.detection.ceiling()).to_owned(),
            traceroute: settings.traceroute,
            characterise: settings.characterise,
            ip_protocols: settings.ip_protocols.clone(),
            tls_enumeration: settings.tls_enumeration,
            listen_only_ports: settings.listen_only_ports.clone(),
            excluded_ports: settings.excluded_ports.to_string(),
            evasion: settings.evasion.as_ref().map(|e| EvasionSettingsRecord {
                source_port: e.source_port,
                ttl: e.ttl,
                padding: e.padding,
                bad_tcp_checksum: e.bad_tcp_checksum,
                spoof_mac: e.spoof_mac.map(|mac| mac.to_string()),
                fragment: e.fragment,
                decoys: e.decoys.iter().map(|ip| ip.to_string()).collect(),
                flags: e.flags.map(wire::tcp_flags_name),
            }),
            idle_scan: settings.idle_scan.map(|i| IdleScanRecord {
                zombie: i.zombie.to_string(),
                zombie_port: i.zombie_port,
            }),
            icmp_evidence: settings.icmp_evidence,
        }
    }
}

impl From<&SettingsRecord> for ScanSettings {
    fn from(record: &SettingsRecord) -> Self {
        Self {
            send_mode: record.send_mode.parse().unwrap_or_default(),
            tcp_technique: record.tcp_technique.parse().unwrap_or_default(),
            sctp_technique: record.sctp_technique.parse().unwrap_or_default(),
            retry: RetryConfig {
                effort: record.retry_effort.parse().unwrap_or_default(),
                // Read downward, as every other field of this record is: a
                // journal written by a build that accepted a zero budget or a
                // NaN scale carries a value that never applied, and reading it
                // as absent is what it always meant.
                max_attempts: record.retry_max_attempts.and_then(NonZeroU8::new),
                timeout_scale: record.retry_timeout_scale.and_then(TimeoutScale::new),
                dampen_silent_hosts: record.retry_dampen_silent_hosts,
            },
            max_probe_rate: record.max_probe_rate.and_then(NonZeroU32::new),
            min_probe_rate: record.min_probe_rate.and_then(NonZeroU32::new),
            host_probe_interval: record.host_probe_interval,
            host_timeout: record.host_timeout,
            scan_timeout: record.scan_timeout,
            dns_enabled: record.dns_enabled,
            redact: record.redact,
            os_detection: record.os_detection.parse().unwrap_or_default(),
            service_detection: record.service_detection.parse().unwrap_or_default(),
            detection: match record.detection.as_str() {
                "off" => DetectionEnvelope::none(),
                name => wire::detection_class(name)
                    .map(DetectionEnvelope::up_to)
                    .unwrap_or_default(),
            },
            traceroute: record.traceroute,
            characterise: record.characterise,
            ip_protocols: record.ip_protocols.clone(),
            tls_enumeration: record.tls_enumeration,
            listen_only_ports: record.listen_only_ports.clone(),
            // Read downward as the fields around it are. This engine writes the
            // canonical form, which always reads back.
            excluded_ports: PortSet::try_from(record.excluded_ports.as_str()).unwrap_or_default(),
            evasion: record.evasion.as_ref().map(|e| EvasionRecord {
                source_port: e.source_port,
                ttl: e.ttl,
                padding: e.padding,
                bad_tcp_checksum: e.bad_tcp_checksum,
                spoof_mac: e.spoof_mac.as_ref().and_then(|s| s.parse().ok()),
                fragment: e.fragment,
                decoys: e.decoys.iter().filter_map(|s| s.parse().ok()).collect(),
                flags: e.flags.as_deref().map(wire::tcp_flags),
            }),
            idle_scan: record.idle_scan.as_ref().and_then(|i| {
                i.zombie.parse().ok().map(|zombie| IdleScan {
                    zombie,
                    zombie_port: i.zombie_port,
                })
            }),
            icmp_evidence: record.icmp_evidence,
        }
    }
}

/// What one strategy recorded about its own run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeStatsRecord {
    /// Which strategy, by wire name.
    pub scanner: String,
    /// How many targets it was given.
    pub targets: u128,
    /// Why its receive loop stopped, by wire name.
    pub stop_reason: String,
    /// How long it ran.
    pub elapsed: Duration,
    /// How many sends it attempted.
    pub sends_attempted: u64,
    /// How many never left this host, refused or unable to reach their
    /// address.
    pub sends_failed: u64,
    /// How many were seen leaving on the wire. Defaulted, so an older record
    /// reads as a run that witnessed nothing.
    #[serde(default)]
    pub sends_witnessed: u64,
    /// How many segments its capture handed it.
    pub segments_seen: u64,
    /// Where its congestion window ended up.
    #[serde(default)]
    pub window: Option<WindowRecord>,
    /// How many captured segments belonged to something else.
    pub segments_off_target: u64,
    /// How many replies named no attempt.
    pub replies_without_rtt: u64,
    /// How many hosts it found.
    pub hosts_found: u64,
    /// How many answers arrived on each attempt.
    #[serde(default)]
    pub answered_on: Vec<u64>,
    /// How many answers could not be attributed.
    pub answered_unattributed: u64,
    /// When the first reply arrived.
    #[serde(default)]
    pub first_reply: Option<Duration>,
    /// When the last did.
    #[serde(default)]
    pub last_reply: Option<Duration>,
    /// How many hosts were found in each time bucket.
    #[serde(default)]
    pub found_at: Vec<u64>,
    /// What the capture reported about its own losses.
    #[serde(default)]
    pub capture: Option<CaptureRecord>,
}

impl From<&ProbeStats> for ProbeStatsRecord {
    fn from(stats: &ProbeStats) -> Self {
        Self {
            scanner: wire::scanner_kind_name(stats.scanner()).to_owned(),
            targets: stats.targets(),
            stop_reason: wire::stop_reason_name(stats.stop_reason()).to_owned(),
            elapsed: stats.elapsed(),
            sends_attempted: stats.sends_attempted(),
            sends_failed: stats.sends_failed(),
            sends_witnessed: stats.sends_witnessed(),
            segments_seen: stats.segments_seen(),
            window: stats.window().map(WindowRecord::from),
            segments_off_target: stats.segments_off_target(),
            replies_without_rtt: stats.replies_without_rtt(),
            hosts_found: stats.hosts_found(),
            answered_on: stats.answered_on().to_vec(),
            answered_unattributed: stats.answered_unattributed(),
            first_reply: stats.first_reply(),
            last_reply: stats.last_reply(),
            found_at: stats.found_at().to_vec(),
            capture: stats.capture().map(CaptureRecord::from),
        }
    }
}

impl From<&ProbeStatsRecord> for ProbeStats {
    fn from(record: &ProbeStatsRecord) -> Self {
        /// Copies as much of `from` as `into` has room for. A file written by a
        /// build that counted more attempts is read for the attempts this one
        /// counts, rather than refused.
        fn fill<const N: usize>(from: &[u64]) -> [u64; N] {
            let mut into = [0u64; N];
            for (slot, value) in into.iter_mut().zip(from) {
                *slot = *value;
            }
            into
        }

        ProbeStats::from_parts(ProbeStatsParts {
            scanner: wire::scanner_kind(&record.scanner).unwrap_or(ScannerKind::Composite),
            targets: record.targets,
            // An unreadable stop reason reads as the one that claims least: a
            // run that was cut short rather than one that finished.
            stop_reason: wire::stop_reason(&record.stop_reason)
                .unwrap_or(StopReason::DeadlineExpired),
            elapsed: record.elapsed,
            sends_attempted: record.sends_attempted,
            sends_failed: record.sends_failed,
            sends_witnessed: record.sends_witnessed,
            segments_seen: record.segments_seen,
            window: record.window.as_ref().map(WindowSummary::from),
            segments_off_target: record.segments_off_target,
            replies_without_rtt: record.replies_without_rtt,
            hosts_found: record.hosts_found,
            answered_on: fill(&record.answered_on),
            answered_unattributed: record.answered_unattributed,
            first_reply: record.first_reply,
            last_reply: record.last_reply,
            found_at: fill(&record.found_at),
            capture: record.capture.as_ref().map(CaptureCounts::from),
        })
    }
}

/// Where a strategy's congestion window ended up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowRecord {
    /// The capacity it finished at.
    pub capacity: usize,
    /// The largest it reached.
    pub peak: usize,
    /// How many times it was cut.
    pub reductions: u32,
    /// Whether it was allowed to adapt.
    pub adaptive: bool,
    /// Whether it ended at its floor.
    pub at_floor: bool,
}

impl From<WindowSummary> for WindowRecord {
    fn from(window: WindowSummary) -> Self {
        Self {
            capacity: window.capacity,
            peak: window.peak,
            reductions: window.reductions,
            adaptive: window.adaptive,
            at_floor: window.at_floor,
        }
    }
}

impl From<&WindowRecord> for WindowSummary {
    fn from(record: &WindowRecord) -> Self {
        Self {
            capacity: record.capacity,
            peak: record.peak,
            reductions: record.reductions,
            adaptive: record.adaptive,
            at_floor: record.at_floor,
        }
    }
}

/// What a capture reported about its own losses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureRecord {
    /// How many packets it handed over.
    pub received: u64,
    /// How many it dropped.
    pub dropped: u64,
    /// How many the interface dropped before it.
    pub if_dropped: u64,
    /// How many captures ended before they were told to.
    ///
    /// Defaulted on read, so a journal written before this was recorded opens
    /// and reports none, which is what it knew. A scan whose receive path was
    /// intact writes zero, and the two are indistinguishable in an old journal
    /// for the same reason every other field added to this record is.
    #[serde(default)]
    pub stopped_early: u64,
}

impl From<CaptureCounts> for CaptureRecord {
    fn from(counts: CaptureCounts) -> Self {
        Self {
            received: counts.received,
            dropped: counts.dropped,
            if_dropped: counts.if_dropped,
            stopped_early: counts.stopped_early,
        }
    }
}

impl From<&CaptureRecord> for CaptureCounts {
    fn from(record: &CaptureRecord) -> Self {
        Self {
            received: record.received,
            dropped: record.dropped,
            if_dropped: record.if_dropped,
            stopped_early: record.stopped_early,
        }
    }
}

/// The plan a scan ran against, as a file holds it.
///
/// Ranges and port lists rather than targets, so a `/16` on every port is a few
/// dozen bytes rather than four billion records. This is what lets a scan be
/// continued without being described again: the plan a resume needs is the one
/// that ran, not one reconstructed from what somebody typed.
///
/// A host-discovery plan is a set of addresses and no ports, and is written
/// here as a single unit whose port list is empty. One shape covers both
/// phases, so a reader does not have to know which it is holding to read the
/// addresses out of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanRecord {
    /// The units, in the order they were walked. Order is part of the plan:
    /// positions are counted through it.
    #[serde(default)]
    pub units: Vec<UnitRecord>,
}

impl PlanRecord {
    /// Every address the plan covers, whatever its ports.
    ///
    /// For a discovery plan this is the whole of it. For a port-scan plan it is
    /// the addresses with the port dimension dropped, so two units naming the
    /// same address collapse into one; a set has no room to say a thing twice.
    pub fn addresses(&self) -> IpSet {
        let mut ips = IpSet::new();
        for unit in &self.units {
            for range in unit.ranges.iter().filter_map(RangeRecord::rebuild) {
                ips.insert_range(range);
            }
        }
        ips.canonicalize();
        ips
    }
}

impl From<&IpSet> for PlanRecord {
    /// Records a host-discovery plan: the addresses, and no ports.
    fn from(addresses: &IpSet) -> Self {
        Self {
            units: vec![UnitRecord {
                ranges: ranges_of(addresses),
                spec: String::new(),
                enumerated_ports: Vec::new(),
            }],
        }
    }
}

/// An address set's ranges, v4 before v6, in the order the set enumerates them.
fn ranges_of(ips: &IpSet) -> Vec<RangeRecord> {
    ips.v4()
        .iter()
        .map(|range| RangeRecord::from(&IpRange::V4(*range)))
        .chain(
            ips.v6()
                .iter()
                .map(|range| RangeRecord::from(&IpRange::V6(*range))),
        )
        .collect()
}

/// One set of addresses paired with the ports to try on each.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRecord {
    /// The addresses, as ranges.
    #[serde(default)]
    pub ranges: Vec<RangeRecord>,
    /// The ports, as the specification [`PortSet`] parses.
    ///
    /// Written the way [`PortsRecord`] writes a phase's scope, and for the
    /// reason given there: a full sweep is six bytes rather than a hundred and
    /// thirty thousand entries, and a person reading the manifest can see what
    /// is being scanned. A [`PortSet`] is canonical from construction, so the
    /// specification and the enumeration are the same order and a position keeps
    /// its meaning across the round trip.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub spec: String,
    /// The ports one at a time, as journal format 1 wrote them.
    ///
    /// Read and never written. A journal from that format cannot be continued,
    /// which [`JOURNAL_VERSION`](crate::journal::JOURNAL_VERSION) covers, but it
    /// still reads back as the report its scan produced, and a manifest that
    /// would not deserialize takes that away too.
    #[serde(default, rename = "ports", skip_serializing_if = "Vec::is_empty")]
    pub enumerated_ports: Vec<(u16, String)>,
}

impl UnitRecord {
    /// The ports this unit walks, from whichever form the record carries.
    fn port_set(&self) -> PortSet {
        if !self.spec.is_empty()
            && let Ok(ports) = PortSet::try_from(self.spec.as_str())
        {
            return ports;
        }

        self.enumerated_ports
            .iter()
            .filter_map(|(port, protocol)| wire::protocol(protocol).map(|p| (*port, p)))
            .collect()
    }
}

impl From<&TargetMap> for PlanRecord {
    fn from(plan: &TargetMap) -> Self {
        Self {
            units: plan
                .units
                .iter()
                .map(|unit| UnitRecord {
                    ranges: ranges_of(unit.ips()),
                    spec: unit.ports().to_string(),
                    enumerated_ports: Vec::new(),
                })
                .collect(),
        }
    }
}

impl From<&PlanRecord> for TargetMap {
    fn from(record: &PlanRecord) -> Self {
        let mut plan = TargetMap::new();

        for unit in &record.units {
            let mut ips = IpSet::new();
            for range in unit.ranges.iter().filter_map(RangeRecord::rebuild) {
                ips.insert_range(range);
            }

            let ports = unit.port_set();

            // A unit with nothing left in it would renumber every position after
            // it, so an unreadable one is kept as an empty unit rather than
            // dropped. It contributes no targets and holds its place.
            plan.add_unit(TargetSet::new(ips, ports));
        }

        plan
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
    use crate::model::host::{HostStatus, NetworkRole};
    use crate::model::mac::MacAddr;
    use crate::model::port::Protocol;
    use std::net::Ipv4Addr;
    use std::time::UNIX_EPOCH;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    /// A host carrying something in every field the model has.
    ///
    /// The oracle below is only as good as this is complete: a field nothing
    /// populates is a field the round trip is not tested on. When the model
    /// gains one, it belongs here.
    fn maximal_host() -> Host {
        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        host.add_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)));
        host.add_ip("2001:db8::1".parse().expect("an address"));
        host.set_hostname(Some("router.example".to_string()));
        host.set_status(HostStatus::Up);
        // Every kind, from every source, so a name the record drops for either
        // reason fails the round trip below.
        for kind in crate::model::host::NameKind::ALL {
            for source in crate::model::host::NameSource::ALL {
                let name = format!("{kind:?}-{source:?}.example");
                host.record_name(HostName::new(kind, source, &name).expect("a name"));
            }
        }

        let mut arp = StatusReason::new(StatusProtocol::Arp, "reply from gateway");
        arp.source = EvidenceSource::Intermediary(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)));
        host.add_reason(arp);
        let mut unreachable = StatusReason::basic(StatusProtocol::IcmpUnreachable);
        unreachable.source = EvidenceSource::Withheld;
        host.add_reason(unreachable);
        host.add_reason(StatusReason::new(
            StatusProtocol::Custom("a-strategy".into()),
            "said so",
        ));

        let mut os = OsFingerprint::new("Linux 5.15", 95)
            .with_family("Unix-like")
            .with_generation("5.15.0")
            .with_vendor("Canonical")
            .with_kernel("5.15.0-91-generic")
            .with_detail_accuracy(70)
            .with_evidence("syn-ack hops>=64 opts=M,S,T,N,W");
        os.add_cpe("cpe:/o:linux:linux_kernel:5.15.0");
        os.add_cpe("cpe:/o:canonical:ubuntu_linux:22.04");
        host.set_os(os);

        host.record_os_evidence(OsEvidence {
            source: OsSource::TcpStack,
            family: Some("Linux".to_string()),
            device: None,
            vendor: Some("Canonical".to_string()),
            product: Some("Ubuntu".to_string()),
            version: Some("22.04".to_string()),
            kernel: Some("5.15.0".to_string()),
            arch: None,
            cpe: Some("cpe:/o:canonical:ubuntu_linux:22.04".to_string()),
            confidence: 0.65,
            evidence: "stack reading".to_string(),
        });
        host.record_os_evidence(OsEvidence {
            source: OsSource::ServiceBanner,
            family: Some("Linux".to_string()),
            device: None,
            vendor: None,
            product: None,
            version: None,
            kernel: None,
            arch: None,
            cpe: None,
            confidence: 0.4,
            evidence: "ssh banner".to_string(),
        });

        host.record_mac(MacAddr::new(0x2c, 0xcf, 0x67, 0x00, 0x00, 0x01));
        host.record_mac(MacAddr::new(0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e));
        host.set_zone(Zone::new(7, "eth0"));

        host.add_rtts([
            Duration::from_micros(1_200),
            Duration::from_micros(1_800),
            Duration::from_micros(3_000),
        ]);
        host.record_hop_counter(58);

        host.record_hop(Hop::answered(
            3,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            Some(Duration::from_micros(4_100)),
        ));
        host.record_hop(Hop::silent(2));
        host.record_hop(
            Hop::answered(1, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)), None).as_inferred(),
        );
        host.record_hop(Hop::withheld(4).as_inferred());

        host.add_network_role(NetworkRole::Tarpit);
        host.add_network_role(NetworkRole::Truncated);

        host.record_ip_protocol(47, IpProtocolState::Open);
        host.record_ip_protocol(89, IpProtocolState::Closed);
        host.record_ip_protocol(103, IpProtocolState::Unasked);

        host.add_port(maximal_port());
        host.add_port(Port::new(53, Protocol::Udp, PortState::OpenFiltered));
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Closed));

        host.add_finding(maximal_finding());

        host.restore_seen(at(1_700_000_000), at(1_700_003_600));
        host
    }

    fn maximal_port() -> Port {
        let service = Service::new("http", 100)
            .with_product("nginx")
            .with_vendor("F5")
            .with_version("1.24.0")
            .with_extrainfo("Ubuntu")
            .with_cpe("cpe:/a:nginx:nginx:1.24.0");

        let certificate = CertificateInfo::new(
            "example.com",
            "R3",
            at(1_690_000_000),
            at(1_720_000_000),
            "ab:cd:ef",
        )
        .with_sans(["example.com".into(), "www.example.com".into()])
        .with_public_key("rsa", 2048);

        let support = TlsSupport::new()
            .accepting(VersionSupport::new(
                TlsVersion::Tls12,
                vec![CipherSuite::from_code(0xC02F).expect("a registered suite")],
                vec![0xFF01],
            ))
            .leaving_unfinished(UnfinishedVersion::new(
                TlsVersion::Tls12,
                Interruption::Unanswered,
            ));

        let security = Security::new()
            .with_tls_version("TLSv1.3")
            .with_cipher_suite("TLS_AES_256_GCM_SHA384")
            .with_alpn("h2")
            .with_alpn("http/1.1")
            .with_certificate(certificate)
            .with_support(support);

        let discovery = Discovery::new(ScanResponse::TcpSynAck)
            .seen_at(at(1_700_000_500))
            .with_rtt(Duration::from_micros(2_400))
            .with_ttl(58)
            .with_source_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));

        let mut port = Port::new(443, Protocol::Tcp, PortState::Open)
            .with_service(service)
            .with_security(security)
            .with_discovery(discovery);
        port.add_finding(maximal_finding());
        port
    }

    /// The oracle.
    ///
    /// A host rendered through the export path before and after a round trip has
    /// to render identically. The export DTO is an independent, complete view of
    /// a host, so a field the record forgets to carry shows up here as a
    /// difference. That keeps this honest as the model grows, with no
    /// hand-written comparison to maintain.
    #[test]
    fn a_fully_populated_host_survives_a_round_trip() {
        let original = maximal_host();
        let rebuilt = Host::from(&HostRecord::from(&original));

        let options = crate::export::ExportOptions::default();
        let render = |host: &Host| {
            serde_json::to_value(crate::export::schema::HostDto::new(host, &options))
                .expect("a host renders")
        };

        assert_eq!(
            render(&original),
            render(&rebuilt),
            "a field was lost in the round trip"
        );
    }

    fn maximal_finding() -> Finding {
        Finding::new(
            DetectionId::new("grafana-path-traversal", Version::new(1, 2, 3), "deadbeef").unwrap(),
            "Grafana plugin path traversal",
            Severity::Critical,
            Confidence::Strong,
            DetectionClass::ActiveBenign,
        )
        .unwrap()
        .with_excerpt(Excerpt::new("root:x:0:0:root:/root:/bin/bash"))
        .with_reference(Reference::cve("CVE-2021-43798").unwrap())
        .with_reference(Reference::cwe(22))
        .with_reference(Reference::url("https://grafana.com/security/"))
        .with_remediation("Upgrade to 8.3.1 or later.")
        .with_cpe("cpe:/a:grafana:grafana:8.3.0")
        .with_cpe("cpe:2.3:a:grafana:grafana:8.3.0:*:*:*:*:*:*:*")
    }

    #[test]
    fn a_fully_populated_finding_survives_a_round_trip() {
        let original = maximal_finding();
        let rebuilt = FindingRecord::from(&original)
            .rebuild()
            .expect("a finding rebuilds");
        assert_eq!(original, rebuilt, "a field was lost in the round trip");
    }

    /// A record written before a finding could name more than one identifier
    /// carries its one in `cpe`, and reads back resting on it.
    #[test]
    fn a_finding_recorded_with_one_identifier_reads_back_resting_on_it() {
        let mut record = FindingRecord::from(&maximal_finding());
        record.cpes.clear();
        let rebuilt = record.rebuild().expect("a finding rebuilds");

        assert_eq!(
            rebuilt.cpes().collect::<Vec<_>>(),
            ["cpe:/a:grafana:grafana:8.3.0"]
        );
    }

    #[test]
    fn a_finding_record_reads_unknown_names_downward_and_a_nameless_one_away() {
        // A record this build does not fully understand still yields a finding,
        // read to the least it could claim, never guessed upward and never
        // dropped over a soft field.
        let softened = FindingRecord {
            detection: DetectionIdRecord {
                id: "det".into(),
                version: "not-a-version".into(), // -> 0.0.0
                content_hash: "h".into(),
            },
            title: "A finding".into(),
            severity: "catastrophic".into(), // -> Info
            confidence: "absolute".into(),   // -> Heuristic
            class: "nosy".into(),            // -> Passive
            excerpt: None,
            references: vec![ReferenceRecord {
                kind: "mystery".into(),
                value: "x".into(),
            }],
            remediation: None,
            cpe: None,
            cpes: Vec::new(),
        };
        let finding = softened
            .rebuild()
            .expect("an unparseable-but-named finding still rebuilds");
        assert_eq!(finding.severity(), Severity::Info);
        assert_eq!(finding.confidence(), Confidence::Heuristic);
        assert_eq!(finding.class(), DetectionClass::Passive);
        assert_eq!(finding.detection().version(), Version::new(0, 0, 0));
        assert_eq!(
            finding.references().count(),
            0,
            "an unknown reference is dropped, the finding kept"
        );

        // A finding that names no detection, or has no title, is not a finding.
        // Those two are refused rather than softened.
        let nameless = FindingRecord {
            detection: DetectionIdRecord {
                id: "  ".into(),
                ..softened.detection.clone()
            },
            ..softened.clone()
        };
        assert!(nameless.rebuild().is_none());
        let titleless = FindingRecord {
            title: "  ".into(),
            ..softened.clone()
        };
        assert!(titleless.rebuild().is_none());
    }

    #[test]
    fn a_hosts_findings_survive_a_record_round_trip() {
        // The silent failure guarded here: a HostRecord that carries ports but
        // forgets findings would round-trip a host with its findings gone.
        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
        host.add_finding(maximal_finding());
        let rebuilt = Host::from(&HostRecord::from(&host));

        let original: Vec<_> = host.findings().cloned().collect();
        let round: Vec<_> = rebuilt.findings().cloned().collect();
        assert_eq!(original, round, "a host's findings were lost in the record");
    }

    #[test]
    fn a_ports_findings_survive_a_record_round_trip() {
        let mut port = Port::new(3000, Protocol::Tcp, PortState::Open);
        port.add_finding(maximal_finding());
        let rebuilt = PortRecord::from(&port)
            .rebuild()
            .expect("a TCP port rebuilds");

        let original: Vec<_> = port.findings().cloned().collect();
        let round: Vec<_> = rebuilt.findings().cloned().collect();
        assert_eq!(original, round, "a port's findings were lost in the record");
    }

    /// The record is the same after a round trip through the model, which
    /// catches a rebuild that drops something the record did carry.
    #[test]
    fn the_record_is_stable_across_a_rebuild() {
        let record = HostRecord::from(&maximal_host());
        let rebuilt = HostRecord::from(&Host::from(&record));

        assert_eq!(record, rebuilt);
    }

    /// And through a file, which is what it exists for.
    #[test]
    fn the_record_survives_json() {
        let record = HostRecord::from(&maximal_host());

        let text = serde_json::to_string(&record).expect("serializes");
        let read: HostRecord = serde_json::from_str(&text).expect("deserializes");

        assert_eq!(record, read);
    }

    /// The times a host was first and last seen are evidence, and a scan
    /// resumed the next morning must not report having first seen everything
    /// that morning.
    #[test]
    fn the_times_a_host_was_seen_survive() {
        let rebuilt = Host::from(&HostRecord::from(&maximal_host()));

        assert_eq!(rebuilt.first_seen(), at(1_700_000_000));
        assert_eq!(rebuilt.last_seen(), at(1_700_003_600));
    }

    /// A record naming values this build does not know reads as the least it
    /// could have established, never as more.
    #[test]
    fn unknown_names_read_downwards() {
        let mut record = HostRecord::from(&maximal_host());
        let recorded = record.ports.len();
        let unreadable = (record.ports[0].port, record.ports[0].protocol.clone());
        record.status = "ascended".to_string();
        record.ports[0].state = "ajar".to_string();
        record.ports[0].protocol = "dccp".to_string();

        let rebuilt = Host::from(&record);

        assert_eq!(rebuilt.status(), HostStatus::Unknown);

        // A status and a state have an ordering with a bottom, so an unreadable
        // one can read as the bottom and claim nothing.
        //
        // **A protocol has no ordering**, and that is why it is the exception.
        // TCP is not *less* than a transport this build cannot name; it is a
        // different one, and ports are keyed by `(number, protocol)`. Reading
        // the unknown record as TCP therefore collides it with the real TCP port
        // of that number and `add_port` merges the two — so the service named on
        // an endpoint this build could not read would be reported as running on
        // one it could. Leaving the record out is the only reading that claims
        // nothing.
        assert_eq!(
            rebuilt.ports().count(),
            recorded - 1,
            "the one port under an unreadable protocol is dropped and the rest stay"
        );
        assert!(
            !rebuilt.ports().any(|port| port.number() == unreadable.0
                && wire::protocol_name(port.protocol()) == unreadable.1),
            "and it is not filed under the protocol it was originally written as"
        );

        // And a state this build cannot read, under a protocol it can, still
        // reads as the bottom rather than being dropped.
        let mut record = HostRecord::from(&maximal_host());
        record.ports[0].state = "ajar".to_string();
        let number = record.ports[0].port;
        let protocol = wire::protocol(&record.ports[0].protocol).expect("a readable protocol");

        let rebuilt = Host::from(&record);
        let port = rebuilt
            .ports()
            .find(|port| port.number() == number && port.protocol() == protocol)
            .expect("the port is still recorded");
        assert_eq!(
            port.state(),
            PortState::Unasked,
            "a verdict this build cannot read is no verdict, which is what the \
             bottom of the ordering says"
        );
    }

    /// **A record this build cannot read does not become a claim about one it
    /// can.**
    ///
    /// `Protocol` is `#[non_exhaustive]`, so a later build may record an
    /// endpoint under a transport this one has never heard of. Ports are keyed
    /// by number and protocol, so misreading that as TCP collides it with the
    /// real TCP port of the same number, and `add_port` merges rather than
    /// replaces: the two endpoints become one, and whichever fields the unknown
    /// one carried are reported on the known one.
    #[test]
    fn an_unreadable_protocol_does_not_contaminate_the_port_it_would_collide_with() {
        let mut host = Host::new("192.0.2.1".parse().expect("literal"));
        host.set_status(HostStatus::Up);
        host.add_port(Port::new(443, Protocol::Tcp, PortState::Open));

        let record = HostRecord::from(&host);
        let mut value: serde_json::Value = serde_json::to_value(&record).expect("serialises");

        // What a later build writes: the same number, a transport this build
        // does not know, and a service of its own.
        let mut future = value["ports"][0].clone();
        future["protocol"] = serde_json::json!("quic");
        future["state"] = serde_json::json!("closed");
        future["service"] = serde_json::json!({"name": "quic-only", "confidence": 95});
        value["ports"]
            .as_array_mut()
            .expect("an array")
            .push(future);

        let read: HostRecord = serde_json::from_value(value).expect("reads back");
        let rebuilt = Host::from(&read);

        let ports: Vec<_> = rebuilt.ports().collect();
        assert_eq!(ports.len(), 1, "the readable port, and only it");
        assert_eq!(ports[0].protocol(), Protocol::Tcp);
        assert_eq!(ports[0].state(), PortState::Open);
        assert!(
            ports[0].service().is_none(),
            "the TCP port must not acquire a service named on an endpoint this \
             build could not read"
        );
    }

    /// **The same holds for a port record rebuilt on its own.**
    ///
    /// The record types are public, so the host rebuild is not the only way
    /// in: a caller holding a `PortRecord` rebuilds it directly. A record under
    /// a transport this build cannot read has to come back as no port there as
    /// well, or the collision the host rebuild avoids reappears one level down,
    /// in whatever map of ports the caller keeps.
    #[test]
    fn a_port_record_under_an_unreadable_transport_rebuilds_as_no_port() {
        let mut record = PortRecord::from(&Port::new(443, Protocol::Tcp, PortState::Open));
        record.protocol = "quic".to_string();

        assert_eq!(
            record.rebuild(),
            None,
            "a transport this build cannot read is not TCP, or any other it can"
        );

        // An unreadable state is the contrast: it has a bottom to read down to.
        let mut record = PortRecord::from(&Port::new(443, Protocol::Tcp, PortState::Open));
        record.state = "ajar".to_string();
        let port = record.rebuild().expect("a readable transport rebuilds");
        assert_eq!(port.protocol(), Protocol::Tcp);
        assert_eq!(port.state(), PortState::Unasked);
    }

    /// A phase survives the round trip, statistics included.
    ///
    /// Rendered through the export path before and after, for the reason the
    /// host oracle gives: it is an independent view, so a field the record
    /// forgets shows up as a difference rather than as silence.
    /// A plan's ports survive as a specification, and a manifest from format 1
    /// still reads.
    ///
    /// The enumeration is what positions are counted through, so the two forms
    /// have to agree about it exactly. They do because a `PortSet` is canonical
    /// from construction: the specification is written from the same order it is
    /// read back into.
    #[test]
    fn a_plans_ports_round_trip_as_a_specification() {
        use crate::model::ip::set::IpSet;
        use crate::model::target::TargetSet;

        let mut plan = TargetMap::new();
        plan.add_unit(TargetSet::new(
            "192.0.2.0/30".parse::<IpSet>().expect("a range"),
            "80,443,1000-1010,u:53".parse::<PortSet>().expect("ports"),
        ));

        let record = PlanRecord::from(&plan);
        assert!(
            record.units[0].enumerated_ports.is_empty(),
            "the enumerated form is read and never written"
        );
        assert_eq!(
            TargetMap::from(&record).iter().collect::<Vec<_>>(),
            plan.iter().collect::<Vec<_>>(),
            "the enumeration a position is counted through has to be identical"
        );

        // Six bytes and change, rather than one entry per port.
        assert!(record.units[0].spec.len() < 40, "{}", record.units[0].spec);

        // And a manifest written before the specification existed still reads.
        let legacy = PlanRecord {
            units: vec![UnitRecord {
                ranges: record.units[0].ranges.clone(),
                spec: String::new(),
                enumerated_ports: plan.units[0]
                    .ports()
                    .iter()
                    .map(|(port, protocol)| (port, wire::protocol_name(protocol).to_owned()))
                    .collect(),
            }],
        };
        assert_eq!(
            TargetMap::from(&legacy).iter().collect::<Vec<_>>(),
            plan.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_phase_survives_a_round_trip() {
        let report = crate::export::fixture::report();

        for phase in report.phases() {
            let rebuilt = ScanPhase::from(&PhaseRecord::from(phase));

            let options = crate::export::ExportOptions::default();
            let render = |phase: &ScanPhase| {
                serde_json::to_value(crate::export::schema::PhaseDto::new(phase, &options))
                    .expect("a phase renders")
            };
            assert_eq!(render(phase), render(&rebuilt), "a field was lost");
        }
    }

    /// A capture that stopped early survives the journal, and an older journal
    /// that never recorded one still opens.
    ///
    /// A log line is not the record: were the count only logged, a resumed
    /// scan, or a report read a week later, would have no way to know part of
    /// the receive path was missing for part of the run, and the counts beside
    /// it would look like a complete measurement.
    #[test]
    fn a_capture_that_stopped_early_survives_the_journal() {
        let counts = CaptureCounts {
            received: 271,
            dropped: 4,
            if_dropped: 1,
            stopped_early: 2,
        };

        let record = CaptureRecord::from(counts);
        assert_eq!(CaptureCounts::from(&record), counts, "a field was lost");

        // Through the serialized form the journal actually holds.
        let json = serde_json::to_string(&record).expect("a record serializes");
        assert!(json.contains("stopped_early"), "{json}");
        let read: CaptureRecord = serde_json::from_str(&json).expect("and reads back");
        assert_eq!(CaptureCounts::from(&read), counts);

        // A journal written before this was recorded opens and reports none,
        // which is what it knew.
        let older = r#"{"received":271,"dropped":4,"if_dropped":1}"#;
        let read: CaptureRecord = serde_json::from_str(older).expect("an older journal opens");
        assert_eq!(CaptureCounts::from(&read).stopped_early, 0);
        assert_eq!(CaptureCounts::from(&read).received, 271);
    }

    /// Privilege is a `Privilege` in the model and a boolean on the wire, and
    /// this is where the two meet.
    ///
    /// The journal's format and the published report schema both promise a
    /// boolean, so the conversion has to be exact in both directions and cannot
    /// drift with the enum. A flipped polarity here would report every
    /// unprivileged scan as privileged in an archived report, which is a claim
    /// about what a result is worth rather than a cosmetic error.
    ///
    /// Driven off a real phase with only this field varied, so it stays true as
    /// `PhaseParts` grows.
    #[test]
    fn privilege_crosses_the_record_boundary_as_the_boolean_the_format_promised() {
        let report = crate::export::fixture::report();
        let original = report.phases().first().expect("the fixture has a phase");

        for (privilege, written) in [
            (Some(Privilege::Raw), Some(true)),
            (Some(Privilege::Connect), Some(false)),
            // A third state, not a missing boolean: a phase read out of another
            // scanner's document is not a phase that ran unprivileged.
            (None, None),
        ] {
            let mut record = PhaseRecord::from(original);
            record.privileged = written;

            let phase = ScanPhase::from(&record);
            assert_eq!(phase.privilege(), privilege, "reading {written:?}");
            assert_eq!(
                PhaseRecord::from(&phase).privileged,
                written,
                "writing {privilege:?}"
            );
        }
    }

    /// The detection envelope has to come back as what the scan ran, not as the
    /// default: a report replayed from a journal must gate a re-analysis the same
    /// way the live scan did.
    /// What a silence means depends on this, so a record that lost it would
    /// leave every filtered port's `no reply` unreadable.
    /// A record that lost which probe measured its round trips would read them
    /// back as figures nobody can place.
    #[test]
    fn the_probe_behind_a_round_trip_survives_the_record() {
        use crate::model::host::StatusProtocol;

        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
        host.add_rtt_from(Duration::from_micros(90), StatusProtocol::Arp);
        host.add_rtt_from(Duration::from_micros(110), StatusProtocol::Arp);

        let record = HostRecord::from(&host);
        assert_eq!(record.telemetry.rtt_protocol.as_deref(), Some("arp"));

        let mut restored = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
        record.telemetry.restore(&mut restored);

        assert_eq!(restored.rtt_protocol(), Some(StatusProtocol::Arp));
        assert_eq!(restored.min_rtt(), host.min_rtt());
    }

    #[test]
    fn asking_for_icmp_evidence_survives_the_settings_round_trip() {
        use crate::config::ZondConfig;

        let mut settings = ScanSettings::from(&ZondConfig::default());
        assert!(settings.icmp_evidence, "on unless declined");

        // Both ways round: a run that declined it has to say so, or a reader
        // cannot tell a scan that saw no errors from one that never looked.
        settings.icmp_evidence = false;
        assert!(!ScanSettings::from(&SettingsRecord::from(&settings)).icmp_evidence);

        settings.icmp_evidence = true;
        assert!(ScanSettings::from(&SettingsRecord::from(&settings)).icmp_evidence);
    }

    #[test]
    fn the_detection_envelope_survives_the_settings_round_trip() {
        use crate::config::DetectionEnvelope;
        use crate::config::ZondConfig;
        use crate::model::finding::DetectionClass;
        use crate::report::ScanSettings;

        // A raised ceiling, so the round trip must carry the value rather than
        // fall back to the default it happens to start at.
        let mut settings = ScanSettings::from(&ZondConfig::default());
        settings.detection = DetectionEnvelope::up_to(DetectionClass::Exploit);

        let rebuilt = ScanSettings::from(&SettingsRecord::from(&settings));
        assert_eq!(
            rebuilt.detection.ceiling(),
            Some(DetectionClass::Exploit),
            "the envelope ceiling was lost in the round trip"
        );
    }

    /// And through a file.
    #[test]
    fn a_phase_survives_json() {
        let report = crate::export::fixture::report();

        for phase in report.phases() {
            let record = PhaseRecord::from(phase);
            let text = serde_json::to_string(&record).expect("serializes");
            let read: PhaseRecord = serde_json::from_str(&text).expect("deserializes");

            assert_eq!(record, read);
        }
    }

    /// What a scan measured has to come back as what a scan measured.
    ///
    /// A replayed report is rendered by the same code the live run used, so
    /// anything the record drops shows up as a quieter report rather than an
    /// error: fewer protocols behind a host, a round trip with no spread.
    #[test]
    fn a_hosts_measurements_survive_the_round_trip() {
        use crate::model::host::{HostStatus, StatusProtocol, StatusReason};
        use std::time::Duration;

        let mut host = Host::new("192.0.2.1".parse().expect("an address"));
        host.set_status(HostStatus::Up);

        for protocol in [
            StatusProtocol::Arp,
            StatusProtocol::IcmpEcho,
            StatusProtocol::TcpSyn,
        ] {
            host.record_evidence(HostStatus::Up, StatusReason::new(protocol, "answered"));
        }
        host.add_rtts([
            Duration::from_micros(5_100),
            Duration::from_micros(6_060),
            Duration::from_micros(6_540),
        ]);

        let restored = Host::from(&HostRecord::from(&host));

        assert_eq!(
            restored.reasons().len(),
            host.reasons().len(),
            "a protocol that answered was lost"
        );
        assert_eq!(restored.min_rtt(), host.min_rtt(), "the fastest round trip");
        assert_eq!(restored.max_rtt(), host.max_rtt(), "the slowest");
        assert_eq!(restored.average_rtt(), host.average_rtt(), "the mean");
    }
}
