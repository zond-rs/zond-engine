// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The comparison document
//!
//! What a consumer parses, and the single site where a change is given its name.
//! [`ChangeDto::of_host`] and [`ChangeDto::of_port`] are how the engine's typed
//! deltas become that vocabulary, and a front end printing one line per change
//! calls them too — so a comparison in a terminal and one in a queue name the
//! same event the same way.
//!
//! The conventions of the report document hold here without exception:
//! timestamps are RFC 3339 in UTC, objects have a fixed shape with `null` rather
//! than an absent field, order is deterministic, and unknown fields may appear.
//! See [`export::schema`](crate::export::schema) for the whole of them.

use serde::Serialize;

use crate::diff::{
    CertificateChange, Confirmed, Coverage, DiffSummary, HostChange, HostDelta, PortChange,
    PortDelta, Presence, ScanDiff, SecurityChange, ServiceChange,
};
use crate::export::ExportOptions;
use crate::export::schema::{EngineDto, HostDto};
use crate::format::time::rfc3339;
use crate::model::host::os::OsFingerprint;
use crate::record::wire::{host_status_name, port_state_name, protocol_name, scan_kind_name};

pub use crate::format::{DIFF_SCHEMA_VERSION, ENGINE_NAME};

// ---------------------------------------------------------------------------
// The names a change is known by
//
// Public because they are the contract: an alerting rule keys on one of these
// strings, and a front end printing a comparison prints the same ones.
// ---------------------------------------------------------------------------

/// Whether a host or an endpoint is in one scan or both.
pub fn presence_name(presence: Presence) -> &'static str {
    match presence {
        Presence::Both => "both",
        Presence::Added { .. } => "added",
        Presence::Removed { .. } => "removed",
    }
}

/// What a report says about having walked a target.
pub fn coverage_name(coverage: Coverage) -> &'static str {
    match coverage {
        Coverage::Covered => "covered",
        Coverage::Withheld => "withheld",
        Coverage::OutOfScope => "out_of_scope",
        Coverage::Unstated => "unstated",
    }
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// The root of a comparison document.
///
/// Borrows the comparison rather than copying it, and serializes host deltas
/// from an iterator, so one delta exists at a time however large the comparison.
#[derive(Debug, Serialize)]
pub struct DiffDto<'a> {
    /// The version of this document's shape. Counted apart from the report's.
    pub schema_version: u32,
    /// Which build wrote the document — not which produced either scan, for
    /// which see `baseline` and `current`.
    pub engine: EngineDto,
    /// When the comparison was taken.
    pub generated_at: String,
    /// The earlier scan.
    pub baseline: ProvenanceDto,
    /// The later scan.
    pub current: ProvenanceDto,
    /// Whether the two scans describe the same network.
    ///
    /// Derivable from an empty `hosts`, and stated because it is the first
    /// question every consumer asks and the cheapest one to answer.
    pub unchanged: bool,
    /// Counts over everything below.
    pub summary: SummaryDto,
    /// Every host that differs, ascending by address. Hosts that did not are
    /// not here.
    pub hosts: Vec<HostDeltaDto<'a>>,
}

impl<'a> DiffDto<'a> {
    /// Renders a comparison, applying the redaction policy in `options`.
    pub fn new(diff: &'a ScanDiff, options: &ExportOptions) -> Self {
        Self {
            schema_version: DIFF_SCHEMA_VERSION,
            engine: EngineDto {
                name: ENGINE_NAME,
                version: crate::report::ENGINE_VERSION,
            },
            generated_at: rfc3339(std::time::SystemTime::now()),
            baseline: ProvenanceDto::new(diff.baseline()),
            current: ProvenanceDto::new(diff.current()),
            unchanged: diff.is_empty(),
            summary: SummaryDto::new(&diff.summary()),
            hosts: diff
                .hosts()
                .iter()
                .map(|host| HostDeltaDto::new(host, options))
                .collect(),
        }
    }
}

/// Which scan one side of the comparison was.
#[derive(Debug, Serialize)]
pub struct ProvenanceDto {
    /// The engine that produced the report, as it attributed itself. A report
    /// built from another tool's output says so — `nmap 7.94` and not this
    /// crate.
    pub engine_version: String,
    /// The moment the scan is judged to have happened, and the moment its
    /// certificates were judged against.
    pub at: String,
    /// How many hosts the report held.
    pub hosts: usize,
    /// Which phases it recorded, in the order they ran.
    pub kinds: Vec<&'static str>,
    /// Whether the report says what it covered.
    ///
    /// `false` makes every coverage answer about this side `unstated`, so
    /// nothing appearing or disappearing against it can be confirmed.
    pub states_scope: bool,
}

impl ProvenanceDto {
    /// Renders one side's provenance.
    pub fn new(provenance: &crate::diff::Provenance) -> Self {
        Self {
            engine_version: provenance.engine_version().to_owned(),
            at: rfc3339(provenance.at()),
            hosts: provenance.hosts(),
            kinds: provenance
                .kinds()
                .iter()
                .copied()
                .map(scan_kind_name)
                .collect(),
            states_scope: provenance.states_scope(),
        }
    }
}

/// A count, and how much of it the other scan is known to have looked for.
#[derive(Debug, Serialize)]
pub struct ConfirmedDto {
    /// How many, whatever the other scan covered.
    pub total: usize,
    /// How many the other scan is known to have covered. **A consumer that
    /// alerts on one of these numbers should alert on this one.**
    pub confirmed: usize,
}

impl ConfirmedDto {
    /// Renders a split count.
    pub fn new(count: Confirmed) -> Self {
        Self {
            total: count.total,
            confirmed: count.confirmed,
        }
    }
}

/// Counts over the whole comparison.
#[derive(Debug, Serialize)]
pub struct SummaryDto {
    /// Hosts only the later scan has a record for.
    pub hosts_added: ConfirmedDto,
    /// Hosts only the earlier scan has a record for.
    pub hosts_removed: ConfirmedDto,
    /// Hosts both scans have, that differ.
    pub hosts_changed: usize,
    /// Endpoints accepting connections now that were not before.
    pub ports_opened: ConfirmedDto,
    /// Endpoints that were accepting connections and are not now.
    pub ports_closed: ConfirmedDto,
    /// Endpoints both scans have, that differ.
    pub ports_changed: usize,
    /// Endpoints where what is listening changed, or was identified where it
    /// was not.
    pub services_changed: usize,
    /// Endpoints presenting a different certificate than before.
    pub certificates_rotated: usize,
    /// Endpoints whose certificate is now inside the expiry threshold and was
    /// not when the earlier scan ran.
    pub certificates_expiring: usize,
    /// Endpoints whose certificate has lapsed since the earlier scan.
    pub certificates_expired: usize,
}

impl SummaryDto {
    /// Renders the derived counts.
    pub fn new(summary: &DiffSummary) -> Self {
        Self {
            hosts_added: ConfirmedDto::new(summary.hosts_added),
            hosts_removed: ConfirmedDto::new(summary.hosts_removed),
            hosts_changed: summary.hosts_changed,
            ports_opened: ConfirmedDto::new(summary.ports_opened),
            ports_closed: ConfirmedDto::new(summary.ports_closed),
            ports_changed: summary.ports_changed,
            services_changed: summary.services_changed,
            certificates_rotated: summary.certificates_rotated,
            certificates_expiring: summary.certificates_expiring,
            certificates_expired: summary.certificates_expired,
        }
    }
}

/// One host, as the two scans between them hold it.
#[derive(Debug, Serialize)]
pub struct HostDeltaDto<'a> {
    /// The address the host is reported under: the later scan's primary where it
    /// has a record, and the earlier scan's where it does not.
    pub address: String,
    /// `both`, `added` or `removed`.
    pub presence: &'static str,
    /// What the scan *lacking* a record says about having covered this address.
    /// `null` when both hold one, where the question does not arise.
    pub coverage: Option<&'static str>,
    /// Whether this is a finding about the network rather than about the scan.
    ///
    /// True when both scans hold a record, and when the one that does not is
    /// known to have covered the address anyway. **This is the field to alert
    /// on.**
    pub confirmed: bool,
    /// How many records each scan held for this host. `{1, 1}` ordinarily.
    pub records: RecordsDto,
    /// Whether the two scans grouped this host's addresses differently: what one
    /// holds as a single record the other holds as several. Both sides are still
    /// compared, merged.
    pub regrouped: bool,
    /// What moved about the host itself.
    pub changes: Vec<ChangeDto>,
    /// Every endpoint that moved, ascending by number and then transport.
    pub ports: Vec<PortDeltaDto>,
    /// The earlier scan's whole record, in the report document's schema.
    pub baseline: Option<HostDto<'a>>,
    /// The later scan's whole record.
    pub current: Option<HostDto<'a>>,
}

impl<'a> HostDeltaDto<'a> {
    /// Renders one host's comparison.
    pub fn new(delta: &'a HostDelta, options: &ExportOptions) -> Self {
        let (baseline_records, current_records) = delta.records();

        Self {
            address: delta.address().to_string(),
            presence: presence_name(delta.presence()),
            coverage: delta.presence().counterpart_coverage().map(coverage_name),
            confirmed: delta.presence().is_confirmed(),
            records: RecordsDto {
                baseline: baseline_records,
                current: current_records,
            },
            regrouped: delta.is_regrouped(),
            changes: delta
                .changes()
                .iter()
                .flat_map(|change| ChangeDto::of_host(change, options))
                .collect(),
            ports: delta
                .ports()
                .iter()
                .map(|port| PortDeltaDto::new(port, options))
                .collect(),
            baseline: delta.baseline().map(|host| HostDto::new(host, options)),
            current: delta.current().map(|host| HostDto::new(host, options)),
        }
    }
}

/// How many records each scan held for one host.
#[derive(Debug, Serialize)]
pub struct RecordsDto {
    /// The earlier scan's count.
    pub baseline: usize,
    /// The later scan's count.
    pub current: usize,
}

/// One endpoint, as the two scans between them hold it.
#[derive(Debug, Serialize)]
pub struct PortDeltaDto {
    /// The port number, the same in both scans.
    pub port: u16,
    /// The transport, the same in both scans.
    pub protocol: &'static str,
    /// `both`, `added` or `removed`.
    pub presence: &'static str,
    /// What the scan lacking a record says about having probed this endpoint.
    /// `null` when both hold one.
    pub coverage: Option<&'static str>,
    /// Whether this is a finding about the network. **The field to alert on.**
    pub confirmed: bool,
    /// Whether the endpoint accepts connections now and did not before.
    pub opened: bool,
    /// Whether it accepted connections before and does not now.
    pub closed: bool,
    /// What moved about the endpoint.
    pub changes: Vec<ChangeDto>,
}

impl PortDeltaDto {
    /// Renders one endpoint's comparison.
    pub fn new(delta: &PortDelta, options: &ExportOptions) -> Self {
        Self {
            port: delta.number(),
            protocol: protocol_name(delta.protocol()),
            presence: presence_name(delta.presence()),
            coverage: delta.presence().counterpart_coverage().map(coverage_name),
            confirmed: delta.presence().is_confirmed(),
            opened: delta.is_opened(),
            closed: delta.is_closed(),
            changes: delta
                .changes()
                .iter()
                .flat_map(|change| ChangeDto::of_port(change, options))
                .collect(),
        }
    }
}

/// One field that moved, as one scalar fact.
///
/// The document's unit of change, and the vocabulary a rule keys on. A set that
/// gained two members produces two of these rather than one carrying a list; see
/// the [module documentation](super) for why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangeDto {
    /// Which field moved, by wire name. The whole list is in
    /// [`of_host`](Self::of_host) and [`of_port`](Self::of_port).
    pub kind: &'static str,
    /// What the earlier scan found. `null` where it found nothing — a value
    /// gained, a service identified, a certificate first presented.
    pub before: Option<String>,
    /// What the later scan found. `null` where it finds nothing — a value lost,
    /// a service no longer identified, a certificate withdrawn.
    pub after: Option<String>,
}

impl ChangeDto {
    /// A change with both values.
    fn between(kind: &'static str, before: impl Into<String>, after: impl Into<String>) -> Self {
        Self {
            kind,
            before: Some(before.into()),
            after: Some(after.into()),
        }
    }

    /// A value the later scan found and the earlier did not.
    fn gained(kind: &'static str, after: impl Into<String>) -> Self {
        Self {
            kind,
            before: None,
            after: Some(after.into()),
        }
    }

    /// A value the earlier scan found and the later does not.
    fn lost(kind: &'static str, before: impl Into<String>) -> Self {
        Self {
            kind,
            before: Some(before.into()),
            after: None,
        }
    }

    /// A pair of optionals, as however many changes it amounts to.
    fn optional(kind: &'static str, before: Option<&str>, after: Option<&str>) -> Vec<Self> {
        match (before, after) {
            (None, None) => Vec::new(),
            (None, Some(after)) => vec![Self::gained(kind, after)],
            (Some(before), None) => vec![Self::lost(kind, before)],
            (Some(before), Some(after)) => vec![Self::between(kind, before, after)],
        }
    }

    /// A set's arrivals and departures, one change each.
    fn set<T: ToString>(
        gained_kind: &'static str,
        lost_kind: &'static str,
        gained: &[T],
        lost: &[T],
    ) -> Vec<Self> {
        gained
            .iter()
            .map(|value| Self::gained(gained_kind, value.to_string()))
            .chain(
                lost.iter()
                    .map(|value| Self::lost(lost_kind, value.to_string())),
            )
            .collect()
    }

    /// What a host-level change amounts to, in this document's vocabulary.
    ///
    /// | `kind` | |
    /// |---|---|
    /// | `status` | whether the host answers |
    /// | `hostname` | its resolved name |
    /// | `address_gained`, `address_lost` | one address each |
    /// | `os` | what it was identified as running |
    /// | `mac_gained`, `mac_lost` | one hardware address each |
    /// | `vendor` | the vendor its hardware address resolves to |
    /// | `role_gained`, `role_lost` | one inferred role each |
    ///
    /// Matched exhaustively and with no wildcard, so a variant added to
    /// [`HostChange`] stops this compiling until somebody decides what it is
    /// called on the wire — the same arrangement
    /// [`export::schema`](crate::export::schema) makes for the report document.
    pub fn of_host(change: &HostChange, options: &ExportOptions) -> Vec<Self> {
        let redaction = options.redaction;

        match change {
            HostChange::Status(status) => vec![Self::between(
                "status",
                host_status_name(status.before),
                host_status_name(status.after),
            )],
            HostChange::Hostname(name) => Self::optional(
                "hostname",
                name.before
                    .as_deref()
                    .map(|n| redaction.hostname(n))
                    .as_deref(),
                name.after
                    .as_deref()
                    .map(|n| redaction.hostname(n))
                    .as_deref(),
            ),
            HostChange::Addresses { gained, lost } => {
                Self::set("address_gained", "address_lost", gained, lost)
            }
            HostChange::Os(os) => Self::optional(
                "os",
                os.before.as_ref().map(identify).as_deref(),
                os.after.as_ref().map(identify).as_deref(),
            ),
            HostChange::Macs { gained, lost } => {
                let gained: Vec<String> = gained.iter().map(|mac| redaction.mac(mac)).collect();
                let lost: Vec<String> = lost.iter().map(|mac| redaction.mac(mac)).collect();
                Self::set("mac_gained", "mac_lost", &gained, &lost)
            }
            HostChange::Vendor(vendor) => {
                Self::optional("vendor", vendor.before.as_deref(), vendor.after.as_deref())
            }
            HostChange::Roles { gained, lost } => {
                let name = crate::record::wire::network_role_name;
                let gained: Vec<&'static str> = gained.iter().copied().map(name).collect();
                let lost: Vec<&'static str> = lost.iter().copied().map(name).collect();
                Self::set("role_gained", "role_lost", &gained, &lost)
            }
        }
    }

    /// What an endpoint-level change amounts to.
    ///
    /// | `kind` | |
    /// |---|---|
    /// | `port_state` | the verdict |
    /// | `service_identified`, `service_lost` | something was identified here, or no longer is |
    /// | `service_name`, `service_product`, `service_vendor`, `service_version`, `service_extrainfo` | one field of it |
    /// | `cpe_gained`, `cpe_lost` | one platform identifier each |
    /// | `tls_version`, `cipher_suite` | what was negotiated |
    /// | `alpn_gained`, `alpn_lost` | one application protocol each |
    /// | `certificate_presented`, `certificate_withdrawn`, `certificate_rotated` | by SHA-256 fingerprint |
    /// | `certificate_expiring`, `certificate_expired` | a threshold crossed since the earlier scan; `after` is the validity end |
    pub fn of_port(change: &PortChange, _options: &ExportOptions) -> Vec<Self> {
        match change {
            PortChange::State(state) => vec![Self::between(
                "port_state",
                port_state_name(state.before),
                port_state_name(state.after),
            )],
            PortChange::Service(service) => Self::of_service(service),
            PortChange::Security(security) => Self::of_security(security),
        }
    }

    fn of_service(change: &ServiceChange) -> Vec<Self> {
        match change {
            ServiceChange::Identified(service) => {
                vec![Self::gained("service_identified", describe(service))]
            }
            ServiceChange::Unidentified(service) => {
                vec![Self::lost("service_lost", describe(service))]
            }
            ServiceChange::Name(name) => {
                vec![Self::between("service_name", &name.before, &name.after)]
            }
            ServiceChange::Product(value) => Self::optional(
                "service_product",
                value.before.as_deref(),
                value.after.as_deref(),
            ),
            ServiceChange::Vendor(value) => Self::optional(
                "service_vendor",
                value.before.as_deref(),
                value.after.as_deref(),
            ),
            ServiceChange::Version(value) => Self::optional(
                "service_version",
                value.before.as_deref(),
                value.after.as_deref(),
            ),
            ServiceChange::ExtraInfo(value) => Self::optional(
                "service_extrainfo",
                value.before.as_deref(),
                value.after.as_deref(),
            ),
            ServiceChange::Cpes { gained, lost } => {
                Self::set("cpe_gained", "cpe_lost", gained, lost)
            }
        }
    }

    fn of_security(change: &SecurityChange) -> Vec<Self> {
        match change {
            SecurityChange::TlsVersion(value) => Self::optional(
                "tls_version",
                value.before.as_deref(),
                value.after.as_deref(),
            ),
            SecurityChange::CipherSuite(value) => Self::optional(
                "cipher_suite",
                value.before.as_deref(),
                value.after.as_deref(),
            ),
            SecurityChange::Alpn { gained, lost } => {
                Self::set("alpn_gained", "alpn_lost", gained, lost)
            }
            SecurityChange::Certificate(certificate) => Self::of_certificate(certificate),
        }
    }

    /// A certificate is identified by its fingerprint, so that is what the
    /// values carry: two certificates are the same one exactly when they are
    /// byte for byte the same.
    fn of_certificate(change: &CertificateChange) -> Vec<Self> {
        match change {
            CertificateChange::Presented(certificate) => vec![Self::gained(
                "certificate_presented",
                certificate.fingerprint_sha256(),
            )],
            CertificateChange::Withdrawn(certificate) => vec![Self::lost(
                "certificate_withdrawn",
                certificate.fingerprint_sha256(),
            )],
            CertificateChange::Rotated { before, after } => vec![Self::between(
                "certificate_rotated",
                before.fingerprint_sha256(),
                after.fingerprint_sha256(),
            )],
            // The certificate did not move; the clock did. `after` is when it
            // lapses, absolute, so a consumer computes whatever window it wants
            // without this document choosing a unit.
            CertificateChange::Expiring { certificate, .. } => vec![Self::gained(
                "certificate_expiring",
                rfc3339(certificate.validity_end()),
            )],
            CertificateChange::Expired { certificate, .. } => vec![Self::gained(
                "certificate_expired",
                rfc3339(certificate.validity_end()),
            )],
        }
    }
}

/// An operating system as one line, for a value in a change.
///
/// The whole fingerprint is in the host records on either side; this is what a
/// person reads in an alert.
fn identify(os: &OsFingerprint) -> String {
    // A name carrying a digit already says which version, and appending the
    // generation to it produces "Linux 5.0 - 5.14 5.X". A bare family name does
    // not, and "Linux" alone is worth less than "Linux 6.1.0". The two shapes
    // come from different fingerprinters and both reach this.
    match os.generation() {
        Some(generation)
            if !os.name().contains(generation)
                && !os.name().contains(|c: char| c.is_ascii_digit()) =>
        {
            format!("{} {generation}", os.name())
        }
        _ => os.name().to_owned(),
    }
}

/// A service as one line, likewise.
fn describe(service: &crate::model::port::Service) -> String {
    let mut described = service.name().to_owned();

    // A fingerprint that recognised the protocol and nothing more names the
    // product after the protocol, and "http http" reads as a mistake.
    if let Some(product) = service
        .product()
        .filter(|p| !p.eq_ignore_ascii_case(&described))
    {
        described.push(' ');
        described.push_str(product);
    }
    if let Some(version) = service.version() {
        described.push(' ');
        described.push_str(version);
    }
    described
}
