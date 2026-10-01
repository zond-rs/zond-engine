// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The comparison document
//!
//! What a consumer parses, and the one place a change is given its name.
//! [`ChangeDto::of_host`] and [`ChangeDto::of_port`] turn the engine's typed
//! deltas into that vocabulary; a front end printing one line per change calls
//! them too, so both name the same event the same way.
//!
//! The report document's conventions hold here: timestamps are RFC 3339 in UTC,
//! objects have a fixed shape with `null` for a missing value, order is
//! deterministic, and unknown fields may appear. See
//! [`export::schema`](crate::export::schema) for the full list.

use serde::Serialize;
use serde::ser::{SerializeSeq, Serializer};

use crate::diff::host::Reassessment;
use crate::diff::{
    CertificateChange, Confirmed, Coverage, DiffSummary, HostChange, HostDelta, PortChange,
    PortDelta, Presence, ScanDiff, SecurityChange, ServiceChange, Significance,
};
use crate::export::schema::{EngineDto, HostDto};
use crate::export::{ExportOptions, HostRedaction};
use crate::format::time::rfc3339;
use crate::model::finding::Finding;
use crate::model::host::os::OsFingerprint;
use crate::model::host::{HostName, IpProtocolState, ip_protocol_name};
use crate::model::port::Build;
use crate::record::wire::{
    host_status_name, ip_protocol_state_name, name_kind_name, name_source_name, port_state_name,
    protocol_name, scan_kind_name,
};

pub use crate::format::{DIFF_SCHEMA_VERSION, ENGINE_NAME};

// ---------------------------------------------------------------------------
// The names a change is known by
//
// Public because they are the contract: alerting rules and front ends both use
// these strings.
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
        Coverage::Unreached => "unreached",
        Coverage::Unstated => "unstated",
    }
}

/// How much a change is worth somebody's attention.
pub fn significance_name(significance: Significance) -> &'static str {
    match significance {
        Significance::Routine => "routine",
        Significance::Notable => "notable",
        Significance::Urgent => "urgent",
    }
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// The root of a comparison document.
///
/// Borrows the comparison and hands its host deltas to [`HostDeltasDto`], which
/// renders one at a time.
#[non_exhaustive]
#[derive(Debug, Serialize)]
pub struct DiffDto<'a> {
    /// The version of this document's shape. Counted apart from the report's.
    pub schema_version: u32,
    /// Which build wrote the document. The builds that produced the scans are
    /// in `baseline` and `current`.
    pub engine: EngineDto,
    /// When the comparison was taken.
    pub generated_at: String,
    /// The earlier scan.
    pub baseline: ProvenanceDto,
    /// The later scan.
    pub current: ProvenanceDto,
    /// Whether the two scans describe the same network.
    ///
    /// Equivalent to an empty `hosts`.
    pub unchanged: bool,
    /// How much the strongest change anywhere below is worth somebody's
    /// attention: `routine`, `notable` or `urgent`.
    ///
    /// The field to triage a scheduled comparison by. `routine` also when nothing
    /// moved; `unchanged` tells the two apart.
    pub significance: &'static str,
    /// Counts over everything below.
    pub summary: SummaryDto,
    /// Every host that differs, ascending by address.
    pub hosts: HostDeltasDto<'a>,
}

/// The comparison's host deltas, serialized one at a time.
///
/// The counterpart of the report document's host array. Each delta carries the
/// whole record from each side, so each is rendered, written and dropped before
/// the next is built, to avoid holding a second copy of both reports.
#[non_exhaustive]
#[derive(Debug)]
pub struct HostDeltasDto<'a> {
    deltas: &'a [HostDelta],
    options: &'a ExportOptions,
}

impl<'a> HostDeltasDto<'a> {
    /// The deltas this will render, typed.
    pub fn deltas(&self) -> &'a [HostDelta] {
        self.deltas
    }

    /// How many hosts differ.
    pub fn len(&self) -> usize {
        self.deltas.len()
    }

    /// Whether the two scans describe the same network.
    pub fn is_empty(&self) -> bool {
        self.deltas.is_empty()
    }
}

impl Serialize for HostDeltasDto<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.deltas.len()))?;
        for delta in self.deltas {
            seq.serialize_element(&HostDeltaDto::new(delta, self.options))?;
        }
        seq.end()
    }
}

impl<'a> DiffDto<'a> {
    /// Renders a comparison, applying the redaction policy in `options`.
    pub fn new(diff: &'a ScanDiff, options: &'a ExportOptions) -> Self {
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
            significance: significance_name(diff.significance()),
            summary: SummaryDto::new(&diff.summary()),
            hosts: HostDeltasDto {
                deltas: diff.hosts(),
                options,
            },
        }
    }
}

/// Which scan one side of the comparison was.
#[non_exhaustive]
#[derive(Debug, Serialize)]
pub struct ProvenanceDto {
    /// The engine that produced the report, as it attributed itself; for a
    /// report imported from another tool, that tool (e.g. `nmap 7.94`).
    pub engine_version: String,
    /// When the scan is taken to have happened, and the time its certificates
    /// were checked against.
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
#[non_exhaustive]
#[derive(Debug, Serialize)]
pub struct ConfirmedDto {
    /// How many, whatever the other scan covered.
    pub total: usize,
    /// How many the other scan is known to have covered. The number to alert
    /// on.
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
#[non_exhaustive]
#[derive(Debug, Serialize)]
pub struct SummaryDto {
    /// Hosts only the later scan has a record for.
    pub hosts_added: ConfirmedDto,
    /// Hosts only the earlier scan has a record for.
    pub hosts_removed: ConfirmedDto,
    /// Hosts both scans have, that differ.
    pub hosts_changed: usize,
    /// Endpoints accepting connections in the later scan and not the earlier.
    pub ports_opened: ConfirmedDto,
    /// Endpoints accepting connections in the earlier scan and not the later.
    pub ports_closed: ConfirmedDto,
    /// Endpoints both scans have, that differ.
    pub ports_changed: usize,
    /// Endpoints where what is listening changed, or was identified where it
    /// was not.
    pub services_changed: usize,
    /// Endpoints presenting a different certificate than before.
    pub certificates_rotated: usize,
    /// Endpoints whose certificate is inside the expiry threshold in the later
    /// scan and was outside it in the earlier one.
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
#[non_exhaustive]
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
    /// Whether this is known to be a change in the network.
    ///
    /// True when both scans hold a record, or when the one without a record is
    /// known to have covered the address.
    pub confirmed: bool,
    /// How much the strongest change on this host, or on any of its endpoints, is
    /// worth somebody's attention: `routine`, `notable` or `urgent`.
    ///
    /// The field to alert on. Already `routine` where `confirmed` is false.
    pub significance: &'static str,
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
    ///
    /// Its text is masked by every name either scan knew the host by, as the
    /// changes are: the earlier scan can hold a reply naming the machine before
    /// it learned the name, which only the later scan knows.
    pub baseline: Option<HostDto<'a>>,
    /// The later scan's whole record, masked the same way.
    pub current: Option<HostDto<'a>>,
}

impl<'a> HostDeltaDto<'a> {
    /// Renders one host's comparison.
    pub fn new(delta: &'a HostDelta, options: &ExportOptions) -> Self {
        let (baseline_records, current_records) = delta.records();
        let masking = options.redaction.for_delta(delta);

        Self {
            address: delta.address().to_string(),
            presence: presence_name(delta.presence()),
            coverage: delta.presence().counterpart_coverage().map(coverage_name),
            confirmed: delta.presence().is_confirmed(),
            significance: significance_name(delta.significance()),
            records: RecordsDto {
                baseline: baseline_records,
                current: current_records,
            },
            regrouped: delta.is_regrouped(),
            changes: delta
                .changes()
                .iter()
                .flat_map(|change| ChangeDto::of_host(change, &masking))
                .collect(),
            ports: delta
                .ports()
                .iter()
                .map(|port| PortDeltaDto::new(port, &masking))
                .collect(),
            baseline: delta
                .baseline()
                .map(|host| HostDto::masked(host, options, &masking)),
            current: delta
                .current()
                .map(|host| HostDto::masked(host, options, &masking)),
        }
    }
}

/// How many records each scan held for one host.
#[non_exhaustive]
#[derive(Debug, Serialize)]
pub struct RecordsDto {
    /// The earlier scan's count.
    pub baseline: usize,
    /// The later scan's count.
    pub current: usize,
}

/// One endpoint, as the two scans between them hold it.
#[non_exhaustive]
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
    /// Whether this is a finding about the network.
    pub confirmed: bool,
    /// How much the strongest change on this endpoint is worth somebody's
    /// attention: `routine`, `notable` or `urgent`. The field to alert on, and
    /// already `routine` where `confirmed` is false.
    pub significance: &'static str,
    /// Whether the endpoint accepts connections in the later scan and not the earlier.
    pub opened: bool,
    /// Whether it accepted connections in the earlier scan and not the later.
    pub closed: bool,
    /// What moved about the endpoint.
    pub changes: Vec<ChangeDto>,
}

impl PortDeltaDto {
    /// Renders one endpoint's comparison, on the host `masking` was made for.
    pub fn new(delta: &PortDelta, masking: &HostRedaction) -> Self {
        Self {
            port: delta.number(),
            protocol: protocol_name(delta.protocol()),
            presence: presence_name(delta.presence()),
            coverage: delta.presence().counterpart_coverage().map(coverage_name),
            confirmed: delta.presence().is_confirmed(),
            significance: significance_name(delta.significance()),
            opened: delta.is_opened(),
            closed: delta.is_closed(),
            changes: delta
                .changes()
                .iter()
                .flat_map(|change| ChangeDto::of_port(change, masking))
                .collect(),
        }
    }
}

/// One field that moved, as one scalar fact.
///
/// The document's unit of change, and the vocabulary a rule keys on. A set that
/// gained two members produces two of these. See the
/// [module documentation](super) for why.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangeDto {
    /// Which field moved, by wire name. The whole list is in
    /// [`of_host`](Self::of_host) and [`of_port`](Self::of_port).
    pub kind: &'static str,
    /// What the earlier scan found. `null` where it found nothing: a value
    /// gained, a service identified, a certificate first presented.
    pub before: Option<String>,
    /// What the later scan found. `null` where it found nothing: a value lost, a
    /// service unidentified, a certificate withdrawn.
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
    /// | `name_gained`, `name_lost` | one name it gave for itself each, as `ntlm domain: corp.example` |
    /// | `address_gained`, `address_lost` | one address each |
    /// | `os` | what it was identified as running |
    /// | `mac_gained`, `mac_lost` | one hardware address each |
    /// | `vendor` | the vendor its hardware address resolves to |
    /// | `role_gained`, `role_lost` | one inferred role each |
    /// | `filtering_gained`, `filtering_lost` | one conclusion about the filter in front of it each |
    /// | `ip_protocol` | one IP protocol whose verdict changed |
    /// | `finding_appeared`, `finding_resolved` | one finding each, as its severity and title |
    /// | `finding_reassessed` | one claim both scans make, graded differently |
    ///
    /// Never `finding_unsettled`: the evidence that can leave a claim unsettled
    /// (a TLS walk, a certificate) belongs to an endpoint, so only
    /// [`of_port`](Self::of_port) emits it.
    ///
    /// Matched with no wildcard, so a new [`HostChange`] variant fails to compile
    /// until it has a wire name, as in [`export::schema`](crate::export::schema).
    ///
    /// `masking` is made for the host the change is on, from both of its
    /// records ([`Redaction::for_delta`](crate::export::Redaction::for_delta)).
    /// A name and a hardware address are masked as their fields are anywhere,
    /// and every value then goes through [`HostRedaction::text`], since an
    /// operating system's name and a finding's title are the host's words.
    pub fn of_host(change: &HostChange, masking: &HostRedaction) -> Vec<Self> {
        let redaction = masking.redaction();

        let changes = match change {
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
            // Source and kind lead, spelled as in the report, so a rule can key on
            // `ntlm domain:` without parsing the name. Only the name is masked.
            HostChange::Names { gained, lost } => {
                let describe = |name: &HostName| {
                    format!(
                        "{} {}: {}",
                        name_source_name(name.source()),
                        name_kind_name(name.kind()),
                        redaction.hostname(name.name())
                    )
                };
                let gained: Vec<String> = gained.iter().map(describe).collect();
                let lost: Vec<String> = lost.iter().map(describe).collect();
                Self::set("name_gained", "name_lost", &gained, &lost)
            }
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
            HostChange::Filtering { gained, lost } => {
                let name = crate::record::wire::filtering_name;
                let gained: Vec<&'static str> = gained.iter().copied().map(name).collect();
                let lost: Vec<&'static str> = lost.iter().copied().map(name).collect();
                Self::set("filtering_gained", "filtering_lost", &gained, &lost)
            }
            // One change per protocol, like every set change here. The number
            // leads the value because it is what a rule keys on.
            HostChange::IpProtocols { changed } => changed
                .iter()
                .map(|moved| {
                    Self::between(
                        "ip_protocol",
                        Self::describe_ip_protocol(moved.protocol, moved.state.before),
                        Self::describe_ip_protocol(moved.protocol, moved.state.after),
                    )
                })
                .collect(),
            HostChange::Findings {
                appeared,
                resolved,
                reassessed,
            } => Self::findings(appeared, resolved, &[], reassessed),
        };
        Self::masked(changes, masking)
    }

    /// `changes` with each value read through `masking`.
    fn masked(changes: Vec<Self>, masking: &HostRedaction) -> Vec<Self> {
        let mask = |value: Option<String>| {
            value.map(|value| match masking.text(&value) {
                std::borrow::Cow::Borrowed(_) => value,
                std::borrow::Cow::Owned(masked) => masked,
            })
        };
        changes
            .into_iter()
            .map(|change| Self {
                kind: change.kind,
                before: mask(change.before),
                after: mask(change.after),
            })
            .collect()
    }

    /// One IP protocol verdict, as `47 gre: open`.
    ///
    /// The number, its registry keyword where it has one, and the verdict, so
    /// each value of a change reads on its own.
    fn describe_ip_protocol(number: u8, state: IpProtocolState) -> String {
        let verdict = ip_protocol_state_name(state);
        match ip_protocol_name(number) {
            Some(name) => format!("{number} {name}: {verdict}"),
            None => format!("{number}: {verdict}"),
        }
    }

    /// Findings gained and lost, as one entry each.
    ///
    /// Rendered as severity and title; the evidence is in the reports.
    ///
    /// A claim the later scan did not settle is its own kind, so a rule on
    /// `finding_resolved` fires only on a fix, and not when the later scan cut a
    /// walk short or was not shown a certificate.
    fn findings(
        appeared: &[Finding],
        resolved: &[Finding],
        unsettled: &[Finding],
        reassessed: &[Reassessment],
    ) -> Vec<Self> {
        let name = crate::record::wire::severity_name;
        let describe =
            |finding: &Finding| format!("{}: {}", name(finding.severity()), finding.title());

        let gained: Vec<String> = appeared.iter().map(describe).collect();
        let lost: Vec<String> = resolved.iter().map(describe).collect();

        let mut entries = Self::set("finding_appeared", "finding_resolved", &gained, &lost);
        entries.extend(
            unsettled
                .iter()
                .map(|finding| Self::lost("finding_unsettled", describe(finding))),
        );
        entries.extend(reassessed.iter().map(|shift| {
            Self::between(
                "finding_reassessed",
                format!("{}: {}", name(shift.severity.before), shift.finding.title()),
                format!("{}: {}", name(shift.severity.after), shift.finding.title()),
            )
        }));
        entries
    }

    /// What an endpoint-level change amounts to.
    ///
    /// | `kind` | |
    /// |---|---|
    /// | `port_state` | the verdict |
    /// | `service_identified`, `service_lost` | something was identified here in one scan only |
    /// | `service_name`, `service_product`, `service_vendor`, `service_version`, `service_extrainfo` | one field of it |
    /// | `service_build` | whose build, as distributor, release and package revision |
    /// | `cpe_gained`, `cpe_lost` | one platform identifier each |
    /// | `tls_version`, `cipher_suite` | what was negotiated |
    /// | `alpn_gained`, `alpn_lost` | one application protocol each |
    /// | `certificate_presented`, `certificate_withdrawn`, `certificate_rotated` | by SHA-256 fingerprint |
    /// | `certificate_expiring`, `certificate_expired` | a threshold crossed since the earlier scan; `after` is the validity end |
    /// | `finding_appeared`, `finding_resolved` | one finding each, as its severity and title |
    /// | `finding_unsettled` | one claim the earlier scan made that the later one neither makes nor settled |
    /// | `finding_reassessed` | one claim both scans make, graded differently |
    ///
    /// Every value goes through `masking`, made as for
    /// [`of_host`](Self::of_host): a service's product and extra information
    /// and a finding's title are filled from the host's replies, and can name
    /// it. A certificate change is rendered by fingerprint, so it names nothing
    /// to mask.
    pub fn of_port(change: &PortChange, masking: &HostRedaction) -> Vec<Self> {
        let changes = match change {
            PortChange::State(state) => vec![Self::between(
                "port_state",
                port_state_name(state.before),
                port_state_name(state.after),
            )],
            PortChange::Service(service) => Self::of_service(service),
            PortChange::Security(security) => Self::of_security(security),
            PortChange::Findings {
                appeared,
                resolved,
                unsettled,
                reassessed,
            } => Self::findings(appeared, resolved, unsettled, reassessed),
        };
        Self::masked(changes, masking)
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
            ServiceChange::Build(value) => Self::optional(
                "service_build",
                value.before.as_ref().map(Build::describe).as_deref(),
                value.after.as_ref().map(Build::describe).as_deref(),
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

    /// Values carry the certificate's SHA-256 fingerprint, which identifies it
    /// byte for byte.
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
            // `after` is the absolute validity end, so a consumer picks its own
            // window.
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
/// The whole fingerprint is in the host records on either side.
fn identify(os: &OsFingerprint) -> String {
    // Append the generation only to a bare family name ("Linux" -> "Linux 6.1.0").
    // A name with a digit already has a version, and appending would give
    // "Linux 5.0 - 5.14 5.X".
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
