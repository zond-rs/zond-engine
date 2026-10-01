// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Holds the exported document to the published schema.
//!
//! `assets/schema/zond-report-v1.schema.json` ships with the crate and is what
//! a consumer validates against. These tests run the real exporter against it so
//! the schema cannot drift from the DTOs.
//!
//! The schema is strict: every object is closed and every field required except
//! the few a writer omits when it has nothing to say. Adding a field to a DTO
//! without describing it in the schema fails the build.
//!
//! The optional fields are pinned by
//! `the_schema_marks_optional_exactly_the_fields_a_writer_leaves_out`, so a new
//! `skip_serializing_if` must be matched by the schema and by what the
//! [`schema`](super::schema) module documentation says an absent field means.

use boon::{Compiler, Schemas};
use regex::Regex;
use serde_json::Value;
use std::collections::BTreeSet;

use crate::config::{OsDetection, ScanEffort, ServiceDetection};
use crate::diff::{Coverage, Significance};
use crate::export::diff::schema::{coverage_name, significance_name};
use crate::export::schema::{SCHEMA_VERSION, scan_effort_name, send_mode_name};
use crate::export::{ExportOptions, Exporter, JsonExporter, Redaction, fixture};
use crate::model::confidence::Confidence;
use crate::model::finding::{DetectionClass, Severity};
use crate::model::host::status::StatusProtocol;
use crate::model::host::{
    Filtering, HostStatus, IpProtocolState, NameKind, NameSource, NetworkRole,
};
use crate::model::port::{Distributor, PortState, Protocol, ReleaseBasis};
use crate::model::technique::{SctpScanTechnique, TcpScanTechnique};
use crate::model::tls::{Interruption, SuiteFault, SuiteStrength, TlsVersion};
use crate::record::wire::{
    attachment_source_name, confidence_name, detection_class_name, filtering_name,
    host_status_name, ip_protocol_state_name, liveness_skip_name, name_kind_name, name_source_name,
    network_role_name, pass_name, port_state_name, protocol_name, scan_kind_name,
    scanner_kind_name, severity_name, stop_reason_name,
};
use crate::report::{AttachmentSource, LivenessSkip, Pass, ScanKind, ScannerKind, StopReason};
use crate::transport::probe::SendMode;

/// The published schemas, compiled into the test binary so the tests check the
/// shipped files.
const SCHEMA: &str = include_str!("../../assets/schema/zond-report-v1.schema.json");
const LINES_SCHEMA: &str = include_str!("../../assets/schema/zond-lines-v1.schema.json");
const DIFF_SCHEMA: &str = include_str!("../../assets/schema/zond-diff-v1.schema.json");

/// The identifiers the schemas declare for themselves.
const SCHEMA_URL: &str = "https://zond.rs/schema/zond-report-v1.schema.json";
const LINES_SCHEMA_URL: &str = "https://zond.rs/schema/zond-lines-v1.schema.json";
const DIFF_SCHEMA_URL: &str = "https://zond.rs/schema/zond-diff-v1.schema.json";

/// A compiled validator over one of the published schemas.
struct Validator {
    schemas: Schemas,
    index: boon::SchemaIndex,
}

impl Validator {
    /// A validator over the single-document schema.
    fn new() -> Self {
        Self::over(SCHEMA_URL)
    }

    /// A validator over the record-per-line schema.
    ///
    /// Validates one record; a JSON Lines file is not one JSON document.
    fn lines() -> Self {
        Self::over(LINES_SCHEMA_URL)
    }

    /// A validator over the comparison schema.
    fn diff() -> Self {
        Self::over(DIFF_SCHEMA_URL)
    }

    /// Compiles the schema at `url`.
    ///
    /// All three are registered, since the lines and comparison schemas refer to
    /// the report schema's definitions.
    fn over(url: &str) -> Self {
        let mut schemas = Schemas::new();
        let mut compiler = Compiler::new();

        for (id, text) in [
            (SCHEMA_URL, SCHEMA),
            (LINES_SCHEMA_URL, LINES_SCHEMA),
            (DIFF_SCHEMA_URL, DIFF_SCHEMA),
        ] {
            let document: Value =
                serde_json::from_str(text).expect("the schema file is valid JSON");
            compiler
                .add_resource(id, document)
                .expect("the schema file is a usable resource");
        }

        let index = compiler
            .compile(url, &mut schemas)
            .expect("the schema file compiles");

        Self { schemas, index }
    }

    /// Fails with the validator's own explanation, which names the offending
    /// path.
    fn check(&self, document: &Value) {
        if let Err(error) = self.schemas.validate(document, self.index) {
            panic!("the exported document does not match the published schema:\n{error:#}");
        }
    }

    /// Whether a document validates, for the tests that assert rejection.
    fn accepts(&self, document: &Value) -> bool {
        self.schemas.validate(document, self.index).is_ok()
    }
}

/// Exports a report and parses it back.
fn document(options: ExportOptions) -> Value {
    let mut bytes = Vec::new();
    JsonExporter::new(options)
        .export(&fixture::report(), &mut bytes)
        .expect("the export succeeds");

    serde_json::from_slice(&bytes).expect("the export parses as JSON")
}

/// The published schema compiles.
#[test]
fn the_published_schema_compiles() {
    let _ = Validator::new();
}

/// The version the code emits is the one the schema pins.
#[test]
fn the_schema_pins_the_version_the_code_emits() {
    let schema: Value = serde_json::from_str(SCHEMA).expect("valid JSON");

    assert_eq!(
        schema["properties"]["schema_version"]["const"],
        Value::from(SCHEMA_VERSION)
    );
}

/// Every enumerated value in the report document, as the schema lists it and as
/// this build spells it, compared both ways.
///
/// A variant the engine writes and the schema rejects produces documents no
/// validator accepts; the document tests only see the variants the fixture
/// carries. A name the schema lists and the engine cannot produce is one a third
/// party may write and the report readers refuse.
///
/// Only enums whose type publishes an `ALL` are here. Every closed enum in the
/// schema has one except `port_scope`, whose variants carry data. A new enum in
/// the document should come with an `ALL`, so the variants are not listed a
/// third time in this file.
///
/// `reason.protocol` is compared through [`StatusProtocol::ALL`], which holds
/// the built-in names. The variant it leaves out carries a strategy-chosen name
/// and matches the schema's other `anyOf` arm, a `custom:` prefix pattern.
fn enumerations() -> Vec<(&'static str, Vec<String>)> {
    let named = |names: Vec<&'static str>| names.into_iter().map(str::to_owned).collect();

    vec![
        (
            "/$defs/settings/properties/tcp_technique/enum",
            named(TcpScanTechnique::ALL.iter().map(|t| t.name()).collect()),
        ),
        (
            "/$defs/build/properties/distributor/enum",
            named(
                Distributor::ALL
                    .iter()
                    .copied()
                    .map(crate::record::wire::distributor_name)
                    .collect(),
            ),
        ),
        (
            "/$defs/release/properties/basis/enum",
            named(
                ReleaseBasis::ALL
                    .iter()
                    .copied()
                    .map(crate::record::wire::release_basis_name)
                    .collect(),
            ),
        ),
        (
            "/$defs/accepted_version/properties/version/enum",
            named(TlsVersion::ALL.iter().map(|v| v.name()).collect()),
        ),
        (
            "/$defs/unfinished_version/properties/version/enum",
            named(TlsVersion::ALL.iter().map(|v| v.name()).collect()),
        ),
        (
            "/$defs/unfinished_version/properties/interruption/enum",
            named(Interruption::ALL.iter().map(|i| i.name()).collect()),
        ),
        (
            "/$defs/accepted_suite/properties/strength/enum",
            named(SuiteStrength::ALL.iter().map(|s| s.name()).collect()),
        ),
        (
            "/$defs/accepted_suite/properties/faults/items/enum",
            named(SuiteFault::ALL.iter().map(|f| f.name()).collect()),
        ),
        (
            "/$defs/settings/properties/sctp_technique/enum",
            named(SctpScanTechnique::ALL.iter().map(|t| t.name()).collect()),
        ),
        (
            "/$defs/settings/properties/send_mode/enum",
            named(SendMode::ALL.iter().copied().map(send_mode_name).collect()),
        ),
        (
            "/$defs/settings/properties/os_detection/enum",
            named(OsDetection::ALL.iter().map(|d| d.name()).collect()),
        ),
        (
            "/$defs/settings/properties/service_detection/enum",
            named(ServiceDetection::ALL.iter().map(|d| d.name()).collect()),
        ),
        (
            "/$defs/settings/properties/detection/enum",
            named(
                DetectionClass::ALL
                    .iter()
                    .copied()
                    .map(detection_class_name)
                    .collect(),
            ),
        ),
        (
            "/$defs/retry/properties/effort/enum",
            named(
                ScanEffort::ALL
                    .iter()
                    .copied()
                    .map(scan_effort_name)
                    .collect(),
            ),
        ),
        (
            "/$defs/host/properties/status/enum",
            named(
                HostStatus::ALL
                    .iter()
                    .copied()
                    .map(host_status_name)
                    .collect(),
            ),
        ),
        (
            "/$defs/host/properties/names/items/properties/source/enum",
            named(
                NameSource::ALL
                    .iter()
                    .copied()
                    .map(name_source_name)
                    .collect(),
            ),
        ),
        (
            "/$defs/host/properties/names/items/properties/kind/enum",
            named(NameKind::ALL.iter().copied().map(name_kind_name).collect()),
        ),
        (
            "/$defs/host/properties/roles/items/enum",
            named(
                NetworkRole::ALL
                    .iter()
                    .copied()
                    .map(network_role_name)
                    .collect(),
            ),
        ),
        (
            // Inside an `anyOf`; the other arm is the `custom:` prefix pattern
            // for strategy-supplied names.
            "/$defs/reason/properties/protocol/anyOf/0/enum",
            StatusProtocol::ALL
                .iter()
                .map(|protocol| crate::record::wire::status_protocol_name(protocol).into_owned())
                .collect(),
        ),
        (
            "/$defs/host/properties/filtering/items/enum",
            named(Filtering::ALL.iter().copied().map(filtering_name).collect()),
        ),
        (
            "/$defs/host/properties/ip_protocols/items/properties/state/enum",
            named(
                IpProtocolState::ALL
                    .iter()
                    .copied()
                    .map(ip_protocol_state_name)
                    .collect(),
            ),
        ),
        (
            "/$defs/port/properties/state/enum",
            named(
                PortState::ALL
                    .iter()
                    .copied()
                    .map(port_state_name)
                    .collect(),
            ),
        ),
        (
            "/$defs/protocol/enum",
            named(Protocol::ALL.iter().copied().map(protocol_name).collect()),
        ),
        (
            "/$defs/finding/properties/severity/enum",
            named(Severity::ALL.iter().copied().map(severity_name).collect()),
        ),
        (
            "/$defs/finding/properties/confidence/enum",
            named(
                Confidence::ALL
                    .iter()
                    .copied()
                    .map(confidence_name)
                    .collect(),
            ),
        ),
        (
            "/$defs/finding/properties/class/enum",
            named(
                DetectionClass::ALL
                    .iter()
                    .copied()
                    .map(detection_class_name)
                    .collect(),
            ),
        ),
        (
            "/$defs/phase/properties/passes_cut/items/enum",
            named(Pass::ALL.iter().copied().map(pass_name).collect()),
        ),
        (
            "/$defs/phase/properties/kind/enum",
            named(ScanKind::ALL.iter().copied().map(scan_kind_name).collect()),
        ),
        (
            "/$defs/phase/properties/liveness_skipped/enum",
            named(
                LivenessSkip::ALL
                    .iter()
                    .copied()
                    .map(liveness_skip_name)
                    .collect(),
            ),
        ),
        (
            "/$defs/scanner_kind/enum",
            named(
                ScannerKind::ALL
                    .iter()
                    .copied()
                    .map(scanner_kind_name)
                    .collect(),
            ),
        ),
        (
            "/$defs/probe_stats/properties/stop_reason/enum",
            named(
                StopReason::ALL
                    .iter()
                    .copied()
                    .map(stop_reason_name)
                    .collect(),
            ),
        ),
        (
            "/$defs/attachment/properties/source/enum",
            named(
                AttachmentSource::ALL
                    .iter()
                    .copied()
                    .map(attachment_source_name)
                    .collect(),
            ),
        ),
    ]
}

/// Every enumerated value in the comparison document, the same way.
///
/// The comparison reuses the report's names for everything it carries over;
/// only the coverage answer and the significance grade are its own.
///
/// [`Presence`](crate::diff::Presence) is the other closed enum in the document.
/// Two of its three variants carry data, so it publishes no `ALL`, like
/// `port_scope`.
fn diff_enumerations() -> Vec<(&'static str, Vec<String>)> {
    let coverage: Vec<String> = Coverage::ALL
        .iter()
        .copied()
        .map(|coverage| coverage_name(coverage).to_owned())
        .collect();

    let significance: Vec<String> = Significance::ALL
        .iter()
        .copied()
        .map(|significance| significance_name(significance).to_owned())
        .collect();

    // Coverage appears on hosts and endpoints, significance on those and on the
    // document; every copy is checked.
    vec![
        (
            "/$defs/host_delta/properties/coverage/oneOf/0/enum",
            coverage.clone(),
        ),
        (
            "/$defs/port_delta/properties/coverage/oneOf/0/enum",
            coverage,
        ),
        ("/properties/significance/enum", significance.clone()),
        (
            "/$defs/host_delta/properties/significance/enum",
            significance.clone(),
        ),
        (
            "/$defs/port_delta/properties/significance/enum",
            significance,
        ),
    ]
}

#[test]
fn the_comparison_schema_lists_exactly_the_enumerated_values_the_engine_writes() {
    let schema: Value = serde_json::from_str(DIFF_SCHEMA).expect("valid JSON");
    check_enumerations(&schema, diff_enumerations());
}

#[test]
fn the_schema_lists_exactly_the_enumerated_values_the_engine_writes() {
    let schema: Value = serde_json::from_str(SCHEMA).expect("valid JSON");
    check_enumerations(&schema, enumerations());
}

/// Holds one document's schema to one build's vocabulary, both ways.
fn check_enumerations(schema: &Value, enumerations: Vec<(&'static str, Vec<String>)>) {
    for (pointer, emitted) in enumerations {
        let accepted: BTreeSet<String> = schema
            .pointer(pointer)
            .unwrap_or_else(|| panic!("the schema has no enumeration at {pointer}"))
            .as_array()
            .unwrap_or_else(|| panic!("{pointer} is not a list of names"))
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .unwrap_or_else(|| panic!("{pointer} holds something that is not a name"))
                    .to_owned()
            })
            .collect();

        let emitted: BTreeSet<String> = emitted.into_iter().collect();

        assert_eq!(
            emitted.difference(&accepted).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "{pointer} does not accept a value this build can write"
        );
        assert_eq!(
            accepted.difference(&emitted).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "{pointer} advertises a value this build cannot write, which a third \
             party producing this format would find refused on the way back in"
        );
    }
}

/// A fully populated report: every optional block present, a failed strategy, an
/// instrumented scanner, a certificate, nested script output.
#[test]
fn a_full_report_matches_the_schema() {
    Validator::new().check(&document(ExportOptions::new()));
}

/// A scan that altered no packets, read no zombie's counter and found no
/// managed equipment, which is most scans.
///
/// The full fixture has one of everything, so it cannot catch a field the schema
/// requires and an ordinary document omits.
#[test]
fn an_ordinary_report_matches_the_schema() {
    let plain = fixture::compared().0;
    let mut bytes = Vec::new();
    JsonExporter::new(ExportOptions::new())
        .export(&plain, &mut bytes)
        .expect("the export succeeds");
    let document: Value = serde_json::from_slice(&bytes).expect("the export parses as JSON");

    // Make sure this fixture really lacks the optional blocks.
    let settings = &document["phases"][0]["settings"];
    assert!(settings["evasion"].is_null(), "the fixture altered packets");
    assert!(settings["idle_scan"].is_null(), "the fixture read a zombie");
    assert!(
        document["phases"][0]["attachments"].is_null(),
        "the fixture found managed equipment"
    );

    Validator::new().check(&document);
}

/// The fields a writer leaves out, as the schema lists them.
///
/// Every other field is always present: `null` for nothing, `[]` for an empty
/// list. [`schema`](super::schema) promises a consumer that reading an absent
/// field as the empty value is correct, so a new `skip_serializing_if` must be
/// added here.
#[test]
fn the_schema_marks_optional_exactly_the_fields_a_writer_leaves_out() {
    /// `$defs` entry, or `report` for the document itself, then field.
    const OMITTED: &[(&str, &str)] = &[
        // Absent when every accepted suite is one this build knows.
        ("accepted_version", "unrecognised"),
        ("attachment", "device_mac"),
        ("attachment", "device_name"),
        ("attachment", "management_address"),
        ("attachment", "native_vlan"),
        ("attachment", "port"),
        // Absent for a strategy that failed outright, not cut short by a limit.
        ("failure", "cut_short"),
        // Only a correlation carries the first three; one against an upstream
        // build omits the build and the stamp.
        ("finding", "advised_by"),
        ("finding", "build"),
        ("finding", "cpe"),
        ("finding", "cpes"),
        ("finding", "excerpt"),
        // Absent unless a known-exploited list names one of its vulnerabilities.
        ("finding", "exploited"),
        // Absent when the detection covers its weakness by itself (most).
        ("finding", "group"),
        ("finding", "remediation"),
        ("finding", "subject"),
        // A rule names whichever parts of a box it knows, usually one or two.
        ("hardware", "cpe23"),
        ("hardware", "family"),
        // Stated by a service, never by an address block. `serial_number` is
        // absent from every redacted document.
        ("hardware", "model"),
        ("hardware", "product"),
        ("hardware", "serial_number"),
        ("hardware", "version"),
        ("origin", "label"),
        ("phase", "attachments"),
        // Absent unless a host rationed its ICMP errors.
        ("phase", "icmp_rate_limited"),
        // Only on a port phase that no liveness pass preceded.
        ("phase", "liveness_skipped"),
        // Only on a phase still open when the sitting was killed.
        ("phase", "open"),
        ("phase", "origin"),
        // Absent unless a stop cut a pass.
        ("phase", "passes_cut"),
        // Absent when everything was reached the way the privilege says, as in
        // every unprivileged phase.
        ("phase", "reached_by_connect"),
        // Absent when the phase declined nothing.
        ("phase", "refusals"),
        // Absent unless a local route refused an address.
        ("phase", "refused_by_route"),
        // Only on a port phase standing in for a dropped liveness pass, and only
        // when some address stayed silent.
        ("phase", "silent"),
        // Absent unless the phase was stopped.
        ("phase", "stopped"),
        // Absent unless a host ran out of its per-host budget.
        ("phase", "timed_out"),
        // Absent when every address got a verdict, as in every finished sweep
        // and every port scan.
        ("phase", "undecided"),
        // As `silent`: only on a stand-in for a liveness pass, and only when
        // some address went unheard.
        ("phase", "unheard_probes"),
        // Only on a port scan whose walk did not finish.
        ("phase", "unreached"),
        // Report-wide versions of the phase lists, absent when empty.
        ("report", "timed_out"),
        ("report", "undecided"),
        ("report", "unreached"),
        ("scope", "listened"),
        // Absent unless the scan enumerated suites.
        ("security", "accepts"),
        // Absent when every walk on the port finished.
        ("security", "unfinished"),
        ("settings", "evasion"),
        ("settings", "excluded_ports"),
        ("settings", "idle_scan"),
    ];

    /// Objects describing a technique's profile, where every field is optional.
    const OMITTED_WHOLESALE: &[&str] = &["evasion", "idle_scan"];

    let schema: Value = serde_json::from_str(SCHEMA).expect("valid JSON");
    let definitions = schema["$defs"]
        .as_object()
        .expect("the schema defines types");

    let mut optional: Vec<(String, String)> = Vec::new();
    // The document itself, beside the types it is built from.
    let report = String::from("report");
    for (name, definition) in definitions.iter().chain([(&report, &schema)]) {
        let Some(properties) = definition["properties"].as_object() else {
            continue;
        };
        let required: BTreeSet<&str> = definition["required"]
            .as_array()
            .map(|names| names.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();

        if OMITTED_WHOLESALE.contains(&name.as_str()) {
            assert!(
                required.is_empty(),
                "`{name}` describes one technique's profile and every part of it \
                 is optional; `{required:?}` says otherwise"
            );
            continue;
        }

        for field in properties.keys() {
            if !required.contains(field.as_str()) {
                optional.push((name.clone(), field.clone()));
            }
        }
    }
    optional.sort();

    let expected: Vec<(String, String)> = OMITTED
        .iter()
        .map(|(object, field)| ((*object).to_string(), (*field).to_string()))
        .collect();

    assert_eq!(
        optional, expected,
        "the schema's optional fields are not the ones `schema`'s module \
         documentation tells a consumer to expect"
    );
}

/// Redacted hostnames and hardware addresses still match the schema.
#[test]
fn a_redacted_report_matches_the_schema() {
    Validator::new().check(&document(
        ExportOptions::new().with_redaction(Redaction::Standard),
    ));
}

/// The schema rejects malformed documents, so passing it means something.
#[test]
fn the_schema_rejects_a_document_it_should_reject() {
    let validator = Validator::new();

    let mut missing_field = document(ExportOptions::new());
    missing_field
        .as_object_mut()
        .expect("an object")
        .remove("summary");
    assert!(
        !validator.accepts(&missing_field),
        "a report with no summary must not validate"
    );

    let mut unknown_field = document(ExportOptions::new());
    unknown_field["hosts"][0]["surprise"] = Value::from("undocumented");
    assert!(
        !validator.accepts(&unknown_field),
        "a field the schema does not describe must not validate - that failure \
         is what stops the schema drifting away from the DTO"
    );

    let mut float_timestamp = document(ExportOptions::new());
    float_timestamp["generated_at"] = Value::from(1_770_000_000.5);
    assert!(
        !validator.accepts(&float_timestamp),
        "an epoch float must not pass where an RFC 3339 string is promised"
    );

    let mut rounded_count = document(ExportOptions::new());
    rounded_count["phases"][0]["targets"]["addresses"] = Value::from(256);
    assert!(
        !validator.accepts(&rounded_count),
        "a count that can exceed 2^53 must be a string, not a number"
    );
}

/// Every line of a JSON Lines export validates on its own, so files can be
/// split, filtered and concatenated.
#[cfg(feature = "export-jsonl")]
#[test]
fn every_exported_line_matches_the_lines_schema() {
    let validator = Validator::lines();

    for options in [
        ExportOptions::new(),
        ExportOptions::new().with_redaction(Redaction::Standard),
    ] {
        let mut bytes = Vec::new();
        crate::export::JsonLinesExporter::new(options)
            .export(&fixture::report(), &mut bytes)
            .expect("the export succeeds");

        let text = String::from_utf8(bytes).expect("utf-8");
        let mut records = 0;
        for line in text.lines() {
            let record: Value = serde_json::from_str(line).expect("a line parses on its own");
            validator.check(&record);
            records += 1;
        }

        assert_eq!(records, 4, "a report record and three hosts");
    }
}

/// The lines schema is written in terms of the report schema, so it rejects on
/// the same grounds, and also rejects a record naming no type.
#[cfg(feature = "export-jsonl")]
#[test]
fn the_lines_schema_rejects_a_record_it_should_reject() {
    let validator = Validator::lines();

    let host = document(ExportOptions::new())["hosts"][0].clone();
    assert!(
        !validator.accepts(&host),
        "a host object with no `type` is not a record"
    );

    let mut mislabelled = host.clone();
    mislabelled["type"] = Value::from("report");
    assert!(
        !validator.accepts(&mislabelled),
        "a host wearing the report tag must not validate as either"
    );

    let mut tagged = host;
    tagged["type"] = Value::from("host");
    assert!(validator.accepts(&tagged), "a tagged host is a host record");

    let mut surprising = tagged;
    surprising["surprise"] = Value::from("undocumented");
    assert!(
        !validator.accepts(&surprising),
        "a field the schema does not describe must not validate"
    );
}

// ---------------------------------------------------------------------------
// The comparison document
// ---------------------------------------------------------------------------

/// Exports a comparison and parses it back.
fn comparison(
    baseline: &crate::report::ScanReport,
    current: &crate::report::ScanReport,
    options: ExportOptions,
) -> Value {
    use crate::diff::ScanDiff;
    use crate::export::diff::{DiffExporter, JsonDiffExporter};

    let diff = ScanDiff::between(baseline, current);
    let mut bytes = Vec::new();
    JsonDiffExporter::new(options)
        .export(&diff, &mut bytes)
        .expect("the export succeeds");

    serde_json::from_slice(&bytes).expect("the export parses as JSON")
}

#[test]
fn the_published_comparison_schema_compiles() {
    let _ = Validator::diff();
}

/// The comparison version the code emits is the one its schema pins.
#[test]
fn the_comparison_schema_pins_the_version_the_code_emits() {
    let schema: Value = serde_json::from_str(DIFF_SCHEMA).expect("valid JSON");

    assert_eq!(
        schema["properties"]["schema_version"]["const"],
        Value::from(crate::format::DIFF_SCHEMA_VERSION)
    );
}

/// A comparison carrying one of every kind of change is a document the published
/// schema accepts.
#[test]
fn a_comparison_matches_the_published_schema() {
    let (before, after) = fixture::compared();
    let document = comparison(&before, &after, ExportOptions::new());
    Validator::diff().check(&document);
}

/// Two identical scans still produce a valid document of the same shape.
#[test]
fn an_unchanged_comparison_matches_the_published_schema() {
    let report = fixture::report();
    let document = comparison(&report, &report, ExportOptions::new());

    Validator::diff().check(&document);
    assert_eq!(document["unchanged"], Value::Bool(true));
    assert_eq!(document["hosts"].as_array().map(Vec::len), Some(0));
}

/// Redaction applies to a comparison as it does to a report.
#[test]
fn a_redacted_comparison_masks_what_a_redacted_report_masks() {
    let (before, after) = fixture::compared();
    let document = comparison(
        &before,
        &after,
        ExportOptions::new().with_redaction(Redaction::Standard),
    );

    Validator::diff().check(&document);

    let rendered = document.to_string();
    assert!(
        !rendered.contains("router.local") && !rendered.contains("gateway.local"),
        "a hostname survived redaction into the comparison"
    );
    assert!(
        document
            .pointer("/hosts/0/changes")
            .is_some_and(|changes| changes.to_string().contains("name_gained"))
            && !rendered.contains("ROUTER")
            && !rendered.contains("GATEWAY"),
        "a name the host gave for itself survived redaction into the comparison"
    );
    assert!(
        !rendered.contains("2c:cf:67:00:00:01"),
        "a hardware address survived redaction into the comparison"
    );
}

/// Redaction masks a phase's attachment, which names a switch and its hardware
/// address.
///
/// A switch name is an internal hostname and a chassis address is a real MAC,
/// and both sit outside the `hosts` array the other redaction tests look at. The
/// JSON Lines writer is checked too because it renders the header through a
/// different type.
#[test]
fn redaction_masks_the_switch_a_phase_says_it_was_plugged_into() {
    let report = fixture::report();
    let options = ExportOptions::new().with_redaction(Redaction::Standard);

    let attachment = report.phases()[0]
        .attachments()
        .first()
        .expect("the fixture records one");
    let name = attachment.device_name().expect("a device name");
    let mac = attachment
        .device_mac()
        .expect("a device address")
        .to_string();

    let mut json = Vec::new();
    JsonExporter::new(options.clone())
        .export(&report, &mut json)
        .expect("the report exports");
    let json = String::from_utf8(json).expect("valid UTF-8");

    assert!(
        !json.contains(name),
        "the switch's name survived redaction: {json}"
    );
    assert!(
        !json.contains(&mac),
        "the switch's hardware address survived redaction"
    );
    assert!(
        json.contains("GigabitEthernet1/0/14"),
        "the port is not a name or an address and is what the finding is for"
    );

    let mut lines = Vec::new();
    crate::export::JsonLinesExporter::new(options)
        .export(&report, &mut lines)
        .expect("the report exports");
    let lines = String::from_utf8(lines).expect("valid UTF-8");

    assert!(
        !lines.contains(name) && !lines.contains(&mac),
        "the header of a record-per-line document leaked what the single \
         document masked"
    );
}

/// Every token the change vocabulary can emit is a value the published schema
/// accepts.
///
/// Covers only the changes the fixtures produce;
/// `the_schema_accepts_exactly_the_change_kinds_the_exporter_emits` covers the
/// rest.
#[test]
fn every_change_the_fixtures_produce_is_a_token_the_schema_accepts() {
    let schema: Value = serde_json::from_str(DIFF_SCHEMA).expect("valid JSON");
    let accepted: Vec<&str> = schema["$defs"]["change"]["properties"]["kind"]["enum"]
        .as_array()
        .expect("the schema names the tokens it accepts")
        .iter()
        .filter_map(Value::as_str)
        .collect();

    let (before, after) = fixture::compared();
    let document = comparison(&before, &after, ExportOptions::new());
    let mut seen = 0usize;

    for host in document["hosts"].as_array().expect("hosts") {
        for change in host["changes"].as_array().expect("changes") {
            let kind = change["kind"].as_str().expect("a token");
            assert!(accepted.contains(&kind), "'{kind}' is not in the schema");
            seen += 1;
        }
        for port in host["ports"].as_array().expect("ports") {
            for change in port["changes"].as_array().expect("changes") {
                let kind = change["kind"].as_str().expect("a token");
                assert!(accepted.contains(&kind), "'{kind}' is not in the schema");
                seen += 1;
            }
        }
    }

    assert!(seen > 0, "the fixtures produced no changes to check");
}

/// The change kinds the comparison exporter emits, read out of its own source.
///
/// Every kind reaches the document through one of these constructors, and
/// [`ChangeDto::set`] names two. Reading the source avoids constructing one of
/// every change by hand.
fn emitted_change_kinds() -> BTreeSet<String> {
    const SOURCE: &str = include_str!("diff/schema.rs");

    let pattern = Regex::new(
        r#"Self::(?:between|gained|lost|optional|set)\(\s*"([a-z_]+)"(?:\s*,\s*"([a-z_]+)")?"#,
    )
    .expect("a valid pattern");

    let mut kinds = BTreeSet::new();
    for captures in pattern.captures_iter(SOURCE) {
        for group in [1, 2] {
            if let Some(kind) = captures.get(group) {
                kinds.insert(kind.as_str().to_string());
            }
        }
    }
    kinds
}

/// The kinds the published schema will accept.
fn accepted_change_kinds() -> BTreeSet<String> {
    let schema: Value = serde_json::from_str(DIFF_SCHEMA).expect("the schema parses");
    schema["$defs"]["change"]["properties"]["kind"]["enum"]
        .as_array()
        .expect("the kind enum is a list")
        .iter()
        .map(|kind| kind.as_str().expect("every kind is a string").to_string())
        .collect()
}

/// The exporter and the schema name the same set of change kinds.
///
/// `a_comparison_matches_the_published_schema` sees only the kinds the fixture
/// produces; this covers the rest.
#[test]
fn the_schema_accepts_exactly_the_change_kinds_the_exporter_emits() {
    let emitted = emitted_change_kinds();
    let accepted = accepted_change_kinds();

    assert!(
        !emitted.is_empty(),
        "the source scan found no change kinds, so it is checking nothing"
    );

    let unlisted: Vec<&String> = emitted.difference(&accepted).collect();
    let unemitted: Vec<&String> = accepted.difference(&emitted).collect();

    assert!(
        unlisted.is_empty(),
        "the exporter emits kinds the published schema rejects: {unlisted:?}"
    );
    assert!(
        unemitted.is_empty(),
        "the schema lists kinds nothing emits: {unemitted:?}"
    );
}

/// The two JSON encodings of a host name their fields the same way.
///
/// A `Host` reaches a file as a [`HostRecord`](crate::record::HostRecord) in the
/// journal and as a `HostDto` in an exported report. Their encodings differ (a
/// duration is a `Duration` in one and integer microseconds in the other, and
/// the report adds derived fields), but where both name the same thing they must
/// spell it the same way.
///
/// This compares the field names the two emit; the lists below are the only
/// permitted differences.
#[test]
fn the_journal_and_the_report_spell_a_host_the_same_way() {
    use crate::record::HostRecord;

    /// Fields one side carries and the other has no reason to.
    ///
    /// Adding a field to one side only fails this test until it is listed
    /// here or in `REPORT_ONLY`.
    const RECORD_ONLY: &[&str] = &[
        // The document carries the OS verdict and not the sources behind it.
        "os_evidence",
        // Round-trip samples, which the report renders as statistics.
        "rtts",
        "hop_counter",
        // Durations, which the report writes as integers of microseconds.
        "rtt",
        "elapsed",
        "first_reply",
        "last_reply",
        // The interface a link-local address is valid on.
        "zone",
        // The retry policy, flattened here and nested under `retry` there.
        "retry_effort",
        "retry_max_attempts",
        "retry_timeout_scale",
        "retry_dampen_silent_hosts",
        // serde's encoding of `SystemTime` and `Duration`; the report writes an
        // RFC 3339 string and integer microseconds.
        "secs_since_epoch",
        "nanos_since_epoch",
        "secs",
        "nanos",
        // A finding's detection identity, nested here and flattened into
        // `id`, `version` and `content_hash` there.
        "detection",
        // Part of `os_evidence`, which the report does not carry.
        "source",
    ];

    /// Fields the report derives for a reader that the journal does not store.
    const REPORT_ONLY: &[&str] = &[
        "alive",
        "families",
        "at",
        "decoration",
        "fe80",
        "mac",
        "vendor",
        "redaction",
        "family",
        "complete",
        "kind",
        "position",
        "data",
        "trip",
        "samples",
        "jitter_us",
        "rtt_avg_us",
        "rtt_max_us",
        "rtt_median_us",
        "rtt_min_us",
        "rtt_us",
        "elapsed_us",
        "first_reply_us",
        "last_reply_us",
        "probe_stats",
        "retry",
        "services",
        "systems",
        // The journal stores a cipher suite by wire number only; the reading
        // build derives its name, grade and faults, so a record cannot disagree
        // with the engine that reads it back.
        "code",
        "strength",
        "faults",
        "deprecated",
    ];

    let report = fixture::report();
    let host = report.hosts().next().expect("the fixture has a host");

    let recorded: Value =
        serde_json::to_value(HostRecord::from(host)).expect("a host records as JSON");
    let exported = &document(ExportOptions::new())["hosts"][0];

    let record_names = field_names(&recorded);
    let export_names = field_names(exported);

    let unmatched_record: Vec<&String> = record_names
        .difference(&export_names)
        .filter(|name| !RECORD_ONLY.contains(&name.as_str()))
        .collect();
    let unmatched_export: Vec<&String> = export_names
        .difference(&record_names)
        .filter(|name| !REPORT_ONLY.contains(&name.as_str()))
        .collect();

    assert!(
        unmatched_record.is_empty(),
        "the journal names fields the report does not, and they are not listed as \
         journal-only: {unmatched_record:?}"
    );
    assert!(
        unmatched_export.is_empty(),
        "the report names fields the journal does not, and they are not listed as \
         report-only: {unmatched_export:?}"
    );
}

/// Every field name in a JSON value, at any depth.
fn field_names(value: &Value) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    fn walk(value: &Value, names: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    names.insert(key.clone());
                    walk(child, names);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| walk(item, names)),
            _ => {}
        }
    }
    walk(value, &mut names);
    names
}

/// **Every string the schema declares is one the hostile fixture poisons.**
///
/// The escaping tests (`no_field_of_a_hostile_report_reaches_the_page_unescaped`
/// and its XML and CSV siblings) only cover the fields
/// [`fixture::hostile`](crate::export::fixture::hostile) poisons.
///
/// Most string properties are the engine's own (enum names, timestamps,
/// addresses), but `device_name`, `device_mac` and `management_address` come
/// from unauthenticated LLDP and CDP, `extrainfo` from a service banner and
/// `kernel` from a fingerprint.
///
/// A string property added to the schema fails here until the fixture carries a
/// hostile value in it or it is listed in [`ENGINE_WRITTEN`]. Keep that list
/// short.
#[test]
fn the_hostile_fixture_poisons_every_string_the_schema_declares() {
    /// Properties no remote bytes can reach.
    ///
    /// Most are the engine's own: enum names, timestamps, versions, the
    /// operator's settings.
    ///
    /// The rest are remote values **parsed into a type before they are ever a
    /// string.** `device_mac` and `management_address` arrive in an LLDP or CDP
    /// advertisement and are read into a `MacAddr` and an `IpAddr` at the frame
    /// reader; the document holds this crate's rendering of that value. Their
    /// neighbour `device_name` is a free string and is *not* exempt.
    const ENGINE_WRITTEN: &[&str] = &[
        "algorithm",
        "at",
        "class",
        "code",
        "confidence",
        "digest",
        "device_mac",
        "digest_algorithm",
        "end",
        "engine_version",
        "excluded_ports",
        "family",
        "first_seen",
        "flags",
        "generated_at",
        "kind",
        "label",
        "last_seen",
        "link",
        "mac",
        "macs",
        "management_address",
        "name",
        "primary_ip",
        "produced_by",
        "protocol",
        "public_key",
        "reason",
        "scanner",
        "severity",
        "signature",
        "source_ip",
        "spec",
        "spoof_mac",
        "start",
        "started_at",
        "state",
        "status",
        "stop_reason",
        "targets",
        "timestamp",
        "validity_end",
        "validity_start",
        "version",
        "withheld",
        "zombie",
        "zone",
    ];

    let mut bytes = Vec::new();
    JsonExporter::new(ExportOptions::new())
        .export(&fixture::hostile(), &mut bytes)
        .expect("the hostile export succeeds");
    let document: Value = serde_json::from_slice(&bytes).expect("it parses as JSON");

    // Every string-valued property the schema declares, by name.
    fn declared(value: &Value, out: &mut BTreeSet<String>) {
        let Some(map) = value.as_object() else {
            return;
        };
        if let Some(Value::Object(properties)) = map.get("properties") {
            for (name, property) in properties {
                let is_string = property.get("type").and_then(Value::as_str) == Some("string")
                    || property
                        .get("type")
                        .and_then(Value::as_array)
                        .is_some_and(|any| any.iter().any(|t| t.as_str() == Some("string")));
                if is_string {
                    out.insert(name.clone());
                }
                declared(property, out);
            }
        }
        for key in ["items", "additionalProperties", "$defs", "definitions"] {
            if let Some(sub) = map.get(key) {
                declared(sub, out);
            }
        }
        if let Some(Value::Object(defs)) = map.get("$defs") {
            for sub in defs.values() {
                declared(sub, out);
            }
        }
        for key in ["oneOf", "anyOf", "allOf"] {
            if let Some(Value::Array(items)) = map.get(key) {
                for item in items {
                    declared(item, out);
                }
            }
        }
    }

    // Every property the hostile document carries a poisoned value in.
    fn poisoned(value: &Value, out: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                for (name, sub) in map {
                    if sub
                        .as_str()
                        .is_some_and(|text| text.contains(fixture::HOSTILE))
                    {
                        out.insert(name.clone());
                    }
                    if let Value::Array(items) = sub
                        && items
                            .iter()
                            .any(|i| i.as_str().is_some_and(|t| t.contains(fixture::HOSTILE)))
                    {
                        out.insert(name.clone());
                    }
                    poisoned(sub, out);
                }
            }
            Value::Array(items) => {
                for item in items {
                    poisoned(item, out);
                }
            }
            _ => {}
        }
    }

    let schema: Value = serde_json::from_str(SCHEMA).expect("the schema file is valid JSON");
    let mut names = BTreeSet::new();
    declared(&schema, &mut names);
    let mut carried = BTreeSet::new();
    poisoned(&document, &mut carried);

    let clean: Vec<&String> = names
        .iter()
        .filter(|name| !carried.contains(*name) && !ENGINE_WRITTEN.contains(&name.as_str()))
        .collect();

    assert!(
        clean.is_empty(),
        "the schema declares these strings and the hostile fixture leaves them clean, so no \
         escaping test covers them: {clean:?}\n\nEither give the field a hostile value in \
         `fixture::hostile`, or — if no remote host can influence it — add it to \
         ENGINE_WRITTEN with that reasoning."
    );
}

// ---------------------------------------------------------------------------
// Names in the host's own words
// ---------------------------------------------------------------------------

/// Every rendering of the [`fixture::named`] host this build can write, by
/// format:
///
/// - each report format;
/// - each comparison format, against the earlier record and against
///   [`fixture::named_late`], whose earlier record names the host only in its
///   text;
/// - each report format over the merge of [`fixture::renamed`], which keeps the
///   text of the record whose names it replaced.
fn named_renderings(options: &ExportOptions) -> Vec<(String, String)> {
    use crate::diff::ScanDiff;
    use crate::export::diff::DiffExporter;
    use crate::merge::{Merge, MergeOptions};
    use crate::report::ScanReport;

    let mut rendered = Vec::new();
    let mut write = |format: String, export: &dyn Fn(&mut Vec<u8>)| {
        let mut bytes = Vec::new();
        export(&mut bytes);
        rendered.push((format, String::from_utf8(bytes).expect("utf-8")));
    };
    let mut reports = |label: &str, report: &ScanReport| {
        for format in crate::export::ExportFormat::all() {
            write(format!("{label}{}", format.extension()), &|bytes| {
                format
                    .exporter(options.clone())
                    .export(report, bytes)
                    .expect("the report exports");
            });
        }
    };

    let (before, after) = fixture::named();
    reports("", &after);

    let (old, new) = fixture::renamed();
    let mut merge = Merge::new(MergeOptions::default());
    merge.add(old).add(new);
    reports("merged ", &merge.finish());

    let (unnamed, _) = fixture::named_late();
    for (label, baseline) in [("", &before), (" named late", &unnamed)] {
        let diff = ScanDiff::between(baseline, &after);
        write(format!("diff json{label}"), &|bytes| {
            crate::export::diff::JsonDiffExporter::new(options.clone())
                .export(&diff, bytes)
                .expect("the comparison exports");
        });
        #[cfg(feature = "export-html")]
        write(format!("diff html{label}"), &|bytes| {
            crate::export::diff::HtmlDiffExporter::new(options.clone())
                .export(&diff, bytes)
                .expect("the comparison exports");
        });
    }

    rendered
}

/// `text` lowercased and with NULs removed in every form a format writes them,
/// so a UTF-16 name read byte for byte matches.
fn as_searched(text: &str) -> String {
    text.replace(r#"<span class="ctl">U+0000</span>"#, "")
        .replace("\\u0000", "")
        .replace("&#x0;", "")
        .replace("&#0;", "")
        .replace('\0', "")
        .to_lowercase()
}

/// A name the host gave reaches a report inside its replies as well as in its
/// fields: an SMB reply in a finding's excerpt, a banner, a title filled from a
/// reply, a service's extra information, a certificate issuer. Every format,
/// including comparisons and a merge, is searched for each name in any case and
/// with UTF-16 NULs removed.
///
/// Comparisons and merges are rendered from a pair in which the record whose
/// text names the host is not the one that states the names.
#[test]
fn no_format_carries_a_name_the_host_gave_under_redaction() {
    let names: Vec<String> = [fixture::NAMED_HOST, fixture::NAMED_DOMAIN]
        .iter()
        .map(|name| name.to_lowercase())
        .collect();

    for (format, text) in named_renderings(&ExportOptions::new()) {
        let searched = as_searched(&text);
        assert!(
            names.iter().all(|name| searched.contains(name)),
            "the unredacted {format} does not carry the names, so this test checks nothing"
        );
    }

    // Every leak at once, so a failure says which formats share it.
    let redacted = ExportOptions::new().with_redaction(Redaction::Standard);
    let leaks: Vec<String> = named_renderings(&redacted)
        .into_iter()
        .flat_map(|(format, text)| {
            let searched = as_searched(&text);
            names
                .iter()
                .filter(move |name| searched.contains(name.as_str()))
                .map(move |name| format!("the redacted {format} still names `{name}`"))
        })
        .collect();
    assert!(leaks.is_empty(), "{leaks:#?}");
}

/// Every path under a host record at which the schema declares a free
/// string, as `host.ports[].service.product`: a property of type `string`, or
/// an array of them, reached through every reference.
fn host_string_paths() -> BTreeSet<String> {
    fn walk(
        node: &Value,
        path: &str,
        defs: &Value,
        within: &mut Vec<String>,
        out: &mut BTreeSet<String>,
    ) {
        if let Some(reference) = node.get("$ref").and_then(Value::as_str) {
            let name = reference
                .rsplit('/')
                .next()
                .expect("a reference names a definition");
            if !within.iter().any(|seen| seen == name) {
                within.push(name.to_owned());
                walk(&defs[name], path, defs, within, out);
                within.pop();
            }
            return;
        }
        for key in ["oneOf", "anyOf", "allOf"] {
            if let Some(Value::Array(branches)) = node.get(key) {
                for branch in branches {
                    walk(branch, path, defs, within, out);
                }
            }
        }
        let is_string = match node.get("type") {
            Some(Value::String(kind)) => kind == "string",
            Some(Value::Array(kinds)) => kinds.iter().any(|kind| kind == "string"),
            _ => false,
        };
        if is_string {
            out.insert(path.to_owned());
        }
        if let Some(items) = node.get("items") {
            walk(items, &format!("{path}[]"), defs, within, out);
        }
        if let Some(Value::Object(properties)) = node.get("properties") {
            for (name, property) in properties {
                walk(property, &format!("{path}.{name}"), defs, within, out);
            }
        }
    }

    let schema: Value = serde_json::from_str(SCHEMA).expect("the schema file is valid JSON");
    let defs = &schema["$defs"];
    let mut paths = BTreeSet::new();
    walk(&defs["host"], "host", defs, &mut Vec::new(), &mut paths);
    paths
}

/// Every path in a rendered host record at which a string names the
/// [`fixture::named`] host, spelled as [`host_string_paths`] spells them.
fn host_paths_naming(host: &Value) -> BTreeSet<String> {
    fn walk(value: &Value, path: &str, out: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                for (key, sub) in map {
                    walk(sub, &format!("{path}.{key}"), out);
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, &format!("{path}[]"), out);
                }
            }
            Value::String(text) => {
                let searched = as_searched(text);
                if [fixture::NAMED_HOST, fixture::NAMED_DOMAIN]
                    .iter()
                    .any(|name| searched.contains(&name.to_lowercase()))
                {
                    out.insert(path.to_owned());
                }
            }
            _ => {}
        }
    }

    let mut paths = BTreeSet::new();
    walk(host, "host", &mut paths);
    paths
}

/// **Every free string the schema declares for a host carries the host's
/// name in the fixture, or is one no host can fill.**
///
/// `no_format_carries_a_name_the_host_gave_under_redaction` only covers the
/// fields [`fixture::named`] names the host in. A string added to the host
/// record fails here until the fixture names the host in it, or it is listed
/// below with the reason no host can.
///
/// It then checks the redacted values are masked in place: a finding keeps its
/// claim, and a binary excerpt is replaced by a note that it was withheld.
#[test]
fn redaction_masks_the_host_s_words_in_every_field_its_replies_fill() {
    /// Strings in a host record that no reply, and no rule reading one, can
    /// fill:
    ///
    /// - the engine's own: timestamps, a detection's identity, the name a
    ///   strategy gives its evidence, an interface on the scanning machine;
    /// - values parsed into a type before they are a string: addresses, hardware
    ///   addresses, a fingerprint, a suite's number;
    /// - values a reply only selects from a closed set this crate offered: a
    ///   protocol version, a cipher suite, a key algorithm, an application
    ///   protocol.
    const UNFILLABLE: &[&str] = &[
        // The advisory dataset's own stamp, chosen by the engine or operator.
        "host.findings[].advised_by.content_hash",
        "host.findings[].advised_by.id",
        "host.findings[].advised_by.version",
        "host.findings[].content_hash",
        // The exploited-vulnerabilities list's stamp and CVE identifiers.
        "host.findings[].exploited.by.content_hash",
        "host.findings[].exploited.by.id",
        "host.findings[].exploited.by.version",
        "host.findings[].exploited.cves[]",
        // Fixed in the detection manifest; unlike a finding's title it has no
        // `{var}` a reply could fill.
        "host.findings[].group.id",
        "host.findings[].group.summary",
        "host.findings[].id",
        "host.findings[].version",
        "host.first_seen",
        "host.hardware.mac",
        "host.hardware.macs[]",
        "host.ip_protocols[].name",
        "host.ips[]",
        "host.last_seen",
        "host.path[].address",
        "host.ports[].discovery.reason",
        "host.ports[].discovery.source_ip",
        "host.ports[].discovery.timestamp",
        "host.ports[].findings[].advised_by.content_hash",
        "host.ports[].findings[].advised_by.id",
        "host.ports[].findings[].advised_by.version",
        "host.ports[].findings[].content_hash",
        "host.ports[].findings[].exploited.by.content_hash",
        "host.ports[].findings[].exploited.by.id",
        "host.ports[].findings[].exploited.by.version",
        "host.ports[].findings[].exploited.cves[]",
        "host.ports[].findings[].group.id",
        "host.ports[].findings[].group.summary",
        "host.ports[].findings[].id",
        "host.ports[].findings[].version",
        "host.ports[].security.accepts[].suites[].code",
        "host.ports[].security.accepts[].suites[].name",
        "host.ports[].security.accepts[].unrecognised[]",
        "host.ports[].security.alpn[]",
        "host.ports[].security.certificate.fingerprint_sha256",
        "host.ports[].security.certificate.pubkey_type",
        "host.ports[].security.certificate.validity_end",
        "host.ports[].security.certificate.validity_start",
        "host.ports[].security.cipher_suite",
        "host.ports[].security.tls_version",
        "host.primary_ip",
        "host.reasons[].protocol",
        "host.reasons[].source_ip",
        "host.zone",
    ];

    let (_, after) = fixture::named();
    let render = |options: ExportOptions| -> Value {
        let mut bytes = Vec::new();
        JsonExporter::new(options)
            .export(&after, &mut bytes)
            .expect("the report exports");
        serde_json::from_slice::<Value>(&bytes).expect("it parses")["hosts"][0].clone()
    };

    let declared = host_string_paths();
    let named = host_paths_naming(&render(ExportOptions::new()));
    let unfillable: BTreeSet<String> = UNFILLABLE.iter().map(|path| path.to_string()).collect();

    let stale: Vec<&String> = unfillable.difference(&declared).collect();
    assert!(
        stale.is_empty(),
        "the schema declares no such string, so the exemption is stale: {stale:?}"
    );
    let contradicted: Vec<&String> = unfillable.intersection(&named).collect();
    assert!(
        contradicted.is_empty(),
        "the fixture names the host in a string listed as one no host can fill: {contradicted:?}"
    );
    let unnamed: Vec<&String> = declared
        .iter()
        .filter(|path| !named.contains(*path) && !unfillable.contains(*path))
        .collect();
    assert!(
        unnamed.is_empty(),
        "the named fixture leaves these strings without the host's name, so no redaction \
         test covers them: {unnamed:?}\n\nEither name the host in them in \
         `fixture::named`, or, if no host can fill one, add it to UNFILLABLE with that \
         reasoning."
    );

    let host = render(ExportOptions::new().with_redaction(Redaction::Standard));
    let ports = host["ports"].as_array().expect("ports");
    let smb = ports
        .iter()
        .find(|port| port["port"] == 445)
        .expect("the SMB port");
    assert_eq!(smb["findings"][0]["title"], "SMBv1 is enabled on XXXXX");
    assert_eq!(
        smb["findings"][0]["excerpt"],
        crate::export::redact::WITHHELD_EXCERPT
    );
    assert_eq!(smb["service"]["extrainfo"], "workgroup: COXXXXXSO");
    assert_eq!(smb["service"]["cpes"][0], "cpe:/a:samba:samba:4.15:XXXXX");
    let banner = ports
        .iter()
        .find(|port| port["port"] == 40390)
        .expect("the port named by its banner");
    assert_eq!(banner["service"]["name"], "banner: zq7 node fsXXXXXle ok");
    assert_eq!(host["hardware"]["product"], "PowerEdge XXXXX");
    assert_eq!(
        host["os"]["cpes"][0],
        "cpe:/o:microsoft:windows_server_2019:XXXXX"
    );
    let details: Vec<&Value> = host["reasons"]
        .as_array()
        .expect("reasons")
        .iter()
        .map(|reason| &reason["details"])
        .collect();
    assert!(
        details.contains(&&Value::from("syn-ack from XXXXX")),
        "{details:?}"
    );
    let smtp = ports
        .iter()
        .find(|port| port["port"] == 25)
        .expect("the SMTP port");
    assert_eq!(
        smtp["findings"][0]["excerpt"],
        "220 fsXXXXXle Microsoft ESMTP MAIL Service ready"
    );
    let ssh = ports
        .iter()
        .find(|port| port["port"] == 22)
        .expect("the SSH port");
    let correlated = &ssh["findings"][0];
    assert_eq!(correlated["cpe"], "cpe:/a:openbsd:openssh:XXXXX");
    assert_eq!(correlated["cpes"][0], "cpe:/a:openbsd:openssh:XXXXX");
    assert_eq!(correlated["references"][0]["value"], "CVE-2023-38408");
    assert_eq!(
        correlated["references"][1]["value"],
        "https://advisories.example/XXXXX"
    );
}
