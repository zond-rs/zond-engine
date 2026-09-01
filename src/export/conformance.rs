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
//! a consumer validates against. A schema nobody checks drifts: a field added to
//! a DTO, a `null` that becomes a string, an enum that gains a variant, and the
//! file on disk stops describing the thing it claims to.
//!
//! The schema is strict, with every object closed and every field required
//! except the handful a writer omits when it has nothing to say, and these tests
//! run the real exporter against it. Adding a field to a DTO without describing
//! it here fails the build.
//!
//! That handful is itself pinned, by
//! `the_schema_marks_optional_exactly_the_fields_a_writer_leaves_out`. The
//! module documentation of [`schema`](super::schema) tells a consumer what an
//! absent field means, and a `skip_serializing_if` added without a thought for
//! that sentence is how the two stopped agreeing once already.

use boon::{Compiler, Schemas};
use regex::Regex;
use serde_json::Value;
use std::collections::BTreeSet;

use crate::config::{OsDetection, ScanEffort, ServiceDetection};
use crate::export::schema::{SCHEMA_VERSION, scan_effort_name, send_mode_name};
use crate::export::{ExportOptions, Exporter, JsonExporter, Redaction, fixture};
use crate::model::confidence::Confidence;
use crate::model::finding::{DetectionClass, Severity};
use crate::model::host::status::StatusProtocol;
use crate::model::host::{Filtering, HostStatus, NetworkRole};
use crate::model::port::{PortState, Protocol};
use crate::model::technique::TcpScanTechnique;
use crate::record::wire::{
    attachment_source_name, confidence_name, detection_class_name, filtering_name,
    host_status_name, network_role_name, port_state_name, protocol_name, scan_kind_name,
    scanner_kind_name, severity_name, stop_reason_name,
};
use crate::report::{AttachmentSource, ScanKind, ScannerKind, StopReason};
use crate::transport::probe::SendMode;

/// The published schemas, compiled into the test binary so a test cannot pass
/// against a file that was not shipped.
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
    /// Validates one record, not a file: JSON Lines is not one JSON document.
    fn lines() -> Self {
        Self::over(LINES_SCHEMA_URL)
    }

    /// A validator over the comparison schema.
    fn diff() -> Self {
        Self::over(DIFF_SCHEMA_URL)
    }

    /// Compiles both schemas and points a validator at one of them.
    ///
    /// All three are registered whichever is being compiled. The lines and
    /// comparison schemas are written in terms of the report schema's
    /// definitions and cannot resolve without it.
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

/// The schema has to be a schema before it can pin anything.
#[test]
fn the_published_schema_compiles() {
    let _ = Validator::new();
}

/// The version the code emits and the version the schema pins are the same
/// number, or one of them was bumped without the other.
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
/// A variant the engine can write and the schema does not accept produces
/// documents no consumer's validator takes, and the document tests below cannot
/// see it since they exercise whichever variant the fixture happens to carry.
///
/// The reverse direction matters as much: a name the schema advertises and the
/// engine cannot produce is a promise to a third party writing this format that
/// both report readers then refuse. That is how `sctp` came to sit in
/// `$defs/protocol` for a release.
///
/// Only the enums whose type publishes an `ALL` are here, and every closed enum
/// in the schema has one except `port_scope`, whose variants carry data. An
/// exhaustive list written out in this file would be a third copy of the
/// variants, which is the arrangement this test exists to catch, so a new enum
/// in the document should arrive with an `ALL`.
///
/// `reason.protocol` was that gap for a while. Its eight built-in names sat in
/// the schema as a closed list with no `ALL` to compare against.
/// [`StatusProtocol::ALL`] now exists and is read below. The enum's ninth variant
/// carries a strategy-chosen name and is the schema's other `anyOf` arm, a
/// `custom:` prefix, which is a pattern rather than an enumeration.
fn enumerations() -> Vec<(&'static str, Vec<String>)> {
    let named = |names: Vec<&'static str>| names.into_iter().map(str::to_owned).collect();

    vec![
        (
            "/$defs/settings/properties/tcp_technique/enum",
            named(TcpScanTechnique::ALL.iter().map(|t| t.name()).collect()),
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
            // Inside an `anyOf`. The other arm is the `custom:` prefix a
            // strategy-supplied name is written under, a pattern rather than an
            // enumeration.
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
            "/$defs/phase/properties/kind/enum",
            named(ScanKind::ALL.iter().copied().map(scan_kind_name).collect()),
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

#[test]
fn the_schema_lists_exactly_the_enumerated_values_the_engine_writes() {
    let schema: Value = serde_json::from_str(SCHEMA).expect("valid JSON");

    for (pointer, emitted) in enumerations() {
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
/// Every test above exports the fixture that has one of everything, so the
/// schema's `required` lists are only exercised where nothing is missing. A field
/// the schema demands and this document omits would pass all of them and fail in
/// a consumer's validator.
#[test]
fn an_ordinary_report_matches_the_schema() {
    let plain = fixture::compared().0;
    let mut bytes = Vec::new();
    JsonExporter::new(ExportOptions::new())
        .export(&plain, &mut bytes)
        .expect("the export succeeds");
    let document: Value = serde_json::from_slice(&bytes).expect("the export parses as JSON");

    // Otherwise this validates the same document the test above does.
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
/// Everything else the document carries is present whatever its value: `null` for
/// nothing, `[]` for nothing in a list. These are the exception, and
/// [`schema`](super::schema) promises a consumer that reading an absent one as
/// the empty value is always correct. A `skip_serializing_if` added to a field
/// not on this list breaks that promise silently.
#[test]
fn the_schema_marks_optional_exactly_the_fields_a_writer_leaves_out() {
    /// `$defs` entry, then field.
    const OMITTED: &[(&str, &str)] = &[
        ("attachment", "device_mac"),
        ("attachment", "device_name"),
        ("attachment", "management_address"),
        ("attachment", "native_vlan"),
        ("attachment", "port"),
        ("finding", "excerpt"),
        ("finding", "remediation"),
        ("origin", "label"),
        ("phase", "attachments"),
        ("phase", "origin"),
        // A phase that declined nothing leaves this out rather than writing an
        // empty list, which is what most phases do.
        ("phase", "refusals"),
        ("scope", "listened"),
        ("settings", "evasion"),
        ("settings", "idle_scan"),
    ];

    /// The two objects that are a technique's own profile, where every field
    /// describes one part of it and any part may be absent.
    const OMITTED_WHOLESALE: &[&str] = &["evasion", "idle_scan"];

    let schema: Value = serde_json::from_str(SCHEMA).expect("valid JSON");
    let definitions = schema["$defs"]
        .as_object()
        .expect("the schema defines types");

    let mut optional: Vec<(String, String)> = Vec::new();
    for (name, definition) in definitions {
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

/// Redaction rewrites hostnames and hardware addresses. It must not rewrite
/// them into something the schema no longer accepts.
#[test]
fn a_redacted_report_matches_the_schema() {
    Validator::new().check(&document(
        ExportOptions::new().with_redaction(Redaction::Standard),
    ));
}

/// If the schema accepted anything, passing it would prove nothing. This checks
/// that it rejects.
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

/// Every line of a JSON Lines export has to validate on its own. A record that
/// only means something in the context of the file is a record that cannot be
/// split, filtered or concatenated, which is most of the reason for the format.
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

/// The version the code emits and the version the schema pins are the same
/// number, counted apart from the report's.
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

/// Two scans that found the same things still produce a document, and it is a
/// valid one: a consumer polling nightly gets the same shape whether or not
/// anything moved.
#[test]
fn an_unchanged_comparison_matches_the_published_schema() {
    let report = fixture::report();
    let document = comparison(&report, &report, ExportOptions::new());

    Validator::diff().check(&document);
    assert_eq!(document["unchanged"], Value::Bool(true));
    assert_eq!(document["hosts"].as_array().map(Vec::len), Some(0));
}

/// Redaction is an export-time policy here as it is for a report, and a
/// comparison leaks the same fields if it is not applied.
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
        !rendered.contains("2c:cf:67:f2:51:e3"),
        "a hardware address survived redaction into the comparison"
    );
}

/// A phase carried nothing worth masking until it began carrying an
/// attachment, which names a device and its hardware address.
///
/// Neither is less identifying for describing a switch rather than a
/// workstation: a switch name is an internal hostname and a chassis address is a
/// real MAC. Both sit outside the `hosts` array, where every other redaction test
/// looks. The JSON Lines writer is checked alongside because it renders the
/// header through a different type.
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
/// The document tests above exercise whichever changes the fixtures happen to
/// produce, so a token added to `ChangeDto` could ship past all of them while
/// producing documents no consumer's validator accepts.
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
/// [`ChangeDto::set`] names two. Reading the source avoids needing one of every
/// change constructed by hand, which would rot faster than the list it checks.
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
/// produces, so a kind the fixture omits is a kind nothing checks.
/// `finding_appeared` and `finding_resolved` were emitted for a while by code the
/// schema would have rejected while the conformance suite stayed green.
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
/// A `Host` reaches a file twice: as a [`HostRecord`](crate::record::HostRecord)
/// in the journal, and as a `HostDto` in an exported report. They differ in
/// encoding on purpose, since a duration is a `Duration` in one and an integer of
/// microseconds in the other, and the exported document carries derived fields
/// the journal has no reason to store. Where both name the same thing they have
/// to spell it the same way, or a consumer who reads both learns two vocabularies
/// for one domain.
///
/// This compares the field names the two emit. The encoding differences listed
/// below are the only permitted divergence.
#[test]
fn the_journal_and_the_report_spell_a_host_the_same_way() {
    use crate::record::HostRecord;

    /// Fields one side carries and the other has no reason to.
    ///
    /// Each is a decision rather than an oversight, named here so that adding a
    /// field to one side without the other fails this test until somebody says
    /// which it is.
    const RECORD_ONLY: &[&str] = &[
        // The document carries the OS verdict and not the sources behind it.
        "os_evidence",
        // Round-trip samples, which the report renders as statistics instead.
        "rtts",
        "hop_counter",
        // Durations, which the report writes as integers of microseconds.
        "rtt",
        "elapsed",
        "first_reply",
        "last_reply",
        // The interface a link-local range is valid on. See ZA-4-009.
        "zone",
        // The retry policy, flattened here and nested under `retry` there.
        "retry_effort",
        "retry_max_attempts",
        "retry_timeout_scale",
        "retry_dampen_silent_hosts",
        // serde's own encoding of `SystemTime` and `Duration`. The report writes
        // an RFC 3339 string and an integer of microseconds instead, both of
        // which a person can read.
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
