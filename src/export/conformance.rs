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
//! a consumer validates against. A schema nobody checks is documentation, and
//! documentation drifts: a field added to a DTO, a `null` that becomes a
//! string, an enum that gains a variant, and the file on disk quietly stops
//! describing the thing it claims to.
//!
//! So the schema is strict - every object closed, every field required - and
//! these tests run the real exporter against it. Adding a field to the DTO
//! without describing it here fails the build, which is the only arrangement
//! under which the schema stays true.

use boon::{Compiler, Schemas};
use serde_json::Value;

use crate::config::{OsDetection, ServiceDetection};
use crate::export::schema::SCHEMA_VERSION;
use crate::export::{ExportOptions, Exporter, JsonExporter, Redaction, fixture};
use crate::model::finding::DetectionClass;
use crate::model::technique::TcpScanTechnique;
use crate::record::wire::detection_class_name;

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
    /// All three are registered whichever is being compiled, because the lines
    /// and comparison schemas are written in terms of the report schema's
    /// definitions - which is what stops them drifting apart - and cannot
    /// resolve without it.
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
    /// path - the useful half of a schema failure.
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

/// Every scan technique the engine can run is a value the published schema
/// accepts.
///
/// The document tests below only ever exercise whichever technique the fixture
/// happens to use, so a seventh technique could be added, exported, and pass
/// every one of them while producing documents no consumer's validator accepts.
/// This is the check that fails instead - and it fails at the point the variant
/// is added, which is where the schema is easiest to update.
#[test]
fn every_technique_the_engine_runs_is_a_value_the_schema_accepts() {
    let schema: Value = serde_json::from_str(SCHEMA).expect("valid JSON");
    let accepted = schema["$defs"]["settings"]["properties"]["tcp_technique"]["enum"]
        .as_array()
        .expect("the schema names the techniques it accepts");

    for technique in TcpScanTechnique::ALL {
        assert!(
            accepted.contains(&Value::from(technique.name())),
            "the schema does not accept `{technique}`, which a scan can be asked for"
        );
    }
}

/// Every OS detection level the engine can be asked for is a value the published
/// schema accepts.
///
/// Same reasoning as the techniques above, and the same blind spot without it:
/// the document tests exercise whichever level the fixture happens to carry, so
/// a fifth level could be added, exported, and pass every one of them while
/// producing documents no consumer's validator accepts. This fails at the point
/// the variant is added instead.
#[test]
fn every_os_detection_level_the_engine_runs_is_a_value_the_schema_accepts() {
    let schema: Value = serde_json::from_str(SCHEMA).expect("valid JSON");
    let accepted = schema["$defs"]["settings"]["properties"]["os_detection"]["enum"]
        .as_array()
        .expect("the schema names the levels it accepts");

    for detection in OsDetection::ALL {
        assert!(
            accepted.contains(&Value::from(detection.name())),
            "the schema does not accept `{detection}`, which a scan can be asked for"
        );
    }
}

/// Every service-detection level, on the same reasoning as the levels above.
#[test]
fn every_service_detection_level_the_engine_runs_is_a_value_the_schema_accepts() {
    let schema: Value = serde_json::from_str(SCHEMA).expect("valid JSON");
    let accepted = schema["$defs"]["settings"]["properties"]["service_detection"]["enum"]
        .as_array()
        .expect("the schema names the levels it accepts");

    for detection in ServiceDetection::ALL {
        assert!(
            accepted.contains(&Value::from(detection.name())),
            "the schema does not accept `{detection}`, which a scan can be asked for"
        );
    }
}

/// Every detection intrusiveness class the envelope can permit, on the same
/// reasoning as the levels above: a class the report can name is a class the
/// schema must list.
#[test]
fn every_detection_class_the_engine_can_run_is_a_value_the_schema_accepts() {
    let schema: Value = serde_json::from_str(SCHEMA).expect("valid JSON");
    let accepted = schema["$defs"]["settings"]["properties"]["detection"]["enum"]
        .as_array()
        .expect("the schema names the classes it accepts");

    for class in DetectionClass::ALL {
        let name = detection_class_name(class);
        assert!(
            accepted.contains(&Value::from(name)),
            "the schema does not accept `{name}`, a class a scan can be permitted"
        );
    }
}

/// A fully populated report - every optional block present, a failed strategy,
/// an instrumented scanner, a certificate, nested script output.
#[test]
fn a_full_report_matches_the_schema() {
    Validator::new().check(&document(ExportOptions::new()));
}

/// Redaction rewrites hostnames and hardware addresses. It must not rewrite
/// them into something the schema no longer accepts.
#[test]
fn a_redacted_report_matches_the_schema() {
    Validator::new().check(&document(
        ExportOptions::new().with_redaction(Redaction::Standard),
    ));
}

/// The strictness is the point: if the schema accepted anything, passing it
/// would prove nothing. This checks it actually rejects.
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

/// The lines schema is written in terms of the report schema, so it must reject
/// on the same grounds - and reject a record that names no type at all.
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
/// workstation — a switch name is an internal hostname and a chassis address is
/// a real MAC — and both sit outside the `hosts` array, where every existing
/// redaction test was looking. The JSON Lines writer is checked alongside
/// because it renders the header through a different type, and a policy applied
/// to one document and not the other is the shape this failure takes.
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
/// The document tests above only exercise whichever changes the fixtures happen
/// to produce, so a token added to `ChangeDto` could ship and pass all of them
/// while producing documents no consumer's validator accepts. This is the check
/// that fails instead.
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
