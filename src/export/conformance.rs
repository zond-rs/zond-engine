// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

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

use crate::export::schema::SCHEMA_VERSION;
use crate::export::{ExportOptions, Exporter, JsonExporter, Redaction, fixture};

/// The published schemas, compiled into the test binary so a test cannot pass
/// against a file that was not shipped.
const SCHEMA: &str = include_str!("../../assets/schema/zond-report-v1.schema.json");
const LINES_SCHEMA: &str = include_str!("../../assets/schema/zond-lines-v1.schema.json");

/// The identifiers the schemas declare for themselves.
const SCHEMA_URL: &str = "https://zond.rs/schema/zond-report-v1.schema.json";
const LINES_SCHEMA_URL: &str = "https://zond.rs/schema/zond-lines-v1.schema.json";

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

    /// Compiles both schemas and points a validator at one of them.
    ///
    /// Both are registered whichever is being compiled, because the lines
    /// schema is written entirely in terms of the report schema's definitions -
    /// which is what stops the two drifting apart - and cannot resolve without
    /// it.
    fn over(url: &str) -> Self {
        let mut schemas = Schemas::new();
        let mut compiler = Compiler::new();

        for (id, text) in [(SCHEMA_URL, SCHEMA), (LINES_SCHEMA_URL, LINES_SCHEMA)] {
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
