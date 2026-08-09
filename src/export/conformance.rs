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

/// The published schema, compiled into the test binary so the test cannot pass
/// against a file that was not shipped.
const SCHEMA: &str = include_str!("../../assets/schema/zond-report-v1.schema.json");

/// The identifier the schema declares for itself.
const SCHEMA_URL: &str = "https://zond.rs/schema/zond-report-v1.schema.json";

/// A compiled validator over the published schema.
struct Validator {
    schemas: Schemas,
    index: boon::SchemaIndex,
}

impl Validator {
    fn new() -> Self {
        let document: Value = serde_json::from_str(SCHEMA).expect("the schema file is valid JSON");

        let mut schemas = Schemas::new();
        let mut compiler = Compiler::new();
        compiler
            .add_resource(SCHEMA_URL, document)
            .expect("the schema file is a usable resource");
        let index = compiler
            .compile(SCHEMA_URL, &mut schemas)
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
        validator
            .schemas
            .validate(&missing_field, validator.index)
            .is_err(),
        "a report with no summary must not validate"
    );

    let mut unknown_field = document(ExportOptions::new());
    unknown_field["hosts"][0]["surprise"] = Value::from("undocumented");
    assert!(
        validator
            .schemas
            .validate(&unknown_field, validator.index)
            .is_err(),
        "a field the schema does not describe must not validate - that failure \
         is what stops the schema drifting away from the DTO"
    );

    let mut float_timestamp = document(ExportOptions::new());
    float_timestamp["generated_at"] = Value::from(1_770_000_000.5);
    assert!(
        validator
            .schemas
            .validate(&float_timestamp, validator.index)
            .is_err(),
        "an epoch float must not pass where an RFC 3339 string is promised"
    );

    let mut rounded_count = document(ExportOptions::new());
    rounded_count["phases"][0]["targets"]["addresses"] = Value::from(256);
    assert!(
        validator
            .schemas
            .validate(&rounded_count, validator.index)
            .is_err(),
        "a count that can exceed 2^53 must be a string, not a number"
    );
}
