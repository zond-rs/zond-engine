// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Export tests against reports the engine actually produced.
//!
//! The unit tests in `export` drive a hand-built report, which is the only way
//! to reach every corner of the schema at once. Their weakness is that the
//! fixture is written by the same hand as the DTO: a field the scanners never
//! populate the way the fixture does would look correct in both.
//!
//! These run real scans through the public API and export what comes back. What
//! they can assert is narrower - loopback answers only open or closed, and how
//! much it answers depends on privilege - so they assert the properties that
//! must hold for *any* report: it validates against the published schema, it
//! survives a round trip through a file, and the numbers in it agree with the
//! report it was made from.

mod common;

use std::io::Write;

use boon::{Compiler, Schemas};
use common::*;
use serde_json::Value;
use zond_engine::core::report::ScanReport;
use zond_engine::export::{ExportFormat, ExportOptions, Exporter, JsonExporter, Redaction};

/// The schema shipped in `assets/`, which is what a consumer validates against.
const SCHEMA: &str = include_str!("../assets/schema/zond-report-v1.schema.json");

/// The identifier the schema declares for itself.
const SCHEMA_URL: &str = "https://zond.rs/schema/zond-report-v1.schema.json";

/// Exports a report as JSON and parses it back.
fn export(report: &ScanReport, options: ExportOptions) -> Value {
    let mut bytes = Vec::new();
    JsonExporter::new(options)
        .export(report, &mut bytes)
        .expect("the export succeeds");

    serde_json::from_slice(&bytes).expect("the export parses as JSON")
}

/// Validates a document against the published schema, failing with the path of
/// whatever did not match.
fn assert_matches_schema(document: &Value) {
    let schema: Value = serde_json::from_str(SCHEMA).expect("the schema file is valid JSON");

    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();
    compiler
        .add_resource(SCHEMA_URL, schema)
        .expect("the schema file is a usable resource");
    let index = compiler
        .compile(SCHEMA_URL, &mut schemas)
        .expect("the schema file compiles");

    if let Err(error) = schemas.validate(document, index) {
        panic!("a real scan produced a document the schema rejects:\n{error:#}");
    }
}

/// The report from a real port scan has to validate. If it does not, the schema
/// describes the fixture rather than the engine.
#[tokio::test]
async fn a_real_port_scan_exports_a_document_the_schema_accepts() {
    let server = spawn_banner_server(b"SSH-2.0-OpenSSH_8.9p1\r\n").await;
    let closed = closed_loopback_port().await;
    let ports = format!("{},{}", server.port, closed);

    let outcome = run_scan(target_map(LOOPBACK, &ports), &test_config()).await;
    let document = export(&outcome.report, ExportOptions::new());

    assert_matches_schema(&document);
    assert_eq!(document["phases"][0]["kind"], "port_scan");
    assert_eq!(document["phases"][0]["targets"]["addresses"], "1");
    assert_eq!(document["phases"][0]["targets"]["probes"], "2");
}

/// Discovery reports take a different shape - no port dimension, a different
/// set of strategies - so they are validated separately rather than assumed to
/// follow.
#[tokio::test]
async fn a_real_discovery_sweep_exports_a_document_the_schema_accepts() {
    let mut targets = zond_engine::core::models::ip::set::IpSet::new();
    targets.insert_range("127.0.0.0/29".parse().expect("a valid range"));

    let outcome = run_discover(targets, &test_config()).await;
    let document = export(&outcome.report, ExportOptions::new());

    assert_matches_schema(&document);
    assert_eq!(document["phases"][0]["kind"], "discovery");
    assert_eq!(document["phases"][0]["targets"]["addresses"], "8");
    assert_eq!(
        document["phases"][0]["targets"]["probes"],
        Value::Null,
        "a discovery sweep has no port dimension to count"
    );
}

/// A merged report is what the CLI exports when a user asks for discovery and a
/// port scan in one command, and its two phases must both survive.
#[tokio::test]
async fn a_merged_two_phase_report_exports_both_phases() {
    let cfg = test_config();
    let server = spawn_banner_server(b"hi\r\n").await;

    let mut report = run_discover(ip_set(LOOPBACK), &cfg).await.report;
    report.merge(
        run_scan(target_map(LOOPBACK, &server.port.to_string()), &cfg)
            .await
            .report,
    );

    let document = export(&report, ExportOptions::new());
    assert_matches_schema(&document);

    let phases = document["phases"].as_array().expect("a phase array");
    assert_eq!(phases.len(), 2);
    assert_eq!(phases[0]["kind"], "discovery");
    assert_eq!(phases[1]["kind"], "port_scan");

    // The document's total is the engine's working time, which is both phases -
    // not the wall clock between them, which includes whatever the caller did.
    let total = document["elapsed_us"].as_u64().expect("a total duration");
    let summed: u64 = phases
        .iter()
        .map(|phase| phase["elapsed_us"].as_u64().expect("a phase duration"))
        .sum();
    assert_eq!(total, summed);
}

/// Whatever the scan found, the summary in the document has to agree with the
/// hosts in the same document. These are two renderings of one truth and a
/// consumer will believe whichever it reads first.
#[tokio::test]
async fn the_exported_summary_agrees_with_the_exported_hosts() {
    let server = spawn_banner_server(b"hi\r\n").await;
    let outcome = run_scan(
        target_map(LOOPBACK, &server.port.to_string()),
        &test_config(),
    )
    .await;

    let document = export(&outcome.report, ExportOptions::new());
    let hosts = document["hosts"].as_array().expect("a host array");

    assert_eq!(document["summary"]["hosts_total"], hosts.len());
    assert_eq!(
        document["summary"]["hosts_total"],
        outcome.report.host_count()
    );

    let alive = hosts
        .iter()
        .filter(|host| host["alive"].as_bool().expect("an alive flag"))
        .count();
    assert_eq!(document["summary"]["hosts_alive"], alive);

    let open = hosts
        .iter()
        .flat_map(|host| host["ports"].as_array().expect("a port array"))
        .filter(|port| port["state"] == "open")
        .count();
    assert_eq!(document["summary"]["ports_open"], open);
}

/// The destination the CLI writes to is a file, and a file that parses only
/// while it is still in memory is not an export.
#[tokio::test]
async fn a_report_written_to_a_file_reads_back_as_the_same_document() {
    let outcome = run_scan(target_map(LOOPBACK, "80"), &test_config()).await;

    let path = std::env::temp_dir().join(format!(
        "zond-export-{}-{}.json",
        std::process::id(),
        line!()
    ));
    let mut file = std::fs::File::create(&path).expect("create the destination");

    let written =
        zond_engine::export::export_to(&path, &outcome.report, &mut file, ExportOptions::new())
            .expect("the .json extension names a format");
    written.expect("the export succeeds");
    file.flush().expect("flush the destination");
    drop(file);

    let from_disk: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read the destination back"))
            .expect("the file parses as JSON");
    std::fs::remove_file(&path).expect("clean up");

    assert_matches_schema(&from_disk);
    assert_eq!(from_disk["schema_version"], 1);
    assert_eq!(
        from_disk["hosts"].as_array().expect("a host array").len(),
        outcome.report.host_count()
    );
}

/// Redaction is applied at the point the data leaves the process, so it has to
/// hold on a report the engine produced rather than only on one built to be
/// redacted.
#[tokio::test]
async fn redacting_a_real_report_changes_nothing_but_the_masked_fields() {
    let outcome = run_scan(target_map(LOOPBACK, "80"), &test_config()).await;

    let plain = export(&outcome.report, ExportOptions::new());
    let masked = export(
        &outcome.report,
        ExportOptions::new().with_redaction(Redaction::Standard),
    );

    assert_matches_schema(&masked);

    let addresses = |document: &Value| -> Vec<String> {
        document["hosts"]
            .as_array()
            .expect("a host array")
            .iter()
            .map(|host| host["primary_ip"].to_string())
            .collect()
    };
    assert_eq!(
        addresses(&plain),
        addresses(&masked),
        "masking must not cost the report its hosts"
    );

    for host in masked["hosts"].as_array().expect("a host array") {
        if let Some(name) = host["hostname"].as_str() {
            assert!(
                name.contains("XXXXX"),
                "an exported hostname escaped redaction: {name}"
            );
        }
    }
}

/// The format a front end resolves from `-o report.json` has to be the one the
/// engine writes, or the two disagree about what a file extension means.
#[test]
fn the_json_format_is_advertised_and_resolvable() {
    assert_eq!(
        ExportFormat::from_path(std::path::Path::new("report.json")),
        Some(ExportFormat::Json)
    );
    assert!(ExportFormat::all().contains(&ExportFormat::Json));
    assert_eq!(ExportFormat::Json.extension(), "json");
}
