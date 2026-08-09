// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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
use zond_engine::export::{
    CsvExporter, ExportFormat, ExportOptions, Exporter, HtmlExporter, JsonExporter,
    JsonLinesExporter, Redaction,
};

/// The schemas shipped in `assets/`, which are what a consumer validates
/// against.
const SCHEMA: &str = include_str!("../assets/schema/zond-report-v1.schema.json");
const LINES_SCHEMA: &str = include_str!("../assets/schema/zond-lines-v1.schema.json");

/// The identifiers the schemas declare for themselves.
const SCHEMA_URL: &str = "https://zond.rs/schema/zond-report-v1.schema.json";
const LINES_SCHEMA_URL: &str = "https://zond.rs/schema/zond-lines-v1.schema.json";

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
    assert_valid_against(SCHEMA_URL, document);
}

/// Validates one JSON Lines record against the record schema.
fn assert_matches_lines_schema(record: &Value) {
    assert_valid_against(LINES_SCHEMA_URL, record);
}

/// Compiles both published schemas and validates against one of them. The lines
/// schema is written in terms of the report schema's definitions, so neither
/// resolves without the other.
fn assert_valid_against(url: &str, document: &Value) {
    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();

    for (id, text) in [(SCHEMA_URL, SCHEMA), (LINES_SCHEMA_URL, LINES_SCHEMA)] {
        let schema: Value = serde_json::from_str(text).expect("the schema file is valid JSON");
        compiler
            .add_resource(id, schema)
            .expect("the schema file is a usable resource");
    }

    let index = compiler
        .compile(url, &mut schemas)
        .expect("the schema file compiles");

    if let Err(error) = schemas.validate(document, index) {
        panic!("a real scan produced output the schema rejects:\n{error:#}");
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

/// Every format a front end can resolve from `-o report.<ext>` has to be one
/// the engine writes, or the two disagree about what an extension means.
#[test]
fn every_extension_resolves_to_the_format_that_claims_it() {
    use std::path::Path;

    assert_eq!(
        ExportFormat::from_path(Path::new("report.json")),
        Some(ExportFormat::Json)
    );
    assert_eq!(
        ExportFormat::from_path(Path::new("report.jsonl")),
        Some(ExportFormat::JsonLines)
    );
    // The same format under the name half the ecosystem knows it by.
    assert_eq!(
        ExportFormat::from_path(Path::new("report.ndjson")),
        Some(ExportFormat::JsonLines)
    );
    assert_eq!(
        ExportFormat::from_path(Path::new("report.csv")),
        Some(ExportFormat::Csv)
    );
    assert_eq!(
        ExportFormat::from_path(Path::new("report.html")),
        Some(ExportFormat::Html)
    );
    // The same format under the name a system that shortens extensions gives it.
    assert_eq!(
        ExportFormat::from_path(Path::new("report.htm")),
        Some(ExportFormat::Html)
    );

    for format in ExportFormat::all() {
        assert_eq!(
            ExportFormat::from_extension(format.extension()),
            Some(*format)
        );
    }
}

/// Every line of a real scan's JSON Lines export has to validate on its own.
#[tokio::test]
async fn a_real_scan_exports_lines_the_schema_accepts() {
    let server = spawn_banner_server(b"SSH-2.0-OpenSSH_8.9p1\r\n").await;
    let outcome = run_scan(
        target_map(LOOPBACK, &server.port.to_string()),
        &test_config(),
    )
    .await;

    let mut bytes = Vec::new();
    JsonLinesExporter::new(ExportOptions::new())
        .export(&outcome.report, &mut bytes)
        .expect("the export succeeds");

    let text = String::from_utf8(bytes).expect("utf-8");
    let mut hosts = 0;
    for (index, line) in text.lines().enumerate() {
        let record: Value = serde_json::from_str(line).expect("a line parses on its own");
        assert_matches_lines_schema(&record);

        if index == 0 {
            assert_eq!(record["type"], "report");
        } else {
            assert_eq!(record["type"], "host");
            hosts += 1;
        }
    }

    assert_eq!(hosts, outcome.report.host_count());
}

/// The two JSON formats are two renderings of one report and must agree about
/// every host in it.
#[tokio::test]
async fn the_document_and_the_line_stream_describe_the_same_hosts() {
    let server = spawn_banner_server(b"hi\r\n").await;
    let outcome = run_scan(
        target_map(LOOPBACK, &server.port.to_string()),
        &test_config(),
    )
    .await;

    let document = export(&outcome.report, ExportOptions::new());

    let mut bytes = Vec::new();
    JsonLinesExporter::new(ExportOptions::new())
        .export(&outcome.report, &mut bytes)
        .expect("the export succeeds");
    let text = String::from_utf8(bytes).expect("utf-8");

    for (index, line) in text.lines().skip(1).enumerate() {
        let mut record: Value = serde_json::from_str(line).expect("a line parses");
        record
            .as_object_mut()
            .expect("an object")
            .remove("type")
            .expect("a tag");

        assert_eq!(record, document["hosts"][index]);
    }
}

/// Splits a CSV document into rows of fields, honouring quoting.
///
/// Splitting on `,` and `\n` would pass here by luck - loopback has no MAC, so
/// nothing gets quoted - and fail the first time a vendor string like
/// `Arris Group, Inc` appears. A test that only works on the network it was
/// written against is not a test of the writer.
fn csv_rows(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut characters = text.chars().peekable();

    while let Some(character) = characters.next() {
        match character {
            '"' if !quoted && field.is_empty() => quoted = true,
            '"' if quoted => {
                if characters.peek() == Some(&'"') {
                    characters.next();
                    field.push('"');
                } else {
                    quoted = false;
                }
            }
            ',' if !quoted => row.push(std::mem::take(&mut field)),
            '\n' if !quoted => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            other => field.push(other),
        }
    }

    assert!(!quoted, "the document ended inside a quoted field");
    assert!(
        field.is_empty() && row.is_empty(),
        "the document did not end with a line break"
    );
    rows
}

/// A real scan's CSV has to be a rectangle. A row with the wrong column count
/// shifts every value after it, silently, in whatever spreadsheet opens it.
#[tokio::test]
async fn a_real_scan_exports_a_rectangular_table() {
    let server = spawn_banner_server(b"SSH-2.0-OpenSSH_8.9p1\r\n").await;
    let closed = closed_loopback_port().await;
    let ports = format!("{},{}", server.port, closed);

    let outcome = run_scan(target_map(LOOPBACK, &ports), &test_config()).await;

    let mut bytes = Vec::new();
    CsvExporter::new(ExportOptions::new())
        .export(&outcome.report, &mut bytes)
        .expect("the export succeeds");

    let rows = csv_rows(&String::from_utf8(bytes).expect("utf-8"));

    assert_eq!(rows[0][0], "ip");
    assert_eq!(rows[0][1], "hostname");

    let columns = rows[0].len();
    for (number, row) in rows.iter().enumerate().skip(1) {
        assert_eq!(
            row.len(),
            columns,
            "row {number} has the wrong column count: {row:?}"
        );
    }

    // Every host contributes at least one row, and a host with ports
    // contributes one per port.
    let expected: usize = outcome
        .report
        .hosts()
        .map(|host| host.port_count().max(1))
        .sum();
    assert_eq!(rows.len(), 1 + expected);
}

/// A discovery sweep finds hosts and no ports. If port-less hosts had no rows,
/// that entire scan would export as a header and nothing else.
#[tokio::test]
async fn a_discovery_sweep_exports_more_than_a_header() {
    let outcome = run_discover(ip_set(LOOPBACK), &test_config()).await;

    let mut bytes = Vec::new();
    CsvExporter::new(ExportOptions::new())
        .export(&outcome.report, &mut bytes)
        .expect("the export succeeds");

    let rows = csv_rows(&String::from_utf8(bytes).expect("utf-8"));
    assert_eq!(
        rows.len(),
        1 + outcome.report.host_count(),
        "a header and one row per host"
    );
}

/// Walks the page and returns the first structural fault it finds.
///
/// Hand-written rather than delegated to an HTML parser: a parser's job is to
/// recover from broken markup, which is exactly the failure this has to report.
/// Browsers recover too, each in its own way - a table that never closes is a
/// different document in every one of them.
fn unbalanced_tag(page: &str) -> Option<String> {
    // The elements that have no closing tag. The exporter writes these three
    // and no others.
    const VOID: [&str; 3] = ["meta", "input", "br"];

    let mut open: Vec<&str> = Vec::new();
    let mut rest = page;

    while let Some(index) = rest.find('<') {
        rest = &rest[index + 1..];

        // The doctype, which opens nothing.
        if rest.starts_with('!') {
            continue;
        }

        let end = rest.find('>')?;
        let tag = &rest[..end];
        rest = &rest[end..];

        let closing = tag.starts_with('/');
        let name = tag
            .trim_start_matches('/')
            .split([' ', '\n', '\t'])
            .next()
            .unwrap_or_default();

        if VOID.contains(&name) {
            continue;
        }

        if closing {
            match open.pop() {
                Some(expected) if expected == name => {}
                Some(expected) => return Some(format!("</{name}> closes <{expected}>")),
                None => return Some(format!("</{name}> closes nothing")),
            }
        } else {
            open.push(name);
        }
    }

    open.pop().map(|name| format!("<{name}> is never closed"))
}

/// A page a browser has to guess at is a page every browser guesses at
/// differently.
#[tokio::test]
async fn a_real_scan_exports_a_page_that_closes_every_tag() {
    let server = spawn_banner_server(b"SSH-2.0-OpenSSH_8.9p1\r\n").await;
    let closed = closed_loopback_port().await;
    let ports = format!("{},{}", server.port, closed);

    let outcome = run_scan(target_map(LOOPBACK, &ports), &test_config()).await;

    let mut bytes = Vec::new();
    HtmlExporter::new(ExportOptions::new())
        .export(&outcome.report, &mut bytes)
        .expect("the export succeeds");

    let page = String::from_utf8(bytes).expect("utf-8");

    assert_eq!(unbalanced_tag(&page), None);
    assert!(page.starts_with("<!doctype html>"));
    assert!(page.trim_end().ends_with("</html>"));

    // Every host the report holds is on the page. A report that renders a
    // subset of itself is worse than one that fails to render.
    for host in outcome.report.hosts() {
        let ip = host.primary_ip().to_string();
        assert!(page.contains(&ip), "{ip} is missing from the page");
    }
}

/// The page and the document are two renderings of one report, and the page is
/// the one somebody acts on.
#[tokio::test]
async fn the_page_and_the_document_agree_about_the_findings() {
    let server = spawn_banner_server(b"SSH-2.0-OpenSSH_8.9p1\r\n").await;
    let outcome = run_scan(
        target_map(LOOPBACK, &server.port.to_string()),
        &test_config(),
    )
    .await;

    let document = export(&outcome.report, ExportOptions::new());

    let mut bytes = Vec::new();
    HtmlExporter::new(ExportOptions::new())
        .export(&outcome.report, &mut bytes)
        .expect("the export succeeds");
    let page = String::from_utf8(bytes).expect("utf-8");

    let summary = &document["summary"];
    assert!(page.contains(&format!(
        "<div class=\"tile-value\">{}</div><div class=\"tile-label\">hosts</div>",
        summary["hosts_total"]
    )));
    assert!(page.contains(&format!(
        "<div class=\"tile-value\">{}</div><div class=\"tile-label\">open ports</div>",
        summary["ports_open"]
    )));

    for host in document["hosts"].as_array().expect("a host array") {
        for port in host["ports"].as_array().expect("a port array") {
            let number = port["port"].as_u64().expect("a port number");
            let protocol = port["protocol"].as_str().expect("a protocol");
            assert!(
                page.contains(&format!("{number}/{protocol}")),
                "{number}/{protocol} is in the document and not on the page"
            );
        }
    }
}
