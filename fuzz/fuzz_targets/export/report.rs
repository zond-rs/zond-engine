// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Every writer, over a report nobody wrote by hand.
//!
//! A writer takes a `ScanReport` rather than bytes, so there is no direct way to
//! point a fuzzer at one. The report is built by reading a document instead:
//! most inputs stop at that line, and `seeds/export_report` is what gets past
//! it. What it buys is a report whose hostnames, banners, certificate subjects
//! and script output are whatever the fuzzer chose — which is the position a
//! scanned network is in, since a device names itself.
//!
//! ## What is asserted
//!
//! One property per format, each the thing that format's own documentation says
//! it will never do:
//!
//! - **JSON and JSON Lines** emit JSON, and every line of the second stands
//!   alone. A document that only parses when it is whole is the failure the
//!   record-per-line format exists to avoid.
//! - **CSV** never opens a field with a character a spreadsheet evaluates. This
//!   is a security control, not a formatting choice: a device named
//!   `=cmd|'/c calc'!A1` is a working attack on whoever opens the report.
//! - **HTML** never emits a script tag or a direction override. The first
//!   executes on the reader; the second reorders the page around it without
//!   being visible, so a report can be made to display one address and carry
//!   another.
//! - **Nmap XML** never emits a character XML 1.0 cannot carry. There is no
//!   escape for those, so one in a banner is a file no consumer can open.
//!
//! And the round trip: what the canonical writer emits reads back as the same
//! network. Asserted through [`ScanDiff`] rather than field by field, for the
//! reason the in-crate round-trip tests give — a field the reader drops shows up
//! there whatever field it was.
//!
//! Both redaction policies, because masking rewrites exactly the
//! attacker-controlled strings these properties are about, and a mask that
//! reintroduced a `<` would be a control that opened the hole it closes.
//!
//! ## What is not asserted
//!
//! That a redacted document contains no unmasked hostname. The obvious spelling
//! is a substring search, and it is wrong here: the policy masks names, hardware
//! addresses and certificate subjects, and deliberately not a service banner —
//! so a fuzzer that puts a hostname in a `product` field would report a leak
//! that policy never promised to stop. The in-crate conformance tests make that
//! check against a fixture, where what is in each field is known.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use zond_engine::diff::ScanDiff;
use zond_engine::export::{ExportFormat, ExportOptions, Redaction};
use zond_engine::format::csv::FORMULA_LEADERS;
use zond_engine::import::report::nmap::NmapXmlReportReader;
use zond_engine::import::report::{ReportFormat, ReportOptions, ReportReader};

fuzz_target!(|data: &[u8]| {
    let Ok(report) = ReportFormat::Json.read(&mut Cursor::new(data), ReportOptions::new()) else {
        return;
    };

    for redaction in [Redaction::None, Redaction::Standard] {
        let options = ExportOptions::new().with_redaction(redaction);

        for format in ExportFormat::all() {
            let mut document = Vec::new();
            format
                .exporter(options.clone())
                .export(&report, &mut document)
                .unwrap_or_else(|error| {
                    panic!("{format} could not write a report this crate just built: {error}")
                });

            check(*format, &document);
        }
    }

    let mut document = Vec::new();
    ExportFormat::Json
        .exporter(ExportOptions::new())
        .export(&report, &mut document)
        .expect("the canonical writer");

    let restored = ReportFormat::Json
        .read(&mut Cursor::new(&document[..]), ReportOptions::new())
        .expect("this crate's own document has to read back");

    assert!(
        ScanDiff::between(&report, &restored).is_empty(),
        "a round trip through the canonical format changed the network it describes"
    );
});

/// Holds one document to what its format promises never to emit.
fn check(format: ExportFormat, document: &[u8]) {
    let text = std::str::from_utf8(document)
        .unwrap_or_else(|error| panic!("{format} wrote something that is not UTF-8: {error}"));

    match format {
        ExportFormat::Json => {
            serde_json::from_str::<serde_json::Value>(text)
                .unwrap_or_else(|error| panic!("the JSON writer did not emit JSON: {error}"));
        }
        ExportFormat::JsonLines => {
            for (index, line) in text.lines().enumerate() {
                serde_json::from_str::<serde_json::Value>(line).unwrap_or_else(|error| {
                    panic!("record {index} does not parse on its own: {error}")
                });
            }
        }
        ExportFormat::Csv => {
            for field in csv_fields(text) {
                assert!(
                    !field.starts_with(FORMULA_LEADERS),
                    "a cell a spreadsheet would evaluate reached the table: {field:?}"
                );
            }
        }
        ExportFormat::Html => {
            assert!(
                !text.to_ascii_lowercase().contains("<script"),
                "a scanned host's own text opened a script tag in the report"
            );
            if let Some(character) = text.chars().find(|character| is_neutralized(*character)) {
                panic!(
                    "U+{:04X} reached the page and reorders it",
                    u32::from(character)
                );
            }
        }
        ExportFormat::NmapXml => {
            if let Some(character) = text.chars().find(|character| is_forbidden(*character)) {
                panic!(
                    "U+{:04X} cannot appear in an XML document and has no escape",
                    u32::from(character)
                );
            }

            // Read back for the panics, not for the verdict. Whether this crate
            // can always re-read its own nmap XML is a real question and a
            // separate one: nmap's vocabulary is narrower than this engine's,
            // and the reader bounds an attribute value that the writer does not.
            // Asserting it here would report that design as a crash.
            let _ = NmapXmlReportReader::default().read(&mut Cursor::new(document));
        }
        // `ExportFormat` is non-exhaustive, and a format added without a
        // property here is a format this target only checks is UTF-8.
        _ => {}
    }
}

/// Every field of a table, quoting undone, without regard for where the rows
/// end.
///
/// Written out rather than split on commas, because a quoted cell may hold a
/// comma, a quote or a line break, and a naive split would report the half of
/// one after a `,=` as a field that opens with a formula character. To a fuzzer
/// that is a crash, and it would be this harness's crash rather than the
/// writer's.
fn csv_fields(document: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut characters = document.chars().peekable();

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
            ',' | '\n' if !quoted => fields.push(std::mem::take(&mut field)),
            other => field.push(other),
        }
    }

    fields.push(field);
    fields
}

/// The characters the HTML writer renders as their code point rather than
/// emitting, mirroring `export::write::is_neutralized`.
///
/// Tab, newline and carriage return are ordinary whitespace and are not here.
fn is_neutralized(character: char) -> bool {
    matches!(character,
        '\u{0}'..='\u{8}'
        | '\u{b}' | '\u{c}'
        | '\u{e}'..='\u{1f}'
        | '\u{7f}'..='\u{9f}'
        | '\u{61c}'
        | '\u{200e}' | '\u{200f}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2066}'..='\u{2069}')
}

/// The characters XML 1.0 cannot carry at all, mirroring
/// `export::nmap::is_forbidden`.
///
/// The bidirectional set the writer also drops is not here: those are legal XML
/// and dropping them is a judgement rather than a rule, so a document keeping
/// one would be a change of mind and not a file nobody can open.
fn is_forbidden(character: char) -> bool {
    matches!(u32::from(character), 0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F | 0xFFFE | 0xFFFF)
}
