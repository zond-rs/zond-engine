// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! This engine's own report format, read back as the findings it records.
//!
//! A document it wrote is still a document somebody can edit, and `diff` takes
//! one from wherever the operator kept it — a shared drive, a ticket, an
//! engagement repository — to compare last quarter against tonight.
//!
//! Both JSON shapes, driven by the reader rather than left to the dispatch, so
//! that a record-per-line file cut off mid-record is reachable as well as a
//! whole document. The dispatch runs too, because choosing between them is its
//! own decision and the one a front end actually makes.
//!
//! ## The oracle
//!
//! Whatever either reader builds has to survive being written out and read back:
//! `read → write → read` describes the same network, or the pair has lost
//! something between them. Asserted through [`ScanDiff`] rather than field by
//! field, for the reason the in-crate round-trip tests give — a field a reader
//! drops shows up there whatever field it was, including one added after this
//! target was written.
//!
//! Each shape round-trips through its own writer. The record-per-line one is
//! why this matters: `export_report` enters through the document reader only, so
//! without this arm the JSON Lines reader has no oracle at all and finds
//! nothing but panics.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use zond_engine::diff::ScanDiff;
use zond_engine::export::{ExportOptions, Exporter, JsonExporter, JsonLinesExporter};
use zond_engine::import::report::json::{JsonLinesReportReader, JsonReportReader};
use zond_engine::import::report::{ReportFormat, ReportOptions, ReportReader};
use zond_engine::report::ScanReport;
use zond_engine_fuzz::report_is_coherent;

fuzz_target!(|data: &[u8]| {
    if let Ok(report) = JsonReportReader::default().read(&mut Cursor::new(data)) {
        report_is_coherent(&report);

        let mut document = Vec::new();
        JsonExporter::new(ExportOptions::new())
            .export(&report, &mut document)
            .expect("a report this crate just built has to be writable");

        let restored = JsonReportReader::default()
            .read(&mut Cursor::new(&document[..]))
            .expect("this crate's own document has to read back");

        unchanged(&report, &restored, "the document");
    }

    if let Ok(report) = JsonLinesReportReader::default().read(&mut Cursor::new(data)) {
        report_is_coherent(&report);

        let mut document = Vec::new();
        JsonLinesExporter::new(ExportOptions::new())
            .export(&report, &mut document)
            .expect("a report this crate just built has to be writable");

        let restored = JsonLinesReportReader::default()
            .read(&mut Cursor::new(&document[..]))
            .expect("this crate's own records have to read back");

        unchanged(&report, &restored, "the record-per-line file");
    }

    // The dispatch a front end calls, which has to reach a reader that can then
    // read the same bytes.
    let mut input = Cursor::new(data);
    if let Ok(format) = ReportFormat::sniff(&mut input) {
        let _ = format.read(&mut input, ReportOptions::new());
    }
});

/// Holds a round trip to describing the same network it started with.
fn unchanged(before: &ScanReport, after: &ScanReport, what: &str) {
    let diff = ScanDiff::between(before, after);
    assert!(
        diff.is_empty(),
        "a round trip through {what} changed the network it describes: {:#?}",
        diff.hosts()
    );
}
