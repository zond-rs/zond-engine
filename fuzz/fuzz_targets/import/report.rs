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
//! whole document. The dispatch runs too, because choosing between the two is
//! its own decision and the one a front end actually makes.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use zond_engine::import::report::json::{JsonLinesReportReader, JsonReportReader};
use zond_engine::import::report::{ReportFormat, ReportOptions, ReportReader};

fuzz_target!(|data: &[u8]| {
    let _ = JsonReportReader::default().read(&mut Cursor::new(data));
    let _ = JsonLinesReportReader::default().read(&mut Cursor::new(data));

    let mut input = Cursor::new(data);
    if let Ok(format) = ReportFormat::sniff(&mut input) {
        let _ = format.read(&mut input, ReportOptions::new());
    }
});
