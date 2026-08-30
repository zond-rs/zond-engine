// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! This engine's own report format, read back.
//!
//! A document it wrote is still a document somebody can edit, and `--resume`
//! and `diff` both take one from wherever the operator kept it.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use zond_engine::import::report::json::JsonReportReader;
use zond_engine::import::report::ReportReader;

fuzz_target!(|data: &[u8]| {
    let _ = JsonReportReader::default().read(&mut Cursor::new(data));
});
