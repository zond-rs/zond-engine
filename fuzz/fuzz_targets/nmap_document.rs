// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Nmap's XML, which this crate parses with a hand-rolled subset reader.
//!
//! `Cargo.toml` calls that reader "defensible only because it refuses far more
//! than it accepts", and this is the check on the claim. The refusals are the
//! interesting part: `<!ENTITY` anywhere, a `DOCTYPE` carrying an internal
//! subset, an entity reference that is not one of the five, and the depth,
//! element, name, value and text bounds.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use zond_engine::import::report::nmap::NmapXmlReportReader;
use zond_engine::import::report::ReportReader;

fuzz_target!(|data: &[u8]| {
    let _ = NmapXmlReportReader::default().read(&mut Cursor::new(data));
});
