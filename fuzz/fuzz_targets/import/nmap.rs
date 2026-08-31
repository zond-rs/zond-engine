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
//!
//! ## The oracle
//!
//! What the reader builds has to be a coherent report — see
//! [`report_is_coherent`]. There is deliberately no round trip here, and the
//! reason is worth writing down rather than rediscovering: nmap's vocabulary is
//! narrower than this engine's, so a report read out of nmap's XML and written
//! back to it loses what the format has no place for. `read → write → read`
//! settles at a fixed point only from the second pass on, and asserting the
//! first would report that design as a defect every time the fuzzer found a
//! field nmap cannot carry.
//!
//! What it *can* assert is that the reader never invents a host: the second
//! reading names no address the first did not.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use zond_engine::export::{ExportOptions, Exporter, NmapXmlExporter};
use zond_engine::import::report::ReportReader;
use zond_engine::import::report::nmap::NmapXmlReportReader;
use zond_engine_fuzz::report_is_coherent;

fuzz_target!(|data: &[u8]| {
    let Ok(report) = NmapXmlReportReader::default().read(&mut Cursor::new(data)) else {
        return;
    };
    report_is_coherent(&report);

    let mut document = Vec::new();
    NmapXmlExporter::new(ExportOptions::new())
        .export(&report, &mut document)
        .expect("a report this crate just built has to be writable");

    let Ok(restored) = NmapXmlReportReader::default().read(&mut Cursor::new(&document[..])) else {
        return;
    };
    report_is_coherent(&restored);

    for host in restored.hosts() {
        assert!(
            report.host(&host.primary_ip()).is_some(),
            "{} is in the document this crate wrote and was not in the one it read",
            host.primary_ip()
        );
    }
});
