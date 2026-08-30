// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A comparison as one JSON document
//!
//! The canonical form, in the schema [`schema`](super::schema) defines. This is
//! what a pipeline ingests: a nightly comparison posted to a queue, filed as a
//! ticket, or fed to a rule that alerts on a port opening where nobody expected
//! one.

use std::io::Write;

use crate::diff::ScanDiff;
use crate::export::diff::DiffExporter;
use crate::export::diff::schema::DiffDto;
use crate::export::{ExportError, ExportOptions};

/// The format name carried in an [`ExportError::Render`].
const FORMAT: &str = "diff json";

/// Writes a comparison as one JSON document.
///
/// ```no_run
/// use std::fs::File;
/// use zond_engine::diff::ScanDiff;
/// use zond_engine::export::diff::{DiffExporter, JsonDiffExporter};
/// use zond_engine::export::{ExportOptions, Redaction};
///
/// # fn example(diff: &ScanDiff) -> Result<(), Box<dyn std::error::Error>> {
/// let options = ExportOptions::new().with_redaction(Redaction::Standard);
/// let mut file = File::create("changes.json")?;
///
/// JsonDiffExporter::new(options).export(diff, &mut file)?;
/// # Ok(())
/// # }
/// ```
#[must_use]
#[derive(Debug, Clone, Default)]
pub struct JsonDiffExporter {
    options: ExportOptions,
    pretty: bool,
}

impl JsonDiffExporter {
    /// An exporter that writes indented JSON.
    ///
    /// Indented for the same reason the report exporter is: the usual
    /// destination is a file somebody opens, and a document that diffs line by
    /// line is worth more than one that saves bytes.
    pub fn new(options: ExportOptions) -> Self {
        Self {
            options,
            pretty: true,
        }
    }

    /// Switches to single-line output, for a queue or an HTTP body.
    pub fn compact(mut self) -> Self {
        self.pretty = false;
        self
    }

    /// Switches back to indented output.
    pub fn pretty(mut self) -> Self {
        self.pretty = true;
        self
    }

    /// The options in force.
    pub fn options(&self) -> &ExportOptions {
        &self.options
    }
}

impl DiffExporter for JsonDiffExporter {
    fn export(&self, diff: &ScanDiff, out: &mut dyn Write) -> Result<(), ExportError> {
        let document = DiffDto::new(diff, &self.options);

        let result = if self.pretty {
            serde_json::to_writer_pretty(&mut *out, &document)
        } else {
            serde_json::to_writer(&mut *out, &document)
        };

        result.map_err(|error| crate::export::write::render_error(FORMAT, error))?;

        writeln!(out)?;
        Ok(())
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝
#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::export::fixture;

    /// A destination that refuses every write with a nameable reason.
    struct FullDisk;

    impl Write for FullDisk {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::StorageFull))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A write that failed reports *why* it failed, and the report exporter and
    /// the comparison exporter say the same thing about the same disk.
    ///
    /// This exporter carried its own copy of the sorting `write::render_error`
    /// does, and the copy wrapped the error with `io::Error::other` instead of
    /// unwrapping serde_json's own. A full disk during a comparison export came
    /// back as `Other` where the same disk during a report export came back as
    /// `StorageFull`. Found by W23's byte-comparison harness.
    #[test]
    fn a_failed_write_keeps_the_kind_the_destination_reported() {
        let (before, after) = fixture::compared();
        let diff = crate::diff::ScanDiff::between(&before, &after);

        let error = JsonDiffExporter::new(ExportOptions::new())
            .export(&diff, &mut FullDisk)
            .expect_err("a destination that refuses every write");

        match error {
            ExportError::Io(io) => assert_eq!(io.kind(), std::io::ErrorKind::StorageFull),
            other => panic!("expected an I/O failure, got {other:?}"),
        }
    }

    /// The fixture pair, compared and parsed back.
    fn document() -> Value {
        let (before, after) = fixture::compared();
        let diff = ScanDiff::between(&before, &after);

        let mut bytes = Vec::new();
        JsonDiffExporter::new(ExportOptions::new())
            .export(&diff, &mut bytes)
            .expect("the export succeeds");

        serde_json::from_slice(&bytes).expect("the export parses as JSON")
    }

    /// Every change in the document, as `address port kind before after`.
    fn changes(document: &Value) -> Vec<String> {
        let mut found = Vec::new();
        for host in document["hosts"].as_array().expect("hosts") {
            let address = host["address"].as_str().expect("an address");
            for change in host["changes"].as_array().expect("changes") {
                found.push(format!(
                    "{address} - {} {} {}",
                    change["kind"].as_str().expect("a token"),
                    change["before"],
                    change["after"]
                ));
            }
            for port in host["ports"].as_array().expect("ports") {
                for change in port["changes"].as_array().expect("changes") {
                    found.push(format!(
                        "{address} {}/{} {} {} {}",
                        port["port"],
                        port["protocol"].as_str().expect("a transport"),
                        change["kind"].as_str().expect("a token"),
                        change["before"],
                        change["after"]
                    ));
                }
            }
        }
        found
    }

    /// The vocabulary is the contract: a rule somebody writes today keys on
    /// these strings.
    #[test]
    fn each_change_is_named_by_its_documented_token() {
        let found = changes(&document());

        for expected in [
            r#"192.168.0.1 - hostname "router.local" "gateway.local""#,
            r#"192.168.0.1 - os "Linux 5.15.0" "Linux 6.1.0""#,
            r#"192.168.0.1 22/tcp service_version "8.9p1" "9.6p1""#,
            r#"192.168.0.1 80/tcp port_state "open" "closed""#,
        ] {
            assert!(
                found.iter().any(|c| c == expected),
                "missing {expected}\nin {found:#?}"
            );
        }
    }

    /// A certificate is identified by its fingerprint, so that is what a
    /// rotation carries: two certificates are the same one exactly when they are
    /// byte for byte the same.
    #[test]
    fn a_rotation_carries_both_fingerprints() {
        let found = changes(&document());
        let rotation = found
            .iter()
            .find(|change| change.contains("certificate_rotated"))
            .expect("the fixture rotates a certificate");

        assert!(rotation.contains("aaaa"), "{rotation}");
        assert!(rotation.contains("bbbb"), "{rotation}");
    }

    /// The certificate did not move; the clock did. `after` is when it lapses,
    /// absolute, so a consumer computes whatever window it wants.
    #[test]
    fn an_expiry_crossing_carries_when_it_lapses_and_no_before() {
        let document = document();
        let host = document["hosts"]
            .as_array()
            .expect("hosts")
            .iter()
            .find(|host| host["address"] == "192.168.0.4")
            .expect("the host whose certificate is running out");

        let change = &host["ports"][0]["changes"][0];
        assert_eq!(change["kind"], "certificate_expiring");
        assert_eq!(change["before"], Value::Null);
        assert!(
            change["after"]
                .as_str()
                .is_some_and(|end| end.ends_with('Z')),
            "an absolute moment, not a window: {}",
            change["after"]
        );
    }

    /// The field a rule keys on, and the one thing this document must never get
    /// wrong.
    #[test]
    fn confirmed_says_whether_the_other_scan_looked() {
        let document = document();
        let hosts = document["hosts"].as_array().expect("hosts");

        let arrived = hosts
            .iter()
            .find(|host| host["address"] == "192.168.0.7")
            .expect("the host that arrived");
        assert_eq!(arrived["presence"], "added");
        assert_eq!(arrived["coverage"], "covered");
        assert_eq!(
            arrived["confirmed"], true,
            "the earlier scan walked this address and did not find it"
        );

        let gone = hosts
            .iter()
            .find(|host| host["address"] == "192.168.0.9")
            .expect("the host that went");
        assert_eq!(gone["presence"], "removed");
        assert_eq!(gone["confirmed"], true);

        // A port both scans walked, that only one found, is likewise a finding.
        let router = hosts
            .iter()
            .find(|host| host["address"] == "192.168.0.1")
            .expect("the gateway");
        let opened = router["ports"]
            .as_array()
            .expect("ports")
            .iter()
            .find(|port| port["port"] == 8080)
            .expect("the port that opened");
        assert_eq!(opened["presence"], "added");
        assert_eq!(
            opened["confirmed"], true,
            "both scans stated they walked 8080"
        );
        assert_eq!(opened["opened"], true);
    }

    /// A scan that never walked the ground cannot confirm what turned up on it.
    #[test]
    fn a_change_the_other_scan_never_covered_is_not_confirmed() {
        // The gateway alone, compared against a sweep that stated it walked
        // addresses and no ports at all.
        let (_, after) = fixture::compared();
        let sweep = fixture::report();

        let diff = ScanDiff::between(&sweep, &after);
        let mut bytes = Vec::new();
        JsonDiffExporter::new(ExportOptions::new())
            .export(&diff, &mut bytes)
            .expect("the export succeeds");
        let document: Value = serde_json::from_slice(&bytes).expect("JSON");

        let unconfirmed = document["hosts"]
            .as_array()
            .expect("hosts")
            .iter()
            .flat_map(|host| host["ports"].as_array().expect("ports"))
            .filter(|port| port["confirmed"] == false)
            .count();

        assert!(
            unconfirmed > 0,
            "a sweep walked no ports, so nothing found on one is a finding about the network"
        );
    }

    /// Two scans that found the same things still produce a document, because a
    /// consumer polling nightly wants the same shape either way.
    #[test]
    fn an_unchanged_comparison_still_writes_a_document() {
        let (before, _) = fixture::compared();
        let diff = ScanDiff::between(&before, &before);

        let mut bytes = Vec::new();
        JsonDiffExporter::new(ExportOptions::new())
            .export(&diff, &mut bytes)
            .expect("the export succeeds");
        let document: Value = serde_json::from_slice(&bytes).expect("JSON");

        assert_eq!(document["unchanged"], true);
        assert_eq!(document["hosts"].as_array().map(Vec::len), Some(0));
        assert_eq!(document["summary"]["hosts_changed"], 0);
    }

    /// The document ends with a newline, so a file of one is a well-formed text
    /// file and a stream of them concatenates.
    #[test]
    fn the_document_ends_with_a_newline() {
        let (before, after) = fixture::compared();
        let diff = ScanDiff::between(&before, &after);

        let mut bytes = Vec::new();
        JsonDiffExporter::new(ExportOptions::new())
            .compact()
            .export(&diff, &mut bytes)
            .expect("the export succeeds");

        assert_eq!(bytes.last(), Some(&b'\n'));
    }
}
