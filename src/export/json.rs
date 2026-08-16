// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # JSON export
//!
//! Writes a report as a single JSON document in the schema defined by
//! [`schema`](super::schema).
//!
//! This is the canonical format. Everything the engine records is in it,
//! nothing is summarized away, and the other formats are lossy views of the
//! same data. When a question arises about what a report contains, the answer
//! is whatever this writes.

use std::io::Write;

use crate::export::schema::ReportDto;
use crate::export::{ExportError, ExportOptions, Exporter};
use crate::scanner::report::ScanReport;

/// The format name carried in a [`ExportError::Render`].
const FORMAT: &str = "json";

/// Writes a report as one JSON document.
///
/// ```no_run
/// use std::fs::File;
/// use zond_engine::scanner::report::ScanReport;
/// use zond_engine::export::{ExportOptions, Exporter, JsonExporter, Redaction};
///
/// # fn example(report: &ScanReport) -> Result<(), Box<dyn std::error::Error>> {
/// let options = ExportOptions::new().with_redaction(Redaction::Standard);
/// let mut file = File::create("scan.json")?;
///
/// JsonExporter::new(options).export(report, &mut file)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct JsonExporter {
    options: ExportOptions,
    pretty: bool,
}

impl JsonExporter {
    /// An exporter that writes indented JSON.
    ///
    /// Indented is the default because the usual destination is a file somebody
    /// will open, and because a report that diffs line by line is worth more
    /// than one that saves bytes. The engine already sorts hosts, ports and
    /// every set it exports for exactly that reason; emitting them all on one
    /// line would throw the property away at the last step.
    pub fn new(options: ExportOptions) -> Self {
        Self {
            options,
            pretty: true,
        }
    }

    /// Switches to single-line output.
    ///
    /// For a pipe rather than a file: an HTTP body, a message queue, anything
    /// that is going to be parsed and never read.
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

impl Exporter for JsonExporter {
    fn export(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), ExportError> {
        let document = ReportDto::new(report, &self.options);

        // `serde_json` writes straight through to the writer as it serializes,
        // and `ReportDto` yields hosts from an iterator, so the document is
        // never assembled anywhere - not as a string, not as a `Value`.
        let written = if self.pretty {
            serde_json::to_writer_pretty(&mut *out, &document)
        } else {
            serde_json::to_writer(&mut *out, &document)
        };
        written.map_err(render_error)?;

        // A trailing newline, so the file is a well-formed POSIX text file and
        // appending output after it does not produce a broken line.
        out.write_all(b"\n")?;
        Ok(())
    }
}

/// Sorts a serialization failure into the two cases a caller can act on.
///
/// `serde_json` reports a failed write and an unrepresentable value through the
/// same error type, and they call for opposite responses: retrying against a
/// different destination can fix the first and can never fix the second.
fn render_error(error: serde_json::Error) -> ExportError {
    if error.is_io() {
        ExportError::Io(error.into())
    } else {
        ExportError::Render {
            format: FORMAT,
            message: error.to_string(),
        }
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
    use super::*;
    use crate::export::Redaction;
    use crate::export::fixture;
    use serde_json::Value;

    fn export(exporter: &JsonExporter, report: &ScanReport) -> Value {
        let mut bytes = Vec::new();
        exporter
            .export(report, &mut bytes)
            .expect("export succeeds");

        assert_eq!(
            bytes.last(),
            Some(&b'\n'),
            "a written report must end in a newline"
        );
        serde_json::from_slice(&bytes).expect("the output parses as JSON")
    }

    fn exported(report: &ScanReport) -> Value {
        export(&JsonExporter::new(ExportOptions::new()), report)
    }

    /// The header is the part a consumer reads before it decides whether it can
    /// read the rest, so every field in it has to be there.
    #[test]
    fn the_document_identifies_itself() {
        let document = exported(&fixture::report());

        assert_eq!(document["schema_version"], 1);
        assert_eq!(document["engine"]["name"], "zond-engine");
        assert_eq!(
            document["engine"]["version"],
            crate::scanner::report::ENGINE_VERSION
        );
        assert!(
            document["generated_at"]
                .as_str()
                .expect("a generation timestamp")
                .ends_with('Z')
        );
        assert_eq!(document["partial"], true);
    }

    /// Counts in the summary are derived from the hosts, so the two views of the
    /// same scan cannot be allowed to disagree.
    #[test]
    fn the_summary_agrees_with_the_hosts_it_summarizes() {
        let document = exported(&fixture::report());

        let hosts = document["hosts"].as_array().expect("a host array");
        let open_ports = hosts
            .iter()
            .flat_map(|host| host["ports"].as_array().expect("a port array"))
            .filter(|port| port["state"] == "open")
            .count();

        assert_eq!(document["summary"]["hosts_total"], hosts.len());
        assert_eq!(document["summary"]["ports_open"], open_ports);
        assert_eq!(document["summary"]["hosts_alive"], 2);
        assert_eq!(document["summary"]["services_identified"], 1);
    }

    /// Hosts sort by address and ports by number, so two scans of the same
    /// network produce documents that diff cleanly.
    #[test]
    fn output_is_ordered_for_diffing() {
        let document = exported(&fixture::report());
        let hosts = document["hosts"].as_array().expect("a host array");

        let addresses: Vec<&str> = hosts
            .iter()
            .map(|host| host["primary_ip"].as_str().expect("an address"))
            .collect();
        assert_eq!(addresses, vec!["192.168.0.1", "192.168.0.2", "192.168.0.9"]);

        let ports: Vec<u64> = hosts[0]["ports"]
            .as_array()
            .expect("a port array")
            .iter()
            .map(|port| port["port"].as_u64().expect("a port number"))
            .collect();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    /// Two exports of one report must be byte-identical apart from the stamp
    /// that says when they were written. Anything else moving means an
    /// unordered collection reached the output.
    #[test]
    fn two_exports_of_one_report_differ_only_in_their_timestamp() {
        let report = fixture::report();
        let exporter = JsonExporter::new(ExportOptions::new());

        let mut first = Vec::new();
        let mut second = Vec::new();
        exporter.export(&report, &mut first).expect("first export");
        exporter
            .export(&report, &mut second)
            .expect("second export");

        let strip = |bytes: &[u8]| {
            String::from_utf8(bytes.to_vec())
                .expect("utf-8")
                .lines()
                .filter(|line| !line.contains("\"generated_at\""))
                .collect::<Vec<_>>()
                .join("\n")
        };

        assert_eq!(strip(&first), strip(&second));
    }

    /// The whole point of the redaction policy: what leaves the process is
    /// masked, and what stays behind is not touched.
    #[test]
    fn redaction_masks_names_and_hardware_without_losing_the_hosts() {
        let report = fixture::report();

        let plain = exported(&report);
        let masked = export(
            &JsonExporter::new(ExportOptions::new().with_redaction(Redaction::Standard)),
            &report,
        );

        assert_eq!(plain["hosts"][0]["hostname"], "router.local");
        assert_eq!(masked["hosts"][0]["hostname"], "roXXXXXal");

        assert_eq!(plain["hosts"][0]["hardware"]["mac"], "2c:cf:67:f2:51:e3");
        assert_eq!(masked["hosts"][0]["hardware"]["mac"], "2c:cf:67:XX:XX:XX");

        // The vendor comes from the OUI, which masking preserves, so hiding it
        // would cost information without buying privacy.
        assert_eq!(
            plain["hosts"][0]["hardware"]["vendor"],
            masked["hosts"][0]["hardware"]["vendor"]
        );

        // Addresses are untouched: a report whose hosts all mask to the same
        // string is not a report.
        assert_eq!(
            plain["hosts"][0]["primary_ip"],
            masked["hosts"][0]["primary_ip"]
        );
        assert_ne!(
            masked["hosts"][0]["primary_ip"],
            masked["hosts"][1]["primary_ip"]
        );

        // A certificate names machines and people too.
        assert_eq!(
            masked["hosts"][0]["ports"][2]["security"]["certificate"]["common_name"],
            "roXXXXXal"
        );

        // The scan's own redaction setting is a record of how the scan ran, not
        // of how it was exported, and must not move when the export policy does.
        assert_eq!(
            plain["phases"][0]["settings"]["redact"],
            masked["phases"][0]["settings"]["redact"]
        );
    }

    /// A field that has no value is present and null; a list with nothing in it
    /// is present and empty. A consumer never has to tell absent from empty.
    #[test]
    fn absent_values_are_present_and_null() {
        let document = exported(&fixture::report());
        let bare = &document["hosts"][2];

        assert!(bare["hostname"].is_null());
        assert!(bare["os"].is_null());
        assert!(bare["hardware"].is_null());
        assert!(bare["telemetry"]["rtt_median_us"].is_null());
        assert!(bare["ports"].as_array().expect("a port array").is_empty());
        assert!(
            bare["reasons"]
                .as_array()
                .expect("a reason array")
                .is_empty()
        );
    }

    /// Instrumentation is what bounds how far a host list can be trusted, so it
    /// has to arrive self-describing: a histogram whose bucket bounds live only
    /// in this crate's source is not a document anyone else can read.
    #[test]
    fn probe_instrumentation_carries_its_own_units() {
        let document = exported(&fixture::report());
        let stats = &document["phases"][0]["probe_stats"][0];

        assert_eq!(stats["scanner"], "routed");
        assert_eq!(stats["stop_reason"], "deadline_expired");
        assert_eq!(stats["complete"], false);
        assert_eq!(stats["targets"], "256");

        let attempts = stats["answered_on"].as_array().expect("an attempt array");
        assert_eq!(attempts[0]["attempt"], 1);
        assert_eq!(attempts[0]["count"], 7);
        assert_eq!(attempts[0]["or_later"], false);
        assert_eq!(
            attempts.last().expect("a final attempt bucket")["or_later"],
            true
        );

        let buckets = stats["found_at"].as_array().expect("a bucket array");
        assert_eq!(buckets[0]["le_ms"], 1);
        assert_eq!(
            buckets.last().expect("a final bucket")["le_ms"],
            Value::Null,
            "the open-ended bucket must say so rather than name a bound"
        );

        assert_eq!(stats["capture"]["dropped"], 0);
    }

    /// A failed strategy is the difference between an empty network and a scan
    /// that never ran, and it is the one thing a consumer must not miss.
    #[test]
    fn a_failed_strategy_reaches_the_document() {
        let document = exported(&fixture::report());
        let failures = document["phases"][0]["failures"]
            .as_array()
            .expect("a failure array");

        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0]["scanner"], "local");
        assert_eq!(failures[0]["reason"], "raw socket unavailable");
        assert!(
            failures[0]["at"]
                .as_str()
                .expect("a timestamp")
                .ends_with('Z')
        );
    }

    /// Compact output is the same document, not a smaller one.
    #[test]
    fn compact_output_carries_the_same_document() {
        let report = fixture::report();

        let indented = exported(&report);
        let compact = export(&JsonExporter::new(ExportOptions::new()).compact(), &report);

        let mut indented = indented;
        let mut compact = compact;
        indented["generated_at"] = Value::Null;
        compact["generated_at"] = Value::Null;

        assert_eq!(indented, compact);
    }

    /// The engine writes into whatever it is handed, and a destination that
    /// fails part way through has to surface as a failed export rather than a
    /// truncated file reported as a success.
    #[test]
    fn a_failing_destination_surfaces_as_an_error() {
        struct Full;

        impl Write for Full {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::StorageFull,
                    "no space left on device",
                ))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let error = JsonExporter::new(ExportOptions::new())
            .export(&fixture::report(), &mut Full)
            .expect_err("a full disk fails the export");

        assert!(matches!(error, ExportError::Io(_)), "got {error:?}");
    }
}
