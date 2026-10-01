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
//! This is the canonical format: everything the engine records is in it, and
//! the other formats are lossy views of the same data.

use std::io::Write;

use crate::export::schema::ReportDto;
use crate::export::{ExportError, ExportOptions, Exporter, write};
use crate::report::ScanReport;

/// The format name carried in a [`ExportError::Render`].
const FORMAT: &str = "json";

/// Writes a report as one JSON document.
///
/// ```no_run
/// use std::fs::File;
/// use zond_engine::report::ScanReport;
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
#[must_use]
#[derive(Debug, Clone)]
pub struct JsonExporter {
    options: ExportOptions,
    pretty: bool,
}

/// Written by hand because a derived one would set `pretty` to `false`, unlike
/// [`JsonExporter::new`].
impl Default for JsonExporter {
    fn default() -> Self {
        Self::new(ExportOptions::default())
    }
}

impl JsonExporter {
    /// An exporter that writes indented JSON.
    ///
    /// Indented by default so the output is readable and diffs line by line,
    /// which is also why hosts, ports and every exported set are sorted.
    pub fn new(options: ExportOptions) -> Self {
        Self {
            options,
            pretty: true,
        }
    }

    /// Switches to single-line output.
    ///
    /// For output that is parsed and never read: an HTTP body, a message queue.
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

        let written = if self.pretty {
            serde_json::to_writer_pretty(&mut *out, &document)
        } else {
            serde_json::to_writer(&mut *out, &document)
        };
        written.map_err(|error| write::render_error(FORMAT, error))?;

        // A POSIX text file ends in a newline; without one, appending would
        // join two documents on a line.
        out.write_all(b"\n")?;
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

    /// The two halves of `engine` name the same build, whoever produced the
    /// findings.
    ///
    /// A report read from nmap's XML must not write `zond-engine` paired with
    /// `nmap 7.94`. What produced the findings is `produced_by`.
    #[test]
    fn the_engine_object_names_the_build_that_wrote_the_document() {
        let foreign =
            ScanReport::recorded("nmap 7.94", fixture::report().phases().to_vec(), Vec::new());
        let document = exported(&foreign);

        assert_eq!(document["engine"]["name"], "zond-engine");
        assert_eq!(
            document["engine"]["version"],
            crate::report::ENGINE_VERSION,
            "the version beside a fixed name has to be that name's"
        );
        assert_eq!(document["produced_by"], "nmap 7.94");
    }

    /// The document states what the report as a whole left open, consistent
    /// with `partial`. A resumed job carries the stopped sitting's phase, whose
    /// lists still name what it left open, beside the sitting that finished
    /// both. The top-level fields give the report's own reading so a consumer
    /// need not reconcile the phases.
    #[test]
    fn the_document_names_what_the_report_left_open_across_its_sittings() {
        use crate::report::{PhaseParts, ScanPhase};

        let stopped = fixture::report();
        let document = exported(&stopped);
        assert_eq!(document["timed_out"], serde_json::json!(["203.0.113.9"]));
        assert_eq!(document["unreached"], "1024");

        let first = &stopped.phases()[0];
        let finished = ScanPhase::from_parts(PhaseParts {
            open: false,
            attachments: Vec::new(),
            kind: first.kind(),
            started_at: first.started_at(),
            elapsed: first.elapsed(),
            privilege: first.privilege(),
            targets: first.targets().clone(),
            settings: first.settings().clone(),
            failures: Vec::new(),
            refusals: Vec::new(),
            unroutable: first.unroutable().to_vec(),
            refused_by_route: first.refused_by_route().to_vec(),
            timed_out: Vec::new(),
            icmp_rate_limited: Vec::new(),
            reached_by_connect: Vec::new(),
            undecided: Vec::new(),
            liveness_skipped: first.liveness_skipped(),
            silent: Vec::new(),
            stopped: None,
            passes_cut: Vec::new(),
            unreached: 0,
            unheard_probes: 0,
            probes: Vec::new(),
            origin: None,
        });
        let mut resumed = stopped.clone();
        resumed.merge(ScanReport::new(finished, []));
        let document = exported(&resumed);

        assert_eq!(
            document["phases"][0]["timed_out"],
            serde_json::json!(["203.0.113.9"]),
            "the stopped sitting's record stands"
        );
        assert!(
            document.get("timed_out").is_none(),
            "{}",
            document["timed_out"]
        );
        assert!(
            document.get("unreached").is_none(),
            "{}",
            document["unreached"]
        );
        assert!(
            document.get("undecided").is_none(),
            "{}",
            document["undecided"]
        );
        assert_eq!(document["partial"], resumed.is_partial());
    }

    /// A consumer reads the header to decide whether it can read the rest.
    #[test]
    fn the_document_identifies_itself() {
        let document = exported(&fixture::report());

        assert_eq!(document["schema_version"], 1);
        assert_eq!(document["engine"]["name"], "zond-engine");
        assert_eq!(document["engine"]["version"], crate::report::ENGINE_VERSION);
        assert_eq!(
            document["produced_by"],
            crate::export::fixture::report().engine_version()
        );
        assert!(
            document["generated_at"]
                .as_str()
                .expect("a generation timestamp")
                .ends_with('Z')
        );
        assert_eq!(document["partial"], true);
    }

    /// The summary's counts agree with the hosts.
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
        assert_eq!(addresses, vec!["203.0.113.1", "203.0.113.2", "203.0.113.9"]);

        let ports: Vec<u64> = hosts[0]["ports"]
            .as_array()
            .expect("a port array")
            .iter()
            .map(|port| port["port"].as_u64().expect("a port number"))
            .collect();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    /// Two exports of one report are byte-identical apart from the timestamp.
    /// Anything else moving means an unordered collection reached the output.
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

    /// Names and hardware addresses are masked; the hosts stay distinct.
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

        // A name the host gave for itself is masked like its hostname, domain
        // included; its kind and protocol are kept.
        assert_eq!(plain["hosts"][0]["names"][0]["name"], "gw01.corp.example");
        assert_eq!(masked["hosts"][0]["names"][0]["name"], "gwXXXXXle");
        assert_eq!(masked["hosts"][0]["names"][0]["kind"], "host");
        assert_eq!(masked["hosts"][0]["names"][0]["source"], "ldap");
        let domains = masked["hosts"][0]["names"].to_string();
        assert!(!domains.contains("corp"), "a domain survived: {domains}");

        assert_eq!(plain["hosts"][0]["hardware"]["mac"], "2c:cf:67:00:00:01");
        assert_eq!(masked["hosts"][0]["hardware"]["mac"], "2c:cf:67:XX:XX:XX");

        // The vendor comes from the OUI, which masking keeps.
        assert_eq!(
            plain["hosts"][0]["hardware"]["vendor"],
            masked["hosts"][0]["hardware"]["vendor"]
        );

        // Addresses are untouched.
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

        // The scan's own redaction setting records how the scan ran and does
        // not follow the export policy.
        assert_eq!(
            plain["phases"][0]["settings"]["redact"],
            masked["phases"][0]["settings"]["redact"]
        );
    }

    /// A field with no value is present and null; an empty list is present and
    /// empty.
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

    /// Probe statistics carry their own units and bucket bounds.
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

    /// A failed strategy, which tells an empty network from a scan that never
    /// ran, reaches the document.
    #[test]
    fn a_failed_strategy_reaches_the_document() {
        let document = exported(&fixture::report());
        let failures = document["phases"][0]["failures"]
            .as_array()
            .expect("a failure array");

        assert_eq!(failures.len(), 2);
        assert_eq!(failures[0]["scanner"], "local");
        assert_eq!(failures[0]["reason"], "raw socket unavailable");
        assert!(
            failures[0]["at"]
                .as_str()
                .expect("a timestamp")
                .ends_with('Z')
        );
    }

    /// Work a limit cut short is marked `cut_short`, so a consumer can tell a
    /// fault from a limit to raise. The field is omitted where false.
    #[test]
    fn work_a_limit_cut_short_is_marked_apart_from_a_failure() {
        let document = exported(&fixture::report());
        let failures = document["phases"][0]["failures"]
            .as_array()
            .expect("a failure array");

        assert_eq!(failures[0]["scanner"], "local");
        assert!(failures[0].get("cut_short").is_none(), "{}", failures[0]);
        assert_eq!(failures[1]["scanner"], "connect");
        assert_eq!(failures[1]["cut_short"], true);
    }

    /// `JsonExporter::default()` and `JsonExporter::new(ExportOptions::default())`
    /// produce the same exporter. Compared as bytes, since the difference a
    /// derived `Default` would make is only whitespace.
    #[test]
    fn the_default_exporter_is_the_one_new_builds() {
        let report = fixture::report();

        // Without the timestamp, the one field that moves between exports.
        let render = |exporter: &JsonExporter| {
            let mut bytes = Vec::new();
            exporter.export(&report, &mut bytes).expect("exports");
            String::from_utf8(bytes)
                .expect("utf-8")
                .lines()
                .filter(|line| !line.contains("\"generated_at\""))
                .collect::<Vec<_>>()
                .join("\n")
        };

        let built = render(&JsonExporter::new(ExportOptions::new()));
        assert_eq!(render(&JsonExporter::default()), built);
        assert!(
            built.contains("\n  "),
            "the documented default is indented output"
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

    /// A destination that fails part way through surfaces as a failed export.
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
