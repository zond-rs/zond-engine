// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # JSON Lines export
//!
//! The same data as [`json`](super::json), one record per line.
//!
//! ## What this buys over a JSON document
//!
//! A JSON document is only valid when it is complete. Kill the process, fill the
//! disk, or lose the pipe half way through writing a /16 and what is on disk is
//! not a shorter report - it is not JSON at all, and every host already written
//! is unreadable. That is the wrong failure mode for the output of a scan that
//! may have taken an hour.
//!
//! Here every line stands alone. A truncated file is a complete file with fewer
//! hosts in it, a consumer can process the first host before the last is
//! written, and `grep`, `split`, `head` and `wc -l` all work on it. Two files
//! concatenate without a parser, because no record's meaning depends on where it
//! sits.
//!
//! ## The records
//!
//! Every line is a JSON object with a `type` field naming what it is, and the
//! rest of its fields are exactly what the same thing has in the JSON document:
//!
//! ```text
//! {"type":"report","schema_version":1,"engine":{…},"summary":{…},"phases":[…]}
//! {"type":"host","primary_ip":"192.168.0.1",…}
//! {"type":"host","primary_ip":"192.168.0.2",…}
//! ```
//!
//! Strip `type` from a `host` line and it is byte-identical to an element of the
//! document's `hosts` array, so one parser reads both formats. The tag is a
//! field rather than a position because a line that has to be the first line to
//! mean anything is a line that cannot be `grep`ed out, concatenated, or
//! reordered - which is most of the reason to choose this format.
//!
//! The `report` record carries everything the document has except the hosts. It
//! is written first because that is the only order in which a consumer reading
//! progressively learns what it is reading before it reads it.

use std::io::Write;

use serde::Serialize;

use crate::core::report::ScanReport;
use crate::export::schema::{HostDto, ReportHeaderDto};
use crate::export::{ExportError, ExportOptions, Exporter};

/// The format name carried in an [`ExportError::Render`].
const FORMAT: &str = "jsonl";

/// The `type` of the record describing the scan.
pub const REPORT_RECORD: &str = "report";

/// The `type` of a record describing one host.
pub const HOST_RECORD: &str = "host";

/// Writes a report as one JSON object per line.
///
/// ```no_run
/// use std::fs::File;
/// use zond_engine::core::report::ScanReport;
/// use zond_engine::export::{ExportOptions, Exporter, JsonLinesExporter};
///
/// # fn example(report: &ScanReport) -> Result<(), Box<dyn std::error::Error>> {
/// let mut file = File::create("scan.jsonl")?;
/// JsonLinesExporter::new(ExportOptions::new()).export(report, &mut file)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct JsonLinesExporter {
    options: ExportOptions,
}

impl JsonLinesExporter {
    /// An exporter under the given options.
    pub fn new(options: ExportOptions) -> Self {
        Self { options }
    }

    /// The options in force.
    pub fn options(&self) -> &ExportOptions {
        &self.options
    }
}

impl Exporter for JsonLinesExporter {
    fn export(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), ExportError> {
        let header = ReportHeaderDto::new(report);
        write_line(out, &tagged(REPORT_RECORD, &header))?;

        // One host is rendered, written and dropped before the next is built,
        // which is what keeps a scan of any size costing a host's worth of
        // memory to export.
        for host in report.hosts() {
            let host = HostDto::new(host, &self.options);
            write_line(out, &tagged(HOST_RECORD, &host))?;
        }

        Ok(())
    }
}

/// Serializes one record and terminates the line.
///
/// The newline is written separately rather than being part of the record so
/// that a serialization failure cannot leave a half-written object followed by
/// a line break, which a consumer would read as a complete but malformed
/// record.
fn write_line<T: Serialize>(out: &mut dyn Write, record: &T) -> Result<(), ExportError> {
    serde_json::to_writer(&mut *out, record).map_err(render_error)?;
    out.write_all(b"\n")?;
    Ok(())
}

/// Labels a record with the kind of thing it describes.
fn tagged<'a, T: Serialize>(tag: &'static str, body: &'a T) -> Tagged<'a, T> {
    Tagged { tag, body }
}

/// A record's tag followed by the record's own fields, flattened into one
/// object.
///
/// The tag is emitted first so a consumer can dispatch on it without buffering
/// the rest of the line. Flattening rather than nesting is what makes a `host`
/// line the document's host object with one field added, instead of a different
/// shape that happens to contain it.
#[derive(Serialize)]
struct Tagged<'a, T: Serialize> {
    #[serde(rename = "type")]
    tag: &'static str,
    #[serde(flatten)]
    body: &'a T,
}

/// Sorts a serialization failure into the two cases a caller can act on: a
/// failed write may succeed against another destination, an unrepresentable
/// value will not.
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
    use crate::export::fixture;
    use serde_json::Value;

    fn lines(report: &ScanReport, options: ExportOptions) -> Vec<Value> {
        let mut bytes = Vec::new();
        JsonLinesExporter::new(options)
            .export(report, &mut bytes)
            .expect("the export succeeds");

        let text = String::from_utf8(bytes).expect("utf-8");
        assert!(text.ends_with('\n'), "every record must terminate its line");

        text.lines()
            .map(|line| {
                assert!(
                    !line.is_empty(),
                    "a blank line is not a record and must not be written"
                );
                serde_json::from_str(line).expect("each line parses on its own")
            })
            .collect()
    }

    /// The shape of the stream: one report record, then one record per host.
    #[test]
    fn the_stream_leads_with_the_report_then_names_every_host() {
        let records = lines(&fixture::report(), ExportOptions::new());

        assert_eq!(records.len(), 4, "a report record and three hosts");
        assert_eq!(records[0]["type"], "report");
        assert_eq!(records[0]["schema_version"], 1);
        assert_eq!(records[0]["summary"]["hosts_total"], 3);
        assert!(
            records[0]["hosts"].is_null(),
            "the report record must not carry the hosts as well"
        );

        for record in &records[1..] {
            assert_eq!(record["type"], "host");
        }
        assert_eq!(records[1]["primary_ip"], "192.168.0.1");
        assert_eq!(records[3]["primary_ip"], "192.168.0.9");
    }

    /// Strip the tag from a host line and it must be exactly what the JSON
    /// document holds, or the two formats need two parsers.
    #[cfg(feature = "export-json")]
    #[test]
    fn a_host_line_is_the_documents_host_object_plus_a_tag() {
        let report = fixture::report();

        let mut document = Vec::new();
        crate::export::JsonExporter::new(ExportOptions::new())
            .export(&report, &mut document)
            .expect("the document export succeeds");
        let document: Value = serde_json::from_slice(&document).expect("valid JSON");

        for (index, mut line) in lines(&report, ExportOptions::new())
            .into_iter()
            .skip(1)
            .enumerate()
        {
            let tag = line
                .as_object_mut()
                .expect("an object")
                .remove("type")
                .expect("a tag");

            assert_eq!(tag, "host");
            assert_eq!(line, document["hosts"][index]);
        }
    }

    /// The report record must say the same things the document's header says.
    /// Two renderings of one scan that disagree are worse than one rendering.
    #[cfg(feature = "export-json")]
    #[test]
    fn the_report_record_matches_the_documents_header() {
        let report = fixture::report();

        let mut document = Vec::new();
        crate::export::JsonExporter::new(ExportOptions::new())
            .export(&report, &mut document)
            .expect("the document export succeeds");
        let document: Value = serde_json::from_slice(&document).expect("valid JSON");

        let record = lines(&report, ExportOptions::new()).swap_remove(0);

        for field in [
            "schema_version",
            "engine",
            "started_at",
            "elapsed_us",
            "partial",
            "summary",
            "phases",
        ] {
            assert_eq!(record[field], document[field], "`{field}` disagrees");
        }
    }

    /// The point of the format: a file cut off part way through is still a
    /// readable file with fewer hosts in it.
    #[test]
    fn a_truncated_stream_still_parses_up_to_the_last_whole_line() {
        let mut bytes = Vec::new();
        JsonLinesExporter::new(ExportOptions::new())
            .export(&fixture::report(), &mut bytes)
            .expect("the export succeeds");

        // Cut somewhere inside the last record.
        let text = String::from_utf8(bytes).expect("utf-8");
        let cut = text.rfind('\n').expect("a line break");
        let truncated = &text[..cut - 5];

        let whole: Vec<&str> = truncated
            .split_inclusive('\n')
            .filter(|line| line.ends_with('\n'))
            .collect();

        assert_eq!(whole.len(), 3, "three records survived the cut");
        for line in whole {
            serde_json::from_str::<Value>(line).expect("a surviving line still parses");
        }
    }

    /// Redaction is a property of the export, not of the format.
    #[test]
    fn redaction_applies_to_the_stream() {
        let records = lines(
            &fixture::report(),
            ExportOptions::new().with_redaction(crate::export::Redaction::Standard),
        );

        assert_eq!(records[1]["hostname"], "roXXXXXal");
        assert_eq!(records[1]["hardware"]["mac"], "2c:cf:67:XX:XX:XX");
    }

    /// A destination that fails part way must surface as a failed export rather
    /// than a short file reported as a success.
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

        let error = JsonLinesExporter::new(ExportOptions::new())
            .export(&fixture::report(), &mut Full)
            .expect_err("a full disk fails the export");

        assert!(matches!(error, ExportError::Io(_)), "got {error:?}");
    }
}
