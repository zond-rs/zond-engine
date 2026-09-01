// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Getting results out of the engine
//!
//! Everything the `export` module can write, in the order it is likely to be
//! needed. Runs anywhere, needs no privileges and touches no network: the report
//! is built through the public API and every document is written into a
//! `Vec<u8>`, through the same code path a file would take.
//!
//! ```text
//! cargo run --example export                        # JSON, the default
//! cargo run --example export --features export-all  # every format
//! ```
//!
//! ## The one thing to understand first
//!
//! An exporter writes into a `dyn Write`. Nothing in the module returns a
//! `String`, and nothing in it opens a file, creates a directory or decides
//! where a report lands. The caller supplies the destination:
//!
//! ```no_run
//! # use std::fs::File;
//! # use std::io::BufWriter;
//! # fn main() -> std::io::Result<()> {
//! let mut file = BufWriter::new(File::create("scan.json")?); // a file
//! let mut piped = std::io::stdout().lock();                  // a pipe
//! let mut body: Vec<u8> = Vec::new();                        // an HTTP body
//! # Ok(())
//! # }
//! ```
//!
//! All three receive the same bytes, because there is one implementation and it
//! cannot tell them apart. A /16 with a host on every address is a document
//! larger than anything worth holding in memory, and writing as the report is
//! walked means whatever sits on the other end of a pipe sees the first host
//! long before the last one is rendered.
//!
//! Buffer the destination. An exporter issues many small writes, and an
//! unbuffered `File` turns each of them into a syscall.

use std::io::{self, Write};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use zond_engine::config::ZondConfig;
use zond_engine::export::{ExportError, ExportFormat, ExportOptions, Exporter, Redaction};
use zond_engine::model::host::{Host, HostStatus, OsFingerprint, StatusProtocol, StatusReason};
use zond_engine::model::mac::MacAddr;
use zond_engine::model::port::{
    CertificateInfo, Discovery, Port, PortSet, PortState, Protocol, ScanResponse, Security, Service,
};
use zond_engine::report::{
    PhaseParts, PortScope, ScanKind, ScanPhase, ScanReport, ScanSettings, ScopeParts, TargetScope,
};
use zond_engine::system::privilege::Privilege;

fn main() {
    let report = report();

    heading("1. The canonical document");
    the_canonical_document(&report);

    heading("2. What every document promises");
    what_the_document_promises(&report);

    heading("3. Choosing a format from the destination");
    choosing_a_format(&report);

    heading("4. Masking what identifies a person");
    masking_identifiers(&report);

    heading("5. One record per line");
    one_record_per_line(&report);

    heading("6. A table, for the spreadsheet");
    a_table_for_the_spreadsheet(&report);

    heading("7. Text the scanned network chose");
    text_the_network_chose();

    heading("8. A page, for a person");
    a_page_for_a_person(&report);

    heading("9. Somebody else's pipeline");
    somebody_elses_pipeline(&report);

    heading("10. Writing a new exporter");
    writing_an_exporter(&report);

    heading("11. When the destination gives out");
    when_the_destination_gives_out(&report);

    heading("12. Exporting what changed since last time");
    what_changed(&report);
}

/// The whole report, as one JSON document.
///
/// This is the format everything else is measured against. Every field the
/// engine records is in it, nothing is summarized away, and the other four are
/// narrower views of the same data. When a question comes up about what a
/// report contains, this is where the answer is.
///
/// Indented by default, since the usual destination is a file somebody opens and
/// a report that diffs line by line is worth more than one that saves bytes.
/// [`compact`](zond_engine::export::json::JsonExporter::compact) is for a
/// destination that is going to be parsed and never read.
#[cfg(feature = "export-json")]
fn the_canonical_document(report: &ScanReport) {
    use zond_engine::export::JsonExporter;

    const SHOWN: usize = 14;

    let pretty = render(&JsonExporter::new(ExportOptions::new()), report);
    let compact = render(&JsonExporter::new(ExportOptions::new()).compact(), report);

    for line in pretty.lines().take(SHOWN) {
        println!("{line}");
    }
    println!(
        "  ... {} more lines",
        pretty.lines().count().saturating_sub(SHOWN)
    );

    println!();
    println!("indented: {:>7} bytes", pretty.len());
    println!("compact:  {:>7} bytes", compact.len());
}

#[cfg(not(feature = "export-json"))]
fn the_canonical_document(_report: &ScanReport) {
    skipped("export-json");
}

/// The conventions a consumer learns once and can then rely on everywhere.
///
/// [`schema`](zond_engine::export::schema) states them in full. This is the same
/// list held against real output.
///
/// - Timestamps are RFC 3339 in UTC, to microsecond precision. Never epoch
///   floats.
/// - Durations are integers of microseconds, in a field whose name ends `_us`.
///   The unit is in the name because a bare `timeout` field is a support ticket
///   waiting to happen.
/// - A count that can exceed 2^53 is a decimal string. An IPv6 sweep's address
///   count does not survive being a JSON number in a browser, and a count that
///   rounds silently is worse than one that needs parsing.
/// - Objects have a fixed shape. A field with no value is present and `null`, a
///   list with nothing in it is present and empty, and absence means only that
///   the scan did not do the thing at all.
/// - Order is deterministic. Hosts sort by address, ports by number. Two scans
///   that found the same things produce documents that diff cleanly.
/// - Unknown fields may appear. Adding one does not bump `schema_version`, so a
///   consumer has to ignore what it does not recognise.
#[cfg(feature = "export-json")]
fn what_the_document_promises(report: &ScanReport) {
    use zond_engine::export::JsonExporter;
    use zond_engine::export::schema::{ENGINE_NAME, ENGINE_VERSION, SCHEMA_VERSION};

    let document = render(&JsonExporter::new(ExportOptions::new()), report);

    println!("written by {ENGINE_NAME} {ENGINE_VERSION}, schema version {SCHEMA_VERSION}");
    println!();

    for field in [
        "\"started_at\"",
        "\"elapsed_us\"",
        "\"addresses\"",
        "\"probes\"",
        "\"rtt_median_us\"",
        "\"hostname\"",
        "\"cpes\"",
    ] {
        match first_line_containing(&document, field) {
            Some(line) => println!("  {line}"),
            None => println!("  {field}: not in this report"),
        }
    }

    println!();
    println!("`addresses` and `probes` are quoted because a sweep of IPv6 has to");
    println!("fit in them. `hostname` on a host with none is null rather than");
    println!("absent, so a parser never has to tell absent from empty from");
    println!("unknown.");
}

#[cfg(not(feature = "export-json"))]
fn what_the_document_promises(_report: &ScanReport) {
    skipped("export-json");
}

/// A front end resolves a destination to a format rather than asking twice.
///
/// `-o report.json` has already said what the user wants, so
/// [`ExportFormat::from_path`] reads it off the extension, and
/// [`ExportFormat::all`] names the formats this build can write, which is what a
/// help text should list. A binary compiled without `export-html` that offers
/// HTML is worse than one that never mentions it.
///
/// An extension no compiled-in format claims resolves to `None`, never to a
/// quiet fallback to JSON in a file named something else.
fn choosing_a_format(report: &ScanReport) {
    println!("this build can write:");
    for format in ExportFormat::all() {
        let document = render(format.exporter(ExportOptions::new()).as_ref(), report);
        println!("  .{:<6} {:>8} bytes", format.extension(), document.len());
    }

    println!();
    for name in [
        "scan.json",
        "scan.JSONL",
        "scan.htm",
        "report.pdf",
        "report",
    ] {
        match ExportFormat::from_path(std::path::Path::new(name)) {
            Some(format) => println!("  {name:>12} -> {format}"),
            None => println!("  {name:>12} -> no format this build writes"),
        }
    }

    // The same resolution in one call, for a front end that has a path and a
    // writer and nothing to decide. The report goes to `out` and never to
    // `path`: opening the destination, and judging whether overwriting it is
    // acceptable, stays with the caller.
    let mut out = Vec::new();
    let written = zond_engine::export::export_to(
        std::path::Path::new("scan.json"),
        report,
        &mut out,
        ExportOptions::new(),
    );

    println!();
    match written {
        Some(Ok(())) => println!("export_to wrote {} bytes", out.len()),
        Some(Err(error)) => println!("export_to failed: {error}"),
        None => println!("export_to: the extension named no format"),
    }
}

/// Redaction happens on the way out, at the one point where data leaves the
/// process.
///
/// A report going to a client, an auditor or a bug tracker is masked here rather
/// than by the caller afterwards, because afterwards is where it gets forgotten.
///
/// [`Redaction::Standard`] masks the two things that name a person or a device.
/// A hostname keeps its first and last two characters, so two devices stay
/// distinguishable without either being readable; a hardware address keeps its
/// OUI, so the vendor survives and the individual NIC does not.
///
/// Addresses are left alone. A report is a list of hosts, and a scheme that
/// hides which host is which turns ten records on a /24 into ten copies of the
/// same string. One residual leak is worth knowing about: an IPv6 address formed
/// the old EUI-64 way embeds the hardware address that is masked elsewhere, so a
/// report from such a network carries hardware identifiers however this is set.
fn masking_identifiers(report: &ScanReport) {
    let mac = MacAddr::new(0x2c, 0xcf, 0x67, 0xf2, 0x51, 0xe3);

    for policy in [Redaction::None, Redaction::Standard] {
        println!("{policy:?} (masks anything: {}):", policy.is_active());
        println!("  workstation  -> {}", policy.hostname("workstation"));
        println!("  wifi-printer -> {}", policy.hostname("wifi-printer"));
        println!("  the address  -> {}", policy.mac(&mac));
    }

    // The policy travels in the options, so it reaches every format rather than
    // the one a front end remembered to mask.
    let masked = ExportOptions::new().with_redaction(Redaction::Standard);

    println!();
    println!("under Standard, in each format:");
    for format in ExportFormat::all() {
        let document = render(format.exporter(masked.clone()).as_ref(), report);
        println!(
            "  .{:<6} hostname {}, vendor {}, address {}",
            format.extension(),
            survives(&document, "router.local"),
            survives(&document, "Raspberry Pi"),
            survives(&document, "192.168.0.1"),
        );
    }
}

/// The same data as the JSON document, one record per line.
///
/// A JSON document is only valid when it is complete. Lose the pipe half way
/// through writing a /16 and what is on disk is not a shorter report but a file
/// that is not JSON, with every host already written unreadable. Here a
/// truncated file is a complete file with fewer hosts in it, and `grep`, `head`,
/// `split` and `wc -l` all work on it.
///
/// Every line is an object with a `type` field saying what it is, and its other
/// fields are the ones the same thing carries in the document. Strip `type` from
/// a `host` line and it is byte-identical to an element of the document's
/// `hosts` array, so one parser reads both formats.
///
/// The `report` record carries everything the document has except the hosts, and
/// comes first, so a consumer reading progressively knows what it is reading
/// before it reads it. The tag is a field rather than a position, since a line
/// that has to come first to mean anything cannot be grepped out or
/// concatenated.
#[cfg(feature = "export-jsonl")]
fn one_record_per_line(report: &ScanReport) {
    use zond_engine::export::JsonLinesExporter;
    use zond_engine::export::jsonl::{HOST_RECORD, REPORT_RECORD};

    let stream = render(&JsonLinesExporter::new(ExportOptions::new()), report);

    println!("one {REPORT_RECORD:?} record, then one {HOST_RECORD:?} per host:");
    println!();
    for line in stream.lines() {
        println!("  {}", ellipsis(line, 92));
    }

    // Cut the stream mid-line, the way a killed process or a full disk would,
    // and read back what survived.
    let kept = stream.len().saturating_sub(220);
    let truncated = String::from_utf8_lossy(&stream.as_bytes()[..kept]);
    let whole = truncated
        .lines()
        .filter(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
        .count();

    println!();
    println!(
        "cut off at {kept} of {} bytes: {whole} of {} record(s) still parse",
        stream.len(),
        stream.lines().count()
    );
}

#[cfg(not(feature = "export-jsonl"))]
fn one_record_per_line(_report: &ScanReport) {
    skipped("export-jsonl");
}

/// One row per host and port, for the people who are going to open this in a
/// spreadsheet.
///
/// A report is a tree and a table is not, so this throws things away: the
/// phases, the settings, the probe instrumentation, the full address list of a
/// multi-homed host. Adding columns until the file is unreadable would cost the
/// format the thing that makes it worth having, and
/// [`json`](zond_engine::export::json) is where the whole record lives.
///
/// A host with no ports still gets a row with the port columns empty, or a
/// discovery sweep would export an empty file. The column list is
/// [`format::csv::COLUMNS`](zond_engine::format::csv::COLUMNS), shared with the
/// reader behind `import-csv` so the two cannot drift.
///
/// The dialect is RFC 4180 quoting with LF line endings, since every spreadsheet
/// accepts LF and CRLF leaves a stray carriage return for the Unix tools that
/// are the other half of this format's audience.
#[cfg(feature = "export-csv")]
fn a_table_for_the_spreadsheet(report: &ScanReport) {
    use zond_engine::export::CsvExporter;
    use zond_engine::format::csv::{COLUMNS, PORT_COLUMNS};

    let boundary = COLUMNS.len() - PORT_COLUMNS;
    println!("host columns: {}", COLUMNS[..boundary].join(" "));
    println!("port columns: {}", COLUMNS[boundary..].join(" "));

    let table = render(&CsvExporter::new(ExportOptions::new()), report);
    println!();
    for line in table.lines() {
        println!("  {}", ellipsis(line, 92));
    }
    println!();
    println!("the swept host has no ports, so its last {PORT_COLUMNS} cells are empty.");

    // Excel on Windows reads unmarked UTF-8 as the system code page and mangles
    // every non-ASCII vendor name. The mark is opt-in because it makes the first
    // column header unrecognisable to a parser that does not expect it.
    let marked = render(
        &CsvExporter::new(ExportOptions::new()).with_excel_bom(),
        report,
    );
    let prefix = marked.len() - table.len();
    println!(
        "with_excel_bom prefixes {prefix} byte(s): {:02x?}",
        &marked.as_bytes()[..prefix]
    );
}

#[cfg(not(feature = "export-csv"))]
fn a_table_for_the_spreadsheet(_report: &ScanReport) {
    skipped("export-csv");
}

/// A scan report is full of text the scanned network chose, and each format has
/// to survive it.
///
/// Hostnames, service banners and certificate subjects are written by whoever
/// runs the device. A device named `=cmd|'/c calc'!A1` is a working attack on
/// whoever opens the CSV, and one named `<script>` is a working attack on
/// whoever opens the page. None of these guards can be turned off, and none of
/// them is the caller's to remember.
///
/// - CSV prefixes a cell starting with a formula character with an apostrophe,
///   the escape spreadsheets themselves use for text, and the reader behind
///   `import-csv` takes exactly that back off. A guarded cell is quoted as well,
///   so the apostrophe is unambiguously part of the cell rather than of the
///   file. It guards the six characters that make a spreadsheet execute a cell
///   and carries everything else through, so a consumer who needs the bytes as
///   the scanner saw them has JSON.
/// - HTML escapes the five characters that carry markup and renders a control
///   character as its code point. That covers the bidirectional overrides, which
///   reorder the text after them and are how a report is made to display one
///   address while carrying another.
/// - Nmap XML escapes the same five and drops what XML 1.0 cannot carry at all.
///   Most C0 controls are forbidden from the document outright, and a numeric
///   reference to one is forbidden just as firmly, so there is no escape to
///   write instead.
fn text_the_network_chose() {
    let report = hostile_report();

    #[cfg(feature = "export-csv")]
    {
        let table = render(
            &zond_engine::export::CsvExporter::new(ExportOptions::new()),
            &report,
        );
        println!("csv rows, with the invisible characters spelled out:");
        for row in table.lines().skip(1) {
            println!("  {}", ellipsis(&visible(row), 88));
        }
    }

    #[cfg(feature = "export-html")]
    {
        let page = render(
            &zond_engine::export::HtmlExporter::new(ExportOptions::new()),
            &report,
        );
        println!();
        println!(
            "html: {} raw \"<script\", {} escaped \"&lt;script&gt;\"",
            page.matches("<script").count(),
            page.matches("&lt;script&gt;").count()
        );
        println!(
            "      U+202E named as a code point {} time(s), raw {} time(s)",
            page.matches("U+202E").count(),
            page.matches('\u{202e}').count()
        );
    }

    #[cfg(feature = "export-nmap")]
    {
        let document = render(
            &zond_engine::export::NmapXmlExporter::new(ExportOptions::new()),
            &report,
        );
        println!();
        println!(
            "xml:  {} raw control character(s), {} raw \"<\" in a value, {} escaped",
            document.chars().filter(|c| *c < ' ' && *c != '\n').count(),
            document.matches("<script").count(),
            document.matches("&lt;script&gt;").count()
        );
    }
}

/// One file, opened in a browser, read by a person.
///
/// The stylesheet is inlined and there is no image, no font, no favicon and no
/// request of any kind to anywhere. A report travels as a mail attachment, as an
/// artifact on a ticket, as a file on a share, and in each of those a request to
/// a CDN either fails and leaves the reader with unstyled text or succeeds and
/// tells a third party that the report was opened, when, and from where.
///
/// There is no JavaScript either, not merely none from a third party, because
/// the places a security tool's output gets read are the places scripts are
/// blocked. Sorting and filtering the host list are the price, and
/// [`csv`](zond_engine::export::csv) exists for the person who wants to sort,
/// in the tool they would sort with. The light and dark switch is CSS.
///
/// There is no PDF exporter, since a PDF crate costs more than a lightweight
/// engine should spend. An `@media print` stylesheet does that job instead, so
/// `Ctrl-P` produces the document that goes in the appendix.
#[cfg(feature = "export-html")]
fn a_page_for_a_person(report: &ScanReport) {
    use zond_engine::export::HtmlExporter;

    let page = render(&HtmlExporter::new(ExportOptions::new()), report);

    println!("{} bytes, and nothing outside them:", page.len());
    for construct in ["<script", "src=", "href=", "url(", "@import"] {
        println!(
            "  {construct:<8} appears {} time(s)",
            page.matches(construct).count()
        );
    }

    // The engine never knows what a scan was for. A front end that does can say
    // so, and the heading is also the page's title.
    let titled = render(
        &HtmlExporter::new(ExportOptions::new()).with_heading("Acme engagement, week 32"),
        report,
    );
    println!();
    match first_line_containing(&titled, "<title>") {
        Some(line) => println!("with_heading: {line}"),
        None => println!("with_heading: the page carries no title"),
    }
}

#[cfg(not(feature = "export-html"))]
fn a_page_for_a_person(_report: &ScanReport) {
    skipped("export-html");
}

/// Nmap-compatible XML, for the ingest pipelines that already exist.
///
/// DefectDojo, Metasploit, Faraday and Dradis all read nmap's XML and none of
/// them read this engine's JSON, so this is the file that puts a zond scan into
/// somebody's existing workflow without asking them to change it. That is the
/// whole justification: a narrower description in somebody else's vocabulary,
/// earning its place by being understood downstream.
///
/// It says `scanner="zond"`, never `scanner="nmap"`. A scan report is evidence,
/// and a document claiming to be nmap's output when it is not is a fabricated
/// record. `xmloutputversion` stays nmap's, since that names the format and this
/// document really is in it. Measured against nmap 7.99's DTD, the scanner name
/// is the only thing that does not validate, and no honest producer of the
/// format can do better: the DTD declares an enumeration with one member in it.
///
/// Where the two vocabularies disagree the document says less rather than
/// something false. Port states map exactly, both naming the same six. Host
/// status is flattened onto nmap's three, so a host this engine calls `filtered`
/// is exported `up` with the distinction carried in the `reason`.
///
/// `examples/nmap_dump.rs` writes one of these to standard output, for holding
/// against a real DTD with `xmllint`.
#[cfg(feature = "export-nmap")]
fn somebody_elses_pipeline(report: &ScanReport) {
    use zond_engine::export::NmapXmlExporter;

    let document = render(&NmapXmlExporter::new(ExportOptions::new()), report);

    for line in document.lines().filter(|line| {
        ["<nmaprun", "<scaninfo", "<address ", "<status ", "<port "]
            .iter()
            .any(|element| line.trim_start().starts_with(element))
    }) {
        println!("  {line}");
    }

    println!();
    println!("192.168.0.7 is `filtered` in the report and `up` here, with the");
    println!("distinction kept in the reason.");
}

#[cfg(not(feature = "export-nmap"))]
fn somebody_elses_pipeline(_report: &ScanReport) {
    skipped("export-nmap");
}

/// [`Exporter`] is public, and so is every type the document is made of.
///
/// A consumer who wants PDF output, or their own branded HTML, or a line
/// protocol for a metrics system, writes an exporter in their own crate with
/// their own dependencies, and this crate takes none of them on. There is no
/// plugin system: dynamic loading inside a process holding raw-socket privileges
/// buys nothing a trait does not.
///
/// Two things move to the implementer along with the trait. Escaping, since the
/// destination format's rules are now theirs; and streaming, since an exporter
/// that collects the hosts first costs a network's worth of memory instead of a
/// host's.
///
/// The name functions in [`schema`](zond_engine::export::schema) are the reason
/// not to invent a second vocabulary for the same things. A port that is `open`
/// in the JSON should be `open` here, and
/// [`port_state_name`](zond_engine::export::schema::port_state_name) is what
/// keeps that true when a state is added. The DTOs are public and `Serialize`
/// for the same reason: an exporter that wants the engine's own field names does
/// not have to restate them.
fn writing_an_exporter(report: &ScanReport) {
    use zond_engine::export::schema::{port_state_name, protocol_name};

    /// Open ports as a markdown table, for pasting into a ticket.
    struct Markdown;

    impl Exporter for Markdown {
        fn export(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), ExportError> {
            writeln!(out, "| host | port | state | service |")?;
            writeln!(out, "|---|---|---|---|")?;

            for host in report.hosts() {
                for port in host.ports() {
                    writeln!(
                        out,
                        "| {} | {}/{} | {} | {} |",
                        host.primary_ip(),
                        port.number(),
                        protocol_name(port.protocol()),
                        port_state_name(port.state()),
                        port.service_name().unwrap_or("-"),
                    )?;
                }
            }

            Ok(())
        }
    }

    print!("{}", render(&Markdown, report));
}

/// The two failures an export can hit, and why they are separate variants.
///
/// [`ExportError::Io`] is the destination refusing the write: a full disk, a
/// closed pipe, a permissions problem. Retrying against a different destination
/// can fix it.
///
/// [`ExportError::Render`] is the report not fitting the format. It names the
/// format and what could not be represented, and retrying anywhere produces the
/// same thing, so a front end should say so rather than offer to try again. It
/// is reachable: `serde_json` reports a failed write and an unrepresentable
/// value through one error type, and the JSON writers sort the two apart rather
/// than passing on whichever it was handed.
///
/// An exporter writes as it walks, so a failure part way through leaves a
/// partial document at the destination. Write somewhere disposable and move it
/// into place if a truncated file would be mistaken for a complete one.
fn when_the_destination_gives_out(report: &ScanReport) {
    /// A pipe whose reader has gone, which is what `| head` looks like from this
    /// end.
    struct ClosedPipe {
        accepted: usize,
    }

    impl Write for ClosedPipe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.accepted >= 256 {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "reader is gone"));
            }
            let taken = buf.len().min(256 - self.accepted);
            self.accepted += taken;
            Ok(taken)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let Some(format) = ExportFormat::all().first() else {
        skipped("export-json");
        return;
    };

    let mut destination = ClosedPipe { accepted: 0 };
    match format
        .exporter(ExportOptions::new())
        .export(report, &mut destination)
    {
        Ok(()) => println!("the whole report fitted in {} bytes", destination.accepted),
        Err(error @ ExportError::Io(_)) => {
            println!("after {} bytes: {error}", destination.accepted);
            println!("Io, so another destination may still accept it");
        }
        Err(error @ ExportError::Render { .. }) => {
            println!("{error}");
            println!("Render, so no destination will accept it");
        }
        Err(error) => println!("{error}"),
    }
}

/// A comparison is a document too, and it has its own module.
///
/// [`export::diff`](zond_engine::export::diff) is to a
/// [`ScanDiff`](zond_engine::diff::ScanDiff) what [`export`](zond_engine::export)
/// is to a report. A comparison that only reaches a terminal serves the person
/// who ran it and nobody downstream, and downstream is where a nightly job earns
/// its keep, in an alerting rule or a ticket or a review queue.
///
/// Every change in the document is one scalar fact, `{kind, before, after}`, so
/// a rule engine needs one code path rather than a parser per variant. A host
/// that gained three addresses produces three changes rather than one carrying a
/// list.
///
/// The field not to drop is `confirmed`. It says how much of a count the other
/// scan is known to have looked for, and a comparison that ignores it reports
/// hosts as gone every time a scan is narrowed. It is derived, and stated anyway,
/// because re-deriving it is the step somebody will skip.
#[cfg(feature = "export-json")]
fn what_changed(baseline: &ScanReport) {
    use zond_engine::diff::ScanDiff;
    use zond_engine::export::diff::{DiffExporter, DiffFormat, JsonDiffExporter};

    let current = tonight();
    let comparison = ScanDiff::between(baseline, &current);
    let summary = comparison.summary();

    println!("formats for a comparison: {:?}", DiffFormat::all());
    println!();
    for (label, count) in [
        ("hosts added  ", summary.hosts_added),
        ("hosts removed", summary.hosts_removed),
        ("ports opened ", summary.ports_opened),
        ("ports closed ", summary.ports_closed),
    ] {
        println!(
            "  {label} {} ({} confirmed by what the other scan covered)",
            count.total, count.confirmed
        );
    }

    println!();
    println!("both opened ports are outside the port scope the baseline phase");
    println!("recorded, so neither is confirmed: 3389 and 445 are not ports the");
    println!("earlier scan looked at, and a port nobody looked at cannot be said");
    println!("to have opened. Widen that scope and both become confirmed.");

    let mut out = Vec::new();
    JsonDiffExporter::new(ExportOptions::new())
        .compact()
        .export(&comparison, &mut out)
        .expect("the comparison exports");

    let document = String::from_utf8(out).expect("the document is UTF-8");
    println!();
    println!("as one line, {} bytes:", document.len());
    println!("  {}", ellipsis(&document, 92));
}

#[cfg(not(feature = "export-json"))]
fn what_changed(_baseline: &ScanReport) {
    skipped("export-json");
}

// ---------------------------------------------------------------------------
// The scan every section above exports
// ---------------------------------------------------------------------------

/// Three hosts, chosen for what they make the formats say.
///
/// A gateway described as fully as the schema allows, a host a discovery sweep
/// saw and nothing port-scanned, and a host that answered nothing but a filtered
/// probe. A real report comes out of [`scanner::scan`](zond_engine::scanner);
/// this one is assembled through the same public API a consumer has, so nothing
/// here needs a network.
fn report() -> ScanReport {
    ScanReport::new(phase(), vec![gateway(), swept(), quiet()])
}

/// What the scan was asked for and what it was set to.
///
/// A phase is a third of the exported document, and a report a scan produced
/// always has at least one, since a phase completing is what produces it. It is
/// also where a comparison's `confirmed` comes from: the scope says what this
/// scan looked at, so the next one can tell a host that went away from a host it
/// did not ask about.
fn phase() -> ScanPhase {
    let scope = TargetScope::from_parts(ScopeParts {
        addresses: 256,
        withheld: 0,
        probes: Some(1_024),
        ranges: vec!["192.168.0.0/24".parse().expect("a well formed range")],
        excluded: Vec::new(),
        links: Vec::new(),
        listened: Vec::new(),
        ports: PortScope::Every(PortSet::try_from("22,53,443,8080").expect("a port set")),
        protocols: vec![Protocol::Tcp, Protocol::Udp],
    });

    ScanPhase::from_parts(PhaseParts {
        kind: ScanKind::PortScan,
        started_at: SystemTime::now() - Duration::from_secs(9),
        elapsed: Duration::from_millis(8_400),
        settings: ScanSettings::from(&ZondConfig::default()),
        targets: scope,
        privilege: Some(Privilege::Raw),
        origin: None,
        probes: Vec::new(),
        failures: Vec::new(),
        // A scan that declined nothing. The field is left out of the document
        // entirely rather than written as an empty list, which is what a
        // consumer reading `refusals` has to expect.
        refusals: Vec::new(),
        attachments: Vec::new(),
        unroutable: Vec::new(),
    })
}

/// The gateway, carrying one of most things the document has a field for.
fn gateway() -> Host {
    let mut host = Host::new(ip(1));
    host.set_status(HostStatus::Up);
    host.set_hostname(Some("router.local".to_string()));
    host.add_reason(StatusReason::new(StatusProtocol::Arp, "reply from gateway"));
    host.record_mac(MacAddr::new(0x2c, 0xcf, 0x67, 0xf2, 0x51, 0xe3));
    host.add_rtt(Duration::from_micros(1_200));
    host.add_rtt(Duration::from_micros(1_800));

    let mut os = OsFingerprint::new("Linux", 95).with_family("Unix-like");
    os.add_cpe("cpe:/o:linux:linux_kernel:5.15.0");
    host.set_os(os);

    host.add_port(
        Port::new(22, Protocol::Tcp, PortState::Open)
            .with_service(
                Service::new("ssh", 100)
                    .with_product("OpenSSH")
                    .with_version("9.6p1"),
            )
            .with_discovery(
                Discovery::new(ScanResponse::TcpSynAck).with_rtt(Duration::from_micros(1_450)),
            ),
    );
    host.add_port(
        Port::new(443, Protocol::Tcp, PortState::Open)
            .with_service(Service::new("https", 90).with_product("nginx"))
            .with_security(
                Security::new()
                    .with_tls_version("TLSv1.3")
                    .with_cipher_suite("TLS_AES_256_GCM_SHA384")
                    .with_certificate(CertificateInfo::new(
                        "router.local",
                        "Local CA",
                        SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_225_600),
                        SystemTime::UNIX_EPOCH + Duration::from_secs(1_798_761_600),
                        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                    )),
            ),
    );
    host.add_port(Port::new(53, Protocol::Udp, PortState::Open));
    host.add_port(Port::new(8080, Protocol::Tcp, PortState::Closed));

    host
}

/// A host a sweep found and nothing port-scanned. Its CSV row carries the host
/// columns and leaves the port columns empty.
fn swept() -> Host {
    let mut host = Host::new(ip(24));
    host.set_status(HostStatus::Up);
    host.add_reason(StatusReason::new(StatusProtocol::IcmpEcho, "echo reply"));
    host
}

/// A host that answered nothing conclusive.
fn quiet() -> Host {
    let mut host = Host::new(ip(7));
    host.set_status(HostStatus::Filtered);
    host.add_port(Port::new(25, Protocol::Tcp, PortState::Filtered));
    host
}

/// The same network a night later: one host gone, one arrived, one port opened.
#[cfg(feature = "export-json")]
fn tonight() -> ScanReport {
    let mut gateway = gateway();
    gateway.add_port(Port::new(3389, Protocol::Tcp, PortState::Open));

    let mut arrival = Host::new(ip(31));
    arrival.set_status(HostStatus::Up);
    arrival.add_port(Port::new(445, Protocol::Tcp, PortState::Open));

    ScanReport::new(phase(), vec![gateway, swept(), arrival])
}

/// Three hosts named by somebody who would rather the report ran than described
/// them.
fn hostile_report() -> ScanReport {
    let mut formula = Host::new(ip(101));
    formula.set_status(HostStatus::Up);
    formula.set_hostname(Some("=cmd|'/c calc'!A1".to_string()));

    let mut markup = Host::new(ip(102));
    markup.set_status(HostStatus::Up);
    markup.set_hostname(Some("<script>alert('report')</script>".to_string()));

    let mut reversed = Host::new(ip(103));
    reversed.set_status(HostStatus::Up);
    reversed.set_hostname(Some("web\u{202e}gnp.evil\u{0001}".to_string()));

    ScanReport::new(phase(), vec![formula, markup, reversed])
}

// ---------------------------------------------------------------------------
// Small helpers, so the demonstrations above stay about the library
// ---------------------------------------------------------------------------

fn ip(last: u8) -> IpAddr {
    IpAddr::from([192, 168, 0, last])
}

/// Exports into memory, which is what makes this file runnable anywhere.
///
/// A real caller passes a [`BufWriter`](std::io::BufWriter) over a file, a
/// response body, or a locked handle to standard output.
fn render(exporter: &dyn Exporter, report: &ScanReport) -> String {
    let mut out = Vec::new();
    exporter
        .export(report, &mut out)
        .expect("a Vec accepts every write");
    String::from_utf8(out).expect("every format this engine writes is UTF-8")
}

/// Whether a value redaction has an opinion about reached the document.
fn survives(document: &str, value: &str) -> &'static str {
    if document.contains(value) {
        "kept"
    } else {
        "gone"
    }
}

/// Spells out the characters a terminal would swallow or obey, and leaves every
/// other character as it is.
///
/// Printing a report's own text raw is how a demonstration of a reordering
/// attack becomes a victim of one.
fn visible(text: &str) -> String {
    text.chars()
        .map(|character| match character {
            '\u{0}'..='\u{1f}' | '\u{7f}' | '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' => {
                format!("\\u{{{:04x}}}", character as u32)
            }
            other => other.to_string(),
        })
        .collect()
}

fn first_line_containing<'a>(document: &'a str, needle: &str) -> Option<&'a str> {
    document
        .lines()
        .find(|line| line.contains(needle))
        .map(str::trim)
}

/// A line short enough for a terminal, with the cut marked.
fn ellipsis(line: &str, width: usize) -> String {
    match line.char_indices().nth(width) {
        Some((cut, _)) => format!("{}...", &line[..cut]),
        None => line.to_string(),
    }
}

fn heading(title: &str) {
    println!("\n\x1b[1m{title}\x1b[0m");
    println!("{}", "-".repeat(title.len()));
}

#[allow(dead_code)]
fn skipped(feature: &str) {
    println!("(not built: re-run with --features {feature})");
}
