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
//! needed. Needs no privileges or network: the report is built through the public
//! API and every document is written into a `Vec<u8>`, as it would be to a file.
//!
//! ```text
//! cargo run --example export                        # JSON, the default
//! cargo run --example export --features export-all  # every format
//! ```
//!
//! ## Writers, not paths
//!
//! An exporter writes into a `dyn Write`; the caller supplies the destination:
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
//! All three receive the same bytes. Output streams as the report is walked, so
//! a large document is never held in memory and a pipe sees the first host early.
//!
//! Buffer the destination: an exporter issues many small writes.

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
/// Every field the engine records is in it; the other formats are narrower views.
///
/// Indented by default, so it diffs line by line.
/// [`compact`](zond_engine::export::json::JsonExporter::compact) is for machine
/// consumers.
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
/// [`schema`](zond_engine::export::schema) states them in full.
///
/// - Timestamps are RFC 3339 in UTC, to microsecond precision.
/// - Durations are integers of microseconds, in a field whose name ends `_us`.
/// - A count that can exceed 2^53 is a decimal string, since a JSON number loses
///   precision in a browser.
/// - Objects have a fixed shape. A field with no value is `null`, an empty list is
///   `[]`, and absence means the scan did not do the thing at all.
/// - Order is deterministic: hosts by address, ports by number.
/// - Unknown fields may appear without a `schema_version` bump; ignore them.
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

/// [`ExportFormat::from_path`] reads the format off a destination's extension, and
/// [`ExportFormat::all`] names the formats this build can write.
///
/// An extension no compiled-in format claims resolves to `None`.
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

    // The same resolution in one call. The report goes to `out`; `path` only
    // picks the format, and opening it stays with the caller.
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

/// Redaction happens on the way out, where data leaves the process.
///
/// [`Redaction::Standard`] masks what names a person or a device. A hostname keeps
/// its first and last two characters, so devices stay distinguishable; a hardware
/// address keeps its OUI, so the vendor survives.
///
/// Addresses are left alone, since hosts must stay distinguishable. An IPv6
/// address formed by EUI-64 embeds the hardware address, so it still leaks there.
fn masking_identifiers(report: &ScanReport) {
    let mac = MacAddr::new(0x2c, 0xcf, 0x67, 0x00, 0x00, 0x01);

    for policy in [Redaction::None, Redaction::Standard] {
        println!("{policy:?} (masks anything: {}):", policy.is_active());
        println!("  workstation  -> {}", policy.hostname("workstation"));
        println!("  wifi-printer -> {}", policy.hostname("wifi-printer"));
        println!("  the address  -> {}", policy.mac(&mac));
    }

    // The policy travels in the options, so it reaches every format.
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
            survives(&document, "203.0.113.1"),
        );
    }
}

/// The same data as the JSON document, one record per line.
///
/// A truncated JSON document is not JSON; a truncated stream is a complete file
/// with fewer hosts, and `grep`, `head`, `split` and `wc -l` work on it.
///
/// Every line has a `type` field. Without it, a `host` line is byte-identical to
/// an element of the document's `hosts` array, so one parser reads both formats.
///
/// The `report` record carries everything except the hosts and comes first. Its
/// tag is a field, so lines can be grepped out or concatenated.
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

    // Cut the stream mid-line, as a killed process would, and read it back.
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
/// A table drops the phases, settings, probe instrumentation and secondary
/// addresses; [`json`](zond_engine::export::json) has the whole record.
///
/// A host with no ports gets a row with empty port columns. The column list is
/// [`format::csv::COLUMNS`](zond_engine::format::csv::COLUMNS), shared with the
/// `import-csv` reader.
///
/// RFC 4180 quoting with LF line endings, which every spreadsheet accepts and
/// Unix tools prefer.
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

    // Excel on Windows reads unmarked UTF-8 as the system code page. Opt-in,
    // since the mark confuses parsers that do not expect it.
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

/// Hostnames, banners and certificate subjects are chosen by whoever runs the
/// device: `=cmd|'/c calc'!A1` attacks a CSV reader, `<script>` a page reader.
/// These guards are always on.
///
/// - CSV prefixes a cell starting with one of six formula characters with an
///   apostrophe and quotes it; the `import-csv` reader removes it. JSON keeps the
///   bytes as seen.
/// - HTML escapes the five markup characters and renders control characters,
///   including bidirectional overrides, as code points.
/// - Nmap XML escapes the same five and drops C0 controls, which XML 1.0 forbids
///   even as numeric references.
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
/// Self-contained: inline stylesheet, no external requests, so it renders offline
/// and tells no third party it was opened.
///
/// No JavaScript, since scripts are often blocked where reports are read. For
/// sorting, use [`csv`](zond_engine::export::csv). The light and dark switch is
/// CSS.
///
/// An `@media print` stylesheet makes printing to PDF work.
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

    // A front end can set a heading, which is also the page's title.
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
/// DefectDojo, Metasploit, Faraday and Dradis read nmap's XML, so this puts a scan
/// into an existing workflow.
///
/// It says `scanner="zond"`, since a report is evidence and must not claim to be
/// nmap's. `xmloutputversion` is nmap's, naming the format. Against nmap 7.99's
/// DTD the scanner name is the only failure, as the DTD's enumeration has one
/// member.
///
/// Where the vocabularies disagree the document says less. Nmap's `filtered`
/// covers both blocked and no reply, told apart in `reason`; a `blocked` host is
/// exported `up`, with the distinction in `reason`.
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
    println!("203.0.113.7 is `blocked` in the report and `up` here, with the");
    println!("distinction kept in the reason.");
}

#[cfg(not(feature = "export-nmap"))]
fn somebody_elses_pipeline(_report: &ScanReport) {
    skipped("export-nmap");
}

/// [`Exporter`] is public, and so is every type the document is made of.
///
/// A PDF, branded HTML or metrics exporter lives in its own crate with its own
/// dependencies. There is no plugin system; a trait is enough.
///
/// The implementer owns escaping for the destination format, and streaming.
///
/// Use the name functions in [`schema`](zond_engine::export::schema), such as
/// [`port_state_name`](zond_engine::export::schema::port_state_name), to keep the
/// engine's vocabulary. The DTOs are public and `Serialize` for the same reason.
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
/// [`ExportError::Io`] is the destination refusing the write (full disk, closed
/// pipe, permissions); another destination may work.
///
/// [`ExportError::Render`] is the report not fitting the format; it names what
/// could not be represented, and retrying will not help. The JSON writers separate
/// it from I/O errors that `serde_json` reports through the same type.
///
/// A failure part way leaves a partial document. Write to a temporary file and
/// move it into place if that matters.
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
/// is to a report, for alerting rules, tickets and review queues.
///
/// Every change is one scalar fact, `{kind, before, after}`: a host that gained
/// three addresses produces three changes.
///
/// Keep `confirmed`: how much of a count the other scan is known to have looked
/// for. Ignoring it reports hosts as gone whenever a scan is narrowed.
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
/// A fully described gateway, a host only a discovery sweep saw, and a host whose
/// path refused a probe. Assembled through the public API, so no network is
/// needed; a real one comes from [`scanner::scan`](zond_engine::scanner).
fn report() -> ScanReport {
    ScanReport::new(phase(), vec![gateway(), swept(), quiet()])
}

/// What the scan was asked for and what it was set to.
///
/// A scan's report always has at least one phase. Its scope is where a
/// comparison's `confirmed` comes from.
fn phase() -> ScanPhase {
    let scope = TargetScope::from_parts(ScopeParts {
        addresses: 256,
        withheld: 0,
        probes: Some(1_024),
        ranges: vec!["203.0.113.0/24".parse().expect("a well formed range")],
        excluded: Vec::new(),
        links: Vec::new(),
        listened: Vec::new(),
        ports: PortScope::Every(PortSet::try_from("22,53,443,8080").expect("a port set")),
        protocols: vec![Protocol::Tcp, Protocol::Udp],
    });

    ScanPhase::from_parts(PhaseParts {
        open: false,
        kind: ScanKind::PortScan,
        started_at: SystemTime::now() - Duration::from_secs(9),
        elapsed: Duration::from_millis(8_400),
        settings: ScanSettings::from(&ZondConfig::default()),
        targets: scope,
        privilege: Some(Privilege::Raw),
        origin: None,
        probes: Vec::new(),
        failures: Vec::new(),
        // A scan that declined nothing. The field is then omitted from the
        // document, not written as an empty list.
        refusals: Vec::new(),
        attachments: Vec::new(),
        unroutable: Vec::new(),
        refused_by_route: Vec::new(),
        timed_out: Vec::new(),
        icmp_rate_limited: Vec::new(),
        // Every target reached with the packets the scan chose; omitted too.
        reached_by_connect: Vec::new(),
        undecided: Vec::new(),
        liveness_skipped: None,
        silent: Vec::new(),
        stopped: None,
        passes_cut: Vec::new(),
        unreached: 0,
        unheard_probes: 0,
    })
}

/// The gateway, carrying one of most things the document has a field for.
fn gateway() -> Host {
    let mut host = Host::new(ip(1));
    host.set_status(HostStatus::Up);
    host.set_hostname(Some("router.local".to_string()));
    host.add_reason(StatusReason::new(StatusProtocol::Arp, "reply from gateway"));
    host.record_mac(MacAddr::new(0x2c, 0xcf, 0x67, 0x00, 0x00, 0x01));
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
    host.set_status(HostStatus::Blocked);
    host.add_port(Port::new(25, Protocol::Tcp, PortState::NoReply));
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

/// Three hosts with hostile names.
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
    IpAddr::from([203, 0, 113, last])
}

/// Exports into memory. A real caller passes a [`BufWriter`](std::io::BufWriter)
/// over a file, a response body, or locked standard output.
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

/// Spells out the characters a terminal would swallow or obey, so printing
/// hostile text does not reorder the output.
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
