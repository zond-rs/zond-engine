// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The import readers driven from outside the crate, against files on disk.
//!
//! Tier 1: no network, no privileges, no harness. Every test here writes a
//! document to a file of its own, hands the engine a reader over that file, and
//! takes the file away again.
//!
//! ## Why a binary of its own
//!
//! `import` is the one part of this engine that parses a document nobody here
//! wrote: a target list from a client, a report off a shared drive, an nmap
//! file out of an engagement repository. The unit tests beside each reader
//! drive it from a `Cursor` over a string literal, which is the right shape for
//! the grammar and the wrong shape for the three things a consumer depends on
//! and those tests never cross: that [`ImportFormat::read`] and
//! [`ReportFormat::read`] reach the reader a caller outside the crate gets,
//! that [`ImportLimits`] and [`OnRefusal`] mean the same thing from out here,
//! and that a real file rather than a string is what gets read.
//!
//! So this covers the dispatch, each bound at the limit and one past it, the
//! refusal policy on the file it was shaped for, and the round trip: a report
//! this engine exported, read back both as the report it was written from and
//! as the targets it names, agreeing about both.
//!
//! ## What it leaves alone
//!
//! The XML refusals. `import::xml` refuses entity declarations, a DOCTYPE with
//! `SYSTEM`, `PUBLIC` or an internal subset, and undeclared references, and it
//! carries twenty unit tests saying so. Nothing here re-tests them. The nmap
//! cases below are about where the dispatch lands and where an error points.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use zond_engine::export::{ExportOptions, Exporter, JsonExporter, JsonLinesExporter};
use zond_engine::import::report::{ReportFormat, ReportOptions};
use zond_engine::import::{
    ImportError, ImportFormat, ImportLimits, ImportOptions, ImportOrigin, Imported, OnRefusal,
};
use zond_engine::model::host::{Host, HostStatus};
use zond_engine::model::port::{Port, PortSet, PortState, Protocol};
use zond_engine::report::ScanReport;

// ---------------------------------------------------------------------------
// Documents, and the file they are read from
// ---------------------------------------------------------------------------

/// A list of the kind a person types or a ticket carries.
const TARGET_LIST: &str = "\
# staging, 2026-02
192.168.0.1
10.0.0.0/30:8080
[2001:db8::1]:443    # the load balancer
192.168.0.20 192.168.0.21
";

/// A table with this engine's own header on it, one row per host and port.
const TARGET_TABLE: &str = "\
ip,hostname,status,port,protocol,state
10.0.0.1,gateway,up,22,tcp,open
10.0.0.1,gateway,up,53,udp,open
2001:db8::1,edge,up,443,tcp,open
198.51.100.7,quiet,up,,,
";

/// A report as a single document, cut down to the fields the target reader
/// promises to read.
const REPORT_DOCUMENT: &str = r#"{
  "schema_version": 1,
  "engine": {"name": "zond-engine", "version": "0.13.0"},
  "hosts": [
    {"primary_ip": "10.0.0.1", "ips": ["10.0.0.1", "2001:db8::1"],
     "ports": [{"port": 22, "protocol": "tcp"}, {"port": 53, "protocol": "udp"}]},
    {"primary_ip": "10.0.0.9"}
  ]
}"#;

/// The same report, one record per line.
const REPORT_RECORDS: &str = concat!(
    r#"{"type":"report","schema_version":1,"engine":{"name":"zond-engine"}}"#,
    "\n",
    r#"{"type":"host","primary_ip":"10.0.0.1","ips":["10.0.0.1","2001:db8::1"],"#,
    r#""ports":[{"port":22,"protocol":"tcp"},{"port":53,"protocol":"udp"}]}"#,
    "\n",
    r#"{"type":"host","primary_ip":"10.0.0.9"}"#,
    "\n",
);

/// What nmap writes, preamble and all.
const NMAP_DOCUMENT: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
    "<!DOCTYPE nmaprun>\n",
    "<nmaprun scanner=\"nmap\" args=\"nmap -oX out.xml\" start=\"1786468167\" version=\"7.94\">\n",
    "<host>\n",
    "<status state=\"up\" reason=\"echo-reply\" reason_ttl=\"64\"/>\n",
    "<address addr=\"10.0.0.1\" addrtype=\"ipv4\"/>\n",
    "<address addr=\"aa:bb:cc:dd:ee:ff\" addrtype=\"mac\" vendor=\"Arris\"/>\n",
    "<ports>\n",
    "<port protocol=\"tcp\" portid=\"22\"><state state=\"open\" reason=\"syn-ack\"/>",
    "<service name=\"ssh\" product=\"OpenSSH\" method=\"probed\" conf=\"10\"/></port>\n",
    "<port protocol=\"udp\" portid=\"53\"><state state=\"open\" reason=\"udp-response\"/></port>\n",
    "</ports>\n</host>\n",
    "<host><status state=\"down\" reason=\"no-response\"/>",
    "<address addr=\"2001:db8::1\" addrtype=\"ipv6\"/></host>\n",
    "<runstats><finished time=\"3\" elapsed=\"0.01\"/></runstats>\n",
    "</nmaprun>\n",
);

/// The happy-path document for a format.
///
/// [`ImportFormat`] is `non_exhaustive`, so the wildcard is what a format added
/// to the crate lands in, and the coverage test below is what makes that a
/// failure rather than a silent gap.
fn sample(format: ImportFormat) -> &'static str {
    match format {
        ImportFormat::List => TARGET_LIST,
        ImportFormat::Csv => TARGET_TABLE,
        ImportFormat::Json => REPORT_DOCUMENT,
        ImportFormat::JsonLines => REPORT_RECORDS,
        ImportFormat::NmapXml => NMAP_DOCUMENT,
        other => panic!("{other} has no document in this file"),
    }
}

/// The ports an expression that names none is scanned on, throughout.
const DEFAULT_PORTS: &str = "80";

fn options() -> ImportOptions<'static> {
    ImportOptions::new(PortSet::try_from(DEFAULT_PORTS).expect("the default ports parse"))
}

/// A scratch path nothing else in this process will pick.
fn scratch(name: &str, extension: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "zond-import-{}-{name}.{extension}",
        std::process::id()
    ))
}

/// Writes `document` to a file, reads it back through `read`, and removes it.
fn through_a_file<T>(
    name: &str,
    extension: &str,
    document: &[u8],
    read: impl FnOnce(&mut dyn BufRead) -> T,
) -> T {
    let path = scratch(name, extension);
    std::fs::write(&path, document).expect("the scratch file is writable");

    let mut input = BufReader::new(File::open(&path).expect("the scratch file is readable"));
    let outcome = read(&mut input);

    drop(input);
    std::fs::remove_file(&path).expect("clean up");
    outcome
}

/// Reads a document off the disk as targets, through the public dispatch.
fn read_targets(
    name: &str,
    format: ImportFormat,
    document: &str,
    options: &ImportOptions<'_>,
) -> Result<Imported, ImportError> {
    through_a_file(name, format.extension(), document.as_bytes(), |input| {
        format.read(input, options)
    })
}

/// Reads a document off the disk as a report, through the public dispatch.
fn read_report(
    name: &str,
    format: ReportFormat,
    document: &str,
    options: ReportOptions,
) -> Result<ScanReport, ImportError> {
    through_a_file(name, format.extension(), document.as_bytes(), |input| {
        format.read(input, options)
    })
}

/// Every host and port a report names, as text, so that a report and the
/// targets read out of the same document can be compared directly.
fn endpoints(report: &ScanReport) -> BTreeSet<(String, u16, String)> {
    let mut endpoints = BTreeSet::new();
    for host in report.hosts() {
        for ip in host.ips() {
            for port in host.ports() {
                endpoints.insert((
                    ip.to_string(),
                    port.number(),
                    format!("{:?}", port.protocol()),
                ));
            }
        }
    }
    endpoints
}

/// A report built by hand, so a round trip is held against values that never
/// went through a serializer.
fn hand_built_report() -> ScanReport {
    let mut gateway = Host::new("10.0.0.1".parse::<IpAddr>().expect("an address"));
    gateway.set_status(HostStatus::Up);
    gateway.set_hostname(Some("gateway.example".to_string()));
    gateway.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
    gateway.add_port(Port::new(53, Protocol::Udp, PortState::Open));
    gateway.add_port(Port::new(8080, Protocol::Tcp, PortState::Closed));

    let mut edge = Host::new("2001:db8::1".parse::<IpAddr>().expect("an address"));
    edge.set_status(HostStatus::Up);
    edge.add_port(Port::new(443, Protocol::Tcp, PortState::Open));

    let mut quiet = Host::new("198.51.100.7".parse::<IpAddr>().expect("an address"));
    quiet.set_status(HostStatus::Filtered);
    quiet.add_port(Port::new(25, Protocol::Tcp, PortState::Filtered));

    ScanReport::recorded("zond-test 1.2.3", Vec::new(), vec![gateway, edge, quiet])
}

fn exported(report: &ScanReport) -> String {
    let mut document = Vec::new();
    JsonExporter::new(ExportOptions::new())
        .export(report, &mut document)
        .expect("the report exports");
    String::from_utf8(document).expect("the export is UTF-8")
}

fn exported_lines(report: &ScanReport) -> String {
    let mut document = Vec::new();
    JsonLinesExporter::new(ExportOptions::new())
        .export(report, &mut document)
        .expect("the report exports");
    String::from_utf8(document).expect("the export is UTF-8")
}

// ---------------------------------------------------------------------------
// Every reader, through the dispatch, against a file
// ---------------------------------------------------------------------------

/// A record-per-line export read back as the scan it records, off the disk and
/// through the public dispatch.
///
/// The path this closes: `jsonl` named no report format, so `resolve` fell
/// through to sniffing, sniffing saw a leading brace and answered `Json`, and
/// the single-document reader parsed the first line and stopped. What came back
/// was a report with the right attribution and no hosts at all, which a
/// comparison reads as a network that emptied out overnight.
#[test]
fn a_record_per_line_report_on_disk_reads_back_as_the_scan_it_records() {
    let report = hand_built_report();
    let document = exported_lines(&report);

    let resolved = through_a_file(
        "report-lines-resolve",
        "jsonl",
        document.as_bytes(),
        |input| {
            ReportFormat::resolve(Some(Path::new("scan.jsonl")), input)
                .expect("the path names a format")
        },
    );
    assert_eq!(
        resolved,
        ReportFormat::JsonLines,
        "a .jsonl report must not resolve to the single-document reader"
    );

    let sniffed = through_a_file(
        "report-lines-sniff",
        "jsonl",
        document.as_bytes(),
        |input| ReportFormat::sniff(input).expect("the bytes name a format"),
    );
    assert_eq!(
        sniffed,
        ReportFormat::JsonLines,
        "and neither must one arriving with no name"
    );

    let restored = read_report(
        "report-lines-read",
        ReportFormat::JsonLines,
        &document,
        ReportOptions::default(),
    )
    .expect("the document reads");

    assert_eq!(restored.host_count(), report.host_count());
    assert_eq!(endpoints(&restored), endpoints(&report));
}

/// Every report format resolves from its own extension, and every one of them
/// can be named for a help text.
#[test]
fn every_report_format_resolves_from_its_own_extension() {
    for format in ReportFormat::all() {
        assert_eq!(
            ReportFormat::from_extension(format.extension()),
            Some(*format),
            "{format:?} does not resolve from its own extension"
        );
    }

    assert_eq!(ReportFormat::from_path(Path::new("/tmp/scan")), None);
    assert_eq!(ReportFormat::from_extension("pdf"), None);
}

/// A format with no document here is a format nothing below covers.
#[test]
fn every_format_this_build_reads_has_a_document_here() {
    for format in ImportFormat::all() {
        let imported = read_targets("coverage", *format, sample(*format), &options())
            .unwrap_or_else(|error| panic!("{format} did not read its own document: {error}"));

        assert!(imported.addresses > 0, "{format} produced no targets");
        assert!(imported.refusals.is_empty(), "{format} refused something");
    }
}

#[test]
fn a_hand_written_list_on_disk_becomes_the_hosts_and_ports_it_names() {
    let imported = read_targets("list", ImportFormat::List, TARGET_LIST, &options())
        .expect("the list reads off the disk");

    assert_eq!(imported.tokens, 5, "the comment and the blank carry none");
    assert_eq!(imported.addresses, 8, "one host, a /30, and three more");
    assert_eq!(imported.map.units.len(), 3, "80, 8080 and 443");

    let units = &imported.map.units;
    assert!(units.iter().any(|unit| unit.ports().has_tcp(8080)));
    assert!(units.iter().any(|unit| unit.ports().has_tcp(443)));
    assert!(
        units
            .iter()
            .any(|unit| unit.ports().has_tcp(80) && unit.ips().len() == 3),
        "the three expressions naming no port share the default"
    );
}

#[test]
fn a_table_on_disk_becomes_the_hosts_and_ports_its_columns_name() {
    let imported = read_targets("table", ImportFormat::Csv, TARGET_TABLE, &options())
        .expect("the table reads off the disk");

    assert_eq!(imported.tokens, 4, "the header is not a row");
    assert_eq!(
        imported.addresses, 4,
        "10.0.0.1 lands in two units and is counted in each"
    );

    let units = &imported.map.units;
    assert_eq!(units.len(), 4, "22/tcp, 53/udp, 443/tcp and the default");
    assert!(
        units.iter().any(|unit| unit.ports().has_udp(53)),
        "the protocol column decides which half of the set a port lands in"
    );
    assert!(units.iter().any(|unit| unit.ports().has_tcp(443)));
    assert!(
        units.iter().any(|unit| unit.ports().has_tcp(80)),
        "the row with no port takes the caller's default"
    );
}

#[test]
fn a_report_document_on_disk_becomes_the_targets_it_recorded() {
    let imported = read_targets("report", ImportFormat::Json, REPORT_DOCUMENT, &options())
        .expect("the report reads off the disk");

    assert_eq!(imported.addresses, 3, "a dual-stack host, and one more");
    assert_eq!(imported.map.units.len(), 2);

    let units = &imported.map.units;
    let found = units
        .iter()
        .find(|unit| unit.ports().has_tcp(22))
        .expect("the ports the scan found");
    assert!(found.ports().has_udp(53), "the UDP port came back as UDP");
    assert!(!found.ports().has_tcp(53), "and not as both");
    assert_eq!(found.ips().len(), 2, "both of the host's addresses");

    assert!(
        units.iter().any(|unit| unit.ports().has_tcp(80)),
        "a host the scan found no ports on takes the caller's default"
    );
}

#[test]
fn a_record_per_line_report_on_disk_becomes_the_same_targets() {
    let from_records = read_targets(
        "records",
        ImportFormat::JsonLines,
        REPORT_RECORDS,
        &options(),
    )
    .expect("the records read off the disk");
    let from_document = read_targets(
        "records-document",
        ImportFormat::Json,
        REPORT_DOCUMENT,
        &options(),
    )
    .expect("the document reads off the disk");

    assert_eq!(from_records.addresses, 3);
    assert_eq!(
        from_records.map.units.len(),
        from_document.map.units.len(),
        "a caller's choice of output format must not change what a rescan covers"
    );
    assert!(
        from_records
            .map
            .units
            .iter()
            .any(|unit| unit.ports().has_tcp(22) && unit.ports().has_udp(53))
    );
}

#[test]
fn an_nmap_document_on_disk_becomes_the_hosts_and_ports_it_found() {
    let imported = read_targets("nmap", ImportFormat::NmapXml, NMAP_DOCUMENT, &options())
        .expect("the nmap document reads off the disk");

    assert_eq!(
        imported.addresses, 2,
        "the hardware address is not a target"
    );
    assert_eq!(imported.map.units.len(), 2);
    assert!(
        imported
            .map
            .units
            .iter()
            .any(|unit| unit.ports().has_tcp(22) && unit.ports().has_udp(53)),
        "the ports nmap found come back on the host it found them on"
    );
    assert!(
        imported
            .map
            .units
            .iter()
            .any(|unit| unit.ports().has_tcp(80)),
        "the host nmap found no ports on takes the caller's default"
    );
}

// ---------------------------------------------------------------------------
// A malformed document names where it went wrong
// ---------------------------------------------------------------------------

#[test]
fn a_list_with_a_typo_in_it_names_the_line_the_typo_is_on() {
    let file = "10.0.0.1\n10.0.0.2\n10.0.0.300\n10.0.0.4\n";

    let error = read_targets("list-typo", ImportFormat::List, file, &options())
        .expect_err("the third line is not an address");

    match error {
        ImportError::Target {
            origin, ref token, ..
        } => {
            assert_eq!(origin, ImportOrigin::line(3));
            assert_eq!(token, "10.0.0.300");
        }
        other => panic!("expected a refused target, got {other:?}"),
    }
    assert!(
        error.to_string().starts_with("line 3:"),
        "the message has to say which line to go and look at: {error}"
    );
}

#[test]
fn a_table_whose_header_holds_no_addresses_is_refused_naming_its_first_row() {
    let file = "port,protocol\n22,tcp\n443,tcp\n";

    let error = read_targets("table-headerless", ImportFormat::Csv, file, &options())
        .expect_err("a header with no address column is a table this build cannot read");

    match error {
        ImportError::Malformed {
            format,
            origin,
            ref message,
        } => {
            assert_eq!(format, "CSV");
            assert_eq!(origin, ImportOrigin::line(1), "the header is row one");
            assert!(message.contains("addresses"), "{message}");
        }
        other => panic!("expected a malformed table, got {other:?}"),
    }
}

/// A JSON document has no lines of its own, so the origin says `input` and the
/// place is carried in the message, which is where the parser puts it.
#[test]
fn a_report_document_that_is_not_json_is_refused_naming_where_it_stopped() {
    let file = concat!(
        "{\n",
        "  \"schema_version\": 1,\n",
        "  \"hosts\": [\n",
        "    {\"primary_ip\": }\n",
        "  ]\n",
        "}\n",
    );

    let error = read_targets("report-broken", ImportFormat::Json, file, &options())
        .expect_err("the fourth line has no value in it");

    match error {
        ImportError::Malformed {
            format,
            origin,
            ref message,
        } => {
            assert_eq!(format, "JSON");
            assert_eq!(origin, ImportOrigin::unknown());
            assert!(
                message.contains("line 4"),
                "the parser knows where it stopped: {message}"
            );
        }
        other => panic!("expected a malformed document, got {other:?}"),
    }
    assert!(error.to_string().starts_with("input:"), "{error}");
}

#[test]
fn a_record_per_line_report_names_the_record_that_is_not_one() {
    let file = concat!(
        r#"{"type":"report","schema_version":1}"#,
        "\n",
        r#"{"type":"host","primary_ip":"10.0.0.1"}"#,
        "\n",
        "not a record at all\n",
    );

    let error = read_targets("records-broken", ImportFormat::JsonLines, file, &options())
        .expect_err("the third line is not a record");

    match error {
        ImportError::Malformed { format, origin, .. } => {
            assert_eq!(format, "JSON Lines");
            assert_eq!(origin, ImportOrigin::line(3));
        }
        other => panic!("expected a malformed record, got {other:?}"),
    }
}

#[test]
fn an_nmap_document_with_an_unreadable_port_names_the_line_it_is_on() {
    let file = concat!(
        "<nmaprun>\n",
        "<host>\n",
        "<address addr=\"10.0.0.1\" addrtype=\"ipv4\"/>\n",
        "<ports>\n",
        "<port protocol=\"tcp\" portid=\"ssh\"><state state=\"open\"/></port>\n",
        "</ports>\n",
        "</host>\n",
        "</nmaprun>\n",
    );

    let error = read_targets("nmap-port", ImportFormat::NmapXml, file, &options())
        .expect_err("'ssh' is not a port number");

    match error {
        ImportError::Malformed {
            format,
            origin,
            ref message,
        } => {
            assert_eq!(format, "nmap XML");
            assert_eq!(origin, ImportOrigin::line(5));
            assert!(message.contains("ssh"), "{message}");
        }
        other => panic!("expected a malformed document, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The bounds, at the limit and one past it
// ---------------------------------------------------------------------------

/// `max_line_bytes` is the longest line excluding its terminator, so a line at
/// the limit has to read whichever way it ends.
#[test]
fn a_line_at_the_byte_limit_reads_and_one_byte_past_it_is_refused() {
    const AT_LIMIT: &str = "192.168.100.100:8080";
    const PAST_LIMIT: &str = "192.168.100.100:18080";
    assert_eq!(PAST_LIMIT.len(), AT_LIMIT.len() + 1, "one byte apart");

    let options = options().with_limits(ImportLimits::new().with_max_line_bytes(AT_LIMIT.len()));

    for terminator in ["\n", "\r\n", ""] {
        let file = format!("{AT_LIMIT}{terminator}");
        let imported = read_targets("line-limit", ImportFormat::List, &file, &options)
            .unwrap_or_else(|error| panic!("a line at the limit was refused: {error}"));
        assert_eq!(imported.addresses, 1, "{terminator:?}");
    }

    let file = format!("10.0.0.1\n{PAST_LIMIT}\n");
    let error = read_targets("line-limit-past", ImportFormat::List, &file, &options)
        .expect_err("one byte past the limit is past the limit");

    match error {
        ImportError::LineTooLong { origin, limit } => {
            assert_eq!(limit, AT_LIMIT.len());
            assert_eq!(origin, ImportOrigin::line(2));
        }
        other => panic!("expected a line refusal, got {other:?}"),
    }
}

/// `max_tokens` counts target expressions, not lines, so a file that puts four
/// of them on two lines is at a limit of four.
#[test]
fn an_import_at_the_token_limit_reads_and_one_expression_past_it_is_refused() {
    let options = options().with_limits(ImportLimits::new().with_max_tokens(4));

    let imported = read_targets(
        "token-limit",
        ImportFormat::List,
        "10.0.0.1 10.0.0.2\n10.0.0.3 10.0.0.4\n",
        &options,
    )
    .expect("four expressions is not more than four");
    assert_eq!(imported.tokens, 4);

    let error = read_targets(
        "token-limit-past",
        ImportFormat::List,
        "10.0.0.1 10.0.0.2\n10.0.0.3 10.0.0.4 10.0.0.5\n",
        &options,
    )
    .expect_err("five expressions is");

    assert!(
        matches!(error, ImportError::TooManyTokens { limit: 4 }),
        "{error:?}"
    );
}

/// `max_addresses` is a ceiling on the scan, and the expression that crosses it
/// is the one the error names.
#[test]
fn an_import_at_the_address_limit_reads_and_one_address_past_it_is_refused() {
    let options = options().with_limits(ImportLimits::new().with_max_addresses(256));

    let imported = read_targets(
        "address-limit",
        ImportFormat::List,
        "10.0.0.0/24\n",
        &options,
    )
    .expect("a /24 is 256 addresses, which is not more than 256");
    assert_eq!(imported.addresses, 256);

    let error = read_targets(
        "address-limit-past",
        ImportFormat::List,
        "10.0.0.0/24\n10.1.0.1\n",
        &options,
    )
    .expect_err("one address more is more");

    match error {
        ImportError::TooManyAddresses {
            origin,
            ref token,
            limit,
        } => {
            assert_eq!(limit, 256);
            assert_eq!(origin, ImportOrigin::line(2));
            assert_eq!(token, "10.1.0.1");
        }
        other => panic!("expected an address refusal, got {other:?}"),
    }
}

/// The bound is checked against a running sum rather than a re-merge of the
/// accumulated set, so a file naming the same block twice pays for it twice.
/// That errs towards refusing, which for a limit is the safe direction.
#[test]
fn the_address_limit_counts_a_block_named_twice_twice() {
    let options = options().with_limits(ImportLimits::new().with_max_addresses(256));

    let error = read_targets(
        "address-limit-overlap",
        ImportFormat::List,
        "10.0.0.0/24\n10.0.0.0/24\n",
        &options,
    )
    .expect_err("the running sum reaches 512 even though the merged set is 256");

    assert!(
        matches!(error, ImportError::TooManyAddresses { limit: 256, .. }),
        "{error:?}"
    );

    // And the count reported to a person is the merged one, which is what the
    // scan will actually probe.
    let imported = read_targets(
        "address-limit-merged",
        ImportFormat::List,
        "10.0.0.0/24\n10.0.0.0/24\n",
        &options.with_limits(ImportLimits::new().with_max_addresses(512)),
    )
    .expect("512 is the running sum, and it is within the raised limit");
    assert_eq!(imported.addresses, 256, "the same block, named twice");
}

/// The bound reaches a report reader too, through its own options type.
#[test]
fn a_report_element_past_the_byte_limit_is_refused() {
    let runaway = format!(
        concat!(
            "<nmaprun version=\"7.94\"><host note=\"{}\">",
            "<status state=\"up\" reason=\"echo-reply\"/>",
            "<address addr=\"10.0.0.1\" addrtype=\"ipv4\"/>",
            "</host></nmaprun>"
        ),
        "x".repeat(4 * 1024)
    );

    let error = read_report(
        "report-element-limit",
        ReportFormat::Nmap,
        &runaway,
        ReportOptions::new().with_limits(ImportLimits::new().with_max_line_bytes(256)),
    )
    .expect_err("an element whose markup runs away is refused");

    assert!(
        matches!(error, ImportError::LineTooLong { limit: 256, .. }),
        "{error:?}"
    );

    // The same document once the bound is raised past it, so what was refused
    // was the length rather than anything about the document.
    let report = read_report(
        "report-element-limit-raised",
        ReportFormat::Nmap,
        &runaway,
        ReportOptions::new().with_limits(ImportLimits::new().with_max_line_bytes(64 * 1024)),
    )
    .expect("the document itself is fine");
    assert_eq!(report.host_count(), 1);
}

// ---------------------------------------------------------------------------
// One bad line in a long list
// ---------------------------------------------------------------------------

/// The file the refusal policy was shaped around: five thousand lines with one
/// typo in them.
#[test]
fn one_bad_line_in_a_long_list_aborts_by_default_and_is_collected_on_request() {
    const LINES: u32 = 5_000;
    const BAD: u32 = 2_500;

    let mut file = String::new();
    for line in 1..=LINES {
        if line == BAD {
            file.push_str("10.0.0.300\n");
        } else {
            file.push_str(&format!("10.0.{}.{}\n", line / 256, line % 256));
        }
    }

    let error = read_targets("long-list-abort", ImportFormat::List, &file, &options())
        .expect_err("one typo stops the import by default");
    match error {
        ImportError::Target { origin, .. } => assert_eq!(origin, ImportOrigin::line(BAD as u64)),
        other => panic!("expected a refused target, got {other:?}"),
    }

    let collecting = options().with_refusal_policy(OnRefusal::Collect);
    let imported = read_targets("long-list-collect", ImportFormat::List, &file, &collecting)
        .expect("collecting does not fail the import");

    assert_eq!(
        imported.addresses,
        u128::from(LINES - 1),
        "the other four thousand nine hundred and ninety-nine are the point"
    );
    assert_eq!(
        imported.tokens,
        u64::from(LINES),
        "a refused expression is still an expression that was read"
    );
    assert_eq!(imported.refusals.len(), 1);

    let refusal = &imported.refusals[0];
    assert_eq!(refusal.origin, ImportOrigin::line(BAD as u64));
    assert_eq!(refusal.token, "10.0.0.300");
    assert!(
        refusal.to_string().starts_with("line 2500:"),
        "a caller has to be able to print what it is disregarding: {refusal}"
    );
}

// ---------------------------------------------------------------------------
// Reading a document as findings
// ---------------------------------------------------------------------------

/// The round trip, held against a report built by hand: the hosts and ports
/// never went through a serializer, so the writer and the reader cannot be
/// wrong together.
#[test]
fn a_report_exported_to_a_file_reads_back_as_the_hosts_and_ports_it_recorded() {
    let original = hand_built_report();
    let restored = read_report(
        "round-trip",
        ReportFormat::Json,
        &exported(&original),
        ReportOptions::new(),
    )
    .expect("this engine reads back what it wrote");

    assert_eq!(restored.host_count(), original.host_count());
    assert_eq!(
        restored.engine_version(),
        "zond-test 1.2.3",
        "the attribution is what produced the findings, not what wrote the file"
    );

    for host in original.hosts() {
        let read_back = restored
            .host(&host.primary_ip())
            .unwrap_or_else(|| panic!("{} is missing", host.primary_ip()));

        assert_eq!(read_back.status(), host.status());
        assert_eq!(read_back.hostname(), host.hostname());
        assert_eq!(read_back.port_count(), host.port_count());

        for port in host.ports() {
            let restored_port = read_back
                .ports()
                .find(|other| {
                    other.number() == port.number() && other.protocol() == port.protocol()
                })
                .unwrap_or_else(|| panic!("{}/{:?} is missing", port.number(), port.protocol()));
            assert_eq!(restored_port.state(), port.state());
        }
    }

    assert!(
        original.hosts().any(|host| host.status() != HostStatus::Up),
        "a fixture whose hosts are all up proves less than it looks"
    );
}

/// The two directions read the same file, and a caller comparing a rescan
/// against the report it came from depends on them agreeing about which
/// endpoints are in it.
#[test]
fn the_same_document_read_for_findings_and_for_targets_names_the_same_endpoints() {
    let document = exported(&hand_built_report());

    let report = read_report(
        "two-directions-report",
        ReportFormat::Json,
        &document,
        ReportOptions::new(),
    )
    .expect("the document reads as a report");

    let imported = read_targets(
        "two-directions-targets",
        ImportFormat::Json,
        &document,
        &options(),
    )
    .expect("the document reads as targets");

    let mut targets = BTreeSet::new();
    for target in imported.map.iter() {
        targets.insert((
            target.ip.to_string(),
            target.port,
            format!("{:?}", target.protocol),
        ));
    }

    let found = endpoints(&report);
    assert!(!found.is_empty(), "a report with no ports proves nothing");
    assert_eq!(
        targets, found,
        "rescanning what a report found has to mean rescanning what it found"
    );
}

#[test]
fn an_nmap_document_on_disk_reads_back_as_the_scan_it_records() {
    let report = read_report(
        "nmap-report",
        ReportFormat::Nmap,
        NMAP_DOCUMENT,
        ReportOptions::new(),
    )
    .expect("the nmap document reads as a report");

    assert_eq!(
        report.engine_version(),
        "nmap 7.94",
        "a report is attributed to whatever produced it"
    );
    assert_eq!(report.host_count(), 2);

    let host = report
        .host(&"10.0.0.1".parse::<IpAddr>().expect("an address"))
        .expect("the host that answered");
    assert_eq!(host.status(), HostStatus::Up);
    assert_eq!(host.port_count(), 2);

    let ssh = host.ports().find(|port| port.number() == 22).expect("22");
    assert_eq!(ssh.state(), PortState::Open);
    assert_eq!(ssh.service().map(|service| service.name()), Some("ssh"));

    let dns = host.ports().find(|port| port.number() == 53).expect("53");
    assert_eq!(dns.protocol(), Protocol::Udp);
}

/// `serde_json` knows which line it stopped on, and the reader keeps it: a
/// twenty thousand line report is not a document anybody bisects by hand.
#[test]
fn a_malformed_report_document_names_the_line_it_stopped_on() {
    let file = concat!(
        "{\n",
        "  \"schema_version\": 1,\n",
        "  \"engine\": {\"name\": \"zond-engine\"},\n",
        "  \"hosts\": [{\"primary_ip\": }]\n",
        "}\n",
    );

    let error = read_report(
        "report-malformed",
        ReportFormat::Json,
        file,
        ReportOptions::new(),
    )
    .expect_err("the fourth line has no value in it");

    match error {
        ImportError::Malformed { format, origin, .. } => {
            assert_eq!(format, "JSON");
            assert_eq!(origin, ImportOrigin::line(4));
        }
        other => panic!("expected a malformed document, got {other:?}"),
    }
}

#[test]
fn an_nmap_report_with_an_address_nmap_could_not_have_written_names_its_line() {
    let file = concat!(
        "<nmaprun version=\"7.94\">\n",
        "<host>\n",
        "<status state=\"up\" reason=\"echo-reply\"/>\n",
        "<address addr=\"10.0.0.999\" addrtype=\"ipv4\"/>\n",
        "</host>\n",
        "</nmaprun>\n",
    );

    let error = read_report(
        "nmap-report-address",
        ReportFormat::Nmap,
        file,
        ReportOptions::new(),
    )
    .expect_err("10.0.0.999 is not an address");

    match error {
        ImportError::Malformed {
            format,
            origin,
            ref message,
        } => {
            assert_eq!(format, "nmap XML");
            assert_eq!(origin, ImportOrigin::line(4));
            assert!(message.contains("10.0.0.999"), "{message}");
        }
        other => panic!("expected a malformed document, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// What a whole-document reader is allowed to spend
//
// A report reader parses the entire document before it returns one, so the
// bound that matters is on what an untrusted file can make the process hold.
// Both readers here go through `ReportFormat::read`, which is the only place a
// caller outside the crate can reach either.
// ---------------------------------------------------------------------------

/// A JSON report naming `count` hosts, written by this engine's own exporter so
/// the document is one the reader is actually meant to accept.
fn json_report_of(count: usize) -> String {
    let hosts: Vec<Host> = (0..count)
        .map(|n| {
            let mut host = Host::new(
                format!("10.{}.{}.{}", n / 65_536, (n / 256) % 256, n % 256)
                    .parse::<IpAddr>()
                    .expect("an address"),
            );
            host.set_status(HostStatus::Up);
            host
        })
        .collect();

    exported(&ScanReport::recorded("zond-test 1.2.3", Vec::new(), hosts))
}

/// An nmap report naming `count` hosts.
fn nmap_report_of(count: usize) -> String {
    let hosts: Vec<String> = (0..count)
        .map(|n| {
            format!(
                concat!(
                    "<host><status state=\"up\" reason=\"echo-reply\"/>",
                    "<address addr=\"10.{}.{}.{}\" addrtype=\"ipv4\"/></host>"
                ),
                n / 65_536,
                (n / 256) % 256,
                n % 256
            )
        })
        .collect();

    format!(
        "<nmaprun scanner=\"nmap\" version=\"7.94\">{}</nmaprun>",
        hosts.join("")
    )
}

/// `max_addresses` is documented as the most addresses one import may name, and
/// a report names one per host it claims was found. Three hosts under a limit
/// of three read; the same document under a limit of two does not.
#[test]
fn a_json_report_naming_more_hosts_than_the_limit_allows_is_refused() {
    let document = json_report_of(3);

    let report = read_report(
        "report-hosts-at-limit",
        ReportFormat::Json,
        &document,
        ReportOptions::new().with_limits(ImportLimits::new().with_max_addresses(3)),
    )
    .expect("three hosts under a limit of three");
    assert_eq!(report.host_count(), 3);

    let error = read_report(
        "report-hosts-past-limit",
        ReportFormat::Json,
        &document,
        ReportOptions::new().with_limits(ImportLimits::new().with_max_addresses(2)),
    )
    .expect_err("three hosts under a limit of two");

    assert!(
        matches!(error, ImportError::TooManyHosts { limit: 2 }),
        "{error:?}"
    );
}

/// The same bound, through the other reader. A limit the caller sets has to
/// mean the same thing whichever document they happen to hand over, since the
/// document is the part they did not write.
#[test]
fn an_nmap_report_naming_more_hosts_than_the_limit_allows_is_refused() {
    let document = nmap_report_of(3);

    let report = read_report(
        "nmap-hosts-at-limit",
        ReportFormat::Nmap,
        &document,
        ReportOptions::new().with_limits(ImportLimits::new().with_max_addresses(3)),
    )
    .expect("three hosts under a limit of three");
    assert_eq!(report.host_count(), 3);

    let error = read_report(
        "nmap-hosts-past-limit",
        ReportFormat::Nmap,
        &document,
        ReportOptions::new().with_limits(ImportLimits::new().with_max_addresses(2)),
    )
    .expect_err("three hosts under a limit of two");

    assert!(
        matches!(error, ImportError::TooManyHosts { limit: 2 }),
        "{error:?}"
    );
}

/// The ceiling counts bytes consumed, not the size of the file, so the value is
/// measured against its own length rather than the trailing whitespace after
/// it. A reader that stops as soon as the value is complete never spends the
/// rest, and a ceiling that refused it would be refusing something nobody read.
#[test]
fn a_json_document_past_the_byte_ceiling_is_refused() {
    let document = json_report_of(64);
    let value = document.trim_end().len() as u64;

    let report = read_report(
        "report-bytes-at-ceiling",
        ReportFormat::Json,
        &document,
        ReportOptions::new().with_max_document_bytes(value),
    )
    .expect("a value exactly as long as the ceiling allows");
    assert_eq!(report.host_count(), 64);

    let error = read_report(
        "report-bytes-past-ceiling",
        ReportFormat::Json,
        &document,
        ReportOptions::new().with_max_document_bytes(value - 1),
    )
    .expect_err("one byte past the ceiling");

    match error {
        ImportError::DocumentTooLarge { limit } => assert_eq!(limit, value - 1),
        other => panic!("expected the document ceiling, got {other:?}"),
    }
}

/// The ceiling lives at the dispatch rather than inside a reader, so a format
/// added later inherits it. Both formats this build reads are held to it.
#[test]
fn an_nmap_document_past_the_byte_ceiling_is_refused() {
    let document = nmap_report_of(64);
    let length = document.len() as u64;

    let error = read_report(
        "nmap-bytes-past-ceiling",
        ReportFormat::Nmap,
        &document,
        ReportOptions::new().with_max_document_bytes(length / 2),
    )
    .expect_err("half a document is not a document");

    assert!(
        matches!(error, ImportError::DocumentTooLarge { .. }),
        "{error:?}"
    );
}

/// The defaults refuse nothing an honest report does, which is the property
/// that makes the ceiling safe to have on by default.
#[test]
fn the_default_ceiling_reads_a_report_of_a_thousand_hosts() {
    let report = read_report(
        "report-default-ceiling",
        ReportFormat::Json,
        &json_report_of(1_000),
        ReportOptions::new(),
    )
    .expect("a thousand hosts is an ordinary engagement");

    assert_eq!(report.host_count(), 1_000);
}
