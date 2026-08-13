// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # CSV export
//!
//! One row per host and port, for the people who are going to open this in a
//! spreadsheet.
//!
//! ## A deliberately lossy view
//!
//! A scan report is a tree and a CSV is a table, so this format throws things
//! away: the phases, the settings, the probe instrumentation, the per-script
//! output, the full address list of a multi-homed host. That is not a gap to be
//! filled by adding columns until the file is unreadable - it is what makes the
//! format worth having. A compliance reviewer wants to sort by port and filter
//! by service, and [`json`](super::json) is where the record of the scan lives
//! when a question needs the whole answer.
//!
//! What survives is one row per *finding*: a host paired with a port. A host
//! with no ports still gets a row with the port columns empty, because a
//! discovery sweep otherwise exports an empty file.
//!
//! ## Formula injection
//!
//! A scanner writes attacker-controlled text - hostnames, service banners,
//! certificate subjects - and a spreadsheet treats a cell beginning with `=`,
//! `+`, `-`, `@`, a tab or a carriage return as a formula to execute. A device
//! named `=cmd|'/c calc'!A1` is a working attack on whoever opens the report.
//!
//! Every field is therefore checked and, where it starts with one of those,
//! prefixed with an apostrophe, which is the escape spreadsheets themselves use
//! for "this is text". It is unconditional. There is no option to turn it off,
//! because the person who would turn it off is not the person who opens the
//! file, and a consumer who needs the bytes exactly as the scanner saw them has
//! JSON.
//!
//! No numeric field the engine emits is ever negative, so the guard never fires
//! on a legitimate number.
//!
//! ## Dialect
//!
//! RFC 4180 quoting - fields containing a delimiter, a quote or a line break are
//! quoted, and quotes inside them are doubled - with LF line endings rather than
//! the RFC's CRLF. Every parser and spreadsheet in use accepts LF, and CRLF
//! leaves a stray carriage return in every last column for the Unix tools that
//! are the other half of this format's audience.
//!
//! Output is UTF-8 with no byte-order mark. Excel on Windows needs one to read
//! UTF-8 correctly, and a BOM breaks naive parsers everywhere else, so it is
//! opt-in through [`CsvExporter::with_excel_bom`] rather than a default that is
//! wrong for one audience or the other.

use std::io::Write;

use crate::export::schema::{
    host_status_name, network_role_name, port_state_name, protocol_name, scan_response_name,
};
use crate::export::time::rfc3339;
use crate::export::{ExportError, ExportOptions, Exporter};
use crate::format::csv::{COLUMNS, PORT_COLUMNS};
use crate::model::host::Host;
use crate::model::port::Port;
use crate::scanner::report::ScanReport;

/// Characters that make a spreadsheet read a cell as a formula.
const FORMULA_LEADERS: [char; 5] = ['=', '+', '-', '@', '\t'];

/// The byte-order mark Excel on Windows wants in front of UTF-8.
const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// Writes a report as one row per host and port.
///
/// ```no_run
/// use std::fs::File;
/// use zond_engine::scanner::report::ScanReport;
/// use zond_engine::export::{CsvExporter, ExportOptions, Exporter};
///
/// # fn example(report: &ScanReport) -> Result<(), Box<dyn std::error::Error>> {
/// let mut file = File::create("scan.csv")?;
/// CsvExporter::new(ExportOptions::new()).export(report, &mut file)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct CsvExporter {
    options: ExportOptions,
    excel_bom: bool,
}

impl CsvExporter {
    /// An exporter under the given options.
    pub fn new(options: ExportOptions) -> Self {
        Self {
            options,
            excel_bom: false,
        }
    }

    /// Prefixes the output with a UTF-8 byte-order mark.
    ///
    /// For a file that will be opened by Excel on Windows, which otherwise
    /// reads UTF-8 as the system code page and mangles every non-ASCII vendor
    /// name. Off by default because the same mark makes the first column header
    /// unrecognisable to a parser that does not expect it.
    pub fn with_excel_bom(mut self) -> Self {
        self.excel_bom = true;
        self
    }

    /// The options in force.
    pub fn options(&self) -> &ExportOptions {
        &self.options
    }
}

impl Exporter for CsvExporter {
    fn export(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), ExportError> {
        if self.excel_bom {
            out.write_all(UTF8_BOM)?;
        }

        let mut row = Row::new();
        for column in COLUMNS {
            row.push(column);
        }
        row.finish(out)?;

        for host in report.hosts() {
            let host_columns = HostColumns::new(host, &self.options);

            if host.port_count() == 0 {
                let mut row = Row::new();
                host_columns.write(&mut row);
                for _ in 0..PORT_COLUMNS {
                    row.push("");
                }
                row.finish(out)?;
                continue;
            }

            for port in host.ports() {
                let mut row = Row::new();
                host_columns.write(&mut row);
                write_port(&mut row, port, &self.options);
                row.finish(out)?;
            }
        }

        Ok(())
    }
}

/// The host half of a row, rendered once and reused for each of its ports.
///
/// A host with 900 open ports would otherwise re-render its address list, its
/// timestamps and its OS string 900 times.
struct HostColumns {
    ip: String,
    hostname: String,
    status: &'static str,
    alive: &'static str,
    ips: String,
    mac: String,
    mac_vendor: String,
    os: String,
    os_accuracy: String,
    roles: String,
    rtt_median_us: String,
    ttl: String,
    first_seen: String,
    last_seen: String,
}

impl HostColumns {
    fn new(host: &Host, options: &ExportOptions) -> Self {
        let redaction = options.redaction;

        let mut roles: Vec<&str> = host
            .network_roles()
            .iter()
            .copied()
            .map(network_role_name)
            .collect();
        roles.sort_unstable();

        Self {
            ip: host.primary_ip().to_string(),
            hostname: host
                .hostname()
                .map(|name| redaction.hostname(name).into_owned())
                .unwrap_or_default(),
            status: host_status_name(host.status()),
            alive: bool_cell(host.is_alive()),
            ips: join(host.ips().iter().map(|ip| ip.to_string())),
            mac: host
                .mac()
                .map(|mac| redaction.mac(&mac))
                .unwrap_or_default(),
            mac_vendor: host.vendor().unwrap_or_default().to_string(),
            os: host.os().map(|os| os.name.to_string()).unwrap_or_default(),
            os_accuracy: host
                .os()
                .map(|os| os.accuracy.to_string())
                .unwrap_or_default(),
            roles: join(roles.into_iter().map(str::to_string)),
            rtt_median_us: host
                .median_rtt()
                .map(|rtt| rtt.as_micros().to_string())
                .unwrap_or_default(),
            ttl: host
                .telemetry()
                .ttl
                .map(|ttl| ttl.to_string())
                .unwrap_or_default(),
            first_seen: rfc3339(host.first_seen()),
            last_seen: rfc3339(host.last_seen()),
        }
    }

    fn write(&self, row: &mut Row) {
        row.push(&self.ip);
        row.push(&self.hostname);
        row.push(self.status);
        row.push(self.alive);
        row.push(&self.ips);
        row.push(&self.mac);
        row.push(&self.mac_vendor);
        row.push(&self.os);
        row.push(&self.os_accuracy);
        row.push(&self.roles);
        row.push(&self.rtt_median_us);
        row.push(&self.ttl);
        row.push(&self.first_seen);
        row.push(&self.last_seen);
    }
}

/// Appends the port half of a row. Must push exactly [`PORT_COLUMNS`] fields.
fn write_port(row: &mut Row, port: &Port, options: &ExportOptions) {
    let service = port.service();
    let certificate = port.security().and_then(|security| security.certificate());

    row.push(port.number().to_string());
    row.push(protocol_name(port.protocol()));
    row.push(port_state_name(port.state()));
    row.push(service.map(|service| service.name()).unwrap_or_default());
    row.push(
        service
            .and_then(|service| service.product())
            .unwrap_or_default(),
    );
    row.push(
        service
            .and_then(|service| service.version())
            .unwrap_or_default(),
    );
    row.push(
        service
            .map(|service| service.confidence().to_string())
            .unwrap_or_default(),
    );
    row.push(
        port.discovery()
            .map(|discovery| scan_response_name(discovery.reason()).into_owned())
            .unwrap_or_default(),
    );
    row.push(
        port.security()
            .and_then(|security| security.tls_version())
            .unwrap_or_default(),
    );
    row.push(
        certificate
            .map(|cert| options.redaction.hostname(cert.common_name()).into_owned())
            .unwrap_or_default(),
    );
    row.push(
        certificate
            .map(|cert| rfc3339(cert.validity_end()))
            .unwrap_or_default(),
    );
}

/// Renders `true` and `false` the way a spreadsheet expects to read them.
fn bool_cell(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

/// Joins several values into one cell, space separated.
///
/// A space rather than a comma or a semicolon: a comma would need the cell
/// quoted for no gain, and a semicolon is the field delimiter in the locales
/// that use a comma for the decimal point, so it reads as a broken row there.
fn join(values: impl Iterator<Item = String>) -> String {
    values.collect::<Vec<_>>().join(" ")
}

/// One row under construction.
///
/// Buffers the row rather than writing field by field so that a row either
/// reaches the destination whole or not at all - a half-written row followed by
/// a line break parses as a complete row with missing columns.
struct Row {
    text: String,
    fields: usize,
}

impl Row {
    fn new() -> Self {
        Self {
            text: String::new(),
            fields: 0,
        }
    }

    /// Appends one field, quoted and escaped as needed.
    fn push(&mut self, field: impl AsRef<str>) {
        if self.fields > 0 {
            self.text.push(',');
        }
        self.fields += 1;

        let field = field.as_ref();
        let needs_formula_guard = field.starts_with(FORMULA_LEADERS) || field.starts_with('\r');
        let needs_quotes = needs_formula_guard
            || field.contains([',', '"', '\n', '\r'])
            || field.starts_with(' ')
            || field.ends_with(' ');

        if !needs_quotes {
            self.text.push_str(field);
            return;
        }

        self.text.push('"');
        if needs_formula_guard {
            self.text.push('\'');
        }
        for character in field.chars() {
            if character == '"' {
                self.text.push('"');
            }
            self.text.push(character);
        }
        self.text.push('"');
    }

    /// Terminates the row and writes it out.
    fn finish(mut self, out: &mut dyn Write) -> Result<(), ExportError> {
        debug_assert_eq!(
            self.fields,
            COLUMNS.len(),
            "every row must have one field per column"
        );

        self.text.push('\n');
        out.write_all(self.text.as_bytes())?;
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
    use crate::export::{Redaction, fixture};

    /// Splits a rendered row into its fields, undoing the quoting.
    ///
    /// Hand-written rather than borrowed from a parser crate on purpose: a
    /// round trip through the same author's assumptions proves nothing, so this
    /// implements what RFC 4180 says a reader does and lets the writer be wrong.
    fn parse_row(line: &str) -> Vec<String> {
        let mut fields = Vec::new();
        let mut field = String::new();
        let mut quoted = false;
        let mut characters = line.chars().peekable();

        while let Some(character) = characters.next() {
            match character {
                '"' if !quoted && field.is_empty() => quoted = true,
                '"' if quoted => {
                    if characters.peek() == Some(&'"') {
                        characters.next();
                        field.push('"');
                    } else {
                        quoted = false;
                    }
                }
                ',' if !quoted => fields.push(std::mem::take(&mut field)),
                other => field.push(other),
            }
        }
        fields.push(field);
        fields
    }

    fn rows(exporter: &CsvExporter) -> Vec<Vec<String>> {
        String::from_utf8(bytes(exporter, &fixture::report()))
            .expect("utf-8")
            .lines()
            .map(parse_row)
            .collect()
    }

    /// Exports one report, so a test comparing two exports compares the same
    /// scan rather than two fixtures built a few microseconds apart.
    fn bytes(exporter: &CsvExporter, report: &crate::scanner::report::ScanReport) -> Vec<u8> {
        let mut bytes = Vec::new();
        exporter
            .export(report, &mut bytes)
            .expect("the export succeeds");
        bytes
    }

    fn column(row: &[String], name: &str) -> String {
        let index = COLUMNS
            .iter()
            .position(|column| *column == name)
            .expect("a known column");
        row[index].clone()
    }

    /// A header, then one row per host and port. The fixture's three hosts have
    /// three ports, one port and none.
    #[test]
    fn every_host_and_port_pairing_gets_a_row() {
        let rows = rows(&CsvExporter::new(ExportOptions::new()));

        assert_eq!(rows[0], COLUMNS.to_vec());
        assert_eq!(rows.len(), 1 + 3 + 1 + 1);

        for row in &rows {
            assert_eq!(
                row.len(),
                COLUMNS.len(),
                "a row with the wrong column count shifts every value after it"
            );
        }

        assert_eq!(column(&rows[1], "ip"), "192.168.0.1");
        assert_eq!(column(&rows[1], "port"), "22");
        assert_eq!(column(&rows[2], "port"), "80");
        assert_eq!(column(&rows[3], "port"), "443");
        assert_eq!(column(&rows[4], "ip"), "192.168.0.2");
    }

    /// A discovery sweep finds hosts and no ports. If a port-less host had no
    /// row, that whole scan would export as a header and nothing else.
    #[test]
    fn a_host_with_no_ports_still_gets_a_row() {
        let rows = rows(&CsvExporter::new(ExportOptions::new()));
        let bare = rows.last().expect("a final row");

        assert_eq!(column(bare, "ip"), "192.168.0.9");
        assert_eq!(column(bare, "status"), "down");
        assert_eq!(column(bare, "port"), "");
        assert_eq!(column(bare, "state"), "");
        assert_eq!(column(bare, "protocol"), "");
    }

    /// The findings a spreadsheet user is actually there for.
    #[test]
    fn a_row_carries_the_host_and_the_port_together() {
        let rows = rows(&CsvExporter::new(ExportOptions::new()));
        let ssh = &rows[1];

        assert_eq!(column(ssh, "hostname"), "router.local");
        assert_eq!(column(ssh, "mac_vendor"), "Raspberry Pi Trading Ltd");
        assert_eq!(column(ssh, "os"), "Linux");
        assert_eq!(column(ssh, "os_accuracy"), "95");
        assert_eq!(column(ssh, "roles"), "gateway");
        assert_eq!(column(ssh, "rtt_median_us"), "1800");
        assert_eq!(column(ssh, "service"), "ssh");
        assert_eq!(column(ssh, "service_product"), "OpenSSH");
        assert_eq!(column(ssh, "service_version"), "8.9p1");
        assert_eq!(column(ssh, "discovery_reason"), "tcp_syn_ack");

        let https = &rows[3];
        assert_eq!(column(https, "tls_version"), "TLSv1.3");
        assert_eq!(column(https, "cert_common_name"), "router.local");
        assert_eq!(
            column(https, "cert_not_after"),
            "2027-01-01T00:00:00.000000Z"
        );
    }

    #[test]
    fn redaction_applies_to_every_column_that_names_something() {
        let rows = rows(&CsvExporter::new(
            ExportOptions::new().with_redaction(Redaction::Standard),
        ));

        assert_eq!(column(&rows[1], "hostname"), "roXXXXXal");
        assert_eq!(column(&rows[1], "mac"), "2c:cf:67:XX:XX:XX");
        assert_eq!(column(&rows[3], "cert_common_name"), "roXXXXXal");
        // The vendor comes from the OUI, which masking preserves.
        assert_eq!(column(&rows[1], "mac_vendor"), "Raspberry Pi Trading Ltd");
    }

    /// A device name is attacker-controlled text, and a spreadsheet executes a
    /// cell that starts with `=`. This is the one thing in this module that is
    /// a security control rather than a formatting choice.
    #[test]
    fn a_cell_that_would_execute_is_neutralised() {
        let mut row = Row::new();
        row.push("=cmd|'/c calc'!A1");
        row.push("+1+1");
        row.push("-2+3");
        row.push("@SUM(A1)");
        row.push("\tstarts-with-tab");
        row.push("harmless=inside");

        assert_eq!(
            row.text,
            "\"'=cmd|'/c calc'!A1\",\"'+1+1\",\"'-2+3\",\"'@SUM(A1)\",\"'\tstarts-with-tab\",harmless=inside"
        );

        // Parsed back, the guard is visible as data rather than executed.
        for field in parse_row(&row.text).iter().take(5) {
            assert!(field.starts_with('\''), "{field} escaped the guard");
        }
    }

    /// The engine emits no negative numbers, so the guard must not be firing on
    /// ordinary values and cluttering every numeric column.
    #[test]
    fn ordinary_values_are_left_alone() {
        let rows = rows(&CsvExporter::new(ExportOptions::new()));

        for row in rows.iter().skip(1) {
            for field in row {
                assert!(
                    !field.starts_with('\''),
                    "a real scan value tripped the formula guard: {field}"
                );
            }
        }
    }

    /// RFC 4180 quoting, exercised against the characters that break a naive
    /// writer.
    #[test]
    fn separators_and_quotes_survive_a_round_trip() {
        let awkward = [
            "plain",
            "has,comma",
            "has\"quote",
            "has\nnewline",
            "has\r\ncrlf",
            " leading space",
            "trailing space ",
            "",
        ];

        let mut row = Row::new();
        for field in awkward {
            row.push(field);
        }

        assert_eq!(parse_row(&row.text), awkward.to_vec());
    }

    /// The mark is opt-in, and when asked for it goes in front of everything.
    #[test]
    fn the_excel_byte_order_mark_is_opt_in() {
        let report = fixture::report();

        let without = bytes(&CsvExporter::new(ExportOptions::new()), &report);
        assert!(without.starts_with(b"ip,"));

        let with = bytes(
            &CsvExporter::new(ExportOptions::new()).with_excel_bom(),
            &report,
        );
        assert!(with.starts_with(UTF8_BOM));
        assert_eq!(&with[UTF8_BOM.len()..], &without[..]);
    }

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

        let error = CsvExporter::new(ExportOptions::new())
            .export(&fixture::report(), &mut Full)
            .expect_err("a full disk fails the export");

        assert!(matches!(error, ExportError::Io(_)), "got {error:?}");
    }
}
