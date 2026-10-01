// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # CSV import
//!
//! A table with a column of addresses in it, typically one of two kinds:
//!
//! - **A report this engine wrote.** The exporter emits one row per host and
//!   port under the header in [`crate::format::csv`], so reading it back
//!   rescans what a previous scan found, on the ports it found open.
//! - **A spreadsheet somebody else wrote**, such as an asset inventory, a
//!   client's scope document or a CMDB export.
//!
//! ## Which column holds the addresses
//!
//! The first record is a header if any of its fields names a column this
//! importer understands. Otherwise there is no header, and the first field of
//! every record is the address.
//!
//! Under a header, `ip`, `ipaddress`, `address`, `host` and `target` are read as
//! addresses, in that order of preference, along with `port` and `protocol`
//! where present. Names are compared case-insensitively and ignoring anything
//! that is not a letter or a digit, so `IP Address` and `ip_address` reach
//! `ipaddress`. A caller can name the columns with
//! [`with_address_column`](CsvImporter::with_address_column),
//! [`with_port_column`](CsvImporter::with_port_column) and
//! [`with_protocol_column`](CsvImporter::with_protocol_column), and state that
//! an unrecognisable first row is a header with [`CsvImporter::with_header`].
//!
//! The values are never used to guess. A file whose first row is
//! `Server,Location` has no recognised name, so it has no header, and `Server`
//! is refused as a target on line 1. Guessing could silently read the wrong
//! column.
//!
//! ## Reading it back the way it was written
//!
//! The reverse of the CSV exporter: RFC 4180 quoting with doubled quotes inside
//! quoted fields, both line endings, a byte-order mark skipped if Excel left
//! one, and the exporter's apostrophe in front of a field beginning with a
//! formula character taken back off.
//!
//! A record ends at a line break outside a quoted field, so a field may span
//! lines and [`ImportLimits::max_line_bytes`] bounds the whole record.
//!
//! ## Rows
//!
//! Every row is a target; the `state` column is not used to filter.
//!
//! A row whose address column is empty or missing is refused under the
//! caller's [`OnRefusal`](crate::import::OnRefusal) policy, and the refusal
//! names the line. A row blank all the way across is skipped.

use std::io::BufRead;

use crate::format::UTF8_BOM;
use crate::format::csv::FORMULA_LEADERS;
use crate::import::{ImportError, ImportLimits, ImportOrigin, Importer, TargetSink};
use crate::model::port::Protocol;

/// The format's name in errors.
const FORMAT: &str = "CSV";

/// Header names read as the address column, in the order they are preferred.
///
/// `ip` leads because that is what this engine's reports call it. `hostname`
/// is absent because in a report it sits beside `ip`; a file of hostnames only
/// needs its column named.
const ADDRESS_NAMES: [&str; 5] = ["ip", "ipaddress", "address", "host", "target"];

/// Header names read as the port column.
const PORT_NAMES: [&str; 1] = ["port"];

/// Header names read as the transport column.
const PROTOCOL_NAMES: [&str; 2] = ["protocol", "proto"];

/// Which column of a record to read.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsvColumn {
    /// By header name, compared case-insensitively and ignoring anything that
    /// is not a letter or a digit, so `IP Address` and `ip_address` are the
    /// same column.
    ///
    /// Naming a column says the file has a header, so the first record is one
    /// whether or not this importer recognises anything in it. A file with no
    /// such column is an error.
    Named(String),
    /// By 0-based position, for a file with no header or an unrecognisable one.
    Index(usize),
}

/// Reads target expressions out of a table.
///
/// Holds one record at a time, so a file of any size costs the same memory.
#[must_use]
#[derive(Debug, Clone)]
pub struct CsvImporter {
    limits: ImportLimits,
    addresses: Option<CsvColumn>,
    ports: Option<CsvColumn>,
    protocols: Option<CsvColumn>,
    has_header: Option<bool>,
}

impl CsvImporter {
    /// A reader bounded by `limits`, finding its columns by the rule above.
    pub fn new(limits: ImportLimits) -> Self {
        Self {
            limits,
            addresses: None,
            ports: None,
            protocols: None,
            has_header: None,
        }
    }

    /// Reads addresses from a column of the caller's choosing.
    pub fn with_address_column(mut self, column: CsvColumn) -> Self {
        self.addresses = Some(column);
        self
    }

    /// Reads per-row ports from a column of the caller's choosing.
    ///
    /// Rows whose port field is empty take the caller's default ports, so a
    /// report of a discovery sweep, with every port column blank, reads back as
    /// a plain list of hosts.
    pub fn with_port_column(mut self, column: CsvColumn) -> Self {
        self.ports = Some(column);
        self
    }

    /// Reads the transport from a column of the caller's choosing.
    ///
    /// The automatic rule looks for `protocol` and `proto`; without this, a
    /// spreadsheet calling the column something else has its UDP rows read as
    /// TCP. A row whose transport field is empty or names anything but UDP takes
    /// the TCP half of the port set.
    pub fn with_protocol_column(mut self, column: CsvColumn) -> Self {
        self.protocols = Some(column);
        self
    }

    /// States whether the first record is a header.
    ///
    /// Needed for a file whose header names none of the columns this importer
    /// knows, read by position. Without it the header is read as a target and
    /// refused on line 1.
    pub fn with_header(mut self, has_header: bool) -> Self {
        self.has_header = Some(has_header);
        self
    }
}

impl Default for CsvImporter {
    fn default() -> Self {
        Self::new(ImportLimits::default())
    }
}

impl Importer for CsvImporter {
    fn import(
        &self,
        input: &mut dyn BufRead,
        sink: &mut dyn TargetSink,
    ) -> Result<(), ImportError> {
        crate::import::bounded::within(input, self.limits.max_document_bytes, |input| {
            let mut record = Record::new();
            let mut line = 1u64;
            let mut layout: Option<Layout> = None;
            let mut token = String::new();
            let mut ports = String::new();

            while let Some(origin) = record.read(input, self.limits.max_line_bytes, &mut line)? {
                if record.is_blank() {
                    continue;
                }

                let layout = match &layout {
                    Some(resolved) => resolved,
                    None => {
                        let resolved = Layout::resolve(&record, self, origin)?;
                        let is_header = resolved.is_header;
                        layout = Some(resolved);
                        if is_header {
                            continue;
                        }
                        layout.as_ref().expect("just set")
                    }
                };

                // An empty address is handed on so the grammar refuses it and the
                // caller's `OnRefusal` decides. Fully blank rows were skipped above.
                let address = record.field(layout.addresses, origin)?.unwrap_or("");

                let port = match layout.ports {
                    Some(column) => record.field(column, origin)?.filter(|s| !s.is_empty()),
                    None => None,
                };
                let protocol = match layout.protocols {
                    Some(column) => record.field(column, origin)?,
                    None => None,
                };

                build_token(&mut token, &mut ports, address, port, protocol);
                sink.accept(&token, origin)?;
            }

            Ok(())
        })
    }
}

/// Which column holds what, once the header has been read or ruled out.
#[derive(Debug)]
struct Layout {
    addresses: usize,
    ports: Option<usize>,
    protocols: Option<usize>,
    /// Whether the record this was resolved from was a header.
    is_header: bool,
}

impl Layout {
    /// Works out the columns from the first record.
    fn resolve(
        record: &Record,
        importer: &CsvImporter,
        origin: ImportOrigin,
    ) -> Result<Self, ImportError> {
        let names: Vec<String> = (0..record.count)
            .map(|index| match record.field(index, origin) {
                Ok(Some(field)) => normalize(field),
                // Not text, so not a name. If the record is data it is refused
                // later.
                _ => String::new(),
            })
            .collect();

        let recognised = |name: &String| {
            ADDRESS_NAMES.contains(&name.as_str())
                || PORT_NAMES.contains(&name.as_str())
                || PROTOCOL_NAMES.contains(&name.as_str())
        };
        // A column named by name implies a header.
        let named_by_name = matches!(importer.addresses, Some(CsvColumn::Named(_)))
            || matches!(importer.ports, Some(CsvColumn::Named(_)))
            || matches!(importer.protocols, Some(CsvColumn::Named(_)));
        let is_header = importer
            .has_header
            .unwrap_or_else(|| named_by_name || names.iter().any(recognised));

        let find = |accepted: &[&str]| -> Option<usize> {
            accepted
                .iter()
                .find_map(|wanted| names.iter().position(|name| name == wanted))
        };

        let resolve_column = |column: &CsvColumn| -> Result<usize, ImportError> {
            match column {
                CsvColumn::Index(index) => Ok(*index),
                CsvColumn::Named(wanted) => {
                    let wanted = normalize(wanted);
                    names
                        .iter()
                        .position(|name| *name == wanted)
                        .ok_or_else(|| ImportError::Malformed {
                            format: FORMAT,
                            origin,
                            message: format!("no column named '{wanted}' in the header"),
                        })
                }
            }
        };

        let addresses = match &importer.addresses {
            Some(column) => resolve_column(column)?,
            None => match find(&ADDRESS_NAMES) {
                Some(index) => index,
                // A recognised header with no address column: reading column 0
                // would be a silent guess. A caller who stated the header has
                // said only that row one is not data, so column 0 applies there.
                None if is_header && importer.has_header.is_none() => {
                    return Err(ImportError::Malformed {
                        format: FORMAT,
                        origin,
                        message: "a header row, but no column in it holds addresses".to_string(),
                    });
                }
                None => 0,
            },
        };

        let ports = match &importer.ports {
            Some(column) => Some(resolve_column(column)?),
            None if is_header => find(&PORT_NAMES),
            None => None,
        };

        let protocols = match &importer.protocols {
            Some(column) => Some(resolve_column(column)?),
            None if is_header => find(&PROTOCOL_NAMES),
            None => None,
        };

        Ok(Self {
            addresses,
            ports,
            protocols,
            is_header,
        })
    }
}

/// Folds a header name to its comparable form: lower case, letters and digits
/// only. `IP Address`, `ip_address` and `IPAddress` are one column.
fn normalize(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Assembles the target expression a row describes, through
/// [`expression`](crate::import::expression), which owns the bracketing rule.
///
/// A transport name this build knows takes that transport's prefix, and
/// anything else is read as TCP, the port grammar's meaning of an unprefixed
/// port. More lenient than the JSON and nmap readers because a hand-typed
/// spreadsheet has no schema behind it.
fn build_token(
    token: &mut String,
    ports: &mut String,
    address: &str,
    port: Option<&str>,
    protocol: Option<&str>,
) {
    ports.clear();

    if let Some(port) = port {
        let protocol = protocol
            .map(str::to_ascii_lowercase)
            .and_then(|name| crate::record::wire::protocol(&name))
            .unwrap_or(Protocol::Tcp);
        ports.push_str(protocol.spec_prefix());
        ports.push_str(port);
    }

    crate::import::expression(token, address, ports);
}

/// Takes off the apostrophe the exporter puts in front of a field starting with
/// a formula character. Any other leading apostrophe stays.
fn unescape(field: &str) -> &str {
    match field.strip_prefix('\'') {
        Some(rest) if rest.starts_with(FORMULA_LEADERS) => rest,
        _ => field,
    }
}

/// One record's fields, with the buffers reused across records.
#[derive(Debug)]
struct Record {
    fields: Vec<Vec<u8>>,
    count: usize,
    /// Whether anything has been read yet, so only the first record has its
    /// byte-order mark stripped.
    started: bool,
}

impl Record {
    fn new() -> Self {
        Self {
            fields: Vec::new(),
            count: 0,
            started: false,
        }
    }

    /// Whether every field is empty or whitespace.
    fn is_blank(&self) -> bool {
        self.fields[..self.count]
            .iter()
            .all(|field| field.trim_ascii().is_empty())
    }

    /// One field as text, or `None` if the record is shorter than that.
    ///
    /// Decoded on demand, so a wide report costs only the fields a target is
    /// built from.
    fn field(&self, column: usize, origin: ImportOrigin) -> Result<Option<&str>, ImportError> {
        let Some(field) = self.fields[..self.count].get(column) else {
            return Ok(None);
        };
        let text = std::str::from_utf8(field)
            .map_err(|_| ImportError::InvalidUtf8 { origin })?
            .trim();
        Ok(Some(unescape(text)))
    }

    /// Reads the next record, returning where it started or `None` at the end
    /// of the input.
    ///
    /// A record can span lines, so `line` is advanced for each line break read.
    fn read(
        &mut self,
        input: &mut dyn BufRead,
        max_bytes: usize,
        line: &mut u64,
    ) -> Result<Option<ImportOrigin>, ImportError> {
        let origin = ImportOrigin::line(*line);
        let first_record = !self.started;
        let fields = &mut self.fields;

        let mut count = 0usize;
        let mut in_quotes = false;
        let mut quote_pending = false;
        let mut at_field_start = true;
        // A carriage return is held, since only one immediately before a line
        // break is a terminator. Anywhere else it is data.
        let mut pending_cr = false;
        let mut total = 0usize;
        let mut saw_any = false;
        let mut finished = false;

        begin_field(fields, count);

        while !finished {
            let taken = {
                let buffered = input.fill_buf()?;
                if buffered.is_empty() {
                    break;
                }

                let mut taken = 0usize;
                for &byte in buffered {
                    taken += 1;
                    total += 1;
                    if total > max_bytes {
                        return Err(ImportError::LineTooLong {
                            origin,
                            limit: max_bytes,
                        });
                    }
                    saw_any = true;

                    if quote_pending {
                        quote_pending = false;
                        if byte == b'"' {
                            // A doubled quote inside a quoted field is one quote.
                            fields[count].push(b'"');
                            continue;
                        }
                        in_quotes = false;
                    }

                    if in_quotes {
                        if byte == b'\n' {
                            *line += 1;
                        }
                        if byte == b'"' {
                            quote_pending = true;
                        } else {
                            fields[count].push(byte);
                        }
                        continue;
                    }

                    if byte == b'\r' {
                        // Held until the next byte says whether it was a line
                        // ending or data.
                        if pending_cr {
                            fields[count].push(b'\r');
                        }
                        pending_cr = true;
                        continue;
                    }
                    if pending_cr {
                        pending_cr = false;
                        if byte != b'\n' {
                            fields[count].push(b'\r');
                            at_field_start = false;
                        }
                    }

                    match byte {
                        // A quote opens a field only at its start; elsewhere
                        // it is a literal (RFC 4180).
                        b'"' if at_field_start => {
                            in_quotes = true;
                            at_field_start = false;
                        }
                        b',' => {
                            count += 1;
                            begin_field(fields, count);
                            at_field_start = true;
                        }
                        b'\n' => {
                            *line += 1;
                            count += 1;
                            finished = true;
                            break;
                        }
                        other => {
                            fields[count].push(other);
                            at_field_start = false;
                        }
                    }
                }

                taken
            };

            input.consume(taken);
        }

        if !finished {
            if !saw_any {
                return Ok(None);
            }
            // A final record with no line break after it is ordinary.
            if pending_cr {
                fields[count].push(b'\r');
            }
            count += 1;
        }

        // A byte-order mark is valid only at the start of the file.
        if first_record && fields[0].starts_with(&UTF8_BOM) {
            fields[0].drain(..UTF8_BOM.len());
        }

        self.count = count;
        self.started = true;
        Ok(Some(origin))
    }
}

/// Makes `fields[index]` exist and be empty, reusing the allocation from the
/// previous record.
fn begin_field(fields: &mut Vec<Vec<u8>>, index: usize) {
    match fields.get_mut(index) {
        Some(field) => field.clear(),
        None => fields.push(Vec::new()),
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
    use crate::import::{ImportFormat, ImportOptions, ImportOrigin, Imported, TargetCollector};
    use crate::model::port::PortSet;
    use std::io::Cursor;

    fn options() -> ImportOptions<'static> {
        ImportOptions::new(PortSet::try_from("80").unwrap())
    }

    fn read(input: &str) -> Imported {
        ImportFormat::Csv
            .read(&mut Cursor::new(input), &options())
            .expect("the table imports")
    }

    fn read_with(input: &str, importer: &CsvImporter) -> Result<Imported, ImportError> {
        let mut collector = TargetCollector::new(options());
        importer.import(&mut Cursor::new(input), &mut collector)?;
        Ok(collector.finish())
    }

    /// A row whose address column is empty or missing is refused, so the
    /// caller learns what it lost.
    #[test]
    fn a_row_with_no_address_is_refused_rather_than_dropped() {
        let file = "ip,port\n198.51.100.1,80\n\n,443\n198.51.100.2,80\n";

        let aborted = ImportFormat::Csv
            .read(&mut Cursor::new(file), &options())
            .expect_err("the third row names no address");
        match aborted {
            ImportError::Target { origin, .. } => {
                assert_eq!(origin, ImportOrigin::line(4), "the blank row is line 3");
            }
            other => panic!("expected a refused target, got {other:?}"),
        }

        let collected = ImportFormat::Csv
            .read(
                &mut Cursor::new(file),
                &options().with_refusal_policy(crate::import::OnRefusal::Collect),
            )
            .expect("collecting carries on past it");

        assert_eq!(collected.addresses, 2, "both good rows survived");
        assert_eq!(collected.refusals.len(), 1, "and the bad one came back");
        assert_eq!(
            collected.tokens, 3,
            "a refused row is still a row that was read"
        );
    }

    /// A row blank all the way across is skipped without a refusal.
    #[test]
    fn a_blank_row_is_still_skipped_without_a_word() {
        let imported = read("ip,port\n198.51.100.1,80\n\n   \n198.51.100.2,80\n");

        assert_eq!(imported.addresses, 2);
        assert_eq!(imported.refusals.len(), 0);
        assert_eq!(imported.tokens, 2);
    }

    /// A spreadsheet whose transport column has an unknown name would
    /// otherwise read every UDP row as TCP.
    #[test]
    fn a_caller_can_name_the_transport_column() {
        let file = "Node,Service,Transport\n198.51.100.1,53,UDP\n198.51.100.2,80,tcp\n";

        let importer = CsvImporter::new(ImportLimits::default())
            .with_address_column(CsvColumn::Named("Node".to_string()))
            .with_port_column(CsvColumn::Named("Service".to_string()))
            .with_protocol_column(CsvColumn::Named("Transport".to_string()));

        let imported = read_with(file, &importer).expect("the table imports");

        assert_eq!(imported.addresses, 2);
        assert!(
            imported
                .map
                .units
                .iter()
                .any(|unit| unit.ports().has_udp(53)),
            "the named transport column has to decide which half of the set a port lands in"
        );
        assert!(
            imported
                .map
                .units
                .iter()
                .any(|unit| unit.ports().has_tcp(80))
        );
    }

    /// A report this engine wrote reads back as the targets it describes, with
    /// the protocol column deciding which half of the port set each row lands
    /// in.
    #[test]
    fn a_report_this_engine_wrote_reads_back_as_its_own_targets() {
        let file = concat!(
            "ip,hostname,status,port,protocol,state\n",
            "198.51.100.1,gateway,up,22,tcp,open\n",
            "198.51.100.1,gateway,up,53,udp,open\n",
            "2001:db8::1,edge,up,443,tcp,open\n",
        );

        let imported = read(file);

        assert_eq!(imported.tokens, 3);
        assert_eq!(
            imported.addresses, 3,
            "198.51.100.1 lands in two units and is counted in each"
        );

        let units = &imported.map.units;
        assert_eq!(units.len(), 3, "22/tcp, 53/udp and 443/tcp are three specs");
        assert!(
            units.iter().any(|unit| unit.ports().has_udp(53)),
            "the protocol column has to decide which half of the set a port lands in"
        );
        assert!(units.iter().any(|unit| unit.ports().has_tcp(443)));
    }

    /// A discovery sweep exports with every port column empty and reads back
    /// as a plain list of hosts.
    #[test]
    fn rows_with_no_port_take_the_default_ports() {
        let imported = read("ip,hostname,port,protocol\n198.51.100.1,gateway,,\n198.51.100.2,,,\n");

        assert_eq!(imported.addresses, 2);
        assert_eq!(imported.map.units.len(), 1, "both took the default");
        assert!(imported.map.units[0].ports().has_tcp(80));
    }

    /// The spreadsheet case: no header this importer recognises, so there is no
    /// header, and the first column is the address.
    #[test]
    fn a_file_with_no_recognised_header_reads_its_first_column() {
        let imported = read("198.51.100.1,web\n198.51.100.2,db\n");

        assert_eq!(imported.tokens, 2);
        assert_eq!(imported.addresses, 2);
    }

    /// An unrecognised header is not a header, so its first field is read as a
    /// target and refused on line 1.
    #[test]
    fn an_unrecognised_header_is_refused_rather_than_guessed_at() {
        let err = ImportFormat::Csv
            .read(
                &mut Cursor::new("Server,Location\nweb01,rack 4\n"),
                &options(),
            )
            .expect_err("'Server' is not a target");

        match err {
            ImportError::Target { origin, token, .. } => {
                assert_eq!(origin, ImportOrigin::line(1));
                assert_eq!(token, "Server");
            }
            other => panic!("expected the first field to be refused, got {other:?}"),
        }

        // Stating the header gets past it.
        let imported = read_with(
            "Server,Location\n198.51.100.1,rack 4\n",
            &CsvImporter::default().with_header(true),
        )
        .expect("a stated header is skipped");
        assert_eq!(imported.addresses, 1);
    }

    /// Naming a column implies a header.
    #[test]
    fn a_named_column_is_read_and_a_missing_one_is_an_error() {
        let file = "name,mgmt_ip,site\nweb01,198.51.100.1,ams\nweb02,198.51.100.2,ams\n";

        let imported = read_with(
            file,
            &CsvImporter::default().with_address_column(CsvColumn::Named("Mgmt IP".to_string())),
        )
        .expect("the named column is found, spelled differently");
        assert_eq!(imported.addresses, 2);

        let missing = read_with(
            file,
            &CsvImporter::default().with_address_column(CsvColumn::Named("nowhere".to_string())),
        );
        assert!(matches!(missing, Err(ImportError::Malformed { .. })));
    }

    /// Getting quoting wrong would shift every column silently.
    #[test]
    fn quoted_fields_carry_commas_quotes_and_line_breaks() {
        let file = concat!(
            "ip,note\n",
            "198.51.100.1,\"comma, inside\"\n",
            "198.51.100.2,\"a \"\"quoted\"\" word\"\n",
            "198.51.100.3,\"two\nlines\"\n",
            "198.51.100.4,plain\n",
        );

        let imported = read(file);
        assert_eq!(imported.tokens, 4);
        assert_eq!(imported.addresses, 4);
    }

    /// A line break inside a quoted field does not end the record but does
    /// advance the line count, so later errors name the right line.
    #[test]
    fn a_line_break_inside_a_field_is_counted_but_does_not_end_the_record() {
        let file = concat!(
            "ip,note\n",          // line 1
            "192.0.2.1,\"two\n",  // line 2
            "lines\"\n",          // line 3
            "not-an-address,x\n", // line 4
        );

        let err = ImportFormat::Csv
            .read(&mut Cursor::new(file), &options())
            .expect_err("the last row is not a target");

        match err {
            ImportError::Target { origin, .. } => assert_eq!(origin, ImportOrigin::line(4)),
            other => panic!("expected a refused target, got {other:?}"),
        }
    }

    /// A carriage return is a line ending only immediately before a line break.
    /// Inside a quoted field it is data.
    #[test]
    fn a_carriage_return_is_a_terminator_only_where_it_terminates() {
        let mut collector = TargetCollector::new(options());
        let file = "ip,note\r\n198.51.100.1,\"carriage\rreturn\"\r\n";
        CsvImporter::default()
            .import(&mut Cursor::new(file), &mut collector)
            .expect("imports");
        assert_eq!(collector.finish().addresses, 1);

        // The CR inside the quotes survives; the one before the line break
        // does not.
        let mut record = Record::new();
        let mut line = 1u64;
        let mut input = Cursor::new("a,\"x\ry\"\r\n");
        record
            .read(&mut input, 4096, &mut line)
            .expect("reads")
            .expect("a record");
        assert_eq!(record.count, 2);
        assert_eq!(record.fields[1], b"x\ry");
    }

    #[test]
    fn the_shapes_a_spreadsheet_arrives_in_are_all_read_the_same() {
        // A byte-order mark, CRLF throughout, a blank row, and no terminator on
        // the last record.
        let file = "\u{feff}ip,port\r\n198.51.100.1,22\r\n\r\n198.51.100.2,443";

        let imported = read(file);
        assert_eq!(imported.tokens, 2);
        assert_eq!(imported.addresses, 2);
        assert_eq!(imported.map.units.len(), 2);
    }

    /// The exporter puts an apostrophe in front of a field that starts like a
    /// spreadsheet formula. Reading back removes exactly that one.
    #[test]
    fn the_exporters_formula_guard_is_taken_back_off() {
        assert_eq!(unescape("'=cmd|'/c calc'!A1"), "=cmd|'/c calc'!A1");
        assert_eq!(unescape("'-lead"), "-lead");
        assert_eq!(unescape("'quoted"), "'quoted", "not a formula, not a guard");
        assert_eq!(unescape("198.51.100.1"), "198.51.100.1");
    }

    /// The bound covers a whole record, because a quoted field can span lines.
    #[test]
    fn a_record_past_the_limit_is_refused() {
        let options = options().with_limits(ImportLimits {
            max_line_bytes: 64,
            ..ImportLimits::default()
        });

        let runaway = format!("ip\n\"{}\"\n", "x".repeat(4096));
        let err = ImportFormat::Csv
            .read(&mut Cursor::new(runaway), &options)
            .expect_err("an unterminated quoted field cannot run forever");

        assert!(matches!(err, ImportError::LineTooLong { limit: 64, .. }));
    }

    #[test]
    fn an_empty_table_produces_no_targets_rather_than_an_error() {
        let imported = read("");
        assert_eq!(imported.tokens, 0);
        assert!(imported.map.is_empty());

        assert_eq!(read("ip,port\n").tokens, 0, "a header and nothing else");
    }
}
