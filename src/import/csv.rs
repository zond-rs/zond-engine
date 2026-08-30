// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # CSV import
//!
//! A table with a column of addresses in it. Two quite different files arrive
//! this way and both are worth reading:
//!
//! - **A report this engine wrote.** The exporter emits one row per host and
//!   port under the header in [`crate::format::csv`], so reading it back is how
//!   a caller rescans exactly what a previous scan found, on exactly the ports
//!   it found open.
//! - **A spreadsheet somebody else wrote.** An asset inventory, a scope
//!   document from a client, an export from a CMDB. One column is addresses and
//!   the rest is theirs.
//!
//! ## Which column holds the addresses
//!
//! One rule, and it is deliberately not a heuristic about what the data looks
//! like: **the first record is a header if any of its fields names a column
//! this importer understands.** Otherwise there is no header, and the first
//! field of every record is the address.
//!
//! Under a header, `ip`, `address`, `host` and `target` are read as addresses -
//! `ip` first, which is what a report this engine wrote calls it - along with
//! `port` and `protocol` where they are present. A caller who knows better says
//! so with [`CsvImporter::with_address_column`], and one whose header this
//! importer cannot recognise says so with [`CsvImporter::with_header`].
//!
//! Nothing here guesses from the values. A file whose first row is
//! `Server,Location` has no recognised name in it, so it has no header, and
//! `Server` is refused as a target on line 1 - which is the loud failure. The
//! alternative is a rule that quietly reads the wrong column, and there is no
//! way for anyone downstream to notice that.
//!
//! ## Reading it back the way it was written
//!
//! The reverse of the CSV exporter, detail for detail: RFC 4180 quoting
//! with doubled quotes inside quoted fields, both line endings, a byte-order
//! mark skipped if Excel left one, and the apostrophe that the exporter puts in
//! front of a field beginning with a formula character taken back off again.
//!
//! A record ends at a line break that is not inside a quoted field, so a field
//! may span lines and [`ImportLimits::max_line_bytes`] bounds the whole record
//! rather than one line of it. That is the same protection under a format where
//! a line is not the unit that can run away.
//!
//! ## What it does not do
//!
//! It does not filter by the `state` column. A row is a target because it is in
//! the file, and choosing which rows to keep is what a spreadsheet is for -
//! reading a report back and silently dropping the closed ports would make
//! "rescan what I found" mean something other than what it says.

use std::io::BufRead;

use crate::import::{ImportError, ImportLimits, ImportOrigin, Importer, TargetSink};

/// The format's name in errors.
const FORMAT: &str = "CSV";

/// The UTF-8 byte-order mark, which Excel writes and everything else trips on.
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Characters a spreadsheet reads as the start of a formula, which the exporter
/// hides behind an apostrophe. Kept in step with `export::csv`.
const FORMULA_LEADERS: [char; 5] = ['=', '+', '-', '@', '\t'];

/// Header names read as the address column, in the order they are preferred.
///
/// `ip` leads because that is what a report this engine wrote calls it, so a
/// round trip never has to think about it. `hostname` is deliberately absent:
/// in a report it sits beside `ip` and is the less useful of the two, and a
/// file that has only hostnames is a file whose column is worth naming.
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
    /// such column is an error rather than a fallback: a caller who named a
    /// column has said what they mean, and reading a different one would answer
    /// a question nobody asked.
    Named(String),
    /// By 0-based position, for a file with no header or an unrecognisable one.
    Index(usize),
}

/// Reads target expressions out of a table.
///
/// Holds one record at a time, so a file of any size costs the same memory.
#[derive(Debug, Clone)]
pub struct CsvImporter {
    limits: ImportLimits,
    addresses: Option<CsvColumn>,
    ports: Option<CsvColumn>,
    has_header: Option<bool>,
}

impl CsvImporter {
    /// A reader bounded by `limits`, finding its columns by the rule above.
    pub fn new(limits: ImportLimits) -> Self {
        Self {
            limits,
            addresses: None,
            ports: None,
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
    /// Rows whose port field is empty take the caller's default ports, which is
    /// what makes a report of a discovery sweep - every port column blank - read
    /// back as a plain list of hosts.
    pub fn with_port_column(mut self, column: CsvColumn) -> Self {
        self.ports = Some(column);
        self
    }

    /// States whether the first record is a header, instead of letting the
    /// importer work it out.
    ///
    /// Needed in one case the automatic rule cannot reach: a file whose header
    /// names none of the columns this importer knows, read by position. Without
    /// this the header is read as a target and refused on line 1.
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
        let mut record = Record::new();
        let mut line = 1u64;
        let mut layout: Option<Layout> = None;
        let mut token = String::new();

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
                        // A header describes the records after it and is not one
                        // of them.
                        continue;
                    }
                    layout.as_ref().expect("just set")
                }
            };

            let address = record.field(layout.addresses, origin)?.unwrap_or("");
            if address.is_empty() {
                continue;
            }

            let port = match layout.ports {
                Some(column) => record.field(column, origin)?.filter(|s| !s.is_empty()),
                None => None,
            };
            let protocol = match layout.protocols {
                Some(column) => record.field(column, origin)?,
                None => None,
            };

            build_token(&mut token, address, port, protocol);
            sink.accept(&token, origin)?;
        }

        Ok(())
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
                // A header field that is not text is not a name, and the record
                // is refused later if it turns out to be data.
                _ => String::new(),
            })
            .collect();

        let recognised = |name: &String| {
            ADDRESS_NAMES.contains(&name.as_str())
                || PORT_NAMES.contains(&name.as_str())
                || PROTOCOL_NAMES.contains(&name.as_str())
        };
        // Naming a column by name is itself a statement that there is a header
        // to find it in.
        let named_by_name = matches!(importer.addresses, Some(CsvColumn::Named(_)))
            || matches!(importer.ports, Some(CsvColumn::Named(_)));
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
                // A header this importer recognised, with no address column in
                // it, is a table it cannot read - reading column 0 there would
                // be the silent guess this whole rule exists to avoid. When the
                // caller *stated* the header instead, they have said only "row
                // one is not data", and the first column is the ordinary
                // default.
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

        Ok(Self {
            addresses,
            ports,
            protocols: if is_header {
                find(&PROTOCOL_NAMES)
            } else {
                None
            },
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

/// Assembles the target expression a row describes.
///
/// The address is always bracketed when ports are present. An IPv6 address must
/// be, and bracketing an IPv4 one costs two characters and removes the only
/// place this could go wrong: `10.0.0.1:u:53` would otherwise be a token with
/// two colons in it, which the grammar reads as an IPv6 address, which it is
/// not.
fn build_token(token: &mut String, address: &str, port: Option<&str>, protocol: Option<&str>) {
    token.clear();

    let Some(port) = port else {
        token.push_str(address);
        return;
    };

    token.push('[');
    token.push_str(address);
    token.push_str("]:");

    // Anything that is not UDP is read as TCP, which is what the port grammar
    // means by an unprefixed port. SCTP has no spelling in a `PortSet` at all.
    if protocol.is_some_and(|protocol| protocol.eq_ignore_ascii_case("udp")) {
        token.push_str("u:");
    }
    token.push_str(port);
}

/// Takes back off the apostrophe the exporter puts in front of a field starting
/// with a formula character, and nothing else.
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
    /// Whether anything has been read yet, which is what makes the byte-order
    /// mark the first record's business alone.
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

    /// Whether every field is empty or blank, which is a blank row.
    fn is_blank(&self) -> bool {
        self.fields[..self.count]
            .iter()
            .all(|field| field.trim_ascii().is_empty())
    }

    /// One field as text, or `None` if the record is shorter than that.
    ///
    /// Decoded on demand rather than all at once, so a twenty-five column report
    /// costs the two or three fields a target is built from.
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
    /// A record ends at a line break that is not inside a quoted field, so this
    /// counts lines as it goes rather than reading one.
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
        // A carriage return is held rather than stored, because only one
        // immediately before a line break is a terminator; anywhere else it is
        // data, including inside a quoted field.
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
                        // A quote only opens a field at its start; anywhere else
                        // it is a literal, which is what RFC 4180 says and what
                        // every spreadsheet emits.
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

        // Only the very first bytes of the file can carry one, and stripping it
        // anywhere else would accept a file that is not what it says it is.
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
    use crate::import::{ImportFormat, ImportOptions, Imported, TargetCollector};
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

    /// The round trip this format exists for: a report this engine wrote, read
    /// back as the targets it describes. The header names the columns and the
    /// protocol column decides which half of the port set each row lands in.
    #[test]
    fn a_report_this_engine_wrote_reads_back_as_its_own_targets() {
        let file = concat!(
            "ip,hostname,status,port,protocol,state\n",
            "10.0.0.1,gateway,up,22,tcp,open\n",
            "10.0.0.1,gateway,up,53,udp,open\n",
            "2001:db8::1,edge,up,443,tcp,open\n",
        );

        let imported = read(file);

        assert_eq!(imported.tokens, 3);
        assert_eq!(
            imported.addresses, 3,
            "10.0.0.1 lands in two units and is counted in each"
        );

        let units = &imported.map.units;
        assert_eq!(units.len(), 3, "22/tcp, 53/udp and 443/tcp are three specs");
        assert!(
            units.iter().any(|unit| unit.ports().has_udp(53)),
            "the protocol column has to decide which half of the set a port lands in"
        );
        assert!(units.iter().any(|unit| unit.ports().has_tcp(443)));
    }

    /// A discovery sweep exports with every port column empty, and has to read
    /// back as a plain list of hosts rather than as nothing at all.
    #[test]
    fn rows_with_no_port_take_the_default_ports() {
        let imported = read("ip,hostname,port,protocol\n10.0.0.1,gateway,,\n10.0.0.2,,,\n");

        assert_eq!(imported.addresses, 2);
        assert_eq!(imported.map.units.len(), 1, "both took the default");
        assert!(imported.map.units[0].ports().has_tcp(80));
    }

    /// The spreadsheet case: no header this importer recognises, so there is no
    /// header, and the first column is the address.
    #[test]
    fn a_file_with_no_recognised_header_reads_its_first_column() {
        let imported = read("10.0.0.1,web\n10.0.0.2,db\n");

        assert_eq!(imported.tokens, 2);
        assert_eq!(imported.addresses, 2);
    }

    /// The loud failure. A header nobody here understands is not a header, so
    /// its first field is read as a target and refused on line 1 - rather than a
    /// rule that quietly reads whichever column looked most address-like.
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

        // And the way out of it, for a caller who knows the shape of the file.
        let imported = read_with(
            "Server,Location\n10.0.0.1,rack 4\n",
            &CsvImporter::default().with_header(true),
        )
        .expect("a stated header is skipped");
        assert_eq!(imported.addresses, 1);
    }

    /// Naming a column is itself a statement that there is a header, or the
    /// name would have nothing to match against.
    #[test]
    fn a_named_column_is_read_and_a_missing_one_is_an_error() {
        let file = "name,mgmt_ip,site\nweb01,10.0.0.1,ams\nweb02,10.0.0.2,ams\n";

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

    /// Quoting is the whole difference between a CSV reader and a line
    /// splitter, and getting it wrong shifts every column silently.
    #[test]
    fn quoted_fields_carry_commas_quotes_and_line_breaks() {
        let file = concat!(
            "ip,note\n",
            "10.0.0.1,\"comma, inside\"\n",
            "10.0.0.2,\"a \"\"quoted\"\" word\"\n",
            "10.0.0.3,\"two\nlines\"\n",
            "10.0.0.4,plain\n",
        );

        let imported = read(file);
        assert_eq!(imported.tokens, 4);
        assert_eq!(imported.addresses, 4);
    }

    /// A line break inside a quoted field must not end the record, and must
    /// still advance the line count - or every error after the first quoted
    /// newline points at the wrong row.
    #[test]
    fn a_line_break_inside_a_field_is_counted_but_does_not_end_the_record() {
        let file = concat!(
            "ip,note\n",          // line 1
            "10.0.0.1,\"two\n",   // line 2
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
    /// Inside a quoted field it is data, and stripping it there would silently
    /// alter a value.
    #[test]
    fn a_carriage_return_is_a_terminator_only_where_it_terminates() {
        let mut collector = TargetCollector::new(options());
        let file = "ip,note\r\n10.0.0.1,\"carriage\rreturn\"\r\n";
        CsvImporter::default()
            .import(&mut Cursor::new(file), &mut collector)
            .expect("imports");
        assert_eq!(collector.finish().addresses, 1);

        // Read the field back directly: the one inside the quotes survives and
        // the one before the line break does not.
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
        let file = "\u{feff}ip,port\r\n10.0.0.1,22\r\n\r\n10.0.0.2,443";

        let imported = read(file);
        assert_eq!(imported.tokens, 2);
        assert_eq!(imported.addresses, 2);
        assert_eq!(imported.map.units.len(), 2);
    }

    /// The exporter hides a field that starts like a spreadsheet formula behind
    /// an apostrophe. Reading one back has to undo exactly that and nothing
    /// else, or a value acquires a quote mark it never had.
    #[test]
    fn the_exporters_formula_guard_is_taken_back_off() {
        assert_eq!(unescape("'=cmd|'/c calc'!A1"), "=cmd|'/c calc'!A1");
        assert_eq!(unescape("'-lead"), "-lead");
        assert_eq!(unescape("'quoted"), "'quoted", "not a formula, not a guard");
        assert_eq!(unescape("10.0.0.1"), "10.0.0.1");
    }

    /// The bound covers a whole record here, because a quoted field can span
    /// lines and a line is therefore not the unit that can run away.
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
