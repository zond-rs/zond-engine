// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reading a report back as targets
//!
//! Scan, export, and feed the report in again: the same hosts, on the ports they
//! were found on. It is the shortest path to checking whether anything changed,
//! and it is why both the document format and the record-per-line one have a
//! reader here.
//!
//! ## The input schema is a narrower contract than the output one
//!
//! The export DTOs are not reused and cannot be. They are borrowing, write-only
//! types, `&'static str` for every enum name and `&'a str` for every borrowed
//! field, and the export side's `ReportDto` is a streaming adapter holding a
//! `&ScanReport` rather than a data structure. There is nothing there for `serde`
//! to deserialize into, and giving them owned fields would cost the export path
//! an allocation per enum name per port to serve a reader that wants four fields.
//!
//! So the records below are written by hand and read only what a rescan needs:
//! the addresses, the zone that makes a link-local address reachable, and the
//! ports with their transport. Everything else in the document is skipped without
//! being built, which leaves the exported schema free to move.
//!
//! ## What this side promises
//!
//! - **Unknown fields are ignored.** A report from a newer engine stays
//!   readable, which is the same forward-compatibility bargain the emitted
//!   document already offers its consumers.
//! - **An unknown enum string is an error naming it.** The opposite choice, on
//!   purpose: a `protocol` this build does not recognise is not a field a reader
//!   can skip but a value that decides what the record says. Reading an unknown
//!   transport as TCP would scan the wrong thing and report success.
//! - **`schema_version` is required and checked.** A document from a future
//!   major version is refused, because by construction its fields mean
//!   something else. Its absence is how a report is told apart from any other
//!   JSON that happens to have a `hosts` key.
//!
//! ## Streaming
//!
//! The document is not read into memory. A `hosts` array is consumed element by
//! element through a [`serde::de::DeserializeSeed`], and each host becomes a
//! target and is dropped before the next is parsed, so a report of a /16 costs one
//! host's worth of memory to import.
//!
//! ## What it does not do
//!
//! It does not filter on `state`. Every port in the document is a target, since a
//! report is the caller's own selection and rescanning what it found should not
//! quietly mean rescanning some of it. A caller who wants only the open ones
//! filters the document, which is one line of `jq`.

use std::fmt;
use std::io::BufRead;
use std::net::Ipv6Addr;

use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::format::{ENGINE_NAME, SCHEMA_VERSION};
use crate::import::{ImportError, ImportLimits, ImportOrigin, Importer, TargetSink};

/// The format's name in errors.
const FORMAT: &str = "JSON";

/// The format's name in errors, for the record-per-line reader.
const LINES_FORMAT: &str = "JSON Lines";

// ---------------------------------------------------------------------------
// The records this side reads
// ---------------------------------------------------------------------------

/// One host, reduced to the parts a rescan needs.
///
/// `#[serde(default)]` throughout, so a document that omits a field this build
/// knows about is read rather than refused. Only `primary_ip` is required: a
/// host record without an address describes nothing that can be scanned.
#[derive(Debug, Deserialize)]
struct HostRecord {
    /// The address the host is keyed by.
    primary_ip: String,
    /// Every address known for the host. When present this is what gets
    /// scanned, so a dual-stack host is rechecked over both families.
    #[serde(default)]
    ips: Vec<String>,
    /// The interface `primary_ip` is valid on.
    ///
    /// Read because without it a link-local record is a host nothing can reach:
    /// every interface has an `fe80::/64`, and an address with no zone names a
    /// different machine on each one.
    #[serde(default)]
    zone: Option<String>,
    /// The ports the scan recorded, whatever state they were in.
    #[serde(default)]
    ports: Vec<PortRecord>,
}

/// One port, reduced to what names it on the wire.
#[derive(Debug, Deserialize)]
struct PortRecord {
    port: u16,
    protocol: String,
}

/// A JSON Lines record, told apart by its `type`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum LineRecord {
    /// The header, which carries the schema version.
    #[serde(rename = "report")]
    Report(HeaderRecord),
    /// One host.
    #[serde(rename = "host")]
    Host(HostRecord),
    /// A record kind this build does not know, skipped so that a newer engine's
    /// output stays readable.
    #[serde(other)]
    Unknown,
}

/// The JSON Lines header, reduced to what identifies the document.
#[derive(Debug, Deserialize)]
struct HeaderRecord {
    schema_version: u32,
}

// ---------------------------------------------------------------------------
// Turning a record into targets
// ---------------------------------------------------------------------------

/// Builds target expressions out of host records and hands them to the sink.
struct Emitter<'a> {
    sink: &'a mut dyn TargetSink,
    /// Reused across hosts, because a report has as many of these as it has
    /// addresses.
    token: String,
    ports: String,
    /// Set when the sink or a record refuses, so the real error survives the
    /// trip out through `serde`'s error type.
    failure: Option<ImportError>,
    /// Whether a `schema_version` has been seen and accepted.
    versioned: bool,
    /// The most addresses one host record may name.
    ///
    /// The sink counts the running total across the whole import, the bound that
    /// matters for a scan. This one is about the document: a record naming more
    /// addresses than the whole import may cover is a record nothing
    /// good comes of building the rest of.
    max_addresses: u128,
    /// Whether the document carried a `hosts` array at all.
    ///
    /// Required, and what tells a document from one record of a record-per-line
    /// file. That file's first line is a complete object carrying
    /// `schema_version` and nothing that names a host, so a reader letting it
    /// pass would parse it, never reach the lines the hosts are on, and return
    /// `Ok` with no targets. A scan of an empty report writes `"hosts": []`, so
    /// present-and-empty is how a document means it.
    hosted: bool,
}

impl<'a> Emitter<'a> {
    fn new(sink: &'a mut dyn TargetSink, limits: ImportLimits) -> Self {
        Self {
            sink,
            token: String::new(),
            ports: String::new(),
            failure: None,
            max_addresses: limits.max_addresses,
            versioned: false,
            hosted: false,
        }
    }

    /// Checks a document's schema version against the one this build writes.
    fn accept_version(&mut self, version: u32, format: &'static str, origin: ImportOrigin) -> bool {
        if version > SCHEMA_VERSION {
            self.failure = Some(ImportError::Malformed {
                format,
                origin,
                message: format!(
                    "schema version {version} is newer than this build understands ({SCHEMA_VERSION}); \
                     its fields do not mean what they used to"
                ),
            });
            return false;
        }
        self.versioned = true;
        true
    }

    /// Turns one host into targets.
    fn emit(&mut self, host: &HostRecord, format: &'static str, origin: ImportOrigin) -> bool {
        self.ports.clear();
        for port in &host.ports {
            let name = port.protocol.to_ascii_lowercase();
            // A transport this build cannot name is a port it cannot probe
            // correctly, and reading it as TCP would scan something else and
            // call it a success.
            let Some(protocol) = crate::record::wire::protocol(&name) else {
                self.failure = Some(ImportError::Malformed {
                    format,
                    origin,
                    message: format!(
                        "'{}' names transport '{name}', which this build cannot probe",
                        host.primary_ip
                    ),
                });
                return false;
            };
            let prefix = protocol.spec_prefix();
            if !self.ports.is_empty() {
                self.ports.push(',');
            }
            self.ports.push_str(prefix);
            self.ports.push_str(&port.port.to_string());
        }

        // `ips` is the full picture and `primary_ip` is the key into it. A
        // document that carries only the key is still a host worth rescanning.
        let addresses: &[String] = if host.ips.is_empty() {
            std::slice::from_ref(&host.primary_ip)
        } else {
            &host.ips
        };

        if addresses.len() as u128 > self.max_addresses {
            self.failure = Some(ImportError::TooManyAddresses {
                origin,
                token: host.primary_ip.clone(),
                limit: self.max_addresses,
            });
            return false;
        }

        for address in addresses {
            let scoped = host
                .zone
                .as_deref()
                .filter(|_| is_link_local(address))
                .map(|zone| format!("{address}%{zone}"));
            let address = scoped.as_deref().unwrap_or(address);

            crate::import::expression(&mut self.token, address, &self.ports);

            if let Err(error) = self.sink.accept(&self.token, origin) {
                self.failure = Some(error);
                return false;
            }
        }

        true
    }
}

/// Whether an address is one that needs a zone to be reachable.
fn is_link_local(address: &str) -> bool {
    address
        .parse::<Ipv6Addr>()
        .is_ok_and(|address| address.is_unicast_link_local())
}

// ---------------------------------------------------------------------------
// The JSON document
// ---------------------------------------------------------------------------

/// Reads a report written as a single JSON document.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonImporter {
    limits: ImportLimits,
}

impl JsonImporter {
    /// A reader bounded by `limits`.
    ///
    /// Which of them bind here, since a document is not a stream of lines:
    ///
    /// - [`max_line_bytes`](ImportLimits::max_line_bytes) does not. A JSON
    ///   document has no lines, and nothing here reads one.
    /// - [`max_tokens`](ImportLimits::max_tokens) binds, through the sink, which
    ///   counts every expression whatever produced it.
    /// - [`max_addresses`](ImportLimits::max_addresses) binds twice: through the
    ///   sink as the running total, and here as the most addresses one host
    ///   record may name. The second is what stops a document with one host and
    ///   ten million addresses in it from being assembled before the sink has
    ///   seen a single one.
    pub fn new(limits: ImportLimits) -> Self {
        Self { limits }
    }
}

impl Importer for JsonImporter {
    fn import(
        &self,
        input: &mut dyn BufRead,
        sink: &mut dyn TargetSink,
    ) -> Result<(), ImportError> {
        crate::import::skip_bom(input)?;

        let mut emitter = Emitter::new(sink, self.limits);
        let mut deserializer = serde_json::Deserializer::from_reader(input);

        let outcome = Document {
            emitter: &mut emitter,
        }
        .deserialize(&mut deserializer);

        // The real error is the one the sink or a record produced; serde's is
        // only the vehicle that carried the stop signal out.
        if let Some(failure) = emitter.failure.take() {
            return Err(failure);
        }

        outcome.map_err(|error| ImportError::Malformed {
            format: FORMAT,
            origin: ImportOrigin::unknown(),
            message: error.to_string(),
        })?;

        if !emitter.versioned {
            return Err(ImportError::Malformed {
                format: FORMAT,
                origin: ImportOrigin::unknown(),
                message: format!("no 'schema_version': this is not a document {ENGINE_NAME} wrote"),
            });
        }

        if !emitter.hosted {
            return Err(ImportError::Malformed {
                format: FORMAT,
                origin: ImportOrigin::unknown(),
                message: "no 'hosts': a document with no host list names no targets, and a \
                          record-per-line export is read as JSON Lines"
                    .to_string(),
            });
        }

        Ok(())
    }
}

/// Visits the document's top-level object, taking the hosts as they arrive.
struct Document<'a, 'e> {
    emitter: &'e mut Emitter<'a>,
}

impl<'de, 'a, 'e> DeserializeSeed<'de> for Document<'a, 'e> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de, 'a, 'e> Visitor<'de> for Document<'a, 'e> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a scan report object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "schema_version" => {
                    let version: u32 = map.next_value()?;
                    if !self
                        .emitter
                        .accept_version(version, FORMAT, ImportOrigin::unknown())
                    {
                        return Err(de::Error::custom("unsupported schema version"));
                    }
                }
                "hosts" => {
                    self.emitter.hosted = true;
                    map.next_value_seed(Hosts {
                        emitter: &mut *self.emitter,
                    })?;
                }
                // Everything else in the document is skipped without being
                // built, which is what keeps this reader's promises narrow.
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        Ok(())
    }
}

/// Visits the `hosts` array one element at a time.
struct Hosts<'a, 'e> {
    emitter: &'e mut Emitter<'a>,
}

impl<'de, 'a, 'e> DeserializeSeed<'de> for Hosts<'a, 'e> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, 'a, 'e> Visitor<'de> for Hosts<'a, 'e> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array of hosts")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        // One host is parsed, turned into targets and dropped before the next
        // is read, so the array never exists in memory.
        while let Some(host) = seq.next_element::<HostRecord>()? {
            if !self.emitter.emit(&host, FORMAT, ImportOrigin::unknown()) {
                return Err(de::Error::custom("import stopped"));
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The record-per-line document
// ---------------------------------------------------------------------------

/// Reads a report written one record per line.
///
/// Every line stands alone, so a report whose scan was killed half way through
/// still reads, which is why that format exists and would be
/// a poor reader that could not take advantage of it.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonLinesImporter {
    limits: ImportLimits,
}

impl JsonLinesImporter {
    /// A reader bounded by `limits`.
    pub fn new(limits: ImportLimits) -> Self {
        Self { limits }
    }
}

impl Importer for JsonLinesImporter {
    fn import(
        &self,
        input: &mut dyn BufRead,
        sink: &mut dyn TargetSink,
    ) -> Result<(), ImportError> {
        crate::import::skip_bom(input)?;

        let mut emitter = Emitter::new(sink, self.limits);
        let mut buffer = Vec::new();
        let mut line_number = 0u64;

        loop {
            buffer.clear();
            line_number += 1;
            let origin = ImportOrigin::line(line_number);

            if !crate::import::list::read_line(
                input,
                &mut buffer,
                self.limits.max_line_bytes,
                origin,
            )? {
                break;
            }

            let text =
                std::str::from_utf8(&buffer).map_err(|_| ImportError::InvalidUtf8 { origin })?;
            if text.trim().is_empty() {
                continue;
            }

            let record: LineRecord =
                serde_json::from_str(text).map_err(|error| ImportError::Malformed {
                    format: LINES_FORMAT,
                    origin,
                    message: error.to_string(),
                })?;

            let carried_on = match record {
                LineRecord::Report(header) => {
                    emitter.accept_version(header.schema_version, LINES_FORMAT, origin)
                }
                LineRecord::Host(host) => emitter.emit(&host, LINES_FORMAT, origin),
                LineRecord::Unknown => true,
            };

            if !carried_on {
                return Err(emitter.failure.take().expect("a refusal records why"));
            }
        }

        if !emitter.versioned {
            return Err(ImportError::Malformed {
                format: LINES_FORMAT,
                origin: ImportOrigin::unknown(),
                message: format!("no 'report' record: this is not output {ENGINE_NAME} wrote"),
            });
        }

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
    use crate::import::{ImportFormat, ImportOptions, Imported};
    use crate::model::port::PortSet;
    use std::io::Cursor;

    /// The port every test's default port set holds, named so the round-trip
    /// expectation can say what a portless host comes back as.
    const DEFAULT_PORT: u16 = 80;

    fn options() -> ImportOptions<'static> {
        ImportOptions::new(PortSet::try_from("80").unwrap())
    }

    fn read(format: ImportFormat, input: &str) -> Result<Imported, ImportError> {
        format.read(&mut Cursor::new(input), &options())
    }

    /// A minimal document, so the parsing tests do not depend on the exporter.
    fn document(hosts: &str) -> String {
        format!(r#"{{"schema_version":1,"engine":{{"name":"zond-engine"}},"hosts":[{hosts}]}}"#)
    }

    #[test]
    fn a_host_is_rescanned_on_the_ports_it_was_found_on() {
        let file = document(
            r#"{"primary_ip":"10.0.0.1","ips":["10.0.0.1"],
                "ports":[{"port":22,"protocol":"tcp"},{"port":53,"protocol":"udp"}]}"#,
        );

        let imported = read(ImportFormat::Json, &file).expect("imports");

        assert_eq!(imported.addresses, 1);
        let ports = imported.map.units[0].ports();
        assert!(ports.has_tcp(22), "the TCP port came back as TCP");
        assert!(ports.has_udp(53), "the UDP port came back as UDP");
        assert!(!ports.has_tcp(53), "and not as both");
    }

    /// A discovery report has no ports at all, and has to read back as the
    /// hosts it found rather than as nothing.
    #[test]
    fn a_host_with_no_ports_takes_the_default_ports() {
        let file = document(r#"{"primary_ip":"10.0.0.1"},{"primary_ip":"10.0.0.2"}"#);

        let imported = read(ImportFormat::Json, &file).expect("imports");

        assert_eq!(imported.addresses, 2);
        assert!(imported.map.units[0].ports().has_tcp(80));
    }

    /// A dual-stack host is a host at both addresses, and rechecking it means
    /// rechecking both.
    #[test]
    fn every_address_of_a_host_becomes_a_target() {
        let file = document(
            r#"{"primary_ip":"10.0.0.1","ips":["10.0.0.1","2001:db8::1"],
                "ports":[{"port":443,"protocol":"tcp"}]}"#,
        );

        let imported = read(ImportFormat::Json, &file).expect("imports");
        assert_eq!(imported.addresses, 2);
    }

    /// Without its zone a link-local record describes a host nothing can reach,
    /// so the zone has to survive into the target.
    #[test]
    fn a_link_local_host_keeps_the_interface_that_makes_it_reachable() {
        fn zones(name: &str) -> Option<u32> {
            (name == "en0").then_some(7)
        }
        let options = options()
            .with_context(crate::model::parse::target::TargetContext::new().with_zones(&zones));

        let file = document(
            r#"{"primary_ip":"fe80::aa","ips":["fe80::aa","10.0.0.1"],"zone":"en0",
                "ports":[{"port":22,"protocol":"tcp"}]}"#,
        );

        let imported = ImportFormat::Json
            .read(&mut Cursor::new(file), &options)
            .expect("imports");

        let v6 = imported.map.units[0].ips().v6();
        assert_eq!(v6.len(), 1);
        assert_eq!(v6[0].zone(), Some(7), "the zone was dropped on the way in");
        // The zone belongs to the link-local address and must not be pasted
        // onto the IPv4 one, which would make it unparseable.
        assert_eq!(imported.map.units[0].ips().v4().len(), 1);
    }

    /// The promise that keeps a newer engine's report readable.
    #[test]
    fn fields_this_build_does_not_know_are_ignored() {
        let file = r#"{
            "schema_version":1,
            "engine":{"name":"zond-engine","version":"9.9.9"},
            "summary":{"hosts_total":1,"anything":{"nested":[1,2,3]}},
            "hosts":[{"primary_ip":"10.0.0.1","telemetry":{"rtt_median_us":1234},
                      "invented_field":true,
                      "ports":[{"port":22,"protocol":"tcp","state":"open","service":{"name":"ssh"}}]}],
            "trailing_unknown":[{"a":1}]
        }"#;

        let imported = read(ImportFormat::Json, file).expect("imports");
        assert_eq!(imported.addresses, 1);
        assert!(imported.map.units[0].ports().has_tcp(22));
    }

    /// A transport this build does scan reads back as itself, prefix and all.
    #[test]
    fn an_sctp_port_reads_back_as_an_sctp_port() {
        let file = document(r#"{"primary_ip":"10.0.0.1","ports":[{"port":9,"protocol":"sctp"}]}"#);

        let imported = read(ImportFormat::Json, &file).expect("imports");
        let ports = imported.map.units[0].ports();
        assert!(ports.has_sctp(9) && !ports.has_tcp(9));
    }

    /// The opposite rule, and the reason for it: an unrecognised transport is
    /// not a field to skip, it is a value that says what the record means.
    /// Reading it as TCP would probe something else and report success.
    #[test]
    fn an_unknown_transport_is_refused_rather_than_assumed() {
        let file = document(r#"{"primary_ip":"10.0.0.1","ports":[{"port":9,"protocol":"dccp"}]}"#);

        let err = read(ImportFormat::Json, &file).expect_err("dccp cannot be probed");

        match err {
            ImportError::Malformed { message, .. } => {
                assert!(
                    message.contains("dccp"),
                    "the error has to name it: {message}"
                );
            }
            other => panic!("expected a malformed document, got {other:?}"),
        }
    }

    /// A document from a future major version means something else by the same
    /// field names, so it is refused rather than half-understood.
    /// A record-per-line file read as a single document has to refuse rather
    /// than parse its first line and report no targets at all.
    ///
    /// The path this closes: `sniff` decides on whatever `fill_buf` returns, and
    /// that is one byte on a pipe. A JSON Lines stream whose first read is short
    /// resolves to `Json`, and without this the reader takes the header record
    /// as the whole document and hands back `Ok` with nothing in it.
    #[test]
    fn a_record_per_line_file_read_as_a_document_is_refused() {
        let file = concat!(
            r#"{"type":"report","schema_version":1,"engine":{"name":"zond-engine"}}"#,
            "\n",
            r#"{"type":"host","primary_ip":"10.0.0.1","ports":[{"port":22,"protocol":"tcp"}]}"#,
            "\n",
        );

        let error =
            read(ImportFormat::Json, file).expect_err("a stream of records is not one document");

        match error {
            ImportError::Malformed { message, .. } => assert!(
                message.contains("hosts"),
                "the refusal should name what was missing, said: {message}"
            ),
            other => panic!("expected a malformed document, got {other:?}"),
        }
    }

    #[test]
    fn a_newer_schema_version_is_refused_and_a_missing_one_is_not_a_report() {
        let newer = r#"{"schema_version":9999,"hosts":[{"primary_ip":"10.0.0.1"}]}"#;
        assert!(matches!(
            read(ImportFormat::Json, newer),
            Err(ImportError::Malformed { .. })
        ));

        let anonymous = r#"{"hosts":[{"primary_ip":"10.0.0.1"}]}"#;
        let err = read(ImportFormat::Json, anonymous)
            .expect_err("JSON with a hosts key is not necessarily a report");
        assert!(matches!(err, ImportError::Malformed { .. }));
    }

    #[test]
    fn a_record_per_line_report_reads_the_same_hosts() {
        let file = concat!(
            r#"{"type":"report","schema_version":1,"engine":{"name":"zond-engine"}}"#,
            "\n",
            r#"{"type":"host","primary_ip":"10.0.0.1","ports":[{"port":22,"protocol":"tcp"}]}"#,
            "\n",
            r#"{"type":"host","primary_ip":"10.0.0.2","ports":[{"port":22,"protocol":"tcp"}]}"#,
            "\n",
        );

        let imported = read(ImportFormat::JsonLines, file).expect("imports");
        assert_eq!(imported.addresses, 2);
        assert_eq!(imported.map.units.len(), 1, "both on 22/tcp");
    }

    /// The format exists so a truncated file is still a file. A reader that
    /// refused one would give that up for nothing.
    #[test]
    fn a_truncated_record_per_line_report_still_reads_what_survived() {
        let file = concat!(
            r#"{"type":"report","schema_version":1}"#,
            "\n",
            r#"{"type":"host","primary_ip":"10.0.0.1"}"#,
            "\n",
        );

        let imported = read(ImportFormat::JsonLines, file).expect("imports");
        assert_eq!(imported.addresses, 1);
    }

    /// A record kind from a newer engine is skipped, for the same reason an
    /// unknown field is.
    #[test]
    fn an_unknown_record_kind_is_skipped() {
        let file = concat!(
            r#"{"type":"report","schema_version":1}"#,
            "\n",
            r#"{"type":"finding","severity":"high","note":"something new"}"#,
            "\n",
            r#"{"type":"host","primary_ip":"10.0.0.1"}"#,
            "\n",
        );

        let imported = read(ImportFormat::JsonLines, file).expect("imports");
        assert_eq!(imported.addresses, 1);
    }

    /// The round trip, held against the fixture rather than against the
    /// document.
    ///
    /// Comparing what came back to what the exporter wrote would only prove the
    /// two agree; both could be wrong together. The fixture's `Host` values are
    /// built by hand and are outside the serialization loop entirely, so this
    /// asks the question that matters: does every host and port the scan
    /// actually found survive being written out and read back in?
    #[cfg(feature = "export-json")]
    #[test]
    fn every_host_and_port_in_a_report_survives_the_round_trip() {
        use crate::export::{ExportOptions, Exporter, JsonExporter};
        use std::collections::BTreeSet;

        let report = crate::export::fixture::report();

        // Taken from the fixture's own types, never from the JSON. A host the
        // scan found no ports on comes back on the caller's default ports,
        // which is the whole reason a discovery report is worth re-importing,
        // so the expectation says so rather than leaving it to a subset check.
        let mut expected: BTreeSet<(String, u16)> = BTreeSet::new();
        let mut expected_addresses: BTreeSet<String> = BTreeSet::new();
        for host in report.hosts() {
            for ip in host.ips() {
                expected_addresses.insert(ip.to_string());
                if host.port_count() == 0 {
                    expected.insert((ip.to_string(), DEFAULT_PORT));
                    continue;
                }
                for port in host.ports() {
                    expected.insert((ip.to_string(), port.number()));
                }
            }
        }

        let mut document = Vec::new();
        JsonExporter::new(ExportOptions::new())
            .export(&report, &mut document)
            .expect("the fixture exports");

        let imported = ImportFormat::Json
            .read(&mut Cursor::new(document), &options())
            .expect("its own document reads back");

        let mut found: BTreeSet<(String, u16)> = BTreeSet::new();
        let mut found_addresses: BTreeSet<String> = BTreeSet::new();
        for target in imported.map.iter() {
            found_addresses.insert(target.ip.to_string());
            found.insert((target.ip.to_string(), target.port));
        }

        assert_eq!(
            found_addresses, expected_addresses,
            "the addresses the scan found are not the addresses that came back"
        );
        assert_eq!(
            found, expected,
            "the host and port pairs the scan found are not the ones that came back"
        );
        assert!(
            !expected.is_empty(),
            "a fixture with no ports proves nothing"
        );
    }

    /// The two record-per-line formats have to agree with the document format
    /// about the same report, or a caller's choice of output format silently
    /// changes what a rescan covers.
    #[cfg(all(feature = "export-json", feature = "export-jsonl"))]
    #[test]
    fn the_two_report_formats_read_back_as_the_same_targets() {
        use crate::export::{ExportOptions, Exporter, JsonExporter, JsonLinesExporter};

        let report = crate::export::fixture::report();
        let options = ExportOptions::new();

        let mut document = Vec::new();
        JsonExporter::new(options.clone())
            .export(&report, &mut document)
            .expect("exports");
        let mut lines = Vec::new();
        JsonLinesExporter::new(options)
            .export(&report, &mut lines)
            .expect("exports");

        let from_document = ImportFormat::Json
            .read(&mut Cursor::new(document), &super::tests::options())
            .expect("imports");
        let from_lines = ImportFormat::JsonLines
            .read(&mut Cursor::new(lines), &super::tests::options())
            .expect("imports");

        assert_eq!(from_document.addresses, from_lines.addresses);
        assert_eq!(
            from_document.map.units.len(),
            from_lines.map.units.len(),
            "the same report produced different targets in two formats"
        );
    }

    #[test]
    fn a_line_that_is_not_a_record_names_its_line() {
        let file = concat!(
            r#"{"type":"report","schema_version":1}"#,
            "\n",
            "not json at all\n",
        );

        match read(ImportFormat::JsonLines, file).expect_err("line 2 is not a record") {
            ImportError::Malformed { origin, .. } => assert_eq!(origin, ImportOrigin::line(2)),
            other => panic!("expected a malformed record, got {other:?}"),
        }
    }
}
