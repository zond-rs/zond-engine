// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reading a document as findings
//!
//! The rest of [`import`](crate::import) reads a document for the targets to scan
//! next: addresses and ports, everything else skipped. This reads the same kind
//! of document for what the scan that produced it found, and builds the
//! [`ScanReport`] that scan would have produced.
//!
//! ## Why both, and why they stay apart
//!
//! Rescanning what a document found and reading what it found are different jobs
//! with opposite instincts. The target readers are narrow on purpose:
//! [`import::json`](crate::import::json) reads four fields, which leaves the
//! exported schema free to move while nothing promises to read most of it.
//! Widening them to carry findings would spend that freedom on a different
//! caller.
//!
//! So the readers here are separate, and the two directions share only the
//! parsing machinery that has no opinion about either, meaning `xml` for the
//! documents that are XML.
//!
//! ## What this unlocks
//!
//! [`diff`](crate::diff) compares two [`ScanReport`]s and asks nothing about
//! where either came from. A scan this process ran, a scan read back out of a
//! [`journal`](crate::journal) and a scan read back out of a file are the same
//! input to it. This module puts the third in reach, and a file is what people
//! archive, where a journal is state a machine keeps and prunes.
//!
//! So: last quarter's nmap output against tonight's scan is one call, two nmap
//! files against each other is one call, and an exported report from a build
//! that has since been upgraded against a fresh one is one call.
//!
//! ## A report is not evidence that this engine produced it
//!
//! A [`ScanReport`] built here is attributed to whatever wrote the document, so
//! `nmap 7.94` rather than this crate, through
//! [`ScanReport::recorded`](crate::report::ScanReport::recorded), and
//! [`Provenance::engine_version`](crate::diff::Provenance::engine_version) hands
//! that back unchanged. Nothing downstream should read a report as proof this
//! engine's scanners ran.
//!
//! ## The same bounds, and the same refusal to open anything
//!
//! Everything the module documentation of [`import`](crate::import) says applies
//! here. A reader takes a [`BufRead`] and never opens a file,
//! [`ImportLimits`] are part of the call rather than a constant, and exceeding
//! one is an error naming what exceeded it.

#[cfg(feature = "import-json")]
pub mod json;

#[cfg(feature = "import-nmap")]
pub mod nmap;

use std::io::BufRead;
use std::path::Path;

use crate::import::{ImportError, ImportLimits};
use crate::report::ScanReport;

/// Reads a document as the report of the scan that produced it.
///
/// The mirror of [`Exporter`](crate::export::Exporter), which writes one. A reader
/// takes bytes from wherever the caller got them and returns the whole report,
/// since a report is a document with a shape rather than a stream of independent
/// records: the phase it belongs to is stated once, at the top.
pub trait ReportReader {
    /// Reads `input` as one report.
    fn read(&self, input: &mut dyn BufRead) -> Result<ScanReport, ImportError>;
}

/// What a report reader is allowed to spend.
///
/// A struct rather than a bare [`ImportLimits`] so that a policy this side needs
/// and the target side does not stays an additive change.
/// [`max_document_bytes`](Self::max_document_bytes) is the first such policy.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportOptions {
    /// The bounds shared with the target readers.
    ///
    /// Not every one of them means something to every reader here, because a
    /// report is a document with a shape and a target list is a stream of
    /// expressions. [`max_addresses`](ImportLimits::max_addresses) bounds the
    /// hosts a document may name and binds both readers.
    /// [`max_line_bytes`](ImportLimits::max_line_bytes) bounds one element's
    /// markup in the nmap reader. A JSON document is one value with no lines
    /// to bound, and a record-per-line one has lines as long as a host's port
    /// list, so [`max_document_bytes`](Self::max_document_bytes) is what bounds
    /// both. [`max_tokens`](ImportLimits::max_tokens) counts target
    /// expressions and a report holds none, so nothing here reads it.
    pub limits: ImportLimits,

    /// The most bytes one document may be read from.
    ///
    /// Every reader here parses a whole document before it returns one, so this
    /// bounds what an untrusted file may make the process do. It is checked as
    /// the bytes are consumed, so a document past the ceiling is refused on the
    /// way in rather than after it has been held.
    ///
    /// It bounds the document, and the process holds a multiple of it. Size
    /// this to what the process can afford rather than to a file you are willing
    /// to read. Measured, in the shapes that cost most per byte: twenty hosts
    /// each listing every TCP port in the fewest bytes a port entry can take,
    /// 64 MB of document and 5.8 times that resident at the peak; one host
    /// whose `ips` array carries four million addresses, 59.9 MB and 2.8
    /// times. A document repeating one port entry or one address costs one,
    /// since a host's ports are folded by endpoint and its addresses into a
    /// set as they are read. So at the default a hostile document can leave the
    /// process holding about 6 GiB, and a caller reading documents from
    /// strangers on a small machine should lower this.
    ///
    /// The default is 1 GiB, sized to read back what this engine writes. One
    /// host scanned across the whole TCP range and found closed is 26 MB of
    /// the indented JSON the exporter writes by default, 14 MB of JSON lines
    /// and 6.5 MB of nmap XML, about 400, 216 and 99 bytes a port. The default
    /// admits 32 such hosts in the first, 64 in the second and 128 in the
    /// third, each with a margin for the services and findings on their open
    /// ports, and reading them back holds less than the document in JSON and
    /// about three times it in XML. Raise it with
    /// [`with_max_document_bytes`](Self::with_max_document_bytes) for a document
    /// that has been vetted, or pass [`u64::MAX`] to lift it.
    ///
    /// It is the one ceiling on a document's size. The most elements an XML
    /// document may hold is derived from it, as the most a document of this
    /// many bytes could hold, so raising it never leaves a document refused
    /// for a count nobody can set.
    pub max_document_bytes: u64,
}

/// 1 GiB. See [`ReportOptions::max_document_bytes`].
const DEFAULT_MAX_DOCUMENT_BYTES: u64 = 1024 * 1024 * 1024;

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            limits: ImportLimits::default(),
            max_document_bytes: DEFAULT_MAX_DOCUMENT_BYTES,
        }
    }
}

impl ReportOptions {
    /// The defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the bounds.
    pub fn with_limits(mut self, limits: ImportLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets the whole-document ceiling.
    pub fn with_max_document_bytes(mut self, bytes: u64) -> Self {
        self.max_document_bytes = bytes;
        self
    }
}

/// A document format a report can be read from.
///
/// The mirror of [`ImportFormat`](crate::import::ImportFormat) for this
/// direction, and shorter: a report is a document some scanner wrote, and only
/// the formats that carry findings appear here. There is no list format, because
/// a list of addresses is not a report of anything.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReportFormat {
    /// This engine's own exported JSON, as a single document.
    #[cfg(feature = "import-json")]
    Json,
    /// The same data one record per line, which is what
    /// [`export::jsonl`](crate::export::jsonl) writes.
    ///
    /// Read here as well as in [`ImportFormat`](crate::import::ImportFormat).
    /// The format exists so a scan cut short still leaves a readable file, and a
    /// file that can only be read as the
    /// targets it names is not that.
    #[cfg(feature = "import-json")]
    JsonLines,
    /// Nmap's XML, which this engine's own nmap exporter also writes.
    #[cfg(feature = "import-nmap")]
    Nmap,
}

impl ReportFormat {
    /// The format a file extension names, if it is one this build reads.
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension
            .trim_start_matches('.')
            .to_ascii_lowercase()
            .as_str()
        {
            #[cfg(feature = "import-json")]
            "json" => Some(ReportFormat::Json),
            // `ndjson` is the other name the same format goes by, matching what
            // the exporter and the target-side reader both accept.
            #[cfg(feature = "import-json")]
            "jsonl" | "ndjson" => Some(ReportFormat::JsonLines),
            #[cfg(feature = "import-nmap")]
            "xml" => Some(ReportFormat::Nmap),
            _ => None,
        }
    }

    /// The canonical file extension for this format, without a leading dot.
    pub fn extension(self) -> &'static str {
        match self {
            #[cfg(feature = "import-json")]
            ReportFormat::Json => "json",
            #[cfg(feature = "import-json")]
            ReportFormat::JsonLines => "jsonl",
            #[cfg(feature = "import-nmap")]
            ReportFormat::Nmap => "xml",
        }
    }

    /// Every report format this build can read.
    ///
    /// Front ends use this to describe their own capabilities, as
    /// [`ImportFormat::all`](crate::import::ImportFormat::all) does: a help
    /// text listing formats the binary was not built with is worse than none.
    pub fn all() -> &'static [ReportFormat] {
        &[
            #[cfg(feature = "import-json")]
            ReportFormat::Json,
            #[cfg(feature = "import-json")]
            ReportFormat::JsonLines,
            #[cfg(feature = "import-nmap")]
            ReportFormat::Nmap,
        ]
    }

    /// The format a path's extension names.
    pub fn from_path(path: &Path) -> Option<Self> {
        path.extension()
            .and_then(|extension| extension.to_str())
            .and_then(Self::from_extension)
    }

    /// The format the start of `input` implies, without consuming it.
    ///
    /// Almost one byte: a report document is an object or an element and nothing
    /// else. Not a content sniff beyond that, since which document this is
    /// belongs to the reader, and each refuses one it does
    /// not recognise by naming what it found.
    ///
    /// The exception is the two JSON shapes, which both open with a brace. The
    /// record-per-line one names itself in its first record, so that tag is what
    /// separates them, exactly as
    /// [`ImportFormat::sniff`](crate::import::ImportFormat::sniff) separates them
    /// in the other direction. Without it a record-per-line export is read as a
    /// single document, its first line parses, its hosts are never reached, and
    /// what comes back is a correctly attributed report of a scan that found
    /// nothing.
    pub fn sniff(input: &mut dyn BufRead) -> Result<Self, ImportError> {
        /// How a record-per-line document's header record names itself, written
        /// as the compact exporter writes it.
        #[cfg(feature = "import-json")]
        const REPORT_TAG: &[u8] = br#""type":"report""#;

        let available = input.fill_buf()?;
        // Excel's mark, which says nothing about the format behind it. Stripped
        // here as the target side strips it, or a document saved by a Windows
        // editor is refused as neither format before either reader sees it.
        let prefix = crate::import::without_bom(available).trim_ascii_start();

        // Bound before the arms, because a build with only one of the two
        // features has no arm to read it and an unused binding there is a
        // warning nobody can act on.
        let _ = &prefix;

        #[cfg(feature = "import-nmap")]
        if prefix.first() == Some(&b'<') {
            return Ok(ReportFormat::Nmap);
        }

        #[cfg(feature = "import-json")]
        if prefix.first() == Some(&b'{') {
            let head = &prefix[..prefix.len().min(256)];
            let tagged = head
                .windows(REPORT_TAG.len())
                .any(|window| window == REPORT_TAG);
            return Ok(if tagged {
                ReportFormat::JsonLines
            } else {
                ReportFormat::Json
            });
        }

        Err(ImportError::Malformed {
            format: "report",
            origin: crate::import::ImportOrigin::unknown(),
            message: "the input begins as neither a JSON document nor an XML one".to_string(),
        })
    }

    /// The format at `path` if its extension names one, and otherwise whatever
    /// the input begins as.
    ///
    /// The extension wins because it is what the person who saved the file meant.
    pub fn resolve(path: Option<&Path>, input: &mut dyn BufRead) -> Result<Self, ImportError> {
        match path.and_then(Self::from_path) {
            Some(format) => Ok(format),
            None => Self::sniff(input),
        }
    }

    /// Reads `input` as a report in this format.
    ///
    /// Refuses a document past
    /// [`ReportOptions::max_document_bytes`] before any reader sees the whole of
    /// it, and refuses one naming more hosts than
    /// [`ImportLimits::max_addresses`] allows. Each reader holds its input to
    /// both itself, so one used directly is bounded the same way.
    #[cfg_attr(
        not(any(feature = "import-json", feature = "import-nmap")),
        allow(unused_variables)
    )]
    pub fn read(
        self,
        input: &mut dyn BufRead,
        options: ReportOptions,
    ) -> Result<ScanReport, ImportError> {
        match self {
            #[cfg(feature = "import-json")]
            ReportFormat::Json => json::JsonReportReader::new(options).read(input),
            #[cfg(feature = "import-json")]
            ReportFormat::JsonLines => json::JsonLinesReportReader::new(options).read(input),
            #[cfg(feature = "import-nmap")]
            ReportFormat::Nmap => nmap::NmapXmlReportReader::new(options).read(input),
        }
    }
}

#[cfg(all(test, feature = "import-json", feature = "import-nmap"))]
mod tests {
    use std::io::Cursor;
    use std::path::Path;

    use super::*;

    /// A reader used directly holds its input to the ceiling its options set,
    /// as the dispatch over formats does. Its options are the only ceiling a
    /// caller who picked the format themselves was given, and a reader that
    /// left the bounding to a dispatch it was not called through would read a
    /// document of any size.
    #[test]
    fn a_reader_used_directly_holds_a_document_to_its_byte_ceiling() {
        let options = ReportOptions::new().with_max_document_bytes(16);
        let json = format!("{{\"hosts\": []{}}}", " ".repeat(64));
        let xml = format!("<nmaprun>{}</nmaprun>", "<a/>".repeat(16));

        let readers: [(&dyn ReportReader, &str); 3] = [
            (&json::JsonReportReader::new(options), &json),
            (&json::JsonLinesReportReader::new(options), &json),
            (&nmap::NmapXmlReportReader::new(options), &xml),
        ];
        for (reader, document) in readers {
            let read = reader.read(&mut Cursor::new(document.as_bytes()));
            assert!(
                matches!(read, Err(ImportError::DocumentTooLarge { limit: 16 })),
                "{document}: {read:?}"
            );
        }
    }

    #[test]
    fn an_extension_names_the_format() {
        assert_eq!(
            ReportFormat::from_path(Path::new("engagement/scan.xml")),
            Some(ReportFormat::Nmap)
        );
        assert_eq!(
            ReportFormat::from_path(Path::new("scan.JSON")),
            Some(ReportFormat::Json)
        );
        assert_eq!(ReportFormat::from_path(Path::new("scan.txt")), None);
    }

    #[test]
    fn the_first_byte_names_the_format_when_nothing_else_does() {
        let mut json = Cursor::new(b"  {\"schema_version\":1}".as_slice());
        assert_eq!(ReportFormat::sniff(&mut json).unwrap(), ReportFormat::Json);

        let mut xml = Cursor::new(b"<?xml version=\"1.0\"?><nmaprun/>".as_slice());
        assert_eq!(ReportFormat::sniff(&mut xml).unwrap(), ReportFormat::Nmap);

        let mut neither = Cursor::new(b"192.0.2.1\n".as_slice());
        assert!(ReportFormat::sniff(&mut neither).is_err());
    }

    #[test]
    fn sniffing_leaves_the_input_where_it_found_it() {
        let document = b"<?xml version=\"1.0\"?><nmaprun/>";
        let mut input = Cursor::new(document.as_slice());

        let format = ReportFormat::sniff(&mut input).unwrap();
        let report = format.read(&mut input, ReportOptions::new());

        assert!(
            report.is_ok(),
            "a sniff must not consume the bytes the reader needs: {report:?}"
        );
    }

    /// A document a Windows editor saved is still the document it is.
    ///
    /// A sniff that stripped no mark would refuse a report saved through
    /// `Out-File` as neither format, nmap XML included, which the reader
    /// behind it reads without complaint.
    #[test]
    fn a_byte_order_mark_hides_neither_format() {
        let marked = |text: &str| {
            let mut bytes = crate::format::UTF8_BOM.to_vec();
            bytes.extend_from_slice(text.as_bytes());
            Cursor::new(bytes)
        };

        for (document, expected) in [
            (r#"{"schema_version":1}"#, ReportFormat::Json),
            (
                "{\"type\":\"report\",\"schema_version\":1}\n",
                ReportFormat::JsonLines,
            ),
            (r#"<?xml version="1.0"?><nmaprun/>"#, ReportFormat::Nmap),
        ] {
            assert_eq!(
                ReportFormat::sniff(&mut marked(document)).expect("sniffs"),
                expected,
                "{document}"
            );
        }

        // And the reader named still reads what the sniff was looking at.
        let mut input = marked(r#"<?xml version="1.0"?><nmaprun/>"#);
        let format = ReportFormat::sniff(&mut input).expect("sniffs");
        assert!(
            format.read(&mut input, ReportOptions::new()).is_ok(),
            "the format was recognised and then refused the same bytes"
        );
    }

    /// What the export writers under test need, beyond the readers this module
    /// is built with.
    #[cfg(all(
        feature = "export-json",
        feature = "export-jsonl",
        feature = "export-nmap"
    ))]
    mod own_exports {
        use std::io::Cursor;
        use std::net::{IpAddr, Ipv4Addr};
        use std::time::Duration;

        use super::super::*;
        use crate::export::{
            ExportOptions, Exporter, JsonExporter, JsonLinesExporter, NmapXmlExporter,
        };
        use crate::import::xml::elements_within;
        use crate::model::host::Host;
        use crate::model::port::{Discovery, Port, PortState, Protocol, ScanResponse};

        /// How many hosts scanned across the full TCP range the documentation
        /// of [`ReportOptions::max_document_bytes`] says the default admits, in
        /// each format this engine writes a report in. Each leaves 15% or more
        /// of the ceiling for what the open ports on real hosts add.
        const FULL_RANGE_HOSTS_AS_JSON: u64 = 32;
        const FULL_RANGE_HOSTS_AS_JSON_LINES: u64 = 64;
        const FULL_RANGE_HOSTS_AS_XML: u64 = 128;

        /// A host scanned across the whole TCP range with every port closed,
        /// each carrying the fullest account a raw probe writes: the reset, its
        /// round trip and its TTL. The largest record per port a scan leaves
        /// when it finds nothing, which is what a full-range export is made of.
        fn full_range_report() -> ScanReport {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
            let mut host = Host::new(ip);
            for number in 1..=u16::MAX {
                host.add_port(
                    Port::new(number, Protocol::Tcp, PortState::Closed).with_discovery(
                        Discovery::new(ScanResponse::TcpRst)
                            .with_rtt(Duration::from_micros(1_234))
                            .with_ttl(64),
                    ),
                );
            }
            ScanReport::recorded("zond", Vec::new(), vec![host])
        }

        fn written(exporter: &dyn Exporter, report: &ScanReport) -> Vec<u8> {
            let mut out = Vec::new();
            exporter.export(report, &mut out).expect("exports");
            out
        }

        /// A record-per-line host is as long as its port list, and a
        /// full-range one is megabytes on one line. The line is part of a
        /// document, so the document's ceiling is what bounds it; the few
        /// kilobytes a target expression is allowed would refuse any host
        /// scanned across more than a few hundred ports.
        #[test]
        fn a_full_range_host_reads_back_from_its_own_record_per_line_export() {
            let report = full_range_report();
            let document = written(&JsonLinesExporter::new(ExportOptions::new()), &report);

            let restored = ReportFormat::JsonLines
                .read(&mut Cursor::new(document), ReportOptions::new())
                .expect("a document this engine wrote reads back");

            let host = restored.hosts().next().expect("the host");
            assert_eq!(host.port_count(), usize::from(u16::MAX));
        }

        /// The default ceiling is sized in hosts scanned across the full TCP
        /// range, and these are the counts its documentation promises, held
        /// against what the writers produce today. A writer that grows, or a
        /// ceiling that shrinks, fails here rather than in front of somebody
        /// comparing last month's engagement with this one's.
        #[test]
        fn the_default_ceiling_admits_the_full_range_hosts_it_promises() {
            let report = full_range_report();
            let ceiling = ReportOptions::new().max_document_bytes;

            let json = written(&JsonExporter::new(ExportOptions::new()), &report).len() as u64;
            let lines =
                written(&JsonLinesExporter::new(ExportOptions::new()), &report).len() as u64;
            let xml = written(&NmapXmlExporter::new(ExportOptions::new()), &report);
            let elements = xml
                .windows(2)
                .filter(|pair| pair[0] == b'<' && pair[1].is_ascii_alphabetic())
                .count() as u64;
            let xml = xml.len() as u64;

            for (format, bytes, promised) in [
                ("indented JSON", json, FULL_RANGE_HOSTS_AS_JSON),
                ("JSON lines", lines, FULL_RANGE_HOSTS_AS_JSON_LINES),
                ("nmap XML", xml, FULL_RANGE_HOSTS_AS_XML),
            ] {
                assert!(
                    bytes * promised <= ceiling,
                    "{promised} full-range hosts of {format} are {} bytes, past the {ceiling}-byte ceiling",
                    bytes * promised,
                );
            }

            // The element count is not the bound this engine's own XML meets
            // first: every document the byte ceiling admits is under it.
            assert!(
                ceiling / xml * elements <= elements_within(ceiling),
                "a document of full-range hosts at the byte ceiling holds {} elements, past {}",
                ceiling / xml * elements,
                elements_within(ceiling),
            );
        }
    }

    /// The extension is what the person who saved the file meant.
    #[test]
    fn an_extension_outranks_what_the_bytes_look_like() {
        let mut input = Cursor::new(b"{}".as_slice());
        assert_eq!(
            ReportFormat::resolve(Some(Path::new("scan.xml")), &mut input).unwrap(),
            ReportFormat::Nmap
        );
    }
}
