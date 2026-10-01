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
//! next: addresses and ports. This reads the same kind of document for what the
//! scan that produced it found, and builds the [`ScanReport`] that scan would have
//! produced.
//!
//! The target readers are narrow on purpose: [`import::json`](crate::import::json)
//! reads four fields, which leaves the exported schema free to move. The readers
//! here are separate, and the two directions share only the `xml` parsing
//! machinery.
//!
//! ## Use with diff
//!
//! [`diff`](crate::diff) compares two [`ScanReport`]s regardless of where either
//! came from: a scan this process ran, one read back from a
//! [`journal`](crate::journal), or one read from a file here. That makes last
//! quarter's nmap output against tonight's scan, or two archived exports against
//! each other, one call.
//!
//! ## Attribution
//!
//! A [`ScanReport`] built here is attributed to whatever wrote the document, such
//! as `nmap 7.94`, through
//! [`ScanReport::recorded`](crate::report::ScanReport::recorded), and
//! [`Provenance::engine_version`](crate::diff::Provenance::engine_version) returns
//! that unchanged. A report read here is no evidence that this engine's scanners
//! ran.
//!
//! ## Bounds
//!
//! The module documentation of [`import`](crate::import) applies here too. A
//! reader takes a [`BufRead`] and never opens a file, [`ImportLimits`] are passed
//! with each call, and exceeding one is an error naming what exceeded it.

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
/// The mirror of [`Exporter`](crate::export::Exporter). A reader returns the whole
/// report at once, since a report is one document whose header applies to
/// everything after it.
pub trait ReportReader {
    /// Reads `input` as one report.
    fn read(&self, input: &mut dyn BufRead) -> Result<ScanReport, ImportError>;
}

/// What a report reader is allowed to spend.
///
/// Wraps [`ImportLimits`] so that limits specific to report reading, such as
/// [`max_document_bytes`](Self::max_document_bytes), can be added without
/// touching the target side.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportOptions {
    /// The bounds shared with the target readers.
    ///
    /// [`max_addresses`](ImportLimits::max_addresses) bounds the hosts a document
    /// may name, in every reader. [`max_line_bytes`](ImportLimits::max_line_bytes)
    /// bounds one element's markup in the nmap reader only; a JSON lines record is
    /// as long as a host's port list, so both JSON readers are bounded by
    /// [`max_document_bytes`](Self::max_document_bytes) alone.
    /// [`max_tokens`](ImportLimits::max_tokens) counts target expressions and is
    /// ignored here.
    pub limits: ImportLimits,

    /// The most bytes one document may be read from.
    ///
    /// Every reader parses the whole document before returning, so this bounds
    /// what an untrusted file can make the process do. It is checked as bytes are
    /// consumed, so an oversized document is refused on the way in.
    ///
    /// The process holds a multiple of the document, so size this to the memory
    /// the process can afford. Measured in the shapes that cost most per byte:
    /// twenty hosts each listing every TCP port in the shortest possible entries
    /// took 64 MB of document and 5.8 times that resident at the peak; one host
    /// whose `ips` array carries four million addresses took 59.9 MB and 2.8
    /// times. Repeating one port entry or one address costs nothing extra, since
    /// ports are folded by endpoint and addresses into a set as they are read. At
    /// the default a hostile document can leave the process holding about 6 GiB,
    /// so a caller reading untrusted documents on a small machine should lower it.
    ///
    /// The default is 1 GiB, sized to read back what this engine writes. One host
    /// scanned across the whole TCP range and found closed is 26 MB of the
    /// exporter's default indented JSON, 14 MB of JSON lines and 6.5 MB of nmap
    /// XML, about 400, 216 and 99 bytes a port. The default admits 32, 64 and 128
    /// such hosts respectively, with a margin for services and findings on open
    /// ports. Reading them back holds less than the document in JSON and about
    /// three times it in XML. Raise it with
    /// [`with_max_document_bytes`](Self::with_max_document_bytes) for a vetted
    /// document, or pass [`u64::MAX`] to lift it.
    ///
    /// The element limit for XML documents is derived from this value, so it is
    /// the only size ceiling a caller needs to set.
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
/// The mirror of [`ImportFormat`](crate::import::ImportFormat), limited to the
/// formats that carry findings.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReportFormat {
    /// This engine's own exported JSON, as a single document.
    #[cfg(feature = "import-json")]
    Json,
    /// The same data one record per line, which is what
    /// [`export::jsonl`](crate::export::jsonl) writes.
    ///
    /// Read here as well as in [`ImportFormat`](crate::import::ImportFormat), since
    /// the format exists so that a scan cut short still leaves a readable report.
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
            // Matches what the exporter and the target-side reader accept.
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
    /// For front ends listing what they support, as
    /// [`ImportFormat::all`](crate::import::ImportFormat::all) is.
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
    /// Looks at the first byte: `<` is nmap XML and `{` is JSON. Telling a
    /// document apart beyond that is left to the reader, which names what it
    /// found when it refuses one.
    ///
    /// The two JSON shapes both open with a brace. The record-per-line one names
    /// itself in its first record, and that tag separates them, as in
    /// [`ImportFormat::sniff`](crate::import::ImportFormat::sniff). Read as a
    /// single document, a record-per-line export would parse its first line and
    /// return an empty report.
    pub fn sniff(input: &mut dyn BufRead) -> Result<Self, ImportError> {
        /// The header record's tag, as the compact exporter writes it.
        #[cfg(feature = "import-json")]
        const REPORT_TAG: &[u8] = br#""type":"report""#;

        let available = input.fill_buf()?;
        // Strip a byte order mark, as the target side does, or a document saved by
        // a Windows editor is refused as neither format.
        let prefix = crate::import::without_bom(available).trim_ascii_start();

        // Silences the unused-binding warning in a build with neither feature.
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
    /// The extension wins because it records what whoever saved the file meant.
    pub fn resolve(path: Option<&Path>, input: &mut dyn BufRead) -> Result<Self, ImportError> {
        match path.and_then(Self::from_path) {
            Some(format) => Ok(format),
            None => Self::sniff(input),
        }
    }

    /// Reads `input` as a report in this format.
    ///
    /// Refuses a document past [`ReportOptions::max_document_bytes`] before any
    /// reader sees the whole of it, and one naming more hosts than
    /// [`ImportLimits::max_addresses`] allows. Each reader enforces both itself,
    /// so one used directly is bounded the same way.
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

    /// A reader used directly enforces its byte ceiling, as the dispatch over
    /// formats does.
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

    /// A byte order mark, as `Out-File` writes, does not hide the format.
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

        // The chosen reader reads the same marked bytes.
        let mut input = marked(r#"<?xml version="1.0"?><nmaprun/>"#);
        let format = ReportFormat::sniff(&mut input).expect("sniffs");
        assert!(
            format.read(&mut input, ReportOptions::new()).is_ok(),
            "the format was recognised and then refused the same bytes"
        );
    }

    /// Tests that also need the export writers.
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

        /// How many full-TCP-range hosts the default ceiling admits per format, as
        /// documented on [`ReportOptions::max_document_bytes`]. Each leaves at
        /// least 15% of the ceiling for what open ports on real hosts add.
        const FULL_RANGE_HOSTS_AS_JSON: u64 = 32;
        const FULL_RANGE_HOSTS_AS_JSON_LINES: u64 = 64;
        const FULL_RANGE_HOSTS_AS_XML: u64 = 128;

        /// A host scanned across the whole TCP range with every port closed, each
        /// carrying the reset, its round trip and its TTL: the largest per-port
        /// record a scan that finds nothing writes.
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

        /// A full-range host is megabytes on one JSON lines record, bounded by the
        /// document ceiling. The line limit for target expressions would refuse
        /// any host with more than a few hundred ports.
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

        /// Holds the documented full-range host counts against what the writers
        /// produce, so a writer that grows or a ceiling that shrinks fails here.
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

            // Every XML document the byte ceiling admits is also under the element
            // limit.
            assert!(
                ceiling / xml * elements <= elements_within(ceiling),
                "a document of full-range hosts at the byte ceiling holds {} elements, past {}",
                ceiling / xml * elements,
                elements_within(ceiling),
            );
        }
    }

    #[test]
    fn an_extension_outranks_what_the_bytes_look_like() {
        let mut input = Cursor::new(b"{}".as_slice());
        assert_eq!(
            ReportFormat::resolve(Some(Path::new("scan.xml")), &mut input).unwrap(),
            ReportFormat::Nmap
        );
    }
}
