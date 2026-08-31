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
    /// [`max_line_bytes`](ImportLimits::max_line_bytes) binds the line-oriented
    /// nmap reader; a JSON document is one value and has no lines to bound, so
    /// [`max_document_bytes`](Self::max_document_bytes) is what stands in its
    /// place. [`max_tokens`](ImportLimits::max_tokens) counts target
    /// expressions and a report holds none, so nothing here reads it.
    pub limits: ImportLimits,

    /// The most bytes one document may be read from.
    ///
    /// Every reader here parses a whole document before it returns one, so this
    /// is the ceiling on what an untrusted file may make the process allocate.
    /// It is checked as the bytes are consumed, so a document past the ceiling
    /// is refused on the way in rather than after it has been held.
    ///
    /// The default is 256 MiB. An exported report of a hundred thousand hosts
    /// with their services and findings runs to a few tens of megabytes, so the
    /// ceiling is several times past anything a scan produces and still a
    /// bound. Raise it with [`with_max_document_bytes`](Self::with_max_document_bytes)
    /// for a document that has been vetted, or pass [`u64::MAX`] to lift it.
    pub max_document_bytes: u64,
}

/// 256 MiB. See [`ReportOptions::max_document_bytes`].
const DEFAULT_MAX_DOCUMENT_BYTES: u64 = 256 * 1024 * 1024;

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

/// A reader that refuses to hand out more than `limit` bytes.
///
/// Wrapped around the caller's input at the dispatch rather than inside each
/// reader, so the ceiling holds for every format and a format added later
/// inherits it instead of having to remember it.
struct Bounded<'a> {
    inner: &'a mut dyn BufRead,
    left: u64,
    /// Whether the budget ran out, which is all the dispatch needs back. A flag
    /// rather than a distinguishable error: the refusal travels out through
    /// `serde_json` and through [`xml`](crate::import::xml), and both rewrite an
    /// I/O failure into an error of their own. Asking afterwards is exact where
    /// reading the
    /// message that came back would be a guess.
    exhausted: bool,
}

impl<'a> Bounded<'a> {
    fn new(inner: &'a mut dyn BufRead, limit: u64) -> Self {
        Self {
            inner,
            left: limit,
            exhausted: false,
        }
    }

    fn over_budget(&mut self) -> std::io::Error {
        self.exhausted = true;
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the document is past its byte ceiling",
        )
    }
}

impl Bounded<'_> {
    /// Whether a reader asking for more bytes is asking for more than the
    /// budget, rather than asking how it ends.
    ///
    /// A spent budget is not by itself an overrun. A document of exactly
    /// `max_document_bytes` has been handed over whole, and a parser then asks
    /// once more because that is how it learns there is nothing after the value
    /// it read. Refusing that reading would make the ceiling refuse the largest
    /// document it is supposed to admit.
    fn overran(&mut self) -> std::io::Result<bool> {
        Ok(self.left == 0 && !self.inner.fill_buf()?.is_empty())
    }
}

impl std::io::Read for Bounded<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.overran()? {
            return Err(self.over_budget());
        }
        let ceiling = usize::try_from(self.left).unwrap_or(usize::MAX);
        let take = buf.len().min(ceiling);
        let read = self.inner.read(&mut buf[..take])?;
        self.left -= read as u64;
        Ok(read)
    }
}

impl BufRead for Bounded<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.overran()? {
            return Err(self.over_budget());
        }
        let ceiling = usize::try_from(self.left).unwrap_or(usize::MAX);
        let available = self.inner.fill_buf()?;
        Ok(&available[..available.len().min(ceiling)])
    }

    fn consume(&mut self, amount: usize) {
        self.left = self.left.saturating_sub(amount as u64);
        self.inner.consume(amount);
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
    /// [`ImportLimits::max_addresses`] allows.
    pub fn read(
        self,
        input: &mut dyn BufRead,
        options: ReportOptions,
    ) -> Result<ScanReport, ImportError> {
        let limit = options.max_document_bytes;
        let mut bounded = Bounded::new(input, limit);

        let read = match self {
            #[cfg(feature = "import-json")]
            ReportFormat::Json => json::JsonReportReader::new(options).read(&mut bounded),
            #[cfg(feature = "import-json")]
            ReportFormat::JsonLines => json::JsonLinesReportReader::new(options).read(&mut bounded),
            #[cfg(feature = "import-nmap")]
            ReportFormat::Nmap => nmap::NmapXmlReportReader::new(options).read(&mut bounded),
        };

        match read {
            Err(_) if bounded.exhausted => Err(ImportError::DocumentTooLarge { limit }),
            other => other,
        }
    }
}

#[cfg(all(test, feature = "import-json", feature = "import-nmap"))]
mod tests {
    use std::io::Cursor;
    use std::path::Path;

    use super::*;

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

        let mut neither = Cursor::new(b"192.168.0.1\n".as_slice());
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
    /// This side stripped no mark at all, so a report saved through
    /// `Out-File` was refused as neither format, nmap XML included, which
    /// the reader behind it would have read without complaint.
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
