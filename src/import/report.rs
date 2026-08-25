// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reading a document as findings
//!
//! The rest of [`import`](crate::import) reads a document for the **targets to
//! scan next**: addresses and ports, everything else skipped. This reads the
//! same kind of document for **what the scan that produced it found**, and
//! builds the [`ScanReport`] that scan would have produced.
//!
//! ## Why both, and why they stay apart
//!
//! "Rescan what I found" and "tell me what this scan found" are different jobs
//! with opposite instincts. The target readers are narrow on purpose and say so:
//! [`import::json`](crate::import::json) reads four fields and calls that
//! narrowness the feature, because the exported schema stays free to move while
//! nothing promises to read most of it. Widening them to carry findings would
//! spend that freedom to serve a different caller.
//!
//! So the readers here are separate, and the two directions share only the
//! parsing machinery that has no opinion about either — `xml` for
//! the documents that are XML.
//!
//! ## What this unlocks
//!
//! [`diff`](crate::diff) compares two [`ScanReport`]s and asks nothing about
//! where either came from. A scan this process ran, a scan read back out of a
//! [`journal`](crate::journal), and a scan read back out of a *file* are the
//! same input to it. This module is what puts the third one in reach — and a
//! file is what people actually archive, where a journal is state a machine
//! keeps and prunes.
//!
//! So: last quarter's nmap output against tonight's scan is one call, two nmap
//! files against each other is one call, and an exported report from a build
//! that has since been upgraded against a fresh one is one call.
//!
//! ## A report is not evidence that this engine produced it
//!
//! A [`ScanReport`] built here is attributed to whatever wrote the document —
//! `nmap 7.94`, not this crate — through
//! [`ScanReport::recorded`](crate::scanner::report::ScanReport::recorded), and
//! [`Provenance::engine_version`](crate::diff::Provenance::engine_version) hands
//! that back unchanged. Nothing downstream should read a report as proof this
//! engine's scanners ran.
//!
//! ## The same bounds, and the same refusal to open anything
//!
//! Everything the module documentation of [`import`](crate::import) says applies
//! here without exception. A reader takes a [`BufRead`] and never opens a file,
//! [`ImportLimits`] are part of the call rather than a constant, and exceeding
//! one is an error naming what exceeded it.

#[cfg(feature = "import-json")]
pub mod json;

#[cfg(feature = "import-nmap")]
pub mod nmap;

use std::io::BufRead;
use std::path::Path;

use crate::import::{ImportError, ImportLimits};
use crate::scanner::report::ScanReport;

/// Reads a document as the report of the scan that produced it.
///
/// The mirror of [`Exporter`](crate::export::Exporter), which writes one. A
/// reader takes bytes from wherever the caller got them and returns the whole
/// report, because a report is a document with a shape rather than a stream of
/// independent records: the phase it belongs to is stated once, at the top.
pub trait ReportReader {
    /// Reads `input` as one report.
    fn read(&self, input: &mut dyn BufRead) -> Result<ScanReport, ImportError>;
}

/// What a report reader is allowed to spend.
///
/// A struct rather than a bare [`ImportLimits`] so that a policy this side needs
/// and the target side does not stays an additive change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReportOptions {
    /// The bounds every reader here obeys.
    pub limits: ImportLimits,
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
}

/// A document format a report can be read from.
///
/// The mirror of [`ImportFormat`](crate::import::ImportFormat) for this
/// direction, and shorter: a report is a document some scanner wrote, and only
/// the formats that carry findings appear here. There is no list format, because
/// a list of addresses is not a report of anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReportFormat {
    /// This engine's own exported JSON.
    #[cfg(feature = "import-json")]
    Json,
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
            #[cfg(feature = "import-nmap")]
            "xml" => Some(ReportFormat::Nmap),
            _ => None,
        }
    }

    /// The format a path's extension names.
    pub fn from_path(path: &Path) -> Option<Self> {
        path.extension()
            .and_then(|extension| extension.to_str())
            .and_then(Self::from_extension)
    }

    /// The format the first byte of `input` implies, without consuming it.
    ///
    /// One byte decides: a report document is an object or an element, and
    /// nothing else. Deliberately not a content sniff — which document *this* is
    /// is the reader's question, and each refuses one it does not recognise by
    /// naming what it found.
    pub fn sniff(input: &mut dyn BufRead) -> Result<Self, ImportError> {
        let available = input.fill_buf()?;
        let first = available.iter().find(|byte| !byte.is_ascii_whitespace());

        match first {
            #[cfg(feature = "import-json")]
            Some(b'{') => Ok(ReportFormat::Json),
            #[cfg(feature = "import-nmap")]
            Some(b'<') => Ok(ReportFormat::Nmap),
            _ => Err(ImportError::Malformed {
                format: "report",
                origin: crate::import::Origin::unknown(),
                message: "the input begins as neither a JSON document nor an XML one".to_string(),
            }),
        }
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
    pub fn read(
        self,
        input: &mut dyn BufRead,
        options: ReportOptions,
    ) -> Result<ScanReport, ImportError> {
        match self {
            #[cfg(feature = "import-json")]
            ReportFormat::Json => json::JsonReportReader::new(options).read(input),
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
