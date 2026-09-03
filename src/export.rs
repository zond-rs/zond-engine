// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Report Export
//!
//! Turns a finished [`ScanReport`] into a document somebody else can read: a
//! file on disk, a body in an HTTP response, a stream into another tool.
//!
//! ## Why the engine owns this
//!
//! A file written by the CLI, by a library consumer and by a web UI has to be
//! the same file, or the format is not a format. The schema and its
//! implementation live here, once, and a front end chooses only a format and a
//! destination.
//!
//! ## The shape of the thing
//!
//! - [`schema`] holds the data transfer objects. They are the wire format,
//!   written by hand rather than derived from the engine's working types. See
//!   that module for what the boundary buys.
//! - [`Exporter`] is the one trait a format implements. It takes a report and
//!   somewhere to write, and it streams.
//! - [`ExportOptions`] carries policy that is not the format's business, most
//!   of all [`Redaction`].
//!
//! ## Writing your own
//!
//! [`Exporter`] is public, and the DTOs are public and `Serialize`. A consumer
//! who wants PDF output or their own branded HTML writes an exporter in their
//! own crate, with their own templating engine, and this crate takes on no
//! dependency for it. There is no plugin system: dynamic loading in a process
//! holding raw-socket privileges buys nothing a trait does not.
//!
//! ```
//! use std::io::{self, Write};
//! use zond_engine::report::ScanReport;
//! use zond_engine::export::{ExportError, Exporter};
//!
//! /// Writes one line per host: the address and how many ports it had.
//! struct Tally;
//!
//! impl Exporter for Tally {
//!     fn export(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), ExportError> {
//!         for host in report.hosts() {
//!             writeln!(out, "{} {}", host.primary_ip(), host.port_count())?;
//!         }
//!         Ok(())
//!     }
//! }
//! ```
//!
//! ## Always to a writer, never to a string
//!
//! [`Exporter::export`] writes into a `dyn Write` and nothing in this module
//! returns a `String`. A /16 with a host on every address is a document larger
//! than anything worth holding in memory, and writing incrementally means a
//! consumer piping output somewhere sees the first host before the last one is
//! scanned out of the report.
//!
//! ## Features
//!
//! The DTOs and the trait are always available, costing nothing beyond `serde`,
//! which the engine already depends on. Each concrete format sits behind a cargo
//! feature so a consumer who wants none of them pays for none. `export-json` is
//! on by default.

pub mod diff;
pub mod redact;
pub mod schema;

#[cfg(any(
    feature = "export-json",
    feature = "export-jsonl",
    feature = "export-html"
))]
pub(crate) mod write;

#[cfg(feature = "export-json")]
pub mod json;

#[cfg(feature = "export-jsonl")]
pub mod jsonl;

#[cfg(feature = "export-csv")]
pub mod csv;

#[cfg(feature = "export-html")]
pub mod html;

#[cfg(feature = "export-nmap")]
pub mod nmap;

#[cfg(test)]
pub(crate) mod fixture;

#[cfg(all(test, feature = "export-json"))]
mod conformance;

use std::borrow::Cow;
use std::fmt;
use std::io::Write;
use std::path::Path;

use crate::model::mac::MacAddr;
use crate::report::ScanReport;

#[cfg(feature = "export-json")]
pub use json::JsonExporter;

#[cfg(feature = "export-jsonl")]
pub use jsonl::JsonLinesExporter;

#[cfg(feature = "export-csv")]
pub use csv::CsvExporter;

#[cfg(feature = "export-html")]
pub use html::HtmlExporter;

#[cfg(feature = "export-nmap")]
pub use nmap::NmapXmlExporter;

/// What went wrong while writing a report out.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// The destination refused the write: a full disk, a closed pipe, a
    /// permissions problem.
    #[error("writing the report failed: {0}")]
    Io(#[from] std::io::Error),

    /// The report could not be rendered in the target format.
    ///
    /// Separate from [`Io`](Self::Io) because the two call for opposite
    /// responses: a failed write may succeed against a different destination,
    /// while a failed render will not.
    #[error("rendering the report as {format} failed: {message}")]
    Render {
        /// The format that could not represent the report.
        format: &'static str,
        /// What could not be represented.
        message: String,
    },
}

/// One output format.
///
/// An exporter is a rendering of a report onto a writer. Every other decision it
/// needs, how much to redact or whether to indent, belongs to the value
/// implementing this trait and is chosen when that value is constructed, so a
/// consumer can implement it without reading this crate's options type.
pub trait Exporter {
    /// Writes `report` to `out`.
    ///
    /// Implementations must stream: the memory an export costs should be a
    /// function of the largest single host, not of the size of the scan.
    fn export(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), ExportError>;
}

/// How much identifying detail to strip on the way out.
///
/// Redaction is an export-time policy rather than something a caller does to a
/// report afterwards, because afterwards is where it gets forgotten. A report
/// destined for a client, an auditor or a bug tracker is masked at the one point
/// where the data leaves the process.
///
/// ## What is masked and what is not
///
/// [`Standard`](Self::Standard) masks the two things that identify a person or a
/// device: hostnames and hardware addresses. Hostnames keep their first and last
/// two characters, so `workstation` and `wifi-printer` stay distinguishable
/// without either being readable. MAC addresses keep their OUI, so the vendor
/// survives and the individual NIC does not.
///
/// IP addresses are left alone. A report is a list of hosts, and a masking
/// scheme that hides which host is which collapses ten records on a /24 into ten
/// copies of the same string. The addresses are also what makes the findings
/// actionable to a recipient who already knows the network they asked to have
/// scanned.
///
/// One residual leak is worth stating: an IPv6 address formed the old EUI-64 way
/// embeds the MAC that redaction masks elsewhere. A report from a network with
/// EUI-64 addressing is not free of hardware identifiers however this is set.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Redaction {
    /// Export what the scan found, unchanged.
    #[default]
    None,
    /// Mask hostnames and hardware addresses.
    Standard,
}

impl Redaction {
    /// Applies the policy to a hostname.
    ///
    /// Borrows when nothing is masked, so an unredacted export of a large scan
    /// does not allocate a string per host to hand back what it was given.
    pub fn hostname<'a>(self, name: &'a str) -> Cow<'a, str> {
        match self {
            Redaction::None => Cow::Borrowed(name),
            Redaction::Standard => Cow::Owned(redact::hostname(name)),
        }
    }

    /// Applies the policy to a hardware address.
    ///
    /// Returns an owned string either way: a [`MacAddr`] has no textual form to
    /// borrow.
    pub fn mac(self, mac: &MacAddr) -> String {
        match self {
            Redaction::None => mac.to_string(),
            Redaction::Standard => redact::mac_addr(mac),
        }
    }

    /// Whether this policy masks anything at all.
    pub fn is_active(self) -> bool {
        !matches!(self, Redaction::None)
    }
}

/// Policy that applies to an export regardless of the format it lands in.
///
/// Non-exhaustive and [`Default`]-constructed, so a future option is an
/// additive change rather than a break for everyone who built one of these.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ExportOptions {
    /// How much identifying detail to strip.
    pub redaction: Redaction,
}

impl ExportOptions {
    /// Options that export everything, unchanged.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the redaction policy.
    pub fn with_redaction(mut self, redaction: Redaction) -> Self {
        self.redaction = redaction;
        self
    }
}

/// The formats this build can write.
///
/// Front ends pick a format from a file extension rather than from a flag, since
/// `-o report.json` already says what the user wants. It lives in the engine so
/// every front end resolves the same extension to the same format.
///
/// Which variants exist depends on the cargo features the crate was built with.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportFormat {
    /// A single JSON document. The canonical format: everything the report
    /// holds, in the schema described by [`schema`].
    #[cfg(feature = "export-json")]
    Json,

    /// The same data as [`Json`](Self::Json), one record per line. Streamable,
    /// and a file cut off part way through is still readable.
    #[cfg(feature = "export-jsonl")]
    JsonLines,

    /// A flat table, one row per host and port. Lossy by design, for the
    /// spreadsheet and compliance audience.
    #[cfg(feature = "export-csv")]
    Csv,

    /// A single self-contained page: everything the report holds, laid out to
    /// be read rather than parsed, and to print.
    #[cfg(feature = "export-html")]
    Html,

    /// Nmap-compatible XML, for the ingest pipelines that already exist. Says
    /// `scanner="zond"`: it is nmap's format, not a claim to be nmap.
    #[cfg(feature = "export-nmap")]
    NmapXml,
}

impl ExportFormat {
    /// Resolves a file extension, case-insensitively and without a leading dot.
    ///
    /// Returns `None` for an extension no compiled-in format claims, which the
    /// caller should report as an unsupported format rather than silently
    /// writing JSON into a file named something else.
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.to_ascii_lowercase().as_str() {
            #[cfg(feature = "export-json")]
            "json" => Some(ExportFormat::Json),
            // `ndjson` is the other name the same format goes by. The
            // canonical spelling stays `jsonl`.
            #[cfg(feature = "export-jsonl")]
            "jsonl" | "ndjson" => Some(ExportFormat::JsonLines),
            #[cfg(feature = "export-csv")]
            "csv" => Some(ExportFormat::Csv),
            #[cfg(feature = "export-html")]
            "html" | "htm" => Some(ExportFormat::Html),
            #[cfg(feature = "export-nmap")]
            "xml" => Some(ExportFormat::NmapXml),
            _ => None,
        }
    }

    /// Resolves a path by its extension.
    ///
    /// A path with no extension has no format rather than a default one. A
    /// caller who wrote `-o report` has not said what they want.
    pub fn from_path(path: &Path) -> Option<Self> {
        path.extension()
            .and_then(|extension| extension.to_str())
            .and_then(Self::from_extension)
    }

    /// The canonical file extension for this format, without a leading dot.
    pub fn extension(self) -> &'static str {
        match self {
            #[cfg(feature = "export-json")]
            ExportFormat::Json => "json",
            #[cfg(feature = "export-jsonl")]
            ExportFormat::JsonLines => "jsonl",
            #[cfg(feature = "export-csv")]
            ExportFormat::Csv => "csv",
            #[cfg(feature = "export-html")]
            ExportFormat::Html => "html",
            #[cfg(feature = "export-nmap")]
            ExportFormat::NmapXml => "xml",
        }
    }

    /// Every format this build can write.
    ///
    /// Front ends use this to describe their own capabilities, since a help
    /// text listing formats the binary was not built with is worse than none.
    pub fn all() -> &'static [ExportFormat] {
        &[
            #[cfg(feature = "export-json")]
            ExportFormat::Json,
            #[cfg(feature = "export-jsonl")]
            ExportFormat::JsonLines,
            #[cfg(feature = "export-csv")]
            ExportFormat::Csv,
            #[cfg(feature = "export-html")]
            ExportFormat::Html,
            #[cfg(feature = "export-nmap")]
            ExportFormat::NmapXml,
        ]
    }

    /// Builds an exporter for this format under the given options.
    pub fn exporter(self, options: ExportOptions) -> Box<dyn Exporter> {
        // A build with no format feature on has no match arm to hand the
        // options to, and an unused parameter would warn. Such a build cannot
        // reach here anyway: `ExportFormat` has no variants to construct.
        let _ = &options;

        match self {
            #[cfg(feature = "export-json")]
            ExportFormat::Json => Box::new(JsonExporter::new(options)),
            #[cfg(feature = "export-jsonl")]
            ExportFormat::JsonLines => Box::new(JsonLinesExporter::new(options)),
            #[cfg(feature = "export-csv")]
            ExportFormat::Csv => Box::new(CsvExporter::new(options)),
            #[cfg(feature = "export-html")]
            ExportFormat::Html => Box::new(HtmlExporter::new(options)),
            #[cfg(feature = "export-nmap")]
            ExportFormat::NmapXml => Box::new(NmapXmlExporter::new(options)),
        }
    }
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.extension())
    }
}

/// Writes a report in the format named by `path`'s extension.
///
/// The convenience over [`ExportFormat::exporter`] is small and the consistency
/// is not: every front end that resolves a destination to a format should do it
/// the same way.
///
/// Returns `None` if the extension names no format this build supports, leaving
/// the caller to decide what to tell the user. The report is written to `out`,
/// not to `path`; opening the destination, and deciding whether overwriting it
/// is acceptable, stays with the caller.
pub fn export_to(
    path: &Path,
    report: &ScanReport,
    out: &mut dyn Write,
    options: ExportOptions,
) -> Option<Result<(), ExportError>> {
    let format = ExportFormat::from_path(path)?;
    Some(format.exporter(options).export(report, out))
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

    #[test]
    fn no_redaction_borrows_rather_than_copying() {
        let borrowed = Redaction::None.hostname("workstation");

        assert!(matches!(borrowed, Cow::Borrowed(_)));
        assert_eq!(borrowed, "workstation");
        assert!(!Redaction::None.is_active());
    }

    /// Masked hostnames must stay distinguishable from each other, or a report
    /// of ten devices becomes a report of one device ten times.
    #[test]
    fn standard_redaction_masks_but_keeps_records_apart() {
        let workstation = Redaction::Standard.hostname("workstation");
        let printer = Redaction::Standard.hostname("wifi-printer");

        assert_eq!(workstation, "woXXXXXon");
        assert_ne!(workstation, printer);
        assert!(Redaction::Standard.is_active());
    }

    /// The vendor has to survive masking. It is the OUI, which is what masking
    /// keeps, and a report without vendors is much less useful for no privacy
    /// gained.
    #[test]
    fn standard_redaction_keeps_the_oui_and_drops_the_device() {
        let mac = MacAddr::new(0x2c, 0xcf, 0x67, 0xf2, 0x51, 0xe3);

        assert_eq!(Redaction::None.mac(&mac), "2c:cf:67:f2:51:e3");
        assert_eq!(Redaction::Standard.mac(&mac), "2c:cf:67:XX:XX:XX");
    }

    #[test]
    fn a_format_is_resolved_from_a_path_case_insensitively() {
        #[cfg(feature = "export-json")]
        {
            assert_eq!(
                ExportFormat::from_path(Path::new("/tmp/scan.JSON")),
                Some(ExportFormat::Json)
            );
            assert_eq!(ExportFormat::Json.extension(), "json");
            assert_eq!(ExportFormat::Json.to_string(), "json");
        }

        // A destination that names no format must not silently acquire one.
        assert_eq!(ExportFormat::from_path(Path::new("/tmp/scan")), None);
        assert_eq!(ExportFormat::from_extension("pdf"), None);
    }

    /// Anything [`ExportFormat::all`] advertises has to actually produce a
    /// document, or a front end built the same way lists a format it cannot
    /// write.
    #[test]
    fn every_advertised_format_can_build_an_exporter() {
        let report = super::fixture::report();

        for format in ExportFormat::all() {
            let mut sink = Vec::new();

            format
                .exporter(ExportOptions::new())
                .export(&report, &mut sink)
                .expect("an advertised format exports");

            assert!(!sink.is_empty(), "{format} produced nothing at all");
            assert_eq!(
                ExportFormat::from_extension(format.extension()),
                Some(*format),
                "{format} does not resolve from its own extension"
            );
        }
    }

    /// The path-driven entry point has to reach the same exporter a caller
    /// would have built by hand, or the two ways of exporting diverge.
    #[test]
    fn exporting_by_path_matches_exporting_by_format() {
        let report = super::fixture::report();

        for format in ExportFormat::all() {
            let name = format!("scan.{}", format.extension());

            let mut by_path = Vec::new();
            export_to(
                Path::new(&name),
                &report,
                &mut by_path,
                ExportOptions::new(),
            )
            .expect("the extension names a format")
            .expect("the export succeeds");

            assert!(!by_path.is_empty());
        }

        let mut sink = Vec::new();
        assert!(
            export_to(
                Path::new("scan.pdf"),
                &report,
                &mut sink,
                ExportOptions::new()
            )
            .is_none(),
            "an unsupported extension must not quietly produce a file"
        );
        assert!(sink.is_empty());
    }
}
