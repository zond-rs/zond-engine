// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Writing a comparison out
//!
//! What [`export`](crate::export) is to a [`ScanReport`](crate::ScanReport),
//! this is to a [`ScanDiff`]: a document for whoever acts on the changes, such as
//! an alerting rule, a ticket or a review queue.
//!
//! ## Every change is one scalar fact
//!
//! A change is `{kind, before, after}`: a fixed token saying which field moved,
//! and the two values, either of which may be `null`. A host that gained three
//! addresses produces three changes.
//!
//! The engine's own [`HostChange`](crate::diff::HostChange) and
//! [`PortChange`](crate::diff::PortChange) group set changes together; the
//! document flattens them so a rule engine handles one shape, and a `kind` maps
//! onto "alert me when this happens". A front end's per-line output uses the same
//! flattening, so the terminal and the document name the same events the same way.
//!
//! ## What a consumer must not lose
//!
//! Every host and every endpoint carries `confirmed` and `significance`, and the
//! document carries one of its own. Both are derivable (from the presence and the
//! other scan's coverage, and from
//! [`Significance`](crate::diff::Significance)'s table) and are stated anyway,
//! because alerting rules key on them. Ignoring `confirmed` reports hosts as gone
//! every time a scan is narrowed, which [`diff`](crate::diff) is arranged to
//! prevent; ignoring `significance` pages somebody because a reverse name moved.
//!
//! A rule that reads only one of them should read `significance`, which already
//! answers `routine` for anything the comparison cannot vouch for.
//!
//! ## The records on either side
//!
//! Each host delta carries the whole [`HostDto`](crate::export::schema::HostDto)
//! from each side that has one, in the report document's own schema, so a ticket
//! or dashboard can show the host without another lookup. A consumer that wants
//! only the changes ignores those two fields.
//!
//! ## Choosing a format
//!
//! [`DiffFormat`] resolves one from a destination's extension and
//! [`DiffFormat::all`] names every one this build can write, as
//! [`ExportFormat`](crate::export::ExportFormat) does for a report.
//!
//! ## Versioned apart from the report
//!
//! The document declares [`DIFF_SCHEMA_VERSION`](schema::DIFF_SCHEMA_VERSION),
//! which is counted separately from the report's. See that constant for why.

pub mod schema;

#[cfg(feature = "export-html")]
pub mod html;

#[cfg(feature = "export-json")]
pub mod json;

use std::fmt;
use std::io::Write;
use std::path::Path;

use crate::diff::ScanDiff;
use crate::export::{ExportError, ExportOptions};

#[cfg(feature = "export-html")]
pub use html::HtmlDiffExporter;

#[cfg(feature = "export-json")]
pub use json::JsonDiffExporter;

/// One output format for a comparison.
///
/// The counterpart of [`Exporter`](crate::export::Exporter) for a [`ScanDiff`].
/// One type may implement both.
pub trait DiffExporter {
    /// Writes `diff` to `out`.
    ///
    /// Implementations must stream: memory should scale with the largest single
    /// host, not with how many hosts changed.
    fn export(&self, diff: &ScanDiff, out: &mut dyn Write) -> Result<(), ExportError>;
}

/// The comparison formats this build can write.
///
/// The counterpart of [`ExportFormat`](crate::export::ExportFormat), including
/// resolving an output path such as `changes.json` to a format. A front end
/// offering the user a choice should list [`all`](Self::all), so it only offers
/// what this build can write.
///
/// Which variants exist depends on the cargo features the crate was built with.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffFormat {
    /// A single JSON document, in the schema [`schema`] describes. What a
    /// pipeline ingests.
    #[cfg(feature = "export-json")]
    Json,

    /// A single self-contained page. What a nightly job attaches to an email.
    #[cfg(feature = "export-html")]
    Html,
}

impl DiffFormat {
    /// Resolves a file extension, case-insensitively and without a leading dot.
    ///
    /// Returns `None` for an extension no compiled-in format claims.
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.to_ascii_lowercase().as_str() {
            #[cfg(feature = "export-json")]
            "json" => Some(DiffFormat::Json),
            #[cfg(feature = "export-html")]
            "html" | "htm" => Some(DiffFormat::Html),
            _ => None,
        }
    }

    /// Resolves a path by its extension.
    ///
    /// A path with no extension has no format, as with
    /// [`ExportFormat::from_path`](crate::export::ExportFormat::from_path).
    pub fn from_path(path: &Path) -> Option<Self> {
        path.extension()
            .and_then(|extension| extension.to_str())
            .and_then(Self::from_extension)
    }

    /// The canonical file extension for this format, without a leading dot.
    pub fn extension(self) -> &'static str {
        match self {
            #[cfg(feature = "export-json")]
            DiffFormat::Json => "json",
            #[cfg(feature = "export-html")]
            DiffFormat::Html => "html",
        }
    }

    /// Every comparison format this build can write.
    pub fn all() -> &'static [DiffFormat] {
        &[
            #[cfg(feature = "export-json")]
            DiffFormat::Json,
            #[cfg(feature = "export-html")]
            DiffFormat::Html,
        ]
    }

    /// Builds an exporter for this format under the given options.
    pub fn exporter(self, options: ExportOptions) -> Box<dyn DiffExporter> {
        // Bound before the match for the reason `ExportFormat::exporter` gives.
        let _ = &options;

        match self {
            #[cfg(feature = "export-json")]
            DiffFormat::Json => Box::new(JsonDiffExporter::new(options)),
            #[cfg(feature = "export-html")]
            DiffFormat::Html => Box::new(HtmlDiffExporter::new(options)),
        }
    }
}

impl fmt::Display for DiffFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.extension())
    }
}

/// Writes a comparison in the format named by `path`'s extension.
///
/// Returns `None` if the extension names no format this build supports. The
/// comparison is written to `out`; `path` only selects the format, and opening
/// the destination is the caller's job.
pub fn export_to(
    path: &Path,
    diff: &ScanDiff,
    out: &mut dyn Write,
    options: ExportOptions,
) -> Option<Result<(), ExportError>> {
    let format = DiffFormat::from_path(path)?;
    Some(format.exporter(options).export(diff, out))
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

    /// Anything [`DiffFormat::all`] advertises resolves from its own extension
    /// and produces a document.
    #[test]
    fn every_advertised_format_writes_and_resolves_from_its_own_extension() {
        let diff = ScanDiff::between(
            &crate::export::fixture::report(),
            &crate::export::fixture::report(),
        );

        for format in DiffFormat::all() {
            assert_eq!(
                DiffFormat::from_extension(format.extension()),
                Some(*format),
                "{format} does not resolve from its own extension"
            );

            let mut sink = Vec::new();
            format
                .exporter(ExportOptions::new())
                .export(&diff, &mut sink)
                .expect("an advertised format exports");
            assert!(!sink.is_empty(), "{format} produced nothing at all");
        }
    }

    /// [`export_to`] writes every format by path, and an unknown extension
    /// writes nothing.
    #[test]
    fn exporting_by_path_matches_exporting_by_format() {
        let diff = ScanDiff::between(
            &crate::export::fixture::report(),
            &crate::export::fixture::report(),
        );

        for format in DiffFormat::all() {
            let name = format!("changes.{}", format.extension());
            let mut by_path = Vec::new();

            export_to(Path::new(&name), &diff, &mut by_path, ExportOptions::new())
                .expect("the extension names a format")
                .expect("the export succeeds");

            assert!(!by_path.is_empty());
        }

        let mut sink = Vec::new();
        assert!(
            export_to(
                Path::new("changes.pdf"),
                &diff,
                &mut sink,
                ExportOptions::new()
            )
            .is_none(),
            "an unsupported extension must not quietly produce a file"
        );
        assert!(sink.is_empty());
    }
}
