// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Report Export
//!
//! Turns a finished [`ScanReport`] into a document: a file on disk, an HTTP
//! response body, a stream into another tool.
//!
//! The schema and its implementation live in the engine so that the CLI, a
//! library consumer and a web UI all write the same file. A front end chooses
//! only a format and a destination.
//!
//! - [`schema`] holds the data transfer objects. They are the wire format,
//!   written by hand and kept apart from the engine's working types.
//! - [`Exporter`] is the one trait a format implements. It takes a report and
//!   somewhere to write, and it streams.
//! - [`ExportOptions`] carries format-independent policy, chiefly
//!   [`Redaction`].
//!
//! ## Writing your own
//!
//! [`Exporter`] is public, and the DTOs are public and `Serialize`. A consumer
//! who wants PDF output or their own branded HTML writes an exporter in their
//! own crate, with their own templating engine.
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
//! ## Streaming
//!
//! [`Exporter::export`] writes into a `dyn Write`; nothing in this module
//! returns a `String`. A /16 with a host on every address is too large to hold
//! in memory, and a consumer piping the output sees the first host early.
//!
//! ## Features
//!
//! The DTOs and the trait are always available and need only `serde`. Each
//! concrete format sits behind a cargo feature. `export-json` is on by default.

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

use crate::diff::HostDelta;
use crate::model::host::{Host, HostName};
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
    /// Unlike [`Io`](Self::Io), retrying against another destination will not
    /// help.
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
/// Renders a report onto a writer. Settings such as redaction or indentation
/// belong to the implementing value and are chosen when it is constructed.
pub trait Exporter {
    /// Writes `report` to `out`.
    ///
    /// Implementations must stream: the memory an export costs should be a
    /// function of the largest single host, not of the size of the scan.
    fn export(&self, report: &ScanReport, out: &mut dyn Write) -> Result<(), ExportError>;
}

/// How much identifying detail to strip on the way out.
///
/// Applied at export, the one point where the data leaves the process.
///
/// ## What is masked
///
/// [`Standard`](Self::Standard) masks names and hardware addresses. Hostnames
/// keep their first and last two characters, so `workstation` and
/// `wifi-printer` stay distinguishable without being readable. MAC addresses
/// keep their OUI, so the vendor survives and the individual NIC does not.
///
/// Every name a host carries is masked the same way: the hostname, the names
/// it gives for itself ([`Host::names`](crate::model::host::Host::names)), a
/// certificate's subject, and a domain or forest, which names the
/// organisation and is the most identifying string a report carries.
///
/// Those names are also masked in free text the host's replies wrote, through
/// [`HostRedaction`]; an excerpt that is not text is withheld whole. A
/// comparison masks both of a host's records by every name either scan knew it
/// by, and a merged report by every name any of its sources did, since each
/// record's text can name the host by a name only the other states.
///
/// IP addresses are left alone. Masking them would collapse ten records on a
/// /24 into ten copies of one string, and they are what makes the findings
/// actionable to a recipient who knows the network.
///
/// ## Residual leaks
///
/// - An IPv6 address formed the EUI-64 way embeds the MAC, whatever this is
///   set to.
/// - A name a host wrote into a text reply without any protocol stating it as
///   a name, such as an HTTP banner naming a machine the scan found no other
///   name for, survives. A merged report written plain and redacted when read
///   back leaks this way for every name the merge did not keep.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Redaction {
    /// Export what the scan found, unchanged.
    #[default]
    None,
    /// Mask host and domain names and hardware addresses.
    Standard,
}

impl Redaction {
    /// Applies the policy to a hostname, or to any other name a report
    /// carries for a host or its domain.
    ///
    /// Borrows when nothing is masked.
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

    /// The policy as it applies to `host`'s record, for the free text its
    /// replies filled.
    pub fn for_host(self, host: &Host) -> HostRedaction {
        self.for_hosts([host])
    }

    /// The policy as it applies to both records a comparison holds of one
    /// host, masking the names either scan knew it by in the text of both. A
    /// name one scan dropped can still appear in the other's text. Every part
    /// of a comparison that renders either record reads it through this.
    pub fn for_delta(self, delta: &HostDelta) -> HostRedaction {
        self.for_hosts(delta.baseline().into_iter().chain(delta.current()))
    }

    fn for_hosts<'h>(self, hosts: impl IntoIterator<Item = &'h Host>) -> HostRedaction {
        HostRedaction {
            redaction: self,
            needles: if self.is_active() {
                redact::Needle::for_names(hosts.into_iter().flat_map(host_names))
            } else {
                Vec::new()
            },
        }
    }
}

/// The redaction policy as it applies to one host's record: the names that
/// host is known by, masked wherever its own replies wrote them.
///
/// A name reaches a report in two ways. The host's hostname and the names it
/// gave for itself ([`Host::names`]) are fields, masked by
/// [`Redaction::hostname`]. The same names also sit inside text the host sent:
/// a finding's excerpt of the reply, a title a detection filled from it, a
/// service's extra information, an issuer naming the machine that issued it.
/// This finds them there in any case, and in UTF-16LE read a byte to a
/// character, which is how SMB, NTLM and Kerberos carry a name. Each is
/// replaced by the mask its field shows, so a reader still sees which name a
/// line spoke of. The first label of a dotted name is also matched on its own,
/// as a banner gives the machine's name, and so is each later label but the
/// top-level one, as a directory spells a domain in `DC=` parts. Labels under
/// three characters and generic ones such as the `com` of `example.com.au` are
/// left alone.
///
/// Under redaction, an excerpt that is not text is withheld whole
/// ([`excerpt`](Self::excerpt)): a binary reply holds names in forms a text
/// search cannot be sure of.
///
/// Every exporter in this crate reads a host's free text through one of
/// these: a finding's title, excerpt, remediation, platform identifiers and
/// links, a service's product, version and extra information, an operating
/// system's name and evidence, a certificate's issuer, the hardware's vendor,
/// product, family, model and version, and the details of the evidence that
/// the host is up. A front end printing any of them should do the same.
///
/// # Examples
/// ```
/// use zond_engine::export::Redaction;
/// use zond_engine::model::host::{Host, HostName, NameKind, NameSource};
///
/// let mut host = Host::new("192.0.2.10".parse().unwrap());
/// host.record_name(HostName::new(NameKind::NetbiosDomain, NameSource::Smb, "EXAMPLE").unwrap());
///
/// let masking = Redaction::Standard.for_host(&host);
/// assert_eq!(masking.text("Workgroup: EXAMPLE"), "Workgroup: EXXXXXXLE");
/// assert_eq!(masking.text("E\0X\0A\0M\0P\0L\0E\0"), "EXXXXXXLE");
/// assert_eq!(Redaction::None.for_host(&host).text("EXAMPLE"), "EXAMPLE");
/// ```
///
/// The [`Default`] masks nothing, for a part of a record rendered with no
/// policy in force.
#[derive(Debug, Clone, Default)]
pub struct HostRedaction {
    redaction: Redaction,
    needles: Vec<redact::Needle>,
}

impl HostRedaction {
    /// The policy in force, for the fields it applies to directly.
    pub fn redaction(&self) -> Redaction {
        self.redaction
    }

    /// Free text the host's replies filled, with every name it is known by
    /// masked. Borrows when nothing is masked.
    pub fn text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        redact::names_in(text, &self.needles)
    }

    /// A finding's excerpt: masked as [`text`](Self::text) is where it is
    /// text, and replaced by a note saying it was withheld where it is not.
    pub fn excerpt<'a>(&self, excerpt: &'a str) -> Cow<'a, str> {
        if self.redaction.is_active() && redact::is_binary(excerpt) {
            Cow::Borrowed(redact::WITHHELD_EXCERPT)
        } else {
            self.text(excerpt)
        }
    }
}

/// Every name a host is known by: its hostname, the names it gave, and the
/// names a fold of its records set aside, which the text kept from those
/// records still holds.
fn host_names(host: &Host) -> impl Iterator<Item = &str> {
    host.hostname()
        .into_iter()
        .chain(host.names().map(HostName::name))
        .chain(host.set_aside_names())
}

/// Policy that applies to an export regardless of the format it lands in.
///
/// Non-exhaustive and [`Default`]-constructed, so adding an option is not a
/// breaking change.
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
/// Resolved from a file extension, so every front end maps the same extension
/// to the same format.
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

    /// A single self-contained page holding everything the report holds, laid
    /// out for reading and printing.
    #[cfg(feature = "export-html")]
    Html,

    /// Nmap-compatible XML, for existing ingest pipelines. Written with
    /// `scanner="zond"`.
    #[cfg(feature = "export-nmap")]
    NmapXml,
}

impl ExportFormat {
    /// Resolves a file extension, case-insensitively and without a leading dot.
    ///
    /// Returns `None` for an extension no compiled-in format claims.
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.to_ascii_lowercase().as_str() {
            #[cfg(feature = "export-json")]
            "json" => Some(ExportFormat::Json),
            // `ndjson` is another name for the same format.
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
    /// A path with no extension has no format.
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
    /// Depends on the enabled cargo features.
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
        // Silences the unused warning in a build with no format feature, which
        // cannot reach here: `ExportFormat` then has no variants.
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
/// Returns `None` if the extension names no format this build supports. The
/// report is written to `out`, not to `path`: opening the destination, and
/// deciding whether to overwrite it, is the caller's job.
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

    /// The OUI, and with it the vendor, survives masking.
    #[test]
    fn standard_redaction_keeps_the_oui_and_drops_the_device() {
        let mac = MacAddr::new(0x2c, 0xcf, 0x67, 0x00, 0x00, 0x01);

        assert_eq!(Redaction::None.mac(&mac), "2c:cf:67:00:00:01");
        assert_eq!(Redaction::Standard.mac(&mac), "2c:cf:67:XX:XX:XX");
    }

    /// A fold of two records keeps one hostname, a bounded number of names,
    /// and the text of both. A name the fold dropped is still masked in the
    /// text it kept.
    #[test]
    fn a_folded_record_masks_the_names_its_fold_did_not_keep() {
        use crate::model::host::{NameKind, NameSource};

        let address = "192.0.2.10".parse().expect("an address");
        let mut kept = Host::new(address);
        kept.set_hostname(Some("files.example".to_owned()));
        // A peer inventing a name per connection, until the ceiling on a
        // host's names turns one away.
        let invented = |n: usize| {
            HostName::new(NameKind::Host, NameSource::Ntlm, &format!("peer{n:03}")).expect("a name")
        };
        let mut n = 0;
        while kept.record_name(invented(n)) {
            n += 1;
        }

        let mut folded = Host::new(address);
        folded.set_hostname(Some("archive.example".to_owned()));
        folded.record_name(
            HostName::new(NameKind::NetbiosHost, NameSource::Netbios, "VAULT").expect("a name"),
        );
        kept.merge(folded);

        assert_eq!(kept.hostname(), Some("files.example"));
        assert!(kept.names().all(|name| name.name() != "VAULT"));
        let masked = Redaction::Standard
            .for_host(&kept)
            .text("archive.example is VAULT")
            .to_lowercase();
        assert!(
            !masked.contains("archive") && !masked.contains("vault"),
            "{masked}"
        );
        assert_eq!(
            Redaction::None.for_host(&kept).text("VAULT"),
            "VAULT",
            "nothing is masked without a policy"
        );
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

    /// Every format [`ExportFormat::all`] advertises produces a document.
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

    /// The path-driven entry point reaches the same exporter a caller would
    /// build by hand.
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
