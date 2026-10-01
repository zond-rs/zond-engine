// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Import
//!
//! How data gets into the engine: the targets a scan is asked to cover, and the
//! settings a caller wants applied before it starts.
//!
//! ## The mirror of export
//!
//! The shapes match [`crate::export`]: one trait per format, formats resolved
//! from a path, hand-written types at the boundary, and streaming input.
//!
//! ## Targets in, and findings in
//!
//! The readers at this level answer what should be scanned next: a report read
//! here becomes a target list and everything else in it is skipped. `report`
//! answers what a scan found and builds the whole
//! [`ScanReport`](crate::report::ScanReport), so [`diff`](crate::diff) can
//! compare a scan another tool performed against one this engine ran.
//!
//! [`kev`] reads a dataset: CISA's Known Exploited Vulnerabilities feed, which
//! supplies the corpus [`cve`](crate::cve) correlates a finished report
//! against. It converts into the catalogue grammar.
//!
//! ## Readers, not files
//!
//! This module opens no files and never touches standard input; everything here
//! reads what the caller hands it, whether a file, a locked stdin, an uploaded
//! body or pasted text, with identical parsing and errors.
//!
//! ```
//! use std::io::Cursor;
//! use zond_engine::model::port::PortSet;
//! use zond_engine::import::{ImportFormat, ImportOptions};
//!
//! let file = "# staging\n192.0.2.1\n198.51.100.0/30:8080\n";
//! let mut input = Cursor::new(file);
//!
//! let options = ImportOptions::new(PortSet::try_from("80").unwrap());
//! let imported = ImportFormat::List.read(&mut input, &options).unwrap();
//!
//! assert_eq!(imported.addresses, 5);
//! assert_eq!(imported.map.units.len(), 2, "one unit per port specification");
//! ```
//!
//! ## Untrusted input
//!
//! Everything read here was written by somebody else: a client's target list, a
//! report off a shared drive, a settings file synced from a team repository.
//!
//! Bounds are part of the API. [`ImportLimits`] is a field of [`ImportOptions`],
//! and exceeding one is an error naming what exceeded it. Truncating would
//! silently scan less than was asked for.
//!
//! A refused target is always reported. The import either stops at it
//! ([`OnRefusal::Abort`], the default) or carries on and hands the refusals back
//! in [`Imported::refusals`] ([`OnRefusal::Collect`]).
//!
//! Nothing an imported document says may name something that gets opened or
//! run: no include directive, no path, no command.

pub mod list;

#[cfg(feature = "import-csv")]
pub mod csv;

#[cfg(feature = "import-json")]
pub mod json;

#[cfg(feature = "import-distro")]
pub mod debian;

#[cfg(feature = "import-kev")]
pub mod kev;

#[cfg(feature = "import-nmap")]
pub mod nmap;

#[cfg(feature = "import-nvd")]
pub mod nvd;

#[cfg(feature = "import-distro")]
pub mod ubuntu;

// The hardened XML pull parser both nmap readers share, limited to what an nmap
// document needs.
#[cfg(feature = "import-nmap")]
pub(crate) mod xml;

#[cfg(feature = "import-settings")]
pub mod settings;

// The byte ceiling every document is read under, targets and reports alike.
mod bounded;

#[cfg(feature = "import-request")]
pub mod request;

// Reading a document for what a scan found. The module's feature is the union
// of its readers', so `ReportFormat` always has a variant.
#[cfg(any(feature = "import-json", feature = "import-nmap"))]
pub mod report;

use std::fmt;
use std::io::BufRead;
use std::path::Path;

use crate::model::parse::target::{TargetContext, TargetMapBuilder, TargetParseError};
use crate::model::port::PortSet;
use crate::model::target::{TargetMap, TargetSet};

pub use list::ListImporter;

#[cfg(feature = "import-csv")]
pub use csv::{CsvColumn, CsvImporter};

#[cfg(feature = "import-json")]
pub use json::{JsonImporter, JsonLinesImporter};

#[cfg(feature = "import-nmap")]
pub use nmap::NmapXmlImporter;

#[cfg(feature = "import-settings")]
pub use settings::{Settings, SettingsDocument, SettingsError, SettingsWarning};

#[cfg(feature = "import-request")]
pub use request::{RequestError, Resolved, ScanRequest};

/// Where in the input a token came from.
///
/// Non-exhaustive because formats locate things differently: a line number
/// suffices for a list, but not for a spreadsheet cell or an element index.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ImportOrigin {
    /// The 1-based line the token was read from, for formats that have lines.
    pub line: Option<u64>,
}

impl ImportOrigin {
    /// An origin naming a 1-based line.
    pub fn line(line: u64) -> Self {
        Self { line: Some(line) }
    }

    /// An origin for input with no position worth naming.
    pub fn unknown() -> Self {
        Self::default()
    }
}

impl fmt::Display for ImportOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "line {line}"),
            None => f.write_str("input"),
        }
    }
}

/// What the engine will read before it decides the input is not a target list.
///
/// Every default is far past anything an honest file reaches. A caller who has
/// vetted its input can lift them with [`ImportLimits::none`].
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ImportLimits {
    /// The longest line, in bytes, excluding its terminator.
    ///
    /// A target expression is a few dozen bytes. The default of 64 KiB is far
    /// past that, and small enough that a file with no newline is not read
    /// into memory as one line.
    pub max_line_bytes: usize,

    /// The most target expressions one import may contain.
    ///
    /// Defaults to sixteen million; a range says the same in one line.
    pub max_tokens: u64,

    /// The most addresses one import may name.
    ///
    /// Defaults to 2^32, the whole of IPv4. Only IPv6 range notation can
    /// exceed it, where `::/0` is one line naming a space no scan will finish,
    /// so a caller who means an IPv6 sweep has to raise this.
    ///
    /// Counted before overlapping expressions are merged, so a block named
    /// twice counts twice. That keeps the check a running sum, and errs
    /// towards refusing.
    pub max_addresses: u128,

    /// The most bytes one document may be read from, in every format.
    ///
    /// A target reader streams one record at a time, so this bounds how long
    /// an import runs. The counts above miss blank lines, comments and
    /// skipped elements, which still cost reading.
    ///
    /// The default is 16 GiB, sized to read back what this engine writes. One
    /// host scanned across the whole TCP range is 6.5 MB of nmap XML, 14 MB of
    /// JSON lines and 26 MB of the exporter's default indented JSON, so the
    /// default admits 2,048 such hosts (a /21) in the first, 1,024 in the
    /// second and 512 in the third, with a margin for services and findings.
    pub max_document_bytes: u64,
}

impl Default for ImportLimits {
    fn default() -> Self {
        Self {
            max_line_bytes: 64 * 1024,
            max_tokens: 16_777_216,
            max_addresses: 1u128 << 32,
            max_document_bytes: DEFAULT_MAX_DOCUMENT_BYTES,
        }
    }
}

/// 16 GiB. See [`ImportLimits::max_document_bytes`].
const DEFAULT_MAX_DOCUMENT_BYTES: u64 = 16 << 30;

impl ImportLimits {
    /// The defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the longest accepted line.
    ///
    /// The type is `non_exhaustive`, so other crates cannot use struct update
    /// syntax; the setters adjust one bound at a time.
    pub fn with_max_line_bytes(mut self, bytes: usize) -> Self {
        self.max_line_bytes = bytes;
        self
    }

    /// Sets the most target expressions one import may contain.
    pub fn with_max_tokens(mut self, tokens: u64) -> Self {
        self.max_tokens = tokens;
        self
    }

    /// Sets the most addresses one import may name.
    ///
    /// Raise it for an intended IPv6 sweep, or lower it where even the whole of
    /// IPv4 is too much.
    pub fn with_max_addresses(mut self, addresses: u128) -> Self {
        self.max_addresses = addresses;
        self
    }

    /// Sets the most bytes one document may be read from.
    pub fn with_max_document_bytes(mut self, bytes: u64) -> Self {
        self.max_document_bytes = bytes;
        self
    }

    /// Limits that refuse nothing, for input the caller has already vetted.
    ///
    /// `max_line_bytes` is lifted too. A line costs only its own length, since
    /// nothing is reserved for the limit. The XML readers apply the same bound
    /// to one element's markup, which a vetted nmap document can exceed: nmap
    /// writes the scanned ports into one attribute, several hundred kilobytes
    /// for a sparse sweep of the full range.
    pub fn none() -> Self {
        Self {
            max_line_bytes: usize::MAX,
            max_tokens: u64::MAX,
            max_addresses: u128::MAX,
            max_document_bytes: u64::MAX,
        }
    }
}

/// What to do with a target expression the grammar refuses.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum OnRefusal {
    /// Stop at the first refused expression and report it.
    ///
    /// The default, so a caller who has not chosen hears about the typo.
    #[default]
    Abort,

    /// Record the refusal and carry on.
    ///
    /// For a long list with one bad line, where scanning the rest is what was
    /// wanted. The refusals come back in [`Imported::refusals`].
    Collect,
}

/// A target expression that was refused, and where it was.
#[non_exhaustive]
#[derive(Debug)]
pub struct RejectedTarget {
    /// Where the expression came from.
    pub origin: ImportOrigin,
    /// The expression, as written.
    pub token: String,
    /// Why it was refused.
    pub reason: TargetParseError,
}

impl fmt::Display for RejectedTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.origin, self.reason)
    }
}

/// Policy that applies to an import regardless of the format it arrives in.
///
/// Non-exhaustive and constructed through [`ImportOptions::new`], so new
/// options can be added without breaking callers.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ImportOptions<'a> {
    /// The ports an expression that names none is scanned on.
    pub default_ports: PortSet,
    /// The lookups an expression may need. Empty by default: literal addresses,
    /// ranges and CIDR blocks only.
    pub context: TargetContext<'a>,
    /// What the import refuses to read.
    pub limits: ImportLimits,
    /// What to do with an expression the grammar refuses.
    pub on_refusal: OnRefusal,
}

impl<'a> ImportOptions<'a> {
    /// Options that resolve nothing, refuse on the first bad expression, and
    /// scan `default_ports` wherever an expression names no ports of its own.
    pub fn new(default_ports: PortSet) -> Self {
        Self {
            default_ports,
            context: TargetContext::new(),
            limits: ImportLimits::default(),
            on_refusal: OnRefusal::default(),
        }
    }

    /// Sets the lookups available to an expression.
    pub fn with_context(mut self, context: TargetContext<'a>) -> Self {
        self.context = context;
        self
    }

    /// Sets the bounds.
    pub fn with_limits(mut self, limits: ImportLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets what happens to a refused expression.
    pub fn with_refusal_policy(mut self, on_refusal: OnRefusal) -> Self {
        self.on_refusal = on_refusal;
        self
    }
}

/// What an import produced.
#[non_exhaustive]
#[derive(Debug)]
pub struct Imported {
    /// The targets, one unit per distinct port specification.
    pub map: TargetMap,
    /// Expressions that were refused, present only under
    /// [`OnRefusal::Collect`]. Under [`OnRefusal::Abort`] the first one is an
    /// error, so this is empty whenever the import succeeded.
    pub refusals: Vec<RejectedTarget>,
    /// How many expressions were read, refused ones included.
    pub tokens: u64,
    /// How many addresses the targets cover, counted after overlapping
    /// expressions are merged, and once per unit an address appears in.
    ///
    /// A host named on two different port specifications counts twice. For
    /// the number of probes the scan will send, ask
    /// [`TargetMap::gross_targets`].
    ///
    /// Exact, unlike the cheaper over-count [`ImportLimits::max_addresses`] is
    /// checked against.
    pub addresses: u128,
}

impl Imported {
    /// Takes the addresses, discarding the ports.
    ///
    /// [`crate::scanner::scan`] takes the [`map`](Self::map) as it stands;
    /// [`crate::scanner::discover`] takes an
    /// [`IpSet`](crate::model::ip::set::IpSet), which this produces.
    ///
    /// Addresses from every unit are merged into one set and canonicalized, so
    /// a file naming the same host under two port specifications sweeps it
    /// once.
    ///
    /// ```
    /// use std::io::Cursor;
    /// use zond_engine::model::port::PortSet;
    /// use zond_engine::import::{ImportFormat, ImportOptions};
    ///
    /// let list = "192.0.2.1\n192.0.2.100\n192.0.2.20\n";
    /// let options = ImportOptions::new(PortSet::try_from("80").unwrap());
    ///
    /// let targets = ImportFormat::List
    ///     .read(&mut Cursor::new(list), &options)
    ///     .unwrap()
    ///     .into_ip_set();
    ///
    /// assert_eq!(targets.len(), 3);
    /// // `zond_engine::scanner::discover(targets, &config)` takes it from here.
    /// ```
    pub fn into_ip_set(self) -> crate::model::ip::set::IpSet {
        self.map
            .units
            .into_iter()
            .map(TargetSet::into_ips)
            .collect()
    }
}

/// What went wrong while reading targets in.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// The source refused the read.
    #[error("reading the input failed: {0}")]
    Io(#[from] std::io::Error),

    /// A line ran past [`ImportLimits::max_line_bytes`].
    #[error("{origin}: longer than the {limit} byte line limit")]
    LineTooLong {
        /// Where the line started.
        origin: ImportOrigin,
        /// The limit it passed.
        limit: usize,
    },

    /// The input was not valid UTF-8.
    #[error("{origin}: not valid UTF-8")]
    InvalidUtf8 {
        /// Where the bytes were.
        origin: ImportOrigin,
    },

    /// A document ran past [`ImportLimits::max_document_bytes`], or, read as
    /// a report, past
    /// [`ReportOptions::max_document_bytes`](crate::import::report::ReportOptions::max_document_bytes).
    ///
    /// For a report reader, which holds the parsed document, this caps memory;
    /// for a streaming target reader it caps the work.
    #[error("the document is longer than the {limit} byte limit")]
    DocumentTooLarge {
        /// The limit it passed.
        limit: u64,
    },

    /// A report named more hosts than [`ImportLimits::max_addresses`] allows.
    ///
    /// Here the bound counts the hosts a document claims were found, which is
    /// what a reader allocates for.
    #[error("the report names more than {limit} hosts")]
    TooManyHosts {
        /// The limit it passed.
        limit: u128,
    },

    /// The input held more expressions than [`ImportLimits::max_tokens`].
    #[error("more than {limit} target expressions; use a range instead of a list")]
    TooManyTokens {
        /// The limit it passed.
        limit: u64,
    },

    /// The targets named more addresses than [`ImportLimits::max_addresses`].
    #[error("{origin}: '{token}' takes the scan past {limit} addresses")]
    TooManyAddresses {
        /// Where the expression that passed the limit was.
        origin: ImportOrigin,
        /// The expression that passed it.
        token: String,
        /// The limit it passed.
        limit: u128,
    },

    /// A target expression was refused under [`OnRefusal::Abort`].
    ///
    /// The message does not repeat the expression; the [`TargetParseError`]
    /// already names it.
    #[error("{origin}: {source}")]
    Target {
        /// Where the expression was.
        origin: ImportOrigin,
        /// The expression, as written.
        token: String,
        /// Why the grammar refused it.
        #[source]
        source: TargetParseError,
    },

    /// The document was not in the format it was read as.
    ///
    /// Separate from [`Target`](Self::Target): a malformed expression is one
    /// line to fix, and a malformed document usually means the wrong format.
    #[error("{origin}: not valid {format}: {message}")]
    Malformed {
        /// The format it was read as.
        format: &'static str,
        /// Where the document stopped making sense.
        origin: ImportOrigin,
        /// What was wrong with it.
        message: String,
    },
}

/// Where an importer puts the target expressions it finds.
///
/// A format knows where the expressions are in a byte stream; a sink decides
/// what to do with them. A custom sink can count targets without building them,
/// feed them somewhere other than a [`TargetMap`], or apply its own policy,
/// across every format.
pub trait TargetSink {
    /// Takes one target expression, as written, and where it was found.
    ///
    /// Returning an error stops the import. A sink that collects returns `Ok`
    /// and keeps its own record, as [`TargetCollector`] does under
    /// [`OnRefusal::Collect`].
    fn accept(&mut self, token: &str, origin: ImportOrigin) -> Result<(), ImportError>;
}

/// `bytes` with a byte-order mark taken off the front, for a reader looking at
/// input it has not consumed.
///
/// The peeking half of [`skip_bom`]. The mark must be ignored both when
/// [`ImportFormat::sniff`] guesses a format and when that format reads, or the
/// two disagree.
pub(crate) fn without_bom(bytes: &[u8]) -> &[u8] {
    bytes
        .strip_prefix(&crate::format::UTF8_BOM)
        .unwrap_or(bytes)
}

/// Consumes a byte-order mark at the very start of `input`, if there is one.
///
/// Called once, before anything else reads; a mark anywhere later is data.
///
/// The line- and record-oriented readers strip it from their own buffers. This
/// is for readers that hand the stream straight to a parser that would refuse
/// the mark, as `serde_json` does with a misleading error at column 1.
#[cfg(any(feature = "import-json", feature = "import-nmap"))]
pub(crate) fn skip_bom(input: &mut dyn BufRead) -> Result<(), ImportError> {
    if input.fill_buf()?.starts_with(&crate::format::UTF8_BOM) {
        input.consume(crate::format::UTF8_BOM.len());
    }
    Ok(())
}

/// Writes the target expression naming `address` on `ports` into `token`.
///
/// Shared by every format that holds an address and its ports as separate
/// fields.
///
/// The address is bracketed whenever ports follow it. IPv6 requires it, and
/// IPv4 needs it too once a protocol prefix is involved: `192.0.2.1:u:53` has
/// two colons and the grammar reads it as IPv6. Bracketing always means no
/// reader has to check the family.
///
/// An empty `ports` names no ports, so the expression is the bare address and
/// the scan uses [`ImportOptions::default_ports`].
#[cfg(any(
    feature = "import-csv",
    feature = "import-json",
    feature = "import-nmap"
))]
pub(crate) fn expression(token: &mut String, address: &str, ports: &str) {
    token.clear();

    if ports.is_empty() {
        token.push_str(address);
        return;
    }

    token.push('[');
    token.push_str(address);
    token.push_str("]:");
    token.push_str(ports);
}

/// One input format.
///
/// Reads a byte stream into target expressions. Any other choices are made
/// when the implementing value is constructed.
pub trait Importer {
    /// Reads every target expression in `input` into `sink`.
    ///
    /// Implementations must stream: the memory an import costs should be a
    /// function of the largest single record, not of the size of the input.
    fn import(&self, input: &mut dyn BufRead, sink: &mut dyn TargetSink)
    -> Result<(), ImportError>;
}

/// The [`TargetSink`] that builds a [`TargetMap`].
///
/// Enforces the bounds only a sink can see: how many expressions have arrived
/// and how many addresses they name. The format enforces line length.
#[derive(Debug)]
pub struct TargetCollector<'a> {
    builder: TargetMapBuilder,
    options: ImportOptions<'a>,
    refusals: Vec<RejectedTarget>,
    tokens: u64,
    /// Addresses named so far, before overlapping expressions are merged.
    ///
    /// A running sum, so the set is not re-merged on every line. It
    /// over-counts a block named twice; see [`ImportLimits::max_addresses`].
    gross_addresses: u128,
}

impl<'a> TargetCollector<'a> {
    /// Starts a collector under `options`.
    pub fn new(options: ImportOptions<'a>) -> Self {
        Self {
            builder: TargetMapBuilder::new(options.default_ports.clone()),
            options,
            refusals: Vec::new(),
            tokens: 0,
            gross_addresses: 0,
        }
    }

    /// Finishes, and reports what was read.
    pub fn finish(mut self) -> Imported {
        let addresses = self.builder.address_count();
        Imported {
            map: self.builder.build(),
            refusals: self.refusals,
            tokens: self.tokens,
            addresses,
        }
    }
}

impl TargetSink for TargetCollector<'_> {
    fn accept(&mut self, token: &str, origin: ImportOrigin) -> Result<(), ImportError> {
        self.tokens = self.tokens.saturating_add(1);
        if self.tokens > self.options.limits.max_tokens {
            return Err(ImportError::TooManyTokens {
                limit: self.options.limits.max_tokens,
            });
        }

        // The builder's count either side of the push gives what was actually
        // added.
        let before = self.builder.gross_address_count();
        match self.builder.push(token, &self.options.context) {
            Ok(()) => {}
            Err(reason) => {
                return match self.options.on_refusal {
                    OnRefusal::Abort => Err(ImportError::Target {
                        origin,
                        token: token.trim().to_string(),
                        source: reason,
                    }),
                    OnRefusal::Collect => {
                        self.refusals.push(RejectedTarget {
                            origin,
                            token: token.trim().to_string(),
                            reason,
                        });
                        Ok(())
                    }
                };
            }
        }

        let added = self.builder.gross_address_count().saturating_sub(before);
        self.gross_addresses = self.gross_addresses.saturating_add(added);

        if self.gross_addresses > self.options.limits.max_addresses {
            return Err(ImportError::TooManyAddresses {
                origin,
                token: token.trim().to_string(),
                limit: self.options.limits.max_addresses,
            });
        }

        Ok(())
    }
}

/// The formats this build can read.
///
/// Which variants exist depends on the cargo features the crate was built with,
/// except for [`List`](Self::List), which needs nothing and is always here.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImportFormat {
    /// One target expression per line or per run of whitespace, `#` starting a
    /// comment.
    List,

    /// A table with a column of addresses: a report this engine wrote, or a
    /// spreadsheet somebody else did.
    #[cfg(feature = "import-csv")]
    Csv,

    /// A report this engine wrote, as a single JSON document.
    #[cfg(feature = "import-json")]
    Json,

    /// A report this engine wrote, one record per line.
    #[cfg(feature = "import-json")]
    JsonLines,

    /// Nmap's XML: a previous scan by nmap, or by this engine writing nmap's
    /// format.
    #[cfg(feature = "import-nmap")]
    NmapXml,
}

impl ImportFormat {
    /// Resolves a file extension, case-insensitively and without a leading dot.
    ///
    /// Returns `None` for an extension no compiled-in format claims. Guessing is
    /// left to [`sniff`](Self::sniff), which a caller asks for explicitly.
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.to_ascii_lowercase().as_str() {
            "txt" | "list" | "lst" => Some(ImportFormat::List),
            #[cfg(feature = "import-csv")]
            "csv" => Some(ImportFormat::Csv),
            #[cfg(feature = "import-json")]
            "json" => Some(ImportFormat::Json),
            // `ndjson` matches what the exporter accepts.
            #[cfg(feature = "import-json")]
            "jsonl" | "ndjson" => Some(ImportFormat::JsonLines),
            #[cfg(feature = "import-nmap")]
            "xml" => Some(ImportFormat::NmapXml),
            _ => None,
        }
    }

    /// Guesses the format from the start of the input, without consuming it.
    ///
    /// For input with no name: a pipe, a socket, a paste. The bytes are peeked
    /// through [`BufRead::fill_buf`], so the importer that runs next sees the
    /// whole document.
    ///
    /// ## The rule is conservative
    ///
    /// It separates a structured format from a list, and anything ambiguous is
    /// a list. A document opening with `{` is JSON, one opening with `<` is XML,
    /// and one whose first row is this crate's CSV header is CSV. Everything
    /// else is a list, so an unfamiliar spreadsheet is refused on its first row.
    ///
    /// A leading `[` is not taken as a JSON array, since `[2001:db8::1]:443` is
    /// an ordinary first line of a target list and this crate's JSON is an
    /// object. A comma is not taken as evidence of CSV, since
    /// `192.0.2.1,192.0.2.2` is a valid list line.
    ///
    /// A caller who knows the format should name it.
    pub fn sniff(input: &mut dyn BufRead) -> Result<Self, ImportError> {
        /// What a record-per-line report calls its header record, exactly as
        /// the exporter's compact JSON writes it.
        #[cfg(feature = "import-json")]
        const REPORT_TAG: &[u8] = br#""type":"report""#;

        let buffered = input.fill_buf()?;
        // A byte-order mark says nothing about the format.
        let prefix = without_bom(buffered).trim_ascii_start();

        // A build with no structured format has no arm reading `prefix`, and
        // the binding would warn.
        let _ = &prefix;

        #[cfg(feature = "import-csv")]
        {
            // Only this crate's own header is recognised.
            let header = crate::format::csv::COLUMNS.join(",");
            let overlap = prefix.len().min(header.len());
            if overlap >= 16 && prefix[..overlap] == header.as_bytes()[..overlap] {
                return Ok(ImportFormat::Csv);
            }
        }

        #[cfg(feature = "import-nmap")]
        if prefix.first() == Some(&b'<') {
            return Ok(ImportFormat::NmapXml);
        }

        #[cfg(feature = "import-json")]
        if prefix.first() == Some(&b'{') {
            // Both JSON formats open with a brace; the record-per-line one names
            // itself in its first record. Checking the tag, not for a line
            // break, keeps a single-line document from reading as records.
            let head = &prefix[..prefix.len().min(256)];
            let tagged = head
                .windows(REPORT_TAG.len())
                .any(|window| window == REPORT_TAG);
            return Ok(if tagged {
                ImportFormat::JsonLines
            } else {
                ImportFormat::Json
            });
        }

        Ok(ImportFormat::List)
    }

    /// Resolves a format from a path if there is one, and from the input's own
    /// first bytes if there is not.
    ///
    /// The name wins over the bytes. An extension that names no format, such as
    /// `targets.dat`, falls through to sniffing.
    pub fn resolve(path: Option<&Path>, input: &mut dyn BufRead) -> Result<Self, ImportError> {
        match path.and_then(Self::from_path) {
            Some(format) => Ok(format),
            None => Self::sniff(input),
        }
    }

    /// Resolves a path by its extension.
    ///
    /// A path with no extension has no format, for the reason
    /// [`crate::export::ExportFormat::from_path`] gives.
    pub fn from_path(path: &Path) -> Option<Self> {
        path.extension()
            .and_then(|extension| extension.to_str())
            .and_then(Self::from_extension)
    }

    /// The canonical file extension for this format, without a leading dot.
    pub fn extension(self) -> &'static str {
        match self {
            ImportFormat::List => "txt",
            #[cfg(feature = "import-csv")]
            ImportFormat::Csv => "csv",
            #[cfg(feature = "import-json")]
            ImportFormat::Json => "json",
            #[cfg(feature = "import-json")]
            ImportFormat::JsonLines => "jsonl",
            #[cfg(feature = "import-nmap")]
            ImportFormat::NmapXml => "xml",
        }
    }

    /// Every format this build can read.
    ///
    /// For front ends describing their own capabilities.
    pub fn all() -> &'static [ImportFormat] {
        &[
            ImportFormat::List,
            #[cfg(feature = "import-csv")]
            ImportFormat::Csv,
            #[cfg(feature = "import-json")]
            ImportFormat::Json,
            #[cfg(feature = "import-json")]
            ImportFormat::JsonLines,
            #[cfg(feature = "import-nmap")]
            ImportFormat::NmapXml,
        ]
    }

    /// Builds an importer for this format under the given options.
    pub fn importer(self, options: &ImportOptions<'_>) -> Box<dyn Importer> {
        match self {
            ImportFormat::List => Box::new(ListImporter::new(options.limits)),
            #[cfg(feature = "import-csv")]
            ImportFormat::Csv => Box::new(CsvImporter::new(options.limits)),
            #[cfg(feature = "import-json")]
            ImportFormat::Json => Box::new(JsonImporter::new(options.limits)),
            #[cfg(feature = "import-json")]
            ImportFormat::JsonLines => Box::new(JsonLinesImporter::new(options.limits)),
            #[cfg(feature = "import-nmap")]
            ImportFormat::NmapXml => Box::new(NmapXmlImporter::new(options.limits)),
        }
    }

    /// Reads `input` in this format and builds the targets it names.
    ///
    /// Drives [`Importer`] and [`TargetCollector`] together, so every front end
    /// turns a file into targets the same way.
    pub fn read(
        self,
        input: &mut dyn BufRead,
        options: &ImportOptions<'_>,
    ) -> Result<Imported, ImportError> {
        let importer = self.importer(options);
        let mut collector = TargetCollector::new(options.clone());
        importer.import(input, &mut collector)?;
        Ok(collector.finish())
    }
}

impl fmt::Display for ImportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ImportFormat::List => "list",
            #[cfg(feature = "import-csv")]
            ImportFormat::Csv => "csv",
            #[cfg(feature = "import-json")]
            ImportFormat::Json => "json",
            #[cfg(feature = "import-json")]
            ImportFormat::JsonLines => "jsonl",
            #[cfg(feature = "import-nmap")]
            ImportFormat::NmapXml => "nmap-xml",
        })
    }
}

/// Reads targets from `input`, in the format named by `path`'s extension.
///
/// Returns `None` if the extension names no format this build supports. The
/// targets are read from `input`; `path` only names the format, so this works
/// for an upload named `targets.txt` that was never a file.
pub fn read_from(
    path: &Path,
    input: &mut dyn BufRead,
    options: &ImportOptions<'_>,
) -> Option<Result<Imported, ImportError>> {
    let format = ImportFormat::from_path(path)?;
    Some(format.read(input, options))
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
    use std::io::Cursor;

    fn options(ports: &str) -> ImportOptions<'static> {
        ImportOptions::new(PortSet::try_from(ports).expect("test ports parse"))
    }

    fn read(input: &str, options: &ImportOptions<'_>) -> Result<Imported, ImportError> {
        ImportFormat::List.read(&mut Cursor::new(input), options)
    }

    /// Every format resolves from its own extension.
    #[test]
    fn every_advertised_format_resolves_from_its_own_extension() {
        for format in ImportFormat::all() {
            assert_eq!(
                ImportFormat::from_extension(format.extension()),
                Some(*format),
                "{format} does not resolve from its own extension"
            );
        }

        assert_eq!(ImportFormat::from_path(Path::new("/tmp/targets")), None);
        assert_eq!(ImportFormat::from_extension("pdf"), None);
    }

    #[test]
    fn reading_by_path_matches_reading_by_format() {
        let opts = options("80");
        let mut input = Cursor::new("198.51.100.1\n");

        let imported = read_from(Path::new("targets.txt"), &mut input, &opts)
            .expect("the extension names a format")
            .expect("the import succeeds");

        assert_eq!(imported.addresses, 1);
        assert!(
            read_from(Path::new("targets.pdf"), &mut Cursor::new(""), &opts).is_none(),
            "an unsupported extension must not quietly produce targets"
        );
    }

    /// The default policy stops at a typo and names its line.
    #[test]
    fn a_refused_expression_aborts_and_names_its_line() {
        let err = read(
            "198.51.100.1\n198.51.100.300\n198.51.100.2\n",
            &options("80"),
        )
        .expect_err("the second line is not an address");

        match err {
            ImportError::Target { origin, token, .. } => {
                assert_eq!(origin, ImportOrigin::line(2));
                assert_eq!(token, "198.51.100.300");
            }
            other => panic!("expected a refused target, got {other:?}"),
        }
    }

    /// Collecting hands the refusals back.
    #[test]
    fn collecting_keeps_the_good_targets_and_reports_the_bad_ones() {
        let opts = options("80").with_refusal_policy(OnRefusal::Collect);

        let imported = read(
            "198.51.100.1\n198.51.100.300\nnot-an-address\n198.51.100.2\n",
            &opts,
        )
        .expect("collecting does not fail the import");

        assert_eq!(imported.addresses, 2, "both good targets survived");
        assert_eq!(imported.refusals.len(), 2);
        assert_eq!(imported.refusals[0].origin, ImportOrigin::line(2));
        assert_eq!(imported.refusals[1].token, "not-an-address");
        assert_eq!(imported.tokens, 4, "refused expressions are still counted");
    }

    /// One short line naming a space no scan can finish is refused.
    #[test]
    fn a_range_past_the_address_limit_is_refused() {
        let err = read("::/0\n", &options("80")).expect_err("the whole of IPv6 is not a scan");

        assert!(matches!(err, ImportError::TooManyAddresses { .. }));

        // The default ceiling admits the whole of IPv4.
        let imported = read("0.0.0.0/0\n", &options("80")).expect("the whole of IPv4 is a scan");
        assert_eq!(imported.addresses, 1u128 << 32);
    }

    #[test]
    fn limits_can_be_lifted_and_tightened() {
        let permissive = options("80").with_limits(ImportLimits::none());
        assert!(read("::/0\n", &permissive).is_ok());

        // The line limit is lifted too.
        let long = format!("# {}\n198.51.100.1\n", "x".repeat(128 * 1024));
        assert!(matches!(
            read(&long, &options("80")),
            Err(ImportError::LineTooLong { .. })
        ));
        assert!(read(&long, &permissive).is_ok());

        let strict = options("80").with_limits(ImportLimits {
            max_addresses: 100,
            ..ImportLimits::default()
        });
        assert!(matches!(
            read("198.51.100.0/24\n", &strict),
            Err(ImportError::TooManyAddresses { .. })
        ));

        let few = options("80").with_limits(ImportLimits {
            max_tokens: 2,
            ..ImportLimits::default()
        });
        assert!(matches!(
            read("198.51.100.1\n198.51.100.2\n198.51.100.3\n", &few),
            Err(ImportError::TooManyTokens { limit: 2 })
        ));
    }

    /// The reported count is the number of hosts that will be probed, not the
    /// running total the limit is checked against.
    #[test]
    fn the_reported_address_count_merges_overlapping_targets() {
        let imported = read("198.51.100.0/24\n198.51.100.5\n", &options("80")).expect("imports");

        assert_eq!(imported.addresses, 256, "the same block, named twice");
        assert_eq!(imported.tokens, 2);
    }

    /// A typed list of addresses feeds both `scan` (the map) and `discover`
    /// (an `IpSet`).
    #[test]
    fn a_hand_written_list_of_addresses_feeds_both_entry_points() {
        let list = "\
192.0.2.1
192.0.2.100
192.0.2.20
192.0.2.53
192.0.2.151
";

        let imported = read(list, &options("22,80")).expect("a list of addresses imports");

        assert_eq!(imported.tokens, 5);
        assert_eq!(imported.addresses, 5);
        assert_eq!(imported.refusals.len(), 0);

        // The port-scan entry point: one unit, both ports, ten probes.
        assert_eq!(imported.map.units.len(), 1);
        let map = imported.map.clone();
        assert_eq!(map.gross_targets().unwrap(), 10);

        // The discovery entry point: the same five addresses, no ports.
        let targets = imported.into_ip_set();
        assert_eq!(targets.len(), 5);
        for address in ["192.0.2.1", "192.0.2.20", "192.0.2.151"] {
            assert!(
                targets.contains(&address.parse().unwrap()),
                "{address} did not survive"
            );
        }
    }

    /// A host named under two port specifications is two units to scan and
    /// one host to sweep.
    #[test]
    fn converting_to_addresses_merges_what_the_units_kept_apart() {
        let imported = read(
            "198.51.100.1:22\n198.51.100.1:443\n198.51.100.2:22\n",
            &options("80"),
        )
        .expect("imports");

        assert_eq!(imported.map.units.len(), 2, "two port specifications");
        assert_eq!(imported.addresses, 3, "counted once per unit");
        assert_eq!(
            imported.into_ip_set().len(),
            2,
            "but only two hosts to sweep"
        );
    }

    /// Sniffing consumes nothing, so whatever runs next reads the whole
    /// document.
    #[test]
    fn sniffing_leaves_the_input_where_it_found_it() {
        let file = "198.51.100.1\n198.51.100.2\n198.51.100.3\n";
        let mut input = Cursor::new(file);

        let format = ImportFormat::sniff(&mut input).expect("sniffs");
        assert_eq!(format, ImportFormat::List);

        let imported = format.read(&mut input, &options("80")).expect("imports");
        assert_eq!(imported.addresses, 3, "sniffing consumed part of the input");
    }

    /// Inputs that could be mistaken for a structured format read as a list.
    #[test]
    fn an_ambiguous_document_is_read_as_a_list() {
        for file in [
            // A bracketed IPv6 target, which is not a JSON array.
            "[2001:db8::1]:443\n",
            // Comma-separated addresses, which are not a table.
            "192.0.2.1,192.0.2.2\n",
            // A table this crate did not write; the list grammar refuses it.
            "Server,Location\nweb01,rack 4\n",
            "",
            "# just a comment\n",
        ] {
            assert_eq!(
                ImportFormat::sniff(&mut Cursor::new(file)).expect("sniffs"),
                ImportFormat::List,
                "{file:?}"
            );
        }
    }

    /// Sniffing recognises the CSV the exporter writes, tested against the
    /// exporter's real output.
    #[cfg(all(feature = "import-csv", feature = "export-csv"))]
    #[test]
    fn a_report_this_engine_wrote_is_recognised_and_read_back() {
        use crate::export::{CsvExporter, ExportOptions, Exporter};

        let report = crate::export::fixture::report();
        let mut document = Vec::new();
        CsvExporter::new(ExportOptions::new())
            .export(&report, &mut document)
            .expect("the fixture exports");

        let mut input = Cursor::new(document);
        let format = ImportFormat::sniff(&mut input).expect("sniffs");
        assert_eq!(
            format,
            ImportFormat::Csv,
            "this crate must recognise its own CSV"
        );

        let imported = format.read(&mut input, &options("80")).expect("imports");
        assert!(
            imported.addresses > 0,
            "a report with hosts in it read back as no targets"
        );
        assert_eq!(
            imported.refusals.len(),
            0,
            "every row of our own output has to parse as a target"
        );
    }

    /// Both report formats open with a brace; the record-per-line one is told
    /// apart by its tag, which also works for a compact single-line document.
    #[cfg(all(
        feature = "import-json",
        feature = "export-json",
        feature = "export-jsonl"
    ))]
    #[test]
    fn the_two_report_formats_are_told_apart_by_what_they_call_themselves() {
        use crate::export::{ExportOptions, Exporter, JsonExporter, JsonLinesExporter};

        let report = crate::export::fixture::report();

        for (exporter, expected) in [
            (
                Box::new(JsonExporter::new(ExportOptions::new())) as Box<dyn Exporter>,
                ImportFormat::Json,
            ),
            (
                Box::new(JsonExporter::new(ExportOptions::new()).compact()),
                ImportFormat::Json,
            ),
            (
                Box::new(JsonLinesExporter::new(ExportOptions::new())),
                ImportFormat::JsonLines,
            ),
        ] {
            let mut document = Vec::new();
            exporter.export(&report, &mut document).expect("exports");

            assert_eq!(
                ImportFormat::sniff(&mut Cursor::new(document)).expect("sniffs"),
                expected,
            );
        }
    }

    /// A document with a byte-order mark sniffs and reads as its format, in
    /// every format. Windows PowerShell's `Out-File` writes the mark by
    /// default.
    #[test]
    fn a_byte_order_mark_costs_no_format_its_document() {
        for (format, document) in documents() {
            let marked = |text: &str| {
                let mut bytes = crate::format::UTF8_BOM.to_vec();
                bytes.extend_from_slice(text.as_bytes());
                Cursor::new(bytes)
            };

            assert_eq!(
                ImportFormat::sniff(&mut marked(&document)).expect("sniffs"),
                format,
                "{format} was not recognised through a byte-order mark"
            );

            let imported = format
                .read(&mut marked(&document), &options("80"))
                .unwrap_or_else(|error| {
                    panic!("{format} sniffed as itself and then refused itself: {error}")
                });
            assert_eq!(
                imported.addresses, 1,
                "{format} read no targets through a byte-order mark"
            );
        }
    }

    /// The same document each format would carry, as short as it can be.
    fn documents() -> Vec<(ImportFormat, String)> {
        let mut all = vec![(ImportFormat::List, "198.51.100.1\n".to_string())];

        // The full header, so sniffing recognises it; the row can stop after
        // the address.
        #[cfg(feature = "import-csv")]
        all.push((
            ImportFormat::Csv,
            format!("{}\n198.51.100.1\n", crate::format::csv::COLUMNS.join(",")),
        ));
        #[cfg(feature = "import-json")]
        {
            let hosts = r#"{"primary_ip":"198.51.100.1","ips":["198.51.100.1"],"ports":[]}"#;
            all.push((
                ImportFormat::Json,
                format!(r#"{{"schema_version":1,"hosts":[{hosts}]}}"#),
            ));
            all.push((
                ImportFormat::JsonLines,
                format!(
                    "{{\"type\":\"report\",\"schema_version\":1}}\n{{\"type\":\"host\",{}\n",
                    &hosts[1..]
                ),
            ));
        }
        #[cfg(feature = "import-nmap")]
        all.push((
            ImportFormat::NmapXml,
            r#"<nmaprun><host><address addr="198.51.100.1" addrtype="ipv4"/></host></nmaprun>"#
                .to_string(),
        ));

        all
    }

    /// **Every format is read under the document ceiling, and a document
    /// exactly at it is read whole.**
    ///
    /// The counts on expressions and addresses see nothing a reader skips, so
    /// only this ceiling bounds a file of comments or ignored elements.
    #[test]
    fn every_format_refuses_a_document_past_its_byte_ceiling() {
        for (format, document) in documents() {
            let at = |bytes: u64| {
                let options = options("80")
                    .with_limits(ImportLimits::default().with_max_document_bytes(bytes));
                format.read(&mut Cursor::new(document.as_bytes()), &options)
            };

            let whole = at(document.len() as u64)
                .unwrap_or_else(|error| panic!("{format} refused itself at its ceiling: {error}"));
            assert_eq!(whole.addresses, 1, "{format} read at its ceiling");

            let error = at(document.len() as u64 - 1)
                .expect_err(&format!("{format} read a byte past its ceiling"));
            assert!(
                matches!(error, ImportError::DocumentTooLarge { .. }),
                "{format} should name the ceiling it passed, said: {error}"
            );
        }
    }

    /// The default ceiling admits the full-range host counts its documentation
    /// promises, measured against what the writers produce.
    #[cfg(all(
        feature = "import-nmap",
        feature = "export-json",
        feature = "export-jsonl",
        feature = "export-nmap"
    ))]
    #[test]
    fn the_default_ceiling_admits_the_full_range_hosts_it_promises() {
        use crate::export::{
            ExportOptions, Exporter, JsonExporter, JsonLinesExporter, NmapXmlExporter,
        };
        use crate::model::host::Host;
        use crate::model::port::{Discovery, Port, PortState, Protocol, ScanResponse};
        use crate::report::ScanReport;

        // Every port closed with the fullest record a raw probe writes.
        let mut host = Host::new("192.0.2.1".parse().expect("an address"));
        for number in 1..=u16::MAX {
            host.add_port(
                Port::new(number, Protocol::Tcp, PortState::Closed).with_discovery(
                    Discovery::new(ScanResponse::TcpRst)
                        .with_rtt(std::time::Duration::from_micros(1_234))
                        .with_ttl(64),
                ),
            );
        }
        let report = ScanReport::recorded("zond", Vec::new(), vec![host]);
        let written = |exporter: &dyn Exporter| {
            let mut out = Vec::new();
            exporter.export(&report, &mut out).expect("exports");
            out
        };

        let ceiling = ImportLimits::default().max_document_bytes;
        let xml = written(&NmapXmlExporter::new(ExportOptions::new()));
        for (format, bytes, promised) in [
            ("nmap XML", xml.len(), 2_048),
            (
                "JSON lines",
                written(&JsonLinesExporter::new(ExportOptions::new())).len(),
                1_024,
            ),
            (
                "indented JSON",
                written(&JsonExporter::new(ExportOptions::new())).len(),
                512,
            ),
        ] {
            assert!(
                bytes as u64 * promised <= ceiling,
                "{promised} full-range hosts of {format} are {} bytes, past the {ceiling}-byte ceiling",
                bytes as u64 * promised,
            );
        }

        // One such host reads back.
        let imported = ImportFormat::NmapXml
            .read(&mut Cursor::new(xml), &options("80"))
            .expect("this engine's own export reads as targets");
        assert_eq!(imported.addresses, 1);
    }

    /// A known extension decides the format, and an unknown one falls through
    /// to sniffing.
    #[test]
    fn a_path_decides_the_format_and_a_silent_one_defers_to_the_input() {
        let mut input = Cursor::new("198.51.100.1\n");

        assert_eq!(
            ImportFormat::resolve(Some(Path::new("scope.txt")), &mut input).unwrap(),
            ImportFormat::List
        );
        assert_eq!(
            ImportFormat::resolve(Some(Path::new("scope.dat")), &mut input).unwrap(),
            ImportFormat::List,
            "an extension that names no format is not an error"
        );
        assert_eq!(
            ImportFormat::resolve(None, &mut input).unwrap(),
            ImportFormat::List
        );
    }
}
