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
//! [`crate::export`] answered most of these questions already, and where the
//! shapes correspond they correspond exactly - one trait per format, formats
//! resolved from a path, hand-written types at the boundary rather than derived
//! onto the engine's working types, and streaming rather than a document held
//! whole in memory. A consumer who has learned one of these modules has learned
//! the other, and they are between them the whole of this crate's contact with
//! the outside world's file formats.
//!
//! ## Targets in, and findings in
//!
//! Two directions, kept apart. The readers at this level answer "what should I
//! scan next", and are narrow on purpose: a report read here becomes a target
//! list and everything else in the document is skipped. `report` answers "what
//! did this scan find", and builds the whole
//! [`ScanReport`](crate::report::ScanReport) — which is what lets
//! [`diff`](crate::diff) compare a scan another tool performed against one this
//! engine ran.
//!
//! ## A source is not a format
//!
//! Reading from a pipe is not a format; it is a place bytes come from. So this
//! module never touches standard input, never opens a file and never names a
//! path it opens. Everything here reads what the caller hands it.
//!
//! A CLI hands it a file or a locked stdin, a web front end hands it a cursor
//! over an uploaded body, a TUI hands it what the user pasted, an embedder
//! hands it a reader over a blob. All four get identical parsing and identical
//! errors, because there is one implementation and it cannot tell them apart.
//!
//! ```
//! use std::io::Cursor;
//! use zond_engine::model::port::PortSet;
//! use zond_engine::import::{ImportFormat, ImportOptions};
//!
//! let file = "# staging\n192.168.1.1\n10.0.0.0/30:8080\n";
//! let mut input = Cursor::new(file);
//!
//! let options = ImportOptions::new(PortSet::try_from("80").unwrap());
//! let imported = ImportFormat::List.read(&mut input, &options).unwrap();
//!
//! assert_eq!(imported.addresses, 5);
//! assert_eq!(imported.map.units.len(), 2, "one unit per port specification");
//! ```
//!
//! ## Input nobody vouches for
//!
//! Every other parser in this engine reads either its own assets or packets it
//! solicited. This one reads a file somebody else wrote: a target list from a
//! client, a report off a shared drive, a settings file synced from a team
//! repository. Three consequences run through the whole module.
//!
//! **Bounds are part of the API.** [`ImportLimits`] is a field of
//! [`ImportOptions`] rather than a constant, and exceeding one is an error
//! naming what exceeded it, never a truncation - a target set quietly missing
//! its tail is a scan that does not cover what it was asked to, and nothing in
//! the report says so.
//!
//! **A refused target is reported, never dropped.** Refusing the whole import
//! over one bad line ([`OnRefusal::Abort`], the default) and carrying on past it
//! ([`OnRefusal::Collect`]) are both defensible, and which is right depends on
//! whether a person is watching. What is not defensible is continuing silently,
//! so collecting hands the refusals back in [`Imported::refusals`] where the
//! caller has to look at them to ignore them.
//!
//! **Nothing an imported document says may name something that gets opened or
//! run.** No include directive, no path that gets resolved, no command. A
//! document changes numbers and chooses between named alternatives, and that is
//! the entire vocabulary.

pub mod list;

#[cfg(feature = "import-csv")]
pub mod csv;

#[cfg(feature = "import-json")]
pub mod json;

#[cfg(feature = "import-nmap")]
pub mod nmap;

// The hardened XML pull parser both nmap readers share. Not public: it is this
// module's own machinery, and a consumer wanting to parse XML has a hundred
// crates to choose from that are not confined to what an nmap document needs.
#[cfg(feature = "import-nmap")]
pub(crate) mod xml;

#[cfg(feature = "import-settings")]
pub mod settings;

// Reading a document for what a scan *found*, rather than for what to scan
// next. Each reader inside carries the feature of the format it reads, and the
// module carries their union: a build that can read no report format has no use
// for a type naming which one to read, and left it holding a `ReportFormat` with
// no variants and a `read` whose arguments nothing could reach.
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

/// Where in the input a token came from.
///
/// Non-exhaustive because formats locate things differently: a line number is
/// the whole of it for a list, and a spreadsheet cell or an element index is
/// not. An error that can say *where* is worth a great deal more than one that
/// only says what.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Origin {
    /// The 1-based line the token was read from, for formats that have lines.
    pub line: Option<u64>,
}

impl Origin {
    /// An origin naming a 1-based line.
    pub fn line(line: u64) -> Self {
        Self { line: Some(line) }
    }

    /// An origin for input with no position worth naming.
    pub fn unknown() -> Self {
        Self::default()
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "line {line}"),
            None => f.write_str("input"),
        }
    }
}

/// What the engine will read before it decides the input is not a target list.
///
/// These are refusals, not tuning. Every default is far past anything an honest
/// file reaches, and a caller who has vetted its input can lift them with
/// [`ImportLimits::none`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ImportLimits {
    /// The longest line, in bytes, excluding its terminator.
    ///
    /// A target expression is a few dozen bytes. 64 KiB is unreachable by
    /// anything written on purpose, and small enough that a file containing no
    /// newline at all cannot be read into memory one line at a time.
    pub max_line_bytes: usize,

    /// The most target expressions one import may contain.
    ///
    /// Sixteen million expressions is a file no person wrote and no tool should
    /// emit - a range says the same thing in one line.
    pub max_tokens: u64,

    /// The most addresses one import may name.
    ///
    /// Defaults to 2^32: the whole of IPv4, which is the largest scan that can
    /// actually be completed. It is a ceiling with a meaning rather than a round
    /// number, and the only way to exceed it is IPv6 range notation - where
    /// `::/0` costs one line to write and names a space no scan will ever
    /// finish. A caller who genuinely means an IPv6 sweep raises this
    /// deliberately, which is the point.
    ///
    /// Counted before overlapping expressions are merged, so a file that names
    /// the same block twice counts it twice. That keeps the check a running
    /// addition rather than a re-merge of the whole set per line, and it errs
    /// towards refusing - which for a limit is the safe direction.
    pub max_addresses: u128,
}

impl Default for ImportLimits {
    fn default() -> Self {
        Self {
            max_line_bytes: 64 * 1024,
            max_tokens: 16_777_216,
            max_addresses: 1u128 << 32,
        }
    }
}

impl ImportLimits {
    /// The defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the longest accepted line.
    ///
    /// A setter rather than a field to assign, because this type is
    /// `non_exhaustive` - which keeps a future limit an additive change, and
    /// means a crate outside this one cannot write `ImportLimits { .. }` with a
    /// struct update. Adjusting one bound should not require constructing all
    /// of them.
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
    /// The bound most worth adjusting: raise it for a deliberate IPv6 sweep,
    /// lower it where even the whole of IPv4 is more than the caller means to
    /// allow.
    pub fn with_max_addresses(mut self, addresses: u128) -> Self {
        self.max_addresses = addresses;
        self
    }

    /// Limits that refuse nothing, for input the caller has already vetted.
    ///
    /// `max_line_bytes` stays finite because it bounds a single allocation
    /// rather than the scan, and no input needs it lifted.
    pub fn none() -> Self {
        Self {
            max_line_bytes: usize::MAX,
            max_tokens: u64::MAX,
            max_addresses: u128::MAX,
        }
    }
}

/// What to do with a target expression the grammar refuses.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum OnRefusal {
    /// Stop at the first refused expression and report it.
    ///
    /// The default, because it is the answer that cannot be ignored. A caller
    /// who has not thought about the question gets told about the typo rather
    /// than a scan that silently covers less than it was given.
    #[default]
    Abort,

    /// Record the refusal and carry on.
    ///
    /// For the five-thousand-line list with one bad line in it, where scanning
    /// the other four thousand nine hundred and ninety-nine is obviously what
    /// was wanted. The refusals come back in [`Imported::refusals`], so the
    /// caller has to have them in hand to disregard them.
    Collect,
}

/// A target expression that was refused, and where it was.
#[derive(Debug)]
pub struct Refusal {
    /// Where the expression came from.
    pub origin: Origin,
    /// The expression, as written.
    pub token: String,
    /// Why it was refused.
    pub reason: TargetParseError,
}

impl Imported {
    /// Takes the addresses, discarding the ports.
    ///
    /// [`crate::scanner::scan`] takes the [`map`](Self::map) as it stands.
    /// [`crate::scanner::discover`] takes an [`IpSet`](crate::model::ip::set::IpSet), because asking whether a
    /// host is there at all has no use for ports - so this is the other half of
    /// the same journey, and it lives here rather than in every front end
    /// writing the same fold.
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
    /// let list = "192.168.0.1\n192.168.0.100\n192.168.0.20\n";
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

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.origin, self.reason)
    }
}

/// Policy that applies to an import regardless of the format it arrives in.
///
/// Non-exhaustive and constructed through [`ImportOptions::new`], so a future
/// option is an additive change rather than a break for everyone who built one.
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
    /// [`OnRefusal::Collect`] - [`OnRefusal::Abort`] returns the first one as an
    /// error instead, so this is empty whenever the import succeeded under it.
    pub refusals: Vec<Refusal>,
    /// How many expressions were read, refused ones included.
    pub tokens: u64,
    /// How many addresses the targets cover, counted after overlapping
    /// expressions are merged, and once per unit an address appears in.
    ///
    /// So a host that was named on two different port specifications counts
    /// twice, because it is two pieces of work. For the number of probes the
    /// scan will send, ask [`TargetMap::gross_targets`].
    ///
    /// Deliberately not the number [`ImportLimits::max_addresses`] is checked
    /// against: the limit errs high to stay cheap, and this one is exact because
    /// a caller reports it to a person.
    pub addresses: u128,
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
        origin: Origin,
        /// The limit it passed.
        limit: usize,
    },

    /// The input was not valid UTF-8.
    #[error("{origin}: not valid UTF-8")]
    InvalidUtf8 {
        /// Where the bytes were.
        origin: Origin,
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
        origin: Origin,
        /// The expression that passed it.
        token: String,
        /// The limit it passed.
        limit: u128,
    },

    /// A target expression was refused under [`OnRefusal::Abort`].
    ///
    /// The expression is not repeated in the message: every
    /// [`TargetParseError`] that has one already names it, and three layers
    /// each quoting the same token reads as a stutter rather than as detail.
    #[error("{origin}: {source}")]
    Target {
        /// Where the expression was.
        origin: Origin,
        /// The expression, as written.
        token: String,
        /// Why the grammar refused it.
        #[source]
        source: TargetParseError,
    },

    /// The document was not in the format it was read as.
    ///
    /// Separate from [`Target`](Self::Target) because the two call for opposite
    /// responses: a malformed expression is one line to fix, and a malformed
    /// document means the format was wrong about what it was reading.
    #[error("{origin}: not valid {format}: {message}")]
    Malformed {
        /// The format it was read as.
        format: &'static str,
        /// Where the document stopped making sense.
        origin: Origin,
        /// What was wrong with it.
        message: String,
    },
}

/// Where an importer puts the target expressions it finds.
///
/// Separate from the importer because the two decisions are separate: a format
/// knows where the expressions are in a byte stream, and a sink knows what to do
/// with one. Splitting them means a caller can count targets without building
/// them, feed them somewhere other than a [`TargetMap`], or apply a policy this
/// crate has not thought of, against every format at once.
pub trait TargetSink {
    /// Takes one target expression, as written, and where it was found.
    ///
    /// Returning an error stops the import. A sink that would rather collect
    /// than stop returns `Ok` and keeps its own record - which is what
    /// [`TargetCollector`] does under [`OnRefusal::Collect`].
    fn accept(&mut self, token: &str, origin: Origin) -> Result<(), ImportError>;
}

/// One input format.
///
/// The single method is deliberate, for the reason [`crate::export::Exporter`]
/// gives: an importer is a reading of a byte stream into target expressions, and
/// every other decision belongs to the value implementing this trait, chosen
/// when it is constructed.
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
/// Enforces the bounds that only a sink can see: how many expressions have
/// arrived, and how many addresses they have named between them. The format
/// enforces the ones only it can see, which is the length of a line.
#[derive(Debug)]
pub struct TargetCollector<'a> {
    builder: TargetMapBuilder,
    options: ImportOptions<'a>,
    refusals: Vec<Refusal>,
    tokens: u64,
    /// Addresses named so far, before overlapping expressions are merged.
    ///
    /// A running sum rather than a re-measurement of the accumulated set, which
    /// would mean merging every group again on every line. It over-counts a file
    /// that names the same block twice; see [`ImportLimits::max_addresses`].
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
    fn accept(&mut self, token: &str, origin: Origin) -> Result<(), ImportError> {
        self.tokens = self.tokens.saturating_add(1);
        if self.tokens > self.options.limits.max_tokens {
            return Err(ImportError::TooManyTokens {
                limit: self.options.limits.max_tokens,
            });
        }

        // Measured against the builder's own count on either side of the push,
        // so what is counted is what was actually added rather than what the
        // expression looked like it would add.
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
                        self.refusals.push(Refusal {
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
    /// comment. What `-iL` reads everywhere else, and what a person types.
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
    /// Returns `None` for an extension no compiled-in format claims. A caller
    /// with an unrecognised extension has not been told what the file is, and
    /// guessing here is how a spreadsheet gets read as a list of hostnames -
    /// which is why the guessing lives in [`sniff`](Self::sniff), where it is
    /// asked for by name, rather than in the fallback of this one.
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.to_ascii_lowercase().as_str() {
            // `lst` is the other spelling in circulation, and `list` is what a
            // person writes when they are not thinking about extensions.
            "txt" | "list" | "lst" => Some(ImportFormat::List),
            #[cfg(feature = "import-csv")]
            "csv" => Some(ImportFormat::Csv),
            #[cfg(feature = "import-json")]
            "json" => Some(ImportFormat::Json),
            // `ndjson` is the other name the same format goes by, matching what
            // the exporter accepts in the other direction.
            #[cfg(feature = "import-json")]
            "jsonl" | "ndjson" => Some(ImportFormat::JsonLines),
            #[cfg(feature = "import-nmap")]
            "xml" => Some(ImportFormat::NmapXml),
            _ => None,
        }
    }

    /// Guesses the format from the start of the input, without consuming it.
    ///
    /// For input that arrived with no name: a pipe, a socket, a paste. The bytes
    /// are read through [`BufRead::fill_buf`], which fills the reader's buffer
    /// and hands back a view of it, so nothing is taken and the importer that
    /// runs next still sees the whole document.
    ///
    /// ## The rule is deliberately timid
    ///
    /// **It only separates a structured format from a list, and anything
    /// ambiguous is a list.** A document opening with `{` is JSON, one opening
    /// with `<` is XML, and one whose first row is a header this crate's CSV
    /// writer emits is that CSV. Everything else is a list - including a
    /// spreadsheet nobody here has seen before, which will then be refused
    /// loudly on its first row rather than read as the wrong thing.
    ///
    /// Two guesses are deliberately not made. A leading `[` is *not* taken as a
    /// JSON array, because `[2001:db8::1]:443` is a perfectly ordinary first
    /// line of a target list and this crate's own JSON is an object. And a
    /// comma is never evidence of CSV, because `192.168.1.1,192.168.1.2` is a
    /// list line that means something quite different read as a table.
    ///
    /// A caller who knows what it has should name the format and skip all of
    /// this.
    pub fn sniff(input: &mut dyn BufRead) -> Result<Self, ImportError> {
        /// Excel's mark, which says nothing about the format behind it.
        const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

        /// What a record-per-line report calls its header record. Compact JSON
        /// has no spaces in it, so this is exactly how the exporter writes it.
        #[cfg(feature = "import-json")]
        const REPORT_TAG: &[u8] = br#""type":"report""#;

        let buffered = input.fill_buf()?;
        let prefix = buffered.strip_prefix(&UTF8_BOM).unwrap_or(buffered);
        let prefix = prefix.trim_ascii_start();

        // Bound before the arms, because a build with no structured format
        // compiled in has no arm to read it and an unused binding there is a
        // warning nobody can act on. Such a build resolves everything to a
        // list, which is the right answer when no other format exists.
        let _ = &prefix;

        #[cfg(feature = "import-csv")]
        {
            // Recognising this crate's own header is not a heuristic about what
            // CSV looks like - it is recognising output this crate wrote. No
            // other table is claimed.
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
            // Both JSON formats open with a brace, and the record-per-line one
            // names itself in its first record. Looking for that tag rather than
            // for a line break is what keeps a compact single-line document from
            // being read as a stream of records.
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
    /// The order matters: a name is something the caller was told, and the
    /// bytes are something this crate worked out. An extension that names no
    /// format falls through to sniffing rather than failing, because
    /// `targets.dat` is a name that says nothing rather than a name that is
    /// wrong.
    pub fn resolve(path: Option<&Path>, input: &mut dyn BufRead) -> Result<Self, ImportError> {
        match path.and_then(Self::from_path) {
            Some(format) => Ok(format),
            None => Self::sniff(input),
        }
    }

    /// Resolves a path by its extension.
    ///
    /// A path with no extension has no format rather than a default one, for
    /// the reason [`crate::export::ExportFormat::from_path`] gives in the other
    /// direction.
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
    /// Front ends use this to describe their own capabilities - a help text
    /// listing formats the binary was not built with is worse than none.
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
    /// The convenience over driving [`Importer`] and [`TargetCollector`]
    /// separately is small, and the consistency is not: every front end that
    /// turns a file into targets should do it the same way.
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
/// Returns `None` if the extension names no format this build supports, leaving
/// the caller to decide what to tell the user. Note that the targets are read
/// from `input`, not from `path` - opening the source stays with the caller, so
/// this works just as well for an upload named `targets.txt` that was never a
/// file.
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

    /// A format resolved from a path has to reach the same importer a caller
    /// would have built by hand, or the two ways of importing diverge.
    #[test]
    fn every_advertised_format_resolves_from_its_own_extension() {
        for format in ImportFormat::all() {
            assert_eq!(
                ImportFormat::from_extension(format.extension()),
                Some(*format),
                "{format} does not resolve from its own extension"
            );
        }

        // An unrecognised extension must not quietly acquire a format.
        assert_eq!(ImportFormat::from_path(Path::new("/tmp/targets")), None);
        assert_eq!(ImportFormat::from_extension("pdf"), None);
    }

    #[test]
    fn reading_by_path_matches_reading_by_format() {
        let opts = options("80");
        let mut input = Cursor::new("10.0.0.1\n");

        let imported = read_from(Path::new("targets.txt"), &mut input, &opts)
            .expect("the extension names a format")
            .expect("the import succeeds");

        assert_eq!(imported.addresses, 1);
        assert!(
            read_from(Path::new("targets.pdf"), &mut Cursor::new(""), &opts).is_none(),
            "an unsupported extension must not quietly produce targets"
        );
    }

    /// The default. One typo must not be absorbed silently, and the error has
    /// to say which line to go and look at.
    #[test]
    fn a_refused_expression_aborts_and_names_its_line() {
        let err = read("10.0.0.1\n10.0.0.300\n10.0.0.2\n", &options("80"))
            .expect_err("the second line is not an address");

        match err {
            ImportError::Target { origin, token, .. } => {
                assert_eq!(origin, Origin::line(2));
                assert_eq!(token, "10.0.0.300");
            }
            other => panic!("expected a refused target, got {other:?}"),
        }
    }

    /// Collecting must hand the refusals back rather than swallow them: the
    /// whole difference between this policy and a silent skip is that the
    /// caller ends up holding the evidence.
    #[test]
    fn collecting_keeps_the_good_targets_and_reports_the_bad_ones() {
        let opts = options("80").with_refusal_policy(OnRefusal::Collect);

        let imported = read("10.0.0.1\n10.0.0.300\nnot-an-address\n10.0.0.2\n", &opts)
            .expect("collecting does not fail the import");

        assert_eq!(imported.addresses, 2, "both good targets survived");
        assert_eq!(imported.refusals.len(), 2);
        assert_eq!(imported.refusals[0].origin, Origin::line(2));
        assert_eq!(imported.refusals[1].token, "not-an-address");
        assert_eq!(imported.tokens, 4, "refused expressions are still counted");
    }

    /// The limit that the whole budget exists for: one short line naming a space
    /// no scan can finish. It has to be refused before anything is probed.
    #[test]
    fn a_range_past_the_address_limit_is_refused() {
        let err = read("::/0\n", &options("80")).expect_err("the whole of IPv6 is not a scan");

        assert!(matches!(err, ImportError::TooManyAddresses { .. }));

        // The default ceiling is the whole of IPv4, which must itself be
        // expressible - a limit that refuses the largest real scan is wrong.
        let imported = read("0.0.0.0/0\n", &options("80")).expect("the whole of IPv4 is a scan");
        assert_eq!(imported.addresses, 1u128 << 32);
    }

    #[test]
    fn limits_can_be_lifted_and_tightened() {
        let permissive = options("80").with_limits(ImportLimits::none());
        assert!(read("::/0\n", &permissive).is_ok());

        let strict = options("80").with_limits(ImportLimits {
            max_addresses: 100,
            ..ImportLimits::default()
        });
        assert!(matches!(
            read("10.0.0.0/24\n", &strict),
            Err(ImportError::TooManyAddresses { .. })
        ));

        let few = options("80").with_limits(ImportLimits {
            max_tokens: 2,
            ..ImportLimits::default()
        });
        assert!(matches!(
            read("10.0.0.1\n10.0.0.2\n10.0.0.3\n", &few),
            Err(ImportError::TooManyTokens { limit: 2 })
        ));
    }

    /// A count reported to a person has to be the number of hosts that will be
    /// probed, which is not the running total the limit is checked against.
    #[test]
    fn the_reported_address_count_merges_overlapping_targets() {
        let imported = read("10.0.0.0/24\n10.0.0.5\n", &options("80")).expect("imports");

        assert_eq!(imported.addresses, 256, "the same block, named twice");
        assert_eq!(imported.tokens, 2);
    }

    /// The plain case this module exists for, end to end: a file of addresses
    /// somebody typed, in both directions the engine can be entered.
    ///
    /// `scan` takes the map as it stands and `discover` takes an `IpSet`, so a
    /// list that only works for one of them only half works.
    #[test]
    fn a_hand_written_list_of_addresses_feeds_both_entry_points() {
        let list = "\
192.168.0.1
192.168.0.100
192.168.0.20
192.168.0.53
192.168.0.151
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
        for address in ["192.168.0.1", "192.168.0.20", "192.168.0.151"] {
            assert!(
                targets.contains(&address.parse().unwrap()),
                "{address} did not survive"
            );
        }
    }

    /// A host named under two different port specifications is two pieces of
    /// work to scan and one host to sweep, so the discovery view has to merge
    /// what the scan view keeps apart.
    #[test]
    fn converting_to_addresses_merges_what_the_units_kept_apart() {
        let imported =
            read("10.0.0.1:22\n10.0.0.1:443\n10.0.0.2:22\n", &options("80")).expect("imports");

        assert_eq!(imported.map.units.len(), 2, "two port specifications");
        assert_eq!(imported.addresses, 3, "counted once per unit");
        assert_eq!(
            imported.into_ip_set().len(),
            2,
            "but only two hosts to sweep"
        );
    }

    /// The contract that makes sniffing usable on a pipe at all: it looks
    /// without taking, so whatever runs next reads the whole document.
    #[test]
    fn sniffing_leaves_the_input_where_it_found_it() {
        let file = "10.0.0.1\n10.0.0.2\n10.0.0.3\n";
        let mut input = Cursor::new(file);

        let format = ImportFormat::sniff(&mut input).expect("sniffs");
        assert_eq!(format, ImportFormat::List);

        let imported = format.read(&mut input, &options("80")).expect("imports");
        assert_eq!(imported.addresses, 3, "sniffing consumed part of the input");
    }

    /// The two guesses deliberately not made, because each would misread a
    /// perfectly ordinary target list.
    #[test]
    fn an_ambiguous_document_is_read_as_a_list() {
        for file in [
            // A bracketed IPv6 target, which is not a JSON array.
            "[2001:db8::1]:443\n",
            // Comma-separated addresses, which are not a table.
            "192.168.1.1,192.168.1.2\n",
            // A table this crate did not write, which is refused loudly by the
            // list grammar rather than guessed at here.
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

    /// Sniffing a table claims this crate's own output and nothing else, so the
    /// signature has to be the header the exporter actually writes - not a copy
    /// of it that can drift.
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

    /// Both report formats open with a brace, so the record-per-line one is
    /// told apart by the tag it names itself with - not by looking for a line
    /// break, which a compact single-line document would also fail.
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

    /// A name the caller was told beats bytes this crate worked out, and a name
    /// that says nothing falls through to the bytes rather than failing.
    #[test]
    fn a_path_decides_the_format_and_a_silent_one_defers_to_the_input() {
        let mut input = Cursor::new("10.0.0.1\n");

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
