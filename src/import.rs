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
//! use zond_engine::core::models::port::PortSet;
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
pub mod target;

use std::fmt;
use std::io::BufRead;
use std::path::Path;

use crate::core::models::port::PortSet;
use crate::core::models::target::TargetMap;

pub use list::ListImporter;
pub use target::{
    HostLookup, TargetContext, TargetExpr, TargetMapBuilder, TargetParseError, to_target_map,
};

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
    /// expressions are merged.
    ///
    /// This is the number of hosts the scan will probe, and it is deliberately
    /// not the number [`ImportLimits::max_addresses`] is checked against: the
    /// limit errs high to stay cheap, and this one is exact because a caller
    /// reports it to a person.
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
    #[error("{origin}: '{token}': {source}")]
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
}

impl ImportFormat {
    /// Resolves a file extension, case-insensitively and without a leading dot.
    ///
    /// Returns `None` for an extension no compiled-in format claims. A caller
    /// with an unrecognised extension has not been told what the file is, and
    /// guessing here is how a spreadsheet gets read as a list of hostnames -
    /// which is why the guessing lives in a named function of its own rather
    /// than in the fallback of this one.
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.to_ascii_lowercase().as_str() {
            // `lst` is the other spelling in circulation, and `list` is what a
            // person writes when they are not thinking about extensions.
            "txt" | "list" | "lst" => Some(ImportFormat::List),
            _ => None,
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
        }
    }

    /// Every format this build can read.
    pub fn all() -> &'static [ImportFormat] {
        &[ImportFormat::List]
    }

    /// Builds an importer for this format under the given options.
    pub fn importer(self, options: &ImportOptions<'_>) -> Box<dyn Importer> {
        match self {
            ImportFormat::List => Box::new(ListImporter::new(options.limits)),
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
}
