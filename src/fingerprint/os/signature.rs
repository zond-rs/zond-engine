// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The operating-system rule authoring schema
//!
//! What an `assets/fingerprinting/os` TOML file is allowed to say, as types.
//!
//! `build.rs` loads this file with `#[path]`, so it may use only `serde` and the
//! standard library.
//!
//! A rule is a table of predicates over the fields of a
//! [`StackObservation`](super::StackObservation). The three predicate forms are
//! what nmap-os-db, p0f and Satori can all express, so rules translate from any
//! of them.

use serde::{Deserialize, Serialize};

/// The largest weight a single rule may carry.
///
/// A weight ranks matching rules; it is not a probability or an accuracy.
///
/// Accuracy is a base worth times the weight, clamped at
/// [`MAX_STACK_ACCURACY`](super::MAX_STACK_ACCURACY), so a measured rule
/// saturates at about 1.08 and a published one at about 1.4. Two leaves
/// headroom above both.
pub const MAX_RULE_WEIGHT: f32 = 2.0;

/// A test against one field of an observation.
///
/// Exactly one of the three forms must be given; the build refuses none or
/// several.
///
/// Three optional fields so the TOML reads `{ equals = 64 }` and
/// `{ range = [40, 64] }` without a tag.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Predicate<T> {
    /// Matches one value exactly.
    pub equals: Option<T>,
    /// Matches any value in the set.
    pub any_of: Option<Vec<T>>,
    /// Matches a closed interval, low bound first.
    pub range: Option<[T; 2]>,
}

impl<T> Predicate<T> {
    /// How many of the three forms this predicate sets. Exactly one is valid.
    pub fn forms_set(&self) -> usize {
        usize::from(self.equals.is_some())
            + usize::from(self.any_of.is_some())
            + usize::from(self.range.is_some())
    }
}

/// Which segment a rule describes.
///
/// Required on every authored rule: a reset carries no TCP options, and the
/// SYN+ACK and reset paths in one stack can disagree about the same field.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyKind {
    /// A listener accepting a connection attempt. The only reply that carries
    /// options.
    ///
    /// The [`Default`] only for rules built in Rust. `reply` has no serde
    /// default, so an authored rule must state it.
    #[default]
    SynAck,
    /// A refusal.
    Reset,
    /// An answer to a ping.
    ///
    /// The only reply a host with no open or closed port can give. A rule
    /// reading it uses only the IP-level features and the two ICMP ones.
    EchoReply,
}

/// Where a rule's values came from.
///
/// It changes what the rule is worth and what the corpus test demands.
///
/// A published value has not been seen **through this engine's probe**. Option
/// negotiation is reciprocal, so a documented layout holds only for a probe
/// that offered those options. A published rule ships but scores lower until
/// confirmed here.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// Read off a real host by this engine, with the machine's operating system
    /// known independently. Must ship an example; the build warns otherwise.
    Measured,

    /// Taken from published characteristics of the stack, the documented
    /// defaults a family is known to have, and not yet confirmed here.
    ///
    /// Scores below a measured rule, and says where it came from in `notes`.
    #[default]
    Published,
}

/// Who a rule says the host is, as much of the path as the evidence supports.
///
/// A path: a rule stops at the most specific part the evidence supports.
///
/// # Two axes
///
/// [`family`](Self::family) is what the machine *runs* and
/// [`device`](Self::device) what it *is*. A rule must name at least one.
///
/// Do not put a device class in `family`: [`resolve`](super::resolve) settles
/// the family by vote, and a router announcing `Debian 12` over SSH resolved to
/// nothing when a hop-counter rule voted `Network device` as its family.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsIdentity {
    /// The broad family the host runs, such as `"Linux"`.
    ///
    /// `None` for a rule that establishes only what kind of box this is, as a
    /// hop-counter rule usually does.
    pub family: Option<String>,
    /// What kind of box this is, such as `"Network device"` or `"Printer"`.
    ///
    /// Independent of [`family`](Self::family): many network devices run Linux.
    #[serde(default)]
    pub device: Option<String>,
    /// The vendor, such as `"Canonical"`.
    pub vendor: Option<String>,
    /// The product, such as `"Ubuntu"`.
    pub product: Option<String>,
    /// The version or generation, such as `"22.04"`.
    pub version: Option<String>,
    /// A Common Platform Enumeration identifier, if one applies exactly.
    pub cpe: Option<String>,
}

impl OsIdentity {
    /// The name this identity goes by in a diagnostic: the family where it names
    /// one, and the device class otherwise.
    ///
    /// For messages and grouping; to decide what a host is, read the two fields.
    pub fn label(&self) -> &str {
        self.family
            .as_deref()
            .or(self.device.as_deref())
            .unwrap_or("unnamed")
    }
}

/// The predicates a rule tests, all optional: a field not named is not tested.
///
/// An absent predicate means "do not care", not "must be absent".
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchRule {
    /// Which segment this rule reads. Required.
    pub reply: ReplyKind,

    /// The smallest common initial hop counter the observed value is consistent
    /// with. **A lower bound**, correct while the path is shorter than the gap
    /// to the next common starting value.
    pub initial_hops: Option<Predicate<u8>>,

    /// Whether the sender forbade fragmentation in transit.
    ///
    /// Unreliable on a reset: the same devices answered two scanners with
    /// opposite values within the hour. Use it on a reset rule only with
    /// evidence from more than one vantage point.
    pub dont_fragment: Option<Predicate<bool>>,

    /// The option layout, as the comma-separated letters
    /// [`StackObservation::layout_string`] renders them: `"M,S,T,N,W"`.
    ///
    /// Depends on the probe, since option negotiation is reciprocal. Shipped rules
    /// are written against the option set `tcp::build_probe` sends.
    ///
    /// [`StackObservation::layout_string`]: super::StackObservation::layout_string
    pub option_layout: Option<Predicate<String>>,

    /// The advertised window exactly as written.
    ///
    /// For stacks that advertise a constant. Darwin announces 65535 whatever the
    /// segment size, so its derived figures move with the path (`45 x 1448 + 375`
    /// at an MSS of 1460, `48 x 1348 + 831` at 1360).
    ///
    /// Use this where the stack picks a number, and
    /// [`window_units`](Self::window_units) where it picks a multiple.
    pub window: Option<Predicate<u16>>,

    /// The advertised window as a multiple of the effective segment size.
    ///
    /// A negotiated timestamp shrinks the unit by twelve bytes, so the raw window
    /// moves with the probe and the multiplier does not: one host gave
    /// `20 x 1460` and `20 x 1448`.
    pub window_units: Option<Predicate<u16>>,

    /// What is left over after that division. It can be stable: a wide-area host
    /// kept an offset of 940 across two probes.
    pub window_remainder: Option<Predicate<u16>>,

    /// The window scale shift count.
    pub window_scale: Option<Predicate<u8>>,

    /// The announced maximum segment size. Mostly about the path, so weak alone.
    pub mss: Option<Predicate<u16>>,

    /// Whether the reply carried a timestamp.
    pub timestamps: Option<Predicate<bool>>,

    /// Whether the reply said it accepts selective acknowledgement.
    pub sack_permitted: Option<Predicate<bool>>,

    /// What a series of IP identifiers turned out to be, as the stable name
    /// [`IdClass::name`](super::IdClass::name) renders it: `"counting"`,
    /// `"zero"`, `"scattered"`.
    ///
    /// A series feature, collected only by the active path; against a single
    /// reply the rule fails as for any absent field.
    ///
    /// [`IdClass::name`]: super::IdClass::name
    pub identifier_class: Option<Predicate<String>>,

    /// What a series of initial sequence numbers turned out to be, as
    /// [`IsnClass::name`](super::IsnClass::name) renders it: `"fixed-step"`,
    /// `"hashed"`.
    ///
    /// Whether a generator hashes (RFC 6528) or steps changed between releases,
    /// which makes it useful for version-level rules.
    ///
    /// [`IsnClass::name`]: super::IsnClass::name
    pub sequence_class: Option<Predicate<String>>,

    /// Whether the timestamp clock is shared across connections or offset
    /// randomly per one, as [`ClockClass::name`](super::ClockClass::name)
    /// renders it: `"ticking"` against `"randomised"`.
    ///
    /// The rate itself carries sampling jitter, so rules cannot key on it.
    ///
    /// [`ClockClass::name`]: super::ClockClass::name
    pub clock_class: Option<Predicate<String>>,

    /// The code byte an echo reply carried.
    ///
    /// Meaningful only against a non-zero request code: some stacks echo it, some
    /// write zero (RFC 792 and RFC 4443 §4.2 leave it open). Shipped rules are
    /// written against
    /// [`ECHO_PROBE_CODE`](crate::protocols::icmp::ECHO_PROBE_CODE).
    pub echo_code: Option<Predicate<u8>>,

    /// Whether an echo reply returned the payload it was sent, unchanged.
    ///
    /// Required by both RFCs, so `false` marks an unusual stack.
    pub echo_payload_intact: Option<Predicate<bool>>,
}

/// One observation a rule is required to match, recorded from a real host.
///
/// The corpus test runs every example through its own rule and every other
/// family's rules.
///
/// `source` says where and when the values were measured.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Example {
    /// Where these values were measured, and when.
    pub source: String,
    /// Which segment they were read off.
    pub reply: ReplyKind,
    /// The hop counter as it arrived.
    pub remaining_hops: u8,
    /// Whether the sender forbade fragmentation.
    pub dont_fragment: bool,
    /// The option layout, as letters.
    #[serde(default)]
    pub option_layout: String,
    /// The advertised window, as written.
    ///
    /// **Required for a TCP example** (enforced by `build.rs`); optional because
    /// an echo reply has none.
    #[serde(default)]
    pub window: Option<u16>,
    /// The announced maximum segment size.
    pub mss: Option<u16>,
    /// The window scale shift count.
    pub window_scale: Option<u8>,
    /// Whether a timestamp was carried.
    #[serde(default)]
    pub timestamps: bool,
    /// Whether selective acknowledgement was permitted.
    #[serde(default)]
    pub sack_permitted: bool,
    /// The code an echo reply carried. Ignored for a TCP example.
    #[serde(default)]
    pub echo_code: u8,
    /// Whether an echo reply returned its payload unchanged. Ignored for a TCP
    /// example; `true` by default, as both RFCs require.
    #[serde(default = "yes")]
    pub echo_payload_intact: bool,

    /// What the identifier series read, as
    /// [`IdClass::name`](super::IdClass::name) renders it.
    ///
    /// Lets the corpus tests check rules that predicate on a series.
    #[serde(default)]
    pub identifier_class: Option<String>,

    /// What the initial-sequence-number series read, as
    /// [`IsnClass::name`](super::IsnClass::name) renders it.
    #[serde(default)]
    pub sequence_class: Option<String>,

    /// What the timestamp series read, as
    /// [`ClockClass::name`](super::ClockClass::name) renders it.
    #[serde(default)]
    pub clock_class: Option<String>,
}

impl Example {
    /// Whether this example recorded what a series read.
    ///
    /// One that states none cannot check a series rule.
    pub fn records_a_series(&self) -> bool {
        self.identifier_class.is_some()
            || self.sequence_class.is_some()
            || self.clock_class.is_some()
    }
}

/// `#[serde(default)]` for a flag whose default is on: a rule that says nothing
/// about it means yes.
fn yes() -> bool {
    true
}

/// One authored rule: who it names, what it tests, and what it must match.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsDefinition {
    /// Who this rule says the host is.
    pub os: OsIdentity,
    /// Where its values came from, and so how much it is worth.
    #[serde(default)]
    pub provenance: Provenance,
    /// Free text: what the values rest on, and anything a later reader needs in
    /// order to confirm or correct them.
    #[serde(default)]
    pub notes: Option<String>,
    /// How much this rule is worth against others that also match. Defaults to
    /// one; bounded by [`MAX_RULE_WEIGHT`].
    #[serde(default = "default_weight")]
    pub weight: f32,
    /// The predicates.
    pub r#match: MatchRule,
    /// Observations this rule must match, from real hosts.
    #[serde(default)]
    pub example: Vec<Example>,
}

impl OsDefinition {
    /// A rule naming `os` by `r#match`, with the defaults an authored file
    /// gets for what it leaves out: published provenance, no notes, a weight
    /// of one and no examples.
    pub fn new(os: OsIdentity, r#match: MatchRule) -> Self {
        Self {
            os,
            provenance: Provenance::default(),
            notes: None,
            weight: default_weight(),
            r#match,
            example: Vec::new(),
        }
    }
}

/// `#[serde(default)]` for a predicate's weight: unweighted means weighted one,
/// not weighted zero.
fn default_weight() -> f32 {
    1.0
}

/// Why one predicate could never do its job.
///
/// Each would make a rule silently match nothing or everything.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateDefect {
    /// None of `equals`, `any_of` or `range` is set, so nothing satisfies it.
    NoForm,
    /// Several are set; exactly one is allowed.
    SeveralForms(usize),
    /// `any_of` is present and empty, so no value is in it.
    EmptyAnyOf,
    /// `range`'s low bound is above its high bound, so the interval is empty.
    BackwardsRange,
}

impl std::fmt::Display for PredicateDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PredicateDefect::NoForm => {
                f.write_str("sets none of equals/any_of/range, so it can never match")
            }
            PredicateDefect::SeveralForms(count) => write!(
                f,
                "sets {count} of equals/any_of/range; exactly one is allowed"
            ),
            PredicateDefect::EmptyAnyOf => {
                f.write_str("has an empty any_of, so it can never match")
            }
            PredicateDefect::BackwardsRange => f.write_str(
                "has a range whose low bound is above its high bound, so it can never match",
            ),
        }
    }
}

/// Why an authored rule cannot be used.
///
/// Every variant is a defect invisible at runtime, so each is refused.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum RuleError {
    /// The rule names neither a family nor a device class, so it identifies
    /// nothing.
    Unidentified,
    /// The rule states a version with no product to version.
    VersionWithoutProduct,
    /// The weight is outside `0.0..=`[`MAX_RULE_WEIGHT`], or is not finite.
    Weight(f32),
    /// One of the rule's predicates could never do its job.
    Predicate {
        /// The observation field it tests, such as `"initial_hops"`.
        field: &'static str,
        /// What is wrong with it.
        defect: PredicateDefect,
    },
    /// The rule tests nothing at all, so it matches every reply of its kind.
    NoPredicates,
    /// A rule reads a series and an example recorded none, so nothing can check
    /// the rule against it.
    ExampleWithoutSeries(String),
    /// A TCP example records no advertised window.
    ///
    /// The schema cannot require it, since an echo reply has none.
    ExampleWithoutWindow(ReplyKind),
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleError::Unidentified => f.write_str("names neither a family nor a device class"),
            RuleError::VersionWithoutProduct => {
                f.write_str("states a version without a product to version")
            }
            RuleError::Weight(value) => {
                write!(f, "has weight {value}, outside 0..={MAX_RULE_WEIGHT}")
            }
            RuleError::Predicate { field, defect } => write!(f, "predicate `{field}` {defect}"),
            RuleError::NoPredicates => {
                f.write_str("states no predicates, so it would match every reply of its kind")
            }
            RuleError::ExampleWithoutSeries(source) => write!(
                f,
                "reads a series and its example ({source}) recorded none, so nothing \
                 checks the rule against it"
            ),
            RuleError::ExampleWithoutWindow(reply) => write!(
                f,
                "has a {reply:?} example with no window; only an echo example may omit one"
            ),
        }
    }
}

impl std::error::Error for RuleError {}

impl<T: PartialOrd> Predicate<T> {
    /// Why this predicate could never do its job, if it could not.
    ///
    /// `None` on a well-formed one. Kept beside the type so a new form must be
    /// handled here.
    pub fn defect(&self) -> Option<PredicateDefect> {
        match self.forms_set() {
            1 => {}
            0 => return Some(PredicateDefect::NoForm),
            several => return Some(PredicateDefect::SeveralForms(several)),
        }
        if self.any_of.as_ref().is_some_and(Vec::is_empty) {
            return Some(PredicateDefect::EmptyAnyOf);
        }
        if let Some([low, high]) = &self.range
            && low > high
        {
            return Some(PredicateDefect::BackwardsRange);
        }
        None
    }
}

impl MatchRule {
    /// Checks every predicate this rule states, and that it states one.
    ///
    /// Add every new predicate field to the macro call here.
    pub fn validate(&self) -> Result<(), RuleError> {
        let mut stated = 0usize;
        macro_rules! check {
            ($($field:ident),* $(,)?) => {$(
                if let Some(predicate) = &self.$field {
                    stated += 1;
                    if let Some(defect) = predicate.defect() {
                        return Err(RuleError::Predicate {
                            field: stringify!($field),
                            defect,
                        });
                    }
                }
            )*};
        }
        check!(
            initial_hops,
            dont_fragment,
            option_layout,
            window,
            window_units,
            window_remainder,
            window_scale,
            mss,
            timestamps,
            sack_permitted,
            echo_code,
            echo_payload_intact,
            identifier_class,
            sequence_class,
            clock_class,
        );

        match stated {
            0 => Err(RuleError::NoPredicates),
            _ => Ok(()),
        }
    }
}

impl OsDefinition {
    /// Whether this rule is one the engine may use.
    ///
    /// Shared with `build.rs`, so the build and
    /// [`RuleDb::try_from_rules`](super::RuleDb::try_from_rules) accept the same
    /// rules. The build also warns about advisory issues (a measured rule with no
    /// example, a published one with no notes).
    ///
    /// [`MatchRule::validate`] does the per-predicate half.
    pub fn validate(&self) -> Result<(), RuleError> {
        let named = |part: &Option<String>| {
            part.as_deref()
                .is_some_and(|value| !value.trim().is_empty())
        };
        if !named(&self.os.family) && !named(&self.os.device) {
            return Err(RuleError::Unidentified);
        }

        // A version needs a product; a product without a vendor is fine.
        if self.os.version.is_some() && self.os.product.is_none() {
            return Err(RuleError::VersionWithoutProduct);
        }

        if !(0.0..=MAX_RULE_WEIGHT).contains(&self.weight) || !self.weight.is_finite() {
            return Err(RuleError::Weight(self.weight));
        }

        self.r#match.validate()?;

        for example in &self.example {
            if example.reply != ReplyKind::EchoReply && example.window.is_none() {
                return Err(RuleError::ExampleWithoutWindow(example.reply));
            }
        }

        // A series rule's examples must record a series, or the corpus test
        // would read the rule as broken.
        let reads_a_series = self.r#match.identifier_class.is_some()
            || self.r#match.sequence_class.is_some()
            || self.r#match.clock_class.is_some();
        if reads_a_series && let Some(example) = self.example.iter().find(|e| !e.records_a_series())
        {
            return Err(RuleError::ExampleWithoutSeries(example.source.clone()));
        }

        Ok(())
    }
}
