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
//! Compiled into the build script as well as the library, `build.rs` loads this
//! very file with `#[path]`, so a rule the build accepts is exactly a rule the
//! runtime can match. Nothing here may reach for anything the build script
//! cannot compile, which in practice means `serde` and the standard library.
//!
//! A rule is a table of predicates over the fields of a
//! [`StackObservation`](super::StackObservation), and not a regex:
//! an operating-system rule matches a typed feature vector rather than text. The
//! three predicate forms are the intersection of what nmap-os-db, p0f and Satori
//! can express, so a translator from any of them never has to invent semantics
//! the source format has no way to state.

use serde::{Deserialize, Serialize};

/// The largest weight a single rule may carry.
///
/// A weight ranks rules against each other when several match; it is not a
/// probability and it is not an accuracy. Bounding it keeps one authored value
/// from dominating every other piece of evidence about a host, which is the same
/// reasoning that clamps `OsFingerprint::accuracy` at construction.
///
/// Two, because that is where the knob stops turning. A verdict's accuracy
/// is a base worth times this, clamped at
/// [`MAX_STACK_ACCURACY`](super::MAX_STACK_ACCURACY), so a measured rule
/// saturates at about 1.08 and a published one at about 1.4. This was ten, and
/// measured, every weight from 1.08 to 10 produced the identical answer: nine
/// tenths of the range an author could reach for did nothing, and the build
/// validated against the end of it where nothing happens.
///
/// Two leaves headroom above both saturation points without pretending to an
/// authority the arithmetic does not give it.
pub const MAX_RULE_WEIGHT: f32 = 2.0;

/// A test against one field of an observation.
///
/// Exactly one of the three forms must be given; the build refuses a predicate
/// that sets none or several, because both are an authoring mistake that would
/// otherwise silently match everything or nothing.
///
/// Written as three optional fields rather than an enum so the TOML reads as
/// `{ equals = 64 }` and `{ range = [40, 64] }` without a tag, and so a
/// malformed one produces an error naming the file rather than a deserialization
/// message about variants.
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
/// Required on every authored rule. A reset carries no TCP options at all
/// whatever the probe offered, and the two replies come from different code
/// paths in one stack that can disagree about the same field, a host measured
/// on a real segment wrote identifier zero on its SYN+ACK path and ran a
/// counter on its reset path. A rule that does not say which segment it reads
/// is matching two different things at once.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyKind {
    /// A listener accepting a connection attempt. The only reply that carries
    /// options.
    ///
    /// The [`Default`] only so that [`MatchRule`] can have one for rules built in
    /// Rust. It is never reached from an authored file: `reply` has no serde
    /// default, so a rule that omits it fails to parse and fails the build.
    #[default]
    SynAck,
    /// A refusal.
    Reset,
    /// An answer to a ping.
    ///
    /// The only reply kind here that a host with no open **and** no closed port
    /// can produce, which is the whole reason for sending one. It carries no
    /// TCP fields at all, so a rule reading it names the IP-level features and
    /// the two ICMP ones and nothing else.
    EchoReply,
}

/// Where a rule's values came from.
///
/// Not bookkeeping. It changes what the rule is worth, and it changes what the
/// corpus test demands of it.
///
/// The distinction is **not** that published values are unreliable. A stack's
/// initial hop counter, the order it writes its TCP options in, and whether it
/// offers timestamps by default are ordinary engineering facts, documented for
/// decades and stable across releases; refusing to use them would mean
/// re-deriving the whole of p0f from scratch to arrive at the same table.
///
/// The distinction is that a published value has not been seen **by this
/// engine, through this probe, on a real network**, and that gap is exactly
/// where this project has already been caught out. Option negotiation is
/// reciprocal, so a layout the literature records is the layout a peer sends
/// *to a probe that asked for those options*; against a probe that asked for
/// less it is simply wrong, and it fails by matching nothing while looking
/// perfectly correct.
///
/// So a published rule ships, and scores lower until somebody confirms it here.
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
/// A path rather than a name: a rule that cannot honestly say more than the
/// broadest part stops there. That is what lets a first iteration ship
/// family-level rules and a later one add versions without the schema, the
/// matcher or the resolver changing.
///
/// # Two axes, and a rule must reach one of them
///
/// [`family`](Self::family) is what the machine *runs* and
/// [`device`](Self::device) is what it *is*, and neither stands in for the
/// other. A rule must name at least one; `build.rs` refuses one that names
/// neither, since it would identify nothing.
///
/// The distinction is not decoration, and getting it wrong has a specific cost.
/// [`resolve`](super::resolve) settles the family by vote, so a device class
/// written into the family field runs against the real families on the ballot
/// and both lose. That is measured, not hypothetical: a Linux-based router
/// announcing `Debian 12` over SSH resolved to nothing at all while a rule
/// reading its hop counter called it a `Network device` in the family field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsIdentity {
    /// The broad family the host runs, such as `"Linux"`.
    ///
    /// `None` for a rule that establishes what kind of box this is and cannot
    /// say what is on it, which is the ordinary case for a rule reading a hop
    /// counter.
    pub family: Option<String>,
    /// What kind of box this is, such as `"Network device"` or `"Printer"`.
    ///
    /// Orthogonal to [`family`](Self::family) and never a substitute for it: a
    /// great many network devices run Linux, and a rule that establishes only
    /// the first says so here and abstains from the second.
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
    /// Every rule reaches one of the two, which `build.rs` enforces, so this
    /// always names something. It is for messages and for grouping rules that
    /// describe the same thing; a consumer deciding what a host *is* reads the
    /// two fields, which say different things on purpose.
    pub fn label(&self) -> &str {
        self.family
            .as_deref()
            .or(self.device.as_deref())
            .unwrap_or("unnamed")
    }
}

/// The predicates a rule tests, all optional: a field not named is not tested.
///
/// Absence is "do not care", never "must be absent". A rule that needs a field
/// to be missing says so with the field's own predicate: `mss` unset on a reset
/// is a property of resets rather than something a rule has to assert.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchRule {
    /// Which segment this rule reads. Required.
    pub reply: ReplyKind,

    /// The smallest common initial hop counter the observed value is consistent
    /// with. **A bound, not the value the sender wrote**: every router
    /// decrements it, so what arrives is the initial value less the hop count.
    /// Correct while the path is shorter than the gap to the next common
    /// starting value, and a rule that needs more than that is a rule that
    /// cannot be written from one reply.
    pub initial_hops: Option<Predicate<u8>>,

    /// Whether the sender forbade fragmentation in transit.
    ///
    /// Measured to be unreliable on a reset. The same labelled devices
    /// answered two scanners on one segment with opposite values within the
    /// hour. Authored on a reset rule only with evidence that it holds from more
    /// than one vantage point.
    pub dont_fragment: Option<Predicate<bool>>,

    /// The option layout, as the comma-separated letters
    /// [`StackObservation::layout_string`] renders them: `"M,S,T,N,W"`.
    ///
    /// Only comparable between observations that asked the same question.
    /// Option negotiation is reciprocal, so this is a joint fact about the peer
    /// and the probe. Every rule shipped here is written against the option set
    /// `tcp::build_probe` sends.
    ///
    /// [`StackObservation::layout_string`]: super::StackObservation::layout_string
    pub option_layout: Option<Predicate<String>>,

    /// The advertised window exactly as written.
    ///
    /// For stacks that advertise a constant, which is the other of the two
    /// ways a stack picks a window and the one
    /// [`window_units`](Self::window_units) cannot express. Darwin announces
    /// 65535, the largest value the field holds, whatever the path's segment
    /// size is, so its window is not a multiple of anything and the derived
    /// figures move with the path for no reason belonging to the sender: at an
    /// MSS of 1460 it reads `45 x 1448 + 375`, and at 1360 it reads `48 x 1348
    /// + 831`. A rule keyed on those would match one path and not the next.
    ///
    /// Use this where the stack picks a number, and
    /// [`window_units`](Self::window_units) where it picks a multiple. Using
    /// this for a stack of the second kind is the mistake it exists to prevent
    /// on the first: the raw value then moves with whatever the probe offered.
    pub window: Option<Predicate<u16>>,

    /// The advertised window as a multiple of the effective segment size.
    ///
    /// This rather than the raw window. A stack counts its window in units
    /// of the segment size it can actually use, and negotiating a timestamp
    /// shrinks that unit by twelve bytes, so the raw value moves with the probe
    /// and the multiplier does not. Measured on one host: `20 x 1460` under one
    /// probe and `20 x 1448` under another, the same twenty either way.
    pub window_units: Option<Predicate<u16>>,

    /// What is left over after that division. Not every stack picks a clean
    /// multiple, and a wide-area host measured a stable offset of 940 across two
    /// probes with two different units, so the remainder is a feature rather
    /// than rounding error.
    pub window_remainder: Option<Predicate<u16>>,

    /// The window scale shift count.
    pub window_scale: Option<Predicate<u8>>,

    /// The announced maximum segment size. Mostly a fact about the path rather
    /// than the sender, so weak on its own and useful beside the window.
    pub mss: Option<Predicate<u16>>,

    /// Whether the reply carried a timestamp.
    pub timestamps: Option<Predicate<bool>>,

    /// Whether the reply said it accepts selective acknowledgement.
    pub sack_permitted: Option<Predicate<bool>>,

    /// What a series of IP identifiers turned out to be, as the stable name
    /// [`IdClass::name`](super::IdClass::name) renders it: `"counting"`,
    /// `"zero"`, `"scattered"`.
    ///
    /// A series feature, not a one-reply feature. A rule naming it is
    /// matched against the classes read from several replies, which only the
    /// active path collects; the passive matcher has no series and a rule
    /// naming this predicate fails against it by the ordinary "the peer did
    /// not say" rule.
    ///
    /// [`IdClass::name`]: super::IdClass::name
    pub identifier_class: Option<Predicate<String>>,

    /// What a series of initial sequence numbers turned out to be, as
    /// [`IsnClass::name`](super::IsnClass::name) renders it: `"fixed-step"`,
    /// `"hashed"`.
    ///
    /// Version-level rules start here: whether a generator hashes (RFC 6528),
    /// steps, or sleeps is a decision the stack's authors made and changed
    /// between releases, which is exactly the axis a "Linux 5.x" rule needs.
    ///
    /// [`IsnClass::name`]: super::IsnClass::name
    pub sequence_class: Option<Predicate<String>>,

    /// Whether the timestamp clock is shared across connections or offset
    /// randomly per one, as [`ClockClass::name`](super::ClockClass::name)
    /// renders it: `"ticking"` against `"randomised"`.
    ///
    /// The rate is not predicate-able: it is a stack constant,
    /// but the sampling jitter of a scan is not, and a rule keyed on an exact
    /// hertz would match one network and not the next.
    ///
    /// [`ClockClass::name`]: super::ClockClass::name
    pub clock_class: Option<Predicate<String>>,

    /// The code byte an echo reply carried.
    ///
    /// Only meaningful against a probe that sent a non-zero code. RFC 792
    /// and RFC 4443 §4.2 define an echo's code as zero and say nothing about
    /// what a responder should do with anything else, so stacks differ: some
    /// echo the request's code back and some write zero. A probe sending zero
    /// cannot tell the two apart, because both answer zero, the same
    /// reciprocity trap the TCP option layout fell into, in a different field.
    /// Every rule shipped here is written against the code
    /// [`ECHO_PROBE_CODE`](crate::protocols::icmp::ECHO_PROBE_CODE) sends.
    pub echo_code: Option<Predicate<u8>>,

    /// Whether an echo reply returned the payload it was sent, unchanged.
    ///
    /// Required by both RFCs, so this is conformance rather than preference and
    /// a rule naming it is naming an *unusual* stack.
    pub echo_payload_intact: Option<Predicate<bool>>,
}

/// One observation a rule is required to match, recorded from a real host.
///
/// Not decoration. The corpus test runs every example through its own rule and
/// through every *other* family's rules, so an authored rule that stopped
/// matching what it was written for, or started matching a different family,
/// fails at that point rather than silently degrading detection.
///
/// `source` is free text and is meant to say where the values came from and
/// when, because a corpus entry nobody can trace is a corpus entry nobody can
/// re-measure.
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
    /// Optional in the schema and **required for a TCP example**, which
    /// `build.rs` enforces. An echo reply has no window, and defaulting the
    /// field to zero instead would let a handshake example omit the single most
    /// load-bearing value it records and still parse, recording a window of zero,
    /// which no stack advertises, as though it had been measured.
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
    /// example, and `true` by default because that is what both RFCs require,
    /// an example recording the conformant case should not have to say so.
    #[serde(default = "yes")]
    pub echo_payload_intact: bool,

    /// What the identifier series read, as
    /// [`IdClass::name`](super::IdClass::name) renders it.
    ///
    /// A series rule could be matched and could not be exampled, and the two
    /// corpus tests that catch a rule which stopped matching, or started
    /// matching the wrong family, run off examples. So the first rule to
    /// predicate on a series shipped with nothing checking it, at the moment the
    /// classifier behind it was least proven. `linux.toml` records having hit
    /// exactly that and declining to write the rule.
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
    /// An example that states none is a single-reply measurement, and a rule
    /// predicating on a series cannot be checked against one.
    pub fn records_a_series(&self) -> bool {
        self.identifier_class.is_some()
            || self.sequence_class.is_some()
            || self.clock_class.is_some()
    }
}

fn yes() -> bool {
    true
}

/// One authored rule: who it names, what it tests, and what it must match.
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

fn default_weight() -> f32 {
    1.0
}

/// Why one predicate could never do its job.
///
/// Each of these is an authoring mistake whose failure mode is silence: the rule
/// parses, ships, and matches nothing or everything. Naming them is what lets
/// both the build and a caller supplying their own corpus refuse the same rule
/// for the same stated reason.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateDefect {
    /// None of `equals`, `any_of` or `range` is set, so nothing satisfies it.
    NoForm,
    /// Several are set. Exactly one is allowed, and which would win is not
    /// something an author should have to know.
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
/// Every variant is a defect whose cost is invisible at runtime. A rule with
/// no predicates matches every reply of its kind and names every host that ever
/// answers; one with a backwards range matches nothing while looking perfectly
/// correct. Neither is distinguishable downstream from detection that worked,
/// which is why they are refused rather than warned about.
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
    /// The schema cannot require one, because an echo reply has no window; the
    /// requirement is per reply kind and lives here. An example that omits it
    /// records nothing about the field its rule most likely keys on.
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
    /// `Ok` on a well-formed one. Kept beside the type rather than in the
    /// validator so a form added to [`Predicate`] is a form this has to answer
    /// for.
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
    /// The macro is what keeps this in step with the struct. A predicate field
    /// added above and not added here is a field nothing validates, and the
    /// failure mode of an unvalidated predicate is a rule that ships and matches
    /// the wrong hosts.
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
    /// Shared with `build.rs`, which loads this very file, so the rules the
    /// build accepts and the rules a caller may load through
    /// [`RuleDb::try_from_rules`](super::RuleDb::try_from_rules) are one set
    /// rather than two descriptions of one idea. The build additionally *warns*
    /// about softer things, a measured rule with no example, an unconfirmed one
    /// that does not say what it rests on, which are advisory and stay there.
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

        // The identity is a path, so a segment cannot be given without the one
        // above it. "Ubuntu 22.04" with no vendor is fine; a version with no
        // product names a version of nothing.
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

        // A rule that reads a series and ships an example that recorded none is
        // an example the corpus test cannot run: the rule fails against it by
        // the ordinary "the peer did not say" rule and the failure looks like a
        // rule that stopped matching. Refused rather than warned about, because
        // it is indistinguishable downstream from a rule that is simply wrong.
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
