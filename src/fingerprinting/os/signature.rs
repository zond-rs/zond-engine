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
//! Compiled into the build script as well as the library — `build.rs` loads this
//! very file with `#[path]` — so a rule the build accepts is exactly a rule the
//! runtime can match. Nothing here may reach for anything the build script
//! cannot compile, which in practice means `serde` and the standard library.
//!
//! A rule is a table of predicates over the fields of a
//! [`StackObservation`](super::StackObservation), and deliberately not a regex:
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
pub const MAX_RULE_WEIGHT: f32 = 10.0;

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
/// Required on every authored rule. A reset carries no TCP options at
/// all whatever the probe offered, and the two replies come from different code
/// paths in one stack that can disagree about the same field — a host measured
/// on a real segment wrote identifier zero on its SYN+ACK path and ran a counter
/// on its reset path. A rule that does not say which segment it reads is
/// matching two different things at once.
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
/// The distinction is that a published value has not been seen **by this engine,
/// through this probe, on a real network** — and that gap is exactly where this
/// project has already been caught out. Option negotiation is reciprocal, so a
/// layout the literature records is the layout a peer sends *to a probe that
/// asked for those options*; against a probe that asked for less it is simply
/// wrong, and it fails by matching nothing while looking perfectly correct.
///
/// So a published rule ships, and scores lower until somebody confirms it here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// Read off a real host by this engine, with the machine's operating system
    /// known independently. Must ship an example; the build warns otherwise.
    Measured,

    /// Taken from published characteristics of the stack — the documented
    /// defaults a family is known to have — and not yet confirmed here.
    ///
    /// Scores below a measured rule, and says where it came from in `notes`.
    #[default]
    Published,
}

/// Who a rule says the host is, as much of the path as the evidence supports.
///
/// A path rather than a name: `family` is the only required part, and a rule
/// that cannot honestly say more stops there. That is what lets a first
/// iteration ship family-level rules and a later one add versions without the
/// schema, the matcher or the resolver changing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsIdentity {
    /// The broad family, such as `"Linux"`. Required.
    pub family: String,
    /// The vendor, such as `"Canonical"`.
    pub vendor: Option<String>,
    /// The product, such as `"Ubuntu"`.
    pub product: Option<String>,
    /// The version or generation, such as `"22.04"`.
    pub version: Option<String>,
    /// A Common Platform Enumeration identifier, if one applies exactly.
    pub cpe: Option<String>,
}

/// The predicates a rule tests, all optional: a field not named is not tested.
///
/// Absence is "do not care", never "must be absent". A rule that needs a field
/// to be missing says so with the field's own predicate — `mss` unset on a reset
/// is a property of resets, not something a rule has to assert.
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
    /// **Measured to be unreliable on a reset.** The same labelled devices
    /// answered two scanners on one segment with opposite values within the
    /// hour. Authored on a reset rule only with evidence that it holds from more
    /// than one vantage point.
    pub dont_fragment: Option<Predicate<bool>>,

    /// The option layout, as the comma-separated letters
    /// [`StackObservation::layout_string`] renders — `"M,S,T,N,W"`.
    ///
    /// **Only comparable between observations that asked the same question.**
    /// Option negotiation is reciprocal, so this is a joint fact about the peer
    /// and the probe. Every rule shipped here is written against the option set
    /// `tcp::create_probe` sends.
    ///
    /// [`StackObservation::layout_string`]: super::StackObservation::layout_string
    pub option_layout: Option<Predicate<String>>,

    /// The advertised window exactly as written.
    ///
    /// **For stacks that advertise a constant**, which is the other of the two
    /// ways a stack picks a window and the one
    /// [`window_units`](Self::window_units) cannot express. Darwin announces
    /// 65535 — the largest value the field holds — whatever the path's segment
    /// size is, so its window is not a multiple of anything and the derived
    /// figures move with the path for no reason belonging to the sender: at an
    /// MSS of 1460 it reads `45 x 1448 + 375`, and at 1360 it reads
    /// `48 x 1348 + 831`. A rule keyed on those would match one path and not the
    /// next.
    ///
    /// Use this where the stack picks a number, and
    /// [`window_units`](Self::window_units) where it picks a multiple. Using
    /// this for a stack of the second kind is the mistake it exists to prevent
    /// on the first: the raw value then moves with whatever the probe offered.
    pub window: Option<Predicate<u16>>,

    /// The advertised window as a multiple of the effective segment size.
    ///
    /// **This rather than the raw window.** A stack counts its window in units
    /// of the segment size it can actually use, and negotiating a timestamp
    /// shrinks that unit by twelve bytes — so the raw value moves with the probe
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
    pub window: u16,
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
