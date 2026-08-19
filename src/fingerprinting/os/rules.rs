// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Deciding whether a rule describes an observation
//!
//! One function, applied field by field. A rule holds a predicate per field and
//! an observation holds a value per field; a rule matches when **every predicate
//! it states is satisfied**, and a field the rule does not name is not tested.
//!
//! ## Absence is "do not care", and it is not free
//!
//! A rule naming no predicates at all matches everything, which is why the build
//! refuses one. Between that and a fully specified rule the trade is the usual
//! one, and it is worth being explicit about which way it fails: a rule that
//! names too few fields matches hosts it should not and is *confidently wrong*,
//! while one that names too many matches nothing and is merely useless. The
//! second failure is visible in the corpus test; the first is not, which is why
//! that test also runs every example against every other family's rules.
//!
//! ## A predicate over a value the observation does not have
//!
//! A rule may ask about a maximum segment size on a reply that carries none — a
//! reset carries no options whatever the probe offered. That is a **failure to
//! match**, never a match: "the peer did not say" and "the peer said something
//! this rule accepts" are different, and treating the first as the second would
//! let a reset satisfy a rule written for a handshake.

use super::observation::StackObservation;
use super::signature::{MatchRule, Predicate, ReplyKind};

/// Whether a predicate accepts `value`.
///
/// Exactly one form is set on a well-formed predicate, which `build.rs` enforces
/// at compile time; a predicate that somehow sets none accepts nothing rather
/// than everything, so a defect that escapes the build narrows detection instead
/// of silently widening it.
pub fn accepts<T: PartialOrd>(predicate: &Predicate<T>, value: &T) -> bool {
    if let Some(expected) = &predicate.equals {
        return expected == value;
    }
    if let Some(expected) = &predicate.any_of {
        return expected.contains(value);
    }
    if let Some([low, high]) = &predicate.range {
        return value >= low && value <= high;
    }
    false
}

/// Whether `predicate` accepts what the observation holds, where the observation
/// may hold nothing.
///
/// Takes the value by reference so a predicate over a `String` costs a
/// comparison rather than a clone. `None` never matches; see the module
/// documentation.
fn accepts_optional<T: PartialOrd>(predicate: &Option<Predicate<T>>, value: Option<&T>) -> bool {
    match (predicate, value) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(predicate), Some(value)) => accepts(predicate, value),
    }
}

/// An observation with its derived values worked out, so a set of rules can be
/// asked about it without each one recomputing them.
///
/// The reason this exists is measurable and was measured. Rendering the option
/// layout allocates, and doing it inside the per-rule test made matching cost
/// **3.2 ms per host against ten thousand rules** — 210 seconds of pure CPU for a
/// `/16`, all of it spent building the same short string ten thousand times.
/// Hoisting it is the difference between linear-with-a-big-constant and
/// linear-with-a-small-one.
///
/// It is the same principle the service signatures run on next door, where a
/// regex is compiled once and cached rather than per match; only the expensive
/// thing differs. Two rules do not need this. Ten thousand, which is what
/// translating a public corpus would bring, very much do — and the shape of the
/// code should not have to change when they arrive.
struct Prepared<'a> {
    observed: &'a StackObservation,
    layout: String,
    initial_hops: u8,
    dont_fragment: bool,
    window_units: Option<u16>,
    window_remainder: Option<u16>,
}

impl<'a> Prepared<'a> {
    fn new(observed: &'a StackObservation) -> Self {
        let (window_units, window_remainder) = match observed.window_in_units() {
            Some((units, remainder)) => (Some(units), Some(remainder)),
            None => (None, None),
        };
        Self {
            observed,
            layout: observed.layout_string(),
            initial_hops: observed.initial_hops_at_least(),
            dont_fragment: matches!(
                observed.ip,
                crate::model::capture::IpObservation::V4(v4) if v4.dont_fragment
            ),
            window_units,
            window_remainder,
        }
    }

    /// Whether `rule` describes the observation this was prepared from.
    fn matches(&self, rule: &MatchRule) -> bool {
        let kind_agrees = match rule.reply {
            ReplyKind::SynAck => self.observed.is_syn_ack(),
            ReplyKind::Reset => self.observed.is_reset(),
        };
        if !kind_agrees {
            return false;
        }

        // Cheapest and most selective first: the integer comparisons reject the
        // overwhelming majority of a large rule set before the string comparison
        // is ever reached.
        accepts_optional(&rule.initial_hops, Some(&self.initial_hops))
            && accepts_optional(&rule.window, Some(&self.observed.window))
            && accepts_optional(&rule.window_units, self.window_units.as_ref())
            && accepts_optional(&rule.window_remainder, self.window_remainder.as_ref())
            && accepts_optional(&rule.window_scale, self.observed.window_scale.as_ref())
            && accepts_optional(&rule.mss, self.observed.mss.as_ref())
            && accepts_optional(&rule.dont_fragment, Some(&self.dont_fragment))
            && accepts_optional(&rule.timestamps, Some(&self.observed.timestamps.is_some()))
            && accepts_optional(&rule.sack_permitted, Some(&self.observed.sack_permitted))
            && accepts_optional(&rule.option_layout, Some(&self.layout))
    }
}

/// Whether `rule` describes `observed`.
///
/// The single-shot entry point. Asking about many rules at once should go
/// through [`RuleDb::matching`](super::RuleDb::matching), which prepares the
/// derived values once rather than per rule.
///
/// The reply kind is checked first and is not optional: a rule written for a
/// handshake must never be applied to a reset, whatever else agrees.
pub fn matches(rule: &MatchRule, observed: &StackObservation) -> bool {
    Prepared::new(observed).matches(rule)
}

/// Every rule in `rules` that describes `observed`, with the derived values
/// computed once for the whole set.
pub(super) fn matching<'a>(
    rules: &'a [super::signature::OsDefinition],
    observed: &'a StackObservation,
) -> impl Iterator<Item = &'a super::signature::OsDefinition> {
    // Moved into the closure so it is built once and lives as long as the
    // iterator, rather than per rule. The iterator stays lazy: a caller wanting
    // only the first match pays for only the rules before it.
    let prepared = Prepared::new(observed);
    rules
        .iter()
        .filter(move |rule| prepared.matches(&rule.r#match))
}
