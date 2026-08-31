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

use super::observation::{StackObservation, StackReply};
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

/// [`accepts_optional`] for a predicate over a *name*: the class enums render
/// `&'static str` names, which have no sized value to take by reference, so
/// the comparison is spelled here once instead of at each call site.
fn accepts_named(predicate: &Option<Predicate<String>>, value: Option<&'static str>) -> bool {
    match (predicate, value) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(predicate), Some(name)) => accepts_str(predicate, name),
    }
}

/// Whether a string predicate accepts `name`.
fn accepts_str(predicate: &Predicate<String>, name: &str) -> bool {
    if let Some(expected) = &predicate.equals {
        return expected == name;
    }
    if let Some(expected) = &predicate.any_of {
        return expected.iter().any(|expected| expected == name);
    }
    if let Some([low, high]) = &predicate.range {
        return name >= low.as_str() && name <= high.as_str();
    }
    false
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
    reply: &'a StackReply,
    series: Option<&'a crate::fingerprint::os::series::SeriesClasses>,
    /// Everything below is `None` for a reply that has no such field, so a rule
    /// naming a TCP field fails against an echo reply by the ordinary
    /// "the peer did not say" rule rather than by a special case.
    tcp: Option<&'a StackObservation>,
    layout: Option<String>,
    initial_hops: u8,
    dont_fragment: bool,
    window_units: Option<u16>,
    window_remainder: Option<u16>,
}

impl<'a> Prepared<'a> {
    fn new(
        reply: &'a StackReply,
        series: Option<&'a crate::fingerprint::os::series::SeriesClasses>,
    ) -> Self {
        let tcp = match reply {
            StackReply::Tcp(observed) => Some(observed),
            StackReply::Echo(_) => None,
        };
        let (window_units, window_remainder) = match tcp.and_then(|o| o.window_in_units()) {
            Some((units, remainder)) => (Some(units), Some(remainder)),
            None => (None, None),
        };
        Self {
            reply,
            series,
            tcp,
            layout: tcp.map(StackObservation::layout_string),
            // The IP header is the one thing both kinds have, so these two are
            // read off the reply rather than off the TCP half.
            initial_hops: reply.initial_hops_at_least(),
            dont_fragment: matches!(
                reply.ip(),
                crate::model::capture::IpObservation::V4(v4) if v4.dont_fragment
            ),
            window_units,
            window_remainder,
        }
    }

    /// Whether `rule` describes the observation this was prepared from.
    fn matches(&self, rule: &MatchRule) -> bool {
        let kind_agrees = match (rule.reply, self.reply) {
            (ReplyKind::SynAck, StackReply::Tcp(observed)) => observed.is_syn_ack(),
            (ReplyKind::Reset, StackReply::Tcp(observed)) => observed.is_reset(),
            (ReplyKind::EchoReply, StackReply::Echo(_)) => true,
            _ => false,
        };
        if !kind_agrees {
            return false;
        }

        // Cheapest and most selective first: the integer comparisons reject the
        // overwhelming majority of a large rule set before the string comparison
        // is ever reached.
        let echo = match self.reply {
            StackReply::Echo(observed) => Some(observed),
            StackReply::Tcp(_) => None,
        };

        accepts_optional(&rule.initial_hops, Some(&self.initial_hops))
            && accepts_optional(&rule.dont_fragment, Some(&self.dont_fragment))
            && accepts_optional(&rule.window, self.tcp.map(|o| &o.window))
            && accepts_optional(&rule.window_units, self.window_units.as_ref())
            && accepts_optional(&rule.window_remainder, self.window_remainder.as_ref())
            && accepts_optional(
                &rule.window_scale,
                self.tcp.and_then(|o| o.window_scale.as_ref()),
            )
            && accepts_optional(&rule.mss, self.tcp.and_then(|o| o.mss.as_ref()))
            && accepts_optional(
                &rule.timestamps,
                self.tcp.map(|o| o.timestamps.is_some()).as_ref(),
            )
            && accepts_optional(&rule.sack_permitted, self.tcp.map(|o| &o.sack_permitted))
            && accepts_optional(&rule.option_layout, self.layout.as_ref())
            && accepts_optional(&rule.echo_code, echo.map(|o| &o.code))
            && accepts_optional(&rule.echo_payload_intact, echo.map(|o| &o.payload_intact))
            && accepts_named(
                &rule.identifier_class,
                self.series.map(|s| s.identifiers.name()),
            )
            && accepts_named(
                &rule.sequence_class,
                self.series.map(|s| s.sequences.name()),
            )
            && accepts_named(&rule.clock_class, self.series.map(|s| s.clock.name()))
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
pub fn matches(rule: &MatchRule, reply: &StackReply) -> bool {
    Prepared::new(reply, None).matches(rule)
}

/// Whether `rule` describes `reply` with its series readings known.
///
/// The form the active path calls, where several replies were collected and
/// classified. A rule predicating on a series field matches only through this
/// entry point; against [`matches`](fn@matches) it fails by the ordinary
/// "the peer did not say" rule, which is what keeps a series rule from ever
/// being satisfied by a single reply.
pub fn matches_with_series(
    rule: &MatchRule,
    reply: &StackReply,
    series: &crate::fingerprint::os::series::SeriesClasses,
) -> bool {
    Prepared::new(reply, Some(series)).matches(rule)
}

/// Every rule in `rules` that describes `observed`, with the derived values
/// computed once for the whole set.
pub(super) fn matching<'a>(
    rules: &'a [super::signature::OsDefinition],
    reply: &'a StackReply,
    series: Option<&'a crate::fingerprint::os::series::SeriesClasses>,
) -> impl Iterator<Item = &'a super::signature::OsDefinition> {
    // Moved into the closure so it is built once and lives as long as the
    // iterator, rather than per rule. The iterator stays lazy: a caller wanting
    // only the first match pays for only the rules before it.
    let prepared = Prepared::new(reply, series);
    rules
        .iter()
        .filter(move |rule| prepared.matches(&rule.r#match))
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
    use crate::model::capture::{IpObservation, Ipv4Observation};
    use crate::protocols::tcp::flags;

    /// A handshake reply whose shape the Linux rules already describe, for
    /// asking whether a series predicate can tell two identical shapes apart.
    fn syn_ack() -> StackReply {
        let options: [u8; 20] = [
            0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0xad, 0x58, 0xa5, 0xa7, 0x64, 0x48,
            0x96, 0x12, 0x01, 0x03, 0x03, 0x07,
        ];
        let mut bytes = vec![0u8; 20 + options.len()];
        bytes[12] = (((20 + options.len()) / 4) as u8) << 4;
        bytes[13] = flags::SYN | flags::ACK;
        bytes[14..16].copy_from_slice(&65_160u16.to_be_bytes());
        bytes[20..].copy_from_slice(&options);
        StackObservation::from_tcp(
            IpObservation::V4(Ipv4Observation {
                ttl: 64,
                identification: 0,
                dont_fragment: true,
                more_fragments: false,
                dscp: 0,
                ecn: 0,
            }),
            &bytes,
        )
        .expect("the recorded reply parses")
        .into()
    }

    fn series_rule(field: &str, name: &str) -> crate::fingerprint::os::signature::OsDefinition {
        use crate::fingerprint::os::signature::{
            MatchRule, OsDefinition, OsIdentity, Predicate, Provenance, ReplyKind,
        };

        let r#match = match field {
            "identifier_class" => MatchRule {
                reply: ReplyKind::SynAck,
                identifier_class: Some(Predicate {
                    equals: Some(name.to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            "sequence_class" => MatchRule {
                reply: ReplyKind::SynAck,
                sequence_class: Some(Predicate {
                    equals: Some(name.to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            "clock_class" => MatchRule {
                reply: ReplyKind::SynAck,
                clock_class: Some(Predicate {
                    equals: Some(name.to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            other => panic!("no such series field: {other}"),
        };

        OsDefinition {
            os: OsIdentity {
                family: "Test family".to_string(),
                vendor: None,
                product: None,
                version: None,
                cpe: None,
            },
            provenance: Provenance::Published,
            notes: Some("a series rule built for the test".to_string()),
            weight: 1.0,
            r#match,
            example: Vec::new(),
        }
    }

    /// The reason this vocabulary exists: two builds of one stack can answer a
    /// single SYN with byte-identical shapes and still be separated, because a
    /// policy is visible only across a series. A rule predicating on the
    /// sequence class matches the hashed generator and not the stepping one,
    /// against replies that no single-reply predicate can tell apart.
    #[test]
    fn a_series_predicate_separates_identical_single_reply_shapes() {
        let reply = syn_ack();

        let hashed = crate::fingerprint::os::series::SeriesClasses {
            identifiers: crate::fingerprint::os::series::IdClass::Zero,
            sequences: crate::fingerprint::os::series::IsnClass::Hashed,
            clock: crate::fingerprint::os::series::ClockClass::Randomised,
        };
        let stepping = crate::fingerprint::os::series::SeriesClasses {
            identifiers: crate::fingerprint::os::series::IdClass::Zero,
            sequences: crate::fingerprint::os::series::IsnClass::FixedStep(64_000),
            clock: crate::fingerprint::os::series::ClockClass::Randomised,
        };

        let rule = series_rule("sequence_class", "hashed");
        assert!(
            matches_with_series(&rule.r#match, &reply, &hashed),
            "the hashed generator matches the hashed rule"
        );
        assert!(
            !matches_with_series(&rule.r#match, &reply, &stepping),
            "a stepping generator does not, on an identical reply shape"
        );
    }

    /// A rule predicating on a series field must never be satisfied by a single
    /// reply, however well the shape agrees. The passive path has no series,
    /// and the ordinary "the peer did not say" rule is what keeps a series rule
    /// from naming a host it never sampled.
    #[test]
    fn a_series_rule_is_never_satisfied_by_a_single_reply() {
        let reply = syn_ack();
        let rule = series_rule("identifier_class", "counting");
        assert!(!matches(&rule.r#match, &reply));

        let rule = series_rule("sequence_class", "hashed");
        assert!(!matches(&rule.r#match, &reply));

        let rule = series_rule("clock_class", "ticking");
        assert!(!matches(&rule.r#match, &reply));
    }
}
