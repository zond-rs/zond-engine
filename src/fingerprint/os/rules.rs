// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Deciding whether a rule describes an observation
//!
//! A rule matches when **every predicate it states is satisfied**; a field it
//! does not name is not tested.
//!
//! ## Absence is "do not care"
//!
//! A rule naming no predicates would match everything, so the build refuses
//! one. A rule naming too few fields matches hosts it should not, which the
//! corpus test catches by running every example against every other family's
//! rules.
//!
//! ## A predicate over a missing value
//!
//! A predicate over a value the reply does not have (an MSS on a reset) **fails
//! to match**.

use super::observation::{StackObservation, StackReply};
use super::signature::{MatchRule, Predicate, ReplyKind};

/// Whether a predicate accepts `value`.
///
/// `build.rs` enforces exactly one form; a predicate with none accepts nothing.
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
/// `None` never matches; see the module documentation.
fn accepts_optional<T: PartialOrd>(predicate: &Option<Predicate<T>>, value: Option<&T>) -> bool {
    match (predicate, value) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(predicate), Some(value)) => accepts(predicate, value),
    }
}

/// [`accepts_optional`] for a predicate over a class enum's `&'static str` name.
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
/// Rendering the option layout per rule cost 3.2 ms per host against ten
/// thousand rules (210 seconds of CPU for a `/16`).
struct Prepared<'a> {
    reply: &'a StackReply,
    series: Option<&'a crate::fingerprint::os::series::SeriesClasses>,
    /// `None` for an echo reply, so TCP predicates fail against it as for any
    /// missing value.
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
            // IP header fields, common to both kinds.
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

        // Cheapest and most selective first; the string comparison comes last.
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
/// For many rules, use [`RuleDb::matching`](super::RuleDb::matching), which
/// prepares the derived values once.
///
/// The reply kind is checked first.
pub fn matches(rule: &MatchRule, reply: &StackReply) -> bool {
    Prepared::new(reply, None).matches(rule)
}

/// Whether `rule` describes `reply` with its series readings known.
///
/// Called by the active path. A series rule matches only through this; against
/// [`matches`](fn@matches) its series predicates fail as missing values.
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
    // Built once for the whole lazy iterator.
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
                family: Some("Test family".to_string()),
                device: None,
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

    /// Identical single-reply shapes are separated by the sequence class.
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

    /// A series rule is never satisfied by a single reply.
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
