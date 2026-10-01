// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The operating-system rule database
//!
//! The compiled rules and the access over them.
//!
//! ## Cost
//!
//! Held flat and walked: a rule is a handful of integer comparisons, so the
//! service signatures' lazy compilation and prefiltering would cost more than
//! they save. One observation against a synthetic rule set:
//!
//! | rules | per host |
//! |---|---|
//! | 2 | 0.8 µs |
//! | 1 000 | 33 µs |
//! | 10 000 | 278 µs |
//!
//! Linear: ten thousand rules would cost 18 seconds of CPU across a `/16`.
//!
//! [`rules::matching`](super::rules) computes the derived values once per
//! observation and runs the integer comparisons before the string one;
//! rendering the option layout per rule cost 3.2 ms per host at ten thousand
//! rules. That is 11.5x faster at ten thousand rules and 1.7x at two.
//!
//! An index, if needed, belongs behind [`RuleDb::matching`]: key rules by reply
//! kind and exact option layout, with an always-checked set for the rest.
//!
//! ## Source
//!
//! The rules are a `bincode` blob `build.rs` compiles from
//! `assets/fingerprinting/os/`, loaded by [`RuleDb::global`]. A caller's own
//! corpus goes through [`RuleDb::try_from_rules`].

use std::sync::OnceLock;

use super::observation::StackReply;
use super::rules;
use super::signature::{OsDefinition, RuleError};

/// The rules compiled from `assets/fingerprinting/os/` by `build.rs`.
const EMBEDDED_RULES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/os_rules.bin"));

/// The decoded rule set, built on first use and shared after, as
/// [`fingerprint::db`](crate::fingerprint::db) does with its signatures.
static DB: OnceLock<RuleDb> = OnceLock::new();

/// A rule [`RuleDb::try_from_rules`] refused, and why.
///
/// Carries the rule's position and label, to find it in a large corpus.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct InvalidRule {
    /// Where the rule sat in the list handed over.
    pub index: usize,
    /// What the rule called itself: its family, or its device class where it
    /// names no family. See [`OsIdentity::label`](super::OsIdentity::label).
    pub identity: String,
    /// What is wrong with it.
    pub error: RuleError,
}

impl std::fmt::Display for InvalidRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            index,
            identity,
            error,
        } = self;
        write!(f, "rule {index} ('{identity}') {error}")
    }
}

impl std::error::Error for InvalidRule {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Runtime view over the operating-system rules.
#[derive(Debug)]
pub struct RuleDb {
    rules: Vec<OsDefinition>,
}

impl RuleDb {
    /// The process-wide database. The first call deserializes the embedded
    /// rules; later calls are a pointer read.
    pub fn global() -> &'static RuleDb {
        DB.get_or_init(|| {
            let rules: Vec<OsDefinition> = bincode::deserialize(EMBEDDED_RULES)
                .expect("the embedded OS rule database failed to deserialize");
            RuleDb { rules }
        })
    }

    /// Builds a database from rules given directly, refusing any the build would
    /// refuse.
    ///
    /// How a caller supplies their own corpus. The checks are
    /// [`OsDefinition::validate`], which `build.rs` also runs. They refuse, for
    /// one, a rule with no predicates, which would name every host that answers.
    ///
    /// # Errors
    ///
    /// [`InvalidRule`] names which rule was refused and why.
    pub fn try_from_rules(rules: Vec<OsDefinition>) -> Result<Self, InvalidRule> {
        for (index, rule) in rules.iter().enumerate() {
            rule.validate().map_err(|error| InvalidRule {
                index,
                identity: rule.os.label().to_owned(),
                error,
            })?;
        }
        Ok(Self { rules })
    }

    /// Builds a database from rules given directly **without checking them**.
    ///
    /// For a caller who has already validated, and for tests. Prefer
    /// [`try_from_rules`](Self::try_from_rules).
    pub fn from_rules_unchecked(rules: Vec<OsDefinition>) -> Self {
        Self { rules }
    }

    /// Every rule, in the order the build compiled them.
    pub fn rules(&self) -> &[OsDefinition] {
        &self.rules
    }

    /// Every rule that describes `observed`.
    ///
    /// All of them; choosing among them is the verdict's job.
    pub fn matching<'a>(&'a self, reply: &'a StackReply) -> impl Iterator<Item = &'a OsDefinition> {
        rules::matching(&self.rules, reply, None)
    }

    /// Every rule that describes `reply` with its series readings known.
    ///
    /// Called by the active path. A series rule matches only here, never through
    /// [`matching`](Self::matching).
    pub fn matching_with_series<'a>(
        &'a self,
        reply: &'a StackReply,
        series: &'a super::series::SeriesClasses,
    ) -> impl Iterator<Item = &'a OsDefinition> {
        rules::matching(&self.rules, reply, Some(series))
    }
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
    use crate::fingerprint::os::{
        MatchRule, OsIdentity, Predicate, PredicateDefect, Provenance, ReplyKind, RuleError,
    };

    fn identity(family: &str) -> OsIdentity {
        OsIdentity {
            family: Some(family.to_owned()),
            device: None,
            vendor: None,
            product: None,
            version: None,
            cpe: None,
        }
    }

    fn rule(family: &str, r#match: MatchRule) -> OsDefinition {
        OsDefinition {
            os: identity(family),
            provenance: Provenance::Measured,
            notes: None,
            weight: 1.0,
            r#match,
            example: Vec::new(),
        }
    }

    fn tests_something() -> MatchRule {
        MatchRule {
            reply: ReplyKind::SynAck,
            initial_hops: Some(Predicate {
                equals: Some(64),
                any_of: None,
                range: None,
            }),
            ..Default::default()
        }
    }

    /// A rule with no predicates is refused; it would match any SYN+ACK at
    /// accuracy 70.
    #[test]
    fn a_rule_that_tests_nothing_is_refused() {
        let refused = RuleDb::try_from_rules(vec![rule("Windows 3.1", MatchRule::default())])
            .expect_err("a rule matching everything is not loadable");

        assert_eq!(refused.error, RuleError::NoPredicates);
        assert_eq!(refused.index, 0);
        assert_eq!(refused.identity, "Windows 3.1");
    }

    /// Every other build check applies here too.
    #[test]
    fn the_checks_are_the_ones_the_build_makes() {
        let cases: Vec<(OsDefinition, RuleError)> = vec![
            (
                OsDefinition {
                    os: OsIdentity {
                        family: None,
                        device: None,
                        ..identity("ignored")
                    },
                    ..rule("ignored", tests_something())
                },
                RuleError::Unidentified,
            ),
            (
                OsDefinition {
                    os: OsIdentity {
                        version: Some("22.04".to_owned()),
                        ..identity("Linux")
                    },
                    ..rule("Linux", tests_something())
                },
                RuleError::VersionWithoutProduct,
            ),
            (
                OsDefinition {
                    weight: 1e9,
                    ..rule("Linux", tests_something())
                },
                RuleError::Weight(1e9),
            ),
            (
                rule(
                    "Linux",
                    MatchRule {
                        reply: ReplyKind::SynAck,
                        initial_hops: Some(Predicate {
                            equals: None,
                            any_of: None,
                            range: None,
                        }),
                        ..Default::default()
                    },
                ),
                RuleError::Predicate {
                    field: "initial_hops",
                    defect: PredicateDefect::NoForm,
                },
            ),
            (
                rule(
                    "Linux",
                    MatchRule {
                        reply: ReplyKind::SynAck,
                        initial_hops: Some(Predicate {
                            equals: None,
                            any_of: Some(Vec::new()),
                            range: None,
                        }),
                        ..Default::default()
                    },
                ),
                RuleError::Predicate {
                    field: "initial_hops",
                    defect: PredicateDefect::EmptyAnyOf,
                },
            ),
            (
                rule(
                    "Linux",
                    MatchRule {
                        reply: ReplyKind::SynAck,
                        initial_hops: Some(Predicate {
                            equals: None,
                            any_of: None,
                            range: Some([128, 64]),
                        }),
                        ..Default::default()
                    },
                ),
                RuleError::Predicate {
                    field: "initial_hops",
                    defect: PredicateDefect::BackwardsRange,
                },
            ),
        ];

        for (definition, expected) in cases {
            let refused = RuleDb::try_from_rules(vec![definition])
                .expect_err("the build would refuse this too");
            assert_eq!(refused.error, expected);
        }
    }

    /// A rule that reads a series must ship an example that recorded one.
    ///
    /// Otherwise the corpus test would report it as broken.
    #[test]
    fn a_series_rule_without_a_series_example_is_refused() {
        use crate::fingerprint::os::Example;

        let series_rule = MatchRule {
            reply: ReplyKind::SynAck,
            initial_hops: Some(Predicate {
                equals: Some(64),
                any_of: None,
                range: None,
            }),
            sequence_class: Some(Predicate {
                equals: Some("hashed".to_owned()),
                any_of: None,
                range: None,
            }),
            ..Default::default()
        };
        let single_reply = Example {
            source: "one reply, no series".to_owned(),
            reply: ReplyKind::SynAck,
            remaining_hops: 64,
            dont_fragment: true,
            option_layout: "M".to_owned(),
            window: Some(64_240),
            mss: Some(1460),
            window_scale: None,
            timestamps: false,
            sack_permitted: false,
            echo_code: 0,
            echo_payload_intact: true,
            identifier_class: None,
            sequence_class: None,
            clock_class: None,
        };

        let mut definition = rule("Linux", series_rule);
        definition.example = vec![single_reply.clone()];
        let refused = RuleDb::try_from_rules(vec![definition.clone()])
            .expect_err("nothing could check this rule");
        assert!(matches!(refused.error, RuleError::ExampleWithoutSeries(_)));

        // With the series recorded it loads.
        definition.example = vec![Example {
            sequence_class: Some("hashed".to_owned()),
            ..single_reply
        }];
        assert!(RuleDb::try_from_rules(vec![definition]).is_ok());
    }

    /// A well-formed rule loads and matches.
    #[test]
    fn a_well_formed_rule_loads() {
        let db = RuleDb::try_from_rules(vec![rule("Linux", tests_something())])
            .expect("a rule with a predicate and an identity");
        assert_eq!(db.rules().len(), 1);
    }

    /// Everything the build compiled passes the build's own check.
    #[test]
    fn every_shipped_rule_satisfies_the_shared_check() {
        for (index, rule) in RuleDb::global().rules().iter().enumerate() {
            assert!(
                rule.validate().is_ok(),
                "shipped rule {index} ('{}') would be refused: {:?}",
                rule.os.label(),
                rule.validate()
            );
        }
    }

    /// The unchecked constructor skips the checks.
    #[test]
    fn the_unchecked_constructor_is_the_one_that_skips_the_checks() {
        let db = RuleDb::from_rules_unchecked(vec![rule("Windows 3.1", MatchRule::default())]);
        assert_eq!(db.rules().len(), 1);
    }

    /// The message names the rule.
    #[test]
    fn the_refusal_names_which_rule_and_why() {
        let refused = RuleDb::try_from_rules(vec![
            rule("Linux", tests_something()),
            rule("Windows 3.1", MatchRule::default()),
        ])
        .expect_err("the second rule is unusable");

        let message = refused.to_string();
        assert!(message.contains("rule 1"), "{message}");
        assert!(message.contains("Windows 3.1"), "{message}");
        assert!(message.contains("every reply of its kind"), "{message}");
    }
}
