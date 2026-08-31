// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The operating-system rule database
//!
//! The compiled artifact and the access over it.
//!
//! ## What it costs, measured
//!
//! Held flat and walked. That is a different shape from the service signatures
//! next door, and deliberately so: those carry thousands of regexes whose
//! *compilation* dominates everything, which is why they are compiled lazily,
//! cached, warmed in parallel, and narrowed by a port index and an Aho-Corasick
//! literal prefilter before any of it happens. A rule here compiles to nothing —
//! it is a handful of integer comparisons — so the same machinery would cost
//! more than it saves.
//!
//! Measured on this machine, one observation against a synthetic rule set:
//!
//! | rules | per host |
//! |---|---|
//! | 2 (what ships) | 0.8 µs |
//! | 1 000 | 33 µs |
//! | 10 000 | 278 µs |
//!
//! Linear, with a small constant. At the two rules that ship it is not
//! measurable against anything else a scan does; at ten thousand — which is what
//! translating a public corpus would bring — it is 18 seconds of CPU across a
//! `/16`, which is real but not disqualifying.
//!
//! Getting there took one fix worth naming, because it is the mistake this shape
//! invites. Rendering the option layout allocates, and doing it inside the
//! per-rule test cost **3.2 ms per host** at ten thousand rules — 210 seconds
//! across a `/16`, essentially all of it spent building the same short string
//! ten thousand times over. [`rules::matching`](super::rules) now works the
//! derived values out once for the whole set and orders the cheap integer
//! comparisons ahead of the string one, which is 11.5x at ten thousand rules and
//! 1.7x at two.
//!
//! ## Where the index goes, when it is needed
//!
//! [`RuleDb::matching`] is the seam, and nothing above it would change. The
//! natural narrowing is the direct analogue of the service side's port index: key
//! rules by reply kind and by an exactly-specified option layout, keep the rules
//! that state neither in a set that is always checked, and the walk goes from
//! every rule to a handful. It is not built, because two rules do not need it and
//! an index nobody can measure the benefit of is a guess.
//!
//! ## Where the artifact comes from
//!
//! Today it is the `bincode` blob `build.rs` compiles from
//! `assets/fingerprinting/os/`. [`RuleDb::global`] is the single place a
//! disk-loaded database will slot in later, which is what makes it possible to
//! use a corpus this crate can never ship: the largest and best operating-system
//! fingerprint database in existence is nmap's, and its licence is incompatible
//! with this one, so it can only ever be something a user brings and translates
//! on their own machine. The translator is the deliverable there; the corpus is
//! not.

use std::sync::OnceLock;

use super::observation::StackReply;
use super::rules;
use super::signature::{OsDefinition, RuleError};

/// The rules compiled from `assets/fingerprinting/os/` by `build.rs`.
const EMBEDDED_RULES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/os_rules.bin"));

static DB: OnceLock<RuleDb> = OnceLock::new();

/// A rule [`RuleDb::try_from_rules`] refused, and why.
///
/// Carries where the rule sat and what it called itself, because a caller
/// loading a corpus of thousands needs to find the one that is wrong rather than
/// be told that one of them is.
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
    /// **This is how a caller supplies their own corpus.** The checks are the
    /// ones in [`OsDefinition::validate`], which `build.rs` runs over the shipped
    /// rules from the same code, so a rule that would fail the build fails here
    /// with the same stated reason rather than shipping into a scan.
    ///
    /// That matters more than it sounds. The worst defect an authored rule can
    /// have is to state no predicates at all: it then matches every reply of its
    /// kind and names every host that ever answers as one operating system, and
    /// nothing downstream can tell that from a detection that worked. The build
    /// calls that one worse than a build failure and aborts over it. An
    /// unchecked constructor is a door around every one of those checks.
    ///
    /// # Errors
    ///
    /// [`InvalidRule`] names which rule was refused and why, so a caller loading
    /// a corpus of thousands can report the one that is wrong.
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
    /// For a caller who has already validated, and for tests that need a rule
    /// the checks would refuse in order to prove the checks matter. Prefer
    /// [`try_from_rules`](Self::try_from_rules) everywhere else: what this skips
    /// is not a formality, it is the difference between a corpus that identifies
    /// hosts and one that names all of them the same thing.
    pub fn from_rules_unchecked(rules: Vec<OsDefinition>) -> Self {
        Self { rules }
    }

    /// Every rule, in the order the build compiled them.
    pub fn rules(&self) -> &[OsDefinition] {
        &self.rules
    }

    /// Every rule that describes `observed`.
    ///
    /// Returns all of them rather than the best one. Which of several matching
    /// rules should name the host is a question about weights and about the other
    /// evidence in hand, and it is not this layer's to answer — two rules
    /// agreeing on a family and disagreeing on a version is a *result*, not a
    /// tie to be broken here.
    pub fn matching<'a>(&'a self, reply: &'a StackReply) -> impl Iterator<Item = &'a OsDefinition> {
        rules::matching(&self.rules, reply, None)
    }

    /// Every rule that describes `reply` with its series readings known.
    ///
    /// The form the active path calls: several replies were collected, their
    /// series classified, and the rules asked about both the reply and the
    /// classes together. A rule predicating on a series field matches only
    /// here, never through [`matching`](Self::matching).
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

    /// **The door the build spent a panic closing.**
    ///
    /// `build.rs` refuses a rule that states no predicates and calls it the one
    /// defect worse than a build failure, because it matches every reply of its
    /// kind and names every host that ever answers. The public constructor used
    /// to accept exactly that: measured, a rule naming `Windows 3.1` and testing
    /// nothing was loaded and returned accuracy 70 for any SYN+ACK on earth.
    #[test]
    fn a_rule_that_tests_nothing_is_refused() {
        let refused = RuleDb::try_from_rules(vec![rule("Windows 3.1", MatchRule::default())])
            .expect_err("a rule matching everything is not loadable");

        assert_eq!(refused.error, RuleError::NoPredicates);
        assert_eq!(refused.index, 0);
        assert_eq!(refused.identity, "Windows 3.1");
    }

    /// Every other check the build makes, made here too. The point is not the
    /// individual rules but that there is one set of them: a check added to
    /// [`OsDefinition::validate`] tightens the build and this door together.
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
    /// Otherwise the example can only ever fail: a series rule is matched
    /// through `matches_with_series` and nothing else, so the corpus test would
    /// report a working rule as one that had stopped matching. Refused rather
    /// than warned about, because the two are indistinguishable from outside.
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

        // Recording the series it reads makes it loadable.
        definition.example = vec![Example {
            sequence_class: Some("hashed".to_owned()),
            ..single_reply
        }];
        assert!(RuleDb::try_from_rules(vec![definition]).is_ok());
    }

    /// A well-formed rule loads and matches, so the gate is a gate rather than a
    /// wall.
    #[test]
    fn a_well_formed_rule_loads() {
        let db = RuleDb::try_from_rules(vec![rule("Linux", tests_something())])
            .expect("a rule with a predicate and an identity");
        assert_eq!(db.rules().len(), 1);
    }

    /// Everything the build compiled passes the check the build ran, which would
    /// be circular if they were two implementations and is a seal because they
    /// are one.
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

    /// The unchecked door still exists and still says so in its name, which is
    /// the whole difference between it and the one that was there before.
    #[test]
    fn the_unchecked_constructor_is_the_one_that_skips_the_checks() {
        let db = RuleDb::from_rules_unchecked(vec![rule("Windows 3.1", MatchRule::default())]);
        assert_eq!(db.rules().len(), 1);
    }

    /// The message names the rule, because a corpus of thousands needs the one
    /// that is wrong rather than the fact that one of them is.
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
