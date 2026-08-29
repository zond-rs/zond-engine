// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The flow, as it is authored
//!
//! The data model of a Tier-1 detection: a bounded, straight-line sequence of
//! steps, each a probe and a match, where a match binds variables and a later
//! step or finding may be guarded on what an earlier one bound. It is the
//! service-signature format ([`crate::fingerprint`]) grown a spine — sequencing,
//! a variable environment, and a typed [`Finding`](crate::model::finding::Finding)
//! on the end — and it reuses the matcher rather than reinventing it: `expect`
//! and `bind` carry the same pattern (and optional product) a Tier-0
//! [`MatchRule`](crate::fingerprint::MatchRule) does, compiled by the one shared
//! engine. The authoring form here ([`MatchDetail`]) is a self-contained mirror
//! of the fields a flow uses, so this schema deserializes without reaching into
//! the fingerprint types — the discipline that lets `build.rs` share this file.
//!
//! ## Authoring against the model
//!
//! These are *authoring* types — they deserialize from TOML and are deliberately
//! separate from the [`model`](crate::model) types they map onto, for the reason
//! [`fingerprint::signature`](crate::fingerprint) is separate from the model: the
//! model stays serde-free, so a flow's `severity` and `references` are parsed here
//! and converted into the model's own vocabulary when a flow produces a finding.
//! The `[detection]` manifest a flow shares with the compute tier — its id, gate,
//! and class — lives in [`manifest`](crate::detect::manifest).
//!
//! ## Bounded by construction
//!
//! A flow has at most [`MAX_FLOW_STEPS`] steps and a `for_each` iterates at most
//! [`MAX_LOOP_ITEMS`] literals, so the total probe count is a number known before
//! the flow runs. That bound is what lets a flow be validated end to end at build
//! time and metered without a fuel counter — see the module documentation for the
//! interpreter and the validator that enforce it.

// `build.rs` compiles this file too, to validate the flow corpus, and its
// structural checks read only a subset of these authoring fields — the rest are
// a finding's payload the runtime reads. Within the library every field is public
// API and live; the unread-field lint fires only in the build-script crate, so it
// is silenced here rather than field by field. (The flow database embeds each
// flow's source, not a serialized form of this type, so unlike the signature
// schema nothing in the build reads every field back.)
#![allow(dead_code)]

use super::authoring::{Reference, Severity};
use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer};

use super::manifest::Manifest;

/// The most steps a flow may have. The whole point of a fixed ceiling is that a
/// flow's cost is knowable before it runs; the validator rejects a longer one.
pub const MAX_FLOW_STEPS: usize = 16;

/// The most literals a `for_each` may name. With [`MAX_FLOW_STEPS`] this bounds a
/// flow's total probe count, which is the number a declared budget is checked
/// against.
pub const MAX_LOOP_ITEMS: usize = 64;

/// A whole flow file: one detection, then its steps.
#[derive(Debug, Clone, Deserialize)]
pub struct FlowDetection {
    pub detection: Manifest,
    #[serde(default)]
    pub step: Vec<Step>,
}

/// One `[[step]]` — a straight-line node. There is no jump field; the absence is
/// the no-backward-jumps guarantee made structural.
#[derive(Debug, Clone, Deserialize)]
pub struct Step {
    /// A guard over variables bound by *earlier* steps. Absent = always run.
    #[serde(default)]
    pub when: Option<String>,
    /// A bounded loop over a literal list — the one repetition construct.
    #[serde(default)]
    pub for_each: Option<ForEach>,
    /// The bytes to emit, `{var}`-interpolated. Absent = a pure-analysis step
    /// over bytes an earlier step already drew.
    #[serde(default)]
    pub send: Option<String>,
    /// The hard gate: every rule must match the reply for the step to "match".
    /// Written as one pattern, a list of patterns, or full rules.
    #[serde(default, deserialize_with = "one_or_many")]
    pub expect: Vec<MatchSpec>,
    /// var name → the rule whose capture supplies its value.
    #[serde(default)]
    pub bind: BTreeMap<String, MatchSpec>,
    /// What to do when `expect` fails: halt (default) or continue with this
    /// step's binds left unbound.
    #[serde(default)]
    pub on_no_match: OnNoMatch,
    #[serde(default, rename = "finding")]
    pub finding: Vec<FindingSpec>,
}

/// A match rule as authored: a bare pattern string, or a full [`MatchDetail`].
/// Boxed so a bare-pattern step does not carry the whole rule's weight.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum MatchSpec {
    Pattern(String),
    Rule(Box<MatchDetail>),
}

impl MatchSpec {
    /// The regular-expression pattern this rule matches on — the one field
    /// present in every form, whether the rule was authored as a bare string or
    /// a table.
    pub fn pattern(&self) -> &str {
        match self {
            MatchSpec::Pattern(pattern) => pattern,
            MatchSpec::Rule(rule) => &rule.pattern,
        }
    }

    /// The 1-based index of the numbered capture group an imported pattern uses
    /// for its value, when it numbers one instead of naming it. A bare pattern
    /// never sets one.
    pub fn version_group(&self) -> Option<u8> {
        match self {
            MatchSpec::Pattern(_) => None,
            MatchSpec::Rule(rule) => rule.version_group,
        }
    }
}

/// The full authored form of a match rule: a [`MatchRule`](crate::fingerprint::MatchRule)
/// reduced to the fields a flow uses. It is a self-contained mirror rather than
/// the fingerprint type itself, so this schema carries no dependency on the
/// fingerprint module and `build.rs` can share it. `product`/`vendor` name what a
/// gate identifies, for a finding's evidence; the matcher reads only `pattern`
/// and `version_group`.
#[derive(Debug, Clone, Deserialize)]
pub struct MatchDetail {
    pub pattern: String,
    #[serde(default)]
    pub version_group: Option<u8>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
}

/// A bounded loop over a literal list.
#[derive(Debug, Clone, Deserialize)]
pub struct ForEach {
    /// The loop variable, referenced in `send` and `{var}` within the step.
    pub var: String,
    /// A literal list — the only form. Never a range, never a computed set.
    #[serde(rename = "in")]
    pub items: Vec<String>,
}

/// What a step does when its `expect` does not match.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnNoMatch {
    /// Stop the flow; nothing further runs.
    #[default]
    Halt,
    /// Proceed with this step's binds left unbound — how a *conditional* later
    /// step reads "the probe happened but did not confirm".
    Continue,
}

/// `[[step.finding]]` — the typed output. Maps onto the model's
/// [`Finding`](crate::model::finding::Finding).
#[derive(Debug, Clone, Deserialize)]
pub struct FindingSpec {
    /// Emit only if this holds. Absent = emit whenever reached.
    #[serde(default)]
    pub when: Option<String>,
    pub severity: Severity,
    /// Overrides [`Manifest::title`] for this finding; most flows omit it.
    #[serde(default)]
    pub title: Option<String>,
    /// `{var}`-interpolated.
    pub summary: String,
    /// `{var}`-interpolated.
    #[serde(default)]
    pub detail: Option<String>,
    /// A confidence wire name; absent defaults to `certain` for a matched check.
    #[serde(default)]
    pub confidence: Option<String>,
    #[serde(default)]
    pub references: Vec<Reference>,
    #[serde(default)]
    pub remediation: Option<String>,
    /// Which variable (or `$response`) supplies the finding's evidence excerpt.
    #[serde(default)]
    pub excerpt_from: Option<String>,
}

/// Accepts one value or a list of them into a `Vec`, so `expect = "x"` and
/// `expect = ["x", "y"]` both read — the ergonomic shorthand the corpus uses.
fn one_or_many<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        One(T),
        Many(Vec<T>),
    }
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(one) => vec![one],
        OneOrMany::Many(many) => many,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::manifest::{Class, Speak};

    fn parse(toml: &str) -> FlowDetection {
        toml::from_str(toml).expect("a valid flow parses")
    }

    #[test]
    fn the_redis_example_parses_into_its_structure() {
        let flow = parse(include_str!("../../../assets/detect/redis-unauth.toml"));

        assert_eq!(flow.detection.id, "redis-unauth-access");
        assert_eq!(flow.detection.when.service.as_deref(), Some("redis"));
        assert_eq!(flow.detection.capabilities.class, Class::ActiveBenign);
        assert_eq!(flow.detection.capabilities.speak, Some(Speak::Target));
        assert_eq!(flow.detection.capabilities.max_bytes, Some(8192));

        assert_eq!(flow.step.len(), 1);
        let step = &flow.step[0];
        // A TOML `\r\n` is a real carriage-return / line-feed by the time it is here.
        assert_eq!(step.send.as_deref(), Some("INFO\r\n"));
        assert_eq!(
            step.expect.len(),
            1,
            "the bare-string shorthand read as one rule"
        );
        assert!(step.bind.contains_key("version"));
        assert_eq!(step.finding.len(), 1);

        let finding = &step.finding[0];
        assert_eq!(finding.when.as_deref(), Some("matched"));
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.references, vec![Reference::Cwe(306)]);
    }

    #[test]
    fn the_snmp_example_parses_its_bounded_loop() {
        let flow = parse(include_str!(
            "../../../assets/detect/snmp-default-community.toml"
        ));

        assert_eq!(flow.detection.when.protocol.as_deref(), Some("udp"));
        let step = &flow.step[0];
        let for_each = step.for_each.as_ref().expect("a for_each loop");
        assert_eq!(for_each.var, "community");
        assert_eq!(for_each.items.len(), 4);
        assert_eq!(step.on_no_match, OnNoMatch::Continue);
    }

    #[test]
    fn a_bare_pattern_and_a_full_rule_both_read_as_a_match_rule() {
        // The shorthand: a pattern with nothing else.
        let pattern = MatchSpec::Pattern("^\\+PONG".to_string());
        assert_eq!(pattern.pattern(), "^\\+PONG");
        assert_eq!(pattern.version_group(), None);

        // The full form, carrying a product the shorthand cannot.
        let flow = parse(
            r#"
            [detection]
            id = "x"
            version = "1.0.0"
            title = "x"
            [detection.when]
            service = "http"
            [detection.capabilities]
            class = "passive"
            [[step]]
            expect = { pattern = "Server: nginx", product = "nginx" }
            "#,
        );
        let spec = &flow.step[0].expect[0];
        assert_eq!(spec.pattern(), "Server: nginx");
        let MatchSpec::Rule(detail) = spec else {
            panic!("the table form reads as a full rule");
        };
        assert_eq!(detail.product.as_deref(), Some("nginx"));
    }
}
