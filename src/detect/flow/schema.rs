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
//! and `bind` are the same [`MatchRule`] every Tier-0 signature is.
//!
//! ## Authoring against the model
//!
//! These are *authoring* types — they deserialize from TOML and are deliberately
//! separate from the [`model`](crate::model) types they map onto, for the reason
//! [`fingerprint::signature`](crate::fingerprint) is separate from the model: the
//! model stays serde-free, so a flow's `class`, `severity` and `references` are
//! parsed here and [converted](Class::into_model) into the model's own vocabulary
//! when a flow produces a finding.
//!
//! ## Bounded by construction
//!
//! A flow has at most [`MAX_FLOW_STEPS`] steps and a `for_each` iterates at most
//! [`MAX_LOOP_ITEMS`] literals, so the total probe count is a number known before
//! the flow runs. That bound is what lets a flow be validated end to end at build
//! time and metered without a fuel counter — see the module documentation for the
//! interpreter and the validator that enforce it.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer};

use crate::fingerprint::MatchRule;
use crate::model::finding::{DetectionClass, Reference as ModelReference, Severity as ModelSeverity};

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

/// `[detection]` — what the detection *is* and what it *asks to be handed*.
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    /// The author-chosen identity, stamped on every finding this flow produces.
    pub id: String,
    /// The version, `major.minor.patch`. A string here; the validator parses it.
    pub version: String,
    pub title: String,
    /// The cheap gate deciding whether this detection runs for a port at all.
    pub when: Rule,
    pub capabilities: Capabilities,
}

/// `[detection.when]` — the rule that gates the whole detection, nmap's portrule.
/// Every set field ANDs; an empty table means "any port the level offers".
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub ports: Vec<u16>,
    /// `"tcp"` or `"udp"`. Gates which transport serves `speak`.
    #[serde(default)]
    pub protocol: Option<String>,
}

/// `[detection.capabilities]` — what the flow asks to be handed. The class *is*
/// the capability set an envelope will serve; nothing here self-reports.
#[derive(Debug, Clone, Deserialize)]
pub struct Capabilities {
    pub class: Class,
    /// The only value today is `target`: exchange bytes with the scanned socket.
    #[serde(default)]
    pub speak: Option<Speak>,
    #[serde(default)]
    pub resolve: bool,
    #[serde(default)]
    pub max_bytes: Option<u32>,
    #[serde(default)]
    pub max_millis: Option<u32>,
    #[serde(default)]
    pub max_connections: Option<u16>,
}

/// The intrusiveness a flow declares. Deserializes from the wire names and maps
/// onto the model's [`DetectionClass`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    Passive,
    ActiveBenign,
    ActiveMutating,
    Exploit,
    Dos,
}

impl Class {
    /// The model class this authoring class names.
    pub fn into_model(self) -> DetectionClass {
        match self {
            Class::Passive => DetectionClass::Passive,
            Class::ActiveBenign => DetectionClass::ActiveBenign,
            Class::ActiveMutating => DetectionClass::ActiveMutating,
            Class::Exploit => DetectionClass::Exploit,
            Class::Dos => DetectionClass::Dos,
        }
    }
}

/// What a flow may `speak` to. One value for now; the enum is the room to grow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Speak {
    Target,
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

/// A match rule as authored: a bare pattern string, or a full [`MatchRule`].
/// Boxed so a bare-pattern step does not carry the whole rule's weight.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum MatchSpec {
    Pattern(String),
    Rule(Box<MatchRule>),
}

impl MatchSpec {
    /// The [`MatchRule`] this authored form denotes — a bare pattern becomes a
    /// pattern-only rule so `expect` and `bind` compile through the one engine
    /// every Tier-0 signature does.
    pub fn as_rule(&self) -> MatchRule {
        match self {
            MatchSpec::Pattern(pattern) => MatchRule {
                name: None,
                pattern: pattern.clone(),
                version_group: None,
                vendor: None,
                product: None,
                context: None,
                example: None,
                metadata: None,
            },
            MatchSpec::Rule(rule) => (**rule).clone(),
        }
    }
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

/// How bad a finding is, as authored. Maps onto the model's [`ModelSeverity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// The model severity this authoring severity names.
    pub fn into_model(self) -> ModelSeverity {
        match self {
            Severity::Info => ModelSeverity::Info,
            Severity::Low => ModelSeverity::Low,
            Severity::Medium => ModelSeverity::Medium,
            Severity::High => ModelSeverity::High,
            Severity::Critical => ModelSeverity::Critical,
        }
    }
}

/// A typed reference, authored as an inline table: `{ cve = "CVE-…" }`,
/// `{ cwe = 79 }`, or `{ url = "…" }`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reference {
    Cve(String),
    Cwe(u32),
    Url(String),
}

impl Reference {
    /// The model reference this names, or [`None`] for a CVE identifier of the
    /// wrong shape — the model refuses a malformed one, and so does this.
    pub fn into_model(&self) -> Option<ModelReference> {
        match self {
            Reference::Cve(id) => ModelReference::cve(id),
            Reference::Cwe(number) => Some(ModelReference::cwe(*number)),
            Reference::Url(url) => Some(ModelReference::url(url)),
        }
    }
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
        assert_eq!(step.expect.len(), 1, "the bare-string shorthand read as one rule");
        assert!(step.bind.contains_key("version"));
        assert_eq!(step.finding.len(), 1);

        let finding = &step.finding[0];
        assert_eq!(finding.when.as_deref(), Some("matched"));
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.references, vec![Reference::Cwe(306)]);
    }

    #[test]
    fn the_snmp_example_parses_its_bounded_loop() {
        let flow = parse(include_str!("../../../assets/detect/snmp-default-community.toml"));

        assert_eq!(flow.detection.when.protocol.as_deref(), Some("udp"));
        let step = &flow.step[0];
        let for_each = step.for_each.as_ref().expect("a for_each loop");
        assert_eq!(for_each.var, "community");
        assert_eq!(for_each.items.len(), 4);
        assert_eq!(step.on_no_match, OnNoMatch::Continue);
    }

    #[test]
    fn a_bare_pattern_and_a_full_rule_both_read_as_a_match_rule() {
        // The shorthand.
        let pattern = MatchSpec::Pattern("^\\+PONG".to_string());
        assert_eq!(pattern.as_rule().pattern, "^\\+PONG");
        assert!(pattern.as_rule().product.is_none());

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
        let rule = flow.step[0].expect[0].as_rule();
        assert_eq!(rule.pattern, "Server: nginx");
        assert_eq!(rule.product.as_deref(), Some("nginx"));
    }

    #[test]
    fn the_authoring_enums_map_onto_the_model_vocabulary() {
        assert_eq!(Class::Exploit.into_model(), DetectionClass::Exploit);
        assert_eq!(Severity::Critical.into_model(), ModelSeverity::Critical);
        assert_eq!(Reference::Cwe(79).into_model(), Some(ModelReference::Cwe(79)));
        assert!(Reference::Cve("CVE-2021-44228".into()).into_model().is_some());
        // A malformed CVE is refused, exactly as the model refuses it.
        assert!(Reference::Cve("not-a-cve".into()).into_model().is_none());
    }
}
