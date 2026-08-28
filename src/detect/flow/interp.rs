// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Running a flow
//!
//! Walks a [`FlowDetection`](super::schema::FlowDetection)'s steps front to back,
//! once — there is no instruction that revisits a step — exchanging bytes with a
//! [`Probe`], matching replies, binding variables, and emitting the
//! [`Finding`]s its findings imply. The bound total probe count and the absence
//! of any jump are what let it run without a fuel meter: it cannot loop forever
//! and cannot exceed its declared budget by construction.
//!
//! ## The variable environment is forward-only
//!
//! A step sees what earlier steps bound, never what a later one will. An ordinary
//! step's binds propagate to the steps after it; a `for_each` step runs each item
//! in an environment of its own, so one iteration's binds never leak into the
//! next.
//!
//! ## Guards, for now
//!
//! A finding's `when` is evaluated here as `matched` or absent; the full guard
//! expression language — comparisons, `and`/`or`/`not`, and the conditional steps
//! it unlocks — joins in the next increment. Until then an unrecognised guard is
//! treated as unmet rather than guessed at.

use std::collections::BTreeMap;

use crate::fingerprint::{Confidence, MAX_COMPILED_REGEX_BYTES, pattern, unescape};
use crate::model::finding::{DetectionId, Excerpt, Finding, Version};
use crate::record::wire;

use super::schema::{FindingSpec, FlowDetection, MatchSpec, OnNoMatch, Step};
use super::schema::MAX_LOOP_ITEMS;

/// The one capability a flow reaches the world through: send bytes to the scanned
/// socket and read its reply. A test supplies a canned one; a scan supplies the
/// real socket.
pub trait Probe {
    /// Sends `bytes` and returns the reply, or [`None`] if the socket said
    /// nothing.
    fn speak(&mut self, bytes: &[u8]) -> Option<Vec<u8>>;
}

/// The variables a flow has bound so far.
type Env = BTreeMap<String, String>;

/// Whether the flow should keep running after a step.
#[derive(PartialEq, Eq)]
enum Flow {
    Continue,
    Halt,
}

/// Runs `flow` against `probe`, returning the findings it produced.
///
/// The findings carry an empty content hash until a loader computes it from the
/// flow's bytes; everything else — id, version, severity, references — is the
/// flow's own.
pub fn run(flow: &FlowDetection, probe: &mut dyn Probe) -> Vec<Finding> {
    let mut env = Env::new();
    let mut findings = Vec::new();

    for step in &flow.step {
        match &step.for_each {
            Some(for_each) => {
                for item in for_each.items.iter().take(MAX_LOOP_ITEMS) {
                    let mut local = env.clone();
                    local.insert(for_each.var.clone(), item.clone());
                    if run_step(flow, step, &mut local, probe, &mut findings) == Flow::Halt {
                        return findings;
                    }
                }
            }
            None => {
                if run_step(flow, step, &mut env, probe, &mut findings) == Flow::Halt {
                    return findings;
                }
            }
        }
    }
    findings
}

fn run_step(
    flow: &FlowDetection,
    step: &Step,
    env: &mut Env,
    probe: &mut dyn Probe,
    findings: &mut Vec<Finding>,
) -> Flow {
    // The probe exchange. A step with no `send` reads nothing new — for now it
    // has no reply to match against.
    let response = match &step.send {
        Some(send) => match interpolate(send, env) {
            // Decoded byte-for-byte, so a binary pattern such as `\xa2` matches
            // the byte it names rather than a lossy replacement character.
            Some(text) => probe.speak(&unescape(&text)).map(|reply| latin1(&reply)),
            // A send whose template names an unbound variable cannot run.
            None => return on_no_match(step),
        },
        None => None,
    };

    // `bind` is best-effort: a capture that does not match leaves its variable
    // unbound. Run it before the gate so a finding may read a value even from a
    // step that then only continues.
    if let Some(response) = &response {
        for (name, spec) in &step.bind {
            if let Some(value) = capture(spec, response, name) {
                env.insert(name.clone(), value);
            }
        }
    }

    // `expect` is the hard gate: every rule must match for the step to "match".
    let matched = match &response {
        Some(response) => step.expect.iter().all(|rule| matches(rule, response)),
        None => step.expect.is_empty(),
    };

    if !matched && step.on_no_match == OnNoMatch::Halt {
        return Flow::Halt;
    }

    for spec in &step.finding {
        if finding_holds(spec, matched)
            && let Some(finding) = build_finding(flow, spec, env, response.as_deref())
        {
            findings.push(finding);
        }
    }

    Flow::Continue
}

fn on_no_match(step: &Step) -> Flow {
    match step.on_no_match {
        OnNoMatch::Halt => Flow::Halt,
        OnNoMatch::Continue => Flow::Continue,
    }
}

/// Whether a bare `matched`/absent guard holds. The richer expression language is
/// a later increment; an unrecognised guard is treated as unmet.
fn finding_holds(spec: &FindingSpec, matched: bool) -> bool {
    match spec.when.as_deref() {
        None => true,
        Some("matched") => matched,
        Some(_) => false,
    }
}

/// Whether `spec`'s pattern matches `text`.
fn matches(spec: &MatchSpec, text: &str) -> bool {
    let rule = spec.as_rule();
    pattern::compile(&rule.pattern, MAX_COMPILED_REGEX_BYTES)
        .is_ok_and(|compiled| compiled.identify(text, rule.version_group).is_some())
}

/// The value `spec` binds out of `text` for a variable named `name`: a named
/// capture group of that name, or the numeric `version_group` an imported pattern
/// numbers instead.
fn capture(spec: &MatchSpec, text: &str, name: &str) -> Option<String> {
    let rule = spec.as_rule();
    let compiled = pattern::compile(&rule.pattern, MAX_COMPILED_REGEX_BYTES).ok()?;
    compiled.capture(text, name).or_else(|| {
        rule.version_group
            .and_then(|group| compiled.identify(text, Some(group)).and_then(|m| m.version))
    })
}

/// Builds the finding a [`FindingSpec`] describes, resolving its `{var}`
/// templates against the environment. [`None`] if a template names a variable
/// nothing bound — a finding that would lie about what it found is dropped, not
/// emitted half-built.
fn build_finding(
    flow: &FlowDetection,
    spec: &FindingSpec,
    env: &Env,
    response: Option<&str>,
) -> Option<Finding> {
    let version = Version::parse(&flow.detection.version).unwrap_or(Version::new(0, 0, 0));
    let detection = DetectionId::new(flow.detection.id.clone(), version, String::new()).ok()?;

    // The finding's one-line title is its own `title`, or its `summary` when it
    // names none.
    let title = interpolate(spec.title.as_deref().unwrap_or(spec.summary.as_str()), env)?;
    let severity = spec.severity.into_model();
    let confidence = spec
        .confidence
        .as_deref()
        .and_then(wire::confidence)
        .unwrap_or(Confidence::Certain);
    let class = flow.detection.capabilities.class.into_model();

    let mut finding = Finding::new(detection, title, severity, confidence, class).ok()?;

    // The excerpt: an explicit source, the interpolated detail, or the reply.
    let excerpt = match spec.excerpt_from.as_deref() {
        Some("$response") => response.map(str::to_owned),
        Some(name) => env.get(name).cloned(),
        None => match &spec.detail {
            Some(detail) => interpolate(detail, env),
            None => response.map(str::to_owned),
        },
    };
    if let Some(excerpt) = excerpt {
        finding = finding.with_excerpt(Excerpt::new(excerpt));
    }

    for reference in &spec.references {
        if let Some(reference) = reference.into_model() {
            finding = finding.with_reference(reference);
        }
    }
    if let Some(remediation) = &spec.remediation {
        finding = finding.with_remediation(remediation.clone());
    }

    Some(finding)
}

/// Substitutes each `{ident}` in `template` for the variable's value. [`None`] if
/// a name is unbound, or the braces are unbalanced — the caller drops the field
/// rather than emit a half-built one.
fn interpolate(template: &str, env: &Env) -> Option<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let close = after.find('}')?;
        out.push_str(env.get(&after[..close])?);
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// Decodes bytes as Latin-1 — each byte its own code point — so a probe reply is
/// a string a byte-oriented pattern can match without a lossy conversion eating
/// the bytes it looks for.
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| byte as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::finding::{Reference, Severity};

    fn flow(name: &str) -> FlowDetection {
        let path = format!("assets/detect/{name}.toml");
        let toml = std::fs::read_to_string(&path).expect("the example flow file");
        toml::from_str(&toml).expect("a valid flow")
    }

    /// A probe that answers every send with the same canned reply.
    struct Canned(Vec<u8>);
    impl Probe for Canned {
        fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
            Some(self.0.clone())
        }
    }

    #[test]
    fn the_redis_flow_runs_and_produces_a_finding() {
        let redis = flow("redis-unauth");
        let mut probe = Canned(b"# Server\r\nredis_version:7.2.4\r\nrun_id:abc".to_vec());

        let findings = run(&redis, &mut probe);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];

        assert_eq!(finding.detection().id(), "redis-unauth-access");
        assert_eq!(finding.severity(), Severity::High);
        assert_eq!(finding.title(), "Redis answered INFO without authentication");
        // The `{version}` in `detail` resolved from the bound capture.
        assert_eq!(
            finding.excerpt().as_str(),
            "Server version 7.2.4 is reachable without a password."
        );
        assert!(
            finding
                .references()
                .any(|r| matches!(r, Reference::Cwe(306)))
        );
    }

    #[test]
    fn a_gate_that_does_not_match_halts_and_emits_nothing() {
        let redis = flow("redis-unauth");
        // No "# Server" line, so the step's `expect` gate fails and the flow halts.
        let mut probe = Canned(b"-ERR NOAUTH Authentication required".to_vec());

        assert!(run(&redis, &mut probe).is_empty());
    }

    /// A probe standing in for an SNMP agent that answers only the `public`
    /// community. `\xa2` (GetResponse) marks a good reply; anything else is an
    /// error the `expect` gate rejects.
    struct Snmp;
    impl Probe for Snmp {
        fn speak(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
            if bytes.windows(6).any(|window| window == b"public") {
                let mut reply = vec![0xa2];
                reply.extend_from_slice(b" sysDescr: Linux router 6.1");
                Some(reply)
            } else {
                Some(b"\xa3 no such community".to_vec())
            }
        }
    }

    #[test]
    fn the_snmp_flow_walks_its_community_list_and_finds_the_open_one() {
        let snmp = flow("snmp-default-community");
        let findings = run(&snmp, &mut Snmp);

        // One community answered; the others continued without a finding.
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity(), Severity::High);
        // The loop variable and the bound capture both reached the detail.
        assert_eq!(
            finding.excerpt().as_str(),
            "Community 'public' returned sysDescr: Linux router 6.1"
        );
    }
}
