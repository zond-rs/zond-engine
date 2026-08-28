// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Checking a flow before it ships
//!
//! The structural half of the flow validator. It walks a parsed
//! [`FlowDetection`](super::schema::FlowDetection) and reports every way it is
//! ill-formed — a guard that names a variable no earlier step binds, a `passive`
//! detection that tries to send, a loop that never ends or never runs, a
//! detection that can emit no finding at all. A flow that passes is a flow the
//! interpreter can run without a surprise, which is the whole promise of a
//! validated tier: the failure is at the build, with a pointer to the file, not
//! at scan time against a live target.
//!
//! ## Why it lives here and not only in `build.rs`
//!
//! Like the schema and the guard grammar, this module carries no dependency on
//! the rest of the crate — only [`std`], its sibling [`schema`](super::schema),
//! and its sibling [`expr`](super::expr). So `build.rs` loads it with `#[path]`
//! and runs it over the flow corpus with the very code that would run over a flow
//! loaded at runtime. Its `#[cfg(test)]` tests are free to reach into the crate
//! (the build never compiles them), so they check the checker against the real
//! matcher and real parsed flows.
//!
//! ## What it does *not* check
//!
//! The engine-backed rules stay with the engine, in `build.rs`: that every
//! `expect`/`bind` pattern compiles and its capture group exists, and that a
//! declared byte budget covers the payloads the flow must send. Those need the
//! fingerprint pattern compiler and the payload unescaper, which the build has on
//! hand; this module is pure over the flow's structure.

// Every item here is consumed by `build.rs` (which `#[path]`-loads this file to
// validate the flow corpus) and by the tests, not by the runtime library yet —
// so the plain `--lib` build alone sees them as unused.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fmt;

use super::expr::{self, ParseError};
use super::schema::{Class, FindingSpec, FlowDetection, MAX_FLOW_STEPS, MAX_LOOP_ITEMS, Step};

/// The reserved identity prefix the engine's own detections use; an authored
/// flow may not claim it, so a third-party flow cannot forge a first-party
/// finding.
const RESERVED_ID_PREFIX: &str = "zond:";

/// One way a flow is ill-formed. Each is a hard error: a flow that produces any
/// does not ship. The [`Display`](fmt::Display) form is the message the build
/// prints beside the offending file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// More than [`MAX_FLOW_STEPS`] steps.
    TooManySteps(usize),
    /// A `for_each` over an empty list — a step that never runs.
    EmptyLoop(usize),
    /// A `for_each` over more than [`MAX_LOOP_ITEMS`] items.
    LoopTooLong(usize, usize),
    /// A `for_each` variable that shadows one an earlier step already bound.
    LoopVarShadows(usize, String),
    /// A `[detection.when].protocol` that is neither `tcp` nor `udp`.
    UnknownProtocol(String),
    /// A `passive` detection that declares or performs something active.
    PassiveDoes(&'static str),
    /// A step sends bytes but the detection was granted no `speak`.
    SendWithoutSpeak,
    /// A guard or template names a variable no earlier step binds. The `&str`
    /// says where — a step guard, a send, a finding guard, a template field.
    UndefinedVariable(usize, String, &'static str),
    /// A step's own guard reads `matched`, which is out of scope before the step
    /// has matched anything.
    MatchedInStepGuard(usize),
    /// A finding guards on `matched` in a step that has no `expect` to match.
    MatchedWithoutExpect(usize),
    /// A guard does not parse. The `&str` says which guard.
    GuardParseError(usize, &'static str, ParseError),
    /// A whole flow with no `[[step.finding]]` — a detection that can conclude
    /// nothing.
    NoFindings,
    /// A `version` that is not a `major.minor.patch` triple.
    MalformedVersion(String),
    /// An empty `id`.
    EmptyId,
    /// An empty `title`.
    EmptyTitle,
    /// An `id` claiming the reserved `zond:` namespace.
    ReservedId(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::TooManySteps(count) => {
                write!(
                    f,
                    "has {count} steps, over the {MAX_FLOW_STEPS}-step ceiling"
                )
            }
            ValidationError::EmptyLoop(step) => {
                write!(f, "step {step} loops over an empty list, so it never runs")
            }
            ValidationError::LoopTooLong(step, count) => write!(
                f,
                "step {step} loops over {count} items, over the {MAX_LOOP_ITEMS}-item cap"
            ),
            ValidationError::LoopVarShadows(step, var) => write!(
                f,
                "step {step} binds loop variable `{var}`, which an earlier step already bound"
            ),
            ValidationError::UnknownProtocol(protocol) => {
                write!(
                    f,
                    "names protocol `{protocol}`, which is neither tcp nor udp"
                )
            }
            ValidationError::PassiveDoes(what) => {
                write!(f, "is passive but declares {what}, which is active")
            }
            ValidationError::SendWithoutSpeak => {
                write!(f, "sends bytes but was granted no `speak` capability")
            }
            ValidationError::UndefinedVariable(step, var, place) => write!(
                f,
                "step {step} reads variable `{var}` in {place}, which no earlier step binds"
            ),
            ValidationError::MatchedInStepGuard(step) => write!(
                f,
                "step {step}'s own guard reads `matched`, but nothing has matched when a step is gated"
            ),
            ValidationError::MatchedWithoutExpect(step) => write!(
                f,
                "step {step} has a finding guarded on `matched` but no `expect` to match against"
            ),
            ValidationError::GuardParseError(step, place, error) => {
                write!(f, "step {step}'s {place} is not a valid guard: {error}")
            }
            ValidationError::NoFindings => {
                write!(f, "declares no finding, so it can conclude nothing")
            }
            ValidationError::MalformedVersion(version) => {
                write!(f, "has version `{version}`, not a major.minor.patch triple")
            }
            ValidationError::EmptyId => write!(f, "has an empty id"),
            ValidationError::EmptyTitle => write!(f, "has an empty title"),
            ValidationError::ReservedId(id) => {
                write!(
                    f,
                    "id `{id}` claims the reserved `{RESERVED_ID_PREFIX}` namespace"
                )
            }
        }
    }
}

/// Checks `flow` and returns every way it is ill-formed, empty if it is sound.
///
/// It reports *all* the problems it finds rather than the first, so one build
/// surfaces every fix a flow needs. Duplicate ids across the corpus and the
/// pattern/budget rules are the caller's to add — they need the whole corpus or
/// the pattern engine, which this pure structural pass does not hold.
pub fn check(flow: &FlowDetection) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    check_identity(flow, &mut errors);
    check_capabilities(flow, &mut errors);
    check_protocol(flow, &mut errors);

    if flow.step.len() > MAX_FLOW_STEPS {
        errors.push(ValidationError::TooManySteps(flow.step.len()));
    }
    if flow.step.iter().all(|step| step.finding.is_empty()) {
        errors.push(ValidationError::NoFindings);
    }

    check_references(flow, &mut errors);

    errors
}

/// H11 — the identity is well-formed and does not forge a first-party finding.
fn check_identity(flow: &FlowDetection, errors: &mut Vec<ValidationError>) {
    let id = &flow.detection.id;
    if id.trim().is_empty() {
        errors.push(ValidationError::EmptyId);
    } else if id.starts_with(RESERVED_ID_PREFIX) {
        errors.push(ValidationError::ReservedId(id.clone()));
    }
    if flow.detection.title.trim().is_empty() {
        errors.push(ValidationError::EmptyTitle);
    }
    if !is_version_triple(&flow.detection.version) {
        errors.push(ValidationError::MalformedVersion(
            flow.detection.version.clone(),
        ));
    }
}

/// H8 — a detection cannot do more than its class allows. The class is what the
/// envelope will serve; the flow's *structure* may not exceed it.
fn check_capabilities(flow: &FlowDetection, errors: &mut Vec<ValidationError>) {
    let caps = &flow.detection.capabilities;
    let has_send = flow.step.iter().any(|step| step.send.is_some());
    let has_for_each = flow.step.iter().any(|step| step.for_each.is_some());

    if caps.class == Class::Passive {
        if caps.speak.is_some() {
            errors.push(ValidationError::PassiveDoes("speak"));
        }
        if caps.resolve {
            errors.push(ValidationError::PassiveDoes("resolve"));
        }
        if has_send {
            errors.push(ValidationError::PassiveDoes("a step that sends"));
        }
        if has_for_each {
            errors.push(ValidationError::PassiveDoes("a for_each step"));
        }
    } else if has_send && caps.speak.is_none() {
        errors.push(ValidationError::SendWithoutSpeak);
    }
}

/// H7 — the transport that will serve `speak` is one the engine speaks.
fn check_protocol(flow: &FlowDetection, errors: &mut Vec<ValidationError>) {
    if let Some(protocol) = &flow.detection.when.protocol
        && protocol != "tcp"
        && protocol != "udp"
    {
        errors.push(ValidationError::UnknownProtocol(protocol.clone()));
    }
}

/// H1, H3, H9, H10, H12, H13 — the forward-only variable walk. It threads the
/// set of variables that reach each step and proves every guard and template
/// names only what is in scope, that every loop is bounded, and that a guard is
/// well-formed.
fn check_references(flow: &FlowDetection, errors: &mut Vec<ValidationError>) {
    // Only a non-`for_each` step's binds persist to later steps: a `for_each`
    // step runs each item in a clone, so neither its loop variable nor its binds
    // outlive it.
    let mut persisted: BTreeSet<String> = BTreeSet::new();

    for (index, step) in flow.step.iter().enumerate() {
        let loop_var = check_loop(index, step, &persisted, errors);

        // A step's guard and its send see the persisted variables plus this
        // step's own loop variable — its binds have not run yet.
        let mut gate_scope = persisted.clone();
        gate_scope.extend(loop_var.clone());

        check_step_guard(index, step, &gate_scope, errors);
        if let Some(send) = &step.send {
            check_template(index, send, "a send", &gate_scope, errors);
        }

        // A finding sees all of the above plus this step's binds, which have run
        // by the time it is reached.
        let mut finding_scope = gate_scope;
        finding_scope.extend(step.bind.keys().cloned());
        for finding in &step.finding {
            check_finding(index, step, finding, &finding_scope, errors);
        }

        if step.for_each.is_none() {
            persisted.extend(step.bind.keys().cloned());
        }
    }
}

/// H1, H13 — a `for_each` is bounded and does not shadow. Returns the loop
/// variable it introduces, if any, for the scope of this step.
fn check_loop(
    index: usize,
    step: &Step,
    persisted: &BTreeSet<String>,
    errors: &mut Vec<ValidationError>,
) -> Option<String> {
    let for_each = step.for_each.as_ref()?;
    if for_each.items.is_empty() {
        errors.push(ValidationError::EmptyLoop(index));
    }
    if for_each.items.len() > MAX_LOOP_ITEMS {
        errors.push(ValidationError::LoopTooLong(index, for_each.items.len()));
    }
    if persisted.contains(&for_each.var) || step.bind.contains_key(&for_each.var) {
        errors.push(ValidationError::LoopVarShadows(index, for_each.var.clone()));
    }
    Some(for_each.var.clone())
}

/// H12, H3, and the `matched`-out-of-scope rule for a step's own guard.
fn check_step_guard(
    index: usize,
    step: &Step,
    scope: &BTreeSet<String>,
    errors: &mut Vec<ValidationError>,
) {
    let Some(when) = &step.when else { return };
    match expr::parse(when) {
        Err(error) => errors.push(ValidationError::GuardParseError(index, "guard", error)),
        Ok(guard) => {
            if guard.uses_matched() {
                errors.push(ValidationError::MatchedInStepGuard(index));
            }
            for var in guard.referenced_vars() {
                if !scope.contains(&var) {
                    errors.push(ValidationError::UndefinedVariable(index, var, "its guard"));
                }
            }
        }
    }
}

/// H12, H10, H3 over one finding's guard, templates, and excerpt source.
fn check_finding(
    index: usize,
    step: &Step,
    finding: &FindingSpec,
    scope: &BTreeSet<String>,
    errors: &mut Vec<ValidationError>,
) {
    if let Some(when) = &finding.when {
        match expr::parse(when) {
            Err(error) => errors.push(ValidationError::GuardParseError(
                index,
                "finding guard",
                error,
            )),
            Ok(guard) => {
                if guard.uses_matched() && step.expect.is_empty() {
                    errors.push(ValidationError::MatchedWithoutExpect(index));
                }
                for var in guard.referenced_vars() {
                    if !scope.contains(&var) {
                        errors.push(ValidationError::UndefinedVariable(
                            index,
                            var,
                            "a finding guard",
                        ));
                    }
                }
            }
        }
    }

    check_template(index, &finding.summary, "a finding summary", scope, errors);
    if let Some(title) = &finding.title {
        check_template(index, title, "a finding title", scope, errors);
    }
    if let Some(detail) = &finding.detail {
        check_template(index, detail, "a finding detail", scope, errors);
    }
    // `$response` is the reply itself, not a variable; any other name must bind.
    if let Some(source) = &finding.excerpt_from
        && source != "$response"
        && !scope.contains(source)
    {
        errors.push(ValidationError::UndefinedVariable(
            index,
            source.clone(),
            "a finding excerpt_from",
        ));
    }
}

/// H9 — every `{var}` a template interpolates is in scope.
fn check_template(
    index: usize,
    template: &str,
    place: &'static str,
    scope: &BTreeSet<String>,
    errors: &mut Vec<ValidationError>,
) {
    for var in template_vars(template) {
        if !scope.contains(&var) {
            errors.push(ValidationError::UndefinedVariable(index, var, place));
        }
    }
}

/// The variable names a template interpolates, read exactly as the interpreter
/// reads them: each `{` opens a name that runs to the next `}`.
fn template_vars(template: &str) -> Vec<String> {
    let mut vars = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else { break };
        vars.push(after[..close].to_string());
        rest = &after[close + 1..];
    }
    vars
}

/// Whether `version` is a `major.minor.patch` triple of numbers, the shape the
/// model's version is, checked here without reaching into the model so the file
/// stays shareable with the build.
fn is_version_triple(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    parts.len() == 3 && parts.iter().all(|part| part.parse::<u16>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::flow::schema::FlowDetection;

    /// Parses a flow the way the corpus is authored.
    fn flow(toml: &str) -> FlowDetection {
        toml::from_str(toml).expect("the test flow parses")
    }

    /// A minimal well-formed flow the negative tests perturb one field of.
    fn sound() -> FlowDetection {
        flow(
            r#"
            [detection]
            id      = "example"
            version = "1.0.0"
            title   = "Example"
            [detection.when]
            service  = "http"
            protocol = "tcp"
            [detection.capabilities]
            class = "active-benign"
            speak = "target"
            [[step]]
            send   = "GET / HTTP/1.0\r\n\r\n"
            expect = "Server:"
            bind   = { version = "Server: nginx/(?<version>[0-9.]+)" }
            [[step.finding]]
            when     = "matched"
            severity = "medium"
            summary  = "nginx {version}"
            "#,
        )
    }

    #[test]
    fn a_sound_flow_has_no_errors() {
        assert!(check(&sound()).is_empty(), "{:?}", check(&sound()));
    }

    #[test]
    fn the_shipped_examples_all_validate() {
        for name in [
            "redis-unauth",
            "snmp-default-community",
            "grafana-path-traversal",
        ] {
            let toml = std::fs::read_to_string(format!("assets/detect/{name}.toml")).unwrap();
            let errors = check(&flow(&toml));
            assert!(errors.is_empty(), "{name}: {errors:?}");
        }
    }

    #[test]
    fn a_guard_naming_a_later_bound_variable_is_a_forward_reference() {
        // Step 0's guard reads `version`, which only step 1 binds.
        let flow = flow(
            r#"
            [detection]
            id = "x"
            version = "1.0.0"
            title = "x"
            [detection.when]
            protocol = "tcp"
            [detection.capabilities]
            class = "active-benign"
            speak = "target"
            [[step]]
            when   = "bound(version)"
            send   = "a"
            [[step.finding]]
            severity = "low"
            summary  = "found"
            [[step]]
            send = "b"
            bind = { version = "v(?<version>[0-9]+)" }
            "#,
        );
        assert!(
            check(&flow).iter().any(
                |e| matches!(e, ValidationError::UndefinedVariable(0, v, _) if v == "version")
            ),
            "{:?}",
            check(&flow)
        );
    }

    #[test]
    fn a_template_naming_an_unbound_variable_is_caught() {
        let mut flow = sound();
        flow.step[0].finding[0].summary = "version {nope}".to_string();
        assert!(
            check(&flow)
                .iter()
                .any(|e| matches!(e, ValidationError::UndefinedVariable(0, v, _) if v == "nope"))
        );
    }

    #[test]
    fn matched_in_a_step_guard_is_rejected() {
        let mut flow = sound();
        flow.step[0].when = Some("matched".to_string());
        assert!(check(&flow).contains(&ValidationError::MatchedInStepGuard(0)));
    }

    #[test]
    fn an_unparseable_guard_is_reported_not_silently_unmet() {
        let mut flow = sound();
        flow.step[0].finding[0].when = Some("bound(".to_string());
        assert!(
            check(&flow)
                .iter()
                .any(|e| matches!(e, ValidationError::GuardParseError(0, "finding guard", _)))
        );
    }

    #[test]
    fn a_passive_flow_that_sends_is_rejected() {
        // Passive, yet it declares speak and a sending step.
        let flow = flow(
            r#"
            [detection]
            id = "x"
            version = "1.0.0"
            title = "x"
            [detection.when]
            protocol = "tcp"
            [detection.capabilities]
            class = "passive"
            speak = "target"
            [[step]]
            send   = "probe"
            expect = "ok"
            [[step.finding]]
            when     = "matched"
            severity = "low"
            summary  = "hit"
            "#,
        );
        let errors = check(&flow);
        assert!(errors.contains(&ValidationError::PassiveDoes("speak")));
        assert!(errors.contains(&ValidationError::PassiveDoes("a step that sends")));
    }

    #[test]
    fn a_send_without_speak_is_rejected() {
        let mut flow = sound();
        flow.detection.capabilities.speak = None;
        assert!(check(&flow).contains(&ValidationError::SendWithoutSpeak));
    }

    #[test]
    fn an_empty_and_an_oversized_loop_are_both_rejected() {
        let mut flow = sound();
        flow.step[0].for_each = Some(crate::detect::flow::schema::ForEach {
            var: "item".to_string(),
            items: vec![],
        });
        assert!(check(&flow).contains(&ValidationError::EmptyLoop(0)));

        flow.step[0].for_each = Some(crate::detect::flow::schema::ForEach {
            var: "item".to_string(),
            items: vec!["x".to_string(); MAX_LOOP_ITEMS + 1],
        });
        assert!(
            check(&flow)
                .iter()
                .any(|e| matches!(e, ValidationError::LoopTooLong(0, _)))
        );
    }

    #[test]
    fn a_flow_with_no_finding_is_dead() {
        let mut flow = sound();
        flow.step[0].finding.clear();
        assert!(check(&flow).contains(&ValidationError::NoFindings));
    }

    #[test]
    fn a_malformed_version_empty_id_and_reserved_id_are_caught() {
        let mut flow = sound();
        flow.detection.version = "1.0".to_string();
        assert!(
            check(&flow)
                .iter()
                .any(|e| matches!(e, ValidationError::MalformedVersion(_)))
        );

        let mut flow = sound();
        flow.detection.id = "  ".to_string();
        assert!(check(&flow).contains(&ValidationError::EmptyId));

        let mut flow = sound();
        flow.detection.id = "zond:cve-kev".to_string();
        assert!(
            check(&flow)
                .iter()
                .any(|e| matches!(e, ValidationError::ReservedId(_)))
        );
    }

    #[test]
    fn an_unknown_protocol_is_rejected() {
        let mut flow = sound();
        flow.detection.when.protocol = Some("sctp".to_string());
        assert!(
            check(&flow)
                .iter()
                .any(|e| matches!(e, ValidationError::UnknownProtocol(p) if p == "sctp"))
        );
    }

    #[test]
    fn a_loop_variable_shadowing_an_earlier_bind_is_rejected() {
        // Step 0 binds `host`; step 1 loops with the same name.
        let flow = flow(
            r#"
            [detection]
            id = "x"
            version = "1.0.0"
            title = "x"
            [detection.when]
            protocol = "udp"
            [detection.capabilities]
            class = "active-benign"
            speak = "target"
            [[step]]
            send = "a"
            bind = { host = "(?<host>.+)" }
            [[step]]
            for_each = { var = "host", in = ["1", "2"] }
            send     = "b {host}"
            expect   = "ok"
            [[step.finding]]
            when     = "matched"
            severity = "low"
            summary  = "hit {host}"
            "#,
        );
        assert!(
            check(&flow)
                .iter()
                .any(|e| matches!(e, ValidationError::LoopVarShadows(1, v) if v == "host"))
        );
    }
}
