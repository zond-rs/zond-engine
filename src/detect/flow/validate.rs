// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Checking a flow before it ships
//!
//! The structural half of the flow validator. It reports every way a parsed
//! [`FlowDetection`] is ill-formed: a guard naming a variable no earlier step
//! binds, a `passive` detection that sends, a loop that is empty or too long, a
//! detection that can emit no finding. Failures surface at build time.
//!
//! ## Shared with `build.rs`
//!
//! It depends only on [`std`], [`schema`](super::schema) and [`expr`], so
//! `build.rs` loads it with `#[path]`. Its tests, which the build never
//! compiles, use the real matcher and parsed flows.
//!
//! ## Not checked here
//!
//! That every `expect`/`bind` pattern compiles with the named group, and that a
//! declared byte budget covers the payloads: `build.rs` checks those with the
//! pattern compiler and payload unescaper.

// Used by `build.rs` and the tests; the `--lib` build alone sees some as unused.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fmt;

use super::expr::{self, ParseError};
use super::manifest::Class;
use super::schema::{FindingSpec, FlowDetection, MAX_FLOW_STEPS, MAX_LOOP_ITEMS, Step};

/// The identity prefix reserved for the engine's own detections.
pub const RESERVED_ID_PREFIX: &str = "zond:";

/// One way a flow is ill-formed. Each is a hard error: a flow that produces any
/// does not ship. The [`Display`](fmt::Display) form is the message the build
/// prints beside the offending file.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// More than [`MAX_FLOW_STEPS`] steps.
    TooManySteps(usize),
    /// A `for_each` over an empty list, a step that never runs.
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
    /// says where, a step guard, a send, a finding guard, a template field.
    UndefinedVariable(usize, String, &'static str),
    /// A step's own guard reads `matched`, which is out of scope before the step
    /// has matched anything.
    MatchedInStepGuard(usize),
    /// A finding guards on `matched` in a step that has no `expect` to match.
    MatchedWithoutExpect(usize),
    /// A guard does not parse. The `&str` says which guard.
    GuardParseError(usize, &'static str, ParseError),
    /// A whole flow with no `[[step.finding]]`, a detection that can conclude
    /// nothing.
    NoFindings,
    /// A `version` that is not a `major.minor.patch` triple.
    MalformedVersion(String),
    /// An empty `id`.
    EmptyId,
    /// An empty `title`.
    EmptyTitle,
    /// A `[detection.group]` with an empty `id` or an empty `summary`.
    HalfGroup,
    /// An `id` claiming the reserved `zond:` namespace.
    ReservedId(String),
    /// A step names an `expect` but sends nothing, so it can never match.
    ExpectWithoutSend(usize),
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
            ValidationError::HalfGroup => {
                write!(f, "has a group without both an id and a summary")
            }
            ValidationError::ReservedId(id) => {
                write!(
                    f,
                    "id `{id}` claims the reserved `{RESERVED_ID_PREFIX}` namespace"
                )
            }
            ValidationError::ExpectWithoutSend(step) => write!(
                f,
                "step {step} has an `expect` but no `send`, so nothing is drawn for it to match"
            ),
        }
    }
}

/// Checks `flow` and returns every way it is ill-formed, empty if it is sound.
///
/// Reports every problem, not just the first. Duplicate ids across the corpus
/// and the pattern and budget rules are the caller's to check.
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

    for (index, step) in flow.step.iter().enumerate() {
        // An `expect` with no `send` is a dead step, like an empty loop.
        if !step.expect.is_empty() && step.send.is_none() {
            errors.push(ValidationError::ExpectWithoutSend(index));
        }
    }

    check_references(flow, &mut errors);

    errors
}

/// The identity is well-formed and does not claim the reserved prefix.
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
    if let Some(group) = &flow.detection.group
        && (group.id.trim().is_empty() || group.summary.trim().is_empty())
    {
        errors.push(ValidationError::HalfGroup);
    }
    if !is_version_triple(&flow.detection.version) {
        errors.push(ValidationError::MalformedVersion(
            flow.detection.version.clone(),
        ));
    }
}

/// A detection's structure may not exceed what its class allows.
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

/// The transport that will serve `speak` is one the engine speaks.
fn check_protocol(flow: &FlowDetection, errors: &mut Vec<ValidationError>) {
    if let Some(protocol) = &flow.detection.when.protocol
        && protocol != "tcp"
        && protocol != "udp"
    {
        errors.push(ValidationError::UnknownProtocol(protocol.clone()));
    }
}

/// The forward-only variable walk: every guard and template names only what is
/// in scope, every loop is bounded, and every guard parses.
fn check_references(flow: &FlowDetection, errors: &mut Vec<ValidationError>) {
    // The scope opens with the seed variables `host` and `port`. Only a
    // non-`for_each` step's binds persist; a `for_each` step runs each item in a
    // clone.
    let mut persisted: BTreeSet<String> = super::schema::SEED_VARS
        .iter()
        .map(|v| v.to_string())
        .collect();

    for (index, step) in flow.step.iter().enumerate() {
        let loop_var = check_loop(index, step, &persisted, errors);

        // The guard and send see persisted variables and this step's loop
        // variable; its binds have not run yet.
        let mut gate_scope = persisted.clone();
        gate_scope.extend(loop_var.clone());

        check_step_guard(index, step, &gate_scope, errors);
        if let Some(send) = &step.send {
            check_template(index, send, "a send", &gate_scope, errors);
        }

        // A finding also sees this step's binds.
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

/// A `for_each` is bounded and does not shadow. Returns the loop variable it
/// introduces, if any.
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

/// A step's own guard parses, names only what is in scope, and does not read
/// `matched`.
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

/// One finding's guard, templates and excerpt source.
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

/// Every `{var}` a template interpolates is in scope.
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
/// reads them: `{ident}` names a variable, `{{` and `}}` are literal braces, and a
/// lone `}` is literal. Must match [`interpolate`](super::interp).
fn template_vars(template: &str) -> Vec<String> {
    let mut vars = Vec::new();
    let mut rest = template;
    while let Some(brace) = rest.find(['{', '}']) {
        let this = rest.as_bytes()[brace];
        let after = &rest[brace + 1..];
        if after.as_bytes().first() == Some(&this) {
            rest = &after[1..];
        } else if this == b'{' {
            let Some(close) = after.find('}') else { break };
            vars.push(after[..close].to_string());
            rest = &after[close + 1..];
        } else {
            rest = after;
        }
    }
    vars
}

/// Whether `version` is a `major.minor.patch` triple of numbers, checked without
/// the model so `build.rs` can share this file.
pub fn is_version_triple(version: &str) -> bool {
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

    /// Every shipped flow re-validates after embedding.
    #[test]
    fn every_shipped_flow_validates() {
        let shipped = crate::detect::flow::db::embedded_flows();
        assert!(!shipped.is_empty(), "the corpus ships no flows at all");

        for compiled in &shipped {
            let errors = check(compiled.flow());
            assert!(
                errors.is_empty(),
                "{}: {errors:?}",
                compiled.flow().detection.id
            );
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
    fn the_seed_variables_are_in_scope_from_the_first_step() {
        // `{host}` and `{port}` are seeded, so a first step may name them.
        let flow = flow(
            r#"
            [detection]
            id = "seed"
            version = "1.0.0"
            title = "seed"
            [detection.when]
            speaks = "http"
            [detection.capabilities]
            class = "active-benign"
            speak = "target"
            [[step]]
            send   = "HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n"
            expect = "HTTP/"
            [[step.finding]]
            when     = "matched"
            severity = "info"
            summary  = "port {port} answered on {host}"
            "#,
        );
        assert!(
            check(&flow).is_empty(),
            "a flow naming the seed variables was rejected: {:?}",
            check(&flow)
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
    fn an_expect_without_a_send_is_dead_and_rejected() {
        // Drop `sound()`'s send so its expect can never match.
        let mut flow = sound();
        flow.step[0].send = None;
        assert!(
            check(&flow)
                .iter()
                .any(|e| matches!(e, ValidationError::ExpectWithoutSend(0))),
            "{:?}",
            check(&flow)
        );
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

    #[test]
    fn template_vars_reads_names_and_skips_escaped_braces() {
        assert_eq!(template_vars("{host}:{port}"), vec!["host", "port"]);
        // A doubled brace is a literal brace.
        assert_eq!(template_vars(r#"{{"key":"{host}"}}"#), vec!["host"]);
        assert!(template_vars(r#"{{"key":"value"}}"#).is_empty());
        // A lone `}` is literal; only `{` opens a name.
        assert_eq!(template_vars("a}b {host}"), vec!["host"]);
    }
}
