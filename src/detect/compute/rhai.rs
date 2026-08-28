// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The Rhai backend
//!
//! The first [`ComputeRuntime`], over [Rhai](https://rhai.rs) — a small,
//! embeddable, pure-Rust scripting language. It is sandboxed by the principle the
//! whole subsystem turns on: Rhai has no I/O of its own, so a script reaches
//! nothing but the host functions this backend registers, and those are exactly
//! the [capability](Capabilities) verbs the grant permits. A `passive` grant
//! registers none, so a passive module cannot reach the network — not because a
//! call is refused, but because there is no `speak` to call.
//!
//! ## A module is a compiled script; an instance is an engine that serves it
//!
//! [`load`](RhaiRuntime::load) compiles the source to a shared, reusable `AST`.
//! [`instantiate`](RhaiRuntime::instantiate) builds an [`Engine`] configured with
//! the grant's bounds and its granted capability verbs.
//! [`run`](RhaiRuntime::run) calls the module's `analyze` function against one
//! port, hands back the findings it returns, and turns a bound hit or a fault
//! into a typed [`RunOutcome`].
//!
//! ## Reaching the per-run capabilities from a registered function
//!
//! Rhai's registered functions are `'static`, so they cannot borrow the
//! [`Capabilities`] a `run` was handed. The bridge is a thread-local raw pointer,
//! set by a guard for the exact span of one `run` and cleared when it returns:
//! the capability functions read it, and because a run holds the blocking thread
//! to itself and never touches its capabilities by any other path while the guest
//! executes, the pointer is the sole live reference and never outlives the borrow.
//! This is the one place unsafe is warranted, and it is confined to
//! [`with_capabilities`].

use std::cell::{Cell, RefCell};
use std::ptr::NonNull;
use std::sync::Arc;

use ::rhai::{
    AST, Array, Blob, Dynamic, Engine, EvalAltResult, ImmutableString, Map, Position, Scope,
};

use crate::fingerprint::{Confidence, PortContext};
use crate::model::finding::{Excerpt, Finding, Reference};
use crate::record::wire;

use super::budget::{BudgetTrap, Denial, ModuleFault, RunOutcome};
use super::capability::{CapError, Capabilities, Capability, Grant};
use super::runtime::{ComputeRuntime, LoadError, ModuleBody};

/// The deepest a module's function calls may nest at run, a guard against
/// unbounded recursion independent of the work budget.
const MAX_CALL_LEVELS: usize = 32;

/// The deepest an expression may nest, bounding the parser's own recursion so a
/// pathologically nested module cannot overflow the stack at compile. Generous
/// enough for any real detection; the same bound applies to a function body and
/// to an expression outside one.
const MAX_PARSE_DEPTH: usize = 256;

thread_local! {
    /// The capabilities the currently-running module is served, as a raw pointer
    /// set by [`ActiveRun`] for the span of one [`run`](RhaiRuntime::run).
    static ACTIVE_CAPS: Cell<Option<NonNull<dyn Capabilities>>> = const { Cell::new(None) };
    /// The abnormal outcome a capability recorded when it ended the run — a budget
    /// or policy refusal the guest cannot catch. Read once the guest returns.
    static ABORT: RefCell<Option<RunOutcome>> = const { RefCell::new(None) };
}

/// Sets the thread-local capability pointer for the span of one run and restores
/// the previous state when dropped, so a panic in the guest cannot leave a dangling
/// pointer or a stale abort behind.
struct ActiveRun {
    previous_caps: Option<NonNull<dyn Capabilities>>,
    previous_abort: Option<RunOutcome>,
}

impl ActiveRun {
    /// Installs `caps` as the active capabilities. The pointer must stay valid —
    /// its referent unmoved and untouched by any other path — until this guard is
    /// dropped, which the sole caller ([`run`](RhaiRuntime::run)) guarantees.
    fn new(caps: *mut dyn Capabilities) -> Self {
        let previous_caps = ACTIVE_CAPS.with(|cell| cell.replace(NonNull::new(caps)));
        let previous_abort = ABORT.with(|cell| cell.borrow_mut().take());
        Self {
            previous_caps,
            previous_abort,
        }
    }

    /// The outcome a capability recorded during the run, if it ended one.
    fn taken_abort(&self) -> Option<RunOutcome> {
        ABORT.with(|cell| cell.borrow_mut().take())
    }
}

impl Drop for ActiveRun {
    fn drop(&mut self) {
        ACTIVE_CAPS.with(|cell| cell.set(self.previous_caps));
        ABORT.with(|cell| *cell.borrow_mut() = self.previous_abort.take());
    }
}

/// Runs `f` with the active capabilities, or returns [`None`] if none are set
/// (a capability called outside a run, which the seam never does).
fn with_capabilities<R>(f: impl FnOnce(&mut dyn Capabilities) -> R) -> Option<R> {
    ACTIVE_CAPS.with(|cell| {
        let mut caps = cell.get()?;
        // SAFETY: the pointer is installed only by `ActiveRun`, for the exact span
        // of one `run`, on this thread. `run` does not touch the capabilities by
        // any other path while the guest executes, so this reconstituted reference
        // is the only live one and does not outlive the borrow `run` was handed.
        Some(f(unsafe { caps.as_mut() }))
    })
}

/// A compiled module: a shared `AST`, built once and run against every port.
pub struct RhaiModule {
    ast: Arc<AST>,
}

/// A per-run instance: an engine bounded and provisioned for one grant.
pub struct RhaiInstance {
    engine: Engine,
    ast: Arc<AST>,
    grant: Grant,
}

/// The Rhai [`ComputeRuntime`].
pub struct RhaiRuntime {
    /// A bare engine used only to parse a module at load. Compilation resolves no
    /// capability calls — those are late-bound at run — so this needs none of them
    /// registered.
    compiler: Engine,
}

impl RhaiRuntime {
    /// A new Rhai runtime.
    pub fn new() -> Self {
        let mut compiler = Engine::new();
        // Parsing is the one place this engine works, so its recursion is bounded
        // here; the run engine never re-parses a compiled module.
        compiler.set_max_expr_depths(MAX_PARSE_DEPTH, MAX_PARSE_DEPTH);
        Self { compiler }
    }
}

impl Default for RhaiRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl ComputeRuntime for RhaiRuntime {
    type Module = RhaiModule;
    type Instance = RhaiInstance;

    fn load(&self, body: &ModuleBody) -> Result<Self::Module, LoadError> {
        let ModuleBody::Rhai(source) = body;
        let ast = self
            .compiler
            .compile(source)
            .map_err(|error| LoadError::Compile(error.to_string()))?;

        // A module that cannot be entered is rejected here, before any port is
        // touched, rather than faulting once per port at run.
        let has_entry = ast
            .iter_functions()
            .any(|function| function.name == "analyze" && function.params.len() == 2);
        if !has_entry {
            return Err(LoadError::Compile(
                "the module must define `fn analyze(ctx, responses)`".to_string(),
            ));
        }

        Ok(RhaiModule { ast: Arc::new(ast) })
    }

    fn instantiate(
        &self,
        module: &Self::Module,
        grant: &Grant,
    ) -> Result<Self::Instance, LoadError> {
        let mut engine = Engine::new();

        // A detection has no business writing to the host; neuter the output verbs
        // so a module cannot use them as a side channel.
        engine.on_print(|_| {});
        engine.on_debug(|_, _, _| {});

        // The work and allocation bounds. The wall-clock deadline and the byte and
        // connection budgets are enforced elsewhere — the deadline against the
        // injected clock in the live phase, the byte and connection counts inside
        // the capabilities that serve the I/O.
        engine.set_max_operations(grant.budget.fuel);
        engine.set_max_string_size(grant.budget.max_memory);
        engine.set_max_array_size(grant.budget.max_memory);
        engine.set_max_map_size(grant.budget.max_memory);
        engine.set_max_call_levels(MAX_CALL_LEVELS);

        // The class becomes the served set here: only the granted verbs are
        // registered, so an ungranted one is not refused but absent. `now` is
        // always available — an injected clock touches nothing.
        engine.register_fn("now", capability_now);
        if grant.speak {
            engine.register_fn("speak", capability_speak);
        }
        if grant.resolve {
            engine.register_fn("resolve", capability_resolve);
        }

        Ok(RhaiInstance {
            engine,
            ast: module.ast.clone(),
            grant: grant.clone(),
        })
    }

    fn run(
        &self,
        instance: &mut Self::Instance,
        ctx: &PortContext,
        responses: &[&[u8]],
        caps: &mut dyn Capabilities,
    ) -> Result<Vec<Finding>, RunOutcome> {
        // Erase the borrow to a raw pointer for the eval, and with it the
        // lifetime, so the thread-local can hold it. `caps` is not touched again
        // until the guard drops, and the guest runs entirely within this call, so
        // the pointer is the sole access path and never outlives the real borrow.
        let caps: *mut (dyn Capabilities + '_) = caps;
        // SAFETY: the two pointer types are identical fat pointers differing only
        // in the pointee's lifetime, which `ActiveRun` bounds to this call.
        let caps: *mut (dyn Capabilities + 'static) = unsafe { std::mem::transmute(caps) };
        let active = ActiveRun::new(caps);

        let context = build_context(ctx);
        let responses = build_responses(responses);
        let mut scope = Scope::new();
        let result = instance.engine.call_fn::<Dynamic>(
            &mut scope,
            &instance.ast,
            "analyze",
            (context, responses),
        );

        match result {
            Ok(value) => collect_findings(value, &instance.grant),
            Err(error) => match active.taken_abort() {
                // A capability ended the run: a budget or policy refusal the guest
                // could not catch. That recorded outcome is the truth, not the
                // generic termination error it surfaced as.
                Some(outcome) => Err(outcome),
                None => Err(classify(&error)),
            },
        }
    }
}

// ── The capability verbs, as Rhai host functions ─────────────────────────────

/// `speak(bytes) -> bytes`. A budget or policy refusal ends the run; an ordinary
/// I/O failure is handed back to the module, which may catch it.
fn capability_speak(bytes: Blob) -> Result<Blob, Box<EvalAltResult>> {
    match with_capabilities(|caps| caps.speak(&bytes)) {
        None => Err(runtime_error("a capability was called outside a run")),
        Some(Ok(reply)) => Ok(reply),
        Some(Err(error)) if error.is_fatal() => {
            record_abort(outcome_for(&error, Capability::Speak));
            Err(terminated())
        }
        Some(Err(error)) => Err(runtime_error(&error.to_string())),
    }
}

/// `resolve(name) -> [address]`, addresses rendered as strings.
fn capability_resolve(name: ImmutableString) -> Result<Array, Box<EvalAltResult>> {
    match with_capabilities(|caps| caps.resolve(name.as_str())) {
        None => Err(runtime_error("a capability was called outside a run")),
        Some(Ok(addresses)) => Ok(addresses
            .into_iter()
            .map(|address| Dynamic::from(address.to_string()))
            .collect()),
        Some(Err(error)) if error.is_fatal() => {
            record_abort(outcome_for(&error, Capability::Resolve));
            Err(terminated())
        }
        Some(Err(error)) => Err(runtime_error(&error.to_string())),
    }
}

/// `now() -> millis`, the injected scan-relative tick.
fn capability_now() -> i64 {
    with_capabilities(|caps| caps.now().millis() as i64).unwrap_or(0)
}

/// The outcome a fatal capability error ends the run with.
fn outcome_for(error: &CapError, capability: Capability) -> RunOutcome {
    match error {
        CapError::ByteBudgetExhausted => RunOutcome::BudgetExceeded(BudgetTrap::Bytes),
        CapError::ConnectionBudgetExhausted => RunOutcome::BudgetExceeded(BudgetTrap::Connections),
        CapError::Denied(reason) => RunOutcome::Denied(Denial {
            capability,
            reason: reason.clone(),
        }),
        // The non-fatal errors are handed back to the module, never here.
        other => RunOutcome::Faulted(ModuleFault::Runtime(other.to_string())),
    }
}

fn record_abort(outcome: RunOutcome) {
    ABORT.with(|cell| *cell.borrow_mut() = Some(outcome));
}

/// An uncatchable termination, the vehicle for ending a run on a fatal capability
/// error — the recorded [`RunOutcome`] carries the real cause.
fn terminated() -> Box<EvalAltResult> {
    Box::new(EvalAltResult::ErrorTerminated(
        Dynamic::UNIT,
        Position::NONE,
    ))
}

/// A catchable runtime error the guest may handle.
fn runtime_error(message: &str) -> Box<EvalAltResult> {
    Box::new(EvalAltResult::ErrorRuntime(message.into(), Position::NONE))
}

/// Turns a guest error with no recorded abort into an outcome: a work or memory
/// bound the engine enforced, an ungranted capability the module named, or a
/// fault in the module's own logic.
fn classify(error: &EvalAltResult) -> RunOutcome {
    match error {
        EvalAltResult::ErrorTooManyOperations(_) => RunOutcome::BudgetExceeded(BudgetTrap::Fuel),
        EvalAltResult::ErrorTerminated(_, _) => RunOutcome::BudgetExceeded(BudgetTrap::Deadline),
        EvalAltResult::ErrorDataTooLarge(_, _) => RunOutcome::BudgetExceeded(BudgetTrap::Memory),
        EvalAltResult::ErrorFunctionNotFound(name, _) if names_capability(name) => {
            RunOutcome::Faulted(ModuleFault::Runtime(format!(
                "the module named an ungranted capability: {name}"
            )))
        }
        other => RunOutcome::Faulted(ModuleFault::Runtime(other.to_string())),
    }
}

/// Whether a not-found function signature names a capability the class withheld,
/// as opposed to an ordinary typo in the module.
fn names_capability(signature: &str) -> bool {
    signature.starts_with("speak")
        || signature.starts_with("resolve")
        || signature.starts_with("now")
}

// ── Marshalling between the model and Rhai values ────────────────────────────

/// The port context, as the object map a module reads: `ctx.port`,
/// `ctx.protocol`, `ctx.addr`.
fn build_context(ctx: &PortContext) -> Map {
    let mut map = Map::new();
    map.insert("port".into(), (i64::from(ctx.port)).into());
    map.insert("protocol".into(), wire::protocol_name(ctx.protocol).into());
    let addr = match ctx.addr {
        Some(addr) => addr.ip().to_string().into(),
        None => Dynamic::UNIT,
    };
    map.insert("addr".into(), addr);
    map
}

/// The gathered responses, as an array of blobs a module indexes.
fn build_responses(responses: &[&[u8]]) -> Array {
    responses
        .iter()
        .map(|payload| Dynamic::from_blob(payload.to_vec()))
        .collect()
}

/// Turns whatever a module returned into findings: unit is no finding, a map is
/// one, an array is many, and anything else is a fault.
fn collect_findings(value: Dynamic, grant: &Grant) -> Result<Vec<Finding>, RunOutcome> {
    if value.is_unit() {
        return Ok(Vec::new());
    }
    if let Some(array) = value.clone().try_cast::<Array>() {
        let mut findings = Vec::with_capacity(array.len());
        for element in array {
            let map = element
                .try_cast::<Map>()
                .ok_or_else(|| bad_output("each finding must be a map"))?;
            findings.push(finding_from_map(&map, grant)?);
        }
        return Ok(findings);
    }
    if let Some(map) = value.try_cast::<Map>() {
        return Ok(vec![finding_from_map(&map, grant)?]);
    }
    Err(bad_output(
        "analyze must return a finding, an array of findings, or nothing",
    ))
}

/// Builds one [`Finding`] from a module's finding map. Provenance and class come
/// from the grant, never the module; the rest is the module's own verdict,
/// re-validated through the constructor exactly as any other finding is.
fn finding_from_map(map: &Map, grant: &Grant) -> Result<Finding, RunOutcome> {
    let severity = map_str(map, "severity")
        .as_deref()
        .and_then(wire::severity)
        .ok_or_else(|| {
            bad_output("a finding needs a severity: info, low, medium, high, or critical")
        })?;
    let summary = map_str(map, "summary")
        .filter(|summary| !summary.trim().is_empty())
        .ok_or_else(|| bad_output("a finding needs a non-empty summary"))?;
    let title = map_str(map, "title")
        .filter(|title| !title.trim().is_empty())
        .unwrap_or_else(|| summary.clone());
    let confidence = map_str(map, "confidence")
        .as_deref()
        .and_then(wire::confidence)
        .unwrap_or(Confidence::Certain);

    let mut finding = Finding::new(
        grant.detection.clone(),
        title,
        severity,
        confidence,
        grant.class,
    )
    .map_err(|error| bad_output(&error.to_string()))?;

    if let Some(text) = map_str(map, "excerpt").or_else(|| map_str(map, "detail")) {
        finding = finding.with_excerpt(Excerpt::new(text));
    }
    if let Some(references) = map
        .get("references")
        .and_then(|d| d.clone().try_cast::<Array>())
    {
        for element in references {
            if let Some(reference) = element
                .try_cast::<Map>()
                .and_then(|m| reference_from_map(&m))
            {
                finding = finding.with_reference(reference);
            }
        }
    }
    if let Some(remediation) =
        map_str(map, "remediation").filter(|remediation| !remediation.trim().is_empty())
    {
        finding = finding.with_remediation(remediation);
    }

    Ok(finding)
}

/// A reference from a module's `{ cve: "…" }`, `{ cwe: 79 }`, or `{ url: "…" }`.
fn reference_from_map(map: &Map) -> Option<Reference> {
    if let Some(cve) = map_str(map, "cve") {
        return Reference::cve(cve);
    }
    if let Some(cwe) = map_int(map, "cwe").filter(|cwe| (0..=i64::from(u32::MAX)).contains(cwe)) {
        return Some(Reference::cwe(cwe as u32));
    }
    map_str(map, "url").map(Reference::url)
}

fn map_str(map: &Map, key: &str) -> Option<String> {
    map.get(key)
        .and_then(|value| value.clone().into_string().ok())
}

fn map_int(map: &Map, key: &str) -> Option<i64> {
    map.get(key).and_then(|value| value.as_int().ok())
}

fn bad_output(message: &str) -> RunOutcome {
    RunOutcome::Faulted(ModuleFault::BadOutput(message.to_string()))
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
    use crate::detect::compute::{Budget, ScanInstant};
    use crate::model::finding::{DetectionClass, DetectionId, Severity, Version};
    use crate::model::port::Protocol;
    use std::collections::VecDeque;
    use std::net::IpAddr;
    use std::time::Duration;

    /// A capabilities implementation that serves canned replies and records what
    /// the module did — the offline path that is also the replay path.
    struct RecordedCaps {
        replies: VecDeque<Result<Vec<u8>, CapError>>,
        sent: Vec<Vec<u8>>,
        clock: u64,
    }

    impl RecordedCaps {
        fn new(replies: Vec<Result<Vec<u8>, CapError>>) -> Self {
            Self {
                replies: replies.into(),
                sent: Vec::new(),
                clock: 0,
            }
        }
    }

    impl Capabilities for RecordedCaps {
        fn speak(&mut self, bytes: &[u8]) -> Result<Vec<u8>, CapError> {
            self.sent.push(bytes.to_vec());
            self.replies.pop_front().unwrap_or(Ok(Vec::new()))
        }

        fn resolve(&mut self, _name: &str) -> Result<Vec<IpAddr>, CapError> {
            Ok(Vec::new())
        }

        fn now(&mut self) -> ScanInstant {
            let millis = self.clock;
            self.clock += 1;
            ScanInstant::from_millis(millis)
        }
    }

    fn budget() -> Budget {
        Budget {
            fuel: 1_000_000,
            deadline: Duration::from_secs(2),
            max_memory: 65_536,
            max_bytes: 8_192,
            max_connections: 4,
        }
    }

    fn grant(class: DetectionClass, speak: bool) -> Grant {
        Grant {
            detection: DetectionId::new("test-detection", Version::new(1, 0, 0), "hash").unwrap(),
            class,
            budget: budget(),
            speak,
            resolve: false,
        }
    }

    fn ctx(port: u16) -> PortContext {
        PortContext {
            port,
            protocol: Protocol::Tcp,
            addr: None,
            tunnel: None,
        }
    }

    /// Compiles `source`, instantiates it under `grant`, and runs it once.
    fn run(
        source: &str,
        grant: Grant,
        caps: &mut RecordedCaps,
    ) -> Result<Vec<Finding>, RunOutcome> {
        let runtime = RhaiRuntime::new();
        let module = runtime
            .load(&ModuleBody::Rhai(source.to_string()))
            .expect("the module compiles");
        let mut instance = runtime
            .instantiate(&module, &grant)
            .expect("the module instantiates");
        runtime.run(&mut instance, &ctx(6379), &[], caps)
    }

    #[test]
    fn a_module_speaks_reads_the_reply_and_returns_a_finding() {
        let source = r#"
            fn analyze(ctx, responses) {
                let reply = speak(blob());
                if reply.len() > 0 {
                    [ #{
                        severity: "high",
                        summary: "port " + ctx.port + " answered",
                        confidence: "probable",
                        references: [ #{ cwe: 306 } ],
                    } ]
                } else {
                    []
                }
            }
        "#;
        let mut caps = RecordedCaps::new(vec![Ok(b"# Server\r\n".to_vec())]);

        let findings =
            run(source, grant(DetectionClass::ActiveBenign, true), &mut caps).expect("a clean run");
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity(), Severity::High);
        assert_eq!(finding.confidence(), Confidence::Probable);
        assert_eq!(finding.title(), "port 6379 answered");
        // Provenance is the grant's, not the module's — a module cannot forge it.
        assert_eq!(finding.detection().id(), "test-detection");
        assert_eq!(finding.detection().content_hash(), "hash");
        assert!(
            finding
                .references()
                .any(|r| matches!(r, Reference::Cwe(306)))
        );
        // The module sent exactly the one empty probe it asked to.
        assert_eq!(caps.sent, vec![Vec::<u8>::new()]);
    }

    #[test]
    fn a_module_that_computes_without_end_is_trapped_at_its_fuel_bound() {
        // Without a work bound this hangs the scan; the test terminating at all is
        // half the proof, the typed outcome the other half.
        let source = r#"
            fn analyze(ctx, responses) {
                let n = 0;
                while true { n += 1; }
                n
            }
        "#;
        let mut grant = grant(DetectionClass::ActiveBenign, true);
        grant.budget.fuel = 10_000;
        let mut caps = RecordedCaps::new(vec![]);

        let outcome = run(source, grant, &mut caps).expect_err("the loop is trapped");
        assert_eq!(outcome, RunOutcome::BudgetExceeded(BudgetTrap::Fuel));
    }

    #[test]
    fn a_passive_module_cannot_reach_the_network_because_speak_is_absent() {
        // The security property: a passive grant registers no `speak`, so the call
        // is not refused but unnameable — and no byte reaches the capabilities.
        let source = r#"
            fn analyze(ctx, responses) {
                speak(blob());
                []
            }
        "#;
        let mut caps = RecordedCaps::new(vec![Ok(b"should never be reached".to_vec())]);

        let outcome = run(source, grant(DetectionClass::Passive, false), &mut caps)
            .expect_err("naming an ungranted capability faults");
        assert!(matches!(
            outcome,
            RunOutcome::Faulted(ModuleFault::Runtime(_))
        ));
        assert!(caps.sent.is_empty(), "a passive module reached the network");
    }

    #[test]
    fn a_byte_budget_refusal_ends_the_run_and_the_module_cannot_catch_it() {
        // The capability refuses on budget grounds; the module wraps the call in a
        // catch, but a budget end is uncatchable, so the run still ends as a trap
        // and emits nothing.
        let source = r#"
            fn analyze(ctx, responses) {
                try { speak(blob()); } catch (err) { }
                [ #{ severity: "low", summary: "the catch swallowed the trap" } ]
            }
        "#;
        let mut caps = RecordedCaps::new(vec![Err(CapError::ByteBudgetExhausted)]);

        let outcome = run(source, grant(DetectionClass::ActiveBenign, true), &mut caps)
            .expect_err("a budget end is not catchable");
        assert_eq!(outcome, RunOutcome::BudgetExceeded(BudgetTrap::Bytes));
    }

    #[test]
    fn the_same_recorded_inputs_yield_identical_findings() {
        let source = r#"
            fn analyze(ctx, responses) {
                let reply = speak(blob());
                [ #{ severity: "medium", summary: "answered at " + now(), detail: reply } ]
            }
        "#;

        let mut first_caps = RecordedCaps::new(vec![Ok(b"banner".to_vec())]);
        let first = run(
            source,
            grant(DetectionClass::ActiveBenign, true),
            &mut first_caps,
        )
        .expect("a clean run");
        let mut second_caps = RecordedCaps::new(vec![Ok(b"banner".to_vec())]);
        let second = run(
            source,
            grant(DetectionClass::ActiveBenign, true),
            &mut second_caps,
        )
        .expect("a clean run");

        assert_eq!(
            first, second,
            "a pure function of its inputs did not replay"
        );
    }
}
