// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The Rhai backend
//!
//! The first [`ComputeRuntime`], over [Rhai](https://rhai.rs), a small,
//! embeddable, pure-Rust scripting language. It is sandboxed by the principle the
//! whole subsystem turns on: Rhai has no I/O of its own, so a script reaches
//! nothing but the host functions this backend registers, and those are exactly
//! the [capability](Capabilities) verbs the grant permits. A `passive` grant
//! registers none, so a passive module cannot reach the network, not because a
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
//!
//! The one part of that a caller could break is re-entry, since `Capabilities`
//! is implementable outside this crate. [`ActiveRun`] refuses a second run on a
//! thread already serving one, so the soundness argument does not rest on an
//! implementation nobody here wrote keeping a rule.

use std::cell::{Cell, RefCell};
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::Instant;

use ::rhai::{
    AST, Array, Blob, Dynamic, Engine, EvalAltResult, ImmutableString, Map, NativeCallContext,
    Position, Scope,
};

use crate::fingerprint::PortContext;
use crate::model::confidence::Confidence;
use crate::model::finding::{Excerpt, Finding, Reference};
use crate::record::wire;

use super::budget::{BudgetTrap, Denial, ModuleFault, RunOutcome};
use super::capability::{CapError, Capabilities, Capability, Grant};
use super::runtime::{ComputeRuntime, LoadError, ModuleBody};

/// The deepest a module's function calls may nest at run, a guard against
/// unbounded recursion independent of the work budget.
const MAX_CALL_LEVELS: usize = 32;

/// How many operations pass between wall-clock deadline checks in the engine's
/// progress callback. Reading the clock every operation would cost more than the
/// work it guards; a few thousand keeps the check off the hot path while still
/// tripping the deadline within a millisecond of expiry.
const PROGRESS_STRIDE: u64 = 8192;

/// The deepest an expression may nest, bounding the parser's own recursion so a
/// pathologically nested module cannot overflow the stack at compile. A real
/// detection nests only a few deep, so this is kept near [`MAX_CALL_LEVELS`]: the
/// bound has to trip before the parser's own recursion exhausts a worker thread's
/// stack, and a bound set for headroom rather than for stack safety overflows a
/// smaller stack before it fires. The same bound applies to a function body and to
/// an expression outside one.
const MAX_PARSE_DEPTH: usize = 64;

thread_local! {
    /// The capabilities the currently-running module is served, as a raw pointer
    /// set by [`ActiveRun`] for the span of one [`run`](RhaiRuntime::run).
    static ACTIVE_CAPS: Cell<Option<NonNull<dyn Capabilities>>> = const { Cell::new(None) };
    /// The abnormal outcome a capability recorded when it ended the run, a budget
    /// or policy refusal the guest cannot catch. Read once the guest returns.
    static ABORT: RefCell<Option<RunOutcome>> = const { RefCell::new(None) };
    /// When the running module's wall-clock budget expires, read by the engine's
    /// progress callback so a run that never speaks is still bounded in time.
    static RUN_DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
}

/// Sets the thread-local capability pointer for the span of one run and restores
/// the previous state when dropped, so a panic in the guest cannot leave a dangling
/// pointer or a stale abort behind.
struct ActiveRun {
    previous_caps: Option<NonNull<dyn Capabilities>>,
    previous_abort: Option<RunOutcome>,
    previous_deadline: Option<Instant>,
}

impl ActiveRun {
    /// Installs `caps` as the active capabilities and `deadline` as the run's
    /// wall-clock ceiling. The pointer must stay valid, its referent unmoved and
    /// untouched by any other path, until this guard is dropped, which the sole
    /// caller ([`run`](RhaiRuntime::run)) guarantees.
    ///
    /// `None` when a run is already active on this thread, which can only happen
    /// if a [`Capabilities`] implementation re-entered the runtime.
    ///
    /// Two things carry the safety here, and it is worth naming both rather than
    /// the refusal alone, because the refusal is the weaker of them.
    ///
    /// **`ACTIVE_CAPS` is per-thread.** It is a `thread_local!` and not a
    /// static, so a thread the guest spawns cannot reach the pointer this
    /// installed — which is what makes the erased lifetime sound across a thread
    /// boundary at all. That matters because [`Capabilities`] is `Send`, so a
    /// reader who checks will find that the borrow *could* travel; what stops it
    /// being observed elsewhere is this and nothing else.
    ///
    /// **A second `&mut` to one capability set cannot exist in safe code.**
    /// [`run`](RhaiRuntime::run) takes a borrow, so aliasing needs the same value
    /// borrowed twice, which the borrow checker refuses. A re-entrant call
    /// carrying a *different* set would not alias anything — it would shadow the
    /// thread-local, and [`Drop`] would put it back.
    ///
    /// So the refusal below is defence in depth against an implementation that
    /// reaches for `unsafe` to do what safe code cannot, rather than the thing
    /// that makes the ordinary case sound. `Capabilities` is implementable
    /// outside this crate, which is why it is worth having.
    fn new(caps: *mut dyn Capabilities, deadline: Instant) -> Option<Self> {
        if ACTIVE_CAPS.with(|cell| cell.get().is_some()) {
            return None;
        }

        let previous_caps = ACTIVE_CAPS.with(|cell| cell.replace(NonNull::new(caps)));
        let previous_abort = ABORT.with(|cell| cell.borrow_mut().take());
        let previous_deadline = RUN_DEADLINE.with(|cell| cell.replace(Some(deadline)));
        Some(Self {
            previous_caps,
            previous_abort,
            previous_deadline,
        })
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
        RUN_DEADLINE.with(|cell| cell.set(self.previous_deadline));
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
    /// capability calls, those are late-bound at run, so this needs none of them
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
        // Harden the compiler too: this is where `eval` is refused, at load, before
        // any port is touched. The other two are function shadows the run engine
        // needs; here they are inert but harmless.
        harden(&mut compiler);
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

        // The work and allocation bounds. The byte and connection budgets are
        // enforced inside the capabilities that serve the I/O; the wall-clock
        // deadline is enforced here, by the progress callback below, so a run doing
        // work but never speaking is bounded in time all the same.
        engine.set_max_operations(grant.budget.fuel);
        engine.set_max_string_size(grant.budget.max_memory);
        engine.set_max_array_size(grant.budget.max_memory);
        engine.set_max_map_size(grant.budget.max_memory);
        engine.set_max_call_levels(MAX_CALL_LEVELS);

        // Refuse the stock symbols again on the engine that runs the code, so the
        // containment does not rest on the compiler alone.
        harden(&mut engine);

        // The wall-clock deadline, enforced independently of the I/O seam. Rhai
        // calls this between operations, so a run that does work but never speaks,
        // a passive module, still stops when its time is spent, where a deadline
        // read only inside `speak` never would. A run past its deadline is
        // terminated, which `classify` reads back as `BudgetTrap::Deadline`.
        engine.on_progress(|operations| {
            if operations % PROGRESS_STRIDE == 0
                && RUN_DEADLINE
                    .with(|cell| cell.get())
                    .is_some_and(|deadline| Instant::now() >= deadline)
            {
                Some(Dynamic::UNIT)
            } else {
                None
            }
        });

        // The pure helpers, always available and never a capability: they touch
        // nothing outside the values handed to them, so registering them for every
        // grant leaves safety, metering and replay exactly where they were.
        register_helpers(&mut engine);

        // The class becomes the served set here: only the granted verbs are
        // registered, so an ungranted one is not refused but absent. `now` is
        // always available, an injected clock touches nothing.
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
        let deadline = Instant::now() + instance.grant.budget.deadline;
        let Some(active) = ActiveRun::new(caps, deadline) else {
            return Err(RunOutcome::HostReentered);
        };

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

/// Registers the pure helper library every module holds, whatever its grant.
///
/// None of these is a capability: each is a total function of its arguments that
/// reaches nothing outside them, so a `passive` module holds them exactly as an
/// `active` one does and none of the four properties the seam guarantees is
/// touched. They are the standard library a detection would otherwise hand-roll,
/// the byte and encoding work that reading a real protocol out of a reply takes.
///
/// - `text(blob) -> string` decodes bytes as Latin-1, so every byte is its own
///   code point and a binary reply is not mangled; `bytes(string) -> blob` is its
///   inverse, for turning a built string back into a probe payload.
/// - `hex_encode`/`hex_decode` and `b64_encode`/`b64_decode` convert between a
///   blob and its Base16 or Base64 text: an SNMP OID to read, a `Basic` header or
///   a JWT segment to decode. Decoding is lenient, a malformed string yields an
///   empty blob rather than a fault, so a module branches on what it got back
///   rather than being killed by a reply it did not choose.
/// - `json(string)` parses a JSON reply into the map, array, and scalar values a
///   module indexes, or unit `()` when the text is not JSON. It runs through the
///   engine's own parser, so the same allocation limits that bound the module
///   bound the parse.
/// - `re_is_match`/`re_find`/`re_capture` run a regular expression over a string:
///   whether it matches, the whole match, or the first capturing group (the whole
///   match when the pattern has no group). The engine is the linear-time
///   [`regex`] crate, not the backtracking matcher the fingerprint corpus uses, so
///   a pattern a module builds from a reply cannot run away past the wall-clock
///   budget the way a catastrophic backtrack would. A pattern that will not
///   compile matches nothing rather than faulting.
fn register_helpers(engine: &mut Engine) {
    engine.register_fn("text", |bytes: Blob| -> String {
        bytes.iter().map(|&byte| byte as char).collect()
    });
    // The inverse of `text`: the low byte of each code point, so a string `text`
    // produced round-trips exactly. A code point past 0xff is truncated to its
    // low byte, which never arises for a string that came from `text` and is the
    // one sensible reading for one a module built to send.
    engine.register_fn("bytes", |string: ImmutableString| -> Blob {
        string.chars().map(|c| c as u8).collect()
    });

    engine.register_fn("hex_encode", |bytes: Blob| -> String {
        data_encoding::HEXLOWER.encode(&bytes)
    });
    engine.register_fn("hex_decode", |string: ImmutableString| -> Blob {
        // Permissive so an upper- or mixed-case digest string decodes; a
        // malformed or odd-length string is not ours to fault over.
        data_encoding::HEXLOWER_PERMISSIVE
            .decode(string.as_bytes())
            .unwrap_or_default()
    });

    engine.register_fn("b64_encode", |bytes: Blob| -> String {
        data_encoding::BASE64.encode(&bytes)
    });
    engine.register_fn("b64_decode", |string: ImmutableString| -> Blob {
        data_encoding::BASE64
            .decode(string.as_bytes())
            .unwrap_or_default()
    });

    // Wrapping the value in a one-field object lets any top-level JSON — object,
    // array, or bare scalar — parse through `parse_json`, whose result is
    // otherwise an object alone. The parse runs on the same engine, so the
    // module's allocation limits bound it; malformed text is unit, not a fault.
    engine.register_fn(
        "json",
        |ctx: NativeCallContext, source: ImmutableString| -> Dynamic {
            let wrapped = format!("{{\"_\":{source}}}");
            match ctx.engine().parse_json(&wrapped, false) {
                Ok(mut map) => map.remove("_").unwrap_or(Dynamic::UNIT),
                Err(_) => Dynamic::UNIT,
            }
        },
    );

    engine.register_fn(
        "re_is_match",
        |pattern: ImmutableString, text: ImmutableString| -> bool {
            compile_regex(&pattern).is_some_and(|re| re.is_match(&text))
        },
    );
    engine.register_fn(
        "re_find",
        |pattern: ImmutableString, text: ImmutableString| -> String {
            compile_regex(&pattern)
                .and_then(|re| re.find(&text).map(|m| m.as_str().to_string()))
                .unwrap_or_default()
        },
    );
    engine.register_fn(
        "re_capture",
        |pattern: ImmutableString, text: ImmutableString| -> String {
            let Some(re) = compile_regex(&pattern) else {
                return String::new();
            };
            // The first capturing group if the pattern has one, else the whole
            // match, so a group-less pattern behaves as `re_find`.
            re.captures(&text)
                .and_then(|caps| caps.get(1).or_else(|| caps.get(0)))
                .map_or(String::new(), |m| m.as_str().to_string())
        },
    );

    // `http_response(blob) -> map | ()`. Parses a reply into `status` (int),
    // `reason`, `version`, a `headers` map (names lowercased, a repeated name
    // joined), and a decoded `body`; unit when the bytes are not an HTTP response.
    engine.register_fn("http_response", |raw: Blob| -> Dynamic {
        let Some(response) = super::http::parse_response(&raw) else {
            return Dynamic::UNIT;
        };
        let mut map = Map::new();
        map.insert("version".into(), response.version.into());
        map.insert("status".into(), (i64::from(response.status)).into());
        map.insert("reason".into(), response.reason.into());

        // Fold a repeated header into one value, as RFC 7230 permits, so a lookup
        // returns a string and not an array a module would have to special-case.
        let mut folded: Vec<(String, String)> = Vec::new();
        for (name, value) in response.headers {
            match folded.iter_mut().find(|(existing, _)| *existing == name) {
                Some((_, current)) => {
                    current.push_str(", ");
                    current.push_str(&value);
                }
                None => folded.push((name, value)),
            }
        }
        let mut headers = Map::new();
        for (name, value) in folded {
            headers.insert(name.into(), value.into());
        }
        map.insert("headers".into(), Dynamic::from(headers));

        let body: String = response.body.iter().map(|&byte| byte as char).collect();
        map.insert("body".into(), body.into());
        Dynamic::from(map)
    });

    // `http_request(map) -> blob`. Builds request bytes from `method` (default
    // GET), `path` (default /), `host`, an optional `headers` map, and an optional
    // `body` string or blob, ready to hand to `speak`.
    engine.register_fn("http_request", |spec: Map| -> Blob {
        let string_field = |key: &str, default: &str| -> String {
            spec.get(key)
                .and_then(|value| value.clone().into_string().ok())
                .unwrap_or_else(|| default.to_string())
        };
        let method = string_field("method", "GET");
        let path = string_field("path", "/");
        let host = string_field("host", "");

        let headers: Vec<(String, String)> = spec
            .get("headers")
            .and_then(|value| value.clone().try_cast::<Map>())
            .map(|map| {
                map.into_iter()
                    .map(|(name, value)| {
                        (name.to_string(), value.into_string().unwrap_or_default())
                    })
                    .collect()
            })
            .unwrap_or_default();

        let body: Vec<u8> = match spec.get("body") {
            None => Vec::new(),
            Some(value) => value.clone().try_cast::<Blob>().unwrap_or_else(|| {
                value
                    .clone()
                    .into_string()
                    .map(String::into_bytes)
                    .unwrap_or_default()
            }),
        };

        super::http::build_request(&method, &path, &host, &headers, &body)
    });
}

/// Compiles a guest-supplied pattern under a size ceiling, or [`None`] if it will
/// not compile within it. The ceiling bounds the one cost the linear matcher does
/// not: a pathologically large pattern's compiled program, which is memory rather
/// than the runaway match time a backtracking engine would risk.
fn compile_regex(pattern: &str) -> Option<::regex::Regex> {
    const REGEX_SIZE_LIMIT: usize = 1 << 20;
    ::regex::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
        .ok()
}

/// Removes the stock-engine symbols and the stock resolver the sandbox's
/// contracts cannot survive.
///
/// `Engine::new` ships a standard library the capability model does not account
/// for: `sleep` parks the thread doing no work, so it spends no fuel and, until
/// the deadline callback lands, escaped the wall-clock bound too; `timestamp`
/// reads the real clock, which the injected [`now`](Capabilities::now) exists to
/// keep a module away from so a run replays identically; and `eval` re-parses a
/// string at run, turning response text a module interpolates into executed
/// source. None is a capability verb, so a module loses nothing it was meant to
/// hold.
///
/// `eval` is a keyword, so disabling the symbol refuses a module that names it at
/// compile. `sleep` and `timestamp` are ordinary library functions, which the
/// symbol machinery does not reach, so they are shadowed by registrations that
/// fault: the call is refused rather than served, `sleep` never parks the thread
/// and `timestamp` never reads the wall clock.
///
/// # The module resolver, which is the one that reaches a file
///
/// `Engine::new` also installs `FileModuleResolver` (rhai 1.26.0
/// `engine.rs:294-300`), gated only on `no_module`, `no_std` and wasm, none of
/// which apply here. With it, a module's `import` is resolved against the
/// filesystem, relative to the process's working directory or by absolute path,
/// and the resolved file is compiled and run. That is a module reaching the world
/// by a path the host injected nothing for, which is the one thing the capability
/// argument in [`detect`](crate::detect) says cannot happen.
///
/// It was previously believed the stock resolver was rhai's
/// `DummyModuleResolver`, on the evidence that `import "secrets" as s` failed
/// with `Module not found`. It does, because no `./secrets.rhai` exists, which
/// is what `FileModuleResolver` says about a path it cannot open. A probe
/// naming a file that *does* exist loads and runs it, under a `passive` grant
/// holding no verbs at all. `a_module_cannot_import_a_file_that_exists` is that
/// probe, and it names a real file for exactly this reason: one naming an
/// absent path passes either way and proves nothing.
///
/// So the resolver is replaced rather than configured. `DummyModuleResolver`
/// refuses every import, which is right for a module body: a detection is one
/// self-contained source, and there is nowhere legitimate for it to import
/// *from*.
fn harden(engine: &mut Engine) {
    engine.disable_symbol("eval");
    engine.set_module_resolver(::rhai::module_resolvers::DummyModuleResolver::new());
    engine.register_fn("sleep", |_seconds: i64| -> Result<(), Box<EvalAltResult>> {
        Err(disabled_symbol("sleep"))
    });
    engine.register_fn("sleep", |_seconds: f64| -> Result<(), Box<EvalAltResult>> {
        Err(disabled_symbol("sleep"))
    });
    engine.register_fn("timestamp", || -> Result<Dynamic, Box<EvalAltResult>> {
        Err(disabled_symbol("timestamp"))
    });
}

/// The error a shadowed stock symbol raises when a module calls it.
fn disabled_symbol(name: &str) -> Box<EvalAltResult> {
    Box::new(EvalAltResult::ErrorRuntime(
        format!("`{name}` is not available to a detection module").into(),
        Position::NONE,
    ))
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

/// `now() -> millis`, the injected run-relative tick.
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

/// Records why a run is about to terminate, so the caller can end it with an
/// uncatchable [`terminated`] fault and the real cause is read back afterward.
fn record_abort(outcome: RunOutcome) {
    ABORT.with(|cell| *cell.borrow_mut() = Some(outcome));
}

/// An uncatchable termination, the vehicle for ending a run on a fatal capability
/// error, the recorded [`RunOutcome`] carries the real cause.
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

/// A string value from a Rhai map, or [`None`] if the key is absent or not a string.
fn map_str(map: &Map, key: &str) -> Option<String> {
    map.get(key)
        .and_then(|value| value.clone().into_string().ok())
}

/// An integer value from a Rhai map, or [`None`] if the key is absent or not an int.
fn map_int(map: &Map, key: &str) -> Option<i64> {
    map.get(key).and_then(|value| value.as_int().ok())
}

/// A fault for a module that returned a value the host could not read as a finding.
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
    /// the module did, the offline path that is also the replay path.
    /// The guard that makes the no-re-entry rule hold rather than merely be
    /// written down, and it holds in a release build: the runtime refuses the
    /// second run instead of trusting an implementation it did not write.
    ///
    /// `Capabilities` is implementable outside this crate, so the rule is one
    /// somebody else's code has to keep, and a re-entrant implementation would
    /// put two live `&mut` on one value, the borrow this runtime erases to a
    /// raw pointer for the span of a run.
    ///
    /// Two guards are asked for and no verb is ever called, so no `&mut` is
    /// reconstituted from either pointer and the test is sound even as it stages
    /// the thing the refusal exists to catch. A real re-entry reaches this same
    /// check one frame deeper.
    #[test]
    fn a_second_run_on_one_thread_is_refused_before_it_can_alias() {
        let mut caps = RecordedCaps::new(Vec::new());
        let pointer: *mut dyn Capabilities = &mut caps;
        let deadline = Instant::now() + Duration::from_secs(1);

        let outer = ActiveRun::new(pointer, deadline);
        assert!(outer.is_some(), "the first run installs");
        assert!(
            ActiveRun::new(pointer, deadline).is_none(),
            "a second run on one thread would alias the first's borrow"
        );

        drop(outer);
        assert!(
            ActiveRun::new(pointer, deadline).is_some(),
            "and the refusal lifts once the first run is over"
        );
    }

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
            speaks_http: false,
            detection: crate::config::ServiceDetection::default(),
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
        // Provenance is the grant's, not the module's, a module cannot forge it.
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
    fn the_pure_helpers_encode_and_decode_without_a_grant() {
        // A passive module (no speak, no resolve) still holds the whole helper
        // library. It decodes a Base64 header, re-encodes it as hex, and turns a
        // built string back into bytes, then reports what each step produced. The
        // point is that a module never handed a capability can still do the byte
        // work reading a protocol takes.
        let source = r#"
            fn analyze(ctx, responses) {
                let raw = b64_decode("aGk=");           // "hi"
                let as_hex = hex_encode(raw);            // "6869"
                let round = text(hex_decode(as_hex));    // "hi"
                let built = bytes("AB");                 // blob [0x41, 0x42]
                [ #{
                    severity: "info",
                    summary: as_hex + " " + round + " " + b64_encode(built),
                } ]
            }
        "#;
        let mut caps = RecordedCaps::new(Vec::new());

        let findings =
            run(source, grant(DetectionClass::Passive, false), &mut caps).expect("a clean run");
        assert_eq!(findings.len(), 1);
        // "6869" (hex of "hi"), "hi" (hex→text round trip), "QUI=" (base64 of "AB").
        assert_eq!(findings[0].title(), "6869 hi QUI=");
    }

    #[test]
    fn json_parses_an_object_an_array_and_reports_bad_input_as_unit() {
        // A passive module reads a JSON reply the way a real one does: index an
        // object, index into a nested array, and fall back cleanly when the body
        // is not JSON at all.
        let source = r#"
            fn analyze(ctx, responses) {
                let obj = json("{\"version\":\"7.2.4\",\"tags\":[\"a\",\"b\"]}");
                let arr = json("[10, 20, 30]");
                let bad = json("<html>not json</html>");
                [ #{
                    severity: "info",
                    summary: obj.version + " " + obj.tags[1] + " " + arr[2] + " " + (bad == ()),
                } ]
            }
        "#;
        let mut caps = RecordedCaps::new(Vec::new());

        let findings =
            run(source, grant(DetectionClass::Passive, false), &mut caps).expect("a clean run");
        // version "7.2.4", tags[1] "b", arr[2] 30, and unit for the non-JSON body.
        assert_eq!(findings[0].title(), "7.2.4 b 30 true");
    }

    #[test]
    fn the_regex_helpers_test_find_and_capture() {
        let source = r#"
            fn analyze(ctx, responses) {
                let body = "Server: nginx/1.25.3";
                let ok = re_is_match("nginx", body);
                let whole = re_find("nginx/[0-9.]+", body);
                let ver = re_capture("nginx/([0-9.]+)", body);
                let none = re_capture("apache/([0-9.]+)", body);
                [ #{
                    severity: "info",
                    summary: "" + ok + " " + whole + " " + ver + " '" + none + "'",
                } ]
            }
        "#;
        let mut caps = RecordedCaps::new(Vec::new());

        let findings =
            run(source, grant(DetectionClass::Passive, false), &mut caps).expect("a clean run");
        // matched, the whole match, the captured version, and empty for no match.
        assert_eq!(findings[0].title(), "true nginx/1.25.3 1.25.3 ''");
    }

    #[test]
    fn a_module_builds_a_request_and_reads_a_response_through_the_http_helpers() {
        // The web-detection shape end to end in the sandbox: build a request to
        // the scanned host, speak it, parse the reply, and grade a header. The
        // canned reply stands in for the socket.
        let source = r#"
            fn analyze(ctx, responses) {
                let request = http_request(#{
                    method: "GET",
                    path: "/",
                    host: "" + ctx.port,
                    headers: #{ "User-Agent": "zond" },
                });
                let reply = http_response(speak(request));
                if reply == () { return []; }
                if reply.status == 200 && reply.headers["server"] != () {
                    [ #{
                        severity: "info",
                        summary: "server is " + reply.headers.server + " body " + reply.body,
                    } ]
                } else {
                    []
                }
            }
        "#;
        let reply = b"HTTP/1.1 200 OK\r\nServer: Caddy\r\nContent-Length: 2\r\n\r\nhi".to_vec();
        let mut caps = RecordedCaps::new(vec![Ok(reply)]);

        let findings =
            run(source, grant(DetectionClass::ActiveBenign, true), &mut caps).expect("a clean run");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title(), "server is Caddy body hi");

        // The module sent a well-formed request naming the host and the header.
        let sent = String::from_utf8_lossy(&caps.sent[0]);
        assert!(
            sent.starts_with("GET / HTTP/1.1\r\n"),
            "request line: {sent:?}"
        );
        assert!(
            sent.contains("Host: 6379"),
            "the seeded host reached the wire: {sent:?}"
        );
        assert!(
            sent.contains("User-Agent: zond"),
            "the header reached the wire: {sent:?}"
        );
    }

    #[test]
    fn an_uncompilable_pattern_matches_nothing_rather_than_faulting() {
        // A pattern a module builds from a reply may be malformed; that must read
        // as no match, not kill the run.
        let source = r#"
            fn analyze(ctx, responses) {
                let broken = re_is_match("(unclosed", "anything");
                [ #{ severity: "info", summary: "" + broken } ]
            }
        "#;
        let mut caps = RecordedCaps::new(Vec::new());

        let findings =
            run(source, grant(DetectionClass::Passive, false), &mut caps).expect("a clean run");
        assert_eq!(findings[0].title(), "false");
    }

    #[test]
    fn a_malformed_decode_is_an_empty_blob_not_a_fault() {
        // A reply a module did not choose must not be able to kill it: a string
        // that is not valid Base64 decodes to nothing, and the module reads the
        // empty length rather than trapping.
        let source = r#"
            fn analyze(ctx, responses) {
                let decoded = b64_decode("not valid base64!!");
                [ #{ severity: "info", summary: "len " + decoded.len() } ]
            }
        "#;
        let mut caps = RecordedCaps::new(Vec::new());

        let findings =
            run(source, grant(DetectionClass::Passive, false), &mut caps).expect("a clean run");
        assert_eq!(findings[0].title(), "len 0");
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
        // is not refused but unnameable, and no byte reaches the capabilities.
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

    #[test]
    fn eval_is_refused_at_load() {
        // `eval` re-parses text at run, which is how attacker-controlled response
        // bytes a module interpolates could become executed source. It is a
        // keyword, so a module naming it is refused at compile, before any port.
        let runtime = RhaiRuntime::new();
        let source = "fn analyze(ctx, responses) { let x = eval(\"1\"); [] }".to_string();
        assert!(
            matches!(
                runtime.load(&ModuleBody::Rhai(source)),
                Err(LoadError::Compile(_))
            ),
            "a module naming `eval` was not refused at load"
        );
    }

    /// The probe that names a file which **exists**.
    ///
    /// An import of an absent path fails whichever resolver is installed, so a
    /// test written that way passes against `FileModuleResolver` and proves
    /// nothing, which is how the stock resolver was read as inert for as long
    /// as it was. This one writes a module to disk first and imports it by
    /// absolute path, so the only thing that can refuse it is the resolver
    /// [`harden`] installs.
    ///
    /// The grant is `passive` with no verbs: the class whose whole security
    /// property is that the network verb is absent rather than refused. It read
    /// and ran a file anyway, before this was fixed.
    #[test]
    fn a_module_cannot_import_a_file_that_exists() {
        let dir = std::env::temp_dir().join(format!("zond-rhai-import-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let smuggled = dir.join("smuggled.rhai");
        std::fs::write(&smuggled, "fn smuggled_value() { 4242 }\n").expect("a module on disk");

        // Without the extension: `FileModuleResolver` appends its own, and this is
        // the spelling a module would use.
        let path = dir.join("smuggled").to_string_lossy().replace('\\', "/");
        let source = format!(
            r#"
            import "{path}" as m;
            fn analyze(ctx, responses) {{
                [ #{{ severity: "high", summary: "value " + m::smuggled_value(),
                      confidence: "probable" }} ]
            }}
        "#
        );

        let mut caps = RecordedCaps::new(Vec::new());
        let outcome = run(&source, grant(DetectionClass::Passive, false), &mut caps);
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            matches!(outcome, Err(RunOutcome::Faulted(ModuleFault::Runtime(_)))),
            "a module imported a file that exists on disk: {outcome:?}"
        );
    }

    #[test]
    fn sleep_and_timestamp_fault_rather_than_parking_or_reading_the_clock() {
        // `sleep` would park the worker unmetered and `timestamp` would read the
        // real wall clock and break replay. Both are shadowed to fault, so a module
        // that calls one is refused the call rather than served it.
        for call in ["sleep(1);", "sleep(1.5);", "let t = timestamp();"] {
            let source = format!("fn analyze(ctx, responses) {{ {call} [] }}");
            let mut caps = RecordedCaps::new(Vec::new());
            let outcome = run(&source, grant(DetectionClass::Passive, false), &mut caps);
            assert!(
                matches!(outcome, Err(RunOutcome::Faulted(ModuleFault::Runtime(_)))),
                "`{call}` was not faulted: {outcome:?}"
            );
        }
    }

    #[test]
    fn a_passive_module_that_runs_without_end_is_bounded_by_its_wall_clock() {
        // A passive grant registers no `speak`, so a deadline read only inside the
        // I/O seam would never be consulted. The progress callback consults it
        // regardless, so a passive module doing endless work still stops in time.
        let source = r#"
            fn analyze(ctx, responses) {
                let n = 0;
                loop { n += 1; }
                []
            }
        "#;
        let mut grant = grant(DetectionClass::Passive, false);
        grant.budget.fuel = u64::MAX; // take fuel out of the picture; the clock must bind
        grant.budget.deadline = Duration::from_millis(50);

        let started = std::time::Instant::now();
        let mut caps = RecordedCaps::new(Vec::new());
        let outcome = run(source, grant, &mut caps);

        assert_eq!(
            outcome,
            Err(RunOutcome::BudgetExceeded(BudgetTrap::Deadline)),
            "a passive run past its deadline was not trapped as a deadline"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the deadline did not stop the run promptly: {:?}",
            started.elapsed()
        );
    }

    /// A run installed on one thread is not reachable from another.
    ///
    /// The property the erased lifetime rests on across a thread boundary, and
    /// the one the SAFETY note used to leave implicit: `Capabilities` is `Send`,
    /// so the borrow *could* travel, and what stops the pointer being observed
    /// elsewhere is that `ACTIVE_CAPS` is a `thread_local!` rather than a
    /// static. A spawned thread sees no run, and installs its own without being
    /// refused — correctly, since it had to produce its own borrow to get here.
    #[test]
    fn a_run_is_not_reachable_from_another_thread() {
        let mut caps = RecordedCaps::new(Vec::new());
        let pointer: *mut dyn Capabilities = &mut caps;
        let deadline = Instant::now() + Duration::from_secs(1);

        let guard = ActiveRun::new(pointer, deadline).expect("the first run installs");

        assert!(
            !std::thread::spawn(|| ACTIVE_CAPS.with(|cell| cell.get().is_some()))
                .join()
                .expect("the thread ran"),
            "another thread could see this run's capabilities"
        );

        assert!(
            std::thread::spawn(|| {
                let mut other = RecordedCaps::new(Vec::new());
                let other_pointer: *mut dyn Capabilities = &mut other;
                ActiveRun::new(other_pointer, Instant::now() + Duration::from_secs(1)).is_some()
            })
            .join()
            .expect("the thread ran"),
            "a thread with its own borrow must not be refused"
        );

        drop(guard);
    }

    /// A guest that panics leaves nothing installed.
    ///
    /// `ActiveRun::drop` runs during unwind, and all three thread-locals have to
    /// come back with it: a stale pointer would be read by the next run on this
    /// thread, and a stale abort or deadline would be attributed to it.
    #[test]
    fn a_panicking_run_restores_every_thread_local() {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut caps = RecordedCaps::new(Vec::new());
            let pointer: *mut dyn Capabilities = &mut caps;
            let _guard =
                ActiveRun::new(pointer, Instant::now() + Duration::from_secs(1)).expect("installs");
            ABORT.with(|cell| *cell.borrow_mut() = Some(RunOutcome::HostReentered));
            panic!("the guest exploded");
        }));

        assert!(
            outcome.is_err(),
            "the panic has to reach here to prove anything"
        );
        assert!(ACTIVE_CAPS.with(|cell| cell.get().is_none()));
        assert!(ABORT.with(|cell| cell.borrow().is_none()));
        assert!(RUN_DEADLINE.with(|cell| cell.get().is_none()));
    }
}
