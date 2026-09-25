// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Fingerprint database compiler
//!
//! Compiles the human-authored TOML signatures in `assets/fingerprinting/` into
//! the `bincode` blob the engine embeds and loads at runtime.
//!
//! Every signature is **validated here, at build time**. A pattern the engine
//! cannot compile, or a `version_group` that points at a capture group the
//! pattern does not have, fails the build with a pointer to the offending file —
//! rather than being silently dropped and shipped as an invisible coverage gap.
//! Softer issues (a service with no ports, an unknown probe protocol) surface as
//! build warnings.
//!
//! The authoring schema is not redefined here: it is `include!`d from the
//! canonical definitions in `src/fingerprint/signature.rs`, so the build-time
//! and runtime views can never drift apart.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// The service-signature authoring schema, shared verbatim with the runtime.
///
/// Loaded via `#[path]` rather than `include!`, for the reason [`pattern`] gives
/// below and for one more: `include!` splices a file into an anonymous position,
/// and tooling that reads this crate without compiling it cannot always follow a
/// derive macro through the splice — so `Serialize` and `Deserialize` appear
/// unimplemented in an editor while `cargo` compiles it perfectly. A `#[path]`
/// module is an ordinary module and analyses like one.
#[path = "src/fingerprint/signature.rs"]
mod signature;

/// The operating-system rule schema, likewise shared verbatim. A rule the build
/// accepts is exactly a rule the runtime can match, because both read this file.
#[path = "src/fingerprint/os/signature.rs"]
mod os_schema;

/// The register of fields a signature may be written against, and whether
/// anything produces each one. Shared the same way, so the build cannot classify
/// a context differently from the engine that reads it.
///
/// The build reads a `Reach` and the library also reads the `note` beside it, so
/// the unread half is dead only here.
#[allow(dead_code)]
#[path = "src/fingerprint/context.rs"]
mod context;

/// The pattern-compilation logic, shared verbatim with the runtime so the build
/// accepts *exactly* the patterns the engine can match — including the
/// backref/lookaround patterns that fall back to the bounded fancy engine. If it
/// compiles here, the runtime can compile it; if it fails here, it never ships.
///
/// Loaded via `#[path]` (rather than `include!`) so the file's own module docs
/// are honoured — `include!` forbids the inner `//!` comments it carries.
#[path = "src/fingerprint/pattern.rs"]
mod pattern;

/// The shared `[detection]` manifest and the Tier-1 flow trio that reads it: the
/// authoring `schema`, the guard-expression grammar `expr`, and the structural
/// `validate` that rejects a malformed flow. A flow the build accepts is a flow
/// the interpreter can run, because both read these files. `schema` and `validate`
/// name their siblings — `manifest`, each other, and `expr` — as `super::…`, which
/// resolves here because every shared file is a crate-root sibling, and in the
/// library because a re-export puts `manifest` beside them. It is also why the
/// service schema above is `signature`: the two must not both be `schema`.
#[path = "src/detect/authoring.rs"]
mod authoring;
/// The Tier-2 compute-detection schema, shared the same way: the build reads a
/// `[compute]` file to validate its structure and resolve a body reference before
/// embedding. It names the shared manifest as `super::manifest`, which resolves
/// here as a crate-root sibling.
#[path = "src/detect/compute/schema.rs"]
mod compute_schema;
#[path = "src/detect/flow/expr.rs"]
mod expr;
#[path = "src/detect/host/schema.rs"]
mod host_schema;
#[path = "src/detect/manifest.rs"]
mod manifest;
#[path = "src/detect/flow/schema.rs"]
mod schema;
#[path = "src/detect/flow/validate.rs"]
mod validate;

use signature::{MAX_COMPILED_REGEX_BYTES, MAX_UDP_PROBE_BYTES, ServiceDefinition, unescape};

fn main() {
    println!("cargo:rerun-if-changed=assets/fingerprinting");
    println!("cargo:rerun-if-changed=src/fingerprint/signature.rs");
    println!("cargo:rerun-if-changed=src/fingerprint/os/signature.rs");
    println!("cargo:rerun-if-changed=assets/detect");
    println!("cargo:rerun-if-changed=src/detect/manifest.rs");
    println!("cargo:rerun-if-changed=src/detect/authoring.rs");
    println!("cargo:rerun-if-changed=src/detect/flow/schema.rs");
    println!("cargo:rerun-if-changed=src/detect/flow/expr.rs");
    println!("cargo:rerun-if-changed=src/detect/flow/validate.rs");
    println!("cargo:rerun-if-changed=src/detect/compute/schema.rs");
    println!("cargo:rerun-if-changed=src/detect/host/schema.rs");
    println!("cargo:rerun-if-changed=src/fingerprint/pattern.rs");

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo");
    let dest_path = Path::new(&out_dir).join("fingerprints.bin");

    let mut toml_files = Vec::new();
    // `os` holds the operating-system rules, which are a different schema
    // entirely; see `collect_toml_files_except`.
    collect_toml_files_except(Path::new("assets/fingerprinting"), &["os"], &mut toml_files);
    // Sort for a deterministic, reproducible artifact: the order here decides
    // which definition wins a shared port in the runtime name index.
    toml_files.sort();

    let mut services = Vec::with_capacity(toml_files.len());
    let mut rule_ids = BTreeSet::new();
    for path in &toml_files {
        let content = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        let def: ServiceDefinition = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()));
        validate(&def, path);
        claim_rule_ids(&def, path, &mut rule_ids);
        services.push(def);
    }

    census_contexts(&services, &toml_files);
    warn_contested_ports(&services, &toml_files);

    let encoded = bincode::serialize(&services).expect("failed to serialize fingerprint database");
    fs::write(&dest_path, encoded).expect("failed to write fingerprint database");

    compile_cve_catalogue(Path::new(&out_dir));

    compile_os_rules(Path::new(&out_dir));
    compile_detections(
        Path::new(&out_dir),
        &corpus_service_names(&services),
        &corpus_protocols(&services),
    );
}

/// Every service name the fingerprint corpus can put on a port.
///
/// A `[service]` name is what a match rule owned by that file reports, and what
/// the runtime's port-to-name index is built from, so this is the whole
/// vocabulary the corpus contributes to a detection gate.
fn corpus_service_names(defs: &[ServiceDefinition]) -> BTreeSet<String> {
    defs.iter().map(|def| def.service.name.clone()).collect()
}

/// Every application protocol the corpus declares a service is carried over.
///
/// Unlike a service name, this vocabulary has exactly one source: nothing in
/// Rust mints one and a tunnel does not rename one, so a gate naming a protocol
/// absent from here can be refused rather than merely reported.
fn corpus_protocols(defs: &[ServiceDefinition]) -> BTreeSet<String> {
    defs.iter()
        .filter_map(|def| def.service.speaks.clone())
        .collect()
}

/// Refuses a gate naming an application protocol no service is carried over.
///
/// A refusal where [`warn_unknown_gate_services`] only warns, and the difference
/// is what each can be sure of. A service name can be minted in Rust, so that
/// check reads a list kept by hand and reports rather than decides. A protocol
/// comes from `[service].speaks` and nowhere else, so a gate naming one the
/// corpus does not is unambiguously a gate that fits no port.
fn refuse_unknown_gate_protocol(
    path: &Path,
    id: &str,
    when: &manifest::Rule,
    known: &BTreeSet<String>,
) {
    let Some(protocol) = when.speaks.as_deref() else {
        return;
    };
    if known.contains(protocol) {
        return;
    }
    panic!(
        "{}: '{id}' gates on speaks = '{protocol}', which no [service] in \
         assets/fingerprinting is carried over; the detection can never fit a port",
        path.display()
    );
}

/// Service names the fingerprint analyzers state outright rather than drawing
/// from the corpus: `src/fingerprint/http.rs` says `http`,
/// `src/fingerprint/ssh.rs` says `ssh`, and `src/fingerprint/tls_cert.rs` says
/// `ssl`. The first two are corpus names as well; `ssl` is not.
const ANALYZER_SERVICE_NAMES: &[&str] = &["http", "ssh", "ssl"];

/// The scheme a service identified through a tunnel is labelled with, as
/// `ServiceVerdict::to_service` writes it. A port speaking HTTP inside TLS is
/// named `ssl/http`, so a gate may reasonably name one.
const TUNNEL_PREFIX: &str = "ssl/";

/// Warns about a gate naming a service nothing this engine runs can produce.
///
/// Such a gate fits no port, ever. The detection is in the binary and in the
/// corpus listing and never runs, and nothing says so without a check here: a
/// detection that never matches looks exactly like a detection whose condition
/// was never met.
///
/// A warning rather than a refusal, because the corpus is not the only place a
/// service name is minted. Three analyzers state one in Rust, and a tunnelled
/// service is labelled with its scheme rather than by the corpus. Both are
/// accounted for below, but by a list kept here rather than derived from those
/// files, so a fourth name added there would make a refusal here reject a valid
/// detection. This reports what it is sure of and leaves the build to the
/// author.
fn warn_unknown_gate_services<'a>(
    path: &Path,
    id: &str,
    gated: impl Iterator<Item = &'a str>,
    known: &BTreeSet<String>,
) {
    let file = path.display();
    for name in gated {
        let bare = name.strip_prefix(TUNNEL_PREFIX).unwrap_or(name);
        if known.contains(bare) || ANALYZER_SERVICE_NAMES.contains(&bare) {
            continue;
        }
        println!(
            "cargo:warning={file}: '{id}' gates on service '{name}', which no \
             fingerprint in assets/fingerprinting names; the detection can never \
             fit a port"
        );
    }
}

/// Refuses a gate whose singular and plural fields share no value.
///
/// `port` and `ports` AND, as do `service` and `services`, so naming a number in
/// one and a disjoint set in the other is a gate that fits no port, ever, the same
/// dead detection [`warn_unknown_gate_services`] guards against by another route.
fn refuse_contradictory_gate(path: &Path, id: &str, when: &manifest::Rule) {
    if let Some(port) = when.port
        && !when.ports.is_empty()
        && !when.ports.contains(&port)
    {
        panic!(
            "{}: '{id}' gates on port = {port} and ports = {:?}, which share no value; \
             the detection can never fit a port",
            path.display(),
            when.ports
        );
    }
    if let Some(service) = &when.service
        && !when.services.is_empty()
        && !when.services.contains(service)
    {
        panic!(
            "{}: '{id}' gates on service = '{service}' and services = {:?}, which share no \
             value; the detection can never fit a port",
            path.display(),
            when.services
        );
    }
}

/// The service names a `[detection.when]` gate gives, both spellings together.
fn gated_services(when: &manifest::Rule) -> impl Iterator<Item = &str> {
    when.service
        .as_deref()
        .into_iter()
        .chain(when.services.iter().map(String::as_str))
}

/// Validates the detection corpus in `assets/detect` and compiles each tier into
/// the `bincode` blob the engine embeds, failing the build on any ill-formed
/// detection with a pointer to its file. A file's body section decides its tier:
/// `[[step]]` is a Tier-1 [flow](compile_flow), `[compute]` a Tier-2
/// [module](compile_module).
///
/// What is emitted for a flow is its **source and content hash**, the same text
/// the runtime re-parses — embedding the parsed form would demand a `bincode`
/// spelling of the `untagged` match rule, which the format cannot round-trip. For
/// a module, its manifest and body **normalised to the inline form**, with the
/// hash taken over the body: a module has no `untagged` rule, so it is embedded as
/// text with any file reference resolved away, and the hash is the provenance a
/// finding records.
fn compile_detections(
    out_dir: &Path,
    known_services: &BTreeSet<String>,
    known_protocols: &BTreeSet<String>,
) {
    let mut toml_files = Vec::new();
    collect_toml_files(Path::new("assets/detect"), &mut toml_files);
    // Sort for a deterministic, reproducible artifact.
    toml_files.sort();

    // An id is a provenance claim and must be unique across the whole corpus, both
    // tiers together: two findings that named one id could not be told apart.
    let mut ids = BTreeSet::new();
    let mut flows: Vec<(String, String)> = Vec::new();
    let mut modules: Vec<(String, String)> = Vec::new();
    let mut hosts: Vec<(String, String)> = Vec::new();
    for path in &toml_files {
        let content = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        let value: toml::Value = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()));

        if value.get("detection").and_then(|d| d.get("host")).is_some() {
            compile_host(path, &content, &mut ids, &mut hosts, known_services);
        } else if value.get("compute").is_some() {
            compile_module(
                path,
                &content,
                &mut ids,
                &mut modules,
                known_services,
                known_protocols,
            );
        } else {
            compile_flow(
                path,
                &content,
                &mut ids,
                &mut flows,
                known_services,
                known_protocols,
            );
        }
    }

    write_database(&out_dir.join("detect_flows.bin"), &flows, "flow");
    write_database(&out_dir.join("detect_modules.bin"), &modules, "module");
    write_database(&out_dir.join("detect_host.bin"), &hosts, "host");
}

/// Validates one Tier-1 flow through the shared [`validate`] plus the rules that
/// need the pattern engine, and appends its source and content hash.
fn compile_flow(
    path: &Path,
    content: &str,
    ids: &mut BTreeSet<String>,
    flows: &mut Vec<(String, String)>,
    known_services: &BTreeSet<String>,
    known_protocols: &BTreeSet<String>,
) {
    let flow: schema::FlowDetection = toml::from_str(content)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()));

    let errors = validate::check(&flow);
    if !errors.is_empty() {
        let mut message = format!("{}: this flow detection is ill-formed:", path.display());
        for error in &errors {
            message.push_str(&format!("\n  - the detection {error}"));
        }
        panic!("{message}");
    }
    claim_id(ids, &flow.detection.id, path);

    validate_flow_patterns(&flow, path);
    validate_flow_budget(&flow, path);
    warn_flow_soft(&flow, path);
    warn_unknown_gate_services(
        path,
        &flow.detection.id,
        gated_services(&flow.detection.when),
        known_services,
    );
    refuse_unknown_gate_protocol(
        path,
        &flow.detection.id,
        &flow.detection.when,
        known_protocols,
    );
    refuse_contradictory_gate(path, &flow.detection.id, &flow.detection.when);

    flows.push((sha256_hex(content.as_bytes()), content.to_string()));
}

/// Validates one Tier-2 module, resolves its body to inline source, and appends
/// the normalised detection with the content hash of that source.
fn compile_module(
    path: &Path,
    content: &str,
    ids: &mut BTreeSet<String>,
    modules: &mut Vec<(String, String)>,
    known_services: &BTreeSet<String>,
    known_protocols: &BTreeSet<String>,
) {
    let detection: compute_schema::ComputeDetection = toml::from_str(content)
        .unwrap_or_else(|e| panic!("{}: not a valid compute detection: {e}", path.display()));

    validate_module(&detection, path);
    claim_id(ids, &detection.detection.id, path);
    warn_unknown_gate_services(
        path,
        &detection.detection.id,
        gated_services(&detection.detection.when),
        known_services,
    );
    refuse_unknown_gate_protocol(
        path,
        &detection.detection.id,
        &detection.detection.when,
        known_protocols,
    );
    refuse_contradictory_gate(path, &detection.detection.id, &detection.detection.when);

    let source = resolve_module_source(&detection.compute, path);

    // Normalise to the inline form so the runtime never sees a file reference; the
    // toml serializer escapes the source, so there is no hand-rolled quoting to
    // get wrong.
    let mut value: toml::Value = toml::from_str(content)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()));
    let compute = value
        .get_mut("compute")
        .and_then(toml::Value::as_table_mut)
        .expect("the compute section is a table");
    compute.insert("source".to_string(), toml::Value::String(source.clone()));
    compute.remove("body");

    let normalised = toml::to_string(&value)
        .unwrap_or_else(|e| panic!("failed to re-serialize {}: {e}", path.display()));
    modules.push((sha256_hex(source.as_bytes()), normalised));
}

/// Records a detection id, failing the build if the corpus already used it.
fn claim_id(ids: &mut BTreeSet<String>, id: &str, path: &Path) {
    if !ids.insert(id.to_string()) {
        panic!(
            "{}: detection id '{id}' is already used by another detection",
            path.display()
        );
    }
}

/// The structural rules a compute detection must satisfy before it ships: a
/// non-empty, non-reserved id, a parseable version, and exactly one of an inline
/// `source` or a `body` file. The body's code is compiled at load, not here — that
/// is the tier's contract — so what the build proves is the shape, not the logic.
fn validate_module(detection: &compute_schema::ComputeDetection, path: &Path) {
    let file = path.display();
    let manifest = &detection.detection;
    if manifest.id.trim().is_empty() {
        panic!("{file}: a detection needs a non-empty id");
    }
    if manifest.id.starts_with(validate::RESERVED_ID_PREFIX) {
        panic!(
            "{file}: '{}' claims the reserved 'zond:' id namespace",
            manifest.id
        );
    }
    if !validate::is_version_triple(&manifest.version) {
        panic!(
            "{file}: '{}' has version '{}', which is not major.minor.patch",
            manifest.id, manifest.version
        );
    }
    if manifest.title.trim().is_empty() {
        panic!("{file}: '{}' has an empty title", manifest.id);
    }
    match (&detection.compute.source, &detection.compute.body) {
        (Some(_), Some(_)) => panic!(
            "{file}: '{}' sets both an inline source and a body file; use exactly one",
            manifest.id
        ),
        (None, None) => panic!(
            "{file}: '{}' sets neither an inline source nor a body file",
            manifest.id
        ),
        _ => {}
    }
}

/// The inline source of a module, reading its `body` file when it names one,
/// resolved beside the manifest so a detection is one directory entry plus, at
/// most, its body.
fn resolve_module_source(compute: &compute_schema::ComputeSection, path: &Path) -> String {
    if let Some(source) = &compute.source {
        return source.clone();
    }
    let body = compute
        .body
        .as_deref()
        .expect("a module validated to have a source or a body");
    let body_path = path.parent().unwrap_or_else(|| Path::new(".")).join(body);
    fs::read_to_string(&body_path).unwrap_or_else(|e| {
        panic!(
            "{}: cannot read its body file {}: {e}",
            path.display(),
            body_path.display()
        )
    })
}

/// Validates one host-level detection and appends its source and content hash. A
/// host detection is embedded as text, like a flow, and re-parsed at runtime.
fn compile_host(
    path: &Path,
    content: &str,
    ids: &mut BTreeSet<String>,
    hosts: &mut Vec<(String, String)>,
    known_services: &BTreeSet<String>,
) {
    let detection: host_schema::HostDetection = toml::from_str(content)
        .unwrap_or_else(|e| panic!("{}: not a valid host detection: {e}", path.display()));

    validate_host(&detection, path);
    claim_id(ids, &detection.detection.id, path);
    warn_unknown_gate_services(
        path,
        &detection.detection.id,
        detection.detection.host.services.iter().map(String::as_str),
        known_services,
    );

    hosts.push((sha256_hex(content.as_bytes()), content.to_string()));
}

/// The rules a host detection must satisfy before it ships: a non-empty,
/// non-reserved id, a parseable version, a gate that names at least one port or
/// service, and at least one finding. An empty gate would fire on every host and a
/// detection that draws no finding can conclude nothing, so both fail the build.
fn validate_host(detection: &host_schema::HostDetection, path: &Path) {
    let file = path.display();
    let manifest = &detection.detection;
    if manifest.id.trim().is_empty() {
        panic!("{file}: a detection needs a non-empty id");
    }
    if manifest.id.starts_with(validate::RESERVED_ID_PREFIX) {
        panic!(
            "{file}: '{}' claims the reserved 'zond:' id namespace",
            manifest.id
        );
    }
    if !validate::is_version_triple(&manifest.version) {
        panic!(
            "{file}: '{}' has version '{}', which is not major.minor.patch",
            manifest.id, manifest.version
        );
    }
    if manifest.title.trim().is_empty() {
        panic!("{file}: '{}' has an empty title", manifest.id);
    }
    if manifest.host.ports_open.is_empty() && manifest.host.services.is_empty() {
        panic!(
            "{file}: '{}' has an empty host gate, which would fire on every host",
            manifest.id
        );
    }
    if detection.finding.is_empty() {
        panic!(
            "{file}: '{}' draws no finding, so it can conclude nothing",
            manifest.id
        );
    }
}

/// Serialises `entries` to `bincode` and writes them to `dest`.
fn write_database(dest: &Path, entries: &[(String, String)], kind: &str) {
    let encoded = bincode::serialize(entries)
        .unwrap_or_else(|e| panic!("failed to serialize the {kind} database: {e}"));
    fs::write(dest, encoded).unwrap_or_else(|e| panic!("failed to write the {kind} database: {e}"));
}

/// The lowercase hex SHA-256 of `bytes` — a detection body's content address, the
/// same digest the certificate fingerprints use.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// H4/H5 — every `expect`/`bind` pattern compiles under the size cap with the
/// engine the runtime uses, and every `bind` can actually capture: its pattern
/// has a named group of the bound variable, or a numeric `version_group` that
/// exists. A bind that can capture nothing is a silent hole, so it fails here.
fn validate_flow_patterns(flow: &schema::FlowDetection, path: &Path) {
    let file = path.display();
    let id = &flow.detection.id;
    for (index, step) in flow.step.iter().enumerate() {
        for spec in &step.expect {
            compile_flow_pattern(
                spec.pattern(),
                format_args!("{file}: '{id}' step {index} expect"),
            );
        }
        for (var, spec) in &step.bind {
            let compiled = compile_flow_pattern(
                spec.pattern(),
                format_args!("{file}: '{id}' step {index} bind '{var}'"),
            );
            let named = compiled.capture_names().iter().any(|name| name == var);
            let numbered = spec
                .version_group()
                .is_some_and(|group| (group as usize) < compiled.captures_len());
            if !named && !numbered {
                panic!(
                    "{file}: '{id}' step {index} binds '{var}', but its pattern has no \
                     (?<{var}>…) group and no valid version_group, so it can never capture\n  \
                     pattern: {}",
                    spec.pattern()
                );
            }
        }
    }
}

/// Compiles a flow pattern the way the runtime will, aborting the build with a
/// pointer if it cannot — so a pattern that would fail at scan time never ships.
fn compile_flow_pattern(pattern: &str, context: std::fmt::Arguments) -> pattern::CompiledPattern {
    pattern::compile(pattern, MAX_COMPILED_REGEX_BYTES)
        .unwrap_or_else(|e| panic!("{context} has an unusable pattern: {e}\n  pattern: {pattern}"))
}

/// H6 — a declared `max_bytes` covers the payloads the flow must send. The reply
/// bytes a target controls are bounded at the capability boundary at run time,
/// not here; what the build proves is that a flow can at least send what it
/// declares without exceeding the budget it claims.
fn validate_flow_budget(flow: &schema::FlowDetection, path: &Path) {
    let id = &flow.detection.id;

    if let Some(max_bytes) = flow.detection.capabilities.max_bytes {
        let mut sent: u64 = 0;
        for step in &flow.step {
            if let Some(send) = &step.send {
                let bytes = unescape(send).len() as u64;
                sent += bytes * step_iterations(step);
            }
        }
        if sent > u64::from(max_bytes) {
            panic!(
                "{}: '{id}' declares max_bytes = {max_bytes} but its steps send {sent} bytes",
                path.display()
            );
        }
    }

    // One connection per send, times a `for_each`'s item count: a flow that would
    // open more than it declared runs out mid-sweep, halting on a refusal the
    // report records rather than finishing. Caught here so it never ships.
    if let Some(max_connections) = flow.detection.capabilities.max_connections {
        let mut opened: u64 = 0;
        for step in &flow.step {
            if step.send.is_some() {
                opened += step_iterations(step);
            }
        }
        if opened > u64::from(max_connections) {
            panic!(
                "{}: '{id}' declares max_connections = {max_connections} but its steps open {opened}",
                path.display()
            );
        }
    }
}

/// How many times a step's `send` runs: once, or once per `for_each` item.
fn step_iterations(step: &schema::Step) -> u64 {
    step.for_each
        .as_ref()
        .map_or(1, |for_each| for_each.items.len() as u64)
}

/// Soft issues that do not fail the build but an author should see: a malformed
/// CVE identifier that a finding would silently drop.
///
/// A class that ships inert does not warn here. Such a warning says nothing the
/// author has not just written, since `class = "exploit"` is the declaration and
/// the warning would repeat it back, and a build script only ever reads this
/// crate's own reviewed corpus, so the line would survive review and then print
/// on every build of the engine and of anything depending on it. What it would
/// guard is worth guarding, though, so `flow::db`'s
/// `the_corpus_ships_the_classes_it_is_known_to_ship` guards it, failing when a
/// shipped detection changes what it may do rather than mentioning it forever.
fn warn_flow_soft(flow: &schema::FlowDetection, path: &Path) {
    let file = path.display();
    let id = &flow.detection.id;

    for step in &flow.step {
        for finding in &step.finding {
            for reference in &finding.references {
                if let authoring::Reference::Cve(cve) = reference
                    && !is_cve_shaped(cve)
                {
                    println!(
                        "cargo:warning={file}: '{id}' cites a malformed CVE id '{cve}' \
                         (expected CVE-YYYY-N…); the finding will drop it"
                    );
                }
            }
        }
    }
}

/// Whether `id` has the shape `CVE-\d{{4}}-\d+`, checked without a regex.
fn is_cve_shaped(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("CVE-") else {
        return false;
    };
    let mut parts = rest.splitn(2, '-');
    let year = parts.next().unwrap_or("");
    let sequence = parts.next().unwrap_or("");
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && !sequence.is_empty()
        && sequence.bytes().all(|b| b.is_ascii_digit())
}

/// Compiles the operating-system rules the same way, and validates them harder.
///
/// Harder because an OS rule fails differently from a service signature. A
/// pattern that cannot compile is dropped and the coverage gap is at least
/// *absent*; a rule with no predicates matches every host that ever answers and
/// reports them all as one operating system. Silently wrong beats silently
/// missing on nobody's scale, so the empty rule fails the build.
fn compile_os_rules(out_dir: &Path) {
    let mut toml_files = Vec::new();
    collect_toml_files(Path::new("assets/fingerprinting/os"), &mut toml_files);
    toml_files.sort();

    let mut rules = Vec::with_capacity(toml_files.len());
    for path in &toml_files {
        let content = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        let def: os_schema::OsDefinition = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()));
        validate_os_rule(&def, path);
        rules.push(def);
    }

    let encoded = bincode::serialize(&rules).expect("failed to serialize the OS rule database");
    fs::write(out_dir.join("os_rules.bin"), encoded).expect("failed to write the OS rule database");
}

/// Validates one operating-system rule, aborting the build on anything that
/// would make it match the wrong hosts or no hosts at all.
fn validate_os_rule(def: &os_schema::OsDefinition, path: &Path) {
    let file = path.display();
    let family = def.os.label();

    // The fatal half lives in the schema, so a rule this build accepts is
    // exactly a rule `RuleDb::try_from_rules` accepts. Adding a check there
    // tightens both at once; adding one here would tighten only what ships.
    if let Err(defect) = def.validate() {
        panic!("{file}: '{family}' {defect}");
    }

    // The advisory half. Neither of these makes a rule unusable, so neither
    // belongs in the shared check: they are about whether a rule can be
    // maintained, which is a question for whoever is authoring it.
    //
    // Only a rule claiming to have been measured is *missing* something by
    // shipping no example. A published rule has no local observation to record —
    // that is what publishing means — and warning about it would train whoever
    // reads this build to ignore the warning that matters.
    if def.example.is_empty() && def.provenance == os_schema::Provenance::Measured {
        println!(
            "cargo:warning={file}: '{family}' claims to be measured and records no \
             observation, so nothing checks it still matches what it was written for"
        );
    }

    if def.provenance == os_schema::Provenance::Published
        && def.notes.as_deref().unwrap_or("").trim().is_empty()
    {
        println!(
            "cargo:warning={file}: '{family}' is unconfirmed and does not say what its \
             values rest on"
        );
    }
}

/// Validates one service definition, aborting the build on any defect that would
/// silently degrade detection, and warning on softer issues.
/// Compiles `assets/cve/` into the pooled form `cve::Catalogue` loads.
///
/// The documents are TOML because they are reviewed as text and one of them is
/// hand-written, and TOML is the wrong thing to parse at start-up: the shipped
/// catalogue is twenty megabytes and seventy thousand entries, which is a tenth
/// of a second every time a process first correlates.
///
/// So the strings are pooled here and the entries reduced to indices, which is
/// the shape the engine holds them in anyway. Seventeen thousand distinct
/// strings back four hundred thousand field slots, because a feed states one
/// entry per affected version and every one repeats the same title.
///
/// The shape is duplicated rather than shared through `#[path]`, as the context
/// register is: `cve.rs` is a module with half the crate behind it and cannot be
/// spliced into a build script. Drift is caught rather than prevented — every
/// test that reads the embedded catalogue deserializes this blob, and a changed
/// field would fail all of them at once.
fn compile_cve_catalogue(out_dir: &Path) {
    #[derive(serde::Deserialize)]
    struct Document {
        #[serde(default)]
        vulnerability: Vec<DocumentEntry>,
    }

    #[derive(serde::Deserialize)]
    struct DocumentEntry {
        cve: String,
        title: String,
        severity: String,
        vendor: String,
        product: String,
        affected: String,
        #[serde(default)]
        cwe: Option<u32>,
        #[serde(default)]
        remediation: Option<String>,
    }

    #[derive(serde::Serialize)]
    struct Entry {
        cve: u32,
        title: u32,
        severity: u32,
        vendor: u32,
        product: u32,
        affected: u32,
        cwe: Option<u32>,
        remediation: Option<u32>,
    }

    let mut sources: Vec<PathBuf> = fs::read_dir("assets/cve")
        .expect("assets/cve is readable")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("toml"))
        .collect();
    // Sorted for a reproducible artifact: two builds of the same tree must
    // produce the same bytes, and a directory listing is not ordered.
    sources.sort();

    let mut pool: Vec<String> = Vec::new();
    let mut seen: BTreeMap<String, u32> = BTreeMap::new();
    let intern = |value: &str, pool: &mut Vec<String>, seen: &mut BTreeMap<String, u32>| -> u32 {
        if let Some(index) = seen.get(value) {
            return *index;
        }
        let index = pool.len() as u32;
        pool.push(value.to_string());
        seen.insert(value.to_string(), index);
        index
    };

    let mut entries: Vec<Entry> = Vec::new();
    for path in &sources {
        println!("cargo:rerun-if-changed={}", path.display());
        let text = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("{}: unreadable: {e}", path.display()));
        let document: Document = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("{}: not a catalogue: {e}", path.display()));

        for entry in &document.vulnerability {
            entries.push(Entry {
                cve: intern(&entry.cve, &mut pool, &mut seen),
                title: intern(&entry.title, &mut pool, &mut seen),
                severity: intern(&entry.severity, &mut pool, &mut seen),
                vendor: intern(&entry.vendor, &mut pool, &mut seen),
                product: intern(&entry.product, &mut pool, &mut seen),
                affected: intern(&entry.affected, &mut pool, &mut seen),
                cwe: entry.cwe,
                remediation: entry
                    .remediation
                    .as_deref()
                    .map(|value| intern(value, &mut pool, &mut seen)),
            });
        }
    }

    let encoded =
        bincode::serialize(&(&pool, &entries)).expect("failed to serialize the CVE catalogue");
    fs::write(out_dir.join("cve_catalogue.bin"), encoded)
        .expect("failed to write the CVE catalogue");
}

/// Holds every rule's declared `context` against the register in
/// `src/fingerprint/context.rs`, and reports how much of the corpus can fire.
///
/// A context no entry classifies fails the build. A rule reading a field nothing
/// yields never fires, and it fails silently: the rule is well-formed and its own
/// example matches it, so no other check here would say so. Classifying a field
/// is one entry in the register, and refusing to build without it keeps that a
/// decision rather than an oversight.
///
/// A field that is classified and not yet produced fails nothing: importing a
/// block of rules before building the decoder they need is a legitimate way to
/// work, and the register is where that state is recorded rather than lost. It
/// is reported instead — and only then. A corpus with nothing waiting prints
/// nothing, so the line is an alarm and not a meter, and a build that has been
/// quiet for months is still counting.
/// Reports a port number two files both put in `default_ports`.
///
/// The index keeps whichever file sorts first, so the losing name disappears
/// with nothing said. `shared_ports` is the fix this points at. A warning rather
/// than a refusal: the resulting label is arbitrary, not wrong enough to stop a
/// build over.
fn warn_contested_ports(defs: &[ServiceDefinition], paths: &[PathBuf]) {
    let mut owners: BTreeMap<u16, Vec<(&str, String)>> = BTreeMap::new();
    for (def, path) in defs.iter().zip(paths) {
        for &port in &def.service.default_ports {
            owners
                .entry(port)
                .or_default()
                .push((def.service.name.as_str(), path.display().to_string()));
        }
    }

    for (port, claims) in owners {
        // Several files of one service agree on the answer either way.
        let distinct: BTreeSet<&str> = claims.iter().map(|(name, _)| *name).collect();
        if distinct.len() < 2 {
            continue;
        }
        let (winner, _) = claims[0];
        let losers: Vec<String> = claims[1..]
            .iter()
            .map(|(name, file)| format!("'{name}' ({file})"))
            .collect();
        println!(
            "cargo:warning=port {port} is claimed in default_ports by '{}' ({}) and {}; \
             the name goes to '{winner}' because its file sorts first. Move {port} to \
             shared_ports in every definition that does not own the number.",
            claims[0].0,
            claims[0].1,
            losers.join(" and ")
        );
    }
}

fn census_contexts(defs: &[ServiceDefinition], paths: &[PathBuf]) {
    use context::Reach;

    let mut tally: BTreeMap<Reach, usize> = BTreeMap::new();
    let mut per_field: BTreeMap<&str, usize> = BTreeMap::new();
    let mut used: BTreeSet<&str> = BTreeSet::new();

    for (def, path) in defs.iter().zip(paths) {
        for rule in &def.r#match {
            let declared = rule.context.as_deref();
            let Some(reach) = context::reach_of(declared) else {
                let field = declared.unwrap_or_default();
                panic!(
                    "{}: a rule reads the field '{field}', which nothing classifies. Add it to \
                     CONTEXTS in src/fingerprint/context.rs, saying what produces it or what \
                     producing it would take. A rule whose field nothing yields never fires, and \
                     nothing else in the build would say so.",
                    path.display()
                );
            };
            *tally.entry(reach).or_default() += 1;
            if let Some(field) = declared {
                used.insert(field);
                // Out-of-scope fields are not waiting on anything, so listing
                // them beside the ones a decoder would fix reads as work.
                if reach == Reach::Unproduced {
                    *per_field.entry(field).or_default() += 1;
                }
            }
        }
    }

    // An entry for a field the corpus stopped reading is a claim nothing tests.
    // A warning rather than a failure: removing the last rule that read a field
    // is a legitimate thing to do, and the register should outlive it long
    // enough for somebody to decide whether the decoder is still wanted.
    for entry in context::CONTEXTS {
        if !used.contains(entry.name) {
            println!(
                "cargo:warning=no rule reads '{}', which the context register still classifies",
                entry.name
            );
        }
    }

    // Nothing is waiting, so there is nothing to say. Every other state the
    // tally counts is a settled one: `Produced` fires, `Contained` fires from
    // inside another field's text, and `OutOfScope` is a decision somebody wrote
    // down in the register. Only `Unproduced` is work nobody has noticed.
    let waiting = tally.get(&Reach::Unproduced).copied().unwrap_or(0);
    if waiting == 0 {
        return;
    }

    let total: usize = tally.values().sum();
    let live: usize = tally
        .iter()
        .filter(|(reach, _)| reach.reaches_the_matcher())
        .map(|(_, n)| n)
        .sum();
    let summary = tally
        .iter()
        .map(|(reach, n)| format!("{} {}", n, reach.label()))
        .collect::<Vec<_>>()
        .join(", ");
    println!("cargo:warning=corpus reachability: {live}/{total} rules can fire ({summary})");

    // The fields costing the most, so the build names where the next decoder
    // buys the most rather than leaving that to be worked out by hand.
    let mut ranked: Vec<_> = per_field.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    for (field, n) in ranked.iter().take(5) {
        println!("cargo:warning=  {n} rules wait on '{field}'");
    }
    if let Some(entry) = ranked.first().and_then(|(field, _)| context::lookup(field)) {
        println!("cargo:warning=  the largest wants {}", entry.note);
    }
}

/// Derives an identifier for every probe and match rule in one file, and fails
/// the build if any of them cannot have one.
///
/// The identifier is what makes a rule citable: a website can link to it, an
/// issue can name it, and a diff across two releases can say which rule changed
/// rather than that a file did. None of that works if two rules can wear one
/// name, so this is the check that makes the scheme trustworthy rather than
/// merely conventional.
///
/// It lives here rather than in `ServiceDefinition::validate` because an
/// identifier needs a path, and a definition a caller builds in memory has none.
/// The runtime stays willing to match a nameless rule from somebody's own
/// corpus; the shipped corpus is held to the stricter rule, which is the same
/// division the UDP payload checks already sit on.
///
/// `corpus` accumulates across files so a collision between two of them is
/// caught even though the slug should already have separated them. It has never
/// fired, and it is what makes that a fact rather than an assumption.
fn claim_rule_ids(def: &ServiceDefinition, path: &Path, corpus: &mut BTreeSet<String>) {
    let file = path.display();
    let slug = signature::corpus_slug(path)
        .unwrap_or_else(|| panic!("{file}: is not under {}", signature::CORPUS_ROOT));

    let mut seen = BTreeSet::new();
    let probes = def.probe.iter().map(|p| ("probe", p.name.as_deref()));
    let rules = def.r#match.iter().map(|r| ("rule", r.name.as_deref()));

    for (kind, name) in probes.chain(rules) {
        let id = signature::claim_rule_id(&slug, name, &mut seen)
            .unwrap_or_else(|defect| panic!("{file}: a {kind} {defect}"));
        if !corpus.insert(id.clone()) {
            panic!("{file}: the identifier '{id}' is already used by another file");
        }
    }
}

fn validate(def: &ServiceDefinition, path: &Path) {
    let file = path.display();
    let service = &def.service.name;

    // Note: a definition with no `default_ports` is legitimate — it is a
    // port-less banner signature intended for global matching, not the port
    // index. Those are reachable through the prefilter; not a defect, not flagged.

    // The fatal half lives in the schema, so a definition this build accepts is
    // exactly a definition `SignatureDb::try_from_definitions` accepts. It
    // compiles every pattern with the engine selection the runtime uses, checks
    // each `version_group` against its pattern's groups, and refuses a probe over
    // a transport nothing speaks or a generic probe that is not TCP.
    if let Err(defect) = def.validate() {
        panic!("{file}: service '{service}' {defect}");
    }

    // The half the runtime cannot do. A UDP datagram whose length fields
    // disagree with its contents is discarded by the target application without
    // a word, and the scanner reads that silence as `OpenFiltered` — the exact
    // verdict it would report for a filtered port. Catching it needs the target
    // protocol's own parser, which is a build dependency and not a runtime one.
    for (i, probe) in def.probe.iter().enumerate() {
        if probe.protocol == "udp" {
            validate_udp_payload(&unescape(&probe.payload), def, i, path);
        }
        // A TCP probe that sends nothing asks nothing: every claimed port is
        // listened to for a greeting before its probes go out, so all an empty
        // one adds is a wait for a reply to no question. And it claims the
        // port, which keeps the generic question from ever being put to it.
        if probe.protocol == "tcp" && unescape(&probe.payload).is_empty() {
            panic!(
                "{file}: service '{service}' tcp probe #{i} decodes to zero bytes; a port \
                 is listened to before it is probed, and an empty probe only keeps the \
                 generic question from it"
            );
        }
        // Rarity is a 0..=9 intensity band (see `Probe::rarity`). A larger value
        // is almost certainly an authoring typo — it silently keeps the probe
        // from every port its service did not register, since no scan
        // intensity reaches past 9. Warn rather than fail: the probe still goes
        // to the ports its own service registered.
        if probe.rarity > 9 {
            println!(
                "cargo:warning={file}: service '{service}' probe #{i} has rarity {} outside the \
                 expected 0..=9 band",
                probe.rarity
            );
        }
    }
}

/// Validates one authored UDP probe payload, aborting the build if it could
/// never work on the wire.
///
/// UDP probes are checked far more strictly than TCP ones because their failure
/// mode is invisible. A TCP probe with a defect still reaches an open port and
/// usually draws *something*; a UDP datagram whose length fields disagree with
/// its contents is discarded by the target application without a word, and the
/// scanner reads the resulting silence as `OpenFiltered` - the exact verdict it
/// would report for a filtered port. The probe would look like it worked, on
/// every host, forever.
///
/// So the bytes are parsed here the way the service would parse them. Generic
/// limits apply to every payload; the format-specific checks are keyed on the
/// service name, and a UDP probe for a service with no validator is reported as
/// a warning rather than passing quietly.
fn validate_udp_payload(payload: &[u8], def: &ServiceDefinition, index: usize, path: &Path) {
    let file = path.display();
    let service = &def.service.name;

    let generic = if payload.is_empty() {
        Err("decodes to zero bytes; an empty datagram cannot elicit a reply".to_string())
    } else if payload.len() > MAX_UDP_PROBE_BYTES {
        Err(format!(
            "is {} bytes, over the {MAX_UDP_PROBE_BYTES}-byte probe ceiling",
            payload.len()
        ))
    } else {
        Ok(())
    };

    let outcome = generic.and_then(|()| match service.as_str() {
        "dns" | "mdns" => validate_dns_query(payload),
        "snmp" => validate_ber(payload),
        "ntp" => validate_ntp_request(payload),
        "netbios-ns" => validate_netbios_query(payload),
        "ssdp" => validate_ssdp_search(payload),
        "sip" => validate_sip_request(payload),
        "ms-sql-browser" => validate_browser_request(payload),
        "xdmcp" => validate_xdmcp_query(payload),
        "source-engine" => validate_a2s_request(payload),
        "minecraft-bedrock" => validate_raknet_ping(payload),
        "coap" => validate_coap_request(payload),
        "rpcbind" | "nfs" => validate_rpc_call(payload),
        "ipmi" => validate_ipmi_request(payload),
        "isakmp" => validate_isakmp_request(payload),
        "stun" => validate_stun_request(payload),
        "kerberos" => validate_as_req(payload),
        "l2tp" => validate_l2tp_control(payload),
        "memcached" => validate_memcached_datagram(payload),
        "ws-discovery" => validate_wsd_probe(payload),
        _ => {
            println!(
                "cargo:warning={file}: service '{service}' udp probe #{index} has no \
                 format-specific validation; a malformed payload here would be \
                 indistinguishable from a filtered port"
            );
            Ok(())
        }
    });

    if let Err(reason) = outcome {
        panic!("{file}: service '{service}' udp probe #{index} {reason}");
    }
}

/// Checks a Kerberos AS-REQ: the application tag, and a DER structure whose
/// lengths describe the bytes behind them.
///
/// A KDC drops a request it cannot parse without answering, which on the wire is
/// a filtered port, so the encoding is walked here rather than trusted. The
/// probe is hand-built DER and one wrong length byte would make it invisible.
fn validate_as_req(payload: &[u8]) -> Result<(), String> {
    /// `[APPLICATION 10]`, which is what an AS-REQ is tagged with.
    const AS_REQ: u8 = 0x6A;

    /// Returns the contents and total encoded length of the element at the
    /// start of `bytes`.
    fn element(bytes: &[u8]) -> Result<(&[u8], usize), String> {
        let first = *bytes.get(1).ok_or("has a DER tag with no length")? as usize;
        let (length, header) = if first & 0x80 == 0 {
            (first, 2)
        } else {
            let count = first & 0x7F;
            if count == 0 || count > 4 {
                return Err(format!(
                    "uses a {count}-byte DER length, which this check does not cover"
                ));
            }
            let mut length = 0usize;
            for index in 0..count {
                length = (length << 8)
                    | *bytes
                        .get(2 + index)
                        .ok_or("has a truncated DER long-form length")?
                        as usize;
            }
            (length, 2 + count)
        };
        let value = bytes
            .get(header..header + length)
            .ok_or_else(|| format!("has a DER element claiming {length} bytes it does not have"))?;
        Ok((value, header + length))
    }

    if payload.first() != Some(&AS_REQ) {
        return Err(format!(
            "opens with {:#04x}; an AS-REQ is {AS_REQ:#04x}",
            payload.first().copied().unwrap_or_default()
        ));
    }
    let (body, consumed) = element(payload)?;
    if consumed != payload.len() {
        return Err(format!(
            "has {} bytes after its application element",
            payload.len() - consumed
        ));
    }

    // The application tag wraps a SEQUENCE whose fields are context-tagged, and
    // every one of their lengths has to hold for a KDC to read the request.
    let (fields, consumed) = element(body)?;
    if consumed != body.len() {
        return Err("has trailing bytes after the request sequence".into());
    }
    let mut at = 0;
    let mut seen = Vec::new();
    while at < fields.len() {
        let (_, next) = element(&fields[at..])?;
        seen.push(fields[at]);
        at += next;
    }
    // pvno, msg-type and the request body: a KDC rejects a request missing any.
    for wanted in [0xA1u8, 0xA2, 0xA4] {
        if !seen.contains(&wanted) {
            return Err(format!(
                "carries no [{}] field, which an AS-REQ requires",
                wanted & 0x1F
            ));
        }
    }
    Ok(())
}

/// Checks an L2TP control message: the flag bits, the version, and a length
/// field and attribute chain that agree with the bytes behind them.
fn validate_l2tp_control(payload: &[u8]) -> Result<(), String> {
    /// Type and length bits, which a control message sets.
    const CONTROL: u8 = 0b1100_0000;
    /// The sequence bit, which a control message also sets.
    const SEQUENCE: u8 = 0b0000_1000;
    const HEADER_BYTES: usize = 12;
    const ATTRIBUTE_HEADER_BYTES: usize = 6;
    /// Message Type, which has to lead the attribute chain.
    const MESSAGE_TYPE: u16 = 0;
    /// SCCRQ, the message that proposes a tunnel.
    const SCCRQ: u16 = 1;

    let first = *payload.first().ok_or("is empty")?;
    if first & CONTROL != CONTROL {
        return Err("does not set the type and length bits a control message carries".into());
    }
    if first & SEQUENCE == 0 {
        return Err("does not set the sequence bit, and a control message always does".into());
    }
    let version = *payload.get(1).ok_or("is too short for a header")? & 0x0F;
    if version != 2 {
        return Err(format!(
            "states L2TP version {version}, and the protocol is 2"
        ));
    }

    let stated = u16::from_be_bytes([
        *payload.get(2).ok_or("has no length field")?,
        *payload.get(3).ok_or("has a truncated length field")?,
    ]) as usize;
    if stated != payload.len() {
        return Err(format!(
            "states a length of {stated} and is {} bytes",
            payload.len()
        ));
    }

    let mut at = HEADER_BYTES;
    let mut first_attribute = None;
    while at + ATTRIBUTE_HEADER_BYTES <= payload.len() {
        let length = (u16::from_be_bytes([payload[at], payload[at + 1]]) & 0x03FF) as usize;
        if length < ATTRIBUTE_HEADER_BYTES {
            return Err(format!(
                "has an attribute claiming {length} bytes, less than its own header"
            ));
        }
        let attribute = u16::from_be_bytes([payload[at + 4], payload[at + 5]]);
        let value = payload
            .get(at + ATTRIBUTE_HEADER_BYTES..at + length)
            .ok_or_else(|| format!("has an attribute claiming {length} bytes past the end"))?;
        if first_attribute.is_none() {
            first_attribute = Some((attribute, u16::from_be_bytes([value[0], value[1]])));
        }
        at += length;
    }
    if at != payload.len() {
        return Err(format!(
            "has {} bytes after its last attribute",
            payload.len() - at
        ));
    }

    match first_attribute {
        Some((MESSAGE_TYPE, SCCRQ)) => Ok(()),
        Some((MESSAGE_TYPE, other)) => Err(format!(
            "opens with message type {other}; a probe proposing a tunnel is {SCCRQ} (SCCRQ)"
        )),
        _ => Err("does not lead with a Message Type attribute, which RFC 2661 requires".into()),
    }
}

/// Checks a STUN binding request: the type, the magic cookie that separates it
/// from the RFC 3489 message it otherwise resembles, and the fixed header size.
fn validate_stun_request(payload: &[u8]) -> Result<(), String> {
    const BINDING_REQUEST: u16 = 0x0001;
    const MAGIC_COOKIE: u32 = 0x2112_A442;
    const HEADER_BYTES: usize = 20;

    if payload.len() < HEADER_BYTES {
        return Err(format!(
            "is {} bytes; a STUN header is {HEADER_BYTES}",
            payload.len()
        ));
    }
    let kind = u16::from_be_bytes([payload[0], payload[1]]);
    if kind != BINDING_REQUEST {
        return Err(format!(
            "is message type {kind:#06x}, not a binding request"
        ));
    }
    let cookie = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if cookie != MAGIC_COOKIE {
        return Err("carries no magic cookie, so the reply could not be told from RFC 3489".into());
    }

    let stated = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    match stated == payload.len() - HEADER_BYTES {
        true => Ok(()),
        false => Err(format!(
            "states {stated} bytes of attributes and carries {}",
            payload.len() - HEADER_BYTES
        )),
    }
}

/// Checks an ONC RPC call: the message type, the RPC version, and a header
/// whose credential and verifier lengths describe the bytes behind them.
fn validate_rpc_call(payload: &[u8]) -> Result<(), String> {
    const MSG_TYPE_CALL: u32 = 0;
    const RPC_VERSION: u32 = 2;

    let word = |at: usize| -> Result<u32, String> {
        payload
            .get(at..at + 4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .ok_or_else(|| {
                format!(
                    "is {} bytes, too short for an RPC call header",
                    payload.len()
                )
            })
    };

    let msg_type = word(4)?;
    if msg_type != MSG_TYPE_CALL {
        return Err(format!(
            "has message type {msg_type}; a probe is a call, type {MSG_TYPE_CALL}"
        ));
    }
    let version = word(8)?;
    if version != RPC_VERSION {
        return Err(format!(
            "states RPC version {version}, and the protocol is {RPC_VERSION}"
        ));
    }

    // The credential and the verifier each state a flavour and a length, and a
    // server reading past the end of one drops the call in silence.
    let mut at = 24;
    for which in ["credential", "verifier"] {
        let length = word(at + 4)? as usize;
        at += 8 + length.next_multiple_of(4);
        if at > payload.len() {
            return Err(format!(
                "has a {which} claiming {length} bytes past the end of the call"
            ));
        }
    }
    match at == payload.len() {
        true => Ok(()),
        false => Err(format!(
            "has {} bytes after its verifier, and these procedures take no arguments",
            payload.len() - at
        )),
    }
}

/// Checks an RMCP-wrapped IPMI request, checksums included.
///
/// The checksums are the reason this exists. A controller drops a message whose
/// checksums do not hold without answering, which on the wire is
/// indistinguishable from a filtered port, so a payload edited by hand and not
/// recomputed would look exactly like a BMC that was not there.
fn validate_ipmi_request(payload: &[u8]) -> Result<(), String> {
    const RMCP_VERSION: u8 = 0x06;
    const CLASS_IPMI: u8 = 0x07;
    /// The RMCP header and the unauthenticated v1.5 session header before the
    /// message length byte.
    const MESSAGE_AT: usize = 13;

    let at = |index: usize| -> Result<u8, String> {
        payload
            .get(index)
            .copied()
            .ok_or_else(|| format!("is {} bytes, too short for an RMCP message", payload.len()))
    };

    if at(0)? != RMCP_VERSION {
        return Err(format!(
            "states RMCP version {:#04x}, and it is {RMCP_VERSION:#04x}",
            at(0)?
        ));
    }
    if at(3)? != CLASS_IPMI {
        return Err(format!(
            "is RMCP class {:#04x}; an IPMI message is class {CLASS_IPMI:#04x}",
            at(3)?
        ));
    }

    let stated = at(MESSAGE_AT)? as usize;
    let body = payload
        .get(MESSAGE_AT + 1..)
        .ok_or("carries a length and no message")?;
    if body.len() != stated {
        return Err(format!(
            "states a {stated}-byte message and carries {}",
            body.len()
        ));
    }
    if body.len() < 7 {
        return Err(format!(
            "has a {}-byte message, too short for an IPMB request",
            body.len()
        ));
    }

    // Both checksums are two's complement over the bytes preceding them, so a
    // correct one sums to zero with what it covers.
    let header: u8 = body[..3]
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    if header != 0 {
        return Err("has a header checksum that does not hold; the BMC would drop it".into());
    }
    let data: u8 = body[3..]
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    match data == 0 {
        true => Ok(()),
        false => Err("has a data checksum that does not hold; the BMC would drop it".into()),
    }
}

/// Checks an XDMCP Query: the version, the opcode a manager dispatches on, and
/// a stated length that matches the body behind it.
fn validate_xdmcp_query(payload: &[u8]) -> Result<(), String> {
    const VERSION: u16 = 1;
    const OPCODE_QUERY: u16 = 2;

    let field = |at: usize| -> Result<u16, String> {
        payload
            .get(at..at + 2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
            .ok_or_else(|| format!("is {} bytes, too short for an XDMCP header", payload.len()))
    };

    let version = field(0)?;
    if version != VERSION {
        return Err(format!(
            "states XDMCP version {version}, and the protocol is {VERSION}"
        ));
    }
    let opcode = field(2)?;
    if opcode != OPCODE_QUERY {
        return Err(format!(
            "has opcode {opcode}; a manager answers a Query, opcode {OPCODE_QUERY}"
        ));
    }

    let stated = field(4)? as usize;
    let body = payload.len() - 6;
    if stated != body {
        return Err(format!("states a {stated}-byte body and carries {body}"));
    }
    Ok(())
}

/// Checks an A2S request: the header every Source query carries, the request
/// byte, and the string the protocol requires after it.
fn validate_a2s_request(payload: &[u8]) -> Result<(), String> {
    const HEADER: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF];
    const A2S_INFO: u8 = b'T';

    if !payload.starts_with(HEADER) {
        return Err("does not open with the four 0xFF bytes every Source query carries".into());
    }
    match payload.get(4) {
        Some(&A2S_INFO) => {}
        Some(other) => {
            return Err(format!(
                "is request {:?}, and this validator covers A2S_INFO",
                *other as char
            ));
        }
        None => return Err("carries a header and no request".into()),
    }
    match payload.ends_with(b"Source Engine Query\0") {
        true => Ok(()),
        false => Err("does not carry the `Source Engine Query` string A2S_INFO requires".into()),
    }
}

/// Checks a RakNet unconnected ping: the packet id, the length, and the magic
/// without which a server does not recognise the message as RakNet at all.
fn validate_raknet_ping(payload: &[u8]) -> Result<(), String> {
    const UNCONNECTED_PING: u8 = 0x01;
    const MAGIC: &[u8] = &[
        0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE, 0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56,
        0x78,
    ];
    // Packet id, timestamp, magic, and the client identifier.
    const PING_BYTES: usize = 1 + 8 + 16 + 8;

    if payload.first() != Some(&UNCONNECTED_PING) {
        return Err(format!(
            "opens with {:#04x}; an unconnected ping is {UNCONNECTED_PING:#04x}",
            payload.first().copied().unwrap_or_default()
        ));
    }
    if payload.len() != PING_BYTES {
        return Err(format!(
            "is {} bytes; an unconnected ping is {PING_BYTES}",
            payload.len()
        ));
    }
    match &payload[9..25] == MAGIC {
        true => Ok(()),
        false => {
            Err("does not carry the offline message magic, so no server reads it as RakNet".into())
        }
    }
}

/// Checks a CoAP request: the version, the code, and options whose lengths
/// describe the bytes behind them.
fn validate_coap_request(payload: &[u8]) -> Result<(), String> {
    const GET: u8 = 0x01;

    let first = *payload.first().ok_or("is empty")?;
    let version = first >> 6;
    if version != 1 {
        return Err(format!("states CoAP version {version}, and RFC 7252 is 1"));
    }
    if payload.get(1) != Some(&GET) {
        return Err(format!(
            "has code {:#04x}; a discovery probe is a GET, {GET:#04x}",
            payload.get(1).copied().unwrap_or_default()
        ));
    }

    // Walk the options the way an endpoint would, so a length that overruns is
    // caught here rather than being dropped in silence by the device.
    let mut at = 4 + (first & 0x0F) as usize;
    while at < payload.len() {
        let byte = payload[at];
        if byte == 0xFF {
            return Ok(());
        }
        at += 1;
        let length = (byte & 0x0F) as usize;
        if byte >> 4 == 15 || length == 15 {
            return Err("uses the reserved option nibble 15".into());
        }
        at += length;
        if at > payload.len() {
            return Err(format!(
                "has an option claiming {length} bytes past the end of the payload"
            ));
        }
    }
    Ok(())
}

/// Checks a SQL Server Browser request: one byte, and one the Browser dispatches
/// on. Anything else is dropped without a reply.
fn validate_browser_request(payload: &[u8]) -> Result<(), String> {
    // CLNT_UCAST_EX lists every instance; CLNT_UCAST_INST and CLNT_UCAST_DAC
    // name one the client already knows.
    const REQUESTS: &[u8] = &[0x02, 0x03, 0x04];

    match payload {
        [request] if REQUESTS.contains(request) => Ok(()),
        [request] => Err(format!(
            "is request type {request:#04x}, which the Browser does not dispatch on"
        )),
        _ => Err(format!(
            "is {} bytes; a Browser request is one",
            payload.len()
        )),
    }
}

/// Checks a memcached UDP datagram: the eight-byte frame, a command behind it,
/// and a frame that describes one datagram rather than part of a larger request.
fn validate_memcached_datagram(payload: &[u8]) -> Result<(), String> {
    const FRAME_BYTES: usize = 8;

    let frame = payload
        .get(..FRAME_BYTES)
        .ok_or_else(|| format!("is {} bytes, shorter than the 8-byte frame", payload.len()))?;

    let sequence = u16::from_be_bytes([frame[2], frame[3]]);
    let total = u16::from_be_bytes([frame[4], frame[5]]);
    if sequence != 0 || total != 1 {
        return Err(format!(
            "declares datagram {sequence} of {total}; a probe is datagram 0 of 1, and a              server waits for the rest of anything else"
        ));
    }

    let command = &payload[FRAME_BYTES..];
    if command.is_empty() {
        return Err("carries a frame and no command".into());
    }
    match command.ends_with(b"\r\n") {
        true => Ok(()),
        false => Err("does not end its command with CRLF, so the server keeps reading".into()),
    }
}

/// Checks a WS-Discovery Probe: that it parses as the SOAP envelope a responder
/// expects, and that it carries the action a responder dispatches on.
fn validate_wsd_probe(payload: &[u8]) -> Result<(), String> {
    const ACTION: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe";

    let text = std::str::from_utf8(payload).map_err(|_| "is not UTF-8, and SOAP is text")?;

    for wanted in ["<s:Envelope", "<s:Header>", "<s:Body>", "</s:Envelope>"] {
        if !text.contains(wanted) {
            return Err(format!(
                "carries no `{wanted}`, so it is not a SOAP envelope"
            ));
        }
    }
    if !text.contains(ACTION) {
        return Err(format!(
            "names no `{ACTION}` action, which is what a responder dispatches on"
        ));
    }
    match text.contains("MessageID") {
        true => Ok(()),
        false => Err("carries no MessageID, which WS-Addressing requires of a request".into()),
    }
}

/// Parses a DNS query with the same parser the runtime uses, then checks it
/// carries exactly one question - a query with none asks nothing and is
/// answered by nobody.
fn validate_dns_query(payload: &[u8]) -> Result<(), String> {
    let packet = dns_parser::Packet::parse(payload)
        .map_err(|e| format!("is not a parseable DNS message: {e}"))?;

    match packet.questions.len() {
        1 => Ok(()),
        n => Err(format!(
            "carries {n} questions; a probe should ask exactly one"
        )),
    }
}

/// Walks a BER structure, checking that every length field describes the bytes
/// that actually follow it, and that the payload is exactly one top-level
/// element with nothing trailing.
fn validate_ber(payload: &[u8]) -> Result<(), String> {
    /// Returns how many bytes the element at the start of `bytes` occupies,
    /// recursing into constructed ones.
    fn walk(bytes: &[u8]) -> Result<usize, String> {
        let tag = *bytes
            .first()
            .ok_or("has a truncated BER element with no tag")?;
        let len = *bytes.get(1).ok_or("has a BER tag with no length byte")? as usize;
        if len & 0x80 != 0 {
            return Err("uses long-form BER lengths, which this validator does not cover".into());
        }
        let body = bytes.get(2..2 + len).ok_or_else(|| {
            format!("has a BER element (tag {tag:#04x}) claiming {len} bytes it does not have")
        })?;

        // SEQUENCE (0x30) and the context-specific PDU tags (0xa0..) are
        // constructed: their contents are themselves elements.
        if tag == 0x30 || tag & 0xa0 == 0xa0 {
            let mut consumed = 0;
            while consumed < body.len() {
                consumed += walk(&body[consumed..])?;
            }
        }
        Ok(2 + len)
    }

    let consumed = walk(payload)?;
    if consumed != payload.len() {
        return Err(format!(
            "has {} trailing bytes after its top-level BER element",
            payload.len() - consumed
        ));
    }
    Ok(())
}

/// Checks an NTP request, dispatching on the mode the first byte carries.
///
/// Two shapes are sent to this port and they share nothing but that byte. A
/// client request is a fixed 48-byte packet a server answers with timestamps; a
/// control message is a 12-byte header a daemon answers with the text that
/// describes it. A validator that knew only the first refused the second for
/// being the wrong length, which is how this one came to dispatch.
fn validate_ntp_request(payload: &[u8]) -> Result<(), String> {
    const MODE_CLIENT: u8 = 3;
    const MODE_CONTROL: u8 = 6;

    let first = *payload.first().ok_or("is empty")?;
    let version = (first >> 3) & 0b111;
    if !(1..=4).contains(&version) {
        return Err(format!(
            "has NTP version {version}, outside the 1..=4 range"
        ));
    }

    match first & 0b111 {
        MODE_CLIENT => validate_ntp_client_request(payload),
        MODE_CONTROL => validate_ntp_control_message(payload),
        mode => Err(format!(
            "has mode {mode}; a request a server will answer is mode {MODE_CLIENT} (client) \
             or mode {MODE_CONTROL} (control)"
        )),
    }
}

/// A client request is a fixed 48 bytes, and a server answers nothing else.
fn validate_ntp_client_request(payload: &[u8]) -> Result<(), String> {
    const NTP_PACKET_BYTES: usize = 48;

    match payload.len() == NTP_PACKET_BYTES {
        true => Ok(()),
        false => Err(format!(
            "is {} bytes; an SNTP packet is exactly {NTP_PACKET_BYTES}",
            payload.len()
        )),
    }
}

/// A control message is a 12-byte header plus the data its count describes, and
/// a request carries neither the response bit nor an error.
fn validate_ntp_control_message(payload: &[u8]) -> Result<(), String> {
    const HEADER_BYTES: usize = 12;
    const RESPONSE: u8 = 0b1000_0000;
    const ERROR: u8 = 0b0100_0000;

    if payload.len() < HEADER_BYTES {
        return Err(format!(
            "is {} bytes; a control header is {HEADER_BYTES}",
            payload.len()
        ));
    }
    let second = payload[1];
    if second & RESPONSE != 0 {
        return Err("has the response bit set, and a probe is a request".into());
    }
    if second & ERROR != 0 {
        return Err("has the error bit set, which a request never carries".into());
    }

    let count = u16::from_be_bytes([payload[10], payload[11]]) as usize;
    match payload.len() == HEADER_BYTES + count {
        true => Ok(()),
        false => Err(format!(
            "states a {count}-byte data field and carries {}",
            payload.len() - HEADER_BYTES
        )),
    }
}

/// Checks an ISAKMP request: the header, a responder cookie a request leaves
/// zero, and a length field that agrees with the payload chain behind it.
fn validate_isakmp_request(payload: &[u8]) -> Result<(), String> {
    const HEADER_BYTES: usize = 28;

    if payload.len() < HEADER_BYTES {
        return Err(format!(
            "is {} bytes; an ISAKMP header is {HEADER_BYTES}",
            payload.len()
        ));
    }
    if payload[8..16] != [0u8; 8] {
        return Err("carries a responder cookie, which only a reply sets".into());
    }

    let stated = u32::from_be_bytes([payload[24], payload[25], payload[26], payload[27]]) as usize;
    if stated != payload.len() {
        return Err(format!(
            "states a length of {stated} and is {} bytes",
            payload.len()
        ));
    }

    // Walk the payload chain the way a responder would. A length that overruns
    // is dropped in silence, which on the wire is a filtered port.
    let mut next = payload[16];
    let mut at = HEADER_BYTES;
    while next != 0 {
        let header = payload
            .get(at..at + 4)
            .ok_or("has a payload chain running past the end of the message")?;
        let length = u16::from_be_bytes([header[2], header[3]]) as usize;
        if length < 4 {
            return Err(format!(
                "has a payload claiming {length} bytes, less than its own header"
            ));
        }
        next = header[0];
        at += length;
        if at > payload.len() {
            return Err(format!(
                "has a payload claiming {length} bytes past the end"
            ));
        }
    }
    match at == payload.len() {
        true => Ok(()),
        false => Err(format!(
            "has {} bytes after its last payload",
            payload.len() - at
        )),
    }
}

/// Checks a NetBIOS Name Service query: one question, and a name field whose
/// declared length matches the encoded name that follows it.
fn validate_netbios_query(payload: &[u8]) -> Result<(), String> {
    const HEADER_BYTES: usize = 12;
    const ENCODED_NAME_BYTES: usize = 32;
    // Header + length byte + encoded name + terminator + QTYPE + QCLASS.
    const REQUEST_BYTES: usize = HEADER_BYTES + 1 + ENCODED_NAME_BYTES + 1 + 4;

    if payload.len() != REQUEST_BYTES {
        return Err(format!(
            "is {} bytes; a node status request is {REQUEST_BYTES}",
            payload.len()
        ));
    }

    let questions = u16::from_be_bytes([payload[4], payload[5]]);
    if questions != 1 {
        return Err(format!(
            "declares {questions} questions; a probe should ask exactly one"
        ));
    }

    let declared = payload[HEADER_BYTES] as usize;
    if declared != ENCODED_NAME_BYTES {
        return Err(format!(
            "declares a {declared}-byte name; first-level encoding always yields \
             {ENCODED_NAME_BYTES}"
        ));
    }
    if payload[HEADER_BYTES + 1 + ENCODED_NAME_BYTES] != 0 {
        return Err("does not terminate its encoded name with a zero length byte".into());
    }
    Ok(())
}

/// Checks an SSDP search: the request line, the headers UPnP devices require,
/// and the blank line that ends the request. A device ignores a request that is
/// missing any of them.
fn validate_ssdp_search(payload: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(payload)
        .map_err(|_| "is not valid UTF-8, but SSDP is a text protocol".to_string())?;

    if !text.starts_with("M-SEARCH * HTTP/1.1\r\n") {
        return Err("does not open with an `M-SEARCH * HTTP/1.1` request line".into());
    }
    if !text.ends_with("\r\n\r\n") {
        return Err("is not terminated by a blank line".into());
    }
    for header in ["HOST:", "MAN:", "MX:", "ST:"] {
        if !text.contains(header) {
            return Err(format!("is missing the required `{header}` header"));
        }
    }
    Ok(())
}

/// Validates an authored SIP request.
///
/// RFC 3261 §7.1 gives a request a `Method Request-URI SIP/2.0` line, and §8.1.1
/// makes six headers mandatory in every one. An endpoint discards a request
/// missing any of them without answering, which over UDP is indistinguishable
/// from a filtered port: the failure this whole pass exists to catch.
///
/// The `Via` transport is checked against the transport the probe declares.
/// A reply is returned over what `Via` names, so a UDP probe announcing TCP asks
/// a question whose answer goes somewhere the scan is not listening.
fn validate_sip_request(payload: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(payload)
        .map_err(|_| "is not valid UTF-8, but SIP is a text protocol".to_string())?;

    let request_line = text.lines().next().unwrap_or_default();
    if !request_line.ends_with("SIP/2.0") {
        return Err("does not open with a request line ending in `SIP/2.0`".into());
    }
    if !text.ends_with("\r\n\r\n") {
        return Err("is not terminated by a blank line".into());
    }
    for header in ["Via:", "From:", "To:", "Call-ID:", "CSeq:", "Max-Forwards:"] {
        if !text.contains(header) {
            return Err(format!(
                "is missing `{header}`, which RFC 3261 §8.1.1 requires in every request"
            ));
        }
    }
    if !text.contains("SIP/2.0/UDP") {
        return Err(
            "declares a `Via` transport other than UDP, so a reply to this datagram \
             would be returned over a transport nothing here is listening on"
                .into(),
        );
    }
    Ok(())
}

/// Recursively collects every `.toml` file under `dir`.
fn collect_toml_files(dir: &Path, files: &mut Vec<PathBuf>) {
    collect_toml_files_except(dir, &[], files);
}

/// The same walk, skipping any directory whose name is in `skip`.
///
/// Two corpora live under `assets/fingerprinting` and they are different
/// schemas: service signatures match a regex against text, and the rules in
/// `os/` match predicates against a typed feature vector. A walk that collected
/// both would hand each file to the wrong parser, and the build would fail
/// somewhere confusing, with a TOML error about a map where a sequence was
/// expected. Naming the exclusion here keeps that a one-line fact rather than a
/// rediscovery.
fn collect_toml_files_except(dir: &Path, skip: &[&str], files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if skip.contains(&name) {
                continue;
            }
            collect_toml_files_except(&path, skip, files);
        } else if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            files.push(path);
        }
    }
}
