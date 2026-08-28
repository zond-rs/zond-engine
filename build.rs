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

use std::collections::BTreeSet;
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

/// The pattern-compilation logic, shared verbatim with the runtime so the build
/// accepts *exactly* the patterns the engine can match — including the
/// backref/lookaround patterns that fall back to the bounded fancy engine. If it
/// compiles here, the runtime can compile it; if it fails here, it never ships.
///
/// Loaded via `#[path]` (rather than `include!`) so the file's own module docs
/// are honoured — `include!` forbids the inner `//!` comments it carries.
#[path = "src/fingerprint/pattern.rs"]
mod pattern;

#[path = "src/detect/flow/expr.rs"]
mod expr;
/// The Tier-1 flow-detection trio, shared with the runtime the same way: the
/// authoring `schema`, the guard-expression grammar `expr`, and the structural
/// `validate` that rejects a malformed flow. A flow the build accepts is a flow
/// the interpreter can run, because both read these files. `validate` names its
/// siblings `schema` and `expr`, which is why the service schema above is
/// `signature`: the two must not both be `schema`.
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
    println!("cargo:rerun-if-changed=src/detect/flow/schema.rs");
    println!("cargo:rerun-if-changed=src/detect/flow/expr.rs");
    println!("cargo:rerun-if-changed=src/detect/flow/validate.rs");

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
    for path in &toml_files {
        let content = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        let def: ServiceDefinition = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()));
        validate(&def, path);
        validate_generic_probes(&def, path);
        services.push(def);
    }

    let encoded = bincode::serialize(&services).expect("failed to serialize fingerprint database");
    fs::write(&dest_path, encoded).expect("failed to write fingerprint database");

    compile_os_rules(Path::new(&out_dir));
    compile_flows(Path::new(&out_dir));
}

/// Validates the Tier-1 flow corpus in `assets/detect` and compiles it into the
/// `bincode` blob the engine embeds, failing the build on any ill-formed
/// detection with a pointer to its file.
///
/// The structural rules run through the shared [`validate`] — the same code a
/// flow loaded at runtime would face — and the rules that need the pattern engine
/// or the payload unescaper run here, where the build has them: that every
/// `expect`/`bind` pattern compiles and its capture group exists, and that a
/// declared byte budget covers what the flow must send.
///
/// What is emitted is each flow's **source and its content hash**, not a
/// serialized [`schema::FlowDetection`]. The runtime re-parses the source it
/// validated (so the build and the runtime read one text), and hashing the file
/// bytes is exactly the provenance the finding records — the answer to "which
/// detection body fired". Embedding the parsed form would demand a `bincode`
/// spelling of the `untagged` match rule, which the format cannot round-trip.
fn compile_flows(out_dir: &Path) {
    let mut toml_files = Vec::new();
    collect_toml_files(Path::new("assets/detect"), &mut toml_files);
    // Sort for a deterministic, reproducible artifact.
    toml_files.sort();

    let mut ids = BTreeSet::new();
    let mut compiled: Vec<(String, String)> = Vec::with_capacity(toml_files.len());
    for path in &toml_files {
        let content = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        let flow: schema::FlowDetection = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()));

        let errors = validate::check(&flow);
        if !errors.is_empty() {
            let mut message = format!("{}: this flow detection is ill-formed:", path.display());
            for error in &errors {
                message.push_str(&format!("\n  - the detection {error}"));
            }
            panic!("{message}");
        }

        // A detection id is a provenance claim, so it must be unique across the
        // corpus — two findings that name the same id could not be told apart.
        if !ids.insert(flow.detection.id.clone()) {
            panic!(
                "{}: detection id '{}' is already used by another flow",
                path.display(),
                flow.detection.id
            );
        }

        validate_flow_patterns(&flow, path);
        validate_flow_budget(&flow, path);
        warn_flow_soft(&flow, path);

        compiled.push((sha256_hex(content.as_bytes()), content));
    }

    let encoded = bincode::serialize(&compiled).expect("failed to serialize the flow database");
    fs::write(out_dir.join("detect_flows.bin"), encoded)
        .expect("failed to write the flow database");
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
    let Some(max_bytes) = flow.detection.capabilities.max_bytes else {
        return;
    };
    let mut sent: u64 = 0;
    for step in &flow.step {
        if let Some(send) = &step.send {
            let bytes = unescape(send).len() as u64;
            let iterations = step
                .for_each
                .as_ref()
                .map_or(1, |for_each| for_each.items.len() as u64);
            sent += bytes * iterations;
        }
    }
    if sent > u64::from(max_bytes) {
        panic!(
            "{}: '{}' declares max_bytes = {max_bytes} but its steps send {sent} bytes",
            path.display(),
            flow.detection.id
        );
    }
}

/// Soft issues that do not fail the build but an author should see: a class that
/// is off by default, so the flow ships inert until an operator opts in, and a
/// malformed CVE identifier that a finding would silently drop.
fn warn_flow_soft(flow: &schema::FlowDetection, path: &Path) {
    let file = path.display();
    let id = &flow.detection.id;

    if matches!(
        flow.detection.capabilities.class,
        schema::Class::ActiveMutating | schema::Class::Exploit | schema::Class::Dos
    ) {
        println!(
            "cargo:warning={file}: '{id}' is class {:?}, which is off by default — it ships \
             inert unless an operator opts the envelope in",
            flow.detection.capabilities.class
        );
    }

    for step in &flow.step {
        for finding in &step.finding {
            for reference in &finding.references {
                if let schema::Reference::Cve(cve) = reference
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
/// Refuses a generic probe that is not TCP.
///
/// `generic` means "send this to any open port with nothing else to send", and
/// over UDP that is a payload aimed at every UDP port in the scan — a different
/// and much larger claim than the one the flag is for, and one nobody would make
/// by ticking a boolean. Caught here because the runtime simply skips such a
/// probe, and a probe silently not sent is the kind of gap that ships.
fn validate_generic_probes(def: &ServiceDefinition, path: &Path) {
    for probe in &def.probe {
        if probe.generic && probe.protocol != "tcp" {
            panic!(
                "{}: probe '{}' is marked generic over {}. A generic probe is sent to \
                 every open port that registers none of its own, which only makes sense \
                 over TCP.",
                path.display(),
                probe.name.as_deref().unwrap_or("<unnamed>"),
                probe.protocol,
            );
        }
    }
}

fn validate_os_rule(def: &os_schema::OsDefinition, path: &Path) {
    let file = path.display();
    let family = &def.os.family;

    if family.trim().is_empty() {
        panic!("{file}: a rule must name a family");
    }

    // The identity is a path, so a segment cannot be given without the one above
    // it. "Ubuntu 22.04" with no vendor is fine; a version with no product names
    // a version of nothing.
    if def.os.version.is_some() && def.os.product.is_none() {
        panic!("{file}: '{family}' states a version without a product to version");
    }

    if !(0.0..=os_schema::MAX_RULE_WEIGHT).contains(&def.weight) || !def.weight.is_finite() {
        panic!(
            "{file}: '{family}' has weight {}, outside 0..={}",
            def.weight,
            os_schema::MAX_RULE_WEIGHT
        );
    }

    let mut predicates = 0usize;
    macro_rules! check {
        ($($field:ident),* $(,)?) => {$(
            if let Some(predicate) = &def.r#match.$field {
                predicates += 1;
                match predicate.forms_set() {
                    1 => {}
                    0 => panic!(
                        "{file}: '{family}' predicate `{}` sets none of equals/any_of/range, \
                         so it can never match",
                        stringify!($field)
                    ),
                    n => panic!(
                        "{file}: '{family}' predicate `{}` sets {n} of equals/any_of/range; \
                         exactly one is allowed",
                        stringify!($field)
                    ),
                }
                if let Some(set) = &predicate.any_of
                    && set.is_empty()
                {
                    panic!(
                        "{file}: '{family}' predicate `{}` has an empty any_of, so it can \
                         never match",
                        stringify!($field)
                    );
                }
                if let Some([low, high]) = &predicate.range
                    && low > high
                {
                    panic!(
                        "{file}: '{family}' predicate `{}` has a range whose low bound is \
                         above its high bound, so it can never match",
                        stringify!($field)
                    );
                }
            }
        )*};
    }
    check!(
        initial_hops,
        dont_fragment,
        option_layout,
        window,
        window_units,
        window_remainder,
        window_scale,
        mss,
        timestamps,
        sack_permitted,
        echo_code,
        echo_payload_intact,
        identifier_class,
        sequence_class,
        clock_class,
    );

    // A TCP example without a window has recorded nothing about the field its
    // rule most likely keys on, and the schema cannot require it: an echo reply
    // has no window at all. So the requirement is stated here, per reply kind,
    // where it can be.
    for example in &def.example {
        if example.reply != os_schema::ReplyKind::EchoReply && example.window.is_none() {
            panic!(
                "{file}: '{family}' has a {:?} example with no window; only an echo \
                 example may omit one",
                example.reply
            );
        }
    }

    // The one defect that is worse than a build failure. A rule testing nothing
    // matches every reply of its kind and names every host that ever answers as
    // this operating system, and nothing downstream can tell that from a
    // detection that worked.
    if predicates == 0 {
        panic!(
            "{file}: '{family}' states no predicates, so it would match every reply of its kind"
        );
    }

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
fn validate(def: &ServiceDefinition, path: &Path) {
    let file = path.display();
    let service = &def.service.name;

    // Note: a definition with no `default_ports` is legitimate — it is a
    // port-less banner signature intended for global matching, not the port
    // index. Those become reachable with the prefilter (see the fingerprinting
    // redesign RFC, phase 3); they are not a defect and are not flagged here.

    for (i, rule) in def.r#match.iter().enumerate() {
        // Compile with the exact engine-selection and limit the runtime uses, so
        // the build accepts precisely the patterns the engine will — including
        // backref/lookaround patterns via the bounded fancy fallback.
        let compiled =
            pattern::compile(&rule.pattern, MAX_COMPILED_REGEX_BYTES).unwrap_or_else(|e| {
                panic!(
                    "{file}: service '{service}' match #{i} has an unusable pattern: {e}\n  \
                     pattern: {}",
                    rule.pattern
                )
            });

        if let Some(group) = rule.version_group {
            // `captures_len()` counts group 0 (the whole match) plus each
            // capturing group, so valid indices are `0..captures_len()`.
            if group as usize >= compiled.captures_len() {
                panic!(
                    "{file}: service '{service}' match #{i} references version_group {group}, but \
                     the pattern has {} capture group(s)\n  pattern: {}",
                    compiled.captures_len() - 1,
                    rule.pattern
                );
            }
        }
    }

    for (i, probe) in def.probe.iter().enumerate() {
        if !matches!(probe.protocol.as_str(), "tcp" | "udp") {
            println!(
                "cargo:warning={file}: service '{service}' probe #{i} has unknown protocol '{}' \
                 (expected 'tcp' or 'udp')",
                probe.protocol
            );
        }

        if probe.protocol == "udp" {
            validate_udp_payload(&unescape(&probe.payload), def, i, path);
        }
        // Rarity is a 0..=9 intensity band (see `Probe::rarity`). A larger value
        // is almost certainly an authoring typo — it would silently keep the
        // probe from ever being sent at normal intensity. Warn rather than fail:
        // it degrades nothing that ships today (the runtime does not gate on it
        // yet) and out-of-band values may be deliberate once it does.
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

/// Checks an SNTP client request: the fixed 48-byte size, and the mode field a
/// server dispatches on. A packet in the wrong mode is answered by nobody.
fn validate_ntp_request(payload: &[u8]) -> Result<(), String> {
    const NTP_PACKET_BYTES: usize = 48;
    const MODE_CLIENT: u8 = 3;

    if payload.len() != NTP_PACKET_BYTES {
        return Err(format!(
            "is {} bytes; an SNTP packet is exactly {NTP_PACKET_BYTES}",
            payload.len()
        ));
    }

    let mode = payload[0] & 0b111;
    if mode != MODE_CLIENT {
        return Err(format!(
            "has mode {mode}; a request a server will answer must be mode {MODE_CLIENT} (client)"
        ));
    }

    let version = (payload[0] >> 3) & 0b111;
    if !(1..=4).contains(&version) {
        return Err(format!(
            "has NTP version {version}, outside the 1..=4 range"
        ));
    }
    Ok(())
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
/// somewhere confusing — as it did, once, with a TOML error about a map where a
/// sequence was expected. Naming the exclusion here keeps that a one-line fact
/// rather than a rediscovery.
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
