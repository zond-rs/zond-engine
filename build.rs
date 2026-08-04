// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

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
//! canonical definitions in `src/core/models/fingerprint.rs`, so the build-time
//! and runtime views can never drift apart.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// The authoring schema, shared verbatim with the runtime. Kept in an inner
/// module so its items don't leak into the build script's namespace.
mod schema {
    include!("src/core/models/fingerprint.rs");
}

/// The pattern-compilation logic, shared verbatim with the runtime so the build
/// accepts *exactly* the patterns the engine can match — including the
/// backref/lookaround patterns that fall back to the bounded fancy engine. If it
/// compiles here, the runtime can compile it; if it fails here, it never ships.
///
/// Loaded via `#[path]` (rather than `include!`) so the file's own module docs
/// are honoured — `include!` forbids the inner `//!` comments it carries.
#[path = "src/fingerprinting/pattern.rs"]
mod pattern;

use schema::{MAX_COMPILED_REGEX_BYTES, MAX_UDP_PROBE_BYTES, ServiceDefinition, unescape};

fn main() {
    println!("cargo:rerun-if-changed=assets/fingerprinting");
    println!("cargo:rerun-if-changed=src/core/models/fingerprint.rs");

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo");
    let dest_path = Path::new(&out_dir).join("fingerprints.bin");

    let mut toml_files = Vec::new();
    collect_toml_files(Path::new("assets/fingerprinting"), &mut toml_files);
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
        services.push(def);
    }

    let encoded = bincode::serialize(&services).expect("failed to serialize fingerprint database");
    fs::write(&dest_path, encoded).expect("failed to write fingerprint database");
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
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_toml_files(&path, files);
        } else if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            files.push(path);
        }
    }
}
