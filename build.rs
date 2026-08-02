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

use schema::{MAX_COMPILED_REGEX_BYTES, ServiceDefinition};

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
        let compiled = pattern::compile(&rule.pattern, MAX_COMPILED_REGEX_BYTES)
            .unwrap_or_else(|e| {
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
