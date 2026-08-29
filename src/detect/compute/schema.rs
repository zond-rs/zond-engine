// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A compute detection, as it is authored
//!
//! A Tier-2 detection on disk: the shared `[detection]`
//! [manifest](crate::detect::manifest) — identical to a flow's — followed by a
//! `[compute]` section carrying the body. It is a sibling of the flow corpus in
//! the same `assets/detect/` directory; the build tells the two apart by which
//! body a file carries, `[[step]]` for a flow and `[compute]` for a module, and
//! the identical manifest is what makes "one corpus, two tiers" true at the file
//! level.
//!
//! ## Inline or a sibling file
//!
//! The body is written one of two ways, and exactly one:
//!
//! - `source` — the code inline, the default for a small module a contributor
//!   authors in one file.
//! - `body` — the name of a sibling file the code lives in, for a module large
//!   enough to want its own file with editor support, and the only form a future
//!   binary (WebAssembly) body can take at all.
//!
//! The build resolves a `body` reference to its source and normalises every
//! module to the inline form before embedding, so the runtime only ever sees
//! `source` — the file reference is an authoring convenience the corpus does not
//! carry.

// `build.rs` compiles this file to validate the module corpus; the runtime reads
// the embedded, normalised form, so a field only the build reads (a `body`
// reference, resolved away before runtime) is not dead — it is read in the build
// script, where this same lint would not fire.
#![allow(dead_code)]

use serde::Deserialize;

use super::manifest::Manifest;

/// A whole compute-detection file: the shared manifest, then its body.
#[derive(Debug, Clone, Deserialize)]
pub struct ComputeDetection {
    pub detection: Manifest,
    pub compute: ComputeSection,
}

/// `[compute]` — the body of a Tier-2 detection and the language it is written in.
#[derive(Debug, Clone, Deserialize)]
pub struct ComputeSection {
    pub language: Language,
    /// The code inline. Exactly one of `source` or [`body`](Self::body) is set.
    #[serde(default)]
    pub source: Option<String>,
    /// The name of a sibling file the code lives in, resolved to `source` at
    /// build. Exactly one of [`source`](Self::source) or this is set.
    #[serde(default)]
    pub body: Option<String>,
}

/// The language a compute body is written in. Rhai today; the enum is the room
/// for a WebAssembly body, whose bytes could only ever be a sibling file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Rhai,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> ComputeDetection {
        toml::from_str(toml).expect("a valid compute detection parses")
    }

    const MANIFEST: &str = r#"
        [detection]
        id = "example"
        version = "1.0.0"
        title = "Example"
        [detection.when]
        service = "http"
        [detection.capabilities]
        class = "passive"
    "#;

    #[test]
    fn an_inline_body_reads_its_source() {
        let detection = parse(&format!(
            "{MANIFEST}\n[compute]\nlanguage = \"rhai\"\nsource = '''\nfn analyze(ctx, responses) {{ [] }}\n'''\n"
        ));
        assert_eq!(detection.detection.id, "example");
        assert_eq!(detection.compute.language, Language::Rhai);
        assert!(
            detection
                .compute
                .source
                .as_deref()
                .unwrap()
                .contains("fn analyze")
        );
        assert!(detection.compute.body.is_none());
    }

    #[test]
    fn a_file_body_reads_its_reference() {
        let detection = parse(&format!(
            "{MANIFEST}\n[compute]\nlanguage = \"rhai\"\nbody = \"example.rhai\"\n"
        ));
        assert_eq!(detection.compute.body.as_deref(), Some("example.rhai"));
        assert!(detection.compute.source.is_none());
    }
}
