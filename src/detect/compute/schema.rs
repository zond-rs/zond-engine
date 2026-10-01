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
//! [manifest](crate::detect::manifest), then a `[compute]` section carrying the
//! body. It lives beside the flows in `assets/detect/`; a `[compute]` section
//! marks a module and `[[step]]` a flow.
//!
//! ## Inline or a sibling file
//!
//! Exactly one of:
//!
//! - `source`, the code inline.
//! - `body`, the name of a sibling file holding the code.
//!
//! The build resolves `body` to inline `source` before embedding, so the runtime
//! only sees `source`.

// `body` is read only by `build.rs`, which compiles this file too.
#![allow(dead_code)]

use serde::Deserialize;

use super::manifest::DetectionManifest;

/// A whole compute-detection file: the shared manifest, then its body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeDetection {
    /// The `[detection]` table: identity, the port gate, and the class and budget
    /// the module asks for, identical to a flow's.
    pub detection: DetectionManifest,
    /// The `[compute]` body and the language it is written in.
    pub compute: ComputeSection,
}

/// `[compute]`, the body of a Tier-2 detection and the language it is written in.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeSection {
    /// The language the body is written in.
    pub language: Language,
    /// The code inline. Exactly one of `source` or [`body`](Self::body) is set.
    #[serde(default)]
    pub source: Option<String>,
    /// The name of a sibling file the code lives in, resolved to `source` at
    /// build. Exactly one of [`source`](Self::source) or this is set.
    #[serde(default)]
    pub body: Option<String>,
}

/// The language a compute body is written in.
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
