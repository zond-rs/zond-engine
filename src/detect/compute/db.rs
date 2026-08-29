// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The compute-module database
//!
//! The compiled Tier-2 corpus the engine embeds and runs at runtime. `build.rs`
//! validates each `[compute]` detection in `assets/detect/`, resolves any body
//! file to inline source, hashes that source, and writes the normalised
//! detection and its hash into the blob included here. This module decodes them
//! once, compiles each body into a runnable module, and hands the set to the
//! [detection stage](super::stage).
//!
//! ## Compiled once, at first use
//!
//! Unlike a [flow](crate::detect::flow), a module is *code* and must be compiled.
//! That happens here, once, when the database is first asked for: each body is
//! loaded through the [`RhaiRuntime`](super::RhaiRuntime), and the runtime and the
//! compiled set are held together, because the [stage](super::stage) needs both to
//! run them. A body that will not compile is skipped with a warning rather than
//! panicking a scan — the shipped corpus is proven to compile by a test, so a skip
//! is a defence, not an expected path.

// The corpus is loaded but not yet run in a scan: the orchestrator that draws on
// it is a later increment, so for now only the tests exercise this.
#![allow(dead_code)]

use std::sync::OnceLock;

use tracing::warn;

use super::rhai::{RhaiModule, RhaiRuntime};
use super::runtime::{ComputeRuntime, ModuleBody};
use super::schema::ComputeDetection;
use super::stage::LoadedDetection;

/// The validated, normalised module corpus, compiled from `assets/detect/` by
/// `build.rs`.
const EMBEDDED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/detect_modules.bin"));

static DB: OnceLock<ComputeDb> = OnceLock::new();

/// The runtime view over the embedded module corpus: the runtime that compiled it
/// and the detections it produced, held together because the stage runs one
/// against the other.
pub(crate) struct ComputeDb {
    runtime: RhaiRuntime,
    detections: Vec<LoadedDetection<RhaiModule>>,
}

impl ComputeDb {
    /// The process-wide database. The first call decodes the embedded blob and
    /// compiles each module; subsequent calls are a pointer read.
    pub(crate) fn global() -> &'static ComputeDb {
        DB.get_or_init(|| {
            let runtime = RhaiRuntime::new();
            let entries: Vec<(String, String)> = bincode::deserialize(EMBEDDED)
                .expect("embedded module database failed to deserialize");
            let detections = entries
                .into_iter()
                .filter_map(|(content_hash, toml)| load_module(&runtime, &content_hash, &toml))
                .collect();
            ComputeDb {
                runtime,
                detections,
            }
        })
    }

    /// The runtime the corpus was compiled with, which the stage runs modules on.
    pub(crate) fn runtime(&self) -> &RhaiRuntime {
        &self.runtime
    }

    /// Every module in the corpus.
    pub(crate) fn detections(&self) -> &[LoadedDetection<RhaiModule>] {
        &self.detections
    }
}

/// Compiles one embedded module into a runnable detection, or [`None`] with a
/// warning if it will not compile — which the corpus test proves cannot happen for
/// what ships.
fn load_module(
    runtime: &RhaiRuntime,
    content_hash: &str,
    toml: &str,
) -> Option<LoadedDetection<RhaiModule>> {
    let detection: ComputeDetection = toml::from_str(toml)
        .expect("an embedded module was validated at build but did not re-parse at runtime");
    let source = detection
        .compute
        .source
        .expect("the build normalises every module to an inline source");
    match runtime.load(&ModuleBody::Rhai(source)) {
        Ok(module) => Some(LoadedDetection::new(
            detection.detection,
            module,
            content_hash,
        )),
        Err(error) => {
            warn!(
                id = detection.detection.id,
                ?error,
                "a shipped module did not compile"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::DetectionEnvelope;
    use crate::detect::compute::{CapError, Capabilities, ScanInstant};
    use crate::fingerprint::PortContext;
    use crate::model::finding::Severity;
    use crate::model::port::Protocol;
    use std::net::IpAddr;

    /// A passive detection reaches for no capability, so the stage's `caps_for`
    /// only has to hand back something; this hands back nothing usable.
    struct NoCaps;
    impl Capabilities for NoCaps {
        fn speak(&mut self, _bytes: &[u8]) -> Result<Vec<u8>, CapError> {
            Ok(Vec::new())
        }
        fn resolve(&mut self, _name: &str) -> Result<Vec<IpAddr>, CapError> {
            Ok(Vec::new())
        }
        fn now(&mut self) -> ScanInstant {
            ScanInstant::from_millis(0)
        }
    }

    fn http_ctx() -> PortContext {
        PortContext {
            port: 80,
            protocol: Protocol::Tcp,
            addr: None,
            tunnel: None,
        }
    }

    #[test]
    fn the_embedded_corpus_compiles_every_module_it_ships() {
        let embedded: Vec<(String, String)> =
            bincode::deserialize(EMBEDDED).expect("the module database decodes");
        assert!(!embedded.is_empty(), "the module corpus is empty");

        // Every embedded entry became a compiled detection: a body that failed to
        // load would be skipped, so an equal count is proof each one compiled.
        let db = ComputeDb::global();
        assert_eq!(
            db.detections().len(),
            embedded.len(),
            "a shipped module did not compile at load"
        );
    }

    #[test]
    fn the_header_detection_flags_a_bare_response_and_clears_a_hardened_one() {
        let db = ComputeDb::global();
        let run = |response: &[u8]| {
            super::super::stage::detect_port(
                db.runtime(),
                db.detections(),
                &DetectionEnvelope::default(),
                Some("http"),
                &http_ctx(),
                &[response],
                |_grant| Some(Box::new(NoCaps)),
            )
        };

        // A response with none of the baseline headers: a finding, and the count of
        // four omitted lands it at medium rather than low.
        let bare = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n";
        let findings = run(bare);
        let finding = findings
            .iter()
            .find(|f| f.detection().id() == "http-missing-security-headers")
            .expect("the header detection fired on a bare response");
        assert_eq!(finding.severity(), Severity::Medium);

        // A response carrying all four: computed clean, no finding.
        let hardened = b"HTTP/1.1 200 OK\r\n\
            Strict-Transport-Security: max-age=31536000\r\n\
            Content-Security-Policy: default-src 'self'\r\n\
            X-Frame-Options: DENY\r\n\
            X-Content-Type-Options: nosniff\r\n\r\n";
        assert!(
            !run(hardened)
                .iter()
                .any(|f| f.detection().id() == "http-missing-security-headers"),
            "a hardened server was flagged"
        );
    }
}
