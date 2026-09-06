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
//! Unlike a [flow](crate::detect::flow), a module is code and must be compiled.
//! That happens here, once, when the database is first asked for: each body is
//! loaded through the [`RhaiRuntime`](super::RhaiRuntime), and the runtime and the
//! compiled set are held together, because the [stage](super::stage) needs both to
//! run them. A body that will not compile aborts the load, the same policy the flow
//! and host loaders hold on a corpus that will not re-parse: the shipped corpus is
//! proven to compile by a test, so a failure is a broken build to surface loudly,
//! not a detection to drop and leave a scan quietly reporting a clean bill it did
//! not earn.

use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

use crate::fingerprint::PortContext;
use crate::model::finding::Finding;
use crate::record::wire;

use super::budget::RunOutcome;
use super::record::DetectionRunRecord;
use super::rhai::{RhaiModule, RhaiRuntime};
use super::runtime::{ComputeRuntime, LoadError, ModuleBody};
use super::schema::ComputeDetection;
use super::stage::{self, LoadedDetection};

/// Why a recorded detection run could not be replayed, or how the replay ended.
///
/// Replay used to collapse every one of these into an empty result, so a caller
/// could not tell a detection that faulted on replay from one that ran clean and
/// found nothing. Each is now its own answer.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplayError {
    /// The corpus no longer holds the detection this record names, matched by
    /// content hash, so a changed or removed detection is never reproduced by a
    /// different one.
    #[error("the corpus no longer holds the detection this run named")]
    UnknownDetection,
    /// The record names a transport this build does not know.
    #[error("the run names a transport this build does not know: {0}")]
    UnknownTransport(String),
    /// The detection's identity would not resolve into a grant. A corpus refuses an
    /// empty id at build, so a shipped detection never reaches this.
    #[error("the detection's identity would not resolve into a grant")]
    GrantFailed,
    /// The module could not be instantiated for the replay.
    #[error("the module could not be instantiated for replay: {0}")]
    Instantiate(#[source] LoadError),
    /// The replay ran and ended abnormally, exactly as the live run would have. The
    /// [`RunOutcome`] it carries is the same one the live run would have recorded.
    #[error("the replay ended abnormally rather than reproducing the run")]
    Run(RunOutcome),
    /// The tape ran short: the module read more from it than the recording holds,
    /// so the replay diverged from the run that was recorded. A faithful replay of
    /// the same detection over a complete tape never does this; a truncated journal
    /// does.
    #[error("the tape was too short to reproduce the run")]
    Diverged,
}

/// The validated, normalised module corpus, compiled from `assets/detect/` by
/// `build.rs`.
const EMBEDDED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/detect_modules.bin"));

/// The process-wide compute database, decoded and compiled once on first use.
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
        DB.get_or_init(ComputeDb::from_embedded)
    }

    /// The embedded corpus, compiled fresh on its own runtime. The default
    /// [`Detections`](crate::detect::Detections) holds one of these.
    pub(crate) fn from_embedded() -> ComputeDb {
        let runtime = RhaiRuntime::new();
        let detections = load_embedded(&runtime);
        ComputeDb {
            runtime,
            detections,
        }
    }

    /// A database over `runtime` and an explicit detection set, for a caller
    /// assembling a corpus of their own. The modules must already be compiled on a
    /// runtime whose bounds match; a Rhai `AST` is portable across runtimes.
    pub(crate) fn from_parts(
        runtime: RhaiRuntime,
        detections: Vec<LoadedDetection<RhaiModule>>,
    ) -> ComputeDb {
        ComputeDb {
            runtime,
            detections,
        }
    }

    /// The runtime the corpus was compiled with, which the stage runs modules on.
    pub(crate) fn runtime(&self) -> &RhaiRuntime {
        &self.runtime
    }

    /// Every module in the corpus.
    pub(crate) fn detections(&self) -> &[LoadedDetection<RhaiModule>] {
        &self.detections
    }

    /// The loaded detection whose body has this content hash, so a journalled run
    /// replays against the exact detection that produced it.
    pub(crate) fn detection_by_hash(
        &self,
        content_hash: &str,
    ) -> Option<&LoadedDetection<RhaiModule>> {
        self.detections
            .iter()
            .find(|detection| detection.content_hash() == content_hash)
    }
}

/// Replays one journalled detection run offline, reproducing the findings it
/// produced, with no network.
///
/// The `Err` half names why: the corpus no longer holds the exact detection that
/// ran (matched by content hash, so a changed or removed detection is never
/// reproduced by a different one), the record names an unknown transport, the
/// replay ran and faulted or hit a bound, or the tape was too short to reproduce
/// the run. A changed detection is never silently reproduced by a different one.
pub fn replay_run(run: &DetectionRunRecord) -> Result<Vec<Finding>, ReplayError> {
    let db = ComputeDb::global();
    let detection = db
        .detection_by_hash(&run.detection.content_hash)
        .ok_or(ReplayError::UnknownDetection)?;
    let protocol = wire::protocol(&run.protocol)
        .ok_or_else(|| ReplayError::UnknownTransport(run.protocol.clone()))?;

    let addr = run
        .host
        .parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, run.port));
    let ctx = PortContext {
        port: run.port,
        protocol,
        addr,
        tunnel: None,
        speaks_http: false,
    };

    let responses: Vec<Vec<u8>> = run
        .responses
        .iter()
        .cloned()
        .map(String::into_bytes)
        .collect();
    let slices: Vec<&[u8]> = responses.iter().map(Vec::as_slice).collect();

    stage::replay_over_tape(db.runtime(), detection, &ctx, &slices, run.tape.rebuild())
}

/// Compiles one embedded module into a runnable detection.
///
/// Every failure is a corpus the build validated but the runtime could not load: a
/// parse, a normalisation, or a compile the build's own checks passed. Each panics,
/// naming the cause, rather than shipping a corpus quietly short a detection, which
/// for a security tool is a false negative worse than a loud abort. The corpus test
/// proves none of these can happen for what ships; this is the guard for a build
/// that broke the invariant, and it is the same policy the flow and host loaders
/// hold on a corpus that will not re-parse.
fn load_module(
    runtime: &RhaiRuntime,
    content_hash: &str,
    toml: &str,
) -> LoadedDetection<RhaiModule> {
    let detection: ComputeDetection = toml::from_str(toml)
        .expect("an embedded module was validated at build but did not re-parse at runtime");
    let source = detection
        .compute
        .source
        .expect("the build normalises every module to an inline source");
    let module = runtime.load(&ModuleBody::Rhai(source)).unwrap_or_else(|error| {
        panic!(
            "the embedded module '{}' was validated at build but did not compile at runtime: {error}",
            detection.detection.id
        )
    });
    LoadedDetection::new(detection.detection, module, content_hash)
}

/// Decodes the embedded module corpus and compiles each body on `runtime`.
pub(crate) fn load_embedded(runtime: &RhaiRuntime) -> Vec<LoadedDetection<RhaiModule>> {
    let entries: Vec<(String, String)> =
        bincode::deserialize(EMBEDDED).expect("embedded module database failed to deserialize");
    entries
        .into_iter()
        .map(|(content_hash, toml)| load_module(runtime, &content_hash, &toml))
        .collect()
}

/// Compiles one caller-supplied compute detection on `runtime`, reporting why it
/// could not be rather than skipping it. Only an inline `source` is accepted: a
/// `body` file reference is a build-time convenience the runtime never resolves.
pub(crate) fn compile_compute_source(
    runtime: &RhaiRuntime,
    toml: &str,
    content_hash: &str,
) -> Result<LoadedDetection<RhaiModule>, String> {
    use crate::detect::flow::validate::{RESERVED_ID_PREFIX, is_version_triple};

    let detection: ComputeDetection = toml::from_str(toml).map_err(|error| error.to_string())?;
    let manifest = &detection.detection;
    if manifest.id.trim().is_empty() {
        return Err("a compute detection needs a non-empty id".to_string());
    }
    if manifest.id.starts_with(RESERVED_ID_PREFIX) {
        return Err(format!(
            "a compute detection id `{}` claims the reserved `{RESERVED_ID_PREFIX}` namespace",
            manifest.id
        ));
    }
    if !is_version_triple(&manifest.version) {
        return Err(format!(
            "a compute detection has version `{}`, not a major.minor.patch triple",
            manifest.version
        ));
    }
    let source = detection
        .compute
        .source
        .ok_or_else(|| "a compute detection needs an inline `source`".to_string())?;
    let module = runtime
        .load(&ModuleBody::Rhai(source))
        .map_err(|error| error.to_string())?;
    Ok(LoadedDetection::new(
        detection.detection,
        module,
        content_hash,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DetectionEnvelope;
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
            speaks_http: false,
        }
    }

    #[test]
    fn the_embedded_corpus_compiles_every_module_it_ships() {
        let embedded: Vec<(String, String)> =
            bincode::deserialize(EMBEDDED).expect("the module database decodes");
        assert!(!embedded.is_empty(), "the module corpus is empty");

        // Reaching this proves every body compiled: `load_module` panics on one
        // that does not, so a broken corpus fails here loudly rather than loading
        // short. The count is then exact, one detection per embedded entry.
        let db = ComputeDb::global();
        assert_eq!(
            db.detections().len(),
            embedded.len(),
            "the module corpus did not load one detection per embedded entry"
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
                |_, _| {},
            )
            .findings
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

        // A bare redirect to HTTPS, what a port-80 Caddy or nginx answers with. It
        // has none of the four, but its headers are not the site's, so grading it
        // reports the redirector rather than the page. No finding.
        let redirect = b"HTTP/1.1 308 Permanent Redirect\r\n\
            Location: https://example.com/\r\n\
            Content-Length: 0\r\n\r\n";
        assert!(
            !run(redirect)
                .iter()
                .any(|f| f.detection().id() == "http-missing-security-headers"),
            "a bare http-to-https redirect was graded as a missing-headers finding"
        );
    }

    #[test]
    fn a_journalled_run_of_a_shipped_detection_replays() {
        use crate::detect::compute::{CapTape, CapTapeRecord, DetectionRunRecord};
        use crate::record::DetectionIdRecord;

        let db = ComputeDb::global();
        let detection = db
            .detections()
            .iter()
            .find(|d| d.manifest().id == "http-missing-security-headers")
            .expect("the http detection ships");

        // A run of that exact detection over a bare response, as the journal holds
        // it. The detection is passive, so its tape is empty and the response is the
        // whole input; replaying it reproduces the finding with no network.
        let run = DetectionRunRecord {
            host: "127.0.0.1".to_string(),
            port: 80,
            protocol: "tcp".to_string(),
            detection: DetectionIdRecord {
                id: "http-missing-security-headers".to_string(),
                version: "1.0.0".to_string(),
                content_hash: detection.content_hash().to_string(),
            },
            responses: vec![
                "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n".to_string(),
            ],
            tape: CapTapeRecord::from(&CapTape::default()),
        };

        let findings = replay_run(&run).expect("the run replays against the shipped detection");
        assert!(
            findings
                .iter()
                .any(|f| f.detection().id() == "http-missing-security-headers"),
            "the replay did not reproduce the finding"
        );
    }
}
