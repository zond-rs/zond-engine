// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The compute-module database
//!
//! `build.rs` validates each `[compute]` detection in `assets/detect/`, inlines
//! any body file, hashes the source, and embeds the result. This module decodes
//! and compiles them once, for the [detection stage](super::stage).
//!
//! ## Compiled once, at first use
//!
//! Each body is loaded through the [`RhaiRuntime`], held together with the
//! compiled set since the [stage] needs both. A body that will not compile
//! aborts the load, as the flow and host loaders do; a test proves the shipped
//! corpus compiles, so a failure is a broken build.

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
/// Kept distinct from an empty result, which means a clean run found nothing.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplayError {
    /// The corpus no longer holds the detection this record names, matched by
    /// content hash.
    #[error("the corpus no longer holds the detection this run named")]
    UnknownDetection,
    /// The record names a transport this build does not know.
    #[error("the run names a transport this build does not know: {0}")]
    UnknownTransport(String),
    /// The detection's identity would not resolve into a grant (an empty id,
    /// which the build refuses).
    #[error("the detection's identity would not resolve into a grant")]
    GrantFailed,
    /// The module could not be instantiated for the replay.
    #[error("the module could not be instantiated for replay: {0}")]
    Instantiate(#[source] LoadError),
    /// The replay ended abnormally, with the [`RunOutcome`] the live run would
    /// have recorded.
    #[error("the replay ended abnormally rather than reproducing the run")]
    Run(RunOutcome),
    /// The module read past the end of the tape, so the replay diverged (a
    /// truncated journal, for one).
    #[error("the tape was too short to reproduce the run")]
    Diverged,
}

/// The validated, normalised module corpus, compiled from `assets/detect/` by
/// `build.rs`.
const EMBEDDED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/detect_modules.bin"));

/// The process-wide compute database, decoded and compiled once on first use.
static DB: OnceLock<ComputeDb> = OnceLock::new();

/// The runtime that compiled the module corpus, and the compiled detections.
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

    /// A database over `runtime` and an explicit detection set. The modules must
    /// be compiled on a runtime whose bounds match; a Rhai `AST` is portable.
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
/// The `Err` half names why: the exact detection (by content hash) is gone, the
/// transport is unknown, the replay faulted or hit a bound, or the tape was too
/// short.
pub fn replay_run(run: &DetectionRunRecord) -> Result<Vec<Finding>, ReplayError> {
    let db = ComputeDb::global();
    let detection = db
        .detection_by_hash(&run.detection.content_hash)
        .ok_or(ReplayError::UnknownDetection)?;
    let protocol = wire::protocol(&run.protocol)
        .ok_or_else(|| ReplayError::UnknownTransport(run.protocol.clone()))?;

    // `ctx.exposure` is derived from this recorded address, so it replays as it
    // ran without being journalled separately.
    let addr = run
        .host
        .parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, run.port));
    // The detection level is irrelevant offline.
    let ctx = PortContext {
        port: run.port,
        protocol,
        addr,
        tunnel: None,
        speaks_http: false,
        detection: crate::config::ServiceDetection::default(),
        host_name: run.host_name.clone(),
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
/// # Panics
///
/// On any parse, normalisation or compile failure of a body the build accepted,
/// naming the cause; a silently missing detection would be a false negative.
/// The corpus test proves the shipped corpus loads.
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

/// Compiles one caller-supplied compute detection on `runtime`, or says why it
/// could not. Only inline `source` is accepted; the runtime does not resolve
/// `body`.
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

    /// Capabilities for a passive detection, which uses none.
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
            detection: crate::config::ServiceDetection::default(),
            host_name: None,
        }
    }

    #[test]
    fn the_embedded_corpus_compiles_every_module_it_ships() {
        let embedded: Vec<(String, String)> =
            bincode::deserialize(EMBEDDED).expect("the module database decodes");
        assert!(!embedded.is_empty(), "the module corpus is empty");

        // `load_module` panics on a body that will not compile, so reaching this
        // proves every one did.
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

        // None of the baseline headers: low. Never medium, since a missing header
        // is a missing mitigation, not a way in.
        let bare = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n";
        let findings = run(bare);
        let finding = findings
            .iter()
            .find(|f| f.detection().id() == "http-missing-security-headers")
            .expect("the header detection fired on a bare response");
        assert_eq!(finding.severity(), Severity::Low);

        // One header short: a rung down.
        let mostly = b"HTTP/1.1 200 OK\r\n\
            Strict-Transport-Security: max-age=31536000\r\n\
            Content-Security-Policy: default-src 'self'\r\n\
            X-Frame-Options: DENY\r\n\r\n";
        let findings = run(mostly);
        let finding = findings
            .iter()
            .find(|f| f.detection().id() == "http-missing-security-headers")
            .expect("one missing header is still reported");
        assert_eq!(finding.severity(), Severity::Info);

        // All four: no finding.
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

        // A bare redirect to HTTPS (a port-80 Caddy or nginx): its headers are not
        // the site's. No finding.
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

    /// **A nonce policy is not a weak policy.**
    ///
    /// CSP Level 3 has a nonce deployment add `'unsafe-inline'` for old
    /// browsers, which ignore the nonce; browsers that understand the nonce
    /// ignore `'unsafe-inline'`. The header is an Arris router's: nonce,
    /// `'strict-dynamic'`, `object-src 'none'` and `base-uri 'none'`.
    #[test]
    fn a_nonce_governed_policy_is_not_graded_for_the_unsafe_inline_beside_the_nonce() {
        let db = ComputeDb::global();
        let csp = |policy: &str| {
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Security-Policy: {policy}\r\nContent-Length: 0\r\n\r\n"
            );
            super::super::stage::detect_port(
                db.runtime(),
                db.detections(),
                &DetectionEnvelope::default(),
                Some("http"),
                &http_ctx(),
                &[response.as_bytes()],
                |_grant| Some(Box::new(NoCaps)),
                |_, _| {},
            )
            .findings
            .into_iter()
            .find(|f| f.detection().id() == "http-weak-csp")
        };

        // Nonce with `'strict-dynamic'`. `img-src *` is not a script source; the
        // only gap is `style-src 'unsafe-inline'`, a rung below a script failure.
        let arris = "default-src 'self' 'nonce-abc' ; img-src *; \
                     style-src 'self' 'unsafe-inline'; \
                     script-src 'strict-dynamic' 'unsafe-inline' 'nonce-abc' http: https:; \
                     base-uri 'none'; object-src 'none';";
        let finding = csp(arris).expect("the inline style is a real gap and is reported");
        assert_eq!(finding.severity(), Severity::Low);
        assert!(
            finding.excerpt().as_str().contains("style-src"),
            "the finding named something other than the inline style: {}",
            finding.excerpt().as_str()
        );
        assert!(
            !finding.excerpt().as_str().contains("script-src"),
            "a nonce-governed script-src was graded: {}",
            finding.excerpt().as_str()
        );

        // A nonce alone cancels it too, and so does a hash.
        assert!(
            csp("script-src 'nonce-abc' 'unsafe-inline'").is_none(),
            "a nonce did not cancel the `'unsafe-inline'` beside it"
        );
        assert!(
            csp("script-src 'sha256-abc' 'unsafe-inline'").is_none(),
            "a hash did not cancel the `'unsafe-inline'` beside it"
        );
    }

    /// Weak policies are still found, each named by its directive.
    #[test]
    fn a_policy_that_permits_inline_script_or_any_origin_is_still_graded() {
        let db = ComputeDb::global();
        let csp = |policy: &str| {
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Security-Policy: {policy}\r\nContent-Length: 0\r\n\r\n"
            );
            super::super::stage::detect_port(
                db.runtime(),
                db.detections(),
                &DetectionEnvelope::default(),
                Some("http"),
                &http_ctx(),
                &[response.as_bytes()],
                |_grant| Some(Box::new(NoCaps)),
                |_, _| {},
            )
            .findings
            .into_iter()
            .find(|f| f.detection().id() == "http-weak-csp")
        };

        // Inline script with no nonce or hash.
        let bare_inline = csp("default-src 'self'; script-src 'self' 'unsafe-inline'")
            .expect("inline script with no nonce is a weakness");
        assert_eq!(bare_inline.severity(), Severity::Medium);

        // `'unsafe-eval'` is not cancelled by a nonce: a nonce says nothing about
        // the strings `eval` is handed.
        let eval = csp("script-src 'nonce-abc' 'unsafe-eval'")
            .expect("`'unsafe-eval'` is a weakness beside a nonce");
        assert_eq!(eval.severity(), Severity::Medium);

        // A wildcard script source permits any script from anywhere.
        let wild = csp("script-src *").expect("a script wildcard is a weakness");
        assert_eq!(wild.severity(), Severity::Medium);

        // A host-pattern wildcard names a domain; `img-src *` is not scripts.
        assert!(
            csp("default-src 'self'; script-src 'self' *.example.com; img-src *").is_none(),
            "a host pattern or an image wildcard was read as permitting any script"
        );

        // A policy governing no script at all, whatever else it says.
        let ungoverned =
            csp("img-src 'self'; style-src 'self'").expect("no script-src and no default-src");
        assert_eq!(ungoverned.severity(), Severity::Medium);

        // A directive whose name merely starts with another's is not that one.
        assert!(
            csp("default-src 'self'; script-src-elem 'self' 'unsafe-inline'").is_none(),
            "`script-src-elem` was read as `script-src`"
        );
    }

    /// **The cookie finding names the flag that is actually missing.**
    ///
    /// A missing `HttpOnly` (script access to the session) ranks above a missing
    /// `Secure` alone.
    #[test]
    fn the_cookie_finding_names_the_flag_that_is_missing_and_grades_by_it() {
        let db = ComputeDb::global();
        let cookie = |header: &str| {
            let response =
                format!("HTTP/1.1 200 OK\r\nSet-Cookie: {header}\r\nContent-Length: 0\r\n\r\n");
            super::super::stage::detect_port(
                db.runtime(),
                db.detections(),
                &DetectionEnvelope::default(),
                Some("http"),
                &http_ctx(),
                &[response.as_bytes()],
                |_grant| Some(Box::new(NoCaps)),
                |_, _| {},
            )
            .findings
            .into_iter()
            .find(|f| f.detection().id() == "http-insecure-cookies")
        };

        // The Arris router's cookie: HttpOnly, no Secure.
        let only_secure = cookie("PHPSESSID=c91c971aadd19d0e; path=/; HttpOnly")
            .expect("a session cookie without Secure is still reported");
        assert_eq!(
            only_secure.title(),
            "A session cookie is set without Secure",
            "the summary named a flag the cookie carries"
        );
        assert_eq!(only_secure.severity(), Severity::Low);

        // Neither flag: both named; `HttpOnly` sets the rank.
        let neither = cookie("PHPSESSID=c91c971aadd19d0e; path=/")
            .expect("a session cookie with no flags is reported");
        assert_eq!(
            neither.title(),
            "A session cookie is set without HttpOnly or Secure"
        );
        assert_eq!(neither.severity(), Severity::Medium);

        // Secure but not HttpOnly.
        let only_httponly = cookie("PHPSESSID=c91c971aadd19d0e; path=/; Secure")
            .expect("a session cookie readable by script is reported");
        assert_eq!(
            only_httponly.title(),
            "A session cookie is set without HttpOnly"
        );
        assert_eq!(only_httponly.severity(), Severity::Medium);

        // Both flags: nothing to report.
        assert!(
            cookie("PHPSESSID=c91c971aadd19d0e; path=/; HttpOnly; Secure").is_none(),
            "a cookie carrying both flags was flagged"
        );
    }

    /// A flag is an attribute, not a substring of the line, and a cookie being
    /// withdrawn is not a session.
    ///
    /// A cookie named `secure_session` does not carry `Secure`, and a logout's
    /// `PHPSESSID=deleted` is not a session.
    #[test]
    fn a_cookie_name_is_not_a_flag_and_a_withdrawn_cookie_is_not_a_session() {
        let db = ComputeDb::global();
        let cookie = |header: &str| {
            let response =
                format!("HTTP/1.1 200 OK\r\nSet-Cookie: {header}\r\nContent-Length: 0\r\n\r\n");
            super::super::stage::detect_port(
                db.runtime(),
                db.detections(),
                &DetectionEnvelope::default(),
                Some("http"),
                &http_ctx(),
                &[response.as_bytes()],
                |_grant| Some(Box::new(NoCaps)),
                |_, _| {},
            )
            .findings
            .into_iter()
            .find(|f| f.detection().id() == "http-insecure-cookies")
        };

        // Missing both flags despite the name.
        let named = cookie("secure_session=abc123; path=/")
            .expect("a cookie whose name contains `secure` still has no flags");
        assert_eq!(
            named.title(),
            "A session cookie is set without HttpOnly or Secure",
            "the cookie's own name was read as its Secure flag"
        );

        // A logout, in three frameworks' spellings.
        for withdrawn in [
            "PHPSESSID=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/",
            "PHPSESSID=; path=/",
            "sessionid=abc; Max-Age=0; path=/",
        ] {
            assert!(
                cookie(withdrawn).is_none(),
                "a cookie being withdrawn was reported as a session: {withdrawn}"
            );
        }

        // A name ending in `sid` is a session identifier; merely containing it is
        // not.
        assert!(
            cookie("residency=London; path=/").is_none(),
            "an ordinary cookie was read as a session identifier"
        );
        assert!(
            cookie("connect.sid=s%3Aabc; path=/").is_some(),
            "a real session cookie was missed"
        );
    }

    /// What the shipped detection `id` finds in `response`, run as a scan runs it.
    fn shipped(id: &str, response: &[u8]) -> Option<crate::model::finding::Finding> {
        let db = ComputeDb::global();
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
        .into_iter()
        .find(|f| f.detection().id() == id)
    }

    /// `body` served as a 200.
    fn served(content_type: &str, body: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n\r\n{body}").into_bytes()
    }

    /// A PEM block under `label`, its body base64 in 64-character lines. The
    /// body is filler, not a key; the header is assembled here so the source
    /// holds no PEM line of its own.
    fn pem(label: &str, line_break: &str) -> String {
        let label = format!("{label} {}", "KEY");
        let line = "MIIEowIBAAKCAQEAzondzondzondzondzondzondzondzondzondzondzondzond";
        let body = [line; 6].join(line_break);
        format!(
            "-----BEGIN {label}-----{line_break}{body}{line_break}QUIDAQAB{line_break}-----END {label}-----"
        )
    }

    /// **A served key is a whole PEM block.** jsencrypt carries the BEGIN and
    /// END lines as strings it builds an export from, so a page bundling it
    /// holds both with script between them and no key.
    #[test]
    fn private_key_served_fires_on_a_pem_block_and_not_on_a_library_that_writes_one() {
        // jsencrypt's export, with its label assembled as `pem` assembles one.
        let jsencrypt = r#"<script>
JSEncryptRSAKey.prototype.getPrivateKey = function () {
    var key = "-----BEGIN RSA PRIVATE {key}-----\n";
    key += wordwrap(this.getPrivateBaseKeyB64()) + "\n";
    key += "-----END RSA PRIVATE {key}-----";
    return key;
};
</script>"#
            .replace("{key}", "KEY");
        assert!(
            shipped("private-key-served", &served("text/html", &jsencrypt)).is_none(),
            "private-key-served read a crypto library's strings as a key"
        );

        for label in ["RSA PRIVATE", "PRIVATE", "OPENSSH PRIVATE"] {
            let finding = shipped(
                "private-key-served",
                &served("text/plain", &pem(label, "\n")),
            )
            .unwrap_or_else(|| panic!("a served {label} KEY block was missed"));
            assert_eq!(finding.severity(), Severity::Critical);
        }
        // Inside a script or JSON string, its lines broken by a written `\n`.
        let in_json = format!("{{\"tls_key\":\"{}\"}}", pem("EC PRIVATE", "\\n"));
        assert!(shipped("private-key-served", &served("application/json", &in_json)).is_some());

        // A BEGIN and an END that do not name the same key.
        let mismatched = pem("RSA PRIVATE", "\n").replace("END RSA", "END EC");
        assert!(shipped("private-key-served", &served("text/plain", &mismatched)).is_none());
    }

    /// **The `none` finding says what was seen:** a token served unsigned. No
    /// forged token is sent, so nothing shows the server accepting one.
    #[test]
    fn jwt_weak_algorithm_reports_a_served_unsigned_token_and_claims_no_more() {
        // `{"alg":"none","typ":"JWT"}` and `{"sub":"1"}`, base64url, no signature.
        let unsigned = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.";
        // The same claims under `{"alg":"HS256","typ":"JWT"}`.
        let signed = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl";
        let token = |jwt: &str| {
            shipped(
                "jwt-weak-algorithm",
                &served("application/json", &format!("{{\"token\":\"{jwt}\"}}")),
            )
        };

        let finding = token(unsigned).expect("an unsigned token was missed");
        assert!(token(signed).is_none(), "a signed token was flagged");

        let manifest = ComputeDb::global()
            .detections()
            .iter()
            .find(|d| d.manifest().id == "jwt-weak-algorithm")
            .expect("the detection ships")
            .manifest();
        for claim in [manifest.title.as_str(), finding.title()] {
            assert!(
                !claim.contains("accept"),
                "`{claim}` claims the server accepts what it was only seen to issue"
            );
        }
    }

    /// **A cookie being withdrawn has no token to guess.** A logout sets a
    /// placeholder and an expiry already past; a live session with a short,
    /// guessable value is still the finding.
    #[test]
    fn session_token_low_entropy_skips_a_withdrawn_cookie_and_grades_a_live_one() {
        let set = |cookie: &str| {
            let response = format!(
                "HTTP/1.1 200 OK\r\nDate: Thu, 01 Oct 2026 09:00:00 GMT\r\n\
                 Set-Cookie: {cookie}\r\nContent-Length: 0\r\n\r\n"
            );
            shipped("session-token-low-entropy", response.as_bytes())
        };

        for withdrawn in [
            // PHP's session_destroy, Django's logout, and a hand-written one.
            "PHPSESSID=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/",
            "sessionid=\"\"; expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/",
            "sessionid=deleted; Path=/",
            "sid=0; Path=/",
            // An expiry before the response's own date, in this year.
            "auth_token=x1; Expires=Wed, 30 Sep 2026 09:00:00 GMT; Path=/",
            "sid=1001; Max-Age=-1",
        ] {
            assert!(
                set(withdrawn).is_none(),
                "a cookie being withdrawn was graded as a weak session: {withdrawn}"
            );
        }

        for live in [
            "sessionid=12345; Max-Age=3600; Path=/",
            "sid=1001; Expires=Fri, 01 Oct 2027 09:00:00 GMT; Path=/",
        ] {
            let finding =
                set(live).unwrap_or_else(|| panic!("a guessable session was missed: {live}"));
            assert_eq!(finding.severity(), Severity::Medium);
        }
        assert!(
            set("residency=EU; Path=/").is_none(),
            "an ordinary cookie was read as a session identifier"
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

        // A journalled passive run: an empty tape, the response the whole input.
        let run = DetectionRunRecord {
            host: "127.0.0.1".to_string(),
            host_name: None,
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
