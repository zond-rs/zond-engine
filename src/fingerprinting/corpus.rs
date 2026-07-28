// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Fingerprinting corpus regression tests
//!
//! Locks matching behaviour against silent regression, in three layers:
//!
//! 1. **Self-consistency** ([`every_signature_matches_its_example`]) — 95% of
//!    signature rules ship a recorded `example` banner they are meant to match.
//!    Every example is run through the real signature and the count of
//!    non-matching examples is pinned to a baseline.
//! 2. **Prefilter soundness** ([`prefilter_never_drops_a_matching_signature`]) —
//!    for every example that matches its pattern, the global-match prefilter
//!    must select that signature as a candidate. This is what makes it safe to
//!    narrow the global set instead of scanning all of it.
//! 3. **Golden end-to-end** ([`golden_cases_resolve_end_to_end`],
//!    [`non_standard_port_is_identified_via_global_fallback`]) — real banners
//!    driven through the whole pipeline with the exact verdict pinned.
//!
//! ## Known baseline
//!
//! 218 recorded examples do not match their own pattern — overwhelmingly **case**
//! mismatches (`"MIPS"` vs `mips`, `"FTP server"` vs `FTP Server`) from imported
//! rapid7/recog signatures whose per-pattern case flag was dropped on import.
//! Restoring it (a re-import that preserves `flags`, not a blanket case-fold) is
//! tracked in the RFC; until then the baseline is pinned so it cannot grow.

use rayon::prelude::*;

use super::db::SignatureDb;
use super::matcher::Signature;
use super::prefilter::{LiteralPrefilter, Prefilter};
use super::response::{ResponseSet, TlsInfo};
use super::{
    Analyzer, BannerRegexAnalyzer, Confidence, PortContext, ServiceVerdict, TlsCertAnalyzer, Tunnel,
};

/// Recorded examples that do not match their own pattern today (lost recog case
/// flags — see the module docs). Ratchet down as fixed; a rise is a regression.
const KNOWN_EXAMPLE_MISMATCHES: usize = 218;

/// The signature set flattened exactly as the runtime builds it, paired with
/// each signature's recorded example (if any).
fn signatures_with_examples() -> (Vec<Signature>, Vec<Option<String>>) {
    let defs = SignatureDb::embedded_definitions();
    let mut signatures = Vec::new();
    let mut examples = Vec::new();
    for def in &defs {
        for rule in &def.r#match {
            signatures.push(Signature::new(&def.service.name, rule));
            examples.push(rule.example.clone().filter(|e| !e.is_empty()));
        }
    }
    (signatures, examples)
}

#[test]
fn every_signature_matches_its_example() {
    let (signatures, examples) = signatures_with_examples();

    let mut mismatches: Vec<String> = signatures
        .par_iter()
        .zip(examples.par_iter())
        .filter_map(|(signature, example)| {
            let example = example.as_deref()?;
            signature
                .identify(example)
                .is_none()
                .then(|| format!("example={example:?} pattern={:?}", signature.pattern()))
        })
        .collect();
    mismatches.sort();

    assert_eq!(
        mismatches.len(),
        KNOWN_EXAMPLE_MISMATCHES,
        "example-match count changed (found {}, baseline {KNOWN_EXAMPLE_MISMATCHES}). If you \
         changed signatures, review the delta and update KNOWN_EXAMPLE_MISMATCHES.\nFirst:\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

#[test]
fn prefilter_never_drops_a_matching_signature() {
    let (signatures, examples) = signatures_with_examples();
    let prefilter = LiteralPrefilter::build(&signatures);

    // For every example that genuinely matches its signature, the prefilter must
    // list that signature as a candidate — otherwise global matching would miss it.
    let violations: usize = signatures
        .par_iter()
        .zip(examples.par_iter())
        .enumerate()
        .filter(|(idx, (signature, example))| {
            let Some(example) = example.as_deref() else {
                return false;
            };
            if signature.identify(example).is_none() {
                return false; // example doesn't match anyway (known baseline)
            }
            !prefilter.candidates(example).contains(idx)
        })
        .count();

    assert_eq!(
        violations, 0,
        "prefilter dropped {violations} matching signature(s)"
    );
}

#[test]
fn golden_cases_resolve_end_to_end() {
    struct Case {
        port: u16,
        response: &'static str,
        service: &'static str,
        product: Option<&'static str>,
        version: Option<&'static str>,
    }

    let cases = [
        Case {
            port: 22,
            response: "SSH-2.0-OpenSSH_9.6p1 Debian-3",
            service: "ssh",
            product: Some("OpenSSH"),
            version: Some("9.6p1"),
        },
        Case {
            port: 22,
            response: "SSH-2.0-dropbear_2022.83",
            service: "ssh",
            product: Some("dropbear"),
            version: Some("2022.83"),
        },
        // Best-match, not first-match: the generic `HTTP/1.1` signature is
        // listed before the `Server: nginx` one and matches this response too,
        // but the more specific match — naming product and version — must win.
        Case {
            port: 80,
            response: "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Type: text/html\r\n\r\n",
            service: "http",
            product: Some("nginx"),
            version: Some("1.25.3"),
        },
    ];

    for case in cases {
        let responses = ResponseSet::from_banners(vec![case.response.to_string()]);
        let evidence = BannerRegexAnalyzer.analyze(
            &PortContext {
                port: case.port,
                tunnel: None,
            },
            &responses,
        );
        let verdict = ServiceVerdict::resolve(evidence);

        assert_eq!(
            verdict.service.as_deref(),
            Some(case.service),
            "service for {:?}",
            case.response
        );
        if let Some(product) = case.product {
            assert_eq!(
                verdict.product.as_deref(),
                Some(product),
                "product for {:?}",
                case.response
            );
        }
        if let Some(version) = case.version {
            assert_eq!(
                verdict.version.as_deref(),
                Some(version),
                "version for {:?}",
                case.response
            );
        }
    }
}

#[test]
fn non_standard_port_is_identified_via_global_fallback() {
    // SSH on an unclaimed high port: no linked signatures, so identification
    // must come from the prefilter-narrowed global fallback.
    let port = 51987;
    assert!(
        SignatureDb::global().signatures_for_port(port).is_empty(),
        "test assumes port {port} is unclaimed"
    );

    let responses = ResponseSet::from_banners(vec!["SSH-2.0-OpenSSH_9.6p1".to_string()]);
    let evidence = BannerRegexAnalyzer.analyze(&PortContext { port, tunnel: None }, &responses);
    let verdict = ServiceVerdict::resolve(evidence);

    assert_eq!(verdict.service.as_deref(), Some("ssh"));
    assert_eq!(verdict.product.as_deref(), Some("OpenSSH"));
    assert_eq!(verdict.version.as_deref(), Some("9.6p1"));
}

/// A recorded self-signed appliance certificate (DER). Subject == issuer,
/// `O=Zond Appliance`, `CN=zond-device.local`. Serves as the parse oracle for
/// the TLS analyzer, mirroring the recorded-banner corpus above.
const SELF_SIGNED_CERT: &[u8] = include_bytes!("testdata/selfsigned.der");

#[test]
fn tls_cert_identifies_self_signed_appliance() {
    let responses = ResponseSet {
        banners: Vec::new(),
        tls: Some(TlsInfo {
            certificates: vec![SELF_SIGNED_CERT.to_vec()],
        }),
    };

    let evidence = TlsCertAnalyzer.analyze(
        &PortContext {
            port: 8443,
            tunnel: Some(Tunnel::Tls),
        },
        &responses,
    );
    let verdict = ServiceVerdict::resolve(evidence);

    // The port is identified as TLS, and the self-signed subject O= names the vendor.
    assert_eq!(verdict.service.as_deref(), Some("ssl"));
    assert_eq!(verdict.vendor.as_deref(), Some("Zond Appliance"));
    assert_eq!(verdict.confidence, Confidence::Probable);
    // The tunnel's own `ssl` verdict is not re-prefixed into `ssl/ssl`, even
    // under a TLS context.
    assert_eq!(verdict.to_service().unwrap().name(), "ssl");
}

#[test]
fn tls_analyzer_is_silent_without_a_certificate() {
    // No TLS captured: the analyzer must produce nothing, not a bare "ssl".
    let responses = ResponseSet::from_banners(vec!["HTTP/1.1 200 OK".to_string()]);
    assert!(
        TlsCertAnalyzer
            .analyze(
                &PortContext {
                    port: 80,
                    tunnel: None,
                },
                &responses,
            )
            .is_empty()
    );
}

#[test]
fn banner_matched_in_a_tunnel_is_labelled_with_scheme() {
    // A protocol identified from data read inside TLS keeps its bare service on
    // the evidence but is labelled `ssl/<proto>` for the user.
    let responses = ResponseSet::from_banners(vec!["SSH-2.0-OpenSSH_9.6p1".to_string()]);
    let ctx = PortContext {
        port: 22,
        tunnel: Some(Tunnel::Tls),
    };
    let evidence = BannerRegexAnalyzer.analyze(&ctx, &responses);
    let verdict = ServiceVerdict::resolve(evidence);

    assert_eq!(verdict.service.as_deref(), Some("ssh")); // evidence stays bare
    assert_eq!(verdict.tunnel, Some(Tunnel::Tls));
    assert_eq!(verdict.to_service().unwrap().name(), "ssl/ssh"); // label composes both
}
