// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Fingerprinting corpus regression tests
//!
//! Locks matching behaviour against silent regression. Two layers:
//!
//! 1. **Self-consistency** — 95% of signature rules ship a recorded `example`
//!    banner they are meant to match. [`every_signature_matches_its_example`]
//!    runs every example through the real compiled matcher and asserts the
//!    count of non-matching examples stays at a known baseline. A signature
//!    edit that breaks (or fixes) an example moves the count and fails the test,
//!    forcing a conscious baseline change.
//!
//! 2. **Golden end-to-end** — [`golden_cases_resolve_end_to_end`] drives real
//!    banners of well-known services through the whole pipeline
//!    (port-linked matcher selection → matching → resolution) and pins the exact
//!    service/product/version verdict.
//!
//! ## Known baseline
//!
//! 218 recorded examples do not match their own pattern. Spot-checks show these
//! are overwhelmingly **case** mismatches (e.g. `"MIPS"` vs `mips`,
//! `"FTP server"` vs `FTP Server`): the imported rapid7/recog signatures carry a
//! per-pattern case-insensitivity flag that was dropped on import. Restoring it
//! (a re-import that preserves `flags`, not a blanket case-fold, which would add
//! false positives) is tracked in the redesign RFC. Until then the baseline is
//! pinned so the number cannot silently grow.

use rayon::prelude::*;

use crate::core::models::fingerprint::{MatchRule, ServiceDefinition, ServiceSignature};

use super::{Analyzer, BannerRegexAnalyzer, PortContext, ServiceMatcher, ServiceVerdict, SignatureDb};

/// Recorded examples that do not match their own pattern today. See the module
/// docs: these are imported signatures whose case flag was lost. Ratchet this
/// down as they are fixed; a change that raises it is a regression.
const KNOWN_EXAMPLE_MISMATCHES: usize = 218;

/// Builds a matcher for a single rule, so a failure names exactly one signature.
fn single_rule_matcher(service: &ServiceSignature, rule: &MatchRule) -> ServiceMatcher {
    ServiceMatcher::compile(&ServiceDefinition {
        service: service.clone(),
        probe: Vec::new(),
        r#match: vec![rule.clone()],
    })
}

#[test]
fn every_signature_matches_its_example() {
    let defs = SignatureDb::global().definitions();

    let cases: Vec<(&ServiceSignature, &MatchRule, &str)> = defs
        .iter()
        .flat_map(|def| {
            def.r#match.iter().filter_map(move |rule| {
                rule.example
                    .as_deref()
                    .filter(|ex| !ex.is_empty())
                    .map(|ex| (&def.service, rule, ex))
            })
        })
        .collect();

    // Compile+match each example in parallel; compilation dominates the cost.
    let mut mismatches: Vec<String> = cases
        .par_iter()
        .filter_map(|(service, rule, example)| {
            let matcher = single_rule_matcher(service, rule);
            matcher.identify(example).is_none().then(|| {
                format!(
                    "service='{}' example={example:?} pattern={:?}",
                    service.name, rule.pattern
                )
            })
        })
        .collect();
    mismatches.sort();

    assert_eq!(
        mismatches.len(),
        KNOWN_EXAMPLE_MISMATCHES,
        "example-match count changed (found {}, baseline {KNOWN_EXAMPLE_MISMATCHES}). If you \
         changed signatures, review the delta and update KNOWN_EXAMPLE_MISMATCHES.\nFirst \
         mismatches:\n{}",
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
fn golden_cases_resolve_end_to_end() {
    struct Case {
        port: u16,
        response: &'static str,
        service: &'static str,
        product: Option<&'static str>,
        version: Option<&'static str>,
    }

    // Real banners of well-known services, driven through the whole pipeline via
    // the analyzer (no socket). These pin the critical path exactly.
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
    ];

    for case in cases {
        let evidence =
            BannerRegexAnalyzer.analyze(&PortContext { port: case.port }, &[case.response.to_string()]);
        let verdict = ServiceVerdict::resolve(evidence);

        assert_eq!(
            verdict.service.as_deref(),
            Some(case.service),
            "service mismatch for {:?}",
            case.response
        );
        if let Some(product) = case.product {
            assert_eq!(
                verdict.product.as_deref(),
                Some(product),
                "product mismatch for {:?}",
                case.response
            );
        }
        if let Some(version) = case.version {
            assert_eq!(
                verdict.version.as_deref(),
                Some(version),
                "version mismatch for {:?}",
                case.response
            );
        }
    }
}
