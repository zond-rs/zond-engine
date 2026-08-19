// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Signatures
//!
//! One [`Signature`] is a single service pattern plus the metadata to turn a
//! match into [`Evidence`]. Signatures are the flat, globally-indexed unit the
//! rest of the engine works in: the port index and the prefilter both address
//! them by index, so a candidate set from either can be matched uniformly.
//!
//! A signature's regex is compiled **lazily, once, on first match**, guarded by
//! a `OnceLock` — never eagerly for the whole set, never per connection. Which
//! engine compiles it (the linear `regex` engine, or the bounded `fancy-regex`
//! backtracking engine for backref/lookaround patterns) is decided by
//! [`pattern::compile`](super::pattern::compile); see that module for the
//! selection and safety rules. The signature set is validated at build time
//! (see `build.rs`) with the same logic and size limit, so in a correctly built
//! binary compilation never fails; the `None` branch is defence in depth and is
//! logged, not silently dropped.

use std::sync::OnceLock;

use crate::fingerprinting::os::OsMetadata;
use crate::fingerprinting::signature::{MAX_COMPILED_REGEX_BYTES, MatchRule};
use crate::warn;

use super::model::{Confidence, Evidence, SourceId};
use super::pattern::{self, CompiledPattern};

/// A single service signature: metadata, its pattern, and its lazily-compiled
/// regex.
pub struct Signature {
    service: String,
    product: Option<String>,
    vendor: Option<String>,
    /// 1-based capture group holding the version string, if any.
    version_group: Option<u8>,
    pattern: String,
    /// `None` until first use; `Some(None)` if the pattern failed to compile.
    compiled: OnceLock<Option<CompiledPattern>>,

    /// What this rule says about the operating system underneath the service,
    /// where it says anything.
    ///
    /// Boxed, and absent on most signatures: 2290 of the 4732 shipped rules name
    /// no operating system, and a scan holds every signature at once. Kept at all
    /// because dropping it is what made a full imported OS corpus invisible to
    /// the engine that compiled it.
    os: Option<Box<OsMetadata>>,
}

impl Signature {
    /// Builds a signature from a rule owned by `service`. Stores metadata only —
    /// no regex is compiled until [`Signature::identify`] is first called.
    pub fn new(service: &str, rule: &MatchRule) -> Self {
        Self {
            service: service.to_string(),
            product: rule.product.clone(),
            vendor: rule.vendor.clone(),
            version_group: rule.version_group,
            pattern: rule.pattern.clone(),
            compiled: OnceLock::new(),
            os: rule
                .metadata
                .as_ref()
                .and_then(OsMetadata::from_map)
                .map(Box::new),
        }
    }

    /// What this signature says about the operating system, before its templates
    /// are resolved against a match.
    pub fn os_metadata(&self) -> Option<&OsMetadata> {
        self.os.as_deref()
    }

    /// The raw pattern, for build-time literal extraction by the prefilter.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Compiles the regex on first call and caches it. Returns `None` if neither
    /// engine can compile the pattern (logged once).
    pub fn compile(&self) {
        self.compiled();
    }

    fn compiled(&self) -> Option<&CompiledPattern> {
        self.compiled
            .get_or_init(
                || match pattern::compile(&self.pattern, MAX_COMPILED_REGEX_BYTES) {
                    Ok(compiled) => Some(compiled),
                    Err(e) => {
                        warn!(
                            "Fingerprint signature for service '{}' was skipped: its pattern \
                             failed to compile ({e}); pattern = {:?}",
                            self.service, self.pattern
                        );
                        None
                    }
                },
            )
            .as_ref()
    }

    /// Matches `response`, returning the [`Evidence`] it yields paired with a
    /// [`MatchQuality`] for ranking it against other signatures that match the
    /// same response. `None` if the pattern does not match.
    pub fn identify(&self, response: &str) -> Option<Match> {
        // Capture groups are collected only for a signature whose operating-system
        // metadata has templates to fill from them. Most have neither, and this
        // runs against every candidate signature for every banner.
        let wants_captures = self.os.is_some();
        let matched = self.compiled()?.identify_with_captures(
            response,
            self.version_group,
            wants_captures,
        )?;
        let version = matched.version;

        // A captured version is a materially stronger signal than a bare match.
        let confidence = if version.is_some() {
            Confidence::Strong
        } else {
            Confidence::Probable
        };

        // Detail counts the identity fields the signature *itself* supplies,
        // beyond what confidence already conveys — an explicit product and an
        // explicit vendor. It breaks ties between equal-confidence matches so a
        // signature that names a product outranks a bare protocol match.
        let detail = self.product.is_some() as u8 + self.vendor.is_some() as u8;

        let mut evidence = Evidence::new(SourceId::BannerRegex, confidence)
            .with_service(self.service.clone())
            // Fall back to the service name as product when the rule names none.
            .with_product(self.product.clone().unwrap_or_else(|| self.service.clone()));
        evidence.vendor = self.vendor.clone();
        evidence.version = version;

        Some(Match {
            evidence,
            quality: MatchQuality { confidence, detail },
            os: self.os.as_deref().and_then(|metadata| {
                super::os::banner_evidence(metadata, matched.captures.as_deref().unwrap_or(&[]))
            }),
        })
    }
}

/// A signature's successful match against a response: the [`Evidence`] it
/// yields, paired with the [`MatchQuality`] used to choose the most specific
/// match when several signatures match the same response.
pub struct Match {
    pub evidence: Evidence,
    pub quality: MatchQuality,
    /// What this match says about the operating system underneath the service,
    /// with its templates already resolved against the capture groups.
    ///
    /// A separate field rather than more fields on [`Evidence`] because it
    /// answers a different question and is resolved by a different set of rules.
    /// A banner identifies a *service*; that it also implies a host is a second
    /// inference, weaker than the first, and one a caller uninterested in
    /// operating systems should be able to ignore entirely.
    pub os: Option<crate::fingerprinting::os::OsEvidence>,
}

/// How specific a signature's match is, for ranking competing matches against
/// one response. Ordered least-to-most specific.
///
/// `confidence` is compared first: a captured version (`Strong`) is the
/// strongest identity signal, so it outranks any versionless match regardless
/// of other fields. Within one confidence level, `detail` — the number of
/// identity fields the signature supplies (an explicit product, a vendor) —
/// breaks the tie, so a specific `Server: Apache` match outranks a bare
/// `HTTP/1.1` protocol match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MatchQuality {
    confidence: Confidence,
    detail: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str, version_group: Option<u8>, product: Option<&str>) -> MatchRule {
        MatchRule {
            name: None,
            pattern: pattern.to_string(),
            version_group,
            vendor: None,
            product: product.map(str::to_string),
            context: None,
            example: None,
            metadata: None,
        }
    }

    #[test]
    fn captures_version_and_reports_strong_confidence() {
        let sig = Signature::new(
            "ssh",
            &rule(r"^SSH-[\d.]+-OpenSSH_([\w.]+)", Some(1), Some("OpenSSH")),
        );
        let ev = sig
            .identify("SSH-2.0-OpenSSH_9.6p1 Debian")
            .expect("should match")
            .evidence;
        assert_eq!(ev.service.as_deref(), Some("ssh"));
        assert_eq!(ev.product.as_deref(), Some("OpenSSH"));
        assert_eq!(ev.version.as_deref(), Some("9.6p1"));
        assert_eq!(ev.confidence, Confidence::Strong);
    }

    #[test]
    fn bare_match_is_probable_and_defaults_product() {
        let sig = Signature::new("http", &rule("^HTTP/1.1", None, None));
        let ev = sig
            .identify("HTTP/1.1 200 OK")
            .expect("should match")
            .evidence;
        assert_eq!(ev.confidence, Confidence::Probable);
        assert_eq!(ev.product.as_deref(), Some("http"));
    }

    #[test]
    fn specific_match_outranks_generic_for_same_response() {
        let response = "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n";
        // Generic protocol match: no version, no explicit product/vendor.
        let generic = Signature::new("http", &rule(r"(?i)^HTTP/\d+\.\d+\s+\d+", None, None));
        // Specific server match: captures a version and names product + vendor.
        let mut nginx_rule = rule(r"(?i)Server:\s*nginx/([\d.]+)", Some(1), Some("nginx"));
        nginx_rule.vendor = Some("NGINX".to_string());
        let nginx = Signature::new("http", &nginx_rule);

        let generic_q = generic.identify(response).expect("generic matches").quality;
        let nginx_q = nginx.identify(response).expect("nginx matches").quality;
        assert!(nginx_q > generic_q, "specific match must outrank generic");
    }

    #[test]
    fn no_match_returns_none() {
        let sig = Signature::new("http", &rule("^HTTP/1.1", None, None));
        assert!(sig.identify("SSH-2.0-OpenSSH_9.6").is_none());
    }

    #[test]
    fn backreference_signature_matches_via_the_fancy_engine() {
        // A backreference: unsupported by the linear engine, so this signature
        // only identifies at all because of the backtracking fallback. It used
        // to be rejected outright at build time.
        let sig = Signature::new("dup", &rule(r"^(\w+) \1$", None, None));
        assert!(sig.identify("token token").is_some());
        assert!(sig.identify("token other").is_none());
    }

    #[test]
    fn unsupported_pattern_is_skipped_not_fatal() {
        // A genuine syntax error that neither engine can compile: identification
        // yields nothing rather than panicking.
        let sig = Signature::new("x", &rule("(", None, None));
        assert!(sig.identify("aa").is_none());
    }
}
