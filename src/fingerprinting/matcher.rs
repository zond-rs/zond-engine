// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Signature Matching
//!
//! Turns a service's signatures into compiled matchers that produce
//! [`Evidence`] from a response.
//!
//! Compilation is the expensive step, and it happens exactly once per service,
//! on first use, driven by the [`SignatureDb`](super::db::SignatureDb) cache —
//! never eagerly for the whole set, and never per connection. A pattern the
//! engine cannot compile is logged and skipped, never dropped silently, so
//! coverage gaps are observable.
//!
//! [`ServiceMatcher`] is the seam a faster backend slots behind. Today it runs
//! each compiled regex in turn; a future prefilter (or a `hyperscan` backend)
//! can replace the internals without changing the [`super`] orchestration.

use regex::{Regex, RegexBuilder};

use crate::core::models::fingerprint::{MAX_COMPILED_REGEX_BYTES, MatchRule, ServiceDefinition};
use crate::warn;

use super::model::{Confidence, Evidence, SourceId};

/// One service signature with its regex compiled and the metadata needed to
/// turn a match into [`Evidence`].
struct CompiledSignature {
    pattern: Regex,
    service: String,
    product: Option<String>,
    vendor: Option<String>,
    /// 1-based capture group holding the version string, if any.
    version_group: Option<u8>,
}

impl CompiledSignature {
    /// Compiles one rule, or logs and returns `None` if its pattern is not
    /// supported by the engine (e.g. backreferences). Never drops silently.
    ///
    /// The signature set is validated at build time (see `build.rs`) with the
    /// same size limit, so in a correctly built binary this never fails; the
    /// fallback exists only as defence in depth.
    fn compile(service: &str, rule: &MatchRule) -> Option<Self> {
        match RegexBuilder::new(&rule.pattern)
            .size_limit(MAX_COMPILED_REGEX_BYTES)
            .build()
        {
            Ok(pattern) => Some(Self {
                pattern,
                service: service.to_string(),
                product: rule.product.clone(),
                vendor: rule.vendor.clone(),
                version_group: rule.version_group,
            }),
            Err(e) => {
                warn!(
                    "Fingerprint signature for service '{service}' was skipped: its pattern \
                     failed to compile ({e}); pattern = {:?}",
                    rule.pattern
                );
                None
            }
        }
    }

    /// Produces evidence if this signature matches `response`.
    fn evidence(&self, response: &str) -> Option<Evidence> {
        let captures = self.pattern.captures(response)?;

        let version = self
            .version_group
            .and_then(|group| captures.get(group as usize))
            .map(|m| m.as_str().to_string());

        // A captured version is a materially stronger signal than a bare match.
        let confidence = if version.is_some() {
            Confidence::Strong
        } else {
            Confidence::Probable
        };

        let mut evidence = Evidence::new(SourceId::BannerRegex, confidence)
            .with_service(self.service.clone())
            // Fall back to the service name as product when the rule names none,
            // preserving the prior engine's behaviour.
            .with_product(self.product.clone().unwrap_or_else(|| self.service.clone()));
        evidence.vendor = self.vendor.clone();
        evidence.version = version;
        Some(evidence)
    }
}

/// A single service's signatures, compiled once.
///
/// This is the unit the [`SignatureDb`](super::db::SignatureDb) caches per
/// service. Constructing one compiles its regexes; matching against it is
/// allocation-light.
pub struct ServiceMatcher {
    service: String,
    signatures: Vec<CompiledSignature>,
}

impl ServiceMatcher {
    /// Compiles every signature in `def`. Unsupported patterns are logged and
    /// omitted (see [`CompiledSignature::compile`]).
    pub fn compile(def: &ServiceDefinition) -> Self {
        let signatures = def
            .r#match
            .iter()
            .filter_map(|rule| CompiledSignature::compile(&def.service.name, rule))
            .collect();

        Self {
            service: def.service.name.clone(),
            signatures,
        }
    }

    /// The service this matcher identifies.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Returns evidence from the first signature that matches `response`, or
    /// `None` if none do.
    pub fn identify(&self, response: &str) -> Option<Evidence> {
        self.signatures
            .iter()
            .find_map(|signature| signature.evidence(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::fingerprint::{MatchRule, ServiceSignature};

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

    fn def(name: &str, rules: Vec<MatchRule>) -> ServiceDefinition {
        ServiceDefinition {
            service: ServiceSignature {
                name: name.to_string(),
                default_ports: vec![0],
                description: None,
                attribution: None,
            },
            probe: Vec::new(),
            r#match: rules,
        }
    }

    #[test]
    fn captures_version_and_reports_strong_confidence() {
        let matcher = ServiceMatcher::compile(&def(
            "ssh",
            vec![rule(r"^SSH-[\d.]+-OpenSSH_([\w.]+)", Some(1), Some("OpenSSH"))],
        ));

        let ev = matcher
            .identify("SSH-2.0-OpenSSH_9.6p1 Debian")
            .expect("should match");
        assert_eq!(ev.service.as_deref(), Some("ssh"));
        assert_eq!(ev.product.as_deref(), Some("OpenSSH"));
        assert_eq!(ev.version.as_deref(), Some("9.6p1"));
        assert_eq!(ev.confidence, Confidence::Strong);
    }

    #[test]
    fn bare_match_is_probable() {
        let matcher = ServiceMatcher::compile(&def("http", vec![rule("^HTTP/1.1", None, None)]));
        let ev = matcher.identify("HTTP/1.1 200 OK").expect("should match");
        assert_eq!(ev.confidence, Confidence::Probable);
        // Product defaults to the service name when the rule names none.
        assert_eq!(ev.product.as_deref(), Some("http"));
    }

    #[test]
    fn no_match_returns_none() {
        let matcher = ServiceMatcher::compile(&def("http", vec![rule("^HTTP/1.1", None, None)]));
        assert!(matcher.identify("SSH-2.0-OpenSSH_9.6").is_none());
    }

    #[test]
    fn unsupported_pattern_is_skipped_not_fatal() {
        // Backreferences are unsupported by the `regex` engine; compilation must
        // skip the rule rather than panic or abort.
        let matcher = ServiceMatcher::compile(&def("x", vec![rule(r"(a)\1", None, None)]));
        assert!(matcher.identify("aa").is_none());
    }
}
