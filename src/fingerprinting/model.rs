// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Fingerprinting Domain Model
//!
//! The vocabulary every detector in the fingerprinting subsystem speaks.
//!
//! A detector's job is to turn raw response data into [`Evidence`]: an
//! independent, provenance-tagged observation about what a port is running. A
//! regex banner match, a parsed TLS certificate, and an HTTP header scrape all
//! produce the same `Evidence`, so they compose without knowing about one
//! another. [`ServiceVerdict`] is how a set of evidence is reconciled into a
//! single answer, retaining the evidence it was drawn from for explainability.
//!
//! These types are deliberately independent of *how* evidence is produced, so
//! adding a new kind of detector never changes them.

use crate::core::models::port::Service;

/// How much trust to place in a single piece of [`Evidence`].
///
/// Ordered weakest-to-strongest, so evidence can be compared and ranked
/// directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Confidence {
    /// A guess from context alone, e.g. the registered name for a port number
    /// with no probing performed.
    #[default]
    Heuristic,
    /// A plausible but non-authoritative signal.
    Weak,
    /// A signature matched, but the match is generic (no product/version).
    Probable,
    /// A specific signature matched, yielding product and/or version detail.
    Strong,
    /// Effectively certain: the service self-identified unambiguously.
    Certain,
}

impl Confidence {
    /// Projects onto the `0..=100` confidence scale used by [`Service`].
    pub fn as_score(self) -> u8 {
        match self {
            Confidence::Heuristic => 0,
            Confidence::Weak => 40,
            Confidence::Probable => 70,
            Confidence::Strong => 90,
            Confidence::Certain => 100,
        }
    }
}

/// Which detector produced a piece of [`Evidence`].
///
/// Retained on every observation for provenance, resolver tie-breaking, and
/// per-analyzer metrics. New analyzers add a variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceId {
    /// The registered name for the port number, with no probing.
    PortHeuristic,
    /// A regex signature matched a banner or active-probe response.
    BannerRegex,
    /// A TLS certificate was captured and parsed from the port.
    TlsCert,
    /// A structured parse of an HTTP response's headers.
    HttpHeaders,
    // Future analyzers: Jarm, Ssh, Snmp, Favicon, ...
}

/// A transport the observed traffic was carried *inside*.
///
/// When an analyzer identifies a protocol from data read through a tunnel, the
/// verdict records it here so the label can reflect both facts (e.g. `ssl/http`)
/// while `Evidence::service` stays the bare protocol for downstream use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tunnel {
    /// A completed TLS handshake — the payload was decrypted before analysis.
    Tls,
}

impl Tunnel {
    /// The scheme prefix this tunnel contributes to a service label.
    fn scheme(self) -> &'static str {
        match self {
            Tunnel::Tls => "ssl",
        }
    }
}

/// One independent observation about what a port is running.
///
/// Every descriptive field is optional: a detector reports only what it
/// actually learned. The resolver merges fields across evidence, so a TLS
/// analyzer supplying `product` and a banner analyzer supplying `version` combine
/// into one verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub vendor: Option<String>,
    /// A CPE identifier, when known. Kept as a string until a typed CPE model
    /// lands; forward-compatible with structured parsing later.
    pub cpe: Option<String>,
    /// The transport this observation was read through, if any. Set when the
    /// data was decrypted from a tunnel (e.g. banner matched inside TLS).
    pub tunnel: Option<Tunnel>,
    pub confidence: Confidence,
    pub source: SourceId,
}

impl Evidence {
    /// Begins an evidence record from `source` at `confidence`, with no fields
    /// populated yet.
    pub fn new(source: SourceId, confidence: Confidence) -> Self {
        Self {
            service: None,
            product: None,
            version: None,
            vendor: None,
            cpe: None,
            tunnel: None,
            confidence,
            source,
        }
    }

    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    pub fn with_product(mut self, product: impl Into<String>) -> Self {
        self.product = Some(product.into());
        self
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn with_vendor(mut self, vendor: impl Into<String>) -> Self {
        self.vendor = Some(vendor.into());
        self
    }

    /// Records the tunnel this observation was read through.
    pub fn with_tunnel(mut self, tunnel: Tunnel) -> Self {
        self.tunnel = Some(tunnel);
        self
    }
}

/// The reconciled answer for a port, plus the full evidence it was drawn from.
///
/// Keeping every contributing [`Evidence`] (not just the winner) is deliberate:
/// provenance is a product feature — it makes results explainable and
/// signatures tunable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceVerdict {
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub cpe: Option<String>,
    /// The tunnel the winning `service` was observed through, if any. Drives the
    /// `ssl/…` label in [`ServiceVerdict::to_service`].
    pub tunnel: Option<Tunnel>,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
}

impl ServiceVerdict {
    /// Reconciles independent observations into one verdict.
    ///
    /// Evidence is ranked strongest-first; each field is filled from the
    /// highest-confidence observation that carries it, so different analyzers
    /// can contribute different fields. Ties preserve insertion order, keeping
    /// the result deterministic. The full evidence set is retained.
    pub fn resolve(mut evidence: Vec<Evidence>) -> Self {
        // Stable sort keeps equal-confidence evidence in the order produced,
        // so results do not depend on analyzer scheduling.
        evidence.sort_by_key(|e| std::cmp::Reverse(e.confidence));

        let mut verdict = ServiceVerdict {
            confidence: evidence
                .first()
                .map(|e| e.confidence)
                .unwrap_or(Confidence::Heuristic),
            ..Default::default()
        };

        for ev in &evidence {
            // The tunnel travels with the service field: whichever evidence
            // first supplies the service also decides how it is labelled.
            if verdict.service.is_none() && ev.service.is_some() {
                verdict.tunnel = ev.tunnel;
            }
            fill(&mut verdict.service, &ev.service);
            fill(&mut verdict.version, &ev.version);
            fill(&mut verdict.vendor, &ev.vendor);
            fill(&mut verdict.cpe, &ev.cpe);
        }

        // Product needs more than "first that carries it". A product that merely
        // echoes the service ("http" for service http) is what a *generic* match
        // emits — the `generic_http` signature, the matcher's product-defaults-
        // to-service fallback, a protocol baseline. It conveys no product, so it
        // must not bury a real name ("cloudflare", bare "nginx") that a more
        // specific analyzer supplied at the *same* confidence. Prefer the
        // highest-confidence product that names something beyond the service;
        // fall back to the echo only when nothing more specific exists.
        verdict.product = evidence
            .iter()
            .filter_map(|ev| ev.product.as_deref())
            .find(|product| Some(*product) != verdict.service.as_deref())
            .or_else(|| evidence.iter().find_map(|ev| ev.product.as_deref()))
            .map(str::to_string);

        verdict.evidence = evidence;
        verdict
    }

    /// Whether the verdict names nothing identifiable.
    pub fn is_empty(&self) -> bool {
        self.service.is_none() && self.product.is_none()
    }

    /// Projects the verdict onto the crate's [`Service`] model, if it names
    /// anything. Returns `None` for an empty verdict.
    ///
    /// A tunnelled service is labelled `<scheme>/<name>` (e.g. `ssl/http`),
    /// keeping both observed facts visible — the protocol *and* that it was
    /// carried inside TLS — without renaming the bare protocol. An untunnelled
    /// service, or the tunnel's own `ssl` verdict, is labelled plainly.
    pub fn to_service(&self) -> Option<Service> {
        let name = self.service.clone().or_else(|| self.product.clone())?;
        let name = match self.tunnel {
            Some(tunnel) => format!("{}/{name}", tunnel.scheme()),
            None => name,
        };
        let mut service = Service::new(name, self.confidence.as_score());
        if let Some(product) = &self.product {
            service = service.with_product(product.clone());
        }
        if let Some(version) = &self.version {
            service = service.with_version(version.clone());
        }
        Some(service)
    }
}

/// Fills `slot` from `value` only if `slot` is empty and `value` is present.
fn fill(slot: &mut Option<String>, value: &Option<String>) {
    if slot.is_none()
        && let Some(v) = value
    {
        *slot = Some(v.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(conf: Confidence) -> Evidence {
        Evidence::new(SourceId::BannerRegex, conf)
    }

    #[test]
    fn confidence_is_ordered() {
        assert!(Confidence::Certain > Confidence::Strong);
        assert!(Confidence::Strong > Confidence::Probable);
        assert!(Confidence::Probable > Confidence::Heuristic);
    }

    #[test]
    fn resolve_prefers_strongest_evidence_per_field() {
        let weak = ev(Confidence::Weak)
            .with_service("http")
            .with_product("generic");
        let strong = ev(Confidence::Strong)
            .with_service("http")
            .with_product("nginx");
        let verdict = ServiceVerdict::resolve(vec![weak, strong]);

        assert_eq!(verdict.product.as_deref(), Some("nginx"));
        assert_eq!(verdict.confidence, Confidence::Strong);
        assert_eq!(verdict.evidence.len(), 2);
    }

    #[test]
    fn informative_product_beats_a_service_echo_at_equal_confidence() {
        // A generic match names product == service ("http"); a specific analyzer
        // names the real server ("cloudflare"). Both Probable. Even with the
        // generic one first (as `generic_http` sorts ahead of later analyzers),
        // the real name must win the product slot.
        let generic = ev(Confidence::Probable)
            .with_service("http")
            .with_product("http");
        let specific = ev(Confidence::Probable)
            .with_service("http")
            .with_product("cloudflare");
        let verdict = ServiceVerdict::resolve(vec![generic, specific]);

        assert_eq!(verdict.service.as_deref(), Some("http"));
        assert_eq!(verdict.product.as_deref(), Some("cloudflare"));
    }

    #[test]
    fn service_echo_product_is_kept_when_nothing_more_specific_exists() {
        // With no informative product available, the echo is still surfaced
        // rather than dropping the product entirely.
        let verdict = ServiceVerdict::resolve(vec![
            ev(Confidence::Probable)
                .with_service("http")
                .with_product("http"),
        ]);
        assert_eq!(verdict.product.as_deref(), Some("http"));
    }

    #[test]
    fn resolve_merges_fields_across_evidence() {
        let a = ev(Confidence::Strong)
            .with_service("https")
            .with_product("nginx");
        let b = ev(Confidence::Probable).with_version("1.25.3");
        let verdict = ServiceVerdict::resolve(vec![a, b]);

        assert_eq!(verdict.product.as_deref(), Some("nginx"));
        assert_eq!(verdict.version.as_deref(), Some("1.25.3"));
    }

    #[test]
    fn empty_verdict_maps_to_no_service() {
        assert!(ServiceVerdict::resolve(Vec::new()).to_service().is_none());
    }

    #[test]
    fn tunnel_prefixes_the_service_label_and_travels_with_service() {
        let tunnelled = ev(Confidence::Strong)
            .with_service("http")
            .with_product("nginx")
            .with_tunnel(Tunnel::Tls);
        let verdict = ServiceVerdict::resolve(vec![tunnelled]);
        assert_eq!(verdict.service.as_deref(), Some("http")); // bare on the verdict
        assert_eq!(verdict.tunnel, Some(Tunnel::Tls));
        assert_eq!(verdict.to_service().unwrap().name(), "ssl/http"); // composed label

        // Without a tunnel the label is plain.
        let plain = ev(Confidence::Strong).with_service("http");
        let verdict = ServiceVerdict::resolve(vec![plain]);
        assert_eq!(verdict.tunnel, None);
        assert_eq!(verdict.to_service().unwrap().name(), "http");
    }

    #[test]
    fn verdict_projects_onto_service_model() {
        let verdict = ServiceVerdict::resolve(vec![
            ev(Confidence::Strong)
                .with_service("ssh")
                .with_product("OpenSSH")
                .with_version("9.6"),
        ]);
        let service = verdict.to_service().expect("names a service");
        assert_eq!(service.confidence(), Confidence::Strong.as_score());
    }
}
