// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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

use crate::model::confidence::Confidence;
use crate::model::port::Service;

/// Which detector produced a piece of [`Evidence`].
///
/// Retained on every observation for provenance, resolver tie-breaking, and
/// per-analyzer metrics. New analyzers add a variant here.
#[non_exhaustive]
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
    /// An SSH protocol exchange (version banner + `KEXINIT` algorithm lists).
    Ssh,
    // Future analyzers: Jarm, Snmp, Favicon, ...
}

/// A transport the observed traffic was carried *inside*.
///
/// When an analyzer identifies a protocol from data read through a tunnel, the
/// verdict records it here so the label can reflect both facts (e.g. `ssl/http`)
/// while `Evidence::service` stays the bare protocol for downstream use.
#[non_exhaustive]
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
/// Comparable but not [`Eq`]: [`os`](Self::os) carries a confidence, which is a
/// float, and a value nobody can write down exactly is not one two observations
/// should be claimed to share.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    /// The protocol the port was speaking, in the corpus's vocabulary: `http`,
    /// `ssh`, `postgresql`. Bare even when it was read through a tunnel, which
    /// [`tunnel`](Self::tunnel) records separately.
    pub service: Option<String>,
    /// The software behind the protocol, where the observation named it:
    /// `nginx`, `OpenSSH`. Empty when all that was established is which
    /// protocol answered.
    pub product: Option<String>,
    /// The product's version, as the response stated it.
    pub version: Option<String>,
    /// Who publishes the product, such as `Apache Software Foundation`.
    pub vendor: Option<String>,
    /// Supplementary detail that is not the product itself: an environment hint
    /// or a *secondary* technology (an HTTP `X-Powered-By` value like `PHP/8.2`,
    /// an SSH `protocol 2.0`). Kept separate from `product` precisely so it can
    /// never displace the primary product in the resolver.
    pub extrainfo: Option<String>,
    /// A CPE identifier, when known. Kept as a string until a typed CPE model
    /// lands; forward-compatible with structured parsing later.
    pub cpe: Option<String>,
    /// The transport this observation was read through, if any. Set when the
    /// data was decrypted from a tunnel (e.g. banner matched inside TLS).
    pub tunnel: Option<Tunnel>,
    /// Whether this match is corroborated by the port it was found on — i.e. the
    /// signature was one registered for this port, not one found only by global
    /// content search. A port-confirmed match carries a stronger prior (the
    /// service was *expected* here), so the resolver ranks it above a
    /// global-only match of equal confidence. Analyzers that do not consult the
    /// port-signature index leave it `false`.
    pub port_confirmed: bool,
    /// How strongly this observation identifies what is running. The
    /// resolver's primary ranking key, and the strongest observation's value
    /// becomes the verdict's own confidence.
    pub confidence: Confidence,
    /// The detector that made the observation, kept on it for provenance.
    pub source: SourceId,
    /// What this observation said about the *machine*, as distinct from the
    /// service.
    ///
    /// Carried alongside rather than folded into the fields above because it
    /// answers a different question and is resolved by different rules. A banner
    /// identifies a service directly; that it also implies an operating system is
    /// a second, weaker inference — a container names the image it was built
    /// from, not the kernel it runs on. `ServiceVerdict` retains its whole
    /// evidence set, so this reaches a caller without the resolver having to
    /// rank it.
    pub os: Option<crate::model::host::OsEvidence>,
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
            extrainfo: None,
            cpe: None,
            tunnel: None,
            port_confirmed: false,
            os: None,
            confidence,
            source,
        }
    }

    /// Names the protocol this observation identified, returning `self`.
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// Names the software behind the protocol, returning `self`.
    pub fn with_product(mut self, product: impl Into<String>) -> Self {
        self.product = Some(product.into());
        self
    }

    /// Sets the version the response stated, returning `self`.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Sets the product's publisher, returning `self`.
    pub fn with_vendor(mut self, vendor: impl Into<String>) -> Self {
        self.vendor = Some(vendor.into());
        self
    }

    /// Sets the supplementary detail described on
    /// [`extrainfo`](Self::extrainfo), returning `self`. It never becomes the
    /// product.
    pub fn with_extrainfo(mut self, extrainfo: impl Into<String>) -> Self {
        self.extrainfo = Some(extrainfo.into());
        self
    }

    /// Records the tunnel this observation was read through.
    pub fn with_tunnel(mut self, tunnel: Tunnel) -> Self {
        self.tunnel = Some(tunnel);
        self
    }

    /// Sets the platform identifier this observation established.
    ///
    /// Whatever names the CPE should name the product too: a verdict takes the
    /// two from one observation, because a CPE is a whole identity and not a
    /// fragment of one. See [`ServiceVerdict::resolve`].
    pub fn with_cpe(mut self, cpe: impl Into<String>) -> Self {
        self.cpe = Some(cpe.into());
        self
    }

    /// Records what this observation said about the *machine* underneath the
    /// service.
    pub fn with_os(mut self, os: crate::model::host::OsEvidence) -> Self {
        self.os = Some(os);
        self
    }
}

/// The reconciled answer for a port, plus the full evidence it was drawn from.
///
/// Keeping every contributing [`Evidence`] (not just the winner) is deliberate:
/// provenance is a product feature — it makes results explainable and
/// signatures tunable.
/// Comparable but not [`Eq`], for the reason [`Evidence`] is not: the
/// observations it retains carry a confidence, and a float is not something two
/// verdicts should be claimed to share exactly.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ServiceVerdict {
    /// The protocol the port is speaking, from the strongest observation that
    /// named one. Bare, as on [`Evidence`]: the `ssl/…` label belongs to
    /// [`to_service`](Self::to_service).
    pub service: Option<String>,
    /// The software behind the protocol. A product that only repeats the
    /// service name is dropped in resolution, so this is empty unless something
    /// identified the software itself.
    pub product: Option<String>,
    /// The version, which need not have come from the same observation as the
    /// product: a TLS certificate can name the software while a banner states
    /// its release.
    pub version: Option<String>,
    /// Who publishes the product.
    pub vendor: Option<String>,
    /// Supplementary detail beside the product, merged from the evidence: an
    /// environment hint, or a secondary technology such as `PHP/8.2`.
    pub extrainfo: Option<String>,
    /// The platform identifier, with any `{service.version}` template already
    /// resolved against the version found. This is what CVE correlation joins
    /// on.
    pub cpe: Option<String>,
    /// The tunnel the winning `service` was observed through, if any. Drives the
    /// `ssl/…` label in [`ServiceVerdict::to_service`].
    pub tunnel: Option<Tunnel>,
    /// The confidence of the strongest observation, and
    /// [`Confidence::Heuristic`] where there was no observation at all.
    pub confidence: Confidence,
    /// Everything that contributed, strongest first, including observations
    /// none of the fields above were taken from. A caller reads it to explain a
    /// verdict, or to see what disagreed with it.
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
        // Rank strongest-first. Confidence dominates: a genuinely stronger
        // identification is never buried by port context. Within one confidence
        // level, a port-confirmed match (its signature was registered for this
        // port) outranks a global-only one — a coincidental cross-protocol
        // banner match (the classic bare-`220` FTP-vs-SMTP ambiguity) loses to
        // the service actually expected on the port. The sort is stable, so a
        // full tie keeps the order produced and stays independent of analyzer
        // scheduling.
        evidence.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then(b.port_confirmed.cmp(&a.port_confirmed))
        });

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
            fill(&mut verdict.extrainfo, &ev.extrainfo);
        }

        // Product needs more than "first that carries it". A product that merely
        // echoes the service ("http" for service http) is what a *generic* match
        // emits — the `generic_http` signature, a protocol baseline. It conveys
        // no product, so it must not bury a real name ("cloudflare", bare
        // "nginx") that a more specific analyzer supplied at the *same*
        // confidence.
        //
        // An echo is never surfaced, whatever else is present. Reporting `dns`
        // as the software behind DNS is a claim nothing made: it disagrees with
        // every other scanner's answer for the same port, and a comparison then
        // reports a difference between two tools that found the same thing. The
        // one thing an echo is good for — naming the port where no service was
        // identified at all — is already covered, because a product is only an
        // echo when there *is* a service for it to echo.
        let named = evidence
            .iter()
            .filter(|ev| ev.product.is_some())
            .find(|ev| ev.product.as_deref() != verdict.service.as_deref());
        verdict.product = named.and_then(|ev| ev.product.clone());

        // **The platform identifier comes from whichever observation named the
        // product**, and not from whichever happened to carry one first.
        //
        // A CPE is a whole identity rather than a fragment of one: vendor,
        // product and version in a single string, already resolved against its
        // own observation's version. Filled independently of the product, a
        // verdict reported `gunicorn 21.2.0` beside
        // `cpe:/a:apache:http_server:2.4.49` — measured — and `cve` joins on the
        // CPE, so the port was matched against Apache's vulnerabilities while
        // the report named something else entirely. That is a false finding in a
        // security report, which is the most expensive thing this crate can
        // produce.
        //
        // Where nothing named a product there is nothing for a CPE to
        // contradict, so the strongest one stands on its own.
        verdict.cpe = match named {
            Some(ev) => ev.cpe.clone(),
            None => evidence.iter().find_map(|ev| ev.cpe.clone()),
        };

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
        if let Some(vendor) = &self.vendor {
            service = service.with_vendor(vendor.clone());
        }
        if let Some(version) = &self.version {
            service = service.with_version(version.clone());
        }
        if let Some(extrainfo) = &self.extrainfo {
            service = service.with_extrainfo(extrainfo.clone());
        }
        if let Some(cpe) = &self.cpe {
            service = service.with_cpe(cpe.clone());
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

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

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
    fn a_cpe_flows_from_evidence_through_the_verdict_into_the_service() {
        // Before `to_service` carried it, the verdict resolved the cpe and then
        // dropped it on the way to the `Service` — so every service CPE was lost.
        let mut evidence = ev(Confidence::Strong).with_product("nginx");
        evidence.cpe = Some("cpe:/a:nginx:nginx:1.24.0".to_string());

        let verdict = ServiceVerdict::resolve(vec![evidence]);
        assert_eq!(verdict.cpe.as_deref(), Some("cpe:/a:nginx:nginx:1.24.0"));

        let service = verdict.to_service().expect("names a service");
        let cpes: Vec<String> = service.cpes().iter().map(ToString::to_string).collect();
        assert_eq!(cpes.len(), 1, "the verdict's cpe reached the service");
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

    /// A product that merely repeats the service is dropped.
    ///
    /// This reverses an earlier choice, which surfaced the echo "rather than
    /// dropping the product entirely". What that cost only became visible when
    /// two scanners were compared: nmap reports port 53 as `domain / Unbound`
    /// and this engine reported it as `dns / dns`, so a comparison of the two
    /// showed a product changing where both tools had found the same thing and
    /// only one of them had named the software.
    ///
    /// `dns` is not the software behind DNS. Where nothing named a product,
    /// none is named.
    #[test]
    fn a_product_that_only_repeats_the_service_is_dropped() {
        let verdict = ServiceVerdict::resolve(vec![
            ev(Confidence::Probable)
                .with_service("http")
                .with_product("http"),
        ]);

        assert_eq!(verdict.service.as_deref(), Some("http"));
        assert_eq!(verdict.product, None);
    }

    /// And the echo is still what *names* the service where nothing else did,
    /// which is the one thing the earlier choice was protecting.
    #[test]
    fn a_product_with_no_service_beside_it_still_names_the_service() {
        let verdict = ServiceVerdict::resolve(vec![ev(Confidence::Probable).with_product("nginx")]);

        assert_eq!(verdict.product.as_deref(), Some("nginx"));
        assert_eq!(
            verdict.to_service().map(|s| s.name().to_owned()),
            Some("nginx".to_string()),
            "with no service named, the product is what the port is called"
        );
    }

    #[test]
    fn port_confirmed_match_wins_the_service_at_equal_confidence() {
        // Insertion order puts the global match first, so without the
        // port-confirmation tie-break the stable sort would keep "smtp". The
        // port-confirmed "ftp" — the service actually expected on this port —
        // must win. This is the bare-`220` FTP-vs-SMTP residue.
        let global_smtp = ev(Confidence::Probable).with_service("smtp");
        let mut port_ftp = ev(Confidence::Probable).with_service("ftp");
        port_ftp.port_confirmed = true;

        let verdict = ServiceVerdict::resolve(vec![global_smtp, port_ftp]);
        assert_eq!(verdict.service.as_deref(), Some("ftp"));
    }

    #[test]
    fn confidence_still_dominates_port_confirmation() {
        // A weak port-confirmed match must not bury a genuinely stronger global
        // identification — confidence is the primary key, port-confirmation only
        // breaks ties within a level.
        let mut weak_port = ev(Confidence::Probable).with_service("ftp");
        weak_port.port_confirmed = true;
        let strong_global = ev(Confidence::Strong)
            .with_service("smtp")
            .with_product("Postfix");

        let verdict = ServiceVerdict::resolve(vec![weak_port, strong_global]);
        assert_eq!(verdict.service.as_deref(), Some("smtp"));
    }

    /// **A platform identifier belongs to the product it names.**
    ///
    /// The HTTP analyzer never sets a CPE and a banner rule often does, so a
    /// versioned `Server` header outranking a versionless curated rule left the
    /// two fields filled from different observations. Measured:
    /// `product=gunicorn version=21.2.0` beside
    /// `cpe:/a:apache:http_server:2.4.49`, which is the path-traversal release
    /// of httpd. `cve` joins on the CPE, so a port the report named gunicorn was
    /// matched against Apache's vulnerabilities.
    #[test]
    fn a_cpe_never_belongs_to_a_product_the_verdict_did_not_name() {
        let http = ev(Confidence::Strong)
            .with_service("http")
            .with_product("gunicorn")
            .with_version("21.2.0");
        let mut curated = ev(Confidence::Probable)
            .with_service("http")
            .with_product("Apache HTTP Server");
        curated.cpe = Some("cpe:/a:apache:http_server:2.4.49".to_string());

        let verdict = ServiceVerdict::resolve(vec![http, curated]);

        assert_eq!(verdict.product.as_deref(), Some("gunicorn"));
        assert_eq!(
            verdict.cpe, None,
            "the winning product carried no platform identifier, so the verdict has none"
        );
        assert!(
            verdict
                .to_service()
                .expect("names a service")
                .cpes()
                .is_empty(),
            "and nothing reaches the CVE join"
        );
    }

    /// The ordinary case is untouched: one observation names a product and its
    /// identifier together, which is how every curated signature carrying a
    /// `service.cpe23` is written.
    #[test]
    fn a_cpe_travels_with_the_product_that_won() {
        let mut nginx = ev(Confidence::Strong)
            .with_service("http")
            .with_product("nginx")
            .with_version("1.24.0");
        nginx.cpe = Some("cpe:/a:nginx:nginx:1.24.0".to_string());
        let weaker = ev(Confidence::Probable).with_service("http");

        let verdict = ServiceVerdict::resolve(vec![weaker, nginx]);

        assert_eq!(verdict.product.as_deref(), Some("nginx"));
        assert_eq!(verdict.cpe.as_deref(), Some("cpe:/a:nginx:nginx:1.24.0"));
    }

    /// Where nothing named a product there is nothing for an identifier to
    /// contradict, so one that was found still reaches the report.
    #[test]
    fn a_cpe_without_a_product_beside_it_still_stands() {
        let mut bare = ev(Confidence::Probable).with_service("http");
        bare.cpe = Some("cpe:/a:apache:http_server:2.4.58".to_string());

        let verdict = ServiceVerdict::resolve(vec![bare]);

        assert_eq!(verdict.product, None);
        assert_eq!(
            verdict.cpe.as_deref(),
            Some("cpe:/a:apache:http_server:2.4.58")
        );
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
    fn vendor_and_extrainfo_resolve_and_reach_the_service() {
        // Different analyzers contribute different attribution: a Server match
        // names product+vendor, an X-Powered-By match adds a secondary tech.
        // Both must survive resolution and land on the projected Service.
        let server = ev(Confidence::Strong)
            .with_service("http")
            .with_product("Apache")
            .with_vendor("Apache Software Foundation");
        let powered_by = ev(Confidence::Probable)
            .with_service("http")
            .with_extrainfo("PHP/8.2.1");
        let verdict = ServiceVerdict::resolve(vec![server, powered_by]);

        assert_eq!(
            verdict.vendor.as_deref(),
            Some("Apache Software Foundation")
        );
        assert_eq!(verdict.extrainfo.as_deref(), Some("PHP/8.2.1"));

        let service = verdict.to_service().expect("names a service");
        assert_eq!(service.product(), Some("Apache"));
        assert_eq!(service.vendor(), Some("Apache Software Foundation"));
        assert_eq!(service.extrainfo(), Some("PHP/8.2.1"));
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
