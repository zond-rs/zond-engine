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
//! These types are independent of how evidence is produced, so
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
    /// The MD5 of the icon a web application serves, which the corpus keys
    /// several hundred products on.
    Favicon,
    /// A JARM hash: how a TLS stack answered ten deliberately awkward hellos.
    Jarm,
    /// A structured read of an LDAP directory's root entry, for the names of
    /// the controller serving it.
    Ldap,
    // Future analyzers: Snmp, ...
}

/// A transport the observed traffic was carried *inside*.
///
/// When an analyzer identifies a protocol from data read through a tunnel, the
/// verdict records it here so the label can reflect both facts (e.g. `ssl/http`)
/// while `Evidence::service` stays the bare protocol for downstream use.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tunnel {
    /// A completed TLS handshake, the payload was decrypted before analysis.
    Tls,
}

impl Tunnel {
    /// The scheme prefix this tunnel contributes to a service label.
    fn scheme(self) -> &'static str {
        match self {
            Tunnel::Tls => "ssl",
        }
    }

    /// The tunnel a service label names, the inverse of the `<scheme>/` prefix
    /// [`to_service`](ServiceVerdict::to_service) writes: `ssl/http` is HTTP
    /// carried inside TLS, a bare `http` is no tunnel, and an unknown scheme is
    /// none either.
    ///
    /// The label is where a tunnel survives past fingerprinting: the [`Service`]
    /// model keeps the protocol name and not the transport it was read through,
    /// so the detection phase reads the label back to decide whether to speak to
    /// the port in the clear or through a handshake.
    pub fn from_service_label(label: &str) -> Option<Self> {
        match label.split_once('/') {
            Some(("ssl", _)) => Some(Tunnel::Tls),
            _ => None,
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
    /// A CPE identifier, when known. Kept as a string rather than a typed CPE
    /// model, so parsing it into parts is left to whoever needs them.
    pub cpe: Option<String>,
    /// The transport this observation was read through, if any. Set when the
    /// data was decrypted from a tunnel (e.g. banner matched inside TLS).
    pub tunnel: Option<Tunnel>,
    /// Whether this match is corroborated by the port it was found on, meaning
    /// the signature was registered for this port rather than found only by
    /// global
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
    /// answers a different question and is resolved by different rules. A
    /// banner identifies a service directly; that it also implies an operating
    /// system is a second, weaker inference, a container names the image it was
    /// built from, not the kernel it runs on. `ServiceVerdict` retains its
    /// whole evidence set, so this reaches a caller without the resolver having
    /// to rank it.
    pub os: Option<crate::model::host::OsEvidence>,

    /// The hardware this observation described, where it described any.
    ///
    /// One question further out than [`os`](Self::os), and separate for the same
    /// reason: a NETGEAR ReadyNAS runs Linux, and the box and the system on it
    /// are two facts about one machine rather than one fact told twice. Over
    /// five hundred shipped rules name a box and no system at all.
    pub hardware: Option<crate::model::host::HardwareInfo>,

    /// The names this observation said the machine goes by, where it said any.
    ///
    /// About the machine, as [`os`](Self::os) is, and never folded into the
    /// service's fields: a report masks a name and does not mask a service's
    /// description. An observation that names the machine and identifies
    /// nothing carries the lowest confidence, so it never leads a verdict it
    /// has nothing to say about.
    pub names: Vec<crate::model::host::HostName>,
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
            hardware: None,
            names: Vec::new(),
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

    /// Records the names this observation said the machine goes by.
    pub fn with_names(mut self, names: Vec<crate::model::host::HostName>) -> Self {
        self.names = names;
        self
    }
}

/// The reconciled answer for a port, plus the full evidence it was drawn from.
///
/// Keeping every contributing [`Evidence`] (not just the winner) is deliberate:
/// provenance is a product feature, it makes results explainable and signatures
/// tunable. Comparable but not [`Eq`], for the reason [`Evidence`] is not: the
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
    /// Evidence is ranked strongest-first. The service comes from the strongest
    /// observation that names one; each other field is filled from the
    /// highest-confidence observation that carries it and agrees about the
    /// service, so different analyzers can contribute different fields while a
    /// reading of the reply as some other protocol contributes none. Ties
    /// preserve insertion order, keeping the result deterministic. The full
    /// evidence set is retained, disagreeing observations included.
    pub fn resolve(mut evidence: Vec<Evidence>) -> Self {
        // Rank strongest-first. Confidence dominates: a genuinely stronger
        // identification is never buried by port context. Within one confidence
        // level, a port-confirmed match (its signature was registered for this
        // port) outranks a global-only one, a coincidental cross-protocol
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

        // The tunnel travels with the service field: whichever evidence first
        // supplies the service also decides how it is labelled.
        if let Some(named) = evidence.iter().find(|ev| ev.service.is_some()) {
            verdict.service = named.service.clone();
            verdict.tunnel = named.tunnel;
        }

        // **Only an observation that agrees about the service may describe
        // it.** Every field below says something about the software behind the
        // protocol the verdict names, and an observation that read the reply as
        // a different protocol was describing different software. A Kerberos
        // reply over TCP opens with a zero length byte, which is also how a line
        // printer daemon answers; with the KDC rule winning the service and the
        // printer rule free to fill the product, the port read as Kerberos run
        // by `lpd`. The same holds for any coincidental match a port-confirmed
        // one outranked: the bare `220` that names FTP says nothing about which
        // mail server the SMTP rule thought it was.
        //
        // Agreement is the corpus's judgement, since the names are its
        // vocabulary; see `SignatureDb::agree`. An observation naming no service
        // agrees with every one, and so does every observation where the verdict
        // names none.
        let db = super::db::SignatureDb::global();
        let evidence_agrees =
            |ev: &Evidence| match (verdict.service.as_deref(), ev.service.as_deref()) {
                (Some(service), Some(other)) => db.agree(service, other),
                _ => true,
            };
        let agreeing: Vec<&Evidence> = evidence.iter().filter(|ev| evidence_agrees(ev)).collect();

        for ev in &agreeing {
            fill(&mut verdict.version, &ev.version);
            fill(&mut verdict.vendor, &ev.vendor);
            fill(&mut verdict.extrainfo, &ev.extrainfo);
        }

        // Product needs more than "first that carries it". A product that merely
        // echoes the service ("http" for service http) is what a *generic* match
        // emits, as the `generic_http` protocol baseline does. It conveys
        // no product, so it must not bury a real name ("cloudflare", bare
        // "nginx") that a more specific analyzer supplied at the *same*
        // confidence.
        //
        // An echo is never surfaced, whatever else is present. Reporting `dns`
        // as the software behind DNS is a claim nothing made: it disagrees with
        // every other scanner's answer for the same port, and a comparison then
        // reports a difference between two tools that found the same thing. The
        // one thing an echo is good for, naming the port where no service was
        // identified at all, is already covered, because a product is only an
        // echo when there *is* a service for it to echo.
        let candidates: Vec<&Evidence> = agreeing
            .iter()
            .copied()
            .filter(|ev| ev.product.is_some())
            .filter(|ev| ev.product.as_deref() != verdict.service.as_deref())
            .collect();

        // Where the strongest candidates tie, the one that also states a
        // platform identifier takes the slot. Two observations can read the same
        // bytes and disagree about what to call the result: splitting
        // `Microsoft-IIS/10.0` on its slash yields `Microsoft-IIS` and nothing
        // else, while the corpus rule for the same value yields `IIS` and the
        // CPE. Both carry a version, so both are `Strong`, and left alone the
        // tie would be settled by the order the analyzers happened to push them.
        //
        // A rule that names a vendor, a product and a version is a stricter
        // reading than a split on a separator, so this is the more specific
        // answer winning rather than a preference for the field itself. The list
        // is sorted strongest-first, so the equal-ranked candidates are the run
        // at its head.
        //
        // The version is part of the condition because a versionless CPE is not
        // the thing this is for. `cloudflare` matches a rule bearing
        // `cpe:/a:cloudflare:load_balancing:-`, which no vulnerability entry can
        // join to, and preferring it would bury the header's own word for the
        // sake of an identifier that buys nothing.
        let best = candidates.first().copied();
        let named = best.map(|first| {
            candidates
                .iter()
                .take_while(|ev| {
                    (ev.confidence, ev.port_confirmed) == (first.confidence, first.port_confirmed)
                })
                .find(|ev| ev.cpe.is_some() && ev.version.is_some())
                .copied()
                .unwrap_or(first)
        });
        verdict.product = named.and_then(|ev| ev.product.clone());

        // **The platform identifier comes from whichever observation named the
        // product**, and not from whichever happened to carry one first.
        //
        // A CPE is a whole identity rather than a fragment of one: vendor,
        // product and version in a single string, already resolved against its
        // own observation's version. Filled independently of the product, a
        // verdict can report `gunicorn 21.2.0` beside
        // `cpe:/a:apache:http_server:2.4.49`, measured, and `cve` joins on the
        // CPE, so the port is matched against Apache's vulnerabilities while
        // the report names something else entirely. That is a false finding in
        // a security report, which is the most expensive thing this crate can
        // produce.
        //
        // Where nothing named a product there is nothing for a CPE to
        // contradict, so the strongest one stands on its own.
        // Where the winner has none, one may still be taken from an observation
        // that agrees with what is being reported: same product under another
        // spelling, or a product echoing the service, which names the same
        // software the service does. Elasticsearch is the case that needs it.
        // Its body rule holds the CPE and names `elasticsearch` on service
        // `elasticsearch`, so the echo rule above bars it from the slot, and a
        // favicon hash naming `Search` and holding nothing would take the
        // identifier down with it.
        //
        // An observation that states no product at all is not agreement. It is
        // the absence of a claim, and borrowing from it is how a verdict comes
        // to report `gunicorn 21.2.0` beside an Apache CPE.
        verdict.cpe = match named {
            Some(ev) if ev.cpe.is_some() => ev.cpe.clone(),
            Some(ev) => agreeing
                .iter()
                .filter(|other| other.cpe.is_some())
                .find(|other| {
                    let product = other.product.as_deref();
                    product == ev.product.as_deref() || product == verdict.service.as_deref()
                })
                .and_then(|other| other.cpe.clone()),
            None => agreeing.iter().find_map(|ev| ev.cpe.clone()),
        };

        // An observation may state one name in both slots, so that it survives
        // losing the product tiebreak: an icon names the application, a `Server`
        // value names the listener in front of it, and on a reverse-proxied host
        // only one of them can have the product. Where the same observation won
        // the slot anyway, the second copy is noise.
        if verdict.extrainfo == verdict.product {
            verdict.extrainfo = None;
        }

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
    /// keeping both observed facts visible, the protocol *and* that it was
    /// carried inside TLS, without renaming the bare protocol. An untunnelled
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
        // `to_service` carries the cpe. A verdict that resolved it and then
        // dropped it on the way to the `Service` would lose every service CPE.
        let mut evidence = ev(Confidence::Strong).with_product("nginx");
        evidence.cpe = Some("cpe:/a:nginx:nginx:1.24.0".to_string());

        let verdict = ServiceVerdict::resolve(vec![evidence]);
        assert_eq!(verdict.cpe.as_deref(), Some("cpe:/a:nginx:nginx:1.24.0"));

        let service = verdict.to_service().expect("names a service");
        let cpes: Vec<String> = service.cpes().iter().map(ToString::to_string).collect();
        assert_eq!(cpes.len(), 1, "the verdict's cpe reached the service");
    }

    /// Two observations read the same header and only one of them knows what
    /// the software is. Measured on `Microsoft-IIS/10.0`, where splitting the
    /// value on its slash yields the product `Microsoft-IIS` and no CPE, and the
    /// corpus rule for the same value yields `IIS` and
    /// `microsoft:internet_information_services`. Both carry a version, so both
    /// are `Strong` and neither is port-confirmed: a tie, which left alone would
    /// be settled by the order the analyzer pushed them.
    #[test]
    fn a_tie_for_the_product_goes_to_the_observation_that_knows_the_platform() {
        let mut split = ev(Confidence::Strong)
            .with_service("http")
            .with_product("Microsoft-IIS");
        split.version = Some("10.0".to_string());
        let mut rule = ev(Confidence::Strong)
            .with_service("http")
            .with_product("IIS")
            .with_cpe("cpe:/a:microsoft:internet_information_services:10.0");
        rule.version = Some("10.0".to_string());

        let verdict = ServiceVerdict::resolve(vec![split, rule]);

        assert_eq!(verdict.product.as_deref(), Some("IIS"));
        assert_eq!(
            verdict.cpe.as_deref(),
            Some("cpe:/a:microsoft:internet_information_services:10.0")
        );
    }

    /// A rule whose product echoes the service is not eligible for the product
    /// slot, but its CPE is. Measured on Elasticsearch, where the body rule
    /// names `elasticsearch` on service `elasticsearch` and holds the CPE,
    /// while a favicon hash names `Search` and holds nothing. The echo is not
    /// surfaced as a product, and naming the service is not a reason to discard
    /// the platform identifier.
    #[test]
    fn an_echoing_product_still_supplies_the_platform_identifier() {
        let favicon = ev(Confidence::Strong)
            .with_service("elasticsearch")
            .with_product("Search");
        let body = ev(Confidence::Strong)
            .with_service("elasticsearch")
            .with_product("elasticsearch")
            .with_cpe("cpe:/a:elastic:elasticsearch:7.17.0");

        let verdict = ServiceVerdict::resolve(vec![favicon, body]);

        assert_eq!(verdict.product.as_deref(), Some("Search"));
        assert_eq!(
            verdict.cpe.as_deref(),
            Some("cpe:/a:elastic:elasticsearch:7.17.0"),
            "the echo names the same software the service does, so its CPE agrees"
        );
    }

    /// And the case the coupling exists for. A reverse-proxied host states two
    /// products and only one can have the slot; the CPE may not be taken from
    /// the loser, because `cve` joins on it and the report would name one
    /// product while being matched against another's vulnerabilities.
    #[test]
    fn a_cpe_naming_a_different_product_is_never_borrowed() {
        let front = ev(Confidence::Strong)
            .with_service("http")
            .with_product("gunicorn");
        let behind = ev(Confidence::Probable)
            .with_service("http")
            .with_product("Apache httpd")
            .with_cpe("cpe:/a:apache:http_server:2.4.49");

        let verdict = ServiceVerdict::resolve(vec![front, behind]);

        assert_eq!(verdict.product.as_deref(), Some("gunicorn"));
        assert_eq!(
            verdict.cpe, None,
            "an Apache CPE beside a gunicorn product is a false finding"
        );
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
    /// Surfacing the echo rather than dropping the product entirely has a cost
    /// that shows when two scanners are compared: nmap reports port 53 as
    /// `domain / Unbound`, and an engine surfacing the echo reports it as
    /// `dns / dns`, so a comparison of the two shows a product changing where
    /// both tools found the same thing and only one of them named the software.
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
    /// which is the one thing an echo is good for.
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
        // port-confirmed "ftp", the service actually expected on this port,
        // must win. This is the bare-`220` FTP-vs-SMTP residue.
        let global_smtp = ev(Confidence::Probable).with_service("smtp");
        let mut port_ftp = ev(Confidence::Probable).with_service("ftp");
        port_ftp.port_confirmed = true;

        let verdict = ServiceVerdict::resolve(vec![global_smtp, port_ftp]);
        assert_eq!(verdict.service.as_deref(), Some("ftp"));
    }

    /// A Kerberos reply over TCP opens with a zero length byte, which a line
    /// printer daemon's rule also reads as its own answer. The KDC rule names
    /// the service and no product, so the printer rule was the only one
    /// offering a product, and the port read as Kerberos run by `lpd`. What a
    /// rule for another protocol says about the software is about software
    /// this port is not running.
    #[test]
    fn a_reading_as_another_protocol_describes_nothing_on_the_port() {
        let mut kdc = ev(Confidence::Probable).with_service("kerberos");
        kdc.port_confirmed = true;
        let mut printer = ev(Confidence::Probable)
            .with_service("lpd")
            .with_product("lpd")
            .with_extrainfo("queue default");
        printer.cpe = Some("cpe:/a:example:lpd:-".to_string());

        let verdict = ServiceVerdict::resolve(vec![printer, kdc]);

        assert_eq!(verdict.service.as_deref(), Some("kerberos"));
        assert_eq!(verdict.product, None, "lpd's product is not the KDC's");
        assert_eq!(verdict.extrainfo, None);
        assert_eq!(verdict.cpe, None);
        assert_eq!(
            verdict.evidence.len(),
            2,
            "the disagreement stays on record"
        );
    }

    /// The corpus files some rules under the text they read rather than a
    /// protocol: a certificate subject under `x509`. Such a rule names whatever
    /// software presented the certificate, which on a TLS web port is the web
    /// application, so it still describes the port.
    #[test]
    fn a_rule_filed_under_the_text_it_reads_still_describes_the_port() {
        let web = ev(Confidence::Strong).with_service("http");
        let subject = ev(Confidence::Probable)
            .with_service("x509")
            .with_product("Zond Appliance")
            .with_vendor("Zond");

        let verdict = ServiceVerdict::resolve(vec![web, subject]);

        assert_eq!(verdict.service.as_deref(), Some("http"));
        assert_eq!(verdict.product.as_deref(), Some("Zond Appliance"));
        assert_eq!(verdict.vendor.as_deref(), Some("Zond"));
    }

    #[test]
    fn confidence_still_dominates_port_confirmation() {
        // A weak port-confirmed match must not bury a genuinely stronger global
        // identification. Confidence is the primary key, port-confirmation only
        // breaks ties within a level.
        let mut weak_port = ev(Confidence::Probable).with_service("ftp");
        weak_port.port_confirmed = true;
        let strong_global = ev(Confidence::Strong)
            .with_service("smtp")
            .with_product("Postfix");

        let verdict = ServiceVerdict::resolve(vec![weak_port, strong_global]);
        assert_eq!(verdict.service.as_deref(), Some("smtp"));
    }

    /// A platform identifier belongs to the product it names.
    ///
    /// The HTTP analyzer never sets a CPE and a banner rule often does, so a
    /// versioned `Server` header outranking a versionless curated rule can
    /// leave the two fields filled from different observations. Measured:
    /// `product=gunicorn version=21.2.0` beside
    /// `cpe:/a:apache:http_server:2.4.49`, which is the path-traversal release
    /// of httpd. `cve` joins on the CPE, so a port the report names gunicorn
    /// would be matched against Apache's vulnerabilities.
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

    /// The reverse-proxy case, which is what the second slot exists for: a
    /// `Server` value names the listener and an icon names the application
    /// behind it, and only one of them can hold the product.
    #[test]
    fn an_application_behind_a_server_survives_losing_the_product_slot() {
        let server = ev(Confidence::Strong)
            .with_service("http")
            .with_product("nginx");
        let application = ev(Confidence::Probable)
            .with_service("http")
            .with_product("Metabase")
            .with_extrainfo("Metabase");

        let verdict = ServiceVerdict::resolve(vec![server, application]);
        assert_eq!(verdict.product.as_deref(), Some("nginx"));
        assert_eq!(verdict.extrainfo.as_deref(), Some("Metabase"));
    }

    /// And where nothing outranks it, the application takes the product slot and
    /// is not also repeated beside itself.
    #[test]
    fn an_application_on_an_anonymous_server_is_named_once() {
        let baseline = ev(Confidence::Probable).with_service("http");
        let application = ev(Confidence::Probable)
            .with_service("http")
            .with_product("Metabase")
            .with_extrainfo("Metabase");

        let verdict = ServiceVerdict::resolve(vec![baseline, application]);
        assert_eq!(verdict.product.as_deref(), Some("Metabase"));
        assert_eq!(verdict.extrainfo, None);
    }

    /// The platform identifier still follows the product rather than the icon.
    /// A CPE naming the application beside a product naming the proxy is what
    /// sends `cve` at the wrong software, which is the most expensive mistake
    /// this crate can make.
    #[test]
    fn the_platform_identifier_follows_the_product_not_the_application() {
        let mut server = ev(Confidence::Strong)
            .with_service("http")
            .with_product("nginx");
        server.cpe = Some("cpe:/a:nginx:nginx:1.24.0".to_string());

        let mut application = ev(Confidence::Probable)
            .with_service("http")
            .with_product("Metabase")
            .with_extrainfo("Metabase");
        application.cpe = Some("cpe:/a:metabase:metabase:-".to_string());

        let verdict = ServiceVerdict::resolve(vec![server, application]);
        assert_eq!(verdict.product.as_deref(), Some("nginx"));
        assert_eq!(verdict.cpe.as_deref(), Some("cpe:/a:nginx:nginx:1.24.0"));
    }
}
