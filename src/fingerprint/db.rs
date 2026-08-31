// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Signature Database
//!
//! The compiled artifact the fingerprinting engine reads at runtime, and the
//! access layer over it.
//!
//! Signatures are stored flat and addressed by index; the port index and the
//! prefilter both hand back index lists, matched uniformly by the caller. Three
//! access patterns, separated by cost:
//!
//! * **Name lookup** ([`SignatureDb::service_name`]): a `port -> name` index
//!   built once at load, with no regex compilation. The scanners call it for
//!   every classified port, so it has to be free.
//! * **Port matching** ([`SignatureDb::signatures_for_port`]): the
//!   service-linked signatures for a port. Their regexes compile lazily (once
//!   each, on first match); [`SignatureDb::warm`] can force a set to compile in
//!   parallel.
//! * **Global matching** ([`SignatureDb::prefilter`]): for services on
//!   non-standard ports, an Aho-Corasick prefilter narrows the whole set to a
//!   small candidate list so matching stays sublinear in the database size.
//!
//! ## Artifact source
//!
//! Today the artifact is the `bincode` blob embedded at build time from
//! `assets/fingerprinting/`. [`SignatureDb::global`] is the single seam where
//! disk/mmap loading of a versioned, integrity-checked artifact will slot in
//! without touching callers.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use rayon::prelude::*;

use crate::fingerprint::signature::{DefinitionError, ServiceDefinition, unescape};
use crate::model::port::Protocol;

use super::model::Evidence;

use super::matcher::Signature;
use super::prefilter::{LiteralPrefilter, Prefilter};

/// The signature set compiled from `assets/fingerprinting/` by `build.rs`.
const EMBEDDED_DB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fingerprints.bin"));

static DB: OnceLock<SignatureDb> = OnceLock::new();

/// A definition [`SignatureDb::try_from_definitions`] refused, and why.
///
/// Carries where the definition sat and which service it was about, because a
/// caller loading a corpus of hundreds needs to find the one that is wrong
/// rather than be told that one of them is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidDefinition {
    /// Where the definition sat in the list handed over.
    pub index: usize,
    /// The service it was about.
    pub service: String,
    /// What is wrong with it.
    pub error: DefinitionError,
}

impl std::fmt::Display for InvalidDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            index,
            service,
            error,
        } = self;
        write!(f, "definition {index} (service '{service}') {error}")
    }
}

impl std::error::Error for InvalidDefinition {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Runtime view over the service-signature database.
#[derive(Debug)]
pub struct SignatureDb {
    /// All signatures, flat, addressed by index.
    signatures: Vec<Signature>,
    /// `port -> primary service name` (first definition to claim the port).
    name_index: HashMap<u16, Arc<str>>,
    /// `port -> signature indices` matchable on that port.
    ///
    /// Service-linked: the union, over every service reachable on the port, of
    /// all that service's signatures, so a service's port-less supplementary
    /// signatures are matched alongside its port-indexed ones.
    by_port: HashMap<u16, Vec<usize>>,
    /// `port -> TCP active-probe payloads` of the services reachable on it.
    /// Payloads are decoded bytes (escapes resolved, see [`unescape`]), ready to
    /// go on the wire as they are, non-UTF-8 binary probes included.
    tcp_probes: HashMap<u16, Vec<Vec<u8>>>,
    /// The TCP probes worth sending to a port that registered none of its own,
    /// decoded to wire bytes.
    ///
    /// Authored with `generic = true`; see
    /// [`Probe::generic`](crate::fingerprint::signature::Probe::generic) for
    /// what earns a probe that mark and why the set is tiny.
    generic_tcp_probes: Vec<Vec<u8>>,
    /// `port -> UDP probe payloads`, indexed exactly like [`Self::tcp_probes`]
    /// but kept apart, because the two are sent by different machinery for
    /// different reasons.
    ///
    /// A TCP probe is a *fingerprinting* payload: the port is already known to
    /// be open, and the probe exists to make the service say something
    /// identifying. A UDP probe is what establishes the port is open at all,
    /// since UDP offers no handshake to infer it from. The same bytes usually
    /// serve both, which is why they are authored together per service, but a
    /// scanner asking "what should I send to port 161" must not be handed a TCP
    /// payload that would mean nothing there.
    udp_probes: HashMap<u16, Vec<Vec<u8>>>,
    /// `service name -> the application protocol it is carried over`, for the
    /// services that declare one. See
    /// [`ServiceSignature::speaks`](crate::fingerprint::ServiceSignature::speaks).
    speaks: HashMap<Arc<str>, Arc<str>>,
    /// The global-match prefilter, built on first use.
    prefilter: OnceLock<LiteralPrefilter>,
}

impl SignatureDb {
    /// The process-wide database. The first call deserializes the embedded set
    /// and builds the name and port indices; it compiles no regexes and builds
    /// no prefilter. Subsequent calls are a pointer read.
    pub fn global() -> &'static SignatureDb {
        DB.get_or_init(|| {
            let defs: Vec<ServiceDefinition> = bincode::deserialize(EMBEDDED_DB)
                .expect("embedded fingerprint database failed to deserialize");
            SignatureDb::from_defs(defs)
        })
    }

    /// Builds a database from definitions given directly, refusing any the build
    /// would refuse.
    ///
    /// This is how a caller supplies signatures of their own, and the reason
    /// the authoring schema is exported at all. The checks are the ones in
    /// [`ServiceDefinition::validate`], which `build.rs` runs over the shipped
    /// corpus from the same code, so a definition that would fail the build fails
    /// here with the same stated reason rather than shipping into a scan and
    /// quietly matching nothing.
    ///
    /// Every pattern is compiled to check it, which is the expensive part and is
    /// why [`global`](Self::global) does not repeat it: the build already did.
    ///
    /// # Errors
    ///
    /// [`InvalidDefinition`] names which definition was refused and why.
    pub fn try_from_definitions(defs: Vec<ServiceDefinition>) -> Result<Self, InvalidDefinition> {
        for (index, def) in defs.iter().enumerate() {
            def.validate().map_err(|error| InvalidDefinition {
                index,
                service: def.service.name.clone(),
                error,
            })?;
        }
        Ok(Self::from_defs(defs))
    }

    /// Builds the flat signature list and its indices from raw definitions.
    /// Involves no regex compilation.
    fn from_defs(defs: Vec<ServiceDefinition>) -> Self {
        let mut signatures = Vec::new();
        // service name -> its signature indices (across every definition).
        let mut service_sigs: HashMap<String, Vec<usize>> = HashMap::new();
        // service name -> its active-probe payloads (decoded to bytes), per
        // transport. Authored in one file per service; separated here because
        // they are sent by different code for different purposes.
        let mut service_tcp_probes: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        let mut service_udp_probes: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        // The probes worth asking of a port nobody registered. Collected across
        // every definition rather than per service, since what makes one generic
        // is precisely that it belongs to no port in particular.
        let mut generic_tcp_probes: Vec<Vec<u8>> = Vec::new();
        for def in &defs {
            for rule in &def.r#match {
                let idx = signatures.len();
                signatures.push(Signature::new(&def.service.name, rule));
                service_sigs
                    .entry(def.service.name.clone())
                    .or_default()
                    .push(idx);
            }
            for probe in &def.probe {
                let by_protocol = match probe.protocol.as_str() {
                    "tcp" => &mut service_tcp_probes,
                    "udp" => &mut service_udp_probes,
                    // An unknown protocol is already a build warning; ignore it
                    // here rather than guess which transport it belongs to.
                    _ => continue,
                };
                let payload = unescape(&probe.payload);
                if probe.generic && probe.protocol == "tcp" {
                    generic_tcp_probes.push(payload.clone());
                }
                by_protocol
                    .entry(def.service.name.clone())
                    .or_default()
                    .push(payload);
            }
        }

        // The application protocol per service, where one is declared. Keyed by
        // name rather than by file, because a service is often authored across
        // several: `http` alone is six.
        let mut speaks: HashMap<Arc<str>, Arc<str>> = HashMap::new();
        for def in &defs {
            if let Some(protocol) = &def.service.speaks {
                speaks
                    .entry(Arc::from(def.service.name.as_str()))
                    .or_insert_with(|| Arc::from(protocol.as_str()));
            }
        }

        // Primary name and reachable-service set per port, from ported defs.
        let mut name_index: HashMap<u16, Arc<str>> = HashMap::new();
        let mut port_services: HashMap<u16, Vec<String>> = HashMap::new();
        for def in &defs {
            for &port in &def.service.default_ports {
                name_index
                    .entry(port)
                    .or_insert_with(|| Arc::from(def.service.name.as_str()));
                let names = port_services.entry(port).or_default();
                if !names.contains(&def.service.name) {
                    names.push(def.service.name.clone());
                }
            }
        }

        // Link: a port's signatures (and probes) are those of every service
        // reachable on it.
        let mut by_port: HashMap<u16, Vec<usize>> = HashMap::new();
        let mut tcp_probes: HashMap<u16, Vec<Vec<u8>>> = HashMap::new();
        let mut udp_probes: HashMap<u16, Vec<Vec<u8>>> = HashMap::new();
        for (port, names) in &port_services {
            let mut indices: Vec<usize> = names
                .iter()
                .filter_map(|name| service_sigs.get(name))
                .flatten()
                .copied()
                .collect();
            indices.sort_unstable();
            indices.dedup();
            by_port.insert(*port, indices);

            for (source, index) in [
                (&service_tcp_probes, &mut tcp_probes),
                (&service_udp_probes, &mut udp_probes),
            ] {
                let payloads: Vec<Vec<u8>> = names
                    .iter()
                    .filter_map(|name| source.get(name))
                    .flatten()
                    .cloned()
                    .collect();
                if !payloads.is_empty() {
                    index.insert(*port, payloads);
                }
            }
        }

        Self {
            signatures,
            name_index,
            by_port,
            tcp_probes,
            generic_tcp_probes,
            udp_probes,
            speaks,
            prefilter: OnceLock::new(),
        }
    }

    /// What this signature set makes of one `response` read from `port`.
    ///
    /// The whole per-response decision: text extraction, both matching
    /// tiers, and the separate choice of a service reading and an
    /// operating-system reading. A caller who has loaded signatures of their own
    /// through [`try_from_definitions`](Self::try_from_definitions) matches with
    /// them through here, and the built-in
    /// [`BannerRegexAnalyzer`](crate::fingerprint::BannerRegexAnalyzer) is a loop
    /// around this and nothing else.
    ///
    /// # Two tiers
    ///
    /// The response is checked first against the signatures registered for its
    /// port, which is a small set and the common case. The global set, narrowed
    /// by the prefilter to a bounded candidate list and compiled on demand, is
    /// consulted when the port set identified nothing, and also when it named a
    /// service but said nothing about the machine**.
    ///
    /// That second case is not a special case. A banner identifies a service, and
    /// what it implies about the host is a separate inference, so the signature
    /// that answers one is very often not the signature that answers the other.
    /// Stopping at the port tier discarded every operating-system reading that
    /// lives only in the global set, measured on a real host whose release was
    /// sitting there unread.
    ///
    /// [`Evidence::port_confirmed`](crate::fingerprint::Evidence::port_confirmed)
    /// records which tier named the service, so the resolver can prefer a match
    /// the port corroborates. What it does not set is the tunnel, which is a fact
    /// about how the bytes arrived rather than about what they say.
    pub fn identify(&self, port: u16, protocol: Protocol, response: &str) -> Option<Evidence> {
        let port_signatures = self.signatures_for_port(port);
        self.warm(port_signatures);
        let attested_by = super::extract::attested_by(port, protocol);
        identify_within(self, port_signatures, response, attested_by)
    }

    /// The primary service name registered for `port`, if any. No compilation.
    pub fn service_name(&self, port: u16) -> Option<Arc<str>> {
        self.name_index.get(&port).cloned()
    }

    /// Every port some service registers, in no particular order.
    ///
    /// What this engine can put a name to, which is a different set from what a
    /// scan asks about. Exposed so the two can be held against each other, since
    /// a signature authored for a service on a port nothing probes is a coverage
    /// gap that ships silently, and the catalogue test in this module is what
    /// stops it.
    pub fn indexed_ports(&self) -> impl Iterator<Item = u16> + '_ {
        self.name_index.keys().copied()
    }

    /// The application protocol `service` is carried over, where the corpus
    /// says it is carried over one.
    ///
    /// A tunnelled service arrives labelled `ssl/http`, and the label is two
    /// facts rather than a name, so the scheme is stripped before the lookup:
    /// what a TLS-wrapped web server speaks is still HTTP.
    pub fn speaks(&self, service: &str) -> Option<&str> {
        let bare = service.rsplit('/').next().unwrap_or(service);
        self.speaks.get(bare).map(|protocol| &**protocol)
    }

    /// The TCP probes to send to a port that registers none of its own.
    ///
    /// What turns an unrecognised open port from a two-second silence into a
    /// named service. See
    /// [`Probe::generic`](crate::fingerprint::signature::Probe::generic).
    pub fn generic_tcp_probe_payloads(&self) -> &[Vec<u8>] {
        &self.generic_tcp_probes
    }

    /// The signature indices matchable on `port` (service-linked). Empty if no
    /// service registers the port.
    pub fn signatures_for_port(&self, port: u16) -> &[usize] {
        self.by_port.get(&port).map_or(&[], Vec::as_slice)
    }

    /// The signature at `idx`, or `None` past the end of the set.
    ///
    /// Crate-visible. It hands back a type a caller outside the crate cannot
    /// name, and every question it was reachable for is answered by
    /// [`identify`](Self::identify) without one.
    pub(crate) fn signature(&self, idx: usize) -> Option<&Signature> {
        self.signatures.get(idx)
    }

    /// The TCP active-probe payloads registered for `port` (service-linked), as
    /// decoded bytes ready to send.
    pub fn tcp_probe_payloads(&self, port: u16) -> &[Vec<u8>] {
        self.tcp_probes.get(&port).map_or(&[], Vec::as_slice)
    }

    /// The UDP probe payloads registered for `port` (service-linked), as decoded
    /// bytes ready to send.
    ///
    /// Empty for a port no service registers a UDP probe for, which a scanner
    /// reads as "send an empty datagram": still enough to draw an ICMP error
    /// from a closed port, never enough to make an open one speak.
    pub fn udp_probe_payloads(&self, port: u16) -> &[Vec<u8>] {
        self.udp_probes.get(&port).map_or(&[], Vec::as_slice)
    }

    /// The global-match prefilter, built (over the whole set) on first use and
    /// cached. Building parses each pattern for literals; it compiles no
    /// regexes.
    ///
    /// Crate-visible. Both the type and the trait its only method comes from are
    /// private, so outside the crate this returned a value with nothing callable
    /// on it; [`identify`](Self::identify) is what it was there to serve.
    pub(crate) fn prefilter(&self) -> &LiteralPrefilter {
        self.prefilter
            .get_or_init(|| LiteralPrefilter::build(&self.signatures))
    }

    /// Forces the regexes of `indices` to compile, in parallel. Idempotent, since
    /// already-compiled signatures are untouched, so a candidate set can be warmed
    /// before matching to spread compilation across cores.
    ///
    /// Crate-visible: the indices only mean anything against this set, and
    /// [`identify`](Self::identify) already warms what it is about to match.
    pub(crate) fn warm(&self, indices: &[usize]) {
        indices
            .par_iter()
            .for_each(|&idx| self.signatures[idx].compile());
    }

    /// Deserializes the embedded definitions afresh. Used by the corpus tests to
    /// reach the recorded `example` banners the runtime signatures drop.
    #[cfg(test)]
    pub(crate) fn embedded_definitions() -> Vec<ServiceDefinition> {
        bincode::deserialize(EMBEDDED_DB)
            .expect("embedded fingerprint database failed to deserialize")
    }
}

/// Evidence from the **most specific** signature in `indices` that identifies any
/// of `texts`, by [`MatchQuality`](super::matcher::MatchQuality).
///
/// Unlike a first-match scan, this evaluates every candidate so a generic
/// signature listed earlier cannot shadow a more specific one (e.g. a bare
/// `HTTP/1.1` match hiding a `Server:`-header match that names a product and
/// version). Ties keep the earliest text and the lowest-indexed signature, so
/// the result stays deterministic. Candidate sets are bounded, being the linked
/// port set or the prefilter-narrowed global set, so evaluating all of them stays
/// cheap.
///
/// Several texts for one banner, on the same reasoning. A structured banner
/// carries a field the corpus is written against, and that field is where the
/// specific rules live, so both the whole banner and the field are offered and
/// the better match wins. Taking the first match instead would
/// reinstate exactly the shadowing this function exists to prevent: the whole
/// line matches a loose rule naming a family, and the field matches the rule
/// naming the release.
fn best_match(
    db: &SignatureDb,
    indices: &[usize],
    texts: &[&str],
    attested_by: crate::model::host::OsSource,
) -> Option<Evidence> {
    let matched: Vec<super::matcher::Match> = texts
        .iter()
        .flat_map(|text| {
            indices
                .iter()
                .filter_map(move |&idx| db.signature(idx)?.identify(text, attested_by))
        })
        .collect();

    // Replace only on a strictly better match, so the earliest text and the
    // lowest index win ties.
    let service = matched
        .iter()
        .reduce(|best, m| if m.quality > best.quality { m } else { best })?;

    // Chosen separately. `quality` ranks how well a signature identified the
    // service, which is a different question from how much it managed to say
    // about the machine, and the two disagree. A rule
    // pinning `OpenSSH_9.2p1` exactly outranks one that also happens to name
    // Debian 12, so ranking the operating system by service quality threw the
    // release away and reported a bare family.
    //
    // The `Match` type already separates them for exactly this reason: a banner
    // identifies a service, and what it implies about the host is a second
    // inference with its own rules. So the service reading comes from the best
    // service match and the operating-system reading from the most complete one,
    // and neither decides the other.
    let os = matched
        .iter()
        .filter_map(|m| m.os.as_ref())
        .reduce(|best, os| {
            if os_detail(os) > os_detail(best) {
                os
            } else {
                best
            }
        })
        .cloned();

    Some(Evidence {
        os,
        ..service.evidence.clone()
    })
}

/// How much of the identity path an operating-system reading fills in.
///
/// Ranks readings against each other and nothing else. A reading that names a
/// release says strictly more than one that stops at the family, and where two
/// say the same amount the first stands, so the answer does not depend on which
/// signature happened to be indexed earlier.
///
/// Every part counts, including the ones added later. A field left out here
/// is a field that cannot win a rule its ranking: when the kernel was first
/// given a home of its own, the rule that read one lost to an imported rule that
/// had crammed the same string into `version`, purely because this function had
/// not been told the new field existed.
pub(super) fn os_detail(os: &crate::model::host::OsEvidence) -> u8 {
    u8::from(os.version.is_some())
        + u8::from(os.kernel.is_some())
        + u8::from(os.product.is_some())
        + u8::from(os.vendor.is_some())
        + u8::from(os.cpe.is_some())
}

/// Everything one banner yields: the evidence, and whether the signature that
/// named the service was registered for this port.
///
/// The whole per-banner decision in one place: text extraction, both tiers, and
/// the separate choice of service and operating-system readings. `analyze` is a
/// loop around it and the tests call it directly, which is on purpose: a test
/// that reproduced this logic instead of calling it is what let the release-
/// naming SSH rules go unreachable while a test asserting "real banners name an
/// operating system" went on passing.
fn identify_within(
    db: &SignatureDb,
    port_signatures: &[usize],
    banner: &str,
    attested_by: crate::model::host::OsSource,
) -> Option<Evidence> {
    let texts = super::extract::texts(banner);

    // Matched against the signatures registered for this port: port-confirmed.
    let mut found = best_match(db, port_signatures, &texts, attested_by);
    let mut port_confirmed = found.is_some();

    // The global set, narrowed by the prefilter to a small candidate list and
    // compiled on demand, is consulted when the port set identified nothing, and
    // also when it named a service but said nothing about the machine.
    //
    // That second case is not a special case: a banner identifies a service, and
    // what it implies about the host is a separate inference, so the signature
    // that answers one is very often not the signature that answers the other.
    // Stopping at the port tier discarded every operating-system reading that
    // lives only in the global set, measured on a real host whose release was
    // sitting there unread.
    //
    // It costs an Aho-Corasick pass over the banner and a bounded candidate
    // evaluation, on banners that previously skipped both. Regex compilation is
    // cached, so a scan pays it once per signature rather than once per host.
    if found.as_ref().is_none_or(|found| found.os.is_none()) {
        // Narrowed against every text, unioned: a literal that only appears in
        // the extracted field would otherwise select no candidates and the field
        // would go unmatched here even though it matches on a known port.
        let mut candidates: Vec<usize> = texts
            .iter()
            .flat_map(|text| db.prefilter().candidates(text))
            .collect();
        candidates.sort_unstable();
        candidates.dedup();

        db.warm(&candidates);
        if let Some(global) = best_match(db, &candidates, &texts, attested_by) {
            match found.as_mut() {
                // The port-confirmed service stands; only the reading about the
                // machine is taken from the wider set.
                Some(found) => found.os = global.os,
                None => {
                    found = Some(global);
                    port_confirmed = false;
                }
            }
        }
    }

    found.map(|mut found| {
        found.port_confirmed = port_confirmed;
        found
    })
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
    use crate::fingerprint::signature::{DefinitionError, MatchRule, Probe, ServiceSignature};
    use crate::model::host::OsSource;

    fn def(name: &str, ports: Vec<u16>, patterns: &[&str]) -> ServiceDefinition {
        speaking(name, ports, patterns, None)
    }

    /// A definition that declares what it is carried over.
    fn speaking(
        name: &str,
        ports: Vec<u16>,
        patterns: &[&str],
        speaks: Option<&str>,
    ) -> ServiceDefinition {
        ServiceDefinition {
            service: ServiceSignature {
                name: name.to_string(),
                default_ports: ports,
                description: None,
                attribution: None,
                speaks: speaks.map(str::to_owned),
            },
            probe: Vec::new(),
            r#match: patterns
                .iter()
                .map(|p| MatchRule {
                    name: None,
                    pattern: p.to_string(),
                    version_group: None,
                    vendor: None,
                    product: None,
                    context: None,
                    example: None,
                    metadata: None,
                })
                .collect(),
        }
    }

    fn db() -> SignatureDb {
        SignatureDb::from_defs(vec![
            def("http", vec![80, 8080], &["^HTTP/1", "^Server:"]),
            def("https", vec![443], &["^TLS"]),
            def("http-alt", vec![80], &["^HTX"]),
        ])
    }

    /// A tunnelled port arrives labelled `ssl/http`, which is two facts and not
    /// a name, so the scheme comes off before the corpus is asked.
    #[test]
    fn a_tunnelled_label_speaks_what_the_service_inside_it_speaks() {
        let db = SignatureDb::from_defs(vec![
            speaking("http", vec![80], &["^HTTP/1"], Some("http")),
            speaking("redis", vec![6379], &["^-ERR"], None),
        ]);

        assert_eq!(db.speaks("http"), Some("http"));
        assert_eq!(db.speaks("ssl/http"), Some("http"));
        assert_eq!(db.speaks("redis"), None);
        assert_eq!(db.speaks("ssl/redis"), None);
        assert_eq!(db.speaks("nothing-here"), None);
    }

    #[test]
    fn name_index_is_first_claimant() {
        let db = db();
        assert_eq!(db.service_name(80).as_deref(), Some("http"));
        assert_eq!(db.service_name(443).as_deref(), Some("https"));
        assert!(db.service_name(22).is_none());
    }

    #[test]
    fn port_index_is_service_linked() {
        let db = SignatureDb::from_defs(vec![
            def("ssh", vec![22], &["^SSH-2", "^SSH-1"]), // 2 signatures, ported
            def("ssh", vec![], &["^SSH banner"]),        // port-less supplementary
            def("http", vec![80], &["^HTTP/1"]),
        ]);
        // Port 22 links both `ssh` definitions: 2 + 1 = 3 signatures.
        assert_eq!(db.signatures_for_port(22).len(), 3);
        assert_eq!(db.signatures_for_port(80).len(), 1);
        assert!(db.signatures_for_port(9999).is_empty());
    }

    #[test]
    fn signatures_identify_through_the_index() {
        let db = db();
        let hit = db.signatures_for_port(80).iter().find_map(|&i| {
            db.signature(i)?
                .identify("HTTP/1.1 200 OK", OsSource::ServiceBanner)
        });
        assert_eq!(
            hit.and_then(|m| m.evidence.service),
            Some("http".to_string())
        );
    }

    /// Every port this engine can name a service on is a port it asks about by
    /// default.
    ///
    /// The two lists are authored in different places for different reasons,
    /// `assets/fingerprinting/` saying what can be identified and
    /// [`catalog`](crate::model::port::catalog) saying what gets probed, and
    /// nothing but this connects them. Authoring a signature for a service on a
    /// port outside the catalogue is not an error the build could catch: the
    /// signature simply never matches, because no scan ever reaches the port.
    ///
    /// The catalogue's two halves are taken together, since a service definition
    /// names ports without saying which transport they are reached over.
    #[test]
    fn every_port_with_a_signature_is_a_port_the_default_scan_reaches() {
        use crate::model::port::catalog::{TCP_BY_PREVALENCE, UDP_BY_PREVALENCE};

        let probed: std::collections::HashSet<u16> = TCP_BY_PREVALENCE
            .iter()
            .chain(UDP_BY_PREVALENCE.iter())
            .copied()
            .collect();

        let unreachable: Vec<u16> = SignatureDb::global()
            .indexed_ports()
            .filter(|port| !probed.contains(port))
            .collect();

        assert!(
            unreachable.is_empty(),
            "these ports have signatures but no default scan reaches them, so the \
             signatures can never match: {unreachable:?}. Add them to the catalogue, \
             or drop the signature."
        );
    }

    /// The generic probe is what an unrecognised open port is asked, and losing
    /// it would fail nothing. It would quietly return the engine to reporting
    /// those ports with no service at all, two seconds at a time.
    ///
    /// Held as a property of the shipped database rather than of any one asset
    /// file, so moving the probe between services keeps the test passing and
    /// dropping it does not.
    #[test]
    fn the_shipped_database_carries_a_generic_probe() {
        let generic = SignatureDb::global().generic_tcp_probe_payloads();

        assert!(
            !generic.is_empty(),
            "no probe is marked generic, so every unrecognised port is asked nothing"
        );
        assert!(
            generic.len() <= 2,
            "a generic probe is sent to every unrecognised port of every scan; \
             {} of them is a cost that wants an argument",
            generic.len()
        );
        assert!(
            generic
                .iter()
                .any(|payload| payload.starts_with(b"GET / HTTP/")),
            "the one question worth asking of an unknown port is an HTTP request"
        );
    }

    /// A generic probe is only meaningful over TCP, see the schema, and the
    /// index has to agree with the build-time rule that enforces it.
    #[test]
    fn a_generic_udp_probe_is_not_indexed_as_generic() {
        let mut def = def("weird", vec![9999], &["^X"]);
        def.probe = vec![Probe {
            name: Some("nope".into()),
            payload: "ping".into(),
            protocol: "udp".into(),
            rarity: 0,
            generic: true,
        }];

        assert!(
            SignatureDb::from_defs(vec![def])
                .generic_tcp_probe_payloads()
                .is_empty()
        );
    }

    /// The other half of the same door.
    ///
    /// The authoring schema is exported so a consumer writing signatures of
    /// their own is held to the same bounds as the shipped corpus. Until this
    /// constructor existed there was nowhere to load what they had authored, so
    /// the export bought the types and not the thing the types are for.
    #[test]
    fn a_caller_can_load_signatures_of_their_own() {
        let db =
            SignatureDb::try_from_definitions(vec![def("acme", vec![9999], &[r"^ACME/([\d.]+)"])])
                .expect("a well-formed definition");

        assert_eq!(db.service_name(9999).as_deref(), Some("acme"));
        let hit = db.signatures_for_port(9999).iter().find_map(|&i| {
            db.signature(i)?
                .identify("ACME/2.1", OsSource::ServiceBanner)
        });
        assert_eq!(
            hit.and_then(|m| m.evidence.service),
            Some("acme".to_string())
        );
    }

    /// And the checks are the build's, so a definition that would fail the build
    /// fails here rather than shipping into a scan and matching nothing.
    #[test]
    fn the_checks_are_the_ones_the_build_makes() {
        // A pattern neither engine compiles.
        let refused = SignatureDb::try_from_definitions(vec![def("broken", vec![1], &["("])])
            .expect_err("an unclosed group is a syntax error in both engines");
        assert!(
            matches!(refused.error, DefinitionError::Pattern { rule: 0, .. }),
            "{:?}",
            refused.error
        );
        assert_eq!(refused.service, "broken");

        // A version group the pattern has no group for.
        let mut d = def("versioned", vec![2], &["^HELLO"]);
        d.r#match[0].version_group = Some(1);
        let refused =
            SignatureDb::try_from_definitions(vec![d]).expect_err("the pattern captures nothing");
        assert_eq!(
            refused.error,
            DefinitionError::VersionGroup {
                rule: 0,
                group: 1,
                available: 0
            }
        );

        // A transport nothing speaks, which the loader would silently drop.
        let mut d = def("odd", vec![3], &["^X"]);
        d.probe = vec![Probe {
            name: None,
            payload: "hello".into(),
            protocol: "sctp".into(),
            rarity: 0,
            generic: false,
        }];
        let refused =
            SignatureDb::try_from_definitions(vec![d]).expect_err("sctp is not a transport here");
        assert_eq!(
            refused.error,
            DefinitionError::ProbeProtocol {
                probe: 0,
                protocol: "sctp".into()
            }
        );

        // A generic probe over UDP is a payload aimed at every UDP port scanned.
        let mut d = def("weird", vec![4], &["^X"]);
        d.probe = vec![Probe {
            name: None,
            payload: "ping".into(),
            protocol: "udp".into(),
            rarity: 0,
            generic: true,
        }];
        let refused = SignatureDb::try_from_definitions(vec![d])
            .expect_err("generic only means anything over TCP");
        assert_eq!(
            refused.error,
            DefinitionError::GenericProbeNotTcp {
                probe: 0,
                protocol: "udp".into()
            }
        );

        // An empty UDP payload cannot elicit a reply.
        let mut d = def("silent", vec![5], &["^X"]);
        d.probe = vec![Probe {
            name: None,
            payload: String::new(),
            protocol: "udp".into(),
            rarity: 0,
            generic: false,
        }];
        let refused = SignatureDb::try_from_definitions(vec![d])
            .expect_err("an empty datagram draws nothing");
        assert_eq!(
            refused.error,
            DefinitionError::UdpProbeSize { probe: 0, bytes: 0 }
        );
    }

    /// Everything the build compiled passes the check the build ran. Circular if
    /// they were two implementations; a seal because they are one.
    #[test]
    fn every_shipped_definition_satisfies_the_shared_check() {
        for (index, def) in SignatureDb::embedded_definitions().iter().enumerate() {
            assert!(
                def.validate().is_ok(),
                "shipped definition {index} ('{}') would be refused: {:?}",
                def.service.name,
                def.validate()
            );
        }
    }

    /// The message names the definition, because a corpus of hundreds needs the
    /// one that is wrong rather than the fact that one of them is.
    #[test]
    fn the_refusal_names_which_definition_and_why() {
        let refused = SignatureDb::try_from_definitions(vec![
            def("fine", vec![1], &["^OK"]),
            def("broken", vec![2], &["("]),
        ])
        .expect_err("the second definition is unusable");

        let message = refused.to_string();
        assert!(message.contains("definition 1"), "{message}");
        assert!(message.contains("broken"), "{message}");
        assert!(message.contains("unusable pattern"), "{message}");
    }

    #[test]
    fn unescape_decodes_common_sequences() {
        assert_eq!(unescape(r"GET /\r\n"), b"GET /\r\n");
        assert_eq!(unescape(r"a\tb\0c"), b"a\tb\0c");
        assert_eq!(unescape(r"\x00\xff\x1b"), &[0x00, 0xff, 0x1b]);
        assert_eq!(unescape(r"c:\path"), br"c:\path"); // unknown escape kept literal
        assert_eq!(unescape(r"\\n"), br"\n"); // escaped backslash, then literal n
    }

    #[test]
    fn probe_payloads_are_decoded_to_wire_bytes() {
        let mut d = def("http", vec![80], &["^HTTP/1"]);
        d.probe = vec![Probe {
            name: None,
            payload: r"GET / HTTP/1.1\r\n\r\n".to_string(),
            protocol: "tcp".to_string(),
            rarity: 0,
            generic: false,
        }];
        let db = SignatureDb::from_defs(vec![d]);
        // The authored `\r\n` must reach the wire as real CRLF, not backslashes.
        assert_eq!(
            db.tcp_probe_payloads(80),
            &[b"GET / HTTP/1.1\r\n\r\n".to_vec()]
        );
    }
}
