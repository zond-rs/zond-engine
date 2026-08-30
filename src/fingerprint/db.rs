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
//! * **Name lookup** ([`SignatureDb::service_name`]) — a `port -> name` index
//!   built once at load, no regex compilation. The scanners call it for every
//!   classified port, so it must be free.
//! * **Port matching** ([`SignatureDb::signatures_for_port`]) — the
//!   service-linked signatures for a port. Their regexes compile lazily (once
//!   each, on first match); [`SignatureDb::warm`] can force a set to compile in
//!   parallel.
//! * **Global matching** ([`SignatureDb::prefilter`]) — for services on
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

use crate::fingerprint::signature::{ServiceDefinition, unescape};

use super::matcher::Signature;
use super::prefilter::LiteralPrefilter;

/// The signature set compiled from `assets/fingerprinting/` by `build.rs`.
const EMBEDDED_DB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fingerprints.bin"));

static DB: OnceLock<SignatureDb> = OnceLock::new();

/// Runtime view over the service-signature database.
pub struct SignatureDb {
    /// All signatures, flat, addressed by index.
    signatures: Vec<Signature>,
    /// `port -> primary service name` (first definition to claim the port).
    name_index: HashMap<u16, Arc<str>>,
    /// `port -> signature indices` matchable on that port.
    ///
    /// Service-linked: the union, over every service reachable on the port, of
    /// all that service's signatures — so a service's port-less supplementary
    /// signatures are matched alongside its port-indexed ones.
    by_port: HashMap<u16, Vec<usize>>,
    /// `port -> TCP active-probe payloads` of the services reachable on it.
    /// Payloads are decoded bytes (escapes resolved, see [`unescape`]), ready to
    /// go on the wire as-is — including non-UTF-8 binary probes.
    tcp_probes: HashMap<u16, Vec<Vec<u8>>>,
    /// The TCP probes worth sending to a port that registered none of its own,
    /// decoded to wire bytes.
    ///
    /// Authored with `generic = true`; see
    /// [`Probe::generic`](crate::fingerprint::signature::Probe::generic) for
    /// what earns a probe that mark and why the set is deliberately tiny.
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

    /// The primary service name registered for `port`, if any. No compilation.
    pub fn service_name(&self, port: u16) -> Option<Arc<str>> {
        self.name_index.get(&port).cloned()
    }

    /// Every port some service registers, in no particular order.
    ///
    /// What this engine can put a name to, which is a different set from what a
    /// scan asks about. Exposed so the two can be held against each other — a
    /// signature authored for a service on a port nothing probes is a coverage
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

    /// The signature at `idx`.
    pub fn signature(&self, idx: usize) -> &Signature {
        &self.signatures[idx]
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
    pub fn prefilter(&self) -> &LiteralPrefilter {
        self.prefilter
            .get_or_init(|| LiteralPrefilter::build(&self.signatures))
    }

    /// Forces the regexes of `indices` to compile, in parallel. Idempotent —
    /// already-compiled signatures are untouched — so callers can warm a
    /// candidate set before matching to spread compilation across cores.
    pub fn warm(&self, indices: &[usize]) {
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
    use crate::fingerprint::signature::{MatchRule, Probe, ServiceSignature};
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
            db.signature(i)
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
    /// The two lists are authored in different places for different reasons —
    /// `assets/fingerprinting/` says what can be identified, and
    /// [`catalog`](crate::model::port::catalog) says what gets probed — and
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
    /// it would not fail anything — it would quietly return the engine to
    /// reporting those ports with no service at all, two seconds at a time.
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

    /// A generic probe is only meaningful over TCP — see the schema — and the
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
