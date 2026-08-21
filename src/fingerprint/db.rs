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
//! (see `docs/fingerprinting-redesign.md`, phase 2) without touching callers.

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
                by_protocol
                    .entry(def.service.name.clone())
                    .or_default()
                    .push(unescape(&probe.payload));
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
            udp_probes,
            prefilter: OnceLock::new(),
        }
    }

    /// The primary service name registered for `port`, if any. No compilation.
    pub fn service_name(&self, port: u16) -> Option<Arc<str>> {
        self.name_index.get(&port).cloned()
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

    fn def(name: &str, ports: Vec<u16>, patterns: &[&str]) -> ServiceDefinition {
        ServiceDefinition {
            service: ServiceSignature {
                name: name.to_string(),
                default_ports: ports,
                description: None,
                attribution: None,
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
        let hit = db
            .signatures_for_port(80)
            .iter()
            .find_map(|&i| db.signature(i).identify("HTTP/1.1 200 OK"));
        assert_eq!(
            hit.and_then(|m| m.evidence.service),
            Some("http".to_string())
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
        }];
        let db = SignatureDb::from_defs(vec![d]);
        // The authored `\r\n` must reach the wire as real CRLF, not backslashes.
        assert_eq!(
            db.tcp_probe_payloads(80),
            &[b"GET / HTTP/1.1\r\n\r\n".to_vec()]
        );
    }
}
