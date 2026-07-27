// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Signature Database
//!
//! The compiled artifact the fingerprinting engine reads at runtime, and the
//! access layer over it.
//!
//! Two access patterns are deliberately separated by cost:
//!
//! * **Name lookup** ([`SignatureDb::service_name`]) is answered from a plain
//!   `port -> name` index built once at load, with **no regex compilation**.
//!   The port scanners call this for every classified port, so it must be —
//!   and is — effectively free. (A prior design compiled the entire signature
//!   set here, on the async scan loop, stalling scans for seconds.)
//! * **Signature matching** ([`SignatureDb::matchers_for_port`]) compiles a
//!   service's regexes on first use and caches the result. A service that is
//!   never matched is never compiled; a service that is matched is compiled
//!   once.
//!
//! ## Artifact source
//!
//! Today the artifact is the `bincode` blob embedded at build time from
//! `assets/fingerprinting/`. [`SignatureDb::global`] is the single seam where
//! disk/mmap loading of a versioned, integrity-checked artifact will slot in
//! (see `docs/fingerprinting-redesign.md`, phase 2) without touching callers.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use rayon::prelude::*;

use crate::core::models::fingerprint::ServiceDefinition;

use super::matcher::ServiceMatcher;

/// The signature set compiled from `assets/fingerprinting/` by `build.rs`.
const EMBEDDED_DB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fingerprints.bin"));

static DB: OnceLock<SignatureDb> = OnceLock::new();

/// Runtime view over the service-signature database.
///
/// Cheap to stand up (the name index costs one pass, no compilation) and cheap
/// to query for names. Regex compilation is deferred to first match and cached.
pub struct SignatureDb {
    /// All service definitions, indexed by position.
    defs: Vec<ServiceDefinition>,
    /// `port -> primary service name`, the first definition to claim the port.
    /// Built eagerly; contains no compiled state.
    name_index: HashMap<u16, Arc<str>>,
    /// `port -> indices into `defs`` matchable on that port.
    ///
    /// This is service-linked, not just the definitions that literally list the
    /// port: it is the union, over every service name reachable on the port, of
    /// *all* that service's definitions. So a service's port-less supplementary
    /// signatures (e.g. imported banner sets) are matched alongside its
    /// port-indexed ones, without a global scan.
    by_port: HashMap<u16, Vec<usize>>,
    /// Lazily compiled, cached matchers keyed by `defs` index.
    matchers: RwLock<HashMap<usize, Arc<ServiceMatcher>>>,
}

impl SignatureDb {
    /// The process-wide database.
    ///
    /// The first call deserializes the embedded set and builds the name index;
    /// it does **not** compile any regexes. Subsequent calls are a pointer read.
    pub fn global() -> &'static SignatureDb {
        DB.get_or_init(|| {
            let defs: Vec<ServiceDefinition> = bincode::deserialize(EMBEDDED_DB)
                .expect("embedded fingerprint database failed to deserialize");
            SignatureDb::from_defs(defs)
        })
    }

    /// Builds the database, its name index, and the service-linked port index
    /// from raw definitions. Involves no regex compilation.
    fn from_defs(defs: Vec<ServiceDefinition>) -> Self {
        // service name -> every definition of that service (ported or port-less).
        let mut service_defs: HashMap<&str, Vec<usize>> = HashMap::new();
        for (idx, def) in defs.iter().enumerate() {
            service_defs
                .entry(def.service.name.as_str())
                .or_default()
                .push(idx);
        }

        // Which service names are reachable on each port, and the primary name
        // for the port (first ported definition to claim it).
        let mut name_index: HashMap<u16, Arc<str>> = HashMap::new();
        let mut port_services: HashMap<u16, Vec<&str>> = HashMap::new();
        for def in defs.iter() {
            let name = def.service.name.as_str();
            for &port in &def.service.default_ports {
                name_index
                    .entry(port)
                    .or_insert_with(|| Arc::from(name));
                let names = port_services.entry(port).or_default();
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }

        // Link: a port's matchable set is every definition of every service
        // name reachable on it, so port-less supplementary signatures come along.
        let by_port = port_services
            .into_iter()
            .map(|(port, names)| {
                let mut indices: Vec<usize> = names
                    .iter()
                    .flat_map(|name| service_defs.get(name).into_iter().flatten().copied())
                    .collect();
                indices.sort_unstable();
                indices.dedup();
                (port, indices)
            })
            .collect();

        Self {
            defs,
            name_index,
            by_port,
            matchers: RwLock::new(HashMap::new()),
        }
    }

    /// The primary service name registered for `port`, if any.
    ///
    /// Pure metadata lookup — no compilation — safe on the hot path.
    pub fn service_name(&self, port: u16) -> Option<Arc<str>> {
        self.name_index.get(&port).cloned()
    }

    /// All raw service definitions. Used by the corpus regression tests to
    /// exercise every signature against its own recorded example.
    #[cfg(test)]
    pub(crate) fn definitions(&self) -> &[ServiceDefinition] {
        &self.defs
    }

    /// The compiled matchers matchable on `port` (service-linked), compiled on
    /// first use and cached. Empty if no service registers the port.
    ///
    /// Any not-yet-cached matchers are compiled in parallel, so the one-time
    /// cost of a port with many linked services (e.g. SMTP) is spread across
    /// cores rather than paid serially.
    pub fn matchers_for_port(&self, port: u16) -> Vec<Arc<ServiceMatcher>> {
        let Some(indices) = self.by_port.get(&port) else {
            return Vec::new();
        };

        let uncached: Vec<usize> = {
            let cache = self.matchers.read().unwrap();
            indices
                .iter()
                .copied()
                .filter(|idx| !cache.contains_key(idx))
                .collect()
        };

        if !uncached.is_empty() {
            let compiled: Vec<(usize, Arc<ServiceMatcher>)> = uncached
                .par_iter()
                .map(|&idx| (idx, Arc::new(ServiceMatcher::compile(&self.defs[idx]))))
                .collect();
            let mut cache = self.matchers.write().unwrap();
            for (idx, matcher) in compiled {
                // `or_insert` keeps the first result if another thread raced us.
                cache.entry(idx).or_insert(matcher);
            }
        }

        let cache = self.matchers.read().unwrap();
        indices.iter().map(|idx| cache[idx].clone()).collect()
    }

    /// The active-probe payloads (TCP only) registered for `port`, in
    /// definition order.
    pub fn tcp_probe_payloads(&self, port: u16) -> Vec<String> {
        self.by_port
            .get(&port)
            .into_iter()
            .flatten()
            .flat_map(|&idx| self.defs[idx].probe.iter())
            .filter(|probe| probe.protocol == "tcp")
            .map(|probe| probe.payload.clone())
            .collect()
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::fingerprint::{Probe, ServiceSignature};

    fn def(name: &str, ports: Vec<u16>) -> ServiceDefinition {
        ServiceDefinition {
            service: ServiceSignature {
                name: name.to_string(),
                default_ports: ports,
                description: None,
                attribution: None,
            },
            probe: vec![Probe {
                name: None,
                payload: "PING".to_string(),
                protocol: "tcp".to_string(),
            }],
            r#match: Vec::new(),
        }
    }

    fn db() -> SignatureDb {
        SignatureDb::from_defs(vec![
            def("http", vec![80, 8080]),
            def("https", vec![443]),
            // Second claimant of 80 must not override the first in the name index.
            def("http-alt", vec![80]),
        ])
    }

    #[test]
    fn name_index_is_first_claimant_and_needs_no_compile() {
        let db = db();
        assert_eq!(db.service_name(80).as_deref(), Some("http"));
        assert_eq!(db.service_name(443).as_deref(), Some("https"));
        assert!(db.service_name(22).is_none());
        // No matcher should have been compiled just to answer names.
        assert!(db.matchers.read().unwrap().is_empty());
    }

    #[test]
    fn matchers_compile_lazily_and_cache() {
        let db = db();
        assert!(db.matchers.read().unwrap().is_empty());

        let first = db.matchers_for_port(80);
        assert_eq!(first.len(), 2); // http + http-alt
        assert_eq!(db.matchers.read().unwrap().len(), 2);

        // A second request returns the same cached Arcs (no recompilation).
        let second = db.matchers_for_port(80);
        assert!(Arc::ptr_eq(&first[0], &second[0]));
    }

    #[test]
    fn tcp_probe_payloads_are_collected_per_port() {
        let db = db();
        assert_eq!(db.tcp_probe_payloads(443), vec!["PING".to_string()]);
        assert!(db.tcp_probe_payloads(22).is_empty());
    }

    #[test]
    fn portless_signatures_link_to_their_services_port() {
        let db = SignatureDb::from_defs(vec![
            def("ssh", vec![22]),      // ported definition
            def("ssh", vec![]),        // port-less supplementary set, same service
            def("http", vec![80]),
        ]);

        // Port 22 pulls in both `ssh` definitions, including the port-less one,
        // even though it lists no port of its own.
        assert_eq!(db.matchers_for_port(22).len(), 2);
        // A service unrelated to port 22 is not linked in.
        assert_eq!(db.matchers_for_port(80).len(), 1);
        // The port-less definition is unreachable on its own (it claims no port).
        assert!(db.service_name(0).is_none()); // port 0 is unclaimed here
    }
}
