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
    /// `port -> indices into `defs`` that list it as a default port.
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

    /// Builds the database (and its name index) from raw definitions.
    fn from_defs(defs: Vec<ServiceDefinition>) -> Self {
        let mut name_index: HashMap<u16, Arc<str>> = HashMap::new();
        let mut by_port: HashMap<u16, Vec<usize>> = HashMap::new();

        for (idx, def) in defs.iter().enumerate() {
            for &port in &def.service.default_ports {
                by_port.entry(port).or_default().push(idx);
                name_index
                    .entry(port)
                    .or_insert_with(|| Arc::from(def.service.name.as_str()));
            }
        }

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

    /// The compiled matchers for every service that claims `port`, compiled on
    /// first use and cached. Empty if no service registers the port.
    pub fn matchers_for_port(&self, port: u16) -> Vec<Arc<ServiceMatcher>> {
        let Some(indices) = self.by_port.get(&port) else {
            return Vec::new();
        };
        indices.iter().map(|&idx| self.matcher(idx)).collect()
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

    /// Returns the cached matcher for `idx`, compiling it on first use.
    fn matcher(&self, idx: usize) -> Arc<ServiceMatcher> {
        if let Some(matcher) = self.matchers.read().unwrap().get(&idx) {
            return matcher.clone();
        }
        // Compile under the write lock; `or_insert_with` makes the first writer
        // win if two threads race the same service.
        self.matchers
            .write()
            .unwrap()
            .entry(idx)
            .or_insert_with(|| Arc::new(ServiceMatcher::compile(&self.defs[idx])))
            .clone()
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
}
