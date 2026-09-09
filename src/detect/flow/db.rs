// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The flow database
//!
//! The compiled Tier-1 corpus the engine embeds and reads at runtime. `build.rs`
//! validates each flow in `assets/detect/`, hashes its bytes, and writes the
//! source-and-hash pairs into the blob included here; this module decodes them
//! once and hands back each flow with the provenance a finding stamps.
//!
//! ## Source, not a parsed form
//!
//! What is embedded is each flow's validated source and the SHA-256 of its
//! bytes, and the source is re-parsed here. Two reasons: the match rule is an
//! `untagged` enum `bincode` cannot round-trip, so the parsed form would not
//! survive the blob; and re-reading the exact bytes the build validated keeps the
//! build and the runtime reading one text. A flow the build accepted parses here
//! without fail, which is why the re-parse may `expect`.

// The scanner runs this corpus; a couple of accessors and the test-only
// constructors the scan path does not reach would otherwise trip the unread-item
// lint, so it is silenced module-wide.
#![allow(dead_code)]

use std::sync::OnceLock;

use crate::model::finding::Finding;

use super::schema::FlowDetection;
use super::{FlowSeed, Probe, run};

/// The validated flow sources and their content hashes, compiled from
/// `assets/detect/` by `build.rs`.
const EMBEDDED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/detect_flows.bin"));

/// The process-wide flow database, decoded once on first use.
static DB: OnceLock<FlowDb> = OnceLock::new();

/// A validated flow and the content address of the bytes it was parsed from.
pub(crate) struct CompiledFlow {
    flow: FlowDetection,
    content_hash: String,
}

impl CompiledFlow {
    /// The flow it wraps, for its rule and steps.
    pub(crate) fn flow(&self) -> &FlowDetection {
        &self.flow
    }

    /// The SHA-256 of the flow's source bytes, stamped on every finding it
    /// produces so a report can say which detection body fired.
    pub(crate) fn content_hash(&self) -> &str {
        &self.content_hash
    }

    /// Runs the flow against `probe`, stamping its content hash on each finding.
    /// `seed` carries the `{host}`/`{port}` the flow's probe templates may name.
    pub(crate) fn run(&self, seed: &FlowSeed, probe: &mut dyn Probe) -> Vec<Finding> {
        run(&self.flow, &self.content_hash, seed, probe)
    }
}

/// The runtime view over the embedded flow corpus.
pub(crate) struct FlowDb {
    flows: Vec<CompiledFlow>,
}

impl FlowDb {
    /// The process-wide database. The first call decodes the embedded blob and
    /// re-parses each validated source; subsequent calls are a pointer read.
    pub(crate) fn global() -> &'static FlowDb {
        DB.get_or_init(FlowDb::from_embedded)
    }

    /// Every flow in the corpus.
    pub(crate) fn flows(&self) -> impl Iterator<Item = &CompiledFlow> {
        self.flows.iter()
    }

    /// The embedded corpus, decoded fresh. The default [`Detections`](crate::detect::Detections)
    /// holds one of these; [`global`](Self::global) caches another for the paths
    /// that reach the corpus without a scan context (replay, the crate's tests).
    pub(crate) fn from_embedded() -> FlowDb {
        FlowDb {
            flows: embedded_flows(),
        }
    }

    /// A database over an explicit flow set, for a caller assembling a corpus of
    /// their own or a test driving flows the shipped corpus does not carry.
    pub(crate) fn from_flows(flows: Vec<CompiledFlow>) -> Self {
        Self { flows }
    }
}

impl CompiledFlow {
    /// Builds a compiled flow from a validated detection and the content address of
    /// the bytes it was parsed from.
    pub(crate) fn from_parts(flow: FlowDetection, content_hash: String) -> Self {
        Self { flow, content_hash }
    }
}

/// The shipped flow with this id, for tests. By id rather than file path, which
/// breaks whenever the corpus is refiled into directories.
#[cfg(test)]
pub(crate) fn shipped_flow(id: &str) -> FlowDetection {
    embedded_flows()
        .into_iter()
        .map(|compiled| compiled.flow)
        .find(|flow| flow.detection.id == id)
        .unwrap_or_else(|| panic!("the corpus ships no flow with the id '{id}'"))
}

/// The embedded flow corpus as compiled flows, for combining with a caller's own.
pub(crate) fn embedded_flows() -> Vec<CompiledFlow> {
    let sources: Vec<(String, String)> =
        bincode::deserialize(EMBEDDED).expect("embedded flow database failed to deserialize");
    sources
        .into_iter()
        .map(|(content_hash, source)| {
            let flow = toml::from_str(&source)
                .expect("an embedded flow was validated at build but did not re-parse at runtime");
            CompiledFlow { flow, content_hash }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_corpus_loads_and_every_flow_carries_a_content_hash() {
        let flows: Vec<&CompiledFlow> = FlowDb::global().flows().collect();
        assert!(!flows.is_empty(), "the flow corpus is empty");

        for flow in flows {
            // A SHA-256 is 32 bytes, so 64 lowercase hex characters.
            let hash = flow.content_hash();
            assert_eq!(hash.len(), 64, "content hash is not a SHA-256: {hash:?}");
            assert!(hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
    }

    /// What each shipped flow may do, pinned as the exceptions to the default.
    ///
    /// A detection's class decides whether a default scan runs it at all: the
    /// envelope's ceiling is `ActiveBenign`, so `Exploit` and `Dos` ship inert
    /// until an operator raises the ceiling, and `ActiveMutating` writes to the
    /// target. Moving a detection across that line either way is a security
    /// decision, not a detail.
    ///
    /// So the tripwire is the set of detections whose class is *not* the
    /// active-benign default, checked against a blessed list. Adding an ordinary
    /// active-benign detection needs no edit here; one that ships anything else
    /// fails this test until it is listed by name, which is the review that must
    /// not be skipped. Enumerating the whole corpus bought nothing over this and
    /// would not survive a thousand detections.
    #[test]
    fn the_corpus_ships_the_classes_it_is_known_to_ship() {
        use crate::detect::manifest::Class;

        // Every entry here was read before it was added, which is the whole
        // point of the list. The ten writers each send a uniquely-named
        // `zond-canary` and then remove it — `DEL`/`RMD`/`DELETE`/`deleterange`
        // — leaving the target as they found it; `redis-config-writable`
        // re-sets `maxmemory` to the value it just read, a no-op; `tftp-writable`
        // cannot delete because the protocol has no such verb, which is itself a
        // reason it is gated; `mqtt-anon-publish` sends one non-retained
        // message. All ten genuinely write, so `ActiveMutating` is the honest
        // class and the ceiling holds them out of a default scan. Sorted by id,
        // because that is the order the assertion below builds its own list in.
        let blessed = [
            ("couchdb-writable", Class::ActiveMutating),
            ("elasticsearch-writable", Class::ActiveMutating),
            ("etcd-writable", Class::ActiveMutating),
            ("ftp-anon-writable", Class::ActiveMutating),
            ("grafana-path-traversal", Class::Exploit),
            ("memcached-writable", Class::ActiveMutating),
            ("mqtt-anon-publish", Class::ActiveMutating),
            ("redis-config-writable", Class::ActiveMutating),
            ("redis-writable", Class::ActiveMutating),
            ("tftp-writable", Class::ActiveMutating),
            ("webdav-writable", Class::ActiveMutating),
        ];

        let mut exceptions: Vec<(String, Class)> = FlowDb::global()
            .flows()
            .map(|flow| {
                (
                    flow.flow().detection.id.clone(),
                    flow.flow().detection.capabilities.class,
                )
            })
            .filter(|(_, class)| *class != Class::ActiveBenign)
            .collect();
        exceptions.sort_by(|a, b| a.0.cmp(&b.0));

        let exceptions: Vec<(&str, Class)> = exceptions
            .iter()
            .map(|(id, class)| (id.as_str(), *class))
            .collect();

        assert_eq!(
            exceptions, blessed,
            "a detection ships a class other than active-benign that is not blessed \
             here: a class above the default is silent by default or intrusive, so \
             adding or changing one is a security decision and must be listed"
        );
    }

    #[test]
    fn a_flow_stamps_its_content_hash_on_the_findings_it_produces() {
        let redis = FlowDb::global()
            .flows()
            .find(|flow| flow.flow().detection.id == "redis-unauth-access")
            .expect("the redis flow is in the corpus");

        struct Canned(Vec<u8>);
        impl Probe for Canned {
            fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
                Some(self.0.clone())
            }
        }

        let seed = FlowSeed::new("192.0.2.10", 6379);
        let findings = redis.run(
            &seed,
            &mut Canned(b"# Server\r\nredis_version:7.2.4".to_vec()),
        );
        assert_eq!(findings.len(), 1);
        // The finding carries the flow's real content hash, not the empty one the
        // interpreter stamps when no loader supplied it.
        assert_eq!(findings[0].detection().content_hash(), redis.content_hash());
        assert_eq!(findings[0].detection().content_hash().len(), 64);
    }
}
