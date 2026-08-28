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
//! What is embedded is each flow's validated *source* and the SHA-256 of its
//! bytes, and the source is re-parsed here. Two reasons: the match rule is an
//! `untagged` enum `bincode` cannot round-trip, so the parsed form would not
//! survive the blob; and re-reading the exact bytes the build validated keeps the
//! build and the runtime reading one text. A flow the build accepted parses here
//! without fail, which is why the re-parse may `expect`.

// The corpus is loaded but not yet run in a scan: the detection stage that will
// draw on it is a later increment, so for now only the tests exercise these.
#![allow(dead_code)]

use std::sync::OnceLock;

use crate::model::finding::Finding;

use super::schema::FlowDetection;
use super::{Probe, run};

/// The validated flow sources and their content hashes, compiled from
/// `assets/detect/` by `build.rs`.
const EMBEDDED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/detect_flows.bin"));

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
    pub(crate) fn run(&self, probe: &mut dyn Probe) -> Vec<Finding> {
        run(&self.flow, &self.content_hash, probe)
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
        DB.get_or_init(|| {
            let sources: Vec<(String, String)> = bincode::deserialize(EMBEDDED)
                .expect("embedded flow database failed to deserialize");
            let flows = sources
                .into_iter()
                .map(|(content_hash, source)| {
                    let flow = toml::from_str(&source).expect(
                        "an embedded flow was validated at build but did not re-parse at runtime",
                    );
                    CompiledFlow { flow, content_hash }
                })
                .collect();
            FlowDb { flows }
        })
    }

    /// Every flow in the corpus.
    pub(crate) fn flows(&self) -> impl Iterator<Item = &CompiledFlow> {
        self.flows.iter()
    }
}

#[cfg(test)]
impl CompiledFlow {
    /// Builds a compiled flow directly, for tests that need a synthetic corpus
    /// rather than the embedded one.
    pub(crate) fn from_parts(flow: FlowDetection, content_hash: String) -> Self {
        Self { flow, content_hash }
    }
}

#[cfg(test)]
impl FlowDb {
    /// A database over an explicit flow set, for tests that need to drive the
    /// runtime with flows the shipped corpus does not carry.
    pub(crate) fn from_flows(flows: Vec<CompiledFlow>) -> Self {
        Self { flows }
    }
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

        let findings = redis.run(&mut Canned(b"# Server\r\nredis_version:7.2.4".to_vec()));
        assert_eq!(findings.len(), 1);
        // The finding carries the flow's real content hash, not the empty one the
        // interpreter stamps when no loader supplied it.
        assert_eq!(findings[0].detection().content_hash(), redis.content_hash());
        assert_eq!(findings[0].detection().content_hash().len(), 64);
    }
}
