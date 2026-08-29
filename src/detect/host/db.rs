// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The host-detection database
//!
//! The compiled host corpus the engine embeds and reads at runtime. `build.rs`
//! validates each host detection in `assets/detect/`, hashes its bytes, and writes
//! the source-and-hash pairs into the blob included here; this module decodes them
//! once and hands back each detection with the provenance a finding stamps.
//!
//! Like the flow corpus, what is embedded is each detection's validated source and
//! the SHA-256 of its bytes, re-parsed here. Re-reading the exact bytes the build
//! checked keeps the build and the runtime reading one text, so a detection the
//! build accepted parses here without fail.

use std::sync::OnceLock;

use super::schema::HostDetection;
use super::stage::LoadedHostDetection;

/// The validated host-detection sources and their content hashes, compiled from
/// `assets/detect/` by `build.rs`.
const EMBEDDED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/detect_host.bin"));

static DB: OnceLock<HostDb> = OnceLock::new();

/// The runtime view over the embedded host corpus.
pub(crate) struct HostDb {
    detections: Vec<LoadedHostDetection>,
}

impl HostDb {
    /// The process-wide database. The first call decodes the embedded blob and
    /// re-parses each validated source; subsequent calls are a pointer read.
    pub(crate) fn global() -> &'static HostDb {
        DB.get_or_init(|| {
            let sources: Vec<(String, String)> = bincode::deserialize(EMBEDDED)
                .expect("embedded host database failed to deserialize");
            let detections = sources
                .into_iter()
                .map(|(content_hash, source)| {
                    let detection: HostDetection = toml::from_str(&source).expect(
                        "an embedded host detection was validated at build but did not re-parse at runtime",
                    );
                    LoadedHostDetection::new(detection, content_hash)
                })
                .collect();
            HostDb { detections }
        })
    }

    /// Every host detection in the corpus.
    pub(crate) fn detections(&self) -> &[LoadedHostDetection] {
        &self.detections
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_corpus_loads_and_carries_the_domain_controller_detection() {
        let db = HostDb::global();
        assert!(!db.detections().is_empty(), "the host corpus is empty");
        assert!(
            db.detections()
                .iter()
                .any(|detection| detection.id() == "domain-controller"),
            "the domain-controller detection did not ship"
        );
    }
}
