// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Upper bound on a single compiled signature's memory footprint.
///
/// The `regex` crate defaults to a 10 MiB compiled-size cap; a few legitimate
/// signatures with large bounded repetitions (e.g. `{1,512}`) compile just past
/// it and would otherwise be dropped. 32 MiB admits them while still bounding
/// worst-case memory. This constant is shared by the runtime matcher and the
/// build-time validator so both accept exactly the same set of patterns.
pub const MAX_COMPILED_REGEX_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSignature {
    pub name: String,
    pub default_ports: Vec<u16>,
    pub description: Option<String>,
    pub attribution: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub name: Option<String>,
    pub payload: String,
    pub protocol: String,
    /// How aggressive/uncommon this probe is, `0..=9`, mirroring nmap's probe
    /// rarity. A probe is sent only when its rarity is within the scan's
    /// intensity level (`rarity <= intensity`), so low-rarity probes go out on
    /// every scan and high-rarity ones only when explicitly asked for.
    ///
    /// Reserved ahead of the intensity/softmatch work (see
    /// `docs/fingerprinting-redesign.md`): the runtime does not yet gate on it.
    /// `#[serde(default)]` makes it backward-compatible — every existing probe
    /// deserializes at rarity `0` (common, always sent), so current behaviour is
    /// unchanged until an intensity cap is wired in.
    #[serde(default)]
    pub rarity: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRule {
    pub name: Option<String>,
    pub pattern: String,
    pub version_group: Option<u8>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub context: Option<String>,
    pub example: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub service: ServiceSignature,
    #[serde(default)]
    pub probe: Vec<Probe>,
    #[serde(default)]
    pub r#match: Vec<MatchRule>,
}
