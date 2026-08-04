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

/// Upper bound on a single UDP probe payload.
///
/// A probe is sent to one port at a time and can draw at most one reply, so a
/// payload large enough to fragment costs more than it can return - and a
/// scanner that emits large datagrams at many hosts is a traffic source out of
/// proportion to what it learns. Shared by the build-time validator and the
/// runtime tests so both hold probes to the same ceiling.
pub const MAX_UDP_PROBE_BYTES: usize = 512;

/// Decodes the backslash escapes in an authored probe payload into raw bytes.
///
/// Payloads are authored as readable TOML *literal* strings (e.g.
/// `'GET / HTTP/1.1\r\n\r\n'`), so escapes arrive verbatim — a literal `\`, `r`
/// — and would go on the wire malformed if sent as-is. This resolves the common
/// set (`\r`, `\n`, `\t`, `\0`, `\xHH`, `\\`) to the bytes they denote; any other
/// escape is preserved literally so nothing is silently lost.
///
/// Lives beside the schema, rather than in the runtime database, because
/// `build.rs` decodes payloads to validate them and the runtime decodes them to
/// send: two readings of the same authored bytes that must never disagree about
/// what was written.
pub fn unescape(payload: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len());
    let mut chars = payload.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.extend_from_slice(c.encode_utf8(&mut [0u8; 4]).as_bytes());
            continue;
        }
        match chars.next() {
            Some('r') => out.push(b'\r'),
            Some('n') => out.push(b'\n'),
            Some('t') => out.push(b'\t'),
            Some('0') => out.push(0),
            Some('\\') => out.push(b'\\'),
            Some('x') => {
                let hi = chars.next().and_then(|h| h.to_digit(16));
                let lo = chars.next().and_then(|l| l.to_digit(16));
                match (hi, lo) {
                    (Some(hi), Some(lo)) => out.push((hi * 16 + lo) as u8),
                    // Malformed \xHH: keep the marker, best-effort.
                    _ => out.extend_from_slice(b"\\x"),
                }
            }
            // Unknown escape (or trailing backslash): keep it literally.
            Some(other) => {
                out.push(b'\\');
                out.extend_from_slice(other.encode_utf8(&mut [0u8; 4]).as_bytes());
            }
            None => out.push(b'\\'),
        }
    }
    out
}

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
