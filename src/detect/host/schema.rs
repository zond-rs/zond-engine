// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A host-level detection, as it is authored
//!
//! The data a host detection is written as: an identity, a gate over the aggregate
//! a host presents, and the findings to draw when the gate fits. Like the flow
//! schema, these types deserialize free of the model so `build.rs` can validate the
//! corpus with the same types the runtime reads; the lowering to the model's own
//! vocabulary lives in [`convert`](super::convert).

// `build.rs` compiles this file to validate the host corpus, and its checks read
// only a subset of these fields and never the runtime `matches`. Within the library
// every item is used; the unread-item lint fires only in the build-script crate, so
// it is silenced here rather than item by item.
#![allow(dead_code)]

use std::collections::BTreeSet;

use serde::Deserialize;

/// A whole host-detection file: what it is, and the findings it draws for a host
/// its gate fits.
#[derive(Debug, Clone, Deserialize)]
pub struct HostDetection {
    pub detection: HostManifest,
    #[serde(default)]
    pub finding: Vec<FindingSpec>,
}

/// `[detection]` for a host-level detection: its identity and the gate that decides
/// which hosts it concludes something about.
#[derive(Debug, Clone, Deserialize)]
pub struct HostManifest {
    pub id: String,
    pub version: String,
    pub title: String,
    pub host: HostGate,
}

/// `[detection.host]`: the aggregate a host must present for the detection to fire.
///
/// Every field is a set every member of which must hold, so listing more narrows
/// the match rather than widening it. An empty gate fits every host.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HostGate {
    /// Ports that must all be open.
    #[serde(default)]
    pub ports_open: Vec<u16>,
    /// Services that must all be present, by identified name.
    #[serde(default)]
    pub services: Vec<String>,
}

impl HostGate {
    /// Whether a host presenting these open ports and identified services fits.
    /// Every listed port must be open and every listed service present. An empty
    /// gate fits any host, which the build rejects so a detection cannot fire
    /// everywhere by saying nothing.
    pub(crate) fn matches(&self, open_ports: &BTreeSet<u16>, services: &BTreeSet<&str>) -> bool {
        self.ports_open.iter().all(|port| open_ports.contains(port))
            && self
                .services
                .iter()
                .all(|service| services.contains(service.as_str()))
    }
}

/// `[[finding]]`: a conclusion the detection draws about a host whose gate fit.
#[derive(Debug, Clone, Deserialize)]
pub struct FindingSpec {
    /// How bad it is if true.
    pub severity: Severity,
    /// The one-line conclusion, which becomes the finding's title unless
    /// [`title`](Self::title) overrides it.
    pub summary: String,
    /// A title distinct from the summary, when one line should name the finding and
    /// another describe it.
    #[serde(default)]
    pub title: Option<String>,
    /// The evidence, in a sentence, for a person reading the report.
    #[serde(default)]
    pub detail: Option<String>,
    /// How sure the conclusion is, by wire name. `certain` when omitted, since a
    /// presence correlation either fits or does not.
    #[serde(default)]
    pub confidence: Option<String>,
    /// External references the finding cites.
    #[serde(default)]
    pub references: Vec<Reference>,
    /// What to do about it, if anything.
    #[serde(default)]
    pub remediation: Option<String>,
}

/// How bad a finding is if true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// An external reference a finding cites, written as `{ cve = "..." }`,
/// `{ cwe = 79 }`, or `{ url = "..." }`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reference {
    Cve(String),
    Cwe(u32),
    Url(String),
}
