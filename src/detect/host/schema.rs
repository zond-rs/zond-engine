// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A host-level detection, as it is authored
//!
//! An identity, a gate over what a host presents, and the findings to draw when
//! it fits. Free of the model, so `build.rs` validates with the same types.

// `build.rs` compiles this file too and does not use every item.
#![allow(dead_code)]

use super::authoring::{Reference, SeveritySpec};
use super::manifest::GroupSpec;
use std::collections::BTreeSet;

use serde::Deserialize;

/// A whole host-detection file: what it is, and the findings it draws for a host
/// its gate fits.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDetection {
    /// The identity and gate: what the detection is, and which hosts it fits.
    pub detection: HostManifest,
    /// The findings to draw for a host the gate fits. The build refuses an empty
    /// list.
    #[serde(default)]
    pub finding: Vec<FindingSpec>,
}

/// `[detection]` for a host-level detection: its identity and the gate that decides
/// which hosts it concludes something about.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostManifest {
    /// A stable identifier for the detection, unique in the corpus. The build
    /// refuses an empty one and reserves the engine's own prefix.
    pub id: String,
    /// The detection's own version, stamped on its findings as provenance.
    pub version: String,
    /// A one-line human name for the detection, the label a report prints for it.
    pub title: String,
    /// `[detection.group]`, as in the other tiers; a group may span tiers.
    #[serde(default)]
    pub group: Option<GroupSpec>,
    /// The gate: the ports and services a host must present together to fit.
    pub host: HostGate,
}

/// `[detection.host]`: the aggregate a host must present for the detection to fire.
///
/// Every listed member must hold. An empty gate fits every host.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// gate fits any host; the build rejects one.
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
#[serde(deny_unknown_fields)]
pub struct FindingSpec {
    /// How bad it is if true: one rating, or one per
    /// [`Exposure`](crate::model::ip::Exposure) rung. See [`SeveritySpec`].
    ///
    /// The per-rung form suits host shapes: RPC, NetBIOS and SMB open together is
    /// a lateral-movement target on the internet and every Windows desktop on a
    /// LAN.
    pub severity: SeveritySpec,
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
