// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The words every authored detection uses for a finding
//!
//! How bad a finding is and what it cites, as an author writes them, shared by
//! both tiers. The [manifest](super::manifest) is the same for the
//! `[detection]` table.
//!
//! ## A severity names an audience
//!
//! [`SeveritySpec`] has two spellings: one severity for a weakness that means the
//! same to everybody, or one per [`Exposure`](crate::model::ip::Exposure) rung
//! for one that is only a weakness when a stranger can reach it.
//!
//! Summary and detail are not here: a flow's are `{var}` templates and a host
//! detection's literal text, so each tier keeps its own `FindingSpec`.
//!
//! Nothing here names the model, so `build.rs` can load this file; lowering into
//! [`model::finding`](crate::model::finding) happens in `detect::convert`.

// `build.rs` compiles this file too and does not use every item; the lint fires
// only there.
#![allow(dead_code)]

use serde::Deserialize;

/// How bad a finding is, as authored. Maps onto the model's
/// [`Severity`](crate::model::finding::Severity) in the runtime
/// `convert` module.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Not a weakness, a fact: a version banner, a management interface
    /// answering where a reader should know it answers.
    Info,
    /// Small on its own. A hardening step skipped, or a disclosure a determined
    /// attacker reaches by other means anyway.
    Low,
    /// A weakness worth scheduling work for, but not worth waking anyone.
    Medium,
    /// Directly exploitable, or it hands an attacker materially more than they
    /// arrived with.
    High,
    /// Assume compromise: remote code execution, an authentication bypass, or a
    /// hole that needs no foothold first.
    Critical,
}

/// How bad a finding is, as a detection states it: one severity, or one per
/// [`Exposure`](crate::model::ip::Exposure) rung.
///
/// ```toml
/// severity = "high"                                    # whoever can reach it
/// severity = { internet = "high", internal = "info" }   # depends who can
/// ```
///
/// Most weaknesses mean one thing anywhere: unauthenticated Redis is `high`
/// whoever can reach it ([`Flat`](Self::Flat)). Some are weaknesses only when a
/// stranger can see them: a recursive resolver on a public address, or SMB, RPC
/// and NetBIOS open together, which is every Windows desktop on a LAN. Those
/// state a rating per rung ([`PerExposure`](Self::PerExposure)).
///
/// The detection decides, since rescaling by exposure engine-wide would
/// downgrade findings such as an unauthenticated database on a file server.
///
/// Untagged, so the bare form is the ordinary spelling.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum SeveritySpec {
    /// `severity = "high"`: one rating, whoever can reach the subject.
    Flat(Severity),
    /// `severity = { internet = "high", internal = "info" }`: a rating per rung.
    PerExposure(SeverityByExposure),
}

/// A severity stated per [`Exposure`](crate::model::ip::Exposure) rung.
///
/// `internet` is required; `local` falls back to `internal`, and `internal` to
/// `internet`. So the widest audience is always stated, and
/// `{ internet = "high", internal = "info" }` is complete.
///
/// `deny_unknown_fields`, so a typo such as `internel` fails the build.
///
/// `non_exhaustive`: there is one field per
/// [`Exposure`](crate::model::ip::Exposure) rung, and that enum may grow.
/// Deserialized from TOML, as
/// [`DetectionManifest`](super::manifest::DetectionManifest) is.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeverityByExposure {
    /// The rating where the internet routes to the address. Required.
    pub internet: Severity,
    /// The rating where only this network can reach the subject. Falls back to
    /// [`internet`](Self::internet).
    #[serde(default)]
    pub internal: Option<Severity>,
    /// The rating where only the machine the scan runs on can. Falls back to
    /// [`internal`](Self::internal), and through it to
    /// [`internet`](Self::internet).
    #[serde(default)]
    pub local: Option<Severity>,
}

impl SeverityByExposure {
    /// The rating for the narrowest rung, `local`, following the fallback.
    pub fn local(&self) -> Severity {
        self.local.unwrap_or_else(|| self.internal())
    }

    /// The rating for `internal`, following the fallback.
    pub fn internal(&self) -> Severity {
        self.internal.unwrap_or(self.internet)
    }
}

/// A typed reference, authored as an inline table: `{ cve = "CVE-…" }`,
/// `{ cwe = 79 }`, or `{ url = "…" }`. Maps onto the model's
/// [`Reference`](crate::model::finding::Reference) in the runtime
/// `convert` module.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reference {
    /// A CVE identifier: `{ cve = "CVE-2021-43798" }`. A malformed one is dropped
    /// from the finding, and the build warns about it.
    Cve(String),
    /// The bare CWE number, `{ cwe = 306 }`. MITRE's canonical link is built
    /// from it.
    Cwe(u32),
    /// Anything else worth citing, `{ url = "https://…" }`: an advisory, a
    /// vendor bulletin, a write-up.
    Url(String),
}
