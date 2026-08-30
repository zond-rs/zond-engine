// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The words every authored detection uses for a finding
//!
//! How bad a finding is and what it cites, as an author writes them. Both tiers
//! declare a finding, and they declare its severity and its references the same
//! way, so this is one vocabulary they share rather than each restating. The
//! [manifest](super::manifest) is the same idea for the `[detection]` table.
//!
//! What a finding *says* is not here. A flow's summary and detail are `{var}`
//! templates resolved against what earlier steps bound; a host detection's are
//! literal text. They are different grammars behind the same field names, so
//! each tier keeps its own `FindingSpec` and only these two enums are shared.
//!
//! Nothing here names the model. That is what lets `build.rs` load this file to
//! validate a corpus before the library exists; the lowering into
//! [`model::finding`](crate::model::finding) happens in `detect::convert`.

use serde::Deserialize;

/// How bad a finding is, as authored. Maps onto the model's
/// [`Severity`](crate::model::finding::Severity) in the runtime
/// `convert` module.
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

/// A typed reference, authored as an inline table: `{ cve = "CVE-…" }`,
/// `{ cwe = 79 }`, or `{ url = "…" }`. Maps onto the model's
/// [`Reference`](crate::model::finding::Reference) in the runtime
/// `convert` module.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reference {
    /// A CVE identifier: `{ cve = "CVE-2021-43798" }`. Only the `CVE-YYYY-N`
    /// shape survives the lowering; a malformed one is dropped rather than
    /// carried into the finding, and the build warns about it.
    Cve(String),
    /// The bare CWE number, `{ cwe = 306 }`. MITRE's canonical link is built
    /// from it.
    Cwe(u32),
    /// Anything else worth citing, `{ url = "https://…" }`: an advisory, a
    /// vendor bulletin, a write-up.
    Url(String),
}
