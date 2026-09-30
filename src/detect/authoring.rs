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
//! ## A severity is written against an audience
//!
//! [`SeveritySpec`] is the one field here with two spellings, because "how bad is
//! this" has no answer that does not name who can reach the subject. A detection
//! whose weakness means the same thing to everybody writes one severity; one
//! whose weakness *is* the configuration on a network that was set up for it
//! writes a severity per
//! [`Exposure`](crate::model::ip::Exposure) rung. See that type for why the
//! question is asked of the address.
//!
//! What a finding says is not here. A flow's summary and detail are `{var}`
//! templates resolved against what earlier steps bound; a host detection's are
//! literal text. They are different grammars behind the same field names, so
//! each tier keeps its own `FindingSpec`, and what is shared is only the
//! vocabulary those fields are written in.
//!
//! Nothing here names the model. That is what lets `build.rs` load this file to
//! validate a corpus before the library exists; the lowering into
//! [`model::finding`](crate::model::finding) happens in `detect::convert`.

// `build.rs` compiles this file too, to validate the detection corpus, and its
// checks read the vocabulary without resolving a severity against an exposure,
// which only the runtime does. Within the library every item is live; the
// unread-item lint fires only in the build-script crate, so it is silenced here
// rather than item by item, as `manifest` silences it for the same reason.
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
/// ## Why both spellings
///
/// Most weaknesses mean one thing wherever they are. Unauthenticated Redis hands
/// over the database to anyone who can open the socket, and a network whose own
/// machines can do that is how ransomware moves sideways, so it is `high` and
/// that is the end of it. Those detections write a bare severity and this reads
/// as [`Flat`](Self::Flat).
///
/// A second, smaller group describes something that is a weakness *because* a
/// stranger can see it, and is the intended arrangement otherwise. A resolver
/// that recurses for an external name is an open resolver on a public address and
/// the service it was configured to provide on the network it serves. A host with
/// SMB, RPC and NetBIOS all open is alarming on the internet and is what every
/// Windows desktop looks like on a LAN. Rating those against the widest audience
/// makes a scanner that cries wolf on every household network; rating them
/// against the narrowest one misses the real thing. They state both, and this
/// reads as [`PerExposure`](Self::PerExposure).
///
/// ## Why the detection decides and not the engine
///
/// Rescaling every severity by exposure engine-side would be one line and would
/// be wrong, in the direction that matters: it would quietly downgrade the
/// unauthenticated database on the file server, which is precisely the finding
/// somebody scanning their own network needs to see. Only the author of a
/// detection knows whether their weakness is one an insider already has. So the
/// engine asks and the detection answers, in its own file, where the reasoning
/// can be written beside it and the corpus can be read to see which detections
/// made the claim.
///
/// Untagged, so the bare form is not a special case of the table but the ordinary
/// way to write a severity, which is what nearly every detection does.
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
/// `internet` is required and the others fall back along it, narrower to wider:
/// `local` to `internal`, and `internal` to `internet`. Two things follow from
/// that shape.
///
/// The required field is the widest audience, so a table can only ever be read as
/// a *reduction* from the rating a detection would have carried with no table at
/// all. An author cannot leave the one rung that matters most unstated.
///
/// And the fallback means a detection says only as much as it has decided.
/// `{ internet = "high", internal = "info" }` is a complete statement for a
/// weakness whose reading on loopback is the same as on a LAN, which is most of
/// them; writing `local = "info"` beside it would add a third claim the author
/// has no separate reason for.
///
/// `deny_unknown_fields`, so `internel` is a build failure rather than a rung
/// silently falling back. The two names differ by two letters, which is the cost
/// of a pairing this natural, and the build is where that cost is paid.
///
/// `non_exhaustive`, and here that is not the usual precaution but a certainty:
/// this struct has one field per [`Exposure`](crate::model::ip::Exposure) rung, and
/// that enum is itself open so a rung can be split later without a major version.
/// Sealing this is what keeps that promise, since the day a rung is added is the day
/// a field arrives here. Deserialized rather than built by hand, as
/// [`DetectionManifest`](super::manifest::DetectionManifest) is: a detection is
/// written as TOML, so nothing is lost by a caller being unable to write the literal.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeverityByExposure {
    /// The rating where the internet routes to the address. Required: it is what
    /// a severity written without asking the question already means.
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
