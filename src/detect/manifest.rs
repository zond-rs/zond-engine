// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a detection declares
//!
//! The `[detection]` table every detection carries, whichever tier runs it: its
//! identity, the cheap gate that decides whether it runs for a port at all, and
//! the capabilities and intrusiveness [class](Class) it asks the operator to
//! grant. A [flow](super::flow) and a [compute module](super::compute) differ in
//! their *body* — steps versus code — but declare themselves the same way, so the
//! manifest is one vocabulary both tiers share rather than each restating.
//!
//! ## The class is the request, not the grant
//!
//! Nothing here self-reports a permission. A detection *declares* a
//! [`Class`] and a [`CapabilitySpec`]; the [envelope](super::envelope) decides
//! what to serve, and the runtime serves exactly that. The class a detection asks
//! for is the set of capabilities an envelope will hand it, so a `passive`
//! detection cannot reach the network however it is authored — the boundary is
//! the serving, not the label.
//!
//! ## Authoring types, kept free of the model
//!
//! These deserialize from TOML and are deliberately separate from the
//! [`model`](crate::model) types they map onto, for the reason the fingerprint
//! signature schema is: the model stays serde-free, so a detection's `class` is
//! parsed here and [converted](super::convert) into the model's own vocabulary
//! when a detection produces a finding. Keeping this file free of any dependency
//! on the rest of the crate is also what lets `build.rs` share it, and validate
//! the corpus with the very types the runtime deserializes.

// `build.rs` compiles this file too, to validate the detection corpus, and its
// checks read only a subset of these fields — the rest are a detection's declared
// budget the runtime reads. Within the library every field is public API and
// live; the unread-field lint fires only in the build-script crate, so it is
// silenced here rather than field by field.
#![allow(dead_code)]

use serde::Deserialize;

/// `[detection]` — what a detection *is* and what it *asks to be handed*, shared
/// by every tier that runs one.
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    /// The author-chosen identity, stamped on every finding this detection
    /// produces.
    pub id: String,
    /// The version, `major.minor.patch`. A string here; a consumer parses it.
    pub version: String,
    pub title: String,
    /// The cheap gate deciding whether this detection runs for a port at all.
    pub when: Rule,
    pub capabilities: CapabilitySpec,
}

/// `[detection.when]` — the rule that gates the whole detection, nmap's portrule.
/// Every set field ANDs; an empty table means "any port the level offers".
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub ports: Vec<u16>,
    /// `"tcp"` or `"udp"`. Gates which transport serves `speak`.
    #[serde(default)]
    pub protocol: Option<String>,
}

/// `[detection.capabilities]` — what a detection asks to be handed. The class *is*
/// the capability set an envelope will serve; nothing here self-reports.
///
/// Named a *spec* for the same reason the flow schema's other authoring types are:
/// it is a specification a detection writes, distinct from the served
/// [`Capabilities`](super::compute::Capabilities) a compute module holds at run
/// and the [`Grant`](super::compute::Grant) an envelope produces from it.
#[derive(Debug, Clone, Deserialize)]
pub struct CapabilitySpec {
    pub class: Class,
    /// The only value today is `target`: exchange bytes with the scanned socket.
    #[serde(default)]
    pub speak: Option<Speak>,
    #[serde(default)]
    pub resolve: bool,
    #[serde(default)]
    pub max_bytes: Option<u32>,
    #[serde(default)]
    pub max_millis: Option<u32>,
    #[serde(default)]
    pub max_connections: Option<u16>,
}

/// The intrusiveness a detection declares. Deserializes from the wire names and
/// maps onto the model's [`DetectionClass`](crate::model::finding::DetectionClass)
/// — the mapping lives in the runtime [`convert`](super::convert) module, so this
/// stays free of the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    Passive,
    ActiveBenign,
    ActiveMutating,
    Exploit,
    Dos,
}

/// What a detection may `speak` to. One value for now; the enum is the room to
/// grow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Speak {
    Target,
}
