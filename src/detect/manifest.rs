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
//! [`Class`] and a [`CapabilitySpec`]; the [envelope](crate::config::envelope) decides
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
//! parsed here and [converted](Class::into_model) into the model's own vocabulary
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
pub struct DetectionManifest {
    /// The author-chosen identity, stamped on every finding this detection
    /// produces.
    pub id: String,
    /// The version, `major.minor.patch`. A string here; a consumer parses it.
    pub version: String,
    /// A one-line human name for the detection, the label a report prints for
    /// it. Required; the build rejects an empty one.
    pub title: String,
    /// The cheap gate deciding whether this detection runs for a port at all.
    pub when: Rule,
    /// `[detection.capabilities]`: the class this detection runs at and the
    /// budget it declares.
    pub capabilities: CapabilitySpec,
}

/// `[detection.when]` — the rule that gates the whole detection, nmap's portrule.
/// Every set field ANDs; an empty table means "any port the level offers".
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Rule {
    /// The identified service name, `redis` or `http`. A port whose service the
    /// scan could not name never fits a rule that names one.
    #[serde(default)]
    pub service: Option<String>,
    /// A set of service names, any of which fits. Empty leaves the service
    /// unconstrained, and this and [`service`](Self::service) set together admit
    /// only a name satisfying both.
    ///
    /// What a detection reaches for when the software it is written about
    /// answers to more than one name. The fingerprint corpus gives a product its
    /// own service name, so a server that says `Grafana` is identified as
    /// `grafana` and a quieter one on the same software as `http`. A gate naming
    /// one of those runs against half the population it was written for.
    #[serde(default)]
    pub services: Vec<String>,
    /// A single port number. Every field of the gate ANDs, so this and
    /// [`ports`](Self::ports) set together admit only a number satisfying both.
    #[serde(default)]
    pub port: Option<u16>,
    /// A set of port numbers, any of which fits. Empty leaves the number
    /// unconstrained.
    #[serde(default)]
    pub ports: Vec<u16>,
    /// `"tcp"` or `"udp"`. Gates which transport serves `speak`.
    #[serde(default)]
    pub protocol: Option<String>,

    /// The application protocol the port must be carried over, `http`.
    ///
    /// What a detection written about a protocol rather than about a product
    /// gates on. The fingerprint corpus gives a product its own service name,
    /// so a Grafana server is identified as `grafana` and a plain web server as
    /// `http`; a gate naming service names has to list every product that
    /// speaks the protocol and is short by one the next time the corpus grows.
    /// This asks the corpus instead, through
    /// [`speaks`](crate::fingerprint::ServiceSignature::speaks).
    ///
    /// Fits a tunnelled service too: a port labelled `ssl/http` is a port
    /// speaking HTTP, and the label is two facts rather than a name.
    #[serde(default)]
    pub speaks: Option<String>,
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
    /// The intrusiveness this detection declares. An envelope permits or
    /// refuses the detection on this alone.
    pub class: Class,
    /// The only value today is `target`: exchange bytes with the scanned socket.
    #[serde(default)]
    pub speak: Option<Speak>,
    /// Whether the detection asks to resolve names. A `passive` detection may
    /// not, and the build rejects one that asks.
    #[serde(default)]
    pub resolve: bool,
    /// A ceiling on the bytes crossing the socket over the whole run, what the
    /// detection sends and what comes back counted together.
    ///
    /// Unset falls back to the runtime's default ceiling. A declared one is
    /// checked at build time against the payloads the steps send, so a flow
    /// cannot ship claiming a budget its own probes would exceed.
    #[serde(default)]
    pub max_bytes: Option<u32>,
    /// Wall-clock milliseconds the whole run has, socket timeouts drawn from
    /// what is left of it. Unset falls back to the runtime's default.
    #[serde(default)]
    pub max_millis: Option<u32>,
    /// How many exchanges the detection may open. A flow spends one per `send`,
    /// so a `for_each` over sixteen items needs sixteen.
    #[serde(default)]
    pub max_connections: Option<u16>,
}

/// The intrusiveness a detection declares. Deserializes from the wire names and
/// maps onto the model's [`DetectionClass`](crate::model::finding::DetectionClass)
/// through [`into_model`](Self::into_model) in the runtime `convert` module, so
/// this stays free of the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    /// `passive`: sends nothing. Everything it concludes comes from bytes the
    /// scan already gathered.
    Passive,
    /// `active-benign`: talks to the scanned socket within a byte budget and
    /// leaves it as it found it.
    ActiveBenign,
    /// `active-mutating`: something is left behind. A write, an entry in an
    /// authentication log, a test record nobody cleans up.
    ActiveMutating,
    /// `exploit`: triggers the weakness to prove it, rather than inferring it
    /// from a version.
    Exploit,
    /// `dos`: the service may not survive the probe.
    Dos,
}

/// What a detection may `speak` to. One value for now; the enum is the room to
/// grow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Speak {
    /// `target`: the one socket the scan already holds open to the port under
    /// examination. There is no address for a detection to name.
    Target,
}
