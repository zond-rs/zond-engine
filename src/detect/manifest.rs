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
//! their body (steps or code) but share this manifest.
//!
//! ## The class is a request
//!
//! A detection declares a [`Class`] and a [`CapabilitySpec`]; the
//! [envelope](crate::config::envelope) decides what to serve, and the runtime
//! serves exactly that. A `passive` detection is never handed the network,
//! however it is authored.
//!
//! ## Authoring types
//!
//! These deserialize from TOML and are kept separate from the serde-free
//! [`model`](crate::model) types; a `class` is
//! [converted](Class::into_model) when a finding is produced. The file has no
//! crate-internal dependencies, so `build.rs` validates the corpus with the
//! same types.

// `build.rs` compiles this file too and reads only some fields; the unread-field
// lint fires only there.
#![allow(dead_code)]

use serde::Deserialize;

/// `[detection]`, what a detection is and what it asks to be handed, shared
/// by every tier that runs one.
///
/// Deserialized, not built by hand; `non_exhaustive` so fields can be added. A
/// caller adds one as TOML through
/// [`Detections::builder`](crate::detect::Detections::builder).
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionManifest {
    /// The author-chosen identity, stamped on every finding this detection
    /// produces.
    pub id: String,
    /// The version, `major.minor.patch`. A string here; a consumer parses it.
    pub version: String,
    /// A one-line human name for the detection, the label a report prints for
    /// it. Required; the build rejects an empty one.
    pub title: String,
    /// `[detection.group]`: the group this detection belongs to, if any.
    #[serde(default)]
    pub group: Option<GroupSpec>,
    /// The cheap gate deciding whether this detection runs for a port at all.
    pub when: Rule,
    /// `[detection.capabilities]`: the class this detection runs at and the
    /// budget it declares.
    pub capabilities: CapabilitySpec,
}

/// `[detection.group]`, what a detection covers a weakness together with.
///
/// Four detections read one SSH KEXINIT and each reports a different weak
/// algorithm: four findings that a report can present as one. The group says so
/// explicitly, so a front end need not guess from a shared CWE and port.
///
/// Both fields are required where the table is written; the build rejects
/// either empty.
///
/// `non_exhaustive` as [`DetectionManifest`] is.
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSpec {
    /// The identity every detection in the group repeats, `ssh-weak-algorithms`.
    /// Two detections are in one group when they spell this the same.
    pub id: String,
    /// A plural noun phrase a count can lead: `weak SSH algorithms offered`
    /// reads as *4 weak SSH algorithms offered*.
    pub summary: String,
}

/// `[detection.when]`, the rule that gates the whole detection. Every set field
/// ANDs; an empty table means "any port the level offers".
///
/// `non_exhaustive` as [`DetectionManifest`] is; [`Rule::default`] builds the
/// empty gate.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// The identified service name, `redis` or `http`. An unidentified port never
    /// fits; a port labelled `ssl/http` fits `http`, reached through the tunnel.
    #[serde(default)]
    pub service: Option<String>,
    /// A set of service names, any of which fits. Empty leaves the service
    /// unconstrained; with [`service`](Self::service) both must hold.
    ///
    /// For software identified under several names: a Grafana server that names
    /// itself is `grafana`, a quieter one `http`.
    #[serde(default)]
    pub services: Vec<String>,
    /// A single port number. With [`ports`](Self::ports) both must hold.
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
    /// For a detection about a protocol rather than a product: `grafana` and
    /// `http` both speak HTTP, per
    /// [`speaks`](crate::fingerprint::ServiceSignature::speaks). A port labelled
    /// `ssl/http` fits too.
    #[serde(default)]
    pub speaks: Option<String>,
}

/// `[detection.capabilities]`, what a detection asks to be handed. The class is
/// the capability set an envelope will serve; nothing here self-reports.
///
/// The authored request, distinct from the served
/// [`Capabilities`](super::compute::Capabilities) and the
/// [`Grant`](super::compute::Grant) an envelope produces.
///
/// `non_exhaustive` as [`DetectionManifest`] is.
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Unset falls back to the runtime's default. A declared one is checked at
    /// build time against the payloads the steps send.
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

/// The intrusiveness a detection declares. Maps onto the model's
/// [`DetectionClass`](crate::model::finding::DetectionClass) through
/// [`into_model`](Self::into_model).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    /// `derived`: sends nothing and reads nothing new. Everything it concludes
    /// is a recombination of what other detections and the port table already
    /// settled.
    ///
    /// Below [`Passive`](Self::Passive), which reads gathered bytes. What a host
    /// correlation declares.
    ///
    /// Becomes [`Passive`](crate::model::finding::DetectionClass::Passive) in the
    /// model, since both run alike on the wire.
    Derived,
    /// `passive`: sends nothing. Everything it concludes comes from bytes the
    /// scan already gathered.
    Passive,
    /// `active-benign`: talks to the scanned socket within a byte budget and
    /// leaves it as it found it.
    ActiveBenign,
    /// `active-mutating`: something is left behind. A write, an entry in an
    /// authentication log, a test record nobody cleans up.
    ActiveMutating,
    /// `exploit`: triggers the weakness to prove it.
    Exploit,
    /// `dos`: the service may not survive the probe.
    Dos,
}

impl Class {
    /// Every class this build knows, cheapest to the target first.
    ///
    /// As [`ScanKind::ALL`](crate::report::ScanKind::ALL): the enum is
    /// non-exhaustive, and a front end needs the full list.
    ///
    /// In declaration order, which is the order an envelope's ceiling reads.
    pub const ALL: &'static [Self] = &[
        Self::Derived,
        Self::Passive,
        Self::ActiveBenign,
        Self::ActiveMutating,
        Self::Exploit,
        Self::Dos,
    ];
}

impl Class {
    /// The name a document spells this class with, which is also the name an
    /// [envelope](crate::config::envelope::DetectionEnvelope) is set to.
    ///
    pub const fn label(self) -> &'static str {
        match self {
            Class::Derived => "derived",
            Class::Passive => "passive",
            Class::ActiveBenign => "active-benign",
            Class::ActiveMutating => "active-mutating",
            Class::Exploit => "exploit",
            Class::Dos => "dos",
        }
    }
}

/// What a detection may `speak` to.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Speak {
    /// `target`: the scanned port. A detection names no address.
    Target,
}

/// The byte budget a detection that declares no `max_bytes` runs under, counting
/// what it sends and what comes back across the whole run. Shared by both tiers.
pub(crate) const DEFAULT_MAX_BYTES: u64 = 64 * 1024;

/// The wall-clock budget, in milliseconds, a detection that declares no
/// `max_millis` runs under.
pub(crate) const DEFAULT_MAX_MILLIS: u64 = 2_000;

/// The connection budget a detection that declares no `max_connections` runs
/// under, the widest a single bounded loop can be.
pub(crate) const DEFAULT_MAX_CONNECTIONS: u32 = 64;

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::Class;

    /// Every class is listed, once each, cheapest to the target first.
    ///
    /// `place` is an exhaustive match, so a new variant must be placed. The order
    /// matters: an envelope permits everything up to its ceiling.
    #[test]
    fn the_list_of_classes_holds_every_one_of_them_once_and_in_order() {
        fn place(class: Class) -> usize {
            match class {
                Class::Derived => 0,
                Class::Passive => 1,
                Class::ActiveBenign => 2,
                Class::ActiveMutating => 3,
                Class::Exploit => 4,
                Class::Dos => 5,
            }
        }

        let places: Vec<usize> = Class::ALL.iter().copied().map(place).collect();

        assert_eq!(
            places,
            (0..Class::ALL.len()).collect::<Vec<_>>(),
            "every class, once, cheapest to the target first"
        );
    }
}
