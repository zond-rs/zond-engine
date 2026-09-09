// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Detections, what to conclude beyond a service name
//!
//! Fingerprinting says what is running; a detection says what is wrong with
//! it, producing a [`Finding`](crate::model::finding::Finding). The engine's
//! own [CVE correlator](crate::cve) is one such detection; this module is where
//! authored ones live.
//!
//! ## Tier 1, first
//!
//! [`flow`] is the declarative tier: a detection authored as data, a bounded
//! sequence of probe-and-match steps ending in a typed finding. It carries no
//! code, so it is safe and replayable by construction and validated end to end
//! at build time, most of what a scripting engine is used for, without a VM.
//!
//! ## Tier 2, for the remainder
//!
//! [`compute`] is the tier for the detections that genuinely need logic, real
//! parsing, a stateful exchange, a decision from behaviour rather than a string.
//! It is code, and code runs in a capability sandbox: a module reaches the world
//! only through the verbs the host injects, so the same fact holds as for a flow:
//! a detection's power is what it was handed, and safety, metering and
//! replay all follow from it rather than being bolted on.
//!
//! ## Somebody else's detections
//!
//! A sandbox nobody can put a stranger's detection into buys nothing, so
//! [`bundle`] is the other half: a signed set of detections that a caller loads by
//! naming the key they trust, held to that key before a byte of it is compiled.
//!
//! ## Loading detections a caller wrote
//!
//! The builder takes what the files hold, name to contents; the engine opens
//! nothing itself.
//!
//! ```no_run
//! # use std::collections::BTreeMap;
//! # use zond_engine::{TargetMap, ZondConfig, scan};
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let sources = BTreeMap::<String, String>::new();
//! # let targets = TargetMap::new();
//! # let cfg = ZondConfig::default();
//! use zond_engine::detect::Detections;
//!
//! let detections = Detections::builder()
//!     .sources(&sources)?   // name to contents, from wherever they came
//!     .build();
//!
//! let (session, task) = scan(targets, &cfg, detections).await?;
//! # let _ = (session, task);
//! # Ok(())
//! # }
//! ```

pub mod authoring;
pub mod bundle;
pub mod compute;
pub mod corpus;
pub mod flow;
pub mod manifest;

// Internal, unlike the two port-level tiers: a caller adds host detections as TOML
// through [`Detections::builder`](corpus::DetectionsBuilder), so nothing here is a
// type they name. Publishing it would render an empty page, since the schema sits
// behind a `pub(crate)` stage. The corpus is the seam; the tier is an implementation.
pub(crate) mod host;

mod convert;
mod gate;
mod source;
// The synchronous TLS client both blocking probe seams speak through when a port
// answered inside a tunnel. `pub(crate)` because the flow probe lives in the
// scanner, a module away, not under `detect`.
pub(crate) mod tls;

pub use corpus::{DetectionError, DetectionSummary, Detections, DetectionsBuilder, Gate};
