// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Detections
//!
//! Fingerprinting says what is running; a detection says what is wrong with
//! it, producing a [`Finding`](crate::model::finding::Finding). The engine's
//! own [CVE correlator](crate::cve) is one such detection; this module holds
//! the authored ones.
//!
//! ## Tier 1
//!
//! [`flow`] is the declarative tier: a detection authored as data, a bounded
//! sequence of probe-and-match steps ending in a typed finding. It carries no
//! code, so it is replayable and is validated end to end at build time.
//!
//! ## Tier 2
//!
//! [`compute`] is for detections that need logic: real parsing, a stateful
//! exchange, a decision from behaviour. Its modules run in a capability sandbox
//! and reach the network only through the verbs the host injects, which is also
//! what makes them metered and replayable.
//!
//! ## Signed bundles
//!
//! [`bundle`] loads a signed set of detections from someone else. The caller
//! names the key they trust, and the bundle is checked against it before any of
//! it is compiled.
//!
//! ## Loading detections a caller wrote
//!
//! The builder takes file names and contents; the engine opens no files itself.
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

// Internal: a caller adds host detections as TOML through
// [`Detections::builder`](corpus::DetectionsBuilder) and names no type from here.
pub(crate) mod host;

// Whether a conversation had the host to itself, counted per host by the flow
// stage and the service pass before it.
pub(crate) mod contention;
mod convert;
// One request and its reply over a socket to the scanned port; both tiers reach the
// network through it.
mod exchange;
mod gate;
// A flow's patterns, compiled once and matched on one thread kept for it.
mod patterns;
mod source;
// The synchronous TLS client an exchange uses when the port speaks TLS.
mod tls;

pub use corpus::{DetectionError, DetectionSummary, Detections, DetectionsBuilder, Gate};
