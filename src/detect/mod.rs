// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Detections — what to conclude beyond a service name
//!
//! Fingerprinting says *what is running*; a detection says *what is wrong with
//! it*, producing a [`Finding`](crate::model::finding::Finding). The engine's
//! own [CVE correlator](crate::cve) is one such detection; this module is where
//! authored ones live.
//!
//! ## Tier 1, first
//!
//! [`flow`] is the declarative tier: a detection authored *as data*, a bounded
//! sequence of probe-and-match steps ending in a typed finding. It carries no
//! code, so it is safe and replayable by construction and validated end to end
//! at build time — most of what a scripting engine is used for, without a VM.
//!
//! ## Tier 2, for the remainder
//!
//! [`compute`] is the tier for the detections that genuinely need logic — real
//! parsing, a stateful exchange, a decision from behaviour rather than a string.
//! It is code, and code runs in a capability sandbox: a module reaches the world
//! only through the verbs the host injects, so the same fact holds as for a flow
//! — a detection's power is exactly what it was handed — and safety, metering and
//! replay all follow from it rather than being bolted on.

pub mod compute;
pub mod envelope;
pub mod flow;
pub mod host;
pub mod manifest;

mod convert;
mod gate;

pub use envelope::DetectionEnvelope;
