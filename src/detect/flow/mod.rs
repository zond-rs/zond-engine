// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Tier 1 — the declarative flow language
//!
//! A detection authored as data: a bounded, straight-line sequence of steps,
//! each a probe and a match, where a match binds variables and a later step or
//! finding may be guarded on what an earlier one bound. It reuses the fingerprint
//! matcher for `expect` and `bind`, adds sequencing, a variable environment, and
//! a typed [`Finding`](crate::model::finding::Finding) on the end, and refuses to
//! become a programming language — no unbounded loop, no jump, no arithmetic — so
//! that a flow cannot hang, cannot exceed its budget by construction, and needs
//! no sandbox because there is no code.
//!
//! ## What is here
//!
//! [`schema`] is the authoring format — the serde types a flow file deserializes
//! into — and [`run`] is the bounded interpreter that runs one against a
//! [`Probe`]. The build-time validator and the full guard expression language
//! join them as the tier is built out; see the design record in
//! `audit/2026-08-28-scripting-engine-spec.md`, Part II.

pub mod schema;

mod interp;

pub use interp::{Probe, run};
