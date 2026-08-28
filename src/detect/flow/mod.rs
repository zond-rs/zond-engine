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
//! into — the internal `expr` module is the guard expression grammar a `when`
//! clause is written in, and [`run`] is the bounded interpreter that walks a
//! flow against a [`Probe`], asking the `eval` module whether each guard holds.
//! The build-time validator joins them as the tier is built out; see the design
//! record in `audit/2026-08-28-scripting-engine-spec.md`, Part II.

pub mod schema;

pub(crate) mod expr;

mod eval;
mod interp;

pub use interp::{Probe, run};

/// The variables a flow has bound so far — names to their string values. One
/// environment threads through a flow's steps (a `for_each` iteration runs in a
/// clone of its own), and it holds only what a `bind` put there: no host facts,
/// no clock, which is what keeps a flow a pure function of the bytes it was told.
type Env = std::collections::BTreeMap<String, String>;
