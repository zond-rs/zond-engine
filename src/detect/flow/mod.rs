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
//! clause is written in, `validate` is the build-time checker that rejects a
//! malformed flow before it ships, and [`run`] is the bounded interpreter that
//! walks a flow against a [`Probe`], asking the `eval` module whether each guard
//! holds and the `convert` module to lower its authored types onto the model. The
//! `db` module holds the compiled corpus the build emits, and `stage` runs that
//! corpus's applicable flows over a host to produce findings. See the design
//! record in `audit/2026-08-28-scripting-engine-spec.md`, Part II.
//!
//! ## Shared with the build
//!
//! `schema`, `expr`, and `validate` carry no dependency on the rest of the crate,
//! so `build.rs` loads them with `#[path]` and validates the flow corpus with the
//! very code the runtime reads — a flow the build accepts is a flow the runtime
//! can run. `convert`, `eval`, and `db` are runtime-only and free to reach into
//! the model and the shared version order.

pub mod schema;

pub(crate) mod expr;
pub(crate) mod validate;

pub(crate) mod db;
mod eval;
mod interp;
pub(crate) mod stage;

pub use interp::{Probe, run};

// Re-exported so the build-shared `schema` and `validate` can name the shared
// manifest as `super::manifest` in both the library, where it lives one level up
// in `detect`, and `build.rs`, where every shared file is a crate-root sibling.
pub(crate) use super::{authoring, manifest};

/// The variables a flow has bound so far — names to their string values. One
/// environment threads through a flow's steps (a `for_each` iteration runs in a
/// clone of its own), and it holds only what a `bind` put there: no host facts,
/// no clock, which is what keeps a flow a pure function of the bytes it was told.
type Env = std::collections::BTreeMap<String, String>;
