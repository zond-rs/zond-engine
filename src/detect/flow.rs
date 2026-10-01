// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Tier 1, the declarative flow language
//!
//! A detection authored as data: a bounded, straight-line sequence of steps,
//! each a probe and a match, where a match binds variables and a later step or
//! finding may be guarded on them. It uses the fingerprint matcher for `expect`
//! and `bind` and ends in a typed
//! [`Finding`](crate::model::finding::Finding). With no unbounded loop, jump or
//! arithmetic, a flow cannot hang or exceed its budget, and needs no sandbox.
//!
//! ## What is here
//!
//! [`schema`] is the authoring format, the serde types a flow file deserializes
//! into, the internal `expr` module is the guard expression grammar a `when`
//! clause is written in, `validate` is the build-time checker that rejects a
//! malformed flow before it ships, and [`run`] is the bounded interpreter that
//! walks a flow against a [`Probe`], asking the `eval` module whether each guard
//! holds and the `convert` module to lower its authored types onto the model. The
//! `db` module holds the compiled corpus the build emits, and `stage` runs that
//! corpus's applicable flows over a host to produce findings.
//!
//! ## Shared with the build
//!
//! `schema`, `expr` and `validate` have no crate-internal dependencies, so
//! `build.rs` loads them with `#[path]` and validates the corpus with the
//! runtime's code. `convert`, `eval` and `db` are runtime-only.

pub mod schema;

pub(crate) mod expr;
pub(crate) mod validate;

pub(crate) mod db;
mod eval;
mod interp;
mod socket;
pub(crate) mod stage;

pub use interp::{FlowSeed, Probe, ProbeRefusal, run};
pub use socket::SocketProbe;
// The builder runs it over a caller's flow; `check` is the public structural pass.
pub(crate) use interp::check_patterns;
pub use validate::{ValidationError, check};
// The guard-parse error a `ValidationError::GuardParseError` carries, published so
// a caller reading `check`'s result can match on it.
pub use expr::ParseError;

// So the build-shared `schema` and `validate` can name `super::manifest` in both
// the library and `build.rs`.
pub(crate) use super::{authoring, manifest};

/// The variables a flow has bound so far, names to string values. One
/// environment threads through the steps (a `for_each` iteration runs in a
/// clone). It holds what `bind` captured, over a [`FlowSeed`] of `host` and
/// `port`. Nothing ambient, so matching is a pure function of the replies.
type Env = std::collections::BTreeMap<String, String>;
