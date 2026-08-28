// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The runtime seam — one trait over every compute backend
//!
//! [`ComputeRuntime`] is the contract a compute backend serves, and the reason
//! there is a contract at all: WebAssembly is the destination and [Rhai] the
//! pure-Rust on-ramp, so a runtime is chosen behind this trait rather than in the
//! detection stage, and choosing Rhai first forecloses nothing — a WebAssembly
//! backend is a second `impl`, not a redesign.
//!
//! [Rhai]: super::RhaiRuntime
//!
//! ## Three stages, because a module is compiled once and run often
//!
//! A detection is validated and compiled *once*, then run against every open port
//! it is interested in, so the lifecycle is three stages:
//! [`load`](ComputeRuntime::load) turns a body into a shared, reusable module;
//! [`instantiate`](ComputeRuntime::instantiate) draws a cheap per-port instance
//! from it under a [grant](super::Grant); and [`run`](ComputeRuntime::run) runs
//! that instance to completion against one port, serving every capability through
//! the [seam](super::Capabilities). The module is `Send + Sync` and shared behind
//! an `Arc`; an instance is not, and is owned by the one task that runs it.
//!
//! ## The body is bytes the host hands in
//!
//! A [`ModuleBody`] is source or a compiled blob a caller supplies, never a path
//! the engine reads — per the library boundary, the engine hunts no filesystem
//! for detections. Accepting one is safe precisely because it grants nothing: the
//! capability model is what lets a detection be accepted from anywhere.

use crate::fingerprint::PortContext;

use super::budget::RunOutcome;
use super::capability::{Capabilities, Grant};
use crate::model::finding::Finding;

/// A detection's body, as the host hands it in.
///
/// Non-exhaustive because the compiled-WebAssembly variant joins the source one
/// as the second backend lands, and a caller matching on it should not have to
/// change when it does.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleBody {
    /// Rhai source, served by [`RhaiRuntime`](super::RhaiRuntime).
    Rhai(String),
}

/// Why a module could not be loaded or instantiated.
///
/// A failure *before any port is touched* — a refusal with a cause, never a run
/// that is quietly clamped. A body that will not compile, or one a given backend
/// cannot serve, is rejected here.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LoadError {
    /// The body did not compile. Carries the backend's own diagnostic.
    #[error("the module did not compile: {0}")]
    Compile(String),
    /// This backend does not serve this kind of body — a compiled blob handed to
    /// a source runtime, or the reverse.
    #[error("this runtime does not serve this kind of module body")]
    UnsupportedBody,
}

/// A compute backend: loads a module once, instantiates it per port, runs it per
/// port. The one trait a WebAssembly backend and the Rhai one both satisfy.
pub trait ComputeRuntime: Send + Sync {
    /// A validated, compiled module — built once per detection and shared across
    /// every port it runs against, so it is `Send + Sync`.
    type Module: Send + Sync;

    /// A per-run instance drawn from a module. It owns the mutable state one run
    /// needs (a scope, a store), so it is neither shared nor `Sync`; each run
    /// owns its own.
    type Instance;

    /// Validate and compile `body` into a reusable module, or reject it with a
    /// cause. The one place a body's own validity is checked; whether a detection
    /// *may run* — its class against the envelope — is decided by the caller
    /// before instantiation.
    fn load(&self, body: &ModuleBody) -> Result<Self::Module, LoadError>;

    /// Draw a fresh instance from `module` under `grant`. The grant decides which
    /// capability verbs the instance will serve and the bounds it will run under,
    /// so a `passive` grant yields an instance that serves no
    /// [`speak`](Capabilities::speak) at all.
    fn instantiate(
        &self,
        module: &Self::Module,
        grant: &Grant,
    ) -> Result<Self::Instance, LoadError>;

    /// Run `instance` to completion against one port, serving every capability
    /// through `caps`. `Ok(vec)` is a clean run — an empty vector its clean
    /// no-finding case; `Err(`[`RunOutcome`]`)` is an abnormal end the report
    /// records rather than swallows.
    fn run(
        &self,
        instance: &mut Self::Instance,
        ctx: &PortContext,
        responses: &[&[u8]],
        caps: &mut dyn Capabilities,
    ) -> Result<Vec<Finding>, RunOutcome>;
}
