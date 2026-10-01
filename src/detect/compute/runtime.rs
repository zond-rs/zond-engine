// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The runtime seam, one trait over every compute backend
//!
//! [`ComputeRuntime`] is the contract a compute backend serves. [Rhai] is the
//! current backend; a WebAssembly one would be a second `impl`.
//!
//! [Rhai]: super::RhaiRuntime
//!
//! ## Three stages
//!
//! [`load`](ComputeRuntime::load) turns a body into a shared, reusable module;
//! [`instantiate`](ComputeRuntime::instantiate) draws a cheap per-port instance
//! from it under a [grant](super::Grant); and [`run`](ComputeRuntime::run) runs
//! that instance to completion against one port, serving every capability through
//! the [seam](super::Capabilities). The module is `Send + Sync` and shared behind
//! an `Arc`; an instance is not, and is owned by the one task that runs it.
//!
//! ## The body is bytes
//!
//! A [`ModuleBody`] is supplied by the caller; the engine reads no files. The
//! capability model makes accepting one from anywhere safe.

use crate::fingerprint::PortContext;

use super::budget::RunOutcome;
use super::capability::{Capabilities, Grant};
use crate::model::finding::Finding;

/// A detection's body, as the host hands it in.
///
/// Non-exhaustive, so another backend's body kind can be added.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleBody {
    /// Rhai source, served by [`RhaiRuntime`](super::RhaiRuntime).
    Rhai(String),
}

/// Why a module could not be loaded or instantiated.
///
/// A failure before any port is touched: a body that will not compile, or that
/// this backend cannot serve.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LoadError {
    /// The body did not compile. Carries the backend's own diagnostic.
    #[error("the module did not compile: {0}")]
    Compile(String),
    /// This backend does not serve this kind of body, a compiled blob handed to
    /// a source runtime, or the reverse.
    #[error("this runtime does not serve this kind of module body")]
    UnsupportedBody,
}

/// A compute backend: loads a module once, instantiates and runs it per port.
pub trait ComputeRuntime: Send + Sync {
    /// A validated, compiled module, built once per detection and shared across
    /// every port it runs against, so it is `Send + Sync`.
    type Module: Send + Sync;

    /// A per-run instance owning one run's mutable state; not `Sync`.
    type Instance;

    /// Validate and compile `body` into a reusable module. Whether a detection
    /// may run (its class against the envelope) is the caller's check.
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
    /// through `caps`. `Ok(vec)` is a clean run (empty when nothing was found);
    /// `Err(`[`RunOutcome`]`)` is an abnormal end the report records.
    fn run(
        &self,
        instance: &mut Self::Instance,
        ctx: &PortContext,
        responses: &[&[u8]],
        caps: &mut dyn Capabilities,
    ) -> Result<Vec<Finding>, RunOutcome>;
}
