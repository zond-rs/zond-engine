// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Tier 2 — the compute sandbox
//!
//! The tier for the detections a [flow](super::flow) cannot express: real
//! parsing, a stateful exchange, a verdict computed from behaviour rather than
//! recognised from a string. It is *code*, and the whole of what makes running a
//! stranger's code safe is one inversion — **the module names nothing that
//! reaches the world; the host hands it a fixed set of verbs, and that set, no
//! larger, is the entire surface between the module and everything outside its
//! own memory.** Inject nothing and the module is a pure calculator over the
//! bytes it was given; inject only what its class grants and it is bounded to
//! exactly that; inject *recorded* bytes and it is a pure function of its inputs,
//! which is the whole of replay.
//!
//! ## The seam
//!
//! Everything here hangs off four types:
//!
//! - [`Capabilities`] — the verbs the host serves: [`speak`](Capabilities::speak)
//!   to the one scanned socket, [`resolve`](Capabilities::resolve) a name,
//!   [`now`](Capabilities::now) an injected clock. Never a socket, a file
//!   descriptor, a dial-able address, or a wall-clock — a verb the host runs, so
//!   the module holds the verb and not the machinery behind it. This is the seam
//!   the whole design turns on: a function call serves it in-process behind the
//!   sandbox, a recorded tape serves it offline byte-identically, and (later) a
//!   pipe serves it from a privilege-dropped worker — the module cannot tell.
//! - [`Budget`] — the bounds the run is held to: work, wall-clock, memory, and
//!   the bytes and connections a `speak` may spend. Each is checked where it
//!   bites, and a breach is a typed, recorded [`RunOutcome`], never a silent kill.
//! - [`ComputeRuntime`] — the backend: load a module once, instantiate it per
//!   port, run it per port. [`RhaiRuntime`] is the first implementation; a
//!   WebAssembly one joins it behind the same trait, so choosing Rhai first
//!   forecloses nothing.
//! - [`RunOutcome`] — why a run ended abnormally, told apart from a clean run
//!   that simply found nothing, so a reader never mistakes "the detection cleared
//!   this host" for "it ran out of fuel halfway."
//!
//! Every tier emits one type, [`Finding`](crate::model::finding::Finding); a
//! compute module is one more producer of it, gated by the same
//! [envelope](super::envelope) a flow is. See the design record in
//! `audit/2026-08-28-scripting-engine-spec.md`, Part III.

mod budget;
mod capability;
mod live;
mod rhai;
mod runtime;

pub use budget::{Budget, BudgetTrap, Denial, ModuleFault, RunOutcome};
pub use capability::{CapError, Capabilities, Capability, Grant, ScanInstant};
pub use live::LiveCapabilities;
pub use rhai::RhaiRuntime;
pub use runtime::{ComputeRuntime, LoadError, ModuleBody};
