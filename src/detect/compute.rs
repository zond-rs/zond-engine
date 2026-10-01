// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Tier 2, the compute sandbox
//!
//! For detections a [flow](super::flow) cannot express: real parsing, a
//! stateful exchange, a verdict computed from behaviour. A module names nothing
//! that reaches the world; the host hands it a fixed set of verbs, and those
//! are its entire surface. With no verbs it is a pure calculator; with recorded
//! bytes behind them it is a pure function of its inputs, which is replay.
//!
//! ## The seam
//!
//! - [`Capabilities`], the verbs the host serves: [`speak`](Capabilities::speak)
//!   to the scanned socket, [`resolve`](Capabilities::resolve) a name,
//!   [`now`](Capabilities::now) an injected clock. The module holds verbs, never
//!   sockets, descriptors or addresses, so the same module runs against a live
//!   port or a recorded tape and cannot tell which.
//! - [`Budget`], the bounds on work, wall-clock, memory, and the bytes and
//!   connections `speak` may spend. A breach is a typed [`RunOutcome`].
//! - [`ComputeRuntime`], the backend: load a module once, instantiate and run it
//!   per port. [`RhaiRuntime`] implements it.
//! - [`RunOutcome`], why a run ended abnormally, kept distinct from a clean run
//!   that found nothing.
//!
//! Every tier emits one type, [`Finding`](crate::model::finding::Finding); a
//! compute module is one more producer of it, gated by the same
//! [envelope](crate::config::envelope) a flow is.

mod budget;
mod capability;
pub(crate) mod db;
mod guest_patterns;
mod http;
mod live;
mod record;
mod replay;
mod rhai;
mod runtime;
pub(crate) mod schema;
pub(crate) mod stage;

// So the build-shared `schema` can name `super::manifest` in both the library
// and `build.rs`.
pub(crate) use super::manifest;

pub use budget::{Budget, BudgetTrap, Denial, ModuleFault, RunOutcome};
pub use capability::{CapError, Capabilities, Capability, Grant, ScanInstant};
pub use db::{ReplayError, replay_run};
pub use live::LiveCapabilities;
pub use record::{
    CapErrorRecord, CapTapeRecord, DetectionRunRecord, ResolveExchangeRecord, SpeakExchangeRecord,
};
#[cfg(feature = "journal-format")]
pub(crate) use record::{DetectionLine, PortRunsRecord};
pub use replay::{
    CapTape, RecordedCapabilities, RecordingCapabilities, ResolveExchange, SpeakExchange,
};
pub use rhai::{RhaiInstance, RhaiModule, RhaiRuntime};
pub use runtime::{ComputeRuntime, LoadError, ModuleBody};
pub use stage::LoadedDetection;
