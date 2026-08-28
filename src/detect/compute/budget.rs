// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a module is held to, and how a run can end
//!
//! A compute module is code, so unlike a [flow](crate::detect::flow) its cost is
//! not knowable before it runs — it must be *metered*, and a breach must be a
//! fact the report can state rather than a scan that silently stalls. This module
//! is the vocabulary for both: the [`Budget`] a run is bounded by, and the
//! [`RunOutcome`] that names why a run ended abnormally.
//!
//! ## Three bounds, three questions
//!
//! [`Budget`] carries bounds that answer different questions and bite in
//! different places. `fuel` bounds *work done*, independent of machine speed, and
//! is what a busy loop hits. `deadline` bounds *wall-clock*, and is what a run
//! stalled in a slow exchange hits, which fuel cannot see. `max_memory` bounds
//! *allocation*. `max_bytes` and `max_connections` bound the *I/O at the seam* —
//! they are spent inside [`speak`](super::Capabilities::speak), the one place a
//! module reaches the network, so a module cannot exceed them because the thing
//! that would spend them refuses to.
//!
//! ## An abnormal end is not an empty result
//!
//! A clean run that found nothing returns `Ok(vec![])` — *ran, no finding*. A run
//! that hit a bound, was refused a call, or broke returns `Err(RunOutcome)` — a
//! different fact, so a reader never reads "it ran out of fuel" as "it cleared the
//! host." This is the honesty the whole subsystem is built for, carried into the
//! one place a detection can fail.

use std::time::Duration;

use super::capability::Capability;

/// The bounds a compute module runs under.
///
/// Resolved from the detection's declared budget and the operator's envelope into
/// the concrete numbers the runtime enforces. Where each bound is checked is not
/// uniform: `fuel`, `deadline`, and `max_memory` are enforced by the runtime that
/// runs the code, while `max_bytes` and `max_connections` are enforced by the
/// [`Capabilities`](super::Capabilities) that serve its I/O — which is the point,
/// because the seam that spends a byte is the seam that can refuse to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// The work bound: how much a module may compute before it is trapped. A
    /// per-operation counter, so it bounds work regardless of how fast the
    /// machine is — the bound a `while true {}` hits.
    pub fuel: u64,
    /// The wall-clock ceiling. Catches what `fuel` cannot: a run parked in a slow
    /// exchange does no work, so it burns no fuel, but it still runs down this.
    pub deadline: Duration,
    /// The allocation ceiling — the largest string, array, or map a module may
    /// build. A module that would grow past it fails the growth, not the scan.
    pub max_memory: usize,
    /// The total bytes a module may exchange across all of its
    /// [`speak`](super::Capabilities::speak) calls. Spent at the seam.
    pub max_bytes: u64,
    /// The number of distinct exchanges a module may open. Class-bounded — one
    /// for an `active-benign` detection that talks to a single socket.
    pub max_connections: u32,
}

/// Which bound a run hit. Each is a *deterministic* trap at a known point, not a
/// timing accident, so the same inputs trap at the same place every time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetTrap {
    /// The work bound. A module that computes without end is trapped here.
    Fuel,
    /// The wall-clock ceiling. A module stalled in an exchange is trapped here.
    Deadline,
    /// The allocation ceiling. A module building an unbounded value is trapped
    /// here, in the guest, before the allocation lands.
    Memory,
    /// The byte budget, spent at the seam. The exchange that would exceed it does
    /// not happen — the trap is *before* the bytes leave.
    Bytes,
    /// The connection budget. The exchange that would open one connection too
    /// many is refused before it is opened.
    Connections,
}

/// A granted capability that refused a specific call.
///
/// The narrow case: not a capability the module was never given — that one is
/// *absent*, and a module that names it fails without a `Denial`, because there
/// is nothing there to refuse — but a capability the module *holds* declining a
/// particular use of it, such as [`resolve`](super::Capabilities::resolve) of a
/// name the envelope's scope forbids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// The verb that refused.
    pub capability: Capability,
    /// Why, for the report a person reads.
    pub reason: String,
}

/// The module itself broke — as opposed to hitting a bound or being refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleFault {
    /// The guest raised an error, or an error it could have handled propagated
    /// out unhandled — a fault in the detection's own logic.
    Runtime(String),
    /// The guest ran to completion but returned something that is not a valid set
    /// of findings — a malformed severity, a finding missing its summary.
    BadOutput(String),
}

/// Why a run ended abnormally.
///
/// The `Err` half of a [`run`](super::ComputeRuntime::run): an `Ok(vec)` is a
/// clean run (an empty vector its clean no-finding case), and every other way a
/// run can end is one of these, recorded rather than swallowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// A bound was hit; the module was trapped at a known point.
    BudgetExceeded(BudgetTrap),
    /// A granted capability refused a specific call.
    Denied(Denial),
    /// The module broke.
    Faulted(ModuleFault),
}
