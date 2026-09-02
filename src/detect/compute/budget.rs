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
//! not knowable before it runs: it must be metered, and a breach must be a
//! fact the report can state rather than a scan that silently stalls. This module
//! is the vocabulary for both: the [`Budget`] a run is bounded by, and the
//! [`RunOutcome`] that names why a run ended abnormally.
//!
//! ## Three bounds, three questions
//!
//! [`Budget`] carries bounds that answer different questions and bite in
//! different places. `fuel` bounds work done, independent of machine speed, and
//! is what a busy loop hits. `deadline` bounds wall-clock, and is what a run
//! stalled in a slow exchange hits, which fuel cannot see. `max_memory` bounds
//! allocation. `max_bytes` and `max_connections` bound the I/O at the seam:
//! they are spent inside [`speak`](super::Capabilities::speak), the one place a
//! module reaches the network, so a module cannot exceed them because the thing
//! that would spend them refuses to.
//!
//! ## An abnormal end is not an empty result
//!
//! A clean run that found nothing returns `Ok(vec![])`, ran, no finding. A run
//! that hit a bound, was refused a call, or broke returns `Err(RunOutcome)`, a
//! different fact, so a reader never reads "it ran out of fuel" as "it cleared the
//! host." This is the honesty the whole subsystem is built for, carried into the
//! one place a detection can fail.

use std::time::Duration;

use super::capability::{Capability, DEFAULT_MAX_MEMORY};
use crate::detect::manifest::{DEFAULT_MAX_BYTES, DEFAULT_MAX_CONNECTIONS};

/// The bounds a compute module runs under.
///
/// Resolved from the detection's declared budget and the operator's envelope into
/// the concrete numbers the runtime enforces. Where each bound is checked is not
/// uniform: `fuel`, `deadline`, and `max_memory` are enforced by the runtime that
/// runs the code, while `max_bytes` and `max_connections` are enforced by the
/// [`Capabilities`](super::Capabilities) that serve its I/O, which is the point,
/// because the seam that spends a byte is the seam that can refuse to.
///
/// A scan resolves one from the detection and the envelope, so the fields stay
/// public to read. To build one directly, for driving a module outside a scan, start
/// from [`new`](Self::new) and tighten a ceiling with a `with_*` setter;
/// [`non_exhaustive`], so a bound added later is not a breaking change.
///
/// [`non_exhaustive`]: https://doc.rust-lang.org/reference/attributes/type-system.html#the-non_exhaustive-attribute
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// The work bound: how much a module may compute before it is trapped. A
    /// per-operation counter, so it bounds work regardless of how fast the
    /// machine is, the bound a `while true {}` hits.
    pub fuel: u64,
    /// The wall-clock ceiling. Catches what `fuel` cannot: a run parked in a slow
    /// exchange does no work, so it burns no fuel, but it still runs down this.
    pub deadline: Duration,
    /// The allocation ceiling, the largest string, array, or map a module may
    /// build. A module that would grow past it fails the growth, not the scan.
    pub max_memory: usize,
    /// The total bytes a module may exchange across all of its
    /// [`speak`](super::Capabilities::speak) calls. Spent at the seam.
    pub max_bytes: u64,
    /// The number of distinct exchanges a module may open. Class-bounded, one
    /// for an `active-benign` detection that talks to a single socket.
    pub max_connections: u32,
}

impl Budget {
    /// A budget bounding `fuel` operations and `deadline` wall-clock time, with the
    /// memory, byte, and connection ceilings left at the runtime's own defaults.
    ///
    /// For driving a module outside a scan; the scan path resolves a budget from the
    /// detection and the envelope instead. Tighten a defaulted ceiling with the
    /// matching `with_*` setter.
    pub fn new(fuel: u64, deadline: Duration) -> Self {
        Self {
            fuel,
            deadline,
            max_memory: DEFAULT_MAX_MEMORY,
            max_bytes: DEFAULT_MAX_BYTES,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }

    /// Sets the allocation ceiling: the largest string, array, or map the module may
    /// build, counted in elements.
    #[must_use]
    pub fn with_max_memory(mut self, max_memory: usize) -> Self {
        self.max_memory = max_memory;
        self
    }

    /// Sets the ceiling on bytes exchanged across all of the module's `speak` calls.
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Sets the ceiling on how many exchanges the module may open.
    #[must_use]
    pub fn with_max_connections(mut self, max_connections: u32) -> Self {
        self.max_connections = max_connections;
        self
    }
}

/// Which bound a run hit. Each is a deterministic trap at a known point, not a
/// timing accident, so the same inputs trap at the same place every time.
#[non_exhaustive]
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
    /// not happen, the trap is before the bytes leave.
    Bytes,
    /// The connection budget. The exchange that would open one connection too
    /// many is refused before it is opened.
    Connections,
}

/// A granted capability that refused a specific call.
///
/// The narrow case: not a capability the module was never given, that one is
/// absent, and a module that names it fails without a `Denial`, because there
/// is nothing there to refuse, but a capability the module holds declining a
/// particular use of it, such as [`resolve`](super::Capabilities::resolve) of a
/// name the envelope's scope forbids.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// The verb that refused.
    pub capability: Capability,
    /// Why, for the report a person reads.
    pub reason: String,
}

/// The module itself broke, as opposed to hitting a bound or being refused.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleFault {
    /// The guest raised an error, or an error it could have handled propagated
    /// out unhandled, a fault in the detection's own logic.
    Runtime(String),
    /// The guest ran to completion but returned something that is not a valid set
    /// of findings, a malformed severity, a finding missing its summary.
    BadOutput(String),
}

/// Why a run ended abnormally.
///
/// The `Err` half of a [`run`](super::ComputeRuntime::run): an `Ok(vec)` is a
/// clean run (an empty vector its clean no-finding case), and every other way a
/// run can end is one of these, recorded rather than swallowed.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// A bound was hit; the module was trapped at a known point.
    BudgetExceeded(BudgetTrap),
    /// A granted capability refused a specific call.
    Denied(Denial),
    /// The module broke.
    Faulted(ModuleFault),
    /// A [`Capabilities`](super::Capabilities) implementation re-entered the
    /// runtime while it was serving a run.
    ///
    /// Not the module's doing, and not a bound it hit. The trait forbids it
    /// because two runs on one thread would hold live `&mut` to one value, and
    /// the runtime refuses the second rather than taking the implementation at
    /// its word.
    HostReentered,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_takes_fuel_and_time_and_defaults_the_rest() {
        let budget = Budget::new(5_000, Duration::from_millis(750));
        assert_eq!(budget.fuel, 5_000);
        assert_eq!(budget.deadline, Duration::from_millis(750));
        // The ceilings a caller did not set are the runtime's own defaults.
        assert_eq!(budget.max_memory, DEFAULT_MAX_MEMORY);
        assert_eq!(budget.max_bytes, DEFAULT_MAX_BYTES);
        assert_eq!(budget.max_connections, DEFAULT_MAX_CONNECTIONS);
    }

    #[test]
    fn each_setter_tightens_only_its_own_ceiling() {
        let budget = Budget::new(1, Duration::from_millis(1))
            .with_max_memory(128)
            .with_max_bytes(256)
            .with_max_connections(2);
        assert_eq!(budget.max_memory, 128);
        assert_eq!(budget.max_bytes, 256);
        assert_eq!(budget.max_connections, 2);
        // Untouched by the setters.
        assert_eq!(budget.fuel, 1);
    }
}
