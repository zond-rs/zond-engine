// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a module is held to, and how a run can end
//!
//! A compute module's cost is unknown before it runs, so it is metered: a
//! [`Budget`] bounds the run, and a [`RunOutcome`] names why it ended abnormally.
//!
//! ## Bounds
//!
//! `fuel` bounds work, independent of machine speed (a busy loop). `deadline`
//! bounds wall-clock (a stalled exchange burns no fuel). `max_memory` bounds
//! allocation. `max_bytes` and `max_connections` are spent inside
//! [`speak`](super::Capabilities::speak), which refuses past them.
//!
//! ## An abnormal end is not an empty result
//!
//! A clean run that found nothing returns `Ok(vec![])`. A run that hit a bound,
//! was refused a call, or broke returns `Err(RunOutcome)`, so running out of
//! fuel never reads as a clean host.

use std::time::Duration;

use super::capability::{Capability, DEFAULT_MAX_MEMORY};
use crate::detect::manifest::{DEFAULT_MAX_BYTES, DEFAULT_MAX_CONNECTIONS};

/// The bounds a compute module runs under.
///
/// Resolved from the detection's declared budget and the operator's envelope.
/// `fuel`, `deadline` and `max_memory` are enforced by the runtime;
/// `max_bytes` and `max_connections` by the
/// [`Capabilities`](super::Capabilities) serving the I/O.
///
/// To drive a module outside a scan, start from [`new`](Self::new) and tighten
/// with the `with_*` setters. [`non_exhaustive`].
///
/// [`non_exhaustive`]: https://doc.rust-lang.org/reference/attributes/type-system.html#the-non_exhaustive-attribute
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// The work bound, a per-operation counter independent of machine speed.
    pub fuel: u64,
    /// The wall-clock ceiling, which catches a run parked in a slow exchange.
    pub deadline: Duration,
    /// The largest string, array or map a module may build.
    pub max_memory: usize,
    /// The total bytes a module may exchange across all of its
    /// [`speak`](super::Capabilities::speak) calls. Spent at the seam.
    pub max_bytes: u64,
    /// The number of exchanges a module may open.
    pub max_connections: u32,
}

impl Budget {
    /// A budget bounding `fuel` operations and `deadline` wall-clock time, with the
    /// memory, byte, and connection ceilings left at the runtime's own defaults.
    ///
    /// For driving a module outside a scan.
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

/// Which bound a run hit. Apart from the deadline, the same inputs trap at the
/// same point every time.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetTrap {
    /// The work bound. A module that computes without end is trapped here.
    Fuel,
    /// The wall-clock ceiling. A module stalled in an exchange is trapped here.
    Deadline,
    /// The allocation ceiling, trapped before the allocation lands.
    Memory,
    /// The byte budget; the exchange that would exceed it is not sent.
    Bytes,
    /// The connection budget; the excess connection is not opened.
    Connections,
}

/// A granted capability that refused a specific call.
///
/// A held capability declining one use, such as
/// [`resolve`](super::Capabilities::resolve) of a name the envelope's scope
/// forbids. (A capability never granted is simply absent.)
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// The verb that refused.
    pub capability: Capability,
    /// Why, for the report a person reads.
    pub reason: String,
}

/// The module itself broke.
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
/// The `Err` half of a [`run`](super::ComputeRuntime::run).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// A bound was hit; the module was trapped at a known point.
    BudgetExceeded(BudgetTrap),
    /// A granted capability refused a specific call.
    Denied(Denial),
    /// No file descriptor was available for an exchange. Raise the process's
    /// file limit.
    OutOfDescriptors,
    /// The scan stopped, or the host's time ran out, while an exchange waited for
    /// its pacing slot.
    Withheld,
    /// The module broke.
    Faulted(ModuleFault),
    /// A [`Capabilities`](super::Capabilities) implementation re-entered the
    /// runtime while it was serving a run.
    ///
    /// The trait forbids it, since two runs on one thread would hold live `&mut`
    /// to one value; the runtime checks.
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
        // Unset ceilings are the runtime's defaults.
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
