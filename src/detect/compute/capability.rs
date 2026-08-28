// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Capabilities — the one seam a module reaches the world through
//!
//! A compute module holds no authority of its own. Everything it can do to
//! anything outside its own memory passes through this one trait, and a module is
//! served only the verbs its [class](crate::model::finding::DetectionClass)
//! grants: a `passive` module is served none and is a pure calculator; an
//! `active-benign` one is served a [`speak`](Capabilities::speak) bound to the
//! single socket the scan already holds. The verbs are the whole surface, which
//! is what makes the four properties the design promises one property: safety
//! (the module cannot do what it was not handed), metering (a budget is a bound
//! checked inside the verb), replay (a recorded verb re-runs the module offline),
//! and provenance (the report names which verbs a detection was granted).
//!
//! ## Why a verb, never a handle
//!
//! The seam is deliberately a set of verbs the host *runs*, not handles the
//! module *holds*, and the rule is absolute: never hand a module a socket, a file
//! descriptor, a dial-able address, or a clock. A handle is authority the module
//! wields directly — the sandbox's memory boundary is beside the point once the
//! thing it can reach is on the far side of a `send` the host no longer mediates;
//! the byte budget becomes advisory the moment a module writes without the seam
//! counting; a held socket returns what the live network says today, so replay is
//! a lie; and a handle cannot cross a process boundary as itself, so it welds the
//! module to in-process execution. `speak(bytes) -> bytes` has none of those
//! problems, and it is the whole architecture.

use std::net::IpAddr;

use thiserror::Error;

use crate::model::finding::{DetectionClass, DetectionId};

use super::budget::Budget;

/// The verbs a compute module may be served. Each is bound and metered by the
/// implementation; a module holds the verb, never the machinery behind it.
///
/// `Send` because a module runs on the blocking pool, off the reactor, so the
/// implementation that serves it — a live socket, a recorded tape — moves there
/// with it. It is deliberately *not* `Sync`: one run owns its capabilities, and a
/// live one drives a single socket that no second thread may touch.
pub trait Capabilities: Send {
    /// Exchange bytes with the one socket the scan already holds open to this
    /// port, and return the reply. There is no address to name and none in the
    /// return: the module cannot widen its reach through this call, only use it.
    /// The byte and connection budgets are spent here, so an exchange the budget
    /// cannot pay for is refused before it happens.
    fn speak(&mut self, bytes: &[u8]) -> Result<Vec<u8>, CapError>;

    /// Resolve a name to addresses. A capability distinct from
    /// [`speak`](Self::speak) so a module that only talks to the scanned socket
    /// cannot also reach the resolver; served only where the class grants it.
    fn resolve(&mut self, name: &str) -> Result<Vec<IpAddr>, CapError>;

    /// The injected clock: a scan-relative tick, the *only* clock a module can
    /// read. It is not wall-clock and not a system time, which is what lets a run
    /// be recorded and replayed — a real clock would make the same replay differ.
    fn now(&mut self) -> ScanInstant;
}

/// A scan-relative instant: milliseconds since the scan's clock started.
///
/// A value the engine mints and can write down, deliberately not a
/// [`std::time::Instant`], whose monotonic reading means nothing outside the
/// process that took it and so cannot be journalled — the same reason a captured
/// round-trip sample's instant does not survive a report round-trip. Recording
/// this tick is what lets a module that reads the clock still replay identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScanInstant {
    millis: u64,
}

impl ScanInstant {
    /// An instant `millis` milliseconds into the scan's clock.
    pub const fn from_millis(millis: u64) -> Self {
        Self { millis }
    }

    /// Milliseconds since the scan's clock started.
    pub const fn millis(self) -> u64 {
        self.millis
    }
}

/// Which capability a call named — recorded on a [`Denial`](super::Denial), and
/// the vocabulary a runtime uses to decide which verbs a grant exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// [`Capabilities::speak`].
    Speak,
    /// [`Capabilities::resolve`].
    Resolve,
    /// [`Capabilities::now`].
    Now,
}

/// Why a capability could not serve a call.
///
/// The distinction the runtime draws on it: a budget or scope refusal is a *hard*
/// end to the run — a module cannot loop-and-retry its way past a byte budget, so
/// the run stops with the matching [`RunOutcome`](super::RunOutcome). An ordinary
/// I/O failure is instead handed *back to the module*, which may catch it and try
/// another approach the way any network client does.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CapError {
    /// The byte budget is spent; this exchange would exceed it. A hard end.
    #[error("the byte budget is exhausted")]
    ByteBudgetExhausted,
    /// The connection budget is spent; this exchange would open one too many. A
    /// hard end.
    #[error("the connection budget is exhausted")]
    ConnectionBudgetExhausted,
    /// The call is refused on policy grounds — a `resolve` outside the granted
    /// scope. A hard end, carrying the reason for the report.
    #[error("the call was denied: {0}")]
    Denied(String),
    /// The exchange timed out. Handed back to the module.
    #[error("the exchange timed out")]
    TimedOut,
    /// The connection was refused. Handed back to the module.
    #[error("the connection was refused")]
    ConnectionRefused,
    /// The connection was reset. Handed back to the module.
    #[error("the connection was reset")]
    Reset,
}

impl CapError {
    /// Whether this error ends the run outright, rather than being handed back to
    /// the module to handle. Budget and policy refusals do; I/O failures do not.
    pub(crate) fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::ByteBudgetExhausted | Self::ConnectionBudgetExhausted | Self::Denied(_)
        )
    }
}

/// What the operator's envelope produced for one detection: its identity, the
/// class it runs at, the concrete [`Budget`], and which verbs to serve it.
///
/// The grant is the whole of what a runtime needs to instantiate a module, and it
/// is where the class becomes enforcement rather than advice: a `passive` grant
/// carries `speak = false`, so the runtime serves no `speak` at all, and a
/// `passive` module that names it fails because the verb is *absent*, not because
/// a present verb returned an error. The identity and class are stamped onto
/// every finding the module produces — a module cannot forge its own provenance.
#[derive(Debug, Clone)]
pub struct Grant {
    /// The provenance stamped on every finding: the detection's id, version, and
    /// content hash. Supplied by the loader, never by the module.
    pub detection: DetectionId,
    /// The intrusiveness the module runs at, recorded on each finding.
    pub class: DetectionClass,
    /// The bounds the run is held to.
    pub budget: Budget,
    /// Whether to serve [`speak`](Capabilities::speak). False for a `passive`
    /// grant, so the verb is not merely refused but absent.
    pub speak: bool,
    /// Whether to serve [`resolve`](Capabilities::resolve).
    pub resolve: bool,
}
