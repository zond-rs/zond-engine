// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Capabilities, the one seam a module reaches the world through
//!
//! Everything a compute module does outside its own memory passes through this
//! trait, and it is served only the verbs its
//! [class](crate::model::finding::DetectionClass) grants: a `passive` module none,
//! an `active-benign` one a [`speak`](Capabilities::speak) bound to the scanned
//! socket. That gives safety (only what was handed), metering (budgets checked
//! inside the verb), replay (recorded verbs re-run the module offline) and
//! provenance (the report names the granted verbs).
//!
//! ## Verbs, never handles
//!
//! Never hand a module a socket, a file descriptor, a dialable address or a
//! clock. A handle bypasses the budget, makes replay impossible, and ties the
//! module to in-process execution; `speak(bytes) -> bytes` does none of that.

use std::net::IpAddr;
use std::time::Duration;

use thiserror::Error;

use crate::detect::manifest::{
    Class, DEFAULT_MAX_BYTES, DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_MILLIS, DetectionManifest,
    GroupSpec,
};
use crate::model::finding::{DetectionClass, DetectionId, FindingGroup, Version};

use super::budget::Budget;

/// The verbs a compute module may be served. Each is bound and metered by the
/// implementation; a module holds the verb, never the machinery behind it.
///
/// `Send` because a module runs on the blocking pool. Not `Sync`: one run owns
/// its capabilities.
///
/// # An implementation must not re-enter a compute runtime
///
/// No method may run a compute module, directly or indirectly. A runtime holds
/// a pointer to the implementation for one run and hands out a `&mut` per verb
/// call, so a second run would create two live `&mut` to one value: undefined
/// behaviour.
///
/// The runtime also checks, in every build, refusing the second run with
/// [`RunOutcome::HostReentered`](super::RunOutcome::HostReentered).
pub trait Capabilities: Send {
    /// Exchange bytes with the scanned port and return the reply. No address is
    /// named or returned. The byte and connection budgets are spent here; an
    /// exchange they cannot pay for is refused before it happens.
    fn speak(&mut self, bytes: &[u8]) -> Result<Vec<u8>, CapError>;

    /// Resolve a name to addresses. Separate from [`speak`](Self::speak) and
    /// served only where the class grants it.
    fn resolve(&mut self, name: &str) -> Result<Vec<IpAddr>, CapError>;

    /// The injected clock: a run-relative tick, the only clock a module can read,
    /// so runs replay identically.
    fn now(&mut self) -> ScanInstant;
}

/// Forwards every verb, so the [recording wrapper](super::RecordingCapabilities)
/// and the detection stage can carry a `Box<dyn Capabilities>`.
impl Capabilities for Box<dyn Capabilities> {
    fn speak(&mut self, bytes: &[u8]) -> Result<Vec<u8>, CapError> {
        (**self).speak(bytes)
    }

    fn resolve(&mut self, name: &str) -> Result<Vec<IpAddr>, CapError> {
        (**self).resolve(name)
    }

    fn now(&mut self) -> ScanInstant {
        (**self).now()
    }
}

/// A run-relative instant: milliseconds since the run's clock started.
///
/// Unlike a [`std::time::Instant`], it can be recorded, so a module reading the
/// clock replays identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScanInstant {
    millis: u64,
}

impl ScanInstant {
    /// An instant `millis` milliseconds into the run's clock.
    pub const fn from_millis(millis: u64) -> Self {
        Self { millis }
    }

    /// Milliseconds since the run's clock started.
    pub const fn millis(self) -> u64 {
        self.millis
    }
}

/// Which capability a call named, recorded on a [`Denial`](super::Denial), and
/// the vocabulary a runtime uses to decide which verbs a grant exposes.
#[non_exhaustive]
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
/// A budget or scope refusal ends the run with the matching
/// [`RunOutcome`](super::RunOutcome). An ordinary I/O failure is handed back to
/// the module, which may catch it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CapError {
    /// The byte budget is spent; this exchange would exceed it. A hard end.
    #[error("the byte budget is exhausted")]
    ByteBudgetExhausted,
    /// The connection budget is spent; this exchange would open one too many. A
    /// hard end.
    #[error("the connection budget is exhausted")]
    ConnectionBudgetExhausted,
    /// The call is refused on policy grounds, a `resolve` outside the granted
    /// scope. A hard end, carrying the reason for the report.
    #[error("the call was denied: {0}")]
    Denied(String),
    /// No file descriptor was available within the run's time, so nothing was
    /// sent. A hard end, since the port was never asked. The remedy is a higher
    /// file limit.
    #[error("no file descriptor was free for the exchange's socket")]
    OutOfDescriptors,
    /// The scan stopped, or the host's time ran out, while the exchange waited
    /// for its pacing slot. A hard end, as for
    /// [`OutOfDescriptors`](Self::OutOfDescriptors).
    #[error("the scan stopped, or left the host, before the exchange's turn came")]
    Withheld,
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
    /// Whether this error ends the run. Budget and policy refusals, a full
    /// descriptor table and a withheld slot do; I/O failures do not.
    pub(crate) fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::ByteBudgetExhausted
                | Self::ConnectionBudgetExhausted
                | Self::Denied(_)
                | Self::OutOfDescriptors
                | Self::Withheld
        )
    }
}

/// What a detection resolves into for the runtime: its identity, the class it
/// declares, the concrete [`Budget`] filled from what it left open, and which verbs
/// to serve it.
///
/// Everything a runtime needs to instantiate a module. A `passive` grant carries
/// `speak = false`, so no `speak` is served at all. The identity and class are
/// stamped onto every finding.
///
/// Built by [`from_manifest`](Self::from_manifest);
/// [`non_exhaustive`](https://doc.rust-lang.org/reference/attributes/type-system.html#the-non_exhaustive-attribute).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Grant {
    /// The provenance stamped on every finding: the detection's id, version, and
    /// content hash. Supplied by the loader, never by the module.
    pub detection: DetectionId,
    /// The intrusiveness the module runs at, recorded on each finding.
    pub class: DetectionClass,
    /// The group stamped on every finding, where the manifest declared one.
    pub group: Option<FindingGroup>,
    /// The bounds the run is held to.
    pub budget: Budget,
    /// Whether to serve [`speak`](Capabilities::speak). False for a `passive`
    /// grant.
    pub speak: bool,
    /// Whether to serve [`resolve`](Capabilities::resolve).
    pub resolve: bool,
}

/// The work bound a compute detection runs under when it declares none. The
/// byte, time and connection defaults are shared with flows, in
/// [`manifest`](crate::detect::manifest).
const DEFAULT_FUEL: u64 = 10_000_000;
/// The allocation ceiling a detection that declares none runs under: the largest
/// string, array, or map it may build, counted in elements. Also the
/// [`Budget::new`](super::Budget::new) default.
pub(crate) const DEFAULT_MAX_MEMORY: usize = 1_000_000;

impl Grant {
    /// The grant a [`DetectionManifest`] and its body's content hash resolve
    /// into, with defaults for any budget left open and verbs per the class.
    /// [`None`] only for an empty id, which the build refuses.
    pub fn from_manifest(manifest: &DetectionManifest, content_hash: &str) -> Option<Self> {
        let version = manifest.version.parse().unwrap_or(Version::new(0, 0, 0));
        let detection = DetectionId::new(manifest.id.clone(), version, content_hash).ok()?;
        let caps = &manifest.capabilities;
        // The class decides: a passive or derived detection gets no network verb
        // whatever its manifest says.
        let active = !matches!(caps.class, Class::Passive | Class::Derived);
        Some(Self {
            detection,
            class: caps.class.into_model(),
            group: manifest.group.as_ref().and_then(GroupSpec::to_model),
            budget: Budget {
                fuel: DEFAULT_FUEL,
                deadline: Duration::from_millis(
                    caps.max_millis.map_or(DEFAULT_MAX_MILLIS, u64::from),
                ),
                max_memory: DEFAULT_MAX_MEMORY,
                max_bytes: caps.max_bytes.map_or(DEFAULT_MAX_BYTES, u64::from),
                max_connections: caps
                    .max_connections
                    .map_or(DEFAULT_MAX_CONNECTIONS, u32::from),
            },
            speak: active && caps.speak.is_some(),
            resolve: active && caps.resolve,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::manifest::{CapabilitySpec, Rule, Speak};

    fn manifest(class: Class, speak: bool, resolve: bool) -> DetectionManifest {
        DetectionManifest {
            group: None,
            id: "test".into(),
            version: "2.1.0".into(),
            title: "test".into(),
            when: Rule {
                service: None,
                services: Vec::new(),
                port: None,
                ports: Vec::new(),
                protocol: None,
                speaks: None,
            },
            capabilities: CapabilitySpec {
                class,
                speak: speak.then_some(Speak::Target),
                resolve,
                max_bytes: None,
                max_millis: Some(500),
                max_connections: None,
            },
        }
    }

    #[test]
    fn a_passive_grant_is_served_no_network_verb_even_if_it_declared_one() {
        let grant = Grant::from_manifest(&manifest(Class::Passive, true, true), "hash").unwrap();
        assert!(!grant.speak, "a passive detection was served speak");
        assert!(!grant.resolve, "a passive detection was served resolve");
        assert_eq!(grant.class, DetectionClass::Passive);
    }

    #[test]
    fn an_active_grant_exposes_the_verbs_it_declared_and_fills_the_budget() {
        let grant =
            Grant::from_manifest(&manifest(Class::ActiveBenign, true, false), "hash").unwrap();
        assert!(grant.speak);
        assert!(!grant.resolve);
        // Provenance and the declared time budget carried through.
        assert_eq!(grant.detection.version(), Version::new(2, 1, 0));
        assert_eq!(grant.budget.deadline, Duration::from_millis(500));
        // Unset fields fall back to defaults.
        assert_eq!(grant.budget.max_bytes, DEFAULT_MAX_BYTES);
    }
}
