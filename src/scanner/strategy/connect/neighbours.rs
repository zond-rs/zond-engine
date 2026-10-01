// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The neighbours a connect waits on
//!
//! A connect to a host on one of this machine's links, or through a gateway on one,
//! waits for the kernel to resolve that neighbour's hardware address before its SYN
//! leaves, and Linux tells the socket nothing about it. If the neighbour never answers,
//! the connect is held for the kernel's three seconds and then fails with a host
//! unreachable, the same error a router's ICMP host unreachable raises; with a shorter
//! timeout it runs out like a dropped SYN. Either way every port of an empty address
//! would read as blocked or silent, though no SYN was ever sent.
//!
//! The kernel's neighbour table tells these apart: read when the connect ends, an
//! unresolved entry for the neighbour it waited on means the SYN never left, while a
//! router's error comes back through a neighbour that answered. [`Neighbours`] reads
//! the table and remembers each neighbour given up on, so the other ports of a host
//! behind it are skipped without each waiting out its own resolution. A port gives up
//! only after a second unanswered resolution, as the raw path does; see
//! [`NEIGHBOR_ROUNDS`].
//!
//! Linux only, as the table is; see [`KernelNeighbors`]. Elsewhere every connect is
//! read as it ended.
//!
//! macOS, for a neighbour it recently gave up on, refuses every connect with
//! `EHOSTDOWN` until its own hold-down passes. The first time, that says nothing about
//! the host: its ports release their scan slots, wait out the hold-down and are asked
//! again. See [`HoldDowns`].

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::limits::NEIGHBOUR_PATH_FINDING_TIMEOUT;
use crate::logging::info;
use crate::scanner::strategy::raw::neighbors::{HoldDowns, NEIGHBOR_ROUNDS, unreached};
use crate::transport::kernel_neighbors::{KernelNeighbors, NeighborState};

/// What a connect port scan knows of the neighbours its connects wait on.
pub(super) struct Neighbours {
    /// The kernel's neighbour table, where this platform has one to read.
    table: Option<KernelNeighbors>,
    /// The neighbours given up on, whose hosts are sent nothing more.
    given_up: Mutex<HashSet<IpAddr>>,
    /// The hosts logged unreachable, so each is logged once.
    filed: Mutex<HashSet<IpAddr>>,
    /// The kernel's hold-downs on the hosts' neighbours.
    holds: Mutex<HoldDowns>,
}

impl Neighbours {
    /// Reads the running kernel's table.
    pub(super) fn of_system() -> Self {
        Self::reading(KernelNeighbors::from_system())
    }

    /// Reads `table`, or nothing when it is `None`.
    pub(super) fn reading(table: Option<KernelNeighbors>) -> Self {
        Self {
            table,
            given_up: Mutex::default(),
            filed: Mutex::default(),
            holds: Mutex::default(),
        }
    }

    /// Sets the hold-down applied when the kernel refuses a connect for one, in place
    /// of the running kernel's.
    #[cfg(all(test, unix))]
    pub(super) fn holding_down_for(self, hold_down_for: Duration) -> Self {
        lock(&self.holds).hold_down_for = hold_down_for;
        self
    }

    /// The state of the neighbour a connect to `host` waits on, read now, if the
    /// kernel has not resolved it: a connect to `host` that just ended never sent its
    /// SYN.
    ///
    /// `None` when the neighbour is resolved, has no entry, or there is no table to
    /// read; the connect is then read as it ended.
    pub(super) fn holding(&self, host: IpAddr) -> Option<NeighborState> {
        let table = self.table.as_ref()?;
        let neighbour = table.next_hop(host)?;
        table
            .state(neighbour, Instant::now())
            .filter(|state| state.is_unresolved())
    }

    /// Until when connects to `host` are held for the kernel's hold-down on
    /// its neighbour, if they still are.
    pub(super) fn held_until(&self, host: IpAddr) -> Option<Instant> {
        lock(&self.holds).until(host, Instant::now())
    }

    /// Holds `host` through the kernel's hold-down on its neighbour after a connect
    /// was refused with `why`, returning when the hold-down ends. If the refusal is
    /// the kernel's verdict, gives the neighbour up and returns `None`. See
    /// [`HoldDowns::hold`].
    pub(super) fn hold_down(&self, host: IpAddr, why: &std::io::Error) -> Option<Instant> {
        let now = Instant::now();
        let (held, until, hold_down_for) = {
            let mut holds = lock(&self.holds);
            let held = holds.until(host, now).is_some();
            (held, holds.hold(host, now), holds.hold_down_for)
        };
        match until {
            Some(_) if !held => info!(
                verbosity = 2,
                "{host} held down by the kernel, asked again in {}s ({why})",
                hold_down_for.as_secs()
            ),
            Some(_) => {}
            None => self.give_up(host),
        }
        until
    }

    /// Whether the neighbour `host`'s connects wait on has been given up, so `host` is
    /// sent nothing more. Logs `host` unreachable the first time.
    pub(super) fn unreached(&self, host: IpAddr) -> bool {
        let neighbour = self.neighbour_of(host);
        let given_up = lock(&self.given_up).contains(&neighbour);
        if given_up {
            self.file(host, neighbour);
        }
        given_up
    }

    /// Gives up the neighbour `host`'s connects wait on and logs `host` unreachable.
    pub(super) fn give_up(&self, host: IpAddr) {
        let neighbour = self.neighbour_of(host);
        lock(&self.given_up).insert(neighbour);
        self.file(host, neighbour);
    }

    /// The neighbour a connect to `host` waits on: the next hop from the table's
    /// routes, or `host` itself when there is no table.
    fn neighbour_of(&self, host: IpAddr) -> IpAddr {
        self.table
            .as_ref()
            .and_then(|table| table.next_hop(host))
            .unwrap_or(host)
    }

    /// Logs `host` unreachable for `neighbour`, once.
    fn file(&self, host: IpAddr, neighbour: IpAddr) {
        if lock(&self.filed).insert(host) {
            let why = unreached(host, Some(neighbour), NeighborState::Failed);
            info!(verbosity = 2, "{host} unreachable ({why})");
        }
    }
}

/// What becomes of a port whose connect the kernel held for its neighbour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Held {
    /// Connect again, waiting this long.
    Again(Duration),
    /// Give the neighbour up: its host is not reached from here.
    Unreached,
}

/// How one port's connects have fared against the neighbour that held them.
#[derive(Debug, Default)]
pub(super) struct HeldConnects {
    /// Unanswered resolutions of the neighbour this port's connects have met.
    unanswered: u8,
    /// Whether a connect's own timeout already ran out on a resolution still in
    /// progress; a port waits that out once.
    outwaited: bool,
}

impl HeldConnects {
    /// What to do with the port after a connect the kernel held for a neighbour at
    /// `state`. `concluded` is true when the kernel ended the connect as
    /// unreachable, false when the connect's own timeout ran out first.
    ///
    /// A resolution the connect timed out on has not answered yet, since the connect
    /// timeout is as short as an ordinary path allows: the port connects once more,
    /// waiting long enough for a resolution plus the handshake. A resolution that
    /// concluded unanswered counts as one of [`NEIGHBOR_ROUNDS`]: the port connects
    /// again, making the kernel ask afresh, until the last round gives the neighbour
    /// up. A host's ports share the same resolutions, so a dead neighbour costs its
    /// host two resolutions however many ports are in flight.
    pub(super) fn after(&mut self, state: NeighborState, concluded: bool) -> Held {
        let again = Held::Again(NEIGHBOUR_PATH_FINDING_TIMEOUT);
        if !concluded && state == NeighborState::Resolving && !self.outwaited {
            self.outwaited = true;
            return again;
        }
        self.unanswered = self.unanswered.saturating_add(1);
        if self.unanswered < NEIGHBOR_ROUNDS {
            again
        } else {
            Held::Unreached
        }
    }
}

/// Reads no table: every connect is read as it ended.
impl Default for Neighbours {
    fn default() -> Self {
        Self::reading(None)
    }
}

/// Locks `held`, ignoring poisoning: every section under these locks leaves its
/// data consistent.
fn lock<T>(held: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    held.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::kernel_neighbors::NeighborTable;
    use std::net::Ipv4Addr;

    const HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    const ROUTED: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    const GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254));

    /// Neighbours read from `table`, with [`HOST`] on a local link and [`ROUTED`]
    /// behind [`GATEWAY`].
    fn reading(table: NeighborTable) -> Neighbours {
        let table = KernelNeighbors::with_reader(Box::new(move || Ok(table.clone()))).routing(
            Box::new(|address| Ok(Some(if address == ROUTED { GATEWAY } else { address }))),
        );
        Neighbours::reading(Some(table))
    }

    /// Only an unresolved neighbour holds a connect; a resolved one (where a router's
    /// unreachable comes from) or one missing from the table does not.
    #[test]
    fn only_an_unresolved_neighbour_holds_a_connect() {
        for state in [NeighborState::Failed, NeighborState::Resolving] {
            let neighbours = reading(NeighborTable::from([(HOST, state), (GATEWAY, state)]));
            assert_eq!(neighbours.holding(HOST), Some(state));
            assert_eq!(
                neighbours.holding(ROUTED),
                Some(state),
                "read at its gateway"
            );
        }
        let answered = reading(NeighborTable::from([
            (HOST, NeighborState::Resolved),
            (GATEWAY, NeighborState::Resolved),
        ]));
        assert_eq!(answered.holding(HOST), None);
        assert_eq!(answered.holding(ROUTED), None);
        assert_eq!(reading(NeighborTable::new()).holding(HOST), None);
        assert_eq!(Neighbours::default().holding(HOST), None);
    }

    /// Giving up a gateway gives up every host behind it, and nothing else.
    #[test]
    fn a_gateway_given_up_leaves_every_host_behind_it_unreached() {
        let neighbours = reading(NeighborTable::new());
        let beside = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
        assert!(!neighbours.unreached(ROUTED));

        neighbours.give_up(beside);

        assert!(
            !neighbours.unreached(ROUTED),
            "{beside} is its own neighbour"
        );
        neighbours.give_up(ROUTED);
        assert!(neighbours.unreached(ROUTED));
        assert!(!neighbours.unreached(HOST));
    }

    /// A connect that timed out on a resolution in progress is retried once, and a
    /// port meets two unanswered resolutions before its neighbour is given up.
    #[test]
    fn a_port_is_given_up_after_its_second_unanswered_resolution() {
        let mut held = HeldConnects::default();
        let again = Held::Again(NEIGHBOUR_PATH_FINDING_TIMEOUT);

        assert_eq!(held.after(NeighborState::Resolving, false), again);
        assert_eq!(held.after(NeighborState::Failed, true), again);
        assert_eq!(held.after(NeighborState::Failed, true), Held::Unreached);

        let mut held = HeldConnects::default();
        assert_eq!(held.after(NeighborState::Resolving, false), again);
        assert_eq!(held.after(NeighborState::Resolving, false), again);
        assert_eq!(
            held.after(NeighborState::Resolving, false),
            Held::Unreached,
            "a resolution that never concludes still ends"
        );
    }
}
