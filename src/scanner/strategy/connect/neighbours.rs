// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The neighbours a connect waits on
//!
//! A connect to a host on one of this machine's links, or through a gateway
//! on one, waits for the kernel to resolve that neighbour's hardware address
//! before its SYN leaves, and Linux tells the socket nothing of how the
//! asking goes. A connect to a neighbour that does not answer is held for the
//! three seconds the kernel asks and then fails with a host unreachable the
//! kernel addresses to itself, the very error a router's ICMP host
//! unreachable raises for a host beyond it; given less than those three
//! seconds, it runs out as a dropped SYN does. Read as either, every port of
//! an address nothing holds is filtered, though no SYN left for any of them.
//!
//! The kernel's neighbour table tells them apart. Read as the connect ends,
//! an entry for the neighbour it waited on that is not resolved says the SYN
//! never left; a router's error comes back through a neighbour that
//! answered. [`Neighbours`] reads it, and remembers each neighbour given up
//! on, so every other port of a host behind one is left unasked rather than
//! each waiting out a resolution of its own. A port is given up on only
//! after a second resolution goes unanswered, as the raw path gives a
//! neighbour up: see [`NEIGHBOR_ROUNDS`].
//!
//! Linux only, as the table is; see [`KernelNeighbors`]. Elsewhere nothing
//! here reads anything, and every connect is read as it ended.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::limits::NEIGHBOUR_PATH_FINDING_TIMEOUT;
use crate::logging::info;
use crate::scanner::strategy::raw::neighbors::{NEIGHBOR_ROUNDS, unreached};
use crate::transport::kernel_neighbors::{KernelNeighbors, NeighborState};

/// What a connect port scan knows of the neighbours its connects wait on.
pub(super) struct Neighbours {
    /// The kernel's neighbour table, where this platform has one to read.
    table: Option<KernelNeighbors>,
    /// The neighbours given up on, whose hosts are sent nothing more.
    given_up: Mutex<HashSet<IpAddr>>,
    /// The hosts filed unreachable for one, each logged once.
    filed: Mutex<HashSet<IpAddr>>,
}

impl Neighbours {
    /// Reading the running kernel's table.
    pub(super) fn of_system() -> Self {
        Self::reading(KernelNeighbors::from_system())
    }

    /// Reading `table`, or nothing.
    pub(super) fn reading(table: Option<KernelNeighbors>) -> Self {
        Self {
            table,
            given_up: Mutex::default(),
            filed: Mutex::default(),
        }
    }

    /// Where the neighbour a connect to `host` waits on stands, read now,
    /// where the kernel has not resolved it: a connect to `host` that just
    /// ended then never sent its SYN.
    ///
    /// `None` where the neighbour is resolved, where the table holds no entry
    /// for it, and where there is no table or no neighbour to read: a connect
    /// that ended is then read as it ended.
    pub(super) fn holding(&self, host: IpAddr) -> Option<NeighborState> {
        let table = self.table.as_ref()?;
        let neighbour = table.next_hop(host)?;
        table
            .state(neighbour, Instant::now())
            .filter(|state| state.is_unresolved())
    }

    /// Whether the neighbour `host`'s connects wait on has been given up on,
    /// so `host` is sent nothing more; filed unreachable, the first time.
    pub(super) fn unreached(&self, host: IpAddr) -> bool {
        let Some(neighbour) = self.neighbour_of(host) else {
            return false;
        };
        let given_up = lock(&self.given_up).contains(&neighbour);
        if given_up {
            self.file(host, neighbour);
        }
        given_up
    }

    /// Gives up the neighbour `host`'s connects wait on, and files `host`
    /// unreachable.
    pub(super) fn give_up(&self, host: IpAddr) {
        let neighbour = self.neighbour_of(host).unwrap_or(host);
        lock(&self.given_up).insert(neighbour);
        self.file(host, neighbour);
    }

    /// The neighbour a connect to `host` waits on, where there is one to read.
    fn neighbour_of(&self, host: IpAddr) -> Option<IpAddr> {
        self.table.as_ref()?.next_hop(host)
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
    /// The resolutions of the neighbour the port's connects met unanswered.
    unanswered: u8,
    /// Whether a connect's own wait has run out on a resolution still
    /// running, which a port waits out once.
    outwaited: bool,
}

impl HeldConnects {
    /// What becomes of the port after a connect the kernel held for a
    /// neighbour at `state`, which the kernel ended as unreachable, where it
    /// `concluded`, or the connect's own wait ended first.
    ///
    /// A resolution the connect gave up on first has not said anything yet,
    /// the connect's wait being as short as an ordinary path allows: the port
    /// connects again, once, waiting long enough for a resolution and the
    /// handshake behind it. One that concluded unanswered is a round of
    /// [`NEIGHBOR_ROUNDS`]: the port connects again, which has the kernel ask
    /// afresh, until the last, when the neighbour is given up. The connects
    /// of a host's ports meet the same resolutions, so a dead neighbour costs
    /// its host two resolutions however many ports are asked at once.
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

/// Reading nothing: every connect is read as it ended.
impl Default for Neighbours {
    fn default() -> Self {
        Self::reading(None)
    }
}

/// `held`, taken even where a thread panicked holding it: every section
/// under these locks leaves what it holds whole.
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

    /// Neighbours read from a table holding `table`, with [`HOST`] on a link
    /// of this machine's and [`ROUTED`] behind [`GATEWAY`].
    fn reading(table: NeighborTable) -> Neighbours {
        let table = KernelNeighbors::with_reader(Box::new(move || Ok(table.clone()))).routing(
            Box::new(|address| Ok(Some(if address == ROUTED { GATEWAY } else { address }))),
        );
        Neighbours::reading(Some(table))
    }

    /// A connect ended by a neighbour the kernel has not resolved is told
    /// from one that crossed a neighbour that answered, which is where a
    /// router's unreachable comes from, and from one the table knows nothing
    /// of, which is read as it ended.
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

    /// A connect that ran out on a resolution still running is asked again
    /// once, waiting for it, and a port meets two unanswered resolutions
    /// before its neighbour is given up.
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
