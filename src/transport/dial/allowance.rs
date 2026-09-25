// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a measured path adds to a conversation's waits
//!
//! The waits a service conversation runs on, a connect, a greeting, the reply
//! to a probe, are set for a path that costs nothing: each is how long the
//! service may take to answer once asked. A path that costs a round trip adds
//! that round trip to every one of them, and a wait that does not allow for it
//! gives up on an answer that is still on its way, however promptly the
//! service sent it.
//!
//! The scan has measured the path by the time it holds such a conversation,
//! finding the host and finding its ports, and the port scans and the echo
//! pass already time their probes from that measurement. This turns the same
//! measurement into the same patience for the conversations that follow, so
//! the passes that talk to a service allow for the path the passes before them
//! found.

use std::time::Duration;

/// How much longer than on a path that costs nothing a reply from one host
/// may take to arrive.
///
/// Zero where nothing was measured, which leaves every wait as it is set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PathAllowance(Duration);

impl PathAllowance {
    /// No allowance: a path nothing was measured on.
    pub(crate) const NONE: Self = Self(Duration::ZERO);

    /// The allowance a path measured at `round_trip` earns: the timeout the
    /// port scans give a probe to a host seeded with that one round trip.
    ///
    /// That is RFC 6298's first measurement, the round trip itself with four
    /// times a variation taken as half of it on top, three round trips in
    /// all: one sample says nothing of how far the next may stray, and the
    /// headroom is what keeps a reply a little slower than the first from
    /// being given up on. Spelled here rather than read off the port scans'
    /// estimator, which lives above this module; a test beside that
    /// estimator holds the two to the same figure.
    pub(crate) fn of_round_trip(round_trip: Duration) -> Self {
        Self(round_trip.saturating_mul(3))
    }

    /// The allowance for a host whose typical round trip is `median`, or none
    /// where the scan measured none. The median, for the reason the port
    /// scans seed their timing from it: a wait sized from a host's fastest
    /// reply misses its typical one.
    pub(crate) fn of_median(median: Option<Duration>) -> Self {
        median.map_or(Self::NONE, Self::of_round_trip)
    }

    /// `wait`, which a path that costs nothing needs, on this path.
    pub(crate) fn over(self, wait: Duration) -> Duration {
        wait.saturating_add(self.0)
    }

    /// `wait` on this path for a walk that waits on the path `waits` times
    /// in a row, each wait allowing for it once.
    pub(crate) fn over_each(self, wait: Duration, waits: u32) -> Duration {
        wait.saturating_add(self.0.saturating_mul(waits))
    }
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

    /// A wait on a measured path outlasts the round trip it has to carry, and
    /// a path nothing measured leaves the wait as it is set.
    #[test]
    fn a_wait_on_a_measured_path_outlasts_its_round_trip() {
        let wait = Duration::from_millis(500);
        let path = Duration::from_millis(1_900);

        let stretched = PathAllowance::of_median(Some(path)).over(wait);
        assert!(stretched > wait + path, "{stretched:?}");
        assert_eq!(PathAllowance::of_median(None).over(wait), wait);
        assert_eq!(
            PathAllowance::of_round_trip(path).over_each(wait, 2),
            wait + (stretched - wait) * 2
        );
    }
}
