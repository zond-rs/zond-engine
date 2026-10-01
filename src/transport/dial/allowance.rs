// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a measured path adds to a conversation's waits
//!
//! The waits a service conversation runs on (a connect, a greeting, the reply to a
//! probe) are set for a path that costs nothing: each is how long the service may take
//! to answer. A path that costs a round trip adds it to every one of them, and a wait
//! that does not allow for it gives up on answers still in flight.
//!
//! By the time it holds a conversation the scan has measured the path, and the port
//! scans and the echo pass already time their probes from that measurement. This turns
//! the same measurement into patience for the service conversations.

use std::time::Duration;

/// The most a round trip measured alone earns, unless it and the floor's quarter need
/// more: the connect path's path-finding wait, used for a path nothing was measured
/// on. A test beside that wait keeps the two equal.
pub(crate) const UNMEASURED_PATH_WAIT: Duration = Duration::from_secs(3);

/// How much longer than on a free path a reply from one host may take to arrive, and
/// how much of that is the path itself.
///
/// Zero where nothing was measured, which leaves every wait as set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PathAllowance {
    /// What every wait on the path adds: its round trip and the headroom its
    /// measurements earn.
    allowance: Duration,
    /// The path's smoothed round trip, which a reply spends crossing it whatever the
    /// service does.
    round_trip: Duration,
}

impl PathAllowance {
    /// No allowance: a path nothing was measured on.
    pub(crate) const NONE: Self = Self {
        allowance: Duration::ZERO,
        round_trip: Duration::ZERO,
    };

    /// The allowance a path measured at `round_trip` alone earns: the timeout the port
    /// scans give a probe to a host seeded with that round trip, three round trips in
    /// all, held to the path-finding wait on a slow path; see
    /// [`of_round_trips`](Self::of_round_trips).
    #[cfg(test)]
    pub(crate) fn of_round_trip(round_trip: Duration) -> Self {
        Self::of_round_trips([round_trip])
    }

    /// The allowance a path measured at `round_trips`, oldest first, earns, or none
    /// for an empty slice: the timeout the port scans give a probe to a host whose
    /// replies took those round trips.
    ///
    /// That is RFC 6298's: the smoothed round trip plus four times its smoothed
    /// variation, never less than a quarter of it on top. The first sample seeds the
    /// variation at half itself, so one round trip alone earns three. Each agreeing
    /// sample after it narrows the headroom, so a steady slow path is waited on for a
    /// little more than its round trip, and one whose replies wander keeps the headroom
    /// they need. The quarter floor covers a steady path's stragglers.
    ///
    /// Computed here because the port scans' estimator lives above this module; a test
    /// beside that estimator keeps the two equal, except for one case. A round trip
    /// measured alone earns no more than [`UNMEASURED_PATH_WAIT`], unless the round
    /// trip and the floor's quarter need more. A lone first sample of a slow path often
    /// carries more than the path (a handshake that waited on neighbour resolution, or
    /// a resent SYN), and a conversation waits on the path several times in a row, so
    /// three of those per wait add up fast. Below a second of round trip the cap is not
    /// reached, and a second sample lifts it.
    pub(crate) fn of_round_trips(round_trips: impl IntoIterator<Item = Duration>) -> Self {
        let mut samples = round_trips.into_iter();
        let Some(first) = samples.next() else {
            return Self::NONE;
        };
        let (mut smoothed, mut variation, mut alone) = (first, first / 2, true);
        for sample in samples {
            variation = (variation * 3 + smoothed.abs_diff(sample)) / 4;
            smoothed = (smoothed * 7 + sample) / 8;
            alone = false;
        }
        let floor = smoothed.saturating_add(smoothed / 4);
        let mut allowance = smoothed.saturating_add((variation * 4).max(smoothed / 4));
        if alone {
            allowance = allowance.min(UNMEASURED_PATH_WAIT.max(floor));
        }
        Self {
            allowance,
            round_trip: smoothed,
        }
    }

    /// `wait`, as set for a free path, on this path.
    pub(crate) fn over(self, wait: Duration) -> Duration {
        wait.saturating_add(self.allowance)
    }

    /// `wait` on this path for a walk that waits on the path `waits` times in a row,
    /// each wait allowing for it once.
    pub(crate) fn over_each(self, wait: Duration, waits: u32) -> Duration {
        wait.saturating_add(self.allowance.saturating_mul(waits))
    }

    /// How much of `elapsed`, the time a reply took to arrive, was the service's own.
    ///
    /// A service's lateness is read from this: a reply across a slow path arrives a
    /// round trip after it was sent, and counting that as the service's time would
    /// call every prompt service behind such a path late.
    pub(crate) fn service_time(self, elapsed: Duration) -> Duration {
        elapsed.saturating_sub(self.round_trip)
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

    /// A wait on a measured path outlasts the round trip it has to carry, and a path
    /// nothing measured leaves the wait as set.
    #[test]
    fn a_wait_on_a_measured_path_outlasts_its_round_trip() {
        let wait = Duration::from_millis(500);
        let path = Duration::from_millis(1_900);

        let stretched = PathAllowance::of_round_trip(path).over(wait);
        assert!(stretched > wait + path, "{stretched:?}");
        assert_eq!(PathAllowance::of_round_trips([]).over(wait), wait);
        assert_eq!(
            PathAllowance::of_round_trip(path).over_each(wait, 2),
            wait + (stretched - wait) * 2
        );
    }

    /// **A steady slow path is waited on for a little more than its round trip, and
    /// one whose replies wander keeps the headroom they need.**
    ///
    /// One sample earns three round trips of headroom on every wait, and a
    /// conversation with a silent port waits several times in a row: on a steady path
    /// two seconds away each such port would cost most of a minute. Still never less
    /// than the round trip and a quarter.
    #[test]
    fn a_steady_path_earns_less_headroom_than_one_sample_or_a_wandering_path() {
        let path = Duration::from_millis(1_900);
        let one = PathAllowance::of_round_trip(path).over(Duration::ZERO);
        let steady = PathAllowance::of_round_trips([path; 10]).over(Duration::ZERO);
        let wandering = PathAllowance::of_round_trips(
            [
                900, 2_900, 1_000, 2_800, 1_100, 2_700, 900, 2_900, 1_000, 2_800,
            ]
            .map(Duration::from_millis),
        )
        .over(Duration::ZERO);

        assert_eq!(one, UNMEASURED_PATH_WAIT, "held to the path-finding wait");
        assert_eq!(steady, path + path / 4, "the floor, once the path agrees");
        assert!(wandering > path * 2, "{wandering:?}");
    }

    /// **One round trip measured alone earns no more patience than an unmeasured path,
    /// unless it needs more.**
    ///
    /// A first sample can carry more than the path: across a path of 1.9 s, a
    /// handshake timed at 2.79 s would earn three times that on every wait of a silent
    /// port's conversation. Held to the path-finding wait, it is waited on as an
    /// unmeasured path is. A fast path keeps its three round trips, a lone sample
    /// slower than the wait keeps the floor over it, and a second sample is weighed as
    /// RFC 6298 weighs it.
    #[test]
    fn a_lone_slow_sample_earns_no_more_than_the_path_finding_wait() {
        let alone = |millis| {
            PathAllowance::of_round_trip(Duration::from_millis(millis)).over(Duration::ZERO)
        };

        let outlier = Duration::from_millis(2_790);
        assert_eq!(alone(2_790), outlier + outlier / 4, "the floor over it");
        assert_eq!(alone(1_900), UNMEASURED_PATH_WAIT);
        assert_eq!(alone(140), Duration::from_millis(420), "three round trips");
        assert_eq!(alone(4_000), Duration::from_millis(5_000), "the floor");

        let two = PathAllowance::of_round_trips([1_900, 1_900].map(Duration::from_millis))
            .over(Duration::ZERO);
        assert!(two > UNMEASURED_PATH_WAIT, "{two:?}");
    }

    /// A reply across a slow path that came as soon as the path allowed spent none of
    /// the service's time; on an unmeasured path all of it is the service's.
    ///
    /// Lateness read off the whole wait would call a prompt service two seconds away
    /// late once the headroom is narrow, and a late answer has its host's silent ports
    /// asked again, alone.
    #[test]
    fn a_reply_spends_the_services_time_only_beyond_the_paths_round_trip() {
        let path = Duration::from_millis(1_900);
        let prompt = path + Duration::from_millis(30);
        let steady = PathAllowance::of_round_trips([path; 10]);

        assert_eq!(steady.service_time(prompt), Duration::from_millis(30));
        assert_eq!(PathAllowance::NONE.service_time(prompt), prompt);
    }
}
