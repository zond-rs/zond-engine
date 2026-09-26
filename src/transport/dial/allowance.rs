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
/// may take to arrive, and how much of that the path itself takes.
///
/// Zero where nothing was measured, which leaves every wait as it is set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PathAllowance {
    /// What every wait on the path adds: its round trip and the headroom
    /// its measurements earn.
    allowance: Duration,
    /// The path's smoothed round trip, which a reply spends crossing it
    /// whatever the service does.
    round_trip: Duration,
}

impl PathAllowance {
    /// No allowance: a path nothing was measured on.
    pub(crate) const NONE: Self = Self {
        allowance: Duration::ZERO,
        round_trip: Duration::ZERO,
    };

    /// The allowance a path measured at `round_trip` alone earns: the
    /// timeout the port scans give a probe to a host seeded with that one
    /// round trip, three round trips in all; see
    /// [`of_round_trips`](Self::of_round_trips).
    #[cfg(test)]
    pub(crate) fn of_round_trip(round_trip: Duration) -> Self {
        Self::of_round_trips([round_trip])
    }

    /// The allowance a path measured at `round_trips`, oldest first, earns,
    /// or none where there are none: the timeout the port scans give a probe
    /// to a host whose replies came back after those.
    ///
    /// That is RFC 6298's: the smoothed round trip, with four times its
    /// smoothed variation on top, and never less than a quarter of it. The
    /// first sample seeds the variation at half itself, so one round trip
    /// alone earns three: one sample says nothing of how far the next may
    /// stray. Each sample after it that agrees narrows the headroom, so a
    /// slow path that has answered steadily is waited on for a little more
    /// than its round trip rather than three times it, and one whose replies
    /// wander keeps the headroom they showed it needs. The floor keeps a
    /// reply a quarter slower than usual from being given up on, which is
    /// how far a steady path's stragglers stray.
    ///
    /// Spelled here rather than read off the port scans' estimator, which
    /// lives above this module; a test beside that estimator holds the two to
    /// the same figure.
    pub(crate) fn of_round_trips(round_trips: impl IntoIterator<Item = Duration>) -> Self {
        let mut samples = round_trips.into_iter();
        let Some(first) = samples.next() else {
            return Self::NONE;
        };
        let (mut smoothed, mut variation) = (first, first / 2);
        for sample in samples {
            variation = (variation * 3 + smoothed.abs_diff(sample)) / 4;
            smoothed = (smoothed * 7 + sample) / 8;
        }
        Self {
            allowance: smoothed.saturating_add((variation * 4).max(smoothed / 4)),
            round_trip: smoothed,
        }
    }

    /// `wait`, which a path that costs nothing needs, on this path.
    pub(crate) fn over(self, wait: Duration) -> Duration {
        wait.saturating_add(self.allowance)
    }

    /// `wait` on this path for a walk that waits on the path `waits` times
    /// in a row, each wait allowing for it once.
    pub(crate) fn over_each(self, wait: Duration, waits: u32) -> Duration {
        wait.saturating_add(self.allowance.saturating_mul(waits))
    }

    /// How much of `elapsed`, the time a reply took to arrive, was the
    /// service's rather than the path's.
    ///
    /// What a service's lateness is read from: a reply across a slow path
    /// arrives a round trip after it was sent however promptly it was
    /// written, and read as the service's own time it would call every
    /// prompt service behind such a path late.
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

    /// A wait on a measured path outlasts the round trip it has to carry, and
    /// a path nothing measured leaves the wait as it is set.
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

    /// **A slow path that has answered steadily is waited on for a little
    /// more than its round trip, and one whose replies wander keeps the
    /// headroom they showed it needs.**
    ///
    /// Three round trips of headroom on every wait is what one sample earns,
    /// and a conversation with a silent port waits several times in a row: a
    /// steady path two seconds away made each such port cost the better part
    /// of a minute. Still never less than the round trip and a quarter, so a
    /// reply a little slower than the rest is not given up on.
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

        assert_eq!(one, path * 3);
        assert_eq!(steady, path + path / 4, "the floor, once the path agrees");
        assert!(wandering > path * 2, "{wandering:?}");
    }

    /// A reply across a slow path that came as soon as the path let it spent
    /// none of the service's time, and on a path nothing measured all of the
    /// time is the service's.
    ///
    /// Lateness read off the whole wait calls a prompt service two seconds
    /// away late once the headroom is narrow, and a late answer has its
    /// host's silent ports asked all over again, alone.
    #[test]
    fn a_reply_spends_the_services_time_only_beyond_the_paths_round_trip() {
        let path = Duration::from_millis(1_900);
        let prompt = path + Duration::from_millis(30);
        let steady = PathAllowance::of_round_trips([path; 10]);

        assert_eq!(steady.service_time(prompt), Duration::from_millis(30));
        assert_eq!(PathAllowance::NONE.service_time(prompt), prompt);
    }
}
