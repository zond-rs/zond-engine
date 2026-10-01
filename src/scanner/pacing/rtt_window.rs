// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A timeout taken from what the network just did
//!
//! The right timeout is a property of the path, which nobody knows in advance.
//! [`RttWindow`] keeps a short history of recent round trips and derives a timeout
//! from their mean and spread: a fast, steady path suggests a short one and an
//! erratic path a long one.
//!
//! [`RttEstimator`](super::retry::RttEstimator) is the smoothed per-host estimate,
//! two durations updated in place. This window is kept once per scan and steers the
//! scan's own deadline, how long the whole run waits before silence means the end,
//! which is a question about the population of hosts.

use std::{collections::VecDeque, time::Duration};

/// The last few round trips a scan measured, and the timeout they justify.
///
/// Bounded and first-in-first-out: past its capacity the oldest sample goes, so
/// the window follows a path that slows down partway through.
#[derive(Debug, Clone)]
pub struct RttWindow {
    samples: VecDeque<Duration>,
    capacity: usize,
}

impl RttWindow {
    /// An empty window holding at most `capacity` samples.
    ///
    /// A capacity of zero records nothing and always suggests the floor, which
    /// gives a fixed timeout.
    pub fn new(capacity: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Folds in one measured round trip, dropping the oldest if the window is
    /// full.
    pub fn record(&mut self, rtt: Duration) {
        if self.capacity == 0 {
            return;
        }

        self.samples.push_back(rtt);
        if self.samples.len() > self.capacity {
            self.samples.pop_front();
        }
    }

    /// Whether nothing has been measured yet, which is when
    /// [`suggest_timeout`](Self::suggest_timeout) has only the floor to offer.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// The mean of the samples held, or `None` while there are none.
    pub fn mean(&self) -> Option<Duration> {
        if self.samples.is_empty() {
            return None;
        }

        let sum: Duration = self.samples.iter().copied().sum();
        Some(sum / self.samples.len() as u32)
    }

    /// The mean difference between one sample and the next, or `None` with fewer
    /// than two samples.
    ///
    /// This is not RFC 6298's `RTTVAR`, the smoothed deviation from the estimate
    /// that [`RttEstimator`](super::retry::RttEstimator) computes. Successive
    /// differences catch a path that oscillates; deviation from a mean catches one
    /// that is merely wide.
    pub fn jitter(&self) -> Option<Duration> {
        if self.samples.len() < 2 {
            return None;
        }

        let mut total = Duration::ZERO;
        let mut previous = self.samples[0];
        for &current in self.samples.iter().skip(1) {
            total += current.abs_diff(previous);
            previous = current;
        }

        Some(total / (self.samples.len() - 1) as u32)
    }

    /// Suggests a timeout derived from recently observed conditions.
    ///
    /// The suggestion is `mean + multiplier * jitter`, held within
    /// `[floor, ceiling]`. `multiplier` is how much margin recent variability
    /// buys; around `4.0` is the order TCP allows its retransmission timeout,
    /// though [`jitter`](Self::jitter) is a different statistic from RFC 6298's.
    /// With nothing recorded, returns `floor`.
    ///
    /// A ceiling below the floor does not panic: the floor wins, as in
    /// [`ProbeLedger`](super::retry::ProbeLedger), since it is the bound the
    /// protocol imposes. `Duration::clamp` would assert, and the crossed arguments
    /// would kill a live scan on the first host that answered.
    pub fn suggest_timeout(&self, multiplier: f64, floor: Duration, ceiling: Duration) -> Duration {
        let Some(mean) = self.mean() else {
            return floor;
        };

        let jitter = self.jitter().unwrap_or(Duration::ZERO);
        let margin = jitter.mul_f64(multiplier.max(0.0));

        (mean + margin).clamp(floor, ceiling.max(floor))
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

    #[test]
    fn empty_window_has_no_statistics() {
        let window = RttWindow::new(5);
        assert!(window.is_empty());
        assert_eq!(window.mean(), None);
        assert_eq!(window.jitter(), None);
    }

    #[test]
    fn suggested_timeout_falls_back_to_floor_when_empty() {
        let window = RttWindow::new(5);
        let floor = Duration::from_millis(200);
        let ceiling = Duration::from_millis(2000);

        assert_eq!(window.suggest_timeout(4.0, floor, ceiling), floor);
    }

    #[test]
    fn mean_and_jitter_match_manual_calculation() {
        let mut window = RttWindow::new(5);
        window.record(Duration::from_millis(100));
        window.record(Duration::from_millis(120));
        window.record(Duration::from_millis(110));

        assert_eq!(window.mean(), Some(Duration::from_millis(110)));
        // |120-100| = 20, |110-120| = 10, average = 15
        assert_eq!(window.jitter(), Some(Duration::from_millis(15)));
    }

    #[test]
    fn oldest_sample_is_evicted_beyond_capacity() {
        let mut window = RttWindow::new(2);
        window.record(Duration::from_millis(100));
        window.record(Duration::from_millis(200));
        window.record(Duration::from_millis(300));

        // 100 ms evicted; mean of [200, 300] = 250.
        assert_eq!(window.mean(), Some(Duration::from_millis(250)));
    }

    #[test]
    fn suggested_timeout_is_clamped_to_the_ceiling() {
        let mut window = RttWindow::new(5);
        window.record(Duration::from_millis(5000));

        let floor = Duration::from_millis(200);
        let ceiling = Duration::from_millis(1000);
        assert_eq!(window.suggest_timeout(4.0, floor, ceiling), ceiling);
    }

    #[test]
    fn suggested_timeout_respects_the_floor_for_fast_stable_samples() {
        let mut window = RttWindow::new(5);
        window.record(Duration::from_millis(1));
        window.record(Duration::from_millis(1));

        let floor = Duration::from_millis(200);
        let ceiling = Duration::from_millis(1000);
        assert_eq!(window.suggest_timeout(4.0, floor, ceiling), floor);
    }

    /// `floor` and `ceiling` are adjacent arguments of one type, so a caller can
    /// cross them. `Duration::clamp` would panic on the first host that answered.
    #[test]
    fn a_ceiling_below_the_floor_yields_the_floor_rather_than_panicking() {
        let mut window = RttWindow::new(5);
        window.record(Duration::from_millis(5));
        window.record(Duration::from_millis(7));

        let floor = Duration::from_secs(3);
        let ceiling = Duration::from_millis(400);

        assert_eq!(
            window.suggest_timeout(4.0, floor, ceiling),
            floor,
            "the floor is the one of the two the protocol imposes, so it wins"
        );
    }

    /// The empty window returns before the clamp, so this case is checked
    /// separately.
    #[test]
    fn crossed_bounds_are_survivable_before_any_sample_too() {
        let window = RttWindow::new(5);
        let floor = Duration::from_secs(3);
        assert_eq!(
            window.suggest_timeout(4.0, floor, Duration::from_millis(400)),
            floor
        );
    }

    #[test]
    fn zero_capacity_window_never_stores_samples() {
        let mut window = RttWindow::new(0);
        window.record(Duration::from_millis(100));

        assert!(window.is_empty());
    }
}
