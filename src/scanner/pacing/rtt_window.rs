// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A timeout taken from what the network just did
//!
//! A fixed timeout is wrong in both directions at once: short enough to give up
//! on a slow host that would have answered, long enough to spend the scan
//! waiting on hosts that never will. Neither value exists, because the right one
//! is a property of the path and nobody knows the path in advance.
//!
//! [`RttWindow`] takes it from measurement instead. A short history of recent
//! round trips, and a timeout derived from their middle and their spread: a
//! fast, steady path suggests a short one and an erratic path a long one,
//! without anybody choosing either.
//!
//! ## Why a window and not a smoothed estimate
//!
//! [`RttEstimator`](super::retry::RttEstimator) is the smoothed one, and it is
//! kept per host: two durations updated in place, which is what makes
//! per-host timing affordable at all. This is kept once per scan and holds real
//! samples, because what it steers is the scan's own deadline: how long the
//! whole run waits before concluding that silence means the end. That question
//! is about the population rather than about any host in it, and a queue of
//! twenty answers it where a running average cannot.

use std::{collections::VecDeque, time::Duration};

/// The last few round trips a scan measured, and the timeout they justify.
///
/// Bounded and first-in-first-out: past its capacity the oldest sample goes, so
/// what it describes is the network now rather than the average of everything
/// since the scan started. A path that slows down halfway through is one the
/// window follows.
#[derive(Debug, Clone)]
pub struct RttWindow {
    samples: VecDeque<Duration>,
    capacity: usize,
}

impl RttWindow {
    /// An empty window holding at most `capacity` samples.
    ///
    /// A capacity of zero records nothing and suggests the floor forever, which
    /// is a working configuration for a caller that wants a fixed timeout out of
    /// the same type rather than a special case.
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

    /// The mean difference between one sample and the next: how much the path
    /// moves between measurements rather than how far each sits from the
    /// middle.
    ///
    /// **Not RFC 6298's `RTTVAR`**, which is the smoothed deviation from the
    /// estimate and is what
    /// [`RttEstimator`](super::retry::RttEstimator) computes. This is the
    /// cheaper statistic over a real window, and it answers a slightly different
    /// question: successive differences catch a path that is oscillating, where
    /// deviation from a mean catches one that is merely wide. For sizing a
    /// scan's patience either would serve, and only one of them needs the
    /// estimate kept.
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
    /// buys; around `4.0` is the same order TCP allows its own retransmission
    /// timeout, though the statistic here is the mean successive difference
    /// rather than RFC 6298's smoothed deviation. With nothing recorded yet
    /// `floor` comes back, there being no measurement to justify waiting
    /// longer.
    ///
    /// **A ceiling below the floor does not panic.** The floor wins, on the
    /// same reasoning [`ProbeLedger`](super::retry::ProbeLedger) applies to its
    /// own bounds: it is the one of the two imposed rather than chosen, and a
    /// pair that has been configured into disagreeing should still describe a
    /// real range. `Duration::clamp` asserts instead, and this is public API
    /// taking two adjacent arguments of one type, so the mistake reached a live
    /// scan and took the caller's process with it on the first host that
    /// answered.
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

        // The 100ms sample should have been evicted; mean of [200, 300] = 250.
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

    /// `floor` and `ceiling` are adjacent arguments of one type, so a caller
    /// can cross them and the compiler cannot say. `Duration::clamp` asserted
    /// `min <= max`, which made that mistake a panic in the caller's process,
    /// and one that waited for the first sample: a scan opened its sockets,
    /// sent its probes and died on the first host that answered.
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

    /// The empty window took the early return and never reached the clamp,
    /// which is exactly why the panic was invisible until a scan was underway.
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
