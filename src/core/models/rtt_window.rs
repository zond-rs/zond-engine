// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Adaptive Timeout Estimation
//!
//! A fixed timeout is always a compromise: too short, and it gives up on
//! slow but genuinely reachable hosts; too long, and it wastes time waiting
//! for hosts that were never going to answer. [`RttWindow`] avoids that
//! compromise by tracking a short history of recently observed round-trip
//! times and deriving a timeout from their average and variability: a fast,
//! stable network yields a short suggested timeout, while a slow or erratic
//! one yields a longer one.

use std::{collections::VecDeque, time::Duration};

/// A bounded, first-in-first-out history of round-trip-time samples, used to
/// suggest timeouts that reflect recently observed network conditions.
///
/// New samples are added with [`RttWindow::record`]. Once the configured
/// capacity is reached, the oldest sample is discarded to make room for the
/// newest, so the window always reflects *recent* conditions rather than
/// everything observed since it was created.
#[derive(Debug, Clone)]
pub struct RttWindow {
    samples: VecDeque<Duration>,
    capacity: usize,
}

impl RttWindow {
    /// Creates an empty window that retains at most `capacity` samples.
    pub fn new(capacity: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Records a newly observed round-trip time, evicting the oldest sample
    /// first if the window is already full.
    pub fn record(&mut self, rtt: Duration) {
        if self.capacity == 0 {
            return;
        }

        self.samples.push_back(rtt);
        while self.samples.len() > self.capacity {
            self.samples.pop_front();
        }
    }

    /// Returns `true` if no samples have been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Returns the arithmetic mean of all samples currently in the window.
    pub fn mean(&self) -> Option<Duration> {
        if self.samples.is_empty() {
            return None;
        }

        let sum: Duration = self.samples.iter().copied().sum();
        Some(sum / self.samples.len() as u32)
    }

    /// Returns the average absolute difference between consecutive samples:
    /// a simple measure of how much round-trip times vary from one
    /// measurement to the next. Higher jitter means less predictable timing.
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
    /// The suggestion is `mean + multiplier * jitter`, clamped to
    /// `[floor, ceiling]`. `multiplier` controls how much safety margin is
    /// added for variability; a value around `4.0` mirrors the margin TCP
    /// uses for its own retransmission timeout. If no samples have been
    /// recorded yet, `floor` is returned, since there is no data yet to
    /// justify a longer wait.
    pub fn suggest_timeout(&self, multiplier: f64, floor: Duration, ceiling: Duration) -> Duration {
        let Some(mean) = self.mean() else {
            return floor;
        };

        let jitter = self.jitter().unwrap_or(Duration::ZERO);
        let margin = jitter.mul_f64(multiplier);

        (mean + margin).clamp(floor, ceiling)
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

    #[test]
    fn zero_capacity_window_never_stores_samples() {
        let mut window = RttWindow::new(0);
        window.record(Duration::from_millis(100));

        assert!(window.is_empty());
    }
}
