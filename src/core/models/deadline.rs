// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Adaptive Scan Deadlines
//!
//! Combines [`ScanTimer`] and [`RttWindow`] into a single policy for
//! deciding how long a discovery sweep should keep running.
//!
//! The timer alone can only enforce fixed limits; the window alone only
//! tracks statistics. Neither answers the actual question a scanning loop
//! needs answered on every iteration: "have we been quiet long enough to
//! give up?" [`AdaptiveDeadline`] answers that by deriving the timer's
//! silence tolerance from the window's own recent samples, so the two
//! pieces of state are always used together and a scanner never has to
//! wire them up itself.

use std::time::Duration;

use super::rtt_window::RttWindow;
use super::timer::{ScanBudget, ScanTimer};

/// The fixed parameters an [`AdaptiveDeadline`] is built from.
///
/// `max_budget` and `min_budget` scale the hard deadline and minimum
/// runtime with the number of targets being scanned. `silence_floor` and
/// `silence_ceiling` bound how far the silence tolerance is allowed to
/// adapt, `jitter_multiplier` controls how much safety margin recent
/// jitter adds to it, and `rtt_window_capacity` sets how many recent
/// samples inform that adaptation. See [`RttWindow::suggest_timeout`] for
/// exactly how the latter three combine.
#[derive(Debug, Clone, Copy)]
pub struct AdaptiveDeadlineConfig {
    pub max_budget: ScanBudget,
    pub min_budget: ScanBudget,
    pub silence_floor: Duration,
    pub silence_ceiling: Duration,
    pub jitter_multiplier: f64,
    pub rtt_window_capacity: usize,
}

impl AdaptiveDeadlineConfig {
    pub const fn new(
        max_budget: ScanBudget,
        min_budget: ScanBudget,
        silence_floor: Duration,
        silence_ceiling: Duration,
        jitter_multiplier: f64,
        rtt_window_capacity: usize,
    ) -> Self {
        Self {
            max_budget,
            min_budget,
            silence_floor,
            silence_ceiling,
            jitter_multiplier,
            rtt_window_capacity,
        }
    }
}

/// Decides when a discovery sweep should stop, adapting to how quickly and
/// how consistently hosts have responded so far.
///
/// A scanner calls [`AdaptiveDeadline::mark_activity`] whenever it learns
/// something new (typically: discovers a host it hadn't seen before) and
/// [`AdaptiveDeadline::record_rtt`] whenever it can measure a round-trip
/// time, then asks [`AdaptiveDeadline::has_expired`] on every iteration of
/// its receive loop. [`AdaptiveDeadline::time_until_next_tick`] gives a
/// duration suitable for sleeping until the next check is worthwhile,
/// rather than busy-polling.
pub struct AdaptiveDeadline {
    timer: ScanTimer,
    rtt_window: RttWindow,
    silence_floor: Duration,
    silence_ceiling: Duration,
    jitter_multiplier: f64,
}

impl AdaptiveDeadline {
    /// Builds a deadline sized for a scan covering `target_count` addresses.
    pub fn new(config: AdaptiveDeadlineConfig, target_count: usize) -> Self {
        Self {
            timer: ScanTimer::new(
                config.max_budget.for_target_count(target_count),
                config.min_budget.for_target_count(target_count),
            ),
            rtt_window: RttWindow::new(config.rtt_window_capacity),
            silence_floor: config.silence_floor,
            silence_ceiling: config.silence_ceiling,
            jitter_multiplier: config.jitter_multiplier,
        }
    }

    /// Resets the silence clock. Call this when the scan learns something
    /// new, as opposed to every packet - repeated activity from an already
    /// known host doesn't represent new information about whether the scan
    /// is still worth continuing.
    pub fn mark_activity(&mut self) {
        self.timer.mark_activity();
    }

    /// Feeds a newly measured round-trip time into the adaptive estimate.
    pub fn record_rtt(&mut self, rtt: Duration) {
        self.rtt_window.record(rtt);
    }

    fn silence_tolerance(&self) -> Duration {
        self.rtt_window.suggest_timeout(
            self.jitter_multiplier,
            self.silence_floor,
            self.silence_ceiling,
        )
    }

    /// Reports whether the scan should stop: either the hard deadline has
    /// passed, or the minimum runtime has elapsed and nothing new has
    /// happened for longer than the current silence tolerance justifies.
    pub fn has_expired(&self) -> bool {
        self.timer.has_expired(self.silence_tolerance())
    }

    /// How long a caller should wait before checking [`has_expired`](Self::has_expired) again.
    pub fn time_until_next_tick(&self) -> Duration {
        self.timer.time_until_next_tick(self.silence_tolerance())
    }
}
