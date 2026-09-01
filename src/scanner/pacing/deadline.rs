// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How long to keep going
//!
//! [`ScanTimer`] and [`RttWindow`] joined into the one policy a probing loop
//! actually needs.
//!
//! Neither half answers the question on its own. The timer enforces fixed
//! limits and knows nothing about the network; the window measures the network
//! and decides nothing. What a loop asks on every iteration is *have we been
//! quiet long enough to stop*, and that is the timer's question answered with
//! the window's evidence: the silence tolerance comes out of the samples, so a
//! scan on a fast segment gives up on silence in a fraction of the time one
//! crossing an ocean does, and no scanner has to wire the two together to get
//! it.

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
///
/// `#[non_exhaustive]`: built through [`new`](Self::new) and the two builders
/// beside it, never by naming every field. See
/// [`WindowLimits`](super::congestion::WindowLimits) for the argument, which is
/// the same one.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct AdaptiveDeadlineConfig {
    /// The hard deadline, past which the scan stops with whatever it has.
    pub max_budget: ScanBudget,
    /// How long the scan runs before silence is allowed to end it.
    pub min_budget: ScanBudget,
    /// The shortest silence that may end a scan, whatever the round trips
    /// suggest. Also the tolerance in force before anything has been measured.
    pub silence_floor: Duration,
    /// The longest silence the scan will wait through, so one slow responder
    /// cannot hold it open on the strength of its own latency.
    pub silence_ceiling: Duration,
    /// How many multiples of the recent jitter are added to the mean round trip
    /// to reach the tolerance. Around `4.0` is the margin TCP allows its own
    /// retransmission timeout.
    pub jitter_multiplier: f64,
    /// How many recent round-trip samples that mean and jitter are taken over.
    pub rtt_window_capacity: usize,
}

impl AdaptiveDeadlineConfig {
    /// A configuration from the six values described on the fields above.
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

    /// The same configuration, guaranteed to outlast a probe that is retried.
    ///
    /// A scan whose probes are retransmitted has two limits that must not
    /// disagree: how long a single probe may keep trying, and how long the scan
    /// as a whole is allowed to run. If the second is shorter, probes are
    /// written off as unanswered having never been fully asked, and the scan
    /// reports a verdict it did not earn. Deriving the hard budget from the
    /// retry schedule keeps that from happening when either is tuned.
    ///
    /// Only the hard budget is widened. The minimum runtime governs when
    /// *silence* may end a scan, and silence is not evidence while probes are
    /// still outstanding, so it is the caller's loop that has to honour that
    /// rather than the clock.
    pub fn allowing_for(self, probe_lifetime: Duration) -> Self {
        Self {
            max_budget: self.max_budget.with_base_at_least(probe_lifetime),
            ..self
        }
    }

    /// The same configuration, guaranteed to outlast the slowest pace the scan's
    /// own pacing may legitimately choose.
    ///
    /// The companion to [`allowing_for`](Self::allowing_for), and it exists for
    /// the same reason one step out. That one keeps the budget from expiring
    /// between a probe's attempts; this one keeps it from expiring because the
    /// scan slowed itself down on purpose.
    ///
    /// A scan paced by a congestion window settles at whatever rate its targets
    /// will bear, and the slowest it may settle at is its window floor over its
    /// shortest round-trip budget — every question timing out, with only the
    /// floor's worth of them outstanding. If the deadline assumed a faster pace
    /// than that, the pacing working as designed is what ends the scan early,
    /// and the ports it never reached are reported as though it had asked.
    ///
    /// `target_count` is what the ceiling is told, and it has to be told:
    /// widening the per-target term alone leaves a fixed ceiling free to clamp
    /// the result straight back down, which is exactly what it did — see
    /// [`ScanBudget::covering`].
    ///
    /// Only the hard budget moves, on the same reasoning
    /// [`allowing_for`](Self::allowing_for) gives.
    pub fn allowing_pace_of(self, per_probe: Duration, target_count: usize) -> Self {
        Self {
            max_budget: self
                .max_budget
                .with_per_target_at_least(per_probe)
                .covering(target_count),
            ..self
        }
    }
}

/// When a scan should stop, given how quickly and how consistently its targets
/// have been answering.
///
/// Three calls make up its whole use. A scanner marks
/// [`mark_activity`](Self::mark_activity) when it learns something new, records
/// a round trip with [`record_rtt`](Self::record_rtt) whenever it can measure
/// one, and asks [`has_expired`](Self::has_expired) each time round its receive
/// loop. [`time_until_next_tick`](Self::time_until_next_tick) is what to sleep
/// on in between, rather than polling.
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

    /// Restarts the silence clock, for a loop that has just learned something.
    ///
    /// Something *new*, rather than every packet: a second reply from a host
    /// already found says nothing about whether the scan is still worth
    /// running, and treating it as activity keeps a sweep open on the strength
    /// of traffic it had already accounted for.
    pub fn mark_activity(&mut self) {
        self.timer.mark_activity();
    }

    /// Folds one measured round trip into what the tolerance is derived from.
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

    /// Whether the scan should stop: the deadline has passed, or the minimum
    /// runtime is behind it and nothing new has happened for longer than the
    /// measured tolerance justifies.
    pub fn has_expired(&self) -> bool {
        self.timer.has_expired(self.silence_tolerance())
    }

    /// Whether the absolute deadline has passed, regardless of silence.
    ///
    /// A loop with work still outstanding may reasonably ignore
    /// [`has_expired`](Self::has_expired), since silence means nothing while
    /// probes are still waiting to be answered or retried. It may not ignore
    /// this one: it is what guarantees the scan terminates at all.
    pub fn hard_deadline_passed(&self) -> bool {
        self.timer.hard_deadline_passed()
    }

    /// How long a caller may sleep before asking
    /// [`has_expired`](Self::has_expired) again.
    pub fn time_until_next_tick(&self) -> Duration {
        self.timer.time_until_next_tick(self.silence_tolerance())
    }
}
