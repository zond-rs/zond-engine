// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How long to keep going
//!
//! [`ScanTimer`] and [`RttWindow`] joined into the policy a probing loop needs.
//!
//! The timer enforces fixed limits; the window measures the network. A loop asks on
//! every iteration whether it has been quiet long enough to stop, and the silence
//! tolerance comes out of the window's samples, so a scan on a fast segment gives up
//! on silence in a fraction of the time one crossing an ocean does.

use std::time::{Duration, Instant};

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
/// how the latter three combine.
///
/// `#[non_exhaustive]`: build it with [`new`](Self::new) and the two builders
/// beside it, as with [`WindowLimits`](super::congestion::WindowLimits).
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
    /// cannot hold it open.
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
    /// If the scan's hard budget were shorter than one probe's retry schedule,
    /// probes would be written off as unanswered before they were fully asked.
    /// Deriving the budget from `probe_lifetime` keeps the two in step when either
    /// is tuned.
    ///
    /// Only the hard budget is widened. The minimum runtime governs when silence
    /// may end a scan, and ignoring silence while probes are outstanding is the
    /// caller's loop's job.
    pub fn allowing_for(self, probe_lifetime: Duration) -> Self {
        Self {
            max_budget: self.max_budget.with_base_at_least(probe_lifetime),
            ..self
        }
    }

    /// The same configuration, guaranteed to outlast the slowest pace the scan's
    /// own pacing may legitimately choose.
    ///
    /// The companion to [`allowing_for`](Self::allowing_for): that one keeps the
    /// budget from expiring between a probe's attempts, this one keeps it from
    /// expiring because the scan slowed itself down.
    ///
    /// A scan paced by a congestion window settles at whatever rate its targets
    /// bear. The slowest is its window floor over its shortest round-trip budget:
    /// every probe timing out, with only the floor's worth outstanding. A deadline
    /// that assumed a faster pace would end the scan early.
    ///
    /// `target_count` is passed to the ceiling, which would otherwise clamp the
    /// widened budget back down; see [`ScanBudget::covering`]. Only the hard
    /// budget moves, as with [`allowing_for`](Self::allowing_for).
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
/// A scanner calls [`mark_activity`](Self::mark_activity) when it learns something
/// new, [`record_rtt`](Self::record_rtt) whenever it can measure a round trip, and
/// [`has_expired`](Self::has_expired) each time round its receive loop, sleeping
/// for [`time_until_next_tick`](Self::time_until_next_tick) in between.
pub struct AdaptiveDeadline {
    timer: ScanTimer,
    rtt_window: RttWindow,
    silence_floor: Duration,
    silence_ceiling: Duration,
    jitter_multiplier: f64,
}

/// How much of a pass's probe hold-time its deadline has already been given, so
/// overlapping holds (several hosts held at once) are credited once.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HeldAllowance {
    /// Until when the deadline has been given the time.
    until: Instant,
}

impl Default for HeldAllowance {
    fn default() -> Self {
        Self {
            until: Instant::now(),
        }
    }
}

impl HeldAllowance {
    /// The part of a hold from `now` to `until` not yet given to the
    /// deadline, noted as given.
    pub(crate) fn take(&mut self, now: Instant, until: Instant) -> Duration {
        let from = self.until.max(now);
        self.until = from.max(until);
        until.saturating_duration_since(from)
    }
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

    /// Runs the deadline from now, for a loop that begins some time after the
    /// deadline was built; see [`ScanTimer::start`].
    pub(crate) fn start(&mut self) {
        self.timer.start();
    }

    /// Restarts the silence clock, for a loop that has just learned something.
    ///
    /// Only for something new: counting a second reply from a known host would
    /// keep a sweep open on traffic it had already accounted for.
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

    /// Gives the hard deadline back the time the loop spent inside its own
    /// sender.
    ///
    /// A send is ordinarily a few microseconds, but a frame sender that must
    /// resolve a neighbour before its first frame blocks the loop for the whole
    /// wait, up to seconds for an address nothing answers. The deadline is sized
    /// for waiting on the network; charged for this, a scan would run out with
    /// addresses unasked. Still bounded: every wait inside a sender is bounded,
    /// and a scan has finitely many targets.
    pub(crate) fn allow_for_sending(&mut self, spent: Duration) {
        self.timer.extend(spent);
    }

    /// Gives the hard deadline `held` more, for probes kept from being sent
    /// while their neighbour could not be asked or was being asked again.
    ///
    /// The deadline was not sized for time the scan could not ask in: a kernel's
    /// hold-down on a neighbour is twenty seconds on macOS, several times what a
    /// small scan is given, and a second resolution of a neighbour costs three
    /// more. Charged for either, a scan ends with the held host's ports unasked.
    /// Still bounded, since a port scan waits out hold-downs and re-resolves a
    /// neighbour a fixed number of times.
    pub(crate) fn allow_for_holding(&mut self, held: Duration) {
        self.timer.extend(held);
    }

    /// Whether the scan should stop: the deadline has passed, or the minimum
    /// runtime is behind it and nothing new has happened for longer than the
    /// measured tolerance justifies.
    pub fn has_expired(&self) -> bool {
        self.timer.has_expired(self.silence_tolerance())
    }

    /// Whether the absolute deadline has passed, regardless of silence.
    ///
    /// A loop with probes still waiting to be answered or retried may ignore
    /// [`has_expired`](Self::has_expired), but not this: it guarantees the scan
    /// terminates.
    pub fn hard_deadline_passed(&self) -> bool {
        self.timer.hard_deadline_passed()
    }

    /// How long a caller may sleep before asking
    /// [`has_expired`](Self::has_expired) again.
    pub fn time_until_next_tick(&self) -> Duration {
        self.timer.time_until_next_tick(self.silence_tolerance())
    }
}
