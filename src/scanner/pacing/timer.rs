// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! High-performance timing and lifecycle management for network scanning engines.
//!
//! Provides two building blocks used to govern how long a scanning loop runs:
//!
//! - [`ScanTimer`] tracks a hard deadline and a minimum runtime, and reports
//!   whether a loop should stop because a period of "silence" (time since
//!   the last relevant activity) has exceeded a caller-supplied tolerance.
//! - [`ScanBudget`] computes how long a scan of a given size should be
//!   allotted, so a single host and a large subnet don't run for the same
//!   fixed duration.

use std::time::{Duration, Instant};

/// Manages the loop lifecycle and operational boundaries for network scanning operations.
///
/// `ScanTimer` tracks a hard deadline, enforces a minimum runtime, and lets a
/// caller decide when a loop should abort early because a period of network
/// "silence" (time since the last relevant packet) has exceeded a tolerance
/// that the caller supplies on each check. That tolerance is intentionally
/// not fixed at construction time: a caller can widen or narrow it as it
/// learns more about current network conditions (for example, from an
/// [`crate::scanner::pacing::rtt_window::RttWindow`]).
#[derive(Debug, Clone, Copy)]
pub struct ScanTimer {
    // Configuration
    hard_deadline: Instant,
    min_runtime: Instant,

    // State
    last_activity: Instant,
}

impl ScanTimer {
    /// Constructs a new `ScanTimer` with the specified operational limits.
    ///
    /// # Arguments
    /// * `max_total_duration` - The absolute maximum time the scan is allowed to run.
    /// * `min_runtime_duration` - The absolute minimum time the scan must run before it can abort due to silence.
    pub fn new(max_total_duration: Duration, min_runtime_duration: Duration) -> Self {
        let now = Instant::now();
        Self {
            hard_deadline: now + max_total_duration,
            min_runtime: now + min_runtime_duration,
            last_activity: now,
        }
    }

    /// Resets the internal "silence" tracker.
    ///
    /// This should be called whenever a relevant packet or activity is observed on the network.
    pub fn mark_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Calculates how long to wait before the next check is worthwhile,
    /// given the current silence tolerance.
    ///
    /// Returns a short fallback duration if that tolerance has already been
    /// exceeded, so a caller re-checks promptly instead of sleeping past an
    /// already-expired condition.
    pub fn time_until_next_tick(&self, max_silence: Duration) -> Duration {
        let now = Instant::now();
        let time_since_last = now.duration_since(self.last_activity);

        max_silence
            .checked_sub(time_since_last)
            .unwrap_or_else(|| Duration::from_millis(100))
    }

    /// Checks if the entire operation should abort due to hard limits or excessive silence.
    ///
    /// Returns `true` if:
    /// 1. The current time has exceeded the `hard_deadline`.
    /// 2. The `min_runtime` has elapsed AND the time since the last recorded
    ///    activity exceeds `max_silence`.
    ///
    /// `max_silence` is supplied by the caller on every call rather than
    /// fixed at construction time, so the silence tolerance can adapt as
    /// network conditions become known over the course of a scan.
    pub fn has_expired(&self, max_silence: Duration) -> bool {
        let now = Instant::now();

        if now > self.hard_deadline {
            return true;
        }

        let time_since_last = now.duration_since(self.last_activity);
        now > self.min_runtime && time_since_last >= max_silence
    }

    /// Whether the absolute deadline has passed, regardless of silence.
    ///
    /// Separate from [`has_expired`](Self::has_expired) because the two answer
    /// different questions. Silence is evidence that nothing more is coming,
    /// which a caller with work still outstanding is entitled to disagree with;
    /// the hard deadline is not evidence of anything, it is the guarantee that a
    /// scan terminates, and nothing may override it.
    pub fn hard_deadline_passed(&self) -> bool {
        Instant::now() > self.hard_deadline
    }

    /// Helper to decide if a socket timeout is fatal or if the scan should continue.
    ///
    /// Returns `true` if the minimum runtime has been met, indicating that a timeout
    /// could be a valid reason to break the loop.
    pub fn should_break_on_timeout(&self) -> bool {
        Instant::now() >= self.min_runtime
    }
}

/// Defines how a scan's time allotment grows with the number of targets involved.
///
/// A single fixed duration is a poor fit for scans that might cover one host
/// or tens of thousands: too short for large sweeps, needlessly long for
/// small ones. A `ScanBudget` instead defines a starting duration (`base`)
/// plus a small increment added once per additional target (`per_target`),
/// so the resulting duration grows with the size of the scan while never
/// exceeding an absolute `ceiling`.
#[derive(Debug, Clone, Copy)]
pub struct ScanBudget {
    base: Duration,
    per_target: Duration,
    ceiling: Duration,
}

impl ScanBudget {
    /// Creates a new budget.
    ///
    /// * `base` - The duration allotted for a single target.
    /// * `per_target` - The additional duration added for every target beyond the first.
    /// * `ceiling` - The maximum duration this budget will ever return, regardless of target count.
    pub const fn new(base: Duration, per_target: Duration, ceiling: Duration) -> Self {
        Self {
            base,
            per_target,
            ceiling,
        }
    }

    /// The same budget with its base widened to at least `minimum`.
    ///
    /// For deriving one limit from another rather than restating it: a scan
    /// whose probes are retransmitted has to outlive its own retry schedule, and
    /// expressing that as a floor on the base keeps the two from drifting apart
    /// when either is tuned.
    pub fn with_base_at_least(self, minimum: Duration) -> Self {
        Self {
            base: self.base.max(minimum),
            ..self
        }
    }

    /// The same budget with its per-target term widened to at least `minimum`.
    ///
    /// The counterpart of [`with_base_at_least`](Self::with_base_at_least), for
    /// the other way a budget can be too short. The base has to cover one
    /// probe's whole life; this has to cover the *pace* the scan will settle at,
    /// and a scan that paces itself has a pace only it knows. Expressing that as
    /// a floor keeps the two from drifting apart when either is tuned.
    pub fn with_per_target_at_least(self, minimum: Duration) -> Self {
        Self {
            per_target: self.per_target.max(minimum),
            ..self
        }
    }

    /// The same budget, with its ceiling raised to whatever `target_count`
    /// targets need at this budget's own rate.
    ///
    /// **A ceiling is in different units from the rest of a budget, and that is
    /// how it goes wrong.** The base and the per-target term both scale with the
    /// work; a fixed ceiling does not, so past some target count it quietly
    /// stops being a backstop and becomes the whole answer — and nothing says
    /// so, because a truncated scan and a finished one report the same way.
    ///
    /// Measured, against one host: a 65 535-port scan whose pacing had settled
    /// at its floor needed 104 seconds and was allowed 60. Thirteen thousand
    /// ports were never reached and thirty-two thousand were reported filtered
    /// without having been asked the whole question. The budget had computed the
    /// right number and the ceiling threw it away.
    ///
    /// So a caller that knows both the pace and the size says so, and the
    /// ceiling stops being able to contradict them. What it still does is bound
    /// a scan whose *pace* nobody derived — which is every caller that does not
    /// call this.
    pub fn covering(self, target_count: usize) -> Self {
        Self {
            ceiling: self.ceiling.max(self.unclamped(target_count)),
            ..self
        }
    }

    /// Computes the effective duration for a scan covering `target_count` addresses.
    pub fn for_target_count(&self, target_count: usize) -> Duration {
        self.unclamped(target_count).min(self.ceiling)
    }

    /// The budget before the ceiling is applied: what the base and the
    /// per-target term actually ask for.
    fn unclamped(&self, target_count: usize) -> Duration {
        let target_count = u32::try_from(target_count).unwrap_or(u32::MAX);
        self.base
            .saturating_add(self.per_target.saturating_mul(target_count))
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
    use std::thread::sleep;

    #[test]
    fn test_initialization() {
        let timer = ScanTimer::new(Duration::from_secs(10), Duration::from_secs(5));
        assert!(!timer.has_expired(Duration::from_secs(1)));
        assert!(!timer.should_break_on_timeout());
    }

    #[test]
    fn test_mark_activity() {
        let mut timer = ScanTimer::new(Duration::from_secs(10), Duration::from_secs(5));
        let max_silence = Duration::from_millis(500);

        let wait_time1 = timer.time_until_next_tick(max_silence);
        sleep(Duration::from_millis(50));
        let wait_time2 = timer.time_until_next_tick(max_silence);

        assert!(wait_time2 < wait_time1);

        timer.mark_activity();
        let wait_time3 = timer.time_until_next_tick(max_silence);

        // Wait time should reset to near the original max_silence
        assert!(wait_time3 > wait_time2);
    }

    #[test]
    fn test_time_until_next_tick_fallback() {
        let timer = ScanTimer::new(Duration::from_secs(10), Duration::from_secs(5));
        let max_silence = Duration::from_millis(10);

        sleep(Duration::from_millis(15)); // Exceed max_silence

        // Should return the 100ms fallback since the time since last activity is greater than max_silence
        assert_eq!(
            timer.time_until_next_tick(max_silence),
            Duration::from_millis(100)
        );
    }

    #[test]
    fn test_hard_deadline_expiration() {
        let timer = ScanTimer::new(
            Duration::from_millis(10),  // short hard deadline
            Duration::from_millis(100), // long min runtime (will not be reached)
        );
        let max_silence = Duration::from_secs(1);

        assert!(!timer.has_expired(max_silence));
        sleep(Duration::from_millis(15));
        assert!(timer.has_expired(max_silence));
    }

    #[test]
    fn test_silence_expiration() {
        let timer = ScanTimer::new(
            Duration::from_secs(10),
            Duration::from_millis(10), // short min runtime
        );
        let max_silence = Duration::from_millis(10); // short max silence

        assert!(!timer.has_expired(max_silence));
        sleep(Duration::from_millis(25)); // Exceed both min_runtime and max_silence
        assert!(timer.has_expired(max_silence));
    }

    #[test]
    fn test_should_break_on_timeout() {
        let timer = ScanTimer::new(Duration::from_secs(10), Duration::from_millis(10));

        assert!(!timer.should_break_on_timeout());
        sleep(Duration::from_millis(15));
        assert!(timer.should_break_on_timeout());
    }

    #[test]
    fn budget_scales_linearly_with_target_count() {
        let budget = ScanBudget::new(
            Duration::from_millis(100),
            Duration::from_millis(10),
            Duration::from_secs(10),
        );

        assert_eq!(budget.for_target_count(0), Duration::from_millis(100));
        assert_eq!(budget.for_target_count(10), Duration::from_millis(200));
    }

    /// A scan that paces itself may settle far below the rate a budget was
    /// written for, and a budget that assumed more expires while the pacing is
    /// doing its job — cutting the scan short and reporting the ports it never
    /// reached as though it had asked.
    #[test]
    fn a_budget_can_be_widened_to_the_pace_a_scan_will_actually_keep() {
        let budget = ScanBudget::new(
            Duration::from_millis(100),
            Duration::from_millis(1),
            Duration::from_secs(60),
        );

        let paced = budget.with_per_target_at_least(Duration::from_millis(4));
        assert_eq!(paced.for_target_count(100), Duration::from_millis(500));

        assert_eq!(
            budget
                .with_per_target_at_least(Duration::from_micros(500))
                .for_target_count(100),
            budget.for_target_count(100),
            "a slower pace than the budget already allows for changes nothing"
        );
    }

    /// A ceiling is in different units from the rest of the budget, so past some
    /// target count it stops bounding a runaway scan and starts truncating a
    /// working one — silently, because a scan cut short reports like a scan that
    /// finished.
    #[test]
    fn a_ceiling_cannot_truncate_a_size_and_a_pace_it_was_told_about() {
        // The shape that failed: a pace of 1.5625 ms per target over 65 535 of
        // them wants 104 seconds, against a ceiling of 60.
        let budget = ScanBudget::new(
            Duration::from_millis(2_000),
            Duration::from_nanos(1_562_500),
            Duration::from_secs(60),
        );
        assert_eq!(
            budget.for_target_count(65_535),
            Duration::from_secs(60),
            "the ceiling is what decides, and it is wrong"
        );

        let covering = budget.covering(65_535);
        assert!(
            covering.for_target_count(65_535) > Duration::from_secs(100),
            "told the size, it allows what the pace implies"
        );
    }

    /// Raising the ceiling for one size does not lower it for another, and does
    /// not disturb a budget that already had room.
    #[test]
    fn covering_only_ever_raises_the_ceiling() {
        let budget = ScanBudget::new(
            Duration::from_millis(100),
            Duration::from_millis(1),
            Duration::from_secs(60),
        );

        let small = budget.covering(10);
        assert_eq!(
            small.for_target_count(10),
            Duration::from_millis(110),
            "a scan well inside the ceiling is unaffected"
        );
        assert_eq!(
            small.for_target_count(1_000_000),
            Duration::from_secs(60),
            "and a size it was never told about is still bounded"
        );
    }

    #[test]
    fn budget_is_clamped_to_its_ceiling() {
        let budget = ScanBudget::new(
            Duration::from_millis(100),
            Duration::from_millis(10),
            Duration::from_millis(500),
        );

        assert_eq!(budget.for_target_count(1000), Duration::from_millis(500));
    }
}
