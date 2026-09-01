// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How long a scan is allowed, and when it stops
//!
//! Two values, and between them they are every clock a probing loop reads.
//!
//! [`ScanBudget`] answers how long a scan of a given size should get. A single
//! host and a `/16` cannot be given the same fixed duration, so a budget is a
//! base plus a term per target, held under a ceiling.
//!
//! [`ScanTimer`] is that duration once it is running, alongside two other
//! limits: a minimum runtime, and a silence tolerance the caller supplies on
//! every check rather than fixing at construction. That last part is what makes
//! it adaptive: a loop learning what the network costs narrows or widens what
//! it is willing to read as "nothing more is coming", and the timer does not
//! have to know how.

use std::time::{Duration, Instant};

/// How long a loop waits before re-checking a silence tolerance that is already
/// spent.
///
/// Short, because the condition it is waiting on has passed and the next check
/// will say so; not zero, because a loop that returns immediately is a busy
/// wait against a clock that has nothing new to tell it.
pub const RECHECK_SOON: Duration = Duration::from_millis(100);

/// The three limits a probing loop runs under: a hard deadline, a minimum
/// runtime, and however long silence has gone on.
///
/// Only the first two are fixed here. The silence tolerance arrives on every
/// check, because it is the one of the three a scan can learn: with round trips
/// measured, silence that means "nothing more is coming" is a different length
/// than it was before anything answered. [`AdaptiveDeadline`] is that pairing
/// written down, and is what a scanner holds rather than one of these.
///
/// [`AdaptiveDeadline`]: super::deadline::AdaptiveDeadline
#[derive(Debug, Clone, Copy)]
pub struct ScanTimer {
    /// When the scan stops whatever else is true.
    hard_deadline: Instant,
    /// Before this, silence is not allowed to end anything.
    min_runtime: Instant,
    /// When the loop last learned something, which is what silence is measured
    /// from.
    last_activity: Instant,
}

impl ScanTimer {
    /// A timer running from now, bounded above by `max_total_duration` and
    /// below by `min_runtime_duration`.
    ///
    /// The lower bound is what keeps silence from ending a scan before an
    /// answer could plausibly have arrived at all.
    pub fn new(max_total_duration: Duration, min_runtime_duration: Duration) -> Self {
        let now = Instant::now();
        Self {
            hard_deadline: now + max_total_duration,
            min_runtime: now + min_runtime_duration,
            last_activity: now,
        }
    }

    /// Restarts the silence clock, for a loop that has just learned something.
    ///
    /// What counts as learning something is the caller's: a discovery sweep
    /// marks a host it had not seen, not every packet, because a duplicate reply
    /// from a host already found says nothing about whether the scan is still
    /// worth running.
    pub fn mark_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// How long a caller may sleep before asking again, given the tolerance in
    /// force.
    ///
    /// [`RECHECK_SOON`] comes back when the tolerance is already spent, so a
    /// loop wakes promptly rather than sleeping through a condition that has
    /// passed.
    pub fn time_until_next_tick(&self, max_silence: Duration) -> Duration {
        let now = Instant::now();
        let time_since_last = now.duration_since(self.last_activity);

        max_silence
            .checked_sub(time_since_last)
            .unwrap_or(RECHECK_SOON)
    }

    /// Whether the loop should stop: the deadline has passed, or the minimum
    /// runtime is behind it and nothing has happened for longer than
    /// `max_silence`.
    ///
    /// Two conditions rather than one, and only the first is binding. Silence is
    /// evidence that nothing more is coming, which a loop with probes still
    /// outstanding is entitled to disagree with; see
    /// [`hard_deadline_passed`](Self::hard_deadline_passed) for the one it may
    /// not.
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

    /// Whether a socket timeout is allowed to end the loop yet.
    ///
    /// A timeout before the minimum runtime is a scan that has not waited long
    /// enough to conclude anything from quiet.
    pub fn should_break_on_timeout(&self) -> bool {
        Instant::now() >= self.min_runtime
    }
}

/// How a scan's time grows with the number of targets.
///
/// A base, a term added per target, and a ceiling over the sum. One fixed
/// duration cannot serve a scan that might cover one host or sixty-five
/// thousand ports: it is too short for the second and spent waiting on the
/// first.
#[must_use]
#[derive(Debug, Clone, Copy)]
pub struct ScanBudget {
    base: Duration,
    per_target: Duration,
    ceiling: Duration,
}

impl ScanBudget {
    /// A budget of `base`, plus `per_target` for each target beyond the first,
    /// never exceeding `ceiling`.
    ///
    /// See [`covering`](Self::covering) for when the ceiling stops being a
    /// backstop and becomes the answer, which is the way this goes wrong.
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
    /// A ceiling is in different units from the rest of a budget, and that is
    /// how it goes wrong. The base and the per-target term both scale with the
    /// work; a fixed ceiling does not, so past some target count it quietly
    /// stops being a backstop and becomes the whole answer, and nothing says
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
    /// a scan whose *pace* nobody derived, which is every caller that does not
    /// call this.
    pub fn covering(self, target_count: usize) -> Self {
        Self {
            ceiling: self.ceiling.max(self.unclamped(target_count)),
            ..self
        }
    }

    /// What a scan of `target_count` targets gets.
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

    /// A timer that has just started has neither run out of time nor waited
    /// long enough for silence to mean anything.
    #[test]
    fn a_fresh_timer_has_neither_expired_nor_earned_the_right_to() {
        let timer = ScanTimer::new(Duration::from_secs(10), Duration::from_secs(5));
        assert!(!timer.has_expired(Duration::from_secs(1)));
        assert!(!timer.should_break_on_timeout());
    }

    /// The sleep shortens as silence accumulates and resets when the loop
    /// learns something, which is what keeps a caller from waking on a schedule
    /// that has nothing to do with the network.
    #[test]
    fn the_next_check_moves_with_the_silence_and_resets_with_activity() {
        let mut timer = ScanTimer::new(Duration::from_secs(10), Duration::from_secs(5));
        let max_silence = Duration::from_millis(500);

        let wait_time1 = timer.time_until_next_tick(max_silence);
        sleep(Duration::from_millis(50));
        let wait_time2 = timer.time_until_next_tick(max_silence);

        assert!(wait_time2 < wait_time1);

        timer.mark_activity();
        let wait_time3 = timer.time_until_next_tick(max_silence);

        assert!(
            wait_time3 > wait_time2,
            "activity restarts the silence clock"
        );
    }

    /// A tolerance already spent has no time left to sleep through, and
    /// returning zero would spin. `RECHECK_SOON` is the floor.
    #[test]
    fn a_spent_tolerance_waits_a_short_fixed_time_rather_than_none() {
        let timer = ScanTimer::new(Duration::from_secs(10), Duration::from_secs(5));
        let max_silence = Duration::from_millis(10);

        sleep(Duration::from_millis(15)); // Exceed max_silence

        // Should return the 100ms fallback since the time since last activity is greater than max_silence
        assert_eq!(timer.time_until_next_tick(max_silence), RECHECK_SOON);
    }

    /// The deadline is the guarantee that a scan terminates, so it fires
    /// whatever the minimum runtime says and whatever the silence tolerance is.
    #[test]
    fn the_hard_deadline_fires_even_before_the_minimum_runtime() {
        let timer = ScanTimer::new(
            Duration::from_millis(10),  // short hard deadline
            Duration::from_millis(100), // long min runtime (will not be reached)
        );
        let max_silence = Duration::from_secs(1);

        assert!(!timer.has_expired(max_silence));
        sleep(Duration::from_millis(15));
        assert!(timer.has_expired(max_silence));
    }

    /// Silence ends a scan only once both conditions hold: the minimum runtime
    /// is behind it, and nothing has happened for longer than the tolerance.
    #[test]
    fn silence_ends_a_scan_once_the_minimum_runtime_is_behind_it() {
        let timer = ScanTimer::new(
            Duration::from_secs(10),
            Duration::from_millis(10), // short min runtime
        );
        let max_silence = Duration::from_millis(10); // short max silence

        assert!(!timer.has_expired(max_silence));
        sleep(Duration::from_millis(25)); // Exceed both min_runtime and max_silence
        assert!(timer.has_expired(max_silence));
    }

    /// A socket timeout before the minimum runtime is a scan that has not
    /// waited long enough to conclude anything from quiet.
    #[test]
    fn a_socket_timeout_may_end_the_loop_only_after_the_minimum_runtime() {
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
    /// doing its job: cutting the scan short and reporting the ports it never
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
    /// working one: silently, because a scan cut short reports like a scan that
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
