// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How long a scan is allowed, and when it stops
//!
//! [`ScanBudget`] says how long a scan of a given size should get: a base plus a
//! term per target, held under a ceiling.
//!
//! [`ScanTimer`] is that duration once it is running, alongside a minimum runtime
//! and a silence tolerance the caller passes on every check. Passing the tolerance
//! per check lets a loop that learns what the network costs change what it reads as
//! "nothing more is coming".

use std::time::{Duration, Instant};

/// How long a loop waits before re-checking a silence tolerance that is already
/// spent.
///
/// Nonzero so the loop does not busy-wait.
pub const RECHECK_SOON: Duration = Duration::from_millis(100);

/// How far ahead [`later`] reads an instant it cannot represent.
///
/// Thirty years, as tokio does for a sleep it cannot represent: past the end of
/// any scan, and within what every platform's [`Instant`] holds.
const FAR_FUTURE: Duration = Duration::from_secs(30 * 365 * 24 * 60 * 60);

/// `from` moved `by` later, or [`FAR_FUTURE`] later where `from + by` is past
/// what an [`Instant`] can hold.
///
/// For every clock moved by a caller's duration. A caller may write an unbounded
/// wait as `Duration::MAX`, on which `Instant + Duration` panics.
pub(crate) fn later(from: Instant, by: Duration) -> Instant {
    from.checked_add(by)
        .or_else(|| from.checked_add(FAR_FUTURE))
        .unwrap_or(from)
}

/// The three limits a probing loop runs under: a hard deadline, a minimum
/// runtime, and however long silence has gone on.
///
/// Only the first two are fixed here. The silence tolerance arrives on every
/// check, because a scan learns it from measured round trips. Scanners hold an
/// [`AdaptiveDeadline`], which pairs a timer with that tolerance.
///
/// [`AdaptiveDeadline`]: super::deadline::AdaptiveDeadline
#[derive(Debug, Clone, Copy)]
pub struct ScanTimer {
    /// When the timer was built or last [started](Self::start).
    started: Instant,
    /// When the scan stops whatever else is true.
    hard_deadline: Instant,
    /// Before this, silence cannot end the scan.
    min_runtime: Instant,
    /// When the loop last learned something; silence is measured from here.
    last_activity: Instant,
}

impl ScanTimer {
    /// A timer running from now, bounded above by `max_total_duration` and
    /// below by `min_runtime_duration`.
    ///
    /// The lower bound keeps silence from ending a scan before any answer could
    /// have arrived.
    pub fn new(max_total_duration: Duration, min_runtime_duration: Duration) -> Self {
        let now = Instant::now();
        Self {
            started: now,
            hard_deadline: later(now, max_total_duration),
            min_runtime: later(now, min_runtime_duration),
            last_activity: now,
        }
    }

    /// Runs the timer from now, as though it had been built now, for a loop
    /// that begins some time after its timer was.
    ///
    /// The time in between is setup. Charged for it, a loop would begin with its
    /// minimum runtime and silence tolerance already spent.
    pub(crate) fn start(&mut self) {
        let now = Instant::now();
        let setup = now.saturating_duration_since(self.started);
        self.started = now;
        self.hard_deadline = later(self.hard_deadline, setup);
        self.min_runtime = later(self.min_runtime, setup);
        self.last_activity = now;
    }

    /// Restarts the silence clock, for a loop that has just learned something.
    ///
    /// The caller decides what counts. A discovery sweep marks a newly seen host,
    /// since a duplicate reply says nothing about whether the scan is still worth
    /// running.
    pub fn mark_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// How long a caller may sleep before asking again, given the tolerance in
    /// force.
    ///
    /// Returns [`RECHECK_SOON`] when the tolerance is already spent.
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
    /// Only the deadline is binding. A loop with probes still outstanding may
    /// ignore the silence condition; see
    /// [`hard_deadline_passed`](Self::hard_deadline_passed) for the deadline alone.
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
    /// The hard deadline guarantees that a scan terminates, so nothing may
    /// override it. Silence, checked by [`has_expired`](Self::has_expired), is
    /// only evidence, and a caller with work outstanding may disagree with it.
    pub fn hard_deadline_passed(&self) -> bool {
        Instant::now() > self.hard_deadline
    }

    /// Moves the hard deadline `by` later.
    ///
    /// For time the loop spent on its own work. The deadline bounds how long a
    /// scan waits for answers.
    pub(crate) fn extend(&mut self, by: Duration) {
        self.hard_deadline = later(self.hard_deadline, by);
    }

    /// Whether a socket timeout is allowed to end the loop yet.
    ///
    /// Not before the minimum runtime.
    #[cfg(test)]
    pub fn should_break_on_timeout(&self) -> bool {
        Instant::now() >= self.min_runtime
    }
}

/// How a scan's time grows with the number of targets.
///
/// A base, a term added per target, and a ceiling over the sum.
#[must_use]
#[derive(Debug, Clone, Copy)]
pub struct ScanBudget {
    base: Duration,
    per_target: Duration,
    ceiling: Duration,
}

impl ScanBudget {
    /// A budget of `base`, plus `per_target` for each target, never exceeding
    /// `ceiling`.
    ///
    /// See [`covering`](Self::covering) for when the ceiling truncates a scan.
    pub const fn new(base: Duration, per_target: Duration, ceiling: Duration) -> Self {
        Self {
            base,
            per_target,
            ceiling,
        }
    }

    /// The same budget with its base widened to at least `minimum`.
    ///
    /// For deriving one limit from another: a scan whose probes are retransmitted
    /// has to outlive its own retry schedule, and a floor keeps the two in step
    /// when either is tuned.
    pub fn with_base_at_least(self, minimum: Duration) -> Self {
        Self {
            base: self.base.max(minimum),
            ..self
        }
    }

    /// The same budget with its per-target term widened to at least `minimum`.
    ///
    /// The counterpart of [`with_base_at_least`](Self::with_base_at_least). The
    /// base covers one probe's whole life; this covers the pace the scan will
    /// settle at, which only a self-pacing scan knows.
    pub fn with_per_target_at_least(self, minimum: Duration) -> Self {
        Self {
            per_target: self.per_target.max(minimum),
            ..self
        }
    }

    /// The same budget, with its ceiling raised to whatever `target_count`
    /// targets need at this budget's own rate.
    ///
    /// The base and per-target term scale with the work; a fixed ceiling does not,
    /// so past some target count it silently truncates the scan, and a truncated
    /// scan reports like a finished one. Against one host, a 65 535-port scan
    /// paced at its floor needed 104 seconds and was allowed 60: thirteen thousand
    /// ports were never reached.
    ///
    /// A caller that knows both the pace and the size calls this. Without it, the
    /// ceiling still bounds a scan whose pace nobody derived.
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

    /// The budget before the ceiling is applied.
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

    /// A timer started some time after it was built runs its whole budget from
    /// the start.
    ///
    /// The budget left after `start` is a second, far more than the two readings
    /// after it take.
    #[test]
    fn a_timer_started_after_it_was_built_runs_its_whole_budget_from_the_start() {
        let budget = Duration::from_secs(1);
        let mut timer = ScanTimer::new(budget, budget);
        sleep(budget + Duration::from_millis(100));
        assert!(
            timer.hard_deadline_passed(),
            "the timer ran from when it was built"
        );

        timer.start();
        assert!(
            !timer.hard_deadline_passed(),
            "the setup before the start was charged to the deadline"
        );
        assert!(
            !timer.has_expired(Duration::ZERO),
            "the setup before the start was charged to the minimum runtime"
        );
    }

    /// A timer that has just started has neither run out of time nor waited
    /// long enough for silence to mean anything.
    #[test]
    fn a_fresh_timer_has_neither_expired_nor_earned_the_right_to() {
        let timer = ScanTimer::new(Duration::from_secs(10), Duration::from_secs(5));
        assert!(!timer.has_expired(Duration::from_secs(1)));
        assert!(!timer.should_break_on_timeout());
    }

    /// The sleep shortens as silence accumulates and resets when the loop learns
    /// something.
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

    /// A spent tolerance returns `RECHECK_SOON`, since zero would spin.
    #[test]
    fn a_spent_tolerance_waits_a_short_fixed_time_rather_than_none() {
        let timer = ScanTimer::new(Duration::from_secs(10), Duration::from_secs(5));
        let max_silence = Duration::from_millis(10);

        sleep(Duration::from_millis(15));

        assert_eq!(timer.time_until_next_tick(max_silence), RECHECK_SOON);
    }

    /// The deadline fires regardless of the minimum runtime and the silence
    /// tolerance.
    #[test]
    fn the_hard_deadline_fires_even_before_the_minimum_runtime() {
        let timer = ScanTimer::new(
            Duration::from_millis(10),  // short hard deadline
            Duration::from_millis(100), // long min runtime, never reached
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
        let timer = ScanTimer::new(Duration::from_secs(10), Duration::from_millis(10));
        let max_silence = Duration::from_millis(10);

        assert!(!timer.has_expired(max_silence));
        sleep(Duration::from_millis(25));
        assert!(timer.has_expired(max_silence));
    }

    /// A socket timeout ends the loop only after the minimum runtime.
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

    /// A self-paced scan may settle far below the rate a budget was written for,
    /// and a budget that assumed more would cut the scan short.
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

    /// Past some target count a fixed ceiling truncates a working scan, silently.
    #[test]
    fn a_ceiling_cannot_truncate_a_size_and_a_pace_it_was_told_about() {
        // 1.5625 ms per target over 65 535 targets wants 104 s, against a 60 s ceiling.
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

    /// Covering one size leaves a budget that already had room unchanged, and
    /// larger sizes still bounded.
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
