// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

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
/// [`crate::core::models::rtt_window::RttWindow`]).
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

    /// Computes the effective duration for a scan covering `target_count` addresses.
    pub fn for_target_count(&self, target_count: usize) -> Duration {
        let target_count = u32::try_from(target_count).unwrap_or(u32::MAX);
        let scaled = self
            .base
            .saturating_add(self.per_target.saturating_mul(target_count));

        scaled.min(self.ceiling)
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
