// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Wire-format timestamps
//!
//! Renders a [`SystemTime`] as an RFC 3339 timestamp in UTC, which is the only
//! form a timestamp takes in an exported report.
//!
//! The alternative - a float of seconds since the epoch - is the trap this
//! module exists to avoid. A `f64` holds a microsecond-resolution epoch time to
//! about a quarter of a microsecond today and steadily worse as the epoch
//! recedes, so two scans of the same host can serialize to timestamps that
//! compare unequal for no reason the data supports. It is also unreadable, and
//! every consumer has to be told which unit it is in. A string in a fixed format
//! has neither problem.
//!
//! The rendering is deliberately dependency-free. Pulling a calendar crate into
//! a packet engine to format a handful of timestamps would cost more, in build
//! time and in supply-chain surface, than the fifty lines below.
//!
//! ## What is and is not represented
//!
//! Output is always UTC, always `Z`-suffixed, always six fractional digits.
//! Fixed width means two timestamps can be compared lexicographically and sort
//! the same way they sort chronologically, which is what makes a report
//! diffable and greppable.
//!
//! Sub-microsecond precision is truncated rather than rounded, so a rendered
//! timestamp never names a moment that had not happened yet.
//!
//! [`Instant`](std::time::Instant) is deliberately absent. A monotonic reading
//! has no meaning outside the process that took it, so durations measured with
//! one are exported as durations and never as points in time.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds in a day. No leap seconds: Unix time does not have them, and
/// [`SystemTime`] is Unix time.
const SECS_PER_DAY: i64 = 86_400;

/// The earliest instant RFC 3339 can express, as seconds from the Unix epoch:
/// midnight on 0000-01-01.
const MIN_SECS: i64 = -62_167_219_200;

/// The latest instant RFC 3339 can express, as seconds from the Unix epoch: the
/// final second of 9999-12-31.
const MAX_SECS: i64 = 253_402_300_799;

/// Formats a moment as an RFC 3339 timestamp in UTC, to microsecond precision.
///
/// ```
/// use std::time::{Duration, UNIX_EPOCH};
/// use zond_engine::export::time::rfc3339;
///
/// let t = UNIX_EPOCH + Duration::new(1_770_000_000, 123_456_789);
/// assert_eq!(rfc3339(t), "2026-02-02T02:40:00.123456Z");
/// ```
///
/// Times outside the range RFC 3339 can express - before 0000-01-01 or after
/// 9999-12-31 - are clamped to the nearest representable instant. Nothing the
/// engine measures can reach either bound: the timestamps in a report come from
/// the system clock during the scan, or from an X.509 validity field, whose
/// ASN.1 encoding is itself limited to four-digit years. Clamping is what keeps
/// a nonsense input from producing a document no consumer can parse.
pub fn rfc3339(time: SystemTime) -> String {
    let (secs, nanos) = epoch_parts(time);
    let secs = secs.clamp(MIN_SECS, MAX_SECS);

    let days = secs.div_euclid(SECS_PER_DAY);
    let time_of_day = secs.rem_euclid(SECS_PER_DAY);

    let (year, month, day) = civil_from_days(days);
    let hour = time_of_day / 3_600;
    let minute = (time_of_day % 3_600) / 60;
    let second = time_of_day % 60;

    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{micros:06}Z",
        micros = nanos / 1_000
    )
}

/// Splits a moment into whole seconds from the Unix epoch and a non-negative
/// nanosecond remainder.
///
/// The remainder always points forward, including before the epoch, because
/// that is the only convention under which the calendar arithmetic below can
/// treat the two halves independently. A [`SystemTime`] far enough from the
/// epoch to overflow the second count is saturated; the caller clamps it to the
/// representable range regardless.
fn epoch_parts(time: SystemTime) -> (i64, u32) {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => (saturating_secs(after), after.subsec_nanos()),
        Err(err) => {
            let before = err.duration();
            match before.subsec_nanos() {
                0 => (-saturating_secs(before), 0),
                // A time 1.25 s before the epoch is second -2 plus 0.75 s, not
                // second -1 plus a negative remainder.
                nanos => (-saturating_secs(before) - 1, 1_000_000_000 - nanos),
            }
        }
    }
}

/// The whole seconds of a duration, saturating rather than wrapping.
fn saturating_secs(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

/// Converts a count of days from the Unix epoch into a proleptic Gregorian
/// date.
///
/// This is Howard Hinnant's `civil_from_days`, the standard branch-free
/// formulation also used by C++20's `<chrono>`. It works by shifting the year
/// to start in March, which puts the leap day at the end of the year and lets a
/// 400-year era be indexed arithmetically instead of by case analysis.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Re-base onto 0000-03-01, the start of an era.
    let shifted = days + 719_468;

    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);

    // Divide out the leap days: one every 4 years, minus one every 100,
    // plus one every 400.
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);

    // Months in the March-based year have a repeating 153-day / 5-month
    // pattern, which this inverts.
    let month_index = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_index + 2) / 5 + 1) as u32;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    } as u32;

    // Shift January and February back into the calendar year they belong to.
    let year = year_of_era + era * 400 + i64::from(month <= 2);

    (year, month, day)
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

    fn at(secs: u64, nanos: u32) -> SystemTime {
        UNIX_EPOCH + Duration::new(secs, nanos)
    }

    #[test]
    fn the_epoch_renders_as_the_epoch() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000000Z");
    }

    #[test]
    fn a_known_instant_matches_a_hand_computed_date() {
        // 1234567890 is the widely-cited "Unix billennium" second.
        assert_eq!(rfc3339(at(1_234_567_890, 0)), "2009-02-13T23:31:30.000000Z");
    }

    /// Leap years are where a hand-rolled calendar breaks first, and the three
    /// rules disagree exactly at these dates.
    #[test]
    fn leap_day_rules_hold_at_every_boundary() {
        // 2000 is a leap year: divisible by 400.
        assert_eq!(rfc3339(at(951_782_400, 0)), "2000-02-29T00:00:00.000000Z");
        // 2024 is a leap year: divisible by 4.
        assert_eq!(rfc3339(at(1_709_164_800, 0)), "2024-02-29T00:00:00.000000Z");
        // 1900 was not: divisible by 100 but not 400. February has 28 days and
        // the next one is March, with no 29th in between.
        let feb_28_1900 = UNIX_EPOCH - Duration::from_secs(2_203_977_600);
        assert_eq!(rfc3339(feb_28_1900), "1900-02-28T00:00:00.000000Z");
        assert_eq!(
            rfc3339(feb_28_1900 + Duration::from_secs(SECS_PER_DAY as u64)),
            "1900-03-01T00:00:00.000000Z"
        );
    }

    /// Truncation, not rounding: a timestamp must never name a moment that had
    /// not yet happened when it was taken.
    #[test]
    fn sub_microsecond_precision_is_truncated() {
        assert_eq!(rfc3339(at(0, 999)), "1970-01-01T00:00:00.000000Z");
        assert_eq!(rfc3339(at(0, 1_999)), "1970-01-01T00:00:00.000001Z");
    }

    /// A moment before the epoch borrows a second, so its fraction still counts
    /// forward. Getting this wrong renders 1969-12-31T23:59:59.75 as a time
    /// three quarters of a second in the wrong direction.
    #[test]
    fn a_time_before_the_epoch_keeps_its_fraction_pointing_forward() {
        let quarter_second_before = UNIX_EPOCH - Duration::new(0, 250_000_000);
        assert_eq!(
            rfc3339(quarter_second_before),
            "1969-12-31T23:59:59.750000Z"
        );

        let exactly_a_second_before = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(
            rfc3339(exactly_a_second_before),
            "1969-12-31T23:59:59.000000Z"
        );
    }

    #[test]
    fn the_last_second_of_a_year_does_not_roll_over_early() {
        assert_eq!(rfc3339(at(1_767_225_599, 0)), "2025-12-31T23:59:59.000000Z");
        assert_eq!(rfc3339(at(1_767_225_600, 0)), "2026-01-01T00:00:00.000000Z");
    }

    /// A time outside RFC 3339's four-digit-year range still has to produce a
    /// parseable timestamp; a document no consumer can read is worse than a
    /// clamped one.
    #[test]
    fn unrepresentable_times_clamp_to_the_format_bounds() {
        // Roughly the year 11500, past the last four-digit year.
        let far_future = UNIX_EPOCH + Duration::new(300_000_000_000, 999_999_999);
        assert_eq!(rfc3339(far_future), "9999-12-31T23:59:59.999999Z");

        // Roughly 220 BC, before the first.
        let far_past = UNIX_EPOCH - Duration::from_secs(70_000_000_000);
        assert_eq!(rfc3339(far_past), "0000-01-01T00:00:00.000000Z");
    }

    /// Fixed-width output is what lets a consumer sort timestamps as text. If
    /// any field could render narrow, that guarantee is gone.
    #[test]
    fn output_is_fixed_width_so_it_sorts_as_text() {
        let early = at(1_000_000, 0);
        let late = at(1_700_000_000, 0);

        assert_eq!(rfc3339(early).len(), rfc3339(late).len());
        assert!(rfc3339(early) < rfc3339(late));
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest::proptest! {
        /// Whatever the input, the output is a timestamp of exactly the shape
        /// the schema promises. A consumer's parser is written once against
        /// this shape and must never meet another.
        #[test]
        fn every_time_renders_in_the_documented_shape(secs in 0..4_000_000_000u64, nanos in 0..1_000_000_000u32) {
            let rendered = rfc3339(UNIX_EPOCH + Duration::new(secs, nanos));

            prop_assert_eq!(rendered.len(), 27);
            prop_assert!(rendered.ends_with('Z'));
            prop_assert_eq!(rendered.as_bytes()[4], b'-');
            prop_assert_eq!(rendered.as_bytes()[7], b'-');
            prop_assert_eq!(rendered.as_bytes()[10], b'T');
            prop_assert_eq!(rendered.as_bytes()[13], b':');
            prop_assert_eq!(rendered.as_bytes()[16], b':');
            prop_assert_eq!(rendered.as_bytes()[19], b'.');
        }

        /// Chronological order and lexicographic order have to agree, because
        /// consumers sort these as strings.
        #[test]
        fn later_times_render_as_larger_strings(a in 0..4_000_000_000u64, b in 0..4_000_000_000u64) {
            let (earlier, later) = if a <= b { (a, b) } else { (b, a) };

            let rendered_earlier = rfc3339(UNIX_EPOCH + Duration::from_secs(earlier));
            let rendered_later = rfc3339(UNIX_EPOCH + Duration::from_secs(later));

            prop_assert!(rendered_earlier <= rendered_later);
        }

        /// The calendar arithmetic must round-trip: rendering day N and day N+1
        /// always yields consecutive, distinct dates.
        #[test]
        fn consecutive_days_render_as_distinct_dates(day in 0..40_000i64) {
            let secs = day * SECS_PER_DAY;
            let today = rfc3339(UNIX_EPOCH + Duration::from_secs(secs as u64));
            let tomorrow = rfc3339(UNIX_EPOCH + Duration::from_secs((secs + SECS_PER_DAY) as u64));

            prop_assert_ne!(&today[..10], &tomorrow[..10]);
            prop_assert!(today < tomorrow);
        }
    }
}
