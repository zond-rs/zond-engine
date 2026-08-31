// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Wire-format timestamps
//!
//! A [`SystemTime`] as an RFC 3339 timestamp in UTC, which is the only form a
//! timestamp takes in an exported report, and the same timestamp read back.
//!
//! Both directions live here, beside each other, because the format is a
//! contract rather than the writer's private business — the rule this module's
//! parent states, and the same one that puts `SCHEMA_VERSION` and the CSV header
//! there. A reader that had to reach into the exporter for the shape of a
//! timestamp would be depending on being able to write a format it only reads.
//! [`rfc3339`] and [`parse_rfc3339`] are inverses, and
//! `a_rendered_timestamp_reads_back_as_itself` is what keeps them so.
//!
//! Compiled in unconditionally, unlike the CSV header beside it, since it costs
//! nothing and both directions want it.
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
/// use zond_engine::format::time::rfc3339;
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

    let Civil {
        year,
        month,
        day,
        hour,
        minute,
        second,
    } = civil_parts(secs);

    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{micros:06}Z",
        micros = nanos / 1_000
    )
}

/// Formats a moment in the reader's own timezone, to the second.
///
/// `2026-08-25 18:21:36 +0200`. For a line a person reads once — a banner, a
/// heading — where [`rfc3339`]'s `T`, its `Z` and its six digits of fractional
/// second are three pieces of precision nobody is going to use and one shape
/// nobody enjoys.
///
/// **The offset is not optional.** A local time with no offset beside it cannot
/// be lined up against anything else — a firewall log, a packet capture, a
/// colleague's transcript from another continent — and a scan whose findings
/// cannot be correlated with the rest of the evidence is a scan somebody has to
/// run again. `+0200` costs five columns and removes the ambiguity entirely.
///
/// Records keep [`rfc3339`]. This is for reading, that is for comparing, and
/// neither is derived from the other because the precision differs.
///
/// Falls back to [`rfc3339`] where the platform will not say what the local time
/// is, which is a container with no zone database rather than anything a user
/// did wrong.
pub fn local(time: SystemTime) -> String {
    let (secs, _) = epoch_parts(time);
    let secs = secs.clamp(MIN_SECS, MAX_SECS);

    let Some(offset) = local_offset(secs) else {
        return rfc3339(time);
    };

    rendered(secs, offset)
}

/// [`local`]'s arithmetic, given an offset rather than asking for one.
///
/// **Split from the lookup so that it can be tested at all.** Which offset this
/// machine is on is a fact about wherever the machine is, so a test that goes
/// through [`local_offset`] can only check the reading against the offset
/// printed beside it — and that holds just as well when both have the wrong
/// sign. It is worse than that in CI, which runs in UTC, where the offset is
/// zero and every such assertion passes without testing anything.
///
/// `offset` is seconds **east** of UTC, the sense `tm_gmtoff` uses: positive is
/// ahead of UTC, so it is added to reach the local reading and subtracted to get
/// back.
fn rendered(secs: i64, offset: i64) -> String {
    // The offset applied to the instant, and the calendar read off the result.
    // This is the whole of what a local rendering is: the same moment, counted
    // from a different zero.
    let Civil {
        year,
        month,
        day,
        hour,
        minute,
        second,
    } = civil_parts(secs.saturating_add(offset));

    format!(
        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} {sign}{hours:02}{minutes:02}",
        sign = if offset < 0 { '-' } else { '+' },
        hours = offset.abs() / 3_600,
        minutes = (offset.abs() % 3_600) / 60,
    )
}

/// How far ahead of UTC this machine's own clock reads at `secs`, in seconds.
///
/// **Asked per instant rather than once**, because the answer moves: a scan run
/// in January and a report of it read in July are the same machine and two
/// offsets, and a summer reading applied to a winter timestamp is an hour of
/// silent error in the one field a reader uses to line this scan up against a
/// firewall log.
///
/// `None` where the platform will not say — a container with no zone database,
/// or an instant outside what its own time type holds. [`local`] falls back to
/// [`rfc3339`], which needs nothing from the platform at all.
#[cfg(unix)]
fn local_offset(secs: i64) -> Option<i64> {
    let when = libc::time_t::try_from(secs).ok()?;

    // SAFETY: `localtime_r` fills `broken` or returns null, and is passed one
    // valid pointer to each. The `tm` is zeroed first so that a partial write
    // cannot leave it reading uninitialised memory.
    //
    // `localtime_r` rather than `localtime`: the reentrant form writes into a
    // caller-supplied `tm` instead of a shared static, which is the difference
    // between a scan that can format a time from any task and one that cannot.
    let broken = unsafe {
        let mut broken: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&when, &mut broken).is_null() {
            return None;
        }
        broken
    };

    Some(broken.tm_gmtoff)
}

/// [`local_offset`] where there is no `tm_gmtoff` to read.
///
/// Windows states a zone as a rule rather than as an offset, so the offset is
/// recovered by converting and differencing: the same instant expressed in both
/// zones, subtracted. `SystemTimeToTzSpecificLocalTime` applies the daylight
/// rule for the date it is handed, which is what makes this per-instant rather
/// than a single reading of the current bias.
///
/// A null `TIME_ZONE_INFORMATION` means the machine's current zone, which is the
/// question being asked.
#[cfg(windows)]
fn local_offset(secs: i64) -> Option<i64> {
    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::System::Time::SystemTimeToTzSpecificLocalTime;

    let utc = civil_parts(secs);
    let universal = SYSTEMTIME {
        wYear: u16::try_from(utc.year).ok()?,
        wMonth: u16::try_from(utc.month).ok()?,
        // Ignored on input, and not worth computing to be discarded.
        wDayOfWeek: 0,
        wDay: u16::try_from(utc.day).ok()?,
        wHour: u16::try_from(utc.hour).ok()?,
        wMinute: u16::try_from(utc.minute).ok()?,
        wSecond: u16::try_from(utc.second).ok()?,
        wMilliseconds: 0,
    };

    // SAFETY: both pointers are to live, fully initialised locals of the right
    // type, and the null first argument is the documented way to name this
    // machine's own time zone.
    let mut local = unsafe { std::mem::zeroed::<SYSTEMTIME>() };
    if unsafe { SystemTimeToTzSpecificLocalTime(std::ptr::null(), &universal, &mut local) } == 0 {
        return None;
    }

    let days = days_from_civil(
        i64::from(local.wYear),
        u32::from(local.wMonth),
        u32::from(local.wDay),
    )?;
    let converted = days * SECS_PER_DAY
        + i64::from(local.wHour) * 3_600
        + i64::from(local.wMinute) * 60
        + i64::from(local.wSecond);

    Some(converted - secs)
}

/// [`local_offset`] on a platform this crate cannot ask.
///
/// Nothing is guessed. `local` renders UTC instead, which is correct rather than
/// approximate — an offset invented here would be a timestamp that cannot be
/// correlated and does not say so.
#[cfg(not(any(unix, windows)))]
fn local_offset(_secs: i64) -> Option<i64> {
    None
}

/// A moment as a calendar reads it.
///
/// Shared by [`rfc3339`] and [`local`], which differ in the zero they count from
/// and in nothing else. Held as a struct rather than returned as six values in a
/// row, where a transposed pair would compile and be wrong for a century.
struct Civil {
    year: i64,
    month: u32,
    day: u32,
    hour: i64,
    minute: i64,
    second: i64,
}

/// Breaks `secs` since the epoch into the fields a calendar shows.
fn civil_parts(secs: i64) -> Civil {
    let days = secs.div_euclid(SECS_PER_DAY);
    let time_of_day = secs.rem_euclid(SECS_PER_DAY);
    let (year, month, day) = civil_from_days(days);

    Civil {
        year,
        month,
        day,
        hour: time_of_day / 3_600,
        minute: (time_of_day % 3_600) / 60,
        second: time_of_day % 60,
    }
}

/// Reads an RFC 3339 timestamp in UTC back as the moment it names.
///
/// The inverse of [`rfc3339`], and deliberately no more permissive than it needs
/// to be: the exact shape this engine writes, `YYYY-MM-DDTHH:MM:SS[.fff…]Z`,
/// with the fractional part optional so that a hand-written document and one
/// from another tool that omits it are both readable. A lower-case `t` or `z` is
/// accepted because RFC 3339 permits them.
///
/// Offsets other than `Z` are refused rather than converted. Accepting them
/// would mean this engine's own documents and somebody else's read differently
/// in the same field, and every timestamp this format defines is UTC.
///
/// A date the calendar does not have is refused too. `2026-02-31` is a moment
/// nobody can point at, and reading it as the third of March would hand back a
/// timestamp that looks perfectly ordinary and names the wrong day.
///
/// ```
/// use zond_engine::format::time::{parse_rfc3339, rfc3339};
/// use std::time::{Duration, UNIX_EPOCH};
///
/// let moment = UNIX_EPOCH + Duration::new(1_770_000_000, 123_456_000);
/// assert_eq!(parse_rfc3339(&rfc3339(moment)), Some(moment));
/// assert_eq!(parse_rfc3339("not a timestamp"), None);
/// assert_eq!(parse_rfc3339("2026-02-31T00:00:00Z"), None);
/// ```
pub fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    let text = text.trim();
    let body = text.strip_suffix('Z').or_else(|| text.strip_suffix('z'))?;

    let (date, rest) = body.split_once(['T', 't'])?;

    let mut date = date.splitn(3, '-');
    let year = i64::from(field(date.next()?, 4)?);
    let month = field(date.next()?, 2)?;
    let day = field(date.next()?, 2)?;
    if date.next().is_some() {
        return None;
    }

    let (clock, fraction) = match rest.split_once('.') {
        Some((clock, fraction)) => (clock, Some(fraction)),
        None => (rest, None),
    };

    let mut clock = clock.splitn(3, ':');
    let hour = i64::from(field(clock.next()?, 2)?);
    let minute = i64::from(field(clock.next()?, 2)?);
    let second = i64::from(field(clock.next()?, 2)?);
    if clock.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    // A leap second is folded onto the second before it. Unix time has no room
    // for one, and refusing a timestamp somebody else legitimately wrote would
    // be worse than placing it a second early.
    let second = second.min(59);

    let nanos = match fraction {
        None => 0,
        Some(digits) => {
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            // Pad or truncate to nanosecond resolution, which is all a
            // `SystemTime` holds.
            let mut scaled = 0u32;
            for i in 0..9 {
                let digit = digits.as_bytes().get(i).map_or(0, |b| u32::from(b - b'0'));
                scaled = scaled * 10 + digit;
            }
            scaled
        }
    };

    let days = days_from_civil(year, month, day)?;
    // Whether the calendar has this date, asked of the inverse rather than of a
    // table of month lengths. A day past the end of its month still counts to a
    // real day number, and it is the only day number that does not count back to
    // the date it was written as.
    if civil_from_days(days) != (year, month, day) {
        return None;
    }

    let secs = days
        .checked_mul(SECS_PER_DAY)?
        .checked_add(hour * 3_600 + minute * 60 + second)?;

    if !(MIN_SECS..=MAX_SECS).contains(&secs) {
        return None;
    }

    Some(if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, nanos)
    } else {
        UNIX_EPOCH - Duration::new(secs.unsigned_abs(), 0) + Duration::new(0, nanos)
    })
}

/// One field of a timestamp: exactly `width` decimal digits, as the number they
/// spell.
///
/// RFC 3339 fixes every field's width, and holding to that is what refuses the
/// shapes an ordinary integer parse waves through. `-5` is an hour to
/// `i64::from_str` and moves the timestamp into the previous day; `+2026` is a
/// year. Neither is a timestamp anybody wrote on purpose, and neither failed to
/// parse.
fn field(text: &str, width: usize) -> Option<u32> {
    if text.len() != width || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Days from the Unix epoch to a civil date, the inverse of
/// [`civil_from_days`].
///
/// Howard Hinnant's algorithm, the same one that function inverts, so the two
/// agree by construction rather than by testing every date.
fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let month = i64::from(month);
    let day = i64::from(day);

    // Re-base onto a March-started year, so the leap day lands at the end.
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);

    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
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
    /// A local time reads as one, and carries the offset that makes it
    /// comparable with anything else.
    ///
    /// Asserted against the shape rather than against a fixed answer: what
    /// `18:21` means depends on where the machine running the test is, and a
    /// test that only passes in one timezone is a test that fails in CI.
    #[test]
    fn a_local_time_is_readable_and_still_unambiguous() {
        let moment = UNIX_EPOCH + Duration::from_secs(1_770_000_000);
        let shown = local(moment);

        // `YYYY-MM-DD HH:MM:SS ±HHMM`, and nothing else.
        assert_eq!(shown.len(), 25, "{shown}");
        assert_eq!(shown.as_bytes()[10], b' ', "{shown}");
        assert_eq!(shown.as_bytes()[19], b' ', "{shown}");
        assert!(
            matches!(shown.as_bytes()[20], b'+' | b'-'),
            "no offset: {shown}"
        );
        assert!(
            !shown.contains('T'),
            "still reads as a machine format: {shown}"
        );
        assert!(!shown.ends_with('Z'), "claims to be UTC: {shown}");

        // The same instant either way, whatever this machine's zone is.
        assert_eq!(&rfc3339(moment)[..4], &shown[..4]);
    }

    /// A positive offset reads *ahead* of UTC, and a negative one behind.
    ///
    /// **The sign is the whole of what this guards, and nothing that goes
    /// through the platform can.** A test that renders through `local_offset`
    /// and checks the reading against the offset printed beside it passes just
    /// as happily when both are inverted — and in CI, which runs in UTC, the
    /// offset is zero and there is nothing to invert at all. So the offset is
    /// handed in here, and the expected string is written out by hand.
    ///
    /// Getting this backwards puts every banner two, five, or eleven hours off
    /// in the field whose entire purpose is lining this scan up against somebody
    /// else's log — and it would look completely plausible.
    #[test]
    fn a_positive_offset_reads_ahead_of_utc_and_a_negative_one_behind() {
        // 2026-02-02T02:40:00Z, the instant the `rfc3339` doctest uses.
        const AT: i64 = 1_770_000_000;

        assert_eq!(rendered(AT, 0), "2026-02-02 02:40:00 +0000", "UTC itself");
        assert_eq!(
            rendered(AT, 2 * 3_600),
            "2026-02-02 04:40:00 +0200",
            "east of UTC reads later in the day"
        );
        assert_eq!(
            rendered(AT, -5 * 3_600),
            "2026-02-01 21:40:00 -0500",
            "west of UTC reads earlier, and back over midnight"
        );
    }

    /// An offset that is not a whole number of hours is carried in the minutes.
    ///
    /// India is `+0530` and Chatham Island is `+1245`. Dividing an offset by
    /// 3,600 and printing the remainder as though it were minutes is the obvious
    /// way to write this and is wrong for both of them; so is dropping the
    /// remainder, which is the same bug rendered as silence.
    #[test]
    fn an_offset_of_half_an_hour_is_not_rounded_away() {
        const AT: i64 = 1_770_000_000;

        assert_eq!(rendered(AT, 5 * 3_600 + 1_800), "2026-02-02 08:10:00 +0530");
        assert_eq!(
            rendered(AT, 12 * 3_600 + 2_700),
            "2026-02-02 15:25:00 +1245"
        );
        assert_eq!(
            rendered(AT, -(3 * 3_600 + 1_800)),
            "2026-02-01 23:10:00 -0330",
            "Newfoundland, where the sign and the remainder are both in play"
        );
    }

    /// The offset is applied to the instant, not to the calendar it was read
    /// off — so it carries across a month, a year and a leap day.
    #[test]
    fn an_offset_carries_across_every_boundary_it_meets() {
        // 2025-01-01T00:30:00Z, half an hour into a new year.
        assert_eq!(
            rendered(1_735_691_400, -3_600),
            "2024-12-31 23:30:00 -0100",
            "back over a year boundary"
        );

        // 2024-03-01T00:30:00Z, the day after a leap day.
        assert_eq!(
            rendered(1_709_253_000, -3_600),
            "2024-02-29 23:30:00 -0100",
            "back onto a leap day that only exists in some years"
        );
    }

    /// Whatever this machine's zone is, the offset it prints puts the reading
    /// back at the instant it renders.
    ///
    /// The weaker companion to the three above: it cannot see a sign convention,
    /// but it is the only one that exercises the real platform lookup, and it is
    /// what would notice `local` forgetting to apply the offset it just asked
    /// for on a machine that is not in UTC.
    #[test]
    fn the_platforms_own_offset_recovers_the_instant() {
        // The epoch, a leap day, a winter and a summer instant, and a date past
        // the 2038 boundary a 32-bit `time_t` stops at.
        for secs in [
            0_i64,
            951_782_400,
            1_770_000_000,
            1_752_000_000,
            4_102_444_800,
        ] {
            let moment = UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).expect("positive"));
            let shown = local(moment);

            // A platform that will not say what its zone is renders UTC instead,
            // which `local` documents and which is not what this is testing.
            if shown.ends_with('Z') {
                continue;
            }

            let field = |range: std::ops::Range<usize>| -> i64 {
                shown[range].parse().unwrap_or_else(|_| panic!("{shown}"))
            };

            let days = days_from_civil(
                field(0..4),
                u32::try_from(field(5..7)).expect("a month"),
                u32::try_from(field(8..10)).expect("a day"),
            )
            .unwrap_or_else(|| panic!("not a date: {shown}"));

            let reading =
                days * SECS_PER_DAY + field(11..13) * 3_600 + field(14..16) * 60 + field(17..19);

            let magnitude = field(21..23) * 3_600 + field(23..25) * 60;
            let offset = if shown.as_bytes()[20] == b'-' {
                -magnitude
            } else {
                magnitude
            };

            assert_eq!(
                reading - offset,
                secs,
                "the offset does not put `{shown}` back at the instant it renders"
            );
        }
    }

    /// Records keep their precision; a line somebody reads does not need it.
    #[test]
    fn a_record_keeps_what_a_banner_drops() {
        let moment = UNIX_EPOCH + Duration::new(1_770_000_000, 123_456_789);

        assert!(rfc3339(moment).contains(".123456"));
        assert!(!local(moment).contains(".123456"));
    }

    /// The one property that matters about a pair of inverses.
    #[test]
    fn a_rendered_timestamp_reads_back_as_itself() {
        let moments = [
            UNIX_EPOCH,
            UNIX_EPOCH + Duration::new(1_770_000_000, 123_456_000),
            UNIX_EPOCH + Duration::new(951_782_400, 0),
            UNIX_EPOCH + Duration::new(4_102_444_799, 999_999_000),
            UNIX_EPOCH - Duration::new(86_400, 0),
        ];

        for moment in moments {
            let rendered = rfc3339(moment);
            assert_eq!(
                parse_rfc3339(&rendered),
                Some(moment),
                "{rendered} did not read back as what rendered it"
            );
        }
    }

    #[test]
    fn a_timestamp_that_is_not_utc_is_refused() {
        assert_eq!(parse_rfc3339("2026-08-24T12:00:00.000000+02:00"), None);
        assert_eq!(parse_rfc3339("2026-08-24T12:00:00.000000"), None);
    }

    #[test]
    fn a_timestamp_without_a_fraction_is_read() {
        assert_eq!(
            parse_rfc3339("1970-01-01T00:00:01Z"),
            Some(UNIX_EPOCH + Duration::from_secs(1))
        );
    }

    /// A leap second is folded onto the second before it: Unix time has no room
    /// for one, and refusing a timestamp somebody legitimately wrote would be
    /// worse than placing it a second early.
    #[test]
    fn a_leap_second_lands_on_the_second_before_it() {
        assert_eq!(
            parse_rfc3339("2016-12-31T23:59:60Z"),
            parse_rfc3339("2016-12-31T23:59:59Z")
        );
    }

    /// The shapes that parsed and should not have.
    ///
    /// **Each of these came back as a perfectly ordinary moment on the wrong
    /// day.** Every field went through an integer parse with only an upper
    /// bound checked, so `-5` was an hour five hours before midnight and
    /// `2026-02-31` was the third of March. Nothing failed, and the only reader
    /// that calls this is the one that rebuilds a report out of a file somebody
    /// else wrote — where a wrong `cert_not_after` is an expiry alert that fires
    /// on the wrong date, or not at all.
    #[test]
    fn a_timestamp_that_is_not_one_is_refused_rather_than_reinterpreted() {
        for text in [
            // A negative field, which moves the moment into another day.
            "2026-01-01T-5:00:00Z",
            "2026-01-01T00:-30:00Z",
            "2026-01-01T00:00:-1Z",
            // A day the month does not have.
            "2026-02-31T00:00:00Z",
            "2025-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-01-00T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-13-01T00:00:00Z",
            // Widths RFC 3339 does not have.
            "2026-2-2T01:02:03Z",
            "+2026-01-01T00:00:00Z",
            "26-01-01T00:00:00Z",
            "2026-01-01T1:02:03Z",
        ] {
            assert_eq!(parse_rfc3339(text), None, "{text} was read as a moment");
        }

        // A leap day that exists still does.
        assert!(parse_rfc3339("2024-02-29T00:00:00Z").is_some());
    }
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

    proptest! {
        /// Every moment the format can express survives the round trip.
        #[test]
        fn every_rendered_time_reads_back_as_itself(secs in MIN_SECS..=MAX_SECS, micros in 0u32..1_000_000) {
            let moment = if secs >= 0 {
                UNIX_EPOCH + Duration::new(secs as u64, micros * 1_000)
            } else {
                UNIX_EPOCH - Duration::new(secs.unsigned_abs(), 0) + Duration::new(0, micros * 1_000)
            };

            let rendered = rfc3339(moment);
            prop_assert_eq!(parse_rfc3339(&rendered), Some(moment), "{}", rendered);
        }
    }
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
