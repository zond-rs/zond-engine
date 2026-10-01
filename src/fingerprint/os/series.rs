// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What several replies say that one reply cannot
//!
//! Three stack features are policies visible only across several replies:
//! whether the IP identifier counts, stays at zero or is random; whether initial
//! sequence numbers step by a constant or are hashed; whether the timestamp
//! clock ticks at a rate or is offset randomly per connection.
//!
//! The classifiers here were tested against real hosts and give rules the
//! vocabulary to say, for example, "Linux 5.x has a hashed ISN generator".
//!
//! ## The comparison key
//!
//! Every class has a short, stable *name*, which is all a rule should match on.
//! The raw figures are kept for the report. A rate such as how fast the
//! identifier advances depends on the host's load, so the name keeps the kind
//! of policy and drops its speed.
//!
//! ## Refusing to classify is a class
//!
//! `TooFew`, `Unclear` (sampled too slowly to tell a wrapping counter from
//! noise) and `Absent` (IPv6 has no identification field) are readings. A
//! series that cannot support a class is not forced into one.
//!
//! ## One code path per series
//!
//! A stack's resets and SYN+ACKs come from different code paths (one host wrote
//! identifier zero on SYN+ACKs and a global counter on resets), so every
//! classifier takes the reply kind and reads each field only from the right one.

use std::time::{Duration, Instant};

/// One reply, reduced to what the series classifiers read.
///
/// Built from a captured segment by whoever collects the series.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeriesSample {
    /// When the reply arrived, stamped as near the wire as possible. Clock rates
    /// and identifier steps are computed against these intervals.
    pub at: Instant,
    /// The TCP flag byte, so a series can say whether it is reading SYN+ACKs or
    /// resets.
    pub flags: u8,
    /// The sequence number as it arrived: the peer's initial sequence number in
    /// a SYN+ACK, and usually zero in a reset.
    pub sequence: u32,
    /// The IPv4 identification field. `None` over IPv6, which has none.
    pub ip_id: Option<u16>,
    /// The peer's own clock, where it sent a timestamp option.
    pub tsval: Option<u32>,
}

impl SeriesSample {
    /// Whether this reply is a handshake answer rather than a refusal.
    ///
    /// A reset opens no connection, so no generator lies behind its sequence
    /// number.
    pub fn is_syn_ack(&self) -> bool {
        use crate::protocols::tcp::flags;
        self.flags & flags::SYN != 0 && self.flags & flags::ACK != 0
    }
}

/// How long two samples may sit apart and still support an identifier reading.
///
/// A 16-bit counter wraps every 65 536 packets; across a gap long enough for a
/// busy host to wrap it, a counter looks random. Longer gaps are reported as
/// [`IdClass::Unclear`].
pub const MAX_INTERVAL_FOR_ID: Duration = Duration::from_millis(500);

/// How fast a host's other traffic may advance an identifier counter between
/// two samples, in identifiers a second, and leave it read as a counter.
///
/// 20 000 identifiers a second is far beyond any interface a scanner shares a
/// segment with, so a larger step is randomness. The reply's own step of one is
/// allowed on top.
const PLAUSIBLE_ID_RATE: f64 = 20_000.0;

/// The largest interval still consistent with reading a clock rate.
///
/// As [`MAX_INTERVAL_FOR_ID`]: a wider gap cannot separate a tick from a
/// coincidence.
const MAX_INTERVAL_FOR_CLOCK: Duration = Duration::from_millis(500);

/// The fastest tick still reported as a frequency. Real timestamp clocks run at
/// 100 Hz to 1 kHz; far beyond that is the per-connection offset of RFC 7323
/// §5.4.
const CLOCK_CEILING: f64 = 10_000.0;

/// Rates within this factor are one clock. Real stacks tick at 100, 250 or
/// 1000 Hz, and sampling jitter must not split one clock into two.
const CLOCK_SPREAD: f64 = 2.0;

/// The smallest common step still read as a pattern in sequence numbers.
///
/// Smaller common steps are consistent with a hashed generator producing near
/// neighbours.
const MEANINGFUL_ISN_STEP: u32 = 1_024;

/// What a series of IP identifiers turned out to be.
///
/// Rules match on the [name](IdClass::name); reports print the class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdClass {
    /// IPv6, which has no identification field to have a policy about.
    Absent,
    /// Fewer values than a policy can be read from.
    TooFew,
    /// Sampled too slowly to tell; see `MAX_INTERVAL_FOR_ID`.
    Unclear,
    /// Zero on every reply. Several stacks write zero on non-fragmentable
    /// datagrams, which RFC 6864 §4.1 permits.
    Zero,
    /// One value across every reply. A per-socket identifier that never
    /// advanced within the window.
    Constant,
    /// Advancing by small steps, wrapping at the field's edge. One counter the
    /// whole host shares.
    Counting,
    /// Values with no relation to each other. A randomised identifier.
    Scattered,
}

impl IdClass {
    /// The class a stable name refers to, or `None` for a name nothing here
    /// produces.
    ///
    /// The inverse of [`name`](Self::name), for a recorded example or a
    /// translated corpus. See [`IsnClass::from_name`].
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "absent" => IdClass::Absent,
            "too-few" => IdClass::TooFew,
            "unclear" => IdClass::Unclear,
            "zero" => IdClass::Zero,
            "constant" => IdClass::Constant,
            "counting" => IdClass::Counting,
            "scattered" => IdClass::Scattered,
            _ => return None,
        })
    }

    /// The stable name a rule or a comparison matches on.
    pub const fn name(self) -> &'static str {
        match self {
            IdClass::Absent => "absent",
            IdClass::TooFew => "too-few",
            IdClass::Unclear => "unclear",
            IdClass::Zero => "zero",
            IdClass::Constant => "constant",
            IdClass::Counting => "counting",
            IdClass::Scattered => "scattered",
        }
    }
}

/// What a series of initial sequence numbers turned out to be.
///
/// Not read from resets, which have no generator behind their sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IsnClass {
    /// A reset carries no generator to read.
    NotRead,
    /// Fewer than three handshake answers, which cannot show whether the
    /// differences between them repeat.
    TooFew,
    /// Zero throughout: a stack that generates no initial sequence numbers.
    Zero,
    /// The generator advances by a constant. The step is for the report and kept
    /// out of the [name](Self::name).
    FixedStep(u32),
    /// Not a constant step, but every difference is a multiple of one.
    Multiples(u32),
    /// No common step: a hashed generator, per RFC 6528.
    Hashed,
}

impl IsnClass {
    /// The class a stable name refers to, or `None` for a name nothing here
    /// produces.
    ///
    /// A rebuilt class carries no figure, since [`name`](Self::name) drops it:
    /// right for matching, wrong for [`detail`](Self::detail).
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "not-read" => IsnClass::NotRead,
            "too-few" => IsnClass::TooFew,
            "zero" => IsnClass::Zero,
            "fixed-step" => IsnClass::FixedStep(0),
            "multiples" => IsnClass::Multiples(0),
            "hashed" => IsnClass::Hashed,
            _ => return None,
        })
    }

    /// The class with the figure behind it, for a person reading a report.
    ///
    /// Includes the step that [`name`](Self::name) drops.
    pub fn detail(self) -> String {
        match self {
            IsnClass::FixedStep(step) => format!("fixed-step({step})"),
            IsnClass::Multiples(step) => format!("multiples({step})"),
            other => other.name().to_owned(),
        }
    }

    /// The stable name a rule or a comparison matches on. Carries no step, which
    /// depends on the machine's load.
    pub const fn name(self) -> &'static str {
        match self {
            IsnClass::NotRead => "not-read",
            IsnClass::TooFew => "too-few",
            IsnClass::Zero => "zero",
            IsnClass::FixedStep(_) => "fixed-step",
            IsnClass::Multiples(_) => "multiples",
            IsnClass::Hashed => "hashed",
        }
    }
}

/// What a series of timestamp values turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClockClass {
    /// The peer offered no timestamp option.
    None,
    /// It sent the option with the value zero.
    Zero,
    /// No rate can be taken: fewer than two timestamps, samples more than half a
    /// second apart, or samples at the same instant.
    TooFew,
    /// The values move, but not as one clock read repeatedly does.
    ///
    /// RFC 7323 §5.4 recommends a per-connection random offset, so samples from
    /// separate connections differ. Whether a stack does this is itself a
    /// discriminator; its rate then needs two timestamps from one connection.
    Randomised,
    /// The clock ticks more slowly than the sampling: nonzero and unchanged.
    Slower,
    /// The clock's frequency, rounded to the nearest ten hertz.
    ///
    /// Rounded to absorb sampling jitter while keeping real frequencies apart.
    Hertz(u32),
}

impl ClockClass {
    /// The class a stable name refers to, or `None` for a name nothing here
    /// produces.
    ///
    /// Carries no frequency, for the reason [`IsnClass::from_name`] gives.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "none" => ClockClass::None,
            "zero" => ClockClass::Zero,
            "too-few" => ClockClass::TooFew,
            "randomised" => ClockClass::Randomised,
            "slower" => ClockClass::Slower,
            "ticking" => ClockClass::Hertz(0),
            _ => return None,
        })
    }

    /// The class with the frequency behind it, for a person reading a report.
    ///
    /// The rate is a stack-build constant (Linux changed it when it stopped
    /// deriving the timestamp clock from the tick rate). Rules cannot key on it,
    /// because of jitter, but rule authors need it.
    pub fn detail(self) -> String {
        match self {
            ClockClass::Hertz(hz) => format!("ticking({hz}Hz)"),
            other => other.name().to_owned(),
        }
    }

    /// The stable name a rule or a comparison matches on.
    pub const fn name(self) -> &'static str {
        match self {
            ClockClass::None => "none",
            ClockClass::Zero => "zero",
            ClockClass::TooFew => "too-few",
            ClockClass::Randomised => "randomised",
            ClockClass::Slower => "slower",
            ClockClass::Hertz(_) => "ticking",
        }
    }
}

/// The three series readings for one host, in the form a rule and a report
/// consume.
///
/// A passive path has none, and a rule with a series predicate then fails to
/// match, as for any absent field.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeriesClasses {
    /// What the IP identifier series turned out to be.
    pub identifiers: IdClass,
    /// What the initial-sequence-number series turned out to be.
    pub sequences: IsnClass,
    /// What the timestamp series turned out to be.
    pub clock: ClockClass,
}

impl SeriesClasses {
    /// Reads all three series from one set of samples.
    ///
    /// A refusal (too few samples, too slow, field absent) is a class that
    /// matches no rule predicating on the field.
    pub fn from_samples(series: &[SeriesSample]) -> Self {
        Self {
            identifiers: read_identifiers(series).class,
            sequences: read_sequences(series).class,
            clock: read_clock(series).class,
        }
    }

    /// One line saying what the series held, for a report to carry beside a
    /// verdict. Written for a person, to the same rule as
    /// [`StackObservation::summary`](super::StackObservation::summary).
    ///
    /// Includes the figures, such as a clock's rate, which rules do not match on.
    pub fn summary(&self) -> String {
        format!(
            "id={} isn={} ts={}",
            self.identifiers.name(),
            self.sequences.detail(),
            self.clock.detail()
        )
    }
}

/// What one classifier made of one series: the class, and the raw values for a
/// report to carry beside it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reading<T> {
    /// The class itself.
    pub class: T,
    /// The raw values, rendered for a person to check the class against.
    pub line: String,
}

/// Reads the identifier series.
///
/// Each value is paired with its arrival time before filtering, so values and
/// times stay aligned when a reply lacks the field.
pub fn read_identifiers(series: &[SeriesSample]) -> Reading<IdClass> {
    let sampled: Vec<(Instant, u16)> = series
        .iter()
        .filter_map(|sample| sample.ip_id.map(|id| (sample.at, id)))
        .collect();

    let values: Vec<u16> = sampled.iter().map(|(_, id)| *id).collect();
    if values.is_empty() {
        return Reading {
            class: IdClass::Absent,
            line: "none - IPv6 has no identification field".to_string(),
        };
    }
    if values.len() < 3 {
        return Reading {
            class: IdClass::TooFew,
            line: format!("{values:?} - too few to read a policy from"),
        };
    }

    let raw = format!("{values:?}");
    let widest = sampled
        .windows(2)
        .map(|pair| pair[1].0.duration_since(pair[0].0))
        .max()
        .unwrap_or_default();
    if widest > MAX_INTERVAL_FOR_ID {
        return Reading {
            class: IdClass::Unclear,
            line: format!("{raw} - unclear"),
        };
    }

    if values.iter().all(|&value| value == 0) {
        return Reading {
            class: IdClass::Zero,
            line: format!("{raw} - zero throughout"),
        };
    }
    if values.windows(2).all(|pair| pair[0] == pair[1]) {
        return Reading {
            class: IdClass::Constant,
            line: format!("{raw} - constant"),
        };
    }

    // Wrapping: a counter crossing 65535 is still a counter. Judged per
    // interval, since an average over the span would hide a single large jump.
    let steps: Vec<u16> = sampled
        .windows(2)
        .map(|pair| pair[1].1.wrapping_sub(pair[0].1))
        .collect();
    // **Every** interval must fit a counter; testing whether any interval does
    // read 284 of 2000 random six-sample series as `counting`.
    //
    // The interval is multiplied, not divided by, since two replies can share a
    // timestamp. A step of one is allowed at any interval. Zero-length intervals
    // are kept (unlike in `read_clock`): a large step between simultaneous
    // replies is itself evidence against a counter.
    let plausible = sampled.windows(2).zip(&steps).all(|(pair, &step)| {
        let elapsed = pair[1].0.duration_since(pair[0].0).as_secs_f64();
        f64::from(step) <= 1.0 + PLAUSIBLE_ID_RATE * elapsed
    });

    if plausible {
        return Reading {
            class: IdClass::Counting,
            line: format!("{raw} - counting"),
        };
    }
    Reading {
        class: IdClass::Scattered,
        line: format!("{raw} - scattered"),
    }
}

/// Reads the sequence-number series, from handshake answers only.
pub fn read_sequences(series: &[SeriesSample]) -> Reading<IsnClass> {
    if series.iter().all(|sample| !sample.is_syn_ack()) {
        return Reading {
            class: IsnClass::NotRead,
            line: "not read - a reset opens no connection to number".to_string(),
        };
    }

    let syn_acks: Vec<&SeriesSample> = series.iter().filter(|s| s.is_syn_ack()).collect();
    let values: Vec<u32> = syn_acks.iter().map(|sample| sample.sequence).collect();
    if values.iter().all(|&value| value == 0) {
        return Reading {
            class: IsnClass::Zero,
            line: "zero throughout".to_string(),
        };
    }
    if values.len() < 3 {
        return Reading {
            class: IsnClass::TooFew,
            line: format!("{values:?} - too few to read a generator from"),
        };
    }

    let steps: Vec<u32> = values
        .windows(2)
        .map(|pair| pair[1].wrapping_sub(pair[0]))
        .collect();
    if steps.windows(2).all(|pair| pair[0] == pair[1]) {
        return Reading {
            class: IsnClass::FixedStep(steps[0]),
            line: format!("fixed step of {}", steps[0]),
        };
    }
    let divisor = steps.iter().copied().fold(0u32, gcd);
    if divisor >= MEANINGFUL_ISN_STEP {
        return Reading {
            class: IsnClass::Multiples(divisor),
            line: format!("stepping in multiples of {divisor}"),
        };
    }
    Reading {
        class: IsnClass::Hashed,
        line: format!("no common step (divisor {divisor}) - consistent with a hashed generator"),
    }
}

/// Reads the peer's clock, where it sent one.
///
/// Every interval is checked: with a per-connection random offset the endpoints
/// alone can look like a plausible rate by chance.
pub fn read_clock(series: &[SeriesSample]) -> Reading<ClockClass> {
    let sampled: Vec<(Instant, u32)> = series
        .iter()
        .filter_map(|sample| sample.tsval.map(|ts| (sample.at, ts)))
        .collect();

    if sampled.is_empty() {
        return Reading {
            class: ClockClass::None,
            line: "none sent".to_string(),
        };
    }
    let values: Vec<u32> = sampled.iter().map(|(_, ts)| *ts).collect();
    if values.iter().all(|&value| value == 0) {
        return Reading {
            class: ClockClass::Zero,
            line: "sent, but always zero".to_string(),
        };
    }
    if values.len() < 2 {
        return Reading {
            class: ClockClass::TooFew,
            line: format!("{values:?} - too few to read a rate from"),
        };
    }

    let raw = format!("{values:?}");
    let widest = sampled
        .windows(2)
        .map(|pair| pair[1].0.duration_since(pair[0].0))
        .max()
        .unwrap_or_default();
    if widest > MAX_INTERVAL_FOR_CLOCK {
        return Reading {
            class: ClockClass::TooFew,
            line: format!("{raw} - sampled too slowly for a rate"),
        };
    }

    // Per interval, wrapping at the 32-bit edge. Zero-length intervals are
    // dropped: dividing by them gives an infinity or a NaN, which compares false
    // against every bound below.
    let rates: Vec<f64> = sampled
        .windows(2)
        .filter_map(|pair| {
            let ticks = pair[1].1.wrapping_sub(pair[0].1);
            let secs = pair[1].0.duration_since(pair[0].0).as_secs_f64();
            (secs > 0.0).then(|| f64::from(ticks) / secs)
        })
        .collect();
    if rates.is_empty() {
        return Reading {
            class: ClockClass::TooFew,
            line: format!("{raw} - no interval to read a rate over"),
        };
    }

    // Every interval's rate must agree with every other's.
    let slowest = rates.iter().copied().fold(f64::INFINITY, f64::min);
    let fastest = rates.iter().copied().fold(0.0, f64::max);
    if fastest > CLOCK_CEILING || fastest / slowest.max(f64::MIN_POSITIVE) > CLOCK_SPREAD {
        return Reading {
            class: ClockClass::Randomised,
            line: format!("{raw} - randomised per connection"),
        };
    }

    let hertz = rates.iter().sum::<f64>() / rates.len() as f64;
    if hertz < 1.0 {
        return Reading {
            class: ClockClass::Slower,
            line: format!("{raw} - slower than sampled"),
        };
    }
    let rounded = (hertz / 10.0).round() * 10.0;
    Reading {
        class: ClockClass::Hertz(rounded as u32),
        line: format!("{raw} - about {rounded:.0} Hz"),
    }
}

/// Greatest common divisor, for finding a fixed step in a set of differences.
fn gcd(a: u32, b: u32) -> u32 {
    let (mut a, mut b) = (a, b);
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
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

    /// Two replies read at one instant span no time, and a clock rate over no
    /// time is not a rate.
    ///
    /// The quotient would be an infinity or a NaN, which passes every bound check.
    #[test]
    fn an_interval_of_no_length_yields_no_rate() {
        let t0 = Instant::now();
        let sample = |at: Instant, tsval: u32| SeriesSample {
            at,
            flags: 0x12,
            sequence: 1,
            ip_id: None,
            tsval: Some(tsval),
        };

        // Non-zero, so the all-zero branch does not take it.
        let stopped = read_clock(&[sample(t0, 7), sample(t0, 7)]);
        assert_eq!(stopped.class, ClockClass::TooFew, "{}", stopped.line);
        assert!(
            !stopped.line.contains("NaN"),
            "and the line says so in words: {}",
            stopped.line
        );

        let moved = read_clock(&[sample(t0, 7), sample(t0, 9)]);
        assert_eq!(moved.class, ClockClass::TooFew, "{}", moved.line);

        // 100 ticks in 100 ms is a kilohertz.
        let t1 = t0 + Duration::from_millis(100);
        let ordinary = read_clock(&[sample(t0, 4096), sample(t1, 4196)]);
        assert_eq!(ordinary.class, ClockClass::Hertz(1000), "{}", ordinary.line);
    }

    /// One implausible step rules out a counter. Testing the slowest interval
    /// instead read 284 of 2000 random six-sample series as `counting`.
    #[test]
    fn a_randomised_identifier_series_is_not_a_counter() {
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let sample = |ms: u64, id: u16| SeriesSample {
            at: at(ms),
            flags: 0x12,
            sequence: 1,
            ip_id: Some(id),
            tsval: None,
        };

        // Two tiny steps and one enormous jump.
        let jumpy = vec![
            sample(0, 1000),
            sample(100, 1001),
            sample(200, 1002),
            sample(300, 41_002),
        ];
        assert_eq!(
            read_identifiers(&jumpy).class,
            IdClass::Scattered,
            "a counter does not jump forty thousand in a tenth of a second"
        );

        // A random series with one near-neighbour pair.
        let random = vec![
            sample(0, 51_234),
            sample(100, 8_123),
            sample(200, 8_223),
            sample(300, 61_999),
            sample(400, 3),
            sample(500, 40_000),
        ];
        assert_eq!(read_identifiers(&random).class, IdClass::Scattered);

        // A random series must almost never read as a counter. The bound is
        // generous so the test does not depend on this generator.
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut counting = 0;
        for _ in 0..2_000 {
            let series: Vec<SeriesSample> = (0..6u64)
                .map(|i| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    sample(i * 100, (state >> 16) as u16)
                })
                .collect();
            if read_identifiers(&series).class == IdClass::Counting {
                counting += 1;
            }
        }
        assert!(
            counting < 20,
            "{counting} of 2000 random series read as a counter; the slowest-interval \
             reading this replaced scored 284"
        );
    }

    /// A real counter is a counter, even advanced by other traffic.
    #[test]
    fn a_counter_is_still_read_as_one() {
        let t0 = Instant::now();
        let sample = |ms: u64, id: u16| SeriesSample {
            at: t0 + Duration::from_millis(ms),
            flags: 0x12,
            sequence: 1,
            ip_id: Some(id),
            tsval: None,
        };

        let steady = vec![
            sample(0, 100),
            sample(100, 103),
            sample(200, 107),
            sample(300, 111),
        ];
        assert_eq!(read_identifiers(&steady).class, IdClass::Counting);

        // Wrapping at the field's edge is still a counter.
        let wrapping = vec![
            sample(0, 65_530),
            sample(100, 65_534),
            sample(200, 2),
            sample(300, 6),
        ];
        assert_eq!(read_identifiers(&wrapping).class, IdClass::Counting);
    }
    use super::*;
    use std::time::Duration;

    /// Builds a series with `offsets` between samples, carrying whichever of
    /// the three fields each reply held. Absent slices mean the field was not
    /// present in those replies, which is a different thing from a zero.
    ///
    /// The base instant is read once, so offsets are exact even on a loaded
    /// machine.
    fn series(
        offsets: &[Duration],
        identifiers: &[u16],
        sequences: &[u32],
        stamps: &[u32],
    ) -> Vec<SeriesSample> {
        use crate::protocols::tcp::flags;
        let base = Instant::now();
        offsets
            .iter()
            .enumerate()
            .map(|(index, offset)| SeriesSample {
                at: base + *offset,
                flags: flags::SYN | flags::ACK,
                sequence: sequences.get(index).copied().unwrap_or(0),
                ip_id: identifiers.get(index).copied(),
                tsval: stamps.get(index).copied(),
            })
            .collect()
    }

    fn spaced(count: usize) -> Vec<Duration> {
        (0..count)
            .map(|i| Duration::from_millis(100 * i as u64))
            .collect()
    }

    #[test]
    fn identifiers_zero_constant_and_absent() {
        let zero = series(&spaced(4), &[0, 0, 0, 0], &[], &[]);
        assert_eq!(read_identifiers(&zero).class, IdClass::Zero);

        let constant = series(&spaced(4), &[7, 7, 7, 7], &[], &[]);
        assert_eq!(read_identifiers(&constant).class, IdClass::Constant);

        let absent = series(&spaced(4), &[], &[], &[]);
        assert_eq!(read_identifiers(&absent).class, IdClass::Absent);

        let too_few = series(&spaced(2), &[5, 6], &[], &[]);
        assert_eq!(read_identifiers(&too_few).class, IdClass::TooFew);
    }

    /// A counter wrapping at the field's edge is still a counter.
    #[test]
    fn a_wrapping_counter_is_still_counting() {
        let wrapping = series(&spaced(4), &[65_530, 65_532, 65_534, 0], &[], &[]);
        assert_eq!(read_identifiers(&wrapping).class, IdClass::Counting);
    }

    /// A gap wide enough for a wrap is `Unclear`.
    #[test]
    fn a_slowly_sampled_series_is_unclear() {
        let gaps = vec![
            Duration::ZERO,
            Duration::from_millis(100),
            Duration::from_millis(900),
        ];
        let slow = series(&gaps, &[10, 11, 12], &[], &[]);
        assert_eq!(read_identifiers(&slow).class, IdClass::Unclear);
    }

    /// Two replies stamped at one instant are still two readings of a counter.
    ///
    /// Replies read off a capture together are often stamped together. A large
    /// step between them still rules out a counter.
    #[test]
    fn replies_stamped_at_one_instant_are_still_read_as_a_counter() {
        let together = [Duration::ZERO, Duration::ZERO, Duration::from_millis(100)];

        let counter = read_identifiers(&series(&together, &[100, 101, 102], &[], &[]));
        assert_eq!(counter.class, IdClass::Counting, "{}", counter.line);

        let unmoved = read_identifiers(&series(&together, &[100, 100, 101], &[], &[]));
        assert_eq!(unmoved.class, IdClass::Counting, "{}", unmoved.line);

        let jumped = read_identifiers(&series(&together, &[100, 40_100, 40_101], &[], &[]));
        assert_eq!(jumped.class, IdClass::Scattered, "{}", jumped.line);
    }

    /// Random values are scattered.
    #[test]
    fn randomised_identifiers_are_scattered() {
        let scattered = series(&spaced(4), &[4_000, 61_000, 12_000, 33_000], &[], &[]);
        assert_eq!(read_identifiers(&scattered).class, IdClass::Scattered);
    }

    #[test]
    fn sequences_fixed_step_multiples_and_hashed() {
        let stepping = series(
            &spaced(4),
            &[],
            &[1_000_000, 1_064_000, 1_128_000, 1_192_000],
            &[],
        );
        assert_eq!(read_sequences(&stepping).class, IsnClass::FixedStep(64_000));

        let hashed = series(
            &spaced(4),
            &[],
            &[2_147_483_647, 91_827_361, 3_918_273_645, 771_293_811],
            &[],
        );
        assert_eq!(read_sequences(&hashed).class, IsnClass::Hashed);

        let zero = series(&spaced(4), &[], &[0, 0, 0, 0], &[]);
        assert_eq!(read_sequences(&zero).class, IsnClass::Zero);
    }

    /// Resets are not read for sequence numbers.
    #[test]
    fn a_resets_sequence_number_is_not_read() {
        use crate::protocols::tcp::flags;
        let mut reset_series = series(
            &spaced(4),
            &[],
            &[1_000_000, 1_064_000, 1_128_000, 1_192_000],
            &[],
        );
        for sample in &mut reset_series {
            sample.flags = flags::RST | flags::ACK;
        }
        assert_eq!(read_sequences(&reset_series).class, IsnClass::NotRead);
    }

    #[test]
    fn clocks_none_zero_and_ticking() {
        let none = series(&spaced(4), &[], &[], &[]);
        assert_eq!(read_clock(&none).class, ClockClass::None);

        let zero = series(&spaced(4), &[], &[], &[0, 0, 0, 0]);
        assert_eq!(read_clock(&zero).class, ClockClass::Zero);

        let ticking = series(
            &spaced(6),
            &[],
            &[],
            &[500_000, 500_100, 500_200, 500_300, 500_400, 500_500],
        );
        assert_eq!(read_clock(&ticking).class, ClockClass::Hertz(1000));
    }

    /// A clock crossing its 32-bit wrap still reads 1000 Hz.
    #[test]
    fn a_clock_crossing_its_wrap_is_still_that_clock() {
        let wrapping = series(
            &spaced(6),
            &[],
            &[],
            &[u32::MAX - 200, u32::MAX - 100, u32::MAX, 99, 199, 299],
        );
        assert_eq!(read_clock(&wrapping).class, ClockClass::Hertz(1000));
    }

    /// RFC 7323 §5.4 per-connection offsets read as `Randomised`, not as a
    /// 1.9 GHz clock.
    #[test]
    fn a_per_connection_random_offset_is_not_a_clock() {
        let randomised = series(
            &spaced(6),
            &[],
            &[],
            &[
                1_913_402_881,
                88_120_004,
                3_774_119_855,
                412_998_002,
                2_660_001_913,
                955_218_744,
            ],
        );
        assert_eq!(read_clock(&randomised).class, ClockClass::Randomised);
    }

    /// Plausible endpoints (500 ticks over half a second) with nonsense steps
    /// between.
    #[test]
    fn endpoints_that_agree_do_not_make_the_middle_a_clock() {
        let plausible = series(
            &spaced(6),
            &[],
            &[],
            &[500_000, 900_000, 100_000, 700_000, 200_000, 500_500],
        );
        assert_eq!(read_clock(&plausible).class, ClockClass::Randomised);
    }

    /// A clock ticking more slowly than the sampling.
    #[test]
    fn a_clock_slower_than_the_sampling_says_so() {
        let slow = series(&spaced(6), &[], &[], &[77_777; 6]);
        assert_eq!(read_clock(&slow).class, ClockClass::Slower);
    }

    /// Two counters at different rates share a name, and jitter does not split a
    /// clock.
    #[test]
    fn the_names_are_coarse_where_the_values_vary() {
        let slow_counter = series(&spaced(6), &[10, 11, 12, 13, 14, 15], &[], &[]);
        let fast_counter = series(&spaced(6), &[900, 950, 1000, 1050, 1100, 1150], &[], &[]);
        assert_eq!(
            read_identifiers(&slow_counter).class.name(),
            read_identifiers(&fast_counter).class.name(),
            "two counters at different rates share one policy name"
        );

        // Both intervals are inside `MAX_INTERVAL_FOR_CLOCK`, so both readings
        // get a rate and the naming is what is tested.
        let jittered = series(
            &[Duration::ZERO, Duration::from_millis(251)],
            &[],
            &[],
            &[500_000, 500_250],
        );
        let exact = series(
            &[Duration::ZERO, Duration::from_millis(250)],
            &[],
            &[],
            &[700_000, 700_250],
        );
        assert_eq!(
            read_clock(&jittered).class,
            ClockClass::Hertz(1_000),
            "996 Hz measured is a 1000 Hz clock, and the rounding is what says so"
        );
        assert_eq!(
            read_clock(&jittered).class.name(),
            read_clock(&exact).class.name(),
            "one clock measured with jitter reads as one clock"
        );
    }

    #[test]
    fn a_series_sample_knows_whether_it_answered_a_handshake() {
        use crate::protocols::tcp::flags;
        let handshake = series(&spaced(1), &[], &[], &[]);
        assert!(handshake[0].is_syn_ack());

        let mut reset = series(&spaced(1), &[], &[], &[]);
        reset[0].flags = flags::RST;
        assert!(!reset[0].is_syn_ack());
    }

    #[test]
    fn gcd_finds_the_common_step() {
        assert_eq!(gcd(0, 0), 0);
        assert_eq!(gcd(64_000, 64_000), 64_000);
        assert_eq!(gcd(48, 18), 6);
    }

    /// The type stays constructible from plain values.
    #[test]
    fn samples_are_buildable_from_plain_values() {
        let sample = SeriesSample {
            at: Instant::now(),
            flags: 0x12,
            sequence: 42,
            ip_id: Some(7),
            tsval: None,
        };
        assert_eq!(sample.ip_id, Some(7));
    }
}
