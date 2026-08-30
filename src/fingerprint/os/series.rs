// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What several replies say that one reply cannot
//!
//! Three features of a stack are policies rather than values, and a policy is
//! only visible across a series: whether the IP identifier counts, stays at
//! zero or is random; whether the initial sequence numbers come from a
//! generator with a fixed step or a hash; whether the timestamp clock ticks at
//! a rate or is offset randomly per connection. One reply is a number, several
//! are an algorithm.
//!
//! The classifiers here are the measurement half. They were written and tested
//! against real hosts first, and moved here once rules needed to predicate on
//! what they read — the same graduation the recorded option layouts took into
//! [`StackObservation`](super::StackObservation). A rule that wants to say
//! "Linux 5.x has a hashed ISN generator" needs this vocabulary to say it with.
//!
//! ## The comparison key, and where it is deliberately coarse
//!
//! Every class carries a *name* — a short, stable string, and the only thing a
//! rule or a comparison should match on. The raw figures are kept beside it for
//! the report, because a person disputing a class needs the numbers behind it;
//! but a rate like "how fast the identifier counter advances" is a fact about
//! what else the host was doing, not about the stack, and two identical
//! machines under different load would be reported as different if it entered
//! the key. The key keeps the *kind* of policy and drops its speed.
//!
//! ## Refusing to classify is a class
//!
//! `TooFew`, `Unclear` (sampled too slowly to separate a wrapping counter from
//! noise), `Absent` (IPv6 has no identification field) are readings, not
//! failures. A series that cannot support a class must not be squeezed into
//! one: the trap list this project keeps is largely a list of confident wrong
//! answers, and a classifier that reports nothing where it cannot see is the
//! cheapest defence against the next one.
//!
//! ## One code path per series
//!
//! A stack's resets and its SYN+ACKs come from different code paths that
//! disagree about the same fields — measured, on one host: identifier zero on
//! its SYN+ACK path, a global counter on its reset path. A series that mixed
//! the two would compare a host against itself under two policies, so every
//! classifier takes the reply kind alongside the values and refuses to read a
//! field out of the wrong one.

use std::time::{Duration, Instant};

/// One reply, reduced to what the series classifiers read.
///
/// Built from a captured segment by whoever is collecting the series; this
/// type holds no packets and knows nothing about how the samples were drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeriesSample {
    /// When the reply was read. The interval between two of these is what a
    /// clock rate and an identifier step are computed against — a nominal
    /// spacing is what the sender intended, not what happened.
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
    /// The distinction is load-bearing: a reset opens no connection, so there
    /// is no generator behind its sequence number to describe.
    pub fn is_syn_ack(&self) -> bool {
        use crate::protocols::tcp::flags;
        self.flags & flags::SYN != 0 && self.flags & flags::ACK != 0
    }
}

/// How long two samples may sit apart and still support an identifier reading.
///
/// A 16-bit identifier counter wraps every 65 536 packets. Sampled across a gap
/// long enough for a busy host to wrap it, a counter and a random number are
/// the same observation, and a handful of samples cannot separate them. Longer
/// gaps are reported as [`IdClass::Unclear`] with the raw values, rather than
/// as a class the series cannot support.
pub const MAX_INTERVAL_FOR_ID: Duration = Duration::from_millis(500);

/// The largest identifier step per sample still consistent with a counter.
///
/// A counter can be advanced by other traffic between two samples — the host
/// was busy — but not by more than its own output can plausibly account for.
/// 20 000 identifiers a second is far beyond any interface a scanner shares a
/// segment with, so a larger step is noise or randomness wearing a counter's
/// shape.
const PLAUSIBLE_ID_RATE: f64 = 20_000.0;

/// The largest interval still consistent with reading a clock rate.
///
/// The same reasoning as [`MAX_INTERVAL_FOR_ID`] one field over: a wider gap
/// cannot separate a real tick from a coincidence, and the reading is refused
/// rather than guessed.
const MAX_INTERVAL_FOR_CLOCK: Duration = Duration::from_millis(500);

/// The fastest tick still reported as a frequency. Above this the values are
/// random or corrupted, not a clock — real timestamp clocks run at 100 Hz to
/// 1 kHz, and anything beyond an order of magnitude past that is the
/// per-connection offset of RFC 7323 §5.4.
const CLOCK_CEILING: f64 = 10_000.0;

/// Two readings of one clock whose implied rates differ by less than this
/// factor are one clock. Real stacks tick at a small set of frequencies (100,
/// 250, 1000 Hz); a key that kept more precision than this would report one
/// machine as two because the sampling was jittered.
const CLOCK_SPREAD: f64 = 2.0;

/// The smallest common step still read as a pattern in sequence numbers.
///
/// Differences below this are consistent with a hashed generator that happened
/// to produce near neighbours, and calling them "multiples of 4" would be
/// finding structure in noise.
const MEANINGFUL_ISN_STEP: u32 = 1_024;

/// What a series of IP identifiers turned out to be.
///
/// The name is what a rule predicates on; the class itself is what a report
/// prints, which is the separation the [comparison key](IdClass::name) exists
/// to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdClass {
    /// IPv6, which has no identification field to have a policy about.
    Absent,
    /// Fewer values than a policy can be read from.
    TooFew,
    /// Sampled too slowly for the question to have an answer. The bound is
    /// `MAX_INTERVAL_FOR_ID`: a 16-bit counter wraps inside it, and past that a
    /// counter and a random number are the same observation.
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
/// Not read from resets: a reset opens no connection, so there is no generator
/// behind its sequence number to describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IsnClass {
    /// A reset carries no generator to read.
    NotRead,
    /// Fewer than three handshake answers, which cannot show whether the
    /// differences between them repeat.
    TooFew,
    /// Zero throughout — a stack that generates no initial sequence numbers,
    /// which is a quirk worth a rule of its own.
    Zero,
    /// The generator advances by a constant, which *is* a stack constant.
    /// The step is carried for the report and deliberately kept out of the
    /// [name](Self::name): two machines running one build differ in load, not
    /// in step.
    FixedStep(u32),
    /// Not a constant step, but every difference is a multiple of one.
    Multiples(u32),
    /// No common step: a hashed generator, per RFC 6528.
    Hashed,
}

impl IsnClass {
    /// The class with the figure behind it, for a person reading a report.
    ///
    /// The other half of what [`name`](Self::name) deliberately drops. A rule
    /// must not key on the step — that is the machine's activity, not the stack
    /// — but somebody disputing the class, or authoring a rule from it, needs
    /// the number in front of them.
    pub fn detail(self) -> String {
        match self {
            IsnClass::FixedStep(step) => format!("fixed-step({step})"),
            IsnClass::Multiples(step) => format!("multiples({step})"),
            other => other.name().to_owned(),
        }
    }

    /// The stable name a rule or a comparison matches on. Carries no step: how
    /// *fast* a stepping generator advances is a fact about the machine's
    /// activity, not about the stack.
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
    /// It sent the option and left the value at zero, which is a stack policy
    /// rather than a clock.
    Zero,
    /// Fewer than two timestamps to compare, or samples more than half a
    /// second apart, past which a tick and a coincidence read the same. Both
    /// come to the same answer: no rate can be taken from this series.
    TooFew,
    /// The values move, but not as one clock read repeatedly does.
    ///
    /// **This is a finding, not a failure.** RFC 7323 §5.4 recommends a sender
    /// add a *per-connection* random offset to its timestamp clock, and every
    /// sample in a series drawn by separate connections sees a different
    /// offset. Whether a stack does this is itself a discriminator — and it
    /// means the clock's *rate* cannot be recovered from separate connections
    /// at all. Recovering that needs two timestamps from **one** connection,
    /// which needs a completed handshake.
    Randomised,
    /// The clock ticks more slowly than the sampling: the values are nonzero
    /// and never changed. A real reading, and one that needs a longer run to
    /// put a number on.
    Slower,
    /// The clock's frequency, rounded to the nearest ten hertz.
    ///
    /// Rounded because the raw figure carries the sampling's own timing
    /// jitter: two readings a few milliseconds off across a half-second span
    /// move the answer by well under one percent, and a key built on the exact
    /// number would report one machine as two. Ten hertz is coarse enough to
    /// absorb that and fine enough to keep the frequencies stacks actually use
    /// apart.
    Hertz(u32),
}

impl ClockClass {
    /// The class with the frequency behind it, for a person reading a report.
    ///
    /// The rate is the whole reason to look: it is a stack-build constant, and
    /// the one that moved when Linux stopped deriving its timestamp clock from
    /// the tick rate. A rule cannot key on it — the sampling's own jitter is in
    /// the figure, so an exact hertz would match one network and not the next —
    /// but a person deciding *what rule to write* has nothing else to go on.
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
/// Built from the samples by whoever collected them; a passive path has no
/// series and no `SeriesClasses`, which is the ordinary case — a rule naming a
/// series predicate then fails to match by the same "the peer did not say"
/// rule that governs every other absent field.
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
    /// The classifiers refuse more than they answer — too few samples, sampled
    /// too slowly, the field absent — and a refusal is a class like any other:
    /// it matches no rule that predicates on the field, which is exactly the
    /// behaviour a series collected badly should have.
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
    /// Figures included, where a class has one. This is the display half, not
    /// the comparison key: a rule still matches on the bare names, and the
    /// module documentation's promise that "the raw figures are kept beside it
    /// for the report" is only kept if the report actually shows them. A reading
    /// of `ticking` alone cannot tell somebody whether they are looking at the
    /// 1 kHz clock of one build or the tick-derived one of an older kernel,
    /// which is the single question this series is best placed to answer.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reading<T> {
    /// The class itself.
    pub class: T,
    /// The raw values, rendered for a person. A class this classifier declined
    /// to give — or gave wrongly — can be overruled by reading these.
    pub line: String,
}

/// Reads the identifier series.
///
/// Each sample's value is paired with its arrival time, because the step each
/// interval implies is what decides the class; a filter on values and a window
/// on times applied separately can fall out of step the first time a reply
/// arrives without the field.
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

    // Wrapping, because a counter crossing 65535 is still a counter and a naive
    // subtraction turns one step into a jump of sixty-five thousand.
    //
    // Judged per interval, not over the whole span. A counter never jumps, so
    // one step implying an implausible rate is enough to say this is not one
    // being followed — where a total advance divided by a total span would let
    // a single large jump hide behind several small ones and report a tidy
    // average describing nothing that happened.
    let steps: Vec<u16> = sampled
        .windows(2)
        .map(|pair| pair[1].1.wrapping_sub(pair[0].1))
        .collect();
    let fastest = sampled
        .windows(2)
        .zip(&steps)
        .map(|(pair, step)| f64::from(*step) / pair[1].0.duration_since(pair[0].0).as_secs_f64())
        .filter(|rate| *rate > 0.0)
        .fold(f64::INFINITY, f64::min);

    if fastest <= PLAUSIBLE_ID_RATE {
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
/// Every interval is checked, not just the span from first to last. A stack
/// that randomises its offset per connection can produce a first-to-last
/// difference that looks perfectly reasonable by chance while every step in
/// between is nonsense, and reading only the endpoints would report a
/// confident frequency for a host that has no comparable clock at all.
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

    // Per interval, wrapping at the 32-bit edge. A clock crossing its wrap is
    // still a clock, and the endpoint-only reading would turn one into a
    // ten-digit rate.
    let rates: Vec<f64> = sampled
        .windows(2)
        .map(|pair| {
            let ticks = pair[1].1.wrapping_sub(pair[0].1);
            let secs = pair[1].0.duration_since(pair[0].0).as_secs_f64();
            f64::from(ticks) / secs
        })
        .collect();

    // The spread check is the whole defence against the plausible-endpoints
    // trap: every interval has to agree with every other, not just the
    // endpoints with themselves.
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
// ║ ████████╗███████╗███████╗██████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████╗   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Builds a series with `offsets` between samples, carrying whichever of
    /// the three fields each reply held. Absent slices mean the field was not
    /// present in those replies, which is a different thing from a zero.
    ///
    /// The base instant is read **once**. Reading it per sample made the offsets
    /// approximate rather than exact — each call advances by however long the
    /// loop took — and every reading here divides a counter's movement by the
    /// interval between samples, so a machine under load could push a rate
    /// across a bucket boundary and fail a test about arithmetic for reasons
    /// that had nothing to do with it.
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

    /// A counter wrapping at the field's edge is still a counter: the naive
    /// subtraction turns one step into a jump of sixty-five thousand.
    #[test]
    fn a_wrapping_counter_is_still_counting() {
        let wrapping = series(&spaced(4), &[65_530, 65_532, 65_534, 0], &[], &[]);
        assert_eq!(read_identifiers(&wrapping).class, IdClass::Counting);
    }

    /// A gap wider than the counter can wrap inside makes the reading
    /// unanswerable, and the class says so rather than guessing.
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

    /// Random values have no step a counter could follow, and the fastest
    /// implied rate is beyond anything a host outputs.
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

    /// A reset opens no connection, so there is no generator behind its
    /// sequence number to describe — whatever the values happen to be.
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

    /// The same clock, crossing the end of its 32-bit counter. Wrapping or not
    /// is the difference between 1000 Hz and a number with ten digits.
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

    /// RFC 7323 §5.4: a per-connection random offset makes every sample a
    /// different clock, and the first run against real hardware produced
    /// exactly this and had it reported as a clock running at 1.9 GHz.
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

    /// The case that decides whether checking every interval was worth it. The
    /// endpoints are five hundred ticks apart across half a second, so an
    /// endpoint-only reading reports a tidy 1000 Hz — while every step in
    /// between is nonsense.
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

    /// A clock ticking more slowly than the sampling: a real reading that a
    /// longer run would put a number on, not a failure.
    #[test]
    fn a_clock_slower_than_the_sampling_says_so() {
        let slow = series(&spaced(6), &[], &[], &[77_777; 6]);
        assert_eq!(read_clock(&slow).class, ClockClass::Slower);
    }

    /// The comparison key is coarse in the right places: two counters at
    /// different rates are one policy, and one clock measured with sampling
    /// jitter is one clock.
    #[test]
    fn the_names_are_coarse_where_the_values_vary() {
        let slow_counter = series(&spaced(6), &[10, 11, 12, 13, 14, 15], &[], &[]);
        let fast_counter = series(&spaced(6), &[900, 950, 1000, 1050, 1100, 1150], &[], &[]);
        assert_eq!(
            read_identifiers(&slow_counter).class.name(),
            read_identifiers(&fast_counter).class.name(),
            "two counters at different rates share one policy name"
        );

        // Both intervals sit inside `MAX_INTERVAL_FOR_CLOCK`, which is the
        // point: this test is about the *naming* being coarse, and a sample
        // spaced beyond that ceiling is refused a rate before any naming
        // happens. The pair used to straddle it — 500 ms and 502 ms — so both
        // readings came back refused and the assertion compared one rejection
        // against another, agreeing for a reason that had nothing to do with
        // clocks.
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

    /// The type is public vocabulary and must stay constructible from plain
    /// values, pinned so an accidental private-field refactor does not strand
    /// the collectors that build these.
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
