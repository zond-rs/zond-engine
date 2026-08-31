// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How far away a host is
//!
//! [`HostTelemetry`] holds a sliding window of round-trip measurements and the
//! summaries a report draws from them: the fastest, the typical, and how much
//! they vary.
//!
//! The whole design turns on one distinction. Not every reply is equally good
//! evidence of a path, and the two kinds must not be pooled — see [`RttSource`]
//! for what separates them and [`HostTelemetry`] for how the ranking is
//! applied. Averaging them together is how a router answering in 7 ms came to
//! be reported at 37.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

/// How many round trips a host keeps by default.
///
/// Every latency figure in every report is computed over this many samples, and
/// it was a bare `10` inside the [`Default`] impl, which is the only bound in
/// the module that was not a named constant with its reasoning under it.
///
/// Ten is enough for a median to mean something and short enough that the window
/// describes the host now rather than an average over an afternoon, which is
/// what [`HostTelemetry`] keeps a window for at all. A caller that wants a
/// longer view sets its own with [`HostTelemetry::new`].
pub const DEFAULT_RTT_SAMPLES: usize = 10;

/// The smallest window [`HostTelemetry::new`] will build.
///
/// One, because zero is a telemetry that accepts every sample and keeps none:
/// `add_rtt` returns as though it recorded something, every statistic answers
/// `None` for ever, and nothing says why. A caller asking for no history is
/// asking for something this type cannot mean, and the nearest thing it can is
/// the most recent reply.
const MIN_RTT_SAMPLES: usize = 1;

/// What kind of question a round-trip sample answers, which decides whether it
/// describes the network or the responder.
///
/// Not every reply is equally good evidence of a path. A probe aimed at one
/// address is answered as fast as the host and the link allow, so the elapsed
/// time is the round trip and nothing else. A probe put to the whole segment is
/// not: implementations deliberately spread their replies to keep every
/// neighbour from answering at once, and a device asleep on wifi answers when it
/// next wakes. Observed on a wireless segment, that difference is an order of
/// magnitude. It shows up as several neighbours reporting the same figure to
/// the millisecond, which is the giveaway that it describes the probe rather
/// than any of them.
///
/// So the two are not comparable and must not be pooled. Both are kept, and the
/// weaker one is used only where there is nothing better: for the neighbour that
/// answers the segment-wide probe and no other, an upper bound is the only
/// latency there is, and it beats a blank.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RttSource {
    /// A reply to a probe aimed at this host alone. A round trip.
    Direct,
    /// A reply to a probe put to the whole segment. An upper bound on the round
    /// trip, inflated by however long the responder waited before answering.
    SegmentWide,
}

/// One round-trip measurement: when it was taken, what it measured, and what
/// kind of question produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RttSample {
    /// When the reply arrived, on the monotonic clock.
    ///
    /// [`Instant`] rather than the wall clock because this exists to order
    /// samples against each other — [`HostTelemetry::merge`] sorts by it and
    /// [`jitter`](HostTelemetry::jitter) differences consecutive pairs — and a
    /// clock adjustment mid-scan must not reorder a history.
    pub at: Instant,
    /// The elapsed time between sending the probe and reading the reply.
    pub rtt: Duration,
    /// Whether that elapsed time is a round trip or an upper bound on one. See
    /// [`RttSource`].
    pub source: RttSource,
}

/// A host's recent round trips, and the summaries drawn from them.
///
/// A sliding window rather than every sample ever taken: a monitor watching one
/// segment for days would otherwise grow without bound, and what a report says
/// about latency should describe the host now rather than an average over an
/// afternoon.
///
/// Every statistic is computed over the host's [`RttSource::Direct`] samples
/// when it has any, and falls back to the segment-wide ones only when it has
/// none. The ranking is applied at the point the numbers are read rather than
/// when they are recorded, so a host that answers a broadcast first and a
/// direct probe afterwards is not left describing itself by the weaker sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTelemetry {
    /// The recent round-trip time measurements with confirmation timestamps.
    /// Ordered chronologically: oldest at the front, newest at the back.
    rtt_history: VecDeque<RttSample>,

    /// How many samples the window holds before the oldest is dropped.
    ///
    /// Private because lowering it has to trim `rtt_history` to match, and a
    /// field a caller can set directly would leave the two disagreeing. See
    /// [`set_max_samples`](Self::set_max_samples).
    max_samples: usize,

    /// The hop counter the most recent reply from this host arrived with.
    ///
    /// Not the value the host wrote: every router on the way decrements it, so
    /// what arrives is the starting value minus the distance. It is kept because
    /// the scan reads it anyway — every captured reply carries one — and
    /// re-obtaining it costs a probe and a round trip.
    ///
    /// What reads it is [`traceroute`](crate::scanner::strategy::routed::traceroute),
    /// which needs to know how far away a host is before it can measure the path
    /// backwards from it. Without this the trace has to send a probe of its own
    /// purely to be answered, which is a round trip spent re-learning something
    /// the port scan already saw — and one more thing that can fail.
    ///
    /// The most recent rather than the first: a route that changed mid-scan is
    /// better described by the reply that came after it.
    ///
    /// Which of two is more recent is not something this type can see, having no
    /// clock of its own for it. [`merge`](Self::merge) takes the other record's,
    /// which is right because of how the engine folds: every call is
    /// `stored.merge(fresh)`, so the argument is always the later account. A
    /// fold across two *documents* has no such guarantee and does not come
    /// through here at all, [`merge`](crate::merge) picking the newest account by
    /// the documents' own clocks and taking its telemetry whole, because an
    /// `Instant` from another process orders against nothing.
    hop_counter: Option<u8>,
}

impl HostTelemetry {
    /// A telemetry whose window holds `max_samples` round trips.
    ///
    /// Raised to one if it is smaller. A window of zero is a telemetry that
    /// accepts every sample and keeps none: `add_rtt` returns as though it had
    /// recorded something, every statistic answers `None` for ever, and nothing
    /// says why. [`DEFAULT_RTT_SAMPLES`] is what [`Default`] uses.
    pub fn new(max_samples: usize) -> Self {
        let max_samples = max_samples.max(MIN_RTT_SAMPLES);
        Self {
            rtt_history: VecDeque::with_capacity(max_samples),
            max_samples,
            hop_counter: None,
        }
    }

    /// How many samples the window holds.
    pub fn max_samples(&self) -> usize {
        self.max_samples
    }

    /// Resizes the window, discarding the oldest samples if it shrinks.
    ///
    /// Trimming here rather than at the next insertion means the history never
    /// holds more than the window says it does, so a caller reading
    /// [`history`](Self::history) immediately afterwards sees what it asked
    /// for.
    pub fn set_max_samples(&mut self, max_samples: usize) {
        self.max_samples = max_samples.max(MIN_RTT_SAMPLES);
        while self.rtt_history.len() > self.max_samples {
            self.rtt_history.pop_front();
        }
    }

    /// Returns a read-only view of the RTT sample history.
    pub fn history(&self) -> &VecDeque<RttSample> {
        &self.rtt_history
    }

    /// Whether this host produced a reply to a probe aimed at it alone.
    ///
    /// One such reply retires the whole segment-wide class, so this is what
    /// every statistic below branches on.
    fn has_direct(&self) -> bool {
        self.rtt_history
            .iter()
            .any(|sample| sample.source == RttSource::Direct)
    }

    /// The direct samples, oldest first.
    ///
    /// A host is described by the best evidence it produced, not by the average
    /// of good evidence and bad. One direct reply is a better account of the
    /// path than a dozen segment-wide ones, so a single direct sample retires
    /// the whole weaker class, and what remains is a set of ordinary round trips
    /// the usual statistics describe properly.
    fn direct(&self) -> impl Iterator<Item = Duration> + '_ {
        self.rtt_history
            .iter()
            .filter(|sample| sample.source == RttSource::Direct)
            .map(|sample| sample.rtt)
    }

    /// The one figure a host with nothing but segment-wide samples is described
    /// by: the smallest of them.
    ///
    /// Those are not round trips to average. Each is the path plus however long
    /// the responder held its reply back, and that hold-off is deliberate and
    /// unbounded, so the smallest is the tightest bound available on the path
    /// and every other summary of them describes the responder's manners
    /// instead.
    ///
    /// Not a refinement. A neighbour that answers one echo request promptly and
    /// a later one after a wake contributes two samples an order of magnitude
    /// apart, whose median is a figure neither reply supports. Every host
    /// answering both requests lands on that same midpoint, since they share the
    /// pair it is derived from, so a whole segment would report a latency
    /// nothing on it produced.
    fn tightest_bound(&self) -> Option<Duration> {
        self.rtt_history.iter().map(|sample| sample.rtt).min()
    }

    /// Adds a new RTT measurement at the current system time.
    ///
    /// Recorded as [`RttSource::Direct`], since a probe aimed at one address is
    /// what almost every caller sends. A segment-wide reply has to say so.
    pub fn add_rtt(&mut self, rtt: Duration) {
        self.add_rtt_at(Instant::now(), rtt);
    }

    /// [`add_rtt`](Self::add_rtt) for a reply that answers a probe the whole
    /// segment was asked.
    pub fn add_segment_wide_rtt(&mut self, rtt: Duration) {
        self.push(RttSample {
            at: Instant::now(),
            rtt,
            source: RttSource::SegmentWide,
        });
    }

    /// [`add_rtt`](Self::add_rtt) at a caller-chosen instant.
    ///
    /// Private: the only reason to record a sample under a time other than now
    /// is to reconstruct a history, and a window whose ordering callers can
    /// choose is one [`merge`](Self::merge) cannot keep in time order.
    fn add_rtt_at(&mut self, time: Instant, rtt: Duration) {
        self.push(RttSample {
            at: time,
            rtt,
            source: RttSource::Direct,
        });
    }

    fn push(&mut self, sample: RttSample) {
        if self.max_samples == 0 {
            return;
        }

        self.rtt_history.push_back(sample);

        while self.rtt_history.len() > self.max_samples {
            self.rtt_history.pop_front();
        }
    }

    /// Records the hop counter a reply from this host arrived with.
    ///
    /// See [`hop_counter`](Self::hop_counter) for what the value is and is not.
    pub fn record_hop_counter(&mut self, arrived: u8) {
        self.hop_counter = Some(arrived);
    }

    /// The hop counter the most recent reply arrived with, if any reply did.
    pub fn hop_counter(&self) -> Option<u8> {
        self.hop_counter
    }

    /// The fastest round trip in the window, and the closest this type comes to
    /// a measurement of the path alone.
    ///
    /// Taken over the [`RttSource::Direct`] samples where the window holds any.
    /// Where it holds only [`RttSource::SegmentWide`] ones, the smallest of
    /// those is the tightest bound they support and is what comes back. `None`
    /// until something has answered.
    pub fn min_rtt(&self) -> Option<Duration> {
        if self.has_direct() {
            self.direct().min()
        } else {
            self.tightest_bound()
        }
    }

    /// The slowest round trip in the window.
    ///
    /// Taken over the [`RttSource::Direct`] samples, as every statistic here is.
    /// **A host with only [`RttSource::SegmentWide`] samples has no slowest
    /// round trip**, and this answers with the same one figure the rest do: the
    /// tightest bound those samples support, which is the *smallest* of them.
    /// That is the same fallback [`min_rtt`](Self::min_rtt) describes, and it is
    /// worth restating here because the name says the opposite. A caller
    /// computing
    /// spread from `max_rtt() - min_rtt()` gets zero for such a host, which is
    /// the honest answer: there is one bound and no spread to report.
    pub fn max_rtt(&self) -> Option<Duration> {
        if self.has_direct() {
            self.direct().max()
        } else {
            self.tightest_bound()
        }
    }

    /// The typical round trip in the window.
    ///
    /// Unlike [`average_rtt`](Self::average_rtt), the median is robust against
    /// outliers: a single anomalously slow sample, a retransmit or a scheduling
    /// hiccup, barely moves it, which makes it the better single-number summary
    /// of a host's latency. For an even number of samples the two middle values
    /// are averaged.
    ///
    /// Taken over the [`RttSource::Direct`] samples. A host with only
    /// [`RttSource::SegmentWide`] ones gets the same tightest bound
    /// [`min_rtt`](Self::min_rtt) describes, because their median is a figure no
    /// reply supports and every host answering the same pair of probes would
    /// report it.
    ///
    /// `None` until something has answered.
    pub fn median_rtt(&self) -> Option<Duration> {
        if !self.has_direct() {
            return self.tightest_bound();
        }

        let mut sorted: Vec<Duration> = self.direct().collect();
        if sorted.is_empty() {
            return None;
        }
        sorted.sort_unstable();

        let mid = sorted.len() / 2;
        if sorted.len() % 2 == 1 {
            Some(sorted[mid])
        } else {
            // Average the two central samples without overflowing on the sum.
            Some(sorted[mid - 1] + (sorted[mid] - sorted[mid - 1]) / 2)
        }
    }

    /// The arithmetic mean of the window's round trips.
    ///
    /// Taken over the [`RttSource::Direct`] samples, and replaced by the same
    /// tightest bound for a host that produced none, exactly as
    /// [`median_rtt`](Self::median_rtt) is. Averaging segment-wide replies is
    /// the specific mistake this type was reshaped to prevent: it is how a
    /// router answering in 7 ms came to be reported at 37.
    pub fn average_rtt(&self) -> Option<Duration> {
        if !self.has_direct() {
            return self.tightest_bound();
        }

        // Saturating, as `median_rtt` above is careful to be and as every other
        // count in the model is. A window of samples cannot realistically reach
        // `Duration::MAX`, but the samples are a caller's to supply and a
        // library has no business panicking in its caller's process over it.
        let (sum, count) = self
            .direct()
            .fold((Duration::ZERO, 0u32), |(sum, count), rtt| {
                (sum.saturating_add(rtt), count.saturating_add(1))
            });

        (count > 0).then(|| sum / count)
    }

    /// Calculates the network jitter as the **Average Absolute Difference**
    /// between consecutive RTT samples.
    ///
    /// Jitter provides a measure of network stability. A high jitter relative
    /// to the average RTT often indicates network congestion or bufferbloat.
    pub fn jitter(&self) -> Option<Duration> {
        // Only the direct samples have consecutive pairs worth differencing:
        // the weaker class collapses to a single figure, which has no jitter.
        let mut samples = self.direct();
        let mut previous = samples.next()?;

        let mut total = Duration::ZERO;
        let mut gaps = 0u32;
        for rtt in samples {
            total = total.saturating_add(rtt.abs_diff(previous));
            previous = rtt;
            gaps = gaps.saturating_add(1);
        }

        (gaps > 0).then(|| total / gaps)
    }

    /// Folds another record's samples into this one, keeping the combined
    /// history in time order and dropping the oldest of it past the window.
    ///
    /// The window widens to the larger of the two, never narrows: two records
    /// of one host disagreeing about how much history to keep are two callers'
    /// requests, and honouring the smaller would discard samples the other
    /// asked for.
    ///
    /// Re-sorted rather than concatenated because the two records were filled
    /// by probes running at the same time, so neither one's samples are wholly
    /// older than the other's. [`jitter`](Self::jitter) reads consecutive
    /// pairs, so an out-of-order history would report a difference between
    /// samples that were never consecutive.
    pub fn merge(&mut self, mut other: HostTelemetry) {
        // Before the sample-window guard below, which returns early. A hop
        // counter is not a sample and is not bounded by the window, so folding
        // it after that check would lose it on exactly the records that keep no
        // round trips.
        //
        // Taken unconditionally, there being nothing here to order two of them
        // by. See the field, which has why that is the right answer for the way
        // the engine folds and where the case it would be wrong for is handled.
        if let Some(arrived) = other.hop_counter {
            self.hop_counter = Some(arrived);
        }

        if other.max_samples > self.max_samples {
            self.max_samples = other.max_samples;
        }

        if self.max_samples == 0 {
            return;
        }

        // Interleave and re-sort samples to maintain network timeline
        let mut combined: Vec<_> = self
            .rtt_history
            .drain(..)
            .chain(other.rtt_history.drain(..))
            .collect();

        combined.sort_by_key(|sample| sample.at);

        let start_idx = combined.len().saturating_sub(self.max_samples);
        self.rtt_history
            .extend(combined.into_iter().skip(start_idx));
    }
}

impl std::fmt::Display for HostTelemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.average_rtt() {
            Some(avg) => write!(
                f,
                "avg={:?}, jitter={:?}",
                avg,
                self.jitter().unwrap_or(Duration::ZERO)
            ),
            None => write!(f, "no telemetry"),
        }
    }
}

impl Default for HostTelemetry {
    /// A window of [`DEFAULT_RTT_SAMPLES`].
    fn default() -> Self {
        Self::new(DEFAULT_RTT_SAMPLES)
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

    /// A window of zero is a telemetry that accepts every sample and keeps
    /// none, so it is not a window this type will build.
    ///
    /// `add_rtt` returned as though it had recorded something, every statistic
    /// answered `None` for ever, and nothing said why. A caller asking for no
    /// history is asking for something this type cannot mean.
    #[test]
    fn a_window_is_never_smaller_than_one_sample() {
        let mut asked_for_none = HostTelemetry::new(0);
        assert_eq!(asked_for_none.max_samples(), MIN_RTT_SAMPLES);

        asked_for_none.add_rtt(Duration::from_millis(5));
        assert_eq!(asked_for_none.history().len(), 1, "the sample is kept");
        assert_eq!(asked_for_none.min_rtt(), Some(Duration::from_millis(5)));

        // And the same floor when a window is narrowed afterwards.
        let mut narrowed = HostTelemetry::new(4);
        narrowed.add_rtt(Duration::from_millis(1));
        narrowed.add_rtt(Duration::from_millis(2));
        narrowed.set_max_samples(0);
        assert_eq!(narrowed.max_samples(), MIN_RTT_SAMPLES);
        assert_eq!(
            narrowed.history().len(),
            1,
            "trimmed to the floor, not to nothing"
        );
    }

    /// A host with nothing but segment-wide replies is described by one figure,
    /// and every statistic answers with it.
    ///
    /// The behaviour was right and three of the four documents describing it
    /// were three revisions behind: `max_rtt` said it returned the slowest,
    /// `median_rtt` the median and `average_rtt` the mean, where all three
    /// return the smallest. This pins what they do so the sentences and the code
    /// cannot drift apart again, and `max_rtt` is the one worth having in a test
    /// at all, since a caller reading its name would predict 90.
    #[test]
    fn segment_wide_samples_alone_give_every_statistic_one_figure() {
        let mut bounded = HostTelemetry::new(10);
        bounded.add_segment_wide_rtt(Duration::from_millis(10));
        bounded.add_segment_wide_rtt(Duration::from_millis(90));

        let tightest = Some(Duration::from_millis(10));
        assert_eq!(bounded.min_rtt(), tightest);
        assert_eq!(bounded.max_rtt(), tightest, "not the slowest of the two");
        assert_eq!(bounded.median_rtt(), tightest, "not their median, 50");
        assert_eq!(bounded.average_rtt(), tightest, "not their mean, 50");

        // One direct reply retires the class, and the four part company again.
        bounded.add_rtt(Duration::from_millis(20));
        assert_eq!(bounded.min_rtt(), Some(Duration::from_millis(20)));
        assert_eq!(bounded.max_rtt(), Some(Duration::from_millis(20)));
    }

    /// Every statistic is `Option`, and an empty window is the case that makes
    /// that necessary: there is no average of nothing, and returning zero would
    /// read as an instantaneous host.
    #[test]
    fn a_window_with_no_samples_reports_no_statistics() {
        let empty = HostTelemetry::new(10);

        assert_eq!(empty.average_rtt(), None);
        assert_eq!(empty.median_rtt(), None);
        assert_eq!(empty.jitter(), None);
        assert_eq!(empty.min_rtt(), None);
        assert_eq!(empty.max_rtt(), None);
    }

    /// A directed probe's answer describes the path; a segment-wide probe's
    /// answer describes the path plus however long the responder waited before
    /// replying. Averaging them together is how a router answering ARP in 7 ms
    /// and a neighbor solicitation in 5 came to be reported at 37: its two
    /// echo replies, at 71 and 72 ms, dragged the median between them.
    #[test]
    fn a_segment_wide_sample_never_dilutes_a_direct_one() {
        let mut t = HostTelemetry::new(10);
        t.add_segment_wide_rtt(Duration::from_millis(72));
        t.add_rtt(Duration::from_millis(7));
        t.add_segment_wide_rtt(Duration::from_millis(71));
        t.add_rtt(Duration::from_millis(5));

        assert_eq!(t.median_rtt(), Some(Duration::from_millis(6)));
        assert_eq!(t.min_rtt(), Some(Duration::from_millis(5)));
        assert_eq!(t.max_rtt(), Some(Duration::from_millis(7)));
        assert_eq!(
            t.history().len(),
            4,
            "the weaker samples are ranked below, not thrown away"
        );
    }

    /// The order they arrive in must not decide the answer. A neighbour often
    /// answers the segment-wide echo before the probe addressed to it, and a
    /// rule applied when samples are recorded rather than when they are read
    /// would leave exactly those hosts describing themselves by the worse
    /// number.
    #[test]
    fn ranking_does_not_depend_on_which_reply_arrived_first() {
        let mut early = HostTelemetry::new(10);
        early.add_rtt(Duration::from_millis(5));
        early.add_segment_wide_rtt(Duration::from_millis(72));

        let mut late = HostTelemetry::new(10);
        late.add_segment_wide_rtt(Duration::from_millis(72));
        late.add_rtt(Duration::from_millis(5));

        assert_eq!(early.median_rtt(), late.median_rtt());
        assert_eq!(early.median_rtt(), Some(Duration::from_millis(5)));
    }

    /// With nothing better, the upper bound is the only latency there is, and it
    /// beats a blank: this is the neighbour that answers the all-nodes echo and
    /// no solicitation at all, which would otherwise be reported with a MAC, a
    /// vendor and an empty space where every IPv4 host has a number.
    #[test]
    fn a_host_with_only_segment_wide_samples_still_reports_latency() {
        let mut t = HostTelemetry::new(10);
        t.add_segment_wide_rtt(Duration::from_millis(72));
        t.add_segment_wide_rtt(Duration::from_millis(219));

        assert_eq!(t.min_rtt(), Some(Duration::from_millis(72)));
        assert!(t.average_rtt().is_some());
    }

    /// Upper bounds are not averaged, they are tightened.
    ///
    /// A neighbour answering one echo request promptly and a later one after a
    /// wake gives two samples an order of magnitude apart, whose median is a
    /// figure neither reply supports, and every host answering both requests
    /// lands on the same midpoint, so a whole segment reports a latency nothing
    /// on it produced.
    ///
    /// A segment-wide sample is the path plus a hold-off the responder chose,
    /// so the smallest is the only one that says anything about the path.
    #[test]
    fn segment_wide_samples_report_the_tightest_bound_not_their_midpoint() {
        let mut t = HostTelemetry::new(10);
        t.add_segment_wide_rtt(Duration::from_millis(104));
        t.add_segment_wide_rtt(Duration::from_millis(1_549));

        assert_eq!(
            t.median_rtt(),
            Some(Duration::from_millis(104)),
            "the reported figure has to be a reply the segment actually gave"
        );
        assert_eq!(t.max_rtt(), Some(Duration::from_millis(104)));
        assert_eq!(t.average_rtt(), Some(Duration::from_millis(104)));
        assert_eq!(
            t.history().len(),
            2,
            "both replies stay on record; only the summary of them narrows"
        );
    }

    /// The collapse applies to the weaker class only. Genuine round trips are
    /// still summarized as round trips, where an outlier is noise to be
    /// smoothed rather than a hold-off to be discarded.
    #[test]
    fn direct_samples_are_still_summarized_by_the_median() {
        let mut t = HostTelemetry::new(10);
        t.add_rtt(Duration::from_millis(5));
        t.add_rtt(Duration::from_millis(7));
        t.add_rtt(Duration::from_millis(200));

        assert_eq!(t.median_rtt(), Some(Duration::from_millis(7)));
        assert_eq!(t.max_rtt(), Some(Duration::from_millis(200)));
    }

    /// The mean over direct samples, which is what a report prints beside a
    /// host.
    #[test]
    fn the_average_is_the_mean_of_the_direct_samples() {
        let mut t = HostTelemetry::new(5);
        t.add_rtt(Duration::from_millis(10));
        t.add_rtt(Duration::from_millis(20));
        assert_eq!(t.average_rtt(), Some(Duration::from_millis(15)));
    }

    /// Jitter is the mean absolute difference between *consecutive* samples,
    /// not the spread of the window — it measures instability over time, which
    /// is why the history has to stay in time order.
    #[test]
    fn jitter_averages_the_gaps_between_consecutive_samples() {
        let mut t = HostTelemetry::new(5);
        t.add_rtt(Duration::from_millis(100)); // prev
        t.add_rtt(Duration::from_millis(110)); // diff 10
        t.add_rtt(Duration::from_millis(105)); // diff 5
        // (10 + 5) / 2 = 7.5ms
        assert_eq!(
            t.jitter(),
            Some(Duration::from_millis(7) + Duration::from_micros(500))
        );
    }

    /// Sorted internally, so the order samples arrived in does not change the
    /// answer.
    #[test]
    fn the_median_of_an_odd_window_is_its_middle_sample() {
        let mut t = HostTelemetry::new(5);
        // Inserted out of order to confirm the median sorts internally.
        t.add_rtt(Duration::from_millis(30));
        t.add_rtt(Duration::from_millis(10));
        t.add_rtt(Duration::from_millis(20));
        assert_eq!(t.median_rtt(), Some(Duration::from_millis(20)));
    }

    /// With no single middle sample, the two central ones are averaged — and
    /// the subtraction is written to avoid overflowing on their sum.
    #[test]
    fn the_median_of_an_even_window_averages_the_two_central_samples() {
        let mut t = HostTelemetry::new(5);
        t.add_rtt(Duration::from_millis(10));
        t.add_rtt(Duration::from_millis(20));
        t.add_rtt(Duration::from_millis(30));
        t.add_rtt(Duration::from_millis(50));
        // (20 + 30) / 2 = 25
        assert_eq!(t.median_rtt(), Some(Duration::from_millis(25)));
    }

    /// The reason a report leads with the median rather than the mean: one
    /// retransmit or scheduling hiccup should not redescribe a host's latency.
    #[test]
    fn the_median_barely_moves_for_a_single_outlier() {
        let mut t = HostTelemetry::new(5);
        t.add_rtt(Duration::from_millis(10));
        t.add_rtt(Duration::from_millis(11));
        t.add_rtt(Duration::from_millis(12));
        t.add_rtt(Duration::from_secs(5)); // outlier
        t.add_rtt(Duration::from_millis(13));
        // Median stays near the cluster despite the 5s spike.
        assert_eq!(t.median_rtt(), Some(Duration::from_millis(12)));
    }

    /// Two records of one host disagreeing about how much history to keep are
    /// two callers' requests, and honouring the smaller would discard samples
    /// the other asked for.
    #[test]
    fn a_merge_widens_the_window_to_the_larger_of_the_two() {
        let mut t1 = HostTelemetry::new(3);
        let t2 = HostTelemetry::new(10);
        t1.merge(t2);
        assert_eq!(t1.max_samples(), 10);
    }

    /// A window of zero holds nothing, and a merge of two of them must not be
    /// the way a sample gets in.
    #[test]
    fn a_window_of_zero_stays_empty_across_a_merge() {
        let mut t1 = HostTelemetry::new(0);
        let t2 = HostTelemetry::new(0);
        t1.merge(t2);
        assert_eq!(t1.rtt_history.len(), 0);
    }
}
