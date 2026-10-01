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
//! Not every reply is equally good evidence of a path, and the kinds are not pooled;
//! see [`RttSource`] and [`HostTelemetry`]. Pooling them once reported a router
//! answering in 7 ms at 37.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use crate::model::host::status::StatusProtocol;

/// How many round trips a host keeps by default.
///
/// Ten is enough for a median to mean something and short enough to describe the host
/// now. A caller wanting a longer view sets its own with [`HostTelemetry::new`].
pub const DEFAULT_RTT_SAMPLES: usize = 10;

/// The smallest window [`HostTelemetry::new`] will build.
///
/// One: a window of zero would accept every sample and keep none, and every statistic
/// would answer `None` forever.
const MIN_RTT_SAMPLES: usize = 1;

/// What kind of question a round-trip sample answers, which decides whether it
/// describes the network or the responder.
///
/// A probe aimed at one address is answered as fast as the host and link allow, so the
/// elapsed time is the round trip. A probe to the whole segment is not: implementations
/// spread their replies, and a device asleep on wifi answers when it wakes. On a
/// wireless segment that is an order of magnitude, visible as several neighbours
/// reporting the same figure to the millisecond.
///
/// So the two are never pooled. The weaker is used only where there is nothing better,
/// such as a neighbour that answers the segment-wide probe and nothing else.
///
/// The first probe to a neighbour, which waits on address resolution, is also an
/// upper bound and is ranked like a segment-wide sample.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RttSource {
    /// A reply to a probe aimed at this host alone. A round trip.
    Direct,
    /// A reply to a probe put to the whole segment. An upper bound on the round
    /// trip, inflated by however long the responder waited before answering.
    SegmentWide,
    /// A reply to the first probe sent to a neighbour, whose hardware address
    /// this host may not have held when it was sent. An upper bound on the
    /// round trip, inflated by the address resolution the probe waited on,
    /// which crosses the same path first: across a path of 1.9 s, a neighbour
    /// whose address was not held answered its first connect in 3.8 s.
    FirstToNeighbour,
}

/// One round-trip measurement: when it was taken, what it measured, and what kind of
/// question produced it.
///
/// Not [`Copy`]: [`protocol`](Self::protocol) may hold an [`Arc<str>`](std::sync::Arc).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RttSample {
    /// When the reply arrived, on the monotonic clock.
    ///
    /// Monotonic, so a clock adjustment mid-scan cannot reorder the history that
    /// [`HostTelemetry::merge`] sorts and [`jitter`](HostTelemetry::jitter) reads.
    pub at: Instant,
    /// The elapsed time between sending the probe and reading the reply.
    pub rtt: Duration,
    /// Whether that elapsed time is a round trip or an upper bound on one. See
    /// [`RttSource`].
    pub source: RttSource,
    /// Which probe drew the reply this was measured from.
    ///
    /// An ARP reply comes off the link layer and a SYN/ACK crosses the target's IP and
    /// TCP stacks, so they measure different distances. `None` where the caller did not
    /// say, as for a rebuilt host.
    pub protocol: Option<StatusProtocol>,
}

/// The median of `samples`, the two central ones averaged where there is an
/// even number of them, or `None` for none.
fn median(mut samples: Vec<Duration>) -> Option<Duration> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();

    let mid = samples.len() / 2;
    if samples.len() % 2 == 1 {
        Some(samples[mid])
    } else {
        // Average the two central samples without overflowing on the sum.
        Some(samples[mid - 1] + (samples[mid] - samples[mid - 1]) / 2)
    }
}

impl RttSample {
    /// Whether the probe that drew this sample was an address resolution,
    /// answered off the link layer rather than across the host's IP stack.
    /// See [`HostTelemetry::round_trips`].
    fn resolves_the_link(&self) -> bool {
        matches!(
            self.protocol,
            Some(StatusProtocol::Arp | StatusProtocol::Ndp)
        )
    }
}

/// A host's recent round trips, and the summaries drawn from them.
///
/// A sliding window, so a long-running monitor stays bounded and figures describe the
/// host now.
///
/// Every statistic uses the host's [`RttSource::Direct`] samples when it has any, and
/// falls back to the upper bounds only when it has none. The ranking is applied when
/// read, so a host answering a broadcast before a direct probe is still described by
/// the better sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTelemetry {
    /// The recent round-trip time measurements with confirmation timestamps.
    /// Ordered chronologically: oldest at the front, newest at the back.
    rtt_history: VecDeque<RttSample>,

    /// How many samples the window holds before the oldest is dropped.
    ///
    /// Private because lowering it must trim `rtt_history`; see
    /// [`set_max_samples`](Self::set_max_samples).
    max_samples: usize,

    /// The hop counter the most recent reply from this host arrived with.
    ///
    /// The starting value minus the distance, since every router decrements it. Kept
    /// so [`traceroute`](crate::scanner::strategy::topology::traceroute), which needs
    /// the host's distance to measure the path backwards, does not spend a probe
    /// re-learning it.
    ///
    /// The most recent, since a route that changed mid-scan is better described by the
    /// later reply.
    ///
    /// [`merge`](Self::merge) takes the other record's, because the engine always calls
    /// `stored.merge(fresh)`. A fold across documents does not come through here;
    /// [`merge`](crate::merge) picks the newest account by the documents' clocks.
    hop_counter: Option<u8>,
}

impl HostTelemetry {
    /// A telemetry whose window holds `max_samples` round trips.
    ///
    /// Raised to one if smaller. [`Default`] uses [`DEFAULT_RTT_SAMPLES`].
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
    /// Trims immediately, so [`history`](Self::history) never holds more than the
    /// window.
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
    /// One such reply retires the whole weaker class; every statistic branches on this.
    fn has_direct(&self) -> bool {
        self.rtt_history
            .iter()
            .any(|sample| sample.source == RttSource::Direct)
    }

    /// The direct samples, oldest first.
    ///
    /// One direct reply is a better account of the path than a dozen segment-wide ones,
    /// so a single direct sample retires the whole weaker class.
    fn direct(&self) -> impl Iterator<Item = Duration> + '_ {
        self.rtt_history
            .iter()
            .filter(|sample| sample.source == RttSource::Direct)
            .map(|sample| sample.rtt)
    }

    /// The round trips a wait on the path to this host is sized from, oldest
    /// first: the direct samples that crossed the host's IP stack, or where
    /// there are none every direct sample, or where there are none of those
    /// the one figure the segment-wide ones support; see
    /// [`tightest_bound`](Self::tightest_bound). Empty until something has
    /// answered.
    ///
    /// An address resolution (ARP or a neighbour solicitation) goes to every station
    /// on the link, which a wireless access point holds for a dozing station until its
    /// next delivery beacon, a tenth of a second or more apart. On one segment
    /// neighbours answered ARP in 80 to 250 ms and SYNs in 10 to 20; pooled, each wait
    /// of a TLS conversation allowed about 800 ms rather than 50. So resolutions size
    /// waits only for a host that answered nothing else. A sample with no named probe
    /// counts as having crossed the IP stack.
    pub(crate) fn round_trips(&self) -> Vec<Duration> {
        if !self.has_direct() {
            return self.tightest_bound().into_iter().collect();
        }
        let crossed: Vec<Duration> = self
            .rtt_history
            .iter()
            .filter(|sample| sample.source == RttSource::Direct && !sample.resolves_the_link())
            .map(|sample| sample.rtt)
            .collect();
        if crossed.is_empty() {
            self.direct().collect()
        } else {
            crossed
        }
    }

    /// The one figure a host with nothing but segment-wide samples is described
    /// by: the smallest of them.
    ///
    /// Each is the path plus a deliberate, unbounded hold-off, so the smallest is the
    /// tightest bound on the path. A median of a prompt answer and one after a wake
    /// would be a figure neither supports, and every host answering both requests
    /// would report the same midpoint.
    fn tightest_bound(&self) -> Option<Duration> {
        self.rtt_history.iter().map(|sample| sample.rtt).min()
    }

    /// Adds a new RTT measurement at the current system time.
    ///
    /// Recorded as [`RttSource::Direct`]; a segment-wide reply has its own method.
    pub fn add_rtt(&mut self, rtt: Duration) {
        self.add_rtt_at(Instant::now(), rtt, None);
    }

    /// [`add_rtt`](Self::add_rtt) for a caller that knows which probe drew the
    /// reply.
    pub fn add_rtt_from(&mut self, rtt: Duration, protocol: StatusProtocol) {
        self.add_rtt_at(Instant::now(), rtt, Some(protocol));
    }

    /// Adds a round trip timed from the first probe sent to a neighbour,
    /// which may have waited on the neighbour's address resolution. See
    /// [`RttSource::FirstToNeighbour`].
    pub fn add_first_to_neighbour_rtt_from(&mut self, rtt: Duration, protocol: StatusProtocol) {
        self.push(RttSample {
            at: Instant::now(),
            rtt,
            source: RttSource::FirstToNeighbour,
            protocol: Some(protocol),
        });
    }

    /// [`add_rtt`](Self::add_rtt) for a reply that answers a probe the whole
    /// segment was asked.
    pub fn add_segment_wide_rtt(&mut self, rtt: Duration) {
        self.push(RttSample {
            at: Instant::now(),
            rtt,
            source: RttSource::SegmentWide,
            protocol: None,
        });
    }

    /// [`add_segment_wide_rtt`](Self::add_segment_wide_rtt) for a caller that
    /// knows which probe drew the reply.
    pub fn add_segment_wide_rtt_from(&mut self, rtt: Duration, protocol: StatusProtocol) {
        self.push(RttSample {
            at: Instant::now(),
            rtt,
            source: RttSource::SegmentWide,
            protocol: Some(protocol),
        });
    }

    /// Adds a sample read back from a record, of the kind and from the probe
    /// the record names, stamped now.
    ///
    /// An [`Instant`] from another process means nothing here, and now preserves the
    /// order: a record lists samples oldest first, and a scan reads its journal before
    /// sending anything, so restored samples precede new ones. [`merge`](Self::merge)
    /// keeps equally stamped samples in order. The spacing is lost; nothing reads it.
    pub(crate) fn restore_rtt(
        &mut self,
        rtt: Duration,
        source: RttSource,
        protocol: Option<StatusProtocol>,
    ) {
        self.push(RttSample {
            at: Instant::now(),
            rtt,
            source,
            protocol,
        });
    }

    /// [`add_rtt`](Self::add_rtt) at a caller-chosen instant.
    ///
    /// Private, so callers cannot break the time order [`merge`](Self::merge) keeps.
    fn add_rtt_at(&mut self, time: Instant, rtt: Duration, protocol: Option<StatusProtocol>) {
        self.push(RttSample {
            at: time,
            rtt,
            source: RttSource::Direct,
            protocol,
        });
    }

    /// The probe every sample here was drawn from, where they agree on one.
    ///
    /// `None` where no sample says, or where two disagree (ARP and an echo measure
    /// different distances).
    #[must_use]
    pub fn rtt_protocol(&self) -> Option<StatusProtocol> {
        let mut named = self.rtt_history.iter().filter_map(|s| s.protocol.clone());
        let first = named.next()?;

        named.all(|other| other == first).then_some(first)
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
    /// See [`hop_counter`](Self::hop_counter).
    pub fn record_hop_counter(&mut self, arrived: u8) {
        self.hop_counter = Some(arrived);
    }

    /// The hop counter the most recent reply arrived with, if any reply did.
    pub fn hop_counter(&self) -> Option<u8> {
        self.hop_counter
    }

    /// The fastest round trip in the window, the closest thing to a measurement of the
    /// path alone.
    ///
    /// Over the [`RttSource::Direct`] samples where there are any; otherwise the
    /// smallest upper bound. `None` until something has answered.
    pub fn min_rtt(&self) -> Option<Duration> {
        if self.has_direct() {
            self.direct().min()
        } else {
            self.tightest_bound()
        }
    }

    /// The slowest round trip in the window.
    ///
    /// Over the [`RttSource::Direct`] samples. A host with only upper bounds gets the
    /// same fallback as [`min_rtt`](Self::min_rtt): the *smallest* bound, despite the
    /// name. `max_rtt() - min_rtt()` is then zero, since there is no spread to report.
    pub fn max_rtt(&self) -> Option<Duration> {
        if self.has_direct() {
            self.direct().max()
        } else {
            self.tightest_bound()
        }
    }

    /// The typical round trip in the window.
    ///
    /// Robust against outliers such as a retransmit or a scheduling hiccup, so the best
    /// single-number summary. For an even count the two middle values are averaged.
    ///
    /// Over the [`RttSource::Direct`] samples; a host with only upper bounds gets the
    /// same fallback as [`min_rtt`](Self::min_rtt).
    ///
    /// `None` until something has answered.
    pub fn median_rtt(&self) -> Option<Duration> {
        if !self.has_direct() {
            return self.tightest_bound();
        }
        median(self.direct().collect())
    }

    /// The median of [`round_trips`](Self::round_trips): the figure a scan
    /// times its first probes to this host from, before it has measured the
    /// host for itself.
    pub(crate) fn median_round_trip(&self) -> Option<Duration> {
        median(self.round_trips())
    }

    /// Whether [`round_trips`](Self::round_trips) are the answers to address
    /// resolutions, the host having answered nothing across its IP stack.
    pub(crate) fn round_trips_resolve_the_link(&self) -> bool {
        let mut direct = self
            .rtt_history
            .iter()
            .filter(|sample| sample.source == RttSource::Direct)
            .peekable();
        direct.peek().is_some() && direct.all(RttSample::resolves_the_link)
    }

    /// The arithmetic mean of the window's round trips.
    ///
    /// Over the [`RttSource::Direct`] samples, with the same fallback as
    /// [`median_rtt`](Self::median_rtt).
    pub fn average_rtt(&self) -> Option<Duration> {
        if !self.has_direct() {
            return self.tightest_bound();
        }

        // Saturating: the samples are caller-supplied and must not cause a panic.
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
        // The weaker class collapses to one figure, which has no jitter.
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

    /// Takes `later`'s round trips in place of these, where it holds any,
    /// keeping the wider of the two windows.
    ///
    /// For a later account of the same window; see
    /// [`Host::merge_later_account`](crate::model::host::Host::merge_later_account).
    /// The hop counter is left as [`merge`](Self::merge) left it.
    pub(crate) fn take_window(&mut self, later: HostTelemetry) {
        if later.rtt_history.is_empty() {
            return;
        }
        self.max_samples = self.max_samples.max(later.max_samples);
        self.rtt_history = later.rtt_history;
        while self.rtt_history.len() > self.max_samples {
            self.rtt_history.pop_front();
        }
    }

    /// Folds another record's samples into this one, keeping the combined
    /// history in time order and dropping the oldest of it past the window.
    ///
    /// The window widens to the larger of the two.
    ///
    /// Re-sorted, since both records were filled by concurrent probes and
    /// [`jitter`](Self::jitter) reads consecutive pairs.
    pub fn merge(&mut self, mut other: HostTelemetry) {
        // Before the early return below, which records with no round trips take.
        // Taken unconditionally; see the field.
        if let Some(arrived) = other.hop_counter {
            self.hop_counter = Some(arrived);
        }

        if other.max_samples > self.max_samples {
            self.max_samples = other.max_samples;
        }

        if self.max_samples == 0 {
            return;
        }

        // Interleave and re-sort by time.
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

    /// The figures are named by the probe that measured them.
    #[test]
    fn round_trips_are_named_by_the_probe_that_measured_them() {
        let mut telemetry = HostTelemetry::default();
        telemetry.add_rtt_from(Duration::from_micros(90), StatusProtocol::Arp);
        telemetry.add_rtt_from(Duration::from_micros(110), StatusProtocol::Arp);

        assert_eq!(telemetry.rtt_protocol(), Some(StatusProtocol::Arp));
    }

    /// Two different probes leave the figures unnamed.
    #[test]
    fn round_trips_from_two_probes_are_named_by_neither() {
        let mut telemetry = HostTelemetry::default();
        telemetry.add_rtt_from(Duration::from_micros(90), StatusProtocol::Arp);
        telemetry.add_rtt_from(Duration::from_micros(220), StatusProtocol::TcpSyn);

        assert_eq!(telemetry.rtt_protocol(), None);
    }

    /// **A wait on the path is sized from the host's answers across its IP
    /// stack once it has any, not from the address resolution before them.**
    ///
    /// One segment's hosts answered ARP in 80 to 250 ms and SYNs in 10 to 20.
    #[test]
    fn a_wait_is_sized_from_answers_across_the_ip_stack_rather_than_the_resolution() {
        let mut telemetry = HostTelemetry::default();
        telemetry.add_rtt_from(Duration::from_millis(246), StatusProtocol::Arp);
        telemetry.add_rtt_from(Duration::from_millis(18), StatusProtocol::TcpSyn);
        telemetry.add_rtt_from(Duration::from_millis(80), StatusProtocol::Ndp);
        telemetry.add_rtt(Duration::from_millis(20));

        assert_eq!(
            telemetry.round_trips(),
            [18, 20].map(Duration::from_millis),
            "the SYN's, and the one no probe was named for"
        );
    }

    /// A host that answered only the resolution is waited on by it.
    #[test]
    fn a_host_that_answered_only_the_resolution_is_sized_from_it() {
        let mut telemetry = HostTelemetry::default();
        telemetry.add_segment_wide_rtt_from(Duration::from_millis(5), StatusProtocol::IcmpEcho);
        telemetry.add_rtt_from(Duration::from_millis(246), StatusProtocol::Arp);
        telemetry.add_rtt_from(Duration::from_millis(90), StatusProtocol::Arp);

        assert_eq!(
            telemetry.round_trips(),
            [246, 90].map(Duration::from_millis),
            "a direct answer still outranks the segment-wide bound"
        );
    }

    /// A caller that did not name the probe leaves the figures unnamed.
    #[test]
    fn round_trips_nobody_named_stay_unnamed() {
        let mut telemetry = HostTelemetry::default();
        telemetry.add_rtt(Duration::from_micros(90));

        assert_eq!(telemetry.rtt_protocol(), None);
    }
    use super::*;

    /// A window of zero is raised to one.
    #[test]
    fn a_window_is_never_smaller_than_one_sample() {
        let mut asked_for_none = HostTelemetry::new(0);
        assert_eq!(asked_for_none.max_samples(), MIN_RTT_SAMPLES);

        asked_for_none.add_rtt(Duration::from_millis(5));
        assert_eq!(asked_for_none.history().len(), 1, "the sample is kept");
        assert_eq!(asked_for_none.min_rtt(), Some(Duration::from_millis(5)));

        // The same floor when narrowed afterwards.
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
    /// Including `max_rtt`, whose name would suggest 90.
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

        // One direct reply retires the class.
        bounded.add_rtt(Duration::from_millis(20));
        assert_eq!(bounded.min_rtt(), Some(Duration::from_millis(20)));
        assert_eq!(bounded.max_rtt(), Some(Duration::from_millis(20)));
    }

    /// An empty window answers `None` everywhere; zero would read as an instantaneous
    /// host.
    #[test]
    fn a_window_with_no_samples_reports_no_statistics() {
        let empty = HostTelemetry::new(10);

        assert_eq!(empty.average_rtt(), None);
        assert_eq!(empty.median_rtt(), None);
        assert_eq!(empty.jitter(), None);
        assert_eq!(empty.min_rtt(), None);
        assert_eq!(empty.max_rtt(), None);
    }

    /// A router answering ARP in 7 ms and a neighbour solicitation in 5 is not reported
    /// at 37 because of two segment-wide echo replies at 71 and 72 ms.
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

    /// Arrival order does not decide the answer.
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

    /// With nothing better, the upper bound is reported.
    #[test]
    fn a_host_with_only_segment_wide_samples_still_reports_latency() {
        let mut t = HostTelemetry::new(10);
        t.add_segment_wide_rtt(Duration::from_millis(72));
        t.add_segment_wide_rtt(Duration::from_millis(219));

        assert_eq!(t.min_rtt(), Some(Duration::from_millis(72)));
        assert!(t.average_rtt().is_some());
    }

    /// Upper bounds are tightened to the smallest, not averaged.
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

    /// Direct round trips are still summarized normally.
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

    /// Jitter is the mean absolute difference between consecutive samples.
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

    /// The median does not depend on arrival order.
    #[test]
    fn the_median_of_an_odd_window_is_its_middle_sample() {
        let mut t = HostTelemetry::new(5);
        // Inserted out of order.
        t.add_rtt(Duration::from_millis(30));
        t.add_rtt(Duration::from_millis(10));
        t.add_rtt(Duration::from_millis(20));
        assert_eq!(t.median_rtt(), Some(Duration::from_millis(20)));
    }

    /// With an even count the two central samples are averaged.
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

    /// One outlier barely moves the median.
    #[test]
    fn the_median_barely_moves_for_a_single_outlier() {
        let mut t = HostTelemetry::new(5);
        t.add_rtt(Duration::from_millis(10));
        t.add_rtt(Duration::from_millis(11));
        t.add_rtt(Duration::from_millis(12));
        t.add_rtt(Duration::from_secs(5)); // outlier
        t.add_rtt(Duration::from_millis(13));
        // The median stays near the cluster.
        assert_eq!(t.median_rtt(), Some(Duration::from_millis(12)));
    }

    /// A merge keeps the wider window.
    #[test]
    fn a_merge_widens_the_window_to_the_larger_of_the_two() {
        let mut t1 = HostTelemetry::new(3);
        let t2 = HostTelemetry::new(10);
        t1.merge(t2);
        assert_eq!(t1.max_samples(), 10);
    }

    /// Merging two empty telemetries adds no samples.
    #[test]
    fn a_window_of_zero_stays_empty_across_a_merge() {
        let mut t1 = HostTelemetry::new(0);
        let t2 = HostTelemetry::new(0);
        t1.merge(t2);
        assert_eq!(t1.rtt_history.len(), 0);
    }
}
