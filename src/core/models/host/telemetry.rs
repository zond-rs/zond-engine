// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Network Telemetry
//!
//! This module provides the [`HostTelemetry`] model for tracking network
//! performance metrics and path discovery data over time.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

/// What kind of question a round-trip sample answers, which decides whether it
/// describes the network or the responder.
///
/// Not every reply is equally good evidence of a path. A probe aimed at one
/// address is answered as fast as the host and the link allow, so the elapsed
/// time is the round trip and nothing else. A probe put to the whole segment is
/// not: implementations deliberately spread their replies to keep every
/// neighbour from answering at once, and a device asleep on wifi answers when it
/// next wakes. Measured on one segment, five neighbours answered the same
/// all-nodes echo within a millisecond of each other at 72 ms, and four more at
/// 219 ms, while the same devices answered a question addressed to them alone in
/// four to six.
///
/// So the two are not comparable and must not be pooled: mixing them moved a
/// router that answers in 5 ms to a reported 37 ms. Both are kept, and the
/// weaker one is used only where there is nothing better - for the neighbour
/// that answers the segment-wide probe and no other, an upper bound is the only
/// latency there is, and it beats a blank.
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
    pub at: Instant,
    pub rtt: Duration,
    pub source: RttSource,
}

/// Performance and discovery metrics for a specific network host.
///
/// `HostTelemetry` maintains a sliding window of Round-Trip Time (RTT)
/// measurements and performs statistical analysis (Averaging and Jitter)
/// used for network health assessment.
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

    /// The maximum number of RTT samples to maintain.
    /// If this limit is reached, adding a new sample will purge the oldest one.
    pub max_samples: usize,

    /// The Time-to-Live (TTL) value from the most recently received response.
    pub ttl: Option<u8>,

    /// The calculated network distance in hops, derived from TTL or traceroute probes.
    pub distance_hops: Option<u8>,
}

impl HostTelemetry {
    /// Creates a new `HostTelemetry` instance with a specific sample window size.
    pub fn new(max_samples: usize) -> Self {
        Self {
            rtt_history: VecDeque::with_capacity(max_samples),
            max_samples,
            ttl: None,
            distance_hops: None,
        }
    }

    /// Returns a read-only view of the RTT sample history.
    pub fn history(&self) -> &VecDeque<RttSample> {
        &self.rtt_history
    }

    /// The samples every statistic is computed from: the direct ones if this
    /// host has any, and otherwise the segment-wide ones.
    ///
    /// A host is described by the best evidence it produced, not by the average
    /// of good evidence and bad. One direct reply is a better account of the
    /// path than a dozen broadcast ones, so a single sample is enough to retire
    /// the whole weaker class.
    fn ranked(&self) -> impl Iterator<Item = Duration> + '_ {
        let has_direct = self
            .rtt_history
            .iter()
            .any(|sample| sample.source == RttSource::Direct);

        self.rtt_history
            .iter()
            .filter(move |sample| !has_direct || sample.source == RttSource::Direct)
            .map(|sample| sample.rtt)
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

    /// Adds a timed RTT measurement to the history, enforcing the sliding window cap.
    pub fn add_rtt_at(&mut self, time: Instant, rtt: Duration) {
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

    /// Returns the Last-Added Round-Trip Time (LARTT).
    pub fn lartt(&self) -> Option<Duration> {
        self.ranked().last()
    }

    /// Returns the minimum (fastest) RTT recorded in the current window.
    pub fn min_rtt(&self) -> Option<Duration> {
        self.ranked().min()
    }

    /// Returns the maximum (slowest) RTT recorded in the current window.
    pub fn max_rtt(&self) -> Option<Duration> {
        self.ranked().max()
    }

    /// Returns the median RTT across all samples in the current window.
    ///
    /// Unlike [`average_rtt`](Self::average_rtt), the median is robust against
    /// outliers: a single anomalously slow sample (a retransmit, a scheduling
    /// hiccup) barely moves it, making it a better single-number summary of a
    /// host's typical latency. For an even number of samples the two middle
    /// values are averaged.
    ///
    /// Returns `None` if no samples have been recorded yet.
    pub fn median_rtt(&self) -> Option<Duration> {
        let mut sorted: Vec<Duration> = self.ranked().collect();
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

    /// Calculates the arithmetic mean RTT from all samples in the window.
    pub fn average_rtt(&self) -> Option<Duration> {
        let count = self.ranked().count();
        if count == 0 {
            return None;
        }
        let sum: Duration = self.ranked().sum();
        Some(sum / count as u32)
    }

    /// Calculates the network jitter as the **Average Absolute Difference**
    /// between consecutive RTT samples.
    ///
    /// Jitter provides a measure of network stability. A high jitter relative
    /// to the average RTT often indicates network congestion or bufferbloat.
    pub fn jitter(&self) -> Option<Duration> {
        let ranked: Vec<Duration> = self.ranked().collect();
        if ranked.len() < 2 {
            return None;
        }

        let mut total_diff = Duration::ZERO;
        for pair in ranked.windows(2) {
            total_diff += pair[1].abs_diff(pair[0]);
        }

        Some(total_diff / (ranked.len() - 1) as u32)
    }

    /// Merges telemetry from another record, Ensuring chronological sortedness
    /// and prioritizing the newest data points.
    ///
    /// If the incoming record has a larger `max_samples` configuration, this
    /// telemetry container will upgrade its own window size to match.
    pub fn merge(&mut self, mut other: HostTelemetry) {
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

        if self.ttl.is_none() {
            self.ttl = other.ttl;
        }
        if self.distance_hops.is_none() {
            self.distance_hops = other.distance_hops;
        }
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
    fn default() -> Self {
        Self::new(10)
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

    #[test]
    fn telemetry_math_safety() {
        let t = HostTelemetry::new(10);
        assert_eq!(t.average_rtt(), None);
        assert_eq!(t.jitter(), None);
        assert_eq!(t.lartt(), None);
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
        assert_eq!(t.lartt(), Some(Duration::from_millis(5)));
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

    /// With nothing better, the upper bound is the only latency there is, and
    /// it beats a blank: this is the neighbour that answers the all-nodes echo
    /// and no solicitation at all - a TV, a console - which the run reported
    /// with a MAC, a vendor and an empty space where every IPv4 host had a
    /// number.
    #[test]
    fn a_host_with_only_segment_wide_samples_still_reports_latency() {
        let mut t = HostTelemetry::new(10);
        t.add_segment_wide_rtt(Duration::from_millis(72));
        t.add_segment_wide_rtt(Duration::from_millis(219));

        assert_eq!(t.min_rtt(), Some(Duration::from_millis(72)));
        assert_eq!(t.max_rtt(), Some(Duration::from_millis(219)));
        assert!(t.average_rtt().is_some());
        assert!(t.jitter().is_some());
    }

    #[test]
    fn telemetry_averaging_logic() {
        let mut t = HostTelemetry::new(5);
        t.add_rtt(Duration::from_millis(10));
        t.add_rtt(Duration::from_millis(20));
        assert_eq!(t.average_rtt(), Some(Duration::from_millis(15)));
    }

    #[test]
    fn jitter_calculation_consistency() {
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

    #[test]
    fn median_is_none_when_empty() {
        let t = HostTelemetry::new(5);
        assert_eq!(t.median_rtt(), None);
    }

    #[test]
    fn median_odd_count_is_the_middle_sample() {
        let mut t = HostTelemetry::new(5);
        // Inserted out of order to confirm the median sorts internally.
        t.add_rtt(Duration::from_millis(30));
        t.add_rtt(Duration::from_millis(10));
        t.add_rtt(Duration::from_millis(20));
        assert_eq!(t.median_rtt(), Some(Duration::from_millis(20)));
    }

    #[test]
    fn median_even_count_averages_the_two_central_samples() {
        let mut t = HostTelemetry::new(5);
        t.add_rtt(Duration::from_millis(10));
        t.add_rtt(Duration::from_millis(20));
        t.add_rtt(Duration::from_millis(30));
        t.add_rtt(Duration::from_millis(50));
        // (20 + 30) / 2 = 25
        assert_eq!(t.median_rtt(), Some(Duration::from_millis(25)));
    }

    #[test]
    fn median_resists_a_single_outlier() {
        let mut t = HostTelemetry::new(5);
        t.add_rtt(Duration::from_millis(10));
        t.add_rtt(Duration::from_millis(11));
        t.add_rtt(Duration::from_millis(12));
        t.add_rtt(Duration::from_secs(5)); // outlier
        t.add_rtt(Duration::from_millis(13));
        // Median stays near the cluster despite the 5s spike.
        assert_eq!(t.median_rtt(), Some(Duration::from_millis(12)));
    }

    #[test]
    fn merge_capacity_upgrade() {
        let mut t1 = HostTelemetry::new(3);
        let t2 = HostTelemetry::new(10);
        t1.merge(t2);
        assert_eq!(t1.max_samples, 10);
    }

    #[test]
    fn merge_zero_capacity_safety() {
        let mut t1 = HostTelemetry::new(0);
        let t2 = HostTelemetry::new(0);
        t1.merge(t2);
        assert_eq!(t1.rtt_history.len(), 0);
    }
}
