// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Probe Auditing
//!
//! What a raw scanner observed about its own run, kept so a disappointing result
//! can be attributed rather than guessed at.
//!
//! A sweep that finds 96 of 256 hosts on one run and 187 on the next has failed
//! in one of three distinguishable ways, and the fix for each is different:
//!
//! - the probes or the replies were **lost**, so the scanner never had the
//!   information — the case retransmission exists for;
//! - the replies arrived but the scan had already **stopped**, so the deadline
//!   is wrong rather than the network;
//! - the replies arrived and were **not recognized**, so correlation is wrong
//!   and no amount of extra time or extra packets would help.
//!
//! The counters here separate those. Sends and captured segments bound the
//! first, the stop reason and the reply-latency histogram bound the second, and
//! the off-target and no-RTT counts bound the third. All of it is per scanner
//! run, held by the scanner itself, and reported once when the loop exits.
//!
//! One of those bounds cannot be measured from inside the scanner. A reply the
//! kernel discards because the capture buffer was full never reaches any counter
//! here, so loss on the receive path and loss on the network read identically —
//! both are silence. [`CaptureCounts`] is reported alongside for that reason: it
//! is the only place the difference is visible.
//!
//! This is instrumentation, not telemetry: nothing here reaches the host store
//! or the event stream, and none of it changes what a scan does.

use std::time::{Duration, Instant};

use crate::network::capture::CaptureCounts;

/// Upper bounds, in milliseconds, of the reply-latency histogram buckets. A
/// final bucket catches everything slower than the last bound.
///
/// Spaced roughly logarithmically because the question being asked spans three
/// orders of magnitude: a same-segment reply lands under a millisecond, a
/// healthy internet round trip in the tens, and a reply that arrived just before
/// the deadline in the hundreds. A linear scale would put every interesting
/// answer in one bucket.
const BUCKET_BOUNDS_MS: [u64; 9] = [1, 2, 5, 10, 25, 50, 100, 250, 1_000];

/// Why a scanner's receive loop stopped.
///
/// This is the single most informative field in an audit: a run that ends in
/// [`AllResponded`](StopReason::AllResponded) was not cut short by anything, and
/// one that ends in [`DeadlineExpired`](StopReason::DeadlineExpired) with
/// replies still arriving near the end almost certainly was.
///
/// There is deliberately no "still running" variant. A scan loop yields its
/// reason as the value it breaks with, so every exit path has to name one and
/// the audit cannot report a reason the code never took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopReason {
    /// The caller aborted the scan through the scan handle.
    Aborted,
    /// Every target answered.
    AllResponded,
    /// Nothing is left outstanding: every target either answered or was asked
    /// as many times as the retry budget allows. Like
    /// [`AllResponded`](StopReason::AllResponded) this is a scan that finished
    /// rather than one that ran out of time, and waiting longer could not have
    /// changed what it found.
    AttemptsSpent,
    /// The adaptive deadline expired: either the hard budget ran out or the
    /// silence tolerance did.
    DeadlineExpired,
    /// The capture stream closed underneath the scanner.
    StreamClosed,
}

/// Per-run counters for one raw scanner.
///
/// Owned by the scanner and mutated from its own loop, so the fields are plain
/// integers rather than atomics.
pub(crate) struct ProbeAudit {
    started: Instant,

    /// Probes the scanner tried to put on the wire.
    pub(crate) sends_attempted: u64,
    /// Of those, ones the sender refused. A non-zero count means the shortfall
    /// starts at home, before the network is implicated at all.
    pub(crate) sends_failed: u64,

    /// Segments the capture handed up, before any of the scanner's own checks.
    /// Bounded above by what the kernel BPF filter admitted.
    pub(crate) segments_seen: u64,
    /// Segments whose source is not in this scan's target set. Expected to be
    /// small; a large count means the filter is admitting other traffic.
    pub(crate) segments_off_target: u64,
    /// In-set replies that answered no outstanding probe, so they proved the
    /// host alive but yielded no round-trip sample. Duplicates and
    /// retransmissions land here, and so does a correlation bug.
    pub(crate) replies_without_rtt: u64,

    /// Targets credited as alive for the first time. This is the number the run
    /// is judged on.
    pub(crate) hosts_found: u64,

    first_reply: Option<Duration>,
    last_reply: Option<Duration>,
    buckets: [u64; BUCKET_BOUNDS_MS.len() + 1],
}

impl ProbeAudit {
    /// Starts an audit, with the clock running from now.
    pub(crate) fn new() -> Self {
        Self {
            started: Instant::now(),
            sends_attempted: 0,
            sends_failed: 0,
            segments_seen: 0,
            segments_off_target: 0,
            replies_without_rtt: 0,
            hosts_found: 0,
            first_reply: None,
            last_reply: None,
            buckets: [0; BUCKET_BOUNDS_MS.len() + 1],
        }
    }

    /// Records one send attempt and whether it reached the wire.
    pub(crate) fn record_send(&mut self, sent: bool) {
        self.sends_attempted += 1;
        if !sent {
            self.sends_failed += 1;
        }
    }

    /// Records one segment lifted off the capture, before any filtering the
    /// scanner does itself.
    pub(crate) fn record_segment(&mut self) {
        self.segments_seen += 1;
    }

    /// Records a segment from an address outside this scan's target set.
    pub(crate) fn record_off_target(&mut self) {
        self.segments_off_target += 1;
    }

    /// Records an in-set reply that matched no outstanding probe.
    pub(crate) fn record_reply_without_rtt(&mut self) {
        self.replies_without_rtt += 1;
    }

    /// Records a target credited as alive for the first time, timestamped
    /// against the start of the run.
    pub(crate) fn record_host_found(&mut self) {
        self.hosts_found += 1;

        let offset = self.started.elapsed();
        self.first_reply.get_or_insert(offset);
        self.last_reply = Some(offset);
        self.buckets[bucket_of(offset)] += 1;
    }

    /// How long the run has been going.
    pub(crate) fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Emits the run's summary as a single log line.
    ///
    /// One line rather than several because the fields are only meaningful
    /// against each other: `sent` versus `captured` says whether packets went
    /// missing, `captured` versus `kernel` says which side of the capture they
    /// went missing on, and the stop reason versus `last` says whether the scan
    /// outlived its own answers.
    ///
    /// `capture` is what the scanner's own transport reports, or `None` where
    /// there is no capture to ask - a scan driven by a synthetic receive stream
    /// has no kernel buffer, and the segment is omitted rather than rendered as
    /// a clean one.
    pub(crate) fn report(
        &self,
        scanner: &str,
        targets: u128,
        reason: StopReason,
        capture: Option<CaptureCounts>,
    ) {
        crate::info!(
            verbosity = 1,
            "audit[{scanner}] {found}/{targets} hosts in {elapsed:.0?}, stopped: {reason:?} \
             | sent {sent} (failed {failed}) \
             | captured {seen} (off-target {off}, no-rtt {no_rtt}){kernel} \
             | first {first}, last {last} \
             | latency {histogram}",
            found = self.hosts_found,
            elapsed = self.elapsed(),
            sent = self.sends_attempted,
            failed = self.sends_failed,
            seen = self.segments_seen,
            off = self.segments_off_target,
            no_rtt = self.replies_without_rtt,
            kernel = format_capture(capture),
            first = format_offset(self.first_reply),
            last = format_offset(self.last_reply),
            histogram = self.histogram(),
        );
    }

    /// The reply-latency histogram, empty buckets omitted.
    fn histogram(&self) -> String {
        let mut out = String::new();
        for (index, count) in self.buckets.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            if !out.is_empty() {
                out.push(' ');
            }
            match BUCKET_BOUNDS_MS.get(index) {
                Some(bound) => out.push_str(&format!("<={bound}ms:{count}")),
                None => out.push_str(&format!(">{}ms:{count}", BUCKET_BOUNDS_MS[index - 1])),
            }
        }

        if out.is_empty() {
            out.push_str("(none)");
        }
        out
    }
}

/// The histogram bucket `offset` belongs in: the first whose bound it does not
/// exceed, or the overflow bucket.
fn bucket_of(offset: Duration) -> usize {
    let ms = offset.as_millis() as u64;
    BUCKET_BOUNDS_MS
        .iter()
        .position(|bound| ms <= *bound)
        .unwrap_or(BUCKET_BOUNDS_MS.len())
}

fn format_offset(offset: Option<Duration>) -> String {
    match offset {
        Some(offset) => format!("{:.0?}", offset),
        None => "-".to_string(),
    }
}

/// The kernel-capture segment of the audit line, empty where there was no
/// capture to report on.
///
/// `received` is deliberately kept next to `dropped` rather than reported
/// alone. The filter admits traffic this scan did not cause, so the count is
/// not the scan's replies; what it gives is the scale the drops happened at,
/// and a drop count without one says nothing about how close the receive path
/// came to keeping up.
fn format_capture(capture: Option<CaptureCounts>) -> String {
    match capture {
        Some(counts) => format!(
            " | kernel {received} (dropped {dropped}, if-dropped {if_dropped})",
            received = counts.received,
            dropped = counts.dropped,
            if_dropped = counts.if_dropped,
        ),
        None => String::new(),
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
    fn offsets_land_in_the_bucket_named_by_their_bound() {
        assert_eq!(bucket_of(Duration::from_micros(200)), 0); // <=1ms
        assert_eq!(bucket_of(Duration::from_millis(1)), 0);
        assert_eq!(bucket_of(Duration::from_millis(2)), 1);
        assert_eq!(bucket_of(Duration::from_millis(3)), 2); // <=5ms
        assert_eq!(bucket_of(Duration::from_millis(1_000)), 8);
    }

    /// Anything slower than the last bound has to land somewhere, and it must
    /// be the overflow bucket rather than a panic on an out-of-range index.
    #[test]
    fn anything_beyond_the_last_bound_overflows_into_the_final_bucket() {
        assert_eq!(bucket_of(Duration::from_secs(30)), BUCKET_BOUNDS_MS.len());

        let mut audit = ProbeAudit::new();
        audit.buckets[BUCKET_BOUNDS_MS.len()] = 2;
        assert_eq!(audit.histogram(), ">1000ms:2");
    }

    #[test]
    fn an_empty_histogram_says_so_rather_than_rendering_blank() {
        assert_eq!(ProbeAudit::new().histogram(), "(none)");
    }

    #[test]
    fn a_found_host_sets_both_ends_of_the_reply_window() {
        let mut audit = ProbeAudit::new();
        assert!(audit.first_reply.is_none());

        audit.record_host_found();
        audit.record_host_found();

        assert_eq!(audit.hosts_found, 2);
        assert!(audit.first_reply.is_some());
        assert!(audit.last_reply >= audit.first_reply);
    }

    /// A transport with no capture behind it has no kernel buffer, and printing
    /// zeroes for one would read as a receive path measured and found clean.
    #[test]
    fn an_absent_capture_contributes_nothing_to_the_line() {
        assert_eq!(format_capture(None), "");
    }

    #[test]
    fn capture_counts_are_reported_next_to_the_scale_they_happened_at() {
        let counts = CaptureCounts {
            received: 881,
            dropped: 17,
            if_dropped: 0,
        };

        assert_eq!(
            format_capture(Some(counts)),
            " | kernel 881 (dropped 17, if-dropped 0)"
        );
    }

    #[test]
    fn a_failed_send_counts_as_attempted_too() {
        let mut audit = ProbeAudit::new();
        audit.record_send(true);
        audit.record_send(false);

        assert_eq!(audit.sends_attempted, 2);
        assert_eq!(audit.sends_failed, 1);
    }
}
