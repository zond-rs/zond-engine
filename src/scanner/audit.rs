// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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

use crate::model::capture::CaptureCounts;
use crate::scanner::report::{ATTEMPTS_COUNTED, BUCKET_BOUNDS_MS, ProbeStats, StopReason};
use crate::scanner::session::ScannerKind;

/// Per-run counters for one raw scanner.
///
/// Owned by the scanner and mutated from its own loop, so the fields are plain
/// integers rather than atomics.
pub struct ProbeAudit {
    started: Instant,

    /// Probes the scanner tried to put on the wire.
    pub(crate) sends_attempted: u64,
    /// Of those, ones the sender refused. A non-zero count means the shortfall
    /// starts at home, before the network is implicated at all.
    pub(crate) sends_failed: u64,

    /// Segments the capture handed up, before any of the scanner's own checks.
    /// Bounded above by what the kernel BPF filter admitted.
    pub(crate) segments_seen: u64,
    /// Segments whose source is not in this scan's target set.
    ///
    /// Small on an IPv4 scan, where the kernel filter admits only the two
    /// segments a probe can draw. Not necessarily small once IPv6 is in play:
    /// libpcap cannot narrow TCP by flags over IPv6, so the SYN transport
    /// admits every IPv6 TCP segment crossing any captured interface and this
    /// is where the host's own connections land. Read it against
    /// `segments_seen` as the receive path's load, not as a fault.
    pub(crate) segments_off_target: u64,
    /// In-set replies that answered no outstanding probe, so they proved the
    /// host alive but yielded no round-trip sample. Duplicates and
    /// retransmissions land here, and so does a correlation bug.
    pub(crate) replies_without_rtt: u64,

    /// Targets a reply resolved, counted once each — a host for a discovery
    /// sweep, an `(address, port)` probe for a port scan. The number the run is
    /// judged on, and the numerator to the `targets` this run was given.
    pub(crate) hosts_found: u64,

    /// Found hosts by the attempt whose reply revealed them, `[0]` being the
    /// first send. The last slot absorbs anything beyond
    /// [`ATTEMPTS_COUNTED`].
    ///
    /// This is what says whether retransmission is earning its traffic. A host
    /// found on its first attempt needed only for the scan to still be
    /// listening; one found on its third needed the packet to be sent again.
    /// The two call for opposite fixes - patience against repetition - and the
    /// host count alone cannot tell them apart.
    answered_on: [u64; ATTEMPTS_COUNTED],
    /// Found hosts whose reply named no attempt: it arrived after the probe was
    /// written off, or carried nothing to match against.
    answered_unattributed: u64,

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
            answered_on: [0; ATTEMPTS_COUNTED],
            answered_unattributed: 0,
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

    /// Records a target resolved by a reply, timestamped against the start of
    /// the run and attributed to the attempt that answered it where the reply
    /// named one.
    ///
    /// Called once per target, on the reply that first resolved it. A duplicate
    /// or a late arrival for the same target is
    /// [`record_reply_without_rtt`](Self::record_reply_without_rtt), not this.
    pub(crate) fn record_host_found(&mut self, answered_attempt: Option<u8>) {
        self.hosts_found += 1;

        match answered_attempt {
            Some(attempt) => {
                // Attempts are numbered from one; a zero would mean the ledger
                // credited a send that never happened, so it is folded into the
                // first rather than indexing out of the array's meaning.
                let index = usize::from(attempt.saturating_sub(1));
                self.answered_on[index.min(ATTEMPTS_COUNTED - 1)] += 1;
            }
            None => self.answered_unattributed += 1,
        }

        let offset = self.started.elapsed();
        self.first_reply.get_or_insert(offset);
        self.last_reply = Some(offset);
        self.buckets[bucket_of(offset)] += 1;
    }

    /// How long the run has been going.
    pub(crate) fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// The exported view of this run, for the scan's report.
    ///
    /// Separate from [`report`](Self::report) rather than derived from it: the
    /// log line is a rendering tuned for a human reading one scan, while this is
    /// the record something else will compute against. Tying the two together
    /// would mean a change to either format silently altering the other.
    pub(crate) fn stats(
        &self,
        scanner: ScannerKind,
        targets: u128,
        reason: StopReason,
        capture: Option<CaptureCounts>,
    ) -> ProbeStats {
        ProbeStats {
            scanner,
            targets,
            stop_reason: reason,
            elapsed: self.elapsed(),
            sends_attempted: self.sends_attempted,
            sends_failed: self.sends_failed,
            segments_seen: self.segments_seen,
            segments_off_target: self.segments_off_target,
            replies_without_rtt: self.replies_without_rtt,
            hosts_found: self.hosts_found,
            answered_on: self.answered_on,
            answered_unattributed: self.answered_unattributed,
            first_reply: self.first_reply,
            last_reply: self.last_reply,
            found_at: self.buckets,
            capture,
        }
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
             | found on {attempts} \
             | first {first}, last {last} \
             | found-at {histogram}",
            found = self.hosts_found,
            elapsed = self.elapsed(),
            sent = self.sends_attempted,
            failed = self.sends_failed,
            seen = self.segments_seen,
            off = self.segments_off_target,
            no_rtt = self.replies_without_rtt,
            kernel = format_capture(capture),
            attempts = self.attempt_distribution(),
            first = format_offset(self.first_reply),
            last = format_offset(self.last_reply),
            histogram = self.histogram(),
        );
    }

    /// Found hosts by the attempt that revealed them, empty attempts omitted.
    ///
    /// Rendered as `attempt:count` so the shape is readable at a glance:
    /// everything on `1` means the retries this run sent bought nothing, and a
    /// tail on `2` and `3` is retransmission doing the work it exists for.
    fn attempt_distribution(&self) -> String {
        let mut out = String::new();
        for (index, count) in self.answered_on.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            if !out.is_empty() {
                out.push(' ');
            }
            if index == ATTEMPTS_COUNTED - 1 {
                out.push_str(&format!("{}+:{count}", ATTEMPTS_COUNTED));
            } else {
                out.push_str(&format!("{}:{count}", index + 1));
            }
        }

        if self.answered_unattributed > 0 {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(&format!("unattributed:{}", self.answered_unattributed));
        }

        if out.is_empty() {
            out.push_str("(none)");
        }
        out
    }

    /// The discovery-time histogram, empty buckets omitted.
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

        audit.record_host_found(Some(1));
        audit.record_host_found(Some(2));

        assert_eq!(audit.hosts_found, 2);
        assert!(audit.first_reply.is_some());
        assert!(audit.last_reply >= audit.first_reply);
    }

    /// The distribution the retry policy is judged on: everything on the first
    /// attempt means the retries a run sent bought nothing.
    #[test]
    fn hosts_are_counted_against_the_attempt_that_revealed_them() {
        let mut audit = ProbeAudit::new();
        audit.record_host_found(Some(1));
        audit.record_host_found(Some(1));
        audit.record_host_found(Some(3));
        audit.record_host_found(None);

        assert_eq!(audit.attempt_distribution(), "1:2 3:1 unattributed:1");
    }

    /// A budget raised past what the line reports still has to land somewhere,
    /// and it must be the final slot rather than an index out of range.
    #[test]
    fn an_attempt_beyond_the_reported_range_falls_into_the_last_slot() {
        let mut audit = ProbeAudit::new();
        audit.record_host_found(Some(ATTEMPTS_COUNTED as u8));
        audit.record_host_found(Some(200));

        assert_eq!(audit.attempt_distribution(), "6+:2");
    }

    #[test]
    fn a_run_that_found_nothing_says_so_rather_than_rendering_blank() {
        assert_eq!(ProbeAudit::new().attempt_distribution(), "(none)");
    }

    /// The exported stats and the log line are two renderings of one run, so
    /// every counter has to survive the crossing intact. A field dropped here
    /// would leave the log telling the truth and the report not.
    #[test]
    fn exported_stats_carry_every_counter_the_run_recorded() {
        let mut audit = ProbeAudit::new();
        audit.record_send(true);
        audit.record_send(true);
        audit.record_send(false);
        audit.record_segment();
        audit.record_segment();
        audit.record_off_target();
        audit.record_reply_without_rtt();
        audit.record_host_found(Some(1));
        audit.record_host_found(Some(3));
        audit.record_host_found(None);

        let capture = CaptureCounts {
            received: 40,
            dropped: 2,
            if_dropped: 0,
        };
        let stats = audit.stats(
            ScannerKind::Routed,
            256,
            StopReason::DeadlineExpired,
            Some(capture),
        );

        assert_eq!(stats.scanner(), ScannerKind::Routed);
        assert_eq!(stats.targets(), 256);
        assert_eq!(stats.stop_reason(), StopReason::DeadlineExpired);
        assert_eq!(stats.sends_attempted(), 3);
        assert_eq!(stats.sends_failed(), 1);
        assert_eq!(stats.segments_seen(), 2);
        assert_eq!(stats.segments_off_target(), 1);
        assert_eq!(stats.replies_without_rtt(), 1);
        assert_eq!(stats.hosts_found(), 3);
        assert_eq!(stats.answered_on()[0], 1);
        assert_eq!(stats.answered_on()[2], 1);
        assert_eq!(stats.answered_unattributed(), 1);
        assert!(stats.first_reply().is_some());
        assert!(stats.last_reply() >= stats.first_reply());
        assert_eq!(stats.capture(), Some(capture));
        // Three hosts were credited, so the discovery histogram accounts for
        // three however they were spread across the buckets.
        assert_eq!(stats.found_at().iter().sum::<u64>(), 3);
    }

    /// A run driven by a synthetic stream has no kernel buffer to ask, and a
    /// zeroed capture in the report would read as a receive path measured and
    /// found clean.
    #[test]
    fn exported_stats_keep_an_absent_capture_absent() {
        let stats = ProbeAudit::new().stats(ScannerKind::Routed, 1, StopReason::AllResponded, None);

        assert_eq!(stats.capture(), None);
        assert!(stats.stop_reason().is_complete());
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
