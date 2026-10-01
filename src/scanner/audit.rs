// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Probe Auditing
//!
//! What a raw scanner observed about its own run, so a disappointing result can
//! be attributed.
//!
//! A sweep that finds 96 of 256 hosts on one run and 187 on the next failed in
//! one of three ways, each with a different fix:
//!
//! - probes or replies were **lost**, which retransmission exists for;
//! - replies arrived after the scan had **stopped**, so the deadline is wrong;
//! - replies arrived and were **not recognized**, so correlation is wrong.
//!
//! Sends and captured segments bound the first, the stop reason and the
//! reply-latency histogram the second, and the off-target and no-RTT counts the
//! third. The counters are per scanner run, held by the scanner, and reported
//! once when its loop exits.
//!
//! A reply the kernel discards because the capture buffer was full reaches no
//! counter here, so receive-path loss looks like network loss. [`CaptureCounts`]
//! is reported alongside because it is the only place the difference shows.
//!
//! Nothing here reaches the host store or the event stream, or changes what a
//! scan does.

use std::time::{Duration, Instant};

use crate::model::capture::CaptureCounts;
use crate::model::port::PortState;
use crate::report::ScannerKind;
use crate::report::WindowSummary;
use crate::report::{ATTEMPTS_COUNTED, BUCKET_BOUNDS_MS, ProbeStats, StopReason};

/// How a port scan paced itself, as its audit line reads it: the congestion
/// window it asked through, and what it concludes of a port nothing answered.
///
/// A window cut to its floor with most ports unanswered suggests loss only where
/// silence means no-reply, not where it is how an open port answers.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Pacing {
    /// What the window did over the run.
    pub(crate) window: WindowSummary,
    /// The verdict this scan gives a port that stayed silent.
    pub(crate) silence: PortState,
    /// Ports this scan never put a probe on the wire for. They are left out of
    /// what is read as possible loss.
    pub(crate) unasked: u128,
}

/// Per-run counters for one raw scanner.
///
/// Owned by the scanner and mutated from its own loop, so the fields are plain
/// integers.
pub struct ProbeAudit {
    started: Instant,

    /// Probes the scanner tried to put on the wire.
    pub(crate) sends_attempted: u64,
    /// Of those, ones the sender refused. Nonzero means the shortfall starts on
    /// this machine.
    pub(crate) sends_failed: u64,
    /// Of those, ones seen leaving on the wire. A send the OS accepted and then
    /// dropped is counted above and not here, which tells an unasked port from a
    /// silent one.
    pub(crate) sends_witnessed: u64,

    /// Segments the capture handed up, before any of the scanner's own checks.
    /// Bounded above by what the kernel BPF filter admitted.
    pub(crate) segments_seen: u64,
    /// Segments whose source is not in this scan's target set.
    ///
    /// Small on IPv4, where the kernel filter admits only the two segments a
    /// probe can draw. Over IPv6 libpcap cannot filter TCP by flags, so the SYN
    /// transport admits every IPv6 TCP segment on the captured interfaces,
    /// including the host's own connections. Read it against `segments_seen` as
    /// receive-path load.
    pub(crate) segments_off_target: u64,
    /// In-set replies that answered no outstanding probe, so they proved the
    /// host alive but yielded no round-trip sample. Duplicates and
    /// retransmissions land here, and so does a correlation bug.
    pub(crate) replies_without_rtt: u64,
    /// ICMP refusals that quoted too little of the probe to name its attempt, so
    /// they settled nothing. A subset of `replies_without_rtt`, kept apart so a
    /// reader knows a refusal was heard for ports that still read no-reply.
    pub(crate) refusals_unattributed: u64,

    /// Targets a reply resolved, counted once each: a host for a discovery
    /// sweep, an `(address, port)` probe for a port scan. The numerator to the
    /// `targets` this run was given.
    pub(crate) hosts_found: u64,

    /// Found hosts by the attempt whose reply revealed them, `[0]` being the
    /// first send. The last slot absorbs anything beyond
    /// [`ATTEMPTS_COUNTED`].
    ///
    /// Shows whether retransmission earns its traffic: a host found on its third
    /// attempt needed the packet resent, one found on its first only needed the
    /// scan to keep listening.
    answered_on: [u64; ATTEMPTS_COUNTED],
    /// Found hosts whose reply named no attempt: it arrived after the probe was
    /// written off, or carried nothing to match against.
    answered_unattributed: u64,

    first_reply: Option<Duration>,
    last_reply: Option<Duration>,
    buckets: [u64; BUCKET_BOUNDS_MS.len() + 1],
}

/// The share of answers arriving only on a retry that is taken as evidence the
/// send rate is too high.
///
/// A fifth of answers arriving on a retry is normal on a lossy path. Past a
/// third, the first attempt fails often enough that verdicts resting on silence
/// cannot be trusted.
const RETRY_SHARE_SUGGESTING_LOSS: f64 = 0.35;

/// The fewest answers a run needs before that share means anything.
///
/// One answer arriving on its second attempt is a hundred percent.
const MIN_ANSWERS_TO_JUDGE: u64 = 20;

/// The share of a run's targets that may go unanswered before a scan which
/// already paced itself to its floor is worth remarking on.
///
/// Silence on a scan whose pacing ran out of room is the signature of a target
/// that was outrun throughout. A tenth is low enough to catch that and high
/// enough to spare an ordinary scan with some genuinely silent ports.
const UNANSWERED_SHARE_SUGGESTING_LOSS: f64 = 0.10;

impl Default for ProbeAudit {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeAudit {
    /// Starts an audit, with the clock running from now.
    ///
    /// Callers see the counts as the [`ProbeStats`] in the report. A strategy
    /// written outside this crate files its own through
    /// [`record_probe_stats`](crate::scanner::session::ScanContext::record_probe_stats).
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            sends_attempted: 0,
            sends_failed: 0,
            sends_witnessed: 0,
            segments_seen: 0,
            segments_off_target: 0,
            replies_without_rtt: 0,
            refusals_unattributed: 0,
            hosts_found: 0,
            answered_on: [0; ATTEMPTS_COUNTED],
            answered_unattributed: 0,
            first_reply: None,
            last_reply: None,
            buckets: [0; BUCKET_BOUNDS_MS.len() + 1],
        }
    }

    /// Records one send attempt and whether the operating system took it.
    pub fn record_send(&mut self, sent: bool) {
        self.sends_attempted += 1;
        if !sent {
            self.sends_failed += 1;
        }
    }

    /// Records one probe seen leaving on the wire. [`record_send`](Self::record_send)
    /// records that the OS took the write; this, that the packet went out.
    pub fn record_witnessed_send(&mut self) {
        self.sends_witnessed += 1;
    }

    /// Whether this run can see its own probes leave. False on a path with no
    /// egress capture, where the witnessed count means nothing.
    pub fn witnesses_its_sends(&self) -> bool {
        self.sends_witnessed > 0
    }

    /// Records one segment lifted off the capture, before any filtering the
    /// scanner does itself.
    pub fn record_segment(&mut self) {
        self.segments_seen += 1;
    }

    /// Records a segment from an address outside this scan's target set.
    pub fn record_off_target(&mut self) {
        self.segments_off_target += 1;
    }

    /// Records an in-set reply that matched no outstanding probe.
    pub fn record_reply_without_rtt(&mut self) {
        self.replies_without_rtt += 1;
    }

    /// Records an ICMP refusal that quoted too little of its probe to name the
    /// attempt. Also counted as a reply without a round trip.
    pub fn record_unattributed_refusal(&mut self) {
        self.refusals_unattributed += 1;
        self.record_reply_without_rtt();
    }

    /// Records a target resolved by a reply, timestamped against the start of
    /// the run and attributed to the attempt that answered it where the reply
    /// named one.
    ///
    /// Called once per target, on the reply that first resolved it. A duplicate
    /// or a late arrival for the same target is
    /// [`record_reply_without_rtt`](Self::record_reply_without_rtt), not this.
    pub fn record_host_found(&mut self, answered_attempt: Option<u8>) {
        self.hosts_found += 1;

        match answered_attempt {
            Some(attempt) => {
                // Attempts are numbered from one; a zero is folded into the
                // first.
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
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Probes per second actually put on the wire, over the whole run.
    ///
    /// The send timer skips ticks missed while the loop was busy with replies,
    /// since catching up would send a burst, so a busy sweep runs slower than
    /// configured. Zero for a run too short to divide by. See
    /// [`ProbeStats::achieved_send_rate`] for the same figure on a report.
    fn achieved_send_rate(&self) -> f64 {
        crate::report::send_rate(self.sends_attempted, self.started.elapsed()).unwrap_or(0.0)
    }

    /// How many probes were seen leaving on the wire.
    #[cfg(test)]
    pub fn sends_witnessed(&self) -> u64 {
        self.sends_witnessed
    }

    /// The exported view of this run, for the scan's report.
    ///
    /// Built independently of [`report`](Self::report)'s log line, so either
    /// format can change without touching the other.
    pub(crate) fn stats(
        &self,
        scanner: ScannerKind,
        targets: u128,
        reason: StopReason,
        capture: Option<CaptureCounts>,
        window: Option<WindowSummary>,
    ) -> ProbeStats {
        ProbeStats {
            scanner,
            targets,
            stop_reason: reason,
            elapsed: self.elapsed(),
            sends_attempted: self.sends_attempted,
            sends_failed: self.sends_failed,
            sends_witnessed: self.sends_witnessed,
            segments_seen: self.segments_seen,
            segments_off_target: self.segments_off_target,
            replies_without_rtt: self.replies_without_rtt,
            refusals_unattributed: self.refusals_unattributed,
            hosts_found: self.hosts_found,
            answered_on: self.answered_on,
            answered_unattributed: self.answered_unattributed,
            first_reply: self.first_reply,
            last_reply: self.last_reply,
            found_at: self.buckets,
            capture,
            window,
        }
    }

    /// Emits the run's summary as a single log line.
    ///
    /// One line because the fields are read against each other: `sent` versus
    /// `captured` says whether packets went missing, `captured` versus `kernel`
    /// on which side of the capture, and the stop reason versus `last` whether
    /// the scan outlived its own answers.
    ///
    /// `capture` is what the scanner's transport reports, or `None` where there
    /// is no kernel buffer (a synthetic receive stream); the segment is then
    /// omitted. `pacing` is a port scan's window and what its silence means, or
    /// `None` for a scanner paced some other way.
    pub(crate) fn report(
        &self,
        scanner: &str,
        targets: u128,
        reason: StopReason,
        capture: Option<CaptureCounts>,
        pacing: Option<Pacing>,
    ) {
        let window = pacing.map(|pacing| pacing.window);
        crate::info!(
            verbosity = 3,
            "audit[{scanner}] {found}/{targets} hosts in {elapsed:.0?}, stopped: {reason:?} \
             | sent {sent} (failed {failed}, {rate:.0}/s) \
             | captured {seen} (off-target {off}, no-rtt {no_rtt}, \
             refusals-unattributed {refusals}){kernel} \
             | found on {attempts}{window} \
             | first {first}, last {last} \
             | found-at {histogram}",
            found = self.hosts_found,
            elapsed = self.elapsed(),
            sent = self.sends_attempted,
            failed = self.sends_failed,
            rate = self.achieved_send_rate(),
            seen = self.segments_seen,
            off = self.segments_off_target,
            no_rtt = self.replies_without_rtt,
            refusals = self.refusals_unattributed,
            kernel = format_capture(capture),
            attempts = self.attempt_distribution(),
            window = format_window(window),
            first = format_offset(self.first_reply),
            last = format_offset(self.last_reply),
            histogram = self.histogram(),
        );

        // At verbosity 1: refusals heard for ports that still read no-reply,
        // because they named no probe.
        if self.refusals_unattributed > 0 {
            crate::info!(
                verbosity = 1,
                "{scanner}: {} not credited (named no probe)",
                crate::logging::counted(
                    u128::from(self.refusals_unattributed),
                    "refusal",
                    "refusals"
                ),
            );
        }

        self.warn_if_degraded(scanner, targets, capture, pacing);
    }

    /// The share of answers that only arrived because the probe was sent again.
    ///
    /// An answer on a retry means the first probe or its reply was lost, since
    /// a firewall's silence does not improve on a second attempt. Across a run,
    /// this is the clearest evidence that probes are going out faster than the
    /// path or target will take.
    fn recovered_by_retry(&self) -> f64 {
        let recovered: u64 = self.answered_on.iter().skip(1).sum();
        match self.hosts_found {
            0 => 0.0,
            found => recovered as f64 / found as f64,
        }
    }

    /// Says so when a run's own counters show it was losing replies.
    ///
    /// A consumer router probed faster than it answers makes a thousand-port
    /// scan report six hundred `NoReply` ports, two of them running services:
    /// verdicts that read as claims about the router but are caused by the send
    /// rate. The signals:
    ///
    /// - **Answers that needed a retry.** The host was willing but the first
    ///   probe was lost.
    /// - **A window at its floor with ports unanswered.** The scan slowed as far
    ///   as allowed and still did not keep up.
    /// - **Frames the kernel dropped.** Loss on this side, though not every
    ///   dropped frame was an answer.
    ///
    /// A scan paced by a congestion window has already cut its rate on the retry
    /// signal, so its warning states the window; a fixed-rate scan is told the
    /// rate is too high.
    fn warn_if_degraded(
        &self,
        scanner: &str,
        targets: u128,
        capture: Option<CaptureCounts>,
        pacing: Option<Pacing>,
    ) {
        let window = pacing.map(|pacing| pacing.window);
        let recovered = self.recovered_by_retry();
        if recovered >= RETRY_SHARE_SUGGESTING_LOSS && self.hosts_found >= MIN_ANSWERS_TO_JUDGE {
            let percent = recovered * 100.0;
            match window {
                Some(window) if window.adaptive => crate::warn!(
                    "{scanner}: {percent:.0}% of answers needed a retry (paced to {})",
                    window.capacity,
                ),
                _ => crate::warn!(
                    "{scanner}: {percent:.0}% of answers needed a retry (rate too high)"
                ),
            }
        }

        // The window at its floor and still not keeping up: silence on this run
        // is not safe to read as a firewall. Only where silence means no-reply,
        // since open ports answer FIN, flagless and most UDP probes with
        // silence. Unsent probes also cut the window, so they are left out of
        // the share.
        if let Some(Pacing {
            window,
            silence,
            unasked,
        }) = pacing
            && silence == PortState::NoReply
            && window.at_floor
            && targets > unasked
        {
            let asked = targets - unasked;
            let unanswered = asked.saturating_sub(u128::from(self.hosts_found));
            let share = unanswered as f64 / asked as f64;
            if share >= UNANSWERED_SHARE_SUGGESTING_LOSS {
                crate::warn!(
                    "{scanner}: {percent:.0}% unanswered at {} in flight (maybe loss)",
                    window.capacity,
                    percent = share * 100.0,
                );
            }
        }

        // The kernel counts drops but not what they were (our own outgoing
        // probes, ICMP errors, unrelated traffic), so a drop can only have cost
        // a verdict where a target went unanswered. Otherwise it is an info line.
        if let Some(counts) = capture
            && counts.dropped > 0
        {
            let frames = crate::logging::counted(counts.dropped.into(), "frame", "frames");
            if u128::from(self.hosts_found) < targets {
                crate::warn!("{scanner}: capture dropped {frames} (answers may be lost)");
            } else {
                crate::info!(
                    verbosity = 1,
                    "{scanner}: capture dropped {frames} (every target answered)"
                );
            }
        }
    }

    /// Found hosts by the attempt that revealed them, empty attempts omitted.
    ///
    /// Rendered as `attempt:count`. Everything on `1` means the retries bought
    /// nothing; a tail on `2` and `3` is retransmission doing its job.
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

/// One reply-time offset as the audit line prints it, or `-` where there was
/// no reply to time.
fn format_offset(offset: Option<Duration>) -> String {
    match offset {
        Some(offset) => format!("{:.0?}", offset),
        None => "-".to_string(),
    }
}

/// The kernel-capture segment of the audit line, empty where there was no
/// capture to report on.
///
/// `received` includes traffic this scan did not cause; it gives the scale the
/// drops happened at.
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

/// The congestion window's own account of the run, or nothing for a scanner
/// that does not pace itself by one.
///
/// Omitted when absent, as in [`format_capture`], so a scan with no window does
/// not read as one whose window never moved.
fn format_window(window: Option<WindowSummary>) -> String {
    match window {
        Some(window) => format!(" | window {window}"),
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

    /// Answers needing a retry separate a lost reply from a silent port.
    #[test]
    fn answers_that_needed_a_retry_are_what_reveals_loss() {
        let mut clean = ProbeAudit::new();
        for _ in 0..50 {
            clean.record_host_found(Some(1));
        }
        assert!(
            clean.recovered_by_retry() < RETRY_SHARE_SUGGESTING_LOSS,
            "every answer on the first ask is a scan that lost nothing"
        );

        let mut lossy = ProbeAudit::new();
        for _ in 0..20 {
            lossy.record_host_found(Some(1));
        }
        for _ in 0..30 {
            lossy.record_host_found(Some(2));
        }
        assert!(
            lossy.recovered_by_retry() >= RETRY_SHARE_SUGGESTING_LOSS,
            "most answers arriving only on the second ask is the first ask failing"
        );
    }

    /// A scan at its window's floor with most ports unanswered warns of loss only
    /// where silence means no-reply. A FIN scan's open ports never answer.
    #[test]
    fn silence_at_the_windows_floor_is_called_loss_only_where_it_is_a_filter() {
        let mut audit = ProbeAudit::new();
        for _ in 0..20 {
            audit.record_host_found(Some(1));
        }
        let window = WindowSummary {
            capacity: 16,
            peak: 256,
            reductions: 5,
            adaptive: true,
            at_floor: true,
        };

        for (silence, warned) in [
            (PortState::NoReply, true),
            (PortState::OpenOrNoReply, false),
        ] {
            let said = crate::logging::logged(|| {
                audit.report(
                    "tcp-port",
                    40,
                    StopReason::AttemptsSpent,
                    None,
                    Some(Pacing {
                        window,
                        silence,
                        unasked: 0,
                    }),
                );
            });
            let lines: Vec<&str> = said
                .iter()
                .filter(|line| line.message.contains("unanswered at"))
                .map(|line| line.message.as_str())
                .collect();
            assert_eq!(!lines.is_empty(), warned, "{silence:?}: {said:?}");
        }
    }

    /// A port whose probe was never sent does not count as possible loss, even
    /// though the refused send cut the window to its floor.
    #[test]
    fn a_probe_never_sent_is_not_read_as_possible_loss() {
        let audit = ProbeAudit::new();
        let window = WindowSummary {
            capacity: 16,
            peak: 16,
            reductions: 1,
            adaptive: true,
            at_floor: true,
        };

        for (unasked, warned) in [(0, true), (1, false)] {
            let said = crate::logging::logged(|| {
                audit.report(
                    "tcp-port",
                    1,
                    StopReason::AttemptsSpent,
                    None,
                    Some(Pacing {
                        window,
                        silence: PortState::NoReply,
                        unasked,
                    }),
                );
            });
            let told = said
                .iter()
                .any(|line| line.message.contains("unanswered at"));
            assert_eq!(told, warned, "{unasked} unasked: {said:?}");
        }
    }

    /// Capture drops are a warning only where a target went unanswered, and are
    /// never claimed as lost replies, since the kernel does not say what it
    /// dropped.
    #[test]
    fn capture_drops_are_told_as_possible_loss_only_where_a_target_went_unanswered() {
        let dropped = CaptureCounts {
            received: 605,
            dropped: 184,
            if_dropped: 0,
            stopped_early: 0,
        };
        let mut every_one_answered = ProbeAudit::new();
        for _ in 0..40 {
            every_one_answered.record_host_found(Some(1));
        }

        for (audit, targets, told) in [
            (&ProbeAudit::new(), 200, true),
            (&every_one_answered, 40, false),
        ] {
            let said = crate::logging::logged(|| {
                audit.report(
                    "local",
                    targets,
                    StopReason::AttemptsSpent,
                    Some(dropped),
                    None,
                );
            });
            let drops: Vec<_> = said
                .iter()
                .filter(|line| line.message.contains("capture dropped 184 frames"))
                .collect();
            assert_eq!(drops.len(), 1, "{targets} targets: {said:?}");
            assert_eq!(drops[0].verbosity == 0, told, "{targets} targets: {said:?}");
            assert!(
                !drops[0].message.contains("replies lost"),
                "a drop is claimed as lost replies: {said:?}"
            );
        }
    }

    /// Without a minimum, the retry share would warn on every small scan.
    #[test]
    fn a_run_too_small_to_judge_is_not_judged() {
        let mut tiny = ProbeAudit::new();
        tiny.record_host_found(Some(2));

        assert!(tiny.recovered_by_retry() > RETRY_SHARE_SUGGESTING_LOSS);
        assert!(
            tiny.hosts_found < MIN_ANSWERS_TO_JUDGE,
            "and the floor is what stops that being reported as a degraded scan"
        );
    }
    use super::*;

    #[test]
    fn offsets_land_in_the_bucket_named_by_their_bound() {
        assert_eq!(bucket_of(Duration::from_micros(200)), 0); // <=1ms
        assert_eq!(bucket_of(Duration::from_millis(1)), 0);
        assert_eq!(bucket_of(Duration::from_millis(2)), 1);
        assert_eq!(bucket_of(Duration::from_millis(3)), 2); // <=5ms
        assert_eq!(bucket_of(Duration::from_millis(1_000)), 8);
    }

    /// Anything slower than the last bound lands in the overflow bucket.
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

    /// The distribution the retry policy is judged on.
    #[test]
    fn hosts_are_counted_against_the_attempt_that_revealed_them() {
        let mut audit = ProbeAudit::new();
        audit.record_host_found(Some(1));
        audit.record_host_found(Some(1));
        audit.record_host_found(Some(3));
        audit.record_host_found(None);

        assert_eq!(audit.attempt_distribution(), "1:2 3:1 unattributed:1");
    }

    /// An attempt past the reported range lands in the final slot.
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

    /// Every counter reaches the exported stats.
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
            stopped_early: 0,
        };
        let stats = audit.stats(
            ScannerKind::Routed,
            256,
            StopReason::DeadlineExpired,
            Some(capture),
            None,
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
        // Three hosts credited, however the buckets spread them.
        assert_eq!(stats.found_at().iter().sum::<u64>(), 3);
    }

    /// A run with no kernel buffer keeps its capture absent; zeroes would read as
    /// a clean receive path.
    #[test]
    fn exported_stats_keep_an_absent_capture_absent() {
        let stats =
            ProbeAudit::new().stats(ScannerKind::Routed, 1, StopReason::AllResponded, None, None);

        assert_eq!(stats.capture(), None);
        assert!(stats.stop_reason().is_complete());
    }

    /// No capture means no segment on the line; zeroes would read as clean.
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
            stopped_early: 0,
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
