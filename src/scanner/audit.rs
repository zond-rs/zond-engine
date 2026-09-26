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
//!   information: the case retransmission exists for;
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
//! here, so loss on the receive path and loss on the network read identically:
//! both are silence. [`CaptureCounts`] is reported alongside for that reason: it
//! is the only place the difference is visible.
//!
//! This is instrumentation, not telemetry: nothing here reaches the host store
//! or the event stream, and none of it changes what a scan does.

use std::time::{Duration, Instant};

use crate::model::capture::CaptureCounts;
use crate::model::port::PortState;
use crate::report::ScannerKind;
use crate::report::WindowSummary;
use crate::report::{ATTEMPTS_COUNTED, BUCKET_BOUNDS_MS, ProbeStats, StopReason};

/// How a port scan paced itself, as its audit line reads it: the congestion
/// window it asked through, and what it concludes of a port nothing answered.
///
/// Together because the window is only read against the silence. A window cut
/// to its floor with most ports unanswered says loss where silence is a filter,
/// and says nothing where silence is what an open port answers.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Pacing {
    /// What the window did over the run.
    pub(crate) window: WindowSummary,
    /// The verdict this scan gives a port that stayed silent.
    pub(crate) silence: PortState,
    /// Ports this scan was handed and never put a probe on the wire for. Their
    /// silence is this machine's, and they are left out of what is read as
    /// possible loss.
    pub(crate) unasked: u128,
}

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
    /// Of those, ones seen leaving on the wire. A send the OS accepted and
    /// dropped is counted above and not here; the gap is what tells an unasked
    /// port from a silent one.
    pub(crate) sends_witnessed: u64,

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

    /// Targets a reply resolved, counted once each: a host for a discovery
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

/// The share of answers arriving only on a retry that is taken as evidence the
/// send rate is too high.
///
/// Retransmission earning its traffic is ordinary and expected: a fifth of
/// answers arriving late on a lossy path is a working scan. Past a third, the
/// first attempt is failing often enough that the verdicts resting on silence
/// cannot be trusted, and a caller who is told nothing will read them as
/// firewall behaviour.
const RETRY_SHARE_SUGGESTING_LOSS: f64 = 0.35;

/// The fewest answers a run needs before that share means anything.
///
/// One answer arriving on its second attempt is a hundred percent, and says
/// nothing whatsoever.
const MIN_ANSWERS_TO_JUDGE: u64 = 20;

/// The share of a run's targets that may go unanswered before a scan which
/// already paced itself to its floor is worth remarking on.
///
/// Silence is an ordinary result and most of it is genuine. What is not ordinary
/// is silence on a scan whose own pacing ran out of room, and the two together
/// are the signature of a target that was outrun from the first probe to the
/// last. A tenth is low enough to catch it and high enough that a scan of a
/// firewalled host, which reaches the floor honestly, is not reported as
/// broken, that scan answers nothing at all, so its window never cut and never
/// arrived here.
const UNANSWERED_SHARE_SUGGESTING_LOSS: f64 = 0.10;

impl Default for ProbeAudit {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeAudit {
    /// Starts an audit, with the clock running from now.
    ///
    /// Internal to the engine, as the whole tally is. What a run's counts are
    /// worth to a caller is the [`ProbeStats`] they close into, which is part
    /// of the report; a strategy written outside this crate files one of those
    /// built from its parts, through
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

    /// Records one probe seen leaving on the wire, the evidence half of
    /// [`record_send`](Self::record_send): that one says the OS took the write,
    /// this that the packet was watched going out.
    pub fn record_witnessed_send(&mut self) {
        self.sends_witnessed += 1;
    }

    /// Whether this run can see its own probes leave at all. Zero is a path with
    /// no egress capture, where a probe's own count says nothing; the guard on
    /// every conclusion drawn from it.
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
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Probes per second actually put on the wire, over the whole run.
    ///
    /// The send timer paces to a configured rate but never makes up a tick it
    /// missed while the loop was busy with replies: catching up would release
    /// the burst the pace exists to prevent, so a busy sweep runs slower than
    /// asked and the deadline is sized to allow for it. This is what it managed,
    /// so the gap between it and the configured rate is readable rather than
    /// hidden in the elapsed time. Zero for a run too short to divide by. See
    /// [`ProbeStats::achieved_send_rate`], which reads the same division off a
    /// report.
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
    /// One line rather than several because the fields are only meaningful
    /// against each other: `sent` versus `captured` says whether packets went
    /// missing, `captured` versus `kernel` says which side of the capture they
    /// went missing on, and the stop reason versus `last` says whether the scan
    /// outlived its own answers.
    ///
    /// `capture` is what the scanner's own transport reports, or `None` where
    /// there is no capture to ask - a scan driven by a synthetic receive stream
    /// has no kernel buffer, and the segment is omitted rather than rendered as
    /// a clean one. `pacing` is a port scan's window and what its silence
    /// means, and `None` for a scanner paced some other way.
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
             | captured {seen} (off-target {off}, no-rtt {no_rtt}){kernel} \
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
            kernel = format_capture(capture),
            attempts = self.attempt_distribution(),
            window = format_window(window),
            first = format_offset(self.first_reply),
            last = format_offset(self.last_reply),
            histogram = self.histogram(),
        );

        self.warn_if_degraded(scanner, targets, capture, pacing);
    }

    /// The share of answers that only arrived because the probe was sent again.
    ///
    /// A first attempt that goes unanswered and a second that succeeds is a
    /// reply that was *lost*, not a port that was silent: the host was always
    /// willing to answer and the question did not survive the trip. Read across
    /// a run, this is the clearest evidence available that probes are going out
    /// faster than the path or the target will take.
    fn recovered_by_retry(&self) -> f64 {
        let recovered: u64 = self.answered_on.iter().skip(1).sum();
        match self.hosts_found {
            0 => 0.0,
            found => recovered as f64 / found as f64,
        }
    }

    /// Says so when a run's own counters show it was losing replies.
    ///
    /// A scan that degrades quietly is the failure this engine exists not to
    /// have. Measured, against a consumer router: probed faster than it would
    /// answer, a thousand-port scan reported six hundred ports `filtered`: with
    /// no more hesitation than it reported the three that really were, and among
    /// them two ports running services. Every one of those verdicts is a claim
    /// about somebody's firewall, and they were claims about this scanner's own
    /// send rate.
    ///
    /// The numbers were already collected; nothing read them back. Two signals,
    /// because they fail in different ways:
    ///
    /// - **Answers that needed a retry.** The host was willing; the first ask
    ///   did not survive. Silence from a firewall does not improve on the second
    ///   attempt.
    /// - **Frames the kernel dropped.** Frames that arrived and were discarded
    ///   before this process saw them, which is loss on *this* side and is
    ///   nobody's firewall at all, though not every one of them was an answer.
    ///
    /// What the first one is *worth telling somebody* depends on whether the
    /// scan could do anything about it. A scan pacing itself by a congestion
    /// window has already cut its rate on this very signal, so the line says what
    /// happened rather than what to change; a scan running at a fixed rate has
    /// not, and there the rate is the thing to reach for. Advising a knob that
    /// is not what set the pace sends the reader to the wrong place.
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
            // Short on purpose. The reasoning is above, where somebody changing
            // this can read it; a scan's output is read while waiting for the
            // next line and has to say the thing and stop.
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

        // The controller having run out of room. Separate from the share above
        // and more serious: that one says retransmission is carrying the scan,
        // this one says the scan slowed itself as far as it is allowed to and
        // was still not keeping up. Whatever it recorded as silence on this run
        // is not safe to read as a firewall.
        //
        // Only where silence is a firewall's verdict. An open port answers a
        // FIN, a flagless segment or most datagrams with silence, so a scan
        // asking those counts its open ports among the unanswered, and a share
        // of them reported as possible loss is its findings reported as a fault.
        //
        // And only of the ports asked. A probe this machine refused to send
        // cuts the window as backpressure does, and its port was never put to
        // the network: counted as unanswered, a scan whose sends all failed
        // reports the network losing every probe it never saw.
        if let Some(Pacing {
            window,
            silence,
            unasked,
        }) = pacing
            && silence == PortState::Filtered
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

        // Told as answers that may be missing, and only where one could be.
        // The kernel counts what it dropped and not what it was, and a capture
        // holds this scan's own probes seen leaving, this machine's reports of
        // probes it could not deliver and other people's traffic in the same
        // slots as answers. So the drop is known and a lost answer is not, and
        // a drop could have cost a verdict only where a target went
        // unanswered. Where every target answered, no verdict rests on a
        // dropped frame, and the line is one of the decisions behind the
        // result rather than a warning.
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
/// `received` is kept next to `dropped` rather than reported
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

/// The congestion window's own account of the run, or nothing for a scanner
/// that does not pace itself by one.
///
/// Omitted rather than rendered as a stationary window, on the same reasoning
/// [`format_capture`] omits an absent capture: a scan with no window and a scan
/// whose window never moved are different facts, and a line that printed the
/// same thing for both would be inviting the reader to conclude the wrong one.
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

    /// The signal that separates a lost reply from a silent port.
    ///
    /// A first attempt that goes unanswered and a second that succeeds means the
    /// host was always willing: silence from a firewall does not improve on the
    /// retry. Read across a run it is the clearest evidence available that
    /// probes are outrunning what the target will answer.
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

    /// A port scan paced to its floor with most of its ports unanswered is
    /// told its silence may be loss where silence is a firewall's verdict, and
    /// not where it is what an open port answers.
    ///
    /// A FIN scan's open ports never answer, so they are counted among the
    /// unanswered: told half of them may be lost probes, its reader reads the
    /// open ports it found as a fault in the scan.
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
            (PortState::Filtered, true),
            (PortState::OpenFiltered, false),
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

    /// A port this machine never sent a probe for is not a port the network
    /// left unanswered. A refused send cuts the window as backpressure does,
    /// so a scan whose probe was refused sits at its floor with its one port
    /// silent, and told that as possible loss it blames the network for a
    /// probe the network never saw.
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
                        silence: PortState::Filtered,
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

    /// A capture's drops are told as lost answers only where an answer could
    /// be missing, and never as replies known to be lost.
    ///
    /// The kernel counts what it dropped and not what it was: this scan's own
    /// probes seen leaving, this machine's reports of probes it could not
    /// deliver and other people's traffic take the same slots as answers do.
    /// Told as lost replies, a scan of addresses nobody holds reports answers
    /// from hosts that do not exist. Where every target answered, no verdict
    /// can rest on a dropped frame, and a default console has nothing to act
    /// on.
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

    /// One answer on its second attempt is a hundred percent and says nothing.
    /// A threshold with no floor under it would warn on every small scan.
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
        // Three hosts were credited, so the discovery histogram accounts for
        // three however they were spread across the buckets.
        assert_eq!(stats.found_at().iter().sum::<u64>(), 3);
    }

    /// A run driven by a synthetic stream has no kernel buffer to ask, and a
    /// zeroed capture in the report would read as a receive path measured and
    /// found clean.
    #[test]
    fn exported_stats_keep_an_absent_capture_absent() {
        let stats =
            ProbeAudit::new().stats(ScannerKind::Routed, 1, StopReason::AllResponded, None, None);

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
