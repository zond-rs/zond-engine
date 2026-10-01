// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How many probes a scan may have outstanding
//!
//! The right number cannot be chosen in advance. A Linux server on a switch takes
//! thousands of probes in flight; the consumer router next to it takes a few dozen,
//! and probed faster than it answers, it reports hundreds of ports `NoReply` that are
//! really a claim about our send rate.
//!
//! [`CongestionWindow`] bounds how many probes a scan may have outstanding, grows
//! that bound while answers keep arriving, and cuts it when the answers show the
//! target is being outrun. Probes leave as earlier ones are answered, so the send
//! rate settles at the rate the target resolves them, with no clock or
//! configuration. The engine's rate ceiling is a backstop against a defect here.
//!
//! ## The loss signal
//!
//! TCP reduces on a timeout because a lost segment means a full queue. For a scanner
//! an unanswered probe usually means a firewall, and reducing on it would crawl
//! through exactly the wide, filtered ranges that are hardest to finish. The rule
//! turns on who is silent:
//!
//! > **Silence from a host that has never spoken is not congestion. Silence from
//! > a host that is otherwise answering us is.**
//!
//! A host counts as talking when it answers more than one probe in ten put to it. A
//! host answering one port in a thousand is a firewall letting it through; read as
//! talking on the strength of one open port, a Windows machine behind its firewall
//! held its scan at the window's floor.
//!
//! | What is happening | What the controller sees | What it does |
//! |---|---|---|
//! | Host answers everything | Answers on the first ask | Grows to the ceiling |
//! | Address is a black hole | Nothing ever answers | Grows; finishes at speed |
//! | A firewall lets a port through | Answers, one in hundreds | Grows; finishes at speed |
//! | Host is being outrun | Timeouts, from a host that talks | Cuts the window |
//! | Host is being outrun badly | Answers arriving only on retries | Cuts the window |
//!
//! The last two are the same fault seen at different times, and both are needed. A
//! recovery on a retry is stronger evidence but arrives late, or not at all when the
//! retries are lost too. Measured against a Raspberry Pi on a home network, a
//! controller that cut only on recoveries never cut: three scans of the same host
//! each found seven of its eleven open ports and reported about 240 ports `NoReply`,
//! a different set each run. All three attempts at a probe fell inside the same
//! congested moment, so no retry was ever answered.
//!
//! ## When silence is itself the answer
//!
//! The rule assumes a live stack answers every probe. That holds for a SYN but not
//! for a FIN, NULL, Xmas or Maimon probe, or a COOKIE-ECHO: an open port ignores
//! those, so each open port is a timeout from a host that is answering. Read as loss,
//! a scan of such a host would cut once per open port it finds.
//!
//! So one such silence is not read either way; what separates open ports from loss is
//! how much silence there is. Open ports are about a tenth of those asked on a
//! service-dense host, while loss retries could not recover was measured at a
//! quarter. Each silence from an answering host adds five to a balance, each answer
//! to a first ask takes one off, and the window is cut once the balance stands twelve
//! silences past even. Five to one is the likelihood ratio between a quarter lost and
//! a tenth open, so the balance sinks at one silence in ten, climbs at one in four
//! and holds still at one in six.
//!
//! A share averaged over recent outcomes would misread bunching. A silence is heard a
//! whole round-trip budget after the answers asked beside it, so silences arrive back
//! to back, a window's worth at once when the loop wakes late. The balance keeps the
//! credit answers earned while the silences asked beside them can still be on their
//! way, five per question in flight, so only silence beyond that reads as loss.
//!
//! ## What occupies the window
//!
//! A probe holds a slot **from its first send until its first outcome**: an answer or
//! the expiry of its round-trip budget. After that it is in the retry schedule and
//! holds nothing. Held until finally resolved, a firewalled port would occupy a slot
//! for most of two seconds against a round trip of one millisecond, and a thousand
//! silent ports through a window of thirty-two would cost a minute.
//!
//! Retries take no slot, but they are real packets and count toward the damping.
//!
//! ## Growth, reduction and damping
//!
//! Growth is TCP's: exponential below [`WindowLimits::slow_start_threshold`], linear
//! above it. A probe that timed out against a silent host grows the window like an
//! answered one, since nothing that host does says anything about capacity; this is
//! what lets a scan of firewalled or dead addresses open up and finish.
//!
//! Every probe yields exactly one signal, and the caller picks it by answering one
//! question: did this outcome say the target is failing to keep up?
//!
//! Reduction halves, then **does not halve again until a window's worth of probes has
//! been sent**. Otherwise a burst of fifty probes that all needed retries would be
//! fifty halvings. TCP applies the same rule per round trip; this counts probes.
//!
//! ## Capture drops
//!
//! A frame the kernel's capture buffer dropped is loss too, but it needs no wiring:
//! the probe times out, is resent and answered, which is a recovery like any other.
//! The drop counter is reported by [`ProbeAudit`](crate::scanner::audit::ProbeAudit),
//! because it is a fact about the operator's machine.
//!
//! ## Where it applies
//!
//! TCP port scanning, where an answer is the norm. A UDP probe's ordinary outcome is
//! silence, and a UDP reply carries nothing that names the attempt it answers, so a
//! UDP scan keeps a window that does not move, [`WindowLimits::fixed`], and is paced
//! by the rate its ICMP rate limiter demands.

use crate::report::WindowSummary;

/// How much a silence that may be an open port weighs against an answer to a
/// first ask, in a scan whose silence is a verdict.
///
/// A silence is two and a half times likelier from a host losing a quarter of its
/// probes (the share measured against a Raspberry Pi) than from one with a tenth of
/// its ports open; an answer is one and a fifth times likelier from the second. Five
/// is the ratio of the logarithms of the two, so the balance [`LOSS_EVIDENCE`] is
/// compared against holds still at one silence in six. A host with more than one in
/// six of the asked ports open is paced as a lossy host, which costs time but never
/// a verdict.
const SILENCE_WEIGHT: i64 = 5;

/// How far the balance of silence against answers has to climb before a scan
/// whose silence is a verdict reads it as loss.
///
/// Twelve silences. A host with a tenth of its ports open reaches it by chance
/// about once in a hundred thousand first outcomes, more than one host's ports; a
/// host losing a quarter of its probes reaches it in about a hundred.
const LOSS_EVIDENCE: i64 = 12 * SILENCE_WEIGHT;

/// The bounds a [`CongestionWindow`] moves within, and where it starts.
///
/// Declared per scanner beside its retry policy and deadline profile, since a
/// reasonable number of outstanding probes depends on the protocol.
///
/// `#[non_exhaustive]`, like the other pacing configurations, because these gain
/// fields as new measurements come in. Build it with [`new`](Self::new).
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct WindowLimits {
    /// The window before anything has been learned.
    ///
    /// Every stack in service answers a few dozen simultaneous probes, so
    /// starting there saves several round trips of ramp, which on a local
    /// segment is most of the scan.
    pub initial: u32,
    /// The smallest window a reduction may reach. Below this a scan stops making
    /// progress.
    pub floor: u32,
    /// The largest window growth may reach, whatever the evidence.
    ///
    /// It bounds correlation state as much as traffic: every outstanding probe
    /// is a ledger entry and a timer.
    pub ceiling: u32,
    /// Where exponential growth gives way to linear.
    ///
    /// Slow start doubles the window every round trip, which can overshoot a
    /// target's capacity before the first recovery arrives.
    pub slow_start_threshold: u32,
}

impl WindowLimits {
    /// Bounds counted in probes: the window opens at `initial`, is never cut
    /// below `floor` or grown past `ceiling`, and doubles only while it is
    /// under `slow_start_threshold`.
    pub const fn new(initial: u32, floor: u32, ceiling: u32, slow_start_threshold: u32) -> Self {
        Self {
            initial,
            floor,
            ceiling,
            slow_start_threshold,
        }
    }

    /// A window that does not move, for a scan whose protocol offers no evidence
    /// to move it on.
    ///
    /// The configuration for UDP, where silence is the ordinary outcome and no
    /// reply names the attempt it answers.
    pub const fn fixed(capacity: u32) -> Self {
        Self {
            initial: capacity,
            floor: capacity,
            ceiling: capacity,
            slow_start_threshold: capacity,
        }
    }

    /// Whether this window can move at all.
    const fn adaptive(&self) -> bool {
        self.floor < self.ceiling
    }
}

/// How many probes a scan may keep outstanding, adapted to what the targets are
/// managing to answer.
///
/// A scanner reads [`capacity`](Self::capacity) to decide whether to admit
/// another target, and reports back sends, releases and outcomes. The loss
/// signals are described in the module documentation.
#[derive(Debug, Clone)]
pub struct CongestionWindow {
    limits: WindowLimits,
    /// Fractional, so linear growth can add a fraction of a probe per answer.
    window: f64,
    threshold: f64,
    /// Probes sent and neither answered nor out of round-trip budget. Bounded
    /// by [`capacity`](Self::capacity).
    in_flight: u32,
    /// Probes released since the last reduction, against which
    /// [`epoch`](Self::epoch) is compared.
    since_reduction: u32,
    /// How many probes must be released before another reduction is allowed:
    /// the window as it stood when the last one happened.
    epoch: u32,
    peak: usize,
    reductions: u32,
    /// Ambiguous silence weighed against answers, among first outcomes from
    /// answering hosts: up [`SILENCE_WEIGHT`] per silence, down one per answer,
    /// never below the credit the probes in flight may spend.
    /// [`record_ambiguous_silence`](Self::record_ambiguous_silence) compares it
    /// against [`LOSS_EVIDENCE`].
    silence_evidence: i64,
    /// Whether the scan has admitted its last probe. See
    /// [`stop_admitting`](Self::stop_admitting).
    admission_over: bool,
}

impl CongestionWindow {
    /// A window at its starting size, with nothing learned yet.
    ///
    /// Crossed bounds do not panic: the floor wins, as in
    /// [`suggest_timeout`](super::rtt_window::RttWindow::suggest_timeout) and
    /// [`ProbeLedger`](super::retry::ProbeLedger), and the window is stationary
    /// and says so through [`WindowSummary::adaptive`].
    pub fn new(limits: WindowLimits) -> Self {
        let window = f64::from(
            limits
                .initial
                .clamp(limits.floor, limits.ceiling.max(limits.floor)),
        );
        Self {
            limits,
            window,
            threshold: f64::from(limits.slow_start_threshold),
            in_flight: 0,
            since_reduction: 0,
            // Zero, so the first recovery is acted on.
            epoch: 0,
            peak: window as usize,
            reductions: 0,
            silence_evidence: 0,
            admission_over: false,
        }
    }

    /// The most questions that may be awaiting an answer right now.
    ///
    /// At least one, so the scan always makes progress.
    pub fn capacity(&self) -> usize {
        (self.window as usize).max(1)
    }

    /// How many questions are awaiting an answer.
    pub fn in_flight(&self) -> usize {
        self.in_flight as usize
    }

    /// Whether another question may be asked.
    pub fn has_room(&self) -> bool {
        self.in_flight() < self.capacity()
    }

    /// Records a first attempt leaving the wire: it takes a slot, and it counts
    /// toward the damping.
    pub fn record_send(&mut self) {
        self.in_flight = self.in_flight.saturating_add(1);
        self.since_reduction = self.since_reduction.saturating_add(1);
    }

    /// Records a retry leaving the wire: it counts toward the damping and takes
    /// no slot.
    ///
    /// The damping counts packets, so it sees retries. The slot was released when
    /// the probe it repeats ran out of round-trip budget.
    pub fn record_resend(&mut self) {
        self.since_reduction = self.since_reduction.saturating_add(1);
    }

    /// Releases the slot one question was holding.
    ///
    /// Separate from the signals below, because a probe that frees its slot may
    /// say the target is struggling or say nothing.
    ///
    /// Call it exactly once per probe, on whichever ends it first: an answer, or
    /// the expiry of its round-trip budget. Not on a retry, whose slot went back
    /// at that expiry.
    pub fn release(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }

    /// Records a probe answered on its first ask: the target is keeping up.
    ///
    /// Grows the window, and weighs against silence in the balance
    /// [`record_ambiguous_silence`](Self::record_ambiguous_silence) reads.
    pub(crate) fn record_answer(&mut self) {
        self.observe_first_outcome(false);
        self.record_progress();
    }

    /// Records silence from a host that is answering, in a scan where every
    /// port would have answered: a probe the target dropped.
    ///
    /// Cuts the window while the scan still has probes to admit; see
    /// [`stop_admitting`](Self::stop_admitting).
    pub(crate) fn record_loss(&mut self) {
        if !self.admission_over {
            self.record_congestion();
        }
    }

    /// Records silence from a host that is answering, in a scan where silence
    /// is also what an open port gives: an open port found, or a probe lost,
    /// and nothing about this one outcome says which.
    ///
    /// Cuts once the balance of silence against answers passes
    /// [`LOSS_EVIDENCE`], which a host's open ports do not reach and a host being
    /// outrun does. Read only while the scan still has probes to admit; see
    /// [`stop_admitting`](Self::stop_admitting).
    pub(crate) fn record_ambiguous_silence(&mut self) {
        if !self.admission_over && self.observe_first_outcome(true) > LOSS_EVIDENCE {
            self.record_congestion();
        }
    }

    /// Records that the scan has admitted its last probe. From here silence is no
    /// longer read as loss.
    ///
    /// A cut would slow nothing, and the outcomes still owed over-represent
    /// silence: an answered probe frees its slot after a round trip and a silent
    /// one after its whole budget. Weighed as evidence, they could leave the window
    /// reported at its floor on a host that dropped nothing.
    pub(crate) fn stop_admitting(&mut self) {
        self.admission_over = true;
    }

    /// Folds one first outcome from an answering host into the balance of
    /// silence against answers, and returns the balance.
    ///
    /// Held above [`credit_in_flight`](Self::credit_in_flight), so clean answers
    /// early in a long scan cannot bank enough credit to hide loss that starts
    /// late.
    fn observe_first_outcome(&mut self, silent: bool) -> i64 {
        let step = if silent { SILENCE_WEIGHT } else { -1 };
        self.silence_evidence = (self.silence_evidence + step).max(self.credit_in_flight());
        self.silence_evidence
    }

    /// The lowest the balance of silence may sink: the weight of one silence
    /// for every probe still in flight, negated.
    ///
    /// Every probe in flight may yet be heard as silence, a round-trip budget
    /// after its answering neighbours, so their credit is kept until then.
    fn credit_in_flight(&self) -> i64 {
        -SILENCE_WEIGHT * i64::from(self.in_flight)
    }

    /// Records an outcome that carried no sign of the target failing to keep up:
    /// answered on the first ask, or silence from a host that answers nothing
    /// anyway.
    ///
    /// Grows the window.
    pub fn record_progress(&mut self) {
        if !self.limits.adaptive() {
            return;
        }

        let step = if self.window < self.threshold {
            1.0
        } else {
            1.0 / self.window
        };
        self.window = (self.window + step).min(f64::from(self.limits.ceiling));
        self.peak = self.peak.max(self.capacity());
    }

    /// Records an outcome that says the target is being asked faster than it can
    /// answer: a question it dropped while answering others, or one it answered
    /// only after being asked again.
    ///
    /// Halves the window, then does not halve again until that many probes have
    /// been sent. The silence balance restarts at the in-flight credit, since the
    /// probes in flight were asked at the pace just cut.
    pub fn record_congestion(&mut self) {
        if !self.limits.adaptive() || self.since_reduction < self.epoch {
            return;
        }

        self.threshold = (self.window / 2.0).max(f64::from(self.limits.floor));
        self.window = self.threshold;
        self.epoch = self.capacity() as u32;
        self.since_reduction = 0;
        self.reductions = self.reductions.saturating_add(1);
        self.silence_evidence = self.credit_in_flight();
    }

    /// Releases every slot still held, for a scan stopping before its outstanding
    /// probes settle.
    pub fn release_all(&mut self) {
        self.in_flight = 0;
    }

    /// What this window did over the run, for the audit line.
    pub fn summary(&self) -> WindowSummary {
        WindowSummary {
            capacity: self.capacity(),
            peak: self.peak,
            reductions: self.reductions,
            adaptive: self.limits.adaptive(),
            at_floor: self.limits.adaptive() && self.capacity() <= self.limits.floor as usize,
        }
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

    /// `floor` and `ceiling` are adjacent `u32`s, so a caller can cross them, and
    /// `u32::clamp` would panic.
    #[test]
    fn crossed_bounds_freeze_the_window_rather_than_panicking() {
        let window = CongestionWindow::new(WindowLimits::new(10, 100, 50, 20));

        assert_eq!(window.capacity(), 100, "the floor wins");
        assert!(
            !window.summary().adaptive,
            "and a range with nothing in it cannot move"
        );
    }

    /// Growth and reduction are both no-ops on such a window.
    #[test]
    fn a_frozen_window_neither_grows_nor_cuts() {
        let mut window = CongestionWindow::new(WindowLimits::new(10, 100, 50, 20));
        let before = window.capacity();

        window.record_send();
        window.record_progress();
        window.record_congestion();

        assert_eq!(window.capacity(), before);
        assert_eq!(window.summary().reductions, 0);
    }
    use super::*;

    fn limits() -> WindowLimits {
        WindowLimits::new(16, 4, 512, 64)
    }

    /// Below the threshold the window doubles per round trip's worth of answers.
    #[test]
    fn slow_start_doubles_the_window_every_round_trip() {
        let mut window = CongestionWindow::new(limits());
        assert_eq!(window.capacity(), 16);

        // One round trip: every outstanding probe answered.
        for _ in 0..16 {
            window.record_progress();
        }
        assert_eq!(window.capacity(), 32);

        for _ in 0..32 {
            window.record_progress();
        }
        assert_eq!(window.capacity(), 64);
    }

    /// Past the threshold, eight round trips' worth of answers buy eight more
    /// probes.
    #[test]
    fn past_the_threshold_the_window_grows_by_one_per_round_trip() {
        let mut window = CongestionWindow::new(WindowLimits::new(64, 4, 4096, 64));
        assert_eq!(window.capacity(), 64);

        for _ in 0..(8 * 64) {
            window.record_progress();
        }

        assert_eq!(
            window.capacity(),
            71,
            "eight round trips of linear growth, less the rounding that adding \
             one over a window at a time costs"
        );
    }

    /// One burst that needed retries produces a burst of recoveries; halving on
    /// each would collapse the window against a host busy for a millisecond.
    #[test]
    fn one_overloaded_moment_cuts_the_window_once_and_not_fifty_times() {
        let mut window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));
        assert_eq!(window.capacity(), 64);

        for _ in 0..50 {
            window.record_congestion();
        }

        assert_eq!(window.capacity(), 32, "halved, and only once");
        assert_eq!(window.summary().reductions, 1);
    }

    /// The damping lifts once a window's worth of probes has gone out.
    #[test]
    fn a_second_window_of_probes_earns_a_second_reduction() {
        let mut window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));
        window.record_congestion();
        assert_eq!(window.capacity(), 32);

        for _ in 0..32 {
            window.record_send();
        }
        window.record_congestion();

        assert_eq!(window.capacity(), 16);
        assert_eq!(window.summary().reductions, 2);
    }

    /// A reduction stops at the floor.
    #[test]
    fn reduction_stops_at_the_floor() {
        let mut window = CongestionWindow::new(WindowLimits::new(64, 8, 512, 512));

        for _ in 0..20 {
            window.record_congestion();
            for _ in 0..64 {
                window.record_send();
            }
        }

        assert_eq!(window.capacity(), 8);
    }

    /// Growth stops at the ceiling.
    #[test]
    fn growth_stops_at_the_ceiling() {
        let mut window = CongestionWindow::new(WindowLimits::new(16, 4, 32, 1024));

        for _ in 0..1000 {
            window.record_progress();
        }

        assert_eq!(window.capacity(), 32);
        assert_eq!(window.summary().peak, 32);
    }

    /// A probe stops occupying the window at its first outcome, and running out of
    /// round-trip budget is an outcome.
    #[test]
    fn silence_frees_the_slot_it_was_holding() {
        let mut window = CongestionWindow::new(WindowLimits::new(4, 2, 512, 512));

        for _ in 0..4 {
            window.record_send();
        }
        assert!(!window.has_room(), "the window is full of open questions");

        window.release();
        window.record_progress();
        assert!(
            window.has_room(),
            "and one of them has now been answered by silence"
        );
        assert!(
            window.capacity() > 4,
            "which is not congestion, so the window opens rather than closing"
        );
    }

    /// A retry counts toward the damping but takes no slot.
    #[test]
    fn a_retry_costs_no_slot() {
        let mut window = CongestionWindow::new(WindowLimits::new(4, 2, 512, 512));

        window.record_send();
        window.release();
        assert_eq!(window.in_flight(), 0);

        window.record_resend();
        assert_eq!(window.in_flight(), 0, "the slot went back at the timeout");
    }

    /// An answer that arrived only on a repeat frees nothing: the slot went back
    /// when the first attempt timed out.
    #[test]
    fn a_recovery_does_not_free_a_second_slot() {
        let mut window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));

        window.record_send();
        window.release();
        window.record_resend();
        window.record_congestion();

        assert_eq!(window.in_flight(), 0);
    }

    /// A fixed window, as UDP uses, ignores every signal.
    #[test]
    fn a_fixed_window_ignores_every_signal() {
        let mut window = CongestionWindow::new(WindowLimits::fixed(64));

        for _ in 0..100 {
            window.record_progress();
            window.record_congestion();
            window.record_send();
        }

        assert_eq!(window.capacity(), 64);
        assert_eq!(window.summary().reductions, 0);
        assert!(!window.summary().adaptive);
    }

    /// An ambiguous silence that is the exception among a host's answers moves
    /// nothing.
    #[test]
    fn an_occasional_ambiguous_silence_among_answers_moves_nothing() {
        let mut window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 64));

        for outcome in 0..(64 * 20) {
            if outcome % 20 == 0 {
                window.record_ambiguous_silence();
            } else {
                window.record_answer();
            }
        }

        assert_eq!(window.summary().reductions, 0, "one in twenty is not loss");
    }

    /// One silence in ten, the open ports of a service-dense host, is not loss
    /// however the silences fall among the answers.
    #[test]
    fn a_tenth_of_first_outcomes_silent_is_not_loss() {
        let mut window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 64));
        // A fixed LCG, so the silences fall unevenly but deterministically.
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;

        for _ in 0..(64 * 50) {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            if (state >> 33).is_multiple_of(10) {
                window.record_ambiguous_silence();
            } else {
                window.record_answer();
            }
        }

        assert_eq!(window.summary().reductions, 0, "one in ten is not loss");
    }

    /// Silences reach the window bunched, a budget after their answers. The
    /// in-flight credit keeps such a bunch from reading as loss.
    ///
    /// Each round asks sixty-four probes, six of them silent, and the silences of
    /// eight rounds are heard together: forty-eight with no answer between them.
    #[test]
    fn silence_heard_bunched_behind_its_answers_is_not_loss() {
        let mut window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 64));

        for round in 1..=64u32 {
            for _ in 0..64 {
                window.record_send();
            }
            for _ in 0..58 {
                window.release();
                window.record_answer();
            }
            if round.is_multiple_of(8) {
                for _ in 0..(6 * 8) {
                    window.release();
                    window.record_ambiguous_silence();
                }
            }
        }

        assert_eq!(window.summary().reductions, 0, "{:?}", window.summary());
    }

    /// Silence at one in four is loss, bunched or not, and cuts without any
    /// answered retry.
    #[test]
    fn ambiguous_silence_at_a_share_of_loss_cuts_the_window() {
        let mut window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 64));

        for round in 1..=16u32 {
            for _ in 0..64 {
                window.record_send();
            }
            for _ in 0..48 {
                window.release();
                window.record_answer();
            }
            if round.is_multiple_of(4) {
                for _ in 0..(16 * 4) {
                    window.release();
                    window.record_ambiguous_silence();
                }
            }
        }

        assert!(window.summary().reductions > 0, "one in four is loss");
        assert!(window.capacity() < 64);
    }

    /// After the last admission, the silence left in flight is not weighed as
    /// loss.
    #[test]
    fn silence_left_in_flight_after_the_last_admission_is_not_weighed_as_loss() {
        let mut window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 64));
        for _ in 0..(64 * 4) {
            window.record_answer();
        }

        window.stop_admitting();
        for _ in 0..64 {
            window.record_ambiguous_silence();
        }

        assert_eq!(window.summary().reductions, 0);
    }

    /// A dropped probe heard after the last admission does not cut either.
    #[test]
    fn a_dropped_probe_heard_after_the_last_admission_does_not_cut() {
        let mut window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 64));

        window.stop_admitting();
        window.record_loss();
        assert_eq!(window.summary().reductions, 0, "nothing left to pace");

        let mut admitting = CongestionWindow::new(WindowLimits::new(64, 4, 512, 64));
        admitting.record_loss();
        assert_eq!(
            admitting.summary().reductions,
            1,
            "while admitting, it cuts"
        );
    }

    /// After a cut the window climbs back linearly, because the threshold moved
    /// down with it; slow start would double straight back past the capacity it
    /// had just exceeded.
    #[test]
    fn a_window_that_was_cut_climbs_back_slowly_rather_than_doubling() {
        let mut window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));
        window.record_congestion();
        assert_eq!(window.capacity(), 32);

        for _ in 0..(2 * 32) {
            window.record_progress();
        }

        assert_eq!(
            window.capacity(),
            33,
            "two round trips buy two probes, not two doublings"
        );
    }
}
