// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How many questions a scan may have outstanding
//!
//! A scan has to decide how hard to push, and the decision cannot be made in
//! advance. The right answer for a Linux server on a switch is thousands of
//! probes in flight; the right answer for the consumer router next to it is a
//! few dozen, and asking that router at the server's pace does not merely
//! annoy it: it manufactures findings. Probed faster than it will answer, a
//! router reports six hundred ports `filtered` with no more hesitation than it
//! reports the three that really are, and every one of those verdicts is a
//! claim about somebody's firewall that is actually a claim about our send rate.
//!
//! [`CongestionWindow`] makes the decision from evidence instead: it bounds how
//! many probes a scan may have outstanding, grows that bound while answers keep
//! arriving, and cuts it when the answers show the target is being outrun.
//!
//! ## Why a window and not a rate
//!
//! A configured rate is a guess, and it is wrong in both directions at once:
//! too fast for the router, too slow for the server, and no rate is right for a
//! scan that meets both. It is also unanchored: nothing about "four hundred
//! probes a second" refers to anything the target does.
//!
//! A window refers to exactly that. Probes leave as earlier ones are answered,
//! so the send rate settles at the rate the target is *resolving* them, whatever
//! that rate happens to be. It needs no clock, it needs no configuration, and it
//! is self-correcting: a target that slows down is asked more slowly without
//! anybody deciding anything.
//!
//! The engine still has a rate ceiling, and it still means something, but it is
//! a backstop against a defect in this file, not the thing that paces a scan.
//!
//! ## The loss signal, and why it is not the timeout
//!
//! TCP congestion control reduces on a timeout, because for TCP a lost segment
//! means a full queue. A port scanner cannot borrow that rule, because for a
//! scanner an unanswered probe usually means a firewall. Reducing on silence
//! would slow a scan to a crawl against exactly the hosts that are silent by
//! policy, and it would do it worst on the wide, heavily filtered ranges where
//! finishing at all is the whole difficulty.
//!
//! So the rule is narrower, and it turns on *who* is silent:
//!
//! > **Silence from a host that has never spoken is not congestion. Silence from
//! > a host that is otherwise answering us is.**
//!
//! A machine that replies to seven hundred probes and drops two hundred is not
//! running a two-hundred-port block list; it is failing to keep up. A machine
//! that replies to nothing is behind a firewall, or is not there, and asking it
//! more slowly discovers nothing at either. That one distinction separates the
//! cases a timeout-driven controller confuses:
//!
//! | What is happening | What the controller sees | What it does |
//! |---|---|---|
//! | Host answers everything | Answers on the first ask | Grows to the ceiling |
//! | Address is a black hole | Nothing ever answers | Grows; finishes at speed |
//! | Host is being outrun | Timeouts, from a host that talks | Cuts the window |
//! | Host is being outrun badly | Answers arriving only on retries | Cuts the window |
//!
//! The last two are the same fault seen at different times, and both are needed.
//! A recovery is the stronger evidence, the port demonstrably wanted to answer,
//! but it arrives late, and it arrives *not at all* when the retries are lost as
//! well as the first attempt.
//!
//! ## What the narrower rule cost, measured
//!
//! The first version of this file cut only on recoveries, on the reasoning that
//! a timeout might be a firewall. Against a Raspberry Pi on a home network it
//! never cut once, and three consecutive scans of the same host reported this:
//!
//! - eleven ports were open across the three runs; **each run found exactly
//!   seven**, and only one port was found by all three;
//! - roughly two hundred and forty ports came back `filtered` each time, and the
//!   set was reshuffled every run: port 53 filtered once and open twice, port 22
//!   open twice and filtered once.
//!
//! Nothing on that host was filtered. Every one of those verdicts was this
//! scanner's own send rate, reported as somebody's firewall, which is precisely
//! the failure the module was written to prevent, arrived at by a different
//! route.
//!
//! The arithmetic says why the recovery signal never fired. At a quarter of
//! probes lost and three *independent* attempts, an open port is missed one time
//! in seventy: eleven open ports should have come back as nearly eleven, not
//! seven. Seven means the attempts were not independent: all three of them fell
//! inside the same congested moment, so nothing was ever recovered on a retry and
//! the controller was handed no evidence at all. A signal that only fires once
//! the target has recovered is a signal that goes quiet exactly when the target
//! is worst off.
//!
//! ## What occupies the window
//!
//! A probe holds a slot **from its first send until its first outcome**, and its
//! first outcome is either an answer or the expiry of its round-trip budget.
//! After that it is in the retry schedule rather than in flight, and it holds
//! nothing.
//!
//! That line is not a detail; getting it wrong is the difference between a
//! working scanner and an unusable one. Hold the slot until the probe is
//! finally resolved and a firewalled port occupies the window for its whole
//! retry lifetime: most of two seconds, against a round trip of one
//! millisecond. A thousand filtered ports through a window of thirty-two is then
//! a minute of waiting for silence the scan had already heard, and the target
//! that is hardest to finish throttles the scan exactly as a congested one does.
//! Which is the confusion this whole module exists not to make.
//!
//! Retries are not readmitted. They are real packets and they count toward the
//! damping below, but a question already given up on once does not take a slot
//! back from a question nobody has asked yet.
//!
//! ## Growth, reduction and damping
//!
//! Growth is TCP's, because TCP's is right here: exponential while the window is
//! below [`WindowLimits::slow_start_threshold`], linear above it. Slow start is
//! what gets a scan up to speed in a handful of round trips instead of a
//! thousand; the threshold is what stops it overshooting a target's capacity by
//! a factor of two before it notices.
//!
//! A probe that timed out against a silent host grows the window exactly as an
//! answered one does. That reads backwards until the rule above is taken
//! seriously: nothing that host does is evidence about capacity, and asking it
//! more slowly discovers nothing. Against an address that answers nothing at all,
//! a firewalled host, a dead address in a range, this is what lets the scan
//! open up and finish, instead of creeping through at whatever window it
//! happened to start with.
//!
//! So every probe yields exactly one signal, and the caller decides which by
//! answering one question about it: did anything about this outcome say the
//! target is failing to keep up?
//!
//! Reduction halves, and then **refuses to halve again until the window's worth
//! of probes has been released**. Without that, one overloaded moment collapses
//! the window: a burst of fifty probes that all needed retries is fifty
//! recoveries arriving together, and fifty halvings is the floor. One reduction
//! per window of sends is the same rule TCP applies for the same reason, phrased
//! in probes rather than in round trips because a scanner already counts probes
//! and would have to invent the round trip.
//!
//! ## What is not a signal
//!
//! A frame the kernel's capture buffer dropped is loss too, and unlike a
//! timeout it is unambiguous: the reply arrived and this process was too busy
//! to take it. It is not wired in here, because it does not need to be: the
//! probe whose reply was dropped times out, is sent again, and is answered, and
//! that is a recovery like any other. Reading the counter as well would react
//! one round trip sooner and cost a poll in the receive loop for a case the
//! controller already handles. The counter is reported to the operator instead,
//! by [`ProbeAudit`](crate::scanner::audit::ProbeAudit), because a receive path
//! that cannot keep up is a fact about their machine rather than about the
//! network, and no amount of pacing makes that the right thing not to say.
//!
//! ## Where it applies, and where it does not
//!
//! TCP port scanning, where silence is exceptional and an answer is the norm.
//! Not UDP: a UDP probe's ordinary outcome *is* silence, and the ledger
//! cannot tell which attempt a reply answered because a UDP probe carries
//! nothing for the reply to echo. Both halves of the signal are missing, so a
//! UDP scan keeps a window that does not move, [`WindowLimits::fixed`], and
//! stays paced by the fixed rate its ICMP rate limiter demands. A controller fed
//! no evidence is not a conservative controller, it is a random one.

use crate::report::WindowSummary;

/// The bounds a [`CongestionWindow`] moves within, and where it starts.
///
/// Declared per scanner beside its retry policy and deadline profile, since what
/// counts as a reasonable number of outstanding questions is a property of the
/// protocol and of what answers it.
///
/// `#[non_exhaustive]`, along with the three other pacing configurations, and
/// for the reason they share: these are the knobs a controller gains a field of
/// every time somebody measures something new, this module having recorded
/// three such measurements already, and every one of them is read here rather
/// than pattern-matched by a consumer. Closing the literal costs a caller
/// [`new`](Self::new) instead of a struct expression, and it is what keeps
/// [`new`](Self::new)'s bounds check from being walked around.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct WindowLimits {
    /// The window before anything has been learned.
    ///
    /// Not one. A scan that begins with a single outstanding probe spends a
    /// round trip per doubling to reach a useful size, and on a local segment
    /// that is most of the scan. Every stack in service will answer a few dozen
    /// simultaneous probes, so starting there costs nothing and saves several
    /// round trips of ramp.
    pub initial: u32,
    /// The smallest window a reduction may reach. Below this a scan stops making
    /// progress rather than merely being polite.
    pub floor: u32,
    /// The largest window growth may reach, whatever the evidence.
    ///
    /// It bounds correlation state as much as traffic: every outstanding probe
    /// is a ledger entry and a timer, and a scan waiting on more answers than
    /// this is not getting them sooner.
    pub ceiling: u32,
    /// Where exponential growth gives way to linear.
    ///
    /// Slow start doubles the window every round trip, which is how a scan
    /// reaches useful speed quickly and also how it sails past a target's
    /// capacity before the first recovery arrives to say so. The threshold is
    /// the size past which the scan stops guessing upward and starts creeping.
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
    /// Not a disabled feature: it is the correct configuration for UDP, where
    /// silence is the ordinary outcome and no reply names the attempt it
    /// answers. See the module documentation.
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
/// another target, and reports three things back: that a probe was sent, that
/// one was answered, and that one was answered *only after being sent again*.
/// The last is the loss signal and the reason this type can tell a slow host
/// apart from a firewalled one; the module documentation has the argument.
#[derive(Debug, Clone)]
pub struct CongestionWindow {
    limits: WindowLimits,
    /// Fractional, so linear growth can add a fraction of a probe per answer and
    /// arrive at one probe per window rather than rounding to nothing.
    window: f64,
    threshold: f64,
    /// Questions currently awaiting an answer: sent, and neither answered nor
    /// yet out of round-trip budget. What [`capacity`](Self::capacity) bounds.
    in_flight: u32,
    /// Probes released since the last reduction, against which
    /// [`epoch`](Self::epoch) is compared.
    since_reduction: u32,
    /// How many probes must be released before another reduction is allowed:
    /// the window as it stood when the last one happened.
    epoch: u32,
    peak: usize,
    reductions: u32,
}

impl CongestionWindow {
    /// A window at its starting size, with nothing learned yet.
    ///
    /// Bounds that disagree do not panic. `floor` and `ceiling` are adjacent
    /// arguments of one type on a public constructor, so a caller can cross
    /// them; the floor wins, for the reason
    /// [`suggest_timeout`](super::rtt_window::RttWindow::suggest_timeout) and
    /// [`ProbeLedger`](super::retry::ProbeLedger) give. A crossed pair then
    /// describes a range with nothing in it, so the window is stationary and
    /// reports itself as such through [`WindowSummary::adaptive`]. `u32::clamp`
    /// asserted instead, and took the scan down before that logic could run.
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
            // Zero, so the first recovery is acted on rather than damped. The
            // damping exists to stop one bad moment being counted many times,
            // not to ignore the first evidence a scan ever gets.
            epoch: 0,
            peak: window as usize,
            reductions: 0,
        }
    }

    /// The most questions that may be awaiting an answer right now.
    ///
    /// Never zero: a window that admits nothing is a scan that cannot make
    /// progress, and the floor is what a reduction is allowed to reach rather
    /// than a value it may pass through.
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
    /// It is real traffic, so the damping has to see it: the window's worth of
    /// sends between reductions is a count of packets, not of targets. It takes
    /// no slot because the slot was released when the question it repeats ran
    /// out of round-trip budget; see the module documentation on what occupies
    /// the window.
    pub fn record_resend(&mut self) {
        self.since_reduction = self.since_reduction.saturating_add(1);
    }

    /// Releases the slot one question was holding.
    ///
    /// Separate from the two signals below, and it has to be: a question can end
    /// in a way that says the target is struggling (a timeout from a host that
    /// is otherwise answering) or in a way that says nothing (silence from a
    /// host that answers nothing), and both free the slot. Folding the release
    /// into either signal would mean the other one leaked.
    ///
    /// Call it exactly once per question, on whichever event ends it first: an
    /// answer, or the expiry of its round-trip budget. Never on a retry: the
    /// slot went back when the question the retry repeats ran out of budget.
    pub fn release(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }

    /// Records an outcome that carried no sign of the target failing to keep up:
    /// answered on the first ask, or silence from a host that answers nothing
    /// anyway.
    ///
    /// Grows the window. See the module documentation for why the second of
    /// those grows it rather than shrinking it.
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
    /// Halves the window, then refuses to halve again until that many probes
    /// have been released.
    pub fn record_congestion(&mut self) {
        if !self.limits.adaptive() || self.since_reduction < self.epoch {
            return;
        }

        self.threshold = (self.window / 2.0).max(f64::from(self.limits.floor));
        self.window = self.threshold;
        self.epoch = self.capacity() as u32;
        self.since_reduction = 0;
        self.reductions = self.reductions.saturating_add(1);
    }

    /// Releases every slot still held, for a scan that is stopping before its
    /// outstanding questions could be settled on their own.
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

    /// `floor` and `ceiling` are adjacent `u32`s on a public constructor, so a
    /// caller can cross them. `u32::clamp` asserted, which turned that into a
    /// panic in the caller's process, two lines before the `adaptive` check
    /// that already handles a range with nothing in it.
    #[test]
    fn crossed_bounds_freeze_the_window_rather_than_panicking() {
        let window = CongestionWindow::new(WindowLimits::new(10, 100, 50, 20));

        assert_eq!(window.capacity(), 100, "the floor wins");
        assert!(
            !window.summary().adaptive,
            "and a range with nothing in it cannot move"
        );
    }

    /// Growth and reduction are both no-ops on such a window, so nothing
    /// downstream has to know the bounds were crossed.
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

    /// Below the threshold the window doubles per round trip's worth of
    /// answers, which is what gets a scan up to speed in a handful of round
    /// trips rather than a thousand.
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

    /// Past the threshold it creeps instead, so a scan that has found a target's
    /// working pace does not immediately overshoot it again.
    ///
    /// Eight round trips' worth of answers buy eight more probes rather than
    /// eight doublings: the same eight round trips of slow start would have
    /// asked for sixteen thousand.
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

    /// The reason this type exists. A halving per recovery would collapse the
    /// window on the first overloaded moment, because one burst that needed
    /// retries produces a burst of recoveries, and the scan would then crawl
    /// against a host that was merely busy for a millisecond.
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

    /// The damping lifts once the window's worth of probes has gone out, so a
    /// target that is still being outrun is still cut back.
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

    /// A reduction stops at the floor. Past it a scan is not being polite, it is
    /// failing to finish, and the verdicts it does not reach are indeterminate
    /// rather than merely late.
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

    /// Growth stops at the ceiling, which bounds correlation state as much as
    /// traffic: a scan waiting on more answers than this is not getting them
    /// sooner.
    #[test]
    fn growth_stops_at_the_ceiling() {
        let mut window = CongestionWindow::new(WindowLimits::new(16, 4, 32, 1024));

        for _ in 0..1000 {
            window.record_progress();
        }

        assert_eq!(window.capacity(), 32);
        assert_eq!(window.summary().peak, 32);
    }

    /// The rule the whole controller turns on: a question stops occupying the
    /// window the moment it is settled, and running out of round-trip budget is
    /// a settlement.
    ///
    /// Held instead until the probe was finally retired, a firewalled port would
    /// occupy a slot for its whole retry lifetime, most of two seconds against
    /// a round trip of one millisecond, and a thousand of them through a small
    /// window is a minute of waiting for silence the scan had already heard.
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

    /// A retry is traffic and the damping has to count it, but it is a repeat of
    /// a question already given up on, so it must not take a slot back from a
    /// question nobody has asked yet.
    #[test]
    fn a_retry_costs_no_slot() {
        let mut window = CongestionWindow::new(WindowLimits::new(4, 2, 512, 512));

        window.record_send();
        window.release();
        assert_eq!(window.in_flight(), 0);

        window.record_resend();
        assert_eq!(window.in_flight(), 0, "the slot went back at the timeout");
    }

    /// An answer that arrived only on a repeat frees nothing, because the slot
    /// went back when the first attempt timed out. Freeing it twice would let
    /// the window admit more than it believes it has.
    #[test]
    fn a_recovery_does_not_free_a_second_slot() {
        let mut window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));

        window.record_send();
        window.release();
        window.record_resend();
        window.record_congestion();

        assert_eq!(window.in_flight(), 0);
    }

    /// A UDP scan has neither half of the signal, silence is its ordinary
    /// outcome and its replies name no attempt, so its window is told to hold
    /// still, and nothing it is fed may move it.
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

    /// After a cut, the window has to be able to climb back: a target that was
    /// briefly busy is not a target that must be asked slowly forever.
    ///
    /// It climbs back *linearly*, and that is the point of moving the threshold
    /// down with the window rather than leaving it where it was. A scan that
    /// re-entered slow start after every cut would double straight back into the
    /// capacity it had just been told it exceeded.
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
