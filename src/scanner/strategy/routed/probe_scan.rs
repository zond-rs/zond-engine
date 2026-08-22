// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What every raw port scan does the same way
//!
//! A raw port scan is the same machine whatever protocol it speaks: send probes
//! from one source port as fast as pacing allows, correlate what comes back,
//! resend what goes unanswered until its budget runs out, and stop when one of
//! four things becomes true. Only the packets and what they prove differ.
//!
//! Two pieces make up that machine, and the division between them is the point
//! of the module. [`RawProbeScan`] is the state a raw port scan carries and the
//! questions it can answer about itself. [`run`] is the loop that asks them,
//! and [`RawPortScan`] is the short list of things it cannot work out alone.
//!
//! The TCP and UDP port scanners each hold a [`RawProbeScan`] and implement
//! [`RawPortScan`]. What stays with them is what is genuinely protocol
//! knowledge: how a probe is built, how a reply is recognised, what an answer
//! proves about a port and its host, and what silence means once a probe has
//! spent its budget.
//!
//! ## Why this line and not a different one
//!
//! The split is drawn where the two scanners were *identical*, not merely
//! similar. Their stop conditions, their pacing arithmetic, their unreachable
//! handling, their audit tails and the loop that drives all of it were
//! duplicated with no difference but a label, while their probe construction
//! and their evidence mapping differed in almost every line, because a RST and
//! an ICMP port unreachable prove genuinely different things. Sharing the first
//! and not the second is what keeps this an abstraction rather than a
//! coincidence.
//!
//! Where the two copies of the loop did differ, they differed in four
//! expressions: which protocol to accept, what silence means, and two labels.
//! [`RawPortScan`] is those four, written down.
//!
//! ## Why the shared half is the half worth sharing
//!
//! The four stop conditions are the subtlest code in either scanner and the
//! least visible when wrong. Each one is a claim about what silence means, and
//! stopping on the wrong one does not fail — it returns a smaller answer that
//! looks exactly like a quiet network. This engine has already paid for that
//! once: `docs/bugs.md` records a stop condition fixed in one discovery scanner
//! and left standing in its twin, because nothing tied the two together. One
//! copy is what makes that class of divergence impossible rather than merely
//! unlikely.
//!
//! ## Writing a third one
//!
//! Everything here is public because the argument above applies to a scanner
//! this engine does not have yet. An SCTP INIT scan, or any protocol added
//! later, needs the same stop conditions, the same congestion window and the
//! same audit tail; implementing [`RawPortScan`] gets all of it, and the only
//! code to write is the part that is actually about the protocol.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::journal::settle::{Fate, Settlement};
use crate::model::host::{HostStatus, StatusProtocol, StatusReason};
use crate::model::port::{PortState, Protocol};
use crate::model::target::Target;
use crate::scanner::audit::ProbeAudit;
use crate::scanner::pacing::congestion::CongestionWindow;
use crate::scanner::pacing::deadline::AdaptiveDeadline;
use crate::scanner::pacing::retry::{Due, ProbeLedger, Resolution};
use crate::scanner::report::StopReason;
use crate::scanner::session::{ScanContext, ScannerKind};
use crate::scanner::strategy::PortScanner;
use crate::system::interface::SourceResolver;
use crate::transport::capture::CapturedSegment;
use crate::transport::probe::ProbeTransport;

/// A probe's identity within a scan: which address, which port.
pub type ProbeTarget = (IpAddr, u16);

/// The state a raw port scan carries, and everything it does that does not
/// depend on which protocol it speaks.
///
/// Generic over the correlation token `T`, the one piece of per-probe state
/// whose type differs: a TCP probe carries a nonce that its answer must echo
/// back, and a UDP probe has nothing to echo, so it correlates on the target
/// alone and its token is `()`.
pub struct RawProbeScan<T> {
    /// Resolves the source address to send each target's probe from, consulting
    /// on-link subnets and the kernel routing table. Each answer is cached, so
    /// the many ports probed on one host cost a single lookup.
    pub resolver: SourceResolver,
    /// Shared state (host store, event channel, abort signal) for the scan this
    /// prober is part of.
    pub ctx: ScanContext,
    /// Sends probes and receives replies.
    pub transport: ProbeTransport,
    /// Governs how long this scan keeps running, adapting to observed
    /// round-trip times.
    pub deadline: AdaptiveDeadline,
    /// Probes sent but not yet resolved, together with when each is next due to
    /// be resent or written off.
    pub ledger: ProbeLedger<ProbeTarget, T>,
    /// Scratch space for the probes coming due on one iteration, reused so a
    /// quiet tick allocates nothing.
    pub due: Vec<Due<ProbeTarget>>,
    /// The source port every probe in this scan is sent from, and so the port
    /// its replies come back to. It is the scan's identity on the wire: the
    /// capture filter narrows to it, and anything addressed elsewhere answered
    /// somebody else.
    pub src_port: u16,
    /// Why the first probe that could not be sent failed, if any did.
    ///
    /// The *first*, and the send path keeps it that way by only recording when
    /// this is empty. It used to hold the last, which on a link that had stopped
    /// accepting sends meant the report named whichever of seven thousand
    /// identical failures happened to finish the run.
    ///
    /// Without this a scan whose probes never reached the wire reports every
    /// port with whatever its protocol reads silence as - the same answer a
    /// firewall produces - and says nothing about the difference. That verdict
    /// is a claim about the network; a probe that was never sent is a claim
    /// about this host.
    pub send_failure: Option<String>,
    /// Per-run counters, so a scan that classified fewer ports than it asked
    /// about can be attributed to loss, to its own deadline, or to correlation
    /// rather than guessed at. Reported once when the loop exits.
    pub audit: ProbeAudit,
    /// How many questions this scan may have awaiting an answer, grown and cut
    /// from what the targets are managing to answer.
    ///
    /// **This is what paces a raw port scan**, and it is the answer to a
    /// question a fixed rate cannot answer. Measured, against a consumer router:
    /// asked as fast as the socket would take it, of a thousand ports it
    /// answered roughly four hundred and the rest were reported *filtered* —
    /// including one running a service. The host was not filtering anything. It
    /// was answering as fast as it could and being asked ten times faster.
    ///
    /// A rate chosen in advance is wrong in both directions at once: too fast
    /// for that router and far too slow for the Linux server on the same
    /// switch. A window is not chosen in advance. Probes leave as earlier ones
    /// are settled, so the send rate settles at the rate the target is actually
    /// resolving them. See [`congestion`](crate::scanner::pacing::congestion)
    /// for what occupies it, how it grows, what makes it cut, and why UDP is
    /// given one that does not move.
    pub window: CongestionWindow,
    /// How long to wait between releases, and the most probes one release may
    /// contain.
    ///
    /// The **backstop**, not the pacing. It exists so that a defect in
    /// [`window`](Self::window) cannot turn a scan into a flood, and so that a
    /// caller who asks for a specific rate gets one. On a healthy scan the
    /// window binds far below it and this never engages; `pacing_for` in the
    /// parent module has how the pair is derived from a rate.
    pub send_tick: Duration,
    /// The most probes one tick releases. See [`send_tick`](Self::send_tick).
    pub batch: usize,
    /// The most probes this scan leaves unresolved at once.
    ///
    /// A bound on memory and correlation state, not on pace — see
    /// [`admitting`](Self::admitting) for why the two are separate. A probe
    /// leaves the [`window`](Self::window) at its first timeout and stays on the
    /// ledger until its last, so against a range that answers nothing the
    /// backlog between those two points is what grows, and this is what bounds
    /// it.
    pub max_unresolved: usize,
}

impl<T: Copy + PartialEq> RawProbeScan<T> {
    /// Whether the loop should keep going, and if not, why it stopped.
    ///
    /// The four conditions in the order that makes each one's answer mean
    /// something. `sending_finished` says the target stream has run dry, which
    /// two of them depend on: an empty ledger means "everything has been
    /// answered or written off" only once there is nothing left to ask.
    ///
    /// - **Aborted.** The caller asked to stop. Checked first, so a scan winds
    ///   down promptly rather than after whatever else it was in the middle of.
    /// - **Hard deadline.** The ceiling on the whole run, which nothing extends.
    /// - **Attempts spent.** Every probe asked as many times as its budget
    ///   allows and none is still outstanding. Waiting longer cannot change what
    ///   this found.
    ///
    /// **Silence is deliberately not one of them.** It reads as a fourth
    /// condition and it cannot be one: with targets still queued, an empty
    /// ledger does not mean the scan has heard nothing, it means the scan has
    /// not *asked* yet — and the way that happens is the send path failing. A
    /// loop that gave up there would abandon everything still queued at the
    /// moment its own machine started refusing sends, and report the remainder
    /// as ports nobody could reach. Measured: a wireless host whose ARP entry
    /// went unresolved mid-scan returned `No route to host` for seven thousand
    /// probes, and the scan concluded after thirty seconds with thirty-one
    /// thousand targets never asked about.
    ///
    /// What still bounds the run is the hard deadline, which nothing extends.
    pub fn stop_reason(&self, sending_finished: bool) -> Option<StopReason> {
        if self.ctx.handle.should_stop() {
            return Some(StopReason::Aborted);
        }
        if self.deadline.hard_deadline_passed() {
            return Some(StopReason::DeadlineExpired);
        }
        if sending_finished && self.ledger.is_empty() {
            return Some(StopReason::AttemptsSpent);
        }
        None
    }

    /// Whether another target may be admitted from the stream.
    ///
    /// Three conditions, and they answer different questions. The stream may be
    /// done. The [`window`](Self::window) may be full, which is the pacing: too
    /// many questions are already awaiting an answer, and asking another would
    /// cost verdicts against a target that is being outrun. Or the ledger may be
    /// at [`max_unresolved`](Self::max_unresolved), which is not pacing at all
    /// but a bound on memory — a probe stays on the ledger long after it has
    /// stopped occupying the window, waiting out a retry schedule, and against a
    /// wide scan of a silent range that backlog is what grows without limit.
    pub fn admitting(&self, sending_finished: bool) -> bool {
        !sending_finished && self.window.has_room() && self.ledger.len() < self.max_unresolved
    }

    /// Records one probe leaving the wire, or failing to.
    ///
    /// Both halves of the bookkeeping in one call because they are one event and
    /// were drifting apart: the audit counts every attempt so a scan that could
    /// not send can say so, and the window counts only the ones that reached the
    /// wire, since a probe nobody sent occupied nothing and must not be part of
    /// the evidence that the path is busy.
    ///
    /// `first_attempt` decides whether the send takes a window slot. A retry
    /// does not: the slot went back when the question it repeats ran out of
    /// round-trip budget, and handing it back a second time would let the window
    /// admit more than it believes it has.
    pub fn record_send(&mut self, sent: bool, first_attempt: bool) {
        self.audit.record_send(sent);
        match (sent, first_attempt) {
            // A send the kernel refused is the one signal this controller gets
            // from *its own machine* rather than from the network, and it is the
            // least ambiguous one there is. Whatever the reason — a full
            // interface queue, an unresolved neighbour, a link that has stopped
            // keeping up — offering it more of the same faster cannot help. So
            // it is read as congestion, and the damping bounds how far a
            // permanent failure can cut.
            (false, _) => self.window.record_congestion(),
            (true, true) => self.window.record_send(),
            (true, false) => self.window.record_resend(),
        }
    }

    /// Reads one probe's first timeout: frees the window slot it was holding,
    /// and decides what the silence meant.
    ///
    /// The whole of the decision is whether `host` has ever answered anything.
    /// See [`service_retries`](RawPortScan::service_retries) for the argument
    /// and [`congestion`](crate::scanner::pacing::congestion) for what it cost
    /// to get wrong.
    pub fn judge_timeout(&mut self, host: IpAddr) {
        self.window.release();
        if self.ledger.host_has_answered(&host) {
            self.window.record_congestion();
        } else {
            self.window.record_progress();
        }
    }

    /// Folds one answered probe into everything this scan tracks about itself:
    /// the deadline, the window and the audit.
    ///
    /// One place rather than one per protocol, because the three used to be
    /// three statements repeated in each scanner and the window is a fourth that
    /// would have been added to one of them.
    ///
    /// The window reads the *attempt* that was answered, not merely that
    /// something was. A reply to the first attempt says the target is keeping
    /// up; a reply to a later one says the target was willing all along and the
    /// first question did not survive, which is the only evidence a port scanner
    /// has that distinguishes being too fast from meeting a firewall. See
    /// [`congestion`](crate::scanner::pacing::congestion).
    pub fn record_answer(&mut self, resolution: &Resolution) {
        self.deadline.mark_activity();
        if let Some(rtt) = resolution.rtt {
            self.deadline.record_rtt(rtt);
        }

        // Three cases, and the middle one is the reason this reads the attempt
        // rather than the fact of an answer.
        match (resolution.attempts, resolution.answered_attempt) {
            // Asked once and answered: the slot is still held, and the target is
            // keeping up.
            (1, _) => {
                self.window.release();
                self.window.record_progress();
            }
            // Answered only because it was asked again: the target was willing
            // all along and the first ask did not survive. The slot went back at
            // that timeout, so this cuts and frees nothing.
            (_, Some(attempt)) if attempt > 1 => self.window.record_congestion(),
            // Answered late — the first ask was answered after its budget had
            // already expired, which the per-attempt token is what lets us see.
            // The timeout already released the slot and already judged it, and
            // doing either again would double-count.
            _ => {}
        }

        self.audit.record_host_found(resolution.answered_attempt);
    }

    /// How long the loop may sleep: until the scan's own next checkpoint, or
    /// until the next probe needs resending or retiring, whichever comes first.
    pub fn tick_delay(&self, now: Instant) -> Duration {
        let until_deadline_tick = self.deadline.time_until_next_tick();
        match self.ledger.next_due() {
            Some(due) => until_deadline_tick.min(due.saturating_duration_since(now)),
            None => until_deadline_tick,
        }
    }

    /// Seeds each host's retry timing from what an earlier phase already
    /// measured about it.
    ///
    /// A port scan almost never meets its targets cold — [`scan`](crate::scan)
    /// establishes that an address is there before spending a probe on each of
    /// its ports, and that liveness pass timed every host that answered. Without
    /// this the port scanner starts from first principles anyway, and the cost
    /// falls entirely on the ports that turn out to be filtered: each one waits
    /// the unmeasured starting timeout three times before silence is allowed to
    /// mean anything.
    ///
    /// Called once at construction rather than per probe. The store is finished
    /// being written by the time a port scanner is built, and a lookup per
    /// target would repeat the same answer for every port of a host.
    ///
    /// The median rather than the minimum, because a retry schedule sized from
    /// the fastest sample a host ever produced repeats every probe that is
    /// merely typical.
    pub fn seed_timing(&mut self) {
        for host in self.ctx.store.iter() {
            if let Some(rtt) = host.value().median_rtt() {
                self.ledger.seed_host_rtt(*host.key(), rtt);
            }
        }
    }

    /// Records that `sender` said the target cannot be reached.
    ///
    /// A host verdict rather than a port one: an unreachable names the
    /// destination it refers to, and nothing about any particular port on it.
    pub fn record_host_down(&mut self, ip: IpAddr, sender: IpAddr) {
        self.ctx.update_host(ip, |host| {
            host.record_evidence(
                HostStatus::Down,
                StatusReason::new(StatusProtocol::IcmpUnreachable, "destination unreachable")
                    .from_source(sender),
            );
        });
    }

    /// Closes out a run: reports probes that never reached the wire, then files
    /// the audit.
    ///
    /// `silence_verdict` is what this scan's protocol reads an unanswered probe
    /// as, named in the failure message so the two cases are distinguishable to
    /// whoever reads it. A scan that could not send is not a scan that found
    /// everything unanswered, and those are identical in every number a caller
    /// otherwise sees.
    ///
    /// Capture counters are read here, while the transport is still alive: they
    /// live with the capture threads it keeps running.
    pub fn finish(
        &mut self,
        kind: ScannerKind,
        audit_tag: &str,
        silence_verdict: &str,
        probes: u128,
        reason: StopReason,
    ) {
        if self.audit.sends_failed > 0 {
            self.ctx.record_failure(
                kind,
                format!(
                    "{} probes could not be sent, so their ports are reported \
                     {silence_verdict} without having been asked: {}",
                    self.audit.sends_failed,
                    self.send_failure.as_deref().unwrap_or("cause unrecorded"),
                ),
            );
        }

        let capture = self.transport.capture_counts();
        self.audit
            .report(audit_tag, probes, reason, capture, Some(self.window.summary()));
        self.ctx.record_probe_stats(self.audit.stats(
            kind,
            probes,
            reason,
            capture,
            Some(self.window.summary()),
        ));
    }
}

/// What a raw port scan has to supply that [`run`] cannot work out for itself.
///
/// Everything below is protocol knowledge: which transport this scan speaks,
/// how it builds a probe, how it reads a reply, what a verdict proves about the
/// host behind the port, and what silence means once a probe has spent its
/// budget. [`run`] supplies the rest, which is the loop those answers are fed
/// into.
///
/// The division is the same one [`RawProbeScan`] draws and for the same reason:
/// a RST and an ICMP port unreachable prove genuinely different things, while
/// the machinery that decides when to stop asking does not know the difference
/// and should not have to.
pub trait RawPortScan: PortScanner {
    /// The per-probe correlation token. A TCP probe carries a nonce its answer
    /// must echo; a UDP probe has nothing to echo and uses `()`.
    type Token: Copy + PartialEq;

    /// The shared machinery this scan is built around.
    fn core(&self) -> &RawProbeScan<Self::Token>;

    /// The same, mutably.
    fn core_mut(&mut self) -> &mut RawProbeScan<Self::Token>;

    /// The transport this scan probes. Targets of any other protocol are not
    /// this scanner's to answer and are passed over.
    fn protocol(&self) -> Protocol;

    /// The verdict a probe takes once every attempt has gone unanswered.
    ///
    /// For UDP always [`PortState::OpenFiltered`], since an open port that did
    /// not recognise the payload is silent exactly as a firewall is. For TCP it
    /// depends on the technique: silence means a filter where any live stack
    /// would have answered, and open-or-filtered where an open port is required
    /// to ignore the probe.
    fn silence_means(&self) -> PortState;

    /// What the audit files this run under, and how its failure message names a
    /// port nobody answered for.
    ///
    /// The second half exists so a scan whose probes never reached the wire
    /// reads as what it is. Reporting "3000 ports unanswered" and "3000 ports
    /// open-filtered" describe the same silence, and only one of them is the
    /// word that scan's protocol would have used.
    fn audit_labels(&self) -> AuditLabels;

    /// Sends one probe at `(ip, port)` and arms the ledger for it.
    ///
    /// Called for the first attempt and every retry alike. A probe that cannot
    /// be sent is simply not armed: the ledger has already charged the attempt
    /// by the time a retry reaches here, so an unroutable target still runs out
    /// of attempts on schedule rather than waiting outstanding forever.
    fn probe(&mut self, ip: IpAddr, port: u16, now: Instant);

    /// Reads one captured reply and resolves whatever probe it answers.
    fn handle_reply(&mut self, reply: &CapturedSegment, now: Instant);

    /// Files a port verdict and whatever the reply that produced it proves
    /// about the host.
    ///
    /// `sender` is the address the reply came from, or `None` when the verdict
    /// came from a spent attempt budget rather than from a packet.
    fn record_port(&mut self, ip: IpAddr, port: u16, state: PortState, sender: Option<IpAddr>);

    /// Records what became of one target, as distinct from the verdict
    /// [`record_port`](Self::record_port) gave it.
    ///
    /// **The two are deliberately not the same call.** Every fate reaches
    /// `record_port` with the same silence verdict — that is the engine's
    /// considered choice, because an absent port is the one shortfall a reader
    /// cannot see. A resume cannot afford the same kindness: skipping a target
    /// that was never probed produces a merged report claiming coverage it never
    /// had. So the fate is reported where it is known, and only
    /// [`Fate::is_settled`] decides what the next sitting may skip.
    fn settle(&mut self, ip: IpAddr, port: u16, fate: Fate) {
        let protocol = self.protocol();
        self.core()
            .ctx
            .record_settlement(Settlement::new(ip, port, protocol, fate));
    }

    /// Probes `target`, if it is one this scan speaks the protocol for.
    ///
    /// A target of another protocol is passed over rather than refused. The
    /// [`CompositePortScanner`](crate::scanner::strategy::composite::CompositePortScanner)
    /// routes by protocol and so should never send one, which is exactly why
    /// this holds: a router that started making mistakes would otherwise have
    /// this scanner probe a UDP port with a TCP segment.
    fn send_probe(&mut self, target: Target) {
        if target.protocol == self.protocol() {
            self.probe(target.ip, target.port, Instant::now());
        }
    }

    /// Resends everything due and writes off everything that has run out of
    /// attempts.
    ///
    /// Exhaustion is what makes a silent verdict mean something: nothing
    /// arrived across every attempt, rather than nothing arrived once.
    /// Retiring probes here rather than at the end of the scan also streams
    /// results to the caller while it is still running, and frees room under
    /// the [`window`](RawProbeScan::window) for the targets queued behind
    /// them.
    ///
    /// Running out of attempts is deliberately not treated as activity, so it
    /// never extends the scan's own deadline. Nothing answered.
    ///
    /// A probe's **first** timeout is also what releases its slot in the
    /// congestion window and what tells the window how the target is coping —
    /// whichever event carries that timeout, the retry that follows it or the
    /// exhaustion that follows it when the budget was one attempt.
    ///
    /// Which of the two signals it carries depends on the host and not on the
    /// probe. A host that has never answered anything is behind a firewall or is
    /// not there, and its silence says nothing about capacity; a host that is
    /// answering most of what it is asked and dropping the rest is being outrun,
    /// and that is the only warning a scan gets before it starts reporting a
    /// firewall that is not there. See
    /// [`congestion`](crate::scanner::pacing::congestion).
    fn service_retries(&mut self, now: Instant) {
        let core = self.core_mut();
        core.ledger.drain_due(now, &mut core.due);

        // Taken so the sends below can borrow `self` mutably; the buffer itself
        // is reused, so this costs no allocation.
        let due = std::mem::take(&mut self.core_mut().due);
        let silence = self.silence_means();
        for event in &due {
            match *event {
                Due::Retry {
                    key: (ip, port),
                    attempt,
                } => {
                    if attempt == 2 {
                        self.core_mut().judge_timeout(ip);
                    }
                    self.probe(ip, port, now);
                }
                Due::Exhausted {
                    key: (ip, port),
                    attempts,
                } => {
                    if attempts == 1 {
                        self.core_mut().judge_timeout(ip);
                    }
                    self.record_port(ip, port, silence, None);
                    // Earned: asked as many times as the policy allows. The one
                    // silence a resume may skip.
                    self.settle(ip, port, Fate::Exhausted);
                }
            }
        }
        let core = self.core_mut();
        core.due = due;
        core.due.clear();
    }

    /// Gives every probe still outstanding the verdict this scan reads silence
    /// as.
    ///
    /// [`service_retries`](Self::service_retries) retires most probes as their
    /// budgets run out; what reaches here are the ones still mid-schedule when
    /// the scan itself ended.
    fn resolve_remaining(&mut self) {
        self.core_mut().window.release_all();
        let silence = self.silence_means();
        for (ip, port) in self.core_mut().ledger.drain_unresolved() {
            self.record_port(ip, port, silence, None);
            // Assigned, not earned: the retry schedule was cut off rather than
            // spent, so the next sitting has to ask again.
            self.settle(ip, port, Fate::Interrupted);
        }
    }

    /// Gives the verdict to every target that was never asked at all.
    ///
    /// A scan that hits its deadline with targets still queued used to leave
    /// them with no record whatsoever — not a filtered port, not an unknown one,
    /// simply absent from the host as though nobody had ever named it. That is
    /// the worst of the three ways a scan can fall short, because it is the only
    /// one a reader cannot see: a truncated port list and a complete one look
    /// identical, and the count in the summary agrees with itself.
    ///
    /// So they take the same verdict silence takes, and are counted. The verdict
    /// is arguably too kind — nothing was asked, so nothing was learned — but a
    /// port reported as this scan's silence alongside a stop reason of
    /// `DeadlineExpired` is a fact somebody can act on, and an absent port is
    /// not.
    ///
    /// **What is already queued, and no more.** Waiting for the dispatcher to
    /// finish emitting would let a scan of a very large range spend longer
    /// filing verdicts than it spent scanning, and the deadline that stopped it
    /// is a guarantee of termination that this must not quietly undo. For every
    /// scan smaller than the dispatcher's buffer — which is every scan whose
    /// port list a person wrote — the queue is the whole remainder.
    fn resolve_unasked(&mut self, targets: &mut mpsc::Receiver<Target>) -> u128 {
        let protocol = self.protocol();
        let silence = self.silence_means();

        let mut unasked = 0;
        while let Ok(target) = targets.try_recv() {
            unasked += 1;
            if target.protocol == protocol {
                self.record_port(target.ip, target.port, silence, None);
                // Nothing was sent, so nothing was learned. The verdict above is
                // the engine's deliberate kindness to a reader; it must never
                // read as coverage.
                self.settle(target.ip, target.port, Fate::Unasked);
            }
        }
        unasked
    }
}

/// How a run names itself in the audit and in its own failure messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditLabels {
    /// The tag the audit line is filed under, such as `"tcp-port"`.
    pub tag: &'static str,
    /// How a port that nothing answered for is described, such as
    /// `"open-filtered"`.
    pub silence: &'static str,
}

/// Drives one raw port scan from its first probe to its audit line.
///
/// This is the whole of what the TCP and UDP scanners used to hold a copy of
/// each. The two copies differed in four expressions: which protocol to accept,
/// what silence meant, and two labels. Everything around those was identical
/// down to the comments, including the ordering that makes the stop conditions
/// mean anything, and that is a dangerous thing to keep two of. A stop
/// condition fixed in one copy and missed in the other does not fail; it
/// returns a smaller answer that looks exactly like a quiet network.
///
/// The shape of one iteration, and why it is that shape:
///
/// 1. **Service retries first.** Probes come due on a timer, and queuing them
///    before the stop conditions are read means the ledger is current when
///    those conditions ask whether anything is still outstanding.
/// 2. **Then decide whether to stop**, on the four conditions
///    [`RawProbeScan::stop_reason`] holds.
/// 3. **Then wait on whichever of three things happens first**: another target
///    to probe, a reply to read, or the moment the next probe is due.
///
/// Anything still outstanding when the loop ends takes the scan's silence
/// verdict, and so does anything still queued and never asked — so a scan cut
/// short by its own deadline reports the ports it never reached instead of
/// leaving them off the host entirely, which is the one shortfall a reader
/// cannot see. See [`RawPortScan::resolve_unasked`] for how far that reaches.
pub async fn run<S: RawPortScan>(scanner: &mut S, mut targets: mpsc::Receiver<Target>) {
    // The rate backstop. What paces the scan is `RawProbeScan::window`, which
    // the batch loop below re-checks after every send; this bounds how fast a
    // window's worth of probes may be released, so a defect in the controller
    // cannot become a flood and a caller asking for a specific rate gets one.
    let mut send_tick = tokio::time::interval(scanner.core().send_tick);
    // Delay rather than Burst: a tick missed while the loop was busy is time the
    // probes were not going out, and catching up by releasing several at once
    // would put back exactly the burst this exists to prevent.
    send_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut sending_finished = false;
    // Counts what the scan was handed rather than what it sent. A target of
    // another protocol is not this scanner's to probe, but it was still part of
    // the work routed here, and the audit reads this as the denominator.
    let mut probes = 0u128;

    // The loop yields why it stopped, so the audit cannot report a reason the
    // code never actually took.
    let reason = loop {
        // Read once per iteration and reused throughout it: a scan at rate
        // takes this path constantly, and the arithmetic below only needs the
        // instants to agree with each other.
        let now = Instant::now();
        scanner.service_retries(now);

        if let Some(reason) = scanner.core().stop_reason(sending_finished) {
            break reason;
        }

        // Both are read before the `select!`, which borrows the receive half
        // mutably for the duration of the statement.
        let admitting = scanner.core().admitting(sending_finished);
        let tick = scanner.core().tick_delay(now);

        tokio::select! {
            // One tick releases a batch, which is how a rate faster than the
            // timer's resolution is expressed. Taken from the stream only when
            // the ledger has room: the ceiling still bounds how many answers are
            // outstanding, and the rate now bounds how fast they are asked for.
            _ = send_tick.tick(), if admitting => {
                for _ in 0..scanner.core().batch {
                    match targets.try_recv() {
                        Ok(target) => {
                            probes += 1;
                            scanner.send_probe(target);
                        }
                        // Nothing waiting: the dispatcher has not caught up, and
                        // blocking here would hold the receive half across the
                        // whole batch.
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            sending_finished = true;
                            break;
                        }
                    }
                    if !scanner.core().admitting(sending_finished) {
                        break;
                    }
                }
            }

            res = scanner.core_mut().transport.rx.recv() => {
                match res {
                    Some(reply) => {
                        scanner.core_mut().audit.record_segment();
                        scanner.handle_reply(&reply, Instant::now());
                    }
                    None => break StopReason::StreamClosed,
                }
            }

            // Wakes when the next probe is due, so a retry is sent on time even
            // though nothing is arriving to wake the loop otherwise.
            _ = tokio::time::sleep(tick) => {}
        }
    };

    scanner.resolve_remaining();
    // Targets still in the channel when the loop ended. Counted into `probes`
    // so the audit's denominator is what the scan was handed rather than what it
    // got round to.
    probes += scanner.resolve_unasked(&mut targets);

    let kind = scanner.kind();
    let labels = scanner.audit_labels();
    scanner
        .core_mut()
        .finish(kind, labels.tag, labels.silence, probes, reason);
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
    use std::net::Ipv4Addr;

    use crate::scanner::pacing::congestion::WindowLimits;
    use crate::scanner::session::ScanSession;
    use crate::transport::probe::{Emission, ProbeSender, ProbeTransport, SendError};

    /// A sender that swallows everything. These tests never look at the wire;
    /// they ask when the loop decides to stop, which is a question about the
    /// ledger and the deadline alone.
    #[derive(Default)]
    struct NullSender;

    impl ProbeSender for NullSender {
        fn send(
            &self,
            _segment: &[u8],
            _src: IpAddr,
            _dst: IpAddr,
            _emission: Emission,
        ) -> Result<(), SendError> {
            Ok(())
        }
    }

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

    /// A core with a generous deadline and a one-attempt retry budget, so the
    /// only thing that moves a verdict is what the test puts in the ledger.
    fn core() -> (RawProbeScan<()>, ScanSession) {
        let (session, ctx) = ScanSession::new();
        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let core = RawProbeScan {
            resolver: SourceResolver::from_interfaces(&[]),
            ctx,
            transport: ProbeTransport::from_parts(Box::new(NullSender), rx),
            deadline: AdaptiveDeadline::new(super::super::DEADLINE_CONFIG, 8),
            ledger: ProbeLedger::new(super::super::RETRY_POLICY, 8),
            due: Vec::new(),
            src_port: 54_321,
            send_failure: None,
            audit: ProbeAudit::new(),
            window: CongestionWindow::new(WindowLimits::fixed(4)),
            send_tick: Duration::from_millis(1),
            batch: 1,
            max_unresolved: 64,
        };
        (core, session)
    }

    /// The condition the whole loop exists to get right: an empty ledger means
    /// "everything has been answered or written off" only once there is nothing
    /// left to ask. Reached before the stream runs dry it would end a scan that
    /// had not yet sent most of its probes.
    ///
    /// The way that actually happens is the send path failing. A link that has
    /// stopped accepting sends leaves the ledger empty while the stream is still
    /// full, and a loop that read the quiet as an answer abandoned thirty-one
    /// thousand queued targets and reported them as ports nobody could reach.
    #[test]
    fn an_empty_ledger_does_not_end_a_scan_that_still_has_targets_coming() {
        let (core, _session) = core();

        assert_eq!(
            core.stop_reason(false),
            None,
            "the target stream is still open, so nothing has been concluded"
        );
        assert_eq!(
            core.stop_reason(true),
            Some(StopReason::AttemptsSpent),
            "with the stream done and nothing outstanding, waiting cannot help"
        );
    }

    /// Silence is only evidence once nothing is outstanding. With probes still
    /// waiting on their timers, quiet is what the retry schedule expects.
    #[test]
    fn an_outstanding_probe_holds_the_scan_open_past_a_dry_target_stream() {
        let (mut core, _session) = core();
        core.ledger.arm(TARGET, (TARGET, 80), (), Instant::now());

        assert_eq!(
            core.stop_reason(true),
            None,
            "a probe is still within its retry schedule"
        );
    }

    /// An abort is checked before anything else, so a scan winds down promptly
    /// rather than after whatever else it was in the middle of.
    #[test]
    fn an_abort_outranks_every_other_reason() {
        let (mut core, _session) = core();
        core.ledger.arm(TARGET, (TARGET, 80), (), Instant::now());
        core.ctx.handle.abort();

        assert_eq!(core.stop_reason(false), Some(StopReason::Aborted));
    }

    /// The window is what makes a scan self-pacing: probes leave as earlier ones
    /// are resolved, rather than as fast as the socket accepts writes.
    #[test]
    fn the_ledger_stops_admitting_at_the_window() {
        let (mut core, _session) = core();
        assert!(core.admitting(false), "an empty ledger admits");

        for _ in 0..core.window.capacity() {
            core.window.record_send();
        }

        assert!(
            !core.admitting(false),
            "admitting past the window grows correlation state for nothing"
        );
        assert!(
            !core.admitting(true),
            "a finished stream never admits, window or not"
        );
    }

    /// A reply to the first attempt says the target is keeping up. A reply to a
    /// later one says it was willing all along and the first question did not
    /// survive — which is the one thing a port scanner can observe that
    /// separates being too fast from meeting a firewall.
    #[test]
    fn the_attempt_that_answered_is_what_moves_the_window() {
        let (mut core, _session) = core();
        core.window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));

        core.record_answer(&Resolution {
            rtt: None,
            attempts: 1,
            answered_attempt: Some(1),
        });
        assert!(core.window.capacity() > 64, "a clean answer buys headroom");

        let grown = core.window.capacity();
        core.record_answer(&Resolution {
            rtt: None,
            attempts: 2,
            answered_attempt: Some(2),
        });
        assert!(
            core.window.capacity() < grown,
            "an answer that needed a retry is loss, and loss cuts the window"
        );
    }

    /// A send the kernel refused is backpressure from this machine, and the one
    /// signal in the controller that does not come from the network at all.
    ///
    /// Whatever refused it — a full interface queue, a neighbour that will not
    /// resolve — offering more of the same faster cannot help. Measured: seven
    /// thousand `No route to host` failures in one run, at an unchanged window,
    /// because nothing was reading them.
    #[test]
    fn a_send_the_kernel_refused_cuts_the_window() {
        let (mut core, _session) = core();
        core.window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));

        core.record_send(false, true);

        assert!(
            core.window.capacity() < 64,
            "the local stack refusing is the least ambiguous evidence there is"
        );
        assert_eq!(
            core.window.in_flight(),
            0,
            "and a probe that never left takes no slot"
        );
    }

    /// Silence from a host that has never said anything is not congestion. It is
    /// what a firewall and a dead address both produce, and a controller that
    /// read it as congestion would crawl against exactly the hosts that are
    /// hardest to finish — while learning nothing, because nothing it did would
    /// change the answer.
    #[test]
    fn silence_from_a_host_that_never_answered_opens_the_window() {
        let (mut core, _session) = core();
        core.window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));

        core.window.record_send();
        core.judge_timeout(TARGET);

        assert!(
            core.window.capacity() >= 64,
            "nothing this host did says the path is busy"
        );
        assert_eq!(core.window.in_flight(), 0, "and the slot went back");
    }

    /// Silence from a host that is answering most of what it is asked is the
    /// opposite: it is not running a block list, it is failing to keep up.
    ///
    /// This is the signal the first version of the controller did not have, and
    /// its absence is measurable. Against a Raspberry Pi answering three quarters
    /// of a thousand probes, the window never cut once and the remaining quarter
    /// was reported as a firewall that did not exist — a different set of ports
    /// on every run.
    #[test]
    fn silence_from_a_host_that_is_answering_cuts_the_window() {
        let (mut core, _session) = core();
        core.window = CongestionWindow::new(WindowLimits::new(64, 4, 512, 512));

        // One port answered, which is what makes this host's silence mean
        // something.
        let now = Instant::now();
        core.ledger.arm(TARGET, (TARGET, 22), (), now);
        core.ledger.resolve(&(TARGET, 22), None, now);

        core.window.record_send();
        core.judge_timeout(TARGET);

        assert!(
            core.window.capacity() < 64,
            "a host that talks and then goes quiet is being outrun"
        );
        assert_eq!(core.window.in_flight(), 0, "and the slot still went back");
    }
}
