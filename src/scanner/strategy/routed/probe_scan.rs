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
//! later, needs the same stop conditions, the same in-flight ceiling and the
//! same audit tail; implementing [`RawPortScan`] gets all of it, and the only
//! code to write is the part that is actually about the protocol.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::model::host::{HostStatus, StatusProtocol, StatusReason};
use crate::model::port::{PortState, Protocol};
use crate::model::target::Target;
use crate::scanner::audit::ProbeAudit;
use crate::scanner::pacing::deadline::AdaptiveDeadline;
use crate::scanner::pacing::retry::{Due, ProbeLedger};
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
    /// The most probes this scan leaves outstanding at once.
    ///
    /// Set per protocol rather than shared, and the two are an order of
    /// magnitude apart for a reason that is not tidiness: a TCP scan is bounded
    /// by what the target's stack will answer, while a UDP scan is bounded by
    /// what its target's *ICMP rate limiter* will answer, which is far lower. A
    /// burst that outruns that limiter manufactures open-filtered verdicts, so
    /// the UDP ceiling has to be low enough that it never does. See each
    /// scanner's constructor for the value it chose and why.
    pub max_in_flight: usize,
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
    /// - **Deadline expired.** Silence is only evidence once nothing is
    ///   outstanding. With probes still waiting on their timers, quiet is
    ///   exactly what the retry schedule expects and is no reason to conclude
    ///   anything.
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
        if self.ledger.is_empty() && self.deadline.has_expired() {
            return Some(StopReason::DeadlineExpired);
        }
        None
    }

    /// Whether another target may be admitted from the stream.
    ///
    /// False once the stream is done, and false while the ledger is at
    /// [`max_in_flight`](Self::max_in_flight). Admitting past that ceiling grows
    /// correlation state without making any answer arrive sooner, and for a
    /// rate-limited target it actively costs verdicts.
    pub fn admitting(&self, sending_finished: bool) -> bool {
        !sending_finished && self.ledger.len() < self.max_in_flight
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
        self.audit.report(audit_tag, probes, reason, capture);
        self.ctx
            .record_probe_stats(self.audit.stats(kind, probes, reason, capture));
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
    /// [`max_in_flight`](RawProbeScan::max_in_flight) for the targets queued
    /// behind them.
    ///
    /// Running out of attempts is deliberately not treated as activity, so it
    /// never extends the scan's own deadline. Nothing answered.
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
                    key: (ip, port), ..
                } => self.probe(ip, port, now),
                Due::Exhausted((ip, port)) => self.record_port(ip, port, silence, None),
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
        let silence = self.silence_means();
        for (ip, port) in self.core_mut().ledger.drain_unresolved() {
            self.record_port(ip, port, silence, None);
        }
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
/// verdict, so every port the scan was given leaves with an answer.
pub async fn run<S: RawPortScan>(scanner: &mut S, mut targets: mpsc::Receiver<Target>) {
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
            target = targets.recv(), if admitting => {
                match target {
                    Some(target) => {
                        probes += 1;
                        scanner.send_probe(target);
                    }
                    None => sending_finished = true,
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

    use crate::scanner::session::ScanSession;
    use crate::transport::probe::{ProbeSender, ProbeTransport, SendError};

    /// A sender that swallows everything. These tests never look at the wire;
    /// they ask when the loop decides to stop, which is a question about the
    /// ledger and the deadline alone.
    #[derive(Default)]
    struct NullSender;

    impl ProbeSender for NullSender {
        fn send(&self, _segment: &[u8], _src: IpAddr, _dst: IpAddr) -> Result<(), SendError> {
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
            max_in_flight: 4,
        };
        (core, session)
    }

    /// The condition the whole loop exists to get right: an empty ledger means
    /// "everything has been answered or written off" only once there is nothing
    /// left to ask. Reached before the stream runs dry it would end a scan that
    /// had not yet sent most of its probes.
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

    /// The in-flight ceiling is what makes a scan self-pacing: probes leave as
    /// earlier ones are resolved, rather than as fast as the socket accepts
    /// writes.
    #[test]
    fn the_ledger_stops_admitting_at_the_ceiling() {
        let (mut core, _session) = core();
        assert!(core.admitting(false), "an empty ledger admits");

        let now = Instant::now();
        for port in 0..core.max_in_flight as u16 {
            core.ledger.arm(TARGET, (TARGET, port), (), now);
        }

        assert!(
            !core.admitting(false),
            "admitting past the ceiling grows correlation state for nothing"
        );
        assert!(
            !core.admitting(true),
            "a finished stream never admits, ceiling or not"
        );
    }
}
