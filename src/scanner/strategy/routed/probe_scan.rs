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
//! [`RawProbeScan`] is that machine. The TCP and UDP port scanners each hold one
//! and keep for themselves exactly what is protocol-specific: how a probe is
//! built, how a reply is recognised, and what a given answer proves about a port
//! and its host.
//!
//! ## Why this line and not a different one
//!
//! The split is drawn where the two scanners were *identical*, not merely
//! similar. Before it existed their stop conditions, their pacing arithmetic,
//! their unreachable handling and their audit tails were duplicated with no
//! difference but a label — while their probe construction and their evidence
//! mapping differed in almost every line, because a RST and an ICMP port
//! unreachable prove genuinely different things. Sharing the first and not the
//! second is what keeps this an abstraction rather than a coincidence.
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

use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::model::host::{HostStatus, StatusProtocol, StatusReason};
use crate::scanner::audit::ProbeAudit;
use crate::scanner::pacing::deadline::AdaptiveDeadline;
use crate::scanner::pacing::retry::{Due, ProbeLedger};
use crate::scanner::report::StopReason;
use crate::scanner::session::{ScanContext, ScannerKind};
use crate::system::interface::SourceResolver;
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
