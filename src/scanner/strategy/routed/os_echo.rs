// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The active operating-system echo probe
//!
//! One ICMP echo request per host, sent where the passive sources concluded
//! nothing, and read for what the reply says about the stack that sent it.
//!
//! ## Why this scanner exists
//!
//! Passive identification reads a reply the scan already drew, so it starts
//! from a host that answered something. The hosts that answer nothing are not
//! a rare case: a stock Windows firewall *drops* rather than refuses, so a
//! desktop with no service exposed emits no packet any TCP rule could read —
//! measured, twice, on two independent installations. A great many of those
//! machines still answer a ping, and what they put in the reply (a hop counter
//! of 128, the request's code echoed or zeroed) is a property of the same
//! stack. This is the only route to those hosts, and it is why
//! [`OsDetection::Active`](crate::config::OsDetection) exists as a level.
//!
//! ## The probe asks a question, or it is not worth sending
//!
//! The request carries [`ECHO_PROBE_CODE`] rather than a conformant zero,
//! because whether a responder echoes a non-zero code or writes zero is a
//! documented disagreement between stacks — invisible to a probe that never
//! asked. The identifier is the scan's identity (every other ping on the host
//! is filtered out by it, in userspace, since no kernel filter can express it),
//! and the sequence names the attempt, which is what makes a round trip real.
//!
//! ## What one reply may claim
//!
//! An echo reply carries no options, no window, no sequence number — an
//! initial hop counter of 64 names *nothing*, because Linux, macOS and the BSDs
//! all start there. The rule corpus is authored under that constraint, and
//! [`classify`](crate::fingerprint::os) reports nothing rather than the
//! least bad guess. A host this scanner cannot name is a host it says nothing
//! about, which is the same honesty the passive path holds itself to.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pnet::packet::ip::IpNextHeaderProtocols;

use crate::config::ProbeTuning;
use crate::error;
use crate::fingerprint::os;
use crate::model::host::{HostStatus, StatusProtocol, StatusReason};
use crate::protocols::icmp;
use crate::scanner::audit::ProbeAudit;
use crate::scanner::pacing::retry::{Due, ProbeLedger, RetryPolicy};
use crate::scanner::report::StopReason;
use crate::scanner::session::{ScanContext, ScannerKind};
use crate::scanner::strategy::{HostScanner, StrategyError};
use crate::success;
use crate::system::interface::SourceResolver;
use crate::transport::capture::CapturedSegment;
use crate::transport::probe::{ProbeKind, ProbeTransport};

/// The payload every echo request carries, so a reply can be checked against
/// what was sent rather than trusted to have come back whole.
const PAYLOAD: &[u8] = b"zond-os-probe";

/// How an echo is retransmitted.
///
/// Two attempts rather than three: this phase runs only where the caller opted
/// in, over hosts the passive sources already found thin, and its verdicts are
/// family-level. A third attempt buys coverage a ping is unlikely to return.
const RETRY_POLICY: RetryPolicy = RetryPolicy::new(
    2,
    Duration::from_millis(200),
    Duration::from_millis(25),
    Duration::from_secs(2),
    2.0,
    0.2,
    None,
);

/// How fast echoes leave the wire. One per millisecond is far slower than the
/// port scanners, deliberately: a scan that opted into active detection pays
/// for its hosts one packet at a time, and this phase is never the thing being
/// timed.
const SEND_TICK: Duration = Duration::from_millis(1);

/// Patience after the last probe resolves or exhausts, so a reply from a slow
/// path still lands before the phase closes.
const QUIET_FLOOR: Duration = Duration::from_secs(1);

/// Sends one ICMP echo per host where passive evidence named nothing, and files
/// what the replies say.
///
/// Targets are chosen by the caller from the host store, because "the passive
/// sources concluded nothing" is a fact about the store rather than about the
/// plan, and it only becomes true once those sources have finished.
pub struct OsEchoScanner {
    ctx: ScanContext,
    transport: ProbeTransport,
    resolver: SourceResolver,
    /// The identifier every request carries, and the only thing separating this
    /// scan's replies from every other ping on the host.
    identifier: u16,
    /// How many requests have left, which is also the next sequence number.
    /// Sequence numbers name attempts, and the ledger arms with them, so a
    /// round trip is measured against the send it answers.
    next_sequence: u16,
    /// Targets not yet asked.
    pending: VecDeque<IpAddr>,
    /// Targets awaiting a retry.
    retries: VecDeque<IpAddr>,
    /// Probes outstanding, keyed by host, carrying the sequence of the attempt.
    ledger: ProbeLedger<IpAddr, u16>,
    /// Which host each sequence went to, since a reply names its attempt, not
    /// its target.
    by_sequence: HashMap<u16, IpAddr>,
    /// Scratch space for the probes coming due on one iteration.
    due: Vec<Due<IpAddr>>,
    /// The hard ceiling on this run, derived from the worst case a retry can
    /// still be answered within.
    deadline: Instant,
    audit: ProbeAudit,
    send_failure: Option<String>,
}

impl OsEchoScanner {
    /// Opens the ICMP transport this scanner needs and takes the targets to
    /// ask. Fails where the raw socket cannot be had, which is the caller's
    /// signal that this level of detection is unavailable rather than silent.
    pub fn new(
        ctx: ScanContext,
        targets: Vec<IpAddr>,
        tuning: ProbeTuning,
    ) -> Result<Self, StrategyError> {
        let identifier = rand::random();
        let transport =
            ProbeTransport::open_with(ProbeKind::IcmpEcho { identifier }, tuning.send_mode)?;
        Ok(Self::with_identifier(ctx, targets, transport, identifier))
    }

    /// Builds the scanner around a transport the caller opened, which is the
    /// seam a test or a custom orchestration drives it through. The identifier
    /// is drawn here, since the transport came from somewhere that could not
    /// have known it.
    pub fn with_transport(
        ctx: ScanContext,
        targets: Vec<IpAddr>,
        transport: ProbeTransport,
    ) -> Self {
        Self::with_identifier(ctx, targets, transport, rand::random())
    }

    fn with_identifier(
        ctx: ScanContext,
        targets: Vec<IpAddr>,
        transport: ProbeTransport,
        identifier: u16,
    ) -> Self {
        let send_duration = SEND_TICK.saturating_mul(targets.len() as u32);
        let target_count = targets.len();
        Self {
            ctx,
            transport,
            resolver: SourceResolver::from_system(),
            identifier,
            next_sequence: 0,
            pending: targets.into(),
            retries: VecDeque::new(),
            ledger: ProbeLedger::new(RETRY_POLICY, 256),
            by_sequence: HashMap::with_capacity(target_count),
            due: Vec::new(),
            deadline: Instant::now()
                + RETRY_POLICY.worst_case_probe_lifetime()
                + send_duration
                + QUIET_FLOOR,
            audit: ProbeAudit::new(),
            send_failure: None,
        }
    }

    /// Resends what has gone unanswered long enough, and writes off what has
    /// spent its budget. A written-off host keeps whatever the passive sources
    /// already said about it — which, for the hosts this scanner is given, is
    /// nothing, so nothing is recorded.
    fn service_retries(&mut self, now: Instant) {
        self.ledger.drain_due(now, &mut self.due);
        for event in self.due.drain(..) {
            if let Due::Retry { key, .. } = event {
                self.retries.push_back(key);
            }
        }
    }

    /// Releases one probe: a retry first, then a target not yet asked.
    ///
    /// Retries first for the same reason the routed sweep puts them first: a
    /// retry is an obligation the scan already owns, and queueing it behind
    /// every first attempt would send it long after the moment it was scheduled
    /// for.
    fn send_one(&mut self, now: Instant) {
        let target = match self
            .retries
            .pop_front()
            .or_else(|| self.pending.pop_front())
        {
            Some(target) => target,
            None => return,
        };
        // The ledger has charged any retry that reached here, so an unroutable
        // target exhausts on schedule rather than waiting outstanding forever.
        let Some(source) = self.resolver.resolve(target) else {
            return;
        };

        let sequence = self.next_sequence;
        let message = match icmp::create_echo_request_message(
            source,
            target,
            icmp::ECHO_PROBE_CODE,
            self.identifier,
            sequence,
            PAYLOAD,
        ) {
            Ok(message) => message,
            Err(e) => {
                error!(verbosity = 2, "Cannot build an echo for {target}: {e}");
                self.audit.record_send(false);
                return;
            }
        };

        let sent = match self.transport.tx.send(&message, source, target) {
            Ok(()) => {
                success!(verbosity = 2, "Sent OS echo probe to {target}");
                true
            }
            Err(e) => {
                error!(
                    verbosity = 2,
                    "Failed to send OS echo probe to {target}: {e:#}"
                );
                self.send_failure = Some(format!("{e:#}"));
                false
            }
        };
        self.audit.record_send(sent);
        if sent {
            self.next_sequence = self.next_sequence.wrapping_add(1);
            self.by_sequence.insert(sequence, target);
            self.ledger.arm(target, target, sequence, now);
        }
    }

    /// Reads one captured message: ours or not, and if ours, what it proved.
    fn handle_reply(&mut self, reply: CapturedSegment, now: Instant) {
        if reply.protocol != IpNextHeaderProtocols::Icmp
            && reply.protocol != IpNextHeaderProtocols::Icmpv6
        {
            self.audit.record_off_target();
            return;
        }
        // An ICMP message does not say which family's numbering it belongs to;
        // the address it arrived from does.
        let over_ipv6 = reply.source.is_ipv6();
        let icmp::EchoReply::Ours { sequence } =
            icmp::classify_echo_reply(&reply.bytes, self.identifier, over_ipv6)
        else {
            // Every other ping on the host arrives here: the identifier cannot
            // be expressed in a kernel filter, so this is where it is enforced.
            self.audit.record_off_target();
            return;
        };
        let Some(&target) = self.by_sequence.get(&sequence) else {
            self.audit.record_off_target();
            return;
        };

        let resolution = self.ledger.resolve(&target, Some(sequence), now);
        if resolution.is_none() {
            // A duplicate, or an answer to a probe already written off. It
            // proved the host alive but yields no sample.
            self.audit.record_reply_without_rtt();
            return;
        }
        let rtt = resolution.and_then(|r| r.rtt);
        self.audit
            .record_host_found(resolution.and_then(|r| r.answered_attempt));

        self.ctx.write_host(target, |host| {
            let was_up = host.status().is_up();
            host.record_evidence(
                HostStatus::Up,
                StatusReason::new(StatusProtocol::IcmpEcho, "echo reply to an OS probe"),
            );
            if let Some(rtt) = rtt {
                host.add_rtt(rtt);
            }
            !was_up
        });

        self.identify(target, &reply);
    }

    /// Reads the operating system off the reply that just resolved, and folds
    /// it into whatever the host already carries.
    ///
    /// The same shape as the port scanner's passive reading: a whole reply is
    /// one item of evidence, combined with the other sources on the host
    /// through [`os::resolve`], merged by accuracy so nothing is overwritten so
    /// much as outranked.
    fn identify(&self, target: IpAddr, reply: &CapturedSegment) {
        // `None` means no IP header was ever there to read — a synthetic
        // receive stream — rather than that nothing notable was in one.
        let Some(observation) = reply.observation else {
            return;
        };
        let Some(observed) =
            os::EchoObservation::from_echo_reply(observation, &reply.bytes, PAYLOAD)
        else {
            return;
        };
        let Some(verdict) = os::classify(os::RuleDb::global(), &observed.into()) else {
            return;
        };

        self.ctx.update_host(target, |host| {
            let mut evidence = vec![verdict.as_evidence()];
            if let Some(hardware) = host.hardware().and_then(os::hardware_evidence) {
                evidence.push(hardware);
            }
            if let Some(name) = os::hostname_evidence(host.hostname()) {
                evidence.push(name);
            }
            let Some(resolved) = os::resolve(evidence) else {
                return;
            };
            let fingerprint = resolved.to_fingerprint();
            match host.os() {
                Some(existing) => {
                    let mut merged = existing.clone();
                    merged.merge(fingerprint);
                    host.set_os(merged);
                }
                None => host.set_os(fingerprint),
            }
        });
    }
}

#[async_trait]
impl HostScanner for OsEchoScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::OsEcho
    }

    async fn discover_hosts(&mut self) -> Result<(), StrategyError> {
        let mut send_tick = tokio::time::interval(SEND_TICK);
        send_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let reason = loop {
            let now = Instant::now();
            self.service_retries(now);

            if self.ctx.handle.should_stop() {
                break StopReason::Aborted;
            }
            if self.pending.is_empty() && self.retries.is_empty() && self.ledger.is_empty() {
                break StopReason::AttemptsSpent;
            }
            if now >= self.deadline {
                break StopReason::DeadlineExpired;
            }

            let sending = !self.pending.is_empty() || !self.retries.is_empty();
            let until_due = self
                .ledger
                .next_due()
                .map_or(Duration::from_millis(50), |due| {
                    due.saturating_duration_since(now)
                        .min(Duration::from_millis(50))
                });

            tokio::select! {
                res = self.transport.rx.recv() => {
                    match res {
                        Some(reply) => {
                            self.audit.record_segment();
                            self.handle_reply(reply, Instant::now());
                        }
                        None => break StopReason::StreamClosed,
                    }
                }

                _ = send_tick.tick(), if sending => {
                    self.send_one(Instant::now());
                }

                _ = tokio::time::sleep(until_due), if !sending => {}
            }
        };

        if self.audit.sends_failed > 0 {
            self.ctx.record_failure(
                ScannerKind::OsEcho,
                format!(
                    "{} of {} echo probes could not be sent: {}",
                    self.audit.sends_attempted,
                    self.audit.sends_attempted,
                    self.send_failure.as_deref().unwrap_or("cause unrecorded"),
                ),
            );
        }

        let capture = self.transport.capture_counts();
        let targets = self.next_sequence as u128;
        self.audit.report("os-echo", targets, reason, capture);
        self.ctx.record_probe_stats(self.audit.stats(
            ScannerKind::OsEcho,
            targets,
            reason,
            capture,
        ));
        Ok(())
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗██████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████╗   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    use tokio::sync::mpsc;

    use crate::model::capture::{IpObservation, Ipv4Observation};
    use crate::scanner::session::ScanSession;
    use crate::transport::capture::CaptureStream;
    use crate::transport::probe::{ProbeSender, SendError};

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

    /// Builds the ICMP echo reply a stack sends, from the request's own
    /// identifier and sequence, under an IP header starting at `hops`.
    ///
    /// Assembled from the RFCs rather than through the engine's own builders,
    /// so a shared misreading of what an echo reply is cannot pass for
    /// agreement.
    fn echo_reply(request: &[u8], hops: u8) -> CapturedSegment {
        let identifier = u16::from_be_bytes([request[4], request[5]]);
        let sequence = u16::from_be_bytes([request[6], request[7]]);

        let mut message = Vec::with_capacity(8 + PAYLOAD.len());
        message.extend_from_slice(&[0, icmp::ECHO_PROBE_CODE, 0, 0]);
        message.extend_from_slice(&identifier.to_be_bytes());
        message.extend_from_slice(&sequence.to_be_bytes());
        message.extend_from_slice(PAYLOAD);

        CapturedSegment {
            source: TARGET,
            protocol: IpNextHeaderProtocols::Icmp,
            observation: Some(IpObservation::V4(Ipv4Observation {
                ttl: hops,
                identification: 0,
                dont_fragment: true,
                more_fragments: false,
                dscp: 0,
                ecn: 0,
            })),
            source_mac: None,
            bytes: message,
        }
    }

    /// A link that answers every echo request with the reply a host whose hop
    /// counter starts at `hops` sends, and records nothing else.
    struct Echoing {
        hops: u8,
        replies: mpsc::UnboundedSender<CapturedSegment>,
    }

    impl ProbeSender for Echoing {
        fn send(&self, segment: &[u8], _src: IpAddr, _dst: IpAddr) -> Result<(), SendError> {
            let _ = self.replies.send(echo_reply(segment, self.hops));
            Ok(())
        }
    }

    fn scanner(
        ctx: &ScanContext,
        hops: u8,
    ) -> (OsEchoScanner, mpsc::UnboundedSender<CapturedSegment>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let link = Echoing {
            hops,
            replies: tx.clone(),
        };
        let transport = ProbeTransport::from_parts(Box::new(link), rx as CaptureStream);
        (
            OsEchoScanner::with_transport(ctx.clone(), vec![TARGET], transport),
            tx,
        )
    }

    /// The whole path this scanner exists for: a host that answered nothing a
    /// TCP probe could read, named from the one reply it does give. A stock
    /// Windows firewall drops rather than refuses, and 128 is the NT-family
    /// hop counter — that one field is what the corpus's Windows echo rule
    /// keys on.
    #[tokio::test(flavor = "current_thread")]
    async fn a_windows_hop_counter_in_an_echo_reply_names_windows() {
        let (session, ctx) = ScanSession::new();
        let (mut scanner, _tx) = scanner(&ctx, 128);

        scanner.discover_hosts().await.expect("the phase runs");

        let host = session.hosts().get(&TARGET).expect("the host is recorded");
        let found = host
            .os()
            .expect("an echo reply with a Windows hop counter names Windows");
        assert_eq!(found.family(), Some("Windows"));
        assert!(
            found.evidence().unwrap_or_default().contains("echo"),
            "the finding says what it was read off: {found}"
        );
        assert_eq!(host.status(), HostStatus::Up);
    }

    /// A Unix-alike hop counter names nothing, on purpose, and this is the
    /// record of why: Linux, macOS and the BSDs all start at 64 and an echo
    /// reply carries nothing else to separate them. The corpus refuses that
    /// rule; this test holds the scanner to the same refusal.
    #[tokio::test(flavor = "current_thread")]
    async fn a_unix_hop_counter_in_an_echo_reply_names_nothing() {
        let (session, ctx) = ScanSession::new();
        let (mut scanner, _tx) = scanner(&ctx, 64);

        scanner.discover_hosts().await.expect("the phase runs");

        let host = session.hosts().get(&TARGET).expect("the host is recorded");
        assert!(
            host.os().is_none(),
            "an echo reply at 64 hops is not evidence for any family, and saying \
             nothing beats the least bad guess"
        );
        assert_eq!(host.status(), HostStatus::Up);
    }

    /// Every other ping on the host is filtered out by the identifier, in
    /// userspace, because no kernel filter can express it. A reply carrying a
    /// different identifier is not this scan's answer and must resolve nothing
    /// — not name the host, not even mark it up.
    #[tokio::test(flavor = "current_thread")]
    async fn somebody_elses_ping_is_not_our_answer() {
        // A link that answers nothing: this host's own probe goes unanswered,
        // and the only reply that arrives is another ping's, carrying an
        // identifier this scan never sent.
        struct Silent;

        impl ProbeSender for Silent {
            fn send(&self, _s: &[u8], _src: IpAddr, _dst: IpAddr) -> Result<(), SendError> {
                Ok(())
            }
        }

        let (session, ctx) = ScanSession::new();
        let (tx, rx) = mpsc::unbounded_channel();
        let transport = ProbeTransport::from_parts(Box::new(Silent), rx);
        let mut scanner = OsEchoScanner::with_transport(ctx.clone(), vec![TARGET], transport);

        // The reply to somebody else's ping, with a Windows hop counter that
        // would name the host were it read.
        let mut message = Vec::with_capacity(8 + PAYLOAD.len());
        message.extend_from_slice(&[0, 0, 0, 0]);
        message.extend_from_slice(&0xBEEFu16.to_be_bytes()); // not our identifier
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(PAYLOAD);
        let theirs = CapturedSegment {
            source: TARGET,
            protocol: IpNextHeaderProtocols::Icmp,
            observation: Some(IpObservation::V4(Ipv4Observation {
                ttl: 128,
                identification: 0,
                dont_fragment: true,
                more_fragments: false,
                dscp: 0,
                ecn: 0,
            })),
            source_mac: None,
            bytes: message,
        };
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = tx.send(theirs);
        });

        scanner.discover_hosts().await.expect("the phase runs");

        // The foreign reply was declined before anything was written: no
        // host record exists, because nothing this scan drew said anything
        // about the address. A reply it did not draw must not even prove it
        // alive.
        assert!(
            session.hosts().get(&TARGET).is_none(),
            "a foreign identifier resolves nothing, records nothing"
        );
    }
}
