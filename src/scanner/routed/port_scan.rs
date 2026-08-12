// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # TCP Port Probing
//!
//! Implements the privileged TCP half of [`crate::scanner::scan`]. It probes
//! specific `(address, port)` pairs with raw TCP segments and classifies each
//! one by whether and how it responds, rather than completing a full TCP
//! handshake per port the way the unprivileged fallback in
//! [`crate::scanner::connect`] must.
//!
//! Which segment goes out, and what an answer to it proves, is
//! [`TcpScanTechnique`]'s business - this drives the same loop whichever of the
//! six is chosen. Everything that makes a scan work rather than merely run is
//! shared across them: retransmission, the in-flight ceiling, the adaptive
//! deadline, source selection, and the rule that silence is only a verdict once
//! a probe has spent its whole budget on it. That last one is what separates
//! observing a firewall from assuming one, and it is the same discipline
//! whether the technique reads silence as filtered or as open-filtered.
//!
//! ## Tying a reply to its probe
//!
//! Every probe in a scan leaves from one source port, chosen when the scanner is
//! built, and that port is the scan's identity on the wire: the kernel's capture
//! filter admits the segments addressed to it and drops the rest of the host's
//! TCP traffic, over both address families ([`ProbeKind::TcpProbe`]). It is a
//! boundary the scanner re-checks rather than relies on, since a transport can
//! be built with no filter behind it at all.
//!
//! Which *attempt* a reply answers is a separate question, and the probe's nonce
//! settles it: each attempt carries a fresh one, and a conformant stack echoes
//! it back ([`tcp::echoed_nonce`]). That is what lets a reply arriving after a
//! retry has already gone out still name the attempt it belongs to, and so yield
//! a round trip that is real rather than one measured against the wrong packet.
//!
//! An ICMP error is correlated the same way, through the copy of the probe it
//! quotes rather than through its own header - so an error relayed by a router
//! still points at the host the probe was aimed at. See
//! [`icmp_error`](super::icmp_error).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use tokio::sync::mpsc;

use crate::core::config::ProbeTuning;
use crate::core::models::deadline::AdaptiveDeadline;
use crate::core::models::host::{HostStatus, StatusProtocol, StatusReason};
use crate::core::models::port::{PortState, Protocol};
use crate::core::models::retry::{Due, ProbeLedger, RetryPolicy};
use crate::core::models::target::Target;
use crate::core::models::technique::TcpScanTechnique;
use crate::core::session::{ScanContext, ScannerKind};
use crate::error;
use crate::network::capture::CapturedSegment;
use crate::network::probe::{ProbeKind, ProbeSender, ProbeTransport};
use crate::protocols::tcp;
use crate::scanner::{PortScanner, StrategyError, service};
use crate::success;
use crate::system::interface::SourceResolver;

// Port scanning and routed discovery send the same kind of raw TCP probe over
// the same kind of network path, so they share one adaptive-deadline profile
// rather than keeping two copies in step.
use super::icmp_error::{self, Unreachable};
use super::{DEADLINE_CONFIG, RETRY_POLICY};

/// The probe a reply refers to: the `(address, port)` it was sent to.
type ProbeTarget = (IpAddr, u16);

/// What identifies one attempt of a probe on the wire.
///
/// The nonce alone, because the source port no longer varies between attempts -
/// it identifies the *scan*, and is checked once against every reply rather than
/// per attempt. A fresh nonce per attempt is what makes a retried probe
/// measurable at all: TCP itself has to discard round-trip samples from
/// retransmissions because it cannot tell which transmission an
/// acknowledgement answers, and a scanner that varies the value the reply echoes
/// does not have that problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpToken {
    nonce: u32,
}

/// Outstanding probes and the schedule they are retried on.
type Ledger = ProbeLedger<ProbeTarget, TcpToken>;

/// The most probes left outstanding at once.
///
/// Retransmission makes this necessary rather than merely tidy. Without a
/// ceiling the send loop empties the dispatcher into the network as fast as the
/// socket accepts writes, and every unanswered probe of that burst then comes
/// due for a retry - turning one burst into several. Capping the outstanding set
/// makes the scan self-pacing: probes leave as earlier ones are answered or
/// retired, so the send rate settles at the rate the network is actually
/// resolving them.
const MAX_IN_FLIGHT: usize = 4_096;

/// Probes specific `(address, port)` pairs with raw TCP segments, using
/// whichever [`TcpScanTechnique`] it was built for.
///
/// Unlike [`RoutedScanner`](super::RoutedScanner), which sends one SYN per host
/// purely to check for a pulse, this sends one per `(address, port)` pair it is
/// given and reports what each one revealed.
pub struct TcpPortScanner {
    /// Which segment each probe carries, and so what every answer means. Fixed
    /// for the life of the scan: a report that mixed techniques could not say
    /// which one produced a given verdict.
    technique: TcpScanTechnique,
    /// Resolves the source address to send each target's probe from, consulting
    /// on-link subnets and the kernel routing table. Each answer is cached, so
    /// the many ports probed on one host cost a single lookup.
    resolver: SourceResolver,
    /// Shared state (host store, event channel, abort signal) for the scan
    /// this prober is part of.
    ctx: ScanContext,
    /// Transport used to send SYN probes and receive replies.
    transport: ProbeTransport,
    /// Governs how long this scan keeps running, adapting to observed
    /// round-trip times.
    deadline: AdaptiveDeadline,
    /// Probes sent but not yet resolved into an open/closed classification,
    /// together with when each is next due to be resent or written off.
    ledger: Ledger,
    /// Scratch space for the probes coming due on one iteration, reused so a
    /// quiet tick allocates nothing.
    due: Vec<Due<ProbeTarget>>,
    /// The source port every probe in this scan is sent from, and so the port
    /// its replies come back to. It is the scan's identity on the wire: the
    /// capture filter narrows to it, and a segment addressed anywhere else
    /// answered somebody else. See the module documentation.
    src_port: u16,
    /// Why the first probe that could not be sent failed, if any did, and how
    /// many followed it.
    ///
    /// Without this a scan whose probes never reached the wire reports every
    /// port `Filtered` - the same answer a firewall produces - and says nothing
    /// about the difference. `Filtered` is a claim about the network; a probe
    /// that was never sent is a claim about this host.
    send_failure: Option<String>,
    sends_failed: u64,
}

impl TcpPortScanner {
    /// Builds a scanner that selects each probe's source via `resolver`, sized
    /// for a scan covering `target_count` `(address, port)` pairs.
    ///
    /// The scan's source port is drawn from the high ephemeral range, where it
    /// is unlikely to collide with a listening service on this host, and the
    /// transport's capture filter is built around it.
    pub fn new(
        resolver: SourceResolver,
        ctx: ScanContext,
        technique: TcpScanTechnique,
        target_count: usize,
        tuning: ProbeTuning,
    ) -> Result<Self, StrategyError> {
        let src_port: u16 = rand::random_range(50_000..u16::MAX);
        let transport = ProbeTransport::open_with(
            ProbeKind::TcpProbe {
                reply_port: src_port,
                icmp_errors: technique.reads_icmp_errors(),
            },
            tuning.send_mode,
        )?;

        Ok(Self::build(
            resolver,
            ctx,
            technique,
            transport,
            target_count,
            src_port,
            RETRY_POLICY.configured(tuning.retry),
        ))
    }

    /// Builds a scanner around an already-opened transport, so the caller
    /// decides how probes reach the wire and where replies come from.
    ///
    /// Paired with a synthetic transport (`ProbeTransport::from_parts`, behind
    /// the `test-support` feature) this is the seam that lets probe and reply
    /// correlation be driven against a simulated network rather than a real
    /// one, with no privileges and no interface.
    ///
    /// The source port is chosen here rather than passed in, unlike
    /// [`UdpPortScanner::with_transport`](super::UdpPortScanner::with_transport):
    /// a TCP reply is addressed back to whatever port the probe came from, so a
    /// simulated network answers correctly without being told, where a
    /// synthesized ICMP error has to be built around a port the test knows.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_transport(
        resolver: SourceResolver,
        ctx: ScanContext,
        technique: TcpScanTechnique,
        transport: ProbeTransport,
        target_count: usize,
    ) -> Self {
        Self::build(
            resolver,
            ctx,
            technique,
            transport,
            target_count,
            rand::random_range(50_000..u16::MAX),
            RETRY_POLICY,
        )
    }

    /// The common constructor, taking the retry schedule as an argument because
    /// it is the one thing the two public ones disagree about - and because the
    /// scan's own deadline is derived from it, so it has to be settled before
    /// anything is built rather than patched in afterwards.
    #[allow(clippy::too_many_arguments)]
    fn build(
        resolver: SourceResolver,
        ctx: ScanContext,
        technique: TcpScanTechnique,
        transport: ProbeTransport,
        target_count: usize,
        src_port: u16,
        retry: RetryPolicy,
    ) -> Self {
        // The scan has to outlive its own retry schedule, or probes are written
        // off as unanswered having never been fully asked.
        let deadline_config = DEADLINE_CONFIG.allowing_for(retry.worst_case_probe_lifetime());

        Self {
            technique,
            resolver,
            ctx,
            transport,
            deadline: AdaptiveDeadline::new(deadline_config, target_count),
            ledger: Ledger::new(retry, target_count.min(MAX_IN_FLIGHT)),
            due: Vec::new(),
            src_port,
            send_failure: None,
            sends_failed: 0,
        }
    }

    fn send_probe(&mut self, target: Target) {
        if target.protocol != Protocol::Tcp {
            return;
        }
        self.probe(target.ip, target.port, Instant::now());
    }

    /// Sends one probe at `(ip, port)` and records the attempt.
    ///
    /// Used for the first attempt and every retry alike. Nothing about the probe
    /// is kept between attempts and none of it needs to be: the packet is built
    /// afresh from the target, which is both cheaper than buffering it and
    /// required, since every attempt must carry its own nonce.
    ///
    /// A probe that cannot be sent is simply not armed. The ledger has already
    /// charged the attempt by the time a retry reaches here, so an unroutable
    /// target still exhausts on schedule rather than waiting outstanding
    /// forever.
    fn probe(&mut self, ip: IpAddr, port: u16, now: Instant) {
        let Some(src_addr) = self.resolver.resolve(ip) else {
            error!(verbosity = 2, "No route to {ip}; skipping {ip}:{port}");
            return;
        };

        match send_tcp_probe(
            self.transport.tx.as_ref(),
            self.technique,
            self.src_port,
            src_addr,
            ip,
            port,
            &mut self.send_failure,
        ) {
            Some(token) => self.ledger.arm(ip, (ip, port), token, now),
            None => self.sends_failed += 1,
        }
    }

    /// Routes one captured reply to whichever half of the classification can
    /// read it.
    ///
    /// ICMP only reaches here for a technique that asked for it; see
    /// [`TcpScanTechnique::reads_icmp_errors`].
    fn handle_reply(&mut self, reply: &CapturedSegment, now: Instant) {
        match reply.protocol {
            IpNextHeaderProtocols::Tcp => self.handle_tcp_reply(reply.source, &reply.bytes, now),
            _ => self.handle_icmp_error(reply, now),
        }
    }

    /// Matches a TCP segment against an outstanding probe and, if it answers
    /// one, classifies it and records the port's state.
    fn handle_tcp_reply(&mut self, ip: IpAddr, bytes: &[u8], now: Instant) {
        let Some(tcp_packet) = TcpPacket::new(bytes) else {
            return;
        };

        // A segment addressed anywhere but this scan's own port answered
        // somebody else's conversation. The capture filter already narrows to
        // it, but that is a performance boundary rather than a guarantee - a
        // transport can be built with no filter at all - and this is the only
        // thing making the reply ours.
        if tcp_packet.get_destination() != self.src_port {
            return;
        }

        let Some(reply) = tcp::classify_probe_response(&tcp_packet) else {
            return;
        };
        // A segment this technique's probe could not have provoked - a SYN+ACK
        // answering an ACK scan, say - is somebody else's traffic on this
        // scan's port, and resolves nothing.
        let Some(state) = self.technique.verdict(reply) else {
            return;
        };

        // Which attempt the segment claims to be answering. The ledger checks it
        // against every attempt still live for this port, so a reply to an
        // earlier attempt that arrives after a retry has gone out is still
        // recognized - and names which attempt it answered, so the round trip it
        // yields is the real one.
        let token = TcpToken {
            nonce: tcp::echoed_nonce(self.technique, &tcp_packet),
        };
        let key = (ip, tcp_packet.get_source());
        self.resolve_probe(key, Some(token), state, None, now);
    }

    /// Reads an ICMP error as a verdict on the probe it quotes.
    ///
    /// The quotation is what makes this attributable at all, and it is checked
    /// as strictly as a TCP reply: it has to be a TCP segment, sent from this
    /// scan's own port, aimed at a probe still outstanding. What it cannot
    /// always carry is *which attempt* - eight quoted bytes reach the sequence
    /// number and no further - so a technique whose nonce lives in the
    /// acknowledgement field resolves the probe without claiming a round trip
    /// rather than inventing one.
    fn handle_icmp_error(&mut self, reply: &CapturedSegment, now: Instant) {
        let Some(error) = icmp_error::parse(reply) else {
            return;
        };
        if error.quoted.protocol != IpNextHeaderProtocols::Tcp {
            return;
        }

        let Some(quoted) = tcp::quoted_probe(error.quoted.payload) else {
            return;
        };
        if quoted.source != self.src_port {
            return;
        }

        let key = (error.quoted.destination, quoted.destination);
        let token = tcp::quoted_nonce(self.technique, &quoted).map(|nonce| TcpToken { nonce });

        match error.reason {
            // Nobody could reach the address at all, so the message carries no
            // verdict on the port it happened to quote. The probe is left
            // outstanding to retire on its own schedule like any other
            // unanswered one.
            Unreachable::Host => self.record_host_down(key.0, reply.source),
            // Everything else is a refusal, and for a TCP probe both kinds read
            // the same way. An administrative prohibition says so outright. A
            // *port* unreachable would mean a closed port had it answered a UDP
            // probe, but no TCP stack emits one - so something in the path
            // rejected the probe on the host's behalf, which is a filter and
            // not a closed port.
            Unreachable::Port | Unreachable::Prohibited => {
                self.resolve_probe(key, token, PortState::Filtered, Some(reply.source), now);
            }
        }
    }

    /// Retires one outstanding probe with the state its reply established,
    /// crediting whatever round trip the ledger is willing to vouch for.
    ///
    /// `token` names the attempt that was answered, or `None` where the reply
    /// could not say. A reply matching no live attempt resolves nothing: it is a
    /// stray or spoofed segment, a duplicate of one already acted on, or an
    /// answer to a probe already written off.
    fn resolve_probe(
        &mut self,
        key: ProbeTarget,
        token: Option<TcpToken>,
        state: PortState,
        sender: Option<IpAddr>,
        now: Instant,
    ) {
        let Some(resolution) = self.ledger.resolve(&key, token, now) else {
            return;
        };

        self.deadline.mark_activity();
        if let Some(rtt) = resolution.rtt {
            self.deadline.record_rtt(rtt);
        }

        self.record_port(key.0, key.1, state, sender);
    }

    /// Records that a router could not reach this address.
    ///
    /// The evidence is second-hand by definition - a host cannot report its own
    /// unreachability - so the reason names the router that sent it. Being the
    /// lowest non-`Unknown` status, it never overwrites evidence that the host
    /// answered for itself, whichever order the two arrive in.
    fn record_host_down(&mut self, ip: IpAddr, sender: IpAddr) {
        self.ctx.update_host(ip, |host| {
            host.record_evidence(
                HostStatus::Down,
                StatusReason::new(StatusProtocol::IcmpUnreachable, "destination unreachable")
                    .from_source(sender),
            );
        });
    }

    /// Resends everything due and writes off everything that has run out of
    /// attempts.
    ///
    /// Exhaustion is what makes a silent verdict mean something: nothing
    /// arrived across every attempt, rather than nothing arrived once. What that
    /// silence *is* depends on the technique - a firewall for the two that any
    /// live stack would have answered, an open port or a firewall for the four
    /// that an open port is required to ignore - which is
    /// [`TcpScanTechnique::silence_means`]. It is deliberately not treated as
    /// activity, so it never extends the scan's own deadline.
    fn service_retries(&mut self, now: Instant) {
        self.ledger.drain_due(now, &mut self.due);

        // Taken so the sends below can borrow `self` mutably; the buffer itself
        // is reused, so this costs no allocation.
        let due = std::mem::take(&mut self.due);
        for event in &due {
            match *event {
                Due::Retry {
                    key: (ip, port), ..
                } => self.probe(ip, port, now),
                Due::Exhausted((ip, port)) => {
                    self.record_port(ip, port, self.technique.silence_means(), None)
                }
            }
        }
        self.due = due;
        self.due.clear();
    }

    /// Gives every probe still outstanding when the scan stops the verdict its
    /// technique reads silence as.
    ///
    /// [`service_retries`](Self::service_retries) retires most probes as their
    /// budgets run out; what reaches here are the ones still mid-schedule when
    /// the scan itself ended.
    fn resolve_remaining_as_silent(&mut self) {
        for (ip, port) in self.ledger.drain_unresolved() {
            self.record_port(ip, port, self.technique.silence_means(), None);
        }
    }

    /// How long the loop may sleep: until the scan's own next checkpoint, or
    /// until the next probe needs resending or retiring, whichever comes first.
    fn tick_delay(&self, now: Instant) -> Duration {
        let until_deadline_tick = self.deadline.time_until_next_tick();
        match self.ledger.next_due() {
            Some(due) => until_deadline_tick.min(due.saturating_duration_since(now)),
            None => until_deadline_tick,
        }
    }

    /// Files a port verdict and whatever the reply that produced it proves about
    /// the host.
    ///
    /// `sender` is the address the reply actually came from, or `None` when the
    /// verdict came from a spent attempt budget rather than from a packet. It
    /// matters because an ICMP error names two addresses - the hop that
    /// generated it and the destination of the datagram it quotes - and they are
    /// different claims:
    ///
    /// - **The target answered.** Any segment the host sent proves it is up, and
    ///   that includes the ones negative about the port. A RST is the clearest
    ///   case: it is the technique's evidence *against* a listener and evidence
    ///   *for* a live stack at the same time, and it is the row most easily
    ///   forgotten because the port verdict reads negative while the host
    ///   verdict does not.
    /// - **A middlebox rejected the probe by policy.** Something is enforcing a
    ///   perimeter around this address, which is [`HostStatus::Filtered`] -
    ///   materially different from an address nothing answers for.
    /// - **Nothing answered.** A verdict reached from silence records nothing.
    ///   Silence is not evidence about a host, and promoting it would make
    ///   `is_alive()` true for a host that has never sent a packet.
    fn record_port(&mut self, ip: IpAddr, port_num: u16, state: PortState, sender: Option<IpAddr>) {
        let port = crate::fingerprinting::baseline_port(port_num, Protocol::Tcp, state);
        let evidence = match (state, sender) {
            (PortState::Open, _) => Some((
                HostStatus::Up,
                StatusReason::new(StatusProtocol::TcpSyn, "syn-ack from a probed port"),
            )),
            // Both verdicts a RST can produce: closed for the techniques that
            // read it as an absent listener, unfiltered for the ACK scan, which
            // reads it as a probe that arrived.
            (PortState::Closed | PortState::Unfiltered, _) => Some((
                HostStatus::Up,
                StatusReason::new(self.status_protocol(), rst_evidence(self.technique)),
            )),
            (PortState::Filtered, Some(sender)) if sender == ip => Some((
                HostStatus::Up,
                StatusReason::new(
                    StatusProtocol::IcmpUnreachable,
                    "unreachable for a probed port, from the host",
                ),
            )),
            (PortState::Filtered, Some(sender)) => Some((
                HostStatus::Filtered,
                StatusReason::new(
                    StatusProtocol::IcmpUnreachable,
                    "unreachable for a probed port, from the path",
                )
                .from_source(sender),
            )),
            _ => None,
        };

        self.ctx.update_host(ip, |host| {
            host.add_port(port);
            if let Some((status, reason)) = evidence {
                host.record_evidence(status, reason);
            }
        });
    }

    /// Which protocol a host verdict from this scan is credited to.
    ///
    /// [`StatusProtocol::TcpSyn`] means what it has always meant, so a report
    /// naming it still describes a half-open connection attempt. Every other
    /// technique credits [`StatusProtocol::Tcp`], with the probe that drew the
    /// answer named in the reason's details.
    const fn status_protocol(&self) -> StatusProtocol {
        match self.technique {
            TcpScanTechnique::Syn => StatusProtocol::TcpSyn,
            _ => StatusProtocol::Tcp,
        }
    }
}

/// What a RST proves, said in the terms of the probe that drew it.
///
/// Static strings rather than a formatted technique name, because
/// [`StatusReason`] holds its details in an `Arc<str>` precisely so thousands of
/// ports reporting the same rationale cost one allocation between them.
const fn rst_evidence(technique: TcpScanTechnique) -> &'static str {
    match technique {
        TcpScanTechnique::Syn => "rst from a probed port",
        TcpScanTechnique::Fin => "rst to a fin probe",
        TcpScanTechnique::Null => "rst to a flagless probe",
        TcpScanTechnique::Xmas => "rst to a fin-psh-urg probe",
        TcpScanTechnique::Maimon => "rst to a fin-ack probe",
        TcpScanTechnique::Ack => "rst to an ack probe",
    }
}

/// Sends one probe of `technique` from `src_port` at `dst_addr:dst_port` and
/// returns the token it went out carrying, so a later reply can be recognized as
/// answering this attempt.
///
/// The nonce is drawn fresh here rather than by the caller, because it is the
/// one thing that must never be repeated between attempts: two probes carrying
/// the same nonce are indistinguishable in their replies, and a round trip
/// measured against the wrong one is worse than no measurement.
///
/// `reason` receives the failure when there is one, so a scan whose probes never
/// reached the wire can say why in its report rather than only in a log line. A
/// probe that was never sent and a probe nobody answered are indistinguishable
/// in a port count and could hardly be more different in what they mean.
fn send_tcp_probe(
    sender: &dyn ProbeSender,
    technique: TcpScanTechnique,
    src_port: u16,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    dst_port: u16,
    reason: &mut Option<String>,
) -> Option<TcpToken> {
    let nonce: u32 = rand::random();

    let packet = match tcp::create_probe(technique, &src_addr, &dst_addr, src_port, dst_port, nonce)
    {
        Ok(packet) => packet,
        Err(e) => {
            error!(
                verbosity = 2,
                "Failed to create {technique} probe for {dst_addr}:{dst_port}: {e}"
            );
            return None;
        }
    };

    match sender.send(&packet, src_addr, dst_addr) {
        Ok(()) => {
            success!(
                verbosity = 2,
                "Sent {technique} probe to {dst_addr}:{dst_port}"
            );
            Some(TcpToken { nonce })
        }
        Err(e) => {
            // `{e:#}` rather than `{e}`: the outer message says which probe
            // failed, and the chained cause is the operating system's own
            // explanation - "No route to host" and "Permission denied" call for
            // completely different responses, and the bare wrapper distinguishes
            // neither.
            error!(
                verbosity = 2,
                "Failed to send {technique} probe to {dst_addr}:{dst_port}: {e:#}"
            );
            *reason = Some(format!("{e:#}"));
            None
        }
    }
}

#[async_trait]
impl PortScanner for TcpPortScanner {
    /// Names the strategy the way a report has to read it.
    ///
    /// A SYN scan keeps [`ScannerKind::SynPort`], which is what every report
    /// this engine has ever written called it and what consumers already parse.
    /// The flag-probe techniques are a different question asked of the same
    /// scanner, and calling their failures `syn_port` would be a plain untruth;
    /// which of them ran is in the phase's settings.
    fn kind(&self) -> ScannerKind {
        match self.technique {
            TcpScanTechnique::Syn => ScannerKind::SynPort,
            _ => ScannerKind::TcpPort,
        }
    }

    fn supported_protocols(&self) -> Vec<Protocol> {
        vec![Protocol::Tcp]
    }

    /// Consumes `targets`, sending one probe for each TCP one, retrying the
    /// ones that go unanswered, and classifying every reply, until each probe
    /// has been resolved or has spent its attempts. UDP and SCTP targets are
    /// skipped, since this scanner does not support them. Anything still
    /// outstanding when the loop ends takes the verdict this technique reads
    /// silence as.
    ///
    /// New targets are admitted only while fewer than `MAX_IN_FLIGHT` probes
    /// are outstanding, and retries are serviced before new targets are taken,
    /// since a retry is an obligation the scan already owns.
    async fn scan(&mut self, mut targets: mpsc::Receiver<Target>) -> Result<(), StrategyError> {
        let mut sending_finished = false;

        loop {
            // Read once per iteration and reused throughout it: a scan at rate
            // takes this path constantly, and the arithmetic below only needs
            // the instants to agree with each other.
            let now = Instant::now();
            self.service_retries(now);

            if self.ctx.handle.should_stop() || self.deadline.hard_deadline_passed() {
                break;
            }
            if sending_finished && self.ledger.is_empty() {
                break;
            }
            // Silence is only evidence once nothing is outstanding. With probes
            // still waiting on their timers, quiet is exactly what the retry
            // schedule expects and is no reason to conclude anything.
            if self.ledger.is_empty() && self.deadline.has_expired() {
                break;
            }

            // Both are read off `self` before the `select!`, which borrows the
            // receive half mutably for the duration of the statement.
            let admitting = !sending_finished && self.ledger.len() < MAX_IN_FLIGHT;
            let tick = self.tick_delay(now);

            tokio::select! {
                target = targets.recv(), if admitting => {
                    match target {
                        Some(target) => self.send_probe(target),
                        None => sending_finished = true,
                    }
                }

                res = self.transport.rx.recv() => {
                    match res {
                        Some(reply) => self.handle_reply(&reply, Instant::now()),
                        None => break,
                    }
                }

                // Wakes when the next probe is due, so a retry is sent on time
                // even though nothing is arriving to wake the loop otherwise.
                _ = tokio::time::sleep(tick) => {}
            }
        }

        self.resolve_remaining_as_silent();

        // Reported once with the first cause, for the reason in
        // `RoutedScanner`: a port scan that could not send is not a port scan
        // that found everything closed, and only this channel says so.
        if self.sends_failed > 0 {
            self.ctx.record_failure(
                self.kind(),
                format!(
                    "{} probes could not be sent, so their ports are reported \
                     unanswered without having been asked: {}",
                    self.sends_failed,
                    self.send_failure.as_deref().unwrap_or("cause unrecorded"),
                ),
            );
        }
        Ok(())
    }

    /// Fingerprints every open port the scan found. The raw exchange that
    /// classified each port never opened a connection, so this second pass makes
    /// one per open port and runs the shared fingerprint engine over it.
    ///
    /// Needs no branch on the technique. Only a SYN scan reports a port
    /// [`PortState::Open`] (see [`TcpScanTechnique::finds_open_ports`]), so after
    /// any other one this finds nothing to identify and returns immediately -
    /// the data already guarantees what a condition here would have enforced.
    async fn detect_services(&mut self, ctx: &ScanContext) {
        service::detect(ctx).await;
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

    use pnet::ipnetwork::{IpNetwork, Ipv4Network};
    use pnet::packet::icmp::destination_unreachable::{
        DestinationUnreachablePacket, IcmpCodes, MutableDestinationUnreachablePacket,
    };
    use pnet::packet::icmp::{IcmpCode, IcmpTypes};
    use pnet::packet::tcp::MutableTcpPacket;

    use crate::core::session::ScanSession;
    use crate::network::probe::{MockSender, ProbeTransport};
    use crate::protocols::ip;

    const SYN: u8 = 1 << 1;
    const RST: u8 = 1 << 2;
    const ACK: u8 = 1 << 4;
    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
    /// This host's address on [`on_link_interface`], which its probes leave from.
    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
    const LOCAL_IP: IpAddr = IpAddr::V4(LOCAL);
    /// A router between here and [`TARGET`], which reports errors under its own
    /// address rather than the target's.
    const ROUTER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

    /// An interface whose /24 contains [`TARGET`], so source resolution
    /// answers on-link without a kernel route probe.
    fn on_link_interface() -> pnet::datalink::NetworkInterface {
        pnet::datalink::NetworkInterface {
            name: "test0".to_string(),
            description: String::new(),
            index: 0,
            mac: None,
            ips: vec![IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 50), 24).unwrap(),
            )],
            flags: 0,
        }
    }

    /// Builds a bare 20-byte TCP segment as a captured reply arrives, once the
    /// link and IP headers are stripped: from `from_port` on the target, back to
    /// `to_port` here, echoing the probe's nonce the way a stack answering
    /// `technique` would.
    ///
    /// The echo rule is written out from RFC 793 §3.4 rather than taken from
    /// [`tcp::echoed_nonce`], so a wrong rule in the engine fails these tests
    /// instead of agreeing with itself. A probe carrying ACK hands the reset its
    /// sequence number; otherwise the reset acknowledges the probe's sequence
    /// number plus the octet a FIN or SYN occupies, which is why a flagless
    /// probe is acknowledged unchanged.
    fn segment_to(
        from_port: u16,
        to_port: u16,
        technique: TcpScanTechnique,
        token: TcpToken,
        flags: u8,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 20];
        let mut tcp = MutableTcpPacket::new(&mut buf).unwrap();
        tcp.set_source(from_port);
        tcp.set_destination(to_port);
        tcp.set_data_offset(5);
        tcp.set_flags(flags);

        match technique {
            TcpScanTechnique::Maimon | TcpScanTechnique::Ack => tcp.set_sequence(token.nonce),
            TcpScanTechnique::Null => tcp.set_acknowledgement(token.nonce),
            _ => tcp.set_acknowledgement(token.nonce.wrapping_add(1)),
        }
        buf
    }

    /// [`segment_to`] addressed where a real answer would arrive: the one port
    /// this scan sends from.
    fn tcp_segment(
        scanner: &TcpPortScanner,
        from_port: u16,
        token: TcpToken,
        flags: u8,
    ) -> Vec<u8> {
        segment_to(from_port, scanner.src_port, scanner.technique, token, flags)
    }

    /// The probes a [`MockSender`] recorded, shared with the scanner under test.
    type SentProbes = std::sync::Arc<std::sync::Mutex<Vec<crate::network::probe::SentProbe>>>;

    /// A SYN scanner wired to a recording [`MockSender`] and an idle capture
    /// stream, plus the session store to assert against and the probe log to
    /// read tokens back out of.
    fn scanner_with_mock() -> (TcpPortScanner, ScanSession, SentProbes) {
        scanner_for(TcpScanTechnique::Syn)
    }

    /// [`scanner_with_mock`] for an explicit technique.
    fn scanner_for(technique: TcpScanTechnique) -> (TcpPortScanner, ScanSession, SentProbes) {
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport = ProbeTransport::from_parts(Box::new(sender), reply_rx);
        let resolver = SourceResolver::from_interfaces(&[on_link_interface()]);
        let scanner = TcpPortScanner::with_transport(resolver, ctx, technique, transport, 8);
        (scanner, session, sent)
    }

    /// Sends a probe to `TARGET:port` and returns the token it went out
    /// carrying, so a matching reply can be synthesized.
    ///
    /// The token is read back off the recording sender rather than out of the
    /// scanner, so what a test answers is what actually reached the wire.
    fn probe(scanner: &mut TcpPortScanner, sent: &SentProbes, port: u16) -> TcpToken {
        let before = sent.lock().unwrap().len();
        scanner.send_probe(Target {
            ip: TARGET,
            port,
            protocol: Protocol::Tcp,
        });

        let sent = sent.lock().unwrap();
        let (segment, _, _) = sent.get(before).expect("probe reached the wire");
        token_of(scanner.technique, segment)
    }

    /// The nonce a recorded probe went out carrying, read from whichever field
    /// its technique writes it to.
    fn token_of(technique: TcpScanTechnique, segment: &[u8]) -> TcpToken {
        let tcp = TcpPacket::new(segment).expect("probe is a TCP segment");
        TcpToken {
            nonce: match technique {
                TcpScanTechnique::Maimon | TcpScanTechnique::Ack => tcp.get_acknowledgement(),
                _ => tcp.get_sequence(),
            },
        }
    }

    /// The token the most recent probe went out carrying.
    fn last_probe(technique: TcpScanTechnique, sent: &SentProbes) -> TcpToken {
        let sent = sent.lock().unwrap();
        let (segment, _, _) = sent.last().expect("a probe reached the wire");
        token_of(technique, segment)
    }

    fn port_state(session: &ScanSession, port: u16) -> Option<PortState> {
        session
            .hosts()
            .get(&TARGET)
            .and_then(|h| h.ports().find(|p| p.number() == port).map(|p| p.state()))
    }

    #[test]
    fn syn_ack_matching_probe_is_open() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 80);

        let reply = tcp_segment(&scanner, 80, token, SYN | ACK);
        scanner.handle_tcp_reply(TARGET, &reply, Instant::now());

        assert_eq!(port_state(&session, 80), Some(PortState::Open));
        assert!(!scanner.ledger.contains(&(TARGET, 80)));
    }

    #[test]
    fn rst_matching_probe_is_closed() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 81);

        let reply = tcp_segment(&scanner, 81, token, RST | ACK);
        scanner.handle_tcp_reply(TARGET, &reply, Instant::now());

        assert_eq!(port_state(&session, 81), Some(PortState::Closed));
    }

    #[test]
    fn reply_carrying_the_wrong_nonce_is_ignored() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 82);

        // Acknowledges a value this scan never sent: a stray or spoofed
        // segment, not a reply to our probe.
        let stray = TcpToken {
            nonce: token.nonce.wrapping_add(999),
        };
        let reply = tcp_segment(&scanner, 82, stray, SYN | ACK);
        scanner.handle_tcp_reply(TARGET, &reply, Instant::now());

        assert_eq!(port_state(&session, 82), None);
        assert!(scanner.ledger.contains(&(TARGET, 82)));
    }

    /// The scan's source port is where its answers arrive. A segment carrying
    /// the right nonce but addressed to another port on this host belongs to
    /// somebody else's conversation, and the capture that would normally have
    /// dropped it does not exist on a synthetic transport.
    #[test]
    fn reply_addressed_to_another_port_on_this_host_is_ignored() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 83);

        let elsewhere = scanner.src_port.wrapping_add(1);
        let reply = segment_to(83, elsewhere, scanner.technique, token, SYN | ACK);
        scanner.handle_tcp_reply(TARGET, &reply, Instant::now());

        assert_eq!(port_state(&session, 83), None);
        assert!(scanner.ledger.contains(&(TARGET, 83)));
    }

    #[test]
    fn reply_for_unprobed_port_is_ignored() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 80);

        // Same host, but a port we never probed.
        let reply = tcp_segment(&scanner, 1234, token, SYN | ACK);
        scanner.handle_tcp_reply(TARGET, &reply, Instant::now());

        assert_eq!(port_state(&session, 1234), None);
        assert!(scanner.ledger.contains(&(TARGET, 80)));
    }

    #[test]
    fn unanswered_probes_resolve_as_filtered() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 443);

        scanner.resolve_remaining_as_silent();

        assert_eq!(port_state(&session, 443), Some(PortState::Filtered));
        assert!(scanner.ledger.is_empty());
    }

    // ── Techniques ─────────────────────────────────────────────────────────

    /// The same RST, three verdicts. Getting this table wrong reports a firewall
    /// map as a list of closed ports, or the reverse.
    #[test]
    fn a_rst_is_read_according_to_the_probe_that_drew_it() {
        for (technique, expected) in [
            (TcpScanTechnique::Syn, PortState::Closed),
            (TcpScanTechnique::Fin, PortState::Closed),
            (TcpScanTechnique::Null, PortState::Closed),
            (TcpScanTechnique::Xmas, PortState::Closed),
            (TcpScanTechnique::Maimon, PortState::Closed),
            (TcpScanTechnique::Ack, PortState::Unfiltered),
        ] {
            let (mut scanner, session, sent) = scanner_for(technique);
            let token = probe(&mut scanner, &sent, 80);

            let reply = tcp_segment(&scanner, 80, token, RST | ACK);
            scanner.handle_tcp_reply(TARGET, &reply, Instant::now());

            assert_eq!(port_state(&session, 80), Some(expected), "{technique}");
        }
    }

    /// A RST is negative about the port and positive about the host, whichever
    /// probe drew it: the row most easily forgotten, since the two verdicts
    /// point opposite ways.
    #[test]
    fn a_rst_proves_the_host_is_up_whatever_it_says_about_the_port() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Fin);
        let token = probe(&mut scanner, &sent, 80);

        let reply = tcp_segment(&scanner, 80, token, RST | ACK);
        scanner.handle_tcp_reply(TARGET, &reply, Instant::now());

        let host = session.hosts().get(&TARGET).expect("host recorded");
        assert!(host.status().is_up());
    }

    /// Nothing but a SYN can provoke a SYN+ACK, so one arriving mid-FIN-scan
    /// answered something else and must not be read as an open port.
    #[test]
    fn a_syn_ack_resolves_nothing_for_a_flag_probe() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Fin);
        let token = probe(&mut scanner, &sent, 80);

        let reply = tcp_segment(&scanner, 80, token, SYN | ACK);
        scanner.handle_tcp_reply(TARGET, &reply, Instant::now());

        assert_eq!(port_state(&session, 80), None);
        assert!(scanner.ledger.contains(&(TARGET, 80)));
    }

    /// What silence means is the other half of the difference between the
    /// families: a SYN or an ACK any live stack would have answered, a flag
    /// probe an open port is required to ignore.
    #[test]
    fn silence_is_filtered_or_open_filtered_by_technique() {
        for (technique, expected) in [
            (TcpScanTechnique::Syn, PortState::Filtered),
            (TcpScanTechnique::Ack, PortState::Filtered),
            (TcpScanTechnique::Fin, PortState::OpenFiltered),
            (TcpScanTechnique::Null, PortState::OpenFiltered),
            (TcpScanTechnique::Xmas, PortState::OpenFiltered),
            (TcpScanTechnique::Maimon, PortState::OpenFiltered),
        ] {
            let (mut scanner, session, sent) = scanner_for(technique);
            probe(&mut scanner, &sent, 443);

            scanner.resolve_remaining_as_silent();

            assert_eq!(port_state(&session, 443), Some(expected), "{technique}");
        }
    }

    /// Silence records nothing about the host, whichever verdict it produces.
    /// Promoting it would make `is_alive()` true for a host that has never sent
    /// a packet.
    #[test]
    fn an_unanswered_probe_says_nothing_about_the_host() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Xmas);
        probe(&mut scanner, &sent, 443);

        scanner.resolve_remaining_as_silent();

        let host = session.hosts().get(&TARGET).expect("the port was recorded");
        assert!(!host.status().is_up());
    }

    /// A flag-probe scan and a SYN scan are different strategies as far as a
    /// report is concerned, even though one scanner runs both.
    #[test]
    fn the_reported_strategy_names_the_probe_that_was_sent() {
        assert_eq!(
            scanner_for(TcpScanTechnique::Syn).0.kind(),
            ScannerKind::SynPort
        );
        assert_eq!(
            scanner_for(TcpScanTechnique::Fin).0.kind(),
            ScannerKind::TcpPort
        );
    }

    // ── ICMP errors ────────────────────────────────────────────────────────

    /// An ICMP error as the capture would deliver it, quoting `quoted` back.
    fn icmp_error_quoting(code: IcmpCode, quoted: &[u8], from: IpAddr) -> CapturedSegment {
        let quotation = quote(quoted);
        let mut bytes =
            vec![0u8; DestinationUnreachablePacket::minimum_packet_size() + quotation.len()];
        let mut packet = MutableDestinationUnreachablePacket::new(&mut bytes).unwrap();
        packet.set_icmp_type(IcmpTypes::DestinationUnreachable);
        packet.set_icmp_code(code);
        packet.set_payload(&quotation);

        CapturedSegment {
            source: from,
            protocol: IpNextHeaderProtocols::Icmp,
            bytes,
        }
    }

    /// The probe under the IP header a router would have echoed back with it.
    fn quote(probe: &[u8]) -> Vec<u8> {
        let header = ip::create_ipv4_header(
            LOCAL,
            match TARGET {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => unreachable!("the fixture is v4"),
            },
            probe.len() as u16,
            IpNextHeaderProtocols::Tcp,
        )
        .unwrap();
        header.into_iter().chain(probe.iter().copied()).collect()
    }

    /// The most recent probe exactly as it left, for an error to quote.
    fn last_probe_bytes(sent: &SentProbes) -> Vec<u8> {
        let sent = sent.lock().unwrap();
        sent.last().expect("a probe reached the wire").0.clone()
    }

    /// The near-miss that separates the two scanners: an ICMP *port* unreachable
    /// means a closed port when it answers a UDP probe, and cannot mean that
    /// here - no TCP stack emits one - so something in the path rejected the
    /// probe, which is filtered.
    #[test]
    fn a_port_unreachable_about_a_tcp_probe_is_filtered_not_closed() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Fin);
        probe(&mut scanner, &sent, 80);

        let error = icmp_error_quoting(
            IcmpCodes::DestinationPortUnreachable,
            &last_probe_bytes(&sent),
            ROUTER,
        );
        scanner.handle_reply(&error, Instant::now());

        assert_eq!(port_state(&session, 80), Some(PortState::Filtered));
        assert!(scanner.ledger.is_empty());
    }

    /// The verdict a flag probe cannot reach from silence, and the whole reason
    /// these techniques ask for ICMP at all: `Filtered` where an unanswered
    /// probe would have said open-filtered.
    #[test]
    fn an_administrative_rejection_beats_the_silence_verdict() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Xmas);
        probe(&mut scanner, &sent, 80);

        let error = icmp_error_quoting(
            IcmpCodes::CommunicationAdministrativelyProhibited,
            &last_probe_bytes(&sent),
            ROUTER,
        );
        scanner.handle_reply(&error, Instant::now());

        assert_eq!(port_state(&session, 80), Some(PortState::Filtered));
        assert_ne!(port_state(&session, 80), Some(PortState::OpenFiltered));
    }

    /// A middlebox refusing on a host's behalf is not the host answering. The
    /// address is enforcing a perimeter, which is `Filtered`, and reading it as
    /// `Up` would credit a NAT's reply to the machine behind it.
    #[test]
    fn a_rejection_from_the_path_does_not_prove_the_host_is_up() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Fin);
        probe(&mut scanner, &sent, 80);

        let error = icmp_error_quoting(
            IcmpCodes::CommunicationAdministrativelyProhibited,
            &last_probe_bytes(&sent),
            ROUTER,
        );
        scanner.handle_reply(&error, Instant::now());

        let host = session.hosts().get(&TARGET).expect("host recorded");
        assert_eq!(host.status(), HostStatus::Filtered);
    }

    /// The same message from the target itself is a host policing its own
    /// traffic, which is a host that exists.
    #[test]
    fn a_rejection_from_the_host_proves_it_is_up() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Fin);
        probe(&mut scanner, &sent, 80);

        let error = icmp_error_quoting(
            IcmpCodes::CommunicationAdministrativelyProhibited,
            &last_probe_bytes(&sent),
            TARGET,
        );
        scanner.handle_reply(&error, Instant::now());

        let host = session.hosts().get(&TARGET).expect("host recorded");
        assert!(host.status().is_up());
    }

    /// A host unreachable reports on the address, not on the port that happened
    /// to be quoted - so the probe keeps its remaining attempts rather than
    /// taking a verdict the message does not support.
    #[test]
    fn a_host_unreachable_leaves_the_port_undecided() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Fin);
        probe(&mut scanner, &sent, 80);

        let error = icmp_error_quoting(
            IcmpCodes::DestinationHostUnreachable,
            &last_probe_bytes(&sent),
            ROUTER,
        );
        scanner.handle_reply(&error, Instant::now());

        assert_eq!(port_state(&session, 80), None);
        assert!(scanner.ledger.contains(&(TARGET, 80)));
        assert_eq!(
            session.hosts().get(&TARGET).map(|host| host.status()),
            Some(HostStatus::Down)
        );
    }

    /// An error quoting a datagram this scan never sent resolves nothing. The
    /// quoted source port is the only thing that makes it ours, and an ICMP
    /// filter cannot narrow on ports at all - so every ICMP packet on the host
    /// reaches this check.
    #[test]
    fn an_error_quoting_somebody_elses_probe_is_ignored() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Fin);
        probe(&mut scanner, &sent, 80);

        // Same shape, but sent from a port this scan never used.
        let theirs = tcp::create_probe(
            TcpScanTechnique::Fin,
            &LOCAL_IP,
            &TARGET,
            scanner.src_port.wrapping_add(1),
            80,
            0xABCD,
        )
        .unwrap();
        let error = icmp_error_quoting(
            IcmpCodes::CommunicationAdministrativelyProhibited,
            &theirs,
            ROUTER,
        );
        scanner.handle_reply(&error, Instant::now());

        assert_eq!(port_state(&session, 80), None);
        assert!(scanner.ledger.contains(&(TARGET, 80)));
    }

    /// A SYN scan does not ask its capture for ICMP, so nothing here should
    /// depend on it - but a stray error must still resolve nothing rather than
    /// panic, since a shared interface can deliver one anyway.
    #[test]
    fn a_truncated_error_resolves_nothing() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 80);

        let mut error = icmp_error_quoting(
            IcmpCodes::DestinationPortUnreachable,
            &last_probe_bytes(&sent),
            ROUTER,
        );
        error.bytes.truncate(12);
        scanner.handle_reply(&error, Instant::now());

        assert_eq!(port_state(&session, 80), None);
        assert!(scanner.ledger.contains(&(TARGET, 80)));
    }

    #[test]
    fn non_tcp_targets_are_not_probed() {
        let (mut scanner, _session, _sent) = scanner_with_mock();
        scanner.send_probe(Target {
            ip: TARGET,
            port: 53,
            protocol: Protocol::Udp,
        });
        assert!(scanner.ledger.is_empty());
    }

    // ── Retransmission ─────────────────────────────────────────────────────

    /// An unanswered probe goes out again, and the port stays undecided in the
    /// meantime rather than being written off after one silence.
    #[test]
    fn an_unanswered_probe_is_sent_again() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 80);

        scanner.service_retries(Instant::now() + Duration::from_secs(1));

        assert_eq!(sent.lock().unwrap().len(), 2, "the probe was not retried");
        assert!(scanner.ledger.contains(&(TARGET, 80)));
        assert_eq!(port_state(&session, 80), None, "no verdict has been earned");
    }

    /// Filtered is what exhausting the budget means, and it takes the whole
    /// budget to get there.
    #[test]
    fn a_port_is_filtered_only_once_every_attempt_is_spent() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 80);

        let mut now = Instant::now();
        for _ in 0..RETRY_POLICY.max_attempts + 2 {
            now += Duration::from_secs(4);
            scanner.service_retries(now);
        }

        assert_eq!(port_state(&session, 80), Some(PortState::Filtered));
        assert_eq!(
            sent.lock().unwrap().len(),
            usize::from(RETRY_POLICY.max_attempts),
        );
        assert!(scanner.ledger.is_empty());
    }

    /// An answered probe must not be resent: a retry after a verdict is pure
    /// traffic, and on a wide scan it multiplies.
    #[test]
    fn an_answered_probe_is_never_retried() {
        let (mut scanner, _session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 80);
        let reply = tcp_segment(&scanner, 80, token, SYN | ACK);
        scanner.handle_tcp_reply(TARGET, &reply, Instant::now());

        scanner.service_retries(Instant::now() + Duration::from_secs(10));

        assert_eq!(sent.lock().unwrap().len(), 1);
    }

    /// Each attempt carries its own nonce, so a reply to the first arriving
    /// after the second has gone out is still a reply. Matching only the newest
    /// attempt would discard it and report an open port filtered.
    #[test]
    fn a_reply_to_a_superseded_attempt_still_resolves_the_port() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let first = probe(&mut scanner, &sent, 80);

        scanner.service_retries(Instant::now() + Duration::from_secs(1));
        let second = last_probe(scanner.technique, &sent);
        assert_ne!(
            first.nonce, second.nonce,
            "each attempt needs its own identity"
        );

        let reply = tcp_segment(&scanner, 80, first, SYN | ACK);
        scanner.handle_tcp_reply(TARGET, &reply, Instant::now());

        assert_eq!(port_state(&session, 80), Some(PortState::Open));
    }

    /// The other half of that identity, and the one this scan does *not* vary:
    /// every attempt leaves from the port the capture filter was built around,
    /// so a retry's answer arrives where the scan is listening rather than
    /// somewhere the kernel has already dropped.
    #[test]
    fn every_attempt_leaves_from_the_scans_own_port() {
        let (mut scanner, _session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 80);
        scanner.service_retries(Instant::now() + Duration::from_secs(1));

        let ports: Vec<u16> = sent
            .lock()
            .unwrap()
            .iter()
            .map(|(segment, _, _)| TcpPacket::new(segment).unwrap().get_source())
            .collect();

        assert_eq!(ports.len(), 2, "the probe was not retried");
        assert!(
            ports.iter().all(|port| *port == scanner.src_port),
            "probes left from {ports:?}, not from {}",
            scanner.src_port
        );
    }

    /// Two answers, one port: the second finds nothing outstanding and is
    /// dropped, so it cannot be credited as a second observation.
    #[test]
    fn a_duplicate_reply_resolves_nothing_further() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 80);

        let reply = tcp_segment(&scanner, 80, token, SYN | ACK);
        scanner.handle_tcp_reply(TARGET, &reply, Instant::now());
        scanner.handle_tcp_reply(TARGET, &reply, Instant::now());

        let host = session.hosts().get(&TARGET).expect("host recorded");
        assert_eq!(host.ports().filter(|p| p.number() == 80).count(), 1);
    }

    /// The scan has to outlive the schedule it commits each probe to, or ports
    /// are written off having never been fully asked.
    #[test]
    fn the_scan_budget_covers_the_whole_retry_schedule() {
        let lifetime = RETRY_POLICY.worst_case_probe_lifetime();
        let budget = DEADLINE_CONFIG
            .allowing_for(lifetime)
            .max_budget
            .for_target_count(1);

        assert!(
            budget > lifetime,
            "a {budget:?} scan cannot finish a {lifetime:?} probe"
        );
    }
}
