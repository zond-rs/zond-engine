// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # SYN Port Probing
//!
//! Implements the privileged half of [`crate::scanner::scan`]. It probes
//! specific `(address, port)` pairs with raw TCP SYN packets and classifies each
//! one by whether and how it responds, rather than completing a full TCP
//! handshake per port the way the unprivileged fallback in
//! [`crate::scanner::connect`] must.
//!
//! A SYN+ACK means the port is open and a RST means it is closed. Silence means
//! nothing on its own, so it is answered with another probe: only when a port
//! has spent its whole retry budget in silence is it reported filtered, which is
//! the difference between observing a firewall and assuming one.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pnet::packet::tcp::TcpPacket;
use tokio::sync::mpsc;

use crate::core::config::ProbeTuning;
use crate::core::models::deadline::AdaptiveDeadline;
use crate::core::models::host::{HostStatus, StatusProtocol, StatusReason};
use crate::core::models::port::{PortState, Protocol};
use crate::core::models::retry::{Due, ProbeLedger, RetryPolicy};
use crate::core::models::target::Target;
use crate::core::session::{ScanContext, ScannerKind};
use crate::error;
use crate::network::probe::{ProbeKind, ProbeTransport};
use crate::protocols::tcp::{self, ProbeResponse};
use crate::scanner::{PortScanner, service};
use crate::system::interface::SourceResolver;

// Port scanning and routed discovery send the same kind of raw TCP SYN over the
// same kind of network path, so they share one adaptive-deadline profile rather
// than keeping two copies in step.
use super::{DEADLINE_CONFIG, RETRY_POLICY, SynToken, send_syn};

/// The probe a reply refers to: the `(address, port)` it was sent to.
type ProbeTarget = (IpAddr, u16);

/// Outstanding probes and the schedule they are retried on.
type Ledger = ProbeLedger<ProbeTarget, SynToken>;

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

/// Probes specific `(address, port)` pairs with raw TCP SYN packets.
///
/// Unlike [`RoutedScanner`](super::RoutedScanner), which sends one SYN per host
/// purely to check for a pulse, this sends one per `(address, port)` pair it is
/// given and reports what each one revealed.
pub struct SynPortScanner {
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

impl SynPortScanner {
    /// Builds a scanner that selects each probe's source via `resolver`, sized
    /// for a scan covering `target_count` `(address, port)` pairs.
    pub fn new(
        resolver: SourceResolver,
        ctx: ScanContext,
        target_count: usize,
        tuning: ProbeTuning,
    ) -> anyhow::Result<Self> {
        let transport = ProbeTransport::open_with(ProbeKind::TcpSyn, tuning.send_mode)?;
        Ok(Self::build(
            resolver,
            ctx,
            transport,
            target_count,
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
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_transport(
        resolver: SourceResolver,
        ctx: ScanContext,
        transport: ProbeTransport,
        target_count: usize,
    ) -> Self {
        Self::build(resolver, ctx, transport, target_count, RETRY_POLICY)
    }

    /// The common constructor, taking the retry schedule as an argument because
    /// it is the one thing the two public ones disagree about - and because the
    /// scan's own deadline is derived from it, so it has to be settled before
    /// anything is built rather than patched in afterwards.
    fn build(
        resolver: SourceResolver,
        ctx: ScanContext,
        transport: ProbeTransport,
        target_count: usize,
        retry: RetryPolicy,
    ) -> Self {
        // The scan has to outlive its own retry schedule, or probes are written
        // off as unanswered having never been fully asked.
        let deadline_config = DEADLINE_CONFIG.allowing_for(retry.worst_case_probe_lifetime());

        Self {
            resolver,
            ctx,
            transport,
            deadline: AdaptiveDeadline::new(deadline_config, target_count),
            ledger: Ledger::new(retry, target_count.min(MAX_IN_FLIGHT)),
            due: Vec::new(),
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

    /// Sends one SYN at `(ip, port)` and records the attempt.
    ///
    /// Used for the first attempt and every retry alike. Nothing about the probe
    /// is kept between attempts and none of it needs to be: the packet is built
    /// afresh from the target, which is both cheaper than buffering it and
    /// required, since every attempt must carry its own sequence number.
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

        match send_syn(
            self.transport.tx.as_ref(),
            src_addr,
            ip,
            port,
            &mut self.send_failure,
        ) {
            Some(token) => self.ledger.arm(ip, (ip, port), token, now),
            None => self.sends_failed += 1,
        }
    }

    /// Matches a reply against an outstanding probe and, if it is one,
    /// classifies it and records the port's state.
    fn handle_reply(&mut self, ip: IpAddr, bytes: &[u8], now: Instant) {
        let Some(tcp_packet) = TcpPacket::new(bytes) else {
            return;
        };

        let Some(response) = tcp::classify_probe_response(&tcp_packet) else {
            return;
        };

        // What the segment claims to be answering. The ledger checks it against
        // every attempt still live for this port, so a reply to an earlier
        // attempt that arrives after a retry has gone out is still recognized -
        // and names which attempt it answered, so the round trip it yields is
        // the real one.
        let token = SynToken {
            seq: tcp_packet.get_acknowledgement().wrapping_sub(1),
            src_port: tcp_packet.get_destination(),
        };
        let key = (ip, tcp_packet.get_source());

        // A token matching nothing outstanding is a stray or spoofed segment, a
        // duplicate of a reply already acted on, or an answer to a probe already
        // written off. None of those may resolve a port.
        let Some(resolution) = self.ledger.resolve(&key, Some(token), now) else {
            return;
        };

        self.deadline.mark_activity();
        if let Some(rtt) = resolution.rtt {
            self.deadline.record_rtt(rtt);
        }

        let state = match response {
            ProbeResponse::Open => PortState::Open,
            ProbeResponse::Closed => PortState::Closed,
        };
        self.record_port(ip, key.1, state);
    }

    /// Resends everything due and writes off everything that has run out of
    /// attempts.
    ///
    /// Exhaustion is the only thing that produces `Filtered` during a scan, and
    /// it is what makes the verdict mean something: no SYN+ACK and no RST
    /// arrived across every attempt, which is the signature of a firewall
    /// dropping the probe rather than answering it. It is deliberately not
    /// treated as activity - nothing answered - so it never extends the scan's
    /// own deadline.
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
                Due::Exhausted((ip, port)) => self.record_port(ip, port, PortState::Filtered),
            }
        }
        self.due = due;
        self.due.clear();
    }

    /// Marks every probe still outstanding when the scan stops as filtered.
    ///
    /// [`service_retries`](Self::service_retries) retires most probes as their
    /// budgets run out; what reaches here are the ones still mid-schedule when
    /// the scan itself ended.
    fn resolve_remaining_as_filtered(&mut self) {
        for (ip, port) in self.ledger.drain_unresolved() {
            self.record_port(ip, port, PortState::Filtered);
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

    /// Files a port verdict and, when that verdict came from a segment the host
    /// sent, records what it proves about the host itself.
    ///
    /// The two are decided together because in this scanner the port state names
    /// its own evidence: `Open` can only come from a SYN+ACK and `Closed` only
    /// from a RST, each of which requires a live stack at the other end. A
    /// closed port is the row most easily forgotten, since the port verdict is
    /// negative while the host verdict is not.
    ///
    /// `Filtered` is the exception and deliberately records nothing. It is
    /// produced by a spent attempt budget - by silence - and silence is not
    /// evidence about a host. Promoting it would make `is_alive()` true for a
    /// host that has never sent a packet.
    fn record_port(&mut self, ip: IpAddr, port_num: u16, state: PortState) {
        let port = crate::fingerprinting::baseline_port(port_num, Protocol::Tcp, state);
        let evidence = match state {
            PortState::Open => Some("syn-ack from a probed port"),
            PortState::Closed => Some("rst from a probed port"),
            _ => None,
        };

        self.ctx.update_host(ip, |host| {
            host.add_port(port);
            if let Some(details) = evidence {
                host.record_evidence(
                    HostStatus::Up,
                    StatusReason::new(StatusProtocol::TcpSyn, details),
                );
            }
        });
    }
}

#[async_trait]
impl PortScanner for SynPortScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::SynPort
    }

    fn supported_protocols(&self) -> Vec<Protocol> {
        vec![Protocol::Tcp]
    }

    /// Consumes `targets`, sending a SYN probe for each TCP one, retrying the
    /// ones that go unanswered, and classifying every reply, until each probe
    /// has been resolved or has spent its attempts. UDP and SCTP targets are
    /// skipped, since this scanner does not support them yet. Anything still
    /// outstanding when the loop ends is reported as filtered.
    ///
    /// New targets are admitted only while fewer than [`MAX_IN_FLIGHT`] probes
    /// are outstanding, and retries are serviced before new targets are taken,
    /// since a retry is an obligation the scan already owns.
    async fn scan(&mut self, mut targets: mpsc::Receiver<Target>) -> anyhow::Result<()> {
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
                        Some(reply) => {
                            self.handle_reply(reply.source, &reply.bytes, Instant::now());
                        }
                        None => break,
                    }
                }

                // Wakes when the next probe is due, so a retry is sent on time
                // even though nothing is arriving to wake the loop otherwise.
                _ = tokio::time::sleep(tick) => {}
            }
        }

        self.resolve_remaining_as_filtered();

        // Reported once with the first cause, for the reason in
        // `RoutedScanner`: a port scan that could not send is not a port scan
        // that found everything closed, and only this channel says so.
        if self.sends_failed > 0 {
            self.ctx.record_failure(
                ScannerKind::SynPort,
                format!(
                    "{} probes could not be sent, so their ports are reported \
                     filtered without having been asked: {}",
                    self.sends_failed,
                    self.send_failure.as_deref().unwrap_or("cause unrecorded"),
                ),
            );
        }
        Ok(())
    }

    /// Fingerprints every open port the SYN pass found. The raw exchange that
    /// classified each port never opened a connection, so this second pass makes
    /// one per open port and runs the shared fingerprint engine over it.
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
    use pnet::packet::tcp::MutableTcpPacket;

    use crate::core::session::ScanSession;
    use crate::network::probe::{MockSender, ProbeTransport};

    const SYN: u8 = 1 << 1;
    const RST: u8 = 1 << 2;
    const ACK: u8 = 1 << 4;
    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));

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
    /// link and IP headers are stripped: from `src_port` on the target, back to
    /// the port the probe was sent from, acknowledging its sequence number.
    fn tcp_segment(src_port: u16, token: SynToken, flags: u8) -> Vec<u8> {
        let mut buf = vec![0u8; 20];
        let mut tcp = MutableTcpPacket::new(&mut buf).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(token.src_port);
        tcp.set_data_offset(5);
        tcp.set_acknowledgement(token.seq.wrapping_add(1));
        tcp.set_flags(flags);
        buf
    }

    /// The probes a [`MockSender`] recorded, shared with the scanner under test.
    type SentProbes = std::sync::Arc<std::sync::Mutex<Vec<crate::network::probe::SentProbe>>>;

    /// A scanner wired to a recording [`MockSender`] and an idle capture
    /// stream, plus the session store to assert against and the probe log to
    /// read tokens back out of.
    fn scanner_with_mock() -> (SynPortScanner, ScanSession, SentProbes) {
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport = ProbeTransport::from_parts(Box::new(sender), reply_rx);
        let resolver = SourceResolver::from_interfaces(&[on_link_interface()]);
        let scanner = SynPortScanner::with_transport(resolver, ctx, transport, 8);
        (scanner, session, sent)
    }

    /// Sends a probe to `TARGET:port` and returns the token it went out
    /// carrying, so a matching reply can be synthesized.
    ///
    /// The token is read back off the recording sender rather than out of the
    /// scanner, so what a test answers is what actually reached the wire.
    fn probe(scanner: &mut SynPortScanner, sent: &SentProbes, port: u16) -> SynToken {
        let before = sent.lock().unwrap().len();
        scanner.send_probe(Target {
            ip: TARGET,
            port,
            protocol: Protocol::Tcp,
        });

        let sent = sent.lock().unwrap();
        let (segment, _, _) = sent.get(before).expect("probe reached the wire");
        let tcp = TcpPacket::new(segment).expect("probe is a TCP segment");
        SynToken {
            seq: tcp.get_sequence(),
            src_port: tcp.get_source(),
        }
    }

    fn port_state(session: &ScanSession, port: u16) -> Option<PortState> {
        session
            .store
            .get(&TARGET)
            .and_then(|h| h.ports().find(|p| p.number() == port).map(|p| p.state()))
    }

    #[test]
    fn syn_ack_matching_probe_is_open() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 80);

        scanner.handle_reply(TARGET, &tcp_segment(80, token, SYN | ACK), Instant::now());

        assert_eq!(port_state(&session, 80), Some(PortState::Open));
        assert!(!scanner.ledger.contains(&(TARGET, 80)));
    }

    #[test]
    fn rst_matching_probe_is_closed() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 81);

        scanner.handle_reply(TARGET, &tcp_segment(81, token, RST | ACK), Instant::now());

        assert_eq!(port_state(&session, 81), Some(PortState::Closed));
    }

    #[test]
    fn reply_with_wrong_ack_is_ignored() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 82);

        // Acknowledgement doesn't correspond to our sequence number: a stray
        // or spoofed segment, not a reply to our probe.
        let stray = SynToken {
            seq: token.seq.wrapping_add(999),
            ..token
        };
        scanner.handle_reply(TARGET, &tcp_segment(82, stray, SYN | ACK), Instant::now());

        assert_eq!(port_state(&session, 82), None);
        assert!(scanner.ledger.contains(&(TARGET, 82)));
    }

    /// The source port is half of a probe's identity. A segment acknowledging
    /// the right sequence number but addressed to a port this scan never sent
    /// from did not answer this scan.
    #[test]
    fn reply_to_a_port_we_never_sent_from_is_ignored() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 83);

        let elsewhere = SynToken {
            src_port: token.src_port.wrapping_add(1),
            ..token
        };
        scanner.handle_reply(
            TARGET,
            &tcp_segment(83, elsewhere, SYN | ACK),
            Instant::now(),
        );

        assert_eq!(port_state(&session, 83), None);
        assert!(scanner.ledger.contains(&(TARGET, 83)));
    }

    #[test]
    fn reply_for_unprobed_port_is_ignored() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 80);

        // Same host, but a port we never probed.
        scanner.handle_reply(TARGET, &tcp_segment(1234, token, SYN | ACK), Instant::now());

        assert_eq!(port_state(&session, 1234), None);
        assert!(scanner.ledger.contains(&(TARGET, 80)));
    }

    #[test]
    fn unanswered_probes_resolve_as_filtered() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 443);

        scanner.resolve_remaining_as_filtered();

        assert_eq!(port_state(&session, 443), Some(PortState::Filtered));
        assert!(scanner.ledger.is_empty());
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
        scanner.handle_reply(TARGET, &tcp_segment(80, token, SYN | ACK), Instant::now());

        scanner.service_retries(Instant::now() + Duration::from_secs(10));

        assert_eq!(sent.lock().unwrap().len(), 1);
    }

    /// Each attempt carries its own sequence number, so a reply to the first
    /// arriving after the second has gone out is still a reply. Matching only
    /// the newest attempt would discard it and report an open port filtered.
    #[test]
    fn a_reply_to_a_superseded_attempt_still_resolves_the_port() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let first = probe(&mut scanner, &sent, 80);

        scanner.service_retries(Instant::now() + Duration::from_secs(1));
        let second = {
            let sent = sent.lock().unwrap();
            let (segment, _, _) = sent.last().expect("retry sent");
            let tcp = TcpPacket::new(segment).unwrap();
            SynToken {
                seq: tcp.get_sequence(),
                src_port: tcp.get_source(),
            }
        };
        assert_ne!(first.seq, second.seq, "each attempt needs its own identity");

        scanner.handle_reply(TARGET, &tcp_segment(80, first, SYN | ACK), Instant::now());

        assert_eq!(port_state(&session, 80), Some(PortState::Open));
    }

    /// Two answers, one port: the second finds nothing outstanding and is
    /// dropped, so it cannot be credited as a second observation.
    #[test]
    fn a_duplicate_reply_resolves_nothing_further() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 80);

        let reply = tcp_segment(80, token, SYN | ACK);
        scanner.handle_reply(TARGET, &reply, Instant::now());
        scanner.handle_reply(TARGET, &reply, Instant::now());

        let host = session.store.get(&TARGET).expect("host recorded");
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
