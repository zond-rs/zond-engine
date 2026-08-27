// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # UDP Port Probing
//!
//! Implements the privileged UDP half of [`crate::scanner::scan`]. It probes
//! specific `(address, port)` pairs with raw UDP packets and classifies each
//! one by whether and how it responds.
//!
//! UDP scanning is harder than the SYN scan next door because UDP carries no
//! handshake to correlate against. A closed port answers with an ICMP Port
//! Unreachable, an open one answers with a UDP datagram *if* it understands
//! what was sent, and a filtered one says nothing at all - which is also what
//! an open port that ignored the probe does. So:
//!
//! - a direct UDP reply is [`PortState::Open`],
//! - an ICMP Port Unreachable is [`PortState::Closed`],
//! - silence until the deadline is [`PortState::OpenFiltered`], because it
//!   genuinely cannot distinguish the two.
//!
//! ## Tying a reply to its probe
//!
//! Every probe in a scan leaves from one fixed source port, chosen when the
//! scanner is built. That single port is what makes both answers correlatable:
//!
//! - A **direct reply** is addressed back to it, so the kernel's BPF filter
//!   admits this scan's replies and drops the rest of the host's UDP traffic
//!   ([`ProbeKind::UdpProbe`]).
//! - An **ICMP error** carries no ports of its own, but RFC 792 requires it to
//!   quote the datagram that caused it - IP header plus the first eight bytes,
//!   which is exactly a whole UDP header. That quotation names the probe: its
//!   source port proves the datagram was ours, and its destination address and
//!   port say *which* probe, so one error retires exactly one probe.
//!
//! Reading the quoted packet rather than the error's own source address also
//! keeps a router's error attributable: the ICMP comes from the router, but the
//! probe it refers to was aimed at the host behind it.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::udp::UdpPacket;
use tokio::sync::mpsc;

use crate::config::ProbeTuning;
use crate::error;
use crate::evasion::SegmentShaping;
use crate::journal::settle::Outcome;
use crate::model::capture::IpObservation;
use crate::model::host::{HostStatus, StatusProtocol, StatusReason};
use crate::model::port::discovery::{Discovery as PortDiscovery, ScanResponse};
use crate::model::port::{PortState, Protocol};
use crate::model::target::PlannedTarget;
use crate::protocols::sizes::UDP_HDR_LEN;
use crate::scanner::pacing::congestion::{CongestionWindow, WindowLimits};
use crate::scanner::pacing::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::scanner::pacing::retry::{ProbeLedger, RetryPolicy, SilentHostPolicy};
use crate::scanner::pacing::timer::ScanBudget;
use crate::scanner::payload;
use crate::scanner::session::{ScanContext, ScannerKind};
use crate::scanner::strategy::{PortScanner, StrategyError};
use crate::system::interface::SourceResolver;
use crate::transport::capture::CapturedSegment;
use crate::transport::probe::{Emission, ProbeKind, ProbeTransport};

use super::icmp_error::{self, Unreachable};
use super::probe_scan::{self, AuditLabels, ProbeTarget, RawPortScan, RawProbeScan};
use super::send_udp;
use crate::scanner::audit::ProbeAudit;

/// Outstanding probes and the schedule they are retried on.
///
/// The attempt token is `()`: a UDP scan sends every probe from one fixed source
/// port, and an ICMP error is only guaranteed to quote the first eight bytes of
/// the datagram, so nothing on the wire distinguishes one attempt from another.
/// The ledger applies Karn's rule on that basis, declining to measure a round
/// trip it cannot attribute.
type Ledger = ProbeLedger<ProbeTarget, (), u64>;

/// How long this scan runs and how it adapts.
///
/// Deliberately *not* the profile the SYN scanners share
/// ([`DEADLINE_CONFIG`](super::DEADLINE_CONFIG)), because the thing being
/// waited for is different in kind. A SYN probe is answered by the target's
/// TCP stack as fast as the link allows. A UDP probe's most informative answer
/// is an ICMP error, and hosts **rate-limit** those: Linux emits roughly one
/// destination-unreachable per second by default (`net.ipv4.icmp_ratelimit`),
/// and BSD does the same. Answers to a multi-port scan therefore arrive spread
/// over seconds no matter how fast the network is.
///
/// That reshapes every number here, but `silence_floor` most of all. The SYN
/// profile gives up after 150 ms of quiet, which is generous for a stack that
/// answers immediately and *meaningless* against a host allowed to speak once
/// per second: the scan would stop while its answers were still queued and
/// legally on their way, then report the ports it never heard about as
/// filtered. A floor above the rate-limit interval is what makes silence
/// evidence of anything at all.
const DEADLINE_CONFIG: AdaptiveDeadlineConfig = AdaptiveDeadlineConfig::new(
    // Hard ceiling: a UDP scan is inherently slow, but it still has to finish.
    ScanBudget::new(
        Duration::from_millis(2_000),
        Duration::from_millis(200),
        Duration::from_secs(45),
    ),
    // Minimum runtime, so a scan cannot conclude before the first rate-limited
    // answers have had time to arrive.
    ScanBudget::new(
        Duration::from_millis(500),
        Duration::from_millis(50),
        Duration::from_secs(10),
    ),
    // Silence floor: longer than one rate-limit interval, so quiet means
    // "nothing is coming" rather than "the host is not allowed to answer yet".
    Duration::from_millis(1_200),
    Duration::from_secs(5),
    4.0,
    20,
);

/// How a UDP probe is retransmitted.
///
/// Every number here is set against a rate limit rather than against a round
/// trip, which is what makes this profile different in kind from the SYN one
/// ([`RETRY_POLICY`](super::RETRY_POLICY)). A closed UDP port answers with an
/// ICMP error, and hosts emit those at roughly one per second; a retry sooner
/// than that interval is guaranteed to be wasted, because the answer it is
/// chasing was never allowed to be sent.
///
/// Two attempts rather than three, and a gentler backoff than the SYN profile
/// uses, for the same reason. Backing off aggressively is how a scanner relieves
/// congestion it is causing, but a UDP scan is not waiting on congestion, it is
/// waiting on permission - so doubling buys little and costs a great deal of
/// tail latency on a scan that is already the slowest thing the engine does. A
/// probe therefore lives about 3.75 s against an unmeasured host and almost
/// exactly 3 s against a measured one, in exchange for every port getting a
/// second chance where it previously got one.
const RETRY_POLICY: RetryPolicy = RetryPolicy::new(
    2,
    Duration::from_millis(1_500),
    Duration::from_millis(1_200),
    Duration::from_secs(5),
    1.5,
    0.2,
    Some(SilentHostPolicy::new(32, 1)),
);

/// The most probes left outstanding at once, and equally the window this scan
/// is paced by — which for UDP is a window that does not move.
///
/// Two jobs: it bounds the memory a scan of a large address space can occupy,
/// and it keeps the send loop from emptying the dispatcher into the network as
/// fast as the socket accepts writes - a burst that outruns any rate-limited
/// host's ability to answer manufactures open-filtered verdicts.
///
/// **Fixed, where the TCP scanner's equivalent adapts.** A congestion window
/// needs evidence, and a UDP scan is given none: silence is its ordinary
/// outcome rather than a signal, and its replies carry nothing naming the
/// attempt they answer, so neither the growth nor the reduction side of the
/// controller has anything to read. See
/// [`congestion`](crate::scanner::pacing::congestion) for the argument, and
/// `UDP_PORT_RATE_PER_SEC` in the parent module for what paces this scan
/// instead.
///
/// The ceiling is global rather than per host because
/// [`Dispatcher`](crate::scanner::dispatcher::Dispatcher) already hands out
/// shuffled targets, so consecutive probes in a multi-host scan naturally land
/// on different hosts. A per-host cap on top of that would constrain something
/// the target stream has already spread out.
const MAX_IN_FLIGHT: u32 = 512;

/// Probes specific `(address, port)` pairs with raw UDP packets.
pub struct UdpPortScanner {
    /// Everything a raw port scan carries and does regardless of protocol: the
    /// transport, the ledger, the deadline, the pacing and the stop conditions.
    /// What stays in this file is what a *UDP* probe is and what its answers
    /// prove - which for UDP is mostly what an ICMP error proves, since an open
    /// port is under no obligation to say anything at all.
    core: RawProbeScan<()>,
}

impl UdpPortScanner {
    /// Builds a scanner that selects each probe's source via `resolver`, sized
    /// for a scan covering `target_count` `(address, port)` pairs.
    ///
    /// The scan's fixed source port is drawn from the high ephemeral range,
    /// where it is unlikely to collide with a listening service on this host,
    /// and the transport's capture filter is built around it.
    pub fn new(
        resolver: SourceResolver,
        ctx: ScanContext,
        target_count: usize,
        tuning: ProbeTuning,
    ) -> Result<Self, StrategyError> {
        let src_port: u16 = tuning
            .evasion
            .source_port_or(rand::random_range(50_000..u16::MAX));
        let emission = tuning.evasion.emission();
        let shaping = tuning.evasion.segment_shaping();
        let transport = ProbeTransport::open_with(
            ProbeKind::UdpProbe {
                reply_port: src_port,
            },
            tuning.send_mode,
        )?;

        Ok(Self::build(
            resolver,
            ctx,
            transport,
            target_count,
            src_port,
            emission,
            shaping,
            RETRY_POLICY.configured(tuning.retry),
            tuning
                .max_probe_rate
                .unwrap_or(super::UDP_PORT_RATE_PER_SEC)
                .max(1),
        ))
    }

    /// Builds a scanner around an already-opened transport, so the caller
    /// decides how probes reach the wire and where replies come from.
    ///
    /// `src_port` must be the port the transport's capture filter was built
    /// around, since it is what both halves use to recognize this scan's own
    /// traffic - see the module documentation. Paired with a synthetic
    /// transport (`ProbeTransport::from_parts`, behind the `test-support`
    /// feature) this is the seam that lets classification be driven against a
    /// simulated network rather than a real one.
    pub fn with_transport(
        resolver: SourceResolver,
        ctx: ScanContext,
        transport: ProbeTransport,
        target_count: usize,
        src_port: u16,
    ) -> Self {
        Self::build(
            resolver,
            ctx,
            transport,
            target_count,
            src_port,
            Emission::routed(),
            SegmentShaping::default(),
            RETRY_POLICY,
            super::UDP_PORT_RATE_PER_SEC,
        )
    }

    /// The common constructor, taking the retry schedule as an argument because
    /// the scan's own deadline is derived from it and so has to be settled
    /// before anything is built.
    #[allow(clippy::too_many_arguments)]
    fn build(
        resolver: SourceResolver,
        ctx: ScanContext,
        transport: ProbeTransport,
        target_count: usize,
        src_port: u16,
        emission: Emission,
        shaping: SegmentShaping,
        retry: RetryPolicy,
        rate_per_sec: u32,
    ) -> Self {
        // Here the rate is the pacing rather than a backstop, because a UDP scan
        // has no evidence to run a window on. See `UDP_PORT_RATE_PER_SEC`.
        let (send_tick, batch) = super::pacing_for(rate_per_sec);

        // The scan has to outlive its own retry schedule, or probes are written
        // off as unanswered having never been fully asked — and it has to
        // outlive its own send rate, which here is the pacing rather than a
        // backstop and is the slowest thing about the scan.
        let deadline_config = DEADLINE_CONFIG
            .allowing_for(retry.worst_case_probe_lifetime())
            .allowing_pace_of(Duration::from_secs(1) / rate_per_sec.max(1), target_count);

        let mut scanner = Self {
            core: RawProbeScan {
                resolver,
                ctx,
                transport,
                deadline: AdaptiveDeadline::new(deadline_config, target_count),
                ledger: Ledger::new(retry, target_count.min(MAX_IN_FLIGHT as usize)),
                due: Vec::new(),
                src_port,
                emission,
                shaping,
                send_failure: None,
                audit: ProbeAudit::new(),
                window: CongestionWindow::new(WindowLimits::fixed(MAX_IN_FLIGHT)),
                send_tick,
                batch,
                max_unresolved: MAX_IN_FLIGHT as usize,
            },
        };

        // What the liveness phase already learned about these hosts, so the
        // first wave of probes is timed against a measurement rather than
        // against a guess. See `RawProbeScan::seed_timing`.
        scanner.core.seed_timing();
        scanner
    }

    /// A reply that matches no outstanding probe is dropped: it is a duplicate
    /// of one already resolved, an answer to a probe already written off, or a
    /// packet that reached us despite not answering anything this scan sent.
    ///
    /// The round trip is whatever the ledger is willing to vouch for. A probe
    /// that was sent once is unambiguous; one that was retried is not, since
    /// the two datagrams are identical on the wire, and no sample is taken.
    fn resolve_probe(
        &mut self,
        target: ProbeTarget,
        state: PortState,
        sender: IpAddr,
        ttl: Option<u8>,
        now: Instant,
    ) {
        let Some(resolution) = self.core.ledger.resolve(&target, None, now) else {
            // A duplicate of one already resolved, an answer to a probe already
            // written off, or a packet that reached us despite answering nothing
            // this scan sent.
            self.core.audit.record_reply_without_rtt();
            return;
        };

        let rtt = resolution.rtt;
        self.core.record_answer(&resolution);
        self.record_port_answered_by(target.0, target.1, state, Some(sender), ttl, rtt);
        // The target spoke: the only outcome that settles positively.
        self.settle(Outcome::Answered {
            position: resolution.payload,
        });
    }
}

/// The port a direct UDP reply answers for, if the datagram is addressed to
/// this scan's source port.
///
/// The capture filter already narrows the UDP half to `src_port`, but that is a
/// performance boundary rather than a guarantee: a transport can be built with
/// no filter at all (`ProbeTransport::from_parts`), and a filter that silently
/// stopped matching would otherwise turn into false `Open`s. The check is cheap
/// and it is the only thing making the reply *ours*.
fn answering_probe(bytes: &[u8], src_port: u16) -> Option<(u16, &[u8])> {
    let udp = UdpPacket::new(bytes)?;
    if udp.get_destination() != src_port {
        return None;
    }
    // The datagram's own payload, which is where the answer to "what is this
    // host" lives when the port's protocol can say. Sliced from `bytes` at the
    // fixed header length rather than taken from the parsed packet, whose
    // borrow ends with it — and rather than derived from the length field,
    // which a padded frame makes shorter than what was actually captured.
    Some((udp.get_source(), &bytes[UDP_HDR_LEN..]))
}

/// What a reply is a statement about: the port that was probed, or the address
/// as a whole.
///
/// The distinction is not cosmetic. A reply reporting on the port resolves the
/// probe that provoked it; one reporting on the host says nothing about any
/// particular port, and the probe is left outstanding to time out on its own
/// rather than being given a verdict its evidence does not support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// The probed port is in this state. Covers both a direct UDP reply and
    /// every ICMP code that reports on a port rather than on the path.
    Port(PortState),
    /// The address itself could not be reached. The only evidence in the engine
    /// that produces [`HostStatus::Down`].
    Host,
}

/// What an ICMP error means for the UDP port it was drawn by.
///
/// A port unreachable is the one unambiguous "closed" a UDP scan ever gets:
/// the datagram reached a stack, which looked for a listener and found none.
/// That reading is specific to UDP - the identical message answering a TCP
/// probe means something else entirely, which is why this mapping lives beside
/// the scanner it belongs to rather than in [`icmp_error`].
fn verdict_of(reason: Unreachable) -> Verdict {
    match reason {
        Unreachable::Port => Verdict::Port(PortState::Closed),
        Unreachable::Prohibited => Verdict::Port(PortState::Filtered),
        Unreachable::Host => Verdict::Host,
    }
}

/// The probe an ICMP error is about and what the error says about it.
///
/// `None` unless the quoted datagram is a UDP probe this scan sent, which its
/// source port is what proves. Its destination address and port name the probe
/// to retire, and both come from the quotation rather than from the error's own
/// header, so an error relayed by a router still points at the host the probe
/// was aimed at.
fn quoted_probe(error: &icmp_error::IcmpError<'_>, src_port: u16) -> Option<ProbeTarget> {
    if error.quoted.protocol != IpNextHeaderProtocols::Udp {
        return None;
    }

    let udp = UdpPacket::new(error.quoted.payload)?;
    if udp.get_source() != src_port {
        return None;
    }

    Some((error.quoted.destination, udp.get_destination()))
}

impl RawPortScan for UdpPortScanner {
    type Token = ();

    fn core(&self) -> &RawProbeScan<()> {
        &self.core
    }

    fn core_mut(&mut self) -> &mut RawProbeScan<()> {
        &mut self.core
    }

    fn protocol(&self) -> Protocol {
        Protocol::Udp
    }

    /// Always open-filtered. UDP carries no handshake, so an open port that did
    /// not recognise the payload says exactly as little as a firewall does, and
    /// no amount of waiting separates the two.
    fn silence_means(&self) -> PortState {
        PortState::OpenFiltered
    }

    fn audit_labels(&self) -> AuditLabels {
        AuditLabels {
            tag: "udp-port",
            silence: "open-filtered",
        }
    }

    /// Sends one datagram at `(ip, port)` and records the attempt.
    ///
    /// Used for the first attempt and every retry alike, and the retry is
    /// byte-for-byte the probe that preceded it: the payload is what makes an
    /// open port answer at all, and the source port is the scan's identity on
    /// the wire, so neither may vary between attempts.
    fn probe(&mut self, ip: IpAddr, port: u16, position: u64, now: Instant) {
        self.send(ip, port, Some(position), now);
    }

    fn reprobe(&mut self, ip: IpAddr, port: u16, now: Instant) {
        self.send(ip, port, None, now);
    }

    /// Classifies one captured reply and, if it answers an outstanding probe,
    /// resolves that probe.
    fn handle_reply(&mut self, reply: &CapturedSegment, now: Instant) {
        let classified = match reply.protocol {
            IpNextHeaderProtocols::Udp => {
                answering_probe(&reply.bytes, self.core.src_port).map(|(port, datagram)| {
                    // What the reply proves about the *host*, which is a
                    // separate claim from the port verdict below and survives
                    // the probe being resolved twice: a duplicate answer is
                    // still a name server answering.
                    if let Some(role) = payload::declared_role(port, datagram) {
                        self.core.ctx.update_host(reply.source, |host| {
                            host.add_network_role(role);
                        });
                    }
                    ((reply.source, port), Verdict::Port(PortState::Open))
                })
            }
            _ => icmp_error::parse(reply).and_then(|error| {
                let target = quoted_probe(&error, self.core.src_port)?;
                Some((target, verdict_of(error.reason)))
            }),
        };

        match classified {
            Some((target, Verdict::Port(state))) => {
                self.resolve_probe(
                    target,
                    state,
                    reply.source,
                    // The header this reply arrived under, read here because
                    // there is no second chance to read it: whether the datagram
                    // came from the target or from something refusing on its
                    // behalf, the hop counter is the cheapest evidence of which.
                    reply.observation.map(IpObservation::remaining_hops),
                    now,
                )
            }
            // Named a host but resolved no probe. Counted as seen rather than
            // off-target: it came from an address this scan asked about.
            // The probe is deliberately left outstanding. This message reports
            // that the address could not be reached at all, so it carries no
            // verdict on the port it happened to quote, and the probe should
            // retire on its own schedule like any other unanswered one.
            Some((target, Verdict::Host)) => self.core.record_host_down(target.0, reply.source),
            None => {}
        }
    }

    /// Retires one outstanding probe with the state its reply established,
    /// crediting the round trip to the deadline.
    ///
    /// Files a port verdict and whatever the reply that produced it proves about
    /// the host.
    ///
    /// `sender` is the address the reply actually came from, or `None` when the
    /// verdict came from a spent attempt budget rather than from a packet.
    /// Everything here turns on comparing it against `ip`, because an ICMP error
    /// names two addresses - the hop that generated it, and the destination of
    /// the datagram it quotes - and they are different claims:
    ///
    /// - **The target answered.** Any reply the host sent proves it is up, and
    ///   that includes ones negative about the port: a port unreachable is
    ///   emitted by the host's own IP stack, and an administrative rejection
    ///   from the host itself is a host that exists and is policing its traffic.
    /// - **A middlebox rejected the probe by policy.** Something is enforcing a
    ///   perimeter around this address, which is [`HostStatus::Filtered`] - the
    ///   variant's documented meaning, and materially different from an address
    ///   nothing answers for.
    /// - **A middlebox reported the port closed.** The port verdict stands,
    ///   since the message reports on the port, but no host status is recorded:
    ///   the address that answered is not the address that was asked, and a NAT
    ///   answering on another host's behalf must not be read as that host being
    ///   up.
    /// - **Nothing answered.** `OpenFiltered` from exhaustion records nothing.
    ///   Silence is not evidence about a host.
    fn record_port(&mut self, ip: IpAddr, port_num: u16, state: PortState, sender: Option<IpAddr>) {
        // Nothing answered, so there is no header to read and no round trip to
        // credit. The fuller form below is for the paths that had a reply.
        self.record_port_answered_by(ip, port_num, state, sender, None, None);
    }
}

impl UdpPortScanner {
    /// [`record_port`](RawPortScan::record_port), also carrying what the reply
    /// that produced the verdict was measured to be.
    ///
    /// Kept off the shared trait for the reason the TCP scanner keeps its own:
    /// the trait is the machinery both protocols share, and what a reply carried
    /// is read from a header only one of them was holding.
    fn record_port_answered_by(
        &mut self,
        ip: IpAddr,
        port_num: u16,
        state: PortState,
        sender: Option<IpAddr>,
        ttl: Option<u8>,
        rtt: Option<Duration>,
    ) {
        let port = crate::fingerprint::baseline_port(port_num, Protocol::Udp, state);

        // The packet that settled it, written down beside the host evidence
        // drawn from the same two facts. Without it a UDP port carried a verdict
        // and no account of it, which for this protocol is the worst case of
        // all: almost every silence here is `open|filtered`, and a reader has no
        // way to tell a refusal that arrived from one that never came.
        let port = match port_evidence(state, sender, ip) {
            Some(reason) => {
                let mut discovery = PortDiscovery::new(reason);
                if let Some(rtt) = rtt {
                    discovery = discovery.with_rtt(rtt);
                }
                if let Some(ttl) = ttl {
                    discovery = discovery.with_ttl(ttl);
                }
                port.with_discovery(discovery)
            }
            None => port,
        };
        let evidence = match (state, sender) {
            (PortState::Open, _) => Some((
                HostStatus::Up,
                StatusReason::new(StatusProtocol::Udp, "udp reply from a probed port"),
            )),
            (PortState::Closed, Some(sender)) if sender == ip => Some((
                HostStatus::Up,
                StatusReason::new(
                    StatusProtocol::IcmpUnreachable,
                    "port unreachable from the host",
                ),
            )),
            (PortState::Filtered, Some(sender)) if sender == ip => Some((
                HostStatus::Up,
                StatusReason::new(
                    StatusProtocol::IcmpUnreachable,
                    "administratively prohibited by the host",
                ),
            )),
            (PortState::Filtered, Some(sender)) => Some((
                HostStatus::Filtered,
                StatusReason::new(
                    StatusProtocol::IcmpUnreachable,
                    "administratively prohibited in path",
                )
                .from_source(sender),
            )),
            _ => None,
        };

        self.core.ctx.update_host(ip, |host| {
            host.add_port(port);
            if let Some((status, reason)) = evidence {
                host.record_evidence(status, reason);
            }
        });
    }
}

/// Which packet settled a UDP port, in the vocabulary a report records.
///
/// The port-level mirror of the host evidence recorded beside it, drawn from the
/// same two facts. A closed UDP port is only ever known by the unreachable that
/// says so — nothing else refuses a datagram — so the two verdicts a reply can
/// produce here are both ICMP, and which one turns on who sent it.
///
/// `None` where nothing arrived. `OpenFiltered` from exhaustion is the ordinary
/// outcome of a UDP scan and has no packet to name: recording `no reply` for it
/// would dress the protocol's normal silence as a finding.
fn port_evidence(state: PortState, sender: Option<IpAddr>, target: IpAddr) -> Option<ScanResponse> {
    match (state, sender) {
        (PortState::Open, _) => Some(ScanResponse::UdpResponse),
        // A port unreachable is the refusal that means nothing is listening.
        (PortState::Closed, _) => Some(ScanResponse::IcmpUnreachable),
        // A prohibition from the host is its own policy; from anywhere else it
        // is somebody in the path refusing on its behalf.
        (PortState::Filtered, Some(from)) => Some(match from == target {
            true => ScanResponse::IcmpProhibited,
            false => ScanResponse::IcmpUnreachable,
        }),
        _ => None,
    }
}

#[async_trait]
impl PortScanner for UdpPortScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::UdpPort
    }

    fn supported_protocols(&self) -> Vec<Protocol> {
        vec![Protocol::Udp]
    }

    /// Consumes `targets`, sending a UDP probe for each UDP target and classifying
    /// every reply (or ICMP error), until each probe has been resolved or the
    /// scan's deadline expires. Anything still outstanding when the loop ends is
    /// reported as OpenFiltered.
    ///
    /// New targets are admitted only while fewer than `MAX_IN_FLIGHT` probes
    /// are outstanding, and released no faster than
    /// `UDP_PORT_RATE_PER_SEC`. Both are fixed,
    /// unlike the TCP scanner's window, because a UDP scan is given no evidence
    /// it could adapt on: silence is its ordinary outcome and its replies name
    /// no attempt.
    async fn scan(&mut self, targets: mpsc::Receiver<PlannedTarget>) -> Result<(), StrategyError> {
        probe_scan::run(self, targets).await;
        Ok(())
    }

    // No `detect_services` override. The second pass in
    // [`service`](crate::scanner::service) opens a TCP connection to each open
    // port, so it identifies nothing this scanner found - and running it here
    // as well as from the SYN scanner beside us would fingerprint every open
    // *TCP* port twice, once per composite member. Identifying a UDP service
    // needs a UDP conversation, which is tracked separately (see
    // `docs/fingerprinting.md`, "UDP fingerprinting"); until that exists the
    // trait's no-op default is the honest implementation.
}

impl UdpPortScanner {
    /// One send, first attempt or retry. `position` is `Some` only for a probe
    /// that has never gone out, since the ledger keeps it thereafter.
    fn send(&mut self, ip: IpAddr, port: u16, position: Option<u64>, now: Instant) {
        let Some(src_addr) = self.core.resolver.resolve(ip) else {
            error!(
                verbosity = 2,
                "no route to {ip}; skipping UDP probe to {ip}:{port}"
            );
            return;
        };

        // Whether this send takes a slot in the congestion window. A retry does
        // not: the slot went back when the question it repeats ran out of
        // round-trip budget. The ledger is what knows, since it is what holds
        // the probe between attempts.
        let first_attempt = !self.core.ledger.contains(&(ip, port));

        let sent = send_udp(
            self.core.transport.tx.as_ref(),
            self.core.src_port,
            src_addr,
            ip,
            port,
            self.core.emission,
            self.core.shaping,
            &mut self.core.send_failure,
        );
        self.core.record_send(sent.is_some(), first_attempt);

        if sent.is_some() {
            match position {
                Some(position) => self.core.ledger.arm(ip, (ip, port), (), position, now),
                None => self.core.ledger.rearm(ip, (ip, port), (), now),
            }
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
    use super::*;
    use crate::model::host::NetworkRole;
    use crate::model::target::Target;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pnet_packet::icmp::destination_unreachable::{
        DestinationUnreachablePacket, IcmpCodes, MutableDestinationUnreachablePacket,
    };
    use pnet_packet::icmp::{IcmpCode, IcmpTypes};
    use pnet_packet::icmpv6::{Icmpv6Code, Icmpv6Packet, Icmpv6Types, MutableIcmpv6Packet};

    use crate::scanner::strategy::routed::icmp_error::{
        ICMPV6_ADMIN_PROHIBITED, ICMPV6_INGRESS_EGRESS_POLICY, ICMPV6_NO_ROUTE,
        ICMPV6_PORT_UNREACHABLE, ICMPV6_REJECT_ROUTE, ICMPV6_UNUSED_LEN,
    };

    use crate::protocols::{ip, udp};
    use crate::scanner::session::ScanSession;
    use crate::transport::probe::{MockSender, ProbeTransport};

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
    const TARGET_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 200));
    /// A router between us and the target, which reports errors under its own
    /// address rather than the target's.
    const ROUTER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    /// This host's addresses, as the scanner's source resolver reports them.
    const LOCAL_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
    const LOCAL_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 50));
    /// The fixed source port the scanner under test probes from.
    const SCAN_SRC_PORT: u16 = 54_321;

    fn on_link_interface() -> crate::system::interface::Link {
        use crate::system::interface::{Link, LinkAddress};
        Link::new("test0", 0).with_addresses(vec![
            LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 24),
            LinkAddress::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 50)),
                64,
            ),
        ])
    }

    /// [`scanner_with_mock`] plus the probe log, for the tests that assert on
    /// what actually reached the wire rather than only on what was recorded.
    fn scanner_with_recorder() -> (UdpPortScanner, ScanSession, SentProbes) {
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport = ProbeTransport::from_parts(Box::new(sender), reply_rx);
        let resolver = SourceResolver::from_links(&[on_link_interface()]);

        let scanner = UdpPortScanner::with_transport(resolver, ctx, transport, 8, SCAN_SRC_PORT);
        (scanner, session, sent)
    }

    /// The probes a [`MockSender`] recorded, shared with the scanner under test.
    type SentProbes = std::sync::Arc<std::sync::Mutex<Vec<crate::transport::probe::SentProbe>>>;

    fn scanner_with_mock() -> (UdpPortScanner, ScanSession) {
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let transport = ProbeTransport::from_parts(Box::new(MockSender::default()), reply_rx);
        let resolver = SourceResolver::from_links(&[on_link_interface()]);

        let scanner = UdpPortScanner::with_transport(resolver, ctx, transport, 8, SCAN_SRC_PORT);
        (scanner, session)
    }

    fn probe(scanner: &mut UdpPortScanner, ip: IpAddr, port: u16) {
        scanner.send_probe(PlannedTarget::new(
            u64::from(port),
            Target {
                ip,
                port,
                protocol: Protocol::Udp,
            },
        ));
    }

    fn host_status(session: &ScanSession, ip: IpAddr) -> Option<HostStatus> {
        session.hosts().get(ip).map(|host| host.status())
    }

    fn port_state(session: &ScanSession, ip: IpAddr, port: u16) -> Option<PortState> {
        session
            .hosts()
            .get(ip)
            .and_then(|h| h.ports().find(|p| p.number() == port).map(|p| p.state()))
    }

    /// A UDP port that answered records what answered it, and the hop counter
    /// the reply arrived under.
    ///
    /// This protocol needs the account more than TCP does: almost every silence
    /// here is `open|filtered`, so a reader with only the verdict cannot tell a
    /// refusal that arrived from one that never came.
    #[test]
    fn an_answered_udp_port_records_the_datagram_that_settled_it() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        let mut reply = udp_reply(53, SCAN_SRC_PORT);
        reply.observation = Some(IpObservation::V4(crate::model::capture::Ipv4Observation {
            ttl: 58,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            dscp: 0,
            ecn: 0,
        }));
        scanner.handle_reply(&reply, Instant::now());

        let discovery = session
            .hosts()
            .get(TARGET)
            .and_then(|host| {
                host.ports()
                    .find(|port| port.number() == 53)
                    .and_then(|port| port.discovery().cloned())
            })
            .expect("the port carries its evidence");

        assert_eq!(discovery.reason(), &ScanResponse::UdpResponse);
        assert_eq!(discovery.ttl(), Some(58));
    }

    /// The protocol's ordinary outcome is silence, and silence gets no packet.
    ///
    /// `OpenFiltered` from exhaustion is what most of a UDP scan comes back as.
    /// Recording `no reply` against every one of them would dress the normal
    /// case as a finding.
    #[test]
    fn an_unanswered_udp_port_records_no_evidence() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.record_port(TARGET, 53, PortState::OpenFiltered, None);

        assert_eq!(
            port_state(&session, TARGET, 53),
            Some(PortState::OpenFiltered)
        );
        assert!(
            session
                .hosts()
                .get(TARGET)
                .and_then(|host| host
                    .ports()
                    .find(|port| port.number() == 53)
                    .and_then(|port| port.discovery().cloned()))
                .is_none(),
            "a silence was dressed up as a packet"
        );
    }

    /// A reply as the capture layer would deliver it: bytes plus the protocol
    /// the IP header said they are.
    fn captured(
        source: IpAddr,
        protocol: pnet_packet::ip::IpNextHeaderProtocol,
        bytes: Vec<u8>,
    ) -> CapturedSegment {
        CapturedSegment::synthetic(source, protocol, bytes)
    }

    /// A direct UDP reply from `src_port`, addressed back to `dst_port`.
    fn udp_reply(src_port: u16, dst_port: u16) -> CapturedSegment {
        udp_reply_saying(src_port, dst_port, vec![])
    }

    /// A reply carrying something, for the ports whose answers say more than
    /// "somebody is listening".
    fn udp_reply_saying(src_port: u16, dst_port: u16, said: Vec<u8>) -> CapturedSegment {
        captured(
            TARGET,
            IpNextHeaderProtocols::Udp,
            udp::create_packet(&TARGET, &LOCAL_V4, src_port, dst_port, said).unwrap(),
        )
    }

    /// The quoted datagram an ICMP error carries: the IP header of the probe
    /// plus its UDP header. Built with the very functions that build a real
    /// probe, so the test agrees with the wire by construction rather than by
    /// a hand-written byte array.
    fn quoted_probe_packet(from: IpAddr, to: IpAddr, src_port: u16, dst_port: u16) -> Vec<u8> {
        let datagram = udp::create_packet(&from, &to, src_port, dst_port, vec![]).unwrap();
        let len = datagram.len() as u16;
        let header = match (from, to) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                ip::create_ipv4_header(s, d, len, IpNextHeaderProtocols::Udp, ip::HOP_LIMIT_ROUTED)
                    .unwrap()
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                ip::create_ipv6_header(s, d, len, IpNextHeaderProtocols::Udp, ip::HOP_LIMIT_ROUTED)
            }
            _ => panic!("IP version mismatch in test fixture"),
        };
        header.into_iter().chain(datagram).collect()
    }

    /// An ICMPv4 error of `code` from `from`, quoting a probe sent to
    /// `to:dst_port` from `src_port`.
    fn icmpv4_error(
        from: IpAddr,
        code: IcmpCode,
        to: IpAddr,
        src_port: u16,
        dst_port: u16,
    ) -> CapturedSegment {
        let quoted = quoted_probe_packet(LOCAL_V4, to, src_port, dst_port);
        let mut buf = vec![0u8; DestinationUnreachablePacket::minimum_packet_size() + quoted.len()];
        let mut packet = MutableDestinationUnreachablePacket::new(&mut buf).unwrap();
        packet.set_icmp_type(IcmpTypes::DestinationUnreachable);
        packet.set_icmp_code(code);
        packet.set_payload(&quoted);
        captured(from, IpNextHeaderProtocols::Icmp, buf)
    }

    /// An ICMPv6 error of `code`, quoting a probe sent to `to:dst_port`.
    fn icmpv6_error(code: Icmpv6Code, to: IpAddr, src_port: u16, dst_port: u16) -> CapturedSegment {
        let quoted = quoted_probe_packet(LOCAL_V6, to, src_port, dst_port);
        let mut buf =
            vec![0u8; Icmpv6Packet::minimum_packet_size() + ICMPV6_UNUSED_LEN + quoted.len()];
        let mut packet = MutableIcmpv6Packet::new(&mut buf).unwrap();
        packet.set_icmpv6_type(Icmpv6Types::DestinationUnreachable);
        packet.set_icmpv6_code(code);
        // Four unused bytes precede the quotation (RFC 4443 §3.1).
        let mut payload = vec![0u8; ICMPV6_UNUSED_LEN];
        payload.extend_from_slice(&quoted);
        packet.set_payload(&payload);
        captured(to, IpNextHeaderProtocols::Icmpv6, buf)
    }

    /// A port verdict and a claim about the host are two findings, and the
    /// second is read out of the datagram the first was inferred from. The
    /// payload has to be sliced off at exactly the UDP header: one byte either
    /// way and the message no longer parses, which reads as an ordinary open
    /// port and silently loses the role on every name server a scan finds.
    #[test]
    fn a_dns_answer_names_the_host_a_name_server() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        // The engine's own question with the QR bit set, which is what a name
        // server sends back.
        let mut answer = crate::scanner::payload::for_port(53).to_vec();
        answer[2] |= 0b1000_0000;

        scanner.handle_reply(&udp_reply_saying(53, SCAN_SRC_PORT, answer), Instant::now());

        assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Open));
        let host = session.hosts().get(TARGET).expect("the host answered");
        assert!(
            host.network_roles().contains(&NetworkRole::DnsServer),
            "the reply parsed as DNS, which a bound socket cannot fake"
        );
    }

    /// The same port answering with something that is not DNS is an open port
    /// and nothing more — a socket bound to 53 is not a name server.
    #[test]
    fn an_open_port_53_that_does_not_speak_dns_is_only_an_open_port() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(
            &udp_reply_saying(53, SCAN_SRC_PORT, b"hello".to_vec()),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Open));
        let host = session.hosts().get(TARGET).expect("the host answered");
        assert!(host.network_roles().is_empty());
    }

    #[test]
    fn direct_udp_reply_is_open() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(&udp_reply(53, SCAN_SRC_PORT), Instant::now());

        assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Open));
        assert!(scanner.core.ledger.is_empty());
    }

    /// A datagram from a pending port that is *not* addressed to this scan's
    /// source port answers some other conversation on the host, not our probe.
    #[test]
    fn udp_traffic_not_addressed_to_the_scan_is_ignored() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(
            &udp_reply(53, SCAN_SRC_PORT.wrapping_add(1)),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET, 53), None);
        assert_eq!(scanner.core.ledger.len(), 1);
    }

    #[test]
    fn icmp_port_unreachable_is_closed() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(
            &icmpv4_error(
                TARGET,
                IcmpCodes::DestinationPortUnreachable,
                TARGET,
                SCAN_SRC_PORT,
                53,
            ),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Closed));
        assert!(scanner.core.ledger.is_empty());
    }

    /// The regression guard for the classification bug this scanner shipped
    /// with: an unreachable message names one port in its quoted datagram, and
    /// must retire that probe alone. Every other probe to the same host is
    /// still outstanding and must stay that way.
    #[test]
    fn icmp_unreachable_closes_only_the_port_it_quotes() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);
        probe(&mut scanner, TARGET, 161);
        probe(&mut scanner, TARGET, 123);

        scanner.handle_reply(
            &icmpv4_error(
                TARGET,
                IcmpCodes::DestinationPortUnreachable,
                TARGET,
                SCAN_SRC_PORT,
                161,
            ),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET, 161), Some(PortState::Closed));
        assert_eq!(port_state(&session, TARGET, 53), None);
        assert_eq!(port_state(&session, TARGET, 123), None);
        assert_eq!(scanner.core.ledger.len(), 2);
    }

    /// An error relayed by a router carries the router's address, but quotes a
    /// probe aimed at the host behind it. The quoted destination is what
    /// identifies the probe.
    #[test]
    fn unreachable_from_a_router_resolves_the_quoted_target() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(
            &icmpv4_error(
                ROUTER,
                IcmpCodes::DestinationPortUnreachable,
                TARGET,
                SCAN_SRC_PORT,
                53,
            ),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Closed));
        assert_eq!(port_state(&session, ROUTER, 53), None);
    }

    /// Host unreachable reports on the address, not on the port that happened to
    /// be quoted. Recording it as a port verdict - which is what this scanner
    /// did before liveness had anywhere to go - invents a fact about a port
    /// nothing ever answered for.
    #[test]
    fn host_unreachable_is_a_host_verdict_and_not_a_port_one() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(
            &icmpv4_error(
                ROUTER,
                IcmpCodes::DestinationHostUnreachable,
                TARGET,
                SCAN_SRC_PORT,
                53,
            ),
            Instant::now(),
        );

        assert_eq!(host_status(&session, TARGET), Some(HostStatus::Down));
        assert_eq!(
            port_state(&session, TARGET, 53),
            None,
            "the port has no verdict yet and the probe must be left to retire on its own"
        );
        assert_eq!(
            scanner.core.ledger.len(),
            1,
            "an unreachable address says nothing about the probe's fate"
        );
    }

    /// The distinction the whole host-status design turns on: an ICMP error
    /// names the hop that sent it as well as the address it is about, and only
    /// the first tells you whether the target is alive.
    #[test]
    fn a_port_unreachable_proves_the_host_only_when_the_host_sent_it() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);
        scanner.handle_reply(
            &icmpv4_error(
                TARGET,
                IcmpCodes::DestinationPortUnreachable,
                TARGET,
                SCAN_SRC_PORT,
                53,
            ),
            Instant::now(),
        );
        assert_eq!(host_status(&session, TARGET), Some(HostStatus::Up));

        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);
        scanner.handle_reply(
            &icmpv4_error(
                ROUTER,
                IcmpCodes::DestinationPortUnreachable,
                TARGET,
                SCAN_SRC_PORT,
                53,
            ),
            Instant::now(),
        );
        assert_eq!(
            host_status(&session, TARGET),
            Some(HostStatus::Unknown),
            "a middlebox answering for an address does not make that address alive"
        );
        assert_eq!(
            port_state(&session, TARGET, 53),
            Some(PortState::Closed),
            "the port verdict still stands: the message does report on the port"
        );
    }

    /// A policy rejection from a middlebox proves a perimeter, not a host - but
    /// a perimeter is still more than nothing, which is what separates
    /// `Filtered` from `Unknown`.
    #[test]
    fn an_in_path_policy_rejection_is_filtered_rather_than_up() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(
            &icmpv4_error(
                ROUTER,
                IcmpCodes::CommunicationAdministrativelyProhibited,
                TARGET,
                SCAN_SRC_PORT,
                53,
            ),
            Instant::now(),
        );

        assert_eq!(host_status(&session, TARGET), Some(HostStatus::Filtered));
    }

    /// Silence is the one thing that must never move a host's status, however
    /// many probes it swallows. `OpenFiltered` is a port verdict reached by
    /// exhaustion, and a host that has sent nothing has proved nothing.
    #[test]
    fn exhausting_every_attempt_leaves_the_host_unknown() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        let mut now = Instant::now();
        for _ in 0..8 {
            now += Duration::from_secs(10);
            scanner.service_retries(now);
        }

        assert_eq!(
            port_state(&session, TARGET, 53),
            Some(PortState::OpenFiltered)
        );
        assert_eq!(host_status(&session, TARGET), Some(HostStatus::Unknown));
        assert!(
            session
                .hosts()
                .get(TARGET)
                .expect("the port verdict created the host")
                .reasons()
                .is_empty(),
            "silence is not evidence and must leave no audit trail"
        );
    }

    /// An unreachable quoting a datagram this scan never sent - a different
    /// source port - belongs to someone else's traffic.
    #[test]
    fn unreachable_quoting_a_foreign_probe_is_ignored() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(
            &icmpv4_error(
                TARGET,
                IcmpCodes::DestinationPortUnreachable,
                TARGET,
                SCAN_SRC_PORT.wrapping_add(1),
                53,
            ),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET, 53), None);
        assert_eq!(scanner.core.ledger.len(), 1);
    }

    /// Only code 3 says a port answered. The codes that describe a blocked
    /// path prove the probe did not arrive, which is `Filtered` - a strictly
    /// better answer than letting the probe time out into `OpenFiltered`.
    #[test]
    fn administratively_prohibited_icmp_is_filtered() {
        for code in [
            IcmpCodes::DestinationProtocolUnreachable,
            IcmpCodes::NetworkAdministrativelyProhibited,
            IcmpCodes::HostAdministrativelyProhibited,
            IcmpCodes::CommunicationAdministrativelyProhibited,
        ] {
            let (mut scanner, session) = scanner_with_mock();
            probe(&mut scanner, TARGET, 53);

            scanner.handle_reply(
                &icmpv4_error(TARGET, code, TARGET, SCAN_SRC_PORT, 53),
                Instant::now(),
            );

            assert_eq!(
                port_state(&session, TARGET, 53),
                Some(PortState::Filtered),
                "ICMP code {code:?} should read as filtered"
            );
        }
    }

    /// A code that reports on neither the port nor the path leaves the probe
    /// outstanding, to time out into `OpenFiltered` like any other silence.
    #[test]
    fn uninformative_icmp_codes_leave_the_probe_outstanding() {
        for code in [
            IcmpCodes::DestinationNetworkUnknown,
            IcmpCodes::FragmentationRequiredAndDFFlagSet,
            IcmpCodes::SourceRouteFailed,
        ] {
            let (mut scanner, session) = scanner_with_mock();
            probe(&mut scanner, TARGET, 53);

            scanner.handle_reply(
                &icmpv4_error(TARGET, code, TARGET, SCAN_SRC_PORT, 53),
                Instant::now(),
            );

            assert_eq!(port_state(&session, TARGET, 53), None, "code {code:?}");
            assert_eq!(scanner.core.ledger.len(), 1, "code {code:?}");
        }
    }

    #[test]
    fn icmpv6_policy_refusals_are_filtered() {
        for code in [
            ICMPV6_ADMIN_PROHIBITED,
            ICMPV6_INGRESS_EGRESS_POLICY,
            ICMPV6_REJECT_ROUTE,
        ] {
            let (mut scanner, session) = scanner_with_mock();
            probe(&mut scanner, TARGET_V6, 53);

            scanner.handle_reply(
                &icmpv6_error(code, TARGET_V6, SCAN_SRC_PORT, 53),
                Instant::now(),
            );

            assert_eq!(
                port_state(&session, TARGET_V6, 53),
                Some(PortState::Filtered),
                "ICMPv6 code {code:?} should read as filtered"
            );
        }
    }

    /// An ICMP error's first two bytes (type 3, code 3) read as the source port
    /// 771 if the segment is parsed as UDP. Carrying the protocol from the IP
    /// header is what stops that from becoming a false `Open`.
    #[test]
    fn icmp_error_is_never_read_as_a_udp_reply() {
        let (mut scanner, session) = scanner_with_mock();
        // 0x0303: what an ICMPv4 unreachable's type/code look like as a port.
        probe(&mut scanner, TARGET, 771);
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(
            &icmpv4_error(
                TARGET,
                IcmpCodes::DestinationPortUnreachable,
                TARGET,
                SCAN_SRC_PORT,
                53,
            ),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET, 771), None);
        assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Closed));
    }

    #[test]
    fn icmpv6_port_unreachable_is_closed() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET_V6, 53);

        scanner.handle_reply(
            &icmpv6_error(ICMPV6_PORT_UNREACHABLE, TARGET_V6, SCAN_SRC_PORT, 53),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET_V6, 53), Some(PortState::Closed));
        assert!(scanner.core.ledger.is_empty());
    }

    /// ICMPv6 code 0 is "no route to destination" - a statement about the path.
    #[test]
    fn icmpv6_no_route_is_ignored() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET_V6, 53);

        scanner.handle_reply(
            &icmpv6_error(ICMPV6_NO_ROUTE, TARGET_V6, SCAN_SRC_PORT, 53),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET_V6, 53), None);
        assert_eq!(scanner.core.ledger.len(), 1);
    }

    /// A truncated or malformed reply must be dropped, never panic: every byte
    /// of it was chosen by a remote host.
    #[test]
    fn malformed_replies_are_dropped() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        for len in 0..48usize {
            let bytes = vec![0xFFu8; len];
            for protocol in [
                IpNextHeaderProtocols::Udp,
                IpNextHeaderProtocols::Icmp,
                IpNextHeaderProtocols::Icmpv6,
            ] {
                scanner.handle_reply(&captured(TARGET, protocol, bytes.clone()), Instant::now());
            }
        }

        assert_eq!(port_state(&session, TARGET, 53), None);
        assert_eq!(scanner.core.ledger.len(), 1);
    }

    /// Checks the quoted-datagram parse against an ICMP error this machine's
    /// own kernel produced, rather than one this test module built. Every
    /// other test here agrees with the wire only as far as our own encoder
    /// does; this one closes that loop.
    ///
    /// It drives the real receive path - a `libpcap` capture with the same
    /// filter a scan uses - but sends its probe from an ordinary `UdpSocket`,
    /// so it needs capture access (root, or `access_bpf` membership on macOS)
    /// but not raw sockets. Ignored by default because that access is not
    /// something a test run can assume; run it with
    /// `cargo test -- --ignored real_kernel_icmp_error`.
    #[tokio::test]
    #[ignore = "needs libpcap capture access (root or access_bpf)"]
    async fn real_kernel_icmp_error_identifies_the_probe_that_caused_it() {
        use crate::transport::capture;
        use std::time::Duration;

        let loopback = crate::system::interface::interfaces()
            .into_iter()
            .find(|link| link.is_loopback() && link.is_up())
            .expect("a loopback interface to capture on");

        // Stands in for the scan's fixed source port: replies and errors are
        // matched against whatever port the probes went out from.
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let src_port = socket.local_addr().unwrap().port();

        // A port nothing listens on, so the kernel answers with an error:
        // bind one to learn a free number, then release it.
        let reserved = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let closed_port = reserved.local_addr().unwrap().port();
        drop(reserved);

        let filter = format!("icmp or icmp6 or (udp and dst port {src_port})");
        let link = loopback.zone();
        let (mut rx, _capture) =
            capture::segments(&[link], &capture::CaptureOptions::for_replies(filter)).unwrap();
        // The capture threads open their devices asynchronously; a probe sent
        // before they are listening would simply not be seen.
        tokio::time::sleep(Duration::from_millis(500)).await;

        socket
            .send_to(b"", ("127.0.0.1", closed_port))
            .await
            .unwrap();

        let reply = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("kernel produced no ICMP error within 3s")
            .expect("capture stream closed");

        assert_eq!(reply.protocol, IpNextHeaderProtocols::Icmp);
        let error = icmp_error::parse(&reply).expect("a real ICMP error parses");
        assert_eq!(
            (quoted_probe(&error, src_port), verdict_of(error.reason)),
            (
                Some((IpAddr::V4(Ipv4Addr::LOCALHOST), closed_port)),
                Verdict::Port(PortState::Closed)
            ),
            "a real ICMP error must name the exact probe that caused it",
        );
    }

    /// The companion to the ICMP check above, for the other half of the
    /// classification: a real reply from a real listener, arriving through the
    /// real capture filter.
    ///
    /// A filter that compiles but never matches would turn every open port
    /// into `OpenFiltered` - the scan would keep running and keep reporting,
    /// just never positively. Only live traffic can catch that.
    #[tokio::test]
    #[ignore = "needs libpcap capture access (root or access_bpf)"]
    async fn real_udp_reply_reaches_the_scan_through_the_capture_filter() {
        use crate::transport::capture;
        use std::time::Duration;

        let loopback = crate::system::interface::interfaces()
            .into_iter()
            .find(|link| link.is_loopback() && link.is_up())
            .expect("a loopback interface to capture on");

        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let src_port = socket.local_addr().unwrap().port();

        // A listener that answers once, so there is a genuine reply to catch.
        let service = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let service_port = service.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            if let Ok((_, from)) = service.recv_from(&mut buf).await {
                let _ = service.send_to(b"pong", from).await;
            }
        });

        let filter = format!("icmp or icmp6 or (udp and dst port {src_port})");
        let link = loopback.zone();
        let (mut rx, _capture) =
            capture::segments(&[link], &capture::CaptureOptions::for_replies(filter)).unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;

        socket
            .send_to(b"ping", ("127.0.0.1", service_port))
            .await
            .unwrap();

        // The filter also admits ICMP, which loopback may carry for unrelated
        // reasons; take the first UDP segment rather than assuming it is first.
        let reply = tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(segment) = rx.recv().await {
                if segment.protocol == IpNextHeaderProtocols::Udp {
                    return segment;
                }
            }
            panic!("capture stream closed before a UDP reply arrived");
        })
        .await
        .expect("no UDP reply captured within 3s");

        assert_eq!(
            answering_probe(&reply.bytes, src_port),
            Some((service_port, b"ping".as_slice())),
            "a real reply must resolve to the port that sent it, and to what it said",
        );
    }

    /// An unanswered probe is sent again rather than written off, since silence
    /// on a first UDP probe is the least informative signal in the protocol.
    #[test]
    fn an_unanswered_probe_is_sent_again() {
        let (mut scanner, session, sent) = scanner_with_recorder();
        probe(&mut scanner, TARGET, 53);

        scanner.service_retries(Instant::now() + Duration::from_secs(2));

        assert_eq!(sent.lock().unwrap().len(), 2, "the probe was not retried");
        assert_eq!(port_state(&session, TARGET, 53), None, "no verdict yet");
    }

    /// A probe that has spent its budget is written off while the scan is still
    /// running, so results reach the caller as they are decided rather than all
    /// at once at the end.
    #[test]
    fn a_probe_that_spends_its_budget_is_written_off_during_the_scan() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        // Each retry reschedules from the moment it is sent, so the schedule
        // has to be walked rather than jumped over.
        let mut now = Instant::now();
        for _ in 0..RETRY_POLICY.max_attempts + 1 {
            now += RETRY_POLICY.worst_case_probe_lifetime();
            scanner.service_retries(now);
        }

        assert_eq!(
            port_state(&session, TARGET, 53),
            Some(PortState::OpenFiltered)
        );
        assert!(scanner.core.ledger.is_empty());
    }

    /// Running out of attempts is not activity: nothing answered, so the
    /// adaptive deadline must not be told the scan is making progress.
    #[test]
    fn running_out_of_attempts_does_not_extend_the_deadline() {
        let (mut scanner, _session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        // A deadline whose silence clock has been reset reports a full tick;
        // capture the value before and after to see whether it moved.
        let before = scanner.core.deadline.time_until_next_tick();
        let mut now = Instant::now();
        for _ in 0..RETRY_POLICY.max_attempts + 1 {
            now += RETRY_POLICY.worst_case_probe_lifetime();
            scanner.service_retries(now);
        }
        let after = scanner.core.deadline.time_until_next_tick();

        assert!(
            after <= before,
            "silence clock was reset by an expiry ({before:?} -> {after:?})"
        );
    }

    /// While probes are outstanding the loop must not sleep past the point
    /// where the next one falls due - nothing else will wake it, because
    /// silence is exactly the case being timed.
    #[test]
    fn pending_probes_shorten_the_sleep() {
        let (mut scanner, _session) = scanner_with_mock();
        let now = Instant::now();
        assert!(scanner.core.ledger.is_empty());
        let idle = scanner.core.tick_delay(now);

        probe(&mut scanner, TARGET, 53);
        let busy = scanner.core.tick_delay(now);

        assert!(busy < idle, "sleep not shortened while probes are out");
        assert!(
            busy <= RETRY_POLICY.worst_case_probe_lifetime(),
            "the loop would sleep past the probe's whole schedule"
        );
    }

    /// The UDP profile has to tolerate silence for longer than a host's ICMP
    /// rate-limit interval (~1/sec), or a scan concludes while its answers are
    /// still queued. This is the property that makes it a separate profile from
    /// the SYN one, so it is asserted rather than left to a comment.
    #[test]
    fn silence_floor_outlasts_the_icmp_rate_limit() {
        const ICMP_RATE_LIMIT_INTERVAL: Duration = Duration::from_secs(1);

        assert!(
            DEADLINE_CONFIG.silence_floor > ICMP_RATE_LIMIT_INTERVAL,
            "silence floor {:?} is shorter than one rate-limited answer",
            DEADLINE_CONFIG.silence_floor
        );
        assert!(
            super::super::DEADLINE_CONFIG.silence_floor < ICMP_RATE_LIMIT_INTERVAL,
            "the SYN profile was expected to be the tighter one"
        );
    }

    #[test]
    fn unanswered_probes_resolve_as_filtered() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 161);

        scanner.resolve_remaining();

        assert_eq!(
            port_state(&session, TARGET, 161),
            Some(PortState::OpenFiltered)
        );
        assert!(scanner.core.ledger.is_empty());
    }

    #[test]
    fn non_udp_targets_are_not_probed() {
        let (mut scanner, _session) = scanner_with_mock();
        scanner.send_probe(PlannedTarget::new(
            0,
            Target {
                ip: TARGET,
                port: 80,
                protocol: Protocol::Tcp,
            },
        ));
        assert!(scanner.core.ledger.is_empty());
    }

    /// Every probe in a scan must leave from the one port the capture filter
    /// and the quoted-datagram check are built around.
    #[test]
    fn every_probe_is_sent_from_the_scan_source_port() {
        let (_session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport = ProbeTransport::from_parts(Box::new(sender), reply_rx);
        let mut scanner = UdpPortScanner::with_transport(
            SourceResolver::from_links(&[on_link_interface()]),
            ctx,
            transport,
            8,
            SCAN_SRC_PORT,
        );

        for port in [53, 161, 123] {
            probe(&mut scanner, TARGET, port);
        }

        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 3);
        for (segment, _src, _dst) in sent.iter() {
            let udp = UdpPacket::new(segment).expect("probe is a UDP datagram");
            assert_eq!(udp.get_source(), SCAN_SRC_PORT);
        }
    }
}
