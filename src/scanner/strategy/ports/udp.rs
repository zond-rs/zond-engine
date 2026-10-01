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
//! UDP has no handshake. A closed port answers with an ICMP Port Unreachable,
//! an open one answers with a UDP datagram only if it understands what was
//! sent, and a port behind a dropping filter says nothing, as does an open
//! port that ignored the probe. So:
//!
//! - a direct UDP reply is [`PortState::Open`],
//! - an ICMP Port Unreachable is [`PortState::Closed`],
//! - silence until the deadline is [`PortState::OpenOrNoReply`].
//!
//! ## Tying a reply to its probe
//!
//! Every probe in a scan leaves from one fixed source port, chosen when the
//! scanner is built:
//!
//! - A **direct reply** is addressed back to it, so the kernel's BPF filter
//!   admits this scan's replies and drops the host's other UDP traffic
//!   ([`ProbeKind::UdpProbe`]).
//! - An **ICMP error** quotes the IP header plus the first eight bytes of the
//!   datagram that caused it (RFC 792), which is a whole UDP header. Its source
//!   port proves the datagram was ours, and its destination address and port
//!   say which probe, so one error retires exactly one probe, even when a
//!   router sent the error.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet_packet::udp::UdpPacket;
use tokio::sync::mpsc;

use crate::config::{ProbeTuning, ServiceDetection};
use crate::journal::settle::Outcome;
use crate::logging::info;
use crate::model::capture::IpObservation;
use crate::model::host::{HostStatus, StatusProtocol, StatusReason};
use crate::model::port::discovery::{Discovery as PortDiscovery, ScanResponse};
use crate::model::port::{PortState, Protocol};
use crate::model::target::PlannedTarget;
use crate::protocols::sizes::UDP_HDR_LEN;
use crate::report::ScannerKind;
use crate::scanner::pacing::congestion::WindowLimits;
use crate::scanner::pacing::deadline::AdaptiveDeadlineConfig;
use crate::scanner::pacing::retry::{RetryPolicy, SilentHostPolicy};
use crate::scanner::pacing::timer::ScanBudget;
use crate::scanner::payload;
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::{PortScanner, StrategyError};
use crate::system::interface::SourceResolver;
use crate::transport::capture::CapturedSegment;
use crate::transport::probe::{ProbeKind, ProbeTransport};

use super::super::raw::{EvasionParts, send_udp};
use super::{AuditLabels, CoreParts, ProbeTarget, RawPortScan, RawProbeScan};
use crate::scanner::strategy::icmp_error::{self, Unreachable};

/// How long this scan runs and how it adapts.
///
/// Differs from the SYN profile
/// ([`DEADLINE_CONFIG`](super::super::raw::DEADLINE_CONFIG)) because a UDP
/// probe's most informative answer is an ICMP error, and hosts **rate-limit**
/// those: Linux emits roughly one destination-unreachable per second by default
/// (`net.ipv4.icmp_ratelimit`), and BSD does the same. Answers to a multi-port
/// scan arrive spread over seconds however fast the network is.
///
/// Hence `silence_floor` above the rate-limit interval: the SYN profile's 150 ms
/// would stop the scan while answers were still legally on their way and report
/// those ports as `OpenOrNoReply`.
const DEADLINE_CONFIG: AdaptiveDeadlineConfig = AdaptiveDeadlineConfig::new(
    // Hard ceiling.
    ScanBudget::new(
        Duration::from_millis(2_000),
        Duration::from_millis(200),
        Duration::from_secs(45),
    ),
    // Minimum runtime, so the first rate-limited answers have time to arrive.
    ScanBudget::new(
        Duration::from_millis(500),
        Duration::from_millis(50),
        Duration::from_secs(10),
    ),
    // Silence floor: longer than one rate-limit interval.
    Duration::from_millis(1_200),
    Duration::from_secs(5),
    4.0,
    20,
);

/// How a UDP probe is retransmitted.
///
/// Set against the ICMP rate limit (about one error per second), unlike the
/// round-trip-based SYN profile ([`RETRY_POLICY`](super::super::raw::RETRY_POLICY)):
/// a retry sooner than that interval chases an answer the host was never
/// allowed to send.
///
/// Two attempts and a gentle backoff: the scan waits on the host's allowance,
/// not on congestion, so doubling would add tail latency for little gain. A
/// probe lives about 3.75 s against an unmeasured host and about 3 s against a
/// measured one.
const RETRY_POLICY: RetryPolicy = RetryPolicy::new(
    2,
    Duration::from_millis(1_500),
    Duration::from_millis(1_200),
    Duration::from_secs(5),
    1.5,
    0.2,
    Some(SilentHostPolicy::new(32, 1)),
);

/// The most probes outstanding at once, which is also this scan's fixed window.
///
/// Bounds the memory of a large scan, and keeps the send loop from bursting
/// faster than a rate-limited host can answer, which would manufacture
/// `OpenOrNoReply` verdicts.
///
/// Fixed, though the TCP scanner's window adapts: silence is a UDP scan's
/// ordinary outcome and its replies do not name the attempt they answer, so a
/// congestion controller has nothing to read (see
/// [`congestion`](crate::scanner::pacing::congestion)). The scan is paced by
/// `UDP_PORT_RATE_PER_SEC` in the parent module.
///
/// Global, since [`Dispatcher`](crate::scanner::dispatcher::Dispatcher) already
/// shuffles targets across hosts.
const MAX_IN_FLIGHT: u32 = 512;

/// Probes specific `(address, port)` pairs with raw UDP packets.
pub struct UdpPortScanner {
    /// The protocol-independent part of a raw port scan: transport, ledger,
    /// deadline, pacing and stop conditions.
    core: RawProbeScan<()>,
    /// How far the second pass may go to name what answered; see
    /// [`detect_services`](PortScanner::detect_services).
    service_detection: ServiceDetection,
    /// What each host's answers showed of the allowance its ICMP errors are
    /// sent under, read once the scan is over; see [`IcmpTally`].
    icmp: HashMap<IpAddr, IcmpTally>,
}

/// How one host answered the ports it was asked about, kept to tell a host
/// rate-limiting its ICMP errors from one whose ports are mostly silent.
///
/// Hosts ration port unreachables: Linux sends a burst of six to each
/// destination and one a second after it, and the BSDs cap the rate as a
/// whole. Against a ration, the answers depend on how long the scan asks, not
/// how fast. Measured against a Linux peer's 250 closed ports, a 4.3 s scan
/// read 8 closed, an 11.8 s scan 13, and one paced to 20 probes a second over
/// 15.8 s read 19; without its ration the same peer answered all 250 in
/// 0.86 s. Only time buys verdicts, about one second a port, which the deadline
/// does not give, so the scan reports the ration; otherwise every unanswered
/// closed port reads as possibly open.
///
/// The signature is a retry answered. A rationed closed port is silent to the
/// first question and answers the retry the next allowance falls to; a
/// filtered port is silent to every attempt; a closed port on a clean link
/// answers the first. A host reads as rationing when a port answered closed
/// only on a retry, others answered at once, and more ports stayed silent than
/// answered. One late answer is often all a ration leaves: a Linux peer asked
/// forty closed ports answered six at once and one retry before the scan ended.
///
/// The answers at once (the ration's initial burst) keep a lossy link from
/// matching: it answers late too, but leaves few ports silent. A filter in front
/// of a single closed port whose first answer was lost answers late and nothing
/// at once. The reading can still mistake a filter in front of several closed
/// ports, some answered at once and one lost.
#[derive(Debug, Default, Clone, Copy)]
struct IcmpTally {
    /// Ports the host itself answered with a port unreachable.
    closed: u32,
    /// Of those, the ones answered after the probe had been sent again.
    late: u32,
    /// Ports that stayed silent to every attempt.
    silent: u32,
}

impl IcmpTally {
    /// Whether this host's answers show its ICMP errors rationed.
    fn rate_limited(self) -> bool {
        self.late > 0 && self.late < self.closed && self.silent > self.closed
    }
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
        let transport = ProbeTransport::open_capturing(
            ProbeKind::UdpProbe {
                reply_port: src_port,
            },
            tuning.evasion.effective_send_mode(tuning.send_mode),
            &ctx.capture_links(),
        )?;

        Ok(Self {
            service_detection: tuning.service_detection,
            core: Self::core(resolver, ctx, transport, &tuning, src_port, target_count),
            icmp: HashMap::new(),
        })
    }

    /// Builds a scanner around an already-opened transport, so the caller
    /// decides how probes reach the wire and where replies come from.
    ///
    /// Probes leave from the port the transport's capture admits replies to
    /// (see the module documentation and [`ProbeTransport::reply_port`]);
    /// `src_port` is used for a transport that fixes none, one built from
    /// parts. With a synthetic transport (`ProbeTransport::from_parts`, behind
    /// the `test-support` feature) this drives classification against a
    /// simulated network.
    ///
    /// A transport opened for anything but [`ProbeKind::UdpProbe`] cannot hear
    /// this scan's answers, and the scan refuses it when it runs, with
    /// [`StrategyError::MismatchedTransport`].
    pub fn with_transport(
        resolver: SourceResolver,
        ctx: ScanContext,
        transport: ProbeTransport,
        target_count: usize,
        src_port: u16,
    ) -> Self {
        Self::with_transport_tuned(
            resolver,
            ctx,
            transport,
            target_count,
            src_port,
            ProbeTuning::default(),
        )
    }

    /// [`with_transport`](Self::with_transport), paced and shaped by `tuning`
    /// as [`new`](Self::new) would be: its retry schedule, its rate limits,
    /// what the evasion profile does to each probe, and how far it identifies
    /// what answers.
    ///
    /// Whatever in `tuning` decides how the transport is opened, including the
    /// profile's source port, is the caller's to have honoured already. Probes
    /// leave from the transport's reply port, and from `src_port` only where it
    /// fixes none.
    pub fn with_transport_tuned(
        resolver: SourceResolver,
        ctx: ScanContext,
        transport: ProbeTransport,
        target_count: usize,
        src_port: u16,
        tuning: ProbeTuning,
    ) -> Self {
        Self {
            service_detection: tuning.service_detection,
            core: Self::core(resolver, ctx, transport, &tuning, src_port, target_count),
            icmp: HashMap::new(),
        }
    }

    /// The core a UDP port scan runs on.
    ///
    /// Paced by the send rate alone, having no evidence to run a congestion
    /// window on; the deadline outlives it (see
    /// [`deadline_for`](super::deadline_for)).
    fn core(
        resolver: SourceResolver,
        ctx: ScanContext,
        transport: ProbeTransport,
        tuning: &ProbeTuning,
        src_port: u16,
        target_count: usize,
    ) -> RawProbeScan<()> {
        let rate = super::super::raw::rate_within(
            tuning.max_probe_rate,
            tuning.min_probe_rate,
            super::UDP_PORT_RATE_PER_SEC,
        );

        RawProbeScan::new(CoreParts {
            resolver,
            ctx,
            transport,
            tuning,
            src_port,
            target_count,
            retry: RETRY_POLICY.configured(tuning.retry),
            rate,
            deadline: DEADLINE_CONFIG,
            window: WindowLimits::fixed(MAX_IN_FLIGHT),
            max_unresolved: MAX_IN_FLIGHT as usize,
        })
    }

    /// A reply that matches no outstanding probe is dropped: a duplicate, an
    /// answer to a probe already written off, or a stray packet. Returns
    /// whether it resolved one.
    ///
    /// No round-trip sample is taken for a retried probe, since its datagrams
    /// are identical on the wire.
    fn resolve_probe(
        &mut self,
        target: ProbeTarget,
        state: PortState,
        sender: IpAddr,
        ttl: Option<u8>,
        now: Instant,
    ) -> bool {
        let Some(resolution) = self.core.ledger.resolve(&target, None, now) else {
            self.core.audit.record_reply_without_rtt();
            return false;
        };

        if state == PortState::Closed && sender == target.0 {
            let tally = self.icmp.entry(target.0).or_default();
            tally.closed += 1;
            if resolution.attempts > 1 {
                tally.late += 1;
            }
        }

        let rtt = resolution.rtt;
        self.core.record_answer(&resolution);
        self.record_port_answered_by(target.0, target.1, state, Some(sender), ttl, rtt);
        // The only outcome that settles positively.
        self.settle(Outcome::Answered {
            position: resolution.payload,
        });
        true
    }

    /// Whether this scan asked `target` and settled it already (its port is on
    /// the host), making an unmatched reply a duplicate or late answer.
    fn asked(&self, (ip, port): ProbeTarget) -> bool {
        self.core
            .ctx
            .read_host(ip, |host| {
                host.ports()
                    .any(|found| found.number() == port && found.protocol() == Protocol::Udp)
            })
            .unwrap_or(false)
    }
}

/// The port a direct UDP reply answers for, if the datagram is addressed to
/// this scan's source port.
///
/// ## The protocols this cannot reach
///
/// The port credited is the port the reply came *from*. TFTP breaks that: per
/// RFC 1350 the server sends every packet after a request, errors included,
/// from a freshly allocated port, and port 69 only receives. So a TFTP error is
/// credited to a transient port nobody asked about, and 69 reads
/// `OpenOrNoReply` on a host that answered. Measured against `tftpd-hpa`, which
/// replied from 54154, 43519 and 34965 on three consecutive probes; no request
/// form draws a reply from 69. Identifying TFTP needs a second way to
/// correlate, since a corpus rule could never see the reply.
///
/// The capture filter already narrows UDP to `src_port`, but a transport can be
/// built without one (`ProbeTransport::from_parts`), and a filter that stopped
/// matching would produce false `Open`s. This check is what makes the reply
/// ours.
fn answering_probe(bytes: &[u8], src_port: u16) -> Option<(u16, &[u8])> {
    let udp = UdpPacket::new(bytes)?;
    if udp.get_destination() != src_port {
        return None;
    }
    // Sliced at the fixed header length: the parsed packet's borrow ends here,
    // and the length field of a padded frame is shorter than what was captured.
    Some((udp.get_source(), &bytes[UDP_HDR_LEN..]))
}

/// What a reply is a statement about: the port that was probed, or the address
/// as a whole.
///
/// A reply about the port resolves the probe that provoked it. One about the
/// host says nothing about any port, so the probe is left to time out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// The probed port is in this state: a direct UDP reply, or an ICMP code
    /// that reports on the port.
    Port(PortState),
    /// The address itself could not be reached. The only evidence in the engine
    /// that produces [`HostStatus::Down`].
    Host,
}

/// What an ICMP error means for the UDP port it was drawn by.
///
/// A port unreachable is the one unambiguous "closed" a UDP scan gets: the
/// datagram reached a stack that found no listener. The same message answering
/// a TCP probe means something else, so this mapping lives here, outside
/// [`icmp_error`].
fn verdict_of(reason: Unreachable) -> Verdict {
    match reason {
        Unreachable::Port => Verdict::Port(PortState::Closed),
        // The path refused delivery, or the host has no UDP stack. Either way no
        // listener was looked for, so the port is in effect unprobed.
        Unreachable::Prohibited | Unreachable::Protocol => Verdict::Port(PortState::Blocked),
        Unreachable::Host => Verdict::Host,
    }
}

/// The probe an ICMP error is about and what the error says about it.
///
/// `None` unless the quoted datagram's source port shows it is a UDP probe this
/// scan sent. Its quoted destination address and port name the probe to
/// retire, so an error from a router still points at the probed host.
fn quoted_probe(error: &icmp_error::IcmpError<'_>, src_port: u16) -> Option<ProbeTarget> {
    if error.quoted.protocol != IpNextHeaderProtocols::Udp.0 {
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

    /// Always `OpenOrNoReply`: an open port that did not recognise the payload is
    /// as silent as a firewall.
    fn silence_means(&self) -> PortState {
        PortState::OpenOrNoReply
    }

    fn audit_labels(&self) -> AuditLabels {
        AuditLabels {
            tag: "udp-port",
            silence: "open|no-reply",
        }
    }

    /// Classifies one captured reply and, if it answers an outstanding probe,
    /// resolves that probe.
    fn handle_reply(&mut self, reply: &CapturedSegment, now: Instant) {
        // The host's role and names from the reply, filed after the port verdict.
        let mut declared = None;
        let mut names = Vec::new();
        let classified = match IpNextHeaderProtocol(reply.protocol) {
            IpNextHeaderProtocols::Udp => {
                answering_probe(&reply.bytes, self.core.src_port).map(|(port, datagram)| {
                    declared = payload::declared_role(port, datagram);
                    names = payload::declared_names(port, datagram);
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
                let resolved = self.resolve_probe(
                    target,
                    state,
                    reply.source,
                    // Read now or never; the hop count hints whether the target
                    // or something on its behalf sent the reply.
                    reply.observation.map(IpObservation::remaining_hops),
                    now,
                );
                // Only for a port this scan asked: the capture also hands over
                // other programs' traffic to the source port, which must not
                // create host records. A duplicate or late answer still counts;
                // its port is already on the host.
                if (declared.is_some() || !names.is_empty()) && (resolved || self.asked(target)) {
                    self.core.ctx.update_host(target.0, |host| {
                        if let Some(role) = declared {
                            host.add_network_role(role);
                        }
                        for name in names {
                            host.record_name(name);
                        }
                    });
                }
            }
            // The address could not be reached: no verdict on the quoted port,
            // and the probe retires on its own schedule.
            Some((target, Verdict::Host)) => {
                // No token: a UDP header has no nonce, so the probe's identity
                // is the key, and it must name a live one.
                self.core.record_host_down(&target, None, reply.source);
            }
            None => {}
        }
    }

    /// Retires one outstanding probe with the state its reply established,
    /// crediting the round trip to the deadline.
    ///
    /// Files a port verdict and whatever the reply proves about the host.
    ///
    /// `sender` is the address the reply came from, or `None` when the verdict
    /// came from a spent attempt budget. It is compared against `ip`, because an
    /// ICMP error names both the hop that generated it and the quoted
    /// destination:
    ///
    /// - **The target answered.** Any reply from the host proves it is up,
    ///   including a port unreachable or an administrative rejection.
    /// - **A middlebox rejected the probe by policy.** Something enforces a
    ///   perimeter around the address: [`HostStatus::Blocked`].
    /// - **A middlebox reported the port closed.** The port verdict stands, but
    ///   no host status is recorded: a NAT answering for another host does not
    ///   show that host is up.
    /// - **Nothing answered.** `OpenOrNoReply` from exhaustion records no host
    ///   evidence.
    fn record_port(&mut self, ip: IpAddr, port_num: u16, state: PortState, sender: Option<IpAddr>) {
        if state == PortState::OpenOrNoReply && sender.is_none() {
            self.icmp.entry(ip).or_default().silent += 1;
        }
        self.record_port_answered_by(ip, port_num, state, sender, None, None);
    }

    /// Sends one datagram at `(ip, port)`, first attempt or retry, and records
    /// it. A retry is byte-for-byte the probe before it: the payload makes an
    /// open port answer and the source port is the scan's identity on the wire.
    /// `position` is `Some` only for a probe that has never gone out, since the
    /// ledger keeps it thereafter.
    fn send(&mut self, ip: IpAddr, port: u16, position: Option<u64>, now: Instant) {
        // Only a first attempt takes a window slot; a retry's slot went back
        // when its question ran out of round-trip budget. Read from `position`,
        // since a retry whose probe settled while it waited is gone from the
        // ledger.
        let first_attempt = position.is_some();
        let Some(src_addr) = self.core.source_for((ip, port), first_attempt) else {
            return;
        };

        let sent = send_udp(
            self.core.transport.tx.as_ref(),
            self.core.src_port,
            src_addr,
            ip,
            self.core.resolver.zone_of(ip),
            port,
            EvasionParts {
                emission: self.core.emission,
                shaping: self.core.shaping,
                decoys: &self.core.decoys,
            },
        );
        self.core
            .record_send((ip, port), sent.as_ref().map(|_| ()), first_attempt);

        if sent.is_ok() {
            match position {
                Some(position) => self.core.ledger.arm(ip, (ip, port), (), position, now),
                None => self.core.ledger.rearm(ip, (ip, port), (), now),
            }
        }
    }
}

impl UdpPortScanner {
    /// Names every host whose answers showed its ICMP errors rationed, so a
    /// reader knows its closed ports may read `OpenOrNoReply` and why.
    fn report_rationed(&mut self) {
        for (ip, tally) in self.icmp.drain() {
            if tally.rate_limited() {
                info!(
                    verbosity = 1,
                    "{ip} rate-limited its ICMP errors: {} of its ports answered closed, \
                     {} of them only when asked again, and {} stayed silent",
                    tally.closed,
                    tally.late,
                    tally.silent
                );
                self.core.ctx.record_icmp_rate_limited(ip);
            }
        }
    }

    /// [`record_port`](RawPortScan::record_port), also carrying what the reply
    /// that produced the verdict was measured to be.
    ///
    /// Kept off the shared trait, as in the TCP scanner: the reply's header is
    /// protocol-specific.
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

        // The packet that settled it, so a reader can tell a refusal that
        // arrived from the usual `OpenOrNoReply` silence.
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
            (PortState::Blocked, Some(sender)) if sender == ip => Some((
                HostStatus::Up,
                StatusReason::new(
                    StatusProtocol::IcmpUnreachable,
                    "administratively prohibited by the host",
                ),
            )),
            (PortState::Blocked, Some(sender)) => Some((
                HostStatus::Blocked,
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
/// The port-level mirror of the host evidence recorded beside it. Both refusals
/// are ICMP; which one turns on who sent it.
///
/// `None` where nothing arrived: `OpenOrNoReply` from exhaustion is a UDP
/// scan's ordinary outcome, not a finding.
fn port_evidence(state: PortState, sender: Option<IpAddr>, target: IpAddr) -> Option<ScanResponse> {
    match (state, sender) {
        (PortState::Open, _) => Some(ScanResponse::UdpResponse),
        (PortState::Closed, _) => Some(ScanResponse::IcmpUnreachable),
        // A prohibition from the host is its own policy; from anywhere else it
        // is the path refusing on its behalf.
        (PortState::Blocked, Some(from)) => Some(match from == target {
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
    /// reported as `OpenOrNoReply`.
    ///
    /// New targets are admitted only while fewer than `MAX_IN_FLIGHT` probes are
    /// outstanding, and released no faster than `UDP_PORT_RATE_PER_SEC`. Both
    /// are fixed; see `MAX_IN_FLIGHT`.
    ///
    /// A host whose ICMP errors look rationed is named in the phase's report once
    /// the scan is over; see
    /// [`ScanPhase::icmp_rate_limited`](crate::report::ScanPhase::icmp_rate_limited).
    async fn scan(&mut self, targets: mpsc::Receiver<PlannedTarget>) -> Result<(), StrategyError> {
        let driven = super::drive(self, targets).await;
        self.report_rationed();
        driven
    }

    /// Identifies the UDP services this scanner found open.
    ///
    /// The second pass sends each port the question the corpus registers for it
    /// and reads the datagram back through
    /// [`from_datagram`](crate::fingerprint::reads_replies).
    ///
    /// Scoped to [`Protocol::Udp`] so the SYN scanner sharing a composite with
    /// this one keeps the TCP half, and no port is fingerprinted once per member.
    async fn detect_services(&mut self, ctx: &ScanContext) {
        crate::scanner::service::detect(ctx, self.service_detection, Protocol::Udp).await;
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

    use crate::scanner::strategy::icmp_error::{
        ICMPV6_ADMIN_PROHIBITED, ICMPV6_INGRESS_EGRESS_POLICY, ICMPV6_NO_ROUTE,
        ICMPV6_PORT_UNREACHABLE, ICMPV6_REJECT_ROUTE, ICMPV6_UNUSED_LEN,
    };

    use crate::protocols::{ip, udp};
    use crate::scanner::session::ScanSession;
    use crate::transport::probe::{MockSender, ProbeTransport};

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));
    const TARGET_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 200));
    /// A router between us and the target, reporting errors under its own
    /// address.
    const ROUTER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    /// This host's addresses, as the scanner's source resolver reports them.
    const LOCAL_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
    const LOCAL_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 50));
    /// The fixed source port the scanner under test probes from.
    const SCAN_SRC_PORT: u16 = 54_321;

    fn on_link_interface() -> crate::system::interface::Link {
        use crate::system::interface::{Link, LinkAddress};
        Link::new("test0", 0).with_addresses(vec![
            LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)), 24),
            LinkAddress::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 50)),
                64,
            ),
        ])
    }

    /// [`scanner_with_mock`] plus the probe log, for tests that assert on what
    /// reached the wire.
    fn scanner_with_recorder() -> (UdpPortScanner, ScanSession, SentProbes) {
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(1024);
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
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(1024);
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

    /// `OpenOrNoReply` from exhaustion, the ordinary UDP outcome, records no
    /// packet.
    #[test]
    fn an_unanswered_udp_port_records_no_evidence() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.record_port(TARGET, 53, PortState::OpenOrNoReply, None);

        assert_eq!(
            port_state(&session, TARGET, 53),
            Some(PortState::OpenOrNoReply)
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
        CapturedSegment::synthetic(source, protocol.0, bytes)
    }

    /// A direct UDP reply from `src_port`, addressed back to `dst_port`.
    fn udp_reply(src_port: u16, dst_port: u16) -> CapturedSegment {
        udp_reply_saying(src_port, dst_port, vec![])
    }

    /// A direct UDP reply with a payload.
    fn udp_reply_saying(src_port: u16, dst_port: u16, said: Vec<u8>) -> CapturedSegment {
        captured(
            TARGET,
            IpNextHeaderProtocols::Udp,
            udp::build_packet(TARGET, LOCAL_V4, src_port, dst_port, said).unwrap(),
        )
    }

    /// The quoted datagram an ICMP error carries: the IP header of the probe
    /// plus its UDP header, built with the functions that build a real probe.
    fn quoted_probe_packet(from: IpAddr, to: IpAddr, src_port: u16, dst_port: u16) -> Vec<u8> {
        let datagram = udp::build_packet(from, to, src_port, dst_port, vec![]).unwrap();
        let len = datagram.len() as u16;
        let header = match (from, to) {
            (IpAddr::V4(s), IpAddr::V4(d)) => ip::build_ipv4_header(
                s,
                d,
                len,
                IpNextHeaderProtocols::Udp.0,
                ip::HOP_LIMIT_ROUTED,
            )
            .unwrap(),
            (IpAddr::V6(s), IpAddr::V6(d)) => ip::build_ipv6_header(
                s,
                d,
                len,
                IpNextHeaderProtocols::Udp.0,
                ip::HOP_LIMIT_ROUTED,
            ),
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

    /// The host's role is read from the same datagram as the port verdict. The
    /// payload must be sliced at exactly the UDP header, or the DNS message
    /// fails to parse and the role is silently lost.
    #[test]
    fn a_dns_answer_names_the_host_a_name_server() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        // The engine's own question with the QR bit set.
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

    /// A name server's answer to a question this scan never asked records
    /// nothing, and one to a question it did ask still names the host however
    /// many times it arrives.
    ///
    /// A local resolver that drew the same ephemeral port hears its name
    /// server's answers on the scan's source port; reading a role from one
    /// would invent a host record. A second answer from an asked host is a
    /// duplicate and says what the first did.
    #[test]
    fn a_dns_answer_names_the_sender_only_if_the_scan_asked_it() {
        let (mut scanner, session) = scanner_with_mock();
        let mut answer = crate::scanner::payload::for_port(53).to_vec();
        answer[2] |= 0b1000_0000;

        scanner.handle_reply(
            &udp_reply_saying(53, SCAN_SRC_PORT, answer.clone()),
            Instant::now(),
        );
        assert!(
            session.hosts().get(TARGET).is_none(),
            "an answer nobody asked for invented a host: {:?}",
            session.hosts().get(TARGET)
        );

        probe(&mut scanner, TARGET, 53);
        scanner.handle_reply(&udp_reply(53, SCAN_SRC_PORT), Instant::now());
        scanner.handle_reply(&udp_reply_saying(53, SCAN_SRC_PORT, answer), Instant::now());
        let host = session.hosts().get(TARGET).expect("the host answered");
        assert!(
            host.network_roles().contains(&NetworkRole::DnsServer),
            "a duplicate answer from a host that was asked still names it"
        );
    }

    /// A name table names the machine and its workgroup on the host that was
    /// asked, as the connect path records them.
    #[test]
    fn a_name_table_names_the_machine_and_its_workgroup() {
        use crate::model::host::{NameKind, NameSource};
        use crate::protocols::netbios::tests::response;

        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 137);
        let table = response(&[("FILESERVER", 0x00, false), ("EXAMPLEGRP", 0x00, true)]);
        scanner.handle_reply(&udp_reply_saying(137, SCAN_SRC_PORT, table), Instant::now());

        let host = session.hosts().get(TARGET).expect("the host answered");
        let names: Vec<_> = host
            .names()
            .map(|name| (name.kind(), name.source(), name.name().to_owned()))
            .collect();
        assert_eq!(
            names,
            [
                (
                    NameKind::NetbiosHost,
                    NameSource::Netbios,
                    "FILESERVER".to_owned()
                ),
                (
                    NameKind::NetbiosDomain,
                    NameSource::Netbios,
                    "EXAMPLEGRP".to_owned()
                ),
            ]
        );
    }

    /// Port 53 answering with something other than DNS is only an open port.
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

    /// A datagram from a pending port addressed to another source port belongs
    /// to some other conversation.
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

    /// An unreachable retires only the probe it quotes; other probes to the
    /// same host stay outstanding.
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

    /// An error from a router is attributed by its quoted destination.
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

    /// Host unreachable reports on the address and gives the quoted port no
    /// verdict.
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

    /// An ICMP error proves the target alive only when the target sent it.
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

    /// A policy rejection from a middlebox proves a perimeter, which is
    /// `Blocked`.
    #[test]
    fn an_in_path_policy_rejection_is_blocked_rather_than_up() {
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

        assert_eq!(host_status(&session, TARGET), Some(HostStatus::Blocked));
    }

    /// Silence never moves a host's status, however many probes it swallows.
    #[test]
    fn exhausting_every_attempt_leaves_the_host_unknown() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        let mut now = Instant::now();
        for _ in 0..8 {
            now += Duration::from_secs(10);
            super::super::retry_due(&mut scanner, now);
        }

        assert_eq!(
            port_state(&session, TARGET, 53),
            Some(PortState::OpenOrNoReply)
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

    /// An unreachable quoting another source port is someone else's traffic.
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

    /// Only code 3 says a port answered. The codes for a blocked path prove the
    /// probe did not arrive: `Blocked`.
    #[test]
    fn administratively_prohibited_icmp_is_blocked() {
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
                Some(PortState::Blocked),
                "ICMP code {code:?} should read as blocked"
            );
        }
    }

    /// A code that reports on neither the port nor the path leaves the probe
    /// outstanding, to time out into `OpenOrNoReply` like any other silence.
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
    fn icmpv6_policy_refusals_are_blocked() {
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
                Some(PortState::Blocked),
                "ICMPv6 code {code:?} should read as blocked"
            );
        }
    }

    /// An ICMP error's first two bytes (type 3, code 3) read as the source port
    /// 771 if the segment is parsed as UDP; the protocol from the IP header
    /// prevents a false `Open`.
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

    /// ICMPv6 code 0 is "no route to destination", a statement about the path.
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

    /// A truncated or malformed reply is dropped without panicking.
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

    /// An unanswered probe is sent again.
    #[test]
    fn an_unanswered_probe_is_sent_again() {
        let (mut scanner, session, sent) = scanner_with_recorder();
        probe(&mut scanner, TARGET, 53);

        super::super::retry_due(&mut scanner, Instant::now() + Duration::from_secs(2));

        assert_eq!(sent.lock().unwrap().len(), 2, "the probe was not retried");
        assert_eq!(port_state(&session, TARGET, 53), None, "no verdict yet");
    }

    /// A host that answers some closed ports only on a retry, and leaves more
    /// silent than it answers, is named as rationing its ICMP errors (Linux's
    /// burst, then one a second). One whose answered ports all answered the
    /// first question is a filter in front of a few closed ports, and is not.
    #[test]
    fn a_host_rationing_its_icmp_errors_is_named_and_a_dropping_one_is_not() {
        const DROPPING: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 201));
        let (mut scanner, _session) = scanner_with_mock();
        let unreachable = |host: IpAddr, port: u16| {
            icmpv4_error(
                host,
                IcmpCodes::DestinationPortUnreachable,
                host,
                SCAN_SRC_PORT,
                port,
            )
        };
        for port in 1..=20 {
            probe(&mut scanner, TARGET, port);
            probe(&mut scanner, DROPPING, port);
        }

        // The burst: six from the rationing host, and all eight closed ports of
        // the dropping one.
        let mut now = Instant::now();
        for port in 1..=6 {
            scanner.handle_reply(&unreachable(TARGET, port), now);
        }
        for port in 1..=8 {
            scanner.handle_reply(&unreachable(DROPPING, port), now);
        }

        // The ration's next allowances fall to retries.
        now += Duration::from_secs(2);
        super::super::retry_due(&mut scanner, now);
        for port in 7..=8 {
            scanner.handle_reply(&unreachable(TARGET, port), now);
        }

        // Everything else stays silent to its last attempt.
        for _ in 0..RETRY_POLICY.max_attempts + 1 {
            now += RETRY_POLICY.worst_case_probe_lifetime();
            super::super::retry_due(&mut scanner, now);
        }
        assert!(scanner.core.ledger.is_empty(), "every probe was settled");

        scanner.report_rationed();
        assert_eq!(scanner.core.ctx.take_icmp_rate_limited(), vec![TARGET]);
    }

    /// **A single closed port answered late behind a filter is not a ration.**
    /// A ration answers its burst at once first; a lossy link can lose the one
    /// closed port's first answer and leave a late answer amid silence.
    #[test]
    fn a_single_closed_port_answered_late_behind_a_filter_is_not_a_ration() {
        let lossy_filter = IcmpTally {
            closed: 1,
            late: 1,
            silent: 19,
        };
        assert!(!lossy_filter.rate_limited(), "{lossy_filter:?}");

        let ration = IcmpTally {
            closed: 7,
            late: 1,
            silent: 33,
        };
        assert!(ration.rate_limited(), "{ration:?}");
    }

    /// A probe that has spent its budget is written off while the scan is still
    /// running, so results reach the caller as they are decided.
    #[test]
    fn a_probe_that_spends_its_budget_is_written_off_during_the_scan() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        // Each retry reschedules from when it is sent, so walk the schedule.
        let mut now = Instant::now();
        for _ in 0..RETRY_POLICY.max_attempts + 1 {
            now += RETRY_POLICY.worst_case_probe_lifetime();
            super::super::retry_due(&mut scanner, now);
        }

        assert_eq!(
            port_state(&session, TARGET, 53),
            Some(PortState::OpenOrNoReply)
        );
        assert!(scanner.core.ledger.is_empty());
    }

    /// Running out of attempts does not count as progress for the adaptive
    /// deadline.
    #[test]
    fn running_out_of_attempts_does_not_extend_the_deadline() {
        let (mut scanner, _session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        // A reset silence clock reports a full tick.
        let before = scanner.core.deadline.time_until_next_tick();
        let mut now = Instant::now();
        for _ in 0..RETRY_POLICY.max_attempts + 1 {
            now += RETRY_POLICY.worst_case_probe_lifetime();
            super::super::retry_due(&mut scanner, now);
        }
        let after = scanner.core.deadline.time_until_next_tick();

        assert!(
            after <= before,
            "silence clock was reset by an expiry ({before:?} -> {after:?})"
        );
    }

    /// While probes are outstanding the loop does not sleep past the next one
    /// falling due; in silence nothing else wakes it.
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

    /// The UDP profile tolerates silence longer than a host's ICMP rate-limit
    /// interval (~1/sec), or a scan concludes while its answers are still
    /// queued.
    #[test]
    fn silence_floor_outlasts_the_icmp_rate_limit() {
        const ICMP_RATE_LIMIT_INTERVAL: Duration = Duration::from_secs(1);

        assert!(
            DEADLINE_CONFIG.silence_floor > ICMP_RATE_LIMIT_INTERVAL,
            "silence floor {:?} is shorter than one rate-limited answer",
            DEADLINE_CONFIG.silence_floor
        );
        assert!(
            super::super::super::raw::DEADLINE_CONFIG.silence_floor < ICMP_RATE_LIMIT_INTERVAL,
            "the SYN profile was expected to be the tighter one"
        );
    }

    #[test]
    fn unanswered_probes_resolve_as_open_or_no_reply() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 161);

        super::super::run_out(&mut scanner);

        assert_eq!(
            port_state(&session, TARGET, 161),
            Some(PortState::OpenOrNoReply)
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
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(1024);
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

    /// A UDP header has no nonce field, so a host unreachable is attributed by
    /// the probe's identity alone and must name a live probe. Neither an
    /// address never probed nor one probed on another port is filed down.
    #[test]
    fn a_host_unreachable_about_no_live_probe_records_nothing() {
        let never = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));

        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        // An address never probed.
        scanner.handle_reply(
            &icmpv4_error(
                ROUTER,
                IcmpCodes::DestinationHostUnreachable,
                never,
                SCAN_SRC_PORT,
                53,
            ),
            Instant::now(),
        );
        assert_eq!(
            host_status(&session, never),
            None,
            "an address nothing was sent to is not a host this scan found"
        );

        // The right address, a port nobody asked about.
        scanner.handle_reply(
            &icmpv4_error(
                ROUTER,
                IcmpCodes::DestinationHostUnreachable,
                TARGET,
                SCAN_SRC_PORT,
                9999,
            ),
            Instant::now(),
        );
        assert_ne!(
            host_status(&session, TARGET),
            Some(HostStatus::Down),
            "port 9999 was never probed, so this quotes nothing this scan sent"
        );
    }
}
