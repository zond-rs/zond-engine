// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # TCP Port Probing
//!
//! The privileged TCP half of [`crate::scanner::scan`]. It probes `(address, port)`
//! pairs with raw TCP segments and classifies each by whether and how it responds. The
//! unprivileged fallback, which completes a handshake per port, is
//! [`crate::scanner::strategy::connect`].
//!
//! [`TcpScanTechnique`] decides which segment goes out and what an answer proves; the
//! loop here is the same for all six. Shared across them: retransmission, the
//! in-flight ceiling, the adaptive deadline, source selection, and the rule that
//! silence becomes a verdict only once a probe has spent its whole retry budget.
//!
//! ## Tying a reply to its probe
//!
//! Every probe in a scan leaves from one source port, chosen when the scanner is
//! built. The kernel's capture filter admits segments addressed to it and drops the
//! host's other TCP traffic, over both address families ([`ProbeKind::TcpProbe`]).
//! The scanner checks the port again itself, since a transport can be built with no
//! filter at all.
//!
//! The probe's nonce identifies the *attempt*: each attempt carries a fresh one and a
//! conformant stack echoes it back ([`tcp::echoed_nonce`]). A reply that arrives
//! after a retry went out still names its own attempt, so its round trip is real.
//!
//! An ICMP error is correlated through the copy of the probe it quotes, so an error
//! relayed by a router still points at the probed host. See `icmp_error`.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use tokio::sync::mpsc;

use crate::config::OsDetection;
use crate::config::ProbeTuning;
use crate::config::ServiceDetection;
use crate::evasion::SegmentShaping;
use crate::fingerprint::os;
use crate::journal::settle::Outcome;
use crate::model::capture::IpObservation;
use crate::model::host::{HostStatus, StatusProtocol, StatusReason};
use crate::model::port::discovery::{Discovery as PortDiscovery, ScanResponse};
use crate::model::port::{PortState, Protocol};
use crate::model::target::PlannedTarget;
use crate::model::technique::{TcpReply, TcpScanTechnique};
use crate::protocols::tcp;
use crate::report::ScannerKind;
use crate::scanner::service;
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::{PortScanner, StrategyError};
use crate::success;
use crate::system::interface::SourceResolver;
use crate::transport::capture::CapturedSegment;
use crate::transport::probe::{Emission, ProbeKind, ProbeSender, ProbeTransport, SendError};

// Port scanning and routed discovery share one adaptive-deadline profile but not a
// retry schedule: a sweep loses probes to the path, a port scan to its own burst at
// one stack. See `PORT_RETRY_POLICY`.
use super::PORT_RETRY_POLICY;
use super::{AuditLabels, CoreParts, ProbeTarget, RawPortScan, RawProbeScan};
use crate::scanner::strategy::icmp_error::{self, Unreachable};

/// What identifies one attempt of a probe on the wire.
///
/// The nonce alone: the source port is the same for every attempt and identifies the
/// scan. A fresh nonce per attempt makes a retried probe's round trip measurable,
/// which TCP itself cannot do (it discards samples from retransmissions, Karn's
/// algorithm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcpToken {
    nonce: u32,
}

/// Probes specific `(address, port)` pairs with raw TCP segments, using
/// whichever [`TcpScanTechnique`] it was built for.
///
/// Sends one probe per `(address, port)` pair and reports what each revealed. For a
/// one-SYN-per-host liveness check, see
/// [`RoutedScanner`](crate::scanner::strategy::routed::RoutedScanner).
pub struct TcpPortScanner {
    /// Which segment each probe carries, and so what every answer means. Fixed for
    /// the scan, so every verdict in a report comes from one technique.
    technique: TcpScanTechnique,
    /// A TCP flag byte to send in place of the technique's, from
    /// [`EvasionProfile::flags`](crate::evasion::EvasionProfile::flags). When set,
    /// verdicts soften to reachable-or-silent, since an arbitrary combination has no
    /// open/closed meaning. See [`effective_flags`](Self::effective_flags).
    flags_override: Option<u8>,
    /// The protocol-independent raw scan: transport, ledger, deadline, pacing and
    /// stop conditions.
    core: RawProbeScan<TcpToken>,

    /// How far this scan may go to identify a host's operating system.
    ///
    /// A SYN+ACK is the only segment that carries a stack's shape, and it arrives
    /// here. At [`OsDetection::Passive`] nothing extra is sent or timed; reading the
    /// reply costs a parse.
    os_detection: OsDetection,

    /// How far the service identification pass over open ports may go; see
    /// [`detect_services`](PortScanner::detect_services).
    service_detection: ServiceDetection,
}

impl TcpPortScanner {
    /// Builds a scanner that selects each probe's source via `resolver`, sized
    /// for a scan covering `target_count` `(address, port)` pairs.
    ///
    /// Unless the evasion profile fixes one, the source port is drawn from 50000 and
    /// up, where it is unlikely to collide with a local listener. The capture filter
    /// is built around it.
    pub fn new(
        resolver: SourceResolver,
        ctx: ScanContext,
        technique: TcpScanTechnique,
        target_count: usize,
        tuning: ProbeTuning,
    ) -> Result<Self, StrategyError> {
        let src_port: u16 = tuning
            .evasion
            .source_port_or(rand::random_range(50_000..u16::MAX));
        let flags_override = tuning.evasion.flags;
        let transport = ProbeTransport::open_capturing(
            ProbeKind::TcpProbe {
                reply_port: src_port,
                // Arbitrary flags read ICMP like a flag-probe technique: an error
                // naming the filter turns silence into blocked.
                icmp_errors: technique.reads_icmp_errors()
                    || flags_override.is_some()
                    || tuning.icmp_evidence,
            },
            tuning.evasion.effective_send_mode(tuning.send_mode),
            &ctx.capture_links(),
        )?;

        Ok(Self::build(
            Self::core(resolver, ctx, transport, &tuning, src_port, target_count),
            technique,
            flags_override,
            tuning.os_detection,
            tuning.service_detection,
        ))
    }

    /// Builds a scanner around an already-opened transport, so the caller decides
    /// how probes reach the wire and where replies come from.
    ///
    /// Probes leave from the transport's reply port ([`ProbeKind::TcpProbe`]'s
    /// `reply_port`; see [`ProbeTransport::reply_port`]). `src_port` is used only
    /// for a transport that fixes none, such as one built from parts. With a
    /// synthetic transport (`ProbeTransport::from_parts`, behind the `test-support`
    /// feature) this drives probe/reply correlation against a simulated network,
    /// with no privileges and no interface.
    ///
    /// A transport opened for a kind other than [`ProbeKind::TcpProbe`] or
    /// [`ProbeKind::TcpSyn`] cannot hear the answers; the scan fails with
    /// [`StrategyError::MismatchedTransport`] when it runs.
    pub fn with_transport(
        resolver: SourceResolver,
        ctx: ScanContext,
        technique: TcpScanTechnique,
        transport: ProbeTransport,
        target_count: usize,
        src_port: u16,
    ) -> Self {
        Self::with_transport_tuned(
            resolver,
            ctx,
            technique,
            transport,
            target_count,
            src_port,
            ProbeTuning::default(),
        )
    }

    /// [`with_transport`](Self::with_transport), paced and shaped by `tuning` as
    /// [`new`](Self::new) would be: retry schedule, rate limits, evasion (including
    /// the flag byte) and identification depth.
    ///
    /// Settings in `tuning` that decide how the transport is opened, including the
    /// profile's source port, are the caller's to have applied already. Probes leave
    /// from the transport's reply port, and from `src_port` only when it fixes none.
    pub fn with_transport_tuned(
        resolver: SourceResolver,
        ctx: ScanContext,
        technique: TcpScanTechnique,
        transport: ProbeTransport,
        target_count: usize,
        src_port: u16,
        tuning: ProbeTuning,
    ) -> Self {
        Self::build(
            Self::core(resolver, ctx, transport, &tuning, src_port, target_count),
            technique,
            tuning.evasion.flags,
            tuning.os_detection,
            tuning.service_detection,
        )
    }

    /// The common constructor: a finished core plus the TCP-specific settings.
    fn build(
        core: RawProbeScan<TcpToken>,
        technique: TcpScanTechnique,
        flags_override: Option<u8>,
        os_detection: OsDetection,
        service_detection: ServiceDetection,
    ) -> Self {
        Self {
            technique,
            flags_override,
            os_detection,
            service_detection,
            core,
        }
    }

    /// The core a TCP port scan runs on.
    ///
    /// Paced by its congestion window under the rate ceiling, with a deadline that
    /// outlasts the slowest pace either may settle at; see
    /// [`deadline_for`](super::deadline_for).
    fn core(
        resolver: SourceResolver,
        ctx: ScanContext,
        transport: ProbeTransport,
        tuning: &ProbeTuning,
        src_port: u16,
        target_count: usize,
    ) -> RawProbeScan<TcpToken> {
        let retry = PORT_RETRY_POLICY.configured(tuning.retry);
        let rate = super::super::raw::rate_within(
            tuning.max_probe_rate,
            tuning.min_probe_rate,
            super::TCP_PORT_RATE_CEILING,
        );

        RawProbeScan::new(CoreParts {
            resolver,
            ctx,
            transport,
            tuning,
            src_port,
            target_count,
            retry,
            rate,
            deadline: super::super::raw::DEADLINE_CONFIG,
            window: super::TCP_PORT_WINDOW,
            max_unresolved: super::TCP_PORT_UNRESOLVED,
        })
    }

    /// Matches a TCP segment against an outstanding probe and, if it answers
    /// one, classifies it and records the port's state.
    fn handle_tcp_reply(&mut self, captured: &CapturedSegment, now: Instant) {
        let (ip, bytes) = (captured.source, &captured.bytes);
        let Ok(tcp_packet) = tcp::parse(bytes) else {
            self.core.audit.record_off_target();
            return;
        };

        // This scan's own outbound probe, witnessed. A segment from the scan's port
        // to that same port is either the probe of that port (a full range asks
        // it) or the answer; only the probe carries the probe's flags, since an
        // answer is a reset or SYN+ACK, which no technique sends.
        if tcp_packet.source_port() == self.core.src_port
            && (tcp_packet.destination_port() != self.core.src_port
                || tcp_packet.flags() == self.effective_flags())
        {
            self.witness_probe(captured, &tcp_packet);
            return;
        }

        // Not addressed to this scan's port: someone else's traffic. The capture
        // filter usually drops these, but a transport can have no filter.
        if tcp_packet.destination_port() != self.core.src_port {
            self.core.audit.record_off_target();
            return;
        }

        let Some(reply) = tcp::classify_probe_response(&tcp_packet) else {
            self.core.audit.record_off_target();
            return;
        };
        // Arbitrary flags have no open/closed meaning, so any reply proves only
        // that the port is reachable. A named technique reads its verdict; a
        // segment it could not have provoked (a SYN+ACK to an ACK scan) is someone
        // else's traffic and resolves nothing.
        let state = if self.arbitrary_flags() {
            PortState::Reachable
        } else {
            match self.technique.verdict(reply) {
                Some(state) => state,
                None => return,
            }
        };

        // The attempt the segment claims to answer. The ledger checks it against
        // every live attempt for this port, so a late reply to an earlier attempt
        // still yields its real round trip.
        let token = TcpToken {
            nonce: tcp::echoed_nonce_with_flags(
                self.effective_flags(),
                &tcp_packet,
                self.core.shaping.padding.unwrap_or(0),
            ),
        };
        let key = (ip, tcp_packet.source_port());
        let resolved = self.resolve_probe(
            key,
            Some(token),
            state,
            Answer {
                drawn_by: Some(reply),
                sender: None,
                ttl: captured.observation.map(IpObservation::remaining_hops),
            },
            now,
        );

        // Only for a reply to one of this scan's probes: a stray segment on the
        // source port would otherwise create a record for a host never asked about.
        if resolved {
            self.identify_stack(ip, state, captured);
        }
    }

    /// Marks the probe this outbound segment carries as seen on the wire,
    /// ignoring a frame it cannot match to a live probe.
    fn witness_probe(&mut self, captured: &CapturedSegment, probe: &tcp::Segment<'_>) {
        let Some(destination) = captured.destination else {
            return;
        };
        let token = TcpToken {
            nonce: tcp::sent_nonce_with_flags(self.effective_flags(), probe),
        };
        if self
            .core
            .ledger
            .witness(&(destination, probe.destination_port()), &token)
        {
            self.core.audit.record_witnessed_send();
        }
    }

    /// Reads what the reply that just resolved a port says about the host's stack,
    /// and files it against the host.
    ///
    /// Runs after the port verdict and cannot change it, so a defect here cannot cost
    /// a port its state.
    ///
    /// Only a SYN+ACK is read. A reset carries no TCP options whatever the probe
    /// offered, and the corpus holds no usable reset rule: the one promising feature
    /// took opposite values for the same labelled devices across two scanners.
    fn identify_stack(&self, ip: IpAddr, state: PortState, captured: &CapturedSegment) {
        // `None`: no IP header was ever available (a synthetic receive stream).
        let Some(observation) = captured.observation else {
            return;
        };

        // Before the detection gate: the hop counter is free to keep, and a
        // traceroute (a separate setting) needs it even without OS detection.
        self.core.ctx.update_host(ip, |host| {
            host.record_hop_counter(observation.remaining_hops())
        });

        if !self.os_detection.is_enabled() || state != PortState::Open {
            return;
        }
        let Some(stack) = os::classify_reply(observation, &captured.bytes) else {
            return;
        };

        self.core.ctx.update_host(ip, |host| {
            // `identify` weighs the host's own hardware and name beside this.
            os::identify(host, [stack.as_evidence()]);
        });
    }

    /// Reads an ICMP error as a verdict on the probe it quotes.
    ///
    /// The quotation is checked as strictly as a TCP reply: a TCP segment from this
    /// scan's port, aimed at a probe still outstanding. Eight quoted bytes reach the
    /// sequence number and no further, so for a technique whose nonce is in the
    /// acknowledgement field a minimal quote names the probe by its ports alone. That
    /// suffices for a host unreachable, which settles no port. A refusal that cannot
    /// name the attempt retires nothing; the port follows its own retry schedule.
    fn handle_icmp_error(&mut self, reply: &CapturedSegment, now: Instant) {
        let Some(error) = icmp_error::parse(reply) else {
            return;
        };
        if error.quoted.protocol != IpNextHeaderProtocols::Tcp.0 {
            return;
        }

        let Some(quoted) = tcp::quoted_probe(error.quoted.payload) else {
            return;
        };
        if quoted.source != self.core.src_port {
            return;
        }

        let key = (error.quoted.destination, quoted.destination);
        let token = tcp::quoted_nonce_with_flags(self.effective_flags(), &quoted)
            .map(|nonce| TcpToken { nonce });

        match error.reason {
            // No verdict on the quoted port. The probe stays outstanding and
            // retires on its own schedule.
            Unreachable::Host => {
                self.core.record_host_down(&key, token, reply.source);
            }
            // The rest are refusals and read alike for TCP. No TCP stack emits a
            // port unreachable, so one means something in the path rejected the
            // probe: a filter, not a closed port. A protocol unreachable (no TCP
            // stack) is not a closed port either; the protocol pass reads it.
            //
            // A refusal settles a port, so it must name the attempt. Four
            // techniques carry the nonce in the sequence number, inside the eight
            // bytes RFC 792 guarantees. The two using the acknowledgement field,
            // and Maimon (which carries ACK), need twelve quoted bytes, and a
            // minimal quote leaves `token` as `None`.
            //
            // Resolving then would trust the ports alone, which anyone who knows
            // the source port can forge: an ACK or window scan's `NoReply` would
            // become `Blocked` with an invented `IcmpProhibited`, and a Maimon
            // scan's `OpenOrNoReply` would dismiss an open port. So such a refusal
            // retires nothing. The SCTP scanner has the same rule, since an INIT's
            // nonce is never inside the guaranteed eight bytes.
            Unreachable::Port | Unreachable::Prohibited | Unreachable::Protocol
                if token.is_none() =>
            {
                self.core.audit.record_unattributed_refusal();
            }
            Unreachable::Port | Unreachable::Prohibited | Unreachable::Protocol => {
                self.resolve_probe(
                    key,
                    token,
                    PortState::Blocked,
                    Answer {
                        drawn_by: None,
                        sender: Some(reply.source),
                        // Distance to whatever refused the probe: a refusal from
                        // nearer than the host is a middlebox answering for it.
                        ttl: reply.observation.map(IpObservation::remaining_hops),
                    },
                    now,
                );
            }
        }
    }

    /// Retires one outstanding probe with the state its reply established, crediting
    /// whatever round trip the ledger vouches for.
    ///
    /// `token` names the answered attempt, or is `None` when the reply could not say.
    /// Returns whether a probe was resolved; only then may the rest of the reply be
    /// read.
    fn resolve_probe(
        &mut self,
        key: ProbeTarget,
        token: Option<TcpToken>,
        state: PortState,
        answer: Answer,
        now: Instant,
    ) -> bool {
        let Some(resolution) = self.core.ledger.resolve(&key, token, now) else {
            // Stray or spoofed, a duplicate, or an answer to a probe already
            // written off. No sample.
            self.core.audit.record_reply_without_rtt();
            return false;
        };

        let rtt = resolution.rtt;
        self.core.record_answer(&resolution);
        self.record_port_answered_by(key.0, key.1, state, answer, rtt);
        self.settle(Outcome::Answered {
            position: resolution.payload,
        });
        true
    }

    /// Which protocol a host verdict from this scan is credited to.
    ///
    /// [`StatusProtocol::TcpSyn`] always means a half-open connection attempt. Other
    /// techniques credit [`StatusProtocol::Tcp`] and name the probe in the reason's
    /// details.
    const fn status_protocol(&self) -> StatusProtocol {
        match self.technique {
            TcpScanTechnique::Syn => StatusProtocol::TcpSyn,
            _ => StatusProtocol::Tcp,
        }
    }

    /// The TCP flag byte every probe carries: the arbitrary override when a
    /// profile set one, otherwise the technique's own combination.
    fn effective_flags(&self) -> u8 {
        self.flags_override
            .unwrap_or_else(|| tcp::probe_flags(self.technique))
    }

    /// Whether this scan sends an arbitrary flag combination, so a reply means only
    /// reachable and silence means `OpenOrNoReply`.
    const fn arbitrary_flags(&self) -> bool {
        self.flags_override.is_some()
    }
}

impl RawPortScan for TcpPortScanner {
    type Token = TcpToken;

    fn core(&self) -> &RawProbeScan<TcpToken> {
        &self.core
    }

    fn core_mut(&mut self) -> &mut RawProbeScan<TcpToken> {
        &mut self.core
    }

    fn protocol(&self) -> Protocol {
        Protocol::Tcp
    }

    /// Set by the technique: a firewall for the two probes any live stack answers,
    /// an open port or a firewall for the four an open port must ignore.
    fn silence_means(&self) -> PortState {
        if self.arbitrary_flags() {
            // A drop, or an open port that ignored the probe.
            PortState::OpenOrNoReply
        } else {
            self.technique.silence_means()
        }
    }

    /// "unanswered" for silence, since its verdict depends on the technique.
    fn audit_labels(&self) -> AuditLabels {
        AuditLabels {
            tag: "tcp-port",
            silence: "unanswered",
        }
    }

    /// Routes one captured reply to the TCP or ICMP classifier.
    ///
    /// ICMP only reaches here for a technique that asked for it; see
    /// [`TcpScanTechnique::reads_icmp_errors`].
    fn handle_reply(&mut self, reply: &CapturedSegment, now: Instant) {
        match IpNextHeaderProtocol(reply.protocol) {
            IpNextHeaderProtocols::Tcp => self.handle_tcp_reply(reply, now),
            _ => self.handle_icmp_error(reply, now),
        }
    }

    /// Files a port verdict and whatever the reply that produced it proves about
    /// the host.
    ///
    /// `sender` is the address the reply came from, or `None` when the verdict came
    /// from a spent attempt budget. An ICMP error names two addresses, the hop that
    /// generated it and the quoted destination, and they mean different things:
    ///
    /// - **The target answered.** Any segment from the host proves it is up,
    ///   including a RST that is negative about the port.
    /// - **A middlebox rejected the probe by policy.** Something enforces a perimeter
    ///   around the address: [`HostStatus::Blocked`].
    /// - **Nothing answered.** Records nothing about the host, so `is_alive()` stays
    ///   false for a host that never sent a packet.
    fn record_port(&mut self, ip: IpAddr, port_num: u16, state: PortState, sender: Option<IpAddr>) {
        // Called by the shared loop for verdicts from silence; replies go through
        // the fuller form below.
        self.record_port_answered_by(
            ip,
            port_num,
            state,
            Answer {
                sender,
                ..Answer::default()
            },
            None,
        );
    }

    /// One send, first attempt or retry. `position` is `Some` only for a probe
    /// that has never gone out, since the ledger keeps it thereafter.
    fn send(&mut self, ip: IpAddr, port: u16, position: Option<u64>, now: Instant) {
        // Only a first attempt takes a congestion-window slot; a retry's slot went
        // back when the attempt it repeats timed out. Decided by `position`, not
        // the ledger, which holds nothing for a retry whose probe settled while
        // it waited.
        let first_attempt = position.is_some();
        let Some(src_addr) = self.core.source_for((ip, port), first_attempt) else {
            return;
        };

        let token = send_tcp_probe(
            self.core.transport.tx.as_ref(),
            self.technique,
            self.effective_flags(),
            self.core.src_port,
            src_addr,
            ip,
            self.core.resolver.zone_of(ip),
            port,
            self.core.emission,
            self.core.shaping,
            &self.core.decoys,
        );
        self.core
            .record_send((ip, port), token.as_ref().map(|_| ()), first_attempt);

        if let Ok(token) = token {
            match position {
                Some(position) => self.core.ledger.arm(ip, (ip, port), token, position, now),
                None => self.core.ledger.rearm(ip, (ip, port), token, now),
            }
        }
    }
}

impl TcpPortScanner {
    /// [`record_port`](RawPortScan::record_port), plus the reply that produced the
    /// verdict and what it carried. Not on the shared trait, since UDP has no
    /// segment flags.
    fn record_port_answered_by(
        &mut self,
        ip: IpAddr,
        port_num: u16,
        state: PortState,
        answer: Answer,
        rtt: Option<Duration>,
    ) {
        let Answer {
            drawn_by, sender, ..
        } = answer;

        let port = crate::fingerprint::baseline_port(port_num, Protocol::Tcp, state);

        // Record the packet that settled it, so `blocked` says whether the target
        // or something on its path refused.
        let port = match port_evidence(state, drawn_by, sender, ip) {
            Some(reason) => {
                let mut discovery = PortDiscovery::new(reason);
                if let Some(rtt) = rtt {
                    discovery = discovery.with_rtt(rtt);
                }
                if let Some(ttl) = answer.ttl {
                    discovery = discovery.with_ttl(ttl);
                }
                port.with_discovery(discovery)
            }
            None => port,
        };
        let evidence = match (state, sender) {
            // Three routes to an open port, recorded distinctly: a SYN+ACK; a
            // challenge ACK (already half-open, which only a listener can be); a
            // RST whose window a window scan reads.
            (PortState::Open, _) => Some((
                HostStatus::Up,
                match drawn_by {
                    Some(TcpReply::Rst { .. }) => {
                        StatusReason::new(self.status_protocol(), rst_evidence(self.technique))
                    }
                    Some(TcpReply::ChallengeAck) => StatusReason::new(
                        StatusProtocol::TcpSyn,
                        "challenge ack from a probed port, so a listener holds it half-open",
                    ),
                    _ => StatusReason::new(StatusProtocol::TcpSyn, "syn-ack from a probed port"),
                },
            )),
            // A RST: closed for most techniques, reachable for the ACK scan.
            (PortState::Closed | PortState::Reachable, _) => Some((
                HostStatus::Up,
                StatusReason::new(self.status_protocol(), rst_evidence(self.technique)),
            )),
            (PortState::Blocked, Some(sender)) if sender == ip => Some((
                HostStatus::Up,
                StatusReason::new(
                    StatusProtocol::IcmpUnreachable,
                    "unreachable for a probed port, from the host",
                ),
            )),
            (PortState::Blocked, Some(sender)) => Some((
                HostStatus::Blocked,
                StatusReason::new(
                    StatusProtocol::IcmpUnreachable,
                    "unreachable for a probed port, from the path",
                )
                .from_source(sender),
            )),
            _ => None,
        };

        // Credit the host with a TCP reply's round trip, as a liveness pass would;
        // a scan that ran none has no other measure. An ICMP error's round trip
        // may be a router's. The echoed nonce times a retried probe from the
        // attempt it answers, where Karn's rule would discard it.
        let timed = rtt.filter(|_| drawn_by.is_some());
        let protocol = self.status_protocol();
        self.core.ctx.update_host(ip, |host| {
            host.add_port(port);
            if let Some((status, reason)) = evidence {
                host.record_evidence(status, reason);
            }
            if let Some(rtt) = timed {
                host.add_rtt_from(rtt, protocol);
            }
        });
    }
}

/// What the reply that settled a port was, past the verdict it produced.
///
/// Every field is `None` for a port nothing answered.
#[derive(Debug, Clone, Copy, Default)]
struct Answer {
    /// Which segment produced the verdict, when a TCP reply did.
    drawn_by: Option<TcpReply>,
    /// Who sent it, when that was not the target itself.
    sender: Option<IpAddr>,
    /// The hop counter as it arrived (IPv4 TTL or IPv6 hop limit): the initial
    /// value less the path length. A reply whose count disagrees with the host's
    /// other replies came from somewhere else. See
    /// [`IpObservation::remaining_hops`](crate::model::capture::IpObservation::remaining_hops).
    ttl: Option<u8>,
}

/// Which packet settled a port, in the vocabulary a report records.
///
/// The port-level counterpart of the host evidence: why the *port* has its state.
///
/// A [`PortState::Blocked`] port records whether the target or the path refused.
/// A [`PortState::NoReply`] port whose attempts ran out records
/// [`ScanResponse::NoResponse`]. [`PortState::OpenOrNoReply`] records nothing, since
/// the flag-probe techniques produce it in bulk and it would repeat the verdict.
///
/// `None` when no packet is named.
fn port_evidence(
    state: PortState,
    drawn_by: Option<TcpReply>,
    sender: Option<IpAddr>,
    target: IpAddr,
) -> Option<ScanResponse> {
    match (state, drawn_by, sender) {
        // A window scan's open port.
        (PortState::Open, Some(TcpReply::Rst { .. }), _) => Some(ScanResponse::TcpRst),
        // SYN+ACK or challenge ACK, both recorded as the SYN/ACK path.
        (PortState::Open, _, _) => Some(ScanResponse::TcpSynAck),
        (PortState::Closed | PortState::Reachable, _, _) => Some(ScanResponse::TcpRst),
        // From the target: its own policy. From the path: someone else's. The
        // sender's address is on the host's evidence.
        (PortState::Blocked, _, Some(from)) => Some(match from == target {
            true => ScanResponse::IcmpProhibited,
            false => ScanResponse::IcmpUnreachable,
        }),
        (PortState::NoReply, None, None) => Some(ScanResponse::NoResponse),
        _ => None,
    }
}

/// What a RST proves, said in the terms of the probe that drew it.
///
/// Static strings, since [`StatusReason`] holds details in an `Arc<str>` so
/// thousands of ports with the same rationale share one allocation.
const fn rst_evidence(technique: TcpScanTechnique) -> &'static str {
    match technique {
        TcpScanTechnique::Syn => "rst from a probed port",
        TcpScanTechnique::Fin => "rst to a fin probe",
        TcpScanTechnique::Null => "rst to a flagless probe",
        TcpScanTechnique::Xmas => "rst to a fin-psh-urg probe",
        TcpScanTechnique::Maimon => "rst to a fin-ack probe",
        TcpScanTechnique::Ack => "rst to an ack probe",
        TcpScanTechnique::Window => "rst to an ack probe, read for its window",
    }
}

/// Sends one probe of `technique` from `src_port` at `dst_addr:dst_port` and
/// returns its token, so a later reply can be matched to this attempt.
///
/// The nonce is drawn fresh here for every attempt: two attempts with the same
/// nonce cannot be told apart by their replies.
///
/// Errors are returned unlogged so the scan can attribute and report each once; a
/// probe never sent must not be counted as one nobody answered. See
/// [`RawProbeScan::record_send`](super::RawProbeScan::record_send).
#[allow(clippy::too_many_arguments)]
fn send_tcp_probe(
    sender: &dyn ProbeSender,
    technique: TcpScanTechnique,
    flags: u8,
    src_port: u16,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    dst_zone: Option<u32>,
    dst_port: u16,
    emission: Emission,
    shaping: SegmentShaping,
    decoys: &[IpAddr],
) -> Result<TcpToken, SendError> {
    let nonce: u32 = rand::random();

    // A build failure is this host's, worded as the link-layer sender words one.
    let packet = tcp::build_probe_with_flags(
        flags,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        nonce,
        shaping.padding,
        shaping.bad_tcp_checksum,
    )
    .map_err(|e| SendError::Refused(format!("the {technique} probe could not be built: {e}")))?;

    // One decoy per address of the target's family, with its own port and nonce
    // and the same flags and shaping, so no probe stands out.
    let decoy_packets: Vec<(IpAddr, Vec<u8>)> = decoys
        .iter()
        .filter(|decoy| decoy.is_ipv4() == dst_addr.is_ipv4())
        .filter_map(|&decoy| {
            tcp::build_probe_with_flags(
                flags,
                decoy,
                dst_addr,
                rand::random_range(50_000..u16::MAX),
                dst_port,
                rand::random(),
                shaping.padding,
                shaping.bad_tcp_checksum,
            )
            .ok()
            .map(|packet| (decoy, packet))
        })
        .collect();

    super::super::raw::emit_among_decoys(
        sender,
        dst_addr,
        dst_zone,
        emission,
        src_addr,
        &packet,
        &decoy_packets,
    )?;
    success!(
        verbosity = 2,
        "sent {technique} probe to {dst_addr}:{dst_port}"
    );
    Ok(TcpToken { nonce })
}

#[async_trait]
impl PortScanner for TcpPortScanner {
    /// A SYN scan is [`ScannerKind::SynPort`], which consumers already parse. The
    /// other techniques are [`ScannerKind::TcpPort`]; which one ran is in the
    /// phase's settings.
    ///
    /// The rule lives on [`ScannerKind::for_raw_tcp`], since
    /// [`PortScanStep`](crate::scanner::plan::PortScanStep) needs the same answer
    /// when attributing a socket that would not open.
    fn kind(&self) -> ScannerKind {
        ScannerKind::for_raw_tcp(self.technique)
    }

    fn supported_protocols(&self) -> Vec<Protocol> {
        vec![Protocol::Tcp]
    }

    /// Consumes `targets`, probing each TCP one, retrying unanswered ones and
    /// classifying every reply until each probe is resolved or out of attempts. UDP
    /// and SCTP targets are skipped. Anything still outstanding at the end takes the
    /// technique's silence verdict.
    ///
    /// New targets are admitted only while the congestion window has room, and
    /// retries go before new targets. The window paces the scan and learns each
    /// target's capacity; see `TCP_PORT_WINDOW`.
    async fn scan(&mut self, targets: mpsc::Receiver<PlannedTarget>) -> Result<(), StrategyError> {
        super::drive(self, targets).await
    }

    /// Fingerprints every open port found. The raw exchange never opened a
    /// connection, so this pass opens one per open port and runs the shared
    /// fingerprint engine over it.
    ///
    /// Only a SYN or window scan reports [`PortState::Open`] (see
    /// [`TcpScanTechnique::finds_open_ports`]); after any other technique this
    /// finds nothing and returns at once.
    async fn detect_services(&mut self, ctx: &ScanContext) {
        service::detect(ctx, self.service_detection, Protocol::Tcp).await;
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
    use crate::model::target::Target;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use pnet_packet::icmp::destination_unreachable::{
        DestinationUnreachablePacket, IcmpCodes, MutableDestinationUnreachablePacket,
    };
    use pnet_packet::icmp::{IcmpCode, IcmpTypes};
    use pnet_packet::tcp::MutableTcpPacket;

    use crate::protocols::ip;
    use crate::scanner::session::ScanSession;
    use crate::scanner::strategy::raw::neighbors::NEIGHBOR_ROUNDS;
    use crate::transport::probe::{MockSender, ProbeTransport};

    /// The port a scanner under test probes from. Any would do with a synthetic
    /// transport; a fixed one keeps runs comparable.
    const SRC_PORT: u16 = 54_321;

    const SYN: u8 = 1 << 1;
    const RST: u8 = 1 << 2;
    const PSH: u8 = 1 << 3;
    const ACK: u8 = 1 << 4;
    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));
    /// This host's address on [`on_link_interface`], which its probes leave from.
    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
    const LOCAL_IP: IpAddr = IpAddr::V4(LOCAL);
    /// A router between here and [`TARGET`], which reports errors under its own
    /// address.
    const ROUTER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    /// An interface whose /24 contains [`TARGET`], so source resolution
    /// answers on-link without a kernel route probe.
    fn on_link_interface() -> crate::system::interface::Link {
        use crate::system::interface::{Link, LinkAddress};
        use std::net::{Ipv4Addr, Ipv6Addr};
        Link::new("test0", 0).with_addresses(vec![
            LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)), 24),
            LinkAddress::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 50)),
                64,
            ),
        ])
    }

    /// A bare 20-byte TCP segment as captured after the link and IP headers are
    /// stripped: from `from_port` on the target to `to_port` here, echoing the
    /// nonce as a stack answering `technique` would.
    ///
    /// The echo rule is written out from RFC 793 §3.4 independently of
    /// [`tcp::echoed_nonce`], so a wrong engine rule fails these tests. A probe
    /// carrying ACK gives the reset its sequence number; otherwise the reset
    /// acknowledges the probe's sequence number plus the octet a FIN or SYN
    /// occupies, so a flagless probe is acknowledged unchanged.
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
            TcpScanTechnique::Maimon | TcpScanTechnique::Ack | TcpScanTechnique::Window => {
                tcp.set_sequence(token.nonce)
            }
            TcpScanTechnique::Null => tcp.set_acknowledgement(token.nonce),
            _ => tcp.set_acknowledgement(token.nonce.wrapping_add(1)),
        }
        buf
    }

    /// [`segment_to`] addressed to the scan's source port.
    fn tcp_segment(
        scanner: &TcpPortScanner,
        from_port: u16,
        token: TcpToken,
        flags: u8,
    ) -> Vec<u8> {
        segment_to(
            from_port,
            scanner.core.src_port,
            scanner.technique,
            token,
            flags,
        )
    }

    /// The probes a [`MockSender`] recorded, shared with the scanner under test.
    type SentProbes = std::sync::Arc<std::sync::Mutex<Vec<crate::transport::probe::SentProbe>>>;

    /// A sender that refuses everything, like an interface with a full queue or an
    /// unresolvable neighbour.
    struct RefusingSender;

    impl crate::transport::probe::ProbeSender for RefusingSender {
        fn send(
            &self,
            _segment: &[u8],
            _src: IpAddr,
            _dst: IpAddr,
            _zone: Option<u32>,
            _emission: Emission,
        ) -> Result<(), crate::transport::probe::SendError> {
            Err(crate::transport::probe::SendError::Refused(
                "no route to host".to_string(),
            ))
        }
    }

    /// A SYN scanner on a recording [`MockSender`] and an idle capture stream, with
    /// the session and the probe log.
    fn scanner_with_mock() -> (TcpPortScanner, ScanSession, SentProbes) {
        scanner_for(TcpScanTechnique::Syn)
    }

    /// [`scanner_with_mock`] for an explicit technique.
    fn scanner_for(technique: TcpScanTechnique) -> (TcpPortScanner, ScanSession, SentProbes) {
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(1024);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport = ProbeTransport::from_parts(Box::new(sender), reply_rx);
        let resolver = SourceResolver::from_links(&[on_link_interface()]);
        let scanner =
            TcpPortScanner::with_transport(resolver, ctx, technique, transport, 8, SRC_PORT);
        (scanner, session, sent)
    }

    /// Sends a probe to `TARGET:port` and returns its token, read off the recording
    /// sender so tests answer what actually reached the wire.
    fn probe(scanner: &mut TcpPortScanner, sent: &SentProbes, port: u16) -> TcpToken {
        let before = sent.lock().unwrap().len();
        scanner.send_probe(PlannedTarget::new(
            u64::from(port),
            Target {
                ip: TARGET,
                port,
                protocol: Protocol::Tcp,
            },
        ));

        let sent = sent.lock().unwrap();
        let (segment, _, _) = sent.get(before).expect("probe reached the wire");
        token_of(scanner.technique, segment)
    }

    /// The nonce a recorded probe carries, from the field its technique uses.
    fn token_of(technique: TcpScanTechnique, segment: &[u8]) -> TcpToken {
        let tcp = tcp::parse(segment).expect("probe is a TCP segment");
        TcpToken {
            nonce: match technique {
                TcpScanTechnique::Maimon | TcpScanTechnique::Ack | TcpScanTechnique::Window => {
                    tcp.acknowledgement()
                }
                _ => tcp.sequence(),
            },
        }
    }

    /// The token of the most recent probe.
    fn last_probe(technique: TcpScanTechnique, sent: &SentProbes) -> TcpToken {
        let sent = sent.lock().unwrap();
        let (segment, _, _) = sent.last().expect("a probe reached the wire");
        token_of(technique, segment)
    }

    fn port_state(session: &ScanSession, port: u16) -> Option<PortState> {
        session
            .hosts()
            .get(TARGET)
            .and_then(|h| h.ports().find(|p| p.number() == port).map(|p| p.state()))
    }

    /// The packet that settled a port is recorded, with the hop counter its header
    /// carried.
    #[test]
    fn an_answered_port_records_the_packet_that_settled_it() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 80);

        let reply = tcp_segment(&scanner, 80, token, SYN | ACK);
        scanner.handle_tcp_reply(&captured_with_ttl(reply, 58), Instant::now());

        let discovery = port_discovery(&session, 80).expect("the port carries its evidence");
        assert_eq!(discovery.reason(), &ScanResponse::TcpSynAck);
        assert_eq!(
            discovery.ttl(),
            Some(58),
            "the hop counter the reply arrived under was not kept"
        );
    }

    /// A scan sends from the transport's reply port, whatever `src_port` it was
    /// given, and reads the answers there. From any other port every answer would
    /// be filtered out and every open port would read as silent.
    #[test]
    fn a_scan_sends_from_the_port_its_transport_hears_replies_on() {
        const HEARD_ON: u16 = 43_210;
        assert_ne!(HEARD_ON, SRC_PORT);
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(8);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport = ProbeTransport::from_parts(Box::new(sender), reply_rx).opened_for(
            ProbeKind::TcpProbe {
                reply_port: HEARD_ON,
                icmp_errors: false,
            },
        );
        let resolver = SourceResolver::from_links(&[on_link_interface()]);
        let mut scanner = TcpPortScanner::with_transport(
            resolver,
            ctx,
            TcpScanTechnique::Syn,
            transport,
            8,
            SRC_PORT,
        );

        let token = probe(&mut scanner, &sent, 80);
        let (segment, _, _) = sent.lock().unwrap()[0].clone();
        let left_from = tcp::parse(&segment).expect("a TCP probe").source_port();
        assert_eq!(left_from, HEARD_ON);

        let reply = segment_to(80, HEARD_ON, scanner.technique, token, SYN | ACK);
        scanner.handle_tcp_reply(&captured_with_ttl(reply, 64), Instant::now());
        assert_eq!(port_state(&session, 80), Some(PortState::Open));
    }

    /// A transport opened for another kind of probe is refused: its capture admits
    /// none of the answers, so every port would falsely read `NoReply`. The scan
    /// explains why, sends nothing, and files every port it was handed as unasked.
    #[tokio::test]
    async fn a_transport_opened_for_another_kind_is_refused_rather_than_read_as_silence() {
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(8);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport = ProbeTransport::from_parts(Box::new(sender), reply_rx).opened_for(
            ProbeKind::UdpProbe {
                reply_port: SRC_PORT,
            },
        );
        let resolver = SourceResolver::from_links(&[on_link_interface()]);
        let mut scanner = TcpPortScanner::with_transport(
            resolver,
            ctx,
            TcpScanTechnique::Syn,
            transport,
            8,
            SRC_PORT,
        );

        let (targets, stream) = tokio::sync::mpsc::channel(8);
        for port in [22, 80] {
            targets
                .send(PlannedTarget::new(
                    u64::from(port),
                    Target {
                        ip: TARGET,
                        port,
                        protocol: Protocol::Tcp,
                    },
                ))
                .await
                .expect("the stream is open");
        }
        drop(targets);
        let refused = scanner.scan(stream).await;

        assert!(
            matches!(
                refused,
                Err(StrategyError::MismatchedTransport {
                    kind: ProbeKind::UdpProbe { .. },
                    protocol: Protocol::Tcp,
                })
            ),
            "{refused:?}"
        );
        assert_eq!(
            refused.expect_err("refused").to_string(),
            "a UDP probe transport cannot hear a TCP port scan's answers"
        );
        assert!(sent.lock().unwrap().is_empty(), "a probe was sent");
        assert_eq!(port_state(&session, 22), Some(PortState::Unasked));
        assert_eq!(port_state(&session, 80), Some(PortState::Unasked));
    }

    /// A reset is recorded as a reset.
    #[test]
    fn a_refused_port_records_the_reset_rather_than_a_silence() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 81);

        let reply = tcp_segment(&scanner, 81, token, RST | ACK);
        scanner.handle_tcp_reply(&captured_with_ttl(reply, 64), Instant::now());

        let discovery = port_discovery(&session, 81).expect("the port carries its evidence");
        assert_eq!(discovery.reason(), &ScanResponse::TcpRst);
        assert_eq!(discovery.ttl(), Some(64));
    }

    /// A synthetic reply has no IP header, so no hop counter is recorded.
    #[test]
    fn a_reply_with_no_header_behind_it_claims_no_hop_counter() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 80);

        let reply = tcp_segment(&scanner, 80, token, SYN | ACK);
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply),
            Instant::now(),
        );

        let discovery = port_discovery(&session, 80).expect("the port carries its evidence");
        assert_eq!(discovery.reason(), &ScanResponse::TcpSynAck);
        assert_eq!(discovery.ttl(), None);
    }

    /// A probe the sender refused leaves the port on the host as unasked. A link
    /// that stops accepting sends refuses every later probe too, and those ports
    /// would otherwise vanish from a host that looked cleanly scanned
    /// (`resolve_unasked` does the same for targets still queued).
    #[test]
    fn a_probe_the_sender_refused_leaves_the_port_unasked() {
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(1024);
        let transport = ProbeTransport::from_parts(Box::new(RefusingSender), reply_rx);
        let resolver = SourceResolver::from_links(&[on_link_interface()]);
        let mut scanner = TcpPortScanner::with_transport(
            resolver,
            ctx,
            TcpScanTechnique::Syn,
            transport,
            8,
            SRC_PORT,
        );

        scanner.send_probe(PlannedTarget::new(
            80,
            Target {
                ip: TARGET,
                port: 80,
                protocol: Protocol::Tcp,
            },
        ));

        assert_eq!(
            port_state(&session, 80),
            Some(PortState::Unasked),
            "a port whose probe never left this machine went missing from the host"
        );
        assert!(
            !scanner.core.ledger.contains(&(TARGET, 80)),
            "a probe that never went out must not be waiting for an answer"
        );
    }

    /// A probe the kernel refused for a neighbour hold-down is held through it and
    /// then sent, as is every later probe to that host, without first being put to
    /// the kernel. macOS refuses every write to a neighbour it gave up on for twenty
    /// seconds, which says nothing about the port.
    #[cfg(unix)]
    #[test]
    fn a_probe_refused_for_a_hold_down_is_sent_after_it() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        /// Refuses its first write as macOS does in a hold-down, then records.
        struct HeldDownOnce {
            writes: Arc<AtomicUsize>,
            sent: SentProbes,
        }
        impl crate::transport::probe::ProbeSender for HeldDownOnce {
            fn send(
                &self,
                segment: &[u8],
                src: IpAddr,
                dst: IpAddr,
                _zone: Option<u32>,
                _emission: Emission,
            ) -> Result<(), crate::transport::probe::SendError> {
                if self.writes.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(crate::transport::probe::SendError::from_io(
                        std::io::Error::from_raw_os_error(libc::EHOSTDOWN),
                    ));
                }
                self.sent.lock().unwrap().push((segment.to_vec(), src, dst));
                Ok(())
            }
        }

        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(1024);
        let writes = Arc::new(AtomicUsize::new(0));
        let sent: SentProbes = Arc::new(Mutex::new(Vec::new()));
        let sender = HeldDownOnce {
            writes: Arc::clone(&writes),
            sent: Arc::clone(&sent),
        };
        let transport = ProbeTransport::from_parts(Box::new(sender), reply_rx);
        let resolver = SourceResolver::from_links(&[on_link_interface()]);
        let mut scanner = TcpPortScanner::with_transport(
            resolver,
            ctx,
            TcpScanTechnique::Syn,
            transport,
            8,
            SRC_PORT,
        );
        let planned = |port: u16| {
            PlannedTarget::new(
                u64::from(port),
                Target {
                    ip: TARGET,
                    port,
                    protocol: Protocol::Tcp,
                },
            )
        };

        let before = Instant::now();
        scanner.send_probe(planned(80));
        scanner.send_probe(planned(81));

        assert_eq!(
            port_state(&session, 80),
            None,
            "the refused port was settled"
        );
        assert_eq!(scanner.core.held.len(), 2, "both probes are held");
        assert_eq!(
            writes.load(Ordering::SeqCst),
            1,
            "a probe behind the refused one was put to the kernel"
        );

        let after = before + scanner.core.held_down.hold_down_for + Duration::from_secs(1);
        while let Some(held) = scanner.core.take_ready(after) {
            scanner.send_held(held, after);
        }

        assert_eq!(
            sent.lock().unwrap().len(),
            2,
            "not sent after the hold-down"
        );
        assert!(scanner.core.ledger.contains(&(TARGET, 80)));
        assert!(scanner.core.ledger.contains(&(TARGET, 81)));
    }

    /// A port nothing answered records the silence as its evidence.
    #[test]
    fn an_unanswered_port_records_the_silence() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 80);

        scanner.record_port(TARGET, 80, PortState::NoReply, None);

        assert_eq!(port_state(&session, 80), Some(PortState::NoReply));

        let discovery = port_discovery(&session, 80).expect("the silence is evidence too");
        assert_eq!(discovery.reason(), &ScanResponse::NoResponse);
        assert_eq!(discovery.rtt(), None, "nothing arrived to be timed");
        assert_eq!(discovery.ttl(), None, "and nothing carried a hop count");
    }

    /// A refusal that arrived is recorded distinctly from a silence.
    #[test]
    fn a_refusal_is_not_recorded_as_a_silence() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 81);

        scanner.record_port(TARGET, 81, PortState::Blocked, Some(TARGET));

        let discovery = port_discovery(&session, 81).expect("the refusal is evidence");
        assert_eq!(discovery.reason(), &ScanResponse::IcmpProhibited);
    }

    /// A TCP reply carrying `bytes` under an IPv4 header with hop counter `ttl`.
    fn captured_with_ttl(bytes: Vec<u8>, ttl: u8) -> CapturedSegment {
        CapturedSegment {
            received_at: Instant::now(),
            source: TARGET,
            destination: None,
            protocol: IpNextHeaderProtocols::Tcp.0,
            bytes,
            observation: Some(IpObservation::V4(crate::model::capture::Ipv4Observation {
                ttl,
                identification: 0,
                dont_fragment: true,
                more_fragments: false,
                dscp: 0,
                ecn: 0,
            })),
            source_mac: None,
        }
    }

    /// A segment answering none of this scan's probes records no host. The capture
    /// delivers everything arriving at the source port, including other programs'
    /// traffic (typically loopback from a process that drew the same ephemeral
    /// port).
    #[test]
    fn a_segment_answering_no_probe_of_this_scan_records_no_host() {
        let (mut scanner, session, _sent) = scanner_with_mock();

        let stray = tcp_segment(&scanner, 443, TcpToken { nonce: 0 }, SYN | ACK);
        scanner.handle_tcp_reply(&captured_with_ttl(stray, 64), Instant::now());

        assert_eq!(
            session.hosts().len(),
            0,
            "a stray segment invented a host: {:?}",
            session.hosts().get(TARGET)
        );
    }

    /// One of this scan's own probes as a capture admitting both directions hands
    /// it back.
    fn own_probe_leaving(bytes: Vec<u8>) -> CapturedSegment {
        CapturedSegment {
            received_at: Instant::now(),
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            destination: Some(TARGET),
            protocol: IpNextHeaderProtocols::Tcp.0,
            bytes,
            observation: None,
            source_mac: None,
        }
    }

    /// The bytes of the probe the recording sender was last handed.
    fn last_sent(sent: &SentProbes) -> Vec<u8> {
        sent.lock().unwrap().last().expect("a probe").0.clone()
    }

    /// A probe seen on the wire is witnessed, and the port still waits for an
    /// answer.
    #[test]
    fn a_probe_seen_leaving_is_witnessed_against_its_own_attempt() {
        let (mut scanner, _session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 80);
        assert!(
            !scanner.core.audit.witnesses_its_sends(),
            "nothing has been seen yet"
        );

        scanner.handle_reply(&own_probe_leaving(last_sent(&sent)), Instant::now());

        assert_eq!(scanner.core.audit.sends_witnessed(), 1);
        assert!(
            scanner.core.ledger.contains(&(TARGET, 80)),
            "a sighting is not an answer, and must not settle the port"
        );
    }

    /// One frame captured on a bridge and its member underneath is one probe
    /// seen twice, counted once.
    #[test]
    fn the_same_probe_seen_twice_is_witnessed_once() {
        let (mut scanner, _session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 80);
        let frame = last_sent(&sent);

        scanner.handle_reply(&own_probe_leaving(frame.clone()), Instant::now());
        scanner.handle_reply(&own_probe_leaving(frame), Instant::now());

        assert_eq!(scanner.core.audit.sends_witnessed(), 1);
    }

    /// The probe of the scan's own source port (a full range asks it) is witnessed
    /// leaving, and its answer, between the same two ports, is read as the answer.
    #[test]
    fn the_probe_of_the_scans_own_port_is_witnessed_and_its_answer_read() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let own = scanner.core.src_port;
        let token = probe(&mut scanner, &sent, own);

        scanner.handle_reply(&own_probe_leaving(last_sent(&sent)), Instant::now());
        assert_eq!(scanner.core.audit.sends_witnessed(), 1);
        assert_eq!(scanner.core.audit.segments_off_target, 0);

        let answer = tcp_segment(&scanner, own, token, SYN | ACK);
        scanner.handle_reply(&captured_with_ttl(answer, 64), Instant::now());
        assert!(
            !scanner.core.ledger.contains(&(TARGET, own)),
            "the answer did not settle the port"
        );
        assert_eq!(
            session.hosts().get(TARGET).and_then(|host| host
                .ports()
                .find(|port| port.number() == own)
                .map(|port| port.state())),
            Some(PortState::Open)
        );
    }

    /// A segment on this scan's port carrying no live nonce is someone else's
    /// traffic, and witnesses nothing.
    #[test]
    fn a_stranger_on_the_scans_own_port_witnesses_nothing() {
        let (mut scanner, _session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 80);

        let mut frame = last_sent(&sent);
        // A different nonce.
        frame[4] ^= 0xFF;

        scanner.handle_reply(&own_probe_leaving(frame), Instant::now());

        assert_eq!(scanner.core.audit.sends_witnessed(), 0);
        assert_eq!(scanner.core.audit.segments_off_target, 0);
    }

    /// The evidence recorded against one of the target's ports.
    fn port_discovery(
        session: &ScanSession,
        port: u16,
    ) -> Option<crate::model::port::discovery::Discovery> {
        session
            .hosts()
            .get(TARGET)?
            .ports()
            .find_map(|probed| (probed.number() == port).then(|| probed.discovery().cloned()))?
    }

    #[test]
    fn syn_ack_matching_probe_is_open() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 80);

        let reply = tcp_segment(&scanner, 80, token, SYN | ACK);
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply.clone()),
            Instant::now(),
        );

        assert_eq!(port_state(&session, 80), Some(PortState::Open));
        assert!(!scanner.core.ledger.contains(&(TARGET, 80)));
    }

    #[test]
    fn rst_matching_probe_is_closed() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 81);

        let reply = tcp_segment(&scanner, 81, token, RST | ACK);
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply.clone()),
            Instant::now(),
        );

        assert_eq!(port_state(&session, 81), Some(PortState::Closed));
    }

    /// An arbitrary flag override reads reachable or open-or-no-reply, never the
    /// technique's open or closed. SYN+PSH occupies one sequence number like a SYN,
    /// so the harness's echo rule still resolves the answer.
    #[test]
    fn an_arbitrary_flag_combination_reads_reachable_not_open_or_closed() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Syn);
        scanner.flags_override = Some(SYN | PSH);

        let token = probe(&mut scanner, &sent, 80);
        let reply = tcp_segment(&scanner, 80, token, RST | ACK);
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply),
            Instant::now(),
        );

        assert_eq!(
            port_state(&session, 80),
            Some(PortState::Reachable),
            "a reply to an arbitrary combination proves only reachability"
        );
        assert_eq!(
            scanner.silence_means(),
            PortState::OpenOrNoReply,
            "and its silence is open or no reply, not a SYN's plain no reply"
        );
    }

    #[test]
    fn reply_carrying_the_wrong_nonce_is_ignored() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 82);

        // Acknowledges a value this scan never sent.
        let stray = TcpToken {
            nonce: token.nonce.wrapping_add(999),
        };
        let reply = tcp_segment(&scanner, 82, stray, SYN | ACK);
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply.clone()),
            Instant::now(),
        );

        assert_eq!(port_state(&session, 82), None);
        assert!(scanner.core.ledger.contains(&(TARGET, 82)));
    }

    /// A segment with the right nonce but addressed to another local port is
    /// someone else's traffic. A synthetic transport has no capture filter to drop
    /// it.
    #[test]
    fn reply_addressed_to_another_port_on_this_host_is_ignored() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 83);

        let elsewhere = scanner.core.src_port.wrapping_add(1);
        let reply = segment_to(83, elsewhere, scanner.technique, token, SYN | ACK);
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply.clone()),
            Instant::now(),
        );

        assert_eq!(port_state(&session, 83), None);
        assert!(scanner.core.ledger.contains(&(TARGET, 83)));
    }

    #[test]
    fn reply_for_unprobed_port_is_ignored() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 80);

        // Same host, unprobed port.
        let reply = tcp_segment(&scanner, 1234, token, SYN | ACK);
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply.clone()),
            Instant::now(),
        );

        assert_eq!(port_state(&session, 1234), None);
        assert!(scanner.core.ledger.contains(&(TARGET, 80)));
    }

    #[test]
    fn unanswered_probes_resolve_as_no_reply() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 443);

        super::super::run_out(&mut scanner);

        assert_eq!(port_state(&session, 443), Some(PortState::NoReply));
        assert!(scanner.core.ledger.is_empty());
    }

    // ── Techniques ─────────────────────────────────────────────────────────

    /// The same RST read according to the probe that drew it.
    #[test]
    fn a_rst_is_read_according_to_the_probe_that_drew_it() {
        for (technique, expected) in [
            (TcpScanTechnique::Syn, PortState::Closed),
            (TcpScanTechnique::Fin, PortState::Closed),
            (TcpScanTechnique::Null, PortState::Closed),
            (TcpScanTechnique::Xmas, PortState::Closed),
            (TcpScanTechnique::Maimon, PortState::Closed),
            (TcpScanTechnique::Ack, PortState::Reachable),
            // The helper's reset has a zero window, as for a closed port.
            (TcpScanTechnique::Window, PortState::Closed),
        ] {
            let (mut scanner, session, sent) = scanner_for(technique);
            let token = probe(&mut scanner, &sent, 80);

            let reply = tcp_segment(&scanner, 80, token, RST | ACK);
            scanner.handle_tcp_reply(
                &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply.clone()),
                Instant::now(),
            );

            assert_eq!(port_state(&session, 80), Some(expected), "{technique}");
        }
    }

    /// A RST proves the host is up, whichever probe drew it.
    #[test]
    fn a_rst_proves_the_host_is_up_whatever_it_says_about_the_port() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Fin);
        let token = probe(&mut scanner, &sent, 80);

        let reply = tcp_segment(&scanner, 80, token, RST | ACK);
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply.clone()),
            Instant::now(),
        );

        let host = session.hosts().get(TARGET).expect("host recorded");
        assert!(host.status().is_up());
    }

    /// A window scan reads a reset with a nonzero window as open, and credits the
    /// reset, not a handshake. The zero-window case is in the table above.
    #[test]
    fn a_window_scan_reads_an_open_port_out_of_a_reset() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Window);
        let token = probe(&mut scanner, &sent, 80);

        let mut reply = tcp_segment(&scanner, 80, token, RST | ACK);
        MutableTcpPacket::new(&mut reply)
            .expect("the reply is a TCP segment")
            .set_window(8192);
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply),
            Instant::now(),
        );

        assert_eq!(port_state(&session, 80), Some(PortState::Open));

        let host = session.hosts().get(TARGET).expect("host recorded");
        assert!(host.status().is_up());
        assert!(
            host.reasons().iter().all(|reason| reason
                .details
                .as_deref()
                .is_some_and(|details| details.contains("rst"))),
            "an open port drawn by a reset was credited to a handshake"
        );
    }

    /// Only a SYN provokes a SYN+ACK, so one arriving during a FIN scan resolves
    /// nothing.
    #[test]
    fn a_syn_ack_resolves_nothing_for_a_flag_probe() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Fin);
        let token = probe(&mut scanner, &sent, 80);

        let reply = tcp_segment(&scanner, 80, token, SYN | ACK);
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply.clone()),
            Instant::now(),
        );

        assert_eq!(port_state(&session, 80), None);
        assert!(scanner.core.ledger.contains(&(TARGET, 80)));
    }

    /// Any live stack answers a SYN or ACK; an open port must ignore a flag probe.
    #[test]
    fn silence_is_no_reply_or_open_or_no_reply_by_technique() {
        for (technique, expected) in [
            (TcpScanTechnique::Syn, PortState::NoReply),
            (TcpScanTechnique::Ack, PortState::NoReply),
            (TcpScanTechnique::Window, PortState::NoReply),
            (TcpScanTechnique::Fin, PortState::OpenOrNoReply),
            (TcpScanTechnique::Null, PortState::OpenOrNoReply),
            (TcpScanTechnique::Xmas, PortState::OpenOrNoReply),
            (TcpScanTechnique::Maimon, PortState::OpenOrNoReply),
        ] {
            let (mut scanner, session, sent) = scanner_for(technique);
            probe(&mut scanner, &sent, 443);

            super::super::run_out(&mut scanner);

            assert_eq!(port_state(&session, 443), Some(expected), "{technique}");
        }
    }

    /// Silence records nothing about the host, whichever verdict it produces.
    #[test]
    fn an_unanswered_probe_says_nothing_about_the_host() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Xmas);
        probe(&mut scanner, &sent, 443);

        super::super::run_out(&mut scanner);

        let host = session.hosts().get(TARGET).expect("the port was recorded");
        assert!(!host.status().is_up());
    }

    /// A flag-probe scan and a SYN scan report different strategies.
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

        CapturedSegment::synthetic(from, IpNextHeaderProtocols::Icmp.0, bytes)
    }

    /// The probe under the IP header a router would quote with it.
    fn quote(probe: &[u8]) -> Vec<u8> {
        let header = ip::build_ipv4_header(
            LOCAL,
            match TARGET {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => unreachable!("the fixture is v4"),
            },
            probe.len() as u16,
            IpNextHeaderProtocols::Tcp.0,
            ip::HOP_LIMIT_ROUTED,
        )
        .unwrap();
        header.into_iter().chain(probe.iter().copied()).collect()
    }

    /// The most recent probe exactly as it left, for an error to quote.
    fn last_probe_bytes(sent: &SentProbes) -> Vec<u8> {
        let sent = sent.lock().unwrap();
        sent.last().expect("a probe reached the wire").0.clone()
    }

    /// An ICMP port unreachable means closed for UDP, but no TCP stack emits one,
    /// so for a TCP probe it means the path rejected it: blocked.
    #[test]
    fn a_port_unreachable_about_a_tcp_probe_is_blocked_not_closed() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Fin);
        probe(&mut scanner, &sent, 80);

        let error = icmp_error_quoting(
            IcmpCodes::DestinationPortUnreachable,
            &last_probe_bytes(&sent),
            ROUTER,
        );
        scanner.handle_reply(&error, Instant::now());

        assert_eq!(port_state(&session, 80), Some(PortState::Blocked));
        assert!(scanner.core.ledger.is_empty());
    }

    /// An administrative prohibition gives a flag probe `Blocked`, which silence
    /// cannot; this is why those techniques read ICMP.
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

        assert_eq!(port_state(&session, 80), Some(PortState::Blocked));
        assert_ne!(port_state(&session, 80), Some(PortState::OpenOrNoReply));
    }

    /// A middlebox refusing on a host's behalf makes the host `Blocked`, not `Up`.
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

        let host = session.hosts().get(TARGET).expect("host recorded");
        assert_eq!(host.status(), HostStatus::Blocked);
    }

    /// The same message from the target itself proves it is up.
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

        let host = session.hosts().get(TARGET).expect("host recorded");
        assert!(host.status().is_up());
    }

    /// For an on-link address the kernel never resolves, the scan hands the kernel
    /// one probe per resolution (two), holds the rest until the kernel gives up,
    /// then reads every port unasked and the address unreached, with no failure.
    ///
    /// Runs the whole loop, since the point is what reaches the sender: Linux
    /// accepts and queues every write to a neighbour still resolving, so unheld
    /// probes never leave, read as silent ports, and their retries fill the send
    /// buffer for every other host.
    #[tokio::test]
    async fn a_neighbour_the_kernel_never_resolves_is_asked_twice_and_reported_unreached() {
        use crate::transport::kernel_neighbors::{KernelNeighbors, NeighborState, NeighborTable};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let reads = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&reads);
        // Resolving for two readings, then failed: the kernel's three requests a
        // second apart, sped up.
        let table = KernelNeighbors::with_reader(Box::new(move || {
            let state = match counted.fetch_add(1, Ordering::SeqCst) {
                0 | 1 => NeighborState::Resolving,
                _ => NeighborState::Failed,
            };
            Ok(NeighborTable::from([(TARGET, state)]))
        }));
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(1024);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport =
            ProbeTransport::from_parts(Box::new(sender), reply_rx).with_kernel_neighbors(table);
        let resolver = SourceResolver::from_links(&[on_link_interface()]);
        let mut scanner = TcpPortScanner::with_transport(
            resolver,
            ctx.clone(),
            TcpScanTechnique::Syn,
            transport,
            8,
            SRC_PORT,
        );

        let (targets, stream) = tokio::sync::mpsc::channel(32);
        for port in 1..=20u16 {
            targets
                .send(PlannedTarget::new(
                    u64::from(port),
                    Target {
                        ip: TARGET,
                        port,
                        protocol: Protocol::Tcp,
                    },
                ))
                .await
                .expect("the stream is open");
        }
        drop(targets);
        scanner.scan(stream).await.expect("the scan runs");

        assert_eq!(
            sent.lock().unwrap().len(),
            usize::from(NEIGHBOR_ROUNDS),
            "one probe went to the kernel for each resolution"
        );
        let host = session
            .hosts()
            .get(TARGET)
            .expect("the address is recorded");
        assert_eq!(host.ports().count(), 20, "every port is on the host");
        assert!(
            host.ports().all(|port| port.state() == PortState::Unasked),
            "no probe left, so no port was asked"
        );
        assert_eq!(
            ctx.take_unroutable(),
            vec![TARGET],
            "the address is unreached"
        );
        assert!(
            ctx.failures_snapshot().is_empty(),
            "and nothing failed here"
        );
    }

    /// A scan through a frame sender resolves every dead neighbour it meets at
    /// once, waits about one resolution for all of them and sends none of their
    /// probes, while a live neighbour behind them is asked everything.
    ///
    /// Resolving inside each send would cost one budget per dead address in turn
    /// (two hundred at half a second is a hundred seconds). Held while the
    /// resolutions run together, the wave costs one budget; the bound here allows
    /// ten.
    #[tokio::test]
    async fn dead_neighbours_behind_a_frame_sender_are_asked_for_together() {
        use crate::model::mac::MacAddr;
        use crate::system::interface::LinkAddress;
        use crate::transport::link::{ARP_TIMEOUT, Answers, LinkNeighbors, Segment};
        use crate::transport::neighbor::NeighborResolver;

        const LIVE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 60);
        const LIVE_PORTS: u16 = 3;
        let dead: Vec<IpAddr> = (101..=150)
            .map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
            .collect();

        let segment = NeighborResolver::on_segment(
            "sim0",
            MacAddr::new(0x02, 0, 0, 0, 0, 0x50),
            LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)), 24),
        );
        let neighbours = LinkNeighbors::simulated(segment, |_| {
            Segment::new().in_real_time().with(
                LIVE,
                MacAddr::new(0x02, 0, 0, 0, 0, 0x60),
                Answers::Request(1),
            )
        });
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(1024);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport =
            ProbeTransport::from_parts(Box::new(sender), reply_rx).with_link_neighbors(neighbours);
        let resolver = SourceResolver::from_links(&[on_link_interface()]);
        let targets_total = dead.len() + usize::from(LIVE_PORTS);
        let mut scanner = TcpPortScanner::with_transport(
            resolver,
            ctx.clone(),
            TcpScanTechnique::Syn,
            transport,
            targets_total,
            SRC_PORT,
        );

        let (targets, stream) = tokio::sync::mpsc::channel(targets_total);
        let plan = dead
            .iter()
            .map(|address| (*address, 80))
            .chain((1..=LIVE_PORTS).map(|port| (IpAddr::V4(LIVE), port)));
        for (position, (ip, port)) in plan.enumerate() {
            targets
                .send(PlannedTarget::new(
                    position as u64,
                    Target {
                        ip,
                        port,
                        protocol: Protocol::Tcp,
                    },
                ))
                .await
                .expect("the stream is open");
        }
        drop(targets);
        let started = Instant::now();
        scanner.scan(stream).await.expect("the scan runs");
        let took = started.elapsed();

        let sent = sent.lock().unwrap();
        assert!(
            sent.iter().all(|(_, _, dst)| *dst == IpAddr::V4(LIVE)),
            "a probe was handed to the sender for a neighbour nobody had resolved"
        );
        let live = session
            .hosts()
            .get(IpAddr::V4(LIVE))
            .expect("the live host is recorded");
        assert_eq!(live.ports().count(), usize::from(LIVE_PORTS));
        assert!(
            live.ports().all(|port| port.state() != PortState::Unasked),
            "the live host is asked every port"
        );
        let mut unreached = ctx.take_unroutable();
        unreached.sort();
        assert_eq!(unreached, dead, "every dead neighbour is unreached");
        assert!(
            ctx.failures_snapshot().is_empty(),
            "and nothing failed here"
        );
        assert!(
            session
                .hosts()
                .get(dead[0])
                .is_some_and(|host| host.ports().all(|port| port.state() == PortState::Unasked)),
            "a dead neighbour's port is recorded unasked"
        );
        assert!(
            took < ARP_TIMEOUT * 10,
            "{} dead neighbours held the scan for {took:?}",
            dead.len()
        );
    }

    /// A neighbour asleep through one whole resolution is asked again, and a host
    /// that answers the second has every port asked. A dozing interface or switch
    /// port, or a segment that dropped three broadcasts, must not cost a live host
    /// all its ports.
    #[tokio::test]
    async fn a_neighbour_asleep_through_one_resolution_is_asked_again() {
        use crate::model::mac::MacAddr;
        use crate::system::interface::LinkAddress;
        use crate::transport::link::{ARP_TIMEOUT, Answers, LinkNeighbors, Segment};
        use crate::transport::neighbor::NeighborResolver;

        const DOZING: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 61);
        const PORTS: u16 = 3;

        let segment = NeighborResolver::on_segment(
            "sim-doze1",
            MacAddr::new(0x02, 0, 0, 0, 0, 0x50),
            LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)), 24),
        );
        // Awake only after the first resolution is given up.
        let awake = Instant::now() + ARP_TIMEOUT + Duration::from_millis(500);
        let neighbours = LinkNeighbors::simulated(segment, move |_| {
            Segment::new().in_real_time().with(
                DOZING,
                MacAddr::new(0x02, 0, 0, 0, 0, 0x61),
                Answers::AwakeFrom(awake),
            )
        });
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(1024);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport =
            ProbeTransport::from_parts(Box::new(sender), reply_rx).with_link_neighbors(neighbours);
        let resolver = SourceResolver::from_links(&[on_link_interface()]);
        let mut scanner = TcpPortScanner::with_transport(
            resolver,
            ctx.clone(),
            TcpScanTechnique::Syn,
            transport,
            usize::from(PORTS),
            SRC_PORT,
        );

        let (targets, stream) = tokio::sync::mpsc::channel(usize::from(PORTS));
        for port in 1..=PORTS {
            targets
                .send(PlannedTarget::new(
                    u64::from(port),
                    Target {
                        ip: IpAddr::V4(DOZING),
                        port,
                        protocol: Protocol::Tcp,
                    },
                ))
                .await
                .expect("the stream is open");
        }
        drop(targets);
        scanner.scan(stream).await.expect("the scan runs");

        assert!(
            ctx.take_unroutable().is_empty(),
            "the host was filed unreachable on one unanswered resolution"
        );
        let asked: std::collections::HashSet<u16> = sent
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, _, dst)| *dst == IpAddr::V4(DOZING))
            .map(|(segment, _, _)| u16::from_be_bytes([segment[2], segment[3]]))
            .collect();
        assert_eq!(asked.len(), usize::from(PORTS), "every port was asked");
        let host = session
            .hosts()
            .get(IpAddr::V4(DOZING))
            .expect("the host is recorded");
        assert!(
            host.ports().all(|port| port.state() != PortState::Unasked),
            "a port of the host was left unasked"
        );
    }

    /// Under a rate ceiling, probes held on a resolution spend none of it, and a
    /// live host behind dead neighbours is asked every port.
    ///
    /// A held probe puts nothing on the wire. If it were charged a share, a few
    /// dead neighbours' ports, re-checked every few tens of milliseconds, would
    /// take every share a slow ceiling gives. The kernel here fails the dead
    /// neighbours only once the live host is fully asked, so a starving scan would
    /// wait to its deadline.
    #[tokio::test]
    async fn probes_held_on_a_resolution_spend_none_of_a_rate_ceiling() {
        use crate::transport::kernel_neighbors::{KernelNeighbors, NeighborState, NeighborTable};
        use std::sync::Arc;

        const LIVE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 60));
        const LIVE_PORTS: u16 = 10;
        let dead: Vec<IpAddr> = (101..106)
            .map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
            .collect();

        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let seen = Arc::clone(&sent);
        let neighbours = dead.clone();
        let table = KernelNeighbors::with_reader(Box::new(move || {
            let live_asked = seen
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, _, dst)| *dst == LIVE)
                .count();
            let state = if live_asked >= usize::from(LIVE_PORTS) {
                NeighborState::Failed
            } else {
                NeighborState::Resolving
            };
            Ok(neighbours
                .iter()
                .map(|address| (*address, state))
                .chain([(LIVE, NeighborState::Resolved)])
                .collect::<NeighborTable>())
        }));
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(1024);
        let transport =
            ProbeTransport::from_parts(Box::new(sender), reply_rx).with_kernel_neighbors(table);
        let resolver = SourceResolver::from_links(&[on_link_interface()]);
        let targets_total = dead.len() * 20 + usize::from(LIVE_PORTS);
        let mut scanner = TcpPortScanner::with_transport(
            resolver,
            ctx.clone(),
            TcpScanTechnique::Syn,
            transport,
            targets_total,
            SRC_PORT,
        );
        // A hundred probes a second: one a tick, a tick every ten milliseconds.
        scanner.core_mut().send_tick = Duration::from_millis(10);
        scanner.core_mut().batch = 1;

        let (targets, stream) = tokio::sync::mpsc::channel(targets_total);
        let plan = dead
            .iter()
            .flat_map(|address| (1..=20u16).map(move |port| (*address, port)))
            .chain((1..=LIVE_PORTS).map(|port| (LIVE, port)));
        for (position, (ip, port)) in plan.enumerate() {
            targets
                .send(PlannedTarget::new(
                    position as u64,
                    Target {
                        ip,
                        port,
                        protocol: Protocol::Tcp,
                    },
                ))
                .await
                .expect("the stream is open");
        }
        drop(targets);
        scanner.scan(stream).await.expect("the scan runs");

        let live = session
            .hosts()
            .get(LIVE)
            .expect("the live host is recorded");
        for port in live.ports() {
            assert_ne!(
                port.state(),
                PortState::Unasked,
                "the live host's port {} was never asked",
                port.number()
            );
        }
        let unreached = ctx.take_unroutable();
        for address in &dead {
            assert!(
                unreached.contains(address),
                "{address} is unreached: {unreached:?}"
            );
        }
        let to_dead = sent
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, _, dst)| dead.contains(dst))
            .count();
        assert_eq!(
            to_dead,
            dead.len() * usize::from(NEIGHBOR_ROUNDS),
            "one probe each started each resolution"
        );
    }

    /// Every address is asked before the deadline, however long the sender spends
    /// resolving dead ones. A frame sender blocks the loop for each resolution;
    /// the deadline allows for that wait, so queued addresses do not read unasked.
    #[tokio::test]
    async fn the_deadline_allows_for_the_time_the_sender_spends_resolving() {
        use std::sync::{Arc, Mutex};

        /// Waits out a resolution the first time it meets each address, then
        /// refuses as unresolved, like the frame path.
        struct Resolving {
            asked: Arc<Mutex<Vec<IpAddr>>>,
        }
        impl crate::transport::probe::ProbeSender for Resolving {
            fn send(
                &self,
                _segment: &[u8],
                _src: IpAddr,
                dst: IpAddr,
                _zone: Option<u32>,
                _emission: crate::transport::probe::Emission,
            ) -> Result<(), crate::transport::probe::SendError> {
                let first = {
                    let mut asked = self.asked.lock().unwrap();
                    let first = !asked.contains(&dst);
                    asked.push(dst);
                    first
                };
                if first {
                    std::thread::sleep(Duration::from_millis(500));
                }
                Err(crate::transport::probe::SendError::Unresolved(format!(
                    "{dst} did not answer address resolution"
                )))
            }
        }

        let dead: Vec<IpAddr> = (101..111)
            .map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
            .collect();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let (_session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(1024);
        let transport = ProbeTransport::from_parts(
            Box::new(Resolving {
                asked: Arc::clone(&asked),
            }),
            reply_rx,
        );
        let resolver = SourceResolver::from_links(&[on_link_interface()]);
        let mut scanner = TcpPortScanner::with_transport(
            resolver,
            ctx.clone(),
            TcpScanTechnique::Syn,
            transport,
            8,
            SRC_PORT,
        );

        // Twenty ports per address, address by address, as a range plan orders them.
        let (targets, stream) = tokio::sync::mpsc::channel(256);
        for (host, ip) in dead.iter().enumerate() {
            for port in 1..=20u16 {
                targets
                    .send(PlannedTarget::new(
                        (host * 20 + usize::from(port)) as u64,
                        Target {
                            ip: *ip,
                            port,
                            protocol: Protocol::Tcp,
                        },
                    ))
                    .await
                    .expect("the stream is open");
            }
        }
        drop(targets);
        scanner.scan(stream).await.expect("the scan runs");

        let asked = asked.lock().unwrap();
        for ip in &dead {
            assert!(asked.contains(ip), "{ip} was never asked");
        }
        assert_eq!(ctx.take_unroutable(), dead, "every address is unreached");
    }

    /// A host unreachable is about the address, not the quoted port, so the probe
    /// keeps its remaining attempts.
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
        assert!(scanner.core.ledger.contains(&(TARGET, 80)));
        assert_eq!(
            session.hosts().get(TARGET).map(|host| host.status()),
            Some(HostStatus::Down)
        );
    }

    /// An error quoting a datagram this scan never sent resolves nothing. An ICMP
    /// capture filter cannot narrow on ports, so the quoted source port is the
    /// only check.
    #[test]
    fn an_error_quoting_somebody_elses_probe_is_ignored() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Fin);
        probe(&mut scanner, &sent, 80);

        // Sent from a port this scan never used.
        let theirs = tcp::build_probe(
            TcpScanTechnique::Fin,
            LOCAL_IP,
            TARGET,
            scanner.core.src_port.wrapping_add(1),
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
        assert!(scanner.core.ledger.contains(&(TARGET, 80)));
    }

    /// A truncated stray error resolves nothing and does not panic. A SYN scan does
    /// not ask for ICMP, but a shared interface can deliver some anyway.
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
        assert!(scanner.core.ledger.contains(&(TARGET, 80)));
    }

    #[test]
    fn non_tcp_targets_are_not_probed() {
        let (mut scanner, _session, _sent) = scanner_with_mock();
        scanner.send_probe(PlannedTarget::new(
            0,
            Target {
                ip: TARGET,
                port: 53,
                protocol: Protocol::Udp,
            },
        ));
        assert!(scanner.core.ledger.is_empty());
    }

    // ── Retransmission ─────────────────────────────────────────────────────

    /// An unanswered probe goes out again, and the port stays undecided meanwhile.
    #[test]
    fn an_unanswered_probe_is_sent_again() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 80);

        super::super::retry_due(&mut scanner, Instant::now() + Duration::from_secs(1));

        assert_eq!(sent.lock().unwrap().len(), 2, "the probe was not retried");
        assert!(scanner.core.ledger.contains(&(TARGET, 80)));
        assert_eq!(port_state(&session, 80), None, "no verdict has been earned");
    }

    /// A port whose probes were never seen leaving is unasked, not `NoReply`.
    #[test]
    fn a_port_whose_probes_were_never_seen_leaving_is_unasked_not_no_reply() {
        let (mut scanner, session, sent) = scanner_with_mock();

        // One port witnessed leaving, so the run sees its egress; the other not.
        probe(&mut scanner, &sent, 80);
        scanner.handle_reply(&own_probe_leaving(last_sent(&sent)), Instant::now());
        probe(&mut scanner, &sent, 443);

        let mut now = Instant::now();
        for _ in 0..PORT_RETRY_POLICY.max_attempts + 2 {
            now += Duration::from_secs(4);
            super::super::retry_due(&mut scanner, now);
        }

        assert_eq!(
            port_state(&session, 443),
            Some(PortState::Unasked),
            "silence from a probe nobody saw leave is not a verdict"
        );
        assert_eq!(
            port_state(&session, 80),
            Some(PortState::NoReply),
            "and a probe that was watched leaving still earns one"
        );
    }

    /// A scan that witnesses no egress reads silence as `NoReply`.
    #[test]
    fn a_scan_that_witnesses_nothing_reads_silence_as_it_always_did() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 443);
        assert!(!scanner.core.audit.witnesses_its_sends(), "test premise");

        let mut now = Instant::now();
        for _ in 0..PORT_RETRY_POLICY.max_attempts + 2 {
            now += Duration::from_secs(4);
            super::super::retry_due(&mut scanner, now);
        }

        assert_eq!(port_state(&session, 443), Some(PortState::NoReply));
    }

    /// `NoReply` takes the whole attempt budget.
    #[test]
    fn a_port_reads_no_reply_only_once_every_attempt_is_spent() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 80);

        let mut now = Instant::now();
        for _ in 0..PORT_RETRY_POLICY.max_attempts + 2 {
            now += Duration::from_secs(4);
            super::super::retry_due(&mut scanner, now);
        }

        assert_eq!(port_state(&session, 80), Some(PortState::NoReply));
        assert_eq!(
            sent.lock().unwrap().len(),
            usize::from(PORT_RETRY_POLICY.max_attempts),
        );
        assert!(scanner.core.ledger.is_empty());
    }

    /// An answered probe is not resent.
    #[test]
    fn an_answered_probe_is_never_retried() {
        let (mut scanner, _session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 80);
        let reply = tcp_segment(&scanner, 80, token, SYN | ACK);
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply.clone()),
            Instant::now(),
        );

        super::super::retry_due(&mut scanner, Instant::now() + Duration::from_secs(10));

        assert_eq!(sent.lock().unwrap().len(), 1);
    }

    /// A retry waiting out the per-host probe interval when a late answer settles
    /// its probe is never sent and takes no window slot. A slot taken by such a
    /// send would never be returned; enough of them and the scan stops admitting
    /// targets and idles to its deadline.
    #[test]
    fn a_retry_overtaken_by_a_late_answer_is_never_sent() {
        let (session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(Duration::from_secs(3600)))
            .build();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(1024);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport = ProbeTransport::from_parts(Box::new(sender), reply_rx);
        let resolver = SourceResolver::from_links(&[on_link_interface()]);
        let mut scanner = TcpPortScanner::with_transport(
            resolver,
            ctx,
            TcpScanTechnique::Syn,
            transport,
            8,
            SRC_PORT,
        );

        let first = probe(&mut scanner, &sent, 80);
        super::super::retry_due(&mut scanner, Instant::now() + Duration::from_secs(1));
        assert_eq!(sent.lock().unwrap().len(), 1, "the retry waits for the gap");

        let reply = tcp_segment(&scanner, 80, first, SYN | ACK);
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply),
            Instant::now(),
        );
        super::super::retry_due(&mut scanner, Instant::now() + Duration::from_secs(7200));

        assert_eq!(
            sent.lock().unwrap().len(),
            1,
            "a retry went out for a port already answered"
        );
        assert_eq!(scanner.core.window.in_flight(), 0, "a window slot leaked");
        assert_eq!(port_state(&session, 80), Some(PortState::Open));
    }

    /// A send with no plan position takes no window slot, whether or not its
    /// probe is still on the ledger. Drives `send` directly, since the loop never
    /// sends such a retry (the previous test).
    #[test]
    fn a_send_without_a_plan_position_never_takes_a_window_slot() {
        let (mut scanner, _session, sent) = scanner_with_mock();

        scanner.send(TARGET, 80, None, Instant::now());

        assert_eq!(sent.lock().unwrap().len(), 1, "test premise: it left");
        assert_eq!(
            scanner.core.window.in_flight(),
            0,
            "a retry took a window slot"
        );
    }

    /// Each attempt carries its own nonce, so a reply to the first that arrives
    /// after the second went out still resolves the port.
    #[test]
    fn a_reply_to_a_superseded_attempt_still_resolves_the_port() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let first = probe(&mut scanner, &sent, 80);

        super::super::retry_due(&mut scanner, Instant::now() + Duration::from_secs(1));
        let second = last_probe(scanner.technique, &sent);
        assert_ne!(
            first.nonce, second.nonce,
            "each attempt needs its own identity"
        );

        let reply = tcp_segment(&scanner, 80, first, SYN | ACK);
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply.clone()),
            Instant::now(),
        );

        assert_eq!(port_state(&session, 80), Some(PortState::Open));
    }

    /// Every attempt leaves from the port the capture filter was built around, so
    /// a retry's answer arrives where the scan listens.
    #[test]
    fn every_attempt_leaves_from_the_scans_own_port() {
        let (mut scanner, _session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 80);
        super::super::retry_due(&mut scanner, Instant::now() + Duration::from_secs(1));

        let ports: Vec<u16> = sent
            .lock()
            .unwrap()
            .iter()
            .map(|(segment, _, _)| tcp::parse(segment).unwrap().source_port())
            .collect();

        assert_eq!(ports.len(), 2, "the probe was not retried");
        assert!(
            ports.iter().all(|port| *port == scanner.core.src_port),
            "probes left from {ports:?}, not from {}",
            scanner.core.src_port
        );
    }

    /// A duplicate answer finds nothing outstanding and is dropped.
    #[test]
    fn a_duplicate_reply_resolves_nothing_further() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let token = probe(&mut scanner, &sent, 80);

        let reply = tcp_segment(&scanner, 80, token, SYN | ACK);
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply.clone()),
            Instant::now(),
        );
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply.clone()),
            Instant::now(),
        );

        let host = session.hosts().get(TARGET).expect("host recorded");
        assert_eq!(host.ports().filter(|p| p.number() == 80).count(), 1);
    }

    /// The scan budget outlasts a probe's whole retry schedule.
    #[test]
    fn the_scan_budget_covers_the_whole_retry_schedule() {
        let lifetime = PORT_RETRY_POLICY.worst_case_probe_lifetime();
        let budget = crate::scanner::strategy::raw::DEADLINE_CONFIG
            .allowing_for(lifetime)
            .max_budget
            .for_target_count(1);

        assert!(
            budget > lifetime,
            "a {budget:?} scan cannot finish a {lifetime:?} probe"
        );
    }

    /// A path that logs when each probe left and, given a delay, answers every SYN
    /// with a SYN+ACK that long after. Without a delay it answers nothing, like a
    /// filter.
    struct Path {
        answer_after: Option<Duration>,
        /// The hosts that answer; empty means all.
        live: Vec<IpAddr>,
        replies: mpsc::Sender<CapturedSegment>,
        sent: std::sync::Arc<std::sync::Mutex<Vec<(u16, Instant)>>>,
    }

    impl ProbeSender for Path {
        fn send(
            &self,
            segment: &[u8],
            _src: IpAddr,
            dst: IpAddr,
            _zone: Option<u32>,
            _emission: Emission,
        ) -> Result<(), SendError> {
            let probe = tcp::parse(segment).expect("the scan sends whole segments");
            self.sent
                .lock()
                .unwrap()
                .push((probe.destination_port(), Instant::now()));
            let Some(delay) = self.answer_after else {
                return Ok(());
            };
            if !self.live.is_empty() && !self.live.contains(&dst) {
                return Ok(());
            }
            let reply = segment_to(
                probe.destination_port(),
                probe.source_port(),
                TcpScanTechnique::Syn,
                TcpToken {
                    nonce: probe.sequence(),
                },
                SYN | ACK,
            );
            let replies = self.replies.clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                // Stamped on arrival, as a capture stamps it.
                let arrived = CapturedSegment::synthetic(dst, IpNextHeaderProtocols::Tcp.0, reply);
                let _ = replies.send(arrived).await;
            });
            Ok(())
        }
    }

    /// A path that answers every SYN at once, then blocks the sending thread for
    /// `stall`, so the loop resumes with the answer already waiting.
    struct StalledAfterAnswering {
        stall: Duration,
        replies: mpsc::Sender<CapturedSegment>,
    }

    impl ProbeSender for StalledAfterAnswering {
        fn send(
            &self,
            segment: &[u8],
            _src: IpAddr,
            dst: IpAddr,
            _zone: Option<u32>,
            _emission: Emission,
        ) -> Result<(), SendError> {
            let probe = tcp::parse(segment).expect("the scan sends whole segments");
            let reply = segment_to(
                probe.destination_port(),
                probe.source_port(),
                TcpScanTechnique::Syn,
                TcpToken {
                    nonce: probe.sequence(),
                },
                SYN | ACK,
            );
            self.replies
                .try_send(CapturedSegment::synthetic(
                    dst,
                    IpNextHeaderProtocols::Tcp.0,
                    reply,
                ))
                .expect("room for the answer");
            std::thread::sleep(self.stall);
            Ok(())
        }
    }

    /// An answer waiting before its probe's timer came due settles the port,
    /// however late the loop gets to either. A loop stalled past a timeout (slow
    /// send, starved runtime) wakes to both; servicing the timer first would file
    /// an open port `NoReply` with one attempt. The answer here arrives within
    /// microseconds, so only the order can make it late.
    #[tokio::test]
    async fn an_answer_waiting_when_its_probe_times_out_still_settles_the_port() {
        let (session, ctx) = ScanSession::new();
        let (replies, reply_rx) = mpsc::channel(16);
        // Longer than the longest first timeout an unmeasured host can draw.
        let first_timeout = PORT_RETRY_POLICY
            .initial_rto
            .mul_f64(1.0 + PORT_RETRY_POLICY.jitter);
        let stall = first_timeout + Duration::from_millis(200);
        let transport = ProbeTransport::from_parts(
            Box::new(StalledAfterAnswering { stall, replies }),
            reply_rx,
        );
        let mut tuning = ProbeTuning::default();
        tuning.retry.max_attempts = std::num::NonZeroU8::new(1);
        let mut scanner = TcpPortScanner::with_transport_tuned(
            SourceResolver::from_links(&[on_link_interface()]),
            ctx,
            TcpScanTechnique::Syn,
            transport,
            1,
            SRC_PORT,
            tuning,
        );

        let (queue, stream) = mpsc::channel(1);
        queue
            .send(PlannedTarget::new(
                0,
                Target {
                    ip: TARGET,
                    port: 80,
                    protocol: Protocol::Tcp,
                },
            ))
            .await
            .expect("the stream is open");
        drop(queue);
        scanner.scan(stream).await.expect("the scan runs");

        assert_eq!(port_state(&session, 80), Some(PortState::Open));
    }

    /// When each probe left, and to which port.
    type Departures = std::sync::Arc<std::sync::Mutex<Vec<(u16, Instant)>>>;

    /// Runs a SYN scan built from `tuning` over `ports` ports of [`TARGET`] through
    /// a [`Path`], returning the session and each probe's departure.
    async fn scan_over_path(
        tuning: &ProbeTuning,
        answer_after: Option<Duration>,
        ports: u16,
    ) -> (ScanSession, Departures) {
        let targets = (1..=ports).map(|port| (TARGET, port)).collect();
        scan_targets_over_path(tuning, answer_after, Vec::new(), targets).await
    }

    /// [`scan_over_path`] of `targets`, with only the hosts in `live` answering
    /// (all when empty).
    async fn scan_targets_over_path(
        tuning: &ProbeTuning,
        answer_after: Option<Duration>,
        live: Vec<IpAddr>,
        targets: Vec<(IpAddr, u16)>,
    ) -> (ScanSession, Departures) {
        let (session, ctx) = ScanSession::new();
        let (replies, reply_rx) = mpsc::channel(4096);
        let sent = Departures::default();
        let path = Path {
            answer_after,
            live,
            replies,
            sent: std::sync::Arc::clone(&sent),
        };
        let transport = ProbeTransport::from_parts(Box::new(path), reply_rx);
        let resolver = SourceResolver::from_links(&[on_link_interface()]);
        let core = TcpPortScanner::core(resolver, ctx, transport, tuning, 54_321, targets.len());
        let mut scanner = TcpPortScanner::build(
            core,
            TcpScanTechnique::Syn,
            None,
            OsDetection::default(),
            ServiceDetection::default(),
        );

        let (queue, stream) = mpsc::channel(targets.len().max(1));
        for (position, (ip, port)) in targets.into_iter().enumerate() {
            queue
                .send(PlannedTarget::new(
                    position as u64,
                    Target {
                        ip,
                        port,
                        protocol: Protocol::Tcp,
                    },
                ))
                .await
                .expect("the stream is open");
        }
        drop(queue);
        scanner.scan(stream).await.expect("the scan runs");
        (session, sent)
    }

    /// The most probes in `sent` that left within one second of any one of them.
    fn busiest_second(sent: &Departures) -> usize {
        let departures: Vec<Instant> = sent.lock().unwrap().iter().map(|(_, at)| *at).collect();
        departures
            .iter()
            .map(|start| {
                departures
                    .iter()
                    .filter(|at| **at >= *start && **at < *start + Duration::from_secs(1))
                    .count()
            })
            .max()
            .unwrap_or(0)
    }

    /// A scan held to a rate ceiling asks every port, however long the ceiling
    /// makes it take. At a hundred probes a second, a few hundred ports outrun any
    /// budget sized for an unlimited scan. One attempt per probe, so only the rate
    /// stretches the budget.
    ///
    /// Asserts every port was asked, not what each answered: with one attempt in
    /// real time, a runner stalling past a timeout can read an open port `NoReply`.
    #[tokio::test]
    async fn a_rate_limited_scan_asks_every_port_however_long_the_ceiling_makes_it() {
        const PORTS: u16 = 300;
        let tuning = ProbeTuning {
            max_probe_rate: std::num::NonZeroU32::new(100),
            retry: crate::config::RetryConfig {
                max_attempts: std::num::NonZeroU8::new(1),
                ..crate::config::RetryConfig::default()
            },
            ..ProbeTuning::default()
        };

        // Well inside the shortest timeout.
        let (session, _sent) = scan_over_path(&tuning, Some(Duration::from_millis(5)), PORTS).await;

        let host = session.hosts().get(TARGET).expect("the target answered");
        let unasked: Vec<u16> = host
            .ports()
            .filter(|port| port.state() == PortState::Unasked)
            .map(|port| port.number())
            .collect();
        assert!(
            unasked.is_empty(),
            "{} of {PORTS} ports never asked, first {:?}",
            unasked.len(),
            unasked.first()
        );
        assert_eq!(host.ports().count(), usize::from(PORTS));
        assert!(
            host.ports().any(|port| port.state() == PortState::Open),
            "the path answered nothing, so the scan proved nothing"
        );
    }

    /// A two-port scan of a mostly empty range under a low rate ceiling finds the
    /// live hosts, asks every address every port and keeps to the ceiling.
    ///
    /// With the port probes standing in for the liveness pass, nothing has timed
    /// the hosts and most addresses use their whole retry budget, so the scan is
    /// slow; the deadline and retries must both respect the ceiling.
    #[tokio::test]
    async fn a_rate_limited_scan_of_a_range_finds_its_hosts_and_asks_every_address() {
        const RATE: u32 = 40;
        let addresses: Vec<IpAddr> = (100..140)
            .map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
            .collect();
        let live = vec![addresses[7], addresses[31]];
        let targets: Vec<(IpAddr, u16)> = addresses
            .iter()
            .flat_map(|ip| [(*ip, 22), (*ip, 80)])
            .collect();
        let tuning = ProbeTuning {
            max_probe_rate: std::num::NonZeroU32::new(RATE),
            ..ProbeTuning::default()
        };

        let (session, sent) = scan_targets_over_path(
            &tuning,
            Some(Duration::from_millis(5)),
            live.clone(),
            targets,
        )
        .await;

        for ip in &addresses {
            let host = session.hosts().get(*ip).expect("every address was asked");
            let expected = if live.contains(ip) {
                PortState::Open
            } else {
                PortState::NoReply
            };
            for port in host.ports() {
                assert_eq!(port.state(), expected, "{ip}:{}", port.number());
            }
            assert_eq!(host.ports().count(), 2, "{ip}");
            assert_eq!(host.status().is_up(), live.contains(ip), "{ip}");
        }
        let busiest = busiest_second(&sent);
        assert!(
            busiest <= RATE as usize + 2,
            "{busiest} probes left in one second under a ceiling of {RATE}"
        );
    }

    /// A scan built from the largest accepted attempt budget and timeout scale
    /// runs. Both feed the deadline arithmetic at build time, which must not
    /// overflow.
    #[tokio::test]
    async fn a_scan_built_from_the_largest_accepted_retry_settings_runs() {
        let tuning = ProbeTuning {
            retry: crate::config::RetryConfig {
                max_attempts: std::num::NonZeroU8::new(u8::MAX),
                timeout_scale: crate::config::TimeoutScale::new(f64::MAX),
                ..crate::config::RetryConfig::default()
            },
            ..ProbeTuning::default()
        };

        let (session, _sent) = scan_over_path(&tuning, Some(Duration::from_millis(1)), 3).await;

        let host = session.hosts().get(TARGET).expect("the target answered");
        assert!(host.ports().all(|port| port.state() == PortState::Open));
    }

    /// A host the scan heard from carries the reply's round trip. Without a
    /// liveness pass this is the only latency measure, as the handshake's is for a
    /// connect scan.
    #[tokio::test]
    async fn a_host_that_answered_is_credited_its_round_trip() {
        let (session, _sent) =
            scan_over_path(&ProbeTuning::default(), Some(Duration::from_millis(5)), 3).await;

        let host = session.hosts().get(TARGET).expect("the target answered");
        assert_eq!(host.rtt_protocol(), Some(StatusProtocol::TcpSyn));
        assert!(
            host.median_rtt()
                .is_some_and(|rtt| rtt >= Duration::from_millis(5)),
            "{:?}",
            host.median_rtt()
        );
    }

    /// A rate ceiling bounds every packet on the wire, retries included. Against a
    /// silent host every probe uses its whole budget; no second may carry more
    /// than the ceiling, give or take the tick a one-second window can straddle.
    #[tokio::test]
    async fn a_rate_ceiling_holds_retries_to_it_as_well() {
        const PORTS: u16 = 100;
        const RATE: u32 = 100;
        // Every port at its full budget, so the count below is exact.
        let tuning = ProbeTuning {
            max_probe_rate: std::num::NonZeroU32::new(RATE),
            retry: crate::config::RetryConfig {
                dampen_silent_hosts: false,
                ..crate::config::RetryConfig::default()
            },
            ..ProbeTuning::default()
        };

        let (session, sent) = scan_over_path(&tuning, None, PORTS).await;

        let attempts = usize::from(PORT_RETRY_POLICY.max_attempts);
        assert_eq!(
            sent.lock().unwrap().len(),
            usize::from(PORTS) * attempts,
            "every port asked as often as its budget allows"
        );
        let busiest = busiest_second(&sent);
        assert!(
            busiest <= RATE as usize + 2,
            "{busiest} probes left in one second under a ceiling of {RATE}"
        );
        let host = session.hosts().get(TARGET).expect("the ports are recorded");
        assert!(host.ports().all(|port| port.state() == PortState::NoReply));
    }

    /// A hand-built ICMP host unreachable with the quoted destination, ports and
    /// quoted header length of the caller's choosing.
    fn forged_host_unreachable(
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        header_bytes: usize,
    ) -> CapturedSegment {
        let mut tcp_header = vec![0u8; 20];
        tcp_header[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp_header[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp_header[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        tcp_header.truncate(header_bytes);

        let ip_header = ip::build_ipv4_header(
            LOCAL,
            dst,
            tcp_header.len() as u16,
            IpNextHeaderProtocols::Tcp.0,
            ip::HOP_LIMIT_ROUTED,
        )
        .expect("an IPv4 header");
        let quotation: Vec<u8> = ip_header.into_iter().chain(tcp_header).collect();

        let mut bytes =
            vec![0u8; DestinationUnreachablePacket::minimum_packet_size() + quotation.len()];
        let mut packet =
            MutableDestinationUnreachablePacket::new(&mut bytes).expect("an ICMP buffer");
        packet.set_icmp_type(IcmpTypes::DestinationUnreachable);
        packet.set_icmp_code(IcmpCodes::DestinationHostUnreachable);
        packet.set_payload(&quotation);

        CapturedSegment::synthetic(ROUTER, IpNextHeaderProtocols::Icmp.0, bytes)
    }

    const TARGET_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 200);

    /// An unreachable naming an address this scan never probed records no host.
    /// `write_host` creates whatever record it is handed.
    #[test]
    fn an_unreachable_naming_an_unprobed_address_records_no_host() {
        let (mut scanner, session, _sent) = scanner_for(TcpScanTechnique::Fin);
        let never = Ipv4Addr::new(203, 0, 113, 77);
        let src = scanner.core.src_port;

        scanner.handle_reply(&forged_host_unreachable(never, src, 443, 8), Instant::now());

        assert_eq!(session.hosts().len(), 0, "no host may be invented");
        assert!(session.hosts().get(IpAddr::V4(never)).is_none());
    }

    /// A probed host is not filed down by an error quoting an unprobed port.
    /// `Unknown` means nothing was heard; `Down` means an intermediary answered for
    /// the address. A host that silently drops traffic is the former.
    #[test]
    fn an_unreachable_quoting_an_unprobed_port_does_not_file_the_host_down() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Fin);
        probe(&mut scanner, &sent, 80);
        let src = scanner.core.src_port;

        scanner.handle_reply(
            &forged_host_unreachable(TARGET_V4, src, 9999, 8),
            Instant::now(),
        );

        assert_ne!(
            session.hosts().get(TARGET).map(|host| host.status()),
            Some(HostStatus::Down),
            "port 9999 was never probed, so this error is about nothing this scan sent"
        );
    }

    /// A host proved up keeps its status and does not collect an unattributable
    /// unreachable as a reason.
    #[test]
    fn a_live_host_does_not_collect_a_forged_unreachable_as_a_reason() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Fin);
        let token = probe(&mut scanner, &sent, 80);
        let rst = tcp_segment(&scanner, 80, token, RST | ACK);
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, rst),
            Instant::now(),
        );

        let before = session
            .hosts()
            .get(TARGET)
            .map(|host| host.reasons().len())
            .expect("the host answered");
        let src = scanner.core.src_port;

        scanner.handle_reply(
            &forged_host_unreachable(TARGET_V4, src, 80, 8),
            Instant::now(),
        );

        let host = session.hosts().get(TARGET).expect("still recorded");
        assert!(host.status().is_up(), "the promotion rule holds");
        assert_eq!(
            host.reasons().len(),
            before,
            "an unreachable this scan cannot attribute adds no evidence"
        );
    }

    /// A router quoting a probe that really went out still files the host down.
    #[test]
    fn an_unreachable_quoting_a_real_probe_still_files_the_host_down() {
        let (mut scanner, session, sent) = scanner_for(TcpScanTechnique::Fin);
        probe(&mut scanner, &sent, 80);

        let error = icmp_error_quoting(
            IcmpCodes::DestinationHostUnreachable,
            &last_probe_bytes(&sent),
            ROUTER,
        );
        scanner.handle_reply(&error, Instant::now());

        assert_eq!(
            session.hosts().get(TARGET).map(|host| host.status()),
            Some(HostStatus::Down)
        );
        assert!(
            scanner.core.ledger.contains(&(TARGET, 80)),
            "and the port keeps its remaining attempts"
        );
    }

    /// A refusal that cannot name the attempt retires nothing. The acknowledgement
    /// field sits at offset eight, past what RFC 792 guarantees an error quotes, so
    /// a minimal quote names an ack-field technique's probe by its ports alone.
    #[test]
    fn a_refusal_quoting_too_little_to_name_the_attempt_resolves_no_port() {
        for technique in [
            TcpScanTechnique::Ack,
            TcpScanTechnique::Window,
            TcpScanTechnique::Maimon,
        ] {
            let (mut scanner, session, sent) = scanner_for(technique);
            probe(&mut scanner, &sent, 80);

            // The probe cut to the guaranteed eight bytes.
            let whole = last_probe_bytes(&sent);
            let error = icmp_error_quoting(
                IcmpCodes::CommunicationAdministrativelyProhibited,
                &whole[..8],
                ROUTER,
            );
            scanner.handle_reply(&error, Instant::now());

            assert_eq!(
                port_state(&session, 80),
                None,
                "{technique:?}: an eight-byte quotation named no attempt"
            );
            assert!(
                scanner.core.ledger.contains(&(TARGET, 80)),
                "{technique:?}: and the probe keeps its remaining attempts"
            );
            assert_eq!(
                scanner.core.audit.refusals_unattributed, 1,
                "{technique:?}: but the refusal is counted as heard"
            );
        }
    }

    /// The four techniques with the nonce in the sequence number still resolve on
    /// a minimal quotation.
    #[test]
    fn a_sequence_nonce_technique_still_resolves_on_the_guaranteed_eight() {
        for technique in [
            TcpScanTechnique::Syn,
            TcpScanTechnique::Fin,
            TcpScanTechnique::Null,
            TcpScanTechnique::Xmas,
        ] {
            let (mut scanner, session, sent) = scanner_for(technique);
            probe(&mut scanner, &sent, 80);

            let whole = last_probe_bytes(&sent);
            let error = icmp_error_quoting(
                IcmpCodes::CommunicationAdministrativelyProhibited,
                &whole[..8],
                ROUTER,
            );
            scanner.handle_reply(&error, Instant::now());

            assert_eq!(
                port_state(&session, 80),
                Some(PortState::Blocked),
                "{technique:?}: the sequence number is inside the guaranteed eight"
            );
            assert_eq!(scanner.core.audit.refusals_unattributed, 0);
        }
    }
}
