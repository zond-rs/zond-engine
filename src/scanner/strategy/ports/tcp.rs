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
//! [`crate::scanner::strategy::connect`] must.
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
//! `icmp_error`.

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

// Port scanning and routed discovery send the same kind of raw TCP probe over
// the same kind of network path, so they share one adaptive-deadline profile
// rather than keeping two copies in step. They do *not* share a retry schedule:
// a sweep's probes are lost to what the path is doing, and a port scan's to the
// burst it is itself making at one stack. See `PORT_RETRY_POLICY`.
use super::PORT_RETRY_POLICY;
use super::{AuditLabels, CoreParts, ProbeTarget, RawPortScan, RawProbeScan};
use crate::scanner::strategy::icmp_error::{self, Unreachable};

/// What identifies one attempt of a probe on the wire.
///
/// The nonce alone, because the source port does not vary between attempts -
/// it identifies the *scan*, and is checked once against every reply rather than
/// per attempt. A fresh nonce per attempt is what makes a retried probe
/// measurable at all: TCP itself has to discard round-trip samples from
/// retransmissions because it cannot tell which transmission an
/// acknowledgement answers, and a scanner that varies the value the reply echoes
/// does not have that problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcpToken {
    nonce: u32,
}

/// Probes specific `(address, port)` pairs with raw TCP segments, using
/// whichever [`TcpScanTechnique`] it was built for.
///
/// Unlike [`RoutedScanner`](crate::scanner::strategy::routed::RoutedScanner), which sends one SYN per host
/// purely to check for a pulse, this sends one per `(address, port)` pair it is
/// given and reports what each one revealed.
pub struct TcpPortScanner {
    /// Which segment each probe carries, and so what every answer means. Fixed
    /// for the life of the scan: a report that mixed techniques could not say
    /// which one produced a given verdict.
    technique: TcpScanTechnique,
    /// An arbitrary TCP flag byte to send in place of the technique's own, from
    /// [`EvasionProfile::flags`](crate::evasion::EvasionProfile::flags), or
    /// `None` to send the technique's. When set, every probe carries it and the
    /// verdict softens to reachable-or-silent, because an arbitrary combination
    /// has no open/closed meaning to read. See [`effective_flags`](Self::effective_flags).
    flags_override: Option<u8>,
    /// Everything a raw port scan carries and does regardless of protocol: the
    /// transport, the ledger, the deadline, the pacing and the stop conditions.
    /// What stays in this file is what a *TCP* probe is and what its answers
    /// prove.
    core: RawProbeScan<TcpToken>,

    /// How far this scan may go to identify the operating system behind a host.
    ///
    /// Read here because this is where the replies that carry a stack's shape
    /// arrive, and a SYN+ACK is the only segment that carries one. At
    /// [`OsDetection::Passive`] nothing extra is sent and nothing is timed
    /// differently: the reply was drawn to classify a port, and reading what else
    /// it says costs a parse.
    os_detection: OsDetection,

    /// How far the second identification pass may go over the ports this scan
    /// found open. Read here because this scanner owns that pass; see
    /// [`detect_services`](PortScanner::detect_services).
    service_detection: ServiceDetection,
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
        let src_port: u16 = tuning
            .evasion
            .source_port_or(rand::random_range(50_000..u16::MAX));
        let flags_override = tuning.evasion.flags;
        let transport = ProbeTransport::open_capturing(
            ProbeKind::TcpProbe {
                reply_port: src_port,
                // An arbitrary flag combination reads its verdict off ICMP the
                // way a flag-probe technique does, silence upgrades to filtered
                // when an error names the filter, so it asks for errors too.
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

    /// Builds a scanner around an already-opened transport, so the caller
    /// decides how probes reach the wire and where replies come from.
    ///
    /// Probes leave from the port the transport's capture admits replies to,
    /// as [`ProbeKind::TcpProbe`]'s `reply_port` names it, since that is what
    /// recognizes this scan's own replies; see
    /// [`ProbeTransport::reply_port`]. `src_port` is the port for a transport
    /// that fixes none, which is one built from parts. Paired with a synthetic
    /// transport (`ProbeTransport::from_parts`, behind the `test-support`
    /// feature) this is the seam that lets probe and reply correlation be
    /// driven against a simulated network rather than a real one, with no
    /// privileges and no interface.
    ///
    /// A transport opened for a kind other than [`ProbeKind::TcpProbe`] or
    /// [`ProbeKind::TcpSyn`] cannot hear this scan's answers, and the scan
    /// refuses it when it runs, with [`StrategyError::MismatchedTransport`].
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

    /// [`with_transport`](Self::with_transport), paced and shaped by `tuning`
    /// as [`new`](Self::new) would be: its retry schedule, its rate limits,
    /// what the evasion profile does to each probe including the flag byte it
    /// sends, and how far it identifies what answers.
    ///
    /// Everything in `tuning` that decides how the transport is opened is the
    /// caller's to have honoured already, since the transport arrives open.
    /// That includes the profile's source port: the transport's reply port is
    /// the one probed from, and `src_port` only where it fixes none.
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

    /// The common constructor.
    ///
    /// Takes a finished core so the two public constructors share one place that
    /// knows how a raw scan is set up, and adds only what a TCP scan decides for
    /// itself.
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
    /// Paced by its congestion window under the rate ceiling, and given a
    /// deadline that outlives the slowest either may settle at; see
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

        // This scan's own probe leaving, witnessed rather than read as a reply.
        // A segment from this scan's port to that same port is the probe of
        // the port the scan sends from, which a full range asks, or the answer
        // to it, and only the probe carries the probe's flags: an answer is a
        // reset or a SYN+ACK, which no technique sends.
        if tcp_packet.source_port() == self.core.src_port
            && (tcp_packet.destination_port() != self.core.src_port
                || tcp_packet.flags() == self.effective_flags())
        {
            self.witness_probe(captured, &tcp_packet);
            return;
        }

        // A segment addressed anywhere but this scan's own port answered
        // somebody else's conversation. The capture filter already narrows to
        // it, but that is a performance boundary rather than a guarantee - a
        // transport can be built with no filter at all - and this is the only
        // thing making the reply ours.
        if tcp_packet.destination_port() != self.core.src_port {
            self.core.audit.record_off_target();
            return;
        }

        let Some(reply) = tcp::classify_probe_response(&tcp_packet) else {
            self.core.audit.record_off_target();
            return;
        };
        // An arbitrary flag combination has no open/closed meaning to read, so
        // any reply this scan's own probe drew proves only that the port is
        // reachable. A named technique reads its defined verdict instead, and a
        // segment it could not have provoked, a SYN+ACK answering an ACK scan,
        // say, is somebody else's traffic on this scan's port and resolves
        // nothing.
        let state = if self.arbitrary_flags() {
            PortState::Unfiltered
        } else {
            match self.technique.verdict(reply) {
                Some(state) => state,
                None => return,
            }
        };

        // Which attempt the segment claims to be answering. The ledger checks it
        // against every attempt still live for this port, so a reply to an
        // earlier attempt that arrives after a retry has gone out is still
        // recognized - and names which attempt it answered, so the round trip it
        // yields is the real one.
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
                // The header this function already had in hand, for the reason
                // the hop counter is kept at all: it costs nothing to read and
                // there is no second chance to read it.
                ttl: captured.observation.map(IpObservation::remaining_hops),
            },
            now,
        );

        // Only for a reply that answered one of this scan's probes. The capture
        // hands over whatever reaches the scan's source port, which on a busy
        // machine includes other programs' conversations, and reading a stray
        // segment's header would write a host record for an address this scan
        // never asked about.
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

    /// Reads what the reply that just resolved a port says about the machine
    /// behind it, and files it against the host.
    ///
    /// After the port verdict, and not able to change
    /// it. Identifying an operating system is a secondary reading of a reply
    /// drawn for another purpose, and a defect here must not be able to cost a
    /// port its state.
    ///
    /// Only a SYN+ACK is read. A reset carries no TCP options at all whatever the
    /// probe offered, and the corpus holds no rule that could be matched against
    /// one: the single reset feature that looks promising is not usable, since
    /// the same labelled devices answered two scanners on one segment with
    /// opposite values.
    fn identify_stack(&self, ip: IpAddr, state: PortState, captured: &CapturedSegment) {
        // `None` means this segment never had an IP header to read - a synthetic
        // receive stream - rather than that nothing notable was in one.
        let Some(observation) = captured.observation else {
            return;
        };

        // Before the detection gate. The hop counter is not an
        // identification and costs nothing to keep - it arrived in a header this
        // function already had in hand - while what needs it later is a
        // traceroute, which is a separate setting entirely. Gated with the OS
        // reading, a scan asking for a path without asking for a fingerprint
        // would have to re-obtain by probe a number it had already been told.
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
            // The stack reading, handed to the one place that knows what else
            // a host implies about itself. This scanner's contribution is the
            // observation it just took; the rule that a host's own hardware and
            // name are always weighed beside it belongs to `identify`.
            os::identify(host, [stack.as_evidence()]);
        });
    }

    /// Reads an ICMP error as a verdict on the probe it quotes.
    ///
    /// The quotation is what makes this attributable at all, and it is checked
    /// as strictly as a TCP reply: it has to be a TCP segment, sent from this
    /// scan's own port, aimed at a probe still outstanding. What it cannot
    /// always carry is *which attempt* - eight quoted bytes reach the sequence
    /// number and no further - so for a technique whose nonce lives in the
    /// acknowledgement field, a sender quoting only the minimum names the probe
    /// by its ports alone. That is enough for a host unreachable, which settles
    /// no port and is filed only while the probe is outstanding. It is not
    /// enough for a refusal, which would settle one: a refusal that cannot name
    /// the attempt retires nothing, and the port takes whatever its own retry
    /// schedule concludes.
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
            // Nobody could reach the address at all, so the message carries no
            // verdict on the port it happened to quote. The probe is left
            // outstanding to retire on its own schedule like any other
            // unanswered one.
            Unreachable::Host => {
                self.core.record_host_down(&key, token, reply.source);
            }
            // Everything else is a refusal, and for a TCP probe all three read
            // the same way. An administrative prohibition says so outright. A
            // *port* unreachable would mean a closed port had it answered a UDP
            // probe, but no TCP stack emits one - so something in the path
            // rejected the probe on the host's behalf, which is a filter and
            // not a closed port. A *protocol* unreachable would mean a host with
            // no TCP stack at all, which is not a closed port either; it is read
            // for what it is by the pass that asks about protocols on purpose.
            //
            // A refusal names a port, so unlike a host unreachable it has to
            // name the *attempt* as well. Four of the six techniques put their
            // nonce in the sequence number, which is inside the eight bytes RFC
            // 792 guarantees, so an error about one of those carries it however
            // stingy the sender. The two that use the acknowledgement field -
            // and Maimon, which carries ACK - need twelve quoted bytes, and a
            // sender offering only the minimum leaves `token` as `None`.
            //
            // Resolving on that would be resolving on the ports alone, which
            // anybody who knows this scan's source port can supply. For an ACK
            // or window scan it would reach the verdict silence reaches, costing
            // only a suppressed retry and an invented `IcmpProhibited`. For a
            // Maimon scan it would cost the verdict: `OpenFiltered` would become
            // `Filtered`, and an open port would be dismissed.
            //
            // So an unattributable refusal retires nothing, and the port takes
            // whatever its own retry schedule concludes. See the SCTP scanner,
            // which reaches the same rule from the other direction: an INIT's
            // nonce is *never* inside the guaranteed eight.
            Unreachable::Port | Unreachable::Prohibited | Unreachable::Protocol
                if token.is_none() =>
            {
                self.core.audit.record_reply_without_rtt();
            }
            Unreachable::Port | Unreachable::Prohibited | Unreachable::Protocol => {
                self.resolve_probe(
                    key,
                    token,
                    PortState::Filtered,
                    Answer {
                        drawn_by: None,
                        sender: Some(reply.source),
                        // The error's own hop counter, which is the distance to
                        // whatever refused the probe rather than to the target.
                        // That is the useful reading: a refusal from nearer than
                        // the host is a middlebox answering on its behalf.
                        ttl: reply.observation.map(IpObservation::remaining_hops),
                    },
                    now,
                );
            }
        }
    }

    /// Retires one outstanding probe with the state its reply established,
    /// crediting whatever round trip the ledger is willing to vouch for.
    ///
    /// `token` names the attempt that was answered, or `None` where the reply
    /// could not say. A reply matching no live attempt resolves nothing: it is a
    /// stray or spoofed segment, a duplicate of one already acted on, or an
    /// answer to a probe already written off. Returns whether it resolved one,
    /// which is what makes anything else the reply carries this scan's to read.
    fn resolve_probe(
        &mut self,
        key: ProbeTarget,
        token: Option<TcpToken>,
        state: PortState,
        answer: Answer,
        now: Instant,
    ) -> bool {
        let Some(resolution) = self.core.ledger.resolve(&key, token, now) else {
            // A reply matching no live attempt: a stray or spoofed segment, a
            // duplicate of one already acted on, or an answer to a probe already
            // written off. It yields no sample.
            self.core.audit.record_reply_without_rtt();
            return false;
        };

        let rtt = resolution.rtt;
        self.core.record_answer(&resolution);
        self.record_port_answered_by(key.0, key.1, state, answer, rtt);
        // The target spoke: the only outcome that settles positively.
        self.settle(Outcome::Answered {
            position: resolution.payload,
        });
        true
    }

    /// Which protocol a host verdict from this scan is credited to.
    ///
    /// [`StatusProtocol::TcpSyn`] keeps its one meaning, so a report naming it
    /// always describes a half-open connection attempt. Every other
    /// technique credits [`StatusProtocol::Tcp`], with the probe that drew the
    /// answer named in the reason's details.
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

    /// Whether this scan sends an arbitrary flag combination, so a reply says
    /// only that the port is reachable and silence means open-filtered: the
    /// softer reading an arbitrary combination licenses, in place of the
    /// technique's defined open/closed verdict.
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

    /// What silence means here is the technique's to say: a firewall for the
    /// two probes any live stack would have answered, an open port or a
    /// firewall for the four an open port is required to ignore.
    fn silence_means(&self) -> PortState {
        if self.arbitrary_flags() {
            // Silence to an arbitrary combination is either a drop or an open
            // port that ignored it, the open-filtered of the flag-probe family:
            // never the plain filtered a SYN's silence would earn.
            PortState::OpenFiltered
        } else {
            self.technique.silence_means()
        }
    }

    /// "unanswered" rather than either verdict, because which one silence
    /// produces depends on the technique and the message is about probes that
    /// never left at all.
    fn audit_labels(&self) -> AuditLabels {
        AuditLabels {
            tag: "tcp-port",
            silence: "unanswered",
        }
    }

    /// Sends one probe at `(ip, port)` and records the attempt.
    ///
    /// Nothing about the probe is kept between attempts and none of it needs to
    /// be: the packet is built afresh from the target, which is both cheaper
    /// than buffering it and required, since every attempt must carry its own
    /// nonce.
    /// Routes one captured reply to whichever half of the classification can
    /// read it.
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
        // The shared loop reaches a verdict from a spent budget rather than from
        // a packet, so it has no reply to name. Everything a reply *did* draw
        // goes through the fuller form below.
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
        // Whether this send takes a slot in the congestion window. A retry does
        // not: the slot went back when the question it repeats ran out of
        // round-trip budget. The position says which this is, as it does for
        // the ledger below; the ledger's own state would not, since a retry
        // whose probe was settled while it waited finds nothing there and
        // would read as a first attempt.
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
    /// [`record_port`](RawPortScan::record_port), also saying what the reply
    /// that produced the verdict was and what it carried.
    ///
    /// Kept off the shared trait because it is a TCP concept: the UDP scanner
    /// implements the same trait and has no notion of a segment's flags, and
    /// widening the shared signature to carry one would put a protocol's
    /// vocabulary into the machinery both protocols share.
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

        // The packet that settled it, written down rather than merely acted on.
        // The classification below already knows which reply arrived, it is
        // what decides the verdict, and without this record a reader would have
        // the word `filtered` and no way to learn whether a firewall said so or
        // nothing came back. The two are different findings.
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
            // Three routes to an open port, told apart. A handshake is the peer
            // accepting the connection; a challenge ACK is the peer saying it is
            // *already* half-open on one, which only a listener can be; a reset
            // is a window scan reading the listening socket's own window off a
            // refusal. Same verdict, materially different evidence, and a report
            // that called any of the three a handshake would be describing a
            // packet nobody sent.
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

        // The round trip of a segment the target sent, credited to the host as
        // a liveness pass would credit its own, since a scan that ran none has
        // no other measure of the host. Only a TCP reply's: an ICMP error may
        // come from a router, and its round trip is the router's. The ledger
        // has already attributed the reply to the attempt it answers by the
        // number it echoes, so a reply to a retried probe is timed from the
        // attempt it answers, where Karn's rule would have to discard it.
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
/// Three facts that arrive together, travel together and are read together, so
/// they are one value rather than three parameters threaded side by side. Every
/// one of them is `None` for a port nothing answered, which is the case the
/// sweep settles on its own schedule.
#[derive(Debug, Clone, Copy, Default)]
struct Answer {
    /// Which segment produced the verdict, where a TCP reply did.
    drawn_by: Option<TcpReply>,
    /// Who sent it, where that was not the target itself.
    sender: Option<IpAddr>,
    /// The hop counter as it arrived: an IPv4 TTL or an IPv6 hop limit.
    ///
    /// Not the value the sender wrote. Every router on the path decrements
    /// it, so what is recorded is the initial value less the distance, which is
    /// what makes it worth keeping per port: a reply whose count disagrees with
    /// the host's other replies did not come from where the others did. See
    /// [`IpObservation::remaining_hops`](crate::model::capture::IpObservation::remaining_hops).
    ttl: Option<u8>,
}

/// Which packet settled a port, in the vocabulary a report records.
///
/// The port-level mirror of the host evidence above, and drawn from the same
/// two facts: the verdict, and the reply that produced it. Kept apart because
/// they answer different questions, that one says why the *host* is believed
/// alive, this says why the *port* is in the state it is.
///
/// A [`PortState::Filtered`] port whose attempts ran out records
/// [`ScanResponse::NoResponse`], because that word alone does not say whether a
/// filter answered or nothing did. [`PortState::OpenFiltered`] says silence on
/// its own face and is left as it is: the flag-probe techniques come back full
/// of it, and a packet recorded against every one would be the verdict written
/// twice.
///
/// `None` where the verdict and the reply that produced it name no packet
/// between them.
fn port_evidence(
    state: PortState,
    drawn_by: Option<TcpReply>,
    sender: Option<IpAddr>,
    target: IpAddr,
) -> Option<ScanResponse> {
    match (state, drawn_by, sender) {
        // A window scan reaches an open port by the reset every other technique
        // reads as a refusal, so the packet named here is the one that arrived.
        (PortState::Open, Some(TcpReply::Rst { .. }), _) => Some(ScanResponse::TcpRst),
        // A challenge ACK is a listener saying it is already half-open, which
        // only a listener can be. Same segment family as a handshake, and the
        // report records both as the SYN/ACK path they are.
        (PortState::Open, _, _) => Some(ScanResponse::TcpSynAck),
        (PortState::Closed | PortState::Unfiltered, _, _) => Some(ScanResponse::TcpRst),
        // An unreachable from the target is the target's own policy; one from
        // the path is somebody else's. Both are prohibitions, and which address
        // sent it is kept on the host's evidence rather than restated here.
        (PortState::Filtered, _, Some(from)) => Some(match from == target {
            true => ScanResponse::IcmpProhibited,
            false => ScanResponse::IcmpUnreachable,
        }),
        (PortState::Filtered, None, None) => Some(ScanResponse::NoResponse),
        _ => None,
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
        TcpScanTechnique::Window => "rst to an ack probe, read for its window",
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
/// A failure comes back whole rather than logged here, so the scan can sort it
/// by whose fact it is and report it once: a probe that was never sent and a
/// probe nobody answered are indistinguishable in a port count and could hardly
/// be more different in what they mean. See
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

    // A probe this host could not build is this host's failure, in the words
    // the link-layer sender uses for a frame it could not build.
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

    // A decoy from each address of the target's own family: its own port and
    // nonce, the same technique and shaping, so it is an equal-looking probe and
    // none of them is the odd one out.
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
    /// Names the strategy the way a report has to read it.
    ///
    /// A SYN scan keeps [`ScannerKind::SynPort`], which is what every report
    /// this engine has ever written called it and what consumers already parse.
    /// The flag-probe techniques are a different question asked of the same
    /// scanner, and calling their failures `syn_port` would be a plain untruth;
    /// which of them ran is in the phase's settings.
    ///
    /// The rule itself lives on [`ScannerKind::for_raw_tcp`], because
    /// [`PortScanStep`](crate::scanner::plan::PortScanStep) has to reach the
    /// same answer when it attributes a socket that would not open.
    fn kind(&self) -> ScannerKind {
        ScannerKind::for_raw_tcp(self.technique)
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
    /// New targets are admitted only while the congestion window has room, and
    /// retries are serviced before new targets are taken, since a retry is an
    /// obligation the scan already owns. The window is what paces the scan and
    /// what it discovers about each target's capacity; see
    /// `TCP_PORT_WINDOW`.
    async fn scan(&mut self, targets: mpsc::Receiver<PlannedTarget>) -> Result<(), StrategyError> {
        super::drive(self, targets).await
    }

    /// Fingerprints every open port the scan found. The raw exchange that
    /// classified each port never opened a connection, so this second pass makes
    /// one per open port and runs the shared fingerprint engine over it.
    ///
    /// Needs no branch on the technique. Only a SYN or a window scan reports a
    /// port [`PortState::Open`] (see [`TcpScanTechnique::finds_open_ports`]), so
    /// after any other one this finds nothing to identify and returns
    /// immediately - the data already guarantees what a condition here would
    /// have enforced. After a window scan it runs, and a port whose openness
    /// rests on a reset's window is the one most worth putting a connection to.
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
    use crate::transport::probe::{MockSender, ProbeTransport};

    /// The port a scanner under test probes from. A synthetic transport's
    /// capture is built around no port at all, so any would do; a fixed one
    /// keeps two runs of a test comparable.
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
    /// address rather than the target's.
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
            TcpScanTechnique::Maimon | TcpScanTechnique::Ack | TcpScanTechnique::Window => {
                tcp.set_sequence(token.nonce)
            }
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

    /// A sender that refuses everything, which is what an interface whose queue
    /// has filled or whose neighbour will not resolve looks like from up here.
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

    /// A SYN scanner wired to a recording [`MockSender`] and an idle capture
    /// stream, plus the session store to assert against and the probe log to
    /// read tokens back out of.
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

    /// Sends a probe to `TARGET:port` and returns the token it went out
    /// carrying, so a matching reply can be synthesized.
    ///
    /// The token is read back off the recording sender rather than out of the
    /// scanner, so what a test answers is what actually reached the wire.
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

    /// The nonce a recorded probe went out carrying, read from whichever field
    /// its technique writes it to.
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

    /// The token the most recent probe went out carrying.
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

    /// The packet that settled a port is written down, with the hop counter the
    /// header carried.
    ///
    /// The scanner knows which reply arrived, it is what decides the verdict,
    /// and one that acted on it and threw it away would leave a reader the word
    /// `open` and no account of it, and no way at all to tell a `filtered` a
    /// firewall produced from a `filtered` nothing answered.
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

    /// A scan over a transport opened for replies to one port sends from that
    /// port, whatever port it was handed beside the transport, and reads the
    /// answers that come back to it. Sent from the other, every answer would
    /// arrive at a port the capture filters out, and every open port would
    /// read as silent.
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

    /// A transport opened for another kind of probe is refused, not scanned
    /// over.
    ///
    /// Its capture admits none of this scan's answers, so run anyway every port
    /// would read filtered, a verdict indistinguishable from a real firewall.
    /// Refused, the scan says why it did not run, sends nothing, and still
    /// files every port it was handed, as one nobody asked about.
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
        assert!(sent.lock().unwrap().is_empty(), "a probe was sent");
        assert_eq!(port_state(&session, 22), Some(PortState::Unasked));
        assert_eq!(port_state(&session, 80), Some(PortState::Unasked));
    }

    /// A reset is recorded as the reset it was, not as the absence of a reply.
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

    /// A synthetic reply has no header to read, and nothing is invented for it.
    ///
    /// The hop counter is the one field here that can only come off a wire, and
    /// a default stamped in its place would be a measurement nobody took.
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

    /// A probe this machine would not send leaves the port on the host saying
    /// nothing was established, rather than leaving it off.
    ///
    /// A link that stops accepting sends refuses every probe behind the one that
    /// noticed, so ports left off would go nowhere at all: not filtered, not
    /// unknown, absent, while the audit counted thousands of failed sends beside
    /// a host that looked cleanly scanned. That is the shortfall a reader cannot
    /// see, and it is the same one `resolve_unasked` closes for the targets
    /// still in the queue.
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

    /// A port nothing answered records the silence, which is an answer of its
    /// own. Leaving the evidence off would give a verdict no account of itself,
    /// and a reader could not tell that from a report where the account was
    /// dropped.
    #[test]
    fn an_unanswered_port_records_the_silence() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 80);

        scanner.record_port(TARGET, 80, PortState::Filtered, None);

        assert_eq!(port_state(&session, 80), Some(PortState::Filtered));

        let discovery = port_discovery(&session, 80).expect("the silence is evidence too");
        assert_eq!(discovery.reason(), &ScanResponse::NoResponse);
        assert_eq!(discovery.rtt(), None, "nothing arrived to be timed");
        assert_eq!(discovery.ttl(), None, "and nothing carried a hop count");
    }

    /// A refusal that did arrive is still told apart from a silence, which is
    /// the whole reason either is written down.
    #[test]
    fn a_refusal_is_not_recorded_as_a_silence() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 81);

        scanner.record_port(TARGET, 81, PortState::Filtered, Some(TARGET));

        let discovery = port_discovery(&session, 81).expect("the refusal is evidence");
        assert_eq!(discovery.reason(), &ScanResponse::IcmpProhibited);
    }

    /// A TCP reply carrying `bytes`, as it would have arrived under a header
    /// whose hop counter reads `ttl`.
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

    /// **A segment answering none of this scan's probes records no host.**
    ///
    /// The capture delivers whatever arrives at the scan's source port, and on
    /// a busy machine that includes other programs' conversations: loopback
    /// traffic from a process that happened to draw the same ephemeral port is
    /// the everyday case. A reply the ledger cannot match resolves nothing, and
    /// reading its header anyway would write a host record for its sender, an
    /// address the scan never asked about, into a report that then lists it.
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

    /// One of this scan's own probes as the capture hands it back, which is
    /// what a transport admitting both directions delivers.
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
    /// answer rather than being resolved by the sighting.
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

    /// The probe of the port the scan sends from is witnessed leaving too, and
    /// its answer, between the same two ports, is still read as the answer.
    ///
    /// A scan of every port asks that one, and its probe, from the scan's port
    /// to itself, read as an answer is a SYN answering nothing: filed off
    /// target, and the one probe of the range never seen leaving.
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
        // A different nonce: the same shape of segment, from another probe.
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

    /// An arbitrary flag override softens the verdict to reachable-or-silent,
    /// where the underlying technique would read open or closed.
    ///
    /// SYN+PSH is span-one like a SYN, so the harness's own echo rule still
    /// applies and the answer resolves. A version that read the override's reply
    /// through the technique's verdict would call this reset closed, and one that
    /// left silence to the technique would call it plain filtered: both untrue
    /// of a combination that carries no open/closed meaning.
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
            Some(PortState::Unfiltered),
            "a reply to an arbitrary combination proves only reachability"
        );
        assert_eq!(
            scanner.silence_means(),
            PortState::OpenFiltered,
            "and its silence is open-filtered, not a SYN's plain filtered"
        );
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
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply.clone()),
            Instant::now(),
        );

        assert_eq!(port_state(&session, 82), None);
        assert!(scanner.core.ledger.contains(&(TARGET, 82)));
    }

    /// The scan's source port is where its answers arrive. A segment carrying
    /// the right nonce but addressed to another port on this host belongs to
    /// somebody else's conversation, and the capture that would normally have
    /// dropped it does not exist on a synthetic transport.
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

        // Same host, but a port we never probed.
        let reply = tcp_segment(&scanner, 1234, token, SYN | ACK);
        scanner.handle_tcp_reply(
            &CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Tcp.0, reply.clone()),
            Instant::now(),
        );

        assert_eq!(port_state(&session, 1234), None);
        assert!(scanner.core.ledger.contains(&(TARGET, 80)));
    }

    #[test]
    fn unanswered_probes_resolve_as_filtered() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 443);

        super::super::run_out(&mut scanner);

        assert_eq!(port_state(&session, 443), Some(PortState::Filtered));
        assert!(scanner.core.ledger.is_empty());
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
            // The helper builds a reset with no window set, which is what a
            // stack with nothing behind the port announces.
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

    /// A RST is negative about the port and positive about the host, whichever
    /// probe drew it: the row most easily forgotten, since the two verdicts
    /// point opposite ways.
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

    /// The window scan's whole claim, end to end: the reset every other
    /// technique reads as a refusal announces the listening socket's own window,
    /// and the port that announced one is open. The zero-window half is in the
    /// table above.
    ///
    /// The evidence matters as much as the verdict here. This open port was
    /// found by a reset, and a report crediting it to a handshake would be
    /// naming a segment the scan never drew.
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

    /// Nothing but a SYN can provoke a SYN+ACK, so one arriving mid-FIN-scan
    /// answered something else and must not be read as an open port.
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

    /// What silence means is the other half of the difference between the
    /// families: a SYN or an ACK any live stack would have answered, a flag
    /// probe an open port is required to ignore.
    #[test]
    fn silence_is_filtered_or_open_filtered_by_technique() {
        for (technique, expected) in [
            (TcpScanTechnique::Syn, PortState::Filtered),
            (TcpScanTechnique::Ack, PortState::Filtered),
            (TcpScanTechnique::Window, PortState::Filtered),
            (TcpScanTechnique::Fin, PortState::OpenFiltered),
            (TcpScanTechnique::Null, PortState::OpenFiltered),
            (TcpScanTechnique::Xmas, PortState::OpenFiltered),
            (TcpScanTechnique::Maimon, PortState::OpenFiltered),
        ] {
            let (mut scanner, session, sent) = scanner_for(technique);
            probe(&mut scanner, &sent, 443);

            super::super::run_out(&mut scanner);

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

        super::super::run_out(&mut scanner);

        let host = session.hosts().get(TARGET).expect("the port was recorded");
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

        CapturedSegment::synthetic(from, IpNextHeaderProtocols::Icmp.0, bytes)
    }

    /// The probe under the IP header a router would have echoed back with it.
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
        assert!(scanner.core.ledger.is_empty());
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

        let host = session.hosts().get(TARGET).expect("host recorded");
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

        let host = session.hosts().get(TARGET).expect("host recorded");
        assert!(host.status().is_up());
    }

    /// A scan of an on-link address the kernel never resolves hands the kernel
    /// one probe, holds the rest until the kernel gives up, and then reads
    /// every port unasked and the address unreached, with nothing failed.
    ///
    /// Through the whole loop, because what is at stake is what reaches the
    /// sender: on Linux every write to a neighbour still being resolved is
    /// accepted and queued against the socket, so twenty ports written freely
    /// are twenty probes that never leave, read as twenty filtered ports, and
    /// their retries are what fills the send buffer for every other host.
    #[tokio::test]
    async fn a_neighbour_the_kernel_never_resolves_is_asked_once_and_reported_unreached() {
        use crate::transport::kernel_neighbors::{KernelNeighbors, NeighborState, NeighborTable};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let reads = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&reads);
        // Resolving for the first two readings, then given up on, as the
        // kernel's three requests a second apart would go, only faster.
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
            1,
            "one probe went to the kernel"
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

    /// A scan through a frame sender asks for every dead neighbour it meets at
    /// once and waits about one resolution for all of them, sending none of
    /// their probes, while a live neighbour behind them is asked everything.
    ///
    /// A frame sender resolving each neighbour inside the send held the whole
    /// scan for every dead one in turn: two hundred dead addresses cost a
    /// hundred seconds at half a second each, and the budget could not grow to
    /// what a client asleep on Wi-Fi needs without multiplying that. Held
    /// instead of sent while the resolutions run together, the wave costs one
    /// budget, which the bound here allows ten of.
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

    /// Under a rate ceiling, the probes held while the kernel resolves dead
    /// neighbours spend none of it, and a live host behind them is asked every
    /// port.
    ///
    /// A tick releases a batch, and a probe that went back to wait on a
    /// resolution put nothing on the wire. Charged a share anyway, the ports
    /// of a few dead neighbours, each re-checked every few tens of
    /// milliseconds, would take every share a slow ceiling gives and the live
    /// host would reach the deadline never asked. Here the kernel gives up on
    /// the dead neighbours only once the live host has been asked everything,
    /// so a scan that starves it waits on them to its deadline.
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
            dead.len(),
            "one probe each started the resolutions"
        );
    }

    /// Every address is asked before the deadline, however long the sender
    /// spends resolving the ones that turn out dead.
    ///
    /// A sender that frames its own probes resolves each neighbour before the
    /// first frame to it and blocks the loop for the whole wait when nothing
    /// answers. That wait is the sender's, not the network's, and a deadline
    /// sized for the network would otherwise run out on it with addresses
    /// still queued, which then read unasked for no reason of their own.
    #[tokio::test]
    async fn the_deadline_allows_for_the_time_the_sender_spends_resolving() {
        use std::sync::{Arc, Mutex};

        /// Waits out a resolution the first time it meets each address and
        /// refuses it as unanswered, as the frame path does.
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

        // Twenty ports an address, one address after another, as a plan
        // covering a range lays them out.
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
        assert!(scanner.core.ledger.contains(&(TARGET, 80)));
        assert_eq!(
            session.hosts().get(TARGET).map(|host| host.status()),
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

    /// An unanswered probe goes out again, and the port stays undecided in the
    /// meantime rather than being written off after one silence.
    #[test]
    fn an_unanswered_probe_is_sent_again() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 80);

        super::super::retry_due(&mut scanner, Instant::now() + Duration::from_secs(1));

        assert_eq!(sent.lock().unwrap().len(), 2, "the probe was not retried");
        assert!(scanner.core.ledger.contains(&(TARGET, 80)));
        assert_eq!(port_state(&session, 80), None, "no verdict has been earned");
    }

    /// A port whose probes were never seen leaving is unasked, not filtered:
    /// silence from a question nobody heard is evidence of nothing.
    #[test]
    fn a_port_whose_probes_were_never_seen_leaving_is_unasked_not_filtered() {
        let (mut scanner, session, sent) = scanner_with_mock();

        // One port witnessed leaving so the run can see its egress; another not.
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
            Some(PortState::Filtered),
            "and a probe that was watched leaving still earns one"
        );
    }

    /// A scan that witnesses no egress reads silence as filtered, as before.
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

        assert_eq!(port_state(&session, 443), Some(PortState::Filtered));
    }

    /// Filtered is what exhausting the budget means, and it takes the whole
    /// budget to get there.
    #[test]
    fn a_port_is_filtered_only_once_every_attempt_is_spent() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 80);

        let mut now = Instant::now();
        for _ in 0..PORT_RETRY_POLICY.max_attempts + 2 {
            now += Duration::from_secs(4);
            super::super::retry_due(&mut scanner, now);
        }

        assert_eq!(port_state(&session, 80), Some(PortState::Filtered));
        assert_eq!(
            sent.lock().unwrap().len(),
            usize::from(PORT_RETRY_POLICY.max_attempts),
        );
        assert!(scanner.core.ledger.is_empty());
    }

    /// An answered probe must not be resent: a retry after a verdict is pure
    /// traffic, and on a wide scan it multiplies.
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

    /// A retry still waiting for its host's next slot when a late answer
    /// settles its probe is never sent, and takes nothing from the window.
    ///
    /// The answer to the first attempt arrived after that attempt's timeout,
    /// while the retry waited out the gap the caller asked the scan to keep.
    /// Sent anyway, it is a packet at a host the caller asked to treat gently,
    /// asking a question nothing is waiting on. And a send read as a first
    /// attempt takes a window slot that no answer or timeout will ever give
    /// back: enough of them and the scan stops admitting targets and idles to
    /// its deadline.
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

    /// A send carrying no plan position takes no slot in the window, whether
    /// or not its probe is still on the ledger when it leaves.
    ///
    /// The position is what tells a retry from a first attempt, being the one
    /// fact about a probe that nothing changes while a retry waits. The
    /// ledger's state is not: a late answer can settle the probe meanwhile,
    /// and a retry read against it as a first attempt takes a slot no answer
    /// or timeout will ever give back. The send is driven directly because the
    /// loop above it declines to send such a retry at all, which is the test
    /// before this one; this one holds the send path to its own contract.
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

    /// Each attempt carries its own nonce, so a reply to the first arriving
    /// after the second has gone out is still a reply. Matching only the newest
    /// attempt would discard it and report an open port filtered.
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

    /// The other half of that identity, and the one this scan does *not* vary:
    /// every attempt leaves from the port the capture filter was built around,
    /// so a retry's answer arrives where the scan is listening rather than
    /// somewhere the kernel has already dropped.
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

    /// Two answers, one port: the second finds nothing outstanding and is
    /// dropped, so it cannot be credited as a second observation.
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

    /// The scan has to outlive the schedule it commits each probe to, or ports
    /// are written off having never been fully asked.
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

    /// A path that logs when each probe left and, given a delay, answers every
    /// SYN with the SYN+ACK an open port sends, that long after the probe left.
    /// Without one it answers nothing, as a filter does.
    struct Path {
        answer_after: Option<Duration>,
        /// The hosts that answer, or every host where this is empty.
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

    /// A path that answers every SYN with a SYN+ACK the moment it leaves, and
    /// then holds the thread that sent it for `stall`: the scan loop stopped
    /// in its tracks with the answer already waiting for it.
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

    /// An answer that was waiting before its probe's timer came due is read
    /// as the answer, however late the loop gets round to either.
    ///
    /// A loop held up for longer than a timeout, by a slow send or a starved
    /// runtime, wakes to find both the answer and the expired timer. Serviced
    /// timer first, the probe is written off before its answer is read, and
    /// with one attempt that is an open port filed filtered on the strength
    /// of a silence that never happened. The answer here arrived within
    /// microseconds of the probe, so nothing but the order can make it late.
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

    /// Runs a SYN scan built from `tuning`, as the engine builds one, of
    /// `ports` ports on [`TARGET`] over a [`Path`], and returns what it
    /// recorded and when each probe left.
    async fn scan_over_path(
        tuning: &ProbeTuning,
        answer_after: Option<Duration>,
        ports: u16,
    ) -> (ScanSession, Departures) {
        let targets = (1..=ports).map(|port| (TARGET, port)).collect();
        scan_targets_over_path(tuning, answer_after, Vec::new(), targets).await
    }

    /// [`scan_over_path`] of `targets`, with only the hosts in `live`
    /// answering, or every host where it is empty.
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

    /// The busiest second on the wire in `sent`: the most probes that left
    /// within one second of any one of them.
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

    /// A scan held to a rate ceiling asks every port, however long the
    /// ceiling makes it take.
    ///
    /// The deadline is the guarantee that a scan ends, and it has to outlive
    /// the pace the caller asked for. A ceiling of a hundred probes a second
    /// puts a few hundred ports past any budget sized for an unlimited scan,
    /// and every one it stops short of reads unasked, open ones with the rest.
    /// A slower scan is meant to take longer, not to ask less. One attempt a
    /// probe, so the retry schedule adds nothing to the budget and what is
    /// left is the part the rate has to cover.
    ///
    /// What is asserted is that every port was asked, not what each answered:
    /// with one attempt and the path running in real time, a runner that
    /// stalls longer than a probe's timeout can read one open port filtered,
    /// which is a verdict about that stall and not about the deadline. A
    /// deadline cut short leaves ports unasked, and that is what fails here.
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

        // Well inside the shortest timeout, so the one attempt is answered
        // whatever the round trips teach the scan.
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

    /// A scan of two ports over a range of mostly empty addresses, held to a
    /// low rate ceiling, finds the hosts that are there, asks every address
    /// every port, and keeps to the ceiling on the wire.
    ///
    /// The shape a scan of a few ports over a range takes when the port probes
    /// stand in for the liveness pass: nothing has timed the hosts, most
    /// addresses answer nothing and are asked as often as the budget allows,
    /// and the ceiling makes the whole of it slow. A deadline sized for an
    /// unlimited scan stops it with most addresses unasked and the live hosts
    /// among them, and retries sent outside the ceiling put more than it on
    /// the wire.
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
                PortState::Filtered
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

    /// A scan built from the largest attempt budget and timeout scale the
    /// configuration accepts runs, and answers what it was asked.
    ///
    /// Both reach the arithmetic that sizes the scan's deadline from its
    /// retry schedule while the scanner is built, and it overflowed there: an
    /// attempt budget of 43 panicked before the first probe.
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

    /// A host the scan heard from carries the round trip of the reply that
    /// answered it.
    ///
    /// A scan that ran no liveness pass has no other measure of a host's
    /// latency, and a report listing a found host with no round trip reads as
    /// one nothing was timed against. A connect scan credits the handshake's;
    /// a raw scan has the reply matched to the probe it answers, which is a
    /// sharper measure than a connect's, and has to credit it too.
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

    /// A rate ceiling bounds every packet the scan puts on the wire, retries
    /// included.
    ///
    /// The ceiling is the fastest a scan may send, and it is the knob for a
    /// target that must not be pushed. Against a host that answers nothing,
    /// every probe is sent as often as its budget allows, and retries sent the
    /// moment they came due would ride on top of first attempts already
    /// filling the ceiling: the wire would carry up to the ceiling once per
    /// attempt. So no second on the wire may carry more than the ceiling,
    /// give or take the one tick a window of a second can straddle.
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
        assert!(host.ports().all(|port| port.state() == PortState::Filtered));
    }

    /// An ICMP error built by hand rather than from a probe this scan sent:
    /// the sender chooses the quoted destination, the quoted port and how much
    /// of the header to include.
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

    /// **An address this scan never probed is not a host this scan may report.**
    ///
    /// `write_host` creates the record it is handed, so without this check an
    /// unreachable naming a destination of the sender's choosing would invent a
    /// host and file it down. Nothing about the message establishes that the
    /// scan had ever addressed that address at all.
    #[test]
    fn an_unreachable_naming_an_unprobed_address_records_no_host() {
        let (mut scanner, session, _sent) = scanner_for(TcpScanTechnique::Fin);
        let never = Ipv4Addr::new(203, 0, 113, 77);
        let src = scanner.core.src_port;

        scanner.handle_reply(&forged_host_unreachable(never, src, 443, 8), Instant::now());

        assert_eq!(session.hosts().len(), 0, "no host may be invented");
        assert!(session.hosts().get(IpAddr::V4(never)).is_none());
    }

    /// A host that *was* probed still may not be filed down on the word of an
    /// error quoting a port nobody asked about.
    ///
    /// The distinction this protects is the one `HostStatus` is ordered by:
    /// `Unknown` says nothing was heard, and `Down` says an intermediary
    /// answered for the address. A hardened host that silently drops traffic is
    /// the first and must not be reported as the second.
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

    /// A host proved up keeps its status — the promotion rule already saw to
    /// that — but it must not collect the unreachable as a reason either.
    ///
    /// The reasons are the evidence trail, kept because "reachability is a claim
    /// someone will want to check". An unreachable filed against a host that
    /// answered for itself is a claim that cannot be checked, because it is not
    /// true.
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

    /// And the honest case still works: a router quoting a probe that really
    /// went out files the host down, which is what the check must not cost.
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

    /// **A refusal that cannot name the attempt retires nothing.**
    ///
    /// The acknowledgement field sits at offset eight, past what RFC 792
    /// guarantees an ICMP error will quote, so a sender offering only the
    /// minimum names an ack-field technique's probe by its ports and nothing
    /// else. The ports are in every packet this scan sends.
    #[test]
    fn a_refusal_quoting_too_little_to_name_the_attempt_resolves_no_port() {
        for technique in [
            TcpScanTechnique::Ack,
            TcpScanTechnique::Window,
            TcpScanTechnique::Maimon,
        ] {
            let (mut scanner, session, sent) = scanner_for(technique);
            probe(&mut scanner, &sent, 80);

            // The probe as it left, cut to the eight bytes and no further.
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
        }
    }

    /// The four techniques whose nonce is the sequence number are unaffected:
    /// it is inside the guaranteed eight, so a minimal quotation still names
    /// the attempt and still resolves the port.
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
                Some(PortState::Filtered),
                "{technique:?}: the sequence number is inside the guaranteed eight"
            );
        }
    }
}
