// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # SCTP Port Probing
//!
//! The privileged SCTP half of [`crate::scanner::scan`]: one chunk per
//! `(address, port)` pair, classified by the chunk that answers it.
//! [`SctpScanTechnique`] decides which chunk goes out and what an answer proves;
//! this file puts it on the wire and reads what comes back.
//!
//! ## Verdicts
//!
//! An SCTP endpoint answers an INIT whichever way its port stands: a listener
//! with an INIT-ACK, a port with nothing behind it with an ABORT (RFC 4960 §5.1,
//! §8.4). As with a SYN scan, a live stack always says something, so silence is
//! a probe no stack took. Neither answer completes an association, so no port is
//! left half-open on the target.
//!
//! A COOKIE-ECHO scan draws only the closed port's ABORT; the listener fails to
//! authenticate a cookie nobody minted and says nothing. Silence there is
//! `OpenOrNoReply` however long the scan waits, the price of a chunk that
//! crosses filters written against the INIT.
//!
//! An ICMP unreachable is read as a filter. A host with no SCTP stack answers
//! protocol unreachable, so a range that comes back entirely blocked may be a
//! machine that does not speak SCTP.
//!
//! ## Tying a reply to its probe
//!
//! Every probe carries a fresh 32-bit nonce that a conformant answer returns in
//! its verification tag, so a retried probe still yields a usable round trip.
//! The two chunks carry it in different fields; the [`sctp`] protocol module
//! explains why.
//!
//! The eight bytes of an ICMP error's quotation that RFC 792 guarantees reach
//! the two ports and the common header's verification tag, which is a
//! COOKIE-ECHO's nonce and zero for an INIT. So a COOKIE-ECHO probe is resolved
//! by the exact attempt an error quotes, and an INIT probe only by an error
//! that quotes past those eight bytes to its Initiate Tag. An error that stops
//! short is not acted on.
//!
//! ## Limits
//!
//! - No service pass: identifying what is behind an SCTP port needs an
//!   association, and this engine holds none.
//! - No unprivileged form; a host that cannot open the raw socket has its SCTP
//!   ports refused.
//! - An [`EvasionProfile`](crate::evasion::EvasionProfile)'s segment shaping is
//!   not applied: SCTP is covered by a CRC32c, and padding a chunk changes what
//!   the receiver reads. Decoys still work, since they only change the source
//!   address.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use tokio::sync::mpsc;

use crate::config::ProbeTuning;
use crate::journal::settle::Outcome;
use crate::model::capture::IpObservation;
use crate::model::host::{HostStatus, StatusProtocol, StatusReason};
use crate::model::port::discovery::{Discovery as PortDiscovery, ScanResponse};
use crate::model::port::{PortState, Protocol};
use crate::model::target::PlannedTarget;
use crate::model::technique::{SctpReply, SctpScanTechnique};
use crate::protocols::sctp;
use crate::report::ScannerKind;
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::{PortScanner, StrategyError};
use crate::success;
use crate::system::interface::SourceResolver;
use crate::transport::capture::CapturedSegment;
use crate::transport::probe::{Emission, ProbeKind, ProbeSender, ProbeTransport, SendError};

use super::{AuditLabels, CoreParts, ProbeTarget, RawPortScan, RawProbeScan};
use crate::scanner::strategy::icmp_error::{self, Unreachable};

/// What identifies one attempt of a probe on the wire: the Initiate Tag it went
/// out carrying, which a conformant peer echoes back whichever answer it sends.
///
/// Fresh per attempt, so a retried probe's answer names its transmission and
/// its round trip can be believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SctpToken {
    tag: u32,
}

/// Probes specific `(address, port)` pairs with raw SCTP chunks.
pub struct SctpPortScanner {
    /// Everything a raw port scan carries regardless of protocol.
    core: RawProbeScan<SctpToken>,
    /// Which chunk this scan sends, and so what an answer to it means.
    technique: SctpScanTechnique,
}

impl SctpPortScanner {
    /// Builds a scanner that selects each probe's source via `resolver`, sized
    /// for a scan covering `target_count` `(address, port)` pairs.
    ///
    /// The scan's fixed source port is drawn from the high ephemeral range and
    /// the transport's capture filter is built around it.
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
            ProbeKind::Sctp {
                reply_port: src_port,
            },
            tuning.evasion.effective_send_mode(tuning.send_mode),
            &ctx.capture_links(),
        )?;

        Ok(Self {
            core: Self::core(resolver, ctx, transport, &tuning, src_port, target_count),
            technique: tuning.sctp_technique,
        })
    }

    /// Builds a scanner around an already-opened transport, so a caller decides
    /// how probes reach the wire and where replies come from.
    ///
    /// Probes leave from the port the transport's capture admits replies to (see
    /// [`ProbeTransport::reply_port`]); `src_port` is used only for a transport
    /// that fixes none, such as one built from parts.
    ///
    /// A transport opened for anything but [`ProbeKind::Sctp`] cannot hear this
    /// scan's answers, and the scan refuses it when it runs, with
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
    /// what the evasion profile does to each probe, and the chunk it sends.
    ///
    /// Whatever in `tuning` decides how the transport is opened, including the
    /// profile's source port, is the caller's to have honoured already. The
    /// transport's reply port is the one probed from, and `src_port` only where it
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
            core: Self::core(resolver, ctx, transport, &tuning, src_port, target_count),
            technique: tuning.sctp_technique,
        }
    }

    /// The same, sending `technique`'s chunk instead of the default INIT, for a
    /// caller that builds the transport itself.
    #[must_use]
    pub fn probing_with(mut self, technique: SctpScanTechnique) -> Self {
        self.technique = technique;
        self
    }

    /// The core an SCTP port scan runs on.
    ///
    /// Uses the TCP port scanner's profiles: an INIT is answered by the target's
    /// stack as fast as the link allows, as a SYN is. The UDP profiles are shaped
    /// around an ICMP rate limit this scan's ordinary answers do not pass through.
    fn core(
        resolver: SourceResolver,
        ctx: ScanContext,
        transport: ProbeTransport,
        tuning: &ProbeTuning,
        src_port: u16,
        target_count: usize,
    ) -> RawProbeScan<SctpToken> {
        let retry = super::PORT_RETRY_POLICY.configured(tuning.retry);
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

    /// Matches an SCTP packet against an outstanding probe and, if it answers
    /// one, records the port's state.
    fn handle_sctp_reply(&mut self, captured: &CapturedSegment, now: Instant) {
        let (ip, bytes) = (captured.source, &captured.bytes);
        let Ok(packet) = sctp::parse(bytes) else {
            self.core.audit.record_off_target();
            return;
        };

        // A packet to any other port belongs to somebody else's association. The
        // capture filter narrows to this port only as a performance measure.
        if packet.destination_port() != self.core.src_port {
            self.core.audit.record_off_target();
            return;
        }

        let Some(reply) = sctp::classify_probe_response(&packet) else {
            self.core.audit.record_off_target();
            return;
        };

        // A chunk the technique has no verdict for did not answer this probe:
        // nothing a COOKIE-ECHO sends can provoke an INIT-ACK.
        let Some(state) = self.technique.verdict(reply) else {
            self.core.audit.record_off_target();
            return;
        };

        self.resolve_probe(
            (ip, packet.source_port()),
            Some(SctpToken {
                tag: sctp::echoed_nonce(&packet),
            }),
            state,
            Answer {
                drawn_by: Some(reply),
                sender: Some(ip),
                ttl: captured.observation.map(IpObservation::remaining_hops),
            },
            now,
        );
    }

    /// Reads an ICMP error for the probe it quotes.
    ///
    /// The quotation has to be an SCTP packet sent from this scan's own port,
    /// carrying the nonce of an attempt still outstanding. A COOKIE-ECHO's nonce is
    /// in the common header, inside the eight bytes RFC 792 guarantees, so an error
    /// names the exact attempt. An INIT's Initiate Tag sits sixteen bytes in, so an
    /// error about one is acted on only when the sender quoted that far; otherwise
    /// it retires no probe and files nothing against the host, whatever its code.
    fn handle_icmp_error(&mut self, reply: &CapturedSegment, now: Instant) {
        let Some(error) = icmp_error::parse(reply) else {
            return;
        };
        if error.quoted.protocol != IpNextHeaderProtocols::Sctp.0 {
            return;
        }

        let Some(quoted) = sctp::quoted_probe(error.quoted.payload) else {
            return;
        };
        if quoted.source != self.core.src_port {
            return;
        }

        let key = (error.quoted.destination, quoted.destination);
        let nonce = match self.technique {
            SctpScanTechnique::Init => sctp::quoted_init_tag(error.quoted.payload),
            // Always present in the common header. Every probe leaves with a
            // non-zero tag, so zero means a quotation of something else.
            SctpScanTechnique::CookieEcho => Some(quoted.verification_tag).filter(|tag| *tag != 0),
        };

        // An error that cannot name the attempt is not acted on.
        //
        // An INIT's guaranteed-quoted header tag must be zero (RFC 4960 §8.5.1), so
        // a minimal quotation names only the ports. The target knows the scan's
        // source port, and an off-path guesser needs fourteen bits once per run; a
        // forged Port Unreachable would then retire the probe as blocked with no
        // retransmission and record `IcmpProhibited` against the target.
        //
        // Refusing costs little: an INIT scan reads silence as `NoReply`, so the
        // probe still settles on its own retry schedule. Only the earlier
        // resolution and the `Blocked` evidence are lost, and those cannot be
        // forged.
        //
        // This applies to every code, `Unreachable::Host` included: a missing nonce
        // also means a quoted COOKIE-ECHO tag of zero, or a quoted packet whose
        // first chunk is not an INIT, neither of which this scan sent. Stricter
        // than the TCP and UDP scanners, which file a host down on the key alone
        // when the quotation carries no nonce.
        let Some(nonce) = nonce else {
            // Counted apart when it was a refusal, so a report can say one was heard
            // for a port that still reads no-reply.
            if error.reason == Unreachable::Host {
                self.core.audit.record_reply_without_rtt();
            } else {
                self.core.audit.record_unattributed_refusal();
            }
            return;
        };
        let token = Some(SctpToken { tag: nonce });

        match error.reason {
            // Nobody could reach the address, so the message says nothing about the
            // quoted port and the probe retires on its own schedule.
            Unreachable::Host => {
                self.core.record_host_down(&key, token, reply.source);
            }
            // Every other code is a refusal, not a closed port: a closed SCTP port
            // answers with its own ABORT. Protocol unreachable (no SCTP stack) lands
            // here too; the protocol pass reads it for what it says.
            Unreachable::Port | Unreachable::Prohibited | Unreachable::Protocol => self
                .resolve_probe(
                    key,
                    token,
                    PortState::Blocked,
                    Answer {
                        drawn_by: None,
                        sender: Some(reply.source),
                        // The distance to whatever refused the probe, which exposes a
                        // middlebox answering on the host's behalf.
                        ttl: reply.observation.map(IpObservation::remaining_hops),
                    },
                    now,
                ),
        }
    }

    /// Retires one outstanding probe with the state its reply established,
    /// crediting whatever round trip the ledger is willing to vouch for.
    ///
    /// A reply matching no live attempt resolves nothing: a stray or spoofed
    /// packet, a duplicate, or an answer to a probe already written off.
    fn resolve_probe(
        &mut self,
        key: ProbeTarget,
        token: Option<SctpToken>,
        state: PortState,
        answer: Answer,
        now: Instant,
    ) {
        let Some(resolution) = self.core.ledger.resolve(&key, token, now) else {
            self.core.audit.record_reply_without_rtt();
            return;
        };

        let rtt = resolution.rtt;
        self.core.record_answer(&resolution);
        self.record_port_answered_by(key.0, key.1, state, answer, rtt);
        self.settle(Outcome::Answered {
            position: resolution.payload,
        });
    }

    /// [`record_port`](RawPortScan::record_port), also carrying what the packet
    /// that produced the verdict was measured to be.
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

        let port = crate::fingerprint::baseline_port(port_num, Protocol::Sctp, state);

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
            // Both chunks prove the same thing about the host and opposite
            // things about the port, so the host evidence names which arrived.
            (PortState::Open | PortState::Closed, _) => Some((
                HostStatus::Up,
                StatusReason::new(
                    StatusProtocol::Sctp,
                    match drawn_by {
                        Some(SctpReply::Abort) => "abort to an sctp probe",
                        _ => "init-ack from a probed port",
                    },
                ),
            )),
            (PortState::Blocked, Some(sender)) if sender == ip => Some((
                HostStatus::Up,
                StatusReason::new(
                    StatusProtocol::IcmpUnreachable,
                    "unreachable for a probed sctp port, from the host",
                ),
            )),
            (PortState::Blocked, Some(sender)) => Some((
                HostStatus::Blocked,
                StatusReason::new(
                    StatusProtocol::IcmpUnreachable,
                    "unreachable for a probed sctp port, from the path",
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

/// What a reply carried, beyond the verdict it produced.
#[derive(Debug, Clone, Copy)]
struct Answer {
    /// Which chunk produced the verdict, where a chunk did.
    drawn_by: Option<SctpReply>,
    /// Who sent it, which for an ICMP error is not always the target.
    sender: Option<IpAddr>,
    /// The hop counter as the reply arrived carrying it.
    ttl: Option<u8>,
}

/// Which packet settled an SCTP port, in the vocabulary a report records.
///
/// `None` where nothing arrived; the sweep that gives up on a timed-out probe
/// records that separately.
fn port_evidence(
    state: PortState,
    drawn_by: Option<SctpReply>,
    sender: Option<IpAddr>,
    target: IpAddr,
) -> Option<ScanResponse> {
    match (state, drawn_by, sender) {
        (_, Some(SctpReply::InitAck), _) => Some(ScanResponse::SctpInitAck),
        (_, Some(SctpReply::Abort), _) => Some(ScanResponse::SctpAbort),
        (PortState::Blocked, None, Some(from)) => Some(match from == target {
            true => ScanResponse::IcmpProhibited,
            false => ScanResponse::IcmpUnreachable,
        }),
        (PortState::NoReply, None, None) => Some(ScanResponse::NoResponse),
        _ => None,
    }
}

impl RawPortScan for SctpPortScanner {
    type Token = SctpToken;

    fn core(&self) -> &RawProbeScan<SctpToken> {
        &self.core
    }

    fn core_mut(&mut self) -> &mut RawProbeScan<SctpToken> {
        &mut self.core
    }

    fn protocol(&self) -> Protocol {
        Protocol::Sctp
    }

    /// The technique's answer. An INIT is answered by an open port and a closed
    /// one alike, so silence there is a filter; a COOKIE-ECHO is answered only
    /// by a closed port, so silence is `OpenOrNoReply` and stays so.
    fn silence_means(&self) -> PortState {
        self.technique.silence_means()
    }

    fn audit_labels(&self) -> AuditLabels {
        AuditLabels {
            tag: "sctp-port",
            silence: self.technique.silence_label(),
        }
    }

    /// Routes one captured packet to whichever half of the classification can
    /// read it.
    fn handle_reply(&mut self, reply: &CapturedSegment, now: Instant) {
        match IpNextHeaderProtocol(reply.protocol) {
            IpNextHeaderProtocols::Sctp => self.handle_sctp_reply(reply, now),
            _ => self.handle_icmp_error(reply, now),
        }
    }

    fn record_port(&mut self, ip: IpAddr, port_num: u16, state: PortState, sender: Option<IpAddr>) {
        self.record_port_answered_by(
            ip,
            port_num,
            state,
            Answer {
                drawn_by: None,
                sender,
                ttl: None,
            },
            None,
        );
    }

    /// One send, first attempt or retry. `position` is `Some` only for a probe
    /// that has never gone out, since the ledger keeps it thereafter.
    ///
    /// The nonce is drawn on the send path because it must never repeat between
    /// attempts: two probes carrying the same tag cannot be told apart by their
    /// answers.
    fn send(&mut self, ip: IpAddr, port: u16, position: Option<u64>, now: Instant) {
        // A retry takes no slot in the window; see the TCP scanner's `send`.
        let first_attempt = position.is_some();
        let Some(src_addr) = self.core.source_for((ip, port), first_attempt) else {
            return;
        };

        let sent = send_probe(
            self.core.transport.tx.as_ref(),
            self.technique,
            self.core.src_port,
            src_addr,
            ip,
            self.core.resolver.zone_of(ip),
            port,
            self.core.emission,
            &self.core.decoys,
        );
        self.core
            .record_send((ip, port), sent.as_ref().map(|_| ()), first_attempt);

        if let Ok(token) = sent {
            match position {
                Some(position) => self.core.ledger.arm(ip, (ip, port), token, position, now),
                None => self.core.ledger.rearm(ip, (ip, port), token, now),
            }
        }
    }
}

/// Sends one probe at `dst_addr:dst_port` and returns the tag it went out
/// carrying, so a later answer can be recognised as this attempt's.
///
/// A failure is returned, not logged, so the scan can sort it by cause and
/// report it once; without it, a scan whose probes never left would look like a
/// filter dropping everything. See
/// [`RawProbeScan::record_send`](super::RawProbeScan::record_send).
#[allow(clippy::too_many_arguments)]
fn send_probe(
    sender: &dyn ProbeSender,
    technique: SctpScanTechnique,
    src_port: u16,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    dst_zone: Option<u32>,
    dst_port: u16,
    emission: Emission,
    decoys: &[IpAddr],
) -> Result<SctpToken, SendError> {
    // Non-zero: RFC 4960 §3.3.2 requires it of an Initiate Tag, and a reflected
    // tag of zero could not be told from a packet that carried none.
    let tag: u32 = rand::random_range(1..=u32::MAX);
    let packet = build(technique, src_port, dst_port, tag);

    // A decoy from each address of the target's family, each with its own port
    // and tag so no probe stands out.
    let decoy_packets: Vec<(IpAddr, Vec<u8>)> = decoys
        .iter()
        .filter(|decoy| decoy.is_ipv4() == dst_addr.is_ipv4())
        .map(|&decoy| {
            let packet = build(
                technique,
                rand::random_range(50_000..u16::MAX),
                dst_port,
                rand::random_range(1..=u32::MAX),
            );
            (decoy, packet)
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
        "sent SCTP {technique} probe to {dst_addr}:{dst_port}"
    );
    Ok(SctpToken { tag })
}

/// The packet `technique` puts on the wire, carrying `tag` wherever that
/// technique's answer will send it back from.
fn build(technique: SctpScanTechnique, src_port: u16, dst_port: u16, tag: u32) -> Vec<u8> {
    match technique {
        SctpScanTechnique::Init => sctp::build_init_probe(src_port, dst_port, tag),
        SctpScanTechnique::CookieEcho => sctp::build_cookie_echo_probe(src_port, dst_port, tag),
    }
}

#[async_trait]
impl PortScanner for SctpPortScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::SctpPort
    }

    fn supported_protocols(&self) -> Vec<Protocol> {
        vec![Protocol::Sctp]
    }

    /// Consumes `targets`, sending one chunk per SCTP target and classifying
    /// every chunk and ICMP error that comes back, until each probe is resolved
    /// or the scan's deadline expires. Anything still outstanding at the end
    /// takes the technique's reading of silence.
    async fn scan(&mut self, targets: mpsc::Receiver<PlannedTarget>) -> Result<(), StrategyError> {
        super::drive(self, targets).await
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

    use pnet_packet::icmp::destination_unreachable::MutableDestinationUnreachablePacket;
    use pnet_packet::icmp::{IcmpCode, IcmpTypes};

    use crate::model::target::Target;
    use crate::scanner::session::ScanSession;
    use crate::transport::probe::{MockSender, SentProbe};

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));
    /// This host's address on [`on_link_interface`], which its probes leave
    /// from.
    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
    /// A router between here and [`TARGET`], which reports errors under its own
    /// address.
    const ROUTER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    /// The chunk types a reply carries, written out from RFC 4960 §3.2 so a wrong
    /// number in [`sctp::chunk_type`] fails these tests.
    const INIT_ACK: u8 = 2;
    const ABORT: u8 = 6;

    type SentProbes = std::sync::Arc<std::sync::Mutex<Vec<SentProbe>>>;

    /// An interface whose /24 contains [`TARGET`], so source resolution answers
    /// on-link without a kernel route probe.
    fn on_link_interface() -> crate::system::interface::Link {
        use crate::system::interface::{Link, LinkAddress};
        Link::new("test0", 0).with_addresses(vec![LinkAddress::new(IpAddr::V4(LOCAL), 24)])
    }

    /// A scanner writing to a recording sender and reading from a channel no
    /// capture feeds, with the session to assert against and the probe log.
    fn scanner_with_mock() -> (SctpPortScanner, ScanSession, SentProbes) {
        scanner_probing(SctpScanTechnique::Init)
    }

    /// The same, sending `technique`'s chunk.
    fn scanner_probing(technique: SctpScanTechnique) -> (SctpPortScanner, ScanSession, SentProbes) {
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(1024);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport = ProbeTransport::from_parts(Box::new(sender), reply_rx);
        let resolver = SourceResolver::from_links(&[on_link_interface()]);
        let scanner = SctpPortScanner::with_transport(resolver, ctx, transport, 8, SCAN_PORT)
            .probing_with(technique);
        (scanner, session, sent)
    }

    /// The port every probe in these tests leaves from.
    const SCAN_PORT: u16 = 50_000;

    /// Sends a probe at `TARGET:port` and returns the tag it carried, read off the
    /// recording sender so the test answers what reached the wire.
    fn probe(scanner: &mut SctpPortScanner, sent: &SentProbes, port: u16) -> u32 {
        let before = sent.lock().unwrap().len();
        scanner.send_probe(PlannedTarget::new(
            u64::from(port),
            Target {
                ip: TARGET,
                port,
                protocol: Protocol::Sctp,
            },
        ));

        let sent = sent.lock().unwrap();
        let (packet, _, _) = sent.get(before).expect("the probe reached the wire");
        // The Initiate Tag: past the twelve-byte common header and the chunk's
        // own four-byte header, per RFC 4960 §3.3.2.
        u32::from_be_bytes([packet[16], packet[17], packet[18], packet[19]])
    }

    /// [`probe`] for a COOKIE-ECHO scan, whose nonce is the common header's
    /// verification tag (RFC 4960 §8.4).
    fn cookie_probe(scanner: &mut SctpPortScanner, sent: &SentProbes, port: u16) -> u32 {
        let before = sent.lock().unwrap().len();
        scanner.send_probe(PlannedTarget::new(
            u64::from(port),
            Target {
                ip: TARGET,
                port,
                protocol: Protocol::Sctp,
            },
        ));

        let sent = sent.lock().unwrap();
        let (packet, _, _) = sent.get(before).expect("the probe reached the wire");
        assert_eq!(
            packet[12],
            sctp::chunk_type::COOKIE_ECHO,
            "a cookie-echo scan must not send an init"
        );
        u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]])
    }

    /// The packet a peer answers an INIT with: the common header carrying the
    /// probe's Initiate Tag as its verification tag, and one chunk of `kind`.
    ///
    /// Built from RFC 4960 §3.3.2 and §8.4 by hand, so the tests assert the
    /// protocol and not the engine's reading of it.
    fn reply(from_port: u16, to_port: u16, tag: u32, kind: u8) -> Vec<u8> {
        let mut packet = Vec::with_capacity(20);
        packet.extend_from_slice(&from_port.to_be_bytes());
        packet.extend_from_slice(&to_port.to_be_bytes());
        packet.extend_from_slice(&tag.to_be_bytes());
        // The CRC32c, which the receive path does not verify.
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.push(kind);
        packet.push(0);
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet
    }

    fn captured(bytes: Vec<u8>) -> CapturedSegment {
        CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Sctp.0, bytes)
    }

    /// An ICMPv4 destination unreachable from `from`, quoting an INIT probe this
    /// scan sent to `port`.
    fn icmp_error(from: IpAddr, code: IcmpCode, port: u16, tag: u32) -> CapturedSegment {
        icmp_error_quoting(from, code, SctpScanTechnique::Init, port, tag)
    }

    /// The same, quoting the probe `technique` actually sends.
    ///
    /// An INIT's common-header verification tag is zero (RFC 4960 §8.5.1), and
    /// that field is a COOKIE-ECHO's whole nonce, so a cookie-echo test needs a
    /// COOKIE-ECHO quotation to exercise anything but the absent-nonce path.
    fn icmp_error_quoting(
        from: IpAddr,
        code: IcmpCode,
        technique: SctpScanTechnique,
        port: u16,
        tag: u32,
    ) -> CapturedSegment {
        let probe = build(technique, SCAN_PORT, port, tag);
        let quoted_ip = crate::protocols::ip::build_ipv4_header(
            LOCAL,
            match TARGET {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => unreachable!("the target is v4"),
            },
            probe.len() as u16,
            IpNextHeaderProtocols::Sctp.0,
            crate::protocols::ip::HOP_LIMIT_ROUTED,
        )
        .expect("an IPv4 header");
        let quoted = [quoted_ip, probe].concat();

        let mut bytes = vec![0u8; 8 + quoted.len()];
        {
            let mut icmp =
                MutableDestinationUnreachablePacket::new(&mut bytes).expect("an ICMP buffer");
            icmp.set_icmp_type(IcmpTypes::DestinationUnreachable);
            icmp.set_icmp_code(code);
            icmp.set_payload(&quoted);
        }
        CapturedSegment::synthetic(from, IpNextHeaderProtocols::Icmp.0, bytes)
    }

    fn port_state(session: &ScanSession, port: u16) -> Option<PortState> {
        session.hosts().get(TARGET).and_then(|host| {
            host.ports()
                .find(|p| p.number() == port && p.protocol() == Protocol::Sctp)
                .map(|p| p.state())
        })
    }

    /// The two answers an INIT draws. Read backwards, every listening port would
    /// report closed while the scan still looked like it worked.
    #[test]
    fn an_init_ack_is_an_open_port_and_an_abort_is_a_closed_one() {
        let (mut scanner, session, sent) = scanner_with_mock();

        let tag = probe(&mut scanner, &sent, 2905);
        scanner.handle_reply(
            &captured(reply(2905, SCAN_PORT, tag, INIT_ACK)),
            Instant::now(),
        );

        let tag = probe(&mut scanner, &sent, 3868);
        scanner.handle_reply(
            &captured(reply(3868, SCAN_PORT, tag, ABORT)),
            Instant::now(),
        );

        assert_eq!(port_state(&session, 2905), Some(PortState::Open));
        assert_eq!(port_state(&session, 3868), Some(PortState::Closed));
    }

    /// Both chunks prove the host is there, and the evidence names which one
    /// arrived.
    #[test]
    fn either_chunk_proves_the_host_and_says_which_it_was() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let tag = probe(&mut scanner, &sent, 3868);
        scanner.handle_reply(
            &captured(reply(3868, SCAN_PORT, tag, ABORT)),
            Instant::now(),
        );

        let host = session.hosts().get(TARGET).expect("the host is recorded");
        assert!(host.status().is_up());
        assert!(
            host.reasons()
                .iter()
                .any(|reason| reason.protocol == StatusProtocol::Sctp
                    && reason.details.as_deref() == Some("abort to an sctp probe")),
            "the abort was not recorded as the chunk it was"
        );

        let port = host
            .ports()
            .find(|port| port.number() == 3868)
            .expect("the port is recorded");
        assert_eq!(
            port.discovery().map(|d| d.reason()),
            Some(&ScanResponse::SctpAbort)
        );
    }

    /// A tag naming no attempt this scan made resolves nothing.
    #[test]
    fn a_reply_carrying_another_tag_resolves_nothing() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let tag = probe(&mut scanner, &sent, 2905);

        scanner.handle_reply(
            &captured(reply(2905, SCAN_PORT, tag.wrapping_add(1), INIT_ACK)),
            Instant::now(),
        );

        assert_eq!(port_state(&session, 2905), None);
        assert!(scanner.core.ledger.contains(&(TARGET, 2905)));
    }

    /// A packet addressed to a port this scan never sent from is not its answer.
    #[test]
    fn a_packet_addressed_elsewhere_is_not_this_scans_answer() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let tag = probe(&mut scanner, &sent, 2905);

        scanner.handle_reply(
            &captured(reply(2905, SCAN_PORT + 1, tag, INIT_ACK)),
            Instant::now(),
        );

        assert_eq!(port_state(&session, 2905), None);
    }

    /// Silence is `NoReply`, because an open SCTP port and a closed one both
    /// answer.
    #[test]
    fn an_unanswered_probe_is_no_reply_rather_than_open_or_no_reply() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 2905);

        super::super::run_out(&mut scanner);

        assert_eq!(port_state(&session, 2905), Some(PortState::NoReply));
        assert_eq!(scanner.silence_means(), PortState::NoReply);
    }

    /// An ICMP refusal is blocked: a closed SCTP port sends its own abort.
    #[test]
    fn an_icmp_refusal_is_blocked_and_not_a_closed_port() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let tag = probe(&mut scanner, &sent, 2905);

        // Protocol unreachable: what a host with no SCTP stack answers.
        scanner.handle_reply(&icmp_error(TARGET, IcmpCode(2), 2905, tag), Instant::now());

        assert_eq!(port_state(&session, 2905), Some(PortState::Blocked));
        let host = session.hosts().get(TARGET).expect("the host is recorded");
        assert!(
            host.status().is_up(),
            "a host refusing a probe under its own address is a host that is there"
        );
    }

    /// The same refusal from the path is blocked without marking the host up.
    #[test]
    fn a_refusal_from_the_path_is_blocked_without_promoting_the_host() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let tag = probe(&mut scanner, &sent, 2905);

        scanner.handle_reply(&icmp_error(ROUTER, IcmpCode(13), 2905, tag), Instant::now());

        assert_eq!(port_state(&session, 2905), Some(PortState::Blocked));
        let host = session.hosts().get(TARGET).expect("the host is recorded");
        assert!(!host.status().is_up());
    }

    // ── The cookie-echo technique ────────────────────────────────────────────

    /// An abort is a closed port to either technique; silence, the difference,
    /// is handled by `silence_means`.
    #[test]
    fn a_cookie_echo_reads_an_abort_as_a_closed_port() {
        let (mut scanner, session, sent) = scanner_probing(SctpScanTechnique::CookieEcho);
        let tag = cookie_probe(&mut scanner, &sent, 3868);
        scanner.handle_reply(
            &captured(reply(3868, SCAN_PORT, tag, ABORT)),
            Instant::now(),
        );

        assert_eq!(port_state(&session, 3868), Some(PortState::Closed));
    }

    /// Nothing a cookie-echo sends can provoke an init-ack, so one arriving
    /// belongs to another association that happened to carry the right tag.
    #[test]
    fn a_cookie_echo_does_not_read_an_init_ack_as_an_open_port() {
        let (mut scanner, session, sent) = scanner_probing(SctpScanTechnique::CookieEcho);
        let tag = cookie_probe(&mut scanner, &sent, 2905);
        scanner.handle_reply(
            &captured(reply(2905, SCAN_PORT, tag, INIT_ACK)),
            Instant::now(),
        );

        assert_eq!(
            port_state(&session, 2905),
            None,
            "an init-ack settled a port for a scan that could not have drawn one"
        );
    }

    /// A listener silently discards a cookie it cannot authenticate, so silence
    /// cannot be told from a filter.
    #[test]
    fn a_cookie_echo_reads_silence_as_open_or_no_reply() {
        let (mut scanner, session, sent) = scanner_probing(SctpScanTechnique::CookieEcho);
        let _ = cookie_probe(&mut scanner, &sent, 2905);
        super::super::run_out(&mut scanner);

        assert_eq!(port_state(&session, 2905), Some(PortState::OpenOrNoReply));
    }

    /// An ICMP error is a filter whichever chunk drew it. A cookie-echo's nonce
    /// sits inside the eight bytes RFC 792 guarantees, so the error names the
    /// exact attempt.
    #[test]
    fn a_cookie_echo_resolves_an_icmp_error_by_the_attempt_it_quotes() {
        let (mut scanner, session, sent) = scanner_probing(SctpScanTechnique::CookieEcho);
        let tag = cookie_probe(&mut scanner, &sent, 3868);
        scanner.handle_reply(
            &icmp_error_quoting(
                TARGET,
                IcmpCode(2),
                SctpScanTechnique::CookieEcho,
                3868,
                tag,
            ),
            Instant::now(),
        );

        assert_eq!(port_state(&session, 3868), Some(PortState::Blocked));
    }

    /// An ICMP error that cannot name the attempt retires nothing.
    ///
    /// RFC 792 guarantees only eight quoted bytes, and an INIT keeps its Initiate
    /// Tag sixteen bytes in behind a header field §8.5.1 requires to be zero, so a
    /// minimal quotation names only the ports, which the scanned host knows and
    /// anybody else can guess in fourteen bits.
    #[test]
    fn a_quotation_too_short_to_name_the_attempt_resolves_no_port() {
        for keep in [8usize, 12, 16] {
            let (mut scanner, session, sent) = scanner_with_mock();
            let real = probe(&mut scanner, &sent, 4000);

            let full = icmp_error(TARGET, IcmpCode(2), 4000, real ^ 0xFFFF_FFFF);
            let mut bytes = full.bytes.clone();
            // Eight bytes of ICMP header, twenty of quoted IPv4 header, then
            // `keep` bytes of the SCTP packet.
            bytes.truncate(8 + 20 + keep);
            let cut = CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Icmp.0, bytes);

            scanner.handle_reply(&cut, Instant::now());
            assert_eq!(
                port_state(&session, 4000),
                None,
                "a quotation of {keep} SCTP bytes named no attempt and must retire none"
            );
            assert_eq!(
                scanner.core.audit.refusals_unattributed, 1,
                "the refusal of {keep} bytes is counted as heard"
            );
        }
    }

    /// A quotation long enough to carry the Initiate Tag still has to carry
    /// *ours*.
    #[test]
    fn a_full_quotation_carrying_another_tag_resolves_no_port() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let real = probe(&mut scanner, &sent, 4001);

        scanner.handle_reply(
            &icmp_error(TARGET, IcmpCode(2), 4001, real ^ 0xFFFF_FFFF),
            Instant::now(),
        );
        assert_eq!(port_state(&session, 4001), None);

        // The same error carrying the tag that really went out does resolve it.
        scanner.handle_reply(&icmp_error(TARGET, IcmpCode(2), 4001, real), Instant::now());
        assert_eq!(port_state(&session, 4001), Some(PortState::Blocked));
    }
}
