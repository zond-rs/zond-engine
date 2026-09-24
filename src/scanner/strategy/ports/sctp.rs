// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # SCTP Port Probing
//!
//! Implements the privileged SCTP half of [`crate::scanner::scan`]. One chunk
//! per `(address, port)` pair, classified by the chunk that answers it. Which
//! chunk goes out is
//! [`SctpScanTechnique`]'s to say,
//! and so is what an answer proves; this file is what puts one on the wire and
//! what reads the packet that comes back.
//!
//! ## Both verdicts arrive, or something took the probe
//!
//! An SCTP endpoint answers an INIT whichever way its port stands. A listener
//! accepts the association attempt with an INIT-ACK, and a port with nothing
//! behind it refuses outright with an ABORT (RFC 4960 §5.1, §8.4). That makes
//! this the SYN scan's shape rather than the UDP scan's: a live stack always
//! says something, so silence is a filter and not an open port keeping quiet.
//! Neither answer completes an association, so no port is ever left half-open on
//! the target.
//!
//! A COOKIE-ECHO scan is the other shape. Only the closed port answers, with an
//! ABORT; the listener authenticates a cookie nobody minted, fails, and says
//! nothing. Silence there is open-or-filtered and stays that way however long
//! the scan waits, which is the price of a chunk that crosses filters written
//! against the INIT.
//!
//! An ICMP unreachable is read as a filter, and one of its codes is worth
//! knowing about: a host with no SCTP stack at all answers protocol
//! unreachable, so a range that comes back entirely filtered may be a machine
//! that does not speak SCTP rather than a firewall in front of one.
//!
//! ## Tying a reply to its probe
//!
//! Every probe carries a fresh 32-bit nonce that a conformant answer sends back
//! in its verification tag, so a retried probe still yields a usable round trip.
//! Which field the probe puts it in differs between the two chunks, and
//! the [`sctp`] protocol module has the reasoning; what reaches here is the
//! same tag either way.
//!
//! An ICMP error is where the two part company. The eight bytes RFC 792
//! guarantees reach the two ports and the common header's verification tag,
//! which is a COOKIE-ECHO's nonce and is zero for an INIT. So a COOKIE-ECHO
//! probe is resolved by the exact attempt an error quotes, and an INIT probe
//! only by an error whose sender quoted past the guaranteed eight to its
//! Initiate Tag. An error that stops short names nothing this scan acts on.
//!
//! ## What this scan does not do
//!
//! There is no service pass behind it: identifying what is behind an SCTP port
//! needs an association, and nothing in this engine holds one. There is no
//! unprivileged form of either technique, so a host that cannot open the raw
//! socket has its SCTP ports refused rather than answered a different way. The segment shaping
//! an [`EvasionProfile`](crate::evasion::EvasionProfile) applies is a TCP and
//! UDP measure and is not applied here: an SCTP packet is covered by a CRC32c
//! rather than a checksum a scanner can perturb meaningfully, and padding a
//! chunk changes what the receiver reads rather than only how the packet looks.
//! Decoys still work, since they are a property of the source address rather
//! than of the packet.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pnet_packet::ip::IpNextHeaderProtocols;
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
/// Fresh per attempt, so a retried probe's answer still names which
/// transmission it belongs to and its round trip can be believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SctpToken {
    tag: u32,
}

/// Probes specific `(address, port)` pairs with raw SCTP chunks.
pub struct SctpPortScanner {
    /// Everything a raw port scan carries regardless of protocol. What stays in
    /// this file is what an SCTP probe is and what the chunk answering it
    /// proves.
    core: RawProbeScan<SctpToken>,
    /// Which chunk this scan sends, and so what an answer to it means.
    technique: SctpScanTechnique,
}

impl SctpPortScanner {
    /// Builds a scanner that selects each probe's source via `resolver`, sized
    /// for a scan covering `target_count` `(address, port)` pairs.
    ///
    /// The scan's fixed source port is drawn from the high ephemeral range and
    /// the transport's capture filter is built around it, so what reaches
    /// userspace is this scan's own answers.
    pub fn new(
        resolver: SourceResolver,
        ctx: ScanContext,
        target_count: usize,
        tuning: ProbeTuning,
    ) -> Result<Self, StrategyError> {
        let src_port: u16 = tuning
            .evasion
            .source_port_or(rand::random_range(50_000..u16::MAX));
        let transport = ProbeTransport::open_with(
            ProbeKind::Sctp {
                reply_port: src_port,
            },
            tuning.evasion.effective_send_mode(tuning.send_mode),
        )?;

        Ok(Self {
            core: Self::core(resolver, ctx, transport, &tuning, src_port, target_count),
            technique: tuning.sctp_technique,
        })
    }

    /// Builds a scanner around an already-opened transport, so a caller decides
    /// how probes reach the wire and where replies come from.
    ///
    /// `src_port` must be the port the transport's capture filter was built
    /// around, since it is what makes a captured packet this scan's.
    pub fn with_transport(
        resolver: SourceResolver,
        ctx: ScanContext,
        transport: ProbeTransport,
        target_count: usize,
        src_port: u16,
    ) -> Self {
        let tuning = ProbeTuning::default();
        Self {
            core: Self::core(resolver, ctx, transport, &tuning, src_port, target_count),
            technique: tuning.sctp_technique,
        }
    }

    /// The same, sending `technique`'s chunk rather than the default INIT.
    ///
    /// The seam a test drives a COOKIE-ECHO scan through, and the one a caller
    /// assembling their own scan reaches for when they are building the
    /// transport themselves.
    #[must_use]
    pub fn probing_with(mut self, technique: SctpScanTechnique) -> Self {
        self.technique = technique;
        self
    }

    /// The core an SCTP port scan runs on.
    ///
    /// The TCP port scanner's profiles, and for its reason: an INIT is answered
    /// by the target's own stack as fast as the link allows, so the schedule
    /// that suits a SYN suits this. The UDP profiles would be wrong here, since
    /// what they are stretched around is an ICMP rate limit that this scan's
    /// ordinary answers do not pass through.
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

        // A packet addressed anywhere but this scan's own port belongs to
        // somebody else's association. The capture filter already narrows to it,
        // which is a performance boundary rather than a guarantee, and this is
        // what makes the reply ours.
        if packet.destination_port() != self.core.src_port {
            self.core.audit.record_off_target();
            return;
        }

        let Some(reply) = sctp::classify_probe_response(&packet) else {
            self.core.audit.record_off_target();
            return;
        };

        // A chunk the technique has no verdict for did not answer this probe.
        // Nothing a COOKIE-ECHO sends can provoke an INIT-ACK, so one arriving
        // there is another association's, and resolving a port on it would
        // report a listener on the strength of a coincidence.
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
    /// Checked as strictly as an SCTP reply: the quotation has to be an SCTP
    /// packet sent from this scan's own port, carrying the nonce of an attempt
    /// still outstanding.
    ///
    /// Whether it carries one depends on the technique, because the two put
    /// their nonce in different places. A COOKIE-ECHO carries it in the common
    /// header, inside the eight bytes RFC 792 guarantees, so an error names the
    /// exact attempt and a refusal credits the round trip. An INIT's Initiate
    /// Tag sits sixteen bytes in, past what a sender has to quote, so an error
    /// about one is acted on only where the sender quoted that far. One that
    /// stopped short is not acted on at all, whatever its code: it retires no
    /// probe and files nothing against the host.
    fn handle_icmp_error(&mut self, reply: &CapturedSegment, now: Instant) {
        let Some(error) = icmp_error::parse(reply) else {
            return;
        };
        if error.quoted.protocol != IpNextHeaderProtocols::Sctp {
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
            // Already read, and always present: it is the common header's own
            // field. Zero would mean a quotation of something this scan did not
            // send, since every probe leaves with a non-zero tag.
            SctpScanTechnique::CookieEcho => Some(quoted.verification_tag).filter(|tag| *tag != 0),
        };

        // **An error that cannot name the attempt is not acted on.**
        //
        // The two techniques differ in where the nonce sits, and only one of
        // them survives a minimal quotation. A COOKIE-ECHO's is the common
        // header's verification tag, inside the eight bytes RFC 792 guarantees.
        // An INIT's Initiate Tag is sixteen bytes in, and the header field that
        // *is* guaranteed must be zero for an INIT (RFC 4960 §8.5.1) — so a
        // sender that quotes only the minimum names an INIT probe's ports and
        // nothing that distinguishes one attempt, or one sender, from another.
        //
        // Resolving on that would be resolving on the ports alone, which
        // anybody who knows the scan's source port can supply. The source port
        // is in every probe this scan sends, so the target of the scan has it
        // for free and an off-path guesser has fourteen bits of it — once, for
        // the whole run. A forged Port Unreachable would retire the probe as
        // filtered, remove it from the ledger so that no retransmission follows,
        // and record `IcmpProhibited` against the target as the evidence.
        //
        // Refusing costs almost nothing, which is what makes this the right
        // trade rather than a cautious one: an INIT scan already reads silence
        // as filtered, so a probe left outstanding here reaches the *same*
        // verdict by its own retry schedule. What is given up is an earlier
        // resolution and an evidence label, and what is bought is that neither
        // can be forged.
        //
        // The gate stands in front of every code, `Unreachable::Host` included.
        // A missing nonce here does not only mean a short quotation: for a
        // COOKIE-ECHO it means a quoted tag of zero, and for an INIT a quoted
        // packet whose first chunk is not an INIT, and both say the quotation is
        // of nothing this scan sent. So a host unreachable that names no attempt
        // files nothing against the host either, and that includes one about an
        // INIT from a sender that quoted only the minimum. There this scanner is
        // stricter than the TCP and UDP ones, which file a host down on the key
        // alone when the quotation carries no nonce.
        let Some(nonce) = nonce else {
            self.core.audit.record_reply_without_rtt();
            return;
        };
        let token = Some(SctpToken { tag: nonce });

        match error.reason {
            // Nobody could reach the address at all, so the message says nothing
            // about the port it happened to quote and the probe is left to
            // retire on its own schedule.
            Unreachable::Host => {
                self.core.record_host_down(&key, token, reply.source);
            }
            // Every other code is a refusal, and none of them is a closed port:
            // a closed SCTP port answers with an ABORT of its own, so an ICMP
            // error means the probe was stopped rather than served. Protocol
            // unreachable is the common one, and it says the host has no SCTP
            // stack at all - which is not a closed port, so it lands here with
            // the rest. The pass that asks about protocols reads it for what it
            // says.
            Unreachable::Port | Unreachable::Prohibited | Unreachable::Protocol => self
                .resolve_probe(
                    key,
                    token,
                    PortState::Filtered,
                    Answer {
                        drawn_by: None,
                        sender: Some(reply.source),
                        // The distance to whatever refused the probe rather than to
                        // the target, which is how a middlebox answering on the
                        // host's behalf gives itself away.
                        ttl: reply.observation.map(IpObservation::remaining_hops),
                    },
                    now,
                ),
        }
    }

    /// Retires one outstanding probe with the state its reply established,
    /// crediting whatever round trip the ledger is willing to vouch for.
    ///
    /// A reply matching no live attempt resolves nothing: it is a stray or
    /// spoofed packet, a duplicate of one already acted on, or an answer to a
    /// probe already written off.
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
            (PortState::Filtered, Some(sender)) if sender == ip => Some((
                HostStatus::Up,
                StatusReason::new(
                    StatusProtocol::IcmpUnreachable,
                    "unreachable for a probed sctp port, from the host",
                ),
            )),
            (PortState::Filtered, Some(sender)) => Some((
                HostStatus::Filtered,
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
/// `None` where nothing arrived: a probe that timed out has no packet to name,
/// and the sweep that gives up on it records that separately.
fn port_evidence(
    state: PortState,
    drawn_by: Option<SctpReply>,
    sender: Option<IpAddr>,
    target: IpAddr,
) -> Option<ScanResponse> {
    match (state, drawn_by, sender) {
        (_, Some(SctpReply::InitAck), _) => Some(ScanResponse::SctpInitAck),
        (_, Some(SctpReply::Abort), _) => Some(ScanResponse::SctpAbort),
        (PortState::Filtered, None, Some(from)) => Some(match from == target {
            true => ScanResponse::IcmpProhibited,
            false => ScanResponse::IcmpUnreachable,
        }),
        (PortState::Filtered, None, None) => Some(ScanResponse::NoResponse),
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
    /// by a closed port, so silence is open-or-filtered and stays so.
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
        match reply.protocol {
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
    /// The nonce is drawn on the send path rather than by the caller, because it
    /// is the one thing that must never repeat between attempts: two probes
    /// carrying the same tag are indistinguishable in their answers.
    fn send(&mut self, ip: IpAddr, port: u16, position: Option<u64>, now: Instant) {
        let Some(src_addr) = self.core.resolver.resolve(ip) else {
            self.core.record_no_route(ip);
            return;
        };

        let first_attempt = !self.core.ledger.contains(&(ip, port));

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
/// A failure comes back whole rather than logged here, so the scan can sort it
/// by whose fact it is and report it once. A scan whose probes never left
/// reports every port filtered, which is what a firewall produces, and only the
/// failure says otherwise. See
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
    // Non-zero either way: RFC 4960 §3.3.2 requires it of an Initiate Tag, and a
    // reflected verification tag of zero would not be distinguishable from a
    // packet that carried none.
    let tag: u32 = rand::random_range(1..=u32::MAX);
    let packet = build(technique, src_port, dst_port, tag);

    // A decoy from each address of the target's own family, carrying its own
    // port and tag so none of the probes is the odd one out.
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
        super::drive(self, targets).await;
        Ok(())
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
    /// address rather than the target's.
    const ROUTER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    /// The chunk types a reply carries, written out from RFC 4960 §3.2 rather
    /// than read from [`sctp::chunk_type`], so a wrong number in the engine
    /// fails these tests instead of agreeing with itself.
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
    /// capture feeds, plus the session store to assert against and the probe log
    /// to read tags back out of.
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

    /// The port every probe in these tests leaves from, which is what the
    /// scanner recognises its own answers by.
    const SCAN_PORT: u16 = 50_000;

    /// Sends a probe at `TARGET:port` and returns the tag it went out carrying,
    /// read back off the recording sender rather than out of the scanner, so
    /// what a test answers is what actually reached the wire.
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

    /// [`probe`] for a COOKIE-ECHO scan, whose nonce is the common header's own
    /// verification tag (RFC 4960 §8.4) rather than a tag inside the chunk.
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
    /// Built here from RFC 4960 §3.3.2 and §8.4 rather than from this crate's
    /// own builders, so what these tests assert is the protocol rather than the
    /// engine's reading of it.
    fn reply(from_port: u16, to_port: u16, tag: u32, kind: u8) -> Vec<u8> {
        let mut packet = Vec::with_capacity(20);
        packet.extend_from_slice(&from_port.to_be_bytes());
        packet.extend_from_slice(&to_port.to_be_bytes());
        packet.extend_from_slice(&tag.to_be_bytes());
        // The CRC32c, which nothing in the receive path verifies: a reply is
        // ours because it carries the tag we sent.
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.push(kind);
        packet.push(0);
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet
    }

    fn captured(bytes: Vec<u8>) -> CapturedSegment {
        CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Sctp, bytes)
    }

    /// An ICMPv4 destination unreachable from `from`, quoting an INIT probe this
    /// scan sent to `port`.
    fn icmp_error(from: IpAddr, code: IcmpCode, port: u16, tag: u32) -> CapturedSegment {
        icmp_error_quoting(from, code, SctpScanTechnique::Init, port, tag)
    }

    /// The same, quoting the probe `technique` actually sends.
    ///
    /// The two techniques carry their nonce in different fields, so an error
    /// quoting an INIT cannot exercise a COOKIE-ECHO scan's correlation: an
    /// INIT's common-header verification tag is zero (RFC 4960 §8.5.1), and
    /// that field is the whole of a COOKIE-ECHO's nonce. A cookie-echo test
    /// handed an INIT quotation is therefore testing the path where the nonce
    /// is *absent*, whatever its name says — which is how the unauthenticated
    /// resolution this parameter exists to stop went unnoticed.
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
            IpNextHeaderProtocols::Sctp,
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
        CapturedSegment::synthetic(from, IpNextHeaderProtocols::Icmp, bytes)
    }

    fn port_state(session: &ScanSession, port: u16) -> Option<PortState> {
        session.hosts().get(TARGET).and_then(|host| {
            host.ports()
                .find(|p| p.number() == port && p.protocol() == Protocol::Sctp)
                .map(|p| p.state())
        })
    }

    /// The two answers an INIT draws, and the opposite things they prove. Read
    /// backwards this reports every listening port closed, which is the one
    /// mistake an INIT scan can make that looks like a working scan.
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
    /// arrived. A report that called an abort an acceptance would describe a
    /// packet nobody sent.
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

    /// A tag naming no attempt this scan made is somebody else's association,
    /// and resolving a port on it would be resolving it on a coincidence.
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

    /// A packet addressed to a port this scan never sent from answered somebody
    /// else. The capture filter narrows to the scan's port, which is a
    /// performance boundary rather than a guarantee.
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

    /// Silence is a filter here rather than the open-or-filtered a UDP scan
    /// reports, because both an open SCTP port and a closed one answer.
    #[test]
    fn an_unanswered_probe_is_filtered_rather_than_open_filtered() {
        let (mut scanner, session, sent) = scanner_with_mock();
        probe(&mut scanner, &sent, 2905);

        scanner.resolve_remaining();

        assert_eq!(port_state(&session, 2905), Some(PortState::Filtered));
        assert_eq!(scanner.silence_means(), PortState::Filtered);
    }

    /// A closed SCTP port sends an abort of its own, so an ICMP refusal is
    /// something stopping the probe rather than a port saying no.
    #[test]
    fn an_icmp_refusal_is_a_filter_and_not_a_closed_port() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let tag = probe(&mut scanner, &sent, 2905);

        // Protocol unreachable: what a host with no SCTP stack answers.
        scanner.handle_reply(&icmp_error(TARGET, IcmpCode(2), 2905, tag), Instant::now());

        assert_eq!(port_state(&session, 2905), Some(PortState::Filtered));
        let host = session.hosts().get(TARGET).expect("the host is recorded");
        assert!(
            host.status().is_up(),
            "a host refusing a probe under its own address is a host that is there"
        );
    }

    /// The same refusal from the path is a perimeter rather than the host's own
    /// policy, and a middlebox answering must not be read as the host being up.
    #[test]
    fn a_refusal_from_the_path_is_filtered_without_promoting_the_host() {
        let (mut scanner, session, sent) = scanner_with_mock();
        let tag = probe(&mut scanner, &sent, 2905);

        scanner.handle_reply(&icmp_error(ROUTER, IcmpCode(13), 2905, tag), Instant::now());

        assert_eq!(port_state(&session, 2905), Some(PortState::Filtered));
        let host = session.hosts().get(TARGET).expect("the host is recorded");
        assert!(!host.status().is_up());
    }

    // ── The cookie-echo technique ────────────────────────────────────────────

    /// The verdict table one protocol over. An abort is a closed port to either
    /// technique; silence is the difference, and it is handled by
    /// `silence_means` rather than here.
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

    /// Nothing a cookie-echo sends can provoke an init-ack, so one arriving is
    /// another association's traffic that happened to carry the right tag.
    /// Resolving a port on it would report a listener on a coincidence.
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

    /// The price of the quieter chunk. A listener discards a cookie it cannot
    /// authenticate without a word, so silence here cannot be told from a
    /// filter, where an init scan would have called it filtered outright.
    #[test]
    fn a_cookie_echo_reads_silence_as_open_or_filtered() {
        let (mut scanner, session, sent) = scanner_probing(SctpScanTechnique::CookieEcho);
        let _ = cookie_probe(&mut scanner, &sent, 2905);
        scanner.resolve_remaining();

        assert_eq!(port_state(&session, 2905), Some(PortState::OpenFiltered));
    }

    /// An icmp error is still a filter and still not a closed port, whichever
    /// chunk drew it: a closed SCTP port answers with an abort of its own.
    ///
    /// What differs is the attribution. A cookie-echo's nonce sits in the common
    /// header, inside the eight bytes RFC 792 guarantees, so the error names the
    /// exact attempt rather than only the probe.
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

        assert_eq!(port_state(&session, 3868), Some(PortState::Filtered));
    }

    /// **An ICMP error that cannot name the attempt retires nothing.**
    ///
    /// RFC 792 guarantees only eight quoted bytes, and an INIT keeps its
    /// Initiate Tag sixteen bytes in behind a header field §8.5.1 requires to
    /// be zero. So a minimal quotation names the ports and nothing else — and
    /// the ports are in every probe the scan sends, which is to say they are
    /// known to the host being scanned and are fourteen bits to anybody else.
    #[test]
    fn a_quotation_too_short_to_name_the_attempt_resolves_no_port() {
        for keep in [8usize, 12, 16] {
            let (mut scanner, session, sent) = scanner_with_mock();
            let real = probe(&mut scanner, &sent, 4000);

            let full = icmp_error(TARGET, IcmpCode(2), 4000, real ^ 0xFFFF_FFFF);
            let mut bytes = full.bytes.clone();
            // Eight bytes of ICMP header, twenty of quoted IPv4 header, then
            // however much of the SCTP packet this sender bothered to include.
            bytes.truncate(8 + 20 + keep);
            let cut = CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Icmp, bytes);

            scanner.handle_reply(&cut, Instant::now());
            assert_eq!(
                port_state(&session, 4000),
                None,
                "a quotation of {keep} SCTP bytes named no attempt and must retire none"
            );
        }
    }

    /// And one generous enough to carry the Initiate Tag still has to carry
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
        assert_eq!(port_state(&session, 4001), Some(PortState::Filtered));
    }
}
