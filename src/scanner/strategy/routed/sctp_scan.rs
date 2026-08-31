// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # SCTP Port Probing
//!
//! Implements the privileged SCTP half of [`crate::scanner::scan`]. One INIT
//! chunk per `(address, port)` pair, classified by the chunk that answers it.
//!
//! ## Both verdicts arrive, or something took the probe
//!
//! An SCTP endpoint answers an INIT whichever way its port stands. A listener
//! accepts the association attempt with an INIT-ACK, and a port with nothing
//! behind it refuses outright with an ABORT (RFC 4960 §5.1, §8.4). That makes
//! this the SYN scan's shape rather than the UDP scan's: a live stack always
//! says something, so silence is a filter and not an open port keeping quiet.
//! Neither answer completes an association, and nothing here sends the
//! COOKIE-ECHO that would, so no port is ever left half-open on the target.
//!
//! An ICMP unreachable is read as a filter, and one of its codes is worth
//! knowing about: a host with no SCTP stack at all answers protocol
//! unreachable, so a range that comes back entirely filtered may be a machine
//! that does not speak SCTP rather than a firewall in front of one.
//!
//! ## Tying a reply to its probe
//!
//! Every probe carries a fresh Initiate Tag, which RFC 4960 §3.3.2 obliges the
//! peer to echo in the verification tag of whatever it sends back. That names
//! the attempt, so a retried probe still yields a usable round trip, and it is
//! the SCTP equivalent of the nonce a TCP probe carries.
//!
//! An ICMP error is weaker evidence of the attempt and strong enough evidence
//! of the probe. The eight bytes RFC 792 guarantees reach the two ports and the
//! common header's own verification tag, which for an INIT is zero, so the
//! probe is named by its ports and resolved without a round trip being claimed.
//!
//! ## What this scan does not do
//!
//! There is no service pass behind it: identifying what is behind an SCTP port
//! needs an association, and nothing in this engine holds one. There is no
//! unprivileged form either, so a host that cannot open the raw socket has its
//! SCTP ports refused rather than answered a different way. The segment shaping
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
use crate::protocols::sctp::{self, SctpReply};
use crate::report::ScannerKind;
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::{PortScanner, StrategyError};
use crate::system::interface::SourceResolver;
use crate::transport::capture::CapturedSegment;
use crate::transport::probe::{Emission, ProbeKind, ProbeSender, ProbeTransport};
use crate::{error, success};

use super::icmp_error::{self, Unreachable};
use super::probe_scan::{self, AuditLabels, CoreParts, ProbeTarget, RawPortScan, RawProbeScan};

/// What identifies one attempt of a probe on the wire: the Initiate Tag it went
/// out carrying, which a conformant peer echoes back whichever answer it sends.
///
/// Fresh per attempt, so a retried probe's answer still names which
/// transmission it belongs to and its round trip can be believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SctpToken {
    tag: u32,
}

/// Probes specific `(address, port)` pairs with raw SCTP INIT chunks.
pub struct SctpPortScanner {
    /// Everything a raw port scan carries regardless of protocol. What stays in
    /// this file is what an INIT probe is and what the chunk answering it
    /// proves.
    core: RawProbeScan<SctpToken>,
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
            ProbeKind::SctpInit {
                reply_port: src_port,
            },
            tuning.evasion.effective_send_mode(tuning.send_mode),
        )?;

        Ok(Self {
            core: Self::core(resolver, ctx, transport, &tuning, src_port, target_count),
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
        }
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
        let rate = super::rate_or(tuning.max_probe_rate, super::TCP_PORT_RATE_CEILING);

        RawProbeScan::new(CoreParts {
            resolver,
            ctx,
            transport,
            tuning,
            src_port,
            target_count,
            retry,
            rate,
            deadline: super::DEADLINE_CONFIG,
            pace: retry.min_rto / super::TCP_PORT_WINDOW.floor,
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

        let state = match reply {
            SctpReply::InitAck => PortState::Open,
            SctpReply::Abort => PortState::Closed,
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
    /// packet sent from this scan's own port, aimed at a probe still
    /// outstanding. Which attempt it names is another matter, since the
    /// Initiate Tag sits past the eight bytes an error is obliged to quote, so
    /// the probe is usually resolved without a round trip being claimed.
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
        let token = sctp::quoted_init_tag(error.quoted.payload).map(|tag| SctpToken { tag });

        match error.reason {
            // Nobody could reach the address at all, so the message says nothing
            // about the port it happened to quote and the probe is left to
            // retire on its own schedule.
            Unreachable::Host => self.core.record_host_down(key.0, reply.source),
            // Every other code is a refusal, and none of them is a closed port:
            // a closed SCTP port answers with an ABORT of its own, so an ICMP
            // error means the probe was stopped rather than served. Protocol
            // unreachable is the common one, and it says the host has no SCTP
            // stack at all.
            Unreachable::Port | Unreachable::Prohibited => self.resolve_probe(
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
                        Some(SctpReply::Abort) => "abort to an init probe",
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

    /// A filter. Both an open port and a closed one answer an INIT, so a probe
    /// that draws nothing was stopped on the way out or on the way back.
    fn silence_means(&self) -> PortState {
        PortState::Filtered
    }

    fn audit_labels(&self) -> AuditLabels {
        AuditLabels {
            tag: "sctp-port",
            silence: "filtered",
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
    /// The Initiate Tag is drawn here rather than by the caller, because it is
    /// the one thing that must never repeat between attempts: two probes
    /// carrying the same tag are indistinguishable in their answers.
    fn send(&mut self, ip: IpAddr, port: u16, position: Option<u64>, now: Instant) {
        let Some(src_addr) = self.core.resolver.resolve(ip) else {
            error!(
                verbosity = 2,
                "no route to {ip}; skipping SCTP probe to {ip}:{port}"
            );
            return;
        };

        let first_attempt = !self.core.ledger.contains(&(ip, port));

        let sent = send_init_probe(
            self.core.transport.tx.as_ref(),
            self.core.src_port,
            src_addr,
            ip,
            port,
            self.core.emission,
            &self.core.decoys,
            &mut self.core.send_failure,
        );
        self.core.record_send(sent.is_some(), first_attempt);

        if let Some(token) = sent {
            match position {
                Some(position) => self.core.ledger.arm(ip, (ip, port), token, position, now),
                None => self.core.ledger.rearm(ip, (ip, port), token, now),
            }
        }
    }
}

/// Sends one INIT probe at `dst_addr:dst_port` and returns the tag it went out
/// carrying, so a later answer can be recognised as this attempt's.
///
/// `reason` receives the failure when there is one. A scan whose probes never
/// left reports every port filtered, which is what a firewall produces, and only
/// this says otherwise.
#[allow(clippy::too_many_arguments)]
fn send_init_probe(
    sender: &dyn ProbeSender,
    src_port: u16,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    dst_port: u16,
    emission: Emission,
    decoys: &[IpAddr],
    reason: &mut Option<String>,
) -> Option<SctpToken> {
    // Non-zero, which RFC 4960 §3.3.2 requires of an Initiate Tag and which the
    // builder leaves to its caller.
    let tag: u32 = rand::random_range(1..=u32::MAX);
    let packet = sctp::build_init_probe(src_port, dst_port, tag);

    // A decoy from each address of the target's own family, carrying its own
    // port and tag so none of the probes is the odd one out.
    let decoy_packets: Vec<(IpAddr, Vec<u8>)> = decoys
        .iter()
        .filter(|decoy| decoy.is_ipv4() == dst_addr.is_ipv4())
        .map(|&decoy| {
            let packet = sctp::build_init_probe(
                rand::random_range(50_000..u16::MAX),
                dst_port,
                rand::random_range(1..=u32::MAX),
            );
            (decoy, packet)
        })
        .collect();

    match super::emit_among_decoys(
        sender,
        dst_addr,
        emission,
        src_addr,
        &packet,
        &decoy_packets,
    ) {
        Ok(()) => {
            success!(
                verbosity = 2,
                "sent SCTP init probe to {dst_addr}:{dst_port}"
            );
            Some(SctpToken { tag })
        }
        Err(e) => {
            // `{e:#}` rather than `{e}`: the chained cause is the operating
            // system's own explanation, and "No route to host" and "Permission
            // denied" call for completely different responses. Once, so a scan
            // of a range that cannot be reached reports one failure rather than
            // one per port.
            if reason.is_none() {
                error!(
                    verbosity = 2,
                    "failed to send SCTP init probe to {dst_addr}:{dst_port}: {e:#}"
                );
                *reason = Some(format!("{e:#}"));
            }
            None
        }
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

    /// Consumes `targets`, sending one INIT per SCTP target and classifying
    /// every chunk and ICMP error that comes back, until each probe is resolved
    /// or the scan's deadline expires. Anything still outstanding at the end is
    /// reported filtered.
    async fn scan(&mut self, targets: mpsc::Receiver<PlannedTarget>) -> Result<(), StrategyError> {
        probe_scan::run(self, targets).await;
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

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
    /// This host's address on [`on_link_interface`], which its probes leave
    /// from.
    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
    /// A router between here and [`TARGET`], which reports errors under its own
    /// address rather than the target's.
    const ROUTER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

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
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::channel(1024);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport = ProbeTransport::from_parts(Box::new(sender), reply_rx);
        let resolver = SourceResolver::from_links(&[on_link_interface()]);
        let scanner = SctpPortScanner::with_transport(resolver, ctx, transport, 8, SCAN_PORT);
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

    /// An ICMPv4 destination unreachable from `from`, quoting an SCTP probe this
    /// scan sent to `port`.
    fn icmp_error(from: IpAddr, code: IcmpCode, port: u16, tag: u32) -> CapturedSegment {
        let probe = sctp::build_init_probe(SCAN_PORT, port, tag);
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
                    && reason.details.as_deref() == Some("abort to an init probe")),
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
}
