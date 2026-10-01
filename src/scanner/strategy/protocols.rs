// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Which IP protocols a host takes delivery of
//!
//! A diagnostic pass, run after the ports are known and only against hosts that
//! answered, shaped like the filter characterisation
//! [`ZondConfig::characterise`](crate::config::ZondConfig::characterise) turns
//! on: a bounded set of probes per host, one listening window, and conclusions
//! recorded on the host.
//!
//! One datagram goes out under each protocol number asked about, and the host's
//! ICMP is the answer:
//!
//! - **A protocol unreachable**: the stack does not implement the number, so
//!   [`Closed`](IpProtocolState::Closed). ICMPv6 reports it as a Parameter
//!   Problem; `icmp_error` resolves both to one meaning.
//! - **A port unreachable**: the stack implements the number, handed the
//!   datagram to that transport and found nothing listening. It proves
//!   acceptance without the protocol answering for itself, which is why UDP
//!   gets a real header.
//! - **Any other unreachable**: the path refused delivery, so
//!   [`Blocked`](IpProtocolState::Blocked); it says nothing about the host.
//! - **An echo reply**, for the two ICMP numbers: the host answering in the
//!   protocol asked about.
//! - **Silence**: [`OpenOrNoReply`](IpProtocolState::OpenOrNoReply), the
//!   ordinary answer.
//!
//! Silence is ordinary because GRE, ESP, AH, OSPF and PIM answer an unsolicited
//! bare header with nothing whether or not the stack implements them; the useful
//! finding is a refusal.
//!
//! TCP and SCTP would answer for themselves (a reset, an abort), but the
//! capture filter is ICMP alone (see [`ProbeKind::IpProtocol`]). Widening it
//! would admit every TCP and SCTP segment on every captured interface to learn
//! what a port scan already establishes, so those two are reported from their
//! ICMP or not at all.
//!
//! The kernel takes a raw Layer-4 socket's next-header value from the socket, so
//! each protocol number needs its own sender; writing the IP header here would
//! mean routing it here too. A number whose socket the kernel refuses is left
//! [`Unasked`](IpProtocolState::Unasked).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};

use crate::model::host::IpProtocolState;
use crate::protocols::{icmp, sctp, tcp, udp};
use crate::report::ScannerKind;
use crate::scanner::session::{ProbeClaim, ScanContext};
use crate::scanner::strategy::icmp_error::{self, Unreachable};
use crate::system::interface::SourceResolver;
use crate::transport::frame::IpSegment;
use crate::transport::probe::{Emission, ProbeKind, ProbeTransport};
use crate::transport::raw::{self, TransportSenderHandle};
use crate::{counted, info};

/// How long to listen once the last probe has left.
///
/// The same window [`characterise`](super::topology::characterise) waits: the
/// tail for a slow path. Each probe is sent once.
const REPLY_WINDOW: Duration = Duration::from_secs(2);

/// The protocols worth asking about when a caller names none.
///
/// A curated set, like
/// [`PortSet::top_tcp`](crate::model::port::PortSet::top_tcp). Each number is
/// a transport a host might terminate or a protocol that says what a machine is
/// for: a tunnel endpoint answers for 47, 50 or 51, a router for 89, 103 or 112,
/// and a multicast segment for 2.
///
/// Each number costs a socket, so the full 0..=255 range is only sent when a
/// caller asks for it.
pub const DEFAULT_PROTOCOLS: &[u8] = &[1, 2, 4, 6, 17, 41, 47, 50, 51, 89, 103, 112, 132];

/// The source port every probe that has one leaves from, drawn afresh for each
/// pass and correlated on.
///
/// Destination and protocol alone are known to the host being scanned, so a
/// forged unreachable could settle a verdict either way; the drawn port is the
/// part of a quoted probe a stranger has to guess. It does nothing for
/// protocols sent without a header; see [`Correlation::admits`].
fn draw_source_port() -> u16 {
    rand::random_range(50_000..u16::MAX)
}

/// The port a probe carrying a transport header is addressed to.
///
/// High and unassigned, so a stack implementing the transport almost certainly
/// has nothing listening and answers with a port unreachable. A listener would
/// answer in the transport, which this pass does not capture.
const CLOSED_PORT: u16 = 54_321;

/// The identifier the echo probes carry, drawn per pass, so this pass's echo
/// replies are told apart from the discovery sweep's under the same capture and
/// from a stranger's.
fn draw_echo_identifier() -> u16 {
    rand::random()
}

/// What a reply has to carry to be this pass's.
///
/// Built once per pass. The two numbers are what a quotation brings back of a
/// probe; `sources` is the set of addresses probes left from, the only evidence
/// for a protocol whose datagram is a bare header.
#[derive(Debug, Clone)]
struct Correlation {
    source_port: u16,
    echo_identifier: u16,
    sources: BTreeSet<IpAddr>,
}

impl Correlation {
    /// Whether the datagram an ICMP error quotes is one this pass sent.
    ///
    /// **Tiered.** A quotation carries the IP header and, per RFC 792, at least
    /// the first eight bytes after it:
    ///
    /// - Every protocol: the quoted *source* address must be one this pass sent
    ///   from.
    /// - The four this crate builds a header for: the eight bytes reach the
    ///   ports or the echo identifier, so the drawn
    ///   [`source_port`](Self::source_port) (~16 bits to guess) is checked too.
    /// - Everything else (GRE, ESP, AH, OSPF, PIM, and an ICMP number asked of
    ///   the other family) is sent bare, so the source address is all there is;
    ///   such a verdict rests on less evidence than one for TCP.
    ///
    /// The tier comes from [`Header::of`], which also built the probe.
    fn admits(&self, quoted: &IpSegment<'_>, number: u8) -> bool {
        if !self.sources.contains(&quoted.source) {
            return false;
        }

        match Header::of(number, quoted.destination) {
            // An echo request carries its identifier at offset four, inside the
            // guaranteed eight.
            Header::Echo => icmp::echo_token(quoted.payload)
                .is_ok_and(|(identifier, _)| identifier == self.echo_identifier),
            // The three transports whose header begins with the two ports.
            Header::Tcp => tcp::quoted_probe(quoted.payload)
                .is_some_and(|probe| probe.source == self.source_port),
            Header::Udp => {
                udp_quoted_source(quoted.payload).is_some_and(|port| port == self.source_port)
            }
            Header::Sctp => sctp::quoted_probe(quoted.payload)
                .is_some_and(|probe| probe.source == self.source_port),
            // The source address above is all there is.
            Header::Bare => true,
        }
    }
}

/// What a probe carries after the IP header the kernel writes, which is also
/// what a quotation of it can be checked for.
///
/// [`probe_payload`] builds what this names and [`Correlation::admits`] checks a
/// quotation for it, so the two cannot disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Header {
    /// An echo request, carrying the pass's identifier.
    Echo,
    /// A SYN from the pass's source port.
    Tcp,
    /// An empty datagram from the pass's source port.
    Udp,
    /// An INIT from the pass's source port.
    Sctp,
    /// Nothing: the IP header is the whole probe.
    Bare,
}

impl Header {
    /// What a probe of `number` to `host` carries.
    ///
    /// The ICMP numbers depend on the family: 1 asked of an IPv6 host and 58 of
    /// an IPv4 one go out bare.
    fn of(number: u8, host: IpAddr) -> Self {
        match (number, host) {
            (1, IpAddr::V4(_)) | (58, IpAddr::V6(_)) => Self::Echo,
            (6, _) => Self::Tcp,
            (17, _) => Self::Udp,
            (132, _) => Self::Sctp,
            _ => Self::Bare,
        }
    }
}

/// The source port a quoted UDP header names, or `None` where the quotation
/// stopped short of one.
fn udp_quoted_source(quoted: &[u8]) -> Option<u16> {
    let head: &[u8; 2] = quoted.first_chunk()?;
    Some(u16::from_be_bytes(*head))
}

/// Asks each host in `targets` which of `protocols` its stack takes delivery of,
/// and records the answers.
///
/// Every host is left with a verdict for every protocol asked about, including
/// those nothing answered for.
pub async fn probe(ctx: &ScanContext, targets: &[IpAddr], protocols: &BTreeSet<u8>) {
    if targets.is_empty() || protocols.is_empty() {
        return;
    }

    let Some((mut transport, senders)) = open(ctx, protocols) else {
        return;
    };

    let mut resolver = SourceResolver::from_system();

    info!(
        "asking {} about {}",
        counted(targets.len() as u128, "host", "hosts"),
        counted(senders.len() as u128, "IP protocol", "IP protocols")
    );

    // Drawn once: probes are built from it and answers checked against it.
    let mut keys = Correlation {
        source_port: draw_source_port(),
        echo_identifier: draw_echo_identifier(),
        sources: BTreeSet::new(),
    };

    let owed = Owed::resolve(targets, &senders, &mut resolver, &mut keys);

    // Sets, since every ICMP message on the host is checked against them.
    let listening = Listening {
        probed: targets.iter().copied().collect(),
        asked: senders.keys().copied().collect(),
        keys,
    };
    send_probes(ctx, owed, &senders, &mut transport, &listening).await;
    collect_replies(ctx, &mut transport, &listening).await;
}

/// What an answer is matched against: the hosts asked, the numbers that got a
/// socket, and the identity the probes carried.
struct Listening {
    probed: BTreeSet<IpAddr>,
    asked: BTreeSet<u8>,
    keys: Correlation,
}

impl Listening {
    /// Raises whatever `reply` establishes, where it is an answer to this pass.
    fn settle(&self, ctx: &ScanContext, reply: &crate::transport::capture::CapturedSegment) {
        if let Some((host, number, state)) = matched(reply, &self.probed, &self.asked, &self.keys) {
            ctx.update_host(host, |host| {
                host.record_ip_protocol(number, state);
            });
        }
    }
}

/// One probe the pass owes: a protocol number to ask a host about, and the
/// address it leaves from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Question {
    host: IpAddr,
    number: u8,
    source: IpAddr,
}

/// The probes a pass still owes, in the order they are owed.
///
/// Each is one probe at its host for the pacing gaps. The pass asks a dozen
/// numbers of every host, so taking whichever owed probe is ready lets it ask
/// the next host while the last one's per-host gap runs.
#[derive(Debug, Default)]
struct Owed {
    pending: VecDeque<Question>,
}

impl Owed {
    /// Every question the pass owes `targets`, one per number in `senders`,
    /// each from the source address the routing table picks for its host.
    ///
    /// A host with no source address is skipped entirely, so no silence is
    /// recorded for probes that never left.
    fn resolve<S>(
        targets: &[IpAddr],
        senders: &BTreeMap<u8, S>,
        resolver: &mut SourceResolver,
        keys: &mut Correlation,
    ) -> Self {
        let mut pending = VecDeque::new();
        for &host in targets {
            let Some(source) = resolver.resolve(host) else {
                continue;
            };
            // Collected here, so the set holds the addresses probes really
            // left from.
            keys.sources.insert(source);
            pending.extend(senders.keys().map(|&number| Question {
                host,
                number,
                source,
            }));
        }
        Self { pending }
    }

    /// The first owed question whose host's slot is free, taken off the queue
    /// with the slot it claimed; or, where none is, when the first will be.
    ///
    /// `None` once nothing is owed. A question turned away stays queued.
    fn take_ready(
        &mut self,
        ctx: &ScanContext,
        now: Instant,
    ) -> Option<Result<(Question, ProbeClaim), Instant>> {
        if self.pending.is_empty() {
            return None;
        }
        // Every probe spends the scan-wide gap.
        if let Some(ready) = ctx.group_probe_ready_at(now) {
            return Some(Err(ready));
        }
        let mut earliest: Option<Instant> = None;
        for index in 0..self.pending.len() {
            let question = self.pending[index];
            let ready = match ctx.probe_ready_at(question.host, now) {
                Some(ready) => ready,
                None => match ctx.claim_probe(question.host) {
                    Ok(claim) => {
                        self.pending.remove(index);
                        return Some(Ok((question, claim)));
                    }
                    Err(ready) => ready,
                },
            };
            earliest = Some(earliest.map_or(ready, |earliest| earliest.min(ready)));
        }
        // Something was pending and nothing was ready, so something is held.
        Some(Err(earliest.unwrap_or(now)))
    }

    /// Records every question still owed as unasked.
    fn abandon(self, ctx: &ScanContext) {
        for question in self.pending {
            ctx.update_host(question.host, |host| {
                host.record_ip_protocol(question.number, IpProtocolState::Unasked);
            });
        }
    }
}

/// One capture for the whole pass, and one sender per protocol.
///
/// The capture is opened receive-only, since a [`ProbeTransport`]'s sender
/// speaks one protocol. The number handed to [`ProbeKind::IpProtocol`] reaches
/// only the filter, which is the same for every number.
///
/// A number whose socket the kernel refuses is dropped with a failure recorded.
/// [`None`] where there is no capture or no socket at all.
fn open(
    ctx: &ScanContext,
    protocols: &BTreeSet<u8>,
) -> Option<(ProbeTransport, BTreeMap<u8, TransportSenderHandle>)> {
    let first = protocols.iter().copied().next()?;

    let transport = match ProbeTransport::open_receiver_capturing(
        ProbeKind::IpProtocol { number: first },
        &ctx.capture_links(),
    ) {
        Ok(transport) => transport,
        Err(failure) => {
            ctx.record_failure(
                ScannerKind::Routed,
                format!("no capture to hear IP protocol answers on: {failure}"),
            );
            return None;
        }
    };

    let mut senders = BTreeMap::new();
    for number in protocols.iter().copied() {
        match raw::open_sender(raw::TransportType::IpProtocol(number)) {
            Ok(handle) => {
                senders.insert(number, handle);
            }
            Err(failure) => ctx.record_failure(
                ScannerKind::Routed,
                format!("no socket for IP protocol {number}, so it goes unasked: {failure:#}"),
            ),
        }
    }

    if senders.is_empty() {
        ctx.record_failure(
            ScannerKind::Routed,
            "no raw socket for any IP protocol asked about".to_string(),
        );
        return None;
    }

    Some((transport, senders))
}

/// Sends one probe per host and protocol, recording what each is owed.
///
/// Each probe claims its pacing slot just before it leaves; while none is free
/// the pass waits for the first that will be, reading answers meanwhile. A send
/// the kernel refused gives its slot back and is recorded unasked.
///
/// A stop ends a wait at once, and every probe not yet sent is recorded
/// unasked. The listening window runs from the last send.
async fn send_probes(
    ctx: &ScanContext,
    mut owed: Owed,
    senders: &BTreeMap<u8, TransportSenderHandle>,
    transport: &mut ProbeTransport,
    listening: &Listening,
) {
    let mut capturing = true;
    loop {
        if ctx.handle.should_stop() {
            owed.abandon(ctx);
            return;
        }
        let (question, claim) = match owed.take_ready(ctx, Instant::now()) {
            None => return,
            Some(Ok(ready)) => ready,
            Some(Err(ready)) => {
                tokio::select! {
                    () = ctx.handle.stopping() => {}
                    () = tokio::time::sleep_until(ready.into()) => {}
                    reply = transport.rx.recv(), if capturing => match reply {
                        Some(reply) => listening.settle(ctx, &reply),
                        None => capturing = false,
                    },
                }
                continue;
            }
        };

        let Question {
            host,
            number,
            source,
        } = question;
        let payload = probe_payload(number, source, host, &listening.keys);
        let sent = senders.get(&number).is_some_and(|sender| {
            sender
                .send_to(Datagram(&payload), host, None, Emission::routed().hop_limit)
                .is_ok()
        });
        if !sent {
            ctx.refund_probe(claim);
        }

        // Recorded before any answer, so the protocol shows as asked even if
        // none comes. The reply loop only raises these.
        let state = match sent {
            true => IpProtocolState::OpenOrNoReply,
            false => IpProtocolState::Unasked,
        };
        ctx.update_host(host, |host| {
            host.record_ip_protocol(number, state);
        });
    }
}

/// What a probe of `number` carries after the IP header the kernel writes.
///
/// A real header for the four protocols this crate can build one for, nothing
/// for the rest. An empty datagram draws a *protocol unreachable*, since the IP
/// layer refuses the number before any transport sees it, but not an
/// acceptance: a transport drops a truncated datagram silently, where a
/// well-formed one draws the port unreachable read as proof of delivery.
fn probe_payload(number: u8, source: IpAddr, host: IpAddr, keys: &Correlation) -> Vec<u8> {
    let built = match Header::of(number, host) {
        Header::Echo => {
            icmp::build_echo_request_message(source, host, 0, keys.echo_identifier, 0, &[])
        }
        Header::Tcp => tcp::build_probe(
            crate::model::technique::TcpScanTechnique::Syn,
            source,
            host,
            keys.source_port,
            CLOSED_PORT,
            rand::random(),
        ),
        Header::Udp => udp::build_packet(source, host, keys.source_port, CLOSED_PORT, Vec::new()),
        Header::Sctp => Ok(sctp::build_init_probe(
            keys.source_port,
            CLOSED_PORT,
            rand::random(),
        )),
        Header::Bare => return Vec::new(),
    };

    // A failed build still sends the bare datagram. Only a source of the other
    // family fails, which the resolver does not hand back; its refusal would go
    // unread, since the quotation lacks the header `Header::of` expects.
    built.unwrap_or_default()
}

/// Listens out the window and raises whatever the answers establish.
async fn collect_replies(ctx: &ScanContext, transport: &mut ProbeTransport, listening: &Listening) {
    let deadline = Instant::now() + REPLY_WINDOW;
    loop {
        if ctx.handle.should_stop() {
            return;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }

        match tokio::time::timeout(remaining, transport.rx.recv()).await {
            Ok(Some(reply)) => listening.settle(ctx, &reply),
            // The stream closed or the window elapsed.
            Ok(None) | Err(_) => return,
        }
    }
}

/// The host, the protocol and what a captured message establishes about it.
///
/// [`None`] for anything this pass did not provoke. The capture admits every
/// ICMP message on every interface, so a message counts only where it quotes a
/// datagram this pass sent to a probed host under an asked protocol, or is an
/// echo reply carrying this pass's identifier.
fn matched(
    reply: &crate::transport::capture::CapturedSegment,
    probed: &BTreeSet<IpAddr>,
    asked: &BTreeSet<u8>,
    keys: &Correlation,
) -> Option<(IpAddr, u8, IpProtocolState)> {
    if let Some(error) = icmp_error::parse(reply) {
        let host = error.quoted.destination;
        let number = error.quoted.protocol;
        if !probed.contains(&host) || !asked.contains(&number) {
            return None;
        }
        // The two sets above are the target list, which the scanned host
        // knows; the quotation must also be of a datagram this pass sent.
        if !keys.admits(&error.quoted, number) {
            return None;
        }

        let state = match error.reason {
            // The stack refused the number itself.
            Unreachable::Protocol => IpProtocolState::Closed,
            // The stack took delivery and the transport found nothing
            // listening.
            Unreachable::Port => IpProtocolState::Open,
            // The path refused delivery; nothing about the host.
            Unreachable::Prohibited => IpProtocolState::Blocked,
            // The address is unreachable: no verdict on the protocol.
            Unreachable::Host => return None,
        };
        return Some((host, number, state));
    }

    // An echo reply, the one direct answer this filter admits.
    let number = match IpNextHeaderProtocol(reply.protocol) {
        IpNextHeaderProtocols::Icmp => 1,
        IpNextHeaderProtocols::Icmpv6 => 58,
        _ => return None,
    };
    if !probed.contains(&reply.source) || !asked.contains(&number) {
        return None;
    }

    let over_ipv6 = number == 58;
    match icmp::classify_echo_reply(&reply.bytes, keys.echo_identifier, over_ipv6) {
        icmp::EchoReply::Ours { .. } => Some((reply.source, number, IpProtocolState::Open)),
        _ => None,
    }
}

/// A built probe on its way to a raw socket.
///
/// As the raw sender wraps its own segments: the bytes are the packet, with no
/// payload past them.
struct Datagram<'a>(&'a [u8]);

impl pnet_packet::Packet for Datagram<'_> {
    fn packet(&self) -> &[u8] {
        self.0
    }
    fn payload(&self) -> &[u8] {
        &[]
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pnet_packet::icmp::destination_unreachable::IcmpCodes;
    use pnet_packet::icmp::destination_unreachable::MutableDestinationUnreachablePacket;
    use pnet_packet::icmp::{IcmpCode, IcmpTypes};
    use pnet_packet::icmpv6::{Icmpv6Packet, Icmpv6Types, MutableIcmpv6Packet};

    use crate::protocols::ip;
    use crate::scanner::strategy::icmp_error::ICMPV6_UNRECOGNISED_NEXT_HEADER;
    use crate::transport::capture::CapturedSegment;

    const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));
    const STRANGER: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
    /// The IPv6 halves of the two above, for a pass that probes both families.
    const LOCAL_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x50));
    const TARGET_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x200));

    /// The protocols a test pass asked about.
    fn asked(numbers: &[u8]) -> BTreeSet<u8> {
        numbers.iter().copied().collect()
    }

    /// The identity a test pass probes under.
    ///
    /// Fixed here, where a real pass draws it, so a fixture can match it.
    const TEST_SOURCE_PORT: u16 = 51_111;
    const TEST_ECHO_IDENTIFIER: u16 = 0x5A4F;

    fn keys() -> Correlation {
        Correlation {
            source_port: TEST_SOURCE_PORT,
            echo_identifier: TEST_ECHO_IDENTIFIER,
            sources: [LOCAL, LOCAL_V6].into_iter().collect(),
        }
    }

    /// An ICMPv4 Destination Unreachable under `code`, quoting a datagram this
    /// pass would have sent to `host` under `number`.
    ///
    /// Built with the real header writer and payload builder, so the quotation
    /// is what a real probe of that number would carry.
    fn refusal(code: IcmpCode, host: IpAddr, number: u8) -> CapturedSegment {
        refusal_quoting(
            code,
            LOCAL,
            host,
            number,
            &probe_payload(number, LOCAL, host, &keys()),
        )
    }

    /// [`refusal`], with the quoted datagram's source address and payload chosen
    /// by the caller, so a test can build one this pass did not send.
    fn refusal_quoting(
        code: IcmpCode,
        quoted_source: IpAddr,
        host: IpAddr,
        number: u8,
        payload: &[u8],
    ) -> CapturedSegment {
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (quoted_source, host) else {
            panic!("the fixture is IPv4");
        };
        let header =
            ip::build_ipv4_header(src, dst, payload.len() as u16, number, ip::HOP_LIMIT_ROUTED)
                .expect("a header");
        let quoted: Vec<u8> = header.into_iter().chain(payload.iter().copied()).collect();

        let mut bytes =
            vec![0u8; MutableDestinationUnreachablePacket::minimum_packet_size() + quoted.len()];
        let mut message = MutableDestinationUnreachablePacket::new(&mut bytes).expect("a packet");
        message.set_icmp_type(IcmpTypes::DestinationUnreachable);
        message.set_icmp_code(code);
        message.set_payload(&quoted);

        CapturedSegment::synthetic(host, IpNextHeaderProtocols::Icmp.0, bytes)
    }

    /// The IPv6 form of a protocol refusal: a Parameter Problem naming an
    /// unrecognised Next Header (RFC 4443 §3.4), from `host`, quoting the
    /// datagram this pass would have sent it under `number`.
    fn next_header_refusal(host: IpAddr, number: u8) -> CapturedSegment {
        let (IpAddr::V6(src), IpAddr::V6(dst)) = (LOCAL_V6, host) else {
            panic!("the fixture is IPv6");
        };
        let payload = probe_payload(number, LOCAL_V6, host, &keys());
        let header =
            ip::build_ipv6_header(src, dst, payload.len() as u16, number, ip::HOP_LIMIT_ROUTED);

        // The Pointer, naming the Next Header field six bytes into the quoted
        // header, and then the quotation.
        let mut body = 6u32.to_be_bytes().to_vec();
        body.extend(header);
        body.extend(payload);

        let mut bytes = vec![0u8; Icmpv6Packet::minimum_packet_size() + body.len()];
        let mut message = MutableIcmpv6Packet::new(&mut bytes).expect("a packet");
        message.set_icmpv6_type(Icmpv6Types::ParameterProblem);
        message.set_icmpv6_code(ICMPV6_UNRECOGNISED_NEXT_HEADER);
        message.set_payload(&body);

        CapturedSegment::synthetic(host, IpNextHeaderProtocols::Icmpv6.0, bytes)
    }

    /// The verdict a captured message settles, for the tests that assert on it
    /// alone.
    fn verdict(reply: &CapturedSegment, named: &[u8]) -> Option<(IpAddr, u8, IpProtocolState)> {
        matched(
            reply,
            &[TARGET, TARGET_V6].into_iter().collect(),
            &asked(named),
            &keys(),
        )
    }

    /// Which message means what.
    #[test]
    fn each_message_settles_the_verdict_it_proves() {
        let cases = [
            // The host's own stack refusing the number.
            (
                IcmpCodes::DestinationProtocolUnreachable,
                IpProtocolState::Closed,
            ),
            // The host's own stack accepting it, with nothing listening.
            (IcmpCodes::DestinationPortUnreachable, IpProtocolState::Open),
            // The path refusing delivery, which says nothing about the host.
            (
                IcmpCodes::CommunicationAdministrativelyProhibited,
                IpProtocolState::Blocked,
            ),
        ];

        for (code, expected) in cases {
            assert_eq!(
                verdict(&refusal(code, TARGET, 47), &[47]),
                Some((TARGET, 47, expected)),
                "{code:?}"
            );
        }
    }

    /// A host unreachable carries no verdict on the protocol it quotes; it is a
    /// routing failure, not the host's policy.
    #[test]
    fn an_unreachable_address_settles_nothing_about_its_protocols() {
        assert_eq!(
            verdict(
                &refusal(IcmpCodes::DestinationHostUnreachable, TARGET, 47),
                &[47]
            ),
            None
        );
    }

    /// The capture admits every ICMP message on every interface, so both the
    /// host and the protocol are checked.
    #[test]
    fn a_message_this_pass_did_not_provoke_settles_nothing() {
        assert_eq!(
            verdict(
                &refusal(IcmpCodes::DestinationProtocolUnreachable, STRANGER, 47),
                &[47]
            ),
            None,
            "a host this pass never probed"
        );
        assert_eq!(
            verdict(
                &refusal(IcmpCodes::DestinationProtocolUnreachable, TARGET, 89),
                &[47]
            ),
            None,
            "a protocol this pass never asked about"
        );
    }

    /// The identifier separates this pass's echo replies from the discovery
    /// sweep's under the same capture.
    #[test]
    fn an_echo_reply_proves_icmp_only_when_it_is_this_passs_own() {
        let ours = icmp::build_echo_request_message(TARGET, LOCAL, 0, TEST_ECHO_IDENTIFIER, 0, &[])
            .expect("an echo message");
        let mut ours = CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Icmp.0, ours);
        ours.bytes[0] = IcmpTypes::EchoReply.0;

        assert_eq!(
            verdict(&ours, &[1]),
            Some((TARGET, 1, IpProtocolState::Open))
        );

        let theirs =
            icmp::build_echo_request_message(TARGET, LOCAL, 0, TEST_ECHO_IDENTIFIER ^ 1, 0, &[])
                .expect("an echo message");
        let mut theirs = CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Icmp.0, theirs);
        theirs.bytes[0] = IcmpTypes::EchoReply.0;

        assert_eq!(verdict(&theirs, &[1]), None, "somebody else's ping");
    }

    /// A header is built for the four protocols whose acceptance can be
    /// observed; the rest go out bare.
    #[test]
    fn a_header_is_built_only_where_it_could_change_the_answer() {
        for number in [1, 6, 17, 132] {
            assert!(
                !probe_payload(number, LOCAL, TARGET, &keys()).is_empty(),
                "protocol {number} went out bare"
            );
        }
        for number in [2, 4, 41, 47, 50, 51, 89, 103, 112] {
            assert!(
                probe_payload(number, LOCAL, TARGET, &keys()).is_empty(),
                "protocol {number} carried a header it has no use for"
            );
        }
    }

    /// An ICMP number aimed at the family that does not carry it goes out bare.
    #[test]
    fn an_icmp_header_follows_its_own_family() {
        assert!(
            !probe_payload(1, LOCAL, TARGET, &keys()).is_empty(),
            "icmp over v4"
        );
        assert!(
            probe_payload(58, LOCAL, TARGET, &keys()).is_empty(),
            "icmpv6 has no business in an IPv4 datagram"
        );
    }

    /// A refusal of an ICMP number sent bare is read on its source address, as
    /// any bare header's is. Demanding an echo identifier would leave it unread,
    /// and since protocol 1 is in the default set every IPv6 host would report
    /// it `OpenOrNoReply` where its stack said closed.
    #[test]
    fn an_icmp_number_sent_bare_is_refused_like_any_bare_header() {
        assert_eq!(
            verdict(&next_header_refusal(TARGET_V6, 1), &[1]),
            Some((TARGET_V6, 1, IpProtocolState::Closed)),
            "ICMP asked of an IPv6 host"
        );
        assert_eq!(
            verdict(
                &refusal(IcmpCodes::DestinationProtocolUnreachable, TARGET, 58),
                &[58]
            ),
            Some((TARGET, 58, IpProtocolState::Closed)),
            "ICMPv6 asked of an IPv4 host"
        );
    }

    /// Every number in the default set has a registry name to print.
    #[test]
    fn every_default_protocol_is_one_the_registry_names() {
        for &number in DEFAULT_PROTOCOLS {
            assert!(
                crate::model::host::ip_protocol_name(number).is_some(),
                "protocol {number} is in the default set and has no name to print"
            );
        }
    }

    /// **A refusal quoting a datagram this pass did not send settles nothing.**
    ///
    /// The probed hosts and asked protocols are known to the scanned host, so
    /// on their own a forged *port* unreachable would assert that a stack takes
    /// delivery of a protocol.
    #[test]
    fn a_refusal_quoting_a_datagram_this_pass_did_not_send_settles_nothing() {
        // The quoted datagram claims a source this pass never sent from.
        for number in [1u8, 6, 17, 47, 132] {
            let forged = refusal_quoting(
                IcmpCodes::DestinationPortUnreachable,
                STRANGER,
                TARGET,
                number,
                &probe_payload(number, LOCAL, TARGET, &keys()),
            );
            assert_eq!(
                verdict(&forged, &[number]),
                None,
                "protocol {number}: a quotation naming a source this pass never used"
            );
        }
    }

    /// For the protocols this crate builds a header for, the quotation must
    /// carry the drawn source port, ~16 bits a stranger has to guess.
    #[test]
    fn a_refusal_quoting_another_ports_datagram_settles_nothing() {
        for number in [6u8, 17, 132] {
            let mut payload = probe_payload(number, LOCAL, TARGET, &keys());
            // The source port is the first two bytes of all three headers.
            payload[0..2].copy_from_slice(&1234u16.to_be_bytes());

            let forged = refusal_quoting(
                IcmpCodes::DestinationPortUnreachable,
                LOCAL,
                TARGET,
                number,
                &payload,
            );
            assert_eq!(
                verdict(&forged, &[number]),
                None,
                "protocol {number}: a quotation carrying a port this pass never sent from"
            );
        }
    }

    /// An echo probe's identifier is checked on the error path too, not only
    /// where the host answers the ping.
    #[test]
    fn a_refusal_quoting_another_pings_identifier_settles_nothing() {
        let mut payload = probe_payload(1, LOCAL, TARGET, &keys());
        payload[4..6].copy_from_slice(&(TEST_ECHO_IDENTIFIER ^ 1).to_be_bytes());

        let forged = refusal_quoting(
            IcmpCodes::DestinationPortUnreachable,
            LOCAL,
            TARGET,
            1,
            &payload,
        );
        assert_eq!(verdict(&forged, &[1]), None);
    }

    /// **A bare-header protocol rests on its source address alone.**
    ///
    /// GRE, ESP, AH, OSPF and PIM go out as an IP header only, so a quotation
    /// carries no port, identifier or nonce, and the verdict is weaker than one
    /// for TCP. This test documents that limit.
    #[test]
    fn a_bare_protocol_is_admitted_on_its_source_address_alone() {
        let sent = refusal_quoting(
            IcmpCodes::DestinationProtocolUnreachable,
            LOCAL,
            TARGET,
            47,
            &[],
        );
        assert_eq!(
            verdict(&sent, &[47]),
            Some((TARGET, 47, IpProtocolState::Closed)),
            "a quotation from an address this pass sent from is admitted"
        );

        let forged = refusal_quoting(
            IcmpCodes::DestinationProtocolUnreachable,
            STRANGER,
            TARGET,
            47,
            &[],
        );
        assert_eq!(
            verdict(&forged, &[47]),
            None,
            "and one from anywhere else is not"
        );
    }

    /// Two hosts asked two numbers each, as the pass owes them.
    fn owed_of_two_hosts() -> Owed {
        let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 201));
        let pending = [TARGET, other]
            .into_iter()
            .flat_map(|host| {
                [1, 17].map(|number| Question {
                    host,
                    number,
                    source: LOCAL,
                })
            })
            .collect();
        Owed { pending }
    }

    /// Under a per-host gap, the pass asks the next host while the last one's
    /// gap runs, and holds, without dropping, what no host is ready for.
    #[test]
    fn a_host_gap_moves_the_pass_to_the_next_host_and_holds_the_rest() {
        let gap = Duration::from_secs(3600);
        let (_session, ctx) = crate::scanner::session::ScanSession::builder()
            .host_probe_interval(Some(gap))
            .build();
        let mut owed = owed_of_two_hosts();
        let now = Instant::now();

        let mut taken = || match owed.take_ready(&ctx, now) {
            Some(Ok((question, _claim))) => Ok((question.host, question.number)),
            Some(Err(ready)) => Err(ready),
            None => panic!("four were owed"),
        };
        let first = taken().expect("nothing has been asked yet");
        let second = taken().expect("the other host has not been asked");
        assert_eq!(first.1, second.1, "the same number of the next host");
        assert_ne!(first.0, second.0);
        let held = taken().expect_err("both hosts were just asked");
        assert!(held > now + gap / 2, "held until the gap has run, {held:?}");
        assert_eq!(owed.pending.len(), 2, "and nothing was dropped");
    }

    /// With no gap, the pass asks in the order it owes, every probe ready.
    #[test]
    fn with_no_gap_every_probe_is_taken_in_order() {
        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let mut owed = owed_of_two_hosts();
        let order: Vec<Question> = owed.pending.iter().copied().collect();
        let now = Instant::now();

        for expected in order {
            match owed.take_ready(&ctx, now) {
                Some(Ok((question, _claim))) => assert_eq!(question, expected),
                other => panic!("expected {expected:?}, got {other:?}"),
            }
        }
        assert!(owed.take_ready(&ctx, now).is_none());
    }

    /// The pass draws a fresh source port and identifier each time, so two runs
    /// against the same host do not accept each other's answers.
    #[test]
    fn each_pass_draws_its_own_identity() {
        let ports: BTreeSet<u16> = (0..64).map(|_| draw_source_port()).collect();
        assert!(
            ports.len() > 1,
            "a drawn port that never varies is a constant"
        );
        assert!(
            ports.iter().all(|port| *port >= 50_000),
            "the range is the ephemeral one the raw sender uses"
        );

        let identifiers: BTreeSet<u16> = (0..64).map(|_| draw_echo_identifier()).collect();
        assert!(identifiers.len() > 1);
    }
}
