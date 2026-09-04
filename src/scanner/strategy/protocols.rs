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
//! answered, in the shape
//! [`characterise`](super::topology::characterise) has: a bounded set of probes
//! per host, one listening window, and conclusions recorded on the host.
//!
//! One datagram goes out under each protocol number the caller asked about, and
//! the host's own ICMP is the answer. What comes back settles it:
//!
//! - **A protocol unreachable** is the stack saying it does not implement the
//!   number, which is [`Closed`](IpProtocolState::Closed). ICMPv4 has a code for
//!   it; ICMPv6 reports it as a Parameter Problem instead, and
//!   [`icmp_error`] resolves both to one meaning.
//! - **A port unreachable** is the stack saying it does implement the number,
//!   handed the datagram to that transport, and found nothing listening. It is
//!   the one message that proves acceptance without the protocol having to
//!   answer for itself, and it is why asking about UDP is worth a real header.
//! - **Any other unreachable** is the path refusing delivery, which is
//!   [`Filtered`](IpProtocolState::Filtered) and says nothing about the host.
//! - **An echo reply**, for the two ICMP numbers, is the host answering in the
//!   protocol asked about.
//! - **Silence** is [`OpenFiltered`](IpProtocolState::OpenFiltered), and it is
//!   the ordinary answer.
//!
//! ## Why silence is the ordinary answer
//!
//! Because most of these protocols have nothing to say. GRE, ESP, AH, OSPF and
//! PIM answer an unsolicited bare header with nothing at all whether or not the
//! stack implements them, so there is no positive signal to wait for and the
//! useful finding is the negative one: a host that refuses a protocol says so,
//! and one that does not refuse it is a host worth asking about by other means.
//! That is the same reading nmap's own protocol scan produces, and it is a
//! property of the protocols rather than of this capture.
//!
//! What the capture does cost is the two transports that would answer for
//! themselves. A TCP probe draws a reset and an SCTP probe an abort, and neither
//! is admitted by this pass's filter, which is ICMP alone; see
//! [`ProbeKind::IpProtocol`]. Widening it to those two would admit every TCP and
//! SCTP segment on every captured interface to learn something a port scan of
//! the same host already establishes, so the pass reports them from their ICMP
//! or not at all.
//!
//! ## One socket per number
//!
//! The kernel derives a raw Layer-4 socket's next-header value from the socket,
//! so asking about a dozen protocols opens a dozen senders. That is the price of
//! not writing the IP header here, and the alternative is worse: a header this
//! crate wrote would have to be routed by this crate, and the raw path exists
//! because the kernel does that better. A number whose socket the kernel refuses
//! is left [`Unasked`](IpProtocolState::Unasked) rather than reported quiet.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use pnet_packet::ip::IpNextHeaderProtocols;

use crate::model::host::IpProtocolState;
use crate::protocols::{icmp, sctp, tcp, udp};
use crate::report::ScannerKind;
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::icmp_error::{self, Unreachable};
use crate::system::interface::SourceResolver;
use crate::transport::probe::{Emission, ProbeKind, ProbeTransport};
use crate::transport::raw::{self, TransportSenderHandle};
use crate::{counted, info};

/// How long to listen once the last probe has left.
///
/// The same window [`characterise`](super::topology::characterise) waits, and
/// for the same reason: every answer here is one message a host sends promptly
/// or not at all, so this is the tail for a slow path rather than a retry
/// schedule. The pass sends each probe once.
const REPLY_WINDOW: Duration = Duration::from_secs(2);

/// The protocols worth asking about when a caller names none.
///
/// A deliberate opinion rather than a neutral default, the way
/// [`PortSet::top_tcp`](crate::model::port::PortSet::top_tcp) is one. Every
/// number here is either a transport a host might terminate or a protocol whose
/// presence says what a machine is for: a tunnel endpoint answers for 47, 50 or
/// 51, a router for 89, 103 or 112, and a multicast segment for 2.
///
/// The whole 0..=255 range is what nmap's protocol scan walks and is a poor
/// default here, because each number costs a socket and two hundred of them
/// would spend the pass's whole budget on assignments nothing has ever
/// answered for. A caller who wants the sweep asks for it.
pub const DEFAULT_PROTOCOLS: [u8; 13] = [1, 2, 4, 6, 17, 41, 47, 50, 51, 89, 103, 112, 132];

/// The source port every probe that has one leaves from, and so the port a
/// direct answer would come back to.
///
/// Fixed rather than random because nothing here correlates on it: an answer is
/// matched by the probe an ICMP message quotes, which names the destination and
/// the protocol, and those two are the whole key. See [`matched`].
const SOURCE_PORT: u16 = 55_555;

/// The port a probe carrying a transport header is addressed to.
///
/// High and unassigned, so that a stack implementing the transport almost
/// certainly has nothing listening there and answers with the port unreachable
/// this pass reads as acceptance. A well-known port would risk finding a
/// listener, which answers in the transport rather than in ICMP and so tells
/// this pass nothing.
const CLOSED_PORT: u16 = 54_321;

/// The identifier the echo probes carry, so an echo reply drawn by this pass is
/// told apart from one drawn by the discovery sweep running under the same
/// capture.
const ECHO_IDENTIFIER: u16 = 0x5A4F;

/// Asks each host in `targets` which of `protocols` its stack takes delivery of,
/// and records the answers.
///
/// Every host is left with a verdict for every protocol asked about, including
/// the ones nothing answered for, so a protocol missing from a host's record is
/// one the pass never named rather than one it forgot.
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

    send_probes(ctx, targets, &senders, &mut resolver);

    // What a reply is matched against: the hosts asked, and the numbers that got
    // a socket. Built once and as sets, because every captured message is
    // checked against both and the capture admits every ICMP on the host.
    let probed: BTreeSet<IpAddr> = targets.iter().copied().collect();
    let asked: BTreeSet<u8> = senders.keys().copied().collect();
    collect_replies(ctx, &mut transport, &probed, &asked).await;
}

/// One capture for the whole pass, and one sender per protocol.
///
/// The capture is opened receive-only. A [`ProbeTransport`] is a sender and a
/// capture together, and the sender half it would open speaks one protocol,
/// which is the one thing this pass needs several of; the number handed to
/// [`ProbeKind::IpProtocol`] here reaches only the filter, and the filter is the
/// same expression for every number.
///
/// A number whose socket the kernel refuses is dropped with a failure recorded
/// rather than ending the pass, so the protocols that can be asked about are.
/// [`None`] only where nothing can be: no capture, or no socket at all.
fn open(
    ctx: &ScanContext,
    protocols: &BTreeSet<u8>,
) -> Option<(ProbeTransport, BTreeMap<u8, TransportSenderHandle>)> {
    let first = protocols.iter().copied().next()?;

    let transport = match ProbeTransport::open_receiver(ProbeKind::IpProtocol { number: first }) {
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
/// A host with no source address to send from is passed over entirely: a probe
/// that never left proves nothing, and recording silence for it would report the
/// scanner's own reach as the host's policy.
fn send_probes(
    ctx: &ScanContext,
    targets: &[IpAddr],
    senders: &BTreeMap<u8, TransportSenderHandle>,
    resolver: &mut SourceResolver,
) {
    for &host in targets {
        let Some(source) = resolver.resolve(host) else {
            continue;
        };

        for (&number, sender) in senders {
            let payload = probe_payload(number, source, host);
            let sent = sender
                .send_to(Datagram(&payload), host, Emission::routed().hop_limit)
                .is_ok();

            // Written down before anything answers, so that the record says a
            // protocol was asked about even where the answer never comes. The
            // reply loop only ever raises these.
            let state = match sent {
                true => IpProtocolState::OpenFiltered,
                false => IpProtocolState::Unasked,
            };
            ctx.update_host(host, |host| {
                host.record_ip_protocol(number, state);
            });
        }
    }
}

/// What a probe of `number` carries after the IP header the kernel writes.
///
/// A real header for the four protocols this crate can build one for, and
/// nothing at all for the rest, which is what nmap sends too. The reasoning is
/// asymmetric and worth stating: an empty datagram is enough to draw a *protocol
/// unreachable*, because the IP layer refuses the number before any transport
/// sees the bytes. It is not enough to draw an acceptance. A stack that
/// implements the protocol hands a truncated datagram to a transport that drops
/// it silently, where a well-formed one draws the port unreachable this pass
/// reads as proof of delivery.
///
/// So the header is spent exactly where it can change the answer, and a
/// protocol this crate cannot build a header for is one whose acceptance it
/// could not have observed anyway.
fn probe_payload(number: u8, source: IpAddr, host: IpAddr) -> Vec<u8> {
    let built = match (number, host) {
        (1, IpAddr::V4(_)) | (58, IpAddr::V6(_)) => {
            icmp::build_echo_request_message(source, host, 0, ECHO_IDENTIFIER, 0, &[])
        }
        (6, _) => tcp::build_probe(
            crate::model::technique::TcpScanTechnique::Syn,
            source,
            host,
            SOURCE_PORT,
            CLOSED_PORT,
            rand::random(),
        ),
        (17, _) => udp::build_packet(source, host, SOURCE_PORT, CLOSED_PORT, Vec::new()),
        (132, _) => Ok(sctp::build_init_probe(
            SOURCE_PORT,
            CLOSED_PORT,
            rand::random(),
        )),
        // Every other number, and an ICMP number aimed at the family that does
        // not carry it. A bare header is the probe.
        _ => return Vec::new(),
    };

    // A header that would not build is not a reason to skip the protocol: the
    // bare datagram still asks the question the pass is about, and only the
    // chance of an acceptance is lost.
    built.unwrap_or_default()
}

/// Listens out the window and raises whatever the answers establish.
async fn collect_replies(
    ctx: &ScanContext,
    transport: &mut ProbeTransport,
    probed: &BTreeSet<IpAddr>,
    asked: &BTreeSet<u8>,
) {
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
            Ok(Some(reply)) => {
                if let Some((host, number, state)) = matched(&reply, probed, asked) {
                    ctx.update_host(host, |host| {
                        host.record_ip_protocol(number, state);
                    });
                }
            }
            // The stream closed, or the window elapsed. Either way there is
            // nothing more to hear.
            Ok(None) | Err(_) => return,
        }
    }
}

/// The host, the protocol and what a captured message establishes about it.
///
/// [`None`] for anything this pass did not provoke. The capture is promiscuous
/// and admits every ICMP message on every interface, so a message is credited
/// only where it quotes a datagram addressed to a host this pass probed under a
/// protocol it asked about, or is an echo reply carrying this pass's own
/// identifier. Without both checks another tool's traffic would settle verdicts
/// here.
fn matched(
    reply: &crate::transport::capture::CapturedSegment,
    probed: &BTreeSet<IpAddr>,
    asked: &BTreeSet<u8>,
) -> Option<(IpAddr, u8, IpProtocolState)> {
    if let Some(error) = icmp_error::parse(reply) {
        let host = error.quoted.destination;
        let number = error.quoted.protocol.0;
        if !probed.contains(&host) || !asked.contains(&number) {
            return None;
        }

        let state = match error.reason {
            // The stack refused the number itself.
            Unreachable::Protocol => IpProtocolState::Closed,
            // The stack took delivery, handed the datagram to the transport the
            // number names, and that transport found nothing listening. Nothing
            // else this pass can hear proves acceptance so cheaply.
            Unreachable::Port => IpProtocolState::Open,
            // The path refused delivery, which says nothing about the host.
            Unreachable::Prohibited => IpProtocolState::Filtered,
            // Nobody could reach the address at all, so the message carries no
            // verdict on the protocol it happened to quote.
            Unreachable::Host => return None,
        };
        return Some((host, number, state));
    }

    // An echo reply is the host answering in the protocol that was asked about,
    // which is the one direct answer this filter admits.
    let number = match reply.protocol {
        IpNextHeaderProtocols::Icmp => 1,
        IpNextHeaderProtocols::Icmpv6 => 58,
        _ => return None,
    };
    if !probed.contains(&reply.source) || !asked.contains(&number) {
        return None;
    }

    let over_ipv6 = number == 58;
    match icmp::classify_echo_reply(&reply.bytes, ECHO_IDENTIFIER, over_ipv6) {
        icmp::EchoReply::Ours { .. } => Some((reply.source, number, IpProtocolState::Open)),
        _ => None,
    }
}

/// A built probe on its way to a raw socket.
///
/// The same shape the raw sender wraps its own segments in: the bytes are the
/// packet and there is no payload past them, because whatever structure they
/// have was decided by whoever built them.
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
    use std::net::Ipv4Addr;

    use pnet_packet::icmp::destination_unreachable::IcmpCodes;
    use pnet_packet::icmp::destination_unreachable::MutableDestinationUnreachablePacket;
    use pnet_packet::icmp::{IcmpCode, IcmpTypes};
    use pnet_packet::ip::IpNextHeaderProtocol;

    use crate::protocols::ip;
    use crate::transport::capture::CapturedSegment;

    const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
    const STRANGER: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));

    /// The protocols a test pass asked about.
    ///
    fn asked(numbers: &[u8]) -> BTreeSet<u8> {
        numbers.iter().copied().collect()
    }

    /// An ICMPv4 Destination Unreachable under `code`, quoting a bare datagram
    /// this pass would have sent to `host` under `number`.
    ///
    /// Built through the same header writer a real probe uses, so the offsets the
    /// parser walks are a router's rather than ones a fixture and a parser agreed
    /// on between themselves.
    fn refusal(code: IcmpCode, host: IpAddr, number: u8) -> CapturedSegment {
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (LOCAL, host) else {
            panic!("the fixture is IPv4");
        };
        let quoted = ip::build_ipv4_header(
            src,
            dst,
            0,
            IpNextHeaderProtocol(number),
            ip::HOP_LIMIT_ROUTED,
        )
        .expect("a header");

        let mut bytes =
            vec![0u8; MutableDestinationUnreachablePacket::minimum_packet_size() + quoted.len()];
        let mut message = MutableDestinationUnreachablePacket::new(&mut bytes).expect("a packet");
        message.set_icmp_type(IcmpTypes::DestinationUnreachable);
        message.set_icmp_code(code);
        message.set_payload(&quoted);

        CapturedSegment::synthetic(host, IpNextHeaderProtocols::Icmp, bytes)
    }

    /// The verdict a captured message settles, for the tests that assert on it
    /// alone.
    fn verdict(reply: &CapturedSegment, named: &[u8]) -> Option<(IpAddr, u8, IpProtocolState)> {
        matched(reply, &[TARGET].into_iter().collect(), &asked(named))
    }

    /// The whole reading, in one place: which message means what.
    #[test]
    fn each_message_settles_the_verdict_it_proves() {
        let cases = [
            // The host's own stack refusing the number.
            (
                IcmpCodes::DestinationProtocolUnreachable,
                IpProtocolState::Closed,
            ),
            // The host's own stack accepting it, handing the datagram to the
            // transport the number names and finding nothing listening. The one
            // message that proves delivery without the protocol answering.
            (IcmpCodes::DestinationPortUnreachable, IpProtocolState::Open),
            // The path refusing delivery, which says nothing about the host.
            (
                IcmpCodes::CommunicationAdministrativelyProhibited,
                IpProtocolState::Filtered,
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

    /// A host unreachable is nobody being able to reach the address at all, so it
    /// carries no verdict on the protocol it happened to quote. Reading it as a
    /// refusal would report a routing failure as a host's policy.
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

    /// The capture admits every ICMP message on every interface, so another
    /// tool's traffic reaches this pass. Both halves of the key are checked, or a
    /// verdict would be credited to a datagram nobody here sent.
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

    /// An echo reply is the host answering in the protocol asked about, and the
    /// identifier is what separates this pass's from the discovery sweep's under
    /// the same capture.
    #[test]
    fn an_echo_reply_proves_icmp_only_when_it_is_this_passs_own() {
        let ours = icmp::build_echo_request_message(TARGET, LOCAL, 0, ECHO_IDENTIFIER, 0, &[])
            .expect("an echo message");
        let mut ours = CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Icmp, ours);
        ours.bytes[0] = IcmpTypes::EchoReply.0;

        assert_eq!(
            verdict(&ours, &[1]),
            Some((TARGET, 1, IpProtocolState::Open))
        );

        let theirs =
            icmp::build_echo_request_message(TARGET, LOCAL, 0, ECHO_IDENTIFIER ^ 1, 0, &[])
                .expect("an echo message");
        let mut theirs = CapturedSegment::synthetic(TARGET, IpNextHeaderProtocols::Icmp, theirs);
        theirs.bytes[0] = IcmpTypes::EchoReply.0;

        assert_eq!(verdict(&theirs, &[1]), None, "somebody else's ping");
    }

    /// The four protocols a header is spent on are the four whose acceptance
    /// could be observed, and the rest go out bare. A header for a protocol
    /// nothing can answer for would be bytes spent to change nothing.
    #[test]
    fn a_header_is_built_only_where_it_could_change_the_answer() {
        for number in [1, 6, 17, 132] {
            assert!(
                !probe_payload(number, LOCAL, TARGET).is_empty(),
                "protocol {number} went out bare"
            );
        }
        for number in [2, 4, 41, 47, 50, 51, 89, 103, 112] {
            assert!(
                probe_payload(number, LOCAL, TARGET).is_empty(),
                "protocol {number} carried a header it has no use for"
            );
        }
    }

    /// An ICMP number aimed at the family that does not carry it builds nothing
    /// rather than a message the other family would reject.
    #[test]
    fn an_icmp_header_follows_its_own_family() {
        assert!(!probe_payload(1, LOCAL, TARGET).is_empty(), "icmp over v4");
        assert!(
            probe_payload(58, LOCAL, TARGET).is_empty(),
            "icmpv6 has no business in an IPv4 datagram"
        );
    }

    /// The default set is the opinion the module documents, and every number in
    /// it is one the registry names, so a report of one reads as a protocol
    /// rather than a bare number.
    #[test]
    fn every_default_protocol_is_one_the_registry_names() {
        for number in DEFAULT_PROTOCOLS {
            assert!(
                crate::model::host::ip_protocol_name(number).is_some(),
                "protocol {number} is in the default set and has no name to print"
            );
        }
    }
}
