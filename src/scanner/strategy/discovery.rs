// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Discovery Response Protocols
//!
//! [`LocalScanner`](super::LocalScanner) sends more than one kind of probe onto
//! the wire and has to recognize more than one kind of reply. Rather than
//! growing a single function that understands every wire format, each format is
//! its own [`DiscoveryProtocol`] implementation, and the scanner tries each one
//! against every frame it receives. Supporting a new discovery mechanism means
//! writing one more implementation here instead of touching the receive loop.

use std::net::IpAddr;

use pnet::packet::ethernet::EtherTypes;

use crate::protocols::ethernet::Frame;

use crate::model::host::{NetworkRole, StatusProtocol};
use crate::protocols::{dhcp, ip, ndp};

/// What a [`DiscoveryProtocol`] found when asked to interpret one received frame.
///
/// The two "handled" answers differ in what they entitle the scanner to
/// conclude about the probe that provoked them, which is why they are separate
/// variants rather than one carrying a round-trip time. A protocol reads bytes;
/// deciding which outstanding probe a frame retires is the scanner's job, since
/// only the scanner knows what it sent and when.
pub enum ProtocolMatch {
    /// The protocol does not recognize this frame. Another protocol may still
    /// claim it.
    Unhandled,
    /// A reply to a probe aimed at one address, so it answers exactly one
    /// outstanding probe and retires it.
    ///
    /// The address is carried because the frame's source is not always it. A
    /// neighbor advertisement names the address it is about in its own target
    /// field, and a host with several addresses answers from whichever its stack
    /// prefers rather than from the one that was asked about — measured on a
    /// real segment, a phone solicited at `2a02:…::21e9` answered from
    /// `2a02:…:14f0:ca99:5818:74ee`. Keyed on the source, that reply retires no
    /// probe, yields no round trip, and files the host under an address nobody
    /// asked about.
    ///
    /// `None` where the frame's source *is* the address, which is ARP's case:
    /// the sender protocol address is the whole content of the reply.
    Solicited(Option<IpAddr>),
    /// A message that proves its sender is present and answers nothing this
    /// scan sent.
    ///
    /// A router advertising itself on its own timer, a DHCP server answering
    /// the segment. The distinction from [`Solicited`](Self::Solicited) is not
    /// bookkeeping: a probe may well be outstanding for the same address, and
    /// retiring it here would credit our question with somebody else's answer
    /// and time it from the moment we asked — a round trip that measures the
    /// gap between two unrelated messages. The probe is left to be answered or
    /// to expire on its own schedule.
    ///
    /// The sender is asked directly afterwards, which is what turns an
    /// overheard neighbour into a measured one. See
    /// [`LocalScanner::confirm`](super::LocalScanner::confirm).
    Unsolicited,
    /// A reply to the all-nodes echo request, carrying the identifier and
    /// sequence number it echoed back.
    ///
    /// That probe is not consumed by any one reply, because every neighbour on
    /// the segment may answer the same packet — but unlike a neighbor
    /// solicitation it is still *attributable*. RFC 4443 requires the reply to
    /// return the request's identifier and sequence unchanged, so the token
    /// names exactly which of the scan's echo requests was answered, and the
    /// round trip follows. Karn's rule costs NDP its measurement because two
    /// solicitations are identical on the wire; two echo requests are not.
    AllNodes { identifier: u16, sequence: u16 },
}

/// Everything one frame turned out to say.
///
/// Two questions, kept apart because they have different answers and different
/// consequences. [`matched`](Self::matched) is what the frame does to the scan's
/// ledger of outstanding probes; [`declared`](Self::declared) is what its sender
/// said about *itself* in the same message, which no probe was outstanding for
/// and which no round trip depends on.
///
/// They arrive together because they are read from the same bytes. A neighbour
/// advertisement answers the solicitation this scan sent and sets the R flag in
/// the same message; parsing it twice to ask the second question separately
/// would let the two answers come from different readings of one frame.
pub struct Reading {
    /// What the frame answers, and what it therefore retires.
    pub matched: ProtocolMatch,
    /// What the sender declared about itself beyond being present, when a
    /// protocol carries such a claim at all.
    pub declared: Option<NetworkRole>,
}

impl Reading {
    /// A frame this protocol does not recognize.
    fn unhandled() -> Self {
        Self {
            matched: ProtocolMatch::Unhandled,
            declared: None,
        }
    }

    /// A frame that means something, and claims nothing beyond it.
    fn matched(matched: ProtocolMatch) -> Self {
        Self {
            matched,
            declared: None,
        }
    }

    /// The same, from a sender that also named what it is.
    fn declaring(matched: ProtocolMatch, role: NetworkRole) -> Self {
        Self {
            matched,
            declared: Some(role),
        }
    }
}

/// A wire-level protocol capable of recognizing discovery responses.
///
/// [`LocalScanner`](super::LocalScanner) tries each configured protocol against
/// every received frame in turn, and the first one to claim a frame decides what
/// kind of answer it is. The scanner has already identified the frame's source
/// address and ruled out obvious noise (packets from itself, addresses outside
/// the scan) before a protocol ever sees the frame, so an implementation is a
/// pure function of the bytes in front of it.
pub trait DiscoveryProtocol: Send {
    fn interpret(&self, frame: &Frame<'_>) -> anyhow::Result<Reading>;

    /// The evidence this protocol produces, for the liveness record of whichever
    /// host it claims a frame from.
    ///
    /// Each implementation names its own evidence rather than the receive loop
    /// inferring it from the frame, so a new discovery mechanism stays one more
    /// implementation in this module — the same reason `interpret` lives here.
    fn status_protocol(&self) -> StatusProtocol;

    /// The `libpcap` filter clause admitting the frames this protocol reads.
    ///
    /// The sweep's capture narrows in the kernel, so a protocol whose traffic no
    /// clause admits is never given a frame to interpret — and it fails that way
    /// silently, since a protocol that is never called and a protocol that
    /// recognises nothing look identical from the receive loop.
    ///
    /// Declared here, beside [`interpret`](Self::interpret), so that the two
    /// cannot disagree: the sweep's whole filter is the union of these, so
    /// adding an implementation widens the capture by the same edit that adds
    /// the reader. Written the other way round — one filter maintained beside
    /// the list — this module's promise that a new mechanism is one more
    /// implementation *here* would quietly stop being true.
    ///
    /// A clause is a complete expression, combined with the others by `or`, so
    /// it must parenthesise anything that would not survive that.
    fn capture_clause(&self) -> &'static str;
}

/// Every protocol a local sweep reads, in the order it tries them against a
/// frame.
///
/// The single list. It is read twice — once to build the scanner's own
/// interpreters, and once to work out what its capture must admit — and both
/// readings have to see the same protocols or the sweep listens for something
/// other than what it can understand.
pub fn sweep_protocols() -> Vec<Box<dyn DiscoveryProtocol>> {
    vec![
        Box::new(ArpProtocol),
        Box::new(NdpProtocol),
        Box::new(RouterAdvertProtocol),
        Box::new(DhcpProtocol),
        Box::new(Icmpv6EchoProtocol),
    ]
}

/// Recognizes ARP replies as discovery responses.
///
/// Every ARP frame from an in-range address counts, whether or not it answers an
/// outstanding request: other hosts' requests and gratuitous announcements are
/// common on a shared segment and are just as good a proof that someone is
/// there. Whether one also yields a round-trip time depends on there being a
/// probe outstanding to measure against, which the scanner determines.
pub struct ArpProtocol;

impl DiscoveryProtocol for ArpProtocol {
    fn interpret(&self, frame: &Frame<'_>) -> anyhow::Result<Reading> {
        if frame.ethertype() != EtherTypes::Arp {
            return Ok(Reading::unhandled());
        }

        Ok(Reading::matched(ProtocolMatch::Solicited(None)))
    }

    fn status_protocol(&self) -> StatusProtocol {
        StatusProtocol::Arp
    }

    /// Every ARP frame on the segment, requests included: an unsolicited request
    /// or a gratuitous announcement proves its sender is there just as well as a
    /// reply to this scan does.
    fn capture_clause(&self) -> &'static str {
        "arp"
    }
}

/// Recognizes neighbor advertisements as answers to the solicitation sent for
/// one address.
///
/// The IPv6 counterpart of [`ArpProtocol`], and conclusive in the same way: the
/// reply came off this segment carrying the neighbour's own MAC. Unlike the
/// all-nodes echo, this answers a probe put to a single address, so it retires
/// that address's outstanding probe and the retry ledger owns it exactly as it
/// owns an ARP request.
///
/// Every advertisement from an in-range address counts, whether or not it
/// answers an outstanding solicitation, for the reason [`ArpProtocol`] accepts
/// every ARP frame: neighbours advertise to each other constantly, and an
/// advertisement is proof its sender is present however it was provoked.
pub struct NdpProtocol;

impl DiscoveryProtocol for NdpProtocol {
    fn interpret(&self, frame: &Frame<'_>) -> anyhow::Result<Reading> {
        match ndp::advertisement(frame) {
            Some(advert) if is_assignable(advert.target) => {
                let matched = ProtocolMatch::Solicited(Some(IpAddr::V6(advert.target)));
                Ok(match advert.router {
                    true => Reading::declaring(matched, NetworkRole::Router),
                    false => Reading::matched(matched),
                })
            }
            // An advertisement naming an address nothing can hold proves its
            // sender exists and says nothing about *which* address that is, so
            // the frame is left for another protocol to claim rather than
            // crediting a host with an address it cannot have.
            Some(_) | None => Ok(Reading::unhandled()),
        }
    }

    fn status_protocol(&self) -> StatusProtocol {
        StatusProtocol::Ndp
    }

    /// See [`NdpProtocol::capture_clause`]: a router advertisement is ICMPv6,
    /// and the clause that admits one admits all of them.
    fn capture_clause(&self) -> &'static str {
        "icmp6"
    }
}

/// Whether an address is one an interface can actually hold.
///
/// A neighbour advertisement carries whatever its sender put in it, and devices
/// on real segments send ones naming addresses that are not addresses. Two are
/// worth refusing by name because both would otherwise be recorded as an address
/// of the host that sent them, and then reported as an address it *gained* the
/// next time the segment was swept:
///
/// - **The unspecified address.** `::` names nothing by definition.
/// - **A link-local with a zero interface identifier.** `fe80::` is the prefix,
///   not an address in it; RFC 4291 gives every link-local unicast address a
///   64-bit interface identifier, and one made entirely of zeros is reserved.
fn is_assignable(address: std::net::Ipv6Addr) -> bool {
    if address.is_unspecified() {
        return false;
    }

    let segments = address.segments();
    let link_local = (segments[0] & 0xffc0) == 0xfe80;
    let no_interface_id = segments[4..] == [0, 0, 0, 0];

    !(link_local && no_interface_id)
}

/// Recognizes router advertisements, the message only a router sends.
///
/// The one piece of evidence this scanner does not have to provoke. Routers
/// advertise themselves unprompted every few minutes, and the sweep's capture is
/// promiscuous, so an advertisement that crosses the segment while a scan is
/// running arrives here for free. A sweep also asks for one outright — see
/// [`LocalScanner`](super::LocalScanner) — because the unprompted timer is
/// measured in minutes and a sweep is measured in seconds.
///
/// Claimed as [`Unsolicited`](ProtocolMatch::Unsolicited), and filed under the
/// frame's source: an advertisement names no target of its own, and its source
/// is required to be the sending interface's link-local address (RFC 4861
/// §4.2). Unsolicited rather than solicited even when the sweep asked for it,
/// because the sweep's solicitation goes to every router at once and no reply
/// to it belongs to any one address's probe.
pub struct RouterAdvertProtocol;

impl DiscoveryProtocol for RouterAdvertProtocol {
    fn interpret(&self, frame: &Frame<'_>) -> anyhow::Result<Reading> {
        Ok(match ndp::is_router_advertisement(frame) {
            true => Reading::declaring(ProtocolMatch::Unsolicited, NetworkRole::Router),
            false => Reading::unhandled(),
        })
    }

    fn status_protocol(&self) -> StatusProtocol {
        StatusProtocol::Ndp
    }

    /// All of ICMPv6 rather than the two neighbour-discovery types, which BPF
    /// cannot select without reading past a header whose length is not fixed.
    /// The surplus is small — ICMPv6 on a segment is nearly all neighbour
    /// discovery — and it is the same clause the other two IPv6 readers need.
    fn capture_clause(&self) -> &'static str {
        "icmp6"
    }
}

/// Recognizes a DHCP server answering the segment.
///
/// The counterpart of [`RouterAdvertProtocol`] over IPv4, and the only way a
/// DHCP server can be found at all: the protocol is built on broadcast, so the
/// server is discovered rather than addressed. See
/// [`dhcp`](crate::protocols::dhcp) for why a port scan cannot ask this
/// question.
///
/// **The role goes on the address the server named for itself, and only when
/// the message came from that address.** A relay agent forwarding for a server
/// on another segment sends the reply from its own address while the message
/// inside names the server; marking the sender would name the relay a DHCP
/// server, and marking the named address would attach the role to a machine
/// this frame is no evidence about. Where they disagree the reply still proves
/// its sender is there, which is all it proves.
pub struct DhcpProtocol;

impl DiscoveryProtocol for DhcpProtocol {
    fn interpret(&self, frame: &Frame<'_>) -> anyhow::Result<Reading> {
        let Some(reply) = dhcp::server_reply(frame) else {
            return Ok(Reading::unhandled());
        };

        let named_itself = matches!(
            (reply.server, ip::ipv4_source(frame)),
            (Some(server), Ok(source)) if server == source
        );

        Ok(match named_itself {
            true => Reading::declaring(ProtocolMatch::Unsolicited, NetworkRole::DhcpServer),
            false => Reading::matched(ProtocolMatch::Unsolicited),
        })
    }

    fn status_protocol(&self) -> StatusProtocol {
        StatusProtocol::Dhcp
    }

    /// Both DHCP ports, though only a server's reply is read.
    ///
    /// Matching either direction rather than `src port 67` alone costs nothing
    /// and leaves a reader that wants to see the request as well as the answer
    /// something to work with, rather than a silence to debug.
    fn capture_clause(&self) -> &'static str {
        "(udp port 67 or udp port 68)"
    }
}

/// Recognizes ICMPv6 echo replies as answers to the all-nodes echo request sent
/// at the start of a sweep.
///
/// Unlike ARP, that probe is not sent per target: it is one multicast echo
/// request any IPv6 neighbour may answer, so it is measured against every
/// qualifying reply rather than being consumed by the first.
///
/// The reply has to be an echo reply, and the check is not a formality. An
/// Ethernet frame from a neighbour proves the neighbour exists whatever it
/// carries, but the *evidence* recorded for it has to name what was actually
/// observed: crediting a segment of unrelated IPv6 traffic to the echo probe
/// attributes a host to a mechanism that had nothing to do with finding it, and
/// a coverage measurement built on that cannot tell a working probe from a
/// chatty network. Traffic this does not recognize is left for another
/// [`DiscoveryProtocol`] to claim - a neighbor advertisement being handled by
/// [`NdpProtocol`].
///
/// The identifier and sequence come back with the match rather than being
/// checked here, because this trait sees bytes and not the scan that sent them.
/// Deciding whether those values name one of *our* requests, and which, is the
/// scanner's job for the same reason attribution always is.
pub struct Icmpv6EchoProtocol;

impl DiscoveryProtocol for Icmpv6EchoProtocol {
    fn interpret(&self, frame: &Frame<'_>) -> anyhow::Result<Reading> {
        if frame.ethertype() != EtherTypes::Ipv6 {
            return Ok(Reading::unhandled());
        }

        // The probe leaves from this host's link-local address, so an answer to
        // it comes back to one. Not proof the frame is addressed to *us* - that
        // needs an address this trait deliberately does not have - but it rules
        // out the multicast and global traffic a promiscuous capture also sees.
        let destination = ip::ipv6_destination(frame)?;
        if !destination.is_unicast_link_local() {
            return Ok(Reading::unhandled());
        }

        match ip::icmpv6_echo_token(frame) {
            Some((identifier, sequence)) => Ok(Reading::matched(ProtocolMatch::AllNodes {
                identifier,
                sequence,
            })),
            None => Ok(Reading::unhandled()),
        }
    }

    fn status_protocol(&self) -> StatusProtocol {
        StatusProtocol::IcmpEcho
    }

    /// See [`NdpProtocol::capture_clause`]. The all-nodes echo is answered over
    /// ICMPv6 and needs no clause of its own.
    fn capture_clause(&self) -> &'static str {
        "icmp6"
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
pub(crate) mod tests {

    /// A segment produced an advertisement naming `fe80::`, and the host that
    /// sent it was then credited with an address nothing can hold — which read
    /// as an address it had *gained* when the segment was swept again.
    #[test]
    fn an_advertisement_naming_an_address_nothing_can_hold_is_left_alone() {
        use std::net::Ipv6Addr;

        assert!(!is_assignable(Ipv6Addr::UNSPECIFIED));
        assert!(
            !is_assignable("fe80::".parse().expect("a valid address")),
            "the link-local prefix is not an address in it"
        );

        assert!(is_assignable("fe80::1".parse().expect("a valid address")));
        assert!(is_assignable(
            "fe80::ca52:61ff:fec7:594".parse().expect("a valid address")
        ));
        assert!(is_assignable(
            "2a02:908:8c1:b880::1".parse().expect("a valid address")
        ));
    }
    use super::*;
    use crate::protocols::{arp, ethernet, ip as ip_protocol};
    use pnet::datalink::MacAddr;
    use pnet::packet::icmpv6::echo_reply::{Icmpv6Codes, MutableEchoReplyPacket};
    use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
    use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
    use std::net::{Ipv4Addr, Ipv6Addr};

    pub(crate) const LOCAL_MAC: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
    pub(crate) const PEER_MAC: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x02);
    pub(crate) const ICMPV6_ECHO_LEN: usize = 8;

    pub(crate) fn arp_reply_frame(sender_ip: Ipv4Addr) -> Vec<u8> {
        arp::create_request(&PEER_MAC, &sender_ip, Ipv4Addr::new(10, 0, 0, 1))
    }

    /// An Ethernet-framed IPv6 packet to `destination`, carrying `body` as
    /// `protocol`.
    pub(crate) fn ipv6_frame(
        destination: Ipv6Addr,
        protocol: IpNextHeaderProtocol,
        body: &[u8],
    ) -> Vec<u8> {
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let eth_header = ethernet::create_header(
            PEER_MAC,
            LOCAL_MAC,
            pnet::packet::ethernet::EtherTypes::Ipv6,
        );
        let ip_header = ip_protocol::create_ipv6_header(
            source,
            destination,
            body.len() as u16,
            protocol,
            ip_protocol::HOP_LIMIT_ON_LINK,
        );

        [eth_header, ip_header, body.to_vec()].concat()
    }

    /// The frame a neighbour actually sends back when it answers the all-nodes
    /// echo request, echoing the request's identifier and sequence as RFC 4443
    /// requires.
    pub(crate) fn echo_reply_frame_with(
        destination: Ipv6Addr,
        identifier: u16,
        sequence: u16,
    ) -> Vec<u8> {
        let mut body = vec![0u8; ICMPV6_ECHO_LEN];
        {
            let mut echo = MutableEchoReplyPacket::new(&mut body).expect("echo reply buffer");
            echo.set_icmpv6_type(Icmpv6Types::EchoReply);
            echo.set_icmpv6_code(Icmpv6Codes::NoCode);
            echo.set_identifier(identifier);
            echo.set_sequence_number(sequence);
        }
        ipv6_frame(destination, IpNextHeaderProtocols::Icmpv6, &body)
    }

    pub(crate) fn echo_reply_frame(destination: Ipv6Addr) -> Vec<u8> {
        echo_reply_frame_with(destination, 0, 0)
    }

    /// A neighbor solicitation body: ICMPv6, but not an answer to our probe.
    pub(crate) fn neighbor_solicitation_body() -> Vec<u8> {
        let mut body = vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + 20];
        {
            let mut icmp = MutableIcmpv6Packet::new(&mut body).expect("icmpv6 buffer");
            icmp.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
        }
        body
    }

    #[test]
    fn arp_protocol_ignores_non_arp_frames() {
        let frame_bytes = echo_reply_frame(Ipv6Addr::LOCALHOST);
        let frame = crate::protocols::ethernet::parse(&frame_bytes).unwrap();

        let result = ArpProtocol.interpret(&frame);

        assert!(matches!(result.unwrap().matched, ProtocolMatch::Unhandled));
    }

    /// An ARP frame answers a probe aimed at the address that sent it, which is
    /// what entitles the scanner to retire exactly that probe.
    #[test]
    fn arp_protocol_claims_arp_frames_as_solicited() {
        let frame_bytes = arp_reply_frame(Ipv4Addr::new(192, 168, 1, 50));
        let frame = crate::protocols::ethernet::parse(&frame_bytes).unwrap();

        let result = ArpProtocol.interpret(&frame).unwrap();

        assert!(matches!(result.matched, ProtocolMatch::Solicited(None)));
    }

    #[test]
    fn icmpv6_protocol_ignores_non_ipv6_frames() {
        let frame_bytes = arp_reply_frame(Ipv4Addr::new(10, 0, 0, 2));
        let frame = crate::protocols::ethernet::parse(&frame_bytes).unwrap();

        let result = Icmpv6EchoProtocol.interpret(&frame);

        assert!(matches!(result.unwrap().matched, ProtocolMatch::Unhandled));
    }

    #[test]
    fn icmpv6_protocol_ignores_traffic_not_addressed_to_a_link_local_unicast() {
        let frame_bytes = echo_reply_frame(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)); // multicast
        let frame = crate::protocols::ethernet::parse(&frame_bytes).unwrap();

        let result = Icmpv6EchoProtocol.interpret(&frame);

        assert!(matches!(result.unwrap().matched, ProtocolMatch::Unhandled));
    }

    /// An echo reply aimed at this host answers the all-nodes echo request, and
    /// every neighbour may answer the same one - so the match must not imply
    /// that any single probe has been used up.
    #[test]
    fn icmpv6_protocol_claims_an_echo_reply_for_the_all_nodes_probe() {
        let frame_bytes = echo_reply_frame(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let frame = crate::protocols::ethernet::parse(&frame_bytes).unwrap();

        for _ in 0..2 {
            let result = Icmpv6EchoProtocol.interpret(&frame).unwrap();
            assert!(matches!(result.matched, ProtocolMatch::AllNodes { .. }));
        }
        assert_eq!(
            Icmpv6EchoProtocol.status_protocol(),
            StatusProtocol::IcmpEcho
        );
    }

    /// The identifier and sequence have to survive interpretation, because they
    /// are the whole of what makes an echo reply measurable: they name which
    /// request was answered, where two neighbor solicitations never can.
    /// Dropping them here is what left every IPv6 neighbour with no round trip.
    #[test]
    fn icmpv6_protocol_carries_the_echoed_token_back() {
        let frame_bytes =
            echo_reply_frame_with(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 0x5ac5, 2);
        let frame = crate::protocols::ethernet::parse(&frame_bytes).unwrap();

        let result = Icmpv6EchoProtocol.interpret(&frame).unwrap();

        assert!(matches!(
            result.matched,
            ProtocolMatch::AllNodes {
                identifier: 0x5ac5,
                sequence: 2
            }
        ));
    }

    /// The regression guard for a scanner crediting its echo probe with finding
    /// a host that never answered it.
    ///
    /// A promiscuous capture on a live segment sees a great deal of IPv6 between
    /// other hosts, and a bare header with no ICMPv6 message behind it is not an
    /// answer to anything. Claiming either as a reply attributes a host to a
    /// mechanism that did not find it, which is invisible in a host count and
    /// fatal to any measurement of what the IPv6 probe contributes.
    #[test]
    fn icmpv6_protocol_ignores_ipv6_traffic_that_is_not_an_echo_reply() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

        for frame_bytes in [
            // A TCP segment between two neighbours.
            ipv6_frame(link_local, IpNextHeaderProtocols::Tcp, &[0u8; 20]),
            // ICMPv6, but a neighbor solicitation rather than an echo reply.
            ipv6_frame(
                link_local,
                IpNextHeaderProtocols::Icmpv6,
                &neighbor_solicitation_body(),
            ),
            // An IPv6 header with nothing behind it at all.
            ipv6_frame(link_local, IpNextHeaderProtocols::Icmpv6, &[]),
        ] {
            let frame = crate::protocols::ethernet::parse(&frame_bytes).unwrap();
            assert!(matches!(
                Icmpv6EchoProtocol.interpret(&frame).unwrap().matched,
                ProtocolMatch::Unhandled
            ));
        }
    }

    /// A frame carrying a neighbour discovery message, which is the one kind of
    /// traffic that must arrive with a hop limit of 255 to be believed.
    pub(crate) fn ndp_frame(body: &[u8]) -> Vec<u8> {
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let eth_header = ethernet::create_header(
            PEER_MAC,
            LOCAL_MAC,
            pnet::packet::ethernet::EtherTypes::Ipv6,
        );
        let ip_header = ip_protocol::create_ipv6_header(
            source,
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
            body.len() as u16,
            IpNextHeaderProtocols::Icmpv6,
            ip_protocol::HOP_LIMIT_NDP,
        );

        [eth_header, ip_header, body.to_vec()].concat()
    }

    /// A neighbour advertisement for `target`, with the flag byte a real one
    /// carries.
    pub(crate) fn advertisement_body(target: Ipv6Addr, flags: u8) -> Vec<u8> {
        let mut body = vec![0u8; 24];
        {
            let mut advert = pnet::packet::icmpv6::ndp::MutableNeighborAdvertPacket::new(&mut body)
                .expect("advertisement buffer");
            advert.set_icmpv6_type(Icmpv6Types::NeighborAdvert);
            advert.set_target_addr(target);
            advert.set_flags(flags);
        }
        body
    }

    /// The declaration has to survive the trip from the wire to the scanner. A
    /// neighbour that answers our solicitation and sets the R flag is a router
    /// found for free, in a reply the sweep was already going to receive — and
    /// the same reply without the flag claims nothing, which is what keeps the
    /// role off every host that merely answered.
    #[test]
    fn an_advertisement_declares_a_router_only_when_its_sender_said_so() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA);

        for (flags, declared) in [(0b1000_0000, Some(NetworkRole::Router)), (0, None)] {
            let frame_bytes = ndp_frame(&advertisement_body(target, flags));
            let frame = crate::protocols::ethernet::parse(&frame_bytes).unwrap();

            let reading = NdpProtocol.interpret(&frame).unwrap();

            assert!(matches!(
                reading.matched,
                ProtocolMatch::Solicited(Some(IpAddr::V6(claimed))) if claimed == target
            ));
            assert_eq!(reading.declared, declared, "flags {flags:#010b}");
        }
    }

    /// An advertisement only a router sends: claimed for its source, because
    /// unlike a neighbour advertisement it names no target of its own, and
    /// declaring what its sender is is the whole of why it is read.
    #[test]
    fn a_router_advertisement_names_its_sender_a_router() {
        let mut body = vec![0u8; 16];
        body[0] = Icmpv6Types::RouterAdvert.0;
        let frame_bytes = ndp_frame(&body);
        let frame = crate::protocols::ethernet::parse(&frame_bytes).unwrap();

        let reading = RouterAdvertProtocol.interpret(&frame).unwrap();

        assert!(matches!(reading.matched, ProtocolMatch::Unsolicited));
        assert_eq!(reading.declared, Some(NetworkRole::Router));
        assert_eq!(RouterAdvertProtocol.status_protocol(), StatusProtocol::Ndp);

        // Everything else on the segment stays with whichever protocol owns it.
        let neighbour = ndp_frame(&advertisement_body(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA),
            0b1000_0000,
        ));
        let frame = crate::protocols::ethernet::parse(&neighbour).unwrap();
        assert!(matches!(
            RouterAdvertProtocol.interpret(&frame).unwrap().matched,
            ProtocolMatch::Unhandled
        ));
    }

    /// A server's answer names the server, and a relay's forwarding does not
    /// name the relay.
    ///
    /// The second half is the one worth pinning. On a network with a relay
    /// agent the reply arrives from the relay's address carrying a server
    /// identifier for a machine on another segment, and both of the obvious
    /// readings are wrong: marking the sender names a relay a DHCP server, and
    /// marking the named address attaches a role to a machine this frame says
    /// nothing about. It proves the relay is there, and that is all.
    #[test]
    fn a_dhcp_answer_names_a_server_only_where_the_server_answered() {
        let server = Ipv4Addr::new(192, 168, 1, 1);

        let itself = dhcp_reply_frame(server, Some(server));
        let frame = crate::protocols::ethernet::parse(&itself).unwrap();
        let reading = DhcpProtocol.interpret(&frame).unwrap();
        assert!(matches!(reading.matched, ProtocolMatch::Unsolicited));
        assert_eq!(reading.declared, Some(NetworkRole::DhcpServer));

        // The same message forwarded by a relay, which is where the address in
        // the packet and the address in the message part company.
        let relayed = dhcp_reply_frame(server, Some(Ipv4Addr::new(10, 0, 0, 254)));
        let frame = crate::protocols::ethernet::parse(&relayed).unwrap();
        let reading = DhcpProtocol.interpret(&frame).unwrap();
        assert!(matches!(reading.matched, ProtocolMatch::Unsolicited));
        assert_eq!(
            reading.declared, None,
            "the sender is a relay, not a server"
        );

        // A client's own broadcast, which every machine on the segment sends.
        let frame_bytes = arp_reply_frame(Ipv4Addr::new(192, 168, 1, 20));
        let frame = crate::protocols::ethernet::parse(&frame_bytes).unwrap();
        assert!(matches!(
            DhcpProtocol.interpret(&frame).unwrap().matched,
            ProtocolMatch::Unhandled
        ));
    }

    /// A DHCP acknowledgement sent from `from`, naming `server_id` as the
    /// server.
    pub(crate) fn dhcp_reply_frame(server_id: Ipv4Addr, from: Option<Ipv4Addr>) -> Vec<u8> {
        const BOOTREPLY: u8 = 2;
        const FIXED_LEN: usize = 236;

        let mut message = vec![0u8; FIXED_LEN];
        message[0] = BOOTREPLY;
        message.extend_from_slice(&[99, 130, 83, 99]);
        message.extend_from_slice(&[53, 1, 5]); // DHCPACK
        message.push(54);
        message.push(4);
        message.extend_from_slice(&server_id.octets());
        message.push(255);

        let datagram = crate::protocols::craft::Packet::new()
            .push(crate::protocols::craft::Ipv4::new(
                from.unwrap_or(server_id),
                Ipv4Addr::new(192, 168, 1, 50),
            ))
            .push(
                crate::protocols::craft::Udp::new(dhcp::SERVER_PORT, dhcp::CLIENT_PORT)
                    .with_payload(message),
            )
            .build()
            .expect("a test datagram");

        [
            ethernet::create_header(
                PEER_MAC,
                LOCAL_MAC,
                pnet::packet::ethernet::EtherTypes::Ipv4,
            ),
            datagram,
        ]
        .concat()
    }

    /// An mDNS response as it arrives on the segment: UDP from port 5353, which
    /// is the only thing `absorb_mdns` matches on.
    pub(crate) fn mdns_frame() -> Vec<u8> {
        let datagram = crate::protocols::craft::Packet::new()
            .push(crate::protocols::craft::Ipv4::new(
                Ipv4Addr::new(192, 168, 1, 50),
                Ipv4Addr::new(224, 0, 0, 251),
            ))
            .push(
                crate::protocols::craft::Udp::new(
                    crate::protocols::mdns::PORT,
                    crate::protocols::mdns::PORT,
                )
                .with_payload(vec![0u8; 12]),
            )
            .build()
            .expect("a test datagram");

        [
            ethernet::create_header(
                PEER_MAC,
                LOCAL_MAC,
                pnet::packet::ethernet::EtherTypes::Ipv4,
            ),
            datagram,
        ]
        .concat()
    }
}
