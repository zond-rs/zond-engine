// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Discovery Response Protocols
//!
//! Each reply format [`LocalScanner`](super::local::LocalScanner) recognizes is
//! a [`DiscoveryProtocol`] implementation, tried in turn against every received
//! frame. A new discovery mechanism is one more implementation here.

use std::net::IpAddr;

use pnet_packet::ethernet::EtherTypes;

use crate::protocols::ethernet::Frame;

use crate::model::host::{NetworkRole, StatusProtocol};
use crate::protocols::error::PacketError;
use crate::protocols::{dhcp, ip, ndp};

/// What a [`DiscoveryProtocol`] found when asked to interpret one received frame.
///
/// A protocol only reads bytes; the scanner, which knows what it sent and
/// when, decides which outstanding probe a frame retires.
#[non_exhaustive]
pub enum ProtocolMatch {
    /// The protocol does not recognize this frame. Another protocol may still
    /// claim it.
    Unhandled,
    /// A reply to a probe aimed at one address, so it answers exactly one
    /// outstanding probe and retires it.
    ///
    /// Carries the address asked about, since the frame's source may differ:
    /// a neighbor advertisement names it in its target field, and a host with
    /// several addresses answers from whichever its stack prefers. On a real
    /// segment a phone solicited at one global address answered from another.
    ///
    /// `None` where the frame's source is the address, as with ARP.
    Solicited(Option<IpAddr>),
    /// A message that proves its sender is present and answers nothing this
    /// scan sent.
    ///
    /// A router advertising on its own timer, or a DHCP server answering the
    /// segment. A probe outstanding for the same address is left alone:
    /// retiring it would time the gap between two unrelated messages.
    ///
    /// The sender is then asked directly, to measure it. See
    /// `LocalScanner::confirm`.
    Unsolicited,
    /// A reply to the all-nodes echo request, carrying the identifier and
    /// sequence number it echoed back.
    ///
    /// No single reply consumes that probe, since every neighbour may answer
    /// it. RFC 4443 requires the reply to return the request's identifier and
    /// sequence unchanged, so it names which echo request was answered and
    /// yields a round trip, which a repeated neighbor solicitation cannot.
    AllNodes {
        /// The identifier echoed back; one value per run, which separates our
        /// pings from others'.
        identifier: u16,
        /// The sequence number echoed back, which names the attempt.
        sequence: u16,
    },
}

/// Everything one frame turned out to say.
///
/// [`matched`](field@Reading::matched) is what the frame does to the ledger of
/// outstanding probes; [`declared`](field@Reading::declared) is what its sender
/// said about itself in the same message, such as a neighbour advertisement's
/// R flag. Both come from one parse of the frame.
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
/// [`LocalScanner`](super::local::LocalScanner) tries each protocol against
/// every received frame in turn, and the first to claim it decides what kind of
/// answer it is. The scanner has already identified the source and dropped
/// noise (its own packets, addresses outside the scan), so an implementation is
/// a pure function of the bytes.
pub trait DiscoveryProtocol: Send {
    /// Reads one frame: what it answers, and what its sender claimed about
    /// itself while answering.
    ///
    /// Return [`ProtocolMatch::Unhandled`] for another protocol's frame, and the
    /// sweep offers it to the next reader.
    ///
    /// # Errors
    ///
    /// [`PacketError`], as the parsers in [`protocols`](crate::protocols)
    /// return, for a frame this protocol owns and could not parse. The frame is
    /// then credited to nobody.
    fn interpret(&self, frame: &Frame<'_>) -> Result<Reading, PacketError>;

    /// Reads one IP packet that arrived with no link-layer header, off a
    /// tunnel or a PPP link, as [`interpret`](Self::interpret) reads a frame.
    ///
    /// Unhandled by default, since ARP and DHCP broadcasts need hardware
    /// addresses. A protocol whose message is plain IP reads it here too.
    fn interpret_packet(&self, _packet: &[u8]) -> Reading {
        Reading::unhandled()
    }

    /// The evidence this protocol produces, for the liveness record of whichever
    /// host it claims a frame from.
    fn status_protocol(&self) -> StatusProtocol;

    /// The `libpcap` filter clause admitting the frames this protocol reads.
    ///
    /// The sweep's filter is the union of these, so a protocol widens the
    /// capture beside its [`interpret`](Self::interpret). Traffic no clause
    /// admits never reaches a protocol, and that failure is silent.
    ///
    /// Clauses are joined with `or`, so each must parenthesise anything that
    /// would not survive that.
    fn capture_clause(&self) -> &'static str;
}

/// Every protocol a local sweep reads, in the order it tries them against a
/// frame.
///
/// Read both to build the scanner's interpreters and to build its capture
/// filter, so the two always agree.
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
/// Every ARP frame from an in-range address counts, including other hosts'
/// requests and gratuitous announcements: each proves its sender is there.
/// The scanner decides whether a probe was outstanding to yield a round trip.
pub struct ArpProtocol;

impl DiscoveryProtocol for ArpProtocol {
    fn interpret(&self, frame: &Frame<'_>) -> Result<Reading, PacketError> {
        if frame.ethertype() != EtherTypes::Arp.0 {
            return Ok(Reading::unhandled());
        }

        Ok(Reading::matched(ProtocolMatch::Solicited(None)))
    }

    fn status_protocol(&self) -> StatusProtocol {
        StatusProtocol::Arp
    }

    /// Every ARP frame on the segment, requests included.
    fn capture_clause(&self) -> &'static str {
        "arp"
    }
}

/// Recognizes neighbor advertisements as answers to the solicitation sent for
/// one address.
///
/// The IPv6 counterpart of [`ArpProtocol`]: the reply carries the neighbour's
/// own MAC, and it retires that address's outstanding probe in the retry
/// ledger. As with ARP, every advertisement from an in-range address counts,
/// however it was provoked.
pub struct NdpProtocol;

impl NdpProtocol {
    /// What `advert` answers, and what its sender said of itself.
    fn read(advert: Option<ndp::Advertisement>) -> Reading {
        match advert {
            Some(advert) if is_assignable(advert.target) => {
                let matched = ProtocolMatch::Solicited(Some(IpAddr::V6(advert.target)));
                match advert.router {
                    true => Reading::declaring(matched, NetworkRole::Router),
                    false => Reading::matched(matched),
                }
            }
            // An address nothing can hold says nothing about which address the
            // sender has, so the frame is left for another protocol.
            Some(_) | None => Reading::unhandled(),
        }
    }
}

impl DiscoveryProtocol for NdpProtocol {
    fn interpret(&self, frame: &Frame<'_>) -> Result<Reading, PacketError> {
        Ok(Self::read(ndp::advertisement(frame)))
    }

    fn interpret_packet(&self, packet: &[u8]) -> Reading {
        Self::read(ndp::advertisement_in(packet))
    }

    fn status_protocol(&self) -> StatusProtocol {
        StatusProtocol::Ndp
    }

    /// All of ICMPv6: BPF cannot select the neighbour-discovery types without
    /// reading past a variable-length header. ICMPv6 on a segment is nearly all
    /// neighbour discovery, and the other IPv6 readers share this clause.
    fn capture_clause(&self) -> &'static str {
        "icmp6"
    }
}

/// Whether an address is one an interface can actually hold.
///
/// Devices on real segments send advertisements naming addresses that are not
/// addresses. Recorded, these would be reported as addresses the host gained on
/// the next sweep. Refused:
///
/// - **The unspecified address** `::`.
/// - **A link-local with a zero interface identifier.** `fe80::` is the prefix;
///   RFC 4291 reserves the all-zeros 64-bit interface identifier.
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
/// Routers advertise unprompted every few minutes, and the capture is
/// promiscuous, so these arrive for free. A sweep also solicits one (see
/// [`LocalScanner`](super::local::LocalScanner)), since it lasts seconds.
///
/// Claimed as [`Unsolicited`](ProtocolMatch::Unsolicited) and filed under the
/// frame's source, which RFC 4861 §4.2 requires to be the sender's link-local
/// address. Unsolicited even when the sweep asked, because its solicitation goes
/// to every router at once and no reply belongs to one address's probe.
pub struct RouterAdvertProtocol;

impl RouterAdvertProtocol {
    /// What a message is, given whether it is a router advertisement.
    fn read(advertises: bool) -> Reading {
        match advertises {
            true => Reading::declaring(ProtocolMatch::Unsolicited, NetworkRole::Router),
            false => Reading::unhandled(),
        }
    }
}

impl DiscoveryProtocol for RouterAdvertProtocol {
    fn interpret(&self, frame: &Frame<'_>) -> Result<Reading, PacketError> {
        Ok(Self::read(ndp::is_router_advertisement(frame)))
    }

    fn interpret_packet(&self, packet: &[u8]) -> Reading {
        Self::read(ndp::is_router_advertisement_in(packet))
    }

    fn status_protocol(&self) -> StatusProtocol {
        StatusProtocol::Ndp
    }

    /// See [`NdpProtocol::capture_clause`].
    fn capture_clause(&self) -> &'static str {
        "icmp6"
    }
}

/// Recognizes a DHCP server answering the segment.
///
/// The IPv4 counterpart of [`RouterAdvertProtocol`]. DHCP runs on broadcast,
/// so this is the only way to find a server; see [`dhcp`] for why a port scan
/// cannot.
///
/// The role is declared only when the message came from the address the server
/// named for itself. A relay agent sends the reply from its own address while
/// the message names a server on another segment; then the reply only proves
/// the relay is there.
pub struct DhcpProtocol;

impl DiscoveryProtocol for DhcpProtocol {
    fn interpret(&self, frame: &Frame<'_>) -> Result<Reading, PacketError> {
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
    fn capture_clause(&self) -> &'static str {
        "(udp port 67 or udp port 68)"
    }
}

/// Recognizes ICMPv6 echo replies as answers to the all-nodes echo request sent
/// at the start of a sweep.
///
/// One multicast request any neighbour may answer, so every qualifying reply
/// is measured against it.
///
/// Only echo replies count. Crediting unrelated IPv6 traffic to the echo probe
/// would make coverage measurements unable to tell a working probe from a
/// chatty network. Anything else is left for another [`DiscoveryProtocol`],
/// such as [`NdpProtocol`].
///
/// The identifier and sequence are returned unchecked; the scanner decides
/// whether they name one of its requests.
///
/// Also read off links with no Ethernet header (tunnels, PPP), where a
/// listener runs though a sweep does not.
pub struct Icmpv6EchoProtocol;

impl Icmpv6EchoProtocol {
    /// What an IPv6 packet sent to `destination` answers, `token` being the
    /// identifier and sequence it carries back where it is an echo reply.
    fn read(destination: std::net::Ipv6Addr, token: Option<(u16, u16)>) -> Reading {
        // The probe leaves from a link-local address, so its answer comes back
        // to one. This trait cannot check it is ours, but it rules out the
        // multicast and global traffic a promiscuous capture sees.
        if !destination.is_unicast_link_local() {
            return Reading::unhandled();
        }

        match token {
            Some((identifier, sequence)) => Reading::matched(ProtocolMatch::AllNodes {
                identifier,
                sequence,
            }),
            None => Reading::unhandled(),
        }
    }
}

impl DiscoveryProtocol for Icmpv6EchoProtocol {
    fn interpret(&self, frame: &Frame<'_>) -> Result<Reading, PacketError> {
        if frame.ethertype() != EtherTypes::Ipv6.0 {
            return Ok(Reading::unhandled());
        }

        let destination = ip::ipv6_destination(frame)?;
        Ok(Self::read(destination, ip::icmpv6_echo_token(frame)))
    }

    fn interpret_packet(&self, packet: &[u8]) -> Reading {
        match ip::ipv6_carrying_in(packet, pnet_packet::ip::IpNextHeaderProtocols::Icmpv6) {
            Some(ipv6) => Self::read(ipv6.get_destination(), ip::icmpv6_echo_token_in(packet)),
            None => Reading::unhandled(),
        }
    }

    fn status_protocol(&self) -> StatusProtocol {
        StatusProtocol::IcmpEcho
    }

    /// See [`NdpProtocol::capture_clause`].
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
    use super::*;
    use crate::model::mac::MacAddr;
    use crate::protocols::mac::IntoPnetMac;
    use crate::protocols::{arp, ethernet, ip as ip_protocol};
    use pnet_packet::icmpv6::echo_reply::{Icmpv6Codes, MutableEchoReplyPacket};
    use pnet_packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
    use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
    use std::net::{Ipv4Addr, Ipv6Addr};

    pub(crate) const LOCAL_MAC: MacAddr = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
    pub(crate) const PEER_MAC: MacAddr = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x02);
    pub(crate) const ICMPV6_ECHO_LEN: usize = 8;

    /// The reply a neighbour at `sender_ip` sends to this host's request.
    pub(crate) fn arp_reply_frame(sender_ip: Ipv4Addr) -> Vec<u8> {
        use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};

        let mut body = vec![0u8; MutableArpPacket::minimum_packet_size()];
        let mut reply = MutableArpPacket::new(&mut body).expect("sized for the packet");
        reply.set_hardware_type(ArpHardwareTypes::Ethernet);
        reply.set_protocol_type(pnet_packet::ethernet::EtherTypes::Ipv4);
        reply.set_hw_addr_len(6);
        reply.set_proto_addr_len(4);
        reply.set_operation(ArpOperations::Reply);
        reply.set_sender_hw_addr(PEER_MAC.into_pnet());
        reply.set_sender_proto_addr(sender_ip);
        reply.set_target_hw_addr(LOCAL_MAC.into_pnet());
        reply.set_target_proto_addr(Ipv4Addr::new(198, 51, 100, 1));
        let header = ethernet::build_header(
            PEER_MAC,
            LOCAL_MAC,
            pnet_packet::ethernet::EtherTypes::Arp.0,
        );
        [header, body].concat()
    }

    /// A request a neighbour at `sender_ip` broadcasts for an address of its
    /// own asking.
    pub(crate) fn arp_request_frame(sender_ip: Ipv4Addr) -> Vec<u8> {
        arp::build_request(PEER_MAC, sender_ip, Ipv4Addr::new(198, 51, 100, 254))
    }

    /// An Ethernet-framed IPv6 packet to `destination`, carrying `body` as
    /// `protocol`.
    pub(crate) fn ipv6_frame(
        destination: Ipv6Addr,
        protocol: IpNextHeaderProtocol,
        body: &[u8],
    ) -> Vec<u8> {
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let eth_header = ethernet::build_header(
            PEER_MAC,
            LOCAL_MAC,
            pnet_packet::ethernet::EtherTypes::Ipv6.0,
        );
        let ip_header = ip_protocol::build_ipv6_header(
            source,
            destination,
            body.len() as u16,
            protocol.0,
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

    /// Real segments carry advertisements naming `fe80::`, which no host can
    /// hold.
    #[test]
    fn an_advertisement_naming_an_address_nothing_can_hold_is_left_alone() {
        assert!(!is_assignable(Ipv6Addr::UNSPECIFIED));
        assert!(
            !is_assignable("fe80::".parse().expect("a valid address")),
            "the link-local prefix is not an address in it"
        );

        assert!(is_assignable("fe80::1".parse().expect("a valid address")));
        assert!(is_assignable(
            "fe80::a8bb:ccff:fedd:eeff"
                .parse()
                .expect("a valid address")
        ));
        assert!(is_assignable(
            "2001:db8::1".parse().expect("a valid address")
        ));
    }

    #[test]
    fn arp_protocol_ignores_non_arp_frames() {
        let frame_bytes = echo_reply_frame(Ipv6Addr::LOCALHOST);
        let frame = crate::protocols::ethernet::parse(&frame_bytes).unwrap();

        let result = ArpProtocol.interpret(&frame);

        assert!(matches!(result.unwrap().matched, ProtocolMatch::Unhandled));
    }

    /// An ARP frame answers the probe aimed at the address that sent it.
    #[test]
    fn arp_protocol_claims_arp_frames_as_solicited() {
        let frame_bytes = arp_reply_frame(Ipv4Addr::new(192, 0, 2, 50));
        let frame = crate::protocols::ethernet::parse(&frame_bytes).unwrap();

        let result = ArpProtocol.interpret(&frame).unwrap();

        assert!(matches!(result.matched, ProtocolMatch::Solicited(None)));
    }

    #[test]
    fn icmpv6_protocol_ignores_non_ipv6_frames() {
        let frame_bytes = arp_reply_frame(Ipv4Addr::new(198, 51, 100, 2));
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

    /// Every neighbour may answer the same all-nodes echo request, so a match
    /// consumes no probe.
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

    /// The identifier and sequence survive interpretation; they name which
    /// request was answered, which makes the reply measurable.
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

    /// The echo probe is not credited with hosts that never answered it: a
    /// promiscuous capture sees plenty of other IPv6, and a bare header answers
    /// nothing.
    #[test]
    fn icmpv6_protocol_ignores_ipv6_traffic_that_is_not_an_echo_reply() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

        for frame_bytes in [
            ipv6_frame(link_local, IpNextHeaderProtocols::Tcp, &[0u8; 20]),
            // ICMPv6, but a neighbor solicitation.
            ipv6_frame(
                link_local,
                IpNextHeaderProtocols::Icmpv6,
                &neighbor_solicitation_body(),
            ),
            // A bare IPv6 header.
            ipv6_frame(link_local, IpNextHeaderProtocols::Icmpv6, &[]),
        ] {
            let frame = crate::protocols::ethernet::parse(&frame_bytes).unwrap();
            assert!(matches!(
                Icmpv6EchoProtocol.interpret(&frame).unwrap().matched,
                ProtocolMatch::Unhandled
            ));
        }
    }

    /// Off a link with no Ethernet header the echo reader applies the same
    /// test. The version nibble is all such a link says about the family, so
    /// an IPv4 packet must not be read as an IPv6 header.
    #[test]
    fn icmpv6_protocol_reads_a_bare_packet_as_it_reads_a_frame() {
        let answered = echo_reply_frame_with(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 7, 3);
        assert!(matches!(
            Icmpv6EchoProtocol.interpret_packet(&answered[14..]).matched,
            ProtocolMatch::AllNodes {
                identifier: 7,
                sequence: 3
            }
        ));

        let multicast = echo_reply_frame(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        let ipv4 = arp_reply_frame(Ipv4Addr::new(198, 51, 100, 2));
        let mut ipv4_header = vec![0x45u8; 1];
        ipv4_header.extend_from_slice(&ipv4[15..]);
        for (what, packet) in [("multicast", &multicast[14..]), ("ipv4", &ipv4_header[..])] {
            assert!(
                matches!(
                    Icmpv6EchoProtocol.interpret_packet(packet).matched,
                    ProtocolMatch::Unhandled
                ),
                "{what}"
            );
        }
    }

    /// A frame carrying a neighbour discovery message, with the hop limit of
    /// 255 such a message needs to be believed.
    pub(crate) fn ndp_frame(body: &[u8]) -> Vec<u8> {
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let eth_header = ethernet::build_header(
            PEER_MAC,
            LOCAL_MAC,
            pnet_packet::ethernet::EtherTypes::Ipv6.0,
        );
        let ip_header = ip_protocol::build_ipv6_header(
            source,
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
            body.len() as u16,
            IpNextHeaderProtocols::Icmpv6.0,
            ip_protocol::HOP_LIMIT_NDP,
        );

        [eth_header, ip_header, body.to_vec()].concat()
    }

    /// A neighbour advertisement for `target`, with the flag byte a real one
    /// carries.
    pub(crate) fn advertisement_body(target: Ipv6Addr, flags: u8) -> Vec<u8> {
        let mut body = vec![0u8; 24];
        {
            let mut advert = pnet_packet::icmpv6::ndp::MutableNeighborAdvertPacket::new(&mut body)
                .expect("advertisement buffer");
            advert.set_icmpv6_type(Icmpv6Types::NeighborAdvert);
            advert.set_target_addr(target);
            advert.set_flags(flags);
        }
        body
    }

    /// An advertisement with the R flag declares a router; without it, the
    /// same reply declares nothing.
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

    /// A router advertisement is claimed for its source, which it declares a
    /// router.
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

    /// A server's answer names the server, and a relay's forwarding names
    /// nobody: it only proves the relay is there.
    #[test]
    fn a_dhcp_answer_names_a_server_only_where_the_server_answered() {
        let server = Ipv4Addr::new(192, 0, 2, 1);

        let itself = dhcp_reply_frame(server, Some(server));
        let frame = crate::protocols::ethernet::parse(&itself).unwrap();
        let reading = DhcpProtocol.interpret(&frame).unwrap();
        assert!(matches!(reading.matched, ProtocolMatch::Unsolicited));
        assert_eq!(reading.declared, Some(NetworkRole::DhcpServer));

        // Forwarded by a relay: the packet's source differs from the message's.
        let relayed = dhcp_reply_frame(server, Some(Ipv4Addr::new(198, 51, 100, 254)));
        let frame = crate::protocols::ethernet::parse(&relayed).unwrap();
        let reading = DhcpProtocol.interpret(&frame).unwrap();
        assert!(matches!(reading.matched, ProtocolMatch::Unsolicited));
        assert_eq!(
            reading.declared, None,
            "the sender is a relay, not a server"
        );

        // Not DHCP at all.
        let frame_bytes = arp_reply_frame(Ipv4Addr::new(192, 0, 2, 20));
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
                Ipv4Addr::new(192, 0, 2, 50),
            ))
            .push(
                crate::protocols::craft::Udp::new(dhcp::SERVER_PORT, dhcp::CLIENT_PORT)
                    .with_payload(message),
            )
            .build()
            .expect("a test datagram");

        [
            ethernet::build_header(
                PEER_MAC,
                LOCAL_MAC,
                pnet_packet::ethernet::EtherTypes::Ipv4.0,
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
                Ipv4Addr::new(192, 0, 2, 50),
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
            ethernet::build_header(
                PEER_MAC,
                LOCAL_MAC,
                pnet_packet::ethernet::EtherTypes::Ipv4.0,
            ),
            datagram,
        ]
        .concat()
    }
}
