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

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmpv6::Icmpv6Types;

use crate::core::models::host::StatusProtocol;
use crate::protocols::ip;

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
    /// A reply to the unicast probe aimed at this frame's own source address,
    /// so it answers exactly one outstanding probe and retires it.
    Solicited,
    /// A reply to the single all-nodes solicitation. That probe is not consumed
    /// by any one reply, because every neighbour on the segment may answer the
    /// same packet.
    AllNodes,
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
    fn interpret(&self, frame: &EthernetPacket) -> anyhow::Result<ProtocolMatch>;

    /// The evidence this protocol produces, for the liveness record of whichever
    /// host it claims a frame from.
    ///
    /// Each implementation names its own evidence rather than the receive loop
    /// inferring it from the frame, so a new discovery mechanism stays one more
    /// implementation in this module — the same reason `interpret` lives here.
    fn status_protocol(&self) -> StatusProtocol;
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
    fn interpret(&self, frame: &EthernetPacket) -> anyhow::Result<ProtocolMatch> {
        if frame.get_ethertype() != EtherTypes::Arp {
            return Ok(ProtocolMatch::Unhandled);
        }

        Ok(ProtocolMatch::Solicited)
    }

    fn status_protocol(&self) -> StatusProtocol {
        StatusProtocol::Arp
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
/// [`DiscoveryProtocol`] to claim - which is where a neighbor advertisement will
/// be handled when NDP exists, as its own implementation reporting
/// [`StatusProtocol::Ndp`].
pub struct Icmpv6EchoProtocol;

impl DiscoveryProtocol for Icmpv6EchoProtocol {
    fn interpret(&self, frame: &EthernetPacket) -> anyhow::Result<ProtocolMatch> {
        if frame.get_ethertype() != EtherTypes::Ipv6 {
            return Ok(ProtocolMatch::Unhandled);
        }

        // The probe leaves from this host's link-local address, so an answer to
        // it comes back to one. Not proof the frame is addressed to *us* - that
        // needs an address this trait deliberately does not have - but it rules
        // out the multicast and global traffic a promiscuous capture also sees.
        let destination = ip::get_ipv6_dst_addr_from_eth(frame)?;
        if !destination.is_unicast_link_local() {
            return Ok(ProtocolMatch::Unhandled);
        }

        match ip::icmpv6_type_from_eth(frame) {
            Some(Icmpv6Types::EchoReply) => Ok(ProtocolMatch::AllNodes),
            _ => Ok(ProtocolMatch::Unhandled),
        }
    }

    fn status_protocol(&self) -> StatusProtocol {
        StatusProtocol::IcmpEcho
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
    use crate::protocols::{arp, ethernet, ip as ip_protocol};
    use pnet::datalink::MacAddr;
    use pnet::packet::icmpv6::MutableIcmpv6Packet;
    use pnet::packet::icmpv6::echo_reply::{Icmpv6Codes, MutableEchoReplyPacket};
    use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
    use std::net::{Ipv4Addr, Ipv6Addr};

    const LOCAL_MAC: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
    const PEER_MAC: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x02);
    const ICMPV6_ECHO_LEN: usize = 8;

    fn arp_reply_frame(sender_ip: Ipv4Addr) -> Vec<u8> {
        arp::create_packet(&PEER_MAC, LOCAL_MAC, &sender_ip, Ipv4Addr::new(10, 0, 0, 1))
            .expect("failed to build ARP test frame")
    }

    /// An Ethernet-framed IPv6 packet to `destination`, carrying `body` as
    /// `protocol`.
    fn ipv6_frame(destination: Ipv6Addr, protocol: IpNextHeaderProtocol, body: &[u8]) -> Vec<u8> {
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let eth_header = ethernet::make_header(
            PEER_MAC,
            LOCAL_MAC,
            pnet::packet::ethernet::EtherTypes::Ipv6,
        )
        .expect("failed to build Ethernet header");
        let ip_header = ip_protocol::create_ipv6_header(
            source,
            destination,
            body.len() as u16,
            protocol,
            ip_protocol::HOP_LIMIT_ON_LINK,
        )
        .expect("failed to build IPv6 header");

        [eth_header, ip_header, body.to_vec()].concat()
    }

    /// The frame a neighbour actually sends back when it answers the all-nodes
    /// echo request.
    fn echo_reply_frame(destination: Ipv6Addr) -> Vec<u8> {
        let mut body = vec![0u8; ICMPV6_ECHO_LEN];
        {
            let mut echo = MutableEchoReplyPacket::new(&mut body).expect("echo reply buffer");
            echo.set_icmpv6_type(Icmpv6Types::EchoReply);
            echo.set_icmpv6_code(Icmpv6Codes::NoCode);
        }
        ipv6_frame(destination, IpNextHeaderProtocols::Icmpv6, &body)
    }

    /// A neighbor solicitation body: ICMPv6, but not an answer to our probe.
    fn neighbor_solicitation_body() -> Vec<u8> {
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
        let frame = EthernetPacket::new(&frame_bytes).unwrap();

        let result = ArpProtocol.interpret(&frame);

        assert!(matches!(result.unwrap(), ProtocolMatch::Unhandled));
    }

    /// An ARP frame answers a probe aimed at the address that sent it, which is
    /// what entitles the scanner to retire exactly that probe.
    #[test]
    fn arp_protocol_claims_arp_frames_as_solicited() {
        let frame_bytes = arp_reply_frame(Ipv4Addr::new(192, 168, 1, 50));
        let frame = EthernetPacket::new(&frame_bytes).unwrap();

        let result = ArpProtocol.interpret(&frame).unwrap();

        assert!(matches!(result, ProtocolMatch::Solicited));
    }

    #[test]
    fn icmpv6_protocol_ignores_non_ipv6_frames() {
        let frame_bytes = arp_reply_frame(Ipv4Addr::new(10, 0, 0, 2));
        let frame = EthernetPacket::new(&frame_bytes).unwrap();

        let result = Icmpv6EchoProtocol.interpret(&frame);

        assert!(matches!(result.unwrap(), ProtocolMatch::Unhandled));
    }

    #[test]
    fn icmpv6_protocol_ignores_traffic_not_addressed_to_a_link_local_unicast() {
        let frame_bytes = echo_reply_frame(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)); // multicast
        let frame = EthernetPacket::new(&frame_bytes).unwrap();

        let result = Icmpv6EchoProtocol.interpret(&frame);

        assert!(matches!(result.unwrap(), ProtocolMatch::Unhandled));
    }

    /// An echo reply aimed at this host answers the all-nodes echo request, and
    /// every neighbour may answer the same one - so the match must not imply
    /// that any single probe has been used up.
    #[test]
    fn icmpv6_protocol_claims_an_echo_reply_for_the_all_nodes_probe() {
        let frame_bytes = echo_reply_frame(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let frame = EthernetPacket::new(&frame_bytes).unwrap();

        for _ in 0..2 {
            let result = Icmpv6EchoProtocol.interpret(&frame).unwrap();
            assert!(matches!(result, ProtocolMatch::AllNodes));
        }
        assert_eq!(
            Icmpv6EchoProtocol.status_protocol(),
            StatusProtocol::IcmpEcho
        );
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
            let frame = EthernetPacket::new(&frame_bytes).unwrap();
            assert!(matches!(
                Icmpv6EchoProtocol.interpret(&frame).unwrap(),
                ProtocolMatch::Unhandled
            ));
        }
    }
}
