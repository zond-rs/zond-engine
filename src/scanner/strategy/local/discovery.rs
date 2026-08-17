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

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};

use crate::model::host::StatusProtocol;
use crate::protocols::{ip, ndp};

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

        Ok(ProtocolMatch::Solicited(None))
    }

    fn status_protocol(&self) -> StatusProtocol {
        StatusProtocol::Arp
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
    fn interpret(&self, frame: &EthernetPacket) -> anyhow::Result<ProtocolMatch> {
        match ndp::advertised_target(frame) {
            Some(target) => Ok(ProtocolMatch::Solicited(Some(IpAddr::V6(target)))),
            None => Ok(ProtocolMatch::Unhandled),
        }
    }

    fn status_protocol(&self) -> StatusProtocol {
        StatusProtocol::Ndp
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

        match ip::icmpv6_echo_token_from_eth(frame) {
            Some((identifier, sequence)) => Ok(ProtocolMatch::AllNodes {
                identifier,
                sequence,
            }),
            None => Ok(ProtocolMatch::Unhandled),
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
    use pnet::packet::icmpv6::echo_reply::{Icmpv6Codes, MutableEchoReplyPacket};
    use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
    use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
    use std::net::{Ipv4Addr, Ipv6Addr};

    const LOCAL_MAC: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
    const PEER_MAC: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x02);
    const ICMPV6_ECHO_LEN: usize = 8;

    fn arp_reply_frame(sender_ip: Ipv4Addr) -> Vec<u8> {
        arp::create_packet(&PEER_MAC, LOCAL_MAC, &sender_ip, Ipv4Addr::new(10, 0, 0, 1))
    }

    /// An Ethernet-framed IPv6 packet to `destination`, carrying `body` as
    /// `protocol`.
    fn ipv6_frame(destination: Ipv6Addr, protocol: IpNextHeaderProtocol, body: &[u8]) -> Vec<u8> {
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let eth_header = ethernet::make_header(
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
    fn echo_reply_frame_with(destination: Ipv6Addr, identifier: u16, sequence: u16) -> Vec<u8> {
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

    fn echo_reply_frame(destination: Ipv6Addr) -> Vec<u8> {
        echo_reply_frame_with(destination, 0, 0)
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

        assert!(matches!(result, ProtocolMatch::Solicited(None)));
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
            assert!(matches!(result, ProtocolMatch::AllNodes { .. }));
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
        let frame = EthernetPacket::new(&frame_bytes).unwrap();

        let result = Icmpv6EchoProtocol.interpret(&frame).unwrap();

        assert!(matches!(
            result,
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
            let frame = EthernetPacket::new(&frame_bytes).unwrap();
            assert!(matches!(
                Icmpv6EchoProtocol.interpret(&frame).unwrap(),
                ProtocolMatch::Unhandled
            ));
        }
    }
}
