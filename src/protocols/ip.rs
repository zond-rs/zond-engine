// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::protocols::utils::{IP_V4_HDR_LEN, IP_V6_HDR_LEN, UDP_HDR_LEN};
use anyhow::Context;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmpv6::echo_reply::EchoReplyPacket;
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Type, Icmpv6Types};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};

const WORD_LEN: usize = 4;
/// The "Don't Fragment" bit, expressed in the 3-bit flags field that
/// `MutableIpv4Packet::set_flags` writes. Our probes are single, minimal
/// packets that should never be fragmented in transit.
const DONT_FRAGMENT: u8 = 0b010;

/// Builds a 20-byte IPv4 header (no options) for a packet carrying
/// `payload_length` bytes of `next_protocol` from `src_addr` to `dst_addr`.
///
/// The header checksum is computed over the finished header. The kernel is
/// not in this path - these headers are emitted straight onto the wire via a
/// Layer-2 send - so every field, including the checksum, has to be correct
/// here or the receiver drops the packet.
pub fn create_ipv4_header(
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    payload_length: u16,
    next_protocol: IpNextHeaderProtocol,
) -> anyhow::Result<Vec<u8>> {
    let mut buffer: [u8; IP_V4_HDR_LEN] = [0; IP_V4_HDR_LEN];
    {
        let mut ipv4: MutableIpv4Packet =
            MutableIpv4Packet::new(&mut buffer[..]).context("creating ipv4 packet")?;
        ipv4.set_version(4);
        ipv4.set_header_length((IP_V4_HDR_LEN / WORD_LEN) as u8);
        ipv4.set_dscp(0);
        ipv4.set_ecn(0);
        ipv4.set_total_length(IP_V4_HDR_LEN as u16 + payload_length);
        ipv4.set_identification(rand::random());
        ipv4.set_flags(DONT_FRAGMENT);
        ipv4.set_fragment_offset(0);
        ipv4.set_ttl(64);
        ipv4.set_next_level_protocol(next_protocol);
        ipv4.set_source(src_addr);
        ipv4.set_destination(dst_addr);
        let csm = checksum(&ipv4.to_immutable());
        ipv4.set_checksum(csm);
    }

    Ok(buffer.to_vec())
}

/// How far a packet meant for this segment may travel.
///
/// One hop, so a router discards it rather than forwarding it. Link-local
/// traffic is required to carry this (RFC 4291 §2.5.6), and for the multicast
/// probes local discovery sends it is also what keeps a sweep of one segment
/// from leaking onto the next.
pub const HOP_LIMIT_ON_LINK: u8 = 1;

/// How far a neighbor discovery message may travel: not at all, verifiably.
///
/// RFC 4861 §7.1.1 requires a receiver to **discard** any neighbor discovery
/// message that did not arrive with a hop limit of 255. Since a router
/// decrements the field, arriving at the maximum is proof the message was never
/// forwarded — which is what stops an off-link attacker from injecting neighbour
/// entries. It is the one on-link case where [`HOP_LIMIT_ON_LINK`] is wrong, and
/// wrong invisibly: every conformant neighbour ignores the probe, and a segment
/// full of them is indistinguishable from an empty one.
pub const HOP_LIMIT_NDP: u8 = 255;

/// How far a packet meant for somewhere else may travel.
///
/// The conventional default, and enough for any path on the public internet:
/// the longest routes in practice are well under half of it. What matters is
/// only that it is not [`HOP_LIMIT_ON_LINK`] — a routed probe sent with a hop
/// limit of one is discarded by the first router, which looks from here exactly
/// like a host that did not answer.
pub const HOP_LIMIT_ROUTED: u8 = 64;

/// Builds a 40-byte IPv6 header for a packet carrying `payload_length` bytes of
/// `next_protocol` from `src_addr` to `dst_addr`.
///
/// `hop_limit` is a parameter rather than a constant because the two callers
/// need opposite values and neither can be inferred from the addresses: local
/// discovery's multicast probes must not leave the segment, while a routed probe
/// must survive every router between here and its target. Getting it wrong is
/// silent in one direction — an on-link probe with a large hop limit still
/// works — and total in the other.
pub fn create_ipv6_header(
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
    payload_length: u16,
    next_protocol: IpNextHeaderProtocol,
    hop_limit: u8,
) -> anyhow::Result<Vec<u8>> {
    let mut buffer: [u8; IP_V6_HDR_LEN] = [0; IP_V6_HDR_LEN];
    {
        let mut ipv6: MutableIpv6Packet =
            MutableIpv6Packet::new(&mut buffer[..]).context("creating ipv6 packet")?;
        ipv6.set_version(6);
        ipv6.set_traffic_class(0);
        ipv6.set_flow_label(rand::random());
        ipv6.set_payload_length(payload_length);
        ipv6.set_next_header(next_protocol);
        ipv6.set_hop_limit(hop_limit);
        ipv6.set_source(src_addr);
        ipv6.set_destination(dst_addr);
    }
    Ok(buffer.to_vec())
}

pub fn get_ipv6_src_addr_from_eth(frame: &EthernetPacket) -> anyhow::Result<Ipv6Addr> {
    let ipv6_packet: Ipv6Packet = Ipv6Packet::new(frame.payload()).context(format!(
        "truncated or invalid ipv6 packet (payload len {})",
        frame.payload().len()
    ))?;
    Ok(ipv6_packet.get_source())
}

pub fn get_ipv6_dst_addr_from_eth(frame: &EthernetPacket) -> anyhow::Result<Ipv6Addr> {
    let ipv6_packet: Ipv6Packet = Ipv6Packet::new(frame.payload()).context(format!(
        "truncated or invalid ipv6 packet (payload len {})",
        frame.payload().len()
    ))?;
    Ok(ipv6_packet.get_destination())
}

/// The ICMPv6 message type an Ethernet-framed IPv6 packet carries, or `None` if
/// it is not ICMPv6 or is too short to say.
///
/// Reads the fixed header's next-header field rather than walking the extension
/// chain, so a packet carrying one is reported as not-ICMPv6. That is the safe
/// direction to be wrong in for a discovery check - it declines to credit a
/// frame it cannot read rather than guessing at its type - and the probes this
/// interprets replies to elicit no extension headers.
pub fn icmpv6_type_from_eth(frame: &EthernetPacket) -> Option<Icmpv6Type> {
    let packet = Ipv6Packet::new(frame.payload())?;
    if packet.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
        return None;
    }

    Some(Icmpv6Packet::new(packet.payload())?.get_icmpv6_type())
}

/// The identifier and sequence number an Ethernet-framed ICMPv6 echo reply
/// carries back, or `None` if the frame is not one or is too short to say.
///
/// RFC 4443 requires a reply to echo both fields from the request unchanged,
/// which is what lets a scanner recognize the answer to a particular probe of
/// its own. Without them an echo reply proves only that its sender exists;
/// with them it also says when the question was asked.
pub fn icmpv6_echo_token_from_eth(frame: &EthernetPacket) -> Option<(u16, u16)> {
    let packet = Ipv6Packet::new(frame.payload())?;
    if packet.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
        return None;
    }

    let reply = EchoReplyPacket::new(packet.payload())?;
    if reply.get_icmpv6_type() != Icmpv6Types::EchoReply {
        return None;
    }

    Some((reply.get_identifier(), reply.get_sequence_number()))
}

/// The payload of a UDP datagram carried in `frame` and sent from `port`, over
/// either address family, or `None` if the frame is not that.
///
/// Reads the fixed IPv6 header's next-header field rather than walking the
/// extension chain, and the IPv4 header's protocol field without reassembling
/// fragments — both the same conservative direction as
/// [`icmpv6_type_from_eth`]: a frame that cannot be read plainly is declined
/// rather than guessed at.
pub fn udp_payload_from_eth<'a>(frame: &'a EthernetPacket<'a>, port: u16) -> Option<&'a [u8]> {
    let packet = frame.payload();

    // Offsets rather than `packet.payload()`, because a pnet view owns the
    // slice it hands back and the caller needs one borrowed from the frame.
    let (header_len, next) = match frame.get_ethertype() {
        EtherTypes::Ipv6 => (IP_V6_HDR_LEN, Ipv6Packet::new(packet)?.get_next_header()),
        EtherTypes::Ipv4 => {
            let ipv4 = Ipv4Packet::new(packet)?;
            (
                ipv4.get_header_length() as usize * WORD_LEN,
                ipv4.get_next_level_protocol(),
            )
        }
        _ => return None,
    };
    if next != IpNextHeaderProtocols::Udp {
        return None;
    }

    let datagram = packet.get(header_len..)?;
    let source = u16::from_be_bytes([*datagram.first()?, *datagram.get(1)?]);
    if source != port {
        return None;
    }

    datagram.get(UDP_HDR_LEN..)
}

pub fn get_ipv4_addr_from_eth(frame: &EthernetPacket) -> anyhow::Result<Ipv4Addr> {
    let ipv4_packet: Ipv4Packet = Ipv4Packet::new(frame.payload()).context(format!(
        "truncated or invalid ipv4 packet (payload len {})",
        frame.payload().len()
    ))?;
    Ok(ipv4_packet.get_source())
}
