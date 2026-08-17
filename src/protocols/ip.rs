// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # IP headers, and reading what a frame carries
//!
//! The network layer: the two headers this engine writes, the hop limits it
//! writes into them, and the readers that pull an address or a payload back out
//! of a captured frame.
//!
//! ## The kernel is not in this path
//!
//! These headers go straight onto the wire over a link-layer send, so every
//! field has to be right here. Nothing downstream fills in a length, corrects a
//! checksum or picks a fragmentation flag, and a receiver silently drops what
//! it cannot parse. That is why the builders compute their own checksums and
//! why a length that will not fit its field is refused rather than truncated.
//!
//! ## The readers decline rather than guess
//!
//! Everything that reads a captured frame here stops at the fixed header: an
//! IPv6 packet carrying extension headers is reported as not-ICMPv6 rather than
//! walked, and a fragmented IPv4 packet is not reassembled. That is the safe
//! direction for discovery, which would rather miss a frame than credit a host
//! on a reading it is not sure of, and none of the probes this engine sends
//! elicit either shape.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::protocols::craft;
use crate::protocols::error::{PacketError, Result};
use crate::protocols::sizes::{IP_V4_HDR_LEN, IP_V6_HDR_LEN, UDP_HDR_LEN};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmpv6::echo_reply::EchoReplyPacket;
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Type, Icmpv6Types};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;

const WORD_LEN: usize = 4;

/// Builds a 20-byte IPv4 header (no options) for a packet carrying
/// `payload_length` bytes of `next_protocol` from `src_addr` to `dst_addr`.
///
/// The header checksum is computed over the finished header, because nothing
/// downstream will do it; see the module documentation.
///
/// # Errors
///
/// [`PacketError::TooLong`] when the payload and the header together exceed
/// what the 16-bit total-length field can describe, which is 65 515 bytes of
/// payload. Refused rather than truncated: a wrapped value describes a packet
/// shorter than its own header, and every receiver drops it.
pub fn create_ipv4_header(
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    payload_length: u16,
    next_protocol: IpNextHeaderProtocol,
) -> Result<Vec<u8>> {
    craft::Ipv4 {
        protocol: craft::Field::Exact(next_protocol),
        ..craft::Ipv4::new(src_addr, dst_addr)
    }
    .header_bytes(payload_length)
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
///
/// Infallible, unlike its IPv4 counterpart: the payload length is its own
/// field here rather than a total that has to include the header, so every
/// `u16` a caller can pass is one the field can hold.
pub fn create_ipv6_header(
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
    payload_length: u16,
    next_protocol: IpNextHeaderProtocol,
    hop_limit: u8,
) -> Vec<u8> {
    craft::Ipv6 {
        next_header: craft::Field::Exact(next_protocol),
        ..craft::Ipv6::new(src_addr, dst_addr).with_hop_limit(hop_limit)
    }
    .header_bytes(payload_length)
}

/// The address an Ethernet-framed IPv6 packet was sent from.
///
/// # Errors
///
/// [`PacketError::Truncated`] when the frame carries too few bytes for a
/// header.
pub fn ipv6_source(frame: &EthernetPacket) -> Result<Ipv6Addr> {
    Ok(ipv6_packet(frame)?.get_source())
}

/// The address an Ethernet-framed IPv6 packet was sent to.
///
/// # Errors
///
/// [`PacketError::Truncated`] when the frame carries too few bytes for a
/// header.
pub fn ipv6_destination(frame: &EthernetPacket) -> Result<Ipv6Addr> {
    Ok(ipv6_packet(frame)?.get_destination())
}

/// The IPv6 packet inside `frame`, or why it could not be read.
fn ipv6_packet<'a>(frame: &'a EthernetPacket<'a>) -> Result<Ipv6Packet<'a>> {
    Ipv6Packet::new(frame.payload()).ok_or_else(|| {
        PacketError::truncated("an IPv6 packet", IP_V6_HDR_LEN, frame.payload().len())
    })
}

/// The ICMPv6 message type an Ethernet-framed IPv6 packet carries, or `None` if
/// it is not ICMPv6 or is too short to say.
///
/// Reads the fixed header's next-header field rather than walking the extension
/// chain, so a packet carrying one is reported as not-ICMPv6. That is the safe
/// direction to be wrong in for a discovery check - it declines to credit a
/// frame it cannot read rather than guessing at its type - and the probes this
/// interprets replies to elicit no extension headers.
pub fn icmpv6_type(frame: &EthernetPacket) -> Option<Icmpv6Type> {
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
pub fn icmpv6_echo_token(frame: &EthernetPacket) -> Option<(u16, u16)> {
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
/// [`icmpv6_type`]: a frame that cannot be read plainly is declined
/// rather than guessed at.
pub fn udp_payload<'a>(frame: &'a EthernetPacket<'a>, port: u16) -> Option<&'a [u8]> {
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

/// The address an Ethernet-framed IPv4 packet was sent from.
///
/// # Errors
///
/// [`PacketError::Truncated`] when the frame carries too few bytes for a
/// header.
pub fn ipv4_source(frame: &EthernetPacket) -> Result<Ipv4Addr> {
    let ipv4_packet = Ipv4Packet::new(frame.payload()).ok_or_else(|| {
        PacketError::truncated("an IPv4 packet", IP_V4_HDR_LEN, frame.payload().len())
    })?;
    Ok(ipv4_packet.get_source())
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
    use pnet::packet::ip::IpNextHeaderProtocols;

    const V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    /// The largest payload the total-length field can describe, and the first
    /// one it cannot.
    ///
    /// The field counts the header as well, so it runs out twenty bytes before
    /// the payload does. Past that the addition used to wrap: in release a
    /// payload of 65 516 produced a header claiming a total length of zero, and
    /// 65 535 one claiming nineteen, which is shorter than the header itself.
    /// A receiver drops both, and the scan reads that as a firewall.
    ///
    /// In debug the same addition panicked instead, so the two build profiles
    /// disagreed about whether this was a crash or a wrong answer.
    #[test]
    fn a_payload_too_large_for_the_length_field_is_refused_rather_than_wrapped() {
        let largest = u16::MAX as usize - IP_V4_HDR_LEN;

        let header = create_ipv4_header(V4, V4, largest as u16, IpNextHeaderProtocols::Tcp)
            .expect("the largest describable payload");
        assert_eq!(
            Ipv4Packet::new(&header).expect("parses").get_total_length(),
            u16::MAX
        );

        for oversize in [largest + 1, u16::MAX as usize] {
            let refused = create_ipv4_header(V4, V4, oversize as u16, IpNextHeaderProtocols::Tcp);
            assert!(
                matches!(refused, Err(PacketError::TooLong { .. })),
                "a payload of {oversize} produced {refused:?}"
            );
        }
    }
}
