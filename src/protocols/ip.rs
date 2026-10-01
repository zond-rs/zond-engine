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
//! writes into them, and the readers that pull an address or a payload out of a
//! captured frame.
//!
//! These headers go straight onto the wire over a link-layer send, so nothing
//! downstream fills in a length, fixes a checksum or picks a fragmentation flag,
//! and a receiver silently drops what it cannot parse. The builders compute
//! their own checksums and refuse a length that will not fit its field.
//!
//! The readers stop at the fixed header: an IPv6 packet carrying extension
//! headers is reported as not-ICMPv6, and a fragmented IPv4 packet is not
//! reassembled. Discovery would rather miss a frame than credit a host on an
//! uncertain reading, and none of the engine's probes elicit either shape.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::protocols::craft;
use crate::protocols::error::{PacketError, Result};
use crate::protocols::ethernet::Frame;
use crate::protocols::sizes::{IP_V4_HDR_LEN, IP_V6_HDR_LEN, UDP_HDR_LEN};
use pnet_packet::Packet;
use pnet_packet::ethernet::{EtherType, EtherTypes};
use pnet_packet::icmpv6::echo_reply::EchoReplyPacket;
use pnet_packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::{Ipv6Packet, MutableFragmentPacket};

const WORD_LEN: usize = 4;

/// The eight-byte unit an IPv4 fragment offset counts in (RFC 791 §3.1), so a
/// fragment that is not the last must carry a whole number of these.
const FRAGMENT_UNIT: usize = 8;

/// The IPv6 fragment extension header (RFC 8200 §4.5): a next-header byte, a
/// reserved byte, the offset-and-flags halfword, and a 32-bit identification.
const FRAGMENT_HEADER_LEN: usize = 8;

/// The smallest MTU [`fragment_ipv4`] will split a datagram to: a header and one
/// whole eight-byte unit.
///
/// Public so a caller choosing a fragment size, such as
/// [`EvasionProfile::validate`], checks against the same bound before a scan
/// runs.
///
/// [`EvasionProfile::validate`]: crate::evasion::EvasionProfile::validate
pub const SMALLEST_FRAGMENT_MTU: u16 = (IP_V4_HDR_LEN + FRAGMENT_UNIT) as u16;

/// The smallest MTU [`fragment_ipv6`] will split a datagram to: the base header,
/// the fragment extension header, and one whole eight-byte unit.
///
/// Larger than [`SMALLEST_FRAGMENT_MTU`] by the extension header and the wider
/// base header.
pub const SMALLEST_FRAGMENT_MTU_V6: u16 =
    (IP_V6_HDR_LEN + FRAGMENT_HEADER_LEN + FRAGMENT_UNIT) as u16;

/// Builds a 20-byte IPv4 header (no options) for a packet carrying
/// `payload_length` bytes of `next_protocol` from `src_addr` to `dst_addr`.
///
/// The header checksum is computed here; see the module documentation.
///
/// `ttl` is a parameter because a probe sent to expire on purpose is how a path
/// is measured. [`HOP_LIMIT_ROUTED`] is what an ordinary probe passes;
/// [`traceroute`](crate::scanner::strategy::topology::traceroute) passes each
/// value in turn and reads the errors that come back.
///
/// # Errors
///
/// [`PacketError::TooLong`] when the payload and header together exceed the
/// 16-bit total-length field, i.e. more than 65 515 bytes of payload. A wrapped
/// value would describe a packet shorter than its own header, which every
/// receiver drops.
pub fn build_ipv4_header(
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    payload_length: u16,
    next_protocol: u8,
    ttl: u8,
) -> Result<Vec<u8>> {
    craft::Ipv4 {
        protocol: craft::Field::Exact(next_protocol),
        ..craft::Ipv4::new(src_addr, dst_addr).with_ttl(ttl)
    }
    .header_bytes(payload_length)
}

/// Splits an IPv4 datagram into fragments that each fit within `mtu` bytes.
///
/// `header` is the IPv4 header the caller would otherwise send whole, and
/// `payload` the finished Layer-4 segment, checksummed over the whole. The
/// segment is split as opaque bytes and never re-checksummed: only the first
/// fragment carries the Layer-4 header, and the receiver reassembles the rest.
///
/// Each returned packet is a complete IPv4 packet, header sized and checksummed
/// for its own piece, ready for a link-layer send.
/// [`MORE_FRAGMENTS`](craft::ipv4_flags::MORE_FRAGMENTS) is set on every
/// fragment but the last, [`DONT_FRAGMENT`](craft::ipv4_flags::DONT_FRAGMENT)
/// is cleared on all, and [`fragment_offset`](craft::Ipv4::fragment_offset)
/// counts eight-byte units from the start of the payload.
///
/// Every fragment shares one [`identification`](craft::Ipv4::identification):
/// a caller's [`Field::Exact`](craft::Field::Exact) is kept, a
/// [`Computed`](craft::Field::Computed) one is resolved to a single random
/// value, since a receiver groups fragments by that field.
///
/// A datagram that already fits `mtu` comes back as one packet with the
/// caller's flags untouched, don't-fragment included.
///
/// # Errors
///
/// [`PacketError::HeaderHasOptions`] when `header` carries options: each
/// option's copy-into-every-fragment bit is not honoured, so a split would
/// reassemble wrongly.
///
/// [`PacketError::MtuTooSmall`] when `mtu` cannot hold the header and one
/// eight-byte unit of payload, since smaller fragments would never make
/// progress.
///
/// [`PacketError::TooLong`] when the datagram exceeds the 16-bit total-length
/// field, as in [`build_ipv4_header`]. That also keeps the last fragment's
/// start inside the thirteen-bit offset field.
pub fn fragment_ipv4(header: &craft::Ipv4, payload: &[u8], mtu: u16) -> Result<Vec<Vec<u8>>> {
    if !header.options.is_empty() {
        return Err(PacketError::HeaderHasOptions {
            options: header.options.len(),
        });
    }

    let header_len = IP_V4_HDR_LEN;
    let mtu = mtu as usize;

    // Past 65 535 bytes the reassembled length cannot be described, and below
    // it no fragment can start beyond what the offset field holds.
    if header_len + payload.len() > u16::MAX as usize {
        return Err(PacketError::too_long(
            "the IPv4 total length",
            header_len,
            payload.len(),
        ));
    }

    if header_len + payload.len() <= mtu {
        let mut packet = header.header_bytes(payload.len() as u16)?;
        packet.extend_from_slice(payload);
        return Ok(vec![packet]);
    }

    // Every fragment but the last carries whole eight-byte units, the offset's
    // unit; the last carries the remainder.
    let max_chunk = (mtu.saturating_sub(header_len) / FRAGMENT_UNIT) * FRAGMENT_UNIT;
    if max_chunk == 0 {
        return Err(PacketError::MtuTooSmall {
            mtu,
            minimum: SMALLEST_FRAGMENT_MTU as usize,
        });
    }

    // One identification for the whole datagram, so a receiver can group the
    // pieces.
    let identification = header.identification.exact().unwrap_or_else(rand::random);

    let mut fragments = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let chunk = &payload[offset..(offset + max_chunk).min(payload.len())];
        let more_fragments = offset + chunk.len() < payload.len();

        let piece = craft::Ipv4 {
            identification: craft::Field::Exact(identification),
            flags: if more_fragments {
                craft::ipv4_flags::MORE_FRAGMENTS
            } else {
                0
            },
            fragment_offset: (offset / FRAGMENT_UNIT) as u16,
            // Re-derived per fragment: the length and checksum move with the piece.
            total_length: craft::Field::Computed,
            checksum: craft::Field::Computed,
            ..header.clone()
        };

        let mut packet = piece.header_bytes(chunk.len() as u16)?;
        packet.extend_from_slice(chunk);
        fragments.push(packet);

        offset += chunk.len();
    }

    Ok(fragments)
}

/// Splits an IPv6 datagram into fragments that each fit within `mtu` bytes.
///
/// Like [`fragment_ipv4`], but IPv6 keeps its base header fixed and carries
/// the offset, flag and identification in a fragment extension header (RFC 8200
/// §4.5). Each returned packet is the base header, eight bytes of fragment
/// header, then the piece. Used by
/// [`EvasionProfile::fragment`](crate::evasion::EvasionProfile::fragment) for
/// IPv6 targets.
///
/// `payload` is the finished Layer-4 segment, split as opaque bytes and never
/// re-checksummed: the v6 pseudo-header names the datagram's own length, which
/// reassembly restores.
///
/// Each base header points at the fragment header
/// ([`Ipv6Frag`](IpNextHeaderProtocols::Ipv6Frag)), which carries the
/// upper-layer protocol. A [`Computed`](craft::Field::Computed) next header
/// resolves as [`header_bytes`](craft::Ipv6::header_bytes) would with no inner
/// layer: to TCP, which every fragmenting caller in this crate carries.
///
/// Every fragment shares one 32-bit identification, generated once; unlike
/// IPv4's, a caller cannot set it.
///
/// A datagram that already fits `mtu` comes back as one ordinary IPv6 packet
/// with no fragment header, so an unsplit probe carries no sign of
/// fragmentation.
///
/// # Errors
///
/// [`PacketError::MtuTooSmall`] when `mtu` cannot hold the base header, the
/// fragment header and one eight-byte unit of payload; the floor is
/// [`SMALLEST_FRAGMENT_MTU_V6`].
///
/// [`PacketError::TooLong`] when the payload is beyond what a thirteen-bit
/// offset in eight-byte units can address. Here the offset field is the bound;
/// it allows the same number of payload bytes as IPv4's length field.
pub fn fragment_ipv6(header: &craft::Ipv6, payload: &[u8], mtu: u16) -> Result<Vec<Vec<u8>>> {
    let mtu = mtu as usize;

    // The offset addresses eight-byte units in thirteen bits, so no fragment
    // may begin beyond 65 528 bytes into the payload. A larger payload is
    // refused, not wrapped.
    if payload.len() > u16::MAX as usize {
        return Err(PacketError::too_long(
            "the IPv6 fragmentable payload",
            IP_V6_HDR_LEN + FRAGMENT_HEADER_LEN,
            payload.len(),
        ));
    }

    // Fits: an ordinary IPv6 packet, no fragment header.
    if IP_V6_HDR_LEN + payload.len() <= mtu {
        let mut packet = header.header_bytes(payload.len() as u16);
        packet.extend_from_slice(payload);
        return Ok(vec![packet]);
    }

    // Every fragment but the last carries whole eight-byte units, plus the
    // fragment header on top of the base one.
    let overhead = IP_V6_HDR_LEN + FRAGMENT_HEADER_LEN;
    let max_chunk = (mtu.saturating_sub(overhead) / FRAGMENT_UNIT) * FRAGMENT_UNIT;
    if max_chunk == 0 {
        return Err(PacketError::MtuTooSmall {
            mtu,
            minimum: SMALLEST_FRAGMENT_MTU_V6 as usize,
        });
    }

    // The upper-layer protocol moves into the fragment header; the base header
    // points at the fragment header.
    let upper = header
        .next_header
        .exact()
        .unwrap_or(IpNextHeaderProtocols::Tcp.0);

    // One identification for the whole datagram, thirty-two bits in IPv6.
    let identification: u32 = rand::random();

    // The base header each fragment repeats, with a payload length re-derived
    // per piece.
    let base = craft::Ipv6 {
        next_header: craft::Field::Exact(IpNextHeaderProtocols::Ipv6Frag.0),
        payload_length: craft::Field::Computed,
        ..header.clone()
    };

    let mut fragments = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let chunk = &payload[offset..(offset + max_chunk).min(payload.len())];
        let more_fragments = offset + chunk.len() < payload.len();

        let mut packet = base.header_bytes((FRAGMENT_HEADER_LEN + chunk.len()) as u16);

        let mut extension = [0u8; FRAGMENT_HEADER_LEN];
        {
            let mut fragment = MutableFragmentPacket::new(&mut extension)
                .expect("an eight-byte buffer holds a fragment header");
            fragment.set_next_header(IpNextHeaderProtocol(upper));
            fragment.set_reserved(0);
            // Offset in the top thirteen bits, More Fragments in bit zero, the two
            // reserved bits clear. Written as one field because pnet's
            // `set_fragment_offset` masks on a two-bit boundary and would need a
            // pre-shifted value.
            let units = (offset / FRAGMENT_UNIT) as u16;
            fragment.set_fragment_offset_with_flags((units << 3) | u16::from(more_fragments));
            fragment.set_id(identification);
        }
        packet.extend_from_slice(&extension);
        packet.extend_from_slice(chunk);
        fragments.push(packet);

        offset += chunk.len();
    }

    Ok(fragments)
}

/// How far a packet meant for this segment may travel.
///
/// One hop, so a router discards it. Link-local traffic must carry this (RFC
/// 4291 §2.5.6), and it keeps local discovery's multicast probes on the
/// segment.
pub const HOP_LIMIT_ON_LINK: u8 = 1;

/// How far a neighbor discovery message may travel: not at all, verifiably.
///
/// RFC 4861 §7.1.1 requires a receiver to **discard** any neighbor discovery
/// message that did not arrive with a hop limit of 255. A router decrements the
/// field, so 255 proves the message was not forwarded. [`HOP_LIMIT_ON_LINK`] is
/// silently wrong here: every conformant neighbour would ignore the probe.
pub const HOP_LIMIT_NDP: u8 = 255;

/// How far a packet meant for somewhere else may travel.
///
/// The conventional default; the longest routes in practice are well under
/// half of it. A routed probe with [`HOP_LIMIT_ON_LINK`] would be discarded by
/// the first router and look like a host that did not answer.
pub const HOP_LIMIT_ROUTED: u8 = 64;

/// Builds a 40-byte IPv6 header for a packet carrying `payload_length` bytes of
/// `next_protocol` from `src_addr` to `dst_addr`.
///
/// `hop_limit` is a parameter because local discovery's multicast probes must
/// not leave the segment while a routed probe must survive every router, and
/// the addresses do not say which applies.
///
/// Infallible: the payload length is its own field and does not include the
/// header, so every `u16` fits.
pub fn build_ipv6_header(
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
    payload_length: u16,
    next_protocol: u8,
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
pub fn ipv6_source(frame: &Frame<'_>) -> Result<Ipv6Addr> {
    Ok(ipv6_packet(frame)?.get_source())
}

/// The address an Ethernet-framed IPv6 packet was sent to.
///
/// # Errors
///
/// [`PacketError::Truncated`] when the frame carries too few bytes for a
/// header.
pub fn ipv6_destination(frame: &Frame<'_>) -> Result<Ipv6Addr> {
    Ok(ipv6_packet(frame)?.get_destination())
}

/// The IPv6 packet inside `frame`, or why it could not be read.
fn ipv6_packet<'a>(frame: &Frame<'a>) -> Result<Ipv6Packet<'a>> {
    Ipv6Packet::new(frame.payload()).ok_or_else(|| {
        PacketError::truncated("an IPv6 packet", IP_V6_HDR_LEN, frame.payload().len())
    })
}

/// The IPv6 packet inside `frame`, when the frame carries one and the packet
/// carries `protocol`.
///
/// The walk every ICMPv6 reader here starts with. The EtherType is checked
/// first: a reader starting at the payload without asking would find an IPv6
/// header in the middle of an ARP one.
///
/// Reads the fixed header's next-header field without walking the extension
/// chain, so a packet carrying extension headers is reported as not carrying
/// `protocol`. The probes whose replies this reads elicit none.
pub(crate) fn ipv6_carrying<'a>(
    frame: &Frame<'a>,
    protocol: IpNextHeaderProtocol,
) -> Option<Ipv6Packet<'a>> {
    if frame.ethertype() != EtherTypes::Ipv6.0 {
        return None;
    }

    let packet = Ipv6Packet::new(frame.payload())?;
    (packet.get_next_header() == protocol).then_some(packet)
}

/// `packet`, a bare IPv6 packet, when it carries `protocol`.
///
/// [`ipv6_carrying`] for a link with no Ethernet header, such as a tunnel or
/// PPP. With no EtherType, the version nibble is checked instead. The extension
/// chain is not walked.
pub(crate) fn ipv6_carrying_in(
    packet: &[u8],
    protocol: IpNextHeaderProtocol,
) -> Option<Ipv6Packet<'_>> {
    if packet.first()? >> 4 != 6 {
        return None;
    }
    let packet = Ipv6Packet::new(packet)?;
    (packet.get_next_header() == protocol).then_some(packet)
}

/// The ICMPv6 message type an Ethernet-framed IPv6 packet carries, by number, or
/// `None` if the frame is not that or is too short to say.
///
/// The EtherType is checked first. The extension chain is not walked, so a
/// packet carrying extension headers is reported as not ICMPv6.
pub fn icmpv6_type(frame: &Frame<'_>) -> Option<u8> {
    let packet = ipv6_carrying(frame, IpNextHeaderProtocols::Icmpv6)?;
    Some(Icmpv6Packet::new(packet.payload())?.get_icmpv6_type().0)
}

/// The identifier and sequence number an Ethernet-framed ICMPv6 echo reply
/// carries back, or `None` if the frame is not one or is too short to say.
///
/// RFC 4443 requires a reply to echo both fields unchanged, which lets a
/// scanner match the answer to its own probe and time it.
pub fn icmpv6_echo_token(frame: &Frame<'_>) -> Option<(u16, u16)> {
    echo_token(&ipv6_carrying(frame, IpNextHeaderProtocols::Icmpv6)?)
}

/// The same, for `packet`, a bare IPv6 packet off a link with no Ethernet
/// header.
pub(crate) fn icmpv6_echo_token_in(packet: &[u8]) -> Option<(u16, u16)> {
    echo_token(&ipv6_carrying_in(packet, IpNextHeaderProtocols::Icmpv6)?)
}

/// The identifier and sequence number `packet` carries back, where its ICMPv6
/// message is an echo reply.
fn echo_token(packet: &Ipv6Packet<'_>) -> Option<(u16, u16)> {
    let reply = EchoReplyPacket::new(packet.payload())?;
    if reply.get_icmpv6_type() != Icmpv6Types::EchoReply {
        return None;
    }

    Some((reply.get_identifier(), reply.get_sequence_number()))
}

/// The payload of a UDP datagram carried in `frame` and sent from `port`, over
/// either address family, or `None` if the frame is not that.
///
/// Reads the fixed IPv6 header's next-header field without walking the
/// extension chain, and an IPv4 packet only where it is the whole datagram.
///
/// Fragments are declined: only the first piece carries a UDP header, so a
/// later one still marked UDP has payload bytes where the ports should be.
///
/// A header length below the five words a header occupies is declined too,
/// since it would put the datagram's start inside the header.
pub fn udp_payload<'a>(frame: &Frame<'a>, port: u16) -> Option<&'a [u8]> {
    let packet = frame.payload();

    // Offsets, because a pnet view owns the slice it hands back and the caller
    // needs one borrowed from the frame.
    let (header_len, next) = match EtherType(frame.ethertype()) {
        EtherTypes::Ipv6 => (IP_V6_HDR_LEN, Ipv6Packet::new(packet)?.get_next_header()),
        EtherTypes::Ipv4 => {
            let ipv4 = Ipv4Packet::new(packet)?;
            if !carries_a_whole_datagram(&ipv4) {
                return None;
            }
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

/// Whether an IPv4 packet holds a whole Layer-4 datagram at a readable offset.
///
/// A packet with a non-zero fragment offset is the middle of a datagram and
/// carries no Layer-4 header. One with more-fragments set is the start of an
/// incomplete datagram and is readable at its own header, so only the first is
/// refused.
///
/// A header length below five words cannot be true, and `pnet` does not check
/// it.
fn carries_a_whole_datagram(packet: &Ipv4Packet<'_>) -> bool {
    packet.get_header_length() >= (IP_V4_HDR_LEN / WORD_LEN) as u8
        && packet.get_fragment_offset() == 0
}

/// The address an Ethernet-framed IPv4 packet was sent from.
///
/// # Errors
///
/// [`PacketError::Truncated`] when the frame carries too few bytes for a
/// header.
pub fn ipv4_source(frame: &Frame<'_>) -> Result<Ipv4Addr> {
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
    use pnet_packet::ip::IpNextHeaderProtocols;
    use proptest::prelude::*;

    const V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

    /// The largest payload the total-length field can describe, and the first
    /// it cannot.
    ///
    /// The field counts the header too, so it runs out twenty bytes before the
    /// payload does. An unchecked addition would wrap in release (65 516 giving a
    /// total length of zero, 65 535 giving nineteen) and panic in debug.
    #[test]
    fn a_payload_too_large_for_the_length_field_is_refused_rather_than_wrapped() {
        let largest = u16::MAX as usize - IP_V4_HDR_LEN;

        let header = build_ipv4_header(
            V4,
            V4,
            largest as u16,
            IpNextHeaderProtocols::Tcp.0,
            HOP_LIMIT_ROUTED,
        )
        .expect("the largest describable payload");
        assert_eq!(
            Ipv4Packet::new(&header).expect("parses").get_total_length(),
            u16::MAX
        );

        for oversize in [largest + 1, u16::MAX as usize] {
            let refused = build_ipv4_header(
                V4,
                V4,
                oversize as u16,
                IpNextHeaderProtocols::Tcp.0,
                HOP_LIMIT_ROUTED,
            );
            assert!(
                matches!(refused, Err(PacketError::TooLong { .. })),
                "a payload of {oversize} produced {refused:?}"
            );
        }
    }

    /// Reads bytes known to be a frame, as every one below is built by
    /// `frame_of`.
    fn read(bytes: &[u8]) -> Frame<'_> {
        crate::protocols::ethernet::parse(bytes).expect("a frame")
    }

    /// An Ethernet frame carrying `payload` under `ethertype`.
    fn frame_of(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 12];
        bytes.extend_from_slice(&ethertype.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    /// An IPv4 packet with the header fields a reader looks at, and `body`
    /// behind it. `ihl` and `fragment_offset` decide where the body starts.
    fn ipv4_packet(ihl: u8, fragment_offset: u16, protocol: u8, body: &[u8]) -> Vec<u8> {
        let mut ip = vec![0u8; IP_V4_HDR_LEN];
        ip[0] = (4 << 4) | ihl;
        ip[2..4].copy_from_slice(&((IP_V4_HDR_LEN + body.len()) as u16).to_be_bytes());
        ip[6..8].copy_from_slice(&fragment_offset.to_be_bytes());
        ip[9] = protocol;
        ip.extend_from_slice(body);
        ip
    }

    /// A UDP datagram from `source_port` carrying `payload`.
    fn udp_datagram(source_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut udp = vec![0u8; UDP_HDR_LEN];
        udp[0..2].copy_from_slice(&source_port.to_be_bytes());
        udp[4..6].copy_from_slice(&((UDP_HDR_LEN + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(payload);
        udp
    }

    /// The ordinary case.
    #[test]
    fn a_whole_datagram_from_the_right_port_yields_its_payload() {
        let bytes = frame_of(
            EtherTypes::Ipv4.0,
            &ipv4_packet(5, 0, 17, &udp_datagram(5353, b"the payload")),
        );
        let frame = read(&bytes);

        assert_eq!(udp_payload(&frame, 5353), Some(&b"the payload"[..]));
        assert_eq!(udp_payload(&frame, 53), None, "another port's datagram");
    }

    /// Only the first piece of a fragmented datagram carries a UDP header. A
    /// later one still says protocol 17 and would hand the middle of somebody's
    /// payload to `mdns::extract_hosts` via `local.rs`.
    #[test]
    fn a_fragment_carries_no_datagram_and_is_declined() {
        let body = udp_datagram(5353, b"the payload");

        let first = frame_of(EtherTypes::Ipv4.0, &ipv4_packet(5, 0, 17, &body));
        assert!(
            udp_payload(&read(&first), 5353).is_some(),
            "the first fragment does carry a header"
        );

        for offset in [1, 2, 0x1FFF] {
            let later = frame_of(EtherTypes::Ipv4.0, &ipv4_packet(5, offset, 17, &body));
            assert_eq!(
                udp_payload(&read(&later), 5353),
                None,
                "a fragment at offset {} was read as a datagram",
                offset * 8
            );
        }
    }

    /// A header length under five words cannot be honoured: with an IHL of zero
    /// the "source port" would be the version nibble and the type of service.
    #[test]
    fn a_header_length_below_the_minimum_is_declined() {
        // The first two bytes must read as the source port being looked for, or
        // the port check stops the walk first. Version 0, IHL 0 and a TOS of 0x35
        // spell port 53.
        let mut packet = ipv4_packet(0, 0, 17, b"not a datagram at all");
        packet[0] = 0x00;
        packet[1] = 0x35;
        assert_eq!(
            u16::from_be_bytes([packet[0], packet[1]]),
            53,
            "the probe does not reach the header-length check it is about"
        );

        let bytes = frame_of(EtherTypes::Ipv4.0, &packet);
        assert_eq!(udp_payload(&read(&bytes), 53), None);

        // Five words is the floor and is legal.
        let honest = frame_of(
            EtherTypes::Ipv4.0,
            &ipv4_packet(5, 0, 17, &udp_datagram(53, b"a datagram")),
        );
        assert_eq!(udp_payload(&read(&honest), 53), Some(&b"a datagram"[..]));
    }

    /// A frame under another EtherType is not an IPv6 packet however its bytes
    /// read. `icmpv6_type` and `icmpv6_echo_token` share the walk `ndp` uses, so
    /// an ARP frame padded to look like IPv6 is declined by all three.
    #[test]
    fn a_frame_of_another_ethertype_carries_no_icmpv6() {
        let mut packet = vec![0u8; IP_V6_HDR_LEN];
        packet[4..6].copy_from_slice(&8u16.to_be_bytes()); // payload length
        packet[6] = IpNextHeaderProtocols::Icmpv6.0;
        packet.extend_from_slice(&[128, 0, 0, 0, 0, 0, 0, 0]); // an echo request

        let honest = frame_of(EtherTypes::Ipv6.0, &packet);
        assert_eq!(
            icmpv6_type(&read(&honest)),
            Some(128),
            "an IPv6 frame is still read"
        );

        for ethertype in [EtherTypes::Arp.0, EtherTypes::Ipv4.0, 0x88CC] {
            let bytes = frame_of(ethertype, &packet);
            assert_eq!(
                icmpv6_type(&read(&bytes)),
                None,
                "ethertype {ethertype:#06x} was read as IPv6"
            );
            assert_eq!(icmpv6_echo_token(&read(&bytes)), None);
        }
    }

    /// The two address readers, and the truncation that credits nobody.
    #[test]
    fn an_address_is_read_from_the_header_that_carries_it() {
        let v4 = frame_of(EtherTypes::Ipv4.0, &{
            let mut packet = ipv4_packet(5, 0, 17, &[]);
            packet[12..16].copy_from_slice(&V4.octets());
            packet
        });
        assert_eq!(ipv4_source(&read(&v4)).expect("a source"), V4);

        let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9);
        let v6 = frame_of(EtherTypes::Ipv6.0, &{
            let mut packet = vec![0u8; IP_V6_HDR_LEN];
            packet[8..24].copy_from_slice(&source.octets());
            packet[24..40].copy_from_slice(&destination.octets());
            packet
        });
        assert_eq!(ipv6_source(&read(&v6)).expect("a source"), source);
        assert_eq!(
            ipv6_destination(&read(&v6)).expect("a destination"),
            destination
        );

        for cut in 0..IP_V4_HDR_LEN {
            let short = frame_of(EtherTypes::Ipv4.0, &vec![0u8; cut]);
            assert!(
                matches!(
                    ipv4_source(&read(&short)),
                    Err(PacketError::Truncated { .. })
                ),
                "a {cut}-byte header credited somebody"
            );
        }
    }

    /// Parses one emitted fragment into the four things a receiver reads to put
    /// a datagram back together: its offset in eight-byte units, whether more
    /// follow, whether fragmentation was forbidden, and the piece it carries.
    fn parse(fragment: &[u8]) -> (u16, bool, bool, Vec<u8>) {
        let packet = Ipv4Packet::new(fragment).expect("a fragment parses");
        let flags = packet.get_flags();
        (
            packet.get_fragment_offset(),
            flags & craft::ipv4_flags::MORE_FRAGMENTS != 0,
            flags & craft::ipv4_flags::DONT_FRAGMENT != 0,
            packet.payload().to_vec(),
        )
    }

    /// Over three fragments: each starts one run of eight-byte units past the
    /// one before, more-fragments is set on all but the last, and don't-fragment
    /// is cleared on all though the caller's header set it.
    #[test]
    fn offsets_and_flags_march_across_three_fragments() {
        // Header 20, MTU 48 leaves 28 bytes, floored to 24 (three units), so a
        // 60-byte payload splits 24, 24, 12.
        let mtu = 48;
        let payload: Vec<u8> = (0..60u8).collect();
        let fragments = fragment_ipv4(&craft::Ipv4::new(V4, V4), &payload, mtu).expect("fragments");
        assert_eq!(fragments.len(), 3);

        let parsed: Vec<_> = fragments.iter().map(|f| parse(f)).collect();
        assert_eq!(
            [parsed[0].0, parsed[1].0, parsed[2].0],
            [0, 3, 6],
            "offsets count eight-byte units: 0, 24/8, 48/8"
        );
        assert_eq!(
            [parsed[0].1, parsed[1].1, parsed[2].1],
            [true, true, false],
            "more-fragments follows every piece but the last"
        );
        for fragment in &parsed {
            assert!(!fragment.2, "don't-fragment is cleared on every fragment");
        }
    }

    /// Over a ragged split: an MTU that is not the header plus whole units still
    /// yields whole-unit non-last pieces, and no packet exceeds the MTU.
    #[test]
    fn every_non_last_piece_is_whole_units_and_within_the_mtu() {
        // MTU 45 leaves 25 bytes, floored to 24; 100 bytes splits 24×4 + 4.
        let mtu = 45;
        let payload = vec![0xA5u8; 100];
        let fragments = fragment_ipv4(&craft::Ipv4::new(V4, V4), &payload, mtu).expect("fragments");
        assert_eq!(fragments.len(), 5);

        for (i, fragment) in fragments.iter().enumerate() {
            assert!(
                fragment.len() <= mtu as usize,
                "fragment {i} is {} bytes, over the {mtu}-byte MTU",
                fragment.len()
            );
            let (_, more_fragments, _, body) = parse(fragment);
            if more_fragments {
                assert_eq!(
                    body.len() % FRAGMENT_UNIT,
                    0,
                    "a non-last fragment is whole units"
                );
            }
        }
    }

    /// A datagram that already fits comes back whole with the caller's flags,
    /// don't-fragment included.
    #[test]
    fn a_datagram_that_fits_is_returned_whole() {
        let payload = vec![0xABu8; 100];
        let fragments =
            fragment_ipv4(&craft::Ipv4::new(V4, V4), &payload, 1500).expect("one packet");
        assert_eq!(fragments.len(), 1);

        let (offset, more_fragments, dont_fragment, body) = parse(&fragments[0]);
        assert_eq!(offset, 0);
        assert!(!more_fragments, "nothing follows a whole datagram");
        assert!(dont_fragment, "the caller's don't-fragment is untouched");
        assert_eq!(body, payload, "and the payload arrives intact");
    }

    /// Every fragment carries the same identification, resolved once from the
    /// caller's computed field.
    #[test]
    fn every_fragment_shares_one_identification() {
        let payload = vec![0u8; 200];
        let fragments = fragment_ipv4(&craft::Ipv4::new(V4, V4), &payload, 60).expect("fragments");
        assert!(fragments.len() >= 2, "the payload must actually split");

        let ids: Vec<u16> = fragments
            .iter()
            .map(|f| Ipv4Packet::new(f).expect("parses").get_identification())
            .collect();
        assert!(
            ids.iter().all(|id| *id == ids[0]),
            "one identification for the datagram, got {ids:?}"
        );
    }

    /// An MTU with no room for a header and one eight-byte unit is refused. The
    /// floor is exact.
    #[test]
    fn an_mtu_with_no_room_to_progress_is_refused() {
        let payload = vec![0u8; 40];
        // The floor is a 20-byte header plus one 8-byte unit: 28.
        let refused = fragment_ipv4(&craft::Ipv4::new(V4, V4), &payload, 27);
        assert!(
            matches!(refused, Err(PacketError::MtuTooSmall { .. })),
            "got {refused:?}"
        );
        fragment_ipv4(&craft::Ipv4::new(V4, V4), &payload, 28)
            .expect("28 bytes is one unit of room");
    }

    /// A datagram larger than the total-length field can describe is refused,
    /// which also keeps the last fragment's start inside the offset field.
    #[test]
    fn a_datagram_too_large_for_the_length_field_is_refused() {
        let largest = u16::MAX as usize - IP_V4_HDR_LEN;

        fragment_ipv4(&craft::Ipv4::new(V4, V4), &vec![0u8; largest], 1500)
            .expect("the largest describable datagram still fragments");

        let refused = fragment_ipv4(&craft::Ipv4::new(V4, V4), &vec![0u8; largest + 1], 1500);
        assert!(
            matches!(refused, Err(PacketError::TooLong { .. })),
            "got {refused:?}"
        );
    }

    /// A header carrying options is refused: the per-option copy bit is not
    /// read, and a blind split reassembles into the wrong header.
    #[test]
    fn a_header_with_options_is_refused() {
        let with_options = craft::Ipv4 {
            // A four-byte option; its contents do not matter to the refusal.
            options: vec![0x01, 0x01, 0x01, 0x00],
            ..craft::Ipv4::new(V4, V4)
        };
        let refused = fragment_ipv4(&with_options, &vec![0u8; 4000], 1500);
        assert!(
            matches!(refused, Err(PacketError::HeaderHasOptions { .. })),
            "got {refused:?}"
        );
    }

    proptest! {
        /// Over any payload and workable MTU: the fragments' payloads in offset
        /// order are exactly the original bytes, each non-last piece is whole
        /// eight-byte units, every packet fits the MTU, and only the last clears
        /// more-fragments. That is what a receiver relies on to reassemble.
        #[test]
        fn fragments_reassemble_into_the_original_datagram(
            payload in prop::collection::vec(any::<u8>(), 0..4096usize),
            mtu in 28u16..=1500,
        ) {
            let fragments = fragment_ipv4(&craft::Ipv4::new(V4, V4), &payload, mtu)
                .expect("a workable MTU fragments");

            // A datagram that fit keeps the caller's flags; only a split rewrites
            // them.
            let split = fragments.len() > 1;

            let mut reassembled = Vec::new();
            for (i, fragment) in fragments.iter().enumerate() {
                prop_assert!(fragment.len() <= mtu as usize);

                let packet = Ipv4Packet::new(fragment).expect("a fragment parses");
                let last = i + 1 == fragments.len();
                let flags = packet.get_flags();
                prop_assert_eq!(
                    flags & craft::ipv4_flags::MORE_FRAGMENTS != 0,
                    !last,
                    "more-fragments is set on every piece but the last"
                );
                if split {
                    prop_assert_eq!(flags & craft::ipv4_flags::DONT_FRAGMENT, 0);
                }

                let body = packet.payload();
                if !last {
                    prop_assert_eq!(body.len() % FRAGMENT_UNIT, 0, "a non-last fragment is whole units");
                }
                // The offset in eight-byte units is exactly how many bytes precede this
                // piece.
                prop_assert_eq!(
                    packet.get_fragment_offset() as usize * FRAGMENT_UNIT,
                    reassembled.len()
                );
                reassembled.extend_from_slice(body);
            }
            prop_assert_eq!(reassembled, payload);
        }
    }

    /// Reads one emitted v6 fragment into what a receiver needs to reassemble:
    /// its offset in eight-byte units, whether more follow, the upper-layer
    /// protocol the fragment header names, and the piece it carries.
    ///
    /// The piece is the base-header payload past the eight-byte extension, since
    /// pnet models the fragment header's own payload as empty.
    fn parse_v6(fragment: &[u8]) -> (u16, bool, IpNextHeaderProtocol, Vec<u8>) {
        use pnet_packet::ipv6::FragmentPacket;

        let packet = Ipv6Packet::new(fragment).expect("a v6 fragment parses");
        assert_eq!(
            packet.get_next_header(),
            IpNextHeaderProtocols::Ipv6Frag,
            "a fragment's base header points at the fragment extension"
        );
        let extension = FragmentPacket::new(packet.payload()).expect("a fragment header");
        let offset_with_flags = extension.get_fragment_offset_with_flags();
        (
            offset_with_flags >> 3,
            offset_with_flags & 1 != 0,
            extension.get_next_header(),
            packet.payload()[FRAGMENT_HEADER_LEN..].to_vec(),
        )
    }

    /// Over three fragments in v6: each starts one run of eight-byte units past
    /// the one before, more-fragments is set on all but the last, and every
    /// fragment header names the upper-layer protocol.
    #[test]
    fn offsets_and_flags_march_across_three_fragments_v6() {
        // Base 40 and fragment header 8 leave, at MTU 72, 24 bytes (three units),
        // so a 60-byte payload splits 24, 24, 12.
        let mtu = (IP_V6_HDR_LEN + FRAGMENT_HEADER_LEN + 24) as u16;
        let payload: Vec<u8> = (0..60u8).collect();
        let header = craft::Ipv6 {
            next_header: craft::Field::Exact(IpNextHeaderProtocols::Udp.0),
            ..craft::Ipv6::new(V6, V6)
        };
        let fragments = fragment_ipv6(&header, &payload, mtu).expect("fragments");
        assert_eq!(fragments.len(), 3);

        let parsed: Vec<_> = fragments.iter().map(|f| parse_v6(f)).collect();
        assert_eq!(
            [parsed[0].0, parsed[1].0, parsed[2].0],
            [0, 3, 6],
            "offsets count eight-byte units: 0, 24/8, 48/8"
        );
        assert_eq!(
            [parsed[0].1, parsed[1].1, parsed[2].1],
            [true, true, false],
            "more-fragments follows every piece but the last"
        );
        for fragment in &parsed {
            assert_eq!(
                fragment.2,
                IpNextHeaderProtocols::Udp,
                "each fragment header carries the protocol the base header gave up"
            );
        }
    }

    /// A datagram that already fits comes back whole: one ordinary IPv6 packet,
    /// no fragment header, its next-header still the upper-layer protocol.
    #[test]
    fn a_datagram_that_fits_is_returned_whole_v6() {
        let payload = vec![0xABu8; 100];
        let header = craft::Ipv6 {
            next_header: craft::Field::Exact(IpNextHeaderProtocols::Tcp.0),
            ..craft::Ipv6::new(V6, V6)
        };
        let fragments = fragment_ipv6(&header, &payload, 1500).expect("one packet");
        assert_eq!(fragments.len(), 1);

        let packet = Ipv6Packet::new(&fragments[0]).expect("parses");
        assert_eq!(
            packet.get_next_header(),
            IpNextHeaderProtocols::Tcp,
            "an unfragmented datagram carries no fragment header"
        );
        assert_eq!(packet.payload(), payload, "and the payload arrives intact");
    }

    /// A receiver groups a datagram's fragments by identification, so every
    /// fragment carries the same one.
    #[test]
    fn every_fragment_shares_one_identification_v6() {
        use pnet_packet::ipv6::FragmentPacket;

        let payload = vec![0u8; 200];
        let fragments = fragment_ipv6(&craft::Ipv6::new(V6, V6), &payload, 96).expect("fragments");
        assert!(fragments.len() >= 2, "the payload must actually split");

        let ids: Vec<u32> = fragments
            .iter()
            .map(|f| {
                let packet = Ipv6Packet::new(f).expect("parses");
                FragmentPacket::new(packet.payload())
                    .expect("a fragment header")
                    .get_id()
            })
            .collect();
        assert!(
            ids.iter().all(|id| *id == ids[0]),
            "one identification for the datagram, got {ids:?}"
        );
    }

    /// An MTU with no room for the two headers and one eight-byte unit is
    /// refused. The floor is exact.
    #[test]
    fn an_mtu_with_no_room_to_progress_is_refused_v6() {
        let payload = vec![0u8; 40];
        let floor = SMALLEST_FRAGMENT_MTU_V6;
        let refused = fragment_ipv6(&craft::Ipv6::new(V6, V6), &payload, floor - 1);
        assert!(
            matches!(refused, Err(PacketError::MtuTooSmall { .. })),
            "got {refused:?}"
        );
        fragment_ipv6(&craft::Ipv6::new(V6, V6), &payload, floor)
            .expect("the floor is one unit of room");
    }

    /// A payload larger than a thirteen-bit offset can address is refused, not
    /// wrapped.
    #[test]
    fn a_payload_too_large_for_the_offset_field_is_refused_v6() {
        let largest = u16::MAX as usize;
        fragment_ipv6(&craft::Ipv6::new(V6, V6), &vec![0u8; largest], 1500)
            .expect("the largest addressable payload still fragments");

        let refused = fragment_ipv6(&craft::Ipv6::new(V6, V6), &vec![0u8; largest + 1], 1500);
        assert!(
            matches!(refused, Err(PacketError::TooLong { .. })),
            "got {refused:?}"
        );
    }

    proptest! {
        /// The v6 reassembly check: over any payload and workable MTU, the pieces
        /// in offset order are exactly the original bytes, each non-last piece is
        /// whole eight-byte units, every packet fits the MTU, and only the last clears
        /// more-fragments.
        #[test]
        fn fragments_reassemble_into_the_original_datagram_v6(
            payload in prop::collection::vec(any::<u8>(), 0..4096usize),
            mtu in (SMALLEST_FRAGMENT_MTU_V6)..=1500,
        ) {
            let fragments = fragment_ipv6(&craft::Ipv6::new(V6, V6), &payload, mtu)
                .expect("a workable MTU fragments");
            let split = fragments.len() > 1;

            let mut reassembled = Vec::new();
            for (i, fragment) in fragments.iter().enumerate() {
                prop_assert!(fragment.len() <= mtu as usize);
                let last = i + 1 == fragments.len();

                // A datagram that fit is a plain packet with no fragment header;
                // only a split one carries the extension this walks.
                if !split {
                    let packet = Ipv6Packet::new(fragment).expect("parses");
                    reassembled.extend_from_slice(packet.payload());
                    continue;
                }

                let (offset, more_fragments, _, body) = parse_v6(fragment);
                prop_assert_eq!(more_fragments, !last, "more-fragments is set on every piece but the last");
                if !last {
                    prop_assert_eq!(body.len() % FRAGMENT_UNIT, 0, "a non-last fragment is whole units");
                }
                prop_assert_eq!(
                    offset as usize * FRAGMENT_UNIT,
                    reassembled.len(),
                    "the offset counts the bytes before this piece"
                );
                reassembled.extend_from_slice(&body);
            }
            prop_assert_eq!(reassembled, payload);
        }
    }

    /// **Every fragment fits its MTU, and the pieces put the datagram back
    /// together**, for both families and any MTU.
    ///
    /// Length fields, offsets in eight-byte units and repeated headers all hide
    /// off-by-ones that do not crash, so the oracle is reassembly: the
    /// concatenated payloads must equal the input exactly. 170 combinations,
    /// including every MTU too small for a fragment, where the answer is a
    /// refusal.
    #[test]
    fn every_fragment_fits_its_mtu_and_the_pieces_reassemble() {
        let v4_header = craft::Ipv4::new(
            "192.0.2.1".parse().expect("literal"),
            "192.0.2.2".parse().expect("literal"),
        );
        let v6_header = craft::Ipv6::new(
            "2001:db8::1".parse().expect("literal"),
            "2001:db8::2".parse().expect("literal"),
        );

        // Around every deciding boundary: the two header sizes, the fragment
        // header, the eight-byte unit, and each family's smallest MTU.
        let mtus = [
            0u16, 1, 7, 8, 20, 21, 27, 28, 39, 40, 47, 48, 55, 56, 64, 1280, 1500,
        ];
        let sizes = [0usize, 1, 7, 8, 9, 63, 64, 1000, 1500, 9000];

        for mtu in mtus {
            for size in sizes {
                let payload: Vec<u8> = (0..size).map(|byte| (byte % 251) as u8).collect();

                if let Ok(fragments) = fragment_ipv4(&v4_header, &payload, mtu) {
                    let mut rebuilt = Vec::new();
                    for fragment in &fragments {
                        if fragments.len() > 1 {
                            assert!(
                                fragment.len() <= mtu as usize,
                                "an IPv4 fragment of {} bytes does not fit an MTU of {mtu}",
                                fragment.len()
                            );
                        }
                        rebuilt.extend_from_slice(&fragment[IP_V4_HDR_LEN..]);
                    }
                    assert_eq!(
                        rebuilt, payload,
                        "IPv4 mtu={mtu} size={size} did not reassemble"
                    );
                }

                if let Ok(fragments) = fragment_ipv6(&v6_header, &payload, mtu) {
                    // One piece and no fragment header is the unfragmented case.
                    let carries_header =
                        fragments.len() > 1 || fragments[0].len() > IP_V6_HDR_LEN + size;
                    let skip = match carries_header {
                        true => IP_V6_HDR_LEN + FRAGMENT_HEADER_LEN,
                        false => IP_V6_HDR_LEN,
                    };

                    let mut rebuilt = Vec::new();
                    for fragment in &fragments {
                        if fragments.len() > 1 {
                            assert!(
                                fragment.len() <= mtu as usize,
                                "an IPv6 fragment of {} bytes does not fit an MTU of {mtu}",
                                fragment.len()
                            );
                        }
                        rebuilt.extend_from_slice(&fragment[skip..]);
                    }
                    assert_eq!(
                        rebuilt, payload,
                        "IPv6 mtu={mtu} size={size} did not reassemble"
                    );
                }
            }
        }
    }
}
