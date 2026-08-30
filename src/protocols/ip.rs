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
use crate::protocols::ethernet::Frame;
use crate::protocols::sizes::{IP_V4_HDR_LEN, IP_V6_HDR_LEN, UDP_HDR_LEN};
use pnet_packet::Packet;
use pnet_packet::ethernet::EtherTypes;
use pnet_packet::icmpv6::echo_reply::EchoReplyPacket;
use pnet_packet::icmpv6::{Icmpv6Packet, Icmpv6Type, Icmpv6Types};
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;

const WORD_LEN: usize = 4;

/// The eight-byte unit an IPv4 fragment offset counts in (RFC 791 §3.1), so a
/// fragment that is not the last must carry a whole number of these.
const FRAGMENT_UNIT: usize = 8;

/// Builds a 20-byte IPv4 header (no options) for a packet carrying
/// `payload_length` bytes of `next_protocol` from `src_addr` to `dst_addr`.
///
/// The header checksum is computed over the finished header, because nothing
/// downstream will do it; see the module documentation.
///
/// `ttl` is a parameter for the same reason its IPv6 counterpart's `hop_limit`
/// is, and for one more: a probe sent to expire on purpose is how a path is
/// measured. [`HOP_LIMIT_ROUTED`] is what an ordinary probe passes;
/// [`traceroute`](crate::scanner::strategy::routed::traceroute) passes each
/// value in turn and reads the errors that come back.
///
/// # Errors
///
/// [`PacketError::TooLong`] when the payload and the header together exceed
/// what the 16-bit total-length field can describe, which is 65 515 bytes of
/// payload. Refused rather than truncated: a wrapped value describes a packet
/// shorter than its own header, and every receiver drops it.
pub fn build_ipv4_header(
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    payload_length: u16,
    next_protocol: IpNextHeaderProtocol,
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
/// `header` is the IPv4 header the caller would otherwise send whole; `payload`
/// is the finished Layer-4 segment behind it — a TCP or UDP segment whose
/// checksum was computed over the entire thing. The segment is split as opaque
/// bytes and never re-checksummed: only the first fragment carries the Layer-4
/// header, and the rest are the middle of a datagram the receiver puts back
/// together.
///
/// Each returned packet is a complete IPv4 packet — header bytes, sized and
/// checksummed for its own piece, followed by that piece — ready to hand to a
/// link-layer send. This is where the engine picks the fragmentation flags the
/// module documentation promises it does:
/// [`MORE_FRAGMENTS`](craft::ipv4_flags::MORE_FRAGMENTS) on every fragment but
/// the last, [`DONT_FRAGMENT`](craft::ipv4_flags::DONT_FRAGMENT) cleared on all
/// of them, and a [`fragment_offset`](craft::Ipv4::fragment_offset) counting
/// eight-byte units from the start of the payload.
///
/// Every fragment shares one [`identification`](craft::Ipv4::identification): a
/// caller's [`Field::Exact`](craft::Field::Exact) is kept, a
/// [`Computed`](craft::Field::Computed) is resolved to a single random value
/// once and stamped on all of them, because a receiver groups fragments by that
/// field and a per-fragment identifier reassembles into nothing.
///
/// A datagram that already fits `mtu` comes back as one packet with the caller's
/// own flags untouched, don't-fragment included.
///
/// # Errors
///
/// [`PacketError::HeaderHasOptions`] when `header` carries options: whether an
/// option is copied into every fragment or kept on the first is a per-option
/// bit this does not yet honour, so an option-bearing header is refused rather
/// than split into fragments a receiver would reassemble wrongly.
///
/// [`PacketError::MtuTooSmall`] when `mtu` cannot hold the header and at least
/// one eight-byte unit of payload — a fragment carrying less makes no forward
/// progress, and refusing is the only alternative to an unbounded run of them.
///
/// [`PacketError::TooLong`] when the datagram is larger than the 16-bit
/// total-length field can describe, the same limit [`build_ipv4_header`]
/// refuses at. Past it the last fragment's start would also overflow the
/// thirteen-bit fragment-offset field, so the two limits are really one.
pub fn fragment_ipv4(header: &craft::Ipv4, payload: &[u8], mtu: u16) -> Result<Vec<Vec<u8>>> {
    if !header.options.is_empty() {
        return Err(PacketError::HeaderHasOptions {
            options: header.options.len(),
        });
    }

    let header_len = IP_V4_HDR_LEN;
    let mtu = mtu as usize;

    // The one limit that governs the whole datagram: past it the reassembled
    // length cannot be described, and — header plus payload being at most 65 535
    // — no fragment can start beyond what the offset field holds either.
    if header_len + payload.len() > u16::MAX as usize {
        return Err(PacketError::too_long(
            "the IPv4 total length",
            header_len,
            payload.len(),
        ));
    }

    // The whole datagram fits: hand it back as the caller described it, flags
    // and all, rather than fragmenting what needs no fragmenting.
    if header_len + payload.len() <= mtu {
        let mut packet = header.header_bytes(payload.len() as u16)?;
        packet.extend_from_slice(payload);
        return Ok(vec![packet]);
    }

    // Every fragment but the last carries a whole number of eight-byte units,
    // since the offset counts in those; the last carries the remainder.
    let max_chunk = (mtu.saturating_sub(header_len) / FRAGMENT_UNIT) * FRAGMENT_UNIT;
    if max_chunk == 0 {
        return Err(PacketError::MtuTooSmall {
            mtu,
            minimum: header_len + FRAGMENT_UNIT,
        });
    }

    // One identification for the whole datagram, resolved from the caller's
    // field once — not rolled afresh for each fragment, which would leave a
    // receiver with pieces it cannot group.
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
            // Re-derived for each fragment: the length and the checksum both
            // move with the piece, so a caller's exact values would be right for
            // at most one of them.
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
pub fn build_ipv6_header(
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

/// The ICMPv6 message type an Ethernet-framed IPv6 packet carries, or `None` if
/// it is not ICMPv6 or is too short to say.
///
/// Reads the fixed header's next-header field rather than walking the extension
/// chain, so a packet carrying one is reported as not-ICMPv6. That is the safe
/// direction to be wrong in for a discovery check - it declines to credit a
/// frame it cannot read rather than guessing at its type - and the probes this
/// interprets replies to elicit no extension headers.
pub fn icmpv6_type(frame: &Frame<'_>) -> Option<Icmpv6Type> {
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
pub fn icmpv6_echo_token(frame: &Frame<'_>) -> Option<(u16, u16)> {
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
pub fn udp_payload<'a>(frame: &Frame<'a>, port: u16) -> Option<&'a [u8]> {
    let packet = frame.payload();

    // Offsets rather than `packet.payload()`, because a pnet view owns the
    // slice it hands back and the caller needs one borrowed from the frame.
    let (header_len, next) = match frame.ethertype() {
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

        let header = build_ipv4_header(
            V4,
            V4,
            largest as u16,
            IpNextHeaderProtocols::Tcp,
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
                IpNextHeaderProtocols::Tcp,
                HOP_LIMIT_ROUTED,
            );
            assert!(
                matches!(refused, Err(PacketError::TooLong { .. })),
                "a payload of {oversize} produced {refused:?}"
            );
        }
    }

    // ── Fragmentation ────────────────────────────────────────────────────────

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

    /// The heart of it, over three fragments: each starts one run of eight-byte
    /// units past the one before, more-fragments is set on every piece but the
    /// last, and don't-fragment is cleared on all of them — even though the
    /// caller's header set it.
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

    /// The two size invariants over a longer, ragged split: an MTU that is not
    /// the header plus a whole number of units still yields non-last pieces that
    /// are whole units, and no packet exceeds the MTU.
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

    /// A datagram that already fits comes back whole — one packet, with the
    /// caller's flags, don't-fragment among them, left exactly as they were.
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

    /// A receiver groups fragments of one datagram by identification, so every
    /// fragment has to carry the same one — resolved from the caller's computed
    /// field once, not rolled afresh per fragment.
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

    /// An MTU with no room for a header and one eight-byte unit is refused
    /// rather than split into a run of headers that never reaches the payload.
    /// The floor is exact: one byte more is enough for a unit.
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
    /// the same limit a whole header is — and the limit that keeps the last
    /// fragment's start inside its thirteen-bit offset field.
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

    /// A header carrying options is refused: whether each option rides every
    /// fragment or only the first is a per-option bit this does not yet read,
    /// and a blind split reassembles into the wrong header.
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
        /// The single most valuable check: over any payload and any workable
        /// MTU, the fragments' payloads in offset order are exactly the original
        /// bytes, each non-last piece is a whole number of eight-byte units,
        /// every packet fits the MTU, and only the last clears more-fragments.
        /// That is the whole of what a receiver relies on to reassemble.
        #[test]
        fn fragments_reassemble_into_the_original_datagram(
            payload in prop::collection::vec(any::<u8>(), 0..4096usize),
            mtu in 28u16..=1500,
        ) {
            let fragments = fragment_ipv4(&craft::Ipv4::new(V4, V4), &payload, mtu)
                .expect("a workable MTU fragments");

            // A datagram that fit comes back as one packet with the caller's own
            // flags; only when it is actually split are the flags this rewrites.
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
                // The offset is in eight-byte units from the payload's start,
                // which is exactly how many bytes precede this piece.
                prop_assert_eq!(
                    packet.get_fragment_offset() as usize * FRAGMENT_UNIT,
                    reassembled.len()
                );
                reassembled.extend_from_slice(body);
            }
            prop_assert_eq!(reassembled, payload);
        }
    }
}
