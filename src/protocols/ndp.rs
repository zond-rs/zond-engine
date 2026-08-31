// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Neighbor Discovery (RFC 4861)
//!
//! IPv6's answer to ARP, and the mechanism that makes local IPv6 discovery
//! reliable rather than opportunistic.
//!
//! The engine's other IPv6 probe is an echo request to the all-nodes group,
//! which is *optional* to answer: Windows does not, and neither do many embedded
//! stacks. A neighbor solicitation is not optional. Answering one is how IPv6
//! resolves link-layer addresses at all, so a host that ignores it cannot be
//! spoken to by its own router. Every conformant neighbour on a segment replies,
//! whatever it thinks of being scanned.
//!
//! It is also the only IPv6 probe that can be aimed at *one* address. The
//! all-nodes echo asks the whole segment a single question and is answered by
//! whoever feels like it; a solicitation asks about a named address, which is
//! what lets a targeted scan probe the host it was asked about and what lets the
//! retry ledger own an outstanding probe per target the way it does for ARP.
//!
//! ## Two details that are fatal to get wrong
//!
//! The hop limit must be 255. RFC 4861 §7.1.1 requires a receiver to discard
//! any neighbor discovery message that did not arrive with a hop limit of 255,
//! which is what proves it was not forwarded by a router. This is the one place
//! the engine's "on-link traffic uses a hop limit of 1" rule does not apply, and
//! getting it wrong produces a probe that is silently ignored by every correct
//! implementation.
//!
//! The destination is the solicited-node multicast group rather than the target
//! itself or all-nodes. Every host joins the group derived from the low 24 bits
//! of each of its addresses, so a solicitation reaches the target while being
//! ignored by the network card of almost every other neighbour, with the
//! filtering happening in hardware rather than in a stack.

use pnet_base::MacAddr;
use pnet_packet::Packet as _;
use pnet_packet::ethernet::EtherTypes;
use pnet_packet::icmpv6::Icmpv6Types;
use pnet_packet::icmpv6::ndp::NeighborAdvertPacket;
use pnet_packet::ip::IpNextHeaderProtocols;
use std::net::Ipv6Addr;

use crate::protocols::craft::{Ethernet, Field, Icmpv6, Ipv6, Packet};
use crate::protocols::ethernet::Frame;
use crate::protocols::ip;

/// What a solicitation carries after the shared ICMPv6 header: the sixteen-byte
/// target address. The four reserved bytes before it are the header's own
/// type-specific field.
const SOLICIT_BODY_LEN: usize = 16;

/// A source link-layer address option: type, length, and six bytes of MAC.
const OPTION_LEN: usize = 8;

/// ICMPv6 neighbor solicitation, RFC 4861.
const NEIGHBOR_SOLICIT: u8 = 135;

/// ICMPv6 router solicitation, RFC 4861 §4.1.
const ROUTER_SOLICIT: u8 = 133;

/// The bit a neighbour sets in an advertisement to say it forwards traffic,
/// RFC 4861 §4.4. The high bit of the byte that follows the ICMP header, ahead
/// of the solicited and override flags.
const ROUTER_FLAG: u8 = 0b1000_0000;

/// Where a router solicitation goes: every router on the segment, and nothing
/// else. RFC 4291 §2.7.1.
const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

/// The option that tells the answering neighbour where to reply, so it does not
/// have to solicit us back first. RFC 4861 §4.6.1.
const NDP_OPTION_SOURCE_LL_ADDR: u8 = 1;

/// The first two octets of the Ethernet address IPv6 multicast maps onto
/// (RFC 2464 §7), the remaining four being the low 32 bits of the group.
const IPV6_MULTICAST_MAC_PREFIX: [u8; 2] = [0x33, 0x33];

/// The solicited-node multicast group `target` listens on.
///
/// Formed from the low 24 bits of the address, which is what makes a
/// solicitation cheap for everyone else on the segment: a neighbour whose own
/// addresses end differently never sees the frame, because its network card
/// filters the multicast MAC out before any software runs.
///
/// The 24-bit tail is also why this is not a unique address. Two neighbours
/// whose addresses agree in their last three octets share a group and both see
/// the frame; the target address inside the message is what decides which of
/// them answers.
pub fn solicited_node_multicast(target: Ipv6Addr) -> Ipv6Addr {
    let octets = target.octets();
    Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        u16::from_be_bytes([0xff, octets[13]]),
        u16::from_be_bytes([octets[14], octets[15]]),
    )
}

/// The Ethernet address an IPv6 multicast group maps onto (RFC 2464 §7).
///
/// Built rather than broadcast, which is the point: a broadcast frame
/// interrupts every device on the segment, while this one is discarded by the
/// hardware of everything except the few neighbours in the group.
pub fn multicast_mac(group: Ipv6Addr) -> MacAddr {
    let octets = group.octets();
    MacAddr::new(
        IPV6_MULTICAST_MAC_PREFIX[0],
        IPV6_MULTICAST_MAC_PREFIX[1],
        octets[12],
        octets[13],
        octets[14],
        octets[15],
    )
}

/// Builds a neighbor solicitation asking whether `target` is present, sent from
/// `src_mac`/`src_addr` to `target`'s solicited-node group.
///
/// The source link-layer address option is included so the answering neighbour
/// can reply directly instead of soliciting us back first. Leaving it out is
/// legal and doubles the exchange.
pub fn build_neighbor_solicitation(
    src_mac: MacAddr,
    src_addr: Ipv6Addr,
    target: Ipv6Addr,
) -> Vec<u8> {
    let group = solicited_node_multicast(target);

    // The message body a solicitation carries after the shared ICMP header:
    // four reserved bytes, the target address, then the source link-layer
    // address option. Written out because it is not an echo, which is the only
    // ICMPv6 shape `craft::Icmpv6` names.
    let mut body = Vec::with_capacity(SOLICIT_BODY_LEN + OPTION_LEN);
    body.extend_from_slice(&target.octets());
    body.push(NDP_OPTION_SOURCE_LL_ADDR);
    // In units of eight bytes, counting the type and length bytes themselves.
    body.push(1);
    body.extend_from_slice(&src_mac.octets());

    let message = Icmpv6 {
        icmp_type: NEIGHBOR_SOLICIT,
        code: 0,
        checksum: Field::Computed,
        // The four reserved bytes sit where an echo puts its identifier and
        // sequence, and RFC 4861 requires them to be zero.
        rest_of_header: [0; 4],
        payload: body,
    };

    Packet::new()
        .push(Ethernet::new(src_mac, multicast_mac(group)).with_ethertype(EtherTypes::Ipv6))
        .push(Ipv6::new(src_addr, group).with_hop_limit(ip::HOP_LIMIT_NDP))
        .push(message)
        .build()
        .expect("a solicitation fits every length field it is counted by")
}

/// Builds a router solicitation: one packet that asks every router on the
/// segment to identify itself, RFC 4861 §4.1.
///
/// A router answers this within half a second (§6.2.6), where an unsolicited
/// advertisement is sent on a timer measured in minutes, longer than any sweep
/// runs. Asking is the difference between finding the segment's routers and
/// happening to be listening when one spoke.
///
/// Carries the source link-layer address option for the reason a neighbor
/// solicitation does: the answer can then come back directly instead of being
/// preceded by a solicitation of its own.
pub fn build_router_solicitation(src_mac: MacAddr, src_addr: Ipv6Addr) -> Vec<u8> {
    let mut body = Vec::with_capacity(OPTION_LEN);
    body.push(NDP_OPTION_SOURCE_LL_ADDR);
    body.push(1);
    body.extend_from_slice(&src_mac.octets());

    let message = Icmpv6 {
        icmp_type: ROUTER_SOLICIT,
        code: 0,
        checksum: Field::Computed,
        // Four reserved bytes, which RFC 4861 §4.1 requires to be zero.
        rest_of_header: [0; 4],
        payload: body,
    };

    Packet::new()
        .push(Ethernet::new(src_mac, multicast_mac(ALL_ROUTERS)).with_ethertype(EtherTypes::Ipv6))
        .push(Ipv6::new(src_addr, ALL_ROUTERS).with_hop_limit(ip::HOP_LIMIT_NDP))
        .push(message)
        .build()
        .expect("a router solicitation fits every length field it is counted by")
}

/// A neighbor advertisement, reduced to what discovery reads from one.
///
/// `#[non_exhaustive]`: RFC 4861 §4.4 puts three flags in the byte this reads
/// one of, and the solicited flag in particular tells an answer to a probe of
/// ours from a neighbour announcing itself. Reading it adds a field here.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Advertisement {
    /// The address being announced.
    ///
    /// Not always the frame's IPv6 source: a router proxying for another host
    /// answers on its behalf, and an unsolicited advertisement is sent to the
    /// all-nodes group rather than to us. Reading the target rather than the
    /// source keeps a reply attributed to the address it is about.
    pub target: Ipv6Addr,
    /// Whether the sender set the R flag, saying it forwards traffic for
    /// others (RFC 4861 §4.4).
    ///
    /// Free evidence: this is an ordinary discovery reply, and the same message
    /// that proves the neighbour is there says what it is.
    pub router: bool,
}

/// Reads `frame` as a neighbor advertisement, if it is one.
pub fn advertisement(frame: &Frame<'_>) -> Option<Advertisement> {
    let packet = icmpv6(frame)?;

    let advert = NeighborAdvertPacket::new(packet.payload())?;
    if advert.get_icmpv6_type() != Icmpv6Types::NeighborAdvert {
        return None;
    }

    Some(Advertisement {
        target: advert.get_target_addr(),
        // The flag is believed only from a message that cannot have been
        // forwarded, which is the check RFC 4861 §7.1.2 puts on a receiver and
        // the whole of what stops an off-link sender from claiming the segment's
        // routing. Presence is not held to it: this engine is not a stack, and
        // refusing a malformed advertisement outright would lose a host that is
        // demonstrably there over a claim it never made.
        router: advert.get_flags() & ROUTER_FLAG != 0
            && packet.get_hop_limit() == ip::HOP_LIMIT_NDP,
    })
}

/// Whether `frame` is a router advertisement, which its sender is only entitled
/// to send if it routes (RFC 4861 §4.2).
///
/// Held to the hop limit the RFC requires (§6.1.2), so an advertisement that
/// crossed a router, and so did not come from the segment it claims to serve,
/// establishes nothing. Unlike a neighbour advertisement there is no
/// second claim here to preserve: the whole message is the router's account of
/// itself.
pub fn is_router_advertisement(frame: &Frame<'_>) -> bool {
    let Some(packet) = icmpv6(frame) else {
        return false;
    };

    packet
        .payload()
        .first()
        .is_some_and(|icmp_type| *icmp_type == Icmpv6Types::RouterAdvert.0)
        && packet.get_hop_limit() == ip::HOP_LIMIT_NDP
}

/// The IPv6 packet inside `frame`, if it carries ICMPv6.
fn icmpv6<'a>(frame: &Frame<'a>) -> Option<pnet_packet::ipv6::Ipv6Packet<'a>> {
    ip::ipv6_carrying(frame, IpNextHeaderProtocols::Icmpv6)
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
    use crate::protocols::ethernet;
    use crate::protocols::sizes::ETH_HDR_LEN;
    use pnet_packet::icmpv6::Icmpv6Type;
    use pnet_packet::icmpv6::ndp::NdpOptionTypes;
    use pnet_packet::icmpv6::ndp::{
        MutableNeighborAdvertPacket, NeighborSolicitPacket, RouterSolicitPacket,
    };
    use pnet_packet::ipv6::Ipv6Packet;

    const SRC_MAC: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 0x01);

    fn src_addr() -> Ipv6Addr {
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x50)
    }

    /// The worked example from RFC 4291 §2.7.1: the group is the prefix plus the
    /// low 24 bits of the address.
    #[test]
    fn the_solicited_node_group_is_the_prefix_plus_the_low_24_bits() {
        let target = Ipv6Addr::new(0x4037, 0, 0, 0, 0x01, 0x800, 0x200e, 0x8c6c);

        assert_eq!(
            solicited_node_multicast(target),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff0e, 0x8c6c)
        );
    }

    /// Two addresses agreeing only in their last three octets share a group,
    /// which is why the target address inside the message decides who answers
    /// rather than the destination doing it.
    #[test]
    fn addresses_sharing_their_low_24_bits_share_a_group() {
        let a = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0x11aa, 0xbbcc);
        let b = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0x99aa, 0xbbcc);

        assert_eq!(solicited_node_multicast(a), solicited_node_multicast(b));
    }

    /// RFC 2464 §7: `33:33` followed by the group's low 32 bits.
    #[test]
    fn a_multicast_group_maps_onto_its_ethernet_address() {
        let group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff0e, 0x8c6c);

        assert_eq!(
            multicast_mac(group),
            MacAddr::new(0x33, 0x33, 0xff, 0x0e, 0x8c, 0x6c)
        );
    }

    /// The detail RFC 4861 §7.1.1 makes a receiver check: a solicitation that
    /// did not arrive with a hop limit of 255 could have been forwarded by a
    /// router, so a conformant neighbour discards it. A probe built with the
    /// engine's ordinary on-link hop limit is ignored by everything correct,
    /// which is indistinguishable from a segment with nothing on it.
    #[test]
    fn a_solicitation_carries_the_hop_limit_the_rfc_requires() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA);
        let frame = build_neighbor_solicitation(SRC_MAC, src_addr(), target);

        let eth = super::super::ethernet::parse(&frame).unwrap();
        let packet = Ipv6Packet::new(eth.payload()).unwrap();

        assert_eq!(packet.get_hop_limit(), 255);
    }

    /// The frame has to be addressed to the target's group at both layers, or
    /// the target's own hardware filters it out before anything reads it.
    #[test]
    fn a_solicitation_is_addressed_to_the_targets_group() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0x11aa, 0xbbcc);
        let frame = build_neighbor_solicitation(SRC_MAC, src_addr(), target);

        let eth = super::super::ethernet::parse(&frame).unwrap();
        assert_eq!(
            eth.destination(),
            MacAddr::new(0x33, 0x33, 0xff, 0xaa, 0xbb, 0xcc)
        );

        let packet = Ipv6Packet::new(eth.payload()).unwrap();
        assert_eq!(packet.get_destination(), solicited_node_multicast(target));
        assert_eq!(packet.get_source(), src_addr());
    }

    /// The message names the address being asked about, and carries our own
    /// link-layer address so the answer can come back directly.
    #[test]
    fn a_solicitation_names_its_target_and_offers_a_return_address() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA);
        let frame = build_neighbor_solicitation(SRC_MAC, src_addr(), target);

        let eth = super::super::ethernet::parse(&frame).unwrap();
        let packet = Ipv6Packet::new(eth.payload()).unwrap();
        let solicit = NeighborSolicitPacket::new(packet.payload()).unwrap();

        assert_eq!(solicit.get_icmpv6_type(), Icmpv6Types::NeighborSolicit);
        assert_eq!(solicit.get_target_addr(), target);

        let options = solicit.get_options();
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].option_type, NdpOptionTypes::SourceLLAddr);
        assert_eq!(options[0].data, SRC_MAC.octets().to_vec());
    }

    /// A checksum of zero is a message every receiver discards, and the
    /// pseudo-header it is computed over is why it cannot be filled in later by
    /// whoever writes the IP header.
    #[test]
    fn a_solicitation_is_checksummed() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA);
        let frame = build_neighbor_solicitation(SRC_MAC, src_addr(), target);

        let eth = super::super::ethernet::parse(&frame).unwrap();
        let packet = Ipv6Packet::new(eth.payload()).unwrap();
        let solicit = NeighborSolicitPacket::new(packet.payload()).unwrap();

        assert_ne!(solicit.get_checksum(), 0);
    }

    fn advertisement_frame(target: Ipv6Addr, message_type: Icmpv6Type) -> Vec<u8> {
        advertisement_frame_with(target, message_type, 0, ip::HOP_LIMIT_NDP)
    }

    /// An advertisement built with the flag byte and hop limit a real one
    /// arrives with, which are the two things a router claim is read from.
    fn advertisement_frame_with(
        target: Ipv6Addr,
        message_type: Icmpv6Type,
        flags: u8,
        hop_limit: u8,
    ) -> Vec<u8> {
        let mut message = vec![0u8; 24];
        {
            let mut advert = MutableNeighborAdvertPacket::new(&mut message).unwrap();
            advert.set_icmpv6_type(message_type);
            advert.set_target_addr(target);
            advert.set_flags(flags);
        }

        let eth = ethernet::build_header(SRC_MAC, SRC_MAC, EtherTypes::Ipv6);
        let ipv6 = ip::build_ipv6_header(
            target,
            src_addr(),
            message.len() as u16,
            IpNextHeaderProtocols::Icmpv6,
            hop_limit,
        );

        [eth, ipv6, message].concat()
    }

    #[test]
    fn an_advertisement_yields_the_address_it_announces() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA);
        let frame = advertisement_frame(target, Icmpv6Types::NeighborAdvert);
        let eth = super::super::ethernet::parse(&frame).unwrap();

        assert_eq!(
            advertisement(&eth),
            Some(Advertisement {
                target,
                router: false
            })
        );
    }

    /// Everything else on the segment has to be refused, including the
    /// solicitations neighbours send each other constantly. Reading one as an
    /// answer would credit the probe with a host that never replied to it.
    #[test]
    fn other_icmpv6_traffic_is_not_an_advertisement() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA);

        for message_type in [Icmpv6Types::NeighborSolicit, Icmpv6Types::EchoReply] {
            let frame = advertisement_frame(target, message_type);
            let eth = super::super::ethernet::parse(&frame).unwrap();
            assert_eq!(advertisement(&eth), None);
        }

        let arp = [0u8; ETH_HDR_LEN + 8];
        let eth = super::super::ethernet::parse(&arp).unwrap();
        assert_eq!(advertisement(&eth), None);
    }

    /// The R flag is the neighbour's own word that it forwards, and it rides on
    /// an advertisement the scan solicited anyway. The bit next to it, S for
    /// solicited, must not be read as it: the two differ by one position, and a
    /// reply to the scan's own probe carries S set on every host that answers.
    #[test]
    fn an_advertisement_carries_whether_its_sender_routes() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA);

        for (flags, routes) in [(ROUTER_FLAG, true), (0b0100_0000, false), (0, false)] {
            let frame = advertisement_frame_with(
                target,
                Icmpv6Types::NeighborAdvert,
                flags,
                ip::HOP_LIMIT_NDP,
            );
            let eth = super::super::ethernet::parse(&frame).unwrap();

            assert_eq!(
                advertisement(&eth).expect("an advertisement").router,
                routes,
                "flags {flags:#010b}"
            );
        }
    }

    /// RFC 4861 §7.1.2: a message that did not arrive with a hop limit of 255
    /// may have been forwarded, so nothing off the segment can claim to route
    /// it. The host itself is still there, the frame having arrived, so the
    /// address survives the claim being dropped.
    #[test]
    fn a_forwarded_advertisement_proves_presence_but_never_routing() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA);
        let frame = advertisement_frame_with(target, Icmpv6Types::NeighborAdvert, ROUTER_FLAG, 254);
        let eth = super::super::ethernet::parse(&frame).unwrap();

        assert_eq!(
            advertisement(&eth),
            Some(Advertisement {
                target,
                router: false
            })
        );
    }

    /// Only a router sends one, so the message type is the whole claim, held to
    /// the same hop limit for the same reason.
    #[test]
    fn a_router_advertisement_is_recognised_only_from_the_segment() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x01);

        let from_the_segment =
            advertisement_frame_with(target, Icmpv6Types::RouterAdvert, 0, ip::HOP_LIMIT_NDP);
        assert!(is_router_advertisement(
            &super::super::ethernet::parse(&from_the_segment).unwrap()
        ));

        let forwarded = advertisement_frame_with(target, Icmpv6Types::RouterAdvert, 0, 254);
        assert!(!is_router_advertisement(
            &super::super::ethernet::parse(&forwarded).unwrap()
        ));

        let neighbour = advertisement_frame(target, Icmpv6Types::NeighborAdvert);
        assert!(!is_router_advertisement(
            &super::super::ethernet::parse(&neighbour).unwrap()
        ));
    }

    /// The one packet that makes routers answer now rather than on their own
    /// timer. Wrong at either layer it reaches nothing: the all-routers group is
    /// what routers listen to, and a hop limit below 255 is discarded by every
    /// conformant receiver (RFC 4861 §6.1.1).
    #[test]
    fn a_router_solicitation_asks_every_router_and_nobody_else() {
        let frame = build_router_solicitation(SRC_MAC, src_addr());

        let eth = super::super::ethernet::parse(&frame).unwrap();
        assert_eq!(
            eth.destination(),
            MacAddr::new(0x33, 0x33, 0x00, 0x00, 0x00, 0x02)
        );

        let packet = Ipv6Packet::new(eth.payload()).unwrap();
        assert_eq!(packet.get_destination(), ALL_ROUTERS);
        assert_eq!(packet.get_hop_limit(), 255);

        let solicit = RouterSolicitPacket::new(packet.payload()).unwrap();
        assert_eq!(solicit.get_icmpv6_type(), Icmpv6Types::RouterSolicit);
        assert_ne!(solicit.get_checksum(), 0);

        let options = solicit.get_options();
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].option_type, NdpOptionTypes::SourceLLAddr);
        assert_eq!(options[0].data, SRC_MAC.octets().to_vec());
    }
}
