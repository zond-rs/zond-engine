// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Neighbor Discovery (RFC 4861)
//!
//! IPv6's equivalent of ARP. An echo request to the all-nodes group is optional
//! to answer (Windows and many embedded stacks ignore it); a neighbor
//! solicitation is how IPv6 resolves link-layer addresses, so every conformant
//! neighbour replies. A solicitation also names one address, which lets a
//! targeted scan probe the host it was asked about and lets the retry ledger
//! track one outstanding probe per target, as it does for ARP.
//!
//! ## Two details that are fatal to get wrong
//!
//! The hop limit must be 255. RFC 4861 §7.1.1 requires a receiver to discard
//! any neighbor discovery message that arrived with less, since only 255 proves
//! no router forwarded it. This overrides the engine's on-link hop limit of 1;
//! getting it wrong makes every correct implementation ignore the probe.
//!
//! The destination is the target's solicited-node multicast group. Every host
//! joins the group derived from the low 24 bits of each of its addresses, so
//! the network card of almost every other neighbour filters the frame out in
//! hardware.

use crate::model::mac::MacAddr;
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
/// Formed from the low 24 bits of the address, so a neighbour whose addresses
/// end differently never sees the frame: its network card filters the
/// multicast MAC out.
///
/// Not unique: neighbours whose addresses share the last three octets share a
/// group, and the target address inside the message decides which answers.
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
/// A broadcast interrupts every device on the segment; this frame is discarded
/// in hardware by everything outside the group.
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
/// Includes the source link-layer address option so the neighbour can reply
/// directly; without it the neighbour would solicit us first.
pub fn build_neighbor_solicitation(
    src_mac: MacAddr,
    src_addr: Ipv6Addr,
    target: Ipv6Addr,
) -> Vec<u8> {
    let group = solicited_node_multicast(target);

    // Written out by hand: `craft::Icmpv6` only names the echo shape. Four
    // reserved bytes, the target address, then the source link-layer option.
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
        // RFC 4861 requires the four reserved bytes to be zero.
        rest_of_header: [0; 4],
        payload: body,
    };

    Packet::new()
        .push(Ethernet::new(src_mac, multicast_mac(group)).with_ethertype(EtherTypes::Ipv6.0))
        .push(Ipv6::new(src_addr, group).with_hop_limit(ip::HOP_LIMIT_NDP))
        .push(message)
        .build()
        .expect("a solicitation fits every length field it is counted by")
}

/// Builds a router solicitation: one packet that asks every router on the
/// segment to identify itself, RFC 4861 §4.1.
///
/// A router answers within half a second (§6.2.6); unsolicited advertisements
/// come on a timer of minutes, longer than any sweep runs.
///
/// Carries the source link-layer address option so the answer can come back
/// directly.
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
        .push(Ethernet::new(src_mac, multicast_mac(ALL_ROUTERS)).with_ethertype(EtherTypes::Ipv6.0))
        .push(Ipv6::new(src_addr, ALL_ROUTERS).with_hop_limit(ip::HOP_LIMIT_NDP))
        .push(message)
        .build()
        .expect("a router solicitation fits every length field it is counted by")
}

/// A neighbor advertisement, reduced to what discovery reads from one.
///
/// `#[non_exhaustive]`: RFC 4861 §4.4 puts three flags in the byte this reads
/// one of. The solicited flag, which tells an answer to our probe from a
/// neighbour announcing itself, would be added here.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Advertisement {
    /// The address being announced.
    /// Not always the frame's IPv6 source: a router proxying for another host
    /// answers on its behalf, and an unsolicited advertisement goes to all-nodes.
    /// The target keeps a reply attributed to the address it is about.
    pub target: Ipv6Addr,
    /// Whether the sender set the R flag, saying it forwards traffic for
    /// others (RFC 4861 §4.4).
    pub router: bool,
}

/// Reads `frame` as a neighbor advertisement, if it is one.
pub fn advertisement(frame: &Frame<'_>) -> Option<Advertisement> {
    advertisement_in(ipv6_payload(frame)?)
}

/// Reads `packet`, a bare IPv6 packet, as a neighbor advertisement, if it is
/// one.
///
/// The form a link with no Ethernet header delivers, such as a tunnel or PPP.
pub(crate) fn advertisement_in(packet: &[u8]) -> Option<Advertisement> {
    let packet = icmpv6(packet)?;

    let advert = NeighborAdvertPacket::new(packet.payload())?;
    if advert.get_icmpv6_type() != Icmpv6Types::NeighborAdvert {
        return None;
    }

    Some(Advertisement {
        target: advert.get_target_addr(),
        // The flag is believed only from a message that cannot have been forwarded
        // (RFC 4861 §7.1.2), so an off-link sender cannot claim the segment's
        // routing. Presence is not held to that check: the host is demonstrably
        // there even if its claim is dropped.
        router: advert.get_flags() & ROUTER_FLAG != 0
            && packet.get_hop_limit() == ip::HOP_LIMIT_NDP,
    })
}

/// Whether `frame` is a router advertisement, which its sender is only entitled
/// to send if it routes (RFC 4861 §4.2).
pub fn is_router_advertisement(frame: &Frame<'_>) -> bool {
    ipv6_payload(frame).is_some_and(is_router_advertisement_in)
}

/// Whether `packet`, a bare IPv6 packet, is a router advertisement.
///
/// Held to the hop limit the RFC requires (§6.1.2): an advertisement that
/// crossed a router did not come from the link it claims to serve.
pub(crate) fn is_router_advertisement_in(packet: &[u8]) -> bool {
    let Some(packet) = icmpv6(packet) else {
        return false;
    };

    packet
        .payload()
        .first()
        .is_some_and(|icmp_type| *icmp_type == Icmpv6Types::RouterAdvert.0)
        && packet.get_hop_limit() == ip::HOP_LIMIT_NDP
}

/// The IPv6 packet `frame` carries, if it carries one.
fn ipv6_payload<'a>(frame: &Frame<'a>) -> Option<&'a [u8]> {
    (frame.ethertype() == EtherTypes::Ipv6.0).then(|| frame.payload())
}

/// `packet` read as IPv6, if it is IPv6 carrying ICMPv6.
fn icmpv6(packet: &[u8]) -> Option<pnet_packet::ipv6::Ipv6Packet<'_>> {
    ip::ipv6_carrying_in(packet, IpNextHeaderProtocols::Icmpv6)
}

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

    const SRC_MAC: MacAddr = MacAddr::new(0x02, 0, 0, 0, 0, 0x01);

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

    /// Two addresses agreeing only in their last three octets share a group, so
    /// the target address inside the message decides who answers.
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

    /// RFC 4861 §7.1.1: a conformant neighbour discards a solicitation that did
    /// not arrive with a hop limit of 255, so a probe with the on-link hop limit
    /// of 1 would look like an empty segment.
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

    /// Every receiver discards a zero checksum, and it covers the IPv6
    /// pseudo-header.
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

    /// An advertisement with the flag byte and hop limit a real one arrives with.
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

        let eth = ethernet::build_header(SRC_MAC, SRC_MAC, EtherTypes::Ipv6.0);
        let ipv6 = ip::build_ipv6_header(
            target,
            src_addr(),
            message.len() as u16,
            IpNextHeaderProtocols::Icmpv6.0,
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

    /// Everything else is refused, including the solicitations neighbours send
    /// each other constantly, which would otherwise credit the probe with a host
    /// that never replied.
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

    /// The R flag says the neighbour forwards. The adjacent S (solicited) bit must
    /// not be read as it: every reply to the scan's own probe has S set.
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

    /// RFC 4861 §7.1.2: a message with a hop limit below 255 may have been
    /// forwarded, so its router claim is dropped. The address still counts, since
    /// the frame arrived.
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

    /// Only a router sends one, so the message type is the claim, held to the
    /// same hop limit.
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

    /// Routers listen on the all-routers group, and every conformant receiver
    /// discards a hop limit below 255 (RFC 4861 §6.1.1).
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
