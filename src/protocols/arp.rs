// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Address resolution
//!
//! ARP requests, and the address a reply claims.
//!
//! The cheapest and most informative probe this engine sends. A neighbour that
//! answers proves it is there, and it answers with its MAC, which is the one
//! identifier a routed probe can never learn. Every conformant IPv4 host
//! replies, whatever it thinks of being scanned, because ignoring ARP means its
//! own router cannot reach it either.

use crate::protocols::craft::{Arp, Ethernet, Packet};
use crate::protocols::error::{PacketError, Result};
use crate::protocols::ethernet::Frame;
use crate::protocols::sizes::{ARP_LEN, MIN_ETH_FRAME_NO_FCS};
use pnet::datalink::MacAddr;
use pnet::packet::arp::ArpPacket;
use std::net::Ipv4Addr;

/// Builds the broadcast ARP request a sweep sends, asking who holds
/// `dst_addr`.
///
/// The frame goes to broadcast, because that is what a request is: the whole
/// point is that the holder of the address is not yet known. The request's own
/// target hardware address is left zero, which RFC 826 expects and every
/// ordinary stack sends, so the probe looks like any other on the segment.
///
/// Padded to [`MIN_ETH_FRAME_NO_FCS`]. A frame shorter than that is treated as
/// a collision fragment and discarded, so an unpadded request is not a slow
/// probe but an invisible one.
///
/// Infallible: nothing here is derived from a length.
pub fn create_request(src_mac: &MacAddr, src_addr: &Ipv4Addr, dst_addr: Ipv4Addr) -> Vec<u8> {
    frame(
        *src_mac,
        MacAddr::broadcast(),
        Arp::request(*src_mac, *src_addr, dst_addr),
    )
}

/// Builds an ARP request aimed at one host rather than at the segment.
///
/// What validates a cache entry: the holder of `dst_addr` is believed to be
/// `dst_mac`, and this asks it directly. Every other neighbour's hardware
/// discards the frame, so it costs the segment nothing.
///
/// Unreachable through [`create_request`] on purpose. The two differ in who
/// sees the frame, which is a decision worth making by choosing a function
/// rather than by passing a different argument to one.
pub fn create_unicast_request(
    src_mac: &MacAddr,
    dst_mac: MacAddr,
    src_addr: &Ipv4Addr,
    dst_addr: Ipv4Addr,
) -> Vec<u8> {
    let mut request = Arp::request(*src_mac, *src_addr, dst_addr);
    // Known here, unlike in a broadcast request, so it is worth stating: a
    // host that has moved answers from a different address and the mismatch
    // is what says the entry was stale.
    request.target_hw_addr = dst_mac;
    frame(*src_mac, dst_mac, request)
}

/// Frames `packet` and pads it to the shortest frame a segment will carry.
fn frame(src_mac: MacAddr, dst_mac: MacAddr, packet: Arp) -> Vec<u8> {
    let mut bytes = Packet::new()
        .push(Ethernet::new(src_mac, dst_mac))
        .push(packet)
        .build()
        .expect("an ARP frame has no length field to overflow");
    bytes.resize(MIN_ETH_FRAME_NO_FCS, 0u8);
    bytes
}

/// The address the sender of an ARP frame claims to hold.
///
/// # Errors
///
/// [`PacketError::Truncated`] when the frame carries too few bytes to be an
/// ARP packet.
pub fn sender_address(eth_packet: &Frame<'_>) -> Result<Ipv4Addr> {
    let arp_packet = ArpPacket::new(eth_packet.payload()).ok_or_else(|| {
        PacketError::truncated("an ARP packet", ARP_LEN, eth_packet.payload().len())
    })?;
    Ok(arp_packet.get_sender_proto_addr())
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
    use pnet::packet::arp::ArpHardwareTypes;
    use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
    use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
    use pnet::util::MacAddr;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;

    const ETH_HDR_LEN: usize = 14;
    const ARP_LEN: usize = 28;

    fn build_mock_arp_packet(sender_ip: Ipv4Addr, payload_size: usize) -> Vec<u8> {
        let mut eth_buffer = vec![0u8; ETH_HDR_LEN];
        {
            let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buffer).unwrap();
            eth_pkt.set_destination(MacAddr::broadcast());
            eth_pkt.set_source(MacAddr::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06));
            eth_pkt.set_ethertype(EtherTypes::Arp);
        }

        let mut arp_buffer = vec![0u8; payload_size];

        if payload_size >= ARP_LEN {
            let mut arp_pkt = MutableArpPacket::new(&mut arp_buffer[..ARP_LEN]).unwrap();

            arp_pkt.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_pkt.set_protocol_type(EtherTypes::Ipv4);
            arp_pkt.set_hw_addr_len(6);
            arp_pkt.set_proto_addr_len(4);
            arp_pkt.set_operation(ArpOperations::Reply);
            arp_pkt.set_sender_hw_addr(MacAddr::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06));
            arp_pkt.set_sender_proto_addr(sender_ip);
            arp_pkt.set_target_hw_addr(MacAddr::zero());
            arp_pkt.set_target_proto_addr(Ipv4Addr::new(192, 168, 1, 1));
        }

        [eth_buffer, arp_buffer].concat()
    }

    /// Every field of the request a sweep sends, including the padding: a
    /// frame under sixty bytes is discarded as a collision fragment, so an
    /// unpadded request is invisible rather than merely small.
    #[test]
    fn a_broadcast_request_asks_the_segment_and_names_nobody() {
        let src_mac = MacAddr::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        let src_addr = Ipv4Addr::new(192, 168, 1, 10);
        let dst_addr = Ipv4Addr::new(192, 168, 1, 1);

        let buffer = create_request(&src_mac, &src_addr, dst_addr);
        assert_eq!(buffer.len(), MIN_ETH_FRAME_NO_FCS);

        let eth_packet =
            super::super::ethernet::parse(&buffer).expect("Failed to parse Ethernet packet");
        assert_eq!(eth_packet.destination(), MacAddr::broadcast());
        assert_eq!(eth_packet.source(), src_mac);
        assert_eq!(eth_packet.ethertype(), EtherTypes::Arp);

        let arp_payload = eth_packet.payload();
        assert!(arp_payload.len() >= ARP_LEN);

        let arp_packet = ArpPacket::new(arp_payload).expect("Failed to parse ARP packet");
        assert_eq!(arp_packet.get_operation(), ArpOperations::Request);
        assert_eq!(arp_packet.get_hardware_type(), ArpHardwareTypes::Ethernet);
        assert_eq!(arp_packet.get_protocol_type(), EtherTypes::Ipv4);
        assert_eq!(arp_packet.get_hw_addr_len(), 6);
        assert_eq!(arp_packet.get_proto_addr_len(), 4);
        assert_eq!(arp_packet.get_sender_hw_addr(), src_mac);
        assert_eq!(arp_packet.get_sender_proto_addr(), src_addr);
        assert_eq!(
            arp_packet.get_target_hw_addr(),
            MacAddr::zero(),
            "undefined in a request, and zero is what every ordinary stack sends"
        );
        assert_eq!(arp_packet.get_target_proto_addr(), dst_addr);
    }

    /// The two requests differ in who sees the frame, which is the whole
    /// reason they are separate functions rather than one with an argument.
    /// Written as an argument, the caller that meant broadcast and the caller
    /// that meant unicast passed different values into the same field and
    /// neither got what they meant.
    #[test]
    fn a_unicast_request_reaches_one_host_and_a_broadcast_one_reaches_all() {
        let src_mac = MacAddr::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        let dst_mac = MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        let src_addr = Ipv4Addr::new(192, 168, 1, 10);
        let dst_addr = Ipv4Addr::new(192, 168, 1, 1);

        let unicast = create_unicast_request(&src_mac, dst_mac, &src_addr, dst_addr);
        let eth = super::super::ethernet::parse(&unicast).expect("a frame");
        assert_eq!(eth.destination(), dst_mac, "only that host's card wakes");

        let arp = ArpPacket::new(eth.payload()).expect("an ARP packet");
        assert_eq!(arp.get_operation(), ArpOperations::Request);
        assert_eq!(
            arp.get_target_hw_addr(),
            dst_mac,
            "the entry being validated is named, so a host that moved is visible"
        );
        assert_eq!(arp.get_target_proto_addr(), dst_addr);
    }

    /// The address an ARP frame is credited to, read through the dispatcher
    /// the receive loop actually calls rather than through a copy of it.
    ///
    /// These used to exercise a reimplementation of `source_address` that
    /// lived in this test module, so they passed whatever the real one did.
    #[test]
    fn a_well_formed_frame_is_credited_to_its_sender() {
        let expected = Ipv4Addr::new(192, 168, 1, 123);
        let buffer = build_mock_arp_packet(expected, ARP_LEN);
        let parsed = super::super::ethernet::parse(&buffer).expect("a frame");

        assert_eq!(
            crate::protocols::source_address(&parsed).expect("an ARP sender"),
            IpAddr::V4(expected)
        );
    }

    /// A frame cut short of an ARP packet credits nobody. Reading the sender
    /// address out of whatever bytes happened to follow would attribute a
    /// finding to an address nothing sent.
    #[test]
    fn a_truncated_frame_credits_nobody() {
        let buffer = build_mock_arp_packet(Ipv4Addr::UNSPECIFIED, 10);
        let parsed = super::super::ethernet::parse(&buffer).expect("a frame");

        assert!(matches!(
            crate::protocols::source_address(&parsed),
            Err(PacketError::Truncated { got: 10, .. })
        ));
    }

    /// An ethertype this module does not read is the ordinary case under
    /// promiscuous capture, not a fault, and it is reported as itself so a
    /// caller can tell it from a frame that arrived broken.
    #[test]
    fn a_frame_of_another_kind_is_reported_as_unread_rather_than_broken() {
        let mut buffer = build_mock_arp_packet(Ipv4Addr::UNSPECIFIED, 20);
        MutableEthernetPacket::new(&mut buffer)
            .expect("a frame")
            .set_ethertype(EtherTypes::Ipv4);
        let parsed = super::super::ethernet::parse(&buffer).expect("a frame");

        // Ethertype IPv4 with twenty bytes behind it parses as an IPv4 header,
        // so this reads a source rather than refusing: the dispatcher covers
        // more than ARP.
        assert!(crate::protocols::source_address(&parsed).is_ok());

        MutableEthernetPacket::new(&mut buffer)
            .expect("a frame")
            .set_ethertype(pnet::packet::ethernet::EtherType(0x88cc));
        let parsed = super::super::ethernet::parse(&buffer).expect("a frame");
        assert!(matches!(
            crate::protocols::source_address(&parsed),
            Err(PacketError::UnsupportedEtherType(0x88cc))
        ));
    }
}
