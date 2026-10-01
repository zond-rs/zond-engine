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
//! The cheapest and most informative probe this engine sends: a neighbour that
//! answers proves it is there and gives its MAC, which a routed probe cannot
//! learn. Every conformant IPv4 host replies, since ignoring ARP would cut it
//! off from its own router.

use crate::model::mac::MacAddr;
use crate::protocols::craft::{Arp, Ethernet, Packet};
use crate::protocols::error::{PacketError, Result};
use crate::protocols::ethernet::Frame;
use crate::protocols::sizes::{ARP_LEN, MIN_ETH_FRAME_NO_FCS};
use pnet_packet::arp::ArpPacket;
use pnet_packet::ethernet::EtherTypes;
use std::net::Ipv4Addr;

/// How long an IPv4 address is, as ARP's own `proto_addr_len` field counts it.
const PROTO_ADDR_LEN_V4: u8 = 4;

/// Builds the broadcast ARP request a sweep sends, asking who holds
/// `dst_addr`.
///
/// The target hardware address is left zero, as RFC 826 expects and every
/// ordinary stack sends, so the probe looks like any other on the segment.
///
/// Padded to [`MIN_ETH_FRAME_NO_FCS`], since a shorter frame is discarded as a
/// collision fragment.
pub fn build_request(src_mac: MacAddr, src_addr: Ipv4Addr, dst_addr: Ipv4Addr) -> Vec<u8> {
    frame(
        src_mac,
        MacAddr::BROADCAST,
        Arp::request(src_mac, src_addr, dst_addr),
    )
}

/// Builds an ARP request sent to `dst_mac` only, to validate a cache entry
/// that says `dst_mac` holds `dst_addr`. Every other neighbour's hardware
/// discards the frame.
pub fn build_unicast_request(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
) -> Vec<u8> {
    // Naming the target makes a host that moved visible: it answers from a
    // different address and the mismatch says the entry was stale.
    let request = Arp::request(src_mac, src_addr, dst_addr).with_target_hw_addr(dst_mac);
    frame(src_mac, dst_mac, request)
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
/// Read only when the packet declares IPv4 protocol addresses. ARP's protocol
/// type and address lengths come off the wire, and a packet with sixteen-byte
/// protocol addresses keeps its sender's address elsewhere; reading the fixed
/// offset anyway would credit four bytes out of the middle of another address.
///
/// # Errors
///
/// [`PacketError::Truncated`] when the frame carries too few bytes to be an
/// ARP packet, and [`PacketError::Unreadable`] when it is an ARP packet about
/// something other than IPv4 over Ethernet.
pub fn sender_address(frame: &Frame<'_>) -> Result<Ipv4Addr> {
    let arp = ArpPacket::new(frame.payload())
        .ok_or_else(|| PacketError::truncated("an ARP packet", ARP_LEN, frame.payload().len()))?;

    if arp.get_protocol_type() != EtherTypes::Ipv4 || arp.get_proto_addr_len() != PROTO_ADDR_LEN_V4
    {
        return Err(PacketError::unreadable(
            "an ARP packet",
            format_args!(
                "it carries protocol {:#06x} in {}-byte addresses, not IPv4 in {PROTO_ADDR_LEN_V4}",
                arp.get_protocol_type().0,
                arp.get_proto_addr_len()
            ),
        ));
    }

    Ok(arp.get_sender_proto_addr())
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
    use crate::model::mac::MacAddr;
    use crate::protocols::mac::{IntoCoreMac, IntoPnetMac};
    use crate::protocols::sizes::ETH_HDR_LEN;
    use pnet_packet::arp::ArpHardwareTypes;
    use pnet_packet::arp::{ArpOperations, MutableArpPacket};
    use pnet_packet::ethernet::MutableEthernetPacket;
    use std::net::IpAddr;

    fn build_mock_arp_packet(sender_ip: Ipv4Addr, payload_size: usize) -> Vec<u8> {
        let mut eth_buffer = vec![0u8; ETH_HDR_LEN];
        {
            let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buffer).unwrap();
            eth_pkt.set_destination(MacAddr::BROADCAST.into_pnet());
            eth_pkt.set_source(MacAddr::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06).into_pnet());
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
            arp_pkt
                .set_sender_hw_addr(MacAddr::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06).into_pnet());
            arp_pkt.set_sender_proto_addr(sender_ip);
            arp_pkt.set_target_hw_addr(MacAddr::ZERO.into_pnet());
            arp_pkt.set_target_proto_addr(Ipv4Addr::new(192, 0, 2, 1));
        }

        [eth_buffer, arp_buffer].concat()
    }

    /// Every field of the request a sweep sends, including the padding to sixty
    /// bytes.
    #[test]
    fn a_broadcast_request_asks_the_segment_and_names_nobody() {
        let src_mac = MacAddr::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        let src_addr = Ipv4Addr::new(192, 0, 2, 10);
        let dst_addr = Ipv4Addr::new(192, 0, 2, 1);

        let buffer = build_request(src_mac, src_addr, dst_addr);
        assert_eq!(buffer.len(), MIN_ETH_FRAME_NO_FCS);

        let eth_packet =
            super::super::ethernet::parse(&buffer).expect("Failed to parse Ethernet packet");
        assert_eq!(eth_packet.destination(), MacAddr::BROADCAST);
        assert_eq!(eth_packet.source(), src_mac);
        assert_eq!(eth_packet.ethertype(), EtherTypes::Arp.0);

        let arp_payload = eth_packet.payload();
        assert!(arp_payload.len() >= ARP_LEN);

        let arp_packet = ArpPacket::new(arp_payload).expect("Failed to parse ARP packet");
        assert_eq!(arp_packet.get_operation(), ArpOperations::Request);
        assert_eq!(arp_packet.get_hardware_type(), ArpHardwareTypes::Ethernet);
        assert_eq!(arp_packet.get_protocol_type(), EtherTypes::Ipv4);
        assert_eq!(arp_packet.get_hw_addr_len(), 6);
        assert_eq!(arp_packet.get_proto_addr_len(), 4);
        assert_eq!(arp_packet.get_sender_hw_addr().into_core(), src_mac);
        assert_eq!(arp_packet.get_sender_proto_addr(), src_addr);
        assert_eq!(
            arp_packet.get_target_hw_addr().into_core(),
            MacAddr::ZERO,
            "undefined in a request, and zero is what every ordinary stack sends"
        );
        assert_eq!(arp_packet.get_target_proto_addr(), dst_addr);
    }

    /// The unicast request goes to one MAC and names it as the target.
    #[test]
    fn a_unicast_request_reaches_one_host_and_a_broadcast_one_reaches_all() {
        let src_mac = MacAddr::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        let dst_mac = MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        let src_addr = Ipv4Addr::new(192, 0, 2, 10);
        let dst_addr = Ipv4Addr::new(192, 0, 2, 1);

        let unicast = build_unicast_request(src_mac, dst_mac, src_addr, dst_addr);
        let eth = super::super::ethernet::parse(&unicast).expect("a frame");
        assert_eq!(eth.destination(), dst_mac, "only that host's card wakes");

        let arp = ArpPacket::new(eth.payload()).expect("an ARP packet");
        assert_eq!(arp.get_operation(), ArpOperations::Request);
        assert_eq!(
            arp.get_target_hw_addr().into_core(),
            dst_mac,
            "the entry being validated is named, so a host that moved is visible"
        );
        assert_eq!(arp.get_target_proto_addr(), dst_addr);
    }

    /// The address an ARP frame is credited to, read through the dispatcher the
    /// receive loop calls.
    #[test]
    fn a_well_formed_frame_is_credited_to_its_sender() {
        let expected = Ipv4Addr::new(192, 0, 2, 123);
        let buffer = build_mock_arp_packet(expected, ARP_LEN);
        let parsed = super::super::ethernet::parse(&buffer).expect("a frame");

        assert_eq!(
            crate::protocols::source_address(&parsed).expect("an ARP sender"),
            IpAddr::V4(expected)
        );
    }

    /// A frame cut short of an ARP packet credits nobody.
    #[test]
    fn a_truncated_frame_credits_nobody() {
        let buffer = build_mock_arp_packet(Ipv4Addr::UNSPECIFIED, 10);
        let parsed = super::super::ethernet::parse(&buffer).expect("a frame");

        assert!(matches!(
            crate::protocols::source_address(&parsed),
            Err(PacketError::Truncated { got: 10, .. })
        ));
    }

    /// A packet declaring sixteen-byte protocol addresses keeps its sender's
    /// address where the IPv4 offsets do not reach, and credits nobody.
    #[test]
    fn an_arp_packet_about_another_protocol_credits_nobody() {
        let mut buffer = build_mock_arp_packet(Ipv4Addr::new(198, 51, 100, 1), ARP_LEN);
        {
            let mut arp = MutableArpPacket::new(&mut buffer[ETH_HDR_LEN..]).expect("an ARP packet");
            arp.set_protocol_type(EtherTypes::Ipv6);
            arp.set_proto_addr_len(16);
        }
        let parsed = super::super::ethernet::parse(&buffer).expect("a frame");

        assert!(matches!(
            crate::protocols::source_address(&parsed),
            Err(PacketError::Unreadable { .. })
        ));

        // The same frame with its own fields telling the truth is still read.
        let honest = build_mock_arp_packet(Ipv4Addr::new(198, 51, 100, 1), ARP_LEN);
        let parsed = super::super::ethernet::parse(&honest).expect("a frame");
        assert_eq!(
            crate::protocols::source_address(&parsed).expect("an ARP sender"),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))
        );
    }

    /// An unread EtherType is reported as itself, so a caller can tell it from
    /// a frame that arrived broken.
    #[test]
    fn a_frame_of_another_kind_is_reported_as_unread_rather_than_broken() {
        let mut buffer = build_mock_arp_packet(Ipv4Addr::UNSPECIFIED, 20);
        MutableEthernetPacket::new(&mut buffer)
            .expect("a frame")
            .set_ethertype(EtherTypes::Ipv4);
        let parsed = super::super::ethernet::parse(&buffer).expect("a frame");

        // EtherType IPv4 with twenty bytes behind it parses as an IPv4 header.
        assert!(crate::protocols::source_address(&parsed).is_ok());

        MutableEthernetPacket::new(&mut buffer)
            .expect("a frame")
            .set_ethertype(pnet_packet::ethernet::EtherType(0x88cc));
        let parsed = super::super::ethernet::parse(&buffer).expect("a frame");
        assert!(matches!(
            crate::protocols::source_address(&parsed),
            Err(PacketError::UnsupportedEtherType(0x88cc))
        ));
    }
}
