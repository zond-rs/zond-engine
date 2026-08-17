// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # ICMP echo
//!
//! Ping, over both families, as complete Ethernet frames.
//!
//! ## What an echo buys that a solicitation cannot
//!
//! An echo is *optional* to answer, unlike the neighbor solicitation in
//! [`ndp`](super::ndp): Windows and many embedded stacks ignore it. What it
//! offers in exchange is a reply that can be **timed**. Both RFCs require a
//! reply to carry the request's identifier and sequence back unchanged, so a
//! scanner that remembers which values it sent knows which request an answer
//! belongs to. A solicitation, identical on the wire from one attempt to the
//! next, never can.
//!
//! The convention that makes those two fields useful: one identifier for the
//! whole scan, the sequence counting attempts. Then a matching identifier means
//! the reply is ours, and the sequence names which request it answers.
//!
//! ## One to everybody, or one to somebody
//!
//! [`create_all_nodes_echo_request_v6`] asks a whole segment at once and is
//! what a sweep sends. The unicast forms ask one host, which is what a targeted
//! run wants and what an IPv4 sweep has no alternative to, there being no
//! all-nodes group to ask.

use crate::protocols::craft::{Ethernet, Icmpv4, Icmpv6, Ipv4, Ipv6, Packet};
use crate::protocols::error::Result;
use crate::protocols::ip;
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::EtherTypes;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The link-layer and IPv6 addresses of the all-nodes group, which every IPv6
/// host on a segment joins (RFC 4291 §2.7.1).
const ALL_NODES_MAC: MacAddr = MacAddr(0x33, 0x33, 0, 0, 0, 1);
const ALL_NODES_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Builds the all-nodes echo request every IPv6 neighbour on the segment may
/// answer.
///
/// Sent with [`HOP_LIMIT_ON_LINK`](super::ip::HOP_LIMIT_ON_LINK), so a router
/// discards it rather than forwarding it and a sweep of one segment cannot leak
/// onto the next.
///
/// See the [module documentation](self) for what `identifier` and `sequence`
/// are for.
pub fn create_all_nodes_echo_request_v6(
    src_mac: &MacAddr,
    src_addr: &Ipv6Addr,
    identifier: u16,
    sequence: u16,
) -> Vec<u8> {
    echo_frame_v6(
        *src_mac,
        ALL_NODES_MAC,
        *src_addr,
        ALL_NODES_V6,
        ip::HOP_LIMIT_ON_LINK,
        identifier,
        sequence,
    )
}

/// Builds an echo request aimed at one IPv6 host.
///
/// The counterpart of [`create_all_nodes_echo_request_v6`] for a run that knows
/// which host it is asking, and so does not need to wake the rest of the
/// segment to ask it.
///
/// `hop_limit` is the caller's because the answer differs by where the target
/// is: [`HOP_LIMIT_ON_LINK`](super::ip::HOP_LIMIT_ON_LINK) for a neighbour, and
/// [`HOP_LIMIT_ROUTED`](super::ip::HOP_LIMIT_ROUTED) for anything past the
/// first router.
pub fn create_echo_request_v6(
    src_mac: &MacAddr,
    dst_mac: MacAddr,
    src_addr: &Ipv6Addr,
    dst_addr: Ipv6Addr,
    hop_limit: u8,
    identifier: u16,
    sequence: u16,
) -> Vec<u8> {
    echo_frame_v6(
        *src_mac, dst_mac, *src_addr, dst_addr, hop_limit, identifier, sequence,
    )
}

/// Builds an echo request aimed at one IPv4 host: an ordinary ping.
///
/// IPv4 has no all-nodes group to ask, so every echo it sends is a unicast one.
/// A sweep that wants to ping a range sends one of these per address.
pub fn create_echo_request_v4(
    src_mac: &MacAddr,
    dst_mac: MacAddr,
    src_addr: &Ipv4Addr,
    dst_addr: Ipv4Addr,
    identifier: u16,
    sequence: u16,
) -> Vec<u8> {
    Packet::new()
        .push(Ethernet::new(*src_mac, dst_mac).with_ethertype(EtherTypes::Ipv4))
        .push(Ipv4::new(*src_addr, dst_addr))
        .push(Icmpv4::echo_request(identifier, sequence))
        .build()
        // Infallible: an eight-byte message cannot overflow a length field, and
        // both addresses come from the same family by construction.
        .expect("an echo request fits every length field it is counted by")
}

/// The IPv6 half of both public builders above.
fn echo_frame_v6(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
    hop_limit: u8,
    identifier: u16,
    sequence: u16,
) -> Vec<u8> {
    Packet::new()
        .push(Ethernet::new(src_mac, dst_mac).with_ethertype(EtherTypes::Ipv6))
        .push(Ipv6::new(src_addr, dst_addr).with_hop_limit(hop_limit))
        .push(Icmpv6::echo_request(identifier, sequence))
        .build()
        .expect("an echo request fits every length field it is counted by")
}

/// The identifier and sequence an echo message carries, for either family.
///
/// Reads the four bytes after the checksum, which is where both RFCs put them.
/// A caller holding a captured reply uses this to find which of its own
/// requests was answered.
///
/// # Errors
///
/// [`PacketError::Truncated`](super::error::PacketError::Truncated) when the
/// message is too short to carry them.
pub fn echo_token(message: &[u8]) -> Result<(u16, u16)> {
    let head: &[u8; 8] = message.first_chunk().ok_or_else(|| {
        super::error::PacketError::truncated("an ICMP echo message", 8, message.len())
    })?;
    Ok((
        u16::from_be_bytes([head[4], head[5]]),
        u16::from_be_bytes([head[6], head[7]]),
    ))
}

/// Whichever unicast echo `dst_addr`'s family calls for.
///
/// A convenience for a caller holding an [`IpAddr`] rather than a decided
/// family, which is the ordinary case once targets have been parsed.
pub fn create_echo_request(
    src_mac: &MacAddr,
    dst_mac: MacAddr,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    hop_limit: u8,
    identifier: u16,
    sequence: u16,
) -> Result<Vec<u8>> {
    match (src_addr, dst_addr) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => Ok(create_echo_request_v4(
            src_mac, dst_mac, &src, dst, identifier, sequence,
        )),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Ok(create_echo_request_v6(
            src_mac, dst_mac, &src, dst, hop_limit, identifier, sequence,
        )),
        (src, dst) => Err(super::error::PacketError::FamilyMismatch { src, dst }),
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
    use pnet::packet::Packet as _;
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
    use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::ipv6::Ipv6Packet;

    const SRC_MAC: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 1);
    const DST_MAC: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 2);
    const ID: u16 = 0xBEEF;
    const SEQ: u16 = 7;

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().expect("a valid address")
    }

    /// The frame a sweep sends, checked end to end: it reaches the all-nodes
    /// group at the link layer and the IP layer both, and it does not leave the
    /// segment.
    #[test]
    fn the_all_nodes_request_is_addressed_to_the_whole_segment_and_stays_on_it() {
        let frame = create_all_nodes_echo_request_v6(&SRC_MAC, &v6("fe80::1"), ID, SEQ);

        let eth = EthernetPacket::new(&frame).expect("a frame");
        assert_eq!(eth.get_destination(), ALL_NODES_MAC);
        assert_eq!(eth.get_ethertype(), EtherTypes::Ipv6);

        let ip = Ipv6Packet::new(eth.payload()).expect("an IPv6 header");
        assert_eq!(ip.get_destination(), ALL_NODES_V6);
        assert_eq!(
            ip.get_hop_limit(),
            ip::HOP_LIMIT_ON_LINK,
            "a router must discard it rather than forward it"
        );

        let icmp = Icmpv6Packet::new(ip.payload()).expect("an ICMPv6 message");
        assert_eq!(icmp.get_icmpv6_type(), Icmpv6Types::EchoRequest);
        assert_ne!(icmp.get_checksum(), 0, "checksummed over the pseudo-header");
    }

    /// IPv4 had no echo at all, so a scan could not ping. The frame has to be a
    /// real one: right ethertype, right protocol number, a checksummed header
    /// and a checksummed message.
    #[test]
    fn an_ipv4_echo_request_is_a_complete_pingable_frame() {
        let frame = create_echo_request_v4(
            &SRC_MAC,
            DST_MAC,
            &Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 9),
            ID,
            SEQ,
        );

        let eth = EthernetPacket::new(&frame).expect("a frame");
        assert_eq!(eth.get_ethertype(), EtherTypes::Ipv4);

        let ip = Ipv4Packet::new(eth.payload()).expect("an IPv4 header");
        assert_eq!(
            ip.get_next_level_protocol(),
            pnet::packet::ip::IpNextHeaderProtocols::Icmp
        );
        assert_eq!(ip.get_total_length() as usize, eth.payload().len());
        assert_ne!(ip.get_checksum(), 0);

        let icmp = IcmpPacket::new(ip.payload()).expect("an ICMP message");
        assert_eq!(icmp.get_icmp_type(), IcmpTypes::EchoRequest);
        assert_ne!(icmp.get_checksum(), 0);
    }

    /// Both families put the identifier and sequence in the same four bytes, so
    /// one reader serves both. Without them an echo reply proves only that its
    /// sender exists; with them it also says which question was asked.
    #[test]
    fn an_echo_carries_back_the_token_that_names_the_request() {
        let v4 = create_echo_request_v4(
            &SRC_MAC,
            DST_MAC,
            &Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 9),
            ID,
            SEQ,
        );
        let v4_message = &v4[EthernetPacket::minimum_packet_size() + 20..];
        assert_eq!(echo_token(v4_message).expect("a token"), (ID, SEQ));

        let v6_frame = create_echo_request_v6(
            &SRC_MAC,
            DST_MAC,
            &v6("fe80::1"),
            v6("fe80::2"),
            ip::HOP_LIMIT_ON_LINK,
            ID,
            SEQ,
        );
        let v6_message = &v6_frame[EthernetPacket::minimum_packet_size() + 40..];
        assert_eq!(echo_token(v6_message).expect("a token"), (ID, SEQ));
    }

    /// A unicast request goes to the host it names rather than to the segment,
    /// which is what lets a targeted scan probe one address without waking
    /// every neighbour.
    #[test]
    fn a_unicast_request_wakes_only_the_host_it_names() {
        let frame = create_echo_request_v6(
            &SRC_MAC,
            DST_MAC,
            &v6("fe80::1"),
            v6("fe80::2"),
            ip::HOP_LIMIT_ON_LINK,
            ID,
            SEQ,
        );

        let eth = EthernetPacket::new(&frame).expect("a frame");
        assert_eq!(eth.get_destination(), DST_MAC);
        assert_ne!(eth.get_destination(), ALL_NODES_MAC);
        assert_eq!(
            Ipv6Packet::new(eth.payload())
                .expect("an IPv6 header")
                .get_destination(),
            v6("fe80::2")
        );
    }

    /// The family-dispatching form has to agree with the two it dispatches to,
    /// or a caller holding an `IpAddr` gets a different packet than one that
    /// had already decided.
    #[test]
    fn the_dispatching_form_builds_what_the_family_specific_ones_do() {
        let v4 = create_echo_request(
            &SRC_MAC,
            DST_MAC,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
            ip::HOP_LIMIT_ROUTED,
            ID,
            SEQ,
        )
        .expect("one family");

        let direct = create_echo_request_v4(
            &SRC_MAC,
            DST_MAC,
            &Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 9),
            ID,
            SEQ,
        );

        // Compared field by field rather than byte by byte: the identification
        // is random per packet and the header checksum covers it, so two
        // correct frames differ in four bytes by design.
        let read = |frame: &[u8]| {
            let eth = EthernetPacket::new(frame).expect("a frame");
            let ip = Ipv4Packet::new(eth.payload()).expect("a header");
            (
                eth.get_destination(),
                eth.get_ethertype(),
                ip.get_source(),
                ip.get_destination(),
                ip.get_ttl(),
                ip.get_next_level_protocol(),
                ip.payload().to_vec(),
            )
        };
        assert_eq!(read(&v4), read(&direct));

        let mismatched = create_echo_request(
            &SRC_MAC,
            DST_MAC,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6(v6("2001:db8::1")),
            ip::HOP_LIMIT_ROUTED,
            ID,
            SEQ,
        );
        assert!(mismatched.is_err(), "two families cannot make one packet");
    }
}
