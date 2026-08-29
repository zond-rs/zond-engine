// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # UDP datagrams
//!
//! The datagram a UDP port probe puts on the wire.
//!
//! Thinner than its TCP counterpart because UDP is thinner: there is no
//! handshake to correlate against, so every probe in a scan leaves from one
//! fixed source port and that port is the whole of the scan's identity on the
//! wire. What makes an open port answer at all is the payload, which is
//! [`payload`](crate::scanner::payload)'s business rather than this module's.

use std::net::IpAddr;

use crate::protocols::craft;
use crate::protocols::error::Result;

/// Builds a UDP datagram from `src_addr` to `dst_addr`, checksummed over the
/// IP pseudo-header.
///
/// The addresses are parameters because a UDP checksum covers them: it is
/// computed over a pseudo-header of source, destination, protocol, and length,
/// not over the datagram alone. Passing them mirrors
/// [`tcp::create_probe`](super::tcp::create_probe).
///
/// The checksum is optional on IPv4 but **mandatory on IPv6** - RFC 8200 §8.1
/// requires a receiver to discard a zero-checksum UDP datagram - so a v6 probe
/// built without one never reaches the port it is aimed at, and the scan reads
/// the resulting silence as `OpenFiltered`.
///
/// # Errors
///
/// [`FamilyMismatch`](crate::protocols::error::PacketError::FamilyMismatch)
/// when the addresses are of different families, and
/// [`TooLong`](crate::protocols::error::PacketError::TooLong) for a payload the
/// 16-bit length field cannot describe.
pub fn create_packet(
    src_addr: &IpAddr,
    dst_addr: &IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    create_packet_shaped(src_addr, dst_addr, src_port, dst_port, payload, None)
}

/// [`create_packet`], with `padding` random bytes appended to the datagram's
/// payload — the segment-level shaping an evasion profile applies to move a
/// probe off the fixed size of a bare header.
///
/// The padding follows the meaningful payload, so it is covered by the length
/// field and the checksum like any other bytes and an open port still reads the
/// request in front of it. `None` appends nothing and builds exactly what
/// [`create_packet`] does. See
/// [`craft::random_padding`] for why the bytes are
/// random.
///
/// # Errors
///
/// The same as [`create_packet`]: a
/// [`FamilyMismatch`](crate::protocols::error::PacketError::FamilyMismatch)
/// across address families, and a
/// [`TooLong`](crate::protocols::error::PacketError::TooLong) for a payload —
/// padding now counted — the 16-bit length field cannot describe.
pub fn create_packet_shaped(
    src_addr: &IpAddr,
    dst_addr: &IpAddr,
    src_port: u16,
    dst_port: u16,
    mut payload: Vec<u8>,
    padding: Option<u16>,
) -> Result<Vec<u8>> {
    if let Some(len) = padding {
        payload.extend(craft::random_padding(len));
    }
    craft::Udp::new(src_port, dst_port)
        .with_payload(payload)
        .to_bytes(Some((*src_addr, *dst_addr)))
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
    use crate::protocols::sizes::UDP_HDR_LEN;
    use pnet_packet::udp::{MutableUdpPacket, UdpPacket};

    /// The value RFC 768 substitutes for a computed checksum of zero, since
    /// zero in that field means "not computed".
    const CHECKSUM_NONE_SUBSTITUTE: u16 = 0xFFFF;
    use pnet_packet::Packet;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const V4_SRC: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
    const V4_DST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
    const V6_SRC: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 50));
    const V6_DST: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 200));

    /// Recomputes the checksum the way a receiver would: over the datagram with
    /// the field zeroed, against the same pseudo-header.
    fn expected_checksum(packet: &[u8], src: &IpAddr, dst: &IpAddr) -> u16 {
        let mut zeroed = packet.to_vec();
        MutableUdpPacket::new(&mut zeroed).unwrap().set_checksum(0);
        let zeroed = UdpPacket::new(&zeroed).unwrap();
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => pnet_packet::udp::ipv4_checksum(&zeroed, s, d),
            (IpAddr::V6(s), IpAddr::V6(d)) => pnet_packet::udp::ipv6_checksum(&zeroed, s, d),
            _ => unreachable!("mismatched families in test fixture"),
        }
    }

    #[test]
    fn header_fields_describe_the_datagram() {
        let packet = create_packet(&V4_SRC, &V4_DST, 40_000, 53, vec![1, 2, 3, 4]).unwrap();
        let udp = UdpPacket::new(&packet).unwrap();

        assert_eq!(udp.get_source(), 40_000);
        assert_eq!(udp.get_destination(), 53);
        assert_eq!(udp.get_length() as usize, UDP_HDR_LEN + 4);
        assert_eq!(udp.payload(), &[1, 2, 3, 4]);
    }

    #[test]
    fn checksum_verifies_against_the_ipv4_pseudo_header() {
        let packet = create_packet(&V4_SRC, &V4_DST, 40_000, 53, vec![]).unwrap();
        let checksum = UdpPacket::new(&packet).unwrap().get_checksum();

        assert_eq!(checksum, expected_checksum(&packet, &V4_SRC, &V4_DST));
        assert_ne!(checksum, 0);
    }

    /// RFC 8200 §8.1: an IPv6 receiver discards a zero-checksum UDP datagram,
    /// so a v6 probe without one never reaches the port it is aimed at.
    #[test]
    fn ipv6_datagram_carries_a_checksum() {
        let packet = create_packet(&V6_SRC, &V6_DST, 40_000, 53, vec![]).unwrap();
        let checksum = UdpPacket::new(&packet).unwrap().get_checksum();

        assert_eq!(checksum, expected_checksum(&packet, &V6_SRC, &V6_DST));
        assert_ne!(checksum, 0);
    }

    /// The two address families checksum over different pseudo-headers, so the
    /// same ports and payload must not produce the same value - that would mean
    /// one of the two was computed against the wrong one.
    #[test]
    fn each_address_family_checksums_over_its_own_pseudo_header() {
        let v4 = create_packet(&V4_SRC, &V4_DST, 40_000, 53, vec![]).unwrap();
        let v6 = create_packet(&V6_SRC, &V6_DST, 40_000, 53, vec![]).unwrap();

        assert_ne!(
            UdpPacket::new(&v4).unwrap().get_checksum(),
            UdpPacket::new(&v6).unwrap().get_checksum()
        );
    }

    /// Zero means "not computed", so a genuine zero goes out as 0xFFFF: the
    /// field is never left at zero. Rare, but a scan sends enough datagrams to
    /// reach it.
    #[test]
    fn a_computed_zero_checksum_is_sent_as_all_ones() {
        let mut exercised = false;
        for src_port in 1..=u16::MAX {
            let packet = create_packet(&V4_SRC, &V4_DST, src_port, 53, vec![]).unwrap();
            if expected_checksum(&packet, &V4_SRC, &V4_DST) == 0 {
                assert_eq!(
                    UdpPacket::new(&packet).unwrap().get_checksum(),
                    CHECKSUM_NONE_SUBSTITUTE
                );
                exercised = true;
                break;
            }
        }
        assert!(
            exercised,
            "no zero-checksum datagram in the port space to exercise the rule"
        );
    }

    #[test]
    fn mismatched_address_families_are_rejected() {
        assert!(create_packet(&V4_SRC, &V6_DST, 40_000, 53, vec![]).is_err());
    }

    /// Padding follows the meaningful payload, and both the length field and the
    /// checksum cover it. The baseline is the same datagram with `None`, which is
    /// how this also pins the inert default: unshaped, nothing is appended.
    ///
    /// A mutant that appended nothing fails the length; one that padded in front
    /// of the payload would displace the request an open port has to read; one
    /// that left the padding out of the checksum fails the recompute.
    #[test]
    fn padding_extends_the_datagram_and_is_covered() {
        let plain =
            create_packet_shaped(&V4_SRC, &V4_DST, 40_000, 53, vec![1, 2, 3, 4], None).unwrap();
        let padded =
            create_packet_shaped(&V4_SRC, &V4_DST, 40_000, 53, vec![1, 2, 3, 4], Some(16)).unwrap();
        let udp = UdpPacket::new(&padded).unwrap();

        assert_eq!(
            padded.len(),
            plain.len() + 16,
            "sixteen bytes were not appended"
        );
        assert_eq!(
            udp.get_length() as usize,
            padded.len(),
            "the length field does not count the padding"
        );
        assert_eq!(
            &udp.payload()[..4],
            &[1, 2, 3, 4],
            "the padding displaced the request an open port has to read"
        );
        assert_eq!(
            udp.get_checksum(),
            expected_checksum(&padded, &V4_SRC, &V4_DST),
            "the checksum does not cover the padding"
        );
    }
}
