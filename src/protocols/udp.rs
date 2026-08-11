// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::net::IpAddr;

use anyhow::Context;
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};

const UDP_HDR_LEN: usize = 8;

/// The value carried in place of a computed checksum of zero.
///
/// Zero in that field means "no checksum was computed" (RFC 768), so a genuine
/// result of zero has to be sent as its ones-complement equivalent instead.
/// Both encode the same arithmetic; only one of them is distinguishable from
/// "not computed".
const CHECKSUM_NONE_SUBSTITUTE: u16 = 0xFFFF;

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
pub fn create_packet(
    src_addr: &IpAddr,
    dst_addr: &IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    let total_len: usize = UDP_HDR_LEN + payload.len();
    let mut buffer: Vec<u8> = vec![0u8; total_len];
    {
        let mut udp: MutableUdpPacket =
            MutableUdpPacket::new(&mut buffer).context("creating udp packet")?;
        udp.set_source(src_port);
        udp.set_destination(dst_port);
        udp.set_length(total_len as u16);
        udp.set_payload(&payload);
        udp.set_checksum(0);

        let udp_packet: UdpPacket = udp.to_immutable();
        let checksum = match (src_addr, dst_addr) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                pnet::packet::udp::ipv4_checksum(&udp_packet, src, dst)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                pnet::packet::udp::ipv6_checksum(&udp_packet, src, dst)
            }
            _ => anyhow::bail!("IP version mismatch between {src_addr} and {dst_addr}"),
        };

        udp.set_checksum(if checksum == 0 {
            CHECKSUM_NONE_SUBSTITUTE
        } else {
            checksum
        });
    }
    Ok(buffer)
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
    use pnet::packet::Packet;
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
            (IpAddr::V4(s), IpAddr::V4(d)) => pnet::packet::udp::ipv4_checksum(&zeroed, s, d),
            (IpAddr::V6(s), IpAddr::V6(d)) => pnet::packet::udp::ipv6_checksum(&zeroed, s, d),
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
}
