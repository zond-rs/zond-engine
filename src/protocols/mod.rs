// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod arp;
pub mod dns;
pub mod ethernet;
pub mod icmp;
pub mod ip;
pub mod mdns;
pub mod ndp;
pub mod sizes;
pub mod tcp;
pub mod udp;

use crate::model::ip::range::{Ipv4Range, Ipv6Range};
use crate::model::ip::set::IpSet;
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

type Bytes = Vec<u8>;
type PacketIter = Box<dyn Iterator<Item = (Bytes, IpAddr)> + Send>;

/// Every first-attempt probe a sweep owes, in the order they should leave.
///
/// The two families are **interleaved rather than concatenated**, and that is
/// the whole point of the shape. Chained, all 254 ARP requests go out first and
/// the neighbor solicitations follow as one unbroken block at the tail - which
/// is exactly where they are least likely to be answered. Measured on a wifi
/// segment with `benches/ndp_pace.rs`: solicitations one millisecond apart
/// under the broadcast the ARP half is generating had **1 of 27** first
/// attempts answered, against 13 of 27 for the same addresses spaced out on a
/// quiet link. Every one of those unanswered first attempts costs either a host
/// or its round trip, because the retry that recovers it cannot be timed.
///
/// Spreading them evenly is what a scan can do about that without spending more
/// time: the solicitations end up separated by however many ARP requests the
/// ratio allows, at no cost in packets or duration to either family.
///
/// The all-nodes echo is deliberately not here. It is one probe on a schedule
/// of its own, repeated on an interval and timed by the identifier it carries,
/// which makes it the scanner's to own rather than an item in a queue.
pub fn eth_packet_iter(
    local_mac: &MacAddr,
    src_v4: &Option<Ipv4Addr>,
    link_local: &Option<Ipv6Addr>,
    ip_set: &IpSet,
) -> anyhow::Result<PacketIter> {
    let arp_iter = src_v4
        .as_ref()
        .map(|v4| create_arp_iter(local_mac, v4, ip_set))
        .transpose()?
        .into_iter()
        .flatten();

    // One solicitation per IPv6 target, the direct counterpart of the ARP
    // request above. Unlike the all-nodes echo this is not gated on sweeping:
    // it asks about one address, so a targeted run can send it without waking
    // the rest of the segment - which is what makes a targeted IPv6 scan
    // possible at all.
    let ndp_iter = link_local
        .as_ref()
        .map(|v6| create_ndp_iter(local_mac, v6, ip_set))
        .into_iter()
        .flatten();

    Ok(Box::new(Interleave::new(
        Box::new(arp_iter),
        ip_set.v4_len(),
        Box::new(ndp_iter),
        ip_set.v6_len(),
    )))
}

/// Draws from two probe streams in proportion to their lengths, so both are
/// spread across the whole sequence instead of one following the other.
///
/// The counts are the caller's because an iterator cannot be asked its length
/// without consuming it, and they only steer the ratio: whichever stream runs
/// out first, the other is drained in full, so no probe is ever dropped by a
/// count that turned out to be wrong.
struct Interleave {
    left: PacketIter,
    right: PacketIter,
    /// Positive when the left stream is ahead of its share, which is the
    /// moment to take from the right. Scaled by both lengths so the comparison
    /// is exact in integers rather than a drifting float ratio.
    credit: i128,
    left_len: i128,
    right_len: i128,
}

impl Interleave {
    fn new(left: PacketIter, left_len: u128, right: PacketIter, right_len: u128) -> Self {
        Self {
            left,
            right,
            credit: 0,
            left_len: left_len.min(i128::MAX as u128) as i128,
            right_len: right_len.min(i128::MAX as u128) as i128,
        }
    }
}

impl Iterator for Interleave {
    type Item = (Bytes, IpAddr);

    fn next(&mut self) -> Option<Self::Item> {
        // A stream with nothing left to spread against is simply drained.
        if self.left_len <= 0 || self.right_len <= 0 {
            return self.left.next().or_else(|| self.right.next());
        }

        if self.credit >= 0 {
            self.credit -= self.right_len;
            if let Some(item) = self.left.next() {
                return Some(item);
            }
        }

        self.credit += self.left_len;
        self.right.next().or_else(|| self.left.next())
    }
}

/// One neighbor solicitation per IPv6 address in `ip_set`.
///
/// Ranges are expanded the same way ARP's are, and bounded the same way: the
/// classifier refuses an IPv6 range too large to walk long before it reaches
/// here, so an unbounded expansion is not reachable through the scan path.
fn create_ndp_iter(local_mac: &MacAddr, src_addr: &Ipv6Addr, ip_set: &IpSet) -> PacketIter {
    let local_mac = *local_mac;
    let src_addr = *src_addr;
    let ranges: Vec<Ipv6Range> = ip_set.v6().to_vec();

    let iter = ranges
        .into_iter()
        .flat_map(|range| {
            let start: u128 = range.start_addr().into();
            let end: u128 = range.end_addr().into();
            (start..=end).map(Ipv6Addr::from)
        })
        .filter_map(move |target| {
            ndp::create_neighbor_solicitation(&local_mac, &src_addr, target)
                .ok()
                .map(|packet| (packet, IpAddr::V6(target)))
        });

    Box::new(iter)
}

pub fn create_arp_iter(
    local_mac: &MacAddr,
    src_ip: &Ipv4Addr,
    ip_set: &IpSet,
) -> anyhow::Result<PacketIter> {
    let local_mac = *local_mac;
    let src_ip = *src_ip;
    let dst_mac = MacAddr::broadcast();

    let ranges: Vec<Ipv4Range> = ip_set.v4().to_vec();

    let iter = ranges
        .into_iter()
        .flat_map(|range| {
            let start: u32 = range.start_addr().into();
            let end: u32 = range.end_addr().into();
            (start..=end).map(Ipv4Addr::from)
        })
        .map(move |dst_addr| {
            let packet = arp::create_packet(&local_mac, dst_mac, &src_ip, dst_addr)
                .expect("Failed to create ARP packet");

            (packet, IpAddr::V4(dst_addr))
        });

    Ok(Box::new(iter))
}

pub fn get_ip_addr_from_eth(frame: &EthernetPacket) -> anyhow::Result<IpAddr> {
    match frame.get_ethertype() {
        EtherTypes::Arp => Ok(IpAddr::V4(arp::get_ipv4_addr_from_eth(frame)?)),
        EtherTypes::Ipv4 => Ok(IpAddr::V4(ip::get_ipv4_addr_from_eth(frame)?)),
        EtherTypes::Ipv6 => Ok(IpAddr::V6(ip::get_ipv6_src_addr_from_eth(frame)?)),
        _ => Err(anyhow::anyhow!(
            "Unsupported EtherType: {:?}",
            frame.get_ethertype()
        )),
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

    /// Builds a stream of `count` probes tagged by family, so the interleaving
    /// can be read off the output.
    fn stream(count: u32, v6: bool) -> PacketIter {
        Box::new((0..count).map(move |i| {
            let ip = if v6 {
                IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, i as u16))
            } else {
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8))
            };
            (Vec::new(), ip)
        }))
    }

    fn interleaved(left: u32, right: u32) -> Vec<IpAddr> {
        Interleave::new(
            stream(left, false),
            left as u128,
            stream(right, true),
            right as u128,
        )
        .map(|(_, ip)| ip)
        .collect()
    }

    /// Nothing may be dropped or duplicated, whatever the ratio. The counts
    /// steer the spacing and nothing else: a probe lost to an arithmetic edge
    /// is an address reported as empty that was never asked.
    #[test]
    fn interleaving_emits_every_probe_exactly_once() {
        for (left, right) in [(254, 27), (27, 254), (1, 1), (0, 5), (5, 0), (0, 0), (7, 3)] {
            let out = interleaved(left, right);

            assert_eq!(out.len(), (left + right) as usize, "{left} and {right}");
            assert_eq!(
                out.iter().filter(|ip| ip.is_ipv4()).count(),
                left as usize,
                "{left} and {right}"
            );
        }
    }

    /// The point of interleaving: the smaller stream is spread across the whole
    /// sequence rather than bunched at either end.
    ///
    /// The bound is what the measurement asks for. Solicitations emitted
    /// back-to-back at the send interval had 1 of 27 first attempts answered on
    /// a real wifi segment; spacing them out is worth an order of magnitude, and
    /// spacing is exactly what a gap of one or two probes fails to buy. With 254
    /// ARP requests against 27 solicitations the even spacing is one every 9.4,
    /// so no gap should fall far below that.
    #[test]
    fn interleaving_spreads_the_smaller_stream_across_the_whole_sweep() {
        let out = interleaved(254, 27);

        let positions: Vec<usize> = out
            .iter()
            .enumerate()
            .filter(|(_, ip)| ip.is_ipv6())
            .map(|(i, _)| i)
            .collect();

        assert_eq!(positions.len(), 27);
        let smallest_gap = positions
            .windows(2)
            .map(|pair| pair[1] - pair[0])
            .min()
            .expect("more than one solicitation");
        assert!(
            smallest_gap >= 8,
            "solicitations {smallest_gap} apart is a burst, not a spread: {positions:?}"
        );
        assert!(
            positions.last().expect("a last solicitation") > &(out.len() - 20),
            "the stream should reach the end of the sweep, not finish early"
        );
    }
}
