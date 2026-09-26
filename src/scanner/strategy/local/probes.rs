// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a local sweep asks first, and in what order
//!
//! One ARP request per IPv4 target and one neighbor solicitation per IPv6
//! target, as a single stream in the order they should leave.
//!
//! This is the sweep's *first attempt* at every address. Repeats are the
//! [`ProbeLedger`](crate::scanner::pacing::retry::ProbeLedger)'s business and
//! leave through the same paced ticker; the all-nodes echo is on a schedule of
//! its own and belongs to the scanner. What is decided here is only which probe
//! is next.
//!
//! ## Why the order is a decision at all
//!
//! It lives beside the scanner rather than beside the packet builders because
//! it is not a fact about ARP or about neighbor discovery. It is a measurement
//! about a contended link, and the packets are only what the measurement is
//! made of.
//!
//! Within each family the addresses leave in the walk a seeded scan names,
//! the order every other phase of the scan asks in, rather than in address
//! order, which is the signature a correlating sensor keys on. See
//! [`WalkOrder`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::model::mac::MacAddr;

use crate::model::ip::range::{Ipv4Range, Ipv6Range};
use crate::model::ip::set::IpSet;
use crate::protocols::{arp, ndp};
use crate::scanner::dispatcher::WalkOrder;

/// One built frame, ready for the link layer.
type Bytes = Vec<u8>;

/// The stream of first-attempt probes a sweep works through, each frame paired
/// with the address it asks about.
pub(super) type PacketIter = Box<dyn Iterator<Item = (Bytes, IpAddr)> + Send>;

/// Every first-attempt probe a sweep owes, in the order they should leave:
/// each family in the order `walk` names, or in the set's own without one.
///
/// The two families are **interleaved rather than concatenated**, and that is
/// the whole point of the shape. Chained, all 254 ARP requests go out first and
/// the neighbor solicitations follow as one unbroken block at the tail - which
/// is exactly where they are least likely to be answered. Measured on a wifi
/// segment: solicitations one millisecond apart
/// under the broadcast the ARP half is generating had **1 of 27** first
/// attempts answered, against 13 of 27 for the same addresses spaced out on a
/// quiet link. Every one of those unanswered first attempts costs either a host
/// or its round trip, because the retry that recovers it cannot be timed.
///
/// Spreading them evenly is what a scan can do about that without spending more
/// time: the solicitations end up separated by however many ARP requests the
/// ratio allows, at no cost in packets or duration to either family.
///
/// The all-nodes echo is not here. It is one probe on a schedule
/// of its own, repeated on an interval and timed by the identifier it carries,
/// which makes it the scanner's to own rather than an item in a queue.
pub fn eth_packet_iter(
    local_mac: &MacAddr,
    src_v4: &Option<Ipv4Addr>,
    link_local: &Option<Ipv6Addr>,
    ip_set: &IpSet,
    walk: Option<&WalkOrder>,
) -> PacketIter {
    let arp_iter = src_v4
        .as_ref()
        .map(|v4| build_arp_iter(local_mac, v4, ip_set, walk))
        .into_iter()
        .flatten();

    // One solicitation per IPv6 target, the direct counterpart of the ARP
    // request above. Unlike the all-nodes echo this is not gated on sweeping:
    // it asks about one address, so a targeted run can send it without waking
    // the rest of the segment - which is what makes a targeted IPv6 scan
    // possible at all.
    let ndp_iter = link_local
        .as_ref()
        .map(|v6| build_ndp_iter(local_mac, v6, ip_set, walk))
        .into_iter()
        .flatten();

    Box::new(Interleave::new(
        Box::new(arp_iter),
        ip_set.v4_len(),
        Box::new(ndp_iter),
        ip_set.v6_len(),
    ))
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
/// Ranges are expanded the same way ARP's are, and bounded the same way: a
/// range too large to walk is withheld from the step's targets before a scanner
/// is built from it, so an unbounded expansion is not reachable through the
/// scan path. That happens in two places, because a range reaches this function
/// by two routes: `map_ips_to_interfaces` refuses an off-link one, and
/// `DiscoveryPlan::build` withholds an on-link one.
fn build_ndp_iter(
    local_mac: &MacAddr,
    src_addr: &Ipv6Addr,
    ip_set: &IpSet,
    walk: Option<&WalkOrder>,
) -> PacketIter {
    let local_mac = *local_mac;
    let src_addr = *src_addr;
    let ranges: Vec<Ipv6Range> = ip_set.v6().to_vec();

    let targets = ranges.into_iter().flat_map(|range| {
        let start: u128 = range.start_addr().into();
        let end: u128 = range.end_addr().into();
        (start..=end).map(Ipv6Addr::from)
    });
    let held = ip_set.clone();
    let owed = move |address| match address {
        IpAddr::V6(v6) if held.contains(&address) => Some(v6),
        _ => None,
    };
    let iter = in_order(targets, ip_set.v6_len(), walk, owed).map(move |target| {
        let packet = ndp::build_neighbor_solicitation(local_mac, src_addr, target);
        (packet, IpAddr::V6(target))
    });

    Box::new(iter)
}

/// One ARP request per IPv4 address in `ip_set`.
pub fn build_arp_iter(
    local_mac: &MacAddr,
    src_ip: &Ipv4Addr,
    ip_set: &IpSet,
    walk: Option<&WalkOrder>,
) -> PacketIter {
    let local_mac = *local_mac;
    let src_ip = *src_ip;

    let ranges: Vec<Ipv4Range> = ip_set.v4().to_vec();

    let targets = ranges.into_iter().flat_map(|range| {
        let start: u32 = range.start_addr().into();
        let end: u32 = range.end_addr().into();
        (start..=end).map(Ipv4Addr::from)
    });
    let held = ip_set.clone();
    let owed = move |address| match address {
        IpAddr::V4(v4) if held.contains(&address) => Some(v4),
        _ => None,
    };
    let iter = in_order(targets, ip_set.v4_len(), walk, owed).map(move |dst_addr| {
        let packet = arp::build_request(local_mac, src_ip, dst_addr);
        (packet, IpAddr::V4(dst_addr))
    });

    Box::new(iter)
}

/// `targets`, `count` of them, in the order `walk` names, or as they come
/// without one.
///
/// A sweep that holds a large enough share of the walk is drawn along it (see
/// [`WalkOrder::draws`]): the walk's addresses in turn, each kept where `owed`
/// names it one of `targets`, and then those of `targets` the walk does not
/// number, as they come, as the stream leaves them last. Neither half holds
/// more than one address at a time. A sparser sweep is collected and sorted,
/// at an entry per address it owes a first attempt, as its ledger holds one
/// for each it has asked. Unseeded, the ranges are expanded as they are drawn.
fn in_order<A>(
    targets: impl Iterator<Item = A> + Send + 'static,
    count: u128,
    walk: Option<&WalkOrder>,
    owed: impl Fn(IpAddr) -> Option<A> + Send + 'static,
) -> Box<dyn Iterator<Item = A> + Send>
where
    A: Copy + Into<IpAddr> + Send + 'static,
{
    match walk {
        Some(walk) if walk.draws(count) => {
            let numbered = walk.clone();
            let unnumbered = targets.filter(move |target| !numbered.numbers((*target).into()));
            Box::new(walk.addresses().filter_map(owed).chain(unnumbered))
        }
        Some(walk) => {
            let mut targets: Vec<A> = targets.collect();
            walk.arrange(&mut targets);
            Box::new(targets.into_iter())
        }
        None => Box::new(targets),
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

    /// A seeded sweep's addresses, `ips`, in the walk of a scan whose plan is
    /// `plan`, and how many of them were drawn from their source to give the
    /// first.
    fn walked(plan: &str, ips: &str) -> (Vec<Ipv4Addr>, Vec<Ipv4Addr>, usize) {
        use crate::model::ip::set::Positions;
        use crate::scanner::session::ScanSession;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let plan: IpSet = plan.parse().expect("a plan");
        let ips: IpSet = ips.parse().expect("a sweep");
        let (_session, ctx) = ScanSession::builder()
            .ordering(Some(0x5EED))
            .counting(Positions::of(&plan))
            .build();
        let walk = WalkOrder::of(&ips, &ctx).expect("a seeded scan walks");
        let expand = |ips: &IpSet| {
            let ranges: Vec<Ipv4Range> = ips.v4().to_vec();
            ranges.into_iter().flat_map(|range| {
                (u32::from(range.start_addr())..=u32::from(range.end_addr())).map(Ipv4Addr::from)
            })
        };

        let mut sorted: Vec<Ipv4Addr> = expand(&ips).collect();
        walk.arrange(&mut sorted);

        let drawn = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&drawn);
        let source = expand(&ips).inspect(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        let held = ips.clone();
        let owed = move |address| match address {
            IpAddr::V4(v4) if held.contains(&address) => Some(v4),
            _ => None,
        };
        let mut order = in_order(source, ips.v4_len(), Some(&walk), owed);
        let first = order.next().expect("a first probe");
        let before_first = drawn.load(Ordering::SeqCst);

        (
            sorted,
            std::iter::once(first).chain(order).collect(),
            before_first,
        )
    }

    /// A seeded sweep leaves in the walk its scan names, which is the order
    /// the checkpoint counts along, and the addresses the walk does not
    /// number follow the rest as they come, whether the sweep is drawn along
    /// the walk or collected and sorted.
    #[test]
    fn a_seeded_sweep_leaves_in_the_walk_however_it_is_arranged() {
        // Dense enough to be drawn: the sweep holds most of the plan, beside
        // an address the plan does not number.
        let (sorted, drawn, _) = walked("192.0.2.0/24", "192.0.2.0-192.0.2.200, 198.51.100.7");
        assert_eq!(drawn, sorted);
        assert_eq!(drawn.last(), Some(&Ipv4Addr::new(198, 51, 100, 7)));

        // Sparse enough to be collected: a few addresses of a wide plan.
        let (sorted, collected, _) = walked("10.0.0.0/16", "10.0.0.1-10.0.0.9");
        assert_eq!(collected, sorted);
    }

    /// A sweep holding most of its walk sends its first probe without first
    /// expanding every address it owes. Collected and sorted, a seeded sweep
    /// of an on-link `/8` holds sixteen million entries and their keys, a third
    /// of a gigabyte, and sorts them all before anything leaves.
    #[test]
    fn a_dense_seeded_sweep_draws_its_first_probe_without_expanding_the_rest() {
        let (_, order, before_first) = walked("10.0.0.0/16", "10.0.0.0/16");

        assert_eq!(order.len(), 1 << 16, "every address, once");
        assert_eq!(before_first, 0, "addresses expanded before the first left");
    }
}
