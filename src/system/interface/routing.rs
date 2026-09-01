// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How this host reaches a target
//!
//! The classifier, and the one decision every strategy a scan runs follows
//! from. A target is on a segment this machine is attached to, or behind a
//! gateway, or reachable by neither, and which of the three it is decides
//! whether it gets a link-layer sweep, a raw probe with a source address
//! attached, or the unprivileged fallback.
//!
//! ## What it refuses, and why refusing is the work
//!
//! Two of the five buckets [`RoutedTargets`] hands back are refusals, and they
//! carry more of this module's reasoning than the three that succeed.
//!
//! A bare IPv6 link-local matches every interface and identifies none, so it is
//! reported as the unanswerable question it is rather than assigned to whichever
//! interface the host listed first. An off-link IPv6 range past
//! [`MAX_ENUMERABLE_ADDRESSES`] is kept whole and refused, because the only
//! strategy the engine has for an off-link range is to walk it and IPv6 defeats
//! walking outright.
//!
//! Both are carried out rather than dropped, on the rule the rest of the crate
//! is built on: a scan may report that it found nothing, and may never be quiet
//! about ground it did not look at.
//!
//! ## What it costs
//!
//! One `connect` per off-link target on an unbound UDP socket, which performs a
//! route lookup and sends nothing, parallelised across the target list. On-link
//! targets cost a prefix comparison and no syscall at all.

use crate::model::ip::range::IpRange::{V4, V6};
use crate::model::ip::range::Ipv6Range;
use crate::model::ip::set::IpSet;
use crate::system::interface::Link;
use crate::system::interface::source::{
    ProbeSockets, plausible_source, probe_route_source, viable_interfaces,
};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// An off-link target paired with the local source address a probe to it must
/// be sent from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutedTarget {
    /// The destination being probed.
    pub target: IpAddr,
    /// The source address to send its probe from.
    pub source: IpAddr,
}

/// The largest IPv6 range any strategy will turn into addresses one at a time.
///
/// Sixty-five thousand addresses, the size of an IPv4 `/16` and of an IPv6
/// `/112`. Enumeration is the only discovery strategy the engine has for an
/// off-link range, and it is a strategy IPv6 defeats outright rather than
/// merely slows: a `/64` holds 2^64 addresses, which at the four thousand
/// probes a second a routed sweep paces itself to is about 146 million years of
/// scanning, and long before that the expansion into a `Vec<IpAddr>` exhausts
/// memory. There is no ceiling at which walking a `/64` becomes reasonable, so
/// the question is only where to stop pretending.
///
/// It is deliberately the same number as the largest IPv4 range anyone sweeps
/// in practice, because the limit is about how many probes a scan can spend
/// rather than about the address family. Larger IPv6 ranges are not scanned
/// less thoroughly here; they are refused, loudly, so the caller knows the
/// engine did not look rather than believing it looked and found nothing.
///
/// IPv4 ranges are not bounded by this. Every IPv4 range is finite in a way a
/// user can reason about, the whole space is 2^32, and a `/8` is an
/// unreasonable request rather than an impossible one.
///
/// Public as the number, where [`is_enumerable`] is the test: three places now
/// ask the question and every one of them asks it through the function, which is
/// what keeps the number in one place. The classifier applies it to a routed
/// range it would have to walk; [`crate::scanner`] applies it on the
/// unprivileged path, which takes its addresses as given and has no classifier
/// to consult; and `DiscoveryPlan::build` applies it to an on-link range, which
/// the classifier hands over whole because a segment is swept by multicast
/// rather than walked.
///
/// Each of the three arrived after a defect. Two spellings of the number meant a
/// `/64` refused with root and scanned forever without it; no check at all on
/// the third path meant an on-link `/64` was walked two thousand addresses deep
/// and reported covered.
pub const MAX_ENUMERABLE_ADDRESSES: u128 = 1 << 16;

/// The result of classifying a set of targets against this host's interfaces
/// and routing table.
#[derive(Debug, Default)]
pub struct RoutedTargets {
    /// Targets that share an interface's Layer-2 segment, grouped by that
    /// interface. Reachable directly, so they get an ARP/NDP discovery
    /// strategy bound to the interface.
    pub local: HashMap<Link, IpSet>,
    /// Targets reached through a gateway, each already paired with the source
    /// address to probe it from. Handled by a single raw TCP SYN scanner.
    pub routed: Vec<RoutedTarget>,
    /// Targets that are neither on-link nor have a resolvable route (e.g.
    /// loopback), left to the unprivileged connect fallback.
    pub unmapped: IpSet,
    /// Link-local IPv6 targets with no interface named on them.
    ///
    /// Every interface holds an `fe80::/64`, so such a target matches all of
    /// them and identifies none. Assigning it to whichever the host happened to
    /// list first probes an arbitrary segment and reports the address absent
    /// when it is present on another: a wrong answer arrived at silently, and
    /// on a laptop with two dozen interfaces an unlikely guess. Written
    /// `fe80::1%en0`, it is unambiguous; written bare, it is a question with no
    /// answer and is reported as one.
    pub ambiguous: Vec<Ipv6Range>,
    /// Off-link IPv6 ranges too large to enumerate, kept whole.
    ///
    /// These are not failures of the network and not addresses that went
    /// unanswered; they were never probed. They are carried out of here rather
    /// than dropped because the one thing a scanner may never do is stay quiet
    /// about a target it declined to look at: a caller reading "no hosts
    /// found" would otherwise take it as evidence about the range.
    pub unenumerable: Vec<Ipv6Range>,
}

/// Classifies target IPs by how this host reaches them: on-link (per
/// interface), routed through a gateway (paired with a source address), or
/// unreachable.
///
/// Reads the host's interface table through
/// [`interfaces`](super::interfaces), narrowed to the links that could carry a
/// probe. Where that table comes from is [`Link::from_netdev`](super::Link)'s
/// business and deliberately nobody else's; this used to name `pnet::datalink`,
/// which stopped being the source, and then stopped being a dependency.
pub fn map_ips_to_interfaces(ip_set: IpSet) -> RoutedTargets {
    map_ips_to_interfaces_with(ip_set, viable_interfaces())
}

/// Per-single classification carried out of the parallel pass, before the
/// results are folded back into interface-indexed buckets.
enum Classification {
    /// On-link on the interface at this index.
    Local(usize),
    /// Routed off-link, to be sent from this source address.
    Routed(IpAddr),
    /// No route found.
    Unmapped,
}

/// [`map_ips_to_interfaces`] against an interface table the caller supplies.
///
/// The seam every classification decision in this module is tested through: on
/// a real host the table comes from the platform, and a test hands in
/// interfaces that do not exist, so which bucket a target lands in can be
/// exercised without depending on what the machine running the tests happens to
/// have plugged in.
pub(crate) fn map_ips_to_interfaces_with(ip_set: IpSet, interfaces: Vec<Link>) -> RoutedTargets {
    let owned_ips: HashSet<IpAddr> = interfaces
        .iter()
        .flat_map(|link| link.addresses().iter().map(|held| held.address()))
        .collect();

    let mut local: HashMap<usize, IpSet> = HashMap::new();
    let mut routed: Vec<RoutedTarget> = Vec::new();
    let mut unmapped = IpSet::new();
    let mut unenumerable: Vec<Ipv6Range> = Vec::new();
    let mut ambiguous: Vec<Ipv6Range> = Vec::new();
    let mut singles_to_route: Vec<IpAddr> = Vec::new();

    // A range wholly inside one interface's subnet is kept intact; anything
    // else is expanded to singles for per-target route resolution.
    for range in ip_set.v4() {
        let start = IpAddr::V4(range.start_addr());
        let end = IpAddr::V4(range.end_addr());
        match owning_interface(&interfaces, start, end) {
            Some(idx) => local.entry(idx).or_default().insert_range(V4(*range)),
            None => singles_to_route.extend(range.iter()),
        }
    }
    for range in ip_set.v6() {
        let start = IpAddr::V6(range.start_addr());
        let end = IpAddr::V6(range.end_addr());

        // Checked before any interface is consulted, because consulting them is
        // exactly the mistake: they all match.
        if range.is_ambiguous() {
            ambiguous.push(*range);
            continue;
        }
        // A named interface answers the question outright. The scope id is the
        // user's own statement about which segment they meant, and it outranks
        // any prefix match.
        if let Some(zone) = range.zone() {
            match interfaces.iter().position(|link| link.index() == zone) {
                Some(idx) => local.entry(idx).or_default().insert_range(V6(*range)),
                None => ambiguous.push(*range),
            }
            continue;
        }

        match owning_interface(&interfaces, start, end) {
            // On-link, so it is kept whole and never expanded here: a segment is
            // reached by multicast, and that is one packet whatever the prefix
            // length. Whether the range is *also* small enough to walk address
            // by address is a question for whoever builds the sweep, since only
            // a targeted run walks one; `DiscoveryPlan::build` asks it.
            Some(idx) => local.entry(idx).or_default().insert_range(V6(*range)),
            // Off-link, where the only strategy is to probe each address in
            // turn. The check comes before `to_iter` because the expansion is
            // what does the damage, not the probing.
            None if !is_enumerable(range) => unenumerable.push(*range),
            None => singles_to_route.extend(range.iter()),
        }
    }

    let processed: Vec<(IpAddr, Classification)> = singles_to_route
        .par_iter()
        .map_init(ProbeSockets::default, |sockets, &target| {
            if let Some(idx) = find_local_index(&interfaces, target) {
                return (target, Classification::Local(idx));
            }

            if let Some(source) = probe_route_source(target, sockets)
                && owned_ips.contains(&source)
            {
                return (target, Classification::Routed(source));
            }

            // The kernel declined, but this host may still hold an address of
            // the right scope - see `plausible_source`. Without this a laptop
            // whose VPN swallowed the IPv6 default route sends no probe at all
            // and reports the targets as unreachable.
            if let Some(source) = plausible_source(&interfaces, target) {
                return (target, Classification::Routed(source));
            }

            (target, Classification::Unmapped)
        })
        .collect();

    for (target, class) in processed {
        match class {
            Classification::Local(idx) => local.entry(idx).or_default().insert(target),
            Classification::Routed(source) => routed.push(RoutedTarget { target, source }),
            Classification::Unmapped => unmapped.insert(target),
        }
    }

    let local = local
        .into_iter()
        .map(|(idx, ips)| (interfaces[idx].clone(), ips))
        .collect();

    RoutedTargets {
        local,
        routed,
        unmapped,
        ambiguous,
        unenumerable,
    }
}

/// Whether an IPv6 range is small enough to probe one address at a time.
///
/// The question every strategy that walks addresses has to ask before it starts,
/// and the reason it is asked of a range rather than of a set: a set holding a
/// `/64` and three literals is partly walkable, and refusing all four of them
/// would throw away three addresses somebody named. See
/// [`MAX_ENUMERABLE_ADDRESSES`].
pub fn is_enumerable(range: &Ipv6Range) -> bool {
    range.len() <= MAX_ENUMERABLE_ADDRESSES
}

/// Finds the first interface whose subnet fully contains the inclusive range
/// `[start, end]`, meaning the whole range is on that interface's segment.
fn owning_interface(links: &[Link], start: IpAddr, end: IpAddr) -> Option<usize> {
    links.iter().position(|link| {
        link.addresses()
            .iter()
            .any(|held| held.contains(&start) && held.contains(&end))
    })
}

/// Finds the first interface whose subnet contains `target`, matching only
/// within the same address family.
fn find_local_index(links: &[Link], target: IpAddr) -> Option<usize> {
    // The family check `LinkAddress::contains` already makes: a range of one
    // family never contains an address of the other.
    links
        .iter()
        .position(|link| link.addresses().iter().any(|held| held.contains(&target)))
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
    use crate::model::ip::range::{IpRange, Ipv4Range, Ipv6Range};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn mock_named(name: &str, index: u32, ip: IpAddr, prefix: u8) -> Link {
        Link::new(name, index)
            .with_addresses(vec![crate::system::interface::LinkAddress::new(ip, prefix)])
    }

    fn mock_interface(ip: IpAddr, prefix: u8) -> Link {
        Link::new("test0", 0)
            .with_addresses(vec![crate::system::interface::LinkAddress::new(ip, prefix)])
    }

    #[test]
    fn test_find_local_index() {
        let interfaces = vec![
            mock_interface(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 24),
            mock_interface(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 8),
        ];

        // 192.168.1.50 is in 192.168.1.0/24 (index 0)
        assert_eq!(
            find_local_index(&interfaces, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))),
            Some(0)
        );

        // 10.50.0.1 is in 10.0.0.0/8 (index 1)
        assert_eq!(
            find_local_index(&interfaces, IpAddr::V4(Ipv4Addr::new(10, 50, 0, 1))),
            Some(1)
        );

        // 172.16.0.1 is unmapped
        assert_eq!(
            find_local_index(&interfaces, IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))),
            None
        );
    }

    #[test]
    fn on_link_v4_range_stays_intact_and_local() {
        let interfaces = vec![mock_interface(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            24,
        )];
        let mut set = IpSet::new();
        set.insert_range(IpRange::V4(
            Ipv4Range::new(
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 20),
            )
            .unwrap(),
        ));

        let result = map_ips_to_interfaces_with(set, interfaces);

        assert!(result.routed.is_empty());
        assert!(result.unmapped.is_empty());
        assert_eq!(result.local.len(), 1);
        let (_, ips) = result.local.into_iter().next().unwrap();
        assert_eq!(ips.len(), 11);
    }

    /// The boundary of the enumeration ceiling, checked exactly rather than by
    /// expanding a range: a `/112` is probed, a `/111` is not.
    #[test]
    fn the_enumeration_ceiling_is_a_112() {
        let base = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let at_ceiling = Ipv6Range::new(base, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xffff));
        let over_ceiling = Ipv6Range::new(base, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 1, 0));

        let at_ceiling = at_ceiling.unwrap();
        assert_eq!(at_ceiling.len(), MAX_ENUMERABLE_ADDRESSES);
        assert!(is_enumerable(&at_ceiling), "a /112 is 65536 addresses");
        assert!(
            !is_enumerable(&over_ceiling.unwrap()),
            "one address more is not"
        );
    }

    /// The failure this ceiling exists to prevent: a routed `/64` expanded into
    /// a `Vec<IpAddr>` is 2^64 allocations, which is not a slow scan but an
    /// out-of-memory condition reached from a perfectly ordinary target
    /// expression.
    ///
    /// It has to come out as its own category. Silently dropping it would report
    /// an empty scan of a range nobody probed, and a caller cannot tell that
    /// from a range with nothing on it.
    #[test]
    fn a_routed_v6_prefix_too_large_to_walk_is_refused_rather_than_expanded() {
        let interfaces = vec![mock_interface(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            24,
        )];
        let mut set = IpSet::new();
        set.insert_range(IpRange::V6(
            Ipv6Range::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff),
            )
            .unwrap(),
        ));

        let result = map_ips_to_interfaces_with(set, interfaces);

        assert_eq!(result.unenumerable.len(), 1, "the /64 is reported whole");
        assert!(result.routed.is_empty());
        assert!(result.unmapped.is_empty());
        assert!(result.local.is_empty());
    }

    /// The silent wrong answer this refusal exists to prevent.
    ///
    /// Every interface holds an `fe80::/64`, so a bare link-local target matches
    /// all of them and `owning_interface` returns whichever the host listed
    /// first. On a laptop with two dozen interfaces that is close to a random
    /// choice: the scan probes one segment, hears nothing, and reports a host
    /// that was present on another as absent.
    #[test]
    fn a_link_local_target_naming_no_interface_is_refused() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA);
        let interfaces = vec![
            mock_interface(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 64),
            mock_interface(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)), 64),
        ];
        let mut set = IpSet::new();
        set.insert(IpAddr::V6(link_local));

        let result = map_ips_to_interfaces_with(set, interfaces);

        assert_eq!(result.ambiguous.len(), 1);
        assert!(
            result.local.is_empty(),
            "guessing an interface is what this prevents"
        );
    }

    /// Named, the same target is unambiguous, and the name outranks any prefix
    /// match: every interface matches the prefix, so a prefix match is no
    /// evidence at all.
    #[test]
    fn a_link_local_target_goes_to_the_interface_it_names() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA);
        let first = mock_named(
            "en3",
            3,
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            64,
        );
        let second = mock_named(
            "en9",
            9,
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)),
            64,
        );

        let mut set = IpSet::new();
        set.insert_range(IpRange::V6(
            Ipv6Range::scoped(link_local, link_local, Some(9)).unwrap(),
        ));

        let result = map_ips_to_interfaces_with(set, vec![first, second]);

        assert!(result.ambiguous.is_empty());
        assert_eq!(result.local.len(), 1);
        let (intf, ips) = result.local.into_iter().next().unwrap();
        assert_eq!(intf.name(), "en9", "the second interface was the one named");
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn on_link_v6_range_is_classified_local() {
        let base = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);
        let interfaces = vec![mock_interface(IpAddr::V6(base), 64)];
        let mut set = IpSet::new();
        set.insert_range(IpRange::V6(
            Ipv6Range::new(
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 5),
            )
            .unwrap(),
        ));

        let result = map_ips_to_interfaces_with(set, interfaces);

        assert!(result.routed.is_empty());
        assert!(result.unmapped.is_empty());
        assert_eq!(result.local.len(), 1);
        let (_, ips) = result.local.into_iter().next().unwrap();
        assert_eq!(ips.len(), 5);
    }
}
