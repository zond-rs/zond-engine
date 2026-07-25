// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use crate::core::models::ip::range::IpRange::{V4, V6};
use crate::core::models::ip::set::IpSet;
use crate::system::interface::source::{ProbeSockets, probe_route_source, viable_interfaces};
use pnet::datalink::NetworkInterface;
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

/// The result of classifying a set of targets against this host's interfaces
/// and routing table.
#[derive(Debug, Default)]
pub struct RoutedTargets {
    /// Targets that share an interface's Layer-2 segment, grouped by that
    /// interface. Reachable directly, so they get an ARP/NDP discovery
    /// strategy bound to the interface.
    pub local: HashMap<NetworkInterface, IpSet>,
    /// Targets reached through a gateway, each already paired with the source
    /// address to probe it from. Handled by a single raw TCP SYN scanner.
    pub routed: Vec<RoutedTarget>,
    /// Targets that are neither on-link nor have a resolvable route (e.g.
    /// loopback), left to the unprivileged connect fallback.
    pub unmapped: IpSet,
}

/// Classifies target IPs by how this host reaches them: on-link (per
/// interface), routed through a gateway (paired with a source address), or
/// unreachable.
///
/// Under the hood, this evaluates `pnet::datalink::interfaces()`.
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

pub(crate) fn map_ips_to_interfaces_with(
    ip_set: IpSet,
    interfaces: Vec<NetworkInterface>,
) -> RoutedTargets {
    let owned_ips: HashSet<IpAddr> = interfaces
        .iter()
        .flat_map(|iface| iface.ips.iter().map(|ip_net| ip_net.ip()))
        .collect();

    let mut local: HashMap<usize, IpSet> = HashMap::new();
    let mut routed: Vec<RoutedTarget> = Vec::new();
    let mut unmapped = IpSet::new();
    let mut singles_to_route: Vec<IpAddr> = Vec::new();

    // A range wholly inside one interface's subnet is kept intact; anything
    // else is expanded to singles for per-target route resolution.
    for range in ip_set.v4() {
        let start = IpAddr::V4(range.start_addr);
        let end = IpAddr::V4(range.end_addr);
        match owning_interface(&interfaces, start, end) {
            Some(idx) => local.entry(idx).or_default().insert_range(V4(*range)),
            None => singles_to_route.extend(range.to_iter()),
        }
    }
    for range in ip_set.v6() {
        let start = IpAddr::V6(range.start_addr);
        let end = IpAddr::V6(range.end_addr);
        match owning_interface(&interfaces, start, end) {
            Some(idx) => local.entry(idx).or_default().insert_range(V6(*range)),
            None => singles_to_route.extend(range.to_iter()),
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
    }
}

/// Finds the first interface whose subnet fully contains the inclusive range
/// `[start, end]`, meaning the whole range is on that interface's segment.
fn owning_interface(interfaces: &[NetworkInterface], start: IpAddr, end: IpAddr) -> Option<usize> {
    interfaces.iter().position(|iface| {
        iface
            .ips
            .iter()
            .any(|net| net.contains(start) && net.contains(end))
    })
}

/// Finds the first interface whose subnet contains `target`, matching only
/// within the same address family.
fn find_local_index(interfaces: &[NetworkInterface], target: IpAddr) -> Option<usize> {
    interfaces.iter().position(|iface| {
        iface.ips.iter().any(|ip_net| match (target, ip_net.ip()) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                ip_net.contains(target)
            }
            _ => false,
        })
    })
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
    use crate::core::models::ip::range::{IpRange, Ipv4Range, Ipv6Range};
    use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn mock_interface(ip: IpAddr, prefix: u8) -> NetworkInterface {
        let net = match ip {
            IpAddr::V4(v4) => IpNetwork::V4(Ipv4Network::new(v4, prefix).unwrap()),
            IpAddr::V6(v6) => IpNetwork::V6(Ipv6Network::new(v6, prefix).unwrap()),
        };

        NetworkInterface {
            name: "test0".to_string(),
            description: "".to_string(),
            index: 0,
            mac: None,
            ips: vec![net],
            flags: 0,
        }
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
