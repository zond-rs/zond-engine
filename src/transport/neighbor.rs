// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Link-Layer Next-Hop Resolution
//!
//! Answers the question a Layer-2 sender has to ask that a raw-IP sender
//! never does: to put a frame for `dst` on the wire myself, which interface
//! does it leave by, what source MAC and IP do I stamp on it, and what
//! *destination* MAC - the next hop's, not the final target's - goes in the
//! Ethernet header?
//!
//! The next hop depends on where the target sits:
//!
//! - **On-link** (same subnet as one of our interfaces): the next hop *is*
//!   the target, and its MAC has to be resolved by ARP/NDP.
//! - **Off-link**: the next hop is the gateway, whose MAC the OS already
//!   knows from its active default route - `netdev` reads it straight out of
//!   the neighbor table, so no probe is needed for the common internet-facing
//!   case.
//!
//! This module owns only the *decision* and a resolved-MAC cache; performing
//! the actual ARP/NDP exchange for an on-link miss is left to the sender,
//! which is the thing that holds a link-layer channel. Keeping the policy
//! here, free of any socket, is what makes it unit-testable.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::system::interface::LinkAddress;
use pnet_base::MacAddr;

/// A resolved link-layer path to a destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRoute {
    /// Name of the interface the frame leaves by.
    pub interface: String,
    /// Source IP to stamp on the packet (must match the interface/subnet the
    /// frame egresses, or the reply won't come back to us).
    pub src_ip: IpAddr,
    /// Source MAC for the Ethernet header.
    pub src_mac: MacAddr,
    /// The next hop's IP: the target itself if on-link, otherwise the gateway.
    pub next_hop: IpAddr,
    /// The next hop's MAC, if already known - resolved from the gateway
    /// (off-link) or a previous ARP/NDP (on-link, cached). `None` means the
    /// sender must resolve it before it can build the frame.
    pub next_hop_mac: Option<MacAddr>,
    /// Whether the next hop is on our own segment (so the sender resolves the
    /// target's own MAC) rather than the gateway.
    pub on_link: bool,
}

/// A single interface's addressing, distilled from `netdev` into just what
/// next-hop resolution needs. Interfaces without a MAC (tunnels, loopback)
/// are excluded at construction, since the Ethernet sender can't use them.
#[derive(Debug, Clone)]
struct InterfaceInfo {
    name: String,
    mac: MacAddr,
    v4: Vec<LinkAddress>,
    v6: Vec<LinkAddress>,
    gateway_v4: Option<(Ipv4Addr, MacAddr)>,
    gateway_v6: Option<(Ipv6Addr, MacAddr)>,
}

/// Resolves link-layer routes for destinations and remembers on-link MACs
/// once the sender has learned them.
pub struct NeighborResolver {
    interfaces: Vec<InterfaceInfo>,
    /// Learned on-link MACs, keyed by `(interface, next-hop IP)`.
    cache: HashMap<(String, IpAddr), MacAddr>,
}

impl NeighborResolver {
    /// Builds a resolver from the system's current Ethernet-capable
    /// interfaces, reading each one's addresses and default gateway (with the
    /// gateway's MAC) from `netdev`.
    pub fn from_system() -> Self {
        let interfaces = netdev::get_interfaces()
            .into_iter()
            .filter_map(interface_info)
            .collect();
        Self::from_interfaces(interfaces)
    }

    fn from_interfaces(interfaces: Vec<InterfaceInfo>) -> Self {
        Self {
            interfaces,
            cache: HashMap::new(),
        }
    }

    /// Whether any Ethernet-capable interface exists at all. When false, the
    /// Ethernet sender has nothing to work with and the caller should use the
    /// raw-IP path instead.
    pub fn has_ethernet(&self) -> bool {
        !self.interfaces.is_empty()
    }

    /// Resolves the link-layer route to `dst`, consulting the on-link MAC
    /// cache. On-link routes come back with `next_hop_mac` set only if
    /// previously learned; off-link routes carry the gateway's MAC directly.
    pub fn resolve(&self, dst: IpAddr) -> Option<LinkRoute> {
        self.resolve_on_link(dst)
            .or_else(|| self.resolve_off_link(dst))
    }

    /// Records a MAC learned for an on-link next hop, so the next probe to
    /// that host skips the ARP/NDP round trip.
    pub fn remember(&mut self, interface: &str, next_hop: IpAddr, mac: MacAddr) {
        self.cache.insert((interface.to_string(), next_hop), mac);
    }

    fn resolve_on_link(&self, dst: IpAddr) -> Option<LinkRoute> {
        for iface in &self.interfaces {
            let src_ip = match dst {
                IpAddr::V4(_) => iface
                    .v4
                    .iter()
                    .find(|held| held.contains(&dst))
                    .map(LinkAddress::address),
                IpAddr::V6(_) => iface
                    .v6
                    .iter()
                    .find(|held| held.contains(&dst))
                    .map(LinkAddress::address),
            };

            if let Some(src_ip) = src_ip {
                return Some(LinkRoute {
                    interface: iface.name.clone(),
                    src_ip,
                    src_mac: iface.mac,
                    next_hop: dst,
                    next_hop_mac: self.cache.get(&(iface.name.clone(), dst)).copied(),
                    on_link: true,
                });
            }
        }
        None
    }

    fn resolve_off_link(&self, dst: IpAddr) -> Option<LinkRoute> {
        // The first interface with a default gateway of the right family and
        // an address to source from wins. Interfaces without one (a
        // gateway-less secondary NIC, say) are skipped, not treated as a dead
        // end for the whole lookup.
        self.interfaces.iter().find_map(|iface| {
            let (next_hop, gw_mac, src_ip) = match dst {
                IpAddr::V4(_) => {
                    let (gw_ip, mac) = iface.gateway_v4?;
                    let src = iface.v4.first()?.address();
                    (IpAddr::V4(gw_ip), mac, src)
                }
                IpAddr::V6(_) => {
                    let (gw_ip, mac) = iface.gateway_v6?;
                    let src = routable_v6_source(iface)?;
                    (IpAddr::V6(gw_ip), mac, IpAddr::V6(src))
                }
            };

            Some(LinkRoute {
                interface: iface.name.clone(),
                src_ip,
                src_mac: iface.mac,
                next_hop,
                next_hop_mac: Some(gw_mac),
                on_link: false,
            })
        })
    }
}

/// Picks the IPv6 address on `iface` a packet leaving the segment may be sent
/// from.
///
/// Not simply the first one. An IPv6 interface normally holds several addresses
/// at once, and they are not interchangeable: a link-local address is valid only
/// on the segment it was configured for, so a packet aimed past the router and
/// sourced from `fe80::` is discarded on the way — and the reply, if one were
/// ever sent, would have nowhere to go. Interface order is whatever the
/// operating system happened to report, so taking the first address is a coin
/// flip on a host that has both, which is every host with working IPv6.
///
/// Unique local addresses are skipped for the same reason at a larger scale:
/// they are not routed off site, so a probe sourced from one reaches nothing
/// beyond it.
fn routable_v6_source(iface: &InterfaceInfo) -> Option<Ipv6Addr> {
    iface
        .v6
        .iter()
        .filter_map(|held| match held.address() {
            IpAddr::V6(v6) => Some(v6),
            IpAddr::V4(_) => None,
        })
        .find(|addr| !addr.is_unicast_link_local() && !addr.is_unique_local())
}

/// Converts a `netdev` interface into an [`InterfaceInfo`], returning `None`
/// for interfaces the Ethernet sender can't drive: those without a MAC
/// (tunnels, loopback) or without any assigned address.
fn interface_info(iface: netdev::Interface) -> Option<InterfaceInfo> {
    let mac = iface.mac_addr.map(to_pnet_mac)?;
    if iface.ipv4.is_empty() && iface.ipv6.is_empty() {
        return None;
    }

    let v4 = iface
        .ipv4
        .iter()
        .map(|net| LinkAddress::new(IpAddr::V4(net.addr()), net.prefix_len()))
        .collect();
    let v6 = iface
        .ipv6
        .iter()
        .map(|net| LinkAddress::new(IpAddr::V6(net.addr()), net.prefix_len()))
        .collect();

    let (gateway_v4, gateway_v6) = match iface.gateway {
        Some(gw) => {
            let mac = to_pnet_mac(gw.mac_addr);
            (
                gw.ipv4.first().map(|ip| (*ip, mac)),
                gw.ipv6.first().map(|ip| (*ip, mac)),
            )
        }
        None => (None, None),
    };

    Some(InterfaceInfo {
        name: iface.name,
        mac,
        v4,
        v6,
        gateway_v4,
        gateway_v6,
    })
}

fn to_pnet_mac(mac: netdev::MacAddr) -> MacAddr {
    let [a, b, c, d, e, f] = mac.octets();
    MacAddr::new(a, b, c, d, e, f)
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

    const IFACE_MAC: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 0x01);
    const GW_MAC: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 0xFE);

    fn ethernet_iface() -> InterfaceInfo {
        InterfaceInfo {
            name: "en0".to_string(),
            mac: IFACE_MAC,
            v4: vec![LinkAddress::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
                24,
            )],
            v6: vec![],
            gateway_v4: Some((Ipv4Addr::new(192, 168, 1, 1), GW_MAC)),
            gateway_v6: None,
        }
    }

    #[test]
    fn on_link_target_routes_to_itself_and_needs_arp() {
        let resolver = NeighborResolver::from_interfaces(vec![ethernet_iface()]);
        let route = resolver
            .resolve(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)))
            .unwrap();

        assert!(route.on_link);
        assert_eq!(route.next_hop, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)));
        assert_eq!(route.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
        assert_eq!(route.src_mac, IFACE_MAC);
        assert_eq!(route.next_hop_mac, None); // must be ARP-resolved
    }

    #[test]
    fn off_link_target_routes_via_gateway_with_known_mac() {
        let resolver = NeighborResolver::from_interfaces(vec![ethernet_iface()]);
        let route = resolver
            .resolve(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
            .unwrap();

        assert!(!route.on_link);
        assert_eq!(route.next_hop, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(route.next_hop_mac, Some(GW_MAC));
        assert_eq!(route.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
    }

    #[test]
    fn cached_on_link_mac_is_returned() {
        let mut resolver = NeighborResolver::from_interfaces(vec![ethernet_iface()]);
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
        let learned = MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);

        assert_eq!(resolver.resolve(target).unwrap().next_hop_mac, None);
        resolver.remember("en0", target, learned);
        assert_eq!(
            resolver.resolve(target).unwrap().next_hop_mac,
            Some(learned)
        );
    }

    #[test]
    fn off_link_skips_gatewayless_interface_for_a_later_one() {
        // A secondary NIC with no gateway comes first; the real one second.
        let gatewayless = InterfaceInfo {
            name: "en1".to_string(),
            mac: MacAddr(0x02, 0, 0, 0, 0, 0x02),
            v4: vec![LinkAddress::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 24)],
            v6: vec![],
            gateway_v4: None,
            gateway_v6: None,
        };
        let resolver = NeighborResolver::from_interfaces(vec![gatewayless, ethernet_iface()]);

        let route = resolver
            .resolve(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
            .unwrap();
        assert_eq!(route.interface, "en0");
        assert_eq!(route.next_hop_mac, Some(GW_MAC));
    }

    #[test]
    fn off_link_without_gateway_is_unresolvable() {
        let mut iface = ethernet_iface();
        iface.gateway_v4 = None;
        let resolver = NeighborResolver::from_interfaces(vec![iface]);
        assert!(
            resolver
                .resolve(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
                .is_none()
        );
    }

    /// A host with working IPv6 has a link-local address *and* a global one, in
    /// whatever order the OS reported them. Sourcing an off-link probe from the
    /// link-local is a packet the first router drops, and picking by position
    /// makes which of the two happens a matter of luck.
    #[test]
    fn an_off_link_v6_probe_is_sourced_from_a_routable_address() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x50);
        let global = Ipv6Addr::new(0x2a02, 0x908, 0, 0, 0, 0, 0, 0xb1a0);
        let unique_local = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

        let iface = InterfaceInfo {
            name: "en0".to_string(),
            mac: IFACE_MAC,
            v4: vec![],
            // Link-local first, as an interface commonly reports it.
            v6: vec![
                LinkAddress::new(IpAddr::V6(link_local), 64),
                LinkAddress::new(IpAddr::V6(unique_local), 64),
                LinkAddress::new(IpAddr::V6(global), 64),
            ],
            gateway_v4: None,
            gateway_v6: Some((Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), GW_MAC)),
        };
        let resolver = NeighborResolver::from_interfaces(vec![iface]);

        let route = resolver
            .resolve(IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
            )))
            .expect("a host with a v6 gateway has a route");

        assert_eq!(route.src_ip, IpAddr::V6(global));
    }

    /// An interface with nothing but link-local IPv6 cannot source an off-link
    /// probe at all, and saying so is better than sending one that dies at the
    /// router.
    #[test]
    fn an_interface_with_only_link_local_v6_has_no_off_link_source() {
        let iface = InterfaceInfo {
            name: "en0".to_string(),
            mac: IFACE_MAC,
            v4: vec![],
            v6: vec![LinkAddress::new(
                IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x50)),
                64,
            )],
            gateway_v4: None,
            gateway_v6: Some((Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), GW_MAC)),
        };
        let resolver = NeighborResolver::from_interfaces(vec![iface]);

        assert!(
            resolver
                .resolve(IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)))
                .is_none()
        );
    }

    #[test]
    fn no_ethernet_interfaces_resolves_nothing() {
        let resolver = NeighborResolver::from_interfaces(vec![]);
        assert!(!resolver.has_ethernet());
        assert!(
            resolver
                .resolve(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
                .is_none()
        );
    }
}
