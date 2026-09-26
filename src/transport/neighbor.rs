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
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::model::mac::MacAddr;
use crate::system::interface::LinkAddress;
use crate::system::interface::{ProbeSockets, probe_route_source};

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

/// Asks the routing table which local address a packet to a destination would
/// be sent from, without sending one. The seam a test replaces.
type KernelRoute = Box<dyn Fn(IpAddr) -> Option<IpAddr> + Send + Sync + UnwindSafe + RefUnwindSafe>;

/// Resolves link-layer routes for destinations and remembers on-link MACs
/// once the sender has learned them.
///
/// **The frame leaves by the interface the packet's source belongs to.** A
/// segment reaches the Ethernet sender with its source address already chosen,
/// and chosen from the routing table, or forced by the caller; the checksum is
/// computed over it. The interface holding that address is the one the kernel
/// would send it from, so it is the one whose gateway and hardware address the
/// frame carries. Where no Ethernet interface holds it, because the kernel
/// routes the destination through a tunnel, there is no Ethernet route: a
/// frame put on a physical link instead would reach the LAN router with the
/// tunnel's address in it, bypassing the tunnel for a target only the tunnel
/// reaches.
///
/// A source no interface holds at all is spoofed on purpose, as the idle scan's
/// is. There the kernel is asked how it would route the destination, and the
/// frame leaves by that interface if it is Ethernet.
pub struct NeighborResolver {
    interfaces: Vec<InterfaceInfo>,
    /// Learned on-link MACs, keyed by `(interface, next-hop IP)`.
    cache: HashMap<(String, IpAddr), MacAddr>,
    /// Every address this host holds on an interface with no Ethernet in front
    /// of it: tunnels and loopback. Read once, because the question it answers
    /// is asked for every probe to a tunnel-routed target.
    unframed: Vec<IpAddr>,
    kernel: KernelRoute,
}

impl NeighborResolver {
    /// Builds a resolver from the system's current Ethernet-capable
    /// interfaces, reading each one's addresses and default gateway (with the
    /// gateway's MAC) from `netdev`.
    pub fn from_system() -> Self {
        let mut interfaces = Vec::new();
        let mut unframed = Vec::new();
        for iface in crate::system::interface::host_table() {
            let held: Vec<IpAddr> = iface
                .ipv4
                .iter()
                .map(|net| IpAddr::V4(net.addr()))
                .chain(iface.ipv6.iter().map(|net| IpAddr::V6(net.addr())))
                .collect();
            match interface_info(iface) {
                Some(info) => interfaces.push(info),
                None => unframed.extend(held),
            }
        }
        Self::from_interfaces(
            interfaces,
            unframed,
            Box::new(|dst| probe_route_source(dst, &mut ProbeSockets::default())),
        )
    }

    fn from_interfaces(
        interfaces: Vec<InterfaceInfo>,
        unframed: Vec<IpAddr>,
        kernel: KernelRoute,
    ) -> Self {
        Self {
            interfaces,
            cache: HashMap::new(),
            unframed,
            kernel,
        }
    }

    /// A resolver for one Ethernet segment with no gateway, `interface`
    /// holding `address` from `mac`, for a test that frames to neighbours on
    /// it.
    #[cfg(test)]
    pub(crate) fn on_segment(interface: &str, mac: MacAddr, address: LinkAddress) -> Self {
        let held = address.address();
        let info = InterfaceInfo {
            name: interface.to_owned(),
            mac,
            v4: vec![address],
            v6: vec![],
            gateway_v4: None,
            gateway_v6: None,
        };
        Self::from_interfaces(vec![info], vec![], Box::new(move |_| Some(held)))
    }

    /// Whether any Ethernet-capable interface exists at all. When false, the
    /// Ethernet sender has nothing to work with and the caller should use the
    /// raw-IP path instead.
    pub fn has_ethernet(&self) -> bool {
        !self.interfaces.is_empty()
    }

    /// Resolves the link-layer route to `dst` for a packet sent from the
    /// address the routing table would choose for it.
    ///
    /// [`None`] where the routing table sends `dst` through an interface with
    /// no Ethernet in front of it, such as a VPN's tunnel, and for loopback,
    /// which no frame reaches. See [`resolve_from`](Self::resolve_from) for a
    /// packet whose source is already chosen.
    #[cfg(test)]
    pub fn resolve(&self, dst: IpAddr) -> Option<LinkRoute> {
        if dst.is_loopback() {
            return None;
        }
        let chosen = (self.kernel)(dst)?;
        let iface = self.holding(chosen)?;
        self.route_via(iface, chosen, dst)
    }

    /// Resolves the link-layer route for a packet from `src` to `dst`: by the
    /// Ethernet interface holding `src`, or, for a source no interface holds,
    /// by the one the routing table would send `dst` through. See the type's
    /// documentation.
    ///
    /// On-link routes come back with `next_hop_mac` set only if previously
    /// learned; off-link routes carry the gateway's MAC directly.
    ///
    /// A loopback destination has no such route. It is not on-link on any
    /// Ethernet interface, so the off-link arm would answer it with the default
    /// gateway, and a SYN aimed at `127.0.0.1` would go out a physical
    /// interface for the gateway to drop. Nothing would reply, which a port
    /// scan reads as filtered: a wrong answer rather than a missing one, and
    /// the reason it is worth refusing here rather than further out.
    pub fn resolve_from(&self, src: IpAddr, dst: IpAddr) -> Option<LinkRoute> {
        if dst.is_loopback() {
            return None;
        }
        if let Some(iface) = self.holding(src) {
            return self.route_via(iface, src, dst);
        }
        // One of this host's own addresses on a tunnel: the kernel sends from it
        // through that tunnel, and no frame follows.
        if src.is_loopback() || self.unframed.contains(&src) {
            return None;
        }
        // Asked per probe, which only a spoofing scan pays: the idle scan sends
        // one or two probes a port, and a lookup is a `connect` on a UDP socket
        // that sends nothing.
        let chosen = (self.kernel)(dst)?;
        let iface = self.holding(chosen)?;
        self.route_via(iface, chosen, dst)
    }

    /// Records a MAC learned for an on-link next hop, so the next probe to
    /// that host skips the ARP/NDP round trip.
    pub fn remember(&mut self, interface: &str, next_hop: IpAddr, mac: MacAddr) {
        self.cache.insert((interface.to_string(), next_hop), mac);
    }

    /// The Ethernet interface holding `address`.
    fn holding(&self, address: IpAddr) -> Option<&InterfaceInfo> {
        self.interfaces.iter().find(|iface| {
            iface
                .v4
                .iter()
                .chain(&iface.v6)
                .any(|held| held.address() == address)
        })
    }

    /// The route to `dst` over `iface`, for a packet from `anchor`, an address
    /// `iface` holds: `dst` itself where it is on the interface's segment, the
    /// interface's gateway otherwise.
    fn route_via(&self, iface: &InterfaceInfo, anchor: IpAddr, dst: IpAddr) -> Option<LinkRoute> {
        if anchor.is_ipv4() != dst.is_ipv4() {
            return None;
        }

        let on_link = match dst {
            IpAddr::V4(_) => iface.v4.iter().any(|held| held.contains(&dst)),
            IpAddr::V6(_) => iface.v6.iter().any(|held| held.contains(&dst)),
        };
        if on_link {
            return Some(LinkRoute {
                interface: iface.name.clone(),
                src_ip: anchor,
                src_mac: iface.mac,
                next_hop: dst,
                next_hop_mac: self.cache.get(&(iface.name.clone(), dst)).copied(),
                on_link: true,
            });
        }

        let (next_hop, gw_mac) = match (dst, anchor) {
            (IpAddr::V4(_), _) => {
                let (gw_ip, mac) = iface.gateway_v4?;
                (IpAddr::V4(gw_ip), mac)
            }
            // A link-local address is valid only on its own segment: a packet
            // sourced from one and aimed past the router is discarded on the
            // way, and a reply would have nowhere to go.
            (IpAddr::V6(_), IpAddr::V6(from)) if from.is_unicast_link_local() => return None,
            (IpAddr::V6(_), _) => {
                let (gw_ip, mac) = iface.gateway_v6?;
                (IpAddr::V6(gw_ip), mac)
            }
        };

        // A gateway whose hardware address the OS has not learned reaches this
        // point as all zeros, `netdev`'s stand-in for "unknown": the neighbour
        // table has no entry, because the default route was learned over IPv6
        // while the gateway's MAC is filled from the IPv4 ARP cache alone, or
        // because the cache had aged the entry out by the time the sender was
        // built. That address is no destination a frame can carry, so it is not
        // handed on as one. The gateway takes the same path a cold on-link
        // neighbour does: its MAC is `None` until an exchange learns it, drawn
        // from the same cache once it has, and resolved by the sender otherwise.
        let next_hop_mac = resolved_gateway_mac(gw_mac)
            .or_else(|| self.cache.get(&(iface.name.clone(), next_hop)).copied());

        Some(LinkRoute {
            interface: iface.name.clone(),
            src_ip: anchor,
            src_mac: iface.mac,
            next_hop,
            next_hop_mac,
            on_link: false,
        })
    }
}

/// How long a hardware address heard for a neighbour stays good enough to
/// frame a probe to it without asking again.
///
/// Asking again is not free, and on some links not reliable. A client on
/// Wi-Fi in power save has an ARP request, which is broadcast, held by the
/// access point until the next DTIM beacon, a delivery that can take longer
/// than the whole resolution waits; its replies, which are unicast, come back
/// at once. Such a host answers a sweep that asks it for seconds and then
/// fails a resolution that allows half of one, so the address a sweep has just
/// heard must be the one its port probes use, as the kernel's own table would
/// serve it.
///
/// Two minutes, because the entry has to outlast the gap between a sweep and
/// every pass that follows it on the same host, and because the one way an
/// entry goes wrong, the address moving to another machine, is rarer than
/// that on any segment a scan is run from. The kernels' own tables are no
/// stricter: Linux goes on framing to an entry for minutes while it
/// re-confirms it, and macOS keeps one for twenty.
const LEARNED_NEIGHBOR_TTL: Duration = Duration::from_secs(120);

/// The hardware addresses this process has heard its neighbours claim, by
/// `(interface, address)`.
///
/// One table for the whole process rather than one per sender, because what
/// it holds is a fact about the link and not about any one scan: every
/// transport a scan opens builds a sender of its own, and each of them asking
/// afresh for an address the discovery sweep heard a moment ago is both
/// wasted time and, on a link that delivers broadcast late, a lost host. The
/// kernel's neighbour table is shared for the same reason.
///
/// Written by whatever hears a neighbour give its address, an ARP frame read
/// by a sweep or a resolution a sender ran, and read by every sender before it
/// asks. Nothing older than [`LEARNED_NEIGHBOR_TTL`] is framed to; an older
/// entry says only where to ask first. See [`heard_neighbor`].
static LEARNED_NEIGHBORS: Mutex<LearnedNeighbors> = Mutex::new(LearnedNeighbors::new());

/// The table behind [`learn_neighbor`] and [`learned_neighbor`], apart from
/// the process's one instance so it can be tested with a clock of its own.
struct LearnedNeighbors {
    heard: Option<HashMap<(String, IpAddr), (MacAddr, Instant)>>,
}

impl LearnedNeighbors {
    const fn new() -> Self {
        Self { heard: None }
    }

    fn learn(&mut self, interface: &str, address: IpAddr, mac: MacAddr, at: Instant) {
        self.heard
            .get_or_insert_with(HashMap::new)
            .insert((interface.to_owned(), address), (mac, at));
    }

    fn recall(&self, interface: &str, address: IpAddr, now: Instant) -> Option<MacAddr> {
        let (mac, at) = self.heard.as_ref()?.get(&(interface.to_owned(), address))?;
        (now.saturating_duration_since(*at) < LEARNED_NEIGHBOR_TTL).then_some(*mac)
    }

    fn last_heard(&self, interface: &str, address: IpAddr) -> Option<MacAddr> {
        let (mac, _) = self.heard.as_ref()?.get(&(interface.to_owned(), address))?;
        Some(*mac)
    }
}

/// Records that `address` on `interface` is held by `mac`, as a neighbour has
/// just said.
///
/// A broadcast or multicast address is not recorded: no neighbour holds one,
/// and a frame sent to it would reach every host on the segment.
pub(crate) fn learn_neighbor(interface: &str, address: IpAddr, mac: MacAddr) {
    learn_neighbor_at(interface, address, mac, Instant::now());
}

/// [`learn_neighbor`], as heard at `at`.
pub(crate) fn learn_neighbor_at(interface: &str, address: IpAddr, mac: MacAddr, at: Instant) {
    if mac.is_broadcast() || mac.is_multicast() || mac == MacAddr::ZERO {
        return;
    }
    LEARNED_NEIGHBORS
        .lock()
        .unwrap_or_else(|held| held.into_inner())
        .learn(interface, address, mac, at);
}

/// The hardware address a neighbour last gave for `address` on `interface`,
/// however long ago.
///
/// Not good enough to frame a probe to once it is older than
/// [`LEARNED_NEIGHBOR_TTL`], which is what [`learned_neighbor`] answers, but
/// the address to ask the neighbour at when it is asked again: a frame for one
/// host reaches a client asleep on Wi-Fi sooner than a broadcast does.
pub(crate) fn heard_neighbor(interface: &str, address: IpAddr) -> Option<MacAddr> {
    LEARNED_NEIGHBORS
        .lock()
        .unwrap_or_else(|held| held.into_inner())
        .last_heard(interface, address)
}

/// The hardware address a neighbour gave for `address` on `interface` within
/// [`LEARNED_NEIGHBOR_TTL`], if one did.
pub(crate) fn learned_neighbor(interface: &str, address: IpAddr) -> Option<MacAddr> {
    LEARNED_NEIGHBORS
        .lock()
        .unwrap_or_else(|held| held.into_inner())
        .recall(interface, address, Instant::now())
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

/// The gateway MAC a frame can be addressed to, or `None` when it is still
/// unknown.
///
/// `netdev` reports a gateway whose hardware address it has not resolved as all
/// zeros rather than as absent. That sentinel is the single fact this converts:
/// an all-zero address names no station on the segment, so a frame built with it
/// as its destination is broadcast to no one and answered by no one, while the
/// send reports success and nothing falls back. Read here as "unknown", the
/// gateway is resolved by the sender before a frame carries it, exactly as an
/// on-link neighbour's address is.
fn resolved_gateway_mac(mac: MacAddr) -> Option<MacAddr> {
    (mac != MacAddr::ZERO).then_some(mac)
}

/// The same six bytes in the type the packet builders take. Two crates spell one
/// address, and this is the single place the spelling changes.
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

    const IFACE_MAC: MacAddr = MacAddr::new(0x02, 0, 0, 0, 0, 0x01);
    const GW_MAC: MacAddr = MacAddr::new(0x02, 0, 0, 0, 0, 0xFE);

    /// en0's address, and what the tests' kernel sources from by default.
    const EN0: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
    /// An address only a tunnel holds.
    const TUNNEL: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));

    fn ethernet_iface() -> InterfaceInfo {
        InterfaceInfo {
            name: "en0".to_string(),
            mac: IFACE_MAC,
            v4: vec![LinkAddress::new(EN0, 24)],
            v6: vec![],
            gateway_v4: Some((Ipv4Addr::new(192, 0, 2, 1), GW_MAC)),
            gateway_v6: None,
        }
    }

    /// A second Ethernet interface, with a gateway of its own.
    fn second_iface() -> InterfaceInfo {
        InterfaceInfo {
            name: "en1".to_string(),
            mac: MacAddr::new(0x02, 0, 0, 0, 0, 0x02),
            v4: vec![LinkAddress::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
                24,
            )],
            v6: vec![],
            gateway_v4: Some((
                Ipv4Addr::new(203, 0, 113, 1),
                MacAddr::new(0x02, 0, 0, 0, 0, 0xFD),
            )),
            gateway_v6: None,
        }
    }

    /// A resolver over `interfaces` and a tunnel holding [`TUNNEL`], whose
    /// kernel sources every destination from `kernel`.
    fn resolver_with(interfaces: Vec<InterfaceInfo>, kernel: Option<IpAddr>) -> NeighborResolver {
        NeighborResolver::from_interfaces(interfaces, vec![TUNNEL], Box::new(move |_| kernel))
    }

    fn resolver(interfaces: Vec<InterfaceInfo>) -> NeighborResolver {
        resolver_with(interfaces, Some(EN0))
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn on_link_target_routes_to_itself_and_needs_arp() {
        let route = resolver(vec![ethernet_iface()])
            .resolve_from(EN0, v4(192, 0, 2, 200))
            .unwrap();

        assert!(route.on_link);
        assert_eq!(route.next_hop, v4(192, 0, 2, 200));
        assert_eq!(route.src_ip, EN0);
        assert_eq!(route.src_mac, IFACE_MAC);
        assert_eq!(route.next_hop_mac, None); // must be ARP-resolved
    }

    /// The off-link arm would otherwise answer for loopback with the default
    /// gateway, and a probe framed to that gateway with `127.0.0.1` in its IP
    /// header is one nothing ever replies to. A port scan reads that silence as
    /// filtered, so the wrong answer here reaches the user as a wrong verdict.
    #[test]
    fn loopback_has_no_ethernet_route() {
        let resolver = resolver(vec![ethernet_iface()]);

        assert!(resolver.resolve(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_none());
        assert!(
            resolver
                .resolve_from(EN0, IpAddr::V4(Ipv4Addr::LOCALHOST))
                .is_none()
        );
        assert!(resolver.resolve(IpAddr::V6(Ipv6Addr::LOCALHOST)).is_none());
        assert!(
            resolver.resolve_from(EN0, v4(127, 0, 0, 53)).is_none(),
            "the whole 127/8 block, not just the one address"
        );
    }

    #[test]
    fn off_link_target_routes_via_gateway_with_known_mac() {
        let route = resolver(vec![ethernet_iface()])
            .resolve_from(EN0, v4(1, 1, 1, 1))
            .unwrap();

        assert!(!route.on_link);
        assert_eq!(route.next_hop, v4(192, 0, 2, 1));
        assert_eq!(route.next_hop_mac, Some(GW_MAC));
        assert_eq!(route.src_ip, EN0);
    }

    #[test]
    fn cached_on_link_mac_is_returned() {
        let mut resolver = resolver(vec![ethernet_iface()]);
        let target = v4(192, 0, 2, 200);
        let learned = MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);

        assert_eq!(
            resolver.resolve_from(EN0, target).unwrap().next_hop_mac,
            None
        );
        resolver.remember("en0", target, learned);
        assert_eq!(
            resolver.resolve_from(EN0, target).unwrap().next_hop_mac,
            Some(learned)
        );
    }

    /// **The frame leaves by the interface the packet's source belongs to.**
    ///
    /// Two Ethernet interfaces with a gateway each, and the probe sourced from
    /// the second: the kernel would send it out of the second, so the frame
    /// does. Picking the first interface with a gateway instead puts the second
    /// interface's address on the first one's wire, where the reply comes back
    /// to an address that link does not hold.
    #[test]
    fn a_probe_leaves_by_the_interface_holding_its_source() {
        let resolver = resolver(vec![ethernet_iface(), second_iface()]);

        let route = resolver
            .resolve_from(v4(203, 0, 113, 50), v4(1, 1, 1, 1))
            .expect("en1 has a gateway");
        assert_eq!(route.interface, "en1");
        assert_eq!(route.next_hop, v4(203, 0, 113, 1));
    }

    /// **A probe the kernel sends through a tunnel has no Ethernet route.**
    ///
    /// Under a VPN the routing table sends a lab target, or everything, through
    /// the tunnel, and the scan sources its probe from the tunnel's address.
    /// Framed onto the physical link instead, the probe reaches the LAN router
    /// with the tunnel's address in it: the target only the tunnel reaches is
    /// never asked, and a full tunnel is bypassed without a word. Refused
    /// here, the send falls back to the socket, and the kernel carries it
    /// through the tunnel.
    #[test]
    fn a_probe_sourced_from_a_tunnel_has_no_ethernet_route() {
        let resolver = resolver(vec![ethernet_iface()]);
        assert!(resolver.resolve_from(TUNNEL, v4(10, 10, 11, 23)).is_none());
    }

    /// The same question without a source: where the routing table would send
    /// the destination through the tunnel, there is no Ethernet route to it.
    #[test]
    fn a_destination_the_kernel_sends_through_a_tunnel_has_no_ethernet_route() {
        let resolver = resolver_with(vec![ethernet_iface()], Some(TUNNEL));
        assert!(resolver.resolve(v4(1, 1, 1, 1)).is_none());

        let direct = resolver_with(vec![ethernet_iface()], Some(EN0));
        assert_eq!(direct.resolve(v4(1, 1, 1, 1)).unwrap().interface, "en0");
    }

    /// A spoofed source, as the idle scan's zombie address is, belongs to no
    /// interface. It leaves the way the kernel would route the destination, and
    /// the route's own address, which an ARP request is sent from, is the
    /// interface's rather than the spoofed one.
    #[test]
    fn a_spoofed_source_leaves_the_way_the_kernel_routes_the_target() {
        let spoofed = v4(198, 51, 100, 77);

        let kernel_says_en1 = resolver_with(
            vec![ethernet_iface(), second_iface()],
            Some(v4(203, 0, 113, 50)),
        );
        let route = kernel_says_en1
            .resolve_from(spoofed, v4(1, 1, 1, 1))
            .expect("the kernel routes it over en1");
        assert_eq!(route.interface, "en1");
        assert_eq!(route.src_ip, v4(203, 0, 113, 50));

        let kernel_says_tunnel = resolver_with(vec![ethernet_iface()], Some(TUNNEL));
        assert!(
            kernel_says_tunnel
                .resolve_from(spoofed, v4(1, 1, 1, 1))
                .is_none()
        );
    }

    /// `netdev` reports a gateway whose MAC it has not learned as all zeros, and
    /// that address is read as "unknown" rather than carried onto the wire.
    #[test]
    fn an_unknown_gateway_mac_is_read_as_unresolved() {
        assert_eq!(resolved_gateway_mac(MacAddr::ZERO), None);
        assert_eq!(resolved_gateway_mac(GW_MAC), Some(GW_MAC));
    }

    /// A gateway with no learned MAC does not send the scan's frames to the
    /// all-zero address `netdev` fills an unresolved neighbour with.
    ///
    /// The default route names the gateway but its hardware address is unknown:
    /// on macOS an IPv6-only default route learns the gateway over IPv6 while
    /// the MAC comes from the IPv4 ARP cache, and any gateway aged out of that
    /// cache when the sender is built looks the same. Carried on as a real next
    /// hop, the zero address is one every frame is addressed to and none is
    /// answered from, the send reports success, and no fallback runs, so the
    /// host reads as down. The route instead comes back asking the sender to
    /// resolve the gateway, the way an on-link neighbour is resolved.
    #[test]
    fn an_off_link_gateway_with_an_unknown_mac_is_resolved_not_sent_to_zeros() {
        let mut iface = ethernet_iface();
        iface.gateway_v4 = Some((Ipv4Addr::new(192, 0, 2, 1), MacAddr::ZERO));

        let route = resolver(vec![iface])
            .resolve_from(EN0, v4(1, 1, 1, 1))
            .expect("a gateway exists, only its MAC is unknown");

        assert!(!route.on_link, "the target is still off-link");
        assert_eq!(
            route.next_hop,
            v4(192, 0, 2, 1),
            "the gateway is the next hop"
        );
        assert_eq!(
            route.next_hop_mac, None,
            "an unknown gateway MAC is resolved, never framed as 00:00:00:00:00:00"
        );
    }

    /// Once the gateway's MAC has been learned it comes back from the cache, so
    /// an unknown-MAC gateway is resolved once and not on every probe after.
    #[test]
    fn a_learned_gateway_mac_is_served_from_the_cache() {
        let mut iface = ethernet_iface();
        iface.gateway_v4 = Some((Ipv4Addr::new(192, 0, 2, 1), MacAddr::ZERO));
        let mut resolver = resolver(vec![iface]);
        let learned = MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);

        assert_eq!(
            resolver
                .resolve_from(EN0, v4(1, 1, 1, 1))
                .unwrap()
                .next_hop_mac,
            None
        );
        resolver.remember("en0", v4(192, 0, 2, 1), learned);
        assert_eq!(
            resolver
                .resolve_from(EN0, v4(1, 1, 1, 1))
                .unwrap()
                .next_hop_mac,
            Some(learned),
            "the gateway is resolved once, then read from the cache"
        );
    }

    #[test]
    fn off_link_without_gateway_is_unresolvable() {
        let mut iface = ethernet_iface();
        iface.gateway_v4 = None;
        assert!(
            resolver(vec![iface])
                .resolve_from(EN0, v4(8, 8, 8, 8))
                .is_none()
        );
    }

    /// A link-local address is valid only on its own segment, so an off-link
    /// probe sourced from one dies at the router; saying so is better than
    /// sending it.
    #[test]
    fn a_link_local_source_has_no_off_link_route() {
        let link_local = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x50));
        let iface = InterfaceInfo {
            name: "en0".to_string(),
            mac: IFACE_MAC,
            v4: vec![],
            v6: vec![LinkAddress::new(link_local, 64)],
            gateway_v4: None,
            gateway_v6: Some((Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), GW_MAC)),
        };

        assert!(
            resolver(vec![iface])
                .resolve_from(
                    link_local,
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
                )
                .is_none()
        );
    }

    /// An off-link IPv6 route is taken from the global address the probe is
    /// sourced from, through the interface's IPv6 gateway.
    #[test]
    fn an_off_link_v6_probe_routes_via_the_v6_gateway() {
        let global = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xb1a0));
        let gateway = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let iface = InterfaceInfo {
            name: "en0".to_string(),
            mac: IFACE_MAC,
            v4: vec![],
            v6: vec![
                LinkAddress::new(
                    IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x50)),
                    64,
                ),
                LinkAddress::new(global, 64),
            ],
            gateway_v4: None,
            gateway_v6: Some((gateway, GW_MAC)),
        };

        let route = resolver(vec![iface])
            .resolve_from(
                global,
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 1)),
            )
            .expect("a host with a v6 gateway has a route");
        assert_eq!(route.src_ip, global);
        assert_eq!(route.next_hop, IpAddr::V6(gateway));
    }

    #[test]
    fn no_ethernet_interfaces_resolves_nothing() {
        let resolver = resolver(vec![]);
        assert!(!resolver.has_ethernet());
        assert!(resolver.resolve(v4(1, 1, 1, 1)).is_none());
    }

    /// A heard address serves until it ages out, on its own interface only.
    #[test]
    fn a_heard_neighbour_serves_until_it_ages_out_on_its_own_link() {
        let mut table = LearnedNeighbors::new();
        let t0 = Instant::now();
        let mac = MacAddr::new(0x02, 0, 0, 0, 0, 0x40);
        let address = v4(192, 0, 2, 40);

        assert_eq!(table.recall("en0", address, t0), None, "nothing heard yet");
        table.learn("en0", address, mac, t0);
        assert_eq!(table.recall("en0", address, t0), Some(mac));
        assert_eq!(
            table.recall(
                "en0",
                address,
                t0 + LEARNED_NEIGHBOR_TTL - Duration::from_secs(1)
            ),
            Some(mac)
        );
        assert_eq!(
            table.recall("en0", address, t0 + LEARNED_NEIGHBOR_TTL),
            None,
            "aged out"
        );
        assert_eq!(table.recall("en1", address, t0), None, "another link");
    }

    /// No neighbour holds a broadcast or multicast address, so neither is
    /// taken as one; framing a probe to it would reach the whole segment.
    #[test]
    fn a_group_address_is_not_learned_as_a_neighbour() {
        let address = v4(192, 0, 2, 41);
        learn_neighbor("test-group0", address, MacAddr::BROADCAST);
        learn_neighbor("test-group0", address, MacAddr::new(0x01, 0, 0x5e, 0, 0, 1));
        assert_eq!(learned_neighbor("test-group0", address), None);
    }
}
