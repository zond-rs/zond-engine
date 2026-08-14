// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Source Address Selection
//!
//! Answers a single question the raw-socket scanners keep asking: given a
//! destination, which of this host's addresses should a packet to it be sent
//! *from*? For a raw Layer-4 socket the kernel fills in the IP header's
//! source, but it does **not** compute the TCP checksum - so the source we
//! feed into the pseudo-header has to match the one the kernel will route the
//! packet out with, or the target silently drops it.
//!
//! Two access patterns share the machinery here:
//!
//! - **Bulk, up-front** ([`crate::system::interface::map_ips_to_interfaces`]):
//!   thousands of distinct targets classified once, in parallel. Callers reuse
//!   [`ProbeSockets`] per worker thread and match on-link targets against an
//!   [`OnLinkTable`].
//! - **Streaming, one-at-a-time** (the SYN port scanner): targets trickle in,
//!   with the *same* host revisited across many ports. [`SourceResolver`]
//!   wraps the same primitives behind a per-destination cache so that repeat
//!   is a single lookup rather than a fresh kernel probe each time.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};

use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

/// The interfaces usable as a probe source: up, not loopback, and holding at
/// least one assigned address. Centralizes a filter that source selection,
/// interface prioritization, and target routing would otherwise each repeat.
pub(crate) fn viable_interfaces() -> Vec<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        .collect()
}

/// The host's on-link subnets paired with the local address to source from
/// when a destination falls inside one, ordered most-specific-first so the
/// longest matching prefix wins. A destination on the same segment is reached
/// directly, so its source is simply this host's address on that segment - no
/// kernel round-trip required.
pub struct OnLinkTable {
    v4: Vec<(Ipv4Network, Ipv4Addr)>,
    v6: Vec<(Ipv6Network, Ipv6Addr)>,
}

impl OnLinkTable {
    /// Builds the table from every address assigned to `interfaces`.
    pub fn from_interfaces(interfaces: &[NetworkInterface]) -> Self {
        let mut v4: Vec<(Ipv4Network, Ipv4Addr)> = Vec::new();
        let mut v6: Vec<(Ipv6Network, Ipv6Addr)> = Vec::new();

        for iface in interfaces {
            for net in &iface.ips {
                match net {
                    IpNetwork::V4(n) => v4.push((*n, n.ip())),
                    IpNetwork::V6(n) => v6.push((*n, n.ip())),
                }
            }
        }

        v4.sort_by_key(|(net, _)| std::cmp::Reverse(net.prefix()));
        v6.sort_by_key(|(net, _)| std::cmp::Reverse(net.prefix()));

        Self { v4, v6 }
    }

    /// Returns the source address for `target` if it sits on one of the
    /// host's own subnets, or `None` if it has to be routed off-link.
    pub fn source_for(&self, target: IpAddr) -> Option<IpAddr> {
        match target {
            IpAddr::V4(t) => self
                .v4
                .iter()
                .find(|(net, _)| net.contains(t))
                .map(|(_, src)| IpAddr::V4(*src)),
            IpAddr::V6(t) => self
                .v6
                .iter()
                .find(|(net, _)| net.contains(t))
                .map(|(_, src)| IpAddr::V6(*src)),
        }
    }

    /// Whether the host has any assigned address to source from at all.
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// Lazily-created UDP sockets used to ask the kernel for a route's source
/// address, kept one per family so a caller can amortize the bind across many
/// probes. Cheap to default-construct and hand to a worker thread.
#[derive(Default)]
pub struct ProbeSockets {
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
}

/// Picks an address on `interfaces` that could plausibly reach `target` when
/// the kernel's own route lookup has declined to answer.
///
/// A refusal is not always the truth about reachability. A VPN that claims the
/// IPv6 default route without carrying IPv6 makes every off-link IPv6 lookup
/// fail while the host still holds a global address on a segment with a working
/// router — measured on the machine this was written on, where `connect` to
/// every public resolver returned `No route to host` and the same addresses
/// answered in 22 ms once a source was named explicitly.
///
/// What follows from that is not that the kernel is wrong, but that giving up
/// here is worse than trying. A probe sourced from an address the host really
/// holds either reaches the target or does not, and either way the scan reports
/// what it observed. Giving up produces a scan that reports nothing and blames
/// the network.
///
/// Scope-matched, since an address of the wrong scope cannot reach the target
/// whatever the routing table says: a global destination needs a global source,
/// and a link-local destination needs the link-local address of the interface it
/// is on.
pub(crate) fn plausible_source(interfaces: &[NetworkInterface], target: IpAddr) -> Option<IpAddr> {
    let IpAddr::V6(target_v6) = target else {
        // IPv4 has no equivalent failure worth second-guessing: there is one
        // scope, and a kernel that cannot route a v4 address is describing a
        // host with no v4 connectivity.
        return None;
    };

    let wants_link_local = target_v6.is_unicast_link_local();
    interfaces
        .iter()
        .flat_map(|iface| iface.ips.iter())
        .filter_map(|net| match net.ip() {
            IpAddr::V6(addr) => Some(addr),
            IpAddr::V4(_) => None,
        })
        .find(|addr| addr.is_unicast_link_local() == wants_link_local && !addr.is_loopback())
        .map(IpAddr::V6)
}

/// Asks the kernel which local address it would route a packet to `target`
/// from, by `connect`-ing an unbound UDP socket to it and reading back the
/// address the routing layer selected. No datagram is ever sent - `connect`
/// on a UDP socket only performs the route lookup and binds the local end.
///
/// `sockets` caches one socket per address family so repeated probes reuse it.
pub fn probe_route_source(target: IpAddr, sockets: &mut ProbeSockets) -> Option<IpAddr> {
    let slot = match target {
        IpAddr::V4(_) => &mut sockets.v4,
        IpAddr::V6(_) => &mut sockets.v6,
    };

    if slot.is_none() {
        let bind_addr = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        *slot = UdpSocket::bind(bind_addr).ok();
    }

    let socket = slot.as_ref()?;
    socket.connect((target, 53)).ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

/// Resolves the source address for arbitrary destinations seen one at a time,
/// memoizing each answer. Built for the streaming SYN port scanner, where the
/// same host recurs across every port it probes: the first probe to a host
/// does the work, and every later port reuses the cached result.
///
/// Three sources, in descending order of confidence. On-link destinations are
/// answered from an in-memory table of each interface's own subnets. Everything
/// else is put to the kernel, by connecting a UDP socket to the target and
/// reading back the address it chose — which asks the routing table without
/// sending a packet. When the kernel declines, the last resort is any address
/// on an interface that could plausibly carry the traffic.
pub struct SourceResolver {
    onlink: OnLinkTable,
    sockets: ProbeSockets,
    cache: HashMap<IpAddr, Option<IpAddr>>,
    /// The interfaces themselves, kept for [`plausible_source`]. The
    /// [`OnLinkTable`] cannot answer for it: that table matches a destination
    /// against a prefix, and the case this exists for is a destination on no
    /// prefix this host holds.
    interfaces: Vec<NetworkInterface>,
}

impl SourceResolver {
    /// Builds a resolver from the host's current viable interfaces.
    pub fn from_system() -> Self {
        Self::from_interfaces(&viable_interfaces())
    }

    /// Builds a resolver from an explicit interface list (used in tests).
    pub fn from_interfaces(interfaces: &[NetworkInterface]) -> Self {
        Self {
            onlink: OnLinkTable::from_interfaces(interfaces),
            sockets: ProbeSockets::default(),
            cache: HashMap::new(),
            interfaces: interfaces.to_vec(),
        }
    }

    /// Whether this host has any address to send probes from. When false,
    /// there is no point standing up a raw-socket scanner at all.
    pub fn has_sources(&self) -> bool {
        !self.onlink.is_empty()
    }

    /// Returns the source address to send a probe to `target` from, or `None`
    /// if no address on this host could plausibly reach it.
    ///
    /// Three answers in order of authority: this host's own segments, then the
    /// kernel's routing table, then `plausible_source` for the case where the
    /// kernel refuses but the host visibly holds an address of the right scope.
    pub fn resolve(&mut self, target: IpAddr) -> Option<IpAddr> {
        if let Some(cached) = self.cache.get(&target) {
            return *cached;
        }

        let source = self
            .onlink
            .source_for(target)
            .or_else(|| probe_route_source(target, &mut self.sockets))
            .or_else(|| plausible_source(&self.interfaces, target));

        self.cache.insert(target, source);
        source
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn mock_interface(nets: Vec<IpNetwork>) -> NetworkInterface {
        NetworkInterface {
            name: "test0".to_string(),
            description: "".to_string(),
            index: 0,
            mac: None,
            ips: nets,
            flags: 0,
        }
    }

    fn v4net(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> IpNetwork {
        IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(a, b, c, d), prefix).unwrap())
    }

    #[test]
    fn on_link_target_uses_that_subnet_source() {
        let intf = mock_interface(vec![v4net(192, 168, 1, 50, 24)]);
        let table = OnLinkTable::from_interfaces(&[intf]);

        assert_eq!(
            table.source_for(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200))),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)))
        );
    }

    #[test]
    fn off_link_target_has_no_on_link_source() {
        let intf = mock_interface(vec![v4net(192, 168, 1, 50, 24)]);
        let table = OnLinkTable::from_interfaces(&[intf]);

        assert_eq!(
            table.source_for(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            None
        );
    }

    #[test]
    fn longest_prefix_wins() {
        let intf = mock_interface(vec![v4net(10, 0, 0, 1, 8), v4net(10, 1, 2, 3, 24)]);
        let table = OnLinkTable::from_interfaces(&[intf]);

        assert_eq!(
            table.source_for(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 200))),
            Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))
        );
    }

    #[test]
    fn v6_and_v4_are_kept_separate() {
        let v6 = IpNetwork::V6(
            Ipv6Network::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64).unwrap(),
        );
        let intf = mock_interface(vec![v4net(192, 168, 1, 50, 24), v6]);
        let table = OnLinkTable::from_interfaces(&[intf]);

        assert_eq!(
            table.source_for(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 99))),
            Some(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)))
        );
        assert_eq!(
            table.source_for(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            None
        );
    }

    #[test]
    fn resolver_caches_and_reports_sources() {
        let intf = mock_interface(vec![v4net(192, 168, 1, 50, 24)]);
        let mut resolver = SourceResolver::from_interfaces(&[intf]);

        assert!(resolver.has_sources());
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
        assert_eq!(
            resolver.resolve(target),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)))
        );
        assert_eq!(
            resolver.resolve(target),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)))
        );
    }

    #[test]
    fn empty_host_has_no_sources() {
        let resolver = SourceResolver::from_interfaces(&[]);
        assert!(!resolver.has_sources());
    }

    fn v6net(addr: Ipv6Addr, prefix: u8) -> IpNetwork {
        IpNetwork::V6(Ipv6Network::new(addr, prefix).unwrap())
    }

    /// The §1.6 case: the kernel refuses to route an off-link IPv6 target - a
    /// VPN holding the default route without carrying IPv6 - while the host
    /// plainly has a global address to send from.
    ///
    /// Answering `None` here is what made a scan of seven live addresses report
    /// zero hosts in two milliseconds, having sent nothing. The address chosen
    /// may not work, and the scan will say so; refusing to try cannot.
    #[test]
    fn a_global_target_the_kernel_will_not_route_still_gets_a_global_source() {
        let global = Ipv6Addr::new(0x2a02, 0x908, 0, 0, 0, 0, 0, 0xb1a0);
        let intf = mock_interface(vec![
            v6net(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x50), 64),
            v6net(global, 64),
        ]);

        let source = plausible_source(
            std::slice::from_ref(&intf),
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
        );

        assert_eq!(source, Some(IpAddr::V6(global)));
    }

    /// Scope is not negotiable in the other direction either: a link-local
    /// destination is reachable only from a link-local address, so a global one
    /// must not be offered for it.
    #[test]
    fn a_link_local_target_gets_a_link_local_source() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x50);
        let intf = mock_interface(vec![
            v6net(Ipv6Addr::new(0x2a02, 0x908, 0, 0, 0, 0, 0, 1), 64),
            v6net(link_local, 64),
        ]);

        let source = plausible_source(
            std::slice::from_ref(&intf),
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA)),
        );

        assert_eq!(source, Some(IpAddr::V6(link_local)));
    }

    /// IPv4 keeps the kernel's answer. It has one scope and no equivalent of a
    /// tunnel swallowing the default route for a family it does not carry, so
    /// second-guessing it would invent a source where the host genuinely has
    /// none.
    #[test]
    fn an_unroutable_v4_target_is_not_second_guessed() {
        let intf = mock_interface(vec![v4net(192, 168, 1, 50, 24)]);

        assert_eq!(
            plausible_source(
                std::slice::from_ref(&intf),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
            ),
            None
        );
    }
}
