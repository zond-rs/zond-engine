// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What the scan can conclude without asking again
//!
//! Three of a host's roles need no probe of their own: two come from this
//! machine's configuration, and the third from paths the scan already traced.
//!
//! - **[`Origin`]**: the address belongs to one of this machine's interfaces.
//! - **[`Router`], from the routing table**: the address is a default gateway of
//!   an interface the scan runs on. On an IPv4-only segment this is the only
//!   proof of forwarding available, since ARP has nothing like the neighbour
//!   advertisement's R flag or a router advertisement.
//! - **[`Router`], from a measured path**: a probe aimed past the address expired
//!   there, so it decremented the hop limit of a packet addressed to another
//!   machine.
//!
//! ## Timing
//!
//! This runs as one pass over the finished store. A host's addresses arrive from
//! several strategies over a scan, and only at the end are all of them recorded;
//! the second address of a dual-stack host is often the one a gateway is found
//! under. Traces also run late, so their paths exist only then.
//!
//! ## Link-local addresses
//!
//! `fe80::1` is a different router on every segment, so a link-local gateway only
//! matches a host seen through the interface the route was read from. Otherwise a
//! scan across two links would mark a neighbour on one as the router of the other.
//!
//! [`Origin`]: NetworkRole::Origin
//! [`Router`]: NetworkRole::Router

use std::collections::HashSet;
use std::net::IpAddr;

use crate::model::host::{Host, NetworkRole};
use crate::model::ip::scoped::{ScopedIp, Zone};
use crate::scanner::session::ScanContext;
use crate::system::interface::host_table;

/// One interface's addressing, reduced to what a role can be read from.
///
/// Only [`Vantage::from_system`] knows these come from `netdev`, so tests can
/// build segments that do not exist.
#[derive(Debug, Clone)]
struct Interface {
    /// The index a scoped address names, matching [`Zone::index`].
    index: u32,
    /// Every address assigned to it.
    addresses: Vec<IpAddr>,
    /// Its default gateways, of either family.
    gateways: Vec<IpAddr>,
}

/// An address this machine's configuration names, and where it names it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Located {
    ip: IpAddr,
    /// The interface index this address is only meaningful on, or `None` for
    /// one that names the same machine wherever it is seen.
    zone: Option<u32>,
}

impl Located {
    fn new(ip: IpAddr, interface: u32) -> Self {
        let zone = ScopedIp::needs_zone(&ip).then_some(interface);
        Self { ip, zone }
    }

    /// Whether `ip`, seen through `zone`, is this address.
    ///
    /// A zoned address seen through no interface does not match, since the scan
    /// cannot say which segment the record came from.
    fn matches(&self, ip: IpAddr, zone: Option<u32>) -> bool {
        self.ip == ip && (self.zone.is_none() || self.zone == zone)
    }
}

/// What this machine's own configuration says about the network it is scanning.
///
/// Both lists are short and walked linearly; matching a link-local address
/// compares its zone too, which a set keyed on the address would miss.
pub(super) struct Vantage {
    own: Vec<Located>,
    gateways: Vec<Located>,
}

impl Vantage {
    /// Reads this machine's interfaces and routing table.
    pub(super) fn from_system() -> Self {
        Self::from_interfaces(host_table().unwrap_or_default().into_iter().map(|iface| {
            let mut addresses: Vec<IpAddr> = iface
                .ipv4
                .iter()
                .map(|net| IpAddr::V4(net.addr()))
                .collect();
            addresses.extend(iface.ipv6.iter().map(|net| IpAddr::V6(net.addr())));

            let gateways = iface.gateway.map_or_else(Vec::new, |gw| {
                let mut ips: Vec<IpAddr> = gw.ipv4.into_iter().map(IpAddr::V4).collect();
                ips.extend(gw.ipv6.into_iter().map(IpAddr::V6));
                ips
            });

            Interface {
                index: iface.index,
                addresses,
                gateways,
            }
        }))
    }

    fn from_interfaces(interfaces: impl IntoIterator<Item = Interface>) -> Self {
        let mut own = Vec::new();
        let mut gateways = Vec::new();

        for iface in interfaces {
            own.extend(
                iface
                    .addresses
                    .into_iter()
                    .map(|ip| Located::new(ip, iface.index)),
            );
            gateways.extend(
                iface
                    .gateways
                    .into_iter()
                    .map(|ip| Located::new(ip, iface.index)),
            );
        }

        Self { own, gateways }
    }

    /// Whether there is nothing to match, so the pass can be skipped.
    fn is_empty(&self) -> bool {
        self.own.is_empty() && self.gateways.is_empty()
    }

    /// Records against `host` whatever this machine's configuration
    /// establishes, returning whether anything was added.
    ///
    /// Checks every address the host is known by, since its primary address is
    /// chosen by [`Host::consider_primary_ip`] on unrelated grounds.
    fn attribute(&self, host: &mut Host) -> bool {
        let zone = host.zone().and_then(Zone::index);

        let mut recorded = false;
        for ip in host.ips().iter().copied().collect::<Vec<_>>() {
            if self.own.iter().any(|own| own.matches(ip, zone)) {
                recorded |= host.add_network_role(NetworkRole::Origin);
            }
            if self.gateways.iter().any(|gw| gw.matches(ip, zone)) {
                recorded |= host.add_network_role(NetworkRole::Router);
            }
        }

        recorded
    }
}

/// Marks every host in `ctx` that this machine's configuration, or the scan's
/// own measurements, have something to say about.
///
/// Runs at the end of a scan, after every strategy and any trace. Sends nothing.
pub(super) fn attribute(ctx: &ScanContext) {
    let vantage = Vantage::from_system();
    let forwarders = forwarders(ctx);
    if vantage.is_empty() && forwarders.is_empty() {
        return;
    }

    // A snapshot of the keys: holding a store iterator across `write_host`
    // deadlocks on the iterator's shard.
    for ip in ctx.host_addresses() {
        // A host finished in an earlier sitting was attributed then; rewrite it
        // only if a path traced since names it a router.
        let rereads = ctx
            .read_host(&ip, |host| {
                ctx.owes_passes(host) || host.ips().iter().any(|ip| forwarders.contains(ip))
            })
            .unwrap_or(false);
        if !rereads {
            continue;
        }
        ctx.write_host(ip, |host| {
            let mut recorded = vantage.attribute(host);

            if host.ips().iter().any(|ip| forwarders.contains(ip)) {
                recorded |= host.add_network_role(NetworkRole::Router);
            }

            recorded
        });
    }
}

/// Every address the scan watched forward a packet.
///
/// Read from the paths already in the store. Empty unless a trace ran (off by
/// default), in which case it costs one walk of the store.
///
/// A completed trace records its own target as the last hop, so each path's own
/// host addresses are left out; otherwise every traced host would be a router.
fn forwarders(ctx: &ScanContext) -> HashSet<IpAddr> {
    let mut forwarders = HashSet::new();

    for address in ctx.host_addresses() {
        // One host at a time under the store's guard, to avoid cloning the store.
        ctx.read_host(&address, |host| {
            for hop in host.path().hops() {
                if let Some(hop) = hop.address().filter(|hop| !host.ips().contains(hop)) {
                    forwarders.insert(hop);
                }
            }
        });
    }

    forwarders
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

    const LAN: u32 = 3;
    const OTHER_LINK: u32 = 7;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("a literal address")
    }

    /// One interface with an address of ours and a router beyond it.
    fn lan() -> Interface {
        Interface {
            index: LAN,
            addresses: vec![ip("203.0.113.50"), ip("fe80::50")],
            gateways: vec![ip("203.0.113.1"), ip("fe80::1")],
        }
    }

    fn host_at(address: &str) -> Host {
        Host::new(ip(address))
    }

    /// Our own address is the origin and our gateway is a router.
    #[test]
    fn this_machine_and_its_gateway_are_named_from_the_routing_table() {
        let vantage = Vantage::from_interfaces([lan()]);

        let mut ourselves = host_at("203.0.113.50");
        assert!(vantage.attribute(&mut ourselves));
        assert!(ourselves.network_roles().contains(&NetworkRole::Origin));
        assert!(!ourselves.network_roles().contains(&NetworkRole::Router));

        let mut gateway = host_at("203.0.113.1");
        assert!(vantage.attribute(&mut gateway));
        assert!(gateway.network_roles().contains(&NetworkRole::Router));

        let mut neighbour = host_at("203.0.113.20");
        assert!(!vantage.attribute(&mut neighbour));
        assert!(neighbour.network_roles().is_empty());
    }

    /// A dual-stack router is matched by any of its addresses, whichever is
    /// primary.
    #[test]
    fn a_gateway_is_recognised_by_any_of_the_addresses_it_answers_at() {
        let vantage = Vantage::from_interfaces([lan()]);

        let mut dual_stack = host_at("2001:db8::1");
        dual_stack.add_ip(ip("203.0.113.1"));

        assert!(vantage.attribute(&mut dual_stack));
        assert!(dual_stack.network_roles().contains(&NetworkRole::Router));
    }

    /// `fe80::1` is a different router on every segment. A record with no
    /// interface cannot say which link it came from, so it is left alone.
    #[test]
    fn a_link_local_gateway_is_only_the_router_of_the_link_it_was_read_on() {
        let vantage = Vantage::from_interfaces([lan()]);

        let mut here = host_at("fe80::1");
        here.set_zone(Zone::new(LAN, "en0"));
        assert!(vantage.attribute(&mut here));
        assert!(here.network_roles().contains(&NetworkRole::Router));

        let mut elsewhere = host_at("fe80::1");
        elsewhere.set_zone(Zone::new(OTHER_LINK, "en1"));
        assert!(!vantage.attribute(&mut elsewhere));
        assert!(elsewhere.network_roles().is_empty());

        let mut unscoped = host_at("fe80::1");
        assert!(!vantage.attribute(&mut unscoped));
        assert!(unscoped.network_roles().is_empty());
    }

    /// A scan run from the router itself records both roles.
    #[test]
    fn a_scan_run_from_the_router_reports_the_address_as_both() {
        let vantage = Vantage::from_interfaces([Interface {
            index: LAN,
            addresses: vec![ip("203.0.113.1")],
            gateways: vec![ip("203.0.113.1")],
        }]);

        let mut host = host_at("203.0.113.1");
        assert!(vantage.attribute(&mut host));
        assert!(host.network_roles().contains(&NetworkRole::Origin));
        assert!(host.network_roles().contains(&NetworkRole::Router));
    }

    /// A hop is a router to whoever was behind it, never to itself; a completed
    /// trace records its target as the last hop. The addresses are RFC 5737
    /// documentation ranges, so the test machine's routing table cannot match
    /// them.
    #[tokio::test]
    async fn a_hop_in_somebody_elses_path_is_a_router_and_a_trace_target_is_not() {
        use crate::model::host::Hop;
        use crate::scanner::session::ScanSession;

        let router = ip("198.51.100.1");
        let target = ip("192.0.2.10");

        let (session, ctx) = ScanSession::new();

        ctx.write_host(target, |host| {
            host.record_hop(Hop::answered(1, router, None));
            // The trace reached the target, recorded as its own last hop.
            host.record_hop(Hop::answered(2, target, None));
            true
        });
        // The router is in the scanned range too, so it has a record.
        ctx.write_host(router, |_| true);

        attribute(&ctx);

        let hosts = session.hosts();
        assert!(
            hosts
                .get(router)
                .expect("the router was scanned")
                .network_roles()
                .contains(&NetworkRole::Router),
            "a probe aimed past it expired there, which is forwarding"
        );
        assert!(
            !hosts
                .get(target)
                .expect("the target was scanned")
                .network_roles()
                .contains(&NetworkRole::Router),
            "the end of a path is where the packet was going, not a hop through"
        );
    }
}
