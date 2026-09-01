// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What the scan can conclude without asking again
//!
//! Three of a host's roles need no probe of their own: two are already written
//! down on the machine the scan runs from, and the third is already in the
//! record, put there by something that was measuring a different thing.
//!
//! - **[`Origin`]**: the address belongs to one of this machine's own
//!   interfaces. A sweep of your own segment always contains you, and the
//!   record it produces is unlike every other one in it.
//! - **[`Router`], from the routing table**: the address is a default gateway
//!   of an interface the scan runs on. Something is only a gateway because it
//!   forwards, and on an IPv4-only segment this is the only proof of that the
//!   engine can obtain by asking: ARP has no equivalent of the neighbour
//!   advertisement's R flag, and no equivalent of a router advertisement.
//! - **[`Router`], from a measured path**: the address answered from inside
//!   somebody else's route. A hop is recorded because a probe aimed past it
//!   expired there, which means it decremented a hop limit on a packet
//!   addressed to another machine. That is not evidence *about* routing; it is
//!   routing, observed.
//!
//! ## Read once, applied once
//!
//! This runs as a pass over the finished store rather than as a check inside
//! each strategy. A host's addresses arrive from several strategies over the
//! life of a scan, and asking the question at the end is the only point where
//! all of them are on the record: a check at creation time would miss the
//! second address of a dual-stack host, which is exactly the address a gateway
//! is most likely to be found under. The path source needs the same ordering
//! for a stronger reason: a trace runs late, so a check anywhere earlier would
//! read paths that had not been measured yet.
//!
//! ## Link-local addresses carry the interface they were read on
//!
//! `fe80::1` is a different router on every segment, so a gateway address in
//! that range is only this host's gateway when the host was seen through the
//! same interface the route was read from. Without that check, a scan across
//! two links would mark a neighbour on the second as the router of the first.
//! An address that names one machine everywhere needs no such qualification and
//! carries none.
//!
//! [`Origin`]: NetworkRole::Origin
//! [`Router`]: NetworkRole::Router

use std::collections::HashSet;
use std::net::IpAddr;

use crate::model::host::{Host, NetworkRole};
use crate::model::ip::scoped::{ScopedIp, Zone};
use crate::scanner::session::ScanContext;

/// One interface's addressing, reduced to what a role can be read from.
///
/// The seam that keeps this module testable. Everything below works on these,
/// and [`Vantage::from_system`] is the only place that knows they come from
/// `netdev`, so the rules can be exercised against a segment that does not
/// exist, on a machine with whatever interfaces it happens to have.
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
    /// A zoned address seen through no interface at all does *not* match: the
    /// scan cannot say which segment such a record came from, and guessing
    /// would put the router marking on a stranger.
    fn matches(&self, ip: IpAddr, zone: Option<u32>) -> bool {
        self.ip == ip && (self.zone.is_none() || self.zone == zone)
    }
}

/// What this machine's own configuration says about the network it is scanning.
///
/// Both lists are short, an interface holds a handful of addresses and a
/// routing table a handful of default routes, so they are walked rather than
/// hashed. A set would be the faster structure for the lookup and the wrong one
/// for the comparison: matching a link-local address means comparing its zone
/// too, which is not part of its identity as an address.
pub(super) struct Vantage {
    own: Vec<Located>,
    gateways: Vec<Located>,
}

impl Vantage {
    /// Reads this machine's interfaces and routing table.
    pub(super) fn from_system() -> Self {
        Self::from_interfaces(netdev::get_interfaces().into_iter().map(|iface| {
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

    /// Whether this machine's configuration says anything about any host at
    /// all, so a scan on a machine with no addresses skips the pass.
    fn is_empty(&self) -> bool {
        self.own.is_empty() && self.gateways.is_empty()
    }

    /// Records against `host` whatever this machine's configuration
    /// establishes, returning whether anything was added.
    ///
    /// Asked of every address the host is known by rather than of the one it
    /// leads with: a router answering at both an IPv4 address and a link-local
    /// one is a single record, and which of the two names it is decided by
    /// [`Host::consider_primary_ip`] on grounds that have nothing to do with
    /// which of them the routing table holds.
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
/// Runs at the end of a scan, once every strategy has contributed the addresses
/// it found and any trace has run. Sends nothing, so there is no setting to
/// turn it off and no reason to want one.
pub(super) fn attribute(ctx: &ScanContext) {
    let vantage = Vantage::from_system();
    let forwarders = forwarders(ctx);
    if vantage.is_empty() && forwarders.is_empty() {
        return;
    }

    // A snapshot of the keys, because `write_host` takes the store's own lock
    // and holding an iterator across it deadlocks on whichever shard the
    // iterator is on.
    for ip in ctx.host_addresses() {
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
/// Read out of the paths already in the store rather than probed for: a
/// traceroute is run to answer "how do I reach this host", and the same replies
/// say "these machines route", which nothing was reading. Empty unless a trace
/// ran, which is off by default, so this costs one walk of the store on a scan
/// that measured no paths at all.
///
/// **A hop is only a router to somebody else.** A completed trace records its
/// own target as the last hop, at the distance it was reached, so a path's
/// hops are read against the host whose path it is, and its own addresses are
/// left out. Without that, every traced host would be reported as a router, and
/// the reader could not tell the routers from the destinations.
fn forwarders(ctx: &ScanContext) -> HashSet<IpAddr> {
    let mut forwarders = HashSet::new();

    for address in ctx.host_addresses() {
        // Read under the store's own guard, one host at a time, so a scan of
        // thousands never clones the store to ask a question about it.
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

    /// One interface with an address of ours and a router beyond it, which is
    /// every ordinary machine.
    fn lan() -> Interface {
        Interface {
            index: LAN,
            addresses: vec![ip("192.168.1.50"), ip("fe80::50")],
            gateways: vec![ip("192.168.1.1"), ip("fe80::1")],
        }
    }

    fn host_at(address: &str) -> Host {
        Host::new(ip(address))
    }

    /// The whole of what this pass claims: our own address is the scan's
    /// origin, and the address we route through forwards.
    #[test]
    fn this_machine_and_its_gateway_are_named_from_the_routing_table() {
        let vantage = Vantage::from_interfaces([lan()]);

        let mut ourselves = host_at("192.168.1.50");
        assert!(vantage.attribute(&mut ourselves));
        assert!(ourselves.network_roles().contains(&NetworkRole::Origin));
        assert!(!ourselves.network_roles().contains(&NetworkRole::Router));

        let mut gateway = host_at("192.168.1.1");
        assert!(vantage.attribute(&mut gateway));
        assert!(gateway.network_roles().contains(&NetworkRole::Router));

        let mut neighbour = host_at("192.168.1.20");
        assert!(!vantage.attribute(&mut neighbour));
        assert!(neighbour.network_roles().is_empty());
    }

    /// A host is a record, not an address. A router found over IPv6 and again
    /// over IPv4 is one host whose primary address is chosen on other grounds,
    /// so the question has to be put to every address it answers at.
    #[test]
    fn a_gateway_is_recognised_by_any_of_the_addresses_it_answers_at() {
        let vantage = Vantage::from_interfaces([lan()]);

        let mut dual_stack = host_at("2001:db8::1");
        dual_stack.add_ip(ip("192.168.1.1"));

        assert!(vantage.attribute(&mut dual_stack));
        assert!(dual_stack.network_roles().contains(&NetworkRole::Router));
    }

    /// `fe80::1` is a different router on every segment. A scan that reached
    /// two links would otherwise mark a neighbour on the second as the router
    /// of the first, and a record with no interface on it cannot say which
    /// link it came from at all, so it is left alone rather than guessed at.
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

    /// A scan run from the router itself is both, and neither claim displaces
    /// the other.
    #[test]
    fn a_scan_run_from_the_router_reports_the_address_as_both() {
        let vantage = Vantage::from_interfaces([Interface {
            index: LAN,
            addresses: vec![ip("192.168.1.1")],
            gateways: vec![ip("192.168.1.1")],
        }]);

        let mut host = host_at("192.168.1.1");
        assert!(vantage.attribute(&mut host));
        assert!(host.network_roles().contains(&NetworkRole::Origin));
        assert!(host.network_roles().contains(&NetworkRole::Router));
    }

    /// A hop is a router to whoever was behind it, and never to itself.
    ///
    /// Both halves are load-bearing. A completed trace records its own target
    /// as the last hop, at the distance it was reached, so reading hops
    /// without regard to whose path they are in reports every traced host as a
    /// router, and a reader can no longer tell the routers from the
    /// destinations. The addresses are documentation ranges (RFC 5737), which
    /// no interface on the machine running this test can hold, so the routing
    /// table has nothing to say about either of them.
    #[tokio::test]
    async fn a_hop_in_somebody_elses_path_is_a_router_and_a_trace_target_is_not() {
        use crate::model::host::Hop;
        use crate::scanner::session::ScanSession;

        let router = ip("198.51.100.1");
        let target = ip("192.0.2.10");

        let (session, ctx) = ScanSession::new();

        ctx.write_host(target, |host| {
            host.record_hop(Hop::answered(1, router, None));
            // The trace reached the target, which is recorded as its own last
            // hop.
            host.record_hop(Hop::answered(2, target, None));
            true
        });
        // The router is in the scanned range too, which is what gives it a
        // record for the role to land on.
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
