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
use std::net::{IpAddr, UdpSocket};

use crate::model::ip::scoped::{ScopedIp, ZoneMap};
use crate::system::descriptors;
use crate::system::interface::{Link, LinkAddress};

/// The links usable as a probe source: up, not loopback, and holding at least
/// one assigned address. Centralizes a filter that source selection, interface
/// prioritization, and target routing would otherwise each repeat.
pub(crate) fn viable_interfaces() -> Vec<Link> {
    crate::system::interface::interfaces()
        .into_iter()
        .filter(|link| link.is_up() && !link.is_loopback() && !link.addresses().is_empty())
        .collect()
}

/// The host's own addresses, ordered most-specific-first so that the longest
/// matching prefix wins.
///
/// A destination on the same segment is reached directly, so its source is
/// simply this host's address on that segment: no kernel round-trip required.
///
/// One list rather than one per family, because a [`LinkAddress`] already knows
/// which family it is and declines a target of the other. Sorting the two
/// together is harmless for the same reason: the order only has to hold *within*
/// a family, and a v6 `/64` sitting between two v4 prefixes is never a candidate
/// for a v4 target to begin with.
pub struct OnLinkTable {
    held: Vec<LinkAddress>,
}

impl OnLinkTable {
    /// Builds the table from every address assigned to `links`.
    pub fn from_links(links: &[Link]) -> Self {
        let mut held: Vec<LinkAddress> = links
            .iter()
            .flat_map(|link| link.addresses().iter().copied())
            .collect();

        held.sort_by_key(|address| std::cmp::Reverse(address.prefix()));

        Self { held }
    }

    /// Returns the source address for `target` if it sits on one of the host's
    /// own subnets, or `None` if it has to be routed off-link.
    ///
    /// A link-local target answers `None`. Every interface holds an
    /// `fe80::/64`, so such a target matches all of them and identifies none,
    /// and the first match would be decided by whatever order the host listed
    /// its interfaces in. [`RoutedTargets::ambiguous`](super::RoutedTargets) is
    /// the same refusal made earlier and with a reason the caller can read.
    ///
    /// A target that named its interface is answered before this table is
    /// consulted, from the interface it named. See
    /// [`SourceResolver::with_zones`](super::SourceResolver::with_zones).
    pub fn source_for(&self, target: IpAddr) -> Option<IpAddr> {
        if ScopedIp::needs_zone(&target) {
            return None;
        }

        self.held
            .iter()
            .find(|held| held.contains(&target))
            .map(LinkAddress::address)
    }

    /// Whether the host has any assigned address to source from at all.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
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
/// router: measured on the machine this was written on, where `connect` to
/// every public resolver returned `No route to host` and the same addresses
/// answered in 22 ms once a source was named explicitly.
///
/// What follows from that is not that the kernel is wrong, but that giving up
/// here is worse than trying, where the kernel said it has no route. A route
/// that refuses by policy is another answer, and this is never asked after
/// one; see [`RouteAnswer::Forbidden`]. A probe sourced from an address the host really
/// holds either reaches the target or does not, and either way the scan reports
/// what it observed. Giving up produces a scan that reports nothing and blames
/// the network.
///
/// Scope-matched, since an address of the wrong scope cannot reach the target
/// whatever the routing table says: a global destination needs a global source.
///
/// A **link-local destination is declined** rather than matched. It would need
/// the link-local address of the interface it is on, and a bare [`IpAddr`]
/// cannot say which interface that is -- so the honest answer is that this
/// function does not know. See
/// [`OnLinkTable::source_for`](OnLinkTable::source_for).
///
/// An **IPv4 address written inside IPv6** is declined as IPv4 itself is. It
/// is an IPv4 host, reached only by a dual-stack socket from an IPv4 source,
/// and a global IPv6 address, the one thing the scope match below offers, is
/// the one source that certainly cannot reach it.
pub(crate) fn plausible_source(links: &[Link], target: IpAddr) -> Option<IpAddr> {
    let IpAddr::V6(target_v6) = target else {
        // IPv4 has no equivalent failure worth second-guessing: there is one
        // scope, and a kernel that cannot route a v4 address is describing a
        // host with no v4 connectivity.
        return None;
    };
    if target_v6.to_ipv4_mapped().is_some() {
        return None;
    }

    // A link-local destination cannot be answered here for the reason
    // `OnLinkTable::source_for` gives: every interface holds one, so any answer
    // is the interface list's order rather than a fact about the target. The
    // scope match below would otherwise pick the first and look deliberate.
    if target_v6.is_unicast_link_local() {
        return None;
    }

    links
        .iter()
        .flat_map(|link| link.ipv6())
        .map(|(addr, _)| addr)
        .find(|addr| !addr.is_unicast_link_local() && !addr.is_loopback())
        .map(IpAddr::V6)
}

/// Asks the kernel which local address it would route a packet to `target`
/// from, by `connect`-ing an unbound UDP socket to it and reading back the
/// address the routing layer selected. No datagram is ever sent - `connect`
/// on a UDP socket only performs the route lookup and binds the local end.
///
/// `sockets` caches one socket per address family so repeated probes reuse it.
pub fn probe_route_source(target: IpAddr, sockets: &mut ProbeSockets) -> Option<IpAddr> {
    match ask_route(target, sockets) {
        RouteAnswer::From(source) => Some(source),
        RouteAnswer::NoRoute | RouteAnswer::Forbidden | RouteAnswer::Unasked(_) => None,
    }
}

/// What the kernel's routing table said about one destination.
#[derive(Debug)]
pub(crate) enum RouteAnswer {
    /// It routes there, from this address.
    From(IpAddr),
    /// It has no route there it can use: `ENETUNREACH` or `EHOSTUNREACH`, or
    /// anything else that is not [`Forbidden`](Self::Forbidden).
    ///
    /// What a missing route answers, and what a VPN holding the IPv6 default
    /// route without carrying IPv6 answers too, which is the case
    /// [`plausible_source`] steps around. An `unreachable` route an
    /// administrator added answers the same and cannot be told apart from
    /// here.
    NoRoute,
    /// A route there refuses by policy: a `prohibit` route answers `EACCES`
    /// and a `blackhole` route `EINVAL`, where Linux has them. No missing or
    /// unusable route answers either, so a refusal in these words is a
    /// decision this host's administrator made about the destination, and a
    /// scan that stepped around it by naming a source would be the one
    /// program on the machine that ignored it.
    Forbidden,
    /// Nothing was asked: no socket to ask with, which says nothing about the
    /// destination.
    Unasked(std::io::Error),
}

impl RouteAnswer {
    /// What a refused `connect` says of the route, by the error it refused
    /// with. See [`Forbidden`](Self::Forbidden).
    fn refused_with(error: &std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidInput => {
                Self::Forbidden
            }
            _ => Self::NoRoute,
        }
    }
}

/// Asks the kernel how it routes to `target`, keeping its refusal apart from a
/// question that could not be put. See [`probe_route_source`].
pub(crate) fn ask_route(target: IpAddr, sockets: &mut ProbeSockets) -> RouteAnswer {
    let slot = match target {
        IpAddr::V4(_) => &mut sockets.v4,
        IpAddr::V6(_) => &mut sockets.v6,
    };

    let socket = match slot {
        Some(socket) => socket,
        None => {
            let bind_addr = if target.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            match UdpSocket::bind(bind_addr) {
                Ok(socket) => slot.insert(socket),
                Err(error) => return RouteAnswer::Unasked(error),
            }
        }
    };
    if let Err(error) = socket.connect((target, 53)) {
        return RouteAnswer::refused_with(&error);
    }
    match socket.local_addr() {
        Ok(local) => RouteAnswer::From(local.ip()),
        Err(error) => RouteAnswer::Unasked(error),
    }
}

/// Why [`SourceResolver::source`] has no address to send from.
#[derive(Debug)]
pub(crate) enum NoSource {
    /// No address on this host reaches the destination, or the routing table
    /// refuses it; [`refused_by_route`](SourceResolver::refused_by_route)
    /// says which. A fact about the destination, and the same answer the next
    /// time it is asked.
    Unreached,
    /// This process had no descriptor for the socket the routing table is
    /// asked through, so the table was never asked. A fact about this
    /// machine, which a socket closing elsewhere undoes: said as the shortage
    /// it is, and asked again next time rather than remembered as an address
    /// nothing reaches.
    Unasked(std::io::Error),
}

/// Resolves the source address for arbitrary destinations seen one at a time,
/// memoizing each answer. Built for the streaming SYN port scanner, where the
/// same host recurs across every port it probes: the first probe to a host
/// does the work, and every later port reuses the cached result.
///
/// Four sources, in descending order of confidence. A link-local destination the
/// scan scoped to an interface is answered from that interface's own link-local
/// address, which [`with_zones`](Self::with_zones) supplies. Other on-link
/// destinations are answered from an in-memory table of each interface's own
/// subnets. Everything else is put to the kernel, by connecting a UDP socket to
/// the target and reading back the address it chose, which asks the routing
/// table without sending a packet. When the kernel has no route, the last
/// resort is any address on an interface that could plausibly carry the
/// traffic. A source the scan [forced](Self::with_forced) answers between the
/// subnets and the kernel, and a route that refuses by policy is answered by
/// none of them.
pub struct SourceResolver {
    onlink: OnLinkTable,
    /// How the routing table is asked about a destination: [`ask_route`].
    route: fn(IpAddr, &mut ProbeSockets) -> RouteAnswer,
    /// Whether the routing table is asked about a destination on one of the
    /// segments this resolver holds: for a resolver of this host's, and not
    /// for one built over links it was handed, which are not this host's
    /// table's to refuse.
    asks_on_link: bool,
    /// The destinations the routing table refused. See
    /// [`refused_by_route`](Self::refused_by_route).
    refused: std::collections::HashSet<IpAddr>,
    sockets: ProbeSockets,
    cache: HashMap<IpAddr, Option<IpAddr>>,
    /// The interfaces themselves, kept for [`plausible_source`]. The
    /// [`OnLinkTable`] cannot answer for it: that table matches a destination
    /// against a prefix, and the case this exists for is a destination on no
    /// prefix this host holds.
    links: Vec<Link>,
    /// The interfaces this scan's link-local targets were named on, empty for a
    /// scan that named none. A prefix match cannot answer for these, since every
    /// interface holds an `fe80::/64`.
    zones: ZoneMap,
    /// Source addresses the caller forced, one per family at most. When set for
    /// a routed target's family, this is the answer, ahead of the routing
    /// table.
    forced: Vec<IpAddr>,
}

impl SourceResolver {
    /// Builds a resolver from the host's current viable interfaces.
    ///
    /// Such a resolver honours the routing table's refusals for destinations
    /// on this host's own segments; see [`resolve`](Self::resolve).
    pub fn from_system() -> Self {
        Self {
            asks_on_link: true,
            ..Self::from_links(&viable_interfaces())
        }
    }

    /// Builds a resolver from an explicit list of links (used in tests).
    pub fn from_links(links: &[Link]) -> Self {
        Self {
            onlink: OnLinkTable::from_links(links),
            route: ask_route,
            asks_on_link: false,
            refused: std::collections::HashSet::new(),
            sockets: ProbeSockets::default(),
            cache: HashMap::new(),
            links: links.to_vec(),
            zones: ZoneMap::new(),
            forced: Vec::new(),
        }
    }

    /// Teaches the resolver which interface each of a scan's link-local targets
    /// was named on.
    ///
    /// Without this a link-local destination has no source address, since the
    /// prefix it sits in is one every interface holds. With it, the source is the
    /// link-local address of the interface the target named, and
    /// [`zone_of`](Self::zone_of) is the scope id the send needs alongside it.
    pub fn with_zones(mut self, zones: ZoneMap) -> Self {
        self.zones = zones;
        self
    }

    /// Forces the source addresses, one per family, ahead of the routing table
    /// for every target no prefix of this host's holds; see
    /// [`resolve`](Self::resolve).
    pub fn with_forced(mut self, forced: Vec<IpAddr>) -> Self {
        self.forced = forced;
        self
    }

    /// The interface index a destination is valid on, for a scan that named one.
    ///
    /// A raw send carries this as the scope id of its destination. Everything
    /// that identifies its host on its own answers `None` and needs none.
    pub fn zone_of(&self, target: IpAddr) -> Option<u32> {
        self.zones.zone_of(&target)
    }

    /// The link-local address of the interface `target` was named on.
    ///
    /// A link-local source is the only one a link-local destination can be
    /// reached from, and which interface holds it is the whole question a zone
    /// answers.
    fn scoped_source(&self, target: IpAddr) -> Option<IpAddr> {
        let zone = self.zones.zone_of(&target)?;
        self.links
            .iter()
            .find(|link| link.index() == zone)?
            .addresses()
            .iter()
            .map(LinkAddress::address)
            .find(|address| matches!(address, IpAddr::V6(v6) if v6.is_unicast_link_local()))
    }

    /// Whether `target` sits on one of this host's own segments, so a packet
    /// to it is framed to the target itself rather than to a gateway.
    ///
    /// A link-local target the scan named an interface for is on that
    /// interface's segment, which is the only place such an address means
    /// anything.
    pub(crate) fn is_on_link(&self, target: IpAddr) -> bool {
        self.zones.zone_of(&target).is_some() || self.onlink.source_for(target).is_some()
    }

    /// Whether [`resolve`](Self::resolve) found no source for `target`
    /// because the routing table refuses it, rather than because nothing
    /// here reaches it.
    pub(crate) fn refused_by_route(&self, target: IpAddr) -> bool {
        self.refused.contains(&target)
    }

    /// Whether this host has any address to send probes from. When false,
    /// there is no point standing up a raw-socket scanner at all.
    pub fn has_sources(&self) -> bool {
        !self.onlink.is_empty()
    }

    /// The forced source matching `target`'s family, when one was set and
    /// applies to it. This is how [`with_forced`](Self::with_forced) overrides
    /// the routing table: a scan pinned to an interface sends a routed target
    /// from that interface's address rather than the one the kernel would have
    /// picked.
    ///
    /// Only a routed target, as the plan and the scan's connections apply it.
    /// [`resolve`](Self::resolve) asks this after this host's own prefixes,
    /// and loopback, an IPv4 address written inside IPv6, and a link-local
    /// address are no link's to be pinned to: the first two are the kernel's,
    /// and the third is on the link its zone names or on none.
    fn forced_source(&self, target: IpAddr) -> Option<IpAddr> {
        let no_link = target.is_loopback()
            || matches!(target, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some()
                || v6.is_unicast_link_local());
        if no_link {
            return None;
        }
        self.forced
            .iter()
            .copied()
            .find(|source| source.is_ipv4() == target.is_ipv4())
    }

    /// Returns the source address to send a probe to `target` from, or `None`
    /// if no address on this host could plausibly reach it.
    ///
    /// Five answers in order of authority: the interface a link-local target
    /// named, this host's own segments and tunnel prefixes, a forced source,
    /// the kernel's routing table, then `plausible_source` for the case where
    /// the kernel refuses but the host visibly holds an address of the right
    /// scope.
    ///
    /// The same order the scan's plan classifies in and its connections leave
    /// by. A target inside a prefix this host holds has one link that reaches
    /// it, which a forced source must not move it off; a forced source placed
    /// ahead would send its probes out by another link while the plan and
    /// every connection to it went by its own.
    ///
    /// A target on one of this host's segments that the routing table
    /// refuses has no source, whatever the segment says. A probe to it would
    /// be framed to the neighbour, or sent by a socket held to the link,
    /// neither of which asks the table, and would reach a host the machine's
    /// own policy keeps it from: the one scanner on the box that ignored a
    /// route its administrator added, found out by the probes arriving. A
    /// segment this host holds is reached directly, so the table's answer for
    /// it is the connected route unless a more specific one overrides it, and
    /// every override that refuses is the host's policy: a `prohibit`,
    /// `unreachable` or `blackhole` route, or the rules a VPN's kill switch
    /// keeps the local network out with. The table is asked by connecting a
    /// UDP socket, as for a routed target.
    ///
    /// A routed target whose route refuses by policy has no source either,
    /// forced or fallen back on. Both send by a socket held to an address,
    /// which the kernel sends from wherever the table refuses, and a routed
    /// target's refusal can be the kernel's own absence of a route as well as
    /// a policy, so only the policy's words decline it: the permission denied
    /// of a `prohibit` route and the invalid argument of a `blackhole` one,
    /// where Linux has them.
    pub fn resolve(&mut self, target: IpAddr) -> Option<IpAddr> {
        self.source(target).ok()
    }

    /// [`resolve`](Self::resolve), saying why there is no source.
    ///
    /// A lookup this process had no descriptor for is not remembered, and
    /// the next asks the table afresh; see [`NoSource::Unasked`]. Everything
    /// else is remembered for the life of the resolver.
    pub(crate) fn source(&mut self, target: IpAddr) -> Result<IpAddr, NoSource> {
        if let Some(cached) = self.cache.get(&target) {
            return cached.ok_or(NoSource::Unreached);
        }

        let source = self.find(target);
        match &source {
            Ok(address) => {
                self.cache.insert(target, Some(*address));
            }
            Err(NoSource::Unreached) => {
                self.cache.insert(target, None);
            }
            Err(NoSource::Unasked(_)) => {}
        }
        source
    }

    /// [`source`](Self::source), asked afresh.
    ///
    /// A table this process could not ask about a target on its own segment
    /// is not read as one that allows it: the question is what keeps the
    /// probes from a neighbour the host's policy refuses, and it is put again
    /// once a descriptor is free rather than skipped.
    fn find(&mut self, target: IpAddr) -> Result<IpAddr, NoSource> {
        if let Some(scoped) = self.scoped_source(target) {
            return Ok(scoped);
        }
        if let Some(on_link) = self.onlink.source_for(target) {
            if !self.asks_on_link {
                return Ok(on_link);
            }
            return match (self.route)(target, &mut self.sockets) {
                RouteAnswer::NoRoute | RouteAnswer::Forbidden => {
                    self.refused.insert(target);
                    Err(NoSource::Unreached)
                }
                RouteAnswer::Unasked(error) if descriptors::exhausted(&error) => {
                    Err(NoSource::Unasked(error))
                }
                RouteAnswer::From(_) | RouteAnswer::Unasked(_) => Ok(on_link),
            };
        }

        let route = (self.route)(target, &mut self.sockets);
        match route {
            RouteAnswer::Forbidden => {
                self.refused.insert(target);
                return Err(NoSource::Unreached);
            }
            RouteAnswer::Unasked(error) if descriptors::exhausted(&error) => {
                return Err(NoSource::Unasked(error));
            }
            _ => {}
        }
        if let Some(forced) = self.forced_source(target) {
            return Ok(forced);
        }
        match route {
            RouteAnswer::From(source) => Ok(source),
            _ => plausible_source(&self.links, target).ok_or(NoSource::Unreached),
        }
    }

    /// This resolver, asking the routing table through `route`, for a test
    /// that needs the table to answer as no host a test runs on does.
    #[cfg(all(test, unix))]
    pub(crate) fn asking_with(
        mut self,
        route: fn(IpAddr, &mut ProbeSockets) -> RouteAnswer,
    ) -> Self {
        self.route = route;
        self
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

    /// The same address, with the interface named. The source is that
    /// interface's own link-local address, which is the only one a link-local
    /// destination can be reached from.
    #[test]
    fn a_link_local_target_that_named_an_interface_is_sourced_from_it() {
        use crate::model::ip::range::Ipv6Range;
        use crate::model::ip::scoped::ZoneMap;

        let mine = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xa);
        let en1 = Link::new("en1", 15).with_addresses(vec![v6net(mine, 64)]);
        let elsewhere = Link::new("en0", 16).with_addresses(vec![v6net(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xb),
            64,
        )]);

        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x99);
        let mut zones = ZoneMap::new();
        zones.insert(
            Ipv6Range::scoped(target, target, Some(15)).expect("a scoped range"),
            &[(15, "en1")],
        );

        let mut resolver = SourceResolver::from_links(&[elsewhere, en1]).with_zones(zones);

        assert_eq!(
            resolver.resolve(IpAddr::V6(target)),
            Some(IpAddr::V6(mine)),
            "the interface named, not whichever was listed first"
        );
        assert_eq!(
            resolver.zone_of(IpAddr::V6(target)),
            Some(15),
            "and the scope id the send has to carry"
        );
    }

    /// The defect this guard exists for, and the shape of it: every interface
    /// holds an `fe80::/64`, so a bare link-local target matched whichever one
    /// the host happened to list first. Measured before the fix: the same
    /// target answered `fe80::a` or `fe80::b` depending only on the order the
    /// links arrived in.
    #[test]
    fn a_bare_link_local_target_has_no_source_rather_than_an_arbitrary_one() {
        let en0 = mock_interface(vec![v6net(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xa),
            64,
        )]);
        let en1 = mock_interface(vec![v6net(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xb),
            64,
        )]);
        let target = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x99));

        assert_eq!(
            OnLinkTable::from_links(&[en0.clone(), en1.clone()]).source_for(target),
            None
        );
        assert_eq!(
            OnLinkTable::from_links(&[en1, en0]).source_for(target),
            None,
            "and the answer does not depend on the order, because there is none"
        );
    }

    /// The fallback made the same guess, so it declines the same case. A global
    /// destination is still answered, which is what the fallback is for.
    #[test]
    fn the_fallback_declines_a_link_local_and_still_answers_a_global() {
        let links = [mock_interface(vec![
            v6net(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xa), 64),
            v6net(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5), 64),
        ])];

        assert_eq!(
            plausible_source(
                &links,
                IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x99))
            ),
            None
        );
        assert_eq!(
            plausible_source(
                &links,
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 9, 0, 0, 0, 0, 1))
            ),
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5))),
            "a global target still gets the global address the host holds"
        );
    }

    /// An ordinary on-link target is untouched: the guard is about one family
    /// of address and must not cost the rest anything.
    #[test]
    fn an_on_link_target_still_resolves_to_its_own_segment() {
        let table = OnLinkTable::from_links(&[mock_interface(vec![v4net(192, 0, 2, 10, 24)])]);

        assert_eq!(
            table.source_for(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 50))),
            Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)))
        );
        assert_eq!(
            table.source_for(IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1))),
            None
        );
    }

    /// A target on this host's own segment that the routing table refuses has
    /// no source, and says why, while its neighbours on the segment keep
    /// theirs.
    ///
    /// A `prohibit`, `unreachable` or `blackhole` host route over an address
    /// on a connected segment is the host's own policy. A probe framed to the
    /// neighbour, or sent by a socket held to the link, never asks the table,
    /// so without this the one program on the box that ignored the route
    /// would be the scanner, found out by its probes arriving.
    #[test]
    fn a_target_on_link_the_routing_table_refuses_has_no_source() {
        let refused = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 13));
        let neighbour = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 14));
        let mut resolver = SourceResolver {
            route: |target, _| match target == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 13)) {
                true => RouteAnswer::NoRoute,
                false => RouteAnswer::From(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            },
            asks_on_link: true,
            ..SourceResolver::from_links(&[mock_interface(vec![v4net(192, 0, 2, 10, 24)])])
        };

        assert_eq!(resolver.resolve(refused), None);
        assert!(resolver.refused_by_route(refused), "and says why");
        assert_eq!(
            resolver.resolve(neighbour),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        );
        assert!(!resolver.refused_by_route(neighbour));
    }

    /// The table is asked, and an address it routes is not refused. Loopback
    /// is routed on every host a test runs on, and the one refusal a test
    /// could build takes privileges; that half is Tier 3's.
    #[test]
    fn an_address_the_kernel_routes_is_not_refused() {
        let mut sockets = ProbeSockets::default();
        assert!(matches!(
            ask_route(IpAddr::V4(Ipv4Addr::LOCALHOST), &mut sockets),
            RouteAnswer::From(_)
        ));
    }

    /// A routed target whose route refuses by policy has no source, and the
    /// fallback that steps around a missing route does not step around it:
    /// a `prohibit` route over an off-link IPv6 address was probed through a
    /// socket held to the global address, the one program on the box that
    /// ignored the route. A missing route still gets the fallback, which is
    /// the case the fallback is for.
    #[test]
    fn a_routed_target_a_route_forbids_is_given_no_fallback() {
        let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xb1a0);
        let links = [mock_interface(vec![v6net(global, 64)])];
        let target = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 9, 0, 0, 0, 0, 1));

        let mut forbidden = SourceResolver {
            route: |_, _| RouteAnswer::Forbidden,
            ..SourceResolver::from_links(&links)
        };
        assert_eq!(forbidden.resolve(target), None);
        assert!(forbidden.refused_by_route(target), "and says why");

        let mut missing = SourceResolver {
            route: |_, _| RouteAnswer::NoRoute,
            ..SourceResolver::from_links(&links)
        };
        assert_eq!(missing.resolve(target), Some(IpAddr::V6(global)));
        assert!(!missing.refused_by_route(target));
    }

    /// Nor does a forced source step around it: a scan pinned to an interface
    /// chose which link its probes leave by, not which of this host's routes
    /// they may ignore.
    #[test]
    fn a_forced_source_does_not_answer_for_a_target_a_route_forbids() {
        let lan = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
        let mut resolver = SourceResolver {
            route: |_, _| RouteAnswer::Forbidden,
            ..SourceResolver::from_links(&[mock_interface(vec![v4net(192, 0, 2, 50, 24)])])
                .with_forced(vec![lan])
        };
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        assert_eq!(resolver.resolve(target), None);
        assert!(resolver.refused_by_route(target));
    }

    /// A routing table this process had no descriptor to ask is a shortage
    /// said as one, and asked again next time: remembered as a target with
    /// no source, a moment's full table would file a live host unreachable
    /// for the rest of the scan. A target on this host's own segment is not
    /// given its segment's source unasked either, since the question is what
    /// keeps its probes from a neighbour the host's policy refuses.
    #[cfg(unix)]
    #[test]
    fn a_route_asked_without_a_descriptor_is_a_shortage_asked_again() {
        let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xb1a0);
        let short = |_: IpAddr, _: &mut ProbeSockets| {
            RouteAnswer::Unasked(std::io::Error::from_raw_os_error(libc::EMFILE))
        };
        let routed = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 9, 0, 0, 0, 0, 1));
        let mut resolver = SourceResolver::from_links(&[mock_interface(vec![v6net(global, 64)])])
            .asking_with(short);

        assert!(matches!(
            resolver.source(routed),
            Err(NoSource::Unasked(e)) if descriptors::exhausted(&e)
        ));
        assert!(!resolver.refused_by_route(routed));

        resolver.route = |_, _| {
            RouteAnswer::From(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xb1a0,
            )))
        };
        assert_eq!(
            resolver.resolve(routed),
            Some(IpAddr::V6(global)),
            "the next lookup asks again"
        );

        let neighbour = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 14));
        let mut on_link = SourceResolver {
            asks_on_link: true,
            ..SourceResolver::from_links(&[mock_interface(vec![v4net(192, 0, 2, 10, 24)])])
                .asking_with(short)
        };
        assert!(matches!(
            on_link.source(neighbour),
            Err(NoSource::Unasked(_))
        ));
    }

    /// A policy route is told from a missing one by the words the kernel
    /// refuses in: `prohibit` answers `EACCES` and `blackhole` `EINVAL`, and a
    /// missing or `unreachable` route `ENETUNREACH` or `EHOSTUNREACH`.
    #[cfg(unix)]
    #[test]
    fn a_policy_route_is_told_apart_by_its_refusal() {
        let refused = |code| RouteAnswer::refused_with(&std::io::Error::from_raw_os_error(code));
        assert!(matches!(refused(libc::EACCES), RouteAnswer::Forbidden));
        assert!(matches!(refused(libc::EINVAL), RouteAnswer::Forbidden));
        assert!(matches!(refused(libc::ENETUNREACH), RouteAnswer::NoRoute));
        assert!(matches!(refused(libc::EHOSTUNREACH), RouteAnswer::NoRoute));
    }

    /// A link-local written with its interface is not this case at all: it
    /// carries the answer, and the sweep that reaches it is the local one.
    #[test]
    fn a_zoned_link_local_is_not_what_this_declines() {
        use crate::model::ip::scoped::ScopedIp;
        let bare: IpAddr = "fe80::1".parse().expect("literal");
        assert!(ScopedIp::needs_zone(&bare), "bare is the case declined");

        let global: IpAddr = "2001:db8::1".parse().expect("literal");
        assert!(!ScopedIp::needs_zone(&global));
    }

    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn mock_interface(nets: Vec<LinkAddress>) -> Link {
        Link::new("test0", 0).with_addresses(nets)
    }

    fn v4net(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> LinkAddress {
        LinkAddress::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), prefix)
    }

    #[test]
    fn on_link_target_uses_that_subnet_source() {
        let intf = mock_interface(vec![v4net(192, 0, 2, 50, 24)]);
        let table = OnLinkTable::from_links(&[intf]);

        assert_eq!(
            table.source_for(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200))),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)))
        );
    }

    #[test]
    fn off_link_target_has_no_on_link_source() {
        let intf = mock_interface(vec![v4net(192, 0, 2, 50, 24)]);
        let table = OnLinkTable::from_links(&[intf]);

        assert_eq!(
            table.source_for(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            None
        );
    }

    #[test]
    fn longest_prefix_wins() {
        let intf = mock_interface(vec![
            v4net(198, 51, 100, 1, 24),
            v4net(198, 51, 100, 130, 25),
        ]);
        let table = OnLinkTable::from_links(&[intf]);

        assert_eq!(
            table.source_for(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200))),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 130)))
        );
    }

    #[test]
    fn v6_and_v4_are_kept_separate() {
        // A global prefix rather than a link-local one: this is about the two
        // families not matching each other, and a link-local target is declined
        // for a different reason that would mask what is being tested.
        let v6 = v6net(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1), 64);
        let intf = mock_interface(vec![v4net(192, 0, 2, 50, 24), v6]);
        let table = OnLinkTable::from_links(&[intf]);

        assert_eq!(
            table.source_for(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 99))),
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1)))
        );
        assert_eq!(
            table.source_for(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 9, 0, 0, 0, 1))),
            None,
            "a prefix the host does not hold is not on-link"
        );
    }

    #[test]
    fn resolver_caches_and_reports_sources() {
        let intf = mock_interface(vec![v4net(192, 0, 2, 50, 24)]);
        let mut resolver = SourceResolver::from_links(&[intf]);

        assert!(resolver.has_sources());
        let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));
        assert_eq!(
            resolver.resolve(target),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)))
        );
        assert_eq!(
            resolver.resolve(target),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)))
        );
    }

    #[test]
    fn empty_host_has_no_sources() {
        let resolver = SourceResolver::from_links(&[]);
        assert!(!resolver.has_sources());
    }

    /// A forced source answers a routed target ahead of the routing table, the
    /// override a scan pinned to an interface needs. It picks by family, so the
    /// IPv4 force answers the IPv4 target even listed behind the IPv6 one, and
    /// the kernel is never consulted.
    #[test]
    fn a_forced_source_answers_a_routed_target_by_family() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        let intf = mock_interface(vec![v4net(192, 0, 2, 50, 24)]);
        let mut resolver = SourceResolver::from_links(&[intf]).with_forced(vec![v6, v4]);

        let public = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        assert_eq!(resolver.resolve(public), Some(v4));
    }

    /// A forced source is for a target the routing table would send out by the
    /// wrong link, and a target inside a prefix this host holds has one link
    /// that reaches it: a neighbour on another segment by that segment, a peer
    /// inside a tunnel's own prefix through the tunnel. The plan and every
    /// connection to such a target leave by its own link; a raw probe sourced
    /// from the forced LAN address would leave by the LAN, reach nothing the
    /// plan expected, and report a host the rest of the scan reached as silent.
    #[test]
    fn a_forced_source_leaves_a_target_inside_a_held_prefix_to_its_own_link() {
        use crate::system::interface::Addressing;

        let lan = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
        let tunnel_address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let other_segment = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let links = [
            Link::new("en0", 4).with_addresses(vec![v4net(192, 0, 2, 50, 24)]),
            Link::new("en1", 5).with_addresses(vec![v4net(203, 0, 113, 7, 24)]),
            Link::new("utun9", 20)
                .with_addressing(Addressing::PointToPoint)
                .with_addresses(vec![v4net(198, 51, 100, 2, 24)]),
        ];
        let mut resolver = SourceResolver::from_links(&links).with_forced(vec![lan]);

        assert_eq!(
            resolver.resolve(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
            Some(tunnel_address),
            "a peer inside the tunnel's prefix is reached through the tunnel"
        );
        assert_eq!(
            resolver.resolve(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
            Some(other_segment),
            "a neighbour on another segment is reached on that segment"
        );
        assert_eq!(
            resolver.resolve(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
            Some(lan),
            "and a neighbour on the forced source's own segment from it"
        );
    }

    /// Loopback and an IPv4 address written inside IPv6 are no link's, so the
    /// plan leaves them to the kernel whatever is forced, and so does this.
    #[test]
    fn a_forced_source_does_not_answer_for_loopback_or_a_mapped_address() {
        let lan = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
        let global = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x50));
        let intf = mock_interface(vec![v4net(192, 0, 2, 50, 24)]);
        let mut resolver = SourceResolver::from_links(&[intf]).with_forced(vec![lan, global]);

        for target in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv4Addr::new(203, 0, 113, 1).to_ipv6_mapped()),
        ] {
            let source = resolver.resolve(target);
            assert!(
                source != Some(lan) && source != Some(global),
                "{target} was sourced from the forced {source:?}"
            );
        }
    }

    fn v6net(addr: Ipv6Addr, prefix: u8) -> LinkAddress {
        LinkAddress::new(IpAddr::V6(addr), prefix)
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
        let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xb1a0);
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
    ///
    /// Nor may a link-local one be. The property above is real, but it does not
    /// establish *which* link-local address, and on a fixture with one
    /// interface there is only one to pick. Every interface holds an
    /// `fe80::/64`, so on a real host the answer would be whichever the platform
    /// listed first: a guess with the shape of an answer, and the one
    /// [`RoutedTargets::ambiguous`](super::RoutedTargets) names as exactly the
    /// mistake.
    #[test]
    fn a_link_local_target_is_offered_no_source_at_all() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x50);
        let intf = mock_interface(vec![
            v6net(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 64),
            v6net(link_local, 64),
        ]);

        let source = plausible_source(
            std::slice::from_ref(&intf),
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA)),
        );

        assert_eq!(
            source, None,
            "a global was never offered, and now nor is a guess"
        );
    }

    /// An IPv4 address written inside IPv6 is an IPv4 host, and a global IPv6
    /// source can never reach it. Offered one, a probe to it would leave as an
    /// IPv6 packet toward the router, the one place the host certainly is not.
    #[test]
    fn a_mapped_target_is_offered_no_ipv6_source() {
        let intf = mock_interface(vec![
            v4net(192, 0, 2, 50, 24),
            v6net(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 64),
        ]);

        assert_eq!(
            plausible_source(
                std::slice::from_ref(&intf),
                IpAddr::V6(Ipv4Addr::new(203, 0, 113, 1).to_ipv6_mapped())
            ),
            None
        );
    }

    /// IPv4 keeps the kernel's answer. It has one scope and no equivalent of a
    /// tunnel swallowing the default route for a family it does not carry, so
    /// second-guessing it would invent a source where the host genuinely has
    /// none.
    #[test]
    fn an_unroutable_v4_target_is_not_second_guessed() {
        let intf = mock_interface(vec![v4net(192, 0, 2, 50, 24)]);

        assert_eq!(
            plausible_source(
                std::slice::from_ref(&intf),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
            ),
            None
        );
    }
}
