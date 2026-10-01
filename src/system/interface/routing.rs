// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How this host reaches a target
//!
//! A target is on a segment this machine is attached to, behind a gateway, or
//! reachable by neither, and that decides whether it gets a link-layer sweep, a
//! raw probe with a source address, or the unprivileged fallback.
//!
//! A segment is a link a frame can be put on. A tunnel's address carries a prefix
//! too, and a WireGuard peer or an OpenVPN server in subnet topology sits inside
//! it, but nothing beyond a tunnel answers ARP or neighbour discovery, so a target
//! inside that prefix is probed through the tunnel like any routed target.
//!
//! ## Refusals
//!
//! Two of the five buckets [`RoutedTargets`] hands back are refusals. A bare IPv6
//! link-local matches every interface and identifies none, so it is reported as
//! ambiguous. An off-link IPv6 range past [`MAX_ENUMERABLE_ADDRESSES`] is kept
//! whole and refused, because the only strategy for an off-link range is to walk
//! it. Both are carried out so a scan never stays quiet about ground it did not
//! look at.
//!
//! ## What a frame reaches
//!
//! A process that can inject frames but holds no raw socket (an unprivileged run
//! on macOS holding the BPF devices, a privileged one on Windows) reaches only
//! targets with Ethernet in front of them. [`beyond_frames`] names the rest and
//! why, so a scan can reach them by connect.
//!
//! ## Cost
//!
//! One `connect` per off-link target on an unbound UDP socket, which performs a
//! route lookup and sends nothing, parallelised across the target list. On-link
//! targets cost a prefix comparison and no syscall.

use crate::model::ip::range::IpRange::{self, V4, V6};
use crate::model::ip::range::{Ipv4Range, Ipv6Range};
use crate::model::ip::scoped::ScopedIp;
use crate::model::ip::set::IpSet;
use crate::system::interface::source::{
    RouteAnswer, ask_route, plausible_source, refuses_neighbour, viable_interfaces,
};
use crate::system::interface::{Link, LinkAddress};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// An off-link target paired with the local source address a probe to it must
/// be sent from.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutedTarget {
    /// The destination being probed.
    pub target: IpAddr,
    /// The source address to send its probe from.
    pub source: IpAddr,
}

impl RoutedTarget {
    /// A probe of `target`, sent from `source`.
    pub const fn new(target: IpAddr, source: IpAddr) -> Self {
        Self { target, source }
    }
}

/// The largest IPv6 range any strategy will turn into addresses one at a time.
///
/// 65,536 addresses, the size of an IPv4 `/16` and an IPv6 `/112`. Walking is
/// the only discovery strategy for an off-link range, and a `/64` holds 2^64
/// addresses: about 146 million years at a routed sweep's four thousand probes
/// a second, and expanding it into a `Vec<IpAddr>` exhausts memory first.
/// Larger IPv6 ranges are refused, loudly, so the caller knows the engine did
/// not look.
///
/// IPv4 ranges are not bounded by this: the whole space is 2^32, and a `/8` is
/// unreasonable but possible.
///
/// Ask through [`is_enumerable`]. The classifier applies it to a routed range
/// it would have to walk; [`crate::scanner`] applies it on the unprivileged
/// path, which has no classifier; and `DiscoveryPlan::build` applies it to an
/// on-link range, which the classifier hands over whole because a segment is
/// swept by multicast.
pub const MAX_ENUMERABLE_ADDRESSES: u128 = 1 << 16;

/// The result of classifying a set of targets against this host's interfaces
/// and routing table.
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct RoutedTargets {
    /// Targets that share an interface's Layer-2 segment, grouped by that
    /// interface. Reachable directly, so they get an ARP/NDP discovery
    /// strategy bound to the interface.
    ///
    /// Only a link that carries frames has a segment, except for a link-local
    /// target whose zone names a link that does not: the zone is the user's own
    /// statement of where the target is.
    pub local: HashMap<Link, IpSet>,
    /// Targets reached through a gateway or a tunnel, each already paired with
    /// the source address to probe it from. Handled by a single raw TCP SYN
    /// scanner.
    pub routed: Vec<RoutedTarget>,
    /// Targets that are neither on-link nor have a resolvable route, left to
    /// the unprivileged connect fallback. Loopback is always here, in both
    /// families, whatever the routing table or a forced source says about it.
    pub unmapped: IpSet,
    /// Targets that are this host's own addresses.
    ///
    /// No strategy can establish one: the kernel reaches an address the host
    /// holds through loopback, so an ARP request for it goes unanswered. It is up
    /// by construction.
    pub ours: IpSet,
    /// Link-local IPv6 targets with no interface named on them.
    ///
    /// Every interface holds an `fe80::/64`, so such a target matches all of
    /// them and identifies none. Probing whichever the host listed first could
    /// report the address absent when it is present on another segment. Written
    /// `fe80::1%en0`, it is unambiguous.
    pub ambiguous: Vec<Ipv6Range>,
    /// Off-link IPv6 ranges too large to enumerate, kept whole.
    ///
    /// They were never probed. They are carried out so a caller reading "no hosts
    /// found" does not take it as evidence about the range.
    pub unenumerable: Vec<Ipv6Range>,
}

/// Classifies target IPs by how this host reaches them: on-link (per
/// interface), routed through a gateway or a tunnel (paired with a source
/// address), or unreachable.
///
/// Reads the host's interface table through
/// [`interfaces`](super::interfaces), narrowed to the links that could carry a
/// probe.
pub fn map_ips_to_interfaces(ip_set: IpSet) -> RoutedTargets {
    map_ips_to_interfaces_with(ip_set, viable_interfaces(), &[])
}

/// [`map_ips_to_interfaces`], with source addresses forced ahead of the routing
/// table. A scan pinned to an interface routes every off-link target from that
/// interface's address, for a host whose default route a VPN owns.
pub(crate) fn map_ips_to_interfaces_forced(ip_set: IpSet, forced: &[IpAddr]) -> RoutedTargets {
    map_ips_to_interfaces_with(ip_set, viable_interfaces(), forced)
}

/// Classification of one target, from the parallel pass, before the results
/// are folded into interface-indexed buckets.
enum Classification {
    /// On-link on the interface at this index.
    Local(usize),
    /// Routed off-link, to be sent from this source address.
    Routed(IpAddr),
    /// An address this host holds.
    Ours,
    /// No route found.
    Unmapped,
}

/// [`map_ips_to_interfaces`] against an interface table the caller supplies.
///
/// The seam the classification is tested through, with interfaces that do not
/// exist.
pub(crate) fn map_ips_to_interfaces_with(
    ip_set: IpSet,
    interfaces: Vec<Link>,
    forced: &[IpAddr],
) -> RoutedTargets {
    map_ips_to_interfaces_asking(ip_set, interfaces, forced, ask_route)
}

/// [`map_ips_to_interfaces_with`], asking the routing table about a routed
/// target through `route`, for a test that needs the table to answer as no test
/// host does.
fn map_ips_to_interfaces_asking(
    ip_set: IpSet,
    interfaces: Vec<Link>,
    forced: &[IpAddr],
    route: fn(IpAddr) -> RouteAnswer,
) -> RoutedTargets {
    let owned_ips: HashSet<IpAddr> = interfaces
        .iter()
        .flat_map(|link| link.addresses().iter().map(|held| held.address()))
        .collect();

    let mut local: HashMap<usize, IpSet> = HashMap::new();
    let mut routed: Vec<RoutedTarget> = Vec::new();
    let mut unmapped = IpSet::new();
    let mut ours = IpSet::new();
    let mut unenumerable: Vec<Ipv6Range> = Vec::new();
    let mut ambiguous: Vec<Ipv6Range> = Vec::new();
    let mut singles_to_route: Vec<IpAddr> = Vec::new();

    // A range wholly inside one segment's subnet is kept intact; anything
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

        // Before any interface is consulted: they all match.
        if range.is_ambiguous() {
            ambiguous.push(*range);
            continue;
        }
        // A named interface answers outright, ahead of any prefix match.
        if let Some(zone) = range.zone() {
            match interfaces.iter().position(|link| link.index() == zone) {
                Some(idx) => local.entry(idx).or_default().insert_range(V6(*range)),
                None => ambiguous.push(*range),
            }
            continue;
        }

        match owning_interface(&interfaces, start, end) {
            // On-link, so kept whole: a segment is reached by multicast, one packet
            // whatever the prefix length. Whether it is also small enough to walk is
            // for `DiscoveryPlan::build` to ask.
            Some(idx) => local.entry(idx).or_default().insert_range(V6(*range)),
            // Off-link, so each address is probed in turn. Checked before `to_iter`
            // because the expansion is what does the damage.
            None if !is_enumerable(range) => unenumerable.push(*range),
            None => singles_to_route.extend(range.iter()),
        }
    }

    let processed: Vec<(IpAddr, Classification)> = singles_to_route
        .par_iter()
        .map(|&target| {
            // Loopback is this host. The kernel answers `::1` with `::1`, which no
            // interface here holds, and the fallback below would then pair it with a
            // global source as if it were routed behind a VPN; a forced source would do
            // the same. This keeps both loopbacks planned alike.
            if target.is_loopback() {
                return (target, Classification::Unmapped);
            }
            // An IPv4-mapped address is an IPv4 host written inside IPv6, and no wire
            // carries one. Unmapped, it is left to the kernel, whose dual-stack socket
            // reaches the IPv4 host.
            if is_ipv4_mapped(target) {
                return (target, Classification::Unmapped);
            }
            // Before any prefix: this host's address is inside its own link's prefix,
            // and the kernel answers it from loopback.
            if owned_ips.contains(&target) {
                return (target, Classification::Ours);
            }

            // Inside a prefix this host holds, that link is the one route to the
            // target: a segment is swept, and inside a tunnel's own prefix the target
            // is reached through the tunnel from its address. A forced source must not
            // move the target off that link.
            if let Some((idx, held)) = holding_prefix(&interfaces, target) {
                return if interfaces[idx].carries_frames() {
                    (target, Classification::Local(idx))
                } else {
                    (target, Classification::Routed(held.address()))
                };
            }

            // A route that refuses by policy is the host's decision, and neither a
            // forced source nor the fallback below steps around it (the kernel sends
            // from a named address wherever the table refuses). Left to the connect
            // fallback, whose connect the kernel refuses too. See
            // `RouteAnswer::Forbidden`.
            let answer = route(target);
            if matches!(answer, RouteAnswer::Forbidden) {
                return (target, Classification::Unmapped);
            }

            // Otherwise a forced source outranks the routing table, for a routed
            // target the kernel would send from the wrong interface.
            if let Some(source) = forced
                .iter()
                .copied()
                .find(|s| s.is_ipv4() == target.is_ipv4())
            {
                return (target, Classification::Routed(source));
            }

            if let RouteAnswer::From(source) = answer
                && owned_ips.contains(&source)
            {
                return (target, Classification::Routed(source));
            }

            // No route, but this host may still hold an address of the right scope;
            // see `plausible_source`. This covers a laptop whose VPN swallowed the IPv6
            // default route.
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
            Classification::Ours => ours.insert(target),
        }
    }

    // Withheld from every strategy. A range wholly inside a segment's subnet is
    // assigned to that link without passing through the per-address check, so an
    // address this host holds can arrive here inside a set.
    for address in &owned_ips {
        let mut one = IpSet::new();
        one.insert(*address);

        for targets in local.values_mut() {
            if targets.contains(address) {
                targets.subtract(&one);
                ours.insert(*address);
            }
        }
    }
    // A link whose only target was ours has nothing left to sweep.
    local.retain(|_, targets| !targets.is_empty());

    let local = local
        .into_iter()
        .map(|(idx, ips)| (interfaces[idx].clone(), ips))
        .collect();

    RoutedTargets {
        local,
        routed,
        unmapped,
        ours,
        ambiguous,
        unenumerable,
    }
}

/// The addresses among `targets`, on `link`'s segment, that this host's
/// routing table refuses.
///
/// Frames built for a neighbour never ask the table, so a route an
/// administrator added over one address of a connected prefix, or a VPN kill
/// switch keeping the local network out, is heard only by asking. Every other
/// program on the machine honours it, and a sweep should too.
///
/// Asked address by address: a route lookup each, no packet. Not asked: a
/// link-local address (on its zone's segment by definition), a range too large
/// to walk, and the network and broadcast addresses of the link's own prefixes,
/// which a kernel refuses on other grounds.
pub(crate) fn refused_neighbours(link: &Link, targets: &IpSet) -> IpSet {
    refused_neighbours_asking(link, targets, refuses_neighbour)
}

/// [`refused_neighbours`], asking the table through `refuses`, for a test that
/// needs the table to refuse as no test host does.
fn refused_neighbours_asking(link: &Link, targets: &IpSet, refuses: fn(IpAddr) -> bool) -> IpSet {
    let edges: HashSet<IpAddr> = link
        .addresses()
        .iter()
        .filter_map(|held| match held.network() {
            IpRange::V4(range) => Some([range.start_addr(), range.end_addr()]),
            IpRange::V6(_) => None,
        })
        .flatten()
        .map(IpAddr::V4)
        .collect();
    let v4 = targets.v4().iter().flat_map(Ipv4Range::iter);
    let v6 = targets
        .v6()
        .iter()
        .filter(|range| range.zone().is_none() && is_enumerable(range))
        .flat_map(Ipv6Range::iter);
    let walked = v4.chain(v6);

    let refused: Vec<IpAddr> = walked
        .filter(|target| !edges.contains(target) && !ScopedIp::needs_zone(target))
        .par_bridge()
        .map(|target| refuses(target).then_some(target))
        .flatten()
        .collect();

    let mut set = IpSet::new();
    for address in refused {
        set.insert(address);
    }
    set.canonicalize();
    set
}

/// Which of the engine's two frame builders a question about reach is asked for.
///
/// The segment sweep resolves an IPv6 neighbour itself, by neighbour discovery
/// over the link it holds open. The probe transport's frame sender has only ARP,
/// so it has no hardware address for an IPv6 neighbour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameSender {
    /// ARP and ICMPv6 across a segment, which is discovery's local step.
    Sweep,
    /// The probe transport's frames: port probes, routed discovery, and every
    /// later pass that sends its own segments to a host.
    Probe,
}

/// Why a self-built frame cannot reach a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unframed {
    /// The target is loopback.
    Loopback,
    /// The target is an address this host holds. Its kernel answers it through
    /// loopback, so a frame put on a link for it reaches nobody who replies.
    Ours,
    /// The route to the target leaves by the named link, which carries no
    /// frames: a tunnel, a VPN, or anything else without a hardware address
    /// and a segment.
    Tunnel(String),
    /// Nothing routes to the target at all.
    NoRoute,
    /// The target is an IPv6 neighbour on the named link, and the probe
    /// transport's sender has no neighbour discovery to resolve it with.
    Neighbour(String),
    /// The target is an IPv4 address written in the IPv4-mapped IPv6 block,
    /// which only a socket can reach: no frame carries such an address.
    Mapped,
}

/// A few words, for the brackets after the addresses a message lists.
impl std::fmt::Display for Unframed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Loopback => f.write_str("loopback"),
            Self::Ours => f.write_str("own address"),
            Self::Tunnel(link) => write!(f, "via {link}"),
            Self::NoRoute => f.write_str("no route"),
            Self::Neighbour(link) => write!(f, "IPv6 neighbour on {link}, no NDP"),
            Self::Mapped => f.write_str("IPv4-mapped"),
        }
    }
}

/// The targets a self-built frame cannot reach from this host, and why.
///
/// Built by [`beyond_frames`], for a process that may inject frames and holds
/// nothing else: an unprivileged run on macOS with the BPF devices handed to a
/// group, or any privileged run on Windows. Everything here needs a strategy
/// that asks the kernel.
#[derive(Debug, Default)]
pub(crate) struct BeyondFrames {
    /// Every target no frame reaches.
    pub(crate) targets: IpSet,
    /// Each reason that applied and the targets it applied to, in a fixed
    /// order, none of them empty.
    reasons: Vec<(Unframed, IpSet)>,
}

impl BeyondFrames {
    /// Whether every target is within a frame's reach.
    pub(crate) fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Each reason with the lowest address it applied to and how many it
    /// covered, for a message about the set.
    pub(crate) fn summary(&self) -> Vec<(Unframed, IpAddr, u128)> {
        self.reasons
            .iter()
            .filter_map(|(reason, targets)| {
                let first = targets.iter().next()?;
                Some((reason.clone(), first, targets.len()))
            })
            .collect()
    }

    /// Whether a connect to these targets is a fallback rather than their
    /// route: some lie behind a tunnel, are IPv6 neighbours the sender cannot
    /// resolve, or have no route at all.
    ///
    /// Root reaches the first two by raw socket, and nothing reaches the third,
    /// so a run probing them by connect is weaker than one that could frame
    /// them. Loopback, this host's own addresses and IPv4-mapped targets are
    /// reached by a socket at any privilege, so connect loses nothing there.
    pub(crate) fn is_a_fallback(&self) -> bool {
        self.reasons.iter().any(|(reason, _)| {
            matches!(
                reason,
                Unframed::Tunnel(_) | Unframed::Neighbour(_) | Unframed::NoRoute
            )
        })
    }

    /// Each reason that applied, in order, joined for the brackets after a
    /// message line.
    pub(crate) fn reasons(&self) -> String {
        let named: Vec<String> = self
            .reasons
            .iter()
            .map(|(reason, _)| reason.to_string())
            .collect();
        named.join(", ")
    }

    /// These, together with every address of `unmapped` they do not already
    /// hold, each under the reason nothing routes a frame to it.
    ///
    /// For a phase whose connect step holds both what a frame cannot reach and
    /// what the routing table left without a route, loopback included. The
    /// second is classified from the address alone, since the routing table has
    /// already been asked.
    pub(crate) fn and_unmapped(mut self, unmapped: &IpSet) -> Self {
        let mut rest = unmapped.clone();
        rest.subtract(&self.targets);
        for (reason, targets) in unmapped_reasons(rest) {
            self.note(reason, targets);
        }
        self.targets.canonicalize();
        self
    }

    /// One reason and the addresses it covers, joined to those it already
    /// covers where it has been noted before.
    fn note(&mut self, reason: Unframed, mut targets: IpSet) {
        targets.canonicalize();
        if targets.is_empty() {
            return;
        }
        extend(&mut self.targets, &targets);
        match self.reasons.iter_mut().find(|(held, _)| *held == reason) {
            Some((_, held)) => {
                extend(held, &targets);
                held.canonicalize();
            }
            None => self.reasons.push((reason, targets)),
        }
    }
}

/// Why no frame reaches each of `unmapped`, addresses the routing table found
/// no link for, split by reason: loopback, IPv4-mapped, and no route.
///
/// Split by block, since an unrouted range can be as wide as the target list.
/// Loopback is `127.0.0.0/8` and `::1`, as [`IpAddr::is_loopback`] has it; an
/// IPv4 loopback address written in the mapped block counts as mapped.
fn unmapped_reasons(unmapped: IpSet) -> Vec<(Unframed, IpSet)> {
    let block = |ranges: &[IpRange]| {
        let mut set = IpSet::new();
        for range in ranges {
            set.insert_range(*range);
        }
        set
    };
    let v4 = |start: [u8; 4], end: [u8; 4]| {
        V4(Ipv4Range::new(start.into(), end.into()).expect("an ordered range"))
    };
    let v6 = |start: u128, end: u128| {
        V6(Ipv6Range::new(start.into(), end.into()).expect("an ordered range"))
    };
    let blocks = [
        (
            Unframed::Loopback,
            block(&[v4([127, 0, 0, 0], [127, 255, 255, 255]), v6(1, 1)]),
        ),
        (
            Unframed::Mapped,
            block(&[v6(0xffff_0000_0000, 0xffff_ffff_ffff)]),
        ),
    ];

    let mut reasons = Vec::new();
    let mut rest = unmapped;
    for (reason, block) in blocks {
        let mut outside = rest.clone();
        outside.subtract(&block);
        let mut inside = rest;
        inside.subtract(&outside);
        reasons.push((reason, inside));
        rest = outside;
    }
    reasons.push((Unframed::NoRoute, rest));
    reasons.retain(|(_, targets)| !targets.is_empty());
    reasons
}

/// Whether `target` is an IPv4 address written in the IPv4-mapped IPv6 block,
/// `::ffff:0:0/96`.
fn is_ipv4_mapped(target: IpAddr) -> bool {
    matches!(target, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
}

/// Adds every range of `from` to `into`, leaving the merge to whoever reads it.
fn extend(into: &mut IpSet, from: &IpSet) {
    for range in from.v4() {
        into.push_v4_range(*range);
    }
    for range in from.v6() {
        into.push_v6_range(*range);
    }
}

/// Which of `ip_set` a frame built by `sender` cannot reach from this host.
///
/// Classified as [`map_ips_to_interfaces_forced`] classifies: a routed target
/// is out of reach when the source the kernel would send it from belongs to a
/// link that carries no frames. The frame sender's own choice of egress is not
/// consulted, since its reach is what is in question.
pub(crate) fn beyond_frames(ip_set: IpSet, forced: &[IpAddr], sender: FrameSender) -> BeyondFrames {
    beyond_frames_with(ip_set, viable_interfaces(), forced, sender)
}

/// [`beyond_frames`] against an interface table the caller supplies, the seam
/// its decisions are tested through.
pub(crate) fn beyond_frames_with(
    ip_set: IpSet,
    interfaces: Vec<Link>,
    forced: &[IpAddr],
    sender: FrameSender,
) -> BeyondFrames {
    let links = interfaces.clone();
    let RoutedTargets {
        local,
        routed,
        unmapped,
        ours,
        ..
    } = map_ips_to_interfaces_with(ip_set, interfaces, forced);

    // Grouped by reason before counting, since one tunnel can hold targets on
    // its own subnet and targets routed through it.
    let mut groups: Vec<(Unframed, IpSet)> = Vec::new();
    let mut add = |reason: Unframed, range: IpRange| match groups
        .iter_mut()
        .find(|(held, _)| *held == reason)
    {
        Some((_, targets)) => targets.insert_range(range),
        None => {
            let mut targets = IpSet::new();
            targets.insert_range(range);
            groups.push((reason, targets));
        }
    };

    for (reason, targets) in unmapped_reasons(unmapped) {
        for range in targets.v4() {
            add(reason.clone(), V4(*range));
        }
        for range in targets.v6() {
            add(reason.clone(), V6(*range));
        }
    }
    for range in ours.v4() {
        add(Unframed::Ours, V4(*range));
    }
    for range in ours.v6() {
        add(Unframed::Ours, V6(*range));
    }

    // Sorted by name, for a stable message order.
    let mut local: Vec<(Link, IpSet)> = local.into_iter().collect();
    local.sort_by(|(a, _), (b, _)| a.name().cmp(b.name()));
    for (link, targets) in &local {
        // Only a link-local target whose zone named a tunnel is in `local` on a
        // link without frames; a tunnel's own subnet is routed through it.
        if !link.carries_frames() {
            for range in targets.v4() {
                add(Unframed::Tunnel(link.name().to_string()), V4(*range));
            }
            for range in targets.v6() {
                add(Unframed::Tunnel(link.name().to_string()), V6(*range));
            }
        } else if sender == FrameSender::Probe {
            for range in targets.v6() {
                add(Unframed::Neighbour(link.name().to_string()), V6(*range));
            }
        }
    }

    for RoutedTarget { target, source } in routed {
        // A source no link here holds is a forced address this host does not
        // have. The frame sender builds that frame as asked, and a connect could
        // not honour it, so it stays.
        let Some(owner) = links
            .iter()
            .find(|link| link.addresses().iter().any(|held| held.address() == source))
        else {
            continue;
        };
        if !owner.carries_frames() {
            add(Unframed::Tunnel(owner.name().to_string()), single(target));
        }
    }

    let mut beyond = BeyondFrames::default();
    for (reason, targets) in groups {
        beyond.note(reason, targets);
    }
    beyond.targets.canonicalize();
    beyond
}

/// One address as a range of itself.
fn single(address: IpAddr) -> IpRange {
    match address {
        IpAddr::V4(v4) => V4(Ipv4Range::single(v4)),
        IpAddr::V6(v6) => V6(Ipv6Range::single(v6)),
    }
}

/// Whether an IPv6 range is small enough to probe one address at a time.
///
/// Asked of a range: a set holding a `/64` and three literals is partly
/// walkable. See [`MAX_ENUMERABLE_ADDRESSES`].
pub fn is_enumerable(range: &Ipv6Range) -> bool {
    range.len() <= MAX_ENUMERABLE_ADDRESSES
}

/// The segment the whole inclusive range `[start, end]` is on, if it is on one.
///
/// Kept whole only where one link answers for every address in it, with no
/// narrower prefix on another link inside the range (a VPN's `/24` within the
/// LAN's `/8`, say). Otherwise each address asks [`holding_prefix`] for
/// itself.
///
/// A host prefix (`/32`, `/128`) does not count: it covers only this host's own
/// address, and Linux lists every DHCPv6 address as one, so splitting an
/// on-link `/64` around it would refuse the segment as too large to walk.
fn owning_interface(links: &[Link], start: IpAddr, end: IpAddr) -> Option<usize> {
    let (idx, owner) = holding_prefix(links, start)?;
    let narrower_inside = links
        .iter()
        .enumerate()
        .filter(|(other, _)| *other != idx)
        .flat_map(|(_, link)| link.addresses())
        .filter(|held| held.prefix() > owner.prefix())
        .map(|held| held.network())
        .filter(|network| network.len() > 1)
        .any(|network| {
            let (low, high) = (network.start_addr(), network.end_addr());
            low.is_ipv4() == start.is_ipv4() && low <= end && start <= high
        });

    (links[idx].carries_frames() && owner.contains(&end) && !narrower_inside).then_some(idx)
}

/// The interface holding the most specific prefix that contains `target`,
/// and the address it holds there.
///
/// The kernel sends by the most specific connected route, so this does too: a
/// VPN's `/24` inside a LAN's `/8` takes the targets in the `/24`. On a tie the
/// first interface listed wins. Matching is within one address family.
///
/// On a link that carries frames the prefix is a segment, swept at the link
/// layer. On a tunnel it is only a route: its peers (a WireGuard peer, an
/// OpenVPN server in subnet topology) are probed through the tunnel from the
/// tunnel's address, since nothing behind it answers ARP or neighbour
/// discovery.
fn holding_prefix(links: &[Link], target: IpAddr) -> Option<(usize, LinkAddress)> {
    let mut best: Option<(usize, LinkAddress)> = None;
    for (idx, link) in links.iter().enumerate() {
        for held in link.addresses() {
            if held.contains(&target) && best.is_none_or(|(_, b)| held.prefix() > b.prefix()) {
                best = Some((idx, *held));
            }
        }
    }
    best
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
    use crate::model::mac::MacAddr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// An Ethernet interface holding one address.
    fn mock_named(name: &str, index: u32, ip: IpAddr, prefix: u8) -> Link {
        Link::new(name, index)
            .with_mac(MacAddr::new(0x02, 0, 0, 0, 0, index as u8))
            .with_addressing(crate::system::interface::Addressing::Broadcast)
            .with_addresses(vec![crate::system::interface::LinkAddress::new(ip, prefix)])
    }

    fn mock_interface(ip: IpAddr, prefix: u8) -> Link {
        mock_named("test0", 0, ip, prefix)
    }

    #[test]
    fn the_interface_holding_a_targets_prefix_is_found() {
        let interfaces = vec![
            mock_interface(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 100)), 24),
            mock_interface(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)), 24),
        ];
        let holder = |target: [u8; 4]| {
            holding_prefix(&interfaces, IpAddr::V4(Ipv4Addr::from(target))).map(|(idx, _)| idx)
        };

        assert_eq!(holder([192, 0, 2, 50]), Some(0));
        assert_eq!(holder([198, 51, 100, 200]), Some(1));
        assert_eq!(holder([203, 0, 113, 1]), None, "held by neither");
    }

    /// A routed target whose route refuses by policy is given to no raw strategy,
    /// forced source or fallback source; the connect fallback meets the same
    /// refusal as the rest of the machine. A missing route still gets the
    /// fallback.
    #[test]
    fn a_routed_target_a_route_forbids_is_left_to_the_connect_fallback() {
        let global = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5));
        let lan = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let interfaces = || vec![mock_interface(global, 64), mock_interface(lan, 24)];
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 9, 0, 0, 0, 0, 1));
        let v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let targets = || {
            let mut set = IpSet::new();
            set.insert(v6);
            set.insert(v4);
            set
        };

        let forbidden = map_ips_to_interfaces_asking(targets(), interfaces(), &[lan], |_| {
            RouteAnswer::Forbidden
        });
        assert!(forbidden.routed.is_empty(), "{:?}", forbidden.routed);
        assert!(forbidden.unmapped.contains(&v6) && forbidden.unmapped.contains(&v4));

        let missing =
            map_ips_to_interfaces_asking(targets(), interfaces(), &[], |_| RouteAnswer::NoRoute);
        assert!(
            missing
                .routed
                .iter()
                .any(|routed| routed.target == v6 && routed.source == global),
            "{:?}",
            missing.routed
        );
    }

    /// A neighbour the routing table refuses is found among a segment's targets,
    /// walked or named, and nothing else is: not its neighbours, not the
    /// segment's network and broadcast addresses, and not a link-local address.
    #[test]
    fn a_neighbour_the_routing_table_refuses_is_told_apart_from_the_segment() {
        let link = mock_interface(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24);
        let mut targets = IpSet::new();
        targets.insert_range(IpRange::V4(
            Ipv4Range::new(Ipv4Addr::new(192, 0, 2, 0), Ipv4Addr::new(192, 0, 2, 255)).unwrap(),
        ));
        targets.insert(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 13)));
        targets.insert(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 13)));

        // Refuses every address whose last group is 13, and the segment's
        // edges, as a kernel refuses a broadcast.
        let refused = refused_neighbours_asking(&link, &targets, |target| match target {
            IpAddr::V4(v4) => matches!(v4.octets()[3], 0 | 13 | 255),
            IpAddr::V6(v6) => v6.segments()[7] == 13,
        });

        let mut expected = IpSet::new();
        expected.insert(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 13)));
        expected.insert(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 13)));
        expected.canonicalize();
        assert_eq!(refused, expected);
    }

    #[test]
    fn on_link_v4_range_stays_intact_and_local() {
        let interfaces = vec![mock_interface(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24)];
        let mut set = IpSet::new();
        set.insert_range(IpRange::V4(
            Ipv4Range::new(Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(192, 0, 2, 20)).unwrap(),
        ));

        let result = map_ips_to_interfaces_with(set, interfaces, &[]);

        assert!(result.routed.is_empty());
        assert!(result.unmapped.is_empty());
        assert_eq!(result.local.len(), 1);
        let (_, ips) = result.local.into_iter().next().unwrap();
        assert_eq!(ips.len(), 11);
    }

    /// The boundary of the enumeration ceiling, checked exactly, without
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

    /// A routed `/64` expanded into a `Vec<IpAddr>` exhausts memory. It must
    /// come out as its own category so the caller can tell it from a range with
    /// nothing on it.
    #[test]
    fn a_routed_v6_prefix_too_large_to_walk_is_refused_rather_than_expanded() {
        let interfaces = vec![mock_interface(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24)];
        let mut set = IpSet::new();
        set.insert_range(IpRange::V6(
            Ipv6Range::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff),
            )
            .unwrap(),
        ));

        let result = map_ips_to_interfaces_with(set, interfaces, &[]);

        assert_eq!(result.unenumerable.len(), 1, "the /64 is reported whole");
        assert!(result.routed.is_empty());
        assert!(result.unmapped.is_empty());
        assert!(result.local.is_empty());
    }

    /// Every interface holds an `fe80::/64`, so a bare link-local target matches
    /// all of them, and `owning_interface` would return whichever the host listed
    /// first.
    #[test]
    fn a_link_local_target_naming_no_interface_is_refused() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA);
        let interfaces = vec![
            mock_interface(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 64),
            mock_interface(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)), 64),
        ];
        let mut set = IpSet::new();
        set.insert(IpAddr::V6(link_local));

        let result = map_ips_to_interfaces_with(set, interfaces, &[]);

        assert_eq!(result.ambiguous.len(), 1);
        assert!(
            result.local.is_empty(),
            "guessing an interface is what this prevents"
        );
    }

    /// Named, the same target is unambiguous, and the name outranks any prefix
    /// match.
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

        let result = map_ips_to_interfaces_with(set, vec![first, second], &[]);

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

        let result = map_ips_to_interfaces_with(set, interfaces, &[]);

        assert!(result.routed.is_empty());
        assert!(result.unmapped.is_empty());
        assert_eq!(result.local.len(), 1);
        let (_, ips) = result.local.into_iter().next().unwrap();
        assert_eq!(ips.len(), 5);
    }

    /// This host's own LAN address sits inside its interface's subnet, so the
    /// on-link test claims it, but no probe can establish it because the kernel
    /// routes it through loopback.
    #[test]
    fn an_address_this_host_holds_is_ours_rather_than_on_link() {
        let own: IpAddr = "203.0.113.160".parse().unwrap();
        let interfaces = vec![mock_interface(own, 24)];

        let mut targets = IpSet::new();
        targets.insert(own);

        let routed = map_ips_to_interfaces_with(targets, interfaces, &[]);

        assert!(routed.ours.contains(&own), "the address is this host's own");
        assert!(
            routed.local.is_empty(),
            "and must not be handed to a link-layer strategy"
        );
    }

    /// A neighbour on the same segment still gets the on-link strategy.
    #[test]
    fn a_neighbour_on_the_same_segment_is_still_on_link() {
        let own: IpAddr = "203.0.113.160".parse().unwrap();
        let neighbour: IpAddr = "203.0.113.101".parse().unwrap();
        let interfaces = vec![mock_interface(own, 24)];

        let mut targets = IpSet::new();
        targets.insert(neighbour);

        let routed = map_ips_to_interfaces_with(targets, interfaces, &[]);

        assert!(routed.ours.is_empty());
        assert_eq!(
            routed.local.values().next().map(IpSet::len),
            Some(1u128),
            "the neighbour is on-link"
        );
    }

    /// A link a frame can be put on: a hardware address and a segment.
    fn ethernet(addresses: &[(&str, u8)]) -> Link {
        Link::new("en0", 4)
            .with_mac(crate::model::mac::MacAddr::new(0x02, 0, 0, 0, 0, 0x10))
            .with_kind(crate::system::interface::LinkKind::Wired)
            .with_addressing(crate::system::interface::Addressing::Broadcast)
            .with_link_up(true)
            .with_addresses(held(addresses))
    }

    /// A VPN's tunnel, as macOS presents one: a peer and no segment, and no
    /// hardware address.
    fn tunnel(addresses: &[(&str, u8)]) -> Link {
        Link::new("utun9", 20)
            .with_addressing(crate::system::interface::Addressing::PointToPoint)
            .with_link_up(true)
            .with_addresses(held(addresses))
    }

    fn held(addresses: &[(&str, u8)]) -> Vec<crate::system::interface::LinkAddress> {
        addresses
            .iter()
            .map(|(address, prefix)| {
                crate::system::interface::LinkAddress::new(
                    address.parse().expect("a literal"),
                    *prefix,
                )
            })
            .collect()
    }

    fn set_of(addresses: &[&str]) -> IpSet {
        let mut set = IpSet::new();
        for address in addresses {
            set.insert(address.parse().expect("a literal"));
        }
        set
    }

    fn ip(literal: &str) -> IpAddr {
        literal.parse().expect("a literal")
    }

    /// Without its own check, `::1` would be classified as a routed target with
    /// a global source: the kernel answers it from `::1`, no viable interface
    /// holds that, and the VPN fallback offers the first global address.
    /// `127.0.0.1` would be spared only because the fallback declines IPv4. A
    /// forced source would do the same to both.
    #[test]
    fn loopback_is_unmapped_in_both_families_whatever_is_forced() {
        let interfaces = vec![ethernet(&[("192.0.2.10", 24), ("2001:db8:1::10", 64)])];
        let forced = [ip("192.0.2.10"), ip("2001:db8:1::10")];

        for forced in [&forced[..], &[]] {
            let routed = map_ips_to_interfaces_with(
                set_of(&["127.0.0.1", "::1"]),
                interfaces.clone(),
                forced,
            );

            assert!(
                routed.routed.is_empty(),
                "loopback is not behind a gateway: {:?}",
                routed.routed
            );
            assert!(routed.unmapped.contains(&ip("127.0.0.1")));
            assert!(routed.unmapped.contains(&ip("::1")));
        }
    }

    /// An IPv4-mapped address is an IPv4 host no frame can carry, so it is never
    /// paired with an IPv6 source and framed toward the router, whatever source
    /// is forced and whatever global address the host holds.
    #[test]
    fn a_mapped_address_is_unmapped_whatever_is_forced() {
        let interfaces = vec![ethernet(&[("192.0.2.10", 24), ("2001:db8:1::10", 64)])];
        let forced = [ip("192.0.2.10"), ip("2001:db8:1::10")];

        for forced in [&forced[..], &[]] {
            let routed = map_ips_to_interfaces_with(
                set_of(&["::ffff:127.0.0.1", "::ffff:198.51.100.7"]),
                interfaces.clone(),
                forced,
            );

            assert!(
                routed.routed.is_empty(),
                "a mapped address is not behind a gateway: {:?}",
                routed.routed
            );
            assert!(routed.unmapped.contains(&ip("::ffff:127.0.0.1")));
            assert!(routed.unmapped.contains(&ip("::ffff:198.51.100.7")));
        }
    }

    /// And a frames-only run says why it reaches one by connect.
    #[test]
    fn a_mapped_address_is_beyond_frames_as_what_it_is() {
        let beyond = beyond_frames_with(
            set_of(&["::ffff:198.51.100.7"]),
            vec![ethernet(&[("192.0.2.10", 24), ("2001:db8:1::10", 64)])],
            &[],
            FrameSender::Probe,
        );

        assert_eq!(
            beyond.summary(),
            vec![(Unframed::Mapped, ip("::ffff:198.51.100.7"), 1)]
        );
    }

    /// A connect step holds what a frame cannot reach and what no route leads
    /// to, and names each address for what it is: loopback, mapped (whichever
    /// block it was written in), or no route. An address already held keeps its
    /// reason.
    #[test]
    fn what_no_route_leads_to_is_named_for_what_it_is() {
        let held = beyond_frames_with(
            set_of(&["::ffff:198.51.100.7"]),
            vec![ethernet(&[("192.0.2.10", 24), ("2001:db8:1::10", 64)])],
            &[],
            FrameSender::Probe,
        );

        let all = held.and_unmapped(&set_of(&[
            "::ffff:198.51.100.7",
            "127.0.0.2",
            "::1",
            "::ffff:127.0.0.1",
            "203.0.113.9",
            "203.0.113.10",
        ]));

        assert_eq!(
            all.summary(),
            vec![
                (Unframed::Mapped, ip("::ffff:127.0.0.1"), 2),
                (Unframed::Loopback, ip("127.0.0.2"), 2),
                (Unframed::NoRoute, ip("203.0.113.9"), 2),
            ]
        );
        assert_eq!(all.targets.len(), 6);
    }

    /// What a frame reaches: a neighbour it can ARP for, and a routed target
    /// whose route leaves by a link with Ethernet in front of it.
    #[test]
    fn a_frame_reaches_an_ipv4_neighbour_and_a_target_routed_over_ethernet() {
        let beyond = beyond_frames_with(
            set_of(&["192.0.2.50", "203.0.113.9"]),
            vec![ethernet(&[("192.0.2.10", 24)])],
            &[ip("192.0.2.10")],
            FrameSender::Probe,
        );

        assert!(beyond.is_empty(), "nothing out of reach: {beyond:?}");
    }

    /// The kernel sends the target from the tunnel's address, so its route
    /// leaves by a link no frame can be put on.
    #[test]
    fn a_target_routed_through_a_tunnel_is_beyond_frames() {
        let beyond = beyond_frames_with(
            set_of(&["203.0.113.23"]),
            vec![
                ethernet(&[("192.0.2.10", 24)]),
                tunnel(&[("198.51.100.2", 32)]),
            ],
            &[ip("198.51.100.2")],
            FrameSender::Sweep,
        );

        assert!(beyond.targets.contains(&ip("203.0.113.23")));
        assert_eq!(
            beyond.summary(),
            vec![(Unframed::Tunnel("utun9".into()), ip("203.0.113.23"), 1)]
        );
        assert!(beyond.is_a_fallback(), "a raw socket reaches it");
    }

    /// A tunnel's own subnet is not a segment. Its subnet and a target routed
    /// through it are one reason, counted once.
    #[test]
    fn a_tunnels_own_subnet_is_beyond_frames_under_the_same_reason() {
        let beyond = beyond_frames_with(
            set_of(&["198.51.100.7", "203.0.113.23"]),
            vec![tunnel(&[("198.51.100.2", 24)])],
            &[ip("198.51.100.2")],
            FrameSender::Sweep,
        );

        assert_eq!(beyond.targets.len(), 2);
        assert_eq!(
            beyond.summary(),
            vec![(Unframed::Tunnel("utun9".into()), ip("198.51.100.7"), 2)]
        );
    }

    /// A WireGuard peer, or an OpenVPN server in subnet topology, sits inside
    /// the prefix the tunnel's own address carries, and is probed through the
    /// tunnel from the tunnel's address, as the kernel would send to it.
    #[test]
    fn a_host_on_a_tunnels_own_subnet_is_routed_through_the_tunnel() {
        let interfaces = vec![
            ethernet(&[("192.0.2.10", 24)]),
            tunnel(&[("198.51.100.2", 24), ("2001:db8:66::2", 64)]),
        ];

        let routed = map_ips_to_interfaces_with(
            set_of(&["198.51.100.1", "2001:db8:66::1"]),
            interfaces,
            &[],
        );

        assert!(
            routed.local.is_empty(),
            "a tunnel has no segment to sweep: {:?}",
            routed.local
        );
        assert_eq!(
            routed.routed,
            vec![
                RoutedTarget {
                    target: ip("198.51.100.1"),
                    source: ip("198.51.100.2"),
                },
                RoutedTarget {
                    target: ip("2001:db8:66::1"),
                    source: ip("2001:db8:66::2"),
                },
            ]
        );
    }

    /// A peer on the tunnel's own subnet is reached only through that tunnel,
    /// so a forced source does not apply and it keeps the tunnel's address.
    #[test]
    fn a_forced_source_does_not_take_a_host_off_its_tunnels_subnet() {
        let routed = map_ips_to_interfaces_with(
            set_of(&["198.51.100.1"]),
            vec![
                ethernet(&[("192.0.2.10", 24)]),
                tunnel(&[("198.51.100.2", 24)]),
            ],
            &[ip("192.0.2.10")],
        );

        assert_eq!(
            routed.routed,
            vec![RoutedTarget {
                target: ip("198.51.100.1"),
                source: ip("198.51.100.2"),
            }]
        );
    }

    /// A sweep of the tunnel's whole subnet is a list of peers to probe through
    /// it, less the tunnel's own address, which is this host's.
    #[test]
    fn a_tunnels_subnet_as_a_range_is_routed_address_by_address() {
        let mut targets = IpSet::new();
        targets.insert_range(V4(Ipv4Range::new(
            "198.51.100.0".parse().unwrap(),
            "198.51.100.3".parse().unwrap(),
        )
        .expect("an ordered range")));

        let routed =
            map_ips_to_interfaces_with(targets, vec![tunnel(&[("198.51.100.2", 24)])], &[]);

        assert!(routed.local.is_empty(), "{:?}", routed.local);
        let probed: Vec<IpAddr> = routed.routed.iter().map(|r| r.target).collect();
        assert_eq!(
            probed,
            ["198.51.100.0", "198.51.100.1", "198.51.100.3"].map(ip)
        );
        assert!(routed.routed.iter().all(|r| r.source == ip("198.51.100.2")));
        assert!(routed.ours.contains(&ip("198.51.100.2")));
        assert_eq!(routed.ours.len(), 1);
    }

    /// Prefixes nest, and the most specific one is the route, as in the kernel:
    /// a VPN's prefix inside the LAN's takes its own targets, and a LAN inside a
    /// tunnel's wider prefix keeps its neighbours.
    #[test]
    fn the_most_specific_prefix_decides_between_a_segment_and_a_tunnel() {
        let interfaces = vec![
            ethernet(&[("198.51.100.10", 24), ("2001:db8:0:1::10", 64)]),
            tunnel(&[("198.51.100.130", 25), ("2001:db8::2", 40)]),
        ];

        let routed = map_ips_to_interfaces_with(
            set_of(&[
                "198.51.100.7",
                "198.51.100.200",
                "2001:db8:0:1::20",
                "2001:db8:5::1",
            ]),
            interfaces,
            &[],
        );

        let swept: Vec<IpAddr> = routed.local.values().flat_map(IpSet::iter).collect();
        assert_eq!(swept, ["198.51.100.7", "2001:db8:0:1::20"].map(ip));
        assert_eq!(
            routed.routed,
            vec![
                RoutedTarget {
                    target: ip("198.51.100.200"),
                    source: ip("198.51.100.130"),
                },
                RoutedTarget {
                    target: ip("2001:db8:5::1"),
                    source: ip("2001:db8::2"),
                },
            ]
        );
    }

    /// A segment's range stays whole around a host prefix, on its own link or
    /// on a tunnel.
    #[test]
    fn a_host_prefix_inside_a_segments_range_leaves_the_range_whole() {
        let mut lan = ethernet(&[("2001:db8:1::10", 64)]);
        lan = lan.with_addresses(held(&[("2001:db8:1::10", 64), ("2001:db8:1::abcd", 128)]));
        let interfaces = vec![lan, tunnel(&[("2001:db8:1::99", 128)])];

        let mut targets = IpSet::new();
        targets.insert_range(V6(Ipv6Range::new(
            "2001:db8:1::".parse().unwrap(),
            "2001:db8:1::ffff:ffff:ffff:ffff".parse().unwrap(),
        )
        .expect("an ordered range")));

        let routed = map_ips_to_interfaces_with(targets, interfaces, &[]);

        assert!(routed.unenumerable.is_empty(), "{:?}", routed.unenumerable);
        assert_eq!(routed.local.len(), 1, "the /64 is swept on its segment");
    }

    /// The segment sweep resolves an IPv6 neighbour itself; the probe sender
    /// has only ARP.
    #[test]
    fn an_ipv6_neighbour_is_within_the_sweep_and_beyond_the_probe_sender() {
        let interfaces = vec![ethernet(&[("192.0.2.10", 24), ("2001:db8:1::10", 64)])];
        let targets = set_of(&["2001:db8:1::20", "192.0.2.50"]);

        let swept =
            beyond_frames_with(targets.clone(), interfaces.clone(), &[], FrameSender::Sweep);
        assert!(swept.is_empty(), "the sweep reaches both: {swept:?}");

        let probed = beyond_frames_with(targets, interfaces, &[], FrameSender::Probe);
        assert_eq!(
            probed.summary(),
            vec![(Unframed::Neighbour("en0".into()), ip("2001:db8:1::20"), 1)],
            "and the probe sender only the IPv4 one"
        );
    }

    /// The kernel answers these itself, so a frame for either reaches nobody who
    /// replies. Two reasons, in the order a message names them.
    #[test]
    fn loopback_and_this_hosts_own_addresses_are_beyond_frames() {
        let beyond = beyond_frames_with(
            set_of(&["127.0.0.1", "::1", "192.0.2.10"]),
            vec![ethernet(&[("192.0.2.10", 24)])],
            &[],
            FrameSender::Probe,
        );

        assert_eq!(
            beyond.summary(),
            vec![
                (Unframed::Loopback, ip("127.0.0.1"), 2),
                (Unframed::Ours, ip("192.0.2.10"), 1),
            ]
        );
        assert!(!beyond.is_a_fallback(), "connect is their route");
    }

    /// One address behind a tunnel makes the whole set a fallback, however
    /// many others are this host's own: a segment routed into a VPN holds the
    /// host's address and every other address through the tunnel.
    #[test]
    fn one_tunnelled_target_makes_a_connect_a_fallback() {
        let mut beyond = BeyondFrames::default();
        beyond.note(Unframed::Ours, set_of(&["192.0.2.10"]));
        assert!(!beyond.is_a_fallback());

        beyond.note(Unframed::Tunnel("utun9".into()), set_of(&["192.0.2.11"]));
        assert!(beyond.is_a_fallback());
        assert_eq!(beyond.reasons(), "own address, via utun9");
    }

    /// A routed target the kernel would send from the tunnel is sent from the
    /// forced LAN source, and the routing table is never asked: the source is
    /// picked by family.
    #[test]
    fn a_forced_source_outranks_the_routing_table_for_a_routed_target() {
        let lan: IpAddr = "203.0.113.160".parse().unwrap();
        let public: IpAddr = "1.1.1.1".parse().unwrap();
        let interfaces = vec![mock_interface(lan, 24)];

        let mut targets = IpSet::new();
        targets.insert(public);

        let routed = map_ips_to_interfaces_with(targets, interfaces, &[lan]);

        assert_eq!(
            routed.routed,
            vec![RoutedTarget {
                target: public,
                source: lan
            }],
            "the off-link target is probed from the forced source"
        );
    }
}
