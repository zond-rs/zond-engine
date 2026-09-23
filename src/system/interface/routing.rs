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
//! A segment is a link a frame can be put on. A tunnel's address carries a
//! prefix too, and a WireGuard peer or an OpenVPN server in subnet topology
//! sits inside it, but nothing on the far side of a tunnel answers ARP or
//! neighbour discovery: the prefix is a route through the tunnel, and a target
//! inside it is probed through the tunnel like any routed target.
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
//! ## What a frame reaches
//!
//! A second question is asked of the same classification, by a process whose
//! raw strategies put self-built frames on the wire with nothing behind them:
//! an unprivileged run on macOS holding the BPF devices, and a privileged one on
//! Windows. A frame reaches what has Ethernet in front of it, and
//! [`beyond_frames`] names the rest and why, so that a scan can reach those
//! targets by connect instead of sending them nothing.
//!
//! ## What it costs
//!
//! One `connect` per off-link target on an unbound UDP socket, which performs a
//! route lookup and sends nothing, parallelised across the target list. On-link
//! targets cost a prefix comparison and no syscall at all.

use crate::model::ip::range::IpRange::{self, V4, V6};
use crate::model::ip::range::{Ipv4Range, Ipv6Range};
use crate::model::ip::set::IpSet;
use crate::system::interface::source::{
    ProbeSockets, plausible_source, probe_route_source, viable_interfaces,
};
use crate::system::interface::{Link, LinkAddress};
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
/// It is the same number as the largest IPv4 range anyone sweeps
/// in practice, because the limit is about how many probes a scan can spend
/// rather than about the address family. Larger IPv6 ranges are not scanned
/// less thoroughly here; they are refused, loudly, so the caller knows the
/// engine did not look rather than believing it looked and found nothing.
///
/// IPv4 ranges are not bounded by this. Every IPv4 range is finite in a way a
/// user can reason about, the whole space is 2^32, and a `/8` is an
/// unreasonable request rather than an impossible one.
///
/// Public as the number, where [`is_enumerable`] is the test: three places
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
    ///
    /// Only a link that carries frames has a segment. The one exception is a
    /// link-local target whose zone names a link that does not: the zone is
    /// the user's own statement of where the target is, and it is kept.
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
    /// Separated because no strategy can establish one. An address the host
    /// holds is reached through loopback whatever its subnet says, so an ARP
    /// request for it goes onto a link where nothing will answer, and the
    /// address is reported down while `ping` to it succeeds. It is up by
    /// construction, and saying so is both the correct answer and the cheap one.
    pub ours: IpSet,
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
/// interface), routed through a gateway or a tunnel (paired with a source
/// address), or unreachable.
///
/// Reads the host's interface table through
/// [`interfaces`](super::interfaces), narrowed to the links that could carry a
/// probe. Where that table comes from is [`Link::from_netdev`](super::Link)'s
/// business and nobody else's, so nothing here names the crate that reads it.
pub fn map_ips_to_interfaces(ip_set: IpSet) -> RoutedTargets {
    map_ips_to_interfaces_with(ip_set, viable_interfaces(), &[])
}

/// [`map_ips_to_interfaces`], with source addresses forced ahead of the routing
/// table. A scan pinned to an interface routes every off-link target from that
/// interface's address, the override for a host whose default route a VPN owns.
pub(crate) fn map_ips_to_interfaces_forced(ip_set: IpSet, forced: &[IpAddr]) -> RoutedTargets {
    map_ips_to_interfaces_with(ip_set, viable_interfaces(), forced)
}

/// Per-single classification carried out of the parallel pass, before the
/// results are folded back into interface-indexed buckets.
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
/// The seam every classification decision in this module is tested through: on
/// a real host the table comes from the platform, and a test hands in
/// interfaces that do not exist, so which bucket a target lands in can be
/// exercised without depending on what the machine running the tests happens to
/// have plugged in.
pub(crate) fn map_ips_to_interfaces_with(
    ip_set: IpSet,
    interfaces: Vec<Link>,
    forced: &[IpAddr],
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
            // Loopback is this host, and nothing below may say otherwise. The
            // kernel answers `::1` with `::1`, which no interface here holds, and
            // the fallback after it would then pair the target with a global
            // source as though it were a routed address behind a VPN; a forced
            // source would do the same. `127.0.0.1` would fall through to
            // `Unmapped` only because that fallback declines IPv4, so without
            // this the two loopbacks would be planned differently for no reason
            // either of them has.
            if target.is_loopback() {
                return (target, Classification::Unmapped);
            }
            // An IPv4-mapped address is an IPv4 host written inside IPv6, and
            // no wire carries one. The fallbacks below would pair it with a
            // global IPv6 source as a routed target and frame it toward the
            // router, which is the one place it certainly is not. Unmapped, it
            // is left to whatever asks the kernel, whose dual-stack socket
            // reaches the IPv4 host it spells.
            if is_ipv4_mapped(target) {
                return (target, Classification::Unmapped);
            }
            // Before any prefix is consulted, because this host's address is
            // inside its own link's prefix and the kernel answers it from
            // loopback whatever that prefix says.
            if owned_ips.contains(&target) {
                return (target, Classification::Ours);
            }

            // Inside a prefix this host holds, the link holding it is the one
            // route to the target. A segment is swept; inside a tunnel's own
            // prefix the target is reached through the tunnel from the
            // tunnel's address. Read off the interface table rather than asked
            // of the kernel: the table already says it, and a forced source
            // must not move the target off the only link that reaches it.
            if let Some((idx, held)) = holding_prefix(&interfaces, target) {
                return if interfaces[idx].carries_frames() {
                    (target, Classification::Local(idx))
                } else {
                    (target, Classification::Routed(held.address()))
                };
            }

            // A forced source outranks the routing table. On-link and tunnel
            // targets are already settled above and answer through their own
            // link; a routed target the kernel would send from the wrong
            // interface is what the override exists for.
            if let Some(source) = forced
                .iter()
                .copied()
                .find(|s| s.is_ipv4() == target.is_ipv4())
            {
                return (target, Classification::Routed(source));
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
            Classification::Ours => ours.insert(target),
        }
    }

    // Withheld from every strategy. The per-address pass settles an address
    // this host holds before anything else, but a range wholly inside a
    // segment's subnet is kept intact and assigned to that link without ever
    // reaching that pass, so an address it holds arrives here inside a set:
    // a sweep of the subnet containing it ends up in `local` whole.
    //
    // Nothing can establish one. The kernel routes traffic for an address this
    // host holds through loopback, so an ARP request goes onto a link where
    // nothing will answer and the address is reported down while `ping` to it
    // succeeds.
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

/// Which of the engine's two frame builders a question about reach is asked for.
///
/// They differ in one respect, and it decides what they reach. The segment sweep
/// resolves an IPv6 neighbour itself, by neighbour discovery over the link it
/// holds open. The probe transport's frame sender has ARP and nothing else, so an
/// IPv6 neighbour on the same segment is one it has no hardware address to send
/// to.
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

/// A few words, since a message puts one in brackets after the addresses it
/// covers.
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
/// Built by [`beyond_frames`]. What it serves is a process that may inject
/// frames and holds nothing else, which is an unprivileged run on macOS with
/// the BPF devices handed to a group, and every privileged run on Windows. The
/// frames reach whatever has Ethernet in front of it; everything here needs the
/// kernel to carry it, and so needs a strategy that asks the kernel.
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
    /// covered, which is what a message about the set quotes.
    pub(crate) fn summary(&self) -> Vec<(Unframed, IpAddr, u128)> {
        self.reasons
            .iter()
            .filter_map(|(reason, targets)| {
                let first = targets.iter().next()?;
                Some((reason.clone(), first, targets.len()))
            })
            .collect()
    }

    /// One reason and the addresses it covers.
    fn note(&mut self, reason: Unframed, mut targets: IpSet) {
        targets.canonicalize();
        if targets.is_empty() {
            return;
        }
        extend(&mut self.targets, &targets);
        self.reasons.push((reason, targets));
    }
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
/// Classified the way [`map_ips_to_interfaces_forced`] classifies, and so by the
/// routing table: a routed target is out of reach when the source the kernel
/// would send it from belongs to a link that carries no frames. That is the
/// kernel's own statement of where the packet leaves, and a VPN that routes a
/// target through its tunnel has made it here. The frame sender's own choice of
/// egress is not consulted, because it is the thing whose reach is in question.
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

    // Grouped by reason before anything is counted, since one tunnel can hold
    // targets on its own subnet and targets routed through it alike.
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

    for address in unmapped.iter() {
        let reason = if address.is_loopback() {
            Unframed::Loopback
        } else if is_ipv4_mapped(address) {
            Unframed::Mapped
        } else {
            Unframed::NoRoute
        };
        add(reason, single(address));
    }
    for range in ours.v4() {
        add(Unframed::Ours, V4(*range));
    }
    for range in ours.v6() {
        add(Unframed::Ours, V6(*range));
    }

    // Sorted by name, so the order a message lists them in does not depend on a
    // hash map's.
    let mut local: Vec<(Link, IpSet)> = local.into_iter().collect();
    local.sort_by(|(a, _), (b, _)| a.name().cmp(b.name()));
    for (link, targets) in &local {
        // Only a link-local target whose zone named a tunnel is in `local` on
        // a link without frames; a tunnel's own subnet is routed through it.
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
        // A source no link here holds is a forced one naming an address this
        // host does not have. The frame sender builds that frame as asked, and
        // a connect could not honour it, so it is left where it is.
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
/// The question every strategy that walks addresses has to ask before it starts,
/// and the reason it is asked of a range rather than of a set: a set holding a
/// `/64` and three literals is partly walkable, and refusing all four of them
/// would throw away three addresses somebody named. See
/// [`MAX_ENUMERABLE_ADDRESSES`].
pub fn is_enumerable(range: &Ipv6Range) -> bool {
    range.len() <= MAX_ENUMERABLE_ADDRESSES
}

/// The segment the whole inclusive range `[start, end]` is on, if it is on one.
///
/// A range is kept whole only where one link answers for every address in
/// it: the segment's, with no narrower prefix on another link inside the range
/// to take some of it elsewhere, a VPN's `/24` within the LAN's `/8` for one.
/// Anything less is expanded and each address asks [`holding_prefix`] for
/// itself.
///
/// A host prefix does not count. A `/32` or `/128` routes only the address it
/// was assigned with, which is this host's own and is withheld as that, and
/// Linux lists every DHCPv6 address as one: splitting an on-link `/64` around
/// it would refuse the segment as too large to walk, where it is swept whole.
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
/// Each prefix an address carries is a connected route, and the kernel sends
/// by the most specific one, so this does too: a VPN's `/24` inside a LAN's
/// `/8` takes the targets in the `/24`. On a tie the first interface listed
/// wins. Matching is within one address family, the check
/// `LinkAddress::contains` already makes.
///
/// What the prefix means depends on the link. On one that carries frames it is
/// a segment, swept at the link layer. On a tunnel it is only a route: its
/// peers sit inside it, a WireGuard peer on the tunnel's `/24` or an OpenVPN
/// server in subnet topology, and a link-layer strategy handed one sends it
/// nothing, since no frame can be put on the tunnel and nothing behind it
/// answers ARP or neighbour discovery. Such a peer is probed through the
/// tunnel from the tunnel's address.
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

    /// An Ethernet interface holding one address, which is the segment the
    /// on-link tests below are about.
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

        let result = map_ips_to_interfaces_with(set, interfaces, &[]);

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

    /// The case that sends a scan of this host's own LAN address looking for an
    /// ARP reply nothing would send: the address sits inside its own
    /// interface's subnet, so the on-link test claims it, and no probe can
    /// establish it because the kernel routes it through loopback.
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

    /// A neighbour on the same segment still gets the on-link strategy, which is
    /// the half of the distinction that has to keep working.
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

    /// A VPN's tunnel, as macOS presents one: a peer rather than a segment, and
    /// no hardware address.
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

    /// Without its own check, `::1` would come out of the classifier as a
    /// routed target paired with a global source, because the kernel answers it
    /// from `::1`, no viable interface holds that, and the VPN fallback then
    /// offers the first global address it finds. `127.0.0.1` would be spared
    /// only because that fallback declines IPv4. A forced source would do the
    /// same to both.
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

    /// And a frames-only run says why it reaches one by connect rather than
    /// calling it unroutable.
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

    /// What a frame reaches, which has to keep working for the split to be worth
    /// anything: a neighbour it can ARP for, and a routed target whose route
    /// leaves by a link with Ethernet in front of it.
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

    /// The case a VPN makes: the kernel sends the target from the tunnel's
    /// address, so its route leaves by a link no frame can be put on, and the
    /// frame sender's own guess at an egress is not what decides it.
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
    }

    /// A tunnel with a prefix of its own claims its subnet as on-link, and it is
    /// no more a segment for that. Its own subnet and a target routed through it
    /// are one reason, counted once.
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
    /// the prefix the tunnel's own address carries. That prefix is a route
    /// through the tunnel and not a segment, so the peer is probed through the
    /// tunnel from the tunnel's address, the way the kernel would send to it.
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

    /// A forced source is for a target the routing table would send through
    /// the wrong interface. A peer on the tunnel's own subnet is reached through
    /// that tunnel and nowhere else, so it keeps the tunnel's address as a
    /// neighbour on a segment keeps the segment's.
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

    /// Prefixes nest, and the most specific one is the route, as it is in the
    /// kernel: a VPN's prefix inside the LAN's takes its own targets, and a
    /// LAN inside a tunnel's wider prefix keeps its neighbours.
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
    /// on a tunnel. Each covers only an address this host holds, and splitting
    /// an on-link `/64` around one would refuse it as too large to walk.
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

    /// The one place the two frame builders differ. The segment sweep resolves
    /// an IPv6 neighbour itself; the probe sender has ARP and nothing else.
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
    }

    /// The VPN case made deterministic: a routed target the kernel would send
    /// from the tunnel is sent from the forced LAN source instead, and the
    /// routing table is never asked - the source picks itself by family.
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
