// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What this machine is plugged into, as this engine needs it
//!
//! One type, [`Link`], owned by this crate rather than borrowed from whichever
//! library happened to enumerate it.
//!
//! ## Why this is a type here and not a re-export
//!
//! It was a re-export: every function that took an interface took
//! `pnet::datalink::NetworkInterface`, and that type reached the public API
//! through half a dozen signatures. Two things were wrong with that, and only
//! one of them was about `pnet`.
//!
//! The one about `pnet`: its Windows backend fills the flags word with a
//! literal zero and a `FIXME`, so `is_up()` was false for every interface on
//! that platform, always. Nothing errored. Every entry point in this engine
//! filtered on it, found nothing, and reported a machine with no network, which
//! is the one failure shape the rest of this crate is built to refuse.
//!
//! The one that outlives it: swapping that type for another library's would
//! have fixed the platform and kept the shape, and the next library's defect
//! would arrive by the same route. A consumer of this crate should not have to
//! know which crate read the interface table, any more than they have to know
//! which syscall did. So the facts an interface has are named here, and where
//! they come from is [`from_netdev`](Link::from_netdev)'s business and nobody
//! else's.
//!
//! ## What it does not carry
//!
//! Speed, MTU, DNS servers, statistics. All available from the source and none
//! of them read by anything in this engine, and a field nothing reads is a
//! field that is wrong on some platform without anybody finding out.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::model::ip::range::{IpRange, cidr_range};
use crate::model::ip::scoped::Zone;
use crate::model::ip::set::IpSet;
use crate::model::mac::MacAddr;

/// One address an interface holds, and how much of it names the network.
///
/// The pair is kept together because the two halves answer different questions
/// and both are asked: the address is what a probe goes out *from*, and the
/// network is what decides whether a target is on this link or beyond it.
/// Carrying only the first loses on-link tests; carrying only the second loses
/// source selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkAddress {
    address: IpAddr,
    prefix: u8,
}

impl LinkAddress {
    /// An address and the length of its prefix.
    ///
    /// The prefix is clamped to what the family allows rather than refused. It
    /// comes from the operating system's own interface table, so a value past
    /// the end is a platform reporting something impossible, and the address is
    /// still true and still worth having.
    pub fn new(address: IpAddr, prefix: u8) -> Self {
        let ceiling = if address.is_ipv4() { 32 } else { 128 };
        Self {
            address,
            prefix: prefix.min(ceiling),
        }
    }

    /// The address itself.
    pub fn address(&self) -> IpAddr {
        self.address
    }

    /// How many leading bits name the network.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Every address this prefix covers, network and broadcast included.
    ///
    /// Whether either end is usable is a question for whoever is sweeping; this
    /// says what the link carries, which is the wider answer and the one an
    /// on-link test needs.
    pub fn network(&self) -> IpRange {
        // `new` clamped the prefix to its family, which is the only way this
        // fails. The expect is a statement that the constructor holds.
        cidr_range(self.address, self.prefix).expect("a prefix clamped to its family")
    }

    /// Whether `ip` is on the same network as this address.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.network().contains(ip)
    }
}

/// What kind of thing a link is.
///
/// Narrower than the source's own two dozen variants, because this engine asks
/// only three questions of it: can it carry a link-layer probe, is it wireless,
/// which is a pacing question rather than a capability one, and is it the
/// machine talking to itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LinkKind {
    /// Something a frame can be put on the wire of: Ethernet at any speed, and
    /// the wired families that look like it from here.
    Wired,
    /// 802.11. Told apart from [`Wired`](Self::Wired) because a wireless link
    /// answers slower and less predictably, not because it is less capable.
    Wireless,
    /// The machine talking to itself.
    Loopback,
    /// A tunnel, a virtual adapter, or anything else with no physical port
    /// behind it. Capable of carrying IP and not of carrying a neighbour.
    Virtual,
}

/// A network interface on this machine.
///
/// Built from the host's interface table by [`from_netdev`](Self::from_netdev),
/// or by hand in a test. Every predicate below is a fact this crate acts on;
/// see the module note for why none of them is delegated to the library that
/// read the table.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Link {
    name: String,
    index: u32,
    mac: Option<MacAddr>,
    addresses: Vec<LinkAddress>,
    kind: LinkKind,
    up: bool,
    addressing: Addressing,
    physical: bool,
    default_route: bool,
}

impl Link {
    /// A link with nothing on it but a name and a number.
    ///
    /// The starting point for a test, and for a caller describing a link this
    /// machine cannot be asked about. Everything else is added through the
    /// builders below, so a `Link` that says an interface is up is one somebody
    /// wrote that down about.
    pub fn new(name: impl Into<String>, index: u32) -> Self {
        Self {
            name: name.into(),
            index,
            mac: None,
            addresses: Vec::new(),
            kind: LinkKind::Virtual,
            up: false,
            addressing: Addressing::Neither,
            physical: false,
            default_route: false,
        }
    }

    /// The hardware address this link answers at.
    #[must_use]
    pub fn with_mac(mut self, mac: MacAddr) -> Self {
        self.mac = Some(mac);
        self
    }

    /// The addresses it holds.
    #[must_use]
    pub fn with_addresses(mut self, addresses: Vec<LinkAddress>) -> Self {
        self.addresses = addresses;
        self
    }

    /// What kind of link it is.
    #[must_use]
    pub fn with_kind(mut self, kind: LinkKind) -> Self {
        self.kind = kind;
        self
    }

    /// Whether the operating system reports it as up.
    #[must_use]
    pub fn with_link_up(mut self, up: bool) -> Self {
        self.up = up;
        self
    }

    /// How addresses on this link reach anything.
    #[must_use]
    pub fn with_addressing(mut self, addressing: Addressing) -> Self {
        self.addressing = addressing;
        self
    }

    /// Whether there is real hardware behind it.
    #[must_use]
    pub fn with_physical(mut self, physical: bool) -> Self {
        self.physical = physical;
        self
    }

    /// Whether this machine's default route leaves by it.
    #[must_use]
    pub fn with_default_route(mut self, carries: bool) -> Self {
        self.default_route = carries;
        self
    }

    /// What the interface is called here.
    ///
    /// Whatever this platform calls it, which is not always what a person
    /// would: on Windows it is the adapter's GUID rather than the name in the
    /// control panel. It is the name every other call in this crate is keyed
    /// by, so it is the one worth carrying.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Its number in this kernel's interface table.
    ///
    /// True of this boot and no other, which is why nothing durable is keyed by
    /// it. see [`Zone`].
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The hardware address, where it has one.
    ///
    /// `None` for a link with no link layer to have one on: a tunnel, and
    /// loopback on most platforms.
    pub fn mac(&self) -> Option<MacAddr> {
        self.mac
    }

    /// Every address this link holds.
    pub fn addresses(&self) -> &[LinkAddress] {
        &self.addresses
    }

    /// The IPv4 addresses among them.
    pub fn ipv4(&self) -> impl Iterator<Item = (Ipv4Addr, u8)> + '_ {
        self.addresses.iter().filter_map(|held| match held.address {
            IpAddr::V4(v4) => Some((v4, held.prefix)),
            IpAddr::V6(_) => None,
        })
    }

    /// The IPv6 addresses among them.
    pub fn ipv6(&self) -> impl Iterator<Item = (Ipv6Addr, u8)> + '_ {
        self.addresses.iter().filter_map(|held| match held.address {
            IpAddr::V6(v6) => Some((v6, held.prefix)),
            IpAddr::V4(_) => None,
        })
    }

    /// This link as a zone, for scoping a link-local address to it.
    pub fn zone(&self) -> Zone {
        Zone::new(self.index, self.name.clone())
    }

    /// What kind of link it is.
    pub fn kind(&self) -> LinkKind {
        self.kind
    }

    /// Whether the operating system reports it as up.
    pub fn is_up(&self) -> bool {
        self.up
    }

    /// Whether this is the machine talking to itself.
    pub fn is_loopback(&self) -> bool {
        self.kind == LinkKind::Loopback
    }

    /// Whether it is 802.11.
    pub fn is_wireless(&self) -> bool {
        self.kind == LinkKind::Wireless
    }

    /// Whether there is a physical port behind it.
    ///
    /// False for a tunnel, a hypervisor's virtual switch, and a VPN: each of
    /// which carries IP perfectly well and none of which has a neighbour to ARP
    /// for.
    pub fn is_physical(&self) -> bool {
        self.physical
    }

    /// Whether it can carry a broadcast.
    pub fn is_broadcast(&self) -> bool {
        self.addressing == Addressing::Broadcast
    }

    /// Whether it is a point-to-point link, which has one peer and no segment.
    pub fn is_point_to_point(&self) -> bool {
        self.addressing == Addressing::PointToPoint
    }

    /// Whether this machine's default route leaves by this link.
    ///
    /// The closest thing there is to "which network am I on". It is a fact
    /// about the routing table rather than a guess about the hardware, which is
    /// what makes it answerable the same way on every platform, and what makes
    /// it right where hardware guesses are wrong. macOS presents `awdl0`
    /// (AirDrop) and `llw0` as ordinary broadcast Ethernet with real hardware
    /// behind them, indistinguishable from a wired port by any other field;
    /// neither carries a route anywhere.
    pub fn carries_default_route(&self) -> bool {
        self.default_route
    }

    /// Whether it is a physical link that is not wireless.
    ///
    /// The one to prefer when there is a choice: a wired segment answers faster
    /// and more consistently than the same segment reached over 802.11, and a
    /// virtual adapter is not a segment at all.
    pub fn is_wired(&self) -> bool {
        self.kind == LinkKind::Wired
    }

    /// Whether a link-layer probe can be put on it.
    ///
    /// The question ARP and neighbour discovery both need answered: there has to
    /// be a segment with somebody else on it, and a hardware address to send
    /// from. A point-to-point link has a peer rather than a segment, loopback
    /// has neither, and a link with no hardware address has nothing to put in
    /// the frame.
    pub fn carries_frames(&self) -> bool {
        !self.is_point_to_point() && !self.is_loopback() && self.mac.is_some()
    }
}

/// How addresses on a link reach anything, which decides what a scan may send
/// out of it.
///
/// One value rather than the two flags this used to be. A link is one of these
/// three and the flags were never independent, so a signature that let a caller
/// say both could describe a link no operating system reports.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Addressing {
    /// A shared segment: one frame sent to the broadcast address reaches every
    /// host on the link, which is what a sweep of a local network needs.
    Broadcast,

    /// Exactly one peer at the far end, and no broadcast address to reach it
    /// by. A tunnel or a dial-up link. Sweeping it means probing one host.
    PointToPoint,

    /// Neither. Loopback carries nothing to another machine at all, and some
    /// virtual interfaces present the same way.
    Neither,
}

impl Addressing {
    /// What a platform's two flags amount to.
    ///
    /// A link reporting both is read as point-to-point. No operating system
    /// sets `IFF_BROADCAST` and `IFF_POINTOPOINT` together, so this is a rule
    /// about a case that should not arise; it picks the direction that refuses
    /// rather than the one that sweeps, because broadcasting onto something
    /// that is not a broadcast domain is the more expensive mistake.
    pub(crate) fn of(broadcast: bool, point_to_point: bool) -> Self {
        match (broadcast, point_to_point) {
            (_, true) => Self::PointToPoint,
            (true, false) => Self::Broadcast,
            (false, false) => Self::Neither,
        }
    }
}

/// Every interface this machine has.
///
/// The one place the host is asked. Everything else in this crate takes
/// [`Link`]s from a caller or from here, which is what makes a scan against a
/// stated set of links and a scan against the real machine the same code path,
/// and what stops a second enumeration appearing with a second library's
/// opinion of what is up.
pub fn interfaces() -> Vec<Link> {
    netdev::get_interfaces()
        .into_iter()
        .map(Link::from_netdev)
        .collect()
}

impl Link {
    /// Reads one interface out of the host's table.
    ///
    /// This is the whole of the crate's dependency on how that table is read.
    /// Every fact below is copied out rather than borrowed, so the
    /// source has no reach past this function.
    ///
    /// Windows is the reason it says `oper_state` rather than a flags word.
    /// Flags are a Unix idea, and a library reporting them on Windows is either
    /// translating or, as the last one did, filling in a zero. The operational
    /// state is what Windows actually publishes, through `GetAdaptersAddresses`,
    /// and what Linux and the BSDs can be asked for as readily.
    pub fn from_netdev(interface: netdev::Interface) -> Self {
        use netdev::interface::types::InterfaceType;

        let kind = if interface.is_loopback() {
            LinkKind::Loopback
        } else if interface.if_type == InterfaceType::Wireless80211 {
            LinkKind::Wireless
        } else if interface.is_physical() {
            LinkKind::Wired
        } else {
            LinkKind::Virtual
        };

        let addresses = interface
            .ipv4
            .iter()
            .map(|net| LinkAddress::new(IpAddr::V4(net.addr()), net.prefix_len()))
            .chain(
                interface
                    .ipv6
                    .iter()
                    .map(|net| LinkAddress::new(IpAddr::V6(net.addr()), net.prefix_len())),
            )
            .collect();

        Self {
            mac: interface.mac_addr.map(|mac| MacAddr::from(mac.octets())),
            addresses,
            kind,
            // Both, because they are not the same claim: a cable can be plugged
            // in to an interface nobody has brought up, and an interface can be
            // administratively up with nothing on the other end. A scan wants
            // the conjunction: there is no point probing out of either.
            up: interface.is_up() && interface.is_oper_up(),
            addressing: Addressing::of(interface.is_broadcast(), interface.is_point_to_point()),
            physical: interface.is_physical(),
            default_route: interface.default,
            name: interface.name,
            index: interface.index,
        }
    }
}

/// Whether a link-layer probe can be put on this link.
///
/// The free-function face of [`Link::carries_frames`], kept because it reads as
/// a question about the link rather than about the type. Both are the same
/// answer and neither is the older one.
pub fn is_layer_2_capable(link: &Link) -> bool {
    link.carries_frames()
}

/// Whether every target in `ips` is on the same segment as `link`.
///
/// Every range, wholly, in both families. A range straddling the edge of
/// the link's network is not on-link: half of it is reachable by ARP and half
/// needs a router, and treating the whole as local would have a sweep wait out
/// a timeout for every address past the boundary.
///
/// It read only the IPv4 ranges until September 2026, which made an IPv6-only
/// target set vacuously on-link for every link, including one holding no IPv6
/// address at all. Nothing called it, so nothing was wrong in a scan; what was
/// wrong was that the answer did not mean what the name said.
///
/// An empty set is on-link, which is the ordinary reading of "every": there is
/// no target here that needs a router.
pub fn is_on_link(link: &Link, ips: &IpSet) -> bool {
    let within = |start: IpAddr, end: IpAddr| {
        link.addresses()
            .iter()
            .any(|held| held.contains(&start) && held.contains(&end))
    };

    ips.v4()
        .iter()
        .all(|range| within(range.start_addr().into(), range.end_addr().into()))
        && ips
            .v6()
            .iter()
            .all(|range| within(range.start_addr().into(), range.end_addr().into()))
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
    use crate::model::ip::range::IpRange;

    fn link(name: &str, kind: LinkKind) -> Link {
        Link::new(name, 1)
            .with_kind(kind)
            .with_mac(MacAddr::new(1, 2, 3, 4, 5, 6))
    }
    fn holding(name: &str, address: &str, prefix: u8) -> Link {
        link(name, LinkKind::Wired).with_addresses(vec![LinkAddress::new(
            address.parse::<IpAddr>().expect("an address"),
            prefix,
        )])
    }
    fn targets(written: &str) -> IpSet {
        let mut set = IpSet::new();
        set.insert_range(written.parse::<IpRange>().expect("a range"));
        set
    }
    /// A range wholly inside the link's network is on it; one that leaves is
    /// not, and half of one is not either.
    ///
    /// The last is the case worth the test. A range straddling the boundary is
    /// half reachable by ARP and half not, and calling it on-link makes the
    /// sweep wait out a timeout for every address past the edge.
    #[test]
    fn a_range_is_on_link_only_if_all_of_it_is() {
        let link = holding("en0", "10.0.0.7", 24);

        assert!(is_on_link(&link, &targets("10.0.0.1-10.0.0.50")));
        assert!(is_on_link(&link, &targets("10.0.0.0/24")), "the whole");
        assert!(!is_on_link(&link, &targets("10.0.1.1-10.0.1.5")), "past");
        assert!(
            !is_on_link(&link, &targets("10.0.0.200-10.0.1.10")),
            "a range that starts on the link and leaves it is not on the link"
        );
    }
    /// A link with no address of its own puts nothing on it.
    #[test]
    fn a_link_with_no_addressing_has_nothing_on_it() {
        let bare = link("en0", LinkKind::Wired);

        assert!(!is_on_link(&bare, &targets("10.0.0.1-10.0.0.50")));
    }
    /// An IPv6 address on the link does not make an IPv4 range local.
    ///
    /// `is_on_link` answers for IPv4 only, the callers that ask it are the ARP
    /// path, and a link holding a v6 prefix that happens to contain the same
    /// bits must not be read as covering a v4 range.
    #[test]
    fn an_ipv6_prefix_does_not_answer_for_an_ipv4_range() {
        let v6_only = link("en0", LinkKind::Wired).with_addresses(vec![LinkAddress::new(
            "fe80::1".parse::<IpAddr>().expect("an address"),
            64,
        )]);

        assert!(!is_on_link(&v6_only, &targets("10.0.0.1-10.0.0.50")));
    }
    use super::*;

    fn v4(address: &str, prefix: u8) -> LinkAddress {
        LinkAddress::new(IpAddr::V4(address.parse().expect("an address")), prefix)
    }

    /// The network is derived from the prefix, and covers both ends.
    ///
    /// Both ends because the question this answers is what the *link* carries,
    /// not what is worth probing. Whether a sweep spends a probe on the network
    /// or broadcast address is a decision made later and by somebody else; an
    /// on-link test that excluded them would report a host at `10.0.0.255` as
    /// being somewhere else entirely.
    #[test]
    fn a_network_covers_every_address_its_prefix_names() {
        let held = v4("10.0.0.7", 24);
        let network = held.network();

        assert_eq!(network.start_addr(), "10.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(network.end_addr(), "10.0.0.255".parse::<IpAddr>().unwrap());
        assert!(held.contains(&"10.0.0.0".parse().unwrap()), "the network");
        assert!(
            held.contains(&"10.0.0.255".parse().unwrap()),
            "the broadcast"
        );
        assert!(!held.contains(&"10.0.1.1".parse().unwrap()), "the next one");
    }

    /// A `/32` is one address, and a `/0` is all of them. Both are real: a
    /// point-to-point link routinely holds the first.
    #[test]
    fn the_ends_of_the_prefix_range_are_both_networks() {
        let single = v4("192.0.2.1", 32);
        assert_eq!(single.network().len(), 1);
        assert!(single.contains(&"192.0.2.1".parse().unwrap()));

        let everything = v4("192.0.2.1", 0);
        assert!(everything.contains(&"8.8.8.8".parse().unwrap()));
    }

    /// A prefix past the end of its family is clamped rather than refused.
    ///
    /// It comes from the operating system's own table, so a `/40` on an IPv4
    /// address is a platform reporting something impossible, and the address is
    /// still true. Refusing would lose a real address over a field nothing else
    /// depends on; clamping keeps it and makes `network` total, which is what
    /// lets it return a value rather than a `Result` nobody could act on.
    #[test]
    fn a_prefix_past_its_family_is_clamped_and_the_address_survives() {
        let absurd = v4("10.0.0.7", 200);

        assert_eq!(absurd.prefix(), 32, "clamped to what IPv4 has");
        assert_eq!(absurd.address(), "10.0.0.7".parse::<IpAddr>().unwrap());
        assert_eq!(absurd.network().len(), 1);

        let v6 = LinkAddress::new(IpAddr::V6("fe80::1".parse().unwrap()), 255);
        assert_eq!(v6.prefix(), 128, "and to what IPv6 has");
    }

    /// The three things a link-layer probe needs, and each one's absence.
    ///
    /// ARP and neighbour discovery both want a segment with somebody else on it
    /// and a hardware address to send from. A point-to-point link has a peer
    /// rather than a segment, loopback has neither, and a link with no hardware
    /// address has nothing to put in the frame.
    #[test]
    fn a_link_carries_frames_only_with_a_segment_and_an_address_to_send_from() {
        let mac = MacAddr::new(2, 0, 0, 0, 0, 1);
        let wired = Link::new("en0", 1).with_kind(LinkKind::Wired).with_mac(mac);
        assert!(wired.carries_frames());

        assert!(
            !Link::new("en0", 1)
                .with_kind(LinkKind::Wired)
                .carries_frames(),
            "no hardware address to send from"
        );
        assert!(
            !Link::new("lo0", 1)
                .with_kind(LinkKind::Loopback)
                .with_mac(mac)
                .carries_frames(),
            "nobody else on it"
        );
        assert!(
            !Link::new("utun0", 1)
                .with_kind(LinkKind::Wired)
                .with_mac(mac)
                .with_addressing(Addressing::PointToPoint)
                .carries_frames(),
            "a peer rather than a segment"
        );
    }

    /// The families are kept apart, because almost everything that reads them
    /// wants one or the other.
    #[test]
    fn a_links_addresses_are_readable_by_family() {
        let link = Link::new("en0", 1).with_addresses(vec![
            v4("10.0.0.7", 24),
            LinkAddress::new(IpAddr::V6("fe80::1".parse().unwrap()), 64),
            v4("192.168.1.5", 25),
        ]);

        let v4s: Vec<_> = link.ipv4().collect();
        assert_eq!(v4s.len(), 2);
        assert_eq!(v4s[0], ("10.0.0.7".parse().unwrap(), 24));
        assert_eq!(v4s[1], ("192.168.1.5".parse().unwrap(), 25));

        let v6s: Vec<_> = link.ipv6().collect();
        assert_eq!(v6s.len(), 1);
        assert_eq!(v6s[0], ("fe80::1".parse().unwrap(), 64));
    }

    /// A link names its own zone, which is what a link-local address needs to
    /// mean anything.
    #[test]
    fn a_link_is_its_own_zone() {
        let zone = Link::new("en0", 7).zone();

        assert_eq!(zone.name(), "en0");
        assert_eq!(zone.index(), Some(7));
    }

    /// Whatever the host says, read through the one function that reads it.
    ///
    /// Not an assertion about this machine, a container has one interface and a
    /// laptop has twenty, but about the mapping holding for every one of them.
    /// A `Link` whose kind is `Loopback` must not also claim to carry frames,
    /// and an address must not survive the trip with a prefix its family cannot
    /// hold. Both are properties of `from_netdev`, and this is the only place
    /// that runs it.
    #[test]
    fn every_interface_this_machine_has_reads_back_consistently() {
        for link in interfaces() {
            assert!(!link.name().is_empty(), "an interface with no name");

            if link.is_loopback() {
                assert!(
                    !link.carries_frames(),
                    "{} is loopback and claims a segment",
                    link.name()
                );
            }

            for held in link.addresses() {
                let ceiling = if held.address().is_ipv4() { 32 } else { 128 };
                assert!(
                    held.prefix() <= ceiling,
                    "{} holds {} with a /{} its family cannot express",
                    link.name(),
                    held.address(),
                    held.prefix()
                );
                assert!(
                    held.contains(&held.address()),
                    "{} holds {} on a network that excludes it",
                    link.name(),
                    held.address()
                );
            }
        }
    }
}
