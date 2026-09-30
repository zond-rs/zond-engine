// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Addresses, and the shapes they come in
//!
//! The address half of the vocabulary. [`range`] holds contiguous corridors of
//! addresses, [`set`] holds collections of those corridors with the arithmetic
//! a scan needs over them, and [`scoped`] holds a single address together with
//! the interface it is valid on, without which an IPv6 link-local address
//! cannot be connected to at all.
//!
//! What is left at this level is the one classification question more than one of
//! those three has to agree about: whether an address is globally scoped, which
//! decides whether it names its host from anywhere or only from one segment.
//!
//! That is a question about scope rather than about reachability. An address in a
//! globally routed prefix may be firewalled to nothing, and an address in a
//! private one may be the only way to reach a host. Confusing the two is how a
//! scanner reports a host under an address nobody can open a socket to, which is
//! the failure [`scoped`] exists to prevent.
//!
//! [`Exposure`] is the third question in that family, and the one a weakness is
//! judged against: not whether an address names its host from anywhere, and not
//! whether a packet to it arrives, but **who else could have sent the packet this
//! scan sent**.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub mod range;
pub mod scoped;
pub mod set;

pub use range::{IpError, IpRange, Ipv4Range, Ipv6Range};
pub use scoped::{ScopedIp, ScopedIpError, Zone, ZoneMap};
pub use set::{IpSet, IpSetError, Positions};

/// Who, besides this scan, can reach the address a subject was reached at.
///
/// The missing half of a severity. A finding's [`Severity`] answers "how bad is
/// this if true", and every wording of that question is relative to an attacker
/// who has to be *somewhere*:
/// [`Critical`](crate::model::finding::Severity::Critical) is defined as needing
/// nothing the internet does not already have. A detection author writing a
/// severity therefore has an audience in mind, and with no way to ask who can
/// reach the subject, the only audience they can assume is the widest one. That
/// assumption is right for a server on a public address and wrong for the
/// household router four hops of nothing away, where it rates the network's own
/// configuration as an attack on it.
///
/// So this is what a detection asks instead, and a
/// [`SeveritySpec`](crate::detect::authoring::SeveritySpec) is how it states a
/// severity per rung.
///
/// ## A fact about the address, and only about the address
///
/// Derived by [`of`](Self::of) from the address alone, which is a deliberate
/// limit rather than an unfinished job. Three properties come out of it:
///
/// - **It is the same answer everywhere.** A live scan, a report read back from
///   a file, and a [`merge`](crate::merge) of two of them all hold addresses, and
///   nothing else about the path survives into a document. An exposure drawn from
///   the routing table would be a rating that changed when a report was reopened
///   on another machine.
/// - **It needs no plumbing.** Nothing has to be threaded from the discovery
///   phase to the detection phase for a detection to ask.
/// - **It cannot be wrong in the expensive direction.** See below.
///
/// What it is *not* is a claim about firewalls. An address this calls
/// [`Internet`](Self::Internet) may drop every packet from everywhere, and the
/// scan that reached it may have come from the same room. The claim is about
/// routing: whether the address is one the internet carries traffic for, so that
/// the path this scan took is a path available to a stranger. Where that is true
/// the widest audience is the right one to rate against, whatever a firewall in
/// front of it happens to be doing on the day of the scan.
///
/// It is also not [`is_globally_scoped`], which asks whether an address names its
/// host from off the segment. Both read the same octets and they answer different
/// questions: a unique-local address names a host across an organization, so it
/// *is* globally scoped, and the internet does not route to it, so its exposure
/// is [`Internal`](Self::Internal).
///
/// ## Lowering a severity takes proof; raising one does not
///
/// [`Internet`](Self::Internet) is the fallback, reached by every address not
/// shown to be one of the others. That asymmetry is the safety property: a
/// detection's severity is reduced only where the address is *demonstrably*
/// unroutable, so the failure mode of an address family this does not recognise,
/// or of a subject that is not a host at all, is the rating the detection would
/// have carried anyway. A scanner that quietly under-rated a real weakness
/// because it mis-read an address would be worse than one that never asked.
///
/// Ordered narrowest reach first, so a comparison reads as "at least this
/// exposed" and a [`SeveritySpec`](crate::detect::authoring::SeveritySpec) can
/// fall back along it.
///
/// `#[non_exhaustive]` so that splitting a rung later, separating a link this
/// scan is attached to from a private network several hops away, costs a
/// recompile rather than a major version. [`ALL`](Self::ALL) is the list to
/// iterate.
///
/// [`Severity`]: crate::model::finding::Severity
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Exposure {
    /// The machine the scan runs on, and nothing else. A loopback address.
    ///
    /// Worth its own rung because loopback is where a service is *supposed* to
    /// be unguarded: a database listening on `127.0.0.1` with no password is the
    /// shipped configuration of most of them, and the weakness a detection was
    /// written about is the same service bound to a network.
    Local,
    /// Somebody already inside this network: a private, link-local, carrier-NAT
    /// or unique-local address, none of which the internet routes.
    ///
    /// Not "safe". It is the rung a weakness reaches by lateral movement rather
    /// than from the outside, which is how most of a network is actually
    /// compromised, so the detections that stay high here are the ones that hand
    /// an attacker a foothold or a credential.
    Internal,
    /// Anybody the internet routes to this address.
    ///
    /// The rung every severity written without asking the question already
    /// assumes, and the fallback for an address not shown to be one of the
    /// others.
    Internet,
}

impl Exposure {
    /// The exposure of `addr`.
    ///
    /// [`Internet`](Self::Internet) unless the address is shown to be narrower;
    /// see the type's own documentation for why the default sits on that side.
    ///
    /// An IPv4-mapped IPv6 address is read as the IPv4 address it carries.
    /// `::ffff:192.168.1.1` is `192.168.1.1` written another way, and reading it
    /// as an ordinary IPv6 address would land it in the fallback and rate a
    /// household network as the internet.
    pub fn of(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => Self::of_v4(addr),
            // A v4-mapped address is a v4 address, so it is classified as one.
            IpAddr::V6(addr) => match addr.to_ipv4_mapped() {
                Some(mapped) => Self::of_v4(mapped),
                None => Self::of_v6(&addr),
            },
        }
    }

    /// The IPv4 half of [`of`](Self::of).
    ///
    /// `is_private` covers RFC 1918 (`10/8`, `172.16/12`, `192.168/16`) and
    /// `is_link_local` covers RFC 3927 (`169.254/16`). The other two are
    /// hand-rolled for the reason [`is_global_unicast`] is: std has a predicate
    /// for each and both have been unstable for years.
    ///
    /// `100.64/10` is RFC 6598, the space a carrier hands its subscribers behind
    /// its own NAT. The internet does not route it, and it is the address a
    /// household router's WAN side holds on a good many networks, so leaving it
    /// in the fallback would rate an ISP's internal numbering as a public one.
    ///
    /// `0.0.0.0/8` is "this network" from RFC 1122. No host answers at one, and
    /// an address that names the local network cannot be a path a stranger has.
    fn of_v4(addr: Ipv4Addr) -> Self {
        if addr.is_loopback() {
            return Self::Local;
        }
        let carrier_nat = addr.octets()[0] == 100 && (64..=127).contains(&addr.octets()[1]);
        let this_network = addr.octets()[0] == 0;
        if addr.is_private() || addr.is_link_local() || carrier_nat || this_network {
            return Self::Internal;
        }
        Self::Internet
    }

    /// The IPv6 half of [`of`](Self::of).
    ///
    /// `fe80::/10` is link-local, which names a different machine on every
    /// segment and is reachable only from the one it is on. `fc00::/7` is
    /// unique-local, unique across an organization and routed by that
    /// organization rather than by the internet; [`is_unique_local`] already
    /// reads it for [`is_globally_scoped`], which is the neighbouring question
    /// that reaches the opposite answer about the same prefix.
    ///
    /// `::` is the unspecified address, and it is read as
    /// [`Internal`](Self::Internal) because [`of_v4`](Self::of_v4) reads the
    /// `0.0.0.0/8` it belongs to that way. Neither names a host a scan can reach,
    /// and answering the same for both is one fact fewer for a reader to hold.
    fn of_v6(addr: &Ipv6Addr) -> Self {
        if addr.is_loopback() {
            return Self::Local;
        }
        let octets = addr.octets();
        let link_local = octets[0] == 0xfe && octets[1] & 0xc0 == 0x80;
        if link_local || is_unique_local(addr) || addr.is_unspecified() {
            return Self::Internal;
        }
        Self::Internet
    }

    /// How an exposure is written for a person to read, and the name a detection
    /// spells it with.
    ///
    /// One spelling for both, by the rule
    /// [`NetworkRole::label`](crate::model::host::NetworkRole::label) follows: a
    /// report and a detection file cannot drift apart over a word neither of them
    /// keeps a table for.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Internal => "internal",
            Self::Internet => "internet",
        }
    }

    /// Every exposure, narrowest reach first.
    pub const ALL: &'static [Self] = &[Self::Local, Self::Internal, Self::Internet];
}

/// Whether `ipv6_addr` falls in `2000::/3`, the range IANA currently allocates
/// global unicast from.
///
/// A membership test rather than a routability claim, which the name invites.
/// `2000::/3` is where global unicast is being handed out today. It is not the
/// whole of what the address architecture reserves for it, and it contains
/// several special-purpose prefixes this does not exclude:
///
/// - `2001:db8::/32`, documentation
/// - `2001::/32`, Teredo, which does turn up on consumer segments
/// - `2002::/16`, 6to4
/// - `2001:2::/48`, benchmarking, and `2001:20::/28`, ORCHIDv2
///
/// Excluding them would be wrong for what this is asked. Every caller wants to
/// know whether an address is globally scoped, meaning it names the host from off
/// the segment rather than naming a different machine on every one, as a
/// link-local does. A Teredo or 6to4 address is globally scoped: unusual, and not
/// local. Filtering them here would report a host under a link-local address it
/// cannot be reached at, to avoid one it can.
///
/// Hand-rolled because `Ipv6Addr::is_unicast_global` is unstable in std, and
/// has been for years.
pub fn is_global_unicast(ipv6_addr: &Ipv6Addr) -> bool {
    let first_byte = ipv6_addr.octets()[0];
    (0x20..=0x3F).contains(&first_byte)
}

/// Whether `ipv6_addr` names its host from off the segment it is on.
///
/// The question this module exists to answer, and the one more than one of
/// [`range`], [`set`] and [`scoped`] has to agree about. Global unicast or
/// unique-local: the first names a host wherever the internet reaches and the
/// second wherever an organization's routing does, and for deciding which address
/// identifies a host those are one answer. A link-local names a different machine
/// on every segment and is neither.
///
/// [`Host::consider_primary_ip`](crate::model::host::Host::consider_primary_ip)
/// reads it rather than carrying the unique-local half itself.
pub fn is_globally_scoped(ipv6_addr: &Ipv6Addr) -> bool {
    is_global_unicast(ipv6_addr) || is_unique_local(ipv6_addr)
}

/// Whether `addr` is in `fc00::/7`, the range reserved for addresses that are
/// unique across an organization but not routed onto the internet.
fn is_unique_local(addr: &Ipv6Addr) -> bool {
    addr.octets()[0] & 0xfe == 0xfc
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

    /// Every rung, at the boundaries of every prefix that reaches it.
    ///
    /// The boundaries rather than a sample from the middle, because an
    /// off-by-one in a hand-rolled prefix test is the defect this can actually
    /// have: `100.64/10` ends at `100.127.255.255` and a `<= 128` would swallow
    /// `100.128.0.0`, which is ordinary public space.
    #[test]
    fn an_address_is_classified_by_what_routes_it() {
        let cases = [
            // Loopback, both families and both ends of the v4 block.
            ("127.0.0.1", Exposure::Local),
            ("127.255.255.255", Exposure::Local),
            ("::1", Exposure::Local),
            // RFC 1918, at both ends of each of the three blocks.
            ("10.0.0.0", Exposure::Internal),
            ("10.255.255.255", Exposure::Internal),
            ("172.16.0.0", Exposure::Internal),
            ("172.31.255.255", Exposure::Internal),
            ("192.168.0.1", Exposure::Internal),
            ("192.168.255.255", Exposure::Internal),
            // RFC 3927 link-local, and RFC 6598 carrier NAT at both ends.
            ("169.254.0.1", Exposure::Internal),
            ("100.64.0.0", Exposure::Internal),
            ("100.127.255.255", Exposure::Internal),
            // RFC 1122 "this network".
            ("0.0.0.0", Exposure::Internal),
            // IPv6 link-local across the whole of fe80::/10, and unique-local
            // across the whole of fc00::/7, and the unspecified address, read the
            // way the 0.0.0.0/8 above it is.
            ("fe80::1", Exposure::Internal),
            ("febf:ffff::1", Exposure::Internal),
            ("fc00::1", Exposure::Internal),
            ("fdff:ffff::1", Exposure::Internal),
            ("::", Exposure::Internal),
            // A v4-mapped private address is the private address it carries.
            ("::ffff:192.168.1.1", Exposure::Internal),
            // Public space, including the addresses that sit one step outside a
            // narrower prefix.
            ("8.8.8.8", Exposure::Internet),
            ("172.32.0.1", Exposure::Internet),
            ("100.128.0.1", Exposure::Internet),
            ("100.63.255.255", Exposure::Internet),
            ("169.255.0.1", Exposure::Internet),
            ("2606:4700::1111", Exposure::Internet),
            ("fec0::1", Exposure::Internet),
            ("::ffff:8.8.8.8", Exposure::Internet),
        ];

        for (text, want) in cases {
            let addr: IpAddr = text.parse().expect("a valid address");
            assert_eq!(Exposure::of(addr), want, "{text}");
        }
    }

    /// The documentation prefixes every test and example in this crate draws its
    /// addresses from are public space, so a detection's stated severity is what
    /// a fixture sees.
    ///
    /// Asserted rather than left to be noticed, because the alternative is a
    /// corpus test that silently checks the reduced rating and reports nothing
    /// about the one a detection was written to give.
    #[test]
    fn the_documentation_prefixes_are_rated_as_the_public_space_they_belong_to() {
        for text in [
            "192.0.2.10",   // TEST-NET-1
            "198.51.100.7", // TEST-NET-2
            "203.0.113.1",  // TEST-NET-3
            "2001:db8::1",  // the IPv6 documentation prefix
        ] {
            let addr: IpAddr = text.parse().expect("a valid address");
            assert_eq!(Exposure::of(addr), Exposure::Internet, "{text}");
        }
    }

    /// An address the internet routes is not the same claim as an address that
    /// names its host from off the segment, and a unique-local address is where
    /// the two part company.
    #[test]
    fn exposure_and_global_scope_are_different_questions_about_the_same_octets() {
        let ula: Ipv6Addr = "fd00::1".parse().expect("a valid address");
        assert!(
            is_globally_scoped(&ula),
            "a unique-local address names its host across an organization"
        );
        assert_eq!(
            Exposure::of(IpAddr::V6(ula)),
            Exposure::Internal,
            "and the internet does not route to it"
        );
    }

    /// Every rung is listed, once each, narrowest reach first, so the ordering a
    /// severity falls back along is the ordering the enum declares.
    #[test]
    fn the_list_of_exposures_holds_every_one_of_them_once_and_in_order() {
        fn place(exposure: Exposure) -> usize {
            match exposure {
                Exposure::Local => 0,
                Exposure::Internal => 1,
                Exposure::Internet => 2,
            }
        }
        let places: Vec<usize> = Exposure::ALL.iter().copied().map(place).collect();
        assert_eq!(places, (0..Exposure::ALL.len()).collect::<Vec<_>>());
        assert!(Exposure::Local < Exposure::Internal);
        assert!(Exposure::Internal < Exposure::Internet);
    }

    /// The boundaries of `2000::/3`, and the special-purpose prefixes inside it
    /// that this does not exclude. Both halves matter: an address
    /// wrongly called local costs a host its usable address, and one wrongly
    /// called global is reported at an address nobody can reach.
    #[test]
    fn the_range_iana_allocates_global_unicast_from_is_what_is_tested() {
        for global in [
            "2000::",          // the first address of the range
            "3fff:ffff::ffff", // and the last
            "2001:db8::1",     // documentation, unusual but globally scoped
            "2001::1",         // Teredo, which does turn up on consumer segments
            "2002::1",         // 6to4
        ] {
            let addr: Ipv6Addr = global.parse().expect("a valid address");
            assert!(is_global_unicast(&addr), "{global}");
        }

        for local in [
            "1fff:ffff::", // just below the range
            "4000::",      // just above it
            "fe80::1",     // link-local: a different machine on every segment
            "fd00::1",     // unique-local
            "::1",         // loopback
            "ff02::1",     // multicast
        ] {
            let addr: Ipv6Addr = local.parse().expect("a valid address");
            assert!(!is_global_unicast(&addr), "{local}");
        }
    }
}
