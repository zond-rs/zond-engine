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
//! This level holds the classification the three share: whether an address is globally
//! scoped, meaning it names its host from anywhere and not only on one segment. That is
//! about scope, not reachability: a globally routed address may be firewalled, and a
//! private one may be the only way to reach a host.
//!
//! [`Exposure`] asks a third question, the one a weakness is judged against: **who
//! else could have sent the packet this scan sent**.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub mod range;
pub mod scoped;
pub mod set;

pub use range::{IpError, IpRange, Ipv4Range, Ipv6Range};
pub use scoped::{ScopedIp, ScopedIpError, Zone, ZoneMap};
pub use set::{IpSet, IpSetError, Positions};

/// Who, besides this scan, can reach the address a subject was reached at.
///
/// A finding's [`Severity`] assumes an attacker somewhere:
/// [`Critical`](crate::model::finding::Severity::Critical) means needing nothing the
/// internet does not already have. Without a way to ask who can reach the subject, a
/// detection author must assume the widest audience, which is wrong for a household
/// router on a private address. A [`SeveritySpec`](crate::detect::authoring::SeveritySpec)
/// states a severity per rung of this instead.
///
/// ## Derived from the address alone
///
/// [`of`](Self::of) reads only the address, so:
///
/// - **The answer is the same everywhere**: a live scan, a report read back, and a
///   [`merge`](crate::merge) all hold addresses, and nothing else about the path
///   survives into a document.
/// - **It needs no plumbing** from discovery to detection.
/// - **It errs on the safe side**; see below.
///
/// It says nothing about firewalls: an [`Internet`](Self::Internet) address may drop
/// everything. The claim is about routing: whether a stranger has the path this scan
/// took.
///
/// It differs from [`is_globally_scoped`]: a unique-local address names a host across
/// an organization, so it is globally scoped, but the internet does not route it, so
/// its exposure is [`Internal`](Self::Internal).
///
/// ## Lowering a severity takes proof
///
/// [`Internet`](Self::Internet) is the fallback for any address not shown to be
/// narrower, so a severity is reduced only where the address is *demonstrably*
/// unroutable, and an unrecognised address keeps the detection's full rating.
///
/// Ordered narrowest reach first, so a comparison reads "at least this exposed" and a
/// [`SeveritySpec`](crate::detect::authoring::SeveritySpec) can fall back along it.
/// [`ALL`](Self::ALL) is the list to iterate.
///
/// [`Severity`]: crate::model::finding::Severity
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Exposure {
    /// The machine the scan runs on, and nothing else. A loopback address.
    ///
    /// Its own rung because loopback is where a service is *supposed* to be unguarded:
    /// most databases ship listening on `127.0.0.1` with no password.
    Local,
    /// Somebody already inside this network: a private, link-local, carrier-NAT
    /// or unique-local address, none of which the internet routes.
    ///
    /// Not "safe": this is reached by lateral movement, which is how most networks are
    /// compromised, so detections handing over a foothold or credential stay high here.
    Internal,
    /// Anybody the internet routes to this address.
    ///
    /// What a severity written without this question assumes, and the fallback.
    Internet,
}

impl Exposure {
    /// The exposure of `addr`.
    ///
    /// [`Internet`](Self::Internet) unless the address is shown to be narrower.
    ///
    /// An IPv4-mapped IPv6 address is read as the IPv4 address it carries, so
    /// `::ffff:192.168.1.1` is [`Internal`](Self::Internal).
    pub fn of(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => Self::of_v4(addr),
            // A v4-mapped address is classified as v4.
            IpAddr::V6(addr) => match addr.to_ipv4_mapped() {
                Some(mapped) => Self::of_v4(mapped),
                None => Self::of_v6(&addr),
            },
        }
    }

    /// The IPv4 half of [`of`](Self::of).
    ///
    /// `is_private` covers RFC 1918 (`10/8`, `172.16/12`, `192.168/16`) and
    /// `is_link_local` covers RFC 3927 (`169.254/16`). The other two are hand-rolled
    /// because std's predicates for them are unstable.
    ///
    /// `100.64/10` is RFC 6598 carrier-grade NAT space, often a household router's WAN
    /// address; the internet does not route it.
    ///
    /// `0.0.0.0/8` is "this network" (RFC 1122), which no stranger has a path to.
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
    /// `fe80::/10` is link-local, reachable only from its own segment. `fc00::/7` is
    /// unique-local, routed by an organization but not the internet ([`is_unique_local`]
    /// reads it for [`is_globally_scoped`], which answers the opposite for it).
    ///
    /// `::`, the unspecified address, is [`Internal`](Self::Internal), matching how
    /// [`of_v4`](Self::of_v4) reads `0.0.0.0/8`.
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
    /// One spelling for both, so a report and a detection file agree.
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
/// A membership test, not a routability claim. `2000::/3` is where global unicast is
/// allocated today, and it contains special-purpose prefixes this does not exclude:
///
/// - `2001:db8::/32`, documentation
/// - `2001::/32`, Teredo, which does turn up on consumer segments
/// - `2002::/16`, 6to4
/// - `2001:2::/48`, benchmarking, and `2001:20::/28`, ORCHIDv2
///
/// Callers ask whether an address is globally scoped, and a Teredo or 6to4 address is:
/// unusual, but not local. Excluding them would report a host under a link-local
/// address instead.
///
/// Hand-rolled because `Ipv6Addr::is_unicast_global` is unstable.
pub fn is_global_unicast(ipv6_addr: &Ipv6Addr) -> bool {
    let first_byte = ipv6_addr.octets()[0];
    (0x20..=0x3F).contains(&first_byte)
}

/// Whether `ipv6_addr` names its host from off the segment it is on.
///
/// Global unicast or unique-local: either names a host beyond one segment, which is
/// what matters for choosing the address that identifies it. A link-local is neither.
/// Used by [`Host::consider_primary_ip`](crate::model::host::Host::consider_primary_ip).
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
    /// Boundaries catch off-by-ones in the hand-rolled prefix tests: `100.64/10` ends
    /// at `100.127.255.255`, and `100.128.0.0` is public.
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
            // IPv6 link-local across fe80::/10, unique-local across fc00::/7, and
            // the unspecified address.
            ("fe80::1", Exposure::Internal),
            ("febf:ffff::1", Exposure::Internal),
            ("fc00::1", Exposure::Internal),
            ("fdff:ffff::1", Exposure::Internal),
            ("::", Exposure::Internal),
            // A v4-mapped private address is the private address it carries.
            ("::ffff:192.168.1.1", Exposure::Internal),
            // Public space, including addresses one step outside a narrower prefix.
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

    /// The documentation prefixes used by every test and example are public space, so
    /// corpus tests see a detection's full stated severity.
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

    /// A unique-local address is globally scoped but internal.
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

    /// Every rung is listed once, narrowest reach first.
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

    /// The boundaries of `2000::/3`, and the special-purpose prefixes inside it.
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
