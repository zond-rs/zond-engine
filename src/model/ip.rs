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
//! the interface it is valid on — the distinction without which an IPv6
//! link-local address cannot be connected to at all.
//!
//! What is left at this level are the classification questions that more than
//! one of those three has to agree about: **how widely does this address
//! reach**, which is what decides whether it names its host from anywhere or
//! only from one segment.
//!
//! Everything here is a question about an address's *scope*, deliberately, and
//! none of it is a question about reachability. An address in a globally routed
//! prefix may be firewalled to nothing; an address in a private one may be the
//! only way to reach a host. Confusing the two is how a scanner ends up
//! reporting a host under an address nobody can open a socket to, which is the
//! failure [`scoped`] exists to prevent.

use std::net::{IpAddr, Ipv6Addr};

pub mod range;
pub mod scoped;
pub mod set;

/// How widely an IPv6 address reaches, which is what decides where it is
/// meaningful to hand one on to.
#[derive(Debug, Default)]
pub enum Ipv6AddressType {
    /// Allocated for global unicast. Names its host from anywhere, and needs
    /// nothing alongside it to be usable. See [`is_global_unicast`] for what
    /// this does and does not claim.
    GlobalUnicast,
    /// `fc00::/7`, the IPv6 counterpart of an RFC 1918 address: routable within
    /// an organization and nowhere beyond it.
    UniqueLocal,
    /// `fe80::/10`. Names a *different machine on every segment*, so it is
    /// meaningless without the interface it was seen on — see
    /// [`ScopedIp`](scoped::ScopedIp).
    LinkLocal,
    /// `::1`, which reaches only the host asking.
    Loopback,
    /// Anything else: the unspecified address, multicast, and the ranges the
    /// address architecture has not handed out. The default because it is the
    /// answer that assumes least.
    #[default]
    Unspecified,
}

/// Classifies `ipv6_addr` by how widely it reaches.
///
/// The order of the tests is the order of decreasing reach, so an address that
/// satisfies more than one predicate is reported under the broadest that fits.
pub fn get_ipv6_type(ipv6_addr: &Ipv6Addr) -> Ipv6AddressType {
    if is_global_unicast(ipv6_addr) {
        Ipv6AddressType::GlobalUnicast
    } else if ipv6_addr.is_unique_local() {
        Ipv6AddressType::UniqueLocal
    } else if ipv6_addr.is_unicast_link_local() {
        Ipv6AddressType::LinkLocal
    } else if ipv6_addr.is_loopback() {
        Ipv6AddressType::Loopback
    } else {
        Ipv6AddressType::Unspecified
    }
}

/// Whether `ipv6_addr` falls in `2000::/3`, the range IANA currently allocates
/// global unicast from.
///
/// **A membership test, not a routability claim**, and the difference is worth
/// stating because the name invites the stronger reading. `2000::/3` is where
/// global unicast is being handed out today; it is not the whole of what the
/// address architecture reserves for it, and it contains several
/// special-purpose prefixes this deliberately does not exclude:
///
/// - `2001:db8::/32`, documentation
/// - `2001::/32`, Teredo, which does turn up on consumer segments
/// - `2002::/16`, 6to4
/// - `2001:2::/48`, benchmarking, and `2001:20::/28`, ORCHIDv2
///
/// Excluding them would be wrong for what this is asked. Every caller wants to
/// know whether an address is *globally scoped* — whether it names the host
/// from off the segment, as against a link-local that names a different machine
/// on every one. A Teredo or 6to4 address is globally scoped; it is unusual,
/// not local. Filtering them here would report a host under a link-local
/// address it cannot be reached at, to avoid an address it can.
///
/// Hand-rolled because `Ipv6Addr::is_unicast_global` is unstable in std, and
/// has been for years.
pub fn is_global_unicast(ipv6_addr: &Ipv6Addr) -> bool {
    let first_byte = ipv6_addr.octets()[0];
    (0x20..=0x3F).contains(&first_byte)
}

/// Whether `ip_addr` is one an organization assigns itself rather than one
/// allocated to it.
///
/// RFC 1918 for IPv4; for IPv6, unique-local *and* link-local, since both are
/// addresses whose meaning stops at a boundary the host controls. It says
/// nothing about whether the address can be reached — a private address is
/// usually the one that can.
pub fn is_private(ip_addr: &IpAddr) -> bool {
    match ip_addr {
        IpAddr::V4(ipv4) => ipv4.is_private(),
        IpAddr::V6(ipv6) => ipv6.is_unicast_link_local() || ipv6.is_unique_local(),
    }
}
