// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::net::{IpAddr, Ipv6Addr};

pub mod range;
pub mod scoped;
pub mod set;

#[derive(Debug, Default)]
pub enum Ipv6AddressType {
    GlobalUnicast,
    UniqueLocal,
    LinkLocal,
    Loopback,
    #[default]
    Unspecified,
}

pub fn get_ipv6_type(ipv6_addr: &Ipv6Addr) -> Ipv6AddressType {
    match true {
        _ if is_global_unicast(ipv6_addr) => Ipv6AddressType::GlobalUnicast,
        _ if ipv6_addr.is_unique_local() => Ipv6AddressType::UniqueLocal,
        _ if ipv6_addr.is_unicast_link_local() => Ipv6AddressType::LinkLocal,
        _ if ipv6_addr.is_loopback() => Ipv6AddressType::Loopback,
        _ => Ipv6AddressType::Unspecified,
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

pub fn is_private(ip_addr: &IpAddr) -> bool {
    match ip_addr {
        IpAddr::V4(ipv4) => ipv4.is_private(),
        IpAddr::V6(ipv6) => ipv6.is_unicast_link_local() || ipv6.is_unique_local(),
    }
}
