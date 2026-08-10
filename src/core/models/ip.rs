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
