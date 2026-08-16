// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{info, warn};
use std::net::Ipv4Addr;

use crate::model::{
    ip::{
        range::{IpError, IpRange, Ipv4Range},
        set::IpSet,
    },
    parse::{IpParseError, ip::Keyword},
};
use crate::system::interface;

/// Looks up an interface by name and returns its scope id, for the
/// `%interface` suffix on a link-local target.
///
/// The engine's answer to [`ZoneResolverFn`](crate::model::parse::ip::ZoneResolverFn):
/// the parser knows the syntax and this knows the host.
pub fn resolve_zone(name: &str) -> Option<u32> {
    pnet::datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
        .map(|iface| iface.index)
}

pub fn resolve_keyword(keyword: Keyword, ip_set: &mut IpSet) -> Result<(), IpParseError> {
    match keyword {
        Keyword::Lan => resolve_lan(ip_set),
    }
}

/// Dynamically resolves the host's primary LAN interface into an inclusive range.
///
/// Resolves the *link* rather than an IPv4 network, because the two can come
/// apart: [`is_viable_lan_interface`](interface::lan) accepts an interface
/// carrying only a link-local IPv6 address, and that link is scannable — the
/// all-nodes echo and neighbour discovery both work on it. Asking only for an
/// `Ipv4Network` reported such a link as **"No active network interface
/// found"**, having just selected one and logged its name, and it does the same
/// on any segment whose IPv4 is not RFC1918: carrier-grade NAT, or a network
/// addressed publicly.
fn resolve_lan(set: &mut IpSet) -> Result<(), IpParseError> {
    let link = interface::get_lan_link()
        .map_err(|e| IpParseError::LanError(e.to_string()))?
        .ok_or_else(|| IpParseError::LanError("No active network interface found".into()))?;

    let Some(net) = link.ipv4 else {
        // Named, and named accurately. What the caller needs to be able to tell
        // apart is "nothing is there" from "this link cannot be swept the way
        // you asked", and the old message asserted the first while meaning the
        // second.
        return Err(IpParseError::LanError(format!(
            "{} has no private IPv4 network to sweep{}. Give an explicit range, \
             or an IPv6 target on this link.",
            link.interface.name,
            match link.link_local() {
                Some(addr) => format!(" (its addressing is IPv6: {addr})"),
                None => String::new(),
            }
        )));
    };

    let start_u32 = u32::from(net.network()).saturating_add(1);
    let end_u32 = u32::from(net.broadcast()).saturating_sub(1);

    if start_u32 <= end_u32 {
        let range = Ipv4Range::new(Ipv4Addr::from(start_u32), Ipv4Addr::from(end_u32)).map_err(
            |e| match e {
                IpError::InvalidRange(s, e) => IpParseError::InvalidRange(s, e),
                _ => IpParseError::LanError("Invalid LAN range".into()),
            },
        )?;

        info!(
            verbosity = 1,
            "Resolved LAN: {} - {}",
            range.start_addr(),
            range.end_addr()
        );
        set.insert_range(IpRange::V4(range));
    } else {
        warn!("Small subnet; scanning full network range.");
        let range = Ipv4Range::new(net.network(), net.broadcast()).unwrap();
        set.insert_range(IpRange::V4(range));
    }

    Ok(())
}
