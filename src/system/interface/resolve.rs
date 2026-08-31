// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{info, warn};
use std::net::{IpAddr, Ipv4Addr};

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
    crate::system::interface::interfaces()
        .into_iter()
        .find(|link| link.name() == name)
        .map(|link| link.index())
}

/// Expands a [`Keyword`] into the addresses it stands for and adds them to
/// `ip_set`, leaving whatever the set already held.
///
/// [`Keyword::Lan`] is the only word so far. It adds the IPv4 network of the
/// interface [`lan_link`](interface::lan_link) chose, less the network and
/// broadcast addresses, which no host answers on. A subnet with nothing left
/// after that is added whole.
pub fn resolve_keyword(keyword: Keyword, ip_set: &mut IpSet) -> Result<(), IpParseError> {
    match keyword {
        Keyword::Lan => resolve_lan(ip_set),
    }
}

/// The `lan` keyword, unresolved, with the reason this module found.
fn lan_unresolved(reason: impl Into<String>) -> IpParseError {
    IpParseError::KeywordUnresolved {
        keyword: Keyword::Lan.as_str(),
        reason: reason.into(),
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
    let link = interface::lan_link()
        .ok_or_else(|| lan_unresolved("no active network interface was found"))?;

    let Some(net) = link.ipv4 else {
        // Named, and named accurately. What the caller needs to be able to tell
        // apart is "nothing is there" from "this link cannot be swept the way
        // you asked", and the old message asserted the first while meaning the
        // second.
        return Err(lan_unresolved(format!(
            "{} has no private IPv4 network to sweep{}. Give an explicit range, \
             or an IPv6 target on this link.",
            link.link.name(),
            match link.link_local() {
                Some(addr) => format!(" (its addressing is IPv6: {addr})"),
                None => String::new(),
            }
        )));
    };

    // The network's own ends, from the prefix rather than from arithmetic
    // repeated here: `LinkAddress::network` is what knows how a prefix becomes a
    // range, and it is the same code the on-link tests use.
    let network = net.network();
    let (IpAddr::V4(first), IpAddr::V4(last)) = (network.start_addr(), network.end_addr()) else {
        return Err(lan_unresolved("the LAN link's IPv4 network is not IPv4"));
    };

    // Neither end is a host: the first names the network and the last is the
    // broadcast, and a sweep spends a probe on each for nothing.
    let start_u32 = u32::from(first).saturating_add(1);
    let end_u32 = u32::from(last).saturating_sub(1);

    if start_u32 <= end_u32 {
        let range = Ipv4Range::new(Ipv4Addr::from(start_u32), Ipv4Addr::from(end_u32)).map_err(
            |e| match e {
                IpError::InvalidRange(s, e) => IpParseError::InvalidRange(s, e),
                _ => lan_unresolved("the network's own ends are out of order"),
            },
        )?;

        info!(
            verbosity = 1,
            "resolved LAN: {} - {}",
            range.start_addr(),
            range.end_addr()
        );
        set.insert_range(IpRange::V4(range));
    } else {
        warn!("small subnet; scanning full network range");
        let range = Ipv4Range::new(first, last).expect("a network's own ends are ordered");
        set.insert_range(IpRange::V4(range));
    }

    Ok(())
}
