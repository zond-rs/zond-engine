// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{info, warn};
use std::{net::Ipv4Addr, sync::atomic::Ordering};

use crate::core::models::ip::range::IpRange;
use crate::core::{
    models::ip::{
        range::{IpError, Ipv4Range},
        set::IpSet,
    },
    parse::{IS_LAN_SCAN, IpParseError, ip::Keyword},
};
use crate::system::interface;

/// Looks up an interface by name and returns its scope id, for the
/// `%interface` suffix on a link-local target.
///
/// The engine's answer to [`ZoneResolverFn`](crate::core::parse::ip::ZoneResolverFn):
/// the parser knows the syntax and this knows the host.
pub fn resolve_zone(name: &str) -> Option<u32> {
    pnet::datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
        .map(|iface| iface.index)
}

pub fn resolve(keyword: Keyword, ip_set: &mut IpSet) -> Result<(), IpParseError> {
    match keyword {
        Keyword::Lan => resolve_lan(ip_set),
        Keyword::Vpn => Err(IpParseError::LanError(
            "VPN resolution not implemented".into(),
        )),
    }
}

/// Dynamically resolves the host's primary LAN interface into an inclusive range.
fn resolve_lan(set: &mut IpSet) -> Result<(), IpParseError> {
    let net = interface::get_lan_network()
        .map_err(|e| IpParseError::LanError(e.to_string()))?
        .ok_or_else(|| IpParseError::LanError("No active network interface found".into()))?;

    let start_u32 = u32::from(net.network()).saturating_add(1);
    let end_u32 = u32::from(net.broadcast()).saturating_sub(1);

    if start_u32 <= end_u32 {
        IS_LAN_SCAN.store(true, Ordering::Relaxed);
        let range = Ipv4Range::new(Ipv4Addr::from(start_u32), Ipv4Addr::from(end_u32)).map_err(
            |e| match e {
                IpError::InvalidRange(s, e) => IpParseError::InvalidRange(s, e),
                _ => IpParseError::LanError("Invalid LAN range".into()),
            },
        )?;

        info!(
            verbosity = 1,
            "Resolved LAN: {} - {}", range.start_addr, range.end_addr
        );
        set.insert_range(IpRange::V4(range));
    } else {
        warn!("Small subnet; scanning full network range.");
        let range = Ipv4Range::new(net.network(), net.broadcast()).unwrap();
        set.insert_range(IpRange::V4(range));
    }

    Ok(())
}
