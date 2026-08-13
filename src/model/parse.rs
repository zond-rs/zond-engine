// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Written down, and read back
//!
//! The grammars that turn what a person typed into the values in
//! [`crate::model`]. [`ip`] handles the address half — literals, ranges, CIDR
//! blocks, zones and keywords — and [`target`] handles an address with a port
//! specification after it.
//!
//! **These grammars live beside the model rather than beside the file formats
//! because every way of naming a target ends here.** A command-line argument, a
//! form field, a line of a target list, a row of somebody's CSV and a hostname
//! read out of an nmap report are all the same expression arriving from
//! different places; writing the grammar once means the formats above decide
//! only where the tokens come from, and none of them can drift into accepting a
//! slightly different dialect.
//!
//! Resolution that needs to ask the machine anything — what `lan` means, which
//! interface a `%zone` names — arrives as a caller-supplied callback
//! ([`ip::ResolverFn`], [`ip::ZoneResolverFn`]). That is what keeps this a leaf:
//! the engine passes [`crate::system::interface`]'s answers in, rather than this
//! module reaching out for them.

pub mod ip;
pub mod target;

pub use ip::{IS_LAN_SCAN, IpParseError, to_set as to_ipset};

use crate::model::port::PortSet;
use crate::model::target::TargetMap;

/// Parses a list of target strings (e.g. `["1.1.1.1:80,443", "8.8.8.8"]`) into a `TargetMap`.
/// Combines per-target specified ports, or falls back to `global_ports`.
///
/// The shape of [`target::to_target_map`] that takes a keyword resolver and
/// nothing else. A caller that also needs interface zones or hostnames builds a
/// [`TargetContext`](target::TargetContext) and calls that function directly.
pub fn to_target_map(
    targets: &[String],
    global_ports: PortSet,
    resolver: Option<ip::ResolverFn>,
) -> Result<TargetMap, anyhow::Error> {
    let mut ctx = target::TargetContext::new();
    ctx.keywords = resolver;

    target::to_target_map(targets, global_ports, &ctx).map_err(anyhow::Error::from)
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
    use std::net::IpAddr;

    #[test]
    fn facade_ip_resolution() {
        let inputs = vec!["127.0.0.1", "10.0.0.1-5"];

        let set = to_ipset(&inputs, None).expect("Facade should resolve IP targets");

        assert_eq!(set.len(), 6);
        assert!(set.contains(&"127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(set.contains(&"10.0.0.3".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn facade_empty_input() {
        let inputs: Vec<&str> = vec![];
        let result = to_ipset(&inputs, None);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IpParseError::EmptySet);
    }

    #[test]
    fn facade_comma_splitting() {
        let inputs = vec!["1.1.1.1, 2.2.2.2"];
        let set = to_ipset(&inputs, None).unwrap();

        assert_eq!(set.len(), 2);
    }
}
