// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Parsing Utilities
//!
//! This module serves as the primary gateway for all parsing and resolution logic
//! within the library. It abstracts the complexities of format-specific grammars
//! into a clean, high-level API.
//!
//! Currently supported:
//! * **IP Resolution**: Translating strings and keywords into [`IpSet`](crate::core::models::ip::set::IpSet) models.

pub mod ip;

pub use ip::{IS_LAN_SCAN, IpParseError, to_set as to_ipset};

use crate::core::models::port::PortSet;
use crate::core::models::target::TargetMap;

/// Parses a list of target strings (e.g. `["1.1.1.1:80,443", "8.8.8.8"]`) into a `TargetMap`.
/// Combines per-target specified ports, or falls back to `global_ports`.
///
/// The grammar, and the choice of which colon separates an address from its
/// ports, belong to [`crate::import::target`]; this is the shape of it that
/// takes a keyword resolver and nothing else. A caller that needs interface
/// zones or hostnames builds a [`TargetContext`](crate::import::TargetContext)
/// and calls [`crate::import::target::to_target_map`] directly.
pub fn to_target_map(
    targets: &[String],
    global_ports: PortSet,
    resolver: Option<ip::ResolverFn>,
) -> Result<TargetMap, anyhow::Error> {
    let mut ctx = crate::import::TargetContext::new();
    ctx.keywords = resolver;

    crate::import::target::to_target_map(targets, global_ports, &ctx).map_err(anyhow::Error::from)
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
