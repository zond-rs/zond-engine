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
//! [`crate::model`]. [`ip`] handles the address half, covering literals,
//! ranges, CIDR blocks, zones and keywords. [`target`] handles an address with
//! a port specification after it.
//!
//! **These grammars live beside the model rather than beside the file formats
//! because every way of naming a target ends here.** A command-line argument, a
//! form field, a line of a target list, a row of somebody's CSV and a hostname
//! read out of an nmap report are all the same expression arriving from
//! different places; writing the grammar once means the formats above decide
//! only where the tokens come from, and none of them can drift into accepting a
//! slightly different dialect.
//!
//! Resolution that needs to ask the machine anything, such as what `lan` means
//! or which interface a `%zone` names, arrives as a caller-supplied callback
//! ([`ip::ResolverFn`], [`ip::ZoneResolverFn`]). That is what keeps this a leaf:
//! the engine passes [`crate::system::interface`]'s answers in, rather than this
//! module reaching out for them.

pub mod ip;
pub mod target;

pub use ip::{IpParseError, names_keyword, to_set as to_ipset};

use crate::model::port::PortSet;
use crate::model::target::TargetMap;

/// Parses target expressions such as `["1.1.1.1:80,443", "8.8.8.8"]` into a
/// [`TargetMap`], giving each one the ports it names or `global_ports` if it
/// names none.
///
/// The shape of [`target::to_target_map`] that takes a keyword resolver and
/// nothing else. To resolve interface zones or hostnames as well, build a
/// [`TargetContext`](target::TargetContext) and call that function directly.
///
/// # Errors
///
/// The first expression that does not parse. Nothing is returned partially, so
/// a caller that wants to log the bad lines and scan the rest should drive
/// [`TargetMapBuilder`](target::TargetMapBuilder) itself.
pub fn to_target_map(
    targets: &[String],
    global_ports: PortSet,
    resolver: Option<ip::ResolverFn>,
) -> Result<TargetMap, target::TargetParseError> {
    let mut ctx = target::TargetContext::new();
    ctx.keywords = resolver;

    target::to_target_map(targets, global_ports, &ctx)
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

    /// [`to_target_map`] is the only thing this module defines rather than
    /// re-exports, and the grammar it wraps is tested where the grammar lives.
    /// What is worth pinning here is the wrapping itself: a context built from
    /// a keyword resolver and nothing else still parses literal targets, and
    /// still groups them by port specification.
    #[test]
    fn the_facade_builds_a_map_from_targets_that_need_no_resolver() {
        let targets = ["10.0.0.1:22".to_string(), "10.0.0.2".to_string()];
        let map = to_target_map(&targets, PortSet::try_from("80").unwrap(), None)
            .expect("literal addresses need nothing resolved");

        assert_eq!(map.units.len(), 2, "port 22, and the default 80");
        assert_eq!(map.gross_targets().unwrap(), 2);
    }

    /// The lookups this shape does *not* take are the point of it. A target
    /// needing one is refused rather than silently dropped, so a scan never
    /// covers less than its input said it would.
    #[test]
    fn the_facade_refuses_a_target_it_cannot_resolve() {
        let targets = ["scanme.example".to_string()];
        let error = to_target_map(&targets, PortSet::try_from("80").unwrap(), None)
            .expect_err("a hostname needs a lookup this shape cannot take");

        assert!(error.to_string().contains("scanme.example"), "{error}");
    }
}
