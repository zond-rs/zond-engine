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
//! What is left at this level is the one classification question more than one
//! of those three has to agree about: **is this address globally scoped**, which
//! decides whether it names its host from anywhere or only from one segment.
//!
//! That is a question about an address's *scope*, deliberately, and not about
//! reachability. An address in a globally routed prefix may be firewalled to
//! nothing; an address in a private one may be the only way to reach a host.
//! Confusing the two is how a scanner ends up reporting a host under an address
//! nobody can open a socket to, which is the failure [`scoped`] exists to
//! prevent.

use std::net::Ipv6Addr;

pub mod range;
pub mod scoped;
pub mod set;

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
/// know whether an address is globally scoped, meaning it names the host from
/// off the segment rather than naming a different machine on every one the way
/// a link-local does. A Teredo or 6to4 address is globally scoped: unusual, but
/// not local. Filtering them here would report a host under a link-local address
/// it cannot be reached at, in order to avoid one it can.
///
/// Hand-rolled because `Ipv6Addr::is_unicast_global` is unstable in std, and
/// has been for years.
pub fn is_global_unicast(ipv6_addr: &Ipv6Addr) -> bool {
    let first_byte = ipv6_addr.octets()[0];
    (0x20..=0x3F).contains(&first_byte)
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

    /// The boundaries of `2000::/3`, and the special-purpose prefixes inside it
    /// that this deliberately does not exclude. Both halves matter: an address
    /// wrongly called local costs a host its usable address, and one wrongly
    /// called global is reported at an address nobody can reach.
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
