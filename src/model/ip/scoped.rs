// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Scoped Addresses
//!
//! An IPv6 link-local address is not an address on its own. `fe80::1` names a
//! different machine on every segment it is spoken on, and the operating system
//! will not send to one without being told which interface is meant: a
//! `SocketAddrV6` with a zero `scope_id` fails to connect however reachable the
//! neighbour is.
//!
//! That makes it a genuine defect for a scanner to discover a neighbour at
//! `fe80::…` and hand that address onward as though it were usable. Every later
//! phase - service detection, fingerprinting, the connect fallback - receives an
//! address it cannot open a socket to, and a report renders one its reader
//! cannot act on.
//!
//! [`ScopedIp`] is an address together with the interface it is valid on, where
//! it needs one. Addresses that do not need a zone do not carry one, so
//! equality and hashing stay the ordinary thing for the ordinary case.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::str::FromStr;
use std::sync::Arc;

/// The interface an address is scoped to.
///
/// Both halves are kept because they answer to different audiences. The index is
/// what a `SocketAddrV6` needs and the only thing the kernel understands; the
/// name is what a person reads, what `%en0` means in a target expression, and
/// what a report has to print for its reader to act on. Deriving either from the
/// other costs a lookup at exactly the moments this is used in bulk.
///
/// **A zone written down is not yet a zone found.** Parsing `%en0` yields a
/// name and nothing else; only a lookup against the running host turns it into
/// an index. [`unresolved`](Self::unresolved) is that first state, and
/// [`index`](Self::index) is `None` for as long as it lasts.
///
/// Identity follows from which state it is in. A resolved zone is its index
/// alone: two of them naming the same interface are the same zone whatever
/// string was recorded alongside, since an interface's index is unique on a host
/// for longer than any one scan. An unresolved zone has only the name it was
/// written under, so that is its identity — and a resolved zone is never equal
/// to an unresolved one, because nothing here can know whether they name the
/// same interface.
#[derive(Debug, Clone)]
pub struct Zone {
    index: Option<u32>,
    name: Arc<str>,
}

impl Zone {
    /// Names the interface with index `index`, as a lookup against the host
    /// reported it.
    pub fn new(index: u32, name: impl Into<Arc<str>>) -> Self {
        Self {
            index: Some(index),
            name: name.into(),
        }
    }

    /// Names an interface that nothing has looked up yet.
    ///
    /// What parsing `%en0` out of a target expression produces. An address
    /// scoped to one of these is [`unusable`](ScopedIp::is_unusable) until
    /// something that knows the host's interfaces replaces it: naming an
    /// interface is not the same as having found it, and a socket needs the
    /// index.
    pub fn unresolved(name: impl Into<Arc<str>>) -> Self {
        Self {
            index: None,
            name: name.into(),
        }
    }

    /// The interface index, as a `SocketAddrV6` scope id, once one is known.
    pub fn index(&self) -> Option<u32> {
        self.index
    }

    /// The interface name, as a person writes it.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What identity compares. An index when there is one, and the name it was
    /// written under when there is not; the two states never match each other.
    fn identity(&self) -> (Option<u32>, Option<&str>) {
        match self.index {
            Some(index) => (Some(index), None),
            None => (None, Some(&*self.name)),
        }
    }
}

impl PartialEq for Zone {
    fn eq(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

impl Eq for Zone {}

impl std::hash::Hash for Zone {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.identity().hash(state);
    }
}

impl PartialOrd for Zone {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Zone {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.identity().cmp(&other.identity())
    }
}

impl fmt::Display for Zone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// An IP address, carrying the interface it is valid on when it needs one.
///
/// Constructed through [`ScopedIp::scoped`], which drops a zone the address has
/// no use for. That is what keeps equality honest: a global address is the same
/// address whichever interface it was seen through, so `2001:db8::1` observed on
/// two interfaces must not become two hosts. Only an address whose meaning
/// genuinely depends on the interface keeps one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScopedIp {
    /// Ordered first so sorting is by address, with the zone breaking ties
    /// between identically-numbered link-locals.
    addr: IpAddr,
    zone: Option<Zone>,
}

impl ScopedIp {
    /// An address that needs no interface to be meaningful.
    pub fn unscoped(addr: IpAddr) -> Self {
        Self { addr, zone: None }
    }

    /// An address observed through `zone`, keeping the zone only if the address
    /// is one that needs it. See the type's own documentation for why.
    pub fn scoped(addr: IpAddr, zone: Zone) -> Self {
        Self {
            addr,
            zone: Self::needs_zone(&addr).then_some(zone),
        }
    }

    /// Whether an address is meaningless without an interface to interpret it
    /// against.
    ///
    /// IPv6 link-local unicast only. A global or unique-local address identifies
    /// its host on its own, an IPv4 address has no zone concept at all, and
    /// loopback is scoped to a single interface by definition.
    pub fn needs_zone(addr: &IpAddr) -> bool {
        matches!(addr, IpAddr::V6(v6) if v6.is_unicast_link_local())
    }

    /// The address itself, without its zone.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The interface this address is valid on, if it needs one.
    pub fn zone(&self) -> Option<&Zone> {
        self.zone.as_ref()
    }

    /// Whether this address is one that needs a zone and has no *resolved* one.
    ///
    /// Such an address cannot be connected to, and the honest thing to do with
    /// it is say so rather than attempt a connection that fails with an error
    /// about the network.
    ///
    /// A zone that names an interface nothing has looked up counts as missing.
    /// The kernel takes a scope id and there is none, so `fe80::1%en0` straight
    /// out of a target file is exactly as unreachable as bare `fe80::1` until
    /// something resolves the name.
    pub fn is_unusable(&self) -> bool {
        Self::needs_zone(&self.addr) && self.zone.as_ref().and_then(Zone::index).is_none()
    }

    /// This address as somewhere a socket can be opened to.
    ///
    /// The scope id is what makes a link-local destination reachable at all;
    /// without it the kernel has no interface to send on and refuses. `None`
    /// when the address needs a zone and has none, because the alternative is a
    /// connection attempt that fails for a reason having nothing to do with the
    /// target.
    pub fn to_socket_addr(&self, port: u16) -> Option<SocketAddr> {
        if self.is_unusable() {
            return None;
        }

        match (self.addr, self.zone.as_ref().and_then(Zone::index)) {
            (IpAddr::V6(v6), Some(scope_id)) => {
                Some(SocketAddr::V6(SocketAddrV6::new(v6, port, 0, scope_id)))
            }
            (addr, _) => Some(SocketAddr::new(addr, port)),
        }
    }
}

impl From<IpAddr> for ScopedIp {
    fn from(addr: IpAddr) -> Self {
        Self::unscoped(addr)
    }
}

/// So that an address held by reference reaches anything taking
/// `impl Into<ScopedIp>` without the caller spelling the conversion.
///
/// The address the engine keys a host under is a `ScopedIp`, and the great
/// majority of them need no zone — every IPv4 address, and every IPv6 address
/// but a link-local. A caller holding one of those holds the whole key already,
/// and this is what lets it pass the key it has.
impl From<&IpAddr> for ScopedIp {
    fn from(addr: &IpAddr) -> Self {
        Self::unscoped(*addr)
    }
}

impl From<&ScopedIp> for ScopedIp {
    fn from(scoped: &ScopedIp) -> Self {
        scoped.clone()
    }
}

impl fmt::Display for ScopedIp {
    /// `fe80::1%en0` for a scoped address, the bare address otherwise. This is
    /// the notation every operating system's tooling accepts and the one a
    /// reader can paste back into a command.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.zone {
            Some(zone) => write!(f, "{}%{}", self.addr, zone),
            None => self.addr.fmt(f),
        }
    }
}

/// Why a scoped address could not be read from a string.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScopedIpError {
    /// What sits before the `%`, or the whole string where there is none, is
    /// not an address in either family. Carries the input as it was written.
    #[error("not an IP address: {0}")]
    NotAnAddress(String),
    /// A zone was written on an address that has no use for one. Accepting it
    /// silently would let two spellings of the same address compare unequal.
    #[error("{0} is not a link-local address, so `%{1}` means nothing")]
    ZoneOnUnscopedAddress(IpAddr, String),
    /// The string ended at its `%`, so no interface was named for the zone.
    #[error("`%` with no interface after it")]
    EmptyZone,
}

impl FromStr for ScopedIp {
    type Err = ScopedIpError;

    /// Reads `fe80::1%en0`, or any plain address.
    ///
    /// The interface index is not resolved here: this parses text, and looking
    /// up a name requires the host's interface list. The zone comes back
    /// [`unresolved`](Zone::unresolved), which is to say it carries the name and
    /// no scope id, and the address is [`unusable`](Self::is_unusable) until
    /// something that knows the interfaces supplies one.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((addr, zone)) = s.split_once('%') else {
            return s
                .parse::<IpAddr>()
                .map(Self::unscoped)
                .map_err(|_| ScopedIpError::NotAnAddress(s.to_string()));
        };

        if zone.is_empty() {
            return Err(ScopedIpError::EmptyZone);
        }

        let addr: IpAddr = addr
            .parse()
            .map_err(|_| ScopedIpError::NotAnAddress(s.to_string()))?;
        if !Self::needs_zone(&addr) {
            return Err(ScopedIpError::ZoneOnUnscopedAddress(addr, zone.to_string()));
        }

        Ok(Self {
            addr,
            zone: Some(Zone::unresolved(zone)),
        })
    }
}

/// The unspecified address, as a convenience for callers building one.
impl Default for ScopedIp {
    fn default() -> Self {
        Self::unscoped(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    }
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
    use std::net::Ipv4Addr;

    fn link_local() -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
    }

    fn global() -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    }

    fn en0() -> Zone {
        Zone::new(4, "en0")
    }

    fn en1() -> Zone {
        Zone::new(5, "en1")
    }

    /// The failure this type exists to prevent: the same link-local address on
    /// two segments is two machines, and merging them into one host would
    /// attribute one device's ports to another.
    #[test]
    fn the_same_link_local_on_two_interfaces_is_two_addresses() {
        assert_ne!(
            ScopedIp::scoped(link_local(), en0()),
            ScopedIp::scoped(link_local(), en1())
        );
    }

    /// And the mirror, which matters just as much: a global address is the same
    /// address however it was reached, so a host seen through two interfaces
    /// must not split into two.
    #[test]
    fn a_global_address_is_the_same_address_through_any_interface() {
        assert_eq!(
            ScopedIp::scoped(global(), en0()),
            ScopedIp::scoped(global(), en1())
        );
        assert_eq!(
            ScopedIp::scoped(global(), en0()),
            ScopedIp::unscoped(global())
        );
        assert!(ScopedIp::scoped(global(), en0()).zone().is_none());
    }

    #[test]
    fn ipv4_never_carries_a_zone() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(!ScopedIp::needs_zone(&v4));
        assert!(ScopedIp::scoped(v4, en0()).zone().is_none());
    }

    /// A zone is identified by its index, so the same interface recorded under
    /// two spellings is still one interface.
    #[test]
    fn a_zone_is_its_index_not_its_name() {
        assert_eq!(Zone::new(4, "en0"), Zone::new(4, "utun4"));
        assert_ne!(Zone::new(4, "en0"), Zone::new(5, "en0"));
    }

    /// Until something resolves it, a parsed zone has no index — and identity
    /// by index alone made every one of them the same zone. Two link-local
    /// targets written against two interfaces would then be one address, which
    /// is precisely the collapse this type exists to prevent, reached from the
    /// other direction.
    #[test]
    fn an_unresolved_zone_is_identified_by_the_name_it_was_written_under() {
        let en0: ScopedIp = "fe80::1%en0".parse().expect("parses");
        let en1: ScopedIp = "fe80::1%en1".parse().expect("parses");

        assert_ne!(en0, en1, "two interfaces, two addresses");
        assert_eq!(en0, "fe80::1%en0".parse().expect("parses"));

        // And an unresolved zone cannot open a socket: naming an interface is
        // not the same as having found it.
        assert!(en0.is_unusable());
        assert_eq!(en0.to_socket_addr(22), None);
    }

    /// The point of the whole exercise: a link-local destination is reachable
    /// only when the socket address carries the interface's scope id.
    #[test]
    fn a_scoped_address_produces_a_socket_address_with_its_scope_id() {
        let socket = ScopedIp::scoped(link_local(), en0())
            .to_socket_addr(443)
            .expect("a scoped link-local is usable");

        match socket {
            SocketAddr::V6(v6) => assert_eq!(v6.scope_id(), 4),
            SocketAddr::V4(_) => panic!("an IPv6 address produced a V4 socket address"),
        }
    }

    /// A link-local address with no zone cannot be connected to, and saying so
    /// is better than handing back a `SocketAddr` whose connection fails with an
    /// error describing the network.
    #[test]
    fn an_unzoned_link_local_is_not_usable() {
        let bare = ScopedIp::unscoped(link_local());

        assert!(bare.is_unusable());
        assert_eq!(bare.to_socket_addr(443), None);
    }

    #[test]
    fn an_ordinary_address_is_usable_without_a_zone() {
        let host = ScopedIp::unscoped(global());

        assert!(!host.is_unusable());
        assert_eq!(
            host.to_socket_addr(443),
            Some(SocketAddr::new(global(), 443))
        );
    }

    #[test]
    fn a_scoped_address_renders_and_parses_the_way_the_operating_system_writes_it() {
        let scoped = ScopedIp::scoped(link_local(), en0());
        assert_eq!(scoped.to_string(), "fe80::1%en0");

        let parsed: ScopedIp = "fe80::1%en0".parse().unwrap();
        assert_eq!(parsed.addr(), link_local());
        assert_eq!(parsed.zone().map(Zone::name), Some("en0"));
    }

    /// The field order is load-bearing, and nothing about it is enforced by
    /// the compiler. Sorting a collection of addresses has to be by address,
    /// with the zone separating link-locals that share a number; ordered
    /// zone-first, a sorted list would be grouped by interface instead, and
    /// every consumer that walks addresses in order, whether a report, a merge
    /// or a binary search, would walk a different sequence than it reads as.
    #[test]
    fn addresses_sort_by_address_with_the_zone_breaking_ties() {
        let mut addresses = vec![
            ScopedIp::scoped(link_local(), en1()),
            ScopedIp::unscoped(global()),
            ScopedIp::scoped(link_local(), en0()),
        ];
        addresses.sort();

        assert_eq!(
            addresses,
            vec![
                ScopedIp::unscoped(global()),
                ScopedIp::scoped(link_local(), en0()),
                ScopedIp::scoped(link_local(), en1()),
            ]
        );
    }

    #[test]
    fn an_unscoped_address_renders_bare() {
        assert_eq!(ScopedIp::unscoped(global()).to_string(), "2001:db8::1");
    }

    /// A zone on an address that cannot use one is a mistake worth reporting.
    /// Dropping it silently would let `2001:db8::1%en0` and `2001:db8::1` be
    /// written for the same thing while only one of them round-trips.
    #[test]
    fn a_zone_on_an_address_that_cannot_use_one_is_rejected() {
        assert!(matches!(
            "2001:db8::1%en0".parse::<ScopedIp>(),
            Err(ScopedIpError::ZoneOnUnscopedAddress(_, _))
        ));
        assert_eq!(
            "fe80::1%".parse::<ScopedIp>(),
            Err(ScopedIpError::EmptyZone)
        );
        assert!(matches!(
            "not-an-address%en0".parse::<ScopedIp>(),
            Err(ScopedIpError::NotAnAddress(_))
        ));
    }
}
