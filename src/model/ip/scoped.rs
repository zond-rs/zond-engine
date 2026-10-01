// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Scoped Addresses
//!
//! `fe80::1` names a different machine on every segment, and the operating system will
//! not send to one without an interface: a `SocketAddrV6` with a zero `scope_id` fails
//! to connect however close the neighbour is. A scanner that passed a bare link-local
//! address on would leave every later phase (service detection, fingerprinting, the
//! connect fallback) unable to open a socket to it.
//!
//! [`ScopedIp`] is an address together with the interface it is valid on, where it
//! needs one. Other addresses carry no zone, so equality and hashing are ordinary.

use super::range::Ipv6Range;
use std::fmt;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::str::FromStr;
use std::sync::Arc;

/// The interface an address is scoped to.
///
/// The index is what a `SocketAddrV6` and the kernel need; the name is what a person
/// reads and what `%en0` means in a target expression. Both are kept, since deriving
/// one from the other costs a lookup.
///
/// Parsing `%en0` yields only a name; a lookup against the running host turns it into
/// an index. Until then the zone is [`unresolved`](Self::unresolved) and
/// [`index`](Self::index) is `None`.
///
/// A resolved zone's identity is its index, which is unique on a host for longer than
/// any scan. An unresolved zone's identity is its name. A resolved zone never equals an
/// unresolved one.
#[derive(Debug, Clone)]
pub struct Zone {
    index: Option<u32>,
    name: Arc<str>,
}

impl Zone {
    /// Names the interface with index `index`, as a lookup against the host
    /// reported it.
    ///
    /// An index of zero is a failed lookup (`if_nametoindex` returns it for no such
    /// name), so the zone is [`unresolved`](Self::unresolved) and an address scoped to
    /// it answers [`is_unusable`](ScopedIp::is_unusable).
    pub fn new(index: u32, name: impl Into<Arc<str>>) -> Self {
        match index {
            0 => Self::unresolved(name),
            index => Self {
                index: Some(index),
                name: name.into(),
            },
        }
    }

    /// Names an interface that nothing has looked up yet.
    ///
    /// What parsing `%en0` from a target expression produces. An address scoped to one
    /// is [`unusable`](ScopedIp::is_unusable) until a lookup supplies the index.
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
/// No [`Default`]: no address means "no address".
///
/// [`ScopedIp::scoped`] drops a zone the address does not need, so `2001:db8::1` seen
/// through two interfaces is one host. Only a link-local keeps its zone.
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
    /// IPv6 link-local unicast only.
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
    /// Such an address cannot be connected to.
    ///
    /// An unresolved zone counts as missing: `fe80::1%en0` straight from a target file
    /// has no scope id until the name is looked up.
    pub fn is_unusable(&self) -> bool {
        Self::needs_zone(&self.addr) && self.zone.as_ref().and_then(Zone::index).is_none()
    }

    /// This address as somewhere a socket can be opened to.
    ///
    /// `None` when the address needs a zone and has no resolved one, since the kernel
    /// would refuse it.
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

    /// This address and a port as an endpoint a reader can paste back. The IPv6
    /// form is bracketed so its port is not read as one more hextet, with the
    /// zone kept inside the brackets where a shell and a URL both take it.
    pub fn endpoint(&self, port: u16) -> String {
        if self.addr.is_ipv6() {
            format!("[{self}]:{port}")
        } else {
            format!("{self}:{port}")
        }
    }
}

impl From<IpAddr> for ScopedIp {
    fn from(addr: IpAddr) -> Self {
        Self::unscoped(addr)
    }
}

/// Lets an address held by reference reach anything taking `impl Into<ScopedIp>`.
/// Most addresses need no zone, so the bare address is the whole host key.
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
    /// `fe80::1%en0` for a scoped address, the bare address otherwise: the notation
    /// operating system tooling accepts.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.zone {
            Some(zone) => write!(f, "{}%{}", self.addr, zone),
            None => self.addr.fmt(f),
        }
    }
}

/// Why a scoped address could not be read from a string.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopedIpError {
    /// What sits before the `%`, or the whole string where there is none, is
    /// not an address in either family. Carries the input as it was written.
    #[error("not an IP address: {0}")]
    NotAnAddress(String),
    /// A zone was written on an address that has no use for one, which would make two
    /// spellings of one address compare unequal.
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
    /// The interface is not looked up here, so the zone comes back
    /// [`unresolved`](Zone::unresolved) and the address is
    /// [`unusable`](Self::is_unusable) until something supplies the index.
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

/// Which interface each of a scan's link-local ranges was named on.
///
/// A port scan addresses targets one at a time over the routing table, which cannot
/// carry `fe80::1` without an interface. The zone is written on the range a target came
/// from, so this holds the zoned ranges for the scan's duration and answers which
/// interface an address is valid on.
///
/// Ranges needing no zone are not held; `zone_of` answers `None` for them.
///
/// ```
/// use zond_engine::model::ip::range::Ipv6Range;
/// use zond_engine::model::ip::scoped::ZoneMap;
/// use std::net::{IpAddr, Ipv6Addr};
///
/// let addr: Ipv6Addr = "fe80::1".parse().unwrap();
/// let mut zones = ZoneMap::new();
/// zones.insert(Ipv6Range::scoped(addr, addr, Some(7)).unwrap(), &[(7, "en0")]);
///
/// assert_eq!(zones.zone_of(&IpAddr::V6(addr)), Some(7));
/// assert_eq!(zones.key(IpAddr::V6(addr)).to_string(), "fe80::1%en0");
/// assert_eq!(zones.zone_of(&"2001:db8::1".parse().unwrap()), None);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZoneMap {
    ranges: Vec<(Ipv6Range, Zone)>,
}

impl ZoneMap {
    /// An empty map, holding no scan's zones yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `range` and the interface it names.
    ///
    /// A range carrying no zone is ignored. `interfaces` is the host's interface table
    /// as index and name, supplying the name a report prints.
    pub fn insert(&mut self, range: Ipv6Range, interfaces: &[(u32, &str)]) {
        let Some(index) = range.zone() else {
            return;
        };
        let name = interfaces
            .iter()
            .find(|(held, _)| *held == index)
            .map_or_else(|| index.to_string(), |(_, name)| (*name).to_owned());

        self.ranges.push((range, Zone::new(index, name)));
    }

    /// The interface `ip` is valid on, if this scan named one for it.
    ///
    /// An address covered by two ranges naming different interfaces answers `None`,
    /// since which segment was meant cannot be told.
    pub fn zone_for(&self, ip: &IpAddr) -> Option<&Zone> {
        let IpAddr::V6(v6) = ip else {
            return None;
        };

        let mut found = None;
        for (_, zone) in self.ranges.iter().filter(|(range, _)| range.contains(v6)) {
            match found {
                None => found = Some(zone),
                Some(held) if held == zone => {}
                Some(_) => return None,
            }
        }
        found
    }

    /// The interface index `ip` is valid on, as a socket's scope id.
    pub fn zone_of(&self, ip: &IpAddr) -> Option<u32> {
        self.zone_for(ip).and_then(Zone::index)
    }

    /// `ip` as the engine keys a host under.
    ///
    /// Completes a bare `fe80::…` with its zone, so a port scan's verdicts and a
    /// sweep's hardware address land on one record. Other addresses come back as
    /// themselves.
    pub fn key(&self, ip: IpAddr) -> ScopedIp {
        match self.zone_for(&ip) {
            Some(zone) => ScopedIp::scoped(ip, zone.clone()),
            None => ScopedIp::unscoped(ip),
        }
    }

    /// Whether any address in `range` is also covered by a range already held
    /// under a different interface.
    ///
    /// Answers before insertion, so a caller can refuse both.
    pub fn contests(&self, range: &Ipv6Range) -> bool {
        self.ranges
            .iter()
            .any(|(held, _)| held.zone() != range.zone() && held.overlaps(range))
    }

    /// `ip` and `port` as somewhere a socket can be opened to.
    ///
    /// A link-local destination carries the scope id the scan named it under.
    pub fn endpoint(&self, ip: IpAddr, port: u16) -> SocketAddr {
        match (ip, self.zone_of(&ip)) {
            (IpAddr::V6(v6), Some(zone)) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, zone)),
            _ => SocketAddr::new(ip, port),
        }
    }

    /// Whether this scan named no zoned range at all.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
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
    use std::net::{Ipv4Addr, Ipv6Addr};

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

    /// The same link-local address on two segments is two machines.
    #[test]
    fn the_same_link_local_on_two_interfaces_is_two_addresses() {
        assert_ne!(
            ScopedIp::scoped(link_local(), en0()),
            ScopedIp::scoped(link_local(), en1())
        );
    }

    /// A global address seen through two interfaces is one host.
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
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
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

    /// Unresolved zones are compared by name, so two link-local targets written
    /// against two interfaces stay two addresses.
    #[test]
    fn an_unresolved_zone_is_identified_by_the_name_it_was_written_under() {
        let en0: ScopedIp = "fe80::1%en0".parse().expect("parses");
        let en1: ScopedIp = "fe80::1%en1".parse().expect("parses");

        assert_ne!(en0, en1, "two interfaces, two addresses");
        assert_eq!(en0, "fe80::1%en0".parse().expect("parses"));

        // An unresolved zone cannot open a socket.
        assert!(en0.is_unusable());
        assert_eq!(en0.to_socket_addr(22), None);
    }

    /// A link-local socket address carries the interface's scope id.
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

    /// A scope id of zero is a lookup that failed, and it has to read as one.
    ///
    /// Zero is what `if_nametoindex` returns for no such name. Taken as resolved, it
    /// would produce `[fe80::1]:22` with a zero scope id, which the kernel refuses.
    #[test]
    fn a_zone_whose_index_is_zero_is_a_zone_nothing_found() {
        let failed = ScopedIp::scoped(link_local(), Zone::new(0, "en0"));

        assert_eq!(
            failed.zone().and_then(Zone::index),
            None,
            "zero is not found"
        );
        assert!(failed.is_unusable());
        assert_eq!(failed.to_socket_addr(22), None);

        // The name survives, so the address renders as written.
        assert_eq!(failed.to_string(), "fe80::1%en0");
        assert_eq!(failed, "fe80::1%en0".parse().expect("parses"));
    }

    /// A link-local address with no zone yields no socket address.
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

    /// Sorting is by address, with the zone breaking ties; the derive depends on field
    /// order.
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

    /// A zone on an address that cannot use one is an error.
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

    /// IPv6 endpoints are bracketed with the zone inside; IPv4 is left as is.
    #[test]
    fn an_endpoint_brackets_ipv6_and_keeps_the_zone_inside() {
        assert_eq!(
            ScopedIp::unscoped(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 160))).endpoint(80),
            "192.0.2.160:80"
        );
        assert_eq!(
            ScopedIp::unscoped(global()).endpoint(80),
            "[2001:db8::1]:80"
        );
        assert_eq!(
            ScopedIp::scoped(link_local(), en0()).endpoint(80),
            "[fe80::1%en0]:80"
        );
    }
}
