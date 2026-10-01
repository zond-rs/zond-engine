// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Contiguous runs of addresses
//!
//! A range is two addresses and everything between them, inclusive at both ends: how a
//! `/8` is held without holding its addresses. It is the unit
//! [`IpSet`](super::set::IpSet) is built from.
//!
//! [`Ipv4Range`] and [`Ipv6Range`] are separate types because the arithmetic differs: a
//! v4 range's length always fits a `u64`, a v6 range's can exceed a `u128`. [`IpRange`]
//! is the enum over both.
//!
//! The families never compare: `::ffff:192.0.2.1` is an IPv6 address here. Membership
//! across families is `false`, not an error, since callers are filtering received
//! packets.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use thiserror::Error;

/// Why a range could not be built or read.
///
/// [`InvalidFormat`](Self::InvalidFormat), [`AddrParse`](Self::AddrParse) and
/// [`PrefixParse`](Self::PrefixParse) mean "not a range" (which a hostname also looks
/// like); the other two mean "a range, but wrong". [`parse::ip`](crate::model::parse::ip)
/// depends on that split.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IpError {
    /// The start address is above the end. Both are named.
    #[error("Invalid range: start address {0} is greater than end address {1}")]
    InvalidRange(IpAddr, IpAddr),

    /// A CIDR prefix longer than its family allows.
    ///
    /// The message omits the bound, since the family is not carried;
    /// [`IpParseError::InvalidPrefix`](crate::model::parse::ip::IpParseError::InvalidPrefix)
    /// names both.
    #[error("Invalid CIDR prefix: {0}")]
    InvalidPrefix(u8),

    /// Not an address at all, on either side of a separator.
    #[error("Failed to parse IP address: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    /// Recognisably a range, having a separator, but not one this grammar
    /// accepts.
    #[error("Invalid IP range format: {0}")]
    InvalidFormat(String),

    /// The text after `/` was not a number.
    #[error("Invalid prefix number format: {0}")]
    PrefixParse(#[from] std::num::ParseIntError),
}

// ══════════════════════════════════════════════════════════════════════════════
// IPv4 Range
// ══════════════════════════════════════════════════════════════════════════════

/// A contiguous run of IPv4 addresses, inclusive at both ends.
///
/// Eight bytes, whatever the range covers. [`new`](Self::new) guarantees the start is
/// never above the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Range {
    /// The inclusive starting address of the range.
    start_addr: Ipv4Addr,
    /// The inclusive ending address of the range.
    end_addr: Ipv4Addr,
}

impl Ipv4Range {
    /// Creates a new `Ipv4Range`.
    ///
    /// # Errors
    ///
    /// Returns [`IpError::InvalidRange`] if `start` is numerically greater than `end`.
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Result<Self, IpError> {
        if u32::from(start) <= u32::from(end) {
            Ok(Self {
                start_addr: start,
                end_addr: end,
            })
        } else {
            Err(IpError::InvalidRange(IpAddr::V4(start), IpAddr::V4(end)))
        }
    }

    /// Returns an iterator over every [`IpAddr`] within the range.
    ///
    /// # Performance
    ///
    /// Iterating over large ranges (e.g., /8) is fast, but collecting the results
    /// into a `Vec` will consume significant memory.
    pub fn iter(&self) -> impl Iterator<Item = IpAddr> {
        let start: u32 = self.start_addr.into();
        let end: u32 = self.end_addr.into();
        (start..=end).map(|ip| IpAddr::V4(Ipv4Addr::from(ip)))
    }

    /// A range covering the single address `addr`.
    ///
    /// Infallible, unlike [`new`](Self::new).
    pub const fn single(addr: Ipv4Addr) -> Self {
        Self {
            start_addr: addr,
            end_addr: addr,
        }
    }

    /// The inclusive first address.
    pub fn start_addr(&self) -> Ipv4Addr {
        self.start_addr
    }

    /// The inclusive last address, never lower than
    /// [`start_addr`](Self::start_addr).
    pub fn end_addr(&self) -> Ipv4Addr {
        self.end_addr
    }

    /// Extends this range to reach `end`, if it does not already.
    ///
    /// The only mutation a range allows, used to merge adjacent ranges. Growing the end
    /// cannot invert the range.
    pub fn extend_end_to(&mut self, end: Ipv4Addr) {
        if end > self.end_addr {
            self.end_addr = end;
        }
    }

    /// Checks if the given [`Ipv4Addr`] falls within this range (inclusive).
    pub fn contains(&self, ip: &Ipv4Addr) -> bool {
        (u32::from(self.start_addr)..=u32::from(self.end_addr)).contains(&u32::from(*ip))
    }

    /// How many addresses the range covers, never fewer than one.
    ///
    /// No `is_empty`: a range always holds at least one address, unlike an
    /// [`IpSet`](crate::model::ip::set::IpSet::is_empty).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 {
        let s_u32: u64 = u32::from(self.start_addr) as u64;
        let e_u32: u64 = u32::from(self.end_addr) as u64;
        (e_u32 - s_u32) + 1
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// IPv6 Range
// ══════════════════════════════════════════════════════════════════════════════

/// A contiguous run of IPv6 addresses, inclusive at both ends, together with the
/// interface they are valid on if they need one.
///
/// The start is never above the end, for the reason [`Ipv4Range`] gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Range {
    /// The inclusive starting address of the range.
    start_addr: Ipv6Addr,
    /// The inclusive ending address of the range.
    end_addr: Ipv6Addr,
    /// The interface these addresses are valid on, as a scope id, for a range
    /// of link-local addresses.
    ///
    /// The index only, so this type stays `Copy`; the index is all a socket needs. The
    /// name lives on [`Zone`](crate::model::ip::scoped::Zone).
    ///
    /// `None` except for link-local ranges. See
    /// [`ScopedIp`](crate::model::ip::scoped::ScopedIp).
    zone: Option<u32>,
}

impl Ipv6Range {
    /// Creates a new `Ipv6Range`.
    ///
    /// # Errors
    ///
    /// Returns [`IpError::InvalidRange`] if `start` is numerically greater than `end`.
    pub fn new(start: Ipv6Addr, end: Ipv6Addr) -> Result<Self, IpError> {
        Self::scoped(start, end, None)
    }

    /// Creates an `Ipv6Range` valid on the interface with scope id `zone`.
    ///
    /// `Some(0)` is read as `None`: zero is a failed name lookup (see
    /// [`Zone::new`](crate::model::ip::scoped::Zone::new)), and kept it would hide the
    /// problem from [`is_ambiguous`](Self::is_ambiguous).
    ///
    /// # Errors
    ///
    /// Returns [`IpError::InvalidRange`] if `start` is numerically greater than
    /// `end`.
    pub fn scoped(start: Ipv6Addr, end: Ipv6Addr, zone: Option<u32>) -> Result<Self, IpError> {
        if u128::from(start) <= u128::from(end) {
            Ok(Self {
                start_addr: start,
                end_addr: end,
                zone: zone.filter(|index| *index != 0),
            })
        } else {
            Err(IpError::InvalidRange(IpAddr::V6(start), IpAddr::V6(end)))
        }
    }

    /// A range covering the single address `addr`, on no particular interface.
    /// The counterpart of [`Ipv4Range::single`].
    pub const fn single(addr: Ipv6Addr) -> Self {
        Self {
            start_addr: addr,
            end_addr: addr,
            zone: None,
        }
    }

    /// The inclusive first address.
    pub fn start_addr(&self) -> Ipv6Addr {
        self.start_addr
    }

    /// The inclusive last address, never lower than
    /// [`start_addr`](Self::start_addr).
    pub fn end_addr(&self) -> Ipv6Addr {
        self.end_addr
    }

    /// Extends this range to reach `end`, if it does not already. See
    /// [`Ipv4Range::extend_end_to`].
    pub fn extend_end_to(&mut self, end: Ipv6Addr) {
        if end > self.end_addr {
            self.end_addr = end;
        }
    }

    /// The interface these addresses are valid on, as a scope id, if they need
    /// one.
    pub fn zone(&self) -> Option<u32> {
        self.zone
    }

    /// Whether these addresses are meaningless without an interface to
    /// interpret them against, and none is recorded.
    ///
    /// Such a range cannot be probed: every interface holds an `fe80::/64`, so which
    /// segment was meant cannot be told.
    ///
    /// True where *any* of the range is link-local, so `fe00::-fe80::5`, which starts
    /// outside it, counts.
    pub fn is_ambiguous(&self) -> bool {
        self.zone.is_none() && self.covers_link_local()
    }

    /// Whether any address in the range is in `fe80::/10`.
    pub fn covers_link_local(&self) -> bool {
        u128::from(self.start_addr) <= LINK_LOCAL_LAST
            && u128::from(self.end_addr) >= LINK_LOCAL_FIRST
    }

    /// Whether every address in the range is in `fe80::/10`.
    ///
    /// What a `%zone` suffix requires of the range it is written on.
    pub fn is_link_local(&self) -> bool {
        u128::from(self.start_addr) >= LINK_LOCAL_FIRST
            && u128::from(self.end_addr) <= LINK_LOCAL_LAST
    }

    /// The IPv4 range this range spells, when it lies wholly inside the
    /// IPv4-mapped block `::ffff:0:0/96`.
    ///
    /// RFC 4291 §2.5.5.2 writes an IPv4 address inside an IPv6 one that way, and a
    /// dual-stack socket handed `::ffff:192.0.2.1` connects to `192.0.2.1`.
    ///
    /// [`None`] when either end lies outside the block, including a range like `::/0`
    /// that merely contains it.
    pub(crate) fn spelled_ipv4(&self) -> Option<Ipv4Range> {
        // The block is contiguous, so both ends inside means the whole range is.
        let start = self.start_addr.to_ipv4_mapped()?;
        let end = self.end_addr.to_ipv4_mapped()?;
        Ipv4Range::new(start, end).ok()
    }

    /// Returns an iterator over every [`IpAddr`] within the range.
    ///
    /// # Warning
    ///
    /// IPv6 ranges can be astronomically large: iterating a `/64` does not finish. For
    /// small ranges.
    pub fn iter(&self) -> impl Iterator<Item = IpAddr> {
        let start: u128 = self.start_addr.into();
        let end: u128 = self.end_addr.into();
        (start..=end).map(|ip| IpAddr::V6(Ipv6Addr::from(ip)))
    }

    /// Checks if the given [`Ipv6Addr`] falls within this range (inclusive).
    ///
    /// Ignores the zone, like [`IpSet::contains`](super::set::IpSet::contains): a
    /// received packet carries a bare address.
    pub fn contains(&self, ip: &Ipv6Addr) -> bool {
        (u128::from(self.start_addr)..=u128::from(self.end_addr)).contains(&u128::from(*ip))
    }

    /// Whether any address falls in both ranges.
    ///
    /// Ignores the zone, as [`contains`](Self::contains) does, so a caller can compare
    /// zones of overlapping ranges.
    pub fn overlaps(&self, other: &Self) -> bool {
        u128::from(self.start_addr) <= u128::from(other.end_addr)
            && u128::from(other.start_addr) <= u128::from(self.end_addr)
    }

    /// How many addresses the range covers, never fewer than one. See
    /// [`Ipv4Range::len`] for why there is no `is_empty` beside it.
    ///
    /// `::/0` covers 2^128 addresses, one more than a `u128` holds, so the count
    /// saturates at [`u128::MAX`]. Wrapping would report the whole of IPv6 as zero and
    /// pass a budget check.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u128 {
        let s_u128: u128 = u128::from(self.start_addr);
        let e_u128: u128 = u128::from(self.end_addr);
        (e_u128 - s_u128).saturating_add(1)
    }
}

/// The first and last address of `fe80::/10`, the block
/// [`Ipv6Addr::is_unicast_link_local`] answers for.
///
/// Written out because the predicate takes one address and a range is two. A test
/// checks they agree at all four boundaries.
const LINK_LOCAL_FIRST: u128 = 0xfe80 << 112;
const LINK_LOCAL_LAST: u128 = (0xfebf << 112) | ((1u128 << 112) - 1);

// ══════════════════════════════════════════════════════════════════════════════
// Unified IpRange API
// ══════════════════════════════════════════════════════════════════════════════

/// Either family's range, for a caller that does not care which it was handed.
///
/// What [`FromStr`] produces, since the text decides the family.
///
/// Not `#[non_exhaustive]`: there is no third address family, so matching both arms is
/// exhaustive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpRange {
    /// An IPv4 address range.
    V4(Ipv4Range),
    /// An IPv6 address range.
    V6(Ipv6Range),
}

impl IpRange {
    /// Every address the range holds, ascending.
    ///
    /// Boxed, since the families iterate as different types, as in
    /// [`IpSet::iter`](super::set::IpSet::iter). Iterating a wide IPv6 range does not
    /// finish.
    pub fn iter(&self) -> Box<dyn Iterator<Item = IpAddr> + Send + '_> {
        match self {
            IpRange::V4(range) => Box::new(range.iter()),
            IpRange::V6(range) => Box::new(range.iter()),
        }
    }

    /// Returns the start address of the range as an [`IpAddr`].
    pub fn start_addr(&self) -> IpAddr {
        match self {
            IpRange::V4(r) => IpAddr::V4(r.start_addr),
            IpRange::V6(r) => IpAddr::V6(r.start_addr),
        }
    }

    /// Returns the end address of the range as an [`IpAddr`].
    pub fn end_addr(&self) -> IpAddr {
        match self {
            IpRange::V4(r) => IpAddr::V4(r.end_addr),
            IpRange::V6(r) => IpAddr::V6(r.end_addr),
        }
    }

    /// Checks if the given [`IpAddr`] falls within this range.
    ///
    /// Returns `false` if the protocol versions do not match (e.g., checking
    /// if a V6 address is in a V4 range).
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (IpRange::V4(r), IpAddr::V4(ip)) => r.contains(ip),
            (IpRange::V6(r), IpAddr::V6(ip)) => r.contains(ip),
            _ => false,
        }
    }

    /// How many addresses the range covers, never fewer than one. See
    /// [`Ipv4Range::len`] for why there is no `is_empty` beside it.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u128 {
        match self {
            IpRange::V4(r) => r.len() as u128,
            IpRange::V6(r) => r.len(),
        }
    }
}

impl FromStr for IpRange {
    type Err = IpError;

    /// Parses an IP range from a string.
    ///
    /// Supports:
    /// - CIDR notation: `192.0.2.0/24`, `2001:db8::/32`
    /// - Hyphenated ranges: `198.51.100.1-198.51.100.5`, `::1-::f`
    /// - Shortened IPv4 ranges, where the end continues the start's octets:
    ///   `10.0.0.1-50`, `192.168.1.1-2.254`
    /// - Single IPs: `1.1.1.1`, `::1`
    ///
    /// The whole range grammar: everything in the crate that reads a written range ends
    /// here.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        // CIDR
        if let Some(pos) = s.find('/') {
            let ip = s[..pos].parse::<IpAddr>()?;
            let prefix = s[pos + 1..].parse::<u8>()?;
            return cidr_range(ip, prefix);
        }

        // Hyphenated range
        if let Some(pos) = s.find('-') {
            // Not trimmed around the separator: `IpSet` splits on spaces, so
            // `192.0.2.1 - 192.0.2.5` arrives as three tokens there, and trimming
            // here would make a second dialect.
            let start_str = &s[..pos];
            let end_str = &s[pos + 1..];

            if let Ok(start) = start_str.parse::<Ipv4Addr>() {
                let end = expand_v4_end(start, end_str)
                    .ok_or_else(|| IpError::InvalidFormat(s.to_string()))?;
                return Ok(IpRange::V4(Ipv4Range::new(start, end)?));
            } else if let Ok(start) = start_str.parse::<Ipv6Addr>() {
                let end = end_str.parse::<Ipv6Addr>()?;
                return Ok(IpRange::V6(Ipv6Range::new(start, end)?));
            }
            return Err(IpError::InvalidFormat(s.to_string()));
        }

        // Single address
        match s.parse::<IpAddr>()? {
            IpAddr::V4(v4) => Ok(IpRange::V4(Ipv4Range::single(v4))),
            IpAddr::V6(v6) => Ok(IpRange::V6(Ipv6Range::single(v6))),
        }
    }
}

/// Reads the end of an IPv4 range, which may be written in full or as however
/// many trailing octets differ from the start.
///
/// `10.0.0.1-50` ends at `10.0.0.50` and `192.168.1.1-2.254` at `192.168.2.254`: the
/// octets given replace as many octets at the end of the start address.
///
/// IPv4 only: an IPv6 form would make `::1-5` ambiguous with a hex group.
fn expand_v4_end(start: Ipv4Addr, end_str: &str) -> Option<Ipv4Addr> {
    if let Ok(full) = end_str.parse::<Ipv4Addr>() {
        return Some(full);
    }

    let suffix: Vec<u8> = end_str.split('.').map(octet).collect::<Option<_>>()?;

    if suffix.is_empty() || suffix.len() > 4 {
        return None;
    }

    let mut octets = start.octets();
    octets[4 - suffix.len()..].copy_from_slice(&suffix);
    Some(Ipv4Addr::from(octets))
}

/// One octet of a shortened range's end, read as strictly as an address's own.
///
/// `u8::from_str` accepts a leading `+` and a leading zero, but `Ipv4Addr::from_str`
/// refuses a leading zero since 1.53, because `010` is octal to enough software to
/// matter. Both halves of a range must use the same rules.
fn octet(part: &str) -> Option<u8> {
    if part.len() > 1 && part.starts_with('0') {
        return None;
    }
    if !part.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    part.parse().ok()
}

/// Constructs an [`IpRange`] from an IP address and a CIDR prefix length.
///
/// # Examples
///
/// ```
/// use zond_engine::model::ip::range::{cidr_range, IpRange};
/// use std::net::IpAddr;
///
/// let range = cidr_range("192.0.2.5".parse().unwrap(), 24).unwrap();
/// assert_eq!(range.len(), 256);
/// ```
pub fn cidr_range(ip: IpAddr, prefix: u8) -> Result<IpRange, IpError> {
    match ip {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return Err(IpError::InvalidPrefix(prefix));
            }

            // `/0` needs no special case: `checked_shr(0)` is the whole mask.
            let ip_u32 = u32::from(v4);
            let mask = !u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(0);

            let network = ip_u32 & mask;
            let broadcast = ip_u32 | !mask;

            Ok(IpRange::V4(
                Ipv4Range::new(Ipv4Addr::from(network), Ipv4Addr::from(broadcast)).unwrap_or_else(
                    |_| unreachable!("a network address is never above its own broadcast"),
                ),
            ))
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return Err(IpError::InvalidPrefix(prefix));
            }

            let ip_u128 = u128::from(v6);
            let mask = !u128::MAX.checked_shr(u32::from(prefix)).unwrap_or(0);

            let network = ip_u128 & mask;
            let broadcast = ip_u128 | !mask;

            Ok(IpRange::V6(
                Ipv6Range::new(Ipv6Addr::from(network), Ipv6Addr::from(broadcast)).unwrap_or_else(
                    |_| unreachable!("a network address is never above its own broadcast"),
                ),
            ))
        }
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

    /// A range holds nothing beyond its inclusive endpoints.
    #[test]
    fn a_range_holds_both_its_bounds_and_nothing_outside_them() {
        let v4 = Ipv4Range::new(
            Ipv4Addr::new(203, 0, 113, 10),
            Ipv4Addr::new(203, 0, 113, 20),
        )
        .unwrap();
        assert!(v4.contains(&Ipv4Addr::new(203, 0, 113, 10)));
        assert!(v4.contains(&Ipv4Addr::new(203, 0, 113, 20)));
        assert!(!v4.contains(&Ipv4Addr::new(203, 0, 113, 9)));
        assert!(!v4.contains(&Ipv4Addr::new(203, 0, 113, 21)));

        let v6 = Ipv6Range::new(Ipv6Addr::from(100), Ipv6Addr::from(200)).unwrap();
        assert_eq!(v6.len(), 101, "inclusive at both ends");
        assert!(v6.contains(&Ipv6Addr::from(100)));
        assert!(v6.contains(&Ipv6Addr::from(200)));
        assert!(!v6.contains(&Ipv6Addr::from(201)));
    }

    /// The ends of each address space, where the arithmetic that counts a range
    /// is one step from overflowing.
    ///
    /// `::/0` saturates at `u128::MAX`.
    #[test]
    fn the_extremes_of_each_address_space_saturate_rather_than_wrap() {
        let top_of_v4 = Ipv4Range::new(
            Ipv4Addr::new(255, 255, 255, 254),
            Ipv4Addr::new(255, 255, 255, 255),
        )
        .unwrap();
        assert_eq!(top_of_v4.len(), 2);

        let sixty_four = cidr_range(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 64).unwrap();
        assert_eq!(sixty_four.len(), 1u128 << 64);

        let everything = cidr_range(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).unwrap();
        assert_eq!(everything.len(), u128::MAX, "saturated, never zero");
    }

    /// Ascending, with no address skipped or repeated.
    #[test]
    fn iteration_yields_every_address_in_ascending_order() {
        let v4 = Ipv4Range::new(Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 1, 1, 3)).unwrap();
        assert_eq!(
            v4.iter().collect::<Vec<_>>(),
            [
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 3)),
            ]
        );

        let v6 = Ipv6Range::new(Ipv6Addr::from(1), Ipv6Addr::from(3)).unwrap();
        assert_eq!(
            v6.iter().collect::<Vec<_>>(),
            [
                IpAddr::V6(Ipv6Addr::from(1)),
                IpAddr::V6(Ipv6Addr::from(2)),
                IpAddr::V6(Ipv6Addr::from(3)),
            ]
        );
    }

    /// Every form the grammar accepts, and what each covers.
    ///
    /// Target files, imported reports and command lines all read ranges here.
    #[test]
    fn every_written_form_names_the_range_it_says_it_does() {
        for (written, first, last) in [
            ("8.8.8.8", "8.8.8.8", "8.8.8.8"),
            ("198.51.100.0/24", "198.51.100.0", "198.51.100.255"),
            ("192.0.2.5/24", "192.0.2.0", "192.0.2.255"),
            ("1.1.1.1-1.1.1.5", "1.1.1.1", "1.1.1.5"),
            ("198.51.100.1-50", "198.51.100.1", "198.51.100.50"),
            ("192.168.1.1-2.254", "192.168.1.1", "192.168.2.254"),
            ("::1", "::1", "::1"),
            ("::1/120", "::", "::ff"),
            ("2001:db8::1-2001:db8::5", "2001:db8::1", "2001:db8::5"),
        ] {
            let range: IpRange = written.parse().unwrap_or_else(|e| panic!("{written}: {e}"));

            assert_eq!(range.start_addr().to_string(), first, "{written} starts");
            assert_eq!(range.end_addr().to_string(), last, "{written} ends");
        }
    }

    /// One grammar for both halves of a range.
    ///
    /// A leading zero or sign is refused on either side of the hyphen.
    #[test]
    fn both_halves_of_a_range_read_octets_the_same_way() {
        for spelling in [
            "010.0.0.1",             // as a start
            "198.51.100.1-010",      // as an end
            "198.51.100.1-0.0.0.50", // in a longer suffix
            "198.51.100.1-+50",      // a sign is not an octet either
            "198.51.100.1- 50",      // nor is one with space around it
        ] {
            assert!(
                spelling.parse::<IpRange>().is_err(),
                "`{spelling}` was read as a range"
            );
        }

        // A single zero is fine, as are the ordinary forms.
        for (spelling, last) in [
            ("198.51.100.0-0", "198.51.100.0"),
            ("198.51.100.1-50", "198.51.100.50"),
            ("192.168.1.1-2.254", "192.168.2.254"),
        ] {
            let range: IpRange = spelling
                .parse()
                .unwrap_or_else(|e| panic!("{spelling}: {e}"));
            assert_eq!(range.end_addr().to_string(), last, "{spelling}");
        }
    }

    /// A range has no spaces in it, whichever door it arrives through.
    ///
    /// `IpSet::from_str` splits on spaces, so trimming around the separator here would
    /// make a second dialect.
    #[test]
    fn a_range_written_with_spaces_is_not_a_range() {
        assert!("198.51.100.1 - 198.51.100.5".parse::<IpRange>().is_err());
        assert!("198.51.100.1 -198.51.100.5".parse::<IpRange>().is_err());

        // The whole token is still trimmed.
        let padded: IpRange = "  198.51.100.1-198.51.100.5  "
            .parse()
            .expect("trimmed as a whole");
        assert_eq!(padded.len(), 5);
    }

    /// The link-local bounds agree with the predicate std answers for one
    /// address, at all four edges.
    #[test]
    fn the_link_local_bounds_are_the_block_std_recognises() {
        let first = Ipv6Addr::from(LINK_LOCAL_FIRST);
        let last = Ipv6Addr::from(LINK_LOCAL_LAST);
        assert!(first.is_unicast_link_local(), "{first}");
        assert!(last.is_unicast_link_local(), "{last}");

        let below = Ipv6Addr::from(LINK_LOCAL_FIRST - 1);
        let above = Ipv6Addr::from(LINK_LOCAL_LAST + 1);
        assert!(!below.is_unicast_link_local(), "{below}");
        assert!(!above.is_unicast_link_local(), "{above}");
    }

    /// A range is two addresses, and whether it is link-local is a question
    /// about both.
    ///
    /// Covering *some* link-local space makes a range ambiguous; covering *only*
    /// link-local space is what a `%zone` suffix needs.
    #[test]
    fn whether_a_range_is_link_local_is_a_question_about_all_of_it() {
        let range = |first: &str, last: &str| {
            Ipv6Range::new(
                first.parse().expect("an address"),
                last.parse().expect("an address"),
            )
            .expect("in order")
        };

        // Runs into the block from below: some of it needs a zone.
        let into = range("fe00::", "fe80::5");
        assert!(into.covers_link_local());
        assert!(!into.is_link_local(), "most of it is not link-local");
        assert!(into.is_ambiguous(), "and the part that is has no interface");

        // Runs out of the block from within: same answer, other direction.
        let out_of = range("fe80::1", "fec0::1");
        assert!(out_of.covers_link_local());
        assert!(!out_of.is_link_local());
        assert!(out_of.is_ambiguous());

        // Entirely inside, where a zone may be written.
        let inside = range("fe80::1", "fe80::5");
        assert!(inside.covers_link_local() && inside.is_link_local());
        assert!(inside.is_ambiguous(), "until an interface is named");

        // Entirely outside, at both ends of the block.
        for (first, last) in [("2001:db8::", "2001:db8::ff"), ("fec0::", "fec0::ff")] {
            let elsewhere = range(first, last);
            assert!(!elsewhere.covers_link_local(), "{first}-{last}");
            assert!(!elsewhere.is_link_local(), "{first}-{last}");
            assert!(!elsewhere.is_ambiguous(), "{first}-{last}");
        }
    }

    /// A scope id of zero names no interface, so a range carrying one is not
    /// scoped and has to say so.
    ///
    /// Otherwise `is_ambiguous` would treat it as answered.
    #[test]
    fn a_zone_of_zero_is_no_zone_at_all() {
        let link_local: Ipv6Addr = "fe80::1".parse().expect("literal");
        let range = Ipv6Range::scoped(link_local, link_local, Some(0)).expect("one address");

        assert_eq!(range.zone(), None);
        assert!(
            range.is_ambiguous(),
            "a link-local range nothing resolved is ambiguous"
        );

        // A real index is untouched.
        let found = Ipv6Range::scoped(link_local, link_local, Some(7)).expect("one address");
        assert_eq!(found.zone(), Some(7));
        assert!(!found.is_ambiguous());
    }

    /// `new` refuses an inverted range.
    #[test]
    fn a_range_can_only_be_built_in_order() {
        let low = Ipv4Addr::new(198, 51, 100, 1);
        let high = Ipv4Addr::new(198, 51, 100, 5);

        assert!(matches!(
            Ipv4Range::new(high, low),
            Err(IpError::InvalidRange(_, _))
        ));

        assert!(matches!(
            Ipv6Range::new(Ipv6Addr::from(2), Ipv6Addr::from(1)),
            Err(IpError::InvalidRange(_, _))
        ));

        let range = Ipv4Range::new(low, high).expect("in order");
        assert_eq!(range.len(), 5);
        assert_eq!(range.iter().count() as u64, range.len());
    }

    /// `extend_end_to` only grows the end.
    #[test]
    fn extending_a_range_never_inverts_it() {
        let mut range = Ipv4Range::new(
            Ipv4Addr::new(198, 51, 100, 1),
            Ipv4Addr::new(198, 51, 100, 5),
        )
        .unwrap();

        range.extend_end_to(Ipv4Addr::new(198, 51, 100, 9));
        assert_eq!(range.end_addr(), Ipv4Addr::new(198, 51, 100, 9));

        // A shorter end does not shrink it.
        range.extend_end_to(Ipv4Addr::new(198, 51, 100, 2));
        assert_eq!(range.end_addr(), Ipv4Addr::new(198, 51, 100, 9));
        assert!(range.end_addr() >= range.start_addr());
        assert_eq!(range.iter().count() as u64, range.len());
    }

    /// The messages name the value that was wrong.
    #[test]
    fn an_error_names_the_input_that_produced_it() {
        let prefix_err = IpError::InvalidPrefix(40);
        assert_eq!(format!("{prefix_err}"), "Invalid CIDR prefix: 40");

        let range_err = IpError::InvalidRange(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        );
        assert!(format!("{range_err}").contains("is greater than"));
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn any_ipv4() -> impl Strategy<Value = Ipv4Addr> {
        proptest::prelude::any::<u32>().prop_map(Ipv4Addr::from)
    }

    fn any_ipv6() -> impl Strategy<Value = Ipv6Addr> {
        proptest::prelude::any::<u128>().prop_map(Ipv6Addr::from)
    }

    fn any_ipv4_range() -> impl Strategy<Value = Ipv4Range> {
        (any_ipv4(), 0..5000u32).prop_map(|(start, len)| {
            let start_u32 = u32::from(start);
            let end_u32 = start_u32.saturating_add(len);
            Ipv4Range::new(start, Ipv4Addr::from(end_u32)).unwrap()
        })
    }

    fn any_ipv6_range() -> impl Strategy<Value = Ipv6Range> {
        (any_ipv6(), 0..5000u128).prop_map(|(start, len)| {
            let start_u128 = u128::from(start);
            let end_u128 = start_u128.saturating_add(len);
            Ipv6Range::new(start, Ipv6Addr::from(end_u128)).unwrap()
        })
    }

    proptest::proptest! {
        #[test]
        fn ipv4_range_invariant(a in any_ipv4(), b in any_ipv4()) {
            let start = std::cmp::min(a, b);
            let end = std::cmp::max(a, b);
            let range = Ipv4Range::new(start, end).unwrap();
            prop_assert!(range.contains(&start));
            prop_assert!(range.contains(&end));
            prop_assert_eq!(range.len(), (u32::from(end) - u32::from(start)) as u64 + 1);
        }

        #[test]
        fn ipv6_range_invariant(a in any_ipv6(), b in any_ipv6()) {
            let start = std::cmp::min(a, b);
            let end = std::cmp::max(a, b);
            let range = Ipv6Range::new(start, end).unwrap();
            prop_assert!(range.contains(&start));
            prop_assert!(range.contains(&end));
            prop_assert_eq!(range.len(), (u128::from(end) - u128::from(start)) + 1);
        }

        #[test]
        fn ipv4_iterator_consistency(range in any_ipv4_range()) {
            prop_assert_eq!(range.iter().count() as u64, range.len());
        }

        #[test]
        fn ipv6_iterator_consistency(range in any_ipv6_range()) {
            prop_assert_eq!(range.iter().count() as u128, range.len());
        }

        /// From zero, the prefix an implementation is tempted to special-case.
        #[test]
        fn cidr_v4_roundtrip(v4 in any_ipv4(), prefix in 0..=32u8) {
            let range = cidr_range(IpAddr::V4(v4), prefix).unwrap();
            prop_assert_eq!(range.len(), 1u128 << (32 - prefix));
        }

        #[test]
        fn cidr_v6_roundtrip(v6 in any_ipv6(), prefix in 0..=128u8) {
            let range = cidr_range(IpAddr::V6(v6), prefix).unwrap();
            // `/0` saturates; every other prefix is the shift.
            let expected = 1u128.checked_shl(u32::from(128 - prefix)).unwrap_or(u128::MAX);
            prop_assert_eq!(range.len(), expected);
        }
    }
}
