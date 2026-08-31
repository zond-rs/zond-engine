// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Contiguous runs of addresses
//!
//! A range is two addresses and everything between them, inclusive at both
//! ends. It is how this engine holds a `/24` or a `/8` without holding the
//! addresses themselves. It is the unit [`IpSet`](super::set::IpSet) is built
//! out of, and the reason a target set naming sixteen million addresses costs
//! two words.
//!
//! [`Ipv4Range`] and [`Ipv6Range`] are separate rather than one type over
//! `IpAddr` because the arithmetic differs in kind: a v4 range is 8 bytes and
//! its length always fits a `u64`, a v6 range is 32 and its length can exceed
//! what a `u128` holds. [`IpRange`] is the enum over the two, for callers that
//! do not care which family they were handed.
//!
//! The two families are never comparable. A v4 address is not in a v6 range
//! whatever the numbers say, and `::ffff:10.0.0.1` is an IPv6 address here even
//! though it names an IPv4 one. Membership across families is `false` rather
//! than an error, because the callers are filtering received packets and a
//! packet of the wrong family is simply not one they asked about.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use thiserror::Error;

/// Why a range could not be built or read.
///
/// The distinction [`parse::ip`](crate::model::parse::ip) depends on runs
/// through these: [`InvalidFormat`](Self::InvalidFormat),
/// [`AddrParse`](Self::AddrParse) and [`PrefixParse`](Self::PrefixParse) mean
/// "this is not a range", which is also what a hostname looks like from here,
/// while the other two mean "this is a range, and it is wrong".
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IpError {
    /// The start address is above the end. Both are named, since which of the
    /// two was mistyped is the reader's to work out.
    #[error("Invalid range: start address {0} is greater than end address {1}")]
    InvalidRange(IpAddr, IpAddr),

    /// A CIDR prefix longer than its family allows.
    ///
    /// The bound is not in the message because this type does not carry the
    /// family it was written against;
    /// [`IpParseError::InvalidPrefix`](crate::model::parse::ip::IpParseError::InvalidPrefix)
    /// is the one a user reads, and it names both.
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
/// Eight bytes, whatever the range covers. The start is never above the end,
/// which [`new`](Self::new) is the only way to construct one in order to
/// guarantee: an inverted range has a length that cannot be represented and
/// yields nothing when iterated, so the two would disagree about what it holds.
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
    /// Infallible, because one address is trivially in order with itself. That
    /// is what keeps the callers that hold one address from writing
    /// `new(addr, addr).unwrap()` and teaching a reader that constructing a
    /// range can panic.
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
    /// The only mutation a range allows, and the one merging adjacent ranges
    /// needs. Growing the end cannot put it below the start, so the ordering
    /// invariant survives without a check.
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
    /// There is no `is_empty`: both bounds are inclusive and
    /// [`new`](Self::new) refuses an inverted range, so a range always holds at
    /// least one address and the answer would be `false` every time it was
    /// asked. [`IpSet::is_empty`](crate::model::ip::set::IpSet::is_empty) next
    /// door means something real, which is exactly what makes an always-false
    /// one here a trap.
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
    /// The index alone rather than the whole
    /// [`Zone`](crate::model::ip::scoped::Zone), so this type stays
    /// `Copy`: a scan expands ranges into millions of targets, and the index is
    /// all a socket ever needs. The interface *name* is a display concern and
    /// belongs where a person reads the output.
    ///
    /// `None` for every range that does not need one, which is all of them
    /// except link-local. See
    /// [`ScopedIp`](crate::model::ip::scoped::ScopedIp) for why an
    /// address that needs a zone and lacks one cannot be probed at all.
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
    /// `Some(0)` is read as `None`, for the reason
    /// [`Zone::new`](crate::model::ip::scoped::Zone::new) gives: zero is what a
    /// name lookup returns when there is no such interface, so a range carrying
    /// it names no segment. Kept as `Some(0)` it would read as scoped, which is
    /// the one answer that stops [`is_ambiguous`](Self::is_ambiguous) saying so.
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
    /// A range spanning link-local addresses without a zone cannot be probed:
    /// every interface holds an `fe80::/64`, so there is no way to tell which
    /// segment was meant, and picking one is a guess a scan must not make
    /// silently.
    ///
    /// True where *any* of the range is link-local, which is the direction a
    /// safety question has to fail in. It used to ask
    /// `start_addr.is_unicast_link_local()`, and a range is two addresses where
    /// that predicate takes one: `fe00::-fe80::5` covers link-local space,
    /// starts outside it, and reached `system::interface::routing`'s
    /// `owning_interface` as though its segment were knowable.
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
    /// What a `%zone` suffix needs to be true of the thing it is written on. A
    /// zone on a range only partly link-local is meaningful for that part and
    /// meaningless for the rest, which is a target that does not mean what it
    /// says.
    pub fn is_link_local(&self) -> bool {
        u128::from(self.start_addr) >= LINK_LOCAL_FIRST
            && u128::from(self.end_addr) <= LINK_LOCAL_LAST
    }

    /// Returns an iterator over every [`IpAddr`] within the range.
    ///
    /// # Warning
    ///
    /// IPv6 ranges can be astronomically large. Iterating over a typical CIDR (like a /64)
    /// will take millions of years. This method is provided for small, manually
    /// defined ranges.
    pub fn iter(&self) -> impl Iterator<Item = IpAddr> {
        let start: u128 = self.start_addr.into();
        let end: u128 = self.end_addr.into();
        (start..=end).map(|ip| IpAddr::V6(Ipv6Addr::from(ip)))
    }

    /// Checks if the given [`Ipv6Addr`] falls within this range (inclusive).
    ///
    /// Blind to the zone, like [`IpSet::contains`](super::set::IpSet::contains)
    /// above it: a received packet carries a bare address with no interface
    /// attached to compare against.
    pub fn contains(&self, ip: &Ipv6Addr) -> bool {
        (u128::from(self.start_addr)..=u128::from(self.end_addr)).contains(&u128::from(*ip))
    }

    /// How many addresses the range covers, never fewer than one. See
    /// [`Ipv4Range::len`] for why there is no `is_empty` beside it.
    ///
    /// `::/0` covers 2^128 addresses, which is one more than a `u128` can hold,
    /// so the count saturates at [`u128::MAX`]. That is an undercount of one
    /// address in the single case where the range is the entire address space -
    /// a quantity no caller can act on differently at either value, and the only
    /// alternative to a wrapping subtraction that reports the whole of IPv6 as
    /// *nothing*. A budget check is the main reader of this, and reporting zero
    /// would wave through precisely the target it exists to stop.
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
/// Written out because that predicate takes one address and a range is two, so
/// asking it about either end says nothing about what lies between them. The
/// test beside them checks the two agree at all four boundaries, which is what
/// keeps these from being a second opinion about where link-local space is.
const LINK_LOCAL_FIRST: u128 = 0xfe80 << 112;
const LINK_LOCAL_LAST: u128 = (0xfebf << 112) | ((1u128 << 112) - 1);

// ══════════════════════════════════════════════════════════════════════════════
// Unified IpRange API
// ══════════════════════════════════════════════════════════════════════════════

/// Either family's range, for a caller that does not care which it was handed.
///
/// What [`FromStr`] produces, since the text decides the family and the caller
/// writing it usually has no reason to branch on the answer.
///
/// The one public enum in [`model`](crate::model) without `#[non_exhaustive]`.
/// There is no third address family to add, so a caller
/// matching both arms is writing something exhaustive that will stay
/// exhaustive, and the marker's whole effect would be to take away the compile
/// error if that ever stopped being true. The same argument
/// [`diff::change::Presence`](crate::diff::change::Presence) is left open on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpRange {
    /// An IPv4 address range.
    V4(Ipv4Range),
    /// An IPv6 address range.
    V6(Ipv6Range),
}

impl IpRange {
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
    /// - CIDR notation: `192.168.1.0/24`, `2001:db8::/32`
    /// - Hyphenated ranges: `10.0.0.1-10.0.0.5`, `::1-::f`
    /// - Shortened IPv4 ranges, where the end continues the start's octets:
    ///   `10.0.0.1-50`, `192.168.1.1-2.254`
    /// - Single IPs: `1.1.1.1`, `::1`
    ///
    /// This is the whole of the range grammar. Everything in the crate that
    /// reads a written range ends here, so no two entry points can accept
    /// different spellings of the same thing.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        // Handle CIDR
        if let Some(pos) = s.find('/') {
            let ip = s[..pos].parse::<IpAddr>()?;
            let prefix = s[pos + 1..].parse::<u8>()?;
            return cidr_range(ip, prefix);
        }

        // Handle hyphenated range
        if let Some(pos) = s.find('-') {
            // Not trimmed around the separator, so `10.0.0.1 - 10.0.0.5` is not
            // a range here either. It was, and nothing that reads a written
            // range through this crate could express it: `IpSet` splits its
            // input on spaces as well as commas, so that spelling arrived as
            // three tokens and the middle one was a bare `-`. The module
            // documentation above claims one grammar with no second dialect, and
            // this was the second dialect.
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

        // Handle single IP
        match s.parse::<IpAddr>()? {
            IpAddr::V4(v4) => Ok(IpRange::V4(Ipv4Range::single(v4))),
            IpAddr::V6(v6) => Ok(IpRange::V6(Ipv6Range::single(v6))),
        }
    }
}

/// Reads the end of an IPv4 range, which may be written in full or as however
/// many trailing octets differ from the start.
///
/// `10.0.0.1-50` ends at `10.0.0.50` and `192.168.1.1-2.254` at
/// `192.168.2.254`: the octets given replace the same number of octets at the
/// end of the start address. A shorthand exists because the alternative is
/// writing an address twice to name a range within one subnet, which is the
/// common case.
///
/// IPv4 only. IPv6 has no comparable form, and inventing one would make `::1-5`
/// ambiguous with an address whose last group is hex.
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
/// `u8::from_str` is not that: it takes a leading `+` and a leading zero, where
/// `Ipv4Addr::from_str` has refused a leading zero since 1.53 because `010` is
/// octal to enough software to matter. Reading the two halves of one range with
/// two grammars meant `010.0.0.50` was refused as a start and accepted as an
/// end, which is the ambiguity the address parser rejects it for arriving by the
/// other door. In a scanner the addresses a range covers are the machines that
/// receive packets.
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
/// let range = cidr_range("192.168.1.5".parse().unwrap(), 24).unwrap();
/// assert_eq!(range.len(), 256);
/// ```
pub fn cidr_range(ip: IpAddr, prefix: u8) -> Result<IpRange, IpError> {
    match ip {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return Err(IpError::InvalidPrefix(prefix));
            }

            // No special case for a zero prefix: `checked_shr(0)` is the whole
            // mask, whose complement is no mask, which is what `/0` means. The
            // branch that used to be here could not change an answer, and both
            // property tests below start at 1, so it was never reached either.
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

    /// Both bounds are inclusive, so the edges are the cases worth writing
    /// down: the property tests below establish that a range holds its own
    /// endpoints, and these establish that it holds nothing beyond them. An
    /// off-by-one here scans an address nobody asked about, or misses one they
    /// did.
    #[test]
    fn a_range_holds_both_its_bounds_and_nothing_outside_them() {
        let v4 =
            Ipv4Range::new(Ipv4Addr::new(172, 16, 0, 10), Ipv4Addr::new(172, 16, 0, 20)).unwrap();
        assert!(v4.contains(&Ipv4Addr::new(172, 16, 0, 10)));
        assert!(v4.contains(&Ipv4Addr::new(172, 16, 0, 20)));
        assert!(!v4.contains(&Ipv4Addr::new(172, 16, 0, 9)));
        assert!(!v4.contains(&Ipv4Addr::new(172, 16, 0, 21)));

        let v6 = Ipv6Range::new(Ipv6Addr::from(100), Ipv6Addr::from(200)).unwrap();
        assert_eq!(v6.len(), 101, "inclusive at both ends");
        assert!(v6.contains(&Ipv6Addr::from(100)));
        assert!(v6.contains(&Ipv6Addr::from(200)));
        assert!(!v6.contains(&Ipv6Addr::from(201)));
    }

    /// The ends of each address space, where the arithmetic that counts a range
    /// is one step from overflowing.
    ///
    /// `::/0` is the case the type cannot represent exactly: 2^128 addresses is
    /// one more than a `u128` holds, so the count saturates. The undercount of
    /// one beats the alternative, a wrapping subtraction reporting the whole of
    /// IPv6 as nothing, where a budget check reading zero would wave through the
    /// target it exists to stop.
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

    /// Ascending, with no address skipped or repeated. The order is what a scan
    /// walks, so two runs over one target list probe in the same sequence, and
    /// the values rather than the count are what the property tests below leave
    /// unpinned.
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
    /// This is the whole of what a written range can mean, and everything in the
    /// crate that reads one ends here, so a spelling that stops working stops
    /// working for target files, imported reports and command lines at once.
    #[test]
    fn every_written_form_names_the_range_it_says_it_does() {
        for (written, first, last) in [
            ("8.8.8.8", "8.8.8.8", "8.8.8.8"),
            ("10.0.0.0/24", "10.0.0.0", "10.0.0.255"),
            ("192.168.1.5/24", "192.168.1.0", "192.168.1.255"),
            ("1.1.1.1-1.1.1.5", "1.1.1.1", "1.1.1.5"),
            ("10.0.0.1-50", "10.0.0.1", "10.0.0.50"),
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
    /// The end of a shortened range was read by `u8::from_str` where the start
    /// was read by `Ipv4Addr::from_str`, and the two disagree about a leading
    /// zero: the address parser has refused it since 1.53 because `010` is octal
    /// to enough software to matter, and the integer parser takes it, along with
    /// a leading `+`. So one token was read by two grammars, and the spelling
    /// refused on the left of the hyphen was accepted on the right.
    #[test]
    fn both_halves_of_a_range_read_octets_the_same_way() {
        for spelling in [
            "010.0.0.1",         // as a start
            "10.0.0.1-010",      // and as an end
            "10.0.0.1-0.0.0.50", // in a longer suffix
            "10.0.0.1-+50",      // a sign is not an octet either
            "10.0.0.1- 50",      // nor is one with space around it
        ] {
            assert!(
                spelling.parse::<IpRange>().is_err(),
                "`{spelling}` was read as a range"
            );
        }

        // A single zero is a zero, and the forms that always worked still do.
        for (spelling, last) in [
            ("10.0.0.0-0", "10.0.0.0"),
            ("10.0.0.1-50", "10.0.0.50"),
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
    /// `IpRange::from_str` trimmed around the separator and `IpSet::from_str`
    /// splits its input on spaces as well as commas, so `10.0.0.1 - 10.0.0.5`
    /// was a range through one entry point and three tokens through the other.
    /// The module documentation says there is one grammar and no two entry
    /// points that accept different spellings of the same thing.
    #[test]
    fn a_range_written_with_spaces_is_not_a_range() {
        assert!("10.0.0.1 - 10.0.0.5".parse::<IpRange>().is_err());
        assert!("10.0.0.1 -10.0.0.5".parse::<IpRange>().is_err());

        // The whole token is still trimmed, which is a different question: a
        // caller that split a file on newlines has trailing whitespace and no
        // second dialect.
        let padded: IpRange = "  10.0.0.1-10.0.0.5  ".parse().expect("trimmed as a whole");
        assert_eq!(padded.len(), 5);
    }

    /// The link-local bounds agree with the predicate std answers for one
    /// address, at all four edges.
    ///
    /// They are a second opinion about where `fe80::/10` sits, and the only
    /// thing that keeps a second opinion honest is checking it against the
    /// first. Written out because a range is two addresses and the predicate
    /// takes one.
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
    /// `is_ambiguous` asked `start_addr.is_unicast_link_local()`, so a range
    /// that runs into link-local space from below was not ambiguous and went to
    /// `owning_interface` as though its segment were knowable, and one that runs
    /// out of it from within was ambiguous along its whole length. The two
    /// questions are also not the same question: covering *some* link-local
    /// space is what makes a range ambiguous, and covering *only* link-local
    /// space is what a `%zone` suffix needs.
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

        // Entirely inside, which is what a zone may be written on.
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
    /// `is_ambiguous` is what a caller asks before deciding a link-local range
    /// can be attributed to a segment, and it reads the zone. A `Some(0)` left
    /// as written made the range look answered, so the question the classifier
    /// exists to ask was never asked.
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

    /// `new` is the only way to build a range, so the ordering it checks is a
    /// property of every range that exists. Without that, an inverted one is
    /// constructible and disagrees with itself: `len` cannot represent a
    /// negative count and `iter` yields nothing, so a budget check and a scan
    /// read the same value differently.
    #[test]
    fn a_range_can_only_be_built_in_order() {
        let low = Ipv4Addr::new(10, 0, 0, 1);
        let high = Ipv4Addr::new(10, 0, 0, 5);

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

    /// The one mutation a range allows. It only ever grows the end, which is
    /// what keeps it unable to invert the range it is called on.
    #[test]
    fn extending_a_range_never_inverts_it() {
        let mut range =
            Ipv4Range::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 5)).unwrap();

        range.extend_end_to(Ipv4Addr::new(10, 0, 0, 9));
        assert_eq!(range.end_addr(), Ipv4Addr::new(10, 0, 0, 9));

        // A shorter end is not an instruction to shrink.
        range.extend_end_to(Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(range.end_addr(), Ipv4Addr::new(10, 0, 0, 9));
        assert!(range.end_addr() >= range.start_addr());
        assert_eq!(range.iter().count() as u64, range.len());
    }

    /// These messages are printed at whoever mistyped a target, so they have to
    /// name the value that was wrong rather than only the rule it broke.
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

        /// From zero, which the ranges used to start at one to avoid: the
        /// assertion could not write `1 << 128`, so the case the implementation
        /// special-cased was the case neither generator reached.
        #[test]
        fn cidr_v4_roundtrip(v4 in any_ipv4(), prefix in 0..=32u8) {
            let range = cidr_range(IpAddr::V4(v4), prefix).unwrap();
            prop_assert_eq!(range.len(), 1u128 << (32 - prefix));
        }

        #[test]
        fn cidr_v6_roundtrip(v6 in any_ipv6(), prefix in 0..=128u8) {
            let range = cidr_range(IpAddr::V6(v6), prefix).unwrap();
            // `/0` is the whole space, which is one more address than a `u128`
            // counts and is what `len` saturates for; every other prefix is the
            // shift.
            let expected = 1u128.checked_shl(u32::from(128 - prefix)).unwrap_or(u128::MAX);
            prop_assert_eq!(range.len(), expected);
        }
    }
}
