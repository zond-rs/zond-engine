// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Addresses, as a person writes them
//!
//! The grammar that turns what someone typed into an [`IpSet`]. This is the
//! address half of a target expression; the ports after it are
//! [`super::target`]'s business.
//!
//! ## What it accepts
//!
//! | Written | Means |
//! |---|---|
//! | `127.0.0.1`, `2001:db8::1` | one address |
//! | `192.0.2.0/24`, `2001:db8::/64` | a CIDR block |
//! | `198.51.100.1-198.51.100.50` | a range, both ends written out |
//! | `198.51.100.1-50`, `192.168.1.1-2.254` | a range whose end continues the start's octets |
//! | `fe80::1%en0` | a link-local address on a named interface |
//! | `lan` | a keyword, resolved by the caller |
//!
//! The shortened range is IPv4 only: the end is read as however many trailing
//! octets it names, so `198.51.100.1-50` ends at `198.51.100.50` and
//! `192.168.1.1-2.254` at `192.168.2.254`. IPv6 has no comparable form, and
//! inventing one would make `::1-5` ambiguous with hex.
//!
//! ## An IPv4-mapped address is the IPv4 host it spells
//!
//! `::ffff:192.0.2.1` is how RFC 4291 §2.5.5.2 writes `192.0.2.1` inside an IPv6
//! address; a dual-stack socket handed it connects over IPv4, and no packet carries it.
//! So an address, block or range written wholly inside `::ffff:0:0/96` becomes the IPv4
//! one it spells, as [`Exclusions`](crate::model::exclusion::Exclusions) reads it too.
//! Kept as IPv6 it would be probed as off-link IPv6 and reported apart from the same
//! machine written normally.
//!
//! A range reaching outside the block is kept as written: whoever writes `::/0` means
//! IPv6.
//!
//! ## Lookups are supplied by the caller
//!
//! Resolving `lan` reads this host's interface table, and resolving `%en0` looks up a
//! name in it. Both arrive as caller-supplied functions ([`ResolverFn`],
//! [`ZoneResolverFn`]), so this module knows nothing about the machine. An expression
//! needing a lookup the caller did not supply is **refused**, so a scan never silently
//! covers less than its input said.
//!
//! Hostnames are resolved by [`super::target::TargetMapBuilder`], since whether a name
//! may be looked up is a policy question. An expression matching none of the forms
//! above comes back as [`IpParseError::Malformed`], the signal to try it as a name.

use std::net::IpAddr;
use thiserror::Error;

use crate::model::ip::range::{IpError, IpRange};
use crate::model::ip::set::IpSet;

/// A name standing for a set of addresses only the running host can supply.
///
/// Written in place of an address and expanded by the caller's [`ResolverFn`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keyword {
    /// The local segment: the network on the interface carrying this host's
    /// default route.
    Lan,
}

impl Keyword {
    /// Every keyword this build knows, in declaration order.
    ///
    /// [`from_token`](Self::from_token) and [`names_keyword`] read this list, so a
    /// keyword missing from it would fall through to the address parser, come back
    /// [`Malformed`](IpParseError::Malformed), be looked up in DNS, and never trigger a
    /// segment sweep.
    pub const ALL: &'static [Self] = &[Self::Lan];

    /// The word as it is written in a target expression.
    pub fn as_str(self) -> &'static str {
        match self {
            Keyword::Lan => "lan",
        }
    }

    /// The keyword `token` is, if it is one.
    ///
    /// Case-insensitive, and the same test [`insert_expression`] applies.
    pub fn from_token(token: &str) -> Option<Self> {
        let token = token.trim();
        Self::ALL
            .iter()
            .copied()
            .find(|keyword| token.eq_ignore_ascii_case(keyword.as_str()))
    }
}

/// Whether any of these target expressions names `keyword`.
///
/// A scan of the local segment sends an all-nodes echo and reads the neighbour table,
/// which a scan of the same addresses does not, so a caller offering `lan` needs to
/// know whether it was used.
///
/// Splits on commas the way [`to_set`] does, so `"lan,198.51.100.0/24"` counts.
pub fn names_keyword<S: AsRef<str>>(targets: &[S], keyword: Keyword) -> bool {
    targets.iter().any(|target| {
        target
            .as_ref()
            .split(',')
            .any(|part| Keyword::from_token(part) == Some(keyword))
    })
}

/// Errors encountered during the parsing or resolution of IP-related strings.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IpParseError {
    /// The CIDR prefix is longer than its address family allows.
    ///
    /// The message names both families' bounds, since the variant does not carry the
    /// family.
    ///
    /// A `u32`, so `/999` is reported as a bad prefix. In a `u8` it would be
    /// [`Malformed`](Self::Malformed), which a caller takes as "might be a hostname",
    /// sending a typo to DNS.
    #[error("Invalid CIDR prefix: {0} (0-32 for IPv4, 0-128 for IPv6)")]
    InvalidPrefix(u32),

    /// The start address of a range is numerically higher than the end address.
    #[error("Invalid range: start address {0} is greater than end address {1}")]
    InvalidRange(IpAddr, IpAddr),

    /// The input string does not match any known IP, Range, or CIDR format.
    #[error("Malformed IP or range string: '{0}'")]
    Malformed(String),

    /// A keyword's resolver could not answer.
    ///
    /// Carries the keyword, since [`Keyword`] may grow. The reason is prose from the
    /// caller's resolver.
    #[error("could not resolve `{keyword}`: {reason}")]
    KeywordUnresolved {
        /// The word that could not be expanded.
        keyword: &'static str,
        /// What the caller's resolver said about it.
        reason: String,
    },

    /// The provided input resulted in zero valid IP addresses.
    #[error("Target input resulted in an empty set")]
    EmptySet,

    /// An `%interface` suffix was written on a target that cannot use one.
    #[error("'{0}': only a link-local address is scoped to an interface")]
    ZoneOnUnscopedTarget(String),

    /// An `%interface` suffix named an interface this host does not have, or
    /// none could be looked up at all.
    #[error("No interface named '{0}'")]
    UnknownInterface(String),
}

/// Expands a [`Keyword`] into the addresses it stands for.
///
/// Supplied by the caller, since answering reads the host's interface table. Writes into
/// the set it is given, so a keyword mixed with literal targets accumulates alongside
/// them.
///
/// A borrowed `dyn Fn`, so a resolver may close over state such as an interface table
/// read once; it stays `Copy`, so [`TargetContext`](super::target::TargetContext) does
/// too.
///
/// `Sync`, so a `&` to one is `Send` and a caller can hold the context across an await
/// in a spawned task.
pub type ResolverFn<'a> = &'a (dyn Fn(Keyword, &mut IpSet) -> Result<(), IpParseError> + Sync);

/// Looks up an interface by name and returns its scope id.
///
/// Supplied by the caller, like [`ResolverFn`], and `Sync` for the same reason. `None`
/// for a name no interface answers to.
pub type ZoneResolverFn<'a> = &'a (dyn Fn(&str) -> Option<u32> + Sync);

/// Resolves a list of address expressions into one [`IpSet`].
///
/// Each element may itself be a comma-separated list, so a single argument and
/// a whole file of targets go through the same call. Surrounding whitespace is
/// trimmed and empty elements are skipped.
///
/// # Errors
///
/// The first expression that does not parse, or [`IpParseError::EmptySet`] if nothing
/// was named.
///
/// Without `zones`, a zoned link-local target fails with
/// [`IpParseError::UnknownInterface`].
///
/// # Examples
///
/// ```
/// use zond_engine::model::parse::ip::to_set;
///
/// let set = to_set(&["192.0.2.0/24", "198.51.100.1", "198.51.100.5-10"], None, None).unwrap();
///
/// // 256 from the block, one literal, six from the range.
/// assert_eq!(set.len(), 263);
/// ```
pub fn to_set<S>(
    ips: &[S],
    resolver: Option<ResolverFn<'_>>,
    zones: Option<ZoneResolverFn<'_>>,
) -> Result<IpSet, IpParseError>
where
    S: AsRef<str>,
{
    let mut set = IpSet::new();

    for ip in ips {
        let s = ip.as_ref().trim();
        if s.is_empty() {
            continue;
        }

        for part in s.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
            insert_expression(part, &mut set, resolver, zones)?;
        }
    }

    if set.is_empty() {
        return Err(IpParseError::EmptySet);
    }

    Ok(set)
}

/// Identifies the format of a single address expression and inserts it into an
/// existing set.
///
/// The grammar without [`to_set`]'s list handling, for a caller that has already
/// tokenized its input, such as an importer reading a file of targets.
///
/// Nothing is inserted when the expression is refused.
///
/// [`IpParseError::Malformed`] means the expression matches no address, range or CIDR
/// form, which is also what a hostname looks like; a caller accepting hostnames tries
/// resolving one. Every other error describes a wrong address.
pub fn insert_expression(
    s: &str,
    set: &mut IpSet,
    resolver: Option<ResolverFn<'_>>,
    zones: Option<ZoneResolverFn<'_>>,
) -> Result<(), IpParseError> {
    // Trimmed here too, for direct callers: `Keyword::from_token` trims but
    // `IpAddr::from_str` does not, so ` 198.51.100.1 ` would otherwise come back
    // malformed and be tried as a hostname.
    let s = s.trim();

    // The suffix applies to whatever the rest parses to, so `fe80::1%en0` and
    // `fe80::1-fe80::5%en0` both work.
    if let Some((address, zone)) = s.split_once('%') {
        return parse_scoped(s, address, zone, set, zones);
    }

    if s.contains('/') {
        let range = parse_cidr(s)?;
        set.insert_range(as_hosts(range));
        return Ok(());
    }

    if s.contains('-') {
        let range = parse_range(s)?;
        set.insert_range(as_hosts(range));
        return Ok(());
    }

    if let Some(keyword) = Keyword::from_token(s) {
        let Some(resolve) = resolver else {
            return Err(IpParseError::KeywordUnresolved {
                keyword: keyword.as_str(),
                reason: "no resolver was supplied to expand it".to_string(),
            });
        };
        return resolve(keyword, set);
    }

    let ip = s
        .parse::<IpAddr>()
        .map_err(|_| IpParseError::Malformed(s.to_string()))?;
    set.insert(ip.to_canonical());

    Ok(())
}

/// `range` as the hosts it names: a range written wholly inside the
/// IPv4-mapped block is the IPv4 range it spells, and anything else is itself.
/// See the module documentation.
fn as_hosts(range: IpRange) -> IpRange {
    match range {
        IpRange::V6(v6) => v6.spelled_ipv4().map_or(range, IpRange::V4),
        IpRange::V4(_) => range,
    }
}

/// Parses a target carrying an explicit `%interface` suffix.
///
/// The suffix is only meaningful on a link-local address, and only resolvable with a
/// caller-supplied lookup. Both failures are reported.
fn parse_scoped(
    original: &str,
    address: &str,
    zone: &str,
    set: &mut IpSet,
    zones: Option<ZoneResolverFn<'_>>,
) -> Result<(), IpParseError> {
    if zone.is_empty() {
        return Err(IpParseError::Malformed(original.to_string()));
    }

    let range = address
        .parse::<IpRange>()
        .map_err(|_| IpParseError::Malformed(original.to_string()))?;
    let IpRange::V6(v6) = range else {
        return Err(IpParseError::ZoneOnUnscopedTarget(original.to_string()));
    };
    // The whole range must be link-local; checking only the start would accept
    // `fe80::1-fec0::1` and refuse `fe00::1-fe80::5`.
    if !v6.is_link_local() {
        return Err(IpParseError::ZoneOnUnscopedTarget(original.to_string()));
    }

    // Zero is what a name lookup returns for no such name. Refused here, the one
    // place that still holds the name to report.
    let lookup = zones.ok_or_else(|| IpParseError::UnknownInterface(zone.to_string()))?;
    let index = lookup(zone)
        .filter(|index| *index != 0)
        .ok_or_else(|| IpParseError::UnknownInterface(zone.to_string()))?;

    let scoped =
        crate::model::ip::range::Ipv6Range::scoped(v6.start_addr(), v6.end_addr(), Some(index))
            .map_err(|e| map_range_error(original, e))?;
    set.insert_range(IpRange::V6(scoped));
    Ok(())
}

/// Parses a hyphenated range, deferring to the one range grammar.
///
/// A thin wrapper, so ranges parse the same here as through [`IpRange`]'s `from_str`.
fn parse_range(s: &str) -> Result<IpRange, IpParseError> {
    s.parse::<IpRange>().map_err(|error| match error {
        // "Not an address", which tells a caller it may be a hostname.
        IpError::InvalidFormat(_) | IpError::AddrParse(_) | IpError::PrefixParse(_) => {
            IpParseError::Malformed(s.into())
        }
        other => map_range_error(s, other),
    })
}

/// Parses CIDR notation strings into an [`IpRange`].
fn parse_cidr(s: &str) -> Result<IpRange, IpParseError> {
    let (ip_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| IpParseError::Malformed(s.into()))?;

    let ip = ip_str
        .parse::<IpAddr>()
        .map_err(|_| IpParseError::Malformed(s.into()))?;

    // Read as a `u32`, so a huge number is a bad prefix, not an unrecognised
    // token that would be tried as a hostname.
    let prefix = prefix_str
        .parse::<u32>()
        .map_err(|_| IpParseError::Malformed(s.into()))?;
    let prefix = u8::try_from(prefix).map_err(|_| IpParseError::InvalidPrefix(prefix))?;

    crate::model::ip::range::cidr_range(ip, prefix).map_err(|e| map_range_error(s, e))
}

/// Restates a range error in this module's vocabulary, against the expression
/// the caller wrote.
///
/// `original` is passed in so the error quotes what the caller wrote.
fn map_range_error(original: &str, e: IpError) -> IpParseError {
    match e {
        IpError::InvalidRange(s, e) => IpParseError::InvalidRange(s, e),
        IpError::InvalidPrefix(p) => IpParseError::InvalidPrefix(u32::from(p)),
        _ => IpParseError::Malformed(original.to_string()),
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
    use std::str::FromStr;

    /// This module and [`IpSet`]'s string constructors (via [`IpRange::from_str`]) are
    /// one grammar and accept the same spellings.
    ///
    /// They differ in one reading: this module reads an IPv4-mapped address as the
    /// host it names, where an [`IpSet`] keeps the value it was given. See
    /// `a_mapped_address_is_read_as_the_ipv4_host_it_spells`.
    #[test]
    fn both_ways_into_the_parser_accept_the_same_spellings() {
        for expression in [
            "198.51.100.1-50",
            "192.168.1.1-2.254",
            "198.51.100.1-198.51.100.50",
            "192.0.2.0/24",
            "2001:db8::1-2001:db8::5",
            "8.8.8.8",
            // Spellings most easily read differently.
            "198.51.100.0-0",
            "  198.51.100.1  ",
        ] {
            let direct = to_set(&[expression], None, None)
                .unwrap_or_else(|e| panic!("to_set rejected `{expression}`: {e}"));
            let via_set = IpSet::from_str(expression)
                .unwrap_or_else(|e| panic!("IpSet::from_str rejected `{expression}`: {e}"));

            assert_eq!(
                direct, via_set,
                "`{expression}` means different things through the two entry points"
            );
        }
    }

    /// An address written the IPv4-mapped way is read as the IPv4 host it
    /// spells, in every form the grammar has.
    ///
    /// Kept as IPv6, a frame for it would go to the router as off-link IPv6.
    #[test]
    fn a_mapped_address_is_read_as_the_ipv4_host_it_spells() {
        for (mapped, plain) in [
            ("::ffff:192.0.2.1", "192.0.2.1"),
            ("::ffff:127.0.0.1", "127.0.0.1"),
            ("::ffff:192.0.2.0/120", "192.0.2.0/24"),
            ("::ffff:192.0.2.1-::ffff:192.0.2.9", "192.0.2.1-192.0.2.9"),
            ("::ffff:0:0/96", "0.0.0.0/0"),
        ] {
            assert_eq!(
                to_set(&[mapped], None, None).expect("parses"),
                to_set(&[plain], None, None).expect("parses"),
                "`{mapped}`"
            );
        }
    }

    /// A range reaching outside the mapped block, such as `::/0`, is kept as written.
    #[test]
    fn a_range_that_only_overlaps_the_mapped_block_is_kept_as_written() {
        for written in ["::/0", "::fffe:ffff:ffff-::ffff:0:5"] {
            let set = to_set(&[written], None, None).expect("parses");
            assert!(set.v4().is_empty(), "`{written}` gained IPv4");
            assert_eq!(set, IpSet::from_str(written).expect("parses"));
        }
    }

    /// A single address.
    #[test]
    fn a_single_literal_address_becomes_a_set_of_one() {
        let input = vec!["192.0.2.1"];
        let set = to_set(&input, None, None).expect("Should parse single IP");
        assert_eq!(set.len(), 1);
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    }

    /// One argument may itself be a comma-separated list.
    #[test]
    fn one_argument_may_name_several_addresses() {
        let input = vec!["198.51.100.1, 198.51.100.2, 198.51.100.5"];
        let set = to_set(&input, None, None).expect("Should parse comma list");
        assert_eq!(set.len(), 3);
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
    }

    /// A block counts every address it covers.
    #[test]
    fn a_cidr_block_covers_every_address_in_it() {
        let input = vec!["203.0.113.0/24"];
        let set = to_set(&input, None, None).expect("Should parse CIDR");
        assert_eq!(set.len(), 256);
    }

    /// The shorthand crosses an octet boundary: `.250-2.10` is seventeen addresses.
    #[test]
    fn a_shortened_range_end_continues_the_starts_octets() {
        let input = vec!["192.168.1.250-2.10"];
        let set = to_set(&input, None, None).unwrap();
        assert_eq!(set.len(), 17);
    }

    /// A prefix too long for its family is refused, not clamped.
    #[test]
    fn a_prefix_longer_than_its_family_allows_is_refused() {
        let input = vec!["192.0.2.1/33"];
        let result = to_set(&input, None, None);
        assert_eq!(result.unwrap_err(), IpParseError::InvalidPrefix(33));
    }

    /// `/999` is reported as an invalid prefix, like `/33`, not as
    /// [`Malformed`](IpParseError::Malformed), which would send it to DNS.
    #[test]
    fn a_prefix_too_large_for_a_u8_is_still_a_prefix() {
        let too_large = to_set(&["198.51.100.0/999"], None, None).unwrap_err();
        assert_eq!(too_large, IpParseError::InvalidPrefix(999));
        assert!(too_large.to_string().contains("0-32"), "{too_large}");

        // Text that is not a number stays malformed, so a hostname reaches DNS.
        assert!(matches!(
            to_set(&["198.51.100.0/wide"], None, None),
            Err(IpParseError::Malformed(_))
        ));
    }

    /// The message names both families' bounds.
    #[test]
    fn a_prefix_error_names_the_bound_for_both_families() {
        let v6 = to_set(&["2001:db8::/129"], None, None).unwrap_err();
        assert_eq!(v6, IpParseError::InvalidPrefix(129));
        assert!(v6.to_string().contains("0-128"), "{v6}");

        let v4 = to_set(&["192.0.2.1/33"], None, None).unwrap_err();
        assert!(v4.to_string().contains("0-32"), "{v4}");
    }

    /// A backwards range is reported, not read as an empty set.
    #[test]
    fn a_range_written_backwards_is_refused() {
        let input = vec!["198.51.100.10-1"];
        let result = to_set(&input, None, None);
        assert!(matches!(result, Err(IpParseError::InvalidRange(_, _))));
    }

    /// The interface a link-local target names survives into the target set.
    ///
    /// Every interface holds an `fe80::/64`, so without it the scan could probe the
    /// wrong segment.
    #[test]
    fn a_link_local_target_keeps_the_interface_it_names() {
        fn zones(name: &str) -> Option<u32> {
            (name == "en0").then_some(7)
        }

        let set = to_set(&["fe80::aa%en0"], None, Some(&zones)).expect("parses");

        assert_eq!(set.v6().len(), 1);
        assert_eq!(set.v6()[0].zone(), Some(7));
        assert!(!set.v6()[0].is_ambiguous());
    }

    /// The same address without an interface is accepted but marked ambiguous, for the
    /// classifier to report.
    #[test]
    fn a_link_local_target_without_an_interface_is_ambiguous() {
        let set = to_set(&["fe80::aa"], None, None).expect("parses");

        assert!(set.v6()[0].is_ambiguous());
    }

    /// A resolver answering zero has not answered: zero means no such interface. Taken
    /// at face value it would build a range that reads as scoped, hiding the problem
    /// from `is_ambiguous`, and probes would go out on whichever link the kernel
    /// picked.
    #[test]
    fn a_resolver_that_answers_zero_has_not_found_an_interface() {
        fn zones(_: &str) -> Option<u32> {
            Some(0)
        }

        assert!(matches!(
            to_set(&["fe80::aa%en0"], None, Some(&zones)),
            Err(IpParseError::UnknownInterface(name)) if name == "en0"
        ));
    }

    /// [`insert_expression`] trims the token itself, so keywords and addresses behave
    /// alike whatever whitespace a direct caller leaves.
    #[test]
    fn an_untrimmed_token_reads_the_same_as_a_trimmed_one() {
        let mut set = IpSet::new();
        insert_expression(" 198.51.100.1 ", &mut set, None, None).expect("an address with space");
        insert_expression("\t192.0.2.0/24\n", &mut set, None, None).expect("a block with space");
        insert_expression(" 198.51.100.5-10 ", &mut set, None, None).expect("a range with space");

        assert_eq!(set.len(), 1 + 256 + 6);

        fn keywords(_: Keyword, set: &mut IpSet) -> Result<(), IpParseError> {
            set.insert("203.0.113.1".parse().expect("an address"));
            Ok(())
        }
        let mut keyword = IpSet::new();
        insert_expression(" lan ", &mut keyword, Some(&keywords), None).expect("a keyword");
        assert_eq!(
            keyword.len(),
            1,
            "which already worked, and is the half it matched"
        );
    }

    /// An unknown interface is refused, not silently stripped.
    #[test]
    fn an_unknown_interface_is_refused() {
        fn zones(_: &str) -> Option<u32> {
            None
        }

        assert!(matches!(
            to_set(&["fe80::aa%wlan9"], None, Some(&zones)),
            Err(IpParseError::UnknownInterface(_))
        ));
        assert!(
            matches!(
                to_set(&["fe80::aa%en0"], None, None),
                Err(IpParseError::UnknownInterface(_))
            ),
            "a caller with no lookup cannot express a scoped target and must be told"
        );
    }

    /// A scope on an address that cannot use one is a mistake, not a hint.
    #[test]
    fn a_zone_on_a_global_target_is_refused() {
        fn zones(_: &str) -> Option<u32> {
            Some(7)
        }

        assert!(matches!(
            to_set(&["2001:db8::1%en0"], None, Some(&zones)),
            Err(IpParseError::ZoneOnUnscopedTarget(_))
        ));
        assert!(matches!(
            to_set(&["192.0.2.1%en0"], None, Some(&zones)),
            Err(IpParseError::ZoneOnUnscopedTarget(_))
        ));
    }

    /// Nothing to scan is an error: an empty set would look like a scan that found no
    /// hosts.
    #[test]
    fn input_naming_no_addresses_is_an_error() {
        let input: Vec<&str> = vec!["", " "];
        let result = to_set(&input, None, None);
        assert_eq!(result.unwrap_err(), IpParseError::EmptySet);
    }
}
