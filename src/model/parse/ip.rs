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
//! | `192.168.1.0/24`, `2001:db8::/64` | a CIDR block |
//! | `10.0.0.1-10.0.0.50` | a range, both ends written out |
//! | `10.0.0.1-50`, `192.168.1.1-2.254` | a range whose end continues the start's octets |
//! | `fe80::1%en0` | a link-local address on a named interface |
//! | `lan` | a keyword, resolved by the caller |
//!
//! The shortened range is IPv4 only: the end is read as however many trailing
//! octets it names, so `10.0.0.1-50` ends at `10.0.0.50` and `192.168.1.1-2.254`
//! at `192.168.2.254`. IPv6 has no comparable form, and inventing one would
//! make `::1-5` ambiguous with hex.
//!
//! ## What it cannot do for itself
//!
//! Resolving `lan` means reading this host's interface table, and resolving
//! `%en0` means looking up a name in it. Both arrive as caller-supplied
//! functions ([`ResolverFn`], [`ZoneResolverFn`]) rather than being called
//! directly, which is what keeps this module free of any knowledge of the
//! machine it runs on. An expression needing a lookup the caller did not supply
//! is **refused**, never silently dropped: a scan that covers less than its
//! input said it covers is a wrong answer that looks like a right one.
//!
//! Hostnames are not resolved here at all. That belongs to
//! [`super::target::TargetMapBuilder`], because whether a name may be looked up
//! is a policy question and this grammar has no business deciding it. An
//! expression that is not any of the forms above comes back as
//! [`IpParseError::Malformed`], which is the signal a caller uses to try a name.

use std::net::IpAddr;
use thiserror::Error;

use crate::model::ip::range::{IpError, IpRange};
use crate::model::ip::set::IpSet;

/// A name standing for a set of addresses only the running host can supply.
///
/// Written in place of an address, and expanded by the caller's
/// [`ResolverFn`]. This module knows the words and nothing about what they
/// resolve to.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keyword {
    /// The local segment: the network on the interface carrying this host's
    /// default route.
    Lan,
}

impl Keyword {
    /// The word as it is written in a target expression.
    pub fn as_str(self) -> &'static str {
        match self {
            Keyword::Lan => "lan",
        }
    }

    /// The keyword `token` is, if it is one.
    ///
    /// Case-insensitive, and the same test [`insert_expression`] applies, so a
    /// caller asking whether its own input names a keyword gets the answer the
    /// parser will act on rather than a second opinion.
    pub fn from_token(token: &str) -> Option<Self> {
        let token = token.trim();
        [Keyword::Lan]
            .into_iter()
            .find(|keyword| token.eq_ignore_ascii_case(keyword.as_str()))
    }
}

/// Whether any of these target expressions names `keyword`.
///
/// A scan of the local segment is a different scan from a scan of the addresses
/// that segment happens to contain: it sends an all-nodes echo and reads the
/// neighbour table, where a targeted run does neither. A caller that offers the
/// `lan` keyword therefore has to know whether it was used, and this answers
/// from the caller's own input rather than from anything the parser remembers.
///
/// Splits on commas the way [`to_set`] does, so `"lan,10.0.0.0/24"` counts.
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
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IpParseError {
    /// The provided CIDR prefix is longer than its address family allows.
    ///
    /// Both bounds are named because the variant carries the prefix and not the
    /// family it was written against, and a reader told only the IPv4 rule after
    /// mistyping an IPv6 prefix is being sent to shorten an address that was
    /// never too long.
    #[error("Invalid CIDR prefix: {0} (0-32 for IPv4, 0-128 for IPv6)")]
    InvalidPrefix(u8),

    /// The start address of a range is numerically higher than the end address.
    #[error("Invalid range: start address {0} is greater than end address {1}")]
    InvalidRange(IpAddr, IpAddr),

    /// The input string does not match any known IP, Range, or CIDR format.
    #[error("Malformed IP or range string: '{0}'")]
    Malformed(String),

    /// Failed to retrieve local interface information for "lan" resolution.
    #[error("Could not resolve LAN interface: {0}")]
    LanError(String),

    /// Wrapper for underlying network library or calculation failures.
    #[error("Network error: {0}")]
    NetworkError(String),

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
/// Supplied by the caller, because answering means reading the host's interface
/// table and this module deliberately knows nothing about the machine it runs
/// on. Writes into the set it is given rather than returning one, so a keyword
/// mixed with literal targets accumulates alongside them.
pub type ResolverFn = fn(Keyword, &mut IpSet) -> Result<(), IpParseError>;

/// Looks up an interface by name and returns its scope id.
///
/// Injected for the same reason [`ResolverFn`] is: resolving a name means
/// reading the host's interface list, and this module deliberately knows nothing
/// about the host it runs on. `None` for a name no interface answers to.
pub type ZoneResolverFn = fn(&str) -> Option<u32>;

/// Resolves a list of address expressions into one [`IpSet`].
///
/// Each element may itself be a comma-separated list, so a single argument and
/// a whole file of targets go through the same call. Surrounding whitespace is
/// trimmed and empty elements are skipped.
///
/// # Errors
///
/// The first expression that does not parse, or [`IpParseError::EmptySet`] if
/// nothing was named, since an empty target set is a caller mistake rather than
/// a scan of nothing.
///
/// # Examples
///
/// ```
/// use zond_engine::model::parse::ip::to_set;
///
/// let set = to_set(&["192.168.1.0/24", "10.0.0.1", "10.0.0.5-10"], None).unwrap();
///
/// // 256 from the block, one literal, six from the range.
/// assert_eq!(set.len(), 263);
/// ```
pub fn to_set<S>(ips: &[S], resolver: Option<ResolverFn>) -> Result<IpSet, IpParseError>
where
    S: AsRef<str>,
{
    to_set_with(ips, resolver, None)
}

/// [`to_set`], additionally able to resolve the `%interface` suffix on a
/// link-local address.
///
/// Separate rather than an extra argument to [`to_set`] so existing callers keep
/// compiling. A caller that does not supply `zones` cannot express a link-local
/// target at all, and gets an error saying so rather than a target set that
/// silently means a different segment.
pub fn to_set_with<S>(
    ips: &[S],
    resolver: Option<ResolverFn>,
    zones: Option<ZoneResolverFn>,
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
/// This is the grammar itself, without the list handling [`to_set_with`] wraps
/// around it. A caller that has already tokenized its input, such as an
/// importer reading a file of targets, wants exactly this: one expression,
/// inserted into a set it is accumulating.
///
/// Nothing is inserted when the expression is refused, so a caller that collects
/// errors and carries on is left with a set holding only what parsed.
///
/// [`IpParseError::Malformed`] is the one error worth treating as a question
/// rather than an answer: it means the expression matches no address, range or
/// CIDR form, which is also what a hostname looks like from here. A caller that
/// accepts hostnames uses it as the signal to try resolving one. Every other
/// error describes an address that is wrong rather than absent.
pub fn insert_expression(
    s: &str,
    set: &mut IpSet,
    resolver: Option<ResolverFn>,
    zones: Option<ZoneResolverFn>,
) -> Result<(), IpParseError> {
    // The interface suffix is stripped first and applied to whatever the rest
    // parses to, so `fe80::1%en0` and `fe80::1-fe80::5%en0` are both expressible
    // and mean the obvious thing.
    if let Some((address, zone)) = s.split_once('%') {
        return parse_scoped(s, address, zone, set, zones);
    }

    if s.contains('/') {
        let range = parse_cidr(s)?;
        set.insert_range(range);
        return Ok(());
    }

    if s.contains('-') {
        let range = parse_range(s)?;
        set.insert_range(range);
        return Ok(());
    }

    if let Some(keyword) = Keyword::from_token(s) {
        let Some(resolve) = resolver else {
            return Err(IpParseError::LanError(format!(
                "the `{}` keyword needs a resolver, and none was supplied",
                keyword.as_str()
            )));
        };
        return resolve(keyword, set);
    }

    let ip = s
        .parse::<IpAddr>()
        .map_err(|_| IpParseError::Malformed(s.to_string()))?;
    set.insert(ip);

    Ok(())
}

/// Parses a target carrying an explicit `%interface` suffix.
///
/// The suffix is only meaningful on a link-local address, and only resolvable by
/// a caller that supplied a lookup. Both failures are reported rather than
/// papered over: an interface nobody recognizes and a zone written on an address
/// with no use for one are each a target that does not mean what it says.
fn parse_scoped(
    original: &str,
    address: &str,
    zone: &str,
    set: &mut IpSet,
    zones: Option<ZoneResolverFn>,
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
    if !v6.start_addr().is_unicast_link_local() {
        return Err(IpParseError::ZoneOnUnscopedTarget(original.to_string()));
    }

    let lookup = zones.ok_or_else(|| IpParseError::UnknownInterface(zone.to_string()))?;
    let index = lookup(zone).ok_or_else(|| IpParseError::UnknownInterface(zone.to_string()))?;

    let scoped =
        crate::model::ip::range::Ipv6Range::scoped(v6.start_addr(), v6.end_addr(), Some(index))
            .map_err(map_range_error)?;
    set.insert_range(IpRange::V6(scoped));
    Ok(())
}

/// Parses a hyphenated range, deferring to the one range grammar.
///
/// Written here as a thin wrapper rather than as a second implementation so
/// that `10.0.0.1-50` cannot mean one thing through this module and fail to
/// parse through [`IpRange::from_str`].
fn parse_range(s: &str) -> Result<IpRange, IpParseError> {
    s.parse::<IpRange>().map_err(|error| match error {
        // "not an address" rather than "a wrong address", which is what tells
        // a caller it may be looking at a hostname.
        IpError::InvalidFormat(_) | IpError::AddrParse(_) | IpError::PrefixParse(_) => {
            IpParseError::Malformed(s.into())
        }
        other => map_range_error(other),
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

    let prefix = prefix_str
        .parse::<u8>()
        .map_err(|_| IpParseError::Malformed(s.into()))?;

    crate::model::ip::range::cidr_range(ip, prefix).map_err(map_range_error)
}

fn map_range_error(e: IpError) -> IpParseError {
    match e {
        IpError::InvalidRange(s, e) => IpParseError::InvalidRange(s, e),
        IpError::InvalidPrefix(p) => IpParseError::InvalidPrefix(p),
        IpError::NetworkError(msg) => IpParseError::NetworkError(msg),
        _ => IpParseError::Malformed("Invalid IP range".into()),
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

    /// Two public entry points read written ranges: this module's, and
    /// [`IpSet`]'s string constructors by way of [`IpRange::from_str`]. They are
    /// the same grammar, and a spelling either accepts the other has to accept
    /// too, or a target file works through one API and silently fails through
    /// the other.
    #[test]
    fn both_ways_into_the_parser_accept_the_same_spellings() {
        for expression in [
            "10.0.0.1-50",
            "192.168.1.1-2.254",
            "10.0.0.1-10.0.0.50",
            "192.168.1.0/24",
            "2001:db8::1-2001:db8::5",
            "8.8.8.8",
        ] {
            let direct = to_set(&[expression], None)
                .unwrap_or_else(|e| panic!("to_set rejected `{expression}`: {e}"));
            let via_set = IpSet::from_str(expression)
                .unwrap_or_else(|e| panic!("IpSet::from_str rejected `{expression}`: {e}"));

            assert_eq!(
                direct.len(),
                via_set.len(),
                "`{expression}` means different things through the two entry points"
            );
        }
    }

    #[test]
    fn to_set_basic_single() {
        let input = vec!["192.168.1.1"];
        let set = to_set(&input, None).expect("Should parse single IP");
        assert_eq!(set.len(), 1);
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn to_set_comma_separated() {
        let input = vec!["10.0.0.1, 10.0.0.2, 10.0.0.5"];
        let set = to_set(&input, None).expect("Should parse comma list");
        assert_eq!(set.len(), 3);
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn parse_cidr_blocks() {
        let input = vec!["172.16.0.0/24"];
        let set = to_set(&input, None).expect("Should parse CIDR");
        assert_eq!(set.len(), 256);
    }

    #[test]
    fn parse_short_range_suffix() {
        let input = vec!["192.168.1.250-2.10"];
        let set = to_set(&input, None).unwrap();
        assert_eq!(set.len(), 17);
    }

    #[test]
    fn error_invalid_cidr() {
        let input = vec!["192.168.1.1/33"];
        let result = to_set(&input, None);
        assert_eq!(result.unwrap_err(), IpParseError::InvalidPrefix(33));
    }

    /// The error carries the prefix and not the family it was written against,
    /// so its message has to name both bounds. Told only the IPv4 rule, whoever
    /// mistyped an IPv6 prefix is sent to shorten an address that was never too
    /// long.
    #[test]
    fn a_prefix_error_names_the_bound_for_both_families() {
        let v6 = to_set(&["2001:db8::/129"], None).unwrap_err();
        assert_eq!(v6, IpParseError::InvalidPrefix(129));
        assert!(v6.to_string().contains("0-128"), "{v6}");

        let v4 = to_set(&["192.168.1.1/33"], None).unwrap_err();
        assert!(v4.to_string().contains("0-32"), "{v4}");
    }

    #[test]
    fn error_invalid_range_order() {
        let input = vec!["10.0.0.10-1"];
        let result = to_set(&input, None);
        assert!(matches!(result, Err(IpParseError::InvalidRange(_, _))));
    }

    /// The interface a link-local target names survives into the target set.
    ///
    /// Without it the address is a question with no answer: every interface
    /// holds an `fe80::/64`, so the scan picks one and probes the wrong segment.
    #[test]
    fn a_link_local_target_keeps_the_interface_it_names() {
        fn zones(name: &str) -> Option<u32> {
            (name == "en0").then_some(7)
        }

        let set = to_set_with(&["fe80::aa%en0"], None, Some(zones)).expect("parses");

        assert_eq!(set.v6().len(), 1);
        assert_eq!(set.v6()[0].zone(), Some(7));
        assert!(!set.v6()[0].is_ambiguous());
    }

    /// The same address without an interface is accepted but marked as the
    /// unanswerable question it is, for the classifier to report.
    #[test]
    fn a_link_local_target_without_an_interface_is_ambiguous() {
        let set = to_set(&["fe80::aa"], None).expect("parses");

        assert!(set.v6()[0].is_ambiguous());
    }

    /// An interface nobody recognizes is a target that does not mean what it
    /// says, and is refused rather than silently stripped of its scope.
    #[test]
    fn an_unknown_interface_is_refused() {
        fn zones(_: &str) -> Option<u32> {
            None
        }

        assert!(matches!(
            to_set_with(&["fe80::aa%wlan9"], None, Some(zones)),
            Err(IpParseError::UnknownInterface(_))
        ));
        assert!(
            matches!(
                to_set(&["fe80::aa%en0"], None),
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
            to_set_with(&["2001:db8::1%en0"], None, Some(zones)),
            Err(IpParseError::ZoneOnUnscopedTarget(_))
        ));
        assert!(matches!(
            to_set_with(&["192.168.1.1%en0"], None, Some(zones)),
            Err(IpParseError::ZoneOnUnscopedTarget(_))
        ));
    }

    #[test]
    fn empty_input_error() {
        let input: Vec<&str> = vec!["", " "];
        let result = to_set(&input, None);
        assert_eq!(result.unwrap_err(), IpParseError::EmptySet);
    }
}
