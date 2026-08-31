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
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IpParseError {
    /// The CIDR prefix is longer than its address family allows.
    ///
    /// Both bounds are named because the variant carries the prefix and not the
    /// family it was written against, and a reader told only the IPv4 rule after
    /// mistyping an IPv6 prefix is being sent to shorten an address that was
    /// never too long.
    ///
    /// Wider than the `u8` a prefix fits in, because what a person types is not
    /// bounded by what a prefix is. `/999` was reported as
    /// [`Malformed`](Self::Malformed) purely because the number did not fit,
    /// and `Malformed` is the signal a caller takes as "this might be a
    /// hostname": a mistyped prefix went to a DNS lookup and came back as a name
    /// that could not be resolved, which sends its author to look at their
    /// resolver over a typo.
    #[error("Invalid CIDR prefix: {0} (0-32 for IPv4, 0-128 for IPv6)")]
    InvalidPrefix(u32),

    /// The start address of a range is numerically higher than the end address.
    #[error("Invalid range: start address {0} is greater than end address {1}")]
    InvalidRange(IpAddr, IpAddr),

    /// The input string does not match any known IP, Range, or CIDR format.
    #[error("Malformed IP or range string: '{0}'")]
    Malformed(String),

    /// Failed to retrieve local interface information for "lan" resolution.
    #[error("Could not resolve LAN interface: {0}")]
    LanError(String),

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
///
/// A borrowed `dyn Fn` rather than a bare `fn` pointer, so that a resolver may
/// close over what it needs — an interface table read once and reused, say —
/// which a function pointer cannot. It stays `Copy`, so
/// [`TargetContext`](super::target::TargetContext) does too.
pub type ResolverFn<'a> = &'a dyn Fn(Keyword, &mut IpSet) -> Result<(), IpParseError>;

/// Looks up an interface by name and returns its scope id.
///
/// Injected for the same reason [`ResolverFn`] is: resolving a name means
/// reading the host's interface list, and this module deliberately knows nothing
/// about the host it runs on. `None` for a name no interface answers to.
pub type ZoneResolverFn<'a> = &'a dyn Fn(&str) -> Option<u32>;

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
/// A caller that supplies no `zones` cannot express a link-local target at all,
/// and gets [`IpParseError::UnknownInterface`] rather than a set that silently
/// means a different segment.
///
/// # Examples
///
/// ```
/// use zond_engine::model::parse::ip::to_set;
///
/// let set = to_set(&["192.168.1.0/24", "10.0.0.1", "10.0.0.5-10"], None, None).unwrap();
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
/// This is the grammar itself, without the list handling [`to_set`] wraps
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
    resolver: Option<ResolverFn<'_>>,
    zones: Option<ZoneResolverFn<'_>>,
) -> Result<(), IpParseError> {
    // Trimmed here rather than by `to_set`, which is the only caller that was
    // doing it. This function is public and its documentation invites an
    // importer to call it directly with a token it has already split out, and
    // such a caller got a grammar split in two: `Keyword::from_token` trims, so
    // ` lan ` resolved, and `IpAddr::from_str` does not, so ` 10.0.0.1 ` came
    // back malformed and was tried as a hostname.
    let s = s.trim();

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
    if !v6.start_addr().is_unicast_link_local() {
        return Err(IpParseError::ZoneOnUnscopedTarget(original.to_string()));
    }

    // A resolver answering zero has not found an interface: zero is what a name
    // lookup returns to say there is no such name, and a range carrying it names
    // no segment. Refused here rather than passed on, since this is the one
    // place that still holds the name the caller wrote and can say which one
    // went unanswered.
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

    // Read as a `u32` and narrowed, so that a number too large to be a prefix is
    // a prefix that is too large rather than a token this grammar did not
    // recognise. The difference is the whole of what a caller does next: an
    // unrecognised token is tried as a hostname.
    let prefix = prefix_str
        .parse::<u32>()
        .map_err(|_| IpParseError::Malformed(s.into()))?;
    let prefix = u8::try_from(prefix).map_err(|_| IpParseError::InvalidPrefix(prefix))?;

    crate::model::ip::range::cidr_range(ip, prefix).map_err(|e| map_range_error(s, e))
}

/// Restates a range error in this module's vocabulary, against the expression
/// the caller wrote.
///
/// `original` is threaded through because the remaining variants describe a
/// token this module no longer holds — a bare "invalid IP range" leaves whoever
/// is reading the error with nothing to search their input for.
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

    /// Two public entry points read written ranges: this module's, and
    /// [`IpSet`]'s string constructors by way of [`IpRange::from_str`]. They are
    /// the same grammar, and a spelling either accepts the other has to accept
    /// too, or a target file works through one API and silently fails through
    /// the other.
    ///
    /// Compares the sets rather than their sizes. Two ranges of equal length are
    /// equal lengths and nothing more, and the divergence this exists to catch
    /// was one entry point reading a spelling the other refused outright, which
    /// a size comparison would have seen only as a panic on the unwrap.
    #[test]
    fn both_ways_into_the_parser_accept_the_same_spellings() {
        for expression in [
            "10.0.0.1-50",
            "192.168.1.1-2.254",
            "10.0.0.1-10.0.0.50",
            "192.168.1.0/24",
            "2001:db8::1-2001:db8::5",
            "8.8.8.8",
            // Spellings one of the two used to take and the other did not.
            "10.0.0.0-0",
            "  10.0.0.1  ",
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

    /// The simplest expression there is, and the one every other form reduces
    /// to.
    #[test]
    fn a_single_literal_address_becomes_a_set_of_one() {
        let input = vec!["192.168.1.1"];
        let set = to_set(&input, None, None).expect("Should parse single IP");
        assert_eq!(set.len(), 1);
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    /// One argument may itself be a list, so a command line and a whole target
    /// file reach the same code.
    #[test]
    fn one_argument_may_name_several_addresses() {
        let input = vec!["10.0.0.1, 10.0.0.2, 10.0.0.5"];
        let set = to_set(&input, None, None).expect("Should parse comma list");
        assert_eq!(set.len(), 3);
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    /// A block is expanded to what it covers, not to what was written — the
    /// difference a budget check depends on.
    #[test]
    fn a_cidr_block_covers_every_address_in_it() {
        let input = vec!["172.16.0.0/24"];
        let set = to_set(&input, None, None).expect("Should parse CIDR");
        assert_eq!(set.len(), 256);
    }

    /// The shorthand crosses an octet boundary, which is where writing it out
    /// by hand goes wrong: `.250-2.10` is seventeen addresses, not eight.
    #[test]
    fn a_shortened_range_end_continues_the_starts_octets() {
        let input = vec!["192.168.1.250-2.10"];
        let set = to_set(&input, None, None).unwrap();
        assert_eq!(set.len(), 17);
    }

    /// A prefix too long for its family is refused rather than clamped, since
    /// a clamped `/33` silently scans the whole `/32` it was not asked about.
    #[test]
    fn a_prefix_longer_than_its_family_allows_is_refused() {
        let input = vec!["192.168.1.1/33"];
        let result = to_set(&input, None, None);
        assert_eq!(result.unwrap_err(), IpParseError::InvalidPrefix(33));
    }

    /// A prefix too large to be a prefix at all is still a prefix.
    ///
    /// `/999` does not fit a `u8`, and the parse failing on the width was read
    /// as [`Malformed`](IpParseError::Malformed), which is the one error a
    /// caller treats as "this might be a hostname". So a mistyped prefix went to
    /// a DNS lookup and came back reported as a name nothing could resolve,
    /// which is the wrong thing to hand somebody who typed one digit too many.
    ///
    /// `/33` and `/999` are the same mistake made twice as far as a person is
    /// concerned, and the two now say the same thing.
    #[test]
    fn a_prefix_too_large_for_a_u8_is_still_a_prefix() {
        let too_large = to_set(&["10.0.0.0/999"], None, None).unwrap_err();
        assert_eq!(too_large, IpParseError::InvalidPrefix(999));
        assert!(too_large.to_string().contains("0-32"), "{too_large}");

        // Text that is not a number at all stays malformed, which is what lets
        // a hostname reach the lookup that resolves it.
        assert!(matches!(
            to_set(&["10.0.0.0/wide"], None, None),
            Err(IpParseError::Malformed(_))
        ));
    }

    /// The error carries the prefix and not the family it was written against,
    /// so its message has to name both bounds. Told only the IPv4 rule, whoever
    /// mistyped an IPv6 prefix is sent to shorten an address that was never too
    /// long.
    #[test]
    fn a_prefix_error_names_the_bound_for_both_families() {
        let v6 = to_set(&["2001:db8::/129"], None, None).unwrap_err();
        assert_eq!(v6, IpParseError::InvalidPrefix(129));
        assert!(v6.to_string().contains("0-128"), "{v6}");

        let v4 = to_set(&["192.168.1.1/33"], None, None).unwrap_err();
        assert!(v4.to_string().contains("0-32"), "{v4}");
    }

    /// A backwards range is a typo, and reporting it is what stops it being
    /// read as an empty set that scans nothing.
    #[test]
    fn a_range_written_backwards_is_refused() {
        let input = vec!["10.0.0.10-1"];
        let result = to_set(&input, None, None);
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

        let set = to_set(&["fe80::aa%en0"], None, Some(&zones)).expect("parses");

        assert_eq!(set.v6().len(), 1);
        assert_eq!(set.v6()[0].zone(), Some(7));
        assert!(!set.v6()[0].is_ambiguous());
    }

    /// The same address without an interface is accepted but marked as the
    /// unanswerable question it is, for the classifier to report.
    #[test]
    fn a_link_local_target_without_an_interface_is_ambiguous() {
        let set = to_set(&["fe80::aa"], None, None).expect("parses");

        assert!(set.v6()[0].is_ambiguous());
    }

    /// A resolver answering zero has not answered.
    ///
    /// Zero is what a name lookup returns to say there is no such interface, so
    /// a resolver that passes it on is reporting a failure as a success. Taken
    /// at face value it built a range that reads as scoped, which stops
    /// `is_ambiguous` reporting the problem, and a scan then sent probes at
    /// `fe80::` on whichever link the kernel picked.
    ///
    /// Refused here rather than downstream, because this is the last place that
    /// still holds the name the target was written with.
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

    /// One grammar, whatever whitespace the caller left on the token.
    ///
    /// [`insert_expression`] is public and its documentation invites an importer
    /// reading a file to call it with a token it has already split out. Such a
    /// caller met a grammar split in two, because `to_set` was the only thing
    /// trimming: `Keyword::from_token` trims of its own accord so ` lan `
    /// resolved, and `IpAddr::from_str` does not, so ` 10.0.0.1 ` came back
    /// malformed and was then tried as a hostname by the builder above it.
    #[test]
    fn an_untrimmed_token_reads_the_same_as_a_trimmed_one() {
        let mut set = IpSet::new();
        insert_expression(" 10.0.0.1 ", &mut set, None, None).expect("an address with space");
        insert_expression("\t192.168.1.0/24\n", &mut set, None, None).expect("a block with space");
        insert_expression(" 10.0.0.5-10 ", &mut set, None, None).expect("a range with space");

        assert_eq!(set.len(), 1 + 256 + 6);

        fn keywords(_: Keyword, set: &mut IpSet) -> Result<(), IpParseError> {
            set.insert("172.16.0.1".parse().expect("an address"));
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

    /// An interface nobody recognizes is a target that does not mean what it
    /// says, and is refused rather than silently stripped of its scope.
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
            to_set(&["192.168.1.1%en0"], None, Some(&zones)),
            Err(IpParseError::ZoneOnUnscopedTarget(_))
        ));
    }

    /// Nothing to scan is a caller mistake rather than a scan of nothing: a
    /// silent empty set looks exactly like a completed scan that found no
    /// hosts.
    #[test]
    fn input_naming_no_addresses_is_an_error() {
        let input: Vec<&str> = vec!["", " "];
        let result = to_set(&input, None, None);
        assert_eq!(result.unwrap_err(), IpParseError::EmptySet);
    }
}
