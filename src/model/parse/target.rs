// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Target Expressions
//!
//! What a scan target looks like written down, and how a stream of them becomes
//! a [`TargetMap`].
//!
//! Every way of getting targets into the engine (a file, a form field, an argument
//! list, a previous report) ends here, so the formats only decide where the tokens come
//! from.
//!
//! ## The grammar
//!
//! A target expression is an address expression with an optional port
//! specification after it:
//!
//! | Written | Address | Ports |
//! |---|---|---|
//! | `192.0.2.1` | `192.0.2.1` | the caller's default |
//! | `192.0.2.1:80,443` | `192.0.2.1` | `80,443` |
//! | `198.51.100.0/24:1-1024` | `198.51.100.0/24` | `1-1024` |
//! | `2001:db8::1` | `2001:db8::1` | the caller's default |
//! | `[2001:db8::1]:443` | `2001:db8::1` | `443` |
//! | `fe80::1%en0` | `fe80::1%en0` | the caller's default |
//! | `[fe80::1%en0]:22` | `fe80::1%en0` | `22` |
//! | `scanme.example:22` | `scanme.example` | `22` |
//! | `192.0.2.1:u:53` | `192.0.2.1` | `u:53` (UDP) |
//!
//! The address half goes to [`crate::model::parse::ip`]; this module only decides where
//! the address ends and the ports begin.
//!
//! ## Where the ports begin
//!
//! `:` separates ports from addresses, appears inside IPv6 addresses, and appears in
//! this engine's `u:53` spelling for a UDP port. Three rules settle it:
//!
//! 1. A token starting with `[` is an address up to the matching `]`,
//!    optionally followed by `:` and a port specification.
//! 2. **A dot before the first colon means the first colon separates.** No IPv6
//!    address can have one: every dotted IPv6 form puts its dots in the last 32
//!    bits, after at least one colon. So `192.0.2.1:u:53` and
//!    `db.internal:u:53` are an address and its ports, however many colons
//!    follow.
//! 3. Otherwise, one colon separates and two or more are an IPv6 address.
//!
//! Rule 2 lets a UDP port be written without brackets on an IPv4 target or a dotted
//! name.
//!
//! **`2001:db8::1:80` is an address, not port 80 on `2001:db8::1`**: it is a valid IPv6
//! address. Write `[2001:db8::1]:80` for the port. A target with colons that is neither
//! is refused with an error saying so; it is never tried as a hostname, since a
//! hostname cannot contain a colon.
//!
//! ## Hostnames
//!
//! Whether a name may be looked up is [`crate::config::ZondConfig::no_dns`]'s business,
//! and how is up to whoever built the resolver. So a name goes to a lookup supplied in
//! [`TargetContext`], like keywords and interface zones. Without one, the hostname is
//! refused with an error naming it.
//!
//! The lookup is called during parsing, synchronously. With many names, parse in two
//! passes: collect them with [`TargetExpr::parse`], resolve them concurrently, then
//! build with a lookup that reads the results.
//!
//! ## One unit per port specification
//!
//! [`TargetMapBuilder`] groups by port specification, so a file of 65,536 bare
//! addresses becomes one unit. Order is first-seen, so two runs over the same input
//! produce the same scan.
//!
//! The saving is in the number of units: each [`TargetSet`] canonicalizes itself and
//! allocates its own port vector when iterated. On a 65,536-line file this is roughly
//! 1.5x faster end to end, whether or not anything merged.
//!
//! ## When grouping stops paying
//!
//! Grouping costs an index lookup per line and pays only while lines share
//! specifications. Reading a report back produces a distinct specification per host,
//! and over 65,536 such units a builder keeping its index took 22.0 ms against the
//! direct path's 12.7 ms.
//!
//! So the builder gives the index up when it earns nothing (see `MIN_REGROUPED_SHARE`),
//! after which every expression becomes its own unit. That shape then costs 13.4 ms
//! (1.05x the direct path, median of nine paired runs). Shapes that group keep the
//! index.
//!
//! Once the index is gone, an address named twice on the same ports is asked twice,
//! which is what a [`TargetMap`] means by counting gross. That only happens after a
//! thousand expressions repeating a specification less than one time in sixteen.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

use thiserror::Error;

use crate::model::ip::set::IpSet;
use crate::model::parse::ip::{IpParseError, ResolverFn, ZoneResolverFn, insert_expression};
use crate::model::port::{PortSet, PortSetParseError};
use crate::model::target::{TargetMap, TargetSet};

/// Looks up the addresses a hostname stands for.
///
/// `None` and an empty vector both mean nothing to scan under that name, reported as
/// [`TargetParseError::UnknownHost`]. A resolver that distinguishes a lookup failure
/// from a name with no records reports that through its own channel.
///
/// `Sync`, for the reason [`ResolverFn`] is.
pub type HostLookup<'a> = &'a (dyn Fn(&str) -> Option<Vec<IpAddr>> + Sync);

/// The lookups a target expression may need, which read the host this process runs on.
///
/// Each is optional, and an expression needing one the caller did not supply is
/// refused.
///
/// Build one with [`new`](Self::new) and the `with_*` methods, or with [`Default`], and
/// assign fields directly where that reads better.
#[must_use]
#[non_exhaustive]
#[derive(Default, Clone, Copy)]
pub struct TargetContext<'a> {
    /// Expands keywords such as `lan` into the addresses they stand for.
    pub keywords: Option<ResolverFn<'a>>,
    /// Resolves the `%interface` suffix on a link-local address to a scope id.
    pub zones: Option<ZoneResolverFn<'a>>,
    /// Resolves a hostname to addresses.
    pub hosts: Option<HostLookup<'a>>,
}

impl<'a> TargetContext<'a> {
    /// A context that can resolve nothing: literal addresses, ranges and CIDR
    /// blocks only.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the keyword resolver.
    pub fn with_keywords(mut self, keywords: ResolverFn<'a>) -> Self {
        self.keywords = Some(keywords);
        self
    }

    /// Sets the interface-zone resolver.
    pub fn with_zones(mut self, zones: ZoneResolverFn<'a>) -> Self {
        self.zones = Some(zones);
        self
    }

    /// Sets the hostname lookup.
    pub fn with_hosts(mut self, hosts: HostLookup<'a>) -> Self {
        self.hosts = Some(hosts);
        self
    }
}

impl fmt::Debug for TargetContext<'_> {
    /// Reports which lookups are present, which is what debugging a refused target
    /// needs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TargetContext")
            .field("keywords", &self.keywords.is_some())
            .field("zones", &self.zones.is_some())
            .field("hosts", &self.hosts.is_some())
            .finish()
    }
}

/// Why a target expression could not be turned into targets.
///
/// Every variant carries the expression it is about; an importer adds the line.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TargetParseError {
    /// The token was empty.
    #[error("a target expression cannot be empty")]
    Empty,

    /// The token held nothing but whitespace.
    ///
    /// Its own variant because a token of spaces looks like the gap between two
    /// arguments, usually from a stray `\` in the shell.
    #[error("a target of {0} space{1}; a stray '\\' in the shell?")]
    Blank(usize, &'static str),

    /// A bracketed address was never closed.
    #[error("'{0}': a bracketed address must be closed with ']'")]
    UnbalancedBracket(String),

    /// Something followed the closing bracket other than a port specification.
    #[error("'{0}': expected ':' and a port specification after ']'")]
    TrailingText(String),

    /// The separator was there and the port specification was not.
    #[error("'{0}': the ':' is not followed by a port specification")]
    EmptyPorts(String),

    /// The address half named nothing scannable.
    #[error("'{expression}': {source}")]
    Address {
        /// The whole expression, as written.
        expression: String,
        /// What the address grammar made of it.
        #[source]
        source: IpParseError,
    },

    /// The port half was not a port specification.
    #[error("'{expression}': {source}")]
    Ports {
        /// The whole expression, as written.
        expression: String,
        /// What the port grammar made of it.
        #[source]
        source: PortSetParseError,
    },

    /// The address half is a hostname and the caller supplied no lookup.
    #[error("'{0}': this is a hostname, and no host lookup was supplied to resolve it")]
    NoHostLookup(String),

    /// Not an address or a range, and shaped like no host name either.
    ///
    /// A typo: `192.0.2.300`, `10.10.10.*` and `10.10.10.0/` are addresses or ranges
    /// written wrong. Never sent to a lookup, which would leak the range to a resolver.
    #[error("'{0}': not a valid address, range or hostname")]
    MistypedAddress(String),

    /// Something with colons in it that is neither an address nor bracketed.
    ///
    /// A hostname cannot contain a colon. Almost always an IPv6 target that needs
    /// brackets to carry its ports.
    #[error(
        "'{0}': not an address, and a hostname cannot contain ':'. \
         An IPv6 target carrying ports must be bracketed, as in `[2001:db8::1]:443`"
    )]
    UnbracketedAddress(String),

    /// The lookup returned nothing for the name.
    #[error("'{0}': no address could be resolved for this name")]
    UnknownHost(String),

    /// The expression parsed and named nothing to scan.
    ///
    /// Reached through a keyword: a [`ResolverFn`] that returns without inserting an
    /// address, as for `lan` on a host with no LAN. Distinct from
    /// [`Empty`](Self::Empty) (a token with no expression) and
    /// [`UnknownHost`](Self::UnknownHost) (a name nothing answered to). The engine's
    /// own resolver always inserts on success, so only a caller-supplied resolver
    /// reaches this.
    #[error("'{0}': this named no addresses to scan")]
    ResolvedToNothing(String),
}

/// Which of the two empties a token is: nothing at all, or whitespace.
fn blank_or_empty(token: &str) -> TargetParseError {
    let spaces = token.chars().count();
    match spaces {
        0 => TargetParseError::Empty,
        1 => TargetParseError::Blank(1, ""),
        _ => TargetParseError::Blank(spaces, "s"),
    }
}

/// A target expression split into the part that says *what* and the part that
/// says *where on it*.
///
/// Borrows from the token it was parsed out of, so splitting a large file costs
/// no allocation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TargetExpr<'a> {
    /// The address expression: a literal, a range, a CIDR block, a keyword or a
    /// hostname, carrying its `%zone` suffix if it had one. Brackets, if there
    /// were any, are stripped.
    pub address: &'a str,
    /// The port specification as written, if the expression carried one.
    pub ports: Option<&'a str>,
}

impl<'a> TargetExpr<'a> {
    /// Splits one token.
    ///
    /// Surrounding whitespace is trimmed. The halves are *not* validated here; the
    /// grammars that own them check them when the expression is built into targets.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::model::parse::target::TargetExpr;
    ///
    /// let bare = TargetExpr::parse("192.0.2.1").unwrap();
    /// assert_eq!(bare.address, "192.0.2.1");
    /// assert_eq!(bare.ports, None);
    ///
    /// let with_ports = TargetExpr::parse("[2001:db8::1]:443").unwrap();
    /// assert_eq!(with_ports.address, "2001:db8::1");
    /// assert_eq!(with_ports.ports, Some("443"));
    ///
    /// // A bare IPv6 address is an address, never an address and a port.
    /// let ambiguous = TargetExpr::parse("2001:db8::1:80").unwrap();
    /// assert_eq!(ambiguous.address, "2001:db8::1:80");
    /// assert_eq!(ambiguous.ports, None);
    /// ```
    pub fn parse(token: &'a str) -> Result<Self, TargetParseError> {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            return Err(blank_or_empty(token));
        }
        let token = trimmed;

        if let Some(rest) = token.strip_prefix('[') {
            let close = rest
                .find(']')
                .ok_or_else(|| TargetParseError::UnbalancedBracket(token.to_string()))?;
            let address = &rest[..close];
            let tail = &rest[close + 1..];

            if address.is_empty() {
                return Err(TargetParseError::Empty);
            }

            return match tail.strip_prefix(':') {
                None if tail.is_empty() => Ok(Self {
                    address,
                    ports: None,
                }),
                None => Err(TargetParseError::TrailingText(token.to_string())),
                Some("") => Err(TargetParseError::EmptyPorts(token.to_string())),
                Some(ports) => Ok(Self {
                    address,
                    ports: Some(ports),
                }),
            };
        }

        let colons = token.matches(':').count();

        // Every dotted IPv6 form (`::ffff:192.0.2.1` and relatives) puts the dots
        // after at least one colon, so a dot first means IPv4 or a dotted
        // hostname, and every later colon belongs to the ports, as in
        // `192.0.2.1:u:53`.
        let dotted_first = match (token.find('.'), token.find(':')) {
            (Some(dot), Some(colon)) => dot < colon,
            _ => false,
        };

        if colons >= 1 && (dotted_first || colons == 1) {
            let (address, ports) = token.split_once(':').expect("a colon was found");
            if address.is_empty() {
                return Err(TargetParseError::Empty);
            }
            if ports.is_empty() {
                return Err(TargetParseError::EmptyPorts(token.to_string()));
            }
            return Ok(Self {
                address,
                ports: Some(ports),
            });
        }

        // No colon, or two or more with no dot in front: a whole address, no
        // ports.
        Ok(Self {
            address: token,
            ports: None,
        })
    }

    /// The addresses the expression names, splitting the address half on commas.
    ///
    /// A comma separates addresses in the address half and is part of the
    /// specification in the port half: `192.0.2.1:80,443` is one host on two ports,
    /// `192.0.2.1,192.0.2.2:80` two hosts on one.
    ///
    /// Empty fields are skipped, so a trailing comma is not an error.
    pub fn addresses(&self) -> impl Iterator<Item = &'a str> {
        self.address
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
    }
}

/// How many expressions [`TargetMapBuilder`] watches before it will judge the
/// shape of its input.
///
/// A thousand entries is a few tens of kilobytes and a tenth of a millisecond, so
/// waiting costs nothing, and the judgement is made once and never revised.
const GROUPING_SAMPLE: usize = 1_024;

/// How little regrouping [`TargetMapBuilder`] will put up with before it stops
/// paying for an index: fewer than one expression in this many joining a group
/// that already existed.
///
/// Measured, grouping and the direct path cross between four and eight lines per port
/// specification, and a distinct specification on every line took 22.0 ms against
/// 12.7 ms.
///
/// Sixteen, well below the crossing, because the reading comes from a prefix and cannot
/// be taken back. A file drawing from a pool of fewer than about eight thousand
/// specifications repeats often enough within its first thousand lines to keep its
/// index; larger pools would not pay anyway. A file that repeats only much later gives
/// the index up and ends no worse off than the direct path.
const MIN_REGROUPED_SHARE: usize = 16;

/// Accumulates target expressions into a [`TargetMap`], one unit per distinct
/// port specification for as long as that is worth doing.
///
/// Built incrementally, so an importer can stream a file of any size and decide what
/// to do with a refused expression.
///
/// Grouping is abandoned on input that does not group; see `MIN_REGROUPED_SHARE` and
/// the module documentation.
#[derive(Debug, Clone)]
pub struct TargetMapBuilder {
    /// The ports an expression that names none is scanned on.
    default_ports: PortSet,
    /// The groups, in the order their port specification was first seen.
    groups: Vec<(PortSet, IpSet)>,
    /// Where each port specification's group sits in `groups`, while grouping
    /// is still earning its keep.
    ///
    /// A map, since the number of distinct specifications is unbounded and untrusted
    /// input must not make this quadratic.
    ///
    /// `None` once `MIN_REGROUPED_SHARE` says grouping buys nothing, which also frees
    /// its memory.
    index: Option<HashMap<PortSet, usize>>,
    /// How many expressions have been accepted, which the rule above reads
    /// against the group count.
    accepted: usize,
    /// Addresses accumulated so far, before overlapping expressions are merged.
    ///
    /// A running total, since it is read once per expression. See
    /// [`gross_address_count`](Self::gross_address_count).
    gross_addresses: u128,
}

impl TargetMapBuilder {
    /// Starts a builder whose expressions take `default_ports` when they name
    /// no ports of their own.
    pub fn new(default_ports: PortSet) -> Self {
        Self {
            default_ports,
            groups: Vec::new(),
            index: Some(HashMap::new()),
            accepted: 0,
            gross_addresses: 0,
        }
    }

    /// Parses one target expression and adds what it names.
    ///
    /// Nothing is added when the expression is refused.
    pub fn push(&mut self, token: &str, ctx: &TargetContext<'_>) -> Result<(), TargetParseError> {
        let expr = TargetExpr::parse(token)?;

        let ports = match expr.ports {
            Some(spec) => PortSet::parse_scan(spec).map_err(|source| TargetParseError::Ports {
                expression: token.trim().to_string(),
                source,
            })?,
            None => self.default_ports.clone(),
        };

        // Resolved into its own set first, so a refusal leaves the builder
        // untouched.
        let mut resolved = IpSet::new();
        for address in expr.addresses() {
            match insert_expression(address, &mut resolved, ctx.keywords, ctx.zones) {
                Ok(()) => {}
                // "Not an address", so possibly a name.
                Err(IpParseError::Malformed(_)) => {
                    self.resolve_host(address, &mut resolved, ctx)?;
                }
                Err(source) => {
                    return Err(TargetParseError::Address {
                        expression: token.trim().to_string(),
                        source,
                    });
                }
            }
        }

        if resolved.is_empty() {
            return Err(TargetParseError::ResolvedToNothing(
                token.trim().to_string(),
            ));
        }

        // Counted from this expression's own ranges; see `gross_address_count`.
        self.gross_addresses = self.gross_addresses.saturating_add(resolved.len_gross());
        self.accepted += 1;

        let existing = self
            .index
            .as_ref()
            .and_then(|index| index.get(&ports).copied());

        match existing {
            Some(slot) => {
                let target = &mut self.groups[slot].1;
                for range in resolved.v4() {
                    target.push_v4_range(*range);
                }
                for range in resolved.v6() {
                    target.push_v6_range(*range);
                }
            }
            None => {
                let slot = self.groups.len();
                if let Some(index) = self.index.as_mut() {
                    index.insert(ports.clone(), slot);
                }
                self.groups.push((ports, resolved));
            }
        }

        self.reconsider_grouping();

        Ok(())
    }

    /// Drops the index once the groups have stopped earning it.
    ///
    /// Irreversible: once the index is gone, existing groups stay and every later
    /// expression becomes its own unit.
    fn reconsider_grouping(&mut self) {
        if self.index.is_none() || self.accepted < GROUPING_SAMPLE {
            return;
        }

        let regrouped = self.accepted - self.groups.len();
        if regrouped * MIN_REGROUPED_SHARE < self.accepted {
            self.index = None;
        }
    }

    /// Looks a hostname up through the caller's lookup and records what it
    /// stands for.
    fn resolve_host(
        &self,
        name: &str,
        into: &mut IpSet,
        ctx: &TargetContext<'_>,
    ) -> Result<(), TargetParseError> {
        match host_name(name) {
            HostName::Yes => {}
            HostName::Unbracketed => {
                return Err(TargetParseError::UnbracketedAddress(name.to_string()));
            }
            HostName::Mistyped => {
                return Err(TargetParseError::MistypedAddress(name.to_string()));
            }
        }

        let lookup = ctx
            .hosts
            .ok_or_else(|| TargetParseError::NoHostLookup(name.to_string()))?;

        let addresses = lookup(name).unwrap_or_default();
        if addresses.is_empty() {
            return Err(TargetParseError::UnknownHost(name.to_string()));
        }

        for address in addresses {
            into.insert(address);
        }

        Ok(())
    }

    /// How many groups have accumulated.
    ///
    /// The number of units [`build`](Self::build) will produce: on input that groups,
    /// the number of distinct port specifications; otherwise, roughly the number of
    /// expressions accepted. See the module documentation.
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// How many addresses have accumulated across every group, counting an
    /// address once per group it appears in.
    ///
    /// Merges ranges to answer, so a block counts what it holds. A caller checks a
    /// scan-size budget against this: `::/0` costs nothing to hold and 2^128 addresses
    /// to scan.
    pub fn address_count(&mut self) -> u128 {
        self.groups
            .iter_mut()
            .map(|(_, ips)| {
                ips.canonicalize();
                ips.len()
            })
            .fold(0u128, |total, count| total.saturating_add(count))
    }

    /// How many addresses have accumulated, counted before overlapping
    /// expressions are merged.
    ///
    /// The constant-time counterpart to [`address_count`](Self::address_count), for a
    /// budget checked once per expression. Walking the accumulated ranges instead made
    /// a 65,536-line import take 3.2 s against 6.9 ms, growing with the square of the
    /// line count.
    ///
    /// Never lower than the true count, so a budget check errs early.
    pub fn gross_address_count(&self) -> u128 {
        self.gross_addresses
    }

    /// Whether anything scannable has accumulated.
    ///
    /// Whether any group exists: [`push`](Self::push) refuses an expression naming no
    /// addresses, so every group holds at least one.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Finishes the map.
    ///
    /// Every group becomes a unit; none is empty (see [`is_empty`](Self::is_empty)).
    pub fn build(self) -> TargetMap {
        let mut map = TargetMap::new();
        for (ports, ips) in self.groups {
            map.add_unit(TargetSet::new(ips, ports));
        }
        map
    }
}

/// Whether a token the address grammar refused is worth looking up as a host
/// name, and if not, what it is instead.
///
/// [`IpParseError::Malformed`] says only "not an address", and many such tokens are not
/// names either; telling the author what they wrote beats a lookup bound to fail.
///
/// ## Only something shaped like a name is a name
///
/// A token goes to a lookup only when it could be a host name: letters, digits, `-`,
/// `_` and dots, with a last label holding at least one letter, and not three or more
/// numbers ahead of that label. Everything else is a mistyped address or range.
///
/// The rule describes names because typos are open-ended: `10.10.10.*`,
/// `10.10.1-5.1-254`, `10.10.10.0/` and `/0` fail in four different ways. The system
/// resolver accepts `*` and `-` in a label and asks upstream, which would tell someone
/// else's resolver what range is being scanned.
///
/// RFC 1123 §2.1 makes a host name's last label alphabetic, which keeps a name from
/// reading as a dotted address. A letter anywhere in it counts, so `nas-1` resolves.
/// `_` is allowed because such hosts exist on real networks; `*`, `/`, `%` and the like
/// are not. Letters and digits include non-ASCII, so a name in its own script reaches a
/// lookup that may encode it.
///
/// The second condition catches a stray letter: `10.10.10.1a`, `10.10.10.a` and
/// `10.10.10.1-2.example` are IPv4 addresses or ranges with a slip. Names that embed an
/// address put a non-numeric label between it and the last label
/// (`192.0.2.1.sslip.example`, reverse names under `in-addr.arpa`), and a leading label
/// with a letter, as in `3com.example`, is a name too.
///
/// ## Both passes ask this
///
/// The synchronous build asks before consulting the lookup, and `resolve::targets`'s
/// collection pass asks before putting a name on the network, so the two cannot
/// disagree.
pub(crate) fn host_name(token: &str) -> HostName {
    // A colon rules out a name. A port specification after the last colon is
    // almost certainly an unbracketed IPv6 target; anything else is a wrong IPv6
    // address, where advice about brackets would mislead.
    if let Some((_, tail)) = token.rsplit_once(':') {
        return if PortSet::try_from(tail).is_ok() {
            HostName::Unbracketed
        } else {
            HostName::Mistyped
        };
    }

    let name_character = |c: char| c.is_alphanumeric() || matches!(c, '-' | '_' | '.');
    // A fully qualified name's trailing dot leaves an empty last label.
    let last_label = token
        .strip_suffix('.')
        .unwrap_or(token)
        .rsplit('.')
        .next()
        .unwrap_or_default();

    // An octet or an octet range.
    let numeric = |label: &str| {
        label
            .split('-')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    };
    let leading: Vec<&str> = token
        .strip_suffix('.')
        .unwrap_or(token)
        .rsplit('.')
        .skip(1)
        .collect();
    let address_shaped = leading.len() >= 3 && leading.iter().all(|label| numeric(label));

    if token.chars().all(name_character)
        && last_label.chars().any(char::is_alphabetic)
        && !address_shaped
    {
        HostName::Yes
    } else {
        HostName::Mistyped
    }
}

/// What [`host_name`] concluded about a token the address grammar refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostName {
    /// Worth resolving.
    Yes,
    /// An IPv6 address and ports, written without brackets.
    Unbracketed,
    /// Shaped like no name: an address or a range with a mistake in it.
    Mistyped,
}

/// Parses a slice of target expressions into a [`TargetMap`].
///
/// For a caller with every target in memory that wants the first error; drive
/// [`TargetMapBuilder`] directly for more control.
pub fn to_target_map<S>(
    targets: &[S],
    default_ports: PortSet,
    ctx: &TargetContext<'_>,
) -> Result<TargetMap, TargetParseError>
where
    S: AsRef<str>,
{
    let mut builder = TargetMapBuilder::new(default_ports);
    for target in targets {
        builder.push(target.as_ref(), ctx)?;
    }
    Ok(builder.build())
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

    /// A context is `Send`, so a caller can resolve targets inside a spawned task.
    #[test]
    fn a_context_can_be_held_across_a_spawn() {
        fn sent<T: Send + Sync>() {}

        sent::<TargetContext<'static>>();
    }
    use crate::model::parse::ip::Keyword;
    use crate::model::target::Target;
    use std::net::Ipv4Addr;

    fn ports(spec: &str) -> PortSet {
        PortSet::try_from(spec).expect("test port specification parses")
    }

    /// Splitting at the first colon would read `fe80::1` as host `fe80` on port `:1`.
    #[test]
    fn an_ipv6_address_is_never_split_at_its_own_colons() {
        for token in [
            "fe80::1",
            "2001:db8::1",
            "2001:db8::1:80",
            "fe80::1%en0",
            "2001:db8::1-2001:db8::5",
            "::1",
        ] {
            let expr = TargetExpr::parse(token).expect("parses");
            assert_eq!(expr.address, token, "{token} lost part of its address");
            assert_eq!(expr.ports, None, "{token} acquired ports it does not name");
        }
    }

    /// Brackets work for every IPv6 address form.
    #[test]
    fn brackets_separate_an_ipv6_address_from_its_ports() {
        let cases = [
            ("[2001:db8::1]:443", "2001:db8::1", Some("443")),
            ("[fe80::1%en0]:22", "fe80::1%en0", Some("22")),
            ("[2001:db8::1]", "2001:db8::1", None),
            (
                "[2001:db8::]:80,443,u:53",
                "2001:db8::",
                Some("80,443,u:53"),
            ),
        ];

        for (token, address, port_spec) in cases {
            let expr = TargetExpr::parse(token).expect("parses");
            assert_eq!(expr.address, address);
            assert_eq!(expr.ports, port_spec);
        }
    }

    #[test]
    fn a_single_colon_separates_ports() {
        let cases = [
            ("192.0.2.1:80", "192.0.2.1", Some("80")),
            ("198.51.100.0/24:1-1024", "198.51.100.0/24", Some("1-1024")),
            ("198.51.100.1-50:80,443", "198.51.100.1-50", Some("80,443")),
            ("scanme.example:22", "scanme.example", Some("22")),
            ("  192.0.2.1:80  ", "192.0.2.1", Some("80")),
        ];

        for (token, address, port_spec) in cases {
            let expr = TargetExpr::parse(token).expect("parses");
            assert_eq!(expr.address, address);
            assert_eq!(expr.ports, port_spec);
        }
    }

    /// A dot before the first colon lets `u:` ports follow an IPv4 address or dotted
    /// name without brackets.
    #[test]
    fn a_udp_port_needs_no_brackets_on_an_address_that_has_a_dot() {
        let cases = [
            ("192.0.2.1:u:53", "192.0.2.1", Some("u:53")),
            ("192.0.2.1:u:53,u:161", "192.0.2.1", Some("u:53,u:161")),
            (
                "198.51.100.0/24:80,u:53",
                "198.51.100.0/24",
                Some("80,u:53"),
            ),
            ("db.internal:u:53", "db.internal", Some("u:53")),
        ];

        for (token, address, port_spec) in cases {
            let expr = TargetExpr::parse(token).expect("parses");
            assert_eq!(expr.address, address, "{token}");
            assert_eq!(expr.ports, port_spec, "{token}");
        }

        // An IPv6 address is still whole.
        for token in ["2001:db8::1", "::ffff:192.0.2.1", "2001:db8::192.0.2.1"] {
            let expr = TargetExpr::parse(token).expect("parses");
            assert_eq!(expr.address, token, "{token} was split");
            assert_eq!(expr.ports, None, "{token} acquired ports");
        }
    }

    /// A token with colons that is not an address is not reported as an unresolvable
    /// host.
    #[test]
    fn an_unbracketed_ipv6_target_with_ports_says_what_to_do_about_it() {
        let mut builder = TargetMapBuilder::new(ports("80"));

        // Two colons, no dot in front: read as an address, and it is not one.
        let err = builder
            .push("2001:db8::zz:443", &TargetContext::new())
            .expect_err("not an address");

        assert!(
            matches!(err, TargetParseError::UnbracketedAddress(_)),
            "got {err:?}"
        );
        assert!(
            err.to_string().contains("[2001:db8::1]:443"),
            "the error has to show the way out: {err}"
        );
    }

    /// A malformed expression is refused: `192.0.2.1:` must not scan the default ports.
    #[test]
    fn a_separator_without_a_port_specification_is_refused() {
        assert!(matches!(
            TargetExpr::parse("192.0.2.1:"),
            Err(TargetParseError::EmptyPorts(_))
        ));
        assert!(matches!(
            TargetExpr::parse("[2001:db8::1]:"),
            Err(TargetParseError::EmptyPorts(_))
        ));
        assert!(matches!(
            TargetExpr::parse("[2001:db8::1"),
            Err(TargetParseError::UnbalancedBracket(_))
        ));
        assert!(matches!(
            TargetExpr::parse("[2001:db8::1]443"),
            Err(TargetParseError::TrailingText(_))
        ));
        assert!(matches!(
            TargetExpr::parse(":80"),
            Err(TargetParseError::Empty)
        ));
        // A token of spaces gets its own message.
        let blank = TargetExpr::parse("   ").expect_err("whitespace is not a target");
        assert!(
            matches!(blank, TargetParseError::Blank(3, "s")),
            "{blank:?}"
        );
        assert_eq!(
            blank.to_string(),
            "a target of 3 spaces; a stray '\\' in the shell?"
        );

        let one = TargetExpr::parse(" ").expect_err("a space is not a target");
        assert_eq!(
            one.to_string(),
            "a target of 1 space; a stray '\\' in the shell?"
        );

        assert!(matches!(
            TargetExpr::parse(""),
            Err(TargetParseError::Empty)
        ));
    }

    /// A port half naming no ports, such as `192.0.2.1:,`, is refused.
    #[test]
    fn a_port_specification_naming_nothing_is_refused() {
        let mut builder = TargetMapBuilder::new(ports("80"));
        let ctx = TargetContext::new();

        let error = builder
            .push("192.0.2.1:,", &ctx)
            .expect_err("a port half naming nothing");
        assert!(error.to_string().contains("names no ports"), "{error}");
        assert!(builder.is_empty(), "and nothing was added");
    }

    /// One unit per port specification, not per input token.
    #[test]
    fn targets_are_grouped_by_port_specification_not_by_token() {
        let mut builder = TargetMapBuilder::new(ports("80"));
        let ctx = TargetContext::new();

        for octet in 0..=255u8 {
            let target = format!("192.0.2.{octet}");
            builder.push(&target, &ctx).expect("parses");
        }

        assert_eq!(builder.group_count(), 1, "one port specification, one unit");
        assert_eq!(builder.address_count(), 256);

        let map = builder.build();
        assert_eq!(map.units.len(), 1);
        // 256 contiguous addresses on one port, merged into a single range.
        assert_eq!(map.gross_targets().unwrap(), 256);
    }

    #[test]
    fn distinct_port_specifications_get_distinct_units_in_first_seen_order() {
        let mut builder = TargetMapBuilder::new(ports("80"));
        let ctx = TargetContext::new();

        builder.push("198.51.100.1:22", &ctx).unwrap();
        builder.push("198.51.100.2:443", &ctx).unwrap();
        builder.push("198.51.100.3:22", &ctx).unwrap();
        builder.push("198.51.100.4", &ctx).unwrap();

        assert_eq!(builder.group_count(), 3, "22, 443, and the default 80");

        let map = builder.build();
        assert_eq!(map.units[0].ports(), &ports("22"));
        assert_eq!(map.units[0].ips().len(), 2, "198.51.100.1 and 198.51.100.3");
        assert_eq!(map.units[1].ports(), &ports("443"));
        assert_eq!(map.units[2].ports(), &ports("80"));
    }

    /// Two spellings of one port set are one group.
    #[test]
    fn port_specifications_group_by_what_they_mean_not_how_they_are_written() {
        let mut builder = TargetMapBuilder::new(ports("80"));
        let ctx = TargetContext::new();

        builder.push("198.51.100.1:80,443", &ctx).unwrap();
        builder.push("198.51.100.2:443,80", &ctx).unwrap();
        builder.push("198.51.100.3:80-81,443", &ctx).unwrap();

        assert_eq!(
            builder.group_count(),
            2,
            "80 with 443 once, 80 through 81 with 443 once"
        );
    }

    /// A keyword that resolved to nothing is not an empty expression.
    ///
    /// A caller's [`ResolverFn`] may insert nothing for `lan` on a host with no LAN;
    /// that is [`TargetParseError::ResolvedToNothing`], not
    /// [`TargetParseError::Empty`].
    #[test]
    fn a_keyword_that_resolves_to_nothing_says_what_went_wrong() {
        fn resolves_to_nothing(_: Keyword, _: &mut IpSet) -> Result<(), IpParseError> {
            Ok(())
        }

        let ctx = TargetContext::new().with_keywords(&resolves_to_nothing);
        let mut builder = TargetMapBuilder::new(ports("80"));
        let error = builder.push("lan", &ctx).expect_err("nothing was named");

        assert_eq!(
            error,
            TargetParseError::ResolvedToNothing("lan".to_string()),
            "the word it was said about has to be in it"
        );
        assert!(!error.to_string().contains("cannot be empty"), "{error}");

        // A token with nothing in it keeps its own error.
        assert_eq!(
            builder.push("   ", &ctx).expect_err("nothing was written"),
            TargetParseError::Blank(3, "s")
        );
        assert_eq!(
            builder.push("", &ctx).expect_err("nothing was written"),
            TargetParseError::Empty
        );
    }

    /// A hostname with no lookup is an error, not silently skipped.
    #[test]
    fn a_hostname_without_a_lookup_is_refused_rather_than_skipped() {
        let mut builder = TargetMapBuilder::new(ports("80"));

        let err = builder
            .push("scanme.example", &TargetContext::new())
            .expect_err("a hostname needs a lookup");

        assert!(
            matches!(err, TargetParseError::NoHostLookup(ref name) if name == "scanme.example")
        );
        assert!(builder.is_empty(), "a refused target left nothing behind");
    }

    #[test]
    fn a_hostname_resolves_through_the_callers_lookup() {
        let lookup = |name: &str| match name {
            "one.example" => Some(vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))]),
            "two.example" => Some(vec![
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3)),
            ]),
            _ => None,
        };
        let ctx = TargetContext::new().with_hosts(&lookup);

        let mut builder = TargetMapBuilder::new(ports("80"));
        builder.push("one.example", &ctx).unwrap();
        builder.push("two.example:443", &ctx).unwrap();

        assert_eq!(builder.address_count(), 3);
        assert_eq!(builder.group_count(), 2);

        let err = builder
            .push("nowhere.example", &ctx)
            .expect_err("a name with no records is not a target");
        assert!(matches!(err, TargetParseError::UnknownHost(_)));
    }

    /// A wrong address is not a hostname: no DNS query for `192.0.2.1/33`.
    #[test]
    fn a_malformed_address_is_reported_as_an_address() {
        let lookup = |_: &str| -> Option<Vec<IpAddr>> {
            panic!("a bad prefix must never be offered to a host lookup")
        };
        let ctx = TargetContext::new().with_hosts(&lookup);

        let mut builder = TargetMapBuilder::new(ports("80"));
        let err = builder.push("192.0.2.1/33", &ctx).expect_err("refused");

        assert!(matches!(
            err,
            TargetParseError::Address {
                source: IpParseError::InvalidPrefix(33),
                ..
            }
        ));
    }

    /// A mistyped range such as `10.10.10.*` is not a hostname either, so no resolver
    /// learns which network is being scanned.
    #[test]
    fn a_mistyped_range_is_refused_without_a_lookup() {
        let lookup =
            |name: &str| -> Option<Vec<IpAddr>> { panic!("{name} was offered to a host lookup") };
        let ctx = TargetContext::new().with_hosts(&lookup);

        for token in [
            "10.10.10.*",
            "10.10.1-5.1-254",
            "10.10.10.1-256",
            "10.10.10.0/",
            "/0",
            "192.0.2.300",
            "2001:db8::1-ff",
            "10.10.10.1a",
            "10.10.10.a",
            "10.10.10.1-2.example",
        ] {
            let mut builder = TargetMapBuilder::new(ports("80"));
            let err = builder.push(token, &ctx).expect_err(token);

            assert!(
                matches!(err, TargetParseError::MistypedAddress(ref t) if t == token),
                "{token}: {err:?}"
            );
            // The concurrent collection pass asks the same question.
            assert_eq!(host_name(token), HostName::Mistyped, "{token}");
        }
    }

    /// Whatever a resolver would plausibly answer for is still asked, including a
    /// trailing dot and a non-ASCII label.
    #[test]
    fn a_name_of_any_ordinary_shape_still_reaches_the_lookup() {
        for name in [
            "printer",
            "nas-1",
            "scanme.example",
            "scanme.example.",
            "host_1.corp.example",
            "3com.example",
            "bücher.example",
            "xn--bcher-kva.example",
            "0.pool.ntp.example",
            "192.0.2.1.sslip.example",
            "1.2.0.192.in-addr.arpa",
        ] {
            assert_eq!(host_name(name), HostName::Yes, "{name}");
        }

        // A port specification after a colon: an IPv6 target that wanted brackets.
        assert_eq!(host_name("2001:db8::zz:443"), HostName::Unbracketed);
    }

    #[test]
    fn a_malformed_port_specification_is_reported_as_ports() {
        let mut builder = TargetMapBuilder::new(ports("80"));
        let err = builder
            .push("198.51.100.1:http", &TargetContext::new())
            .expect_err("refused");

        assert!(matches!(err, TargetParseError::Ports { .. }));
        assert!(builder.is_empty());
    }

    /// The zone survives the split.
    #[test]
    fn a_bracketed_link_local_target_keeps_its_interface() {
        fn zones(name: &str) -> Option<u32> {
            (name == "en0").then_some(7)
        }
        let ctx = TargetContext::new().with_zones(&zones);

        let mut builder = TargetMapBuilder::new(ports("80"));
        builder.push("[fe80::aa%en0]:22", &ctx).unwrap();

        let map = builder.build();
        assert_eq!(map.units[0].ips().v6()[0].zone(), Some(7));
        assert_eq!(map.units[0].ports(), &ports("22"));
    }

    /// A resolver can close over state, such as an interface table read once.
    #[test]
    fn a_resolver_may_close_over_what_it_needs_to_answer() {
        let interfaces = [("en0".to_string(), 7u32), ("utun3".to_string(), 12)];
        let zones = |name: &str| {
            interfaces
                .iter()
                .find(|(known, _)| known == name)
                .map(|(_, index)| *index)
        };
        let ctx = TargetContext::new().with_zones(&zones);

        let mut builder = TargetMapBuilder::new(ports("80"));
        builder.push("[fe80::aa%utun3]:22", &ctx).expect("parses");

        let map = builder.build();
        assert_eq!(map.units[0].ips().v6()[0].zone(), Some(12));
    }

    /// The running total equals what walking the accumulated groups would give.
    #[test]
    fn the_running_address_total_matches_what_the_groups_hold() {
        let ctx = TargetContext::new();
        let mut builder = TargetMapBuilder::new(ports("80"));

        for target in [
            "198.51.100.0/24",
            "198.51.100.5",
            "192.0.2.1:22",
            "2001:db8::/120",
            "203.0.113.1,203.0.113.2,203.0.113.3",
            "[fe80::1]:443",
        ] {
            builder.push(target, &ctx).expect("parses");
        }

        let walked = builder
            .groups
            .iter()
            .fold(0u128, |total, (_, ips)| total + ips.len_gross());

        assert_eq!(builder.gross_address_count(), walked);
        // Never below the merged figure.
        assert!(builder.gross_address_count() >= builder.address_count());
    }

    /// A CIDR block counts every address it covers.
    #[test]
    fn address_count_reports_what_a_block_holds_not_what_was_written() {
        let mut builder = TargetMapBuilder::new(ports("80"));
        builder.push("10.0.0.0/8", &TargetContext::new()).unwrap();

        assert_eq!(builder.address_count(), 16_777_216);

        let mut everything = TargetMapBuilder::new(ports("80"));
        everything.push("::/0", &TargetContext::new()).unwrap();
        assert_eq!(everything.address_count(), u128::MAX);
    }

    /// A comma separates addresses left of the port separator and ports right of it.
    #[test]
    fn a_comma_separates_addresses_before_the_ports_and_ports_after_them() {
        let ctx = TargetContext::new();

        let mut hosts = TargetMapBuilder::new(ports("80"));
        hosts.push("198.51.100.1,198.51.100.2:443", &ctx).unwrap();
        assert_eq!(hosts.address_count(), 2);
        assert_eq!(hosts.build().units[0].ports(), &ports("443"));

        let mut services = TargetMapBuilder::new(ports("80"));
        services.push("198.51.100.1:80,443", &ctx).unwrap();
        assert_eq!(services.address_count(), 1);
        assert_eq!(services.build().units[0].ports(), &ports("80,443"));

        let mut bare = TargetMapBuilder::new(ports("80"));
        bare.push("198.51.100.1, 198.51.100.2 ,198.51.100.3", &ctx)
            .unwrap();
        assert_eq!(bare.address_count(), 3);
    }

    /// The map a builder that grouped unconditionally would have produced.
    ///
    /// Computed independently of the builder.
    fn grouped_by_hand(tokens: &[String], default: &PortSet) -> Vec<(PortSet, Vec<Target>)> {
        let mut order: Vec<PortSet> = Vec::new();
        let mut groups: HashMap<PortSet, IpSet> = HashMap::new();

        for token in tokens {
            let expr = TargetExpr::parse(token).expect("parses");
            let ports = match expr.ports {
                Some(spec) => PortSet::try_from(spec).expect("ports parse"),
                None => default.clone(),
            };

            if !groups.contains_key(&ports) {
                order.push(ports.clone());
                groups.insert(ports.clone(), IpSet::new());
            }

            let ips = groups.get_mut(&ports).expect("just inserted");
            for address in expr.addresses() {
                insert_expression(address, ips, None, None).expect("addresses parse");
            }
        }

        order
            .into_iter()
            .map(|ports| {
                let ips = groups.remove(&ports).expect("one group per spelling");
                let unit = TargetSet::new(ips, ports.clone());
                (ports, unit.iter().collect())
            })
            .collect()
    }

    /// Every unit of a map, as its ports and the targets it yields.
    fn units_of(map: &TargetMap) -> Vec<(PortSet, Vec<Target>)> {
        map.units
            .iter()
            .map(|unit| (unit.ports().clone(), unit.iter().collect()))
            .collect()
    }

    /// The threshold changes how the builder works, not what it produces. Checked at
    /// three lengths around the sample size.
    #[test]
    fn the_map_is_the_same_either_side_of_the_grouping_threshold() {
        let ctx = TargetContext::new();
        let default = ports("80");

        for count in [
            GROUPING_SAMPLE - 1,
            GROUPING_SAMPLE + 1,
            GROUPING_SAMPLE * 4,
        ] {
            let tokens: Vec<String> = (0..count)
                .map(|i| format!("10.0.{}.{}:{}", i / 256, i % 256, 1 + i))
                .collect();

            let mut builder = TargetMapBuilder::new(default.clone());
            for token in &tokens {
                builder.push(token, &ctx).expect("parses");
            }
            let built = builder.build();

            assert_eq!(
                units_of(&built),
                grouped_by_hand(&tokens, &default),
                "{count} expressions, none of them sharing a specification"
            );
        }
    }

    /// A distinct specification on every line gives the index up; after that a
    /// specification already seen gets a unit of its own.
    #[test]
    fn a_file_that_never_groups_gives_the_index_up() {
        let mut builder = TargetMapBuilder::new(ports("80"));
        let ctx = TargetContext::new();

        for i in 0..GROUPING_SAMPLE {
            let token = format!("10.0.{}.{}:{}", i / 256, i % 256, 1 + i);
            builder.push(&token, &ctx).expect("parses");
        }
        assert_eq!(builder.group_count(), GROUPING_SAMPLE);

        // Port 1 has had a group since the first line; with the index gone it
        // gets a second.
        builder.push("10.9.9.9:1", &ctx).expect("parses");
        assert_eq!(builder.group_count(), GROUPING_SAMPLE + 1);

        let map = builder.build();
        assert_eq!(map.units[0].ports(), &ports("1"));
        assert_eq!(map.units[GROUPING_SAMPLE].ports(), &ports("1"));
        assert_eq!(
            map.gross_targets().unwrap(),
            GROUPING_SAMPLE as u128 + 1,
            "both units are still scanned, on the ports they named"
        );
    }

    /// A long file that groups keeps its index.
    #[test]
    fn a_file_that_groups_keeps_its_index_however_long_it_is() {
        let mut builder = TargetMapBuilder::new(ports("80"));
        let ctx = TargetContext::new();

        for i in 0..GROUPING_SAMPLE * 4 {
            let token = format!("10.0.{}.{}", i / 256, i % 256);
            builder.push(&token, &ctx).expect("parses");
        }

        assert_eq!(builder.group_count(), 1);
    }

    /// One line in eight repeating a specification keeps the index; one in
    /// thirty-two does not.
    #[test]
    fn the_index_is_kept_or_given_up_on_how_much_actually_regroups() {
        let ctx = TargetContext::new();
        let lines = GROUPING_SAMPLE * 4;

        for (every, kept) in [(8usize, true), (32, false)] {
            let mut builder = TargetMapBuilder::new(ports("80"));
            for i in 0..lines {
                // Every `every`th line repeats the specification before it.
                let spec = 1 + i - usize::from(i % every == every - 1);
                let token = format!("10.0.{}.{}:{}", i / 256, i % 256, spec);
                builder.push(&token, &ctx).expect("parses");
            }

            let regrouped = lines / every;
            if kept {
                assert_eq!(
                    builder.group_count(),
                    lines - regrouped,
                    "one line in {every} joined the group before it"
                );
            } else {
                assert!(
                    builder.group_count() > lines - regrouped,
                    "one line in {every} is too little to keep an index for"
                );
            }
        }
    }

    #[test]
    fn overlapping_targets_in_one_group_merge_rather_than_duplicate() {
        let mut builder = TargetMapBuilder::new(ports("80"));
        let ctx = TargetContext::new();

        builder.push("10.0.0.0/24", &ctx).unwrap();
        builder.push("10.0.0.5", &ctx).unwrap();
        builder.push("10.0.0.128-10.0.1.10", &ctx).unwrap();

        assert_eq!(builder.address_count(), 267, "0.0-1.10, counted once each");
        assert_eq!(builder.group_count(), 1);
    }
}
