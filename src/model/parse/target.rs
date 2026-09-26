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
//! Every way of getting targets into the engine - a file, a form field, an
//! argument list, a previous report - ends here, so the grammar is written once
//! and the formats above it only decide where the tokens come from.
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
//! The address half is handed to [`crate::model::parse::ip`], which already
//! understands literals, ranges, CIDR blocks, zones and keywords. This module
//! adds no address grammar of its own; it decides only where the address ends
//! and the ports begin.
//!
//! ## Where the ports begin
//!
//! That decision is the entire difficulty, because `:` separates ports from
//! addresses, separates an IPv6 address from itself, and - in this engine's own
//! `u:53` spelling for a UDP port - appears inside a port specification too.
//! Three rules settle it:
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
//! Rule 2 is what lets a UDP port be written without brackets. Without it,
//! `192.0.2.1:u:53` has two colons and would be read as an address - and `u:`
//! is this engine's own invention, so the collision is its own to resolve
//! rather than the user's to work around.
//!
//! The consequence worth stating plainly: **`2001:db8::1:80` is an address, not
//! port 80 on `2001:db8::1`.** It is a syntactically valid IPv6 address and
//! nothing in the token says otherwise. Brackets exist for exactly this, and a
//! caller that means the port writes `[2001:db8::1]:80`. A target with colons
//! that is neither is refused with an error saying so, rather than being tried
//! as a hostname - a hostname cannot contain a colon, so whatever its author
//! meant, they did not mean a name.
//!
//! ## Hostnames
//!
//! A target list written by a human contains hostnames, and resolving one means
//! speaking DNS - which this module must not decide to do. Whether a name may
//! be looked up at all is [`crate::config::ZondConfig::no_dns`]'s
//! business, and how it is looked up belongs to whoever built the resolver.
//!
//! So a name goes to a lookup supplied in [`TargetContext`], the same way
//! keywords and interface zones already do. A caller that supplies none gets an
//! error naming the hostname rather than a target set quietly missing it: a
//! scan that does not cover what its input said it covers is a wrong answer
//! that looks like a right one.
//!
//! The lookup is called during parsing and is therefore synchronous. A caller
//! with enough names for that to matter should parse in two passes - collect
//! them with [`TargetExpr::parse`], resolve them concurrently, then build with a
//! lookup that reads the results - which is why the expression grammar is public
//! separately from the builder.
//!
//! ## One unit per port specification
//!
//! [`TargetMapBuilder`] groups by port specification rather than emitting a
//! [`TargetSet`] per input token. A file of sixty-five thousand bare addresses
//! becomes one unit instead of sixty-five thousand units of one address each.
//! Ordering is first-seen and therefore deterministic: two runs over the same
//! input produce the same scan.
//!
//! The saving is in the number of units, not in how well the addresses merge.
//! Each [`TargetSet`] canonicalizes itself and allocates its own port vector
//! when iterated, so sixty-five thousand units means sixty-five thousand of
//! each. A file of deliberately non-adjacent addresses keeps every one of its
//! ranges and still benefits by the same amount.
//!
//! On a 65 536-line file this is roughly 1.5x faster end to end, whether or not
//! anything merged.
//!
//! ## When grouping stops paying
//!
//! Grouping buys a smaller unit count with an index lookup on every line, and
//! the trade only works while lines share specifications. A file naming a
//! distinct specification on every line groups nothing and pays the index
//! anyway, and that file is not a contrivance: it is what reading a report back
//! produces, one specification per host because each host was found on its own
//! ports. Measured over 65 536 units of that shape, a builder that keeps its
//! index takes 22.0 ms against the direct path's 12.7 ms, so the optimisation
//! inverts on the very input the import formats feed it.
//!
//! So the builder watches its own input and gives the index up when it is
//! earning nothing: see `MIN_REGROUPED_SHARE`. Past that point every
//! expression becomes a unit of its own, which is what the direct path does,
//! and the shape costs 13.4 ms instead of 22.0: 1.05x the direct path rather
//! than 0.61x, the median of nine paired runs. Every shape that does group
//! keeps its index and its speedup.
//!
//! The one thing given up is that two expressions naming the same ports no
//! longer share a unit once the index is gone. Both are still scanned, on the
//! same ports; what changes is that an address named twice is asked twice
//! rather than once, which is what a [`TargetMap`] means by counting gross.
//! That can only happen on input that had already gone a thousand expressions
//! without repeating a specification more than one time in sixteen.

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
/// Returning `None` and returning an empty vector mean the same thing to the
/// caller - there is nothing to scan under that name - and both are reported as
/// [`TargetParseError::UnknownHost`]. A resolver that distinguishes a lookup
/// failure from a name that genuinely has no records should say so through its
/// own channel; from here they are the same target, missing.
///
/// `Sync`, for the reason [`ResolverFn`] is: a caller that resolves targets
/// inside a spawned task needs the context it holds to be `Send`, and a `&` to
/// a trait object is only `Send` where the object is `Sync`.
pub type HostLookup<'a> = &'a (dyn Fn(&str) -> Option<Vec<IpAddr>> + Sync);

/// The lookups a target expression may need, and none of which this module can
/// perform for itself.
///
/// Each is optional, and an expression that needs one the caller did not supply
/// is refused rather than guessed at. That is the whole reason they are here:
/// resolving `lan`, `%en0` or a hostname means reading the host this process
/// runs on, and a parser that does that on its own behalf cannot be embedded
/// anywhere its author did not anticipate.
///
/// `#[non_exhaustive]`, which almost nothing else in this module is. This is a
/// list of the lookups the grammar may need, and the grammar learns to need new
/// ones: it has learned twice. Build one with [`new`](Self::new) and the
/// `with_*` methods, or with [`Default`], and assign the fields directly where
/// that reads better. What the marker rules out is a struct literal, which is
/// the one shape a fourth lookup would break.
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
    /// Reports which lookups are present rather than trying to describe them,
    /// since what a caller debugging a refused target needs to know is which
    /// resolver was missing.
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
/// Every variant carries the expression it is about. An importer reading a file
/// reports the line as well, and between the two a user can find what to fix
/// without re-reading their own input.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TargetParseError {
    /// The token was empty.
    #[error("a target expression cannot be empty")]
    Empty,

    /// The token held nothing but whitespace.
    ///
    /// Its own variant because a token of spaces looks exactly like the gap
    /// between two arguments, so a reader is checking a command line whose every
    /// word is plainly there.
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
    /// Reported instead of treating it as a hostname, because it is a typo:
    /// `192.0.2.300`, `10.10.10.*` and `10.10.10.0/` are each an address or a
    /// range written wrong. Offering one to a lookup would send the range to a
    /// resolver, and calling it an unresolvable name would send its author to
    /// look at their DNS.
    #[error("'{0}': not a valid address, range or hostname")]
    MistypedAddress(String),

    /// Something with colons in it that is neither an address nor bracketed.
    ///
    /// Reported instead of treating it as a hostname, because a hostname cannot
    /// contain a colon: whatever the author meant, they did not mean a name.
    /// Almost always an IPv6 target that needs brackets to carry its ports.
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
    /// A keyword is how it is reached: a [`ResolverFn`] that returns without
    /// inserting an address, which is the honest answer for `lan` on a host that
    /// has no LAN. Distinct from [`Empty`](Self::Empty), which is a token with
    /// no expression in it, and from [`UnknownHost`](Self::UnknownHost), which
    /// is a name nothing answered to.
    ///
    /// Reported as `Empty` this would say "a target expression cannot be empty"
    /// about `lan`, which is neither empty nor the problem. The engine's own
    /// resolver always inserts on success, so it takes a caller supplying their
    /// own to reach, which is every consumer of this crate that is not the CLI.
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
    /// Surrounding whitespace is trimmed. The halves are *not* validated - this
    /// decides only where the boundary is, and both sides are checked by the
    /// grammars that own them when the expression is built into targets.
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

        // A dot before the first colon settles it: no IPv6 address can have
        // one. Every dotted form IPv6 has - `::ffff:192.0.2.1` and its
        // relatives - puts the dots in the last 32 bits, after at least one
        // colon. So a dot first means IPv4, or a dotted hostname, and every
        // colon after the first belongs to the ports.
        //
        // This is what lets a UDP port be written without brackets.
        // `192.0.2.1:u:53` has two colons and is not an address; without this
        // rule it would be read as one, and `u:` is this engine's own spelling
        // so the collision is its own to resolve.
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

        // No colon at all, or two or more with no dot in front of them: an
        // address, whole, with no ports. There is no other reading of
        // `2001:db8::1`.
        Ok(Self {
            address: token,
            ports: None,
        })
    }

    /// The addresses the expression names, splitting the address half on commas.
    ///
    /// A comma is a separator in the address half and part of the specification
    /// in the port half, and the ambiguity resolves itself once the two are
    /// apart: `192.0.2.1:80,443` is one host on two ports, while
    /// `192.0.2.1,192.0.2.2:80` is two hosts on one. Both readings are what the
    /// author of either expression meant, and neither is reachable by a rule
    /// applied to the token as a whole.
    ///
    /// Empty fields are skipped, so a trailing comma is untidy rather than an
    /// error.
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
/// The index is not worth measuring while it is this small. A thousand entries
/// is a few tens of kilobytes and around a tenth of a millisecond of work, so
/// nothing is lost by waiting, and what the wait buys is a reading taken from
/// enough of a file to act on. The judgement below is made once and never
/// revised, which is the whole reason it is not made on the first few lines.
const GROUPING_SAMPLE: usize = 1_024;

/// How little regrouping [`TargetMapBuilder`] will put up with before it stops
/// paying for an index: fewer than one expression in this many joining a group
/// that already existed.
///
/// Grouping trades a lookup on every expression against the number of units the
/// map ends up with. Measured, the two paths cross somewhere between four and
/// eight lines to each port specification, and a file naming a
/// distinct specification on every line has lost outright, taking 22.0 ms where
/// the direct path takes 12.7 ms for the same units.
///
/// Sixteen, rather than the one or two that would sit at the crossing, because
/// the reading is taken from a prefix and cannot be taken back. A file drawing
/// its specifications from a pool repeats them at a rate this rule sees within
/// its first thousand lines, and asking for only one repeat in sixteen means a
/// pool smaller than about eight thousand keeps its index: past that the pool
/// is large enough that grouping was not going to pay anyway. What no prefix can
/// see is a file that spends its opening thousand lines on distinct
/// specifications and repeats them only much later, and such a file does give
/// its index up. It ends no worse off than the direct path it falls back to.
const MIN_REGROUPED_SHARE: usize = 16;

/// Accumulates target expressions into a [`TargetMap`], one unit per distinct
/// port specification for as long as that is worth doing.
///
/// Built incrementally rather than from a slice, so an importer can stream a
/// file of any size through it and so a caller can decide for itself what to do
/// with an expression that is refused.
///
/// Grouping is abandoned on input that does not group: see
/// `MIN_REGROUPED_SHARE` for the rule, and the module documentation for why the
/// builder degrades rather than inverting.
#[derive(Debug, Clone)]
pub struct TargetMapBuilder {
    /// The ports an expression that names none is scanned on.
    default_ports: PortSet,
    /// The groups, in the order their port specification was first seen, so
    /// that two runs over the same input scan in the same order.
    groups: Vec<(PortSet, IpSet)>,
    /// Where each port specification's group sits in `groups`, while grouping
    /// is still earning its keep.
    ///
    /// A map rather than a scan over `groups`, because the number of distinct
    /// port specifications in a file is not bounded by anything: input nobody
    /// vouches for should not be able to make this quadratic.
    ///
    /// `None` once `MIN_REGROUPED_SHARE` says the grouping is buying nothing.
    /// Taken rather than emptied, so a file that does not group stops paying
    /// for the index's memory as well as for its lookups.
    index: Option<HashMap<PortSet, usize>>,
    /// How many expressions have been accepted, which the rule above reads
    /// against the group count.
    accepted: usize,
    /// Addresses accumulated so far, before overlapping expressions are merged.
    ///
    /// Kept as a running total rather than computed on demand, because it is
    /// read once per expression and anything read that often has to be free.
    /// See [`gross_address_count`](Self::gross_address_count).
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
    /// Nothing is added when the expression is refused, so a caller that logs
    /// the error and carries on ends up with exactly the targets that parsed.
    pub fn push(&mut self, token: &str, ctx: &TargetContext<'_>) -> Result<(), TargetParseError> {
        let expr = TargetExpr::parse(token)?;

        let ports = match expr.ports {
            Some(spec) => PortSet::parse_scan(spec).map_err(|source| TargetParseError::Ports {
                expression: token.trim().to_string(),
                source,
            })?,
            None => self.default_ports.clone(),
        };

        // Resolved into a set of its own first. A hostname that resolves to
        // nothing, or an address that does not parse, must leave the builder
        // exactly as it was rather than half-populating a group.
        let mut resolved = IpSet::new();
        for address in expr.addresses() {
            match insert_expression(address, &mut resolved, ctx.keywords, ctx.zones) {
                Ok(()) => {}
                // The one error that means "this is not an address" rather than
                // "this address is wrong", and so the one worth trying as a name.
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

        // Counted from this expression's own ranges, which are a handful at
        // most, rather than from the accumulated set - see
        // `gross_address_count` for what re-reading the whole set per line cost.
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
    /// The two constants carry the argument. Nothing here can be undone: once
    /// the index is gone the groups already built stay as they are, and every
    /// expression after this one becomes a unit of its own.
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
    /// This is the number of units [`build`](Self::build) will produce, and on
    /// input that groups it is the number of distinct port specifications seen:
    /// a property of the input's shape rather than of its size.
    ///
    /// On input that does not group it is the number of expressions accepted,
    /// because a builder that has given the index up makes a unit of each. The
    /// module documentation has when that happens and why.
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// How many addresses have accumulated across every group, counting an
    /// address once per group it appears in.
    ///
    /// Merges ranges to answer, so an expression naming a block counts what the
    /// block holds rather than what was written. This is what a caller checks a
    /// scan-size budget against: `::/0` costs nothing to hold and 2^128
    /// addresses to scan, and the difference is only visible here.
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
    /// The cheap counterpart to [`address_count`](Self::address_count), and
    /// cheap is the entire point of it: a running total kept as expressions
    /// arrive, returned in constant time.
    ///
    /// A caller checking a budget does so once per expression, so anything this
    /// walks - the groups, or the ranges inside them - it walks once per line of
    /// the file. Walking the accumulated ranges here made importing a 65 536
    /// line list take 3.2 seconds against 6.9 milliseconds for the same file
    /// through [`push`](Self::push) alone, and the cost grew with the square of
    /// the line count. Measured.
    ///
    /// Never lower than the true count, so a budget checked against it refuses
    /// early rather than late.
    pub fn gross_address_count(&self) -> u128 {
        self.gross_addresses
    }

    /// Whether anything scannable has accumulated.
    ///
    /// Which is whether any group exists. [`push`](Self::push) refuses an
    /// expression that named no addresses before a group is created or joined,
    /// and nothing removes addresses from one afterwards, so a group holds at
    /// least one address for as long as it exists.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Finishes the map.
    ///
    /// Every group becomes a unit. There is no empty one to skip, for the reason
    /// [`is_empty`](Self::is_empty) gives: `push` refuses the expression that
    /// would produce one, even for a caller that collects errors and carries
    /// on.
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
/// [`IpParseError::Malformed`] says only "this is not an address". Plenty of
/// tokens reach that verdict and are still not names, and telling the author
/// what they wrote is worth more than a lookup that was always going to fail.
///
/// ## Only something shaped like a name is a name
///
/// A token is offered to a lookup only when it could be a host name: letters,
/// digits, `-`, `_` and dots, with a last label holding at least one letter.
/// Everything else is an address or a range with a slip in it.
///
/// The rule is drawn from the name's side because the typos are open-ended and
/// the names are not. `10.10.10.*`, `10.10.1-5.1-254`, `10.10.10.0/` and `/0`
/// fail in four different ways, and a list of ways to fail would be missing
/// the fifth. What they share is that no name looks like them, and a lookup
/// handed one does not refuse it: the system resolver accepts `*` and `-` in a
/// label and asks upstream, which tells a resolver somebody else operates the
/// range a scan was aimed at before failing with "no such host".
///
/// The last label is the top-level domain, or the whole name when it has one
/// label, and RFC 1123 section 2.1 settles it: a host name's highest-level
/// label is alphabetic, which is what keeps a name from ever reading as a
/// dotted address. A letter anywhere in it is asked for rather than a letter
/// first, so a single-label name like `nas-1` still resolves. `_` is allowed
/// because hosts named with one exist on real networks and a resolver may
/// answer for them; `*`, `/`, `%` and the rest are allowed by no naming scheme
/// a resolver answers for. Letters and digits are not only ASCII, so a name
/// written in its own script reaches a lookup that may know how to encode it.
///
/// ## Both passes ask this
///
/// That is the point of it being a function. The synchronous build asks before
/// it consults the lookup, and `resolve::targets`'s collection pass asks before
/// it puts a name on the network. Written out once each, the two would
/// disagree: a collector taking `Malformed` as the whole answer turns a
/// mistyped address into a query to a resolver somebody else operates, which
/// the builder then refuses without ever looking it up.
pub(crate) fn host_name(token: &str) -> HostName {
    // A token with a colon in it is not a name. When what follows its last
    // colon is a port specification, the author almost certainly wrote an
    // IPv6 target and its ports without brackets, and the error for that says
    // how to write it. Anything else after the colon is an IPv6 address or
    // range that is wrong, where advice about brackets would mislead.
    if let Some((_, tail)) = token.rsplit_once(':') {
        return if PortSet::try_from(tail).is_ok() {
            HostName::Unbracketed
        } else {
            HostName::Mistyped
        };
    }

    let name_character = |c: char| c.is_alphanumeric() || matches!(c, '-' | '_' | '.');
    // One trailing dot is how a fully qualified name is written, and it leaves
    // an empty last label that says nothing about the name.
    let last_label = token
        .strip_suffix('.')
        .unwrap_or(token)
        .rsplit('.')
        .next()
        .unwrap_or_default();

    if token.chars().all(name_character) && last_label.chars().any(char::is_alphabetic) {
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
/// The convenience over driving [`TargetMapBuilder`] directly is small, and it
/// is the right shape for a caller that already has every target in memory and
/// wants the first error rather than all of them.
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

    /// A context crosses a thread, which is what a caller resolving targets
    /// inside a spawned task needs.
    ///
    /// The three hooks are borrowed trait objects, and a `&` to one is `Send`
    /// only where the object is `Sync`. Without that, every future that resolves
    /// a target is pinned to the thread that made it: no cost to a caller doing
    /// one thing at a time, and the difference between working and not for a
    /// front end serving more than one request at once.
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

    /// Splitting at the first colon would read `fe80::1` as host `fe80` on
    /// port `:1`, which fails to parse and drops the target entirely. This
    /// covers every shape that mistake can take.
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

    /// Brackets are the only way to write ports on an IPv6 target, so they have
    /// to work for every address form that can carry them.
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

    /// `u:` is this engine's own spelling for a UDP port, and it puts a second
    /// colon in a token that already uses one as a separator. A rule that read
    /// every multi-colon token as IPv6 would make a UDP port unwritable on an
    /// IPv4 target without brackets - which is what a user types first, and what
    /// a plain reading of the grammar promises them.
    ///
    /// A dot before the first colon settles it: no IPv6 address can have one,
    /// because every dotted IPv6 form puts its dots in the last 32 bits, after
    /// at least one colon.
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

        // And the rule it must not break: an IPv6 address is still whole.
        for token in ["2001:db8::1", "::ffff:192.0.2.1", "2001:db8::192.0.2.1"] {
            let expr = TargetExpr::parse(token).expect("parses");
            assert_eq!(expr.address, token, "{token} was split");
            assert_eq!(expr.ports, None, "{token} acquired ports");
        }
    }

    /// A hostname cannot contain a colon, so whatever the author of one meant,
    /// they did not mean a name. Reporting it as an unresolvable host would send
    /// them looking for a DNS problem they do not have.
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

    /// A malformed expression has to be refused rather than silently read as
    /// something narrower - `192.0.2.1:` scanning the default ports would be
    /// a scan the user did not ask for.
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
        // A token of spaces is its own answer: it looks like the gap between two
        // arguments on screen, so the message names what it actually got.
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

    /// A port half that names no ports is refused, as the empty one is:
    /// `192.0.2.1:,` scanning nothing would finish without a word, and
    /// scanning the defaults would be a scan nobody wrote.
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

    /// The property the builder exists for. One unit per port specification,
    /// not one per input token: the difference between a scan iterating a
    /// vector of one and a vector of two hundred and fifty-six.
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
        // 256 contiguous addresses on one port: the IpSet merged them into a
        // single range on the way in.
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

    /// Two spellings of one port set are one group, which is what deriving
    /// `Hash` on the canonicalized `PortSet` buys.
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
    /// A [`ResolverFn`] belongs to the caller, and one that returns without
    /// inserting is the honest answer for `lan` on a host with no LAN. Reported
    /// as [`TargetParseError::Empty`], it would carry the message "a target
    /// expression cannot be empty", said about the word `lan`. The engine's own
    /// resolver always inserts on success, so only a consumer supplying its own
    /// can meet it, which is every consumer that is not the CLI.
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

        // And a token with nothing written in it keeps its own error.
        assert_eq!(
            builder.push("   ", &ctx).expect_err("nothing was written"),
            TargetParseError::Blank(3, "s")
        );
        assert_eq!(
            builder.push("", &ctx).expect_err("nothing was written"),
            TargetParseError::Empty
        );
    }

    /// A hostname with no lookup must be an error. Skipping it would produce a
    /// scan that covers less than its input said, with nothing to show for it.
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

    /// An address that is wrong is not a hostname. Falling through to a lookup
    /// would turn a typo'd prefix into a DNS query for `192.0.2.1/33`.
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

    /// A range with a slip in it is not a hostname either. Offered to a
    /// lookup, `10.10.10.*` becomes a query that tells a resolver somebody
    /// else runs which network is being scanned, and then fails as a name the
    /// author never meant to write.
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
        ] {
            let mut builder = TargetMapBuilder::new(ports("80"));
            let err = builder.push(token, &ctx).expect_err(token);

            assert!(
                matches!(err, TargetParseError::MistypedAddress(ref t) if t == token),
                "{token}: {err:?}"
            );
            // The collection pass that resolves names concurrently asks the
            // same question before it puts anything on the network.
            assert_eq!(host_name(token), HostName::Mistyped, "{token}");
        }
    }

    /// The other half of the rule above: whatever a resolver would plausibly
    /// answer for is still asked, including forms the rule has to step round,
    /// a fully qualified name's trailing dot and a label that is not ASCII.
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
        ] {
            assert_eq!(host_name(name), HostName::Yes, "{name}");
        }

        // A colon with a port specification after it is an IPv6 target that
        // wanted brackets, which is the one case that error's advice fits.
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

    /// The zone has to survive the split, or a link-local target with ports
    /// scans whichever segment the engine happens to pick.
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

    /// A resolver is whatever the caller has, not whatever fits in a function
    /// pointer. The host's interface table is read once and closed over here,
    /// which is the shape a caller resolving thousands of targets needs and
    /// which `fn(&str) -> Option<u32>` cannot express. Under that signature this
    /// does not compile and the lookup has to become a global.
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

    /// The running total has to equal what walking the accumulated groups would
    /// have said, or the budget it feeds is checking a number of its own
    /// invention.
    ///
    /// Kept as a total because reading it costs nothing that way and it is read
    /// once per line of a file; the equality below is what a future change that
    /// adds ranges by some other route would break.
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
        // And it is an over-count of the merged figure, never an under-count,
        // which is the direction a budget has to err in.
        assert!(builder.gross_address_count() >= builder.address_count());
    }

    /// A CIDR block is an upper bound on scan size that its written form hides
    /// completely, and the budget a caller enforces is the only thing between a
    /// one-line file and a scan of the whole address space.
    #[test]
    fn address_count_reports_what_a_block_holds_not_what_was_written() {
        let mut builder = TargetMapBuilder::new(ports("80"));
        builder.push("10.0.0.0/8", &TargetContext::new()).unwrap();

        assert_eq!(builder.address_count(), 16_777_216);

        let mut everything = TargetMapBuilder::new(ports("80"));
        everything.push("::/0", &TargetContext::new()).unwrap();
        assert_eq!(everything.address_count(), u128::MAX);
    }

    /// A comma separates addresses on the left of the port separator and ports
    /// on the right of it. Both readings are common in a hand-written target
    /// list, and no rule applied to the whole token can reach both.
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
    /// Computed here rather than taken from the builder, so that a test
    /// comparing the two is not asking the builder to vouch for itself.
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

    /// Every unit of a map, as the ports it asks about and the targets it
    /// yields. Enough to tell two maps apart by what they would scan.
    fn units_of(map: &TargetMap) -> Vec<(PortSet, Vec<Target>)> {
        map.units
            .iter()
            .map(|unit| (unit.ports().clone(), unit.iter().collect()))
            .collect()
    }

    /// The threshold changes how the builder works, and must not change what
    /// it produces. Built at three lengths, one short of the sample and two
    /// past it, and checked against a grouping computed in the test.
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

    /// The shape the threshold exists for: a distinct specification on every
    /// line, which is what reading a report back produces. Once the index is
    /// given up a specification already seen gets a unit of its own, and from
    /// outside the builder that is the only way to see it happened.
    #[test]
    fn a_file_that_never_groups_gives_the_index_up() {
        let mut builder = TargetMapBuilder::new(ports("80"));
        let ctx = TargetContext::new();

        for i in 0..GROUPING_SAMPLE {
            let token = format!("10.0.{}.{}:{}", i / 256, i % 256, 1 + i);
            builder.push(&token, &ctx).expect("parses");
        }
        assert_eq!(builder.group_count(), GROUPING_SAMPLE);

        // Port 1 has had a group since the first line. With the index gone it
        // gets a second rather than joining it.
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

    /// The other half of the rule. A file that does group must not lose its
    /// index for being long, since that is where the whole saving is.
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

    /// The rule itself, from both sides. One line in eight repeating the
    /// specification before it is thin grouping and still grouping, and the
    /// shapes that gain from an index are the ones the rule must leave alone.
    /// One line in thirty-two is not enough to be worth an index.
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
