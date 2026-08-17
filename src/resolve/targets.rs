// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Resolving a whole target list
//!
//! The two-pass bridge between synchronous parsing and asynchronous resolution.
//! [`collect_names`] finds the names in a list of target expressions by asking
//! the address grammar which halves it cannot make an address of; those are
//! resolved concurrently, and the answers feed the
//! [`HostLookup`](crate::model::parse::target::HostLookup) the second pass reads.
//!
//! Nothing here re-implements the grammar. A name is exactly what
//! [`insert_expression`] rejects as [`IpParseError::Malformed`] — the same
//! signal [`TargetMapBuilder`](crate::model::parse::target::TargetMapBuilder)
//! uses to decide a token is worth resolving — so the classification cannot drift
//! from the one the builder applies when it later consumes the same input.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use tokio::task::JoinSet;

use crate::model::ip::set::IpSet;
use crate::model::parse::ip::{IpParseError, ResolverFn, ZoneResolverFn, insert_expression};
use crate::model::parse::target::{self, TargetContext, TargetExpr, TargetParseError};
use crate::model::port::PortSet;
use crate::model::target::TargetMap;

use super::Resolver;

/// How many names are resolved at once.
///
/// An mDNS lookup holds a socket open for the length of its reply window, so the
/// ceiling bounds how many sockets a list of `.local` names opens at a time
/// rather than letting a large file open one per name. Unicast lookups are far
/// cheaper, but sharing one ceiling keeps the pass simple, and the network, not
/// this number, is the limit that matters for them.
const MAX_CONCURRENT_LOOKUPS: usize = 16;

/// Resolves every name in `exprs` concurrently, returning a map from each name
/// to the addresses it stands for.
///
/// A name nothing answered for is absent from the map rather than present with
/// an empty list, so a caller can tell "resolved to nothing" from "resolved" by
/// membership alone. This is the pass to run when a caller wants to build the
/// [`TargetMap`] itself, or to move the work across threads: the returned map is
/// owned, where the [`TargetContext`] this reads borrows the caller's keyword
/// and zone resolvers and so cannot cross a thread boundary.
pub async fn resolve_names<S: AsRef<str>>(
    exprs: &[S],
    ctx: &TargetContext<'_>,
    resolver: &Resolver,
) -> HashMap<String, Vec<IpAddr>> {
    let names = collect_names(exprs, ctx);
    resolve_all(names, resolver).await
}

/// Parses `exprs` into a [`TargetMap`], resolving any hostnames along the way.
///
/// The asynchronous counterpart to
/// [`target::to_target_map`](crate::model::parse::target::to_target_map): it
/// resolves first, then builds with a lookup that reads the results, so a name
/// becomes the addresses it stands for instead of the error an unresolved one
/// would raise.
///
/// The returned future borrows `ctx`, and so is only as `Send` as the keyword
/// and zone resolvers `ctx` holds — which are `&dyn Fn` and need not be. A
/// caller that must move the work across threads resolves with [`resolve_names`]
/// and builds synchronously from the owned map it returns.
pub async fn to_target_map<S: AsRef<str>>(
    exprs: &[S],
    default_ports: PortSet,
    ctx: &TargetContext<'_>,
    resolver: &Resolver,
) -> Result<TargetMap, TargetParseError> {
    let resolved = resolve_names(exprs, ctx, resolver).await;

    // Read by the builder's second pass; owns its addresses so it outlives no
    // borrow of the map.
    let lookup = |name: &str| resolved.get(name).cloned();
    let ctx = TargetContext {
        keywords: ctx.keywords,
        zones: ctx.zones,
        hosts: Some(&lookup),
    };

    target::to_target_map(exprs, default_ports, &ctx)
}

/// Resolves `exprs` into a single [`IpSet`], for the discovery phase, which asks
/// only whether a host is there and has no use for ports.
///
/// The convenience over [`to_target_map`] for a caller feeding
/// [`discover`](crate::scanner::discover): a name resolves the same way, and the
/// ports every expression is grouped by are discarded rather than carried.
/// Reports a [`TargetParseError`] — richer than the address grammar's own error,
/// since it can name a host that would not resolve.
pub async fn to_set<S: AsRef<str>>(
    exprs: &[S],
    keywords: Option<ResolverFn<'_>>,
    zones: Option<ZoneResolverFn<'_>>,
    resolver: &Resolver,
) -> Result<IpSet, TargetParseError> {
    let ctx = TargetContext {
        keywords,
        zones,
        hosts: None,
    };

    // The port specification is immaterial here: it only groups addresses, and
    // they are unioned back together below regardless of which group they fell
    // into.
    let map = to_target_map(exprs, PortSet::default(), &ctx, resolver).await?;

    let mut set = IpSet::new();
    for unit in &map.units {
        for range in unit.ips().v4() {
            set.push_v4_range(*range);
        }
        for range in unit.ips().v6() {
            set.push_v6_range(*range);
        }
    }
    set.canonicalize();

    Ok(set)
}

/// Every distinct hostname named across `exprs`, in first-seen order.
///
/// A name is an address half the grammar rejects as
/// [`IpParseError::Malformed`], which is precisely what the builder treats as a
/// name to look up. Every other rejection — a wrong address, a keyword with no
/// resolver, a zone on a global address — is an error about something that was
/// meant to be an address, and is left for the build pass to report against the
/// expression it belongs to. A token that will not even split is skipped for the
/// same reason: the builder will raise it verbatim.
fn collect_names<S: AsRef<str>>(exprs: &[S], ctx: &TargetContext<'_>) -> Vec<String> {
    let mut names = Vec::new();
    let mut seen = HashSet::new();

    for token in exprs {
        let Ok(expr) = TargetExpr::parse(token.as_ref()) else {
            continue;
        };

        for address in expr.addresses() {
            let mut throwaway = IpSet::new();
            if let Err(IpParseError::Malformed(_)) =
                insert_expression(address, &mut throwaway, ctx.keywords, ctx.zones)
                && seen.insert(address.to_string())
            {
                names.push(address.to_string());
            }
        }
    }

    names
}

/// Resolves a list of names concurrently, at most [`MAX_CONCURRENT_LOOKUPS`] in
/// flight, keeping only those that resolved to something.
async fn resolve_all(names: Vec<String>, resolver: &Resolver) -> HashMap<String, Vec<IpAddr>> {
    let mut resolved = HashMap::new();
    if names.is_empty() {
        return resolved;
    }

    let mut set: JoinSet<(String, Vec<IpAddr>)> = JoinSet::new();
    let mut pending = names.into_iter();

    for name in pending.by_ref().take(MAX_CONCURRENT_LOOKUPS) {
        spawn_lookup(&mut set, resolver, name);
    }

    while let Some(joined) = set.join_next().await {
        if let Ok((name, addresses)) = joined
            && !addresses.is_empty()
        {
            resolved.insert(name, addresses);
        }

        if let Some(name) = pending.next() {
            spawn_lookup(&mut set, resolver, name);
        }
    }

    resolved
}

/// Spawns one lookup, cloning the resolver into the task so the set owns it.
fn spawn_lookup(set: &mut JoinSet<(String, Vec<IpAddr>)>, resolver: &Resolver, name: String) {
    let resolver = resolver.clone();
    set.spawn(async move {
        let addresses = resolver.resolve(&name).await;
        (name, addresses)
    });
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
    use crate::model::parse::ip::Keyword;

    /// A keyword resolver that expands `lan` to one address, so a list mixing a
    /// keyword, literals and names can be classified the way the builder would.
    fn keywords(keyword: Keyword, set: &mut IpSet) -> Result<(), IpParseError> {
        match keyword {
            Keyword::Lan => {
                set.insert("192.168.1.1".parse().expect("a valid address"));
                Ok(())
            }
        }
    }

    /// The whole point of the classification: names are picked out and nothing
    /// else is. A literal, a range, a CIDR block and a resolvable keyword are all
    /// addresses the grammar handles, and only the two hostnames are left for
    /// resolution — carrying their ports stripped, since a name is the address
    /// half alone.
    #[test]
    fn only_the_hostnames_in_a_mixed_list_are_collected() {
        let ctx = TargetContext::new().with_keywords(&keywords);

        let exprs = [
            "192.168.1.10",
            "example.com:443",
            "10.0.0.0/24",
            "raspberrypi.local",
            "10.0.0.1-10",
            "lan",
        ];

        assert_eq!(
            collect_names(&exprs, &ctx),
            vec!["example.com".to_string(), "raspberrypi.local".to_string()]
        );
    }

    /// A name written twice, or on two ports, is one name to resolve. Order is
    /// first-seen so a run over the same input resolves in the same order.
    #[test]
    fn a_repeated_name_is_collected_once() {
        let ctx = TargetContext::new();

        let exprs = ["host.example:80", "host.example:443", "host.example"];

        assert_eq!(
            collect_names(&exprs, &ctx),
            vec!["host.example".to_string()]
        );
    }

    /// The comma-separated address half is split before classification, so a
    /// single token naming a literal and a name yields just the name.
    #[test]
    fn names_are_found_inside_a_comma_list() {
        let ctx = TargetContext::new();

        assert_eq!(
            collect_names(&["10.0.0.1,db.internal:5432"], &ctx),
            vec!["db.internal".to_string()]
        );
    }

    /// A keyword with no resolver is rejected by the grammar, but not as
    /// `Malformed`, so it is never mistaken for a hostname and sent to a
    /// resolver that would report "no such host" for it.
    #[test]
    fn a_keyword_without_a_resolver_is_not_taken_for_a_name() {
        let ctx = TargetContext::new();
        assert!(collect_names(&["lan"], &ctx).is_empty());
    }

    /// An empty list resolves to an empty map with no tasks spawned, so the
    /// common case of a list with no names at all costs nothing.
    #[tokio::test]
    async fn resolving_no_names_yields_an_empty_map() {
        let resolver = Resolver::from_system();
        assert!(resolve_all(Vec::new(), &resolver).await.is_empty());
    }

    /// A list of literals reaches `to_set` without a name to resolve, so it
    /// touches no network — which is what makes this seam testable offline. What
    /// it pins is the union: expressions land in separate port groups, and
    /// `to_set` has to fold every group's addresses back into one set across
    /// both families rather than returning only the last group's.
    #[tokio::test]
    async fn to_set_unions_every_group_across_both_families() {
        let resolver = Resolver::from_system();

        let set = to_set(
            &["10.0.0.1:80", "10.0.0.2:443", "2001:db8::1"],
            None,
            None,
            &resolver,
        )
        .await
        .expect("literals resolve without a lookup");

        assert_eq!(set.len(), 3);
        assert!(set.contains(&"10.0.0.1".parse().unwrap()));
        assert!(set.contains(&"10.0.0.2".parse().unwrap()));
        assert!(set.contains(&"2001:db8::1".parse().unwrap()));
    }
}
