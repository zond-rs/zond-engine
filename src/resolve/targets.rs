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
//! A name is what [`insert_expression`] rejects as [`IpParseError::Malformed`],
//! the same signal
//! [`TargetMapBuilder`](crate::model::parse::target::TargetMapBuilder) uses to
//! decide a token is worth resolving, so the two classifications cannot
//! drift apart.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use tokio::task::JoinSet;

use crate::config::ZondConfig;
use crate::model::exclusion::Exclusions;
use crate::model::ip::set::IpSet;
use crate::model::parse::ip::{
    IpParseError, Keyword, ResolverFn, ZoneResolverFn, insert_expression, names_keyword,
};
use crate::model::parse::target::{self, TargetContext, TargetExpr, TargetParseError};
use crate::model::port::PortSet;
use crate::model::target::TargetMap;
use crate::system::interface;
use crate::warn;

use super::{Resolver, Snapshot};

/// How many names are resolved at once.
///
/// An mDNS lookup holds a socket open for its whole reply window, so this bounds
/// how many sockets a list of `.local` names opens at a time. Unicast lookups
/// are far cheaper and share the same ceiling for simplicity.
const MAX_CONCURRENT_LOOKUPS: usize = 16;

/// Resolves every name in `exprs` concurrently, returning a map from each name
/// to the addresses it stands for.
///
/// A name nothing answered for is absent from the map, so membership alone
/// tells "resolved" from "resolved to nothing". This is the pass to run when a
/// caller builds the [`TargetMap`] itself or moves the work across threads: it
/// borrows only its arguments and returns an owned map, while the
/// [`TargetContext`] the build reads borrows the caller's keyword and zone
/// resolvers and cannot cross a thread boundary.
///
/// No keyword or zone is looked up here. Whether a token is a name is decided
/// by how it is written; see `collect_names`.
pub async fn resolve_names<S: AsRef<str>>(
    exprs: &[S],
    resolver: &Resolver,
) -> HashMap<String, Vec<IpAddr>> {
    let names = collect_names(exprs);
    resolve_all(names, resolver).await
}

/// Parses `exprs` into a [`TargetMap`], resolving any hostnames along the way.
///
/// The asynchronous counterpart to [`target::to_target_map`]: it resolves
/// first, then builds with a lookup that reads the results.
///
/// The returned future borrows `ctx`, so it is only `Send` if the keyword and
/// zone resolvers `ctx` holds are, and as `&dyn Fn` they need not be. A caller
/// that must move the work across threads resolves with [`resolve_names`] and
/// builds synchronously from the owned map it returns.
pub async fn to_target_map<S: AsRef<str>>(
    exprs: &[S],
    default_ports: PortSet,
    ctx: &TargetContext<'_>,
    resolver: &Resolver,
) -> Result<TargetMap, TargetParseError> {
    let resolved = resolve_names(exprs, resolver).await;

    let lookup = |name: &str| resolved.get(name).cloned();
    let ctx = TargetContext {
        keywords: ctx.keywords,
        zones: ctx.zones,
        hosts: Some(&lookup),
    };

    target::to_target_map(exprs, default_ports, &ctx)
}

/// What a port scan was asked to cover: the plan, and the name each address
/// was reached by where an expression named a host.
///
/// A [`TargetMap`] holds only addresses, so the names travel beside it. A web
/// port on an address a name led to is asked for by that name; drop the names
/// and every virtual host answers with its default site.
#[derive(Debug, Clone)]
pub struct PortScanTargets {
    map: TargetMap,
    names: BTreeMap<IpAddr, String>,
}

impl PortScanTargets {
    /// The plan, for [`scan`](crate::scanner::scan).
    pub fn map(&self) -> &TargetMap {
        &self.map
    }

    /// Takes the plan, for handing to [`scan`](crate::scanner::scan).
    pub fn into_map(self) -> TargetMap {
        self.map
    }

    /// The name each address was reached by, where an expression named a
    /// host; see [`ZondConfig::target_names`].
    pub fn names(&self) -> &BTreeMap<IpAddr, String> {
        &self.names
    }

    /// Writes what these targets imply into `cfg`: the names, into
    /// [`target_names`](ZondConfig::target_names).
    pub fn apply_to(&self, cfg: &mut ZondConfig) {
        cfg.target_names = self.names.clone();
    }

    /// The same plan with `ports` in place of the empty set on every group
    /// that has none, which in a plan [`for_request`] built are the targets
    /// written without a port half.
    #[cfg(feature = "import-request")]
    pub(crate) fn with_unported_on(&self, ports: &PortSet) -> Self {
        let mut map = TargetMap::new();
        for unit in &self.map.units {
            if unit.ports().is_empty() {
                map.add_unit(crate::model::target::TargetSet::new(
                    unit.ips().clone(),
                    ports.clone(),
                ));
            } else {
                map.add_unit(unit.clone());
            }
        }
        Self {
            map,
            names: self.names.clone(),
        }
    }
}

/// Resolves target expressions once into a discovery sweep's input and a port
/// scan's plan, for a caller that settles the ports of an unported target
/// later, as a scan request does.
///
/// The plan keeps the ports each expression wrote and groups every expression
/// that wrote none under the empty set, which no written port half can produce.
/// [`PortScanTargets::with_unported_on`] gives those the ports settled later.
/// A single pass, so a name is looked up once and both halves hold the same
/// answer.
#[cfg(feature = "import-request")]
pub(crate) async fn for_request<S: AsRef<str>>(
    exprs: &[S],
    names: Option<&Resolver>,
) -> Result<(DiscoveryTargets, PortScanTargets), TargetParseError> {
    let ctx = TargetContext {
        keywords: Some(&interface::resolve_keyword),
        zones: Some(&interface::resolve_zone),
        hosts: None,
    };
    let plan = for_port_scan(exprs, PortSet::new(), &ctx, names).await?;
    let discovery = DiscoveryTargets {
        ips: ips_of(&plan.map),
        segment_sweep: names_keyword(exprs, Keyword::Lan),
    };
    Ok((discovery, plan))
}

/// Parses `exprs` into a port scan's plan, resolving any hostnames under the
/// caller's DNS policy and keeping the name each address was reached by.
///
/// [`to_target_map`] with the names kept. `names` is the DNS policy, as on
/// [`for_discovery`]: `None` refuses every name, and the targets then carry
/// none.
pub async fn for_port_scan<S: AsRef<str>>(
    exprs: &[S],
    default_ports: PortSet,
    ctx: &TargetContext<'_>,
    names: Option<&Resolver>,
) -> Result<PortScanTargets, TargetParseError> {
    let Some(resolver) = names else {
        let map = target::to_target_map(exprs, default_ports, ctx)?;
        return Ok(PortScanTargets {
            map,
            names: BTreeMap::new(),
        });
    };

    let written = collect_names(exprs);
    let resolved = resolve_all(written.clone(), resolver).await;
    let lookup = |name: &str| resolved.get(name).cloned();
    let with_lookup = TargetContext {
        keywords: ctx.keywords,
        zones: ctx.zones,
        hosts: Some(&lookup),
    };
    let map = target::to_target_map(exprs, default_ports, &with_lookup)?;

    Ok(PortScanTargets {
        map,
        names: names_by_address(&written, &resolved),
    })
}

/// The name each resolved address was reached by: the first written where
/// several led to one address, so the result does not depend on which lookup
/// answered first.
///
/// Kept as the target wrote it, less the trailing dot of a fully qualified
/// name, which a `Host` header and a TLS server name both leave off.
///
/// A later name sharing an address goes unasked there (no `Host` header or
/// server name carries it, and no certificate is checked against it), so it is
/// reported at the first verbosity, once per name. See
/// [`ZondConfig::target_names`] for why one name is kept per address.
fn names_by_address(
    written: &[String],
    resolved: &HashMap<String, Vec<IpAddr>>,
) -> BTreeMap<IpAddr, String> {
    let mut names: BTreeMap<IpAddr, String> = BTreeMap::new();
    for name in written {
        let bare = name.strip_suffix('.').unwrap_or(name);
        let mut shared = None;
        for address in resolved.get(name).into_iter().flatten() {
            match names.get(address) {
                Some(first) if first != bare => shared = Some((*address, first.clone())),
                Some(_) => {}
                None => {
                    names.insert(*address, bare.to_string());
                }
            }
        }
        if let Some((address, first)) = shared {
            crate::info!(
                verbosity = 1,
                "{bare} not asked by name at {address} (asked as {first})"
            );
        }
    }
    names
}

/// Resolves `exprs` into a single [`IpSet`], for the discovery phase, which asks
/// only whether a host is there and has no use for ports.
///
/// [`to_target_map`] for a caller feeding
/// [`discover`](crate::scanner::discover): names resolve the same way, and the
/// port groupings are discarded. Reports a [`TargetParseError`], which, unlike
/// the address grammar's own error, can name a host that would not resolve.
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

    // Ports only group addresses, and the groups are merged below.
    let map = to_target_map(exprs, PortSet::default(), &ctx, resolver).await?;

    Ok(ips_of(&map))
}

/// The addresses `exprs` names, under the caller's DNS policy.
///
/// Shared by [`for_discovery_with`] and [`for_exclusion_with`]. `Some` resolves
/// hostnames through the resolver given; `None` refuses them all. Either way a
/// name that cannot be turned into addresses is reported as an error.
///
/// An empty list of expressions gives an empty set through the ordinary path.
async fn addresses_of<S: AsRef<str>>(
    exprs: &[S],
    names: Option<&Resolver>,
    keywords: Option<ResolverFn<'_>>,
    zones: Option<ZoneResolverFn<'_>>,
) -> Result<IpSet, TargetParseError> {
    match names {
        Some(resolver) => to_set(exprs, keywords, zones, resolver).await,
        None => {
            let ctx = TargetContext {
                keywords,
                zones,
                hosts: None,
            };
            Ok(ips_of(&target::to_target_map(
                exprs,
                PortSet::default(),
                &ctx,
            )?))
        }
    }
}

/// Every address a target map covers, with the port groupings discarded.
///
/// The groups only decide which ports go with which addresses, so a caller
/// with no use for ports takes their union.
fn ips_of(map: &TargetMap) -> IpSet {
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
    set
}

/// What a discovery sweep was asked to cover.
///
/// The addresses, and whether a *network* was named, which the addresses alone
/// cannot say.
///
/// `lan` and the range it expands to produce the same [`IpSet`], so
/// [`discover`](crate::scanner::discover) cannot tell which was written. A
/// caller that drops the flag gets a targeted run where a sweep was asked for:
/// no all-nodes echo, no neighbour-table leads, and an IPv6 half that reports
/// the network as empty, with nothing to show the scan went wrong.
#[derive(Debug, Clone)]
pub struct DiscoveryTargets {
    ips: IpSet,
    segment_sweep: bool,
}

impl DiscoveryTargets {
    /// The addresses to probe.
    pub fn ips(&self) -> &IpSet {
        &self.ips
    }

    /// Takes the addresses, for handing to [`discover`](crate::scanner::discover).
    pub fn into_ips(self) -> IpSet {
        self.ips
    }

    /// Whether a network was named, as opposed to a set of addresses.
    ///
    /// The value for [`ZondConfig::segment_sweep`]. Prefer
    /// [`apply_to`](Self::apply_to), which sets it there.
    pub fn segment_sweep(&self) -> bool {
        self.segment_sweep
    }

    /// Writes what these targets imply into `cfg`.
    ///
    /// Sets [`segment_sweep`](ZondConfig::segment_sweep). Same shape as
    /// `import::settings::Settings::apply_to`.
    pub fn apply_to(&self, cfg: &mut ZondConfig) {
        cfg.segment_sweep = self.segment_sweep;
    }
}

/// Resolves target expressions into everything a discovery sweep needs.
///
/// Uses this host's interface table for `lan` and for the `%interface` suffix,
/// resolves any hostnames, and works out whether a segment sweep was asked for.
///
/// `names` is the caller's DNS policy. `Some` resolves hostnames through the
/// resolver given; `None` refuses them. A scan running under
/// [`ZondConfig::no_dns`] passes [`Resolver::hosts_file_only`], which sends no
/// query, so a name listed in the hosts file is scanned and any other is
/// reported as an unknown host. A name that cannot be resolved is an error.
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use zond_engine::{Resolver, ZondConfig, discover, resolve};
///
/// let resolver = Resolver::from_system();
/// let targets = resolve::for_discovery(&["lan"], Some(&resolver)).await?;
///
/// let mut cfg = ZondConfig::default();
/// targets.apply_to(&mut cfg);
///
/// let (_session, task) = discover(targets.into_ips(), &cfg).await?;
/// let report = task.join().await?;
/// # Ok(())
/// # }
/// ```
pub async fn for_discovery<S: AsRef<str>>(
    exprs: &[S],
    names: Option<&Resolver>,
) -> Result<DiscoveryTargets, TargetParseError> {
    for_discovery_with(
        exprs,
        names,
        Some(&interface::resolve_keyword),
        Some(&interface::resolve_zone),
    )
    .await
}

/// [`for_discovery`], with the keyword and zone lookups supplied by the caller.
///
/// Makes the behaviour around `lan` and `%en0` testable on a machine that has
/// neither, and lets a caller who means something else by `lan`, such as a
/// management network or a lab segment, say so.
pub async fn for_discovery_with<S: AsRef<str>>(
    exprs: &[S],
    names: Option<&Resolver>,
    keywords: Option<ResolverFn<'_>>,
    zones: Option<ZoneResolverFn<'_>>,
) -> Result<DiscoveryTargets, TargetParseError> {
    let ips = addresses_of(exprs, names, keywords, zones).await?;

    // Asked of what was written; the expanded addresses cannot answer it.
    let segment_sweep = names_keyword(exprs, Keyword::Lan);

    Ok(DiscoveryTargets { ips, segment_sweep })
}

/// Resolves exclusion expressions into a policy [`scan`](crate::scanner::scan)
/// and [`discover`](crate::scanner::discover) will honour.
///
/// The counterpart of [`for_discovery`], with the same grammar:
/// `198.51.100.0/24`, `192.0.2.10-20`, `db.internal`, `lan` and `fe80::1%en0`
/// all work, so both halves of a scope document can be transcribed as written.
///
/// `names` is the DNS policy, as on [`for_discovery`]. A name given with `None`
/// is an error, so an exclusion that failed to parse cannot silently not apply.
///
/// A name is resolved once, here, and the policy holds the addresses it stood
/// for at that moment. A host that moves during the scan is then not excluded,
/// and one whose record lists two addresses is excluded at both. Write the
/// addresses where that matters.
///
/// # Combining with a settings document
///
/// Layer with [`Exclusions::extend`], never by assigning over
/// [`ZondConfig::exclusions`](crate::config::ZondConfig::exclusions):
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use zond_engine::{Resolver, ZondConfig, resolve};
///
/// let mut cfg = ZondConfig::default();
/// // ... a settings document has already contributed its own ...
///
/// let resolver = Resolver::from_system();
/// let from_arguments = resolve::for_exclusion(&["192.0.2.0/24"], Some(&resolver)).await?;
/// cfg.exclusions.extend(&from_arguments);
/// # Ok(())
/// # }
/// ```
///
/// Assigning would silently drop whatever an administrator put in a system-wide
/// file. See [`Exclusions::extend`] for why this is the one setting that
/// unions.
pub async fn for_exclusion<S: AsRef<str>>(
    exprs: &[S],
    names: Option<&Resolver>,
) -> Result<Exclusions, TargetParseError> {
    for_exclusion_with(
        exprs,
        names,
        Some(&interface::resolve_keyword),
        Some(&interface::resolve_zone),
    )
    .await
}

/// [`for_exclusion`], with the keyword and zone lookups supplied by the caller,
/// as [`for_discovery_with`] is to [`for_discovery`].
pub async fn for_exclusion_with<S: AsRef<str>>(
    exprs: &[S],
    names: Option<&Resolver>,
    keywords: Option<ResolverFn<'_>>,
    zones: Option<ZoneResolverFn<'_>>,
) -> Result<Exclusions, TargetParseError> {
    Ok(Exclusions::new(
        addresses_of(exprs, names, keywords, zones).await?,
    ))
}

/// Every distinct hostname named across `exprs`, in first-seen order.
///
/// A name is an address half the grammar rejects as
/// [`IpParseError::Malformed`] **and** that [`host_name`](target::host_name)
/// agrees is a name. Every other rejection (a wrong address, a keyword with no
/// resolver, a zone on a global address) is left for the build pass to report
/// against its expression. A token that will not split is skipped for the same
/// reason.
///
/// `Malformed` alone is not the builder's rule: it applies two more tests
/// before consulting the lookup. Without them `192.0.2.300` would be sent to a
/// resolver here and refused as a mistyped address there. Calling the same
/// function keeps the two passes in agreement.
///
/// The grammar is asked without the host's keyword and zone lookups, which
/// cannot change whether a token is `Malformed`. Passing them would only add an
/// interface-table read whose result is thrown away.
fn collect_names<S: AsRef<str>>(exprs: &[S]) -> Vec<String> {
    let mut names = Vec::new();
    let mut seen = HashSet::new();

    for token in exprs {
        let Ok(expr) = TargetExpr::parse(token.as_ref()) else {
            continue;
        };

        for address in expr.addresses() {
            let mut throwaway = IpSet::new();
            if let Err(IpParseError::Malformed(_)) =
                insert_expression(address, &mut throwaway, None, None)
                && target::host_name(address) == target::HostName::Yes
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
///
/// One lookup per name, not per spelling: DNS is case-insensitive, so `NAS` and
/// `nas` are resolved once. The answer is recorded under every spelling that
/// asked for it, because the build pass looks a name up by the token as
/// written.
async fn resolve_all(names: Vec<String>, resolver: &Resolver) -> HashMap<String, Vec<IpAddr>> {
    let mut resolved = HashMap::new();
    if names.is_empty() {
        return resolved;
    }

    // Spellings grouped under the folded name to look up.
    let mut spellings: HashMap<String, Vec<String>> = HashMap::new();
    let mut order = Vec::new();
    for name in names {
        let folded = name.to_ascii_lowercase();
        let written = spellings.entry(folded.clone()).or_default();
        if written.is_empty() {
            order.push(folded);
        }
        written.push(name);
    }

    // Read once, so every name sees the same hosts file and servers.
    let snapshot = Arc::new(resolver.snapshot());
    let mut set: JoinSet<(String, Vec<IpAddr>)> = JoinSet::new();
    let mut pending = order.into_iter();

    for name in pending.by_ref().take(MAX_CONCURRENT_LOOKUPS) {
        spawn_lookup(&mut set, resolver, &snapshot, name);
    }

    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((folded, addresses)) if !addresses.is_empty() => {
                for spelling in spellings.remove(&folded).unwrap_or_default() {
                    resolved.insert(spelling, addresses.clone());
                }
            }
            Ok(_) => {}
            // A lookup that did not finish resolves to nothing, but is logged
            // since it means a task failed.
            Err(e) => warn!("a name lookup did not finish: {e}"),
        }

        if let Some(name) = pending.next() {
            spawn_lookup(&mut set, resolver, &snapshot, name);
        }
    }

    resolved
}

/// Spawns one lookup, cloning the resolver and the pass's snapshot into the
/// task.
fn spawn_lookup(
    set: &mut JoinSet<(String, Vec<IpAddr>)>,
    resolver: &Resolver,
    snapshot: &Arc<Snapshot>,
    name: String,
) {
    let resolver = resolver.clone();
    let snapshot = Arc::clone(snapshot);
    set.spawn(async move {
        let addresses = resolver.resolve_in(&snapshot, &name).await;
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

    /// The two passes agree about what a name is, because they ask the same
    /// function.
    ///
    /// A collector taking [`IpParseError::Malformed`] as the whole answer would
    /// send a mistyped address to a resolver somebody else operates, which the
    /// builder then refuses anyway. A typo in a target file would become a DNS
    /// query.
    #[test]
    fn a_token_the_builder_will_refuse_is_never_put_on_the_network() {
        let refused = [
            "192.0.2.300",     // an octet out of range
            "999.999.999.999", // every octet out of range
            "192.0.2",         // too few octets
        ];
        assert_eq!(
            collect_names(&refused),
            Vec::<String>::new(),
            "a mistyped address was collected as a name to look up"
        );

        // The builder's own verdict on the same tokens.
        for token in refused {
            assert_eq!(target::host_name(token), target::HostName::Mistyped);
        }

        // A real name is still collected.
        assert_eq!(
            collect_names(&["nas.local", "example.com"]),
            vec!["nas.local".to_string(), "example.com".to_string()]
        );
    }

    /// One host is one lookup, however many ways it is spelled.
    ///
    /// DNS is case-insensitive, so `NAS` and `nas` name one host.
    #[test]
    fn a_name_written_two_ways_is_looked_up_once() {
        // Collection keeps every spelling, since the build pass looks a name up
        // by the token as written.
        let collected = collect_names(&["NAS", "nas", "Nas"]);
        assert_eq!(collected.len(), 3);

        // Resolution asks for one.
        let folded: std::collections::HashSet<String> = collected
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect();
        assert_eq!(folded.len(), 1, "three spellings of one host");
    }

    /// A keyword resolver that expands `lan` to one address, so a list mixing a
    /// keyword, literals and names can be classified the way the builder would.
    fn keywords(keyword: Keyword, set: &mut IpSet) -> Result<(), IpParseError> {
        match keyword {
            Keyword::Lan => {
                set.insert("192.0.2.1".parse().expect("a valid address"));
                Ok(())
            }
        }
    }

    /// A keyword is resolved once per call, by the pass that builds the set.
    ///
    /// Resolving `lan` reads the whole interface table. The pass that picks out
    /// hostnames has no use for the answer, since a keyword is never a name.
    #[tokio::test]
    async fn a_keyword_is_resolved_once_per_call() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = AtomicUsize::new(0);
        let counting = |keyword: Keyword, set: &mut IpSet| {
            calls.fetch_add(1, Ordering::Relaxed);
            keywords(keyword, set)
        };
        let resolver = Resolver::from_system();

        let set = to_set(&["lan", "203.0.113.1"], Some(&counting), None, &resolver)
            .await
            .expect("the keyword resolver answers");

        assert_eq!(set.len(), 2);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    /// Both of these resolve to the same single address, and only one is a
    /// request to sweep a segment.
    #[tokio::test]
    async fn only_the_keyword_asks_for_a_segment_sweep() {
        let keyword = for_discovery_with(&["lan"], None, Some(&keywords), None)
            .await
            .expect("the keyword resolver answers");
        assert!(keyword.segment_sweep());
        assert_eq!(keyword.ips().len(), 1);

        let spelled_out = for_discovery_with(&["192.0.2.1"], None, Some(&keywords), None)
            .await
            .expect("a literal address");
        assert!(!spelled_out.segment_sweep());
        assert_eq!(spelled_out.ips().len(), 1);
    }

    /// The keyword is found wherever it appears, including inside a
    /// comma-separated list.
    #[tokio::test]
    async fn the_keyword_is_found_alongside_other_targets() {
        let mixed = for_discovery_with(&["lan,198.51.100.0/30"], None, Some(&keywords), None)
            .await
            .expect("the keyword resolver answers");
        assert!(mixed.segment_sweep());
    }

    /// `apply_to` carries the sweep flag into the config.
    #[tokio::test]
    async fn applying_targets_to_a_config_sets_the_sweep() {
        let targets = for_discovery_with(&["lan"], None, Some(&keywords), None)
            .await
            .expect("the keyword resolver answers");

        let mut cfg = ZondConfig::default();
        assert!(!cfg.segment_sweep, "off until something asks for it");
        targets.apply_to(&mut cfg);
        assert!(cfg.segment_sweep);
    }

    /// With no resolver, a name is an error against the expression that
    /// contains it.
    #[tokio::test]
    async fn a_name_is_refused_when_no_resolver_is_offered() {
        let refused = for_discovery_with(&["one.one.one.one"], None, Some(&keywords), None).await;

        let Err(TargetParseError::NoHostLookup(expression)) = refused else {
            panic!("a name with nothing to resolve it is not a target");
        };
        assert_eq!(expression, "one.one.one.one");
    }

    /// Literal addresses need no resolver.
    #[tokio::test]
    async fn addresses_still_resolve_with_no_name_resolver() {
        let targets = for_discovery_with(&["198.51.100.0/30", "2001:db8::1"], None, None, None)
            .await
            .expect("literals need nothing looked up");
        assert_eq!(targets.ips().len(), 5);
    }

    /// Two names leading to one address ask for the one written first,
    /// whichever lookup answered first, and a fully qualified name is asked
    /// for without the dot that marks it.
    #[test]
    fn an_address_is_asked_for_by_the_first_name_that_led_to_it() {
        let shared: IpAddr = "192.0.2.10".parse().expect("an address");
        let own: IpAddr = "192.0.2.11".parse().expect("an address");
        let written = vec!["box.example.".to_string(), "dev.box.example".to_string()];
        let resolved = HashMap::from([
            ("dev.box.example".to_string(), vec![shared, own]),
            ("box.example.".to_string(), vec![shared]),
        ]);

        let mut names = BTreeMap::new();
        let logged = crate::logging::logged(|| names = names_by_address(&written, &resolved));
        assert_eq!(names.get(&shared).map(String::as_str), Some("box.example"));
        assert_eq!(names.get(&own).map(String::as_str), Some("dev.box.example"));

        // The name that goes unasked at the shared address is reported once.
        let said: Vec<_> = logged
            .iter()
            .filter(|line| line.message.contains("not asked by name"))
            .collect();
        assert_eq!(said.len(), 1, "{logged:?}");
        assert_eq!(said[0].verbosity, 1);
        assert_eq!(
            said[0].message,
            "dev.box.example not asked by name at 192.0.2.10 (asked as box.example)"
        );
    }

    /// Only hostnames are collected: a literal, a range, a CIDR block and a
    /// keyword are left to the grammar, and a name's port is stripped.
    #[test]
    fn only_the_hostnames_in_a_mixed_list_are_collected() {
        let exprs = [
            "192.0.2.10",
            "example.com:443",
            "198.51.100.0/24",
            "raspberrypi.local",
            "198.51.100.1-10",
            "lan",
        ];

        assert_eq!(
            collect_names(&exprs),
            vec!["example.com".to_string(), "raspberrypi.local".to_string()]
        );
    }

    /// A name written twice, or on two ports, is one name to resolve. Order is
    /// first-seen so a run over the same input resolves in the same order.
    #[test]
    fn a_repeated_name_is_collected_once() {
        let exprs = ["host.example:80", "host.example:443", "host.example"];

        assert_eq!(collect_names(&exprs), vec!["host.example".to_string()]);
    }

    /// The comma-separated address half is split before classification, so a
    /// single token naming a literal and a name yields just the name.
    #[test]
    fn names_are_found_inside_a_comma_list() {
        assert_eq!(
            collect_names(&["198.51.100.1,db.internal:5432"]),
            vec!["db.internal".to_string()]
        );
    }

    /// A keyword with no resolver is rejected by the grammar, but not as
    /// `Malformed`, so it is not mistaken for a hostname.
    #[test]
    fn a_keyword_without_a_resolver_is_not_taken_for_a_name() {
        assert!(collect_names(&["lan"]).is_empty());
    }

    /// An empty list resolves to an empty map with no tasks spawned.
    #[tokio::test]
    async fn resolving_no_names_yields_an_empty_map() {
        let resolver = Resolver::from_system();
        assert!(resolve_all(Vec::new(), &resolver).await.is_empty());
    }

    /// Expressions land in separate port groups, and `to_set` folds every
    /// group's addresses back into one set across both families. Literals only,
    /// so the test needs no network.
    #[tokio::test]
    async fn to_set_unions_every_group_across_both_families() {
        let resolver = Resolver::from_system();

        let set = to_set(
            &["198.51.100.1:80", "198.51.100.2:443", "2001:db8::1"],
            None,
            None,
            &resolver,
        )
        .await
        .expect("literals resolve without a lookup");

        assert_eq!(set.len(), 3);
        assert!(set.contains(&"198.51.100.1".parse().unwrap()));
        assert!(set.contains(&"198.51.100.2".parse().unwrap()));
        assert!(set.contains(&"2001:db8::1".parse().unwrap()));
    }
}
