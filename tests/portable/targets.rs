// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Turning what a person wrote into what a scan will probe.
//!
//! [`resolve::for_discovery`] and [`resolve::for_exclusion`] are how a front end
//! hands this engine a scope, and they are the first thing any caller touches.
//! The unit tests beside them drive `addresses_of` and the grammar underneath;
//! these drive the two functions a consumer actually calls, from outside the
//! crate, which is where the difference between an expression and a scope shows
//! up.
//!
//! Names are left to the tier that has a segment to answer them on. Everything
//! here passes no resolver at all, which is both the common case for a scope
//! written in CIDR and the branch a consumer hits before they own a resolver.

use std::net::{IpAddr, Ipv4Addr};

use zond_engine::config::ZondConfig;
use zond_engine::resolve;

/// Nothing to resolve names with, which is what a CIDR scope needs.
const NO_NAMES: Option<&zond_engine::resolve::Resolver> = None;

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// A prefix and a range become the union of the two, counted once.
#[tokio::test]
async fn a_prefix_and_a_range_become_one_set() {
    let targets =
        resolve::for_discovery(&["198.51.100.0/30", "198.51.100.2-198.51.100.5"], NO_NAMES)
            .await
            .expect("both expressions are well formed");

    // /30 is .0 through .3, the range is .2 through .5, so the union is .0-.5.
    assert_eq!(targets.ips().len(), 6, "the overlap should be counted once");
    assert!(targets.ips().contains(&v4(198, 51, 100, 0)));
    assert!(targets.ips().contains(&v4(198, 51, 100, 5)));
    assert!(!targets.ips().contains(&v4(198, 51, 100, 6)));
}

/// A scope written in addresses is not a segment sweep.
///
/// The flag is asked of what was written rather than of what it expanded to, so
/// a `/24` naming a whole network is still a list of addresses and not the
/// instruction to sweep the local segment.
#[tokio::test]
async fn a_prefix_is_not_a_segment_sweep() {
    let targets = resolve::for_discovery(&["192.0.2.0/24"], NO_NAMES)
        .await
        .expect("a prefix is well formed");

    assert!(!targets.segment_sweep());

    let mut cfg = ZondConfig::default();
    targets.apply_to(&mut cfg);
    assert!(
        !cfg.segment_sweep,
        "applying the scope should carry the answer, not invent one"
    );
}

/// The set survives being taken out of the scope it was resolved into.
#[tokio::test]
async fn a_scope_hands_over_its_addresses() {
    let targets = resolve::for_discovery(&["198.51.100.7"], NO_NAMES)
        .await
        .expect("a single address is well formed");

    let ips = targets.into_ips();
    assert_eq!(ips.len(), 1);
    assert!(ips.contains(&v4(198, 51, 100, 7)));
}

/// An exclusion excludes what it names and nothing beside it.
#[tokio::test]
async fn an_exclusion_covers_what_it_names() {
    let exclusions = resolve::for_exclusion(&["203.0.113.0/31"], NO_NAMES)
        .await
        .expect("a prefix is well formed");

    assert!(!exclusions.is_empty());
    assert!(exclusions.excludes(&v4(203, 0, 113, 0)));
    assert!(exclusions.excludes(&v4(203, 0, 113, 1)));
    assert!(
        !exclusions.excludes(&v4(203, 0, 113, 2)),
        "a /31 is two addresses"
    );
}

/// An empty scope is a scope, not an error.
///
/// A front end with nothing excluded passes an empty list rather than deciding
/// for itself what that means.
#[tokio::test]
async fn an_empty_exclusion_list_excludes_nothing() {
    let exclusions: Vec<&str> = Vec::new();
    let exclusions = resolve::for_exclusion(&exclusions, NO_NAMES)
        .await
        .expect("nothing is well formed");

    assert!(exclusions.is_empty());
    assert!(!exclusions.excludes(&v4(198, 51, 100, 1)));
}

/// With no keyword or zone resolver, an expression needing one is refused
/// rather than guessed at.
///
/// The `_with` forms exist so a caller can supply both, and passing `None`
/// twice is how a consumer with no view of the local network asks for the
/// grammar without the parts that depend on one.
#[tokio::test]
async fn an_expression_needing_a_resolver_that_is_absent_is_refused() {
    let refused = resolve::for_exclusion_with(&["lan"], NO_NAMES, None, None).await;

    assert!(
        refused.is_err(),
        "with nothing to resolve `lan` against, the scope cannot be built: {refused:?}"
    );
}

/// An expression that is not an address, a range or a name is refused.
#[tokio::test]
async fn nonsense_is_refused_with_the_token_that_caused_it() {
    let refused = resolve::for_discovery(&["198.51.100.0/33"], NO_NAMES).await;

    let error = refused.expect_err("a /33 does not exist").to_string();
    assert!(
        error.contains("198.51.100.0/33"),
        "the refusal should name what was written: {error}"
    );
}
