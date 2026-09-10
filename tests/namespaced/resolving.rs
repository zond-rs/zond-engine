// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Resolving a `.local` name over multicast that a responder really answers.
//!
//! Multicast is the one part of name resolution that cannot be faked with a
//! socket on loopback: the query goes to a group, and whether it arrives depends
//! on the interface it was sent from, the membership the socket joined, and a
//! responder in a position to hear it. Tier 1 covers unicast against resolvers
//! bound to loopback, and this covers the half that needs a segment.

use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Duration;

use crate::netns::{Segment, available};
use zond_engine::resolve::{ResolveConfig, Resolver};

/// The window to wait for a reply. Longer than the responder needs and short
/// enough that the no-answer case does not dominate the tier's runtime.
const WINDOW: Duration = Duration::from_millis(1200);

/// Held for the length of every test here, because these cannot run beside each
/// other.
///
/// A responder lives in its own namespace, but the socket the engine queries
/// from is in this process's, bound to 5353 with `SO_REUSEPORT` so it can sit
/// beside the machine's own responder. Two of these tests at once means two such
/// sockets, and the kernel hands an arriving answer to one of them: the query
/// goes out from one test and the reply is delivered to another, which fails
/// whichever one lost the toss. Nothing about that is the engine's problem.
static ONE_AT_A_TIME: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

fn config(mdns: bool) -> ResolveConfig {
    let mut config = ResolveConfig::default();
    config.mdns = mdns;
    config.mdns_timeout = WINDOW;
    config
}

fn resolver() -> Resolver {
    Resolver::with_config(config(true))
}

/// A name a responder on the segment claims resolves to its address.
#[tokio::test]
async fn a_local_name_a_responder_claims_is_resolved() {
    if !available() {
        return;
    }
    let _one_at_a_time = ONE_AT_A_TIME.lock().await;

    let mut segment = Segment::new();
    let address = segment.answers_mdns_for("zond-peer");
    // The responder binds and joins the group on its own thread; a query sent
    // before it is listening goes to a group with nobody in it.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let found = resolver().resolve("zond-peer.local").await;

    assert!(
        found.contains(&IpAddr::V4(address)),
        "the responder claims zond-peer.local at {address}, but the lookup found {found:?}"
    );
}

/// A name nobody answers for resolves to nothing, rather than failing.
///
/// The ordinary outcome on any real segment, and the path that opens a group
/// socket, sends a query and waits the window out without an answer.
#[tokio::test]
async fn a_local_name_nobody_claims_resolves_to_nothing() {
    if !available() {
        return;
    }
    let _one_at_a_time = ONE_AT_A_TIME.lock().await;

    let _segment = Segment::new();
    let found = resolver().resolve("nothing-answers-to-this.local").await;

    assert!(
        found.is_empty(),
        "nothing on the segment answers to that name, but the lookup found {found:?}"
    );
}

/// With multicast off, a `.local` name is left alone rather than sent to a
/// unicast server that would answer NXDOMAIN for it.
#[tokio::test]
async fn multicast_off_leaves_a_local_name_unresolved() {
    if !available() {
        return;
    }
    let _one_at_a_time = ONE_AT_A_TIME.lock().await;

    let mut segment = Segment::new();
    let _address = segment.answers_mdns_for("zond-peer");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let resolver = Resolver::with_config(config(false));
    let found = resolver.resolve("zond-peer.local").await;

    assert!(
        found.is_empty(),
        "a responder is answering, but with mdns off nothing should ask it: {found:?}"
    );
}

/// A scope written as a `.local` name becomes the address a responder claims.
///
/// The name-resolution half of `resolve::for_discovery`, which is the path a
/// front end takes when somebody types a hostname into a scope rather than a
/// prefix. It concurrently looks up every name in the expression list, keeps the
/// spellings apart from the addresses, and folds what came back into the set. A
/// resolver that answers nothing exercises none of that, so it needs a name
/// something really claims.
#[tokio::test]
async fn a_scope_naming_a_responder_resolves_to_its_address() {
    if !available() {
        return;
    }
    let _one_at_a_time = ONE_AT_A_TIME.lock().await;

    let mut segment = Segment::new();
    let address = segment.answers_mdns_for("zond-peer");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let resolver = resolver();
    let targets = zond_engine::resolve::for_discovery(&["zond-peer.local"], Some(&resolver))
        .await
        .expect("a name is a well-formed target expression");

    assert!(
        targets.ips().contains(&IpAddr::V4(address)),
        "the scope should hold what the responder claimed, but holds {} address(es)",
        targets.ips().len()
    );
}

/// A name and a prefix in one scope are both resolved and folded together.
///
/// The mixed case, and the one where a name that resolves to nothing would be
/// invisible: the prefix alone would satisfy a test that only counted a
/// non-empty set.
#[tokio::test]
async fn a_scope_mixing_a_name_and_a_prefix_holds_both() {
    if !available() {
        return;
    }
    let _one_at_a_time = ONE_AT_A_TIME.lock().await;

    let mut segment = Segment::new();
    let address = segment.answers_mdns_for("zond-peer");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let resolver = resolver();
    let targets =
        zond_engine::resolve::for_discovery(&["zond-peer.local", "192.0.2.0/30"], Some(&resolver))
            .await
            .expect("both expressions are well formed");

    assert!(
        targets.ips().contains(&IpAddr::V4(address)),
        "the name should have resolved"
    );
    assert_eq!(
        targets.ips().len(),
        5,
        "four from the prefix and one from the name"
    );
}

/// A name nothing claims refuses the whole scope rather than shrinking it.
///
/// Written the other way round first, on the assumption that a scope document
/// naming a machine that is off should still scan the rest. The engine refuses,
/// and is right to: a scan that quietly covers less than it was asked to covers
/// less than its operator will report, and there is no way to tell that from a
/// scan of a scope that was smaller to begin with. A refusal naming the host is
/// something a person can act on.
#[tokio::test]
async fn a_name_nothing_claims_refuses_the_whole_scope() {
    if !available() {
        return;
    }
    let _one_at_a_time = ONE_AT_A_TIME.lock().await;

    let _segment = Segment::new();
    let resolver = resolver();
    let refused = zond_engine::resolve::for_discovery(
        &["nothing-answers-to-this.local", "192.0.2.0/30"],
        Some(&resolver),
    )
    .await;

    let error = refused
        .expect_err("nothing on the segment answers to that name")
        .to_string();
    assert!(
        error.contains("nothing-answers-to-this.local"),
        "the refusal should name the host that could not be found: {error}"
    );
}
