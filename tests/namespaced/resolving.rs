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
use std::time::Duration;

use crate::netns::{Segment, available};
use zond_engine::resolve::{ResolveConfig, Resolver};

/// The window to wait for a reply. Longer than the responder needs and short
/// enough that the no-answer case does not dominate the tier's runtime.
const WINDOW: Duration = Duration::from_millis(1200);

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
