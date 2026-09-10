// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Finding the right neighbour, on the right link.
//!
//! A scanner with one address and one route can get interface selection wrong
//! and still look correct. These build the conditions where it cannot: a second
//! address family that resolves through a different protocol, and a second
//! segment that a wrong choice would send the probes down.

use crate::netns::{Segment, available};
use crate::support::{run_scan, target_map, test_config};
use zond_engine::model::port::PortState;

/// A peer is scanned over IPv6, which means NDP rather than ARP.
///
/// Neighbour discovery is ICMPv6 multicast where ARP is a broadcast frame, so
/// nothing about the v4 path being right implies this one is. `FakeLan` can
/// answer a solicitation it was told to expect; a kernel answers the one it was
/// actually sent.
#[tokio::test]
async fn a_peer_is_scanned_over_ipv6() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let port = segment.listen_tcp_v6();

    let outcome = run_scan(
        target_map(segment.peer_v6(), &port.to_string()),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(segment.peer_v6(), port),
        Some(PortState::Open),
        "a listener reached over IPv6 should read Open"
    );
}

/// Two segments at once are not confused for one another.
///
/// Each one adds a link and a subnet to the same namespace, so the engine has
/// to choose per target rather than taking whatever interface it finds first.
/// A wrong choice sends the probes down a wire the target is not on, and the
/// port comes back filtered rather than wrong, which is the kind of failure
/// that reads as a flake.
#[tokio::test]
async fn two_segments_at_once_are_not_confused_for_one_another() {
    if !available() {
        return;
    }

    let mut first = Segment::new();
    let mut second = Segment::new();
    let open = first.listen_tcp();
    let closed = second.closed_tcp_port();

    let outcome = run_scan(target_map(first.peer(), &open.to_string()), &test_config()).await;
    let other = run_scan(
        target_map(second.peer(), &closed.to_string()),
        &test_config(),
    )
    .await;

    assert_eq!(
        (
            outcome.port_state(first.peer(), open),
            other.port_state(second.peer(), closed)
        ),
        (Some(PortState::Open), Some(PortState::Closed)),
        "each segment should be scanned over its own link"
    );
}
