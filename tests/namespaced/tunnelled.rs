// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A target reached through a tunnel, on a link that carries no frames.
//!
//! The case a VPN makes of every target it carries, and the one where the
//! engine's picture of the host has to match the kernel's: the tunnel's
//! address carries a prefix like any other, and what sits inside it is
//! reached by routing through the tunnel, never by a frame put on it.

use crate::netns::{Segment, available};
use crate::support::{run_scan, target_map, test_config};
use std::net::IpAddr;
use zond_engine::model::port::PortState;

/// A peer inside the tunnel's own prefix is found and its port scanned.
///
/// The prefix makes the peer look on-link, and a target on-link goes to the
/// ARP sweep, which cannot put a frame on a tunnel. The peer then answers
/// nothing it was never sent, reads down, and has no port scanned at all. It
/// is found only if it is probed as what it is: a host behind the tunnel,
/// sent to from the tunnel's address.
#[tokio::test]
async fn a_peer_on_a_tunnels_own_subnet_is_found_and_scanned_through_it() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let peer = segment.tunnel();
    let open = segment.listen_tcp_on(peer);
    let target = IpAddr::V4(peer);

    let outcome = run_scan(target_map(target, &open.to_string()), &test_config()).await;

    assert!(
        outcome.host(target).is_some(),
        "the peer behind the tunnel should be found alive"
    );
    assert_eq!(outcome.port_state(target, open), Some(PortState::Open));
}

/// The far end of a point-to-point link, named as its peer the way pppd and
/// OpenVPN's p2p topology name it, is scanned through the link.
///
/// Linux reports such a link's address with the peer first. Read as it comes,
/// the peer is taken for this host's own address: reported up without being
/// asked, and a probe sourced from it that the kernel will not send, so the
/// port behind it never reads open.
#[tokio::test]
async fn the_peer_of_a_point_to_point_link_is_scanned_rather_than_taken_for_this_host() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let peer = segment.peer_tunnel();
    let open = segment.listen_tcp_on(peer);
    let target = IpAddr::V4(peer);

    let outcome = run_scan(target_map(target, &open.to_string()), &test_config()).await;

    assert_eq!(outcome.port_state(target, open), Some(PortState::Open));
}
