// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a scan concludes about a port on the other side of a real wire.
//!
//! These are the two verdicts a cooperating kernel will produce, which is the
//! same pair Tier 1 gets from loopback. The difference is everything underneath:
//! loopback never builds an IP header, never resolves a neighbour, and never
//! puts a frame on a link, so a scan against it proves the classifier and
//! nothing below it. Here the engine has to find the interface, ARP for the
//! peer, emit a packet another kernel will accept, and read the answer back
//! through a capture.

use crate::netns::{Segment, available};
use crate::support::{is_privileged, run_scan, target_map, test_config};
use zond_engine::model::port::PortState;

/// The tier sends raw packets, and says so.
///
/// A user namespace maps this process to uid 0 inside itself, which is what
/// gives `scan` its raw socket path rather than the connect fallback Tier 1
/// runs on. Without this the tier would still pass: a connect scan reports the
/// same two verdicts, over a path that never builds an IP header. It would just
/// have stopped testing anything the tiers above it do not.
#[test]
fn the_engine_takes_its_raw_path_here() {
    if !available() {
        return;
    }

    assert!(
        is_privileged(),
        "the namespace should give this process the privilege a raw scan needs"
    );
}

/// A port nothing is listening on is reported Closed.
///
/// The peer's kernel answers with a reset, which has to survive being built
/// here, carried over the pair, generated over there, and matched by the
/// capture filter on the way back.
#[tokio::test]
async fn a_port_nothing_listens_on_is_reported_closed() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let port = segment.closed_tcp_port();

    let outcome = run_scan(
        target_map(segment.peer(), &port.to_string()),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(segment.peer(), port),
        Some(PortState::Closed),
        "a reset from the peer's kernel should read as Closed"
    );
}

/// A port with a listener behind it is reported Open.
#[tokio::test]
async fn a_port_with_a_listener_is_reported_open() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let port = segment.listen_tcp();

    let outcome = run_scan(
        target_map(segment.peer(), &port.to_string()),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(segment.peer(), port),
        Some(PortState::Open),
        "a listener on the far side of the pair should read as Open"
    );
}

/// The peer answers a liveness probe, so the host is found up.
///
/// This is the ARP exchange as much as the probe: the engine has an address on
/// a segment and no idea what hardware answers for it until the peer's kernel
/// says so.
#[tokio::test]
async fn the_peer_is_found_alive() {
    if !available() {
        return;
    }

    let segment = Segment::new();
    let outcome = run_scan(target_map(segment.peer(), "1-2"), &test_config()).await;

    assert!(
        outcome.host(segment.peer()).is_some(),
        "the peer should be discovered before its ports are scanned"
    );
}
