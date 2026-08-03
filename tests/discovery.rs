// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Portable host-discovery tests.
//!
//! Discovery of loopback works even with no listener because a refused
//! connection is still proof the host answered at the TCP layer — the connect
//! path treats that as alive. ARP/SYN discovery of real neighbours (with MAC and
//! vendor) needs raw sockets on a real network, so it is out of scope here (see
//! `tests/README.md`).

mod common;

use common::*;
use zond_engine::core::models::ip::set::IpSet;

/// Loopback is discovered as alive, with at least one RTT sample recorded.
#[tokio::test]
async fn loopback_is_discovered_alive_with_rtt() {
    if is_privileged() {
        eprintln!("SKIP: unprivileged connect path");
        return;
    }

    let outcome = run_discover(ip_set(LOOPBACK), &test_config()).await;

    let host = outcome
        .host(LOOPBACK)
        .expect("loopback should be found alive");
    assert!(
        host.min_rtt().is_some(),
        "a discovered host should carry an RTT sample"
    );
}

/// An empty target set completes cleanly and finds nothing — no panics, no
/// spurious hosts.
#[tokio::test]
async fn empty_target_set_finds_nothing() {
    let outcome = run_discover(IpSet::new(), &test_config()).await;
    assert!(
        outcome.store.is_empty(),
        "discovering an empty set must yield no hosts"
    );
}

/// Overlapping input ranges are canonicalised to their union before scanning,
/// and discovery still runs to completion over the merged set.
#[tokio::test]
async fn overlapping_ranges_are_merged() {
    let mut targets = IpSet::new();
    // 127.0.0.1/31 -> {.0, .1}; 127.0.0.1-.5 -> {.1..=.5}; union = {.0..=.5} = 6.
    targets.insert_range("127.0.0.0/31".parse().unwrap());
    targets.insert_range("127.0.0.1-127.0.0.5".parse().unwrap());
    assert_eq!(
        targets.len(),
        6,
        "overlapping loopback ranges should collapse to 6 unique addresses"
    );

    // The orchestration must accept the canonicalised set and finish.
    let _ = run_discover(targets, &test_config()).await;
}
