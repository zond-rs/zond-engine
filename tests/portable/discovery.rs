// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable host-discovery tests.
//!
//! Discovery of loopback works even with no listener because a refused
//! connection is still proof the host answered at the TCP layer — the connect
//! path treats that as alive. ARP/SYN discovery of real neighbours (with MAC and
//! vendor) needs raw sockets on a real network, so it is out of scope here (see
//! `tests/README.md`).

use crate::support::*;
use zond_engine::model::ip::set::IpSet;

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
        outcome.hosts().is_empty(),
        "discovering an empty set must yield no hosts"
    );
}
