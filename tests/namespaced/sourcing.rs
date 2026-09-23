// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Which address a probe leaves from, against a kernel that picks its own.
//!
//! A raw Layer-4 socket has the kernel write the IP header, source address
//! included, while the engine computes the segment's checksum over the source
//! it chose. The two agree only where the engine took the kernel's choice. A
//! forced source is by definition one it did not, and a segment carrying one
//! address in its header and a checksum over another is dropped by every
//! target. Nothing short of a real kernel stamping its own source shows that.

use crate::netns::{Segment, available};
use crate::support::{run_scan, target_map, test_config};
use zond_engine::model::port::PortState;

/// A probe sent from a forced source carries that source, and its checksum
/// holds.
///
/// The segment has two addresses on this side, the first primary, and the
/// target sits behind the peer, where the routing table sends the probe from
/// the primary. Forced to the secondary, the scan's SYN has to leave from the
/// secondary, or the peer drops it for a checksum computed over an address
/// the header does not carry, and an open port reads filtered.
#[tokio::test]
async fn a_forced_source_is_the_source_a_probe_carries() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let forced = segment.add_scanner_address();
    let target = segment.routed_peer();
    let open = segment.listen_tcp_on(target);

    let mut cfg = test_config();
    cfg.send_source = vec![forced];
    // Straight to the port: the liveness sweep takes the same path, and this
    // is about the verdict a probe from the forced source earns.
    cfg.assume_up = true;

    let outcome = run_scan(
        target_map(std::net::IpAddr::V4(target), &open.to_string()),
        &cfg,
    )
    .await;
    assert_eq!(
        outcome.port_state(std::net::IpAddr::V4(target), open),
        Some(PortState::Open)
    );
}
