// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What survives a link that loses and delays packets.
//!
//! Tier 2 drops packets by decision, from a generator it seeds, so it can say
//! exactly which probe went missing and assert on the count that followed. This
//! cannot, and should not try: `netem` draws from its own generator and will not
//! honour a precise assertion. What it can establish is the property that
//! matters and that no amount of simulation proves, which is that the real send
//! and receive path goes on working when the wire stops being perfect.

use crate::netns::{Segment, available};
use crate::support::{run_scan, target_map, test_config};
use zond_engine::model::port::PortState;

/// Every port in a scan over a lossy link still leaves with a verdict.
///
/// Losing an answer is not supposed to lose a port. The verdict may soften from
/// Closed to Filtered, since a reset that never arrives is indistinguishable
/// from a firewall, but a port that was asked about must come back having been
/// asked.
#[tokio::test]
async fn a_lossy_link_still_accounts_for_every_port() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let ports: Vec<u16> = (0..4).map(|_| segment.closed_tcp_port()).collect();
    segment.degrade(&["loss", "20%"]);

    let spec = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let outcome = run_scan(target_map(segment.peer(), &spec), &test_config()).await;

    let unasked: Vec<u16> = ports
        .iter()
        .copied()
        .filter(|&port| {
            !matches!(
                outcome.port_state(segment.peer(), port),
                Some(PortState::Closed) | Some(PortState::Filtered)
            )
        })
        .collect();

    assert!(
        unasked.is_empty(),
        "every port should carry a verdict over a lossy link, but {unasked:?} did not \
         (seed is netem's own, so rerun rather than reproduce)"
    );
}

/// An open port is still found when every answer arrives late.
///
/// The engine's deadlines are tuned against round trips it measures, and a link
/// that adds tens of milliseconds to each one is the cheapest way to find a
/// timeout that was really a constant.
#[tokio::test]
async fn a_slow_link_still_finds_an_open_port() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let port = segment.listen_tcp();
    segment.degrade(&["delay", "40ms"]);

    let outcome = run_scan(
        target_map(segment.peer(), &port.to_string()),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(segment.peer(), port),
        Some(PortState::Open),
        "a listener 40ms away should still read Open"
    );
}
