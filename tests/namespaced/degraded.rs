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

/// The connect sweep, which is how an unprivileged run asks, finds a host
/// whose every answer takes nearly two seconds.
///
/// A connect waits a fixed time where nothing has measured the path, and
/// across a path slower than that wait each connect gives up while the answer
/// to its SYN is on the way: the host reads silent, however many ports it
/// answers on. Driven at the strategy, because this tier runs with raw sockets
/// and a scan here takes the raw path.
#[tokio::test]
async fn a_connect_sweep_finds_a_host_two_seconds_away() {
    use zond_engine::EvasionProfile;
    use zond_engine::scanner::session::ScanSession;
    use zond_engine::scanner::strategy::connect;

    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let target = segment.peer();
    // Resolved before the path slows, so what the sweep crosses is a slow
    // path and not a slow address resolution in front of one.
    let closed = segment.closed_tcp_port();
    let _ = std::net::TcpStream::connect((target, closed));
    segment.degrade(&["delay", "1900ms"]);

    let (session, ctx) = ScanSession::new();
    connect::discover(target.into(), ctx, &EvasionProfile::default())
        .await
        .expect("the sweep runs");

    assert!(
        session.hosts().contains(target),
        "a host answering across a 1.9s path was called silent"
    );
}

/// A connect port scan reads an open port open across a path of nearly two
/// seconds that nothing measured before it asked.
///
/// A scan told the host is up runs no liveness pass, so its first connect is
/// the first thing to cross the path, and waited as on an ordinary one it
/// gives up on the answer and files the port filtered. The host answering
/// nothing is what sends one of its ports a connect that waits long enough
/// to find the path.
#[tokio::test]
async fn a_connect_scan_reads_an_open_port_two_seconds_away_open() {
    use zond_engine::config::ServiceDetection;
    use zond_engine::model::target::{PlannedTarget, Target};
    use zond_engine::scanner::session::ScanSession;

    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let open = segment.listen_tcp();
    segment.degrade(&["delay", "1900ms"]);
    let target = segment.peer();

    let (session, ctx) = ScanSession::new();
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(PlannedTarget::new(
        0,
        Target::new(target, open, zond_engine::model::port::Protocol::Tcp),
    ))
    .await
    .expect("queue");
    drop(tx);

    zond_engine::scanner::strategy::connect::scan(
        rx,
        1,
        ctx,
        ServiceDetection::Off,
        &zond_engine::EvasionProfile::default(),
        &zond_engine::ZoneMap::new(),
    )
    .await
    .expect("the connect scan runs");

    assert_eq!(
        crate::support::port_state(&session, target, open),
        Some(PortState::Open),
        "an open port across a 1.9s path read as something else"
    );
}
