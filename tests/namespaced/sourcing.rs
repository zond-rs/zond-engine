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

/// Every connection a scan opens after its probe leaves from the forced source
/// and by the link that holds it, as the probe did.
///
/// Two segments reach one target: the first by the routing table's own route,
/// the second by a route standing behind it. The scan is forced to the second
/// segment's address, which is how a scan leaves by a LAN interface when a
/// VPN holds the default route. The probe finds the port open by the second
/// segment, and then the service pass dials it, the fingerprint engine dials
/// it again, and the detections speak to it. A connection that took the
/// routing table's word would reach the target by the first segment, from
/// that segment's address, and the first peer counts whatever arrives there.
#[tokio::test]
async fn every_connection_a_scan_opens_leaves_by_the_forced_source() {
    if !available() {
        return;
    }

    let default = Segment::new();
    let mut forced_link = Segment::new();
    let target = default.routed_peer();
    forced_link.also_routes(target, 100);
    let (open, seen) = forced_link.listen_http_recording_on(target);
    default.count_tcp(open);
    let forced = forced_link.scanner();

    let mut cfg = test_config();
    cfg.send_source = vec![forced];
    cfg.assume_up = true;

    let outcome = run_scan(
        target_map(std::net::IpAddr::V4(target), &open.to_string()),
        &cfg,
    )
    .await;

    assert_eq!(
        outcome.port_state(std::net::IpAddr::V4(target), open),
        Some(PortState::Open),
        "the probe reached the target by the forced link"
    );
    assert_eq!(
        default.count_of(open),
        0,
        "something reached the target by the routing table's own link"
    );
    let seen = seen.lock().expect("the record").clone();
    assert!(
        !seen.is_empty(),
        "the service pass never connected by the forced link"
    );
    assert!(
        seen.iter().all(|source| *source == forced),
        "a connection came from somewhere other than {forced}: {seen:?}"
    );
}

/// A connect scan honours a forced source too: its probe, and the fingerprint
/// it takes over the connection that probe opened, leave by the forced link.
///
/// The connect scan is what a scan without raw sockets runs on, and what
/// stands in for a raw probe a frame cannot carry. Driven directly here, since
/// a process with raw sockets never plans one for a routed target. Without the
/// pin its SYN leaves by the routing table's link, which reaches a target with
/// nothing listening, and the port reads closed.
#[tokio::test]
async fn a_connect_scan_leaves_by_the_forced_source() {
    use zond_engine::config::ServiceDetection;
    use zond_engine::model::target::{PlannedTarget, Target};
    use zond_engine::scanner::session::ScanSession;

    if !available() {
        return;
    }

    let default = Segment::new();
    let mut forced_link = Segment::new();
    let target = default.routed_peer();
    forced_link.also_routes(target, 100);
    let (open, seen) = forced_link.listen_http_recording_on(target);
    default.count_tcp(open);
    let forced = forced_link.scanner();

    let (session, ctx) = ScanSession::builder().send_source(vec![forced]).build();
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(PlannedTarget::new(
        0,
        Target::new(
            std::net::IpAddr::V4(target),
            open,
            zond_engine::model::port::Protocol::Tcp,
        ),
    ))
    .await
    .expect("queue");
    drop(tx);

    zond_engine::scanner::strategy::connect::scan(
        rx,
        1,
        ctx,
        ServiceDetection::default(),
        &zond_engine::EvasionProfile::default(),
        &zond_engine::ZoneMap::new(),
    )
    .await
    .expect("the connect scan runs");

    assert_eq!(
        crate::support::port_state(&session, std::net::IpAddr::V4(target), open),
        Some(PortState::Open),
        "the connect reached the target by the forced link"
    );
    assert_eq!(
        default.count_of(open),
        0,
        "something reached the target by the routing table's own link"
    );
    let seen = seen.lock().expect("the record").clone();
    assert!(
        !seen.is_empty() && seen.iter().all(|source| *source == forced),
        "a connection came from somewhere other than {forced}: {seen:?}"
    );
}

/// A host on this process's own segment that its routing table refuses is not
/// probed.
///
/// A `prohibit`, `unreachable` or `blackhole` route for one address of a
/// connected prefix is the host's policy, and ping and every connect honour
/// it. A raw socket held to the link, or a frame built for the neighbour,
/// never asks the table, and without the scan asking it for them the peer's
/// listener answers the scan's SYN, and the port reads open, from the one
/// program on the box that ignored the route. The answer is captured
/// whatever the route says of it, so an open port is the probe arriving.
#[tokio::test]
async fn a_host_on_link_behind_a_refusing_route_is_not_probed() {
    if !available() {
        return;
    }

    for kind in ["prohibit", "unreachable", "blackhole"] {
        let mut segment = Segment::new();
        let open = segment.listen_tcp();
        segment.refuse_peer_by_route(kind);

        let mut cfg = test_config();
        // Straight to the port: the probe is what the route has to stop.
        cfg.assume_up = true;
        let outcome = run_scan(target_map(segment.peer(), &open.to_string()), &cfg).await;

        assert_ne!(
            outcome.port_state(segment.peer(), open),
            Some(PortState::Open),
            "{kind}: the probe reached the peer"
        );
    }
}
