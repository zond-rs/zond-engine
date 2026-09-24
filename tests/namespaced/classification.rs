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
use zond_engine::system::interface::SourceResolver;

/// The tier really is on the raw path, by the planner's own test for it.
///
/// Privilege alone is not the question, and asking only that is how this tier
/// spent its first two phases quietly scanning over `connect`: `PortScanPlan`
/// takes the raw path only when the process may send raw *and* a source address
/// can be resolved, and the second half was false because every link read as
/// down. A connect scan reports the same two verdicts over a path that never
/// builds an IP header, so the tier would have gone on passing while testing
/// nothing the tiers above it do not.
///
/// Both halves are asserted here, which is the whole of `plan.rs`'s condition.
/// A segment has to exist first: a namespace holding only its loopback has no
/// source to offer, and Linux reports `lo`'s operational state as unknown
/// rather than up in any case.
#[test]
fn the_engine_takes_its_raw_path_here() {
    if !available() {
        return;
    }
    let _segment = Segment::new();

    assert!(
        is_privileged(),
        "the namespace should give this process the privilege a raw scan needs"
    );
    assert!(
        SourceResolver::from_system().has_sources(),
        "the planner needs a source address to choose the raw path, and finds \
         none when a link reads as down"
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

/// A port a firewall silently discards is reported Filtered.
///
/// The verdict that motivates this whole tier. Loopback cannot produce it and
/// Tier 2 can only describe it, because silence is not something a cooperating
/// kernel will give you: it takes a real filter deciding not to answer, and a
/// scanner that waits out its retry schedule before saying so.
#[tokio::test]
async fn a_dropped_port_is_reported_filtered() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let port = segment.closed_tcp_port();
    segment.drop_tcp(port);

    let outcome = run_scan(
        target_map(segment.peer(), &port.to_string()),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(segment.peer(), port),
        Some(PortState::Filtered),
        "a port whose probes are dropped should read Filtered, not Closed"
    );
}

/// An ICMP prohibition reads as Filtered rather than Closed.
///
/// The near miss worth a test of its own. Both this port and a closed one
/// answer, and both answers are errors; only the reason differs. Reading an
/// administrative prohibition as a port unreachable would report a firewalled
/// port as a closed one, which is a confident and wrong answer rather than a
/// missing one.
///
/// This read `Unasked` for a while, and the engine was not at fault: with no
/// usable interface the scan fell back to `connect`, where the kernel reports
/// the prohibition as a failed send rather than handing the error to a capture.
/// On the raw path the ICMP error is read as what it is.
#[tokio::test]
async fn an_administratively_prohibited_port_is_filtered_rather_than_closed() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let port = segment.closed_tcp_port();
    segment.prohibit_tcp(port);

    let outcome = run_scan(
        target_map(segment.peer(), &port.to_string()),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(segment.peer(), port),
        Some(PortState::Filtered),
        "an admin-prohibited ICMP error should read Filtered"
    );
}

/// A connect scan reads a port a filter rejects as filtered, as the raw path
/// does, rather than as a port it never asked.
///
/// A firewall's reject answers with an ICMP administrative prohibition, and
/// Linux hands a connect that as a host it cannot reach: the error a missing
/// route raises before anything is sent. Read as that, every port behind the
/// reject is filed unasked, asked again on every resume, and the scan says
/// nothing about the filter it met. Driven directly, since a process with raw
/// sockets never plans a connect scan here.
#[tokio::test]
async fn a_connect_scan_reads_a_port_a_filter_rejects_as_filtered() {
    use zond_engine::config::ServiceDetection;
    use zond_engine::model::port::Protocol;
    use zond_engine::model::port::discovery::ScanResponse;
    use zond_engine::model::target::{PlannedTarget, Target};
    use zond_engine::scanner::session::ScanSession;

    if !available() {
        return;
    }

    let segment = Segment::new();
    let target = std::net::IpAddr::V4(segment.prohibited_host());
    let (session, ctx) = ScanSession::new();
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(PlannedTarget::new(
        0,
        Target {
            ip: target,
            port: 443,
            protocol: Protocol::Tcp,
        },
    ))
    .await
    .expect("queue");
    drop(tx);

    zond_engine::scanner::strategy::connect::scan(
        rx,
        1,
        ctx.clone(),
        ServiceDetection::Off,
        &zond_engine::EvasionProfile::default(),
        &zond_engine::ZoneMap::new(),
    )
    .await
    .expect("the connect scan runs");

    let port = session
        .hosts()
        .read(target, |host| {
            host.ports().find(|port| port.number() == 443).cloned()
        })
        .flatten()
        .expect("the port is on the host");
    assert_eq!(
        (
            port.state(),
            port.discovery().map(|found| found.reason().clone())
        ),
        (PortState::Filtered, Some(ScanResponse::IcmpUnreachable)),
        "a rejected connect is a filtered port, settled by the ICMP error"
    );
    assert!(
        ctx.failures_snapshot().is_empty(),
        "a filter answering is not this machine failing: {:?}",
        ctx.failures_snapshot()
    );
}

/// The unprivileged UDP scan reads a datagram a filter rejects as filtered
/// too, which a connected socket is handed as a host it cannot reach.
#[tokio::test]
async fn a_plain_udp_scan_reads_a_port_a_filter_rejects_as_filtered() {
    use zond_engine::model::port::Protocol;
    use zond_engine::model::target::{PlannedTarget, Target};
    use zond_engine::scanner::session::ScanSession;
    use zond_engine::scanner::strategy::PortScanner;
    use zond_engine::scanner::strategy::connect::ConnectUdpPortScanner;

    if !available() {
        return;
    }

    let segment = Segment::new();
    let target = std::net::IpAddr::V4(segment.prohibited_host());
    let (session, ctx) = ScanSession::new();
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(PlannedTarget::new(
        0,
        Target {
            ip: target,
            port: 161,
            protocol: Protocol::Udp,
        },
    ))
    .await
    .expect("queue");
    drop(tx);

    ConnectUdpPortScanner::new(ctx, 1, &zond_engine::EvasionProfile::default())
        .scan(rx)
        .await
        .expect("the scan runs");

    assert_eq!(
        crate::support::port_state(&session, target, 161),
        Some(PortState::Filtered),
        "a rejected datagram is a filtered port, not an open|filtered one"
    );
}

/// A UDP port nothing is bound to is reported Closed.
///
/// The only thing that makes a UDP port positively closed is an ICMP port
/// unreachable, and the only thing that produces one is a real kernel. The
/// error has to be parsed, and the datagram quoted inside it matched back to
/// the probe that caused it, before the verdict means anything.
#[tokio::test]
async fn a_udp_port_nothing_is_bound_to_is_reported_closed() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let port = segment.closed_udp_port();

    let outcome = run_scan(
        target_map(segment.peer(), &format!("U:{port}")),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(segment.peer(), port),
        Some(PortState::Closed),
        "an ICMP port unreachable from the peer should read Closed"
    );
}

/// A UDP reply reaches the scan and opens the port.
///
/// The other half of the same path, and the one that catches a capture filter
/// which compiles but matches nothing: such a filter turns every open UDP port
/// into `OpenFiltered`, so the scan keeps running and keeps reporting, just
/// never positively. Only live traffic shows it.
#[tokio::test]
async fn a_udp_reply_reaches_the_scan_and_opens_the_port() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let port = segment.echo_udp();

    let outcome = run_scan(
        target_map(segment.peer(), &format!("U:{port}")),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(segment.peer(), port),
        Some(PortState::Open),
        "a datagram answered by a real listener should read Open"
    );
}
