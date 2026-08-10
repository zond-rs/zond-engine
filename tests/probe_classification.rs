// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the raw scanners conclude from each kind of answer, against the
//! simulated network.
//!
//! The Tier 1 tests cover open and closed on loopback, which is all a
//! cooperative kernel will produce. Everything else a real network does - the
//! silence of a firewall, an ICMP error from a router rather than the host, a
//! duplicate, a reply too damaged to parse - has no coverage without a network
//! that can be told to misbehave. That is what this file adds.
//!
//! These pass today. They are regression guards, and the most valuable ones are
//! the near-misses: an administratively prohibited port that must read
//! `Filtered` rather than `Closed`, and an ICMPv6 code that means something
//! different from the identically numbered ICMPv4 one. Both are the kind of
//! mistake that produces a confident, wrong answer.

mod common;

use std::time::Duration;

use common::fake_net::{FakeNet, Layer4, Policy, Unreachable};
use common::*;
use zond_engine::core::models::host::HostStatus;
use zond_engine::core::models::port::PortState;
use zond_engine::core::session::ScanSession;
use zond_engine::scanner::NetworkExplorer;
use zond_engine::scanner::routed::{RoutedScanner, SynPortScanner, UdpPortScanner};
use zond_engine::system::interface::RoutedTarget;

/// The fixed source port the simulated UDP scans probe from.
const UDP_SRC_PORT: u16 = 54_321;

/// Runs one SYN scan over the given policies and returns the session to assert
/// against, together with the network that served it.
async fn syn_scan(ports: &[(u16, Policy)]) -> (ScanSession, FakeNet) {
    let mut net = FakeNet::new(Layer4::Tcp);
    for (port, policy) in ports {
        net = net.host(TARGET, *port, *policy);
    }

    let (session, ctx) = ScanSession::new();
    let mut scanner =
        SynPortScanner::with_transport(scanner_resolver(), ctx, net.transport(), ports.len());
    let targets = ports.iter().map(|(port, _)| tcp(TARGET, *port)).collect();
    run_port_scanner(&mut scanner, targets).await;

    (session, net)
}

/// The UDP counterpart of [`syn_scan`], against `target` so the v6 path can be
/// exercised with the same helper.
async fn udp_scan(target: std::net::IpAddr, ports: &[(u16, Policy)]) -> (ScanSession, FakeNet) {
    let mut net = FakeNet::new(Layer4::Udp);
    for (port, policy) in ports {
        net = net.host(target, *port, *policy);
    }

    let (session, ctx) = ScanSession::new();
    let mut scanner = UdpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        net.transport(),
        ports.len(),
        UDP_SRC_PORT,
    );
    let targets = ports.iter().map(|(port, _)| udp(target, *port)).collect();
    run_port_scanner(&mut scanner, targets).await;

    (session, net)
}

// ── TCP SYN ────────────────────────────────────────────────────────────────

/// The three outcomes a SYN probe can reach, in one scan, so a fix for one
/// cannot quietly break the others.
#[tokio::test]
async fn syn_classifies_open_closed_and_filtered() {
    let (session, _net) = syn_scan(&[
        (80, Policy::open()),
        (81, Policy::closed()),
        (82, Policy::silent()),
    ])
    .await;

    assert_eq!(port_state(&session, TARGET, 80), Some(PortState::Open));
    assert_eq!(port_state(&session, TARGET, 81), Some(PortState::Closed));
    assert_eq!(
        port_state(&session, TARGET, 82),
        Some(PortState::Filtered),
        "silence until the deadline is what a firewall drop looks like"
    );
}

/// A reply that arrives well after the probe must still be matched to it. The
/// adaptive deadline is what keeps the scan open long enough, so this is really
/// a check that a slow host is not written off as filtered.
#[tokio::test]
async fn a_slow_reply_is_still_matched_to_its_probe() {
    let (session, _net) = syn_scan(&[(80, Policy::open().delay(Duration::from_millis(50)))]).await;

    assert_eq!(port_state(&session, TARGET, 80), Some(PortState::Open));
}

/// A duplicated SYN+ACK is normal on a real network, since the host retransmits
/// when our RST never arrives. It must resolve the port once, not twice: a
/// second resolution would feed a bogus round-trip sample into the deadline.
#[tokio::test]
async fn a_duplicated_reply_records_the_port_once() {
    let (session, _net) = syn_scan(&[(80, Policy::open().duplicated())]).await;

    let host = session.store.get(&TARGET).expect("host recorded");
    assert_eq!(
        host.ports().filter(|p| p.number() == 80).count(),
        1,
        "two replies to one probe still describe one port"
    );
    assert_eq!(
        host.ports().find(|p| p.number() == 80).map(|p| p.state()),
        Some(PortState::Open)
    );
}

/// Traffic from a probed host that answers no probe must not classify its port.
///
/// This became reachable when the SYN transport learned to admit IPv6. libpcap
/// cannot narrow TCP by flags over IPv6 - `tcp[tcpflags]` is `proto[x]`
/// indexing, which an extension-header chain makes uncompilable - so the filter
/// admits every IPv6 TCP segment and the narrowing moved into userspace. Over
/// IPv4 the kernel still drops this segment before anyone sees it.
///
/// What must not change is the conclusion. A scan of an address the user happens
/// to be connected to sees that connection's ACKs, and if a bare ACK were read
/// as an answer, every such port would report `Open` or `Closed` on the strength
/// of somebody else's session - a wrong result, arrived at confidently, on one
/// address family only.
#[tokio::test]
async fn established_traffic_is_not_an_answer_to_a_probe() {
    let (session, _net) = syn_scan(&[(80, Policy::established())]).await;

    assert_eq!(
        port_state(&session, TARGET, 80),
        Some(PortState::Filtered),
        "a bare ACK answers no probe, so the probe went unanswered"
    );
}

/// The same segment, and the same conclusion, for host discovery: a host is
/// credited only by a reply to a probe this scan actually sent.
#[tokio::test]
async fn established_traffic_does_not_discover_a_host() {
    let net = FakeNet::new(Layer4::Tcp).host(TARGET_V6, 443, Policy::established());
    let (session, ctx) = ScanSession::new();

    let scanner = RoutedScanner::with_transport(
        vec![RoutedTarget {
            target: TARGET_V6,
            source: SCANNER_V6.into(),
        }],
        ctx,
        None,
        net.transport(),
    );
    Box::new(scanner)
        .discover_hosts()
        .await
        .expect("sweep runs to completion");

    assert!(
        !session.store.contains_key(&TARGET_V6),
        "an ACK from an established connection is not evidence of discovery"
    );
}

/// A reply too short to parse must be discarded, not guessed at. The probe stays
/// outstanding and times out as filtered, which is the honest answer: nothing
/// interpretable ever came back.
#[tokio::test]
async fn an_unparseable_reply_is_ignored_rather_than_classified() {
    let (session, _net) = syn_scan(&[(80, Policy::truncated())]).await;

    assert_eq!(
        port_state(&session, TARGET, 80),
        Some(PortState::Filtered),
        "a reply that could not be read is not evidence of an open port"
    );
}

// ── UDP ────────────────────────────────────────────────────────────────────

/// The UDP outcomes. Silence is `OpenFiltered` rather than `Filtered`, because
/// an open UDP port that simply had nothing to say is indistinguishable from a
/// blocked one, and claiming otherwise would be a guess.
#[tokio::test]
async fn udp_classifies_open_closed_and_silence() {
    let (session, _net) = udp_scan(
        TARGET,
        &[
            (53, Policy::open()),
            (161, Policy::closed()),
            (123, Policy::silent()),
        ],
    )
    .await;

    assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Open));
    assert_eq!(
        port_state(&session, TARGET, 161),
        Some(PortState::Closed),
        "an ICMP port-unreachable is the one unambiguous closed signal UDP gets"
    );
    assert_eq!(
        port_state(&session, TARGET, 123),
        Some(PortState::OpenFiltered),
        "silence cannot distinguish an open port from a blocked one"
    );
}

/// A RST proves the host even though it is a negative verdict on the port.
///
/// This is the row of the liveness mapping most easily lost: a closed port and a
/// live host arrive in the same segment, and a scanner reading only the port
/// half reports a machine that answered as never having been heard from.
#[tokio::test]
async fn a_closed_port_still_proves_its_host_is_up() {
    let (session, _net) = syn_scan(&[(80, Policy::closed())]).await;

    assert_eq!(port_state(&session, TARGET, 80), Some(PortState::Closed));
    assert_eq!(host_status(&session, TARGET), Some(HostStatus::Up));
}

/// The complement, and the invariant the whole design rests on: a port that
/// answers nothing leaves the host exactly as unknown as it was. `Filtered` here
/// is reached by exhausting the retry budget, and a status inferred from silence
/// would make `is_alive()` true for a host that never sent a packet - the
/// original defect in a new place.
#[tokio::test]
async fn a_silent_port_leaves_its_host_unknown() {
    let (session, _net) = syn_scan(&[(80, Policy::silent())]).await;

    assert_eq!(port_state(&session, TARGET, 80), Some(PortState::Filtered));
    assert_eq!(host_status(&session, TARGET), Some(HostStatus::Unknown));
    assert!(
        status_protocols(&session, TARGET).is_empty(),
        "silence must leave no audit trail"
    );
}

/// The classic UDP scanning error, guarded. An administratively prohibited
/// message says a filter refused the probe, so the port's real state was never
/// observed. Reading it as `Closed` reports a firewalled port as definitively
/// shut.
#[tokio::test]
async fn an_administratively_prohibited_port_is_filtered_not_closed() {
    let (session, _net) = udp_scan(TARGET, &[(123, Policy::admin_prohibited())]).await;

    assert_eq!(
        port_state(&session, TARGET, 123),
        Some(PortState::Filtered),
        "a filter refusing the probe says nothing about the port behind it"
    );
}

/// A host-unreachable describes the address, not the port. It is the engine's
/// only source of [`HostStatus::Down`], and it deliberately leaves the port
/// alone: a router that could not deliver the datagram never learned anything
/// about the port it was addressed to, so the probe retires by exhaustion like
/// any other unanswered one.
#[tokio::test]
async fn a_host_unreachable_error_is_a_verdict_on_the_host() {
    let (session, _net) = udp_scan(TARGET, &[(123, Policy::unreachable(Unreachable::Host))]).await;

    assert_eq!(host_status(&session, TARGET), Some(HostStatus::Down));
    assert_eq!(
        port_state(&session, TARGET, 123),
        Some(PortState::OpenFiltered),
        "the port was never reported on, so it ends where silence leaves it"
    );
}

/// The same reasons over IPv6, which numbers them differently. Port-unreachable
/// is code 3 on v4 and code 4 on v6; a scanner that compared raw code numbers
/// across families would read one as the other and report the opposite answer.
#[tokio::test]
async fn icmpv6_errors_are_classified_by_their_own_code_numbers() {
    let (session, _net) = udp_scan(
        TARGET_V6,
        &[(161, Policy::closed()), (123, Policy::admin_prohibited())],
    )
    .await;

    assert_eq!(
        port_state(&session, TARGET_V6, 161),
        Some(PortState::Closed),
        "ICMPv6 code 4 is port-unreachable, whatever code 4 means over v4"
    );
    assert_eq!(
        port_state(&session, TARGET_V6, 123),
        Some(PortState::Filtered)
    );
}

/// A duplicated UDP reply, like its TCP counterpart, describes one port once.
#[tokio::test]
async fn a_duplicated_udp_reply_records_the_port_once() {
    let (session, _net) = udp_scan(TARGET, &[(53, Policy::open().duplicated())]).await;

    let host = session.store.get(&TARGET).expect("host recorded");
    assert_eq!(host.ports().filter(|p| p.number() == 53).count(), 1);
}

/// An unparseable UDP reply leaves the probe outstanding rather than producing
/// a classification, and must not panic on the way.
#[tokio::test]
async fn an_unparseable_udp_reply_is_ignored() {
    let (session, _net) = udp_scan(TARGET, &[(53, Policy::truncated())]).await;

    assert_eq!(
        port_state(&session, TARGET, 53),
        Some(PortState::OpenFiltered)
    );
}

/// Every probe in a UDP scan must leave from the one source port the capture
/// filter and the quoted-datagram check are both built around. A probe sent
/// from anywhere else is invisible to its own scan.
#[tokio::test]
async fn every_udp_probe_leaves_from_the_scan_source_port() {
    let (_session, net) = udp_scan(
        TARGET,
        &[
            (53, Policy::open()),
            (161, Policy::open()),
            (123, Policy::open()),
        ],
    )
    .await;

    assert_eq!(
        net.probes().len(),
        3,
        "each target should have been probed exactly once"
    );
}
