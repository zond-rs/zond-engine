// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! The retransmission contract, written before the feature existed.
//!
//! Each test here was `#[ignore]`d until the path it covers retransmitted, and
//! removing that attribute is what "retransmission is done" meant for that path.
//! Every path now does: SYN port scanning, routed discovery, UDP, and ARP on the
//! local segment. What is left is a regression suite - these are the cases that
//! would silently stop being true if the retry policy were retuned carelessly.
//!
//! # Why this matters more than it looks
//!
//! Without it, a single lost probe is indistinguishable from a firewall. The SYN
//! path reports `Filtered`, the UDP path reports `OpenFiltered`, and local
//! discovery reports the host as absent. All three are wrong, and none of them
//! look wrong: the scan completes, reports a plausible answer, and gives no hint
//! that it guessed. On a link with a few percent loss, a wide scan quietly
//! misreports a proportional slice of its results. That is the difference
//! between a scanner people check twice and one they trust.
//!
//! # The contract
//!
//! 1. A probe that goes unanswered is sent again, up to a bounded number of
//!    attempts.
//! 2. Retries are spaced out rather than sent back to back, so a congested path
//!    is given time to drain instead of being hammered.
//! 3. A reply to *any* attempt resolves the probe, and resolves it exactly once.
//! 4. Exhausting the attempts is what produces `Filtered`. A port is only
//!    reported filtered after the engine has genuinely tried.
//! 5. Retrying never invents a result. A target that is truly silent still ends
//!    up `Filtered`, just later, and a closed port stays `Closed`.
//!
//! # Where it lives
//!
//! Every probing path needs this and every one of them already kept the state it
//! requires, which argued for one shared retry policy beside `AdaptiveDeadline`
//! rather than several implementations drifting apart. It landed that way, in
//! `core::models::retry`. These tests assert on observable behaviour and assume
//! none of it, so they stay honest regardless of how it is built.
//!
//! The one number they do assume is the attempt count, kept in [`ATTEMPTS`]
//! below. Change it in one place if the policy lands on a different budget.

mod common;

use std::time::Duration;

use common::fake_lan::{FakeLan, LanHost, LanProbe};
use common::fake_net::{FakeNet, Layer4, Policy};
use common::*;
use pnet::datalink::MacAddr;
use zond_engine::core::models::ip::set::IpSet;
use zond_engine::core::models::port::PortState;
use zond_engine::core::session::ScanSession;
use zond_engine::scanner::NetworkExplorer;
use zond_engine::scanner::local::{LocalScanner, Scope};
use zond_engine::scanner::routed::{RoutedScanner, SynPortScanner, UdpPortScanner};
use zond_engine::system::interface::RoutedTarget;

/// How many times a probe should be sent before the engine concludes the target
/// is silent. One initial attempt plus retries.
///
/// Two is the least that is useful and three is what most scanners settle on;
/// the tests below only require that it is greater than one, except where the
/// exact ceiling is the point.
const ATTEMPTS: usize = 3;

/// The fixed source port the simulated UDP scans probe from.
const UDP_SRC_PORT: u16 = 54_321;

const PEER_MAC: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0xAA);

// ── TCP SYN ────────────────────────────────────────────────────────────────

/// The core case. An open port whose first SYN is lost must still be found.
#[tokio::test]
async fn a_lost_syn_is_retried_and_the_port_still_reads_open() {
    let net = FakeNet::new(Layer4::Tcp).host(TARGET, 80, Policy::open().drop_first(1));

    let (session, ctx) = ScanSession::new();
    let mut scanner = SynPortScanner::with_transport(scanner_resolver(), ctx, net.transport(), 1);
    run_port_scanner(&mut scanner, vec![tcp(TARGET, 80)]).await;

    assert_eq!(
        port_state(&session, TARGET, 80),
        Some(PortState::Open),
        "a port that answered the second SYN is open, not filtered"
    );
    assert!(
        net.probe_count(TARGET, 80) > 1,
        "the lost probe should have been retried, but only {} was sent",
        net.probe_count(TARGET, 80)
    );
}

/// A closed port whose RST is lost must still read `Closed`, not `Filtered`.
/// Retrying has to recover the true answer, not merely find open ports.
#[tokio::test]
async fn a_lost_rst_is_retried_and_the_port_still_reads_closed() {
    let net = FakeNet::new(Layer4::Tcp).host(TARGET, 81, Policy::closed().drop_first(1));

    let (session, ctx) = ScanSession::new();
    let mut scanner = SynPortScanner::with_transport(scanner_resolver(), ctx, net.transport(), 1);
    run_port_scanner(&mut scanner, vec![tcp(TARGET, 81)]).await;

    assert_eq!(port_state(&session, TARGET, 81), Some(PortState::Closed));
}

/// Retrying must be bounded. A silent target is still filtered, and the engine
/// must not sit there resending forever.
#[tokio::test]
async fn a_silent_port_is_filtered_after_a_bounded_number_of_attempts() {
    let net = FakeNet::new(Layer4::Tcp).host(TARGET, 82, Policy::silent());

    let (session, ctx) = ScanSession::new();
    let mut scanner = SynPortScanner::with_transport(scanner_resolver(), ctx, net.transport(), 1);
    run_port_scanner(&mut scanner, vec![tcp(TARGET, 82)]).await;

    assert_eq!(
        port_state(&session, TARGET, 82),
        Some(PortState::Filtered),
        "silence after every attempt is what filtered means"
    );
    assert_eq!(
        net.probe_count(TARGET, 82),
        ATTEMPTS,
        "a silent target should be probed exactly {ATTEMPTS} times"
    );
}

/// An answered probe must not be retried. Resending after a reply wastes the
/// budget and, on a wide scan, multiplies traffic for no information.
///
/// Unlike the rest of this file, this one passes today, trivially, because
/// nothing is ever sent twice. It is not ignored because it is the invariant a
/// too-eager retry policy would break, and it should be guarding from the
/// moment that policy is written rather than from some later cleanup.
#[tokio::test]
async fn an_answered_probe_is_never_retried() {
    let net = FakeNet::new(Layer4::Tcp).host(TARGET, 80, Policy::open());

    let (_session, ctx) = ScanSession::new();
    let mut scanner = SynPortScanner::with_transport(scanner_resolver(), ctx, net.transport(), 1);
    run_port_scanner(&mut scanner, vec![tcp(TARGET, 80)]).await;

    assert_eq!(
        net.probe_count(TARGET, 80),
        1,
        "a port that answered the first probe needs no second one"
    );
}

/// Retries must be spaced. Sending the whole budget back to back within a
/// millisecond is not retransmission, it is a burst, and it makes a congested
/// path worse at the moment it is least able to cope.
#[tokio::test]
async fn retries_are_spaced_out_rather_than_burst() {
    let net = FakeNet::new(Layer4::Tcp).host(TARGET, 82, Policy::silent());

    let (_session, ctx) = ScanSession::new();
    let mut scanner = SynPortScanner::with_transport(scanner_resolver(), ctx, net.transport(), 1);
    run_port_scanner(&mut scanner, vec![tcp(TARGET, 82)]).await;

    let probes = net.probes();
    assert!(
        probes.len() > 1,
        "expected retries to inspect their spacing"
    );

    for pair in probes.windows(2) {
        let gap = pair[1].at.duration_since(pair[0].at);
        assert!(
            gap >= Duration::from_millis(1),
            "retries {gap:?} apart are a burst, not a retransmission"
        );
    }
}

/// A reply that arrives after a retry has already gone out must resolve the
/// probe once, not twice. Duplicate resolution would corrupt the RTT samples
/// the adaptive deadline is steering on.
#[tokio::test]
async fn a_late_reply_plus_its_retry_resolves_the_port_once() {
    let net = FakeNet::new(Layer4::Tcp).host(
        TARGET,
        80,
        Policy::open().delay(Duration::from_millis(40)).duplicated(),
    );

    let (session, ctx) = ScanSession::new();
    let mut scanner = SynPortScanner::with_transport(scanner_resolver(), ctx, net.transport(), 1);
    run_port_scanner(&mut scanner, vec![tcp(TARGET, 80)]).await;

    assert_eq!(port_state(&session, TARGET, 80), Some(PortState::Open));

    let host = session.store.get(&TARGET).expect("host recorded");
    assert_eq!(
        host.ports().filter(|p| p.number() == 80).count(),
        1,
        "one port should be recorded once, however many replies arrived"
    );
}

// ── Routed host discovery ──────────────────────────────────────────────────

/// The discovery counterpart of the SYN port case, and the one with the
/// bluntest consequence: a sweep that gives up after one unanswered probe does
/// not report a degraded result for that host, it reports no host at all.
#[tokio::test]
async fn a_lost_discovery_syn_is_retried_and_the_host_is_still_found() {
    let net = FakeNet::new(Layer4::Tcp).host(TARGET, 443, Policy::open().drop_first(1));

    let (session, ctx) = ScanSession::new();
    let scanner = RoutedScanner::with_transport(
        vec![RoutedTarget {
            target: TARGET,
            source: SCANNER_V4.into(),
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
        session.store.contains_key(&TARGET),
        "a host that answered the second SYN is still a live host"
    );
    assert!(
        net.probe_count(TARGET, 443) > 1,
        "the lost probe should have been retried"
    );
}

/// An address with nothing on it must not be probed indefinitely, and a sweep
/// of a mostly-empty range has to terminate.
#[tokio::test]
async fn a_silent_address_is_probed_a_bounded_number_of_times() {
    let net = FakeNet::new(Layer4::Tcp);

    let (session, ctx) = ScanSession::new();
    let scanner = RoutedScanner::with_transport(
        vec![RoutedTarget {
            target: TARGET,
            source: SCANNER_V4.into(),
        }],
        ctx,
        None,
        net.transport(),
    );
    Box::new(scanner)
        .discover_hosts()
        .await
        .expect("sweep runs to completion");

    assert!(!session.store.contains_key(&TARGET), "nothing answered");
    assert_eq!(
        net.probe_count(TARGET, 443),
        ATTEMPTS,
        "a silent address should be probed exactly {ATTEMPTS} times"
    );
}

/// A host that answers the first probe is not asked again. On a sweep of a
/// live range this is the difference between one packet per host and three.
#[tokio::test]
async fn a_discovered_host_is_not_probed_again() {
    let net = FakeNet::new(Layer4::Tcp).host(TARGET, 443, Policy::open());

    let (session, ctx) = ScanSession::new();
    let scanner = RoutedScanner::with_transport(
        vec![RoutedTarget {
            target: TARGET,
            source: SCANNER_V4.into(),
        }],
        ctx,
        None,
        net.transport(),
    );
    Box::new(scanner)
        .discover_hosts()
        .await
        .expect("sweep runs to completion");

    assert!(session.store.contains_key(&TARGET));
    assert_eq!(net.probe_count(TARGET, 443), 1);
}

// ── UDP ────────────────────────────────────────────────────────────────────

/// UDP has no handshake, so a lost probe is even more costly: there is no
/// second signal to fall back on, and the result degrades to `OpenFiltered`.
#[tokio::test]
async fn a_lost_udp_probe_is_retried_and_the_port_still_reads_open() {
    let net = FakeNet::new(Layer4::Udp).host(TARGET, 53, Policy::open().drop_first(1));

    let (session, ctx) = ScanSession::new();
    let mut scanner =
        UdpPortScanner::with_transport(scanner_resolver(), ctx, net.transport(), 1, UDP_SRC_PORT);
    run_port_scanner(&mut scanner, vec![udp(TARGET, 53)]).await;

    assert_eq!(
        port_state(&session, TARGET, 53),
        Some(PortState::Open),
        "a UDP port that answered the retry is open, not open-filtered"
    );
    assert!(
        net.probe_count(TARGET, 53) > 1,
        "the lost probe was not retried"
    );
}

/// A lost ICMP port-unreachable must be recovered too, so a closed UDP port is
/// reported closed rather than left ambiguous.
#[tokio::test]
async fn a_lost_icmp_error_is_retried_and_the_port_still_reads_closed() {
    let net = FakeNet::new(Layer4::Udp).host(TARGET, 161, Policy::closed().drop_first(1));

    let (session, ctx) = ScanSession::new();
    let mut scanner =
        UdpPortScanner::with_transport(scanner_resolver(), ctx, net.transport(), 1, UDP_SRC_PORT);
    run_port_scanner(&mut scanner, vec![udp(TARGET, 161)]).await;

    assert_eq!(port_state(&session, TARGET, 161), Some(PortState::Closed));
}

// ── Local discovery (ARP) ──────────────────────────────────────────────────

/// ARP is lossy on a busy segment far more often than people expect, and a
/// discovery sweep that never retries simply reports live hosts as absent.
#[tokio::test]
async fn a_lost_arp_request_is_retried_and_the_host_is_still_discovered() {
    let target_v4 = match TARGET {
        std::net::IpAddr::V4(v4) => v4,
        _ => unreachable!("TARGET is v4"),
    };

    let lan = FakeLan::new().host(TARGET, LanHost::at(PEER_MAC).drop_first(1));

    let mut ips = IpSet::new();
    ips.insert(TARGET);
    ips.canonicalize();

    let (session, ctx) = ScanSession::new();
    let scanner = LocalScanner::with_handle(
        scanner_interface(),
        ips,
        ctx,
        None,
        Scope::Targeted,
        lan.handle(),
    )
    .expect("scanner builds over the simulated segment");
    Box::new(scanner)
        .discover_hosts()
        .await
        .expect("sweep runs to completion");

    assert!(
        session.store.contains_key(&TARGET),
        "a host that answered the second ARP request is still a live host"
    );
    assert!(
        lan.arp_count(target_v4) > 1,
        "the lost request should have been retried"
    );
}

/// The bound applies here too: an address with nothing on it must not be
/// probed indefinitely, or a sweep of a mostly-empty range never terminates.
#[tokio::test]
async fn an_empty_address_is_probed_a_bounded_number_of_times() {
    let target_v4 = match TARGET {
        std::net::IpAddr::V4(v4) => v4,
        _ => unreachable!("TARGET is v4"),
    };

    let lan = FakeLan::new();

    let mut ips = IpSet::new();
    ips.insert(TARGET);
    ips.canonicalize();

    let (_session, ctx) = ScanSession::new();
    let scanner = LocalScanner::with_handle(
        scanner_interface(),
        ips,
        ctx,
        None,
        Scope::Targeted,
        lan.handle(),
    )
    .expect("scanner builds over the simulated segment");
    Box::new(scanner)
        .discover_hosts()
        .await
        .expect("sweep runs to completion");

    assert_eq!(
        lan.arp_count(target_v4),
        ATTEMPTS,
        "an empty address should be probed exactly {ATTEMPTS} times"
    );
    assert!(
        lan.probes()
            .iter()
            .all(|p| matches!(p, LanProbe::Arp { .. })),
        "a targeted run must not emit an all-nodes solicitation"
    );
}
