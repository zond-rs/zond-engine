// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Local-segment discovery against the simulated LAN.
//!
//! This is the path with the least coverage historically, because it is the one
//! that cannot be faked with sockets: it builds Ethernet frames, sends them on
//! an interface, and identifies a neighbour by the source MAC of what comes
//! back. Until the segment could be simulated, none of it ran outside a real
//! network with real privileges.
//!
//! The cases worth guarding are the ones where discovery decides *identity*
//! rather than mere presence: one host answering at several addresses must be
//! recorded once, and a targeted run must not solicit the whole segment.

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use common::fake_lan::{FakeLan, LanHost, LanProbe};
use common::*;
use pnet::datalink::MacAddr;
use zond_engine::core::models::ip::set::IpSet;
use zond_engine::core::session::ScanSession;
use zond_engine::scanner::NetworkExplorer;
use zond_engine::scanner::local::{LocalScanner, Scope};

const PEER_A: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0xAA);
const PEER_B: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0xBB);

fn v4(host: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, host))
}

/// Runs one sweep of `lan` over `targets` and returns the session to assert
/// against.
async fn sweep(lan: &FakeLan, targets: &[IpAddr], scope: Scope) -> ScanSession {
    let mut ips = IpSet::new();
    for ip in targets {
        ips.insert(*ip);
    }
    ips.canonicalize();

    let (session, ctx) = ScanSession::new();
    let scanner =
        LocalScanner::with_handle(scanner_interface(), ips, ctx, None, scope, lan.handle())
            .expect("scanner builds over the simulated segment");

    Box::new(scanner)
        .discover_hosts()
        .await
        .expect("sweep runs to completion");

    session
}

/// A host that answers ARP is discovered, and its MAC is recorded from the
/// reply rather than guessed.
#[tokio::test]
async fn an_answering_host_is_discovered_with_its_mac() {
    let lan = FakeLan::new().host(v4(10), LanHost::at(PEER_A));
    let session = sweep(&lan, &[v4(10)], Scope::Targeted).await;

    let host = session.store.get(&v4(10)).expect("host discovered");
    assert_eq!(
        host.mac().map(|m| m.to_string()),
        Some(PEER_A.to_string()),
        "the MAC must come from the ARP reply"
    );
}

/// An address with nothing on it produces no host. Discovery must not invent a
/// neighbour from silence.
#[tokio::test]
async fn an_empty_address_produces_no_host() {
    let lan = FakeLan::new().host(v4(10), LanHost::at(PEER_A));
    let session = sweep(&lan, &[v4(10), v4(11)], Scope::Targeted).await;

    assert!(session.store.contains_key(&v4(10)));
    assert!(
        !session.store.contains_key(&v4(11)),
        "silence is not evidence of a host"
    );
}

/// A slow ARP reply still counts. The adaptive deadline has to hold the sweep
/// open long enough for a segment that is merely busy.
#[tokio::test]
async fn a_slow_arp_reply_still_discovers_the_host() {
    let lan = FakeLan::new().host(v4(10), LanHost::at(PEER_A).delay(Duration::from_millis(50)));
    let session = sweep(&lan, &[v4(10)], Scope::Targeted).await;

    assert!(session.store.contains_key(&v4(10)));
}

/// One machine holding two addresses is one host, not two.
///
/// This is what the MAC-to-IP map exists for, and getting it wrong inflates
/// every result on a segment where multi-homing is normal. The second address
/// must be folded into the host discovered first rather than creating a new
/// entry.
#[tokio::test]
async fn one_machine_answering_at_two_addresses_is_recorded_once() {
    let lan = FakeLan::new()
        .host(v4(10), LanHost::at(PEER_A))
        .host(v4(11), LanHost::at(PEER_A));
    let session = sweep(&lan, &[v4(10), v4(11)], Scope::Targeted).await;

    assert_eq!(
        session.store.len(),
        1,
        "two addresses behind one MAC are one machine"
    );
}

/// Two machines are two hosts, which is the other half of the check above: the
/// deduplication must key on the MAC and not collapse everything it sees.
#[tokio::test]
async fn two_machines_are_recorded_separately() {
    let lan = FakeLan::new()
        .host(v4(10), LanHost::at(PEER_A))
        .host(v4(11), LanHost::at(PEER_B));
    let session = sweep(&lan, &[v4(10), v4(11)], Scope::Targeted).await;

    assert_eq!(session.store.len(), 2);
}

/// A targeted run must not send the all-nodes solicitation.
///
/// That probe makes every IPv6 neighbour on the segment answer. Scanning one
/// host is not permission to light up its neighbours, and a scan that does so
/// is both noisy and surprising.
#[tokio::test]
async fn a_targeted_run_does_not_solicit_the_whole_segment() {
    let lan = FakeLan::new().host(v4(10), LanHost::at(PEER_A));
    let _ = sweep(&lan, &[v4(10)], Scope::Targeted).await;

    assert!(
        !lan.probes()
            .iter()
            .any(|p| matches!(p, LanProbe::Solicitation { .. })),
        "a targeted run must probe only what it was given"
    );
}

/// A sweep, by contrast, does solicit, and picks up IPv6 neighbours that no
/// ARP request would ever have found.
#[tokio::test]
async fn a_sweep_discovers_ipv6_neighbours_through_the_solicitation() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    let lan = FakeLan::new()
        .host(v4(10), LanHost::at(PEER_A))
        .host(peer_v6, LanHost::at(PEER_B));

    // A range wide enough that the sweep does not finish the moment its IPv4
    // targets have all answered. See the ignored test below for why that
    // matters.
    let targets: Vec<IpAddr> = (10..=20).map(v4).collect();
    let session = sweep(&lan, &targets, Scope::Sweep).await;

    assert!(
        lan.probes()
            .iter()
            .any(|p| matches!(p, LanProbe::Solicitation { .. })),
        "a sweep should solicit the segment"
    );
    assert!(
        session.store.contains_key(&peer_v6),
        "an IPv6 neighbour answering the solicitation is a discovered host"
    );
}

/// A sweep whose IPv4 targets have all answered stops before draining IPv6
/// replies that are already queued, losing them.
///
/// `all_targets_responded` compares the count of responders against the size of
/// the address range, but under [`Scope::Sweep`] only in-range IPv4 addresses
/// are ever counted as responders. An IPv6 neighbour can therefore have answered
/// the solicitation, with its reply sitting in the receive queue, at the moment
/// the sweep decides it is finished.
///
/// The comment at the check says it "effectively never trips" for a sweep, which
/// holds for a /24 and does not hold for a sweep of a handful of addresses. That
/// is the case reproduced here: one IPv4 target that answers, and one IPv6
/// neighbour that is silently dropped.
#[tokio::test]
#[ignore = "known bug: a fully-answered sweep drops queued IPv6 replies"]
async fn a_small_sweep_does_not_drop_ipv6_neighbours() {
    let peer_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xAA));
    let lan = FakeLan::new()
        .host(v4(10), LanHost::at(PEER_A))
        .host(peer_v6, LanHost::at(PEER_B));

    let session = sweep(&lan, &[v4(10)], Scope::Sweep).await;

    assert!(
        session.store.contains_key(&peer_v6),
        "the neighbour answered before the sweep ended and must not be lost"
    );
}
