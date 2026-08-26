// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a paced scan must still deliver.
//!
//! A raw TCP port scan admits targets only while its congestion window has room,
//! and the window moves during the run — it grows on clean answers and is cut
//! when an answer arrives only because the probe was sent again. Every one of
//! those movements is an opportunity to lose a verdict, and losing one does not
//! fail: the port simply comes back with whatever the technique reads silence
//! as, which is indistinguishable from a firewall.
//!
//! So these tests assert on the outcome rather than on the controller. The unit
//! tests beside
//! [`CongestionWindow`](zond_engine::scanner::pacing::congestion::CongestionWindow)
//! say what it does; these say that whatever it does, every port the scan was
//! given leaves with the answer it earned.
//!
//! Each scan here is deliberately wider than the window starts, so admission
//! control is exercised rather than skipped.

mod common;

use common::fake_net::{FakeNet, Layer4, Policy};
use common::*;
use zond_engine::model::port::PortState;
use zond_engine::model::technique::TcpScanTechnique;
use zond_engine::scanner::session::ScanSession;

/// More targets than the window is allowed to *grow* to, let alone start at, so
/// the scan cannot put them all in flight at once and has to admit them as
/// earlier questions are settled. Wide enough that a controller which failed to
/// release slots, or failed to open up against silence, would run out of
/// deadline rather than merely be slow.
const WIDE: u16 = 3_000;

/// The first port of the scan, chosen away from the low numbers so a mistake
/// that indexed rather than keyed would produce visibly wrong ports.
const FIRST: u16 = 1_000;

/// Runs a SYN scan of [`WIDE`] consecutive ports, every one of them answering
/// under `policy`, and returns what the scan concluded about each.
async fn wide_syn_scan(policy: Policy) -> Vec<PortState> {
    let ports: Vec<u16> = (FIRST..FIRST + WIDE).collect();

    let mut net = FakeNet::new(Layer4::Tcp);
    for &port in &ports {
        net = net.host(TARGET, port, policy);
    }

    let (session, ctx) = ScanSession::new();
    let mut scanner = zond_engine::scanner::strategy::routed::TcpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        TcpScanTechnique::Syn,
        net.transport(),
        ports.len(),
    );

    let targets = ports.iter().map(|&port| tcp(TARGET, port)).collect();
    run_port_scanner(&mut scanner, targets).await;

    let host = session
        .hosts()
        .get(TARGET)
        .expect("the target answered and so is on record");

    ports
        .iter()
        .map(|&port| {
            host.ports()
                .find(|recorded| recorded.number() == port)
                .unwrap_or_else(|| panic!("port {port} was given to the scan and has no verdict"))
                .state()
        })
        .collect()
}

/// The window starts well below this many targets, so the scan can only finish
/// by admitting more as earlier probes resolve. A controller that grew but never
/// released, or released but never re-admitted, loses the tail — and loses it
/// silently, as ports nobody has a verdict for.
#[tokio::test]
async fn a_scan_wider_than_its_window_still_classifies_every_port() {
    let states = wide_syn_scan(Policy::open()).await;

    assert_eq!(states.len(), WIDE as usize);
    assert!(
        states.iter().all(|&state| state == PortState::Open),
        "every port answered, so every port is open"
    );
}

/// The signal that cuts the window is an answer that arrived only on a retry, so
/// a host that ignores every first attempt drives the controller down for the
/// whole run. It must arrive at the same answer, more slowly.
///
/// This is the case the pacing exists for. Measured against a consumer router
/// asked faster than it would answer, the same six hundred ports came back
/// `Filtered` — with no more hesitation than the three that really were.
#[tokio::test]
async fn a_host_that_answers_only_on_the_retry_is_paced_down_rather_than_written_off() {
    let states = wide_syn_scan(Policy::open().drop_first(1)).await;

    assert_eq!(states.len(), WIDE as usize);
    assert!(
        states.iter().all(|&state| state == PortState::Open),
        "the host answered every one of them, late; none of that is a firewall"
    );
}

/// Silence is what a firewall produces, and it must not be read as congestion.
/// A controller that cut on every timeout would crawl against exactly the hosts
/// that are hardest to finish — and this scan, where nothing answers at all,
/// would be the worst case of it.
#[tokio::test]
async fn a_host_that_answers_nothing_is_still_finished_and_still_filtered() {
    let states = wide_syn_scan(Policy::silent()).await;

    assert_eq!(states.len(), WIDE as usize);
    assert!(
        states.iter().all(|&state| state == PortState::Filtered),
        "a SYN any live stack would have answered, unanswered, is a filter"
    );
}

/// The case the controller was rebuilt for, and the one it used to be blind to:
/// a host that answers most of what it is asked and drops the rest, where the
/// drops are never recovered because the retries are lost too.
///
/// Measured against a Raspberry Pi, that produced two hundred and forty
/// `filtered` verdicts per run on a host with no firewall at all, a different
/// two hundred and forty each time. What the scanner can see is that the host is
/// plainly talking to it and plainly dropping things, and that combination is
/// the only warning it gets.
#[tokio::test]
async fn a_host_that_talks_and_drops_is_recognised_as_being_outrun() {
    // One port in eight answers; the rest are dropped outright, retries and all.
    let ports: Vec<u16> = (FIRST..FIRST + WIDE).collect();
    let mut net = FakeNet::new(Layer4::Tcp);
    for (index, &port) in ports.iter().enumerate() {
        let policy = if index % 8 == 0 {
            Policy::closed()
        } else {
            Policy::silent()
        };
        net = net.host(TARGET, port, policy);
    }

    let (session, ctx) = ScanSession::new();
    let mut scanner = zond_engine::scanner::strategy::routed::TcpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        TcpScanTechnique::Syn,
        net.transport(),
        ports.len(),
    );
    let targets = ports.iter().map(|&port| tcp(TARGET, port)).collect();
    run_port_scanner(&mut scanner, targets).await;

    let host = session.hosts().get(TARGET).expect("the host answered");
    assert_eq!(
        host.ports().count(),
        ports.len(),
        "every port the scan was given leaves with a verdict, however it was paced"
    );

    let closed = host
        .ports()
        .filter(|port| port.state() == PortState::Closed)
        .count();
    assert_eq!(
        closed,
        ports.len().div_ceil(8),
        "and the ports that did answer are all accounted for"
    );
}

/// Closed is an answer, and a scan of a host that refuses everything is the
/// ordinary case — the great majority of ports in any real scan. It must not be
/// read as loss, or every scan would pace itself down to the floor.
#[tokio::test]
async fn a_host_that_refuses_everything_is_answering_and_not_losing() {
    let states = wide_syn_scan(Policy::closed()).await;

    assert_eq!(states.len(), WIDE as usize);
    assert!(states.iter().all(|&state| state == PortState::Closed));
}
