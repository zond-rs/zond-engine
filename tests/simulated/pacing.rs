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

use std::time::{Duration, Instant};

use crate::support::fake_net::{FakeNet, Layer4, Policy};
use crate::support::*;
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
    let mut scanner = zond_engine::scanner::strategy::ports::TcpPortScanner::with_transport(
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

/// The case the controller exists for, and the one a controller reading only
/// silence is blind to: a host that answers most of what it is asked and drops
/// the rest, where the drops are never recovered because the retries are lost
/// too.
///
/// Measured against a Raspberry Pi, a scan that does not recognise it produces
/// two hundred and forty `filtered` verdicts per run on a host with no firewall
/// at all, a different two hundred and forty each time. What the scanner can
/// see is that the host is plainly talking to it and plainly dropping things,
/// and that combination is the only warning it gets.
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
    let mut scanner = zond_engine::scanner::strategy::ports::TcpPortScanner::with_transport(
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

// ---------------------------------------------------------------------------
// The gap between two probes at one host
// ---------------------------------------------------------------------------

/// Few enough ports that the whole scan fits inside a test's patience at a gap
/// wide enough to measure.
const SPACED_PORTS: u16 = 8;

/// Wide enough that eight of them are unmistakably longer than the scan would
/// otherwise take, and short enough that the test costs a fifth of a second.
const GAP: Duration = Duration::from_millis(25);

/// A scan spaced at one host still leaves every port with the verdict it earned,
/// and takes at least as long as the spacing it was given.
///
/// The two halves are the whole feature. A probe held for its host's next slot
/// has been taken off the stream and owes a verdict, so a queue that lost one
/// would report an open port as whatever the technique reads silence as — the
/// same answer a firewall produces, and indistinguishable from it. And a gap
/// that did not actually delay anything would be a bound the report records and
/// the scan never applied.
///
/// The timing assertion is a lower bound on purpose. An upper bound would be a
/// claim about the machine the test runs on.
#[tokio::test]
async fn a_scan_spaced_at_one_host_still_answers_every_port_and_takes_the_time() {
    let ports: Vec<u16> = (FIRST..FIRST + SPACED_PORTS).collect();

    let mut net = FakeNet::new(Layer4::Tcp);
    for &port in &ports {
        net = net.host(TARGET, port, Policy::open());
    }

    let (session, ctx) = ScanSession::builder()
        .host_probe_interval(Some(GAP))
        .build();
    let mut scanner = zond_engine::scanner::strategy::ports::TcpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        TcpScanTechnique::Syn,
        net.transport(),
        ports.len(),
    );

    let targets = ports.iter().map(|&port| tcp(TARGET, port)).collect();
    let started = Instant::now();
    run_port_scanner(&mut scanner, targets).await;
    let elapsed = started.elapsed();

    let host = session
        .hosts()
        .get(TARGET)
        .expect("the target answered and so is on record");

    for &port in &ports {
        let recorded = host
            .ports()
            .find(|recorded| recorded.number() == port)
            .unwrap_or_else(|| panic!("port {port} was given to the scan and has no verdict"));
        assert_eq!(
            recorded.state(),
            PortState::Open,
            "port {port} answered, and being held for the gap is not a reason to lose that"
        );
    }

    // The first probe waits for nothing, so the run is bounded below by the
    // seven gaps between the eight of them.
    let least = GAP * u32::from(SPACED_PORTS - 1);
    assert!(
        elapsed >= least,
        "eight probes at one host with a {GAP:?} gap cannot finish in {elapsed:?}"
    );
}

/// A scan that stops while probes are still held reports them as never asked.
///
/// The failure this guards against is the worst one the queue can produce. A
/// held first attempt has been taken off the target stream and is on no ledger,
/// so nothing else accounts for it: without the account at the end of the loop
/// it is not a wrong verdict but a *missing* one, the port simply absent from
/// the host, which is the shortfall a reader cannot see.
///
/// `Unasked` and not `Filtered` is the whole point. Both would leave the port
/// with no service behind it, and only one of them is true.
#[tokio::test]
async fn probes_still_held_when_a_scan_stops_are_recorded_as_never_asked() {
    let ports: Vec<u16> = (FIRST..FIRST + SPACED_PORTS).collect();

    let mut net = FakeNet::new(Layer4::Tcp);
    for &port in &ports {
        net = net.host(TARGET, port, Policy::open());
    }

    // A gap far wider than the budget, so the scan stops with most of its
    // probes still waiting for a slot they will never get.
    let (session, ctx) = ScanSession::builder()
        .host_probe_interval(Some(Duration::from_secs(30)))
        .scan_timeout(Some(Duration::from_millis(150)))
        .build();
    let mut scanner = zond_engine::scanner::strategy::ports::TcpPortScanner::with_transport(
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
        .expect("the first probe was sent, so the target is on record");

    let mut unasked = 0;
    for &port in &ports {
        let recorded = host
            .ports()
            .find(|recorded| recorded.number() == port)
            .unwrap_or_else(|| {
                panic!("port {port} was given to the scan and is absent from the host entirely")
            });
        match recorded.state() {
            PortState::Unasked => unasked += 1,
            PortState::Open => {}
            other => panic!("port {port} was held or answered, and reads as {other:?}"),
        }
    }

    assert!(
        unasked > 0,
        "the gap outlasted the budget, so some ports must be reported as never asked"
    );
}

/// A scan spaced at one host whose answers arrive after the first timeout
/// still settles every port, and leaves nothing outstanding when it ends.
///
/// Both clocks run here at once. Each reply lands after its probe's retry has
/// come due, so a retry is queued for the gap behind every first attempt, and
/// most are overtaken by the late answer while they wait. A retry sent after
/// its answer arrived asks a question nothing is waiting on; one that took
/// back a slot in the window for that would leak it, and a scan that leaked
/// enough stops admitting targets and idles until its deadline with the rest
/// never asked. And the spacing alone makes this scan slower than any deadline
/// sized for an unspaced one, so a deadline that ignored the gap would stop it
/// with ports queued.
#[tokio::test]
async fn a_spaced_scan_whose_answers_come_late_settles_every_port() {
    const PORTS: u16 = 150;
    let ports: Vec<u16> = (FIRST..FIRST + PORTS).collect();

    let mut net = FakeNet::new(Layer4::Tcp);
    for &port in &ports {
        net = net.host(
            TARGET,
            port,
            Policy::open().delay(Duration::from_millis(400)),
        );
    }

    let (session, ctx) = ScanSession::builder()
        .host_probe_interval(Some(GAP))
        .build();
    let mut scanner = zond_engine::scanner::strategy::ports::TcpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        TcpScanTechnique::Syn,
        net.transport(),
        ports.len(),
    );

    let targets = ports.iter().map(|&port| tcp(TARGET, port)).collect();
    run_port_scanner(&mut scanner, targets).await;

    let host = session.hosts().get(TARGET).expect("the target answered");
    let unsettled: Vec<(u16, PortState)> = ports
        .iter()
        .map(|&port| {
            let state = host
                .ports()
                .find(|recorded| recorded.number() == port)
                .map_or(PortState::Unasked, |recorded| recorded.state());
            (port, state)
        })
        .filter(|(_, state)| *state != PortState::Open)
        .collect();
    assert!(
        unsettled.is_empty(),
        "{} of {PORTS} ports answered and read otherwise: {:?}",
        unsettled.len(),
        &unsettled[..unsettled.len().min(8)]
    );
}
