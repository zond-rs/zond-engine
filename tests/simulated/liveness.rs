// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Whether a routed sweep finds a host that answers only where it serves.
//!
//! A port scan probes the hosts its liveness pass found and no others, so a
//! host that pass misses is not reported closed or filtered: it is left out of
//! the report altogether. The host that is easiest to miss is one behind a
//! filter that drops a SYN to anything not listening, which is Windows
//! Firewall's default and what an `iptables` `DROP` policy does. It answers on
//! the ports it serves and is silent on every other, and the simulated network
//! models exactly that: one listening port, and silence as the fallback for
//! every port nobody named.

use std::net::IpAddr;

use crate::support::fake_lan::FakeLan;
use crate::support::fake_net::{FakeNet, Layer4, Policy};
use crate::support::*;
use zond_engine::journal::settle::Outcome;
use zond_engine::model::host::Host;
use zond_engine::model::ip::set::IpSet;
use zond_engine::model::port::{PortSet, PortState};
use zond_engine::model::technique::TcpScanTechnique;
use zond_engine::scanner::session::ScanSession;
use zond_engine::scanner::strategy::HostScanner;
use zond_engine::scanner::strategy::local::{LocalScanner, Scope};
use zond_engine::scanner::strategy::ports::TcpPortScanner;
use zond_engine::scanner::strategy::routed::{RoutedScanner, SweepProbe, SynPorts};
use zond_engine::system::interface::RoutedTarget;

/// A host behind a `DROP` policy serving `port` and nothing else.
fn serving_only(port: u16) -> FakeNet {
    FakeNet::new(Layer4::Tcp).host(TARGET, port, Policy::open())
}

/// Sweeps [`TARGET`] on `net` asking `probe`, then SYN-scans `scan_ports` on
/// every host the sweep found, as `scanner::scan` does, and returns the session.
async fn liveness_then_ports(net: &FakeNet, probe: SweepProbe, scan_ports: &[u16]) -> ScanSession {
    let (session, ctx) = ScanSession::new();
    let mut sweep = RoutedScanner::with_transport_asking(
        vec![RoutedTarget {
            target: TARGET,
            source: SCANNER_V4.into(),
        }],
        ctx.clone(),
        None,
        net.transport(),
        probe,
    );
    sweep
        .discover_hosts()
        .await
        .expect("the sweep runs to completion");

    let live: Vec<IpAddr> = session
        .hosts()
        .snapshot()
        .iter()
        .filter(|host| host.is_alive())
        .map(Host::primary_ip)
        .collect();
    let targets: Vec<_> = live
        .iter()
        .flat_map(|ip| scan_ports.iter().map(move |port| tcp(*ip, *port)))
        .collect();
    if !targets.is_empty() {
        let mut scanner = TcpPortScanner::with_transport(
            scanner_resolver(),
            ctx,
            TcpScanTechnique::Syn,
            net.transport(),
            targets.len(),
        );
        run_port_scanner(&mut scanner, targets).await;
    }
    session
}

/// The case the probe set exists for. SSH is the one service on the machine,
/// every other port is dropped, and the sweep that finds it is the only reason
/// the port scan ever asks about 22.
#[tokio::test]
async fn a_host_that_drops_syns_to_closed_ports_is_found_and_its_one_port_read_open() {
    let net = serving_only(22);

    let session = liveness_then_ports(&net, SweepProbe::syn(None), &[22]).await;

    assert!(
        session.hosts().contains(TARGET),
        "a host serving SSH behind a DROP policy was reported down"
    );
    assert_eq!(
        port_state(&session, TARGET, 22),
        Some(PortState::Open),
        "the port the host serves was never read"
    );
}

/// The scan's own ports are asked too, which is what finds a host serving
/// something none of the common five is. A liveness pass that asked only those
/// would leave out the one machine a scan of 8443 is about.
#[tokio::test]
async fn a_host_serving_only_a_port_the_scan_names_is_found_by_the_scan_liveness_pass() {
    let net = serving_only(8443);
    let scan = PortSet::try_from("8443").expect("a port specification");

    let session = liveness_then_ports(
        &net,
        SweepProbe::syn_to(None, SynPorts::for_scan(&scan)),
        &[8443],
    )
    .await;

    assert_eq!(port_state(&session, TARGET, 8443), Some(PortState::Open));
}

/// Every port is asked on every attempt, so a SYN to the one port a filtered
/// host serves has retransmissions behind it like any other. Asked once and
/// lost, that host would be gone.
#[tokio::test]
async fn every_port_is_asked_on_every_attempt_at_a_silent_address() {
    let net = FakeNet::new(Layer4::Tcp);

    liveness_then_ports(&net, SweepProbe::syn(None), &[]).await;

    for port in SynPorts::common().as_slice() {
        assert_eq!(
            net.probe_count(TARGET, *port),
            3,
            "port {port} was not asked on every attempt"
        );
    }
}

/// A segment sweep stopped with addresses it never asked counts them as never
/// asked, rather than as asked and silent, so its phase can tell an address
/// nobody asked about from one that answered nothing.
///
/// Stopped by the caller, so the sweep files no failure of its own; the
/// addresses are still without a verdict, and that is what is asserted.
#[tokio::test]
async fn a_segment_sweep_stopped_early_names_the_addresses_it_never_asked() {
    // A quarter of a second of first attempts at a frame a millisecond, so a
    // stop at a fifth of that lands mid-send.
    let range: IpSet = "192.0.2.0/24".parse().expect("a range");
    let lan = FakeLan::new();
    let (session, ctx) = ScanSession::new();
    let handle = session.handle().clone();

    let mut scanner = LocalScanner::with_handle(
        scanner_interface(),
        range.clone(),
        ctx.clone(),
        None,
        Scope::Targeted,
        lan.handle(),
    )
    .expect("the scanner builds over the simulated segment");
    let sweeping = tokio::spawn(async move { scanner.discover_hosts().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    handle.abort();
    sweeping
        .await
        .expect("the sweep winds down")
        .expect("the sweep runs");

    let unasked = ctx.settlements().count(Outcome::Unasked);
    assert!(
        u128::from(unasked) > range.len() / 2,
        "{unasked} of {} addresses counted unasked, where most were never asked",
        range.len()
    );
    assert!(ctx.failures_snapshot().is_empty());
}
