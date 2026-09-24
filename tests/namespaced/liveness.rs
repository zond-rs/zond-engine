// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a port scan establishes before it spends a probe on a port, asked of
//! a host that is not there.
//!
//! Tier 1 asks the same of a loopback address nothing answers for, which macOS
//! has and Linux does not: Linux holds the whole of `127.0.0.0/8` and answers
//! every address in it. Here the silent host is built, as an address routed
//! through the peer that nothing holds, so the questions are asked on Linux
//! too and nothing leaves the machine to ask them.

use std::net::IpAddr;

use crate::netns::{Segment, available};
use crate::support::{run_scan, target_map, test_config};
use zond_engine::model::port::PortState;
use zond_engine::report::ScanKind;

/// An address nothing answers for gets a handful of liveness probes, not one
/// per port, and the report's second phase covers none of it.
#[tokio::test]
async fn an_address_nothing_answers_for_is_never_port_scanned() {
    if !available() {
        return;
    }

    let segment = Segment::new();
    let silent = IpAddr::V4(segment.silent_host());

    let outcome = run_scan(target_map(silent, "1-64"), &test_config()).await;

    assert_eq!(
        outcome.host(silent).map_or(0, |host| host.port_count()),
        0,
        "a silent address was port-scanned anyway"
    );
    let [liveness, ports, ..] = outcome.report.phases() else {
        panic!("a port scan records two phases");
    };
    assert_eq!(
        liveness.targets().addresses(),
        1,
        "one address was asked about"
    );
    assert_eq!(ports.targets().addresses(), 0, "and none of it answered");
}

/// `assume_up` probes the ports of a host that answers no knock, and skips the
/// liveness phase rather than running it and ignoring the result.
#[tokio::test]
async fn assume_up_probes_a_silent_hosts_ports_without_asking_first() {
    if !available() {
        return;
    }

    let segment = Segment::new();
    let silent = IpAddr::V4(segment.silent_host());
    let mut cfg = test_config();
    cfg.assume_up = true;

    let outcome = run_scan(target_map(silent, "1,2"), &cfg).await;

    let kinds: Vec<ScanKind> = outcome
        .report
        .phases()
        .iter()
        .map(|phase| phase.kind())
        .collect();
    assert_eq!(kinds, vec![ScanKind::PortScan], "no liveness phase ran");
    assert_eq!(
        outcome.report.summary().ports_total,
        2,
        "the ports were probed on trust"
    );
}

/// A host that drops a SYN to anything but the one port it serves is asked
/// about that port before the port scan, and so is port-scanned at all.
///
/// The listener's port is an ephemeral one none of the common five is, so the
/// only probe that can find this host is the one to a port the scan names.
#[tokio::test]
async fn a_host_behind_a_drop_policy_is_found_on_the_port_the_scan_names() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let routed = segment.routed_peer();
    let port = segment.listen_tcp_on(routed);
    segment.drop_tcp_except(port);
    let target = IpAddr::V4(routed);

    let outcome = run_scan(target_map(target, &port.to_string()), &test_config()).await;

    assert_eq!(
        outcome.port_state(target, port),
        Some(PortState::Open),
        "the host's one open port was never scanned"
    );
}

/// A scan of few ports over a silent, routed host skips the liveness pass and
/// probes the ports directly, and the host that answers nothing is left
/// [`Unknown`], with the ports it was asked, rather than down or unasked.
///
/// The skip must not make a silent host read as one nothing asked about: the
/// port phase covers the address, and the address answering nothing is the
/// same [`Unknown`] a port scan produces for any silent target, not a verdict
/// the missing liveness pass never earned.
///
/// [`Unknown`]: zond_engine::model::host::HostStatus::Unknown
#[tokio::test]
async fn a_few_port_scan_skips_liveness_and_leaves_a_silent_host_unknown() {
    use zond_engine::model::host::HostStatus;

    if !available() {
        return;
    }

    let segment = Segment::new();
    let silent = IpAddr::V4(segment.silent_host());

    let report = run_scan(target_map(silent, "1,2"), &test_config())
        .await
        .report;

    let kinds: Vec<ScanKind> = report.phases().iter().map(|phase| phase.kind()).collect();
    assert_eq!(
        kinds,
        vec![ScanKind::PortScan],
        "a two-port scan of a routed host runs the ports without a liveness pass"
    );
    assert_eq!(
        report.phases()[0].targets().addresses(),
        1,
        "the port phase asked about the address, so it is not one nothing asked"
    );
    if let Some(host) = report.host(silent) {
        assert_ne!(
            host.status(),
            HostStatus::Down,
            "a silent host is unknown, never down on evidence no pass gathered"
        );
    }
}

/// The connect sweep, which is how an unprivileged run asks, finds the same
/// host behind a drop policy on the port the scan names, and misses it asking
/// the common five alone.
///
/// Driven at the strategy rather than through a scan, because this tier runs
/// as root and a scan here takes the raw path.
#[tokio::test]
async fn a_connect_sweep_finds_a_host_behind_a_drop_policy_on_the_port_the_scan_names() {
    use zond_engine::EvasionProfile;
    use zond_engine::scanner::session::ScanSession;
    use zond_engine::scanner::strategy::connect;
    use zond_engine::scanner::strategy::routed::SynPorts;

    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let routed = segment.routed_peer();
    let port = segment.listen_tcp_on(routed);
    segment.drop_tcp_except(port);
    let target = IpAddr::V4(routed);
    let scan_ports = zond_engine::model::port::PortSet::try_from(port.to_string().as_str())
        .expect("a port specification");

    let (common, ctx) = ScanSession::new();
    connect::discover(target.into(), ctx, &EvasionProfile::default())
        .await
        .expect("the sweep runs");
    assert!(
        !common.hosts().contains(target),
        "the host answered one of the common five, so this proves nothing"
    );

    let (asked, ctx) = ScanSession::new();
    connect::discover_on(
        target.into(),
        ctx,
        &EvasionProfile::default(),
        SynPorts::for_scan(&scan_ports),
    )
    .await
    .expect("the sweep runs");
    assert!(
        asked.hosts().contains(target),
        "the connect sweep never asked the one port the host serves"
    );
}

/// `assume_up` sends the target its port probes and nothing else.
///
/// A caller who turned the liveness pass off asked for no question about
/// whether the host is there, so no sweep asks it one beside the ports under
/// any other name. Counted at the target on the port the routed sweep asks,
/// which the scan itself names no probe for.
#[tokio::test]
async fn assume_up_sends_no_sweep_beside_the_port_probes() {
    if !available() {
        return;
    }

    let segment = Segment::new();
    let target = segment.routed_peer();
    segment.count_tcp(443);
    let mut cfg = test_config();
    cfg.assume_up = true;

    let outcome = run_scan(target_map(IpAddr::V4(target), "1"), &cfg).await;

    assert_eq!(
        outcome.report.summary().ports_total,
        1,
        "the port was probed"
    );
    assert_eq!(
        segment.count_of(443),
        0,
        "a liveness sweep reached the target although the caller turned it off"
    );
}

/// An idle scan sends the target nothing from this host.
///
/// The zombie is excluded, so the idle scan is refused and nothing is forged;
/// what is counted is whether anything else asked the target, on the port the
/// routed sweep asks and on the port the scan names.
#[tokio::test]
async fn an_idle_scan_sends_its_target_nothing_from_this_host() {
    if !available() {
        return;
    }

    let segment = Segment::new();
    let target = segment.routed_peer();
    segment.count_tcp(443);
    segment.count_tcp(1);
    let zombie: IpAddr = "192.0.2.9".parse().expect("an address");
    let mut cfg = test_config();
    cfg.idle_scan = Some(zond_engine::config::IdleScan::new(zombie));
    cfg.exclusions = zond_engine::Exclusions::new(crate::support::ip_set(zombie));

    let _outcome = run_scan(target_map(IpAddr::V4(target), "1"), &cfg).await;

    assert_eq!(
        segment.count_of(443),
        0,
        "a liveness sweep reached the target"
    );
    assert_eq!(segment.count_of(1), 0, "a port probe left from this host");
}
