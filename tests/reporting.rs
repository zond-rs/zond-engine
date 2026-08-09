// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Scan report tests: what the engine records about a run it just completed.
//!
//! The unit tests in `core::report` cover the aggregate's own arithmetic against
//! hand-built hosts. These drive the real public entry points instead, so they
//! catch the failure the unit tests cannot see: a report that is correct in
//! isolation but wired to the wrong scan, taken at the wrong moment, or filled
//! from a store that was still being written.

mod common;

use std::time::Duration;

use common::*;
use zond_engine::core::models::port::{PortState, Protocol};
use zond_engine::core::report::{ENGINE_VERSION, ScanKind};
use zond_engine::scanner;

/// A discovery report describes the sweep that produced it: one phase, the
/// discovery kind, and the address scope the caller asked for.
#[tokio::test]
async fn a_discovery_report_records_its_own_scope() {
    let mut targets = zond_engine::core::models::ip::set::IpSet::new();
    targets.insert_range("127.0.0.0/29".parse().unwrap());

    let outcome = run_discover(targets, &test_config()).await;
    let report = &outcome.report;

    assert_eq!(report.phases().len(), 1);

    let phase = &report.phases()[0];
    assert_eq!(phase.kind(), ScanKind::Discovery);
    assert_eq!(phase.targets().addresses(), 8);
    assert_eq!(phase.targets().probes(), None);
    assert!(phase.targets().protocols().is_empty());
    assert_eq!(report.engine_version(), ENGINE_VERSION);
}

/// A port-scan report records the probe count, not just the address count: the
/// port dimension is what makes the two phases cost different amounts.
#[tokio::test]
async fn a_port_scan_report_counts_probes() {
    let outcome = run_scan(target_map(LOOPBACK, "80,443,8080"), &test_config()).await;
    let phase = &outcome.report.phases()[0];

    assert_eq!(phase.kind(), ScanKind::PortScan);
    assert_eq!(phase.targets().addresses(), 1);
    assert_eq!(phase.targets().probes(), Some(3));
    assert_eq!(phase.targets().protocols(), &[Protocol::Tcp]);
}

/// The report's hosts are the store's hosts. A snapshot taken while strategies
/// were still writing would show fewer.
#[tokio::test]
async fn the_report_snapshots_every_host_the_store_holds() {
    if is_privileged() {
        eprintln!("SKIP: relies on the connect path finding the loopback listener");
        return;
    }

    let server = spawn_banner_server(b"hi\r\n").await;
    let outcome = run_scan(
        target_map(LOOPBACK, &server.port.to_string()),
        &test_config(),
    )
    .await;

    assert_eq!(outcome.report.host_count(), outcome.store.len());

    let summary = outcome.report.summary();
    assert_eq!(summary.hosts_total, outcome.store.len());
    assert_eq!(
        summary.ports_open, 1,
        "the listener's port should be counted open"
    );
    assert_eq!(
        outcome
            .report
            .host(&LOOPBACK)
            .expect("loopback is in the report")
            .port_count(),
        1
    );
}

/// A clean run reports itself as clean, which is what makes a report that *does*
/// carry failures worth acting on.
#[tokio::test]
async fn a_report_distinguishes_a_clean_run() {
    let outcome = run_scan(target_map(LOOPBACK, "80"), &test_config()).await;

    if is_privileged() {
        // The raw paths' availability is environment-specific; only assert the
        // two views agree with each other.
        assert_eq!(
            outcome.report.is_partial(),
            outcome.report.failures().count() > 0
        );
        return;
    }

    assert!(!outcome.report.is_partial());
    assert_eq!(outcome.report.failures().count(), 0);
}

/// An aborted scan still yields a report. Cutting a scan short changes how much
/// it found, not whether the run can be accounted for afterwards.
#[tokio::test]
async fn an_aborted_scan_still_reports() {
    let mut targets = zond_engine::core::models::ip::set::IpSet::new();
    targets.insert_range("127.0.0.0/22".parse().unwrap());

    let (session, task) = scanner::discover(targets, &test_config())
        .await
        .expect("discover starts");

    tokio::time::sleep(Duration::from_millis(50)).await;
    session.handle.abort();

    let report = tokio::time::timeout(Duration::from_secs(5), task.join())
        .await
        .expect("scan unwinds within the abort deadline")
        .expect("an aborted scan still joins Ok");

    // The scope is what was asked for, even though the sweep stopped early: the
    // gap between it and the host count is the point of recording both.
    assert_eq!(report.phases()[0].targets().addresses(), 1024);
    assert_eq!(report.phases().len(), 1);
}

/// Discovery followed by a port scan is one job, and merging their reports must
/// lose nothing either phase established.
///
/// The assertions are the merge law rather than fixed values, because what
/// loopback discovery finds depends on which of the common ports it probes
/// happen to be listening. Whatever each phase saw, the union has to hold: the
/// more definitive status wins and every port survives.
#[tokio::test]
async fn merging_two_phases_keeps_both_findings() {
    if is_privileged() {
        eprintln!("SKIP: relies on the connect path finding the loopback listener");
        return;
    }

    let server = spawn_banner_server(b"hi\r\n").await;
    let cfg = test_config();

    let discovery = run_discover(ip_set(LOOPBACK), &cfg).await.report;
    let ports = run_scan(target_map(LOOPBACK, &server.port.to_string()), &cfg)
        .await
        .report;

    let discovered_status = discovery.host(&LOOPBACK).map(|h| h.status());
    let scanned_status = ports.host(&LOOPBACK).map(|h| h.status());
    let scanned_ports = ports.host(&LOOPBACK).map_or(0, |h| h.port_count());

    let mut combined = discovery;
    combined.merge(ports);

    let host = combined
        .host(&LOOPBACK)
        .expect("loopback survives the merge");
    assert_eq!(
        Some(host.status()),
        discovered_status.max(scanned_status),
        "the merge must promote to the more definitive of the two statuses"
    );
    assert_eq!(host.port_count(), scanned_ports);
    assert_eq!(
        host.ports().next().map(|p| p.state()),
        Some(PortState::Open),
        "the port scan found the listener, so the merged host must carry it"
    );

    assert_eq!(
        combined
            .phases()
            .iter()
            .map(|phase| phase.kind())
            .collect::<Vec<_>>(),
        vec![ScanKind::Discovery, ScanKind::PortScan]
    );
    // Two phases ran, so the recorded time is both of them.
    assert!(combined.elapsed() >= combined.phases()[0].elapsed());
}
