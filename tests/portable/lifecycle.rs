// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scan lifecycle tests: aborting, wall-clock budgets, event delivery, and
//! clean task completion.
//!
//! These exercise the session/handle/event contract rather than any particular
//! scan path, so they hold regardless of privilege and run everywhere.

use std::time::Duration;

use crate::support::*;
use zond_engine::report::StopReason;
use zond_engine::scanner;
use zond_engine::scanner::session::ScanEvent;

/// Aborting via the session handle brings a running scan to a prompt, clean stop
/// well inside a generous deadline — the loops honour `should_stop` rather than
/// only checking between targets.
#[tokio::test]
async fn abort_stops_a_scan_promptly() {
    let mut targets = zond_engine::model::ip::set::IpSet::new();
    // A large loopback range: enough work that an abort is observable.
    targets.insert_range("127.0.0.0/22".parse().unwrap());

    let (session, task) = scanner::discover(targets, &test_config())
        .await
        .expect("discover starts");

    // Let it get going, then pull the abort signal.
    tokio::time::sleep(Duration::from_millis(50)).await;
    session.handle().abort();

    let stopped = tokio::time::timeout(Duration::from_secs(5), task.join()).await;
    assert!(
        stopped.is_ok(),
        "scan did not unwind within the abort deadline"
    );
    assert!(
        stopped.unwrap().is_ok(),
        "aborted scan should still join Ok"
    );
}

/// A scan that finds an open host emits at least one `HostUpdated` for it, so a
/// live consumer can react before the scan finishes.
#[tokio::test]
async fn scan_emits_host_updated_events() {
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

    assert!(
        outcome.saw_host_update(LOOPBACK),
        "expected a HostUpdated event for the scanned host"
    );
    // Sanity: the event stream only ever carries the documented variants.
    assert!(outcome.events.iter().all(|e| matches!(
        e,
        ScanEvent::HostUpdated(_) | ScanEvent::ScannerFailed { .. }
    )),);
}

/// An empty port scan completes cleanly and records nothing — the task resolves
/// Ok even with no work to do.
#[tokio::test]
async fn empty_port_scan_completes_cleanly() {
    let outcome = run_scan(zond_engine::model::target::TargetMap::new(), &test_config()).await;
    assert!(outcome.hosts().is_empty());
}

/// A scan given a budget stops on its own, with nobody watching, and the report
/// says which of the two stops it was.
///
/// The budget is already spent when the session is built, so every loop reads it
/// on its first pass. A run this deterministic is the only kind worth asserting
/// a stop reason against: a budget racing a real sweep would test the machine.
#[tokio::test]
async fn a_spent_scan_budget_stops_a_run_nobody_is_watching() {
    let mut targets = zond_engine::model::ip::set::IpSet::new();
    targets.insert_range("127.0.0.0/22".parse().unwrap());

    let mut cfg = test_config();
    cfg.scan_timeout = Some(Duration::ZERO);

    let (_session, task) = scanner::discover(targets, &cfg)
        .await
        .expect("discover starts");

    let stopped = tokio::time::timeout(Duration::from_secs(5), task.join()).await;
    assert!(stopped.is_ok(), "a spent budget did not unwind the scan");
    let report = stopped
        .unwrap()
        .expect("a scan that timed out still joins Ok");

    let reasons: Vec<StopReason> = report
        .phases()
        .iter()
        .flat_map(|phase| phase.probe_stats())
        .map(zond_engine::report::ProbeStats::stop_reason)
        .collect();
    assert!(
        !reasons.is_empty(),
        "a phase that ran should record what its scanners did"
    );
    assert!(
        reasons.iter().all(|reason| *reason == StopReason::TimedOut),
        "an expired budget must not be reported as a caller's abort: {reasons:?}"
    );
    assert!(
        reasons.iter().all(|reason| !reason.is_complete()),
        "a scan cut short by its budget is not a complete one"
    );
}

/// A host whose own budget is spent is left where it stands, and the phase names
/// the address so a short port list is not read as a quiet machine.
#[tokio::test]
async fn a_spent_host_budget_leaves_the_host_and_says_so() {
    let server = spawn_banner_server(b"hi\r\n").await;

    let mut cfg = test_config();
    cfg.host_timeout = Some(Duration::ZERO);
    // Straight to the port phase: the liveness sweep is outside the per-host
    // budget, and this test is about what the port phase does with it.
    cfg.assume_up = true;

    let outcome = run_scan(target_map(LOOPBACK, &server.port.to_string()), &cfg).await;

    assert!(
        outcome
            .report
            .phases()
            .iter()
            .any(|phase| phase.timed_out().contains(&LOOPBACK)),
        "a host left early has to be named in the phase that left it"
    );
    assert_ne!(
        outcome.port_state(LOOPBACK, server.port),
        Some(zond_engine::model::port::PortState::Open),
        "a port nobody asked about must not be reported open"
    );
}

/// The budget is a bound and not a floor. A scan that finishes inside it says so
/// the way any finished scan does, and nothing is named as cut short.
#[tokio::test]
async fn a_budget_nothing_reached_changes_no_result() {
    let server = spawn_banner_server(b"hi\r\n").await;

    let mut cfg = test_config();
    cfg.host_timeout = Some(Duration::from_secs(3600));
    cfg.scan_timeout = Some(Duration::from_secs(3600));

    let outcome = run_scan(target_map(LOOPBACK, &server.port.to_string()), &cfg).await;

    assert!(
        outcome
            .report
            .phases()
            .iter()
            .all(|phase| phase.timed_out().is_empty()),
        "a budget nothing came near must not name a host"
    );
    assert_eq!(
        outcome.port_state(LOOPBACK, server.port),
        Some(zond_engine::model::port::PortState::Open)
    );
}
