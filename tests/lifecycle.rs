// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Scan lifecycle tests: aborting, event delivery, and clean task completion.
//!
//! These exercise the session/handle/event contract rather than any particular
//! scan path, so they hold regardless of privilege and run everywhere.

mod common;

use std::time::Duration;

use common::*;
use zond_engine::core::session::ScanEvent;
use zond_engine::scanner;

/// Aborting via the session handle brings a running scan to a prompt, clean stop
/// well inside a generous deadline — the loops honour `should_stop` rather than
/// only checking between targets.
#[tokio::test]
async fn abort_stops_a_scan_promptly() {
    let mut targets = zond_engine::core::models::ip::set::IpSet::new();
    // A large loopback range: enough work that an abort is observable.
    targets.insert_range("127.0.0.0/22".parse().unwrap());

    let (session, task) = scanner::discover(targets, &test_config())
        .await
        .expect("discover starts");

    // Let it get going, then pull the abort signal.
    tokio::time::sleep(Duration::from_millis(50)).await;
    session.handle.abort();

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
    let outcome = run_scan(
        zond_engine::core::models::target::TargetMap::new(),
        &test_config(),
    )
    .await;
    assert!(outcome.store.is_empty());
}
