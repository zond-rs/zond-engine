// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! Portable port-state classification tests.
//!
//! The privileged SYN path's Open/Closed/Filtered logic is unit-tested in-crate
//! with synthetic replies; these assert the unprivileged connect path's real
//! behaviour against loopback. `Filtered` (a silent firewall drop) can't be
//! reproduced on loopback without netfilter, so it is left to a privileged CI
//! tier on a real Linux host (see `tests/README.md`).

mod common;

use common::*;
use zond_engine::core::models::port::PortState;

/// A live listener's port is reported Open.
#[tokio::test]
async fn open_listener_is_reported_open() {
    if is_privileged() {
        eprintln!("SKIP: unprivileged connect path");
        return;
    }

    let server = spawn_banner_server(b"hi\r\n").await;
    let outcome = run_scan(
        target_map(LOOPBACK, &server.port.to_string()),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(LOOPBACK, server.port),
        Some(PortState::Open),
    );
}

/// A refused (closed) port is never reported Open. The connect fallback records
/// only non-closed ports, so the expected result is the *absence* of an Open
/// entry — the important invariant being no false positive.
#[tokio::test]
async fn closed_port_is_not_reported_open() {
    if is_privileged() {
        eprintln!("SKIP: unprivileged connect path");
        return;
    }

    let port = closed_loopback_port().await;
    let outcome = run_scan(target_map(LOOPBACK, &port.to_string()), &test_config()).await;

    assert_ne!(
        outcome.port_state(LOOPBACK, port),
        Some(PortState::Open),
        "a closed loopback port must never classify as Open"
    );
}

/// Scanning a mix of one open and several closed ports yields exactly the open
/// one, and does not invent hosts or ports for the closed ones.
#[tokio::test]
async fn only_open_ports_survive_a_mixed_scan() {
    if is_privileged() {
        eprintln!("SKIP: unprivileged connect path");
        return;
    }

    let open = spawn_banner_server(b"hi\r\n").await;
    let closed_a = closed_loopback_port().await;
    let closed_b = closed_loopback_port().await;

    let spec = format!("{},{},{}", open.port, closed_a, closed_b);
    let outcome = run_scan(target_map(LOOPBACK, &spec), &test_config()).await;

    assert_eq!(
        outcome.port_state(LOOPBACK, open.port),
        Some(PortState::Open)
    );
    assert_ne!(
        outcome.port_state(LOOPBACK, closed_a),
        Some(PortState::Open)
    );
    assert_ne!(
        outcome.port_state(LOOPBACK, closed_b),
        Some(PortState::Open)
    );
}
