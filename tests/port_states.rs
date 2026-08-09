// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable port-state classification tests.
//!
//! These assert the unprivileged connect path's real behaviour against
//! loopback, which is limited to what a cooperative kernel will produce: open
//! and closed. `Filtered` is a silent firewall drop and cannot be reproduced on
//! loopback at all, so the privileged SYN path's full Open/Closed/Filtered
//! logic belongs against the simulated network in `common::fake_net` instead
//! (see `tests/README.md`).

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

/// A live UDP listener that responds is reported Open.
#[tokio::test]
async fn open_udp_listener_is_reported_open() {
    if is_privileged() {
        eprintln!("SKIP: unprivileged connect path");
        return;
    }

    let server = spawn_udp_server(b"hi\n").await;
    let spec = format!("u:{}", server.port);
    let outcome = run_scan(target_map(LOOPBACK, &spec), &test_config()).await;

    assert_eq!(
        outcome.port_state(LOOPBACK, server.port),
        Some(PortState::Open),
    );
}

/// A refused (closed) UDP port is never reported Open.
#[tokio::test]
async fn closed_udp_port_is_not_reported_open() {
    if is_privileged() {
        eprintln!("SKIP: unprivileged connect path");
        return;
    }

    let port = closed_udp_loopback_port().await;
    let spec = format!("u:{}", port);
    let outcome = run_scan(target_map(LOOPBACK, &spec), &test_config()).await;

    assert_ne!(
        outcome.port_state(LOOPBACK, port),
        Some(PortState::Open),
        "a closed loopback udp port must never classify as Open"
    );
}
