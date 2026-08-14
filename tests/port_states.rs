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
//! and closed. Both are recorded, so the port list a scan produces does not
//! depend on whether the process had root. `Filtered` is a silent firewall drop and cannot be reproduced on
//! loopback at all, so the privileged SYN path's full Open/Closed/Filtered
//! logic belongs against the simulated network in `common::fake_net` instead
//! (see `tests/README.md`).

mod common;

use common::*;
use zond_engine::model::port::PortState;

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

/// A refused port is reported Closed.
///
/// A refusal is the clearest verdict this path ever gets: the RST the kernel
/// translated proves the port has nothing listening *and* that something is
/// there to say so. Asserting the state rather than merely the absence of `Open`
/// is what makes this cover the summary figure too — `ports_closed` counts these
/// and was structurally zero for every unprivileged scan until they were filed.
#[tokio::test]
async fn a_refused_port_is_reported_closed() {
    if is_privileged() {
        eprintln!("SKIP: unprivileged connect path");
        return;
    }

    let port = closed_loopback_port().await;
    let outcome = run_scan(target_map(LOOPBACK, &port.to_string()), &test_config()).await;

    assert_eq!(
        outcome.port_state(LOOPBACK, port),
        Some(PortState::Closed),
        "a refusal proves the port closed and must be recorded as such"
    );
}

/// A mixed scan reports every port it probed, each as what it found.
///
/// The privilege-independence check: this is the same list the raw path
/// produces for the same host, which is the property that broke when a refusal
/// went unrecorded. A consumer diffing two scans should see a change in the
/// network, never a change in who ran the scanner.
#[tokio::test]
async fn a_mixed_scan_reports_open_and_closed_alike() {
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
    assert_eq!(
        outcome.port_state(LOOPBACK, closed_a),
        Some(PortState::Closed)
    );
    assert_eq!(
        outcome.port_state(LOOPBACK, closed_b),
        Some(PortState::Closed)
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

/// The refusals reach the summary, not just the port list.
///
/// The figure the omission actually broke. `ports_by_state` is what a consumer
/// reads to learn the shape of a scan without walking every host, and with
/// refusals unrecorded it carried no `Closed` entry at all for an unprivileged
/// run — reporting a network where nothing is closed rather than one nobody
/// asked properly.
#[tokio::test]
async fn closed_ports_reach_the_summary() {
    if is_privileged() {
        eprintln!("SKIP: unprivileged connect path");
        return;
    }

    let closed_a = closed_loopback_port().await;
    let closed_b = closed_loopback_port().await;
    let spec = format!("{closed_a},{closed_b}");
    let outcome = run_scan(target_map(LOOPBACK, &spec), &test_config()).await;

    let summary = outcome.report.summary();
    assert_eq!(
        summary.ports_by_state.get(&PortState::Closed).copied(),
        Some(2),
        "both refusals should be counted: {:?}",
        summary.ports_by_state
    );
}
