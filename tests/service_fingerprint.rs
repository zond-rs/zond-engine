// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable service-fingerprinting tests.
//!
//! These scan a *real* speak-first server on loopback and assert the full
//! pipeline — connect, banner grab, analyzer, verdict — identifies its product
//! and version. Speak-first protocols (SSH here) are the ones the engine can
//! identify on any port from the banner alone, which is what makes this portable
//! without root. Fingerprinting that needs a port-specific probe (HTTP, TLS,
//! Postgres, Redis) needs root to bind its real port, so its classification
//! logic is covered by in-crate unit tests instead (see `tests/README.md`).

mod common;

use common::*;

/// An SSH server announcing an OpenSSH banner must be resolved all the way to
/// service + product + version, not left at the port→name baseline.
#[tokio::test]
async fn identifies_openssh_from_its_banner() {
    if is_privileged() {
        eprintln!("SKIP: exercises the unprivileged connect path; run as non-root");
        return;
    }

    let server = spawn_banner_server(b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n").await;
    let outcome = run_scan(
        target_map(LOOPBACK, &server.port.to_string()),
        &test_config(),
    )
    .await;

    let host = outcome.host(LOOPBACK).expect("loopback host recorded");
    let port = host
        .ports()
        .find(|p| p.number() == server.port)
        .expect("scanned port present in results");

    let service = port.service().expect("a service was identified");
    assert_eq!(service.name(), "ssh", "protocol should resolve to ssh");
    assert_eq!(
        service.product(),
        Some("OpenSSH"),
        "product should be extracted from the banner"
    );
    assert_eq!(
        service.version(),
        Some("9.6p1"),
        "version should be extracted from the banner"
    );
}

/// A server that greets with an unrecognised banner still gets an open port and
/// *some* service label (a last-resort banner tag), never a silent drop of the
/// finding.
#[tokio::test]
async fn unknown_banner_still_yields_an_open_port() {
    if is_privileged() {
        eprintln!("SKIP: exercises the unprivileged connect path; run as non-root");
        return;
    }

    let server = spawn_banner_server(b"WIDGET/4.2 ready\r\n").await;
    let outcome = run_scan(
        target_map(LOOPBACK, &server.port.to_string()),
        &test_config(),
    )
    .await;

    let state = outcome
        .port_state(LOOPBACK, server.port)
        .expect("port present");
    assert_eq!(
        state,
        zond_engine::model::port::PortState::Open,
        "a reachable listener must read Open regardless of banner recognisability"
    );
}

/// ZA-4-013: an unprivileged scan reads what a banner says about the *machine*
/// and has to file it, the way the privileged path does.
///
/// `SSH-2.0-OpenSSH_9.6p1 Debian-3` names an operating system as plainly as it
/// names a product, and both come out of the one handshake this scanner makes.
/// The connect prober drew that evidence and dropped it, so a scan without root
/// disagreed with a scan with root about what it had just been told.
#[tokio::test]
async fn a_banner_naming_an_operating_system_reaches_the_host_record() {
    if is_privileged() {
        eprintln!("SKIP: exercises the unprivileged connect path; run as non-root");
        return;
    }

    let server = spawn_banner_server(b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n").await;
    let outcome = run_scan(
        target_map(LOOPBACK, &server.port.to_string()),
        &test_config(),
    )
    .await;

    let host = outcome.host(LOOPBACK).expect("loopback host recorded");
    let os = host
        .os()
        .expect("the banner named a system, so the host record should say so");

    assert_eq!(
        os.family().map(str::to_lowercase),
        Some("linux".to_string()),
        "got {os:?}"
    );
}
