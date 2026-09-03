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

/// An unprivileged scan reads what a banner says about the *machine* and has to
/// file it, the way the privileged path does.
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

/// A host that contradicts itself must not be better attested than one that
/// spoke once.
///
/// The banner is the most freely chosen thing a host emits, and a scan reads one
/// per port, so this is the shape a machine can arrange for itself: three SSH
/// banners naming three Debian releases it cannot all be running. Combined item
/// by item they read as three witnesses agreeing on Linux and resolved to 91,
/// eight of them to 95, past the point a caller treats an answer as settled.
///
/// Written here rather than beside `resolve`'s own tests because the evidence
/// has to arrive the way a scan delivers it. `identify` is called once per port
/// by the service pass, which is what files three items under one source, and
/// hand-built evidence is what let this stand.
#[tokio::test]
async fn a_host_contradicting_itself_gains_no_confidence() {
    if is_privileged() {
        eprintln!("SKIP: exercises the unprivileged connect path; run as non-root");
        return;
    }

    let honest = spawn_banner_server(b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n").await;
    let once = run_scan(
        target_map(LOOPBACK, &honest.port.to_string()),
        &test_config(),
    )
    .await;
    let baseline = once
        .host(LOOPBACK)
        .and_then(|host| host.os().map(|os| os.accuracy()))
        .expect("one banner names a system");

    let servers = [
        spawn_banner_server(b"SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4\r\n").await,
        spawn_banner_server(b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n").await,
        spawn_banner_server(b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u2\r\n").await,
    ];
    let ports: Vec<String> = servers.iter().map(|s| s.port.to_string()).collect();
    let outcome = run_scan(target_map(LOOPBACK, &ports.join(",")), &test_config()).await;
    let host = outcome.host(LOOPBACK).expect("loopback host recorded");

    // Non-vacuity: the three did reach the record separately. Were they folded
    // into one item on the way in, this would pass without saying anything about
    // the arithmetic it is here to pin.
    assert_eq!(
        host.os_evidence().count(),
        3,
        "three distinct claims, which is what makes the count meaningful"
    );

    let os = host.os().expect("the family is still named");
    assert_eq!(
        os.accuracy(),
        baseline,
        "three contradictory banners are one source speaking three times, got {os:?}"
    );
    assert!(
        os.generation().is_none(),
        "and the release the three disagree about is not reported, got {os:?}"
    );
}
