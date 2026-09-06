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
//!
//! The last test here runs the same servers against port numbers registered to
//! something else. `fingerprint_tcp` takes the number as an argument rather than
//! reading it off the socket, so a misleading one can be handed to the real
//! engine over an ephemeral listener, with no root and no privileged bind.

mod common;

use std::net::Ipv4Addr;

use tokio::net::TcpStream;

use zond_engine::config::ServiceDetection;
use zond_engine::fingerprint::{baseline_port, fingerprint_tcp};
use zond_engine::model::port::{PortState, Protocol};

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

/// A port number orders the questions the engine asks and never answers them.
///
/// Services move. SSH is put on 443 to survive a proxy, a web UI is put on 22
/// because that hole is already open, and a database is put wherever the
/// compose file said. Every fixture above puts a service somewhere plausible,
/// which is the one arrangement that cannot catch a scanner reading the number
/// instead of the wire.
///
/// One did get through: OpenSSH on 443 came out as `http` for as long as an
/// implicit-TLS number sent the collection to a handshake and ended it there
/// when the handshake failed. This is written against the shape of that rather
/// than the instance, so the next number that acquires a shortcut has to survive
/// the same table.
///
/// No privilege check: this drives `fingerprint_tcp` directly rather than a
/// scan, so there is no raw-socket path for root to take and the assertions hold
/// either way.
#[tokio::test]
async fn a_service_is_named_from_the_wire_and_not_from_the_port_number() {
    // Two speak-first transcripts and what the engine owes each of them.
    let ssh: &'static [u8] = b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n";
    let web: &'static [u8] =
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n";

    // Numbers that suggest something else: two registered for implicit TLS,
    // where the shortcut lived; two registered for an unrelated service; and one
    // nothing in the corpus claims at all.
    let misleading = [443u16, 8443, 22, 3306, 55_555];

    for (transcript, expected, product) in [(ssh, "ssh", "OpenSSH"), (web, "http", "nginx")] {
        let server = spawn_banner_server(transcript).await;

        for number in misleading {
            let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, server.port))
                .await
                .expect("the loopback fixture accepts");

            let identified = fingerprint_tcp(
                stream,
                baseline_port(number, Protocol::Tcp, PortState::Open),
                ServiceDetection::default(),
            )
            .await;

            let service = identified
                .service()
                .unwrap_or_else(|| panic!("nothing identified on port {number}"));

            assert_eq!(
                service.name(),
                expected,
                "port {number} named the service, the wire said {expected}"
            );
            assert_eq!(
                service.product(),
                Some(product),
                "port {number} lost the product the transcript names"
            );
        }
    }
}
