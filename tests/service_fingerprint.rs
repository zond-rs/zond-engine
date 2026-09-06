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

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

/// A server that answers one question and hangs up on every other, which is how
/// the services this exists for actually behave: Redis closes on the second line
/// of an HTTP request rather than answering it, and PostgreSQL reads the first
/// four bytes as a length and gives up.
///
/// Returns the port it is listening on. It accepts in a loop, because a ladder
/// that falls through dials again for each rung.
async fn spawn_challenge_server(question: &'static [u8], answer: &'static [u8]) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind a loopback challenge server");
    let port = listener.local_addr().expect("its address").port();

    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 512];
                let Ok(read) = sock.read(&mut buffer).await else {
                    return;
                };
                if buffer[..read].starts_with(question) {
                    let _ = sock.write_all(answer).await;
                    let _ = sock.flush().await;
                }
            });
        }
    });

    port
}

/// A service that speaks only when spoken to is identified on a port that
/// registers a different question entirely.
///
/// The half of the problem the ladder does not reach. Ordering the questions
/// gets a service that greets on connect, or one that answers the generic HTTP
/// request; it does nothing for a service that answers neither and whose own
/// probe is addressed to a port number it is no longer on. Redis moved to 8443
/// was reported as `kubernetes`, which is the number's registration and not
/// anything the host said.
///
/// 8443 and 8080 are chosen because they are registered, and registered to
/// something else: the last rung has to be reached past a port's own probes
/// drawing nothing, not merely on a port nobody claims.
#[tokio::test]
async fn a_service_that_answers_only_its_own_probe_is_still_identified() {
    // The version is what proves the reply was read rather than merely matched.
    // Redis has none to give: `+PONG` carries no version, which is why its own
    // signature captures none.
    for (question, answer, number, expected, version) in [
        (&b"PING"[..], &b"+PONG\r\n"[..], 8443u16, "redis", None),
        (
            &b"version"[..],
            &b"VERSION 1.6.21\r\n"[..],
            8080,
            "memcached",
            Some("1.6.21"),
        ),
    ] {
        let port = spawn_challenge_server(question, answer).await;

        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("the challenge server accepts");

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
            "port {number} kept its registration over what the host answered"
        );
        assert_eq!(service.version(), version, "on port {number}");
    }
}

/// The level below the default asks none of it.
///
/// The last rung is the one that puts other services' questions to a stranger,
/// and a caller who set the dial lower asked for that not to happen. The
/// assertion is that the probe never goes out, which shows as the service
/// staying unidentified against a server that would have answered it.
#[tokio::test]
async fn a_lower_level_does_not_reach_for_another_service_s_probe() {
    let port = spawn_challenge_server(b"PING", b"+PONG\r\n").await;

    let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("the challenge server accepts");

    let identified = fingerprint_tcp(
        stream,
        baseline_port(8443, Protocol::Tcp, PortState::Open),
        ServiceDetection::Banner,
    )
    .await;

    let named = identified
        .service()
        .map(|service| service.name().to_string());
    assert_ne!(
        named.as_deref(),
        Some("redis"),
        "a level that asks nothing cannot have asked redis its own question"
    );
}
