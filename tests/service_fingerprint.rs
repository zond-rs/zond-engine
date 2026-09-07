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

/// Redis, in the detail this needs, checked against `redis:7-alpine`.
///
/// Two behaviours, and the test turns on having both. A question it does not
/// know is *refused* rather than hung up on, so a collection that stopped at
/// the first reply it drew would take the refusal for an answer. An HTTP
/// request draws nothing, because `Host:` on the second line trips Redis's
/// guard against being driven by a web page and it closes without flushing;
/// that silence is what carries the port past the plaintext rung.
///
/// Returns the port it is listening on, and accepts in a loop, since a ladder
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
                let request = &buffer[..read];
                if request.windows(7).any(|w| w == b"HTTP/1.") {
                    return;
                }

                let reply: &[u8] = if request.starts_with(question) {
                    answer
                } else {
                    b"-ERR unknown command\r\n"
                };
                let _ = sock.write_all(reply).await;
                let _ = sock.flush().await;
            });
        }
    });

    port
}

/// A service that speaks only when spoken to is identified on a port that
/// registers a different question entirely.
///
/// The half of the problem ordering does not reach. Asking in the right order
/// finds a service that greets on connect or answers the generic HTTP request;
/// it does nothing for one that answers neither and whose own probe is
/// addressed to a port it is no longer on.
///
/// The numbers are registered ones, and registered to something else, because
/// the last rung has to be reached past a port's own probes drawing nothing and
/// not merely on a port nobody claims.
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
        // The refusal a StartupMessage naming an unspeakable protocol version
        // draws, as `postgres:16-alpine` writes it.
        (
            &b"\x00\x00\x00\x13\x00\x04\x00\x00user"[..],
            &b"E\x00\x00\x00\x83SFATAL\x00C0A000\x00Munsupported frontend protocol 4.0: server supports 3.0 to 3.0\x00"[..],
            55_555,
            "postgresql",
            None,
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

/// An SSH banner's trailing comment reaches the report.
///
/// RFC 4253 §4.2 allows free text after the software version, and a
/// distribution puts its own build of the package there. That build is finer
/// than the release it implies, and it is what somebody patching a fleet is
/// matching against, so it belongs on the port beside the version rather than
/// only in what the host record infers from it.
#[tokio::test]
async fn an_ssh_banners_distribution_build_survives_into_the_service() {
    for (banner, version, build) in [
        (
            &b"SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4\r\n"[..],
            "10.0p2",
            Some("Debian-7+deb13u4"),
        ),
        (
            &b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"[..],
            "9.6p1",
            Some("Ubuntu-3ubuntu13.5"),
        ),
        // `DebianBanner no` strips the comment, and a rule that invented one
        // would be reporting a build nothing announced.
        (&b"SSH-2.0-OpenSSH_9.6p1\r\n"[..], "9.6p1", None),
    ] {
        let server = spawn_banner_server(banner).await;
        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, server.port))
            .await
            .expect("the loopback fixture accepts");

        let identified = fingerprint_tcp(
            stream,
            baseline_port(22, Protocol::Tcp, PortState::Open),
            ServiceDetection::default(),
        )
        .await;

        let service = identified.service().expect("the banner names a service");
        let shown = String::from_utf8_lossy(banner);
        assert_eq!(service.version(), Some(version), "{shown:?}");
        assert_eq!(service.extrainfo(), build, "{shown:?}");
    }
}

/// A UPnP responder on 1900 is identified from the `SERVER` header of its
/// M-SEARCH answer.
///
/// The first UDP service identification this suite covers, and it exercises the
/// half of the pipeline TCP never reaches: a UDP reply becomes a banner only
/// through `extract::from_datagram`, so nothing the corpus says about SSDP can
/// fire unless that decoder produced the text. A rule matching its own example
/// would pass with the decoder missing entirely.
///
/// Bound to 1900 rather than to a free port because the corpus keys a UDP probe
/// on the destination number: on any other port this responder is sent nothing
/// and says nothing.
#[tokio::test]
async fn identifies_a_upnp_responder_from_its_server_header() {
    if is_privileged() {
        eprintln!("SKIP: exercises the unprivileged connect path; run as non-root");
        return;
    }

    /// What a consumer router answers M-SEARCH with.
    const ANSWER: &[u8] = b"HTTP/1.1 200 OK\r\n\
        CACHE-CONTROL: max-age=120\r\n\
        ST: upnp:rootdevice\r\n\
        USN: uuid:11111111-2222-3333-4444-555555555555::upnp:rootdevice\r\n\
        EXT:\r\n\
        SERVER: Linux/3.14.0, UPnP/1.0, MiniUPnPd/1.9\r\n\
        LOCATION: http://127.0.0.1:5000/rootDesc.xml\r\n\r\n";

    let Some(server) = spawn_udp_server_on(1900, ANSWER).await else {
        eprintln!("SKIP: 1900/udp is in use on this machine");
        return;
    };

    let outcome = run_scan(target_map(LOOPBACK, "U:1900"), &test_config()).await;
    let host = outcome.host(LOOPBACK).expect("loopback host recorded");
    let port = host
        .ports()
        .find(|p| p.number() == server.port && p.protocol() == Protocol::Udp)
        .expect("the scanned UDP port is present in the results");

    let service = port.service().expect("a service was identified");
    assert_eq!(
        service.product(),
        Some("MiniUPnPd"),
        "the SERVER header names the daemon"
    );
    assert_eq!(service.version(), Some("1.9"));
    assert_ne!(
        service.name(),
        "http",
        "an HTTP-shaped answer over UDP is not a web server"
    );
}
