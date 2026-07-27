// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Service Fingerprinting
//!
//! Identifies the service, product, and version behind an open port. This is
//! distinct from discovery (which ports are alive); fingerprinting answers
//! *what is running there*.
//!
//! ## Shape
//!
//! ```text
//! open port ─▶ probe I/O (async) ─▶ responses ─▶ analyzers (CPU, off-reactor)
//!                                                     │
//!                                              Vec<Evidence>
//!                                                     ▼
//!                                        Resolver ─▶ ServiceVerdict ─▶ Service
//! ```
//!
//! * [`model`] is the shared vocabulary: [`Evidence`], [`ServiceVerdict`],
//!   [`Confidence`].
//! * [`SignatureDb`] is the runtime view of the signature database — a cheap
//!   `port -> name` index plus lazily compiled, cached matchers.
//! * [`Analyzer`]s are the extension point; [`BannerRegexAnalyzer`] is the first.
//!
//! ## Concurrency contract
//!
//! Network I/O runs on the async reactor here in [`fingerprint_tcp`]; the
//! CPU-bound analysis runs on the blocking pool via [`analyze`]. Nothing in this
//! module compiles a regex on a reactor thread — see `SignatureDb` for why that
//! matters.
//!
//! The design and roadmap live in `docs/fingerprinting-redesign.md`.

pub mod model;

mod analyzer;
mod db;
mod matcher;
mod prefilter;
mod response;
mod tls;
mod tls_cert;

#[cfg(test)]
mod corpus;

pub use analyzer::{Analyzer, BannerRegexAnalyzer, PortContext};
pub use db::SignatureDb;
pub use model::{Confidence, Evidence, ServiceVerdict, SourceId, Tunnel};
pub use response::{ResponseSet, TlsInfo};
pub use tls_cert::TlsCertAnalyzer;

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::core::models::port::{Port, Protocol, Service};

/// How long to wait for a service to speak first (banner grab).
const BANNER_READ_TIMEOUT: Duration = Duration::from_millis(500);
/// How long to wait for a reply to an active probe.
const PROBE_READ_TIMEOUT: Duration = Duration::from_millis(1_000);
/// Upper bound on how much of a single response we read/keep.
const MAX_RESPONSE_BYTES: usize = 4096;

/// The service name registered for a port number, if any.
///
/// A pure metadata lookup with **no regex compilation**, safe to call on the
/// scan hot path for every classified port. Returns the same names the fuller
/// fingerprinting path uses, so a quick label and a deep identification agree.
pub fn lookup_service_name(port: u16, _protocol: Protocol) -> Option<String> {
    SignatureDb::global()
        .service_name(port)
        .map(|s| s.to_string())
}

/// Actively fingerprints an open TCP `stream` and refines `port`'s service.
///
/// Network I/O — the banner grab and any active probes — runs here on the async
/// reactor with bounded reads and per-stage timeouts. The CPU-bound signature
/// matching is handed to [`analyze`], which runs on the blocking pool so a large
/// match set can never stall the scheduler.
///
/// If nothing identifies, a trimmed printable banner is attached as a
/// last-resort label rather than leaving the port unannotated.
pub async fn fingerprint_tcp(stream: TcpStream, mut port: Port) -> Port {
    let (responses, tunnel) = gather(stream, port.number()).await;
    if responses.is_empty() {
        return port;
    }

    // Analysis runs off the reactor. Keep a last-resort banner label before the
    // response set is handed to the blocking pool.
    let fallback = first_printable(&responses.banners);
    match analyze(port.number(), responses, tunnel).await {
        Some(verdict) if !verdict.is_empty() => {
            if let Some(service) = verdict.to_service() {
                port.set_service(service);
            }
        }
        _ => {
            if let Some(banner) = fallback {
                port.set_service(Service::new(format!("banner: {banner}"), 0));
            }
        }
    }

    port
}

/// Collects everything the transport can learn from the port over the network,
/// and how it was carried.
///
/// Three cases: an **implicit-TLS** port handshakes straight away and collects
/// through the tunnel; a plaintext port grabs a banner and runs its probes; a
/// plaintext port that stays **silent and un-probed** (so the socket is still
/// pristine) gets one *speculative* handshake in case it is TLS on a
/// non-standard port. Whenever a handshake succeeds, the banner/probe collection
/// re-runs *inside* the tunnel, so the protocol carried by TLS is fingerprinted
/// too — and the returned [`Tunnel`] records that it was.
async fn gather(mut stream: TcpStream, port: u16) -> (ResponseSet, Option<Tunnel>) {
    let peer = stream.peer_addr().ok().map(|addr| addr.ip());

    if tls::is_tls_port(port) {
        // Implicit-TLS port: the peer waits for our ClientHello, so skip the
        // banner grab that would only time out and handshake immediately.
        return match peer {
            Some(ip) => tunneled(tls::handshake(stream, ip).await, port).await,
            None => (ResponseSet::default(), None),
        };
    }

    // Plaintext: banner grab + active probes over the raw socket.
    let had_probes = !SignatureDb::global().tcp_probe_payloads(port).is_empty();
    let banners = collect_responses(&mut stream, port).await;

    // A port that answered, or that we already probed (committing the socket to
    // its plaintext protocol), is not a TLS re-probe candidate.
    if !banners.is_empty() || had_probes {
        return (ResponseSet::from_banners(banners), None);
    }

    // Silent and pristine: it might be TLS on a non-standard port.
    match peer {
        Some(ip) => tunneled(tls::speculative_handshake(stream, ip).await, port).await,
        None => (ResponseSet::default(), None),
    }
}

/// Given the outcome of a handshake, re-probes through the tunnel (if it
/// completed) and packages the decrypted responses with the captured
/// certificate. A failed handshake yields nothing.
async fn tunneled(
    handshake: Option<(tls::TlsTunnel, TlsInfo)>,
    port: u16,
) -> (ResponseSet, Option<Tunnel>) {
    let Some((mut tunnel, info)) = handshake else {
        return (ResponseSet::default(), None);
    };
    let banners = collect_responses(&mut tunnel, port).await;
    let responses = ResponseSet {
        banners,
        tls: Some(info),
    };
    (responses, Some(Tunnel::Tls))
}

/// Grabs a first-speak banner and then runs the port's active probes over
/// `stream`, returning every non-empty response. Generic over the transport, so
/// it runs identically on a raw socket or inside a TLS tunnel.
async fn collect_responses<S>(stream: &mut S, port: u16) -> Vec<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut banners = Vec::new();

    // Many services announce themselves on connect.
    if let Some(banner) = read_response(stream, BANNER_READ_TIMEOUT).await {
        banners.push(banner);
    }

    for payload in SignatureDb::global().tcp_probe_payloads(port) {
        if stream.write_all(payload).await.is_err() {
            break;
        }
        if let Some(reply) = read_response(stream, PROBE_READ_TIMEOUT).await {
            banners.push(reply);
        }
    }

    banners
}

/// Runs the registered analyzers over `responses` on the blocking pool and
/// resolves their evidence into a verdict. `tunnel` marks how the responses were
/// carried, so evidence drawn from decrypted data is labelled accordingly.
/// Returns `None` if analysis produced nothing (or the blocking task failed to
/// join).
async fn analyze(
    port: u16,
    responses: ResponseSet,
    tunnel: Option<Tunnel>,
) -> Option<ServiceVerdict> {
    tokio::task::spawn_blocking(move || {
        let ctx = PortContext { port, tunnel };

        // The analyzer registry. New evidence sources (HTTP, JARM, SNMP, ...)
        // are added here.
        let analyzers: [&dyn Analyzer; 2] = [&BannerRegexAnalyzer, &TlsCertAnalyzer];

        let mut evidence = Vec::new();
        for analyzer in analyzers {
            if analyzer.interested(&ctx) {
                evidence.extend(analyzer.analyze(&ctx, &responses));
            }
        }

        (!evidence.is_empty()).then(|| ServiceVerdict::resolve(evidence))
    })
    .await
    .ok()
    .flatten()
}

/// Reads one bounded chunk from `stream`, giving up after `wait`. Returns `None`
/// on timeout, error, or a clean empty read.
async fn read_response<S>(stream: &mut S, wait: Duration) -> Option<String>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = [0u8; MAX_RESPONSE_BYTES];
    match timeout(wait, stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => Some(String::from_utf8_lossy(&buffer[..n]).into_owned()),
        _ => None,
    }
}

/// The first 32 printable characters across `responses`, for a last-resort
/// banner label. `None` if there is nothing printable.
fn first_printable(responses: &[String]) -> Option<String> {
    let printable: String = responses
        .iter()
        .flat_map(|response| response.chars())
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(32)
        .collect();

    (!printable.is_empty()).then_some(printable)
}
