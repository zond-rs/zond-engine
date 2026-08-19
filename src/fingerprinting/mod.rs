// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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
//! Every analyzer runs in two phases and `analyze` enforces the split: the
//! transport's first-contact I/O and each analyzer's own `collect` probes run on
//! the async reactor; all `analyze` (CPU) work is handed to the blocking pool.
//! Nothing in this module compiles a regex on a reactor thread — see
//! `SignatureDb` for why that matters.
//!
//! The design and roadmap live in `docs/fingerprinting.md`.

pub mod model;

pub mod os;

mod analyzer;
mod db;
mod http;
mod matcher;
mod pattern;
mod prefilter;
mod response;
mod signature;
mod ssh;
mod tls;
mod tls_cert;
mod tls_summary;

#[cfg(test)]
mod corpus;
// Kept apart from `pattern` because `build.rs` loads that file with `#[path]`
// and has no `proptest`; see the module docs.
#[cfg(test)]
mod pattern_properties;

pub use analyzer::{Analyzer, BannerRegexAnalyzer, PortContext};
pub use db::SignatureDb;
pub use http::HttpHeadersAnalyzer;
pub use model::{Confidence, Evidence, ServiceVerdict, SourceId, Tunnel};
pub use response::{Collected, ResponseSet, TlsInfo};
// The schema an `assets/fingerprinting` signature file is written against.
// `build.rs` compiles the shipped signatures out of it and validates them; these
// are exported so a consumer authoring signatures of their own is held to the
// same bounds rather than discovering them when a pattern is silently dropped.
pub use signature::{
    MAX_COMPILED_REGEX_BYTES, MAX_UDP_PROBE_BYTES, MatchRule, Probe, ServiceDefinition,
    ServiceSignature,
};
pub use ssh::SshAnalyzer;
pub use tls_cert::TlsCertAnalyzer;

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::model::port::{Port, PortState, Protocol, Service};

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

/// The confidence-0 service every scan path seeds before deeper fingerprinting:
/// the port→name label, or the `???` placeholder when a port has no registered
/// name. Centralising it keeps the SYN, connect, and service-detection paths
/// agreeing on the same starting point.
pub fn baseline_service(port: u16, protocol: Protocol) -> Service {
    let name = lookup_service_name(port, protocol).unwrap_or_else(|| "???".to_string());
    Service::new(name, 0)
}

/// A [`Port`] in the given `state` carrying only the [`baseline_service`] label.
///
/// This is the shape every discovery path records before (and if) a full
/// fingerprint refines it: the SYN and filtered/closed paths stop here, while
/// the connect and service-detection paths hand the result to
/// [`fingerprint_tcp`] to upgrade in place.
pub fn baseline_port(port: u16, protocol: Protocol, state: PortState) -> Port {
    let mut classified = Port::new(port, protocol, state);
    classified.set_service(baseline_service(port, protocol));
    classified
}

/// Actively fingerprints an open TCP `stream` and refines `port`'s service.
///
/// Network I/O — the banner grab and any active probes — runs here on the async
/// reactor with bounded reads and per-stage timeouts. The CPU-bound signature
/// matching is handed to `analyze`, which runs on the blocking pool so a large
/// match set can never stall the scheduler.
///
/// If nothing identifies, a trimmed printable banner is attached as a
/// last-resort label rather than leaving the port unannotated.
pub async fn fingerprint_tcp(stream: TcpStream, port: Port) -> Port {
    fingerprint_tcp_detailed(stream, port).await.0
}

/// [`fingerprint_tcp`], also returning what the service said about the *machine*.
///
/// Over half the shipped signature corpus carries operating-system metadata, and
/// a banner naming a distribution — `OpenSSH_9.6p1 Debian` — is the most direct
/// statement a host ever makes about itself. It is read here because this is
/// where the text already is; no probe is added to collect it.
///
/// Separate from [`fingerprint_tcp`] rather than replacing it because the two
/// findings belong to different places: the service belongs to the port, and what
/// it implies about the operating system belongs to the host. A caller with no
/// host to file it against should not have to handle it.
pub async fn fingerprint_tcp_detailed(
    stream: TcpStream,
    mut port: Port,
) -> (Port, Vec<os::OsEvidence>) {
    // Capture the peer address before `gather` consumes the stream, so active
    // analyzers can open their own connection to the same target.
    let addr = stream.peer_addr().ok();
    let (responses, tunnel) = gather(stream, port.number()).await;
    if responses.is_empty() {
        return (port, Vec::new());
    }

    // Recorded before the response set is handed off, and independently of what
    // the analyzers conclude. A handshake is a fact about the port; whether any
    // analyzer manages to name the service behind it is a separate question, and
    // a port whose service stays unidentified still has a certificate worth
    // reporting.
    if let Some(tls) = responses.tls.as_ref() {
        port.set_security(tls_summary::security(tls));
    }

    // Analysis runs off the reactor. Keep a last-resort banner label before the
    // response set is handed to the blocking pool.
    let fallback = first_printable(&responses.banners);
    let mut about_the_host = Vec::new();
    match analyze(port.number(), addr, responses, tunnel).await {
        Some(verdict) if !verdict.is_empty() => {
            // Taken from the whole retained evidence set rather than from the
            // winning service alone: a host running two identifiable services
            // says the same thing about itself twice, and a signature that lost
            // the ranking for *service* may still be the one that named the
            // operating system.
            about_the_host.extend(verdict.evidence.iter().filter_map(|e| e.os.clone()));
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

    (port, about_the_host)
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

/// The analyzer registry. New evidence sources (HTTP, JARM, SNMP, nerva binary
/// handlers, ...) are added here — the only place the set is enumerated. The
/// instances are stateless zero-sized values, so a `'static` slice of shared
/// references is free and lets both phases (and the blocking task) reference the
/// same set.
static ANALYZERS: &[&dyn Analyzer] = &[
    &BannerRegexAnalyzer,
    &HttpHeadersAnalyzer,
    &SshAnalyzer,
    &TlsCertAnalyzer,
];

/// Runs the registered analyzers over `responses` and resolves their evidence
/// into a verdict, honouring the two-phase contract: each interested analyzer's
/// [`collect`](Analyzer::collect) runs here on the reactor (I/O), then all the
/// [`analyze`](Analyzer::analyze) work is handed to the blocking pool (CPU).
/// `tunnel` marks how the shared responses were carried, so evidence drawn from
/// decrypted data is labelled accordingly. Returns `None` if analysis produced
/// nothing (or the blocking task failed to join).
async fn analyze(
    port: u16,
    addr: Option<std::net::SocketAddr>,
    responses: ResponseSet,
    tunnel: Option<Tunnel>,
) -> Option<ServiceVerdict> {
    let ctx = PortContext { port, addr, tunnel };

    // Phase 1 — I/O on the reactor: let each interested analyzer run its own
    // probes. Passive analyzers return an empty `Collected` (their inputs are in
    // the shared `responses`); the index of each result matches `ANALYZERS`.
    let mut collected = Vec::with_capacity(ANALYZERS.len());
    for analyzer in ANALYZERS {
        collected.push(if analyzer.interested(&ctx) {
            analyzer.collect(&ctx).await
        } else {
            Collected::default()
        });
    }

    // Phase 2 — CPU off the reactor: parse the shared responses plus each
    // analyzer's own frames into evidence, then resolve. A large match set can
    // never stall the scheduler from here.
    tokio::task::spawn_blocking(move || {
        let mut evidence = Vec::new();
        for (analyzer, collected) in ANALYZERS.iter().zip(&collected) {
            if analyzer.interested(&ctx) {
                evidence.extend(analyzer.analyze(&ctx, &responses, collected));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn analyze_runs_both_phases_and_resolves() {
        // Drives the real orchestration — the collect phase (a no-op for the two
        // passive analyzers) followed by the off-reactor analyze phase — over a
        // recorded SSH banner, and asserts it resolves through to a verdict.
        let responses = ResponseSet::from_banners(vec!["SSH-2.0-OpenSSH_9.6p1 Debian".to_string()]);
        let verdict = analyze(22, None, responses, None)
            .await
            .expect("names a service");

        assert_eq!(verdict.service.as_deref(), Some("ssh"));
        assert_eq!(verdict.product.as_deref(), Some("OpenSSH"));
        assert_eq!(verdict.version.as_deref(), Some("9.6p1"));
    }

    #[tokio::test]
    async fn analyze_identifies_a_long_tail_http_server_end_to_end() {
        // gunicorn has no curated `Server:` regex, so the banner analyzer can
        // only reach the generic `http` label. The structured HTTP analyzer must
        // carry it through to product and version via the full pipeline.
        let responses = ResponseSet::from_banners(vec![
            "HTTP/1.1 200 OK\r\nServer: gunicorn/21.2.0\r\nContent-Type: text/html\r\n\r\n"
                .to_string(),
        ]);
        let verdict = analyze(8000, None, responses, None)
            .await
            .expect("names a service");

        assert_eq!(verdict.service.as_deref(), Some("http"));
        assert_eq!(verdict.product.as_deref(), Some("gunicorn"));
        assert_eq!(verdict.version.as_deref(), Some("21.2.0"));
    }

    #[tokio::test]
    async fn analyze_composes_curated_product_vendor_with_powered_by_extrainfo() {
        // End-to-end composition across analyzers: the curated Apache signature
        // (banner analyzer) supplies the rich product + vendor, the structured
        // HTTP analyzer supplies the X-Powered-By extrainfo, and the framework
        // never usurps the product slot. All three land on one Service.
        let responses = ResponseSet::from_banners(vec![
            "HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\nX-Powered-By: PHP/8.2.1\r\n\r\n"
                .to_string(),
        ]);
        let service = analyze(80, None, responses, None)
            .await
            .expect("names a service")
            .to_service()
            .expect("projects onto a service");

        assert_eq!(service.name(), "http");
        assert_eq!(service.product(), Some("Apache HTTP Server"));
        assert_eq!(service.vendor(), Some("Apache Software Foundation"));
        assert_eq!(service.version(), Some("2.4.58"));
        assert_eq!(service.extrainfo(), Some("PHP/8.2.1"));
    }

    #[tokio::test]
    async fn analyze_resolves_a_versionless_server_to_its_name_not_generic_http() {
        // Regression: a versionless `Server` is Probable, the same as the HTTP
        // analyzer's baseline. If the baseline names a product, the stable sort
        // keeps it first and the real server ("cloudflare") is buried under a
        // generic "http". This must resolve to the server name.
        let responses = ResponseSet::from_banners(vec![
            "HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\n\r\n".to_string(),
        ]);
        let verdict = analyze(8000, None, responses, None)
            .await
            .expect("names a service");

        assert_eq!(verdict.service.as_deref(), Some("http"));
        assert_eq!(verdict.product.as_deref(), Some("cloudflare"));
    }

    #[tokio::test]
    async fn analyze_returns_none_when_no_evidence() {
        // No banners and no TLS: both phases run, no analyzer produces evidence,
        // so the orchestration resolves to nothing rather than an empty verdict.
        assert!(
            analyze(1, None, ResponseSet::default(), None)
                .await
                .is_none()
        );
    }
}
