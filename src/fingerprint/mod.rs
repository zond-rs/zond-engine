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
mod extract;
mod http;
mod matcher;
mod pattern;
mod prefilter;
mod response;
mod signature;
mod snmp;
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

use crate::config::ServiceDetection;
use crate::model::port::{Port, PortState, Protocol, Service};

/// How long to wait for a service to speak first (banner grab).
const BANNER_READ_TIMEOUT: Duration = Duration::from_millis(500);
/// How long to wait for a reply to an active probe.
const PROBE_READ_TIMEOUT: Duration = Duration::from_millis(1_000);
/// How long to keep reading once a response has started arriving.
///
/// Not a second timeout on the response: the response has already begun, and
/// this is only how long its remainder is worth waiting for. What it has to
/// bridge is the gap between a server writing its headers and writing its body,
/// which is a segment boundary rather than a delay — sub-millisecond on a
/// segment and one round trip at worst anywhere else.
///
/// It is paid in full by every response that is *already* complete, since a
/// finished server simply goes quiet and there is no way to tell that apart from
/// a slow one without waiting. So it is set as low as the job allows: fifty
/// milliseconds bridges any real gap, and the ports pay it in parallel, so it
/// costs a scan the grace once rather than once per port.
const CONTINUATION_GRACE: Duration = Duration::from_millis(50);
/// How long to wait for the second connection a speculative TLS handshake needs.
///
/// The first one already completed to this same port, so this either succeeds
/// immediately or the port has stopped accepting — there is nothing here worth
/// a long wait.
const CONNECT_RETRY_TIMEOUT: Duration = Duration::from_millis(500);
/// Upper bound on how much of a single response we read/keep.
const MAX_RESPONSE_BYTES: usize = 4096;

/// Whether a reply from this port over this protocol is one the engine can read.
///
/// What decides whether a port is worth the exchange a service pass costs. A TCP
/// port always is: any of them may volunteer a banner, and reading one costs a
/// connection. A UDP port is worth a datagram only where something here can turn
/// the answer into text — otherwise the reply proves the port open, which the
/// scan that found it already knew.
#[must_use]
pub fn reads_replies(port: u16, protocol: Protocol) -> bool {
    extract::reads(port, protocol)
}

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
pub async fn fingerprint_tcp(stream: TcpStream, port: Port, detection: ServiceDetection) -> Port {
    fingerprint_tcp_detailed(stream, port, detection).await.0
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
    detection: ServiceDetection,
) -> (Port, Vec<os::OsEvidence>) {
    // Capture the peer address before `gather` consumes the stream, so active
    // analyzers can open their own connection to the same target.
    let addr = stream.peer_addr().ok();
    let (responses, tunnel) = gather(stream, port.number(), detection).await;
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
    match analyze(port.number(), Protocol::Tcp, addr, responses, tunnel).await {
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

/// Fingerprints an open **UDP** port, returning the upgraded [`Port`] and
/// whatever the reply said about the machine behind it.
///
/// The sibling of [`fingerprint_tcp_detailed`], and deliberately the same shape:
/// draw a response, turn it into the text the corpus is written against, and
/// hand it to the same analyzers. Only the drawing differs, because UDP has no
/// connection to open and no banner to wait for.
///
/// # Why this is a second datagram rather than the scan's own
///
/// The UDP port scan already sends this exact payload and already sees this
/// exact reply — it is how the port was known to be open at all — and then
/// discards the body, because what it needed was the *fact* of an answer. Wiring
/// that reply through would save a datagram and cost the thing that makes the
/// scan fast: the scanner would have to hold every response body for every port
/// it probed, through a paced run, against the chance that a later phase wants
/// one. This is the same trade the TCP side already makes, where the service
/// pass reconnects to a port the scan has already knocked on.
///
/// # What it will not do
///
/// **Speak to a port it cannot read.** A datagram is only worth sending where
/// something here could turn the answer into text — see
/// [`reads_replies`] — because unlike a TCP banner grab, an unread UDP reply
/// teaches nothing the scan does not already know.
///
/// **Claim a port answered when it did not.** `None` means silence, and silence
/// over UDP is the ordinary case: no connection is refused and no banner is
/// withheld, so nothing distinguishes a filtered port from one with nothing
/// behind it. A caller that dialled a port on its own account uses this to tell
/// whether it found anything at all.
pub async fn fingerprint_udp_detailed(
    addr: std::net::SocketAddr,
    mut port: Port,
) -> Option<(Port, Vec<os::OsEvidence>)> {
    let text = probe_udp(addr).await?;
    let responses = ResponseSet::from_banners(vec![text]);

    // No tunnel: nothing here carries UDP over TLS. No peer address handed to
    // the analyzers either — an active analyzer dials TCP, and this port's
    // address is not one it could speak to.
    let verdict = analyze(addr.port(), Protocol::Udp, None, responses, None)
        .await
        .filter(|verdict| !verdict.is_empty())?;

    let about_the_host = verdict
        .evidence
        .iter()
        .filter_map(|e| e.os.clone())
        .collect();
    if let Some(service) = verdict.to_service() {
        port.set_service(service);
    }

    Some((port, about_the_host))
}

/// Sends this port's registered probe and reads back whatever text the reply
/// carries, or `None` if it carried none.
///
/// Bound to an ephemeral port of the same family as the target, and
/// **connected**, so the kernel drops anything from another address before it
/// reaches here: a scanner reading unsolicited datagrams off an unconnected
/// socket would attribute one host's answer to another's port.
async fn probe_udp(addr: std::net::SocketAddr) -> Option<String> {
    let payload = SignatureDb::global()
        .udp_probe_payloads(addr.port())
        .first()?;

    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = tokio::net::UdpSocket::bind(bind).await.ok()?;
    socket.connect(addr).await.ok()?;
    socket.send(payload).await.ok()?;

    let mut buffer = vec![0u8; MAX_RESPONSE_BYTES];
    let read = timeout(PROBE_READ_TIMEOUT, socket.recv(&mut buffer))
        .await
        .ok()?
        .ok()?;

    extract::from_datagram(addr.port(), &buffer[..read])
}

/// Collects everything the transport can learn from the port over the network,
/// and how it was carried.
///
/// Three shapes, and which one a port gets is decided by whether anything in the
/// signature database claims it.
///
/// An **implicit-TLS** port handshakes straight away and collects through the
/// tunnel. A **claimed** port — one some service registered a probe for — is
/// listened to and then asked, in that order, because a service that greets on
/// connect should be heard before it is interrupted. An **unclaimed** port is
/// asked generically; see [`ask_generically`].
///
/// Whenever a handshake succeeds the collection re-runs *inside* the tunnel, so
/// the protocol carried by TLS is fingerprinted too, and the returned [`Tunnel`]
/// records that it was.
async fn gather(
    mut stream: TcpStream,
    port: u16,
    detection: ServiceDetection,
) -> (ResponseSet, Option<Tunnel>) {
    let peer = stream.peer_addr().ok().map(|addr| addr.ip());
    let socket = stream.peer_addr().ok();

    // Identify nothing. Reached only from the unprivileged path, where the
    // connection is how the port's state was established and so exists whether
    // or not anything is to be learned from it; the privileged path stops a
    // level earlier, in `service::detect`, and never opens one at all.
    if !detection.connects() {
        return (ResponseSet::default(), None);
    }

    // Listen only. Everything below this line puts bytes on the wire — the
    // ClientHello of a handshake as much as the probes — so the level that
    // promises to send nothing has to stop here rather than further in.
    if !detection.sends() {
        let banner = read_response(&mut stream, BANNER_READ_TIMEOUT).await;
        return (ResponseSet::from_banners(banner.into_iter().collect()), None);
    }

    if tls::is_tls_port(port) {
        // Implicit-TLS port: the peer waits for our ClientHello, so skip the
        // banner grab that would only time out and handshake immediately.
        return match peer {
            Some(ip) => tunneled(tls::handshake(stream, ip).await, port).await,
            None => (ResponseSet::default(), None),
        };
    }

    let probes = SignatureDb::global().tcp_probe_payloads(port);
    if !probes.is_empty() {
        // A port something claims: listen, then ask what that service asks.
        let banners = collect_responses(&mut stream, probes).await;
        return (ResponseSet::from_banners(banners), None);
    }

    // A port nothing claims. Ask it the one question worth asking of anything.
    match ask_generically(&mut stream).await {
        GenericReply::Spoke(banners) => (ResponseSet::from_banners(banners), None),
        // Either it answered in TLS or it answered nothing, and both are reasons
        // to try a handshake. The socket cannot be reused for one — it has our
        // plaintext request on it — so this costs a second connection, paid only
        // on the ports that have already declined to speak.
        GenericReply::Tls | GenericReply::Silent => match (peer, socket) {
            (Some(ip), Some(socket)) => {
                let Ok(Ok(fresh)) = timeout(CONNECT_RETRY_TIMEOUT, TcpStream::connect(socket)).await
                else {
                    return (ResponseSet::default(), None);
                };
                tunneled(tls::speculative_handshake(fresh, ip).await, port).await
            }
            _ => (ResponseSet::default(), None),
        },
    }
}

/// What a generic probe drew out of a port nothing in the database claims.
enum GenericReply {
    /// It answered in something we can read. Whatever it said is here.
    Spoke(Vec<String>),
    /// It answered in TLS — an alert, most likely, since what we sent was not a
    /// ClientHello. The port speaks, just not to that question.
    Tls,
    /// Nothing came back at all.
    Silent,
}

/// Asks an unclaimed port the one question worth asking of any open port, and
/// reads whatever comes back.
///
/// **The request goes out before anything is read**, which inverts the order the
/// claimed-port path uses, and the inversion is safe for a reason worth writing
/// down: a service that greets on connect has *already sent* its greeting by the
/// time we write, and TCP will deliver it whether or not we asked for something
/// else first. So writing first cannot lose a banner — it can only save the
/// timeout that waiting for a banner nobody is going to send would cost.
///
/// That saving is the whole point. The old path waited half a second for a
/// greeting, sent nothing, concluded the port was silent, and then spent up to
/// another second and a half guessing that the silence was TLS. Measured against
/// one ordinary home server that was two seconds per unidentified port, on seven
/// of its eleven open ports, to learn nothing about any of them. An HTTP request
/// answers in a round trip and names most of them.
async fn ask_generically(stream: &mut TcpStream) -> GenericReply {
    for payload in SignatureDb::global().generic_tcp_probe_payloads() {
        if stream.write_all(payload).await.is_err() {
            break;
        }
    }

    let Some(bytes) = read_bytes(stream, PROBE_READ_TIMEOUT, CONTINUATION_GRACE).await else {
        return GenericReply::Silent;
    };
    if looks_like_tls(&bytes) {
        return GenericReply::Tls;
    }

    GenericReply::Spoke(vec![String::from_utf8_lossy(&bytes).into_owned()])
}

/// Whether `bytes` open a TLS record.
///
/// A content type in the range TLS defines, then a major version of 3 and a
/// minor version no higher than TLS 1.3 uses on the wire. What this catches in
/// practice is the alert a TLS server sends when it is handed a plaintext
/// request: our `G` of `GET` is not a record type it knows, so it says so and
/// closes. Read as text that alert is a handful of unprintable bytes, and taking
/// it for a banner would leave a TLS service reported as an unidentifiable one.
fn looks_like_tls(bytes: &[u8]) -> bool {
    matches!(bytes, [0x14..=0x17, 0x03, 0x00..=0x04, ..])
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
    // Inside the tunnel the port's own probes apply if it has any, and the
    // generic question if it does not — the protocol under TLS is as
    // unidentified as it would have been in the clear. A caller who asked to
    // send nothing never reaches here: `gather` returns before the handshake.
    let db = SignatureDb::global();
    let probes = match db.tcp_probe_payloads(port) {
        [] => db.generic_tcp_probe_payloads(),
        own => own,
    };
    let banners = collect_responses(&mut tunnel, probes).await;
    let responses = ResponseSet {
        banners,
        tls: Some(info),
    };
    (responses, Some(Tunnel::Tls))
}

/// Grabs a first-speak banner and then sends `probes` over `stream`, returning
/// every non-empty response. Generic over the transport, so it runs identically
/// on a raw socket or inside a TLS tunnel.
///
/// The probes are passed in rather than looked up, because the caller is what
/// knows which set applies: a port's own where it has them, and the generic set
/// where it does not.
async fn collect_responses<S>(stream: &mut S, probes: &[Vec<u8>]) -> Vec<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut banners = Vec::new();

    // Many services announce themselves on connect.
    if let Some(banner) = read_response(stream, BANNER_READ_TIMEOUT).await {
        banners.push(banner);
    }

    for payload in probes {
        if stream.write_all(payload).await.is_err() {
            break;
        }
        if let Some(reply) = read_document(stream, PROBE_READ_TIMEOUT).await {
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
    protocol: Protocol,
    addr: Option<std::net::SocketAddr>,
    responses: ResponseSet,
    tunnel: Option<Tunnel>,
) -> Option<ServiceVerdict> {
    let ctx = PortContext {
        port,
        protocol,
        addr,
        tunnel,
    };

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
    read_bytes(stream, wait, Duration::ZERO)
        .await
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// [`read_response`], but reading on until the port goes quiet.
///
/// For a reply that may be a *document* rather than a line. One `read` returns
/// one segment, and an HTTP server that writes its headers and its body
/// separately hands over the headers alone — so the `Server` header arrives and
/// the `<title>` that names the application does not, on exactly the ports where
/// the title is the only thing that would have named it.
///
/// Deliberately not what a banner grab uses. A greeting is one short write and
/// waiting on for a second one costs [`CONTINUATION_GRACE`] on every port that
/// greets, which is the fastest path there is and the last one worth taxing.
async fn read_document<S>(stream: &mut S, wait: Duration) -> Option<String>
where
    S: AsyncRead + Unpin,
{
    read_bytes(stream, wait, CONTINUATION_GRACE)
        .await
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Reads up to [`MAX_RESPONSE_BYTES`] of whatever the port sends, waiting `wait`
/// for the first byte and `grace` for each read after it.
///
/// A `grace` of zero reads exactly once, which is what a banner grab wants; a
/// non-zero one reads on until the port goes quiet, which is what a document
/// wants. See [`read_response`] and [`read_document`].
///
/// Bytes rather than text, because the caller sometimes has to tell a banner
/// from a TLS alert and `from_utf8_lossy` destroys the difference.
async fn read_bytes<S>(stream: &mut S, wait: Duration, grace: Duration) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut collected: Vec<u8> = Vec::new();
    let mut buffer = [0u8; MAX_RESPONSE_BYTES];
    let mut budget = wait;

    while collected.len() < MAX_RESPONSE_BYTES {
        match timeout(budget, stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let room = MAX_RESPONSE_BYTES - collected.len();
                collected.extend_from_slice(&buffer[..n.min(room)]);
                if grace.is_zero() {
                    break;
                }
                budget = grace;
            }
            // A clean close, an error, or the port going quiet: whatever has
            // arrived is all there is.
            _ => break,
        }
    }

    (!collected.is_empty()).then_some(collected)
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

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn analyze_runs_both_phases_and_resolves() {
        // Drives the real orchestration — the collect phase (a no-op for the two
        // passive analyzers) followed by the off-reactor analyze phase — over a
        // recorded SSH banner, and asserts it resolves through to a verdict.
        let responses = ResponseSet::from_banners(vec!["SSH-2.0-OpenSSH_9.6p1 Debian".to_string()]);
        let verdict = analyze(22, Protocol::Tcp, None, responses, None)
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
        let verdict = analyze(8000, Protocol::Tcp, None, responses, None)
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
        let service = analyze(80, Protocol::Tcp, None, responses, None)
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
        let verdict = analyze(8000, Protocol::Tcp, None, responses, None)
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
            analyze(1, Protocol::Tcp, None, ResponseSet::default(), None)
                .await
                .is_none()
        );
    }
}
