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

#[cfg(test)]
mod corpus;

pub use analyzer::{Analyzer, BannerRegexAnalyzer, PortContext};
pub use db::SignatureDb;
pub use matcher::ServiceMatcher;
pub use model::{Confidence, Evidence, ServiceVerdict, SourceId};

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    SignatureDb::global().service_name(port).map(|s| s.to_string())
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
pub async fn fingerprint_tcp(mut stream: TcpStream, mut port: Port) -> Port {
    let mut responses: Vec<String> = Vec::new();

    // Stage 1: banner grab. Many services announce themselves on connect.
    if let Some(banner) = read_response(&mut stream, BANNER_READ_TIMEOUT).await {
        responses.push(banner);
    }

    // Stage 2: active probes registered for this port.
    for payload in SignatureDb::global().tcp_probe_payloads(port.number()) {
        if stream.write_all(payload.as_bytes()).await.is_err() {
            break;
        }
        if let Some(reply) = read_response(&mut stream, PROBE_READ_TIMEOUT).await {
            responses.push(reply);
        }
    }

    if responses.is_empty() {
        return port;
    }

    // Stage 3: analysis, off the reactor.
    match analyze(port.number(), responses.clone()).await {
        Some(verdict) if !verdict.is_empty() => {
            if let Some(service) = verdict.to_service() {
                port.set_service(service);
            }
        }
        _ => {
            if let Some(banner) = first_printable(&responses) {
                port.set_service(Service::new(format!("banner: {banner}"), 0));
            }
        }
    }

    port
}

/// Runs the registered analyzers over `responses` on the blocking pool and
/// resolves their evidence into a verdict. Returns `None` if analysis produced
/// nothing (or the blocking task failed to join).
async fn analyze(port: u16, responses: Vec<String>) -> Option<ServiceVerdict> {
    tokio::task::spawn_blocking(move || {
        let ctx = PortContext { port };

        // The analyzer registry. New evidence sources (TLS, HTTP, JARM, ...)
        // are added here.
        let analyzers: [&dyn Analyzer; 1] = [&BannerRegexAnalyzer];

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
async fn read_response(stream: &mut TcpStream, wait: Duration) -> Option<String> {
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
