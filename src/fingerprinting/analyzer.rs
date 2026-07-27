// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Analyzers
//!
//! The extension point of the fingerprinting engine.
//!
//! An [`Analyzer`] turns raw response data into zero or more [`Evidence`]
//! records, independently of every other analyzer. Adding TLS-certificate,
//! HTTP-header, JARM, or SNMP detection means adding an `Analyzer` and
//! registering it — not touching the orchestration or the other analyzers.
//!
//! Analyzers are **CPU-bound and synchronous by contract**. The orchestrator in
//! [`super`] is responsible for running them off the async reactor. This keeps
//! the concurrency rule ("network I/O on Tokio, CPU on the blocking pool") in
//! one place instead of scattered through each analyzer.

use super::db::SignatureDb;
use super::model::{Evidence, SourceId};

/// What an [`Analyzer`] is told about the port it is examining.
///
/// Deliberately small for now; it grows as analyzers need more context (TLS
/// tunnel state, prior evidence, transport hints) without changing the trait.
pub struct PortContext {
    pub port: u16,
}

/// A source of fingerprinting evidence.
///
/// See the module docs: implementations are synchronous and CPU-bound; the
/// orchestrator schedules them off the reactor.
pub trait Analyzer: Send + Sync {
    /// Stable identity of this analyzer, recorded on the evidence it produces.
    fn id(&self) -> SourceId;

    /// Cheap gate deciding whether this analyzer should run for `ctx` at all,
    /// so irrelevant analyzers cost nothing (e.g. a TLS analyzer on a plaintext
    /// port).
    fn interested(&self, ctx: &PortContext) -> bool;

    /// Produces evidence from the collected `responses` for the port.
    fn analyze(&self, ctx: &PortContext, responses: &[String]) -> Vec<Evidence>;
}

/// Identifies services by matching regex signatures against banner and
/// active-probe responses. The port-out of the previous engine, now one
/// analyzer among the eventual many.
pub struct BannerRegexAnalyzer;

impl Analyzer for BannerRegexAnalyzer {
    fn id(&self) -> SourceId {
        SourceId::BannerRegex
    }

    fn interested(&self, _ctx: &PortContext) -> bool {
        true
    }

    fn analyze(&self, ctx: &PortContext, responses: &[String]) -> Vec<Evidence> {
        let matchers = SignatureDb::global().matchers_for_port(ctx.port);
        let mut evidence = Vec::new();

        for response in responses {
            for matcher in &matchers {
                if let Some(found) = matcher.identify(response) {
                    evidence.push(found);
                    // One service match per response from this analyzer; other
                    // responses may still add corroborating evidence.
                    break;
                }
            }
        }

        evidence
    }
}
