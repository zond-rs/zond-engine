// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Analyzers
//!
//! The extension point of the fingerprinting engine.
//!
//! An [`Analyzer`] turns response data into zero or more [`Evidence`] records,
//! independently of every other analyzer. Adding TLS-certificate, HTTP-header,
//! JARM, SNMP, or nerva-derived binary detection means adding an `Analyzer` and
//! registering it — not touching the orchestration or the other analyzers.
//!
//! ## Two phases
//!
//! An analyzer runs in two clearly separated phases so the concurrency rule
//! ("network I/O on the reactor, CPU on the blocking pool") is enforced by the
//! orchestrator in [`super`] rather than trusted to each analyzer:
//!
//! 1. [`collect`](Analyzer::collect) — **async, on the reactor.** An analyzer
//!    that needs its own probe exchange (beyond the shared first-contact the
//!    transport already did) runs it here and returns raw [`Collected`] frames.
//!    The default does no I/O, which is exactly right for *passive* analyzers
//!    that read only the shared [`ResponseSet`].
//! 2. [`analyze`](Analyzer::analyze) — **sync, off the reactor.** Pure CPU: turn
//!    the shared responses and this analyzer's own collected frames into
//!    evidence. No network here, ever.
//!
//! `BannerRegexAnalyzer` and `TlsCertAnalyzer` are passive (phase 1 is the
//! default no-op); an active analyzer such as JARM or a Modbus handler overrides
//! `collect` to speak its protocol, then parses the bytes in `analyze`.

use async_trait::async_trait;

use super::db::SignatureDb;
use super::model::{Evidence, SourceId, Tunnel};
use super::prefilter::Prefilter;
use super::response::{Collected, ResponseSet};

/// What an [`Analyzer`] is told about the port it is examining.
///
/// Deliberately small; it grows as analyzers need more context (prior evidence,
/// transport hints) without changing the trait.
pub struct PortContext {
    pub port: u16,
    /// The address of the peer being fingerprinted, when known. An *active*
    /// analyzer whose [`collect`](Analyzer::collect) opens its own connection
    /// (SSH, JARM, a binary/ICS handler) dials this; it is `None` in contexts
    /// with no live socket (unit tests, a passive-only path), and passive
    /// analyzers ignore it.
    pub addr: Option<std::net::SocketAddr>,
    /// The tunnel the responses were read through, if any. Set when the
    /// transport handed the analyzers data decrypted from a tunnel, so evidence
    /// drawn from it can be marked accordingly.
    pub tunnel: Option<Tunnel>,
}

/// A source of fingerprinting evidence, run in two phases (see the module docs):
/// [`collect`](Analyzer::collect) does any I/O on the reactor,
/// [`analyze`](Analyzer::analyze) does the CPU work off it.
#[async_trait]
pub trait Analyzer: Send + Sync {
    /// Stable identity of this analyzer, recorded on the evidence it produces.
    fn id(&self) -> SourceId;

    /// Cheap gate deciding whether this analyzer should run for `ctx` at all,
    /// so irrelevant analyzers cost nothing (e.g. a TLS analyzer on a plaintext
    /// port). Applies to both phases.
    fn interested(&self, ctx: &PortContext) -> bool;

    /// **I/O phase, on the reactor.** Runs this analyzer's own probe exchange —
    /// beyond the shared first-contact the transport already performed — and
    /// returns the raw frames it read.
    ///
    /// The default does no I/O and returns nothing: *passive* analyzers (banner
    /// regex, TLS certificate) draw entirely on the shared [`ResponseSet`] and
    /// leave this alone. An *active* analyzer (JARM, SSH, a binary/ICS handler)
    /// overrides it to speak its protocol.
    async fn collect(&self, _ctx: &PortContext) -> Collected {
        Collected::default()
    }

    /// **CPU phase, off the reactor.** Turns the shared first-contact
    /// `responses` and this analyzer's own `collected` frames into evidence. An
    /// analyzer reads only the inputs it understands and ignores the rest; this
    /// method must not perform network I/O.
    fn analyze(
        &self,
        ctx: &PortContext,
        responses: &ResponseSet,
        collected: &Collected,
    ) -> Vec<Evidence>;
}

/// Identifies services by matching regex signatures against banner and
/// active-probe responses. The port-out of the previous engine, now one
/// analyzer among the eventual many.
///
/// Matching is tiered: each response is checked first against the signatures
/// linked to its port, and only if none match is it checked against the global
/// set — narrowed by the prefilter — so a service on a non-standard port is
/// still identified without scanning every signature. The prefilter is built
/// lazily; most responses match on their port and never trigger it.
///
/// Within a tier the analyzer picks the **most specific** match, not the first
/// one to fire (see `best_match`): a generic `HTTP/1.1` signature no longer
/// shadows the `Server: nginx/1.25.3` signature that names a product and
/// version.
pub struct BannerRegexAnalyzer;

#[async_trait]
impl Analyzer for BannerRegexAnalyzer {
    fn id(&self) -> SourceId {
        SourceId::BannerRegex
    }

    fn interested(&self, _ctx: &PortContext) -> bool {
        true
    }

    // Passive: reads the shared banners, runs no probes of its own — the default
    // `collect` is exactly right.
    fn analyze(
        &self,
        ctx: &PortContext,
        responses: &ResponseSet,
        _collected: &Collected,
    ) -> Vec<Evidence> {
        let db = SignatureDb::global();

        let port_signatures = db.signatures_for_port(ctx.port);
        db.warm(port_signatures);

        let mut evidence = Vec::new();
        for response in &responses.banners {
            if let Some(found) = best_match(db, port_signatures, response) {
                // Matched a signature registered for this port: port-confirmed.
                evidence.push(stamp(found, ctx, true));
                continue;
            }

            // No port match: fall back to the whole set, narrowed by the
            // prefilter to a small candidate list, compiled on demand. A match
            // here is global-only — found by content, not corroborated by port.
            let candidates = db.prefilter().candidates(response);
            db.warm(&candidates);
            if let Some(found) = best_match(db, &candidates, response) {
                evidence.push(stamp(found, ctx, false));
            }
        }

        evidence
    }
}

/// Evidence from the **most specific** signature in `indices` that identifies
/// `response`, by [`MatchQuality`](super::matcher::MatchQuality).
///
/// Unlike a first-match scan, this evaluates every candidate so a generic
/// signature listed earlier cannot shadow a more specific one (e.g. a bare
/// `HTTP/1.1` match hiding a `Server:`-header match that names a product and
/// version). Ties keep the lowest-indexed signature, so the result stays
/// deterministic. Candidate sets are bounded — the linked port set, or the
/// prefilter-narrowed global set — so evaluating all of them stays cheap.
fn best_match(db: &SignatureDb, indices: &[usize], response: &str) -> Option<Evidence> {
    indices
        .iter()
        .filter_map(|&idx| db.signature(idx).identify(response))
        // Replace only on a strictly better match, so the lowest index wins ties.
        .reduce(|best, m| if m.quality > best.quality { m } else { best })
        // The match's operating-system reading travels on the evidence it
        // becomes. It is retained by `ServiceVerdict` rather than ranked by it —
        // the resolver ranks services, and what a banner implies about the
        // machine is a different question with different rules.
        .map(|m| Evidence {
            os: m.os,
            ..m.evidence
        })
}

/// Marks `evidence` with the tunnel its response was read through (so a banner
/// matched inside TLS is labelled as tunnelled) and whether the match was
/// port-confirmed (from the port-linked signature set) or global-only.
fn stamp(mut evidence: Evidence, ctx: &PortContext, port_confirmed: bool) -> Evidence {
    evidence.tunnel = ctx.tunnel;
    evidence.port_confirmed = port_confirmed;
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::model::Confidence;

    /// An active analyzer: its `collect` produces raw frames that its `analyze`
    /// turns into evidence. Proves the two-phase wiring end to end — the frames
    /// gathered in the I/O phase reach the CPU phase intact, as raw bytes.
    struct EchoAnalyzer;

    #[async_trait]
    impl Analyzer for EchoAnalyzer {
        fn id(&self) -> SourceId {
            SourceId::BannerRegex
        }

        fn interested(&self, _ctx: &PortContext) -> bool {
            true
        }

        async fn collect(&self, ctx: &PortContext) -> Collected {
            // Stand in for a real probe exchange: emit a frame derived from the
            // context, including a non-UTF-8 byte to prove the channel is binary.
            Collected {
                frames: vec![vec![0xff, ctx.port as u8]],
            }
        }

        fn analyze(
            &self,
            _ctx: &PortContext,
            _responses: &ResponseSet,
            collected: &Collected,
        ) -> Vec<Evidence> {
            collected
                .frames
                .iter()
                .map(|frame| {
                    Evidence::new(SourceId::BannerRegex, Confidence::Weak)
                        .with_product(format!("{frame:?}"))
                })
                .collect()
        }
    }

    #[tokio::test]
    async fn collect_output_reaches_analyze_as_raw_bytes() {
        let ctx = PortContext {
            port: 7,
            addr: None,
            tunnel: None,
        };
        // Drive the two phases exactly as the orchestrator does.
        let collected = EchoAnalyzer.collect(&ctx).await;
        assert_eq!(collected.frames, vec![vec![0xff, 7]]);

        let evidence = EchoAnalyzer.analyze(&ctx, &ResponseSet::default(), &collected);
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].product.as_deref(), Some("[255, 7]"));
    }

    #[tokio::test]
    async fn default_collect_is_a_silent_no_op() {
        // A passive analyzer that never overrides `collect` gathers nothing.
        let ctx = PortContext {
            port: 80,
            addr: None,
            tunnel: None,
        };
        assert!(BannerRegexAnalyzer.collect(&ctx).await.frames.is_empty());
    }
}
