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
use super::response::{Collected, ResponseSet};
use crate::model::port::Protocol;

/// What an [`Analyzer`] is told about the port it is examining.
///
/// Deliberately small; it grows as analyzers need more context (prior evidence,
/// transport hints) without changing the trait. `#[non_exhaustive]` is what
/// makes that true outside this crate: with every field public and the type
/// open, the growth its own documentation anticipates would break every caller
/// that had built one. Construct it through [`new`](Self::new).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PortContext {
    /// The port being examined. It selects the signatures registered for that
    /// port, and it is what an analyzer bound to particular ports (SSH on 22)
    /// gates on in [`interested`](Analyzer::interested).
    pub port: u16,
    /// The transport the responses were read over.
    ///
    /// Load-bearing for an **active** analyzer: one gated on a port number alone
    /// would dial TCP 22 because UDP 22 was scanned, probing a service nobody
    /// asked about at an address that never offered one. Passive analyzers
    /// mostly ignore it — what they read is already in the responses.
    pub protocol: Protocol,
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

impl PortContext {
    /// A context for `port` over `protocol`, with no live socket and no tunnel.
    ///
    /// The two required facts, because they are the two an analyzer gates on:
    /// a port number alone would have an SSH probe dial TCP 22 because UDP 22
    /// was scanned.
    #[must_use]
    pub fn new(port: u16, protocol: Protocol) -> Self {
        Self {
            port,
            protocol,
            addr: None,
            tunnel: None,
        }
    }

    /// Names the peer, so an active analyzer has somewhere to dial.
    #[must_use]
    pub fn with_addr(mut self, addr: Option<std::net::SocketAddr>) -> Self {
        self.addr = addr;
        self
    }

    /// Records the tunnel the responses were read through, if any.
    #[must_use]
    pub fn with_tunnel(mut self, tunnel: Option<Tunnel>) -> Self {
        self.tunnel = tunnel;
        self
    }
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
        responses
            .banners
            .iter()
            .filter_map(|response| db.identify(ctx.port, ctx.protocol, response))
            .map(|found| stamp(found, ctx))
            .collect()
    }
}

/// Marks `evidence` with the tunnel its response was read through, so a banner
/// matched inside TLS is labelled as tunnelled.
///
/// The tunnel is the one thing the signature set cannot know: it is a fact about
/// how the bytes arrived rather than about what they say, and only the transport
/// that opened it can supply it. Port confirmation comes back on the evidence
/// already, from the tier that matched.
fn stamp(mut evidence: Evidence, ctx: &PortContext) -> Evidence {
    evidence.tunnel = ctx.tunnel;
    evidence
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
    use crate::model::confidence::Confidence;

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
            protocol: crate::model::port::Protocol::Tcp,
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
            protocol: crate::model::port::Protocol::Tcp,
            addr: None,
            tunnel: None,
        };
        assert!(BannerRegexAnalyzer.collect(&ctx).await.frames.is_empty());
    }
}
