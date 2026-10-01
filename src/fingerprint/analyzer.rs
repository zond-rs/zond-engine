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
//! independently of every other analyzer. A new source of detection is a new
//! `Analyzer`, registered with the orchestrator.
//!
//! ## Two phases
//!
//! The orchestrator in [`super`] runs network I/O on the reactor and CPU work
//! on the blocking pool, in two phases:
//!
//! 1. [`collect`](Analyzer::collect), async, on the reactor. An analyzer that
//!    needs its own probe exchange beyond the shared first contact runs it here
//!    and returns raw [`Collected`] frames. The default does no I/O, which suits
//!    *passive* analyzers that read only the shared [`ResponseSet`].
//! 2. [`analyze`](Analyzer::analyze), sync, off the reactor. Turns the shared
//!    responses and the analyzer's own frames into evidence. No network I/O.
//!
//! `BannerRegexAnalyzer` and `TlsCertAnalyzer` are passive (phase 1 is the
//! default no-op); an active analyzer such as JARM or a Modbus handler overrides
//! `collect` to speak its protocol, then parses the bytes in `analyze`.

use async_trait::async_trait;

use super::db::SignatureDb;
use super::model::{Evidence, SourceId, Tunnel};
use super::response::{Collected, ResponseSet};
use crate::config::ServiceDetection;
use crate::model::port::Protocol;

/// What an [`Analyzer`] is told about the port it is examining.
///
/// Non-exhaustive so it can grow without changing the trait. Construct it
/// through [`new`](Self::new).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PortContext {
    /// The port being examined. It selects the signatures registered for that
    /// port, and port-bound analyzers (SSH on 22) gate on it in
    /// [`interested`](Analyzer::interested).
    pub port: u16,
    /// The transport the responses were read over.
    ///
    /// An **active** analyzer must gate on it: on the port alone it would dial
    /// TCP 22 because UDP 22 was scanned.
    pub protocol: Protocol,
    /// The address of the peer, when known. An *active* analyzer whose
    /// [`collect`](Analyzer::collect) opens its own connection dials this. `None`
    /// where there is no live socket (unit tests, passive-only paths).
    pub addr: Option<std::net::SocketAddr>,
    /// The tunnel the responses were read through, if any, so evidence drawn
    /// from them can be marked as tunnelled.
    pub tunnel: Option<Tunnel>,
    /// Whether first contact drew an HTTP response.
    ///
    /// The gate for an *active* analyzer that only makes sense against a web
    /// server. [`interested`](Analyzer::interested) is asked before either phase
    /// and sees no responses, so it reads this. Gating on the port number would
    /// miss web servers on unusual ports.
    ///
    /// `false` wherever nothing was read, including passive-only paths and
    /// hand-built contexts.
    pub speaks_http: bool,
    /// How far the caller asked this scan to go.
    ///
    /// Expensive active analyzers gate on it: a JARM fingerprint is ten
    /// connections where a favicon is one.
    ///
    /// [`ServiceDetection::default()`] wherever a context is built by hand.
    pub detection: ServiceDetection,
    /// The name the peer was reached by, where the target was a host name.
    ///
    /// An active analyzer speaking HTTP or TLS sends it, since a server with
    /// several sites at one address routes by name and otherwise answers with its
    /// default site. `None` where an address was given, and in hand-built
    /// contexts.
    pub host_name: Option<String>,
}

impl PortContext {
    /// A context for `port` over `protocol`, with no live socket and no tunnel.
    ///
    /// Both are required because analyzers gate on both.
    #[must_use]
    pub fn new(port: u16, protocol: Protocol) -> Self {
        Self {
            port,
            protocol,
            addr: None,
            tunnel: None,
            speaks_http: false,
            detection: ServiceDetection::default(),
            host_name: None,
        }
    }

    /// Names the peer, so an active analyzer has somewhere to dial.
    #[must_use]
    pub fn with_addr(mut self, addr: Option<std::net::SocketAddr>) -> Self {
        self.addr = addr;
        self
    }

    /// Records that first contact drew an HTTP response.
    #[must_use]
    pub fn with_speaks_http(mut self, speaks_http: bool) -> Self {
        self.speaks_http = speaks_http;
        self
    }

    /// Records the tunnel the responses were read through, if any.
    #[must_use]
    pub fn with_tunnel(mut self, tunnel: Option<Tunnel>) -> Self {
        self.tunnel = tunnel;
        self
    }

    /// Records how far the caller asked the scan to go.
    #[must_use]
    pub fn with_detection(mut self, detection: ServiceDetection) -> Self {
        self.detection = detection;
        self
    }

    /// Names the host the peer was reached as, for an analyzer that asks it
    /// for a site.
    #[must_use]
    pub fn with_host_name(mut self, host_name: Option<String>) -> Self {
        self.host_name = host_name;
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

    /// Cheap gate deciding whether this analyzer runs for `ctx` at all. Applies
    /// to both phases.
    fn interested(&self, ctx: &PortContext) -> bool;

    /// I/O phase, on the reactor. Runs this analyzer's own probe exchange and
    /// returns the raw frames it read.
    ///
    /// The default does no I/O. *Passive* analyzers (banner regex, TLS
    /// certificate) read only the shared [`ResponseSet`]; an *active* analyzer
    /// (JARM, SSH, a binary/ICS handler) overrides this to speak its protocol.
    ///
    /// `responses` is what first contact already read. The favicon analyzer, for
    /// one, finds the icon's location in the page already fetched.
    async fn collect(&self, _ctx: &PortContext, _responses: &ResponseSet) -> Collected {
        Collected::default()
    }

    /// CPU phase, off the reactor. Turns the shared first-contact `responses` and
    /// this analyzer's own `collected` frames into evidence. Must not perform
    /// network I/O.
    fn analyze(
        &self,
        ctx: &PortContext,
        responses: &ResponseSet,
        collected: &Collected,
    ) -> Vec<Evidence>;
}

/// Identifies services by matching regex signatures against banner and
/// active-probe responses. One analyzer among several.
///
/// Matching is tiered: each response is checked first against the signatures
/// linked to its port, and only if none match against the global set, narrowed
/// by the prefilter. The prefilter is built lazily.
///
/// Within a tier the analyzer picks the **most specific** match (see
/// `best_match`), so a generic `HTTP/1.1` signature does not shadow one that
/// names a product and version.
pub struct BannerRegexAnalyzer;

#[async_trait]
impl Analyzer for BannerRegexAnalyzer {
    fn id(&self) -> SourceId {
        SourceId::BannerRegex
    }

    fn interested(&self, _ctx: &PortContext) -> bool {
        true
    }

    // Passive: reads the shared banners only.
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
/// The signature set cannot know how the bytes arrived; only the transport can.
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

    /// An active analyzer whose frames must reach `analyze` intact, as raw bytes.
    struct EchoAnalyzer;

    #[async_trait]
    impl Analyzer for EchoAnalyzer {
        fn id(&self) -> SourceId {
            SourceId::BannerRegex
        }

        fn interested(&self, _ctx: &PortContext) -> bool {
            true
        }

        async fn collect(&self, ctx: &PortContext, _responses: &ResponseSet) -> Collected {
            // Includes a non-UTF-8 byte to show the channel is binary.
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
            speaks_http: false,
            detection: crate::config::ServiceDetection::default(),
            host_name: None,
        };
        let collected = EchoAnalyzer.collect(&ctx, &ResponseSet::default()).await;
        assert_eq!(collected.frames, vec![vec![0xff, 7]]);

        let evidence = EchoAnalyzer.analyze(&ctx, &ResponseSet::default(), &collected);
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].product.as_deref(), Some("[255, 7]"));
    }

    #[tokio::test]
    async fn default_collect_is_a_silent_no_op() {
        let ctx = PortContext {
            port: 80,
            protocol: crate::model::port::Protocol::Tcp,
            addr: None,
            tunnel: None,
            speaks_http: false,
            detection: crate::config::ServiceDetection::default(),
            host_name: None,
        };
        assert!(
            BannerRegexAnalyzer
                .collect(&ctx, &ResponseSet::default())
                .await
                .frames
                .is_empty()
        );
    }
}
