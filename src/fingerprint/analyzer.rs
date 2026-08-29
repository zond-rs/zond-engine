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
use crate::model::port::Protocol;

/// What an [`Analyzer`] is told about the port it is examining.
///
/// Deliberately small; it grows as analyzers need more context (prior evidence,
/// transport hints) without changing the trait.
pub struct PortContext {
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

        let attested_by = super::extract::attested_by(ctx.port, ctx.protocol);

        let mut evidence = Vec::new();
        for response in &responses.banners {
            if let Some((found, port_confirmed)) =
                banner_evidence(db, port_signatures, response, attested_by)
            {
                evidence.push(stamp(found, ctx, port_confirmed));
            }
        }
        evidence
    }
}

/// Evidence from the **most specific** signature in `indices` that identifies any
/// of `texts`, by [`MatchQuality`](super::matcher::MatchQuality).
///
/// Unlike a first-match scan, this evaluates every candidate so a generic
/// signature listed earlier cannot shadow a more specific one (e.g. a bare
/// `HTTP/1.1` match hiding a `Server:`-header match that names a product and
/// version). Ties keep the earliest text and the lowest-indexed signature, so
/// the result stays deterministic. Candidate sets are bounded — the linked port
/// set, or the prefilter-narrowed global set — so evaluating all of them stays
/// cheap.
///
/// **Several texts, for one banner, for the same reason.** A structured banner
/// carries a field the corpus is actually written against, and that field is
/// where the specific rules live — so both the whole banner and the field are
/// offered, and the better match wins. Taking the *first* match instead would
/// reinstate exactly the shadowing this function exists to prevent: the whole
/// line matches a loose rule naming a family, and the field matches the rule
/// naming the release.
fn best_match(
    db: &SignatureDb,
    indices: &[usize],
    texts: &[&str],
    attested_by: crate::model::host::OsSource,
) -> Option<Evidence> {
    let matched: Vec<super::matcher::Match> = texts
        .iter()
        .flat_map(|text| {
            indices
                .iter()
                .filter_map(move |&idx| db.signature(idx).identify(text, attested_by))
        })
        .collect();

    // Replace only on a strictly better match, so the earliest text and the
    // lowest index win ties.
    let service = matched
        .iter()
        .reduce(|best, m| if m.quality > best.quality { m } else { best })?;

    // **Chosen separately, and that is the point.** `quality` ranks how well a
    // signature identified the *service*, which is a different question from how
    // much it managed to say about the machine — and the two disagree. A rule
    // pinning `OpenSSH_9.2p1` exactly outranks one that also happens to name
    // Debian 12, so ranking the operating system by service quality threw the
    // release away and reported a bare family.
    //
    // The `Match` type already separates them for exactly this reason: a banner
    // identifies a service, and what it implies about the host is a second
    // inference with its own rules. So the service reading comes from the best
    // service match and the operating-system reading from the most complete one,
    // and neither decides the other.
    let os = matched
        .iter()
        .filter_map(|m| m.os.as_ref())
        .reduce(|best, os| {
            if os_detail(os) > os_detail(best) {
                os
            } else {
                best
            }
        })
        .cloned();

    Some(Evidence {
        os,
        ..service.evidence.clone()
    })
}

/// How much of the identity path an operating-system reading fills in.
///
/// Ranks readings against each other and nothing else. A reading that names a
/// release says strictly more than one that stops at the family, and where two
/// say the same amount the first stands — so the answer does not depend on which
/// signature happened to be indexed earlier.
///
/// **Every part counts, including the ones added later.** A field left out here
/// is a field that cannot win a rule its ranking: when the kernel was first
/// given a home of its own, the rule that read one lost to an imported rule that
/// had crammed the same string into `version`, purely because this function had
/// not been told the new field existed.
fn os_detail(os: &crate::model::host::OsEvidence) -> u8 {
    u8::from(os.version.is_some())
        + u8::from(os.kernel.is_some())
        + u8::from(os.product.is_some())
        + u8::from(os.vendor.is_some())
        + u8::from(os.cpe.is_some())
}

/// Everything one banner yields: the evidence, and whether the signature that
/// named the service was registered for this port.
///
/// The whole per-banner decision in one place — text extraction, both tiers, and
/// the separate choice of service and operating-system readings. `analyze` is a
/// loop around it and the tests call it directly, which is deliberate: a test
/// that reproduced this logic instead of calling it is what let the release-
/// naming SSH rules go unreachable while a test asserting "real banners name an
/// operating system" went on passing.
fn banner_evidence(
    db: &SignatureDb,
    port_signatures: &[usize],
    banner: &str,
    attested_by: crate::model::host::OsSource,
) -> Option<(Evidence, bool)> {
    let texts = super::extract::texts(banner);

    // Matched against the signatures registered for this port: port-confirmed.
    let mut found = best_match(db, port_signatures, &texts, attested_by);
    let mut port_confirmed = found.is_some();

    // The global set — narrowed by the prefilter to a small candidate list,
    // compiled on demand — is consulted when the port set identified nothing,
    // and **also when it named a service but said nothing about the machine**.
    //
    // That second case is not a special case: a banner identifies a service, and
    // what it implies about the host is a separate inference, so the signature
    // that answers one is very often not the signature that answers the other.
    // Stopping at the port tier discarded every operating-system reading that
    // lives only in the global set — measured, on a real host, whose release was
    // sitting there unread.
    //
    // It costs an Aho-Corasick pass over the banner and a bounded candidate
    // evaluation, on banners that previously skipped both. Regex compilation is
    // cached, so a scan pays it once per signature rather than once per host.
    if found.as_ref().is_none_or(|found| found.os.is_none()) {
        // Narrowed against every text, unioned: a literal that only appears in
        // the extracted field would otherwise select no candidates and the field
        // would go unmatched here even though it matches on a known port.
        let mut candidates: Vec<usize> = texts
            .iter()
            .flat_map(|text| db.prefilter().candidates(text))
            .collect();
        candidates.sort_unstable();
        candidates.dedup();

        db.warm(&candidates);
        if let Some(global) = best_match(db, &candidates, &texts, attested_by) {
            match found.as_mut() {
                // The port-confirmed service stands; only the reading about the
                // machine is taken from the wider set.
                Some(found) => found.os = global.os,
                None => {
                    found = Some(global);
                    port_confirmed = false;
                }
            }
        }
    }

    found.map(|found| (found, port_confirmed))
}

/// What a banner says about the operating system underneath it, matched exactly
/// as [`BannerRegexAnalyzer`] matches it.
#[cfg(test)]
pub(crate) fn os_from_banner(
    db: &SignatureDb,
    port: u16,
    protocol: Protocol,
    banner: &str,
) -> Option<crate::model::host::OsEvidence> {
    let port_signatures = db.signatures_for_port(port);
    db.warm(port_signatures);
    let attested_by = super::extract::attested_by(port, protocol);
    banner_evidence(db, port_signatures, banner, attested_by).and_then(|(found, _)| found.os)
}

/// Marks `evidence` with the tunnel its response was read through (so a banner
/// matched inside TLS is labelled as tunnelled) and whether the match was
/// port-confirmed (from the port-linked signature set) or global-only.
fn stamp(mut evidence: Evidence, ctx: &PortContext, port_confirmed: bool) -> Evidence {
    evidence.tunnel = ctx.tunnel;
    evidence.port_confirmed = port_confirmed;
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
