// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Operating system fingerprinting
//!
//! What machine is behind an address, read from the same replies the service
//! modules use.
//!
//! ## Usable on its own
//!
//! Nothing here opens a socket, spawns a task or needs a runtime. A
//! [`StackObservation`] is built from bytes, so a caller with packets from a
//! capture, their own raw socket or a fixture can use it without
//! [`scanner`](crate::scanner):
//!
//! ```
//! use zond_engine::fingerprint::os::StackObservation;
//!
//! # fn main() {
//! // An IPv4 packet carrying a TCP segment, from wherever it was captured.
//! let packet: &[u8] = &[
//!     0x45, 0x00, 0x00, 0x2c, 0xbe, 0xef, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
//!     192, 0, 2, 1, 192, 0, 2, 100,
//!     0x00, 0x50, 0xc3, 0x50, 0, 0, 0, 1, 0, 0, 0, 2,
//!     0x60, 0x12, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00,
//!     0x02, 0x04, 0x05, 0xb4,
//! ];
//!
//! let observed = StackObservation::from_ip_packet(packet).expect("a TCP reply");
//! assert!(observed.is_syn_ack());
//! assert_eq!(observed.mss, Some(1460));
//! assert_eq!(observed.layout_string(), "M");
//! # }
//! ```
//!
//! The module depends only on [`model`](crate::model) and
//! [`protocols`](crate::protocols). The crate still compiles its capture and
//! runtime dependencies whatever a consumer imports.
//!
//! ## Shape
//!
//! ```text
//!  one reply  ─▶ StackObservation ──────────────▶ classify ───┐
//!                                                             │
//!  several   ─┬▶ StackObservation ─┐                          │
//!  replies    └▶ SeriesSample[]  ──┴▶ SeriesClasses ─▶ classify_series ─┐
//!                                                             │        │
//!  banner / hostname / hardware address ─────────────────────┐│        │
//!                                                            ▼▼        ▼
//!                                        [OsEvidence] ─▶ resolve ─▶ OsFingerprint
//! ```
//!
//! [`identify()`] is the entry point: it takes what a caller read off the wire,
//! adds what the host says about itself, resolves the combination and merges
//! the result. Every scanner in this crate goes through it.
//!
//! ## Two axes: what it runs, and what it is
//!
//! A source may answer either question without the other.
//! [`OsEvidence::family`](crate::model::host::OsEvidence::family) is what the
//! machine *runs*; [`OsEvidence::device`](crate::model::host::OsEvidence::device)
//! is what it *is* (printer, switch, camera). A TTL of 255 informs the first
//! only; an SNMP agent reading `Brother NC-8700w` informs the second only.
//!
//! [`resolve`] settles the family by vote and everything else by agreement, so a
//! source with nothing to say about the family casts no vote. A model number
//! counted as a family would split the vote.
//!
//! ## One reply, or several
//!
//! Both entry points score the same way. [`classify`] reads a single reply the
//! scan already drew, at no extra cost. [`classify_series`] reads several
//! replies from one host plus their series classes, which costs probes and is
//! what [`OsDetection::Active`](crate::config::OsDetection) enables.
//!
//! A series adds **specificity, not confidence**. It is still one stack, so
//! still one piece of evidence bounded by [`MAX_STACK_ACCURACY`]. It adds the
//! three features a single reply cannot carry (the IP identifier policy, the
//! sequence generator and the clock), which rules naming a release need.
//!
//! ## What one observation can settle
//!
//! A [`StackObservation`] describes **one reply**. The IP identifier policy and
//! the clock frequency need several replies and are not on it.
//!
//! Observations are **not comparable across probes**: the option layout and the
//! advertised window depend on what the probe offered (see
//! [`StackObservation`]). Compare two only when the same probe drew both.

mod db;
mod evidence;
mod hardware;
mod hostname;
mod identify;
mod observation;
mod rules;
mod series;
mod signature;
mod text;
mod verdict;

#[cfg(test)]
mod corpus;

pub use observation::{
    EchoObservation, Quirks, StackObservation, StackReply, TcpOptionKind, Timestamps,
};
// The schema an `assets/fingerprinting/os` rule is authored against, exported for
// callers writing their own rules.
pub use db::{InvalidRule, RuleDb};
pub use evidence::{MAX_FUSED_ACCURACY, resolve};
pub use hardware::evidence_from as hardware_evidence;
pub use hostname::evidence_from as hostname_evidence;
pub use identify::identify;
pub use rules::{accepts, matches, matches_with_series};
pub use series::{
    ClockClass, IdClass, IsnClass, Reading as SeriesReading, SeriesClasses, SeriesSample,
    read_clock, read_identifiers, read_sequences,
};
pub use signature::{
    Example, MAX_RULE_WEIGHT, MatchRule, OsDefinition, OsIdentity, Predicate, PredicateDefect,
    Provenance, ReplyKind, RuleError,
};
pub use text::{
    AGENT_CEILING, BANNER_CEILING, OsMetadata, canonicalise, ceiling,
    evidence_from as banner_evidence, hardware_from,
};
// A rule's `service.component.*` fields use the same `{capture:N}` templates as
// its `os.*` fields, so they share one resolver.
pub(crate) use text::fill;
pub use verdict::{
    MAX_STACK_ACCURACY, MIN_REPORTABLE_ACCURACY, OsVerdict, classify, classify_echo_reply,
    classify_reply, classify_series,
};
