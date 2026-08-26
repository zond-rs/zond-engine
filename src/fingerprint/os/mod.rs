// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Operating system fingerprinting
//!
//! What machine is behind an address, as distinct from what service is behind a
//! port. The sibling modules answer the second question; this one answers the
//! first, from the same replies.
//!
//! ## Usable on its own
//!
//! Nothing here opens a socket, spawns a task, holds a runtime or touches the
//! scanner. A [`StackObservation`] is built by a function from bytes to a value,
//! so a caller who already has packets — a saved capture, their own raw socket,
//! a fixture — can use this without going anywhere near
//! [`scanner`](crate::scanner):
//!
//! ```
//! use zond_engine::fingerprint::os::StackObservation;
//!
//! # fn main() {
//! // An IPv4 packet carrying a TCP segment, from wherever you got it.
//! let packet: &[u8] = &[
//!     0x45, 0x00, 0x00, 0x2c, 0xbe, 0xef, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
//!     192, 168, 0, 1, 192, 168, 0, 100,
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
//! That decoupling is a design constraint rather than an accident, and it is
//! kept honest by the imports: this module reaches for the vocabulary in
//! [`model`](crate::model) and the header parsing in
//! [`protocols`](crate::protocols) and for nothing else. What it does *not* yet
//! buy is a smaller build — the crate still compiles its capture and its runtime
//! whatever a consumer imports, because those are unconditional dependencies.
//! Turning this into a feature that costs nothing to leave out is a change to
//! the dependency set rather than to this module, and the module is written so
//! that change is mechanical when someone wants it.
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
//! [`identify`] is the door: it takes whatever a caller read off the wire, adds
//! the two sources a host carries about itself, resolves the combination and
//! merges the result. Every scanner in this crate goes through it.
//!
//! ## Two axes: what it runs, and what it is
//!
//! A verdict answers two questions, and a source may answer either without the
//! other. [`OsEvidence::family`] is what the machine *runs*, [`OsEvidence::device`]
//! is what it *is* — printer, switch, camera — and neither stands in for the
//! other. A hop counter of 255 reaches the first and never the second; an SNMP
//! agent reading `Brother NC-8700w` reaches the second and genuinely does not
//! know the first.
//!
//! [`resolve`] settles the family by vote and everything else by agreement, so a
//! source with nothing to say about the family says nothing there rather than
//! being made to guess. That distinction is load-bearing: read as a family, a
//! model number runs against the real families on the ballot and both lose.
//!
//! ## One reply, or several
//!
//! The two entry points differ in what evidence they have, not in how they
//! score it. [`classify`] reads a single reply, which is what a scan already
//! drew for another reason and therefore costs nothing. [`classify_series`]
//! reads several replies from one host together with what their series turned
//! out to be, which costs probes and is what
//! [`OsDetection::Active`](crate::config::OsDetection) buys.
//!
//! What the second one buys is **specificity, not confidence**. A series is
//! still one stack, so it is still one piece of evidence and still bounded by
//! [`MAX_STACK_ACCURACY`]; what it adds is the three features a single reply
//! cannot carry — the identifier policy, the sequence generator and the clock —
//! and those are what a rule naming a *release* rather than a family has to
//! predicate on.
//!
//! ## What one observation can and cannot settle
//!
//! It describes **one reply**, and several of the most tempting features need
//! more than one. Whether a stack's IP identifier counts, stays at zero or is
//! random is a policy visible only across several replies; so is a clock
//! frequency, which needs two timestamps and the interval between them. Neither
//! belongs on this type, and putting either here would mean inventing a value
//! from a single sample.
//!
//! It is also **not comparable across probes**. The option layout and the
//! advertised window both depend on what the probe offered, which is measured
//! and explained on [`StackObservation`]. Two may be compared when the
//! same question was asked of both.

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
// The schema an `assets/fingerprinting/os` rule is authored against. Exported so
// a consumer writing rules of their own is held to the same shape rather than
// discovering it when one is silently dropped, exactly as the service signature
// schema is.
pub use db::RuleDb;
pub use evidence::{MAX_FUSED_ACCURACY, OsEvidence, resolve};
pub use hardware::evidence_from as hardware_evidence;
pub use hostname::evidence_from as hostname_evidence;
pub use identify::identify;
pub use rules::{accepts, matches, matches_with_series};
pub use series::{
    ClockClass, IdClass, IsnClass, Reading as SeriesReading, SeriesClasses, SeriesSample,
    read_clock, read_identifiers, read_sequences,
};
pub use signature::{
    Example, MAX_RULE_WEIGHT, MatchRule, OsDefinition, OsIdentity, Predicate, Provenance, ReplyKind,
};
pub use text::{
    AGENT_CEILING, BANNER_CEILING, OsMetadata, ceiling, evidence_from as banner_evidence,
};
pub use verdict::{
    MAX_STACK_ACCURACY, MIN_REPORTABLE_ACCURACY, OsSource, OsVerdict, classify,
    classify_echo_reply, classify_reply, classify_series,
};
