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
//! use zond_engine::fingerprinting::os::StackObservation;
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
//! reply bytes ─▶ StackObservation ─┐
//!                                  ├─▶ [evidence] ─▶ resolve ─▶ OsFingerprint
//!  banner / OUI / active probes ───┘
//! ```
//!
//! [`StackObservation`] is the first of those and the only one built today.
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
mod observation;
mod rules;
mod signature;
mod verdict;

#[cfg(test)]
mod corpus;

pub use observation::{Quirks, StackObservation, TcpOptionKind, Timestamps};
// The schema an `assets/fingerprinting/os` rule is authored against. Exported so
// a consumer writing rules of their own is held to the same shape rather than
// discovering it when one is silently dropped, exactly as the service signature
// schema is.
pub use db::RuleDb;
pub use rules::{accepts, matches};
pub use signature::{
    Example, MAX_RULE_WEIGHT, MatchRule, OsDefinition, OsIdentity, Predicate, Provenance, ReplyKind,
};
pub use verdict::{
    MAX_STACK_ACCURACY, MIN_REPORTABLE_ACCURACY, OsSource, OsVerdict, classify, classify_reply,
};
