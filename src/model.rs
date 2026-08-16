// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The domain vocabulary
//!
//! What a scan talks about: a [`Host`](host::Host), a [`Port`](port::Port), the
//! addresses to visit ([`IpSet`](ip::set::IpSet), [`TargetMap`](target::TargetMap)),
//! and what a probe observed on the way
//! ([`CaptureCounts`](capture::CaptureCounts)).
//!
//! **This module depends on nothing else in the crate, and that is a property to
//! keep rather than an accident of how it grew.** Every other module names these
//! types — the scanners fill them in, the report records them, the exporters
//! write them out, the parsers construct them — so anything this layer reached
//! back up to would be pulled into the foundation with it, and the layering
//! below it would stop meaning anything.
//!
//! **Nothing here reports to a user, either.** A value in this module is
//! returned, never announced. A leaf that logs on its own behalf writes into
//! output whose shape it cannot see, at a verbosity it was not told, and the
//! caller — who knows what it asked for and what it is going to do with the
//! answer — is the only one placed to decide whether any of it is worth saying.
//! Counting a target set to announce its size is not free either: an [`IpSet`]
//! that has just been built is unmerged, so `len` clones and merges the whole of
//! it to produce a number nobody may read.
//!
//! [`IpSet`]: ip::set::IpSet
//!
//! ## What belongs here
//!
//! **A type belongs here when more than one module has to agree on it; a type
//! that only one module uses belongs in that module.** That rule is easy to
//! state and easy to drift from, because a leaf everything can reach is a
//! convenient place to put anything. It has drifted once already: the retry
//! ledger, the adaptive deadline, the scan timer and the round-trip window all
//! lived here, and every one of them was named by exactly one module. They are
//! [`scanner::pacing`](crate::scanner::pacing) now — a `ProbeLedger` is not
//! something a scan *talks about*, it is how a scan is *run*.
//!
//! The knobs that survived that move are the test for the rule. [`ScanEffort`]
//! and [`RetryConfig`] are set by a caller, scaled by the scanner and recorded
//! in the report, so three modules must agree on them — and they are in
//! [`crate::config`] rather than here, because what a caller *asks for* is its
//! own vocabulary and is answered before a scan starts.
//!
//! [`ScanEffort`]: crate::config::ScanEffort
//! [`RetryConfig`]: crate::config::RetryConfig
//!
//! For the same reason nothing here is serializable. The wire format is a
//! separate contract, written out by hand in
//! [`export::schema`](crate::export::schema), so that moving a field in this
//! module is a private matter rather than a breaking change to somebody's
//! parser.
//!
//! [`parse`] is the other direction: the grammars that turn what a person wrote
//! — `192.168.1.0/24`, `[fe80::1%en0]:22` — into the values above. It takes its
//! hostname and zone resolution as caller-supplied callbacks precisely so that
//! constructing a target does not drag the host's interface table into the leaf.

pub mod capture;
pub mod host;
pub mod ip;
pub mod mac;
pub mod parse;
pub mod port;
pub mod target;
pub mod technique;
