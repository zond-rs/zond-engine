// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Writing a comparison out
//!
//! What [`export`](crate::export) is to a [`ScanReport`], this is to a
//! [`ScanDiff`]: the document somebody else reads. A comparison that only ever
//! reaches a terminal serves the person who ran it and nobody downstream, and
//! downstream is where a nightly comparison earns its keep — an alerting rule, a
//! ticket, a review queue, a dashboard.
//!
//! ## Every change is one scalar fact
//!
//! The document's whole shape follows from one decision. A change is
//! `{kind, before, after}` and nothing else: a fixed token saying which field
//! moved, and the two values, either of which may be `null`. A host that gained
//! three addresses produces three changes rather than one carrying a list.
//!
//! That costs some faithfulness to the engine's own [`HostChange`] and
//! [`PortChange`], which group set changes together. It buys a document a rule
//! engine can act on without a parser per variant: one shape, one code path,
//! and a `kind` that maps directly onto "alert me when this happens". The same
//! flattening produces a front end's per-line output, so a comparison printed in
//! a terminal and one posted to a queue name the same events the same way.
//!
//! ## What a consumer must not lose
//!
//! Every host and every endpoint carries `confirmed`. It is derived — from the
//! presence and the other scan's coverage — and it is stated anyway, because it
//! is the field an alerting rule keys on and re-deriving it is exactly the step
//! somebody will skip. A comparison whose `confirmed` is ignored reports hosts
//! as gone every time a scan is narrowed, which is the failure
//! [`diff`](crate::diff) is arranged to prevent and which this document must not
//! reintroduce at the last step.
//!
//! ## The records on either side
//!
//! Each host delta carries the whole [`HostDto`](crate::export::schema::HostDto)
//! from each side that has one, in the report document's own schema. A ticket
//! wants the ports the new host is running, not another lookup; a dashboard
//! wants to render the host beside the change. A consumer that wants only the
//! changes ignores those two fields.
//!
//! ## Versioned apart from the report
//!
//! The document declares [`DIFF_SCHEMA_VERSION`], which is counted separately
//! from the report's. See that constant for why.

pub mod schema;

#[cfg(feature = "export-json")]
pub mod json;

use std::io::Write;

use crate::diff::ScanDiff;
use crate::export::ExportError;

#[cfg(feature = "export-json")]
pub use json::JsonDiffExporter;

/// One output format for a comparison.
///
/// The counterpart of [`Exporter`](crate::export::Exporter), and separate from
/// it because the two take different things: a report is what a scan found, and
/// a comparison is what changed between two of them. A type could implement both
/// and several will.
pub trait DiffExporter {
    /// Writes `diff` to `out`.
    fn export(&self, diff: &ScanDiff, out: &mut dyn Write) -> Result<(), ExportError>;
}
