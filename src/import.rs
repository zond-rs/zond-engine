// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Import
//!
//! How data gets into the engine: the targets a scan is asked to cover, and the
//! settings a caller wants applied before it starts.
//!
//! ## The mirror of export
//!
//! [`crate::export`] answered most of these questions already, and where the
//! shapes correspond they correspond exactly - one trait per format, formats
//! resolved from a path, hand-written types at the boundary rather than derived
//! onto the engine's working types, and streaming rather than a document held
//! whole in memory. A consumer who has learned one of these modules has learned
//! the other, and they are between them the whole of this crate's contact with
//! the outside world's file formats.
//!
//! ## A source is not a format
//!
//! Reading from a pipe is not a format; it is a place bytes come from. So this
//! module never touches standard input, never opens a file and never names a
//! path it opens. Everything here reads what the caller hands it.
//!
//! A CLI hands it a file or a locked stdin, a web front end hands it a cursor
//! over an uploaded body, a TUI hands it what the user pasted, an embedder
//! hands it a reader over a blob. All four get identical parsing and identical
//! errors, because there is one implementation and it cannot tell them apart.
//!
//! ## Input nobody vouches for
//!
//! Every other parser in this engine reads either its own assets or packets it
//! solicited. This one reads a file somebody else wrote: a target list from a
//! client, a report off a shared drive, a settings file synced from a team
//! repository. Two consequences run through the whole module.
//!
//! **Bounds are part of the API.** A limit that is exceeded is an error naming
//! what exceeded it, never a truncation - a target set quietly missing its tail
//! is a scan that does not cover what it was asked to, and nothing in the report
//! says so.
//!
//! **Nothing an imported document says may name something that gets opened or
//! run.** No include directive, no path that gets resolved, no command. A
//! document changes numbers and chooses between named alternatives, and that is
//! the entire vocabulary.

pub mod target;

pub use target::{TargetContext, TargetExpr, TargetMapBuilder, TargetParseError};
