// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What the two directions have to agree on
//!
//! The constants that define this engine's own file formats, separated from the
//! code that writes them ([`crate::export`]) and the code that reads them
//! ([`crate::import`]).
//!
//! ## Why the contract is not kept with the writer
//!
//! A reader and a writer of the same format have to agree on a handful of
//! values: the schema version a document declares, the name it is written under,
//! the exact header row a table starts with. There are only two places that
//! agreement can live. Either the reader reaches into the writer for it, or both
//! reach into something neither of them owns.
//!
//! The first is what this module exists to stop. It makes reading a format
//! depend on being able to write it, which is untrue — recognising a header is
//! not emitting one — and the dependency is not merely cosmetic: it reaches the
//! feature list, where a consumer who only ever imports ends up compiling every
//! exporter to get at a string constant. It also puts the definition somewhere
//! nobody looks. A value the reader consults and the writer emits is the
//! *format's*, and finding it under the writer suggests the writer may change it
//! unilaterally, which is exactly what must not happen.
//!
//! So the contract sits here, below both, and the rule is short: **a value
//! belongs in this module when changing it would break the other direction.**
//! Everything else — how a document is streamed, how a field is quoted, which
//! DTOs a writer borrows through — is one direction's own business and stays
//! where it is used.

/// The version a document declares in its `schema_version` field, and the
/// highest version a reader in this build understands.
///
/// It changes only when a document that a previous reader would misinterpret
/// becomes possible. Adding a field does not bump it, because a consumer that
/// ignores what it does not recognise is unaffected — and one that does not
/// ignore it was going to break on the next scanner either way.
///
/// The engine's own version travels alongside it in `engine.version`, so a
/// report can be attributed to a build without the schema having to move every
/// time the engine does.
pub const SCHEMA_VERSION: u32 = 1;

/// The name reported in a document's `engine.name` field, and the name a reader
/// checks to decide whether a document is one this engine wrote.
pub const ENGINE_NAME: &str = "zond-engine";

/// Rendering and reading the one timestamp shape every document here uses.
///
/// A function rather than a constant, and it belongs by the same rule: changing
/// how a timestamp is written breaks every reader of it. Compiled in
/// unconditionally, since it costs nothing and both directions want it.
pub mod time;

/// The header row of this engine's CSV, which the writer emits and the reader
/// recognises.
///
/// Compiled in whenever either direction is, since it is the one thing they must
/// not disagree about: a reader matching a stale header does not fail, it
/// declines to recognise a table this engine wrote and falls through to treating
/// it as a plain target list.
#[cfg(any(feature = "export-csv", feature = "import-csv"))]
pub mod csv;
