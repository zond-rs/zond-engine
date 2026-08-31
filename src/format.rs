// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What the two directions agree on
//!
//! Constants that define this engine's own file formats, shared by the writers
//! in [`crate::export`] and the readers in [`crate::import`].
//!
//! A reader and a writer of the same format have to agree on a handful of
//! values: the schema version a document declares, the name it is written under,
//! the exact header row a table starts with. Those live here, below both
//! directions, so neither owns them and a consumer that only ever imports does
//! not compile an exporter to reach a string constant.
//!
//! The rule for what belongs here is short: a value belongs in this module when
//! changing it would break the other direction. How a document is streamed, how
//! a field is quoted, which DTOs a writer borrows through are one direction's
//! own business and stay where they are used.

/// The version a document declares in its `schema_version` field, and the
/// highest version a reader in this build understands.
///
/// It changes only when a document that a previous reader would misinterpret
/// becomes possible. Adding a field does not bump it, since a consumer that
/// ignores what it does not recognise is unaffected.
///
/// The engine's own version travels alongside it in `engine.version`, so a
/// report can be attributed to a build without the schema having to move every
/// time the engine does.
pub const SCHEMA_VERSION: u32 = 1;

/// The version a comparison document declares, and the highest a reader in this
/// build understands.
///
/// Counted separately from [`SCHEMA_VERSION`], which answers a different
/// question: one says what a scan found, the other says what changed between two
/// of them. Tying the numbers together would mean a report gaining a field
/// invalidates every stored comparison.
pub const DIFF_SCHEMA_VERSION: u32 = 1;

/// The name reported in a document's `engine.name` field, and the name a reader
/// checks to decide whether a document is one this engine wrote.
pub const ENGINE_NAME: &str = "zond-engine";

/// The mark a Windows editor leaves at the start of a file, as UTF-8.
///
/// Every reader in [`crate::import`] strips it from the first thing it reads and
/// nowhere else, and the CSV writer emits it on request.
///
/// Compiled in unconditionally, like [`time`]: the list reader is always present
/// and always strips one.
pub const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// [`UTF8_BOM`] as the character it encodes, for a reader holding text rather
/// than bytes.
pub const UTF8_BOM_CHAR: char = '\u{feff}';

pub mod time;

/// The header row of this engine's CSV, which the writer emits and the reader
/// recognises.
///
/// Compiled in whenever either direction is. A reader matching a stale header
/// does not fail; it declines to recognise a table this engine wrote and falls
/// through to treating it as a plain target list.
#[cfg(any(feature = "export-csv", feature = "import-csv"))]
pub mod csv;
