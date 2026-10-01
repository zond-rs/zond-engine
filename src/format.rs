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
//! in [`crate::export`] and the readers in [`crate::import`]: schema versions,
//! the engine name, the CSV header row.
//!
//! A value belongs here when changing it would break the other direction.

/// The version a document declares in its `schema_version` field, and the
/// highest version a reader in this build understands.
///
/// Bumped only when a previous reader would misinterpret a document; adding a
/// field does not bump it. The engine's own version is in `engine.version`.
pub const SCHEMA_VERSION: u32 = 1;

/// The version a comparison document declares, and the highest a reader in this
/// build understands.
///
/// Counted separately from [`SCHEMA_VERSION`], so a report change does not
/// invalidate stored comparisons.
pub const DIFF_SCHEMA_VERSION: u32 = 1;

/// The name reported in a document's `engine.name` field, and the name a reader
/// checks to decide whether a document is one this engine wrote.
pub const ENGINE_NAME: &str = "zond-engine";

/// The `scanner` attribute of nmap XML this engine writes, which the importer
/// checks to apply this engine's conventions. It names the program, so `zond`.
#[cfg(any(feature = "export-nmap", feature = "import-nmap"))]
pub(crate) const NMAP_SCANNER: &str = "zond";

/// The mark a Windows editor leaves at the start of a file, as UTF-8.
///
/// Every reader in [`crate::import`] strips it from the start of its input, and the
/// CSV writer emits it on request. Always compiled, since the list reader is.
pub const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// [`UTF8_BOM`] as a character, for readers holding text.
pub const UTF8_BOM_CHAR: char = '\u{feff}';

pub mod time;

/// The header row of this engine's CSV, which the writer emits and the reader
/// recognises.
///
/// A reader holding a stale header does not fail; it reads the table as a plain
/// target list.
#[cfg(any(feature = "export-csv", feature = "import-csv"))]
pub mod csv;
