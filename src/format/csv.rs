// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The shape of this engine's CSV: which columns there are and what order they
//! come in.
//!
//! The writer emits it as the header row; the reader matches an incoming header
//! against it to recognise this engine's tables, then maps columns by name.

/// The column names, in order: host columns, then the port columns that are
/// empty on a host with no ports, then the host columns added after them.
///
/// Columns are only added at the end, since Unix tools find a column by position.
/// That is why a host's names follow its port's findings.
///
/// A slice, so adding a column does not change the constant's type.
pub const COLUMNS: &[&str] = &[
    "ip",
    "hostname",
    "status",
    "alive",
    "ips",
    "mac",
    "mac_vendor",
    "os",
    "os_accuracy",
    "roles",
    "rtt_median_us",
    "first_seen",
    "last_seen",
    "port",
    "protocol",
    "state",
    "service",
    "service_product",
    "service_version",
    "service_confidence",
    "discovery_reason",
    "tls_version",
    "cert_common_name",
    "cert_not_after",
    "findings",
    "names",
];

/// The characters that make a spreadsheet read a cell as a formula, which the
/// writer hides behind an apostrophe and the reader takes back off.
///
/// Shared so both sides agree; a mismatch reads back with a stray apostrophe.
///
/// The carriage return is not a formula character, but a spreadsheet mangles a
/// cell beginning with one.
#[cfg(any(feature = "export-csv", feature = "import-csv"))]
pub const FORMULA_LEADERS: &[char] = &['=', '+', '-', '@', '\t', '\r'];

/// How many of [`COLUMNS`] describe the port: `port` through `findings`. The
/// columns before and after them are the host's.
pub const PORT_COLUMNS: usize = 12;
