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
//! Both directions read this list rather than each keeping their own. The writer
//! emits it as the header row and fills a field per entry; the reader matches an
//! incoming header against it to decide whether the table is one this engine
//! wrote, then maps each column it recognises by name.

/// The column names, in order: host columns, then the port columns that are
/// empty on a host with no ports, then the host columns added after them.
///
/// A column is only ever added at the end. A spreadsheet finds a column by its
/// header, but the Unix tools that are the format's other audience find it by
/// position, and a column put anywhere else would move every one after it. So
/// a host's names follow its port's findings rather than its hostname.
///
/// A slice rather than an array, so that a column added is not a change to the
/// constant's type.
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
/// A character one side guards and the other does not know to unguard reads back
/// with a stray apostrophe in it, and nothing errors, so the list is shared for
/// the same reason [`COLUMNS`] is.
///
/// The carriage return is not a formula character. It is guarded by the same
/// apostrophe because a cell beginning with one is a cell a spreadsheet
/// mangles.
#[cfg(any(feature = "export-csv", feature = "import-csv"))]
pub const FORMULA_LEADERS: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// How many of [`COLUMNS`] describe the port rather than the host.
///
/// The port columns run from `port` to `findings`, after the host columns
/// [`COLUMNS`] opens with, and every column after them is the host's again.
pub const PORT_COLUMNS: usize = 12;
