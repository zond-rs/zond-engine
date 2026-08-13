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
//! wrote, and maps each column it recognises by name. Two copies of this list
//! would let a rename land in one direction and not the other, which produces no
//! error at all — just a table that stops being recognised as its own.

/// The column names, in order. Host columns first, then the port columns that
/// are empty on a host with no ports.
pub const COLUMNS: [&str; 25] = [
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
    "ttl",
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
];

/// How many of [`COLUMNS`] describe the port rather than the host.
///
/// The split point, not a second list: the host half is everything before it.
pub const PORT_COLUMNS: usize = 11;
