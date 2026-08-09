// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Host System
//!
//! This module brokers the host-facing capabilities a scan depends on.
//! [`interface`] resolves, validates, and routes the network hardware attached to
//! the host, classifying local connections (wired vs wireless), fetching network
//! IPv4 assignments, and routing an arbitrary set of targets securely out of the
//! host boundaries. [`privilege`] reports whether the process may open raw
//! sockets.
//!
//! Exposes a clean facade for all host system logic to consumers.

pub mod interface;
pub mod privilege;
