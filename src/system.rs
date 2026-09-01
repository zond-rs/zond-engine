// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Host System
//!
//! Everything the engine asks the machine it is running on, and nothing else.
//!
//! [`interface`] resolves, validates and routes the network hardware attached to
//! the host: which links are physical, which are wireless, what addresses they
//! carry, and which source address reaches a given target. [`neighbor_cache`] reads
//! the host's own IPv6 neighbour table, which is the only source of an IPv6
//! address nobody named. [`privilege`] reports whether the process may open raw
//! sockets.
//!
//! This is the only module that asks the host about itself, and it asks only
//! what a scan needs to send a packet. It does not profile the
//! machine, what it is listening on, what firewall it runs, because none of
//! that changes what goes on the wire, and a library that gathers it is
//! collecting data on its embedder's host for nobody's benefit.

pub mod interface;
pub mod neighbor_cache;
pub mod privilege;
