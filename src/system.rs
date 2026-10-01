// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Host System
//!
//! What the engine asks the machine it runs on.
//!
//! [`interface`] resolves, validates and routes the network hardware attached to
//! the host: which links are physical, which are wireless, what addresses they
//! carry, and which source address reaches a given target. [`neighbor_cache`] reads
//! the host's own IPv6 neighbour table, the only source of an IPv6 address nobody
//! named. [`privilege`] reports whether the process may open raw sockets.
//! `descriptors`, internal to the crate, reads how many sockets the process may
//! hold at once and shares that budget among every scan it runs.
//!
//! It asks only what a scan needs to send a packet. Listening services, firewall
//! rules and the like are left alone: they change nothing on the wire, and
//! gathering them would be collecting data on the embedder's host.

pub(crate) mod descriptors;
pub mod interface;
pub mod neighbor_cache;
pub mod privilege;
