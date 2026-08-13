// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Getting bytes onto the wire, and off it
//!
//! Everything here does I/O. [`crate::protocols`] is the other half of the same
//! job and does none: it builds and parses packets as plain byte slices, and
//! this module opens the sockets and captures that carry them. The split is
//! worth the two modules because it is the difference between code a unit test
//! can exercise on any machine and code that needs a NIC and root — and a probe
//! that cannot be built without a socket open is a probe nobody can test.
//!
//! [`probe`] is the handle a scanner actually holds. It pairs a send path with a
//! receive path, because on this crate's platforms those cannot be the same
//! socket: a raw Layer-4 socket sends fine everywhere but receives only on
//! Linux, so replies always come back through a `libpcap` [`capture`] at the
//! link layer.
//!
//! The two send backends are named for the layer they write at. [`raw`] hands a
//! segment to a raw Layer-4 socket and lets the kernel route it, resolve the
//! next hop and fragment it. [`link`] builds the whole Ethernet frame itself,
//! which is what Windows requires — it blocks raw TCP sends outright — and what
//! deliberately bypassing the host's firewall and connection tracking needs.
//! A scanner picks between them through [`probe::ProbeSender`] and is otherwise
//! unaware of which one it has.

pub mod capture;
pub mod channel;
pub mod frame;
pub mod link;
pub mod mac;
pub mod neighbor;
pub mod probe;
pub mod raw;
