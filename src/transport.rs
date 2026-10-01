// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Getting bytes onto the wire, and off it
//!
//! Everything here does I/O. [`crate::protocols`] builds and parses packets as plain
//! byte slices; this module opens the sockets and captures that carry them. The split
//! keeps packet code testable on any machine, without a NIC or root.
//!
//! [`probe`] is the handle a scanner holds. It pairs a send path with a receive path
//! because a raw Layer-4 socket can send everywhere but receives only on Linux, so
//! replies always come back through a `libpcap` [`capture`] at the link layer.
//!
//! ## One way in
//!
//! Everything this crate hears arrives through [`capture`], in one of two shapes.
//! [`capture::segments`] parses each admitted frame down to the Layer-4 segment a port
//! scanner reads; [`capture::frames`] forwards it whole, for a reader whose answer is
//! below that: ARP, neighbour discovery, a VLAN tag, a hardware address. Both share
//! the filter, the counters, the threading and the shutdown.
//!
//! Every receive path needs a kernel filter, so unread traffic is never copied into
//! this process; the kernel's drop count, so a short result can say it heard less than
//! was sent; and a way to be told to stop. [`channel`] sends at the link layer and
//! hears through a capture like everything else.
//!
//! The two send backends are named for the layer they write at. `raw` hands a segment
//! to a raw Layer-4 socket and lets the kernel route it, resolve the next hop and
//! fragment it. `link` builds the whole Ethernet frame itself, which Windows requires
//! (it blocks raw TCP sends) and which bypasses the host's firewall and connection
//! tracking. A scanner picks between them through [`probe::ProbeSender`]. Both are
//! internal, along with the neighbour resolution `link` needs: a caller asks for one by
//! [`SendMode`](probe::SendMode) when it opens a
//! [`ProbeTransport`](probe::ProbeTransport), which keeps the packet libraries they
//! are built on out of public signatures.
//!
//! `dial`, internal to the crate, opens the ordinary TCP and UDP sockets used when the
//! kernel builds the packets, and applies the socket options each needs before it
//! connects.

pub mod capture;
pub mod channel;
pub(crate) mod dial;

#[cfg(feature = "packet-exchange")]
pub mod exchange;
pub mod frame;
pub(crate) mod kernel_neighbors;
pub(crate) mod link;
pub(crate) mod neighbor;
pub mod probe;
pub(crate) mod raw;
