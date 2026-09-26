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
//! can exercise on any machine and code that needs a NIC and root. A probe that
//! cannot be built without a socket open is a probe nobody can test.
//!
//! [`probe`] is the handle a scanner actually holds. It pairs a send path with a
//! receive path, because on this crate's platforms those cannot be the same
//! socket: a raw Layer-4 socket sends fine everywhere but receives only on
//! Linux, so replies always come back through a `libpcap` [`capture`] at the
//! link layer.
//!
//! ## One way in
//!
//! Everything this crate hears arrives through [`capture`], in one of two
//! shapes. [`capture::segments`] parses each admitted frame down to the Layer-4
//! segment a port scanner reads; [`capture::frames`] forwards it whole, for a
//! reader whose answer is below that: ARP, neighbour discovery, a VLAN tag, a
//! hardware address. They share the filter, the counters, the threading and the
//! shutdown, and differ only in what they hand over.
//!
//! One path rather than one per reader, because every receive path needs the
//! same three things: a filter, so the kernel discards what nobody reads
//! instead of copying the whole segment into this process; the kernel's own
//! drop count, so a short result can say it heard less than was sent; and a
//! way to be told to stop. [`channel`] sends at the link layer and hears
//! through a capture like everything else, because building and emitting a
//! frame byte for byte is a genuinely different job from hearing one.
//!
//! The two send backends are named for the layer they write at. `raw` hands a
//! segment to a raw Layer-4 socket and lets the kernel route it, resolve the
//! next hop and fragment it. `link` builds the whole Ethernet frame itself,
//! which is what Windows requires, since it blocks raw TCP sends outright, and
//! what bypassing the host's firewall and connection tracking needs.
//! A scanner picks between them through [`probe::ProbeSender`] and is otherwise
//! unaware of which one it has. Both are internal to the crate, along with the
//! neighbour resolution the second needs: a caller asks for one by
//! [`SendMode`](probe::SendMode) when it opens a
//! [`ProbeTransport`](probe::ProbeTransport), and each is built on a packet
//! library whose types would otherwise surface in its signatures.
//!
//! `dial`, internal to the crate, opens the ordinary TCP and UDP sockets the
//! engine speaks to a target through when the kernel builds the packets, which
//! is where each one is given what the host's stack has to be told before it
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
