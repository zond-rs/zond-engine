// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Packets, in and out
//!
//! What every layer of a probe looks like on the wire, and how to read one that
//! comes back. One module per protocol, each holding both halves: [`tcp`] knows
//! what a TCP header is and what a TCP reply says, [`arp`] the same for ARP, and
//! so on down.
//!
//! ## What this module knows, and what it does not
//!
//! It knows headers. It does not know what a scan is. Nothing here decides which
//! address to probe, how often, in what order, or what an answer proves about a
//! host; all of that belongs to [`scanner`](crate::scanner), and keeping it out
//! is what lets these functions serve a caller who is not running a scan at
//! all.
//!
//! The one place the line is easy to blur is a reply.
//! [`tcp::classify_probe_response`] says a RST arrived and does not say what
//! that means, since a RST is a closed port to a FIN probe and an unfiltered path
//! to an ACK probe. Only the technique that sent the probe knows which, so that
//! verdict lives on
//! [`TcpScanTechnique`](crate::model::technique::TcpScanTechnique) instead.
//!
//! ## How things are named
//!
//! The module already says which protocol, so a function name does not repeat
//! it. Four shapes cover everything here:
//!
//! | Shape | Means | Example |
//! |---|---|---|
//! | `build_*` | builds bytes to send | [`arp::build_request`] |
//! | `parse` | reads bytes into a view of them | [`tcp::parse`] |
//! | a plain noun | reads one thing out of a frame | [`ip::ipv6_source`] |
//! | `classify_*` | says which of a few answers arrived | [`tcp::classify_probe_response`] |
//!
//! A reader takes the frame or the bytes and nothing else, so its parameter
//! already says where it is reading from and the name does not have to.
//!
//! ## Two of these only read
//!
//! [`lldp`] and [`cdp`] carry no builders. Every other protocol here exists so a
//! scan can ask something, where those two are what the equipment on a link says
//! about itself on its own timer with no question put to it. A switch names
//! itself, names the port this machine is plugged into, and lists what it is
//! doing, roughly every thirty seconds, whether or not anybody is listening.
//!
//! Emitting one would be this engine claiming to be network equipment on a
//! segment it was asked to measure, so the modules read and do not write.
//!
//! ## Building a packet usually cannot fail
//!
//! Most builders here write a fixed-size header into a buffer they allocate
//! themselves, which cannot go wrong, and they say so by returning the packet
//! rather than a `Result`. The few that are fallible fail for one of two
//! reasons: a payload too large for a 16-bit length field, or a checksum asked
//! for across two address families. See [`error`].
//!
//! ## Reading one declines rather than guesses
//!
//! A promiscuous capture sees the whole segment's traffic, so most of what
//! arrives belongs to somebody else. Every reader here stops at the fixed
//! header, and reports a frame it cannot read plainly rather than working harder
//! to interpret it. Missing a frame costs one observation; misreading one
//! credits a host that was never there.
//!
//! ## What a short tail costs, and what it does not
//!
//! Four readers here walk a run of records whose lengths came off the wire:
//! [`lldp`]'s type-length-value units, [`cdp`]'s records, [`dhcp`]'s options and
//! [`sctp`]'s chunks. All four meet the same two situations, and all four answer
//! them the same way.
//!
//! A record whose length runs past the buffer ends the walk, and what was already
//! read is kept. A capture cut at its snapshot length ends mid-record, and so
//! does a frame from equipment that miscounted, and neither is a reason to throw
//! away the fields in front of it. An LLDP unit that names the switch and the
//! port and then stops mid-description is worth the switch and the port.
//!
//! A record whose value cannot be read is skipped and the walk carries on. One
//! vendor's malformed system description must not cost the chassis identifier
//! beside it.
//!
//! Each walk is bounded by a count as well. The lengths that drive it are a
//! stranger's, and a run of them must not decide how long a loop in this process
//! runs. Past the bound the walk stops and keeps what it has, which is the same
//! answer as a short tail.

pub mod arp;
pub mod cdp;
pub mod craft;
pub mod dhcp;
pub mod dns;
pub mod error;
pub mod ethernet;
pub mod icmp;
pub mod ip;
pub mod lldp;
pub mod mdns;
pub mod ndp;
pub mod sctp;
pub mod sizes;
pub mod tcp;
pub mod udp;

// Reading a string a stranger wrote, shared by the three announcement protocols
// that carry one. Private, being a helper rather than a protocol.
mod text;

use crate::protocols::ethernet::Frame;
use pnet_packet::ethernet::EtherTypes;
use std::net::IpAddr;

/// The address `frame` was sent from, whichever of the three shapes it is.
///
/// An ARP frame answers from the sender's protocol address and an IP frame from
/// its header's source. A caller that already knows which it is holding should
/// ask that protocol's module directly; this is for the receive loop that does
/// not yet.
///
/// # Errors
///
/// [`UnsupportedEtherType`](error::PacketError::UnsupportedEtherType) for
/// anything else, which under promiscuous capture is the ordinary case rather
/// than a fault, and [`Truncated`](error::PacketError::Truncated) for a frame
/// too short to read.
pub fn source_address(frame: &Frame<'_>) -> error::Result<IpAddr> {
    match frame.ethertype() {
        EtherTypes::Arp => Ok(IpAddr::V4(arp::sender_address(frame)?)),
        EtherTypes::Ipv4 => Ok(IpAddr::V4(ip::ipv4_source(frame)?)),
        EtherTypes::Ipv6 => Ok(IpAddr::V6(ip::ipv6_source(frame)?)),
        other => Err(error::PacketError::UnsupportedEtherType(other.0)),
    }
}
