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
//! host — all of that belongs to [`scanner`](crate::scanner), and keeping it out
//! is what lets these functions serve anything, including a caller who is not
//! running a scan at all.
//!
//! The one place the line is easy to blur is a reply.
//! [`tcp::classify_probe_response`] says a RST arrived and deliberately does not
//! say what that means, because a RST is a closed port to a FIN probe and an
//! unfiltered path to an ACK probe. Only the technique that sent the probe
//! knows which, so that verdict lives on
//! [`TcpScanTechnique`](crate::model::technique::TcpScanTechnique) instead.
//!
//! ## How things are named
//!
//! The module already says which protocol, so a function name does not repeat
//! it. Four shapes cover everything here:
//!
//! | Shape | Means | Example |
//! |---|---|---|
//! | `create_*` | builds bytes to send | [`arp::create_request`] |
//! | `parse` | reads bytes into a view of them | [`tcp::parse`] |
//! | a plain noun | reads one thing out of a frame | [`ip::ipv6_source`] |
//! | `classify_*` | says which of a few answers arrived | [`tcp::classify_probe_response`] |
//!
//! A reader takes the frame or the bytes and nothing else, so its parameter
//! already says where it is reading from and the name does not have to.
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

pub mod arp;
pub mod craft;
pub mod dns;
pub mod error;
pub mod ethernet;
pub mod icmp;
pub mod ip;
pub mod mdns;
pub mod ndp;
pub mod sizes;
pub mod tcp;
pub mod udp;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
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
pub fn source_address(frame: &EthernetPacket) -> error::Result<IpAddr> {
    match frame.get_ethertype() {
        EtherTypes::Arp => Ok(IpAddr::V4(arp::sender_address(frame)?)),
        EtherTypes::Ipv4 => Ok(IpAddr::V4(ip::ipv4_source(frame)?)),
        EtherTypes::Ipv6 => Ok(IpAddr::V6(ip::ipv6_source(frame)?)),
        other => Err(error::PacketError::UnsupportedEtherType(other.0)),
    }
}
