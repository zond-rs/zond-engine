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
//! comes back. One module per protocol, each holding both halves: [`tcp`] builds
//! TCP headers and reads TCP replies, [`arp`] the same for ARP, and so on.
//!
//! This module knows headers, not scans. Which address to probe, how often, and
//! what an answer proves about a host belong to [`scanner`](crate::scanner), so
//! these functions also serve callers that are not running a scan.
//!
//! The line blurs at replies. [`tcp::classify_probe_response`] says a RST
//! arrived, not what it means: a RST is a closed port to a FIN probe and a
//! reachable port to an ACK probe. That verdict lives on
//! [`TcpScanTechnique`](crate::model::technique::TcpScanTechnique).
//!
//! ## Naming
//!
//! The module names the protocol, so function names do not repeat it:
//!
//! | Shape | Means | Example |
//! |---|---|---|
//! | `build_*` | builds bytes to send | [`arp::build_request`] |
//! | `parse` | reads bytes into a view of them | [`tcp::parse`] |
//! | a plain noun | reads one thing out of a frame | [`ip::ipv6_source`] |
//! | `classify_*` | says which of a few answers arrived | [`tcp::classify_probe_response`] |
//!
//! ## Read-only protocols
//!
//! [`lldp`] and [`cdp`] have no builders. They carry what equipment on a link
//! announces about itself, unprompted, roughly every thirty seconds: a switch's
//! name, the port this machine is plugged into, and its capabilities. Emitting
//! one would make the engine pose as network equipment on the segment it is
//! measuring.
//!
//! ## Building
//!
//! Most builders write a fixed-size header into a buffer they allocate and
//! return the packet directly. The few that return a `Result` fail on a payload
//! too large for a 16-bit length field or a checksum across two address
//! families. See [`error`].
//!
//! ## Reading
//!
//! A promiscuous capture sees the whole segment, so most frames belong to
//! somebody else. Every reader stops at the fixed header and reports a frame it
//! cannot read plainly as an error. Missing a frame costs one observation;
//! misreading one credits a host that was never there.
//!
//! Four readers walk records whose lengths come off the wire: [`lldp`]'s TLVs,
//! [`cdp`]'s records, [`dhcp`]'s options and [`sctp`]'s chunks. All four behave
//! the same way:
//!
//! - A record whose length runs past the buffer ends the walk, and what was
//!   already read is kept. Captures cut at the snapshot length and miscounting
//!   equipment both end mid-record; an LLDP unit that names the switch and port
//!   and then stops mid-description is still worth the switch and port.
//! - A record whose value cannot be read is skipped and the walk continues, so
//!   one malformed system description does not cost the chassis ID beside it.
//! - Each walk is capped at a record count, so lengths from a stranger cannot
//!   decide how long the loop runs. Past the cap the walk keeps what it has.

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
pub mod netbios;
pub mod sctp;
pub mod sizes;
pub mod tcp;
pub mod tls;
pub mod udp;

// Where an HTTP response ends by its own framing, for the two readers that
// fetch pages.
pub(crate) mod http;

// Conversion between this crate's `MacAddr` and `pnet`'s. Public signatures use
// the model's type only.
pub(crate) mod mac;

// Reading a string a stranger wrote, shared by the three announcement protocols
// that carry one.
mod text;

use crate::protocols::ethernet::Frame;
use pnet_packet::ethernet::{EtherType, EtherTypes};
use std::net::IpAddr;

/// The address `frame` was sent from, whichever of the three shapes it is.
///
/// ARP's sender protocol address, or the IP header's source. For a receive loop
/// that does not yet know the frame's type.
///
/// # Errors
///
/// [`UnsupportedEtherType`](error::PacketError::UnsupportedEtherType) for any
/// other EtherType (the ordinary case under promiscuous capture), and
/// [`Truncated`](error::PacketError::Truncated) for a frame too short to read.
pub fn source_address(frame: &Frame<'_>) -> error::Result<IpAddr> {
    match EtherType(frame.ethertype()) {
        EtherTypes::Arp => Ok(IpAddr::V4(arp::sender_address(frame)?)),
        EtherTypes::Ipv4 => Ok(IpAddr::V4(ip::ipv4_source(frame)?)),
        EtherTypes::Ipv6 => Ok(IpAddr::V6(ip::ipv6_source(frame)?)),
        other => Err(error::PacketError::UnsupportedEtherType(other.0)),
    }
}
