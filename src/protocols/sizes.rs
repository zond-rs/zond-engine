// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How long each header is
//!
//! The fixed sizes the builders in this module allocate and the parsers step
//! over, in one place so a buffer and the parse that reads it cannot disagree.
//!
//! These are the *fixed* portions only. An IPv4 header may carry options and an
//! IPv6 header may be followed by extension headers, so
//! [`IP_V4_HDR_LEN`] and [`IP_V6_HDR_LEN`] are where the next layer starts in
//! the packets this engine builds, not a claim about every packet it might
//! parse. Anything reading a captured frame reads the length out of the header
//! rather than assuming one of these.
//!
//! Public because crafting a packet is a supported use of this crate, and a
//! caller doing that needs the same numbers rather than a second copy of them.

/// A DNS header: transaction id, flags, and four section counts.
pub const DNS_HDR_LEN: usize = 12;

/// An ICMPv6 echo request: type, code, checksum, identifier, sequence.
pub const ICMP_V6_ECHO_REQ_LEN: usize = 8;

/// An IPv4 header with no options, which is what this engine emits.
pub const IP_V4_HDR_LEN: usize = 20;

/// An IPv6 header, which is fixed — anything variable is an extension header
/// after it.
pub const IP_V6_HDR_LEN: usize = 40;

/// An ARP packet over Ethernet and IPv4: the whole thing, not a header, since
/// ARP carries no payload.
pub const ARP_LEN: usize = 28;

/// An Ethernet II header: destination, source, ethertype. No VLAN tag, which
/// would add four bytes.
pub const ETH_HDR_LEN: usize = 14;

/// A UDP header: source port, destination port, length, checksum.
pub const UDP_HDR_LEN: usize = 8;

/// The shortest Ethernet frame that may legally go out, excluding the frame
/// check sequence the hardware appends.
///
/// A frame shorter than this has to be padded rather than sent as-is: a
/// receiver treats an undersized frame as a collision fragment and discards it,
/// so an unpadded ARP request is not a slow probe but an invisible one.
pub const MIN_ETH_FRAME_NO_FCS: usize = 60;
