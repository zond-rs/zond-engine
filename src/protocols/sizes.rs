// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How long each header is
//!
//! The fixed sizes the builders allocate and the parsers step over, kept in one
//! place so a buffer and the parse that reads it cannot disagree.
//!
//! These are fixed portions only. IPv4 options and IPv6 extension headers make
//! [`IP_V4_HDR_LEN`] and [`IP_V6_HDR_LEN`] where the next layer starts in
//! packets this engine builds, not in every packet it might parse; code reading
//! a captured frame takes the length from the header.

/// A DNS header: transaction id, flags, and four section counts.
pub const DNS_HDR_LEN: usize = 12;

/// An ICMP header of either family: type, code, checksum, and four bytes whose
/// meaning depends on the type. An echo carries its identifier and sequence in
/// those four.
pub const ICMP_HDR_LEN: usize = 8;

/// An ICMPv6 echo request with no payload, which is [`ICMP_HDR_LEN`] exactly.
pub const ICMP_V6_ECHO_REQ_LEN: usize = ICMP_HDR_LEN;

/// An IPv4 header with no options, which is what this engine emits.
pub const IP_V4_HDR_LEN: usize = 20;

/// An IPv6 header, which is fixed; anything variable is an extension header after
/// it.
pub const IP_V6_HDR_LEN: usize = 40;

/// An ARP packet over Ethernet and IPv4. The whole packet, since ARP carries no
/// payload.
pub const ARP_LEN: usize = 28;

/// An Ethernet II header: destination, source, ethertype. No VLAN tag, which
/// would add four bytes.
pub const ETH_HDR_LEN: usize = 14;

/// A TCP header with no options, which is every probe this engine sends but
/// the SYN.
pub const TCP_HDR_LEN: usize = 20;

/// A UDP header: source port, destination port, length, checksum.
pub const UDP_HDR_LEN: usize = 8;

/// An SCTP common header: source port, destination port, verification tag, and
/// the CRC32c checksum. The chunks follow it.
pub const SCTP_COMMON_HDR_LEN: usize = 12;

/// An SCTP chunk header: type, flags, and a length that counts these four bytes
/// and the value after them, but not the padding to a four-byte boundary.
pub const SCTP_CHUNK_HDR_LEN: usize = 4;

/// The shortest Ethernet frame that may legally go out, excluding the frame
/// check sequence the hardware appends.
///
/// Shorter frames must be padded: a receiver treats an undersized frame as a
/// collision fragment and discards it, so an unpadded ARP request is never seen.
pub const MIN_ETH_FRAME_NO_FCS: usize = 60;
