// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Ethernet framing
//!
//! The outermost header on everything the link-layer paths send, and the first
//! thing read off everything they capture.
//!
//! Fourteen bytes with no options and no VLAN tag, which is why building one
//! cannot fail: the buffer is exactly the header written into it. Reading one
//! can, because the bytes come off the wire.

use pnet::datalink::MacAddr;
use pnet::packet::ethernet::{EtherType, EthernetPacket};

use crate::protocols::craft;
use crate::protocols::error::{PacketError, Result};
use crate::protocols::sizes::ETH_HDR_LEN;

/// Builds the Ethernet header carrying `et` from `src_mac` to `dst_mac`.
pub fn create_header(src_mac: MacAddr, dst_mac: MacAddr, et: EtherType) -> Vec<u8> {
    craft::Ethernet::new(src_mac, dst_mac)
        .with_ethertype(et)
        .header_bytes()
}

/// Reads `frame_bytes` as an Ethernet frame.
///
/// # Errors
///
/// [`PacketError::Truncated`] when there are too few bytes for a header, which
/// is what a cut-short capture looks like from here.
pub fn parse(frame_bytes: &'_ [u8]) -> Result<EthernetPacket<'_>> {
    EthernetPacket::new(frame_bytes)
        .ok_or_else(|| PacketError::truncated("an Ethernet frame", ETH_HDR_LEN, frame_bytes.len()))
}
