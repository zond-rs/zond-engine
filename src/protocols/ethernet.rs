// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Context;
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::{EtherType, EthernetPacket, MutableEthernetPacket};

use crate::protocols::utils::ETH_HDR_LEN;

pub fn make_header(src_mac: MacAddr, dst_mac: MacAddr, et: EtherType) -> anyhow::Result<Vec<u8>> {
    let mut buffer: [u8; ETH_HDR_LEN] = [0; ETH_HDR_LEN];
    {
        let mut eth: MutableEthernetPacket = MutableEthernetPacket::new(&mut buffer[..])
            .context("failed to create mutable Ethernet packet")?;
        eth.set_source(src_mac);
        eth.set_destination(dst_mac);
        eth.set_ethertype(et);
    }
    Ok(buffer.to_vec())
}

pub fn get_packet_from_u8(frame_bytes: &'_ [u8]) -> anyhow::Result<EthernetPacket<'_>> {
    let eth_packet: EthernetPacket =
        EthernetPacket::new(frame_bytes).context("truncated or invalid Ethernet frame")?;
    Ok(eth_packet)
}
