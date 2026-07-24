// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::net::IpAddr;

use anyhow::Context;
use pnet::packet::tcp::{MutableTcpPacket, TcpOption, TcpPacket};

const MIN_TCP_HDR_LEN: usize = 24;
const WORD_IN_BYTES: usize = 4;
const SYN_FLAG: u8 = 1 << 1;
const RST_FLAG: u8 = 1 << 2;
const ACK_FLAG: u8 = 1 << 4;

pub fn create_packet(
    src_addr: &IpAddr,
    dst_addr: &IpAddr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
) -> anyhow::Result<Vec<u8>> {
    let mut buffer: Vec<u8> = vec![0u8; MIN_TCP_HDR_LEN];
    {
        let mut tcp: MutableTcpPacket =
            MutableTcpPacket::new(&mut buffer).context("creating tcp packet")?;
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_data_offset((MIN_TCP_HDR_LEN / WORD_IN_BYTES) as u8);
        tcp.set_sequence(seq_num);
        tcp.set_acknowledgement(0);
        tcp.set_flags(SYN_FLAG);
        tcp.set_window(1024);
        tcp.set_checksum(0);

        let mut tcp_options: Vec<TcpOption> = Vec::new();
        let mss: TcpOption = TcpOption::mss(1412);
        tcp_options.push(mss);
        tcp.set_options(&tcp_options);

        let tcp_packet: TcpPacket = tcp.to_immutable();
        let checksum = match (src_addr, dst_addr) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                pnet::packet::tcp::ipv4_checksum(&tcp_packet, src, dst)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                pnet::packet::tcp::ipv6_checksum(&tcp_packet, src, dst)
            }
            _ => anyhow::bail!("IP version mismatch"),
        };

        tcp.set_checksum(checksum);
    }
    Ok(buffer)
}

pub fn from_u8(bytes: &'_ [u8]) -> anyhow::Result<TcpPacket<'_>> {
    TcpPacket::new(bytes).context("truncated or invalid TCP packet")
}

/// What a SYN probe's response reveals about the state of the port it was sent to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResponse {
    /// SYN+ACK: something is listening and accepted the connection attempt.
    Open,
    /// RST: the port actively refused the connection attempt.
    Closed,
}

/// Classifies a received segment as a response to a SYN probe, if it looks like one.
///
/// Returns `None` for anything that isn't a plain SYN+ACK or RST - established
/// connection traffic, unrelated flag combinations, and so on - which a caller
/// should treat as noise rather than a probe result.
pub fn classify_probe_response(packet: &TcpPacket) -> Option<ProbeResponse> {
    let flags = packet.get_flags();

    if flags & RST_FLAG != 0 {
        Some(ProbeResponse::Closed)
    } else if flags & SYN_FLAG != 0 && flags & ACK_FLAG != 0 {
        Some(ProbeResponse::Open)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::tcp::MutableTcpPacket;

    fn packet_with_flags(flags: u8) -> Vec<u8> {
        let mut buffer = vec![0u8; MIN_TCP_HDR_LEN];
        let mut tcp = MutableTcpPacket::new(&mut buffer).unwrap();
        tcp.set_data_offset((MIN_TCP_HDR_LEN / WORD_IN_BYTES) as u8);
        tcp.set_flags(flags);
        buffer
    }

    #[test]
    fn classifies_syn_ack_as_open() {
        let bytes = packet_with_flags(SYN_FLAG | ACK_FLAG);
        let packet = TcpPacket::new(&bytes).unwrap();
        assert_eq!(classify_probe_response(&packet), Some(ProbeResponse::Open));
    }

    #[test]
    fn classifies_rst_as_closed() {
        let bytes = packet_with_flags(RST_FLAG);
        let packet = TcpPacket::new(&bytes).unwrap();
        assert_eq!(
            classify_probe_response(&packet),
            Some(ProbeResponse::Closed)
        );
    }

    #[test]
    fn classifies_rst_ack_as_closed() {
        // A RST replying to our SYN legitimately carries ACK too (RFC 793 §3.4);
        // RST should take priority over the ACK bit alone.
        let bytes = packet_with_flags(RST_FLAG | ACK_FLAG);
        let packet = TcpPacket::new(&bytes).unwrap();
        assert_eq!(
            classify_probe_response(&packet),
            Some(ProbeResponse::Closed)
        );
    }

    #[test]
    fn ignores_unrelated_flag_combinations() {
        let bytes = packet_with_flags(ACK_FLAG);
        let packet = TcpPacket::new(&bytes).unwrap();
        assert_eq!(classify_probe_response(&packet), None);
    }
}
