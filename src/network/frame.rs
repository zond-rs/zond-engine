// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Link-Layer Framing
//!
//! Turns captured link-layer frames into transport-layer segments, and
//! transport-layer segments into fully-formed Ethernet frames, without either
//! side of the scanner having to know what kind of link it's running over.
//!
//! ## Receive
//!
//! A `pcap` capture hands back whatever the interface's *data-link type*
//! (DLT) prescribes: a 14-byte Ethernet header on `en0`/`eth0`, a 4-byte
//! address-family word on a VPN `utun`/`tun` or loopback link, or nothing at
//! all on a raw-IP link. [`strip_to_ip`] normalizes all of these down to the
//! IP packet, and [`parse_ip_segment`] then extracts the source address and
//! the Layer-4 payload the scanners actually care about.
//!
//! Crucially, once the link header is stripped, the IP version is read from
//! the packet itself (the version nibble) rather than trusting the link
//! layer's `AF_*` tag - those constants differ across BSD variants (macOS
//! `AF_INET6` is 30, FreeBSD 28, NetBSD/OpenBSD 24), and reading the IP
//! header directly sidesteps that entirely.
//!
//! ## Send
//!
//! [`build_ethernet_frame`] wraps an already-built Layer-4 segment in IP and
//! Ethernet headers for a Layer-2 send. The raw-IP send path (tunnel and
//! loopback links) doesn't use this - there the kernel writes the IP header -
//! so this is only exercised on true Ethernet links.

use std::net::IpAddr;

use anyhow::Context;
use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::util::MacAddr;

use crate::protocols::ethernet;
use crate::protocols::ip;
use crate::protocols::utils::ETH_HDR_LEN;

/// The subset of `pcap` data-link types this crate knows how to strip down to
/// an IP packet. Anything else is [`LinkType::Unsupported`] and the caller
/// must refuse to capture on that interface rather than misparse its frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// `DLT_EN10MB`: a 14-byte Ethernet II header (plus optional 802.1Q VLAN
    /// tags), selected by EtherType.
    Ethernet,
    /// `DLT_NULL` / `DLT_LOOP`: a 4-byte address-family word precedes the IP
    /// packet. Used by macOS/BSD loopback and `utun`/`tun` tunnel links.
    NullLoop,
    /// `DLT_RAW`: the captured buffer *is* the IP packet, with no link header.
    Raw,
    /// A data-link type this crate can't parse; the numeric DLT is preserved
    /// for diagnostics.
    Unsupported(i32),
}

/// The width of the pseudo-header `DLT_NULL`/`DLT_LOOP` links prepend: a
/// single 32-bit address-family word.
const NULL_LOOP_HDR_LEN: usize = 4;

// libpcap data-link type numbers. Kept local rather than pulled from a
// dependency so the mapping is auditable in one place.
const DLT_NULL: i32 = 0;
const DLT_EN10MB: i32 = 1;
const DLT_LOOP: i32 = 108;
const DLT_RAW_BSD: i32 = 12;
const DLT_RAW_LINKTYPE: i32 = 101;

impl LinkType {
    /// Maps a raw libpcap DLT number (as returned by `Capture::get_datalink`)
    /// onto a [`LinkType`].
    pub fn from_dlt(dlt: i32) -> Self {
        match dlt {
            DLT_EN10MB => LinkType::Ethernet,
            DLT_NULL | DLT_LOOP => LinkType::NullLoop,
            DLT_RAW_BSD | DLT_RAW_LINKTYPE => LinkType::Raw,
            other => LinkType::Unsupported(other),
        }
    }
}

/// EtherType marking an 802.1Q VLAN tag, after which four more bytes (the tag
/// plus the real EtherType) precede the payload.
const ETHERTYPE_VLAN: u16 = 0x8100;
const VLAN_TAG_LEN: usize = 4;

/// Strips `frame`'s link-layer header according to `link`, returning the IP
/// packet within, or `None` if the frame is too short, carries a non-IP
/// payload (e.g. ARP on an Ethernet link), or rides an unsupported link type.
pub fn strip_to_ip(link: LinkType, frame: &[u8]) -> Option<&[u8]> {
    match link {
        LinkType::Ethernet => strip_ethernet(frame),
        LinkType::NullLoop => frame.get(NULL_LOOP_HDR_LEN..),
        LinkType::Raw => Some(frame),
        LinkType::Unsupported(_) => None,
    }
}

/// Walks an Ethernet header, transparently skipping a single 802.1Q VLAN tag,
/// and returns the payload only if the EtherType marks it as IPv4 or IPv6.
fn strip_ethernet(frame: &[u8]) -> Option<&[u8]> {
    let ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    let (ethertype, payload_offset) = if ethertype == ETHERTYPE_VLAN {
        let inner =
            u16::from_be_bytes([*frame.get(ETH_HDR_LEN + 2)?, *frame.get(ETH_HDR_LEN + 3)?]);
        (inner, ETH_HDR_LEN + VLAN_TAG_LEN)
    } else {
        (ethertype, ETH_HDR_LEN)
    };

    match EtherType(ethertype) {
        EtherTypes::Ipv4 | EtherTypes::Ipv6 => frame.get(payload_offset..),
        _ => None,
    }
}

/// Extracts the source IP address and the Layer-4 segment from an IP packet,
/// dispatching on the version nibble so it works regardless of how the link
/// layer labeled the packet.
///
/// Returns `None` for a truncated packet or an unrecognized IP version.
/// IPv6 extension headers are not walked - the probes this parses replies to
/// never elicit them - so the returned slice is the bytes immediately after
/// the fixed IPv6 header.
pub fn parse_ip_segment(ip_bytes: &[u8]) -> Option<(IpAddr, &[u8])> {
    match ip_bytes.first()? >> 4 {
        4 => {
            let packet = Ipv4Packet::new(ip_bytes)?;
            let header_len = packet.get_header_length() as usize * 4;
            let segment = ip_bytes.get(header_len..)?;
            Some((IpAddr::V4(packet.get_source()), segment))
        }
        6 => {
            let packet = Ipv6Packet::new(ip_bytes)?;
            let segment = ip_bytes.get(crate::protocols::utils::IP_V6_HDR_LEN..)?;
            Some((IpAddr::V6(packet.get_source()), segment))
        }
        _ => None,
    }
}

/// Convenience over [`strip_to_ip`] + [`parse_ip_segment`]: takes a captured
/// frame and its link type and yields `(source_ip, layer4_segment)`.
pub fn parse_captured_segment(link: LinkType, frame: &[u8]) -> Option<(IpAddr, &[u8])> {
    parse_ip_segment(strip_to_ip(link, frame)?)
}

/// Wraps a finished Layer-4 `segment` in IP and Ethernet headers, producing a
/// frame ready to hand to a Layer-2 send.
///
/// The IP version is taken from `src`/`dst`, which must agree; a mismatch is
/// an error rather than a silent wrong-family packet.
pub fn build_ethernet_frame(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src: IpAddr,
    dst: IpAddr,
    protocol: IpNextHeaderProtocol,
    segment: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let payload_len = u16::try_from(segment.len()).context("layer-4 segment too large for IP")?;

    let (ethertype, ip_header) = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (
            EtherTypes::Ipv4,
            ip::create_ipv4_header(s, d, payload_len, protocol)?,
        ),
        (IpAddr::V6(s), IpAddr::V6(d)) => (
            EtherTypes::Ipv6,
            ip::create_ipv6_header(s, d, payload_len, protocol)?,
        ),
        _ => anyhow::bail!("IP version mismatch between {src} and {dst}"),
    };

    let mut frame = Vec::with_capacity(ETH_HDR_LEN + ip_header.len() + segment.len());
    frame.extend_from_slice(&ethernet::make_header(src_mac, dst_mac, ethertype)?);
    frame.extend_from_slice(&ip_header);
    frame.extend_from_slice(segment);
    Ok(frame)
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const TCP: IpNextHeaderProtocol = IpNextHeaderProtocols::Tcp;

    #[test]
    fn dlt_mapping_covers_known_link_types() {
        assert_eq!(LinkType::from_dlt(1), LinkType::Ethernet);
        assert_eq!(LinkType::from_dlt(0), LinkType::NullLoop);
        assert_eq!(LinkType::from_dlt(108), LinkType::NullLoop);
        assert_eq!(LinkType::from_dlt(12), LinkType::Raw);
        assert_eq!(LinkType::from_dlt(101), LinkType::Raw);
        assert_eq!(LinkType::from_dlt(999), LinkType::Unsupported(999));
    }

    /// Builds a minimal IPv4 packet carrying `payload` as its (opaque) L4.
    fn ipv4_packet(src: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        ip::create_ipv4_header(src, Ipv4Addr::LOCALHOST, payload.len() as u16, TCP)
            .unwrap()
            .into_iter()
            .chain(payload.iter().copied())
            .collect()
    }

    #[test]
    fn parses_source_and_segment_from_ipv4() {
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let src = Ipv4Addr::new(203, 0, 113, 7);
        let packet = ipv4_packet(src, &payload);

        let (parsed_src, segment) = parse_ip_segment(&packet).unwrap();
        assert_eq!(parsed_src, IpAddr::V4(src));
        assert_eq!(segment, &payload);
    }

    #[test]
    fn parses_source_and_segment_from_ipv6() {
        let payload = [1, 2, 3, 4];
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let header = ip::create_ipv6_header(
            src,
            Ipv6Addr::LOCALHOST,
            payload.len() as u16,
            IpNextHeaderProtocols::Tcp,
        )
        .unwrap();
        let packet: Vec<u8> = header.into_iter().chain(payload).collect();

        let (parsed_src, segment) = parse_ip_segment(&packet).unwrap();
        assert_eq!(parsed_src, IpAddr::V6(src));
        assert_eq!(segment, &payload);
    }

    #[test]
    fn null_loop_link_strips_four_byte_family_word() {
        let payload = [9, 9, 9, 9];
        let packet = ipv4_packet(Ipv4Addr::new(10, 0, 0, 1), &payload);
        // macOS AF_INET word (host byte order), immaterial to the parser.
        let mut framed = vec![2, 0, 0, 0];
        framed.extend_from_slice(&packet);

        let (src, segment) = parse_captured_segment(LinkType::NullLoop, &framed).unwrap();
        assert_eq!(src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(segment, &payload);
    }

    #[test]
    fn ethernet_link_selects_ipv4_by_ethertype() {
        let payload = [7, 7];
        let ip_packet = ipv4_packet(Ipv4Addr::new(192, 0, 2, 5), &payload);
        let frame = build_ethernet_frame(
            MacAddr::new(1, 2, 3, 4, 5, 6),
            MacAddr::new(6, 5, 4, 3, 2, 1),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            TCP,
            &payload,
        )
        .unwrap();

        // Rebuilt frame should round-trip back to source + payload. The IP
        // header inside carries a different total length than `ip_packet`'s
        // only if lengths diverge; here they match, so compare the segment.
        let _ = ip_packet;
        let (src, segment) = parse_captured_segment(LinkType::Ethernet, &frame).unwrap();
        assert_eq!(src, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)));
        assert_eq!(segment, &payload);
    }

    #[test]
    fn ethernet_link_ignores_non_ip_ethertype() {
        // EtherType 0x0806 (ARP) must not be parsed as IP.
        let mut frame = vec![0u8; ETH_HDR_LEN + 8];
        frame[12] = 0x08;
        frame[13] = 0x06;
        assert!(parse_captured_segment(LinkType::Ethernet, &frame).is_none());
    }

    #[test]
    fn ethernet_link_skips_vlan_tag() {
        let payload = [4, 2];
        let inner = ipv4_packet(Ipv4Addr::new(198, 51, 100, 9), &payload);
        let mut frame = vec![0u8; ETH_HDR_LEN];
        frame[12] = 0x81; // 0x8100 VLAN
        frame[13] = 0x00;
        frame.extend_from_slice(&[0x00, 0x64]); // VLAN id 100
        frame.extend_from_slice(&[0x08, 0x00]); // inner EtherType IPv4
        frame.extend_from_slice(&inner);

        let (src, segment) = parse_captured_segment(LinkType::Ethernet, &frame).unwrap();
        assert_eq!(src, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
        assert_eq!(segment, &payload);
    }

    #[test]
    fn unsupported_link_yields_nothing() {
        let frame = [0u8; 32];
        assert!(parse_captured_segment(LinkType::Unsupported(42), &frame).is_none());
    }
}
