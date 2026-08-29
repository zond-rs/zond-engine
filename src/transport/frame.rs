// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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
//! The same parse is reused for the IP packet *quoted inside* an ICMP error,
//! which is how a UDP scan learns which probe an unreachable message answers.
//! That path parses bytes chosen by a remote host, so every length here is
//! taken from the packet and bounds-checked rather than assumed.
//!
//! ## Send
//!
//! [`build_ethernet_frame`] wraps an already-built Layer-4 segment in IP and
//! Ethernet headers for a Layer-2 send, and [`build_fragmented_ethernet_frames`]
//! does the same while splitting the IP packet across fragments when a scan
//! asked to. The raw-IP send path (tunnel and loopback links) doesn't use these,
//! because there the kernel writes the IP header, so they are only exercised on
//! true Ethernet links.

use std::net::IpAddr;

use anyhow::Context;
use pnet_base::MacAddr;
use pnet_packet::ethernet::EtherTypes;
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;

use crate::model::capture::{IpObservation, Ipv4Observation, Ipv6Observation};
use crate::protocols::craft;
use crate::protocols::ethernet;
use crate::protocols::ip;
use crate::protocols::sizes::{ETH_HDR_LEN, IP_V4_HDR_LEN, IP_V6_HDR_LEN};

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

/// The don't-fragment and more-fragments bits within an IPv4 header's
/// three-bit flags field, as `pnet` hands it back. The mirror of
/// [`ipv4_flags`](crate::protocols::craft::ipv4_flags) on the send side, named
/// here rather than shared because reading a captured header and writing one
/// are different jobs and only one of them may write a value that is wrong.
const IPV4_DONT_FRAGMENT: u8 = 0b010;
const IPV4_MORE_FRAGMENTS: u8 = 0b001;

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

/// Walks an Ethernet header, transparently skipping any VLAN tags, and returns
/// the payload only if the EtherType marks it as IPv4 or IPv6.
///
/// The tag walk is [`ethernet::parse`]'s rather than a second copy of it. It used
/// to be a copy here, and the copy understood one tag where the original
/// understands a stack — which is the ordinary way two implementations of one
/// rule come to disagree.
fn strip_ethernet(frame: &[u8]) -> Option<&[u8]> {
    let parsed = ethernet::parse(frame).ok()?;
    match parsed.ethertype() {
        EtherTypes::Ipv4 | EtherTypes::Ipv6 => Some(parsed.payload()),
        _ => None,
    }
}

/// The hardware address a captured frame came from, where the link has one.
///
/// # What this is for, and what it is not for
///
/// It answers **"did this reply come from the host whose address it claims?"**,
/// and that is a question the source *IP* structurally cannot answer: anything
/// answering in a host's place — a transparent proxy, a DNS interceptor, a
/// firewall resetting on a host's behalf — uses that host's address, so the IP
/// header of a forged answer and a real one are identical. The hardware address
/// is not, and on an on-link segment it settles the matter outright.
///
/// It is a poor basis for **vendor attribution**, which is the use it looks like
/// it has. A reply from off-link carries the last-hop router's address, not the
/// sender's, and the two are indistinguishable from here — so an OUI lookup
/// against this would confidently report the router's manufacturer as the host's.
/// Where a vendor is actually wanted, it belongs to the on-link discovery path
/// ([`crate::system::neighbors`] and the local scanner), which knows a neighbour
/// is a neighbour.
///
/// `None` where there is genuinely nothing to read: a `DLT_NULL`/`DLT_LOOP`
/// tunnel or loopback link prepends an address-family word and no addresses at
/// all, a `DLT_RAW` link prepends nothing, and a frame too short to hold an
/// Ethernet header describes nothing. `None` never means "the sender had no
/// hardware address".
pub fn source_mac(link: LinkType, frame: &[u8]) -> Option<MacAddr> {
    match link {
        // Offsets 0..6 destination, 6..12 source, then the EtherType. A VLAN tag
        // sits *after* both addresses, so unlike the payload offset this one does
        // not move for a tagged frame — which is exactly the mistake to avoid,
        // since a tag-shifted read lands in the middle of the EtherType and the
        // start of the IP header and yields a plausible-looking address.
        LinkType::Ethernet => Some(MacAddr::new(
            *frame.get(6)?,
            *frame.get(7)?,
            *frame.get(8)?,
            *frame.get(9)?,
            *frame.get(10)?,
            *frame.get(11)?,
        )),
        LinkType::NullLoop | LinkType::Raw | LinkType::Unsupported(_) => None,
    }
}

/// One parsed IP packet: its endpoints, the Layer-4 protocol it carries, and
/// that Layer-4 segment.
///
/// The protocol travels with the bytes because a Layer-4 segment is *not*
/// self-describing. `UdpPacket::new` succeeds on any eight bytes, so an ICMP
/// error read as UDP yields a header full of plausible nonsense - a reader
/// that has to guess will eventually guess wrong. Carrying the IP header's
/// answer removes the guess.
///
/// Both endpoints are kept, not just the source. A reply's source is who sent
/// it, but an ICMP error's *quoted* packet identifies the probe by its
/// destination - and the router that reports the error is not the host the
/// probe was aimed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpSegment<'a> {
    /// Who sent the packet.
    pub source: IpAddr,
    /// Who it was addressed to.
    pub destination: IpAddr,
    /// The Layer-4 protocol [`payload`](Self::payload) is, read from the IPv4
    /// protocol field or the IPv6 next-header field.
    pub protocol: IpNextHeaderProtocol,
    /// The Layer-4 segment: the bytes after the IP header.
    pub payload: &'a [u8],
    /// What the rest of the IP header said about the stack that wrote it.
    ///
    /// Kept because the header is parsed here and nowhere else. Everything
    /// downstream sees a Layer-4 segment with the IP header already gone, so a
    /// field dropped at this line is not recoverable at any later one — and
    /// three of these are among the cheapest identifying signals a reply
    /// carries. They cost six bytes to keep and a second packet to re-obtain.
    pub observation: IpObservation,
}

/// Parses an IP packet into its endpoints, protocol, and Layer-4 segment,
/// dispatching on the version nibble so it works regardless of how the link
/// layer labeled the packet.
///
/// Returns `None` for a truncated packet, an implausible header length, an
/// unrecognized IP version, or an IPv6 chain that names no Layer-4 segment at
/// all (see `walk_ipv6_headers`).
pub fn parse_ip_segment(ip_bytes: &[u8]) -> Option<IpSegment<'_>> {
    match ip_bytes.first()? >> 4 {
        4 => {
            let packet = Ipv4Packet::new(ip_bytes)?;
            // IHL is four bits of remote-chosen data. Anything below the fixed
            // header size would slice back into the header itself, so reject it
            // rather than hand out a payload that overlaps the addresses.
            let header_len = packet.get_header_length() as usize * 4;
            if header_len < IP_V4_HDR_LEN {
                return None;
            }
            Some(IpSegment {
                source: IpAddr::V4(packet.get_source()),
                destination: IpAddr::V4(packet.get_destination()),
                protocol: packet.get_next_level_protocol(),
                payload: ip_bytes.get(header_len..)?,
                observation: IpObservation::V4(Ipv4Observation {
                    ttl: packet.get_ttl(),
                    identification: packet.get_identification(),
                    dont_fragment: packet.get_flags() & IPV4_DONT_FRAGMENT != 0,
                    more_fragments: packet.get_flags() & IPV4_MORE_FRAGMENTS != 0,
                    dscp: packet.get_dscp(),
                    ecn: packet.get_ecn(),
                }),
            })
        }
        6 => {
            let packet = Ipv6Packet::new(ip_bytes)?;
            let (protocol, offset) =
                walk_ipv6_headers(ip_bytes, packet.get_next_header(), IP_V6_HDR_LEN)?;
            Some(IpSegment {
                source: IpAddr::V6(packet.get_source()),
                destination: IpAddr::V6(packet.get_destination()),
                protocol,
                payload: ip_bytes.get(offset..)?,
                observation: IpObservation::V6(Ipv6Observation {
                    hop_limit: packet.get_hop_limit(),
                    traffic_class: packet.get_traffic_class(),
                    flow_label: packet.get_flow_label(),
                }),
            })
        }
        _ => None,
    }
}

/// How many extension headers to walk before giving up.
///
/// A chain this long is not a packet anyone sends; it is someone seeing how long
/// this loop will run. Eight is past anything legitimate and bounds the work per
/// frame at a constant.
const MAX_EXTENSION_HEADERS: usize = 8;

/// Follows an IPv6 next-header chain from `protocol` at `offset`, returning the
/// Layer-4 protocol and the offset its segment starts at.
///
/// The fixed header's next-header field is not the transport protocol; it is
/// only the first link of a chain, and each extension header names the next.
/// Reading it as the transport protocol hands out an extension header as though
/// it were a TCP or ICMPv6 segment - a header full of plausible nonsense that
/// parses cleanly and means nothing.
///
/// `None` where there is no Layer-4 segment to point at: a chain that runs past
/// the end of the packet, one longer than [`MAX_EXTENSION_HEADERS`], an explicit
/// no-next-header, or a non-initial fragment, whose bytes are the middle of
/// somebody's datagram rather than the start of a header. Every length here is
/// read from the packet and bounds-checked, because these bytes are chosen by a
/// remote host - and by a hostile one, in the packet quoted inside an ICMP
/// error.
fn walk_ipv6_headers(
    bytes: &[u8],
    protocol: IpNextHeaderProtocol,
    offset: usize,
) -> Option<(IpNextHeaderProtocol, usize)> {
    use IpNextHeaderProtocols as Protocols;

    let mut protocol = protocol;
    let mut offset = offset;

    for _ in 0..MAX_EXTENSION_HEADERS {
        let length = match protocol {
            // Explicitly nothing follows, so there is no segment to return.
            Protocols::Ipv6NoNxt => return None,
            // The common shape: a next-header byte, a length in 8-octet units
            // not counting the first, then options.
            Protocols::Hopopt | Protocols::Ipv6Route | Protocols::Ipv6Opts => {
                (usize::from(*bytes.get(offset + 1)?) + 1) * 8
            }
            // The authentication header counts in 4-octet units, not 8, and
            // excludes two rather than one.
            Protocols::Ah => (usize::from(*bytes.get(offset + 1)?) + 2) * 4,
            // Fixed at eight bytes. Only the first fragment carries the Layer-4
            // header the caller is looking for; in any other the offset field is
            // non-zero and what follows is payload.
            Protocols::Ipv6Frag => {
                let fragment_offset =
                    u16::from_be_bytes([*bytes.get(offset + 2)?, *bytes.get(offset + 3)?]) >> 3;
                if fragment_offset != 0 {
                    return None;
                }
                8
            }
            // Anything else is the Layer-4 protocol, including the payloads
            // (ESP) this cannot see past.
            transport => return Some((transport, offset)),
        };

        protocol = IpNextHeaderProtocol::new(*bytes.get(offset)?);
        offset = offset.checked_add(length)?;
        // A header that claims to end past the packet describes nothing.
        if offset > bytes.len() {
            return None;
        }
    }

    None
}

/// Convenience over [`strip_to_ip`] + [`parse_ip_segment`]: takes a captured
/// frame and its link type and yields the [`IpSegment`] within.
pub fn parse_captured_segment(link: LinkType, frame: &[u8]) -> Option<IpSegment<'_>> {
    parse_ip_segment(strip_to_ip(link, frame)?)
}

/// Everything a frame needs except its payload: where it goes at both layers,
/// what it carries, and how far it may travel.
///
/// A struct rather than positional arguments. Two `MacAddr`s and two `IpAddr`s
/// sit next to each other here, and nothing would diagnose a caller swapping
/// either pair.
#[derive(Debug, Clone, Copy)]
pub struct FrameSpec {
    /// The sending interface's address, or a spoofed one.
    pub src_mac: MacAddr,
    /// The next hop's address on this segment.
    pub dst_mac: MacAddr,
    /// The source address written into the IP header. Must agree in family with
    /// [`dst`](Self::dst).
    pub src: IpAddr,
    /// The destination address written into the IP header.
    pub dst: IpAddr,
    /// What the IP header says it carries.
    pub protocol: IpNextHeaderProtocol,
    /// IPv4's TTL or IPv6's hop limit, whichever the family calls it, so one
    /// caller decides it once for both. It lives here rather than with the
    /// kernel because this is the backend that can honour it exactly, the header
    /// being built in this module; see
    /// [`Emission`](crate::transport::probe::Emission).
    pub hop_limit: u8,
}

/// Wraps a finished Layer-4 `segment` in IP and Ethernet headers, producing a
/// frame ready to hand to a Layer-2 send.
///
/// The IP version comes from the spec's address pair, which must agree. A
/// mismatch is an error rather than a silent wrong-family packet.
pub fn build_ethernet_frame(spec: &FrameSpec, segment: &[u8]) -> anyhow::Result<Vec<u8>> {
    let FrameSpec {
        src_mac,
        dst_mac,
        src,
        dst,
        protocol,
        hop_limit,
    } = *spec;
    let payload_len = u16::try_from(segment.len()).context("layer-4 segment too large for IP")?;

    let (ethertype, ip_header) = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (
            EtherTypes::Ipv4,
            ip::create_ipv4_header(s, d, payload_len, protocol, hop_limit)?,
        ),
        (IpAddr::V6(s), IpAddr::V6(d)) => (
            EtherTypes::Ipv6,
            ip::create_ipv6_header(s, d, payload_len, protocol, hop_limit),
        ),
        _ => anyhow::bail!("IP version mismatch between {src} and {dst}"),
    };

    let mut frame = Vec::with_capacity(ETH_HDR_LEN + ip_header.len() + segment.len());
    frame.extend_from_slice(&ethernet::create_header(src_mac, dst_mac, ethertype));
    frame.extend_from_slice(&ip_header);
    frame.extend_from_slice(segment);
    Ok(frame)
}

/// The Ethernet frames a probe becomes once its IP packet is split into
/// fragments no larger than `mtu` bytes each: one frame per fragment, in order,
/// each ready to put on the wire.
///
/// The counterpart of [`build_ethernet_frame`] for a caller who chose to
/// fragment. It builds the same IPv4 packet, splits it with
/// [`ip::fragment_ipv4`], and wraps each fragment in an Ethernet header. A packet
/// that already fits the MTU comes back as a single frame.
///
/// IPv4 only. IPv6 fragments through an extension header this engine does not
/// build, so an IPv6 destination is refused rather than sent whole. A scan that
/// reported it fragmented must have.
///
/// # Errors
///
/// Refuses an IPv6 destination, a mismatched address pair, and, through
/// [`ip::fragment_ipv4`], an MTU too small to carry a fragment or a datagram
/// larger than the IP length field can describe.
pub fn build_fragmented_ethernet_frames(
    spec: &FrameSpec,
    segment: &[u8],
    mtu: u16,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let FrameSpec {
        src_mac,
        dst_mac,
        src,
        dst,
        protocol,
        hop_limit,
    } = *spec;
    let (src4, dst4) = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
        (IpAddr::V6(_), IpAddr::V6(_)) => anyhow::bail!(
            "cannot fragment to {dst}: IPv6 fragments through an extension header this engine \
             does not build"
        ),
        _ => anyhow::bail!("IP version mismatch between {src} and {dst}"),
    };

    let header = craft::Ipv4 {
        protocol: craft::Field::Exact(protocol),
        ..craft::Ipv4::new(src4, dst4).with_ttl(hop_limit)
    };

    let frames = ip::fragment_ipv4(&header, segment, mtu)?
        .into_iter()
        .map(|packet| {
            let mut frame = Vec::with_capacity(ETH_HDR_LEN + packet.len());
            frame.extend_from_slice(&ethernet::create_header(src_mac, dst_mac, EtherTypes::Ipv4));
            frame.extend_from_slice(&packet);
            frame
        })
        .collect();
    Ok(frames)
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
    use pnet_packet::ip::IpNextHeaderProtocols;
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
        ip::create_ipv4_header(
            src,
            Ipv4Addr::LOCALHOST,
            payload.len() as u16,
            TCP,
            ip::HOP_LIMIT_ROUTED,
        )
        .unwrap()
        .into_iter()
        .chain(payload.iter().copied())
        .collect()
    }

    #[test]
    fn parses_endpoints_protocol_and_segment_from_ipv4() {
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let src = Ipv4Addr::new(203, 0, 113, 7);
        let packet = ipv4_packet(src, &payload);

        let parsed = parse_ip_segment(&packet).unwrap();
        assert_eq!(parsed.source, IpAddr::V4(src));
        assert_eq!(parsed.destination, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(parsed.protocol, TCP);
        assert_eq!(parsed.payload, &payload);
    }

    #[test]
    fn parses_endpoints_protocol_and_segment_from_ipv6() {
        let payload = [1, 2, 3, 4];
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let header = ip::create_ipv6_header(
            src,
            Ipv6Addr::LOCALHOST,
            payload.len() as u16,
            IpNextHeaderProtocols::Udp,
            ip::HOP_LIMIT_ROUTED,
        );
        let packet: Vec<u8> = header.into_iter().chain(payload).collect();

        let parsed = parse_ip_segment(&packet).unwrap();
        assert_eq!(parsed.source, IpAddr::V6(src));
        assert_eq!(parsed.destination, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(parsed.protocol, IpNextHeaderProtocols::Udp);
        assert_eq!(parsed.payload, &payload);
    }

    /// The fields a stack is identified by, read out of bytes laid out by hand
    /// from RFC 791 rather than by this crate's own writer.
    ///
    /// Written as literal bytes on purpose. Building the fixture with
    /// [`crate::protocols::craft`] would check that this parser agrees with that
    /// builder, which is two views of one understanding — the same shape of
    /// mistake as a simulator that emits what the parser already accepts. The
    /// offsets below come from the specification, so a field read from the wrong
    /// place fails here instead of shipping as a signature nobody can match.
    #[test]
    fn an_ipv4_header_yields_the_fields_its_stack_chose() {
        let mut packet = vec![0u8; IP_V4_HDR_LEN];
        packet[0] = 0x45; // version 4, 5-word header
        packet[1] = 0x8B; // DSCP 0b100010 = 34, ECN 0b11 = 3
        packet[2..4].copy_from_slice(&(IP_V4_HDR_LEN as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&0xBEEFu16.to_be_bytes()); // identification
        packet[6] = 0x40; // don't-fragment set, more-fragments clear
        packet[8] = 57; // TTL
        packet[9] = TCP.0;

        let IpObservation::V4(observed) = parse_ip_segment(&packet).unwrap().observation else {
            panic!("an IPv4 packet observes an IPv4 header");
        };

        assert_eq!(observed.ttl, 57);
        assert_eq!(observed.identification, 0xBEEF);
        assert!(observed.dont_fragment);
        assert!(!observed.more_fragments);
        assert_eq!(observed.dscp, 34);
        assert_eq!(observed.ecn, 3);
    }

    /// Don't-fragment and more-fragments are adjacent bits of one three-bit
    /// field, and swapping them is invisible: both readings parse, both produce
    /// a plausible packet, and the only symptom is a stack rule that never
    /// matches. This pins each bit to the meaning RFC 791 gives it.
    #[test]
    fn the_two_fragment_bits_are_not_each_other() {
        let observe = |flag_byte: u8| {
            let mut packet = vec![0u8; IP_V4_HDR_LEN];
            packet[0] = 0x45;
            packet[6] = flag_byte;
            packet[9] = TCP.0;
            match parse_ip_segment(&packet).unwrap().observation {
                IpObservation::V4(observed) => observed,
                IpObservation::V6(_) => panic!("an IPv4 packet observes an IPv4 header"),
            }
        };

        // Bit 6 of the byte is DF; bit 5 is MF.
        let dont_fragment = observe(0b0100_0000);
        assert!(dont_fragment.dont_fragment && !dont_fragment.more_fragments);

        let more_fragments = observe(0b0010_0000);
        assert!(more_fragments.more_fragments && !more_fragments.dont_fragment);
        assert!(
            IpObservation::V4(more_fragments).is_fragment(),
            "a datagram with more to come is a fragment, and its headers describe only this piece"
        );
    }

    /// Traffic class and flow label share a 32-bit word with the version nibble
    /// and neither is byte-aligned, so both are read with a shift and a mask and
    /// both are easy to read one nibble out. Hand-laid bytes per RFC 8200.
    #[test]
    fn an_ipv6_header_yields_the_fields_across_its_first_word() {
        let mut packet = vec![0u8; IP_V6_HDR_LEN];
        // version 6, traffic class 0x8B, flow label 0x12345.
        packet[0..4].copy_from_slice(&0x68B1_2345u32.to_be_bytes());
        packet[6] = TCP.0;
        packet[7] = 57; // hop limit

        let IpObservation::V6(observed) = parse_ip_segment(&packet).unwrap().observation else {
            panic!("an IPv6 packet observes an IPv6 header");
        };

        assert_eq!(observed.hop_limit, 57);
        assert_eq!(observed.traffic_class, 0x8B);
        assert_eq!(observed.flow_label, 0x12345);
    }

    /// A header length below the fixed 20 bytes would slice back into the
    /// header itself. Remote hosts choose this field inside a quoted ICMP
    /// packet, so it is rejected rather than trusted.
    #[test]
    fn implausible_ipv4_header_length_is_rejected() {
        let mut packet = ipv4_packet(Ipv4Addr::new(10, 0, 0, 1), &[1, 2, 3, 4]);
        // Version 4, IHL 3 (12 bytes - shorter than the fixed header).
        packet[0] = 0x43;
        assert!(parse_ip_segment(&packet).is_none());
    }

    #[test]
    fn null_loop_link_strips_four_byte_family_word() {
        let payload = [9, 9, 9, 9];
        let packet = ipv4_packet(Ipv4Addr::new(10, 0, 0, 1), &payload);
        // macOS AF_INET word (host byte order), immaterial to the parser.
        let mut framed = vec![2, 0, 0, 0];
        framed.extend_from_slice(&packet);

        let parsed = parse_captured_segment(LinkType::NullLoop, &framed).unwrap();
        assert_eq!(parsed.source, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(parsed.payload, &payload);
    }

    #[test]
    fn ethernet_link_selects_ipv4_by_ethertype() {
        let payload = [7, 7];
        let ip_packet = ipv4_packet(Ipv4Addr::new(192, 0, 2, 5), &payload);
        let frame = build_ethernet_frame(
            &FrameSpec {
                src_mac: MacAddr::new(1, 2, 3, 4, 5, 6),
                dst_mac: MacAddr::new(6, 5, 4, 3, 2, 1),
                src: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
                dst: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                protocol: TCP,
                hop_limit: ip::HOP_LIMIT_ROUTED,
            },
            &payload,
        )
        .unwrap();

        // Rebuilt frame should round-trip back to source + payload. The IP
        // header inside carries a different total length than `ip_packet`'s
        // only if lengths diverge; here they match, so compare the segment.
        let _ = ip_packet;
        let parsed = parse_captured_segment(LinkType::Ethernet, &frame).unwrap();
        assert_eq!(parsed.source, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)));
        assert_eq!(parsed.destination, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(parsed.payload, &payload);
    }

    #[test]
    fn fragmenting_wraps_each_ip_fragment_in_its_own_ethernet_frame() {
        use pnet_packet::Packet;

        let src_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let dst_mac = MacAddr::new(0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB);
        let src = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let segment: Vec<u8> = (0..40u8).collect();
        // Sixteen payload bytes per fragment, so forty do not fit one.
        let mtu = (IP_V4_HDR_LEN + 16) as u16;

        let frames = build_fragmented_ethernet_frames(
            &FrameSpec {
                src_mac,
                dst_mac,
                src,
                dst,
                protocol: TCP,
                hop_limit: ip::HOP_LIMIT_ROUTED,
            },
            &segment,
            mtu,
        )
        .expect("an IPv4 segment fragments");
        assert!(
            frames.len() > 1,
            "40 bytes should not fit one 16-byte fragment"
        );

        let mut reassembled = Vec::new();
        for frame in &frames {
            assert_eq!(
                &frame[12..14],
                &[0x08, 0x00],
                "each frame is an IPv4 Ethernet frame"
            );
            let ip_packet = &frame[ETH_HDR_LEN..];
            assert!(
                ip_packet.len() <= usize::from(mtu),
                "each fragment fits the MTU"
            );
            reassembled.extend_from_slice(Ipv4Packet::new(ip_packet).unwrap().payload());
        }
        assert_eq!(
            reassembled, segment,
            "the fragments reassemble to the original segment"
        );
    }

    #[test]
    fn ipv6_fragmentation_is_refused() {
        let mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let src = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let dst = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let result = build_fragmented_ethernet_frames(
            &FrameSpec {
                src_mac: mac,
                dst_mac: mac,
                src,
                dst,
                protocol: TCP,
                hop_limit: ip::HOP_LIMIT_ROUTED,
            },
            &[0u8; 40],
            40,
        );
        assert!(
            result.is_err(),
            "IPv6 fragments through an extension header this engine does not build, so it is refused"
        );
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

        let parsed = parse_captured_segment(LinkType::Ethernet, &frame).unwrap();
        assert_eq!(parsed.source, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
        assert_eq!(parsed.payload, &payload);
    }

    /// The addresses sit before the EtherType, so a VLAN tag does not move them —
    /// unlike the payload offset, which it does move. Reading them at a
    /// tag-shifted offset lands across the EtherType and the start of the IP
    /// header and yields a perfectly plausible-looking address, which is why both
    /// framings are pinned here rather than only the plain one.
    #[test]
    fn the_source_hardware_address_does_not_move_for_a_vlan_tag() {
        let sender = MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);
        let inner = ipv4_packet(Ipv4Addr::new(198, 51, 100, 9), &[4, 2]);

        let plain = build_ethernet_frame(
            &FrameSpec {
                src_mac: sender,
                dst_mac: MacAddr::new(1, 1, 1, 1, 1, 1),
                src: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
                dst: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                protocol: TCP,
                hop_limit: ip::HOP_LIMIT_ROUTED,
            },
            &[4, 2],
        )
        .unwrap();
        assert_eq!(source_mac(LinkType::Ethernet, &plain), Some(sender));

        let mut tagged = vec![0u8; ETH_HDR_LEN];
        tagged[6..12].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        tagged[12] = 0x81; // 0x8100 VLAN
        tagged[13] = 0x00;
        tagged.extend_from_slice(&[0x00, 0x64]); // VLAN id 100
        tagged.extend_from_slice(&[0x08, 0x00]); // inner EtherType IPv4
        tagged.extend_from_slice(&inner);
        assert_eq!(source_mac(LinkType::Ethernet, &tagged), Some(sender));
    }

    /// A link that prepends no addresses has none to report, and that is not the
    /// same claim as "the sender had none". Every one of these carries IP traffic
    /// this engine captures on, so each has to answer `None` deliberately rather
    /// than by reading six bytes of somebody's IP header.
    #[test]
    fn a_link_without_hardware_addresses_reports_none() {
        let packet = ipv4_packet(Ipv4Addr::new(10, 0, 0, 1), &[1, 2, 3, 4]);

        // A tunnel or loopback link prepends a four-byte address-family word.
        let mut framed = vec![2, 0, 0, 0];
        framed.extend_from_slice(&packet);
        assert!(source_mac(LinkType::NullLoop, &framed).is_none());

        // A raw-IP link prepends nothing at all.
        assert!(source_mac(LinkType::Raw, &packet).is_none());

        assert!(source_mac(LinkType::Unsupported(42), &packet).is_none());

        // Too short to hold an Ethernet header. Reading past it would be a
        // panic on a frame chosen by whoever is on the wire.
        assert!(source_mac(LinkType::Ethernet, &[0u8; 8]).is_none());
    }

    #[test]
    fn unsupported_link_yields_nothing() {
        let frame = [0u8; 32];
        assert!(parse_captured_segment(LinkType::Unsupported(42), &frame).is_none());
    }

    // ─── IPv6 extension headers ──────────────────────────────────────────────

    /// An IPv6 packet whose fixed header names `first`, followed by `chain`
    /// (already-encoded extension headers) and then `segment`.
    fn ipv6_chain(first: IpNextHeaderProtocol, chain: &[u8], segment: &[u8]) -> Vec<u8> {
        let payload_len = (chain.len() + segment.len()) as u16;
        ip::create_ipv6_header(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::LOCALHOST,
            payload_len,
            first,
            ip::HOP_LIMIT_ROUTED,
        )
        .into_iter()
        .chain(chain.iter().copied())
        .chain(segment.iter().copied())
        .collect()
    }

    /// One extension header in the common shape: next protocol, length in
    /// 8-octet units past the first, then padding to that length.
    fn extension(next: IpNextHeaderProtocol, units_past_first: u8) -> Vec<u8> {
        let mut header = vec![0u8; (usize::from(units_past_first) + 1) * 8];
        header[0] = next.0;
        header[1] = units_past_first;
        header
    }

    /// The defect this walking exists to prevent. Read as the transport
    /// protocol, the fixed header's next-header field hands a destination-options
    /// header to a caller expecting TCP - and `TcpPacket::new` accepts it, so
    /// nothing downstream can notice.
    #[test]
    fn a_chain_of_extension_headers_yields_the_transport_behind_it() {
        let segment = [0xAB, 0xCD, 0xEF, 0x01];
        let chain = [
            extension(IpNextHeaderProtocols::Ipv6Route, 0),
            extension(IpNextHeaderProtocols::Tcp, 2),
        ]
        .concat();
        let packet = ipv6_chain(IpNextHeaderProtocols::Ipv6Opts, &chain, &segment);

        let parsed = parse_ip_segment(&packet).unwrap();
        assert_eq!(parsed.protocol, TCP);
        assert_eq!(parsed.payload, &segment);
    }

    /// The first fragment carries the Layer-4 header, so it parses.
    #[test]
    fn the_first_fragment_yields_its_transport_header() {
        let segment = [1, 2, 3, 4];
        let mut fragment = vec![0u8; 8];
        fragment[0] = IpNextHeaderProtocols::Tcp.0;
        // Offset zero, more-fragments set.
        fragment[3] = 1;
        let packet = ipv6_chain(IpNextHeaderProtocols::Ipv6Frag, &fragment, &segment);

        let parsed = parse_ip_segment(&packet).unwrap();
        assert_eq!(parsed.protocol, TCP);
        assert_eq!(parsed.payload, &segment);
    }

    /// A later fragment does not. Its bytes are the middle of somebody's
    /// datagram, and handing them over as a TCP header invents a segment.
    #[test]
    fn a_later_fragment_yields_nothing() {
        let mut fragment = vec![0u8; 8];
        fragment[0] = IpNextHeaderProtocols::Tcp.0;
        // Fragment offset 185, in 8-octet units, shifted past the flag bits.
        fragment[2..4].copy_from_slice(&(185u16 << 3).to_be_bytes());
        let packet = ipv6_chain(IpNextHeaderProtocols::Ipv6Frag, &fragment, &[1, 2, 3, 4]);

        assert!(parse_ip_segment(&packet).is_none());
    }

    /// Remote-chosen lengths, so each of these has to be refused rather than
    /// trusted: a header claiming to extend past the packet, a chain long enough
    /// to be a denial of service, and an explicit end with nothing after it.
    #[test]
    fn implausible_extension_chains_are_refused() {
        let overrunning = ipv6_chain(
            IpNextHeaderProtocols::Ipv6Opts,
            &[IpNextHeaderProtocols::Tcp.0, 200, 0, 0, 0, 0, 0, 0],
            &[],
        );
        assert!(parse_ip_segment(&overrunning).is_none());

        let endless: Vec<u8> = (0..MAX_EXTENSION_HEADERS + 2)
            .flat_map(|_| extension(IpNextHeaderProtocols::Ipv6Opts, 0))
            .collect();
        let too_long = ipv6_chain(IpNextHeaderProtocols::Ipv6Opts, &endless, &[1, 2, 3, 4]);
        assert!(parse_ip_segment(&too_long).is_none());

        let nothing_follows = ipv6_chain(IpNextHeaderProtocols::Ipv6NoNxt, &[], &[]);
        assert!(parse_ip_segment(&nothing_follows).is_none());
    }

    /// A payload this cannot see past is reported as itself, not guessed at.
    #[test]
    fn an_encrypted_payload_is_reported_as_esp() {
        let packet = ipv6_chain(IpNextHeaderProtocols::Esp, &[], &[9, 9, 9, 9]);

        let parsed = parse_ip_segment(&packet).unwrap();
        assert_eq!(parsed.protocol, IpNextHeaderProtocols::Esp);
    }
}
