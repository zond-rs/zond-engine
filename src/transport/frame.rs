// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Link-Layer Framing
//!
//! Turns captured link-layer frames into transport-layer segments, and transport-layer
//! segments into complete Ethernet frames, so the scanner never needs to know what
//! kind of link it runs over.
//!
//! ## Receive
//!
//! A `pcap` capture returns whatever the interface's *data-link type* (DLT) prescribes:
//! a 14-byte Ethernet header on `en0`/`eth0`, a 4-byte address-family word on a VPN
//! `utun`/`tun` or loopback link, a 16-byte pseudo-header Linux writes on a PPP link,
//! or nothing on a raw-IP link. [`strip_to_ip`] reduces all of these to the IP packet,
//! and [`parse_ip_segment`] extracts the addresses and the Layer-4 payload.
//!
//! Once the link header is stripped, the IP version is read from the packet's version
//! nibble. The link layer's `AF_*` tag is unreliable for this: macOS `AF_INET6` is 30,
//! FreeBSD 28, NetBSD/OpenBSD 24.
//!
//! The same parse reads the IP packet *quoted inside* an ICMP error, which is how a UDP
//! scan learns which probe an unreachable message answers. Those bytes are chosen by a
//! remote host, so every length is taken from the packet and bounds-checked.
//!
//! ## Send
//!
//! [`build_ethernet_frame`] wraps a built Layer-4 segment in IP and Ethernet headers
//! for a Layer-2 send, and [`build_fragmented_ethernet_frames`] does the same while
//! splitting the IP packet into fragments. The raw-IP send path (tunnel and loopback
//! links) does not use these, since the kernel writes the IP header there. The macOS
//! loopback interface, which takes a frame through BPF, gets what
//! `build_null_loop_frames` makes: the same packet behind the four-byte family word its
//! captures carry.

use std::net::IpAddr;

use crate::model::mac::MacAddr;
use pnet_packet::ethernet::{EtherType, EtherTypes};
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;

use crate::model::capture::{IpObservation, Ipv4Observation, Ipv6Observation};
use crate::protocols::craft;
use crate::protocols::error::PacketError;
use crate::protocols::ethernet;
use crate::protocols::ip;
use crate::protocols::sizes::{ETH_HDR_LEN, IP_V4_HDR_LEN, IP_V6_HDR_LEN};

/// The `pcap` data-link types this crate can strip down to an IP packet. Anything else
/// is [`LinkType::Unsupported`], and the caller must refuse to capture on that
/// interface.
#[non_exhaustive]
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
    /// `DLT_LINUX_SLL`: a 16-byte pseudo-header Linux writes in place of a link header
    /// it will not hand over, naming what follows by EtherType.
    ///
    /// `libpcap` opens a PPP link (and so a PPP VPN's tunnel) as this, and falls back
    /// to it for any link whose hardware type it cannot map, GRE and IPv6 tunnels
    /// among them.
    LinuxSll,
    /// `DLT_LINUX_SLL2`: the 20-byte successor to [`LinuxSll`](Self::LinuxSll), the
    /// same fields reordered with the interface's index added.
    ///
    /// What `tcpdump -i any` writes. A capture of one named link comes up as
    /// [`LinuxSll`](Self::LinuxSll) unless it asks for this, so it reaches this crate
    /// in captures taken by other tools.
    LinuxSll2,
    /// A data-link type this crate can't parse; the numeric DLT is kept for
    /// diagnostics.
    Unsupported(i32),
}

/// The width of the pseudo-header `DLT_NULL`/`DLT_LOOP` links prepend: a single 32-bit
/// address-family word.
const NULL_LOOP_HDR_LEN: usize = 4;

/// The width of the pseudo-header a `DLT_LINUX_SLL` link prepends.
///
/// Crate-visible for the capture's snapshot floor, which must leave room for the
/// deepest link header this module strips.
pub(crate) const SLL_HDR_LEN: usize = 16;

/// The width of the pseudo-header a `DLT_LINUX_SLL2` link prepends. See
/// [`SLL_HDR_LEN`].
pub(crate) const SLL2_HDR_LEN: usize = 20;

// libpcap data-link type numbers, kept local so the mapping is auditable in one
// place.
const DLT_NULL: i32 = 0;
const DLT_EN10MB: i32 = 1;
const DLT_LOOP: i32 = 108;
const DLT_RAW_BSD: i32 = 12;
const DLT_RAW_LINKTYPE: i32 = 101;
const DLT_LINUX_SLL: i32 = 113;
const DLT_LINUX_SLL2: i32 = 276;

impl LinkType {
    /// Maps a raw libpcap DLT number (as returned by `Capture::get_datalink`) onto a
    /// [`LinkType`].
    pub fn from_dlt(dlt: i32) -> Self {
        match dlt {
            DLT_EN10MB => LinkType::Ethernet,
            DLT_NULL | DLT_LOOP => LinkType::NullLoop,
            DLT_RAW_BSD | DLT_RAW_LINKTYPE => LinkType::Raw,
            DLT_LINUX_SLL => LinkType::LinuxSll,
            DLT_LINUX_SLL2 => LinkType::LinuxSll2,
            other => LinkType::Unsupported(other),
        }
    }
}

/// The don't-fragment and more-fragments bits within an IPv4 header's three-bit flags
/// field, as `pnet` returns it. The read-side mirror of
/// [`ipv4_flags`](crate::protocols::craft::ipv4_flags), kept separate because only the
/// writer may produce a wrong value on purpose.
const IPV4_DONT_FRAGMENT: u8 = 0b010;
const IPV4_MORE_FRAGMENTS: u8 = 0b001;

/// Strips `frame`'s link-layer header according to `link`, returning the IP packet
/// within, or `None` if the frame is too short, carries a non-IP payload (ARP on an
/// Ethernet link, a non-IP address family on a tunnel), or uses an unsupported link
/// type.
///
/// Every link type that carries a protocol label is held to it: the Ethernet arm reads
/// the EtherType, the tunnel arm the address-family word, and the cooked arms the
/// protocol field. Otherwise a `DLT_NULL` frame carrying something else would pass as
/// IP whenever its first nibble happened to be 4 or 6.
pub fn strip_to_ip(link: LinkType, frame: &[u8]) -> Option<&[u8]> {
    match link {
        LinkType::Ethernet => strip_ethernet(frame),
        LinkType::NullLoop => strip_null_loop(frame),
        LinkType::Raw => Some(frame),
        LinkType::LinuxSll => Cooked::sll(frame)?.ip_packet(),
        LinkType::LinuxSll2 => Cooked::sll2(frame)?.ip_packet(),
        LinkType::Unsupported(_) => None,
    }
}

/// What a Linux cooked pseudo-header says, from either version of it.
///
/// Linux writes one of these in place of a link header `libpcap` has no use for, as on
/// a PPP link. The two versions carry the same fields at different places and widths,
/// so each has its own constructor and everything after reads this.
///
/// # What is not read
///
/// The packet-type field, which says whether the frame arrived or left. A probe this
/// host sent is captured leaving on a cooked link as on every other link, and that is
/// wanted: a port scan admits both directions and counts its own probes leaving, which
/// is how it tells a silent port from one whose probe never reached the wire.
/// Discarding outgoing frames would make every probe through a PPP link look unsent.
struct Cooked<'a> {
    /// What the payload is. An EtherType on every link that carries IP.
    protocol: u16,
    /// The kernel's `ARPHRD_` value for the link, which says what kind of address
    /// [`address`](Self::address) holds.
    hardware_type: u16,
    /// How long the sender's address is, which may exceed the eight bytes the header
    /// has room for, or be zero.
    address_len: usize,
    /// The sender's address, padded or cut to eight bytes.
    address: &'a [u8; 8],
    /// Everything after the pseudo-header.
    payload: &'a [u8],
}

/// The kernel's `ARPHRD_` value for an Ethernet link: the one hardware type whose
/// cooked-header address this crate reads as a hardware address.
const ARPHRD_ETHER: u16 = 1;

impl<'a> Cooked<'a> {
    /// Reads a `DLT_LINUX_SLL` header: packet type, hardware type, address length,
    /// eight bytes of address, then the protocol, all in network order.
    fn sll(frame: &'a [u8]) -> Option<Self> {
        let (header, payload) = frame.split_first_chunk::<SLL_HDR_LEN>()?;
        Some(Self {
            hardware_type: u16::from_be_bytes([header[2], header[3]]),
            address_len: usize::from(u16::from_be_bytes([header[4], header[5]])),
            address: header[6..].first_chunk()?,
            protocol: u16::from_be_bytes([header[14], header[15]]),
            payload,
        })
    }

    /// Reads a `DLT_LINUX_SLL2` header: the protocol first, two reserved bytes, the
    /// interface index, the hardware type, then a one-byte packet type and a one-byte
    /// address length ahead of the same eight bytes of address.
    fn sll2(frame: &'a [u8]) -> Option<Self> {
        let (header, payload) = frame.split_first_chunk::<SLL2_HDR_LEN>()?;
        Some(Self {
            protocol: u16::from_be_bytes([header[0], header[1]]),
            hardware_type: u16::from_be_bytes([header[8], header[9]]),
            address_len: usize::from(header[11]),
            address: header[12..].first_chunk()?,
            payload,
        })
    }

    /// The IP packet behind the header, if the protocol field says it is one.
    fn ip_packet(&self) -> Option<&'a [u8]> {
        match EtherType(self.protocol) {
            EtherTypes::Ipv4 | EtherTypes::Ipv6 => Some(self.payload),
            _ => None,
        }
    }

    /// The sender's hardware address, where the header holds one.
    ///
    /// Only an Ethernet link's six bytes count. A PPP link or a tunnel reports no
    /// address, and any other hardware type's address is that link's own kind, which
    /// read as a MAC would be misnamed.
    fn hardware_address(&self) -> Option<MacAddr> {
        if self.hardware_type != ARPHRD_ETHER || self.address_len != 6 {
            return None;
        }
        let [a, b, c, d, e, f, _, _] = *self.address;
        Some(MacAddr::new(a, b, c, d, e, f))
    }
}

/// Reads the address-family word a `DLT_NULL`/`DLT_LOOP` link prepends and returns the
/// IP packet behind it, or `None` for a family this does not parse.
///
/// The word's byte order is not fixed, so it is read both ways. `DLT_NULL` writes the
/// host's own order, so a capture file means different things on different machines;
/// `DLT_LOOP` was defined later to settle that and writes network order. This crate
/// maps both to [`NullLoop`](LinkType::NullLoop).
///
/// Reading both ways is safe: the families involved are small numbers whose
/// byte-swapped forms are enormous, so no reading of one is a valid reading of another.
fn strip_null_loop(frame: &[u8]) -> Option<&[u8]> {
    let word = u32::from_ne_bytes(*frame.first_chunk::<NULL_LOOP_HDR_LEN>()?);
    if !IP_ADDRESS_FAMILIES.contains(&word) && !IP_ADDRESS_FAMILIES.contains(&word.swap_bytes()) {
        return None;
    }

    frame.get(NULL_LOOP_HDR_LEN..)
}

/// The address-family numbers a `DLT_NULL`/`DLT_LOOP` word may carry for an IP packet.
///
/// `AF_INET` is 2 everywhere. `AF_INET6` is 30 on macOS and the BSDs, 28 on FreeBSD,
/// 10 on Linux, and 24 on OpenBSD. A capture written on one machine may be read on
/// another, so all four are recognised.
const IP_ADDRESS_FAMILIES: [u32; 5] = [2, 30, 28, 10, 24];

/// Walks an Ethernet header, skipping any VLAN tags, and returns the payload only if
/// the EtherType marks it as IPv4 or IPv6.
///
/// The tag walk is [`ethernet::parse`]'s. A second copy could drift silently: one that
/// understood a single tag where the original understands a stack would discard every
/// double-tagged reply as though none had come.
fn strip_ethernet(frame: &[u8]) -> Option<&[u8]> {
    let parsed = ethernet::parse(frame).ok()?;
    match EtherType(parsed.ethertype()) {
        EtherTypes::Ipv4 | EtherTypes::Ipv6 => Some(parsed.payload()),
        _ => None,
    }
}

/// The hardware address a captured frame came from, where the link has one.
///
/// # What this is for
///
/// It answers whether a reply came from the host whose address it claims, which the
/// source IP cannot. Anything answering in a host's place (a transparent proxy, a DNS
/// interceptor, a firewall resetting on a host's behalf) uses that host's address, so
/// a forged answer's IP header is identical to a real one. On an on-link segment the
/// hardware address settles it.
///
/// It is a poor basis for vendor attribution. A reply from off-link carries the
/// last-hop router's address, indistinguishable here from the sender's, so an OUI
/// lookup would report the router's manufacturer as the host's. Vendor lookup belongs
/// to the on-link discovery path ([`crate::system::neighbor_cache`] and the local
/// scanner), which knows a neighbour is a neighbour.
///
/// `None` where there is nothing to read: a `DLT_NULL`/`DLT_LOOP` tunnel or loopback
/// link prepends only an address-family word, a `DLT_RAW` link prepends nothing, a
/// cooked header names a hardware address only for an Ethernet link, and a frame too
/// short for its header describes nothing. `None` does not mean the sender had no
/// hardware address.
pub fn source_mac(link: LinkType, frame: &[u8]) -> Option<MacAddr> {
    match link {
        // Offsets 0..6 destination, 6..12 source, then the EtherType. A VLAN tag sits
        // after both addresses, so this offset does not move for a tagged frame. A
        // tag-shifted read would land across the EtherType and the IP header and
        // yield a plausible-looking address.
        LinkType::Ethernet => Some(MacAddr::new(
            *frame.get(6)?,
            *frame.get(7)?,
            *frame.get(8)?,
            *frame.get(9)?,
            *frame.get(10)?,
            *frame.get(11)?,
        )),
        LinkType::LinuxSll => Cooked::sll(frame)?.hardware_address(),
        LinkType::LinuxSll2 => Cooked::sll2(frame)?.hardware_address(),
        LinkType::NullLoop | LinkType::Raw | LinkType::Unsupported(_) => None,
    }
}

/// One parsed IP packet: its endpoints, the Layer-4 protocol it carries, and that
/// Layer-4 segment.
///
/// The protocol travels with the bytes because a Layer-4 segment is not
/// self-describing. `UdpPacket::new` succeeds on any eight bytes, so an ICMP error read
/// as UDP yields a plausible but meaningless header.
///
/// Both endpoints are kept. A reply's source is who sent it, but an ICMP error's quoted
/// packet identifies the probe by its destination, and the router reporting the error
/// is not the host the probe was aimed at.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpSegment<'a> {
    /// Who sent the packet.
    pub source: IpAddr,
    /// Who it was addressed to.
    pub destination: IpAddr,
    /// The Layer-4 protocol [`payload`](Self::payload) is, read from the IPv4
    /// protocol field or the IPv6 next-header field.
    pub protocol: u8,
    /// The Layer-4 segment: the bytes after the IP header.
    pub payload: &'a [u8],
    /// What the rest of the IP header said about the stack that wrote it.
    ///
    /// The header is parsed only here; everything downstream sees a Layer-4 segment, so
    /// a field dropped here cannot be recovered. Three of these are among the cheapest
    /// identifying signals a reply carries, at six bytes to keep.
    pub observation: IpObservation,
}

/// Parses an IP packet into its endpoints, protocol, and Layer-4 segment, dispatching
/// on the version nibble so the link layer's label does not matter.
///
/// Returns `None` for a truncated packet, an implausible header length, an unknown IP
/// version, or an IPv6 chain that names no Layer-4 segment (see `walk_ipv6_headers`).
pub fn parse_ip_segment(ip_bytes: &[u8]) -> Option<IpSegment<'_>> {
    match ip_bytes.first()? >> 4 {
        4 => {
            let packet = Ipv4Packet::new(ip_bytes)?;
            // IHL is four bits of remote-chosen data. Anything below the fixed header
            // size would slice back into the header, overlapping the addresses.
            let header_len = packet.get_header_length() as usize * 4;
            if header_len < IP_V4_HDR_LEN {
                return None;
            }
            // Only the first fragment of a datagram carries the Layer-4 header; in any
            // other, what follows the IP header is the middle of a payload.
            // `walk_ipv6_headers` refuses the same on IPv6. The offset must be checked,
            // not just the flags: the last fragment does not set More Fragments.
            if packet.get_fragment_offset() != 0 {
                return None;
            }
            Some(IpSegment {
                source: IpAddr::V4(packet.get_source()),
                destination: IpAddr::V4(packet.get_destination()),
                protocol: packet.get_next_level_protocol().0,
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
                protocol: protocol.0,
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
/// No legitimate packet has a chain this long. Eight bounds the work per frame at a
/// constant.
const MAX_EXTENSION_HEADERS: usize = 8;

/// Follows an IPv6 next-header chain from `protocol` at `offset`, returning the
/// Layer-4 protocol and the offset its segment starts at.
///
/// The fixed header's next-header field is only the first link of a chain; each
/// extension header names the next. Read as the transport protocol, it would hand out
/// an extension header as a TCP or ICMPv6 segment that parses cleanly and means
/// nothing.
///
/// `None` where there is no Layer-4 segment: a chain that runs past the end of the
/// packet, one longer than [`MAX_EXTENSION_HEADERS`], an explicit no-next-header, or a
/// non-initial fragment, whose bytes are the middle of a datagram. Every length is read
/// from the packet and bounds-checked, because a remote host chooses these bytes, and a
/// hostile one in the packet quoted inside an ICMP error.
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
            // Explicitly nothing follows.
            Protocols::Ipv6NoNxt => return None,
            // The common shape: a next-header byte, a length in 8-octet units not
            // counting the first, then options.
            Protocols::Hopopt | Protocols::Ipv6Route | Protocols::Ipv6Opts => {
                (usize::from(*bytes.get(offset + 1)?) + 1) * 8
            }
            // The authentication header counts in 4-octet units and excludes two.
            Protocols::Ah => (usize::from(*bytes.get(offset + 1)?) + 2) * 4,
            // Fixed at eight bytes. Only the first fragment carries the Layer-4
            // header; in any other the offset is non-zero and what follows is payload.
            Protocols::Ipv6Frag => {
                let fragment_offset =
                    u16::from_be_bytes([*bytes.get(offset + 2)?, *bytes.get(offset + 3)?]) >> 3;
                if fragment_offset != 0 {
                    return None;
                }
                8
            }
            // Anything else is the Layer-4 protocol, including payloads (ESP) this
            // cannot see past.
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

/// [`strip_to_ip`] followed by [`parse_ip_segment`]: takes a captured frame and its
/// link type and yields the [`IpSegment`] within.
pub fn parse_captured_segment(link: LinkType, frame: &[u8]) -> Option<IpSegment<'_>> {
    parse_ip_segment(strip_to_ip(link, frame)?)
}

/// The [`IpSegment`] within a captured frame, and the hardware address the frame came
/// from where the link has one.
///
/// Both answers in one pass over the link header, for every frame a capture admits.
///
/// `None` on the same terms as [`parse_captured_segment`]. The source address is absent
/// for a link that carries none (see [`source_mac`]), which never refuses the segment.
pub fn parse_captured(link: LinkType, frame: &[u8]) -> Option<(IpSegment<'_>, Option<MacAddr>)> {
    let segment = parse_captured_segment(link, frame)?;
    Some((segment, source_mac(link, frame)))
}

/// Everything a frame needs except its payload: where it goes at both layers, what it
/// carries, and how far it may travel.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct FrameSpec {
    /// The sending interface's address, or a spoofed one.
    pub src_mac: MacAddr,
    /// The next hop's address on this segment.
    pub dst_mac: MacAddr,
    /// The source address written into the IP header. Must match the family of
    /// [`dst`](Self::dst).
    pub src: IpAddr,
    /// The destination address written into the IP header.
    pub dst: IpAddr,
    /// What the IP header says it carries, by its IANA number.
    pub protocol: u8,
    /// IPv4's TTL or IPv6's hop limit, so one caller decides it once for both. This
    /// backend builds the header and so honours it exactly; see
    /// [`Emission`](crate::transport::probe::Emission).
    pub hop_limit: u8,
}

/// Everything an IP packet needs except its payload, for a link with no hardware
/// addresses.
#[derive(Debug, Clone, Copy)]
pub(crate) struct IpSpec {
    /// The source address written into the IP header. Must match the family of
    /// [`dst`](Self::dst).
    pub(crate) src: IpAddr,
    /// The destination address written into the IP header.
    pub(crate) dst: IpAddr,
    /// What the IP header says it carries, by its IANA number.
    pub(crate) protocol: u8,
    /// IPv4's TTL or IPv6's hop limit; see [`FrameSpec::hop_limit`].
    pub(crate) hop_limit: u8,
}

impl FrameSpec {
    /// The IP half of this spec, which is a whole packet on a link with no link
    /// header.
    fn ip(&self) -> IpSpec {
        IpSpec {
            src: self.src,
            dst: self.dst,
            protocol: self.protocol,
            hop_limit: self.hop_limit,
        }
    }
}

/// The IP packets a probe becomes before any link header: the one datagram, or with
/// `mtu` set, one per fragment of at most `mtu` bytes. A datagram that already fits
/// `mtu` comes back whole.
///
/// [`build_ethernet_frame`], [`build_fragmented_ethernet_frames`] and
/// [`build_null_loop_frames`] put a link header in front of these, so a probe's IP is
/// built the same way on every link.
///
/// # Errors
///
/// Refuses a mismatched address pair, a payload longer than the length field holds,
/// and, through the two fragmenters, an MTU too small to carry a fragment or a datagram
/// larger than the family's offset field can address.
pub(crate) fn build_ip_packets(
    spec: &IpSpec,
    segment: &[u8],
    mtu: Option<u16>,
) -> Result<Vec<Vec<u8>>, PacketError> {
    let IpSpec {
        src,
        dst,
        protocol,
        hop_limit,
    } = *spec;

    if let Some(mtu) = mtu {
        return match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let header = craft::Ipv4 {
                    protocol: craft::Field::Exact(protocol),
                    ..craft::Ipv4::new(s, d).with_ttl(hop_limit)
                };
                ip::fragment_ipv4(&header, segment, mtu)
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                let header = craft::Ipv6 {
                    next_header: craft::Field::Exact(protocol),
                    ..craft::Ipv6::new(s, d).with_hop_limit(hop_limit)
                };
                ip::fragment_ipv6(&header, segment, mtu)
            }
            _ => Err(PacketError::FamilyMismatch { src, dst }),
        };
    }

    // Counted before the family is known, so the bound is the width of the field
    // alone.
    let payload_len = u16::try_from(segment.len())
        .map_err(|_| PacketError::too_long("an IP payload length", 0, segment.len()))?;
    let header = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            ip::build_ipv4_header(s, d, payload_len, protocol, hop_limit)?
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            ip::build_ipv6_header(s, d, payload_len, protocol, hop_limit)
        }
        _ => return Err(PacketError::FamilyMismatch { src, dst }),
    };
    let mut packet = Vec::with_capacity(header.len() + segment.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(segment);
    Ok(vec![packet])
}

/// The frames a probe becomes on a macOS loopback interface: each IP packet
/// [`build_ip_packets`] makes, behind the address-family word a `DLT_NULL` link
/// carries, in this machine's byte order.
///
/// The word uses macOS numbering (`AF_INET` 2, `AF_INET6` 30), since macOS is the one
/// platform whose loopback a frame is written to; see [`IP_ADDRESS_FAMILIES`] for the
/// others a capture reads. The sending handle marks its header complete, as it must for
/// an Ethernet frame to keep the source address it was built with, and a loopback
/// interface told that reads the family from the first four bytes. Without the word,
/// the kernel reads the IP header's first bytes as the family and drops the packet.
pub(crate) fn build_null_loop_frames(
    spec: &IpSpec,
    segment: &[u8],
    mtu: Option<u16>,
) -> Result<Vec<Vec<u8>>, PacketError> {
    const AF_INET: u32 = 2;
    const AF_INET6_MACOS: u32 = 30;
    let family = match spec.dst {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6_MACOS,
    };
    let packets = build_ip_packets(spec, segment, mtu)?;
    Ok(packets
        .into_iter()
        .map(|packet| [&family.to_ne_bytes()[..], &packet].concat())
        .collect())
}

/// Each of `packets` behind an Ethernet header from `src_mac` to `dst_mac`, labelled
/// with the family of `dst`.
fn behind_ethernet(
    packets: Vec<Vec<u8>>,
    src_mac: MacAddr,
    dst_mac: MacAddr,
    dst: IpAddr,
) -> Vec<Vec<u8>> {
    let ethertype = match dst {
        IpAddr::V4(_) => EtherTypes::Ipv4,
        IpAddr::V6(_) => EtherTypes::Ipv6,
    };
    let header = ethernet::build_header(src_mac, dst_mac, ethertype.0);
    packets
        .into_iter()
        .map(|packet| {
            let mut frame = Vec::with_capacity(ETH_HDR_LEN + packet.len());
            frame.extend_from_slice(&header);
            frame.extend_from_slice(&packet);
            frame
        })
        .collect()
}

/// Wraps a finished Layer-4 `segment` in IP and Ethernet headers, producing a frame
/// ready for a Layer-2 send.
///
/// The IP version comes from the spec's address pair, which must agree; a mismatch is
/// an error.
pub fn build_ethernet_frame(spec: &FrameSpec, segment: &[u8]) -> Result<Vec<u8>, PacketError> {
    let packets = build_ip_packets(&spec.ip(), segment, None)?;
    let frames = behind_ethernet(packets, spec.src_mac, spec.dst_mac, spec.dst);
    Ok(frames
        .into_iter()
        .next()
        .expect("an unfragmented packet is one"))
}

/// The Ethernet frames a probe becomes once its IP packet is split into fragments of at
/// most `mtu` bytes: one frame per fragment, in order.
///
/// The fragmenting counterpart of [`build_ethernet_frame`]. It builds the same packet,
/// splits it with [`ip::fragment_ipv4`] or [`ip::fragment_ipv6`], and wraps each
/// fragment in an Ethernet header.
///
/// IPv4 splits the header itself; IPv6 keeps its base header and carries the
/// fragmentation in an extension header. A datagram that already fits `mtu` comes back
/// as a single frame either way.
///
/// # Errors
///
/// Refuses a mismatched address pair, and, through the two fragmenters, an MTU too
/// small to carry a fragment or a datagram larger than the family's offset field can
/// address.
pub fn build_fragmented_ethernet_frames(
    spec: &FrameSpec,
    segment: &[u8],
    mtu: u16,
) -> Result<Vec<Vec<u8>>, PacketError> {
    let packets = build_ip_packets(&spec.ip(), segment, Some(mtu))?;
    Ok(behind_ethernet(
        packets,
        spec.src_mac,
        spec.dst_mac,
        spec.dst,
    ))
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

    /// A tunnel link labels what it carries, and the label is read.
    ///
    /// Skipping the four bytes unread would pass a non-IP frame on as IP whenever its
    /// first nibble happened to be 4 or 6. The Ethernet arm reads its EtherType the
    /// same way.
    #[test]
    fn a_tunnel_frame_is_held_to_the_family_it_names() {
        let packet = [
            0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 203, 0, 113, 1, 203, 0, 113, 2,
        ];

        // AF_INET is 2 on every platform, and a tunnel writes the word in the
        // capturing machine's byte order.
        for word in [2u32.to_ne_bytes(), 2u32.to_be_bytes(), 2u32.to_le_bytes()] {
            let frame = [&word[..], &packet[..]].concat();
            assert_eq!(
                strip_to_ip(LinkType::NullLoop, &frame),
                Some(&packet[..]),
                "an AF_INET frame was refused"
            );
        }

        // AF_INET6 differs by platform, and a capture may be read on a different
        // machine from the one that wrote it.
        for family in [30u32, 28, 10, 24] {
            let frame = [&family.to_ne_bytes()[..], &packet[..]].concat();
            assert_eq!(strip_to_ip(LinkType::NullLoop, &frame), Some(&packet[..]));
        }

        // A family this does not read is refused.
        for family in [1u32, 17, 0xDEAD_BEEF] {
            let frame = [&family.to_ne_bytes()[..], &packet[..]].concat();
            assert_eq!(
                strip_to_ip(LinkType::NullLoop, &frame),
                None,
                "address family {family} was read as an IP packet"
            );
        }

        // Too short to carry the word at all.
        assert_eq!(strip_to_ip(LinkType::NullLoop, &[0, 0, 0]), None);
    }

    /// A loopback frame's family word and packet are read back by a capture of that
    /// link, whole or in fragments, for both families.
    ///
    /// A frame whose word the loopback interface does not read as IP is dropped, which
    /// a scan sees as a port that never answered.
    #[test]
    fn a_loopback_frame_reads_back_as_the_packet_it_carries() {
        let payload = [0xABu8; 128];
        for (src, dst) in [
            (
                IpAddr::from(Ipv4Addr::LOCALHOST),
                IpAddr::from(Ipv4Addr::LOCALHOST),
            ),
            (
                IpAddr::from(Ipv6Addr::LOCALHOST),
                IpAddr::from(Ipv6Addr::LOCALHOST),
            ),
        ] {
            let spec = IpSpec {
                src,
                dst,
                protocol: TCP,
                hop_limit: 64,
            };
            for mtu in [None, Some(96)] {
                let frames = build_null_loop_frames(&spec, &payload, mtu).expect("the frames");
                assert_eq!(frames.len() > 1, mtu.is_some(), "{dst} at {mtu:?}");
                for frame in &frames {
                    let packet = strip_to_ip(LinkType::NullLoop, frame)
                        .unwrap_or_else(|| panic!("{dst} at {mtu:?}: the word was not read"));
                    assert_eq!(packet.len() + NULL_LOOP_HDR_LEN, frame.len());
                    assert_eq!(packet[0] >> 4, if dst.is_ipv4() { 4 } else { 6 });
                }
                let whole = strip_to_ip(LinkType::NullLoop, &frames[0]).expect("a packet");
                let segment = parse_ip_segment(whole).expect("an IP packet");
                assert_eq!((segment.source, segment.destination), (src, dst));
                if mtu.is_none() {
                    assert_eq!(segment.payload, &payload[..]);
                }
            }
        }
    }

    /// One walk of the link header answers both questions a receive path asks of a
    /// frame, with the same answers as the separate functions.
    #[test]
    fn one_pass_yields_the_segment_and_the_address_the_two_passes_did() {
        let mut frame = vec![
            0x02, 0, 0, 0, 0, 1, // destination
            0x02, 0, 0, 0, 0, 2, // source
            0x08, 0x00, // IPv4
        ];
        frame.extend_from_slice(&[
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 203, 0, 113, 1, 203, 0, 113, 2,
        ]);

        let (segment, mac) = parse_captured(LinkType::Ethernet, &frame).expect("a segment");
        assert_eq!(
            Some(segment),
            parse_captured_segment(LinkType::Ethernet, &frame)
        );
        assert_eq!(mac, source_mac(LinkType::Ethernet, &frame));
        assert_eq!(mac, Some(MacAddr::new(0x02, 0, 0, 0, 0, 2)));
    }
    use pnet_packet::ip::IpNextHeaderProtocols;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const TCP: u8 = IpNextHeaderProtocols::Tcp.0;

    #[test]
    fn dlt_mapping_covers_known_link_types() {
        assert_eq!(LinkType::from_dlt(1), LinkType::Ethernet);
        assert_eq!(LinkType::from_dlt(0), LinkType::NullLoop);
        assert_eq!(LinkType::from_dlt(108), LinkType::NullLoop);
        assert_eq!(LinkType::from_dlt(12), LinkType::Raw);
        assert_eq!(LinkType::from_dlt(101), LinkType::Raw);
        assert_eq!(LinkType::from_dlt(113), LinkType::LinuxSll);
        assert_eq!(LinkType::from_dlt(276), LinkType::LinuxSll2);
        assert_eq!(LinkType::from_dlt(999), LinkType::Unsupported(999));
    }

    /// Builds a minimal IPv4 packet carrying `payload` as its (opaque) L4.
    fn ipv4_packet(src: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        ip::build_ipv4_header(
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
        let header = ip::build_ipv6_header(
            src,
            Ipv6Addr::LOCALHOST,
            payload.len() as u16,
            IpNextHeaderProtocols::Udp.0,
            ip::HOP_LIMIT_ROUTED,
        );
        let packet: Vec<u8> = header.into_iter().chain(payload).collect();

        let parsed = parse_ip_segment(&packet).unwrap();
        assert_eq!(parsed.source, IpAddr::V6(src));
        assert_eq!(parsed.destination, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(parsed.protocol, IpNextHeaderProtocols::Udp.0);
        assert_eq!(parsed.payload, &payload);
    }

    /// The fields a stack is identified by, read from bytes laid out by hand from RFC
    /// 791.
    ///
    /// Literal bytes, because a fixture built with [`crate::protocols::craft`] would
    /// only check that this parser agrees with that builder. The offsets come from the
    /// specification, so a field read from the wrong place fails here.
    #[test]
    fn an_ipv4_header_yields_the_fields_its_stack_chose() {
        let mut packet = vec![0u8; IP_V4_HDR_LEN];
        packet[0] = 0x45; // version 4, 5-word header
        packet[1] = 0x8B; // DSCP 0b100010 = 34, ECN 0b11 = 3
        packet[2..4].copy_from_slice(&(IP_V4_HDR_LEN as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&0xBEEFu16.to_be_bytes()); // identification
        packet[6] = 0x40; // don't-fragment set, more-fragments clear
        packet[8] = 57; // TTL
        packet[9] = TCP;

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

    /// A fragment that is not the first carries no Layer-4 header, so there is no
    /// segment to hand out.
    ///
    /// The bytes after its header are the middle of a payload. And
    /// [`IpObservation::is_fragment`] answers from the More Fragments bit, which the
    /// last fragment does not set, so reading the flags alone would report the last
    /// piece as whole. `os_series` reads that flag before folding a reply's IP
    /// identifier into a sequence.
    #[test]
    fn a_later_ipv4_fragment_is_not_a_segment() {
        let fragment = |flag_and_offset: u16| {
            let mut packet = vec![0u8; IP_V4_HDR_LEN + 8];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&((IP_V4_HDR_LEN + 8) as u16).to_be_bytes());
            packet[6..8].copy_from_slice(&flag_and_offset.to_be_bytes());
            packet[9] = TCP;
            packet
        };

        // A middle fragment: more-fragments set, offset past the start.
        assert!(parse_ip_segment(&fragment(0b0010_0000_0000_0000 | 185)).is_none());
        // And the last one, which sets no flag and which the More Fragments bit
        // cannot see.
        assert!(parse_ip_segment(&fragment(185)).is_none());

        // The first fragment does carry a header, and parses.
        let first_bytes = fragment(0b0010_0000_0000_0000);
        let first =
            parse_ip_segment(&first_bytes).expect("the first fragment holds the Layer-4 header");
        assert!(
            first.observation.is_fragment(),
            "the first fragment says it is one"
        );

        // A whole datagram is not a fragment, the other half of what `is_fragment`
        // must get right.
        let whole_bytes = fragment(0);
        let whole = parse_ip_segment(&whole_bytes).expect("a whole datagram");
        assert!(!whole.observation.is_fragment());
    }

    /// Don't-fragment and more-fragments are adjacent bits of one three-bit field, and
    /// swapping them is invisible: both readings parse and the only symptom is a stack
    /// rule that never matches. This pins each bit to its RFC 791 meaning.
    #[test]
    fn the_two_fragment_bits_are_not_each_other() {
        let observe = |flag_byte: u8| {
            let mut packet = vec![0u8; IP_V4_HDR_LEN];
            packet[0] = 0x45;
            packet[6] = flag_byte;
            packet[9] = TCP;
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

    /// Traffic class and flow label share a 32-bit word with the version nibble and
    /// neither is byte-aligned, so both are easy to read one nibble off. Hand-laid
    /// bytes per RFC 8200.
    #[test]
    fn an_ipv6_header_yields_the_fields_across_its_first_word() {
        let mut packet = vec![0u8; IP_V6_HDR_LEN];
        // version 6, traffic class 0x8B, flow label 0x12345.
        packet[0..4].copy_from_slice(&0x68B1_2345u32.to_be_bytes());
        packet[6] = TCP;
        packet[7] = 57; // hop limit

        let IpObservation::V6(observed) = parse_ip_segment(&packet).unwrap().observation else {
            panic!("an IPv6 packet observes an IPv6 header");
        };

        assert_eq!(observed.hop_limit, 57);
        assert_eq!(observed.traffic_class, 0x8B);
        assert_eq!(observed.flow_label, 0x12345);
    }

    /// A header length below the fixed 20 bytes would slice back into the header.
    /// Remote hosts choose this field inside a quoted ICMP packet, so it is rejected.
    #[test]
    fn implausible_ipv4_header_length_is_rejected() {
        let mut packet = ipv4_packet(Ipv4Addr::new(203, 0, 113, 1), &[1, 2, 3, 4]);
        // Version 4, IHL 3 (12 bytes, shorter than the fixed header).
        packet[0] = 0x43;
        assert!(parse_ip_segment(&packet).is_none());
    }

    #[test]
    fn null_loop_link_strips_four_byte_family_word() {
        let payload = [9, 9, 9, 9];
        let packet = ipv4_packet(Ipv4Addr::new(203, 0, 113, 1), &payload);
        // macOS AF_INET word (host byte order), immaterial to the parser.
        let mut framed = vec![2, 0, 0, 0];
        framed.extend_from_slice(&packet);

        let parsed = parse_captured_segment(LinkType::NullLoop, &framed).unwrap();
        assert_eq!(parsed.source, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
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

        // The rebuilt frame round-trips back to source and payload; compare the
        // segment.
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
    fn fragmenting_wraps_each_ipv6_fragment_in_its_own_ethernet_frame() {
        use pnet_packet::Packet;
        use pnet_packet::ipv6::{FragmentPacket, Ipv6Packet};

        let mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let src = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let dst = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
        let segment: Vec<u8> = (0..40u8).collect();
        // Sixteen payload bytes per fragment on top of the base and fragment
        // headers, so forty do not fit one.
        let mtu = (IP_V6_HDR_LEN + 8 + 16) as u16;

        let frames = build_fragmented_ethernet_frames(
            &FrameSpec {
                src_mac: mac,
                dst_mac: mac,
                src,
                dst,
                protocol: TCP,
                hop_limit: ip::HOP_LIMIT_ROUTED,
            },
            &segment,
            mtu,
        )
        .expect("an IPv6 segment fragments");
        assert!(
            frames.len() > 1,
            "40 bytes should not fit one 16-byte fragment"
        );

        let mut reassembled = Vec::new();
        for frame in &frames {
            assert_eq!(
                &frame[12..14],
                &[0x86, 0xDD],
                "each frame is an IPv6 Ethernet frame"
            );
            let ip_bytes = &frame[ETH_HDR_LEN..];
            assert!(
                ip_bytes.len() <= usize::from(mtu),
                "each fragment fits the MTU"
            );

            let packet = Ipv6Packet::new(ip_bytes).expect("a v6 packet");
            assert_eq!(
                packet.get_next_header(),
                IpNextHeaderProtocols::Ipv6Frag,
                "the base header points at the fragment extension header"
            );
            let fragment = FragmentPacket::new(packet.payload()).expect("a fragment header");
            assert_eq!(
                fragment.get_next_header().0,
                TCP,
                "the fragment header carries the upper-layer protocol"
            );
            // pnet models the fragment header's own payload as zero-length, so the
            // piece is the base-header payload past the eight-byte extension.
            reassembled.extend_from_slice(&packet.payload()[8..]);
        }
        assert_eq!(
            reassembled, segment,
            "the fragments reassemble to the original segment"
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

    /// The addresses sit before the EtherType, so a VLAN tag does not move them,
    /// though it moves the payload offset. A tag-shifted read lands across the
    /// EtherType and the IP header and yields a plausible address, so both framings
    /// are tested.
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

    /// A link that prepends no addresses has none to report, which is not the same as
    /// the sender having none. Each of these carries IP traffic this engine captures,
    /// so each must answer `None` without reading six bytes of an IP header.
    #[test]
    fn a_link_without_hardware_addresses_reports_none() {
        let packet = ipv4_packet(Ipv4Addr::new(203, 0, 113, 1), &[1, 2, 3, 4]);

        // A tunnel or loopback link prepends a four-byte address-family word.
        let mut framed = vec![2, 0, 0, 0];
        framed.extend_from_slice(&packet);
        assert!(source_mac(LinkType::NullLoop, &framed).is_none());

        // A raw-IP link prepends nothing at all.
        assert!(source_mac(LinkType::Raw, &packet).is_none());

        assert!(source_mac(LinkType::Unsupported(42), &packet).is_none());

        // Too short to hold an Ethernet header. Reading past it would panic on a
        // frame chosen by whoever is on the wire.
        assert!(source_mac(LinkType::Ethernet, &[0u8; 8]).is_none());
    }

    #[test]
    fn unsupported_link_yields_nothing() {
        let frame = [0u8; 32];
        assert!(parse_captured_segment(LinkType::Unsupported(42), &frame).is_none());
    }

    // ─── Linux cooked capture ────────────────────────────────────────────────

    /// The data-link types `libpcap` reports for a cooked capture, as `pcap/dlt.h`
    /// numbers them. Written out here so a wrong constant in the module fails against
    /// these.
    const DLT_SLL: i32 = 113;
    const DLT_SLL2: i32 = 276;

    /// The packet types a cooked header carries, from `pcap/sll.h`, which takes them
    /// from the kernel's `PACKET_` values.
    const TO_US: u8 = 0;
    const FROM_US: u8 = 4;

    /// Hardware types, the kernel's `ARPHRD_` values: an Ethernet link, a PPP link,
    /// and a GRE tunnel.
    const ARPHRD_ETHER: u16 = 1;
    const ARPHRD_PPP: u16 = 512;
    const ARPHRD_IPGRE: u16 = 778;

    /// An IPv4 packet from 203.0.113.1 to 203.0.113.2 carrying an empty TCP payload,
    /// laid out by hand.
    const COOKED_V4: [u8; 20] = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 203, 0, 113, 1, 203, 0, 113, 2,
    ];

    /// An IPv6 packet from 2001:db8::1 to 2001:db8::2 carrying an empty TCP payload,
    /// laid out by hand.
    const COOKED_V6: [u8; 40] = [
        0x60, 0, 0, 0, 0, 0, 6, 64, // version, no payload length, TCP, hop limit
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // source
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, // destination
    ];

    /// A cooked frame of either version carrying `payload`, with its header laid out by
    /// hand from `pcap/sll.h`.
    ///
    /// The two versions hold the same fields at different places and widths:
    ///
    /// ```text
    /// SLL,  16 bytes: packet type (2) · hardware type (2) · address length (2)
    ///                 · address (8) · protocol (2)
    /// SLL2, 20 bytes: protocol (2) · reserved (2) · interface index (4)
    ///                 · hardware type (2) · packet type (1)
    ///                 · address length (1) · address (8)
    /// ```
    ///
    /// Every multi-byte field is in network order. The address is padded to eight
    /// bytes whatever its length says.
    fn cooked(
        dlt: i32,
        packet_type: u8,
        hardware_type: u16,
        address: &[u8],
        protocol: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut padded = [0u8; 8];
        padded[..address.len()].copy_from_slice(address);
        let address_len = address.len() as u8;

        let mut frame = Vec::new();
        match dlt {
            DLT_SLL => {
                frame.extend_from_slice(&u16::from(packet_type).to_be_bytes());
                frame.extend_from_slice(&hardware_type.to_be_bytes());
                frame.extend_from_slice(&u16::from(address_len).to_be_bytes());
                frame.extend_from_slice(&padded);
                frame.extend_from_slice(&protocol.to_be_bytes());
                assert_eq!(frame.len(), 16);
            }
            DLT_SLL2 => {
                frame.extend_from_slice(&protocol.to_be_bytes());
                frame.extend_from_slice(&[0, 0]);
                frame.extend_from_slice(&7u32.to_be_bytes());
                frame.extend_from_slice(&hardware_type.to_be_bytes());
                frame.push(packet_type);
                frame.push(address_len);
                frame.extend_from_slice(&padded);
                assert_eq!(frame.len(), 20);
            }
            other => panic!("{other} is not a cooked data-link type"),
        }
        frame.extend_from_slice(payload);
        frame
    }

    /// A PPP or tunnel link gives `libpcap` no usable header, so Linux writes its own,
    /// and behind it is the IP packet the protocol field names, in both families and
    /// both header versions.
    #[test]
    fn a_cooked_frame_yields_the_ip_packet_its_protocol_field_names() {
        for dlt in [DLT_SLL, DLT_SLL2] {
            let link = LinkType::from_dlt(dlt);
            for (protocol, packet, source) in [
                (0x0800, &COOKED_V4[..], IpAddr::from([203, 0, 113, 1])),
                (0x86DD, &COOKED_V6[..], "2001:db8::1".parse().unwrap()),
            ] {
                let frame = cooked(dlt, TO_US, ARPHRD_PPP, &[], protocol, packet);
                assert_eq!(
                    strip_to_ip(link, &frame),
                    Some(packet),
                    "data-link type {dlt} did not yield the packet behind protocol {protocol:#06x}"
                );
                let segment = parse_captured_segment(link, &frame).expect("a segment");
                assert_eq!(segment.source, source);
            }
        }
    }

    /// A probe this host sent is read off a cooked link exactly as an arriving answer
    /// is, as on every other link.
    ///
    /// A port scan admits both directions and counts its own probes leaving, to tell a
    /// silent port from one whose probe never reached the wire. Dropping outgoing
    /// frames by packet type would make every probe through a PPP link look unsent and
    /// every port behind it unasked.
    #[test]
    fn a_probe_leaving_a_cooked_link_is_read_like_an_answer_arriving() {
        for dlt in [DLT_SLL, DLT_SLL2] {
            let link = LinkType::from_dlt(dlt);
            let arriving = cooked(dlt, TO_US, ARPHRD_PPP, &[], 0x0800, &COOKED_V4);
            let leaving = cooked(dlt, FROM_US, ARPHRD_PPP, &[], 0x0800, &COOKED_V4);

            assert_eq!(strip_to_ip(link, &leaving), Some(&COOKED_V4[..]));
            assert_eq!(
                parse_captured(link, &leaving),
                parse_captured(link, &arriving)
            );
        }
    }

    /// The protocol field is read, as the EtherType and the address-family word are on
    /// other links, so a cooked frame carrying something other than IP is refused even
    /// if its first nibble is 4 or 6. A frame too short for its header describes
    /// nothing.
    #[test]
    fn a_cooked_frame_carrying_anything_but_ip_is_refused() {
        for dlt in [DLT_SLL, DLT_SLL2] {
            let link = LinkType::from_dlt(dlt);

            // ARP, an 802.2 frame without an EtherType, and nothing at all. Each
            // carries a well-formed IPv4 packet, so only the field refuses it.
            let sender = [0x02, 0, 0, 0, 0, 1];
            for protocol in [0x0806, 0x0004, 0x0000] {
                let frame = cooked(dlt, TO_US, ARPHRD_ETHER, &sender, protocol, &COOKED_V4);
                assert_eq!(
                    strip_to_ip(link, &frame),
                    None,
                    "data-link type {dlt} read protocol {protocol:#06x} as IP"
                );
            }

            let whole = cooked(dlt, TO_US, ARPHRD_PPP, &[], 0x0800, &[]);
            assert!(strip_to_ip(link, &whole).is_some());
            for cut in 0..whole.len() {
                assert_eq!(
                    strip_to_ip(link, &whole[..cut]),
                    None,
                    "data-link type {dlt} read a {cut}-byte header"
                );
            }
        }
    }

    /// A cooked header names the address the frame came from and what kind of address
    /// it is. Only an Ethernet link's six bytes are a hardware address. A PPP link has
    /// none, and any other hardware type's address is that link's own kind.
    #[test]
    fn a_cooked_frame_names_a_hardware_address_only_where_its_header_says_it_holds_one() {
        let sender = [0x02, 0, 0, 0, 0, 0x2A];
        for dlt in [DLT_SLL, DLT_SLL2] {
            let link = LinkType::from_dlt(dlt);

            let ethernet = cooked(dlt, TO_US, ARPHRD_ETHER, &sender, 0x0800, &COOKED_V4);
            assert_eq!(
                source_mac(link, &ethernet),
                Some(MacAddr::new(0x02, 0, 0, 0, 0, 0x2A)),
                "data-link type {dlt} lost an Ethernet sender's address"
            );
            let (_, mac) = parse_captured(link, &ethernet).expect("a segment");
            assert_eq!(mac, source_mac(link, &ethernet));

            for (hardware_type, address) in [
                (ARPHRD_PPP, &[][..]),
                (ARPHRD_IPGRE, &[198, 51, 100, 1][..]),
                // An Ethernet link claiming an address of the wrong length is not read.
                (ARPHRD_ETHER, &[0x02, 0, 0, 0, 0, 0x2A, 0, 0][..]),
            ] {
                let frame = cooked(dlt, TO_US, hardware_type, address, 0x0800, &COOKED_V4);
                assert_eq!(
                    source_mac(link, &frame),
                    None,
                    "data-link type {dlt} read hardware type {hardware_type} as an Ethernet address"
                );
            }

            assert_eq!(source_mac(link, &ethernet[..11]), None);
        }
    }

    /// Checks the tests above against something outside this crate.
    ///
    /// Their frames are hand-laid from `pcap/sll.h`, and a parser agreeing with a
    /// fixture written from the same understanding proves only that the two agree.
    /// `libpcap` compiles `ip` and `ip6` for a cooked link to a read of the protocol
    /// field at the offset it knows, so its own program admitting each frame for its
    /// family and refusing it for the other pins the layout to the library that writes
    /// these headers. The PPP header is also checked against bytes captured from a real
    /// link.
    #[test]
    fn libpcap_reads_the_protocol_where_these_cooked_frames_put_it() {
        for dlt in [DLT_SLL, DLT_SLL2] {
            let capture = pcap::Capture::dead(pcap::Linktype(dlt)).expect("a dead capture");
            let admits = |filter: &str, frame: &[u8]| {
                capture
                    .compile(filter, true)
                    .unwrap_or_else(|e| panic!("compiling `{filter}` for {dlt}: {e}"))
                    .filter(frame)
            };

            let v4 = cooked(dlt, TO_US, ARPHRD_PPP, &[], 0x0800, &COOKED_V4);
            let v6 = cooked(dlt, TO_US, ARPHRD_PPP, &[], 0x86DD, &COOKED_V6);
            assert!(admits("ip", &v4) && !admits("ip6", &v4), "{dlt}: IPv4");
            assert!(admits("ip6", &v6) && !admits("ip", &v6), "{dlt}: IPv6");
            assert!(
                admits("src host 203.0.113.1", &v4),
                "{dlt}: libpcap found the IPv4 header somewhere other than behind the pseudo-header"
            );
        }

        // The header built for a PPP link is, byte for byte, the one a Linux PPP link
        // was captured writing ahead of an outgoing IPv6 packet: sent by this host,
        // hardware type 512, no address.
        let captured = [0, 4, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x86, 0xDD];
        assert_eq!(
            cooked(DLT_SLL, FROM_US, ARPHRD_PPP, &[], 0x86DD, &[]),
            captured
        );
    }

    // ─── IPv6 extension headers ──────────────────────────────────────────────

    /// An IPv6 packet whose fixed header names `first`, followed by `chain`
    /// (encoded extension headers) and then `segment`.
    fn ipv6_chain(first: IpNextHeaderProtocol, chain: &[u8], segment: &[u8]) -> Vec<u8> {
        let payload_len = (chain.len() + segment.len()) as u16;
        ip::build_ipv6_header(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::LOCALHOST,
            payload_len,
            first.0,
            ip::HOP_LIMIT_ROUTED,
        )
        .into_iter()
        .chain(chain.iter().copied())
        .chain(segment.iter().copied())
        .collect()
    }

    /// One extension header in the common shape: next protocol, length in 8-octet
    /// units past the first, then padding to that length.
    fn extension(next: IpNextHeaderProtocol, units_past_first: u8) -> Vec<u8> {
        let mut header = vec![0u8; (usize::from(units_past_first) + 1) * 8];
        header[0] = next.0;
        header[1] = units_past_first;
        header
    }

    /// Read as the transport protocol, the fixed header's next-header field would hand
    /// a destination-options header to a caller expecting TCP, and `TcpPacket::new`
    /// accepts it, so nothing downstream could notice.
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

    /// A later fragment does not. Its bytes are the middle of a datagram, and handing
    /// them over as a TCP header invents a segment.
    #[test]
    fn a_later_fragment_yields_nothing() {
        let mut fragment = vec![0u8; 8];
        fragment[0] = IpNextHeaderProtocols::Tcp.0;
        // Fragment offset 185, in 8-octet units, shifted past the flag bits.
        fragment[2..4].copy_from_slice(&(185u16 << 3).to_be_bytes());
        let packet = ipv6_chain(IpNextHeaderProtocols::Ipv6Frag, &fragment, &[1, 2, 3, 4]);

        assert!(parse_ip_segment(&packet).is_none());
    }

    /// Remote-chosen lengths, each refused: a header claiming to extend past the
    /// packet, a chain long enough to be a denial of service, and an explicit end with
    /// nothing after it.
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

    /// A payload this cannot see past is reported as itself.
    #[test]
    fn an_encrypted_payload_is_reported_as_esp() {
        let packet = ipv6_chain(IpNextHeaderProtocols::Esp, &[], &[9, 9, 9, 9]);

        let parsed = parse_ip_segment(&packet).unwrap();
        assert_eq!(parsed.protocol, IpNextHeaderProtocols::Esp.0);
    }
}
