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
//! address-family word on a VPN `utun`/`tun` or loopback link, a 16-byte
//! pseudo-header Linux writes on a PPP link, or nothing at all on a raw-IP
//! link. [`strip_to_ip`] normalizes all of these down to the IP packet, and
//! [`parse_ip_segment`] then extracts the source address and the Layer-4
//! payload the scanners actually care about.
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

use pnet_base::MacAddr;
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

/// The subset of `pcap` data-link types this crate knows how to strip down to
/// an IP packet. Anything else is [`LinkType::Unsupported`] and the caller
/// must refuse to capture on that interface rather than misparse its frames.
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
    /// `DLT_LINUX_SLL`: a 16-byte pseudo-header Linux writes in place of a link
    /// header it will not hand over, naming what follows by EtherType.
    ///
    /// What `libpcap` opens a PPP link as, which is how a PPP VPN's tunnel is
    /// captured, and what it falls back to for any link whose hardware type it
    /// has no mapping for, GRE and IPv6 tunnels among them.
    LinuxSll,
    /// `DLT_LINUX_SLL2`: the 20-byte successor to [`LinuxSll`](Self::LinuxSll),
    /// the same fields reordered with the interface's index added.
    ///
    /// What `tcpdump -i any` writes. A capture of one named link comes up as
    /// [`LinuxSll`](Self::LinuxSll) unless it asks for this, so it reaches this
    /// crate in a capture somebody else took rather than in one of its own.
    LinuxSll2,
    /// A data-link type this crate can't parse; the numeric DLT is preserved
    /// for diagnostics.
    Unsupported(i32),
}

/// The width of the pseudo-header `DLT_NULL`/`DLT_LOOP` links prepend: a
/// single 32-bit address-family word.
const NULL_LOOP_HDR_LEN: usize = 4;

/// The width of the pseudo-header a `DLT_LINUX_SLL` link prepends.
///
/// Public to the crate for the capture's snapshot floor, which has to leave
/// room for the deepest link header this module strips.
pub(crate) const SLL_HDR_LEN: usize = 16;

/// The width of the pseudo-header a `DLT_LINUX_SLL2` link prepends. See
/// [`SLL_HDR_LEN`].
pub(crate) const SLL2_HDR_LEN: usize = 20;

// libpcap data-link type numbers. Kept local rather than pulled from a
// dependency so the mapping is auditable in one place.
const DLT_NULL: i32 = 0;
const DLT_EN10MB: i32 = 1;
const DLT_LOOP: i32 = 108;
const DLT_RAW_BSD: i32 = 12;
const DLT_RAW_LINKTYPE: i32 = 101;
const DLT_LINUX_SLL: i32 = 113;
const DLT_LINUX_SLL2: i32 = 276;

impl LinkType {
    /// Maps a raw libpcap DLT number (as returned by `Capture::get_datalink`)
    /// onto a [`LinkType`].
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

/// The don't-fragment and more-fragments bits within an IPv4 header's
/// three-bit flags field, as `pnet` hands it back. The mirror of
/// [`ipv4_flags`](crate::protocols::craft::ipv4_flags) on the send side, named
/// here rather than shared because reading a captured header and writing one
/// are different jobs and only one of them may write a value that is wrong.
const IPV4_DONT_FRAGMENT: u8 = 0b010;
const IPV4_MORE_FRAGMENTS: u8 = 0b001;

/// Strips `frame`'s link-layer header according to `link`, returning the IP
/// packet within, or `None` if the frame is too short, carries a non-IP
/// payload (ARP on an Ethernet link, a non-IP address family on a tunnel), or
/// rides an unsupported link type.
///
/// Every link type that carries a protocol label is held to it. The Ethernet
/// arm reads the EtherType, the tunnel arm reads the address-family word, and
/// the cooked arms read the protocol field. Skipped, the word would let a
/// `DLT_NULL` frame carrying something else through as an IP packet, refused
/// only if its first nibble happened not to be 4 or 6.
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
/// Linux writes one of these in place of a link header `libpcap` has no use
/// for, as on a PPP link. The two versions carry the same fields in different
/// places and at different widths, so each is read by its own constructor and
/// everything after that reads this.
///
/// # What is not read
///
/// The packet-type field, which says whether the frame arrived or left. A probe
/// this host sent is captured leaving on a cooked link just as it is on every
/// other link, and that is wanted rather than tolerated. A port scan admits
/// both directions and counts its own probes leaving, which is how it tells a
/// port that stayed silent from one whose probe never reached the wire, and it
/// tells the two directions apart by address. Discarding outgoing frames here
/// would make every probe through a PPP link look unsent.
struct Cooked<'a> {
    /// What the payload is. An EtherType on every link that carries IP.
    protocol: u16,
    /// The kernel's `ARPHRD_` value for the link, which is what says what kind
    /// of address [`address`](Self::address) holds.
    hardware_type: u16,
    /// How long the sender's address is, which may be more than the eight
    /// bytes the header has room for, or none at all.
    address_len: usize,
    /// The sender's address, padded or cut to eight bytes.
    address: &'a [u8; 8],
    /// Everything after the pseudo-header.
    payload: &'a [u8],
}

/// The kernel's `ARPHRD_` value for an Ethernet link: the one hardware type
/// whose address a cooked header's address field holds as a hardware address
/// this crate reads.
const ARPHRD_ETHER: u16 = 1;

impl<'a> Cooked<'a> {
    /// Reads a `DLT_LINUX_SLL` header: packet type, hardware type, address
    /// length, eight bytes of address, then the protocol, all in network order.
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

    /// Reads a `DLT_LINUX_SLL2` header: the protocol first, two reserved bytes,
    /// the interface index, the hardware type, then a one-byte packet type and
    /// a one-byte address length ahead of the same eight bytes of address.
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

    /// The sender's hardware address, where the header says it holds one.
    ///
    /// Only an Ethernet link's six bytes are one. A PPP link or a tunnel reports
    /// no address at all, and any other hardware type's address is that link's
    /// own notion of one, which six bytes read as a MAC would misname.
    fn hardware_address(&self) -> Option<MacAddr> {
        if self.hardware_type != ARPHRD_ETHER || self.address_len != 6 {
            return None;
        }
        let [a, b, c, d, e, f, _, _] = *self.address;
        Some(MacAddr::new(a, b, c, d, e, f))
    }
}

/// Reads the address-family word a `DLT_NULL`/`DLT_LOOP` link prepends and
/// returns the IP packet behind it, or `None` for a family this does not parse.
///
/// The word's byte order is not fixed, which is why this reads it both ways
/// rather than picking one. `DLT_NULL` writes the host's own order, so the same
/// capture file means different things on two machines; `DLT_LOOP` was defined
/// later precisely to settle that, and writes network order. `libpcap` reports
/// them as different link types and this crate maps both to
/// [`NullLoop`](LinkType::NullLoop), so the value has to be recognised whichever
/// way round it arrived.
///
/// That is safe to do rather than sloppy: the four families involved are small
/// numbers whose byte-swapped forms are enormous, so no reading of one is a
/// valid reading of another.
fn strip_null_loop(frame: &[u8]) -> Option<&[u8]> {
    let word = u32::from_ne_bytes(*frame.first_chunk::<NULL_LOOP_HDR_LEN>()?);
    if !IP_ADDRESS_FAMILIES.contains(&word) && !IP_ADDRESS_FAMILIES.contains(&word.swap_bytes()) {
        return None;
    }

    frame.get(NULL_LOOP_HDR_LEN..)
}

/// The address-family numbers a `DLT_NULL`/`DLT_LOOP` word may carry for an IP
/// packet.
///
/// `AF_INET` is 2 everywhere. `AF_INET6` is not: 30 on macOS and the BSDs, 28 on
/// FreeBSD, 10 on Linux, and 24 on OpenBSD. A tunnel link is read on whichever
/// of those wrote it, and a capture written on one machine may be read on
/// another, so all four are recognised rather than the running platform's alone.
const IP_ADDRESS_FAMILIES: [u32; 5] = [2, 30, 28, 10, 24];

/// Walks an Ethernet header, transparently skipping any VLAN tags, and returns
/// the payload only if the EtherType marks it as IPv4 or IPv6.
///
/// The tag walk is [`ethernet::parse`]'s rather than a second copy of it. It used
/// to be a copy here, and the copy understood one tag where the original
/// understands a stack, which is the ordinary way two implementations of one
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
/// It answers whether a reply came from the host whose address it claims, which
/// is a question the source IP structurally cannot answer. Anything answering in
/// a host's place, whether a transparent proxy, a DNS interceptor or a
/// firewall resetting on a host's behalf, uses that host's address, so the IP
/// header of a forged answer and a real one are identical. The hardware address
/// is not, and on an on-link segment it settles the matter outright.
///
/// It is a poor basis for vendor attribution, which is the use it looks like it
/// has. A reply from off-link carries the last-hop router's address rather than
/// the sender's, and the two are indistinguishable from here, so an OUI lookup
/// against this would confidently report the router's manufacturer as the host's.
/// Where a vendor is actually wanted, it belongs to the on-link discovery path
/// ([`crate::system::neighbor_cache`] and the local scanner), which knows a neighbour
/// is a neighbour.
///
/// `None` where there is genuinely nothing to read: a `DLT_NULL`/`DLT_LOOP`
/// tunnel or loopback link prepends an address-family word and no addresses at
/// all, a `DLT_RAW` link prepends nothing, a cooked header names a hardware
/// address only for an Ethernet link, and a frame too short to hold its header
/// describes nothing. `None` never means "the sender had no hardware address".
pub fn source_mac(link: LinkType, frame: &[u8]) -> Option<MacAddr> {
    match link {
        // Offsets 0..6 destination, 6..12 source, then the EtherType. A VLAN tag
        // sits after both addresses, so unlike the payload offset this one does
        // not move for a tagged frame. That is the mistake to avoid: a
        // tag-shifted read lands in the middle of the EtherType and the start of
        // the IP header and yields a plausible-looking address.
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
    /// field dropped at this line is not recoverable at any later one, and three
    /// of these are among the cheapest identifying signals a reply carries. They
    /// cost six bytes to keep and a second packet to re-obtain.
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
            // Only the first fragment of a fragmented datagram carries the
            // Layer-4 header a caller is looking for. In any other, what follows
            // the IP header is the middle of somebody's payload, and handing it
            // out is handing out a header full of plausible nonsense.
            // `walk_ipv6_headers` refuses the same thing on the other family.
            // Reading the flags and never the offset would let a non-initial
            // fragment through as a segment, with an `IpObservation` answering
            // `is_fragment()` from the More Fragments bit, which the *last*
            // fragment does not set.
            if packet.get_fragment_offset() != 0 {
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

/// The [`IpSegment`] within a captured frame, and the hardware address the frame
/// came from where the link has one.
///
/// The two answers a receive path wants from one frame, taken in one pass.
/// Asking for them separately walks the link header twice, once to reach the IP
/// packet and once to reach an address six bytes into the same header, for every
/// frame a capture admits.
///
/// `None` on the same terms [`parse_captured_segment`] is: the source address is
/// absent for a link that carries none (see [`source_mac`]) and never a reason to
/// refuse the segment.
pub fn parse_captured(link: LinkType, frame: &[u8]) -> Option<(IpSegment<'_>, Option<MacAddr>)> {
    let segment = parse_captured_segment(link, frame)?;
    Some((segment, source_mac(link, frame)))
}

/// Everything a frame needs except its payload: where it goes at both layers,
/// what it carries, and how far it may travel.
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
pub fn build_ethernet_frame(spec: &FrameSpec, segment: &[u8]) -> Result<Vec<u8>, PacketError> {
    let FrameSpec {
        src_mac,
        dst_mac,
        src,
        dst,
        protocol,
        hop_limit,
    } = *spec;
    // Counted before the family is known, so the header this will be added to
    // has no size yet and the bound is the width of the field alone.
    let payload_len = u16::try_from(segment.len())
        .map_err(|_| PacketError::too_long("an IP payload length", 0, segment.len()))?;

    let (ethertype, ip_header) = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (
            EtherTypes::Ipv4,
            ip::build_ipv4_header(s, d, payload_len, protocol, hop_limit)?,
        ),
        (IpAddr::V6(s), IpAddr::V6(d)) => (
            EtherTypes::Ipv6,
            ip::build_ipv6_header(s, d, payload_len, protocol, hop_limit),
        ),
        _ => return Err(PacketError::FamilyMismatch { src, dst }),
    };

    let mut frame = Vec::with_capacity(ETH_HDR_LEN + ip_header.len() + segment.len());
    frame.extend_from_slice(&ethernet::build_header(src_mac, dst_mac, ethertype));
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
/// Both families. IPv4 splits the header itself; IPv6 keeps its base header and
/// carries the fragmentation in an extension header, which
/// [`ip::fragment_ipv6`] builds. A datagram that already fits `mtu` comes back
/// as a single frame either way.
///
/// # Errors
///
/// Refuses a mismatched address pair, and, through the two fragmenters, an MTU
/// too small to carry a fragment or a datagram larger than the family's offset
/// field can address.
pub fn build_fragmented_ethernet_frames(
    spec: &FrameSpec,
    segment: &[u8],
    mtu: u16,
) -> Result<Vec<Vec<u8>>, PacketError> {
    let FrameSpec {
        src_mac,
        dst_mac,
        src,
        dst,
        protocol,
        hop_limit,
    } = *spec;

    let (packets, ethertype) = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let header = craft::Ipv4 {
                protocol: craft::Field::Exact(protocol),
                ..craft::Ipv4::new(s, d).with_ttl(hop_limit)
            };
            (ip::fragment_ipv4(&header, segment, mtu)?, EtherTypes::Ipv4)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let header = craft::Ipv6 {
                next_header: craft::Field::Exact(protocol),
                ..craft::Ipv6::new(s, d).with_hop_limit(hop_limit)
            };
            (ip::fragment_ipv6(&header, segment, mtu)?, EtherTypes::Ipv6)
        }
        _ => return Err(PacketError::FamilyMismatch { src, dst }),
    };

    let frames = packets
        .into_iter()
        .map(|packet| {
            let mut frame = Vec::with_capacity(ETH_HDR_LEN + packet.len());
            frame.extend_from_slice(&ethernet::build_header(src_mac, dst_mac, ethertype));
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

    /// A tunnel link labels what it carries, and the label is read.
    ///
    /// An arm skipping the four bytes without looking at them would hand a
    /// frame carrying something other than IP on as an IP packet, refused only
    /// where its first nibble happened not to be 4 or 6. The Ethernet arm
    /// beside it reads its EtherType the same way.
    #[test]
    fn a_tunnel_frame_is_held_to_the_family_it_names() {
        let packet = [
            0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 203, 0, 113, 1, 203, 0, 113, 2,
        ];

        // AF_INET is 2 on every platform, and a tunnel writes the word in
        // whichever order the machine that captured it uses.
        for word in [2u32.to_ne_bytes(), 2u32.to_be_bytes(), 2u32.to_le_bytes()] {
            let frame = [&word[..], &packet[..]].concat();
            assert_eq!(
                strip_to_ip(LinkType::NullLoop, &frame),
                Some(&packet[..]),
                "an AF_INET frame was refused"
            );
        }

        // AF_INET6 differs by platform, and a capture is read on whichever
        // machine happens to have it rather than the one that wrote it.
        for family in [30u32, 28, 10, 24] {
            let frame = [&family.to_ne_bytes()[..], &packet[..]].concat();
            assert_eq!(strip_to_ip(LinkType::NullLoop, &frame), Some(&packet[..]));
        }

        // And a family this does not read is refused rather than handed on.
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

    /// One walk of the link header answers both questions a receive path asks
    /// of a frame, and gives the same answers the two separate walks did.
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

    const TCP: IpNextHeaderProtocol = IpNextHeaderProtocols::Tcp;

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
    /// builder, which is two views of one understanding, the same shape of
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

    /// A fragment that is not the first carries no Layer-4 header, so there is
    /// no segment to hand out and this refuses to.
    ///
    /// The IPv6 path has refused the same thing since it was written, in
    /// `walk_ipv6_headers`, and this arm read the flags and never the offset.
    /// Two things came of that. The bytes after the header were handed out as a
    /// transport segment, when they are the middle of somebody's payload. And
    /// [`IpObservation::is_fragment`] answers with the More Fragments bit, which
    /// the *last* fragment does not set, so the one piece of a datagram whose
    /// segment fields belong to a different piece was the one piece reported as
    /// whole. `os_series` reads that flag before folding a reply's IP identifier
    /// into a sequence, which is the analysis a terminal fragment would have
    /// been admitted to.
    #[test]
    fn a_later_ipv4_fragment_is_not_a_segment() {
        let fragment = |flag_and_offset: u16| {
            let mut packet = vec![0u8; IP_V4_HDR_LEN + 8];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&((IP_V4_HDR_LEN + 8) as u16).to_be_bytes());
            packet[6..8].copy_from_slice(&flag_and_offset.to_be_bytes());
            packet[9] = TCP.0;
            packet
        };

        // A middle fragment: more-fragments set, offset past the start.
        assert!(parse_ip_segment(&fragment(0b0010_0000_0000_0000 | 185)).is_none());
        // And the last one, which sets no flag at all and is the case the More
        // Fragments bit cannot see.
        assert!(parse_ip_segment(&fragment(185)).is_none());

        // The first fragment does carry a header, and still parses.
        let first_bytes = fragment(0b0010_0000_0000_0000);
        let first =
            parse_ip_segment(&first_bytes).expect("the first fragment holds the Layer-4 header");
        assert!(
            first.observation.is_fragment(),
            "the first fragment says it is one"
        );

        // And a whole datagram is not a fragment, which is the other half of
        // what `is_fragment` has to get right.
        let whole_bytes = fragment(0);
        let whole = parse_ip_segment(&whole_bytes).expect("a whole datagram");
        assert!(!whole.observation.is_fragment());
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
        let mut packet = ipv4_packet(Ipv4Addr::new(203, 0, 113, 1), &[1, 2, 3, 4]);
        // Version 4, IHL 3 (12 bytes - shorter than the fixed header).
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
                fragment.get_next_header(),
                TCP,
                "the fragment header carries the upper-layer protocol"
            );
            // pnet models the fragment header's own payload as zero-length, so
            // the piece is the base-header payload past the eight-byte extension.
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
    /// unlike the payload offset which it does move. Reading them at a
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
        let packet = ipv4_packet(Ipv4Addr::new(203, 0, 113, 1), &[1, 2, 3, 4]);

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

    // ─── Linux cooked capture ────────────────────────────────────────────────

    /// The data-link types `libpcap` reports for a cooked capture, as
    /// `pcap/dlt.h` numbers them. Written out here rather than borrowed from the
    /// module, so a wrong constant there fails against these.
    const DLT_SLL: i32 = 113;
    const DLT_SLL2: i32 = 276;

    /// The packet types a cooked header carries, from `pcap/sll.h`, which
    /// takes them from the kernel's `PACKET_` values.
    const TO_US: u8 = 0;
    const FROM_US: u8 = 4;

    /// Hardware types, the kernel's `ARPHRD_` values: an Ethernet link, a PPP
    /// link, and a GRE tunnel.
    const ARPHRD_ETHER: u16 = 1;
    const ARPHRD_PPP: u16 = 512;
    const ARPHRD_IPGRE: u16 = 778;

    /// An IPv4 packet from 203.0.113.1 to 203.0.113.2 carrying an empty TCP
    /// payload, laid out by hand.
    const COOKED_V4: [u8; 20] = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 203, 0, 113, 1, 203, 0, 113, 2,
    ];

    /// An IPv6 packet from 2001:db8::1 to 2001:db8::2 carrying an empty TCP
    /// payload, laid out by hand.
    const COOKED_V6: [u8; 40] = [
        0x60, 0, 0, 0, 0, 0, 6, 64, // version, no payload length, TCP, hop limit
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // source
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, // destination
    ];

    /// A cooked frame of either version carrying `payload`, with its header laid
    /// out by hand from `pcap/sll.h` rather than by anything in this crate.
    ///
    /// The two versions hold the same fields in different places and at
    /// different widths, which is the whole reason there are two:
    ///
    /// ```text
    /// SLL,  16 bytes: packet type (2) · hardware type (2) · address length (2)
    ///                 · address (8) · protocol (2)
    /// SLL2, 20 bytes: protocol (2) · reserved (2) · interface index (4)
    ///                 · hardware type (2) · packet type (1)
    ///                 · address length (1) · address (8)
    /// ```
    ///
    /// Every multi-byte field is in network order. The address is padded to
    /// eight bytes whatever its length says.
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

    /// A PPP or tunnel link hands `libpcap` no header it can use, so Linux
    /// writes one of its own, and behind it is the IP packet the protocol field
    /// names, in both families and both versions of the header.
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

    /// A probe this host sent is read off a cooked link exactly as an answer
    /// arriving on it is, which is the same thing every other link does.
    ///
    /// The packet-type field would let the capture drop its own traffic, and
    /// dropping it would be a defect rather than a tidying. A port scan admits
    /// both directions on purpose and counts its own probes leaving: that is how
    /// it tells a port that stayed silent from one whose probe this machine
    /// never put on the wire. Discarded here, every probe through a PPP link
    /// would look unsent and every port behind it would be recorded unasked.
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

    /// The protocol field is read, as the EtherType and the address-family word
    /// are on the other links, so a cooked frame carrying something other than
    /// IP is refused rather than passed on because its first nibble happens to
    /// be 4 or 6. And a frame too short for its header describes nothing.
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

    /// A cooked header names the address the frame came from, and names what
    /// kind of address it is. Only an Ethernet link's six bytes are a hardware
    /// address. A PPP link has none, and an address any other hardware type
    /// reports is that link's own kind, which six bytes read as a MAC would
    /// misname.
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
                // An Ethernet link claiming an address of the wrong length is
                // not one to read six bytes of.
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

    /// The instrument for the tests above, checked against something outside
    /// this crate.
    ///
    /// The frames those tests build are hand-laid from `pcap/sll.h`, and a
    /// parser agreeing with a fixture written by the same understanding proves
    /// only that the two agree. `libpcap` compiles `ip` and `ip6` for a cooked
    /// link to a read of the protocol field at the offset it knows, so its own
    /// program admitting each frame for the family it carries, and refusing it
    /// for the other, pins the layout to the library that writes these headers.
    /// The PPP header is pinned to the wire as well, against bytes a real link
    /// was captured writing.
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

        // And the header built for a PPP link is, byte for byte, the one a
        // Linux PPP link was captured writing ahead of an IPv6 packet leaving
        // it: sent by this host, hardware type 512, no address.
        let captured = [0, 4, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x86, 0xDD];
        assert_eq!(
            cooked(DLT_SLL, FROM_US, ARPHRD_PPP, &[], 0x86DD, &[]),
            captured
        );
    }

    // ─── IPv6 extension headers ──────────────────────────────────────────────

    /// An IPv6 packet whose fixed header names `first`, followed by `chain`
    /// (already-encoded extension headers) and then `segment`.
    fn ipv6_chain(first: IpNextHeaderProtocol, chain: &[u8], segment: &[u8]) -> Vec<u8> {
        let payload_len = (chain.len() + segment.len()) as u16;
        ip::build_ipv6_header(
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
