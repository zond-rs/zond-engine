// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Building a packet field by field
//!
//! The other half of this module. [`tcp::build_probe`](super::tcp::build_probe)
//! and its neighbours build the handful of packets a scan needs, correctly and
//! with nothing to decide. This is for everything else: a packet you describe
//! yourself, layer by layer, including one that is deliberately wrong.
//!
//! ```
//! use zond_engine::protocols::craft::{Ipv4, Packet, Tcp, tcp_flags};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let bytes = Packet::new()
//!     .push(Ipv4::new("192.0.2.1".parse()?, "192.0.2.9".parse()?))
//!     .push(Tcp::new(50_000, 80).with_flags(tcp_flags::SYN))
//!     .build()?;
//! # assert_eq!(bytes.len(), 40);
//! # Ok(())
//! # }
//! ```
//!
//! ## One rule: [`Field`]
//!
//! A header has two kinds of field. Most are simply yours — a port, a TTL, a
//! flag. A few are *derived*: a length that counts what is inside, a checksum
//! computed over it, a protocol number naming the layer below. Those are the
//! interesting ones, because a scanner wants them right and somebody probing a
//! stack's error handling wants them wrong.
//!
//! Every derived field is a [`Field<T>`](Field), which is [`Computed`] by
//! default and [`Exact`] when you say otherwise:
//!
//! ```
//! use zond_engine::protocols::craft::{Field, Ipv4};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let src = "192.0.2.1".parse()?;
//! let dst = "192.0.2.9".parse()?;
//!
//! // The header a stack would accept.
//! let correct = Ipv4::new(src, dst);
//!
//! // The same header claiming to be shorter than it is, with a checksum that
//! // was never computed.
//! let wrong = Ipv4 {
//!     total_length: Field::Exact(4),
//!     checksum: Field::Exact(0),
//!     ..Ipv4::new(src, dst)
//! };
//! # let _ = (correct, wrong);
//! # Ok(())
//! # }
//! ```
//!
//! That is the whole of the malformed-packet story. There is no separate
//! "corrupt" API and no flag that turns validation off, because a packet with
//! one wrong field and nineteen right ones is what actually finds bugs in a
//! stack, and an all-or-nothing switch cannot express it.
//!
//! ## Why the fields are public
//!
//! Everywhere else in this crate a type hides its fields, because it has an
//! invariant worth protecting: a [`Host`](crate::model::host::Host)'s status
//! only ever climbs, a [`PortSet`](crate::model::port::PortSet) is always
//! canonical. A header has no such invariant. Being able to write a value that
//! is wrong *is the feature*, so there is nothing for an accessor to defend and
//! a great deal for it to get in the way of.
//!
//! So these are plain data: public fields, [`Default`], and functional update
//! syntax for the common case of changing one thing. The `with_*` methods are
//! there for chaining and do nothing a struct literal could not.
//!
//! ## What it costs
//!
//! Nothing the scanner pays. The presets are written in terms of these types,
//! so there is one implementation rather than two, but a preset knows its own
//! sizes and builds into an exact buffer; a [`Packet`] allocates per layer
//! because it cannot know what it is holding until it is asked to build.
//!
//! [`Computed`]: Field::Computed
//! [`Exact`]: Field::Exact

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pnet_base::MacAddr;
use pnet_packet::arp::{ArpHardwareTypes, ArpOperation, MutableArpPacket};
use pnet_packet::ethernet::{EtherType, EtherTypes, MutableEthernetPacket};
use pnet_packet::icmp::IcmpPacket;
use pnet_packet::icmpv6::Icmpv6Packet;
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet_packet::ipv4::{MutableIpv4Packet, checksum as ipv4_checksum};
use pnet_packet::ipv6::MutableIpv6Packet;
use pnet_packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet_packet::udp::{MutableUdpPacket, UdpPacket};

use crate::protocols::error::{PacketError, Result};
use crate::protocols::sizes::{
    ARP_LEN, ETH_HDR_LEN, ICMP_HDR_LEN, IP_V4_HDR_LEN, IP_V6_HDR_LEN, SCTP_COMMON_HDR_LEN,
    TCP_HDR_LEN, UDP_HDR_LEN,
};

/// TCP header flag bits, re-exported so a caller building a [`Tcp`] header does
/// not have to reach into the probe builders for them.
pub use crate::protocols::tcp::flags as tcp_flags;

/// A header field the builder can work out for itself, unless you would rather
/// it did not.
///
/// See the [module documentation](self) for what this is for. In short:
/// [`Computed`](Self::Computed) writes the value a conformant stack expects,
/// and [`Exact`](Self::Exact) writes precisely what you give it, wrong or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Field<T> {
    /// Work it out from the packet being built. The correct value.
    #[default]
    Computed,
    /// Write exactly this, whether or not it is correct.
    Exact(T),
}

impl<T> Field<T> {
    /// The value to write, given what the builder worked out.
    ///
    /// `computed` is evaluated only when it is needed, so a caller overriding a
    /// checksum does not pay for computing the one it is discarding.
    fn resolve(self, computed: impl FnOnce() -> T) -> T {
        match self {
            Self::Computed => computed(),
            Self::Exact(value) => value,
        }
    }

    /// Whether this field was given a value rather than left to the builder.
    pub const fn is_exact(&self) -> bool {
        matches!(self, Self::Exact(_))
    }

    /// The value, if one was given.
    pub fn exact(self) -> Option<T> {
        match self {
            Self::Computed => None,
            Self::Exact(value) => Some(value),
        }
    }
}

impl<T> From<T> for Field<T> {
    /// So `checksum: 0.into()` reads as well as `Field::Exact(0)`.
    fn from(value: T) -> Self {
        Self::Exact(value)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Headers
// ══════════════════════════════════════════════════════════════════════════════

/// An Ethernet II header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ethernet {
    /// The address the frame claims to come from.
    pub source: MacAddr,
    /// The address it is aimed at.
    pub destination: MacAddr,
    /// What the frame carries. Computed from the layer inside it.
    pub ethertype: Field<EtherType>,
}

impl Ethernet {
    /// A frame from `source` to `destination`, carrying whatever is pushed
    /// after it.
    pub fn new(source: MacAddr, destination: MacAddr) -> Self {
        Self {
            source,
            destination,
            ethertype: Field::Computed,
        }
    }

    /// Declares an ethertype rather than taking it from the layer inside.
    #[must_use]
    pub fn with_ethertype(mut self, ethertype: EtherType) -> Self {
        self.ethertype = Field::Exact(ethertype);
        self
    }

    /// This header alone. A caller that does not declare an
    /// [`ethertype`](Self::ethertype) and pushes nothing after it gets IPv4,
    /// since there is nothing to read one from.
    pub fn header_bytes(&self) -> Vec<u8> {
        write_ethernet(self, Vec::new(), None).expect("nothing here can overflow")
    }
}

/// An IPv4 header.
///
/// Twenty bytes plus whatever [`options`](Self::options) holds. The default
/// matches what this engine's own probes send: don't-fragment set, a random
/// identification, and a TTL of [`HOP_LIMIT_ROUTED`](super::ip::HOP_LIMIT_ROUTED).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4 {
    /// Where the packet claims to come from.
    pub source: Ipv4Addr,
    /// Where it is going.
    pub destination: Ipv4Addr,
    /// Differentiated services, six bits.
    pub dscp: u8,
    /// Explicit congestion notification, two bits.
    pub ecn: u8,
    /// The fragment identifier. Computed at random, which is what a stack does.
    pub identification: Field<u16>,
    /// The three-bit flags field. See [`ipv4_flags`].
    pub flags: u8,
    /// Where this fragment sits in the original datagram, in eight-byte units.
    pub fragment_offset: u16,
    /// How many hops the packet may cross.
    pub ttl: u8,
    /// What the packet carries. Computed from the layer pushed inside this one,
    /// and TCP where there is none: see [`header_bytes`](Self::header_bytes).
    pub protocol: Field<IpNextHeaderProtocol>,
    /// Header and payload together. Computed from the packet being built.
    pub total_length: Field<u16>,
    /// The header checksum. Computed over the finished header.
    pub checksum: Field<u16>,
    /// Header options, at most forty bytes and a whole number of four-byte
    /// words.
    ///
    /// Both bounds come from the header-length field, which is four bits
    /// counting words: fifteen of them, five of which the fixed header already
    /// takes. [`Packet::build`] refuses a run that breaks either, because the
    /// field wraps rather than saturating and a header that misdescribes itself
    /// is read as something else by every receiver.
    pub options: Vec<u8>,
}

/// IPv4 fragmentation flags, in the three-bit field
/// [`Ipv4::flags`] carries.
pub mod ipv4_flags {
    /// The packet may not be fragmented in transit.
    pub const DONT_FRAGMENT: u8 = 0b010;
    /// More fragments follow this one.
    pub const MORE_FRAGMENTS: u8 = 0b001;
}

impl Ipv4 {
    /// A header from `source` to `destination`, with every derived field left
    /// for the builder and the defaults this engine's probes use.
    pub fn new(source: Ipv4Addr, destination: Ipv4Addr) -> Self {
        Self {
            source,
            destination,
            dscp: 0,
            ecn: 0,
            identification: Field::Computed,
            flags: ipv4_flags::DONT_FRAGMENT,
            fragment_offset: 0,
            ttl: super::ip::HOP_LIMIT_ROUTED,
            protocol: Field::Computed,
            total_length: Field::Computed,
            checksum: Field::Computed,
            options: Vec::new(),
        }
    }

    /// Sets how many hops the packet may cross.
    #[must_use]
    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    /// Writes `checksum` instead of computing one.
    #[must_use]
    pub fn with_checksum(mut self, checksum: u16) -> Self {
        self.checksum = Field::Exact(checksum);
        self
    }

    /// Writes `total_length` instead of measuring the packet.
    #[must_use]
    pub fn with_total_length(mut self, total_length: u16) -> Self {
        self.total_length = Field::Exact(total_length);
        self
    }

    /// How long this header is once its options are counted.
    fn header_len(&self) -> usize {
        IP_V4_HDR_LEN + self.options.len()
    }

    /// This header alone, sized and checksummed for a packet carrying
    /// `payload_length` bytes after it.
    ///
    /// For a caller assembling the layers itself, which is what the transport
    /// does when it already holds a finished segment. [`Packet::build`] is the
    /// easier road when the payload is to hand.
    ///
    /// **Set [`protocol`](Self::protocol) before calling this.** There is no
    /// layer inside a header built on its own, so a `Computed` protocol has
    /// nothing to read and falls back to TCP. A caller holding a finished UDP
    /// segment and taking the default gets a header naming the wrong protocol,
    /// and the packet is dropped by the receiver rather than refused here.
    ///
    /// # Errors
    ///
    /// [`PacketError::TooLong`] when header and payload together exceed what
    /// the total-length field can describe.
    pub fn header_bytes(&self, payload_length: u16) -> Result<Vec<u8>> {
        let mut bytes = write_ipv4(self, Vec::new(), None)?;
        let total_length = match self.total_length {
            Field::Exact(value) => value,
            Field::Computed => (self.header_len() as u32 + u32::from(payload_length))
                .try_into()
                .map_err(|_| {
                    PacketError::too_long(
                        "the IPv4 total length",
                        self.header_len(),
                        payload_length as usize,
                    )
                })?,
        };

        // Rewritten and re-checksummed, because the length the header claims is
        // part of what the checksum covers.
        let mut ipv4 =
            MutableIpv4Packet::new(&mut bytes).expect("a header-sized buffer holds a header");
        ipv4.set_total_length(total_length);
        ipv4.set_checksum(0);
        let sum = self
            .checksum
            .resolve(|| ipv4_checksum(&ipv4.to_immutable()));
        ipv4.set_checksum(sum);
        Ok(bytes)
    }
}

/// An IPv6 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6 {
    /// Where the packet claims to come from.
    pub source: Ipv6Addr,
    /// Where it is going.
    pub destination: Ipv6Addr,
    /// Traffic class, eight bits.
    pub traffic_class: u8,
    /// The flow label, twenty bits. Computed at random.
    pub flow_label: Field<u32>,
    /// What follows this header. Computed from the layer pushed inside this one,
    /// and TCP where there is none: see [`header_bytes`](Self::header_bytes).
    pub next_header: Field<IpNextHeaderProtocol>,
    /// Everything after this header. Computed from the packet being built.
    pub payload_length: Field<u16>,
    /// How many hops the packet may cross. See
    /// [`HOP_LIMIT_ON_LINK`](super::ip::HOP_LIMIT_ON_LINK) and its neighbours
    /// for the three values that matter and why.
    pub hop_limit: u8,
}

impl Ipv6 {
    /// A header from `source` to `destination`, with the routed hop limit.
    pub fn new(source: Ipv6Addr, destination: Ipv6Addr) -> Self {
        Self {
            source,
            destination,
            traffic_class: 0,
            flow_label: Field::Computed,
            next_header: Field::Computed,
            payload_length: Field::Computed,
            hop_limit: super::ip::HOP_LIMIT_ROUTED,
        }
    }

    /// Sets how many hops the packet may cross.
    #[must_use]
    pub fn with_hop_limit(mut self, hop_limit: u8) -> Self {
        self.hop_limit = hop_limit;
        self
    }

    /// Writes `payload_length` instead of measuring the packet.
    #[must_use]
    pub fn with_payload_length(mut self, payload_length: u16) -> Self {
        self.payload_length = Field::Exact(payload_length);
        self
    }

    /// This header alone, declaring `payload_length` bytes after it. The IPv6
    /// counterpart of [`Ipv4::header_bytes`], and infallible for the reason
    /// that one is not: the field counts the payload rather than the total.
    ///
    /// **Set [`next_header`](Self::next_header) before calling this**, for the
    /// reason [`Ipv4::header_bytes`] gives about its own protocol field. A
    /// header built alone has no layer inside it to name.
    pub fn header_bytes(&self, payload_length: u16) -> Vec<u8> {
        let declared = Ipv6 {
            payload_length: Field::Exact(self.payload_length.resolve(|| payload_length)),
            ..self.clone()
        };
        write_ipv6(&declared, Vec::new(), None).expect("nothing here can overflow")
    }
}

/// A TCP header and whatever it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tcp {
    /// The port the segment claims to come from.
    pub source_port: u16,
    /// The port it is aimed at.
    pub destination_port: u16,
    /// The sequence number.
    pub sequence: u32,
    /// The acknowledgement number, meaningful only with
    /// [`ACK`](tcp_flags::ACK) set.
    pub acknowledgement: u32,
    /// The flag bits. See [`tcp_flags`].
    pub flags: u8,
    /// The receive window advertised.
    ///
    /// Defaults to 1024, which is what every probe this engine sends carries, so
    /// a hand-built segment is unremarkable beside them without having to say
    /// so. Read from `tcp`'s own constant rather than written twice.
    pub window: u16,
    /// The urgent pointer, meaningful only with [`URG`](tcp_flags::URG) set.
    pub urgent_pointer: u16,
    /// How long the header is, in four-byte words. Computed from the options.
    ///
    /// The field a stack uses to find the payload, so an exact value smaller
    /// than the real header makes the receiver read option bytes as data, and a
    /// larger one makes it read data as options.
    pub data_offset: Field<u8>,
    /// The checksum, over the segment and an IP pseudo-header. Computed.
    pub checksum: Field<u16>,
    /// Header options, as raw bytes: at most forty, and a whole number of
    /// four-byte words.
    ///
    /// The data offset is the same shape of field as IPv4's header length and
    /// carries the same bounds; see [`Ipv4::options`]. [`Packet::build`] refuses
    /// a run that breaks either.
    pub options: Vec<u8>,
    /// The segment's payload.
    pub payload: Vec<u8>,
}

impl Tcp {
    /// A bare segment from `source_port` to `destination_port`, with no flags
    /// set and every derived field left for the builder.
    pub fn new(source_port: u16, destination_port: u16) -> Self {
        Self {
            source_port,
            destination_port,
            sequence: 0,
            acknowledgement: 0,
            flags: 0,
            window: super::tcp::PROBE_WINDOW,
            urgent_pointer: 0,
            data_offset: Field::Computed,
            checksum: Field::Computed,
            options: Vec::new(),
            payload: Vec::new(),
        }
    }

    /// Sets the flag bits, replacing any already set. See [`tcp_flags`].
    #[must_use]
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    /// Sets the sequence number.
    #[must_use]
    pub fn with_sequence(mut self, sequence: u32) -> Self {
        self.sequence = sequence;
        self
    }

    /// Sets the acknowledgement number.
    #[must_use]
    pub fn with_acknowledgement(mut self, acknowledgement: u32) -> Self {
        self.acknowledgement = acknowledgement;
        self
    }

    /// Sets the receive window advertised.
    #[must_use]
    pub fn with_window(mut self, window: u16) -> Self {
        self.window = window;
        self
    }

    /// Writes `checksum` instead of computing one.
    #[must_use]
    pub fn with_checksum(mut self, checksum: u16) -> Self {
        self.checksum = Field::Exact(checksum);
        self
    }

    /// Attaches a payload.
    #[must_use]
    pub fn with_payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = payload.into();
        self
    }

    /// How long this header is once its options are counted.
    fn header_len(&self) -> usize {
        TCP_HDR_LEN + self.options.len()
    }

    /// This segment's bytes, checksummed against `addresses`.
    ///
    /// The addresses are a parameter because a TCP checksum covers a
    /// pseudo-header built from them, and a segment does not carry them. Pass
    /// `None` to leave the checksum zero, which is what a caller assembling a
    /// fragment to embed elsewhere wants.
    ///
    /// [`Packet::build`] calls this with the addresses of the IP layer it
    /// found. A preset that already knows them calls it directly and skips
    /// building a header it would only throw away.
    ///
    /// # Errors
    ///
    /// [`PacketError::FamilyMismatch`] when the two addresses are of different
    /// families.
    pub fn to_bytes(&self, addresses: Option<(IpAddr, IpAddr)>) -> Result<Vec<u8>> {
        write_tcp(self, Vec::new(), addresses)
    }

    /// The checksum this segment should carry against `addresses`, perturbed to
    /// one that is definitely wrong and never zero.
    ///
    /// Computes the correct checksum through the ordinary build, then corrupts
    /// it with [`corrupt_internet_checksum`]. Set the result on
    /// [`checksum`](Self::checksum) with [`Field::Exact`] to emit a segment a
    /// conformant host drops — so a reply to it came from something in the path
    /// rather than from the host. Computing the correct value first and
    /// perturbing it is what makes the result *guaranteed* wrong: an arbitrary
    /// number might, once in 2^16, be the checksum the segment actually needs.
    ///
    /// # Errors
    ///
    /// [`PacketError::FamilyMismatch`] when the two addresses are of different
    /// families, exactly as [`to_bytes`](Self::to_bytes) reports it.
    pub fn corrupt_checksum(&self, addresses: Option<(IpAddr, IpAddr)>) -> Result<u16> {
        let bytes = Tcp {
            checksum: Field::Computed,
            ..self.clone()
        }
        .to_bytes(addresses)?;
        let correct = TcpPacket::new(&bytes)
            .expect("a segment just built parses")
            .get_checksum();
        Ok(corrupt_internet_checksum(correct))
    }
}

/// A UDP header and whatever it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp {
    /// The port the datagram claims to come from.
    pub source_port: u16,
    /// The port it is aimed at.
    pub destination_port: u16,
    /// Header and payload together. Computed from the packet being built.
    pub length: Field<u16>,
    /// The checksum, over the datagram and an IP pseudo-header. Computed.
    ///
    /// Optional over IPv4 and mandatory over IPv6: RFC 8200 §8.1 requires a
    /// receiver to discard a zero-checksum datagram, so
    /// `Field::Exact(0)` over IPv6 builds something that never arrives.
    pub checksum: Field<u16>,
    /// The datagram's payload.
    pub payload: Vec<u8>,
}

impl Udp {
    /// A bare datagram from `source_port` to `destination_port`.
    pub fn new(source_port: u16, destination_port: u16) -> Self {
        Self {
            source_port,
            destination_port,
            length: Field::Computed,
            checksum: Field::Computed,
            payload: Vec::new(),
        }
    }

    /// Attaches a payload.
    #[must_use]
    pub fn with_payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = payload.into();
        self
    }

    /// Writes `checksum` instead of computing one.
    #[must_use]
    pub fn with_checksum(mut self, checksum: u16) -> Self {
        self.checksum = Field::Exact(checksum);
        self
    }

    /// This datagram's bytes, checksummed against `addresses`. The UDP
    /// counterpart of [`Tcp::to_bytes`], and the same rules apply.
    ///
    /// # Errors
    ///
    /// [`PacketError::FamilyMismatch`] when the two addresses are of different
    /// families, and [`PacketError::TooLong`] for a payload the length field
    /// cannot describe.
    pub fn to_bytes(&self, addresses: Option<(IpAddr, IpAddr)>) -> Result<Vec<u8>> {
        write_udp(self, Vec::new(), addresses)
    }
}

/// An SCTP packet: the twelve-byte common header and the chunks after it.
///
/// The one transport here whose checksum is not the internet checksum. SCTP
/// carries a CRC32c (RFC 3309, RFC 4960 §6.8) over the whole packet with no
/// pseudo-header, so unlike [`Tcp`] and [`Udp`] it depends on nothing outside
/// itself and [`to_bytes`](Self::to_bytes) takes no addresses.
///
/// Chunks are carried already encoded, in [`chunks`](Self::chunks): building an
/// INIT or any other chunk is [`sctp`](super::sctp)'s job, and this type owns
/// only the common header and the one derived field worth getting wrong on
/// purpose, the [`checksum`](Self::checksum).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sctp {
    /// The port the packet claims to come from.
    pub source_port: u16,
    /// The port it is aimed at.
    pub destination_port: u16,
    /// The association's verification tag, zero in a packet carrying an INIT
    /// (RFC 4960 §8.5.1).
    pub verification_tag: u32,
    /// The CRC32c over the whole packet. Computed, and written little-endian per
    /// RFC 4960 §6.8.
    pub checksum: Field<u32>,
    /// The chunks after the common header, already encoded.
    pub chunks: Vec<u8>,
}

impl Sctp {
    /// A bare packet from `source_port` to `destination_port`: verification tag
    /// zero, no chunks, checksum left for the builder.
    pub fn new(source_port: u16, destination_port: u16) -> Self {
        Self {
            source_port,
            destination_port,
            verification_tag: 0,
            checksum: Field::Computed,
            chunks: Vec::new(),
        }
    }

    /// Sets the verification tag.
    #[must_use]
    pub fn with_verification_tag(mut self, verification_tag: u32) -> Self {
        self.verification_tag = verification_tag;
        self
    }

    /// Attaches the already-encoded chunks after the common header.
    #[must_use]
    pub fn with_chunks(mut self, chunks: impl Into<Vec<u8>>) -> Self {
        self.chunks = chunks.into();
        self
    }

    /// Writes `checksum` instead of computing one.
    #[must_use]
    pub fn with_checksum(mut self, checksum: u32) -> Self {
        self.checksum = Field::Exact(checksum);
        self
    }

    /// This packet's bytes. The SCTP counterpart of [`Tcp::to_bytes`], and
    /// simpler: the CRC32c covers no pseudo-header, so there are no addresses to
    /// pass and nothing that can mismatch.
    pub fn to_bytes(&self) -> Vec<u8> {
        write_sctp(self, Vec::new())
    }
}

/// An ICMPv4 message.
///
/// The four bytes after the checksum mean different things to different message
/// types, so they are carried as [`rest_of_header`](Self::rest_of_header) rather
/// than named. [`echo_request`](Self::echo_request) fills them in for the one
/// type a scan sends; anything else is yours to lay out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv4 {
    /// The message type. 8 is an echo request, 0 an echo reply, 3 destination
    /// unreachable.
    pub icmp_type: u8,
    /// The code, whose meaning depends on the type.
    pub code: u8,
    /// The checksum, over the whole message. Computed.
    ///
    /// Unlike its IPv6 counterpart this covers the ICMP message alone, with no
    /// pseudo-header, so it does not depend on the addresses around it.
    pub checksum: Field<u16>,
    /// The four type-specific bytes between the checksum and the payload. An
    /// echo carries its identifier and sequence here.
    pub rest_of_header: [u8; 4],
    /// Whatever follows the header.
    pub payload: Vec<u8>,
}

impl Icmpv4 {
    /// An echo request carrying `identifier` and `sequence`.
    ///
    /// RFC 792 requires a reply to echo both back unchanged, which is what lets
    /// a scanner tell one of its own requests from another and both from
    /// somebody else's ping.
    pub fn echo_request(identifier: u16, sequence: u16) -> Self {
        Self::echo(ECHO_REQUEST_V4, identifier, sequence)
    }

    /// An echo reply carrying `identifier` and `sequence`.
    pub fn echo_reply(identifier: u16, sequence: u16) -> Self {
        Self::echo(ECHO_REPLY_V4, identifier, sequence)
    }

    fn echo(icmp_type: u8, identifier: u16, sequence: u16) -> Self {
        let [id_hi, id_lo] = identifier.to_be_bytes();
        let [seq_hi, seq_lo] = sequence.to_be_bytes();
        Self {
            icmp_type,
            code: 0,
            checksum: Field::Computed,
            rest_of_header: [id_hi, id_lo, seq_hi, seq_lo],
            payload: Vec::new(),
        }
    }

    /// Attaches a payload, which an echo reply is required to send back.
    #[must_use]
    pub fn with_payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = payload.into();
        self
    }

    /// Writes `checksum` instead of computing one.
    #[must_use]
    pub fn with_checksum(mut self, checksum: u16) -> Self {
        self.checksum = Field::Exact(checksum);
        self
    }

    /// Sets the code, whose meaning depends on the message type.
    ///
    /// Zero for a conformant echo, and a probe sending zero asks nothing a
    /// responder can differ about: see
    /// [`ECHO_PROBE_CODE`](super::icmp::ECHO_PROBE_CODE).
    #[must_use]
    pub fn with_code(mut self, code: u8) -> Self {
        self.code = code;
        self
    }

    /// This message's bytes.
    ///
    /// Takes no addresses, unlike [`Icmpv6::to_bytes`]: an ICMPv4 checksum
    /// covers the message alone.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = icmp_body(
            self.icmp_type,
            self.code,
            self.rest_of_header,
            &self.payload,
        );
        let sum = self.checksum.resolve(|| {
            let message = IcmpPacket::new(&bytes).expect("just written");
            pnet_packet::icmp::checksum(&message)
        });
        bytes[2..4].copy_from_slice(&sum.to_be_bytes());
        bytes
    }
}

/// An ICMPv6 message.
///
/// The IPv6 counterpart of [`Icmpv4`], with one difference that matters: its
/// checksum covers an IPv6 pseudo-header as well as the message, so it depends
/// on the addresses of the header around it. See [`to_bytes`](Self::to_bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv6 {
    /// The message type. 128 is an echo request, 129 an echo reply, 135 a
    /// neighbor solicitation.
    pub icmp_type: u8,
    /// The code, whose meaning depends on the type.
    pub code: u8,
    /// The checksum, over the message and an IPv6 pseudo-header. Computed.
    pub checksum: Field<u16>,
    /// The four type-specific bytes between the checksum and the payload.
    pub rest_of_header: [u8; 4],
    /// Whatever follows the header.
    pub payload: Vec<u8>,
}

impl Icmpv6 {
    /// An echo request carrying `identifier` and `sequence`.
    pub fn echo_request(identifier: u16, sequence: u16) -> Self {
        Self::echo(ECHO_REQUEST_V6, identifier, sequence)
    }

    /// An echo reply carrying `identifier` and `sequence`.
    pub fn echo_reply(identifier: u16, sequence: u16) -> Self {
        Self::echo(ECHO_REPLY_V6, identifier, sequence)
    }

    fn echo(icmp_type: u8, identifier: u16, sequence: u16) -> Self {
        let [id_hi, id_lo] = identifier.to_be_bytes();
        let [seq_hi, seq_lo] = sequence.to_be_bytes();
        Self {
            icmp_type,
            code: 0,
            checksum: Field::Computed,
            rest_of_header: [id_hi, id_lo, seq_hi, seq_lo],
            payload: Vec::new(),
        }
    }

    /// Attaches a payload.
    #[must_use]
    pub fn with_payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = payload.into();
        self
    }

    /// Writes `checksum` instead of computing one.
    #[must_use]
    pub fn with_checksum(mut self, checksum: u16) -> Self {
        self.checksum = Field::Exact(checksum);
        self
    }

    /// Sets the code, whose meaning depends on the message type.
    ///
    /// Zero for a conformant echo, and a probe sending zero asks nothing a
    /// responder can differ about: see
    /// [`ECHO_PROBE_CODE`](super::icmp::ECHO_PROBE_CODE).
    #[must_use]
    pub fn with_code(mut self, code: u8) -> Self {
        self.code = code;
        self
    }

    /// This message's bytes, checksummed against `addresses`.
    ///
    /// The addresses are required for a computed checksum and ignored for an
    /// exact one. `None` leaves a computed checksum zero, which over IPv6 is
    /// not merely wrong but fatal: RFC 4443 has no "no checksum" encoding, so a
    /// receiver discards it.
    ///
    /// # Errors
    ///
    /// [`PacketError::WrongFamily`] when both addresses are IPv4, which is an
    /// ICMPv6 message inside an IPv4 header and a packet nothing can build, and
    /// [`PacketError::FamilyMismatch`] when the two do not agree with each other
    /// at all.
    pub fn to_bytes(&self, addresses: Option<(IpAddr, IpAddr)>) -> Result<Vec<u8>> {
        let mut bytes = icmp_body(
            self.icmp_type,
            self.code,
            self.rest_of_header,
            &self.payload,
        );

        let sum = match self.checksum {
            Field::Exact(value) => value,
            Field::Computed => {
                let message = Icmpv6Packet::new(&bytes).expect("just written");
                match addresses {
                    None => 0,
                    Some((IpAddr::V6(src), IpAddr::V6(dst))) => {
                        pnet_packet::icmpv6::checksum(&message, &src, &dst)
                    }
                    // Not a family mismatch: the two may agree with each other
                    // and still not be IPv6, which is what an ICMPv6 layer
                    // inside an IPv4 header looks like from here.
                    Some((IpAddr::V4(src), IpAddr::V4(_))) => {
                        return Err(PacketError::WrongFamily {
                            protocol: "ICMPv6",
                            expected: "IPv6",
                            got: IpAddr::V4(src),
                        });
                    }
                    Some((src, dst)) => return Err(PacketError::FamilyMismatch { src, dst }),
                }
            }
        };
        bytes[2..4].copy_from_slice(&sum.to_be_bytes());
        Ok(bytes)
    }
}

/// An ICMP message with its checksum left zero, for either family.
///
/// The two share a layout — type, code, checksum, four type-specific bytes,
/// payload — and differ only in what the checksum covers.
fn icmp_body(icmp_type: u8, code: u8, rest_of_header: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ICMP_HDR_LEN + payload.len());
    bytes.push(icmp_type);
    bytes.push(code);
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&rest_of_header);
    bytes.extend_from_slice(payload);
    bytes
}

/// ICMPv4 echo request, RFC 792.
const ECHO_REQUEST_V4: u8 = 8;
/// ICMPv4 echo reply, RFC 792.
const ECHO_REPLY_V4: u8 = 0;
/// ICMPv6 echo request, RFC 4443.
const ECHO_REQUEST_V6: u8 = 128;
/// ICMPv6 echo reply, RFC 4443.
const ECHO_REPLY_V6: u8 = 129;

/// An ARP packet over Ethernet and IPv4.
///
/// Twenty-eight bytes with no payload, so nothing here is derived and every
/// field is simply yours. It is in this module anyway, because the interesting
/// ARP packets are the ones a preset would not build: a reply nobody asked for,
/// a request claiming an address that is not yours, a hardware length that does
/// not match the addresses beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arp {
    /// Request or reply. See [`arp_operations`].
    pub operation: u16,
    /// How long a hardware address is, in bytes. Six for Ethernet.
    pub hw_addr_len: u8,
    /// How long a protocol address is, in bytes. Four for IPv4.
    pub proto_addr_len: u8,
    /// The hardware address the sender claims.
    pub sender_hw_addr: MacAddr,
    /// The protocol address the sender claims.
    pub sender_proto_addr: Ipv4Addr,
    /// The hardware address being asked about. Undefined in a request, which
    /// is why a request conventionally leaves it zero.
    pub target_hw_addr: MacAddr,
    /// The protocol address being asked about.
    pub target_proto_addr: Ipv4Addr,
}

/// ARP operation codes, RFC 826.
pub mod arp_operations {
    /// Who holds this address?
    pub const REQUEST: u16 = 1;
    /// I do.
    pub const REPLY: u16 = 2;
}

impl Arp {
    /// A request asking who holds `target_proto_addr`.
    ///
    /// The target hardware address is left zero, which is what RFC 826 expects
    /// of a request and what every ordinary stack sends. Filling it with
    /// anything else is legal and makes the probe distinctive, which is the
    /// opposite of what a scan wants.
    pub fn request(
        sender_hw_addr: MacAddr,
        sender_proto_addr: Ipv4Addr,
        target_proto_addr: Ipv4Addr,
    ) -> Self {
        Self {
            operation: arp_operations::REQUEST,
            hw_addr_len: 6,
            proto_addr_len: 4,
            sender_hw_addr,
            sender_proto_addr,
            target_hw_addr: MacAddr::zero(),
            target_proto_addr,
        }
    }

    /// A reply announcing that `sender_hw_addr` holds `sender_proto_addr`.
    pub fn reply(
        sender_hw_addr: MacAddr,
        sender_proto_addr: Ipv4Addr,
        target_hw_addr: MacAddr,
        target_proto_addr: Ipv4Addr,
    ) -> Self {
        Self {
            operation: arp_operations::REPLY,
            hw_addr_len: 6,
            proto_addr_len: 4,
            sender_hw_addr,
            sender_proto_addr,
            target_hw_addr,
            target_proto_addr,
        }
    }

    /// Names the hardware address being asked about.
    ///
    /// Undefined in a request, which is why [`request`](Self::request) leaves it
    /// zero. A unicast request validating a cache entry sets it, so a host that
    /// has moved answers from a different address and the mismatch is what says
    /// the entry was stale.
    #[must_use]
    pub fn with_target_hw_addr(mut self, target_hw_addr: MacAddr) -> Self {
        self.target_hw_addr = target_hw_addr;
        self
    }

    /// This packet's bytes. Nothing here is derived, so nothing can fail.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; ARP_LEN];
        {
            let mut arp =
                MutableArpPacket::new(&mut bytes).expect("an ARP-sized buffer holds an ARP packet");
            arp.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp.set_protocol_type(EtherTypes::Ipv4);
            arp.set_hw_addr_len(self.hw_addr_len);
            arp.set_proto_addr_len(self.proto_addr_len);
            arp.set_operation(ArpOperation(self.operation));
            arp.set_sender_hw_addr(self.sender_hw_addr);
            arp.set_sender_proto_addr(self.sender_proto_addr);
            arp.set_target_hw_addr(self.target_hw_addr);
            arp.set_target_proto_addr(self.target_proto_addr);
        }
        bytes
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Stacking
// ══════════════════════════════════════════════════════════════════════════════

/// One header in a [`Packet`], outermost first.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer {
    /// An Ethernet II header.
    Ethernet(Ethernet),
    /// An IPv4 header.
    Ipv4(Ipv4),
    /// An IPv6 header.
    Ipv6(Ipv6),
    /// A TCP header and its payload.
    Tcp(Tcp),
    /// A UDP header and its payload.
    Udp(Udp),
    /// An SCTP packet and its chunks.
    Sctp(Sctp),
    /// An ICMPv4 message.
    Icmpv4(Icmpv4),
    /// An ICMPv6 message.
    Icmpv6(Icmpv6),
    /// An ARP packet.
    Arp(Arp),
    /// Bytes written exactly as given, for a protocol nothing here models yet.
    Raw(Vec<u8>),
}

macro_rules! layer_from {
    ($($variant:ident($ty:ty)),* $(,)?) => {
        $(impl From<$ty> for Layer {
            fn from(header: $ty) -> Self {
                Self::$variant(header)
            }
        })*
    };
}

layer_from!(
    Ethernet(Ethernet),
    Ipv4(Ipv4),
    Ipv6(Ipv6),
    Tcp(Tcp),
    Udp(Udp),
    Sctp(Sctp),
    Icmpv4(Icmpv4),
    Icmpv6(Icmpv6),
    Arp(Arp),
    Raw(Vec<u8>),
);

impl Layer {
    /// What an enclosing header should call this one, if it is computing its
    /// own protocol number.
    fn ip_protocol(&self) -> Option<IpNextHeaderProtocol> {
        match self {
            Self::Tcp(_) => Some(IpNextHeaderProtocols::Tcp),
            Self::Udp(_) => Some(IpNextHeaderProtocols::Udp),
            Self::Sctp(_) => Some(IpNextHeaderProtocols::Sctp),
            Self::Icmpv4(_) => Some(IpNextHeaderProtocols::Icmp),
            Self::Icmpv6(_) => Some(IpNextHeaderProtocols::Icmpv6),
            _ => None,
        }
    }

    /// What an enclosing Ethernet header should call this one.
    fn ethertype(&self) -> Option<EtherType> {
        match self {
            Self::Ipv4(_) => Some(EtherTypes::Ipv4),
            Self::Ipv6(_) => Some(EtherTypes::Ipv6),
            Self::Arp(_) => Some(EtherTypes::Arp),
            _ => None,
        }
    }
}

/// A packet described as a stack of headers, outermost first.
///
/// See the [module documentation](self) for the idea and an example. Push what
/// you want, in the order it appears on the wire, and call [`build`](Self::build).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Packet {
    layers: Vec<Layer>,
}

impl Packet {
    /// An empty packet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a header inside everything pushed so far.
    #[must_use]
    pub fn push(mut self, layer: impl Into<Layer>) -> Self {
        self.layers.push(layer.into());
        self
    }

    /// The layers, outermost first.
    pub fn layers(&self) -> &[Layer] {
        &self.layers
    }

    /// The layers, for a caller editing a packet it did not build.
    pub fn layers_mut(&mut self) -> &mut Vec<Layer> {
        &mut self.layers
    }

    /// Serializes the packet.
    ///
    /// Built from the inside out, because a derived length cannot be known
    /// until what it counts has been written. The one exception is a transport
    /// checksum, which needs the addresses of the IP header *outside* it, so
    /// those are found up front.
    ///
    /// # Errors
    ///
    /// [`PacketError::TooLong`] when a computed length will not fit its field,
    /// and [`PacketError::FamilyMismatch`] when a transport layer sits inside
    /// an IP header of a family its addresses do not match. A field written
    /// with [`Field::Exact`] is never checked, which is the point of it.
    pub fn build(&self) -> Result<Vec<u8>> {
        let addresses = self.enclosing_addresses();

        let mut bytes = Vec::new();
        // What the layer being written should call the one just written, when
        // it is working its own protocol or ethertype out.
        let mut inner: Option<&Layer> = None;

        for layer in self.layers.iter().rev() {
            bytes = write_layer(layer, bytes, inner, addresses)?;
            inner = Some(layer);
        }

        Ok(bytes)
    }

    /// The addresses a transport checksum's pseudo-header is built from, taken
    /// from the outermost IP layer.
    fn enclosing_addresses(&self) -> Option<(IpAddr, IpAddr)> {
        self.layers.iter().find_map(|layer| match layer {
            Layer::Ipv4(h) => Some((IpAddr::V4(h.source), IpAddr::V4(h.destination))),
            Layer::Ipv6(h) => Some((IpAddr::V6(h.source), IpAddr::V6(h.destination))),
            _ => None,
        })
    }
}

/// Writes `layer` around `payload`, returning the two together.
fn write_layer(
    layer: &Layer,
    payload: Vec<u8>,
    inner: Option<&Layer>,
    addresses: Option<(IpAddr, IpAddr)>,
) -> Result<Vec<u8>> {
    match layer {
        Layer::Raw(bytes) => Ok([bytes.as_slice(), payload.as_slice()].concat()),
        Layer::Ethernet(header) => write_ethernet(header, payload, inner),
        Layer::Ipv4(header) => write_ipv4(header, payload, inner),
        Layer::Ipv6(header) => write_ipv6(header, payload, inner),
        Layer::Tcp(header) => write_tcp(header, payload, addresses),
        Layer::Udp(header) => write_udp(header, payload, addresses),
        Layer::Sctp(header) => Ok(write_sctp(header, payload)),
        Layer::Icmpv4(message) => Ok([message.to_bytes(), payload].concat()),
        Layer::Icmpv6(message) => Ok([message.to_bytes(addresses)?, payload].concat()),
        Layer::Arp(packet) => Ok([packet.to_bytes(), payload].concat()),
    }
}

fn write_ethernet(header: &Ethernet, payload: Vec<u8>, inner: Option<&Layer>) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; ETH_HDR_LEN];
    {
        let mut eth =
            MutableEthernetPacket::new(&mut bytes).expect("a header-sized buffer holds a header");
        eth.set_source(header.source);
        eth.set_destination(header.destination);
        eth.set_ethertype(
            header
                .ethertype
                .resolve(|| inner.and_then(Layer::ethertype).unwrap_or(EtherTypes::Ipv4)),
        );
    }
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn write_ipv4(header: &Ipv4, payload: Vec<u8>, inner: Option<&Layer>) -> Result<Vec<u8>> {
    PacketError::check_options("an IPv4 header", header.options.len())?;

    let header_len = header.header_len();
    let total = header_len + payload.len();
    let total_length = match header.total_length {
        Field::Exact(value) => value,
        Field::Computed => u16::try_from(total).map_err(|_| {
            PacketError::too_long("the IPv4 total length", header_len, payload.len())
        })?,
    };

    let mut bytes = vec![0u8; header_len];
    {
        let mut ipv4 =
            MutableIpv4Packet::new(&mut bytes).expect("a header-sized buffer holds a header");
        ipv4.set_version(4);
        ipv4.set_header_length((header_len / 4) as u8);
        ipv4.set_dscp(header.dscp);
        ipv4.set_ecn(header.ecn);
        ipv4.set_total_length(total_length);
        ipv4.set_identification(header.identification.resolve(rand::random));
        ipv4.set_flags(header.flags);
        ipv4.set_fragment_offset(header.fragment_offset);
        ipv4.set_ttl(header.ttl);
        ipv4.set_next_level_protocol(header.protocol.resolve(|| {
            inner
                .and_then(Layer::ip_protocol)
                .unwrap_or(IpNextHeaderProtocols::Tcp)
        }));
        ipv4.set_source(header.source);
        ipv4.set_destination(header.destination);
        if !header.options.is_empty() {
            bytes[IP_V4_HDR_LEN..header_len].copy_from_slice(&header.options);
        }
    }
    {
        let mut ipv4 =
            MutableIpv4Packet::new(&mut bytes).expect("a header-sized buffer holds a header");
        let sum = header
            .checksum
            .resolve(|| ipv4_checksum(&ipv4.to_immutable()));
        ipv4.set_checksum(sum);
    }

    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn write_ipv6(header: &Ipv6, payload: Vec<u8>, inner: Option<&Layer>) -> Result<Vec<u8>> {
    let payload_length = match header.payload_length {
        Field::Exact(value) => value,
        Field::Computed => u16::try_from(payload.len())
            .map_err(|_| PacketError::too_long("the IPv6 payload length", 0, payload.len()))?,
    };

    let mut bytes = vec![0u8; IP_V6_HDR_LEN];
    {
        let mut ipv6 =
            MutableIpv6Packet::new(&mut bytes).expect("a header-sized buffer holds a header");
        ipv6.set_version(6);
        ipv6.set_traffic_class(header.traffic_class);
        ipv6.set_flow_label(header.flow_label.resolve(rand::random));
        ipv6.set_payload_length(payload_length);
        ipv6.set_next_header(header.next_header.resolve(|| {
            inner
                .and_then(Layer::ip_protocol)
                .unwrap_or(IpNextHeaderProtocols::Tcp)
        }));
        ipv6.set_hop_limit(header.hop_limit);
        ipv6.set_source(header.source);
        ipv6.set_destination(header.destination);
    }
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn write_tcp(
    header: &Tcp,
    payload: Vec<u8>,
    addresses: Option<(IpAddr, IpAddr)>,
) -> Result<Vec<u8>> {
    PacketError::check_options("a TCP header", header.options.len())?;

    let header_len = header.header_len();
    let mut bytes = vec![0u8; header_len];
    bytes.extend_from_slice(&header.payload);
    bytes.extend_from_slice(&payload);

    {
        let mut tcp =
            MutableTcpPacket::new(&mut bytes).expect("a header-sized buffer holds a header");
        tcp.set_source(header.source_port);
        tcp.set_destination(header.destination_port);
        tcp.set_sequence(header.sequence);
        tcp.set_acknowledgement(header.acknowledgement);
        tcp.set_data_offset(header.data_offset.resolve(|| (header_len / 4) as u8));
        tcp.set_flags(header.flags);
        tcp.set_window(header.window);
        tcp.set_urgent_ptr(header.urgent_pointer);
        tcp.set_checksum(0);
        if !header.options.is_empty() {
            bytes[TCP_HDR_LEN..header_len].copy_from_slice(&header.options);
        }
    }

    let sum = match header.checksum {
        Field::Exact(value) => value,
        Field::Computed => {
            let segment = TcpPacket::new(&bytes).expect("just written");
            transport_checksum(
                addresses,
                |src, dst| pnet_packet::tcp::ipv4_checksum(&segment, src, dst),
                |src, dst| pnet_packet::tcp::ipv6_checksum(&segment, src, dst),
            )?
        }
    };
    MutableTcpPacket::new(&mut bytes)
        .expect("a header-sized buffer holds a header")
        .set_checksum(sum);

    Ok(bytes)
}

fn write_udp(
    header: &Udp,
    payload: Vec<u8>,
    addresses: Option<(IpAddr, IpAddr)>,
) -> Result<Vec<u8>> {
    let body_len = header.payload.len() + payload.len();
    let length = match header.length {
        Field::Exact(value) => value,
        Field::Computed => u16::try_from(UDP_HDR_LEN + body_len)
            .map_err(|_| PacketError::too_long("the UDP length", UDP_HDR_LEN, body_len))?,
    };

    let mut bytes = vec![0u8; UDP_HDR_LEN];
    bytes.extend_from_slice(&header.payload);
    bytes.extend_from_slice(&payload);

    {
        let mut udp =
            MutableUdpPacket::new(&mut bytes).expect("a header-sized buffer holds a header");
        udp.set_source(header.source_port);
        udp.set_destination(header.destination_port);
        udp.set_length(length);
        udp.set_checksum(0);
    }

    let sum = match (header.checksum, addresses) {
        (Field::Exact(value), _) => value,
        // No IP header means no pseudo-header to sum over, and the field is left
        // for whoever supplies one. The substitution below must not fire here:
        // it would answer "there was nothing to compute" with a value that says
        // "computed, and it came to zero", which nothing downstream can tell
        // from a real checksum. See `transport_checksum`.
        (Field::Computed, None) => 0,
        (Field::Computed, Some(_)) => {
            let datagram = UdpPacket::new(&bytes).expect("just written");
            let computed = transport_checksum(
                addresses,
                |src, dst| pnet_packet::udp::ipv4_checksum(&datagram, src, dst),
                |src, dst| pnet_packet::udp::ipv6_checksum(&datagram, src, dst),
            )?;
            // Zero in this field means "not computed" (RFC 768), so a genuine
            // result of zero is sent as its ones-complement equivalent.
            if computed == 0 { 0xFFFF } else { computed }
        }
    };
    MutableUdpPacket::new(&mut bytes)
        .expect("a header-sized buffer holds a header")
        .set_checksum(sum);

    Ok(bytes)
}

/// Runs whichever checksum the enclosing IP layer calls for.
///
/// A transport layer with no IP header around it has no pseudo-header to
/// checksum over, so it gets zero: the caller is building a fragment to embed
/// somewhere else, and inventing addresses for it would be worse than leaving
/// the field for them to set.
fn transport_checksum(
    addresses: Option<(IpAddr, IpAddr)>,
    v4: impl FnOnce(&Ipv4Addr, &Ipv4Addr) -> u16,
    v6: impl FnOnce(&Ipv6Addr, &Ipv6Addr) -> u16,
) -> Result<u16> {
    match addresses {
        None => Ok(0),
        Some((IpAddr::V4(src), IpAddr::V4(dst))) => Ok(v4(&src, &dst)),
        Some((IpAddr::V6(src), IpAddr::V6(dst))) => Ok(v6(&src, &dst)),
        Some((src, dst)) => Err(PacketError::FamilyMismatch { src, dst }),
    }
}

/// `len` random bytes, for padding a probe's payload out to an unusual size.
///
/// Random rather than zero because a run of zeroes is itself a fixed pattern —
/// the very thing padding exists to move a probe off. Drawn fresh on each call,
/// so two probes padded to the same length still differ in their tails.
pub fn random_padding(len: u16) -> Vec<u8> {
    std::iter::repeat_with(rand::random)
        .take(len as usize)
        .collect()
}

/// A one's-complement internet checksum (RFC 1071) made deliberately, verifiably
/// wrong.
///
/// Flipping every bit is the surest single change: a value and its complement
/// verify differently, so the result is a checksum a conformant receiver
/// rejects — which is the whole point, since a reply to a segment that should
/// have been dropped came from something that did not check.
///
/// The one exception is a one's-complement zero, which has two encodings —
/// `0x0000` and `0xFFFF` — that verify identically. Complementing one lands on
/// the other, which is not actually a different value and so not actually wrong;
/// zero is besides a checksum a segment may legitimately carry. So a corruption
/// that produces either is moved to `0x0001`, which is unambiguously neither
/// encoding of zero and therefore unambiguously wrong.
pub fn corrupt_internet_checksum(correct: u16) -> u16 {
    match correct ^ 0xFFFF {
        0x0000 | 0xFFFF => 0x0001,
        flipped => flipped,
    }
}

fn write_sctp(header: &Sctp, payload: Vec<u8>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SCTP_COMMON_HDR_LEN + header.chunks.len() + payload.len());
    bytes.extend_from_slice(&header.source_port.to_be_bytes());
    bytes.extend_from_slice(&header.destination_port.to_be_bytes());
    bytes.extend_from_slice(&header.verification_tag.to_be_bytes());
    bytes.extend_from_slice(&[0; 4]); // checksum, filled once the packet is whole
    bytes.extend_from_slice(&header.chunks);
    bytes.extend_from_slice(&payload);

    // Computed over the packet with the field zeroed — which it is — and written
    // little-endian: the byte order RFC 4960 §6.8 puts the CRC on the wire in,
    // and the single most common way an SCTP checksum comes out wrong.
    let sum = header.checksum.resolve(|| crc32c(&bytes));
    bytes[8..12].copy_from_slice(&sum.to_le_bytes());
    bytes
}

/// The CRC32c reduction table, one entry per input byte.
///
/// Built at compile time from the reflected polynomial `0x82F6_3B78`, the
/// bit-reversal of the `0x1EDC_6F41` in RFC 3309 — the reflected form is what
/// goes with the reflected input and output the reduction below uses.
static CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut byte = 0;
    while byte < 256 {
        let mut crc = byte as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[byte] = crc;
        byte += 1;
    }
    table
};

/// The CRC32c (Castagnoli) of `data`, the checksum SCTP carries (RFC 3309).
///
/// The standard CRC-32C/iSCSI parameters — reflected in and out, initialised to
/// all-ones and finished by complementing — so this is the value that goes in
/// the SCTP checksum field, little-endian; see [`write_sctp`]. Shared with
/// [`sctp`](super::sctp) rather than reimplemented there, so a probe and a
/// hand-built packet cannot come to disagree about what the checksum is.
pub(crate) fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc = (crc >> 8) ^ CRC32C_TABLE[((crc ^ u32::from(byte)) & 0xFF) as usize];
    }
    !crc
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
    use pnet_packet::Packet as _;
    use pnet_packet::ipv4::Ipv4Packet;
    use pnet_packet::ipv6::Ipv6Packet;

    const V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const V4_DST: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 9);
    const MAC: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 1);

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().expect("a valid address")
    }

    // ── What a layer with nothing around it gets ─────────────────────────────

    /// A transport layer with no IP header around it has no pseudo-header to
    /// checksum over, so the field is left for whoever supplies one.
    ///
    /// UDP used to answer that with `0xFFFF`, because the RFC 768 substitution
    /// for a genuine zero fired on the "there was nothing to sum" zero as well.
    /// `0xFFFF` is a valid checksum meaning "computed, and it came to zero", so
    /// nothing downstream could tell the two apart, and `Udp::to_bytes`'s own
    /// documentation says the rules are `Tcp::to_bytes`'s.
    #[test]
    fn a_transport_layer_with_no_addresses_leaves_its_checksum_unset() {
        let tcp = Tcp::new(50_000, 80).to_bytes(None).expect("a segment");
        let udp = Udp::new(50_000, 53).to_bytes(None).expect("a datagram");

        assert_eq!(u16::from_be_bytes([tcp[16], tcp[17]]), 0);
        assert_eq!(u16::from_be_bytes([udp[6], udp[7]]), 0);

        // The substitution still fires where there was something to compute:
        // a datagram whose checksum genuinely sums to zero goes out as 0xFFFF,
        // because zero in that field means "not computed".
        let addresses = Some((IpAddr::V4(V4_SRC), IpAddr::V4(V4_DST)));
        let summed = Udp::new(50_000, 53)
            .to_bytes(addresses)
            .expect("a datagram");
        assert_ne!(u16::from_be_bytes([summed[6], summed[7]]), 0);
    }

    /// An ICMPv6 message inside an IPv4 header is a packet nothing can build,
    /// and it is not two addresses of different families.
    ///
    /// It used to report `FamilyMismatch`, whose message reads "an IPv4 and an
    /// IPv6 address" about two IPv4 ones, which sends a reader after a fault
    /// that is not there.
    #[test]
    fn an_icmpv6_message_under_an_ipv4_header_names_the_family_it_needed() {
        let refused = Packet::new()
            .push(Ipv4::new(V4_SRC, V4_DST))
            .push(Icmpv6::echo_request(1, 1))
            .build()
            .unwrap_err();

        assert!(
            matches!(
                refused,
                PacketError::WrongFamily {
                    protocol: "ICMPv6",
                    expected: "IPv6",
                    ..
                }
            ),
            "got {refused:?}"
        );
        assert!(
            !refused.to_string().contains("an IPv4 and an IPv6 address"),
            "the message still claims a mismatch that is not there: {refused}"
        );

        // Two addresses that genuinely disagree are still a mismatch.
        let mixed = Icmpv6::echo_request(1, 1)
            .to_bytes(Some((IpAddr::V4(V4_SRC), IpAddr::V6(v6("2001:db8::1")))))
            .unwrap_err();
        assert!(matches!(mixed, PacketError::FamilyMismatch { .. }));
    }

    /// A header built on its own has no layer inside it to name, so its protocol
    /// field falls back rather than being derived. That is a trap worth pinning
    /// rather than fixing: making it a refusal would turn two infallible
    /// builders fallible, and the fallback is now documented at both.
    #[test]
    fn a_header_built_alone_falls_back_to_tcp_and_says_so() {
        let derived = Ipv4 {
            protocol: Field::Exact(IpNextHeaderProtocols::Udp),
            ..Ipv4::new(V4_SRC, V4_DST)
        }
        .header_bytes(100)
        .expect("a header");
        assert_eq!(derived[9], IpNextHeaderProtocols::Udp.0);

        let fallback = Ipv4::new(V4_SRC, V4_DST)
            .header_bytes(100)
            .expect("a header");
        assert_eq!(
            fallback[9],
            IpNextHeaderProtocols::Tcp.0,
            "the documented fallback moved; the doc on `header_bytes` moves with it"
        );
    }

    // ── The default is a correct packet ──────────────────────────────────────

    /// Left alone, every derived field is the value a conformant stack expects.
    /// That is what makes the overrides below mean something: a caller who
    /// changes one field changes only that field.
    #[test]
    fn a_packet_nobody_overrode_is_one_a_stack_would_accept() {
        let bytes = Packet::new()
            .push(Ipv4::new(V4_SRC, V4_DST))
            .push(Tcp::new(50_000, 80).with_flags(tcp_flags::SYN))
            .build()
            .expect("builds");

        let ip = Ipv4Packet::new(&bytes).expect("an IPv4 header");
        assert_eq!(ip.get_total_length() as usize, bytes.len());
        assert_eq!(ip.get_next_level_protocol(), IpNextHeaderProtocols::Tcp);
        assert_eq!(
            ip.get_checksum(),
            ipv4_checksum(&Ipv4Packet::new(&bytes[..20]).expect("header")),
            "the header checksums itself"
        );

        let tcp = TcpPacket::new(ip.payload()).expect("a TCP header");
        assert_eq!(tcp.get_data_offset(), 5);
        assert_eq!(tcp.get_flags(), tcp_flags::SYN);
        assert_ne!(tcp.get_checksum(), 0, "checksummed over the pseudo-header");
    }

    /// The enclosing header works out what it is carrying, so a caller who
    /// swaps the transport does not have to remember to change the protocol
    /// number alongside it.
    #[test]
    fn an_enclosing_header_names_what_is_inside_it() {
        let over_udp = Packet::new()
            .push(Ethernet::new(MAC, MacAddr::broadcast()))
            .push(Ipv4::new(V4_SRC, V4_DST))
            .push(Udp::new(50_000, 53))
            .build()
            .expect("builds");

        let eth = super::super::ethernet::parse(&over_udp).expect("a frame");
        assert_eq!(eth.ethertype(), EtherTypes::Ipv4);
        assert_eq!(
            Ipv4Packet::new(eth.payload())
                .expect("an IPv4 header")
                .get_next_level_protocol(),
            IpNextHeaderProtocols::Udp
        );

        let over_v6 = Packet::new()
            .push(Ethernet::new(MAC, MacAddr::broadcast()))
            .push(Ipv6::new(v6("2001:db8::1"), v6("2001:db8::2")))
            .push(Tcp::new(50_000, 80))
            .build()
            .expect("builds");

        let eth = super::super::ethernet::parse(&over_v6).expect("a frame");
        assert_eq!(eth.ethertype(), EtherTypes::Ipv6);
        assert_eq!(
            Ipv6Packet::new(eth.payload())
                .expect("an IPv6 header")
                .get_next_header(),
            IpNextHeaderProtocols::Tcp
        );
    }

    /// The checksum covers a pseudo-header built from the addresses of the IP
    /// layer outside the transport, which is the one thing a layer cannot see
    /// by looking inward. Getting it from the wrong place is invisible until a
    /// real stack drops the packet.
    #[test]
    fn a_transport_checksum_covers_the_addresses_of_the_layer_around_it() {
        let checksum_with = |dst: Ipv4Addr| {
            let bytes = Packet::new()
                .push(Ipv4::new(V4_SRC, dst))
                .push(Tcp::new(50_000, 80).with_flags(tcp_flags::SYN))
                .build()
                .expect("builds");
            let ip = Ipv4Packet::new(&bytes).expect("header");
            TcpPacket::new(ip.payload())
                .expect("segment")
                .get_checksum()
        };

        assert_ne!(
            checksum_with(V4_DST),
            checksum_with(Ipv4Addr::new(192, 0, 2, 10)),
            "the destination is part of what is summed"
        );
    }

    // ── Overrides ────────────────────────────────────────────────────────────

    /// The point of the whole design: one wrong field, every other one still
    /// right. A packet that is wrong in nineteen ways is rejected by the first
    /// check a stack runs and tells you nothing about the rest.
    #[test]
    fn an_exact_field_is_written_verbatim_and_nothing_else_moves() {
        let bytes = Packet::new()
            .push(Ipv4 {
                total_length: Field::Exact(4),
                ..Ipv4::new(V4_SRC, V4_DST)
            })
            .push(Tcp::new(50_000, 80).with_flags(tcp_flags::SYN))
            .build()
            .expect("a wrong length is not an error, it is the request");

        let ip = Ipv4Packet::new(&bytes).expect("an IPv4 header");
        assert_eq!(ip.get_total_length(), 4, "written as asked");
        assert_eq!(bytes.len(), 40, "and the packet is its real size");
        assert_eq!(
            ip.get_next_level_protocol(),
            IpNextHeaderProtocols::Tcp,
            "the fields nobody touched are still correct"
        );

        // Read at a fixed offset rather than through `payload()`, which trusts
        // the length field and so hands back nothing. That a parser is already
        // misled by this packet is the point of building it.
        assert!(ip.payload().is_empty(), "a reader believes the header");
        let tcp = TcpPacket::new(&bytes[20..]).expect("the segment is really there");
        assert_ne!(tcp.get_checksum(), 0, "and is checksummed correctly");
        assert_eq!(tcp.get_destination(), 80);
    }

    /// A checksum of zero is a real thing to want to send and is exactly what
    /// `Computed` would never produce, so it is the clearest test that an
    /// override is honoured rather than validated away.
    #[test]
    fn a_deliberately_wrong_checksum_survives_to_the_wire() {
        let bytes = Packet::new()
            .push(Ipv4::new(V4_SRC, V4_DST).with_checksum(0))
            .push(Tcp::new(50_000, 80).with_checksum(0xDEAD))
            .build()
            .expect("builds");

        let ip = Ipv4Packet::new(&bytes).expect("an IPv4 header");
        assert_eq!(ip.get_checksum(), 0);
        assert_eq!(
            TcpPacket::new(ip.payload()).expect("tcp").get_checksum(),
            0xDEAD
        );
    }

    /// A data offset larger than the header makes a receiver read payload as
    /// options, and one smaller makes it read options as payload. Both are
    /// worth being able to send and neither is something the builder should
    /// second-guess.
    #[test]
    fn a_data_offset_that_lies_about_the_header_is_written_as_given() {
        let bytes = Packet::new()
            .push(Ipv4::new(V4_SRC, V4_DST))
            .push(Tcp {
                data_offset: Field::Exact(15),
                ..Tcp::new(50_000, 80)
            })
            .build()
            .expect("builds");

        let ip = Ipv4Packet::new(&bytes).expect("header");
        assert_eq!(
            TcpPacket::new(ip.payload()).expect("tcp").get_data_offset(),
            15
        );
    }

    // ── Refusals ─────────────────────────────────────────────────────────────

    /// A *computed* length that will not fit its field is refused, because the
    /// caller asked for the correct value and there is not one. An exact one is
    /// written whatever it says, which is the previous test.
    #[test]
    fn a_computed_length_that_cannot_fit_is_refused() {
        let refused = Packet::new()
            .push(Ipv4::new(V4_SRC, V4_DST))
            .push(Udp::new(50_000, 53).with_payload(vec![0u8; u16::MAX as usize]))
            .build();

        assert!(
            matches!(refused, Err(PacketError::TooLong { .. })),
            "got {refused:?}"
        );
    }

    /// A packet may be edited after it is described, which is how a caller
    /// works from a template. Swapping the IP layer for another family has to
    /// carry the transport checksum with it rather than leaving one computed
    /// against the old pseudo-header.
    #[test]
    fn editing_the_ip_layer_moves_the_checksum_that_depends_on_it() {
        let mut packet = Packet::new()
            .push(Ipv4::new(V4_SRC, V4_DST))
            .push(Tcp::new(50_000, 80).with_flags(tcp_flags::SYN));
        let over_v4 = packet.build().expect("builds");

        packet.layers_mut()[0] = Layer::Ipv6(Ipv6::new(v6("2001:db8::1"), v6("2001:db8::2")));
        let over_v6 = packet.build().expect("builds");

        let v4_sum = TcpPacket::new(&over_v4[20..]).expect("tcp").get_checksum();
        let v6_sum = TcpPacket::new(&over_v6[40..]).expect("tcp").get_checksum();
        assert_ne!(
            v4_sum, v6_sum,
            "the pseudo-header changed, so the checksum must have"
        );
    }

    /// A transport layer with no IP header around it is a fragment the caller
    /// means to embed somewhere else, so it gets a zero checksum rather than an
    /// invented pseudo-header.
    #[test]
    fn a_bare_transport_layer_builds_without_inventing_addresses() {
        let bytes = Packet::new()
            .push(Tcp::new(50_000, 80).with_flags(tcp_flags::SYN))
            .build()
            .expect("builds");

        assert_eq!(bytes.len(), 20);
        assert_eq!(TcpPacket::new(&bytes).expect("tcp").get_checksum(), 0);
    }

    // ── Payloads and options ─────────────────────────────────────────────────

    #[test]
    fn a_payload_is_counted_by_every_length_above_it() {
        let bytes = Packet::new()
            .push(Ipv4::new(V4_SRC, V4_DST))
            .push(Udp::new(50_000, 53).with_payload(b"hello".to_vec()))
            .build()
            .expect("builds");

        let ip = Ipv4Packet::new(&bytes).expect("header");
        assert_eq!(ip.get_total_length() as usize, 20 + 8 + 5);
        assert_eq!(
            UdpPacket::new(ip.payload()).expect("udp").get_length(),
            8 + 5
        );
        assert_eq!(&bytes[bytes.len() - 5..], b"hello");
    }

    /// Options past what the length field measures are refused rather than
    /// wrapped into it.
    ///
    /// Both fields are four bits of four-byte words, so forty bytes of options
    /// is the most either header can describe. Silently, forty-four produced a
    /// header declaring itself **zero** words long and a hundred produced one
    /// claiming fifty-six bytes over a buffer of a hundred and twenty — a packet
    /// every receiver reads as something other than what was built.
    #[test]
    fn options_past_what_the_length_field_measures_are_refused() {
        const LARGEST: usize = 40;

        for options in [LARGEST + 4, 100, 252] {
            let mut ip = Ipv4::new(V4_SRC, V4_DST);
            ip.options = vec![0u8; options];
            assert!(
                matches!(
                    Packet::new().push(Layer::Ipv4(ip)).build(),
                    Err(PacketError::OptionsTooLong { .. })
                ),
                "{options} bytes of IPv4 options was accepted"
            );

            let mut tcp = Tcp::new(1234, 80);
            tcp.options = vec![0u8; options];
            assert!(
                matches!(
                    Packet::new().push(Layer::Tcp(tcp)).build(),
                    Err(PacketError::OptionsTooLong { .. })
                ),
                "{options} bytes of TCP options was accepted"
            );
        }

        // And the largest that fits still builds, with the field describing it.
        let mut ip = Ipv4::new(V4_SRC, V4_DST);
        ip.options = vec![0u8; LARGEST];
        let bytes = Packet::new()
            .push(Layer::Ipv4(ip))
            .build()
            .expect("forty bytes of options is the most that fits");
        assert_eq!(usize::from(bytes[0] & 0x0F) * 4, IP_V4_HDR_LEN + LARGEST);
    }

    /// Options that are not a whole number of words are refused too.
    ///
    /// The field counts words, so the division rounded down and the odd bytes
    /// became payload to whatever received the packet: six bytes of options
    /// built a twenty-six byte header declaring twenty-four.
    #[test]
    fn options_that_are_not_a_whole_number_of_words_are_refused() {
        for options in [1usize, 2, 3, 5, 6, 7, 39] {
            let mut ip = Ipv4::new(V4_SRC, V4_DST);
            ip.options = vec![0u8; options];
            assert!(
                matches!(
                    Packet::new().push(Layer::Ipv4(ip)).build(),
                    Err(PacketError::OptionsMisaligned { .. })
                ),
                "{options} bytes of IPv4 options was accepted"
            );

            let mut tcp = Tcp::new(1234, 80);
            tcp.options = vec![0u8; options];
            assert!(
                matches!(
                    Packet::new().push(Layer::Tcp(tcp)).build(),
                    Err(PacketError::OptionsMisaligned { .. })
                ),
                "{options} bytes of TCP options was accepted"
            );
        }
    }

    /// Options lengthen the header, so the data offset that finds the payload
    /// has to move with them.
    #[test]
    fn tcp_options_move_the_data_offset_that_finds_the_payload() {
        let bytes = Packet::new()
            .push(Ipv4::new(V4_SRC, V4_DST))
            .push(Tcp {
                // One four-byte option: kind 2, length 4, MSS 1412.
                options: vec![2, 4, 0x05, 0x84],
                payload: b"body".to_vec(),
                ..Tcp::new(50_000, 80)
            })
            .build()
            .expect("builds");

        let ip = Ipv4Packet::new(&bytes).expect("header");
        let tcp = TcpPacket::new(ip.payload()).expect("tcp");
        assert_eq!(tcp.get_data_offset(), 6, "twenty bytes plus one word");
        assert_eq!(tcp.payload(), b"body");
    }

    /// Bytes nothing here models yet still go on the wire, so a protocol this
    /// module has not learned is not a wall.
    #[test]
    fn a_raw_layer_is_written_exactly_as_given() {
        let bytes = Packet::new()
            .push(Ipv4::new(V4_SRC, V4_DST))
            .push(Layer::Raw(vec![0xDE, 0xAD, 0xBE, 0xEF]))
            .build()
            .expect("builds");

        assert_eq!(&bytes[20..], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(
            Ipv4Packet::new(&bytes).expect("header").get_total_length(),
            24
        );
    }

    // ── SCTP ─────────────────────────────────────────────────────────────────

    /// The one non-circular anchor for the whole CRC32c path: the check value
    /// RFC 3309 and the CRC-32C/iSCSI definition both publish for the ASCII
    /// digits "123456789". A wrong polynomial or a missing reflection fails
    /// here rather than by silently disagreeing with every real stack.
    #[test]
    fn crc32c_matches_the_published_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    /// SCTP writes its checksum little-endian (RFC 4960 §6.8), which is the
    /// classic way to get it wrong. The stored field is the CRC's little-endian
    /// bytes, computed over the packet with the field zeroed — and, since the
    /// value is byte-order-sensitive, demonstrably not its big-endian bytes.
    #[test]
    fn an_sctp_checksum_is_written_little_endian_over_a_zeroed_field() {
        let bytes = Sctp::new(50_000, 9)
            .with_chunks(vec![1, 0, 0, 4]) // a minimal well-formed chunk header
            .to_bytes();

        let mut zeroed = bytes.clone();
        zeroed[8..12].copy_from_slice(&[0; 4]);
        let crc = crc32c(&zeroed);

        assert_eq!(&bytes[8..12], &crc.to_le_bytes());
        assert_ne!(
            &bytes[8..12],
            &crc.to_be_bytes(),
            "little-endian, not big — the check value makes the two differ"
        );
    }

    /// The enclosing IP header names SCTP for itself, so a caller stacking one
    /// does not have to remember protocol 132.
    #[test]
    fn an_ip_header_names_the_sctp_inside_it() {
        let bytes = Packet::new()
            .push(Ipv4::new(V4_SRC, V4_DST))
            .push(Sctp::new(50_000, 9).with_chunks(vec![1, 0, 0, 4]))
            .build()
            .expect("builds");

        assert_eq!(
            Ipv4Packet::new(&bytes)
                .expect("header")
                .get_next_level_protocol(),
            IpNextHeaderProtocols::Sctp
        );
    }

    /// The malformed-packet story reaches SCTP too: an exact checksum is written
    /// as given, which is what probing a stack's CRC validation needs.
    #[test]
    fn a_deliberately_wrong_sctp_checksum_survives_to_the_wire() {
        let bytes = Sctp::new(50_000, 9).with_checksum(0).to_bytes();
        assert_eq!(&bytes[8..12], &[0; 4]);
    }

    // ── Corrupting a checksum on purpose ─────────────────────────────────────

    /// The common case: flipping every bit lands on a value that verifies
    /// differently, so it is guaranteed wrong. A mutant that returned the input
    /// unchanged — a "corruption" equal to the correct checksum — would leave a
    /// probe every host accepts, which is the opposite of the point.
    #[test]
    fn a_corrupt_checksum_differs_from_the_one_it_was_made_from() {
        for correct in [0x1234, 0x00FF, 0xABCD, 0x8000, 0x0001] {
            let corrupt = corrupt_internet_checksum(correct);
            assert_ne!(corrupt, correct, "{correct:#06x} was not changed");
            assert_ne!(corrupt, 0, "{correct:#06x} corrupted to a zero checksum");
        }
    }

    /// The two encodings of a one's-complement zero verify identically, so a
    /// flip between them is not actually wrong — and zero is a checksum a segment
    /// may legitimately carry, so it can never be the corrupt one. A mutant that
    /// only flipped the bits would return the *other* encoding of zero here and
    /// ship a checksum still accepted as correct.
    #[test]
    fn corrupting_a_zero_encoding_avoids_the_other_encoding_of_zero() {
        assert_eq!(corrupt_internet_checksum(0x0000), 0x0001);
        assert_eq!(corrupt_internet_checksum(0xFFFF), 0x0001);
    }

    /// A segment asked for a bad TCP checksum carries one that a real parse
    /// confirms is neither the value the segment should have nor zero — with
    /// every other byte of the header untouched.
    #[test]
    fn a_tcp_segment_can_be_built_with_a_verifiably_wrong_checksum() {
        let addresses = Some((IpAddr::V4(V4_SRC), IpAddr::V4(V4_DST)));
        let segment = Tcp::new(50_000, 80).with_flags(tcp_flags::SYN);

        let good = segment.to_bytes(addresses).expect("builds");
        let corrupt = segment.corrupt_checksum(addresses).expect("perturbs");
        let bad = Tcp {
            checksum: Field::Exact(corrupt),
            ..segment
        }
        .to_bytes(addresses)
        .expect("builds");

        let should_carry = TcpPacket::new(&good).expect("tcp").get_checksum();
        let on_the_wire = TcpPacket::new(&bad).expect("tcp").get_checksum();
        assert_ne!(on_the_wire, should_carry, "the checksum is not wrong");
        assert_ne!(on_the_wire, 0, "zero is ambiguous, not wrong");

        // Only the checksum moved: zero both copies' checksum field (bytes 16..18
        // of the TCP header) and the rest must be byte-for-byte equal.
        let (mut good, mut bad) = (good, bad);
        good[16..18].fill(0);
        bad[16..18].fill(0);
        assert_eq!(good, bad, "corrupting the checksum disturbed another field");
    }
}
