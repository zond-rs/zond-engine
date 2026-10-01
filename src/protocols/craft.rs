// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Building a packet field by field
//!
//! [`tcp::build_probe`](super::tcp::build_probe) and its neighbours build the
//! handful of packets a scan needs. This module builds anything else: a packet
//! described a layer at a time, including one that is wrong on purpose.
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
//! Most header fields are the caller's outright: a port, a TTL, a flag. A few are
//! derived: a length that counts what is inside, a checksum computed over it, a
//! protocol number naming the layer below. Every derived field is a
//! [`Field<T>`](Field), [`Computed`] by default and [`Exact`] when the caller
//! sets it:
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
//! // Claims to be shorter than it is, with a zero checksum.
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
//! That is the only way to make a malformed packet: one wrong field among
//! correct ones is what finds bugs in a stack.
//!
//! ## Public fields
//!
//! A header has no invariant to protect, since writing a wrong value is the
//! point, so these are plain data: public fields and functional update syntax.
//! The `with_*` methods exist for chaining.
//!
//! ## Cost
//!
//! The scan presets are written in terms of these types but build into an
//! exact buffer of known size. A [`Packet`] allocates per layer.
//!
//! [`Computed`]: Field::Computed
//! [`Exact`]: Field::Exact

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::model::mac::MacAddr;
use crate::protocols::mac::IntoPnetMac;
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

/// TCP header flag bits, for building a [`Tcp`] header.
pub use crate::protocols::tcp::flags as tcp_flags;

/// A header field the builder can work out for itself, unless the caller sets it.
///
/// [`Computed`](Self::Computed) writes the value a conformant stack expects;
/// [`Exact`](Self::Exact) writes what it is given, wrong or not. See the
/// [module documentation](self).
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
    /// `computed` is evaluated only for [`Computed`](Self::Computed).
    fn resolve(self, computed: impl FnOnce() -> T) -> T {
        match self {
            Self::Computed => computed(),
            Self::Exact(value) => value,
        }
    }

    /// Whether this field was given a value.
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
#[cfg_attr(
    feature = "packet-exchange",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Ethernet {
    /// The address the frame claims to come from.
    #[cfg_attr(feature = "packet-exchange", serde(with = "document::mac"))]
    pub source: MacAddr,
    /// The address it is aimed at.
    #[cfg_attr(feature = "packet-exchange", serde(with = "document::mac"))]
    pub destination: MacAddr,
    /// What the frame carries. Computed from the layer inside it.
    #[cfg_attr(
        feature = "packet-exchange",
        serde(
            default = "document::computed",
            skip_serializing_if = "document::is_computed",
            with = "document::number"
        )
    )]
    pub ethertype: Field<u16>,
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

    /// Sets the ethertype instead of taking it from the layer inside.
    #[must_use]
    pub fn with_ethertype(mut self, ethertype: u16) -> Self {
        self.ethertype = Field::Exact(ethertype);
        self
    }

    /// This header alone. A `Computed` [`ethertype`](Self::ethertype) becomes
    /// IPv4, since there is no inner layer to read one from.
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
#[cfg_attr(
    feature = "packet-exchange",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Ipv4 {
    /// Where the packet claims to come from.
    pub source: Ipv4Addr,
    /// Where it is going.
    pub destination: Ipv4Addr,
    /// Differentiated services, six bits.
    pub dscp: u8,
    /// Explicit congestion notification, two bits.
    pub ecn: u8,
    /// The fragment identifier. Computed at random, as a stack does.
    #[cfg_attr(
        feature = "packet-exchange",
        serde(
            default = "document::computed",
            skip_serializing_if = "document::is_computed"
        )
    )]
    pub identification: Field<u16>,
    /// The three-bit flags field. See [`ipv4_flags`].
    pub flags: u8,
    /// Where this fragment sits in the original datagram, in eight-byte units.
    pub fragment_offset: u16,
    /// How many hops the packet may cross.
    pub ttl: u8,
    /// What the packet carries. Computed from the layer pushed inside this one,
    /// and TCP where there is none: see [`header_bytes`](Self::header_bytes).
    #[cfg_attr(
        feature = "packet-exchange",
        serde(
            default = "document::computed",
            skip_serializing_if = "document::is_computed",
            with = "document::number"
        )
    )]
    pub protocol: Field<u8>,
    /// Header and payload together. Computed from the packet being built.
    #[cfg_attr(
        feature = "packet-exchange",
        serde(
            default = "document::computed",
            skip_serializing_if = "document::is_computed"
        )
    )]
    pub total_length: Field<u16>,
    /// The header checksum. Computed over the finished header.
    #[cfg_attr(
        feature = "packet-exchange",
        serde(
            default = "document::computed",
            skip_serializing_if = "document::is_computed"
        )
    )]
    pub checksum: Field<u16>,
    /// Header options, at most forty bytes and a whole number of four-byte
    /// words.
    ///
    /// Both bounds come from the four-bit header-length field, which counts
    /// words: fifteen at most, five taken by the fixed header. [`Packet::build`]
    /// refuses options that break either, because the field would wrap and
    /// receivers would misparse the header.
    #[cfg_attr(feature = "packet-exchange", serde(with = "document::hex"))]
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
    /// For a caller assembling the layers itself, such as the transport holding
    /// a finished segment. [`Packet::build`] is simpler when the payload is to
    /// hand.
    ///
    /// Set [`protocol`](Self::protocol) first: with no inner layer, a `Computed`
    /// protocol falls back to TCP. A UDP segment behind that header is dropped
    /// by the receiver, and nothing here catches it.
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

        // The checksum covers the total length, so it is recomputed.
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
#[cfg_attr(
    feature = "packet-exchange",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Ipv6 {
    /// Where the packet claims to come from.
    pub source: Ipv6Addr,
    /// Where it is going.
    pub destination: Ipv6Addr,
    /// Traffic class, eight bits.
    pub traffic_class: u8,
    /// The flow label, twenty bits. Computed at random.
    #[cfg_attr(
        feature = "packet-exchange",
        serde(
            default = "document::computed",
            skip_serializing_if = "document::is_computed"
        )
    )]
    pub flow_label: Field<u32>,
    /// What follows this header. Computed from the layer pushed inside this one,
    /// and TCP where there is none: see [`header_bytes`](Self::header_bytes).
    #[cfg_attr(
        feature = "packet-exchange",
        serde(
            default = "document::computed",
            skip_serializing_if = "document::is_computed",
            with = "document::number"
        )
    )]
    pub next_header: Field<u8>,
    /// Everything after this header. Computed from the packet being built.
    #[cfg_attr(
        feature = "packet-exchange",
        serde(
            default = "document::computed",
            skip_serializing_if = "document::is_computed"
        )
    )]
    pub payload_length: Field<u16>,
    /// How many hops the packet may cross. See
    /// [`HOP_LIMIT_ON_LINK`](super::ip::HOP_LIMIT_ON_LINK) and its neighbours
    /// for the values that matter.
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
    /// counterpart of [`Ipv4::header_bytes`], infallible because the field
    /// counts only the payload.
    ///
    /// Set [`next_header`](Self::next_header) first: with no inner layer, a
    /// `Computed` value falls back to TCP, as in [`Ipv4::header_bytes`].
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
#[cfg_attr(
    feature = "packet-exchange",
    derive(serde::Serialize, serde::Deserialize)
)]
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
    /// Defaults to 1024, the window every probe this engine sends carries, so a
    /// hand-built segment looks like them.
    pub window: u16,
    /// The urgent pointer, meaningful only with [`URG`](tcp_flags::URG) set.
    pub urgent_pointer: u16,
    /// How long the header is, in four-byte words. Computed from the options.
    ///
    /// A stack finds the payload with it: an exact value smaller than the real
    /// header makes the receiver read options as data, a larger one data as
    /// options.
    #[cfg_attr(
        feature = "packet-exchange",
        serde(
            default = "document::computed",
            skip_serializing_if = "document::is_computed"
        )
    )]
    pub data_offset: Field<u8>,
    /// The checksum, over the segment and an IP pseudo-header. Computed.
    #[cfg_attr(
        feature = "packet-exchange",
        serde(
            default = "document::computed",
            skip_serializing_if = "document::is_computed"
        )
    )]
    pub checksum: Field<u16>,
    /// Header options, as raw bytes: at most forty, and a whole number of
    /// four-byte words.
    ///
    /// The same bounds as [`Ipv4::options`], from the same shape of length
    /// field. [`Packet::build`] refuses options that break either.
    #[cfg_attr(feature = "packet-exchange", serde(with = "document::hex"))]
    pub options: Vec<u8>,
    /// The segment's payload.
    #[cfg_attr(feature = "packet-exchange", serde(with = "document::hex"))]
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
    /// The TCP checksum covers a pseudo-header built from the IP addresses.
    /// `None` leaves a `Computed` checksum zero, for a segment to embed
    /// elsewhere. [`Packet::build`] passes the addresses of its IP layer.
    ///
    /// # Errors
    ///
    /// [`PacketError::FamilyMismatch`] when the two addresses are of different
    /// families.
    pub fn to_bytes(&self, addresses: Option<(IpAddr, IpAddr)>) -> Result<Vec<u8>> {
        write_tcp(self, Vec::new(), addresses)
    }

    /// The checksum this segment should carry against `addresses`, perturbed to
    /// one that is certainly wrong and never zero.
    ///
    /// Computes the correct checksum, then corrupts it with
    /// [`corrupt_internet_checksum`]. Set the result on
    /// [`checksum`](Self::checksum) with [`Field::Exact`] to emit a segment a
    /// conformant host drops, so any reply came from something in the path.
    /// An arbitrary value would be correct once in 2^16.
    ///
    /// # Errors
    ///
    /// [`PacketError::FamilyMismatch`] when the two addresses are of different
    /// families, as from [`to_bytes`](Self::to_bytes).
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
#[cfg_attr(
    feature = "packet-exchange",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Udp {
    /// The port the datagram claims to come from.
    pub source_port: u16,
    /// The port it is aimed at.
    pub destination_port: u16,
    /// Header and payload together. Computed from the packet being built.
    #[cfg_attr(
        feature = "packet-exchange",
        serde(
            default = "document::computed",
            skip_serializing_if = "document::is_computed"
        )
    )]
    pub length: Field<u16>,
    /// The checksum, over the datagram and an IP pseudo-header. Computed.
    ///
    /// Optional over IPv4 and mandatory over IPv6: RFC 8200 §8.1 requires a
    /// receiver to discard a zero-checksum datagram, so
    /// `Field::Exact(0)` over IPv6 builds something that never arrives.
    #[cfg_attr(
        feature = "packet-exchange",
        serde(
            default = "document::computed",
            skip_serializing_if = "document::is_computed"
        )
    )]
    pub checksum: Field<u16>,
    /// The datagram's payload.
    #[cfg_attr(feature = "packet-exchange", serde(with = "document::hex"))]
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

    /// This datagram's bytes, checksummed against `addresses` as in
    /// [`Tcp::to_bytes`].
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
/// The checksum is a CRC32c (RFC 3309, RFC 4960 §6.8) over the whole packet
/// with no pseudo-header, so [`to_bytes`](Self::to_bytes) takes no addresses.
///
/// [`chunks`](Self::chunks) holds chunks already encoded; [`sctp`](super::sctp)
/// builds them. This type owns the common header and its
/// [`checksum`](Self::checksum).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "packet-exchange",
    derive(serde::Serialize, serde::Deserialize)
)]
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
    #[cfg_attr(
        feature = "packet-exchange",
        serde(
            default = "document::computed",
            skip_serializing_if = "document::is_computed"
        )
    )]
    pub checksum: Field<u32>,
    /// The chunks after the common header, already encoded.
    #[cfg_attr(feature = "packet-exchange", serde(with = "document::hex"))]
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

    /// This packet's bytes. The CRC32c covers no pseudo-header, so this cannot
    /// fail.
    pub fn to_bytes(&self) -> Vec<u8> {
        write_sctp(self, Vec::new())
    }
}

/// An ICMPv4 message.
///
/// The four bytes after the checksum depend on the message type, so they are
/// raw [`rest_of_header`](Self::rest_of_header) bytes.
/// [`echo_request`](Self::echo_request) fills them in for an echo request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "packet-exchange",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Icmpv4 {
    /// The message type. 8 is an echo request, 0 an echo reply, 3 destination
    /// unreachable.
    pub icmp_type: u8,
    /// The code, whose meaning depends on the type.
    pub code: u8,
    /// The checksum, over the ICMP message alone with no pseudo-header. Computed.
    #[cfg_attr(
        feature = "packet-exchange",
        serde(
            default = "document::computed",
            skip_serializing_if = "document::is_computed"
        )
    )]
    pub checksum: Field<u16>,
    /// The four type-specific bytes between the checksum and the payload. An
    /// echo carries its identifier and sequence here.
    #[cfg_attr(feature = "packet-exchange", serde(with = "document::hex_fixed"))]
    pub rest_of_header: [u8; 4],
    /// Whatever follows the header.
    #[cfg_attr(feature = "packet-exchange", serde(with = "document::hex"))]
    pub payload: Vec<u8>,
}

impl Icmpv4 {
    /// An echo request carrying `identifier` and `sequence`.
    ///
    /// RFC 792 requires a reply to echo both back unchanged, which is how a
    /// scanner matches replies to its own requests.
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

    /// A timestamp request carrying `identifier` and `sequence`.
    ///
    /// RFC 792's type 13, with an echo's header layout. The caller supplies the
    /// twelve timestamp bytes as the payload; a conformant target fills them in
    /// before replying.
    ///
    /// IPv4 only: RFC 4443 defines no ICMPv6 timestamp message.
    pub fn timestamp_request(identifier: u16, sequence: u16) -> Self {
        Self::echo(TIMESTAMP_REQUEST_V4, identifier, sequence)
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
    /// Zero for a conformant echo. A probe sending zero tells responders apart
    /// less: see [`ECHO_PROBE_CODE`](super::icmp::ECHO_PROBE_CODE).
    #[must_use]
    pub fn with_code(mut self, code: u8) -> Self {
        self.code = code;
        self
    }

    /// This message's bytes. No addresses are needed: the checksum covers the
    /// message alone.
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
/// Like [`Icmpv4`], except that the checksum also covers an IPv6
/// pseudo-header, so it depends on the addresses. See
/// [`to_bytes`](Self::to_bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "packet-exchange",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Icmpv6 {
    /// The message type. 128 is an echo request, 129 an echo reply, 135 a
    /// neighbor solicitation.
    pub icmp_type: u8,
    /// The code, whose meaning depends on the type.
    pub code: u8,
    /// The checksum, over the message and an IPv6 pseudo-header. Computed.
    #[cfg_attr(
        feature = "packet-exchange",
        serde(
            default = "document::computed",
            skip_serializing_if = "document::is_computed"
        )
    )]
    pub checksum: Field<u16>,
    /// The four type-specific bytes between the checksum and the payload.
    #[cfg_attr(feature = "packet-exchange", serde(with = "document::hex_fixed"))]
    pub rest_of_header: [u8; 4],
    /// Whatever follows the header.
    #[cfg_attr(feature = "packet-exchange", serde(with = "document::hex"))]
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
    /// Zero for a conformant echo. A probe sending zero tells responders apart
    /// less: see [`ECHO_PROBE_CODE`](super::icmp::ECHO_PROBE_CODE).
    #[must_use]
    pub fn with_code(mut self, code: u8) -> Self {
        self.code = code;
        self
    }

    /// This message's bytes, checksummed against `addresses`.
    ///
    /// The addresses are ignored for an exact checksum. `None` leaves a computed
    /// checksum zero, which a receiver discards: RFC 4443 has no "no checksum"
    /// encoding.
    ///
    /// # Errors
    ///
    /// [`PacketError::WrongFamily`] when both addresses are IPv4, and
    /// [`PacketError::FamilyMismatch`] when the two are of different families.
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
                    // Both agree but are not IPv6: ICMPv6 inside an IPv4 header.
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
/// Both share the layout: type, code, checksum, four type-specific bytes,
/// payload.
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
/// ICMPv4 timestamp request, RFC 792. No IPv6 counterpart exists.
const TIMESTAMP_REQUEST_V4: u8 = 13;
/// ICMPv6 echo request, RFC 4443.
const ECHO_REQUEST_V6: u8 = 128;
/// ICMPv6 echo reply, RFC 4443.
const ECHO_REPLY_V6: u8 = 129;

/// An ARP packet over Ethernet and IPv4.
///
/// Twenty-eight bytes with no payload and no derived fields. Useful for packets a
/// preset would not build: an unsolicited reply, a request claiming an address
/// the sender does not hold, a hardware length that does not match the addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "packet-exchange",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Arp {
    /// Request or reply. See [`arp_operations`].
    pub operation: u16,
    /// How long a hardware address is, in bytes. Six for Ethernet.
    pub hw_addr_len: u8,
    /// How long a protocol address is, in bytes. Four for IPv4.
    pub proto_addr_len: u8,
    /// The hardware address the sender claims.
    #[cfg_attr(feature = "packet-exchange", serde(with = "document::mac"))]
    pub sender_hw_addr: MacAddr,
    /// The protocol address the sender claims.
    pub sender_proto_addr: Ipv4Addr,
    /// The hardware address being asked about. Undefined in a request, which
    /// conventionally leaves it zero.
    #[cfg_attr(feature = "packet-exchange", serde(with = "document::mac"))]
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
    /// The target hardware address is left zero, as RFC 826 expects and
    /// ordinary stacks send. Anything else is legal but makes the probe
    /// distinctive.
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
            target_hw_addr: MacAddr::ZERO,
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
    /// Undefined in a request; [`request`](Self::request) leaves it zero. A
    /// unicast request validating a cache entry sets it, so a host that has
    /// moved answers from a different address and the entry shows as stale.
    #[must_use]
    pub fn with_target_hw_addr(mut self, target_hw_addr: MacAddr) -> Self {
        self.target_hw_addr = target_hw_addr;
        self
    }

    /// This packet's bytes.
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
            arp.set_sender_hw_addr(self.sender_hw_addr.into_pnet());
            arp.set_sender_proto_addr(self.sender_proto_addr);
            arp.set_target_hw_addr(self.target_hw_addr.into_pnet());
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
#[cfg_attr(
    feature = "packet-exchange",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "packet-exchange", serde(rename_all = "snake_case"))]
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
    #[cfg_attr(feature = "packet-exchange", serde(with = "document::hex"))]
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
    /// The IP protocol number naming this layer, for an enclosing IP header.
    fn ip_protocol(&self) -> Option<u8> {
        let protocol = match self {
            Self::Tcp(_) => IpNextHeaderProtocols::Tcp,
            Self::Udp(_) => IpNextHeaderProtocols::Udp,
            Self::Sctp(_) => IpNextHeaderProtocols::Sctp,
            Self::Icmpv4(_) => IpNextHeaderProtocols::Icmp,
            Self::Icmpv6(_) => IpNextHeaderProtocols::Icmpv6,
            _ => return None,
        };
        Some(protocol.0)
    }

    /// The ethertype naming this layer, for an enclosing Ethernet header.
    fn ethertype(&self) -> Option<u16> {
        let ethertype = match self {
            Self::Ipv4(_) => EtherTypes::Ipv4,
            Self::Ipv6(_) => EtherTypes::Ipv6,
            Self::Arp(_) => EtherTypes::Arp,
            _ => return None,
        };
        Some(ethertype.0)
    }
}

/// A packet described as a stack of headers, outermost first.
///
/// Layers are pushed in wire order, then [`build`](Self::build) assembles them.
/// See the [module documentation](self) for an example.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "packet-exchange",
    derive(serde::Serialize, serde::Deserialize)
)]
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
    /// Built from the inside out, since a derived length counts what is inside
    /// it. A transport checksum needs the addresses of the outer IP header, so
    /// those are found first.
    ///
    /// # Errors
    ///
    /// [`PacketError::TooLong`] when a computed length will not fit its field,
    /// and [`PacketError::FamilyMismatch`] when a transport layer sits inside
    /// an IP header of a family its addresses do not match. A field written
    /// with [`Field::Exact`] is never checked.
    pub fn build(&self) -> Result<Vec<u8>> {
        let addresses = self.enclosing_addresses();

        let mut bytes = Vec::new();
        // The layer just written, for computing the next one's protocol or
        // ethertype.
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

// ══════════════════════════════════════════════════════════════════════════════
// A packet as a document
// ══════════════════════════════════════════════════════════════════════════════

/// Reading and writing a packet as a document, behind `packet-exchange`.
///
/// Field names follow the RFCs (`ttl`, `checksum`, `source_port` as in RFC 791
/// and RFC 793), so the format is derived from the structs. Compare
/// [`import::settings`](crate::import::settings), which is hand-written.
///
/// ```toml
/// [[layers]]
/// [layers.ipv4]
/// source = "192.0.2.1"
/// destination = "192.0.2.9"
/// ttl = 12
/// total_length = 4        # the datagram claims to be shorter than it is
///
/// [[layers]]
/// [layers.tcp]
/// source_port = 50000
/// destination_port = 80
/// flags = 2
/// payload = "48454c4c4f"
/// ```
///
/// Conventions:
///
/// - **A derived field appears only when it was pinned.** An absent key is
///   [`Field::Computed`], a present one [`Field::Exact`].
/// - **Bytes are lowercase hex**: options, payloads, chunks and a raw layer.
/// - **A hardware address is written `aa:bb:cc:dd:ee:ff`.** An ethertype and a
///   next-header protocol are written as the numbers that go on the wire.
#[cfg(feature = "packet-exchange")]
mod document {
    use super::{Field, MacAddr};
    use data_encoding::HEXLOWER;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// What an absent key means: the builder works the value out.
    ///
    /// A function because the [`Default`] derive on [`Field`] requires
    /// `T: Default`.
    pub(super) fn computed<T>() -> Field<T> {
        Field::Computed
    }

    /// Whether a field is left out of a document: a derived field nobody pinned.
    pub(super) fn is_computed<T>(field: &Field<T>) -> bool {
        !field.is_exact()
    }

    impl<T: Serialize> Serialize for Field<T> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            match self {
                Field::Computed => serializer.serialize_none(),
                Field::Exact(value) => serializer.serialize_some(value),
            }
        }
    }

    impl<'de, T: Deserialize<'de>> Deserialize<'de> for Field<T> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            Ok(Option::<T>::deserialize(deserializer)?.map_or(Field::Computed, Field::Exact))
        }
    }

    /// Bytes, as lowercase hex.
    pub(super) mod hex {
        use super::{Deserialize, Deserializer, HEXLOWER, Serializer};

        pub(in super::super) fn serialize<S: Serializer>(
            bytes: &[u8],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&HEXLOWER.encode(bytes))
        }

        pub(in super::super) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Vec<u8>, D::Error> {
            let written = String::deserialize(deserializer)?;
            HEXLOWER
                .decode(written.as_bytes())
                .map_err(serde::de::Error::custom)
        }
    }

    /// The four type-specific bytes of an ICMP header, as hex of exactly that
    /// length.
    pub(super) mod hex_fixed {
        use super::{Deserializer, Serializer};

        pub(in super::super) fn serialize<S: Serializer>(
            bytes: &[u8; 4],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            super::hex::serialize(bytes, serializer)
        }

        pub(in super::super) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<[u8; 4], D::Error> {
            let bytes = super::hex::deserialize(deserializer)?;
            <[u8; 4]>::try_from(bytes.as_slice()).map_err(|_| {
                serde::de::Error::custom(format!(
                    "the four type-specific bytes are 8 hex characters, not {}",
                    bytes.len() * 2
                ))
            })
        }
    }

    /// A hardware address as `aa:bb:cc:dd:ee:ff`.
    pub(super) mod mac {
        use super::{Deserialize, Deserializer, MacAddr, Serializer};

        pub(in super::super) fn serialize<S: Serializer>(
            mac: &MacAddr,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.collect_str(mac)
        }

        pub(in super::super) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<MacAddr, D::Error> {
            let written = String::deserialize(deserializer)?;
            written.parse().map_err(serde::de::Error::custom)
        }
    }

    /// A next-header protocol number or an ethertype: the number itself, or
    /// nothing where the builder works it out.
    pub(super) mod number {
        use super::{Deserialize, Deserializer, Field, Serialize, Serializer};

        pub(in super::super) fn serialize<S: Serializer, T: Serialize>(
            field: &Field<T>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match field {
                Field::Computed => serializer.serialize_none(),
                Field::Exact(number) => serializer.serialize_some(number),
            }
        }

        pub(in super::super) fn deserialize<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
            deserializer: D,
        ) -> Result<Field<T>, D::Error> {
            Ok(Option::<T>::deserialize(deserializer)?.map_or(Field::Computed, Field::Exact))
        }
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

/// Writes an Ethernet header in front of `payload`. `inner` supplies a computed
/// ethertype.
fn write_ethernet(header: &Ethernet, payload: Vec<u8>, inner: Option<&Layer>) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; ETH_HDR_LEN];
    {
        let mut eth =
            MutableEthernetPacket::new(&mut bytes).expect("a header-sized buffer holds a header");
        eth.set_source(header.source.into_pnet());
        eth.set_destination(header.destination.into_pnet());
        eth.set_ethertype(EtherType(header.ethertype.resolve(|| {
            inner
                .and_then(Layer::ethertype)
                .unwrap_or(EtherTypes::Ipv4.0)
        })));
    }
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

/// Writes an IPv4 header in front of `payload`, deriving each
/// [`Field::Computed`] value and writing each [`Field::Exact`] as given.
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
        ipv4.set_next_level_protocol(IpNextHeaderProtocol(header.protocol.resolve(|| {
            inner
                .and_then(Layer::ip_protocol)
                .unwrap_or(IpNextHeaderProtocols::Tcp.0)
        })));
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

/// [`write_ipv4`] for IPv6, which has no header checksum.
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
        ipv6.set_next_header(IpNextHeaderProtocol(header.next_header.resolve(|| {
            inner
                .and_then(Layer::ip_protocol)
                .unwrap_or(IpNextHeaderProtocols::Tcp.0)
        })));
        ipv6.set_hop_limit(header.hop_limit);
        ipv6.set_source(header.source);
        ipv6.set_destination(header.destination);
    }
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

/// Writes a TCP segment.
///
/// `addresses` are the enclosing IP header's, for the checksum's pseudo-header.
/// With `None`, a computed checksum is left zero.
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

/// [`write_tcp`] for UDP, with the same pseudo-header and `addresses`.
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
        // No pseudo-header to sum over: leave zero. The 0xFFFF substitution
        // below must not fire here, since 0xFFFF means "computed, and it came
        // to zero".
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
/// With no IP header around the transport layer there is no pseudo-header, so
/// the result is zero, for the caller to fill in.
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
/// Random, since zeroes would be a fixed pattern of their own. Drawn fresh on
/// each call, so two probes padded to the same length still differ.
pub fn random_padding(len: u16) -> Vec<u8> {
    std::iter::repeat_with(rand::random)
        .take(len as usize)
        .collect()
}

/// A one's-complement internet checksum (RFC 1071) made certainly wrong.
///
/// Flips every bit, so a conformant receiver rejects the result and a reply to
/// the segment came from something that did not check.
///
/// The exception is one's-complement zero, whose two encodings `0x0000` and
/// `0xFFFF` verify identically, so complementing one yields the other. A result
/// of either is moved to `0x0001`, which is neither encoding of zero.
pub fn corrupt_internet_checksum(correct: u16) -> u16 {
    match correct ^ 0xFFFF {
        0x0000 | 0xFFFF => 0x0001,
        flipped => flipped,
    }
}

/// Writes an SCTP packet: the common header, the caller's chunks, then the
/// CRC32c over the whole of it, written into the zeroed checksum field.
///
/// Infallible: every length is a fixed width and the chunks arrive framed.
fn write_sctp(header: &Sctp, payload: Vec<u8>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SCTP_COMMON_HDR_LEN + header.chunks.len() + payload.len());
    bytes.extend_from_slice(&header.source_port.to_be_bytes());
    bytes.extend_from_slice(&header.destination_port.to_be_bytes());
    bytes.extend_from_slice(&header.verification_tag.to_be_bytes());
    bytes.extend_from_slice(&[0; 4]); // checksum, filled once the packet is whole
    bytes.extend_from_slice(&header.chunks);
    bytes.extend_from_slice(&payload);

    // Computed with the field zeroed and written little-endian, per RFC 4960
    // §6.8. The byte order is the most common SCTP checksum mistake.
    let sum = header.checksum.resolve(|| crc32c(&bytes));
    bytes[8..12].copy_from_slice(&sum.to_le_bytes());
    bytes
}

/// The CRC32c reduction table, one entry per input byte.
///
/// Built at compile time from the reflected polynomial `0x82F6_3B78`, the
/// bit-reversal of RFC 3309's `0x1EDC_6F41`, to match the reflected input and
/// output of [`crc32c`].
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
/// The standard CRC-32C/iSCSI parameters: reflected in and out, initialised to
/// all-ones and finished by complementing. The result goes in the SCTP checksum
/// field little-endian; see [`write_sctp`]. Shared with [`sctp`](super::sctp)
/// so probes and hand-built packets agree.
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

#[cfg(all(test, feature = "packet-exchange"))]
mod document_tests {
    use super::*;

    /// Every kind of layer, with a derived field pinned in each header so both
    /// [`Field`] variants cross the document.
    fn everything() -> Packet {
        Packet::new()
            .push(Ethernet {
                ethertype: Field::Exact(0x88b5),
                ..Ethernet::new(
                    MacAddr::new(2, 0, 0, 0, 0, 1),
                    MacAddr::new(2, 0, 0, 0, 0, 2),
                )
            })
            .push(Ipv4 {
                ttl: 12,
                // Pinned so two builds draw the same identification.
                identification: Field::Exact(0x4242),
                total_length: Field::Exact(4),
                checksum: Field::Exact(0),
                protocol: Field::Exact(IpNextHeaderProtocols::Tcp.0),
                options: vec![1, 2, 3, 4],
                ..Ipv4::new(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 9))
            })
            .push(Tcp {
                data_offset: Field::Exact(15),
                options: vec![0; 4],
                payload: b"HELLO".to_vec(),
                ..Tcp::new(50_000, 80).with_flags(tcp_flags::SYN)
            })
            .push(Layer::Raw(vec![0xde, 0xad, 0xbe, 0xef]))
    }

    /// What comes back from a document builds the same bytes as the original,
    /// which also covers fields this test does not name.
    #[test]
    fn a_packet_written_as_a_document_reads_back_as_the_same_packet() {
        let original = everything();
        let written = toml::to_string(&original).expect("a packet is a document");
        let read: Packet = toml::from_str(&written).expect("and reads back");

        assert_eq!(
            read.build().expect("the copy builds"),
            original.build().expect("the original builds"),
            "the packet that came back is not the packet that went in:\n{written}"
        );
    }

    /// A derived field left to the builder is left out of the document, and a
    /// pinned one is written down.
    #[test]
    fn only_a_pinned_field_is_written_down() {
        let pinned = Packet::new().push(Ipv4 {
            checksum: Field::Exact(0),
            ..Ipv4::new(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST)
        });
        let written = toml::to_string(&pinned).expect("a document");

        assert!(written.contains("checksum"), "{written}");
        assert!(
            !written.contains("total_length"),
            "a field left to the builder was written down as though it were chosen:\n{written}"
        );

        let read: Packet = toml::from_str(&written).expect("reads back");
        let Some(Layer::Ipv4(header)) = read.layers().first() else {
            panic!("the layer came back as something else");
        };
        assert_eq!(header.checksum, Field::Exact(0));
        assert_eq!(header.total_length, Field::Computed);
    }

    /// Bytes are written as hex.
    #[test]
    fn bytes_are_written_as_hex() {
        let packet = Packet::new().push(Layer::Raw(vec![0xde, 0xad, 0xbe, 0xef]));
        let written = toml::to_string(&packet).expect("a document");

        assert!(written.contains("deadbeef"), "{written}");
    }

    /// Hex that is not four bytes is refused on read, with a message saying
    /// why, and not padded or truncated.
    #[test]
    fn a_rest_of_header_that_is_not_four_bytes_is_refused() {
        let error = toml::from_str::<Packet>(
            "[[layers]]\n[layers.icmpv4]\nicmp_type = 8\ncode = 0\nrest_of_header = \"dead\"\npayload = \"\"\n",
        )
        .expect_err("two bytes are not the four an ICMP header has");

        assert!(error.to_string().contains("8 hex characters"), "{error}");
    }

    /// A document round-trips through JSON as well as TOML.
    ///
    /// `serde_json` comes from this package's dev-dependency on itself with
    /// `export-all`, so a test build always has it.
    #[test]
    fn the_same_packet_round_trips_through_json() {
        let original = everything();
        let written = serde_json::to_string(&original).expect("a packet is JSON too");
        let read: Packet = serde_json::from_str(&written).expect("and reads back");

        assert_eq!(
            read.build().expect("the copy builds"),
            original.build().expect("the original builds")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet_packet::Packet as _;
    use pnet_packet::ipv4::Ipv4Packet;
    use pnet_packet::ipv6::Ipv6Packet;

    const V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const V4_DST: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 9);
    const MAC: MacAddr = MacAddr::new(0x02, 0, 0, 0, 0, 1);

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().expect("a valid address")
    }

    // ── What a layer with nothing around it gets ─────────────────────────────

    /// A transport layer with no IP header around it leaves its checksum zero.
    ///
    /// UDP must not substitute `0xFFFF` here (RFC 768's encoding of a computed
    /// zero), since nothing was computed.
    #[test]
    fn a_transport_layer_with_no_addresses_leaves_its_checksum_unset() {
        let tcp = Tcp::new(50_000, 80).to_bytes(None).expect("a segment");
        let udp = Udp::new(50_000, 53).to_bytes(None).expect("a datagram");

        assert_eq!(u16::from_be_bytes([tcp[16], tcp[17]]), 0);
        assert_eq!(u16::from_be_bytes([udp[6], udp[7]]), 0);

        // With addresses, a computed checksum is never zero on the wire.
        let addresses = Some((IpAddr::V4(V4_SRC), IpAddr::V4(V4_DST)));
        let summed = Udp::new(50_000, 53)
            .to_bytes(addresses)
            .expect("a datagram");
        assert_ne!(u16::from_be_bytes([summed[6], summed[7]]), 0);
    }

    /// An ICMPv6 message inside an IPv4 header reports `WrongFamily`. A
    /// `FamilyMismatch` message would claim an IPv4 and an IPv6 address.
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

        // Two addresses of different families are a mismatch.
        let mixed = Icmpv6::echo_request(1, 1)
            .to_bytes(Some((IpAddr::V4(V4_SRC), IpAddr::V6(v6("2001:db8::1")))))
            .unwrap_err();
        assert!(matches!(mixed, PacketError::FamilyMismatch { .. }));
    }

    /// A header built alone has no inner layer, so a computed protocol field
    /// falls back to TCP, as documented at both builders.
    #[test]
    fn a_header_built_alone_falls_back_to_tcp_and_says_so() {
        let derived = Ipv4 {
            protocol: Field::Exact(IpNextHeaderProtocols::Udp.0),
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

    /// The enclosing header computes the protocol number or ethertype of what
    /// it carries.
    #[test]
    fn an_enclosing_header_names_what_is_inside_it() {
        let over_udp = Packet::new()
            .push(Ethernet::new(MAC, MacAddr::BROADCAST))
            .push(Ipv4::new(V4_SRC, V4_DST))
            .push(Udp::new(50_000, 53))
            .build()
            .expect("builds");

        let eth = super::super::ethernet::parse(&over_udp).expect("a frame");
        assert_eq!(eth.ethertype(), EtherTypes::Ipv4.0);
        assert_eq!(
            Ipv4Packet::new(eth.payload())
                .expect("an IPv4 header")
                .get_next_level_protocol(),
            IpNextHeaderProtocols::Udp
        );

        let over_v6 = Packet::new()
            .push(Ethernet::new(MAC, MacAddr::BROADCAST))
            .push(Ipv6::new(v6("2001:db8::1"), v6("2001:db8::2")))
            .push(Tcp::new(50_000, 80))
            .build()
            .expect("builds");

        let eth = super::super::ethernet::parse(&over_v6).expect("a frame");
        assert_eq!(eth.ethertype(), EtherTypes::Ipv6.0);
        assert_eq!(
            Ipv6Packet::new(eth.payload())
                .expect("an IPv6 header")
                .get_next_header(),
            IpNextHeaderProtocols::Tcp
        );
    }

    /// The checksum covers a pseudo-header built from the addresses of the
    /// enclosing IP layer. A mistake here shows only when a real stack drops
    /// the packet.
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

    /// One wrong field, every other one still right.
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

        // Read at a fixed offset: `payload()` trusts the length field and
        // returns nothing.
        assert!(ip.payload().is_empty(), "a reader believes the header");
        let tcp = TcpPacket::new(&bytes[20..]).expect("the segment is really there");
        assert_ne!(tcp.get_checksum(), 0, "and is checksummed correctly");
        assert_eq!(tcp.get_destination(), 80);
    }

    /// An exact checksum, including zero, which `Computed` never produces, is
    /// written as given.
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

    /// A data offset that misdescribes the header is written as given.
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

    /// A *computed* length that will not fit its field is refused, since no
    /// correct value exists. An exact one is written as given.
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

    /// Swapping the IP layer of a described packet for another family
    /// recomputes the transport checksum against the new pseudo-header.
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

    /// A transport layer with no IP header around it gets a zero checksum.
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

    /// Options past what the length field measures are refused.
    ///
    /// Both fields are four bits of four-byte words, so forty bytes of options
    /// is the most either header can describe. Wrapped, forty-four would make a
    /// header declaring zero words, and a hundred one claiming fifty-six bytes
    /// over a buffer of a hundred and twenty.
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

        // The largest that fits builds, with the field describing it.
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
    /// The field counts words, so the odd bytes would be read as payload: six
    /// bytes of options would build a twenty-six byte header declaring
    /// twenty-four.
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

    /// Options lengthen the header, and the data offset follows.
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

    /// A raw layer goes on the wire as given and is counted by the lengths
    /// above it.
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

    /// The check value RFC 3309 and the CRC-32C/iSCSI definition publish for
    /// the ASCII digits "123456789": the one non-circular test of [`crc32c`].
    /// A wrong polynomial or missing reflection fails here.
    #[test]
    fn crc32c_matches_the_published_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    /// SCTP writes its checksum little-endian (RFC 4960 §6.8), computed over
    /// the packet with the field zeroed.
    #[test]
    fn an_sctp_checksum_is_written_little_endian_over_a_zeroed_field() {
        let bytes = Sctp::new(50_000, 9)
            .with_chunks(vec![1, 0, 0, 4]) // minimal chunk header
            .to_bytes();

        let mut zeroed = bytes.clone();
        zeroed[8..12].copy_from_slice(&[0; 4]);
        let crc = crc32c(&zeroed);

        assert_eq!(&bytes[8..12], &crc.to_le_bytes());
        assert_ne!(
            &bytes[8..12],
            &crc.to_be_bytes(),
            "little-endian rather than big; the check value makes the two differ"
        );
    }

    /// The enclosing IP header computes protocol 132 for SCTP.
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

    /// An exact SCTP checksum is written as given.
    #[test]
    fn a_deliberately_wrong_sctp_checksum_survives_to_the_wire() {
        let bytes = Sctp::new(50_000, 9).with_checksum(0).to_bytes();
        assert_eq!(&bytes[8..12], &[0; 4]);
    }

    // ── Corrupting a checksum on purpose ─────────────────────────────────────

    /// Flipping every bit gives a value that verifies differently, and never
    /// zero.
    #[test]
    fn a_corrupt_checksum_differs_from_the_one_it_was_made_from() {
        for correct in [0x1234, 0x00FF, 0xABCD, 0x8000, 0x0001] {
            let corrupt = corrupt_internet_checksum(correct);
            assert_ne!(corrupt, correct, "{correct:#06x} was not changed");
            assert_ne!(corrupt, 0, "{correct:#06x} corrupted to a zero checksum");
        }
    }

    /// The two encodings of one's-complement zero verify identically, so a
    /// plain bit flip would turn one into the other and still be accepted.
    #[test]
    fn corrupting_a_zero_encoding_avoids_the_other_encoding_of_zero() {
        assert_eq!(corrupt_internet_checksum(0x0000), 0x0001);
        assert_eq!(corrupt_internet_checksum(0xFFFF), 0x0001);
    }

    /// A segment built with [`Tcp::corrupt_checksum`] carries a checksum that is
    /// neither correct nor zero, with every other byte unchanged.
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

        // Zero the checksum field (TCP bytes 16..18) in both; the rest must match.
        let (mut good, mut bad) = (good, bad);
        good[16..18].fill(0);
        bad[16..18].fill(0);
        assert_eq!(good, bad, "corrupting the checksum disturbed another field");
    }
}
