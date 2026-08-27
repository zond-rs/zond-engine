// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Why a packet could not be built or read
//!
//! One error type for the whole module, with a variant per thing that can
//! actually go wrong. There are fewer of those than the old signatures
//! suggested: most builders here write fixed-size headers into buffers they
//! allocate themselves, which cannot fail, and they say so now by returning a
//! packet rather than a `Result`.
//!
//! What remains is the two failures a caller can genuinely cause, and one a
//! parser can meet.

use std::net::IpAddr;

/// Why a packet could not be built, or a captured one could not be read.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    /// A length field cannot represent a packet this large.
    ///
    /// Both length fields in IP and the one in UDP are 16 bits and count the
    /// header as well as the payload, so the largest payload each can describe
    /// is slightly under 64 KiB. A payload past that is refused rather than
    /// truncated into the field: the wrapped value describes a packet shorter
    /// than its own header, which every receiver drops, and the scan reads the
    /// resulting silence as a firewall.
    #[error("{field} cannot describe {actual} bytes; the most it can hold is {limit}")]
    TooLong {
        /// The header field that cannot hold the value, such as
        /// `"the IPv4 total length"`.
        field: &'static str,
        /// The length that was asked for, in bytes.
        actual: usize,
        /// The largest this field can describe, in bytes.
        limit: usize,
    },

    /// A transport checksum was asked for over two addresses of different
    /// families.
    ///
    /// TCP and UDP checksum over a pseudo-header built from the source and
    /// destination, so the two have to agree on what an address is. This is a
    /// caller mistake rather than a network condition: nothing on the wire
    /// produces it.
    #[error("cannot checksum from {src} to {dst}: an IPv4 and an IPv6 address")]
    FamilyMismatch {
        /// The source that was given.
        src: IpAddr,
        /// The destination that was given.
        dst: IpAddr,
    },

    /// A datagram was handed to the fragmenter with an MTU too small to split
    /// it into any useful piece.
    ///
    /// A fragment offset counts eight-byte units, so the smallest step a
    /// fragment can make through the datagram is one unit past the header. An
    /// MTU that will not hold even that carries no payload at all, and splitting
    /// to fit it would emit headers forever without ever reaching the end —
    /// refused rather than looped.
    #[error("an MTU of {mtu} cannot fragment past a {minimum}-byte floor")]
    MtuTooSmall {
        /// The MTU that was asked for, in bytes.
        mtu: usize,
        /// The smallest MTU that could carry a fragment: the header and one
        /// eight-byte unit.
        minimum: usize,
    },

    /// An IPv4 header carrying options was handed to the fragmenter.
    ///
    /// Each option names in its own high bit whether it is copied into every
    /// fragment or kept only on the first (RFC 791 §3.1). Splitting a header
    /// without honouring that bit produces fragments a receiver reassembles into
    /// the wrong header, so an option-bearing header is refused rather than
    /// split blind.
    #[error("cannot fragment an IPv4 header carrying {options} bytes of options")]
    HeaderHasOptions {
        /// How many option bytes the header carried.
        options: usize,
    },

    /// A frame carried something this module does not read.
    ///
    /// Not a malformed frame and not a fault. A promiscuous capture sees the
    /// whole segment's traffic, so most of what arrives is somebody else's, and
    /// the ethertype is named so a caller debugging a missed host can tell
    /// "arrived and was not understood" from "never arrived".
    #[error("nothing here reads ethertype {0:#06x}")]
    UnsupportedEtherType(u16),

    /// A buffer held too few bytes to read the header it was supposed to
    /// contain.
    ///
    /// What a truncated capture looks like from here, and the one variant that
    /// describes something arriving rather than something being built.
    #[error("{what} needs at least {needed} bytes and got {got}")]
    Truncated {
        /// What was being read, such as `"an Ethernet frame"`.
        what: &'static str,
        /// The smallest a valid one could be, in bytes.
        needed: usize,
        /// What was actually there, in bytes.
        got: usize,
    },
}

impl PacketError {
    /// The error for a payload that will not fit a 16-bit length field
    /// counting `header` bytes of header alongside it.
    pub(crate) fn too_long(field: &'static str, header: usize, payload: usize) -> Self {
        Self::TooLong {
            field,
            actual: header.saturating_add(payload),
            limit: u16::MAX as usize,
        }
    }

    /// The error for reading `what` out of a buffer that is too short.
    pub(crate) fn truncated(what: &'static str, needed: usize, got: usize) -> Self {
        Self::Truncated { what, needed, got }
    }
}

/// What every builder and parser in this module returns.
pub type Result<T> = std::result::Result<T, PacketError>;
