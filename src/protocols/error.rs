// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Why a packet could not be built or read
//!
//! One error type for the whole module. Most builders write fixed-size headers
//! into buffers they allocate and cannot fail; the rest fail in three ways. A
//! caller can describe a packet no header can measure ([`TooLong`],
//! [`OptionsTooLong`], [`OptionsMisaligned`], [`UnwritableName`]), ask for
//! something the protocols do not offer ([`FamilyMismatch`], [`WrongFamily`],
//! [`MtuTooSmall`], [`HeaderHasOptions`]), or hand a reader bytes that are not
//! what they were read as ([`Truncated`], [`Unreadable`], [`UnexpectedMessage`],
//! [`UnsupportedEtherType`]). Under promiscuous capture the last group is
//! ordinary.
//!
//! [`TooLong`]: PacketError::TooLong
//! [`OptionsTooLong`]: PacketError::OptionsTooLong
//! [`OptionsMisaligned`]: PacketError::OptionsMisaligned
//! [`UnwritableName`]: PacketError::UnwritableName
//! [`FamilyMismatch`]: PacketError::FamilyMismatch
//! [`WrongFamily`]: PacketError::WrongFamily
//! [`MtuTooSmall`]: PacketError::MtuTooSmall
//! [`HeaderHasOptions`]: PacketError::HeaderHasOptions
//! [`Truncated`]: PacketError::Truncated
//! [`Unreadable`]: PacketError::Unreadable
//! [`UnexpectedMessage`]: PacketError::UnexpectedMessage
//! [`UnsupportedEtherType`]: PacketError::UnsupportedEtherType

use std::net::IpAddr;

/// Why a packet could not be built, or a captured one could not be read.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    /// A length field cannot represent a packet this large.
    ///
    /// The IP length fields and UDP's are 16 bits and count the header, so each
    /// payload limit is slightly under 64 KiB. Wrapping the field instead would
    /// describe a packet shorter than its own header, which receivers drop and the
    /// scan would read as a firewall.
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
    /// TCP and UDP checksum over a pseudo-header built from both addresses. A
    /// caller mistake; nothing on the wire produces it. See also
    /// [`WrongFamily`](Self::WrongFamily), where the addresses agree with each
    /// other but not with the protocol.
    #[error("cannot checksum from {src} to {dst}: an IPv4 and an IPv6 address")]
    FamilyMismatch {
        /// The source that was given.
        src: IpAddr,
        /// The destination that was given.
        dst: IpAddr,
    },

    /// A checksum was asked for over an address family the protocol it belongs
    /// to does not have.
    ///
    /// ICMPv6 checksums over an IPv6 pseudo-header and has no IPv4 form, so an
    /// ICMPv6 layer inside an IPv4 header cannot be built. The addresses agree
    /// with each other here, unlike [`FamilyMismatch`](Self::FamilyMismatch).
    #[error("an {protocol} checksum covers {expected} addresses, and {got} is not one")]
    WrongFamily {
        /// The protocol whose checksum was being computed, such as `"ICMPv6"`.
        protocol: &'static str,
        /// The family it needs, such as `"IPv6"`.
        expected: &'static str,
        /// One of the addresses that was given.
        got: IpAddr,
    },

    /// A datagram was handed to the fragmenter with an MTU too small to split
    /// it into any useful piece.
    ///
    /// A fragment offset counts eight-byte units, so each fragment must carry at
    /// least one unit past the header. A smaller MTU would loop forever emitting
    /// empty fragments.
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
    /// Each option's high bit says whether it is copied into every fragment or
    /// kept on the first only (RFC 791 §3.1). The fragmenter does not honour that
    /// bit, so receivers would reassemble the wrong header.
    #[error("cannot fragment an IPv4 header carrying {options} bytes of options")]
    HeaderHasOptions {
        /// How many option bytes the header carried.
        options: usize,
    },

    /// A header's options do not fit the field that measures them.
    ///
    /// IPv4's header length and TCP's data offset are four bits counting
    /// four-byte words: at most sixty bytes of header, forty of them options. The
    /// field wraps, so forty-four bytes of options would declare a header zero
    /// words long.
    #[error(
        "{what} carrying {options} bytes of options cannot be measured: its length field holds at most {limit}"
    )]
    OptionsTooLong {
        /// Which header, such as `"an IPv4 header"`.
        what: &'static str,
        /// How many option bytes were given.
        options: usize,
        /// The most that field can describe, in bytes.
        limit: usize,
    },

    /// A header's options are not a whole number of four-byte words.
    ///
    /// The field counts words, so a receiver would read the odd bytes as payload.
    /// Padding to the boundary is the caller's job.
    #[error(
        "{what} carrying {options} bytes of options is not a whole number of the four-byte words its length field counts"
    )]
    OptionsMisaligned {
        /// Which header, such as `"a TCP header"`.
        what: &'static str,
        /// How many option bytes were given.
        options: usize,
    },

    /// A frame carried something this module does not read.
    ///
    /// Ordinary under promiscuous capture. The EtherType is named so a caller
    /// debugging a missed host can tell "arrived and was not understood" from
    /// "never arrived".
    #[error("nothing here reads ethertype {0:#06x}")]
    UnsupportedEtherType(u16),

    /// Bytes that are not the message they were read as.
    ///
    /// A message whose structure never held, as opposed to
    /// [`Truncated`](Self::Truncated): a length pointing past its own record, a
    /// label the name grammar does not allow, a value its field has no room for.
    /// `detail` carries what the reader that found it said.
    #[error("{what} could not be read: {detail}")]
    Unreadable {
        /// What was being read, such as `"a DNS response"`.
        what: &'static str,
        /// What the reader said about it.
        detail: String,
    },

    /// A message of the right protocol and the wrong kind.
    ///
    /// It parsed but is not what was asked for, such as a DNS query arriving
    /// where a response was expected. Worth telling apart because a query on that
    /// socket means somebody is asking.
    #[error("expected {expected} and got {got}")]
    UnexpectedMessage {
        /// What the reader was looking for, such as `"a DNS response"`.
        expected: &'static str,
        /// What arrived instead, such as `"a query"`.
        got: &'static str,
    },

    /// A name has no wire form, so no message could be built around it.
    ///
    /// DNS spells a name as length-prefixed labels with a one-byte prefix whose
    /// top two bits are reserved for compression, capping a label at 63 octets and
    /// a name at 255 (RFC 1035 §2.3.4).
    #[error("{name} is not a name this can write: {detail}")]
    UnwritableName {
        /// The name that was given.
        name: String,
        /// Which bound it broke, and by how much.
        detail: String,
    },

    /// A buffer held too few bytes to read the header it was supposed to
    /// contain, as a truncated capture does.
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

    /// Checks that `options` can be measured by a four-bit field counting
    /// four-byte words, as both IPv4 and TCP use.
    pub(crate) fn check_options(
        what: &'static str,
        options: usize,
    ) -> std::result::Result<(), Self> {
        /// Four bits of words, less the five words of fixed header both have.
        const LARGEST: usize = (15 - 5) * 4;

        if !options.is_multiple_of(4) {
            return Err(Self::OptionsMisaligned { what, options });
        }
        if options > LARGEST {
            return Err(Self::OptionsTooLong {
                what,
                options,
                limit: LARGEST,
            });
        }
        Ok(())
    }

    /// The error for `what` whose structure did not hold, carrying whatever the
    /// reader that found it said.
    pub(crate) fn unreadable(what: &'static str, detail: impl std::fmt::Display) -> Self {
        Self::Unreadable {
            what,
            detail: detail.to_string(),
        }
    }

    /// The error for a name that cannot be spelled in DNS's label encoding.
    pub(crate) fn unwritable_name(name: &str, detail: impl std::fmt::Display) -> Self {
        Self::UnwritableName {
            name: name.to_string(),
            detail: detail.to_string(),
        }
    }
}

/// What every builder and parser in this module returns.
pub type Result<T> = std::result::Result<T, PacketError>;
