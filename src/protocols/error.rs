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
//! actually go wrong. There are fewer of those than the signatures suggest: most
//! builders here write fixed-size headers into buffers they allocate themselves,
//! which cannot fail, and they say so by returning a packet rather than a
//! `Result`.
//!
//! What remains falls in three groups. A caller can describe a packet no header
//! can measure ([`TooLong`], [`OptionsTooLong`], [`OptionsMisaligned`],
//! [`UnwritableName`]), ask for something the protocols do not offer
//! ([`FamilyMismatch`], [`WrongFamily`], [`MtuTooSmall`], [`HeaderHasOptions`],
//! [`UnsupportedFragmentation`]), or hand a reader bytes that are not what they
//! were read as ([`Truncated`], [`Unreadable`], [`UnexpectedMessage`],
//! [`UnsupportedEtherType`]).
//!
//! The last group is the one that arrives rather than being caused, and under
//! promiscuous capture most of it is ordinary. See [`PacketError`] for which is
//! which.
//!
//! [`TooLong`]: PacketError::TooLong
//! [`OptionsTooLong`]: PacketError::OptionsTooLong
//! [`OptionsMisaligned`]: PacketError::OptionsMisaligned
//! [`UnwritableName`]: PacketError::UnwritableName
//! [`FamilyMismatch`]: PacketError::FamilyMismatch
//! [`WrongFamily`]: PacketError::WrongFamily
//! [`MtuTooSmall`]: PacketError::MtuTooSmall
//! [`HeaderHasOptions`]: PacketError::HeaderHasOptions
//! [`UnsupportedFragmentation`]: PacketError::UnsupportedFragmentation
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
    ///
    /// Distinct from [`WrongFamily`](Self::WrongFamily), which is two addresses
    /// that agree with each other and not with the protocol between them.
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
    /// ICMPv6 is the case this exists for: its checksum covers an IPv6
    /// pseudo-header and there is no IPv4 form of the message, so an ICMPv6
    /// layer inside an IPv4 header is a packet nothing can build. Reported apart
    /// from [`FamilyMismatch`](Self::FamilyMismatch) because the two addresses
    /// agree here, and saying they do not sends a reader after the wrong fault.
    #[error("an {protocol} checksum covers {expected} addresses, and {got} is not one")]
    WrongFamily {
        /// The protocol whose checksum was being computed, such as `"ICMPv6"`.
        protocol: &'static str,
        /// The family it needs, such as `"IPv6"`.
        expected: &'static str,
        /// One of the addresses that was given instead.
        got: IpAddr,
    },

    /// A datagram was handed to the fragmenter with an MTU too small to split
    /// it into any useful piece.
    ///
    /// A fragment offset counts eight-byte units, so the smallest step a
    /// fragment can make through the datagram is one unit past the header. An
    /// MTU that will not hold even that carries no payload at all, and splitting
    /// to fit it would emit headers forever without reaching the end, so it is
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

    /// A datagram was handed to the fragmenter for a family this engine does
    /// not fragment.
    ///
    /// IPv6 puts fragmentation in an extension header rather than in the header
    /// itself, and a sender is meant to discover the path MTU instead of
    /// splitting on the way out. Nothing here builds that header, so the request
    /// is refused by name rather than answered with a datagram that is not
    /// fragmented at all.
    #[error(
        "cannot fragment to {dst}: IPv6 fragments through an extension header this engine does not build"
    )]
    UnsupportedFragmentation {
        /// The destination that was asked for.
        dst: IpAddr,
    },

    /// A header's options do not fit the field that measures them.
    ///
    /// Both IPv4's header length and TCP's data offset are four bits counting
    /// four-byte words, so each describes at most fifteen of them: sixty bytes
    /// of header, forty of which are options. A longer run cannot be measured,
    /// and the field wraps rather than saturating, so forty-four bytes of options
    /// produce a header declaring itself zero words long.
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
    /// The field that measures them counts words, so a run that is not a
    /// multiple of four is rounded down and the odd bytes are read as payload
    /// by whatever receives the packet. Padding options to the boundary is the
    /// caller's job, and this is what says they did not.
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
    /// Not a malformed frame and not a fault. A promiscuous capture sees the
    /// whole segment's traffic, so most of what arrives is somebody else's, and
    /// the ethertype is named so a caller debugging a missed host can tell
    /// "arrived and was not understood" from "never arrived".
    #[error("nothing here reads ethertype {0:#06x}")]
    UnsupportedEtherType(u16),

    /// Bytes that are not the message they were read as.
    ///
    /// Distinct from [`Truncated`](Self::Truncated), which is a message that
    /// stopped early. This is one whose structure never held: a length pointing
    /// past its own record, a label the name grammar does not allow, a field
    /// carrying a value its type has no room for. Whatever the reader that
    /// found it says goes in `detail`, because that reader knows and this type
    /// does not.
    #[error("{what} could not be read: {detail}")]
    Unreadable {
        /// What was being read, such as `"a DNS response"`.
        what: &'static str,
        /// What the reader said about it.
        detail: String,
    },

    /// A message of the right protocol and the wrong kind.
    ///
    /// Not malformed and not truncated: it parsed, and it is not what was
    /// asked for. A DNS query arriving where a response was expected is the
    /// case this exists for, and it is worth telling apart because a query on
    /// that socket means something (somebody is asking) rather than nothing.
    #[error("expected {expected} and got {got}")]
    UnexpectedMessage {
        /// What the reader was looking for, such as `"a DNS response"`.
        expected: &'static str,
        /// What arrived instead, such as `"a query"`.
        got: &'static str,
    },

    /// A name has no wire form, so no message could be built around it.
    ///
    /// DNS spells a name as length-prefixed labels, and the prefix is one byte
    /// with its top two bits reserved for compression pointers. That caps a
    /// label at 63 octets and a whole name at 255 (RFC 1035 §2.3.4). A name past
    /// either bound is refused here rather than encoded into a message no
    /// resolver will read back.
    #[error("{name} is not a name this can write: {detail}")]
    UnwritableName {
        /// The name that was given.
        name: String,
        /// Which bound it broke, and by how much.
        detail: String,
    },

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

    /// Checks that `options` can be measured by a four-bit field counting
    /// four-byte words, which is what both IPv4 and TCP use.
    ///
    /// Shared because the two headers have the same field in the same shape, and
    /// a bound written twice is a bound that comes to disagree with itself.
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
