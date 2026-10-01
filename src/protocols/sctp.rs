// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # SCTP probes
//!
//! Builds the packet an SCTP port scan puts on the wire and reads the packet
//! that comes back. What a reply means about a port is the scanner's to decide,
//! as with [`tcp`](super::tcp).
//!
//! ## Two probes, and the answers they draw
//!
//! An INIT scan sends an INIT chunk and reads the chunk that answers. RFC 4960
//! fixes two decisive answers:
//!
//! - INIT-ACK (§5.1): an endpoint willing to open an association. The port is
//!   open.
//! - ABORT (§8.4): a reachable stack refusing the association because nothing
//!   listens on that port. The port is closed.
//!
//! An endpoint that is up answers an INIT either way, so silence means the
//! probe or the reply was stopped on the way.
//!
//! A COOKIE-ECHO scan draws only one of those answers. RFC 4960 §8.4 hands an
//! out-of-the-blue COOKIE-ECHO to the cookie authentication of §5.1, which a
//! listener fails and then drops silently; a port with no endpoint answers an
//! unrecognised packet with an ABORT. So an ABORT is a closed port and silence
//! is everything else.
//!
//! What an answer means about a port belongs to
//! [`SctpScanTechnique`](crate::model::technique::SctpScanTechnique); see
//! [`classify_probe_response`].
//!
//! ## Where the nonce lives
//!
//! Both probes recover their nonce from the reply's verification tag, but put
//! it in different fields.
//!
//! An INIT carries a 32-bit Initiate Tag that a listener's INIT-ACK and a closed
//! port's ABORT both echo as their common-header verification tag (RFC 4960
//! §3.3.2, §8.4). The INIT's own verification tag is zero, as §8.5.1 requires.
//!
//! A COOKIE-ECHO has no Initiate Tag. §8.4 obliges the ABORT to reflect the
//! offending packet's verification tag and set the T bit, so the nonce goes in
//! the common header.
//!
//! [`echoed_nonce`] reads either. They differ in what survives an ICMP error: a
//! quotation is only guaranteed to reach the first eight bytes (the ports and
//! the common header's tag). That names a COOKIE-ECHO's exact attempt and not
//! an INIT's, whose Initiate Tag sits sixteen bytes in. See [`quoted_probe`] and
//! [`quoted_init_tag`], and [`tcp::quoted_nonce`](super::tcp::quoted_nonce) for
//! the TCP equivalent.
//!
//! ## The checksum is a CRC32c
//!
//! SCTP carries a CRC32c (RFC 3309, RFC 4960 §6.8) over the whole packet with
//! the field zeroed, written into the field **little-endian**. It covers no
//! pseudo-header, so building a probe needs no addresses. The computation lives
//! in [`craft`].

use crate::model::technique::SctpReply;
use crate::protocols::craft;
use crate::protocols::error::{PacketError, Result};
use crate::protocols::sizes::{SCTP_CHUNK_HDR_LEN, SCTP_COMMON_HDR_LEN};

/// The IANA protocol number SCTP is carried under in an IP header (RFC 4960
/// §1.7), for a caller writing `protocol` / `next_header` by hand.
pub const IP_PROTOCOL_NUMBER: u8 = 132;

/// SCTP chunk type numbers, from the registry in RFC 4960 §3.2.
///
/// Only those a scan builds or reads.
pub mod chunk_type {
    /// Requests a new association. The probe an INIT scan sends.
    pub const INIT: u8 = 1;
    /// Accepts an association attempt: an open port's answer to an INIT.
    pub const INIT_ACK: u8 = 2;
    /// Refuses an association outright: a closed port's answer to an INIT.
    pub const ABORT: u8 = 6;
    /// Replays a state cookie. The chunk a COOKIE-ECHO scan sends, with a cookie
    /// no endpoint minted, so only a stack with nothing listening answers.
    pub const COOKIE_ECHO: u8 = 10;
}

/// The receive window an INIT advertises, in bytes.
///
/// Immaterial to classification, but a peer reads it, so it is one plausible
/// value across every probe. Mirrors [`tcp`](super::tcp)'s advertised window.
const ADVERTISED_RWND: u32 = 65_535;

/// The number of outbound streams an INIT asks to open, and the number of
/// inbound streams it will accept. Ordinary client values, and immaterial to
/// whether a port answers.
const OUTBOUND_STREAMS: u16 = 10;
const INBOUND_STREAMS: u16 = 65_535;

/// Builds an INIT-scan probe from `src_port` to `dst_port`, carrying
/// `initiate_tag` as the nonce a reply will echo.
///
/// The common-header verification tag is zero, as RFC 4960 §8.5.1 requires of
/// a packet carrying an INIT. A conformant peer copies `initiate_tag` into its
/// reply's verification tag whether it answers INIT-ACK or ABORT, and the
/// caller recovers it with [`echoed_nonce`].
///
/// `initiate_tag` must be non-zero (RFC 4960 §3.3.2); a random tag per probe
/// meets that and makes correlation trustworthy. A zero tag is the caller's to
/// avoid, as with [`tcp::build_probe`](super::tcp::build_probe)'s nonce.
///
/// Infallible: the checksum covers no pseudo-header and the INIT chunk is a
/// fixed size.
pub fn build_init_probe(src_port: u16, dst_port: u16, initiate_tag: u32) -> Vec<u8> {
    craft::Sctp::new(src_port, dst_port)
        .with_chunks(init_chunk(initiate_tag))
        .to_bytes()
}

/// The INIT chunk [`build_init_probe`] carries, twenty bytes with no
/// optional parameters.
fn init_chunk(initiate_tag: u32) -> Vec<u8> {
    let mut value = Vec::with_capacity(16);
    value.extend_from_slice(&initiate_tag.to_be_bytes());
    value.extend_from_slice(&ADVERTISED_RWND.to_be_bytes());
    value.extend_from_slice(&OUTBOUND_STREAMS.to_be_bytes());
    value.extend_from_slice(&INBOUND_STREAMS.to_be_bytes());
    // Initial TSN. Nothing reads it back; a random value is what an ordinary
    // stack sends.
    value.extend_from_slice(&rand::random::<u32>().to_be_bytes());
    chunk(chunk_type::INIT, 0, &value).expect("a sixteen-byte value fits the length field")
}

/// Builds a COOKIE-ECHO scan probe from `src_port` to `dst_port`, carrying
/// `verification_tag` as the nonce a refusal will reflect.
///
/// The tag goes in the common header, the field RFC 4960 §8.4 obliges an
/// out-of-the-blue ABORT to send back. The chunk's value is the cookie, opaque
/// to all but the endpoint that minted it.
///
/// `verification_tag` should be non-zero, so a reflected tag is
/// distinguishable from a packet that carried none.
///
/// The cookie is random bytes; no value could authenticate, so its content
/// cannot change a verdict. Its length can: an empty chunk is a plausible
/// protocol violation that a stack might answer with an ABORT, making an open
/// port look closed. A realistically sized cookie takes the authentication
/// path this scan reads.
pub fn build_cookie_echo_probe(src_port: u16, dst_port: u16, verification_tag: u32) -> Vec<u8> {
    craft::Sctp::new(src_port, dst_port)
        .with_verification_tag(verification_tag)
        .with_chunks(cookie_echo_chunk())
        .to_bytes()
}

/// How many bytes of cookie a COOKIE-ECHO probe carries.
///
/// RFC 4960 fixes no length; real implementations mint cookies from a few
/// dozen bytes upward. The bytes are random per probe.
const COOKIE_LEN: usize = 32;

/// The COOKIE-ECHO chunk [`build_cookie_echo_probe`] carries.
fn cookie_echo_chunk() -> Vec<u8> {
    let cookie: [u8; COOKIE_LEN] = rand::random();
    chunk(chunk_type::COOKIE_ECHO, 0, &cookie).expect("a fixed short cookie fits the length field")
}

/// The largest value a chunk may carry: what is left of the 16-bit length field
/// once the four bytes of chunk header it also counts are taken out.
pub const MAX_CHUNK_VALUE: usize = u16::MAX as usize - SCTP_CHUNK_HDR_LEN;

/// Encodes one chunk: the four-byte header, the value, and the padding that
/// aligns whatever follows to a four-byte boundary.
///
/// The length field counts the header and value but **not** the padding (RFC
/// 4960 §3.2), so a reader steps by the padded length and trusts the field for
/// where the value ends. Exposed so other chunk types can be built in a few
/// lines.
///
/// # Errors
///
/// [`PacketError::TooLong`] for a value past [`MAX_CHUNK_VALUE`]. The field
/// wraps, so a value four bytes short of 64 KiB would declare a zero-length
/// chunk, which receivers read as the end of the packet.
pub fn chunk(chunk_type: u8, flags: u8, value: &[u8]) -> Result<Vec<u8>> {
    if value.len() > MAX_CHUNK_VALUE {
        return Err(PacketError::too_long(
            "an SCTP chunk length",
            SCTP_CHUNK_HDR_LEN,
            value.len(),
        ));
    }
    let length = SCTP_CHUNK_HDR_LEN + value.len();

    let mut bytes = Vec::with_capacity(round_up_to_4(length));
    bytes.push(chunk_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(length as u16).to_be_bytes());
    bytes.extend_from_slice(value);
    bytes.resize(round_up_to_4(length), 0);
    Ok(bytes)
}

/// A view over a received SCTP packet: the common header, and an iterator over
/// the chunks after it.
///
/// Borrows the bytes, and holds the common header as a `[u8; 12]` split off at
/// construction, so no accessor can index past it whatever constructs a
/// `Segment`.
#[derive(Debug, Clone, Copy)]
pub struct Segment<'a> {
    header: &'a [u8; SCTP_COMMON_HDR_LEN],
    chunks: &'a [u8],
}

impl<'a> Segment<'a> {
    /// The port the packet came from.
    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes([self.header[0], self.header[1]])
    }

    /// The port it was aimed at: for a reply, the scan's source port.
    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes([self.header[2], self.header[3]])
    }

    /// The verification tag. In a reply to an INIT this is the Initiate Tag the
    /// probe carried, echoed back; see [`echoed_nonce`].
    pub fn verification_tag(&self) -> u32 {
        u32::from_be_bytes([
            self.header[4],
            self.header[5],
            self.header[6],
            self.header[7],
        ])
    }

    /// The chunks after the common header.
    pub fn chunks(&self) -> Chunks<'a> {
        Chunks { rest: self.chunks }
    }
}

/// One chunk of a [`Segment`], as read from the wire.
///
/// Not `#[non_exhaustive]`: RFC 4960 §3.2 defines a chunk as a type byte, a
/// flags byte, a length and the value, and there is nothing else to read.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk<'a> {
    /// What kind of chunk it is. See [`chunk_type`].
    pub chunk_type: u8,
    /// The chunk's flag bits, whose meaning depends on the type.
    pub flags: u8,
    /// The chunk's value, without the four-byte header or the trailing padding.
    ///
    /// **Cut to what arrived, which may be less than the length field claimed.**
    /// A capture stopped at its snapshot length, or a sender omitting the padding
    /// on a last chunk, leaves fewer bytes than declared, indistinguishable from a
    /// whole chunk. The walk clamps so the chunk's type still classifies the
    /// answer; a reader wanting a field from the value must use `get`, not
    /// indexing. An INIT-ACK cut after its header yields an empty value.
    pub value: &'a [u8],
}

/// Walks the chunks of a [`Segment`], outermost first.
///
/// A chunk claiming fewer than its four header bytes cannot say where the next
/// one starts, so iteration ends there. A missed chunk credits nothing; a loop
/// that never advances would hang the receive path.
#[derive(Debug, Clone, Copy)]
pub struct Chunks<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Chunks<'a> {
    type Item = Chunk<'a>;

    fn next(&mut self) -> Option<Chunk<'a>> {
        if self.rest.len() < SCTP_CHUNK_HDR_LEN {
            return None;
        }

        let chunk_type = self.rest[0];
        let flags = self.rest[1];
        let length = usize::from(u16::from_be_bytes([self.rest[2], self.rest[3]]));

        // A length that does not clear the header would never advance the cursor.
        if length < SCTP_CHUNK_HDR_LEN {
            return None;
        }

        // A sender may omit the last chunk's padding and a capture may be cut
        // short, so the value and the step are clamped to what is present.
        let value_end = length.min(self.rest.len());
        let value = &self.rest[SCTP_CHUNK_HDR_LEN..value_end];
        let advance = round_up_to_4(length).min(self.rest.len());
        self.rest = &self.rest[advance..];

        Some(Chunk {
            chunk_type,
            flags,
            value,
        })
    }
}

/// Reads `bytes` as an SCTP packet.
///
/// # Errors
///
/// [`PacketError::Truncated`] when there are too few bytes for the common
/// header. The checksum is not validated: a reply is correlated by its
/// verification tag.
pub fn parse(bytes: &'_ [u8]) -> Result<Segment<'_>> {
    let Some((header, chunks)) = bytes.split_first_chunk::<SCTP_COMMON_HDR_LEN>() else {
        return Err(PacketError::truncated(
            "an SCTP packet",
            SCTP_COMMON_HDR_LEN,
            bytes.len(),
        ));
    };
    Ok(Segment { header, chunks })
}

/// Classifies a received packet as one of the two answers an SCTP port probe can
/// draw, if it is one.
///
/// `None` for anything else (a heartbeat, a shutdown, another association's
/// chunk), which a caller treats as noise. An INIT-ACK is read ahead of
/// anything bundled behind it, as
/// [`tcp::classify_probe_response`](super::tcp::classify_probe_response) reads
/// a RST first; the two never legitimately arrive together.
pub fn classify_probe_response(segment: &Segment<'_>) -> Option<SctpReply> {
    for chunk in segment.chunks() {
        match chunk.chunk_type {
            chunk_type::INIT_ACK => return Some(SctpReply::InitAck),
            chunk_type::ABORT => return Some(SctpReply::Abort),
            _ => {}
        }
    }
    None
}

/// The nonce `reply` implies: the verification tag a conformant peer echoed from
/// the Initiate Tag it was sent.
///
/// A caller compares this against the tags it sent. A match names the probe
/// that was answered; anything else (a stray, a duplicate, another
/// association) must not resolve a port.
pub fn echoed_nonce(reply: &Segment<'_>) -> u32 {
    reply.verification_tag()
}

/// A probe's common header as an ICMP error quotes it back.
///
/// RFC 792 guarantees only the IP header plus the offending packet's first
/// eight bytes: for SCTP, the two ports and the verification tag. That says a
/// probe was this scan's but not which attempt, since an INIT's tag is zero
/// and its Initiate Tag lies past the eight. See [`quoted_init_tag`].
///
/// `#[non_exhaustive]`, as
/// [`tcp::QuotedProbe`](crate::protocols::tcp::QuotedProbe) is: more of the
/// quotation may be read when a sender includes it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotedProbe {
    /// The port the probe was sent from, which proves the quoted packet belongs
    /// to this scan.
    pub source: u16,
    /// The port it was aimed at.
    pub destination: u16,
    /// The common-header verification tag, zero for a quoted INIT.
    pub verification_tag: u32,
}

/// Reads what an ICMP error quoted of an SCTP probe, or `None` if the quotation
/// is too short to name one.
///
/// The error's sender chose every byte, so nothing past the eight RFC 792
/// guarantees is assumed.
pub fn quoted_probe(quoted: &[u8]) -> Option<QuotedProbe> {
    let head: &[u8; 8] = quoted.first_chunk()?;
    Some(QuotedProbe {
        source: u16::from_be_bytes([head[0], head[1]]),
        destination: u16::from_be_bytes([head[2], head[3]]),
        verification_tag: u32::from_be_bytes([head[4], head[5], head[6], head[7]]),
    })
}

/// The Initiate Tag a quoted INIT carried, or `None` when the quotation stopped
/// short of it or did not begin with an INIT.
///
/// The tag names the exact attempt but sits sixteen bytes in, past the common
/// header and the INIT chunk header, so only a sender quoting past the
/// guaranteed eight reveals it.
///
/// With `None`, nothing ties the error to an attempt: not the ports (see
/// [`tcp::quoted_nonce`](super::tcp::quoted_nonce)), and not the verification
/// tag, which RFC 4960 §8.5.1 requires to be zero on every INIT. The engine's
/// INIT scan acts on no error without the tag.
pub fn quoted_init_tag(quoted: &[u8]) -> Option<u32> {
    let head: &[u8; 20] = quoted.first_chunk()?;
    // Byte twelve is the first chunk's type; the tag is read only if that chunk
    // is an INIT.
    (head[SCTP_COMMON_HDR_LEN] == chunk_type::INIT)
        .then(|| u32::from_be_bytes([head[16], head[17], head[18], head[19]]))
}

/// Rounds `n` up to the next multiple of four, the boundary every SCTP chunk is
/// aligned to.
const fn round_up_to_4(n: usize) -> usize {
    (n + 3) & !3
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

    const SRC_PORT: u16 = 50_000;
    const DST_PORT: u16 = 9;
    const NONCE: u32 = 0xDEAD_BEEF;

    /// A conformant reply: the common header carrying `vtag`, then a single
    /// chunk of `chunk_type`. Built from the wire layout, independent of
    /// [`parse`] and [`classify_probe_response`].
    fn reply(vtag: u32, chunk_type: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&DST_PORT.to_be_bytes()); // from the port we hit
        bytes.extend_from_slice(&SRC_PORT.to_be_bytes()); // back to where we sent
        bytes.extend_from_slice(&vtag.to_be_bytes());
        bytes.extend_from_slice(&[0; 4]); // checksum, unread by the parser
        bytes.extend_from_slice(&chunk(chunk_type, 0, &[]).expect("an empty value fits"));
        bytes
    }

    // ── Probe construction ───────────────────────────────────────────────────

    /// The probe is a well-formed INIT: the requested ports, a zeroed
    /// verification tag per RFC 4960 §8.5.1, and its nonce in the Initiate Tag.
    #[test]
    fn an_init_probe_is_framed_the_way_a_peer_expects() {
        let bytes = build_init_probe(SRC_PORT, DST_PORT, NONCE);
        let segment = parse(&bytes).expect("the probe parses");

        assert_eq!(segment.source_port(), SRC_PORT);
        assert_eq!(segment.destination_port(), DST_PORT);
        assert_eq!(
            segment.verification_tag(),
            0,
            "a packet carrying an INIT must have a zero verification tag"
        );

        let mut chunks = segment.chunks();
        let init = chunks.next().expect("one chunk");
        assert_eq!(init.chunk_type, chunk_type::INIT);
        assert_eq!(init.value.len(), 16, "INIT has a sixteen-byte fixed part");
        assert_eq!(
            u32::from_be_bytes(init.value[0..4].try_into().unwrap()),
            NONCE,
            "the Initiate Tag carries the nonce"
        );
        assert!(chunks.next().is_none(), "the probe sends nothing else");
        assert_eq!(bytes.len(), SCTP_COMMON_HDR_LEN + 20);
    }

    /// A COOKIE-ECHO carries its nonce in the common header, where RFC 4960 §8.4
    /// obliges an out-of-the-blue ABORT to send it back from.
    #[test]
    fn a_cookie_echo_probe_carries_its_nonce_in_the_common_header() {
        let bytes = build_cookie_echo_probe(SRC_PORT, DST_PORT, NONCE);
        let segment = parse(&bytes).expect("the probe parses");

        assert_eq!(segment.source_port(), SRC_PORT);
        assert_eq!(segment.destination_port(), DST_PORT);
        assert_eq!(
            segment.verification_tag(),
            NONCE,
            "the verification tag carries the nonce a refusal reflects"
        );

        let mut chunks = segment.chunks();
        let cookie = chunks.next().expect("one chunk");
        assert_eq!(cookie.chunk_type, chunk_type::COOKIE_ECHO);
        assert_eq!(cookie.value.len(), COOKIE_LEN);
        assert!(chunks.next().is_none(), "the probe sends nothing else");
    }

    /// The cookie is random per probe.
    #[test]
    fn two_cookie_echo_probes_do_not_carry_the_same_cookie() {
        let first = build_cookie_echo_probe(SRC_PORT, DST_PORT, NONCE);
        let second = build_cookie_echo_probe(SRC_PORT, DST_PORT, NONCE);
        assert_ne!(first, second);
    }

    /// The cookie is not empty: a stack might answer an empty COOKIE-ECHO with
    /// an ABORT, making an open port look closed.
    #[test]
    fn a_cookie_echo_probe_carries_a_cookie_worth_authenticating() {
        let bytes = build_cookie_echo_probe(SRC_PORT, DST_PORT, NONCE);
        let segment = parse(&bytes).expect("parses");
        let cookie = segment.chunks().next().expect("one chunk");
        assert!(!cookie.value.is_empty());
    }

    /// Both probes leave with a checksum a receiver will accept.
    #[test]
    fn a_cookie_echo_probe_carries_a_valid_crc32c() {
        let bytes = build_cookie_echo_probe(SRC_PORT, DST_PORT, NONCE);

        let mut zeroed = bytes.clone();
        zeroed[8..12].copy_from_slice(&[0; 4]);
        assert_eq!(&bytes[8..12], &craft::crc32c(&zeroed).to_le_bytes());
    }

    /// The probe carries a valid CRC32c, over the packet with the field zeroed
    /// and written little-endian, recomputed here as a receiver would.
    #[test]
    fn an_init_probe_carries_a_valid_crc32c() {
        let bytes = build_init_probe(SRC_PORT, DST_PORT, NONCE);

        let mut zeroed = bytes.clone();
        zeroed[8..12].copy_from_slice(&[0; 4]);
        let expected = craft::crc32c(&zeroed);

        assert_eq!(
            &bytes[8..12],
            &expected.to_le_bytes(),
            "the checksum verifies, and is little-endian on the wire"
        );
    }

    // ── Correlation and classification ───────────────────────────────────────

    /// An open port answers with an INIT-ACK, a closed one with an ABORT, and
    /// both echo the probe's Initiate Tag as their verification tag.
    #[test]
    fn an_init_ack_reads_as_open_and_an_abort_as_closed() {
        let init_ack_bytes = reply(NONCE, chunk_type::INIT_ACK);
        let init_ack = parse(&init_ack_bytes).expect("parses");
        assert_eq!(classify_probe_response(&init_ack), Some(SctpReply::InitAck));
        assert_eq!(echoed_nonce(&init_ack), NONCE);

        let abort_bytes = reply(NONCE, chunk_type::ABORT);
        let abort = parse(&abort_bytes).expect("parses");
        assert_eq!(classify_probe_response(&abort), Some(SctpReply::Abort));
        assert_eq!(echoed_nonce(&abort), NONCE);
    }

    /// A reply to another association does not carry the tag we sent.
    #[test]
    fn a_reply_to_another_association_yields_a_different_nonce() {
        let theirs_bytes = reply(NONCE ^ 0x1234, chunk_type::INIT_ACK);
        let theirs = parse(&theirs_bytes).expect("parses");
        assert_ne!(echoed_nonce(&theirs), NONCE);
    }

    /// Chunks that are not one of the two decisive answers are noise.
    #[test]
    fn an_unrelated_chunk_answers_no_probe() {
        // Type 4 is HEARTBEAT, type 11 COOKIE-ACK: neither settles an INIT scan.
        for chunk_type in [4u8, 11] {
            let bytes = reply(NONCE, chunk_type);
            let other = parse(&bytes).expect("parses");
            assert_eq!(classify_probe_response(&other), None, "chunk {chunk_type}");
        }
    }

    /// A chunk whose length field cannot advance the cursor ends iteration.
    #[test]
    fn a_chunk_length_that_cannot_advance_stops_iteration() {
        let mut bytes = reply(NONCE, chunk_type::ABORT);
        // Overwrite the ABORT's length field with one below the header size.
        let length_at = SCTP_COMMON_HDR_LEN + 2;
        bytes[length_at..length_at + 2].copy_from_slice(&1u16.to_be_bytes());

        let segment = parse(&bytes).expect("parses");
        assert_eq!(segment.chunks().count(), 0, "the walk terminates");
        assert_eq!(classify_probe_response(&segment), None);
    }

    // ── Quotation ────────────────────────────────────────────────────────────

    /// The eight bytes an ICMP error is guaranteed to quote name the probe's
    /// ports and its zero verification tag; the Initiate Tag needs a longer
    /// quotation.
    #[test]
    fn a_quoted_probe_needs_a_generous_quotation_to_name_its_attempt() {
        let bytes = build_init_probe(SRC_PORT, DST_PORT, NONCE);

        let quoted = quoted_probe(&bytes[..8]).expect("eight bytes are enough");
        assert_eq!(quoted.source, SRC_PORT);
        assert_eq!(quoted.destination, DST_PORT);
        assert_eq!(quoted.verification_tag, 0);

        assert_eq!(
            quoted_init_tag(&bytes[..8]),
            None,
            "the tag is past the eight"
        );
        assert_eq!(
            quoted_init_tag(&bytes),
            Some(NONCE),
            "a full quote names it"
        );
    }

    /// A COOKIE-ECHO keeps its nonce in the common header, so the eight bytes
    /// RFC 792 guarantees name the exact attempt; an INIT's do not.
    #[test]
    fn a_quoted_cookie_echo_names_its_attempt_from_the_guaranteed_eight() {
        let bytes = build_cookie_echo_probe(SRC_PORT, DST_PORT, NONCE);

        let quoted = quoted_probe(&bytes[..8]).expect("eight bytes are enough");
        assert_eq!(quoted.source, SRC_PORT);
        assert_eq!(quoted.destination, DST_PORT);
        assert_eq!(
            quoted.verification_tag, NONCE,
            "the attempt is named without a generous quotation"
        );

        assert_eq!(
            quoted_init_tag(&bytes),
            None,
            "the INIT reader must not claim a tag from another chunk"
        );
    }

    #[test]
    fn a_quotation_too_short_for_the_common_header_names_nothing() {
        let bytes = build_init_probe(SRC_PORT, DST_PORT, NONCE);
        assert_eq!(quoted_probe(&bytes[..7]), None);
    }

    /// A chunk value past what the length field can count is refused, not
    /// wrapped, in debug and release builds alike. A wrapped field four bytes
    /// short of 64 KiB declares a zero-length chunk, which receivers read as the
    /// end of the packet.
    #[test]
    fn a_chunk_value_too_large_for_the_length_field_is_refused_rather_than_wrapped() {
        let largest = vec![0u8; MAX_CHUNK_VALUE];
        let encoded = chunk(chunk_type::INIT, 0, &largest).expect("the largest describable value");
        assert_eq!(
            u16::from_be_bytes([encoded[2], encoded[3]]),
            u16::MAX,
            "the largest value fills the field exactly"
        );

        for oversize in [MAX_CHUNK_VALUE + 1, u16::MAX as usize] {
            let refused = chunk(chunk_type::INIT, 0, &vec![0u8; oversize]);
            assert!(
                matches!(refused, Err(PacketError::TooLong { .. })),
                "a value of {oversize} produced {refused:?}"
            );
        }
    }

    // ── Parsing ──────────────────────────────────────────────────────────────

    #[test]
    fn a_packet_too_short_for_the_common_header_is_rejected() {
        assert!(matches!(
            parse(&[0u8; SCTP_COMMON_HDR_LEN - 1]),
            Err(PacketError::Truncated { .. })
        ));
    }

    /// **The walk terminates on every input.**
    ///
    /// Exhaustive over every 16-bit length value against every buffer length that
    /// can hold a chunk header. A zero step would hang the capture thread, so the
    /// test bounds the count.
    #[test]
    fn the_chunk_walk_terminates_for_every_length_field() {
        for rest_len in 0..24usize {
            for declared in 0..=u16::MAX {
                let mut bytes = vec![0u8; SCTP_COMMON_HDR_LEN];
                bytes.resize(SCTP_COMMON_HDR_LEN + rest_len, 0xAA);
                if rest_len >= SCTP_CHUNK_HDR_LEN {
                    let at = SCTP_COMMON_HDR_LEN + 2;
                    bytes[at..at + 2].copy_from_slice(&declared.to_be_bytes());
                }
                let segment = parse(&bytes).expect("the common header is present");

                // A 24-byte tail holds at most six four-byte chunks, so reaching the cap
                // means the walk stopped advancing.
                assert!(
                    segment.chunks().take(8).count() < 8,
                    "the walk did not advance: rest_len={rest_len} declared={declared}"
                );
            }
        }
    }

    /// **Reading more bytes only ever adds to what was read**, as
    /// `fuzz/wire/ethernet_frame` holds for the announcement readers, here for the
    /// chunk walk.
    ///
    /// It holds because a clamped step always empties the remainder, so a
    /// truncated read stops instead of resuming at an offset the whole packet
    /// never had.
    #[test]
    fn a_shorter_read_reports_a_prefix_of_the_longer_one() {
        let mut packet = vec![0u8; SCTP_COMMON_HDR_LEN];
        packet.extend_from_slice(&chunk(chunk_type::INIT_ACK, 0, &[0xAB; 16]).expect("a chunk"));
        packet.extend_from_slice(&chunk(chunk_type::ABORT, 0, &[0xCD; 4]).expect("a chunk"));

        let whole = parse(&packet).expect("the whole packet parses");
        let full: Vec<Chunk<'_>> = whole.chunks().collect();
        assert_eq!(full.len(), 2, "the fixture has to hold two chunks");

        for cut in SCTP_COMMON_HDR_LEN..packet.len() {
            let short = parse(&packet[..cut]).expect("still has a common header");
            let near: Vec<Chunk<'_>> = short.chunks().collect();

            assert!(
                near.len() <= full.len(),
                "a {cut}-byte read found more chunks than the whole packet"
            );
            for (near, far) in near.iter().zip(&full) {
                assert_eq!(near.chunk_type, far.chunk_type, "at {cut} bytes");
                assert!(
                    far.value.starts_with(near.value),
                    "a {cut}-byte read reported a value the whole packet contradicts"
                );
            }
        }
    }

    /// A quotation short of the Initiate Tag names no attempt, and one that
    /// reaches it names exactly the tag that was sent.
    #[test]
    fn an_init_tag_is_named_only_by_a_quotation_that_reaches_it() {
        let probe = build_init_probe(50_000, 132, 0x1234_5678);

        for cut in 0..20 {
            assert_eq!(
                quoted_init_tag(&probe[..cut.min(probe.len())]),
                None,
                "{cut} bytes cannot name the tag, which sits at sixteen"
            );
        }
        assert_eq!(quoted_init_tag(&probe[..20]), Some(0x1234_5678));

        // The common header's tag, which a COOKIE-ECHO uses, is zero for an INIT,
        // so it cannot stand in for the Initiate Tag.
        let quoted = quoted_probe(&probe).expect("eight bytes are there");
        assert_eq!(
            quoted.verification_tag, 0,
            "RFC 4960 §8.5.1 requires an INIT to carry a zero verification tag"
        );
    }
}
