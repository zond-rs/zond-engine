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
//! that comes back. What a reply *means* about a port is the scanner's to
//! decide, as with [`tcp`](super::tcp); this module knows only what an SCTP
//! packet is.
//!
//! ## The one scan, and its two answers
//!
//! An INIT scan puts an INIT chunk to a port and reads the chunk that answers.
//! Two answers are decisive, and RFC 4960 fixes both:
//!
//! - INIT-ACK (§5.1): an endpoint willing to open an association. The port is
//!   open.
//! - ABORT (§8.4): a reachable stack with nothing listening on that port,
//!   refusing the association outright. The port is closed.
//!
//! Silence is neither, and it is the weakest of the three. An endpoint that is
//! up answers an INIT whichever way its port stands, so a probe that drew
//! nothing was stopped on the way out or on the way back rather than ignored by
//! a listener. What verdict that earns, and how an ICMP unreachable is read, is
//! the scanner's decision; see [`classify_probe_response`] for where this module
//! stops, and [`sctp_scan`](crate::scanner::strategy::routed) for what reads it.
//!
//! ## The nonce is the Initiate Tag
//!
//! Every INIT carries a 32-bit Initiate Tag the peer is obliged to echo: a
//! listener's INIT-ACK and a closed port's ABORT both set their common-header
//! verification tag to it (RFC 4960 §3.3.2, §8.4). That is what ties a reply to
//! the exact probe that drew it, the way a TCP probe's nonce does, and unlike TCP
//! it never moves between fields, since an INIT has only the one place to put it.
//! [`echoed_nonce`] reads it back.
//!
//! The INIT's *own* common-header verification tag is zero, which RFC 4960
//! §8.5.1 requires. That is why a probe quoted back inside an ICMP error names
//! its port but not its attempt until the quotation runs past the common header.
//! See [`quoted_init_tag`], the SCTP twin of the story in
//! [`tcp::quoted_nonce`](super::tcp::quoted_nonce).
//!
//! ## The checksum is a CRC32c, over the packet alone
//!
//! SCTP does not use the internet checksum. It carries a CRC32c (RFC 3309, RFC
//! 4960 §6.8) computed over the whole packet with the field zeroed and written
//! into the field little-endian, which is the detail most implementations get
//! wrong first. It covers no pseudo-header, so unlike a TCP or UDP probe an SCTP
//! one needs no addresses to be built. The computation lives in [`craft`]; this module
//! assembles the chunks around it.

use crate::protocols::craft;
use crate::protocols::error::{PacketError, Result};
use crate::protocols::sizes::{SCTP_CHUNK_HDR_LEN, SCTP_COMMON_HDR_LEN};

/// The IANA protocol number SCTP is carried under in an IP header (RFC 4960
/// §1.7). The value a raw sender writes into `protocol` / `next_header`, offered
/// here so a caller building the IP layer by hand does not reach for a magic
/// `132`.
pub const IP_PROTOCOL_NUMBER: u8 = 132;

/// SCTP chunk type numbers, from the registry in RFC 4960 §3.2.
///
/// Only the handful a scan builds or reads. A reply to an INIT is one of the
/// first two; the rest are here because the probes that draw them are the
/// natural next tenants of this module.
pub mod chunk_type {
    /// Requests a new association. The probe an INIT scan sends.
    pub const INIT: u8 = 1;
    /// Accepts an association attempt: an open port's answer to an INIT.
    pub const INIT_ACK: u8 = 2;
    /// Refuses an association outright: a closed port's answer to an INIT.
    pub const ABORT: u8 = 6;
    /// Replays a listener's state cookie. The probe a COOKIE-ECHO scan would
    /// send; unused until one is wired up.
    pub const COOKIE_ECHO: u8 = 10;
}

/// The receive window an INIT advertises, in bytes.
///
/// Immaterial to classification, the probe intending to receive nothing, but a
/// field a peer reads back, so it is one plausible value across every probe
/// rather than a signature. Mirrors [`tcp`](super::tcp)'s advertised window.
const ADVERTISED_RWND: u32 = 65_535;

/// The number of outbound streams an INIT asks to open, and the number of
/// inbound streams it will accept. Ordinary client values, and immaterial to
/// whether a port answers.
const OUTBOUND_STREAMS: u16 = 10;
const INBOUND_STREAMS: u16 = 65_535;

/// Builds an INIT-scan probe from `src_port` to `dst_port`, carrying
/// `initiate_tag` as the nonce a reply will echo.
///
/// The packet's common-header verification tag is zero, which RFC 4960 §8.5.1
/// requires of anything carrying an INIT, and the Initiate Tag inside the chunk
/// is `initiate_tag`. A conformant peer copies that tag into its reply's
/// verification tag, whether it accepts with an INIT-ACK or refuses with an
/// ABORT, so
/// the caller recovers it with [`echoed_nonce`] and matches it against what it
/// sent.
///
/// `initiate_tag` must be non-zero (RFC 4960 §3.3.2); a random tag per probe
/// is both the requirement and what makes correlation trustworthy. A zero tag is
/// left to the caller to avoid rather than silently rewritten, on the same
/// reasoning [`tcp::build_probe`](super::tcp::build_probe) does not police its
/// nonce.
///
/// Infallible, unlike its TCP and UDP counterparts: an SCTP checksum covers no
/// pseudo-header, so there are no addresses to reconcile, and the INIT chunk is
/// a fixed size that no length field can fail to describe.
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
    // Initial TSN. The peer's own reply carries its choice, not ours, so nothing
    // reads this back; a random value is what an ordinary stack would send.
    value.extend_from_slice(&rand::random::<u32>().to_be_bytes());
    chunk(chunk_type::INIT, 0, &value).expect("a sixteen-byte value fits the length field")
}

/// The largest value a chunk may carry: what is left of the 16-bit length field
/// once the four bytes of chunk header it also counts are taken out.
pub const MAX_CHUNK_VALUE: usize = u16::MAX as usize - SCTP_CHUNK_HDR_LEN;

/// Encodes one chunk: the four-byte header, the value, and the padding that
/// aligns whatever follows to a four-byte boundary.
///
/// The length field counts the header and value but **not** the padding (RFC
/// 4960 §3.2), which is why a reader steps to the next chunk by the padded
/// length while trusting the field for where the value ends. The primitive the
/// probe builders are written on; exposed so a chunk this module does not send
/// yet, a COOKIE-ECHO say, is a few lines rather than a fork.
///
/// # Errors
///
/// [`PacketError::TooLong`] for a value past [`MAX_CHUNK_VALUE`]. The field
/// wraps rather than saturating, so a value four bytes short of 64 KiB would
/// otherwise produce a chunk declaring itself zero bytes long, which every
/// receiver reads as the end of the packet. Every chunk a scan sends is a few
/// dozen bytes and cannot reach this.
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

/// The two answers an INIT scan can draw, as read off the wire.
///
/// What either one proves about a port, open or closed, is the scanner's to
/// conclude, the way [`TcpReply`](crate::model::technique::TcpReply) leaves its
/// verdict to the technique that sent the probe. Naming the chunk rather than
/// the conclusion keeps this module from deciding something only the scan knows.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpReply {
    /// An INIT-ACK: an endpoint accepted the association attempt. Positive
    /// evidence of an open port, the SCTP analogue of a SYN+ACK.
    InitAck,
    /// An ABORT: a reachable stack refused the attempt because nothing is
    /// listening there. The SCTP analogue of a RST to a SYN.
    Abort,
}

/// A view over a received SCTP packet: the common header, and an iterator over
/// the chunks after it.
///
/// Borrows the bytes rather than copying them. Built by [`parse`], which is the
/// only thing that guarantees the common header is really there.
#[derive(Debug, Clone, Copy)]
pub struct Segment<'a> {
    bytes: &'a [u8],
}

impl<'a> Segment<'a> {
    /// The port the packet came from.
    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }

    /// The port it was aimed at, which for a reply is the source port the scan
    /// sent from.
    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }

    /// The verification tag. In a reply to an INIT this is the Initiate Tag the
    /// probe carried, echoed back; see [`echoed_nonce`].
    pub fn verification_tag(&self) -> u32 {
        u32::from_be_bytes([self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7]])
    }

    /// The chunks after the common header.
    pub fn chunks(&self) -> Chunks<'a> {
        Chunks {
            rest: &self.bytes[SCTP_COMMON_HDR_LEN..],
        }
    }
}

/// One chunk of a [`Segment`], as read from the wire.
///
/// Not `#[non_exhaustive]`, on the reasoning
/// [`VlanTag`](crate::protocols::ethernet::VlanTag) sets out: RFC 4960 §3.2
/// defines a chunk as a type byte, a flags byte, a length and the value it
/// measures, and there is nothing else in one to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk<'a> {
    /// What kind of chunk it is. See [`chunk_type`].
    pub chunk_type: u8,
    /// The chunk's flag bits, whose meaning depends on the type.
    pub flags: u8,
    /// The chunk's value, without the four-byte header or the trailing padding.
    pub value: &'a [u8],
}

/// Walks the chunks of a [`Segment`], outermost first.
///
/// Stops rather than guesses at a malformed length: a chunk claiming fewer than
/// its four header bytes cannot say where the next one starts, so iteration ends
/// there instead of spinning. That is the safe reading of a hostile or truncated
/// packet: a missed chunk credits nothing, where a loop that never advances hangs
/// the receive path.
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

        // A length that does not clear the header would leave the cursor where it
        // is; stopping is what makes the walk terminate on any input at all.
        if length < SCTP_CHUNK_HDR_LEN {
            return None;
        }

        // A sender may omit the padding on the last chunk, and a capture may be
        // cut short, so both the value and the step are clamped to what is
        // actually present rather than to what the length claims.
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
/// header. Nothing here validates the checksum: a scan correlates a reply by its
/// verification tag, and a CRC32c only a captured packet could carry is not what
/// establishes it is ours.
pub fn parse(bytes: &'_ [u8]) -> Result<Segment<'_>> {
    if bytes.len() < SCTP_COMMON_HDR_LEN {
        return Err(PacketError::truncated(
            "an SCTP packet",
            SCTP_COMMON_HDR_LEN,
            bytes.len(),
        ));
    }
    Ok(Segment { bytes })
}

/// Classifies a received packet as one of the two answers an INIT scan can draw,
/// if it is one.
///
/// Returns `None` for anything else, such as a heartbeat, a shutdown, or a chunk
/// from an association this scan is not part of, which a caller treats as noise.
/// An INIT-ACK settles the question ahead of anything bundled behind it, on the
/// same reasoning [`tcp::classify_probe_response`](super::tcp::classify_probe_response)
/// reads a RST first: it is the decisive answer, and the two never legitimately
/// arrive together.
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
/// A caller compares this against the tags it actually sent. A match names the
/// probe that was answered; anything else is a stray, a duplicate, or a packet
/// from another association, none of which may resolve a port.
pub fn echoed_nonce(reply: &Segment<'_>) -> u32 {
    reply.verification_tag()
}

/// A probe's common header as an ICMP error quotes it back.
///
/// Not a [`Segment`], because there may not be a whole one: RFC 792 guarantees
/// only the IP header plus the offending packet's first eight bytes, which for
/// SCTP are the two ports and the verification tag, enough to say a probe was
/// this scan's but not which attempt, since an INIT's tag is zero and its
/// Initiate Tag sits past the eight. See [`quoted_init_tag`].
///
/// `#[non_exhaustive]`, for the reason
/// [`tcp::QuotedProbe`](crate::protocols::tcp::QuotedProbe) is: what a sender
/// quotes past the guaranteed eight bytes is worth reading when it is there, and
/// reading more of it adds a field.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotedProbe {
    /// The port the probe was sent from, which is what proves the quoted packet
    /// belongs to this scan.
    pub source: u16,
    /// The port it was aimed at.
    pub destination: u16,
    /// The common-header verification tag, zero for a quoted INIT.
    pub verification_tag: u32,
}

/// Reads what an ICMP error quoted of an SCTP probe, or `None` if the quotation
/// is too short to name one.
///
/// Every byte here was chosen by whatever sent the error, so nothing is assumed
/// beyond the eight bytes RFC 792 guarantees.
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
/// The tag names the exact attempt, but it sits sixteen bytes in, past the common
/// header and the INIT chunk's own header, so only a sender generous enough to
/// quote past the guaranteed eight reveals it. A caller that gets
/// `None` still has the ports from [`quoted_probe`] and should resolve the error
/// against the probe without claiming to know which attempt, exactly as an
/// ACK-carrying TCP probe does in
/// [`tcp::quoted_nonce`](super::tcp::quoted_nonce).
pub fn quoted_init_tag(quoted: &[u8]) -> Option<u32> {
    let head: &[u8; 20] = quoted.first_chunk()?;
    // Byte twelve is the first chunk's type; the Initiate Tag is only where this
    // reads it if that chunk is an INIT.
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
    /// chunk of `chunk_type`. Built from the wire layout directly rather than
    /// from anything above, so a wrong rule in [`parse`] or
    /// [`classify_probe_response`] fails instead of agreeing with itself.
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

    /// The probe is a well-formed INIT: the ports it was asked for, a zeroed
    /// verification tag per RFC 4960 §8.5.1, and its nonce in the Initiate Tag
    /// where a reply will echo it from.
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

    /// What the CRC32c living behind the builder buys: the probe leaves
    /// with a valid one, computed over the packet with the field zeroed and
    /// written little-endian. Recomputed here the way a receiver would.
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
    /// both echo the probe's Initiate Tag as their verification tag, which is
    /// what ties a reply to the probe that drew it.
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

    /// A reply to somebody else's association must not read as one of ours: its
    /// verification tag is not the tag we sent.
    #[test]
    fn a_reply_to_another_association_yields_a_different_nonce() {
        let theirs_bytes = reply(NONCE ^ 0x1234, chunk_type::INIT_ACK);
        let theirs = parse(&theirs_bytes).expect("parses");
        assert_ne!(echoed_nonce(&theirs), NONCE);
    }

    /// Chunks that are not one of the two decisive answers are noise, not a
    /// verdict.
    #[test]
    fn an_unrelated_chunk_answers_no_probe() {
        // Type 4 is HEARTBEAT, type 11 COOKIE-ACK: neither settles an INIT scan.
        for chunk_type in [4u8, 11] {
            let bytes = reply(NONCE, chunk_type);
            let other = parse(&bytes).expect("parses");
            assert_eq!(classify_probe_response(&other), None, "chunk {chunk_type}");
        }
    }

    /// A chunk whose length field cannot advance the cursor ends iteration
    /// rather than looping. The reading a hostile packet must not be able to
    /// hang the receive path.
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
    /// ports and its zero verification tag, but the Initiate Tag that names the
    /// attempt needs a more generous quotation, the SCTP twin of an ACK-carrying
    /// TCP probe.
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

    #[test]
    fn a_quotation_too_short_for_the_common_header_names_nothing() {
        let bytes = build_init_probe(SRC_PORT, DST_PORT, NONCE);
        assert_eq!(quoted_probe(&bytes[..7]), None);
    }

    /// A chunk value past what the length field can count is refused, not
    /// wrapped.
    ///
    /// The two build profiles used to disagree about this. A `debug_assert`
    /// stated the bound, so a debug build panicked and a release build wrapped:
    /// four bytes short of 64 KiB produced a chunk declaring itself zero bytes
    /// long, which every receiver reads as the end of the packet. `ip.rs` has a
    /// test making the same argument about `build_ipv4_header`, and this is the
    /// same fix.
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
}
