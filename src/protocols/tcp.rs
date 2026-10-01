// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # TCP Probes
//!
//! Builds the segment a port probe puts on the wire and reads the segment that
//! comes back. What either means is [`TcpScanTechnique`]'s business.
//!
//! ## Where the nonce goes
//!
//! Every probe carries a 32-bit value a conformant stack must echo, which ties a
//! reply to the attempt that provoked it and keeps unrelated or forged segments
//! from resolving a port. RFC 793 §3.4 decides where it comes back:
//!
//! > If the incoming segment has an ACK field, the reset takes its sequence
//! > number from the ACK field of the segment; otherwise the reset has sequence
//! > number zero and the ACK field is set to the sum of the sequence number and
//! > segment length of the incoming segment.
//!
//! So a probe carrying ACK (ACK and Maimon scans) puts the nonce in its
//! acknowledgement field and gets it back as the RST's sequence number; reading
//! `acknowledgement - 1` as a SYN scan does would find zero. A probe without ACK
//! puts it in the sequence field and gets it back in the acknowledgement,
//! advanced by the sequence space its flags occupy: one for SYN or FIN, none
//! otherwise.
//!
//! [`build_probe`] and [`echoed_nonce`] both derive this from the probe's flags,
//! so any technique gets it right by construction.

use std::net::IpAddr;

use crate::model::technique::{TcpReply, TcpScanTechnique};
use crate::protocols::craft;
use crate::protocols::error::{PacketError, Result};
use crate::protocols::sizes::TCP_HDR_LEN;

/// TCP header flag bits, in the order they sit in the header.
pub mod flags {
    /// Ends a sender's half of a connection. Alone it is the FIN scan: a closed
    /// port answers RST and a listener must stay silent. Also set by Xmas and
    /// Maimon probes.
    pub const FIN: u8 = 1;
    /// Opens a connection, occupying one octet of sequence space. The SYN scan's
    /// probe, and the only bit that draws a SYN+ACK, naming a listener outright.
    pub const SYN: u8 = 1 << 1;
    /// Aborts a connection, or refuses a segment for one that does not exist.
    /// No technique sends it; every flag scan reads its verdict from it.
    pub const RST: u8 = 1 << 2;
    /// Asks the receiver to hand buffered data up. Meaningless for a port with
    /// no connection, so on a probe it only makes the segment strange, as an Xmas
    /// scan wants.
    pub const PSH: u8 = 1 << 3;
    /// Marks the acknowledgement field significant. Alone it is the ACK scan,
    /// which maps the filter in front of a port; beside FIN it is a Maimon probe.
    /// Moves a probe's nonce into the acknowledgement field (see the module
    /// documentation).
    pub const ACK: u8 = 1 << 4;
    /// Marks the urgent pointer significant. Ordinary traffic almost never sets
    /// it, which is why an Xmas probe does.
    pub const URG: u8 = 1 << 5;
}

/// A header with room for the MSS option a SYN carries.
#[cfg(test)]
const TCP_HDR_LEN_WITH_OPTIONS: usize = TCP_HDR_LEN + SYN_OPTIONS_LEN;
#[cfg(test)]
const WORD_IN_BYTES: usize = 4;

/// The receive window every probe advertises.
///
/// Immaterial to classification, but stack fingerprinters read it, so it is
/// one value across all techniques. `pub(crate)` so [`craft::Tcp::new`] can use
/// it and hand-built segments match the probes.
pub(crate) const PROBE_WINDOW: u16 = 1024;

/// The maximum segment size advertised on a SYN, sized to clear the common
/// tunnel overheads without inviting fragmentation.
const PROBE_MSS: u16 = 1412;

/// The length of a SYN's option list: twenty bytes, already a multiple of
/// four. [`syn_options`] asserts it builds exactly this.
const SYN_OPTIONS_LEN: usize = 20;

/// The flags each technique's probe carries.
/// The only on-wire difference between techniques. [`TcpScanTechnique::Window`]
/// sends the ACK scan's segment and differs only in which field of the answer
/// it reads.
pub const fn probe_flags(technique: TcpScanTechnique) -> u8 {
    match technique {
        TcpScanTechnique::Syn => flags::SYN,
        TcpScanTechnique::Fin => flags::FIN,
        // Empty: a segment with no flags is unlike anything a real connection
        // produces, which is the point of the NULL scan.
        TcpScanTechnique::Null => 0,
        TcpScanTechnique::Xmas => flags::FIN | flags::PSH | flags::URG,
        TcpScanTechnique::Maimon => flags::FIN | flags::ACK,
        TcpScanTechnique::Ack | TcpScanTechnique::Window => flags::ACK,
    }
}

/// Which header field carries a probe's nonce, and how a reply gives it back.
///
/// Derived from the probe's flags per RFC 793 §3.4; see the module
/// documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NonceField {
    /// The nonce is the probe's sequence number, and comes back in the reply's
    /// acknowledgement field advanced by `span`, which is the sequence space the
    /// probe's control flags occupy.
    Sequence { span: u32 },
    /// The nonce is the probe's acknowledgement number, and comes back
    /// unchanged as the reply's sequence number.
    Acknowledgement,
}

/// Where `flags` puts a probe's nonce.
const fn nonce_field(flags: u8) -> NonceField {
    if flags & flags::ACK != 0 {
        return NonceField::Acknowledgement;
    }

    // SYN and FIN each occupy one octet of sequence space (RFC 793's SEG.LEN
    // "counting SYN and FIN"). Getting this wrong is silent: a NULL scan using a
    // FIN scan's offset rejects every RST and reports the whole range
    // `OpenOrNoReply`.
    let mut span = 0;
    if flags & flags::SYN != 0 {
        span += 1;
    }
    if flags & flags::FIN != 0 {
        span += 1;
    }
    NonceField::Sequence { span }
}

/// Builds one probe of `technique` from `src_addr` to `dst_addr:dst_port`,
/// carrying `nonce` in whichever field the technique's flags call for.
///
/// The header's other 32-bit field is zero where not significant (the
/// acknowledgement of a segment without ACK), and a random sequence number on
/// an ACK-carrying probe, since sequence zero there is an oddity a filter can
/// match.
///
/// # What a SYN offers
///
/// The option list an ordinary client sends: maximum segment size,
/// SACK-permitted, a timestamp and a window scale. **TCP option negotiation is
/// reciprocal**: RFC 7323 §2.2 permits a window scale in a SYN+ACK only if the
/// SYN carried one, §3.2 the same for timestamps, RFC 2018 §2 for
/// SACK-permitted. A SYN offering only an MSS draws only an MSS back from every
/// stack, erasing the reply's shape, which is the strongest thing a single
/// answer says about the machine that sent it.
///
/// Measured: against a labelled segment, every host with an open port named
/// four more options when offered four more, and no port changed its verdict.
/// The probe is twenty bytes longer and looks more like a real connection
/// attempt.
pub fn build_probe(
    technique: TcpScanTechnique,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    src_port: u16,
    dst_port: u16,
    nonce: u32,
) -> Result<Vec<u8>> {
    build_probe_shaped(
        technique, src_addr, dst_addr, src_port, dst_port, nonce, None, false,
    )
}

/// [`build_probe`] with the segment-level evasion an
/// [`EvasionProfile`](crate::evasion::EvasionProfile) applies: `padding` random
/// bytes appended to the payload, and a deliberately wrong checksum when
/// `bad_checksum` is set. With `None` and `false` it is `build_probe` exactly.
///
/// The padding is appended before the checksum is computed, so the checksum
/// covers it. A corrupt checksum is the correct one perturbed (see
/// [`craft::Tcp::corrupt_checksum`]), so it cannot be valid by chance.
#[allow(clippy::too_many_arguments)]
pub fn build_probe_shaped(
    technique: TcpScanTechnique,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    src_port: u16,
    dst_port: u16,
    nonce: u32,
    padding: Option<u16>,
    bad_checksum: bool,
) -> Result<Vec<u8>> {
    build_probe_with_flags(
        probe_flags(technique),
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        nonce,
        padding,
        bad_checksum,
    )
}

/// [`build_probe_shaped`] over an explicit TCP flag byte, for the evasion path
/// that sends an arbitrary combination (see
/// [`EvasionProfile::flags`](crate::evasion::EvasionProfile::flags)). The nonce
/// field and the SYN options follow from the flags, so any combination is
/// built and read back consistently.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_probe_with_flags(
    flags: u8,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    src_port: u16,
    dst_port: u16,
    nonce: u32,
    padding: Option<u16>,
    bad_checksum: bool,
) -> Result<Vec<u8>> {
    let mut segment = craft::Tcp::new(src_port, dst_port).with_flags(flags);

    match nonce_field(flags) {
        NonceField::Sequence { .. } => {
            segment.sequence = nonce;
            segment.acknowledgement = 0;
        }
        NonceField::Acknowledgement => {
            segment.sequence = rand::random();
            segment.acknowledgement = nonce;
        }
    }

    // Options go on a SYN only; on anything else they are meaningless to the
    // receiver and distinctive to an observer.
    if flags & flags::SYN != 0 {
        segment.options = syn_options(PROBE_MSS);
    }

    // Set before the checksum so it covers the padding.
    if let Some(len) = padding {
        segment.payload = craft::random_padding(len);
    }

    // The checksum covers a pseudo-header built from both addresses. Written
    // through `craft` so this and a hand-crafted segment agree on the header.
    let addresses = (src_addr, dst_addr);
    if bad_checksum {
        segment.checksum = craft::Field::Exact(segment.corrupt_checksum(Some(addresses))?);
    }
    segment.to_bytes(Some(addresses))
}

/// The option list a SYN offers, as the bytes a TCP header carries them in.
///
/// Five options in twenty bytes: maximum segment size, SACK-permitted, a
/// timestamp, a no-op for alignment, and a window scale. See [`build_probe`]
/// for why: a peer only answers about the options it was offered.
fn syn_options(mss: u16) -> Vec<u8> {
    let [high, low] = mss.to_be_bytes();
    let timestamp: u32 = rand::random();

    let mut options = Vec::with_capacity(SYN_OPTIONS_LEN);
    options.extend_from_slice(&[2, 4, high, low]); // maximum segment size
    options.extend_from_slice(&[4, 2]); // SACK permitted
    options.extend_from_slice(&[8, 10]); // timestamp: kind, length
    options.extend_from_slice(&timestamp.to_be_bytes()); // TSval
    options.extend_from_slice(&0u32.to_be_bytes()); // TSecr, nothing to echo yet
    options.push(1); // NOP, aligning what follows
    options.extend_from_slice(&[3, 3, 7]); // window scale

    // The tests measure the probe against the constant.
    debug_assert_eq!(options.len(), SYN_OPTIONS_LEN);
    options
}

/// The nonce `reply` implies, read from whichever field `technique` expects it
/// back in.
///
/// A caller compares this against the nonces it sent: a match names the
/// attempt that was answered; a stray, duplicate or forgery must not resolve a
/// port. Arithmetic wraps, as sequence space does.
///
/// `padding` is how many payload bytes the probe carried (`0` unpadded). A
/// reset from a closed port acknowledges the whole segment, padding included;
/// a SYN+ACK acknowledges only the SYN. So the padding is subtracted from a
/// reset's acknowledgement only. Without this a padded scan reads every closed
/// port as silent.
pub fn echoed_nonce(technique: TcpScanTechnique, reply: &Segment<'_>, padding: u16) -> u32 {
    echoed_nonce_with_flags(probe_flags(technique), reply, padding)
}

/// The nonce a probe of `flags` went out carrying, read back off the probe
/// itself.
///
/// The outbound counterpart of [`echoed_nonce_with_flags`], for a scan
/// watching its own segments leave. Reads the field the flags put the nonce
/// in; the sequence number would be wrong for an ACK-family probe.
pub(crate) fn sent_nonce_with_flags(flags: u8, probe: &Segment<'_>) -> u32 {
    match nonce_field(flags) {
        NonceField::Sequence { .. } => probe.sequence(),
        NonceField::Acknowledgement => probe.acknowledgement(),
    }
}

/// [`echoed_nonce`] over an explicit TCP flag byte, for the arbitrary-flags
/// evasion path. The acknowledgement's span follows from the sent flags.
pub(crate) fn echoed_nonce_with_flags(flags: u8, reply: &Segment<'_>, padding: u16) -> u32 {
    match nonce_field(flags) {
        NonceField::Sequence { span } => {
            let acked_padding = if reply.flags() & flags::RST != 0 {
                u32::from(padding)
            } else {
                0
            };
            reply
                .acknowledgement()
                .wrapping_sub(span)
                .wrapping_sub(acked_padding)
        }
        NonceField::Acknowledgement => reply.sequence(),
    }
}

/// A probe's header as an ICMP error quotes it back.
///
/// RFC 792 requires an error to quote only the IP header plus the first
/// **eight** bytes of the offending segment, and a TCP header is twenty. Those
/// eight are the ports and the sequence number, enough to identify the probe;
/// the acknowledgement is reported when a sender quotes more, as many do.
///
/// `#[non_exhaustive]`: further fields past twelve bytes may be read the same
/// way. Built by [`quoted_probe`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotedProbe {
    /// The port the probe was sent from, which proves the quoted datagram
    /// belongs to this scan.
    pub source: u16,
    /// The port it was aimed at.
    pub destination: u16,
    /// The sequence number it carried, where four of the six techniques put
    /// their nonce. Always readable: it ends the eight guaranteed bytes.
    pub sequence: u32,
    /// Present only where the quotation ran past the guaranteed eight bytes.
    pub acknowledgement: Option<u32>,
}

/// Reads what an ICMP error quoted of a TCP probe, or `None` if the quotation
/// is too short to name one.
///
/// The error's sender chose every byte, so nothing past the RFC's guarantee
/// is assumed.
pub fn quoted_probe(quoted: &[u8]) -> Option<QuotedProbe> {
    let head: &[u8; 8] = quoted.first_chunk()?;

    Some(QuotedProbe {
        source: u16::from_be_bytes([head[0], head[1]]),
        destination: u16::from_be_bytes([head[2], head[3]]),
        sequence: u32::from_be_bytes([head[4], head[5], head[6], head[7]]),
        acknowledgement: quoted
            .first_chunk::<12>()
            .map(|full| u32::from_be_bytes([full[8], full[9], full[10], full[11]])),
    })
}

/// The nonce a quoted probe carried, or `None` when the quotation stopped short
/// of the field this technique put it in.
///
/// The four techniques that put their nonce in the sequence number are named
/// by the guaranteed eight bytes. The two that use the acknowledgement field
/// need a sender that quotes twelve.
///
/// With `None` the caller holds only the ports, which every probe carries and
/// which the scanned host knows and anyone else can guess. That is no ground
/// for settling a port. The engine's scanner treats such an error as no verdict
/// and leaves the probe to its retry schedule, except that a host unreachable
/// is filed against the host while the probe it quotes is outstanding.
pub fn quoted_nonce(technique: TcpScanTechnique, quoted: &QuotedProbe) -> Option<u32> {
    quoted_nonce_with_flags(probe_flags(technique), quoted)
}

/// [`quoted_nonce`] over an explicit TCP flag byte, for the arbitrary-flags
/// evasion path.
pub(crate) fn quoted_nonce_with_flags(flags: u8, quoted: &QuotedProbe) -> Option<u32> {
    match nonce_field(flags) {
        NonceField::Sequence { .. } => Some(quoted.sequence),
        NonceField::Acknowledgement => quoted.acknowledgement,
    }
}

/// A TCP segment: the fixed header, and whatever follows it.
///
/// Borrows the bytes. Only [`parse`] constructs one, and it guarantees the
/// header is there: the accessors below index without checking.
///
/// This crate's own type, like [`sctp::Segment`](super::sctp::Segment), so no
/// public signature exposes `pnet_packet::TcpPacket` from a pre-1.0 dependency.
///
/// Only the fields the engine reads: ports and sequence fields for
/// correlation, flags for classification, and the window for the window scan.
/// The OS fingerprinter reads options and the urgent pointer off the bytes
/// itself.
#[derive(Debug, Clone, Copy)]
pub struct Segment<'a> {
    bytes: &'a [u8],
}

impl<'a> Segment<'a> {
    /// The port the segment came from, which for a reply is the port probed.
    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }

    /// The port it was aimed at: for a reply, the scan's source port.
    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }

    /// The sequence number.
    pub fn sequence(&self) -> u32 {
        u32::from_be_bytes([self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7]])
    }

    /// The acknowledgement number, significant only when [`ACK`](flags::ACK) is
    /// set.
    pub fn acknowledgement(&self) -> u32 {
        u32::from_be_bytes([self.bytes[8], self.bytes[9], self.bytes[10], self.bytes[11]])
    }

    /// The flag bits, as [`flags`] names them.
    pub fn flags(&self) -> u8 {
        self.bytes[13]
    }

    /// The receive window advertised.
    ///
    ///
    /// On a reset, the field [`TcpScanTechnique::Window`] concludes from.
    pub fn window(&self) -> u16 {
        u16::from_be_bytes([self.bytes[14], self.bytes[15]])
    }

    /// Whatever follows the header.
    ///
    /// The data offset is the sender's claim and is clamped to what is present:
    /// a header shorter than the minimum names no payload, and one running past
    /// the buffer yields an empty payload.
    pub fn payload(&self) -> &'a [u8] {
        let offset = usize::from(self.bytes[12] >> 4) * 4;
        if offset < TCP_HDR_LEN || offset > self.bytes.len() {
            return &[];
        }
        &self.bytes[offset..]
    }
}

/// Reads `bytes` as a TCP segment.
///
/// # Errors
///
/// [`PacketError::Truncated`] when there are too few bytes for a header.
pub fn parse(bytes: &'_ [u8]) -> Result<Segment<'_>> {
    if bytes.len() < TCP_HDR_LEN {
        return Err(PacketError::truncated(
            "a TCP segment",
            TCP_HDR_LEN,
            bytes.len(),
        ));
    }
    Ok(Segment { bytes })
}

/// Classifies a received segment as one of the two answers a port probe can
/// draw, if it is one.
///
/// `None` for anything else (established-connection traffic, unrelated flag
/// combinations), which a caller treats as noise. What a classified segment
/// proves depends on the technique: see [`TcpScanTechnique::verdict`].
pub fn classify_probe_response(segment: &Segment<'_>) -> Option<TcpReply> {
    let flags = segment.flags();

    // RST takes priority: a reset answering a probe legitimately carries ACK too
    // (RFC 793 §3.4), and reading that as a handshake would make every closed
    // port open.
    if flags & flags::RST != 0 {
        Some(TcpReply::Rst {
            window: segment.window(),
        })
    } else if flags & flags::SYN != 0 && flags & flags::ACK != 0 {
        Some(TcpReply::SynAck)
    } else if flags & flags::ACK != 0 && flags & (flags::SYN | flags::FIN) == 0 {
        // ACK with nothing structural beside it: a challenge ACK, sent for a
        // segment that does not fit a connection the stack holds. Checked last, so
        // SYN+ACK and RST+ACK are classified first.
        //
        // FIN+ACK is excluded: that is a peer closing a conversation.
        Some(TcpReply::ChallengeAck)
    } else {
        None
    }
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
    use pnet_packet::Packet;
    use pnet_packet::tcp::MutableTcpPacket;
    use std::net::Ipv4Addr;

    const SRC: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    const DST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
    const NONCE: u32 = 0xDEAD_BEEF;

    fn packet_with_flags(flags: u8) -> Vec<u8> {
        let mut buffer = vec![0u8; TCP_HDR_LEN];
        let mut tcp = MutableTcpPacket::new(&mut buffer).unwrap();
        tcp.set_data_offset((TCP_HDR_LEN / WORD_IN_BYTES) as u8);
        tcp.set_flags(flags);
        buffer
    }

    fn probe(technique: TcpScanTechnique) -> Vec<u8> {
        build_probe(technique, SRC, DST, 50_000, 80, NONCE).expect("probe builds")
    }

    /// The RST a conformant stack sends back, built from RFC 793 §3.4 directly
    /// so a wrong rule in [`nonce_field`] fails here. Mirrors Linux's
    /// `tcp_v?_send_reset`: an incoming ACK gives the reset its sequence number;
    /// otherwise the reset acknowledges the sequence number plus the octets SYN
    /// and FIN occupy.
    fn conformant_rst(probe: &[u8]) -> Vec<u8> {
        let sent = parse(probe).expect("the probe parses");
        let sent_flags = sent.flags();

        let mut buffer = vec![0u8; TCP_HDR_LEN];
        let mut rst = MutableTcpPacket::new(&mut buffer).unwrap();
        rst.set_source(sent.destination_port());
        rst.set_destination(sent.source_port());
        rst.set_data_offset((TCP_HDR_LEN / WORD_IN_BYTES) as u8);

        if sent_flags & flags::ACK != 0 {
            rst.set_flags(flags::RST);
            rst.set_sequence(sent.acknowledgement());
        } else {
            let control_octets = u32::from(sent_flags & flags::SYN != 0)
                + u32::from(sent_flags & flags::FIN != 0)
                + sent.payload().len() as u32;
            rst.set_flags(flags::RST | flags::ACK);
            rst.set_sequence(0);
            rst.set_acknowledgement(sent.sequence().wrapping_add(control_octets));
        }
        buffer
    }

    // ── Probe construction ───────────────────────────────────────────────────

    #[test]
    fn each_technique_carries_its_own_flags() {
        use TcpScanTechnique::*;
        let sent = |technique| parse(&probe(technique)).unwrap().flags();

        assert_eq!(sent(Syn), flags::SYN);
        assert_eq!(sent(Fin), flags::FIN);
        assert_eq!(sent(Null), 0);
        assert_eq!(sent(Xmas), flags::FIN | flags::PSH | flags::URG);
        assert_eq!(sent(Maimon), flags::FIN | flags::ACK);
        assert_eq!(sent(Ack), flags::ACK);
        assert_eq!(
            sent(Window),
            flags::ACK,
            "a window scan sends the ack probe"
        );
    }

    /// Where the nonce goes decides whether replies correlate at all.
    #[test]
    fn the_nonce_goes_in_the_field_the_reply_will_echo() {
        use TcpScanTechnique::*;

        for technique in [Syn, Fin, Null, Xmas] {
            let bytes = probe(technique);
            let sent = parse(&bytes).unwrap();
            assert_eq!(sent.sequence(), NONCE, "{technique} nonce");
            assert_eq!(
                sent.acknowledgement(),
                0,
                "{technique} must not claim to acknowledge anything"
            );
        }

        for technique in [Maimon, Ack, Window] {
            let bytes = probe(technique);
            let sent = parse(&bytes).unwrap();
            assert_eq!(sent.acknowledgement(), NONCE, "{technique} nonce");
        }
    }

    /// An MSS announcement is meaningful only on a SYN, and distinctive on
    /// anything else.
    #[test]
    fn only_a_syn_probe_carries_options() {
        assert_eq!(probe(TcpScanTechnique::Syn).len(), TCP_HDR_LEN_WITH_OPTIONS);
        for technique in [
            TcpScanTechnique::Fin,
            TcpScanTechnique::Null,
            TcpScanTechnique::Xmas,
            TcpScanTechnique::Maimon,
            TcpScanTechnique::Ack,
            TcpScanTechnique::Window,
        ] {
            assert_eq!(probe(technique).len(), TCP_HDR_LEN, "{technique}");
        }
    }

    /// A SYN+ACK may carry a window scale, timestamp or SACK-permitted only if
    /// the SYN did (RFC 7323 §2.2 and §3.2, RFC 2018 §2). Dropping one here would
    /// silently make replies identical across operating systems.
    #[test]
    fn a_syn_offers_every_option_it_wants_answered() {
        let probe = probe(TcpScanTechnique::Syn);
        let options = &probe[TCP_HDR_LEN..];

        // Kind, then length for everything but the single-byte no-op.
        assert_eq!(options[0..2], [2, 4], "maximum segment size");
        assert_eq!(options[4..6], [4, 2], "SACK permitted");
        assert_eq!(options[6..8], [8, 10], "timestamp");
        assert_eq!(options[16], 1, "no-op, aligning what follows");
        assert_eq!(options[17..20], [3, 3, 7], "window scale");

        // A SYN's timestamp echo is zero: there is no clock to acknowledge yet.
        assert_eq!(options[12..16], [0, 0, 0, 0], "TSecr");

        assert_eq!(
            options.len() % 4,
            0,
            "the header is measured in four-byte words, so an option list that is \
             not a multiple of four needs padding it does not have"
        );
    }

    #[test]
    fn a_probe_across_address_families_is_refused_rather_than_mis_checksummed() {
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(build_probe(TcpScanTechnique::Syn, SRC, v6, 50_000, 80, NONCE).is_err());
    }

    // ── Correlation ──────────────────────────────────────────────────────────

    /// For every technique, the RST an RFC-conformant stack sends back yields
    /// exactly the nonce that went out. The ACK-carrying techniques would break
    /// under the SYN scan's rule, and NULL and FIN under each other's.
    #[test]
    fn every_technique_reads_its_nonce_back_out_of_a_conformant_reset() {
        for &technique in TcpScanTechnique::ALL {
            let sent = probe(technique);
            let rst = conformant_rst(&sent);
            let reply = parse(&rst).unwrap();

            assert_eq!(
                echoed_nonce(technique, &reply, 0),
                NONCE,
                "{technique} could not recognize its own answer"
            );
        }
    }

    /// The evasion path sends a flag combination no technique names and reads
    /// its own answer back. SYN+FIN is one filters and stacks disagree about; a
    /// conformant reset acking that combination's span yields the nonce.
    #[test]
    fn an_arbitrary_flag_combination_is_sent_and_read_back() {
        const MASK: u8 = flags::SYN | flags::FIN;

        let sent = build_probe_with_flags(MASK, SRC, DST, 50_000, 80, NONCE, None, false)
            .expect("probe builds");
        let parsed = parse(&sent).unwrap();
        assert_eq!(parsed.flags(), MASK, "the segment carries the chosen flags");

        let rst = conformant_rst(&sent);
        let reply = parse(&rst).unwrap();
        assert_eq!(echoed_nonce_with_flags(MASK, &reply, 0), NONCE);
    }

    /// A reply to somebody else's probe does not read as one of ours.
    #[test]
    fn a_reset_answering_a_different_probe_yields_a_different_nonce() {
        let ours = probe(TcpScanTechnique::Fin);
        let theirs = build_probe(TcpScanTechnique::Fin, SRC, DST, 50_000, 80, NONCE ^ 0x1234)
            .expect("probe builds");
        assert_ne!(ours, theirs);

        let reply_bytes = conformant_rst(&theirs);
        let reply = parse(&reply_bytes).unwrap();
        assert_ne!(echoed_nonce(TcpScanTechnique::Fin, &reply, 0), NONCE);
    }

    /// A padded probe still recognises its own answer. A closed port's reset
    /// acknowledges the padding along with the control span, so it is
    /// subtracted; an open port's SYN+ACK acknowledges only the SYN, so it is
    /// not.
    #[test]
    fn a_padded_probe_reads_its_nonce_back_from_either_answer() {
        const PADDING: u16 = 24;

        let padded = build_probe_shaped(
            TcpScanTechnique::Syn,
            SRC,
            DST,
            50_000,
            80,
            NONCE,
            Some(PADDING),
            false,
        )
        .expect("a padded probe builds");

        // Closed: the reset acknowledges the SYN and the padding.
        let rst = conformant_rst(&padded);
        let reply = parse(&rst).unwrap();
        assert_eq!(
            echoed_nonce(TcpScanTechnique::Syn, &reply, PADDING),
            NONCE,
            "a closed port's reset acks the padding, which has to be subtracted back"
        );

        // Open: the SYN+ACK acknowledges the SYN only.
        let sent = parse(&padded).unwrap();
        let mut buffer = vec![0u8; TCP_HDR_LEN];
        let mut syn_ack = MutableTcpPacket::new(&mut buffer).unwrap();
        syn_ack.set_source(sent.destination_port());
        syn_ack.set_destination(sent.source_port());
        syn_ack.set_data_offset((TCP_HDR_LEN / WORD_IN_BYTES) as u8);
        syn_ack.set_flags(flags::SYN | flags::ACK);
        syn_ack.set_sequence(0x5555_5555);
        syn_ack.set_acknowledgement(sent.sequence().wrapping_add(1));
        let reply = parse(syn_ack.packet()).expect("the reply parses");
        assert_eq!(
            echoed_nonce(TcpScanTechnique::Syn, &reply, PADDING),
            NONCE,
            "an open port's SYN+ACK acks only the SYN, so padding must be left in place"
        );
    }

    /// A shaped probe with no shaping is the ordinary probe, byte for byte.
    ///
    /// Only the deterministic techniques compare byte for byte: a SYN carries a
    /// random timestamp and an ACK or Maimon probe a random sequence number.
    #[test]
    fn an_unshaped_probe_is_the_ordinary_probe() {
        for technique in [
            TcpScanTechnique::Fin,
            TcpScanTechnique::Null,
            TcpScanTechnique::Xmas,
        ] {
            let plain = build_probe(technique, SRC, DST, 50_000, 80, NONCE).unwrap();
            let shaped =
                build_probe_shaped(technique, SRC, DST, 50_000, 80, NONCE, None, false).unwrap();
            assert_eq!(
                plain, shaped,
                "{technique} shaped with nothing must not differ"
            );
        }
    }

    /// A padded probe is exactly `len` bytes longer, the checksum covers the
    /// padding, and nothing else about the segment moves.
    #[test]
    fn padding_lengthens_the_probe_and_the_checksum_covers_it() {
        const LEN: u16 = 20;
        let bare = build_probe(TcpScanTechnique::Fin, SRC, DST, 50_000, 80, NONCE).unwrap();
        let padded = build_probe_shaped(
            TcpScanTechnique::Fin,
            SRC,
            DST,
            50_000,
            80,
            NONCE,
            Some(LEN),
            false,
        )
        .unwrap();

        assert_eq!(padded.len(), bare.len() + usize::from(LEN));
        assert_eq!(parse(&padded).unwrap().payload().len(), usize::from(LEN));
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (SRC, DST) else {
            unreachable!("the fixtures are IPv4")
        };
        // Checked through `pnet`'s reader, the crate whose checksum function the
        // builder used. `Segment` does not carry the field: a capture only hands up
        // segments the kernel already verified.
        let segment = pnet_packet::tcp::TcpPacket::new(&padded).expect("the probe parses");
        assert_eq!(
            pnet_packet::tcp::ipv4_checksum(&segment, &src, &dst),
            segment.get_checksum(),
            "a well-formed padded probe carries a checksum that covers its padding"
        );
    }

    /// A bad-checksum probe carries a checksum the host will reject: different
    /// from the correct one and never zero (which means "not computed").
    #[test]
    fn a_bad_checksum_probe_carries_a_checksum_the_host_rejects() {
        let bad = build_probe_shaped(
            TcpScanTechnique::Syn,
            SRC,
            DST,
            50_000,
            80,
            NONCE,
            None,
            true,
        )
        .unwrap();
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (SRC, DST) else {
            unreachable!("the fixtures are IPv4")
        };
        // `pnet`'s reader, as above: `Segment` does not carry the checksum.
        let segment = pnet_packet::tcp::TcpPacket::new(&bad).expect("the probe parses");
        let correct = pnet_packet::tcp::ipv4_checksum(&segment, &src, &dst);
        assert_ne!(
            segment.get_checksum(),
            correct,
            "the checksum must be wrong"
        );
        assert_ne!(
            segment.get_checksum(),
            0,
            "zero is a checksum a host accepts"
        );
    }

    /// A NULL probe occupies no sequence space and a FIN probe one octet. Using
    /// the other's offset rejects every reply, which looks like a firewall.
    #[test]
    fn a_null_probe_and_a_fin_probe_are_acknowledged_one_apart() {
        let null = conformant_rst(&probe(TcpScanTechnique::Null));
        let fin = conformant_rst(&probe(TcpScanTechnique::Fin));

        let null_ack = parse(&null).unwrap().acknowledgement();
        let fin_ack = parse(&fin).unwrap().acknowledgement();

        assert_eq!(null_ack, NONCE);
        assert_eq!(fin_ack, NONCE.wrapping_add(1));
    }

    // ── Quotation ────────────────────────────────────────────────────────────

    /// The eight bytes an ICMP error is guaranteed to quote name the probe, and,
    /// for the four techniques that put their nonce there, the attempt.
    #[test]
    fn eight_quoted_bytes_name_the_probe_and_a_sequence_nonce() {
        let sent = probe(TcpScanTechnique::Fin);
        let quoted = quoted_probe(&sent[..8]).expect("eight bytes are enough");

        assert_eq!(quoted.source, 50_000);
        assert_eq!(quoted.destination, 80);
        assert_eq!(quoted.acknowledgement, None);
        assert_eq!(quoted_nonce(TcpScanTechnique::Fin, &quoted), Some(NONCE));
    }

    /// A technique whose nonce sits in the acknowledgement field is past the
    /// guaranteed quotation, so a short quote names the probe but not the
    /// attempt.
    #[test]
    fn an_ack_carrying_probe_needs_a_generous_quotation_to_name_its_attempt() {
        let sent = probe(TcpScanTechnique::Ack);

        let short = quoted_probe(&sent[..8]).expect("eight bytes are enough");
        assert_eq!(short.destination, 80, "the probe is still identified");
        assert_eq!(quoted_nonce(TcpScanTechnique::Ack, &short), None);

        let full = quoted_probe(&sent).expect("a full header parses");
        assert_eq!(quoted_nonce(TcpScanTechnique::Ack, &full), Some(NONCE));
    }

    #[test]
    fn a_quotation_too_short_to_name_a_probe_is_rejected() {
        assert_eq!(quoted_probe(&probe(TcpScanTechnique::Syn)[..7]), None);
    }

    // ── Classification ───────────────────────────────────────────────────────

    #[test]
    fn classifies_syn_ack_and_rst() {
        let syn_ack = packet_with_flags(flags::SYN | flags::ACK);
        let rst = packet_with_flags(flags::RST);

        assert_eq!(
            classify_probe_response(&parse(&syn_ack).unwrap()),
            Some(TcpReply::SynAck)
        );
        assert_eq!(
            classify_probe_response(&parse(&rst).unwrap()),
            Some(TcpReply::Rst { window: 0 })
        );
    }

    /// A RST replying to a probe legitimately carries ACK too (RFC 793 §3.4).
    #[test]
    fn classifies_rst_ack_as_a_reset() {
        let bytes = packet_with_flags(flags::RST | flags::ACK);
        assert_eq!(
            classify_probe_response(&parse(&bytes).unwrap()),
            Some(TcpReply::Rst { window: 0 })
        );
    }

    /// The classifier carries the window off the wire intact for a window scan.
    #[test]
    fn a_reset_carries_the_window_it_announced() {
        let mut buffer = vec![0u8; TCP_HDR_LEN];
        let mut tcp = MutableTcpPacket::new(&mut buffer).unwrap();
        tcp.set_data_offset((TCP_HDR_LEN / WORD_IN_BYTES) as u8);
        tcp.set_flags(flags::RST | flags::ACK);
        tcp.set_window(4096);

        assert_eq!(
            classify_probe_response(&parse(&buffer).unwrap()),
            Some(TcpReply::Rst { window: 4096 })
        );
    }

    /// An acknowledgement with nothing structural beside it is a *challenge
    /// ACK*: the segment does not fit a connection the stack holds (RFC 793 §3.9,
    /// RFC 5961 §4 for a SYN). Only a listener has a half-open connection, so this
    /// is evidence about the port.
    ///
    /// It is what a retransmitted SYN draws when the first SYN+ACK was lost, so
    /// discarding it would lose open ports on exactly the lossy paths
    /// retransmission exists for.
    #[test]
    fn classifies_a_bare_ack_as_a_challenge() {
        let bytes = packet_with_flags(flags::ACK);
        assert_eq!(
            classify_probe_response(&parse(&bytes).unwrap()),
            Some(TcpReply::ChallengeAck)
        );
    }

    /// Segments that have nothing to do with a probe: a FIN+ACK is a peer
    /// closing a conversation, a bare SYN is somebody opening one, and a lone PSH
    /// or URG acknowledges nothing.
    #[test]
    fn ignores_unrelated_flag_combinations() {
        for flags in [
            flags::ACK | flags::FIN,
            flags::SYN,
            flags::PSH,
            flags::URG,
            0,
        ] {
            let bytes = packet_with_flags(flags);
            assert_eq!(
                classify_probe_response(&parse(&bytes).unwrap()),
                None,
                "flags {flags:#04b} answer no probe"
            );
        }
    }
}
