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
//! comes back. What either one *means* is
//! [`TcpScanTechnique`]'s
//! business; this module knows only what a TCP header is.
//!
//! ## The nonce, and why it moves between fields
//!
//! Every probe carries a 32-bit value a conformant stack is obliged to echo,
//! which is what lets a reply be tied to the exact attempt that provoked it -
//! and what stops an unrelated or forged segment from resolving a port. Where
//! that value is written, and where it comes back, is decided by RFC 793 §3.4:
//!
//! > If the incoming segment has an ACK field, the reset takes its sequence
//! > number from the ACK field of the segment; otherwise the reset has sequence
//! > number zero and the ACK field is set to the sum of the sequence number and
//! > segment length of the incoming segment.
//!
//! So a probe carrying ACK - a Maimon or ACK scan - draws a RST that
//! acknowledges *nothing*, and reading `acknowledgement - 1` from it, the way a
//! SYN scan does, finds zero and rejects every genuine answer. The value comes
//! back in the sequence field instead. A probe without ACK is echoed in the
//! acknowledgement field, offset by the sequence space its control flags
//! occupy: one for SYN or FIN, none for a bare ACK-less segment with no flags
//! at all.
//!
//! [`create_probe`] and [`echoed_nonce`] are the two halves of that rule, and
//! both derive it from the probe's flags rather than from a table kept per
//! technique, so a technique added later inherits it by construction.

use std::net::IpAddr;

use pnet_packet::tcp::TcpPacket;

use crate::model::technique::{TcpReply, TcpScanTechnique};
use crate::protocols::craft;
use crate::protocols::error::{PacketError, Result};
use crate::protocols::sizes::TCP_HDR_LEN;

/// TCP header flag bits, in the order they sit in the header.
pub mod flags {
    pub const FIN: u8 = 1;
    pub const SYN: u8 = 1 << 1;
    pub const RST: u8 = 1 << 2;
    pub const PSH: u8 = 1 << 3;
    pub const ACK: u8 = 1 << 4;
    pub const URG: u8 = 1 << 5;
}

/// A header with room for the MSS option a SYN carries.
#[cfg(test)]
const TCP_HDR_LEN_WITH_OPTIONS: usize = TCP_HDR_LEN + SYN_OPTIONS_LEN;
#[cfg(test)]
const WORD_IN_BYTES: usize = 4;

/// The receive window every probe advertises.
///
/// Immaterial to classification - no probe here intends to receive anything -
/// but it is a field stack fingerprinters read, so it is one value across all
/// six techniques rather than a per-technique signature.
const PROBE_WINDOW: u16 = 1024;

/// The maximum segment size advertised on a SYN, sized to clear the common
/// tunnel overheads without inviting fragmentation.
const PROBE_MSS: u16 = 1412;

/// How long the option list on a SYN is: twenty bytes, which is already a
/// multiple of four and so needs no padding.
const SYN_OPTIONS_LEN: usize = 20;

/// The flags each technique's probe carries.
///
/// The whole of the difference between the six, on the wire. Everything else -
/// the header length, the window, the checksum, the retransmission schedule the
/// scanner runs them on - is identical.
pub const fn probe_flags(technique: TcpScanTechnique) -> u8 {
    match technique {
        TcpScanTechnique::Syn => flags::SYN,
        TcpScanTechnique::Fin => flags::FIN,
        // Deliberately empty. A segment with no flags at all is unlike anything
        // a real connection produces, which is the entire point of the NULL
        // scan.
        TcpScanTechnique::Null => 0,
        TcpScanTechnique::Xmas => flags::FIN | flags::PSH | flags::URG,
        TcpScanTechnique::Maimon => flags::FIN | flags::ACK,
        TcpScanTechnique::Ack => flags::ACK,
    }
}

/// Which header field carries a probe's nonce, and how a reply gives it back.
///
/// Derived from the probe's flags per RFC 793 §3.4; see the module
/// documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NonceField {
    /// The nonce is the probe's sequence number, and comes back in the reply's
    /// acknowledgement field advanced by `span` - the sequence space the
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
    // "counting SYN and FIN"), and a stack replying to a segment carrying
    // neither acknowledges the sequence number it was sent unchanged. Getting
    // this wrong is silent: a NULL scan reading a FIN scan's offset rejects
    // every RST it receives and reports the whole range open-filtered.
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
/// The header's *other* 32-bit field carries no meaning and is filled
/// accordingly: zero where it is not significant - the acknowledgement field of
/// a segment without the ACK flag - and a random sequence number where the
/// segment claims to be acknowledging something, since a Maimon or ACK probe
/// announcing sequence zero is an oddity a filter can match on.
///
/// # What a SYN offers, and why it is not just an MSS
///
/// A SYN carries the option list an ordinary client carries: maximum segment
/// size, SACK-permitted, a timestamp and a window scale. That is not politeness.
/// It is the only way to learn what the peer supports, because **TCP option
/// negotiation is reciprocal**: RFC 7323 §2.2 permits a window scale in a
/// SYN+ACK only if the SYN carried one, §3.2 says the same of timestamps, and
/// RFC 2018 §2 of SACK-permitted. A peer reports the options it was *asked*
/// about and nothing more, so a SYN offering only an MSS draws back only an MSS
/// from every stack alike, and the shape of a reply — the strongest thing a
/// single answer says about the machine that sent it — is erased before it is
/// ever read.
///
/// Measured rather than assumed: against a labelled segment, every host with an
/// open port named four more options when asked about four more, and not one
/// port on any host changed its verdict between the two option lists.
/// `benches/os_observe.rs` is the experiment.
///
/// It costs one packet, the same one, twenty bytes longer. If anything it is
/// *less* remarkable on the wire than the bare version, since a real connection
/// attempt looks like this and an MSS-only SYN does not.
pub fn create_probe(
    technique: TcpScanTechnique,
    src_addr: &IpAddr,
    dst_addr: &IpAddr,
    src_port: u16,
    dst_port: u16,
    nonce: u32,
) -> Result<Vec<u8>> {
    let flags = probe_flags(technique);

    let mut segment = craft::Tcp::new(src_port, dst_port).with_flags(flags);
    segment.window = PROBE_WINDOW;

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

    // Options are for a SYN alone. An announcement on a FIN is meaningless to the
    // receiver and distinctive to anything watching, and these techniques are
    // chosen for being unremarkable.
    if flags & flags::SYN != 0 {
        segment.options = syn_options(PROBE_MSS);
    }

    // The checksum covers a pseudo-header built from both addresses, which is
    // why they are parameters. Written through `craft` rather than by hand, so
    // this probe and a hand-crafted segment cannot come to disagree about what
    // a TCP header is.
    segment.to_bytes(Some((*src_addr, *dst_addr)))
}

/// The maximum-segment-size option, as the four bytes a TCP header carries it
/// in: kind 2, length 4, then the value.
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
    options
}

/// The nonce `reply` implies, read from whichever field `technique` expects it
/// back in.
///
/// A caller compares this against the nonces it actually sent: a match names the
/// attempt that was answered, and anything else is a stray, a duplicate, or a
/// forgery, none of which may resolve a port. Arithmetic wraps, because sequence
/// space does.
pub fn echoed_nonce(technique: TcpScanTechnique, reply: &TcpPacket) -> u32 {
    match nonce_field(probe_flags(technique)) {
        NonceField::Sequence { span } => reply.get_acknowledgement().wrapping_sub(span),
        NonceField::Acknowledgement => reply.get_sequence(),
    }
}

/// A probe's header as an ICMP error quotes it back.
///
/// Not a [`TcpPacket`], because there may not be one: RFC 792 requires an error
/// to quote the IP header plus the first **eight** bytes of the offending
/// segment, and a TCP header is twenty. Those eight bytes are the two ports and
/// the sequence number, which is enough to say which probe the error is about;
/// implementations commonly quote more, and the acknowledgement field is
/// reported when they do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotedProbe {
    /// The port the probe was sent from, which is what proves the quoted
    /// datagram belongs to this scan.
    pub source: u16,
    /// The port it was aimed at.
    pub destination: u16,
    pub sequence: u32,
    /// Present only where the quotation ran past the guaranteed eight bytes.
    pub acknowledgement: Option<u32>,
}

/// Reads what an ICMP error quoted of a TCP probe, or `None` if the quotation
/// is too short to name one.
///
/// Every byte here was chosen by whatever sent the error, so nothing is assumed
/// about the length beyond what the RFC guarantees.
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
/// The four techniques that write their nonce into the sequence number are named
/// by the guaranteed eight bytes, so an error about one of them can be tied to
/// the exact attempt it refers to. The two that write it into the acknowledgement
/// field can only be tied that precisely by a sender generous enough to quote
/// twelve, and a caller that gets `None` should fall back to resolving the probe
/// without claiming to know which attempt.
pub fn quoted_nonce(technique: TcpScanTechnique, quoted: &QuotedProbe) -> Option<u32> {
    match nonce_field(probe_flags(technique)) {
        NonceField::Sequence { .. } => Some(quoted.sequence),
        NonceField::Acknowledgement => quoted.acknowledgement,
    }
}

/// Reads `bytes` as a TCP segment.
///
/// # Errors
///
/// [`PacketError::Truncated`] when there are too few bytes for a header.
pub fn parse(bytes: &'_ [u8]) -> Result<TcpPacket<'_>> {
    TcpPacket::new(bytes)
        .ok_or_else(|| PacketError::truncated("a TCP segment", TCP_HDR_LEN, bytes.len()))
}

/// Classifies a received segment as one of the two answers a port probe can
/// draw, if it is one.
///
/// Returns `None` for anything else - established connection traffic, unrelated
/// flag combinations - which a caller should treat as noise. What a classified
/// segment *proves* is technique-dependent and belongs to
/// [`TcpScanTechnique::verdict`]: this says only what arrived.
pub fn classify_probe_response(packet: &TcpPacket) -> Option<TcpReply> {
    let flags = packet.get_flags();

    // RST takes priority over the ACK bit: a reset answering a probe legitimately
    // carries ACK too (RFC 793 §3.4), and reading that as a handshake would turn
    // every closed port into an open one.
    if flags & flags::RST != 0 {
        Some(TcpReply::Rst)
    } else if flags & flags::SYN != 0 && flags & flags::ACK != 0 {
        Some(TcpReply::SynAck)
    } else if flags & flags::ACK != 0 && flags & (flags::SYN | flags::FIN) == 0 {
        // ACK and nothing structural beside it: a challenge ACK, which a stack
        // sends for a segment that does not fit a connection it already holds.
        // Checked last, so a SYN+ACK and a RST+ACK are classified as what they
        // are first — this is the *remainder* of the acknowledging segments, not
        // a competing reading of them.
        //
        // FIN is excluded because a FIN+ACK is a peer closing a connection, which
        // is a statement about a conversation rather than an answer to a probe.
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
        create_probe(technique, &SRC, &DST, 50_000, 80, NONCE).expect("probe builds")
    }

    /// The RST a conformant stack sends back, built here from RFC 793 §3.4
    /// directly rather than from anything in this module - so a wrong rule in
    /// [`nonce_field`] fails rather than agreeing with itself.
    ///
    /// This mirrors Linux's `tcp_v?_send_reset`: an incoming ACK hands the reset
    /// its sequence number, and otherwise the reset acknowledges the sequence
    /// number plus the octets SYN and FIN occupy.
    fn conformant_rst(probe: &[u8]) -> Vec<u8> {
        let sent = TcpPacket::new(probe).expect("the probe parses");
        let sent_flags = sent.get_flags();

        let mut buffer = vec![0u8; TCP_HDR_LEN];
        let mut rst = MutableTcpPacket::new(&mut buffer).unwrap();
        rst.set_source(sent.get_destination());
        rst.set_destination(sent.get_source());
        rst.set_data_offset((TCP_HDR_LEN / WORD_IN_BYTES) as u8);

        if sent_flags & flags::ACK != 0 {
            rst.set_flags(flags::RST);
            rst.set_sequence(sent.get_acknowledgement());
        } else {
            let control_octets = u32::from(sent_flags & flags::SYN != 0)
                + u32::from(sent_flags & flags::FIN != 0)
                + sent.payload().len() as u32;
            rst.set_flags(flags::RST | flags::ACK);
            rst.set_sequence(0);
            rst.set_acknowledgement(sent.get_sequence().wrapping_add(control_octets));
        }
        buffer
    }

    // ── Probe construction ───────────────────────────────────────────────────

    #[test]
    fn each_technique_carries_its_own_flags() {
        use TcpScanTechnique::*;
        let sent = |technique| TcpPacket::new(&probe(technique)).unwrap().get_flags();

        assert_eq!(sent(Syn), flags::SYN);
        assert_eq!(sent(Fin), flags::FIN);
        assert_eq!(sent(Null), 0);
        assert_eq!(sent(Xmas), flags::FIN | flags::PSH | flags::URG);
        assert_eq!(sent(Maimon), flags::FIN | flags::ACK);
        assert_eq!(sent(Ack), flags::ACK);
    }

    /// Where the nonce goes is the difference between a scan that correlates its
    /// replies and one that discards every genuine answer it receives.
    #[test]
    fn the_nonce_goes_in_the_field_the_reply_will_echo() {
        use TcpScanTechnique::*;

        for technique in [Syn, Fin, Null, Xmas] {
            let bytes = probe(technique);
            let sent = TcpPacket::new(&bytes).unwrap();
            assert_eq!(sent.get_sequence(), NONCE, "{technique} nonce");
            assert_eq!(
                sent.get_acknowledgement(),
                0,
                "{technique} must not claim to acknowledge anything"
            );
        }

        for technique in [Maimon, Ack] {
            let bytes = probe(technique);
            let sent = TcpPacket::new(&bytes).unwrap();
            assert_eq!(sent.get_acknowledgement(), NONCE, "{technique} nonce");
        }
    }

    /// An MSS announcement is meaningful only on a SYN, and distinctive on
    /// anything else - these techniques are chosen for being unremarkable.
    #[test]
    fn only_a_syn_probe_carries_options() {
        assert_eq!(probe(TcpScanTechnique::Syn).len(), TCP_HDR_LEN_WITH_OPTIONS);
        for technique in [
            TcpScanTechnique::Fin,
            TcpScanTechnique::Null,
            TcpScanTechnique::Xmas,
            TcpScanTechnique::Maimon,
            TcpScanTechnique::Ack,
        ] {
            assert_eq!(probe(technique).len(), TCP_HDR_LEN, "{technique}");
        }
    }

    /// A peer answers about the options it was *asked* about — a SYN+ACK may
    /// carry a window scale, a timestamp or SACK-permitted only if the SYN did
    /// (RFC 7323 §2.2 and §3.2, RFC 2018 §2). So an option this probe stops
    /// offering is an answer the engine stops being able to read, from every
    /// stack at once, and nothing downstream would report the loss: replies
    /// would simply become identical across operating systems.
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

        // The timestamp a SYN carries has nothing to echo yet, and a non-zero
        // value there claims to be acknowledging a clock nobody sent.
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
        assert!(create_probe(TcpScanTechnique::Syn, &SRC, &v6, 50_000, 80, NONCE).is_err());
    }

    // ── Correlation ──────────────────────────────────────────────────────────

    /// The property the whole correlation rests on: for every technique, the RST
    /// an RFC-conformant stack sends back yields exactly the nonce that went
    /// out. The two ACK-carrying techniques are the ones that would break under
    /// the SYN scan's rule, and the NULL/FIN pair are the ones that would break
    /// under each other's.
    #[test]
    fn every_technique_reads_its_nonce_back_out_of_a_conformant_reset() {
        for technique in TcpScanTechnique::ALL {
            let sent = probe(technique);
            let rst = conformant_rst(&sent);
            let reply = TcpPacket::new(&rst).unwrap();

            assert_eq!(
                echoed_nonce(technique, &reply),
                NONCE,
                "{technique} could not recognize its own answer"
            );
        }
    }

    /// A reply to somebody else's probe must not be readable as one of ours.
    #[test]
    fn a_reset_answering_a_different_probe_yields_a_different_nonce() {
        let ours = probe(TcpScanTechnique::Fin);
        let theirs = create_probe(
            TcpScanTechnique::Fin,
            &SRC,
            &DST,
            50_000,
            80,
            NONCE ^ 0x1234,
        )
        .expect("probe builds");
        assert_ne!(ours, theirs);

        let reply_bytes = conformant_rst(&theirs);
        let reply = TcpPacket::new(&reply_bytes).unwrap();
        assert_ne!(echoed_nonce(TcpScanTechnique::Fin, &reply), NONCE);
    }

    /// A NULL probe occupies no sequence space and a FIN probe occupies one
    /// octet. Reading one with the other's offset is off by exactly one and
    /// rejects every reply, which is the kind of mistake that looks like a
    /// firewall.
    #[test]
    fn a_null_probe_and_a_fin_probe_are_acknowledged_one_apart() {
        let null = conformant_rst(&probe(TcpScanTechnique::Null));
        let fin = conformant_rst(&probe(TcpScanTechnique::Fin));

        let null_ack = TcpPacket::new(&null).unwrap().get_acknowledgement();
        let fin_ack = TcpPacket::new(&fin).unwrap().get_acknowledgement();

        assert_eq!(null_ack, NONCE);
        assert_eq!(fin_ack, NONCE.wrapping_add(1));
    }

    // ── Quotation ────────────────────────────────────────────────────────────

    /// The eight bytes an ICMP error is guaranteed to quote name the probe:
    /// which port on which host, and - for the four techniques that put their
    /// nonce there - which attempt.
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
    /// attempt - and says so rather than guessing.
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
            classify_probe_response(&TcpPacket::new(&syn_ack).unwrap()),
            Some(TcpReply::SynAck)
        );
        assert_eq!(
            classify_probe_response(&TcpPacket::new(&rst).unwrap()),
            Some(TcpReply::Rst)
        );
    }

    /// A RST replying to a probe legitimately carries ACK too (RFC 793 §3.4),
    /// and reading that as a handshake would report every closed port open.
    #[test]
    fn classifies_rst_ack_as_a_reset() {
        let bytes = packet_with_flags(flags::RST | flags::ACK);
        assert_eq!(
            classify_probe_response(&TcpPacket::new(&bytes).unwrap()),
            Some(TcpReply::Rst)
        );
    }

    /// An acknowledgement with nothing structural beside it is a *challenge
    /// ACK*: a stack saying the segment does not fit a connection it already
    /// holds (RFC 793 §3.9, and RFC 5961 §4 for a SYN specifically). Only a host
    /// with a half-open connection sends one, and only a listener has one — so
    /// this is positive evidence about a port rather than the noise it was read
    /// as before.
    ///
    /// It is the reply a *retransmitted* SYN draws when the first SYN+ACK was
    /// lost, which is why discarding it lost open ports on exactly the paths
    /// retransmission exists for. See `docs/bugs.md`.
    #[test]
    fn classifies_a_bare_ack_as_a_challenge() {
        let bytes = packet_with_flags(flags::ACK);
        assert_eq!(
            classify_probe_response(&TcpPacket::new(&bytes).unwrap()),
            Some(TcpReply::ChallengeAck)
        );
    }

    /// The segments that are still nothing to do with a probe. Each carries
    /// something the challenge reading must not swallow: a FIN+ACK is a peer
    /// closing a conversation, a bare SYN is somebody opening one, and a lone
    /// PSH or URG acknowledges nothing at all.
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
                classify_probe_response(&TcpPacket::new(&bytes).unwrap()),
                None,
                "flags {flags:#04b} answer no probe"
            );
        }
    }
}
