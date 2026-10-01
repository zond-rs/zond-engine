// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What one reply says about the stack that sent it
//!
//! A [`StackObservation`] is the typed feature vector a rule is matched
//! against: everything readable off a single TCP segment and its IP header.
//! Building one is a pure function from bytes; see the
//! [module documentation](super).
//!
//! ## Read the reply kind first
//!
//! A reset carries no TCP options, and the SYN+ACK and reset paths in one stack
//! can disagree: one measured host wrote IP identifier zero on its SYN+ACKs and
//! ran a global counter on its resets. A rule reading the identifier must say
//! which segment it reads.
//!
//! ## Two fields depend on the probe
//!
//! TCP option negotiation is reciprocal (RFC 7323 §2.2 and §3.2, RFC 2018 §2): a
//! SYN+ACK names window scale, timestamps or SACK-permitted only if the SYN did.
//! A SYN offering only an MSS drew only an MSS back from Linux, a router and a
//! wide-area server alike. Layouts are comparable only between observations
//! drawn by the same probe.
//!
//! A stack sizes its receive window in units of the effective segment size, and
//! a negotiated timestamp costs twelve bytes per segment, so the window moves
//! with the options. Measured on four hosts:
//!
//! ```text
//! 64240 = 44 x 1460      65160 = 45 x 1448     (two Linux hosts)
//! 29200 = 20 x 1460      28960 = 20 x 1448     (a low-memory Linux host)
//! 64860 = 47 x 1360+940  64296 = 47 x 1348+940 (a wide-area server)
//! ```
//!
//! The multiplier holds across both; the raw value does not. Rules should use
//! [`window_in_units`](StackObservation::window_in_units);
//! [`window`](StackObservation::window) keeps the raw value.

use pnet_packet::tcp::TcpPacket;

use crate::model::capture::IpObservation;

/// How many options to walk before giving up.
///
/// A TCP header holds at most forty bytes of options, and a non-padding option
/// is at least two bytes. Bounds the walk over remote-chosen bytes.
const MAX_OPTIONS: usize = 20;

/// What a negotiated timestamp costs on every segment after the handshake: ten
/// option bytes plus two of padding to the next four-byte boundary.
///
/// Subtracted from the announced MSS to get the size a stack sizes its window
/// against. See the module documentation.
const TIMESTAMP_OVERHEAD: u16 = 12;

/// A TCP option, by kind, in the order it appeared.
///
/// The *order* is the signal: which options a stack supports depends on era and
/// configuration, but the sequence and padding are particular to each stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum TcpOptionKind {
    /// Kind 0. Ends the list; anything after it is padding.
    EndOfList,
    /// Kind 1. A single padding byte.
    NoOp,
    /// Kind 2. Maximum segment size.
    MaximumSegmentSize,
    /// Kind 3. Window scale.
    WindowScale,
    /// Kind 4. SACK permitted.
    SackPermitted,
    /// Kind 5. A selective-acknowledgement block.
    Sack,
    /// Kind 8. Timestamp.
    Timestamp,
    /// Anything else, by its kind byte. Rare options are highly identifying.
    Other(u8),
}

impl TcpOptionKind {
    fn from_kind(kind: u8) -> Self {
        match kind {
            0 => TcpOptionKind::EndOfList,
            1 => TcpOptionKind::NoOp,
            2 => TcpOptionKind::MaximumSegmentSize,
            3 => TcpOptionKind::WindowScale,
            4 => TcpOptionKind::SackPermitted,
            5 => TcpOptionKind::Sack,
            8 => TcpOptionKind::Timestamp,
            other => TcpOptionKind::Other(other),
        }
    }

    /// The letter for this kind in a layout string, as the public fingerprint
    /// corpora write it.
    pub fn letter(self) -> char {
        match self {
            TcpOptionKind::EndOfList => 'E',
            TcpOptionKind::NoOp => 'N',
            TcpOptionKind::MaximumSegmentSize => 'M',
            TcpOptionKind::WindowScale => 'W',
            TcpOptionKind::SackPermitted => 'S',
            TcpOptionKind::Sack => 'K',
            TcpOptionKind::Timestamp => 'T',
            TcpOptionKind::Other(_) => '?',
        }
    }
}

/// The timestamp option's two values.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamps {
    /// The sender's clock. Two samples and their interval give its frequency.
    pub value: u32,
    /// The value being echoed back. Zero in a segment that has nothing to echo.
    pub echo: u32,
}

/// Header oddities, each of which is rare on its own and close to conclusive
/// when present.
///
/// Each is something a conformant stack does not do.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Quirks {
    /// The three reserved bits after the data offset are not all zero.
    pub reserved_bits_set: bool,
    /// The urgent pointer is non-zero on a segment without the URG flag.
    pub urgent_pointer_without_urg: bool,
    /// The acknowledgement field is non-zero on a segment without the ACK flag.
    pub acknowledgement_without_ack: bool,
    /// A segment announcing an *initial* sequence number announced zero. Legal,
    /// and vanishingly rare from a stack that generates them the way it should.
    ///
    /// Read only off a SYN segment. RFC 793 §3.4 requires a reset answering a
    /// segment without an ACK (this engine's bare SYN) to carry sequence zero,
    /// so every conformant reset would set it.
    pub zero_sequence: bool,
    /// The option list ended with a length that ran past the header, so what
    /// this observation holds is what could be read before it did.
    ///
    /// A sender defect, and a strong signal.
    pub malformed_options: bool,
    /// Something other than padding followed an end-of-list marker.
    pub data_after_end_of_list: bool,
    /// The option list held more options than the walk reads, so the recorded
    /// layout is the first twenty options of it and not the whole.
    ///
    /// Reachable with forty single-byte no-ops. A rule keyed on
    /// [`option_layout`](StackObservation::option_layout) needs to know it is
    /// partial.
    pub options_truncated: bool,
}

impl Quirks {
    /// Whether any oddity at all was seen.
    pub fn any(self) -> bool {
        self != Quirks::default()
    }
}

/// Everything one TCP reply says about the stack that sent it.
///
/// See the [module documentation](super) for the two probe-dependent fields,
/// and for why the reply kind has to be read first.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackObservation {
    /// The TCP flag byte, verbatim.
    ///
    /// [`is_syn_ack`](Self::is_syn_ack) and [`is_reset`](Self::is_reset) are the
    /// usual readings. A bare ACK answering a SYN is a challenge ACK, sent only
    /// by a host holding a half-open connection.
    pub flags: u8,

    /// What the IP header this segment arrived under said.
    pub ip: IpObservation,

    /// The advertised receive window, as written. See
    /// [`window_in_units`](Self::window_in_units) before comparing it.
    pub window: u16,

    /// The option kinds in the order they appeared. Empty for a reset, which
    /// carries none whatever was offered.
    pub option_layout: Vec<TcpOptionKind>,

    /// The announced maximum segment size, if the peer announced one.
    pub mss: Option<u16>,

    /// The window scale shift count, if the peer offered one.
    pub window_scale: Option<u8>,

    /// The timestamp values, if the peer sent them.
    pub timestamps: Option<Timestamps>,

    /// Whether the peer said it accepts selective acknowledgement.
    pub sack_permitted: bool,

    /// Header oddities.
    pub quirks: Quirks,
}

impl StackObservation {
    /// Reads one TCP `segment`, given what its IP header said.
    ///
    /// `segment` is the Layer-4 bytes with the IP header already stripped, which
    /// is what [`CapturedSegment::bytes`] holds. `None` when there are too
    /// few bytes for a TCP header, or when the header claims a length the bytes
    /// do not support.
    ///
    /// [`CapturedSegment::bytes`]: crate::transport::capture::CapturedSegment::bytes
    pub fn from_tcp(ip: IpObservation, segment: &[u8]) -> Option<Self> {
        let packet = TcpPacket::new(segment)?;

        // Below five words the data offset would put the options slice
        // backwards into the fixed header.
        let header_len = usize::from(packet.get_data_offset()) * 4;
        if header_len < 20 || header_len > segment.len() {
            return None;
        }

        let flags = packet.get_flags();
        let walked = walk_options(packet.get_options_raw());

        Some(Self {
            flags,
            ip,
            window: packet.get_window(),
            option_layout: walked.layout,
            mss: walked.mss,
            window_scale: walked.window_scale,
            timestamps: walked.timestamps,
            sack_permitted: walked.sack_permitted,
            quirks: Quirks {
                reserved_bits_set: packet.get_reserved() != 0,
                urgent_pointer_without_urg: packet.get_urgent_ptr() != 0
                    && flags & crate::protocols::tcp::flags::URG == 0,
                acknowledgement_without_ack: packet.get_acknowledgement() != 0
                    && flags & crate::protocols::tcp::flags::ACK == 0,
                zero_sequence: packet.get_sequence() == 0
                    && flags & crate::protocols::tcp::flags::SYN != 0,
                malformed_options: walked.malformed,
                data_after_end_of_list: walked.data_after_end,
                options_truncated: walked.truncated,
            },
        })
    }

    /// Reads a whole IP packet: the IP header for [`IpObservation`], and the TCP
    /// segment behind it.
    ///
    /// For a caller with raw packets (a capture, their own socket, a fixture).
    /// `None` for anything that is not an IP packet carrying a readable TCP
    /// segment.
    pub fn from_ip_packet(packet: &[u8]) -> Option<Self> {
        let parsed = crate::transport::frame::parse_ip_segment(packet)?;
        if parsed.protocol != pnet_packet::ip::IpNextHeaderProtocols::Tcp.0 {
            return None;
        }
        Self::from_tcp(parsed.observation, parsed.payload)
    }

    /// Whether this is a SYN+ACK: a listener accepting a connection attempt, and
    /// the only reply that carries options.
    pub fn is_syn_ack(&self) -> bool {
        use crate::protocols::tcp::flags;
        self.flags & flags::SYN != 0 && self.flags & flags::ACK != 0
    }

    /// Whether this is a reset.
    pub fn is_reset(&self) -> bool {
        self.flags & crate::protocols::tcp::flags::RST != 0
    }

    /// The segment size the sender's window is actually measured in: the
    /// announced maximum segment size, less what a negotiated timestamp costs on
    /// every segment.
    ///
    /// `None` when no maximum segment size was announced, which is every reset
    /// and any SYN+ACK that declined to name one.
    pub fn effective_mss(&self) -> Option<u16> {
        let mss = self.mss?;
        Some(if self.timestamps.is_some() {
            mss.saturating_sub(TIMESTAMP_OVERHEAD)
        } else {
            mss
        })
    }

    /// The advertised window as a multiple of [`effective_mss`](Self::effective_mss),
    /// and what is left over.
    ///
    /// What a rule should compare, rather than [`window`](Self::window): one host
    /// gave `29200 = 20 x 1460` and `28960 = 20 x 1448` to two probes.
    ///
    /// The remainder is also stable: a wide-area server gave `47 x 1360 + 940`
    /// and `47 x 1348 + 940`.
    pub fn window_in_units(&self) -> Option<(u16, u16)> {
        let unit = self.effective_mss()?;
        if unit == 0 {
            return None;
        }
        Some((self.window / unit, self.window % unit))
    }

    /// The smallest common initial hop counter the observed value could have been
    /// decremented from.
    ///
    /// A lower bound: a reply arriving at 57 cannot have started below 64. On a
    /// path longer than the gap to the next starting value it stays true but
    /// says little (a host 40 hops away that started at 64 reads "at least 32").
    pub fn initial_hops_at_least(&self) -> u8 {
        initial_hops_at_least(self.ip.remaining_hops())
    }

    /// One line saying what this observation held, for a report to carry beside a
    /// verdict.
    ///
    /// For a person checking a finding; do not parse it.
    ///
    /// The window is shown as its multiple of the effective segment size, as
    /// rules compare it, with the raw value beside it.
    pub fn summary(&self) -> String {
        let mut out = String::with_capacity(96);
        out.push_str(if self.is_syn_ack() {
            "syn-ack"
        } else if self.is_reset() {
            "reset"
        } else {
            "other"
        });

        out.push_str(&format!(" hops>={}", self.initial_hops_at_least()));
        if !self.option_layout.is_empty() {
            out.push_str(&format!(" opts={}", self.layout_string()));
        }
        match self.window_in_units() {
            Some((units, 0)) => out.push_str(&format!(
                " win={}={}x{}",
                self.window,
                units,
                self.effective_mss().unwrap_or_default()
            )),
            Some((units, remainder)) => out.push_str(&format!(
                " win={}={}x{}+{remainder}",
                self.window,
                units,
                self.effective_mss().unwrap_or_default()
            )),
            None => out.push_str(&format!(" win={}", self.window)),
        }
        if let Some(scale) = self.window_scale {
            out.push_str(&format!(" ws={scale}"));
        }
        if let Some(mss) = self.mss {
            out.push_str(&format!(" mss={mss}"));
        }
        if self.quirks.any() {
            out.push_str(" quirks");
        }
        out
    }

    /// The option layout as the letters the public corpora write it in, comma
    /// separated: `M,S,T,N,W` for a stack that sends a maximum segment size,
    /// SACK-permitted, a timestamp, a no-op and a window scale in that order.
    ///
    /// For display and for translating rules. Match on
    /// [`option_layout`](Self::option_layout).
    pub fn layout_string(&self) -> String {
        let mut out = String::with_capacity(self.option_layout.len() * 2);
        for (index, kind) in self.option_layout.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            match kind {
                TcpOptionKind::Other(number) => out.push_str(&format!("?{number}")),
                named => out.push(named.letter()),
            }
        }
        out
    }
}

/// Everything one ICMP echo reply says about the stack that sent it.
///
/// Shares nothing with [`StackObservation`] below the IP header. Useful for a
/// host with no open or closed port, which many still answer a ping from.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoObservation {
    /// What the IP header this reply arrived under said. The initial hop counter
    /// is the strongest signal here.
    pub ip: IpObservation,

    /// The code byte the reply carried.
    ///
    /// RFC 792 and RFC 4443 §4.2 define the echo code as zero but not what to do
    /// with a request carrying another. Some stacks echo it back, some write
    /// zero; only a non-zero request tells them apart.
    pub code: u8,

    /// How many payload bytes came back.
    pub payload_len: usize,

    /// Whether those bytes are the ones that were sent.
    ///
    /// Both RFCs require the data returned unchanged; a responder that
    /// truncates, pads or rewrites it is distinctive.
    pub payload_intact: bool,
}

impl EchoObservation {
    /// Reads an echo reply, given what its IP header said and what was sent.
    ///
    /// `message` is the ICMP message with the IP header already stripped, which
    /// is what [`CapturedSegment::bytes`] holds. `sent_payload` is the payload of
    /// the request this answers.
    ///
    /// `None` when there are too few bytes for the eight-byte echo header.
    ///
    /// [`CapturedSegment::bytes`]: crate::transport::capture::CapturedSegment::bytes
    pub fn from_echo_reply(ip: IpObservation, message: &[u8], sent_payload: &[u8]) -> Option<Self> {
        // Type, code, checksum, identifier, sequence, then the payload.
        let header: &[u8; 8] = message.first_chunk()?;
        let payload = &message[8..];
        Some(Self {
            ip,
            code: header[1],
            payload_len: payload.len(),
            payload_intact: payload == sent_payload,
        })
    }
}

impl EchoObservation {
    /// One line saying what this reply held, for a report to carry beside a
    /// verdict.
    ///
    /// For a person; do not parse it.
    pub fn summary(&self) -> String {
        let mut out = format!(
            "echo hops>={}",
            initial_hops_at_least(self.ip.remaining_hops())
        );
        if let IpObservation::V4(v4) = self.ip
            && v4.dont_fragment
        {
            out.push_str(" df");
        }
        out.push_str(&format!(" code={}", self.code));
        out.push_str(&format!(" payload={}", self.payload_len));
        if !self.payload_intact {
            // Both RFCs require the payload back unchanged.
            out.push_str(" altered");
        }
        out
    }
}

/// One reply a rule can be asked about.
///
/// A rule declares which reply kind it reads, and fails on any other. A TCP
/// field asked of an echo reply is absent, and fails as any absent value does.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum StackReply {
    /// A TCP reply: a handshake or a refusal.
    Tcp(StackObservation),
    /// An answer to a ping.
    Echo(EchoObservation),
}

impl StackReply {
    /// What the IP header said, whichever kind this is.
    pub fn ip(&self) -> IpObservation {
        match self {
            StackReply::Tcp(observed) => observed.ip,
            StackReply::Echo(observed) => observed.ip,
        }
    }

    /// One line saying what this reply held, for a report to carry beside a
    /// verdict.
    pub fn summary(&self) -> String {
        match self {
            StackReply::Tcp(observed) => observed.summary(),
            StackReply::Echo(observed) => observed.summary(),
        }
    }

    /// The smallest common initial hop counter this reply's is consistent with.
    ///
    /// The same IP field on both kinds. See
    /// [`StackObservation::initial_hops_at_least`].
    pub fn initial_hops_at_least(&self) -> u8 {
        initial_hops_at_least(self.ip().remaining_hops())
    }
}

/// The smallest of the usual initial hop counters that `arrived` could have been
/// decremented from.
///
/// A lower bound; see [`StackObservation::initial_hops_at_least`].
fn initial_hops_at_least(arrived: u8) -> u8 {
    const COMMON: [u8; 4] = [32, 64, 128, 255];
    COMMON
        .into_iter()
        .find(|start| *start >= arrived)
        .unwrap_or(u8::MAX)
}

impl From<StackObservation> for StackReply {
    fn from(observed: StackObservation) -> Self {
        StackReply::Tcp(observed)
    }
}

impl From<EchoObservation> for StackReply {
    fn from(observed: EchoObservation) -> Self {
        StackReply::Echo(observed)
    }
}

/// What one walk of an option list found.
struct Walked {
    layout: Vec<TcpOptionKind>,
    mss: Option<u16>,
    window_scale: Option<u8>,
    timestamps: Option<Timestamps>,
    sack_permitted: bool,
    malformed: bool,
    data_after_end: bool,
    truncated: bool,
}

/// Walks a TCP option list, recording the kinds in order and extracting the
/// values worth naming.
///
/// Every index is checked. A list running off its own end stops the walk and is
/// recorded as a quirk; what was read before it is kept.
fn walk_options(options: &[u8]) -> Walked {
    let mut walked = Walked {
        layout: Vec::new(),
        mss: None,
        window_scale: None,
        timestamps: None,
        sack_permitted: false,
        malformed: false,
        data_after_end: false,
        truncated: false,
    };

    let mut at = 0;
    for _ in 0..MAX_OPTIONS {
        let Some(&kind) = options.get(at) else {
            break;
        };
        walked.layout.push(TcpOptionKind::from_kind(kind));

        // End-of-list: what follows is padding and must be zero.
        if kind == 0 {
            walked.data_after_end = options[at + 1..].iter().any(|byte| *byte != 0);
            break;
        }
        // No-op is the only other single-byte kind; the rest carry a length that
        // includes the kind and length bytes.
        if kind == 1 {
            at += 1;
            continue;
        }

        let Some(&length) = options.get(at + 1) else {
            walked.malformed = true;
            break;
        };
        // A length under two is shorter than the option's own header; checked
        // explicitly, not left to the slice below.
        let length = usize::from(length);
        if length < 2 {
            walked.malformed = true;
            break;
        }
        let Some(value) = options.get(at + 2..at + length) else {
            walked.malformed = true;
            break;
        };

        match (kind, value) {
            (2, [high, low]) => walked.mss = Some(u16::from_be_bytes([*high, *low])),
            (3, [shift]) => walked.window_scale = Some(*shift),
            (4, []) => walked.sack_permitted = true,
            (8, [v0, v1, v2, v3, e0, e1, e2, e3]) => {
                walked.timestamps = Some(Timestamps {
                    value: u32::from_be_bytes([*v0, *v1, *v2, *v3]),
                    echo: u32::from_be_bytes([*e0, *e1, *e2, *e3]),
                });
            }
            // A wrong-sized known kind or an unknown kind: step past by length.
            _ => {}
        }

        at += length;
    }

    // Stopped at the bound: the layout is partial.
    walked.truncated = at < options.len() && !walked.malformed && !walked.data_after_end;

    walked
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

    /// Forty no-ops exceed the walk's bound and are recorded as truncated.
    #[test]
    fn a_truncated_option_walk_says_so() {
        let forty_nops = [1u8; 40];
        let observed = StackObservation::from_tcp(ip(), &segment(0x12, 64_240, &forty_nops))
            .expect("a well-formed header");

        assert_eq!(observed.option_layout.len(), MAX_OPTIONS);
        assert!(observed.quirks.options_truncated);
        assert!(
            !observed.quirks.malformed_options,
            "nothing was malformed; the walk simply stopped"
        );
        assert!(observed.quirks.any());
    }

    /// An ordinary list is not reported as truncated.
    #[test]
    fn a_list_the_walk_reads_whole_is_not_truncated() {
        // Maximum segment size, SACK permitted, timestamp, no-op, window scale.
        let linux: [u8; 20] = [
            0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0xad, 0x58, 0xa5, 0xa7, 0x64, 0x48,
            0x96, 0x12, 0x01, 0x03, 0x03, 0x07,
        ];
        let observed = StackObservation::from_tcp(ip(), &segment(0x12, 65_160, &linux))
            .expect("a well-formed header");

        assert_eq!(observed.layout_string(), "M,S,T,N,W");
        assert!(!observed.quirks.options_truncated);
        assert!(!observed.quirks.any(), "nothing odd about it");
    }

    /// An option claiming a length shorter than its own header is malformed.
    #[test]
    fn an_option_shorter_than_its_own_header_is_malformed() {
        for length in [0u8, 1] {
            let observed =
                StackObservation::from_tcp(ip(), &segment(0x12, 64_240, &[2, length, 0x05, 0xb4]))
                    .expect("a well-formed header");
            assert!(
                observed.quirks.malformed_options,
                "an option of length {length} describes less than its own header"
            );
            assert_eq!(observed.mss, None);
        }
    }
    use super::*;
    use crate::model::capture::Ipv4Observation;

    /// An IPv4 observation with values real Linux hosts produced.
    fn ip() -> IpObservation {
        IpObservation::V4(Ipv4Observation {
            ttl: 64,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            dscp: 0,
            ecn: 0,
        })
    }

    /// Builds a TCP segment with `flags`, `window` and `options` verbatim.
    ///
    /// Assembled from RFC 793 offsets, independently of
    /// [`crate::protocols::craft`].
    fn segment(flags: u8, window: u16, options: &[u8]) -> Vec<u8> {
        assert_eq!(options.len() % 4, 0, "the fixture must be word-aligned");
        let mut bytes = vec![0u8; 20 + options.len()];
        bytes[0..2].copy_from_slice(&80u16.to_be_bytes()); // source port
        bytes[2..4].copy_from_slice(&50_000u16.to_be_bytes()); // destination port
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes()); // sequence
        bytes[8..12].copy_from_slice(&2u32.to_be_bytes()); // acknowledgement
        bytes[12] = (((20 + options.len()) / 4) as u8) << 4; // data offset
        bytes[13] = flags;
        bytes[14..16].copy_from_slice(&window.to_be_bytes());
        bytes[20..].copy_from_slice(options);
        bytes
    }

    const SYN_ACK: u8 = 0b0001_0010; // SYN | ACK
    const RST_ACK: u8 = 0b0001_0100; // RST | ACK

    /// The option bytes three real hosts answered a negotiating SYN with,
    /// recorded off the wire.
    mod recorded {
        /// A consumer router running Linux. Window 65160, MSS 1460.
        pub const ROUTER: [u8; 20] = [
            0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0xf9, 0xc1, 0x3d, 0x9a, 0x7a, 0xfc,
            0xb9, 0x37, 0x01, 0x03, 0x03, 0x07,
        ];
        /// A network appliance running Linux with small receive buffers. Window
        /// 28960, MSS 1460.
        pub const OLDER_LINUX: [u8; 20] = [
            0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x09, 0x6f, 0xa4, 0xb5, 0x56, 0x09,
            0x46, 0x63, 0x01, 0x03, 0x03, 0x03,
        ];
        /// A wide-area server, across a routed path. Window 64296, MSS 1360.
        pub const WIDE_AREA: [u8; 20] = [
            0x02, 0x04, 0x05, 0x50, 0x04, 0x02, 0x08, 0x0a, 0xdb, 0xe1, 0xf2, 0x7e, 0x7d, 0x69,
            0x6f, 0x3b, 0x01, 0x03, 0x03, 0x08,
        ];
    }

    /// The order is pinned, since it is the signal.
    #[test]
    fn a_recorded_reply_yields_its_options_in_the_order_they_arrived() {
        let observed =
            StackObservation::from_tcp(ip(), &segment(SYN_ACK, 65_160, &recorded::ROUTER)).unwrap();

        assert_eq!(observed.layout_string(), "M,S,T,N,W");
        assert_eq!(
            observed.option_layout,
            vec![
                TcpOptionKind::MaximumSegmentSize,
                TcpOptionKind::SackPermitted,
                TcpOptionKind::Timestamp,
                TcpOptionKind::NoOp,
                TcpOptionKind::WindowScale,
            ]
        );
        assert_eq!(observed.mss, Some(1460));
        assert_eq!(observed.window_scale, Some(7));
        assert!(observed.sack_permitted);
        assert_eq!(observed.timestamps.map(|t| t.echo), Some(0x7afc_b937));
        assert!(observed.is_syn_ack() && !observed.is_reset());
        assert!(
            !observed.quirks.any(),
            "a conformant header has no oddities"
        );
    }

    /// The raw window moves with the probe; the multiplier does not. Both arms of
    /// the recorded A/B are checked.
    #[test]
    fn the_window_is_the_same_multiple_of_the_unit_under_either_probe() {
        // MSS-only SYN: no timestamp, so the unit is the announced size.
        let mss_only = [(65_535u16, 64_240u16, 44u16), (65_535, 29_200, 20)];
        for (_, window, expected) in mss_only {
            let observed =
                StackObservation::from_tcp(ip(), &segment(SYN_ACK, window, &[2, 4, 0x05, 0xb4]))
                    .unwrap();
            assert_eq!(observed.effective_mss(), Some(1460));
            assert_eq!(observed.window_in_units(), Some((expected, 0)));
        }

        // Negotiating SYN: with timestamps the unit is twelve bytes smaller.
        let router =
            StackObservation::from_tcp(ip(), &segment(SYN_ACK, 65_160, &recorded::ROUTER)).unwrap();
        assert_eq!(router.effective_mss(), Some(1448));
        assert_eq!(router.window_in_units(), Some((45, 0)));

        let older =
            StackObservation::from_tcp(ip(), &segment(SYN_ACK, 28_960, &recorded::OLDER_LINUX))
                .unwrap();
        assert_eq!(older.effective_mss(), Some(1448));
        assert_eq!(
            older.window_in_units(),
            Some((20, 0)),
            "the same twenty it answered the MSS-only probe with"
        );
    }

    /// The remainder is stable too: this host kept multiplier and offset across
    /// two probes.
    #[test]
    fn a_window_that_is_not_a_clean_multiple_keeps_its_remainder() {
        let negotiated =
            StackObservation::from_tcp(ip(), &segment(SYN_ACK, 64_296, &recorded::WIDE_AREA))
                .unwrap();
        assert_eq!(negotiated.mss, Some(1360));
        assert_eq!(negotiated.effective_mss(), Some(1348));
        assert_eq!(negotiated.window_in_units(), Some((47, 940)));

        let bare = StackObservation::from_tcp(ip(), &segment(SYN_ACK, 64_860, &[2, 4, 0x05, 0x50]))
            .unwrap();
        assert_eq!(
            bare.window_in_units(),
            Some((47, 940)),
            "same host, same shape"
        );
    }

    /// Three hosts, three window scales. A misread shift would look plausible.
    #[test]
    fn each_recorded_host_reports_its_own_window_scale() {
        for (options, expected) in [
            (recorded::ROUTER, 7),
            (recorded::OLDER_LINUX, 3),
            (recorded::WIDE_AREA, 8),
        ] {
            let observed =
                StackObservation::from_tcp(ip(), &segment(SYN_ACK, 1024, &options)).unwrap();
            assert_eq!(observed.window_scale, Some(expected));
        }
    }

    /// A reset carries no options, so every option-derived reading is absent, not
    /// defaulted.
    #[test]
    fn a_reset_carries_nothing_the_options_would_have_said() {
        let observed = StackObservation::from_tcp(ip(), &segment(RST_ACK, 0, &[])).unwrap();

        assert!(observed.is_reset() && !observed.is_syn_ack());
        assert!(observed.option_layout.is_empty());
        assert_eq!(observed.mss, None);
        assert_eq!(observed.window_scale, None);
        assert_eq!(observed.timestamps, None);
        assert!(!observed.sack_permitted);
        assert_eq!(
            observed.window_in_units(),
            None,
            "with no announced size there is no unit to count the window in"
        );
    }

    /// A length running off the end stops the walk and is recorded.
    #[test]
    fn a_length_running_past_the_end_is_kept_as_a_quirk_not_a_panic() {
        // MSS, then a window scale claiming sixty-four bytes of value.
        let observed = StackObservation::from_tcp(
            ip(),
            &segment(SYN_ACK, 1024, &[2, 4, 0x05, 0xb4, 3, 64, 0, 0]),
        )
        .unwrap();

        assert_eq!(observed.mss, Some(1460), "what was read before the defect");
        assert_eq!(observed.window_scale, None);
        assert!(observed.quirks.malformed_options);
    }

    /// An option list that never terminates is bounded.
    #[test]
    fn a_list_of_nothing_but_padding_terminates() {
        let observed = StackObservation::from_tcp(ip(), &segment(SYN_ACK, 1024, &[1; 40])).unwrap();
        assert!(observed.option_layout.len() <= MAX_OPTIONS);
    }

    /// A data offset below five words is refused.
    #[test]
    fn an_impossible_data_offset_is_refused() {
        let mut bytes = segment(SYN_ACK, 1024, &[]);
        bytes[12] = 3 << 4; // three words: shorter than the fixed twenty bytes
        assert!(StackObservation::from_tcp(ip(), &bytes).is_none());
    }

    /// Each quirk is detected.
    #[test]
    fn oddities_a_conformant_header_does_not_have_are_recorded() {
        let mut bytes = segment(0, 1024, &[]); // no flags at all
        bytes[8..12].copy_from_slice(&99u32.to_be_bytes()); // ack without ACK
        bytes[18..20].copy_from_slice(&7u16.to_be_bytes()); // urgent without URG
        bytes[12] |= 0b0000_1110; // reserved bits

        let observed = StackObservation::from_tcp(ip(), &bytes).unwrap();
        assert!(observed.quirks.acknowledgement_without_ack);
        assert!(observed.quirks.urgent_pointer_without_urg);
        assert!(observed.quirks.reserved_bits_set);
        assert!(observed.quirks.any());
    }

    /// A SYN+ACK with initial sequence zero is a quirk.
    #[test]
    fn a_handshake_announcing_sequence_zero_is_an_oddity() {
        let mut bytes = segment(SYN_ACK, 1024, &[]);
        bytes[4..8].copy_from_slice(&0u32.to_be_bytes());

        let observed = StackObservation::from_tcp(ip(), &bytes).unwrap();
        assert!(observed.quirks.zero_sequence);
    }

    /// A reset with sequence zero is not (RFC 793 §3.4).
    #[test]
    fn a_reset_carrying_the_sequence_the_rfc_demands_is_not_an_oddity() {
        let bytes = segment(RST_ACK, 0, &[]); // sequence already zero
        let observed = StackObservation::from_tcp(ip(), &bytes).unwrap();

        assert!(!observed.quirks.zero_sequence);
        assert!(
            !observed.quirks.any(),
            "a textbook reset has nothing odd about it: {:?}",
            observed.quirks
        );
    }
}
