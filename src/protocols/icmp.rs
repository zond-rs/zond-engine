// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # ICMP echo
//!
//! Ping, over both families, as complete Ethernet frames.
//!
//! ## What an echo buys that a solicitation cannot
//!
//! An echo is *optional* to answer, unlike the neighbor solicitation in
//! [`ndp`](super::ndp): Windows and many embedded stacks ignore it. What it
//! offers in exchange is a reply that can be **timed**. Both RFCs require a
//! reply to carry the request's identifier and sequence back unchanged, so a
//! scanner that remembers which values it sent knows which request an answer
//! belongs to. A solicitation, identical on the wire from one attempt to the
//! next, never can.
//!
//! The convention that makes those two fields useful: one identifier for the
//! whole scan, the sequence counting attempts. Then a matching identifier means
//! the reply is ours, and the sequence names which request it answers.
//!
//! ## One to everybody, or one to somebody
//!
//! [`build_all_nodes_echo_request_v6`] asks a whole segment at once and is
//! what a sweep sends. The unicast forms ask one host, which is what a targeted
//! run wants and what an IPv4 sweep has no alternative to, there being no
//! all-nodes group to ask.

use crate::model::mac::MacAddr;
use crate::protocols::craft::{Ethernet, Icmpv4, Icmpv6, Ipv4, Ipv6, Packet};
use crate::protocols::error::Result;
use crate::protocols::ip;
use pnet_packet::ethernet::EtherTypes;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The code an OS-fingerprinting echo request carries.
///
/// Non-zero on purpose. RFC 792 and RFC 4443 §4.2 define an echo's code as zero
/// and neither says what a responder should do with anything else, so stacks
/// differ: some echo the request's code back and some write zero regardless. A
/// probe sending zero cannot tell those apart, since both answer zero.
///
/// This is the same trap the TCP option layout fell into and it is worth naming
/// as one: a documented difference between stacks is only *observable* if the
/// probe asks the question. Nine carries no meaning of its own; it is simply a
/// value no conformant echo would carry by accident.
pub const ECHO_PROBE_CODE: u8 = 9;

/// An IPv4 echo reply's type number (RFC 792).
const ECHO_REPLY_V4: u8 = 0;
/// An IPv6 echo reply's type number (RFC 4443 §4.2). Different from the IPv4
/// one, like every other number these two protocols share a name for.
const ECHO_REPLY_V6: u8 = 129;

/// The link-layer and IPv6 addresses of the all-nodes group, which every IPv6
/// host on a segment joins (RFC 4291 §2.7.1).
const ALL_NODES_MAC: MacAddr = MacAddr::new(0x33, 0x33, 0, 0, 0, 1);
const ALL_NODES_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Builds the all-nodes echo request every IPv6 neighbour on the segment may
/// answer.
///
/// Sent with [`HOP_LIMIT_ON_LINK`](super::ip::HOP_LIMIT_ON_LINK), so a router
/// discards it rather than forwarding it and a sweep of one segment cannot leak
/// onto the next.
///
/// See the [module documentation](self) for what `identifier` and `sequence`
/// are for.
pub fn build_all_nodes_echo_request_v6(
    src_mac: MacAddr,
    src_addr: Ipv6Addr,
    identifier: u16,
    sequence: u16,
) -> Vec<u8> {
    echo_frame_v6(
        src_mac,
        ALL_NODES_MAC,
        src_addr,
        ALL_NODES_V6,
        ip::HOP_LIMIT_ON_LINK,
        identifier,
        sequence,
    )
}

/// Builds an echo request aimed at one IPv6 host.
///
/// The counterpart of [`build_all_nodes_echo_request_v6`] for a run that knows
/// which host it is asking, and so does not need to wake the rest of the
/// segment to ask it.
///
/// `hop_limit` is the caller's because the answer differs by where the target
/// is: [`HOP_LIMIT_ON_LINK`](super::ip::HOP_LIMIT_ON_LINK) for a neighbour, and
/// [`HOP_LIMIT_ROUTED`](super::ip::HOP_LIMIT_ROUTED) for anything past the
/// first router.
pub fn build_echo_request_v6(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
    hop_limit: u8,
    identifier: u16,
    sequence: u16,
) -> Vec<u8> {
    echo_frame_v6(
        src_mac, dst_mac, src_addr, dst_addr, hop_limit, identifier, sequence,
    )
}

/// Builds an echo request aimed at one IPv4 host: an ordinary ping.
///
/// IPv4 has no all-nodes group to ask, so every echo it sends is a unicast one.
/// A sweep that wants to ping a range sends one of these per address.
pub fn build_echo_request_v4(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    identifier: u16,
    sequence: u16,
) -> Vec<u8> {
    Packet::new()
        .push(Ethernet::new(src_mac, dst_mac).with_ethertype(EtherTypes::Ipv4.0))
        .push(Ipv4::new(src_addr, dst_addr))
        .push(Icmpv4::echo_request(identifier, sequence))
        .build()
        // Infallible: an eight-byte message cannot overflow a length field, and
        // both addresses come from the same family by construction.
        .expect("an echo request fits every length field it is counted by")
}

/// The IPv6 half of both public builders above.
fn echo_frame_v6(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
    hop_limit: u8,
    identifier: u16,
    sequence: u16,
) -> Vec<u8> {
    Packet::new()
        .push(Ethernet::new(src_mac, dst_mac).with_ethertype(EtherTypes::Ipv6.0))
        .push(Ipv6::new(src_addr, dst_addr).with_hop_limit(hop_limit))
        .push(Icmpv6::echo_request(identifier, sequence))
        .build()
        .expect("an echo request fits every length field it is counted by")
}

/// Builds an echo request as a **message**, with no IP or Ethernet header
/// around it, for a caller sending over a raw Layer-4 socket.
///
/// The other builders here produce whole Ethernet frames, which need a
/// destination hardware address and so only reach a neighbour on the local
/// segment. This is the form that reaches a host behind a router: the kernel
/// supplies the IP header and does the routing, exactly as it does for the TCP
/// and UDP probes.
///
/// `payload` is echoed back by a conformant responder (RFC 792, RFC 4443 §4.2),
/// so its length and contents are part of what a probe asks. A stack that
/// truncates it, or returns something else, has said something about itself.
///
/// `code` is part of the question too, and a probe sending zero is asking
/// nothing: see [`ECHO_PROBE_CODE`].
///
/// Both addresses are taken because an ICMPv6 checksum covers a pseudo-header
/// built from them. An ICMPv4 checksum does not, and `src` is unused there.
///
/// # Errors
///
/// [`PacketError::FamilyMismatch`](super::error::PacketError::FamilyMismatch)
/// when the two addresses are not of the same family, and
/// [`PacketError`](super::error::PacketError) from the IPv6 checksum for a
/// payload too large to be counted.
pub fn build_echo_request_message(
    src_addr: IpAddr,
    dst_addr: IpAddr,
    code: u8,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    match (src_addr, dst_addr) {
        (IpAddr::V4(_), IpAddr::V4(_)) => Ok(Icmpv4::echo_request(identifier, sequence)
            .with_payload(payload)
            .with_code(code)
            .to_bytes()),
        (IpAddr::V6(_), IpAddr::V6(_)) => Icmpv6::echo_request(identifier, sequence)
            .with_payload(payload)
            .with_code(code)
            .to_bytes(Some((src_addr, dst_addr))),
        (src, dst) => Err(super::error::PacketError::FamilyMismatch { src, dst }),
    }
}

/// What an ICMP message arriving at an echo scan turned out to be.
///
/// Shallow on purpose. It separates the answers a caller can act on from the
/// traffic a promiscuous, unnarrowed capture brings up alongside them, and does
/// not interpret any of them further: an error means something different to each
/// probe that could have drawn it, which is the reasoning
/// [`tcp::classify_probe_response`](super::tcp::classify_probe_response) already
/// records.
///
/// `#[non_exhaustive]`: an ICMP error that is worth telling apart from the rest
/// becomes a variant here, and the four below are the ones a scan acts on today
/// rather than all it could ever meet. A caller matching on this needs a
/// wildcard arm, and would need one anyway.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoReply {
    /// An echo reply carrying back the identifier this scan sent, and the
    /// sequence number naming which request it answers.
    Ours {
        /// The sequence number the request went out with, which is what ties
        /// the reply to one attempt and so lets it be timed.
        sequence: u16,
    },
    /// An echo reply, but to somebody else's ping.
    ///
    /// Not folded in with the message below. A capture this wide sees every ping
    /// on the host, and a scan counting these separately can tell "the filter is
    /// noisy" from "the target answered something unexpected".
    SomebodyElses,
    /// An ICMP message that is not an echo reply at all, most usefully an error,
    /// which says the probe was stopped rather than answered.
    ///
    /// The type is carried rather than named because the two families number
    /// their messages differently and a name would have to say which.
    Other {
        /// The type byte, read under the family the message arrived over:
        /// destination unreachable is 3 over IPv4 and 1 over IPv6.
        icmp_type: u8,
    },
    /// Too few bytes to be an ICMP message.
    Truncated,
}

/// Reads one ICMP message and says whether it answers this scan.
///
/// `over_ipv6` selects which numbering to read the type under, and it is a
/// parameter rather than a guess because **an ICMP message does not say which
/// family it belongs to**: type 0 is an IPv4 echo reply and also a perfectly
/// ordinary reserved value over IPv6, and type 128 is an IPv6 echo *request*
/// while over IPv4 it is unassigned. A caller has the address the reply came
/// from and therefore knows; a reader that guessed would be wrong silently.
///
/// The identifier is checked rather than assumed because the kernel filter
/// cannot check it: it sits past a header whose length is not fixed over IPv6.
/// Everything the capture admits therefore arrives here, including every other
/// ping on the host.
pub fn classify_echo_reply(message: &[u8], identifier: u16, over_ipv6: bool) -> EchoReply {
    let Ok((seen_identifier, sequence)) = echo_token(message) else {
        return EchoReply::Truncated;
    };
    let icmp_type = message[0];
    let expected = if over_ipv6 {
        ECHO_REPLY_V6
    } else {
        ECHO_REPLY_V4
    };
    if icmp_type != expected {
        return EchoReply::Other { icmp_type };
    }
    if seen_identifier != identifier {
        return EchoReply::SomebodyElses;
    }
    EchoReply::Ours { sequence }
}

/// The identifier and sequence an echo message carries, for either family.
///
/// Reads the four bytes after the checksum, which is where both RFCs put them.
/// A caller holding a captured reply uses this to find which of its own
/// requests was answered.
///
/// # Errors
///
/// [`PacketError::Truncated`](super::error::PacketError::Truncated) when the
/// message is too short to carry them.
pub fn echo_token(message: &[u8]) -> Result<(u16, u16)> {
    let head: &[u8; 8] = message.first_chunk().ok_or_else(|| {
        super::error::PacketError::truncated("an ICMP echo message", 8, message.len())
    })?;
    Ok((
        u16::from_be_bytes([head[4], head[5]]),
        u16::from_be_bytes([head[6], head[7]]),
    ))
}

// ---------------------------------------------------------------------------
// Timestamp
// ---------------------------------------------------------------------------

/// ICMPv4 timestamp reply, RFC 792. There is no IPv6 counterpart.
const TIMESTAMP_REPLY_V4: u8 = 14;

/// The bytes a timestamp message carries after its identifier and sequence:
/// three four-byte values, RFC 792.
const TIMESTAMP_PAYLOAD_LEN: usize = 12;

/// Builds a timestamp request, RFC 792's type 13.
///
/// IPv4 only, and the caller has to know it: RFC 4443 defines no timestamp
/// message, so there is nothing to send an IPv6 target and a scan that tried
/// would be building a message no stack has ever been asked to parse.
///
/// The three timestamps go out as zero. A conformant sender writes its own
/// clock into the originate field and a conformant target echoes it back, which
/// would let the round trip be read off the reply alone; sending zero instead
/// keeps this host's clock off the wire and leaves the offset to be computed
/// against a local reading, which is what [`TimestampReply::offset_from`] takes.
/// A scanner asking a stranger what time it is has no business volunteering its
/// own.
pub fn build_timestamp_request(identifier: u16, sequence: u16) -> Vec<u8> {
    Icmpv4::timestamp_request(identifier, sequence)
        .with_payload([0u8; TIMESTAMP_PAYLOAD_LEN])
        .to_bytes()
}

/// The three clock readings a timestamp reply carries, RFC 792.
///
/// Each is milliseconds since midnight UT. The high bit is a flag rather than
/// part of the value: a target whose clock is not referenced to midnight UT sets
/// it to say so, and the number underneath means nothing a reader can compare
/// against. See [`is_standard`](Self::is_standard).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimestampReply {
    /// What the sender put in the request, which this engine sends as zero.
    pub originate: u32,
    /// When the target received the request, by its own clock.
    pub receive: u32,
    /// When it sent the reply, by the same clock.
    pub transmit: u32,
}

/// The bit RFC 792 reserves to say a timestamp is not referenced to midnight UT.
const NON_STANDARD: u32 = 0x8000_0000;

/// Milliseconds in a day, which is the range a reading has to fall in to be a
/// time of day at all.
const MILLIS_PER_DAY: u32 = 86_400_000;

impl TimestampReply {
    /// Whether the target's clock is referenced to midnight UT, so its readings
    /// can be compared with anything.
    ///
    /// False where the target set the high bit on either of its own readings,
    /// which RFC 792 defines as "this value is not a standard time". An offset
    /// computed from one of those is arithmetic on two different scales.
    pub const fn is_standard(self) -> bool {
        self.receive & NON_STANDARD == 0 && self.transmit & NON_STANDARD == 0
    }

    /// Whether the readings are times of day at all.
    ///
    /// Stricter than [`is_standard`](Self::is_standard), and the flag is not
    /// enough on its own: it occupies the top bit, so every value from a day's
    /// worth of milliseconds up to a little over two billion clears it and is
    /// still not a time. A target sending one of those is not answering the
    /// question, whether through a broken clock, a deliberately odd stack, or a
    /// reply somebody else wrote.
    ///
    /// It matters because the alternative is worse than a missing answer. The
    /// offset below folds onto the half-day either side of zero so that a reply
    /// crossing midnight reads correctly, and folding an out-of-range reading
    /// the same way would turn a number that means nothing into a plausible
    /// offset of a few hours, which a report would then state as a fact.
    pub const fn is_a_time_of_day(self) -> bool {
        self.is_standard() && self.receive < MILLIS_PER_DAY && self.transmit < MILLIS_PER_DAY
    }

    /// How far the target's clock is ahead of `local_millis`, in milliseconds,
    /// or `None` where the target said its clock is not a standard time.
    ///
    /// `local_millis` is this host's own milliseconds since midnight UT, read
    /// when the reply arrived. Positive means the target is ahead.
    ///
    /// The reading includes the return path, so it is out by up to the time the
    /// reply spent in flight. That is a millisecond or two on a segment and does
    /// not matter to what this is for: an offset of hours says a host is in
    /// another timezone or has never had its clock set, and one of seconds says
    /// it is not synchronised, and neither conclusion turns on the round trip.
    ///
    /// Wrapping is handled rather than ignored. Both clocks reset at midnight,
    /// so a reply crossing it would otherwise read as an offset of nearly a full
    /// day in whichever direction the two readings happened to fall.
    ///
    /// `None` where the target's readings are not times of day, or where
    /// `local_millis` is not one either, which would be this engine's own fault
    /// rather than the target's. See [`is_a_time_of_day`](Self::is_a_time_of_day).
    pub fn offset_from(self, local_millis: u32) -> Option<i64> {
        if !self.is_a_time_of_day() || local_millis >= MILLIS_PER_DAY {
            return None;
        }
        let day = i64::from(MILLIS_PER_DAY);
        let difference = i64::from(self.transmit) - i64::from(local_millis);
        // Fold onto the half-day either side of zero, so a crossing of midnight
        // reads as the small offset it is rather than as a day's worth. Both
        // readings are inside a day, so one adjustment is always enough.
        Some(match difference {
            d if d > day / 2 => d - day,
            d if d < -day / 2 => d + day,
            d => d,
        })
    }
}

/// What an ICMP message arriving at a timestamp probe turned out to be.
///
/// The same shape [`EchoReply`] has, and for its reasons.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampAnswer {
    /// A timestamp reply carrying back this scan's identifier.
    Ours {
        /// Which request it answers.
        sequence: u16,
        /// The three readings it carried.
        reply: TimestampReply,
    },
    /// A timestamp reply to somebody else's request.
    SomebodyElses,
    /// An ICMP message that is not a timestamp reply.
    Other {
        /// The type byte, read under IPv4's numbering.
        icmp_type: u8,
    },
    /// Too few bytes to be a timestamp reply.
    Truncated,
}

/// Reads one ICMP message and says whether it answers a timestamp probe.
///
/// IPv4 numbering only, because a timestamp message exists nowhere else. A
/// caller holding a reply from an IPv6 address has not received one of these
/// whatever the type byte says.
///
/// Every offset is checked against what arrived: these bytes are a stranger's,
/// and a capture admitting all ICMP brings up every message on the host.
pub fn classify_timestamp_reply(message: &[u8], identifier: u16) -> TimestampAnswer {
    let Ok((seen_identifier, sequence)) = echo_token(message) else {
        return TimestampAnswer::Truncated;
    };
    if message[0] != TIMESTAMP_REPLY_V4 {
        return TimestampAnswer::Other {
            icmp_type: message[0],
        };
    }
    if seen_identifier != identifier {
        return TimestampAnswer::SomebodyElses;
    }

    // The three readings sit behind the eight bytes `echo_token` already
    // checked. A reply that stopped short of them is a reply that answered
    // nothing, whatever its type said.
    let Some(values) = message.get(8..8 + TIMESTAMP_PAYLOAD_LEN) else {
        return TimestampAnswer::Truncated;
    };
    let word = |at: usize| {
        u32::from_be_bytes([values[at], values[at + 1], values[at + 2], values[at + 3]])
    };

    TimestampAnswer::Ours {
        sequence,
        reply: TimestampReply {
            originate: word(0),
            receive: word(4),
            transmit: word(8),
        },
    }
}

/// Whichever unicast echo `dst_addr`'s family calls for.
///
/// A convenience for a caller holding an [`IpAddr`] rather than a decided
/// family, which is the ordinary case once targets have been parsed.
pub fn build_echo_request(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    hop_limit: u8,
    identifier: u16,
    sequence: u16,
) -> Result<Vec<u8>> {
    match (src_addr, dst_addr) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => Ok(build_echo_request_v4(
            src_mac, dst_mac, src, dst, identifier, sequence,
        )),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Ok(build_echo_request_v6(
            src_mac, dst_mac, src, dst, hop_limit, identifier, sequence,
        )),
        (src, dst) => Err(super::error::PacketError::FamilyMismatch { src, dst }),
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
    use pnet_packet::Packet as _;
    use pnet_packet::icmp::{IcmpPacket, IcmpTypes};
    use pnet_packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
    use pnet_packet::ipv4::Ipv4Packet;
    use pnet_packet::ipv6::Ipv6Packet;

    const SRC_MAC: MacAddr = MacAddr::new(0x02, 0, 0, 0, 0, 1);
    const DST_MAC: MacAddr = MacAddr::new(0x02, 0, 0, 0, 0, 2);
    const ID: u16 = 0xBEEF;
    const SEQ: u16 = 7;

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().expect("a valid address")
    }

    /// The frame a sweep sends, checked end to end: it reaches the all-nodes
    /// group at the link layer and the IP layer both, and it does not leave the
    /// segment.
    #[test]
    fn the_all_nodes_request_is_addressed_to_the_whole_segment_and_stays_on_it() {
        let frame = build_all_nodes_echo_request_v6(SRC_MAC, v6("fe80::1"), ID, SEQ);

        let eth = super::super::ethernet::parse(&frame).expect("a frame");
        assert_eq!(eth.destination(), ALL_NODES_MAC);
        assert_eq!(eth.ethertype(), EtherTypes::Ipv6.0);

        let ip = Ipv6Packet::new(eth.payload()).expect("an IPv6 header");
        assert_eq!(ip.get_destination(), ALL_NODES_V6);
        assert_eq!(
            ip.get_hop_limit(),
            ip::HOP_LIMIT_ON_LINK,
            "a router must discard it rather than forward it"
        );

        let icmp = Icmpv6Packet::new(ip.payload()).expect("an ICMPv6 message");
        assert_eq!(icmp.get_icmpv6_type(), Icmpv6Types::EchoRequest);
        assert_ne!(icmp.get_checksum(), 0, "checksummed over the pseudo-header");
    }

    /// Without an IPv4 echo a scan cannot ping at all. The frame has to be a
    /// real one: right ethertype, right protocol number, a checksummed header
    /// and a checksummed message.
    #[test]
    fn an_ipv4_echo_request_is_a_complete_pingable_frame() {
        let frame = build_echo_request_v4(
            SRC_MAC,
            DST_MAC,
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 9),
            ID,
            SEQ,
        );

        let eth = super::super::ethernet::parse(&frame).expect("a frame");
        assert_eq!(eth.ethertype(), EtherTypes::Ipv4.0);

        let ip = Ipv4Packet::new(eth.payload()).expect("an IPv4 header");
        assert_eq!(
            ip.get_next_level_protocol(),
            pnet_packet::ip::IpNextHeaderProtocols::Icmp
        );
        assert_eq!(ip.get_total_length() as usize, eth.payload().len());
        assert_ne!(ip.get_checksum(), 0);

        let icmp = IcmpPacket::new(ip.payload()).expect("an ICMP message");
        assert_eq!(icmp.get_icmp_type(), IcmpTypes::EchoRequest);
        assert_ne!(icmp.get_checksum(), 0);
    }

    /// Both families put the identifier and sequence in the same four bytes, so
    /// one reader serves both. Without them an echo reply proves only that its
    /// sender exists; with them it also says which question was asked.
    #[test]
    fn an_echo_carries_back_the_token_that_names_the_request() {
        let v4 = build_echo_request_v4(
            SRC_MAC,
            DST_MAC,
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 9),
            ID,
            SEQ,
        );
        let v4_message = &v4[crate::protocols::sizes::ETH_HDR_LEN + 20..];
        assert_eq!(echo_token(v4_message).expect("a token"), (ID, SEQ));

        let v6_frame = build_echo_request_v6(
            SRC_MAC,
            DST_MAC,
            v6("fe80::1"),
            v6("fe80::2"),
            ip::HOP_LIMIT_ON_LINK,
            ID,
            SEQ,
        );
        let v6_message = &v6_frame[crate::protocols::sizes::ETH_HDR_LEN + 40..];
        assert_eq!(echo_token(v6_message).expect("a token"), (ID, SEQ));
    }

    /// A unicast request goes to the host it names rather than to the segment,
    /// which is what lets a targeted scan probe one address without waking
    /// every neighbour.
    #[test]
    fn a_unicast_request_wakes_only_the_host_it_names() {
        let frame = build_echo_request_v6(
            SRC_MAC,
            DST_MAC,
            v6("fe80::1"),
            v6("fe80::2"),
            ip::HOP_LIMIT_ON_LINK,
            ID,
            SEQ,
        );

        let eth = super::super::ethernet::parse(&frame).expect("a frame");
        assert_eq!(eth.destination(), DST_MAC);
        assert_ne!(eth.destination(), ALL_NODES_MAC);
        assert_eq!(
            Ipv6Packet::new(eth.payload())
                .expect("an IPv6 header")
                .get_destination(),
            v6("fe80::2")
        );
    }

    /// The family-dispatching form has to agree with the two it dispatches to,
    /// or a caller holding an `IpAddr` gets a different packet than one that
    /// had already decided.
    #[test]
    fn the_dispatching_form_builds_what_the_family_specific_ones_do() {
        let v4 = build_echo_request(
            SRC_MAC,
            DST_MAC,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
            ip::HOP_LIMIT_ROUTED,
            ID,
            SEQ,
        )
        .expect("one family");

        let direct = build_echo_request_v4(
            SRC_MAC,
            DST_MAC,
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 9),
            ID,
            SEQ,
        );

        // Compared field by field rather than byte by byte: the identification
        // is random per packet and the header checksum covers it, so two
        // correct frames differ in four bytes by design.
        let read = |frame: &[u8]| {
            let eth = super::super::ethernet::parse(frame).expect("a frame");
            let ip = Ipv4Packet::new(eth.payload()).expect("a header");
            (
                eth.destination(),
                eth.ethertype(),
                ip.get_source(),
                ip.get_destination(),
                ip.get_ttl(),
                ip.get_next_level_protocol(),
                ip.payload().to_vec(),
            )
        };
        assert_eq!(read(&v4), read(&direct));

        let mismatched = build_echo_request(
            SRC_MAC,
            DST_MAC,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6(v6("2001:db8::1")),
            ip::HOP_LIMIT_ROUTED,
            ID,
            SEQ,
        );
        assert!(mismatched.is_err(), "two families cannot make one packet");
    }
    /// The message form starts at the ICMP header and nowhere else.
    ///
    /// Pinned because the mistake it guards against is silent and this module
    /// invites it: every other builder here returns a whole Ethernet frame, and
    /// handing one of those to a raw Layer-4 socket puts a second IP header on
    /// the wire inside the first. The receiver would read the outer header, find
    /// what it thinks is an ICMP message, and see an Ethernet header where the
    /// type byte should be. Reading the token straight out of the first eight
    /// bytes is the cheapest way to say "this begins where it claims to".
    #[test]
    fn the_message_form_carries_no_headers_of_its_own() {
        let message = build_echo_request_message(
            IpAddr::from([192, 0, 2, 1]),
            IpAddr::from([192, 0, 2, 9]),
            0,
            ID,
            SEQ,
            b"payload",
        )
        .expect("one family");

        let parsed = IcmpPacket::new(&message).expect("an ICMP message");
        assert_eq!(parsed.get_icmp_type(), IcmpTypes::EchoRequest);
        assert_eq!(echo_token(&message).expect("a token"), (ID, SEQ));
        assert_eq!(&message[8..], b"payload");
    }

    /// The code has to reach the wire, because a probe sending zero asks nothing.
    ///
    /// The behaviour this field exists to observe, whether a responder echoes a
    /// non-zero code or writes zero, is invisible to a conformant request, since
    /// both stacks answer zero to a zero. A builder that dropped
    /// the code would produce a probe that always looked like it worked and
    /// never discriminated anything.
    #[test]
    fn the_probe_code_is_written_into_the_message() {
        let probe = build_echo_request_message(
            IpAddr::from([192, 0, 2, 1]),
            IpAddr::from([192, 0, 2, 9]),
            ECHO_PROBE_CODE,
            ID,
            SEQ,
            &[],
        )
        .expect("one family");
        assert_eq!(probe[1], ECHO_PROBE_CODE);
        assert_ne!(ECHO_PROBE_CODE, 0, "a zero code asks nothing");

        // And over IPv6, where the code is also covered by the checksum.
        let v6_probe = build_echo_request_message(
            IpAddr::V6(v6("2001:db8::1")),
            IpAddr::V6(v6("2001:db8::9")),
            ECHO_PROBE_CODE,
            ID,
            SEQ,
            &[],
        )
        .expect("one family");
        assert_eq!(v6_probe[1], ECHO_PROBE_CODE);
    }

    /// A conformant responder echoes the payload back, so its length and
    /// contents are part of the question a probe asks.
    #[test]
    fn a_payload_is_carried_verbatim_and_may_be_empty() {
        let empty = build_echo_request_message(
            IpAddr::from([192, 0, 2, 1]),
            IpAddr::from([192, 0, 2, 9]),
            0,
            ID,
            SEQ,
            &[],
        )
        .expect("one family");
        assert_eq!(empty.len(), 8);

        let long = build_echo_request_message(
            IpAddr::from([192, 0, 2, 1]),
            IpAddr::from([192, 0, 2, 9]),
            0,
            ID,
            SEQ,
            &[0xA5; 120],
        )
        .expect("one family");
        assert_eq!(&long[8..], &[0xA5; 120]);
    }

    /// The two families are two protocols, and the type number is the visible
    /// half of that: 8 is an IPv4 echo request and 128 an IPv6 one. A message
    /// built with the wrong one is not rejected anywhere. It goes unanswered, and
    /// a scan reads that as a silent host.
    #[test]
    fn each_family_gets_its_own_message_type() {
        let v4 = build_echo_request_message(
            IpAddr::from([192, 0, 2, 1]),
            IpAddr::from([192, 0, 2, 9]),
            0,
            ID,
            SEQ,
            &[],
        )
        .expect("one family");
        assert_eq!(v4[0], 8);

        let v6_message = build_echo_request_message(
            IpAddr::V6(v6("2001:db8::1")),
            IpAddr::V6(v6("2001:db8::9")),
            0,
            ID,
            SEQ,
            &[],
        )
        .expect("one family");
        assert_eq!(
            Icmpv6Packet::new(&v6_message)
                .expect("an ICMPv6 message")
                .get_icmpv6_type(),
            Icmpv6Types::EchoRequest
        );
    }

    /// An ICMPv6 checksum covers a pseudo-header built from both addresses, and
    /// RFC 4443 has no encoding for an absent checksum, and a zero one is not
    /// merely wrong but discarded. So the addresses have to reach the checksum,
    /// and
    /// a builder that dropped them would produce a message nothing ever answers.
    #[test]
    fn an_ipv6_message_is_checksummed_against_its_addresses() {
        let message = build_echo_request_message(
            IpAddr::V6(v6("2001:db8::1")),
            IpAddr::V6(v6("2001:db8::9")),
            0,
            ID,
            SEQ,
            &[],
        )
        .expect("one family");
        let checksum = u16::from_be_bytes([message[2], message[3]]);
        assert_ne!(checksum, 0);

        // A different destination is a different pseudo-header and so a
        // different checksum. Without this the test above passes for a builder
        // that computes over the message alone, which is the ICMPv4 rule.
        let elsewhere = build_echo_request_message(
            IpAddr::V6(v6("2001:db8::1")),
            IpAddr::V6(v6("2001:db8::a")),
            0,
            ID,
            SEQ,
            &[],
        )
        .expect("one family");
        assert_ne!(
            checksum,
            u16::from_be_bytes([elsewhere[2], elsewhere[3]]),
            "the checksum did not depend on the destination"
        );
    }

    /// Two families in one call is a caller error, not something to guess at.
    #[test]
    fn a_mixed_pair_of_addresses_is_refused() {
        assert!(
            build_echo_request_message(
                IpAddr::from([192, 0, 2, 1]),
                IpAddr::V6(v6("2001:db8::9")),
                0,
                ID,
                SEQ,
                &[],
            )
            .is_err()
        );
    }

    /// The scan's own reply is the one carrying back the identifier it sent.
    #[test]
    fn a_reply_is_ours_only_when_it_carries_our_identifier() {
        let ours = Icmpv4::echo_reply(ID, SEQ).to_bytes();
        assert_eq!(
            classify_echo_reply(&ours, ID, false),
            EchoReply::Ours { sequence: SEQ }
        );

        let theirs = Icmpv4::echo_reply(ID ^ 0xFFFF, SEQ).to_bytes();
        assert_eq!(
            classify_echo_reply(&theirs, ID, false),
            EchoReply::SomebodyElses
        );
    }

    /// The two families number their messages differently, and reading one under
    /// the other's numbering is the mistake worth a test of its own.
    ///
    /// An IPv4 echo reply is type 0 and an IPv6 one is 129. Read an IPv6 reply
    /// as IPv4 and it is not an echo reply at all; read an IPv4 reply as IPv6
    /// and the same. Both directions are silent: the scan sees a message it
    /// cannot use and files the host as unanswered.
    #[test]
    fn a_reply_is_read_under_its_own_family_numbering() {
        let v4 = Icmpv4::echo_reply(ID, SEQ).to_bytes();
        let v6 = Icmpv6::echo_reply(ID, SEQ)
            .to_bytes(Some((
                IpAddr::V6(v6("2001:db8::1")),
                IpAddr::V6(v6("2001:db8::9")),
            )))
            .expect("one family");

        assert_eq!(
            classify_echo_reply(&v4, ID, false),
            EchoReply::Ours { sequence: SEQ }
        );
        assert_eq!(
            classify_echo_reply(&v6, ID, true),
            EchoReply::Ours { sequence: SEQ }
        );

        assert_eq!(
            classify_echo_reply(&v6, ID, false),
            EchoReply::Other { icmp_type: 129 },
            "an IPv6 reply read as IPv4"
        );
        assert_eq!(
            classify_echo_reply(&v4, ID, true),
            EchoReply::Other { icmp_type: 0 },
            "an IPv4 reply read as IPv6"
        );
    }

    /// An error is not an echo reply, and saying so is the whole verdict: what
    /// it means depends on what was being probed, which this does not know.
    #[test]
    fn an_error_is_reported_as_itself() {
        // Destination unreachable, code 13, administratively prohibited.
        let error = Icmpv4 {
            icmp_type: 3,
            code: 13,
            checksum: super::super::craft::Field::Computed,
            rest_of_header: [0; 4],
            payload: vec![0; 8],
        }
        .to_bytes();
        assert_eq!(
            classify_echo_reply(&error, ID, false),
            EchoReply::Other { icmp_type: 3 }
        );
    }

    /// Too short to hold a token is not "somebody else's": a scan counting the
    /// two together cannot tell a noisy filter from a malformed answer.
    #[test]
    fn a_message_too_short_to_carry_a_token_says_so() {
        assert_eq!(
            classify_echo_reply(&[0, 0, 0], ID, false),
            EchoReply::Truncated
        );
        assert_eq!(classify_echo_reply(&[], ID, false), EchoReply::Truncated);
    }

    // ── Timestamp ────────────────────────────────────────────────────────────

    /// A request a conformant target will answer: the type RFC 792 gives it, the
    /// identifier and sequence where an echo puts them, and twelve bytes behind
    /// them for the three readings.
    #[test]
    fn a_timestamp_request_is_framed_the_way_rfc_792_asks() {
        let message = build_timestamp_request(0xBEEF, 7);

        assert_eq!(message[0], 13, "a timestamp request");
        assert_eq!(message[1], 0, "code zero");
        assert_eq!(echo_token(&message).expect("a token"), (0xBEEF, 7));
        assert_eq!(
            message.len(),
            8 + TIMESTAMP_PAYLOAD_LEN,
            "header, identifier and sequence, then three four-byte readings"
        );
        assert!(
            message[8..].iter().all(|byte| *byte == 0),
            "this host's own clock does not go on the wire"
        );
    }

    /// A reply, built from the RFC layout rather than from the builder above, so
    /// what this asserts is the protocol and not the engine's reading of it.
    fn timestamp_reply(identifier: u16, sequence: u16, values: [u32; 3]) -> Vec<u8> {
        let mut message = vec![14u8, 0, 0, 0];
        message.extend_from_slice(&identifier.to_be_bytes());
        message.extend_from_slice(&sequence.to_be_bytes());
        for value in values {
            message.extend_from_slice(&value.to_be_bytes());
        }
        message
    }

    #[test]
    fn a_timestamp_reply_yields_its_three_readings() {
        let message = timestamp_reply(0xBEEF, 7, [0, 1_000, 1_005]);

        let TimestampAnswer::Ours { sequence, reply } = classify_timestamp_reply(&message, 0xBEEF)
        else {
            panic!("the reply answers this scan");
        };
        assert_eq!(sequence, 7);
        assert_eq!(reply.receive, 1_000);
        assert_eq!(reply.transmit, 1_005);
        assert!(reply.is_standard());
    }

    /// The offset is what the probe is for, and it is read against a local
    /// reading rather than off the wire.
    #[test]
    fn the_offset_is_the_targets_clock_less_ours() {
        let ahead = TimestampReply {
            originate: 0,
            receive: 5_000,
            transmit: 5_000,
        };
        assert_eq!(ahead.offset_from(2_000), Some(3_000));
        assert_eq!(ahead.offset_from(9_000), Some(-4_000));
    }

    /// Both clocks reset at midnight, so a reply that crosses it would otherwise
    /// read as an offset of nearly a whole day in whichever direction the two
    /// readings happened to fall. A scan reporting a host as twenty-four hours
    /// out because it was probed at 23:59 is reporting the arithmetic.
    #[test]
    fn a_reply_across_midnight_is_a_small_offset_and_not_a_days_worth() {
        const DAY: u32 = 86_400_000;

        // The target has just passed midnight; this host has not quite.
        let target_past_midnight = TimestampReply {
            originate: 0,
            receive: 500,
            transmit: 500,
        };
        assert_eq!(
            target_past_midnight.offset_from(DAY - 500),
            Some(1_000),
            "one second ahead, not a day behind"
        );

        // And the other way round.
        let target_before_midnight = TimestampReply {
            originate: 0,
            receive: DAY - 500,
            transmit: DAY - 500,
        };
        assert_eq!(
            target_before_midnight.offset_from(500),
            Some(-1_000),
            "one second behind, not a day ahead"
        );
    }

    /// A reading past a day's worth of milliseconds is not a time of day, and
    /// the RFC's flag does not catch it: the flag is the top bit, so everything
    /// from a day up to two billion clears it.
    ///
    /// Reading the RFC does not show it, and the property test below does. It
    /// matters: the fold onto the half-day would turn a number meaning nothing
    /// into a plausible offset of a few hours, which a report would then state
    /// as a fact about the host's clock.
    #[test]
    fn a_reading_that_is_not_a_time_of_day_yields_no_offset() {
        let absurd = TimestampReply {
            originate: 0,
            receive: 2_000_000_000,
            transmit: 2_000_000_000,
        };
        assert!(
            absurd.is_standard(),
            "the high bit is clear, so the RFC's own flag says nothing"
        );
        assert!(!absurd.is_a_time_of_day());
        assert_eq!(absurd.offset_from(2_000), None);

        // The boundary: one millisecond short of a day is a time, and a day is
        // not, since midnight is the next day's zero.
        let last = TimestampReply {
            originate: 0,
            receive: 86_399_999,
            transmit: 86_399_999,
        };
        assert!(last.is_a_time_of_day());
        let midnight = TimestampReply {
            originate: 0,
            receive: 86_400_000,
            transmit: 86_400_000,
        };
        assert!(!midnight.is_a_time_of_day());

        // And a local reading out of range is this engine's fault rather than
        // the target's, answered the same way.
        assert_eq!(last.offset_from(86_400_000), None);
    }

    /// RFC 792 lets a target say its clock is not referenced to midnight UT by
    /// setting the high bit. An offset computed from one of those is arithmetic
    /// across two different scales, so none is offered.
    #[test]
    fn a_non_standard_clock_yields_no_offset_at_all() {
        let non_standard = TimestampReply {
            originate: 0,
            receive: 0x8000_0000 | 5_000,
            transmit: 0x8000_0000 | 5_000,
        };
        assert!(!non_standard.is_standard());
        assert_eq!(non_standard.offset_from(2_000), None);

        // The flag on either reading is enough to disqualify the pair.
        let half = TimestampReply {
            originate: 0,
            receive: 5_000,
            transmit: 0x8000_0000 | 5_000,
        };
        assert!(!half.is_standard());
        assert_eq!(half.offset_from(2_000), None);
    }

    /// Somebody else's timestamp exchange is not this scan's answer. The capture
    /// admits every ICMP message on the host, so this is the check that makes a
    /// reply ours.
    #[test]
    fn another_scans_timestamp_reply_is_not_ours() {
        let message = timestamp_reply(0x1234, 1, [0, 1, 2]);
        assert_eq!(
            classify_timestamp_reply(&message, 0xBEEF),
            TimestampAnswer::SomebodyElses
        );
    }

    /// An echo reply is not a timestamp reply, and neither is an error. Both
    /// arrive on the same capture.
    #[test]
    fn what_is_not_a_timestamp_reply_is_named_by_its_type() {
        let echo = vec![0u8, 0, 0, 0, 0xBE, 0xEF, 0, 1];
        assert_eq!(
            classify_timestamp_reply(&echo, 0xBEEF),
            TimestampAnswer::Other { icmp_type: 0 }
        );

        // Destination unreachable, which says the probe was stopped.
        let unreachable = vec![3u8, 1, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            classify_timestamp_reply(&unreachable, 0xBEEF),
            TimestampAnswer::Other { icmp_type: 3 }
        );
    }

    /// A reply of the right type that stops before its readings answered
    /// nothing, whatever its header claimed.
    #[test]
    fn a_timestamp_reply_without_its_readings_is_truncated() {
        let mut message = timestamp_reply(0xBEEF, 7, [0, 1, 2]);
        message.truncate(8 + 4);
        assert_eq!(
            classify_timestamp_reply(&message, 0xBEEF),
            TimestampAnswer::Truncated
        );

        assert_eq!(
            classify_timestamp_reply(&[], 0xBEEF),
            TimestampAnswer::Truncated
        );
    }

    proptest::proptest! {
        /// These bytes come off a capture that admits every ICMP message on the
        /// host, so the walk has to terminate on any input.
        #[test]
        fn classifying_a_timestamp_reply_never_panics(
            message in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64)
        ) {
            let _ = classify_timestamp_reply(&message, 0xBEEF);
        }

        /// And the offset is arithmetic on a stranger's numbers, so it must not
        /// overflow or panic for any of them.
        #[test]
        fn the_offset_never_panics(
            receive in proptest::prelude::any::<u32>(),
            transmit in proptest::prelude::any::<u32>(),
            local in proptest::prelude::any::<u32>(),
        ) {
            let reply = TimestampReply { originate: 0, receive, transmit };
            if let Some(offset) = reply.offset_from(local) {
                assert!(offset.abs() <= 86_400_000 / 2, "folded onto the half-day");
            }
        }
    }
}
