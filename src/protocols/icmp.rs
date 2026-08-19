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
//! [`create_all_nodes_echo_request_v6`] asks a whole segment at once and is
//! what a sweep sends. The unicast forms ask one host, which is what a targeted
//! run wants and what an IPv4 sweep has no alternative to, there being no
//! all-nodes group to ask.

use crate::protocols::craft::{Ethernet, Icmpv4, Icmpv6, Ipv4, Ipv6, Packet};
use crate::protocols::error::Result;
use crate::protocols::ip;
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::EtherTypes;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The link-layer and IPv6 addresses of the all-nodes group, which every IPv6
/// host on a segment joins (RFC 4291 §2.7.1).
/// An IPv4 echo reply's type number (RFC 792).
const ECHO_REPLY_V4: u8 = 0;
/// An IPv6 echo reply's type number (RFC 4443 §4.2). Different from the IPv4
/// one, like every other number these two protocols share a name for.
const ECHO_REPLY_V6: u8 = 129;

const ALL_NODES_MAC: MacAddr = MacAddr(0x33, 0x33, 0, 0, 0, 1);
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
pub fn create_all_nodes_echo_request_v6(
    src_mac: &MacAddr,
    src_addr: &Ipv6Addr,
    identifier: u16,
    sequence: u16,
) -> Vec<u8> {
    echo_frame_v6(
        *src_mac,
        ALL_NODES_MAC,
        *src_addr,
        ALL_NODES_V6,
        ip::HOP_LIMIT_ON_LINK,
        identifier,
        sequence,
    )
}

/// Builds an echo request aimed at one IPv6 host.
///
/// The counterpart of [`create_all_nodes_echo_request_v6`] for a run that knows
/// which host it is asking, and so does not need to wake the rest of the
/// segment to ask it.
///
/// `hop_limit` is the caller's because the answer differs by where the target
/// is: [`HOP_LIMIT_ON_LINK`](super::ip::HOP_LIMIT_ON_LINK) for a neighbour, and
/// [`HOP_LIMIT_ROUTED`](super::ip::HOP_LIMIT_ROUTED) for anything past the
/// first router.
pub fn create_echo_request_v6(
    src_mac: &MacAddr,
    dst_mac: MacAddr,
    src_addr: &Ipv6Addr,
    dst_addr: Ipv6Addr,
    hop_limit: u8,
    identifier: u16,
    sequence: u16,
) -> Vec<u8> {
    echo_frame_v6(
        *src_mac, dst_mac, *src_addr, dst_addr, hop_limit, identifier, sequence,
    )
}

/// Builds an echo request aimed at one IPv4 host: an ordinary ping.
///
/// IPv4 has no all-nodes group to ask, so every echo it sends is a unicast one.
/// A sweep that wants to ping a range sends one of these per address.
pub fn create_echo_request_v4(
    src_mac: &MacAddr,
    dst_mac: MacAddr,
    src_addr: &Ipv4Addr,
    dst_addr: Ipv4Addr,
    identifier: u16,
    sequence: u16,
) -> Vec<u8> {
    Packet::new()
        .push(Ethernet::new(*src_mac, dst_mac).with_ethertype(EtherTypes::Ipv4))
        .push(Ipv4::new(*src_addr, dst_addr))
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
        .push(Ethernet::new(src_mac, dst_mac).with_ethertype(EtherTypes::Ipv6))
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
/// so its length and contents are part of what a probe asks — a stack that
/// truncates it, or returns something else, has said something about itself.
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
pub fn create_echo_request_message(
    src_addr: IpAddr,
    dst_addr: IpAddr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    match (src_addr, dst_addr) {
        (IpAddr::V4(_), IpAddr::V4(_)) => Ok(Icmpv4::echo_request(identifier, sequence)
            .with_payload(payload)
            .to_bytes()),
        (IpAddr::V6(_), IpAddr::V6(_)) => Icmpv6::echo_request(identifier, sequence)
            .with_payload(payload)
            .to_bytes(Some((src_addr, dst_addr))),
        (src, dst) => Err(super::error::PacketError::FamilyMismatch { src, dst }),
    }
}

/// What an ICMP message arriving at an echo scan turned out to be.
///
/// Deliberately shallow. It separates the answers a caller can act on from the
/// traffic a promiscuous, unnarrowed capture brings up alongside them, and does
/// not interpret any of them further — an error means something different to
/// each probe that could have drawn it, which is the reasoning
/// [`tcp::classify_probe_response`](super::tcp::classify_probe_response) already
/// records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoReply {
    /// An echo reply carrying back the identifier this scan sent, and the
    /// sequence number naming which request it answers.
    Ours { sequence: u16 },
    /// An echo reply, but to somebody else's ping.
    ///
    /// Not folded in with the message below. A capture this wide sees every ping
    /// on the host, and a scan counting these separately can tell "the filter is
    /// noisy" from "the target answered something unexpected".
    SomebodyElses,
    /// An ICMP message that is not an echo reply at all — most usefully an
    /// error, which says the probe was stopped rather than answered.
    ///
    /// The type is carried rather than named because the two families number
    /// their messages differently and a name would have to say which.
    Other { icmp_type: u8 },
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

/// Whichever unicast echo `dst_addr`'s family calls for.
///
/// A convenience for a caller holding an [`IpAddr`] rather than a decided
/// family, which is the ordinary case once targets have been parsed.
pub fn create_echo_request(
    src_mac: &MacAddr,
    dst_mac: MacAddr,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    hop_limit: u8,
    identifier: u16,
    sequence: u16,
) -> Result<Vec<u8>> {
    match (src_addr, dst_addr) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => Ok(create_echo_request_v4(
            src_mac, dst_mac, &src, dst, identifier, sequence,
        )),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Ok(create_echo_request_v6(
            src_mac, dst_mac, &src, dst, hop_limit, identifier, sequence,
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
    use pnet::packet::Packet as _;
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
    use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::ipv6::Ipv6Packet;

    const SRC_MAC: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 1);
    const DST_MAC: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 2);
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
        let frame = create_all_nodes_echo_request_v6(&SRC_MAC, &v6("fe80::1"), ID, SEQ);

        let eth = EthernetPacket::new(&frame).expect("a frame");
        assert_eq!(eth.get_destination(), ALL_NODES_MAC);
        assert_eq!(eth.get_ethertype(), EtherTypes::Ipv6);

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

    /// IPv4 had no echo at all, so a scan could not ping. The frame has to be a
    /// real one: right ethertype, right protocol number, a checksummed header
    /// and a checksummed message.
    #[test]
    fn an_ipv4_echo_request_is_a_complete_pingable_frame() {
        let frame = create_echo_request_v4(
            &SRC_MAC,
            DST_MAC,
            &Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 9),
            ID,
            SEQ,
        );

        let eth = EthernetPacket::new(&frame).expect("a frame");
        assert_eq!(eth.get_ethertype(), EtherTypes::Ipv4);

        let ip = Ipv4Packet::new(eth.payload()).expect("an IPv4 header");
        assert_eq!(
            ip.get_next_level_protocol(),
            pnet::packet::ip::IpNextHeaderProtocols::Icmp
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
        let v4 = create_echo_request_v4(
            &SRC_MAC,
            DST_MAC,
            &Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 9),
            ID,
            SEQ,
        );
        let v4_message = &v4[EthernetPacket::minimum_packet_size() + 20..];
        assert_eq!(echo_token(v4_message).expect("a token"), (ID, SEQ));

        let v6_frame = create_echo_request_v6(
            &SRC_MAC,
            DST_MAC,
            &v6("fe80::1"),
            v6("fe80::2"),
            ip::HOP_LIMIT_ON_LINK,
            ID,
            SEQ,
        );
        let v6_message = &v6_frame[EthernetPacket::minimum_packet_size() + 40..];
        assert_eq!(echo_token(v6_message).expect("a token"), (ID, SEQ));
    }

    /// A unicast request goes to the host it names rather than to the segment,
    /// which is what lets a targeted scan probe one address without waking
    /// every neighbour.
    #[test]
    fn a_unicast_request_wakes_only_the_host_it_names() {
        let frame = create_echo_request_v6(
            &SRC_MAC,
            DST_MAC,
            &v6("fe80::1"),
            v6("fe80::2"),
            ip::HOP_LIMIT_ON_LINK,
            ID,
            SEQ,
        );

        let eth = EthernetPacket::new(&frame).expect("a frame");
        assert_eq!(eth.get_destination(), DST_MAC);
        assert_ne!(eth.get_destination(), ALL_NODES_MAC);
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
        let v4 = create_echo_request(
            &SRC_MAC,
            DST_MAC,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
            ip::HOP_LIMIT_ROUTED,
            ID,
            SEQ,
        )
        .expect("one family");

        let direct = create_echo_request_v4(
            &SRC_MAC,
            DST_MAC,
            &Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 9),
            ID,
            SEQ,
        );

        // Compared field by field rather than byte by byte: the identification
        // is random per packet and the header checksum covers it, so two
        // correct frames differ in four bytes by design.
        let read = |frame: &[u8]| {
            let eth = EthernetPacket::new(frame).expect("a frame");
            let ip = Ipv4Packet::new(eth.payload()).expect("a header");
            (
                eth.get_destination(),
                eth.get_ethertype(),
                ip.get_source(),
                ip.get_destination(),
                ip.get_ttl(),
                ip.get_next_level_protocol(),
                ip.payload().to_vec(),
            )
        };
        assert_eq!(read(&v4), read(&direct));

        let mismatched = create_echo_request(
            &SRC_MAC,
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
        let message = create_echo_request_message(
            IpAddr::from([192, 0, 2, 1]),
            IpAddr::from([192, 0, 2, 9]),
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

    /// A conformant responder echoes the payload back, so its length and
    /// contents are part of the question a probe asks.
    #[test]
    fn a_payload_is_carried_verbatim_and_may_be_empty() {
        let empty = create_echo_request_message(
            IpAddr::from([192, 0, 2, 1]),
            IpAddr::from([192, 0, 2, 9]),
            ID,
            SEQ,
            &[],
        )
        .expect("one family");
        assert_eq!(empty.len(), 8);

        let long = create_echo_request_message(
            IpAddr::from([192, 0, 2, 1]),
            IpAddr::from([192, 0, 2, 9]),
            ID,
            SEQ,
            &[0xA5; 120],
        )
        .expect("one family");
        assert_eq!(&long[8..], &[0xA5; 120]);
    }

    /// The two families are two protocols, and the type number is the visible
    /// half of that: 8 is an IPv4 echo request and 128 an IPv6 one. A message
    /// built with the wrong one is not rejected anywhere — it simply goes
    /// unanswered, and a scan reads that as a silent host.
    #[test]
    fn each_family_gets_its_own_message_type() {
        let v4 = create_echo_request_message(
            IpAddr::from([192, 0, 2, 1]),
            IpAddr::from([192, 0, 2, 9]),
            ID,
            SEQ,
            &[],
        )
        .expect("one family");
        assert_eq!(v4[0], 8);

        let v6_message = create_echo_request_message(
            IpAddr::V6(v6("2001:db8::1")),
            IpAddr::V6(v6("2001:db8::9")),
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
    /// RFC 4443 has no encoding for "no checksum" — a zero one is not merely
    /// wrong, it is discarded. So the addresses have to reach the checksum, and
    /// a builder that dropped them would produce a message nothing ever answers.
    #[test]
    fn an_ipv6_message_is_checksummed_against_its_addresses() {
        let message = create_echo_request_message(
            IpAddr::V6(v6("2001:db8::1")),
            IpAddr::V6(v6("2001:db8::9")),
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
        let elsewhere = create_echo_request_message(
            IpAddr::V6(v6("2001:db8::1")),
            IpAddr::V6(v6("2001:db8::a")),
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
            create_echo_request_message(
                IpAddr::from([192, 0, 2, 1]),
                IpAddr::V6(v6("2001:db8::9")),
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
    /// and the same. Both directions are silent — the scan sees a message it
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
        // Destination unreachable, code 13 — administratively prohibited.
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
}
