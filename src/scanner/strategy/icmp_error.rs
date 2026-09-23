// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # ICMP Errors
//!
//! Reads the two ICMP errors this engine acts on, Destination Unreachable and
//! Time Exceeded, for what each establishes and which probe it is about.
//!
//! They are in one module because the hard part is identical. Neither carries
//! ports of its own, both are attributable only through the datagram they quote
//! back, and that quotation is remote-chosen bytes that have to be parsed
//! defensively. What differs is one type number and what the message means, and
//! those are the only parts written twice.
//!
//! Three strategies depend on this, the UDP and SCTP port scans and the trace,
//! and each would otherwise carry its own copy of two code tables that number
//! the same meanings differently. It sits beside them rather than inside any of
//! them because it is a parser and none of them owns it; a caller writing a
//! fourth raw scanner needs it for the reason the UDP one does.
//!
//! The types here are `#[non_exhaustive]`. Nothing outside this module builds
//! one: they come back from [`parse`] and [`parse_expired`] and are read, so
//! closing construction costs a caller nothing and leaves room for whatever the
//! next protocol turns out to need.
//! What they must *not* share is the conclusion, which is why this module stops
//! at [`Unreachable`] and leaves [`PortState`](crate::model::port::PortState)
//! to the caller: a port unreachable answering a UDP probe is the port's own
//! stack reporting no listener, and the identical message answering a TCP probe
//! cannot be - no TCP stack emits one - so it is a middlebox speaking for an
//! address, which is filtered rather than closed. One enum value, two opposite
//! verdicts, and nothing in the message itself distinguishes them.
//!
//! ## Which probe an error is about
//!
//! An ICMP error carries no ports of its own. RFC 792 requires it to quote the
//! datagram that caused it - the IP header plus at least the first eight bytes -
//! and that quotation is the only thing tying an error to a probe. Reading the
//! quoted packet rather than the error's own header is also what keeps a
//! router's error attributable: the message comes from the router, but the probe
//! it refers to was aimed at the host behind it.
//!
//! Every field in the quotation was chosen by a remote host, so nothing here
//! assumes: it is parsed with the same bounds-checked path as a captured packet
//! ([`frame::parse_ip_segment`]), and eight bytes is all a caller may count on.
//!
//! ## What a caller owes, which is not optional
//!
//! **Parsing a quotation is not attributing one.** Everything above says how the
//! bytes are read safely; none of it says the message is about a probe this scan
//! sent, and this module cannot say that — it does not know what any scanner
//! sent. So every caller owes a check of its own, and *what* satisfies it
//! differs by protocol and by technique:
//!
//! - a nonce, where the technique put one inside the guaranteed eight bytes;
//! - a drawn port or identifier, where it did not;
//! - membership of a ledger of probes still outstanding;
//! - and, where a probe carries nothing at all after its IP header, the source
//!   address it left from, which is weaker and has to be admitted as weaker.
//!
//! Reading an error without one of those is reading a stranger's packet, and
//! the mistake is easy to make in any scanner that reads errors, however
//! carefully it is written: an SCTP INIT believed on its ports, a host filed
//! down on a quoted source port, a TCP technique resolved on a quotation too
//! short to carry its nonce, an IP protocol settled on membership of the scan's
//! own target list.
//!
//! `tests/hygiene/attribution.rs` is what holds every reader to this: a census of
//! every file that reads an error, each with a line saying how it attributes
//! one. A new caller fails that test until the line is written.

use pnet_packet::icmp::destination_unreachable::{DestinationUnreachablePacket, IcmpCodes};
use pnet_packet::icmp::{IcmpCode, IcmpPacket, IcmpTypes};
use pnet_packet::icmpv6::{Icmpv6Code, Icmpv6Packet, Icmpv6Types};
use pnet_packet::ip::IpNextHeaderProtocols;

use crate::transport::capture::CapturedSegment;
use crate::transport::frame::{self, IpSegment};

// The ICMPv6 Destination Unreachable codes worth acting on (RFC 4443 §3.1).
// Spelled out because `pnet` models ICMPv6 codes as a bare newtype, with no
// named constants the way it has for ICMPv4. Visible to the scanners beside
// this module, which build these messages in their own tests: a test naming a
// code by its number is one number away from asserting on a different message
// entirely.
//
/// Code 4: the v6 counterpart of [`IcmpCodes::DestinationPortUnreachable`].
pub(super) const ICMPV6_PORT_UNREACHABLE: Icmpv6Code = Icmpv6Code(4);
/// Code 1: communication with the destination administratively prohibited.
pub(super) const ICMPV6_ADMIN_PROHIBITED: Icmpv6Code = Icmpv6Code(1);
/// Code 5: source address failed an ingress/egress policy.
pub(super) const ICMPV6_INGRESS_EGRESS_POLICY: Icmpv6Code = Icmpv6Code(5);
/// Code 6: the route to the destination is a reject route.
pub(super) const ICMPV6_REJECT_ROUTE: Icmpv6Code = Icmpv6Code(6);
/// Code 0: no route to destination - the v6 counterpart of host unreachable.
pub(super) const ICMPV6_NO_ROUTE: Icmpv6Code = Icmpv6Code(0);
/// Code 3: the address itself is unreachable, whatever the port.
pub(super) const ICMPV6_ADDR_UNREACHABLE: Icmpv6Code = Icmpv6Code(3);

/// The ICMPv6 Parameter Problem code for a Next Header value the receiver does
/// not implement (RFC 4443 §3.4).
///
/// ICMPv6 has no protocol-unreachable code, so this message under this code is
/// the whole of how a v6 host says it does not speak a protocol. It arrives
/// under a different *type* from every other error this module reads, which is
/// why [`parse_v6`] branches on the type rather than only on the code.
pub(super) const ICMPV6_UNRECOGNISED_NEXT_HEADER: Icmpv6Code = Icmpv6Code(1);

/// The four unused bytes between an ICMPv6 Destination Unreachable header and
/// the packet it quotes (RFC 4443 §3.1).
///
/// `pnet` models ICMPv6 only as the generic type/code/checksum header, so its
/// payload still has these in front of the quotation. ICMPv4 needs no
/// equivalent: `pnet` models the Destination Unreachable header itself, so
/// the payload of a `DestinationUnreachablePacket` already starts at the
/// quotation.
pub(super) const ICMPV6_UNUSED_LEN: usize = 4;

/// What a Destination Unreachable code says, named by meaning rather than by
/// number, and stopping short of what it means for the probe.
///
/// The two families number the same meanings differently - a port unreachable
/// is code 3 over IPv4 and code 4 over IPv6 - so resolving the number here is
/// what keeps a scanner from reading a v6 code as its identically numbered v4
/// neighbour, which is a different message entirely.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreachable {
    /// Something received the datagram, looked for a listener on that port, and
    /// found none.
    Port,
    /// Delivery was refused by policy: a filter, an administrative
    /// prohibition, a reject route. It proves only that the probe did not
    /// arrive.
    Prohibited,
    /// The host's own stack does not implement the IP protocol the probe was
    /// sent under.
    ///
    /// Told apart from [`Prohibited`](Self::Prohibited) rather than folded into
    /// it, because they are opposite claims: a prohibition is the path
    /// speaking for the host and this is the host speaking for itself, which
    /// also proves it is there. A probe's own protocol is the one thing a
    /// scanner picks rather than discovers, so for a transport scan the message
    /// is a curiosity and for
    /// [`protocols`](crate::scanner::strategy::protocols) it is the whole
    /// verdict.
    ///
    /// The two families deliver it under different headers. ICMPv4 has a
    /// Destination Unreachable code for it; ICMPv6 has none, and reports an
    /// unrecognised Next Header as a Parameter Problem instead (RFC 4443 §3.4,
    /// type 4 code 1). Resolving both to one meaning here is what this enum is
    /// for.
    Protocol,
    /// The address itself could not be reached at all. A statement about the
    /// host, not about the port that happened to be asked for.
    Host,
}

/// One parsed ICMP error about a probe: what it says, and the packet it quotes.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct IcmpError<'a> {
    /// What the code establishes.
    pub reason: Unreachable,
    /// The probe the message is about, as the sender quoted it back. Its
    /// destination names the host and its payload the transport header, of
    /// which only the first eight bytes are guaranteed to be present.
    ///
    /// **The only thing tying this message to one of yours, and it does not do
    /// that by itself.** Every byte here was chosen by whoever sent the error;
    /// reading it establishes what they claim, not that the claim is about a
    /// probe you sent. See the module documentation for what a caller owes, and
    /// `tests/hygiene/attribution.rs` for who has paid it.
    pub quoted: IpSegment<'a>,
}

/// Reads `reply` as an ICMP error about a probe, whichever family it arrived
/// over.
///
/// A Destination Unreachable in both families, and over IPv6 also a Parameter
/// Problem naming an unrecognised Next Header, which is that family's way of
/// saying what IPv4 says with a protocol-unreachable code.
///
/// `None` for any other captured segment, for a code that reports on neither the
/// port, the protocol nor the path, and for a message whose quotation cannot be
/// parsed.
pub fn parse(reply: &CapturedSegment) -> Option<IcmpError<'_>> {
    match reply.protocol {
        IpNextHeaderProtocols::Icmp => parse_v4(&reply.bytes),
        IpNextHeaderProtocols::Icmpv6 => parse_v6(&reply.bytes),
        _ => None,
    }
}

/// One router naming itself, having discarded a probe that ran out of hops.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Expired<'a> {
    /// The probe the router discarded, as it quoted it back. The only thing
    /// tying this message to one of ours. see [`parse_expired`].
    pub quoted: IpSegment<'a>,
}

/// Reads `reply` as a Time Exceeded: the message a router is required to send
/// when it decrements a hop limit to zero and drops what it was carrying.
///
/// This is the whole mechanism of path discovery, and it works by obligation
/// rather than by cooperation. A router that forwards a packet is
/// under no duty to identify itself; a router that *discards* one is (RFC 792,
/// RFC 4443 §3.3). So a probe built to expire a chosen number of hops away
/// makes exactly that router announce itself, and the announcement arrives from
/// its own address, [`CapturedSegment::source`](crate::transport::capture::CapturedSegment::source),
/// while the quotation inside names the probe that provoked it.
///
/// Both codes are accepted and not distinguished. Code 0 is a hop limit reaching
/// zero in transit and code 1 is a fragment reassembly timeout at the
/// destination; the second cannot answer a probe this engine sends, since
/// nothing here fragments, and treating an unexpected one as a hop would at
/// worst record the destination as its own last hop, which it is.
///
/// `None` for any other captured segment and for a message whose quotation
/// cannot be parsed. A truncated quotation is refused rather than guessed at:
/// eight bytes past the IP header is all RFC 792 guarantees, and a hop
/// attributed to the wrong probe is a wrong path rather than a missing one.
pub fn parse_expired(reply: &CapturedSegment) -> Option<Expired<'_>> {
    let quoted_at = match reply.protocol {
        IpNextHeaderProtocols::Icmp => {
            let message = IcmpPacket::new(&reply.bytes)?;
            if message.get_icmp_type() != IcmpTypes::TimeExceeded {
                return None;
            }
            // Type, code, checksum, and four unused bytes: the same eight-byte
            // preamble a Destination Unreachable carries, which is why the
            // quotation sits at the same offset in both.
            TIME_EXCEEDED_HEADER_LEN
        }
        IpNextHeaderProtocols::Icmpv6 => {
            let message = Icmpv6Packet::new(&reply.bytes)?;
            if message.get_icmpv6_type() != Icmpv6Types::TimeExceeded {
                return None;
            }
            Icmpv6Packet::minimum_packet_size() + ICMPV6_UNUSED_LEN
        }
        _ => return None,
    };

    Some(Expired {
        quoted: frame::parse_ip_segment(reply.bytes.get(quoted_at..)?)?,
    })
}

/// How far into an ICMPv4 Time Exceeded its quotation begins: type, code,
/// checksum, and the four unused bytes (RFC 792).
///
/// Spelled out rather than taken from `DestinationUnreachablePacket`, whose
/// minimum size happens to be the same number. Borrowing a constant from a
/// different message because the arithmetic currently agrees is how the two stop
/// agreeing silently.
const TIME_EXCEEDED_HEADER_LEN: usize = 8;

/// [`parse`] for an ICMPv4 message.
fn parse_v4(bytes: &[u8]) -> Option<IcmpError<'_>> {
    let unreachable = DestinationUnreachablePacket::new(bytes)?;
    if unreachable.get_icmp_type() != IcmpTypes::DestinationUnreachable {
        return None;
    }

    // The quotation is sliced out of `bytes` rather than read through the
    // parsed packet, so it borrows the caller's buffer and outlives this
    // function without a copy. The header before it is fixed: type, code,
    // checksum and four unused bytes.
    let quoted_at = DestinationUnreachablePacket::minimum_packet_size();
    Some(IcmpError {
        reason: reason_v4(unreachable.get_icmp_code())?,
        quoted: frame::parse_ip_segment(bytes.get(quoted_at..)?)?,
    })
}

/// [`parse`] for an ICMPv6 message.
///
/// Two types, because the family splits one meaning across them. Destination
/// Unreachable carries the path's refusals and the address's; a host saying it
/// does not implement a Next Header answers with a Parameter Problem instead,
/// and ICMPv4 has no such split. Both quote the offending packet after a
/// four-byte field, so the quotation sits at one offset either way: unused bytes
/// for the first, the Pointer for the second.
fn parse_v6(bytes: &[u8]) -> Option<IcmpError<'_>> {
    let message = Icmpv6Packet::new(bytes)?;

    let reason = match message.get_icmpv6_type() {
        Icmpv6Types::DestinationUnreachable => reason_v6(message.get_icmpv6_code())?,
        Icmpv6Types::ParameterProblem
            if message.get_icmpv6_code() == ICMPV6_UNRECOGNISED_NEXT_HEADER =>
        {
            Unreachable::Protocol
        }
        // The other two Parameter Problem codes are about a header this engine
        // built, not about the target: an erroneous field or an unrecognised
        // option is a defect here and reading one as a verdict about the host
        // would report this scanner's mistake as the network's.
        _ => return None,
    };

    let quoted_at = Icmpv6Packet::minimum_packet_size() + ICMPV6_UNUSED_LEN;
    Some(IcmpError {
        reason,
        quoted: frame::parse_ip_segment(bytes.get(quoted_at..)?)?,
    })
}

/// What an ICMPv4 Destination Unreachable code establishes, or `None` if it says
/// nothing usable.
///
/// The three administrative prohibitions describe the *path*. "Protocol
/// unreachable" describes the host's own stack and is kept apart from them; see
/// [`Unreachable::Protocol`]. "Host unreachable" is neither: a router could not
/// deliver to the address at all. The remaining codes, network unknown,
/// fragmentation needed, source route failed, say nothing either way.
fn reason_v4(code: IcmpCode) -> Option<Unreachable> {
    match code {
        IcmpCodes::DestinationPortUnreachable => Some(Unreachable::Port),
        IcmpCodes::DestinationProtocolUnreachable => Some(Unreachable::Protocol),
        IcmpCodes::NetworkAdministrativelyProhibited
        | IcmpCodes::HostAdministrativelyProhibited
        | IcmpCodes::CommunicationAdministrativelyProhibited => Some(Unreachable::Prohibited),
        IcmpCodes::DestinationHostUnreachable => Some(Unreachable::Host),
        _ => None,
    }
}

/// The ICMPv6 counterpart of [`reason_v4`] (RFC 4443 §3.1).
///
/// Code 2 (beyond scope of source address) describes the *sender's* address
/// selection rather than the target's reachability, and is left
/// unclassified.
fn reason_v6(code: Icmpv6Code) -> Option<Unreachable> {
    match code {
        ICMPV6_PORT_UNREACHABLE => Some(Unreachable::Port),
        ICMPV6_ADMIN_PROHIBITED | ICMPV6_INGRESS_EGRESS_POLICY | ICMPV6_REJECT_ROUTE => {
            Some(Unreachable::Prohibited)
        }
        ICMPV6_NO_ROUTE | ICMPV6_ADDR_UNREACHABLE => Some(Unreachable::Host),
        _ => None,
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use pnet_packet::icmp::destination_unreachable::MutableDestinationUnreachablePacket;
    use pnet_packet::icmpv6::MutableIcmpv6Packet;

    use crate::protocols::{ip, udp};

    const LOCAL_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
    const TARGET_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));
    const LOCAL_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 50));
    const TARGET_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 200));

    /// The quoted datagram an error carries: the probe's IP header and its
    /// transport header, built with the same functions that build a real probe.
    fn quoted_packet(from: IpAddr, to: IpAddr) -> Vec<u8> {
        let datagram = udp::build_packet(from, to, 50_000, 53, vec![]).unwrap();
        let len = datagram.len() as u16;
        let header = match (from, to) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                ip::build_ipv4_header(s, d, len, IpNextHeaderProtocols::Udp, ip::HOP_LIMIT_ROUTED)
                    .unwrap()
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                ip::build_ipv6_header(s, d, len, IpNextHeaderProtocols::Udp, ip::HOP_LIMIT_ROUTED)
            }
            _ => panic!("IP version mismatch in test fixture"),
        };
        header.into_iter().chain(datagram).collect()
    }

    /// A Time Exceeded from `router`, quoting a probe from us to `target`.
    ///
    /// Built with the same header writers a real probe uses, so the offsets the
    /// parser walks are the ones a router would actually produce rather than
    /// ones a fixture and a parser agreed on between themselves.
    fn expired_v4(router: IpAddr, target: IpAddr) -> CapturedSegment {
        let quoted = quoted_packet(LOCAL_V4, target);
        let mut bytes = vec![0u8; TIME_EXCEEDED_HEADER_LEN + quoted.len()];
        bytes[0] = IcmpTypes::TimeExceeded.0;
        bytes[TIME_EXCEEDED_HEADER_LEN..].copy_from_slice(&quoted);

        CapturedSegment::synthetic(router, IpNextHeaderProtocols::Icmp, bytes)
    }

    /// The IPv6 counterpart.
    fn expired_v6(router: IpAddr, target: IpAddr) -> CapturedSegment {
        let quoted = quoted_packet(LOCAL_V6, target);
        let mut payload = vec![0u8; ICMPV6_UNUSED_LEN];
        payload.extend_from_slice(&quoted);

        let mut bytes = vec![0u8; Icmpv6Packet::minimum_packet_size() + payload.len()];
        let mut packet = MutableIcmpv6Packet::new(&mut bytes).unwrap();
        packet.set_icmpv6_type(Icmpv6Types::TimeExceeded);
        packet.set_payload(&payload);

        CapturedSegment::synthetic(router, IpNextHeaderProtocols::Icmpv6, bytes)
    }

    /// A Time Exceeded names the router in its own header and the probe in its
    /// quotation, and the two are different addresses.
    ///
    /// The distinction the whole of path measurement rests on. Read from the
    /// wrong one, every hop of every trace would come back as the target and a
    /// path would be a list of the host repeated.
    #[test]
    fn an_expiry_names_the_router_that_discarded_it_and_the_probe_it_discarded() {
        for (reply, target) in [
            (expired_v4(TARGET_V4, TARGET_V4), TARGET_V4),
            (expired_v6(TARGET_V6, TARGET_V6), TARGET_V6),
        ] {
            let expired = parse_expired(&reply).expect("a Time Exceeded parses");

            assert_eq!(
                expired.quoted.destination, target,
                "the probe's destination"
            );
            assert_eq!(
                expired.quoted.source,
                if target.is_ipv4() { LOCAL_V4 } else { LOCAL_V6 },
                "the probe left from this host"
            );
        }
    }

    /// The two errors are told apart, in both directions.
    ///
    /// They share a header layout and an eight-byte preamble, so a parser that
    /// skipped the type check would read each as the other, and a Destination
    /// Unreachable read as an expiry puts a firewall into a path as though it
    /// were a router on the way.
    #[test]
    fn an_unreachable_is_not_an_expiry_and_an_expiry_is_not_an_unreachable() {
        let unreachable = error_v4(IcmpCodes::DestinationPortUnreachable);
        assert!(parse(&unreachable).is_some());
        assert!(parse_expired(&unreachable).is_none());

        let expired = expired_v4(TARGET_V4, TARGET_V4);
        assert!(parse_expired(&expired).is_some());
        assert!(parse(&expired).is_none());
    }

    fn error_v4(code: IcmpCode) -> CapturedSegment {
        let quoted = quoted_packet(LOCAL_V4, TARGET_V4);
        let mut bytes =
            vec![0u8; DestinationUnreachablePacket::minimum_packet_size() + quoted.len()];
        let mut packet = MutableDestinationUnreachablePacket::new(&mut bytes).unwrap();
        packet.set_icmp_type(IcmpTypes::DestinationUnreachable);
        packet.set_icmp_code(code);
        packet.set_payload(&quoted);

        CapturedSegment::synthetic(TARGET_V4, IpNextHeaderProtocols::Icmp, bytes)
    }

    fn error_v6(code: Icmpv6Code) -> CapturedSegment {
        let quoted = quoted_packet(LOCAL_V6, TARGET_V6);
        let mut payload = vec![0u8; ICMPV6_UNUSED_LEN];
        payload.extend_from_slice(&quoted);

        let mut bytes = vec![0u8; Icmpv6Packet::minimum_packet_size() + payload.len()];
        let mut packet = MutableIcmpv6Packet::new(&mut bytes).unwrap();
        packet.set_icmpv6_type(Icmpv6Types::DestinationUnreachable);
        packet.set_icmpv6_code(code);
        packet.set_payload(&payload);

        CapturedSegment::synthetic(TARGET_V6, IpNextHeaderProtocols::Icmpv6, bytes)
    }

    /// An ICMPv6 Parameter Problem under `code`, quoting a probe of ours.
    ///
    /// A different type from every other error here, and the only way a v6 host
    /// says it does not implement a protocol.
    fn parameter_problem_v6(code: Icmpv6Code) -> CapturedSegment {
        let quoted = quoted_packet(LOCAL_V6, TARGET_V6);
        // The Pointer field, which sits where a Destination Unreachable's unused
        // bytes do and is why the quotation is at the same offset in both.
        let mut payload = vec![0u8; ICMPV6_UNUSED_LEN];
        payload.extend_from_slice(&quoted);

        let mut bytes = vec![0u8; Icmpv6Packet::minimum_packet_size() + payload.len()];
        let mut packet = MutableIcmpv6Packet::new(&mut bytes).unwrap();
        packet.set_icmpv6_type(Icmpv6Types::ParameterProblem);
        packet.set_icmpv6_code(code);
        packet.set_payload(&payload);

        CapturedSegment::synthetic(TARGET_V6, IpNextHeaderProtocols::Icmpv6, bytes)
    }

    /// What `reply` establishes, for the tests that assert on the reason alone.
    fn reason_of(reply: &CapturedSegment) -> Unreachable {
        parse(reply).expect("the message parses").reason
    }

    /// A host refusing a protocol is not the path refusing delivery, and a scan
    /// that asks which protocols a host speaks needs the two kept apart.
    ///
    /// A prohibition says the probe never arrived. This says it arrived and the
    /// stack had nothing to hand it to, which also proves the host is there.
    #[test]
    fn a_protocol_unreachable_is_the_host_speaking_and_not_the_path() {
        assert_eq!(
            reason_of(&error_v4(IcmpCodes::DestinationProtocolUnreachable)),
            Unreachable::Protocol
        );
        assert_eq!(
            reason_of(&error_v4(
                IcmpCodes::CommunicationAdministrativelyProhibited
            )),
            Unreachable::Prohibited,
            "a prohibition is still a prohibition"
        );
    }

    /// ICMPv6 has no protocol-unreachable code and reports the same thing under
    /// another type entirely, so a reader that only ever opened Destination
    /// Unreachable messages could not see it at all.
    #[test]
    fn the_ipv6_form_of_a_protocol_refusal_arrives_as_a_parameter_problem() {
        assert_eq!(
            reason_of(&parameter_problem_v6(ICMPV6_UNRECOGNISED_NEXT_HEADER)),
            Unreachable::Protocol
        );
    }

    /// The other two Parameter Problem codes are about a header this engine
    /// built. Reading one as a verdict would report a defect here as a fact
    /// about the network.
    #[test]
    fn a_parameter_problem_about_our_own_header_says_nothing_about_the_host() {
        for code in [Icmpv6Code(0), Icmpv6Code(2)] {
            assert!(
                parse(&parameter_problem_v6(code)).is_none(),
                "code {code:?} was read as a verdict"
            );
        }
    }

    /// The quotation names the host the probe was aimed at, not the address the
    /// error came from - which for a router-generated error are different, and
    /// only one of them is the probe's target.
    #[test]
    fn the_quoted_packet_names_the_probe_rather_than_the_sender() {
        let reply = error_v4(IcmpCodes::DestinationPortUnreachable);
        let error = parse(&reply).expect("parses");

        assert_eq!(error.quoted.destination, TARGET_V4);
        assert_eq!(error.quoted.protocol, IpNextHeaderProtocols::Udp);
    }

    /// The near-miss this module exists to prevent: code 3 is a port unreachable
    /// over IPv4 and an *address* unreachable over IPv6, and code 4 is the port
    /// unreachable there. Reading one table for both families reports a
    /// filtered host as a closed port.
    #[test]
    fn the_same_code_number_means_different_things_per_family() {
        let (as_v4, as_v6) = (error_v4(IcmpCode(3)), error_v6(Icmpv6Code(3)));

        assert_eq!(reason_of(&as_v4), Unreachable::Port);
        assert_eq!(reason_of(&as_v6), Unreachable::Host);
        assert_eq!(
            reason_of(&error_v6(ICMPV6_PORT_UNREACHABLE)),
            Unreachable::Port
        );
    }

    #[test]
    fn administrative_refusals_are_recognized_in_both_families() {
        assert_eq!(
            reason_of(&error_v4(
                IcmpCodes::CommunicationAdministrativelyProhibited
            )),
            Unreachable::Prohibited
        );
        for code in [
            ICMPV6_ADMIN_PROHIBITED,
            ICMPV6_INGRESS_EGRESS_POLICY,
            ICMPV6_REJECT_ROUTE,
        ] {
            assert_eq!(reason_of(&error_v6(code)), Unreachable::Prohibited);
        }
    }

    /// A code that reports on neither the port nor the path resolves nothing,
    /// and the probe it quotes is left to retire on its own schedule.
    #[test]
    fn an_uninformative_code_is_not_parsed_into_a_verdict() {
        // Fragmentation needed: a path MTU problem, not a statement about the
        // port or about reachability.
        assert!(parse(&error_v4(IcmpCode(4))).is_none());
        // Beyond scope of source address: about our address selection.
        assert!(parse(&error_v6(Icmpv6Code(2))).is_none());
    }

    /// A message that is not a Destination Unreachable at all - an echo reply,
    /// say - must not be read as one.
    #[test]
    fn another_icmp_message_is_not_an_error() {
        let mut reply = error_v4(IcmpCodes::DestinationPortUnreachable);
        MutableDestinationUnreachablePacket::new(&mut reply.bytes)
            .unwrap()
            .set_icmp_type(IcmpTypes::EchoReply);

        assert!(parse(&reply).is_none());
    }

    /// Every byte of a quotation is remote-chosen, so a truncated one must come
    /// back as `None` rather than as a panic or a wrong target.
    #[test]
    fn a_truncated_quotation_resolves_nothing() {
        let mut error = error_v4(IcmpCodes::DestinationPortUnreachable);
        error
            .bytes
            .truncate(DestinationUnreachablePacket::minimum_packet_size() + 4);

        assert!(parse(&error).is_none());
    }
}
