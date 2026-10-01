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
//! Time Exceeded, for what each establishes and which probe it is about. Used
//! by the UDP and SCTP port scans and the trace.
//!
//! The types here are `#[non_exhaustive]`; they come back from [`parse`] and
//! [`parse_expired`] and are only read.
//!
//! The module stops at [`Unreachable`] and leaves
//! [`PortState`](crate::model::port::PortState) to the caller, because the same
//! code means opposite things per protocol: a port unreachable answering a UDP
//! probe is the port's own stack reporting no listener, while one answering a
//! TCP probe can only come from a middlebox (no TCP stack emits one), so the
//! port is blocked.
//!
//! ## Which probe an error is about
//!
//! An ICMP error carries no ports of its own. RFC 792 requires it to quote the
//! IP header plus at least the first eight bytes of the datagram that caused
//! it, and that quotation is the only thing tying an error to a probe. A
//! router's error comes from the router, but the quoted probe names the host
//! behind it.
//!
//! Every field in the quotation was chosen by a remote host. It is parsed with
//! the same bounds-checked path as a captured packet
//! ([`frame::parse_ip_segment`]), and eight bytes is all a caller may count on.
//!
//! ## What a caller owes
//!
//! **Parsing a quotation is not attributing one.** This module does not know
//! what any scanner sent, so every caller must check that the error is about
//! one of its own probes, using one of:
//!
//! - a nonce, where the technique put one inside the guaranteed eight bytes;
//! - a drawn port or identifier, where it did not;
//! - membership of a ledger of probes still outstanding;
//! - where a probe carries nothing after its IP header, the source address it
//!   left from, which is weaker and has to be admitted as weaker.
//!
//! Without one of those, the scanner is reading a stranger's packet.
//! `tests/hygiene/attribution.rs` holds every reader to this: it lists every
//! file that reads an error with a line saying how it attributes one, and a
//! new caller fails that test until the line is written.

use pnet_packet::icmp::destination_unreachable::{DestinationUnreachablePacket, IcmpCodes};
use pnet_packet::icmp::{IcmpCode, IcmpPacket, IcmpTypes};
use pnet_packet::icmpv6::{Icmpv6Code, Icmpv6Packet, Icmpv6Types};
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};

use crate::transport::capture::CapturedSegment;
use crate::transport::frame::{self, IpSegment};

// The ICMPv6 Destination Unreachable codes worth acting on (RFC 4443 §3.1).
// `pnet` has no named constants for ICMPv6 codes. Visible to the sibling
// scanners so their tests can name codes by meaning.
//
/// Code 4: the v6 counterpart of [`IcmpCodes::DestinationPortUnreachable`].
pub(super) const ICMPV6_PORT_UNREACHABLE: Icmpv6Code = Icmpv6Code(4);
/// Code 1: communication with the destination administratively prohibited.
pub(super) const ICMPV6_ADMIN_PROHIBITED: Icmpv6Code = Icmpv6Code(1);
/// Code 5: source address failed an ingress/egress policy.
pub(super) const ICMPV6_INGRESS_EGRESS_POLICY: Icmpv6Code = Icmpv6Code(5);
/// Code 6: the route to the destination is a reject route.
pub(super) const ICMPV6_REJECT_ROUTE: Icmpv6Code = Icmpv6Code(6);
/// Code 0: no route to destination, the v6 counterpart of host unreachable.
pub(super) const ICMPV6_NO_ROUTE: Icmpv6Code = Icmpv6Code(0);
/// Code 3: the address itself is unreachable, whatever the port.
pub(super) const ICMPV6_ADDR_UNREACHABLE: Icmpv6Code = Icmpv6Code(3);

/// The ICMPv6 Parameter Problem code for a Next Header value the receiver does
/// not implement (RFC 4443 §3.4).
///
/// ICMPv6 has no protocol-unreachable code; this is how a v6 host says it does
/// not speak a protocol. It arrives under a different *type* from the other
/// errors here, so [`parse_v6`] branches on the type as well as the code.
pub(super) const ICMPV6_UNRECOGNISED_NEXT_HEADER: Icmpv6Code = Icmpv6Code(1);

/// The four unused bytes between an ICMPv6 Destination Unreachable header and
/// the packet it quotes (RFC 4443 §3.1).
///
/// `pnet` models ICMPv6 only as the generic type/code/checksum header, so its
/// payload still has these in front of the quotation. ICMPv4 needs no
/// equivalent: a `DestinationUnreachablePacket` payload starts at the quotation.
pub(super) const ICMPV6_UNUSED_LEN: usize = 4;

/// What a Destination Unreachable code says, named by meaning, stopping short
/// of what it means for the probe.
///
/// The two families number the same meanings differently (port unreachable is
/// code 3 over IPv4 and code 4 over IPv6), so the number is resolved here once.
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
    /// Distinct from [`Prohibited`](Self::Prohibited): a prohibition is the
    /// path speaking for the host, this is the host speaking for itself, which
    /// also proves it is there. For a transport scan it is a curiosity; for
    /// [`protocols`](crate::scanner::strategy::protocols) it is the verdict.
    ///
    /// ICMPv4 has a Destination Unreachable code for it; ICMPv6 reports an
    /// unrecognised Next Header as a Parameter Problem (RFC 4443 §3.4, type 4
    /// code 1).
    Protocol,
    /// The address itself could not be reached at all, whatever the port.
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
    /// **This does not by itself tie the message to one of your probes.** Every
    /// byte was chosen by whoever sent the error. See the module documentation
    /// for the check a caller owes, and `tests/hygiene/attribution.rs`.
    pub quoted: IpSegment<'a>,
}

/// Reads `reply` as an ICMP error about a probe, whichever family it arrived
/// over.
///
/// Accepts a Destination Unreachable in both families, and over IPv6 also a
/// Parameter Problem naming an unrecognised Next Header (the v6 protocol
/// unreachable).
///
/// `None` for any other captured segment, for a code that reports on neither
/// the port, the protocol nor the path, and for an unparseable quotation.
pub fn parse(reply: &CapturedSegment) -> Option<IcmpError<'_>> {
    match IpNextHeaderProtocol(reply.protocol) {
        IpNextHeaderProtocols::Icmp => parse_v4(&reply.bytes),
        IpNextHeaderProtocols::Icmpv6 => parse_v6(&reply.bytes),
        _ => None,
    }
}

/// One router naming itself, having discarded a probe that ran out of hops.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Expired<'a> {
    /// The probe the router discarded, as it quoted it back. See
    /// [`parse_expired`].
    pub quoted: IpSegment<'a>,
}

/// Reads `reply` as a Time Exceeded: the message a router is required to send
/// when it decrements a hop limit to zero and drops what it was carrying.
///
/// The basis of path discovery: a router that discards a packet must identify
/// itself (RFC 792, RFC 4443 §3.3). A probe built to expire a chosen number of
/// hops away makes that router announce itself from its own address,
/// [`CapturedSegment::source`](crate::transport::capture::CapturedSegment::source),
/// while the quotation names the probe that provoked it.
///
/// Both codes are accepted alike. Code 0 is a hop limit reaching zero in
/// transit; code 1 is a reassembly timeout at the destination, which cannot
/// answer a probe here since nothing here fragments, and would at worst record
/// the destination as its own last hop.
///
/// `None` for any other captured segment and for an unparseable or truncated
/// quotation; a hop attributed to the wrong probe is a wrong path.
pub fn parse_expired(reply: &CapturedSegment) -> Option<Expired<'_>> {
    let quoted_at = match IpNextHeaderProtocol(reply.protocol) {
        IpNextHeaderProtocols::Icmp => {
            let message = IcmpPacket::new(&reply.bytes)?;
            if message.get_icmp_type() != IcmpTypes::TimeExceeded {
                return None;
            }
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
/// Spelled out on its own, though `DestinationUnreachablePacket`'s minimum size
/// is the same number, so the two messages cannot drift together silently.
const TIME_EXCEEDED_HEADER_LEN: usize = 8;

/// [`parse`] for an ICMPv4 message.
fn parse_v4(bytes: &[u8]) -> Option<IcmpError<'_>> {
    let unreachable = DestinationUnreachablePacket::new(bytes)?;
    if unreachable.get_icmp_type() != IcmpTypes::DestinationUnreachable {
        return None;
    }

    // Sliced from `bytes` so the quotation borrows the caller's buffer without
    // a copy. The header before it is type, code, checksum, four unused bytes.
    let quoted_at = DestinationUnreachablePacket::minimum_packet_size();
    Some(IcmpError {
        reason: reason_v4(unreachable.get_icmp_code())?,
        quoted: frame::parse_ip_segment(bytes.get(quoted_at..)?)?,
    })
}

/// [`parse`] for an ICMPv6 message.
///
/// Reads two types: Destination Unreachable for the path's and the address's
/// refusals, and Parameter Problem for an unimplemented Next Header. Both quote
/// the offending packet after a four-byte field (unused bytes, or the Pointer),
/// so the quotation sits at one offset either way.
fn parse_v6(bytes: &[u8]) -> Option<IcmpError<'_>> {
    let message = Icmpv6Packet::new(bytes)?;

    let reason = match message.get_icmpv6_type() {
        Icmpv6Types::DestinationUnreachable => reason_v6(message.get_icmpv6_code())?,
        Icmpv6Types::ParameterProblem
            if message.get_icmpv6_code() == ICMPV6_UNRECOGNISED_NEXT_HEADER =>
        {
            Unreachable::Protocol
        }
        // The other Parameter Problem codes report a defect in a header this
        // engine built, and say nothing about the target.
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
/// The three administrative prohibitions describe the *path*; "protocol
/// unreachable" describes the host's own stack (see [`Unreachable::Protocol`]);
/// "host unreachable" means a router could not deliver to the address at all.
/// The remaining codes (network unknown, fragmentation needed, source route
/// failed) say nothing either way.
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
/// selection and is left unclassified.
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
            (IpAddr::V4(s), IpAddr::V4(d)) => ip::build_ipv4_header(
                s,
                d,
                len,
                IpNextHeaderProtocols::Udp.0,
                ip::HOP_LIMIT_ROUTED,
            )
            .unwrap(),
            (IpAddr::V6(s), IpAddr::V6(d)) => ip::build_ipv6_header(
                s,
                d,
                len,
                IpNextHeaderProtocols::Udp.0,
                ip::HOP_LIMIT_ROUTED,
            ),
            _ => panic!("IP version mismatch in test fixture"),
        };
        header.into_iter().chain(datagram).collect()
    }

    /// A Time Exceeded from `router`, quoting a probe from us to `target`, built
    /// with the same header writers a real probe uses.
    fn expired_v4(router: IpAddr, target: IpAddr) -> CapturedSegment {
        let quoted = quoted_packet(LOCAL_V4, target);
        let mut bytes = vec![0u8; TIME_EXCEEDED_HEADER_LEN + quoted.len()];
        bytes[0] = IcmpTypes::TimeExceeded.0;
        bytes[TIME_EXCEEDED_HEADER_LEN..].copy_from_slice(&quoted);

        CapturedSegment::synthetic(router, IpNextHeaderProtocols::Icmp.0, bytes)
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

        CapturedSegment::synthetic(router, IpNextHeaderProtocols::Icmpv6.0, bytes)
    }

    /// A Time Exceeded names the router in its own header and the probe in its
    /// quotation. Read from the wrong one, every hop of a trace would come back
    /// as the target.
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
    /// They share an eight-byte preamble; a Destination Unreachable read as an
    /// expiry would put a firewall into a path as a router.
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

        CapturedSegment::synthetic(TARGET_V4, IpNextHeaderProtocols::Icmp.0, bytes)
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

        CapturedSegment::synthetic(TARGET_V6, IpNextHeaderProtocols::Icmpv6.0, bytes)
    }

    /// An ICMPv6 Parameter Problem under `code`, quoting a probe of ours.
    fn parameter_problem_v6(code: Icmpv6Code) -> CapturedSegment {
        let quoted = quoted_packet(LOCAL_V6, TARGET_V6);
        // The Pointer field, where a Destination Unreachable has unused bytes.
        let mut payload = vec![0u8; ICMPV6_UNUSED_LEN];
        payload.extend_from_slice(&quoted);

        let mut bytes = vec![0u8; Icmpv6Packet::minimum_packet_size() + payload.len()];
        let mut packet = MutableIcmpv6Packet::new(&mut bytes).unwrap();
        packet.set_icmpv6_type(Icmpv6Types::ParameterProblem);
        packet.set_icmpv6_code(code);
        packet.set_payload(&payload);

        CapturedSegment::synthetic(TARGET_V6, IpNextHeaderProtocols::Icmpv6.0, bytes)
    }

    /// What `reply` establishes, for the tests that assert on the reason alone.
    fn reason_of(reply: &CapturedSegment) -> Unreachable {
        parse(reply).expect("the message parses").reason
    }

    /// A host refusing a protocol is kept apart from the path refusing delivery:
    /// the first proves the host is there, the second that the probe never
    /// arrived.
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

    /// ICMPv6 has no protocol-unreachable code and reports it under another
    /// type.
    #[test]
    fn the_ipv6_form_of_a_protocol_refusal_arrives_as_a_parameter_problem() {
        assert_eq!(
            reason_of(&parameter_problem_v6(ICMPV6_UNRECOGNISED_NEXT_HEADER)),
            Unreachable::Protocol
        );
    }

    /// The other two Parameter Problem codes are about a header this engine
    /// built.
    #[test]
    fn a_parameter_problem_about_our_own_header_says_nothing_about_the_host() {
        for code in [Icmpv6Code(0), Icmpv6Code(2)] {
            assert!(
                parse(&parameter_problem_v6(code)).is_none(),
                "code {code:?} was read as a verdict"
            );
        }
    }

    /// The quotation names the host the probe was aimed at, which for a
    /// router-generated error differs from the error's source.
    #[test]
    fn the_quoted_packet_names_the_probe_rather_than_the_sender() {
        let reply = error_v4(IcmpCodes::DestinationPortUnreachable);
        let error = parse(&reply).expect("parses");

        assert_eq!(error.quoted.destination, TARGET_V4);
        assert_eq!(error.quoted.protocol, IpNextHeaderProtocols::Udp.0);
    }

    /// Code 3 is port unreachable over IPv4 and *address* unreachable over IPv6,
    /// where code 4 is port unreachable. One table for both families would
    /// report an unreachable host as a closed port.
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

    /// A code that reports on neither the port nor the path resolves nothing;
    /// the probe it quotes retires on its own schedule.
    #[test]
    fn an_uninformative_code_is_not_parsed_into_a_verdict() {
        // Fragmentation needed: a path MTU problem.
        assert!(parse(&error_v4(IcmpCode(4))).is_none());
        // Beyond scope of source address: about our address selection.
        assert!(parse(&error_v6(Icmpv6Code(2))).is_none());
    }

    /// Another ICMP message, such as an echo reply, is not read as an error.
    #[test]
    fn another_icmp_message_is_not_an_error() {
        let mut reply = error_v4(IcmpCodes::DestinationPortUnreachable);
        MutableDestinationUnreachablePacket::new(&mut reply.bytes)
            .unwrap()
            .set_icmp_type(IcmpTypes::EchoReply);

        assert!(parse(&reply).is_none());
    }

    /// A truncated quotation comes back as `None`, without a panic or a wrong
    /// target.
    #[test]
    fn a_truncated_quotation_resolves_nothing() {
        let mut error = error_v4(IcmpCodes::DestinationPortUnreachable);
        error
            .bytes
            .truncate(DestinationUnreachablePacket::minimum_packet_size() + 4);

        assert!(parse(&error).is_none());
    }
}
