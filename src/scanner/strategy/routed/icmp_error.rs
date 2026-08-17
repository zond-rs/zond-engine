// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # ICMP Errors
//!
//! Reads a Destination Unreachable message: what it establishes, and which
//! probe it is about.
//!
//! Both raw port scanners depend on this, and both would otherwise carry their
//! own copy of two code tables that number the same meanings differently.
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

use pnet::packet::icmp::destination_unreachable::{DestinationUnreachablePacket, IcmpCodes};
use pnet::packet::icmp::{IcmpCode, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;

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

/// The four unused bytes between an ICMPv6 Destination Unreachable header and
/// the packet it quotes (RFC 4443 §3.1).
///
/// `pnet` models ICMPv6 only as the generic type/code/checksum header, so its
/// payload still has these in front of the quotation. ICMPv4 needs no
/// equivalent: `pnet` models the Destination Unreachable header itself, so
/// [`DestinationUnreachablePacket::payload`] already starts at the quotation.
pub(super) const ICMPV6_UNUSED_LEN: usize = 4;

/// What a Destination Unreachable code says, named by meaning rather than by
/// number, and stopping short of what it means for the probe.
///
/// The two families number the same meanings differently - a port unreachable
/// is code 3 over IPv4 and code 4 over IPv6 - so resolving the number here is
/// what keeps a scanner from reading a v6 code as its identically numbered v4
/// neighbour, which is a different message entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreachable {
    /// Something received the datagram, looked for a listener on that port, and
    /// found none.
    Port,
    /// Delivery was refused by policy: a filter, an administrative
    /// prohibition, a reject route. It proves only that the probe did not
    /// arrive.
    Prohibited,
    /// The address itself could not be reached at all. A statement about the
    /// host, not about the port that happened to be asked for.
    Host,
}

/// One parsed Destination Unreachable: what it says, and the packet it quotes.
#[derive(Debug, Clone, Copy)]
pub struct IcmpError<'a> {
    /// What the code establishes.
    pub reason: Unreachable,
    /// The probe the message is about, as the sender quoted it back. Its
    /// destination names the host and its payload the transport header, of
    /// which only the first eight bytes are guaranteed to be present.
    pub quoted: IpSegment<'a>,
}

/// Reads `reply` as a Destination Unreachable, whichever family it arrived over.
///
/// `None` for any other captured segment, for a code that reports on neither the
/// port nor the path, and for a message whose quotation cannot be parsed.
pub fn parse(reply: &CapturedSegment) -> Option<IcmpError<'_>> {
    match reply.protocol {
        IpNextHeaderProtocols::Icmp => parse_v4(&reply.bytes),
        IpNextHeaderProtocols::Icmpv6 => parse_v6(&reply.bytes),
        _ => None,
    }
}

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
fn parse_v6(bytes: &[u8]) -> Option<IcmpError<'_>> {
    let unreachable = Icmpv6Packet::new(bytes)?;
    if unreachable.get_icmpv6_type() != Icmpv6Types::DestinationUnreachable {
        return None;
    }

    let quoted_at = Icmpv6Packet::minimum_packet_size() + ICMPV6_UNUSED_LEN;
    Some(IcmpError {
        reason: reason_v6(unreachable.get_icmpv6_code())?,
        quoted: frame::parse_ip_segment(bytes.get(quoted_at..)?)?,
    })
}

/// What an ICMPv4 Destination Unreachable code establishes, or `None` if it says
/// nothing usable.
///
/// "Protocol unreachable" and the three administrative prohibitions describe the
/// *path*. "Host unreachable" is neither port nor path: a router could not
/// deliver to the address at all. The remaining codes - network unknown,
/// fragmentation needed, source route failed - say nothing either way.
fn reason_v4(code: IcmpCode) -> Option<Unreachable> {
    match code {
        IcmpCodes::DestinationPortUnreachable => Some(Unreachable::Port),
        IcmpCodes::DestinationProtocolUnreachable
        | IcmpCodes::NetworkAdministrativelyProhibited
        | IcmpCodes::HostAdministrativelyProhibited
        | IcmpCodes::CommunicationAdministrativelyProhibited => Some(Unreachable::Prohibited),
        IcmpCodes::DestinationHostUnreachable => Some(Unreachable::Host),
        _ => None,
    }
}

/// The ICMPv6 counterpart of [`reason_v4`] (RFC 4443 §3.1).
///
/// Code 2 (beyond scope of source address) describes the *sender's* address
/// selection rather than the target's reachability, and is deliberately left
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

    use pnet::packet::icmp::destination_unreachable::MutableDestinationUnreachablePacket;
    use pnet::packet::icmpv6::MutableIcmpv6Packet;

    use crate::protocols::{ip, udp};

    const LOCAL_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
    const TARGET_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
    const LOCAL_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 50));
    const TARGET_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 200));

    /// The quoted datagram an error carries: the probe's IP header and its
    /// transport header, built with the same functions that build a real probe.
    fn quoted_packet(from: IpAddr, to: IpAddr) -> Vec<u8> {
        let datagram = udp::create_packet(&from, &to, 50_000, 53, vec![]).unwrap();
        let len = datagram.len() as u16;
        let header = match (from, to) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                ip::create_ipv4_header(s, d, len, IpNextHeaderProtocols::Udp).unwrap()
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                ip::create_ipv6_header(s, d, len, IpNextHeaderProtocols::Udp, ip::HOP_LIMIT_ROUTED)
            }
            _ => panic!("IP version mismatch in test fixture"),
        };
        header.into_iter().chain(datagram).collect()
    }

    fn error_v4(code: IcmpCode) -> CapturedSegment {
        let quoted = quoted_packet(LOCAL_V4, TARGET_V4);
        let mut bytes =
            vec![0u8; DestinationUnreachablePacket::minimum_packet_size() + quoted.len()];
        let mut packet = MutableDestinationUnreachablePacket::new(&mut bytes).unwrap();
        packet.set_icmp_type(IcmpTypes::DestinationUnreachable);
        packet.set_icmp_code(code);
        packet.set_payload(&quoted);

        CapturedSegment {
            source: TARGET_V4,
            protocol: IpNextHeaderProtocols::Icmp,
            bytes,
        }
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

        CapturedSegment {
            source: TARGET_V6,
            protocol: IpNextHeaderProtocols::Icmpv6,
            bytes,
        }
    }

    /// What `reply` establishes, for the tests that assert on the reason alone.
    fn reason_of(reply: &CapturedSegment) -> Unreachable {
        parse(reply).expect("the message parses").reason
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
