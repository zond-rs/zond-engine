// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # DHCP (RFC 2131)
//!
//! Enough of the protocol to ask a segment which machine hands out its
//! configuration, and to recognise the answer.
//!
//! ## Why a DHCP server cannot be found by scanning ports
//!
//! Every other service this engine identifies is reached by addressing it. A
//! DHCP server is not: a client that has no address yet cannot address anyone,
//! so the protocol is built on broadcast, and the server is discovered rather
//! than connected to. Probing UDP/67 on each address in turn asks the wrong
//! question — a server that answers a broadcast may ignore a unicast to the
//! same port, and a port with nothing listening is `open|filtered` like every
//! other silent UDP port. One broadcast to the segment finds every server on
//! it; sixty thousand unicasts find none.
//!
//! ## Which message, and why it is the safe one
//!
//! [`create_inform`] builds a `DHCPINFORM` (§3.4): the message a client with an
//! address already sends to ask for the *rest* of its configuration — routers,
//! name servers, a domain. It allocates nothing. A `DHCPDISCOVER` would find
//! the same servers and would also make each of them reserve an address for a
//! client that never appears, which is a scan changing the network it is
//! measuring.
//!
//! ## Who the answer is about
//!
//! A server names itself in the server-identifier option (§9.7), and that is
//! read rather than the packet's source address, because the two differ exactly
//! when it matters: where a relay agent forwards for a server on another
//! segment, the frame comes from the relay. The caller compares the two — see
//! [`ServerReply::server`].

use pnet::datalink::MacAddr;
use pnet::packet::Packet as _;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use std::net::Ipv4Addr;

use crate::protocols::craft::{Ethernet, Ipv4, Packet, Udp};
use crate::protocols::ip;

/// Where a DHCP client listens, and the port a server's reply is addressed to.
pub const CLIENT_PORT: u16 = 68;
/// Where a DHCP server listens.
pub const SERVER_PORT: u16 = 67;

/// A message from a client to a server.
const BOOTREQUEST: u8 = 1;
/// A message from a server to a client, which is the only kind that can say
/// anything about a server.
const BOOTREPLY: u8 = 2;

/// Ethernet, in the hardware-type registry BOOTP borrows (RFC 1700).
const HTYPE_ETHERNET: u8 = 1;
/// The length of an Ethernet address, as `htype` counts it.
const HLEN_ETHERNET: u8 = 6;

/// The fixed part of a BOOTP message, ahead of any options: the opcode and
/// addressing through `chaddr`, then the 64-byte server name and 128-byte boot
/// file fields BOOTP defined and DHCP inherited.
const BOOTP_FIXED_LEN: usize = 236;

/// What marks the bytes after the fixed header as DHCP options rather than
/// BOOTP's vendor area (RFC 2131 §3).
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// The smallest message some servers will accept, a BOOTP-era expectation that
/// costs one padded datagram to satisfy and an unanswered probe to ignore.
const MIN_MESSAGE_LEN: usize = 300;

const OPT_PAD: u8 = 0;
const OPT_MESSAGE_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAMETER_REQUEST: u8 = 55;
const OPT_END: u8 = 255;

/// The message types a *server* sends. Anything else on the wire is a client
/// talking, and a client says nothing about who serves it.
const DHCPOFFER: u8 = 2;
const DHCPACK: u8 = 5;
const DHCPNAK: u8 = 6;

/// The message this engine sends: "I have an address, tell me the rest".
const DHCPINFORM: u8 = 8;

/// The parameters asked for, chosen to be the ones every server is configured
/// to hand out — a request no server would decline for want of anything to say.
const REQUESTED_PARAMETERS: [u8; 4] = [
    1,  // subnet mask
    3,  // router
    6,  // domain name server
    15, // domain name
];

/// A DHCP message sent by a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerReply {
    /// The address the server identified *itself* as (option 54), where it gave
    /// one.
    ///
    /// The claim to attribute the role to, and not the same thing as where the
    /// frame came from. A relay agent forwarding for a server on another
    /// segment puts its own address on the packet, so a caller that marks the
    /// sender marks the relay; a caller that compares the two can tell the
    /// difference and decline.
    pub server: Option<Ipv4Addr>,
}

/// Builds a `DHCPINFORM` from `src_mac`/`src_addr`, broadcast at the segment.
///
/// The address goes in `ciaddr`, which is what makes this an inform rather than
/// a request: it says the sender is already configured, and it is where the
/// server sends its answer.
///
/// The transaction id is derived from the sending hardware address rather than
/// drawn at random, because nothing correlates on it. A server's reply is
/// evidence about the server whether it answers this probe or a real client's,
/// so the field only has to be ours and stable.
pub fn create_inform(src_mac: &MacAddr, src_addr: &Ipv4Addr) -> Vec<u8> {
    let mut message = Vec::with_capacity(MIN_MESSAGE_LEN);
    let mac = src_mac.octets();

    message.push(BOOTREQUEST);
    message.push(HTYPE_ETHERNET);
    message.push(HLEN_ETHERNET);
    message.push(0); // hops: zero from a client, incremented by relays
    message.extend_from_slice(&transaction_id(src_mac).to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes()); // secs
    message.extend_from_slice(&0u16.to_be_bytes()); // flags: reply to ciaddr
    message.extend_from_slice(&src_addr.octets()); // ciaddr
    message.extend_from_slice(&[0; 4]); // yiaddr: the server's to fill in
    message.extend_from_slice(&[0; 4]); // siaddr
    message.extend_from_slice(&[0; 4]); // giaddr: no relay
    message.extend_from_slice(&mac);
    message.extend_from_slice(&[0; 10]); // chaddr is 16 bytes; six are ours
    message.extend_from_slice(&[0; 64]); // sname
    message.extend_from_slice(&[0; 128]); // file
    debug_assert_eq!(message.len(), BOOTP_FIXED_LEN);

    message.extend_from_slice(&MAGIC_COOKIE);
    message.extend_from_slice(&[OPT_MESSAGE_TYPE, 1, DHCPINFORM]);
    message.push(OPT_PARAMETER_REQUEST);
    message.push(REQUESTED_PARAMETERS.len() as u8);
    message.extend_from_slice(&REQUESTED_PARAMETERS);
    message.push(OPT_END);
    message.resize(message.len().max(MIN_MESSAGE_LEN), OPT_PAD);

    Packet::new()
        .push(Ethernet::new(*src_mac, MacAddr::broadcast()).with_ethertype(EtherTypes::Ipv4))
        .push(Ipv4::new(*src_addr, Ipv4Addr::BROADCAST).with_ttl(ip::HOP_LIMIT_ON_LINK))
        .push(Udp::new(CLIENT_PORT, SERVER_PORT).with_payload(message))
        .build()
        .expect("an inform fits every length field it is counted by")
}

/// Reads `frame` as a DHCP message from a server, if it is one.
///
/// Refuses a client's own traffic, which is most of the DHCP a segment carries:
/// the discovers and requests every machine broadcasts when it wakes up prove
/// only that the network has clients on it.
pub fn server_reply(frame: &EthernetPacket) -> Option<ServerReply> {
    if frame.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    let packet = Ipv4Packet::new(frame.payload())?;
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return None;
    }

    let datagram = UdpPacket::new(packet.payload())?;
    if datagram.get_source() != SERVER_PORT {
        return None;
    }

    let message = datagram.payload();
    if message.first() != Some(&BOOTREPLY) {
        return None;
    }
    if message.get(BOOTP_FIXED_LEN..BOOTP_FIXED_LEN + MAGIC_COOKIE.len()) != Some(&MAGIC_COOKIE) {
        return None;
    }

    let mut kind = None;
    let mut server = None;
    for (code, value) in options(&message[BOOTP_FIXED_LEN + MAGIC_COOKIE.len()..]) {
        match code {
            OPT_MESSAGE_TYPE => kind = value.first().copied(),
            OPT_SERVER_ID => server = ipv4(value),
            _ => {}
        }
    }

    // A message with no type is BOOTP rather than DHCP, and a BOOTP reply comes
    // from a boot server rather than from a DHCP one. Named as absent rather
    // than assumed: this engine reports what it can prove.
    matches!(kind, Some(DHCPOFFER | DHCPACK | DHCPNAK)).then_some(ServerReply { server })
}

/// The options in `bytes`, as code and value.
///
/// Stops at the end option and at any truncation. A malformed option list is
/// ordinary — it is whatever arrived — so it ends the walk rather than
/// discarding what was already read.
fn options(bytes: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut rest = bytes;
    std::iter::from_fn(move || {
        loop {
            let (&code, tail) = rest.split_first()?;
            match code {
                OPT_END => return None,
                // A pad has no length byte, which is the whole reason this walk
                // cannot be a simple stride.
                OPT_PAD => rest = tail,
                _ => {
                    let (&len, tail) = tail.split_first()?;
                    let value = tail.get(..len as usize)?;
                    rest = &tail[len as usize..];
                    return Some((code, value));
                }
            }
        }
    })
}

/// An option's value as an address, when it is one.
fn ipv4(value: &[u8]) -> Option<Ipv4Addr> {
    let octets: [u8; 4] = value.try_into().ok()?;
    Some(Ipv4Addr::from(octets))
}

/// A transaction id belonging to this machine, from the half of its hardware
/// address that is not the vendor prefix.
fn transaction_id(mac: &MacAddr) -> u32 {
    let [_, _, a, b, c, d] = mac.octets();
    u32::from_be_bytes([a, b, c, d])
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
    use crate::protocols::ethernet;

    const SRC_MAC: MacAddr = MacAddr(0x02, 0x00, 0x11, 0x22, 0x33, 0x44);
    const SERVER_MAC: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);

    fn src_addr() -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, 50)
    }

    fn server_addr() -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, 1)
    }

    /// A server's message: a BOOTP reply carrying the options a server sets.
    fn reply_frame(message_type: u8, server_id: Option<Ipv4Addr>) -> Vec<u8> {
        let mut message = vec![0u8; BOOTP_FIXED_LEN];
        message[0] = BOOTREPLY;
        message.extend_from_slice(&MAGIC_COOKIE);
        message.extend_from_slice(&[OPT_MESSAGE_TYPE, 1, message_type]);
        if let Some(id) = server_id {
            message.push(OPT_SERVER_ID);
            message.push(4);
            message.extend_from_slice(&id.octets());
        }
        message.push(OPT_END);

        udp_frame(SERVER_PORT, CLIENT_PORT, message)
    }

    fn udp_frame(source_port: u16, destination_port: u16, message: Vec<u8>) -> Vec<u8> {
        let datagram = Packet::new()
            .push(Ipv4::new(server_addr(), src_addr()))
            .push(Udp::new(source_port, destination_port).with_payload(message))
            .build()
            .expect("a test datagram");

        [
            ethernet::create_header(SERVER_MAC, SRC_MAC, EtherTypes::Ipv4),
            datagram,
        ]
        .concat()
    }

    /// The probe has to be addressed so that every server on the segment sees
    /// it, and shaped so that each one answers: an inform asks for
    /// configuration without asking for an address, and `ciaddr` is both the
    /// claim that we have one and where the answer is sent.
    #[test]
    fn an_inform_is_broadcast_and_asks_for_nothing_it_would_have_to_be_given() {
        let bytes = create_inform(&SRC_MAC, &src_addr());
        let frame = EthernetPacket::new(&bytes).expect("an ethernet frame");

        assert_eq!(frame.get_destination(), MacAddr::broadcast());
        assert_eq!(frame.get_ethertype(), EtherTypes::Ipv4);

        let packet = Ipv4Packet::new(frame.payload()).expect("an ipv4 packet");
        assert_eq!(packet.get_destination(), Ipv4Addr::BROADCAST);
        assert_eq!(packet.get_source(), src_addr());

        let datagram = UdpPacket::new(packet.payload()).expect("a datagram");
        assert_eq!(datagram.get_source(), CLIENT_PORT);
        assert_eq!(datagram.get_destination(), SERVER_PORT);
        assert_ne!(datagram.get_checksum(), 0);

        let message = datagram.payload();
        assert_eq!(message[0], BOOTREQUEST);
        assert_eq!(
            &message[12..16],
            &src_addr().octets(),
            "ciaddr is what makes this an inform, and where the answer goes"
        );
        assert_eq!(
            &message[BOOTP_FIXED_LEN..BOOTP_FIXED_LEN + 4],
            &MAGIC_COOKIE
        );
        assert!(message.len() >= MIN_MESSAGE_LEN);

        let options: Vec<_> = options(&message[BOOTP_FIXED_LEN + 4..]).collect();
        assert_eq!(options[0], (OPT_MESSAGE_TYPE, [DHCPINFORM].as_slice()));
        assert_eq!(
            options[1],
            (OPT_PARAMETER_REQUEST, REQUESTED_PARAMETERS.as_slice())
        );
    }

    /// What the role is read from: a server's own message, and the address it
    /// gives for itself in it.
    #[test]
    fn a_server_message_yields_the_address_the_server_named() {
        for kind in [DHCPOFFER, DHCPACK, DHCPNAK] {
            let bytes = reply_frame(kind, Some(server_addr()));
            let frame = EthernetPacket::new(&bytes).unwrap();

            assert_eq!(
                server_reply(&frame),
                Some(ServerReply {
                    server: Some(server_addr())
                }),
                "message type {kind}"
            );
        }
    }

    /// Everything else on the segment says nothing about who serves it.
    ///
    /// The client half of DHCP is the case that matters: a machine waking up
    /// broadcasts a discover and a request, which any listener sees, and
    /// reading one as a server's answer would name every laptop on the network
    /// a DHCP server.
    #[test]
    fn a_clients_own_traffic_is_never_a_servers_answer() {
        // A discover: from the client port, and a request rather than a reply.
        let mut message = vec![0u8; BOOTP_FIXED_LEN];
        message[0] = BOOTREQUEST;
        message.extend_from_slice(&MAGIC_COOKIE);
        message.extend_from_slice(&[OPT_MESSAGE_TYPE, 1, 1]); // DHCPDISCOVER
        message.push(OPT_END);
        let bytes = udp_frame(CLIENT_PORT, SERVER_PORT, message);
        assert_eq!(server_reply(&EthernetPacket::new(&bytes).unwrap()), None);

        // A reply with no DHCP options at all is BOOTP, from a boot server.
        let mut bootp = vec![0u8; BOOTP_FIXED_LEN];
        bootp[0] = BOOTREPLY;
        let bytes = udp_frame(SERVER_PORT, CLIENT_PORT, bootp);
        assert_eq!(server_reply(&EthernetPacket::new(&bytes).unwrap()), None);

        // Ordinary traffic from another port.
        let bytes = udp_frame(53, CLIENT_PORT, vec![0u8; 300]);
        assert_eq!(server_reply(&EthernetPacket::new(&bytes).unwrap()), None);
    }

    /// A server that does not name itself is still a server; the caller is left
    /// to decide what to do with a message it cannot attribute.
    #[test]
    fn a_reply_without_a_server_identifier_names_nobody() {
        let bytes = reply_frame(DHCPACK, None);
        let frame = EthernetPacket::new(&bytes).unwrap();

        assert_eq!(server_reply(&frame), Some(ServerReply { server: None }));
    }

    /// Options are a walk rather than a stride: a pad carries no length byte,
    /// and a truncated option ends the list rather than being read past it.
    #[test]
    fn the_option_walk_survives_padding_and_truncation() {
        let padded = [OPT_PAD, OPT_PAD, OPT_MESSAGE_TYPE, 1, DHCPACK, OPT_END];
        let read: Vec<_> = options(&padded).collect();
        assert_eq!(read, vec![(OPT_MESSAGE_TYPE, [DHCPACK].as_slice())]);

        // An option claiming four bytes with two behind it.
        let truncated = [OPT_SERVER_ID, 4, 192, 168];
        assert_eq!(options(&truncated).count(), 0);

        // No end option: the walk stops when the bytes do.
        let unterminated = [OPT_MESSAGE_TYPE, 1, DHCPACK];
        assert_eq!(options(&unterminated).count(), 1);
    }
}
