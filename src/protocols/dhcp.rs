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
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use std::net::Ipv4Addr;

use crate::protocols::craft::{Ethernet, Ipv4, Packet, Udp};
use crate::protocols::ethernet::Frame;
use crate::protocols::ip;
use crate::protocols::sizes::UDP_HDR_LEN;

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

/// Where `chaddr` — the hardware address being configured — begins.
///
/// Past the opcode, hardware type, address length and hop count (4), the
/// transaction id (4), the seconds and flags (4), and the four addresses
/// `ciaddr`, `yiaddr`, `siaddr` and `giaddr` (16).
const CHADDR_OFFSET: usize = 28;

/// What marks the bytes after the fixed header as DHCP options rather than
/// BOOTP's vendor area (RFC 2131 §3).
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// The smallest message some servers will accept, a BOOTP-era expectation that
/// costs one padded datagram to satisfy and an unanswered probe to ignore.
const MIN_MESSAGE_LEN: usize = 300;

const OPT_PAD: u8 = 0;
const OPT_ROUTER: u8 = 3;
const OPT_DOMAIN_NAME_SERVER: u8 = 6;
const OPT_HOSTNAME: u8 = 12;
const OPT_DOMAIN_NAME: u8 = 15;
const OPT_REQUESTED_ADDRESS: u8 = 50;
const OPT_MESSAGE_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAMETER_REQUEST: u8 = 55;
const OPT_VENDOR_CLASS: u8 = 60;
const OPT_END: u8 = 255;

/// The message types a *client* sends, which is everything a server does not.
const DHCPDISCOVER: u8 = 1;
const DHCPREQUEST: u8 = 3;
const DHCPDECLINE: u8 = 4;
const DHCPRELEASE: u8 = 7;

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
///
/// Beyond identifying the server, this is a description of the network the
/// server is configuring — the way out, the resolvers, and the domain — stated
/// by the one machine on the segment that is authoritative about all three. No
/// probe obtains that. A port scan of the gateway establishes that something
/// answers on 53; this says which resolvers the network *tells its clients to
/// use*, which is a different and better-sourced fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerReply<'a> {
    /// The address the server identified *itself* as (option 54), where it gave
    /// one.
    ///
    /// The claim to attribute the role to, and not the same thing as where the
    /// frame came from. A relay agent forwarding for a server on another
    /// segment puts its own address on the packet, so a caller that marks the
    /// sender marks the relay; a caller that compares the two can tell the
    /// difference and decline.
    pub server: Option<Ipv4Addr>,

    /// The domain name the network hands out (option 15).
    pub domain: Option<&'a str>,

    /// The routers offered, as the option's raw bytes. Read through
    /// [`routers`](Self::routers).
    routers: &'a [u8],

    /// The resolvers offered, as the option's raw bytes. Read through
    /// [`resolvers`](Self::resolvers).
    resolvers: &'a [u8],
}

impl<'a> ServerReply<'a> {
    /// The routers this server offers its clients (option 3), in the order it
    /// listed them — which is the order a client tries them in.
    pub fn routers(&self) -> impl Iterator<Item = Ipv4Addr> + 'a {
        addresses(self.routers)
    }

    /// The resolvers this server offers its clients (option 6), in the order it
    /// listed them.
    ///
    /// Every address here is one the network's own machines are being told to
    /// send their lookups to, which is a stronger statement about what a box is
    /// *for* than finding 53 open on it.
    pub fn resolvers(&self) -> impl Iterator<Item = Ipv4Addr> + 'a {
        addresses(self.resolvers)
    }
}

/// A DHCP message sent by a client.
///
/// What a machine says about itself while asking for an address, which it does
/// on joining any network and then periodically for as long as it stays. It is
/// the one moment a device volunteers its own name and model without being
/// asked, and it happens on a broadcast every other machine on the segment can
/// hear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientRequest<'a> {
    /// The hardware address the client is asking on behalf of, from the message's
    /// own `chaddr` field.
    ///
    /// Read from the message rather than from the Ethernet header, because those
    /// are different claims: the frame's source is whatever put it on this
    /// segment, and this is the address being configured. A relay forwarding a
    /// client's request preserves the second and replaces the first.
    pub client_mac: Option<MacAddr>,

    /// What the client calls itself (option 12).
    ///
    /// Often the only name a device ever announces: a printer or a camera with
    /// no DNS record and no open port still says this every time its lease is
    /// renewed.
    pub hostname: Option<&'a str>,

    /// What the client says it is (option 60): a vendor class such as
    /// `MSFT 5.0`, `android-dhcp-14`, or a model string a manufacturer chose.
    pub vendor_class: Option<&'a str>,

    /// The options the client asked for (option 55), **in the order it asked**.
    ///
    /// Kept as raw bytes precisely because the order is the signal. Which
    /// options a stack requests, and in what sequence, is chosen by whoever
    /// wrote it and is near-identical across every device running that software
    /// — so the list distinguishes a Windows laptop from an Android phone from a
    /// network printer without any of them being probed. Sorting or
    /// deduplicating it would destroy exactly the part that identifies.
    pub parameter_request_list: Option<&'a [u8]>,

    /// The address the client is asking to keep (option 50), which on a renewal
    /// is the address it already had.
    pub requested_address: Option<Ipv4Addr>,
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
pub fn server_reply<'a>(frame: &Frame<'a>) -> Option<ServerReply<'a>> {
    let message = bootp_message(frame, SERVER_PORT, BOOTREPLY)?;

    let mut kind = None;
    let mut reply = ServerReply {
        server: None,
        domain: None,
        routers: &[],
        resolvers: &[],
    };

    for (code, value) in options(message) {
        match code {
            OPT_MESSAGE_TYPE => kind = value.first().copied(),
            OPT_SERVER_ID => reply.server = ipv4(value),
            OPT_ROUTER => reply.routers = value,
            OPT_DOMAIN_NAME_SERVER => reply.resolvers = value,
            OPT_DOMAIN_NAME => reply.domain = text(value),
            _ => {}
        }
    }

    // A message with no type is BOOTP rather than DHCP, and a BOOTP reply comes
    // from a boot server rather than from a DHCP one. Named as absent rather
    // than assumed: this engine reports what it can prove.
    matches!(kind, Some(DHCPOFFER | DHCPACK | DHCPNAK)).then_some(reply)
}

/// Reads `frame` as a DHCP message sent by a client, or `None` if it is not one.
///
/// The mirror of [`server_reply`], and the more informative direction for
/// anything building an inventory: a server's answer describes the *network*,
/// where a client's request describes the *device*.
///
/// **This proves the client is present and nothing more.** A request is a
/// broadcast, so hearing one says its sender is on this segment; it does not say
/// the sender holds the address it is asking for, and a `DHCPDISCOVER` is sent
/// by a machine that has no address at all.
pub fn client_request<'a>(frame: &Frame<'a>) -> Option<ClientRequest<'a>> {
    let message = bootp_message(frame, CLIENT_PORT, BOOTREQUEST)?;

    let mut kind = None;
    let mut request = ClientRequest {
        client_mac: client_hardware_address(frame)?,
        hostname: None,
        vendor_class: None,
        parameter_request_list: None,
        requested_address: None,
    };

    for (code, value) in options(message) {
        match code {
            OPT_MESSAGE_TYPE => kind = value.first().copied(),
            OPT_HOSTNAME => request.hostname = text(value),
            OPT_VENDOR_CLASS => request.vendor_class = text(value),
            OPT_PARAMETER_REQUEST => request.parameter_request_list = Some(value),
            OPT_REQUESTED_ADDRESS => request.requested_address = ipv4(value),
            _ => {}
        }
    }

    matches!(
        kind,
        Some(DHCPDISCOVER | DHCPREQUEST | DHCPDECLINE | DHCPRELEASE | DHCPINFORM)
    )
    .then_some(request)
}

/// The option bytes of a BOOTP message inside `frame`, when it is one sent from
/// `source_port` with operation `op`.
///
/// The walk both readers above share, down through IPv4 and UDP to the magic
/// cookie that separates a DHCP message from the BOOTP it extends.
fn bootp_message<'a>(frame: &Frame<'a>, source_port: u16, op: u8) -> Option<&'a [u8]> {
    if frame.ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    let packet = Ipv4Packet::new(frame.payload())?;
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return None;
    }

    // Offsets rather than the parsed views' own `payload`, because those borrow
    // from the view and the value returned here has to outlive it.
    let header_len = usize::from(packet.get_header_length()) * 4;
    let datagram_bytes = frame.payload().get(header_len..)?;

    let datagram = UdpPacket::new(datagram_bytes)?;
    if datagram.get_source() != source_port {
        return None;
    }

    let message = datagram_bytes.get(UDP_HDR_LEN..)?;
    if message.first() != Some(&op) {
        return None;
    }

    let cookie_at = BOOTP_FIXED_LEN;
    if message.get(cookie_at..cookie_at + MAGIC_COOKIE.len()) != Some(&MAGIC_COOKIE) {
        return None;
    }

    message.get(cookie_at + MAGIC_COOKIE.len()..)
}

/// The hardware address out of a BOOTP message's `chaddr` field.
///
/// Read only where the message says it is an Ethernet address of the length
/// Ethernet addresses have. The field is sixteen bytes whatever the link, and
/// taking the first six from a message describing some other kind of hardware
/// would produce a plausible-looking address for a device that has none.
fn client_hardware_address(frame: &Frame<'_>) -> Option<Option<MacAddr>> {
    let packet = Ipv4Packet::new(frame.payload())?;
    let header_len = usize::from(packet.get_header_length()) * 4;
    let message = frame.payload().get(header_len + UDP_HDR_LEN..)?;

    let htype = *message.get(1)?;
    let hlen = *message.get(2)?;
    if htype != HTYPE_ETHERNET || hlen != HLEN_ETHERNET {
        return Some(None);
    }

    let address = message.get(CHADDR_OFFSET..CHADDR_OFFSET + usize::from(HLEN_ETHERNET))?;
    Some(Some(MacAddr::new(
        address[0], address[1], address[2], address[3], address[4], address[5],
    )))
}

/// The addresses packed into an option carrying a list of them, four bytes each.
///
/// A trailing partial address is dropped rather than padded: an option whose
/// length is not a multiple of four is malformed, and the addresses before the
/// remainder are still what the server said.
fn addresses(bytes: &[u8]) -> impl Iterator<Item = Ipv4Addr> + '_ {
    // `.0` is the whole four-byte groups and `.1` is the remainder, which is
    // dropped — the behaviour the doc comment above describes, and the same one
    // `chunks_exact` gave. Taking the chunks as arrays rather than as slices is
    // what lets the address be built from one value instead of four indexes,
    // each of which the compiler would otherwise have to prove is in bounds.
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|&group| Ipv4Addr::from(group))
}

/// An option's value as text, trimming a trailing NUL.
///
/// `None` for bytes that are not UTF-8, on the same reasoning every reader in
/// this module follows: something to decline rather than to guess at.
fn text(value: &[u8]) -> Option<&str> {
    let trimmed = value.strip_suffix(&[0]).unwrap_or(value);
    if trimmed.is_empty() {
        return None;
    }
    std::str::from_utf8(trimmed).ok()
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
pub(crate) mod tests {
    use super::*;
    use crate::protocols::ethernet;
    use pnet::packet::Packet as _;

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
        reply_frame_with(message_type, server_id, &[])
    }

    /// The same, carrying `extra` options beyond the message type and the
    /// server identifier.
    fn reply_frame_with(
        message_type: u8,
        server_id: Option<Ipv4Addr>,
        extra: &[(u8, Vec<u8>)],
    ) -> Vec<u8> {
        let mut message = vec![0u8; BOOTP_FIXED_LEN];
        message[0] = BOOTREPLY;
        message.extend_from_slice(&MAGIC_COOKIE);
        message.extend_from_slice(&[OPT_MESSAGE_TYPE, 1, message_type]);
        if let Some(id) = server_id {
            message.push(OPT_SERVER_ID);
            message.push(4);
            message.extend_from_slice(&id.octets());
        }
        for (code, value) in extra {
            message.push(*code);
            message.push(u8::try_from(value.len()).expect("an option length"));
            message.extend_from_slice(value);
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
        let frame = super::super::ethernet::parse(&bytes).expect("an ethernet frame");

        assert_eq!(frame.destination(), MacAddr::broadcast());
        assert_eq!(frame.ethertype(), EtherTypes::Ipv4);

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
            let frame = super::super::ethernet::parse(&bytes).unwrap();

            assert_eq!(
                server_reply(&frame).map(|reply| reply.server),
                Some(Some(server_addr())),
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
        assert_eq!(
            server_reply(&super::super::ethernet::parse(&bytes).unwrap()),
            None
        );

        // A reply with no DHCP options at all is BOOTP, from a boot server.
        let mut bootp = vec![0u8; BOOTP_FIXED_LEN];
        bootp[0] = BOOTREPLY;
        let bytes = udp_frame(SERVER_PORT, CLIENT_PORT, bootp);
        assert_eq!(
            server_reply(&super::super::ethernet::parse(&bytes).unwrap()),
            None
        );

        // Ordinary traffic from another port.
        let bytes = udp_frame(53, CLIENT_PORT, vec![0u8; 300]);
        assert_eq!(
            server_reply(&super::super::ethernet::parse(&bytes).unwrap()),
            None
        );
    }

    /// A server that does not name itself is still a server; the caller is left
    /// to decide what to do with a message it cannot attribute.
    #[test]
    fn a_reply_without_a_server_identifier_names_nobody() {
        let bytes = reply_frame(DHCPACK, None);
        let frame = super::super::ethernet::parse(&bytes).unwrap();

        assert_eq!(
            server_reply(&frame).map(|reply| reply.server),
            Some(None),
            "the message is a server's; the address in it is not"
        );
    }

    /// A client's request, built the way a real one arrives: broadcast from
    /// port 68, `chaddr` naming the machine, and the options it volunteers.
    fn request_frame(kind: u8, options: &[(u8, Vec<u8>)]) -> Vec<u8> {
        request_frame_from(Ipv4Addr::UNSPECIFIED, kind, options)
    }

    /// A client renewing its lease: a `DHCPREQUEST` sent from the address it
    /// already holds, naming itself. The common shape on a segment that has
    /// been up for any length of time, and the one a listener can attribute.
    pub(crate) fn renewal_frame(from: Ipv4Addr, hostname: &str) -> Vec<u8> {
        request_frame_from(
            from,
            DHCPREQUEST,
            &[(OPT_HOSTNAME, hostname.as_bytes().to_vec())],
        )
    }

    /// A client with no address yet, which names itself from `0.0.0.0`.
    pub(crate) fn discover_frame(hostname: &str) -> Vec<u8> {
        request_frame_from(
            Ipv4Addr::UNSPECIFIED,
            DHCPDISCOVER,
            &[(OPT_HOSTNAME, hostname.as_bytes().to_vec())],
        )
    }

    /// The shared builder, taking the address the client sends from — which is
    /// the whole of the difference between a discover and a renewal.
    fn request_frame_from(from: Ipv4Addr, kind: u8, options: &[(u8, Vec<u8>)]) -> Vec<u8> {
        const CLIENT_MAC: MacAddr = MacAddr(0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33);

        let mut message = vec![0u8; BOOTP_FIXED_LEN];
        message[0] = BOOTREQUEST;
        message[1] = HTYPE_ETHERNET;
        message[2] = HLEN_ETHERNET;
        message[CHADDR_OFFSET..CHADDR_OFFSET + 6].copy_from_slice(&[
            CLIENT_MAC.0,
            CLIENT_MAC.1,
            CLIENT_MAC.2,
            CLIENT_MAC.3,
            CLIENT_MAC.4,
            CLIENT_MAC.5,
        ]);

        message.extend_from_slice(&MAGIC_COOKIE);
        message.extend_from_slice(&[OPT_MESSAGE_TYPE, 1, kind]);
        for (code, value) in options {
            message.push(*code);
            message.push(u8::try_from(value.len()).expect("an option length"));
            message.extend_from_slice(value);
        }
        message.push(OPT_END);

        let datagram = Packet::new()
            .push(Ipv4::new(from, Ipv4Addr::BROADCAST))
            .push(Udp::new(CLIENT_PORT, SERVER_PORT).with_payload(message))
            .build()
            .expect("a test datagram");

        [
            super::super::ethernet::create_header(
                MacAddr(0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33),
                MacAddr::broadcast(),
                EtherTypes::Ipv4,
            ),
            datagram,
        ]
        .concat()
    }

    /// What a device volunteers about itself while asking for an address.
    ///
    /// The whole reason to read the client half: a printer with no DNS record
    /// and no open port still says its name and its model here, on a broadcast,
    /// every time its lease renews.
    #[test]
    fn a_clients_request_carries_its_name_and_what_it_says_it_is() {
        let bytes = request_frame(
            DHCPREQUEST,
            &[
                (OPT_HOSTNAME, b"office-printer-3".to_vec()),
                (OPT_VENDOR_CLASS, b"HP JetDirect".to_vec()),
                (OPT_PARAMETER_REQUEST, vec![1, 3, 6, 15, 119, 252]),
                (OPT_REQUESTED_ADDRESS, vec![192, 168, 1, 74]),
            ],
        );
        let frame = super::super::ethernet::parse(&bytes).expect("an ethernet frame");
        let request = client_request(&frame).expect("a client request");

        assert_eq!(request.hostname, Some("office-printer-3"));
        assert_eq!(request.vendor_class, Some("HP JetDirect"));
        assert_eq!(
            request.requested_address,
            Some(Ipv4Addr::new(192, 168, 1, 74))
        );
        assert_eq!(
            request.client_mac,
            Some(MacAddr(0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33))
        );
    }

    /// The parameter request list identifies a device by *what it asks for and
    /// in what order*, which is chosen by whoever wrote the stack and is
    /// near-identical across every device running it.
    ///
    /// Sorting or deduplicating it would leave two stacks asking for the same
    /// four options indistinguishable — which is most of them.
    #[test]
    fn the_parameter_request_list_keeps_the_order_it_was_asked_in() {
        let asked = vec![1u8, 121, 3, 6, 15, 119, 252];
        let bytes = request_frame(DHCPDISCOVER, &[(OPT_PARAMETER_REQUEST, asked.clone())]);
        let frame = super::super::ethernet::parse(&bytes).expect("an ethernet frame");

        assert_eq!(
            client_request(&frame)
                .expect("a client request")
                .parameter_request_list,
            Some(asked.as_slice()),
            "the order is the signal, so it is kept exactly"
        );
    }

    /// A server's answer describes the network rather than the device: the way
    /// out, the resolvers, and the domain, from the one machine on the segment
    /// that is authoritative about all three.
    #[test]
    fn a_server_reply_carries_what_the_network_hands_out() {
        let mut extra = vec![
            (OPT_ROUTER, vec![192, 168, 1, 1]),
            (OPT_DOMAIN_NAME_SERVER, vec![192, 168, 1, 1, 9, 9, 9, 9]),
            (OPT_DOMAIN_NAME, b"corp.example.net".to_vec()),
        ];
        extra.sort_by_key(|(code, _)| *code);

        let bytes = reply_frame_with(DHCPACK, Some(server_addr()), &extra);
        let frame = super::super::ethernet::parse(&bytes).expect("an ethernet frame");
        let reply = server_reply(&frame).expect("a server reply");

        assert_eq!(reply.server, Some(server_addr()));
        assert_eq!(reply.domain, Some("corp.example.net"));
        assert_eq!(
            reply.routers().collect::<Vec<_>>(),
            vec![Ipv4Addr::new(192, 168, 1, 1)]
        );
        assert_eq!(
            reply.resolvers().collect::<Vec<_>>(),
            vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(9, 9, 9, 9)],
            "in the order the server listed them, which is the order a client tries"
        );
    }

    /// The two directions must not be read as each other. A client broadcast
    /// read as a server's answer would name every laptop on the network a DHCP
    /// server; a server's answer read as a client request would invent a device.
    #[test]
    fn neither_direction_is_readable_as_the_other() {
        let request = request_frame(DHCPDISCOVER, &[(OPT_HOSTNAME, b"laptop".to_vec())]);
        let frame = super::super::ethernet::parse(&request).expect("an ethernet frame");
        assert_eq!(
            server_reply(&frame),
            None,
            "a client asking is not a server answering"
        );

        let reply = reply_frame(DHCPACK, Some(server_addr()));
        let frame = super::super::ethernet::parse(&reply).expect("an ethernet frame");
        assert_eq!(
            client_request(&frame),
            None,
            "a server answering is not a client asking"
        );
    }

    /// An option list carrying a partial address is malformed. The addresses in
    /// front of the remainder are still what the server said, and padding the
    /// remainder out would invent one.
    #[test]
    fn a_trailing_partial_address_is_dropped_rather_than_padded() {
        let bytes = reply_frame_with(
            DHCPACK,
            Some(server_addr()),
            &[(OPT_DOMAIN_NAME_SERVER, vec![10, 0, 0, 1, 10, 0])],
        );
        let frame = super::super::ethernet::parse(&bytes).expect("an ethernet frame");

        assert_eq!(
            server_reply(&frame)
                .expect("a server reply")
                .resolvers()
                .collect::<Vec<_>>(),
            vec![Ipv4Addr::new(10, 0, 0, 1)]
        );
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
