// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Discovery Response Protocols
//!
//! [`LocalScanner`](super::LocalScanner) sends more than one kind of probe onto
//! the wire and has to recognize more than one kind of reply. Rather than
//! growing a single function that understands every wire format, each format is
//! its own [`DiscoveryProtocol`] implementation, and the scanner tries each one
//! against every frame it receives. Supporting a new discovery mechanism means
//! writing one more implementation here instead of touching the receive loop.

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};

use crate::core::models::host::StatusProtocol;
use crate::protocols::ip;

/// What a [`DiscoveryProtocol`] found when asked to interpret one received frame.
///
/// The two "handled" answers differ in what they entitle the scanner to
/// conclude about the probe that provoked them, which is why they are separate
/// variants rather than one carrying a round-trip time. A protocol reads bytes;
/// deciding which outstanding probe a frame retires is the scanner's job, since
/// only the scanner knows what it sent and when.
pub enum ProtocolMatch {
    /// The protocol does not recognize this frame. Another protocol may still
    /// claim it.
    Unhandled,
    /// A reply to the unicast probe aimed at this frame's own source address,
    /// so it answers exactly one outstanding probe and retires it.
    Solicited,
    /// A reply to the single all-nodes solicitation. That probe is not consumed
    /// by any one reply, because every neighbour on the segment may answer the
    /// same packet.
    AllNodes,
}

/// A wire-level protocol capable of recognizing discovery responses.
///
/// [`LocalScanner`](super::LocalScanner) tries each configured protocol against
/// every received frame in turn, and the first one to claim a frame decides what
/// kind of answer it is. The scanner has already identified the frame's source
/// address and ruled out obvious noise (packets from itself, addresses outside
/// the scan) before a protocol ever sees the frame, so an implementation is a
/// pure function of the bytes in front of it.
pub trait DiscoveryProtocol: Send {
    fn interpret(&self, frame: &EthernetPacket) -> anyhow::Result<ProtocolMatch>;

    /// The evidence this protocol produces, for the liveness record of whichever
    /// host it claims a frame from.
    ///
    /// Each implementation names its own evidence rather than the receive loop
    /// inferring it from the frame, so a new discovery mechanism stays one more
    /// implementation in this module — the same reason `interpret` lives here.
    fn status_protocol(&self) -> StatusProtocol;
}

/// Recognizes ARP replies as discovery responses.
///
/// Every ARP frame from an in-range address counts, whether or not it answers an
/// outstanding request: other hosts' requests and gratuitous announcements are
/// common on a shared segment and are just as good a proof that someone is
/// there. Whether one also yields a round-trip time depends on there being a
/// probe outstanding to measure against, which the scanner determines.
pub struct ArpProtocol;

impl DiscoveryProtocol for ArpProtocol {
    fn interpret(&self, frame: &EthernetPacket) -> anyhow::Result<ProtocolMatch> {
        if frame.get_ethertype() != EtherTypes::Arp {
            return Ok(ProtocolMatch::Unhandled);
        }

        Ok(ProtocolMatch::Solicited)
    }

    fn status_protocol(&self) -> StatusProtocol {
        StatusProtocol::Arp
    }
}

/// Recognizes inbound IPv6 traffic addressed directly to this host as a reply to
/// the single ICMPv6 all-nodes probe sent at the start of a sweep.
///
/// Unlike ARP, that probe is not sent per target: it is one multicast
/// solicitation any IPv6 neighbour may answer, so it is measured against every
/// qualifying reply rather than being consumed by the first.
pub struct Icmpv6Protocol;

impl DiscoveryProtocol for Icmpv6Protocol {
    fn interpret(&self, frame: &EthernetPacket) -> anyhow::Result<ProtocolMatch> {
        if frame.get_ethertype() != EtherTypes::Ipv6 {
            return Ok(ProtocolMatch::Unhandled);
        }

        let destination = ip::get_ipv6_dst_addr_from_eth(frame)?;
        if !destination.is_unicast_link_local() {
            return Ok(ProtocolMatch::Unhandled);
        }

        Ok(ProtocolMatch::AllNodes)
    }

    fn status_protocol(&self) -> StatusProtocol {
        StatusProtocol::Ndp
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
    use crate::protocols::{arp, ethernet, ip as ip_protocol};
    use pnet::datalink::MacAddr;
    use pnet::packet::ip::IpNextHeaderProtocol;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const LOCAL_MAC: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
    const PEER_MAC: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x02);

    fn arp_reply_frame(sender_ip: Ipv4Addr) -> Vec<u8> {
        arp::create_packet(&PEER_MAC, LOCAL_MAC, &sender_ip, Ipv4Addr::new(10, 0, 0, 1))
            .expect("failed to build ARP test frame")
    }

    fn ipv6_frame(destination: Ipv6Addr) -> Vec<u8> {
        let source = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let eth_header = ethernet::make_header(
            PEER_MAC,
            LOCAL_MAC,
            pnet::packet::ethernet::EtherTypes::Ipv6,
        )
        .expect("failed to build Ethernet header");
        let ip_header = ip_protocol::create_ipv6_header(
            source,
            destination,
            0,
            IpNextHeaderProtocol::new(58), // ICMPv6, payload contents are irrelevant here
        )
        .expect("failed to build IPv6 header");

        [eth_header, ip_header].concat()
    }

    #[test]
    fn arp_protocol_ignores_non_arp_frames() {
        let frame_bytes = ipv6_frame(Ipv6Addr::LOCALHOST);
        let frame = EthernetPacket::new(&frame_bytes).unwrap();

        let result = ArpProtocol.interpret(&frame);

        assert!(matches!(result.unwrap(), ProtocolMatch::Unhandled));
    }

    /// An ARP frame answers a probe aimed at the address that sent it, which is
    /// what entitles the scanner to retire exactly that probe.
    #[test]
    fn arp_protocol_claims_arp_frames_as_solicited() {
        let frame_bytes = arp_reply_frame(Ipv4Addr::new(192, 168, 1, 50));
        let frame = EthernetPacket::new(&frame_bytes).unwrap();

        let result = ArpProtocol.interpret(&frame).unwrap();

        assert!(matches!(result, ProtocolMatch::Solicited));
    }

    #[test]
    fn icmpv6_protocol_ignores_non_ipv6_frames() {
        let frame_bytes = arp_reply_frame(Ipv4Addr::new(10, 0, 0, 2));
        let frame = EthernetPacket::new(&frame_bytes).unwrap();

        let result = Icmpv6Protocol.interpret(&frame);

        assert!(matches!(result.unwrap(), ProtocolMatch::Unhandled));
    }

    #[test]
    fn icmpv6_protocol_ignores_traffic_not_addressed_to_a_link_local_unicast() {
        let frame_bytes = ipv6_frame(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)); // multicast
        let frame = EthernetPacket::new(&frame_bytes).unwrap();

        let result = Icmpv6Protocol.interpret(&frame);

        assert!(matches!(result.unwrap(), ProtocolMatch::Unhandled));
    }

    /// IPv6 traffic aimed at this host answers the all-nodes solicitation, and
    /// every neighbour may answer the same one - so the match must not imply
    /// that any single probe has been used up.
    #[test]
    fn icmpv6_protocol_claims_link_local_traffic_for_the_all_nodes_probe() {
        let frame_bytes = ipv6_frame(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let frame = EthernetPacket::new(&frame_bytes).unwrap();

        for _ in 0..2 {
            let result = Icmpv6Protocol.interpret(&frame).unwrap();
            assert!(matches!(result, ProtocolMatch::AllNodes));
        }
    }
}
