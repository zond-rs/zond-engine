// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Discovery Response Protocols
//!
//! [`LocalScanner`](super::LocalScanner) sends more than one kind of probe
//! onto the wire and has to recognize more than one kind of reply. Rather
//! than growing a single function that understands every wire format it
//! might ever need to, each format is its own [`DiscoveryProtocol`]
//! implementation, and the scanner just tries each one against every frame
//! it receives. Adding support for a new discovery mechanism means writing
//! one more implementation here, not touching the receive loop.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};

use crate::protocols::ip;

use super::LocalScannerError;

/// Outstanding discovery probes, keyed by the address a reply is expected
/// from, recording when each one was sent.
pub type PendingProbes = HashMap<IpAddr, Instant>;

/// What a [`DiscoveryProtocol`] found when asked to interpret one received frame.
pub enum ProtocolMatch {
    /// This frame isn't one the protocol recognizes; another protocol may still claim it.
    Unhandled,
    /// This frame is a discovery response, with a round-trip time if a
    /// matching outbound probe was still on record.
    Handled { rtt: Option<Duration> },
}

/// A wire-level protocol capable of recognizing discovery responses.
///
/// [`LocalScanner`](super::LocalScanner) tries each configured protocol
/// against every received frame in turn; the first one that claims it
/// decides whether - and how precisely - a round-trip time can be computed.
/// The scanner has already identified the frame's source address and ruled
/// out obvious noise (packets from itself, addresses outside the scan)
/// before a protocol ever sees the frame, so implementations only need to
/// concern themselves with their own wire format.
pub trait DiscoveryProtocol: Send {
    fn interpret(
        &self,
        frame: &EthernetPacket,
        source: IpAddr,
        pending: &mut PendingProbes,
    ) -> anyhow::Result<ProtocolMatch>;
}

/// Recognizes ARP replies as discovery responses.
///
/// A round trip is measured from when a request was sent to a given
/// address to when that same address answers. ARP traffic that doesn't
/// correspond to an outstanding probe - other hosts' requests, gratuitous
/// announcements - is common on a shared segment and isn't treated as an
/// error, just a response with no timing data.
pub struct ArpProtocol;

impl DiscoveryProtocol for ArpProtocol {
    fn interpret(
        &self,
        frame: &EthernetPacket,
        source: IpAddr,
        pending: &mut PendingProbes,
    ) -> anyhow::Result<ProtocolMatch> {
        if frame.get_ethertype() != EtherTypes::Arp {
            return Ok(ProtocolMatch::Unhandled);
        }

        let rtt = pending.remove(&source).map(|sent_at| sent_at.elapsed());
        Ok(ProtocolMatch::Handled { rtt })
    }
}

/// Recognizes inbound IPv6 traffic addressed directly to this host as a
/// reply to the single ICMPv6 all-nodes probe sent at the start of a scan.
///
/// Unlike ARP, this probe isn't sent per target - it's one multicast
/// solicitation any IPv6 neighbor may answer - so the round trip is
/// measured from that single send against every qualifying reply, rather
/// than being consumed after the first one. A qualifying reply with no
/// matching send on record would mean the probe was never actually sent,
/// which is treated as an error rather than silently ignored.
pub struct Icmpv6Protocol;

impl DiscoveryProtocol for Icmpv6Protocol {
    fn interpret(
        &self,
        frame: &EthernetPacket,
        _source: IpAddr,
        pending: &mut PendingProbes,
    ) -> anyhow::Result<ProtocolMatch> {
        if frame.get_ethertype() != EtherTypes::Ipv6 {
            return Ok(ProtocolMatch::Unhandled);
        }

        let destination = ip::get_ipv6_dst_addr_from_eth(frame)?;
        if !destination.is_unicast_link_local() {
            return Ok(ProtocolMatch::Unhandled);
        }

        let destination = IpAddr::V6(destination);
        let sent_at = pending
            .get(&destination)
            .ok_or(LocalScannerError::UnmappedRttSource(destination))?;

        Ok(ProtocolMatch::Handled {
            rtt: Some(sent_at.elapsed()),
        })
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
        let mut pending = PendingProbes::new();

        let result = ArpProtocol.interpret(&frame, Ipv6Addr::LOCALHOST.into(), &mut pending);

        assert!(matches!(result.unwrap(), ProtocolMatch::Unhandled));
    }

    #[test]
    fn arp_protocol_reports_rtt_for_a_pending_probe() {
        let sender = Ipv4Addr::new(192, 168, 1, 50);
        let frame_bytes = arp_reply_frame(sender);
        let frame = EthernetPacket::new(&frame_bytes).unwrap();

        let mut pending = PendingProbes::new();
        pending.insert(sender.into(), Instant::now());

        let result = ArpProtocol
            .interpret(&frame, sender.into(), &mut pending)
            .unwrap();

        match result {
            ProtocolMatch::Handled { rtt } => assert!(rtt.is_some()),
            ProtocolMatch::Unhandled => panic!("expected a handled ARP reply"),
        }
        assert!(
            !pending.contains_key(&sender.into()),
            "a consumed probe should be removed"
        );
    }

    #[test]
    fn arp_protocol_reports_no_rtt_without_a_pending_probe() {
        let sender = Ipv4Addr::new(192, 168, 1, 50);
        let frame_bytes = arp_reply_frame(sender);
        let frame = EthernetPacket::new(&frame_bytes).unwrap();
        let mut pending = PendingProbes::new();

        let result = ArpProtocol
            .interpret(&frame, sender.into(), &mut pending)
            .unwrap();

        match result {
            ProtocolMatch::Handled { rtt } => assert!(rtt.is_none()),
            ProtocolMatch::Unhandled => panic!("unsolicited ARP traffic should still be handled"),
        }
    }

    #[test]
    fn icmpv6_protocol_ignores_non_ipv6_frames() {
        let frame_bytes = arp_reply_frame(Ipv4Addr::new(10, 0, 0, 2));
        let frame = EthernetPacket::new(&frame_bytes).unwrap();
        let mut pending = PendingProbes::new();

        let result =
            Icmpv6Protocol.interpret(&frame, Ipv4Addr::new(10, 0, 0, 2).into(), &mut pending);

        assert!(matches!(result.unwrap(), ProtocolMatch::Unhandled));
    }

    #[test]
    fn icmpv6_protocol_ignores_traffic_not_addressed_to_a_link_local_unicast() {
        let frame_bytes = ipv6_frame(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)); // multicast
        let frame = EthernetPacket::new(&frame_bytes).unwrap();
        let mut pending = PendingProbes::new();

        let result = Icmpv6Protocol.interpret(&frame, Ipv6Addr::LOCALHOST.into(), &mut pending);

        assert!(matches!(result.unwrap(), ProtocolMatch::Unhandled));
    }

    #[test]
    fn icmpv6_protocol_reports_rtt_without_consuming_the_probe() {
        let own_link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let frame_bytes = ipv6_frame(own_link_local);
        let frame = EthernetPacket::new(&frame_bytes).unwrap();

        let mut pending = PendingProbes::new();
        pending.insert(own_link_local.into(), Instant::now());

        for _ in 0..2 {
            let result = Icmpv6Protocol
                .interpret(&frame, own_link_local.into(), &mut pending)
                .unwrap();

            match result {
                ProtocolMatch::Handled { rtt } => assert!(rtt.is_some()),
                ProtocolMatch::Unhandled => panic!("expected a handled reply"),
            }
        }
        assert!(
            pending.contains_key(&own_link_local.into()),
            "a multicast probe's timestamp isn't consumed by a single reply"
        );
    }

    #[test]
    fn icmpv6_protocol_errors_when_no_probe_was_ever_sent() {
        let own_link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let frame_bytes = ipv6_frame(own_link_local);
        let frame = EthernetPacket::new(&frame_bytes).unwrap();
        let mut pending = PendingProbes::new();

        let result = Icmpv6Protocol.interpret(&frame, own_link_local.into(), &mut pending);

        assert!(result.is_err());
    }
}
