// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Layer-2 (Ethernet) Send Backend
//!
//! A [`ProbeSender`] that builds and
//! emits complete Ethernet frames itself, rather than handing a segment to a
//! raw socket and letting the kernel route it.
//!
//! Two situations need this:
//!
//! - **Windows**, where the OS blocks raw-socket TCP sends outright, so the
//!   only way to emit a SYN probe is to write the frame at the link layer.
//! - **Deliberate host-stack bypass**: crafting the frame end to end (source
//!   MAC included) sidesteps the local firewall and connection-tracking that
//!   a raw-socket send still traverses.
//!
//! It leans on [`NeighborResolver`] to decide, per destination, which
//! interface to send from and what the next-hop MAC is - reading the gateway
//! straight from the OS for off-link targets, and resolving on-link targets'
//! MACs with an active ARP exchange that it caches.
//!
//! **Portability note:** on-link IPv6 currently returns an error rather than
//! performing NDP neighbor solicitation; off-link IPv6 works, since the
//! gateway's MAC comes from the OS. Wiring up NDP is the remaining gap.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Context;
use pnet::datalink::{self, Config, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::util::MacAddr;

use crate::protocols::arp;
use crate::transport::channel::open_eth_channel;
use crate::transport::frame;
use crate::transport::neighbor::{LinkRoute, NeighborResolver};
use crate::transport::probe::{Emission, IpProtocols, ProbeSender, SendError};

/// How long to wait for an ARP reply before giving up on an on-link target.
const ARP_TIMEOUT: Duration = Duration::from_millis(500);

/// Per-interface datalink read timeout, so the ARP receive loop wakes often
/// enough to honor [`ARP_TIMEOUT`] instead of blocking indefinitely.
const CHANNEL_READ_TIMEOUT: Duration = Duration::from_millis(50);

/// The open link-layer channel for one interface, plus the source MAC to
/// stamp on frames leaving it.
struct InterfaceChannel {
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
}

/// A Layer-2 send backend. Interfaces' channels are opened lazily on first
/// use and reused thereafter.
pub struct EthernetSender {
    resolver: Mutex<NeighborResolver>,
    channels: Mutex<HashMap<String, InterfaceChannel>>,
    /// The IP protocol numbers to stamp into the headers this sender builds,
    /// one per address family. Fixed per sender because a transport carries one
    /// kind of probe; see [`EthernetSender::from_system`].
    protocols: IpProtocols,
}

impl EthernetSender {
    /// Builds a sender over the system's Ethernet-capable interfaces, emitting
    /// segments as `protocols` says for the family being addressed.
    ///
    /// Unlike the raw-socket sender, this one writes the IP header itself, so
    /// nothing else can tell it what it is carrying: the segment is opaque
    /// bytes by the time it arrives. The protocols are fixed at construction
    /// rather than passed per send because a transport is opened for one
    /// `ProbeKind` and carries only that kind's probes — but they are a *pair*,
    /// because a kind carrying ICMP carries two different protocol numbers and
    /// only the destination says which. A wrong number here is invisible
    /// locally and fatal remotely: the datagram arrives and is handed to the
    /// wrong protocol handler, so it is simply never answered.
    ///
    /// Returns `None` if the host has no Ethernet-capable interface (only
    /// tunnels or loopback), so the caller can fall back to the raw-IP path
    /// rather than stand up a backend that can never send.
    pub fn from_system(protocols: IpProtocols) -> Option<Self> {
        let resolver = NeighborResolver::from_system();
        if !resolver.has_ethernet() {
            return None;
        }
        Some(Self {
            resolver: Mutex::new(resolver),
            channels: Mutex::new(HashMap::new()),
            protocols,
        })
    }

    /// Determines the next-hop MAC for `route`, performing (and caching) an
    /// ARP exchange if it's an on-link target we haven't learned yet.
    fn next_hop_mac(&self, route: &LinkRoute) -> anyhow::Result<MacAddr> {
        if let Some(mac) = route.next_hop_mac {
            return Ok(mac);
        }

        let target_v4 = match route.next_hop {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                anyhow::bail!("on-link IPv6 next-hop resolution (NDP) is not yet implemented")
            }
        };
        let src_v4 = match route.src_ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => anyhow::bail!("IPv4 target with IPv6 source is invalid"),
        };

        let mac = self.arp_resolve(&route.interface, route.src_mac, src_v4, target_v4)?;
        self.resolver
            .lock()
            .unwrap()
            .remember(&route.interface, route.next_hop, mac);
        Ok(mac)
    }

    /// Sends an ARP request for `target` and waits for the reply, returning
    /// the target's MAC. Runs synchronously against the interface's datalink
    /// channel, bounded by [`ARP_TIMEOUT`].
    fn arp_resolve(
        &self,
        interface: &str,
        src_mac: MacAddr,
        src_ip: Ipv4Addr,
        target: Ipv4Addr,
    ) -> anyhow::Result<MacAddr> {
        let mut channels = self.channels.lock().unwrap();
        let channel = self.channel_for(&mut channels, interface)?;

        let request = arp::create_request(&src_mac, &src_ip, target);
        channel
            .tx
            .send_to(&request, None)
            .context("no ARP send result")?
            .context("sending ARP request")?;

        let deadline = Instant::now() + ARP_TIMEOUT;
        while Instant::now() < deadline {
            let Ok(frame) = channel.rx.next() else {
                continue; // read timeout; keep waiting until the deadline
            };
            if let Some(mac) = parse_arp_reply(frame, target) {
                return Ok(mac);
            }
        }
        anyhow::bail!("ARP timed out resolving {target} on {interface}")
    }

    /// Returns the datalink channel for `interface`, opening it on first use.
    fn channel_for<'a>(
        &self,
        channels: &'a mut HashMap<String, InterfaceChannel>,
        interface: &str,
    ) -> anyhow::Result<&'a mut InterfaceChannel> {
        if !channels.contains_key(interface) {
            let intf = find_interface(interface)
                .with_context(|| format!("interface {interface} not found"))?;
            let cfg = Config {
                read_timeout: Some(CHANNEL_READ_TIMEOUT),
                ..Default::default()
            };
            let (tx, rx) = open_eth_channel(&intf, datalink::channel, cfg)?;
            channels.insert(interface.to_string(), InterfaceChannel { tx, rx });
        }
        Ok(channels.get_mut(interface).unwrap())
    }
}

impl ProbeSender for EthernetSender {
    fn send(
        &self,
        segment: &[u8],
        src: IpAddr,
        dst: IpAddr,
        emission: Emission,
    ) -> Result<(), SendError> {
        // Every step here can fail for a reason outside this process - no route,
        // a neighbour that never answered our ARP, an interface that went down
        // mid-scan - so they are all refusals carrying the cause, not claims
        // that the transport is incapable.
        (|| -> anyhow::Result<()> {
            let route = self
                .resolver
                .lock()
                .unwrap()
                .resolve(dst)
                .with_context(|| format!("no Ethernet route to {dst}"))?;

            let dst_mac = self.next_hop_mac(&route)?;
            let frame = frame::build_ethernet_frame(
                route.src_mac,
                dst_mac,
                src,
                dst,
                self.protocols.for_destination(dst),
                segment,
                emission.hop_limit,
            )?;

            let mut channels = self.channels.lock().unwrap();
            let channel = self.channel_for(&mut channels, &route.interface)?;
            channel
                .tx
                .send_to(&frame, None)
                .context("no frame send result")?
                .context("sending frame")?;
            Ok(())
        })()
        .map_err(SendError::from_io)
    }
}

/// Finds the `pnet` interface with the given name.
fn find_interface(name: &str) -> Option<NetworkInterface> {
    datalink::interfaces().into_iter().find(|i| i.name == name)
}

/// Parses an Ethernet frame as an ARP reply from `target`, returning the
/// sender's hardware address if it matches.
fn parse_arp_reply(frame: &[u8], target: Ipv4Addr) -> Option<MacAddr> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() == ArpOperations::Reply && arp.get_sender_proto_addr() == target {
        Some(arp.get_sender_hw_addr())
    } else {
        None
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
    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
    use pnet::packet::ethernet::MutableEthernetPacket;

    /// Builds an Ethernet-framed ARP reply from `sender_ip`/`sender_mac`.
    fn arp_reply(sender_ip: Ipv4Addr, sender_mac: MacAddr) -> Vec<u8> {
        let mut buf = vec![0u8; 42];
        {
            let mut eth = MutableEthernetPacket::new(&mut buf[..14]).unwrap();
            eth.set_ethertype(EtherTypes::Arp);
            eth.set_source(sender_mac);
            eth.set_destination(MacAddr::broadcast());
        }
        {
            let mut a = MutableArpPacket::new(&mut buf[14..]).unwrap();
            a.set_hardware_type(ArpHardwareTypes::Ethernet);
            a.set_protocol_type(EtherTypes::Ipv4);
            a.set_hw_addr_len(6);
            a.set_proto_addr_len(4);
            a.set_operation(ArpOperations::Reply);
            a.set_sender_hw_addr(sender_mac);
            a.set_sender_proto_addr(sender_ip);
            a.set_target_proto_addr(Ipv4Addr::new(192, 168, 1, 50));
        }
        buf
    }

    #[test]
    fn parses_matching_arp_reply() {
        let ip = Ipv4Addr::new(192, 168, 1, 200);
        let mac = MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);
        assert_eq!(parse_arp_reply(&arp_reply(ip, mac), ip), Some(mac));
    }

    #[test]
    fn ignores_arp_reply_from_other_ip() {
        let mac = MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);
        let reply = arp_reply(Ipv4Addr::new(192, 168, 1, 201), mac);
        assert_eq!(
            parse_arp_reply(&reply, Ipv4Addr::new(192, 168, 1, 200)),
            None
        );
    }

    #[test]
    fn ignores_non_arp_frame() {
        let mut buf = vec![0u8; 42];
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_ethertype(EtherTypes::Ipv4);
        assert_eq!(parse_arp_reply(&buf, Ipv4Addr::new(192, 168, 1, 200)), None);
    }
}
