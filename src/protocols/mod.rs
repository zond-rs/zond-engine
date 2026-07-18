// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

pub mod arp;
pub mod dns;
pub mod ethernet;
pub mod icmp;
pub mod ip;
pub mod mdns;
pub mod ndp;
pub mod tcp;
pub mod udp;
pub mod utils;

use crate::core::models::ip::range::Ipv4Range;
use crate::core::models::ip::set::IpSet;
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

type Bytes = Vec<u8>;
type PacketIter = Box<dyn Iterator<Item = (Bytes, IpAddr)> + Send>;

pub fn eth_packet_iter(
    local_mac: &MacAddr,
    src_v4: &Option<Ipv4Addr>,
    link_local: &Option<Ipv6Addr>,
    ip_set: &IpSet,
) -> anyhow::Result<PacketIter> {
    let arp_iter = src_v4
        .as_ref()
        .map(|v4| create_arp_iter(local_mac, v4, ip_set))
        .transpose()?
        .into_iter()
        .flatten();

    let icmp_iter = link_local
        .as_ref()
        .map(|v6| create_icmpv6_packets(local_mac, v6))
        .transpose()?
        .into_iter()
        .flatten();

    Ok(Box::new(arp_iter.chain(icmp_iter)))
}

pub fn create_arp_iter(
    local_mac: &MacAddr,
    src_ip: &Ipv4Addr,
    ip_set: &IpSet,
) -> anyhow::Result<PacketIter> {
    let local_mac = *local_mac;
    let src_ip = *src_ip;
    let dst_mac = MacAddr::broadcast();

    let ranges: Vec<Ipv4Range> = ip_set.v4().to_vec();

    let iter = ranges
        .into_iter()
        .flat_map(|range| {
            let start: u32 = range.start_addr.into();
            let end: u32 = range.end_addr.into();
            (start..=end).map(Ipv4Addr::from)
        })
        .map(move |dst_addr| {
            let packet = arp::create_packet(&local_mac, dst_mac, &src_ip, dst_addr)
                .expect("Failed to create ARP packet");

            (packet, IpAddr::V4(dst_addr))
        });

    Ok(Box::new(iter))
}

fn create_icmpv6_packets(
    local_mac: &MacAddr,
    link_local_addr: &Ipv6Addr,
) -> anyhow::Result<PacketIter> {
    let packet: Vec<u8> = icmp::create_all_nodes_echo_request_v6(local_mac, link_local_addr)?;

    let iter = std::iter::once((packet, IpAddr::V6(*link_local_addr)));

    Ok(Box::new(iter))
}

pub fn get_ip_addr_from_eth(frame: &EthernetPacket) -> anyhow::Result<IpAddr> {
    match frame.get_ethertype() {
        EtherTypes::Arp => Ok(IpAddr::V4(arp::get_ipv4_addr_from_eth(frame)?)),
        EtherTypes::Ipv4 => Ok(IpAddr::V4(ip::get_ipv4_addr_from_eth(frame)?)),
        EtherTypes::Ipv6 => Ok(IpAddr::V6(ip::get_ipv6_src_addr_from_eth(frame)?)),
        _ => Err(anyhow::anyhow!(
            "Unsupported EtherType: {:?}",
            frame.get_ethertype()
        )),
    }
}
