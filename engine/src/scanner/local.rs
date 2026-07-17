// Copyright (c) 2026 OverTheFlow and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! A **local area network (LAN)** scanner.
//!
//! Primarily used for discovering and scanning hosts on the same physical network,
//! using protocols like ARP, NDP, and ICMP for discovery and TCP/UDP for port scanning.
//!
//! This scanner requires **root privileges** to construct and intercept raw
//! Layer 2 packets via the operating system's network sockets.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use std::net::Ipv4Addr;
use anyhow::{anyhow, bail, ensure};
use pnet::{
    datalink::NetworkInterface,
    packet::{
        Packet,
        arp::ArpPacket,
        ethernet::{EtherTypes, EthernetPacket},
    },
};

use zond_core::models::timer::ScanTimer;
use zond_core::{
    error,
    models::{host::Host, ip::set::IpSet},
    success,
};

use protocol::ethernet;
use tokio::{
    sync::mpsc::UnboundedSender,
    time::{Interval, Sleep},
};
use zond_protocols::{self as protocol, ip};

use crate::network::{
    channel::{self, EthernetHandle},
    mac::IntoCoreMac,
};

use super::NetworkExplorer;
use async_trait::async_trait;
use pnet::datalink::MacAddr;
use zond_system::interface::NetworkInterfaceExtension;

const MAX_CHANNEL_TIME: Duration = Duration::from_millis(7_500);
const MIN_CHANNEL_TIME: Duration = Duration::from_millis(2_500);
const MAX_SILENCE_MS: Duration = Duration::from_millis(500);
const SEND_INTERVAL_US: Duration = Duration::from_micros(1000);

pub struct LocalScanner {
    hosts_map: HashMap<MacAddr, Host>,
    ip_set: IpSet,
    local_mac: MacAddr,
    src_v4: Option<Ipv4Addr>,
    link_local: Option<Ipv6Addr>,
    eth_handle: EthernetHandle,
    timer: ScanTimer,
    dns_tx: Option<UnboundedSender<IpAddr>>,
    rtt_map: HashMap<IpAddr, Instant>,
}

#[async_trait]
impl NetworkExplorer for LocalScanner {
    async fn discover_hosts(&mut self) -> anyhow::Result<Vec<Host>> {
        let mut packet_iter = protocol::eth_packet_iter(
            &self.local_mac,
            &self.src_v4,
            &self.link_local,
            &self.ip_set,
        )?;

        let mut sending_finished = false;
        let mut send_interval: Interval = tokio::time::interval(SEND_INTERVAL_US);

        let scan_deadline: Sleep = tokio::time::sleep(MAX_CHANNEL_TIME);
        tokio::pin!(scan_deadline);

        loop {
            if (!self.should_continue() && sending_finished)
                || super::STOP_SIGNAL.load(Ordering::Relaxed)
            {
                break;
            }

            tokio::select! {
                pkt = self.eth_handle.rx.recv() => {
                    match pkt {
                        Some(bytes) => _ = self.process_eth_packet(&bytes),
                        None => break,
                    }
                }

                _ = send_interval.tick(), if !sending_finished => {
                    match packet_iter.next() {
                        Some((packet, ip)) => {
                            self.rtt_map.insert(ip, Instant::now());
                            self.eth_handle.tx.send_to(&packet, None);
                        },
                        None => {
                            sending_finished = true;
                        },
                    }
                }

                _ = &mut scan_deadline => break,
            }
        }

        Ok(self.hosts_map.drain().map(|(_, v)| v).collect())
    }
}

impl LocalScanner {
    pub fn new(
        intf: NetworkInterface,
        ip_set: IpSet,
        dns_tx: Option<UnboundedSender<IpAddr>>,
    ) -> anyhow::Result<Self> {
        let eth_handle: EthernetHandle = channel::start_capture(&intf)?;
        let timer: ScanTimer = ScanTimer::new(MAX_CHANNEL_TIME, MIN_CHANNEL_TIME, MAX_SILENCE_MS);
        let len = ip_set.len() as usize;
        let local_mac = intf.mac.unwrap();

        let mut src_v4 = None;
        for net in intf.get_ipv4_nets() {
            if src_v4.is_none() && !net.ip().is_loopback() {
                src_v4 = Some(net.ip());
            }
            if ip_set.v4().iter().any(|range| net.contains(range.start_addr)) {
                src_v4 = Some(net.ip());
                break;
            }
        }

        let link_local = intf
            .get_ipv6_nets()
            .into_iter()
            .find(|net| net.ip().is_unicast_link_local())
            .map(|net| net.ip());

        Ok(Self {
            hosts_map: HashMap::new(),
            ip_set,
            local_mac,
            src_v4,
            link_local,
            eth_handle,
            timer,
            dns_tx,
            rtt_map: HashMap::with_capacity(len),
        })
    }

    fn process_eth_packet(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        let eth_frame: EthernetPacket = ethernet::get_packet_from_u8(bytes)?;
        let other_mac_addr = eth_frame.get_source();
        ensure!(other_mac_addr != self.local_mac);

        let source_addr: IpAddr = protocol::get_ip_addr_from_eth(&eth_frame)?;

        ensure!(
            self.ip_set.contains(&source_addr),
            "{source_addr} is not in range"
        );

        let rtt: Option<Duration> = self.calculate_rtt(&eth_frame).unwrap_or_else(|e| {
            error!(verbosity = 2, "Failed to calculate RTT: {e}");
            None
        });

        let mut is_new_host: bool = false;
        let host: &mut Host = self.hosts_map.entry(other_mac_addr).or_insert_with(|| {
            self.timer.mark_activity();
            super::increment_host_count();
            is_new_host = true;
            Host::new(source_addr).with_mac(other_mac_addr.into_core())
        });

        if let Some(rtt) = rtt {
            success!(
                verbosity = 2,
                "{source_addr} response in {}ms",
                rtt.as_millis()
            );
            host.add_rtt(rtt);
        }

        let is_new_ip: bool = host.add_ip(source_addr);

        if source_addr.is_ipv4() && host.primary_ip().is_ipv6() {
            host.set_primary_ip(source_addr);
        }

        if is_new_host || is_new_ip {
            self.dns_tx.as_ref().map(|tx| tx.send(source_addr));
        }

        Ok(())
    }

    fn calculate_rtt(&mut self, eth_frame: &EthernetPacket) -> anyhow::Result<Option<Duration>> {
        match eth_frame.get_ethertype() {
            EtherTypes::Arp => {
                let arp_packet: ArpPacket = ArpPacket::new(eth_frame.payload())
                    .ok_or_else(|| anyhow!("packet invalid [ARP]"))?;

                let src_addr: IpAddr = IpAddr::V4(arp_packet.get_sender_proto_addr());

                let start_time: Instant = self
                    .rtt_map
                    .remove(&src_addr)
                    .ok_or_else(|| anyhow!("unmapped address [ARP]"))?;

                Ok(Some(start_time.elapsed()))
            }

            EtherTypes::Ipv6 => {
                let dst_addr: Ipv6Addr = match ip::get_ipv6_dst_addr_from_eth(eth_frame) {
                    Ok(addr) => addr,
                    Err(_) => bail!("packet invalid [IPv6]"),
                };

                if dst_addr.is_unicast_link_local() {
                    let dst_addr: IpAddr = IpAddr::V6(dst_addr);
                    let start_time: &Instant = self
                        .rtt_map
                        .get(&dst_addr)
                        .ok_or_else(|| anyhow!("unmapped link local [IPv6]"))?;

                    return Ok(Some(start_time.elapsed()));
                }

                Ok(None)
            }

            _ => Ok(None),
        }
    }

    fn should_continue(&self) -> bool {
        let not_stopped: bool = !super::STOP_SIGNAL.load(Ordering::Relaxed);
        let time_not_expired: bool = !self.timer.has_expired();
        let work_remains: bool = self.ip_set.len() as usize > self.hosts_map.len();

        not_stopped && time_not_expired && work_remains
    }
}
