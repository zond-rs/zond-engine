// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
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

use pnet::{
    datalink::NetworkInterface,
    packet::{
        Packet,
        arp::ArpPacket,
        ethernet::{EtherTypes, EthernetPacket},
    },
};
use std::net::Ipv4Addr;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    time::{Duration, Instant},
};

use crate::core::models::rtt_window::RttWindow;
use crate::core::models::timer::{ScanBudget, ScanTimer};
use crate::core::models::{host::Host, ip::set::IpSet};
use crate::{error, info};

use crate::protocols::{self as protocol, ip};
use protocol::ethernet;
use tokio::{sync::mpsc::UnboundedSender, time::Interval};

use crate::network::{
    channel::{self, EthernetHandle},
    mac::IntoCoreMac,
};

use crate::core::session::{ScanContext, ScanEvent};
use crate::scanner::NetworkExplorer;
use crate::system::interface::NetworkInterfaceExtension;
use async_trait::async_trait;
use pnet::datalink::MacAddr;

#[derive(Debug, thiserror::Error)]
pub enum LocalScannerError {
    #[error("interface has no mac address")]
    NoMacAddress,
    #[error("invalid ARP packet")]
    InvalidArpPacket,
    #[error("unmapped RTT source: {0}")]
    UnmappedRTTSource(IpAddr),
    #[error("packet originated from this host")]
    SelfSourcedPacket,
    #[error("{0} is not in the scanned range")]
    AddressOutOfRange(IpAddr),
}

/// The overall time budget for one scan, before accounting for its target count.
///
/// `base` covers a single target; `per_target` is added for every additional
/// one, up to `ceiling`. These starting values assume a local network
/// segment, where round trips are typically well under a millisecond.
const MAX_CHANNEL_BUDGET: ScanBudget = ScanBudget::new(
    Duration::from_millis(2_000),
    Duration::from_millis(20),
    Duration::from_millis(15_000),
);

/// The minimum time a scan must run before it is allowed to end early due to
/// silence, scaled the same way as [`MAX_CHANNEL_BUDGET`].
const MIN_CHANNEL_BUDGET: ScanBudget = ScanBudget::new(
    Duration::from_millis(800),
    Duration::from_millis(7),
    Duration::from_millis(5_000),
);

/// The bounds within which the silence tolerance is allowed to adapt, and
/// how many recent samples inform that adaptation. See [`RttWindow`] for how
/// the tolerance itself is derived from observed round-trip times.
const SILENCE_FLOOR: Duration = Duration::from_millis(250);
const SILENCE_CEILING: Duration = Duration::from_millis(2_000);
const SILENCE_JITTER_MULTIPLIER: f64 = 4.0;
const RTT_WINDOW_CAPACITY: usize = 20;

const SEND_INTERVAL_US: Duration = Duration::from_micros(1000);

pub struct LocalScanner {
    ctx: ScanContext,
    ip_set: IpSet,
    local_mac: MacAddr,
    src_v4: Option<Ipv4Addr>,
    link_local: Option<Ipv6Addr>,
    eth_handle: EthernetHandle,
    timer: ScanTimer,
    /// Recent round-trip times observed from any responding host, used to
    /// adapt how long the scan waits before concluding the network has gone
    /// quiet. See [`LocalScanner::current_silence_tolerance`].
    rtt_window: RttWindow,
    dns_tx: Option<UnboundedSender<IpAddr>>,
    rtt_map: HashMap<IpAddr, Instant>,
    mac_to_ip: HashMap<MacAddr, IpAddr>,
}

#[async_trait]
impl NetworkExplorer for LocalScanner {
    async fn discover_hosts(&mut self) -> anyhow::Result<()> {
        let mut packet_iter = protocol::eth_packet_iter(
            &self.local_mac,
            &self.src_v4,
            &self.link_local,
            &self.ip_set,
        )?;

        let mut sending_finished = false;
        let mut send_interval: Interval = tokio::time::interval(SEND_INTERVAL_US);

        loop {
            if self.should_stop() && sending_finished {
                break;
            }

            // Only needed once sending has finished: while packets are still
            // going out, `send_interval` already drives the loop frequently
            // enough for the check above to run promptly.
            let next_tick = self
                .timer
                .time_until_next_tick(self.current_silence_tolerance());

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

                _ = tokio::time::sleep(next_tick), if sending_finished => {}
            }
        }

        Ok(())
    }
}

impl LocalScanner {
    pub fn new(
        intf: NetworkInterface,
        ip_set: IpSet,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
    ) -> anyhow::Result<Self> {
        let eth_handle: EthernetHandle = channel::start_capture(&intf)?;
        let len = ip_set.len() as usize;
        let timer: ScanTimer = ScanTimer::new(
            MAX_CHANNEL_BUDGET.for_target_count(len),
            MIN_CHANNEL_BUDGET.for_target_count(len),
        );
        let local_mac = intf.mac.ok_or(LocalScannerError::NoMacAddress)?;

        let mut src_v4 = None;
        for net in intf.get_ipv4_nets() {
            if src_v4.is_none() && !net.ip().is_loopback() {
                src_v4 = Some(net.ip());
            }
            if ip_set
                .v4()
                .iter()
                .any(|range| net.contains(range.start_addr))
            {
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
            ctx,
            ip_set,
            local_mac,
            src_v4,
            link_local,
            eth_handle,
            timer,
            rtt_window: RttWindow::new(RTT_WINDOW_CAPACITY),
            dns_tx,
            rtt_map: HashMap::with_capacity(len),
            mac_to_ip: HashMap::new(),
        })
    }

    fn process_eth_packet(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        let eth_frame: EthernetPacket = ethernet::get_packet_from_u8(bytes)?;
        let other_mac_addr = eth_frame.get_source();
        if other_mac_addr == self.local_mac {
            return Err(LocalScannerError::SelfSourcedPacket.into());
        }

        let source_addr: IpAddr = protocol::get_ip_addr_from_eth(&eth_frame)?;

        if source_addr.is_ipv4() && !self.ip_set.contains(&source_addr) {
            return Err(LocalScannerError::AddressOutOfRange(source_addr).into());
        }

        let rtt: Option<Duration> = self.calculate_rtt(&eth_frame).unwrap_or_else(|e| {
            error!(verbosity = 1, "Failed to calculate RTT: {e}");
            None
        });

        let primary_ip = *self.mac_to_ip.entry(other_mac_addr).or_insert(source_addr);

        let mut is_new_host: bool = false;
        let mut host = self.ctx.store.entry(primary_ip).or_insert_with(|| {
            self.timer.mark_activity();
            is_new_host = true;
            Host::new(primary_ip).with_mac(other_mac_addr.into_core())
        });

        let mut emit_update = false;

        if let Some(rtt) = rtt {
            info!(
                incoming,
                verbosity = 2,
                "{source_addr} responded in {}ms",
                rtt.as_millis()
            );
            host.add_rtt(rtt);
            self.rtt_window.record(rtt);
            emit_update = true;
        }

        let is_new_ip: bool = host.add_ip(source_addr);
        if is_new_ip {
            emit_update = true;
        }

        if source_addr.is_ipv4() && host.primary_ip().is_ipv6() {
            host.set_primary_ip(source_addr);
            emit_update = true;
        }

        // drop the lock before sending over channel
        drop(host);

        if emit_update || is_new_host {
            let _ = self.ctx.events_tx.send(ScanEvent::HostUpdated(primary_ip));
        }

        if is_new_host || is_new_ip {
            self.dns_tx.as_ref().map(|tx| tx.send(source_addr));
        }

        Ok(())
    }

    fn calculate_rtt(&mut self, eth_frame: &EthernetPacket) -> anyhow::Result<Option<Duration>> {
        match eth_frame.get_ethertype() {
            EtherTypes::Arp => {
                let arp_packet = ArpPacket::new(eth_frame.payload())
                    .ok_or(LocalScannerError::InvalidArpPacket)?;

                let src_addr: IpAddr = IpAddr::V4(arp_packet.get_sender_proto_addr());

                let start_time: Instant = self
                    .rtt_map
                    .remove(&src_addr)
                    .ok_or(LocalScannerError::UnmappedRTTSource(src_addr))?;

                Ok(Some(start_time.elapsed()))
            }

            EtherTypes::Ipv6 => {
                let dst_addr: Ipv6Addr = ip::get_ipv6_dst_addr_from_eth(eth_frame)?;

                if dst_addr.is_unicast_link_local() {
                    let dst_addr: IpAddr = IpAddr::V6(dst_addr);
                    let start_time: &Instant = self
                        .rtt_map
                        .get(&dst_addr)
                        .ok_or(LocalScannerError::UnmappedRTTSource(dst_addr))?;

                    return Ok(Some(start_time.elapsed()));
                }

                Ok(None)
            }

            _ => Ok(None),
        }
    }

    /// Derives how long to wait, right now, for further activity before
    /// concluding the network has gone quiet.
    ///
    /// The value adapts to recently observed round-trip times: a fast,
    /// stable network yields a short tolerance, while a slower or jitterier
    /// one yields a longer one, within fixed safety bounds.
    fn current_silence_tolerance(&self) -> Duration {
        self.rtt_window
            .suggest_timeout(SILENCE_JITTER_MULTIPLIER, SILENCE_FLOOR, SILENCE_CEILING)
    }

    fn should_stop(&self) -> bool {
        let stopped: bool = self.ctx.handle.should_stop();
        let time_expired: bool = self.timer.has_expired(self.current_silence_tolerance());

        stopped || time_expired
    }
}
