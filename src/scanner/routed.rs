// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use crate::core::handle::ScanHandle;
use crate::core::models::{host::Host, ip::set::IpSet};
use crate::protocols as protocol;
use crate::core::session::ScanEvent;
use crate::{error, success};
use anyhow::ensure;
use async_trait::async_trait;
use dashmap::DashMap;
use pnet::{datalink::NetworkInterface, packet::tcp::TcpPacket};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;

use crate::network::transport::{self, TransportHandle, TransportType};

use super::NetworkExplorer;

// this shit needs improvement
const MIN_SCAN_DURATION: Duration = Duration::from_millis(200);
const MAX_SCAN_DURATION: Duration = Duration::from_millis(3000);
const MS_PER_IP: f64 = 0.5;

type SeqNum = u32;

pub struct RoutedScanner {
    src_v4: Option<Ipv4Addr>,
    src_v6: Option<Ipv6Addr>,
    store: Arc<DashMap<IpAddr, Host>>,
    events_tx: UnboundedSender<ScanEvent>,
    ips: IpSet,
    scan_handle: ScanHandle,
    tcp_handle: TransportHandle,
    dns_tx: Option<UnboundedSender<IpAddr>>,
    rtt_map: HashMap<(IpAddr, SeqNum), Instant>,
    responded_count: usize,
}

#[async_trait]
impl NetworkExplorer for RoutedScanner {
    async fn discover_hosts(&mut self) -> anyhow::Result<()> {
        if let Err(e) = self.send_discovery_packets() {
            error!("Failed to send packets: {e}");
        }

        let deadline: Instant = calculate_deadline(self.ips.len() as usize);

        loop {
            let all_responded = self.ips.len() == self.responded_count as u128;
            if self.scan_handle.should_stop() || all_responded {
                break;
            }

            let remaining: Duration = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            tokio::select! {
                res = self.tcp_handle.rx.recv() => {
                    match res {
                        Some((bytes, ip)) => {
                            if !self.ips.contains(&ip) {
                                continue;
                            }

                            let mut is_new = false;
                            let mut host = self.store.entry(ip).or_insert_with(|| {
                                is_new = true;
                                Host::new(ip)
                            });

                            if is_new {
                                self.responded_count += 1;
                                let _ = self.dns_tx.as_ref().map(|dns| dns.send(ip));
                            }

                            let mut emit_update = false;

                            if let Some(tcp_packet) = TcpPacket::new(&bytes) {
                                let ack_num: u32 = tcp_packet.get_acknowledgement();
                                let original_seq: u32 = ack_num.wrapping_sub(1);

                                if let Some(start_time) = self.rtt_map.remove(&(ip, original_seq)) {
                                    let rtt: Duration = start_time.elapsed();
                                    host.add_rtt(rtt);
                                    emit_update = true;
                                }
                            }

                            drop(host);

                            if is_new || emit_update {
                                let _ = self.events_tx.send(ScanEvent::HostUpdated(ip));
                            }
                        },
                        None => break,
                    }
                },
                _ = tokio::time::sleep(remaining) => {
                    break;
                }
            }
        }

        self.rtt_map.clear();
        Ok(())
    }
}

impl RoutedScanner {
    pub fn new(
        intf: NetworkInterface,
        ips: IpSet,
        scan_handle: ScanHandle,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        store: Arc<DashMap<IpAddr, Host>>,
        events_tx: UnboundedSender<ScanEvent>,
    ) -> anyhow::Result<Self> {
        let tcp_handle: TransportHandle =
            transport::start_packet_capture(TransportType::TcpLayer4)?;

        let src_v4: Option<Ipv4Addr> = intf.ips.iter().find_map(|ip_net| match ip_net.ip() {
            IpAddr::V4(ipv4) => Some(ipv4),
            _ => None,
        });

        let src_v6: Option<Ipv6Addr> = intf.ips.iter().find_map(|ip_net| match ip_net.ip() {
            IpAddr::V6(ipv6) => Some(ipv6),
            _ => None,
        });

        ensure!(
            src_v4.is_some() || src_v6.is_some(),
            "interface has no ip addresses"
        );

        Ok(Self {
            src_v4,
            src_v6,
            store,
            events_tx,
            ips,
            scan_handle,
            tcp_handle,
            dns_tx,
            rtt_map: HashMap::new(),
            responded_count: 0,
        })
    }

    fn send_discovery_packets(&mut self) -> anyhow::Result<()> {
        let src_port: u16 = rand::random_range(50_000..u16::MAX);
        let dst_port: u16 = 443;
        for dst_addr in self.ips.iter() {
            let src_addr: IpAddr = match dst_addr {
                IpAddr::V4(_) => {
                    ensure!(self.src_v4.is_some(), "interface has no ipv4 address");
                    IpAddr::V4(self.src_v4.unwrap())
                }
                IpAddr::V6(_) => {
                    ensure!(self.src_v6.is_some(), "interface has no ipv6 address");
                    IpAddr::V6(self.src_v6.unwrap())
                }
            };

            let seq_num: u32 = rand::random_range(0..=u32::MAX);
            let packet: Vec<u8> =
                protocol::tcp::create_packet(&src_addr, &dst_addr, src_port, dst_port, seq_num)?;

            if let Some(packet) = TcpPacket::new(&packet) {
                let mut tx = self.tcp_handle.tx.lock().unwrap();
                match tx.send_to(packet, dst_addr) {
                    Ok(_) => {
                        success!(verbosity = 2, "Sent discovery packet to {dst_addr}");
                        self.rtt_map.insert((dst_addr, seq_num), Instant::now());
                    }
                    Err(e) => error!(verbosity = 2, "Failed to send packet to {dst_addr}: {e}"),
                }
            }
        }
        Ok(())
    }
}

fn calculate_deadline(ips_len: usize) -> Instant {
    let variable_ms = (ips_len as f64 * MS_PER_IP) as u64;

    let scan_duration = (MIN_SCAN_DURATION + Duration::from_millis(variable_ms))
        .clamp(MIN_SCAN_DURATION, MAX_SCAN_DURATION);

    Instant::now() + scan_duration
}
