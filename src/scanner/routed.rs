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

use crate::core::models::rtt_window::RttWindow;
use crate::core::models::timer::{ScanBudget, ScanTimer};
use crate::core::models::{host::Host, ip::set::IpSet};
use crate::core::session::{ScanContext, ScanEvent};
use crate::network::transport::{self, TransportHandle, TransportType};
use crate::protocols as protocol;
use crate::{error, success};
use async_trait::async_trait;
use pnet::{datalink::NetworkInterface, packet::tcp::TcpPacket};
use tokio::sync::mpsc::UnboundedSender;

use super::NetworkExplorer;

#[derive(Debug, thiserror::Error)]
pub enum RoutedScannerError {
    #[error("interface has no ipv4 or ipv6 address")]
    NoInterfaceIp,
    #[error("interface has no ipv4 address")]
    NoIpv4Address,
    #[error("interface has no ipv6 address")]
    NoIpv6Address,
}

/// The overall time budget for one scan, before accounting for its target
/// count. Routed targets may sit anywhere on the internet rather than on the
/// local segment, but a probe that was ever going to get a reply typically
/// does so quickly, so this starts noticeably tighter than a local-network scan.
const MAX_SCAN_BUDGET: ScanBudget = ScanBudget::new(
    Duration::from_millis(200),
    Duration::from_micros(500),
    Duration::from_millis(3_000),
);

/// The minimum time a scan must run before it is allowed to end early due to
/// silence, scaled the same way as [`MAX_SCAN_BUDGET`].
const MIN_SCAN_BUDGET: ScanBudget = ScanBudget::new(
    Duration::from_millis(70),
    Duration::from_micros(175),
    Duration::from_millis(1_000),
);

/// The bounds within which the silence tolerance is allowed to adapt, and
/// how many recent samples inform that adaptation. See [`RttWindow`] for how
/// the tolerance itself is derived from observed round-trip times.
const SILENCE_FLOOR: Duration = Duration::from_millis(150);
const SILENCE_CEILING: Duration = Duration::from_millis(1_500);
const SILENCE_JITTER_MULTIPLIER: f64 = 4.0;
const RTT_WINDOW_CAPACITY: usize = 20;

type SeqNum = u32;

pub struct RoutedScanner {
    src_v4: Option<Ipv4Addr>,
    src_v6: Option<Ipv6Addr>,
    ctx: ScanContext,
    ips: IpSet,
    tcp_handle: TransportHandle,
    timer: ScanTimer,
    /// Recent round-trip times observed from any responding host, used to
    /// adapt how long the scan waits before concluding the network has gone
    /// quiet. See [`RoutedScanner::current_silence_tolerance`].
    rtt_window: RttWindow,
    dns_tx: Option<UnboundedSender<IpAddr>>,
    rtt_map: HashMap<(IpAddr, SeqNum), Instant>,
    responded_count: usize,
}

#[async_trait]
impl NetworkExplorer for RoutedScanner {
    async fn discover_hosts(&mut self) -> anyhow::Result<()> {
        match self.send_discovery_packets() {
            Ok(_) => success!("Discovery packets sent successfully"),
            Err(e) => error!("Sending discovery packets failed: {e}"),
        }

        loop {
            let all_responded = self.ips.len() == self.responded_count as u128;
            let silence = self.current_silence_tolerance();
            if self.ctx.handle.should_stop() || all_responded || self.timer.has_expired(silence) {
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
                            let mut host = self.ctx.store.entry(ip).or_insert_with(|| {
                                is_new = true;
                                Host::new(ip)
                            });

                            if is_new {
                                self.responded_count += 1;
                                self.timer.mark_activity();
                                let _ = self.dns_tx.as_ref().map(|dns| dns.send(ip));
                            }

                            let mut emit_update = false;

                            if let Some(tcp_packet) = TcpPacket::new(&bytes) {
                                let ack_num: u32 = tcp_packet.get_acknowledgement();
                                let original_seq: u32 = ack_num.wrapping_sub(1);

                                if let Some(start_time) = self.rtt_map.remove(&(ip, original_seq)) {
                                    let rtt: Duration = start_time.elapsed();
                                    host.add_rtt(rtt);
                                    self.rtt_window.record(rtt);
                                    emit_update = true;
                                }
                            }

                            drop(host);

                            if is_new || emit_update {
                                let _ = self.ctx.events_tx.send(ScanEvent::HostUpdated(ip));
                            }
                        },
                        None => break,
                    }
                },
                // Wakes periodically so the checks above are re-evaluated even
                // when no further responses arrive.
                _ = tokio::time::sleep(self.timer.time_until_next_tick(silence)) => {}
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
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
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

        if src_v4.is_none() && src_v6.is_none() {
            return Err(RoutedScannerError::NoInterfaceIp.into());
        }

        let target_count = ips.len() as usize;
        let timer = ScanTimer::new(
            MAX_SCAN_BUDGET.for_target_count(target_count),
            MIN_SCAN_BUDGET.for_target_count(target_count),
        );

        Ok(Self {
            src_v4,
            src_v6,
            ctx,
            ips,
            tcp_handle,
            timer,
            rtt_window: RttWindow::new(RTT_WINDOW_CAPACITY),
            dns_tx,
            rtt_map: HashMap::new(),
            responded_count: 0,
        })
    }

    /// Derives how long to wait, right now, for further responses before
    /// concluding no more hosts will answer.
    ///
    /// The value adapts to recently observed round-trip times: a fast,
    /// stable path yields a short tolerance, while a slower or jitterier one
    /// yields a longer one, within fixed safety bounds.
    fn current_silence_tolerance(&self) -> Duration {
        self.rtt_window
            .suggest_timeout(SILENCE_JITTER_MULTIPLIER, SILENCE_FLOOR, SILENCE_CEILING)
    }

    fn send_discovery_packets(&mut self) -> anyhow::Result<()> {
        let dst_port: u16 = 443;

        let src_v4 = self.src_v4.ok_or(RoutedScannerError::NoIpv4Address)?;
        let src_v6 = self.src_v6.ok_or(RoutedScannerError::NoIpv6Address)?;

        let targets: Vec<IpAddr> = self.ips.iter().collect();

        for dst_addr in targets {
            let src_addr = match dst_addr {
                IpAddr::V4(_) => IpAddr::V4(src_v4),
                IpAddr::V6(_) => IpAddr::V6(src_v6),
            };
            self.send_tcp_packet(&src_addr, &dst_addr, dst_port);
        }

        Ok(())
    }

    fn send_tcp_packet(&mut self, src_addr: &IpAddr, dst_addr: &IpAddr, dst_port: u16) {
        let src_port: u16 = rand::random_range(50_000..u16::MAX);
        let seq_num: u32 = rand::random_range(0..=u32::MAX);
        let packet =
            match protocol::tcp::create_packet(src_addr, dst_addr, src_port, dst_port, seq_num) {
                Ok(pkt) => pkt,
                Err(e) => {
                    error!(
                        verbosity = 2,
                        "Failed to create TCP packet for {dst_addr}:{dst_port}: {e}"
                    );
                    return;
                }
            };

        match TcpPacket::new(&packet) {
            None => {}
            Some(packet) => {
                let mut tx = self.tcp_handle.tx.lock().unwrap();
                match tx.send_to(packet, *dst_addr) {
                    Ok(_) => {
                        success!(verbosity = 2, "Sent TCP packet to {dst_addr}:{dst_port}");
                        self.rtt_map.insert((*dst_addr, seq_num), Instant::now());
                    }
                    Err(e) => error!(
                        verbosity = 2,
                        "Failed to send packet to {dst_addr}:{dst_port}: {e}"
                    ),
                }
            }
        }
    }
}
