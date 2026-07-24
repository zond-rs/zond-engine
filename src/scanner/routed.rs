// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Routed Host Discovery
//!
//! Finds hosts reached through a gateway rather than sitting on the local
//! segment, by sending a single raw TCP SYN packet to each target and
//! listening for any reply - a full three-way handshake is never
//! completed, so this works whether the target port is actually open or
//! not. [`port_scan`] builds on the same raw-socket machinery to answer a
//! different question: not just whether a host is alive, but which of its
//! ports are open.
//!
//! This scanner requires root privileges to open the raw sockets involved.

mod port_scan;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use crate::core::models::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::core::models::timer::ScanBudget;
use crate::core::models::{host::Host, ip::set::IpSet};
use crate::core::session::{ScanContext, ScanEvent};
use crate::network::transport::{self, TransportHandle, TransportType};
use crate::protocols as protocol;
use crate::{error, success};
use async_trait::async_trait;
use pnet::{datalink::NetworkInterface, packet::tcp::TcpPacket};
use tokio::sync::mpsc::UnboundedSender;

use super::NetworkExplorer;

pub use port_scan::SynPortScanner;

#[derive(Debug, thiserror::Error)]
pub enum RoutedScannerError {
    #[error("interface has no ipv4 or ipv6 address")]
    NoInterfaceIp,
    #[error("interface has no ipv4 address")]
    NoIpv4Address,
    #[error("interface has no ipv6 address")]
    NoIpv6Address,
}

/// How long a discovery sweep runs, and how it adapts. Routed targets may
/// sit anywhere on the internet rather than on the local segment, but a
/// probe that was ever going to get a reply typically does so quickly, so
/// this starts noticeably tighter than
/// [`LocalScanner`](super::local::LocalScanner)'s budget.
const DEADLINE_CONFIG: AdaptiveDeadlineConfig = AdaptiveDeadlineConfig::new(
    ScanBudget::new(
        Duration::from_millis(200),
        Duration::from_micros(500),
        Duration::from_millis(3_000),
    ),
    ScanBudget::new(
        Duration::from_millis(70),
        Duration::from_micros(175),
        Duration::from_millis(1_000),
    ),
    Duration::from_millis(150),
    Duration::from_millis(1_500),
    4.0,
    20,
);

type SeqNum = u32;

/// The addressing identity a raw TCP scanner uses when crafting outbound
/// packets, resolved once at construction time and never changed
/// afterward.
struct RoutedSourceIdentity {
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
}

impl RoutedSourceIdentity {
    /// Picks the addresses to present as this scanner's own from whatever
    /// `intf` has assigned. Fails only if the interface has neither an
    /// IPv4 nor an IPv6 address to probe with.
    fn resolve(intf: &NetworkInterface) -> Result<Self, RoutedScannerError> {
        let v4 = intf.ips.iter().find_map(|ip_net| match ip_net.ip() {
            IpAddr::V4(ipv4) => Some(ipv4),
            _ => None,
        });

        let v6 = intf.ips.iter().find_map(|ip_net| match ip_net.ip() {
            IpAddr::V6(ipv6) => Some(ipv6),
            _ => None,
        });

        if v4.is_none() && v6.is_none() {
            return Err(RoutedScannerError::NoInterfaceIp);
        }

        Ok(Self { v4, v6 })
    }
}

/// Sends a single TCP SYN packet from `src_addr` to `dst_addr:dst_port` and
/// logs the outcome. Returns the randomly chosen sequence number it was
/// sent with on success, so the caller can record it for correlating a
/// later reply.
fn send_syn(
    tcp_handle: &TransportHandle,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    dst_port: u16,
) -> Option<SeqNum> {
    let src_port: u16 = rand::random_range(50_000..u16::MAX);
    let seq_num: u32 = rand::random_range(0..=u32::MAX);

    let packet =
        match protocol::tcp::create_packet(&src_addr, &dst_addr, src_port, dst_port, seq_num) {
            Ok(pkt) => pkt,
            Err(e) => {
                error!(
                    verbosity = 2,
                    "Failed to create SYN packet for {dst_addr}:{dst_port}: {e}"
                );
                return None;
            }
        };

    let tcp_packet = TcpPacket::new(&packet)?;

    match tcp_handle.tx.send_to(tcp_packet, dst_addr) {
        Ok(_) => {
            success!(verbosity = 2, "Sent SYN probe to {dst_addr}:{dst_port}");
            Some(seq_num)
        }
        Err(e) => {
            error!(
                verbosity = 2,
                "Failed to send SYN probe to {dst_addr}:{dst_port}: {e}"
            );
            None
        }
    }
}

pub struct RoutedScanner {
    /// The address this scanner presents as its own when probing.
    identity: RoutedSourceIdentity,
    /// Shared state (host store, event channel, abort signal) for the scan
    /// this explorer is part of.
    ctx: ScanContext,
    /// The addresses being probed for aliveness.
    ips: IpSet,
    /// Raw socket used to send SYN probes and receive replies.
    tcp_handle: TransportHandle,
    /// Governs how long this sweep keeps running, adapting to observed
    /// round-trip times.
    deadline: AdaptiveDeadline,
    /// Where to forward newly discovered addresses for hostname
    /// resolution, if enabled.
    dns_tx: Option<UnboundedSender<IpAddr>>,
    /// Outstanding probes, keyed by destination and the sequence number
    /// they were sent with.
    rtt_map: HashMap<(IpAddr, SeqNum), Instant>,
    /// How many distinct addresses have responded so far.
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
            if self.ctx.handle.should_stop() || all_responded || self.deadline.has_expired() {
                break;
            }

            tokio::select! {
                res = self.tcp_handle.rx.recv() => {
                    match res {
                        Some((bytes, ip)) => self.handle_discovery_reply(ip, &bytes),
                        None => break,
                    }
                },
                // Wakes periodically so the checks above are re-evaluated even
                // when no further responses arrive.
                _ = tokio::time::sleep(self.deadline.time_until_next_tick()) => {}
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
        let identity = RoutedSourceIdentity::resolve(&intf)?;
        let tcp_handle: TransportHandle =
            transport::start_packet_capture(TransportType::TcpLayer4)?;

        let target_count = ips.len() as usize;
        let deadline = AdaptiveDeadline::new(DEADLINE_CONFIG, target_count);

        Ok(Self {
            identity,
            ctx,
            ips,
            tcp_handle,
            deadline,
            dns_tx,
            rtt_map: HashMap::new(),
            responded_count: 0,
        })
    }

    /// Records a raw TCP reply from `ip` as evidence the host is alive,
    /// crediting it with a round-trip time if the reply's acknowledgement
    /// number matches an outstanding probe.
    fn handle_discovery_reply(&mut self, ip: IpAddr, bytes: &[u8]) {
        if !self.ips.contains(&ip) {
            return;
        }

        let rtt = self.correlate_rtt(ip, bytes);

        let mut is_new = false;
        let mut host = self.ctx.store.entry(ip).or_insert_with(|| {
            is_new = true;
            Host::new(ip)
        });

        if is_new {
            self.responded_count += 1;
            self.deadline.mark_activity();
            let _ = self.dns_tx.as_ref().map(|dns| dns.send(ip));
        }

        let mut emit_update = false;

        if let Some(rtt) = rtt {
            host.add_rtt(rtt);
            self.deadline.record_rtt(rtt);
            emit_update = true;
        }

        drop(host);

        if is_new || emit_update {
            let _ = self.ctx.events_tx.send(ScanEvent::HostUpdated(ip));
        }
    }

    /// Matches a reply's acknowledgement number against the sequence
    /// number an earlier probe to `ip` was sent with, returning the
    /// elapsed time since that probe if they correspond.
    fn correlate_rtt(&mut self, ip: IpAddr, bytes: &[u8]) -> Option<Duration> {
        let tcp_packet = TcpPacket::new(bytes)?;
        let original_seq = tcp_packet.get_acknowledgement().wrapping_sub(1);
        let sent_at = self.rtt_map.remove(&(ip, original_seq))?;
        Some(sent_at.elapsed())
    }

    fn send_discovery_packets(&mut self) -> anyhow::Result<()> {
        let dst_port: u16 = 443;

        let src_v4 = self.identity.v4.ok_or(RoutedScannerError::NoIpv4Address)?;
        let src_v6 = self.identity.v6.ok_or(RoutedScannerError::NoIpv6Address)?;

        let targets: Vec<IpAddr> = self.ips.iter().collect();

        for dst_addr in targets {
            let src_addr = match dst_addr {
                IpAddr::V4(_) => IpAddr::V4(src_v4),
                IpAddr::V6(_) => IpAddr::V6(src_v6),
            };
            self.send_tcp_packet(src_addr, dst_addr, dst_port);
        }

        Ok(())
    }

    fn send_tcp_packet(&mut self, src_addr: IpAddr, dst_addr: IpAddr, dst_port: u16) {
        if let Some(seq_num) = send_syn(&self.tcp_handle, src_addr, dst_addr, dst_port) {
            self.rtt_map.insert((dst_addr, seq_num), Instant::now());
        }
    }
}
