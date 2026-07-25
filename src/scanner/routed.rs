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
    net::IpAddr,
    time::{Duration, Instant},
};

use crate::core::models::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::core::models::timer::ScanBudget;
use crate::core::models::{host::Host, ip::set::IpSet};
use crate::core::session::{ScanContext, ScanEvent};
use crate::network::transport::{self, TransportHandle, TransportType};
use crate::protocols as protocol;
use crate::system::interface::RoutedTarget;
use crate::{error, success};
use async_trait::async_trait;
use pnet::packet::tcp::TcpPacket;
use tokio::sync::mpsc::UnboundedSender;

use super::NetworkExplorer;

pub use port_scan::SynPortScanner;

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
    /// Shared state (host store, event channel, abort signal) for the scan
    /// this explorer is part of.
    ctx: ScanContext,
    /// The targets to probe, each paired with the source address to send from.
    /// Drained when the probes are sent.
    targets: Vec<RoutedTarget>,
    /// Membership-and-count view of `targets`, used to filter incoming replies
    /// and to size the adaptive deadline.
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
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
    ) -> anyhow::Result<Self> {
        let tcp_handle: TransportHandle =
            transport::start_packet_capture(TransportType::TcpLayer4)?;

        let mut ips = IpSet::new();
        for target in &targets {
            ips.insert(target.target);
        }
        ips.canonicalize();

        let deadline = AdaptiveDeadline::new(DEADLINE_CONFIG, targets.len());

        Ok(Self {
            ctx,
            targets,
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

        // Taken so the send loop can mutate `self` while iterating them.
        let targets = std::mem::take(&mut self.targets);

        for RoutedTarget { target, source } in targets {
            self.send_tcp_packet(source, target, dst_port);
        }

        Ok(())
    }

    fn send_tcp_packet(&mut self, src_addr: IpAddr, dst_addr: IpAddr, dst_port: u16) {
        if let Some(seq_num) = send_syn(&self.tcp_handle, src_addr, dst_addr, dst_port) {
            self.rtt_map.insert((dst_addr, seq_num), Instant::now());
        }
    }
}
