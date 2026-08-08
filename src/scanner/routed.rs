// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Routed Host Discovery
//!
//! Finds hosts reached through a gateway rather than ones sitting on the local
//! segment. It sends a single raw TCP SYN packet to each target and listens for
//! any reply. A full three-way handshake is never completed, so this works
//! whether or not the target port is open. [`port_scan`] builds on the same
//! raw-socket machinery to answer a different question: not whether a host is
//! alive, but which of its ports are open.
//!
//! This scanner requires root privileges to open the raw sockets involved.

mod port_scan;
mod udp_scan;

use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

use crate::core::config::SendMode;
use crate::core::models::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::core::models::ip::set::IpSet;
use crate::core::models::timer::ScanBudget;
use crate::core::session::ScanContext;
use crate::network::probe::{ProbeKind, ProbeSender, ProbeTransport};
use crate::protocols as protocol;
use crate::system::interface::RoutedTarget;
use crate::{error, success};
use async_trait::async_trait;
use pnet::packet::tcp::TcpPacket;
use tokio::sync::mpsc::UnboundedSender;

use super::audit::{ProbeAudit, StopReason};
use super::{NetworkExplorer, payload};

pub use port_scan::SynPortScanner;
pub use udp_scan::UdpPortScanner;

/// How long a routed sweep or port scan runs and how it adapts.
///
/// Routed targets sit anywhere on the internet rather than on one segment, so a
/// single scan spans a wide range of round trips and the extremes matter more
/// than the average. Two of these values carry most of that weight:
///
/// - **Silence floor.** The silence tolerance is derived from observed round
///   trips, which the fastest responders dominate - they answer first and pull
///   the estimate toward their own latency, which would end the scan while
///   slower targets are still legitimately in flight. The floor is what bounds
///   that, so it is set against the tail of the round-trip distribution rather
///   than its middle.
/// - **Hard budget.** The base gives a distant target room for several round
///   trips; the per-target term covers the send burst and the spread of
///   arrivals behind it. The ceiling is a backstop against a scan that will not
///   terminate, not a duration any scan is expected to reach.
///
/// The minimum runtime exists so silence is never the reason a scan stops
/// before an answer could plausibly have arrived at all.
///
/// A generous budget costs nothing when a scan succeeds, since both loops exit
/// as soon as every target is resolved ([`RoutedScanner`] once all targets have
/// responded, [`SynPortScanner`] once nothing is pending). It is spent only
/// when something is still missing.
const DEADLINE_CONFIG: AdaptiveDeadlineConfig = AdaptiveDeadlineConfig::new(
    ScanBudget::new(
        Duration::from_millis(2_000),
        Duration::from_millis(1),
        Duration::from_secs(60),
    ),
    ScanBudget::new(
        Duration::from_millis(300),
        Duration::from_micros(500),
        Duration::from_secs(10),
    ),
    Duration::from_millis(400),
    Duration::from_secs(3),
    4.0,
    20,
);

type SeqNum = u32;

/// Sends a single TCP SYN packet from `src_addr` to `dst_addr:dst_port` through
/// `sender` and logs the outcome. On success it returns the randomly chosen
/// sequence number the packet was sent with, so the caller can record it and
/// correlate a later reply.
fn send_syn(
    sender: &dyn ProbeSender,
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

    match sender.send(&packet, src_addr, dst_addr) {
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

/// Sends a single UDP probe from `src_port` to `dst_addr:dst_port` through
/// `sender` and logs the outcome.
///
/// Unlike [`send_syn`], which randomizes its source port per probe, every UDP
/// probe in a scan leaves from the same `src_port`. That single port is the
/// scan's identity on the wire: the capture filter narrows direct replies down
/// to it, and the datagram quoted inside an ICMP error is checked against it.
/// Randomizing per probe would leave no filter expressible but "all UDP".
fn send_udp(
    sender: &dyn ProbeSender,
    src_port: u16,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    dst_port: u16,
) -> Option<()> {
    // What makes an open port answer at all: UDP has no handshake, so the
    // application itself has to recognize the request. See [`payload`].
    let payload = payload::for_port(dst_port).to_vec();

    let packet = match crate::protocols::udp::create_packet(
        &src_addr, &dst_addr, src_port, dst_port, payload,
    ) {
        Ok(pkt) => pkt,
        Err(e) => {
            error!(
                verbosity = 2,
                "Failed to create UDP packet for {dst_addr}:{dst_port}: {e}"
            );
            return None;
        }
    };

    match sender.send(&packet, src_addr, dst_addr) {
        Ok(_) => {
            success!(verbosity = 2, "Sent UDP probe to {dst_addr}:{dst_port}");
            Some(())
        }
        Err(e) => {
            error!(
                verbosity = 2,
                "Failed to send UDP probe to {dst_addr}:{dst_port}: {e}"
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
    /// Transport used to send SYN probes and receive replies.
    transport: ProbeTransport,
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
    /// Per-run counters, so a sweep that finds fewer hosts than it should can be
    /// attributed to loss, to its own deadline, or to correlation rather than
    /// guessed at. Reported once when the loop exits.
    audit: ProbeAudit,
}

#[async_trait]
impl NetworkExplorer for RoutedScanner {
    async fn discover_hosts(mut self: Box<Self>) -> anyhow::Result<()> {
        match self.send_discovery_packets() {
            Ok(_) => success!("Discovery packets sent successfully"),
            Err(e) => error!("Sending discovery packets failed: {e}"),
        }

        // The loop yields why it stopped, so the audit cannot report a reason
        // the code never actually took.
        let reason = loop {
            let all_responded = self.ips.len() == self.responded_count as u128;
            if self.ctx.handle.should_stop() {
                break StopReason::Aborted;
            }
            if all_responded {
                break StopReason::AllResponded;
            }
            if self.deadline.has_expired() {
                break StopReason::DeadlineExpired;
            }

            tokio::select! {
                res = self.transport.rx.recv() => {
                    match res {
                        Some(reply) => {
                            self.audit.record_segment();
                            self.handle_discovery_reply(reply.source, &reply.bytes);
                        }
                        None => break StopReason::StreamClosed,
                    }
                },
                // Wakes periodically so the checks above are re-evaluated even
                // when no further responses arrive.
                _ = tokio::time::sleep(self.deadline.time_until_next_tick()) => {}
            }
        };

        self.audit.report("routed-discovery", self.ips.len(), reason);
        self.rtt_map.clear();
        Ok(())
    }
}

impl RoutedScanner {
    pub fn new(
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        send_mode: SendMode,
    ) -> anyhow::Result<Self> {
        let transport = ProbeTransport::open_with(ProbeKind::TcpSyn, send_mode)?;
        Ok(Self::with_transport(targets, ctx, dns_tx, transport))
    }

    /// Builds a sweep around an already-opened transport, so the caller decides
    /// how probes reach the wire and where replies come from.
    ///
    /// Paired with a synthetic transport (`ProbeTransport::from_parts`, behind
    /// the `test-support` feature) this is the seam that lets liveness
    /// detection and RTT correlation be driven against a simulated network
    /// rather than a real one.
    pub fn with_transport(
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        transport: ProbeTransport,
    ) -> Self {
        let mut ips = IpSet::new();
        for target in &targets {
            ips.insert(target.target);
        }
        ips.canonicalize();

        let deadline = AdaptiveDeadline::new(DEADLINE_CONFIG, targets.len());

        Self {
            ctx,
            targets,
            ips,
            transport,
            deadline,
            dns_tx,
            rtt_map: HashMap::new(),
            responded_count: 0,
            audit: ProbeAudit::new(),
        }
    }

    /// Records a raw TCP reply from `ip` as evidence the host is alive,
    /// crediting it with a round-trip time if the reply's acknowledgement
    /// number matches an outstanding probe.
    fn handle_discovery_reply(&mut self, ip: IpAddr, bytes: &[u8]) {
        if !self.ips.contains(&ip) {
            self.audit.record_off_target();
            return;
        }

        let rtt = self.correlate_rtt(ip, bytes);
        if rtt.is_none() {
            self.audit.record_reply_without_rtt();
        }

        // Host mutation only; the guard is dropped and the event emitted inside
        // `write_host`, so the deadline and DNS follow-ups below never run under
        // the store lock.
        let is_new = self.ctx.write_host(ip, |host| {
            if let Some(rtt) = rtt {
                host.add_rtt(rtt);
                return true;
            }
            false
        });

        if is_new {
            self.responded_count += 1;
            self.audit.record_host_found();
            self.deadline.mark_activity();
            if let Some(dns) = &self.dns_tx {
                let _ = dns.send(ip);
            }
        }

        if let Some(rtt) = rtt {
            self.deadline.record_rtt(rtt);
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
        let seq_num = send_syn(self.transport.tx.as_ref(), src_addr, dst_addr, dst_port);
        self.audit.record_send(seq_num.is_some());

        if let Some(seq_num) = seq_num {
            self.rtt_map.insert((dst_addr, seq_num), Instant::now());
        }
    }
}
