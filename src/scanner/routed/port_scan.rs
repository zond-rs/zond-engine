// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # SYN Port Probing
//!
//! Implements the privileged half of [`crate::scanner::scan`]: probing
//! specific `(address, port)` pairs with raw TCP SYN packets and
//! classifying each one by how - or whether - it responds, rather than
//! completing a full TCP handshake per port the way the unprivileged
//! fallback in [`crate::scanner::connect`] has to.
//!
//! A SYN+ACK means the port is open; a RST means it's closed; silence
//! until the scan's deadline means it's filtered - most likely a firewall
//! dropping the probe rather than responding to it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use pnet::packet::tcp::TcpPacket;
use tokio::sync::mpsc;

use crate::core::models::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::core::models::host::Host;
use crate::core::models::port::{Port, PortState, Protocol, Service};
use crate::core::models::target::Target;
use crate::core::models::timer::ScanBudget;
use crate::core::session::{ScanContext, ScanEvent};
use crate::error;
use crate::network::probe::{ProbeKind, ProbeTransport};
use crate::protocols::tcp::{self, ProbeResponse};
use crate::system::interface::SourceResolver;

use super::{SeqNum, send_syn};

/// How long a port scan runs, and how it adapts. Uses the same bounds as
/// [`super::DEADLINE_CONFIG`], since both send raw TCP SYN probes over the
/// same kind of network path.
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

/// Outstanding probes, keyed by the target they were sent to, recording the
/// sequence number they were sent with and when.
type PendingProbes = HashMap<(IpAddr, u16), (SeqNum, Instant)>;

/// Probes specific `(address, port)` pairs with raw TCP SYN packets.
///
/// Unlike [`RoutedScanner`](super::RoutedScanner), which sends one SYN per
/// host purely to check for a pulse, this sends one per `(address, port)`
/// pair it's given and reports back what each one revealed.
pub struct SynPortScanner {
    /// Resolves, per target, the source address to send its probe from -
    /// consulting on-link subnets and the kernel routing table, and caching
    /// each answer so the many ports probed on one host cost a single lookup.
    resolver: SourceResolver,
    /// Shared state (host store, event channel, abort signal) for the scan
    /// this prober is part of.
    ctx: ScanContext,
    /// Transport used to send SYN probes and receive replies.
    transport: ProbeTransport,
    /// Governs how long this scan keeps running, adapting to observed
    /// round-trip times.
    deadline: AdaptiveDeadline,
    /// Probes sent but not yet resolved into an open/closed classification.
    pending: PendingProbes,
}

impl SynPortScanner {
    /// Builds a scanner that selects each probe's source via `resolver`, sized
    /// for a scan covering `target_count` `(address, port)` pairs.
    pub fn new(
        resolver: SourceResolver,
        ctx: ScanContext,
        target_count: usize,
    ) -> anyhow::Result<Self> {
        let transport = ProbeTransport::open(ProbeKind::TcpSyn)?;
        let deadline = AdaptiveDeadline::new(DEADLINE_CONFIG, target_count);

        Ok(Self {
            resolver,
            ctx,
            transport,
            deadline,
            pending: PendingProbes::new(),
        })
    }

    /// Consumes `targets`, sending a SYN probe for each TCP one - this
    /// scanner doesn't support UDP or SCTP yet, so those are skipped - and
    /// classifying every reply, until every probe has been resolved or the
    /// scan's deadline expires. Anything still outstanding at that point is
    /// reported as filtered.
    pub async fn scan(&mut self, mut targets: mpsc::Receiver<Target>) -> anyhow::Result<()> {
        let mut sending_finished = false;

        loop {
            if self.ctx.handle.should_stop() || self.deadline.has_expired() {
                break;
            }
            if sending_finished && self.pending.is_empty() {
                break;
            }

            tokio::select! {
                target = targets.recv(), if !sending_finished => {
                    match target {
                        Some(target) => self.send_probe(target),
                        None => sending_finished = true,
                    }
                }

                res = self.transport.rx.recv() => {
                    match res {
                        Some((bytes, ip)) => self.handle_reply(ip, &bytes),
                        None => break,
                    }
                }

                // Wakes periodically so the checks above are re-evaluated
                // even when no further replies arrive.
                _ = tokio::time::sleep(self.deadline.time_until_next_tick()) => {}
            }
        }

        self.resolve_remaining_as_filtered();
        Ok(())
    }

    fn send_probe(&mut self, target: Target) {
        if target.protocol != Protocol::Tcp {
            return;
        }

        let Some(src_addr) = self.resolver.resolve(target.ip) else {
            error!(
                verbosity = 2,
                "No route to {}; skipping {}:{}", target.ip, target.ip, target.port
            );
            return;
        };

        if let Some(seq_num) = send_syn(self.transport.tx.as_ref(), src_addr, target.ip, target.port)
        {
            self.pending
                .insert((target.ip, target.port), (seq_num, Instant::now()));
        }
    }

    /// Matches a reply against an outstanding probe and, if it is one,
    /// classifies it and records the port's state.
    fn handle_reply(&mut self, ip: IpAddr, bytes: &[u8]) {
        let Some(tcp_packet) = TcpPacket::new(bytes) else {
            return;
        };

        let key = (ip, tcp_packet.get_source());
        let Some(&(sent_seq, sent_at)) = self.pending.get(&key) else {
            return;
        };

        // Guards against stray or spoofed packets being mistaken for a reply.
        if tcp_packet.get_acknowledgement().wrapping_sub(1) != sent_seq {
            return;
        }

        let Some(response) = tcp::classify_probe_response(&tcp_packet) else {
            return;
        };

        self.pending.remove(&key);
        self.deadline.mark_activity();
        self.deadline.record_rtt(sent_at.elapsed());

        let state = match response {
            ProbeResponse::Open => PortState::Open,
            ProbeResponse::Closed => PortState::Closed,
        };
        self.record_port(ip, key.1, state);
    }

    /// Marks every probe still outstanding once the scan winds down as
    /// filtered: no SYN+ACK, no RST, nothing - the most common signature of
    /// a firewall silently dropping the packet rather than answering it.
    fn resolve_remaining_as_filtered(&mut self) {
        let remaining: Vec<(IpAddr, u16)> = self.pending.drain().map(|(key, _)| key).collect();
        for (ip, port) in remaining {
            self.record_port(ip, port, PortState::Filtered);
        }
    }

    fn record_port(&mut self, ip: IpAddr, port_num: u16, state: PortState) {
        let mut port = Port::new(port_num, Protocol::Tcp, state);
        let service_name = crate::fingerprinting::lookup_service_name(port_num, Protocol::Tcp)
            .unwrap_or("???".to_string());
        port.set_service(Service::new(service_name, 0));

        let mut host = self.ctx.store.entry(ip).or_insert_with(|| Host::new(ip));
        host.add_port(port);
        drop(host);

        let _ = self.ctx.events_tx.send(ScanEvent::HostUpdated(ip));
    }
}
