// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # SYN Port Probing
//!
//! Implements the privileged half of [`crate::scanner::scan`]. It probes
//! specific `(address, port)` pairs with raw TCP SYN packets and classifies each
//! one by whether and how it responds, rather than completing a full TCP
//! handshake per port the way the unprivileged fallback in
//! [`crate::scanner::connect`] must.
//!
//! A SYN+ACK means the port is open, a RST means it is closed, and silence until
//! the scan's deadline means it is filtered, most likely by a firewall dropping
//! the probe rather than answering it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use async_trait::async_trait;
use pnet::packet::tcp::TcpPacket;
use tokio::sync::mpsc;

use crate::core::config::SendMode;
use crate::core::models::deadline::AdaptiveDeadline;
use crate::core::models::port::{PortState, Protocol};
use crate::core::models::target::Target;
use crate::core::session::{ScanContext, ScannerKind};
use crate::error;
use crate::network::probe::{ProbeKind, ProbeTransport};
use crate::protocols::tcp::{self, ProbeResponse};
use crate::scanner::{PortScanner, service};
use crate::system::interface::SourceResolver;

// Port scanning and routed discovery send the same kind of raw TCP SYN over the
// same kind of network path, so they share one adaptive-deadline profile rather
// than keeping two copies in step.
use super::{DEADLINE_CONFIG, SeqNum, send_syn};

/// Outstanding probes, keyed by the target they were sent to, recording the
/// sequence number they were sent with and when.
type PendingProbes = HashMap<(IpAddr, u16), (SeqNum, Instant)>;

/// Probes specific `(address, port)` pairs with raw TCP SYN packets.
///
/// Unlike [`RoutedScanner`](super::RoutedScanner), which sends one SYN per host
/// purely to check for a pulse, this sends one per `(address, port)` pair it is
/// given and reports what each one revealed.
pub struct SynPortScanner {
    /// Resolves the source address to send each target's probe from, consulting
    /// on-link subnets and the kernel routing table. Each answer is cached, so
    /// the many ports probed on one host cost a single lookup.
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
        send_mode: SendMode,
    ) -> anyhow::Result<Self> {
        let transport = ProbeTransport::open_with(ProbeKind::TcpSyn, send_mode)?;
        let deadline = AdaptiveDeadline::new(DEADLINE_CONFIG, target_count);

        Ok(Self {
            resolver,
            ctx,
            transport,
            deadline,
            pending: PendingProbes::new(),
        })
    }

    /// Builds a scanner around an already-constructed transport, opening no
    /// sockets. This is the seam that lets tests drive probe and reply
    /// correlation with a mock sender and synthesized replies.
    #[cfg(test)]
    pub(crate) fn with_transport(
        resolver: SourceResolver,
        ctx: ScanContext,
        transport: ProbeTransport,
        target_count: usize,
    ) -> Self {
        Self {
            resolver,
            ctx,
            transport,
            deadline: AdaptiveDeadline::new(DEADLINE_CONFIG, target_count),
            pending: PendingProbes::new(),
        }
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

        if let Some(seq_num) =
            send_syn(self.transport.tx.as_ref(), src_addr, target.ip, target.port)
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

    /// Marks every probe still outstanding once the scan winds down as filtered.
    /// No SYN+ACK and no RST ever arrived, which is the most common signature of
    /// a firewall silently dropping the packet rather than answering it.
    fn resolve_remaining_as_filtered(&mut self) {
        let remaining: Vec<(IpAddr, u16)> = self.pending.drain().map(|(key, _)| key).collect();
        for (ip, port) in remaining {
            self.record_port(ip, port, PortState::Filtered);
        }
    }

    fn record_port(&mut self, ip: IpAddr, port_num: u16, state: PortState) {
        let port = crate::fingerprinting::baseline_port(port_num, Protocol::Tcp, state);
        self.ctx.update_host(ip, |host| host.add_port(port));
    }
}

#[async_trait]
impl PortScanner for SynPortScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::SynPort
    }

    /// Consumes `targets`, sending a SYN probe for each TCP one and classifying
    /// every reply, until each probe has been resolved or the scan's deadline
    /// expires. UDP and SCTP targets are skipped, since this scanner does not
    /// support them yet. Anything still outstanding when the loop ends is
    /// reported as filtered.
    async fn scan(&mut self, mut targets: mpsc::Receiver<Target>) -> anyhow::Result<()> {
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

    /// Fingerprints every open port the SYN pass found. The raw exchange that
    /// classified each port never opened a connection, so this second pass makes
    /// one per open port and runs the shared fingerprint engine over it.
    async fn detect_services(&mut self, ctx: &ScanContext) {
        service::detect(ctx).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use pnet::ipnetwork::{IpNetwork, Ipv4Network};
    use pnet::packet::tcp::MutableTcpPacket;

    use crate::core::session::ScanSession;
    use crate::network::capture::CaptureGuard;
    use crate::network::probe::{MockSender, ProbeTransport};

    const SYN: u8 = 1 << 1;
    const RST: u8 = 1 << 2;
    const ACK: u8 = 1 << 4;
    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));

    /// An interface whose /24 contains [`TARGET`], so source resolution
    /// answers on-link without a kernel route probe.
    fn on_link_interface() -> pnet::datalink::NetworkInterface {
        pnet::datalink::NetworkInterface {
            name: "test0".to_string(),
            description: String::new(),
            index: 0,
            mac: None,
            ips: vec![IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 50), 24).unwrap(),
            )],
            flags: 0,
        }
    }

    /// Builds a bare 20-byte TCP segment carrying the given source port,
    /// acknowledgement number, and flags. This is the shape a captured reply
    /// arrives in after the link and IP headers are stripped.
    fn tcp_segment(src_port: u16, ack: u32, flags: u8) -> Vec<u8> {
        let mut buf = vec![0u8; 20];
        let mut tcp = MutableTcpPacket::new(&mut buf).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(40_000);
        tcp.set_data_offset(5);
        tcp.set_acknowledgement(ack);
        tcp.set_flags(flags);
        buf
    }

    /// A scanner wired to a recording [`MockSender`] and an idle capture
    /// stream, plus the session store to assert against.
    fn scanner_with_mock() -> (SynPortScanner, ScanSession) {
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let transport = ProbeTransport::from_parts(
            Box::new(MockSender::default()),
            reply_rx,
            CaptureGuard::noop(),
        );
        let resolver = SourceResolver::from_interfaces(&[on_link_interface()]);
        let scanner = SynPortScanner::with_transport(resolver, ctx, transport, 8);
        (scanner, session)
    }

    /// Sends a probe to `TARGET:port` and returns the sequence number it was
    /// recorded under, so a matching reply can be synthesized.
    fn probe(scanner: &mut SynPortScanner, port: u16) -> SeqNum {
        scanner.send_probe(Target {
            ip: TARGET,
            port,
            protocol: Protocol::Tcp,
        });
        scanner
            .pending
            .get(&(TARGET, port))
            .expect("probe recorded")
            .0
    }

    fn port_state(session: &ScanSession, port: u16) -> Option<PortState> {
        session
            .store
            .get(&TARGET)
            .and_then(|h| h.ports().find(|p| p.number() == port).map(|p| p.state()))
    }

    #[test]
    fn syn_ack_matching_probe_is_open() {
        let (mut scanner, session) = scanner_with_mock();
        let seq = probe(&mut scanner, 80);

        scanner.handle_reply(TARGET, &tcp_segment(80, seq.wrapping_add(1), SYN | ACK));

        assert_eq!(port_state(&session, 80), Some(PortState::Open));
        assert!(!scanner.pending.contains_key(&(TARGET, 80)));
    }

    #[test]
    fn rst_matching_probe_is_closed() {
        let (mut scanner, session) = scanner_with_mock();
        let seq = probe(&mut scanner, 81);

        scanner.handle_reply(TARGET, &tcp_segment(81, seq.wrapping_add(1), RST | ACK));

        assert_eq!(port_state(&session, 81), Some(PortState::Closed));
    }

    #[test]
    fn reply_with_wrong_ack_is_ignored() {
        let (mut scanner, session) = scanner_with_mock();
        let seq = probe(&mut scanner, 82);

        // Acknowledgement doesn't correspond to our sequence number: a stray
        // or spoofed segment, not a reply to our probe.
        scanner.handle_reply(TARGET, &tcp_segment(82, seq.wrapping_add(999), SYN | ACK));

        assert_eq!(port_state(&session, 82), None);
        assert!(scanner.pending.contains_key(&(TARGET, 82)));
    }

    #[test]
    fn reply_for_unprobed_port_is_ignored() {
        let (mut scanner, session) = scanner_with_mock();
        let seq = probe(&mut scanner, 80);

        // Same host, but a port we never probed.
        scanner.handle_reply(TARGET, &tcp_segment(1234, seq.wrapping_add(1), SYN | ACK));

        assert_eq!(port_state(&session, 1234), None);
        assert!(scanner.pending.contains_key(&(TARGET, 80)));
    }

    #[test]
    fn unanswered_probes_resolve_as_filtered() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, 443);

        scanner.resolve_remaining_as_filtered();

        assert_eq!(port_state(&session, 443), Some(PortState::Filtered));
        assert!(scanner.pending.is_empty());
    }

    #[test]
    fn non_tcp_targets_are_not_probed() {
        let (mut scanner, _session) = scanner_with_mock();
        scanner.send_probe(Target {
            ip: TARGET,
            port: 53,
            protocol: Protocol::Udp,
        });
        assert!(scanner.pending.is_empty());
    }
}
