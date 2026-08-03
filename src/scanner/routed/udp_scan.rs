// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # UDP Port Probing
//!
//! Implements the privileged UDP half of [`crate::scanner::scan`]. It probes
//! specific `(address, port)` pairs with raw UDP packets and classifies each
//! one by whether and how it responds.
//!
//! UDP scanning is notoriously difficult because UDP is stateless. A closed port
//! responds with an ICMP Port Unreachable message, while an open port typically
//! responds with a valid UDP payload (if it understands our payload) or silence.
//! A filtered port drops the packet entirely, which also results in silence.
//!
//! This scanner watches the capture interface for ICMP Unreachable replies,
//! marking them as `Closed`. Direct UDP replies are marked `Open`. Silence
//! until the scan's deadline expires is marked `OpenFiltered`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use async_trait::async_trait;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, destination_unreachable::IcmpCodes};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::udp::UdpPacket;
use tokio::sync::mpsc;

use crate::core::config::SendMode;
use crate::core::models::deadline::AdaptiveDeadline;
use crate::core::models::port::{PortState, Protocol};
use crate::core::models::target::Target;
use crate::core::session::{ScanContext, ScannerKind};
use crate::error;
use crate::network::probe::{ProbeKind, ProbeTransport};
use crate::scanner::{PortScanner, service};
use crate::system::interface::SourceResolver;

use super::{DEADLINE_CONFIG, send_udp};

/// Outstanding probes, keyed by the target they were sent to.
type PendingProbes = HashMap<(IpAddr, u16), Instant>;

/// Probes specific `(address, port)` pairs with raw UDP packets.
pub struct UdpPortScanner {
    /// Resolves the source address to send each target's probe from, consulting
    /// on-link subnets and the kernel routing table.
    resolver: SourceResolver,
    /// Shared state (host store, event channel, abort signal) for the scan
    /// this prober is part of.
    ctx: ScanContext,
    /// Transport used to send raw UDP probes and receive replies (or ICMP errors).
    transport: ProbeTransport,
    /// Governs how long this scan keeps running, adapting to observed
    /// round-trip times.
    deadline: AdaptiveDeadline,
    /// Probes sent but not yet resolved into a classification.
    pending: PendingProbes,
}

impl UdpPortScanner {
    /// Builds a scanner that selects each probe's source via `resolver`, sized
    /// for a scan covering `target_count` `(address, port)` pairs.
    pub fn new(
        resolver: SourceResolver,
        ctx: ScanContext,
        target_count: usize,
        send_mode: SendMode,
    ) -> anyhow::Result<Self> {
        let transport = ProbeTransport::open_with(ProbeKind::UdpProbe, send_mode)?;
        let deadline = AdaptiveDeadline::new(DEADLINE_CONFIG, target_count);

        Ok(Self {
            resolver,
            ctx,
            transport,
            deadline,
            pending: PendingProbes::new(),
        })
    }

    fn send_probe(&mut self, target: Target) {
        if target.protocol != Protocol::Udp {
            return;
        }

        let Some(src_addr) = self.resolver.resolve(target.ip) else {
            error!(
                verbosity = 2,
                "No route to {}; skipping UDP probe to {}:{}", target.ip, target.ip, target.port
            );
            return;
        };

        if send_udp(self.transport.tx.as_ref(), src_addr, target.ip, target.port).is_some() {
            self.pending
                .insert((target.ip, target.port), Instant::now());
        }
    }

    /// Matches a reply against an outstanding probe and classifies it.
    /// Since we capture both UDP and ICMP traffic, we first look for a valid
    /// UDP response. If we don't find one, we check if the packet is an ICMP
    /// Port Unreachable message.
    fn handle_reply(&mut self, ip: IpAddr, bytes: &[u8]) {
        // Try parsing as UDP reply first (means port is Open)
        if let Some(udp) = UdpPacket::new(bytes) {
            let src_port = udp.get_source();
            let key = (ip, src_port);
            if let Some(sent_at) = self.pending.remove(&key) {
                self.deadline.mark_activity();
                self.deadline.record_rtt(sent_at.elapsed());
                self.record_port(ip, src_port, PortState::Open);
                return;
            }
        }

        // Try parsing as ICMP Port Unreachable (means port is Closed)
        if ip.is_ipv4() {
            if let Some(icmp) = IcmpPacket::new(bytes)
                && icmp.get_icmp_type() == IcmpTypes::DestinationUnreachable
                && icmp.get_icmp_code() == IcmpCodes::DestinationPortUnreachable
            {
                // For now, if we get Port Unreachable from this IP, we mark the
                // pending probes for this IP as Closed. A deeper packet inspection
                // would extract the original IP/UDP header from the ICMP payload.
                let ports: Vec<u16> = self
                    .pending
                    .keys()
                    .filter(|(target_ip, _)| target_ip == &ip)
                    .map(|(_, p)| *p)
                    .collect();
                for p in ports {
                    if let Some(sent_at) = self.pending.remove(&(ip, p)) {
                        self.deadline.mark_activity();
                        self.deadline.record_rtt(sent_at.elapsed());
                        self.record_port(ip, p, PortState::Closed);
                    }
                }
            }
        } else if ip.is_ipv6()
            && let Some(icmp) = Icmpv6Packet::new(bytes)
            && icmp.get_icmpv6_type() == Icmpv6Types::DestinationUnreachable
        {
            let ports: Vec<u16> = self
                .pending
                .keys()
                .filter(|(target_ip, _)| target_ip == &ip)
                .map(|(_, p)| *p)
                .collect();
            for p in ports {
                if let Some(sent_at) = self.pending.remove(&(ip, p)) {
                    self.deadline.mark_activity();
                    self.deadline.record_rtt(sent_at.elapsed());
                    self.record_port(ip, p, PortState::Closed);
                }
            }
        }
    }

    /// Marks every probe still outstanding once the scan winds down as filtered.
    /// No ICMP Port Unreachable and no valid UDP response arrived, which is
    /// typical of a firewall silently dropping the packet.
    fn resolve_remaining_as_filtered(&mut self) {
        let remaining: Vec<(IpAddr, u16)> = self.pending.drain().map(|(key, _)| key).collect();
        for (ip, port) in remaining {
            self.record_port(ip, port, PortState::OpenFiltered);
        }
    }

    fn record_port(&mut self, ip: IpAddr, port_num: u16, state: PortState) {
        let port = crate::fingerprinting::baseline_port(port_num, Protocol::Udp, state);
        self.ctx.update_host(ip, |host| host.add_port(port));
    }
}

#[async_trait]
impl PortScanner for UdpPortScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::UdpPort
    }

    fn supported_protocols(&self) -> Vec<Protocol> {
        vec![Protocol::Udp]
    }

    /// Consumes `targets`, sending a UDP probe for each UDP target and classifying
    /// every reply (or ICMP error), until each probe has been resolved or the
    /// scan's deadline expires. Anything still outstanding when the loop ends is
    /// reported as OpenFiltered.
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

    /// Fingerprints every open port the UDP pass found.
    async fn detect_services(&mut self, ctx: &ScanContext) {
        service::detect(ctx).await;
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use pnet::ipnetwork::{IpNetwork, Ipv4Network};
    use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket, destination_unreachable::IcmpCodes};
    use pnet::packet::udp::MutableUdpPacket;

    use crate::core::session::ScanSession;
    use crate::network::capture::CaptureGuard;
    use crate::network::probe::{MockSender, ProbeTransport};

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));

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

    fn scanner_with_mock() -> (UdpPortScanner, ScanSession) {
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let transport = ProbeTransport::from_parts(
            Box::new(MockSender::default()),
            reply_rx,
            CaptureGuard::noop(),
        );
        let resolver = SourceResolver::from_interfaces(&[on_link_interface()]);

        let scanner = UdpPortScanner {
            resolver,
            ctx,
            transport,
            deadline: AdaptiveDeadline::new(DEADLINE_CONFIG, 8),
            pending: PendingProbes::new(),
        };
        (scanner, session)
    }

    fn probe(scanner: &mut UdpPortScanner, port: u16) {
        scanner.send_probe(Target {
            ip: TARGET,
            port,
            protocol: Protocol::Udp,
        });
    }

    fn port_state(session: &ScanSession, port: u16) -> Option<PortState> {
        session
            .store
            .get(&TARGET)
            .and_then(|h| h.ports().find(|p| p.number() == port).map(|p| p.state()))
    }

    fn udp_reply(src_port: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 8];
        let mut udp = MutableUdpPacket::new(&mut buf).unwrap();
        udp.set_source(src_port);
        udp.set_destination(40_000);
        udp.set_length(8);
        buf
    }

    fn icmp_unreachable() -> Vec<u8> {
        let mut buf = vec![0u8; 8];
        let mut icmp = MutableIcmpPacket::new(&mut buf).unwrap();
        icmp.set_icmp_type(IcmpTypes::DestinationUnreachable);
        icmp.set_icmp_code(IcmpCodes::DestinationPortUnreachable);
        buf
    }

    #[test]
    fn direct_udp_reply_is_open() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, 53);

        scanner.handle_reply(TARGET, &udp_reply(53));

        assert_eq!(port_state(&session, 53), Some(PortState::Open));
        assert!(scanner.pending.is_empty());
    }

    #[test]
    fn icmp_port_unreachable_is_closed() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, 53);

        scanner.handle_reply(TARGET, &icmp_unreachable());

        assert_eq!(port_state(&session, 53), Some(PortState::Closed));
        assert!(scanner.pending.is_empty());
    }

    #[test]
    fn unanswered_probes_resolve_as_filtered() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, 161);

        scanner.resolve_remaining_as_filtered();

        assert_eq!(port_state(&session, 161), Some(PortState::OpenFiltered));
        assert!(scanner.pending.is_empty());
    }

    #[test]
    fn non_udp_targets_are_not_probed() {
        let (mut scanner, _session) = scanner_with_mock();
        scanner.send_probe(Target {
            ip: TARGET,
            port: 80,
            protocol: Protocol::Tcp,
        });
        assert!(scanner.pending.is_empty());
    }
}
