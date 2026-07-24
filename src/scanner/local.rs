// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Local Area Network Scanner
//!
//! Discovers hosts on the same physical network segment by sending ARP
//! requests (IPv4) and a single ICMPv6 all-nodes solicitation (IPv6), then
//! listening for replies. Recognizing those replies is delegated to the
//! [`discovery`] module, so adding a new discovery mechanism doesn't mean
//! touching the receive loop itself.
//!
//! This scanner requires root privileges: it constructs and intercepts raw
//! Ethernet frames directly, bypassing the operating system's own IP stack.

mod discovery;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::Interval;

use crate::core::models::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::core::models::timer::ScanBudget;
use crate::core::models::{host::Host, ip::set::IpSet};
use crate::core::session::{ScanContext, ScanEvent};
use crate::network::channel::{self, EthernetHandle};
use crate::network::mac::IntoCoreMac;
use crate::protocols::{self as protocol, ethernet};
use crate::scanner::NetworkExplorer;
use crate::system::interface::NetworkInterfaceExtension;
use crate::{error, info};

use discovery::{ArpProtocol, DiscoveryProtocol, Icmpv6Protocol, PendingProbes, ProtocolMatch};

/// Errors specific to local-network scanning: interface setup problems and
/// packets that fail the sanity checks a discovery reply is expected to pass.
#[derive(Debug, thiserror::Error)]
pub enum LocalScannerError {
    #[error("interface has no mac address")]
    NoMacAddress,
    #[error("unmapped RTT source: {0}")]
    UnmappedRttSource(IpAddr),
    #[error("packet originated from this host")]
    SelfSourcedPacket,
    #[error("{0} is not in the scanned range")]
    AddressOutOfRange(IpAddr),
}

/// How long a discovery sweep runs, and how it adapts. `base` and
/// `per_target` scale with the number of targets; `silence_floor`,
/// `silence_ceiling`, and `jitter_multiplier` bound how the tolerance for
/// network silence adapts to recently observed round-trip times. These
/// starting values assume a local network segment, where round trips are
/// typically well under a millisecond.
const DEADLINE_CONFIG: AdaptiveDeadlineConfig = AdaptiveDeadlineConfig::new(
    ScanBudget::new(
        Duration::from_millis(2_000),
        Duration::from_millis(20),
        Duration::from_millis(15_000),
    ),
    ScanBudget::new(
        Duration::from_millis(800),
        Duration::from_millis(7),
        Duration::from_millis(5_000),
    ),
    Duration::from_millis(250),
    Duration::from_millis(2_000),
    4.0,
    20,
);

const SEND_INTERVAL: Duration = Duration::from_micros(1000);

/// The addressing identity this scanner uses to speak on its interface,
/// resolved once at construction time and never changed afterward.
struct SourceIdentity {
    mac: MacAddr,
    ipv4: Option<Ipv4Addr>,
    link_local_ipv6: Option<Ipv6Addr>,
}

impl SourceIdentity {
    /// Picks the addresses this scanner will present as its own when
    /// probing `ip_set` from `intf`.
    ///
    /// The IPv4 address preferred is, in order: one in the same subnet as
    /// the targets being scanned, falling back to the interface's first
    /// non-loopback address. The IPv6 address is the interface's link-local
    /// address, if it has one, since that's what the ICMPv6 all-nodes probe
    /// is sent from.
    fn resolve(intf: &NetworkInterface, ip_set: &IpSet) -> Result<Self, LocalScannerError> {
        let mac = intf.mac.ok_or(LocalScannerError::NoMacAddress)?;

        let mut ipv4 = None;
        for net in intf.get_ipv4_nets() {
            if ipv4.is_none() && !net.ip().is_loopback() {
                ipv4 = Some(net.ip());
            }
            if ip_set
                .v4()
                .iter()
                .any(|range| net.contains(range.start_addr))
            {
                ipv4 = Some(net.ip());
                break;
            }
        }

        let link_local_ipv6 = intf
            .get_ipv6_nets()
            .into_iter()
            .find(|net| net.ip().is_unicast_link_local())
            .map(|net| net.ip());

        Ok(Self {
            mac,
            ipv4,
            link_local_ipv6,
        })
    }
}

pub struct LocalScanner {
    ctx: ScanContext,
    ip_set: IpSet,
    identity: SourceIdentity,
    eth_handle: EthernetHandle,
    deadline: AdaptiveDeadline,
    protocols: Vec<Box<dyn DiscoveryProtocol>>,
    pending_probes: PendingProbes,
    dns_tx: Option<UnboundedSender<IpAddr>>,
    mac_to_ip: HashMap<MacAddr, IpAddr>,
}

#[async_trait]
impl NetworkExplorer for LocalScanner {
    async fn discover_hosts(&mut self) -> anyhow::Result<()> {
        let mut packet_iter = protocol::eth_packet_iter(
            &self.identity.mac,
            &self.identity.ipv4,
            &self.identity.link_local_ipv6,
            &self.ip_set,
        )?;

        let mut sending_finished = false;
        let mut send_interval: Interval = tokio::time::interval(SEND_INTERVAL);

        loop {
            if self.should_stop() && sending_finished {
                break;
            }

            // Only needed once sending has finished: while packets are still
            // going out, `send_interval` already drives the loop frequently
            // enough for the check above to run promptly.
            let next_tick = self.deadline.time_until_next_tick();

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
                            self.pending_probes.insert(ip, Instant::now());
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
        let identity = SourceIdentity::resolve(&intf, &ip_set)?;

        let target_count = ip_set.len() as usize;
        let deadline = AdaptiveDeadline::new(DEADLINE_CONFIG, target_count);

        Ok(Self {
            ctx,
            ip_set,
            identity,
            eth_handle,
            deadline,
            protocols: vec![Box::new(ArpProtocol), Box::new(Icmpv6Protocol)],
            pending_probes: PendingProbes::with_capacity(target_count),
            dns_tx,
            mac_to_ip: HashMap::new(),
        })
    }

    /// Validates an incoming frame and routes it to the two halves of
    /// handling a discovery reply: figuring out what it means, then
    /// recording that in shared scan state.
    fn process_eth_packet(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        let eth_frame: EthernetPacket = ethernet::get_packet_from_u8(bytes)?;

        let source_mac = eth_frame.get_source();
        if source_mac == self.identity.mac {
            return Err(LocalScannerError::SelfSourcedPacket.into());
        }

        let source_addr: IpAddr = protocol::get_ip_addr_from_eth(&eth_frame)?;
        if source_addr.is_ipv4() && !self.ip_set.contains(&source_addr) {
            return Err(LocalScannerError::AddressOutOfRange(source_addr).into());
        }

        if let ProtocolMatch::Handled { rtt } = self.interpret_response(&eth_frame, source_addr) {
            self.record_response(source_mac, source_addr, rtt);
        }

        Ok(())
    }

    /// Tries each configured [`DiscoveryProtocol`] against `frame` in turn.
    ///
    /// Returns [`ProtocolMatch::Unhandled`] if no protocol recognized the
    /// frame as a discovery response, or if one failed to interpret it - in
    /// both cases the frame carries no reliable information about who sent
    /// it and must not be attributed to any host. A frame reaching us
    /// promiscuously that no protocol claims is common: LAN traffic between
    /// other hosts, or traffic merely forwarded through a router rather than
    /// sent directly, whose Ethernet source is the router, not whoever the
    /// IP packet actually originated from.
    fn interpret_response(&mut self, frame: &EthernetPacket, source: IpAddr) -> ProtocolMatch {
        for protocol in &self.protocols {
            match protocol.interpret(frame, source, &mut self.pending_probes) {
                Ok(ProtocolMatch::Handled { rtt }) => return ProtocolMatch::Handled { rtt },
                Ok(ProtocolMatch::Unhandled) => continue,
                Err(e) => {
                    error!(verbosity = 1, "Failed to interpret discovery response: {e}");
                    return ProtocolMatch::Unhandled;
                }
            }
        }

        ProtocolMatch::Unhandled
    }

    /// Applies a discovery response to shared scan state: updates or
    /// creates the responding host, feeds the adaptive deadline, and
    /// notifies both the scan's event channel and the hostname resolver of
    /// anything new.
    fn record_response(&mut self, source_mac: MacAddr, source_addr: IpAddr, rtt: Option<Duration>) {
        let primary_ip = *self.mac_to_ip.entry(source_mac).or_insert(source_addr);

        let mut is_new_host = false;
        let mut host = self.ctx.store.entry(primary_ip).or_insert_with(|| {
            self.deadline.mark_activity();
            is_new_host = true;
            Host::new(primary_ip).with_mac(source_mac.into_core())
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
            self.deadline.record_rtt(rtt);
            emit_update = true;
        }

        let is_new_ip = host.add_ip(source_addr);
        emit_update |= is_new_ip;

        if source_addr.is_ipv4() && host.primary_ip().is_ipv6() {
            host.set_primary_ip(source_addr);
            emit_update = true;
        }

        // Drop the lock on the shared store before sending over the event channel.
        drop(host);

        if emit_update || is_new_host {
            let _ = self.ctx.events_tx.send(ScanEvent::HostUpdated(primary_ip));
        }

        if is_new_host || is_new_ip {
            self.dns_tx.as_ref().map(|tx| tx.send(source_addr));
        }
    }

    fn should_stop(&self) -> bool {
        self.ctx.handle.should_stop() || self.deadline.has_expired()
    }
}
