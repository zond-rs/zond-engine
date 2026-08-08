// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Local Area Network Scanner
//!
//! Discovers hosts on the same physical network segment by sending ARP requests
//! (IPv4) and a single ICMPv6 all-nodes solicitation (IPv6), then listening for
//! replies. Recognizing those replies is left to the [`discovery`] module, so
//! adding a new discovery mechanism does not mean touching the receive loop.
//!
//! This scanner requires root privileges. It builds and intercepts raw Ethernet
//! frames directly, bypassing the operating system's own IP stack.

mod discovery;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::Interval;

use crate::core::models::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::core::models::ip::set::IpSet;
use crate::core::models::timer::ScanBudget;
use crate::core::session::ScanContext;
use crate::network::channel::{self, EthernetHandle};
use crate::network::mac::IntoCoreMac;
use crate::protocols::{self as protocol, ethernet};
use crate::scanner::NetworkExplorer;
use crate::system::interface::NetworkInterfaceExtension;
use crate::{error, info};

use discovery::{ArpProtocol, DiscoveryProtocol, Icmpv6Protocol, PendingProbes, ProtocolMatch};

/// Errors specific to local-network scanning, covering interface setup problems
/// and packets that fail the sanity checks a discovery reply is expected to pass.
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

/// How long a discovery sweep runs and how it adapts. The base and per-target
/// budgets scale with the number of targets, while the silence floor, silence
/// ceiling, and jitter multiplier bound how far the tolerance for network
/// silence can stretch in response to recent round-trip times. These starting
/// values assume a local segment, where round trips are usually well under a
/// millisecond.
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

/// How much of the segment a [`LocalScanner`] run touches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Probe every address in range and record every responder, including
    /// IPv6-only neighbors found through an all-nodes solicitation. Used by
    /// `discover`, whose job is to find whatever is on the segment.
    Sweep,
    /// Probe only the given target addresses and record only those. No all-nodes
    /// solicitation is sent, so scanning one host never lights up its neighbors.
    /// Used by `scan`, where the targets are already known.
    Targeted,
}

/// The addressing identity this scanner uses to speak on its interface,
/// resolved once at construction time and never changed afterward.
struct SourceIdentity {
    mac: MacAddr,
    ipv4: Option<Ipv4Addr>,
    link_local_ipv6: Option<Ipv6Addr>,
}

impl SourceIdentity {
    /// Picks the addresses this scanner will present as its own when probing
    /// `ip_set` from `intf`.
    ///
    /// For IPv4, it prefers an address in the same subnet as the targets being
    /// scanned and otherwise falls back to the interface's first non-loopback
    /// address. For IPv6, it uses the interface's link-local address when it has
    /// one, since that is what the ICMPv6 all-nodes probe is sent from.
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
    /// Shared state (host store, event channel, abort signal) for the scan
    /// this explorer is part of.
    ctx: ScanContext,
    /// The addresses being probed for aliveness.
    ip_set: IpSet,
    /// The address this scanner presents as its own when probing.
    identity: SourceIdentity,
    /// Raw Ethernet capture used to send probe packets and receive replies.
    eth_handle: EthernetHandle,
    /// Governs how long this sweep keeps running, adapting to observed
    /// round-trip times.
    deadline: AdaptiveDeadline,
    /// Wire formats this scanner recognizes as discovery replies, tried in
    /// order against every received frame.
    protocols: Vec<Box<dyn DiscoveryProtocol>>,
    /// Outstanding probes, keyed by the address a reply is expected from.
    pending_probes: PendingProbes,
    /// Where to forward newly discovered addresses for hostname
    /// resolution, if enabled.
    dns_tx: Option<UnboundedSender<IpAddr>>,
    /// Maps each MAC seen back to the first address observed from it, so a
    /// host reachable at more than one address is recorded once.
    mac_to_ip: HashMap<MacAddr, IpAddr>,
    /// Whether to sweep the segment or probe only the given targets.
    scope: Scope,
    /// Target addresses that have answered, so a targeted run can stop the
    /// moment every one of them has, rather than waiting out the deadline.
    responded: HashSet<IpAddr>,
}

#[async_trait]
impl NetworkExplorer for LocalScanner {
    async fn discover_hosts(mut self: Box<Self>) -> anyhow::Result<()> {
        let mut packet_iter = protocol::eth_packet_iter(
            &self.identity.mac,
            &self.identity.ipv4,
            &self.identity.link_local_ipv6,
            &self.ip_set,
            matches!(self.scope, Scope::Sweep),
        )?;

        let mut sending_finished = false;
        let mut send_interval: Interval = tokio::time::interval(SEND_INTERVAL);

        loop {
            if sending_finished && (self.should_stop() || self.all_targets_responded()) {
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
        scope: Scope,
    ) -> anyhow::Result<Self> {
        let eth_handle: EthernetHandle = channel::start_capture(&intf)?;
        Self::with_handle(intf, ip_set, ctx, dns_tx, scope, eth_handle)
    }

    /// Builds a scanner around an already-opened Ethernet channel, so the caller
    /// decides how frames reach the wire and where replies come from.
    ///
    /// The addressing identity is still resolved from `intf`, since a probe has
    /// to be sent from some MAC and address, but nothing here touches the
    /// interface itself. Paired with a synthetic channel
    /// (`EthernetHandle::from_parts`, behind the `test-support` feature) and a
    /// hand-built [`NetworkInterface`], this is the seam that lets ARP and NDP
    /// discovery be driven against a simulated segment with no privileges.
    pub fn with_handle(
        intf: NetworkInterface,
        ip_set: IpSet,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        scope: Scope,
        eth_handle: EthernetHandle,
    ) -> anyhow::Result<Self> {
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
            scope,
            responded: HashSet::new(),
        })
    }

    /// Validates an incoming frame, then handles a discovery reply in two steps:
    /// working out what it means, and recording that in shared scan state.
    fn process_eth_packet(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        let eth_frame: EthernetPacket = ethernet::get_packet_from_u8(bytes)?;

        let source_mac = eth_frame.get_source();
        if source_mac == self.identity.mac {
            return Err(LocalScannerError::SelfSourcedPacket.into());
        }

        let source_addr: IpAddr = protocol::get_ip_addr_from_eth(&eth_frame)?;
        // A targeted run records only its exact targets; a sweep records every
        // in-range IPv4 responder plus any IPv6 neighbor (linked by MAC).
        let out_of_range = match self.scope {
            Scope::Targeted => !self.ip_set.contains(&source_addr),
            Scope::Sweep => source_addr.is_ipv4() && !self.ip_set.contains(&source_addr),
        };
        if out_of_range {
            return Err(LocalScannerError::AddressOutOfRange(source_addr).into());
        }

        if let ProtocolMatch::Handled { rtt } = self.interpret_response(&eth_frame, source_addr) {
            if self.ip_set.contains(&source_addr) {
                self.responded.insert(source_addr);
            }
            self.record_response(source_mac, source_addr, rtt);
        }

        Ok(())
    }

    /// Whether every target address has answered. This is only meaningful for a
    /// [`Scope::Targeted`] run. A sweep's range is far larger than the set of
    /// live hosts, so the check effectively never trips and the sweep runs to
    /// its deadline.
    fn all_targets_responded(&self) -> bool {
        self.responded.len() as u128 >= self.ip_set.len()
    }

    /// Tries each configured [`DiscoveryProtocol`] against `frame` in turn.
    ///
    /// Returns [`ProtocolMatch::Unhandled`] when no protocol recognized the frame
    /// as a discovery response, or when one recognized it but failed to interpret
    /// it. Either way the frame carries no reliable information about who sent it
    /// and must not be attributed to any host. Seeing a frame that no protocol
    /// claims is common in promiscuous mode: it may be LAN traffic between other
    /// hosts, or traffic forwarded through a router rather than sent directly,
    /// whose Ethernet source is the router itself and not the host the IP packet
    /// originated from.
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

    /// Applies a discovery response to shared scan state. It creates or updates
    /// the responding host, feeds the adaptive deadline, and notifies both the
    /// scan's event channel and the hostname resolver of anything new.
    fn record_response(&mut self, source_mac: MacAddr, source_addr: IpAddr, rtt: Option<Duration>) {
        let primary_ip = *self.mac_to_ip.entry(source_mac).or_insert(source_addr);

        // Host mutation only. `write_host` owns the guard, the drop-before-emit
        // ordering, and the event. `is_new_ip` is returned for the DNS decision
        // below, which runs after the guard is released, as does the deadline
        // bookkeeping.
        let mut is_new_ip = false;
        let is_new_host = self.ctx.write_host(primary_ip, |host| {
            // Set the MAC whether we just created the host or the port scanner
            // created it first, so enrichment order doesn't decide whether a MAC
            // is recorded. Only the first MAC seen for the host is kept.
            if host.mac().is_none() {
                host.set_mac(source_mac.into_core());
            }

            let mut changed = rtt.is_some();
            if let Some(rtt) = rtt {
                host.add_rtt(rtt);
            }

            is_new_ip = host.add_ip(source_addr);
            changed |= is_new_ip;

            if source_addr.is_ipv4() && host.primary_ip().is_ipv6() {
                host.set_primary_ip(source_addr);
                changed = true;
            }

            changed
        });

        if is_new_host {
            self.deadline.mark_activity();
        }

        if let Some(rtt) = rtt {
            info!(
                incoming,
                verbosity = 2,
                "{source_addr} responded in {}ms",
                rtt.as_millis()
            );
            self.deadline.record_rtt(rtt);
        }

        if (is_new_host || is_new_ip)
            && let Some(tx) = &self.dns_tx
        {
            let _ = tx.send(source_addr);
        }
    }

    fn should_stop(&self) -> bool {
        self.ctx.handle.should_stop() || self.deadline.has_expired()
    }
}
