// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Local Area Network Scanner
//!
//! Discovers hosts on the same physical network segment by sending ARP requests
//! (IPv4) and ICMPv6 all-nodes solicitations (IPv6), then listening for replies.
//! Recognizing those replies is left to the `discovery` module, so adding a
//! new discovery mechanism does not mean touching the receive loop.
//!
//! The two probes are repeated on different terms, because they ask different
//! questions. An ARP request is put to one address, answered once, and retired
//! by that answer, so it is retransmitted through the shared
//! [`ProbeLedger`] like every other
//! probe in the engine. The solicitation is put to the whole segment and
//! answered by whoever is listening, so it is simply repeated a few times and
//! given a window to be answered in.
//!
//! This scanner requires root privileges. It builds and intercepts raw Ethernet
//! frames directly, bypassing the operating system's own IP stack.

mod discovery;
mod ipv6;
mod probes;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::Interval;

use crate::config::RetryConfig;
use crate::model::host::telemetry::RttSource;
use crate::model::host::{HostStatus, StatusProtocol, StatusReason};
use crate::model::ip::scoped::Zone;
use crate::model::ip::set::IpSet;
use crate::protocols::{self as protocol, ethernet};
use crate::scanner::audit::ProbeAudit;
use crate::scanner::pacing::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::scanner::pacing::retry::{Due, ProbeLedger, RetryPolicy};
use crate::scanner::pacing::timer::ScanBudget;
use crate::scanner::report::StopReason;
use crate::scanner::session::{ScanContext, ScannerKind};
use crate::scanner::strategy::{HostScanner, StrategyError};
use crate::system::interface::NetworkInterfaceExtension;
use crate::transport::channel::{self, EthernetHandle};
use crate::transport::mac::IntoCoreMac;
use crate::{error, info};

use discovery::{ArpProtocol, DiscoveryProtocol, Icmpv6EchoProtocol, NdpProtocol, ProtocolMatch};
use ipv6::Ipv6Discovery;

/// Outstanding ARP requests and the schedule they are retried on.
///
/// The attempt token is `()`: consecutive requests for one address are
/// identical on the wire, so a reply cannot say which of them it answers. The
/// ledger applies Karn's rule on that basis and declines to measure a round trip
/// it cannot attribute.
///
/// The all-nodes solicitation is deliberately not in here. It is one multicast
/// packet that every neighbour may answer, so it has no single outcome to
/// resolve and nothing to retire; the scanner times it separately.
type Ledger = ProbeLedger<IpAddr, ()>;

/// How an ARP request is retransmitted.
///
/// ARP is lost on a busy segment considerably more often than its reputation
/// suggests - requests are broadcast, and a switch under load drops broadcast
/// before anything else - and a sweep that never asks twice simply reports the
/// hosts it missed as absent.
///
/// The timings are a segment's, not an internet path's: a neighbour that is
/// going to answer does so in well under a millisecond, so the floor is what
/// governs almost immediately and a silent address is settled in about a second
/// rather than in the seconds a wide-area profile would spend.
///
/// No silent-host rule, because there would be nothing for it to do: each
/// address here is probed once, so no host ever accumulates the exhausted
/// probes that rule counts.
const RETRY_POLICY: RetryPolicy = RetryPolicy::new(
    3,
    Duration::from_millis(150),
    Duration::from_millis(25),
    Duration::from_secs(1),
    2.0,
    0.2,
    None,
);

/// Why a captured frame is not a discovery finding.
///
/// Not a failure of the scanner: a promiscuous capture sees the whole segment's
/// traffic, so most of what arrives is somebody else's and rejecting it is the
/// normal case rather than an error. These are named rather than lumped into one
/// `None` because which check rejected a frame is the first thing worth knowing
/// when a host that should have been found was not.
///
/// Kept apart from [`StrategyError`], which is about a strategy that could not
/// run at all.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FrameRejected {
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
///
/// The hard ceiling carries a constraint the other values do not. This scanner
/// paces its own sends at [`SEND_INTERVAL`], so a sweep needs at least
/// `target_count * SEND_INTERVAL` simply to emit its probes. A ceiling below
/// that stops the sweep mid-send, and does so invisibly: an address that was
/// never probed is indistinguishable from one with nothing on it. Keep this
/// well above `SEND_INTERVAL` times the largest range worth sweeping.
const DEADLINE_CONFIG: AdaptiveDeadlineConfig = AdaptiveDeadlineConfig::new(
    ScanBudget::new(
        Duration::from_millis(2_000),
        Duration::from_millis(20),
        Duration::from_secs(120),
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

/// How long to leave between probes.
///
/// Slowing this down measurably raises the share of *first* attempts that get
/// answered on a wireless segment, where both of this scanner's first-attempt
/// probes are group-addressed and group-addressed frames are the expensive
/// case. It is deliberately not slowed down anyway: a first attempt that goes
/// unanswered is recovered by [`RETRY_POLICY`], so the gain is a better
/// *attributed* round trip on a few hosts rather than more hosts, and it is
/// bought at several times the scan duration — the send phase drags the
/// adaptive deadline along behind it, so the cost compounds rather than adds.
///
/// `benches/ndp_pace.rs` measures the trade if it is revisited. Two cautions
/// from the last attempt: the run-to-run variance on a segment of sleeping
/// wireless devices is large enough to swamp small differences, so arms are
/// only comparable within one block; and the number to judge it on is hosts
/// found and hosts timed *per second of scan*, not first-attempt rate.
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
    /// The interface itself, which this scanner is the only kind that knows.
    ///
    /// Every neighbour it finds was reached across this one segment, so every
    /// link-local address it records is valid on this interface and no other.
    /// Recording that alongside the host is what makes those addresses usable
    /// by the phases that come after discovery; see
    /// [`ScopedIp`](crate::model::ip::scoped::ScopedIp).
    zone: Zone,
}

impl SourceIdentity {
    /// Picks the addresses this scanner will present as its own when probing
    /// `ip_set` from `intf`.
    ///
    /// For IPv4, it prefers an address in the same subnet as the targets being
    /// scanned and otherwise falls back to the interface's first non-loopback
    /// address. For IPv6, it uses the interface's link-local address when it has
    /// one, since that is what the ICMPv6 all-nodes probe is sent from.
    fn resolve(intf: &NetworkInterface, ip_set: &IpSet) -> Result<Self, StrategyError> {
        let mac = intf.mac.ok_or_else(|| StrategyError::Interface {
            interface: intf.name.clone(),
            reason: "it has no MAC address, and every probe here is an Ethernet frame",
        })?;

        let mut ipv4 = None;
        for net in intf.get_ipv4_nets() {
            if ipv4.is_none() && !net.ip().is_loopback() {
                ipv4 = Some(net.ip());
            }
            if ip_set
                .v4()
                .iter()
                .any(|range| net.contains(range.start_addr()))
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
            zone: Zone::new(intf.index, intf.name.clone()),
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
    /// Outstanding ARP requests, and when each is next due to be repeated or
    /// given up on.
    ledger: Ledger,
    /// Scratch space for the probes coming due on one iteration, reused so a
    /// quiet tick allocates nothing.
    due: Vec<Due<IpAddr>>,
    /// Addresses waiting to be asked again. Held as a queue rather than resent
    /// on the spot so a retry leaves through the same paced ticker a first
    /// attempt does, which is what keeps a burst of expiring probes from
    /// becoming a burst on the wire.
    retries: VecDeque<IpAddr>,
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
    /// Per-run counters, so a sweep that finds fewer hosts than the segment
    /// holds can be attributed to loss, to its own deadline, or to correlation
    /// rather than guessed at. Reported once when the loop exits.
    ///
    /// `capture` is always `None` here: this scanner reads frames off an
    /// [`EthernetHandle`], which is a plain reader thread with no kernel buffer
    /// to interrogate, so what the kernel dropped is not knowable from inside
    /// this scanner rather than being zero.
    audit: ProbeAudit,
    /// Why the first frame that could not be put on the wire failed, if any did.
    ///
    /// The count alone cannot separate a link that refused every write from a
    /// scanner that could not build a packet, and those call for opposite
    /// responses. Kept as the first cause rather than all of them: a segment
    /// that refuses one write refuses the next few hundred for the same reason,
    /// and a report carrying that reason three hundred times says nothing the
    /// first one did not.
    send_failure: Option<String>,
    /// What this sweep has asked the IPv6 half of the segment, and what it is
    /// still waiting to hear back.
    ///
    /// A `/64` cannot be walked the way an IPv4 range can, so nothing about the
    /// ARP half carries over: the probes are different, the retry schedule is
    /// different, and an advertisement cannot say which attempt it answers. That
    /// mechanism keeps its own state rather than sharing this struct's, and the
    /// reasoning behind its timing lives with it.
    ipv6: Ipv6Discovery,
}

#[async_trait]
impl HostScanner for LocalScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::Local
    }

    async fn discover_hosts(&mut self) -> Result<(), StrategyError> {
        let mut packet_iter = probes::eth_packet_iter(
            &self.identity.mac,
            &self.identity.ipv4,
            &self.identity.link_local_ipv6,
            &self.ip_set,
        );

        // The first all-nodes echo is owed immediately, so it goes out at the
        // head of the sweep rather than behind every ARP request. It is the one
        // probe that reaches an IPv6 neighbour holding no address anybody could
        // have guessed, and the sooner it is asked the more of its response
        // window falls inside the scan.
        if matches!(self.scope, Scope::Sweep) && self.identity.link_local_ipv6.is_some() {
            self.ipv6.arm_solicitation(Instant::now());
        }

        let mut sending_finished = false;
        let mut send_interval: Interval = tokio::time::interval(SEND_INTERVAL);
        // Without this, an interval that went unpolled while the loop waited on
        // replies hands back every tick it missed at once, and the pacing this
        // ticker exists to impose evaporates exactly when the queue is longest.
        send_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // The loop yields why it stopped, so the audit cannot report a reason
        // the code never actually took.
        let reason = loop {
            let now = Instant::now();
            self.service_retries(now);

            if self.ctx.handle.should_stop() {
                break StopReason::Aborted;
            }
            if self.deadline.hard_deadline_passed() {
                break StopReason::DeadlineExpired;
            }
            if sending_finished && self.all_targets_responded() {
                break StopReason::AllResponded;
            }
            // Silence is only evidence once nothing is outstanding: with probes
            // still waiting on their timers, quiet is what the retry schedule
            // expects rather than a sign the segment has gone quiet.
            if sending_finished && self.idle(now) && self.deadline.has_expired() {
                break StopReason::DeadlineExpired;
            }

            // Anything left to put on the wire, whether a first attempt or a
            // repeat, goes through the same paced ticker.
            let sending = !sending_finished
                || !self.retries.is_empty()
                || self.ipv6.confirmations_pending()
                || self.ipv6.solicitation().is_due(now);
            let idle_delay = self.tick_delay(now);

            tokio::select! {
                pkt = self.eth_handle.rx.recv() => {
                    match pkt {
                        Some(bytes) => {
                            self.audit.record_segment();
                            _ = self.process_eth_packet(&bytes, Instant::now());
                        }
                        None => break StopReason::StreamClosed,
                    }
                }

                _ = send_interval.tick(), if sending => {
                    // Repeats first: an address already asked once is an
                    // obligation this sweep owns, where the next new address is
                    // only work it intends to do.
                    let now = Instant::now();
                    if let Some(target) = self.retries.pop_front() {
                        self.send_probe(target, now);
                    } else if let Some(target) = self.ipv6.next_confirmation() {
                        self.send_confirmation(target, now);
                    } else if self.ipv6.solicitation().is_due(now) {
                        self.send_solicitation(now);
                    } else if !sending_finished {
                        match packet_iter.next() {
                            Some((packet, ip)) => {
                                self.record_probe(ip, Instant::now());
                                self.emit(&packet, "first attempt");
                            },
                            None => {
                                sending_finished = true;
                            },
                        }
                    }
                }

                _ = tokio::time::sleep(idle_delay), if !sending => {}
            }
        };

        // What the confirmations bought, which is only visible from here. An
        // entry still in the map is a solicitation that went out and was never
        // answered, and the difference between "none were sent" and "none came
        // back" is the difference between a bug here and a segment full of
        // devices that decline to answer a direct question.
        if self.ipv6.unanswered_confirmations() > 0 {
            info!(
                verbosity = 2,
                "{} of the addresses asked about directly never answered",
                self.ipv6.unanswered_confirmations()
            );
        }

        // A sweep whose frames never left is not a sweep that found nothing, and
        // the difference is invisible in every number a caller reads. Reported
        // once with a count and the first cause rather than once per probe, as
        // the routed paths do.
        //
        // This covers every frame the sweep emits, which is what makes it worth
        // having: while the first attempts bypassed the audit, the one path that
        // sends a frame per target could fail entirely and this stayed silent.
        if self.audit.sends_failed > 0 {
            self.ctx.record_failure(
                ScannerKind::Local,
                format!(
                    "{} of {} frames never reached {}, so those addresses are \
                     reported absent without having been asked: {}",
                    self.audit.sends_failed,
                    self.audit.sends_attempted,
                    self.identity.zone,
                    self.send_failure.as_deref().unwrap_or("cause unrecorded"),
                ),
            );
        }

        // No capture counts: frames arrive over an `EthernetHandle`, which is a
        // reader thread rather than a kernel capture, so what the kernel dropped
        // is unknowable here rather than zero.
        let targets = self.ip_set.len();
        self.audit.report("local-discovery", targets, reason, None);
        self.ctx
            .record_probe_stats(self.audit.stats(ScannerKind::Local, targets, reason, None));
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
        retry: RetryConfig,
    ) -> Result<Self, StrategyError> {
        let eth_handle: EthernetHandle = channel::start_capture(&intf)?;
        Self::build(
            intf,
            ip_set,
            ctx,
            dns_tx,
            scope,
            eth_handle,
            RETRY_POLICY.configured(retry),
        )
    }

    /// Builds a scanner around an already-opened Ethernet channel, so the caller
    /// decides how frames reach the wire and where replies come from.
    ///
    /// The addressing identity is still resolved from `intf`, since a probe has
    /// to be sent from some MAC and address, but nothing here touches the
    /// interface itself.
    ///
    /// This is the constructor for a caller orchestrating their own scan, who
    /// has opened a channel on the interface they mean rather than letting
    /// [`new`](Self::new) choose. Paired with a synthetic channel
    /// (`EthernetHandle::from_parts`, behind the `test-support` feature) and a
    /// hand-built [`NetworkInterface`], it is also the seam that lets ARP and
    /// NDP discovery be driven against a simulated segment with no privileges.
    pub fn with_handle(
        intf: NetworkInterface,
        ip_set: IpSet,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        scope: Scope,
        eth_handle: EthernetHandle,
    ) -> Result<Self, StrategyError> {
        Self::build(intf, ip_set, ctx, dns_tx, scope, eth_handle, RETRY_POLICY)
    }

    /// The common constructor, taking the retry schedule as an argument because
    /// the sweep's own deadline is derived from it and so has to be settled
    /// before anything is built.
    #[allow(clippy::too_many_arguments)]
    fn build(
        intf: NetworkInterface,
        ip_set: IpSet,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        scope: Scope,
        eth_handle: EthernetHandle,
        retry: RetryPolicy,
    ) -> Result<Self, StrategyError> {
        let identity = SourceIdentity::resolve(&intf, &ip_set)?;

        let target_count = ip_set.len() as usize;
        // The sweep has to outlive the schedule it commits each probe to, or
        // addresses are given up on having never been fully asked.
        // The longer of the two schedules, because the sweep has to outlive
        // whichever probe it commits to last. Sized from ARP alone, it ends
        // while solicitations are still legitimately outstanding - which is the
        // shape of the bug `ipv6::NDP_RETRY_POLICY` exists to fix, arriving one layer
        // up.
        let probe_lifetime = retry
            .worst_case_probe_lifetime()
            .max(ipv6::NDP_RETRY_POLICY.worst_case_probe_lifetime());
        let deadline_config = DEADLINE_CONFIG.allowing_for(probe_lifetime);
        let deadline = AdaptiveDeadline::new(deadline_config, target_count);

        Ok(Self {
            ctx,
            ip_set,
            identity,
            eth_handle,
            deadline,
            protocols: vec![
                Box::new(ArpProtocol),
                Box::new(NdpProtocol),
                Box::new(Icmpv6EchoProtocol),
            ],
            ledger: Ledger::new(retry, target_count),

            due: Vec::new(),
            retries: VecDeque::new(),

            dns_tx,
            mac_to_ip: HashMap::new(),
            scope,
            responded: HashSet::new(),
            ipv6: Ipv6Discovery::new(target_count),
            audit: ProbeAudit::new(),
            send_failure: None,
        })
    }

    /// Puts one frame on the segment and records what actually happened to it.
    ///
    /// **Every send in this scanner goes through here, and that is the point.**
    /// The audit's counters are only worth reading if they cover every frame,
    /// and a second send path is how they stop doing that: the sweep's own first
    /// attempts went out beside this one for a while, uncounted, so
    /// `sends_attempted` described the retries and nothing else while reading
    /// like a total.
    ///
    /// [`DataLinkSender::send_to`] returns `Option<io::Result<()>>` and both
    /// halves mean the frame never left — `None` when the channel had no buffer
    /// to write into, `Some(Err(..))` when the write itself failed. Reading only
    /// whether the *packet built* leaves `sends_failed` making a claim about
    /// this code where a caller reads it as a claim about the link.
    fn emit(&mut self, packet: &[u8], what: &str) -> bool {
        match self.eth_handle.tx.send_to(packet, None) {
            Some(Ok(())) => {
                self.audit.record_send(true);
                true
            }
            outcome => {
                self.audit.record_send(false);
                self.send_failure.get_or_insert_with(|| match outcome {
                    Some(Err(e)) => format!("{what}: {e}"),
                    _ => format!("{what}: the link-layer channel accepted no frame"),
                });
                false
            }
        }
    }

    /// Notes that a probe for `ip` has just gone out.
    ///
    /// Everything the packet iterator emits is one address's own probe, to be
    /// repeated and eventually given up on. The all-nodes echo is not among
    /// them: it belongs to [`Solicitation`], which records its own sends
    /// because it has to remember the token each one carried.
    fn record_probe(&mut self, ip: IpAddr, now: Instant) {
        if ip.is_ipv6() {
            self.ipv6.record_asked(ip, now);
        } else {
            self.ledger.arm(ip, ip, (), now);
        }
    }

    /// Queues a solicitation for an IPv6 address that turned up without one
    /// having been sent.
    ///
    /// Most IPv6 neighbours are found this way rather than by being asked. A
    /// segment carries a constant traffic of advertisements - neighbours
    /// resolving each other, announcing a new address, answering somebody else's
    /// question - and a promiscuous capture sees all of it. That is real evidence
    /// the host is there, and it is the mechanism behind most of what a sweep
    /// reports, but it is evidence of a conversation we were not part of: there
    /// is no probe of ours to measure against, so the host arrives with no round
    /// trip and no proof it is answering *now* rather than having answered
    /// somebody a moment ago.
    ///
    /// Asking directly costs one packet and settles both. The address came from
    /// the wire seconds ago, so unlike a neighbour-table entry it is almost
    /// certainly still live, and a solicitation to it is answered by the host
    /// itself rather than overheard.
    ///
    /// Bounded by [`solicited`](Self::solicited), so an address is asked about
    /// once however often it advertises itself.
    fn confirm(&mut self, address: IpAddr) {
        if !address.is_ipv6()
            || !matches!(self.scope, Scope::Sweep)
            || self.identity.link_local_ipv6.is_none()
        {
            return;
        }

        // Queued rather than sent here, so a confirmation leaves on the same
        // paced ticker every other probe does.
        self.ipv6.note_overheard(address);
    }

    /// Sends the one solicitation an overheard address gets, and notes when.
    fn send_confirmation(&mut self, target: IpAddr, now: Instant) {
        let (IpAddr::V6(target_v6), Some(source_v6)) = (target, self.identity.link_local_ipv6)
        else {
            return;
        };

        let packet =
            protocol::ndp::create_neighbor_solicitation(&self.identity.mac, &source_v6, target_v6);
        self.emit(&packet, "confirming solicitation");
        self.ipv6.record_confirmation_sent(target, now);
        info!(
            verbosity = 2,
            "Asked {target} directly, having only overheard it"
        );
    }

    /// Sends the all-nodes solicitation again.
    ///
    /// Unlike an ARP request this is never retired by an answer, so it is simply
    /// repeated a fixed number of times: a neighbour that missed the last one,
    /// or was asleep when it arrived, gets another chance to hear it.
    fn send_solicitation(&mut self, now: Instant) {
        let Some(link_local) = self.identity.link_local_ipv6 else {
            return;
        };

        let packet = protocol::icmp::create_all_nodes_echo_request_v6(
            &self.identity.mac,
            &link_local,
            self.ipv6.solicitation().identifier,
            self.ipv6.solicitation().next_sequence(),
        );
        self.emit(&packet, "all-nodes solicitation");
        self.ipv6.record_solicitation_sent(now);
    }

    /// Rebuilds and sends the probe for `target`, whichever kind its address
    /// calls for: an ARP request over IPv4, a neighbor solicitation over IPv6.
    ///
    /// Nothing about either is kept between attempts, because nothing needs to
    /// be: the frame is a function of this scanner's identity and the address
    /// being asked about, and rebuilding it is cheaper than holding a copy per
    /// outstanding probe.
    fn send_probe(&mut self, target: IpAddr, now: Instant) {
        let packet = match target {
            IpAddr::V4(target_v4) => {
                let Some(source_v4) = self.identity.ipv4 else {
                    return;
                };
                protocol::arp::create_packet(
                    &self.identity.mac,
                    MacAddr::broadcast(),
                    &source_v4,
                    target_v4,
                )
            }
            IpAddr::V6(target_v6) => {
                let Some(source_v6) = self.identity.link_local_ipv6 else {
                    return;
                };
                protocol::ndp::create_neighbor_solicitation(
                    &self.identity.mac,
                    &source_v6,
                    target_v6,
                )
            }
        };

        self.emit(&packet, "probe");
        if target.is_ipv6() {
            self.ipv6.record_asked(target, now);
        } else {
            self.ledger.arm(target, target, (), now);
        }
    }

    /// Takes the IPv6 addresses an overheard mDNS message names as leads,
    /// returning whether the frame was one.
    ///
    /// A segment announces itself constantly and this scanner's capture is
    /// promiscuous, so these addresses already arrive here.
    /// The hostname resolver caches mDNS records too, but applies them to hosts
    /// *already in the store* — a record naming an address nothing has answered
    /// for goes nowhere there.
    ///
    /// They arrive as candidates, never as hosts. An mDNS record is a claim
    /// somebody else made, possibly some time ago and possibly about an address
    /// that has since moved — the same standing as a neighbour-table entry, and
    /// it earns its place in the report the same way, by answering a
    /// solicitation now. [`confirm`](Self::confirm) is that mechanism and
    /// already bounds itself to one solicitation per address.
    ///
    /// The sender is deliberately not credited either. A frame off the segment
    /// does prove its sender exists, but crediting a host to "was chatty on
    /// mDNS" attributes it to a mechanism that did not find it, which is the
    /// distinction [`Icmpv6EchoProtocol`] is careful about for the same reason.
    ///
    /// Nothing is taken once the sweep has run its course. Each confirmation
    /// holds the run open for a reply, so a segment that keeps talking could
    /// otherwise keep extending it — and a lead that arrives after the sweep
    /// would have ended belongs to the next scan.
    fn absorb_mdns(&mut self, frame: &EthernetPacket) -> bool {
        let Some(payload) = protocol::ip::udp_payload_from_eth(frame, protocol::mdns::PORT) else {
            return false;
        };
        if self.deadline.has_expired() {
            return true;
        }

        let Ok(hosts) = protocol::mdns::extract_hosts(payload) else {
            return true;
        };

        for host in hosts {
            for ip in host.ips {
                if ip.is_ipv6() && !self.ipv6.is_solicited(&ip) {
                    info!(
                        verbosity = 2,
                        "mDNS named {ip} as {}, which nothing has answered for", host.hostname
                    );
                    self.confirm(ip);
                }
            }
        }

        true
    }

    /// Queues everything due to be asked again.
    ///
    /// An address that has run out of attempts needs nothing recorded: a host
    /// that never answered is one this sweep does not report, and the ledger
    /// emptying is part of what tells the loop it is finished.
    fn service_retries(&mut self, now: Instant) {
        // Taken so each ledger can borrow `self` mutably in turn; the buffer
        // itself is reused, so this costs no allocation.
        let mut due = std::mem::take(&mut self.due);

        self.ledger.drain_due(now, &mut due);
        self.ipv6.drain_due(now, &mut due);
        for event in due.drain(..) {
            if let Due::Retry { key, .. } = event {
                self.retries.push_back(key);
            }
        }

        self.due = due;
    }

    /// Retires the probe for `address` from whichever ledger owns its family.
    fn resolve_probe(
        &mut self,
        address: &IpAddr,
        now: Instant,
    ) -> Option<crate::scanner::pacing::retry::Resolution> {
        if address.is_ipv6() {
            self.ipv6.resolve(address, now)
        } else {
            self.ledger.resolve(address, None, now)
        }
    }

    /// Whether the sweep has nothing left to send and nothing left to wait for.
    fn idle(&self, now: Instant) -> bool {
        self.retries.is_empty() && self.ledger.is_empty() && self.ipv6.is_idle(now)
    }

    /// How long the loop may sleep once it has stopped sending: until the
    /// sweep's next checkpoint, until the next address is due to be asked again,
    /// or until the solicitation's schedule next needs attention - whichever
    /// comes first.
    fn tick_delay(&self, now: Instant) -> Duration {
        let mut delay = self.deadline.time_until_next_tick();
        for wakeup in [self.ledger.next_due(), self.ipv6.next_wakeup()]
            .into_iter()
            .flatten()
        {
            delay = delay.min(wakeup.saturating_duration_since(now));
        }
        delay
    }

    /// Validates an incoming frame, then handles a discovery reply in two steps:
    /// working out what it means, and recording that in shared scan state.
    fn process_eth_packet(&mut self, bytes: &[u8], now: Instant) -> anyhow::Result<()> {
        let eth_frame: EthernetPacket = ethernet::get_packet_from_u8(bytes)?;

        let source_mac = eth_frame.get_source();
        if source_mac == self.identity.mac {
            self.audit.record_off_target();
            return Err(FrameRejected::SelfSourcedPacket.into());
        }

        let source_addr: IpAddr = protocol::get_ip_addr_from_eth(&eth_frame)?;

        if self.absorb_mdns(&eth_frame) {
            return Ok(());
        }

        let Some((matched, protocol)) = self.interpret_response(&eth_frame) else {
            // Common in promiscuous mode: traffic between other hosts, or
            // forwarded through a router. Not this scan's, and not a fault.
            self.audit.record_off_target();
            return Ok(());
        };

        // Which address this reply is *about*, which is not always where it came
        // from. A neighbor advertisement names its subject, and a host with
        // several addresses answers from whichever its stack prefers - so the
        // claim has to be read before the frame is judged, or a reply to a probe
        // this scan sent is discarded for naming an address nobody asked about.
        let subject = match matched {
            ProtocolMatch::Solicited(Some(claimed)) => claimed,
            _ => source_addr,
        };

        // A targeted run records only its exact targets; a sweep records every
        // in-range IPv4 responder plus any IPv6 neighbor (linked by MAC).
        let out_of_range = match self.scope {
            Scope::Targeted => !self.ip_set.contains(&subject),
            Scope::Sweep => subject.is_ipv4() && !self.ip_set.contains(&subject),
        };
        if out_of_range {
            self.audit.record_off_target();
            return Err(FrameRejected::AddressOutOfRange(subject).into());
        }

        if subject != source_addr {
            info!(
                verbosity = 2,
                "{subject} answered from {source_addr}, which is another of its addresses"
            );
        }

        // Which send the reply answered, where the wire can say. Set inside the
        // one arm that can know it rather than threaded through the match: the
        // all-nodes echo is timed against a request it names, but that request
        // was put to the whole segment and answers no address's own probe.
        let mut answered_attempt = None;

        let rtt = match matched {
            // `interpret_response` returns `None` rather than this, so the arm
            // exists only to satisfy the match.
            ProtocolMatch::Unhandled => return Ok(()),
            // The reply retires this address's own probe, and measures it if
            // the ledger can say which attempt was answered.
            //
            // The two ways that fails are worth telling apart out loud, because
            // from the outside they look identical - a host with no latency
            // beside it - and they call for opposite responses. One is a probe
            // this scan never had outstanding, which means the reply answered
            // somebody else's question or arrived after we gave up. The other is
            // Karn's rule: the address was asked more than once, consecutive
            // probes are identical on the wire, and the reply cannot say which
            // it answers.
            ProtocolMatch::Solicited(_) => match self.resolve_probe(&subject, now) {
                Some(resolution) => {
                    answered_attempt = resolution.answered_attempt;
                    if resolution.rtt.is_none() {
                        info!(
                            verbosity = 2,
                            "{subject} answered over {protocol:?} after {} attempts, so it is not timed{}",
                            resolution.attempts,
                            self.ipv6.since_first_asked(&subject, now)
                        );
                    }
                    resolution.rtt.map(|rtt| (rtt, RttSource::Direct))
                }
                // Not in the ledger, so either it answers the one confirmation
                // an overheard address gets - unambiguous, because there is only
                // ever one - or it is a neighbour talking to somebody else,
                // which is worth asking about directly.
                None => match self.ipv6.take_confirmation_rtt(&subject, now) {
                    Some(rtt) => Some((rtt, RttSource::Direct)),
                    None => {
                        info!(
                            verbosity = 2,
                            "{subject} answered over {protocol:?} with no probe of ours outstanding{}",
                            self.ipv6.since_first_asked(&subject, now)
                        );
                        self.confirm(subject);
                        None
                    }
                },
            },
            // Measured against the exact request it answers, which the echoed
            // identifier and sequence name outright. That is what a neighbor
            // advertisement can never do, and it is why this probe is timed at
            // all: a neighbour that wakes in time for the third request is
            // measured against the third rather than the first. Several
            // neighbours answering the same request each get their own
            // measurement from it, because a segment-wide question is not used
            // up by whoever replies first.
            //
            // Recorded as [`RttSource::SegmentWide`], because knowing *which*
            // request was answered does not make the interval a clean round
            // trip: a node answering the whole segment waits before it does, so
            // this is an upper bound and is reported only by a host that
            // produced nothing better.
            //
            // A token this scan never sent belongs to somebody else's ping, and
            // a reply with no request on record cannot be an answer to one of
            // ours at all.
            ProtocolMatch::AllNodes {
                identifier,
                sequence,
            } => {
                if self.ipv6.solicitation().nothing_sent() {
                    return Err(FrameRejected::UnmappedRttSource(subject).into());
                }
                match self.ipv6.solicitation().sent_at(identifier, sequence) {
                    Some(sent_at) => Some((
                        now.saturating_duration_since(sent_at),
                        RttSource::SegmentWide,
                    )),
                    None => {
                        info!(
                            verbosity = 2,
                            "{subject} answered an echo request that was not ours, so it is not timed"
                        );
                        None
                    }
                }
            }
        };

        if self.ip_set.contains(&subject) {
            self.responded.insert(subject);
        }
        self.record_response(source_mac, subject, rtt, protocol.clone(), answered_attempt);

        // The address the reply came *from* belongs to the same host and is just
        // as real, so it is recorded too - but only after the subject, which is
        // what keys the host. Filing it under an address the scan never asked
        // about is how a phone solicited at one address came back reported under
        // another.
        if subject != source_addr {
            self.record_response(source_mac, source_addr, None, protocol, None);
        }

        Ok(())
    }

    /// Whether every target address has answered, which is a question only a
    /// [`Scope::Targeted`] run can ask.
    ///
    /// A sweep counts only in-range IPv4 addresses as responders — an IPv6
    /// neighbour found through the all-nodes echo was never in the range — so
    /// comparing that count against the whole target set asks whether the IPv4
    /// half is done and then stops the IPv6 half on the answer. On a wide range
    /// it never trips and the bug stays hidden; on a handful of addresses that
    /// all answer, the sweep exits with advertisements still in the receive
    /// queue.
    ///
    /// It is also the difference between a sweep of a link with no IPv4 at all
    /// and no sweep whatsoever: with an empty target set the comparison is
    /// `0 >= 0`, true on the first iteration, so the run ends before the echo it
    /// exists to send can be answered.
    fn all_targets_responded(&self) -> bool {
        matches!(self.scope, Scope::Targeted) && self.responded.len() as u128 >= self.ip_set.len()
    }

    /// Tries each configured [`DiscoveryProtocol`] against `frame` in turn.
    ///
    /// Returns the claiming protocol's verdict together with the evidence it
    /// counts as, or `None` when no protocol recognized the frame as a discovery
    /// response, or when one recognized it but failed to interpret it. Either
    /// way the frame carries no reliable information about who sent it and must
    /// not be attributed to any host. Seeing a frame that no protocol
    /// claims is common in promiscuous mode: it may be LAN traffic between other
    /// hosts, or traffic forwarded through a router rather than sent directly,
    /// whose Ethernet source is the router itself and not the host the IP packet
    /// originated from.
    fn interpret_response(
        &mut self,
        frame: &EthernetPacket,
    ) -> Option<(ProtocolMatch, StatusProtocol)> {
        for protocol in &self.protocols {
            match protocol.interpret(frame) {
                Ok(ProtocolMatch::Unhandled) => continue,
                Ok(matched) => return Some((matched, protocol.status_protocol())),
                Err(e) => {
                    error!(verbosity = 1, "Failed to interpret discovery response: {e}");
                    return None;
                }
            }
        }

        None
    }

    /// Applies a discovery response to shared scan state. It creates or updates
    /// the responding host, records what the reply proves about its liveness,
    /// feeds the adaptive deadline, and notifies both the scan's event channel
    /// and the hostname resolver of anything new.
    ///
    /// `protocol` is the evidence the claiming [`DiscoveryProtocol`] stands
    /// behind. Every frame reaching here came off the local segment with the
    /// host's own MAC as its Ethernet source, which is the strongest liveness
    /// evidence the engine can obtain: the host is provably present, so the
    /// status is [`HostStatus::Up`] regardless of which protocol claimed it and
    /// regardless of whether the reply could be timed.
    ///
    /// `rtt` carries what kind of question produced it, because the host is what
    /// ranks the two: a reply to a segment-wide probe is an upper bound rather
    /// than a round trip, and pooling it with a directed probe's answer is what
    /// reported a router that answers in 5 ms as answering in 37.
    fn record_response(
        &mut self,
        source_mac: MacAddr,
        source_addr: IpAddr,
        rtt: Option<(Duration, RttSource)>,
        protocol: StatusProtocol,
        answered_attempt: Option<u8>,
    ) {
        // Whether *this scanner* has seen this device before, which is not the
        // same question as whether the store has a host at this address. In a
        // port-scan phase local discovery runs as enrichment beside the port
        // scanner, so the host usually exists already and `write_host` reports
        // nothing new - crediting the audit on that would report a sweep that
        // found nothing while its own log said a neighbour answered.
        //
        // Keyed on the MAC rather than the address because a device answering
        // at three addresses is one device found once, which is the unit the
        // roster and the audit both count in.
        let first_sighting = !self.mac_to_ip.contains_key(&source_mac);
        let primary_ip = *self.mac_to_ip.entry(source_mac).or_insert(source_addr);

        // Host mutation only. `write_host` owns the guard, the drop-before-emit
        // ordering, and the event. `is_new_ip` is returned for the DNS decision
        // below, which runs after the guard is released, as does the deadline
        // bookkeeping.
        let mut is_new_ip = false;
        let is_new_host = self.ctx.write_host(primary_ip, |host| {
            // Recorded whether we just created the host or the port scanner
            // created it first, so enrichment order doesn't decide whether a MAC
            // is recorded. Repeating one already on record refreshes its
            // last-seen time, which is what `HardwareInfo` keeps them for.
            host.record_mac(source_mac.into_core());
            host.set_zone(self.identity.zone.clone());

            // The protocol name is the whole of the evidence here - a reply came
            // off the segment carrying this host's own MAC - so there is nothing
            // a details string would add that `arp` or `ndp` does not already
            // say.
            let was_up = host.status().is_up();
            host.record_evidence(HostStatus::Up, StatusReason::basic(protocol.clone()));

            let mut changed = rtt.is_some() || !was_up;
            match rtt {
                Some((rtt, RttSource::Direct)) => host.add_rtt(rtt),
                Some((rtt, RttSource::SegmentWide)) => host.add_segment_wide_rtt(rtt),
                None => {}
            }

            is_new_ip = !host.ips().contains(&source_addr);
            // The rule for which address names a dual-stack host lives on the
            // host, not here: this scanner is one of several that learn a new
            // address for one, and a rule spread across their receive loops is
            // one each of them can disagree about.
            changed |= host.consider_primary_ip(source_addr) || is_new_ip;

            changed
        });

        if is_new_host {
            self.deadline.mark_activity();
        }
        if first_sighting {
            self.audit.record_host_found(answered_attempt);
        }
        if rtt.is_none() {
            // Alive, and no round trip to show for it: a reply to a probe this
            // scan no longer had outstanding, or one Karn's rule refuses to
            // time. Both are worth counting separately from the finding itself.
            self.audit.record_reply_without_rtt();
        }

        if let Some((rtt, source)) = rtt {
            // Named in the log, because several neighbours reporting the same
            // figure to the millisecond is a property of the probe rather than
            // of the network, and a reader who cannot tell the two kinds of
            // sample apart has no way to know that.
            let asked = match source {
                RttSource::Direct => "",
                RttSource::SegmentWide => " to the all-nodes echo",
            };
            info!(
                incoming,
                verbosity = 2,
                "{source_addr} responded in {}ms{asked}",
                rtt.as_millis()
            );
            // Both kinds steer the deadline, which is asking a different
            // question from the one a reported latency answers: how long this
            // sweep should keep listening. A neighbour that takes 200 ms to
            // answer the segment is 200 ms this scan has to stay open for,
            // whatever inflated it.
            self.deadline.record_rtt(rtt);
        }

        if (is_new_host || is_new_ip)
            && let Some(tx) = &self.dns_tx
        {
            let _ = tx.send(source_addr);
        }
    }
}
