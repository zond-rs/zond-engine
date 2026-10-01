// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Local Area Network Scanner
//!
//! Discovers hosts on the same network segment by sending ARP requests (IPv4)
//! and ICMPv6 all-nodes solicitations (IPv6), then listening for replies, which
//! the `frames` module recognizes.
//!
//! An ARP request asks one address and is retired by its answer, so it is
//! retransmitted through the shared `ProbeLedger`. The solicitation asks the
//! whole segment, so it is repeated a few times and given a window to be
//! answered in.
//!
//! Requires root privileges: it builds and captures raw Ethernet frames,
//! bypassing the operating system's IP stack.

mod ipv6;
mod probes;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::model::mac::MacAddr;
use crate::protocols::ethernet::Frame;
use async_trait::async_trait;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::Interval;

use crate::config::RetryConfig;
use crate::info;
use crate::journal::settle::{Outcome, Settled};
use crate::logging::error;
use crate::model::host::telemetry::RttSource;
use crate::model::host::{HostStatus, NetworkRole, StatusProtocol, StatusReason};
use crate::model::ip::scoped::Zone;
use crate::model::ip::set::IpSet;
use crate::protocols::{self as protocol, ethernet};
use crate::report::ScannerKind;
use crate::report::{Attachment, AttachmentSource, StopReason};
use crate::scanner::dispatcher::WalkOrder;
use crate::scanner::pacing::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::scanner::pacing::retry::{ProbeLedger, RetryPolicy};
use crate::scanner::pacing::timer::ScanBudget;
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::sweep::HostSweep;
use crate::scanner::strategy::{HostScanner, StrategyError};
use crate::system::interface::{self, Link};
use crate::transport::capture::CapturedFrame;
use crate::transport::channel::{self, EthernetHandle};
use crate::transport::frame::LinkType;
use crate::transport::neighbor;

use crate::scanner::strategy::frames::{self, DiscoveryProtocol, ProtocolMatch, Reading};
use ipv6::Ipv6Discovery;

/// What a local sweep's capture admits, as a `libpcap` filter expression.
///
/// The union of every [`DiscoveryProtocol`]'s clause and the
/// [`ABSORBED_CLAUSES`]; see [`DiscoveryProtocol::capture_clause`]. Filtering
/// in the kernel spares copying every frame on a busy link to userspace.
///
/// 802.1Q-tagged frames are not admitted; the frame reader takes the EtherType
/// from its fixed offset and would reject them anyway.
///
/// One expression, unlike a listener's set of per-link alternatives: the
/// Ethernet clauses make a link without Ethernet headers refuse the filter,
/// where it would otherwise hear nothing readable and report an empty segment.
/// See [`CaptureFilter`](crate::transport::capture::CaptureFilter).
fn sweep_filter() -> String {
    let mut clauses: Vec<&'static str> = frames::sweep_protocols()
        .iter()
        .map(|protocol| protocol.capture_clause())
        .collect();

    clauses.extend(ABSORBED_CLAUSES);

    // The three IPv6 readers share `icmp6`.
    clauses.sort_unstable();
    clauses.dedup();

    clauses.join(" or ")
}

/// The clauses for readers that conclude no liveness, and so have no
/// [`DiscoveryProtocol`] to declare them:
///
/// - **mDNS** (`absorb_mdns`) reads names but credits nobody with being there,
///   since the announcer is often not the machine announced.
/// - **LLDP** and **CDP** (`absorb_announcement`) describe the equipment this
///   machine is plugged into. See [`Attachment`].
///
/// A new reader of this kind must add its clause here; nothing else will.
///
/// CDP rides 802.3 framing with no EtherType, so its clause matches the group
/// address, which also carries VTP, DTP and PAgP that the reader declines.
const ABSORBED_CLAUSES: [&str; 3] = [
    "(udp port 5353)",
    "(ether proto 0x88cc)",
    "(ether dst 01:00:0c:cc:cc:cc)",
];

/// Outstanding ARP requests and the schedule they are retried on.
///
/// The attempt token is `()`: consecutive requests for one address are
/// identical on the wire, so under Karn's rule a retried one is not measured.
type Ledger = ProbeLedger<IpAddr, ()>;

/// How an ARP request is retransmitted.
///
/// ARP is lost on a busy segment more often than expected: requests are
/// broadcast, and a loaded switch drops broadcast first.
///
/// Until the segment answers anything, an address is asked on the kernel's
/// schedule: three requests a second apart, silent once the third has gone a
/// second unanswered. That is the evidence the kernel and the frame path's
/// address resolution take before giving up on a neighbour. Judged sooner, a
/// neighbour the port scans would resolve is written off here, and a late
/// answer lands in the next process's capture, so runs disagree.
///
/// Once the segment answers, its round trip governs; a wired neighbour answers
/// in well under a millisecond, so silent addresses settle in a fraction of a
/// second. Only a sweep that hears nothing pays the full second.
///
/// No silent-host rule: each address is probed once, so no host accumulates
/// the exhausted probes that rule counts.
const RETRY_POLICY: RetryPolicy = RetryPolicy::new(
    3,
    Duration::from_secs(1),
    Duration::from_millis(25),
    Duration::from_secs(1),
    2.0,
    0.2,
    None,
);

/// How many machines may declare what they are before this scanner knows which
/// hosts they are.
///
/// Router advertisements and DHCP replies are unsolicited, so a neighbour
/// sending them from a new hardware address each time could otherwise grow
/// this record without limit. Sixty-four exceeds any real segment's routers and
/// DHCP servers. Past it, a declaration from an unknown machine is dropped like
/// any other off-target frame.
const MAX_DECLARING_MACS: usize = 64;

/// Why a captured frame is not a discovery finding.
///
/// A promiscuous capture sees the whole segment, so rejection is the normal
/// case. Each check is named so a missing host can be traced to the one that
/// dropped its frame. Unlike [`StrategyError`], not a failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FrameRejected {
    #[error("unmapped RTT source: {0}")]
    UnmappedRttSource(IpAddr),
    #[error("packet originated from this host")]
    SelfSourcedPacket,
    #[error("{0} is not in the scanned range")]
    AddressOutOfRange(IpAddr),
    #[error("the frame came off a link that prepends no Ethernet header")]
    UnreadableLink,
    /// The bytes did not hold the headers they were read for.
    ///
    /// An ordinary arrival on a promiscuous capture. Carries the parser's
    /// reason, which names the header that ran out.
    #[error("{0}")]
    Malformed(#[from] crate::protocols::error::PacketError),
}

/// How long a discovery sweep runs and how it adapts, assuming a local segment
/// with sub-millisecond round trips.
///
/// The hard ceiling only bounds small ranges. Sends are paced at
/// [`SEND_INTERVAL`] per address per attempt, and a ceiling below that would
/// stop the sweep mid-send, leaving unprobed addresses indistinguishable from
/// empty ones. [`deadline_for`] raises it to what the range needs.
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
/// A slower pace measurably raises the share of first attempts answered on
/// wireless, where group-addressed frames are expensive. But [`RETRY_POLICY`]
/// recovers unanswered first attempts, so the gain is a few more timed round
/// trips, not more hosts, at several times the scan duration, since the send
/// phase drags the adaptive deadline along.
///
/// When measuring changes here: run-to-run variance on a segment of sleeping
/// wireless devices swamps small differences, so compare arms only within one
/// block, and judge by hosts found and timed per second of scan.
const SEND_INTERVAL: Duration = Duration::from_micros(1000);

/// The deadline a sweep of `target_count` addresses runs under when its ARP
/// requests are retried on `retry`, in a scan that keeps `gap` between probes
/// at one host (the longer of its two gaps, since every probe waits out both)
/// and `scan_gap` between any two probes.
///
/// It must outlive both the probe schedule and the send pacing, which a large
/// range would push past [`DEADLINE_CONFIG`]'s ceiling.
fn deadline_for(
    target_count: usize,
    retry: &RetryPolicy,
    gap: Option<Duration>,
    scan_gap: Option<Duration>,
) -> AdaptiveDeadlineConfig {
    // The longer of the ARP and NDP schedules, each at its longest: every
    // attempt at its ceiling (a slow segment can time silent addresses up to
    // it) or at the gap where longer, since a repeat waits the gap out with
    // its probe's clock stopped.
    let probe_lifetime = retry
        .longest_spaced_probe_lifetime(gap)
        .max(ipv6::NDP_RETRY_POLICY.longest_spaced_probe_lifetime(gap));

    // Pacing: every frame, repeats included, leaves through one ticker, so a
    // silent address costs one tick per attempt. A scan-wide gap slows the
    // ticker. The segment-wide frames are a fixed count, added once.
    let attempts = retry.max_attempts.max(ipv6::NDP_RETRY_POLICY.max_attempts);
    let tick = SEND_INTERVAL.max(scan_gap.unwrap_or_default());
    let group_frames = scan_gap.unwrap_or_default().saturating_mul(GROUP_FRAMES);
    DEADLINE_CONFIG
        .allowing_for(probe_lifetime.saturating_add(group_frames))
        .allowing_pace_of(tick.saturating_mul(u32::from(attempts)), target_count)
}

/// How many group-addressed frames a sweep sends: the two segment questions
/// and every all-nodes echo.
const GROUP_FRAMES: u32 = 2 + ipv6::SOLICITATION_ATTEMPTS as u32;

/// How much of the segment a [`LocalScanner`] run touches.
///
#[non_exhaustive]
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

/// The addresses this scanner speaks from on its interface, resolved once at
/// construction.
struct SourceIdentity {
    mac: MacAddr,
    ipv4: Option<Ipv4Addr>,
    link_local_ipv6: Option<Ipv6Addr>,
    /// The interface. Every link-local address this scanner records is valid
    /// on it alone, and later phases need the zone to use them; see
    /// [`ScopedIp`](crate::model::ip::scoped::ScopedIp).
    zone: Zone,
}

impl SourceIdentity {
    /// How the store keys a neighbour this scanner found.
    ///
    /// The interface is part of the key: `fe80::1` on `en0` and `fe80::1` on
    /// `en1` are two machines, and keyed by the bare address their records
    /// would merge.
    ///
    /// [`ScopedIp::scoped`](crate::model::ip::scoped::ScopedIp::scoped) drops
    /// the zone where it is not needed, so IPv4 and global IPv6 neighbours are
    /// keyed by the plain address.
    fn key_for(&self, addr: std::net::IpAddr) -> crate::model::ip::scoped::ScopedIp {
        crate::model::ip::scoped::ScopedIp::scoped(addr, self.zone.clone())
    }
    /// Picks the addresses this scanner will present as its own when probing
    /// `ip_set` from `intf`.
    ///
    /// For IPv4, an address in the targets' subnet, else the first non-loopback
    /// one. For IPv6, the link-local address, which the all-nodes probe is sent
    /// from.
    fn resolve(link: &Link, ip_set: &IpSet) -> Result<Self, StrategyError> {
        let mac = link.mac().ok_or_else(|| StrategyError::Interface {
            interface: link.name().to_owned(),
            reason: "it has no MAC address, and every probe here is an Ethernet frame",
        })?;

        let mut ipv4 = None;
        for held in link.addresses() {
            let IpAddr::V4(address) = held.address() else {
                continue;
            };
            if ipv4.is_none() && !address.is_loopback() {
                ipv4 = Some(address);
            }
            // A probe from the wrong subnet is answered where we do not listen.
            if ip_set
                .v4()
                .iter()
                .any(|range| held.contains(&IpAddr::V4(range.start_addr())))
            {
                ipv4 = Some(address);
                break;
            }
        }

        let link_local_ipv6 = link
            .ipv6()
            .map(|(address, _)| address)
            .find(Ipv6Addr::is_unicast_link_local);

        Ok(Self {
            mac,
            ipv4,
            link_local_ipv6,
            zone: link.zone(),
        })
    }
}

/// What a solicited reply proves about the probe it answers.
///
/// Either can be missing alone: a retried address names the send it settles
/// but not the interval, and a confirmation is timed with no ledger send to
/// retire.
struct ProbeCorrelation {
    /// The round trip, where one can be attributed to this reply.
    rtt: Option<(Duration, RttSource)>,
    /// Which of this address's sends the reply retires, where the ledger can
    /// say.
    answered_attempt: Option<u8>,
}

/// What one turn of the send ticker put on the wire.
enum Dispatched {
    /// A frame, of whichever kind was owed first.
    Sent,
    /// The iterator is empty: every address has been asked at least once.
    Drained,
    /// Nothing was due.
    Nothing,
}

/// Finds the hosts sharing one Ethernet segment, asking IPv4 addresses by ARP
/// and the IPv6 half of the segment by all-nodes solicitation.
///
/// Frames bypass the IP stack, so a run needs root and reaches only its
/// [`Link`]'s segment. The `DiscoveryProtocol` implementations in `frames`
/// interpret replies, and [`Scope`] decides whether a run probes the whole
/// segment or only the addresses it was handed.
pub struct LocalScanner {
    /// Shared state (host store, event channel, abort signal) of the scan.
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
    /// The outstanding ARP requests, the retry queue, what has answered and
    /// the run's counters, shared with the two routed sweeps.
    ///
    /// The NDP schedule is `ipv6`'s own, serviced through
    /// [`HostSweep::service_second_ledger`]: a mains-powered router answers a
    /// solicitation in 5 ms, a phone asleep on wifi in 400.
    sweep: HostSweep<()>,
    /// Where to forward newly discovered addresses for hostname
    /// resolution, if enabled.
    dns_tx: Option<UnboundedSender<IpAddr>>,
    /// Each MAC seen, to the first address observed from it, so a host with
    /// several addresses is recorded once.
    mac_to_ip: HashMap<MacAddr, IpAddr>,
    /// What a machine said it is, held by MAC until that MAC answers one of
    /// our probes.
    ///
    /// The segment-wide questions are answered from addresses the scan may not
    /// target (a router's link-local, a DHCP server outside the range). A
    /// declaration only lands on a record the scan built by asking, so a
    /// targeted run never gains hosts from it.
    ///
    /// Bounded by [`MAX_DECLARING_MACS`], since it grows from unsolicited
    /// traffic.
    declared: HashMap<MacAddr, HashSet<NetworkRole>>,
    /// Whether to sweep the segment or probe only the given targets.
    scope: Scope,
    /// Why the first frame that could not be put on the wire failed, if any did.
    ///
    /// Separates a link that refused writes from a scanner that could not
    /// build a packet. Only the first is kept, since the rest repeat it.
    send_failure: Option<String>,
    /// What this sweep has asked the IPv6 half of the segment, and what it is
    /// still waiting to hear back.
    ///
    ipv6: Ipv6Discovery,
    /// The link's prefixes, which say whether the routing table's refusal of
    /// an overheard address means anything; see [`confirm`](Self::confirm).
    prefixes: interface::OnLinkTable,
    /// Whether the routing table refuses an overheard address:
    /// [`interface::refuses_neighbour`], or a stub in tests.
    refuses: fn(IpAddr) -> bool,
    /// The questions put to the whole segment that have not left yet, in the
    /// order they are owed; see [`SegmentQuestion`].
    questions: VecDeque<SegmentQuestion>,
    /// First attempts the scan's probe gaps turned away, each sent once its
    /// address's slot is free. Dropped, an address would never be asked and
    /// would read as absent; the walk is a stream and cannot take it back.
    held_first: VecDeque<(Vec<u8>, IpAddr)>,
}

/// A question a sweep puts to the whole segment, sent once at its head.
///
/// Each is a frame to a group address, so it spends the scan-wide gap between
/// probes and no host's own; see [`ScanContext::claim_group_probe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegmentQuestion {
    /// Which machines route this segment; see
    /// [`router_solicitation`](LocalScanner::router_solicitation).
    Routers,
    /// Which machine configures it; see
    /// [`configuration_request`](LocalScanner::configuration_request).
    Configuration,
}

impl SegmentQuestion {
    /// The group the frame is addressed to, which its claim names.
    fn group(self) -> IpAddr {
        match self {
            // All-routers, link-local scope.
            Self::Routers => IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2)),
            Self::Configuration => IpAddr::V4(Ipv4Addr::BROADCAST),
        }
    }

    /// What a failed send of it is reported as.
    fn what(self) -> &'static str {
        match self {
            Self::Routers => "router solicitation",
            Self::Configuration => "dhcp inform",
        }
    }
}

/// The group the all-nodes solicitation is addressed to, which its claim on
/// the scan-wide gap names.
const ALL_NODES: IpAddr = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));

#[async_trait]
impl HostScanner for LocalScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::Local
    }

    async fn discover_hosts(&mut self) -> Result<(), StrategyError> {
        // Every reply records its sender's MAC vendor, so load the database now.
        crate::model::mac::load_vendors().await;
        // Start the clock after the load, which can take seconds on a loaded
        // machine, and after any delay between construction and running, or
        // the sweep spends its minimum runtime before reading a frame.
        self.deadline.start();
        let mut packet_iter = probes::eth_packet_iter(
            &self.identity.mac,
            &self.identity.ipv4,
            &self.identity.link_local_ipv6,
            &self.ip_set,
            WalkOrder::of(&self.ip_set, &self.ctx).as_ref(),
        );

        // The first all-nodes echo goes at the head of the sweep, so more of its
        // response window falls inside the scan. It is the only probe that
        // reaches an IPv6 neighbour at an unguessable address.
        if matches!(self.scope, Scope::Sweep) && self.identity.link_local_ipv6.is_some() {
            self.ipv6.arm_solicitation(Instant::now());

            // Only here does the phase cover the whole link, and the record
            // must say so for hosts no target set named.
            self.ctx.record_sweep(self.identity.zone.clone());
        }

        // Asked on every run, sweep or not, to find the router and the DHCP
        // server. A targeted run records nothing new from the answers, only
        // what their senders declare; see
        // [`note_declaration`](Self::note_declaration). A question the
        // scan-wide gap turns away waits at the head of the ticker's queue.
        while let Some(true) = self.ask_next_question() {}

        let mut sending_finished = false;
        let mut send_interval: Interval = tokio::time::interval(SEND_INTERVAL);
        // Otherwise an unpolled interval fires every missed tick at once,
        // bursting exactly when the queue is longest.
        send_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let reason = loop {
            let now = Instant::now();
            // Waiting answers first, so one that arrived before its timer fired
            // settles the probe; see the port scans' `read_waiting_replies`.
            self.read_waiting_frames();
            self.sweep.service_retries(&self.ctx, now);
            self.sweep
                .service_second_ledger(&self.ctx, self.ipv6.ledger_mut(), now);

            if let Some(reason) = self.stop_reason(now, sending_finished) {
                break reason;
            }

            // First attempts and repeats share one paced ticker.
            let sending = !sending_finished
                || !self.questions.is_empty()
                || !self.sweep.retries.is_empty()
                || self.ipv6.confirmations_pending()
                || self.ipv6.solicitation().is_due(now);
            let idle_delay = self.tick_delay(now);

            tokio::select! {
                pkt = self.eth_handle.rx.recv() => {
                    match pkt {
                        Some(frame) => {
                            self.sweep.audit.record_segment();
                            // When the capture took it; see
                            // `CapturedFrame::received_at`.
                            _ = self.process_eth_packet(&frame, frame.received_at);
                        }
                        None => break StopReason::StreamClosed,
                    }
                }

                _ = send_interval.tick(), if sending => {
                    let now = Instant::now();
                    match self.send_next(&mut packet_iter, sending_finished, now) {
                        Dispatched::Drained => sending_finished = true,
                        Dispatched::Sent | Dispatched::Nothing => {}
                    }
                }

                _ = tokio::time::sleep(idle_delay), if !sending => {}
            }
        };

        // Whatever the iterator and `held_first` still hold was never asked,
        // which the report must tell apart from unanswered.
        let unasked: Vec<IpAddr> = if sending_finished {
            Vec::new()
        } else {
            self.held_first
                .drain(..)
                .map(|(_, ip)| ip)
                .chain(packet_iter.map(|(_, ip)| ip))
                .collect()
        };
        self.report_outcome(reason, &unasked);
        Ok(())
    }
}

impl LocalScanner {
    /// A sweep for `ip_set` across the segment `link` is attached to, over a
    /// capture this constructor opens on that interface.
    ///
    /// `scope` decides whether the whole segment or only the given addresses
    /// are asked. Findings go to `ctx`, and each address to `dns_tx` for a
    /// reverse lookup if set. `retry` scales how often an unanswered ARP
    /// request is repeated, and with it the sweep's deadline.
    ///
    /// # Errors
    ///
    /// When the capture cannot be opened, or `link` has no MAC address.
    pub fn new(
        link: Link,
        ip_set: IpSet,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        scope: Scope,
        retry: RetryConfig,
    ) -> Result<Self, StrategyError> {
        let eth_handle: EthernetHandle = channel::start_capture(&link, &sweep_filter())?;
        Self::build(
            link,
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
    /// The source MAC and addresses still come from `link`, but nothing here
    /// touches the interface.
    ///
    /// With a synthetic channel (`EthernetHandle::from_parts`, behind the
    /// `test-support` feature) and a hand-built [`Link`], this drives ARP and
    /// NDP discovery against a simulated segment without privileges.
    ///
    /// # Errors
    ///
    /// When `link` has no MAC address.
    pub fn with_handle(
        link: Link,
        ip_set: IpSet,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        scope: Scope,
        eth_handle: EthernetHandle,
    ) -> Result<Self, StrategyError> {
        Self::build(link, ip_set, ctx, dns_tx, scope, eth_handle, RETRY_POLICY)
    }

    /// The common constructor. Takes the retry schedule because the deadline
    /// is derived from it.
    #[allow(clippy::too_many_arguments)]
    fn build(
        link: Link,
        ip_set: IpSet,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        scope: Scope,
        eth_handle: EthernetHandle,
        retry: RetryPolicy,
    ) -> Result<Self, StrategyError> {
        let identity = SourceIdentity::resolve(&link, &ip_set)?;

        // Saturating: a `/64` is `usize::MAX + 1` addresses, which a plain
        // cast would turn into zero targets and the smallest budget.
        let target_count = usize::try_from(ip_set.len()).unwrap_or(usize::MAX);
        let deadline = AdaptiveDeadline::new(
            deadline_for(
                target_count,
                &retry,
                ctx.probe_gap(),
                ctx.scan_probe_interval(),
            ),
            target_count,
        );

        Ok(Self {
            ctx,
            ip_set,
            identity,
            eth_handle,
            deadline,
            protocols: frames::sweep_protocols(),
            sweep: HostSweep::new(Ledger::new(retry, target_count)),
            dns_tx,
            mac_to_ip: HashMap::new(),
            declared: HashMap::new(),
            scope,
            ipv6: Ipv6Discovery::new(target_count),
            send_failure: None,
            prefixes: interface::OnLinkTable::from_links(std::slice::from_ref(&link)),
            refuses: interface::refuses_neighbour,
            questions: VecDeque::from([SegmentQuestion::Routers, SegmentQuestion::Configuration]),
            held_first: VecDeque::new(),
        })
    }

    /// Reads every frame already waiting in the capture stream, without
    /// waiting for more, bounded by what is queued on entry.
    ///
    /// A loop held up past a timeout wakes to the answer and the expired timer
    /// at once. Reading the answer first lets it settle and time the probe
    /// before the timer spends the last attempt.
    fn read_waiting_frames(&mut self) {
        let waiting = self.eth_handle.rx.len();
        for _ in 0..waiting {
            let Ok(frame) = self.eth_handle.rx.try_recv() else {
                // Empty, or closed, which the `select!` handles.
                return;
            };
            self.sweep.audit.record_segment();
            _ = self.process_eth_packet(&frame, frame.received_at);
        }
    }

    /// Why the loop should stop, if it should.
    ///
    /// An abort or an exhausted wall-clock budget is reported as such
    /// whatever state the sweep was in.
    ///
    /// A sweep with every first attempt sent and nothing outstanding stops as
    /// [`AttemptsSpent`](StopReason::AttemptsSpent) once the segment has been
    /// quiet for its silence tolerance or the hard deadline passes. Unlike the
    /// routed sweep it keeps listening that long. Only a sweep stopped with
    /// something unsent or outstanding reads
    /// [`DeadlineExpired`](StopReason::DeadlineExpired).
    fn stop_reason(&self, now: Instant, sending_finished: bool) -> Option<StopReason> {
        if let Some(cause) = self.ctx.handle.stopped() {
            return Some(cause.into());
        }
        if sending_finished && self.all_targets_responded() {
            return Some(StopReason::AllResponded);
        }
        // Silence means nothing while probes still wait on their timers.
        let spent = sending_finished && self.idle(now);
        if self.deadline.hard_deadline_passed() {
            return Some(if spent {
                StopReason::AttemptsSpent
            } else {
                StopReason::DeadlineExpired
            });
        }
        if spent && self.deadline.has_expired() {
            return Some(StopReason::AttemptsSpent);
        }

        None
    }

    /// Puts the next frame this sweep owes on the wire, and says which kind it
    /// was.
    ///
    /// Order: segment questions held back by a gap, then repeats, then the two
    /// IPv6 schedules, which have due times to keep, then first attempts.
    ///
    /// # Pacing
    ///
    /// A frame about one address (an ARP request, though broadcast, or a
    /// neighbour solicitation) is a probe at that address. One put to a group
    /// (the all-nodes echo, the segment questions) spends only the scan-wide
    /// gap; see [`ScanContext::claim_group_probe`].
    ///
    /// A slot is claimed just before sending. A frame turned away stays where
    /// it was owed: a repeat stays queued with its clock stopped, a
    /// confirmation stays queued, the all-nodes echo stays due, and a first
    /// attempt is held (see [`held_first`](Self::held_first)). Each address's
    /// slot is checked before choosing, so one held address does not stall the
    /// ticker. A frame the link refused gives its slot back.
    fn send_next(
        &mut self,
        packet_iter: &mut probes::PacketIter,
        sending_finished: bool,
        now: Instant,
    ) -> Dispatched {
        // Every frame spends the scan-wide gap.
        if self.ctx.group_probe_ready_at(now).is_some() {
            return Dispatched::Nothing;
        }
        match self.ask_next_question() {
            Some(true) => return Dispatched::Sent,
            Some(false) => return Dispatched::Nothing,
            None => {}
        }

        if let Some(target) = self.next_live_retry(now) {
            self.send_probe(target, now)
        } else if let Some(target) = self
            .ipv6
            .next_confirmation(|address| self.ctx.probe_ready_at(address, now).is_none())
        {
            self.send_confirmation(target, now)
        } else if self.ipv6.solicitation().is_due(now) {
            self.send_solicitation(now)
        } else if !sending_finished {
            self.send_first_attempt(packet_iter, now)
        } else {
            Dispatched::Nothing
        }
    }

    /// Sends the next first attempt: a held one whose address's slot is now
    /// free, or else the walk's next.
    ///
    /// Drained only once the walk is empty and nothing is held.
    fn send_first_attempt(
        &mut self,
        packet_iter: &mut probes::PacketIter,
        now: Instant,
    ) -> Dispatched {
        let ready = self
            .held_first
            .iter()
            .position(|(_, ip)| self.ctx.probe_ready_at(*ip, now).is_none());
        let next = match ready {
            Some(index) => self.held_first.remove(index),
            None => packet_iter.next(),
        };
        let Some((packet, ip)) = next else {
            return if self.held_first.is_empty() {
                Dispatched::Drained
            } else {
                Dispatched::Nothing
            };
        };

        // Turned away if another pass probed the address since it was read,
        // or for the walk's next, which was never checked.
        let Ok(claim) = self.ctx.claim_probe(ip) else {
            self.held_first.push_back((packet, ip));
            return Dispatched::Nothing;
        };
        // Armed only if the frame left, so an unsent probe earns no verdict.
        if self.emit(&packet, "first attempt") {
            self.record_probe(ip, Instant::now());
        } else {
            self.ctx.refund_probe(claim);
        }
        Dispatched::Sent
    }

    /// What the sweep leaves behind once the loop has stopped: the addresses it
    /// never settled, the questions that went unanswered, the frames that never
    /// left, and the counters a later phase reads.
    ///
    /// `unasked` is every address the sweep never sent a first attempt to.
    fn report_outcome(&mut self, reason: StopReason, unasked: &[IpAddr]) {
        // Addresses without a verdict, so a resumed sweep asks them again.
        let interrupted = self.sweep.ledger.drain_unresolved();
        self.ctx
            .record_address_outcomes(Outcome::Interrupted, interrupted.len() as u64);
        self.ctx
            .record_address_outcomes(Outcome::Unasked, unasked.len() as u64);

        // Unasked addresses narrow the result, so report a failure, unless the
        // caller aborted or set the budget and so knows why, as the routed
        // sweep decides.
        if !unasked.is_empty() && !matches!(reason, StopReason::Aborted | StopReason::TimedOut) {
            self.ctx.record_failure(
                ScannerKind::Local,
                format!(
                    "{} of {} addresses on {} were never asked: {reason} with them \
                     still queued",
                    unasked.len(),
                    self.ip_set.len(),
                    self.identity.zone,
                ),
            );
        }

        // Separates "none were sent" from "none came back".
        if self.ipv6.unanswered_confirmations() > 0 {
            info!(
                verbosity = 2,
                "{} of the addresses asked about directly never answered",
                self.ipv6.unanswered_confirmations()
            );
        }

        // Frames that never left look like hosts that found nothing in every
        // other number. Reported once, with a count and the first cause.
        if self.sweep.audit.sends_failed > 0 {
            self.ctx.record_failure(
                ScannerKind::Local,
                format!(
                    "{} of {} frames never reached {}, so those addresses are \
                     reported absent without having been asked: {}",
                    self.sweep.audit.sends_failed,
                    self.sweep.audit.sends_attempted,
                    self.identity.zone,
                    self.send_failure.as_deref().unwrap_or("cause unrecorded"),
                ),
            );
        }

        // Frames the kernel dropped, which otherwise look like hosts that never
        // answered. `None` for a synthetic stream.
        let capture = self.eth_handle.capture_counts();
        let targets = self.ip_set.len();
        self.sweep.report(
            &self.ctx,
            "local-discovery",
            ScannerKind::Local,
            targets,
            reason,
            capture,
        );
    }

    /// Puts one frame on the segment and records what actually happened to it.
    ///
    /// Every send goes through here, so the audit's counters cover every frame.
    /// Returns whether
    /// [`FrameSink::send_frame`](crate::transport::capture::FrameSink::send_frame)
    /// put the frame on the link.
    fn emit(&mut self, packet: &[u8], what: &str) -> bool {
        match self.eth_handle.tx.send_frame(packet) {
            Ok(()) => {
                self.sweep.audit.record_send(true);
                true
            }
            Err(reason) => {
                self.sweep.audit.record_send(false);
                self.send_failure
                    .get_or_insert_with(|| format!("{what}: {reason}"));
                false
            }
        }
    }

    /// Notes that a probe for `ip` has just gone out.
    ///
    /// For per-address probes only. The all-nodes echo records its own sends in
    /// [`Solicitation`](ipv6::Solicitation).
    fn record_probe(&mut self, ip: IpAddr, now: Instant) {
        if ip.is_ipv6() {
            self.ipv6.record_asked(ip, now);
        } else {
            self.sweep.ledger.arm(ip, ip, (), (), now);
        }
    }

    /// Queues a solicitation for an IPv6 address that turned up without one
    /// having been sent.
    ///
    /// Most IPv6 neighbours are found by overhearing their advertisements,
    /// which proves presence but yields no round trip. One direct solicitation
    /// measures it and confirms the host answers now.
    ///
    /// Bounded by [`solicited`](ipv6::Ipv6Discovery::solicited), so an address
    /// is asked about once however often it advertises.
    ///
    /// The one place a lead becomes a probe, so exclusions are checked here:
    /// these addresses never passed through the target list's filtering.
    fn confirm(&mut self, address: IpAddr) {
        if !address.is_ipv6()
            || !matches!(self.scope, Scope::Sweep)
            || self.identity.link_local_ipv6.is_none()
        {
            return;
        }

        if !self.ctx.may_probe(&address) {
            info!(
                verbosity = 2,
                "{address} was overheard and is excluded, so it is not asked about"
            );
            return;
        }
        // Nor one the routing table refuses, as for the sweep's own targets
        // (see `interface::refused_neighbours`). Only addresses on a prefix the
        // link holds are checked: there a refusal is host policy overriding the
        // connected route. Elsewhere the table answers about a path through a
        // router the solicitation does not take, so a host without IPv6 routes
        // would refuse every neighbour on another prefix. Link-local addresses
        // are on no such prefix, and Linux refuses a zoneless lookup with the
        // same error a blackhole route gives.
        let on_a_prefix = self.prefixes.source_for(address).is_some();
        if on_a_prefix && (self.refuses)(address) {
            info!(
                verbosity = 2,
                "{address} was overheard and a route refuses it, so it is not asked about"
            );
            return;
        }

        // Queued for the paced ticker.
        self.ipv6.note_overheard(address);
    }

    /// Sends the one solicitation an overheard address gets, and notes when.
    ///
    /// A probe at that address. One turned away by the probe gaps is queued
    /// again.
    fn send_confirmation(&mut self, target: IpAddr, now: Instant) -> Dispatched {
        let (IpAddr::V6(target_v6), Some(source_v6)) = (target, self.identity.link_local_ipv6)
        else {
            return Dispatched::Nothing;
        };

        let Ok(claim) = self.ctx.claim_probe(target) else {
            self.ipv6.requeue_confirmation(target);
            return Dispatched::Nothing;
        };
        let packet =
            protocol::ndp::build_neighbor_solicitation(self.identity.mac, source_v6, target_v6);
        if !self.emit(&packet, "confirming solicitation") {
            self.ctx.refund_probe(claim);
        }
        self.ipv6.record_confirmation_sent(target, now);
        info!(
            verbosity = 2,
            "asked {target} directly, having only overheard it"
        );
        Dispatched::Sent
    }

    /// Puts the first segment question still owed on the wire, if the
    /// scan-wide gap allows it.
    ///
    /// `None` when none is owed, `Some(false)` when the gap turned it away
    /// (it stays at the head of the queue), and `Some(true)` when it was sent
    /// or could not be built. Neither question is repeated, even when the link
    /// refused it; that gives its slot back.
    fn ask_next_question(&mut self) -> Option<bool> {
        let question = *self.questions.front()?;
        let packet = match question {
            SegmentQuestion::Routers => self.router_solicitation(),
            SegmentQuestion::Configuration => self.configuration_request(),
        };
        let Some(packet) = packet else {
            self.questions.pop_front();
            return Some(true);
        };
        let Ok(claim) = self.ctx.claim_group_probe(question.group()) else {
            return Some(false);
        };
        self.questions.pop_front();
        if !self.emit(&packet, question.what()) {
            self.ctx.refund_probe(claim);
        }
        Some(true)
    }

    /// Asks every router on the segment to say so, once, at the head of a
    /// sweep.
    ///
    /// Routers advertise unprompted every few minutes, longer than a sweep.
    /// The reply is claimed by
    /// [`RouterAdvertProtocol`](frames::RouterAdvertProtocol).
    ///
    /// Sent on any local run, unlike the all-nodes echo: an answer from an
    /// address nobody asked about only contributes a role, never a host, while
    /// everything the echo draws is a new address.
    ///
    /// Not repeated: a router answering any neighbour solicitation also
    /// declares itself in the reply's R flag.
    ///
    /// `None` for an interface with no link-local address.
    fn router_solicitation(&self) -> Option<Vec<u8>> {
        let link_local = self.identity.link_local_ipv6?;
        Some(protocol::ndp::build_router_solicitation(
            self.identity.mac,
            link_local,
        ))
    }

    /// Asks the segment which machine configures it, once.
    ///
    /// A `DHCPINFORM` asks for configuration without asking for an address, so
    /// every server answers and none reserves a lease. See
    /// [`dhcp`](crate::protocols::dhcp) for why this is a broadcast.
    ///
    /// Sent on any local run, on the same terms as the router solicitation. For
    /// a single-address scan the two questions triple the discovery phase's
    /// frames, from one to three.
    ///
    /// The reply is read off the capture by
    /// [`DhcpProtocol`](frames::DhcpProtocol), without binding UDP/68.
    ///
    /// `None` for an interface with no IPv4 address.
    fn configuration_request(&self) -> Option<Vec<u8>> {
        let source = self.identity.ipv4?;
        Some(protocol::dhcp::build_inform(self.identity.mac, source))
    }

    /// Sends the all-nodes solicitation again.
    ///
    /// No answer retires it, so it is repeated a fixed number of times for
    /// neighbours that missed or slept through the last. Spends only the
    /// scan-wide gap; one that gap turns away stays due.
    fn send_solicitation(&mut self, now: Instant) -> Dispatched {
        let Some(link_local) = self.identity.link_local_ipv6 else {
            return Dispatched::Nothing;
        };
        let Ok(claim) = self.ctx.claim_group_probe(ALL_NODES) else {
            return Dispatched::Nothing;
        };

        let packet = protocol::icmp::build_all_nodes_echo_request_v6(
            self.identity.mac,
            link_local,
            self.ipv6.solicitation().identifier,
            self.ipv6.solicitation().next_sequence(),
        );
        if !self.emit(&packet, "all-nodes solicitation") {
            self.ctx.refund_probe(claim);
        }
        self.ipv6.record_solicitation_sent(now);
        Dispatched::Sent
    }

    /// The first queued retry whose probe is still outstanding and whose
    /// address's slot is free, taken off the queue.
    ///
    /// One whose probe has left its ledger was answered while it waited and is
    /// dropped. One the probe gaps hold back stays queued with its clock
    /// stopped.
    fn next_live_retry(&mut self, now: Instant) -> Option<IpAddr> {
        let waiting = self.sweep.retries.len();
        for _ in 0..waiting {
            let target = self.sweep.retries.pop_front()?;
            let outstanding = if target.is_ipv6() {
                self.ipv6.ledger_mut().contains(&target)
            } else {
                self.sweep.ledger.contains(&target)
            };
            if !outstanding {
                continue;
            }
            if self.ctx.probe_ready_at(target, now).is_some() {
                self.sweep.retries.push_back(target);
                continue;
            }
            return Some(target);
        }
        None
    }

    /// Rebuilds and sends a queued retry for `target`, whichever kind its
    /// address calls for: an ARP request over IPv4, a neighbor solicitation
    /// over IPv6.
    ///
    /// Rebuilding is cheaper than keeping a copy per outstanding probe.
    ///
    /// The probe's clock, stopped while queued, restarts on its ledger: from
    /// the send, or from now for a frame that did not leave, whose attempt
    /// stays charged so the address still runs out on schedule. See
    /// [`HostSweep::retries`](crate::scanner::strategy::sweep::HostSweep::retries).
    ///
    /// If another pass took the slot meanwhile, the retry goes back to the
    /// queue. A frame that did not leave gives its slot back.
    fn send_probe(&mut self, target: IpAddr, now: Instant) -> Dispatched {
        let Ok(claim) = self.ctx.claim_probe(target) else {
            self.sweep.retries.push_back(target);
            return Dispatched::Nothing;
        };
        let packet = match target {
            IpAddr::V4(target_v4) => self
                .identity
                .ipv4
                .map(|source| protocol::arp::build_request(self.identity.mac, source, target_v4)),
            IpAddr::V6(target_v6) => self.identity.link_local_ipv6.map(|source| {
                protocol::ndp::build_neighbor_solicitation(self.identity.mac, source, target_v6)
            }),
        };

        let left = packet.is_some_and(|packet| self.emit(&packet, "probe"));
        let ledger = if target.is_ipv6() {
            self.ipv6.ledger_mut()
        } else {
            &mut self.sweep.ledger
        };
        if left {
            ledger.rearm(target, target, (), now);
        } else {
            ledger.resume(&target, now);
            self.ctx.refund_probe(claim);
        }
        Dispatched::Sent
    }

    /// Reads a switch's LLDP or CDP announcement of itself, returning whether
    /// the frame was one.
    ///
    /// Where this machine is plugged in is recorded unconditionally as an
    /// [`Attachment`] on the phase, even on a targeted run, since it is not a
    /// host. The roles the sender claims go through `note_declaration` and
    /// usually land nowhere, as a switch rarely holds an address on the segment
    /// it serves.
    ///
    /// An announcement does not prove its sender is a switch: anything on a
    /// link can emit one. The group address only shows it came from this link,
    /// since conforming bridges do not forward it.
    fn absorb_announcement(
        &mut self,
        frame: &Frame<'_>,
        source_mac: MacAddr,
        captured: &CapturedFrame,
    ) -> bool {
        let mut attachment = Attachment::new(
            captured.zone.clone(),
            AttachmentSource::Lldp,
            captured.observed_at,
        );
        let mut roles: Vec<NetworkRole> = Vec::new();

        if let Some(advertisement) = protocol::lldp::parse(frame) {
            attachment = attachment.with_device_mac(source_mac);

            if let Some(name) = advertisement.system_name {
                attachment = attachment.with_device_name(name);
            }
            if let Some(protocol::lldp::Identifier::Text(port)) = advertisement.port_id {
                attachment = attachment.with_port(port);
            }
            if let Some(vlan) = advertisement.port_vlan {
                attachment = attachment.with_native_vlan(vlan);
            }
            if let Some(address) = advertisement.management_address {
                attachment = attachment.with_management_address(address);
            }
            if let Some(capabilities) = advertisement.capabilities {
                if capabilities.is_bridge() {
                    roles.push(NetworkRole::Switch);
                }
                if capabilities.is_router() {
                    roles.push(NetworkRole::Router);
                }
            }
        } else if let Some(announcement) = protocol::cdp::parse(frame) {
            attachment = Attachment::new(
                captured.zone.clone(),
                AttachmentSource::Cdp,
                captured.observed_at,
            )
            .with_device_mac(source_mac);

            if let Some(name) = announcement.device_id {
                attachment = attachment.with_device_name(name);
            }
            if let Some(port) = announcement.port_id {
                attachment = attachment.with_port(port);
            }
            if let Some(vlan) = announcement.native_vlan {
                attachment = attachment.with_native_vlan(vlan);
            }
            if let Some(address) = announcement.address {
                attachment = attachment.with_management_address(address);
            }
            if let Some(capabilities) = announcement.capabilities {
                if capabilities.is_switch() {
                    roles.push(NetworkRole::Switch);
                }
                if capabilities.is_router() {
                    roles.push(NetworkRole::Router);
                }
            }
        } else {
            return false;
        }

        info!(
            verbosity = 1,
            "{} says this machine is on {}{}",
            self.identity.zone,
            attachment.device_name().unwrap_or("an unnamed device"),
            match attachment.port() {
                Some(port) => format!(" port {port}"),
                None => String::new(),
            },
        );

        self.ctx.record_attachment(attachment);
        for role in roles {
            self.note_declaration(source_mac, role);
        }

        true
    }

    /// Takes the IPv6 addresses an overheard mDNS message names as leads,
    /// returning whether the frame was mDNS.
    ///
    /// The hostname resolver applies mDNS records only to hosts already in the
    /// store. Here the addresses become candidates for [`confirm`](Self::confirm),
    /// never hosts, since a record may be stale. The sender is not credited
    /// either: being chatty on mDNS is not what found it.
    ///
    /// Nothing is taken once the deadline has expired, or a talkative segment
    /// could extend the run indefinitely through confirmations.
    fn absorb_mdns(&mut self, frame: &Frame<'_>) -> bool {
        let Some(payload) = protocol::ip::udp_payload(frame, protocol::mdns::PORT) else {
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

    /// Retires the probe for `address` from whichever ledger owns its family.
    fn resolve_probe(
        &mut self,
        address: &IpAddr,
        now: Instant,
    ) -> Option<crate::scanner::pacing::retry::Resolution> {
        if address.is_ipv6() {
            self.ipv6.resolve(address, now)
        } else {
            self.sweep.ledger.resolve(address, None, now)
        }
    }

    /// Whether an ARP frame is a reply sent to this scanner, the one kind that
    /// can answer the request it put to the frame's sender.
    ///
    /// A neighbour's own request, an announcement, or an overheard reply to
    /// another machine proves presence but would time the probe against an
    /// unrelated conversation.
    ///
    /// ARP carries no token, so a reply to another process on this machine is
    /// indistinguishable and accepted. The worst case is a round trip timed
    /// short, which later passes correct by retransmitting early. The patience
    /// of [`RETRY_POLICY`] keeps it rare.
    fn answers_our_request(&self, frame: &Frame<'_>) -> bool {
        frame.destination() == self.identity.mac
            && pnet_packet::arp::ArpPacket::new(frame.payload())
                .is_some_and(|arp| arp.get_operation() == pnet_packet::arp::ArpOperations::Reply)
    }

    /// Whether the sweep has nothing left to send and nothing left to wait for.
    fn idle(&self, now: Instant) -> bool {
        self.sweep.retries.is_empty() && self.sweep.ledger.is_empty() && self.ipv6.is_idle(now)
    }

    /// How long the loop may sleep once it has stopped sending: until the
    /// sweep's next checkpoint, the next retry, or the next IPv6 deadline,
    /// whichever comes first.
    fn tick_delay(&self, now: Instant) -> Duration {
        let mut delay = self.deadline.time_until_next_tick();
        for wakeup in [self.sweep.ledger.next_due(), self.ipv6.next_wakeup()]
            .into_iter()
            .flatten()
        {
            delay = delay.min(wakeup.saturating_duration_since(now));
        }
        delay
    }

    /// Validates an incoming frame, then handles a discovery reply in two steps:
    /// working out what it means, and recording that in shared scan state.
    fn process_eth_packet(
        &mut self,
        frame: &CapturedFrame,
        now: Instant,
    ) -> Result<(), FrameRejected> {
        // Only a synthetic stream can deliver this (`start_capture` refuses
        // such links), and its bytes read as Ethernet would invent a source.
        if frame.link != LinkType::Ethernet {
            self.sweep.audit.record_off_target();
            return Err(FrameRejected::UnreadableLink);
        }

        let eth_frame: Frame<'_> = ethernet::parse(&frame.bytes)?;

        let source_mac = eth_frame.source();
        if source_mac == self.identity.mac {
            self.sweep.audit.record_off_target();
            return Err(FrameRejected::SelfSourcedPacket);
        }

        // Before the address is read: LLDP and CDP carry no IP header, so
        // `source_address` refuses them.
        if self.absorb_announcement(&eth_frame, source_mac, frame) {
            return Ok(());
        }

        let source_addr: IpAddr = protocol::source_address(&eth_frame)?;

        if self.absorb_mdns(&eth_frame) {
            return Ok(());
        }

        let Some((reading, protocol)) = self.interpret_response(&eth_frame) else {
            // Other hosts' traffic, common in promiscuous mode.
            self.sweep.audit.record_off_target();
            return Ok(());
        };

        // The address the reply is about, which a neighbor advertisement names
        // and which may differ from its source. Read before the range check, or
        // the reply is rejected for its source address.
        let subject = match reading.matched {
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
            // A declared role (a router's link-local advertisement, a DHCP
            // server outside the range) is still filed by MAC, applied only if
            // the scan finds that machine by asking.
            if let Some(role) = reading.declared
                && self.note_declaration(source_mac, role)
            {
                return Ok(());
            }

            self.sweep.audit.record_off_target();
            return Err(FrameRejected::AddressOutOfRange(subject));
        }

        // Hand the IP-to-MAC pair to later passes so they need not resolve it
        // again by a broadcast the neighbour may miss.
        if protocol == StatusProtocol::Arp && subject.is_ipv4() {
            neighbor::learn_neighbor(self.identity.zone.name(), subject, source_mac);
        }

        if subject != source_addr {
            info!(
                verbosity = 2,
                "{subject} answered from {source_addr}, which is another of its addresses"
            );
        }

        // Which send the reply answered, where the wire can say; only a
        // solicited reply retires an address's own probe.
        let mut answered_attempt = None;

        // Only an ARP reply to this scanner answers its request; see
        // `answers_our_request`.
        let matched = match reading.matched {
            ProtocolMatch::Solicited(_)
                if protocol == StatusProtocol::Arp && !self.answers_our_request(&eth_frame) =>
            {
                ProtocolMatch::Unsolicited
            }
            matched => matched,
        };

        let rtt = match matched {
            // `interpret_response` returns `None` for this.
            ProtocolMatch::Unhandled => return Ok(()),
            ProtocolMatch::Solicited(_) => {
                let correlated = self.correlate_rtt(subject, &protocol, now);
                answered_attempt = correlated.answered_attempt;
                correlated.rtt
            }
            // Proof of presence only; any outstanding probe stays outstanding.
            // An IPv6 sender is asked directly to be measured; an IPv4 one is
            // measured by its own outstanding request.
            ProtocolMatch::Unsolicited => {
                self.confirm(subject);
                None
            }
            ProtocolMatch::AllNodes {
                identifier,
                sequence,
            } => self.match_solicitation(subject, identifier, sequence, now)?,
        };

        if self.ip_set.contains(&subject) {
            self.sweep.responded.insert(subject);
        }
        self.record_response(
            source_mac,
            subject,
            rtt,
            protocol.clone(),
            answered_attempt,
            reading.declared,
        );

        // The source address belongs to the same host, recorded after the
        // subject, which keys the host. Both reach the same record by MAC, so
        // the declaration went in once above.
        if subject != source_addr {
            self.record_response(source_mac, source_addr, None, protocol, None, None);
        }

        Ok(())
    }

    /// What a solicited reply from `subject` says about the send it answers:
    /// the round trip, and which attempt it retires.
    ///
    /// A missing round trip is logged with its cause, since the two look the
    /// same in the report: no probe outstanding (the reply answered someone
    /// else, or came after we gave up), or Karn's rule after a retry.
    ///
    /// An address with neither a probe nor a confirmation outstanding is asked
    /// directly, so its next reply can be measured.
    fn correlate_rtt(
        &mut self,
        subject: IpAddr,
        protocol: &StatusProtocol,
        now: Instant,
    ) -> ProbeCorrelation {
        match self.resolve_probe(&subject, now) {
            Some(resolution) => {
                if resolution.rtt.is_none() {
                    info!(
                        verbosity = 2,
                        "{subject} answered over {protocol:?} after {} attempts, so it is not timed{}",
                        resolution.attempts,
                        self.ipv6.since_first_asked(&subject, now)
                    );
                }
                ProbeCorrelation {
                    rtt: resolution.rtt.map(|rtt| (rtt, RttSource::Direct)),
                    answered_attempt: resolution.answered_attempt,
                }
            }
            // Either the answer to the address's single confirmation, or a
            // neighbour talking to someone else, worth asking directly.
            None => {
                let rtt = match self.ipv6.take_confirmation_rtt(&subject, now) {
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
                };
                ProbeCorrelation {
                    rtt,
                    answered_attempt: None,
                }
            }
        }
    }

    /// Which all-nodes echo request a reply answers, and how long that took.
    ///
    /// The echoed identifier and sequence name the request, so a neighbour
    /// that wakes for the third request is measured against the third. Every
    /// neighbour answering a request gets its own measurement.
    ///
    /// Reported as [`RttSource::SegmentWide`]: a node answering a multicast
    /// waits before replying, so this is an upper bound, used only for a host
    /// with nothing better.
    ///
    /// A foreign token is not timed. A reply before any request was sent is
    /// rejected.
    fn match_solicitation(
        &self,
        subject: IpAddr,
        identifier: u16,
        sequence: u16,
        now: Instant,
    ) -> Result<Option<(Duration, RttSource)>, FrameRejected> {
        if self.ipv6.solicitation().nothing_sent() {
            return Err(FrameRejected::UnmappedRttSource(subject));
        }

        let rtt = match self.ipv6.solicitation().sent_at(identifier, sequence) {
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
        };

        Ok(rtt)
    }

    /// Whether every target address has answered. Only a [`Scope::Targeted`]
    /// run can end this way.
    ///
    /// A sweep's responder count covers only in-range addresses, not the IPv6
    /// neighbours the all-nodes echo finds, so ending on it would cut the IPv6
    /// half short. With an empty target set it would end the sweep at once
    /// (`0 >= 0`) before the echo could be answered.
    fn all_targets_responded(&self) -> bool {
        matches!(self.scope, Scope::Targeted) && self.sweep.all_responded(self.ip_set.len())
    }

    /// Tries each configured [`DiscoveryProtocol`] against `frame` in turn.
    ///
    /// Returns the claiming protocol's reading and the evidence it counts as,
    /// or `None` when no protocol claimed the frame or the claiming one failed
    /// to parse it. Such a frame is attributed to no host. Unclaimed frames are
    /// common in promiscuous mode: traffic between other hosts, or forwarded
    /// traffic whose Ethernet source is a router.
    fn interpret_response(&mut self, frame: &Frame<'_>) -> Option<(Reading, StatusProtocol)> {
        for protocol in &self.protocols {
            match protocol.interpret(frame) {
                Ok(Reading {
                    matched: ProtocolMatch::Unhandled,
                    ..
                }) => continue,
                Ok(reading) => return Some((reading, protocol.status_protocol())),
                Err(e) => {
                    error!(verbosity = 3, "failed to interpret discovery response: {e}");
                    return None;
                }
            }
        }

        None
    }

    /// Files what a machine said it is, against the hardware address that said
    /// it.
    ///
    /// Returns whether the claim was kept.
    ///
    /// Applied at once if the MAC is known, held otherwise: a router answers a
    /// solicitation within half a second (RFC 4861 §6.2.6), usually before the
    /// paced ARP request that identifies it leaves.
    ///
    /// Never creates a host or records an address.
    fn note_declaration(&mut self, source_mac: MacAddr, role: NetworkRole) -> bool {
        if let Some(ip) = self.mac_to_ip.get(&source_mac).copied() {
            self.ctx.write_host(self.identity.key_for(ip), |host| {
                host.add_network_role(role);
                true
            });
            return true;
        }

        if self.declared.len() >= MAX_DECLARING_MACS && !self.declared.contains_key(&source_mac) {
            return false;
        }

        self.declared.entry(source_mac).or_default().insert(role);
        true
    }

    /// Applies a discovery response to shared scan state: creates or updates
    /// the host, records liveness, feeds the adaptive deadline, and notifies
    /// the event channel and hostname resolver of anything new.
    ///
    /// `protocol` is the claiming [`DiscoveryProtocol`]'s evidence. Every frame
    /// here came off the segment with the host's own MAC, so the status is
    /// [`HostStatus::Up`] whatever the protocol and whether or not it was timed.
    ///
    /// `rtt` carries its source so the host can rank samples: a segment-wide
    /// reply is an upper bound, and pooled with directed answers it can make a
    /// 5 ms router read as 37 ms.
    ///
    /// `declared` is the role the sender claimed in the frame, such as an
    /// advertisement's R flag.
    fn record_response(
        &mut self,
        source_mac: MacAddr,
        source_addr: IpAddr,
        rtt: Option<(Duration, RttSource)>,
        protocol: StatusProtocol,
        answered_attempt: Option<u8>,
        declared: Option<NetworkRole>,
    ) {
        // Whether this scanner has seen the device, by MAC: in a port-scan
        // phase the store usually holds the host already, and a device at
        // three addresses counts once.
        let first_sighting = !self.mac_to_ip.contains_key(&source_mac);
        let primary_ip = *self.mac_to_ip.entry(source_mac).or_insert(source_addr);

        // Roles declared before the host was known. The MAC is now in
        // `mac_to_ip`, so later declarations apply directly.
        let held = self.declared.remove(&source_mac);

        // `write_host` owns the guard and the event. The DNS and deadline work
        // below runs after the guard is released.
        let mut is_new_ip = false;
        let zone = self.identity.zone.clone();
        let is_new_host = self
            .ctx
            .write_host(self.identity.key_for(primary_ip), |host| {
                // Set explicitly: a host created from its IPv4 key is
                // unscoped, and its link-local would then be reported bare.
                // `set_zone` keeps the first value, so repeating is free.
                host.set_zone(zone.clone());

                // Repeating a known MAC refreshes its last-seen time.
                host.record_mac(source_mac);

                let was_up = host.status().is_up();
                host.record_evidence(HostStatus::Up, StatusReason::basic(protocol.clone()));

                let mut changed = rtt.is_some() || !was_up;
                for role in held.into_iter().flatten() {
                    changed |= host.add_network_role(role);
                }
                if let Some(role) = declared {
                    // A new role is news to watchers; a repeated one is not.
                    changed |= host.add_network_role(role);
                }
                match rtt {
                    Some((rtt, RttSource::Direct)) => {
                        host.add_rtt_from(rtt, protocol.clone());
                    }
                    Some((rtt, RttSource::SegmentWide)) => {
                        host.add_segment_wide_rtt_from(rtt, protocol.clone());
                    }
                    Some((rtt, RttSource::FirstToNeighbour)) => {
                        host.add_first_to_neighbour_rtt_from(rtt, protocol.clone());
                    }
                    None => {}
                }

                is_new_ip = !host.ips().contains(&source_addr);
                // The host decides which address names it, so every scanner
                // agrees.
                changed |= host.consider_primary_ip(source_addr) || is_new_ip;

                changed
            });
        // Settles the address that answered, not the host's primary, after the
        // answer is stored; see `ScanContext::record_outcome`.
        self.ctx.settle_address(source_addr, Settled::Answered);

        if is_new_host {
            self.deadline.mark_activity();
        }
        if first_sighting {
            self.sweep.audit.record_host_found(answered_attempt);
        }
        if rtt.is_none() {
            // No probe outstanding, or Karn's rule refused the sample.
            self.sweep.audit.record_reply_without_rtt();
        }

        if let Some((rtt, source)) = rtt {
            // Named, since many neighbours sharing one figure is a property of
            // the probe, not the network.
            let asked = match source {
                RttSource::Direct => "",
                RttSource::SegmentWide => " to the all-nodes echo",
                RttSource::FirstToNeighbour => " before it was resolved",
            };
            info!(
                incoming,
                verbosity = 2,
                "{source_addr} responded in {}ms{asked}",
                rtt.as_millis()
            );
            // Every kind steers the deadline: a slow answer is time the sweep
            // must stay open, whatever inflated it.
            self.deadline.record_rtt(rtt);
        }

        if (is_new_host || is_new_ip)
            && let Some(tx) = &self.dns_tx
        {
            let _ = tx.send(source_addr);
        }
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
    use crate::model::mac::MacAddr;
    use crate::scanner::strategy::frames::tests::{
        LOCAL_MAC, PEER_MAC, advertisement_body, arp_reply_frame, arp_request_frame,
        dhcp_reply_frame, echo_reply_frame, mdns_frame, ndp_frame,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// A sweep is given at least the time its ticker needs to send every
    /// attempt to every address: a frame per address per attempt at
    /// [`SEND_INTERVAL`].
    #[test]
    fn a_segment_sweep_outlasts_the_time_its_ticker_needs_to_send_every_attempt() {
        const SLASH_16: usize = 1 << 16;
        let thorough = RetryConfig {
            effort: crate::config::ScanEffort::Thorough,
            ..RetryConfig::default()
        };

        for (case, retry, attempts) in [
            ("by default", RetryConfig::default(), 3),
            ("at thorough", thorough, 5),
        ] {
            let needed = SEND_INTERVAL * (SLASH_16 as u32) * attempts;
            let given = deadline_for(SLASH_16, &RETRY_POLICY.configured(retry), None, None)
                .max_budget
                .for_target_count(SLASH_16);
            assert!(
                given >= needed,
                "a /16 {case}: needs {needed:?} to send every attempt and is given {given:?}"
            );
        }
    }

    /// Under a scan-wide gap, the sweep outlasts every attempt and every
    /// segment-wide frame sent that gap apart.
    #[test]
    fn a_scan_wide_gap_is_the_pace_of_a_segment_sweep() {
        let gap = Duration::from_secs(1);
        let targets = 256;
        let attempts = RETRY_POLICY
            .max_attempts
            .max(ipv6::NDP_RETRY_POLICY.max_attempts);
        let needed = gap * (u32::from(attempts) * targets as u32 + GROUP_FRAMES);
        let given = deadline_for(targets, &RETRY_POLICY, Some(gap), Some(gap))
            .max_budget
            .for_target_count(targets);
        assert!(
            given >= needed,
            "{targets} addresses asked {gap:?} apart take {needed:?} and the \
             sweep is given {given:?}"
        );
    }

    /// A sweep outlasts the longer of its two ledgers' schedules with every
    /// attempt at the retry ceiling, which a slow segment of sleeping wireless
    /// devices can reach.
    #[test]
    fn a_segment_sweep_outlasts_a_probe_timed_at_the_ceiling_on_every_attempt() {
        let thorough = RetryConfig {
            effort: crate::config::ScanEffort::Thorough,
            ..RetryConfig::default()
        };
        for (case, retry) in [
            ("by default", RetryConfig::default()),
            ("at thorough", thorough),
        ] {
            let arp = RETRY_POLICY.configured(retry);
            let needed = arp
                .longest_probe_lifetime()
                .max(ipv6::NDP_RETRY_POLICY.longest_probe_lifetime());
            let given = deadline_for(1, &arp, None, None)
                .max_budget
                .for_target_count(1);
            assert!(
                given >= needed,
                "one address {case}: its schedule at the ceiling takes {needed:?} \
                 and the sweep is given {given:?}"
            );
        }
    }

    /// A segment whose first neighbour's answer arrives while the sweep asks
    /// the next, and whose next send then blocks for `stall`.
    struct StalledAfterAnswering {
        stall: Duration,
        frames: tokio::sync::mpsc::Sender<CapturedFrame>,
        /// The first address asked about, whose answer is held for the next
        /// request.
        first: Option<Ipv4Addr>,
        answered: bool,
    }

    impl crate::transport::capture::FrameSink for StalledAfterAnswering {
        fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
            let asked = ethernet::parse(frame)
                .ok()
                .filter(|frame| frame.ethertype() == pnet_packet::ethernet::EtherTypes::Arp.0)
                .and_then(|frame| pnet_packet::arp::ArpPacket::owned(frame.payload().to_vec()))
                .map(|request| request.get_target_proto_addr());
            let Some(target) = asked.filter(|_| !self.answered) else {
                return Ok(());
            };
            let Some(first) = self.first else {
                self.first = Some(target);
                return Ok(());
            };
            self.answered = true;
            self.frames
                .try_send(CapturedFrame {
                    zone: Zone::new(7, "sim0"),
                    link: LinkType::Ethernet,
                    bytes: arp_reply_frame(first),
                    observed_at: std::time::SystemTime::now(),
                    received_at: Instant::now(),
                })
                .expect("room for the answer");
            std::thread::sleep(self.stall);
            Ok(())
        }
    }

    /// An answer waiting when its probe ran out of attempts still times its
    /// host, however late the loop gets to either.
    #[tokio::test(flavor = "current_thread")]
    async fn an_answer_waiting_when_its_probe_runs_out_still_times_the_host() {
        use crate::system::interface::LinkAddress;

        // Unseeded, so asked in address order: the first answers and the
        // stall comes on asking the second.
        let target = Ipv4Addr::new(192, 0, 2, 10);
        let silent = Ipv4Addr::new(192, 0, 2, 11);
        let (session, ctx) = crate::scanner::session::ScanSession::builder()
            .ordering(None)
            .build();
        let retry = RETRY_POLICY.configured(RetryConfig {
            max_attempts: std::num::NonZeroU8::new(1),
            ..RetryConfig::default()
        });
        let (frames, rx) = tokio::sync::mpsc::channel(16);
        // Longer than the longest first timeout an unmeasured address draws.
        let stall = retry.initial_rto.mul_f64(1.0 + retry.jitter) + Duration::from_millis(200);
        let handle = EthernetHandle::from_parts(
            Box::new(StalledAfterAnswering {
                stall,
                frames,
                first: None,
                answered: false,
            }),
            rx,
        );
        let link = Link::new("sim0", 7)
            .with_mac(LOCAL_MAC)
            .with_addresses(vec![LinkAddress::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                24,
            )]);
        let mut targets = IpSet::new();
        targets.insert(IpAddr::V4(target));
        targets.insert(IpAddr::V4(silent));
        let mut scanner =
            LocalScanner::build(link, targets, ctx, None, Scope::Targeted, handle, retry)
                .expect("a scanner over the simulated segment");

        scanner.discover_hosts().await.expect("the sweep runs");

        let host = session
            .hosts()
            .get(IpAddr::V4(target))
            .expect("the host answered and is not on record");
        assert!(
            host.min_rtt().is_some(),
            "the answer was read after its probe was written off"
        );
    }

    /// A neighbour that, asked for its address, first broadcasts a request of
    /// its own and answers the question it was asked `delay` later.
    struct AsksBeforeAnswering {
        delay: Duration,
        frames: tokio::sync::mpsc::Sender<CapturedFrame>,
        answered: bool,
    }

    impl AsksBeforeAnswering {
        fn captured(bytes: Vec<u8>, received_at: Instant) -> CapturedFrame {
            CapturedFrame {
                zone: Zone::new(7, "sim0"),
                link: LinkType::Ethernet,
                bytes,
                observed_at: std::time::SystemTime::now(),
                received_at,
            }
        }
    }

    impl crate::transport::capture::FrameSink for AsksBeforeAnswering {
        fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
            let asked = ethernet::parse(frame)
                .ok()
                .filter(|frame| frame.ethertype() == pnet_packet::ethernet::EtherTypes::Arp.0)
                .and_then(|frame| pnet_packet::arp::ArpPacket::owned(frame.payload().to_vec()))
                .map(|request| request.get_target_proto_addr());
            let Some(target) = asked.filter(|_| !self.answered) else {
                return Ok(());
            };
            self.answered = true;
            self.frames
                .try_send(Self::captured(arp_request_frame(target), Instant::now()))
                .expect("room for the neighbour's own request");
            let frames = self.frames.clone();
            let arrives = Instant::now() + self.delay;
            tokio::spawn(async move {
                tokio::time::sleep_until(arrives.into()).await;
                let _ = frames
                    .send(Self::captured(arp_reply_frame(target), arrives))
                    .await;
            });
            Ok(())
        }
    }

    /// A neighbour's own request, heard while the sweep's is outstanding,
    /// proves it is there but times nothing; its reply does. A neighbour often
    /// asks something itself before answering.
    #[tokio::test(flavor = "current_thread")]
    async fn a_neighbours_own_request_does_not_answer_the_sweeps() {
        use crate::system::interface::LinkAddress;

        let target = Ipv4Addr::new(198, 51, 100, 2);
        let delay = Duration::from_millis(80);
        let (session, ctx) = crate::scanner::session::ScanSession::new();
        let (frames, rx) = tokio::sync::mpsc::channel(16);
        let handle = EthernetHandle::from_parts(
            Box::new(AsksBeforeAnswering {
                delay,
                frames,
                answered: false,
            }),
            rx,
        );
        let link = Link::new("sim0", 7)
            .with_mac(LOCAL_MAC)
            .with_addresses(vec![LinkAddress::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                24,
            )]);
        let mut targets = IpSet::new();
        targets.insert(IpAddr::V4(target));
        let mut scanner = LocalScanner::build(
            link,
            targets,
            ctx,
            None,
            Scope::Targeted,
            handle,
            RETRY_POLICY,
        )
        .expect("a scanner over the simulated segment");

        scanner.discover_hosts().await.expect("the sweep runs");

        let host = session
            .hosts()
            .get(IpAddr::V4(target))
            .expect("the neighbour answered and is not on record");
        assert!(
            host.min_rtt().is_none_or(|rtt| rtt >= delay),
            "a neighbour answering in {delay:?} was timed at {:?}",
            host.min_rtt()
        );
    }

    /// A table refusing as Linux's does when asked about a link-local address
    /// with no zone, and allowing everything else.
    fn refuses_as_linux_does(address: IpAddr) -> bool {
        crate::model::ip::scoped::ScopedIp::needs_zone(&address)
    }

    /// A table refusing every address it is asked about.
    fn refuses_everything(_: IpAddr) -> bool {
        true
    }

    /// A sweep over a simulated segment holding `192.0.2.1/24`, `fe80::1/64`
    /// and `2001:db8::1/64`, for a test that hands it overheard addresses.
    fn overhearing_scanner() -> LocalScanner {
        use crate::system::interface::LinkAddress;

        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let (_frames, rx) = tokio::sync::mpsc::channel(16);
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let handle = EthernetHandle::from_parts(Box::new(Asked(asked)), rx);
        let link = Link::new("sim0", 7)
            .with_mac(LOCAL_MAC)
            .with_addresses(vec![
                LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24),
                LinkAddress::new("fe80::1".parse().expect("an address"), 64),
                LinkAddress::new("2001:db8::1".parse().expect("an address"), 64),
            ]);
        let targets: IpSet = "192.0.2.0/30".parse().expect("a prefix");
        LocalScanner::build(link, targets, ctx, None, Scope::Sweep, handle, RETRY_POLICY)
            .expect("a scanner over the simulated segment")
    }

    /// An overheard link-local address is asked about whatever the table says
    /// without its zone; one on the link's prefix that the table refuses is
    /// not.
    ///
    /// Linux refuses a zoneless link-local lookup as a blackhole route would,
    /// so a phone found only through mDNS would never be asked.
    #[tokio::test(flavor = "current_thread")]
    async fn an_overheard_link_local_address_is_asked_whatever_the_table_says_without_a_zone() {
        let link_local: IpAddr = "fe80::2".parse().expect("an address");
        let on_link: IpAddr = "2001:db8::2".parse().expect("an address");
        let mut scanner = overhearing_scanner();

        scanner.refuses = refuses_as_linux_does;
        scanner.confirm(link_local);
        assert_eq!(
            scanner.ipv6.next_confirmation(|_| true),
            Some(link_local),
            "an overheard link-local neighbour was read as refused by a route"
        );

        scanner.refuses = refuses_everything;
        scanner.confirm(on_link);
        assert_eq!(
            scanner.ipv6.next_confirmation(|_| true),
            None,
            "an address the table refuses was asked about"
        );
    }

    /// An overheard address on no prefix the link holds is asked about
    /// whatever the table says: the table answers about a path through a
    /// router, which a solicitation does not take.
    #[tokio::test(flavor = "current_thread")]
    async fn an_overheard_address_off_the_links_prefixes_is_asked_whatever_the_table_says() {
        let elsewhere: IpAddr = "2001:db8:1::2".parse().expect("an address");
        let mut scanner = overhearing_scanner();

        scanner.refuses = refuses_everything;
        scanner.confirm(elsewhere);
        assert_eq!(
            scanner.ipv6.next_confirmation(|_| true),
            Some(elsewhere),
            "an address off the link's prefixes was read as refused by a route"
        );
    }

    /// A segment that answers nothing and notes the address every ARP request
    /// it is sent asks about, in the order they leave.
    struct Asked(std::sync::Arc<std::sync::Mutex<Vec<IpAddr>>>);

    impl crate::transport::capture::FrameSink for Asked {
        fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
            let asked = ethernet::parse(frame)
                .ok()
                .filter(|frame| frame.ethertype() == pnet_packet::ethernet::EtherTypes::Arp.0)
                .and_then(|frame| pnet_packet::arp::ArpPacket::owned(frame.payload().to_vec()))
                .map(|request| request.get_target_proto_addr());
            if let Some(target) = asked {
                self.0.lock().expect("the log").push(IpAddr::V4(target));
            }
            Ok(())
        }
    }

    /// A seeded sweep asks in the order the seed names, the order a dispatched
    /// sweep streams the same plan in. Address order is what a correlating
    /// sensor keys on.
    #[tokio::test(flavor = "current_thread")]
    async fn a_seeded_sweep_asks_in_the_order_the_seed_names() {
        use crate::model::ip::set::Positions;
        use crate::system::interface::LinkAddress;

        const SEED: u64 = 0x5EED;
        let targets: IpSet = "192.0.2.64/27".parse().expect("a prefix");
        let (_session, ctx) = crate::scanner::session::ScanSession::builder()
            .ordering(Some(SEED))
            .counting(Positions::of(&targets))
            .build();
        let mut walk = crate::scanner::dispatcher::dispatch_addresses_of(
            targets.clone(),
            1,
            Some(SEED),
            Some(std::sync::Arc::clone(&ctx.positions)),
            &ctx.handle,
        );
        let mut expected = Vec::new();
        while let Some(ip) = walk.recv().await {
            expected.push(ip);
        }
        assert_ne!(
            expected,
            targets.iter().collect::<Vec<_>>(),
            "the walk the seed names is not the range"
        );

        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (_frames, rx) = tokio::sync::mpsc::channel(16);
        let handle = EthernetHandle::from_parts(Box::new(Asked(std::sync::Arc::clone(&asked))), rx);
        let link = Link::new("sim0", 7)
            .with_mac(LOCAL_MAC)
            .with_addresses(vec![LinkAddress::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                24,
            )]);
        let retry = RETRY_POLICY.configured(RetryConfig {
            max_attempts: std::num::NonZeroU8::new(1),
            ..RetryConfig::default()
        });
        let mut scanner =
            LocalScanner::build(link, targets, ctx, None, Scope::Targeted, handle, retry)
                .expect("a scanner over the simulated segment");

        scanner.discover_hosts().await.expect("the sweep runs");

        assert_eq!(*asked.lock().expect("the log"), expected);
    }

    /// A frame the filter drops never reaches a [`DiscoveryProtocol`], and
    /// fails silently.
    ///
    /// The fake-LAN fixtures inject frames past the capture, so only this test
    /// catches it: it compiles the real expression with `libpcap` and runs it
    /// against real frames, with no interface or privileges.
    #[test]
    fn the_sweep_filter_admits_every_frame_the_sweep_can_read() {
        let filter = super::sweep_filter();
        let program = pcap::Capture::dead(pcap::Linktype::ETHERNET)
            .expect("a dead capture")
            .compile(&filter, true)
            .unwrap_or_else(|e| panic!("the sweep filter `{filter}` does not compile: {e}"));

        // The filter reads only the EtherType and destination of these.
        let lldp = ethernet::build_header(
            PEER_MAC,
            MacAddr::new(0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E),
            crate::protocols::lldp::ETHERTYPE,
        );
        let cdp = {
            let group = crate::protocols::cdp::GROUP_ADDRESS;
            let mut bytes = group.octets().to_vec();
            bytes.extend_from_slice(&PEER_MAC.octets());
            // 802.3: a length, not an EtherType.
            bytes.extend_from_slice(&[0x00, 0x20]);
            bytes.resize(60, 0);
            bytes
        };

        let readable: [(&str, Vec<u8>); 7] = [
            (
                "an ARP frame",
                arp_reply_frame(Ipv4Addr::new(198, 51, 100, 2)),
            ),
            (
                "a neighbour advertisement",
                ndp_frame(&advertisement_body(
                    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                    0,
                )),
            ),
            (
                "an echo reply",
                echo_reply_frame(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            ),
            (
                "a DHCP server reply",
                dhcp_reply_frame(Ipv4Addr::new(192, 0, 2, 1), None),
            ),
            ("an mDNS response", mdns_frame()),
            ("an LLDP advertisement", lldp),
            ("a CDP announcement", cdp),
        ];

        for (what, frame) in readable {
            assert!(
                program.filter(&frame),
                "the sweep filter rejects {what}, so the sweep would never see one: {filter}"
            );
        }
    }

    /// A link with no Ethernet header refuses the sweep's filter whole, so the
    /// sweep reports it cannot run there instead of an empty segment.
    #[test]
    fn a_link_without_ethernet_refuses_the_sweep_filter_whole() {
        /// `DLT_RAW`, how a WireGuard or IP-in-IP tunnel comes up.
        const RAW: i32 = 12;

        let filter = super::sweep_filter();
        let tunnel = pcap::Capture::dead(pcap::Linktype(RAW)).expect("a dead capture");

        assert!(
            tunnel.compile(&filter, true).is_err(),
            "a tunnel took the sweep filter: {filter}"
        );
    }

    /// A filter admitting everything would pass the tests above and copy the
    /// whole segment into this process.
    #[test]
    fn the_sweep_filter_rejects_traffic_no_reader_asked_for() {
        let filter = super::sweep_filter();
        let program = pcap::Capture::dead(pcap::Linktype::ETHERNET)
            .expect("a dead capture")
            .compile(&filter, true)
            .expect("the sweep filter compiles");

        let ordinary_tcp = {
            let datagram = crate::protocols::craft::Packet::new()
                .push(crate::protocols::craft::Ipv4::new(
                    Ipv4Addr::new(192, 0, 2, 50),
                    Ipv4Addr::new(192, 0, 2, 60),
                ))
                .push(crate::protocols::craft::Udp::new(4444, 8080).with_payload(vec![0u8; 16]))
                .build()
                .expect("a test datagram");

            [
                ethernet::build_header(
                    PEER_MAC,
                    LOCAL_MAC,
                    pnet_packet::ethernet::EtherTypes::Ipv4.0,
                ),
                datagram,
            ]
            .concat()
        };

        assert!(
            !program.filter(&ordinary_tcp),
            "the sweep filter admits traffic between two other hosts on ports \
             nothing here reads, which is the copying it exists to avoid: {filter}"
        );
    }
}
