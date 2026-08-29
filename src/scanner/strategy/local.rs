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

mod ipv6;
mod probes;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::protocols::ethernet::Frame;
use async_trait::async_trait;
use pnet_base::MacAddr;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::Interval;

use crate::config::RetryConfig;
use crate::journal::settle::{Outcome, Settled};
use crate::model::host::telemetry::RttSource;
use crate::model::host::{HostStatus, NetworkRole, StatusProtocol, StatusReason};
use crate::model::ip::scoped::Zone;
use crate::model::ip::set::IpSet;
use crate::protocols::{self as protocol, ethernet};
use crate::report::ScannerKind;
use crate::report::{Attachment, AttachmentSource, StopReason};
use crate::scanner::audit::ProbeAudit;
use crate::scanner::pacing::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::scanner::pacing::retry::{Due, ProbeLedger, RetryPolicy};
use crate::scanner::pacing::timer::ScanBudget;
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::{HostScanner, StrategyError};
use crate::system::interface::Link;
use crate::transport::capture::CapturedFrame;
use crate::transport::channel::{self, EthernetHandle};
use crate::transport::frame::LinkType;
use crate::transport::mac::IntoCoreMac;
use crate::transport::mac::IntoPnetMac;
use crate::{error, info};

use crate::scanner::strategy::discovery::{self, DiscoveryProtocol, ProtocolMatch, Reading};
use ipv6::Ipv6Discovery;

/// What a local sweep's capture admits, as a `libpcap` filter expression.
///
/// The union of what every [`DiscoveryProtocol`] declares it reads, plus the one
/// thing the sweep reads without one. Derived rather than written down, so that
/// adding a protocol widens the capture by the same edit that adds the reader —
/// see [`DiscoveryProtocol::capture_clause`] for why that is not a convenience.
///
/// The sweep used to receive the whole segment and reject the surplus in
/// userspace, which on a busy link meant copying every frame on the wire to
/// discard almost all of it.
///
/// **802.1Q-tagged frames are not admitted**, and that is not a new loss: the
/// frame reader below takes the EtherType from its fixed offset, so a tagged
/// frame already read as an unsupported EtherType and was rejected a layer up.
fn sweep_filter() -> String {
    let mut clauses: Vec<&'static str> = discovery::sweep_protocols()
        .iter()
        .map(|protocol| protocol.capture_clause())
        .collect();

    clauses.extend(ABSORBED_CLAUSES);

    // Several protocols share a clause — the three IPv6 readers are all
    // `icmp6` — and a filter repeating it would compile to the same program
    // while reading as though it meant something.
    clauses.sort_unstable();
    clauses.dedup();

    clauses.join(" or ")
}

/// The clauses for the readers that conclude no liveness, and so have no
/// [`DiscoveryProtocol`] to declare them.
///
/// Every protocol in [`discovery::sweep_protocols`] exists to conclude that a
/// host is present. These three deliberately do not, and each declines for its
/// own reason:
///
/// - **mDNS** (`absorb_mdns`) reads a name off the segment and credits nobody
///   with being there for it, because every laptop and printer on a link
///   answers mDNS and the announcer is often not the machine being announced.
/// - **LLDP** and **CDP** (`absorb_announcement`) are equipment describing
///   *itself*, and what they establish is where **this** machine is plugged in
///   — a fact about the phase rather than about any host in it. See
///   [`Attachment`].
///
/// A fourth reader of this kind needs a clause here, and nothing will say so:
/// the derivation above covers only the protocols that conclude liveness.
///
/// The CDP clause matches the group address rather than the protocol, because
/// CDP rides 802.3 framing and has no EtherType to match on. That address also
/// carries VTP, DTP and PAgP, which the reader declines — a small surplus, and
/// the alternative is reaching past a header whose length BPF cannot express.
const ABSORBED_CLAUSES: [&str; 3] = [
    "(udp port 5353)",
    "(ether proto 0x88cc)",
    "(ether dst 01:00:0c:cc:cc:cc)",
];

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

/// How many machines may declare what they are before this scanner knows which
/// hosts they are.
///
/// One bound on what the segment can make this process hold. A router
/// advertisement and a DHCP reply are unsolicited traffic, so unlike every
/// other record here this one grows from frames nobody asked for, and a
/// neighbour sending them under a new hardware address each time would
/// otherwise grow it without limit.
///
/// Sixty-four is past any segment that has this many routers and DHCP servers
/// on it, and small enough that reaching the cap costs nothing worth measuring.
/// Past it, a declaration from a machine still unknown is dropped like any other
/// off-target frame: it is a claim about a host this scan has not found.
const MAX_DECLARING_MACS: usize = 64;

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
    #[error("the frame came off a link that prepends no Ethernet header")]
    UnreadableLink,
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
    /// How the store keys a neighbour this scanner found.
    ///
    /// **The interface belongs in the key, not only on the record.** Every
    /// address here was read off one segment, and a link-local one is valid on
    /// that segment alone: `fe80::1` on `en0` and `fe80::1` on `en1` are two
    /// machines. Keyed by the bare address they were one entry, and the second
    /// sweep to find one folded its neighbour's hardware address, roles and
    /// round trips into the first's record.
    ///
    /// [`ScopedIp::scoped`] drops the zone from every address that does not need
    /// one, so this is the plain address for an IPv4 neighbour and for a global
    /// IPv6 one — which is right, since a machine reachable at a global address
    /// is the same machine through whichever interface it answered.
    fn key_for(&self, addr: std::net::IpAddr) -> crate::model::ip::scoped::ScopedIp {
        crate::model::ip::scoped::ScopedIp::scoped(addr, self.zone.clone())
    }
    /// Picks the addresses this scanner will present as its own when probing
    /// `ip_set` from `intf`.
    ///
    /// For IPv4, it prefers an address in the same subnet as the targets being
    /// scanned and otherwise falls back to the interface's first non-loopback
    /// address. For IPv6, it uses the interface's link-local address when it has
    /// one, since that is what the ICMPv6 all-nodes probe is sent from.
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
            // An address on the same segment as the targets beats one that
            // merely exists: a probe sourced from the wrong subnet is answered
            // to somewhere this scanner is not listening.
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
            mac: mac.into_pnet(),
            ipv4,
            link_local_ipv6,
            zone: link.zone(),
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
    /// What a machine said it is, held until this scanner knows which host that
    /// machine is.
    ///
    /// The two segment-wide questions are answered from an address the scan was
    /// never asked about — a router advertises from its link-local, a DHCP
    /// server may sit outside the range — so on a targeted run the answer
    /// arrives before, and often instead of, anything that identifies its
    /// sender. Held by MAC rather than dropped, and applied the moment that MAC
    /// answers a probe of ours.
    ///
    /// **This is what keeps a targeted run targeted.** Nothing here creates a
    /// host or adds an address: a declaration only ever lands on a record the
    /// scan built by asking, so a run handed one address still reports one
    /// host — with, if it happens to be the router, the fact that it routes.
    ///
    /// Bounded by [`MAX_DECLARING_MACS`], unlike `mac_to_ip`, which only ever
    /// grows from replies to probes this scanner sent. This grows from traffic
    /// nobody solicited.
    declared: HashMap<MacAddr, HashSet<NetworkRole>>,
    /// Whether to sweep the segment or probe only the given targets.
    scope: Scope,
    /// Target addresses that have answered, so a targeted run can stop the
    /// moment every one of them has, rather than waiting out the deadline.
    responded: HashSet<IpAddr>,
    /// Per-run counters, so a sweep that finds fewer hosts than the segment
    /// holds can be attributed to loss, to its own deadline, or to correlation
    /// rather than guessed at. Reported once when the loop exits.
    ///
    /// `capture` comes from the [`EthernetHandle`]'s own capture, and is `None`
    /// only for a synthetic frame stream — which has no kernel buffer to have
    /// overflowed, and must not report a clean receive path it never had.
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

            // Recorded where the probe is armed, because this is the one
            // condition under which the phase covers the whole link rather than
            // the addresses it was handed. A host found here holds an address
            // no target set named, and without this the record cannot say it
            // was looked for.
            self.ctx.record_sweep(self.identity.zone.clone());
        }

        // Asked on every local run, sweep or not, and answered by a class of
        // machine rather than by an address: neither question can be put to a
        // target, and a scan of a segment that does not ask them reports the
        // segment without the two machines it is built around.
        //
        // This is not the sweep's reach in disguise. A sweep may *record* a
        // host nobody named; a targeted run still may not, and does not — an
        // answer from an address outside the target set is read for what its
        // sender said it is and for nothing else. See
        // [`note_declaration`](Self::note_declaration).
        self.solicit_routers();
        self.ask_for_configuration();

        let mut sending_finished = false;
        // What the packet iterator has handed out, so what it still holds can be
        // counted as unasked without draining it — building those packets is the
        // work the sweep was stopped to avoid.
        let mut dispatched: u128 = 0;
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
                        Some(frame) => {
                            self.audit.record_segment();
                            _ = self.process_eth_packet(&frame, Instant::now());
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
                                // Armed only if the frame left. A probe nobody
                                // sent must not run out of attempts and earn a
                                // verdict, and the failure message below is
                                // about exactly these addresses.
                                if self.emit(&packet, "first attempt") {
                                    self.record_probe(ip, Instant::now());
                                }
                                dispatched += 1;
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

        // What the sweep did not earn a verdict for, so a resumed one asks again
        // rather than skipping it. None of these carries a position: a probe
        // still mid-schedule was cut off rather than spent, and one the iterator
        // still holds was never built, let alone sent.
        let outstanding = self.ledger.drain_unresolved().len() as u64;
        self.ctx.record_many(Outcome::Interrupted, outstanding);
        self.ctx.record_many(
            Outcome::Unasked,
            u64::try_from(self.ip_set.len().saturating_sub(dispatched)).unwrap_or(u64::MAX),
        );

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

        // What the kernel discarded before this scanner could read it. A frame
        // lost there is indistinguishable from a host that never answered, so a
        // sweep finding fewer hosts than the segment holds can now be attributed
        // to loss rather than guessed at. `None` only for a synthetic stream,
        // which has no kernel buffer to have overflowed.
        let capture = self.eth_handle.capture_counts();
        let targets = self.ip_set.len();
        self.audit
            .report("local-discovery", targets, reason, capture, None);
        self.ctx.record_probe_stats(self.audit.stats(
            ScannerKind::Local,
            targets,
            reason,
            capture,
            None,
        ));
        Ok(())
    }
}

impl LocalScanner {
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
    /// The addressing identity is still resolved from `intf`, since a probe has
    /// to be sent from some MAC and address, but nothing here touches the
    /// interface itself.
    ///
    /// This is the constructor for a caller orchestrating their own scan, who
    /// has opened a channel on the interface they mean rather than letting
    /// [`new`](Self::new) choose. Paired with a synthetic channel
    /// (`EthernetHandle::from_parts`, behind the `test-support` feature) and a
    /// hand-built [`Link`], it is also the seam
    /// that lets ARP and
    /// NDP discovery be driven against a simulated segment with no privileges.
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

    /// The common constructor, taking the retry schedule as an argument because
    /// the sweep's own deadline is derived from it and so has to be settled
    /// before anything is built.
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
            protocols: discovery::sweep_protocols(),
            ledger: Ledger::new(retry, target_count),

            due: Vec::new(),
            retries: VecDeque::new(),

            dns_tx,
            mac_to_ip: HashMap::new(),
            declared: HashMap::new(),
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
    /// [`FrameSink::send_frame`] reports whether the frame left, and an error is
    /// the only way it did not. The predecessor returned `Option<io::Result<()>>`
    /// with two shapes of failure — no buffer to write into, and a write that
    /// failed — and both meant the same thing to every caller, which is why this
    /// says it once. Reading only whether the *packet built* would leave
    /// `sends_failed` making a claim about this code where a caller reads it as
    /// a claim about the link.
    fn emit(&mut self, packet: &[u8], what: &str) -> bool {
        match self.eth_handle.tx.send_frame(packet) {
            Ok(()) => {
                self.audit.record_send(true);
                true
            }
            Err(reason) => {
                self.audit.record_send(false);
                self.send_failure
                    .get_or_insert_with(|| format!("{what}: {reason}"));
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
            self.ledger.arm(ip, ip, (), (), now);
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
            "asked {target} directly, having only overheard it"
        );
    }

    /// Asks every router on the segment to say so, once, at the head of a
    /// sweep.
    ///
    /// One packet for a question nothing else on the segment answers. A router
    /// advertises itself unprompted on a timer measured in minutes, which
    /// outlasts any sweep, so without asking the engine finds the segment's
    /// routers only by luck. The reply is an ordinary advertisement claimed by
    /// [`RouterAdvertProtocol`], so the router arrives as a host in the same
    /// breath as being named one.
    ///
    /// Sent on any local run, unlike the all-nodes echo. The rule that keeps a
    /// targeted run targeted is about what may be *recorded*, and it is
    /// enforced where records are made: an answer from an address nobody asked
    /// about is read for the role its sender claims and never becomes a host.
    /// The echo has no such reading — everything it draws is a new address —
    /// which is why it stays behind the sweep.
    ///
    /// Not repeated. A lost solicitation costs the *unsolicited* route to this
    /// finding, not the finding: a router that answers any of the scan's
    /// ordinary neighbour solicitations declares itself in the R flag of the
    /// reply, and every address the sweep asks about is asked more than once.
    fn solicit_routers(&mut self) {
        let Some(link_local) = self.identity.link_local_ipv6 else {
            return;
        };

        let packet = protocol::ndp::create_router_solicitation(&self.identity.mac, &link_local);
        self.emit(&packet, "router solicitation");
    }

    /// Asks the segment which machine configures it, once.
    ///
    /// A `DHCPINFORM`, which asks for configuration without asking for an
    /// address, so every server on the link answers and none of them reserves
    /// anything for a client that will never appear. See
    /// [`dhcp`](crate::protocols::dhcp) for why this is a broadcast rather than
    /// a port probe.
    ///
    /// Broadcast, and therefore seen by every device on the segment — which is
    /// the same reach an ARP request has, and a scan of a range sends one of
    /// those per address in it. Sent on any local run, on the same terms as the
    /// router solicitation: what a targeted run may record is enforced where
    /// records are made, not by declining to ask.
    ///
    /// The one run this is disproportionate for is a scan of a single address,
    /// where it triples a discovery phase that would otherwise put one ARP
    /// request on the wire. It is still two frames, on a segment this machine
    /// is already on.
    ///
    /// The answer comes back to this host's address, and is read off the
    /// segment by [`DhcpProtocol`] rather than through a socket: binding UDP/68
    /// is a privilege this scanner already has a better use for, and the
    /// capture sees the reply either way.
    fn ask_for_configuration(&mut self) {
        let Some(source) = self.identity.ipv4 else {
            return;
        };

        let packet = protocol::dhcp::create_inform(&self.identity.mac, &source);
        self.emit(&packet, "dhcp inform");
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
                protocol::arp::create_request(&self.identity.mac, &source_v4, target_v4)
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
            self.ledger.arm(target, target, (), (), now);
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
    /// Reads a switch's announcement of itself, where the frame is one.
    ///
    /// Returns whether the frame was an announcement, so the caller can stop
    /// reading it as something else.
    ///
    /// # Two findings, and only one of them is about a host
    ///
    /// **Where this machine is plugged in** is recorded unconditionally, as an
    /// [`Attachment`] on the phase. It is not a claim about a host in the
    /// report — it is a relation between this machine and somebody else's
    /// equipment — so the rule that keeps a targeted run targeted does not
    /// apply to it. A run handed one address still reports one host, and now
    /// also says which switch port it was run from.
    ///
    /// **What the sender is** goes through `note_declaration` like any other
    /// overheard claim: filed against the announcing hardware address and
    /// applied only if that machine turns out to be one the scan found by
    /// asking. A switch usually holds no address on the segment it serves, so
    /// in the common case the claim is never applied to anything — and that is
    /// the correct outcome, not a loss. The switch's identity is in the
    /// attachment, where it belongs.
    ///
    /// # What an announcement is not evidence of
    ///
    /// That its sender is a switch. Anything on a link can emit one, and
    /// nothing here authenticates it. What the group address buys is a
    /// statement about *where* — conforming bridges constrain those addresses
    /// rather than forwarding them — and never about truthfulness. The role
    /// this files carries that caveat in its own documentation.
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
            attachment = attachment.with_device_mac(source_mac.into_core());

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
            .with_device_mac(source_mac.into_core());

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
            match event {
                Due::Retry { key, .. } => self.retries.push_back(key),
                // The budget is spent, which is the moment silence stops being
                // provisional and becomes a verdict this sweep earned. A probe
                // whose frame never left is not armed, so nothing settled here
                // went unasked.
                Due::Exhausted { key, .. } => self.ctx.settle_address(key, Settled::Exhausted),
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
    fn process_eth_packet(&mut self, frame: &CapturedFrame, now: Instant) -> anyhow::Result<()> {
        // Every probe this sweep sends is an Ethernet frame and every reading it
        // takes starts from an Ethernet header, so a link that prepends
        // something else carries nothing this can read. `start_capture` refuses
        // such an interface outright; a synthetic stream is the only way one
        // reaches here, and reading its bytes as Ethernet would invent a source
        // address rather than fail.
        if frame.link != LinkType::Ethernet {
            self.audit.record_off_target();
            return Err(FrameRejected::UnreadableLink.into());
        }

        let eth_frame: Frame<'_> = ethernet::parse(&frame.bytes)?;

        let source_mac = eth_frame.source();
        if source_mac == self.identity.mac {
            self.audit.record_off_target();
            return Err(FrameRejected::SelfSourcedPacket.into());
        }

        // Before the address is read, because neither of these frames has one.
        // LLDP carries no IP header at all and CDP is not even an EtherType
        // protocol, so `source_address` refuses both — which is correct, and is
        // why they have to be taken out of the stream first.
        if self.absorb_announcement(&eth_frame, source_mac, frame) {
            return Ok(());
        }

        let source_addr: IpAddr = protocol::source_address(&eth_frame)?;

        if self.absorb_mdns(&eth_frame) {
            return Ok(());
        }

        let Some((reading, protocol)) = self.interpret_response(&eth_frame) else {
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
            // Out of range and still worth reading, in the one case where the
            // frame says something about a machine rather than about an
            // address: a router advertising from its link-local, a DHCP server
            // answering from outside the range. The claim is filed against the
            // sender's hardware address and applied only if that machine turns
            // out to be one this scan asked about.
            if let Some(role) = reading.declared
                && self.note_declaration(source_mac, role)
            {
                return Ok(());
            }

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

        let rtt = match reading.matched {
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
            // Proof of presence and of nothing else. A probe may well be
            // outstanding for this address, and it stays outstanding: this
            // message did not answer it, so retiring it here would credit our
            // question with somebody else's answer and time it from the moment
            // we asked.
            //
            // Asked directly instead, which is the same treatment an overheard
            // address gets, and the only way one of these senders is ever
            // measured.
            ProtocolMatch::Unsolicited => {
                self.confirm(subject);
                None
            }
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
        self.record_response(
            source_mac,
            subject,
            rtt,
            protocol.clone(),
            answered_attempt,
            reading.declared,
        );

        // The address the reply came *from* belongs to the same host and is just
        // as real, so it is recorded too - but only after the subject, which is
        // what keys the host. Filing it under an address the scan never asked
        // about is how a phone solicited at one address came back reported under
        // another.
        if subject != source_addr {
            // The declaration went in with the subject above, and both calls
            // reach the same record: a host is keyed by the MAC that answered,
            // whichever of its addresses this frame was about.
            self.record_response(source_mac, source_addr, None, protocol, None, None);
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
    fn interpret_response(&mut self, frame: &Frame<'_>) -> Option<(Reading, StatusProtocol)> {
        for protocol in &self.protocols {
            match protocol.interpret(frame) {
                Ok(Reading {
                    matched: ProtocolMatch::Unhandled,
                    ..
                }) => continue,
                Ok(reading) => return Some((reading, protocol.status_protocol())),
                Err(e) => {
                    error!(verbosity = 1, "failed to interpret discovery response: {e}");
                    return None;
                }
            }
        }

        None
    }

    /// Files what a machine said it is, against the hardware address that said
    /// it.
    ///
    /// Returns whether the claim was kept, which is the caller's answer to
    /// whether the frame was worth receiving.
    ///
    /// Applied immediately where the MAC is already on the roster, and held
    /// otherwise, because the order is not ours to choose: a router answers a
    /// solicitation within half a second (RFC 4861 §6.2.6) and the ARP request
    /// that will identify it leaves on a paced ticker some way into the sweep.
    /// Dropping the early half of that race is dropping the common case.
    ///
    /// Never creates a host and never records an address. A declaration is a
    /// claim about a machine, and the machine has to be one the scan found by
    /// asking before there is anything for the claim to attach to.
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
    ///
    /// `declared` is what the sender said it *is*, where the frame carried such
    /// a claim — the R flag on an advertisement, or an advertisement only a
    /// router sends. It is the host's own word rather than an inference of
    /// ours, which is why it is recorded here beside the liveness evidence and
    /// not derived later from what the record ended up holding.
    fn record_response(
        &mut self,
        source_mac: MacAddr,
        source_addr: IpAddr,
        rtt: Option<(Duration, RttSource)>,
        protocol: StatusProtocol,
        answered_attempt: Option<u8>,
        declared: Option<NetworkRole>,
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
        // The address answered, which is a verdict this sweep earned however the
        // reply was timed and whether it was solicited or overheard. It is the
        // address that answered rather than the host's primary: a device
        // reachable at three addresses answered at this one.
        self.ctx.settle_address(source_addr, Settled::Answered);

        let first_sighting = !self.mac_to_ip.contains_key(&source_mac);
        let primary_ip = *self.mac_to_ip.entry(source_mac).or_insert(source_addr);

        // Whatever this machine told the segment before this scan knew which
        // host it was. Taken out of the roster rather than left in it: the MAC
        // is on `mac_to_ip` from here on, so a later declaration is applied on
        // the spot.
        let held = self.declared.remove(&source_mac);

        // Host mutation only. `write_host` owns the guard, the drop-before-emit
        // ordering, and the event. `is_new_ip` is returned for the DNS decision
        // below, which runs after the guard is released, as does the deadline
        // bookkeeping.
        let mut is_new_ip = false;
        let zone = self.identity.zone.clone();
        let is_new_host = self
            .ctx
            .write_host(self.identity.key_for(primary_ip), |host| {
                // Every frame this scanner reads came off the one link it is
                // bound to, so a host it credits was observed through that
                // interface — whichever of its addresses answered first.
                //
                // **Set here rather than left to the key.** A host is born with
                // the zone its *key* carries, and a key carries one only where
                // the address needs it: a machine whose IPv4 answered before its
                // link-local was created unscoped, and its link-local was then
                // reported bare. `fe80::41a:992a:fb73:5c91` names a different
                // machine on every segment, so which of two addresses replied
                // first decided whether the record was usable. `set_zone` keeps
                // the first it is given, so repeating this is free.
                host.set_zone(zone.clone());

                // Recorded whether we just created the host or the port scanner
                // created it first, so enrichment order doesn't decide whether a MAC
                // is recorded. Repeating one already on record refreshes its
                // last-seen time, which is what `HardwareInfo` keeps them for.
                host.record_mac(source_mac.into_core());

                // The protocol name is the whole of the evidence here - a reply came
                // off the segment carrying this host's own MAC - so there is nothing
                // a details string would add that `arp` or `ndp` does not already
                // say.
                let was_up = host.status().is_up();
                host.record_evidence(HostStatus::Up, StatusReason::basic(protocol.clone()));

                let mut changed = rtt.is_some() || !was_up;
                for role in held.into_iter().flatten() {
                    changed |= host.add_network_role(role);
                }
                if let Some(role) = declared {
                    // A watcher told about this host before its sender said what it
                    // is has to hear the correction, so a role it did not carry is
                    // news in the same way a status change is. Repeating one is not:
                    // a router advertises on a timer.
                    changed |= host.add_network_role(role);
                }
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
    use crate::scanner::strategy::discovery::tests::{
        LOCAL_MAC, PEER_MAC, advertisement_body, arp_reply_frame, dhcp_reply_frame,
        echo_reply_frame, mdns_frame, ndp_frame,
    };
    use pnet_base::MacAddr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// The sweep's capture narrows in the kernel, so a frame the filter does not
    /// admit is one no [`DiscoveryProtocol`] is ever offered — and it fails
    /// silently, because a protocol that is never called looks exactly like one
    /// that recognised nothing.
    ///
    /// Nothing else can catch it. The fake-LAN fixtures inject frames straight
    /// into the scanner through `EthernetHandle::from_parts`, so they bypass the
    /// capture entirely and would stay green against a filter that admitted
    /// nothing at all. This compiles the real expression with `libpcap` and runs
    /// it against real frames, which needs no interface and no privileges.
    #[test]
    fn the_sweep_filter_admits_every_frame_the_sweep_can_read() {
        let filter = super::sweep_filter();
        let program = pcap::Capture::dead(pcap::Linktype::ETHERNET)
            .expect("a dead capture")
            .compile(&filter, true)
            .unwrap_or_else(|e| panic!("the sweep filter `{filter}` does not compile: {e}"));

        // The two announcement frames need only their framing: the filter reads
        // the EtherType and the destination address, and what the sender put
        // behind them is the reader's business rather than the kernel's.
        let lldp = ethernet::create_header(
            PEER_MAC,
            MacAddr::new(0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E),
            crate::protocols::lldp::ETHERTYPE,
        );
        let cdp = {
            let group = crate::protocols::cdp::GROUP_ADDRESS;
            let mut bytes = vec![group.0, group.1, group.2, group.3, group.4, group.5];
            bytes.extend_from_slice(&[
                PEER_MAC.0, PEER_MAC.1, PEER_MAC.2, PEER_MAC.3, PEER_MAC.4, PEER_MAC.5,
            ]);
            // 802.3: a length rather than an EtherType, which is the whole
            // reason this clause matches the address instead.
            bytes.extend_from_slice(&[0x00, 0x20]);
            bytes.resize(60, 0);
            bytes
        };

        let readable: [(&str, Vec<u8>); 7] = [
            ("an ARP frame", arp_reply_frame(Ipv4Addr::new(10, 0, 0, 2))),
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
                dhcp_reply_frame(Ipv4Addr::new(192, 168, 1, 1), None),
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

    /// The other half of the same rule. A filter that admitted everything would
    /// pass the test above while undoing the reason for having one: the sweep
    /// would go back to copying the whole segment into this process.
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
                    Ipv4Addr::new(192, 168, 1, 50),
                    Ipv4Addr::new(192, 168, 1, 60),
                ))
                .push(crate::protocols::craft::Udp::new(4444, 8080).with_payload(vec![0u8; 16]))
                .build()
                .expect("a test datagram");

            [
                ethernet::create_header(
                    PEER_MAC,
                    LOCAL_MAC,
                    pnet_packet::ethernet::EtherTypes::Ipv4,
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
