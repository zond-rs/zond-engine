// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Routed host discovery
//!
//! Finds hosts reached through a gateway. Sends raw TCP SYNs to a handful of
//! ports per target (see [`SynPorts`]), or an SCTP INIT, and credits the host
//! on any answer: the handshake is never completed, so a closed port answers
//! too, and one answering port is enough.
//!
//! The counterpart of [`local`](super::local), which reaches the local segment
//! at the link layer. [`plan`](crate::scanner::plan) picks one per target from
//! this host's routing table. Needs raw sockets; probe building and sending
//! live in `raw`.

use std::num::NonZeroU32;
use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

use crate::config::ProbeTuning;
use crate::evasion::SegmentShaping;
use crate::info;
use crate::journal::settle::{Outcome, Settled};
use crate::model::host::{HostStatus, StatusProtocol, StatusReason};
use crate::model::ip::set::IpSet;
use crate::model::port::set::COMMON_DISCOVERY_PORTS;
use crate::model::port::{PortSet, Protocol, TCP_BY_PREVALENCE};
use crate::model::technique::{TcpReply, TcpScanTechnique};
use crate::protocols as protocol;
use crate::scanner::dispatcher::WalkOrder;
use crate::scanner::pacing::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig, HeldAllowance};
use crate::scanner::pacing::retry::{ProbeLedger, Resolution, RetryPolicy};
use crate::scanner::session::ScanContext;
use crate::system::interface::RoutedTarget;
use crate::transport::capture::CapturedSegment;
use crate::transport::probe::{Emission, ProbeKind, ProbeTransport};
use async_trait::async_trait;
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use tokio::sync::mpsc::UnboundedSender;

use crate::report::ScannerKind;
use crate::report::StopReason;
use crate::scanner::strategy::raw::{
    DEADLINE_CONFIG, EvasionParts, RETRY_POLICY, SendFaults, SynToken, pacing_for, rate_within,
    send_init, send_syn,
};
use crate::scanner::strategy::sweep::HostSweep;
use crate::scanner::strategy::{HostScanner, StrategyError};

/// The fastest a routed sweep puts probes on the wire, in probes per second.
///
/// A probe's chance of being answered falls as the rate rises. Unpaced, a sweep
/// of a large range loses most of its first attempt and recovers those hosts
/// only by retransmitting, at several times the traffic.
///
/// Set below where that loss begins. Measured against a /22 where every address
/// answers, the first attempt finds a sixth to a third of the range unpaced and
/// about three quarters at this rate, and the sweep needs roughly half the
/// packets. Loss reappears at several times this rate.
///
/// The cost is emission time, linear in range size: a /22 leaves in a quarter
/// of a second, a /16 in sixteen.
pub(super) const PROBE_RATE_PER_SEC: NonZeroU32 = NonZeroU32::new(4_000).expect("a non-zero rate");

/// Whether `bytes` is one of the two segments a SYN probe can draw *and be
/// credited for without correlating it*.
///
/// A SYN+ACK and a RST each require the target to have received the probe and
/// answered it; nothing else a SYN elicits sets either flag.
///
/// A challenge ACK is excluded, though it is a genuine answer. The port scanner
/// can act on one because it checks the probe's nonce; this check does not, and
/// a bare ACK is the commonest segment on any network, so any established
/// connection to the address would credit the host.
fn answers_a_syn_probe(bytes: &[u8]) -> bool {
    protocol::tcp::parse(bytes)
        .ok()
        .and_then(|tcp| protocol::tcp::classify_probe_response(&tcp))
        .is_some_and(|reply| !matches!(reply, TcpReply::ChallengeAck))
}

/// The TCP ports a liveness sweep asks every address about: a routed SYN sweep
/// all of them on every attempt, a connect sweep each in turn until one
/// answers.
///
/// One port is enough for an unfiltered stack, which answers a SYN to a closed
/// port with a reset. A host behind a filter that drops SYNs to anything not
/// listening (Windows Firewall's default, an `iptables` `DROP` policy) answers
/// only on the ports it serves; asked about one it does not serve, it reads as
/// down and is never port-scanned.
///
/// So the set is two lists:
///
/// - **The common five**, SSH, HTTP, HTTPS, SMB and RDP, from
///   [`COMMON_DISCOVERY_PORTS`].
/// - **Up to [`SCAN_PORTS`](Self::SCAN_PORTS) of the scan's own ports**, for a
///   port scan's liveness pass, so a filtered host serving only those still
///   answers. The catalogue's order picks among them: a scan of a thousand
///   ports adds the likeliest few, a scan naming one port adds that port.
///
/// Both the SYN and connect sweeps use this set, so privilege decides how an
/// address is asked and never which ports. See
/// [`connect::discover_on`](super::connect::discover_on) for what a connect
/// sweep pays for it.
///
/// A SYN sweep sends all of them on every attempt, under one sequence number
/// and source port, so a reply on any of them names the attempt and retires
/// the address, and every port gets its retransmissions.
///
/// **Cost**: a packet per port per unanswered attempt. A silent range costs five
/// to eight times the packets of a single port, and the sweep paces and sizes
/// its deadline from that total. A host missed here is not port-scanned at all.
///
/// An ICMP echo and a bare ACK are not sent: neither passes the stateful
/// filters this set exists for, and an echo would need a second transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynPorts {
    /// The ports, in the order they leave, valid up to `len`.
    ports: [u16; Self::CAPACITY],
    /// How many of `ports` are in the set.
    len: u8,
}

impl SynPorts {
    /// How many of a scan's own ports the set may add to the common five.
    ///
    /// Three covers a short list of particular services in full. A broader
    /// scan's likeliest ports are the common five already.
    pub const SCAN_PORTS: usize = 3;

    /// The most ports a set can hold.
    pub const CAPACITY: usize = COMMON_DISCOVERY_PORTS.len() + Self::SCAN_PORTS;

    /// The common five alone, for a sweep that was asked about no ports.
    pub fn common() -> Self {
        let mut set = Self {
            ports: [0; Self::CAPACITY],
            len: 0,
        };
        for &port in COMMON_DISCOVERY_PORTS {
            set.push(port);
        }
        set
    }

    /// One port and nothing else, for a caller who knows which port every
    /// target it sweeps answers on and wants a packet per address per attempt.
    pub fn only(port: u16) -> Self {
        let mut set = Self {
            ports: [0; Self::CAPACITY],
            len: 0,
        };
        set.push(port);
        set
    }

    /// The common five and up to [`SCAN_PORTS`](Self::SCAN_PORTS) of the TCP
    /// ports in `scan`, for a port scan's liveness pass.
    ///
    /// Ranked by [`TCP_BY_PREVALENCE`], with uncatalogued ports after, lowest
    /// first, so the choice is the same on every run.
    pub fn for_scan(scan: &PortSet) -> Self {
        let mut set = Self::common();
        let common = set.len();
        let ranked = TCP_BY_PREVALENCE
            .iter()
            .copied()
            .filter(|&port| scan.has_tcp(port));
        let unranked = scan
            .ranges(Protocol::Tcp)
            .iter()
            .flat_map(|range| range.clone())
            .filter(|port| !TCP_BY_PREVALENCE.contains(port));
        for port in ranked.chain(unranked) {
            if set.len() == common + Self::SCAN_PORTS {
                break;
            }
            if !set.as_slice().contains(&port) {
                set.push(port);
            }
        }
        set
    }

    /// The ports, in the order they leave.
    pub fn as_slice(&self) -> &[u16] {
        &self.ports[..usize::from(self.len)]
    }

    /// How many ports an attempt asks, and so how many packets it is.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Whether the set asks no port at all, which only `excluding` can cause.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// This set less every port `excluded` names on TCP, in the order the rest
    /// leave.
    ///
    /// For a sweep held to
    /// [`ZondConfig::excluded_ports`](crate::config::ZondConfig::excluded_ports),
    /// which liveness probes obey too. Nothing replaces an excluded port. The
    /// result may be empty; declining an empty sweep is the caller's job.
    pub(crate) fn excluding(self, excluded: &PortSet) -> Self {
        let mut kept = Self {
            ports: [0; Self::CAPACITY],
            len: 0,
        };
        for &port in self.as_slice() {
            if !excluded.has_tcp(port) {
                kept.push(port);
            }
        }
        kept
    }

    fn push(&mut self, port: u16) {
        self.ports[usize::from(self.len)] = port;
        self.len += 1;
    }
}

/// Which packet a routed sweep asks with.
///
/// Pacing, retries, deadline and audit are the same either way. The packet
/// decides the transport, what a probe is, what counts as an answer, and what
/// the report says the host was found by.
///
/// A host behind a filter that passes one transport and drops the other
/// answers only one of these probes, so a scan about SCTP ports sweeps with
/// SCTP.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepProbe {
    /// TCP SYNs, never completed, one to each of a set of ports.
    Syn {
        /// The port every probe leaves from when a caller pinned one (say, a
        /// port a filter trusts), or `None` for a fresh high port per attempt.
        /// The reply names its attempt by port and sequence number; a pinned
        /// port leaves only the sequence number varying.
        src_port: Option<u16>,
        /// The ports every attempt is aimed at, all of them each time.
        dst_ports: SynPorts,
    },
    /// An SCTP INIT, for a scan that asked about SCTP.
    ///
    /// Both answers prove the host: an INIT-ACK accepts the association, an
    /// ABORT refuses it. The association is never completed.
    Init {
        /// The one port every probe leaves from, fixed because the capture
        /// filter narrows on it; the Initiate Tag varies per attempt.
        src_port: u16,
        /// The port every probe is aimed at, taken from the ports the scan is
        /// about, since a filter passing SCTP most likely passes it there.
        dst_port: u16,
    },
}

impl SweepProbe {
    /// A SYN sweep asking the common five ports; see [`SynPorts::common`].
    pub fn syn(src_port: Option<u16>) -> Self {
        Self::syn_to(src_port, SynPorts::common())
    }

    /// A SYN sweep asking `dst_ports`.
    pub const fn syn_to(src_port: Option<u16>, dst_ports: SynPorts) -> Self {
        Self::Syn {
            src_port,
            dst_ports,
        }
    }

    /// An INIT sweep, leaving from `src_port` and asking `dst_port`.
    pub const fn init(src_port: u16, dst_port: u16) -> Self {
        Self::Init { src_port, dst_port }
    }

    /// This sweep, its probes leaving from `port` when a transport's capture
    /// admits replies to that port alone.
    const fn leaving_from(self, port: Option<u16>) -> Self {
        match (self, port) {
            (Self::Syn { dst_ports, .. }, Some(port)) => Self::Syn {
                src_port: Some(port),
                dst_ports,
            },
            (Self::Init { dst_port, .. }, Some(port)) => Self::Init {
                src_port: port,
                dst_port,
            },
            (probe, _) => probe,
        }
    }

    /// The transport this sweep's probes and answers travel over.
    const fn transport(self) -> ProbeKind {
        match self {
            Self::Syn { .. } => ProbeKind::TcpSyn,
            Self::Init { src_port, .. } => ProbeKind::Sctp {
                reply_port: src_port,
            },
        }
    }

    /// How many packets one attempt at one address puts on the wire; the unit
    /// of the sweep's pacing and deadline.
    fn packets_per_attempt(self) -> u32 {
        match self {
            Self::Syn { dst_ports, .. } => dst_ports.len() as u32,
            Self::Init { .. } => 1,
        }
    }

    /// Which strategy a sweep asking this way reports itself as.
    const fn scanner_kind(self) -> ScannerKind {
        match self {
            Self::Syn { .. } => ScannerKind::Routed,
            Self::Init { .. } => ScannerKind::RoutedSctp,
        }
    }

    /// The IP protocol an answer to this probe arrives under, the same one the
    /// probe left under.
    const fn answered_under(self) -> IpNextHeaderProtocol {
        match self {
            Self::Syn { .. } => IpNextHeaderProtocols::Tcp,
            Self::Init { .. } => IpNextHeaderProtocols::Sctp,
        }
    }

    /// Whether `reply` answers a probe of this kind at all.
    ///
    /// The capture filter narrows what arrives, but over IPv6 it cannot filter
    /// TCP flags, the INIT sweep's filter admits every ICMP message for the
    /// SCTP port scan sharing it, and a transport can be built with no filter.
    ///
    /// The protocol is checked before parsing, since a Layer-4 header does not
    /// say what it is: an ICMP error read as SCTP puts its first chunk on the
    /// quoted IPv4 identification, which spells an INIT-ACK or an ABORT often
    /// enough to credit a host falsely.
    fn answers(self, reply: &CapturedSegment) -> bool {
        if reply.protocol != self.answered_under().0 {
            return false;
        }
        match self {
            Self::Syn { .. } => answers_a_syn_probe(&reply.bytes),
            // An INIT-ACK or an ABORT, which other associations' packets lack.
            Self::Init { .. } => protocol::sctp::parse(&reply.bytes)
                .ok()
                .and_then(|packet| protocol::sctp::classify_probe_response(&packet))
                .is_some(),
        }
    }

    /// The attempt `bytes` names, for matching against an outstanding probe.
    fn token_of(self, bytes: &[u8], padding: u16) -> Option<SweepToken> {
        match self {
            Self::Syn { .. } => protocol::tcp::parse(bytes).ok().map(|tcp| {
                SweepToken::Syn(SynToken {
                    seq: protocol::tcp::echoed_nonce(TcpScanTechnique::Syn, &tcp, padding),
                    src_port: tcp.destination_port(),
                })
            }),
            Self::Init { .. } => protocol::sctp::parse(bytes)
                .ok()
                .map(|packet| SweepToken::Init(protocol::sctp::echoed_nonce(&packet))),
        }
    }

    /// What a report says about a host this probe found.
    fn evidence(self) -> StatusReason {
        match self {
            // A SYN+ACK and a RST both prove a live stack.
            Self::Syn { .. } => {
                StatusReason::new(StatusProtocol::TcpSyn, "tcp reply to a discovery probe")
            }
            Self::Init { .. } => {
                StatusReason::new(StatusProtocol::Sctp, "sctp reply to a discovery probe")
            }
        }
    }
}

/// What identifies one attempt of a sweep's probe on the wire; one token kind
/// per [`SweepProbe`] kind.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SweepToken {
    /// A SYN's sequence number and source port. See [`SynToken`].
    Syn(SynToken),
    /// An INIT's Initiate Tag, which RFC 4960 §3.3.2 obliges a peer to echo in
    /// the verification tag of whatever it answers with.
    Init(u32),
}

/// Checks whether addresses behind a gateway are alive, putting raw probes to
/// each and crediting whatever comes back.
///
/// Every probe leaves from the source address its route named.
/// [`new`](Self::new) opens the raw transport, which takes root;
/// [`with_transport`](Self::with_transport) takes one the caller opened.
pub struct RoutedScanner {
    /// Shared state (host store, event channel, abort signal) for the scan.
    ctx: ScanContext,
    /// The source address to probe each target from, kept for the whole sweep
    /// so a retry leaves from the same place.
    sources: HashMap<IpAddr, IpAddr>,
    /// Membership-and-count view of the targets, used to filter incoming
    /// replies and to size the adaptive deadline.
    ips: IpSet,
    /// Transport used to send SYN probes and receive replies.
    transport: ProbeTransport,
    /// What this sweep asks with.
    probe: SweepProbe,
    /// The IP-header state every SYN carries: its hop limit and any evasion
    /// override of the IP header.
    emission: Emission,
    /// The segment-level shaping every SYN carries: payload padding, and a bad
    /// TCP checksum when the sweep asked for one.
    shaping: SegmentShaping,
    /// The decoy source addresses every SYN is copied from, or empty.
    decoys: Vec<IpAddr>,
    /// Governs how long this sweep keeps running, adapting to observed
    /// round-trip times.
    deadline: AdaptiveDeadline,
    /// Where to forward newly discovered addresses for hostname
    /// resolution, if enabled.
    dns_tx: Option<UnboundedSender<IpAddr>>,
    /// Outstanding probes, retry queue, answers and counters, shared with the
    /// other probing sweeps.
    sweep: HostSweep<SweepToken>,
    /// Targets whose first probe has not left yet, released by the send ticker.
    pending: std::vec::IntoIter<IpAddr>,
    /// Targets whose first probe was put off by the scan's probe gap or by a
    /// kernel hold-down on their neighbour (see [`SendFaults::hold`]); each is
    /// sent once both allow it.
    held: std::collections::VecDeque<IpAddr>,
    /// How much hold-down time the deadline has been given.
    held_allowed: HeldAllowance,
    /// How often the send ticker fires, and how many probes it releases each
    /// time; together the configured rate (see [`pacing_for`]).
    send_tick: Duration,
    batch: usize,
    /// Why sends failed, if any did, for the report. The audit's count cannot
    /// tell no route from refused raw sockets, which call for different fixes.
    faults: SendFaults,
}

#[async_trait]
impl HostScanner for RoutedScanner {
    fn kind(&self) -> ScannerKind {
        self.probe.scanner_kind()
    }

    async fn discover_hosts(&mut self) -> Result<(), StrategyError> {
        let mut send_tick = tokio::time::interval(self.send_tick);
        // Otherwise missed ticks fire in a burst after a busy stretch.
        send_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let reason = loop {
            let now = Instant::now();
            // Waiting answers first, so one that arrived before its probe came
            // due settles it before the timer retires it; see the port scans'
            // `read_waiting_replies`.
            self.read_waiting_replies();
            self.sweep.service_retries(&self.ctx, now);

            let all_responded = self.sweep.all_responded(self.ips.len());
            if let Some(cause) = self.ctx.handle.stopped() {
                break cause.into();
            }
            if all_responded {
                break StopReason::AllResponded;
            }
            // Every target answered or was asked its last time. The send queues
            // are checked too, since the ledger is empty before the first send.
            if self.nothing_left_to_send() && self.sweep.ledger.is_empty() {
                break StopReason::AttemptsSpent;
            }
            if self.deadline.hard_deadline_passed() {
                break StopReason::DeadlineExpired;
            }

            let sending = !self.nothing_left_to_send();
            let tick = self.sweep.idle_delay(&self.deadline, now);

            tokio::select! {
                res = self.transport.rx.recv() => {
                    match res {
                        Some(reply) => {
                            self.sweep.audit.record_segment();
                            // Capture time; see `CapturedSegment::received_at`.
                            self.handle_discovery_reply(&reply, reply.received_at);
                        }
                        None => break StopReason::StreamClosed,
                    }
                },

                _ = send_tick.tick(), if sending => {
                    self.send_allowance(Instant::now());
                }

                // Wakes when the next probe is due, so retries go out on time in
                // silence. While sending, the ticker above drives the loop.
                _ = tokio::time::sleep(tick), if !sending => {}
            }
        };

        self.finish(reason);
        Ok(())
    }
}

/// How much longer than its pacing needs a sweep is allowed to send for.
///
/// A multiple, since the shortfall grows with the sweep: the ticker delays
/// missed ticks, so every stretch spent on replies pushes the remaining
/// schedule back. 1.5 covers a loop kept busy a third of the time. Only a sweep
/// still sending at the end spends it.
const SEND_SLACK: f64 = 1.5;

/// How a sweep of `target_count` addresses asking `probe` paces its sends, and
/// the deadline it runs under: the send ticker's interval, how many addresses
/// each tick releases, and the deadline's configuration.
fn schedule(
    target_count: usize,
    probe: SweepProbe,
    retry: &RetryPolicy,
    rate_per_sec: NonZeroU32,
    gap: Option<Duration>,
    scan_gap: Option<Duration>,
) -> (Duration, usize, AdaptiveDeadlineConfig) {
    // The rate is in packets, as a policer counts them; the ticker releases
    // addresses, each one attempt of `packets_per_attempt` packets.
    let addresses_per_sec = NonZeroU32::new(rate_per_sec.get() / probe.packets_per_attempt())
        .unwrap_or(NonZeroU32::MIN);
    let (send_tick, batch) = pacing_for(addresses_per_sec);

    // The deadline must outlive the retry schedule and the send rate. Cutting
    // the sweep off mid-send fails invisibly: an unprobed address looks empty.
    //
    // The schedule is taken at its longest, every attempt at the ceiling (a
    // sweep that heard slow hosts times the rest from them) and at the longer
    // probe gap, which a retry waits out with its clock stopped.
    //
    // Retries leave through the same ticker, so a silent range takes the
    // ticker's time once per attempt. Given to the deadline as a pace per
    // address so the ceiling covers the range (see `ScanBudget::covering`).
    // The slack costs nothing once attempts are spent.
    //
    // The scan-wide gap paces one attempt per gap, whatever the port count,
    // and wins where it is slower.
    let by_rate = Duration::from_secs_f64(
        SEND_SLACK * f64::from(retry.max_attempts) / f64::from(addresses_per_sec.get()),
    );
    let by_gap = scan_gap
        .unwrap_or_default()
        .saturating_mul(u32::from(retry.max_attempts));
    let per_address = by_rate.max(by_gap);
    let deadline_config = DEADLINE_CONFIG
        .allowing_for(retry.longest_spaced_probe_lifetime(gap))
        .allowing_pace_of(per_address, target_count);

    (send_tick, batch, deadline_config)
}

impl RoutedScanner {
    /// A sweep of `targets`, each already paired with the source address to
    /// probe it from, over a transport this constructor opens, asking the
    /// common five ports.
    ///
    /// Hosts land in `ctx`, which also carries the abort signal; every address
    /// found is posted to `dns_tx` for a reverse lookup (`None` for no
    /// lookups). `tuning` supplies the retry schedule, the probe rate, and the
    /// evasion profile that shapes each packet and the transport.
    ///
    /// Fails when the transport cannot be opened, as without root.
    pub fn new(
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        tuning: ProbeTuning,
    ) -> Result<Self, StrategyError> {
        Self::over_tcp(targets, ctx, dns_tx, tuning, SynPorts::common())
    }

    /// [`new`](Self::new), asking `ports`.
    ///
    /// A port scan's liveness pass passes [`SynPorts::for_scan`], so a filtered
    /// host is asked about the ports the scan is about to ask it.
    pub fn over_tcp(
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        tuning: ProbeTuning,
        ports: SynPorts,
    ) -> Result<Self, StrategyError> {
        Self::asking(
            SweepProbe::syn_to(tuning.evasion.source_port, ports),
            targets,
            ctx,
            dns_tx,
            tuning,
        )
    }

    /// A sweep of `targets` sending one SCTP INIT per address to `dst_port`.
    ///
    /// For a scan whose ports name SCTP: a host that answers only SCTP reads as
    /// down to a SYN sweep, and its ports are never probed. `dst_port` comes
    /// from the ports the scan is about; see [`SweepProbe::Init`].
    ///
    /// Fails when the raw transport cannot be opened, as without root.
    pub fn over_sctp(
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        tuning: ProbeTuning,
        dst_port: u16,
    ) -> Result<Self, StrategyError> {
        let src_port = tuning
            .evasion
            .source_port
            .unwrap_or_else(|| rand::random_range(50_000..u16::MAX));
        Self::asking(
            SweepProbe::init(src_port, dst_port),
            targets,
            ctx,
            dns_tx,
            tuning,
        )
    }

    /// Opens the transport `probe` calls for and hands the rest to
    /// [`build`](Self::build).
    fn asking(
        probe: SweepProbe,
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        tuning: ProbeTuning,
    ) -> Result<Self, StrategyError> {
        let transport = ProbeTransport::open_capturing(
            probe.transport(),
            tuning.evasion.effective_send_mode(tuning.send_mode),
            &ctx.capture_links(),
        )?;
        Ok(Self::build(
            targets,
            ctx,
            dns_tx,
            transport,
            probe,
            tuning.evasion.emission(),
            tuning.evasion.segment_shaping(),
            tuning.evasion.decoys.clone(),
            RETRY_POLICY.configured(tuning.retry),
            rate_within(
                tuning.max_probe_rate,
                tuning.min_probe_rate,
                PROBE_RATE_PER_SEC,
            ),
        ))
    }

    /// Builds a sweep around an already-opened transport, so the caller decides
    /// how probes reach the wire and where replies come from.
    ///
    /// For a caller orchestrating their own scan, for example through a
    /// transport with a particular send mode or bound to particular interfaces.
    /// With a synthetic transport (`ProbeTransport::from_parts`, behind the
    /// `test-support` feature) it drives liveness detection and RTT correlation
    /// against a simulated network.
    pub fn with_transport(
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        transport: ProbeTransport,
    ) -> Self {
        Self::with_transport_asking(targets, ctx, dns_tx, transport, SweepProbe::syn(None))
    }

    /// [`with_transport`](Self::with_transport) asking with `probe`.
    ///
    /// The transport must be one `probe` would have opened: an INIT sweep on a
    /// TCP-filtered capture hears nothing and reports an empty range. Probes
    /// leave from the transport's reply port where it fixes one, whatever port
    /// `probe` names; see [`ProbeTransport::reply_port`].
    pub fn with_transport_asking(
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        transport: ProbeTransport,
        probe: SweepProbe,
    ) -> Self {
        Self::build(
            targets,
            ctx,
            dns_tx,
            transport,
            probe,
            Emission::routed(),
            SegmentShaping::default(),
            Vec::new(),
            RETRY_POLICY,
            PROBE_RATE_PER_SEC,
        )
    }

    /// The common constructor. Takes the retry schedule and send rate because
    /// the deadline is derived from both.
    #[allow(clippy::too_many_arguments)]
    fn build(
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        transport: ProbeTransport,
        probe: SweepProbe,
        emission: Emission,
        shaping: SegmentShaping,
        decoys: Vec<IpAddr>,
        retry: RetryPolicy,
        rate_per_sec: NonZeroU32,
    ) -> Self {
        let mut ips = IpSet::new();
        let mut order = Vec::with_capacity(targets.len());
        let mut sources = HashMap::with_capacity(targets.len());
        for RoutedTarget { target, source } in targets {
            ips.insert(target);
            if sources.insert(target, source).is_none() {
                order.push(target);
            }
        }
        ips.canonicalize();
        // In the seed's walk order: a sweep in address order is what a
        // correlating sensor keys on.
        if let Some(walk) = WalkOrder::of(&ips, &ctx) {
            walk.arrange(&mut order);
        }

        let target_count = sources.len();
        let probe = probe.leaving_from(transport.reply_port());

        let (send_tick, batch, deadline_config) = schedule(
            target_count,
            probe,
            &retry,
            rate_per_sec,
            ctx.probe_gap(),
            ctx.scan_probe_interval(),
        );

        Self {
            ctx,
            sources,
            ips,
            transport,
            probe,
            emission,
            shaping,
            decoys,
            deadline: AdaptiveDeadline::new(deadline_config, target_count),
            dns_tx,
            sweep: HostSweep::new(ProbeLedger::new(retry, target_count)),
            pending: order.into_iter(),
            held: std::collections::VecDeque::new(),
            held_allowed: HeldAllowance::default(),
            send_tick,
            batch,
            faults: SendFaults::default(),
        }
    }

    /// Files what the sweep leaves behind once its loop has stopped for
    /// `reason`: the addresses it reached no verdict on and why, the sends that
    /// failed, and its audit.
    fn finish(&mut self, reason: StopReason) {
        // `Routed` for the SYN sweep, `RoutedSctp` for the INIT one.
        let kind = self.kind();
        let label = match self.probe {
            SweepProbe::Init { .. } => "sctp-discovery",
            _ => "routed-discovery",
        };

        // Addresses without a verdict, so a resumed sweep asks them again: cut
        // off mid-schedule, never sent, or never routable.
        let interrupted = self.sweep.ledger.drain_unresolved();
        let unasked: Vec<IpAddr> = self.held.drain(..).chain(self.pending.by_ref()).collect();
        self.ctx
            .record_address_outcomes(Outcome::Interrupted, interrupted.len() as u64);
        self.ctx
            .record_address_outcomes(Outcome::Unasked, unasked.len() as u64);

        // Unasked addresses narrow the result, so they are a failure, but only
        // where the sweep stopped itself: an abort or a budget is the caller's.
        if !unasked.is_empty() && !matches!(reason, StopReason::Aborted | StopReason::TimedOut) {
            self.ctx.record_failure(
                self.kind(),
                format!(
                    "{} of {} addresses were never asked: {reason} with them \
                     still queued",
                    unasked.len(),
                    self.sources.len(),
                ),
            );
        }
        // Distinct addresses: an unroutable target fails on every retry.
        self.ctx
            .record_address_outcomes(Outcome::Unroutable, self.faults.addresses.len() as u64);

        // Probes that never left would otherwise look like a sweep that found
        // nothing, so this host's send failures are recorded as a failure, once
        // with the first cause. An address with no route is recorded against the
        // address, so a dual-stack name on an IPv4-only network does not mark
        // every scan partial. The shared filing does both.
        self.faults.file(
            &self.ctx,
            kind,
            "probes",
            self.sweep.audit.sends_attempted,
            self.sweep.audit.sends_failed,
        );

        // Names the address at -v; the default console has the count already.
        // Counted in addresses, since each attempt is a packet per port.
        // "Unreachable" covers a neighbour that never answered address
        // resolution, which has a route. No error prefix or errno: the scan
        // itself is fine, and the send's own line carries the detail.
        if let Some((address, _)) = &self.faults.unroutable {
            match self.faults.addresses.len().saturating_sub(1) {
                0 => info!(verbosity = 1, "{address} unreachable"),
                1 => info!(verbosity = 1, "{address} and 1 other address unreachable"),
                more => info!(
                    verbosity = 1,
                    "{address} and {more} other addresses unreachable"
                ),
            }
        }

        // Read while the transport keeps the capture threads alive.
        let capture = self.transport.capture_counts();
        let targets = self.ips.len();
        self.sweep
            .report(&self.ctx, label, kind, targets, reason, capture);
    }

    /// Records a captured reply as evidence its sender is alive, if it answers
    /// this sweep's probe, crediting it with a round-trip time if it names an
    /// outstanding attempt.
    fn handle_discovery_reply(&mut self, reply: &CapturedSegment, now: Instant) {
        let ip = reply.source;
        if !self.ips.contains(&ip) {
            self.sweep.audit.record_off_target();
            return;
        }

        // `tcp[tcpflags]` does not compile for IPv6, so the transport admits
        // established traffic there and the flags are checked here, holding
        // both families to what the IPv4 filter admits.
        if !self.probe.answers(reply) {
            self.sweep.audit.record_off_target();
            return;
        }

        let resolution = self.resolve_probe(ip, &reply.bytes, now);
        let rtt = resolution.and_then(|resolution| resolution.rtt);
        if rtt.is_none() {
            self.sweep.audit.record_reply_without_rtt();
        }

        // Host mutation only, so the follow-ups below run outside the store
        // lock. The return value reports store novelty and is ignored; the
        // decisions below are about this sweep's first sighting.
        let evidence = self.probe.evidence();
        self.ctx.write_host(ip, |host| {
            let was_up = host.status().is_up();
            host.record_evidence(HostStatus::Up, evidence.clone());

            if let Some(rtt) = rtt {
                host.add_rtt_from(rtt, evidence.protocol.clone());
                return true;
            }
            !was_up
        });
        // Settled once the answer is stored; see `ScanContext::record_outcome`.
        self.ctx.settle_address(ip, Settled::Answered);

        if self.sweep.responded.insert(ip) {
            self.sweep
                .audit
                .record_host_found(resolution.and_then(|resolution| resolution.answered_attempt));
            self.deadline.mark_activity();
            if let Some(dns) = &self.dns_tx {
                let _ = dns.send(ip);
            }
        }

        if let Some(rtt) = rtt {
            self.deadline.record_rtt(rtt);
        }
    }

    /// Retires the probe to `ip` and reports what resolving it revealed.
    ///
    /// Matches the exact attempt the segment acknowledges first, which gives a
    /// true round trip even after retries. Failing that, the reply still
    /// retires the probe without a round trip, since discovery only asks
    /// whether something is there.
    fn resolve_probe(&mut self, ip: IpAddr, bytes: &[u8], now: Instant) -> Option<Resolution> {
        let token = self
            .probe
            .token_of(bytes, self.shaping.padding.unwrap_or(0));

        token
            .and_then(|token| self.sweep.ledger.resolve(&ip, Some(token), now))
            .or_else(|| self.sweep.ledger.resolve(&ip, None, now))
    }

    /// Reads every reply already waiting in the capture stream, without
    /// waiting for more, bounded by what is queued on entry.
    ///
    /// A loop held up past a timeout wakes to the answer and the expired timer
    /// at once; handling the timer first would spend the last attempt and stop
    /// the sweep with a live host's answer unread.
    fn read_waiting_replies(&mut self) {
        let waiting = self.transport.rx.len();
        for _ in 0..waiting {
            let Ok(reply) = self.transport.rx.try_recv() else {
                return;
            };
            self.sweep.audit.record_segment();
            self.handle_discovery_reply(&reply, reply.received_at);
        }
    }

    /// Whether every probe this sweep intends to send has left.
    fn nothing_left_to_send(&self) -> bool {
        self.sweep.retries.is_empty() && self.held.is_empty() && self.pending.len() == 0
    }

    /// Releases one tick's worth of probes: retries first, then targets not yet
    /// asked.
    fn send_allowance(&mut self, now: Instant) {
        for _ in 0..self.batch {
            // A ready retry first; one the probe gaps turn away stays queued
            // with its clock stopped. A first attempt can be turned away too,
            // by another pass's probe to the address or the scan-wide gap, and
            // is then held; see `probe`.
            if let Some(target) = self.next_ready_retry(now) {
                self.reprobe(target, now);
            } else if let Some(target) = self.next_unheld(now) {
                self.probe(target, now);
            } else if let Some(target) = self.pending.next() {
                self.probe(target, now);
            } else {
                return;
            }
        }
    }

    /// The first queued retry whose host may be asked now, taken off the
    /// queue, or `None` where none is ready.
    ///
    /// A retry whose probe has left the ledger was answered while it waited and
    /// is dropped. One turned away for the gap goes to the back. The walk is
    /// bounded by the queue's length on entry.
    fn next_ready_retry(&mut self, now: Instant) -> Option<IpAddr> {
        for _ in 0..self.sweep.retries.len() {
            let target = self.sweep.retries.pop_front()?;
            if !self.sweep.ledger.contains(&target) {
                continue;
            }
            if self.ctx.probe_ready_at(target, now).is_some()
                || self.faults.held_until(target, now).is_some()
            {
                self.sweep.retries.push_back(target);
                continue;
            }
            return Some(target);
        }
        None
    }

    /// The first held target whose hold-down is over and whose slot is free,
    /// taken off the queue, or `None` where none is.
    fn next_unheld(&mut self, now: Instant) -> Option<IpAddr> {
        let ready = self.held.iter().position(|target| {
            self.faults.held_until(*target, now).is_none()
                && self.ctx.probe_ready_at(*target, now).is_none()
        })?;
        self.held.remove(ready)
    }

    /// Whether the kernel refused the attempt just made at `target` for a
    /// hold-down on its neighbour. If so the deadline is given the hold time,
    /// once for overlapping holds.
    fn held_down(&mut self, target: IpAddr, now: Instant) -> bool {
        let Some(until) = self.faults.held_until(target, now) else {
            return false;
        };
        self.deadline
            .allow_for_holding(self.held_allowed.take(now, until));
        true
    }

    /// Puts the first attempt at `target` on the wire and arms its probe.
    ///
    /// Armed if any of its packets left, so an address never asked earns no
    /// verdict. One the probe gaps turn away, or the kernel refuses for a
    /// neighbour's hold-down, is held until both allow it; a refused one gives
    /// back its slot.
    fn probe(&mut self, target: IpAddr, now: Instant) {
        let Ok(claim) = self.ctx.claim_probe(target) else {
            self.held.push_back(target);
            return;
        };
        match self.send_attempt(target, now) {
            Some(token) => self.sweep.ledger.arm(target, target, token, (), now),
            None => {
                self.ctx.refund_probe(claim);
                if self.held_down(target, now) {
                    self.held.push_back(target);
                }
            }
        }
    }

    /// Puts a queued retry at `target` on the wire, and restarts its probe's
    /// clock: from the send, or from now for a retry none of whose packets
    /// left, whose attempt stays charged so an unroutable target still runs
    /// out of attempts on schedule. See [`HostSweep::retries`].
    ///
    /// One refused for a neighbour's hold-down, or whose slot another pass
    /// took, goes back to the queue with its clock still stopped.
    fn reprobe(&mut self, target: IpAddr, now: Instant) {
        let Ok(claim) = self.ctx.claim_probe(target) else {
            self.sweep.retries.push_back(target);
            return;
        };
        match self.send_attempt(target, now) {
            Some(token) => self.sweep.ledger.rearm(target, target, token, now),
            None => {
                self.ctx.refund_probe(claim);
                if self.held_down(target, now) {
                    self.sweep.retries.push_back(target);
                } else {
                    self.sweep.ledger.resume(&target, now);
                }
            }
        }
    }

    /// Sends one attempt at `target`, returning the token it carried if any
    /// of its packets left.
    fn send_attempt(&mut self, target: IpAddr, now: Instant) -> Option<SweepToken> {
        let &source = self.sources.get(&target)?;

        match self.probe {
            SweepProbe::Syn {
                src_port,
                dst_ports,
            } => {
                let token = SynToken::fresh(src_port);
                let mut sent = false;
                for &dst_port in dst_ports.as_slice() {
                    // Skip the rest while the kernel holds its neighbour down.
                    if self.faults.held_until(target, now).is_some() {
                        break;
                    }
                    let left = send_syn(
                        self.transport.tx.as_ref(),
                        source,
                        target,
                        None,
                        dst_port,
                        token,
                        EvasionParts {
                            emission: self.emission,
                            shaping: self.shaping,
                            decoys: &self.decoys,
                        },
                        &mut self.faults,
                    );
                    self.sweep.audit.record_send(left);
                    sent |= left;
                }
                sent.then_some(SweepToken::Syn(token))
            }
            SweepProbe::Init { src_port, dst_port } => {
                let tag = send_init(
                    self.transport.tx.as_ref(),
                    source,
                    target,
                    None,
                    dst_port,
                    src_port,
                    &self.decoys,
                    self.emission,
                    &mut self.faults,
                );
                self.sweep.audit.record_send(tag.is_some());
                tag.map(SweepToken::Init)
            }
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
    use std::net::Ipv4Addr;

    use pnet_packet::icmp::IcmpTypes;
    use pnet_packet::icmp::destination_unreachable::{
        IcmpCodes, MutableDestinationUnreachablePacket,
    };

    use crate::config::RetryConfig;
    use crate::model::technique::SctpReply;
    use crate::protocols::craft::{self, Field};
    use crate::scanner::session::{ScanContext, ScanSession};
    use crate::transport::probe::MockSender;

    /// The ports a scan of `spec` has its liveness pass ask.
    fn asked_for(spec: &str) -> Vec<u16> {
        SynPorts::for_scan(&PortSet::try_from(spec).expect("a port specification"))
            .as_slice()
            .to_vec()
    }

    /// A sweep over a transport opened for replies to one port leaves from
    /// that port, whatever port its probe named, or it would hear nothing.
    #[test]
    fn a_sweep_leaves_from_the_port_its_transport_hears_replies_on() {
        let (_session, ctx) = ScanSession::new();
        let (_reply_tx, rx) = tokio::sync::mpsc::channel(1);
        let transport = ProbeTransport::from_parts(Box::new(MockSender::default()), rx)
            .opened_for(ProbeKind::Sctp { reply_port: 5_000 });
        let sweep = RoutedScanner::with_transport_asking(
            Vec::new(),
            ctx,
            None,
            transport,
            SweepProbe::init(4_000, 80),
        );
        assert_eq!(sweep.probe, SweepProbe::init(5_000, 80));

        let unfixed = SweepProbe::syn(None);
        assert_eq!(
            unfixed.leaving_from(None),
            unfixed,
            "a transport fixing none"
        );
    }

    /// A sweep asks at least what the unprivileged sweep asks, pinned against
    /// the list that sweep reads.
    #[test]
    fn the_common_set_is_the_list_the_unprivileged_sweep_asks() {
        assert_eq!(SynPorts::common().as_slice(), COMMON_DISCOVERY_PORTS);
    }

    /// A scan naming a few ports has every one of them asked, beside the
    /// common five, so a host serving only one of them is found.
    #[test]
    fn a_scan_of_a_short_list_has_all_of_it_asked() {
        assert_eq!(
            asked_for("8443,3306"),
            [COMMON_DISCOVERY_PORTS, &[8443, 3306]].concat(),
            "the catalogue ranks 8443 ahead of 3306, so it leaves first"
        );
    }

    /// A broad scan adds the catalogue's likeliest ports, up to capacity.
    #[test]
    fn a_broad_scan_adds_its_highest_ranked_ports_up_to_the_limit() {
        let asked = asked_for("1-65535");
        assert_eq!(asked.len(), SynPorts::CAPACITY);
        assert_eq!(
            asked[COMMON_DISCOVERY_PORTS.len()..],
            TCP_BY_PREVALENCE[5..8],
            "the three ranked straight after the common five"
        );
    }

    /// A port the catalogue does not know is still asked, after every one it
    /// does and lowest first, so the choice is the same on every run.
    #[test]
    fn a_port_the_catalogue_does_not_rank_comes_after_one_it_does() {
        assert_eq!(
            asked_for("40001,40000,8080")[COMMON_DISCOVERY_PORTS.len()..],
            [8080, 40000, 40001]
        );
    }

    /// A scan port already among the common five is not asked twice, and does
    /// not spend one of the scan's places.
    #[test]
    fn a_scan_port_among_the_common_five_is_asked_once() {
        assert_eq!(asked_for("22,443"), COMMON_DISCOVERY_PORTS);
    }

    /// An excluded port leaves the set and nothing else does, and a UDP
    /// exclusion of the same number leaves it alone.
    #[test]
    fn an_excluded_port_is_not_asked_and_the_rest_keep_their_order() {
        let excluded = |spec: &str| PortSet::try_from(spec).expect("a port specification");

        let asked = SynPorts::for_scan(&excluded("8443"));
        assert_eq!(
            asked.excluding(&excluded("22,445,u:80")).as_slice(),
            [80, 443, 3389, 8443]
        );
        assert!(
            SynPorts::common()
                .excluding(&excluded("1-65535"))
                .is_empty()
        );
        assert_eq!(
            SynPorts::common().excluding(&PortSet::new()),
            SynPorts::common()
        );
    }

    /// The hard deadline a sweep of `targets` addresses runs under.
    fn hard_deadline(targets: usize, retry: RetryConfig, rate: NonZeroU32) -> Duration {
        let (_, _, deadline) = schedule(
            targets,
            SweepProbe::syn(None),
            &RETRY_POLICY.configured(retry),
            rate,
            None,
            None,
        );
        deadline.max_budget.for_target_count(targets)
    }

    /// What a silent range of `targets` costs to put on the wire at `rate`,
    /// computed independently of the sweep: every attempt at every address,
    /// one packet per port.
    fn every_packet_sent(targets: usize, attempts: u8, rate: u32) -> Duration {
        let packets = targets * usize::from(attempts) * SynPorts::common().len();
        Duration::from_secs_f64(packets as f64 / f64::from(rate))
    }

    /// A sweep is given at least the time its own pacing needs to ask every
    /// address as often as its schedule says, retries included, however large
    /// the range, however slow the rate and however many attempts. An address
    /// never asked looks like one with nothing on it.
    #[test]
    fn a_sweep_outlasts_the_time_its_pacing_needs_to_send_every_attempt() {
        const SLASH_16: usize = 1 << 16;
        let default_rate = PROBE_RATE_PER_SEC;
        let thorough = RetryConfig {
            effort: crate::config::ScanEffort::Thorough,
            ..RetryConfig::default()
        };
        let cases = [
            (
                "a /16 by default",
                SLASH_16,
                RetryConfig::default(),
                3,
                default_rate,
            ),
            ("a /16 at thorough", SLASH_16, thorough, 5, default_rate),
            (
                "a /16 at 1000 packets a second",
                SLASH_16,
                RetryConfig::default(),
                3,
                NonZeroU32::new(1_000).expect("non-zero"),
            ),
            (
                "a /15 by default",
                2 * SLASH_16,
                RetryConfig::default(),
                3,
                default_rate,
            ),
        ];

        for (case, targets, retry, attempts, rate) in cases {
            let needed = every_packet_sent(targets, attempts, rate.get());
            let given = hard_deadline(targets, retry, rate);
            assert!(
                given >= needed,
                "{case}: needs {needed:?} to send every attempt and is given {given:?}"
            );
        }
    }

    /// A sweep outlasts the schedule of the last address it asks, with every
    /// attempt timed at the retry ceiling, as a sweep that heard slow hosts
    /// may time it.
    #[test]
    fn a_sweep_outlasts_a_probe_timed_at_the_ceiling_on_every_attempt() {
        let thorough = RetryConfig {
            effort: crate::config::ScanEffort::Thorough,
            ..RetryConfig::default()
        };
        for (case, retry) in [
            ("by default", RetryConfig::default()),
            ("at thorough", thorough),
        ] {
            let needed = RETRY_POLICY.configured(retry).longest_probe_lifetime();
            let given = hard_deadline(1, retry, PROBE_RATE_PER_SEC);
            assert!(
                given >= needed,
                "one address {case}: its schedule at the ceiling takes {needed:?} \
                 and the sweep is given {given:?}"
            );
        }
    }

    /// A sweep keeping a gap between two probes at one host outlasts the
    /// schedule of the last address it asks with every attempt waiting out
    /// that gap, since a retry held for the gap waits with its clock stopped.
    #[test]
    fn a_spaced_sweep_outlasts_every_attempt_waiting_out_the_gap() {
        let gap = Duration::from_secs(60);
        let (_, _, deadline) = schedule(
            1,
            SweepProbe::syn(None),
            &RETRY_POLICY,
            PROBE_RATE_PER_SEC,
            Some(gap),
            None,
        );
        let needed = gap * u32::from(RETRY_POLICY.max_attempts);
        let given = deadline.max_budget.for_target_count(1);
        assert!(
            given >= needed,
            "three attempts a {gap:?} gap apart take {needed:?} and the sweep \
             is given {given:?}"
        );
    }

    /// A sweep under a scan-wide gap outlasts every attempt at every address
    /// leaving that gap apart, which on a range is far slower than its rate.
    #[test]
    fn a_scan_wide_gap_is_the_pace_of_a_range() {
        let gap = Duration::from_secs(1);
        let targets = 256;
        let (_, _, deadline) = schedule(
            targets,
            SweepProbe::syn(None),
            &RETRY_POLICY,
            PROBE_RATE_PER_SEC,
            Some(gap),
            Some(gap),
        );
        let needed = gap * u32::from(RETRY_POLICY.max_attempts) * targets as u32;
        let given = deadline.max_budget.for_target_count(targets);
        assert!(
            given >= needed,
            "{targets} addresses asked {gap:?} apart take {needed:?} and the \
             sweep is given {given:?}"
        );
    }

    /// A SYN sweep of `targets` over a sender that takes everything, with
    /// `asked` of them given a first attempt, and the context it files into.
    fn sweep_with_first_attempts(
        targets: &[Ipv4Addr],
        asked: usize,
    ) -> (RoutedScanner, ScanContext) {
        let (_session, ctx) = ScanSession::new();
        let (_replies, rx) = tokio::sync::mpsc::channel(8);
        let mut scanner = RoutedScanner::with_transport(
            targets
                .iter()
                .map(|&target| RoutedTarget {
                    target: target.into(),
                    source: LOCAL.into(),
                })
                .collect(),
            ctx.clone(),
            None,
            ProbeTransport::from_parts(Box::new(MockSender::default()), rx),
        );
        for _ in 0..asked {
            let next = scanner.pending.next().expect("a target still queued");
            scanner.probe(next, Instant::now());
        }
        (scanner, ctx)
    }

    /// A seeded sweep asks its addresses in the order the scan's seed names,
    /// the same order a dispatched sweep streams the plan in.
    #[tokio::test]
    async fn a_seeded_sweep_asks_in_the_order_the_seed_names() {
        use crate::model::ip::set::Positions;

        const SEED: u64 = 0x5EED;
        let targets: IpSet = "198.51.100.0/26".parse().expect("a prefix");
        let (_session, ctx) = ScanSession::builder()
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

        let (_replies, rx) = tokio::sync::mpsc::channel(8);
        let scanner = RoutedScanner::with_transport(
            targets
                .iter()
                .map(|target| RoutedTarget {
                    target,
                    source: LOCAL.into(),
                })
                .collect(),
            ctx,
            None,
            ProbeTransport::from_parts(Box::new(MockSender::default()), rx),
        );

        assert_eq!(scanner.pending.collect::<Vec<_>>(), expected);
    }

    const THREE: [Ipv4Addr; 3] = [
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 2),
        Ipv4Addr::new(198, 51, 100, 3),
    ];

    /// A sweep that stops itself with addresses still queued records how many
    /// it never asked as a failure, and files none of its undecided addresses
    /// as silent.
    #[test]
    fn a_sweep_cut_short_reports_what_it_never_asked() {
        let (mut scanner, ctx) = sweep_with_first_attempts(&THREE, 1);

        scanner.finish(StopReason::DeadlineExpired);

        let failures: Vec<String> = ctx
            .take_failures()
            .iter()
            .map(|failure| failure.reason().to_owned())
            .collect();
        assert_eq!(
            failures,
            ["2 of 3 addresses were never asked: deadline expired with them still queued"],
            "the result is partial and says by how much"
        );
        assert_eq!(ctx.settlements().count(Outcome::Unasked), 2);
        assert_eq!(
            ctx.settlements().count(Outcome::Interrupted),
            1,
            "the one still mid-schedule has no verdict either"
        );
        assert!(ctx.take_silent().is_empty(), "none of them was silent");
    }

    /// An unreachable address is recorded against the address and named only
    /// at -v, since a front end already counts it on the default console.
    #[test]
    fn an_unreachable_address_is_named_only_beyond_the_default_console() {
        let (mut scanner, ctx) = sweep_with_first_attempts(&THREE, THREE.len());
        let [first, second, _] = THREE;
        scanner.faults.unroutable = Some((first.into(), "no route to host".to_owned()));
        scanner.faults.unroutable_count = 2;
        scanner.faults.addresses = [first.into(), second.into()].into();

        let said = crate::logging::logged(|| scanner.finish(StopReason::AttemptsSpent));

        let unroutable: Vec<_> = said
            .iter()
            .filter(|line| line.message.contains("unreachable"))
            .collect();
        assert_eq!(unroutable.len(), 1, "said once: {said:?}");
        assert_eq!(
            unroutable[0].message,
            "198.51.100.1 and 1 other address unreachable"
        );
        assert!(
            unroutable[0].verbosity >= 1,
            "a default console already has the count: {said:?}"
        );
        assert_eq!(ctx.take_unroutable().len(), 2, "both are recorded");
    }

    /// A send path that refused probes is one failure naming how many sends it
    /// refused, unroutable ones apart; an address with no route is filed
    /// against the address. Every raw pass files the same way.
    #[test]
    fn a_refused_send_is_one_failure_and_an_unroutable_address_is_filed_against_itself() {
        let (mut scanner, ctx) = sweep_with_first_attempts(&THREE, THREE.len());
        let [first, ..] = THREE;
        let attempted = scanner.sweep.audit.sends_attempted;
        scanner.sweep.audit.sends_failed = 3;
        scanner.faults.broken = Some("refused for the test".to_owned());
        scanner.faults.unroutable = Some((first.into(), "no route to host".to_owned()));
        scanner.faults.unroutable_count = 1;
        scanner.faults.addresses = [first.into()].into();

        scanner.finish(StopReason::AttemptsSpent);

        let failures: Vec<String> = ctx
            .take_failures()
            .iter()
            .map(|failure| failure.reason().to_owned())
            .collect();
        assert_eq!(
            failures,
            [format!(
                "2 of {attempted} probes could not be sent: refused for the test"
            )]
        );
        assert_eq!(ctx.take_unroutable(), [IpAddr::from(first)]);
    }

    /// An attempt the kernel refused for a hold-down on the target's
    /// neighbour, `EHOSTDOWN` on macOS, is made again once the hold-down is
    /// over, and the address is not filed unreached on it; refused for a
    /// second hold-down after waiting one out, it is.
    #[cfg(unix)]
    #[test]
    fn an_attempt_refused_for_a_hold_down_is_made_after_it() {
        use crate::transport::probe::{ProbeSender, SendError};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        /// Refuses every send while `holding`, as macOS does inside a
        /// hold-down, and counts the ones it takes.
        struct HeldDown {
            holding: Arc<AtomicBool>,
            taken: Arc<AtomicUsize>,
        }

        impl ProbeSender for HeldDown {
            fn send(
                &self,
                _s: &[u8],
                _src: IpAddr,
                _dst: IpAddr,
                _zone: Option<u32>,
                _emission: Emission,
            ) -> Result<(), SendError> {
                if self.holding.load(Ordering::SeqCst) {
                    return Err(SendError::from_io(std::io::Error::from_raw_os_error(
                        libc::EHOSTDOWN,
                    )));
                }
                self.taken.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        for held_again in [false, true] {
            let (_session, ctx) = ScanSession::new();
            let (_replies, rx) = tokio::sync::mpsc::channel(8);
            let holding = Arc::new(AtomicBool::new(true));
            let taken = Arc::new(AtomicUsize::new(0));
            let sender = HeldDown {
                holding: Arc::clone(&holding),
                taken: Arc::clone(&taken),
            };
            let mut scanner = RoutedScanner::with_transport_asking(
                vec![RoutedTarget {
                    target: TARGET.into(),
                    source: LOCAL.into(),
                }],
                ctx.clone(),
                None,
                ProbeTransport::from_parts(Box::new(sender), rx),
                SweepProbe::syn(None),
            );
            let target = IpAddr::from(TARGET);

            scanner.send_allowance(Instant::now());
            holding.store(held_again, Ordering::SeqCst);
            scanner.send_allowance(Instant::now());
            assert!(
                !scanner.sweep.ledger.contains(&target) && taken.load(Ordering::SeqCst) == 0,
                "asked inside the hold-down"
            );
            scanner.faults.held_down.lift(target);
            scanner.send_allowance(Instant::now());

            if held_again {
                assert!(!scanner.sweep.ledger.contains(&target));
                assert_eq!(scanner.faults.addresses, [target].into(), "held down twice");
            } else {
                assert!(
                    scanner.faults.addresses.is_empty(),
                    "filed on one hold-down"
                );
                assert!(
                    scanner.sweep.ledger.contains(&target),
                    "not asked after the hold-down"
                );
            }
            assert!(scanner.faults.broken.is_none(), "blamed on this machine");
        }
    }

    /// A caller who stopped the scan knows why it ended, so the sweep files no
    /// failure of its own. The addresses still have no verdict, and say so.
    #[test]
    fn a_sweep_the_caller_stopped_names_what_it_never_asked_without_failing() {
        let (mut scanner, ctx) = sweep_with_first_attempts(&THREE, 0);

        scanner.finish(StopReason::Aborted);

        assert!(ctx.take_failures().is_empty());
        assert_eq!(
            ctx.settlements().count(Outcome::Unasked),
            THREE.len() as u64
        );
        assert!(ctx.take_silent().is_empty(), "none of them was silent");
    }

    /// A sweep that asked everything and heard nothing reports nothing unasked;
    /// silence is its verdict.
    #[test]
    fn a_sweep_that_spent_its_attempts_reports_nothing_unasked() {
        let (mut scanner, ctx) = sweep_with_first_attempts(&THREE, THREE.len());
        scanner.sweep.ledger.drain_unresolved();

        scanner.finish(StopReason::AttemptsSpent);

        assert!(ctx.take_failures().is_empty());
        assert_eq!(ctx.settlements().count(Outcome::Unasked), 0);
        assert_eq!(ctx.settlements().count(Outcome::Interrupted), 0);
    }

    /// The address every probe leaves from.
    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    /// The one address the sweep asks about.
    const TARGET: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
    /// The port every INIT leaves from.
    const SCAN_PORT: u16 = 50_000;

    /// An INIT sweep of [`TARGET`] with its first probe out, and that probe as
    /// it reached the wire.
    fn init_sweep_with_a_probe_out() -> (RoutedScanner, ScanSession, Vec<u8>) {
        let (session, ctx) = ScanSession::new();
        let (_replies, rx) = tokio::sync::mpsc::channel(8);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let mut scanner = RoutedScanner::with_transport_asking(
            vec![RoutedTarget {
                target: TARGET.into(),
                source: LOCAL.into(),
            }],
            ctx,
            None,
            ProbeTransport::from_parts(Box::new(sender), rx),
            SweepProbe::init(SCAN_PORT, 3868),
        );
        scanner.probe(TARGET.into(), Instant::now());

        let (probe, _, _) = sent.lock().unwrap().first().cloned().expect("an INIT");
        (scanner, session, probe)
    }

    /// What a host with no SCTP stack answers an INIT with: a protocol
    /// unreachable from its own address, quoting `probe` under an IPv4 header
    /// that carries don't-fragment and `identification`, as this engine's own
    /// probes do.
    fn protocol_unreachable(probe: &[u8], identification: u16) -> CapturedSegment {
        let header = craft::Ipv4 {
            identification: Field::Exact(identification),
            protocol: Field::Exact(IpNextHeaderProtocols::Sctp.0),
            ..craft::Ipv4::new(LOCAL, TARGET)
        }
        .header_bytes(probe.len() as u16)
        .expect("an IPv4 header");
        let quoted = [header.as_slice(), probe].concat();

        let mut bytes =
            vec![0u8; MutableDestinationUnreachablePacket::minimum_packet_size() + quoted.len()];
        {
            let mut icmp =
                MutableDestinationUnreachablePacket::new(&mut bytes).expect("an ICMP buffer");
            icmp.set_icmp_type(IcmpTypes::DestinationUnreachable);
            icmp.set_icmp_code(IcmpCodes::DestinationProtocolUnreachable);
            icmp.set_payload(&quoted);
        }
        CapturedSegment::synthetic(TARGET.into(), IpNextHeaderProtocols::Icmp.0, bytes)
    }

    /// An ICMP error from a swept address is never read as an SCTP answer,
    /// however its bytes fall.
    ///
    /// Read as SCTP, an error's first chunk header lands on the quoted IPv4
    /// identification; under don't-fragment and a random identification, two
    /// in 256 spell an INIT-ACK or an ABORT.
    #[test]
    fn an_icmp_error_is_not_read_as_an_sctp_answer() {
        let (mut scanner, session, probe) = init_sweep_with_a_probe_out();
        // ABORT's chunk type in the identification's high byte.
        let error = protocol_unreachable(&probe, 0x0600);
        assert_eq!(
            protocol::sctp::parse(&error.bytes)
                .ok()
                .and_then(|packet| protocol::sctp::classify_probe_response(&packet)),
            Some(SctpReply::Abort),
            "the fixture no longer spells the chunk it exists to spell"
        );

        scanner.handle_discovery_reply(&error, Instant::now());

        let credited_to_sctp = session
            .hosts()
            .get(IpAddr::from(TARGET))
            .is_some_and(|host| {
                host.reasons()
                    .iter()
                    .any(|reason| reason.protocol == StatusProtocol::Sctp)
            });
        assert!(
            !credited_to_sctp,
            "an ICMP error was credited as an SCTP reply"
        );
        assert!(
            scanner.sweep.ledger.contains(&IpAddr::from(TARGET)),
            "the probe was retired by an answer it never drew"
        );
    }

    /// Answers the first SYN with an immediate SYN+ACK, then holds the sending
    /// thread for `stall`, leaving the sweep stopped with the answer waiting.
    struct StalledAfterAnswering {
        stall: Duration,
        replies: tokio::sync::mpsc::Sender<CapturedSegment>,
        answered: std::sync::atomic::AtomicBool,
    }

    impl crate::transport::probe::ProbeSender for StalledAfterAnswering {
        fn send(
            &self,
            segment: &[u8],
            _src: IpAddr,
            dst: IpAddr,
            _zone: Option<u32>,
            _emission: Emission,
        ) -> Result<(), crate::transport::probe::SendError> {
            if self
                .answered
                .swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                return Ok(());
            }
            self.replies
                .try_send(syn_ack(segment, dst))
                .expect("room for the answer");
            std::thread::sleep(self.stall);
            Ok(())
        }
    }

    /// The SYN+ACK `dst` answers the SYN in `segment` with, captured now.
    fn syn_ack(segment: &[u8], dst: IpAddr) -> CapturedSegment {
        let probe = protocol::tcp::parse(segment).expect("a whole segment");
        let mut reply = vec![0u8; 20];
        let mut tcp = pnet_packet::tcp::MutableTcpPacket::new(&mut reply).expect("20 bytes");
        tcp.set_source(probe.destination_port());
        tcp.set_destination(probe.source_port());
        tcp.set_data_offset(5);
        tcp.set_flags(pnet_packet::tcp::TcpFlags::SYN | pnet_packet::tcp::TcpFlags::ACK);
        tcp.set_acknowledgement(probe.sequence().wrapping_add(1));
        CapturedSegment::synthetic(dst, IpNextHeaderProtocols::Tcp.0, reply)
    }

    /// Answers every SYN at once and hands the answer to the reader `backlog`
    /// later, like a capture queue the sweep has fallen behind on.
    struct AnsweringThroughABacklog {
        backlog: Duration,
        replies: tokio::sync::mpsc::Sender<CapturedSegment>,
    }

    impl crate::transport::probe::ProbeSender for AnsweringThroughABacklog {
        fn send(
            &self,
            segment: &[u8],
            _src: IpAddr,
            dst: IpAddr,
            _zone: Option<u32>,
            _emission: Emission,
        ) -> Result<(), crate::transport::probe::SendError> {
            let answer = syn_ack(segment, dst);
            let (backlog, replies) = (self.backlog, self.replies.clone());
            std::thread::spawn(move || {
                std::thread::sleep(backlog);
                let _ = replies.blocking_send(answer);
            });
            Ok(())
        }
    }

    /// An answer that was waiting before its probe ran out of attempts finds
    /// its host, however late the loop gets round to either; see
    /// `read_waiting_replies`.
    #[tokio::test]
    async fn an_answer_waiting_when_its_probe_runs_out_still_finds_the_host() {
        let (session, ctx) = ScanSession::new();
        let (replies, rx) = tokio::sync::mpsc::channel(16);
        let retry = RETRY_POLICY.configured(RetryConfig {
            max_attempts: std::num::NonZeroU8::new(1),
            ..RetryConfig::default()
        });
        // Longer than the longest first timeout an unmeasured address can draw.
        let stall = retry.initial_rto.mul_f64(1.0 + retry.jitter) + Duration::from_millis(200);
        let transport = ProbeTransport::from_parts(
            Box::new(StalledAfterAnswering {
                stall,
                replies,
                answered: std::sync::atomic::AtomicBool::new(false),
            }),
            rx,
        );
        let mut scanner = RoutedScanner::build(
            vec![RoutedTarget {
                target: TARGET.into(),
                source: LOCAL.into(),
            }],
            ctx,
            None,
            transport,
            SweepProbe::syn(None),
            Emission::routed(),
            SegmentShaping::default(),
            Vec::new(),
            retry,
            PROBE_RATE_PER_SEC,
        );

        scanner.discover_hosts().await.expect("the sweep runs");

        assert!(
            session
                .hosts()
                .get(IpAddr::from(TARGET))
                .is_some_and(|host| host.status().is_up()),
            "the host answered and is not on record as up"
        );
    }

    /// A reply is timed from when the capture took it, so queue depth and
    /// scheduling do not inflate the round trip later passes time from.
    #[tokio::test]
    async fn a_reply_read_late_is_timed_from_its_capture() {
        let (session, ctx) = ScanSession::new();
        let (replies, rx) = tokio::sync::mpsc::channel(16);
        // Inside the first timeout, which is stretched well past the backlog
        // so a loaded machine cannot deliver the answer after the probe ran
        // out.
        let backlog = Duration::from_millis(100);
        let retry = RETRY_POLICY.configured(RetryConfig {
            max_attempts: std::num::NonZeroU8::new(1),
            timeout_scale: crate::config::TimeoutScale::new(10.0),
            ..RetryConfig::default()
        });
        let transport =
            ProbeTransport::from_parts(Box::new(AnsweringThroughABacklog { backlog, replies }), rx);
        let mut scanner = RoutedScanner::build(
            vec![RoutedTarget {
                target: TARGET.into(),
                source: LOCAL.into(),
            }],
            ctx,
            None,
            transport,
            SweepProbe::syn(None),
            Emission::routed(),
            SegmentShaping::default(),
            Vec::new(),
            retry,
            PROBE_RATE_PER_SEC,
        );

        scanner.discover_hosts().await.expect("the sweep runs");

        let rtt = session
            .hosts()
            .get(IpAddr::from(TARGET))
            .expect("the host answered")
            .min_rtt()
            .expect("and was timed");
        assert!(
            rtt < backlog / 2,
            "an immediate answer read {backlog:?} late was timed at {rtt:?}"
        );
    }
}
