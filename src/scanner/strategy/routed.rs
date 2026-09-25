// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Routed host discovery
//!
//! Finds hosts reached through a gateway, as against ones sitting on the local
//! segment. Raw TCP SYNs to a handful of ports per target, and anything that
//! comes back credits the host: the handshake is never completed, so an address
//! answers whether or not the port it was asked about is open, and it only has
//! to answer on one of them. See [`SynPorts`] for which ports and why.
//!
//! The counterpart of [`local`](super::local), which reaches a segment at the
//! link layer. Between them they are what a privileged discovery sweep is made
//! of, and which one a target gets is decided by
//! [`plan`](crate::scanner::plan) from this host's own routing table.
//!
//! Raw sockets, so root. What a probe is built from and how it reaches the wire
//! is [`raw`](super::raw), shared with every other strategy that opens one.

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
use crate::scanner::pacing::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
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
/// A probe's chance of being answered is not a constant of the path; it falls
/// as the rate rises. Unpaced, a sweep of a large range loses most of its first
/// attempt, and the hosts behind those packets are recovered only by
/// retransmitting into a quieter moment - coverage bought at several times the
/// traffic, and only where the attempt budget happens to outlast the policer.
///
/// So the rate is set below where that loss sets in rather than at whatever the
/// socket will accept. Measured against a /22 where every address answers, the
/// first attempt alone finds a sixth to a third of the range unpaced and around
/// three quarters of it at this rate, and the sweep needs roughly half the
/// packets to finish. Loss becomes visible again several times higher.
///
/// What it costs is the time a large range takes to emit, which grows linearly:
/// a /22 leaves in a quarter of a second, a /16 in sixteen. That is the trade,
/// and it is the right way round - a probe not yet sent and a probe dropped by a
/// policer are equally invisible, and only the first is under our control.
pub(super) const PROBE_RATE_PER_SEC: NonZeroU32 = NonZeroU32::new(4_000).expect("a non-zero rate");

/// Whether `bytes` is one of the two segments a SYN probe can draw *and be
/// credited for without correlating it*.
///
/// A SYN+ACK and a RST each require the target to have received the probe and
/// answered it, and nothing else a SYN elicits sets either flag. Anything else
/// from the same address is traffic that happens to share a host with the scan.
///
/// A challenge ACK is excluded, though it is a genuine answer.
/// It says a listener holds a connection half-open, which the port scanner acts
/// on, but the port scanner earns that by checking the probe's nonce against
/// its ledger, and this sweep has no ledger and checks nothing. A bare ACK is
/// the commonest segment on any network: every established connection emits a
/// stream of them, and a scan of an address somebody is talking to would credit
/// the host on the strength of that conversation. The flags of a SYN+ACK or a
/// RST are their own correlation; the flags of an ACK are not.
///
/// The asymmetry is the point. Evidence usable where it can be tied to a probe
/// is not usable where it cannot.
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
/// One port is enough for a host that answers a SYN to a closed port with a
/// reset, which is what an unfiltered stack does. It is not enough for the
/// host that matters most: one behind a filter that drops a SYN to anything
/// not listening, which is Windows Firewall's default and what an `iptables`
/// `DROP` policy does. That host answers on the ports it serves and nowhere
/// else, so a sweep that asks one port it does not serve reports it down, and
/// a port scan then never asks about the port it does serve.
///
/// So the set is two lists:
///
/// - **The common five**, SSH, HTTP, HTTPS, SMB and RDP, from
///   [`COMMON_DISCOVERY_PORTS`].
/// - **Up to [`SCAN_PORTS`](Self::SCAN_PORTS) of the scan's own ports**, for
///   a port scan's liveness pass: those are the ports whose answers the scan
///   exists to report, so a filtered host serving nothing else still has a
///   port it answers on among the ones asked. The catalogue's order
///   picks among them, so a scan of a thousand ports adds the few the engine
///   thinks likeliest to be listening and a scan naming one port adds that
///   port.
///
/// One set for both sweeps, so that privilege decides how an address is
/// asked and never which ports: a set kept by each would let an unprivileged
/// run find fewer hosts than a privileged one over the same ports, or the
/// reverse, and nothing would report the two drifting apart. See
/// [`connect::discover_on`](super::connect::discover_on) for what a connect
/// sweep pays for the larger set.
///
/// A SYN sweep sends all of them on every attempt, under one sequence number
/// and source port, so a reply on any of them names the attempt and retires
/// the address.
/// Spreading them across attempts instead would leave a lost SYN to the one
/// port a filtered host serves with no retransmission behind it.
///
/// **What it costs** is a packet per port per unanswered attempt. A host that
/// answers costs one attempt; an address with nothing on it costs the whole set
/// on every attempt, so a silent range costs five to eight times the packets a
/// single port would, and the sweep paces and sizes its deadline from that
/// total rather than
/// from its address count. That is the price of asking the question the scan
/// depends on: a host missed here is not port-scanned at all, which no later
/// phase recovers.
///
/// Not asked: an ICMP echo or a bare ACK. Both find hosts a SYN does not, an
/// echo where nothing listens and pings pass, an ACK through a filter that
/// keeps no state, and neither passes the stateful filters this set exists for.
/// An echo also needs a second transport beside the TCP one the sweep holds.
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
    /// Three covers a port scan naming a short list in full, which is the
    /// usual shape of a scan about particular services. Past that the scan is
    /// broad, and its likeliest ports are the common five already.
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
    /// Ranked by the catalogue, [`TCP_BY_PREVALENCE`], and a port it has never
    /// heard of after every one it has, lowest first, so the choice is the same
    /// on every run of one scan.
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

    /// Always false: every constructor puts at least one port in the set.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push(&mut self, port: u16) {
        self.ports[usize::from(self.len)] = port;
        self.len += 1;
    }
}

/// Which packet a routed sweep asks with.
///
/// The sweep is the same either way. Its pacing, its retry schedule, its
/// deadline and its audit are properties of asking a list of addresses whether
/// anything is there, not of the packet that asks. Four things do follow from
/// the packet: the transport the probes and their answers travel over, what a
/// probe is, what counts as an answer to one, and what the report says the host
/// was found by.
///
/// There are two because a scan asking about SCTP ports and a scan asking about
/// TCP ports are putting different questions to the network. A host behind a
/// filter that passes one transport and drops the other answers exactly one of
/// these probes, and sweeping it with the wrong one reports it down while its
/// ports are listening.
/// Non-exhaustive: a probe kind per transport, and the transports a sweep can
/// ask with is a list that has grown twice already.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepProbe {
    /// TCP SYNs, never completed, one to each of a set of ports.
    Syn {
        /// The port every probe leaves from when a caller pinned one, or `None`
        /// for a fresh high port per attempt. A fresh port and a fresh sequence
        /// number together are what let a reply name the attempt it answers; a
        /// pinned one keeps the sequence number varying and buys a port a filter
        /// is known to trust.
        src_port: Option<u16>,
        /// The ports every attempt is aimed at, all of them each time.
        dst_ports: SynPorts,
    },
    /// An SCTP INIT, for a scan that asked about SCTP.
    ///
    /// Both answers it can draw prove the host: an INIT-ACK is an endpoint
    /// accepting the association, an ABORT is the same stack refusing it. The
    /// association is never completed, so nothing is left half-open.
    Init {
        /// The one port every probe leaves from. Fixed rather than fresh per
        /// probe, because it is what the capture filter narrows on; the Initiate
        /// Tag is what varies per attempt.
        src_port: u16,
        /// The port every probe is aimed at, which a caller takes from the ports
        /// the scan is about. A filter that passes SCTP at all is likeliest to
        /// pass it to the port something is running on.
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

    /// The transport this sweep's probes and answers travel over.
    const fn transport(self) -> ProbeKind {
        match self {
            Self::Syn { .. } => ProbeKind::TcpSyn,
            Self::Init { src_port, .. } => ProbeKind::Sctp {
                reply_port: src_port,
            },
        }
    }

    /// How many packets one attempt at one address puts on the wire, which is
    /// what the sweep's pacing and deadline are counted in.
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

    /// The IP protocol an answer to this probe arrives under, over either
    /// family: the one the probe left under, since a SYN is answered in TCP and
    /// an INIT in SCTP.
    const fn answered_under(self) -> IpNextHeaderProtocol {
        match self {
            Self::Syn { .. } => IpNextHeaderProtocols::Tcp,
            Self::Init { .. } => IpNextHeaderProtocols::Sctp,
        }
    }

    /// Whether `reply` answers a probe of this kind at all.
    ///
    /// The capture filter has already narrowed what arrives, but it is a
    /// performance boundary rather than a guarantee: over IPv6 the TCP half
    /// cannot be narrowed on flags at all, the INIT sweep's filter admits every
    /// ICMP message for the SCTP port scan that shares it, and a transport can
    /// be built with no filter. This is what holds all of them to one standard.
    ///
    /// The protocol is checked before a byte is parsed, because a Layer-4
    /// header does not say what it is. An ICMP error read as SCTP puts its first
    /// chunk on the quoted IPv4 identification, which spells an INIT-ACK or an
    /// ABORT often enough to credit a host with an answer it never sent.
    fn answers(self, reply: &CapturedSegment) -> bool {
        if reply.protocol != self.answered_under() {
            return false;
        }
        match self {
            Self::Syn { .. } => answers_a_syn_probe(&reply.bytes),
            // Either chunk an INIT can draw, and nothing else. A packet from an
            // association this sweep is not part of carries neither.
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
            // A TCP segment from a probed address is proof of a live stack
            // whichever flags it carries: a SYN+ACK and a RST both require the
            // host to have received the probe and answered it.
            Self::Syn { .. } => {
                StatusReason::new(StatusProtocol::TcpSyn, "tcp reply to a discovery probe")
            }
            Self::Init { .. } => {
                StatusReason::new(StatusProtocol::Sctp, "sctp reply to a discovery probe")
            }
        }
    }
}

/// What identifies one attempt of a sweep's probe on the wire.
/// Non-exhaustive, and for the same reason as [`SweepProbe`]: one token kind per
/// probe kind, so the two grow together.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepToken {
    /// A SYN's sequence number and source port. See [`SynToken`].
    Syn(SynToken),
    /// An INIT's Initiate Tag, which RFC 4960 §3.3.2 obliges a peer to echo in
    /// the verification tag of whatever it answers with.
    Init(u32),
}

/// Checks whether addresses behind a gateway are alive, putting raw probes to
/// each and crediting whatever comes back.
///
/// The handshake is never completed, so an address answers whether or not the
/// port it was asked about is open, and every probe leaves from the source
/// address its route named. [`new`](Self::new) opens the raw transport it
/// sends through, which takes root; [`with_transport`](Self::with_transport)
/// takes one the caller opened.
pub struct RoutedScanner {
    /// Shared state (host store, event channel, abort signal) for the scan
    /// this explorer is part of.
    ctx: ScanContext,
    /// The source address to probe each target from. Kept for the whole sweep
    /// rather than consumed by the first pass, since a retry has to leave from
    /// the same place the probe it repeats did.
    sources: HashMap<IpAddr, IpAddr>,
    /// Membership-and-count view of the targets, used to filter incoming
    /// replies and to size the adaptive deadline.
    ips: IpSet,
    /// Transport used to send SYN probes and receive replies.
    transport: ProbeTransport,
    /// What this sweep asks with, and everything that follows from it: the
    /// packet, what counts as an answer, and what the report credits.
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
    /// The outstanding probes, the retry queue, what has answered and the
    /// run's counters, shared with the other two probing sweeps.
    sweep: HostSweep<SweepToken>,
    /// Targets whose first probe has not left yet, released by the send ticker.
    pending: std::vec::IntoIter<IpAddr>,
    /// How often the send ticker fires, and how many probes it releases each
    /// time. Together they are the configured rate; see [`pacing_for`].
    send_tick: Duration,
    batch: usize,
    /// Why probes that could not be sent could not be sent, if any could not.
    ///
    /// Kept so the reason survives into the report. The count of failed sends is
    /// already in the audit, but a count cannot distinguish a host with no route
    /// to the target from one refusing raw sockets, and those call for opposite
    /// responses from whoever is reading.
    faults: SendFaults,
}

#[async_trait]
impl HostScanner for RoutedScanner {
    fn kind(&self) -> ScannerKind {
        self.probe.scanner_kind()
    }

    async fn discover_hosts(&mut self) -> Result<(), StrategyError> {
        let mut send_tick = tokio::time::interval(self.send_tick);
        // Without this, a ticker that went unpolled while the loop was busy with
        // replies hands back every missed tick at once, and the pacing it exists
        // to impose evaporates exactly when the queue is longest.
        send_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // The loop yields why it stopped, so the audit cannot report a reason
        // the code never actually took.
        let reason = loop {
            let now = Instant::now();
            // Answers already waiting first, so one that arrived before its
            // probe came due settles it before the timer can retire it; see
            // the port scans' `read_waiting_replies`.
            self.read_waiting_replies();
            // A sweep settles: it was asked whether an address is there and
            // has now asked as many times as the policy allows.
            self.sweep.service_retries(&self.ctx, now);

            let all_responded = self.sweep.all_responded(self.ips.len());
            if let Some(cause) = self.ctx.handle.stopped() {
                break cause.into();
            }
            if all_responded {
                break StopReason::AllResponded;
            }
            // Nothing outstanding and nothing left to send means every target
            // has either answered or been asked as many times as it is going
            // to be. Waiting longer cannot change the result.
            //
            // Both queues have to be checked, not just the ledger: at the first
            // iteration the ledger is empty because no probe has left yet, and
            // stopping there would end the sweep before it began.
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
                            // The moment the capture took the reply, not the
                            // moment this loop reached it. See
                            // `CapturedSegment::received_at`.
                            self.handle_discovery_reply(&reply, reply.received_at);
                        }
                        None => break StopReason::StreamClosed,
                    }
                },

                _ = send_tick.tick(), if sending => {
                    self.send_allowance(Instant::now());
                }

                // Wakes when the next probe is due, so a retry is queued on time
                // even though nothing is arriving to wake the loop otherwise.
                // Only while idle: with probes still to send, the ticker above
                // is what governs how often the loop comes round.
                _ = tokio::time::sleep(tick), if !sending => {}
            }
        };

        self.finish(reason);
        Ok(())
    }
}

/// How much longer than its pacing needs a sweep is allowed to send for.
///
/// A multiple rather than a fixed margin because the shortfall it covers
/// grows with the sweep: the send ticker skips no tick it missed, it delays
/// the next one, so every stretch the loop spends on replies pushes the whole
/// remaining schedule back. A half again is room for a loop kept busy a third
/// of the time. Only a sweep that is still sending when it runs out ever
/// spends it.
const SEND_SLACK: f64 = 1.5;

/// How a sweep of `target_count` addresses asking `probe` paces its sends, and
/// the deadline it runs under: the send ticker's interval, how many addresses
/// each tick releases, and the deadline's configuration.
fn schedule(
    target_count: usize,
    probe: SweepProbe,
    retry: &RetryPolicy,
    rate_per_sec: NonZeroU32,
    host_gap: Option<Duration>,
) -> (Duration, usize, AdaptiveDeadlineConfig) {
    // The rate is in packets, because a policer counts packets, and an
    // attempt at one address is as many packets as the probe asks ports.
    // The ticker releases addresses, so it runs at that fraction of it.
    let addresses_per_sec = NonZeroU32::new(rate_per_sec.get() / probe.packets_per_attempt())
        .unwrap_or(NonZeroU32::MIN);
    let (send_tick, batch) = pacing_for(addresses_per_sec);

    // The sweep has to outlive both of the limits it sets itself: its own
    // retry schedule, or probes are given up on having never been fully
    // asked, and its own send rate, or the sweep is cut off mid-send. The
    // second fails invisibly, since an address never probed is
    // indistinguishable from one with nothing on it, which is why it is
    // derived here rather than left to a constant that has to be remembered.
    //
    // The schedule is taken at its longest, every attempt at the ceiling,
    // rather than as an unmeasured path would run it. A sweep that has heard
    // slow hosts times the rest from what it heard, at up to the ceiling on
    // every attempt, the first included. And every attempt at the gap the
    // scan keeps between two probes at one host, where that is longer, since
    // a retry waits it out with its probe's clock stopped.
    //
    // The send rate is the one that grows with the range, and it is counted
    // in every attempt rather than the first: a retry leaves through the same
    // ticker as a first attempt, so a silent range takes the ticker's time
    // once per attempt. Handed to the deadline as a pace per address, so the
    // ceiling is raised to cover the range rather than left to clamp it; see
    // `ScanBudget::covering`. The slack is for the ticker falling behind, which
    // it does whenever the loop is busy with replies and never makes up, and
    // it costs a sweep that finishes nothing, since the sweep stops the moment
    // its attempts are spent.
    let per_address = Duration::from_secs_f64(
        SEND_SLACK * f64::from(retry.max_attempts) / f64::from(addresses_per_sec.get()),
    );
    let deadline_config = DEADLINE_CONFIG
        .allowing_for(retry.longest_spaced_probe_lifetime(host_gap))
        .allowing_pace_of(per_address, target_count);

    (send_tick, batch, deadline_config)
}

impl RoutedScanner {
    /// A sweep of `targets`, each already paired with the source address to
    /// probe it from, over a transport this constructor opens, asking the
    /// common five ports.
    ///
    /// Hosts land in `ctx`, which is also where an abort is read from, and
    /// every address found is posted to `dns_tx` for a reverse lookup; pass
    /// `None` to resolve no hostnames. `tuning` supplies the retry schedule,
    /// the probe rate the sweep paces itself to, and the evasion profile that
    /// shapes each packet and decides how the transport is opened.
    ///
    /// Fails when that transport cannot be opened, which is what happens
    /// without root.
    pub fn new(
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        tuning: ProbeTuning,
    ) -> Result<Self, StrategyError> {
        Self::over_tcp(targets, ctx, dns_tx, tuning, SynPorts::common())
    }

    /// [`new`](Self::new), asking `ports` rather than the common five.
    ///
    /// For a port scan's liveness pass, which takes
    /// [`SynPorts::for_scan`] so that a host behind a filter is asked about
    /// the ports the scan is about to ask it.
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

    /// A sweep of `targets` that asks over SCTP, sending one INIT per address to
    /// `dst_port` instead of a SYN.
    ///
    /// For a scan whose ports name SCTP. A host that answers only SCTP is
    /// reported down by a SYN sweep, and its ports are never reached: the port
    /// phase probes what discovery found. `dst_port` is the caller's to choose
    /// from the ports the scan is about; see [`SweepProbe::Init`].
    ///
    /// Fails when the raw transport cannot be opened, which is what happens
    /// without root.
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

    /// The constructor both of the above are: it opens the transport `probe`
    /// calls for and hands everything else to [`build`](Self::build).
    fn asking(
        probe: SweepProbe,
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        tuning: ProbeTuning,
    ) -> Result<Self, StrategyError> {
        let transport = ProbeTransport::open_with(
            probe.transport(),
            tuning.evasion.effective_send_mode(tuning.send_mode),
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
    /// This is the constructor for a caller orchestrating their own scan.
    /// [`new`](Self::new) opens a transport with the settings this engine would
    /// choose; this one takes whatever the caller opened, which is what makes it
    /// possible to scan through a transport built with a particular send mode or
    /// bound to particular interfaces.
    ///
    /// Paired with a synthetic transport (`ProbeTransport::from_parts`, behind
    /// the `test-support` feature) it is also the seam that lets liveness
    /// detection and RTT correlation be driven against a simulated network
    /// rather than a real one.
    pub fn with_transport(
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        transport: ProbeTransport,
    ) -> Self {
        Self::with_transport_asking(targets, ctx, dns_tx, transport, SweepProbe::syn(None))
    }

    /// [`with_transport`](Self::with_transport) for a sweep asking something
    /// other than a SYN.
    ///
    /// The transport has to be one `probe` would have opened: an INIT sweep
    /// reading a capture filtered for TCP hears nothing, and the silence is
    /// indistinguishable from a range with nothing on it.
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

    /// The common constructor, taking the retry schedule and the send rate as
    /// arguments because the sweep's own deadline is derived from both and so
    /// has to be settled before anything is built.
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

        let target_count = sources.len();

        let (send_tick, batch, deadline_config) = schedule(
            target_count,
            probe,
            &retry,
            rate_per_sec,
            ctx.host_probe_interval(),
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
            send_tick,
            batch,
            faults: SendFaults::default(),
        }
    }

    /// Files what the sweep leaves behind once its loop has stopped for
    /// `reason`: the addresses it reached no verdict on and why, the sends that
    /// failed, and its audit.
    fn finish(&mut self, reason: StopReason) {
        // What this sweep is in the report: `Routed` for the SYN sweep,
        // `RoutedSctp` for the INIT one. Read from the probe rather than
        // hardcoded, or an SCTP sweep's failures and counters would be filed as
        // the SYN sweep's and a reader could not tell which question the network
        // did not answer.
        let kind = self.kind();
        let label = match self.probe {
            SweepProbe::Init { .. } => "sctp-discovery",
            _ => "routed-discovery",
        };

        // What the sweep did not earn a verdict for, so a resumed one asks again
        // rather than skipping it. None of these carries a position: a probe
        // still mid-schedule was cut off rather than spent, one still queued was
        // never sent, and one with no route was never asked.
        let interrupted = self.sweep.ledger.drain_unresolved();
        let unasked: Vec<IpAddr> = self.pending.by_ref().collect();
        self.ctx
            .record_address_outcomes(Outcome::Interrupted, interrupted.len() as u64);
        self.ctx
            .record_address_outcomes(Outcome::Unasked, unasked.len() as u64);

        // Addresses never asked leave the result narrower than the caller asked
        // for, which is what a failure says, and the number is the part a reader
        // can act on. Only where the sweep stopped itself: a caller who aborted
        // the scan or set its budget knows why it ended, and every strategy
        // running when it did was cut short alike.
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
        // Distinct addresses rather than failed sends: a target with no route
        // fails on every retry, and counting each of those would report more
        // unreached addresses than the sweep had.
        self.ctx
            .record_address_outcomes(Outcome::Unroutable, self.faults.addresses.len() as u64);

        // A sweep whose probes never left is not a sweep that found nothing, and
        // the difference is invisible in every number a caller reads: the host
        // count is zero either way, no strategy errored, and the audit line that
        // does say so is a log at verbosity 1. So it is recorded as a failure,
        // which is the one channel a library consumer sees without opting in.
        //
        // Reported once with the first cause rather than once per probe. Sixteen
        // identical lines say nothing the first does not, and a sweep of a large
        // range would bury everything else in the report.
        //
        // **Only the failures that are about this host.** An address with no
        // route is not a strategy that did not run: the strategy ran, and that
        // address is not reachable from here. Recorded as a failure it would
        // make every scan of a dual-stack name on an IPv4-only network report
        // itself as partial, which is the surest way to teach a reader to
        // ignore the warning that matters. It is recorded against the address
        // instead, where a report counts what it did not cover and a front end
        // says so beside its result. The filing every raw pass shares does both.
        self.faults.file(
            &self.ctx,
            kind,
            "probes",
            self.sweep.audit.sends_attempted,
            self.sweep.audit.sends_failed,
        );

        // Which address it was, at the level that says what went uncovered and
        // why: the default console already has the count from the report, and
        // a second line there would say the same thing twice. Addresses rather
        // than failed sends, since an attempt at one address is a packet per
        // port and each of them fails. "Unreachable" rather than "no route",
        // since a neighbour that never answered its address resolution is
        // filed here too, and it has a route. Nothing is wrong with the scan,
        // so the line carries no error prefix and no errno; that detail is on
        // the line beside the send that failed.
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

        // Read before the transport is dropped, since the counters live with
        // the capture threads it keeps alive.
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

        // Not every TCP segment from a probed address answers a probe, and over
        // IPv6 the kernel does not guarantee otherwise: `tcp[tcpflags]` does
        // not compile for that family, so the transport admits established
        // traffic too and the narrowing has to happen here.
        //
        // Checking it is what keeps the two families held to one standard. The
        // IPv4 half only ever sees SYN+ACK and RST because the filter drops the
        // rest; without the same test, an ACK from an IPv6 host the user
        // happens to be connected to would credit a discovery this scan did not
        // make, on evidence the IPv4 path never accepts.
        if !self.probe.answers(reply) {
            self.sweep.audit.record_off_target();
            return;
        }

        // The address answered, which is a verdict however the reply was timed.
        self.ctx.settle_address(ip, Settled::Answered);

        let resolution = self.resolve_probe(ip, &reply.bytes, now);
        let rtt = resolution.and_then(|resolution| resolution.rtt);
        if rtt.is_none() {
            self.sweep.audit.record_reply_without_rtt();
        }

        // Host mutation only; the guard is dropped and the event emitted inside
        // `write_host`, so the deadline and DNS follow-ups below never run under
        // the store lock.
        // Evidence goes in whatever this sweep has seen before; the return
        // value is ignored, because it reports store novelty and
        // the decisions below are about *this sweep's* first sighting.
        // Whichever answer arrived, it required the host to have received the
        // probe and answered it: a SYN+ACK and a RST both do, and so do an
        // INIT-ACK and an ABORT. Discovery already treats either of a pair as an
        // answer; this records which packet proved it.
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
    /// Correlation is attempted twice on purpose. The first pass matches the
    /// segment against the exact attempt it acknowledges, which is what yields a
    /// true round trip even for a target that had to be asked more than once.
    /// The second accepts the reply on its own terms: for discovery the question
    /// is only whether something is there, and a TCP segment from a probed
    /// address answers that whether or not it can be tied to a particular
    /// attempt. Retiring the probe either way is what stops a host that has
    /// already proved it exists from being asked again.
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
    /// at once, and read in the other order an address's last attempt is
    /// spent, the sweep finds nothing left to do and stops with the answer
    /// unread: a live host reported absent.
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
        self.sweep.retries.is_empty() && self.pending.len() == 0
    }

    /// Releases one tick's worth of probes: retries first, then targets not yet
    /// asked.
    fn send_allowance(&mut self, now: Instant) {
        for _ in 0..self.batch {
            // A queued retry first, unless its host was asked too recently for
            // the gap the scan keeps. A retry turned away stays queued with its
            // clock stopped, and the allowance moves on to one that is ready,
            // or to a fresh target, instead of spending the slot waiting.
            //
            // Only a retry can be turned away. The gap is measured from a
            // previous probe and a sweep sends one per host per attempt, so a
            // first attempt reaches an address this sweep has never asked
            // about and there is no earlier probe for it to be too close to.
            if let Some(target) = self.next_ready_retry(now) {
                self.reprobe(target, now);
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
    /// A retry whose probe has left the ledger was answered while it waited
    /// and is dropped: sending it asks a question nothing is waiting on, and
    /// arming it would start its address a fresh schedule after its verdict.
    /// One turned away for the gap goes to the back. The walk is bounded by
    /// the queue's length on entry.
    fn next_ready_retry(&mut self, now: Instant) -> Option<IpAddr> {
        for _ in 0..self.sweep.retries.len() {
            let target = self.sweep.retries.pop_front()?;
            if !self.sweep.ledger.contains(&target) {
                continue;
            }
            if self.ctx.host_ready_at(target, now).is_some() {
                self.sweep.retries.push_back(target);
                continue;
            }
            return Some(target);
        }
        None
    }

    /// Puts the first attempt at `target` on the wire and arms its probe.
    ///
    /// An attempt none of whose packets could be sent is not armed, so an
    /// address nobody asked never earns a verdict. One that reached the wire
    /// on any port is armed, since any of them can draw the answer.
    fn probe(&mut self, target: IpAddr, now: Instant) {
        if let Some(token) = self.send_attempt(target, now) {
            self.sweep.ledger.arm(target, target, token, (), now);
        }
    }

    /// Puts a queued retry at `target` on the wire, and restarts its probe's
    /// clock: from the send, or from now for a retry none of whose packets
    /// left, whose attempt stays charged so an unroutable target still runs
    /// out of attempts on schedule. See [`HostSweep::retries`].
    fn reprobe(&mut self, target: IpAddr, now: Instant) {
        match self.send_attempt(target, now) {
            Some(token) => self.sweep.ledger.rearm(target, target, token, now),
            None => self.sweep.ledger.resume(&target, now),
        }
    }

    /// Sends one attempt at `target`, returning the token it carried if any
    /// of its packets left.
    fn send_attempt(&mut self, target: IpAddr, now: Instant) -> Option<SweepToken> {
        let &source = self.sources.get(&target)?;

        let token = match self.probe {
            SweepProbe::Syn {
                src_port,
                dst_ports,
            } => {
                let token = SynToken::fresh(src_port);
                let mut sent = false;
                for &dst_port in dst_ports.as_slice() {
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
        };

        if token.is_some() {
            // Only for a probe that reached the wire, on the same reasoning
            // `record_send` gives for keeping a refused one out of the
            // congestion window: a packet the kernel would not take occupied
            // nothing at the target and must not spend its slot.
            self.ctx.host_probed(target, now);
        }
        token
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

    /// A sweep asks at least what the unprivileged sweep asks, so privilege
    /// never finds fewer hosts. Pinned against the list that sweep reads rather
    /// than restated, since the two drifting apart is the failure.
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

    /// A broad scan adds the ports the catalogue thinks likeliest, and no more
    /// than the set holds, so the cost per address stays bounded whatever the
    /// scan's size.
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

    /// The hard deadline a sweep of `targets` addresses runs under.
    fn hard_deadline(targets: usize, retry: RetryConfig, rate: NonZeroU32) -> Duration {
        let (_, _, deadline) = schedule(
            targets,
            SweepProbe::syn(None),
            &RETRY_POLICY.configured(retry),
            rate,
            None,
        );
        deadline.max_budget.for_target_count(targets)
    }

    /// What a silent range of `targets` costs to put on the wire at `rate`,
    /// worked out from the numbers rather than from the sweep: every attempt
    /// at every address, one packet per port.
    fn every_packet_sent(targets: usize, attempts: u8, rate: u32) -> Duration {
        let packets = targets * usize::from(attempts) * SynPorts::common().len();
        Duration::from_secs_f64(packets as f64 / f64::from(rate))
    }

    /// A sweep is given at least the time its own pacing needs to ask every
    /// address as often as its schedule says, retries included, however large
    /// the range, however slow the rate and however many attempts.
    ///
    /// A deadline shorter than that stops the sweep with addresses never
    /// asked, and an address never asked looks exactly like one with nothing
    /// on it. Each case is one the fixed ceiling cut short.
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
    /// attempt timed as long as measurement may make it.
    ///
    /// A sweep that has heard slow hosts times the rest at up to the retry
    /// ceiling on every attempt, the first included, which is far longer than
    /// the schedule an unmeasured path gets. Sized for the unmeasured one, the
    /// deadline stops a small sweep of a slow path while its last address
    /// still has attempts to spend, and that address reads as cut off.
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
    /// that gap.
    ///
    /// A retry held for the gap waits with its probe's clock stopped, so a gap
    /// longer than the timeout is what spaces the attempts, and a deadline
    /// sized from the timeouts alone stops the sweep with retries still owed.
    #[test]
    fn a_spaced_sweep_outlasts_every_attempt_waiting_out_the_gap() {
        let gap = Duration::from_secs(60);
        let (_, _, deadline) = schedule(
            1,
            SweepProbe::syn(None),
            &RETRY_POLICY,
            PROBE_RATE_PER_SEC,
            Some(gap),
        );
        let needed = gap * u32::from(RETRY_POLICY.max_attempts);
        let given = deadline.max_budget.for_target_count(1);
        assert!(
            given >= needed,
            "three attempts a {gap:?} gap apart take {needed:?} and the sweep \
             is given {given:?}"
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

    const THREE: [Ipv4Addr; 3] = [
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 2),
        Ipv4Addr::new(198, 51, 100, 3),
    ];

    /// A sweep that stops itself with addresses still queued says how many it
    /// never asked, where a caller reads whether a result is partial, and files
    /// none of the addresses it reached no verdict on as silent, so its phase
    /// names them undecided rather than reading them as hosts that are not
    /// there.
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

    /// An unreachable address is recorded against the address, which a front
    /// end counts beside its result, and named at the verbosity that says
    /// what went uncovered. A default console that printed the name as
    /// well would say the same thing twice, once in the engine's words and
    /// once in the front end's.
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

    /// A send path that refused probes is one failure naming how many of the
    /// sweep's sends it refused, the unroutable ones apart, and an address with
    /// no route is filed against the address rather than as a failure. The
    /// same filing every raw pass makes, so the report reads a broken send
    /// path the same way whichever pass met it.
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

    /// A sweep that asked everything and heard nothing has nothing to report:
    /// every address was asked as often as the schedule says, and silence is
    /// its verdict.
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
            protocol: Field::Exact(IpNextHeaderProtocols::Sctp),
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
        CapturedSegment::synthetic(TARGET.into(), IpNextHeaderProtocols::Icmp, bytes)
    }

    /// An ICMP error from a swept address is never read as an SCTP answer,
    /// however its bytes fall.
    ///
    /// The capture an INIT sweep reads admits every ICMP message, and an error
    /// read as an SCTP packet puts its first chunk header on the quoted IPv4
    /// identification. Under don't-fragment and a random identification two of
    /// every 256 such errors spell an INIT-ACK or an ABORT. Read that way, each
    /// files its host as found by an SCTP answer nobody sent and retires the
    /// probe, so the retry that might draw a real one never leaves.
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

    /// A path that answers the first SYN it is handed with a SYN+ACK the
    /// moment it leaves, and then holds the sending thread for `stall`: the
    /// sweep stopped in its tracks with the answer already waiting for it.
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
        CapturedSegment::synthetic(dst, IpNextHeaderProtocols::Tcp, reply)
    }

    /// A path that answers every SYN at once, captured the moment it is sent,
    /// and hands the answer to the reader `backlog` later: a capture queue the
    /// sweep has fallen behind on.
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
    /// its host, however late the loop gets round to either.
    ///
    /// A loop held up for longer than a timeout wakes to find both the answer
    /// and the expired timer. Serviced timer first, the address's last attempt
    /// is spent, nothing is left to send or wait for, and the sweep stops
    /// without reading the answer behind it: a live host reported absent.
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

    /// A reply is timed from when the capture took it, not from when the sweep
    /// got round to reading it.
    ///
    /// A sweep reads its replies behind a queue, and a round trip measured at
    /// the read carries the queue's depth and the runtime's scheduling. Under
    /// load that is most of the figure: the host is recorded as far slower
    /// than its path, and every later pass times its probes from that.
    #[tokio::test]
    async fn a_reply_read_late_is_timed_from_its_capture() {
        let (session, ctx) = ScanSession::new();
        let (replies, rx) = tokio::sync::mpsc::channel(16);
        // Inside the first timeout, so the answer finds its probe out on one
        // attempt and is timed at all.
        let backlog = Duration::from_millis(100);
        let retry = RETRY_POLICY.configured(RetryConfig {
            max_attempts: std::num::NonZeroU8::new(1),
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
