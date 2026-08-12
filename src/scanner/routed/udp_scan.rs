// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # UDP Port Probing
//!
//! Implements the privileged UDP half of [`crate::scanner::scan`]. It probes
//! specific `(address, port)` pairs with raw UDP packets and classifies each
//! one by whether and how it responds.
//!
//! UDP scanning is harder than the SYN scan next door because UDP carries no
//! handshake to correlate against. A closed port answers with an ICMP Port
//! Unreachable, an open one answers with a UDP datagram *if* it understands
//! what was sent, and a filtered one says nothing at all - which is also what
//! an open port that ignored the probe does. So:
//!
//! - a direct UDP reply is [`PortState::Open`],
//! - an ICMP Port Unreachable is [`PortState::Closed`],
//! - silence until the deadline is [`PortState::OpenFiltered`], because it
//!   genuinely cannot distinguish the two.
//!
//! ## Tying a reply to its probe
//!
//! Every probe in a scan leaves from one fixed source port, chosen when the
//! scanner is built. That single port is what makes both answers correlatable:
//!
//! - A **direct reply** is addressed back to it, so the kernel's BPF filter
//!   admits this scan's replies and drops the rest of the host's UDP traffic
//!   ([`ProbeKind::UdpProbe`]).
//! - An **ICMP error** carries no ports of its own, but RFC 792 requires it to
//!   quote the datagram that caused it - IP header plus the first eight bytes,
//!   which is exactly a whole UDP header. That quotation names the probe: its
//!   source port proves the datagram was ours, and its destination address and
//!   port say *which* probe, so one error retires exactly one probe.
//!
//! Reading the quoted packet rather than the error's own source address also
//! keeps a router's error attributable: the ICMP comes from the router, but the
//! probe it refers to was aimed at the host behind it.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::udp::UdpPacket;
use tokio::sync::mpsc;

use crate::core::config::ProbeTuning;
use crate::core::models::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::core::models::host::{HostStatus, StatusProtocol, StatusReason};
use crate::core::models::port::{PortState, Protocol};
use crate::core::models::retry::{Due, ProbeLedger, RetryPolicy, SilentHostPolicy};
use crate::core::models::target::Target;
use crate::core::models::timer::ScanBudget;
use crate::core::session::{ScanContext, ScannerKind};
use crate::error;
use crate::network::capture::CapturedSegment;
use crate::network::probe::{ProbeKind, ProbeTransport};
use crate::scanner::{PortScanner, StrategyError};
use crate::system::interface::SourceResolver;

use super::icmp_error::{self, Unreachable};
use super::send_udp;

/// The probe a reply refers to: the `(address, port)` it was sent to.
type ProbeTarget = (IpAddr, u16);

/// Outstanding probes and the schedule they are retried on.
///
/// The attempt token is `()`: a UDP scan sends every probe from one fixed source
/// port, and an ICMP error is only guaranteed to quote the first eight bytes of
/// the datagram, so nothing on the wire distinguishes one attempt from another.
/// The ledger applies Karn's rule on that basis, declining to measure a round
/// trip it cannot attribute.
type Ledger = ProbeLedger<ProbeTarget, ()>;

/// How long this scan runs and how it adapts.
///
/// Deliberately *not* the profile the SYN scanners share
/// ([`DEADLINE_CONFIG`](super::DEADLINE_CONFIG)), because the thing being
/// waited for is different in kind. A SYN probe is answered by the target's
/// TCP stack as fast as the link allows. A UDP probe's most informative answer
/// is an ICMP error, and hosts **rate-limit** those: Linux emits roughly one
/// destination-unreachable per second by default (`net.ipv4.icmp_ratelimit`),
/// and BSD does the same. Answers to a multi-port scan therefore arrive spread
/// over seconds no matter how fast the network is.
///
/// That reshapes every number here, but `silence_floor` most of all. The SYN
/// profile gives up after 150 ms of quiet, which is generous for a stack that
/// answers immediately and *meaningless* against a host allowed to speak once
/// per second: the scan would stop while its answers were still queued and
/// legally on their way, then report the ports it never heard about as
/// filtered. A floor above the rate-limit interval is what makes silence
/// evidence of anything at all.
const DEADLINE_CONFIG: AdaptiveDeadlineConfig = AdaptiveDeadlineConfig::new(
    // Hard ceiling: a UDP scan is inherently slow, but it still has to finish.
    ScanBudget::new(
        Duration::from_millis(2_000),
        Duration::from_millis(200),
        Duration::from_secs(45),
    ),
    // Minimum runtime, so a scan cannot conclude before the first rate-limited
    // answers have had time to arrive.
    ScanBudget::new(
        Duration::from_millis(500),
        Duration::from_millis(50),
        Duration::from_secs(10),
    ),
    // Silence floor: longer than one rate-limit interval, so quiet means
    // "nothing is coming" rather than "the host is not allowed to answer yet".
    Duration::from_millis(1_200),
    Duration::from_secs(5),
    4.0,
    20,
);

/// How a UDP probe is retransmitted.
///
/// Every number here is set against a rate limit rather than against a round
/// trip, which is what makes this profile different in kind from the SYN one
/// ([`RETRY_POLICY`](super::RETRY_POLICY)). A closed UDP port answers with an
/// ICMP error, and hosts emit those at roughly one per second; a retry sooner
/// than that interval is guaranteed to be wasted, because the answer it is
/// chasing was never allowed to be sent.
///
/// Two attempts rather than three, and a gentler backoff than the SYN profile
/// uses, for the same reason. Backing off aggressively is how a scanner relieves
/// congestion it is causing, but a UDP scan is not waiting on congestion, it is
/// waiting on permission - so doubling buys little and costs a great deal of
/// tail latency on a scan that is already the slowest thing the engine does. A
/// probe therefore lives about 3.75 s against an unmeasured host and almost
/// exactly 3 s against a measured one, in exchange for every port getting a
/// second chance where it previously got one.
const RETRY_POLICY: RetryPolicy = RetryPolicy::new(
    2,
    Duration::from_millis(1_500),
    Duration::from_millis(1_200),
    Duration::from_secs(5),
    1.5,
    0.2,
    Some(SilentHostPolicy::new(32, 1)),
);

/// The most probes left outstanding at once.
///
/// Two jobs: it bounds the memory a scan of a large address space can occupy,
/// and it keeps the send loop from emptying the dispatcher into the network as
/// fast as the socket accepts writes - a burst that outruns any rate-limited
/// host's ability to answer manufactures open-filtered verdicts.
///
/// The ceiling is global rather than per host because
/// [`Dispatcher`](crate::scanner::dispatcher::Dispatcher) already hands out
/// shuffled targets, so consecutive probes in a multi-host scan naturally land
/// on different hosts. A per-host cap on top of that would constrain something
/// the target stream has already spread out.
const MAX_IN_FLIGHT: usize = 512;

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
    /// Probes sent but not yet resolved into a classification, and when each is
    /// next due to be resent or written off.
    ledger: Ledger,
    /// Scratch space for the probes coming due on one iteration, reused so a
    /// quiet tick allocates nothing.
    due: Vec<Due<ProbeTarget>>,
    /// The source port every probe in this scan is sent from. It is the scan's
    /// identity on the wire: the capture filter narrows direct replies to it,
    /// and an ICMP error's quoted datagram is only believed when it names this
    /// port as its source. See the module documentation.
    src_port: u16,
}

impl UdpPortScanner {
    /// Builds a scanner that selects each probe's source via `resolver`, sized
    /// for a scan covering `target_count` `(address, port)` pairs.
    ///
    /// The scan's fixed source port is drawn from the high ephemeral range,
    /// where it is unlikely to collide with a listening service on this host,
    /// and the transport's capture filter is built around it.
    pub fn new(
        resolver: SourceResolver,
        ctx: ScanContext,
        target_count: usize,
        tuning: ProbeTuning,
    ) -> Result<Self, StrategyError> {
        let src_port: u16 = rand::random_range(50_000..u16::MAX);
        let transport = ProbeTransport::open_with(
            ProbeKind::UdpProbe {
                reply_port: src_port,
            },
            tuning.send_mode,
        )?;

        Ok(Self::build(
            resolver,
            ctx,
            transport,
            target_count,
            src_port,
            RETRY_POLICY.configured(tuning.retry),
        ))
    }

    /// Builds a scanner around an already-opened transport, so the caller
    /// decides how probes reach the wire and where replies come from.
    ///
    /// `src_port` must be the port the transport's capture filter was built
    /// around, since it is what both halves use to recognize this scan's own
    /// traffic - see the module documentation. Paired with a synthetic
    /// transport (`ProbeTransport::from_parts`, behind the `test-support`
    /// feature) this is the seam that lets classification be driven against a
    /// simulated network rather than a real one.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_transport(
        resolver: SourceResolver,
        ctx: ScanContext,
        transport: ProbeTransport,
        target_count: usize,
        src_port: u16,
    ) -> Self {
        Self::build(
            resolver,
            ctx,
            transport,
            target_count,
            src_port,
            RETRY_POLICY,
        )
    }

    /// The common constructor, taking the retry schedule as an argument because
    /// the scan's own deadline is derived from it and so has to be settled
    /// before anything is built.
    fn build(
        resolver: SourceResolver,
        ctx: ScanContext,
        transport: ProbeTransport,
        target_count: usize,
        src_port: u16,
        retry: RetryPolicy,
    ) -> Self {
        // The scan has to outlive its own retry schedule, or probes are written
        // off as unanswered having never been fully asked.
        let deadline_config = DEADLINE_CONFIG.allowing_for(retry.worst_case_probe_lifetime());

        Self {
            resolver,
            ctx,
            transport,
            deadline: AdaptiveDeadline::new(deadline_config, target_count),
            ledger: Ledger::new(retry, target_count.min(MAX_IN_FLIGHT)),
            due: Vec::new(),
            src_port,
        }
    }

    fn send_probe(&mut self, target: Target) {
        if target.protocol != Protocol::Udp {
            return;
        }
        self.probe(target.ip, target.port, Instant::now());
    }

    /// Sends one datagram at `(ip, port)` and records the attempt.
    ///
    /// Used for the first attempt and every retry alike, and the retry is
    /// byte-for-byte the probe that preceded it: the payload is what makes an
    /// open port answer at all, and the source port is the scan's identity on
    /// the wire, so neither may vary between attempts.
    fn probe(&mut self, ip: IpAddr, port: u16, now: Instant) {
        let Some(src_addr) = self.resolver.resolve(ip) else {
            error!(
                verbosity = 2,
                "No route to {ip}; skipping UDP probe to {ip}:{port}"
            );
            return;
        };

        if send_udp(
            self.transport.tx.as_ref(),
            self.src_port,
            src_addr,
            ip,
            port,
        )
        .is_some()
        {
            self.ledger.arm(ip, (ip, port), (), now);
        }
    }

    /// Classifies one captured reply and, if it answers an outstanding probe,
    /// resolves that probe.
    fn handle_reply(&mut self, reply: &CapturedSegment, now: Instant) {
        let classified = match reply.protocol {
            IpNextHeaderProtocols::Udp => answering_probe(&reply.bytes, self.src_port)
                .map(|port| ((reply.source, port), Verdict::Port(PortState::Open))),
            _ => icmp_error::parse(reply).and_then(|error| {
                let target = quoted_probe(&error, self.src_port)?;
                Some((target, verdict_of(error.reason)))
            }),
        };

        match classified {
            Some((target, Verdict::Port(state))) => {
                self.resolve_probe(target, state, reply.source, now)
            }
            // The probe is deliberately left outstanding. This message reports
            // that the address could not be reached at all, so it carries no
            // verdict on the port it happened to quote, and the probe should
            // retire on its own schedule like any other unanswered one.
            Some((target, Verdict::Host)) => self.record_host_down(target.0, reply.source),
            None => {}
        }
    }

    /// Records that a router could not reach this address.
    ///
    /// The engine's only producer of [`HostStatus::Down`], and the reason the
    /// UDP scanner is the only path that can report it: it is the only one whose
    /// capture filter admits ICMP at all.
    ///
    /// The evidence is second-hand by definition - the host cannot report its
    /// own unreachability - so the reason names the router that sent it. Being
    /// the lowest non-`Unknown` status, it never overwrites evidence that the
    /// host answered for itself, whichever order the two arrive in.
    fn record_host_down(&mut self, ip: IpAddr, sender: IpAddr) {
        self.ctx.update_host(ip, |host| {
            host.record_evidence(
                HostStatus::Down,
                StatusReason::new(StatusProtocol::IcmpUnreachable, "destination unreachable")
                    .from_source(sender),
            );
        });
    }

    /// Retires one outstanding probe with the state its reply established,
    /// crediting the round trip to the deadline.
    ///
    /// A reply that matches no outstanding probe is dropped: it is a duplicate
    /// of one already resolved, an answer to a probe already written off, or a
    /// packet that reached us despite not answering anything this scan sent.
    ///
    /// The round trip is whatever the ledger is willing to vouch for. A probe
    /// that was sent once is unambiguous; one that was retried is not, since
    /// the two datagrams are identical on the wire, and no sample is taken.
    fn resolve_probe(
        &mut self,
        target: ProbeTarget,
        state: PortState,
        sender: IpAddr,
        now: Instant,
    ) {
        let Some(resolution) = self.ledger.resolve(&target, None, now) else {
            return;
        };

        self.deadline.mark_activity();
        if let Some(rtt) = resolution.rtt {
            self.deadline.record_rtt(rtt);
        }
        self.record_port(target.0, target.1, state, Some(sender));
    }

    /// Resends every probe that has gone unanswered long enough, and writes off
    /// the ones that have run out of attempts.
    ///
    /// Silence is a verdict in UDP rather than an absence of one, so there is no
    /// reason to hold it until the end of the scan: probes retire as their
    /// budgets run out, which streams results to the caller while the scan is
    /// still running and frees room under [`MAX_IN_FLIGHT`] for the targets
    /// queued behind them.
    ///
    /// Running out of attempts is not activity - nothing answered - so the
    /// adaptive deadline is deliberately left untouched here.
    fn service_retries(&mut self, now: Instant) {
        self.ledger.drain_due(now, &mut self.due);

        // Taken so the sends below can borrow `self` mutably; the buffer itself
        // is reused, so this costs no allocation.
        let due = std::mem::take(&mut self.due);
        for event in &due {
            match *event {
                Due::Retry {
                    key: (ip, port), ..
                } => self.probe(ip, port, now),
                Due::Exhausted((ip, port)) => {
                    self.record_port(ip, port, PortState::OpenFiltered, None)
                }
            }
        }
        self.due = due;
        self.due.clear();
    }

    /// Marks every probe still outstanding once the scan winds down as
    /// open-filtered. No ICMP error and no UDP reply arrived, which is equally
    /// consistent with a firewall dropping the probe and with a service that
    /// had nothing to say to it.
    ///
    /// [`service_retries`](Self::service_retries) retires most probes long
    /// before this runs; what reaches here are the ones still mid-schedule when
    /// the scan's own deadline ran out.
    fn resolve_remaining_as_filtered(&mut self) {
        for (ip, port) in self.ledger.drain_unresolved() {
            self.record_port(ip, port, PortState::OpenFiltered, None);
        }
    }

    /// How long the loop may sleep before it must look at its own state again.
    ///
    /// The adaptive deadline decides this while nothing is outstanding. With
    /// probes in flight the wait is additionally capped at the moment the next
    /// one falls due, so a retry goes out on time - which matters most in the
    /// case where *nothing* is arriving, since then no reply will wake the loop
    /// either.
    fn tick_delay(&self, now: Instant) -> Duration {
        let until_deadline_tick = self.deadline.time_until_next_tick();
        match self.ledger.next_due() {
            Some(due) => until_deadline_tick.min(due.saturating_duration_since(now)),
            None => until_deadline_tick,
        }
    }

    /// Files a port verdict and whatever the reply that produced it proves about
    /// the host.
    ///
    /// `sender` is the address the reply actually came from, or `None` when the
    /// verdict came from a spent attempt budget rather than from a packet.
    /// Everything here turns on comparing it against `ip`, because an ICMP error
    /// names two addresses - the hop that generated it, and the destination of
    /// the datagram it quotes - and they are different claims:
    ///
    /// - **The target answered.** Any reply the host sent proves it is up, and
    ///   that includes ones negative about the port: a port unreachable is
    ///   emitted by the host's own IP stack, and an administrative rejection
    ///   from the host itself is a host that exists and is policing its traffic.
    /// - **A middlebox rejected the probe by policy.** Something is enforcing a
    ///   perimeter around this address, which is [`HostStatus::Filtered`] - the
    ///   variant's documented meaning, and materially different from an address
    ///   nothing answers for.
    /// - **A middlebox reported the port closed.** The port verdict stands,
    ///   since the message reports on the port, but no host status is recorded:
    ///   the address that answered is not the address that was asked, and a NAT
    ///   answering on another host's behalf must not be read as that host being
    ///   up.
    /// - **Nothing answered.** `OpenFiltered` from exhaustion records nothing.
    ///   Silence is not evidence about a host.
    fn record_port(&mut self, ip: IpAddr, port_num: u16, state: PortState, sender: Option<IpAddr>) {
        let port = crate::fingerprinting::baseline_port(port_num, Protocol::Udp, state);
        let evidence = match (state, sender) {
            (PortState::Open, _) => Some((
                HostStatus::Up,
                StatusReason::new(StatusProtocol::Udp, "udp reply from a probed port"),
            )),
            (PortState::Closed, Some(sender)) if sender == ip => Some((
                HostStatus::Up,
                StatusReason::new(
                    StatusProtocol::IcmpUnreachable,
                    "port unreachable from the host",
                ),
            )),
            (PortState::Filtered, Some(sender)) if sender == ip => Some((
                HostStatus::Up,
                StatusReason::new(
                    StatusProtocol::IcmpUnreachable,
                    "administratively prohibited by the host",
                ),
            )),
            (PortState::Filtered, Some(sender)) => Some((
                HostStatus::Filtered,
                StatusReason::new(
                    StatusProtocol::IcmpUnreachable,
                    "administratively prohibited in path",
                )
                .from_source(sender),
            )),
            _ => None,
        };

        self.ctx.update_host(ip, |host| {
            host.add_port(port);
            if let Some((status, reason)) = evidence {
                host.record_evidence(status, reason);
            }
        });
    }
}

/// The port a direct UDP reply answers for, if the datagram is addressed to
/// this scan's source port.
///
/// The capture filter already narrows the UDP half to `src_port`, but that is a
/// performance boundary rather than a guarantee: a transport can be built with
/// no filter at all (`ProbeTransport::from_parts`), and a filter that silently
/// stopped matching would otherwise turn into false `Open`s. The check is cheap
/// and it is the only thing making the reply *ours*.
fn answering_probe(bytes: &[u8], src_port: u16) -> Option<u16> {
    let udp = UdpPacket::new(bytes)?;
    if udp.get_destination() != src_port {
        return None;
    }
    Some(udp.get_source())
}

/// What a reply is a statement about: the port that was probed, or the address
/// as a whole.
///
/// The distinction is not cosmetic. A reply reporting on the port resolves the
/// probe that provoked it; one reporting on the host says nothing about any
/// particular port, and the probe is left outstanding to time out on its own
/// rather than being given a verdict its evidence does not support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// The probed port is in this state. Covers both a direct UDP reply and
    /// every ICMP code that reports on a port rather than on the path.
    Port(PortState),
    /// The address itself could not be reached. The only evidence in the engine
    /// that produces [`HostStatus::Down`].
    Host,
}

/// What an ICMP error means for the UDP port it was drawn by.
///
/// A port unreachable is the one unambiguous "closed" a UDP scan ever gets:
/// the datagram reached a stack, which looked for a listener and found none.
/// That reading is specific to UDP - the identical message answering a TCP
/// probe means something else entirely, which is why this mapping lives beside
/// the scanner it belongs to rather than in [`icmp_error`].
fn verdict_of(reason: Unreachable) -> Verdict {
    match reason {
        Unreachable::Port => Verdict::Port(PortState::Closed),
        Unreachable::Prohibited => Verdict::Port(PortState::Filtered),
        Unreachable::Host => Verdict::Host,
    }
}

/// The probe an ICMP error is about and what the error says about it.
///
/// `None` unless the quoted datagram is a UDP probe this scan sent, which its
/// source port is what proves. Its destination address and port name the probe
/// to retire, and both come from the quotation rather than from the error's own
/// header, so an error relayed by a router still points at the host the probe
/// was aimed at.
fn quoted_probe(error: &icmp_error::IcmpError<'_>, src_port: u16) -> Option<ProbeTarget> {
    if error.quoted.protocol != IpNextHeaderProtocols::Udp {
        return None;
    }

    let udp = UdpPacket::new(error.quoted.payload)?;
    if udp.get_source() != src_port {
        return None;
    }

    Some((error.quoted.destination, udp.get_destination()))
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
    ///
    /// New targets are admitted only while fewer than `MAX_IN_FLIGHT` probes
    /// are outstanding. That ceiling is what paces the scan: probes leave as
    /// earlier ones are answered or expire, so the send rate settles at the
    /// rate the network is actually resolving them instead of at the rate the
    /// dispatcher can produce them.
    async fn scan(&mut self, mut targets: mpsc::Receiver<Target>) -> Result<(), StrategyError> {
        let mut sending_finished = false;

        loop {
            // Read once per iteration and reused throughout it; the arithmetic
            // below only needs the instants to agree with each other.
            let now = Instant::now();
            self.service_retries(now);

            if self.ctx.handle.should_stop() || self.deadline.hard_deadline_passed() {
                break;
            }
            if sending_finished && self.ledger.is_empty() {
                break;
            }
            // Silence is only evidence once nothing is outstanding. With probes
            // still waiting on their timers, quiet is exactly what the retry
            // schedule expects - and against a host rate-limiting its ICMP
            // errors, it is what the protocol expects too.
            if self.ledger.is_empty() && self.deadline.has_expired() {
                break;
            }

            // Both are read off `self` before the `select!`, which borrows the
            // receive half mutably for the duration of the statement.
            let admitting = !sending_finished && self.ledger.len() < MAX_IN_FLIGHT;
            let tick = self.tick_delay(now);

            tokio::select! {
                target = targets.recv(), if admitting => {
                    match target {
                        Some(target) => self.send_probe(target),
                        None => sending_finished = true,
                    }
                }

                res = self.transport.rx.recv() => {
                    match res {
                        Some(reply) => self.handle_reply(&reply, Instant::now()),
                        None => break,
                    }
                }

                // Wakes when the next probe is due, so a retry is sent on time
                // even though nothing is arriving to wake the loop otherwise.
                _ = tokio::time::sleep(tick) => {}
            }
        }

        self.resolve_remaining_as_filtered();
        Ok(())
    }

    // No `detect_services` override. The second pass in
    // [`service`](crate::scanner::service) opens a TCP connection to each open
    // port, so it identifies nothing this scanner found - and running it here
    // as well as from the SYN scanner beside us would fingerprint every open
    // *TCP* port twice, once per composite member. Identifying a UDP service
    // needs a UDP conversation, which is tracked separately (see
    // `docs/fingerprinting.md`, "UDP fingerprinting"); until that exists the
    // trait's no-op default is the honest implementation.
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
    use pnet::packet::icmp::destination_unreachable::{
        DestinationUnreachablePacket, IcmpCodes, MutableDestinationUnreachablePacket,
    };
    use pnet::packet::icmp::{IcmpCode, IcmpTypes};
    use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Packet, Icmpv6Types, MutableIcmpv6Packet};

    use super::super::icmp_error::{
        ICMPV6_ADMIN_PROHIBITED, ICMPV6_INGRESS_EGRESS_POLICY, ICMPV6_NO_ROUTE,
        ICMPV6_PORT_UNREACHABLE, ICMPV6_REJECT_ROUTE, ICMPV6_UNUSED_LEN,
    };

    use crate::core::session::ScanSession;
    use crate::network::probe::{MockSender, ProbeTransport};
    use crate::protocols::{ip, udp};

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
    const TARGET_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 200));
    /// A router between us and the target, which reports errors under its own
    /// address rather than the target's.
    const ROUTER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    /// This host's addresses, as the scanner's source resolver reports them.
    const LOCAL_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
    const LOCAL_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 50));
    /// The fixed source port the scanner under test probes from.
    const SCAN_SRC_PORT: u16 = 54_321;

    fn on_link_interface() -> pnet::datalink::NetworkInterface {
        pnet::datalink::NetworkInterface {
            name: "test0".to_string(),
            description: String::new(),
            index: 0,
            mac: None,
            ips: vec![
                IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 50), 24).unwrap()),
                IpNetwork::V6(
                    Ipv6Network::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 50), 64).unwrap(),
                ),
            ],
            flags: 0,
        }
    }

    /// [`scanner_with_mock`] plus the probe log, for the tests that assert on
    /// what actually reached the wire rather than only on what was recorded.
    fn scanner_with_recorder() -> (UdpPortScanner, ScanSession, SentProbes) {
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport = ProbeTransport::from_parts(Box::new(sender), reply_rx);
        let resolver = SourceResolver::from_interfaces(&[on_link_interface()]);

        let scanner = UdpPortScanner::with_transport(resolver, ctx, transport, 8, SCAN_SRC_PORT);
        (scanner, session, sent)
    }

    /// The probes a [`MockSender`] recorded, shared with the scanner under test.
    type SentProbes = std::sync::Arc<std::sync::Mutex<Vec<crate::network::probe::SentProbe>>>;

    fn scanner_with_mock() -> (UdpPortScanner, ScanSession) {
        let (session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let transport = ProbeTransport::from_parts(Box::new(MockSender::default()), reply_rx);
        let resolver = SourceResolver::from_interfaces(&[on_link_interface()]);

        let scanner = UdpPortScanner::with_transport(resolver, ctx, transport, 8, SCAN_SRC_PORT);
        (scanner, session)
    }

    fn probe(scanner: &mut UdpPortScanner, ip: IpAddr, port: u16) {
        scanner.send_probe(Target {
            ip,
            port,
            protocol: Protocol::Udp,
        });
    }

    fn host_status(session: &ScanSession, ip: IpAddr) -> Option<HostStatus> {
        session.hosts().get(&ip).map(|host| host.status())
    }

    fn port_state(session: &ScanSession, ip: IpAddr, port: u16) -> Option<PortState> {
        session
            .hosts()
            .get(&ip)
            .and_then(|h| h.ports().find(|p| p.number() == port).map(|p| p.state()))
    }

    /// A reply as the capture layer would deliver it: bytes plus the protocol
    /// the IP header said they are.
    fn captured(
        source: IpAddr,
        protocol: pnet::packet::ip::IpNextHeaderProtocol,
        bytes: Vec<u8>,
    ) -> CapturedSegment {
        CapturedSegment {
            source,
            protocol,
            bytes,
        }
    }

    /// A direct UDP reply from `src_port`, addressed back to `dst_port`.
    fn udp_reply(src_port: u16, dst_port: u16) -> CapturedSegment {
        captured(
            TARGET,
            IpNextHeaderProtocols::Udp,
            udp::create_packet(&TARGET, &LOCAL_V4, src_port, dst_port, vec![]).unwrap(),
        )
    }

    /// The quoted datagram an ICMP error carries: the IP header of the probe
    /// plus its UDP header. Built with the very functions that build a real
    /// probe, so the test agrees with the wire by construction rather than by
    /// a hand-written byte array.
    fn quoted_probe_packet(from: IpAddr, to: IpAddr, src_port: u16, dst_port: u16) -> Vec<u8> {
        let datagram = udp::create_packet(&from, &to, src_port, dst_port, vec![]).unwrap();
        let len = datagram.len() as u16;
        let header = match (from, to) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                ip::create_ipv4_header(s, d, len, IpNextHeaderProtocols::Udp).unwrap()
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                ip::create_ipv6_header(s, d, len, IpNextHeaderProtocols::Udp, ip::HOP_LIMIT_ROUTED)
                    .unwrap()
            }
            _ => panic!("IP version mismatch in test fixture"),
        };
        header.into_iter().chain(datagram).collect()
    }

    /// An ICMPv4 error of `code` from `from`, quoting a probe sent to
    /// `to:dst_port` from `src_port`.
    fn icmpv4_error(
        from: IpAddr,
        code: IcmpCode,
        to: IpAddr,
        src_port: u16,
        dst_port: u16,
    ) -> CapturedSegment {
        let quoted = quoted_probe_packet(LOCAL_V4, to, src_port, dst_port);
        let mut buf = vec![0u8; DestinationUnreachablePacket::minimum_packet_size() + quoted.len()];
        let mut packet = MutableDestinationUnreachablePacket::new(&mut buf).unwrap();
        packet.set_icmp_type(IcmpTypes::DestinationUnreachable);
        packet.set_icmp_code(code);
        packet.set_payload(&quoted);
        captured(from, IpNextHeaderProtocols::Icmp, buf)
    }

    /// An ICMPv6 error of `code`, quoting a probe sent to `to:dst_port`.
    fn icmpv6_error(code: Icmpv6Code, to: IpAddr, src_port: u16, dst_port: u16) -> CapturedSegment {
        let quoted = quoted_probe_packet(LOCAL_V6, to, src_port, dst_port);
        let mut buf =
            vec![0u8; Icmpv6Packet::minimum_packet_size() + ICMPV6_UNUSED_LEN + quoted.len()];
        let mut packet = MutableIcmpv6Packet::new(&mut buf).unwrap();
        packet.set_icmpv6_type(Icmpv6Types::DestinationUnreachable);
        packet.set_icmpv6_code(code);
        // Four unused bytes precede the quotation (RFC 4443 §3.1).
        let mut payload = vec![0u8; ICMPV6_UNUSED_LEN];
        payload.extend_from_slice(&quoted);
        packet.set_payload(&payload);
        captured(to, IpNextHeaderProtocols::Icmpv6, buf)
    }

    #[test]
    fn direct_udp_reply_is_open() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(&udp_reply(53, SCAN_SRC_PORT), Instant::now());

        assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Open));
        assert!(scanner.ledger.is_empty());
    }

    /// A datagram from a pending port that is *not* addressed to this scan's
    /// source port answers some other conversation on the host, not our probe.
    #[test]
    fn udp_traffic_not_addressed_to_the_scan_is_ignored() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(
            &udp_reply(53, SCAN_SRC_PORT.wrapping_add(1)),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET, 53), None);
        assert_eq!(scanner.ledger.len(), 1);
    }

    #[test]
    fn icmp_port_unreachable_is_closed() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(
            &icmpv4_error(
                TARGET,
                IcmpCodes::DestinationPortUnreachable,
                TARGET,
                SCAN_SRC_PORT,
                53,
            ),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Closed));
        assert!(scanner.ledger.is_empty());
    }

    /// The regression guard for the classification bug this scanner shipped
    /// with: an unreachable message names one port in its quoted datagram, and
    /// must retire that probe alone. Every other probe to the same host is
    /// still outstanding and must stay that way.
    #[test]
    fn icmp_unreachable_closes_only_the_port_it_quotes() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);
        probe(&mut scanner, TARGET, 161);
        probe(&mut scanner, TARGET, 123);

        scanner.handle_reply(
            &icmpv4_error(
                TARGET,
                IcmpCodes::DestinationPortUnreachable,
                TARGET,
                SCAN_SRC_PORT,
                161,
            ),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET, 161), Some(PortState::Closed));
        assert_eq!(port_state(&session, TARGET, 53), None);
        assert_eq!(port_state(&session, TARGET, 123), None);
        assert_eq!(scanner.ledger.len(), 2);
    }

    /// An error relayed by a router carries the router's address, but quotes a
    /// probe aimed at the host behind it. The quoted destination is what
    /// identifies the probe.
    #[test]
    fn unreachable_from_a_router_resolves_the_quoted_target() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(
            &icmpv4_error(
                ROUTER,
                IcmpCodes::DestinationPortUnreachable,
                TARGET,
                SCAN_SRC_PORT,
                53,
            ),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Closed));
        assert_eq!(port_state(&session, ROUTER, 53), None);
    }

    /// Host unreachable reports on the address, not on the port that happened to
    /// be quoted. Recording it as a port verdict - which is what this scanner
    /// did before liveness had anywhere to go - invents a fact about a port
    /// nothing ever answered for.
    #[test]
    fn host_unreachable_is_a_host_verdict_and_not_a_port_one() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(
            &icmpv4_error(
                ROUTER,
                IcmpCodes::DestinationHostUnreachable,
                TARGET,
                SCAN_SRC_PORT,
                53,
            ),
            Instant::now(),
        );

        assert_eq!(host_status(&session, TARGET), Some(HostStatus::Down));
        assert_eq!(
            port_state(&session, TARGET, 53),
            None,
            "the port has no verdict yet and the probe must be left to retire on its own"
        );
        assert_eq!(
            scanner.ledger.len(),
            1,
            "an unreachable address says nothing about the probe's fate"
        );
    }

    /// The distinction the whole host-status design turns on: an ICMP error
    /// names the hop that sent it as well as the address it is about, and only
    /// the first tells you whether the target is alive.
    #[test]
    fn a_port_unreachable_proves_the_host_only_when_the_host_sent_it() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);
        scanner.handle_reply(
            &icmpv4_error(
                TARGET,
                IcmpCodes::DestinationPortUnreachable,
                TARGET,
                SCAN_SRC_PORT,
                53,
            ),
            Instant::now(),
        );
        assert_eq!(host_status(&session, TARGET), Some(HostStatus::Up));

        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);
        scanner.handle_reply(
            &icmpv4_error(
                ROUTER,
                IcmpCodes::DestinationPortUnreachable,
                TARGET,
                SCAN_SRC_PORT,
                53,
            ),
            Instant::now(),
        );
        assert_eq!(
            host_status(&session, TARGET),
            Some(HostStatus::Unknown),
            "a middlebox answering for an address does not make that address alive"
        );
        assert_eq!(
            port_state(&session, TARGET, 53),
            Some(PortState::Closed),
            "the port verdict still stands: the message does report on the port"
        );
    }

    /// A policy rejection from a middlebox proves a perimeter, not a host - but
    /// a perimeter is still more than nothing, which is what separates
    /// `Filtered` from `Unknown`.
    #[test]
    fn an_in_path_policy_rejection_is_filtered_rather_than_up() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(
            &icmpv4_error(
                ROUTER,
                IcmpCodes::CommunicationAdministrativelyProhibited,
                TARGET,
                SCAN_SRC_PORT,
                53,
            ),
            Instant::now(),
        );

        assert_eq!(host_status(&session, TARGET), Some(HostStatus::Filtered));
    }

    /// Silence is the one thing that must never move a host's status, however
    /// many probes it swallows. `OpenFiltered` is a port verdict reached by
    /// exhaustion, and a host that has sent nothing has proved nothing.
    #[test]
    fn exhausting_every_attempt_leaves_the_host_unknown() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        let mut now = Instant::now();
        for _ in 0..8 {
            now += Duration::from_secs(10);
            scanner.service_retries(now);
        }

        assert_eq!(
            port_state(&session, TARGET, 53),
            Some(PortState::OpenFiltered)
        );
        assert_eq!(host_status(&session, TARGET), Some(HostStatus::Unknown));
        assert!(
            session
                .hosts()
                .get(&TARGET)
                .expect("the port verdict created the host")
                .reasons()
                .is_empty(),
            "silence is not evidence and must leave no audit trail"
        );
    }

    /// An unreachable quoting a datagram this scan never sent - a different
    /// source port - belongs to someone else's traffic.
    #[test]
    fn unreachable_quoting_a_foreign_probe_is_ignored() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(
            &icmpv4_error(
                TARGET,
                IcmpCodes::DestinationPortUnreachable,
                TARGET,
                SCAN_SRC_PORT.wrapping_add(1),
                53,
            ),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET, 53), None);
        assert_eq!(scanner.ledger.len(), 1);
    }

    /// Only code 3 says a port answered. The codes that describe a blocked
    /// path prove the probe did not arrive, which is `Filtered` - a strictly
    /// better answer than letting the probe time out into `OpenFiltered`.
    #[test]
    fn administratively_prohibited_icmp_is_filtered() {
        for code in [
            IcmpCodes::DestinationProtocolUnreachable,
            IcmpCodes::NetworkAdministrativelyProhibited,
            IcmpCodes::HostAdministrativelyProhibited,
            IcmpCodes::CommunicationAdministrativelyProhibited,
        ] {
            let (mut scanner, session) = scanner_with_mock();
            probe(&mut scanner, TARGET, 53);

            scanner.handle_reply(
                &icmpv4_error(TARGET, code, TARGET, SCAN_SRC_PORT, 53),
                Instant::now(),
            );

            assert_eq!(
                port_state(&session, TARGET, 53),
                Some(PortState::Filtered),
                "ICMP code {code:?} should read as filtered"
            );
        }
    }

    /// A code that reports on neither the port nor the path leaves the probe
    /// outstanding, to time out into `OpenFiltered` like any other silence.
    #[test]
    fn uninformative_icmp_codes_leave_the_probe_outstanding() {
        for code in [
            IcmpCodes::DestinationNetworkUnknown,
            IcmpCodes::FragmentationRequiredAndDFFlagSet,
            IcmpCodes::SourceRouteFailed,
        ] {
            let (mut scanner, session) = scanner_with_mock();
            probe(&mut scanner, TARGET, 53);

            scanner.handle_reply(
                &icmpv4_error(TARGET, code, TARGET, SCAN_SRC_PORT, 53),
                Instant::now(),
            );

            assert_eq!(port_state(&session, TARGET, 53), None, "code {code:?}");
            assert_eq!(scanner.ledger.len(), 1, "code {code:?}");
        }
    }

    #[test]
    fn icmpv6_policy_refusals_are_filtered() {
        for code in [
            ICMPV6_ADMIN_PROHIBITED,
            ICMPV6_INGRESS_EGRESS_POLICY,
            ICMPV6_REJECT_ROUTE,
        ] {
            let (mut scanner, session) = scanner_with_mock();
            probe(&mut scanner, TARGET_V6, 53);

            scanner.handle_reply(
                &icmpv6_error(code, TARGET_V6, SCAN_SRC_PORT, 53),
                Instant::now(),
            );

            assert_eq!(
                port_state(&session, TARGET_V6, 53),
                Some(PortState::Filtered),
                "ICMPv6 code {code:?} should read as filtered"
            );
        }
    }

    /// An ICMP error's first two bytes (type 3, code 3) read as the source port
    /// 771 if the segment is parsed as UDP. Carrying the protocol from the IP
    /// header is what stops that from becoming a false `Open`.
    #[test]
    fn icmp_error_is_never_read_as_a_udp_reply() {
        let (mut scanner, session) = scanner_with_mock();
        // 0x0303: what an ICMPv4 unreachable's type/code look like as a port.
        probe(&mut scanner, TARGET, 771);
        probe(&mut scanner, TARGET, 53);

        scanner.handle_reply(
            &icmpv4_error(
                TARGET,
                IcmpCodes::DestinationPortUnreachable,
                TARGET,
                SCAN_SRC_PORT,
                53,
            ),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET, 771), None);
        assert_eq!(port_state(&session, TARGET, 53), Some(PortState::Closed));
    }

    #[test]
    fn icmpv6_port_unreachable_is_closed() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET_V6, 53);

        scanner.handle_reply(
            &icmpv6_error(ICMPV6_PORT_UNREACHABLE, TARGET_V6, SCAN_SRC_PORT, 53),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET_V6, 53), Some(PortState::Closed));
        assert!(scanner.ledger.is_empty());
    }

    /// ICMPv6 code 0 is "no route to destination" - a statement about the path.
    #[test]
    fn icmpv6_no_route_is_ignored() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET_V6, 53);

        scanner.handle_reply(
            &icmpv6_error(ICMPV6_NO_ROUTE, TARGET_V6, SCAN_SRC_PORT, 53),
            Instant::now(),
        );

        assert_eq!(port_state(&session, TARGET_V6, 53), None);
        assert_eq!(scanner.ledger.len(), 1);
    }

    /// A truncated or malformed reply must be dropped, never panic: every byte
    /// of it was chosen by a remote host.
    #[test]
    fn malformed_replies_are_dropped() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        for len in 0..48usize {
            let bytes = vec![0xFFu8; len];
            for protocol in [
                IpNextHeaderProtocols::Udp,
                IpNextHeaderProtocols::Icmp,
                IpNextHeaderProtocols::Icmpv6,
            ] {
                scanner.handle_reply(&captured(TARGET, protocol, bytes.clone()), Instant::now());
            }
        }

        assert_eq!(port_state(&session, TARGET, 53), None);
        assert_eq!(scanner.ledger.len(), 1);
    }

    /// Checks the quoted-datagram parse against an ICMP error this machine's
    /// own kernel produced, rather than one this test module built. Every
    /// other test here agrees with the wire only as far as our own encoder
    /// does; this one closes that loop.
    ///
    /// It drives the real receive path - a `libpcap` capture with the same
    /// filter a scan uses - but sends its probe from an ordinary `UdpSocket`,
    /// so it needs capture access (root, or `access_bpf` membership on macOS)
    /// but not raw sockets. Ignored by default because that access is not
    /// something a test run can assume; run it with
    /// `cargo test -- --ignored real_kernel_icmp_error`.
    #[tokio::test]
    #[ignore = "needs libpcap capture access (root or access_bpf)"]
    async fn real_kernel_icmp_error_identifies_the_probe_that_caused_it() {
        use crate::network::capture;
        use std::time::Duration;

        let loopback = pnet::datalink::interfaces()
            .into_iter()
            .find(|iface| iface.is_loopback() && iface.is_up())
            .expect("a loopback interface to capture on");

        // Stands in for the scan's fixed source port: replies and errors are
        // matched against whatever port the probes went out from.
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let src_port = socket.local_addr().unwrap().port();

        // A port nothing listens on, so the kernel answers with an error:
        // bind one to learn a free number, then release it.
        let reserved = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let closed_port = reserved.local_addr().unwrap().port();
        drop(reserved);

        let filter = format!("icmp or icmp6 or (udp and dst port {src_port})");
        let (mut rx, _capture) = capture::start(&[loopback.name], &filter).unwrap();
        // The capture threads open their devices asynchronously; a probe sent
        // before they are listening would simply not be seen.
        tokio::time::sleep(Duration::from_millis(500)).await;

        socket
            .send_to(b"", ("127.0.0.1", closed_port))
            .await
            .unwrap();

        let reply = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("kernel produced no ICMP error within 3s")
            .expect("capture stream closed");

        assert_eq!(reply.protocol, IpNextHeaderProtocols::Icmp);
        let error = icmp_error::parse(&reply).expect("a real ICMP error parses");
        assert_eq!(
            (quoted_probe(&error, src_port), verdict_of(error.reason)),
            (
                Some((IpAddr::V4(Ipv4Addr::LOCALHOST), closed_port)),
                Verdict::Port(PortState::Closed)
            ),
            "a real ICMP error must name the exact probe that caused it",
        );
    }

    /// The companion to the ICMP check above, for the other half of the
    /// classification: a real reply from a real listener, arriving through the
    /// real capture filter.
    ///
    /// A filter that compiles but never matches would turn every open port
    /// into `OpenFiltered` - the scan would keep running and keep reporting,
    /// just never positively. Only live traffic can catch that.
    #[tokio::test]
    #[ignore = "needs libpcap capture access (root or access_bpf)"]
    async fn real_udp_reply_reaches_the_scan_through_the_capture_filter() {
        use crate::network::capture;
        use std::time::Duration;

        let loopback = pnet::datalink::interfaces()
            .into_iter()
            .find(|iface| iface.is_loopback() && iface.is_up())
            .expect("a loopback interface to capture on");

        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let src_port = socket.local_addr().unwrap().port();

        // A listener that answers once, so there is a genuine reply to catch.
        let service = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let service_port = service.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            if let Ok((_, from)) = service.recv_from(&mut buf).await {
                let _ = service.send_to(b"pong", from).await;
            }
        });

        let filter = format!("icmp or icmp6 or (udp and dst port {src_port})");
        let (mut rx, _capture) = capture::start(&[loopback.name], &filter).unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;

        socket
            .send_to(b"ping", ("127.0.0.1", service_port))
            .await
            .unwrap();

        // The filter also admits ICMP, which loopback may carry for unrelated
        // reasons; take the first UDP segment rather than assuming it is first.
        let reply = tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(segment) = rx.recv().await {
                if segment.protocol == IpNextHeaderProtocols::Udp {
                    return segment;
                }
            }
            panic!("capture stream closed before a UDP reply arrived");
        })
        .await
        .expect("no UDP reply captured within 3s");

        assert_eq!(
            answering_probe(&reply.bytes, src_port),
            Some(service_port),
            "a real reply must resolve to the port that sent it",
        );
    }

    /// An unanswered probe is sent again rather than written off, since silence
    /// on a first UDP probe is the least informative signal in the protocol.
    #[test]
    fn an_unanswered_probe_is_sent_again() {
        let (mut scanner, session, sent) = scanner_with_recorder();
        probe(&mut scanner, TARGET, 53);

        scanner.service_retries(Instant::now() + Duration::from_secs(2));

        assert_eq!(sent.lock().unwrap().len(), 2, "the probe was not retried");
        assert_eq!(port_state(&session, TARGET, 53), None, "no verdict yet");
    }

    /// A probe that has spent its budget is written off while the scan is still
    /// running, so results reach the caller as they are decided rather than all
    /// at once at the end.
    #[test]
    fn a_probe_that_spends_its_budget_is_written_off_during_the_scan() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        // Each retry reschedules from the moment it is sent, so the schedule
        // has to be walked rather than jumped over.
        let mut now = Instant::now();
        for _ in 0..RETRY_POLICY.max_attempts + 1 {
            now += RETRY_POLICY.worst_case_probe_lifetime();
            scanner.service_retries(now);
        }

        assert_eq!(
            port_state(&session, TARGET, 53),
            Some(PortState::OpenFiltered)
        );
        assert!(scanner.ledger.is_empty());
    }

    /// Running out of attempts is not activity: nothing answered, so the
    /// adaptive deadline must not be told the scan is making progress.
    #[test]
    fn running_out_of_attempts_does_not_extend_the_deadline() {
        let (mut scanner, _session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 53);

        // A deadline whose silence clock has been reset reports a full tick;
        // capture the value before and after to see whether it moved.
        let before = scanner.deadline.time_until_next_tick();
        let mut now = Instant::now();
        for _ in 0..RETRY_POLICY.max_attempts + 1 {
            now += RETRY_POLICY.worst_case_probe_lifetime();
            scanner.service_retries(now);
        }
        let after = scanner.deadline.time_until_next_tick();

        assert!(
            after <= before,
            "silence clock was reset by an expiry ({before:?} -> {after:?})"
        );
    }

    /// While probes are outstanding the loop must not sleep past the point
    /// where the next one falls due - nothing else will wake it, because
    /// silence is exactly the case being timed.
    #[test]
    fn pending_probes_shorten_the_sleep() {
        let (mut scanner, _session) = scanner_with_mock();
        let now = Instant::now();
        assert!(scanner.ledger.is_empty());
        let idle = scanner.tick_delay(now);

        probe(&mut scanner, TARGET, 53);
        let busy = scanner.tick_delay(now);

        assert!(busy < idle, "sleep not shortened while probes are out");
        assert!(
            busy <= RETRY_POLICY.worst_case_probe_lifetime(),
            "the loop would sleep past the probe's whole schedule"
        );
    }

    /// The UDP profile has to tolerate silence for longer than a host's ICMP
    /// rate-limit interval (~1/sec), or a scan concludes while its answers are
    /// still queued. This is the property that makes it a separate profile from
    /// the SYN one, so it is asserted rather than left to a comment.
    #[test]
    fn silence_floor_outlasts_the_icmp_rate_limit() {
        const ICMP_RATE_LIMIT_INTERVAL: Duration = Duration::from_secs(1);

        assert!(
            DEADLINE_CONFIG.silence_floor > ICMP_RATE_LIMIT_INTERVAL,
            "silence floor {:?} is shorter than one rate-limited answer",
            DEADLINE_CONFIG.silence_floor
        );
        assert!(
            super::super::DEADLINE_CONFIG.silence_floor < ICMP_RATE_LIMIT_INTERVAL,
            "the SYN profile was expected to be the tighter one"
        );
    }

    #[test]
    fn unanswered_probes_resolve_as_filtered() {
        let (mut scanner, session) = scanner_with_mock();
        probe(&mut scanner, TARGET, 161);

        scanner.resolve_remaining_as_filtered();

        assert_eq!(
            port_state(&session, TARGET, 161),
            Some(PortState::OpenFiltered)
        );
        assert!(scanner.ledger.is_empty());
    }

    #[test]
    fn non_udp_targets_are_not_probed() {
        let (mut scanner, _session) = scanner_with_mock();
        scanner.send_probe(Target {
            ip: TARGET,
            port: 80,
            protocol: Protocol::Tcp,
        });
        assert!(scanner.ledger.is_empty());
    }

    /// Every probe in a scan must leave from the one port the capture filter
    /// and the quoted-datagram check are built around.
    #[test]
    fn every_probe_is_sent_from_the_scan_source_port() {
        let (_session, ctx) = ScanSession::new();
        let (_reply_tx, reply_rx) = tokio::sync::mpsc::unbounded_channel();
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport = ProbeTransport::from_parts(Box::new(sender), reply_rx);
        let mut scanner = UdpPortScanner::with_transport(
            SourceResolver::from_interfaces(&[on_link_interface()]),
            ctx,
            transport,
            8,
            SCAN_SRC_PORT,
        );

        for port in [53, 161, 123] {
            probe(&mut scanner, TARGET, port);
        }

        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 3);
        for (segment, _src, _dst) in sent.iter() {
            let udp = UdpPacket::new(segment).expect("probe is a UDP datagram");
            assert_eq!(udp.get_source(), SCAN_SRC_PORT);
        }
    }
}
