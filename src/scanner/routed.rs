// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Routed Host Discovery
//!
//! Finds hosts reached through a gateway rather than ones sitting on the local
//! segment. It sends a single raw TCP SYN packet to each target and listens for
//! any reply. A full three-way handshake is never completed, so this works
//! whether or not the target port is open. [`port_scan`] builds on the same
//! raw-socket machinery to answer a different question: not whether a host is
//! alive, but which of its ports are open.
//!
//! This scanner requires root privileges to open the raw sockets involved.

mod port_scan;
mod udp_scan;

use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

use crate::core::config::ProbeTuning;
use crate::core::models::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::core::models::ip::set::IpSet;
use crate::core::models::retry::{Due, ProbeLedger, RetryPolicy, SilentHostPolicy};
use crate::core::models::timer::ScanBudget;
use crate::core::session::ScanContext;
use crate::network::probe::{ProbeKind, ProbeSender, ProbeTransport};
use crate::protocols as protocol;
use crate::system::interface::RoutedTarget;
use crate::{error, success};
use async_trait::async_trait;
use pnet::packet::tcp::TcpPacket;
use tokio::sync::mpsc::UnboundedSender;

use super::audit::{ProbeAudit, StopReason};
use super::{NetworkExplorer, payload};

pub use port_scan::SynPortScanner;
pub use udp_scan::UdpPortScanner;

/// How long a routed sweep or port scan runs and how it adapts.
///
/// Routed targets sit anywhere on the internet rather than on one segment, so a
/// single scan spans a wide range of round trips and the extremes matter more
/// than the average. Two of these values carry most of that weight:
///
/// - **Silence floor.** The silence tolerance is derived from observed round
///   trips, which the fastest responders dominate - they answer first and pull
///   the estimate toward their own latency, which would end the scan while
///   slower targets are still legitimately in flight. The floor is what bounds
///   that, so it is set against the tail of the round-trip distribution rather
///   than its middle.
/// - **Hard budget.** The base gives a distant target room for several round
///   trips; the per-target term covers the send burst and the spread of
///   arrivals behind it. The ceiling is a backstop against a scan that will not
///   terminate, not a duration any scan is expected to reach.
///
/// The minimum runtime exists so silence is never the reason a scan stops
/// before an answer could plausibly have arrived at all.
///
/// A generous budget costs nothing when a scan succeeds, since both loops exit
/// as soon as every target is resolved ([`RoutedScanner`] once all targets have
/// responded, [`SynPortScanner`] once nothing is pending). It is spent only
/// when something is still missing.
const DEADLINE_CONFIG: AdaptiveDeadlineConfig = AdaptiveDeadlineConfig::new(
    ScanBudget::new(
        Duration::from_millis(2_000),
        Duration::from_millis(1),
        Duration::from_secs(60),
    ),
    ScanBudget::new(
        Duration::from_millis(300),
        Duration::from_micros(500),
        Duration::from_secs(10),
    ),
    Duration::from_millis(400),
    Duration::from_secs(3),
    4.0,
    20,
);

/// How a SYN probe is retransmitted, shared by both scanners here for the same
/// reason they share a deadline profile: it is the same probe over the same kind
/// of path.
///
/// Three attempts is where the useful range begins and stops paying. Two is the
/// least that distinguishes a lost packet from a silent one; beyond three, the
/// marginal probe recovers little on any path healthy enough to be worth
/// scanning, and every extra attempt is paid on every unanswered target.
///
/// The floor sits far below the starting timeout, and the gap between them is
/// the point. Before anything has been measured the network is unknown rather
/// than known to be fast, so 200 ms of patience is cheap insurance against
/// tripling the traffic of a scan that crosses an ocean. Once a target has
/// answered, its own round trip governs, and on a local path that collapses
/// toward the floor - so silence is settled in a fraction of a second where a
/// fixed timeout would have spent the whole budget waiting.
const RETRY_POLICY: RetryPolicy = RetryPolicy::new(
    3,
    Duration::from_millis(200),
    Duration::from_millis(25),
    Duration::from_secs(2),
    2.0,
    0.2,
    Some(SilentHostPolicy::new(32, 2)),
);

type SeqNum = u32;

/// What identifies one SYN attempt on the wire.
///
/// Both halves earn their place. The sequence number comes back in the reply's
/// acknowledgement, and the source port is where the reply is addressed, so
/// together they establish that a segment answers *this probe* rather than
/// merely that it came from the right port on the right host.
///
/// A fresh pair per attempt is also what makes a retried probe measurable. TCP
/// itself must discard round-trip samples from retransmissions because it
/// cannot tell which transmission an acknowledgement answers; a scanner picks a
/// new sequence number every time, so the reply names the attempt it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynToken {
    pub seq: SeqNum,
    pub src_port: u16,
}

/// Sends a single TCP SYN packet from `src_addr` to `dst_addr:dst_port` through
/// `sender` and logs the outcome. On success it returns the [`SynToken`] the
/// packet went out carrying, so the caller can record it and recognize a later
/// reply as answering this attempt.
fn send_syn(
    sender: &dyn ProbeSender,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    dst_port: u16,
) -> Option<SynToken> {
    let src_port: u16 = rand::random_range(50_000..u16::MAX);
    let seq_num: u32 = rand::random_range(0..=u32::MAX);

    let packet =
        match protocol::tcp::create_packet(&src_addr, &dst_addr, src_port, dst_port, seq_num) {
            Ok(pkt) => pkt,
            Err(e) => {
                error!(
                    verbosity = 2,
                    "Failed to create SYN packet for {dst_addr}:{dst_port}: {e}"
                );
                return None;
            }
        };

    match sender.send(&packet, src_addr, dst_addr) {
        Ok(_) => {
            success!(verbosity = 2, "Sent SYN probe to {dst_addr}:{dst_port}");
            Some(SynToken {
                seq: seq_num,
                src_port,
            })
        }
        Err(e) => {
            error!(
                verbosity = 2,
                "Failed to send SYN probe to {dst_addr}:{dst_port}: {e}"
            );
            None
        }
    }
}

/// Sends a single UDP probe from `src_port` to `dst_addr:dst_port` through
/// `sender` and logs the outcome.
///
/// Unlike [`send_syn`], which randomizes its source port per probe, every UDP
/// probe in a scan leaves from the same `src_port`. That single port is the
/// scan's identity on the wire: the capture filter narrows direct replies down
/// to it, and the datagram quoted inside an ICMP error is checked against it.
/// Randomizing per probe would leave no filter expressible but "all UDP".
fn send_udp(
    sender: &dyn ProbeSender,
    src_port: u16,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    dst_port: u16,
) -> Option<()> {
    // What makes an open port answer at all: UDP has no handshake, so the
    // application itself has to recognize the request. See [`payload`].
    let payload = payload::for_port(dst_port).to_vec();

    let packet = match crate::protocols::udp::create_packet(
        &src_addr, &dst_addr, src_port, dst_port, payload,
    ) {
        Ok(pkt) => pkt,
        Err(e) => {
            error!(
                verbosity = 2,
                "Failed to create UDP packet for {dst_addr}:{dst_port}: {e}"
            );
            return None;
        }
    };

    match sender.send(&packet, src_addr, dst_addr) {
        Ok(_) => {
            success!(verbosity = 2, "Sent UDP probe to {dst_addr}:{dst_port}");
            Some(())
        }
        Err(e) => {
            error!(
                verbosity = 2,
                "Failed to send UDP probe to {dst_addr}:{dst_port}: {e}"
            );
            None
        }
    }
}

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
    /// Governs how long this sweep keeps running, adapting to observed
    /// round-trip times.
    deadline: AdaptiveDeadline,
    /// Where to forward newly discovered addresses for hostname
    /// resolution, if enabled.
    dns_tx: Option<UnboundedSender<IpAddr>>,
    /// Probes sent but not yet answered, and when each is next due to be
    /// resent or given up on.
    ledger: ProbeLedger<IpAddr, SynToken>,
    /// Scratch space for the probes coming due on one iteration, reused so a
    /// quiet tick allocates nothing.
    due: Vec<Due<IpAddr>>,
    /// How many distinct addresses have responded so far.
    responded_count: usize,
    /// Per-run counters, so a sweep that finds fewer hosts than it should can be
    /// attributed to loss, to its own deadline, or to correlation rather than
    /// guessed at. Reported once when the loop exits.
    audit: ProbeAudit,
}

#[async_trait]
impl NetworkExplorer for RoutedScanner {
    async fn discover_hosts(mut self: Box<Self>) -> anyhow::Result<()> {
        match self.send_discovery_packets() {
            Ok(_) => success!("Discovery packets sent successfully"),
            Err(e) => error!("Sending discovery packets failed: {e}"),
        }

        // The loop yields why it stopped, so the audit cannot report a reason
        // the code never actually took.
        let reason = loop {
            let now = Instant::now();
            self.service_retries(now);

            let all_responded = self.ips.len() == self.responded_count as u128;
            if self.ctx.handle.should_stop() {
                break StopReason::Aborted;
            }
            if all_responded {
                break StopReason::AllResponded;
            }
            // Nothing outstanding means every target has either answered or
            // been asked as many times as it is going to be. Waiting longer
            // cannot change the result, where previously the sweep sat out the
            // rest of its budget on the chance that it might.
            if self.ledger.is_empty() {
                break StopReason::AttemptsSpent;
            }
            if self.deadline.hard_deadline_passed() {
                break StopReason::DeadlineExpired;
            }

            let tick = self.tick_delay(now);

            tokio::select! {
                res = self.transport.rx.recv() => {
                    match res {
                        Some(reply) => {
                            self.audit.record_segment();
                            self.handle_discovery_reply(reply.source, &reply.bytes, Instant::now());
                        }
                        None => break StopReason::StreamClosed,
                    }
                },
                // Wakes when the next probe is due, so a retry goes out on time
                // even though nothing is arriving to wake the loop otherwise.
                _ = tokio::time::sleep(tick) => {}
            }
        };

        // Read before the transport is dropped, since the counters live with
        // the capture threads it keeps alive.
        let capture = self.transport.capture_counts();
        self.audit
            .report("routed-discovery", self.ips.len(), reason, capture);
        Ok(())
    }
}

impl RoutedScanner {
    pub fn new(
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        tuning: ProbeTuning,
    ) -> anyhow::Result<Self> {
        let transport = ProbeTransport::open_with(ProbeKind::TcpSyn, tuning.send_mode)?;
        Ok(Self::build(targets, ctx, dns_tx, transport, RETRY_POLICY.configured(tuning.retry)))
    }

    /// Builds a sweep around an already-opened transport, so the caller decides
    /// how probes reach the wire and where replies come from.
    ///
    /// Paired with a synthetic transport (`ProbeTransport::from_parts`, behind
    /// the `test-support` feature) this is the seam that lets liveness
    /// detection and RTT correlation be driven against a simulated network
    /// rather than a real one.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_transport(
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        transport: ProbeTransport,
    ) -> Self {
        Self::build(targets, ctx, dns_tx, transport, RETRY_POLICY)
    }

    /// The common constructor, taking the retry schedule as an argument because
    /// the sweep's own deadline is derived from it and so has to be settled
    /// before anything is built.
    fn build(
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        transport: ProbeTransport,
        retry: RetryPolicy,
    ) -> Self {
        let mut ips = IpSet::new();
        let mut sources = HashMap::with_capacity(targets.len());
        for RoutedTarget { target, source } in targets {
            ips.insert(target);
            sources.insert(target, source);
        }
        ips.canonicalize();

        let target_count = sources.len();
        // The sweep has to outlive its own retry schedule, or probes are given
        // up on having never been fully asked.
        let deadline_config = DEADLINE_CONFIG.allowing_for(retry.worst_case_probe_lifetime());

        Self {
            ctx,
            sources,
            ips,
            transport,
            deadline: AdaptiveDeadline::new(deadline_config, target_count),
            dns_tx,
            ledger: ProbeLedger::new(retry, target_count),
            due: Vec::new(),
            responded_count: 0,
            audit: ProbeAudit::new(),
        }
    }

    /// Records a raw TCP reply from `ip` as evidence the host is alive,
    /// crediting it with a round-trip time if the reply's acknowledgement
    /// number matches an outstanding probe.
    fn handle_discovery_reply(&mut self, ip: IpAddr, bytes: &[u8], now: Instant) {
        if !self.ips.contains(&ip) {
            self.audit.record_off_target();
            return;
        }

        let rtt = self.resolve_probe(ip, bytes, now);
        if rtt.is_none() {
            self.audit.record_reply_without_rtt();
        }

        // Host mutation only; the guard is dropped and the event emitted inside
        // `write_host`, so the deadline and DNS follow-ups below never run under
        // the store lock.
        let is_new = self.ctx.write_host(ip, |host| {
            if let Some(rtt) = rtt {
                host.add_rtt(rtt);
                return true;
            }
            false
        });

        if is_new {
            self.responded_count += 1;
            self.audit.record_host_found();
            self.deadline.mark_activity();
            if let Some(dns) = &self.dns_tx {
                let _ = dns.send(ip);
            }
        }

        if let Some(rtt) = rtt {
            self.deadline.record_rtt(rtt);
        }
    }

    /// Retires the probe to `ip` and reports the round trip it revealed.
    ///
    /// Correlation is attempted twice on purpose. The first pass matches the
    /// segment against the exact attempt it acknowledges, which is what yields a
    /// true round trip even for a target that had to be asked more than once.
    /// The second accepts the reply on its own terms: for discovery the question
    /// is only whether something is there, and a TCP segment from a probed
    /// address answers that whether or not it can be tied to a particular
    /// attempt. Retiring the probe either way is what stops a host that has
    /// already proved it exists from being asked again.
    fn resolve_probe(&mut self, ip: IpAddr, bytes: &[u8], now: Instant) -> Option<Duration> {
        let token = TcpPacket::new(bytes).map(|tcp| SynToken {
            seq: tcp.get_acknowledgement().wrapping_sub(1),
            src_port: tcp.get_destination(),
        });

        let resolution = token
            .and_then(|token| self.ledger.resolve(&ip, Some(token), now))
            .or_else(|| self.ledger.resolve(&ip, None, now))?;

        resolution.rtt
    }

    /// Resends every probe that has gone unanswered long enough.
    ///
    /// A probe that runs out of attempts needs nothing recorded: a host that
    /// never answered is simply one this sweep does not report, and the ledger
    /// emptying is what tells the loop the sweep is finished.
    fn service_retries(&mut self, now: Instant) {
        self.ledger.drain_due(now, &mut self.due);

        // Taken so the sends below can borrow `self` mutably; the buffer itself
        // is reused, so this costs no allocation.
        let due = std::mem::take(&mut self.due);
        for event in &due {
            if let Due::Retry { key, .. } = *event {
                self.probe(key, now);
            }
        }
        self.due = due;
        self.due.clear();
    }

    /// How long the loop may sleep: until the sweep's next checkpoint, or until
    /// the next probe is due, whichever comes first.
    fn tick_delay(&self, now: Instant) -> Duration {
        let until_deadline_tick = self.deadline.time_until_next_tick();
        match self.ledger.next_due() {
            Some(due) => until_deadline_tick.min(due.saturating_duration_since(now)),
            None => until_deadline_tick,
        }
    }

    fn send_discovery_packets(&mut self) -> anyhow::Result<()> {
        // Collected so the send loop can mutate `self` while iterating; the
        // source map itself is kept, since a retry leaves from the same address.
        let targets: Vec<IpAddr> = self.sources.keys().copied().collect();

        let now = Instant::now();
        for target in targets {
            self.probe(target, now);
        }

        Ok(())
    }

    /// Sends one SYN at `target` and records the attempt.
    ///
    /// Used for the first attempt and every retry alike. A probe that cannot be
    /// sent is not armed; the ledger has already charged the attempt by the time
    /// a retry reaches here, so an unroutable target still runs out of attempts
    /// on schedule.
    fn probe(&mut self, target: IpAddr, now: Instant) {
        const DST_PORT: u16 = 443;

        let Some(&source) = self.sources.get(&target) else {
            return;
        };

        let token = send_syn(self.transport.tx.as_ref(), source, target, DST_PORT);
        self.audit.record_send(token.is_some());

        if let Some(token) = token {
            self.ledger.arm(target, target, token, now);
        }
    }
}
