// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Routed Host Discovery
//!
//! Finds hosts reached through a gateway rather than ones sitting on the local
//! segment. It sends a single raw TCP SYN packet to each target and listens for
//! any reply. A full three-way handshake is never completed, so this works
//! whether or not the target port is open. `port_scan` builds on the same
//! raw-socket machinery to answer a different question: not whether a host is
//! alive, but which of its ports are open.
//!
//! This scanner requires root privileges to open the raw sockets involved.

mod icmp_error;
mod port_scan;
mod udp_scan;

use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};

use crate::config::ProbeTuning;
use crate::model::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::model::host::{HostStatus, StatusProtocol, StatusReason};
use crate::model::ip::set::IpSet;
use crate::model::retry::{Due, ProbeLedger, Resolution, RetryPolicy, SilentHostPolicy};
use crate::model::technique::TcpScanTechnique;
use crate::model::timer::ScanBudget;
use crate::protocols as protocol;
use crate::scanner::session::ScanContext;
use crate::system::interface::RoutedTarget;
use crate::transport::probe::{ProbeKind, ProbeSender, ProbeTransport};
use crate::{error, success};
use async_trait::async_trait;
use pnet::packet::tcp::TcpPacket;
use tokio::sync::mpsc::UnboundedSender;

use crate::scanner::audit::ProbeAudit;
use crate::scanner::payload;
use crate::scanner::report::StopReason;
use crate::scanner::session::ScannerKind;
use crate::scanner::strategy::{HostScanner, StrategyError};

pub use port_scan::TcpPortScanner;
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
/// responded, [`TcpPortScanner`] once nothing is pending). It is spent only
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
/// Three attempts is what a paced sweep needs and what an unpaced one cannot be
/// rescued by. Two is the least that distinguishes a lost packet from a silent
/// one, and the third still earns its place: on a large range it is the
/// attempt that recovers the last few percent.
///
/// The budget is bounded here rather than raised because the loss it would be
/// compensating for is not the kind repetition fixes. Sending faster than a path
/// absorbs costs coverage on every attempt alike, so a scan that answers it with
/// more attempts pays the full budget on every dead address to buy back what
/// [`PROBE_RATE_PER_SEC`] gives away for nothing. On a range with nothing on it,
/// which is the ordinary case, each attempt is the whole range's worth of
/// packets and recovers no host at all.
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
const PROBE_RATE_PER_SEC: u32 = 4_000;

/// The shortest interval the send ticker is asked to keep.
///
/// A tokio interval cannot be relied on much below a millisecond, so a rate
/// faster than one probe per tick is expressed by releasing several per tick
/// rather than by ticking faster. Below that the tick lengthens instead - see
/// [`pacing_for`], where getting this wrong is silent.
const MIN_SEND_TICK: Duration = Duration::from_millis(1);

/// How often to wake and how many probes to release each time, for a sweep
/// paced at `rate_per_sec`.
///
/// The batch is chosen first and the interval derived from it, so the product
/// is the rate that was asked for rather than something near it. Fixing the
/// interval and rounding the batch instead is the obvious way to write this and
/// it is wrong in a way nothing reports: a batch cannot be less than one probe,
/// so every rate below one probe per tick collapses to the same value and a
/// sweep configured for 500 probes a second quietly runs at 1000.
fn pacing_for(rate_per_sec: u32) -> (Duration, usize) {
    let rate = f64::from(rate_per_sec.max(1));
    let batch = (rate * MIN_SEND_TICK.as_secs_f64()).round().max(1.0);

    (Duration::from_secs_f64(batch / rate), batch as usize)
}

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
///
/// `reason` receives the failure when there is one, so a scan whose probes never
/// reached the wire can say why in its report rather than only in a log line. A
/// probe that was never sent and a probe nobody answered are indistinguishable
/// in a host count and could hardly be more different in what they mean.
fn send_syn(
    sender: &dyn ProbeSender,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    dst_port: u16,
    reason: &mut Option<String>,
) -> Option<SynToken> {
    let src_port: u16 = rand::random_range(50_000..u16::MAX);
    let seq_num: u32 = rand::random_range(0..=u32::MAX);

    let packet = match protocol::tcp::create_probe(
        TcpScanTechnique::Syn,
        &src_addr,
        &dst_addr,
        src_port,
        dst_port,
        seq_num,
    ) {
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
            // `{e:#}` rather than `{e}`: the outer message says which probe
            // failed, and the chained cause is the operating system's own
            // explanation - "No route to host" and "Permission denied" call for
            // completely different responses, and the bare wrapper distinguishes
            // neither.
            error!(
                verbosity = 2,
                "Failed to send SYN probe to {dst_addr}:{dst_port}: {e:#}"
            );
            *reason = Some(format!("{e:#}"));
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
///
/// `reason` receives the failure when there is one, exactly as it does for
/// [`send_syn`]. A UDP scan whose probes never left reports every port
/// open-filtered - the same answer a firewall produces - and only this says
/// otherwise.
fn send_udp(
    sender: &dyn ProbeSender,
    src_port: u16,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    dst_port: u16,
    reason: &mut Option<String>,
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
            // `{e:#}` rather than `{e}`, for the reason `send_syn` gives: the
            // chained cause is the operating system's own explanation, and
            // "No route to host" and "Permission denied" call for completely
            // different responses.
            error!(
                verbosity = 2,
                "Failed to send UDP probe to {dst_addr}:{dst_port}: {e:#}"
            );
            *reason = Some(format!("{e:#}"));
            None
        }
    }
}

/// Whether `bytes` is one of the two segments a SYN probe can draw.
///
/// A SYN+ACK and a RST each require the target to have received the probe and
/// answered it, and nothing else a SYN elicits sets either flag. Anything else
/// from the same address is traffic that happens to share a host with the scan.
fn answers_a_syn_probe(bytes: &[u8]) -> bool {
    TcpPacket::new(bytes)
        .and_then(|tcp| protocol::tcp::classify_probe_response(&tcp))
        .is_some()
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
    /// Targets whose first probe has not left yet, released by the send ticker.
    pending: std::vec::IntoIter<IpAddr>,
    /// Targets due for another attempt, released by the same ticker and ahead
    /// of anything in `pending`.
    ///
    /// A retry is an obligation the sweep already owns, where the next unprobed
    /// address is only work it intends to do. Draining them first is also what
    /// keeps the schedule honest: a retry queued behind thousands of first
    /// attempts would be sent long after the moment it was scheduled for.
    retries: VecDeque<IpAddr>,
    /// How often the send ticker fires, and how many probes it releases each
    /// time. Together they are the configured rate; see [`pacing_for`].
    send_tick: Duration,
    batch: usize,
    /// How many distinct addresses have responded so far.
    responded_count: usize,
    /// Per-run counters, so a sweep that finds fewer hosts than it should can be
    /// attributed to loss, to its own deadline, or to correlation rather than
    /// guessed at. Reported once when the loop exits.
    audit: ProbeAudit,
    /// Why the first probe that could not be sent failed, if any did.
    ///
    /// Kept so the reason survives into the report. The count of failed sends is
    /// already in the audit, but a count cannot distinguish a host with no route
    /// to the target from one refusing raw sockets, and those call for opposite
    /// responses from whoever is reading.
    send_failure: Option<String>,
}

#[async_trait]
impl HostScanner for RoutedScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::Routed
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
            self.service_retries(now);

            let all_responded = self.ips.len() == self.responded_count as u128;
            if self.ctx.handle.should_stop() {
                break StopReason::Aborted;
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
            if self.nothing_left_to_send() && self.ledger.is_empty() {
                break StopReason::AttemptsSpent;
            }
            if self.deadline.hard_deadline_passed() {
                break StopReason::DeadlineExpired;
            }

            let sending = !self.nothing_left_to_send();
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

        // A sweep whose probes never left is not a sweep that found nothing, and
        // the difference is invisible in every number a caller reads: the host
        // count is zero either way, no strategy errored, and the audit line that
        // does say so is a log at verbosity 1. So it is recorded as a failure,
        // which is the one channel a library consumer sees without opting in.
        //
        // Reported once with the first cause rather than once per probe. Sixteen
        // identical "no route to host" lines say nothing the first does not, and
        // a sweep of a large range would bury everything else in the report.
        if self.audit.sends_failed > 0 {
            self.ctx.record_failure(
                ScannerKind::Routed,
                format!(
                    "{} of {} probes could not be sent: {}",
                    self.audit.sends_failed,
                    self.audit.sends_attempted,
                    self.send_failure.as_deref().unwrap_or("cause unrecorded"),
                ),
            );
        }

        // Read before the transport is dropped, since the counters live with
        // the capture threads it keeps alive.
        let capture = self.transport.capture_counts();
        let targets = self.ips.len();
        self.audit
            .report("routed-discovery", targets, reason, capture);
        self.ctx.record_probe_stats(self.audit.stats(
            ScannerKind::Routed,
            targets,
            reason,
            capture,
        ));
        Ok(())
    }
}

impl RoutedScanner {
    pub fn new(
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        tuning: ProbeTuning,
    ) -> Result<Self, StrategyError> {
        let transport = ProbeTransport::open_with(ProbeKind::TcpSyn, tuning.send_mode)?;
        Ok(Self::build(
            targets,
            ctx,
            dns_tx,
            transport,
            RETRY_POLICY.configured(tuning.retry),
            tuning.max_probe_rate.unwrap_or(PROBE_RATE_PER_SEC).max(1),
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
        Self::build(
            targets,
            ctx,
            dns_tx,
            transport,
            RETRY_POLICY,
            PROBE_RATE_PER_SEC,
        )
    }

    /// The common constructor, taking the retry schedule and the send rate as
    /// arguments because the sweep's own deadline is derived from both and so
    /// has to be settled before anything is built.
    fn build(
        targets: Vec<RoutedTarget>,
        ctx: ScanContext,
        dns_tx: Option<UnboundedSender<IpAddr>>,
        transport: ProbeTransport,
        retry: RetryPolicy,
        rate_per_sec: u32,
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

        // The sweep has to outlive both of the limits it sets itself: its own
        // retry schedule, or probes are given up on having never been fully
        // asked, and its own send rate, or the sweep is cut off mid-send. The
        // second fails invisibly - an address never probed is indistinguishable
        // from one with nothing on it - which is why it is derived here rather
        // than left to a constant that has to be remembered.
        let (send_tick, batch) = pacing_for(rate_per_sec);
        let send_duration = Duration::from_secs_f64(target_count as f64 / f64::from(rate_per_sec));
        let deadline_config =
            DEADLINE_CONFIG.allowing_for(retry.worst_case_probe_lifetime() + send_duration);

        Self {
            ctx,
            sources,
            ips,
            transport,
            deadline: AdaptiveDeadline::new(deadline_config, target_count),
            dns_tx,
            ledger: ProbeLedger::new(retry, target_count),
            due: Vec::new(),
            pending: order.into_iter(),
            retries: VecDeque::new(),
            send_tick,
            batch,
            responded_count: 0,
            audit: ProbeAudit::new(),
            send_failure: None,
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

        // Not every TCP segment from a probed address answers a probe, and over
        // IPv6 the kernel no longer guarantees otherwise: `tcp[tcpflags]` does
        // not compile for that family, so the transport admits established
        // traffic too and the narrowing has to happen here.
        //
        // Checking it is what keeps the two families held to one standard. The
        // IPv4 half has only ever seen SYN+ACK and RST because the filter
        // dropped the rest; without the same test, an ACK from an IPv6 host the
        // user happens to be connected to would credit a discovery this scan did
        // not make, on evidence the IPv4 path has never accepted.
        if !answers_a_syn_probe(bytes) {
            self.audit.record_off_target();
            return;
        }

        let resolution = self.resolve_probe(ip, bytes, now);
        let rtt = resolution.and_then(|resolution| resolution.rtt);
        if rtt.is_none() {
            self.audit.record_reply_without_rtt();
        }

        // Host mutation only; the guard is dropped and the event emitted inside
        // `write_host`, so the deadline and DNS follow-ups below never run under
        // the store lock.
        let is_new = self.ctx.write_host(ip, |host| {
            // A TCP segment from a probed address is proof of a live stack
            // whichever flags it carries: a SYN+ACK and a RST both require the
            // host to have received the probe and answered it. Discovery already
            // treats either as an answer; this records what the answer proved.
            let was_up = host.status().is_up();
            host.record_evidence(
                HostStatus::Up,
                StatusReason::new(StatusProtocol::TcpSyn, "tcp reply to a discovery probe"),
            );

            if let Some(rtt) = rtt {
                host.add_rtt(rtt);
                return true;
            }
            !was_up
        });

        if is_new {
            self.responded_count += 1;
            self.audit
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
        let token = TcpPacket::new(bytes).map(|tcp| SynToken {
            seq: protocol::tcp::echoed_nonce(TcpScanTechnique::Syn, &tcp),
            src_port: tcp.get_destination(),
        });

        token
            .and_then(|token| self.ledger.resolve(&ip, Some(token), now))
            .or_else(|| self.ledger.resolve(&ip, None, now))
    }

    /// Queues every probe that has gone unanswered long enough.
    ///
    /// Queued rather than sent, so a retry leaves through the same paced ticker
    /// a first attempt does. Sending them here would put the whole of one
    /// attempt on the wire in a single iteration - which is the burst this
    /// scanner exists to avoid, arriving one round later.
    ///
    /// A probe that runs out of attempts needs nothing recorded: a host that
    /// never answered is simply one this sweep does not report, and the ledger
    /// emptying is what tells the loop the sweep is finished.
    fn service_retries(&mut self, now: Instant) {
        self.ledger.drain_due(now, &mut self.due);

        for event in self.due.drain(..) {
            if let Due::Retry { key, .. } = event {
                self.retries.push_back(key);
            }
        }
    }

    /// Whether every probe this sweep intends to send has left.
    fn nothing_left_to_send(&self) -> bool {
        self.retries.is_empty() && self.pending.len() == 0
    }

    /// Releases one tick's worth of probes: retries first, then targets not yet
    /// asked.
    fn send_allowance(&mut self, now: Instant) {
        for _ in 0..self.batch {
            let target = match self.retries.pop_front() {
                Some(target) => target,
                None => match self.pending.next() {
                    Some(target) => target,
                    None => return,
                },
            };
            self.probe(target, now);
        }
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

        let token = send_syn(
            self.transport.tx.as_ref(),
            source,
            target,
            DST_PORT,
            &mut self.send_failure,
        );
        self.audit.record_send(token.is_some());

        if let Some(token) = token {
            self.ledger.arm(target, target, token, now);
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

    /// The rate a sweep actually paces itself at, which is what the pair has
    /// to reproduce however it is split between the two.
    fn effective_rate(rate_per_sec: u32) -> f64 {
        let (tick, batch) = pacing_for(rate_per_sec);
        batch as f64 / tick.as_secs_f64()
    }

    #[test]
    fn a_fast_rate_is_expressed_as_a_batch_on_the_shortest_tick() {
        assert_eq!(pacing_for(2_000), (MIN_SEND_TICK, 2));
        assert_eq!(pacing_for(100_000), (MIN_SEND_TICK, 100));
    }

    /// The failure this pair exists to prevent. A batch cannot be less than one
    /// probe, so holding the tick fixed collapses every rate below one probe
    /// per tick onto the same value - and a sweep asked for 500 a second runs
    /// at 1000 without saying so.
    #[test]
    fn a_slow_rate_lengthens_the_tick_rather_than_doubling_the_rate() {
        assert_eq!(pacing_for(500), (Duration::from_millis(2), 1));
        assert_eq!(pacing_for(100), (Duration::from_millis(10), 1));
    }

    #[test]
    fn every_rate_is_paced_at_the_rate_it_asked_for() {
        for rate in [1, 100, 500, 999, 1_000, 1_500, 2_000, 4_000, 16_000] {
            let effective = effective_rate(rate);
            let error = (effective - f64::from(rate)).abs() / f64::from(rate);
            assert!(
                error < 0.01,
                "{rate}/s is paced at {effective}/s, off by {:.0}%",
                error * 100.0
            );
        }
    }

    /// A rate of zero is a caller error, not an instruction to stall forever.
    #[test]
    fn a_zero_rate_still_sends() {
        let (tick, batch) = pacing_for(0);
        assert_eq!(batch, 1);
        assert!(tick <= Duration::from_secs(1));
    }
}
