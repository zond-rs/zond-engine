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
//! segment. One raw TCP SYN per target, and anything that comes back credits
//! the host: the handshake is never completed, so an address answers whether or
//! not the port it was asked about is open.
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
use crate::model::technique::{TcpReply, TcpScanTechnique};
use crate::protocols as protocol;
use crate::scanner::pacing::deadline::AdaptiveDeadline;
use crate::scanner::pacing::retry::{ProbeLedger, Resolution, RetryPolicy};
use crate::scanner::session::ScanContext;
use crate::system::interface::RoutedTarget;
use crate::transport::probe::{Emission, ProbeKind, ProbeTransport};
use async_trait::async_trait;
use tokio::sync::mpsc::UnboundedSender;

use crate::report::ScannerKind;
use crate::report::StopReason;
use crate::scanner::strategy::raw::{
    DEADLINE_CONFIG, EvasionParts, RETRY_POLICY, SendFaults, SynToken, pacing_for, rate_or,
    send_syn,
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
/// **A challenge ACK is deliberately excluded, though it is a genuine answer.**
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

/// Checks whether addresses behind a gateway are alive, putting one raw TCP SYN
/// to each and crediting whatever comes back.
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
    /// The source port every probe leaves from, when a caller pinned one.
    ///
    /// `None` is the default and keeps this sweep's own behaviour: a fresh
    /// random high port per probe, which together with a fresh sequence number
    /// is what lets a reply name the attempt it answers. An evasion profile that
    /// set a source port replaces that with the one port, the sequence number
    /// still varies per attempt, so a reply is still attributable, so a probe
    /// can leave from a port a filter is known to trust.
    src_port: Option<u16>,
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
    sweep: HostSweep<SynToken>,
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
            // A sweep settles: it was asked whether an address is there and
            // has now asked as many times as the policy allows.
            self.sweep.service_retries(&self.ctx, now, true);

            let all_responded = self.sweep.all_responded(self.ips.len());
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

        // What the sweep did not earn a verdict for, so a resumed one asks again
        // rather than skipping it. None of these carries a position: a probe
        // still mid-schedule was cut off rather than spent, one still queued was
        // never sent, and one with no route was never asked.
        let outstanding = self.sweep.ledger.drain_unresolved().len() as u64;
        self.ctx
            .record_many_outcomes(Outcome::Interrupted, outstanding);
        self.ctx
            .record_many_outcomes(Outcome::Unasked, self.pending.len() as u64);
        // Distinct addresses rather than failed sends: a target with no route
        // fails on every retry, and counting each of those would report more
        // unreached addresses than the sweep had.
        self.ctx
            .record_many_outcomes(Outcome::Unroutable, self.faults.addresses.len() as u64);

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
        // address is not reachable from here. Recorded as a failure it made
        // every scan of a dual-stack name on an IPv4-only network report itself
        // as partial, which is the surest way to teach a reader to ignore the
        // warning that matters. It is recorded against the address instead, just
        // below.
        if let Some(reason) = &self.faults.broken {
            let broken = self.sweep.audit.sends_failed - self.faults.unroutable_count;
            self.ctx.record_failure(
                ScannerKind::Routed,
                format!(
                    "{broken} of {} probes could not be sent: {reason}",
                    self.sweep.audit.sends_attempted,
                ),
            );
        }

        // Said once, at the level a person watching a scan sees: an address they
        // named was not covered, and nothing else in the output would tell them
        // so. Nothing is wrong with the scan, so it carries neither an error
        // prefix nor the operating system's errno, that is a diagnostic detail
        // and it is on the `-v` line beside the send that failed.
        //
        // The address and nothing else. That it went unscanned follows from
        // there being no route to it, and saying so out loud is a line of
        // output that tells a reader what they have just read.
        for address in &self.faults.addresses {
            self.ctx.record_unroutable(*address);
        }

        if let Some((address, _)) = &self.faults.unroutable {
            match self.faults.unroutable_count.saturating_sub(1) {
                0 => info!("no route to {address}"),
                1 => info!("no route to {address} and 1 other address"),
                more => info!("no route to {address} and {more} other addresses"),
            }
        }

        // Read before the transport is dropped, since the counters live with
        // the capture threads it keeps alive.
        let capture = self.transport.capture_counts();
        let targets = self.ips.len();
        self.sweep.report(
            &self.ctx,
            "routed-discovery",
            ScannerKind::Routed,
            targets,
            reason,
            capture,
        );
        Ok(())
    }
}

impl RoutedScanner {
    /// A sweep of `targets`, each already paired with the source address to
    /// probe it from, over a transport this constructor opens.
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
        let transport = ProbeTransport::open_with(
            ProbeKind::TcpSyn,
            tuning.evasion.effective_send_mode(tuning.send_mode),
        )?;
        Ok(Self::build(
            targets,
            ctx,
            dns_tx,
            transport,
            tuning.evasion.source_port,
            tuning.evasion.emission(),
            tuning.evasion.segment_shaping(),
            tuning.evasion.decoys.clone(),
            RETRY_POLICY.configured(tuning.retry),
            rate_or(tuning.max_probe_rate, PROBE_RATE_PER_SEC),
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
            None,
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
        src_port: Option<u16>,
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

        // The sweep has to outlive both of the limits it sets itself: its own
        // retry schedule, or probes are given up on having never been fully
        // asked, and its own send rate, or the sweep is cut off mid-send. The
        // second fails invisibly - an address never probed is indistinguishable
        // from one with nothing on it - which is why it is derived here rather
        // than left to a constant that has to be remembered.
        let (send_tick, batch) = pacing_for(rate_per_sec);
        let send_duration =
            Duration::from_secs_f64(target_count as f64 / f64::from(rate_per_sec.get()));
        let deadline_config =
            DEADLINE_CONFIG.allowing_for(retry.worst_case_probe_lifetime() + send_duration);

        Self {
            ctx,
            sources,
            ips,
            transport,
            src_port,
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

    /// Records a raw TCP reply from `ip` as evidence the host is alive,
    /// crediting it with a round-trip time if the reply's acknowledgement
    /// number matches an outstanding probe.
    fn handle_discovery_reply(&mut self, ip: IpAddr, bytes: &[u8], now: Instant) {
        if !self.ips.contains(&ip) {
            self.sweep.audit.record_off_target();
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
            self.sweep.audit.record_off_target();
            return;
        }

        // The address answered, which is a verdict however the reply was timed.
        self.ctx.settle_address(ip, Settled::Answered);

        let resolution = self.resolve_probe(ip, bytes, now);
        let rtt = resolution.and_then(|resolution| resolution.rtt);
        if rtt.is_none() {
            self.sweep.audit.record_reply_without_rtt();
        }

        // Host mutation only; the guard is dropped and the event emitted inside
        // `write_host`, so the deadline and DNS follow-ups below never run under
        // the store lock.
        // Evidence goes in whatever this sweep has seen before; the return
        // value is deliberately ignored, because it reports store novelty and
        // the decisions below are about *this sweep's* first sighting.
        self.ctx.write_host(ip, |host| {
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
        let token = protocol::tcp::parse(bytes).ok().map(|tcp| SynToken {
            seq: protocol::tcp::echoed_nonce(
                TcpScanTechnique::Syn,
                &tcp,
                self.shaping.padding.unwrap_or(0),
            ),
            src_port: tcp.destination_port(),
        });

        token
            .and_then(|token| self.sweep.ledger.resolve(&ip, Some(token), now))
            .or_else(|| self.sweep.ledger.resolve(&ip, None, now))
    }

    /// Whether every probe this sweep intends to send has left.
    fn nothing_left_to_send(&self) -> bool {
        self.sweep.retries.is_empty() && self.pending.len() == 0
    }

    /// Releases one tick's worth of probes: retries first, then targets not yet
    /// asked.
    fn send_allowance(&mut self, now: Instant) {
        for _ in 0..self.batch {
            let target = match self.sweep.retries.pop_front() {
                Some(target) => target,
                None => match self.pending.next() {
                    Some(target) => target,
                    None => return,
                },
            };
            self.probe(target, now);
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
            self.src_port,
            EvasionParts {
                emission: self.emission,
                shaping: self.shaping,
                decoys: &self.decoys,
            },
            &mut self.faults,
        );
        self.sweep.audit.record_send(token.is_some());

        if let Some(token) = token {
            self.sweep.ledger.arm(target, target, token, (), now);
        }
    }
}
