// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The active operating-system echo probe
//!
//! One ICMP echo request per host, sent where the passive sources concluded
//! nothing, and read for what the reply says about the sending stack.
//!
//! Passive identification needs a host that answered something. A stock Windows
//! firewall *drops* unsolicited TCP, so a desktop with no service exposed emits
//! nothing a TCP rule could read (measured on two independent installations).
//! Many such machines still answer a ping, and the reply (a hop counter of 128,
//! the request's code echoed or zeroed) is a property of the same stack. This is
//! the only route to those hosts, under
//! [`OsDetection::Active`](crate::config::OsDetection).
//!
//! The request carries a non-zero
//! [`ECHO_PROBE_CODE`](crate::protocols::icmp::ECHO_PROBE_CODE), because stacks
//! disagree on whether to echo it or write zero. The identifier marks the scan's
//! replies (filtered in userspace; no kernel filter can express it), and the
//! sequence names the attempt, so a round trip is timed against its own send.
//!
//! An echo reply carries no options, window or sequence number, and an initial
//! hop counter of 64 names nothing, since Linux, macOS and the BSDs all start
//! there. The rule corpus is authored under that constraint, and
//! [`classify`](crate::fingerprint::os) reports nothing when no rule fits.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use pnet_packet::ip::IpNextHeaderProtocols;

use crate::config::ProbeTuning;
use crate::fingerprint::os;
use crate::logging::error;
use crate::model::host::{HostStatus, StatusProtocol, StatusReason};
use crate::protocols::icmp;
use crate::report::ScannerKind;
use crate::report::StopReason;
use crate::scanner::pacing::deadline::HeldAllowance;
use crate::scanner::pacing::retry::{ProbeLedger, RetryPolicy};
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::StrategyError;
use crate::scanner::strategy::raw::SendFaults;
use crate::scanner::strategy::raw::neighbors::{Admission, NEIGHBOR_BUDGET, NeighborGates};
use crate::scanner::strategy::sweep::HostSweep;
use crate::system::interface::SourceResolver;
use crate::transport::capture::CapturedSegment;
use crate::transport::probe::{Emission, ProbeKind, ProbeTransport};
use crate::{info, success};

/// The payload every echo request carries, so a reply can be checked against
/// what was sent.
const PAYLOAD: &[u8] = b"zond-os-probe";

/// How an echo is retransmitted.
///
/// Two attempts: this phase runs only where the caller opted in, over hosts the
/// passive sources found thin, and a third attempt rarely draws a ping reply.
const RETRY_POLICY: RetryPolicy = RetryPolicy::new(
    2,
    Duration::from_millis(200),
    Duration::from_millis(25),
    Duration::from_secs(2),
    2.0,
    0.2,
    None,
);

/// How fast echoes leave the wire: one per millisecond, far slower than the port
/// scanners, since this phase covers few hosts.
const SEND_TICK: Duration = Duration::from_millis(1);

/// Patience after the last probe resolves or exhausts, so a reply from a slow
/// path still lands before the phase closes.
const QUIET_FLOOR: Duration = Duration::from_secs(1);

/// This host's own milliseconds since midnight UT, which is the scale RFC 792
/// puts a timestamp on.
///
/// The reference an offset is measured against. Read when a reply is folded,
/// so it includes the return path; see
/// [`TimestampReply::offset_from`](crate::protocols::icmp::TimestampReply::offset_from)
/// for why a millisecond or two does not matter.
///
/// Zero where the clock is before the Unix epoch, so the offset is plainly
/// wrong, not plausible.
fn local_millis_since_midnight() -> u32 {
    const MILLIS_PER_DAY: u128 = 86_400_000;
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| (since.as_millis() % MILLIS_PER_DAY) as u32)
        .unwrap_or(0)
}

/// Sends one ICMP echo per host where passive evidence named nothing, and files
/// what the replies say.
///
/// The caller chooses targets from the host store once the passive sources have
/// finished.
pub struct OsEchoScanner {
    ctx: ScanContext,
    transport: ProbeTransport,
    /// The IP-header state every echo carries. An evasion profile contributes
    /// only its hop limit, since reshaping the echo would change the reply read.
    /// See
    /// [`EvasionProfile::hop_limited_emission`](crate::evasion::EvasionProfile::hop_limited_emission).
    emission: Emission,
    resolver: SourceResolver,
    /// The identifier every request carries, separating this scan's replies from
    /// every other ping on the host.
    identifier: u16,
    /// How many requests have left, which is also the next sequence number.
    next_sequence: u16,
    /// Targets not yet asked.
    pending: VecDeque<IpAddr>,
    /// How far this pass has read the resolution of each target's neighbour,
    /// so no send waits on one or is lost behind it. See [`NeighborGates`].
    neighbors: NeighborGates,
    /// The outstanding probes, the retry queue and the run's counters, shared
    /// with the two discovery sweeps. The ledger carries each attempt's
    /// sequence, so a round trip is measured against the send it answers.
    sweep: HostSweep<u16>,
    /// Which host each sequence went to, since a reply names its attempt, not
    /// its target.
    by_sequence: HashMap<u16, IpAddr>,
    /// The hard ceiling on this run: every attempt at the retry ceiling (or the
    /// per-host gap where longer), plus the longest a first attempt can be held
    /// while its neighbour is resolved.
    deadline: Instant,
    /// How much hold-down time the deadline has already been extended by.
    held_allowed: HeldAllowance,
    /// Why requests did not leave: this host's send path, or an address nothing
    /// reaches from here; and the targets held through the kernel's hold-down on
    /// their neighbour.
    faults: SendFaults,
}

/// What became of one attempt's request.
enum Attempt {
    /// It left, under this sequence.
    Sent(u16),
    /// The kernel refused it for a hold-down on the target's neighbour, and
    /// the target is held through it; see [`SendFaults::hold`].
    Held,
    /// It did not leave.
    Unsent,
}

impl OsEchoScanner {
    /// Opens the ICMP transport and takes the targets to ask. Fails where the
    /// raw socket cannot be had, telling the caller this level of detection is
    /// unavailable.
    pub fn new(
        ctx: ScanContext,
        targets: Vec<IpAddr>,
        tuning: ProbeTuning,
    ) -> Result<Self, StrategyError> {
        let identifier = rand::random();
        let transport = ProbeTransport::open_capturing(
            ProbeKind::IcmpEcho { identifier },
            tuning.send_mode,
            &ctx.capture_links(),
        )?;
        Ok(Self::with_identifier(
            ctx,
            targets,
            transport,
            identifier,
            tuning.evasion.hop_limited_emission(),
        ))
    }

    /// Builds the scanner around a transport the caller opened, for tests and
    /// custom orchestration. The identifier is drawn here.
    pub fn with_transport(
        ctx: ScanContext,
        targets: Vec<IpAddr>,
        transport: ProbeTransport,
    ) -> Self {
        Self::with_identifier(ctx, targets, transport, rand::random(), Emission::routed())
    }

    fn with_identifier(
        ctx: ScanContext,
        targets: Vec<IpAddr>,
        transport: ProbeTransport,
        identifier: u16,
        emission: Emission,
    ) -> Self {
        // Where a scan-wide gap is slower than the tick, it sets how long
        // sending takes.
        let spaced = ctx
            .scan_probe_interval()
            .unwrap_or_default()
            .saturating_mul(
                (targets.len() as u32).saturating_mul(u32::from(RETRY_POLICY.max_attempts)),
            );
        let send_duration = SEND_TICK.saturating_mul(targets.len() as u32).max(spaced);
        let target_count = targets.len();
        let probe_lifetime = RETRY_POLICY.longest_spaced_probe_lifetime(ctx.probe_gap());
        let held = if transport.neighbors().is_some() {
            NEIGHBOR_BUDGET
        } else {
            Duration::ZERO
        };

        // Seeded from what earlier phases measured, as the port scans'
        // `seed_timing` is: from first principles, a host behind a path slower
        // than the first timeout has every attempt given up on.
        let mut ledger = ProbeLedger::new(RETRY_POLICY, 256);
        let wanted: std::collections::HashSet<IpAddr> = targets.iter().copied().collect();
        for host in ctx.store.iter() {
            let address = host.key().addr();
            if !wanted.contains(&address) {
                continue;
            }
            ledger.seed_host(address, host.value().telemetry());
        }

        Self {
            ctx,
            transport,
            emission,
            resolver: SourceResolver::from_system(),
            identifier,
            next_sequence: 0,
            pending: targets.into(),
            neighbors: NeighborGates::default(),
            sweep: HostSweep::new(ledger),
            by_sequence: HashMap::with_capacity(target_count),
            deadline: Instant::now() + held + probe_lifetime + send_duration + QUIET_FLOOR,
            held_allowed: HeldAllowance::default(),
            faults: SendFaults::default(),
        }
    }

    /// Releases one probe: a retry first, then a target not yet asked.
    ///
    /// Retries go first so they leave near their scheduled moment.
    fn send_one(&mut self, now: Instant) {
        // Either queue may be turned away by the per-host gap; this pass
        // revisits addresses already probed. The gap spaces the echo and
        // timestamp *pair*, which travel back to back (see `send_timestamp` and
        // `ZondConfig::host_probe_interval`).
        //
        // A queued retry's clock is stopped (see `HostSweep::retries`); one
        // answered meanwhile is dropped unsent.
        self.sweep
            .retries
            .retain(|target| self.sweep.ledger.contains(target));
        let (target, retry) = match self.take_ready(true, now) {
            Some(target) => (target, true),
            None => match self.take_ready(false, now) {
                Some(target) => (target, false),
                None => return,
            },
        };
        // Claimed last, so a target held for its neighbour spends no slot.
        // Fails only where another pass took the slot since the target was
        // chosen.
        let Ok(claim) = self.ctx.claim_probe(target) else {
            self.queue(retry).push_back(target);
            return;
        };
        let sent = self.send_pair(target, now);
        // A pair that got nowhere gives its slot back (see `record_send`). Only
        // the echo counts: the timestamp is IPv4-only, and the refund should
        // not depend on the address family.
        if !matches!(sent, Attempt::Sent(_)) {
            self.ctx.refund_probe(claim);
        }
        // A retry restarts its clock: from the send, or from now if it did not
        // leave, with the attempt still charged so an unroutable target
        // exhausts on schedule. One held for a hold-down goes back to its queue,
        // clock still stopped.
        match sent {
            Attempt::Sent(sequence) if retry => {
                self.sweep.ledger.rearm(target, target, sequence, now);
            }
            Attempt::Sent(sequence) => self.sweep.ledger.arm(target, target, sequence, (), now),
            Attempt::Held => self.queue(retry).push_back(target),
            Attempt::Unsent if retry => self.sweep.ledger.resume(&target, now),
            Attempt::Unsent => {}
        }
    }

    /// The first address in the retry queue, or with `retries` false the
    /// queue of targets not yet asked, whose host may be probed now, rotating
    /// past the ones that may not.
    ///
    /// Three things send a target to the back of the queue: the per-host gap, a
    /// neighbour still being resolved (see [`NeighborGates::admit`]), and a
    /// kernel hold-down (see [`SendFaults::hold`]). A target whose neighbour
    /// never answered is taken out and filed unreached, with nothing sent.
    ///
    /// The walk is bounded by the queue's length at entry and does not stop at
    /// the first held target, so every new neighbour in the queue is asked for
    /// in one call and a wave of them costs one wait.
    fn take_ready(&mut self, retries: bool, now: Instant) -> Option<IpAddr> {
        let waiting = self.queue(retries).len();
        for _ in 0..waiting {
            let candidate = self.queue(retries).pop_front()?;
            if self.ctx.probe_ready_at(candidate, now).is_some()
                || self.faults.held_until(candidate, now).is_some()
            {
                self.queue(retries).push_back(candidate);
                continue;
            }
            let watch = self.transport.neighbors();
            match self
                .neighbors
                .admit(watch, &mut self.resolver, candidate, now)
            {
                Admission::Send => return Some(candidate),
                Admission::Hold(_) => self.queue(retries).push_back(candidate),
                Admission::Unreachable => self.unreached(candidate, retries, now),
            }
        }
        None
    }

    /// The retry queue, or with `retries` false the targets not yet asked.
    fn queue(&mut self, retries: bool) -> &mut VecDeque<IpAddr> {
        if retries {
            &mut self.sweep.retries
        } else {
            &mut self.pending
        }
    }

    /// Files `target` as an address nothing reaches: its neighbour did not
    /// answer or never resolved, so nothing was sent. A retry's clock restarts
    /// from now, the attempt still charged, so it runs out on schedule.
    fn unreached(&mut self, target: IpAddr, retry: bool, now: Instant) {
        let why = self.neighbors.refusal(target);
        if self.faults.unroutable.is_none() {
            info!(verbosity = 2, "{target} unreachable ({why})");
        }
        self.faults.record_unreached(target, why);
        if retry {
            self.sweep.ledger.resume(&target, now);
        }
    }

    /// Sends the echo, and for an IPv4 target the timestamp, that make up one
    /// attempt at `target`, and says what became of the echo.
    fn send_pair(&mut self, target: IpAddr, now: Instant) -> Attempt {
        let Some(source) = self.resolver.resolve(target) else {
            return Attempt::Unsent;
        };

        let sequence = self.next_sequence;
        let message = match icmp::build_echo_request_message(
            source,
            target,
            icmp::ECHO_PROBE_CODE,
            self.identifier,
            sequence,
            PAYLOAD,
        ) {
            Ok(message) => message,
            Err(e) => {
                error!(verbosity = 2, "cannot build an echo for {target}: {e}");
                self.sweep.audit.record_send(false);
                return Attempt::Unsent;
            }
        };

        let sent = match self
            .transport
            .tx
            .send(&message, source, target, None, self.emission)
        {
            Ok(()) => {
                success!(verbosity = 2, "sent OS echo probe to {target}");
                true
            }
            Err(e) => {
                // A hold-down on the neighbour: nothing was sent and the target
                // is asked again after it. The deadline is extended once for
                // overlapping holds.
                if let Some(until) = self.faults.hold(target, &e) {
                    self.deadline += self.held_allowed.take(now, until);
                    return Attempt::Held;
                }
                // Unroutable is the address's fact; only this host's own
                // refusals are the pass failing. Each said once. See `SendFaults`.
                if e.is_unroutable() {
                    if self.faults.unroutable.is_none() {
                        info!(verbosity = 2, "{target} unreachable ({e:#})");
                    }
                } else if self.faults.broken.is_none() {
                    error!(
                        verbosity = 2,
                        "failed to send OS echo probe to {target}: {e:#}"
                    );
                }
                self.faults.record(target, &e);
                false
            }
        };
        self.sweep.audit.record_send(sent);
        if sent {
            self.next_sequence = self.next_sequence.wrapping_add(1);
            self.by_sequence.insert(sequence, target);
        }

        self.send_timestamp(source, target);

        if sent {
            Attempt::Sent(sequence)
        } else {
            Attempt::Unsent
        }
    }

    /// Asks the same target what time it thinks it is, where the family has a
    /// message for the question.
    ///
    /// A second packet per IPv4 target. Filters written against ping often pass
    /// type 13, so a host silent to the echo may answer this, and the reply
    /// carries the target's own clock, which no other probe here obtains.
    ///
    /// IPv4 only: RFC 4443 defines no timestamp message.
    ///
    /// The ledger is not armed a second time. It already holds the echo's
    /// attempt under the target; a timestamp reply resolves that entry without
    /// claiming a round trip, since it would be timed against the echo's send.
    fn send_timestamp(&mut self, source: IpAddr, target: IpAddr) {
        if !target.is_ipv4() {
            return;
        }

        let sequence = self.next_sequence;
        let message = icmp::build_timestamp_request(self.identifier, sequence);

        match self
            .transport
            .tx
            .send(&message, source, target, None, self.emission)
        {
            Ok(()) => {
                success!(verbosity = 2, "sent OS timestamp probe to {target}");
                self.next_sequence = self.next_sequence.wrapping_add(1);
                self.by_sequence.insert(sequence, target);
            }
            Err(e) => {
                // Not counted as a send failure: the pass is counted in echoes.
                // Not logged when unroutable, since the echo already said so.
                if !e.is_unroutable() {
                    error!(
                        verbosity = 2,
                        "failed to send OS timestamp probe to {target}: {e:#}"
                    );
                }
            }
        }
    }

    /// Reads one captured message: ours or not, and if ours, what it proved.
    fn handle_reply(&mut self, reply: CapturedSegment, now: Instant) {
        if reply.protocol != IpNextHeaderProtocols::Icmp.0
            && reply.protocol != IpNextHeaderProtocols::Icmpv6.0
        {
            self.sweep.audit.record_off_target();
            return;
        }
        // The ICMP numbering family comes from the source address.
        let over_ipv6 = reply.source.is_ipv6();
        let sequence = match icmp::classify_echo_reply(&reply.bytes, self.identifier, over_ipv6) {
            icmp::EchoReply::Ours { sequence } => sequence,
            // Not an echo reply; it may answer the timestamp sent beside it.
            icmp::EchoReply::Other { .. } if !over_ipv6 => {
                return self.handle_timestamp_reply(reply, now);
            }
            // Every other ping on the host lands here; no kernel filter can
            // express the identifier.
            _ => {
                self.sweep.audit.record_off_target();
                return;
            }
        };
        let Some(&target) = self.by_sequence.get(&sequence) else {
            self.sweep.audit.record_off_target();
            return;
        };

        let resolution = self.sweep.ledger.resolve(&target, Some(sequence), now);
        if resolution.is_none() {
            // A duplicate, or an answer to a probe already written off.
            self.sweep.audit.record_reply_without_rtt();
            return;
        }
        let rtt = resolution.and_then(|r| r.rtt);
        self.sweep
            .audit
            .record_host_found(resolution.and_then(|r| r.answered_attempt));

        self.ctx.write_host(target, |host| {
            let was_up = host.status().is_up();
            host.record_evidence(
                HostStatus::Up,
                StatusReason::new(StatusProtocol::IcmpEcho, "echo reply to an OS probe"),
            );
            if let Some(rtt) = rtt {
                host.add_rtt_from(rtt, StatusProtocol::IcmpEcho);
            }
            !was_up
        });

        self.identify(target, &reply);
    }

    /// Reads one ICMP message as an answer to the timestamp probe.
    ///
    /// The host is recorded as up and its clock offset noted. No round trip is
    /// credited, since the ledger timed the echo.
    fn handle_timestamp_reply(&mut self, reply: CapturedSegment, now: Instant) {
        let icmp::TimestampAnswer::Ours {
            sequence,
            reply: readings,
        } = icmp::classify_timestamp_reply(&reply.bytes, self.identifier)
        else {
            self.sweep.audit.record_off_target();
            return;
        };
        let Some(&target) = self.by_sequence.get(&sequence) else {
            self.sweep.audit.record_off_target();
            return;
        };

        // No token, so the entry retires without crediting a round trip.
        let resolution = self.sweep.ledger.resolve(&target, None, now);
        if resolution.is_none() {
            // The echo already answered, or the probe was written off; the
            // clock is still worth recording.
            self.sweep.audit.record_reply_without_rtt();
        } else {
            self.sweep.audit.record_host_found(None);
        }

        let detail = match readings.offset_from(local_millis_since_midnight()) {
            Some(offset) => format!("timestamp reply to an OS probe, clock {offset} ms from ours"),
            // Still an answer, from a host a ping may not reach.
            None => {
                "timestamp reply to an OS probe, on a clock that is not a time of day".to_string()
            }
        };

        self.ctx.write_host(target, |host| {
            let was_up = host.status().is_up();
            host.record_evidence(
                HostStatus::Up,
                StatusReason::new(StatusProtocol::IcmpTimestamp, detail),
            );
            !was_up
        });
    }

    /// Reads the operating system off the reply that just resolved, and folds
    /// it into whatever the host already carries.
    ///
    /// A whole reply is one item of evidence, combined with the host's other
    /// sources through [`os::resolve`] and merged by accuracy.
    fn identify(&self, target: IpAddr, reply: &CapturedSegment) {
        // `None` means no IP header was kept (a synthetic receive stream).
        let Some(observation) = reply.observation else {
            return;
        };
        let Some(observed) =
            os::EchoObservation::from_echo_reply(observation, &reply.bytes, PAYLOAD)
        else {
            return;
        };
        let Some(verdict) = os::classify(os::RuleDb::global(), &observed.into()) else {
            return;
        };

        self.ctx.update_host(target, |host| {
            os::identify(host, [verdict.as_evidence()]);
        });
    }

    /// Reads every reply already waiting in the capture stream, without
    /// waiting for more, bounded by what is queued on entry.
    ///
    /// A loop held up past a timeout wakes to the answer and the expired timer
    /// at once; replies must be read first, or the last attempt is written off
    /// and its answer dropped.
    fn read_waiting_replies(&mut self) {
        let waiting = self.transport.rx.len();
        for _ in 0..waiting {
            let Ok(reply) = self.transport.rx.try_recv() else {
                return;
            };
            self.sweep.audit.record_segment();
            let received_at = reply.received_at;
            self.handle_reply(reply, received_at);
        }
    }
}

impl OsEchoScanner {
    /// Sends one echo request per target and reads what answers for the shape
    /// of the stack behind it.
    ///
    /// `Ok` once the run reached its end, including an end forced by
    /// [`ScanHandle::abort`](crate::scanner::handle::ScanHandle::abort), and
    /// `Err` only where the probe itself could not do its job.
    pub async fn probe(&mut self) -> Result<(), StrategyError> {
        let mut send_tick = tokio::time::interval(SEND_TICK);
        send_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let reason = loop {
            let now = Instant::now();
            // Waiting answers first, so the timer cannot retire their probes.
            self.read_waiting_replies();
            // Exhausted probes settle nothing: this pass is not counted in
            // addresses.
            self.sweep.service_retries_without_settling(&self.ctx, now);

            if let Some(cause) = self.ctx.handle.stopped() {
                break cause.into();
            }
            if self.pending.is_empty()
                && self.sweep.retries.is_empty()
                && self.sweep.ledger.is_empty()
            {
                break StopReason::AttemptsSpent;
            }
            if now >= self.deadline {
                break StopReason::DeadlineExpired;
            }

            let sending = !self.pending.is_empty() || !self.sweep.retries.is_empty();
            let until_due = self
                .sweep
                .ledger
                .next_due()
                .map_or(Duration::from_millis(50), |due| {
                    due.saturating_duration_since(now)
                        .min(Duration::from_millis(50))
                });

            tokio::select! {
                res = self.transport.rx.recv() => {
                    match res {
                        Some(reply) => {
                            self.sweep.audit.record_segment();
                            // Timed from the capture, not from this read.
                            let received_at = reply.received_at;
                            self.handle_reply(reply, received_at);
                        }
                        None => break StopReason::StreamClosed,
                    }
                }

                _ = send_tick.tick(), if sending => {
                    self.send_one(Instant::now());
                }

                _ = tokio::time::sleep(until_due), if !sending => {}
            }
        };

        self.faults.file(
            &self.ctx,
            ScannerKind::OsEcho,
            "echo probes",
            self.sweep.audit.sends_attempted,
            self.sweep.audit.sends_failed,
        );

        let capture = self.transport.capture_counts();
        let targets = self.next_sequence as u128;
        self.sweep.report(
            &self.ctx,
            "os-echo",
            ScannerKind::OsEcho,
            targets,
            reason,
            capture,
        );
        Ok(())
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

    use tokio::sync::mpsc;

    use crate::model::capture::{IpObservation, Ipv4Observation};
    use crate::scanner::session::ScanSession;
    use crate::transport::capture::CaptureStream;
    use crate::transport::probe::{ProbeSender, SendError};

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

    /// Builds the ICMP echo reply a stack sends, from the request's own
    /// identifier and sequence, under an IP header starting at `hops`.
    ///
    /// Assembled from the RFCs by hand, so a misreading shared with the engine's
    /// builders cannot pass as agreement.
    fn echo_reply(request: &[u8], hops: u8) -> CapturedSegment {
        let identifier = u16::from_be_bytes([request[4], request[5]]);
        let sequence = u16::from_be_bytes([request[6], request[7]]);

        let mut message = Vec::with_capacity(8 + PAYLOAD.len());
        message.extend_from_slice(&[0, icmp::ECHO_PROBE_CODE, 0, 0]);
        message.extend_from_slice(&identifier.to_be_bytes());
        message.extend_from_slice(&sequence.to_be_bytes());
        message.extend_from_slice(PAYLOAD);

        CapturedSegment {
            received_at: Instant::now(),
            source: TARGET,
            destination: None,
            protocol: IpNextHeaderProtocols::Icmp.0,
            observation: Some(IpObservation::V4(Ipv4Observation {
                ttl: hops,
                identification: 0,
                dont_fragment: true,
                more_fragments: false,
                dscp: 0,
                ecn: 0,
            })),
            source_mac: None,
            bytes: message,
        }
    }

    /// A link that answers every echo request with the reply a host whose hop
    /// counter starts at `hops` sends, and records nothing else.
    struct Echoing {
        hops: u8,
        replies: mpsc::Sender<CapturedSegment>,
    }

    impl ProbeSender for Echoing {
        fn send(
            &self,
            segment: &[u8],
            _src: IpAddr,
            _dst: IpAddr,
            _zone: Option<u32>,
            _emission: Emission,
        ) -> Result<(), SendError> {
            let _ = self.replies.try_send(echo_reply(segment, self.hops));
            Ok(())
        }
    }

    fn scanner(ctx: &ScanContext, hops: u8) -> (OsEchoScanner, mpsc::Sender<CapturedSegment>) {
        let (tx, rx) = mpsc::channel(1024);
        let link = Echoing {
            hops,
            replies: tx.clone(),
        };
        let transport = ProbeTransport::from_parts(Box::new(link), rx as CaptureStream);
        (
            OsEchoScanner::with_transport(ctx.clone(), vec![TARGET], transport),
            tx,
        )
    }

    /// The pass outlasts the last host's schedule with every attempt timed at
    /// the retry ceiling, which slow hosts can push every attempt to.
    #[tokio::test(flavor = "current_thread")]
    async fn the_pass_outlasts_a_probe_timed_at_the_ceiling_on_every_attempt() {
        let (_session, ctx) = ScanSession::new();
        let built = Instant::now();
        let (scanner, _tx) = scanner(&ctx, 64);

        let needed = RETRY_POLICY.longest_probe_lifetime();
        let given = scanner.deadline.saturating_duration_since(built);
        assert!(
            given >= needed,
            "one host's schedule at the ceiling takes {needed:?} and the pass \
             is given {given:?}"
        );
    }

    /// With a per-host gap, the pass outlasts the last host's schedule with
    /// every attempt waiting out the gap (a held retry's clock is stopped).
    #[tokio::test(flavor = "current_thread")]
    async fn a_spaced_pass_outlasts_every_attempt_waiting_out_the_gap() {
        let gap = Duration::from_secs(60);
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(gap))
            .build();
        let built = Instant::now();
        let (scanner, _tx) = scanner(&ctx, 64);

        let needed = gap * u32::from(RETRY_POLICY.max_attempts);
        let given = scanner.deadline.saturating_duration_since(built);
        assert!(
            given >= needed,
            "two attempts a {gap:?} gap apart take {needed:?} and the pass is \
             given {given:?}"
        );
    }

    /// A host an earlier phase timed is asked on that timing, so a path slower
    /// than the default first timeout is still answered.
    #[tokio::test(flavor = "current_thread")]
    async fn a_host_already_timed_is_asked_on_its_own_timing() {
        let path = Duration::from_millis(1_900);
        let (_session, ctx) = ScanSession::new();
        ctx.update_host(TARGET, |host| host.add_rtt(path));
        let (mut scanner, _tx) = scanner(&ctx, 64);

        let now = Instant::now();
        scanner.send_one(now);
        let timeout = scanner
            .sweep
            .ledger
            .next_due()
            .expect("the probe is armed")
            .saturating_duration_since(now);
        assert!(
            timeout > path,
            "a host timed at {path:?} is given {timeout:?} to answer"
        );
    }

    /// A host silent to TCP is named from its echo reply: 128 is the NT-family
    /// hop counter the corpus's Windows echo rule keys on.
    #[tokio::test(flavor = "current_thread")]
    async fn a_windows_hop_counter_in_an_echo_reply_names_windows() {
        let (session, ctx) = ScanSession::new();
        let (mut scanner, _tx) = scanner(&ctx, 128);

        scanner.probe().await.expect("the phase runs");

        let host = session.hosts().get(TARGET).expect("the host is recorded");
        let found = host
            .os()
            .expect("an echo reply with a Windows hop counter names Windows");
        assert_eq!(found.family(), Some("Windows"));
        assert!(
            found.evidence().unwrap_or_default().contains("echo"),
            "the finding says what it was read off: {found}"
        );
        assert_eq!(host.status(), HostStatus::Up);
    }

    /// A host whose first echo is lost and whose answer to the second arrives
    /// while the sending thread is held for `stall`.
    struct StalledAfterAnswering {
        stall: Duration,
        replies: mpsc::Sender<CapturedSegment>,
        echoes: std::sync::atomic::AtomicU32,
    }

    impl ProbeSender for StalledAfterAnswering {
        fn send(
            &self,
            segment: &[u8],
            _src: IpAddr,
            _dst: IpAddr,
            _zone: Option<u32>,
            _emission: Emission,
        ) -> Result<(), SendError> {
            const ECHO_REQUEST: u8 = 8;
            if segment.first() != Some(&ECHO_REQUEST) {
                return Ok(());
            }
            let echo = self
                .echoes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if echo == 1 {
                self.replies
                    .try_send(echo_reply(segment, 128))
                    .expect("room for the answer");
                std::thread::sleep(self.stall);
            }
            Ok(())
        }
    }

    /// An answer waiting when its probe ran out of attempts is still read: the
    /// stalled loop wakes to the answer and the expired timer at once.
    #[tokio::test(flavor = "current_thread")]
    async fn an_answer_waiting_when_its_probe_runs_out_is_still_read() {
        let (session, ctx) = ScanSession::new();
        let (tx, rx) = mpsc::channel(16);
        // Longer than the second attempt's timeout, the one the answer is to.
        let stall = RETRY_POLICY
            .initial_rto
            .mul_f64(RETRY_POLICY.backoff * (1.0 + RETRY_POLICY.jitter))
            + Duration::from_millis(200);
        let link = StalledAfterAnswering {
            stall,
            replies: tx,
            echoes: std::sync::atomic::AtomicU32::new(0),
        };
        let transport = ProbeTransport::from_parts(Box::new(link), rx as CaptureStream);
        let mut scanner = OsEchoScanner::with_transport(ctx.clone(), vec![TARGET], transport);

        scanner.probe().await.expect("the phase runs");

        let host = session
            .hosts()
            .get(TARGET)
            .expect("the answer was dropped and the host is not on record");
        assert_eq!(
            host.os()
                .and_then(|found| found.family().map(str::to_owned)),
            Some("Windows".to_owned())
        );
    }

    /// A hop counter of 64 names nothing: Linux, macOS and the BSDs all start
    /// there and an echo reply carries nothing else to separate them.
    #[tokio::test(flavor = "current_thread")]
    async fn a_unix_hop_counter_in_an_echo_reply_names_nothing() {
        let (session, ctx) = ScanSession::new();
        let (mut scanner, _tx) = scanner(&ctx, 64);

        scanner.probe().await.expect("the phase runs");

        let host = session.hosts().get(TARGET).expect("the host is recorded");
        assert!(
            host.os().is_none(),
            "an echo reply at 64 hops is not evidence for any family, and saying \
             nothing beats the least bad guess"
        );
        assert_eq!(host.status(), HostStatus::Up);
    }

    /// A host the sender cannot reach is reported unreached; only a refusal of
    /// this host's own fails the pass.
    #[tokio::test(flavor = "current_thread")]
    async fn an_address_that_cannot_be_reached_is_not_a_failed_pass() {
        struct Refusing(fn() -> SendError);

        impl ProbeSender for Refusing {
            fn send(
                &self,
                _s: &[u8],
                _src: IpAddr,
                _dst: IpAddr,
                _zone: Option<u32>,
                _emission: Emission,
            ) -> Result<(), SendError> {
                Err((self.0)())
            }
        }

        let unresolved = || SendError::Unresolved("192.0.2.10 did not answer".to_string());
        let full = || SendError::Refused("No buffer space available".to_string());
        for (refusal, unreached) in [(unresolved as fn() -> SendError, true), (full, false)] {
            let (_session, ctx) = ScanSession::new();
            let (_tx, rx) = mpsc::channel(1024);
            let transport = ProbeTransport::from_parts(Box::new(Refusing(refusal)), rx);
            let mut scanner = OsEchoScanner::with_transport(ctx.clone(), vec![TARGET], transport);

            scanner.probe().await.expect("the phase runs");

            let failures = ctx.failures_snapshot();
            if unreached {
                assert_eq!(ctx.take_unroutable(), vec![TARGET], "reported unreached");
                assert!(failures.is_empty(), "and nothing failed: {failures:?}");
            } else {
                assert!(ctx.take_unroutable().is_empty());
                assert_eq!(failures.len(), 1, "this host's refusal is a failure");
            }
        }
    }

    /// A request refused for a hold-down on the target's neighbour (`EHOSTDOWN`
    /// on macOS) is sent again once it is over. Refused for a second hold-down
    /// after waiting one out, the target is filed unreached.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn a_request_refused_for_a_hold_down_is_sent_after_it() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// Refuses its first `refused` echo requests as macOS does inside a
        /// hold-down, and counts the ones it takes.
        struct HeldDown {
            refused: usize,
            asked: Arc<AtomicUsize>,
            taken: Arc<AtomicUsize>,
        }

        impl ProbeSender for HeldDown {
            fn send(
                &self,
                segment: &[u8],
                _src: IpAddr,
                _dst: IpAddr,
                _zone: Option<u32>,
                _emission: Emission,
            ) -> Result<(), SendError> {
                // Echo requests only.
                if segment.first() != Some(&8) {
                    return Ok(());
                }
                if self.asked.fetch_add(1, Ordering::SeqCst) < self.refused {
                    return Err(SendError::from_io(std::io::Error::from_raw_os_error(
                        libc::EHOSTDOWN,
                    )));
                }
                self.taken.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        for (refused, unreached) in [(1, false), (2, true)] {
            let (_session, ctx) = ScanSession::new();
            let (_tx, rx) = mpsc::channel(1024);
            let taken = Arc::new(AtomicUsize::new(0));
            let sender = HeldDown {
                refused,
                asked: Arc::new(AtomicUsize::new(0)),
                taken: Arc::clone(&taken),
            };
            let transport = ProbeTransport::from_parts(Box::new(sender), rx);
            let mut scanner = OsEchoScanner::with_transport(ctx.clone(), vec![TARGET], transport);
            scanner.faults.held_down.hold_down_for = Duration::from_millis(200);

            scanner.probe().await.expect("the phase runs");

            let failures = ctx.failures_snapshot();
            assert!(
                failures.is_empty(),
                "a hold-down failed the pass: {failures:?}"
            );
            if unreached {
                assert_eq!(ctx.take_unroutable(), vec![TARGET], "held down twice");
                assert_eq!(taken.load(Ordering::SeqCst), 0);
            } else {
                assert!(ctx.take_unroutable().is_empty(), "filed on one hold-down");
                assert!(
                    taken.load(Ordering::SeqCst) > 0,
                    "not asked after the hold-down"
                );
            }
        }
    }

    /// A reply carrying a different identifier must neither name the host nor
    /// mark it up.
    #[tokio::test(flavor = "current_thread")]
    async fn somebody_elses_ping_is_not_our_answer() {
        struct Silent;

        impl ProbeSender for Silent {
            fn send(
                &self,
                _s: &[u8],
                _src: IpAddr,
                _dst: IpAddr,
                _zone: Option<u32>,
                _emission: Emission,
            ) -> Result<(), SendError> {
                Ok(())
            }
        }

        let (session, ctx) = ScanSession::new();
        let (tx, rx) = mpsc::channel(1024);
        let transport = ProbeTransport::from_parts(Box::new(Silent), rx);
        let mut scanner = OsEchoScanner::with_transport(ctx.clone(), vec![TARGET], transport);

        // Somebody else's ping reply, with a Windows hop counter.
        let mut message = Vec::with_capacity(8 + PAYLOAD.len());
        message.extend_from_slice(&[0, 0, 0, 0]);
        message.extend_from_slice(&0xBEEFu16.to_be_bytes()); // not our identifier
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(PAYLOAD);
        let theirs = CapturedSegment {
            received_at: Instant::now(),
            source: TARGET,
            destination: None,
            protocol: IpNextHeaderProtocols::Icmp.0,
            observation: Some(IpObservation::V4(Ipv4Observation {
                ttl: 128,
                identification: 0,
                dont_fragment: true,
                more_fragments: false,
                dscp: 0,
                ecn: 0,
            })),
            source_mac: None,
            bytes: message,
        };
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = tx.try_send(theirs);
        });

        scanner.probe().await.expect("the phase runs");

        assert!(
            session.hosts().get(TARGET).is_none(),
            "a foreign identifier resolves nothing, records nothing"
        );
    }

    // ── Timestamp ────────────────────────────────────────────────────────────

    /// A link that records what it was asked to send and answers nothing.
    #[derive(Clone, Default)]
    struct Recording(std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>);

    impl ProbeSender for Recording {
        fn send(
            &self,
            segment: &[u8],
            _src: IpAddr,
            _dst: IpAddr,
            _zone: Option<u32>,
            _emission: Emission,
        ) -> Result<(), SendError> {
            self.0.lock().expect("the log").push(segment.to_vec());
            Ok(())
        }
    }

    /// A scanner over `target` whose link records and never answers.
    fn recording(ctx: &ScanContext, target: IpAddr) -> (OsEchoScanner, Recording) {
        use crate::system::interface::{Link, LinkAddress, SourceResolver};
        use std::net::{Ipv4Addr, Ipv6Addr};

        let link = Recording::default();
        let (_tx, rx) = mpsc::channel(16);
        let transport = ProbeTransport::from_parts(Box::new(link.clone()), rx as CaptureStream);
        let mut scanner = OsEchoScanner::with_transport(ctx.clone(), vec![target], transport);

        // A fixed resolver: `from_system` can find no route to a documentation
        // target under the suite's parallel load. Both families on-link.
        scanner.resolver =
            SourceResolver::from_links(&[Link::new("test0", 0).with_addresses(vec![
                LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24),
                LinkAddress::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    64,
                ),
            ])]);

        (scanner, link)
    }

    /// A timestamp reply to `request`, built by hand from the RFC 792 layout.
    fn timestamp_reply(request: &[u8], readings: [u32; 3]) -> CapturedSegment {
        let mut bytes = vec![14u8, 0, 0, 0];
        // Identifier and sequence, carried back unchanged.
        bytes.extend_from_slice(&request[4..8]);
        for value in readings {
            bytes.extend_from_slice(&value.to_be_bytes());
        }

        CapturedSegment {
            received_at: Instant::now(),
            source: TARGET,
            destination: None,
            protocol: IpNextHeaderProtocols::Icmp.0,
            observation: None,
            source_mac: None,
            bytes,
        }
    }

    /// An IPv4 target is sent an echo and a timestamp request.
    #[tokio::test(flavor = "current_thread")]
    async fn an_ipv4_target_is_asked_for_a_timestamp_as_well() {
        let (_session, ctx) = ScanSession::new();
        let (mut scanner, link) = recording(&ctx, TARGET);

        scanner.send_one(Instant::now());

        let sent = link.0.lock().expect("the log").clone();
        assert_eq!(sent.len(), 2, "an echo and a timestamp");
        assert_eq!(sent[0][0], 8, "an echo request");
        assert_eq!(sent[1][0], 13, "a timestamp request");
        assert_eq!(
            &sent[0][4..6],
            &sent[1][4..6],
            "both carry this scan's identifier"
        );
        assert_ne!(
            &sent[0][6..8],
            &sent[1][6..8],
            "and each names its own attempt"
        );
    }

    /// A host that answers no ping is still found when it answers a timestamp.
    #[tokio::test(flavor = "current_thread")]
    async fn a_host_that_answers_only_a_timestamp_is_still_found() {
        let (session, ctx) = ScanSession::new();
        let (mut scanner, link) = recording(&ctx, TARGET);

        scanner.send_one(Instant::now());
        let timestamp_request = link.0.lock().expect("the log")[1].clone();

        // Only the timestamp comes back.
        scanner.handle_reply(
            timestamp_reply(&timestamp_request, [0, 1_000, 1_000]),
            Instant::now(),
        );

        let host = session.hosts().get(TARGET).expect("the host was found");
        assert!(host.status().is_up());
        assert!(
            host.reasons()
                .iter()
                .any(|reason| reason.protocol == StatusProtocol::IcmpTimestamp),
            "the evidence names the probe that found it"
        );
    }

    /// The clock reading reaches the host record's evidence.
    #[tokio::test(flavor = "current_thread")]
    async fn the_targets_clock_offset_reaches_the_host_record() {
        let (session, ctx) = ScanSession::new();
        let (mut scanner, link) = recording(&ctx, TARGET);

        scanner.send_one(Instant::now());
        let request = link.0.lock().expect("the log")[1].clone();

        // A clock that is not a time of day is reported as such.
        scanner.handle_reply(
            timestamp_reply(&request, [0, 0x8000_0000, 0x8000_0000]),
            Instant::now(),
        );

        let host = session.hosts().get(TARGET).expect("the host was found");
        let reason = host
            .reasons()
            .iter()
            .find(|reason| reason.protocol == StatusProtocol::IcmpTimestamp)
            .expect("the timestamp evidence");
        assert!(
            reason
                .details
                .as_deref()
                .unwrap_or_default()
                .contains("not a time of day"),
            "an unusable clock is said to be unusable: {reason:?}"
        );
    }

    /// An IPv6 target is sent no timestamp: RFC 4443 defines no such message.
    #[tokio::test(flavor = "current_thread")]
    async fn an_ipv6_target_is_sent_no_timestamp() {
        let (_session, ctx) = ScanSession::new();
        let target = IpAddr::V6("2001:db8::10".parse().expect("an address"));
        let (mut scanner, link) = recording(&ctx, target);

        scanner.send_one(Instant::now());

        let sent = link.0.lock().expect("the log").clone();
        assert_eq!(sent.len(), 1, "the echo alone");
        assert_eq!(sent[0][0], 128, "an ICMPv6 echo request");
    }

    /// A timestamp reply with another identifier finds nothing.
    #[tokio::test(flavor = "current_thread")]
    async fn another_scans_timestamp_reply_finds_nothing() {
        let (session, ctx) = ScanSession::new();
        let (mut scanner, link) = recording(&ctx, TARGET);

        scanner.send_one(Instant::now());
        let request = link.0.lock().expect("the log")[1].clone();

        let mut stranger = timestamp_reply(&request, [0, 1_000, 1_000]);
        stranger.bytes[4] ^= 0xFF;
        scanner.handle_reply(stranger, Instant::now());

        assert!(
            session.hosts().get(TARGET).is_none(),
            "a stranger's reply found a host"
        );
    }

    /// Through a frame sender every new neighbour is resolved at once: dead ones
    /// are reported unreached with nothing sent, and a live one is asked.
    /// Resolved one at a time inside the send, each dead neighbour would cost
    /// the whole resolution budget.
    #[tokio::test]
    async fn neighbours_behind_a_frame_sender_are_asked_for_together() {
        use crate::system::interface::{Link, LinkAddress};
        use crate::transport::link::{LinkNeighbors, SIMULATED_HOST};
        use crate::transport::probe::MockSender;

        const LIVE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 61);
        let dead: Vec<IpAddr> = (171..=190)
            .map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
            .collect();
        let (_session, ctx) = ScanSession::new();
        let (_tx, rx) = mpsc::channel(1024);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport = ProbeTransport::from_parts(Box::new(sender), rx)
            .with_link_neighbors(LinkNeighbors::on_simulated_segment("sim-echo0", &[LIVE]));
        let targets = dead.iter().copied().chain([IpAddr::V4(LIVE)]).collect();
        let mut scanner = OsEchoScanner::with_transport(ctx.clone(), targets, transport);
        scanner.resolver = SourceResolver::from_links(&[Link::new("test0", 0)
            .with_addresses(vec![LinkAddress::new(IpAddr::V4(SIMULATED_HOST), 24)])]);

        scanner.probe().await.expect("the phase runs");

        let sent = sent.lock().unwrap();
        assert!(!sent.is_empty(), "the live neighbour is asked");
        assert!(
            sent.iter().all(|(_, _, dst)| *dst == IpAddr::V4(LIVE)),
            "a request was handed to the sender for a neighbour nobody had resolved"
        );
        let mut unreached = ctx.take_unroutable();
        unreached.sort();
        assert_eq!(
            unreached, dead,
            "every dead neighbour is reported unreached"
        );
        assert!(
            ctx.failures_snapshot().is_empty(),
            "and nothing failed here"
        );
    }
}
