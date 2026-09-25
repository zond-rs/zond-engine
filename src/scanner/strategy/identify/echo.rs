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
//! nothing, and read for what the reply says about the stack that sent it.
//!
//! ## Why this scanner exists
//!
//! Passive identification reads a reply the scan already drew, so it starts
//! from a host that answered something. The hosts that answer nothing are not
//! a rare case: a stock Windows firewall *drops* rather than refuses, so a
//! desktop with no service exposed emits no packet any TCP rule could read:
//! measured, twice, on two independent installations. A great many of those
//! machines still answer a ping, and what they put in the reply (a hop counter
//! of 128, the request's code echoed or zeroed) is a property of the same
//! stack. This is the only route to those hosts, and it is why
//! [`OsDetection::Active`](crate::config::OsDetection) exists as a level.
//!
//! ## The probe asks a question, or it is not worth sending
//!
//! The request carries [`ECHO_PROBE_CODE`](crate::protocols::icmp::ECHO_PROBE_CODE)
//! rather than a conformant zero,
//! because whether a responder echoes a non-zero code or writes zero is a
//! documented disagreement between stacks: invisible to a probe that never
//! asked. The identifier is the scan's identity (every other ping on the host
//! is filtered out by it, in userspace, since no kernel filter can express it),
//! and the sequence names the attempt, which is what makes a round trip real.
//!
//! ## What one reply may claim
//!
//! An echo reply carries no options, no window, no sequence number: an
//! initial hop counter of 64 names *nothing*, because Linux, macOS and the BSDs
//! all start there. The rule corpus is authored under that constraint, and
//! [`classify`](crate::fingerprint::os) reports nothing rather than the
//! least bad guess. A host this scanner cannot name is a host it says nothing
//! about, which is the same honesty the passive path holds itself to.

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
use crate::scanner::pacing::retry::{ProbeLedger, RetryPolicy};
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::StrategyError;
use crate::scanner::strategy::raw::SendFaults;
use crate::scanner::strategy::sweep::HostSweep;
use crate::system::interface::SourceResolver;
use crate::transport::capture::CapturedSegment;
use crate::transport::probe::{Emission, ProbeKind, ProbeTransport};
use crate::{info, success};

/// The payload every echo request carries, so a reply can be checked against
/// what was sent rather than trusted to have come back whole.
const PAYLOAD: &[u8] = b"zond-os-probe";

/// How an echo is retransmitted.
///
/// Two attempts rather than three: this phase runs only where the caller opted
/// in, over hosts the passive sources already found thin, and its verdicts are
/// family-level. A third attempt buys coverage a ping is unlikely to return.
const RETRY_POLICY: RetryPolicy = RetryPolicy::new(
    2,
    Duration::from_millis(200),
    Duration::from_millis(25),
    Duration::from_secs(2),
    2.0,
    0.2,
    None,
);

/// How fast echoes leave the wire. One per millisecond is far slower than the
/// port scanners: a scan that opted into active detection pays
/// for its hosts one packet at a time, and this phase is never the thing being
/// timed.
const SEND_TICK: Duration = Duration::from_millis(1);

/// Patience after the last probe resolves or exhausts, so a reply from a slow
/// path still lands before the phase closes.
const QUIET_FLOOR: Duration = Duration::from_secs(1);

/// This host's own milliseconds since midnight UT, which is the scale RFC 792
/// puts a timestamp on.
///
/// The reference an offset is measured against. Read at the moment a reply is
/// folded rather than when the probe went out, so it includes the return path;
/// see [`TimestampReply::offset_from`](crate::protocols::icmp::TimestampReply::offset_from)
/// for why a millisecond or two does not matter to what this is for.
///
/// Zero where the clock is before the Unix epoch, which is a machine with no
/// clock rather than a case worth a signature of its own: the offset it produces
/// is then plainly wrong rather than quietly plausible.
fn local_millis_since_midnight() -> u32 {
    const MILLIS_PER_DAY: u128 = 86_400_000;
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| (since.as_millis() % MILLIS_PER_DAY) as u32)
        .unwrap_or(0)
}

/// The first address in `queue` whose host may be probed now, rotating past the
/// ones that may not.
///
/// [`None`] means every address in the queue was asked too recently for the gap
/// the scan keeps. The queue keeps every address it had, in a different order:
/// one turned away goes to the back rather than out, because a probe dropped on
/// this answer is a host the pass silently stops asking about.
///
/// The walk is bounded by the queue's length at entry, so a queue in which
/// nothing is ready costs one pass over it rather than being walked until
/// something becomes ready. Free-standing rather than a method because it is
/// called on each of two queues while the context is borrowed.
fn take_ready(queue: &mut VecDeque<IpAddr>, ctx: &ScanContext, now: Instant) -> Option<IpAddr> {
    for _ in 0..queue.len() {
        let candidate = queue.pop_front()?;
        if ctx.host_ready_at(candidate, now).is_none() {
            return Some(candidate);
        }
        queue.push_back(candidate);
    }
    None
}

/// Sends one ICMP echo per host where passive evidence named nothing, and files
/// what the replies say.
///
/// Targets are chosen by the caller from the host store, because "the passive
/// sources concluded nothing" is a fact about the store rather than about the
/// plan, and it only becomes true once those sources have finished.
pub struct OsEchoScanner {
    ctx: ScanContext,
    transport: ProbeTransport,
    /// The IP-header state every echo carries. An evasion profile contributes
    /// only its hop limit: an echo has no port to pin, and reshaping it would
    /// change the very reply this scanner reads a stack's shape from. See
    /// [`EvasionProfile::hop_limited_emission`](crate::evasion::EvasionProfile::hop_limited_emission).
    emission: Emission,
    resolver: SourceResolver,
    /// The identifier every request carries, and the only thing separating this
    /// scan's replies from every other ping on the host.
    identifier: u16,
    /// How many requests have left, which is also the next sequence number.
    /// Sequence numbers name attempts, and the ledger arms with them, so a
    /// round trip is measured against the send it answers.
    next_sequence: u16,
    /// Targets not yet asked.
    pending: VecDeque<IpAddr>,
    /// The outstanding probes, the retry queue and the run's counters, shared
    /// with the two discovery sweeps. The ledger carries the sequence of the
    /// attempt, so a round trip is measured against the send it answers.
    sweep: HostSweep<u16>,
    /// Which host each sequence went to, since a reply names its attempt, not
    /// its target.
    by_sequence: HashMap<u16, IpAddr>,
    /// The hard ceiling on this run, derived from the longest a probe's
    /// schedule can take: every attempt at the retry ceiling, which is where
    /// hosts that answered slowly time the rest, or at the gap the scan keeps
    /// between two probes at one host where that is longer.
    deadline: Instant,
    /// Why requests did not leave, split by whose fact it was: this host's
    /// send path, or an address nothing reaches from here.
    faults: SendFaults,
}

impl OsEchoScanner {
    /// Opens the ICMP transport this scanner needs and takes the targets to
    /// ask. Fails where the raw socket cannot be had, which is the caller's
    /// signal that this level of detection is unavailable rather than silent.
    pub fn new(
        ctx: ScanContext,
        targets: Vec<IpAddr>,
        tuning: ProbeTuning,
    ) -> Result<Self, StrategyError> {
        let identifier = rand::random();
        let transport =
            ProbeTransport::open_with(ProbeKind::IcmpEcho { identifier }, tuning.send_mode)?;
        Ok(Self::with_identifier(
            ctx,
            targets,
            transport,
            identifier,
            tuning.evasion.hop_limited_emission(),
        ))
    }

    /// Builds the scanner around a transport the caller opened, which is the
    /// seam a test or a custom orchestration drives it through. The identifier
    /// is drawn here, since the transport came from somewhere that could not
    /// have known it.
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
        let send_duration = SEND_TICK.saturating_mul(targets.len() as u32);
        let target_count = targets.len();
        let probe_lifetime = RETRY_POLICY.longest_spaced_probe_lifetime(ctx.host_probe_interval());

        // Timed from what the phases before this one measured, since every
        // target is a host the scan already found and most were timed finding
        // it. From first principles, a host behind a path slower than the
        // first timeout has every attempt given up on before it can answer.
        // The median, for the reason the port scans' `seed_timing` gives.
        let mut ledger = ProbeLedger::new(RETRY_POLICY, 256);
        let wanted: std::collections::HashSet<IpAddr> = targets.iter().copied().collect();
        for host in ctx.store.iter() {
            let address = host.key().addr();
            if !wanted.contains(&address) {
                continue;
            }
            if let Some(rtt) = host.value().median_rtt() {
                ledger.seed_host_rtt(address, rtt);
            }
        }

        Self {
            ctx,
            transport,
            emission,
            resolver: SourceResolver::from_system(),
            identifier,
            next_sequence: 0,
            pending: targets.into(),
            sweep: HostSweep::new(ledger),
            by_sequence: HashMap::with_capacity(target_count),
            deadline: Instant::now() + probe_lifetime + send_duration + QUIET_FLOOR,
            faults: SendFaults::default(),
        }
    }

    /// Releases one probe: a retry first, then a target not yet asked.
    ///
    /// Retries first for the same reason the routed sweep puts them first: a
    /// retry is an obligation the scan already owns, and queueing it behind
    /// every first attempt would send it long after the moment it was scheduled
    /// for.
    fn send_one(&mut self, now: Instant) {
        // A queued retry first, then a fresh target, and either may be turned
        // away by the gap the scan keeps between probes at one host. Both queues
        // are asked, because unlike a sweep this pass revisits addresses it has
        // already probed.
        //
        // What the gap spaces here is the *pair* below: an IPv4 target gets an
        // echo and a timestamp back to back, and splitting them would mean
        // deferring half a probe. See `send_timestamp` for why they travel
        // together, and `ZondConfig::host_probe_interval` for the two-packet
        // consequence, which is written down there rather than left to be
        // measured.
        //
        // A retry's probe has its clock stopped while it is queued (see
        // `HostSweep::retries`), and one whose probe was answered meanwhile is
        // dropped unsent.
        self.sweep
            .retries
            .retain(|target| self.sweep.ledger.contains(target));
        let (target, retry) = match take_ready(&mut self.sweep.retries, &self.ctx, now) {
            Some(target) => (target, true),
            None => match take_ready(&mut self.pending, &self.ctx, now) {
                Some(target) => (target, false),
                None => return,
            },
        };
        let sent = self.send_pair(target, now);
        // A retry restarts its probe's clock whatever became of it: from the
        // send, which re-arms it, or from now for one that did not leave, whose
        // attempt stays charged so an unroutable target exhausts on schedule
        // rather than waiting outstanding forever.
        match sent {
            Some(sequence) if retry => self.sweep.ledger.rearm(target, target, sequence, now),
            Some(sequence) => self.sweep.ledger.arm(target, target, sequence, (), now),
            None if retry => self.sweep.ledger.resume(&target, now),
            None => {}
        }
    }

    /// Sends the echo, and for an IPv4 target the timestamp, that make up one
    /// attempt at `target`, returning the echo's sequence if it left.
    fn send_pair(&mut self, target: IpAddr, now: Instant) -> Option<u16> {
        let source = self.resolver.resolve(target)?;

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
                return None;
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
                // An address nothing reaches is the address's fact and is
                // reported against it; only this host's own refusals are the
                // pass failing. Each said once. See `SendFaults`.
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

        // After the pair and only for a pair that got somewhere. A probe the
        // kernel refused reached no target and must not spend its slot, on the
        // same reasoning `record_send` gives for keeping it out of the
        // congestion window. The timestamp is not consulted: it is the smaller
        // half of the probe and IPv4-only, so a target that answered neither
        // question would otherwise have its slot decided by which family it is
        // in.
        if sent {
            self.ctx.host_probed(target, now);
        }
        sent.then_some(sequence)
    }

    /// Asks the same target what time it thinks it is, where the family has a
    /// message for the question.
    ///
    /// A second packet per IPv4 target, which is the cost, and it buys the two
    /// things an echo cannot. A filter written against ping frequently passes
    /// type 13, so a host that answers nothing here still answers this; and the
    /// reply carries the target's own clock, which no other probe in this engine
    /// obtains. The pass this runs in covers only hosts nothing else could name,
    /// so the doubling is of a small number.
    ///
    /// IPv4 only. RFC 4443 defines no timestamp message, so an IPv6 target has
    /// nothing to be asked and is left with the echo alone.
    ///
    /// The ledger is not armed a second time. It is keyed by target and already
    /// holds the echo's attempt; a timestamp reply resolves that entry without
    /// claiming its round trip, since the two probes are not the same question
    /// and timing one against the other would report a measurement nobody made.
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
                // Not recorded as a send failure of its own: the echo beside it
                // is what this pass is counted in, and a host whose timestamp
                // could not be sent is still being asked. Nor logged as an
                // error where the echo beside it already said the address
                // cannot be reached.
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
        if reply.protocol != IpNextHeaderProtocols::Icmp
            && reply.protocol != IpNextHeaderProtocols::Icmpv6
        {
            self.sweep.audit.record_off_target();
            return;
        }
        // An ICMP message does not say which family's numbering it belongs to;
        // the address it arrived from does.
        let over_ipv6 = reply.source.is_ipv6();
        let sequence = match icmp::classify_echo_reply(&reply.bytes, self.identifier, over_ipv6) {
            icmp::EchoReply::Ours { sequence } => sequence,
            // Not an echo reply. It may still be the answer to the timestamp
            // sent beside it, which is the whole reason that probe goes out: a
            // host behind a filter that drops ping answers here and nowhere
            // else.
            icmp::EchoReply::Other { .. } if !over_ipv6 => {
                return self.handle_timestamp_reply(reply, now);
            }
            // Every other ping on the host arrives here: the identifier cannot
            // be expressed in a kernel filter, so this is where it is enforced.
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
            // A duplicate, or an answer to a probe already written off. It
            // proved the host alive but yields no sample.
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
    /// credited: the ledger timed the echo, and a reply to a different probe is
    /// not a measurement of that one.
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

        // Resolved without a token, so the entry retires and no attempt is
        // credited with a round trip it did not measure.
        let resolution = self.sweep.ledger.resolve(&target, None, now);
        if resolution.is_none() {
            // The echo beside it already answered, or the probe was written
            // off. The host is alive either way and the clock is still worth
            // recording.
            self.sweep.audit.record_reply_without_rtt();
        } else {
            self.sweep.audit.record_host_found(None);
        }

        let detail = match readings.offset_from(local_millis_since_midnight()) {
            Some(offset) => format!("timestamp reply to an OS probe, clock {offset} ms from ours"),
            // A target whose readings are not times of day still answered, which
            // is the half of this that finds hosts a ping cannot.
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
    /// The same shape as the port scanner's passive reading: a whole reply is
    /// one item of evidence, combined with the other sources on the host
    /// through [`os::resolve`], merged by accuracy so nothing is overwritten so
    /// much as outranked.
    fn identify(&self, target: IpAddr, reply: &CapturedSegment) {
        // `None` means no IP header was ever there to read, a synthetic
        // receive stream, rather than that nothing notable was in one.
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
}

impl OsEchoScanner {
    /// Sends one echo request per target and reads what answers for the shape
    /// of the stack behind it.
    ///
    /// Not `discover_hosts`, and not a [`HostScanner`](super::super::HostScanner).
    /// The trait says a strategy that finds which hosts are reachable, and every
    /// address here came out of the store because something else already found
    /// it. Nothing dispatches this dynamically, so an impl would buy a method
    /// name and the method name would be untrue.
    ///
    /// `Ok` once the run reached its end, including an end forced by
    /// [`ScanHandle::abort`](crate::scanner::handle::ScanHandle::abort), and
    /// `Err` only where the probe itself could not do its job.
    pub async fn probe(&mut self) -> Result<(), StrategyError> {
        let mut send_tick = tokio::time::interval(SEND_TICK);
        send_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let reason = loop {
            let now = Instant::now();
            // An exhausted probe settles nothing: this asks hosts the scan
            // already found what they run, and a scan not counted in addresses
            // has no position to settle against.
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
                            self.handle_reply(reply, Instant::now());
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
    /// Assembled from the RFCs rather than through the engine's own builders,
    /// so a shared misreading of what an echo reply is cannot pass for
    /// agreement.
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
            protocol: IpNextHeaderProtocols::Icmp,
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

    /// The pass outlasts the schedule of the last host it asks, with every
    /// attempt timed as long as measurement may make it.
    ///
    /// Hosts that answered slowly time the rest from what they showed, at up
    /// to the retry ceiling on every attempt, the first included. A deadline
    /// sized for an unmeasured schedule stops the pass while its last host
    /// still has attempts to spend, and that host goes unidentified.
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

    /// A pass keeping a gap between two probes at one host outlasts the
    /// schedule of the last host it asks with every attempt waiting out that
    /// gap, since a retry held for the gap waits with its clock stopped.
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

    /// A host an earlier phase timed is asked on that timing, not on the
    /// guess an unmeasured path starts from.
    ///
    /// This pass revisits hosts the scan has already found, and most of them
    /// were timed finding them. Started from first principles instead, a host
    /// behind a path slower than the first timeout has every attempt given up
    /// on before its answer can arrive, and goes unidentified.
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

    /// The whole path this scanner exists for: a host that answered nothing a
    /// TCP probe could read, named from the one reply it does give. A stock
    /// Windows firewall drops rather than refuses, and 128 is the NT-family
    /// hop counter, that one field is what the corpus's Windows echo rule
    /// keys on.
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

    /// A Unix-alike hop counter names nothing, on purpose, and this is the
    /// record of why: Linux, macOS and the BSDs all start at 64 and an echo
    /// reply carries nothing else to separate them. The corpus refuses that
    /// rule; this test holds the scanner to the same refusal.
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

    /// A host the sender cannot reach is reported unreached, and only a
    /// refusal of this host's own is the pass failing.
    ///
    /// A dead neighbour's every request is refused with the same answer, and
    /// read as a failure it would report the pass broken for a fact about the
    /// address, the way the port scanners and the sweeps do not.
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

    /// Every other ping on the host is filtered out by the identifier, in
    /// userspace, because no kernel filter can express it. A reply carrying a
    /// different identifier is not this scan's answer and must resolve nothing:
    /// not name the host, not even mark it up.
    #[tokio::test(flavor = "current_thread")]
    async fn somebody_elses_ping_is_not_our_answer() {
        // A link that answers nothing: this host's own probe goes unanswered,
        // and the only reply that arrives is another ping's, carrying an
        // identifier this scan never sent.
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

        // The reply to somebody else's ping, with a Windows hop counter that
        // would name the host were it read.
        let mut message = Vec::with_capacity(8 + PAYLOAD.len());
        message.extend_from_slice(&[0, 0, 0, 0]);
        message.extend_from_slice(&0xBEEFu16.to_be_bytes()); // not our identifier
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(PAYLOAD);
        let theirs = CapturedSegment {
            received_at: Instant::now(),
            source: TARGET,
            destination: None,
            protocol: IpNextHeaderProtocols::Icmp,
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

        // The foreign reply was declined before anything was written: no
        // host record exists, because nothing this scan drew said anything
        // about the address. A reply it did not draw must not even prove it
        // alive.
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

    /// A scanner over `target` whose link records rather than answers.
    fn recording(ctx: &ScanContext, target: IpAddr) -> (OsEchoScanner, Recording) {
        use crate::system::interface::{Link, LinkAddress, SourceResolver};
        use std::net::{Ipv4Addr, Ipv6Addr};

        let link = Recording::default();
        let (_tx, rx) = mpsc::channel(16);
        let transport = ProbeTransport::from_parts(Box::new(link.clone()), rx as CaptureStream);
        let mut scanner = OsEchoScanner::with_transport(ctx.clone(), vec![target], transport);

        // A fixed resolver, not the host's: `from_system` can find no route to a
        // documentation target under the suite's parallel load. Both families
        // on-link so every target these tests use resolves.
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

    /// A timestamp reply to `request`, built from the RFC 792 layout rather than
    /// from this crate's own reader.
    fn timestamp_reply(request: &[u8], readings: [u32; 3]) -> CapturedSegment {
        let mut bytes = vec![14u8, 0, 0, 0];
        // The identifier and sequence sit where an echo puts them, and a reply
        // carries both back unchanged.
        bytes.extend_from_slice(&request[4..8]);
        for value in readings {
            bytes.extend_from_slice(&value.to_be_bytes());
        }

        CapturedSegment {
            received_at: Instant::now(),
            source: TARGET,
            destination: None,
            protocol: IpNextHeaderProtocols::Icmp,
            observation: None,
            source_mac: None,
            bytes,
        }
    }

    /// An IPv4 target is asked twice, and the second question is the one a ping
    /// filter is least likely to have been written against.
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

    /// The whole point of the probe: a host that answers no ping is still found
    /// when it answers a timestamp, which is the filter case type 13 gets past.
    #[tokio::test(flavor = "current_thread")]
    async fn a_host_that_answers_only_a_timestamp_is_still_found() {
        let (session, ctx) = ScanSession::new();
        let (mut scanner, link) = recording(&ctx, TARGET);

        scanner.send_one(Instant::now());
        let timestamp_request = link.0.lock().expect("the log")[1].clone();

        // The echo goes unanswered; only the timestamp comes back.
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

    /// The offset is what the probe adds beyond liveness, and it reaches the
    /// report in words rather than being computed and dropped.
    #[tokio::test(flavor = "current_thread")]
    async fn the_targets_clock_offset_reaches_the_host_record() {
        let (session, ctx) = ScanSession::new();
        let (mut scanner, link) = recording(&ctx, TARGET);

        scanner.send_one(Instant::now());
        let request = link.0.lock().expect("the log")[1].clone();

        // A clock that is not a time of day at all, which is reported as such
        // rather than folded into a plausible-looking offset.
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

    /// An IPv6 target is asked nothing of the kind, because RFC 4443 defines no
    /// timestamp message and a probe of that shape would be bytes no stack has
    /// ever been asked to parse.
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

    /// Somebody else's timestamp exchange is not this scan's answer. The capture
    /// admits every ICMP message on the host, so this is where the identifier is
    /// enforced.
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
}
