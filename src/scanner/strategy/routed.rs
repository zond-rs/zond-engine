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

pub mod characterise;
mod icmp_error;
mod os_echo;
mod os_series;
mod port_scan;
mod probe_scan;
pub mod traceroute;
mod udp_scan;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};

use crate::config::ProbeTuning;
use crate::evasion::SegmentShaping;
use crate::journal::settle::{Outcome, Settled};
use crate::model::host::{HostStatus, StatusProtocol, StatusReason};
use crate::model::ip::set::IpSet;
use crate::model::technique::{TcpReply, TcpScanTechnique};
use crate::protocols as protocol;
use crate::scanner::pacing::congestion::WindowLimits;
use crate::scanner::pacing::deadline::{AdaptiveDeadline, AdaptiveDeadlineConfig};
use crate::scanner::pacing::retry::{Due, ProbeLedger, Resolution, RetryPolicy, SilentHostPolicy};
use crate::scanner::pacing::timer::ScanBudget;
use crate::scanner::session::ScanContext;
use crate::system::interface::RoutedTarget;
use crate::transport::probe::{Emission, ProbeKind, ProbeSender, ProbeTransport, SendError};
use crate::{error, info, success};
use async_trait::async_trait;
use pnet_packet::tcp::TcpPacket;
use tokio::sync::mpsc::UnboundedSender;

use crate::scanner::audit::ProbeAudit;
use crate::scanner::payload;
use crate::scanner::report::StopReason;
use crate::scanner::session::ScannerKind;
use crate::scanner::strategy::{HostScanner, StrategyError};

pub use os_echo::OsEchoScanner;
pub use os_series::{ACTIVE_SAMPLES, AGGRESSIVE_SAMPLES, OsSeriesScanner, SeriesTarget};
pub use port_scan::TcpPortScanner;
pub use udp_scan::UdpPortScanner;

// The machinery both raw port scanners are built from: the state, the loop
// that drives it, and the short list of protocol facts the loop cannot supply
// itself. Exported alongside them because a caller writing a third one — SCTP
// INIT, or a protocol this engine does not speak yet — needs the same stop
// conditions and the same audit tail, and reimplementing those is how the two
// here would have drifted apart.
pub use probe_scan::{AuditLabels, ProbeTarget, RawPortScan, RawProbeScan, run};

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
///   arrivals behind it. The ceiling bounds a scan whose pace nobody derived —
///   it is *not* what bounds the port scanners, which tell it their size and
///   their pacing floor and so cannot be clamped by it. It used to be, and it
///   truncated a 65 535-port scan at 60 seconds of the 104 it had earned.
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

/// How a **port scan's** probes are retransmitted.
///
/// [`RETRY_POLICY`] with a steeper backoff and a wider spread, and the reason is
/// specific to what a port scan's retries are recovering from. A sweep's probes
/// are lost to whatever the path is doing, which is not correlated with the
/// sweep; a port scan's are lost to the burst the port scan itself is making at
/// one stack, and a retry sent while that burst is still going is a second
/// packet into the same congested moment.
///
/// Measured, against a Raspberry Pi: a quarter of a thousand probes went
/// unanswered, and with three independent attempts at that loss rate an open
/// port should be missed one time in seventy — eleven open ports should have
/// come back as nearly eleven. Three runs found seven each. The attempts were
/// not independent; all three of them fitted inside the congestion that lost the
/// first.
///
/// So the schedule is stretched at the back and left alone at the front. The
/// first timeout stays as early as measurement allows, because it is what tells
/// [`TCP_PORT_WINDOW`] the target is struggling; the last lands far enough out
/// to sample a network state the scan has had time to stop causing. The jitter
/// is widened for the same reason one step down: probes admitted together time
/// out together, and an unspread retry wave rebuilds the burst it is escaping.
const PORT_RETRY_POLICY: RetryPolicy = RetryPolicy::new(
    3,
    Duration::from_millis(200),
    Duration::from_millis(25),
    Duration::from_secs(2),
    3.0,
    0.3,
    Some(SilentHostPolicy::new(32, 2)),
);

/// The window a **TCP** port scan paces itself by.
///
/// This is the answer to a question no fixed rate answers well. A port scan
/// aims every probe at one stack, and it is that stack's willingness to answer
/// that bounds the result — a number that differs by two orders of magnitude
/// between the consumer router and the Linux server on the same switch, and
/// that neither this crate nor its caller can know in advance. So the scan
/// discovers it: see [`congestion`](crate::scanner::pacing::congestion) for how,
/// and for why the signal it grows and cuts on is a probe answered *on a retry*
/// rather than a probe not answered at all.
///
/// Each of the four numbers, and what would go wrong at another value:
///
/// - **Start at 32.** Every stack in service answers a few dozen simultaneous
///   SYNs without noticing. Starting at one would spend a round trip per
///   doubling, and on a local segment the ramp would be most of the scan.
/// - **Never below 16.** The floor is what a target that is genuinely being
///   outrun gets cut back to, and it has to leave the scan able to finish: at
///   sixteen questions per round-trip budget a thousand silent ports still
///   settle in a few seconds, where single digits would take a minute. Past
///   that a scan is not being polite, it is failing, and an unfinished scan's
///   verdicts are indeterminate rather than late.
/// - **Never above 1024.** A thousand questions outstanding at one stack is
///   already more than any of them will answer; growth past it buys nothing and
///   the rate ceiling would bind first anyway.
/// - **Stop doubling at 64.** This is the number the controller is blind for.
///   Nothing can be known about a target until a probe to it has been answered
///   or has timed out, and slow start doubles every round trip in the meantime —
///   so the threshold is the worst overshoot a target can be subjected to before
///   the scan has any evidence about it at all. It was 256, and against a
///   Raspberry Pi that meant several hundred probes already in the air by the
///   time the first timeout arrived. Sixty-four outstanding still empties a
///   thousand ports in a fraction of a second on any local segment, and linear
///   growth carries it further wherever the evidence supports it.
const TCP_PORT_WINDOW: WindowLimits = WindowLimits::new(32, 16, 1_024, 64);

/// The most probes a TCP port scan leaves unresolved at once.
///
/// Not the pacing — [`TCP_PORT_WINDOW`] is — but the bound on how far the
/// bookkeeping may run ahead of it. A probe leaves the window at its first
/// timeout and stays on the ledger until its last, so against a range that
/// answers nothing the scan admits at window speed while the backlog of
/// half-finished probes grows behind it. Several times the window's ceiling,
/// because that backlog is the retry schedule's whole length divided by the
/// first timeout and is expected to be a multiple of what is in flight; far
/// below where the memory matters, because each entry is two durations and a
/// handful of tokens.
const TCP_PORT_UNRESOLVED: usize = 8_192;

/// The fastest a TCP port scan will go regardless of what the window says.
///
/// A **backstop**, not the pacing — [`TCP_PORT_WINDOW`] is the pacing. It is
/// here so that a defect in the controller cannot turn a scan into a flood, and
/// it is set far above any rate a correct scan reaches: at this rate a
/// thousand-port scan emits in fifty milliseconds, which is already faster than
/// the round trips it is waiting on. A caller who wants a real rate limit sets
/// `--max-probe-rate`, which replaces this.
const TCP_PORT_RATE_CEILING: u32 = 20_000;

/// The fastest a **UDP** port scan puts probes on the wire, in probes per
/// second.
///
/// Two orders of magnitude below [`TCP_PORT_RATE_CEILING`], and it is a real
/// limit rather than a backstop, because UDP has no window to pace it with. A
/// UDP probe's ordinary outcome is silence and its replies name no attempt, so
/// neither half of the congestion signal exists (see
/// [`congestion`](crate::scanner::pacing::congestion)) and the scan is held to a
/// fixed rate instead.
///
/// The rate is set against the thing that actually answers a UDP probe. Most
/// UDP verdicts come from an ICMP port unreachable, and a Linux host emits those
/// under a token bucket that refills at roughly one per second; a burst that
/// outruns it does not merely go unanswered, it manufactures
/// [`OpenFiltered`](crate::model::port::PortState::OpenFiltered) verdicts on
/// ports that are closed. Spread across the hosts of a shuffled scan this is
/// survivable; aimed at one host it is the whole result.
///
/// **This number is inherited reasoning, not a measurement.** The sweep's rate
/// was measured; this is set an order of magnitude below it because the
/// per-target load is an order of magnitude higher, and that is an argument
/// rather than an experiment.
const UDP_PORT_RATE_PER_SEC: u32 = 400;

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
pub(super) fn pacing_for(rate_per_sec: u32) -> (Duration, usize) {
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

/// Sends the real probe among its already-built decoy probes, in random order,
/// and returns the real probe's send outcome.
///
/// The randomisation is of the wire order, so an observer cannot pick the real
/// source out of the decoys by position. A decoy is sent and forgotten —
/// nothing about it is recorded — which is what keeps a decoy's reply from ever
/// resolving a port. With no decoys this is one ordinary send.
pub(super) fn emit_among_decoys(
    sender: &dyn ProbeSender,
    dst: IpAddr,
    emission: Emission,
    real_src: IpAddr,
    real_packet: &[u8],
    decoy_packets: &[(IpAddr, Vec<u8>)],
) -> Result<(), SendError> {
    if decoy_packets.is_empty() {
        return sender.send(real_packet, real_src, dst, emission);
    }

    use rand::seq::SliceRandom;

    // The real probe is flagged rather than found by address, so a caller that
    // lists its own address among the decoys still gets its real send back.
    let mut probes: Vec<(IpAddr, &[u8], bool)> = Vec::with_capacity(1 + decoy_packets.len());
    probes.push((real_src, real_packet, true));
    for (src, packet) in decoy_packets {
        probes.push((*src, packet.as_slice(), false));
    }
    probes.shuffle(&mut rand::rng());

    let mut real_result = None;
    for (src, packet, is_real) in &probes {
        let result = sender.send(packet, *src, dst, emission);
        if *is_real {
            real_result = Some(result);
        }
    }
    real_result.expect("the real probe is always among those sent")
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
    src_port_override: Option<u16>,
    emission: Emission,
    shaping: SegmentShaping,
    decoys: &[IpAddr],
    faults: &mut SendFaults,
) -> Option<SynToken> {
    // A caller who pinned a source port gets that port; otherwise a fresh
    // random high port, which is this sweep's default and is what makes a
    // retried probe measurable — see the field this override travels on.
    let src_port: u16 = src_port_override.unwrap_or_else(|| rand::random_range(50_000..u16::MAX));
    let seq_num: u32 = rand::random_range(0..=u32::MAX);

    let packet = match protocol::tcp::create_probe_shaped(
        TcpScanTechnique::Syn,
        &src_addr,
        &dst_addr,
        src_port,
        dst_port,
        seq_num,
        shaping.padding,
        shaping.bad_tcp_checksum,
    ) {
        Ok(pkt) => pkt,
        Err(e) => {
            error!(
                verbosity = 2,
                "failed to create SYN packet for {dst_addr}:{dst_port}: {e}"
            );
            return None;
        }
    };

    // A decoy from each address of the target's own family, built with its own
    // port and sequence so it is a probe in its own right, and the same shaping
    // so no decoy is the odd one out carrying a different-looking checksum.
    let decoy_packets: Vec<(IpAddr, Vec<u8>)> = decoys
        .iter()
        .filter(|decoy| decoy.is_ipv4() == dst_addr.is_ipv4())
        .filter_map(|&decoy| {
            protocol::tcp::create_probe_shaped(
                TcpScanTechnique::Syn,
                &decoy,
                &dst_addr,
                rand::random_range(50_000..u16::MAX),
                dst_port,
                rand::random_range(0..=u32::MAX),
                shaping.padding,
                shaping.bad_tcp_checksum,
            )
            .ok()
            .map(|packet| (decoy, packet))
        })
        .collect();

    match emit_among_decoys(
        sender,
        dst_addr,
        emission,
        src_addr,
        &packet,
        &decoy_packets,
    ) {
        Ok(_) => {
            success!(verbosity = 2, "sent SYN probe to {dst_addr}:{dst_port}");
            Some(SynToken {
                seq: seq_num,
                src_port,
            })
        }
        Err(e) => {
            // Which of the two this was decides how it is reported; see
            // `SendFaults`. Either way it is said once per kind rather than once
            // per probe: a dual-stack sweep of a range has one unroutable
            // address per name in it, and sixteen identical lines bury
            // everything else.
            if e.is_unroutable() {
                // **Not an error, and not logged as one here at all.** An
                // address this host has no route to is ordinary, the caller
                // reports it once against the address, and an `error!` would
                // print regardless of verbosity — errors are exempt from it,
                // which is exactly right for a scan that broke and exactly
                // wrong for a machine that has no IPv6.
                //
                // The operating system's own words are kept for `-v`, where
                // somebody is asking why rather than being told.
                if faults.unroutable.is_none() {
                    info!(verbosity = 1, "no route to {dst_addr}: {e:#}");
                }
            } else if faults.broken.is_none() {
                // `{e:#}` rather than `{e}`: the outer message says which probe
                // failed, and the chained cause is the operating system's own
                // explanation. "Permission denied" and a full send buffer call
                // for completely different responses, and the bare wrapper
                // distinguishes neither.
                error!(
                    verbosity = 2,
                    "failed to send SYN probe to {dst_addr}:{dst_port}: {e:#}"
                );
            }
            faults.record(dst_addr, &e);
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
    emission: Emission,
    shaping: SegmentShaping,
    decoys: &[IpAddr],
    reason: &mut Option<String>,
) -> Option<()> {
    // What makes an open port answer at all: UDP has no handshake, so the
    // application itself has to recognize the request. See [`payload`].
    let payload = payload::for_port(dst_port).to_vec();

    let packet = match crate::protocols::udp::create_packet_shaped(
        &src_addr,
        &dst_addr,
        src_port,
        dst_port,
        payload,
        shaping.padding,
    ) {
        Ok(pkt) => pkt,
        Err(e) => {
            error!(
                verbosity = 2,
                "failed to create UDP packet for {dst_addr}:{dst_port}: {e}"
            );
            return None;
        }
    };

    // A decoy datagram from each address of the target's own family, from its
    // own source port so its reply falls outside this scan's capture filter, and
    // the same payload so it asks the same question the real probe does.
    let decoy_packets: Vec<(IpAddr, Vec<u8>)> = decoys
        .iter()
        .filter(|decoy| decoy.is_ipv4() == dst_addr.is_ipv4())
        .filter_map(|&decoy| {
            crate::protocols::udp::create_packet_shaped(
                &decoy,
                &dst_addr,
                rand::random_range(50_000..u16::MAX),
                dst_port,
                payload::for_port(dst_port).to_vec(),
                shaping.padding,
            )
            .ok()
            .map(|packet| (decoy, packet))
        })
        .collect();

    match emit_among_decoys(
        sender,
        dst_addr,
        emission,
        src_addr,
        &packet,
        &decoy_packets,
    ) {
        Ok(_) => {
            success!(verbosity = 2, "sent UDP probe to {dst_addr}:{dst_port}");
            Some(())
        }
        Err(e) => {
            // `{e:#}` rather than `{e}`, for the reason `send_syn` gives: the
            // chained cause is the operating system's own explanation, and
            // "No route to host" and "Permission denied" call for completely
            // different responses.
            // Once; see the same guard in `port_scan::send_tcp_probe`.
            if reason.is_none() {
                error!(
                    verbosity = 2,
                    "failed to send UDP probe to {dst_addr}:{dst_port}: {e:#}"
                );
                *reason = Some(format!("{e:#}"));
            }
            None
        }
    }
}

/// Whether `bytes` is one of the two segments a SYN probe can draw *and be
/// credited for without correlating it*.
///
/// A SYN+ACK and a RST each require the target to have received the probe and
/// answered it, and nothing else a SYN elicits sets either flag. Anything else
/// from the same address is traffic that happens to share a host with the scan.
///
/// **A challenge ACK is deliberately excluded, though it is a genuine answer.**
/// It says a listener holds a connection half-open, which the port scanner acts
/// on — but the port scanner earns that by checking the probe's nonce against
/// its ledger, and this sweep has no ledger and checks nothing. A bare ACK is
/// the commonest segment on any network: every established connection emits a
/// stream of them, and a scan of an address somebody is talking to would credit
/// the host on the strength of that conversation. The flags of a SYN+ACK or a
/// RST are their own correlation; the flags of an ACK are not.
///
/// The asymmetry is the point. Evidence usable where it can be tied to a probe
/// is not usable where it cannot.
fn answers_a_syn_probe(bytes: &[u8]) -> bool {
    TcpPacket::new(bytes)
        .and_then(|tcp| protocol::tcp::classify_probe_response(&tcp))
        .is_some_and(|reply| !matches!(reply, TcpReply::ChallengeAck))
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
    /// The source port every probe leaves from, when a caller pinned one.
    ///
    /// `None` is the default and keeps this sweep's own behaviour: a fresh
    /// random high port per probe, which together with a fresh sequence number
    /// is what lets a reply name the attempt it answers. An evasion profile that
    /// set a source port replaces that with the one port — the sequence number
    /// still varies per attempt, so a reply is still attributable — so a probe
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
    /// The targets *this sweep* has seen answer.
    ///
    /// A set rather than a counter, and kept here rather than read off the
    /// store, because the two answer different questions. `write_host` reports
    /// whether the **store** gained a host, which in a discovery-only phase is
    /// the same thing and in a port-scan phase is not: discovery runs there as
    /// enrichment beside the port scanner, the host almost always exists
    /// already, and every one of this sweep's own answers would report "not
    /// new". The count then never reaches `ips.len()`, so the
    /// [`AllResponded`](StopReason::AllResponded) exit is silently unavailable
    /// in exactly the phase where discovery is cheapest.
    ///
    /// Not taken from the [`ProbeLedger`] either, though it is the obvious
    /// source. `resolve` retires a probe, so a duplicate reply correctly reports
    /// nothing — but an exhausted probe is drained out of the ledger entirely,
    /// and a reply arriving after that would go uncredited. This is the same
    /// shape [`LocalScanner`](super::local::LocalScanner) settled on when its
    /// mirror of this defect was fixed.
    responded: HashSet<IpAddr>,
    /// Per-run counters, so a sweep that finds fewer hosts than it should can be
    /// attributed to loss, to its own deadline, or to correlation rather than
    /// guessed at. Reported once when the loop exits.
    audit: ProbeAudit,
    /// Why probes that could not be sent could not be sent, if any could not.
    ///
    /// Kept so the reason survives into the report. The count of failed sends is
    /// already in the audit, but a count cannot distinguish a host with no route
    /// to the target from one refusing raw sockets, and those call for opposite
    /// responses from whoever is reading.
    faults: SendFaults,
}

/// Why probes did not reach the wire, split by what that says.
///
/// **Two kinds, because they are not the same finding.** A send path that will
/// not work is a strategy that did not run, and a caller has to hear that the
/// scan covered less than it was asked to. An address this host has no route to
/// is ordinary — a dual-stack name on an IPv4-only network resolves to an AAAA
/// nobody here can reach — and reporting it as a broken scan makes every such
/// scan look partial, which trains a reader to ignore the one that is.
///
/// Each keeps the first of its kind rather than all of them: sixteen identical
/// "no route to host" lines say nothing the first does not.
#[derive(Debug, Default)]
struct SendFaults {
    /// The first failure that says this host's send path is the problem.
    broken: Option<String>,
    /// The first address this host has no route to, and what it said.
    unroutable: Option<(IpAddr, String)>,
    /// How many addresses had no route.
    unroutable_count: u64,
    /// Which addresses those were, so the report can name them.
    ///
    /// The count above is what a message says; this is what a consumer reads. A
    /// number cannot tell somebody *which* of their targets went uncovered, and
    /// that is the only part they can act on.
    addresses: std::collections::BTreeSet<IpAddr>,
}

impl SendFaults {
    /// Files one failed send against the address it was aimed at.
    fn record(&mut self, target: IpAddr, error: &SendError) {
        if error.is_unroutable() {
            self.unroutable_count += 1;
            self.addresses.insert(target);
            self.unroutable
                .get_or_insert_with(|| (target, error.to_string()));
        } else {
            self.broken.get_or_insert_with(|| error.to_string());
        }
    }
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

            let all_responded = self.ips.len() == self.responded.len() as u128;
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

        // What the sweep did not earn a verdict for, so a resumed one asks again
        // rather than skipping it. None of these carries a position: a probe
        // still mid-schedule was cut off rather than spent, one still queued was
        // never sent, and one with no route was never asked.
        let outstanding = self.ledger.drain_unresolved().len() as u64;
        self.ctx.record_many(Outcome::Interrupted, outstanding);
        self.ctx
            .record_many(Outcome::Unasked, self.pending.len() as u64);
        // Distinct addresses rather than failed sends: a target with no route
        // fails on every retry, and counting each of those would report more
        // unreached addresses than the sweep had.
        self.ctx
            .record_many(Outcome::Unroutable, self.faults.addresses.len() as u64);

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
        // route is not a strategy that did not run — the strategy ran, and that
        // address is not reachable from here. Recorded as a failure it made
        // every scan of a dual-stack name on an IPv4-only network report itself
        // as partial, which is the surest way to teach a reader to ignore the
        // warning that matters. It is recorded against the address instead, just
        // below.
        if let Some(reason) = &self.faults.broken {
            let broken = self.audit.sends_failed - self.faults.unroutable_count;
            self.ctx.record_failure(
                ScannerKind::Routed,
                format!(
                    "{broken} of {} probes could not be sent: {reason}",
                    self.audit.sends_attempted,
                ),
            );
        }

        // Said once, at the level a person watching a scan sees: an address they
        // named was not covered, and nothing else in the output would tell them
        // so. Nothing is wrong with the scan, so it carries neither an error
        // prefix nor the operating system's errno — that is a diagnostic detail
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
        self.audit
            .report("routed-discovery", targets, reason, capture, None);
        self.ctx.record_probe_stats(self.audit.stats(
            ScannerKind::Routed,
            targets,
            reason,
            capture,
            None,
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
            src_port,
            emission,
            shaping,
            decoys,
            deadline: AdaptiveDeadline::new(deadline_config, target_count),
            dns_tx,
            ledger: ProbeLedger::new(retry, target_count),
            due: Vec::new(),
            pending: order.into_iter(),
            retries: VecDeque::new(),
            send_tick,
            batch,
            responded: HashSet::new(),
            audit: ProbeAudit::new(),
            faults: SendFaults::default(),
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

        // The address answered, which is a verdict however the reply was timed.
        self.ctx.settle_address(ip, Settled::Answered);

        let resolution = self.resolve_probe(ip, bytes, now);
        let rtt = resolution.and_then(|resolution| resolution.rtt);
        if rtt.is_none() {
            self.audit.record_reply_without_rtt();
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

        if self.responded.insert(ip) {
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
            seq: protocol::tcp::echoed_nonce(
                TcpScanTechnique::Syn,
                &tcp,
                self.shaping.padding.unwrap_or(0),
            ),
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
            match event {
                Due::Retry { key, .. } => self.retries.push_back(key),
                // The budget is spent, which is the moment silence stops being
                // provisional and becomes a verdict this sweep earned. Only
                // probes that actually left are armed, so nothing settled here
                // went unasked.
                Due::Exhausted { key, .. } => self.ctx.settle_address(key, Settled::Exhausted),
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
            self.src_port,
            self.emission,
            self.shaping,
            &self.decoys,
            &mut self.faults,
        );
        self.audit.record_send(token.is_some());

        if let Some(token) = token {
            self.ledger.arm(target, target, token, (), now);
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

    /// A sender that refuses one chosen source and accepts every other, so a
    /// test can tell whose send outcome came back.
    struct RefusesOneSource(IpAddr);
    impl ProbeSender for RefusesOneSource {
        fn send(
            &self,
            _segment: &[u8],
            src: IpAddr,
            _dst: IpAddr,
            _emission: Emission,
        ) -> Result<(), SendError> {
            if src == self.0 {
                Err(SendError::Unsupported("refused for the test"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn emit_among_decoys_sends_every_probe_and_reports_the_real_ones_outcome() {
        use crate::transport::probe::MockSender;

        let real = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let real_packet = vec![0xAAu8, 0xBB];
        let decoys = vec![
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), vec![1u8, 1]),
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), vec![2u8, 2]),
        ];

        // Every probe reaches the wire — the real one and both decoys — and the
        // real source appears exactly once.
        let mock = MockSender::default();
        assert!(
            emit_among_decoys(&mock, dst, Emission::routed(), real, &real_packet, &decoys).is_ok()
        );
        let sent = mock.sent.lock().unwrap();
        assert_eq!(sent.len(), 3, "the real probe and both decoys are all sent");
        assert_eq!(sent.iter().filter(|(_, src, _)| *src == real).count(), 1);
        drop(sent);

        // With no decoys it is a single ordinary send.
        let mock = MockSender::default();
        emit_among_decoys(&mock, dst, Emission::routed(), real, &real_packet, &[]).unwrap();
        assert_eq!(mock.sent.lock().unwrap().len(), 1);

        // The outcome returned is the real probe's own, never a decoy's — which
        // is what lets a caller keep a token only when *its* probe was sent, the
        // root of the invariant that a decoy resolves no port.
        let refusing_the_real = RefusesOneSource(real);
        assert!(
            emit_among_decoys(
                &refusing_the_real,
                dst,
                Emission::routed(),
                real,
                &real_packet,
                &decoys
            )
            .is_err()
        );
        let refusing_a_decoy = RefusesOneSource(decoys[0].0);
        assert!(
            emit_among_decoys(
                &refusing_a_decoy,
                dst,
                Emission::routed(),
                real,
                &real_packet,
                &decoys
            )
            .is_ok()
        );
    }

    /// The two kinds of send failure are kept apart, and each keeps only its
    /// first.
    ///
    /// They are reported through different channels — a broken send path is a
    /// strategy that did not run and reaches the report as a failure; an
    /// address with no route is said once and changes nothing about the scan's
    /// standing. Collapsed into one counter, a dual-stack name on an IPv4-only
    /// network made every scan of it report itself partial, which teaches a
    /// reader to ignore the warning that matters.
    #[test]
    fn a_missing_route_is_counted_apart_from_a_broken_send_path() {
        let unreachable = |address: &str| {
            SendError::from_io(
                anyhow::Error::new(std::io::Error::new(
                    std::io::ErrorKind::HostUnreachable,
                    "No route to host",
                ))
                .context(format!("failed to send to {address}")),
            )
        };

        let mut faults = SendFaults::default();
        let first: IpAddr = "2001:db8::1".parse().expect("literal");
        let second: IpAddr = "2001:db8::2".parse().expect("literal");

        faults.record(first, &unreachable("2001:db8::1"));
        faults.record(second, &unreachable("2001:db8::2"));

        assert_eq!(faults.unroutable_count, 2);
        assert_eq!(
            faults.unroutable.as_ref().map(|(address, _)| *address),
            Some(first),
            "the first address is kept, not the last"
        );
        assert!(
            faults.broken.is_none(),
            "no route to somewhere is not a scan that could not run"
        );

        faults.record(
            first,
            &SendError::from_io(anyhow::Error::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Operation not permitted",
            ))),
        );

        assert!(faults.broken.is_some(), "and this one is");
        assert_eq!(faults.unroutable_count, 2, "which is a separate tally");
    }

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
