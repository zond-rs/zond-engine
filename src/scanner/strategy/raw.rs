// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What every raw strategy is built from
//!
//! The layer under the strategies that open a raw socket: how a probe reaches
//! the wire, what identifies one attempt, and the timing profiles a probe over
//! a routed path is held to. Nothing here scans anything. It is what
//! [`routed`](super::routed), [`ports`](super::ports),
//! [`identify`](super::identify) and [`topology`](super::topology) have in
//! common, gathered so that none of them has to reach into another.
//!
//! ## Why it is a module rather than part of a scanner
//!
//! It used to live in `routed`, beside the SYN sweep, because the sweep was the
//! first thing to need it. Everything raw that arrived afterwards — four port
//! scanners, two operating-system probes, a trace and a filter probe — was then
//! written as a submodule of the sweep, which is not what any of them is. The
//! contents did not change; what changed is that `routed` no longer means both
//! "reached through a gateway" and "opens a raw socket".
//!
//! ## What is shared and what deliberately is not
//!
//! The timings here are the ones a probe over a routed path shares whatever it
//! is asking about: a SYN sweep and a TCP port scan cross the same links and
//! wait on the same round trips. What each *scan* does with them is its own —
//! [`ports`](super::ports) holds the profiles that belong to a port scan, and
//! the UDP scanner keeps its own outright, because an ICMP rate limiter is not
//! a property of the path.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use crate::evasion::SegmentShaping;
use crate::model::technique::TcpScanTechnique;
use crate::protocols as protocol;
use crate::scanner::pacing::deadline::AdaptiveDeadlineConfig;
use crate::scanner::pacing::retry::{RetryPolicy, SilentHostPolicy};
use crate::scanner::pacing::timer::ScanBudget;
use crate::scanner::payload;
use crate::transport::probe::{Emission, ProbeSender, SendError};
use crate::{error, info, success};

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
pub(super) const DEADLINE_CONFIG: AdaptiveDeadlineConfig = AdaptiveDeadlineConfig::new(
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
pub(super) const RETRY_POLICY: RetryPolicy = RetryPolicy::new(
    3,
    Duration::from_millis(200),
    Duration::from_millis(25),
    Duration::from_secs(2),
    2.0,
    0.2,
    Some(SilentHostPolicy::new(32, 2)),
);

/// The shortest interval the send ticker is asked to keep.
///
/// A tokio interval cannot be relied on much below a millisecond, so a rate
/// faster than one probe per tick is expressed by releasing several per tick
/// rather than by ticking faster. Below that the tick lengthens instead - see
/// [`pacing_for`], where getting this wrong is silent.
pub(super) const MIN_SEND_TICK: Duration = Duration::from_millis(1);

/// The rate a scan runs at, given what the caller asked for.
///
/// A configured zero is a caller error rather than an instruction to stall, and
/// falls back to the engine's own rate the same way an unset one does. Pacing at
/// one probe a second would honour the number and not the intent.
pub(super) fn rate_or(configured: Option<NonZeroU32>, default: NonZeroU32) -> NonZeroU32 {
    configured.unwrap_or(default)
}

/// How often to wake and how many probes to release each time, for a sweep
/// paced at `rate_per_sec`.
///
/// The batch is chosen first and the interval derived from it, so the product
/// is the rate that was asked for rather than something near it. Fixing the
/// interval and rounding the batch instead is the obvious way to write this and
/// it is wrong in a way nothing reports: a batch cannot be less than one probe,
/// so every rate below one probe per tick collapses to the same value and a
/// sweep configured for 500 probes a second quietly runs at 1000.
pub(super) fn pacing_for(rate_per_sec: NonZeroU32) -> (Duration, usize) {
    let rate = f64::from(rate_per_sec.get());
    let batch = (rate * MIN_SEND_TICK.as_secs_f64()).round().max(1.0);

    (Duration::from_secs_f64(batch / rate), batch as usize)
}

/// A TCP sequence number, which is what a SYN attempt is recognised by when
/// its answer echoes it back. See [`SynToken`].
pub(super) type SeqNum = u32;

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
    /// The sequence number this attempt carried, returned in the
    /// acknowledgement of whatever answers it.
    pub seq: SeqNum,
    /// The port this attempt left from, and so where its reply is addressed.
    pub src_port: u16,
}

/// What a scan's evasion settings come to for one probe: how the packet reaches
/// the wire, how its segment is shaped, and the decoys it travels among.
///
/// All three are derived from one
/// [`EvasionProfile`](crate::evasion::EvasionProfile).
#[derive(Debug, Clone, Copy)]
pub(super) struct EvasionParts<'a> {
    /// How the packet is put on the wire, including any fragmentation.
    pub emission: Emission,
    /// Padding and checksum corruption applied to the Layer-4 segment.
    pub shaping: SegmentShaping,
    /// Addresses the real probe is sent among. Empty for an ordinary send.
    pub decoys: &'a [IpAddr],
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
pub(super) fn send_syn(
    sender: &dyn ProbeSender,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    dst_port: u16,
    src_port_override: Option<u16>,
    evasion: EvasionParts<'_>,
    faults: &mut SendFaults,
) -> Option<SynToken> {
    let EvasionParts {
        emission,
        shaping,
        decoys,
    } = evasion;
    // A caller who pinned a source port gets that port; otherwise a fresh
    // random high port, which is this sweep's default and is what makes a
    // retried probe measurable — see the field this override travels on.
    let src_port: u16 = src_port_override.unwrap_or_else(|| rand::random_range(50_000..u16::MAX));
    let seq_num: u32 = rand::random_range(0..=u32::MAX);

    let packet = match protocol::tcp::build_probe_shaped(
        TcpScanTechnique::Syn,
        src_addr,
        dst_addr,
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
            protocol::tcp::build_probe_shaped(
                TcpScanTechnique::Syn,
                decoy,
                dst_addr,
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
pub(super) fn send_udp(
    sender: &dyn ProbeSender,
    src_port: u16,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    dst_port: u16,
    evasion: EvasionParts<'_>,
    reason: &mut Option<String>,
) -> Option<()> {
    let EvasionParts {
        emission,
        shaping,
        decoys,
    } = evasion;
    // What makes an open port answer at all: UDP has no handshake, so the
    // application itself has to recognize the request. See [`payload`].
    let payload = payload::for_port(dst_port).to_vec();

    let packet = match crate::protocols::udp::build_packet_shaped(
        src_addr,
        dst_addr,
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
            crate::protocols::udp::build_packet_shaped(
                decoy,
                dst_addr,
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
            // Once; see the same guard in `ports::tcp::send_tcp_probe`.
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
pub(super) struct SendFaults {
    /// The first failure that says this host's send path is the problem.
    pub(super) broken: Option<String>,
    /// The first address this host has no route to, and what it said.
    pub(super) unroutable: Option<(IpAddr, String)>,
    /// How many addresses had no route.
    pub(super) unroutable_count: u64,
    /// Which addresses those were, so the report can name them.
    ///
    /// The count above is what a message says; this is what a consumer reads. A
    /// number cannot tell somebody *which* of their targets went uncovered, and
    /// that is the only part they can act on.
    pub(super) addresses: std::collections::BTreeSet<IpAddr>,
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
    use crate::scanner::strategy::routed::PROBE_RATE_PER_SEC;
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
            SendError::from_io(std::io::Error::new(
                std::io::ErrorKind::HostUnreachable,
                format!("failed to send to {address}: No route to host"),
            ))
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
            &SendError::from_io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Operation not permitted",
            )),
        );

        assert!(faults.broken.is_some(), "and this one is");
        assert_eq!(faults.unroutable_count, 2, "which is a separate tally");
    }

    /// The rate a sweep actually paces itself at, which is what the pair has
    /// to reproduce however it is split between the two.
    fn effective_rate(rate_per_sec: u32) -> f64 {
        let (tick, batch) = pacing_for(NonZeroU32::new(rate_per_sec).expect("a non-zero rate"));
        batch as f64 / tick.as_secs_f64()
    }

    #[test]
    fn a_fast_rate_is_expressed_as_a_batch_on_the_shortest_tick() {
        assert_eq!(
            pacing_for(NonZeroU32::new(2_000).unwrap()),
            (MIN_SEND_TICK, 2)
        );
        assert_eq!(
            pacing_for(NonZeroU32::new(100_000).unwrap()),
            (MIN_SEND_TICK, 100)
        );
    }

    /// The failure this pair exists to prevent. A batch cannot be less than one
    /// probe, so holding the tick fixed collapses every rate below one probe
    /// per tick onto the same value - and a sweep asked for 500 a second runs
    /// at 1000 without saying so.
    #[test]
    fn a_slow_rate_lengthens_the_tick_rather_than_doubling_the_rate() {
        assert_eq!(
            pacing_for(NonZeroU32::new(500).unwrap()),
            (Duration::from_millis(2), 1)
        );
        assert_eq!(
            pacing_for(NonZeroU32::new(100).unwrap()),
            (Duration::from_millis(10), 1)
        );
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
    ///
    /// It can no longer be asked at any level. `pacing_for` takes a
    /// [`NonZeroU32`] and so does the configuration above it, so the fallback
    /// this holds is now only the one a caller means: no ceiling at all.
    ///
    /// Zero used to arrive here as `Some(0)` and resolve to the engine's own
    /// rate, at three call sites of which only this one went through `rate_or`,
    /// while the report recorded the ceiling the caller believed they had set.
    #[test]
    fn an_unset_rate_falls_back_to_the_default_and_a_set_one_is_obeyed() {
        assert_eq!(rate_or(None, PROBE_RATE_PER_SEC), PROBE_RATE_PER_SEC);
        assert_eq!(
            rate_or(NonZeroU32::new(500), PROBE_RATE_PER_SEC).get(),
            500,
            "a rate the caller meant is the rate they get"
        );
    }
}
