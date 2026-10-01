// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What every raw strategy is built from
//!
//! What the raw-socket strategies ([`routed`](super::routed),
//! [`ports`](super::ports), [`identify`](super::identify) and
//! [`topology`](super::topology)) share: how a probe reaches the wire, what
//! identifies one attempt, and the timing profiles of a probe over a routed
//! path.
//!
//! [`ports`](super::ports) holds the profiles specific to a port scan, and the
//! UDP scanner keeps its own, because an ICMP rate limiter is not a property of
//! the path. `neighbors` holds a probe until the hardware address of the
//! neighbour it is framed to is known.

pub(super) mod neighbors;

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use crate::evasion::SegmentShaping;
use crate::logging::error;
use crate::model::technique::TcpScanTechnique;
use crate::protocols as protocol;
use crate::scanner::pacing::deadline::AdaptiveDeadlineConfig;
use crate::scanner::pacing::retry::{RetryPolicy, SilentHostPolicy};
use crate::scanner::pacing::timer::ScanBudget;
use crate::scanner::payload;
use crate::transport::probe::{Emission, ProbeSender, SendError};
use crate::{info, success};

/// How long a routed sweep or port scan runs and how it adapts.
///
/// Routed targets span a wide range of round trips, so the extremes matter
/// more than the average:
///
/// - **Silence floor.** The silence tolerance follows observed round trips,
///   which the fastest responders dominate. The floor is set against the tail
///   of the distribution, so slower targets still in flight are waited for.
/// - **Hard budget.** The base gives a distant target room for several round
///   trips; the per-target term covers the send burst and the spread of
///   arrivals. The ceiling only bounds a scan whose pace nobody derived. The
///   port scanners and the routed sweep supply their size and pace and are not
///   clamped by it: clamped, a 65 535-port scan would stop at 60 of its 104
///   seconds, and a silent `/16` at 60 of 246.
///
/// The minimum runtime keeps silence from stopping a scan before any answer
/// could have arrived.
///
/// A generous budget costs nothing when a scan succeeds, since
/// [`RoutedScanner`](super::routed::RoutedScanner) and
/// [`TcpPortScanner`](super::ports::TcpPortScanner) exit once nothing is
/// pending.
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

/// How a SYN probe is retransmitted, shared by the sweep and the TCP port scan.
///
/// Two attempts distinguish a lost packet from a silent host; on a large range
/// the third recovers the last few percent. More would not help: loss from
/// sending faster than a path absorbs hits every attempt alike, and on an empty
/// range, the ordinary case, each attempt costs the whole range's packets. Pace
/// with [`PROBE_RATE_PER_SEC`](super::routed::PROBE_RATE_PER_SEC) instead.
///
/// The 200 ms starting timeout covers an unmeasured path, such as one across an
/// ocean, without tripling its traffic. Once a target answers its own round
/// trip governs, and on a local path that falls toward the 25 ms floor.
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
/// A tokio interval is unreliable much below a millisecond, so a faster rate
/// releases several probes per tick and a slower one lengthens the tick; see
/// [`pacing_for`].
pub(super) const MIN_SEND_TICK: Duration = Duration::from_millis(1);

/// The rate a scan runs at, given the bounds the caller asked for.
///
/// `default` applies when no `ceiling` is set. `floor` lifts the default, for a
/// plan large enough that the budget runs out before the targets do, but never
/// lifts a `ceiling` the caller set: that is a safety limit.
///
/// A sweep and a UDP scan are paced at this rate; a TCP scan reads it as a
/// ceiling and paces itself on
/// [`CongestionWindow`](crate::scanner::pacing::congestion::CongestionWindow).
pub(super) fn rate_within(
    ceiling: Option<NonZeroU32>,
    floor: Option<NonZeroU32>,
    default: NonZeroU32,
) -> NonZeroU32 {
    let rate = ceiling.unwrap_or(default);
    let lifted = match floor {
        Some(floor) => rate.max(floor),
        None => rate,
    };
    match ceiling {
        Some(ceiling) => lifted.min(ceiling),
        None => lifted,
    }
}

/// How often to wake and how many probes to release each time, for a sweep
/// paced at `rate_per_sec`.
///
/// The batch is chosen first and the interval derived from it, so the product
/// is the requested rate. Fixing the interval would silently collapse every
/// rate below one probe per tick onto 1000/s, since a batch cannot be below one.
pub(super) fn pacing_for(rate_per_sec: NonZeroU32) -> (Duration, usize) {
    let rate = f64::from(rate_per_sec.get());
    let batch = (rate * MIN_SEND_TICK.as_secs_f64()).round().max(1.0);

    (Duration::from_secs_f64(batch / rate), batch as usize)
}

/// A TCP sequence number, echoed back in the answer to a SYN. See
/// [`SynToken`].
pub(super) type SeqNum = u32;

/// What identifies one SYN attempt on the wire.
///
/// The sequence number comes back in the reply's acknowledgement and the reply
/// is addressed to the source port, so together they tie a segment to this
/// probe. A fresh pair per attempt lets the reply name the attempt it answers,
/// so a retried probe is still measurable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynToken {
    /// The sequence number this attempt carried, returned in the answer's
    /// acknowledgement.
    pub seq: SeqNum,
    /// The port this attempt left from, where its reply is addressed.
    pub src_port: u16,
}

impl SynToken {
    /// A token for a new attempt: a random sequence number, and `src_port` if
    /// the caller pinned one (a port a filter trusts), else a random high port.
    pub(super) fn fresh(src_port: Option<u16>) -> Self {
        Self {
            seq: rand::random_range(0..=u32::MAX),
            src_port: src_port.unwrap_or_else(|| rand::random_range(50_000..u16::MAX)),
        }
    }
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
/// The random order keeps an observer from picking the real source by
/// position. Nothing about a decoy is recorded, so a decoy's reply never
/// resolves a port. With no decoys this is one ordinary send.
pub(super) fn emit_among_decoys(
    sender: &dyn ProbeSender,
    dst: IpAddr,
    zone: Option<u32>,
    emission: Emission,
    real_src: IpAddr,
    real_packet: &[u8],
    decoy_packets: &[(IpAddr, Vec<u8>)],
) -> Result<(), SendError> {
    if decoy_packets.is_empty() {
        return sender.send(real_packet, real_src, dst, zone, emission);
    }

    use rand::seq::SliceRandom;

    // Flagged, not found by address, in case a decoy repeats the real source.
    let mut probes: Vec<(IpAddr, &[u8], bool)> = Vec::with_capacity(1 + decoy_packets.len());
    probes.push((real_src, real_packet, true));
    for (src, packet) in decoy_packets {
        probes.push((*src, packet.as_slice(), false));
    }
    probes.shuffle(&mut rand::rng());

    let mut real_result = None;
    for (src, packet, is_real) in &probes {
        let result = sender.send(packet, *src, dst, zone, emission);
        if *is_real {
            real_result = Some(result);
        }
    }
    real_result.expect("the real probe is always among those sent")
}

/// Sends a single SCTP INIT from `src_addr` to `dst_addr:dst_port` through
/// `sender` and logs the outcome. On success returns the Initiate Tag it
/// carried, which a conformant peer echoes back, tying the reply to this
/// attempt.
///
/// The SCTP counterpart of [`send_syn`], reporting failures the same way. No
/// segment shaping: SCTP uses a CRC32c, and padding a chunk changes what the
/// receiver reads. Decoys still apply. Building cannot fail, since the SCTP
/// checksum covers no pseudo-header.
#[allow(clippy::too_many_arguments)]
pub(super) fn send_init(
    sender: &dyn ProbeSender,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    dst_zone: Option<u32>,
    dst_port: u16,
    src_port: u16,
    decoys: &[IpAddr],
    emission: Emission,
    faults: &mut SendFaults,
) -> Option<u32> {
    // RFC 4960 §3.3.2: the Initiate Tag must be non-zero.
    let tag: u32 = rand::random_range(1..=u32::MAX);
    let packet = protocol::sctp::build_init_probe(src_port, dst_port, tag);

    // One decoy per address of the target's family, each with its own port and
    // tag so none stands out.
    let decoy_packets: Vec<(IpAddr, Vec<u8>)> = decoys
        .iter()
        .filter(|decoy| decoy.is_ipv4() == dst_addr.is_ipv4())
        .map(|&decoy| {
            let packet = protocol::sctp::build_init_probe(
                rand::random_range(50_000..u16::MAX),
                dst_port,
                rand::random_range(1..=u32::MAX),
            );
            (decoy, packet)
        })
        .collect();

    match emit_among_decoys(
        sender,
        dst_addr,
        dst_zone,
        emission,
        src_addr,
        &packet,
        &decoy_packets,
    ) {
        Ok(()) => {
            success!(verbosity = 2, "sent SCTP init to {dst_addr}:{dst_port}");
            Some(tag)
        }
        Err(e) => {
            if faults.hold(dst_addr, &e).is_none() {
                faults.record(dst_addr, &e);
            }
            None
        }
    }
}

/// Sends a single TCP SYN packet from `src_addr` to `dst_addr:dst_port` through
/// `sender`, carrying `token`'s sequence number and source port, and logs the
/// outcome. Returns whether it reached the wire.
///
/// The caller draws the token with [`SynToken::fresh`] because one attempt may
/// be several packets: a sweep asking one address on several ports sends them
/// under one token, so the ledger needs one entry per address.
///
/// A failure is filed in `faults`, so the report can say why probes never left;
/// in a host count that looks the same as a probe nobody answered.
#[allow(clippy::too_many_arguments)]
pub(super) fn send_syn(
    sender: &dyn ProbeSender,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    dst_zone: Option<u32>,
    dst_port: u16,
    token: SynToken,
    evasion: EvasionParts<'_>,
    faults: &mut SendFaults,
) -> bool {
    let EvasionParts {
        emission,
        shaping,
        decoys,
    } = evasion;
    let SynToken {
        seq: seq_num,
        src_port,
    } = token;

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
            return false;
        }
    };

    // One decoy per address of the target's family, with its own port and
    // sequence and the same shaping, so none stands out.
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
        dst_zone,
        emission,
        src_addr,
        &packet,
        &decoy_packets,
    ) {
        Ok(_) => {
            success!(verbosity = 2, "sent SYN probe to {dst_addr}:{dst_port}");
            true
        }
        Err(e) if faults.hold(dst_addr, &e).is_some() => false,
        Err(e) => {
            // Logged once per kind (see `SendFaults`): a dual-stack sweep has
            // one unroutable address per name, and repeated lines bury the rest.
            if e.is_unroutable() {
                // Ordinary, so not an `error!`, which prints at any verbosity and
                // would fire on every machine without IPv6.
                if faults.unroutable.is_none() {
                    info!(verbosity = 2, "no route to {dst_addr}: {e:#}");
                }
            } else if faults.broken.is_none() {
                // `{e:#}` includes the OS cause: "Permission denied" and a full
                // send buffer need different fixes.
                error!(
                    verbosity = 2,
                    "failed to send SYN probe to {dst_addr}:{dst_port}: {e:#}"
                );
            }
            faults.record(dst_addr, &e);
            false
        }
    }
}

/// Sends a single UDP probe from `src_port` to `dst_addr:dst_port` through
/// `sender` and logs the outcome.
///
/// Every UDP probe in a scan leaves from the same `src_port`, unlike
/// [`send_syn`]'s random one. The capture filter narrows replies to that port,
/// and the datagram quoted in an ICMP error is checked against it.
///
/// A failure is returned unlogged for the port scan to classify and report
/// once. Unsent probes would otherwise read as every port `OpenOrNoReply`, as
/// if a filter dropped everything. See
/// [`RawProbeScan::record_send`](super::ports::RawProbeScan::record_send).
#[allow(clippy::too_many_arguments)]
pub(super) fn send_udp(
    sender: &dyn ProbeSender,
    src_port: u16,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    dst_zone: Option<u32>,
    dst_port: u16,
    evasion: EvasionParts<'_>,
) -> Result<(), SendError> {
    let EvasionParts {
        emission,
        shaping,
        decoys,
    } = evasion;
    // UDP has no handshake, so an open port answers only a request its
    // application recognizes. See [`payload`].
    let payload = payload::for_port(dst_port).to_vec();

    // Worded as the link-layer sender words a frame it could not build.
    let packet = crate::protocols::udp::build_packet_shaped(
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        payload,
        shaping.padding,
    )
    .map_err(|e| SendError::Refused(format!("the UDP probe could not be built: {e}")))?;

    // One decoy per address of the target's family, from its own source port so
    // its reply falls outside the capture filter, with the same payload.
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

    emit_among_decoys(
        sender,
        dst_addr,
        dst_zone,
        emission,
        src_addr,
        &packet,
        &decoy_packets,
    )?;
    success!(verbosity = 2, "sent UDP probe to {dst_addr}:{dst_port}");
    Ok(())
}

/// Why probes did not reach the wire, split by what that says.
///
/// A broken send path means the strategy did not run, and the caller must
/// hear that coverage fell short. An address with no route is ordinary (a
/// dual-stack name on an IPv4-only network), and reporting it as a broken scan
/// would make every such scan look partial. Each kind keeps its first failure.
///
/// A first refusal for the kernel's hold-down on the neighbour is neither: the
/// address is held and asked again after; see [`hold`](Self::hold).
#[derive(Debug, Default)]
pub(super) struct SendFaults {
    /// The first failure that says this host's send path is the problem.
    pub(super) broken: Option<String>,
    /// The first address this host has no route to, and what it said.
    pub(super) unroutable: Option<(IpAddr, String)>,
    /// How many addresses had no route.
    pub(super) unroutable_count: u64,
    /// Which addresses those were, so the report can name the uncovered
    /// targets.
    pub(super) addresses: std::collections::BTreeSet<IpAddr>,
    /// The addresses held through the kernel's hold-down on their neighbour.
    pub(super) held_down: neighbors::HoldDowns,
}

impl SendFaults {
    /// Holds `target` through the kernel's hold-down on its neighbour, where
    /// `error` refused a send to it for one and it is not yet the kernel's
    /// verdict, and returns when the hold-down is over; `None` for any other
    /// refusal, which the caller [`record`](Self::record)s.
    ///
    /// Logged once per hold-down at verbosity 2. The caller sends the address
    /// nothing until then; see [`HoldDowns`](neighbors::HoldDowns).
    pub(super) fn hold(&mut self, target: IpAddr, error: &SendError) -> Option<Instant> {
        if !matches!(error, SendError::HeldDown(_)) {
            return None;
        }
        let now = Instant::now();
        let held = self.held_down.until(target, now).is_some();
        let until = self.held_down.hold(target, now)?;
        if !held {
            info!(
                verbosity = 2,
                "{target} held down by the kernel, asked again in {}s ({error:#})",
                self.held_down.hold_down_for.as_secs()
            );
        }
        Some(until)
    }

    /// Until when `target` is held through a hold-down, if it still is at
    /// `now`. See [`hold`](Self::hold).
    pub(super) fn held_until(&self, target: IpAddr, now: Instant) -> Option<Instant> {
        self.held_down.until(target, now)
    }

    /// Files one failed send against the address it was aimed at.
    pub(super) fn record(&mut self, target: IpAddr, error: &SendError) {
        if error.is_unroutable() {
            self.unroutable_count += 1;
            self.addresses.insert(target);
            self.unroutable
                .get_or_insert_with(|| (target, error.to_string()));
        } else {
            self.broken.get_or_insert_with(|| error.to_string());
        }
    }

    /// Files `target` as unreached because its neighbour did not answer while
    /// the pass held its probe. Not counted as a send. See [`neighbors`].
    pub(super) fn record_unreached(&mut self, target: IpAddr, reason: String) {
        self.addresses.insert(target);
        self.unroutable.get_or_insert((target, reason));
    }

    /// Reports a pass's refused sends: a broken send path as a failure naming
    /// how many of `attempted` `probes` it refused, and each unreachable
    /// address against the address.
    pub(super) fn file(
        &self,
        ctx: &crate::scanner::session::ScanContext,
        kind: crate::report::ScannerKind,
        probes: &str,
        attempted: u64,
        failed: u64,
    ) {
        if let Some(reason) = &self.broken {
            let broken = failed.saturating_sub(self.unroutable_count);
            ctx.record_failure(
                kind,
                format!("{broken} of {attempted} {probes} could not be sent: {reason}"),
            );
        }
        for address in &self.addresses {
            ctx.record_unroutable(*address);
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
            _zone: Option<u32>,
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

        let real = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
        let real_packet = vec![0xAAu8, 0xBB];
        let decoys = vec![
            (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), vec![1u8, 1]),
            (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3)), vec![2u8, 2]),
        ];

        let mock = MockSender::default();
        assert!(
            emit_among_decoys(
                &mock,
                dst,
                None,
                Emission::routed(),
                real,
                &real_packet,
                &decoys
            )
            .is_ok()
        );
        let sent = mock.sent.lock().unwrap();
        assert_eq!(sent.len(), 3, "the real probe and both decoys are all sent");
        assert_eq!(sent.iter().filter(|(_, src, _)| *src == real).count(), 1);
        drop(sent);

        let mock = MockSender::default();
        emit_among_decoys(
            &mock,
            dst,
            None,
            Emission::routed(),
            real,
            &real_packet,
            &[],
        )
        .unwrap();
        assert_eq!(mock.sent.lock().unwrap().len(), 1);

        // The outcome is the real probe's, so a caller keeps a token only when
        // its own probe was sent and a decoy resolves no port.
        let refusing_the_real = RefusesOneSource(real);
        assert!(
            emit_among_decoys(
                &refusing_the_real,
                dst,
                None,
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
                None,
                Emission::routed(),
                real,
                &real_packet,
                &decoys
            )
            .is_ok()
        );
    }

    /// The two kinds of send failure are kept apart, and each keeps only its
    /// first. A broken send path fails the scan; a missing route does not.
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

    /// The rate a sweep actually paces itself at.
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

    /// With a fixed tick, every rate below one probe per tick would collapse
    /// onto 1000/s.
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

    /// No ceiling falls back to the default; a set one is obeyed. Zero cannot
    /// be asked, since the rate is a [`NonZeroU32`] at every level.
    #[test]
    fn an_unset_rate_falls_back_to_the_default_and_a_set_one_is_obeyed() {
        assert_eq!(
            rate_within(None, None, PROBE_RATE_PER_SEC),
            PROBE_RATE_PER_SEC
        );
        assert_eq!(
            rate_within(NonZeroU32::new(500), None, PROBE_RATE_PER_SEC).get(),
            500,
            "a rate the caller meant is the rate they get"
        );
    }

    /// The floor lifts a default and stops at a ceiling, which a settings file
    /// can set below the floor.
    #[test]
    fn a_floor_raises_the_default_but_never_a_ceiling() {
        let default = PROBE_RATE_PER_SEC;

        assert_eq!(
            rate_within(None, NonZeroU32::new(default.get() * 2), default).get(),
            default.get() * 2,
            "with no ceiling set, a floor above the engine's own rate is the rate"
        );
        assert_eq!(
            rate_within(None, NonZeroU32::new(1), default),
            default,
            "a floor below the engine's own rate changes nothing"
        );
        assert_eq!(
            rate_within(NonZeroU32::new(50), NonZeroU32::new(5_000), default).get(),
            50,
            "the ceiling wins: a safety limit is not traded away for a throughput wish"
        );
        assert_eq!(
            rate_within(NonZeroU32::new(5_000), NonZeroU32::new(50), default).get(),
            5_000,
            "a ceiling already above the floor is left where it is"
        );
    }
}
