// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The idle (zombie) port scan
//!
//! A TCP port scan that never sends the target a packet under its own address.
//! Every probe is forged to come from a third party, the *zombie*, so the
//! target's answers go there, and what the target said is read back off the one
//! thing the zombie's own replies leak: a global IP-ID counter.
//!
//! ## The side channel
//!
//! A host with a single shared IP-ID counter advances it by one for every packet
//! it sends. That makes the counter a message the zombie broadcasts without
//! meaning to, and the scan reads it three steps at a time:
//!
//! 1. Probe the zombie and read its counter, `before`.
//! 2. Send [`SPOOFED_PROBES`] SYNs to one target port, each forged to come from
//!    the zombie.
//!    - **Open**: the target answers each with a SYN+ACK: to the zombie, which
//!      never asked for it and resets each one, advancing its counter once per
//!      probe.
//!    - **Closed, or no reply**: the target resets (which the zombie ignores) or
//!      drops the probe; either way the zombie sends nothing and its counter does
//!      not move.
//! 3. Probe the zombie again and read `after`.
//!
//! Between the two readings the zombie sent one packet for the second reading
//! itself, plus one per forged probe the target bounced off it. So `after -
//! before` is about `SPOOFED_PROBES + 1` for an open port and about `1` for a
//! closed or unreached one, and [`OPEN_MIN_DELTA`] is the line between them.
//! Sending several probes per port is the method's only noise tolerance: a stray
//! packet from the zombie shifts the count by one, the signal by
//! [`SPOOFED_PROBES`].
//!
//! A closed port's reset and a dropped probe's silence both leave the counter
//! still, so the verdicts are [`PortState::Open`] and
//! [`PortState::ClosedOrNoReply`] and nothing finer.
//!
//! ## Requirements
//!
//! - **A suitable zombie.** Its counter must be a single shared one advancing in
//!   small steps, the *counting* class the OS-detection series reads
//!   ([`IdClass::Counting`]). A random, per-connection or zero IP-ID carries no
//!   signal, and IPv6 has no such field. The scan qualifies the zombie first and
//!   refuses, naming the class it found, when it is unsuitable.
//! - **A self-built frame.** The kernel will not send from a forged source
//!   address, so the spoofed probe goes out over an Ethernet frame this engine
//!   builds, the same path fragmentation and decoys need. A host without that
//!   path, or the privilege to open it, is refused: scanning under its own
//!   address would defeat the technique.
//!
//! A refusal is recorded and no port gets a verdict; there is never a fallback
//! to an ordinary scan. Every port the scan was handed is recorded unasked, so
//! the target reaches the report as one nothing asked about.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::config::ProbeTuning;
use crate::fingerprint;
use crate::fingerprint::os::{IdClass, SeriesClasses, SeriesSample};
use crate::info;
use crate::journal::settle::Outcome;
use crate::model::capture::IpObservation;
use crate::model::host::{HostStatus, StatusProtocol, StatusReason};
use crate::model::port::{PortState, Protocol};
use crate::model::target::PlannedTarget;
use crate::model::technique::TcpScanTechnique;
use crate::protocols::tcp::{self, flags};
use crate::report::ScannerKind;
use crate::report::StopReason;
use crate::scanner::audit::ProbeAudit;
use crate::scanner::session::{ProbeClaim, ScanContext};
use crate::scanner::strategy::{PortScanner, StrategyError, record_unasked};
use crate::system::interface::SourceResolver;
use crate::transport::probe::{Emission, ProbeKind, ProbeTransport};

/// The port on the zombie probed for its counter when a caller names none.
///
/// Any port draws the reset whose IP-ID the scan reads, since an unsolicited
/// SYN+ACK is reset whether the port is open or closed. Eighty is the one most
/// often reachable through a zombie's own filter.
const DEFAULT_ZOMBIE_PORT: u16 = 80;

/// How many times the zombie's counter is sampled to decide whether it is the
/// counting kind an idle scan needs.
///
/// The same count the OS-detection series uses: enough that "counting" and
/// "constant" are distinct observations, and no more, since each sample is a
/// round trip to the zombie.
const QUALIFICATION_SAMPLES: usize = 6;

/// The gap between qualification samples, so the counter's rate of advance is
/// readable and not an artefact of how fast the path answered.
///
/// A step of one across five milliseconds is two hundred a second, plausible for
/// a shared counter; across the microsecond a local reply can take it would read
/// as tens of thousands a second, which is noise. Paid six times, once per scan.
const QUALIFICATION_SPACING: Duration = Duration::from_millis(5);

/// How many forged SYNs are sent to each target port per measurement.
///
/// An open port moves the zombie's counter by this many where a stray packet
/// moves it by one, so a wider count survives a zombie that is not perfectly
/// idle. The cost is this many spoofed packets per port.
pub const SPOOFED_PROBES: u16 = 6;

/// The smallest counter advance, over the one the second reading itself causes,
/// that is read as an open port.
///
/// Halfway between the closed case (the counter moves by one, for the reading)
/// and the open one (by `SPOOFED_PROBES + 1`), so the verdict tolerates losing
/// up to half the forged probes and up to half of [`SPOOFED_PROBES`]-worth of
/// stray zombie traffic before it turns over.
pub const OPEN_MIN_DELTA: u16 = SPOOFED_PROBES / 2 + 1;

/// How long to wait for the zombie's reset to one probe of its counter.
///
/// A ceiling, not a pace: a responsive zombie answers in a round trip. Two
/// samples further apart than the identifier classifier's
/// `MAX_INTERVAL_FOR_ID`, the same half second, cannot support a counter
/// reading, so a zombie that slow has already lost its signal.
const ZOMBIE_REPLY_TIMEOUT: Duration = Duration::from_millis(500);

/// How many times one reading of the zombie's counter is retried before it is
/// given up as lost.
///
/// A reading that cannot be had after this many tries is treated as the zombie
/// having gone quiet, which costs the port its verdict.
const ZOMBIE_READ_ATTEMPTS: usize = 3;

/// One reading of the zombie's IP-ID counter, and the shape of the reply it came
/// from, so a run of them can be classified.
#[derive(Debug, Clone, Copy)]
struct Reading {
    /// The IP-ID the zombie's reset carried: the counter's value at that moment.
    ip_id: u16,
    /// When the reply was read, for the interval the classifier reasons about.
    at: Instant,
    /// The reset's flags and sequence, so a qualification sample describes the
    /// segment it was read from.
    flags: u8,
    sequence: u32,
}

/// Scans TCP ports through a zombie's IP-ID counter, addressing the target only
/// as the zombie.
pub struct IdlePortScanner {
    /// Shared store, event channel and abort signal for the scan.
    ctx: ScanContext,
    /// The Ethernet transport: it forges the spoofed probes to the target and
    /// probes the zombie, and its capture reads the zombie's resets back.
    transport: ProbeTransport,
    /// This host's source address on the route to the zombie, or `None` when
    /// there is no route; resolved once per scan.
    source: Option<IpAddr>,
    /// The zombie whose counter is the side channel.
    zombie: IpAddr,
    /// The port on the zombie the counter is read from.
    zombie_port: u16,
    /// The port this scan probes the zombie from, and so the one its resets come
    /// back to. Fixed, so the capture is built around it.
    reply_port: u16,
    /// Counts what left and what came back, for the report.
    audit: ProbeAudit,
}

impl IdlePortScanner {
    /// Opens the Ethernet transport an idle scan needs, or refuses.
    ///
    /// A forged source address needs a self-built frame, so a host without that
    /// path fails here. Whether the *zombie* is usable is answered against the wire
    /// once the scan runs.
    pub fn new(
        ctx: ScanContext,
        zombie: IpAddr,
        zombie_port: Option<u16>,
        tuning: ProbeTuning,
    ) -> Result<Self, StrategyError> {
        let _ = tuning;
        let reply_port: u16 = rand::random_range(50_000..u16::MAX);
        let transport = ProbeTransport::open_ethernet_capturing(
            ProbeKind::TcpProbe {
                reply_port,
                icmp_errors: false,
            },
            &ctx.capture_links(),
        )?;
        let source = SourceResolver::from_system().resolve(zombie);

        Ok(Self {
            ctx,
            transport,
            source,
            zombie,
            zombie_port: zombie_port.unwrap_or(DEFAULT_ZOMBIE_PORT),
            reply_port,
            audit: ProbeAudit::new(),
        })
    }

    /// Builds the scanner around a caller-supplied transport and source, so a test
    /// can drive it against a synthetic zombie with no privilege, interface or
    /// route.
    #[cfg(test)]
    fn with_transport(
        ctx: ScanContext,
        zombie: IpAddr,
        zombie_port: Option<u16>,
        source: IpAddr,
        transport: ProbeTransport,
    ) -> Self {
        Self {
            ctx,
            transport,
            source: Some(source),
            zombie,
            zombie_port: zombie_port.unwrap_or(DEFAULT_ZOMBIE_PORT),
            reply_port: rand::random_range(50_000..u16::MAX),
            audit: ProbeAudit::new(),
        }
    }

    /// Waits until a probe to `address` may leave under the gaps the scan
    /// keeps between probes, then hands back the slot it claimed, or `None`
    /// where the scan stopped while it waited.
    ///
    /// Taken immediately before a send and given back by the caller with
    /// [`ScanContext::refund_probe`] when the send did not leave. Waiting costs
    /// nothing this scan measures: the counter is timed from the zombie's reply.
    async fn claim_paced(&self, address: IpAddr) -> Option<ProbeClaim> {
        loop {
            match self.ctx.claim_probe(address) {
                Ok(claim) => return Some(claim),
                Err(ready) => {
                    tokio::select! {
                        () = self.ctx.handle.stopping() => return None,
                        () = tokio::time::sleep_until(ready.into()) => {}
                    }
                }
            }
        }
    }

    /// Probes the zombie once and reads its counter, retrying a lost reply.
    ///
    /// The probe is an unsolicited SYN+ACK, which any port resets; the reset
    /// echoes the probe's nonce, so a reset carrying it is this scan's and its
    /// IP-ID is the reading. `None` means the zombie did not answer within
    /// [`ZOMBIE_READ_ATTEMPTS`] tries, or the scan stopped while waiting for a slot.
    ///
    /// Each read takes its slot on the zombie's address.
    async fn read_counter(&mut self, source: IpAddr) -> Option<Reading> {
        for _ in 0..ZOMBIE_READ_ATTEMPTS {
            let nonce: u32 = rand::random();
            let Ok(probe) = tcp::build_probe_with_flags(
                flags::SYN | flags::ACK,
                source,
                self.zombie,
                self.reply_port,
                self.zombie_port,
                nonce,
                None,
                false,
            ) else {
                return None;
            };

            let claim = self.claim_paced(self.zombie).await?;
            let sent = self
                .transport
                .tx
                .send(&probe, source, self.zombie, None, Emission::routed())
                .is_ok();
            self.audit.record_send(sent);
            if !sent {
                self.ctx.refund_probe(claim);
                continue;
            }

            if let Some(reading) = self.await_reset(nonce).await {
                return Some(reading);
            }
        }
        None
    }

    /// Waits for the zombie's reset echoing `nonce` and reads its counter.
    async fn await_reset(&mut self, nonce: u32) -> Option<Reading> {
        let deadline = Instant::now() + ZOMBIE_REPLY_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let reply = match timeout(remaining, self.transport.rx.recv()).await {
                Ok(Some(reply)) => reply,
                // The capture closed, or the window elapsed with no reply.
                Ok(None) | Err(_) => return None,
            };
            self.audit.record_segment();

            if reply.source != self.zombie {
                self.audit.record_off_target();
                continue;
            }
            let Ok(tcp) = tcp::parse(&reply.bytes) else {
                continue;
            };
            // The reset takes its sequence from our probe's acknowledgement field
            // (RFC 793 §3.4), where a SYN+ACK's nonce rides.
            if tcp::echoed_nonce_with_flags(flags::SYN | flags::ACK, &tcp, 0) != nonce {
                self.audit.record_off_target();
                continue;
            }
            let Some(IpObservation::V4(observation)) = reply.observation else {
                // No IPv4 header, so an IPv6 zombie with no counter. Qualification
                // turns this into a refusal.
                return None;
            };
            return Some(Reading {
                ip_id: observation.identification,
                at: Instant::now(),
                flags: tcp.flags(),
                sequence: tcp.sequence(),
            });
        }
    }

    /// Reads the zombie's counter a handful of times and decides whether it is
    /// the counting kind an idle scan can use.
    ///
    /// Returns the disqualifying class on refusal, so the caller can name it.
    /// [`IdClass::TooFew`] stands in for a zombie that would not answer at all.
    async fn qualify(&mut self, source: IpAddr) -> Result<(), IdClass> {
        let mut samples = Vec::with_capacity(QUALIFICATION_SAMPLES);
        for sample in 0..QUALIFICATION_SAMPLES {
            // Spaced so the rate of advance is meaningful; see
            // QUALIFICATION_SPACING.
            if sample > 0 {
                tokio::time::sleep(QUALIFICATION_SPACING).await;
            }
            let Some(reading) = self.read_counter(source).await else {
                return Err(IdClass::TooFew);
            };
            samples.push(SeriesSample {
                at: reading.at,
                flags: reading.flags,
                sequence: reading.sequence,
                ip_id: Some(reading.ip_id),
                tsval: None,
            });
        }

        match SeriesClasses::from_samples(&samples).identifiers {
            IdClass::Counting => Ok(()),
            other => Err(other),
        }
    }

    /// Measures one target port through the zombie's counter.
    ///
    /// Reads the counter, forges [`SPOOFED_PROBES`] SYNs from the zombie to the
    /// port, reads the counter again, and judges the advance. A counter reading
    /// that cannot be had leaves the port [`PortState::Unasked`], since a silence
    /// filed against the target would be the zombie's.
    async fn measure(&mut self, source: IpAddr, target: IpAddr, port: u16) -> PortState {
        let Some(before) = self.read_counter(source).await else {
            return PortState::Unasked;
        };

        // Each forged probe takes its slot on the target's address, so the burst
        // keeps the same gaps as every other probe. If the scan stops while waiting,
        // the burst is abandoned and the port reads as unasked.
        for _ in 0..SPOOFED_PROBES {
            let nonce: u32 = rand::random();
            let spoofed_port: u16 = rand::random_range(50_000..u16::MAX);
            let Ok(probe) = tcp::build_probe(
                TcpScanTechnique::Syn,
                self.zombie,
                target,
                spoofed_port,
                port,
                nonce,
            ) else {
                continue;
            };
            let Some(claim) = self.claim_paced(target).await else {
                return PortState::Unasked;
            };
            // Forged from the zombie: the target's answer goes there, so nothing is
            // awaited.
            let sent = self
                .transport
                .tx
                .send(&probe, self.zombie, target, None, Emission::routed())
                .is_ok();
            self.audit.record_send(sent);
            if !sent {
                self.ctx.refund_probe(claim);
            }
        }

        let Some(after) = self.read_counter(source).await else {
            return PortState::Unasked;
        };

        verdict(before.ip_id, after.ip_id)
    }

    /// Files a port's verdict, and the host as up when the verdict proves it.
    ///
    /// An open port is one the target answered (to the zombie), so it proves the
    /// host is up; a closed-or-no-reply verdict records nothing about the host.
    fn record(&self, target: IpAddr, port: u16, state: PortState) {
        let recorded = fingerprint::baseline_port(port, Protocol::Tcp, state);
        self.ctx.update_host(target, |host| {
            host.add_port(recorded.clone());
            if state == PortState::Open {
                host.record_evidence(
                    HostStatus::Up,
                    StatusReason::new(
                        StatusProtocol::TcpSyn,
                        "the target answered a forged probe, read through the zombie's counter",
                    ),
                );
            }
        });
    }
}

#[async_trait]
impl PortScanner for IdlePortScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::Idle
    }

    fn supported_protocols(&self) -> Vec<Protocol> {
        vec![Protocol::Tcp]
    }

    async fn scan(
        &mut self,
        mut targets: mpsc::Receiver<PlannedTarget>,
    ) -> Result<(), StrategyError> {
        let Some(source) = self.source else {
            self.ctx.record_failure(
                ScannerKind::Idle,
                format!(
                    "no route to the zombie {} to run an idle scan through",
                    self.zombie
                ),
            );
            refuse(&self.ctx, targets).await;
            return Ok(());
        };

        if let Err(class) = self.qualify(source).await {
            self.ctx.record_failure(
                ScannerKind::Idle,
                format!(
                    "zombie {} unusable ({})",
                    self.zombie,
                    unsuitable_zombie(class)
                ),
            );
            refuse(&self.ctx, targets).await;
            return Ok(());
        }

        info!(
            "idle-scanning through the zombie {} on port {}",
            self.zombie, self.zombie_port
        );

        let mut probes = 0u128;
        let mut reason = StopReason::AttemptsSpent;
        while let Some(planned) = targets.recv().await {
            if let Some(cause) = self.ctx.handle.stopped() {
                reason = cause.into();
                record_unasked(&self.ctx, &planned);
                break;
            }
            let target = planned.target;
            // TCP and IPv4 only: the side channel is the IPv4 IP-ID field, and a forged
            // probe must share the zombie's address family. Other targets are recorded
            // unasked; an idle scan has no second way to reach them.
            if target.protocol != Protocol::Tcp || !target.ip.is_ipv4() || !self.zombie.is_ipv4() {
                record_unasked(&self.ctx, &planned);
                continue;
            }

            probes += 1;
            let state = self.measure(source, target.ip, target.port).await;
            self.record(target.ip, target.port, state);
            self.ctx.record_outcome(Outcome::Answered {
                position: planned.position,
            });
        }

        // Anything still queued when a stop cut the loop was never asked. Closed
        // first, so a target handed over meanwhile finds this scanner gone and the
        // router records it.
        targets.close();
        while let Ok(planned) = targets.try_recv() {
            record_unasked(&self.ctx, &planned);
        }

        let capture = self.transport.capture_counts();
        self.audit.report("idle", probes, reason, capture, None);
        self.ctx.record_probe_stats(self.audit.stats(
            ScannerKind::Idle,
            probes,
            reason,
            capture,
            None,
        ));
        Ok(())
    }
}

/// Records every target a refused scan is handed as unasked on its host, read
/// until the router has handed over the last one.
///
/// Reads to the end, so every target is on its host with its ports unasked
/// whether it was queued before the refusal or routed after it, and the
/// refusal is the one failure reported for them.
async fn refuse(ctx: &ScanContext, mut targets: mpsc::Receiver<PlannedTarget>) {
    while let Some(planned) = targets.recv().await {
        record_unasked(ctx, &planned);
    }
}

/// The flag a refusal names for a zombie whose IP-ID counter classified as
/// `class`, terse and parenthesised as the console wants it.
///
/// The classifier's names are wire facts, so `class.name()` would read "a
/// too-few IP-ID counter". `Counting` never reaches here but keeps the match
/// exhaustive.
fn unsuitable_zombie(class: IdClass) -> &'static str {
    match class {
        IdClass::Absent => "IPv6, no IP-ID",
        IdClass::TooFew => "too few replies",
        IdClass::Unclear => "IP-ID unreadably slow",
        IdClass::Zero => "IP-ID always zero",
        IdClass::Constant => "IP-ID never advances",
        IdClass::Scattered => "IP-ID randomised",
        IdClass::Counting => "IP-ID counts",
    }
}

/// The verdict a counter advance implies, between two samples that bracket one
/// port's forged probes.
///
/// The counter is sixteen bits and wraps, so the advance is a wrapping
/// difference. An advance reaching [`OPEN_MIN_DELTA`] is an open port; anything
/// less is closed or unreached, which this technique cannot tell apart.
fn verdict(before: u16, after: u16) -> PortState {
    if after.wrapping_sub(before) >= OPEN_MIN_DELTA {
        PortState::Open
    } else {
        PortState::ClosedOrNoReply
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU16, Ordering};

    use pnet_packet::ip::IpNextHeaderProtocols;

    use super::*;
    use crate::model::capture::Ipv4Observation;
    use crate::model::target::Target;
    use crate::scanner::session::ScanSession;
    use crate::transport::capture::{CaptureStream, CapturedSegment};
    use crate::transport::probe::{ProbeSender, SendError};

    const ZOMBIE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    const SOURCE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const OPEN_PORT: u16 = 22;
    const CLOSED_PORT: u16 = 81;

    /// The counter advance is read as open exactly when it clears the threshold,
    /// and the reading wraps with the sixteen-bit field. An off-by-one here
    /// swaps open and closed while every packet still goes out correctly.
    #[test]
    fn a_counter_advance_reads_open_only_when_it_clears_the_threshold() {
        // The clean cases: an open port advances the counter by SPOOFED_PROBES
        // plus the reading's own step; a closed one, by the reading alone.
        assert_eq!(verdict(100, 100 + SPOOFED_PROBES + 1), PortState::Open);
        assert_eq!(verdict(100, 101), PortState::ClosedOrNoReply);

        // The threshold itself is open; one short of it is not.
        assert_eq!(verdict(100, 100 + OPEN_MIN_DELTA), PortState::Open);
        assert_eq!(
            verdict(100, 100 + OPEN_MIN_DELTA - 1),
            PortState::ClosedOrNoReply
        );

        // Across the wrap the advance is the short distance, so an open port
        // whose probes carried the counter over the top still reads open.
        assert_eq!(verdict(65_530, 2), PortState::Open); // an advance of eight
        assert_eq!(verdict(u16::MAX, 0), PortState::ClosedOrNoReply); // an advance of one
    }

    /// How the synthetic zombie writes its IP-ID: a shared counter that advances
    /// (usable), or a fixed value (refused).
    enum Counter {
        Counting,
        Constant,
    }

    /// A responsive zombie. It resets every probe of its counter, carrying the
    /// counter's value in the reset's IP-ID, and for an *open* target port advances
    /// the counter as if it had reset the target's SYN+ACK. Its resets are built
    /// from RFC 793's offsets by hand, so a shared misreading of a TCP header cannot
    /// pass as agreement between the scanner and its test.
    struct Zombie {
        replies: mpsc::Sender<CapturedSegment>,
        counter: AtomicU16,
        kind: Counter,
        open_ports: Vec<u16>,
        /// When each probe reached the segment, and the address it was aimed
        /// at, so a test can assert on how the sends were spaced.
        sent_at: SendLog,
    }

    impl Zombie {
        /// The IP-ID the zombie's next packet carries: a counting zombie advances
        /// its shared counter, a constant one never moves.
        fn next_id(&self) -> u16 {
            match self.kind {
                Counter::Counting => self.counter.fetch_add(1, Ordering::Relaxed),
                Counter::Constant => 4242,
            }
        }
    }

    impl ProbeSender for Zombie {
        fn send(
            &self,
            segment: &[u8],
            _src: IpAddr,
            dst: IpAddr,
            _zone: Option<u32>,
            _emission: Emission,
        ) -> Result<(), SendError> {
            self.sent_at.lock().unwrap().push((dst, Instant::now()));
            let Ok(tcp) = tcp::parse(segment) else {
                return Ok(());
            };
            if dst == ZOMBIE {
                // A probe of the counter; the reset echoes the probe's acknowledgement
                // field, where the nonce rides.
                let reset = reset(
                    tcp.destination_port(),
                    tcp.source_port(),
                    tcp.acknowledgement(),
                );
                let _ = self.replies.try_send(captured(reset, self.next_id()));
            } else if dst == TARGET && self.open_ports.contains(&tcp.destination_port()) {
                // An open target bounced a SYN+ACK off the zombie, which reset it and
                // advanced the counter.
                let _ = self.next_id();
            }
            Ok(())
        }
    }

    /// A bare reset carrying `sequence`, laid out from the header offsets by hand.
    fn reset(source_port: u16, destination_port: u16, sequence: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 20];
        bytes[0..2].copy_from_slice(&source_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&destination_port.to_be_bytes());
        bytes[4..8].copy_from_slice(&sequence.to_be_bytes());
        bytes[12] = 5 << 4; // data offset: five 32-bit words, a bare header
        bytes[13] = flags::RST | flags::ACK;
        bytes
    }

    /// A captured segment from the zombie, carrying `identification` as its IP-ID.
    fn captured(bytes: Vec<u8>, identification: u16) -> CapturedSegment {
        CapturedSegment {
            received_at: Instant::now(),
            source: ZOMBIE,
            destination: None,
            protocol: IpNextHeaderProtocols::Tcp.0,
            observation: Some(IpObservation::V4(Ipv4Observation {
                ttl: 64,
                identification,
                dont_fragment: false,
                more_fragments: false,
                dscp: 0,
                ecn: 0,
            })),
            source_mac: None,
            bytes,
        }
    }

    /// A shared log of the address each probe left for, and when.
    type SendLog = std::sync::Arc<std::sync::Mutex<Vec<(IpAddr, Instant)>>>;

    /// A scanner pointed at the synthetic [`Zombie`], over a synthetic transport.
    fn scanner(ctx: &ScanContext, kind: Counter, open_ports: Vec<u16>) -> IdlePortScanner {
        scanner_logging(ctx, kind, open_ports).0
    }

    /// [`scanner`], keeping the log of what left the segment and when.
    fn scanner_logging(
        ctx: &ScanContext,
        kind: Counter,
        open_ports: Vec<u16>,
    ) -> (IdlePortScanner, SendLog) {
        let (tx, rx) = mpsc::channel(1024);
        let sent_at = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let zombie = Zombie {
            replies: tx,
            counter: AtomicU16::new(1000),
            kind,
            open_ports,
            sent_at: sent_at.clone(),
        };
        let transport = ProbeTransport::from_parts(Box::new(zombie), rx as CaptureStream);
        (
            IdlePortScanner::with_transport(ctx.clone(), ZOMBIE, None, SOURCE, transport),
            sent_at,
        )
    }

    /// Runs `scanner` over `ports` of the target and returns once it is done.
    async fn scan(scanner: &mut IdlePortScanner, ports: &[u16]) {
        let (tx, rx) = mpsc::channel(ports.len().max(1));
        for (position, &port) in ports.iter().enumerate() {
            tx.send(PlannedTarget::new(
                position as u64,
                Target {
                    ip: TARGET,
                    port,
                    protocol: Protocol::Tcp,
                },
            ))
            .await
            .expect("the target is admitted");
        }
        drop(tx);
        scanner.scan(rx).await.expect("the idle scan runs");
    }

    fn port_state(session: &ScanSession, port: u16) -> Option<PortState> {
        session
            .hosts()
            .get(TARGET)
            .and_then(|host| host.ports().find(|p| p.number() == port).map(|p| p.state()))
    }

    /// The whole side channel, end to end: an open port and a closed one read
    /// through a counting zombie come back open and closed-or-no-reply.
    ///
    /// Nothing addresses the target directly: the open verdict is the counter's
    /// extra advance, the closed one its movement for the readings alone.
    #[tokio::test]
    async fn an_open_and_a_closed_port_are_read_through_a_counting_zombie() {
        let (session, ctx) = ScanSession::new();
        let mut scanner = scanner(&ctx, Counter::Counting, vec![OPEN_PORT]);

        scan(&mut scanner, &[OPEN_PORT, CLOSED_PORT]).await;

        assert_eq!(port_state(&session, OPEN_PORT), Some(PortState::Open));
        assert_eq!(
            port_state(&session, CLOSED_PORT),
            Some(PortState::ClosedOrNoReply)
        );
    }

    /// A zombie whose counter does not move is refused before any port is
    /// measured, and the refusal is recorded against the idle scanner.
    ///
    /// A constant counter carries no signal, so the target is left unasked.
    #[tokio::test]
    async fn a_zombie_whose_counter_does_not_move_is_refused() {
        let (session, ctx) = ScanSession::new();
        let mut scanner = scanner(&ctx, Counter::Constant, vec![OPEN_PORT]);

        scan(&mut scanner, &[OPEN_PORT]).await;

        assert_eq!(port_state(&session, OPEN_PORT), Some(PortState::Unasked));
        let failures = ctx.failures_snapshot();
        let refusal = failures
            .iter()
            .find(|failure| failure.scanner() == ScannerKind::Idle)
            .expect("the refusal is recorded against the idle scanner");
        assert!(
            refusal.reason().contains("IP-ID never advances"),
            "the refusal flags what the counter did, not \"a constant IP-ID counter\": {}",
            refusal.reason()
        );
    }

    /// Under a per-host gap, zombie reads are spaced among themselves and the
    /// forged burst among itself, and the verdict is still reached.
    #[tokio::test]
    async fn a_gap_spaces_the_zombie_reads_and_the_forged_burst() {
        let gap = Duration::from_millis(20);
        let (session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(gap))
            .build();
        let (mut scanner, sent_at) = scanner_logging(&ctx, Counter::Counting, vec![OPEN_PORT]);

        scan(&mut scanner, &[OPEN_PORT]).await;

        assert_eq!(port_state(&session, OPEN_PORT), Some(PortState::Open));

        let log = sent_at.lock().unwrap();
        for address in [ZOMBIE, TARGET] {
            let at: Vec<Instant> = log
                .iter()
                .filter(|(dst, _)| *dst == address)
                .map(|(_, at)| *at)
                .collect();
            assert!(at.len() >= 2, "{address} was probed more than once");
            for pair in at.windows(2) {
                assert!(
                    pair[1].duration_since(pair[0]) >= gap,
                    "two probes at {address} left {:?} apart, under a {gap:?} gap",
                    pair[1].duration_since(pair[0])
                );
            }
        }
    }

    /// A refused scan records every target it is handed as unasked on its host,
    /// whether queued before the refusal or routed after it, so the result does not
    /// depend on how the refusal and the routing interleave.
    #[tokio::test]
    async fn a_refused_scan_records_every_target_it_is_handed_unasked() {
        let (session, ctx) = ScanSession::new();
        let mut scanner = scanner(&ctx, Counter::Constant, vec![OPEN_PORT]);
        let (tx, rx) = mpsc::channel(4);
        let target = |position, port| {
            PlannedTarget::new(
                position,
                Target {
                    ip: TARGET,
                    port,
                    protocol: Protocol::Tcp,
                },
            )
        };
        tx.send(target(0, OPEN_PORT)).await.expect("queued");
        let scan = tokio::spawn(async move {
            scanner.scan(rx).await.expect("the idle scan runs");
        });
        while !ctx
            .failures_snapshot()
            .iter()
            .any(|failure| failure.scanner() == ScannerKind::Idle)
        {
            tokio::task::yield_now().await;
        }

        let late = tx.send(target(1, CLOSED_PORT)).await;
        drop(tx);
        scan.await.expect("the scan task ends");

        assert!(late.is_ok(), "a target routed after the refusal is taken");
        assert_eq!(port_state(&session, OPEN_PORT), Some(PortState::Unasked));
        assert_eq!(port_state(&session, CLOSED_PORT), Some(PortState::Unasked));
        assert_eq!(ctx.settlements().count(Outcome::Unasked), 2);
    }
}
