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
//! Every probe is forged to come from a third party — the *zombie* — so the
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
//!    - **Open**: the target answers each with a SYN+ACK — to the zombie, which
//!      never asked for it and resets each one, advancing its counter once per
//!      probe.
//!    - **Closed or filtered**: the target resets (which the zombie ignores) or
//!      drops the probe; either way the zombie sends nothing and its counter does
//!      not move.
//! 3. Probe the zombie again and read `after`.
//!
//! Between the two readings the zombie sent one packet for the second reading
//! itself, plus one per forged probe the target bounced off it. So `after -
//! before` is about `SPOOFED_PROBES + 1` for an open port and about `1` for a
//! closed or filtered one, and [`OPEN_MIN_DELTA`] is the line between them. The
//! several probes per port are the whole of the method's noise tolerance: one
//! stray packet from the zombie shifts the count by one, where the signal is
//! [`SPOOFED_PROBES`] wide.
//!
//! ## Open, or closed-and-filtered, and nothing finer
//!
//! A closed port's reset and a filtered port's silence both leave the zombie's
//! counter still, so the scan cannot tell them apart — its verdicts are
//! [`PortState::Open`] and [`PortState::ClosedFiltered`], the honest pair for a
//! technique that reads a port only through what a third party bounced off it.
//!
//! ## What it demands, and what it refuses
//!
//! - **A suitable zombie.** The counter has to be a single shared one, advancing
//!   in small steps — the *counting* class the OS-detection series already reads
//!   ([`IdClass::Counting`]). A zombie whose IP-ID is random, per-connection, or
//!   zero carries no usable signal, and one that is IPv6 has no such field at
//!   all; the scan qualifies the zombie first and is refused, with the class it
//!   found named, when the zombie is not the kind this needs.
//! - **A self-built frame.** A forged source address is one the kernel would
//!   never place, so the spoofed probe can only go out over an Ethernet frame
//!   this engine builds itself — the same path fragmentation and decoys need. A
//!   host with no such path, or without the privilege to open one, is refused
//!   rather than scanned under its own address, which would betray the whole
//!   point of the technique.
//!
//! Both refusals are recorded and no port is reported, because a silent
//! fallback to an ordinary scan is the one outcome an idle scan must never have.

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
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::{PortScanner, StrategyError};
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
/// The same count the OS-detection series settled on: enough that "counting" and
/// "constant" are different observations rather than one reading that happened
/// to repeat, and no more, since each sample is a round trip to the zombie.
const QUALIFICATION_SAMPLES: usize = 6;

/// The gap left between qualification samples, so the counter's rate of advance
/// is readable rather than an artefact of how fast the path answered.
///
/// A step of one across five milliseconds is two hundred a second, well inside
/// what a shared counter plausibly runs at; the same step across the microsecond
/// a local reply can return in would read as tens of thousands a second, which is
/// noise, not a counter. The whole qualification pays this six times, once.
const QUALIFICATION_SPACING: Duration = Duration::from_millis(5);

/// How many forged SYNs are sent to each target port per measurement.
///
/// This is the method's signal-to-noise ratio made concrete: an open port moves
/// the zombie's counter by this many where a stray packet moves it by one, so a
/// wider count is a measurement that survives a zombie that is not perfectly
/// idle. The cost is this many spoofed packets per port.
const SPOOFED_PROBES: u16 = 6;

/// The smallest counter advance, over the one the second reading itself causes,
/// that is read as an open port.
///
/// Halfway between the closed case (the counter moves by one, for the reading)
/// and the open one (by `SPOOFED_PROBES + 1`), so the verdict tolerates losing
/// up to half the forged probes and up to half of [`SPOOFED_PROBES`]-worth of
/// stray zombie traffic before it turns over.
const OPEN_MIN_DELTA: u16 = SPOOFED_PROBES / 2 + 1;

/// How long to wait for the zombie's reset to one probe of its counter.
///
/// A ceiling, not a pace: a responsive zombie answers in a round trip and the
/// next sample follows at once. It is bounded because two samples further apart
/// than [`MAX_INTERVAL_FOR_ID`](crate::fingerprint::os::MAX_INTERVAL_FOR_ID)
/// cannot support a counter reading at all, so a zombie slow enough to approach
/// it is one whose signal has already gone.
const ZOMBIE_REPLY_TIMEOUT: Duration = Duration::from_millis(500);

/// How many times one reading of the zombie's counter is retried before it is
/// given up as lost.
///
/// A probe of the zombie can go missing like any other; a reading that cannot be
/// had after this many tries is treated as the zombie having gone quiet, which
/// costs the port its verdict rather than inventing one.
const ZOMBIE_READ_ATTEMPTS: usize = 3;

/// One reading of the zombie's IP-ID counter, and the shape of the reply it came
/// from, so a run of them can be classified.
#[derive(Debug, Clone, Copy)]
struct Reading {
    /// The IP-ID the zombie's reset carried — the counter's value at that moment.
    ip_id: u16,
    /// When the reply was read, for the interval the classifier reasons about.
    at: Instant,
    /// The reset's flags and sequence, so a qualification sample describes the
    /// segment it was read from rather than an assumed one.
    flags: u8,
    sequence: u32,
}

/// Scans TCP ports through a zombie's IP-ID counter, addressing the target only
/// as the zombie and never as itself.
pub struct IdlePortScanner {
    /// Shared store, event channel and abort signal for the scan.
    ctx: ScanContext,
    /// The Ethernet transport: it forges the spoofed probes to the target and
    /// probes the zombie, and its capture reads the zombie's resets back.
    transport: ProbeTransport,
    /// This host's own source address on the route to the zombie, or `None` when
    /// there is no route to it — resolved once, since the route to one zombie
    /// does not change across a scan.
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
    /// The transport is the environmental gate: a forged source address needs a
    /// self-built frame, so a host without that path fails here rather than
    /// quietly falling back to a scan under its own address. Whether the *zombie*
    /// is usable is a separate question, answered against the wire once the scan
    /// runs.
    pub fn new(
        ctx: ScanContext,
        zombie: IpAddr,
        zombie_port: Option<u16>,
        tuning: ProbeTuning,
    ) -> Result<Self, StrategyError> {
        let _ = tuning;
        let reply_port: u16 = rand::random_range(50_000..u16::MAX);
        let transport = ProbeTransport::open_ethernet(ProbeKind::TcpProbe {
            reply_port,
            icmp_errors: false,
        })?;
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

    /// Builds the scanner around a transport and source the caller supplies —
    /// the seam a test drives it through, against a synthetic zombie, with no
    /// privilege, no interface, and no route to resolve.
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

    /// Probes the zombie once and reads its counter, retrying a lost reply.
    ///
    /// The probe is an unsolicited SYN+ACK, which any port resets; the reset's
    /// acknowledgement carries the nonce this probe put in its own, so a reset
    /// echoing it is this scan's and its IP-ID is the reading. `None` means the
    /// zombie did not answer within [`ZOMBIE_READ_ATTEMPTS`] tries.
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

            let sent = self
                .transport
                .tx
                .send(&probe, source, self.zombie, Emission::routed())
                .is_ok();
            self.audit.record_send(sent);
            if !sent {
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
            // The reset takes its sequence from our probe's acknowledgement
            // field (RFC 793 §3.4), which is where a SYN+ACK's nonce rides, so
            // this reads the nonce straight back out.
            if tcp::echoed_nonce_with_flags(flags::SYN | flags::ACK, &tcp, 0) != nonce {
                self.audit.record_off_target();
                continue;
            }
            let Some(IpObservation::V4(observation)) = reply.observation else {
                // No IPv4 header to read a counter from — an IPv6 zombie, which
                // has no such field. Qualification turns this into a refusal.
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
    /// Returns the disqualifying class on refusal, so the caller can name it —
    /// [`IdClass::TooFew`] stands in for a zombie that would not answer at all,
    /// which is the same practical outcome as an unusable counter.
    async fn qualify(&mut self, source: IpAddr) -> Result<(), IdClass> {
        let mut samples = Vec::with_capacity(QUALIFICATION_SAMPLES);
        for sample in 0..QUALIFICATION_SAMPLES {
            // Space the samples deliberately. The counter is judged a followable
            // one by its rate of advance, and a reply that returns in
            // microseconds off a fast path would make a single step look like
            // tens of thousands a second and read as noise — so a small gap is
            // left for the rate to be meaningful, at a cost paid once per scan.
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
    /// port, reads the counter again, and reads the advance: an open port bounced
    /// each probe off the zombie and moved it, a closed or filtered one did not.
    /// A counter reading that cannot be had leaves the port
    /// [`PortState::Filtered`] — an honest "not determined", since nothing about
    /// the target was learned.
    async fn measure(&mut self, source: IpAddr, target: IpAddr, port: u16) -> PortState {
        let Some(before) = self.read_counter(source).await else {
            return PortState::Filtered;
        };

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
            // Forged from the zombie: the target's answer, if any, goes to the
            // zombie and never here. The reply is neither awaited nor captured.
            let sent = self
                .transport
                .tx
                .send(&probe, self.zombie, target, Emission::routed())
                .is_ok();
            self.audit.record_send(sent);
        }

        let Some(after) = self.read_counter(source).await else {
            return PortState::Filtered;
        };

        verdict(before.ip_id, after.ip_id)
    }

    /// Files a port's verdict, and the host as up when the verdict proves it.
    ///
    /// An open port is one the target answered — to the zombie, but answer it
    /// did — so it is proof the host is alive; a closed-or-filtered verdict
    /// proves nothing about the host and records nothing about it.
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
            drain(&mut targets);
            return Ok(());
        };

        if let Err(class) = self.qualify(source).await {
            self.ctx.record_failure(
                ScannerKind::Idle,
                format!(
                    "the zombie {} has a {} IP-ID counter, not the counting one an idle scan reads",
                    self.zombie,
                    class.name()
                ),
            );
            drain(&mut targets);
            return Ok(());
        }

        info!(
            "idle-scanning through the zombie {} on port {}",
            self.zombie, self.zombie_port
        );

        let mut probes = 0u128;
        let mut reason = StopReason::AttemptsSpent;
        while let Some(planned) = targets.recv().await {
            if self.ctx.handle.should_stop() {
                reason = StopReason::Aborted;
                self.ctx.record_outcome(Outcome::Unasked);
                break;
            }
            let target = planned.target;
            // TCP only, and IPv4 only: the side channel is the IPv4 IP-ID field,
            // and a forged probe has to share the zombie's address family. A
            // target this scan cannot read this way is left for no one — an idle
            // scan has, by design, no second way to reach it.
            if target.protocol != Protocol::Tcp || !target.ip.is_ipv4() || !self.zombie.is_ipv4() {
                self.ctx.record_outcome(Outcome::Unasked);
                continue;
            }

            probes += 1;
            let state = self.measure(source, target.ip, target.port).await;
            self.record(target.ip, target.port, state);
            self.ctx.record_outcome(Outcome::Answered {
                position: planned.position,
            });
        }

        // Anything still queued when a stop cut the loop was never asked.
        while targets.try_recv().is_ok() {
            self.ctx.record_outcome(Outcome::Unasked);
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

/// Discards every target still queued, so a refused scan settles what it was
/// handed as unasked rather than leaving it looking merely unfinished.
fn drain(targets: &mut mpsc::Receiver<PlannedTarget>) {
    while targets.try_recv().is_ok() {}
}

/// The verdict a counter advance implies, read between two counter samples that
/// bracket one port's forged probes.
///
/// The counter is sixteen bits and wraps, so the advance is a wrapping
/// difference; `before` already accounts for the reading that produced it, so
/// every step past the one `after`'s own reading causes is a probe the target
/// bounced off the zombie. An advance that reaches [`OPEN_MIN_DELTA`] is an open
/// port; anything less is a closed or filtered one, which this technique cannot
/// tell apart.
fn verdict(before: u16, after: u16) -> PortState {
    if after.wrapping_sub(before) >= OPEN_MIN_DELTA {
        PortState::Open
    } else {
        PortState::ClosedFiltered
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
    /// and the reading wraps with the sixteen-bit field rather than around it.
    ///
    /// The arithmetic is the whole of the method: a version that read the advance
    /// off the wrong end of a wrap, or moved the line by one, would turn open
    /// ports closed and closed ones open while every packet still went out
    /// correctly.
    #[test]
    fn a_counter_advance_reads_open_only_when_it_clears_the_threshold() {
        // The clean cases: an open port advances the counter by SPOOFED_PROBES
        // plus the reading's own step; a closed one, by the reading alone.
        assert_eq!(verdict(100, 100 + SPOOFED_PROBES + 1), PortState::Open);
        assert_eq!(verdict(100, 101), PortState::ClosedFiltered);

        // The threshold itself is open; one short of it is not.
        assert_eq!(verdict(100, 100 + OPEN_MIN_DELTA), PortState::Open);
        assert_eq!(
            verdict(100, 100 + OPEN_MIN_DELTA - 1),
            PortState::ClosedFiltered
        );

        // Across the field's wrap the advance is the true short distance, not the
        // huge one a plain subtraction would see: an open port whose probes
        // carried the counter over the top is still read open.
        assert_eq!(verdict(65_530, 2), PortState::Open); // an advance of eight
        assert_eq!(verdict(u16::MAX, 0), PortState::ClosedFiltered); // an advance of one
    }

    /// How the synthetic zombie writes its IP-ID: a shared counter that advances,
    /// or a fixed value that does not — the difference between a usable zombie and
    /// one the scan must refuse.
    enum Counter {
        Counting,
        Constant,
    }

    /// A responsive zombie. It resets every probe of its counter, carrying the
    /// counter's value in the reset's IP-ID, and — for an *open* target port — it
    /// advances the counter as if it had reset the SYN+ACK the target bounced off
    /// it, sending nothing back. Its resets are assembled from RFC 793's offsets
    /// by hand, so a shared misreading of a TCP header cannot pass for agreement
    /// between the scanner and its test.
    struct Zombie {
        replies: mpsc::Sender<CapturedSegment>,
        counter: AtomicU16,
        kind: Counter,
        open_ports: Vec<u16>,
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
            _emission: Emission,
        ) -> Result<(), SendError> {
            let Ok(tcp) = tcp::parse(segment) else {
                return Ok(());
            };
            if dst == ZOMBIE {
                // A probe of the counter. The reset takes its sequence from the
                // probe's acknowledgement field, which is where a SYN+ACK's nonce
                // rides, so the scanner reads it straight back.
                let reset = reset(
                    tcp.destination_port(),
                    tcp.source_port(),
                    tcp.acknowledgement(),
                );
                let _ = self.replies.try_send(captured(reset, self.next_id()));
            } else if dst == TARGET && self.open_ports.contains(&tcp.destination_port()) {
                // An open target bounced a SYN+ACK off the zombie, which reset it
                // and advanced the counter — a step this scan reads but never sees.
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
            source: ZOMBIE,
            protocol: IpNextHeaderProtocols::Tcp,
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

    /// A scanner pointed at the synthetic [`Zombie`], over a synthetic transport.
    fn scanner(ctx: &ScanContext, kind: Counter, open_ports: Vec<u16>) -> IdlePortScanner {
        let (tx, rx) = mpsc::channel(1024);
        let zombie = Zombie {
            replies: tx,
            counter: AtomicU16::new(1000),
            kind,
            open_ports,
        };
        let transport = ProbeTransport::from_parts(Box::new(zombie), rx as CaptureStream);
        IdlePortScanner::with_transport(ctx.clone(), ZOMBIE, None, SOURCE, transport)
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
    /// through a counting zombie come back open and closed-filtered.
    ///
    /// Nothing here addresses the target directly — the open verdict is the
    /// counter having advanced the extra steps the target bounced off the zombie,
    /// and the closed one is the counter having moved only for the readings
    /// themselves. A version that miscounted, mis-correlated a reset, or forged
    /// the probes wrong would turn one verdict into the other.
    #[tokio::test]
    async fn an_open_and_a_closed_port_are_read_through_a_counting_zombie() {
        let (session, ctx) = ScanSession::new();
        let mut scanner = scanner(&ctx, Counter::Counting, vec![OPEN_PORT]);

        scan(&mut scanner, &[OPEN_PORT, CLOSED_PORT]).await;

        assert_eq!(port_state(&session, OPEN_PORT), Some(PortState::Open));
        assert_eq!(
            port_state(&session, CLOSED_PORT),
            Some(PortState::ClosedFiltered)
        );
    }

    /// A zombie whose counter does not move is refused before any port is
    /// measured, and the refusal is recorded against the idle scanner.
    ///
    /// The guard is that nothing is guessed: a constant counter carries no
    /// signal, so the target is left with no verdict rather than a made-up one.
    #[tokio::test]
    async fn a_zombie_whose_counter_does_not_move_is_refused() {
        let (session, ctx) = ScanSession::new();
        let mut scanner = scanner(&ctx, Counter::Constant, vec![OPEN_PORT]);

        scan(&mut scanner, &[OPEN_PORT]).await;

        assert_eq!(port_state(&session, OPEN_PORT), None);
        assert!(
            ctx.failures_snapshot()
                .iter()
                .any(|failure| failure.scanner() == ScannerKind::Idle),
            "the refusal is recorded against the idle scanner"
        );
    }
}
