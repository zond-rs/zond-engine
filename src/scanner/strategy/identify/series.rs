// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The active operating-system series probe
//!
//! Asks one host the same question several times, so that the *policies* behind
//! its counters become visible.
//!
//! A single reply cannot show three of the features that separate one release of
//! a stack from the next. An IP identifier of `0` fits a stack that always writes
//! zero, a per-socket counter that happened to start there, and a randomiser. An
//! initial sequence number is one number; the *generator* (fixed step, multiples,
//! hashed per RFC 6528) shows only across several. A timestamp clock's rate needs
//! two readings and the interval between them. These are the features a
//! release-level rule ("Linux 6.x", not just "Linux") turns on.
//!
//! Every probe is [`crate::protocols::tcp::build_probe`] for
//! [`TcpScanTechnique::Syn`], the segment an ordinary SYN scan sends; each target
//! is just asked more than once. That is extra traffic at hosts the caller may
//! only have meant to enumerate, so it sits behind
//! [`OsDetection::Active`](crate::config::OsDetection).
//!
//! ## Fresh source port per sweep
//!
//! Two SYNs from one source port are the same 4-tuple: the first has put the
//! peer in `SYN-RECEIVED`, and the second's answer describes that state, not the
//! stack. An initial sequence number is chosen per connection, so each sample
//! must be a new one. This also means no settle period is needed between
//! samples.
//!
//! ## Two ports per host
//!
//! A SYN+ACK is an atomic datagram with don't-fragment set, and RFC 6864 §4.1
//! frees its sender from putting anything meaningful in the identification
//! field; a reset from the same host is where the identifier policy shows. A
//! reset carries no options and opens no connection, so the sequence generator
//! and the peer's clock are readable only from the SYN+ACK. Sampling with one
//! port per host (preferring open) once reported identifiers zero for every
//! host, while the same hosts' closed ports separated three of them three ways.
//!
//! So a host is followed on both where the port scan found both, and the two
//! series are kept **apart**: a stack's reset path and handshake path are
//! different code that can disagree about the same field. See
//! [`series`](crate::fingerprint::os::SeriesClasses) and
//! [`classify_series`](crate::fingerprint::os::classify_series).
//!
//! ## Spacing and batches
//!
//! A 16-bit identifier counter wraps every 65 536 packets, so across a long
//! enough gap a counter and a random number look the same.
//! [`read_identifiers`](crate::fingerprint::os::read_identifiers) refuses a series
//! spaced more than half a second apart. **One sweep has to finish inside the
//! spacing**, or every host in it reads as unclear. Hosts are therefore followed
//! in batches small enough for a sweep to fit, each its own timing window;
//! `BATCH` carries the arithmetic.
//!
//! ## No retransmission
//!
//! The interval between two readings is the measurement, and a retry arrives at
//! an unplanned moment. A missing sample costs one sample; a mistimed one costs
//! the reading. A short series is reported as
//! [`TooFew`](crate::fingerprint::os::IdClass::TooFew).
//!
//! [`TcpScanTechnique::Syn`]: crate::model::technique::TcpScanTechnique::Syn

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use pnet_packet::ip::IpNextHeaderProtocols;

use crate::config::ProbeTuning;
use crate::fingerprint::os::{self, SeriesClasses, SeriesSample, StackObservation, StackReply};
use crate::logging::error;
use crate::model::capture::IpObservation;
use crate::model::host::Host;
use crate::model::ip::scoped::ScopedIp;
use crate::model::port::{PortState, Protocol};
use crate::model::technique::TcpScanTechnique;
use crate::protocols::tcp;
use crate::report::ScannerKind;
use crate::report::StopReason;
use crate::scanner::audit::ProbeAudit;
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::StrategyError;
use crate::scanner::strategy::raw::SendFaults;
use crate::scanner::strategy::raw::neighbors::{Admission, NeighborGates, resolve_ahead};
use crate::system::interface::SourceResolver;
use crate::transport::capture::CapturedSegment;
use crate::transport::probe::{Emission, ProbeKind, ProbeTransport};
use crate::{counted, info, success};

/// How many times each host is asked, at [`OsDetection::Active`].
///
/// Six is the smallest number that answers the three questions. An identifier
/// policy needs at least three values to tell "constant" from "counting"; a clock
/// rate wants a span, so one late reply cannot set it; and a generator's step is
/// a property of several differences. Past six an extra sample buys precision on
/// a rate, not a class, at a packet per port per host.
///
/// [`OsDetection::Active`]: crate::config::OsDetection::Active
pub const ACTIVE_SAMPLES: usize = 6;

/// How many times each host is asked at
/// [`OsDetection::Aggressive`](crate::config::OsDetection::Aggressive).
///
/// Twice the traffic for a reading that refuses less often: the commonest reason
/// a classifier declines is that too few samples came back. It buys no new kind
/// of answer.
pub const AGGRESSIVE_SAMPLES: usize = 12;

/// The source port after `port` in [`SOURCE_PORTS`], back to its start past
/// its end.
fn following(port: u16) -> u16 {
    if port + 1 < SOURCE_PORTS.end {
        port + 1
    } else {
        SOURCE_PORTS.start
    }
}

/// The range a sweep's source port is taken from, clear of the well-known and
/// most registered ports a reply could be mistaken for.
const SOURCE_PORTS: std::ops::Range<u16> = 50_000..u16::MAX;

/// The gap between one sweep and the next.
///
/// A measurement parameter: too long and a counter can wrap inside the gap and
/// look random. The classifier's ceiling is 500 ms; this leaves room for a sweep
/// that runs late.
const SPACING: Duration = Duration::from_millis(100);

/// The most hosts followed in one timing window.
///
/// A sweep has to finish inside [`SPACING`], and is up to two probes per host. At
/// [`SEND_TICK`] that is 256 probes in 64 ms of a 100 ms interval, leaving the
/// rest for replies to arrive and be stamped. A larger set is followed as several
/// windows, costing wall-clock time but keeping the readings.
///
/// A host keeps its position in the sweep across samples, so each host is
/// measured over exactly the spacing; the batch size bounds only the spread
/// between the first host and the last.
const BATCH: usize = 128;

/// How fast probes leave within one sweep.
///
/// Fast, because time spent sending is subtracted from the interval the
/// classifiers read. A batch is at most 256 probes, then silence for the rest of
/// the spacing.
const SEND_TICK: Duration = Duration::from_micros(250);

/// How long to keep reading after the last sweep of a batch.
///
/// Generous: a slow answer carries the same counters as a fast one.
const LISTEN_AFTER_LAST: Duration = Duration::from_secs(2);

/// How long to block on the receive channel before checking the clock again.
///
/// Short, because this loop also paces the gap between samples and a coarse tick
/// would smear the interval a clock rate is computed over.
const RECV_TICK: Duration = Duration::from_millis(5);

/// One host and the ports it will be followed on.
///
/// Built only from ports the port scan already settled.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeriesTarget {
    /// The host to follow, as the store keys it.
    ///
    /// The probe is aimed at its
    /// [`addr`](crate::model::ip::scoped::ScopedIp::addr), and the reading is
    /// written back under the full key: a link-local host written back under a
    /// bare address would fork its record into a second entry.
    pub address: ScopedIp,
    /// A port that answered with a SYN+ACK: where the sequence generator and
    /// the peer's clock are readable.
    pub open: Option<u16>,
    /// A port that answered with a reset: where the identifier policy is.
    pub closed: Option<u16>,
}

impl SeriesTarget {
    /// What a host offers to follow, or `None` if it offers nothing.
    ///
    /// A host with no open or closed TCP port is left to the echo prober.
    ///
    /// `address` is passed in because a dual-stack machine is one record under
    /// several addresses, and the one to probe is the one the caller looked it
    /// up by, not its primary.
    pub fn for_host(address: ScopedIp, host: &Host) -> Option<Self> {
        let tcp = || host.ports().filter(|port| port.protocol() == Protocol::Tcp);
        // Lowest-numbered of each, so two runs follow the same ports.
        let open = tcp()
            .find(|port| port.state() == PortState::Open)
            .map(|port| port.number());
        let closed = tcp()
            .find(|port| port.state() == PortState::Closed)
            .map(|port| port.number());

        (open.is_some() || closed.is_some()).then_some(Self {
            address,
            open,
            closed,
        })
    }

    /// The probes one sweep sends for this host.
    fn ports(&self) -> impl Iterator<Item = u16> {
        self.open.into_iter().chain(self.closed)
    }
}

/// The samples of one host a sweep held for its neighbour and did not send.
#[derive(Debug, Clone)]
struct Owed {
    /// The host, with the ports a sweep asks it on.
    target: SeriesTarget,
    /// How many samples its open port is owed.
    open: usize,
    /// How many samples its closed port is owed.
    closed: usize,
}

/// One probe, recorded once it reached the wire, so a probe the kernel refused
/// is not counted as a silent host.
#[derive(Debug, Clone, Copy)]
struct Sent {
    address: IpAddr,
}

/// One host's replies, kept as two series because they come from two code paths.
#[derive(Debug, Default)]
struct Collected {
    /// What the handshake answers said.
    open: Track,
    /// What the refusals said.
    closed: Track,
}

/// One series: the readings, and the first reply whole.
#[derive(Debug, Default)]
struct Track {
    /// The first reply of this kind, entire: a rule's per-reply predicates
    /// (option layout, window, hop counter) read this.
    first: Option<StackObservation>,
    /// The readings, in arrival order.
    samples: Vec<SeriesSample>,
}

impl Track {
    fn record(&mut self, observed: StackObservation, sample: SeriesSample) {
        self.samples.push(sample);
        self.first.get_or_insert(observed);
    }

    /// This series as a reading a rule can be matched against, or `None` when
    /// nothing of this kind ever arrived.
    fn reading(&self) -> Option<(StackReply, SeriesClasses)> {
        let first = self.first.clone()?;
        Some((first.into(), SeriesClasses::from_samples(&self.samples)))
    }
}

/// Asks each host the same question several times and reads the policies behind
/// its counters.
///
/// Targets come from the store, since which hosts answered TCP and which the
/// passive sources could not name are known only after the port scan.
pub struct OsSeriesScanner {
    ctx: ScanContext,
    transport: ProbeTransport,
    /// The IP-header state every sample carries. Only the hop limit is taken
    /// from an evasion profile, since the sample's answer is the measurement; the
    /// source port varies per sample (see [`send_one`](Self::send_one)). See
    /// [`EvasionProfile::hop_limited_emission`](crate::evasion::EvasionProfile::hop_limited_emission).
    emission: Emission,
    resolver: SourceResolver,
    /// Hosts to follow, already cut into windows one sweep can fit inside.
    batches: VecDeque<Vec<SeriesTarget>>,
    /// How many times each host is asked.
    samples: usize,
    /// Which probe each nonce belongs to; a reply names its attempt, not its
    /// target.
    sent: HashMap<u32, Sent>,
    /// Nonces already answered, so a duplicate is not filed as a second reading.
    answered: HashSet<u32>,
    /// What has been read, per host.
    collected: HashMap<IpAddr, Collected>,
    audit: ProbeAudit,
    /// Why probes did not leave: this host's send path, or an address nothing
    /// reaches from here; and the hosts held through the kernel's hold-down on
    /// their neighbour (see [`SendFaults::hold`]). A held host's samples are
    /// dropped, since a sample sent a hold-down late would read as one taken
    /// then.
    faults: SendFaults,
    /// How far the current batch has read the resolution of each host's
    /// neighbour, which every sample is admitted through. See
    /// [`sweep`](Self::sweep).
    neighbors: NeighborGates,
    /// The hosts of the current batch found unreachable, sent nothing more.
    unreached: HashSet<IpAddr>,
    /// The samples of the current batch held for a neighbour and so not sent,
    /// by host, which the batch's make-up sweeps send; see
    /// [`make_up`](Self::make_up).
    owed: BTreeMap<ScopedIp, Owed>,
    /// How many hosts this run managed to name, for the closing line.
    named: usize,
    /// The source port the next sweep sends from.
    ///
    /// Drawn once and then counted up. Random draws per sweep could repeat an
    /// earlier sweep's 4-tuple, whose SYN would then describe the
    /// `SYN-RECEIVED` state the first left. A run takes at most
    /// [`AGGRESSIVE_SAMPLES`] sweeps per batch against a range of fifteen
    /// thousand; the random start keeps runs apart from each other.
    next_source_port: u16,
}

impl OsSeriesScanner {
    /// Opens the TCP transport and takes the hosts to follow. Fails where the
    /// raw socket cannot be had, telling the caller this level of detection is
    /// unavailable.
    pub fn new(
        ctx: ScanContext,
        targets: Vec<SeriesTarget>,
        samples: usize,
        tuning: ProbeTuning,
    ) -> Result<Self, StrategyError> {
        let transport = ProbeTransport::open_capturing(
            ProbeKind::TcpSyn,
            tuning.send_mode,
            &ctx.capture_links(),
        )?;
        Ok(Self::with_transport(
            ctx,
            targets,
            samples,
            transport,
            tuning.evasion.hop_limited_emission(),
        ))
    }

    /// Builds the scanner around a transport the caller opened, for tests and
    /// custom orchestration.
    pub fn with_transport(
        ctx: ScanContext,
        mut targets: Vec<SeriesTarget>,
        samples: usize,
        transport: ProbeTransport,
        emission: Emission,
    ) -> Self {
        // Sorted so two runs over one network follow the same hosts in the same
        // windows.
        targets.sort_unstable_by(|a, b| a.address.cmp(&b.address));
        targets.dedup_by(|a, b| a.address == b.address);

        let batches: VecDeque<Vec<SeriesTarget>> = targets
            .chunks(BATCH)
            .map(<[SeriesTarget]>::to_vec)
            .collect();

        Self {
            ctx,
            transport,
            emission,
            resolver: SourceResolver::from_system(),
            batches,
            // None of the three questions has an answer below two samples.
            samples: samples.max(2),
            sent: HashMap::new(),
            answered: HashSet::new(),
            collected: HashMap::new(),
            audit: ProbeAudit::new(),
            faults: SendFaults::default(),
            neighbors: NeighborGates::default(),
            unreached: HashSet::new(),
            owed: BTreeMap::new(),
            named: 0,
            next_source_port: rand::random_range(SOURCE_PORTS),
        }
    }

    /// The source port for one sweep, advancing the next one's within
    /// [`SOURCE_PORTS`].
    fn take_source_port(&mut self) -> u16 {
        let port = self.next_source_port;
        self.next_source_port = following(port);
        port
    }

    /// Sends one probe per port of every host in `batch`, from a source port of
    /// this sweep's own.
    ///
    /// Each sample is admitted through the batch's neighbour gates (see
    /// [`NeighborGates::admit`]). One held while a host's neighbour is asked for
    /// is dropped from the sweep, since a late sample costs the reading, and
    /// owed to a later sweep at the spacing; see [`make_up`](Self::make_up). Its
    /// tick still passes, so every other host keeps its place. A host whose
    /// neighbour is given up on is sent nothing more.
    ///
    /// Returns once the last probe is away. Replies are filed *while* it sends to
    /// keep the capture's queue drained: a full queue holds the capture thread,
    /// and a reply waiting behind it in the kernel is stamped when the thread
    /// gets to it, not when it arrived.
    async fn sweep(&mut self, batch: &[SeriesTarget]) {
        let source_port = self.take_source_port();
        let mut tick = tokio::time::interval(SEND_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);

        for target in batch {
            let address = target.address.addr();
            let Some(source) = self.resolver.resolve(address) else {
                continue;
            };
            for port in target.ports() {
                tick.tick().await;
                if self.unreached.contains(&address)
                    || self.faults.held_until(address, Instant::now()).is_some()
                {
                    continue;
                }
                let watch = self.transport.neighbors();
                match self
                    .neighbors
                    .admit(watch, &mut self.resolver, address, Instant::now())
                {
                    Admission::Send => self.send_one(source, address, source_port, port),
                    Admission::Hold(_) => self.owe(target, port),
                    Admission::Unreachable => {
                        let why = self.neighbors.refusal(address);
                        self.record_unreached(address, why);
                    }
                }
                self.file_queued();
            }
        }
        self.file_queued();
    }

    /// Notes that the sample of `target` on `port` was held for its
    /// neighbour and not sent, for a make-up sweep to send.
    fn owe(&mut self, target: &SeriesTarget, port: u16) {
        let owed = self
            .owed
            .entry(target.address.clone())
            .or_insert_with(|| Owed {
                target: target.clone(),
                open: 0,
                closed: 0,
            });
        if target.open == Some(port) {
            owed.open += 1;
        } else {
            owed.closed += 1;
        }
    }

    /// Sends the samples the batch's sweeps held for a neighbour, one sweep at a
    /// time at the spacing, so each port ends its series with as many samples as
    /// every other.
    ///
    /// Through the kernel, the first sample to a host whose neighbour is not
    /// cached is the write that asks for it, and the sample right behind it is
    /// held and dropped. Typically one sample at the start of a series is
    /// missing; a neighbour slower than the spacing costs one per sweep until it
    /// answers. Make-up sweeps are capped at the batch's own count, so a table
    /// that never settles cannot keep the batch running.
    async fn make_up(&mut self) -> Option<StopReason> {
        for _ in 0..self.samples {
            let due: Vec<SeriesTarget> = self
                .owed
                .values_mut()
                .map(|owed| {
                    let target = SeriesTarget {
                        address: owed.target.address.clone(),
                        open: owed.target.open.filter(|_| owed.open > 0),
                        closed: owed.target.closed.filter(|_| owed.closed > 0),
                    };
                    owed.open = owed.open.saturating_sub(1);
                    owed.closed = owed.closed.saturating_sub(1);
                    target
                })
                .filter(|target| target.open.is_some() || target.closed.is_some())
                .collect();
            if due.is_empty() {
                break;
            }
            let began = Instant::now();
            self.sweep(&due).await;
            self.drain_until(began + SPACING, false).await;
            if let Some(cause) = self.ctx.handle.stopped() {
                return Some(cause.into());
            }
        }
        None
    }

    /// Files every host of the batch whose neighbour was still unresolved when
    /// its sampling ended: the kernel still asking, or given up.
    ///
    /// The write that started the asking never left, so the address is filed as
    /// unreached, not as a silent host.
    fn conclude_pending_neighbors(&mut self) {
        for host in self.neighbors.waiting() {
            if self.unreached.contains(&host) {
                continue;
            }
            let watch = self.transport.neighbors();
            if let Some(state) = self.neighbors.pending(watch, &mut self.resolver, host)
                && state.is_unresolved()
            {
                let why = self.neighbors.unreached(host, state);
                self.record_unreached(host, why);
            }
        }
    }

    /// Files `address` as one nothing reaches from here, said once for the
    /// run, and sends it nothing more this batch.
    fn record_unreached(&mut self, address: IpAddr, why: String) {
        if self.faults.unroutable.is_none() {
            info!(verbosity = 2, "{address} unreachable ({why})");
        }
        self.faults.record_unreached(address, why);
        self.unreached.insert(address);
    }

    /// `batch`, less the hosts nothing reaches, once the neighbour of every
    /// host in it has answered or been given up.
    ///
    /// Resolved all at once before the first sample, since a sweep waiting
    /// inside a send would overrun the spacing for every host in the batch. A
    /// host whose neighbour never answered is filed unreached. Through the
    /// kernel, which asks only once a probe is written, an uncached neighbour is
    /// left to the sweeps' admission. See [`resolve_ahead`].
    async fn resolve_neighbors(&mut self, batch: Vec<SeriesTarget>) -> Vec<SeriesTarget> {
        let (gates, unreached) = resolve_ahead(
            &self.ctx,
            self.transport.neighbors(),
            &mut self.resolver,
            batch.iter().map(|target| target.address.addr()),
        )
        .await;
        self.neighbors = gates;
        self.unreached.clear();
        for (address, why) in unreached {
            self.record_unreached(address, why);
        }
        batch
            .into_iter()
            .filter(|target| !self.unreached.contains(&target.address.addr()))
            .collect()
    }

    /// Puts one probe on the wire and records the nonce it went out under.
    fn send_one(&mut self, source: IpAddr, address: IpAddr, source_port: u16, port: u16) {
        let nonce: u32 = rand::random();
        // The engine's own probe, so readings and rules track the shipped SYN.
        let segment = match tcp::build_probe(
            TcpScanTechnique::Syn,
            source,
            address,
            source_port,
            port,
            nonce,
        ) {
            Ok(segment) => segment,
            Err(e) => {
                error!(
                    verbosity = 2,
                    "cannot build a series probe for {address}: {e}"
                );
                self.audit.record_send(false);
                return;
            }
        };

        match self
            .transport
            .tx
            .send(&segment, source, address, None, self.emission)
        {
            Ok(()) => {
                self.sent.insert(nonce, Sent { address });
                self.audit.record_send(true);
            }
            Err(e) => {
                // The kernel's hold-down on the neighbour: nothing was sent, and
                // the host's samples are dropped while it lasts. See `faults`.
                if self.faults.hold(address, &e).is_some() {
                    return;
                }
                // Unroutable is the address's fact; only this host's own
                // refusals are the pass failing. Each said once. See `SendFaults`.
                if e.is_unroutable() {
                    if self.faults.unroutable.is_none() {
                        info!(verbosity = 2, "{address} unreachable ({e:#})");
                    }
                } else if self.faults.broken.is_none() {
                    error!(
                        verbosity = 2,
                        "failed to send a series probe to {address}: {e:#}"
                    );
                }
                self.faults.record(address, &e);
                self.audit.record_send(false);
            }
        }
    }

    /// Files every reply already waiting, without blocking.
    fn file_queued(&mut self) {
        while let Ok(reply) = self.transport.rx.try_recv() {
            self.audit.record_segment();
            self.file(&reply);
        }
    }

    /// Reads replies until `until`.
    ///
    /// `until_quiet` ends the wait early once every probe has been answered.
    /// Use it only *after* the last sweep of a batch: between samples the wait
    /// is the interval the classifiers read.
    async fn drain_until(&mut self, until: Instant, until_quiet: bool) {
        while Instant::now() < until {
            if self.ctx.handle.should_stop() {
                return;
            }
            if until_quiet && self.answered.len() == self.sent.len() {
                return;
            }
            let Ok(received) = tokio::time::timeout(RECV_TICK, self.transport.rx.recv()).await
            else {
                continue;
            };
            let Some(reply) = received else {
                return;
            };
            self.audit.record_segment();
            self.file(&reply);
        }
    }

    /// Files one reply against the probe whose nonce it echoes.
    fn file(&mut self, reply: &CapturedSegment) {
        if reply.protocol != IpNextHeaderProtocols::Tcp.0 {
            self.audit.record_off_target();
            return;
        }
        // When the capture took delivery: replies leave the capture's queue in
        // bursts, and stamping here would collapse intervals.
        let at = reply.received_at;

        let Ok(segment) = tcp::parse(&reply.bytes) else {
            self.audit.record_off_target();
            return;
        };
        // Ours only if it echoes a nonce we sent; the filter admits other
        // connections too. Series probes are never padded, so a reset
        // acknowledges the control span alone.
        let nonce = tcp::echoed_nonce(TcpScanTechnique::Syn, &segment, 0);
        let Some(&Sent { address }) = self.sent.get(&nonce) else {
            self.audit.record_off_target();
            return;
        };
        if !self.answered.insert(nonce) {
            // A duplicate, not a second reading.
            self.audit.record_reply_without_rtt();
            return;
        }

        // `None` means no IP header was kept (a synthetic receive stream).
        let Some(observation) = reply.observation else {
            return;
        };
        if observation.is_fragment() {
            // A fragment's identifier belongs to a datagram the path split, not
            // to a counter policy.
            return;
        }
        let Some(observed) = StackObservation::from_tcp(observation, &reply.bytes) else {
            return;
        };

        let sample = SeriesSample {
            at,
            flags: observed.flags,
            sequence: segment.sequence(),
            ip_id: match observation {
                IpObservation::V4(v4) => Some(v4.identification),
                IpObservation::V6(_) => None,
            },
            tsval: observed.timestamps.map(|stamps| stamps.value),
        };

        // Filed by what the reply *is*, not which port drew it, so a port whose
        // state changed since the scan cannot put a reset among the handshakes.
        let host = self.collected.entry(address).or_default();
        let track = if sample.is_syn_ack() {
            &mut host.open
        } else {
            &mut host.closed
        };
        track.record(observed, sample);
    }

    /// Reads what a batch's replies added up to, and records it against each
    /// host.
    ///
    /// One verdict per host however many replies it gave: passing them to
    /// [`os::identify`] separately would count a machine agreeing with itself as
    /// independent sources agreeing.
    fn conclude(&mut self, batch: &[SeriesTarget]) {
        for target in batch {
            let Some(collected) = self.collected.remove(&target.address.addr()) else {
                continue;
            };
            let readings: Vec<(StackReply, SeriesClasses)> =
                [collected.open.reading(), collected.closed.reading()]
                    .into_iter()
                    .flatten()
                    .collect();
            if readings.is_empty() {
                continue;
            }
            // Once per host, since the audit's ratio is over hosts; probes are
            // `sends_attempted`. `None`: there are no retries here.
            self.audit.record_host_found(None);

            let Some(verdict) = os::classify_series(os::RuleDb::global(), &readings) else {
                continue;
            };
            success!(
                verbosity = 2,
                "series probe named {} as {}",
                target.address,
                verdict.label()
            );
            self.named += 1;
            self.ctx.update_host(&target.address, |host| {
                os::identify(host, [verdict.as_evidence()]);
            });
        }

        // Anything left answered from an address nobody asked.
        self.collected.clear();
        self.sent.clear();
        self.answered.clear();
    }
}

impl OsSeriesScanner {
    /// The scan-wide gap between probes this pass cannot honour, or `None`
    /// when it can run.
    ///
    /// Within one sweep probes leave [`SEND_TICK`] apart. A scan-wide gap no
    /// wider than that is already satisfied, so the pass runs unchanged and
    /// claims no probe slot: waiting on the gate between samples would skew the
    /// intervals it measures. A wider gap would spread one series across it
    /// and make it unreadable, so the pass is skipped. The per-host gap does
    /// not apply to this pass. See
    /// [`ZondConfig::probe_interval`](crate::config::ZondConfig::probe_interval).
    ///
    /// Skipping is not recorded as a failure: the caller chose the pace, and
    /// the other identification sources still run.
    pub(crate) fn gap_it_cannot_keep(ctx: &ScanContext) -> Option<Duration> {
        ctx.scan_probe_interval().filter(|gap| *gap > SEND_TICK)
    }

    /// Asks each target the same question several times and reads the
    /// policies behind the answers.
    ///
    /// `Ok` once the run reached its end, including an end forced by
    /// [`ScanHandle::abort`](crate::scanner::handle::ScanHandle::abort), and
    /// `Err` only where the probe itself could not do its job.
    pub async fn probe(&mut self) -> Result<(), StrategyError> {
        // See `gap_it_cannot_keep`. Every target keeps the passive answer.
        if Self::gap_it_cannot_keep(&self.ctx).is_some() {
            return Ok(());
        }

        let followed: u128 = self.batches.iter().map(|batch| batch.len() as u128).sum();
        let mut reason = StopReason::AttemptsSpent;

        while let Some(batch) = self.batches.pop_front() {
            if let Some(cause) = self.ctx.handle.stopped() {
                reason = cause.into();
                break;
            }
            let batch = self.resolve_neighbors(batch).await;
            self.owed.clear();

            for _ in 0..self.samples {
                let began = Instant::now();
                self.sweep(&batch).await;
                // Paced from when the sweep *began*, so a sweep that ran long
                // eats into its own quiet time and the next starts on schedule.
                self.drain_until(began + SPACING, false).await;
                if let Some(cause) = self.ctx.handle.stopped() {
                    reason = cause.into();
                    break;
                }
            }
            if self.ctx.handle.stopped().is_none()
                && let Some(cause) = self.make_up().await
            {
                reason = cause;
            }

            self.drain_until(Instant::now() + LISTEN_AFTER_LAST, true)
                .await;
            self.conclude_pending_neighbors();
            self.conclude(&batch);

            if matches!(reason, StopReason::Aborted | StopReason::TimedOut) {
                break;
            }
        }

        self.faults.file(
            &self.ctx,
            ScannerKind::OsSeries,
            "series probes",
            self.audit.sends_attempted,
            self.audit.sends_failed,
        );
        if self.named > 0 {
            info!(
                verbosity = 1,
                "named {} from repeated probes",
                counted(self.named as u128, "host", "hosts")
            );
        }

        let capture = self.transport.capture_counts();
        self.audit
            .report("os-series", followed, reason, capture, None);
        self.ctx.record_probe_stats(self.audit.stats(
            ScannerKind::OsSeries,
            followed,
            reason,
            capture,
            None,
        ));
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU16, Ordering};

    use tokio::sync::mpsc;

    use crate::model::capture::Ipv4Observation;
    use crate::scanner::session::ScanSession;
    use crate::transport::capture::CaptureStream;
    use crate::transport::probe::{ProbeSender, SendError};

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    /// The port the synthetic host accepts on, and the one it refuses on.
    const OPEN: u16 = 22;
    const CLOSED: u16 = 81;

    /// The reply a stack sends, assembled from RFC 793's offsets by hand so a
    /// misreading shared with this crate's builder cannot pass as agreement.
    struct Reply {
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
        window: u16,
        options: Vec<u8>,
    }

    impl Reply {
        fn bytes(&self) -> Vec<u8> {
            let mut bytes = vec![0u8; 20 + self.options.len()];
            bytes[0..2].copy_from_slice(&self.source_port.to_be_bytes());
            bytes[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
            bytes[4..8].copy_from_slice(&self.sequence.to_be_bytes());
            bytes[8..12].copy_from_slice(&self.acknowledgement.to_be_bytes());
            bytes[12] = (((20 + self.options.len()) / 4) as u8) << 4;
            bytes[13] = self.flags;
            bytes[14..16].copy_from_slice(&self.window.to_be_bytes());
            bytes[20..].copy_from_slice(&self.options);
            bytes
        }
    }

    /// The options a current Linux kernel answers this engine's SYN with:
    /// maximum segment size, SACK permitted, timestamp, a padding byte, window
    /// scale: the `M,S,T,N,W` layout the shipped rule is written against.
    fn linux_options(tsval: u32) -> Vec<u8> {
        let mut options = Vec::with_capacity(20);
        options.extend_from_slice(&[2, 4]);
        options.extend_from_slice(&1460u16.to_be_bytes());
        options.extend_from_slice(&[4, 2]);
        options.extend_from_slice(&[8, 10]);
        options.extend_from_slice(&tsval.to_be_bytes());
        options.extend_from_slice(&0u32.to_be_bytes());
        options.push(1);
        options.extend_from_slice(&[3, 3, 7]);
        options
    }

    fn captured(bytes: Vec<u8>, identification: u16) -> CapturedSegment {
        CapturedSegment {
            received_at: Instant::now(),
            source: TARGET,
            destination: None,
            protocol: IpNextHeaderProtocols::Tcp.0,
            observation: Some(IpObservation::V4(Ipv4Observation {
                ttl: 64,
                identification,
                dont_fragment: true,
                more_fragments: false,
                dscp: 0,
                ecn: 0,
            })),
            source_mac: None,
            bytes,
        }
    }

    /// A host that accepts on [`OPEN`] and refuses on [`CLOSED`], answering the
    /// way a current Linux kernel does.
    ///
    /// The handshake answer writes identifier zero (RFC 6864 §4.1 permits it on
    /// a datagram that cannot be fragmented); the refusal runs a counter the
    /// whole host shares.
    struct Linux {
        replies: mpsc::Sender<CapturedSegment>,
        /// The host's shared identifier counter, read by its reset path.
        identifier: Arc<AtomicU16>,
        /// When this host booted, so its timestamp clock ticks at a rate.
        booted: Instant,
        /// Whether the refusing port answers at all, so a test can have a host
        /// that offers only a handshake.
        refuses: bool,
    }

    impl ProbeSender for Linux {
        fn send(
            &self,
            segment: &[u8],
            _src: IpAddr,
            _dst: IpAddr,
            _zone: Option<u32>,
            _emission: Emission,
        ) -> Result<(), SendError> {
            let source_port = u16::from_be_bytes([segment[0], segment[1]]);
            let destination_port = u16::from_be_bytes([segment[2], segment[3]]);
            let nonce = u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]);

            let reply = if destination_port == OPEN {
                // A 1000 Hz clock, as modern Linux runs, and an initial
                // sequence number with no common step (RFC 6528's hashed
                // generator).
                let ticks = self.booted.elapsed().as_millis() as u32;
                Reply {
                    source_port: destination_port,
                    destination_port: source_port,
                    sequence: rand::random(),
                    // The probe's SYN occupies one octet of sequence space.
                    acknowledgement: nonce.wrapping_add(1),
                    flags: crate::protocols::tcp::flags::SYN | crate::protocols::tcp::flags::ACK,
                    // 45 x 1448, the shape the shipped rule was measured from.
                    window: 65160,
                    options: linux_options(ticks),
                }
            } else if self.refuses {
                Reply {
                    source_port: destination_port,
                    destination_port: source_port,
                    sequence: 0,
                    acknowledgement: nonce.wrapping_add(1),
                    flags: crate::protocols::tcp::flags::RST | crate::protocols::tcp::flags::ACK,
                    window: 0,
                    options: Vec::new(),
                }
            } else {
                return Ok(());
            };

            let identification = if destination_port == OPEN {
                0
            } else {
                self.identifier.fetch_add(1, Ordering::Relaxed)
            };
            let _ = self
                .replies
                .try_send(captured(reply.bytes(), identification));
            Ok(())
        }
    }

    /// A scanner pointed at one synthetic Linux host, taking `samples` readings.
    fn scanner(
        ctx: &ScanContext,
        target: SeriesTarget,
        samples: usize,
        refuses: bool,
    ) -> OsSeriesScanner {
        let (tx, rx) = mpsc::channel(1024);
        let link = Linux {
            replies: tx,
            identifier: Arc::new(AtomicU16::new(1000)),
            booted: Instant::now(),
            refuses,
        };
        let transport = ProbeTransport::from_parts(Box::new(link), rx as CaptureStream);
        OsSeriesScanner::with_transport(
            ctx.clone(),
            vec![target],
            samples,
            transport,
            Emission::routed(),
        )
    }

    fn both_ports() -> SeriesTarget {
        SeriesTarget {
            address: ScopedIp::unscoped(TARGET),
            open: Some(OPEN),
            closed: Some(CLOSED),
        }
    }

    /// A host offers the *lowest* port of each kind the port scan found, so two
    /// runs follow the same ports.
    #[test]
    fn a_host_offers_the_lowest_port_of_each_kind_it_answered_on() {
        use crate::model::port::Port;

        let mut host = Host::new(TARGET);
        host.add_port(Port::new(443, Protocol::Tcp, PortState::Open));
        host.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
        host.add_port(Port::new(139, Protocol::Tcp, PortState::Closed));
        host.add_port(Port::new(81, Protocol::Tcp, PortState::Closed));

        let target = SeriesTarget::for_host(ScopedIp::unscoped(TARGET), &host)
            .expect("both kinds of answer");
        assert_eq!(target.open, Some(22));
        assert_eq!(target.closed, Some(81));
    }

    /// A host with no TCP answer offers nothing; it belongs to the echo prober.
    #[test]
    fn a_host_with_no_tcp_answer_is_not_a_target() {
        use crate::model::port::Port;

        let mut nothing = Host::new(TARGET);
        assert!(SeriesTarget::for_host(ScopedIp::unscoped(TARGET), &nothing).is_none());

        // A `NoReply` port gave no reply to repeat.
        nothing.add_port(Port::new(80, Protocol::Tcp, PortState::NoReply));
        assert!(SeriesTarget::for_host(ScopedIp::unscoped(TARGET), &nothing).is_none());

        // Nor does a UDP finding help: this scanner sends TCP.
        let mut udp = Host::new(TARGET);
        udp.add_port(Port::new(53, Protocol::Udp, PortState::Open));
        assert!(SeriesTarget::for_host(ScopedIp::unscoped(TARGET), &udp).is_none());
    }

    /// End to end: probes go out, replies form series, the series are
    /// classified, and the shipped corpus names the host.
    #[tokio::test(flavor = "current_thread")]
    async fn a_followed_host_is_named_from_what_its_replies_added_up_to() {
        let (session, ctx) = ScanSession::new();
        let mut scanner = scanner(&ctx, both_ports(), 4, true);

        scanner.probe().await.expect("the phase runs");

        let host = session.hosts().get(TARGET).expect("the host is recorded");
        let found = host.os().expect("a Linux-shaped series names Linux");
        assert_eq!(found.family(), Some("Linux"));
    }

    /// The finding's evidence carries what the *series* found, not only one
    /// packet's fields.
    #[tokio::test(flavor = "current_thread")]
    async fn the_finding_carries_the_series_readings_and_not_just_one_reply() {
        let (session, ctx) = ScanSession::new();
        let mut scanner = scanner(&ctx, both_ports(), 4, true);

        scanner.probe().await.expect("the phase runs");

        let host = session.hosts().get(TARGET).expect("the host is recorded");
        let evidence = host
            .os()
            .and_then(|os| os.evidence().map(str::to_owned))
            .expect("a finding with its evidence");

        assert!(
            evidence.contains("isn=hashed"),
            "a hashed generator is only visible across replies: {evidence}"
        );
        assert!(
            evidence.contains("ts=ticking"),
            "a clock rate needs two readings and an interval: {evidence}"
        );
    }

    /// This host writes identifier zero on the handshake path and runs a counter
    /// on the reset path; each series is read under its own policy.
    #[tokio::test(flavor = "current_thread")]
    async fn the_two_reply_kinds_are_read_as_two_series() {
        let (session, ctx) = ScanSession::new();
        let mut scanner = scanner(&ctx, both_ports(), 4, true);

        scanner.probe().await.expect("the phase runs");

        let evidence = session
            .hosts()
            .get(TARGET)
            .and_then(|host| host.os().and_then(|os| os.evidence().map(str::to_owned)))
            .expect("a finding with its evidence");

        assert!(
            evidence.contains("id=zero"),
            "the handshake path writes zero: {evidence}"
        );
        assert!(
            evidence.contains("id=counting"),
            "the reset path runs a counter, and pooling the two would hide it: {evidence}"
        );
    }

    /// A host offering only a handshake is read from the one series it gave.
    #[tokio::test(flavor = "current_thread")]
    async fn a_host_with_only_an_open_port_is_still_read() {
        let (session, ctx) = ScanSession::new();
        let target = SeriesTarget {
            address: ScopedIp::unscoped(TARGET),
            open: Some(OPEN),
            closed: None,
        };
        let mut scanner = scanner(&ctx, target, 4, false);

        scanner.probe().await.expect("the phase runs");

        let host = session.hosts().get(TARGET).expect("the host is recorded");
        assert_eq!(host.os().and_then(|os| os.family()), Some("Linux"));
    }

    /// Every sample has to be a new connection attempt: a repeated 4-tuple
    /// describes the `SYN-RECEIVED` state the first SYN created.
    #[tokio::test(flavor = "current_thread")]
    async fn each_sample_leaves_from_a_source_port_of_its_own() {
        use crate::transport::probe::MockSender;

        let (_session, ctx) = ScanSession::new();
        let mock = MockSender::default();
        let recorded = mock.sent.clone();
        let (_tx, rx) = mpsc::channel(1024);
        let transport = ProbeTransport::from_parts(Box::new(mock), rx as CaptureStream);

        let samples = 4;
        let target = SeriesTarget {
            address: ScopedIp::unscoped(TARGET),
            open: Some(OPEN),
            closed: None,
        };
        let mut scanner = OsSeriesScanner::with_transport(
            ctx.clone(),
            vec![target],
            samples,
            transport,
            Emission::routed(),
        );
        scanner.probe().await.expect("the phase runs");

        let sent = recorded.lock().expect("the record is readable").clone();
        assert_eq!(sent.len(), samples, "one probe per sample");

        let ports: std::collections::HashSet<u16> = sent
            .iter()
            .map(|(segment, _, _)| u16::from_be_bytes([segment[0], segment[1]]))
            .collect();
        assert_eq!(
            ports.len(),
            samples,
            "a repeated source port makes every sample after the first describe \
             a connection the previous one opened"
        );
    }

    /// A scan-wide gap slower than the series' cadence skips the pass: nothing
    /// is sent and nothing is recorded as failed.
    #[tokio::test(flavor = "current_thread")]
    async fn a_scan_wide_gap_slower_than_the_cadence_steps_the_series_aside() {
        use crate::transport::probe::MockSender;

        let (_session, ctx) = ScanSession::builder()
            .probe_interval(Some(SEND_TICK * 8))
            .build();
        let mock = MockSender::default();
        let recorded = mock.sent.clone();
        let (_tx, rx) = mpsc::channel(1024);
        let transport = ProbeTransport::from_parts(Box::new(mock), rx as CaptureStream);
        let mut scanner = OsSeriesScanner::with_transport(
            ctx.clone(),
            vec![both_ports()],
            4,
            transport,
            Emission::routed(),
        );

        scanner.probe().await.expect("the phase runs");

        assert!(
            recorded.lock().expect("readable").is_empty(),
            "not one sample is sent under a gap the measurement cannot honour"
        );
        assert!(
            ctx.failures_snapshot().is_empty(),
            "a pass the chosen pace rules out is not a pass that failed"
        );
    }

    /// A scan-wide gap the series' cadence already satisfies leaves the pass
    /// running, every sample sent.
    #[tokio::test(flavor = "current_thread")]
    async fn a_scan_wide_gap_within_the_cadence_leaves_the_series_running() {
        use crate::transport::probe::MockSender;

        let (_session, ctx) = ScanSession::builder()
            .probe_interval(Some(SEND_TICK / 2))
            .build();
        let mock = MockSender::default();
        let recorded = mock.sent.clone();
        let (_tx, rx) = mpsc::channel(1024);
        let transport = ProbeTransport::from_parts(Box::new(mock), rx as CaptureStream);
        let mut scanner = OsSeriesScanner::with_transport(
            ctx.clone(),
            vec![both_ports()],
            4,
            transport,
            Emission::routed(),
        );

        scanner.probe().await.expect("the phase runs");

        assert_eq!(
            recorded.lock().expect("readable").len(),
            8,
            "both ports, four samples each, all sent"
        );
    }

    /// Every sweep of a run takes its own source port, wherever in the range the
    /// run starts. (Drawn per sweep, two of a dozen samples would share a
    /// 4-tuple about once in 250 runs.)
    #[test]
    fn the_sweeps_of_a_run_never_share_a_source_port() {
        for start in [
            SOURCE_PORTS.start,
            SOURCE_PORTS.end - AGGRESSIVE_SAMPLES as u16 / 2,
            SOURCE_PORTS.end - 1,
        ] {
            let taken: Vec<u16> = std::iter::successors(Some(start), |&port| Some(following(port)))
                .take(AGGRESSIVE_SAMPLES)
                .collect();
            let distinct: HashSet<u16> = taken.iter().copied().collect();
            assert_eq!(
                distinct.len(),
                AGGRESSIVE_SAMPLES,
                "from {start}: {taken:?}"
            );
            assert!(taken.iter().all(|port| SOURCE_PORTS.contains(port)));
        }
    }

    /// A reply is timed by the capture that took it, not by when it was filed.
    ///
    /// Here a counter advances by fifty a tenth of a second apart, and three
    /// refusals are filed in one burst: stamped as filed, it would jump fifty at
    /// a time in no time at all.
    #[test]
    fn a_reply_is_timed_by_the_capture_that_took_it() {
        use crate::fingerprint::os::{IdClass, read_identifiers};
        use crate::protocols::tcp::flags;
        use crate::transport::probe::MockSender;

        let (_session, ctx) = ScanSession::new();
        let (_tx, rx) = mpsc::channel(1);
        let transport = ProbeTransport::from_parts(Box::new(MockSender::default()), rx);
        let mut scanner = OsSeriesScanner::with_transport(
            ctx,
            vec![both_ports()],
            3,
            transport,
            Emission::routed(),
        );

        let first = Instant::now();
        for (nth, identification) in [100u16, 150, 200].into_iter().enumerate() {
            let nonce = 0x5eed_0000 + nth as u32;
            scanner.sent.insert(nonce, Sent { address: TARGET });
            let refusal = Reply {
                source_port: CLOSED,
                destination_port: 50_000,
                sequence: 0,
                acknowledgement: nonce.wrapping_add(1),
                flags: flags::RST | flags::ACK,
                window: 0,
                options: Vec::new(),
            };
            scanner.file(&CapturedSegment {
                received_at: first + SPACING * nth as u32,
                ..captured(refusal.bytes(), identification)
            });
        }

        let refusals = &scanner.collected[&TARGET].closed.samples;
        let reading = read_identifiers(refusals);
        assert_eq!(reading.class, IdClass::Counting, "{}", reading.line);
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
            let transport =
                ProbeTransport::from_parts(Box::new(Refusing(refusal)), rx as CaptureStream);
            let mut scanner = OsSeriesScanner::with_transport(
                ctx.clone(),
                vec![both_ports()],
                2,
                transport,
                Emission::routed(),
            );

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

    /// A sample refused for a hold-down on the host's neighbour (`EHOSTDOWN` on
    /// macOS) is dropped and the host sampled again once it is over. Refused for
    /// a second hold-down after waiting one out, the host is filed unreached.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn a_sample_refused_for_a_hold_down_is_not_the_host_s_verdict() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// Refuses its first `refused` samples as macOS does inside a
        /// hold-down, and counts the ones it takes.
        struct HeldDown {
            refused: usize,
            asked: Arc<AtomicUsize>,
            taken: Arc<AtomicUsize>,
        }

        impl ProbeSender for HeldDown {
            fn send(
                &self,
                _s: &[u8],
                _src: IpAddr,
                _dst: IpAddr,
                _zone: Option<u32>,
                _emission: Emission,
            ) -> Result<(), SendError> {
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
            let transport = ProbeTransport::from_parts(Box::new(sender), rx as CaptureStream);
            let mut scanner = OsSeriesScanner::with_transport(
                ctx.clone(),
                vec![both_ports()],
                3,
                transport,
                Emission::routed(),
            );
            // Over as soon as it is met, so the next sample asks again.
            scanner.faults.held_down.hold_down_for = Duration::ZERO;

            scanner.probe().await.expect("the phase runs");

            let failures = ctx.failures_snapshot();
            assert!(
                failures.is_empty(),
                "a hold-down failed the pass: {failures:?}"
            );
            if unreached {
                assert_eq!(ctx.take_unroutable(), vec![TARGET], "held down twice");
            } else {
                assert!(ctx.take_unroutable().is_empty(), "filed on one hold-down");
                assert!(taken.load(Ordering::SeqCst) > 0, "never sampled again");
            }
        }
    }

    /// A segment carrying a nonce this scan never sent must not name or record
    /// the host; the filter admits far more than this scan's replies.
    #[tokio::test(flavor = "current_thread")]
    async fn a_segment_this_scan_never_drew_is_not_a_reading() {
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
        let transport = ProbeTransport::from_parts(Box::new(Silent), rx as CaptureStream);
        let mut scanner = OsSeriesScanner::with_transport(
            ctx.clone(),
            vec![both_ports()],
            2,
            transport,
            Emission::routed(),
        );

        // A Linux-shaped handshake answer acknowledging a nonce never sent.
        let theirs = Reply {
            source_port: OPEN,
            destination_port: 40_000,
            sequence: 12345,
            acknowledgement: 0xDEAD_BEEF,
            flags: crate::protocols::tcp::flags::SYN | crate::protocols::tcp::flags::ACK,
            window: 65160,
            options: linux_options(1000),
        };
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = tx.try_send(captured(theirs.bytes(), 0));
        });

        scanner.probe().await.expect("the phase runs");

        assert!(
            session.hosts().get(TARGET).is_none(),
            "a segment answering no probe of ours records nothing whatsoever"
        );
    }

    /// A batch through a frame sender resolves every new neighbour at once
    /// before its first sample: dead ones are reported unreached with nothing
    /// sent, and a live one has every sample leave.
    #[tokio::test]
    async fn neighbours_behind_a_frame_sender_are_asked_for_before_the_first_sample() {
        use crate::system::interface::{Link, LinkAddress};
        use crate::transport::link::{LinkNeighbors, SIMULATED_HOST};
        use crate::transport::probe::MockSender;

        const LIVE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 62);
        const SAMPLES: usize = 3;
        let dead: Vec<IpAddr> = (191..=200)
            .map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
            .collect();
        let (_session, ctx) = ScanSession::new();
        let (_tx, rx) = mpsc::channel(1024);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport = ProbeTransport::from_parts(Box::new(sender), rx as CaptureStream)
            .with_link_neighbors(LinkNeighbors::on_simulated_segment("sim-series0", &[LIVE]));
        let targets = dead
            .iter()
            .copied()
            .chain([IpAddr::V4(LIVE)])
            .map(|address| SeriesTarget {
                address: ScopedIp::unscoped(address),
                open: Some(OPEN),
                closed: Some(CLOSED),
            })
            .collect();
        let mut scanner = OsSeriesScanner::with_transport(
            ctx.clone(),
            targets,
            SAMPLES,
            transport,
            Emission::routed(),
        );
        scanner.resolver = SourceResolver::from_links(&[Link::new("test0", 0)
            .with_addresses(vec![LinkAddress::new(IpAddr::V4(SIMULATED_HOST), 24)])]);

        scanner.probe().await.expect("the phase runs");

        let sent = sent.lock().unwrap();
        assert!(
            sent.iter().all(|(_, _, dst)| *dst == IpAddr::V4(LIVE)),
            "a probe was handed to the sender for a neighbour nobody had resolved"
        );
        assert_eq!(
            sent.len(),
            SAMPLES * 2,
            "every sample of the live host leaves"
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

    /// Through the kernel, the first sample to an uncached neighbour is the
    /// write that asks for it, and the samples behind it wait on the verdict:
    /// a dead neighbour is sent nothing more and reported unreached; a live or
    /// already cached one has every sample leave.
    #[tokio::test]
    async fn samples_behind_the_kernel_asking_for_a_neighbour_wait_on_its_verdict() {
        use crate::system::interface::{Link, LinkAddress};
        use crate::transport::kernel_neighbors::KernelNeighbors;
        use crate::transport::probe::MockSender;

        const SAMPLES: usize = 3;
        let held = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 61));
        let live = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 62));
        let dead: Vec<IpAddr> = (191..=194)
            .map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
            .collect();
        let (_session, ctx) = ScanSession::new();
        let (_tx, rx) = mpsc::channel(1024);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let table = KernelNeighbors::asking_on_write(sent.clone(), &[held], &[live]);
        let transport = ProbeTransport::from_parts(Box::new(sender), rx as CaptureStream)
            .with_kernel_neighbors(table);
        let targets = dead
            .iter()
            .copied()
            .chain([held, live])
            .map(|address| SeriesTarget {
                address: ScopedIp::unscoped(address),
                open: Some(OPEN),
                closed: Some(CLOSED),
            })
            .collect();
        let mut scanner = OsSeriesScanner::with_transport(
            ctx.clone(),
            targets,
            SAMPLES,
            transport,
            Emission::routed(),
        );
        scanner.resolver =
            SourceResolver::from_links(&[Link::new("test0", 1).with_addresses(vec![
                LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24),
            ])]);

        scanner.probe().await.expect("the phase runs");

        let sent = sent.lock().unwrap();
        let to = |address: IpAddr| sent.iter().filter(|(_, _, dst)| *dst == address).count();
        for &address in &dead {
            assert_eq!(
                to(address),
                1,
                "{address} was sent past the write that asked"
            );
        }
        assert_eq!(to(held), SAMPLES * 2, "a neighbour the kernel held");
        assert_eq!(to(live), SAMPLES * 2, "a neighbour that answered");
        let mut unreached = ctx.take_unroutable();
        unreached.sort();
        assert_eq!(
            unreached, dead,
            "every dead neighbour is reported unreached"
        );
    }

    /// A neighbour slower to resolve than a sweep's tick costs the sample behind
    /// the asking write, and a make-up sweep sends it: both ports end with every
    /// sample.
    #[tokio::test]
    async fn a_sample_held_behind_the_asking_write_is_made_up_after_the_last_sweep() {
        use crate::system::interface::{Link, LinkAddress};
        use crate::transport::kernel_neighbors::{KernelNeighbors, NeighborState, NeighborTable};
        use crate::transport::probe::MockSender;

        const SAMPLES: usize = 3;
        /// How long the neighbour takes to answer once asked: longer than a
        /// tick, well inside a spacing.
        const RESOLVING: Duration = Duration::from_millis(5);
        let slow = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 63));
        let (_session, ctx) = ScanSession::new();
        let (_tx, rx) = mpsc::channel(1024);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let written = sent.clone();
        let asked = std::sync::Mutex::new(None::<Instant>);
        let table = KernelNeighbors::with_reader(Box::new(move || {
            let mut table = NeighborTable::new();
            if written.lock().expect("the record").is_empty() {
                return Ok(table);
            }
            let asked = *asked
                .lock()
                .expect("the stamp")
                .get_or_insert_with(Instant::now);
            let state = match asked.elapsed() < RESOLVING {
                true => NeighborState::Resolving,
                false => NeighborState::Resolved,
            };
            table.insert(slow, state);
            Ok(table)
        }));
        let transport = ProbeTransport::from_parts(Box::new(sender), rx as CaptureStream)
            .with_kernel_neighbors(table);
        let mut scanner = OsSeriesScanner::with_transport(
            ctx.clone(),
            vec![SeriesTarget {
                address: ScopedIp::unscoped(slow),
                open: Some(OPEN),
                closed: Some(CLOSED),
            }],
            SAMPLES,
            transport,
            Emission::routed(),
        );
        scanner.resolver =
            SourceResolver::from_links(&[Link::new("test0", 1).with_addresses(vec![
                LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24),
            ])]);

        scanner.probe().await.expect("the phase runs");

        let sent = sent.lock().unwrap();
        let to = |port: u16| {
            sent.iter()
                .filter(|(segment, _, _)| {
                    tcp::parse(segment).is_ok_and(|probe| probe.destination_port() == port)
                })
                .count()
        };
        assert_eq!(to(OPEN), SAMPLES, "the open port's samples");
        assert_eq!(to(CLOSED), SAMPLES, "the closed port's samples");
    }
}
