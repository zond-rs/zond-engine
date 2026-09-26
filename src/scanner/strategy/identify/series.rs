// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The active operating-system series probe
//!
//! One host, asked the same question several times, so that the *policies*
//! behind its counters become visible.
//!
//! ## What one reply cannot say
//!
//! Everything the passive path knows comes from a single reply, and three of the
//! features that separate one build of a stack from the next are not in a single
//! reply at all. An IP identifier of `0` is consistent with a stack that always
//! writes zero, one that runs a per-socket counter which happened to start
//! there, and one that randomises. An initial sequence number is a number; a
//! *generator*, fixed step, multiples, hashed per RFC 6528, is what several of
//! them are. A timestamp clock's rate needs two readings and the interval
//! between them.
//!
//! Those three are exactly the axis a release-level rule turns on, because they
//! are decisions a stack's authors made and changed between releases, where the
//! option layout and the initial hop counter have been stable for decades. A
//! corpus that wants to say "Linux 6.x" rather than "Linux" is a corpus that
//! needs this scanner's readings to say it with.
//!
//! ## The probe is the one the scanner already sends
//!
//! There is no new packet shape here: every probe is
//! [`crate::protocols::tcp::build_probe`] for
//! [`TcpScanTechnique::Syn`], the same segment an ordinary SYN scan sends. What
//! differs is only that each target is asked more than once.
//!
//! That decides what this costs. A repeated SYN carries nothing malformed and is
//! indistinguishable from a client retrying a connection; it is *extra* traffic
//! aimed at hosts the caller may only have meant to enumerate, which is why it
//! sits behind [`OsDetection::Active`](crate::config::OsDetection) rather than
//! being on by default, but it is not traffic of an unusual shape.
//!
//! ## Every sample leaves from a fresh source port
//!
//! Two SYNs to one host and port from one source port are the same 4-tuple, so
//! the second is not a second connection attempt: the first has already put the
//! peer in `SYN-RECEIVED`, and what comes back describes that state rather than
//! the stack holding it. A fresh source port per sweep makes each sample a
//! genuine new connection, which is what the sequence-number question needs: an
//! initial sequence number is chosen per connection, and sampling one connection
//! repeatedly measures nothing.
//!
//! It is also why no settle period is needed between samples, and that matters,
//! because the spacing here is a **measurement parameter** rather than hygiene.
//!
//! ## Two ports per host, and the reason is a measurement
//!
//! An earlier sampling run followed one port per host, preferring an open one,
//! and reported "identifiers zero throughout" for every host that answered: no
//! discrimination at all. The same run's *closed* ports, on the same hosts in
//! the same sweep, separated three of them three ways: one counting, one
//! scattered, one zero.
//!
//! The two answers live in different replies. A SYN+ACK is an atomic datagram
//! with don't-fragment set, and RFC 6864 §4.1 releases its sender from putting
//! anything meaningful in the identification field; a reset from the same host
//! is where the identifier policy shows. Meanwhile a reset opens no connection
//! and carries no options, so the sequence generator and the peer's clock are
//! readable only from the SYN+ACK. Following one port answers half the question
//! and reports the other half as "nothing here", which is not the same as having
//! measured it.
//!
//! So a host is followed on both where the port scan found both, and the two
//! series are kept **apart**: a stack's reset path and its handshake path are
//! different code that can disagree about the same field, so a series mixing
//! them would compare a host against itself under two policies. See
//! [`series`](crate::fingerprint::os::SeriesClasses) and
//! [`classify_series`](crate::fingerprint::os::classify_series).
//!
//! ## Why the spacing is short, and what bounds a run
//!
//! A 16-bit identifier counter wraps every 65 536 packets. Sampled across a gap
//! long enough for a busy host to wrap it, a counter and a random number are the
//! same observation, and the classifier refuses to read one rather than guess:
//! half a second between samples is the bound
//! [`read_identifiers`](crate::fingerprint::os::read_identifiers) holds a
//! series to.
//!
//! That is a constraint on this scanner, not just on its rules: **one sweep has
//! to finish inside the spacing**, or every host in it is reported as unclear
//! and the traffic bought nothing. Hosts are therefore followed in batches small
//! enough for a sweep to fit, and each batch is its own timing window rather
//! than a slice of one long one. `BATCH` is that size, and carries the
//! arithmetic behind it.
//!
//! ## Why there is no retransmission
//!
//! Every other scanner here resends what went unanswered. This one does not, and
//! it is the same fact read again: a retry arrives at a moment nothing planned,
//! and the interval between two readings *is* the measurement. A sample that
//! goes missing costs one sample; a sample that arrives at an unintended time
//! costs the reading. The classifiers already report a short series as
//! [`TooFew`](crate::fingerprint::os::IdClass::TooFew) rather than straining to
//! answer, which is the correct outcome for a host that answered four times out
//! of six.
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
/// policy needs at least three values before "constant" and "counting" are
/// different observations; a clock rate wants a span rather than a pair, so that
/// one late reply cannot set it; and a generator's step is a property of several
/// differences rather than one. Past six the marginal sample buys precision on a
/// rate rather than a class, and every one of them is a packet per port per
/// host.
///
/// [`OsDetection::Active`]: crate::config::OsDetection::Active
pub const ACTIVE_SAMPLES: usize = 6;

/// How many times each host is asked at
/// [`OsDetection::Aggressive`](crate::config::OsDetection::Aggressive).
///
/// Twice the traffic for a reading that refuses less often: the classifiers
/// decline a series whose values do not settle, and the commonest reason a run
/// declines is that too few of its samples came back. It buys no new *kind* of
/// answer, which is why it is a level rather than the default.
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

/// The range a sweep's source port is taken from, clear of the well-known
/// and most registered ports a reply could otherwise be mistaken for.
const SOURCE_PORTS: std::ops::Range<u16> = 50_000..u16::MAX;

/// The gap between one sweep and the next.
///
/// A measurement parameter, not politeness. Too long and the identifier question
/// stops having an answer, because a counter can wrap inside the gap and become
/// indistinguishable from a random value; the classifier's own ceiling is 500 ms
/// and this leaves room beneath it for a sweep that runs late.
const SPACING: Duration = Duration::from_millis(100);

/// The most hosts followed in one timing window.
///
/// A sweep has to finish inside [`SPACING`], and a sweep is up to two probes per
/// host. At [`SEND_TICK`] that is 256 probes in 64 ms of a 100 ms interval,
/// leaving the remainder for replies to arrive and be stamped. Beyond this the
/// window is missed and every reading in it degrades to "sampled too slowly", so
/// a larger set is followed as several windows rather than one long one, which
/// costs wall-clock time and keeps the readings.
///
/// A host keeps its position in the sweep across every sample, so the interval
/// *each host* is measured over is the spacing regardless of where in the batch
/// it sits. What the batch size bounds is the spread between the first host and
/// the last, not the consistency of any one series.
const BATCH: usize = 128;

/// How fast probes leave within one sweep.
///
/// Fast, and it has to be: the whole sweep is one sample of a series, and time
/// spent sending is time subtracted from the interval the classifiers read. This
/// is not the rate a scan is paced at: a batch is at most 256 probes and then
/// the scanner is silent for the rest of the spacing.
const SEND_TICK: Duration = Duration::from_micros(250);

/// How long to keep reading after the last sweep of a batch.
///
/// Generous: a slow answer carries the same counters as a fast one, and dropping
/// it costs a sample the series cannot get back.
const LISTEN_AFTER_LAST: Duration = Duration::from_secs(2);

/// How long to block on the receive channel before checking the clock again.
///
/// Short, because this loop also paces the gap between samples, and a coarse
/// tick would smear the interval a clock rate is computed over.
const RECV_TICK: Duration = Duration::from_millis(5);

/// One host and the ports it will be followed on.
///
/// Built from what the port scan already found, never from a guess: this
/// scanner revisits ports whose state is settled and asks a different question
/// about them, and probing a port nobody established anything about would be a
/// port scan wearing another name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeriesTarget {
    /// The host to follow, as the store keys it.
    ///
    /// The key rather than a bare address, because this is both what the probe
    /// is aimed at, through [`addr`](crate::model::ip::scoped::ScopedIp::addr),
    /// and what the reading is written back under. A link-local host written
    /// back under a bare address would fork its record into a second entry.
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
    /// A host that answered no TCP probe at all is not a target here however
    /// little is known about it: there is no port to ask again. That host is
    /// the echo prober's, which is the only route left to it.
    ///
    /// `address` is given rather than read off the host because a dual-stack
    /// machine is one record under several addresses, and the one to probe is
    /// the one the caller looked it up by: probing its primary instead would
    /// silently ask a different question over a different protocol.
    pub fn for_host(address: ScopedIp, host: &Host) -> Option<Self> {
        let tcp = || host.ports().filter(|port| port.protocol() == Protocol::Tcp);
        // Lowest-numbered of each, so two runs against one host follow the same
        // ports and their readings are comparable.
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

/// One probe, recorded when it reached the wire and not before. A probe the
/// kernel refused is not a host that stayed silent.
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
    /// The first reply of this kind, entire. A rule's per-reply predicates,
    /// the option layout, the window, the hop counter, read this, and the
    /// series classes are matched beside it.
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
/// Targets come from the store rather than from the plan, because "this host
/// answered a TCP probe" and "the passive sources could not name it" are both
/// facts about the store and only become true once the port scan has finished.
pub struct OsSeriesScanner {
    ctx: ScanContext,
    transport: ProbeTransport,
    /// The IP-header state every sample carries. Only the hop limit is taken
    /// from an evasion profile: a sample's answer is the measurement, so it must
    /// not be reshaped, and its source port is varied per sample
    /// (see [`send_one`](Self::send_one)) rather than pinned. See
    /// [`EvasionProfile::hop_limited_emission`](crate::evasion::EvasionProfile::hop_limited_emission).
    emission: Emission,
    resolver: SourceResolver,
    /// Hosts to follow, already cut into windows one sweep can fit inside.
    batches: VecDeque<Vec<SeriesTarget>>,
    /// How many times each host is asked.
    samples: usize,
    /// Which probe each nonce belongs to, since a reply names its attempt
    /// rather than its target.
    sent: HashMap<u32, Sent>,
    /// Nonces already answered, so a duplicate is counted as the path repeating
    /// itself rather than filed as a second reading.
    answered: HashSet<u32>,
    /// What has been read, per host.
    collected: HashMap<IpAddr, Collected>,
    audit: ProbeAudit,
    /// Why probes did not leave, split by whose fact it was: this host's send
    /// path, or an address nothing reaches from here.
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
    /// Drawn once and then counted up, rather than drawn per sweep: a sample
    /// has to be a new connection attempt, and a second sweep drawing the
    /// port an earlier one used repeats that sample's 4-tuple, so its SYN
    /// describes the `SYN-RECEIVED` state the first left rather than the
    /// stack. Counting gives every sweep of a run a port of its own, since a
    /// run takes at most [`AGGRESSIVE_SAMPLES`] sweeps per batch against a
    /// range of fifteen thousand; drawing the start keeps runs apart from each
    /// other and from a fixed guess.
    next_source_port: u16,
}

impl OsSeriesScanner {
    /// Opens the TCP transport this scanner needs and takes the hosts to
    /// follow. Fails where the raw socket cannot be had, which is the caller's
    /// signal that this level of detection is unavailable rather than silent.
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

    /// Builds the scanner around a transport the caller opened, which is the
    /// seam a test or a custom orchestration drives it through.
    pub fn with_transport(
        ctx: ScanContext,
        mut targets: Vec<SeriesTarget>,
        samples: usize,
        transport: ProbeTransport,
        emission: Emission,
    ) -> Self {
        // Sorted so a run is reproducible and two runs over one network follow
        // the same hosts in the same windows.
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
            // Two is the floor below which none of the three questions has an
            // answer, and a caller asking for one sample has asked for the
            // passive path with extra packets.
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

    /// Sends one probe per port of every host in `batch`, from a source port of
    /// this sweep's own.
    ///
    /// Each sample is admitted through the batch's neighbour gates, as every
    /// pass's probes are (see [`NeighborGates::admit`]), and one held while a
    /// host's neighbour is asked for is dropped from the sweep rather than
    /// sent late: the spacing is the measurement, and a sample at an
    /// unplanned moment costs the reading. It is owed instead, and a sweep
    /// after the last sends it at the spacing; see [`make_up`](Self::make_up).
    /// Its tick passes all the same, so every other host keeps its place in
    /// the sweep. A host whose neighbour is given up on is sent nothing more.
    ///
    /// Returns once the last probe is away. Replies are filed *while* it sends
    /// rather than afterwards, which keeps the capture's queue drained. A
    /// reading carries the moment the capture took delivery of it, so filing
    /// late does not move its stamp, but a queue left to fill holds the capture
    /// thread, and a reply waiting behind it in the kernel is stamped when the
    /// thread gets to it rather than when it arrived. The filter admits more
    /// than this scan's own replies, so how soon that happens is the network's
    /// to decide.
    /// The source port for one sweep, and the next one's after it, wrapping
    /// within [`SOURCE_PORTS`].
    fn take_source_port(&mut self) -> u16 {
        let port = self.next_source_port;
        self.next_source_port = following(port);
        port
    }

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
                if self.unreached.contains(&address) {
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

    /// Sends the samples the batch's sweeps held for a neighbour, one sweep
    /// at a time at the spacing, so each port the neighbour cost a sample
    /// ends its series with as many as every other.
    ///
    /// Through the kernel, the first sample of a host whose neighbour it does
    /// not hold is the write that asks for it, and a sample right behind it
    /// in the same sweep is sent a tick later, before a neighbour on a real
    /// link has answered: that one is held, and dropped from the sweep so the
    /// spacing holds. The neighbour has answered long before the next sweep,
    /// so what is missing is one sample at the start of that port's series,
    /// and a sweep after the last makes it up at the same spacing. A
    /// neighbour slower than a spacing costs a sample in each sweep until it
    /// answers or is given up on, and is made up in as many; the make-up
    /// sweeps are held to as many as the batch's own, so a table that never
    /// settles cannot keep the batch running.
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
    /// The one write that started the asking is all that host was sent, and it
    /// never left while the kernel asked, so the address is one nothing
    /// reached rather than a host that stayed silent.
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
    /// Asked for all at once and waited for before the first sample, rather
    /// than met one at a time by the sends: a sweep that waited inside a send
    /// for a neighbour to answer would overrun the spacing the samples are
    /// read across, for every host in the batch. A host whose neighbour never
    /// answered is filed unreached and sent nothing. Through the kernel, which
    /// asks only once a probe is written, a host whose neighbour it does not
    /// already hold is left to the sweeps' admission instead. See
    /// [`resolve_ahead`].
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
        // The engine's own probe, not a reproduction of it. If the shipped SYN
        // changes, these readings change with it rather than quietly describing
        // a packet the scanner no longer sends, and the rules, which are
        // authored against that same segment, stay applicable.
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
                // Recorded after a successful send, which is the point of
                // recording it there: a probe the kernel refused is not a host
                // that stayed silent.
                self.sent.insert(nonce, Sent { address });
                self.audit.record_send(true);
            }
            Err(e) => {
                // An address nothing reaches is the address's fact and is
                // reported against it; only this host's own refusals are the
                // pass failing. Each said once. See `SendFaults`.
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
    /// `until_quiet` ends the wait early once every probe sent has been
    /// answered. Correct only *after* the last sweep of a batch: between two
    /// samples the wait is the measurement, and cutting it short because the
    /// replies arrived promptly would start the next sweep early and shrink the
    /// very interval the classifiers read.
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
        if reply.protocol != IpNextHeaderProtocols::Tcp {
            self.audit.record_off_target();
            return;
        }
        // When the capture took delivery, not when this got round to filing it.
        // Every interval the classifiers read is a difference of two of these,
        // and replies leave the capture's queue in bursts: stamped here, two
        // that arrived a sweep apart would read as having arrived together.
        let at = reply.received_at;

        let Ok(segment) = tcp::parse(&reply.bytes) else {
            self.audit.record_off_target();
            return;
        };
        // A reply is one of ours only if it echoes a nonce we sent. Without the
        // check every segment the filter admits is read as an answer, and on a
        // busy host that is a table of other people's connections.
        // The OS-detection series does not carry an evasion profile, so its
        // probes are never padded and the reset acknowledges the control span
        // alone.
        let nonce = tcp::echoed_nonce(TcpScanTechnique::Syn, &segment, 0);
        let Some(&Sent { address }) = self.sent.get(&nonce) else {
            self.audit.record_off_target();
            return;
        };
        if !self.answered.insert(nonce) {
            // A duplicate: the path repeating itself, not a second reading.
            self.audit.record_reply_without_rtt();
            return;
        }

        // `None` means no IP header was ever kept, a synthetic receive stream,
        // rather than that nothing notable was in one.
        let Some(observation) = reply.observation else {
            return;
        };
        if observation.is_fragment() {
            // A fragment's header describes the fragment. Its identifier
            // belongs to a datagram the path split, not to a counter policy.
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

        // Filed by what the reply *is* rather than by which port drew it. A
        // stack's handshake path and its reset path disagree about these fields,
        // and a port whose state changed since the scan classified it would
        // otherwise put a reset into the series read as handshakes.
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
    /// One verdict per host however many replies it gave: they all came from one
    /// stack, so passing them to [`os::identify`] separately would put a machine
    /// agreeing with itself through the same arithmetic as two independent
    /// sources agreeing with each other.
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
            // Once per host and not once per reply: this run's targets are
            // hosts, so the ratio the audit reports has to be hosts too. How
            // many probes it took is `sends_attempted`, which is counted
            // separately and is the other half of the picture.
            //
            // `None` because there are no retries here: every probe is a first
            // attempt, and claiming otherwise would put readings in a bucket
            // that exists to say whether retransmission earned its traffic.
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

        // Anything left belongs to a host that answered from an address nobody
        // asked, and nothing here can attribute it.
        self.collected.clear();
        self.sent.clear();
        self.answered.clear();
    }
}

impl OsSeriesScanner {
    /// Asks each target the same question several times and reads the
    /// policies behind the answers.
    ///
    /// Not `discover_hosts`, for the reason
    /// [`echo`](super::echo::OsEchoScanner::probe) gives: every host here has
    /// already been found, and this revisits a port whose state is already
    /// settled.
    ///
    /// `Ok` once the run reached its end, including an end forced by
    /// [`ScanHandle::abort`](crate::scanner::handle::ScanHandle::abort), and
    /// `Err` only where the probe itself could not do its job.
    pub async fn probe(&mut self) -> Result<(), StrategyError> {
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
                // Paced from the moment the sweep *began*, so a sweep that ran
                // long eats into its own quiet time rather than pushing the next
                // sample out and widening every interval behind it.
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

    /// The reply a stack sends, assembled from RFC 793's offsets rather than
    /// through this crate's own builder, so a shared misreading of what a TCP
    /// header is cannot pass for agreement between the two.
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
            protocol: IpNextHeaderProtocols::Tcp,
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
    /// The two answers differ in more than their flags, and that difference is
    /// the whole point of following two ports: the handshake answer writes
    /// identifier zero: RFC 6864 §4.1 permits it on a datagram that cannot be
    /// fragmented, while the refusal runs a counter the whole host shares.
    struct Linux {
        replies: mpsc::Sender<CapturedSegment>,
        /// The host's shared identifier counter, read by its reset path.
        identifier: Arc<AtomicU16>,
        /// When this host booted, so its timestamp clock can tick at a rate
        /// rather than jump.
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
                // A 1000 Hz clock, which is what a modern Linux build runs, and
                // an initial sequence number with no common step: RFC 6528's
                // hashed generator.
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

    /// A host offers whichever of the two answers the port scan already drew
    /// from it, and the *lowest* port of each kind, so two runs against one
    /// machine follow the same ports and their readings can be compared.
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

    /// A host that answered no TCP probe offers nothing, whatever else is known
    /// about it. There is no port to ask again, and probing one nothing
    /// established anything about would be a port scan wearing another name,
    /// that host belongs to the echo prober.
    #[test]
    fn a_host_with_no_tcp_answer_is_not_a_target() {
        use crate::model::port::Port;

        let mut nothing = Host::new(TARGET);
        assert!(SeriesTarget::for_host(ScopedIp::unscoped(TARGET), &nothing).is_none());

        // A filtered port is silence with a name on it, not an answer: nothing
        // came back, so there is no reply to ask for a second one of.
        nothing.add_port(Port::new(80, Protocol::Tcp, PortState::Filtered));
        assert!(SeriesTarget::for_host(ScopedIp::unscoped(TARGET), &nothing).is_none());

        // Nor does a UDP finding help: this scanner sends TCP.
        let mut udp = Host::new(TARGET);
        udp.add_port(Port::new(53, Protocol::Udp, PortState::Open));
        assert!(SeriesTarget::for_host(ScopedIp::unscoped(TARGET), &udp).is_none());
    }

    /// The whole path this scanner exists for, end to end: probes go out, the
    /// replies are collected into series, the series are classified, and the
    /// shipped corpus names the host from them.
    #[tokio::test(flavor = "current_thread")]
    async fn a_followed_host_is_named_from_what_its_replies_added_up_to() {
        let (session, ctx) = ScanSession::new();
        let mut scanner = scanner(&ctx, both_ports(), 4, true);

        scanner.probe().await.expect("the phase runs");

        let host = session.hosts().get(TARGET).expect("the host is recorded");
        let found = host.os().expect("a Linux-shaped series names Linux");
        assert_eq!(found.family(), Some("Linux"));
    }

    /// The reading a rule is offered says what the *series* found, not only what
    /// one packet held, which is the entire difference between this scanner and
    /// the passive path, and has to survive into what a report shows a person.
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

    /// A stack's reset path and its handshake path are different code that
    /// disagrees about the same field: this host writes identifier zero on the
    /// one and runs a counter on the other. The two series are kept apart, so
    /// each is read under its own policy rather than the pair being averaged
    /// into a reading neither supports.
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

    /// A host offering only a handshake is read from the one series it gave,
    /// rather than being declined for want of the other.
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

    /// Every sample has to be a genuine new connection attempt, or the sequence
    /// question measures nothing: two SYNs to one host and port from one source
    /// port are the same 4-tuple, and the second describes the `SYN-RECEIVED`
    /// state the first created rather than the stack holding it.
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

    /// Every sweep of a run takes a source port no other sweep of it took,
    /// wherever in the range the run starts: drawn per sweep instead, two of
    /// a dozen samples share a 4-tuple about once in two hundred and fifty runs.
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

    /// A reply is timed by the capture that took it, not by when this scanner
    /// got round to filing it.
    ///
    /// Replies come off the capture's queue in bursts, so the moment one is
    /// filed says how the queue was drained rather than when the reply arrived,
    /// and every interval the classifiers read is a difference of two stamps.
    /// Here a counter the host's other traffic advances by fifty a tenth of a
    /// second apart, three refusals filed in one burst: stamped as filed, it
    /// jumps fifty at a time in no time at all, which no counter does.
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

    /// A host the sender cannot reach is reported unreached, and only a
    /// refusal of this host's own is the pass failing.
    ///
    /// A dead neighbour's every probe is refused with the same answer, and
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

    /// Somebody else's segment carries a nonce this scan never sent. It must
    /// resolve nothing, not name the host, not record it at all, because the
    /// filter this transport uses admits far more than this scan's own replies.
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

        // A perfectly Linux-shaped handshake answer, acknowledging a sequence
        // number nothing here ever sent.
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

    /// A batch through a frame sender waits for every new neighbour in it
    /// before its first sample, all of them asked for at once: the ones that
    /// never answer are reported unreached with nothing sent them, and a live
    /// one among them has every sample leave.
    ///
    /// A frame sender resolves a neighbour nobody asked for ahead inside the
    /// send, and a sweep held there for the resolution's budget overruns the
    /// spacing the samples are read across, for every host in the batch.
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
    /// Through the kernel, which asks for a neighbour only once a probe is
    /// written to it, the first sample to a host whose neighbour it does not
    /// hold is the one write that asks, and every sample behind it waits on
    /// the verdict: a neighbour that never answers is sent nothing more and
    /// reported unreached, while a live one, and one the kernel already held,
    /// has every sample leave.
    ///
    /// Written freely, every sample to a dead neighbour queues in the kernel,
    /// charged to the socket, and is thrown away, and the host reads as one
    /// that stayed silent rather than one nothing reached.
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

    /// A neighbour the kernel takes longer to resolve than a sweep's tick,
    /// as one on a real link does, costs the sample right behind the write
    /// that asked for it, and a sweep after the last makes that sample up:
    /// both ports end with every sample the run takes.
    ///
    /// Left unmade, the port whose first sample was held has one fewer in its
    /// series than it was sent for, on every host the kernel had to ask for.
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
