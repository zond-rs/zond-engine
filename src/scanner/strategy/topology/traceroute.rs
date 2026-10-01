// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Measuring the path to a host
//!
//! Which routers sit between this machine and a target, and how far away each
//! one is.
//!
//! A router discarding a packet whose hop limit it decremented to zero must
//! report that to the sender (RFC 792, RFC 4443 §3.3). A probe built to run out
//! of hops at a chosen distance therefore makes the router at that distance
//! announce itself from its own address. Silence at one distance says nothing
//! about the next, so a [`Hop`] with no address is recorded.
//!
//! A trace to a host with an open TCP port is made of SYNs to that port; to any
//! other host, of ICMP echoes. The probe that reached a host is the one its
//! network permits, and a SYN to :443 crosses filters that discard pings and
//! unsolicited UDP.
//!
//! ## Walking backwards
//!
//! A trace starts at the target and walks *towards* this machine, so the first
//! hop recognised from another trace lets the rest be skipped; on a scan of many
//! hosts behind one gateway that is nearly all of the work. Starting at the
//! target needs its distance, so only hosts that answered are traced. The
//! distance is the gap between the reply's hop counter and the value it
//! plausibly started at; see `distance_from`.
//!
//! ## What the cache assumes
//!
//! [`PathCache`] holds, for each router seen at each distance, the path from
//! here to it. When a trace meets a router already recorded at the same
//! distance, the hops before it are copied from the earlier trace. This assumes
//! two paths through one router at one distance are identical up to it. Routing
//! does not promise that (a load balancer can split and rejoin flows), so every
//! spliced hop is marked [`Hop::inferred`].

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet_packet::tcp::TcpPacket;

use crate::counted;
use crate::model::host::path::Hop;
use crate::model::port::{PortState, Protocol};
use crate::protocols::{icmp, tcp};
use crate::report::ScannerKind;
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::raw::neighbors::{
    Admission, NEIGHBOR_RECHECK, NeighborGates, admit_waiting, resolve_ahead,
};
use crate::system::interface::SourceResolver;
use crate::transport::capture::CapturedSegment;
use crate::transport::frame::IpSegment;
use crate::transport::kernel_neighbors::NeighborState;
use crate::transport::probe::{Emission, ProbeKind, ProbeTransport, SendMode};
use crate::{info, warn};

use crate::scanner::strategy::icmp_error;

/// How far a trace will look before giving up on reaching the target.
///
/// Thirty, the traditional traceroute default; a bound on wasted probes.
pub const MAX_HOPS: u8 = 30;

/// How long one round of probes is given to be answered.
///
/// Generous compared with a port probe's budget: a Time Exceeded is generated
/// by the router's control plane at low priority and commonly rate-limited to a
/// handful per second.
const ROUND_TIMEOUT: Duration = Duration::from_millis(1500);

/// How many probes are sent before a distance is called silent.
///
/// Three, the traditional traceroute default. Routers rate-limit the error this
/// depends on, so one miss is weak evidence of silence. And opening a `libpcap`
/// handle on every interface takes real time, so the first probe of a run can
/// leave before the capture is live.
const ATTEMPTS: u8 = 3;

/// How many probes are in the air at once, across all targets.
///
/// A ceiling on burst, not a rate. Routers rate-limit the errors this depends
/// on, and probes sent too fast push the answers to other probes out of the
/// same budget.
const MAX_IN_FLIGHT: usize = 16;

/// The paths already measured, shared by every trace in one scan.
///
/// See the module documentation for what a hit assumes and how a spliced hop is
/// marked. Cheap to clone: it is a handle to one shared map.
///
/// It holds routers as they answered, including excluded ones. Nothing leaves
/// it except into a traced host's record through [`ScanContext::write_host`],
/// which withholds an excluded router's address on spliced and measured paths
/// alike.
#[derive(Debug, Clone, Default)]
pub struct PathCache {
    /// A router, at a distance, and everything known to be in front of it.
    known: Arc<DashMap<Waypoint, Arc<[Hop]>>>,
}

/// A router recognised at a distance: the key a splice matches on.
///
/// A router met at a different distance is a different point in a path; see
/// `a_router_at_another_distance_is_not_the_same_point_in_a_path`.
type Waypoint = (u8, IpAddr);

impl PathCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// The path in front of `address` if some earlier trace found it at
    /// `distance`, already marked [`Hop::inferred`].
    fn prefix_of(&self, distance: u8, address: IpAddr) -> Option<Vec<Hop>> {
        let prefix = self.known.get(&(distance, address))?;
        Some(prefix.iter().map(|hop| hop.as_inferred()).collect())
    }

    /// Files a completed trace, so later ones can splice from it.
    ///
    /// Only hops that answered are keys, but silent hops are kept *inside* the
    /// stored prefixes, so a spliced path is not shorter than it was.
    fn remember(&self, hops: &[Hop]) {
        for (index, hop) in hops.iter().enumerate() {
            let Some(address) = hop.address() else {
                continue;
            };
            // Strictly nearer than this router, which is the key itself.
            let prefix: Arc<[Hop]> = hops[..index].into();
            self.known.insert((hop.distance(), address), prefix);
        }
    }
}

/// What a trace sends, chosen per host to match what already reached it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TraceProbe {
    /// A SYN to a port already known to be open.
    Syn { port: u16 },
    /// An ICMP echo request, for a host with no open TCP port to aim at.
    Echo,
}

impl TraceProbe {
    /// The transport a group of these needs.
    ///
    /// Both admit ICMP errors: a router is heard only through the error it
    /// sends.
    fn probe_kind(self, marker: u16) -> ProbeKind {
        match self {
            TraceProbe::Syn { .. } => ProbeKind::TcpProbe {
                reply_port: marker,
                icmp_errors: true,
            },
            TraceProbe::Echo => ProbeKind::IcmpEcho { identifier: marker },
        }
    }
}

/// One outstanding probe: which host, and how far it was built to travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Sent {
    target: IpAddr,
    distance: u8,
}

/// Measures the path to each of a set of hosts.
///
/// Built by [`trace`], which splits its hosts by what will reach them and runs
/// one of these per group.
struct Tracer {
    ctx: ScanContext,
    transport: ProbeTransport,
    probe: TraceProbe,
    cache: PathCache,
    /// The ICMP identifier, or the TCP source port, every probe in this run
    /// carries, and its replies come back to.
    marker: u16,
    /// Which of this host's addresses to send from, per target. A mutating
    /// cached lookup, so each strategy keeps its own.
    resolver: SourceResolver,
    /// How far this run has read the resolution of each target's neighbour,
    /// which every probe is admitted through. See
    /// [`admitted`](Self::admitted).
    neighbors: NeighborGates,
    /// When each outstanding probe left, so a reply can be timed against it.
    in_flight: HashMap<Sent, Instant>,
    sent: u64,
    /// Probes the transport refused. In an empty path these look the same as
    /// probes nobody answered, but only the latter are about the network.
    failed: u64,
    answered: u64,
}

impl Tracer {
    fn new(
        ctx: ScanContext,
        transport: ProbeTransport,
        probe: TraceProbe,
        marker: u16,
        cache: PathCache,
    ) -> Self {
        Self {
            ctx,
            transport,
            probe,
            cache,
            marker,
            resolver: SourceResolver::from_system(),
            neighbors: NeighborGates::default(),
            in_flight: HashMap::new(),
            sent: 0,
            failed: 0,
            answered: 0,
        }
    }

    /// Waits until a probe to `target` may be handed to the transport, and
    /// says whether one may be at all.
    ///
    /// See [`NeighborGates::admit`]: the first probe to an uncached neighbour is
    /// the write that asks for it, and the rest wait on the verdict. Waiting
    /// costs nothing measured, since a round trip is timed from its own send. A
    /// target whose neighbour is given up on is not traced, since every probe
    /// would be discarded and read as silence.
    async fn admitted(&mut self, target: IpAddr) -> bool {
        let watch = self.transport.neighbors();
        match admit_waiting(
            &mut self.neighbors,
            &self.ctx,
            watch,
            &mut self.resolver,
            target,
        )
        .await
        {
            Ok(()) => true,
            Err(why) => {
                if let Some(why) = why {
                    info!(verbosity = 2, "{target} not traced: unreachable ({why})");
                }
                false
            }
        }
    }

    /// Builds and sends one probe to `target`, built to expire `distance` hops
    /// away. Returns whether it reached the wire.
    fn send(&mut self, target: IpAddr, distance: u8, source: IpAddr) -> bool {
        let segment = match self.probe {
            TraceProbe::Syn { port } => {
                // The distance rides in the sequence number's low byte: an ICMP
                // error is only guaranteed to quote eight bytes past the IP
                // header, which for TCP is the two ports and the sequence.
                let sequence = (u32::from(self.marker) << 8) | u32::from(distance);
                match tcp::build_probe(
                    crate::model::technique::TcpScanTechnique::Syn,
                    source,
                    target,
                    self.marker,
                    port,
                    sequence,
                ) {
                    Ok(segment) => segment,
                    Err(error) => {
                        warn!(
                            verbosity = 2,
                            "could not build a trace probe for {target}: {error}"
                        );
                        return false;
                    }
                }
            }
            TraceProbe::Echo => {
                // The echo sequence field sits inside the eight quoted bytes.
                match icmp::build_echo_request_message(
                    source,
                    target,
                    icmp::ECHO_PROBE_CODE,
                    self.marker,
                    u16::from(distance),
                    &[],
                ) {
                    Ok(message) => message,
                    Err(error) => {
                        warn!(
                            verbosity = 2,
                            "could not build a trace probe for {target}: {error}"
                        );
                        return false;
                    }
                }
            }
        };

        match self
            .transport
            .tx
            .send(&segment, source, target, None, Emission::at_hop(distance))
        {
            Ok(()) => {
                self.in_flight
                    .insert(Sent { target, distance }, Instant::now());
                self.sent += 1;
                true
            }
            Err(error) => {
                // Per-probe, so verbosity 2; the end of the trace counts the
                // refusals and says so when no probe left at all.
                warn!(
                    verbosity = 2,
                    "trace probe to {target} was not sent: {error:#}"
                );
                self.failed += 1;
                false
            }
        }
    }

    /// Waits until a probe to `target` may leave under the gaps the scan keeps
    /// between probes, then [sends](Self::send) one built to expire `distance`
    /// hops away, and says whether it reached the wire.
    ///
    /// A trace probe counts as a probe at the target, spending both the
    /// per-host and the scan-wide gap on that address. The slot is taken just
    /// before the send and refunded if the transport refused it. Waiting costs
    /// nothing measured: a round trip is timed from the probe's own send, and
    /// each round's reply window opens once its probes are out.
    ///
    /// `false` where the probe did not leave, because the transport refused it
    /// or the scan stopped while it waited; the caller reads the stop from
    /// [`should_stop`](crate::scanner::handle::ScanHandle::should_stop).
    async fn send_paced(&mut self, target: IpAddr, distance: u8, source: IpAddr) -> bool {
        loop {
            match self.ctx.claim_probe(target) {
                Ok(claim) => {
                    let left = self.send(target, distance, source);
                    if !left {
                        self.ctx.refund_probe(claim);
                    }
                    return left;
                }
                Err(ready) => {
                    tokio::select! {
                        () = self.ctx.handle.stopping() => return false,
                        () = tokio::time::sleep_until(ready.into()) => {}
                    }
                }
            }
        }
    }

    /// Reads replies until `deadline`, handing each to `on_reply`.
    ///
    /// Stops early once nothing is outstanding, so a fully answered round costs
    /// its round trip, not its timeout.
    async fn collect(&mut self, deadline: Instant, mut on_reply: impl FnMut(&mut Self, Reply)) {
        while !self.in_flight.is_empty() {
            let now = Instant::now();
            if now >= deadline || self.ctx.handle.should_stop() {
                return;
            }

            let next = tokio::time::timeout(deadline - now, self.transport.rx.recv()).await;
            let Ok(Some(segment)) = next else {
                return;
            };

            if let Some(reply) = self.classify(&segment) {
                self.answered += 1;
                on_reply(self, reply);
            }
        }
    }

    /// What a captured segment says, if it says anything about this run.
    fn classify(&mut self, segment: &CapturedSegment) -> Option<Reply> {
        // A router reporting a probe it discarded; only the quotation ties it
        // to one of ours.
        if let Some(expired) = icmp_error::parse_expired(segment) {
            let sent = self.attribute(&expired.quoted)?;
            let rtt = self.in_flight.remove(&sent).map(|at| at.elapsed());
            return Some(Reply::Expired {
                sent,
                router: segment.source,
                rtt,
            });
        }

        // The target itself; its hop counter says how far away it is.
        let arrived = segment.observation.as_ref()?.remaining_hops();

        // **Attributed to the probe it answers, not merely to its sender.**
        // Stragglers from an earlier distance are still in the air; matched by
        // source alone, one would clear the entry for a distance it says
        // nothing about, which would then be recorded as silent.
        let answered = self.answered_distance(segment)?;
        self.in_flight.remove(&Sent {
            target: segment.source,
            distance: answered,
        });

        Some(Reply::Arrived {
            target: segment.source,
            probed: answered,
            implied: distance_from(arrived),
        })
    }

    /// Which of this run's probes a direct answer is answering.
    ///
    /// The counterpart of [`attribute`] for replies from the target itself.
    ///
    /// A SYN draws a segment acknowledging its sequence, so the marker comes
    /// back one higher. An echo reply carries its identifier and sequence back
    /// unchanged (RFC 792 §Echo, RFC 4443 §4.2).
    ///
    /// **The answer's kind is checked before its fields.** The capture sees both
    /// directions, so an echo trace's own requests come back carrying the marker
    /// and distance where a reply does; only the type byte tells them apart.
    fn answered_distance(&self, segment: &CapturedSegment) -> Option<u8> {
        match self.probe {
            TraceProbe::Syn { .. } => {
                if segment.protocol != IpNextHeaderProtocols::Tcp.0 {
                    return None;
                }
                let reply = TcpPacket::new(&segment.bytes)?;
                if reply.get_destination() != self.marker {
                    return None;
                }
                let echoed = reply.get_acknowledgement().checked_sub(1)?;
                if (echoed >> 8) != u32::from(self.marker) {
                    return None;
                }
                Some((echoed & 0xff) as u8)
            }
            TraceProbe::Echo => {
                // The ICMP numbering family comes from the IP protocol.
                let over_ipv6 = match IpNextHeaderProtocol(segment.protocol) {
                    IpNextHeaderProtocols::Icmp => false,
                    IpNextHeaderProtocols::Icmpv6 => true,
                    _ => return None,
                };
                match icmp::classify_echo_reply(&segment.bytes, self.marker, over_ipv6) {
                    icmp::EchoReply::Ours { sequence } => u8::try_from(sequence).ok(),
                    _ => None,
                }
            }
        }
    }

    /// Which of this run's probes an error is quoting.
    fn attribute(&self, quoted: &IpSegment<'_>) -> Option<Sent> {
        attribute(self.probe, self.marker, quoted)
    }
}

/// Which probe of a run using `probe` and `marker` an error is quoting, or
/// `None` if it is quoting somebody else's packet.
///
/// The quoted destination names the host and the marker inside the transport
/// header names the distance; see [`Tracer::send`] for where each is written.
///
/// Both are checked, and the marker twice for TCP. The capture admits *every*
/// ICMP error on every captured interface, and a foreign error attributed to a
/// probe puts a router into a path it is not on, which nothing downstream can
/// detect.
///
/// Only the first eight bytes past the quoted IP header are read, since only
/// those are guaranteed (RFC 792): for TCP up to the end of the sequence
/// number, for ICMP the end of the echo sequence.
fn attribute(probe: TraceProbe, marker: u16, quoted: &IpSegment<'_>) -> Option<Sent> {
    let head: [u8; 8] = quoted.payload.get(..8)?.try_into().ok()?;

    let distance = match (probe, IpNextHeaderProtocol(quoted.protocol)) {
        (TraceProbe::Syn { .. }, IpNextHeaderProtocols::Tcp) => {
            // The source port, then the sequence number's high bytes: routers
            // quoting mangled probes are common enough that one field can match
            // by chance.
            if u16::from_be_bytes([head[0], head[1]]) != marker {
                return None;
            }
            let sequence = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
            if (sequence >> 8) != u32::from(marker) {
                return None;
            }
            (sequence & 0xff) as u8
        }
        (TraceProbe::Echo, IpNextHeaderProtocols::Icmp | IpNextHeaderProtocols::Icmpv6) => {
            if u16::from_be_bytes([head[4], head[5]]) != marker {
                return None;
            }
            u8::try_from(u16::from_be_bytes([head[6], head[7]])).ok()?
        }
        _ => return None,
    };

    Some(Sent {
        target: quoted.destination,
        distance,
    })
}

/// What a probe at one distance found there.
///
/// Silence and the target answering are separate outcomes, or a trace could
/// stop short of its target.
enum Landing {
    /// A router discarded the probe and named itself.
    Router(IpAddr, Option<Duration>),
    /// The target answered, so the probe was never discarded: the target is at
    /// or nearer than this distance.
    Target,
    /// Nothing came back.
    Silent,
}

/// What one reply established.
enum Reply {
    /// A router discarded a probe and said so.
    Expired {
        sent: Sent,
        router: IpAddr,
        rtt: Option<Duration>,
    },
    /// The target answered, so the probe was not discarded at all.
    Arrived {
        target: IpAddr,
        /// Which of this run's probes it answers, by the distance that probe
        /// was built to expire at.
        ///
        /// Without it a straggler from an earlier distance reads as "the target
        /// is reachable *here*", and on a quiet path walks the far end one hop
        /// nearer per round until the whole path is discarded.
        probed: u8,
        /// How far away the reply's own hop counter says the target is, which
        /// is a statement about the path *back*. See [`distance_from`].
        implied: u8,
    },
}

/// How many routers a reply crossed, from the hop counter it arrived with.
///
/// The starting value is not in the packet, so it is taken as the smallest of
/// the usual ones (32, 64, 128, 255) that could have produced what arrived.
///
/// A bound, wrong in one direction: a host more than 64 hops away is read
/// against 128 and reported nearer than it is. Such paths do not occur outside
/// a laboratory.
fn distance_from(arrived: u8) -> u8 {
    const COMMON: [u8; 4] = [32, 64, 128, 255];
    let started = COMMON
        .into_iter()
        .find(|start| *start >= arrived)
        .unwrap_or(u8::MAX);
    started.saturating_sub(arrived)
}

/// What will reach `target`, given what the scan already found on it.
///
/// An open TCP port if there is one, since the path is known to permit it. The
/// lowest-numbered one, so two runs against an unchanged host trace alike.
fn probe_for(ctx: &ScanContext, target: &IpAddr) -> TraceProbe {
    let port = ctx.read_host(target, |host| {
        host.ports()
            .filter(|port| port.protocol() == Protocol::Tcp && port.state() == PortState::Open)
            .map(crate::model::port::Port::number)
            .min()
    });

    match port.flatten() {
        Some(port) => TraceProbe::Syn { port },
        None => TraceProbe::Echo,
    }
}

/// Measures the path to every host in `targets` that answered something.
///
/// Hosts are grouped by what will reach them and each group is traced with its
/// own transport; the [`PathCache`] is shared, so TCP and ICMP traces through
/// one gateway measure it once.
///
/// Records through [`ScanContext::update_host`], so an excluded address gets no
/// path, and an excluded router on a permitted host's path keeps its distance
/// but loses its address: see [`Hop::withheld`].
pub async fn trace(ctx: &ScanContext, targets: Vec<IpAddr>) {
    if targets.is_empty() {
        return;
    }

    let cache = PathCache::new();
    let mut groups: HashMap<TraceProbe, Vec<IpAddr>> = HashMap::new();
    for target in targets {
        groups
            .entry(probe_for(ctx, &target))
            .or_default()
            .push(target);
    }

    for (probe, group) in groups {
        if ctx.handle.should_stop() {
            return;
        }

        let marker: u16 = rand::random_range(33_000..60_000);
        let transport = match ProbeTransport::open_capturing(
            probe.probe_kind(marker),
            SendMode::Auto,
            &ctx.capture_links(),
        ) {
            Ok(transport) => transport,
            Err(error) => {
                ctx.record_failure(
                    ScannerKind::Routed,
                    format!("no transport to trace with: {error}"),
                );
                return;
            }
        };

        let mut tracer = Tracer::new(ctx.clone(), transport, probe, marker, cache.clone());
        tracer.run(group).await;
    }
}

impl Tracer {
    /// Traces every host in `group`.
    ///
    /// Every host's neighbour is resolved at once before the first probe, so
    /// the walks do not wait out one resolution per host in turn. A host whose
    /// neighbour never answered is not traced. Through the kernel, which asks
    /// only once a probe is written, this happens once the distances are known;
    /// see [`ask_together`](Self::ask_together).
    async fn run(&mut self, group: Vec<IpAddr>) {
        let (gates, unreached) = resolve_ahead(
            &self.ctx,
            self.transport.neighbors(),
            &mut self.resolver,
            group.iter().copied(),
        )
        .await;
        self.neighbors = gates;
        for (target, why) in &unreached {
            info!(verbosity = 2, "{target} not traced: unreachable ({why})");
        }
        let group: Vec<IpAddr> = group
            .into_iter()
            .filter(|target| !unreached.contains_key(target))
            .collect();
        let mut distances = self.measure_distances(&group).await;
        let hosts: Vec<IpAddr> = distances.iter().map(|(target, _)| *target).collect();
        let unreached = self.ask_together(&hosts).await;
        for (target, why) in &unreached {
            info!(verbosity = 2, "{target} not traced: unreachable ({why})");
        }
        distances.retain(|(target, _)| !unreached.contains_key(target));

        for (target, distance) in distances {
            if self.ctx.handle.should_stop() {
                break;
            }
            // A host that has spent its time budget is not traced.
            if self.ctx.host_expired(target) {
                continue;
            }
            self.walk(target, distance).await;
        }

        // Probes that never left and probes nobody answered are reported
        // apart, so a broken send or capture path is not mistaken for a quiet
        // network.
        if self.sent == 0 && self.failed > 0 {
            warn!(
                "traceroute could not put any of its {} probes on the wire; no path was measured",
                self.failed
            );
        } else if self.sent > 0 && self.answered == 0 {
            warn!(
                "traceroute heard nothing back from {} probes; no path was measured",
                self.sent
            );
        } else {
            info!(
                verbosity = 3,
                "traceroute: {} probes sent ({} refused), {} answered",
                self.sent,
                self.failed,
                self.answered
            );
        }
    }

    /// Writes one probe to every host in `targets` whose neighbour the kernel
    /// is not known to hold, together, and waits until each neighbour has
    /// answered or been given up on. Returns the hosts given up on, each with
    /// why.
    ///
    /// The kernel asks for a neighbour only once a probe is written, and walks
    /// go one host at a time, so a wave of dead neighbours would otherwise cost
    /// a resolution's wait each, in turn. The probe written is at full distance
    /// and its answer is not read.
    ///
    /// A frame sender's neighbours were resolved before the distances were
    /// measured, so nothing is written for them.
    async fn ask_together(&mut self, targets: &[IpAddr]) -> BTreeMap<IpAddr, String> {
        let mut unreached = BTreeMap::new();
        let now = Instant::now();
        let mut sources = HashMap::new();
        for &target in targets {
            let Some(source) = self.resolver.resolve(target) else {
                continue;
            };
            let watch = self.transport.neighbors();
            if self.neighbors.admit(watch, &mut self.resolver, target, now) == Admission::Send {
                sources.insert(target, source);
            }
        }
        // A gate left asking has an uncached neighbour; the probe written now
        // is the write that asks. An open one is written nothing.
        let mut waiting: Vec<IpAddr> = self
            .neighbors
            .waiting()
            .into_iter()
            .filter(|host| sources.contains_key(host))
            .collect();
        for &target in &waiting {
            self.send_paced(target, MAX_HOPS, sources[&target]).await;
        }
        self.in_flight.clear();

        while !waiting.is_empty() && !self.ctx.handle.should_stop() {
            tokio::time::sleep(NEIGHBOR_RECHECK).await;
            let now = Instant::now();
            let watch = self.transport.neighbors();
            let (gates, resolver) = (&mut self.neighbors, &mut self.resolver);
            let mut asking_again = Vec::new();
            waiting.retain(|&target| match gates.admit(watch, resolver, target, now) {
                // A neighbour the kernel gave up on once: write again so it
                // asks again, and keep waiting.
                Admission::Send if gates.is_waiting(target) => {
                    asking_again.push(target);
                    true
                }
                Admission::Send => false,
                Admission::Hold(_) => true,
                Admission::Unreachable => {
                    unreached.insert(target, gates.unreached(target, NeighborState::Failed));
                    false
                }
            });
            for target in asking_again {
                self.send_paced(target, MAX_HOPS, sources[&target]).await;
            }
            self.in_flight.clear();
        }
        unreached
    }

    /// How far away each host is.
    ///
    /// Read from the hop counter the scan recorded for the host's latest reply
    /// wherever possible, which costs no probe and does not depend on a second
    /// exchange succeeding.
    ///
    /// A host with no recorded counter gets a probe. A host that answers
    /// neither is skipped, since the walk needs a far end to start from.
    async fn measure_distances(&mut self, group: &[IpAddr]) -> Vec<(IpAddr, u8)> {
        let mut found: Vec<(IpAddr, u8)> = Vec::new();
        let mut unknown: Vec<IpAddr> = Vec::new();

        for target in group {
            match self
                .ctx
                .read_host(target, |host| host.telemetry().hop_counter())
                .flatten()
            {
                Some(arrived) => {
                    let distance = distance_from(arrived);
                    info!(
                        verbosity = 2,
                        "{target} is about {} away, from the hop counter of {arrived} \
                         its reply arrived with",
                        counted(u128::from(distance), "hop", "hops")
                    );
                    found.push((*target, distance));
                }
                None => unknown.push(*target),
            }
        }

        found.extend(self.probe_for_distances(&unknown).await);
        found
    }

    /// The fallback: one full-distance probe apiece, for hosts whose replies
    /// this scan never read a hop counter from.
    ///
    /// **An answer is kept only from a host the round asked, and only once.**
    /// Whatever this returns is walked, and the marker rides in every probe for
    /// anyone who sees one to copy under an address of their choosing. A host
    /// answers each probe the round sends it, and a second answer kept would
    /// be a second walk of the same path.
    ///
    /// Since a trace only probes addresses a caller of [`trace`] named (from
    /// the store, which the exclusions keep clean), it does not consult
    /// [`ScanContext::may_probe`].
    async fn probe_for_distances(&mut self, group: &[IpAddr]) -> Vec<(IpAddr, u8)> {
        let mut found: Vec<(IpAddr, u8)> = Vec::new();

        for window in group.chunks(MAX_IN_FLIGHT) {
            if self.ctx.handle.should_stop() {
                break;
            }
            let mut asked: Vec<(IpAddr, IpAddr)> = Vec::new();
            for target in window {
                let Some(source) = self.resolver.resolve(*target) else {
                    warn!(
                        verbosity = 2,
                        "no source address to trace {target} from; skipping it"
                    );
                    continue;
                };
                asked.push((*target, source));
            }
            // One attempt per host per round, so the first round starts every
            // new neighbour's resolution together and they cost one wait.
            for _ in 0..ATTEMPTS {
                let mut admitted = Vec::with_capacity(asked.len());
                for (target, source) in asked {
                    if self.admitted(target).await {
                        self.send_paced(target, MAX_HOPS, source).await;
                        admitted.push((target, source));
                    }
                }
                asked = admitted;
            }

            let deadline = Instant::now() + ROUND_TIMEOUT;
            let mut reached: Vec<(IpAddr, u8)> = Vec::new();
            self.collect(deadline, |_, reply| match reply {
                Reply::Arrived {
                    target,
                    probed: MAX_HOPS,
                    implied,
                } if window.contains(&target)
                    && !reached.iter().any(|(host, _)| *host == target) =>
                {
                    reached.push((target, implied));
                }
                _ => {}
            })
            .await;

            found.extend(reached);
            self.in_flight.clear();
        }

        found
    }

    /// Asks what is at one distance from here, and reports what answered.
    ///
    /// [`walk`](Self::walk) chooses the distances; see [`Landing`] for the
    /// outcomes. `None` where nothing could be asked (the target's neighbour
    /// given up on, or the scan stopped).
    async fn probe_distance(&mut self, target: IpAddr, at: u8, source: IpAddr) -> Option<Landing> {
        // All attempts in one burst: one round trip, and the first answer
        // settles the distance.
        for _ in 0..ATTEMPTS {
            if !self.admitted(target).await {
                self.in_flight.clear();
                return None;
            }
            self.send_paced(target, at, source).await;
        }
        let deadline = Instant::now() + ROUND_TIMEOUT;

        let mut landing = Landing::Silent;
        let attempted = self.sent;
        self.collect(deadline, |_, reply| match reply {
            Reply::Expired {
                sent,
                router: from,
                rtt,
            } if sent.target == target && sent.distance == at => {
                landing = Landing::Router(from, rtt);
            }
            // The target answering *this* probe puts it at or nearer than this
            // distance. An answer to an earlier round says nothing here.
            Reply::Arrived {
                target: who,
                probed,
                ..
            } if who == target && probed == at => {
                landing = Landing::Target;
            }
            _ => {}
        })
        .await;
        self.in_flight.clear();

        // One line per distance, so a wrong path can be debugged afterwards.
        info!(
            verbosity = 2,
            "trace {target} at hop {at}: {} ({} sent)",
            match landing {
                Landing::Router(address, _) => format!("router {address}"),
                Landing::Target => "the target itself".to_string(),
                Landing::Silent => "nothing answered".to_string(),
            },
            counted((self.sent - attempted) as u128, "probe", "probes")
        );

        Some(landing)
    }

    /// Measures the path to `target`, starting from `estimate` and correcting it.
    ///
    /// `estimate` comes from the reply's hop counter, which measures the path
    /// *back*; routing is asymmetric, so it routinely differs by more than a hop
    /// (an anycast address can answer from two hops nearer than it is reached).
    /// Trusted outright, it would drop every router beyond it.
    ///
    /// So the walk goes outward until the target answers, then inward. Outward
    /// corrects a shorter return path; inward, the target answering nearer moves
    /// the far end in.
    async fn walk(&mut self, target: IpAddr, estimate: u8) {
        let Some(source) = self.resolver.resolve(target) else {
            return;
        };

        let mut measured: Vec<Hop> = Vec::new();
        let mut spliced: Option<Vec<Hop>> = None;

        // ─── Outward, until the target answers ───────────────────────────────
        let mut reached = estimate.max(1);
        while reached <= MAX_HOPS {
            if self.ctx.handle.should_stop() {
                return;
            }
            let Some(landing) = self.probe_distance(target, reached, source).await else {
                return;
            };
            match landing {
                Landing::Target => break,
                // The target is further out; the router is a genuine hop.
                Landing::Router(address, rtt) => {
                    measured.push(Hop::answered(reached, address, rtt));
                }
                Landing::Silent => measured.push(Hop::silent(reached)),
            }
            reached += 1;
        }

        // Nothing answered out to the ceiling: the far end is left unstated
        // and only the routers that answered are kept.
        let target_hop = (reached <= MAX_HOPS).then_some(reached);

        // ─── Inward, to the first router ─────────────────────────────────────
        let known: Vec<u8> = measured.iter().map(Hop::distance).collect();
        let mut at = target_hop.unwrap_or(reached).saturating_sub(1);
        let mut far_end = target_hop;

        while at >= 1 {
            if self.ctx.handle.should_stop() {
                break;
            }
            // Already settled on the way out.
            if known.contains(&at) {
                at -= 1;
                continue;
            }

            let Some(landing) = self.probe_distance(target, at, source).await else {
                return;
            };
            match landing {
                // The outward walk overshot: the far end moves in.
                Landing::Target => far_end = Some(at),
                Landing::Router(address, rtt) => {
                    measured.push(Hop::answered(at, address, rtt));
                    if let Some(prefix) = self.cache.prefix_of(at, address) {
                        spliced = Some(prefix);
                        break;
                    }
                }
                Landing::Silent => measured.push(Hop::silent(at)),
            }

            at -= 1;
        }

        let mut hops: Vec<Hop> = Vec::new();
        if let Some(distance) = far_end {
            // The target itself, as the far end.
            hops.push(Hop::answered(distance, target, None));
        }
        if let Some(prefix) = spliced {
            hops.extend(prefix);
        }
        // Drop outward hops recorded beyond the settled far end.
        hops.extend(
            measured
                .into_iter()
                .filter(|hop| far_end.is_none_or(|distance| hop.distance() < distance)),
        );
        hops.sort_by_key(Hop::distance);

        if hops.is_empty() {
            return;
        }

        self.cache.remember(&hops);
        self.ctx.update_host(target, |host| {
            for hop in &hops {
                host.record_hop(*hop);
            }
        });
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use tokio::sync::mpsc;

    use crate::model::capture::{IpObservation, Ipv4Observation};
    use crate::model::exclusion::Exclusions;
    use crate::protocols::craft;
    use crate::scanner::session::ScanSession;
    use crate::transport::probe::{MockSender, ProbeSender, SendError};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    // ─── A network that answers ──────────────────────────────────────────────

    /// A fake internet: routers that expire probes and a target that answers.
    ///
    /// It honours the [`Emission`] hop limit: a probe with a hop limit below
    /// `distance` comes back as a Time Exceeded from the router at that
    /// distance; one that reaches the target comes back as its answer.
    struct Network {
        /// How many routers away the target is, going out.
        distance: u8,
        /// The hop counter the target's own answers arrive with.
        ///
        /// Independent of [`distance`](Self::distance), since asymmetric
        /// routing makes the return path differ, and the walk must correct for
        /// it.
        reply_ttl: u8,
        /// Distances whose router refuses to identify itself.
        silent: Vec<u8>,
        replies: mpsc::Sender<CapturedSegment>,
    }

    /// The SYN+ACK a listening port answers `probe` with.
    ///
    /// Ports swapped and the acknowledgement one past the sequence, which the
    /// trace reads to tell its probes apart.
    fn syn_ack_to(probe: &[u8]) -> Vec<u8> {
        use pnet_packet::tcp::{MutableTcpPacket, TcpFlags};

        let sent = TcpPacket::new(probe).expect("the probe is a TCP segment");

        let mut bytes = vec![0u8; 20];
        let mut reply = MutableTcpPacket::new(&mut bytes).expect("20 bytes is a header");
        reply.set_source(sent.get_destination());
        reply.set_destination(sent.get_source());
        reply.set_acknowledgement(sent.get_sequence().wrapping_add(1));
        reply.set_flags(TcpFlags::SYN | TcpFlags::ACK);
        reply.set_data_offset(5);
        bytes
    }

    /// The address of the router `distance` hops out.
    fn router_at(distance: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, distance))
    }

    impl Network {
        /// A reply carrying an IP observation, whose hop counter the loop needs.
        fn observed(
            source: IpAddr,
            protocol: pnet_packet::ip::IpNextHeaderProtocol,
            bytes: Vec<u8>,
            ttl: u8,
        ) -> CapturedSegment {
            CapturedSegment {
                received_at: Instant::now(),
                source,
                destination: None,
                protocol: protocol.0,
                bytes,
                observation: Some(IpObservation::V4(Ipv4Observation {
                    ttl,
                    identification: 0,
                    dont_fragment: false,
                    more_fragments: false,
                    dscp: 0,
                    ecn: 0,
                })),
                source_mac: None,
            }
        }
    }

    impl ProbeSender for Network {
        fn send(
            &self,
            segment: &[u8],
            src: IpAddr,
            dst: IpAddr,
            _zone: Option<u32>,
            emission: Emission,
        ) -> Result<(), SendError> {
            if emission.hop_limit >= self.distance {
                // The target answers with a real SYN+ACK, whose acknowledgement
                // names the probe being answered.
                let reply = Network::observed(
                    dst,
                    IpNextHeaderProtocols::Tcp,
                    syn_ack_to(segment),
                    self.reply_ttl,
                );
                let _ = self.replies.try_send(reply);
                return Ok(());
            }

            if self.silent.contains(&emission.hop_limit) {
                return Ok(());
            }

            // A router discarding the probe, quoting it per RFC 792.
            let quoted = {
                let (IpAddr::V4(s), IpAddr::V4(d)) = (src, dst) else {
                    unreachable!("the fixture is IPv4")
                };
                let header = crate::protocols::ip::build_ipv4_header(
                    s,
                    d,
                    segment.len() as u16,
                    IpNextHeaderProtocols::Tcp.0,
                    emission.hop_limit,
                )
                .expect("a header builds");
                header
                    .into_iter()
                    .chain(segment.iter().copied())
                    .collect::<Vec<u8>>()
            };

            let mut bytes = vec![0u8; 8];
            bytes[0] = pnet_packet::icmp::IcmpTypes::TimeExceeded.0;
            bytes.extend_from_slice(&quoted);

            let _ = self.replies.try_send(Network::observed(
                router_at(emission.hop_limit),
                IpNextHeaderProtocols::Icmp,
                bytes,
                255,
            ));
            Ok(())
        }
    }

    /// A tracer wired to `network`, with the store it writes into.
    fn tracer_against(network: Network) -> (ScanContext, Tracer) {
        tracer_under(network, Exclusions::none())
    }

    /// [`tracer_against`], for a scan forbidden to report `exclusions`.
    fn tracer_under(network: Network, exclusions: Exclusions) -> (ScanContext, Tracer) {
        let (_session, ctx) = ScanSession::builder().excluding(exclusions).build();
        let (tx, rx) = mpsc::channel(1024);
        let network = Network {
            replies: tx,
            ..network
        };
        let transport = ProbeTransport::from_parts(Box::new(network), rx);
        let tracer = Tracer::new(
            ctx.clone(),
            transport,
            TraceProbe::Syn { port: 443 },
            41_234,
            PathCache::new(),
        );
        (ctx, tracer)
    }

    /// The whole loop: probes, replies and attribution fit together.
    ///
    /// The silent router at distance two is where a straggler from distance one
    /// lands; matched on sender alone it would clear distance two's entry.
    #[tokio::test(flavor = "current_thread")]
    async fn a_trace_records_every_router_between_here_and_the_target() {
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let (ctx, mut tracer) = tracer_against(Network {
            distance: 4,
            reply_ttl: 60,
            silent: vec![2],
            replies: mpsc::channel(1024).0,
        });

        tracer.run(vec![target]).await;

        let path = ctx
            .read_host(target, |host| host.path().clone())
            .expect("the target was recorded");

        let seen: Vec<(u8, Option<IpAddr>)> = path
            .hops()
            .iter()
            .map(|hop| (hop.distance(), hop.address()))
            .collect();

        assert_eq!(
            seen,
            vec![
                (1, Some(router_at(1))),
                (2, None),
                (3, Some(router_at(3))),
                (4, Some(target)),
            ],
            "every distance is accounted for, including the router that stayed quiet"
        );
    }

    /// A recording sender that answers as the target at every distance, so a
    /// trace through it sends its probes and finishes at once, and logs when
    /// each probe left.
    struct TimedNetwork {
        reply_ttl: u8,
        replies: mpsc::Sender<CapturedSegment>,
        sent_at: std::sync::Arc<std::sync::Mutex<Vec<Instant>>>,
    }

    impl ProbeSender for TimedNetwork {
        fn send(
            &self,
            segment: &[u8],
            _src: IpAddr,
            dst: IpAddr,
            _zone: Option<u32>,
            _emission: Emission,
        ) -> Result<(), SendError> {
            self.sent_at.lock().unwrap().push(Instant::now());
            let reply = Network::observed(
                dst,
                IpNextHeaderProtocols::Tcp,
                syn_ack_to(segment),
                self.reply_ttl,
            );
            let _ = self.replies.try_send(reply);
            Ok(())
        }
    }

    /// Under a per-host gap, no two of a trace's probes leave nearer than the
    /// gap, and every one is still sent.
    #[tokio::test(flavor = "current_thread")]
    async fn a_gap_spaces_a_traces_probes() {
        let gap = Duration::from_millis(40);
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(gap))
            .build();
        let (tx, rx) = mpsc::channel(1024);
        let sent_at = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let network = TimedNetwork {
            reply_ttl: 60,
            replies: tx,
            sent_at: sent_at.clone(),
        };
        let transport = ProbeTransport::from_parts(Box::new(network), rx);
        let mut tracer = Tracer::new(
            ctx.clone(),
            transport,
            TraceProbe::Syn { port: 443 },
            41_234,
            PathCache::new(),
        );

        tracer.run(vec![target]).await;

        let sent = sent_at.lock().unwrap();
        assert!(sent.len() >= 3, "the trace sent its probes: {}", sent.len());
        for pair in sent.windows(2) {
            assert!(
                pair[1].duration_since(pair[0]) >= gap,
                "two probes left {:?} apart, under a {gap:?} gap",
                pair[1].duration_since(pair[0])
            );
        }
    }

    /// A router the scan may not report is withheld on every path through it,
    /// the one measured and the one spliced from it alike.
    ///
    /// The cache holds routers as they answered, and the second trace splices
    /// from it, so withholding must happen at the store.
    #[tokio::test(flavor = "current_thread")]
    async fn an_excluded_router_is_withheld_whether_measured_or_spliced() {
        let first = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let second = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

        let mut forbidden = crate::model::ip::set::IpSet::new();
        forbidden.insert(router_at(2));
        let (ctx, mut tracer) = tracer_under(
            Network {
                distance: 4,
                reply_ttl: 60,
                silent: vec![],
                replies: mpsc::channel(1024).0,
            },
            Exclusions::new(forbidden),
        );

        tracer.run(vec![first, second]).await;

        for (target, spliced) in [(first, false), (second, true)] {
            let path = ctx
                .read_host(target, |host| host.path().clone())
                .expect("the target was recorded");
            assert!(
                path.hops()
                    .iter()
                    .all(|hop| hop.address() != Some(router_at(2))),
                "{target}: {path:?}"
            );

            let at_two = path.hops()[1];
            assert_eq!(at_two.distance(), 2, "{target}: {path:?}");
            assert!(at_two.is_withheld(), "{target}: {path:?}");
            assert_eq!(
                at_two.inferred(),
                spliced,
                "{target}: the splice happened, and stays marked: {path:?}"
            );
            assert_eq!(path.at(3), Some(router_at(3)), "{target}: {path:?}");
            assert_eq!(path.length(), Some(4));
        }
    }

    /// Traces `target` across `network`, seeding the hop counter the scan would
    /// have recorded from an earlier reply.
    async fn trace_across(network: Network, target: IpAddr) -> Vec<(u8, Option<IpAddr>)> {
        let seed = network.reply_ttl;
        let (ctx, mut tracer) = tracer_against(network);

        // As the port scan would leave it.
        ctx.update_host(target, |host| host.record_hop_counter(seed));

        tracer.run(vec![target]).await;

        ctx.read_host(target, |host| {
            host.path()
                .hops()
                .iter()
                .map(|hop| (hop.distance(), hop.address()))
                .collect()
        })
        .unwrap_or_default()
    }

    /// The estimate reads short, and the trace walks out past it.
    ///
    /// A reply's hop counter measures the path back; an anycast address answers
    /// from nearer than it can be reached.
    #[tokio::test(flavor = "current_thread")]
    async fn a_target_further_out_than_its_replies_suggest_is_still_reached() {
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

        let seen = trace_across(
            Network {
                distance: 7,
                // 64 - 59 = five hops back, against seven going out.
                reply_ttl: 59,
                silent: vec![2],
                replies: mpsc::channel(1024).0,
            },
            target,
        )
        .await;

        assert_eq!(
            seen.last(),
            Some(&(7, Some(target))),
            "the target sits where it actually is, not where its replies implied"
        );
        assert_eq!(seen.len(), 7, "every distance out to it is accounted for");
        assert_eq!(
            seen[4],
            (5, Some(router_at(5))),
            "the hops past the estimate"
        );
        assert_eq!(seen[5], (6, Some(router_at(6))));
    }

    /// The estimate reads long, and the far end moves back in.
    ///
    /// Otherwise the target would be recorded beyond its last router, with
    /// phantom distances in between.
    #[tokio::test(flavor = "current_thread")]
    async fn a_target_nearer_than_its_replies_suggest_is_not_reported_far_away() {
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

        let seen = trace_across(
            Network {
                distance: 5,
                // 64 - 56 = eight hops back, against five going out.
                reply_ttl: 56,
                silent: vec![],
                replies: mpsc::channel(1024).0,
            },
            target,
        )
        .await;

        assert_eq!(seen.last(), Some(&(5, Some(target))));
        assert_eq!(seen.len(), 5, "nothing is recorded past the target");
    }

    /// A path whose routers all stay quiet still reports its own length.
    ///
    /// Why the distance on an answer is checked. Where no router answers (large
    /// networks often rate-limit these errors to nothing), a straggler is the
    /// only reply a round sees; unchecked, the far end would walk one hop nearer
    /// per round and the whole path would be discarded.
    #[tokio::test(flavor = "current_thread")]
    async fn a_path_of_silent_routers_keeps_its_length() {
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

        let seen = trace_across(
            Network {
                distance: 6,
                reply_ttl: 58,
                // Not one router identifies itself.
                silent: (1..=6).collect(),
                replies: mpsc::channel(1024).0,
            },
            target,
        )
        .await;

        assert_eq!(
            seen.last(),
            Some(&(6, Some(target))),
            "the target stays where its own answers put it"
        );
        assert_eq!(seen.len(), 6, "every silent distance holds its place");
        assert!(
            seen[..5].iter().all(|(_, address)| address.is_none()),
            "the routers that said nothing are recorded as having said nothing: {seen:?}"
        );
    }

    // ─── An echo trace, fed by hand ──────────────────────────────────────────

    /// The address an echo trace's probes leave from.
    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
    /// Two hosts an echo trace is asked about, on [`LOCAL`]'s /24 so a source
    /// resolves without a kernel route lookup.
    const TARGET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 9);
    const OTHER_TARGET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    /// An address nobody asked the trace about.
    const STRANGER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 77);
    /// The identifier every probe of an echo trace below carries.
    const MARKER: u16 = 41_234;

    /// An echo trace from [`LOCAL`], sending into a recorder and reading
    /// whatever a test pushes into the channel handed back.
    fn echo_tracer() -> (Tracer, mpsc::Sender<CapturedSegment>) {
        use crate::system::interface::{Link, LinkAddress};

        let (_session, ctx) = ScanSession::new();
        let (replies, rx) = mpsc::channel(16);
        let transport = ProbeTransport::from_parts(Box::new(MockSender::default()), rx);
        let mut tracer = Tracer::new(ctx, transport, TraceProbe::Echo, MARKER, PathCache::new());
        tracer.resolver = SourceResolver::from_links(&[
            Link::new("test0", 0).with_addresses(vec![LinkAddress::new(LOCAL.into(), 24)])
        ]);
        (tracer, replies)
    }

    /// `message` as the capture hands it up: from `source`, arriving with `ttl`.
    fn captured_echo(message: &craft::Icmpv4, source: Ipv4Addr, ttl: u8) -> CapturedSegment {
        Network::observed(
            source.into(),
            IpNextHeaderProtocols::Icmp,
            message.to_bytes(),
            ttl,
        )
    }

    /// An echo request carrying the trace's own marker is not an answer to it.
    ///
    /// The capture sees both directions, and a request differs from a reply only
    /// in its type byte.
    #[test]
    fn an_echo_request_is_not_an_answer_to_an_echo_trace() {
        let (mut tracer, _replies) = echo_tracer();
        let sequence = u16::from(MAX_HOPS);

        let request = craft::Icmpv4::echo_request(MARKER, sequence);
        assert!(
            tracer
                .classify(&captured_echo(&request, LOCAL, MAX_HOPS))
                .is_none(),
            "the trace's own request was read as an answer"
        );

        let reply = craft::Icmpv4::echo_reply(MARKER, sequence);
        assert!(
            matches!(
                tracer.classify(&captured_echo(&reply, TARGET, 60)),
                Some(Reply::Arrived { target, probed: MAX_HOPS, .. }) if target == IpAddr::from(TARGET)
            ),
            "and the reply it draws still is one"
        );
    }

    /// The round that measures distances keeps an answer only from a host it
    /// asked, and only once.
    ///
    /// Anyone who sees a probe can copy its marker under an address nobody
    /// named, and the trace's own requests come back up the capture; either,
    /// kept, would be traced with no exclusion consulted. A duplicate kept
    /// would be another walk of the same path.
    #[tokio::test(flavor = "current_thread")]
    async fn the_distance_round_keeps_one_answer_from_each_host_it_asked() {
        let (mut tracer, replies) = echo_tracer();
        let sequence = u16::from(MAX_HOPS);
        let request = craft::Icmpv4::echo_request(MARKER, sequence);
        let reply = craft::Icmpv4::echo_reply(MARKER, sequence);

        for segment in [
            captured_echo(&request, LOCAL, MAX_HOPS),
            captured_echo(&reply, STRANGER, 60),
            captured_echo(&reply, TARGET, 60),
            captured_echo(&reply, TARGET, 60),
            captured_echo(&reply, OTHER_TARGET, 60),
        ] {
            replies.try_send(segment).expect("room in the channel");
        }

        let found = tracer
            .probe_for_distances(&[TARGET.into(), OTHER_TARGET.into()])
            .await;

        assert_eq!(
            found,
            vec![(IpAddr::from(TARGET), 4), (IpAddr::from(OTHER_TARGET), 4)]
        );
    }

    /// A probe as a router would quote it: the IP header plus the transport
    /// header, built by the real writers.
    fn quoted_probe(probe: TraceProbe, marker: u16, target: IpAddr, distance: u8) -> Vec<u8> {
        let source = ip(200);
        let (segment, protocol) = match probe {
            TraceProbe::Syn { port } => (
                tcp::build_probe(
                    crate::model::technique::TcpScanTechnique::Syn,
                    source,
                    target,
                    marker,
                    port,
                    (u32::from(marker) << 8) | u32::from(distance),
                )
                .expect("a probe builds"),
                IpNextHeaderProtocols::Tcp,
            ),
            TraceProbe::Echo => (
                icmp::build_echo_request_message(
                    source,
                    target,
                    icmp::ECHO_PROBE_CODE,
                    marker,
                    u16::from(distance),
                    &[],
                )
                .expect("a probe builds"),
                IpNextHeaderProtocols::Icmp,
            ),
        };

        let (IpAddr::V4(s), IpAddr::V4(d)) = (source, target) else {
            unreachable!("the fixture is IPv4")
        };
        let header = crate::protocols::ip::build_ipv4_header(
            s,
            d,
            segment.len() as u16,
            protocol.0,
            distance,
        )
        .expect("a header builds");

        header.into_iter().chain(segment).collect()
    }

    /// A quoted probe is matched back to the host and distance it was built
    /// for, under both probe types.
    ///
    /// If the distance field's placement inside the eight guaranteed bytes were
    /// wrong, every hop would land at the wrong distance and still look real.
    #[test]
    fn a_quoted_probe_names_the_host_and_the_distance_it_was_built_for() {
        for probe in [TraceProbe::Syn { port: 443 }, TraceProbe::Echo] {
            for distance in [1u8, 7, 30] {
                let bytes = quoted_probe(probe, 41_234, ip(9), distance);
                let quoted =
                    crate::transport::frame::parse_ip_segment(&bytes).expect("the fixture parses");

                let sent = attribute(probe, 41_234, &quoted)
                    .unwrap_or_else(|| panic!("{probe:?} at {distance} should be attributed"));

                assert_eq!(sent.target, ip(9));
                assert_eq!(sent.distance, distance);
            }
        }
    }

    /// Somebody else's packet is not attributed to a probe of ours.
    ///
    /// The capture admits every ICMP error on the host, since an error cannot be
    /// narrowed in a kernel filter; one accepted here puts a router into a path
    /// it is not on.
    #[test]
    fn an_error_about_somebody_elses_packet_is_refused() {
        let probe = TraceProbe::Syn { port: 443 };
        let bytes = quoted_probe(probe, 41_234, ip(9), 5);
        let quoted = crate::transport::frame::parse_ip_segment(&bytes).expect("the fixture parses");

        assert!(attribute(probe, 41_234, &quoted).is_some(), "our own probe");
        assert!(
            attribute(probe, 41_235, &quoted).is_none(),
            "another run's marker"
        );
        assert!(
            attribute(TraceProbe::Echo, 41_234, &quoted).is_none(),
            "a TCP quotation read by an echo trace"
        );
    }

    /// A quotation cut short of the transport header settles nothing.
    ///
    /// Eight bytes past the IP header is all RFC 792 guarantees, and some routers
    /// give less.
    #[test]
    fn a_truncated_quotation_is_refused() {
        let probe = TraceProbe::Syn { port: 443 };
        let bytes = quoted_probe(probe, 41_234, ip(9), 5);
        let quoted = crate::transport::frame::parse_ip_segment(&bytes).expect("the fixture parses");

        let short = IpSegment {
            payload: &quoted.payload[..4],
            ..quoted
        };
        assert!(attribute(probe, 41_234, &short).is_none());
    }

    /// The distance a hop counter implies, against the four starting values
    /// stacks actually use.
    ///
    /// Pins the *choice* of starting value: a Linux reply read against 128 would
    /// put every host sixty-four hops further away.
    #[test]
    fn a_hop_counter_says_how_far_a_reply_travelled() {
        assert_eq!(distance_from(64), 0, "a host on this segment");
        assert_eq!(distance_from(57), 7, "seven routers, from a 64 stack");
        assert_eq!(distance_from(250), 5, "five routers, from a 255 stack");
        assert_eq!(distance_from(120), 8, "eight routers, from a 128 stack");
        assert_eq!(distance_from(30), 2, "two routers, from a 32 stack");
    }

    /// A cached path is handed out as inference, never as measurement.
    ///
    /// A spliced hop is a router this host's probes never met. Marked as it
    /// leaves the cache, so no caller can forget.
    #[test]
    fn a_spliced_path_is_marked_as_inherited() {
        let cache = PathCache::new();
        cache.remember(&[
            Hop::answered(1, ip(1), Some(Duration::from_millis(1))),
            Hop::answered(2, ip(2), Some(Duration::from_millis(2))),
            Hop::answered(3, ip(3), Some(Duration::from_millis(3))),
        ]);

        let prefix = cache
            .prefix_of(3, ip(3))
            .expect("a router another trace recorded at this distance");

        assert_eq!(prefix.len(), 2, "everything in front of the router matched");
        assert!(prefix.iter().all(Hop::inferred));
        assert!(
            prefix.iter().all(|hop| hop.rtt().is_none()),
            "a timing belongs to the trace that measured it"
        );
        assert_eq!(prefix[0].address(), Some(ip(1)));
    }

    /// A router recognised at a *different* distance is not a match.
    ///
    /// Two paths meeting the same router at different distances have not
    /// converged; splicing on the address alone would graft a path never
    /// travelled.
    #[test]
    fn a_router_at_another_distance_is_not_the_same_point_in_a_path() {
        let cache = PathCache::new();
        cache.remember(&[Hop::answered(1, ip(1), None), Hop::answered(2, ip(2), None)]);

        assert!(cache.prefix_of(2, ip(2)).is_some());
        assert!(
            cache.prefix_of(3, ip(2)).is_none(),
            "same router, further away"
        );
        assert!(
            cache.prefix_of(2, ip(9)).is_none(),
            "another router entirely"
        );
    }

    /// A gap in a remembered path stays a gap when it is spliced into another.
    ///
    /// Otherwise later traces would get a shorter path, with every hop past the
    /// hole renumbered.
    #[test]
    fn a_silent_hop_survives_being_cached() {
        let cache = PathCache::new();
        cache.remember(&[
            Hop::answered(1, ip(1), None),
            Hop::silent(2),
            Hop::answered(3, ip(3), None),
        ]);

        let prefix = cache.prefix_of(3, ip(3)).expect("the far router is known");
        assert_eq!(prefix.len(), 2);
        assert_eq!(prefix[1].distance(), 2);
        assert_eq!(prefix[1].address(), None, "the hole is still a hole");
    }

    /// A trace through a frame sender resolves every host's neighbour at once
    /// before its first probe, and sends nothing towards a dead one. Resolved
    /// inside each send, every dead neighbour would cost the whole budget in
    /// turn.
    #[tokio::test]
    async fn neighbours_behind_a_frame_sender_are_asked_for_before_the_trace() {
        use crate::system::interface::{Link, LinkAddress};
        use crate::transport::link::{LinkNeighbors, SIMULATED_HOST};

        const LIVE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 63);
        let dead: Vec<IpAddr> = (201..=210)
            .map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
            .collect();
        let (_session, ctx) = ScanSession::new();
        let (_tx, rx) = mpsc::channel(1024);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let transport = ProbeTransport::from_parts(Box::new(sender), rx)
            .with_link_neighbors(LinkNeighbors::on_simulated_segment("sim-trace0", &[LIVE]));
        let mut tracer = Tracer::new(
            ctx.clone(),
            transport,
            TraceProbe::Echo,
            41_234,
            PathCache::new(),
        );
        tracer.resolver = SourceResolver::from_links(&[Link::new("test0", 0)
            .with_addresses(vec![LinkAddress::new(IpAddr::V4(SIMULATED_HOST), 24)])]);

        tracer
            .run(dead.iter().copied().chain([IpAddr::V4(LIVE)]).collect())
            .await;

        let sent = sent.lock().unwrap();
        assert!(!sent.is_empty(), "the live neighbour is traced");
        assert!(
            sent.iter().all(|(_, _, dst)| *dst == IpAddr::V4(LIVE)),
            "a probe was handed to the sender for a neighbour nobody had resolved"
        );
    }

    /// Through the kernel, the first probe to an uncached neighbour is the write
    /// that asks, and the attempts behind it wait on the verdict: a dead
    /// neighbour is sent nothing more and not traced; a live or cached one gets
    /// every attempt. New neighbours are all asked for before any second
    /// attempt, so their resolutions overlap.
    #[tokio::test]
    async fn attempts_behind_the_kernel_asking_for_a_neighbour_wait_on_its_verdict() {
        use crate::system::interface::{Link, LinkAddress};
        use crate::transport::kernel_neighbors::KernelNeighbors;

        let held = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 65));
        let live = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 66));
        let dead: Vec<IpAddr> = (221..=224)
            .map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
            .collect();
        let (_session, ctx) = ScanSession::new();
        let (_tx, rx) = mpsc::channel(1024);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let table = KernelNeighbors::asking_on_write(sent.clone(), &[held], &[live]);
        let transport =
            ProbeTransport::from_parts(Box::new(sender), rx).with_kernel_neighbors(table);
        let mut tracer = Tracer::new(
            ctx.clone(),
            transport,
            TraceProbe::Echo,
            41_235,
            PathCache::new(),
        );
        tracer.resolver =
            SourceResolver::from_links(&[Link::new("test0", 1).with_addresses(vec![
                LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24),
            ])]);

        tracer
            .run(
                [held, live]
                    .into_iter()
                    .chain(dead.iter().copied())
                    .collect(),
            )
            .await;

        let sent = sent.lock().unwrap();
        let to = |address: IpAddr| sent.iter().filter(|(_, _, dst)| *dst == address).count();
        for &address in &dead {
            assert_eq!(
                to(address),
                1,
                "{address} was sent past the write that asked"
            );
        }
        assert_eq!(
            to(held),
            usize::from(ATTEMPTS),
            "a neighbour the kernel held"
        );
        assert_eq!(to(live), usize::from(ATTEMPTS), "a neighbour that answered");
        let first_retry = sent
            .iter()
            .enumerate()
            .filter(|(_, (_, _, dst))| *dst == held)
            .nth(1)
            .map(|(at, _)| at)
            .expect("a second attempt to the held neighbour");
        assert!(
            sent[..first_retry]
                .iter()
                .filter(|(_, _, dst)| dead.contains(dst))
                .count()
                == dead.len(),
            "every new neighbour is asked for before any host's second attempt, \
             so their resolutions run together rather than one after another"
        );
    }

    /// Hosts with a known distance skip the distance round, so their
    /// neighbours are asked for together before the first walk and a wave of
    /// dead ones is given up within one resolution's wait. (Asked walk by walk,
    /// four took a quarter of a minute in a namespace.) The bound is two waits
    /// against the four a sequential trace needs.
    #[tokio::test]
    async fn neighbours_of_hosts_with_a_known_distance_are_given_up_together() {
        use crate::scanner::strategy::raw::neighbors::RESOLUTION_WAIT_LIMIT;
        use crate::system::interface::{Link, LinkAddress};
        use crate::transport::kernel_neighbors::KernelNeighbors;

        let dead: Vec<IpAddr> = (225..=228)
            .map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
            .collect();
        let (_session, ctx) = ScanSession::new();
        for &host in &dead {
            ctx.update_host(host, |host| host.record_hop_counter(64));
        }
        let (_tx, rx) = mpsc::channel(1024);
        let sender = MockSender::default();
        let sent = sender.sent.clone();
        let table = KernelNeighbors::asking_on_write(sent.clone(), &[], &[]);
        let transport =
            ProbeTransport::from_parts(Box::new(sender), rx).with_kernel_neighbors(table);
        let mut tracer = Tracer::new(
            ctx.clone(),
            transport,
            TraceProbe::Echo,
            41_236,
            PathCache::new(),
        );
        tracer.resolver =
            SourceResolver::from_links(&[Link::new("test0", 1).with_addresses(vec![
                LinkAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24),
            ])]);

        let started = Instant::now();
        tracer.run(dead.clone()).await;
        let took = started.elapsed();

        let sent = sent.lock().unwrap();
        for &address in &dead {
            assert_eq!(
                sent.iter().filter(|(_, _, dst)| *dst == address).count(),
                1,
                "{address} was sent past the write that asked"
            );
        }
        assert!(
            took < RESOLUTION_WAIT_LIMIT * 2,
            "four dead neighbours took {took:?}, a wait apiece"
        );
    }
}
