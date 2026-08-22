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
//! one is. The one thing this engine measures that is about neither end of a
//! scan but the space between them.
//!
//! ## How a router is made to identify itself
//!
//! A router forwarding a packet is under no obligation to say it did. A router
//! *discarding* one is: when it decrements a hop limit to zero it must report
//! that back to the sender (RFC 792, RFC 4443 §3.3). So a probe built to run out
//! of hops at a chosen distance makes exactly the router at that distance
//! announce itself, and the announcement arrives from its own address.
//!
//! Nothing about this is a request a router can decline politely. It either
//! answers or it is silent, and silence at one distance says nothing about the
//! next — which is why a [`Hop`] with no address is recorded rather than
//! skipped.
//!
//! ## The probe matches the scan
//!
//! A trace to a host with an open TCP port is made of SYNs to that port; a trace
//! to any other host is made of ICMP echoes. That is not a detail. The probe
//! that reached a host is by definition the probe its network permits, and a
//! trace made of something else measures the path to wherever that something
//! else is dropped. A SYN to :443 crosses filters that discard every ping and
//! every unsolicited UDP datagram, and on the public internet that is most of
//! the interesting ones.
//!
//! ## Backwards, and why
//!
//! A trace starts at the target and walks *towards* this machine rather than
//! away from it. Walking outward is the obvious direction and it makes the cache
//! below worthless: by the time a shared router is recognised, every hop before
//! it has already been probed.
//!
//! Walking inward, the first hop recognised as one another trace already found
//! is the point at which the rest of the work can be skipped — which on a scan
//! of many hosts behind one gateway is nearly all of it.
//!
//! Starting at the target requires knowing how far away it is, which is why
//! **only hosts that answered are traced**. The distance is read out of the
//! reply: a hop counter arrives having been decremented once per router, so the
//! gap between what arrived and the value it plausibly started at is the
//! distance. See [`distance_from`].
//!
//! ## What the cache assumes
//!
//! [`PathCache`] holds, for each router seen at each distance, the path from
//! here to it. When a trace meets a router another trace already recorded at the
//! same distance, the hops before it are taken from that earlier trace instead
//! of being measured again.
//!
//! **That is an assumption, and it is worth stating plainly**: it takes two
//! paths that pass through one router at one distance to have been identical up
//! to that point. Routing does not promise this — a load balancer can send two
//! flows over different upstreams that rejoin — and it is nonetheless true of
//! very nearly every network anyone traces. The engine's answer is not to
//! pretend otherwise but to mark what it did: every spliced hop is
//! [`Hop::inferred`], so a reader can tell a measurement from an inheritance
//! without knowing this module exists.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;

use crate::model::host::path::Hop;
use crate::model::port::{PortState, Protocol};
use crate::protocols::{icmp, tcp};
use crate::scanner::session::{ScanContext, ScannerKind};
use crate::system::interface::SourceResolver;
use crate::transport::capture::CapturedSegment;
use crate::transport::frame::IpSegment;
use crate::transport::probe::{Emission, ProbeKind, ProbeTransport};
use crate::{info, warn};

use super::icmp_error;

/// How far a trace will look before giving up on reaching the target.
///
/// Thirty, which is what every traceroute has used since the first one. Paths
/// longer than this exist and are pathological; the number is a bound on wasted
/// probes rather than a claim about the internet.
pub const MAX_HOPS: u8 = 30;

/// How long one round of probes is given to be answered.
///
/// Generous compared with a port probe's budget, and deliberately. A Time
/// Exceeded is the lowest-priority work a router does: it is generated on the
/// control plane, by software, usually after every packet that could be
/// forwarded has been, and commonly rate-limited to a handful per second. A
/// timeout tuned for a host's TCP stack would report most of the internet's
/// routers as silent.
const ROUND_TIMEOUT: Duration = Duration::from_millis(1500);

/// How many probes are sent before a distance is called silent.
///
/// Three, which is what every traceroute has sent per hop since the first one,
/// and for two reasons that both still hold.
///
/// **Routers rate-limit the error this depends on.** A single unanswered probe
/// is weak evidence of silence: the router may simply have spent its budget on
/// somebody else that second. Reporting a hop as silent on one miss fills a path
/// with holes that are an artefact of the scan.
///
/// **And the capture is not ready the instant a transport opens.** Opening a
/// `libpcap` handle on every interface takes real time, and the first probe of a
/// run can leave before the handles are live — so its reply is not missed on the
/// network but here. Every other strategy in this engine survives that by
/// retrying, and this one is not special.
const ATTEMPTS: u8 = 3;

/// How many probes are in the air at once, across all targets.
///
/// A ceiling on burst rather than a rate. Routers rate-limit the errors this
/// depends on, so probes sent faster than they can be answered are not merely
/// wasted — they push the answers to *other* probes out of the same budget, and
/// the path comes back full of holes that are an artefact of the scan.
const MAX_IN_FLIGHT: usize = 16;

/// The paths already measured, shared by every trace in one scan.
///
/// See the module documentation for what a hit assumes and how a spliced hop is
/// marked. Cheap to clone: it is a handle to one shared map.
#[derive(Debug, Clone, Default)]
pub struct PathCache {
    /// A router, at a distance, and everything known to be in front of it.
    known: Arc<DashMap<Waypoint, Arc<[Hop]>>>,
}

/// A router recognised at a distance: the key a splice matches on.
///
/// Both halves, because a router met at a different distance is a different
/// point in a path — see `a_router_at_another_distance_is_not_the_same_point_in_a_path`.
type Waypoint = (u8, IpAddr);

impl PathCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// The path in front of `address` if some earlier trace found it at
    /// `distance`, as hops to be adopted rather than measured.
    ///
    /// Already marked [`Hop::inferred`], so a caller cannot record them as its
    /// own measurements by forgetting to.
    fn prefix_of(&self, distance: u8, address: IpAddr) -> Option<Vec<Hop>> {
        let prefix = self.known.get(&(distance, address))?;
        Some(prefix.iter().map(|hop| hop.as_inferred()).collect())
    }

    /// Files a completed trace, so later ones can splice from it.
    ///
    /// Only hops that answered are filed as keys — a silent distance names no
    /// router and could not be recognised again — but silent hops are kept
    /// *inside* the stored prefixes, because a path that quietly closed its own
    /// gaps would be spliced into later traces as a shorter path than it was.
    fn remember(&self, hops: &[Hop]) {
        for (index, hop) in hops.iter().enumerate() {
            let Some(address) = hop.address() else {
                continue;
            };
            // Everything strictly nearer than this router. The router itself is
            // the key, so including it would have a splice record it twice.
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
    /// Both admit ICMP errors, because both depend on them entirely: a trace
    /// hears from a router only through the error it is obliged to send, and a
    /// capture narrowed to the probe's own protocol would hear nothing but the
    /// final hop.
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
    /// carries — and so the value its replies come back to.
    marker: u16,
    /// Which of this host's addresses to send from, per target. Owned rather
    /// than consulted through the caller, because resolving is a cached lookup
    /// that mutates and every strategy here keeps its own.
    resolver: SourceResolver,
    /// When each outstanding probe left, so a reply can be timed against it.
    in_flight: HashMap<Sent, Instant>,
    sent: u64,
    /// Probes the transport refused, counted apart from the ones it took.
    ///
    /// A probe that never reached the wire and a probe nobody answered look
    /// identical in an empty path, and only one of them is about the network.
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
            in_flight: HashMap::new(),
            sent: 0,
            failed: 0,
            answered: 0,
        }
    }

    /// Builds and sends one probe to `target`, built to expire `distance` hops
    /// away. Returns whether it reached the wire.
    fn send(&mut self, target: IpAddr, distance: u8, source: IpAddr) -> bool {
        let segment = match self.probe {
            TraceProbe::Syn { port } => {
                // The distance rides in the sequence number's low byte. An ICMP
                // error is only guaranteed to quote eight bytes past the IP
                // header, which for TCP is the two ports and the sequence — so
                // this is the last field a router can be relied on to hand back,
                // and the only one with room to spare.
                let sequence = (u32::from(self.marker) << 8) | u32::from(distance);
                match tcp::create_probe(
                    crate::model::technique::TcpScanTechnique::Syn,
                    &source,
                    &target,
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
                // The echo sequence field, for the same reason: it sits inside
                // the eight bytes a quotation guarantees.
                match icmp::create_echo_request_message(
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
            .send(&segment, source, target, Emission::at_hop(distance))
        {
            Ok(()) => {
                self.in_flight
                    .insert(Sent { target, distance }, Instant::now());
                self.sent += 1;
                true
            }
            Err(error) => {
                // At the first level of detail, not the second. A probe that
                // never reached the wire and a probe nobody answered look
                // identical in an empty path, and only one of them is about the
                // network — logging the difference at `-vv` hid the answer to
                // exactly the question a reader with an empty path is asking.
                warn!(
                    verbosity = 1,
                    "trace probe to {target} was not sent: {error:#}"
                );
                self.failed += 1;
                false
            }
        }
    }

    /// Reads replies until `deadline`, handing each to `on_reply`.
    ///
    /// Stops early once nothing is outstanding, so a round that is fully
    /// answered costs its round trip rather than its timeout.
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
        // A router reporting a probe it discarded. The quotation is the only
        // thing tying it to one of ours.
        if let Some(expired) = icmp_error::parse_expired(segment) {
            let sent = self.attribute(&expired.quoted)?;
            let rtt = self.in_flight.remove(&sent).map(|at| at.elapsed());
            return Some(Reply::Expired {
                sent,
                router: segment.source,
                rtt,
            });
        }

        // The target itself, having been reached. Its own hop counter is what
        // says how far away it is.
        let arrived = segment.observation.as_ref()?.remaining_hops();

        // **Attributed to the probe it answers, not merely to its sender.** A
        // trace sends several probes per distance and moves on when the first is
        // answered, so the later ones are still in the air when the next
        // distance is being probed. Matched on the source address alone, one of
        // those stragglers clears the outstanding entry for a distance it says
        // nothing about — and that distance is then recorded as silent. It is
        // the same discipline `attribute` applies to an error, for the same
        // reason, and a first run against a real host is what showed both were
        // needed.
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
    /// The counterpart of [`attribute`] for the replies that come back from the
    /// target rather than from a router. Neither kind may be taken on trust: an
    /// answer names the probe it answers, and reading only its sender confuses
    /// two probes to one host.
    ///
    /// A SYN draws a segment acknowledging the sequence it carried, so the
    /// marker written into that sequence comes back one higher. An echo request
    /// draws a reply required to carry its identifier and sequence back
    /// unchanged (RFC 792 §Echo, RFC 4443 §4.2), which is simpler and exact.
    fn answered_distance(&self, segment: &CapturedSegment) -> Option<u8> {
        match self.probe {
            TraceProbe::Syn { .. } => {
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
                let (identifier, sequence) = icmp::echo_token(&segment.bytes).ok()?;
                if identifier != self.marker {
                    return None;
                }
                u8::try_from(sequence).ok()
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
/// header names the distance — see [`Tracer::send`] for where each is written.
///
/// **Both halves are checked, and the marker twice for TCP.** An ICMP error
/// carries no ports of its own, so the capture that admits them admits *every*
/// ICMP error on every captured interface: a busy host produces a steady
/// background of errors about packets this engine never sent, and one of those
/// attributed to a probe puts a router into a path it is not on. A wrong hop is
/// worse than a missing one, because nothing downstream can tell it is wrong.
///
/// Only the first eight bytes past the quoted IP header are read, because only
/// those are guaranteed to be there (RFC 792). For TCP that reaches exactly to
/// the end of the sequence number; for ICMP, to the end of the echo sequence.
fn attribute(probe: TraceProbe, marker: u16, quoted: &IpSegment<'_>) -> Option<Sent> {
    let head: [u8; 8] = quoted.payload.get(..8)?.try_into().ok()?;

    let distance = match (probe, quoted.protocol) {
        (TraceProbe::Syn { .. }, IpNextHeaderProtocols::Tcp) => {
            // The source port, then the sequence number's high bytes. Two
            // independent checks of the same value, because a router quoting a
            // truncated or mangled probe is common enough that one field
            // matching by chance is not a theory.
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
/// Three outcomes and not two: a distance where nothing answered is not the
/// same as one where the target did, and collapsing them is what let a trace
/// stop short of its own target.
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
        /// Carried for the same reason [`Sent::distance`] is: a trace sends
        /// several probes per distance and moves on at the first answer, so the
        /// rest arrive while the next distance is being probed. Without this a
        /// straggler is read as "the target is reachable *here*", and on a path
        /// whose routers stay quiet it walks the far end one hop nearer per
        /// round until the whole path is discarded.
        probed: u8,
        /// How far away the reply's own hop counter says the target is, which
        /// is a statement about the path *back*. See [`distance_from`].
        implied: u8,
    },
}

/// How many routers a reply crossed, from the hop counter it arrived with.
///
/// A hop counter is decremented once per router, so the distance is the gap
/// between what arrived and the value it started at. The starting value is not
/// carried in the packet and is a property of the sender's stack, so it is
/// inferred from the usual ones — 32, 64, 128, 255 — by taking the smallest that
/// could have produced what arrived.
///
/// **A bound rather than a measurement**, and it can be wrong in one direction:
/// a host more than 64 hops away is read against 128 and reported nearer than it
/// is. Paths that long do not occur outside a laboratory, and the alternative —
/// refusing to trace anything whose stack is not already fingerprinted — would
/// decline nearly every host to avoid an error nobody has met.
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
/// An open TCP port if there is one, since a probe that reached a port is proof
/// the path permits that probe. The lowest-numbered open port rather than an
/// arbitrary one, so two runs against an unchanged host produce the same trace.
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
/// The entry point, and the whole of this module's public surface. Hosts are
/// grouped by what will reach them and each group is traced with a transport of
/// its own; the [`PathCache`] is shared across the groups, so a TCP trace and an
/// ICMP trace through the same gateway still only measure it once.
///
/// Records what it finds through [`ScanContext::update_host`], so an excluded
/// address cannot acquire a path any more than it can acquire a port.
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
        let transport = match ProbeTransport::open(probe.probe_kind(marker)) {
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
    async fn run(&mut self, group: Vec<IpAddr>) {
        let distances = self.measure_distances(&group).await;

        for (target, distance) in distances {
            if self.ctx.handle.should_stop() {
                break;
            }
            self.walk(target, distance).await;
        }

        // A run that drew nothing at all is reported rather than left to look
        // like a network with no routers in it. It is the difference between
        // "nothing answered" and "nothing was heard", and only one of those is
        // about the network — a scan whose capture or send path is wrong looks
        // exactly like a quiet internet, which is how the first version of this
        // shipped silently broken.
        // Three ways a trace comes back with nothing, and they call for
        // completely different responses: probes that would not leave this host,
        // probes that left and drew no answer, and a network with nothing to
        // say. Reported apart, because collapsed into one empty path they are
        // indistinguishable — which is how the first version of this shipped
        // broken and looked like a quiet internet.
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
                verbosity = 1,
                "traceroute: {} probes sent ({} refused), {} answered",
                self.sent,
                self.failed,
                self.answered
            );
        }
    }

    /// How far away each host is.
    ///
    /// **Read from what the scan already saw wherever possible.** Every reply a
    /// host sent arrived with a hop counter, the scan recorded the most recent
    /// one, and the distance falls straight out of it — so for a host the port
    /// scan reached, this costs no probe, no round trip and no waiting.
    ///
    /// That is not only cheaper, it is sturdier. The first version of this sent
    /// a probe purely to be answered, which made every trace depend on a second
    /// exchange succeeding after the first already had; when that exchange
    /// produced nothing the whole trace silently produced nothing, and no part
    /// of the output said why.
    ///
    /// A host with no recorded counter still gets the probe. That is the honest
    /// fallback rather than the normal path, and a host that answers neither is
    /// skipped: a path is measured backwards from its far end, and there is no
    /// far end to start from.
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
                        verbosity = 1,
                        "{target} is about {distance} hop(s) away, from the hop counter of {arrived} \
                         its reply arrived with"
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
    async fn probe_for_distances(&mut self, group: &[IpAddr]) -> Vec<(IpAddr, u8)> {
        let mut found: Vec<(IpAddr, u8)> = Vec::new();

        for window in group.chunks(MAX_IN_FLIGHT) {
            if self.ctx.handle.should_stop() {
                break;
            }
            for target in window {
                let Some(source) = self.resolver.resolve(*target) else {
                    warn!(
                        verbosity = 1,
                        "no source address to trace {target} from; skipping it"
                    );
                    continue;
                };
                for _ in 0..ATTEMPTS {
                    self.send(*target, MAX_HOPS, source);
                }
            }

            let deadline = Instant::now() + ROUND_TIMEOUT;
            let mut reached: Vec<(IpAddr, u8)> = Vec::new();
            self.collect(deadline, |_, reply| {
                if let Reply::Arrived {
                    target, implied, ..
                } = reply
                {
                    reached.push((target, implied));
                }
            })
            .await;

            found.extend(reached);
            self.in_flight.clear();
        }

        found
    }

    /// Walks from `distance` back to the first router, splicing where the cache
    /// recognises one.
    /// What one distance turned out to hold.
    async fn probe_distance(&mut self, target: IpAddr, at: u8, source: IpAddr) -> Landing {
        // A burst rather than one probe waited out three times: the answers are
        // independent, so sending them together costs one round trip instead of
        // three and the first to arrive settles the distance.
        for _ in 0..ATTEMPTS {
            self.send(target, at, source);
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
            // The target answering *this* probe means the probe was never
            // discarded, so the target is at or nearer than this distance. The
            // distance is checked as strictly as it is for an expiry: an answer
            // to an earlier round says nothing about this one.
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

        // One line per distance, which is what makes a wrong path readable
        // afterwards. A trace that stops short, or names the target at the wrong
        // distance, looks entirely plausible in its finished form; the round it
        // went wrong in does not.
        info!(
            verbosity = 2,
            "trace {target} at hop {at}: {} ({} probe(s) sent)",
            match landing {
                Landing::Router(address, _) => format!("router {address}"),
                Landing::Target => "the target itself".to_string(),
                Landing::Silent => "nothing answered".to_string(),
            },
            self.sent - attempted
        );

        landing
    }

    /// Measures the path to `target`, starting from `estimate` and correcting it.
    ///
    /// **`estimate` is a starting point, not the answer.** It is read from the
    /// hop counter of a reply the host sent, which measures the path *back* from
    /// the host — and internet routing is asymmetric, so the two differ
    /// routinely and by more than a hop. An anycast address can easily answer
    /// from two hops nearer than it can be reached. Trusting the estimate
    /// outright reports the target closer than it is and silently drops every
    /// router beyond it, which is a confidently wrong path rather than a short
    /// one.
    ///
    /// So the walk goes outward first, until the target actually answers, and
    /// only then inward. Both directions correct the estimate: outward when the
    /// return path was shorter, and inward — where the target answering at a
    /// nearer distance moves the far end in — when it was longer.
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
            match self.probe_distance(target, reached, source).await {
                Landing::Target => break,
                // A router still stands here, so the target is further out. The
                // router is a genuine hop and is kept: walking outward is
                // measuring the path, not merely searching for its end.
                Landing::Router(address, rtt) => {
                    measured.push(Hop::answered(reached, address, rtt));
                }
                Landing::Silent => measured.push(Hop::silent(reached)),
            }
            reached += 1;
        }

        // Nothing answered anywhere out to the ceiling. Reporting the target at
        // `MAX_HOPS` would invent a distance, so the far end is left unstated
        // and only the routers that did answer are kept.
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

            match self.probe_distance(target, at, source).await {
                // The target answers nearer than the outward walk settled on,
                // so the outward walk overshot: the far end moves in, and this
                // distance holds the target rather than a router.
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
            // The far end of its own path, and the one hop whose address needed
            // no error to learn.
            hops.push(Hop::answered(distance, target, None));
        }
        if let Some(prefix) = spliced {
            hops.extend(prefix);
        }
        // Anything the outward walk recorded beyond where the far end settled
        // describes a distance the target is not at and the path does not
        // reach.
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
    use crate::scanner::session::ScanSession;
    use crate::transport::probe::{ProbeSender, SendError};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    // ─── A network that answers ──────────────────────────────────────────────

    /// A fake internet: routers that expire probes and a target that answers.
    ///
    /// Built around the hop limit rather than ignoring it, which is the whole
    /// point — [`Emission`] is what a real router acts on, so a fake that
    /// discards it would test the loop against a network that does not behave
    /// like one. A probe with a hop limit below `distance` comes back as a Time
    /// Exceeded from the router at that distance; one that reaches the target
    /// comes back as an answer from the target.
    struct Network {
        /// How many routers away the target is, going out.
        distance: u8,
        /// The hop counter the target's own answers arrive with.
        ///
        /// Independent of [`distance`](Self::distance) on purpose. A reply's
        /// counter measures the path *back*, and internet routing is asymmetric
        /// — so the number a trace estimates its starting point from routinely
        /// disagrees with the number of routers it then has to walk. A fake
        /// where the two always agreed would never exercise the correction, and
        /// that is exactly the case a real host found first.
        reply_ttl: u8,
        /// Distances whose router refuses to identify itself.
        silent: Vec<u8>,
        replies: mpsc::UnboundedSender<CapturedSegment>,
    }

    /// The SYN+ACK a listening port answers `probe` with.
    ///
    /// Ports swapped, and the acknowledgement one past the sequence that
    /// arrived, which is what every TCP stack does and what the trace reads to
    /// tell one of its own probes from another.
    fn syn_ack_to(probe: &[u8]) -> Vec<u8> {
        use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};

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
        IpAddr::V4(Ipv4Addr::new(10, 0, distance, 1))
    }

    impl Network {
        /// A reply carrying an IP observation, which a synthetic segment
        /// otherwise has none of — and which the loop needs, since the hop
        /// counter is what says how far away the target is.
        fn observed(
            source: IpAddr,
            protocol: pnet::packet::ip::IpNextHeaderProtocol,
            bytes: Vec<u8>,
            ttl: u8,
        ) -> CapturedSegment {
            CapturedSegment {
                source,
                protocol,
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
            emission: Emission,
        ) -> Result<(), SendError> {
            if emission.hop_limit >= self.distance {
                // Far enough: the target itself answers, and its hop counter is
                // what the trace reads the distance out of. A real SYN+ACK, not
                // the probe echoed back — the acknowledgement is what names the
                // probe being answered, so a fake that omitted it would be
                // testing the loop against a stack that does not exist.
                let reply = Network::observed(
                    dst,
                    IpNextHeaderProtocols::Tcp,
                    syn_ack_to(segment),
                    self.reply_ttl,
                );
                let _ = self.replies.send(reply);
                return Ok(());
            }

            if self.silent.contains(&emission.hop_limit) {
                return Ok(());
            }

            // A router discarding the probe, quoting it back the way RFC 792
            // requires.
            let quoted = {
                let (IpAddr::V4(s), IpAddr::V4(d)) = (src, dst) else {
                    unreachable!("the fixture is IPv4")
                };
                let header = crate::protocols::ip::create_ipv4_header(
                    s,
                    d,
                    segment.len() as u16,
                    IpNextHeaderProtocols::Tcp,
                    emission.hop_limit,
                )
                .expect("a header builds");
                header
                    .into_iter()
                    .chain(segment.iter().copied())
                    .collect::<Vec<u8>>()
            };

            let mut bytes = vec![0u8; 8];
            bytes[0] = pnet::packet::icmp::IcmpTypes::TimeExceeded.0;
            bytes.extend_from_slice(&quoted);

            let _ = self.replies.send(Network::observed(
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
        let (_session, ctx) = ScanSession::new();
        let (tx, rx) = mpsc::unbounded_channel();
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

    /// The whole loop, against a network that behaves like one.
    ///
    /// This is the test the unit tests around it cannot be: they check that a
    /// quotation is read correctly and that a cache splices correctly, and a
    /// trace can still record nothing at all with both of those working. What
    /// this asserts is that the probes, the replies and the attribution fit
    /// together — which is exactly what a first run against a real host found
    /// they did not.
    ///
    /// It has already earned its place twice. It caught the straggler defect:
    /// several probes go out per distance and the trace moves on when the first
    /// is answered, so the rest are still in the air during the next distance —
    /// and matched on sender alone, one of them cleared the outstanding entry
    /// for a distance it said nothing about, which was then recorded as silent.
    /// The silent router at distance two is in the fixture for that reason: it
    /// is the case where the loop has to wait rather than being handed an
    /// answer, and it is where a straggler lands.
    #[tokio::test(flavor = "current_thread")]
    async fn a_trace_records_every_router_between_here_and_the_target() {
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let (ctx, mut tracer) = tracer_against(Network {
            distance: 4,
            reply_ttl: 60,
            silent: vec![2],
            replies: mpsc::unbounded_channel().0,
        });

        tracer.run(vec![target]).await;

        let path = ctx
            .read_host(&target, |host| host.path().clone())
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

    /// Traces `target` across `network`, seeding the hop counter the scan would
    /// have recorded from an earlier reply.
    async fn trace_across(network: Network, target: IpAddr) -> Vec<(u8, Option<IpAddr>)> {
        let seed = network.reply_ttl;
        let (ctx, mut tracer) = tracer_against(network);

        // What the port scan leaves behind, and what the trace starts from.
        ctx.update_host(target, |host| host.record_hop_counter(seed));

        tracer.run(vec![target]).await;

        ctx.read_host(&target, |host| {
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
    /// **The defect a real host found.** A reply's hop counter measures the path
    /// back from the host, and traceroute measures the path out to it; an
    /// anycast address answers from nearer than it can be reached. Trusted as
    /// the answer, the estimate reported the target two routers closer than it
    /// was and dropped both hops beyond it — a confidently wrong path, which is
    /// worse than a short one because nothing in it looks wrong.
    #[tokio::test(flavor = "current_thread")]
    async fn a_target_further_out_than_its_replies_suggest_is_still_reached() {
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

        let seen = trace_across(
            Network {
                distance: 7,
                // 64 - 59 = five hops back, against seven going out.
                reply_ttl: 59,
                silent: vec![2],
                replies: mpsc::unbounded_channel().0,
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
    /// The other direction of the same asymmetry, and the one that would
    /// otherwise leave a path with the target recorded beyond its own last
    /// router and phantom distances in between.
    #[tokio::test(flavor = "current_thread")]
    async fn a_target_nearer_than_its_replies_suggest_is_not_reported_far_away() {
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

        let seen = trace_across(
            Network {
                distance: 5,
                // 64 - 56 = eight hops back, against five going out.
                reply_ttl: 56,
                silent: vec![],
                replies: mpsc::unbounded_channel().0,
            },
            target,
        )
        .await;

        assert_eq!(seen.last(), Some(&(5, Some(target))));
        assert_eq!(seen.len(), 5, "nothing is recorded past the target");
    }

    /// A path whose routers all stay quiet still reports its own length.
    ///
    /// **The shape that broke against a real host, and the reason the distance
    /// on an answer is checked.** Where every router answers, a straggler read
    /// as "the target is here" is overwritten by the genuine expiry arriving in
    /// the same round, and the defect stays hidden. Where none of them answer —
    /// which is ordinary, since large networks rate-limit these errors to
    /// nothing — a straggler is the *only* reply a round sees, so the far end
    /// walked one hop nearer per round until it reached the first, and the
    /// filter that drops hops beyond the far end then discarded the entire
    /// path. What came back was a single line claiming the target was one hop
    /// away.
    #[tokio::test(flavor = "current_thread")]
    async fn a_path_of_silent_routers_keeps_its_length() {
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

        let seen = trace_across(
            Network {
                distance: 6,
                reply_ttl: 58,
                // Not one router identifies itself.
                silent: (1..=6).collect(),
                replies: mpsc::unbounded_channel().0,
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

    /// A probe as a router would quote it: the IP header plus the transport
    /// header, built by the same writers that build a real one.
    fn quoted_probe(probe: TraceProbe, marker: u16, target: IpAddr, distance: u8) -> Vec<u8> {
        let source = ip(200);
        let (segment, protocol) = match probe {
            TraceProbe::Syn { port } => (
                tcp::create_probe(
                    crate::model::technique::TcpScanTechnique::Syn,
                    &source,
                    &target,
                    marker,
                    port,
                    (u32::from(marker) << 8) | u32::from(distance),
                )
                .expect("a probe builds"),
                IpNextHeaderProtocols::Tcp,
            ),
            TraceProbe::Echo => (
                icmp::create_echo_request_message(
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
        let header = crate::protocols::ip::create_ipv4_header(
            s,
            d,
            segment.len() as u16,
            protocol,
            distance,
        )
        .expect("a header builds");

        header.into_iter().chain(segment).collect()
    }

    /// A quoted probe is matched back to the host and distance it was built
    /// for, under both probe types.
    ///
    /// The pairing the whole trace rests on. The distance rides in a field
    /// chosen because it falls inside the eight bytes a quotation guarantees,
    /// and if that arithmetic is wrong the failure is not a crash — it is a path
    /// whose hops are all at the wrong distance, which looks like a real answer.
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
    /// The capture admits every ICMP error on the host, because an error names
    /// no ports of its own and cannot be narrowed in a kernel filter. A busy
    /// machine produces a steady background of them, and one accepted here puts
    /// a router into a path it is not on — a wrong hop, which nothing
    /// downstream can tell from a right one.
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
    /// Eight bytes past the IP header is all RFC 792 guarantees and some routers
    /// give exactly that or less. Guessing at what is missing would attribute a
    /// hop on partial evidence.
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
    /// The arithmetic is one subtraction; what is worth pinning is the *choice*
    /// of starting value, since reading a Linux reply against 128 would report
    /// every host as sixty-four hops further away than it is.
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
    /// The property the whole cache rests on: a spliced hop is a claim about a
    /// router this host's probes never met, and a report that presented it as a
    /// measurement would be overstating what the scan did. Marked at the point
    /// it leaves the cache rather than by whoever adopts it, so no caller can
    /// forget.
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
    /// converged — one of them went somewhere else first — so splicing on the
    /// address alone would graft a path that was never travelled.
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
    /// A cache that quietly closed its own holes would hand later traces a path
    /// shorter than the one measured, renumbering every hop past the hole.
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
}
