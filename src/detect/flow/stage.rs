// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Running the flow corpus over a host
//!
//! The Tier-1 detection stage. For each open port a host holds, every enabled
//! flow whose `when` gate fits the port is run against it, and the findings it
//! produces are recorded on the port. It is the active analogue of the [CVE
//! correlator](crate::cve): that reads what a scan already gathered, this
//! exchanges bytes with the port to decide, and both hand a [`Finding`] to the
//! subject it concerns.
//!
//! ## What runs, and how it reaches the port
//!
//! A flow runs for a port when its `when` fits the port's service, number and
//! protocol, and its class is one the default policy enables, `passive` and
//! `active-benign`, the intrusive classes staying off until an operator opts
//! them in through an envelope. The [`Probe`] each flow
//! speaks through is supplied per port by the caller: that is the seam the live
//! transport plugs into, and it keeps this stage testable with a canned socket
//! and free of any transport of its own. A caller that cannot reach a port
//! returns [`None`], and the port is skipped.

// `run_flows` is a synchronous convenience the scanner bypasses, driving
// `detect_port` directly, so only the tests exercise it.
#![allow(dead_code)]

use crate::config::DetectionEnvelope;
use crate::model::finding::Finding;
use crate::model::host::Host;
use crate::model::port::{Port, PortState, Protocol};

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::db::FlowDb;
use super::schema::FlowDetection;
use super::{FlowSeed, Probe, ProbeRefusal};
use crate::config::limits::DETECTION_FLOW_CONCURRENCY;
use crate::detect::manifest::{
    CapabilitySpec, Class, DEFAULT_MAX_BYTES, DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_MILLIS,
};

/// Runs `corpus`'s enabled, applicable flows against each open port of `host`,
/// recording every finding they produce. `probe_for` supplies the [`Probe`] a
/// flow speaks through for a given port, or [`None`] to skip that port. A scan
/// passes [`FlowDb::global`]; a test can pass a corpus of its own.
///
/// The host-level convenience over [`detect_port`], for a synchronous caller with
/// the whole host in hand.
pub(crate) fn run_flows(
    host: &mut Host,
    corpus: &FlowDb,
    envelope: &DetectionEnvelope,
    probe_for: impl Fn(&Port) -> Option<Box<dyn Probe>> + Sync,
) {
    let host_addr = host.scoped_ip().addr().to_string();
    // Collect first, mutate second: reading the ports borrows the host, and
    // recording a finding needs them back mutably, so the two cannot overlap.
    let mut hits: Vec<(u16, Protocol, Finding)> = Vec::new();
    for port in host.ports() {
        if port.state() != PortState::Open {
            continue;
        }
        let number = port.number();
        let protocol = port.protocol();
        let service = port.service().map(|service| service.name());
        // run_flows is a synchronous convenience; the scanner drives detect_port
        // directly and surfaces the shortfalls this discards.
        let (produced, _shortfalls) = detect_port(
            corpus,
            envelope,
            &host_addr,
            service,
            number,
            protocol,
            |_caps| probe_for(port),
        );
        for finding in produced {
            hits.push((number, protocol, finding));
        }
    }

    for (number, protocol, finding) in hits {
        host.add_port_finding(number, protocol, finding);
    }
}

/// The findings `corpus`'s enabled, applicable flows produce for one port with
/// these facts. `probe_for` is handed the running flow's declared
/// [`CapabilitySpec`] (its budget) and yields a fresh [`Probe`] bound to the port,
/// or [`None`] to skip that flow. This is the per-port core the live detection
/// phase drives: it holds no host and does no I/O of its own, so a caller can run
/// it wherever the socket lives.
///
/// Beside the findings it returns each flow that stopped short of its questions,
/// a [`Shortfall`] saying whether its own budget or the port's silence stopped
/// it, in corpus order like the findings. A flow the port was given up on before
/// it could ask is among them: a question left unasked is reported, never
/// dropped.
pub(crate) fn detect_port(
    corpus: &FlowDb,
    envelope: &DetectionEnvelope,
    host: &str,
    service: Option<&str>,
    number: u16,
    protocol: Protocol,
    probe_for: impl Fn(&CapabilitySpec) -> Option<Box<dyn Probe>> + Sync,
) -> (Vec<Finding>, Vec<Shortfall>) {
    // Which flows this port answers to, settled before any of them runs. The pass
    // is cheap, it decides how wide the run below should be, and it gives every
    // flow the index that puts its findings back in corpus order afterwards.
    let applicable: Vec<_> = corpus
        .flows()
        .filter(|flow| {
            let manifest = &flow.flow().detection;
            enabled(manifest.capabilities.class, envelope)
                && manifest.when.applies(service, number, protocol)
        })
        .collect();
    if applicable.is_empty() {
        return (Vec::new(), Vec::new());
    }

    // One seed for the port serves every flow that runs against it: the address
    // and number are the port's, not any flow's, so a `{host}`/`{port}` template
    // resolves to the endpoint under probe whichever detection names it.
    let seed = FlowSeed::new(host, number);
    // What the port's flows share: its replies, and how it has behaved under
    // them. See [`PortShare`].
    let port = PortShare::default();

    let run_one = |index: usize| -> Option<Run> {
        let flow = applicable[index];
        let manifest = &flow.flow().detection;
        let inner = probe_for(&manifest.capabilities)?;
        let limits = Limits::of(&manifest.capabilities);
        let mut probe = CachingProbe::new(
            inner,
            &port,
            Duration::from_millis(limits.millis / 4 * 3),
            limits.bytes,
        );
        let found = flow.run(&seed, &mut probe);
        let shortfall = probe.stopped(&limits).map(|stopped| Shortfall {
            detection: manifest.id.clone(),
            stopped,
            answered: probe.answered,
            requests: requests(flow.flow()),
        });
        Some(Run {
            index,
            findings: found,
            shortfall,
            slow: probe.slow(),
            crowded: probe.crowded,
        })
    };

    // The first flow runs alone, and the rest widen out behind it only if that one
    // came back without the port proving slow.
    //
    // Widening from the start defeats the very thing that makes a slow host
    // bearable. [`DEAD_PORT_STRIKES`] works because the flows that follow a dead
    // wait can be spared it, and eight flows launched together are all already
    // waiting when the first strike lands: a port that stalls costs eight dead
    // waits instead of two, and eight connections instead of two, for exactly the
    // wall clock it cost before. So the port answers one question first, and only
    // a port that answered it in good time is asked the rest at once.
    let mut runs: Vec<Run> = Vec::with_capacity(applicable.len());
    let first = run_one(0);
    let widen = first.as_ref().is_none_or(|run| !run.slow);
    runs.extend(first);

    let width = if widen {
        DETECTION_FLOW_CONCURRENCY.min(applicable.len() - 1)
    } else {
        1
    };

    // The flows left to ask one at a time, in corpus order: every flow after
    // the first when the port is not widened onto, and otherwise the ones the
    // wide run never took up and the ones it has to ask again.
    let mut alone: Vec<usize> = Vec::new();
    if width <= 1 {
        alone.extend(1..applicable.len());
    } else {
        // The port stays wide only while it keeps pace. A flow that comes back
        // slow, a dead wait or its clock run out, says the port is being asked
        // more at once than it answers, and from then on no worker takes up
        // another flow: the ones already running finish, and everything left is
        // asked one at a time below. A slow flow that shared the port with
        // others is not taken at its word either. Its wait was the queue in
        // front of it as much as the port, so its run is set aside and the flow
        // is asked again alone, where the answers it already drew in full come
        // back from the cache and only what it never heard goes to the port.
        //
        // Narrowing rather than a strike because a port answering one request
        // at a time is alive, and costs its flows their budgets only when they
        // queue behind each other. Asked in turn, it answers every one.
        let next = AtomicUsize::new(1);
        let narrowed = AtomicBool::new(false);
        let done: Mutex<Vec<Run>> = Mutex::new(Vec::with_capacity(applicable.len()));
        let again: Mutex<Vec<usize>> = Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..width {
                scope.spawn(|| {
                    loop {
                        if narrowed.load(Ordering::Relaxed) {
                            break;
                        }
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        if index >= applicable.len() {
                            break;
                        }
                        let Some(run) = run_one(index) else {
                            continue;
                        };
                        if run.slow {
                            narrowed.store(true, Ordering::Relaxed);
                            if run.crowded && repeatable(applicable[index]) {
                                again
                                    .lock()
                                    .unwrap_or_else(|held| held.into_inner())
                                    .push(index);
                                continue;
                            }
                        }
                        done.lock()
                            .unwrap_or_else(|held| held.into_inner())
                            .push(run);
                    }
                });
            }
        });
        runs.extend(done.into_inner().unwrap_or_else(|held| held.into_inner()));
        alone.extend(again.into_inner().unwrap_or_else(|held| held.into_inner()));
        alone.extend(next.into_inner().min(applicable.len())..applicable.len());
        alone.sort_unstable();
    }
    // Serially, which is where the strike count does its work: each dead wait is
    // seen before the next flow opens a socket, and no wait here is anyone's but
    // the port's.
    runs.extend(alone.into_iter().filter_map(&run_one));

    // Back into corpus order. A scan is written down and read back, and a report
    // whose findings are in whatever order the threads happened to finish is one
    // that cannot be diffed against the same scan run twice.
    runs.sort_by_key(|run| run.index);

    let mut findings = Vec::new();
    let mut shortfalls = Vec::new();
    for run in runs {
        findings.extend(run.findings);
        shortfalls.extend(run.shortfall);
    }
    (findings, shortfalls)
}

/// What one flow left behind, carrying the position it holds in the corpus so a
/// run finished out of order can be put back into it.
struct Run {
    index: usize,
    findings: Vec<Finding>,
    shortfall: Option<Shortfall>,
    /// Whether the port was slow to this flow: an exchange held past the
    /// dead-wait mark, or the flow's clock ran out. See [`CachingProbe::slow`].
    slow: bool,
    /// Whether any of the flow's exchanges shared the port with another's, so
    /// that how long it waited was partly the queue's doing.
    crowded: bool,
}

/// Whether a flow may be asked a second time after a run the port's queue
/// spoiled.
///
/// Only a flow that leaves the target as it found it. A second run repeats
/// every request the first sent without hearing a whole reply, and a request
/// that changes the target or tests a weakness may have taken effect unheard:
/// the operator who opted such a flow in granted it one attempt, not two. Its
/// crowded run stands, cut short or not, and is reported as it came out.
fn repeatable(flow: &super::db::CompiledFlow) -> bool {
    matches!(
        flow.flow().detection.capabilities.class,
        Class::Derived | Class::Passive | Class::ActiveBenign
    )
}

/// A flow that stopped short of what it set out to ask: which flow, what
/// stopped it, and how far it had got.
///
/// Carried to the report as its own fact because it is neither of the two
/// things it would otherwise read as. It is not a clean run, since a question
/// the flow meant to ask went unasked or unanswered and its silence clears
/// nothing. And it is not a fault, since nothing broke: the detection declared
/// a ceiling and the ceiling held, or the port stopped answering and was not
/// waited on further. A reader deciding whether to look again needs which of
/// those, and how much of the flow was left when it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Shortfall {
    /// The flow's id.
    pub(crate) detection: String,
    /// What stopped it.
    pub(crate) stopped: Stopped,
    /// The requests that drew a reply before it stopped.
    pub(crate) answered: u32,
    /// The requests the flow makes when every step runs, which is what it set
    /// out to ask. See [`requests`].
    pub(crate) requests: u32,
}

/// What left a flow short of its questions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stopped {
    /// One of the flow's own budgets ran out on a port still answering.
    Budget {
        /// Which budget.
        refusal: ProbeRefusal,
        /// Its ceiling as the flow ran under it, in its own unit:
        /// milliseconds, bytes, or connections.
        limit: u64,
    },
    /// The port stopped answering in time, with nothing else of the scan's
    /// waiting on it, and was given up on: this flow either held one of the
    /// [`DEAD_PORT_STRIKES`] dead waits itself or came after them and had
    /// questions only the port could answer. The shortfall is the port's, so
    /// it names no budget of the flow's.
    PortUnresponsive,
    /// The process had no socket to give one of the flow's exchanges for as
    /// long as the flow's time allowed, so a question went unasked. The
    /// shortfall is this machine's, neither the port's nor the flow's budget,
    /// and raising the process's descriptor limit is its remedy.
    Starved,
}

/// The ceilings a flow runs under, the ones it declared and this runtime's
/// defaults for the ones it left open.
struct Limits {
    millis: u64,
    bytes: u64,
    connections: u64,
}

impl Limits {
    fn of(capabilities: &CapabilitySpec) -> Self {
        Self {
            millis: capabilities
                .max_millis
                .map_or(DEFAULT_MAX_MILLIS, u64::from),
            bytes: capabilities.max_bytes.map_or(DEFAULT_MAX_BYTES, u64::from),
            connections: capabilities
                .max_connections
                .map_or(u64::from(DEFAULT_MAX_CONNECTIONS), u64::from),
        }
    }

    /// The ceiling `refusal` names, or [`None`] for a refusal that is not one
    /// of the flow's budgets.
    fn of_refusal(&self, refusal: ProbeRefusal) -> Option<u64> {
        match refusal {
            ProbeRefusal::Deadline => Some(self.millis),
            ProbeRefusal::Bytes => Some(self.bytes),
            ProbeRefusal::Connections => Some(self.connections),
            ProbeRefusal::Descriptors => None,
        }
    }
}

/// How many requests `flow` makes when every step runs, which is the number a
/// reader weighs a shortfall against: what the flow set out to ask. A guard
/// that would have skipped a step the budget already stopped is not something
/// the run can know. See [`exchanges`](super::interp::exchanges).
fn requests(flow: &FlowDetection) -> u32 {
    super::interp::exchanges(flow)
}

/// What the flows run against one port share: the replies it has given, and
/// how it has behaved under them.
#[derive(Default)]
struct PortShare {
    /// Replies read to a clean end, by the request that drew them. See
    /// [`CachingProbe`].
    cache: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    /// Exchanges that held the port to themselves and still ran past the
    /// dead-wait mark, so the flows that follow can stop paying for them. See
    /// [`DEAD_PORT_STRIKES`].
    strikes: AtomicU32,
    /// Exchanges on the socket right now, from any of the port's flows.
    in_flight: AtomicU32,
    /// Exchanges ever begun on the socket, so one that ends can tell whether
    /// another began and finished while it waited.
    begun: AtomicU64,
}

/// A [`Probe`] that shares one port's replies across the flows run against it.
///
/// Many flows gate onto the same HTTP port and send the same bytes, most often a
/// bare `GET /`, and without this each would open its own connection for an
/// identical answer. This wraps the port's real probe and a cache the whole port
/// shares: a request already answered is served from the cache, and only a
/// request not seen before reaches the socket.
///
/// The reuse is exact, not approximate. Only a reply read to a clean close is
/// cached, so nothing a budget cut short is ever replayed, and a cached reply is
/// served only when it fits within `budget`, the flow's own `max_bytes`. A reply
/// that fits is the whole of what the port sent, which is byte-for-byte what a
/// fresh fetch under a budget that large would have read, so a cached hit and a
/// real fetch are indistinguishable to the flow. A reply larger than this flow's
/// budget is not served: that flow fetches its own, which its smaller budget
/// truncates exactly as it would have without the cache.
///
/// The wrapper also cuts a port loose once it has proven unresponsive. A port that
/// takes a probe's connection but then answers slowly or not at all holds the flow
/// until its whole time budget is spent, and a port that does this to
/// [`DEAD_PORT_STRIKES`] fresh exchanges will do it to every detection that gates
/// onto it. After that many the wrapper stops opening new sockets: a request already
/// cached is still served, and a request not seen before yields nothing rather than
/// another dead wait. On an HTTP port this is the difference between one slow host
/// and that host multiplied across the dozens of flows a web port attracts.
///
/// A wait counts toward that only when the exchange had the port to itself. One
/// that shared it with other flows' exchanges waited behind them as well as on
/// the port, and a port that answers one request at a time is slow in company
/// and prompt alone: it is live, and writing it off for the queue the scan
/// itself built would leave its detections unasked. The stage narrows such a
/// port instead. See [`detect_port`].
///
/// Nothing the cut leaves unasked goes unsaid. A flow the port left short, by
/// stalling it or by being given up on before its questions reached the socket,
/// reports a [`Stopped::PortUnresponsive`] shortfall rather than the budget
/// refusal its stalled wait would otherwise read as.
struct CachingProbe<'a> {
    inner: Box<dyn Probe>,
    port: &'a PortShare,
    /// How long a fresh exchange may run before it counts as a dead wait, three
    /// quarters of the flow's time budget. A real reply lands well inside this; a
    /// port that holds the socket to its read timeout does not.
    dead_after: Duration,
    /// Whether one of this flow's exchanges ran past `dead_after`, alone or in
    /// company.
    stalled: bool,
    /// Whether one of this flow's exchanges ran past `dead_after` with the port
    /// to itself, and so counted a strike against it.
    struck: bool,
    /// Whether one of this flow's exchanges shared the socket with another's.
    crowded: bool,
    /// Whether a request of this flow's went unasked because the port had
    /// already been given up on.
    written_off: bool,
    budget: u64,
    /// The first budget that refused one of this flow's requests.
    ///
    /// Kept from the first rather than read off the last exchange, because a
    /// refused request is a question left unasked whatever the flow does
    /// next: a flow whose large request the byte budget turned away and whose
    /// smaller one then fitted still left the first unanswered.
    refused: Option<ProbeRefusal>,
    /// Whether one of this flow's exchanges was refused a socket, whichever
    /// refusal came first.
    starved: bool,
    /// How many of this flow's requests drew a reply, from the socket or the
    /// cache, which is how far a flow a budget stopped had got.
    answered: u32,
    /// Whether the reply the last `speak` returned was read to a clean end,
    /// wherever it came from. See [`Probe::reply_complete`].
    last_complete: bool,
}

impl<'a> CachingProbe<'a> {
    /// A flow's view of the port: its own probe, what the port's flows share,
    /// and the two figures from its budget this wrapper reads.
    fn new(inner: Box<dyn Probe>, port: &'a PortShare, dead_after: Duration, budget: u64) -> Self {
        Self {
            inner,
            port,
            dead_after,
            stalled: false,
            struck: false,
            crowded: false,
            written_off: false,
            budget,
            refused: None,
            starved: false,
            answered: 0,
            last_complete: false,
        }
    }

    /// What left this flow short of what it set out to ask, or [`None`] when
    /// nothing did. The process is to blame when it had no socket for one of
    /// the flow's exchanges, whatever else happened, since that is the one
    /// shortfall with a remedy outside the target. The port is to blame when
    /// it was given up on before one of the flow's questions, or when it
    /// stalled this flow alone and the flow then ran out of budget on it; the
    /// flow's own budget otherwise.
    fn stopped(&self, limits: &Limits) -> Option<Stopped> {
        if self.starved {
            return Some(Stopped::Starved);
        }
        if self.written_off || (self.struck && self.refused.is_some()) {
            return Some(Stopped::PortUnresponsive);
        }
        let refusal = self.refused?;
        Some(match limits.of_refusal(refusal) {
            Some(limit) => Stopped::Budget { refusal, limit },
            None => Stopped::Starved,
        })
    }

    /// Whether the port was slow to this flow: an exchange ran past the
    /// dead-wait mark, or the flow's clock ran out before its questions did.
    /// Either says the port did not keep pace with what it was being asked.
    fn slow(&self) -> bool {
        self.stalled || self.refused == Some(ProbeRefusal::Deadline)
    }
}

/// How many dead exchanges a port may cost before its remaining flows stop opening
/// sockets to it and read only from the shared cache. A live service answers a
/// simple request in milliseconds, so holding one exchange past three quarters of a
/// detection's whole budget, with nothing else of the scan's asking it anything, is
/// already aberrant; two is the port, not the network, and the rest of its flows
/// are spared the same wait.
///
/// Only an exchange that had the port to itself counts, so the strikes land on
/// the stage's serial path, where each is seen before the next flow opens a
/// socket and a silent port costs two dead exchanges. The flows already running
/// when the stage narrowed a wide port finish their own waits first, a bound of
/// [`DETECTION_FLOW_CONCURRENCY`] more, which is far below the dozens of flows a
/// web port attracts.
const DEAD_PORT_STRIKES: u32 = 2;

impl Probe for CachingProbe<'_> {
    fn speak(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
        self.last_complete = false;
        {
            let cache = self
                .port
                .cache
                .lock()
                .unwrap_or_else(|held| held.into_inner());
            if let Some(reply) = cache.get(bytes)
                && reply.len() as u64 <= self.budget
            {
                self.answered += 1;
                // Only a whole reply is ever cached, so one served from the
                // cache is whole, whatever this flow's own last fetch was.
                self.last_complete = true;
                return Some(reply.clone());
            }
        }
        if self.port.strikes.load(Ordering::Relaxed) >= DEAD_PORT_STRIKES {
            self.written_off = true;
            return None;
        }

        // Alone means no exchange was in flight when this one began and none
        // began before it ended: the whole wait was the port's.
        let company = self.port.in_flight.fetch_add(1, Ordering::SeqCst);
        let ticket = self.port.begun.fetch_add(1, Ordering::SeqCst);
        let started = Instant::now();
        let reply = self.inner.speak(bytes);
        let elapsed = started.elapsed();
        let alone = company == 0 && self.port.begun.load(Ordering::SeqCst) == ticket + 1;
        self.port.in_flight.fetch_sub(1, Ordering::SeqCst);

        self.crowded |= !alone;
        if elapsed >= self.dead_after {
            self.stalled = true;
            if alone {
                self.struck = true;
                self.port.strikes.fetch_add(1, Ordering::Relaxed);
            }
        }
        let Some(reply) = reply else {
            let refusal = self.inner.last_refusal();
            self.starved |= refusal == Some(ProbeRefusal::Descriptors);
            self.refused = self.refused.or(refusal);
            return None;
        };
        self.answered += 1;
        self.last_complete = self.inner.reply_complete();
        if self.last_complete {
            self.port
                .cache
                .lock()
                .unwrap_or_else(|held| held.into_inner())
                .entry(bytes.to_vec())
                .or_insert_with(|| reply.clone());
        }
        Some(reply)
    }

    fn reply_complete(&self) -> bool {
        self.last_complete
    }

    fn plan(&mut self, exchanges: u32) {
        self.inner.plan(exchanges);
    }
}

/// Whether any enabled flow in `corpus` gates onto a port with these facts, so a
/// caller can skip opening a socket to a port no flow would probe.
pub(crate) fn interested(
    corpus: &FlowDb,
    envelope: &DetectionEnvelope,
    service: Option<&str>,
    number: u16,
    protocol: Protocol,
) -> bool {
    corpus.flows().any(|flow| {
        let manifest = &flow.flow().detection;
        enabled(manifest.capabilities.class, envelope)
            && manifest.when.applies(service, number, protocol)
    })
}

/// Whether `envelope` permits a flow of this class to run. The class is the
/// flow's declared intrusiveness; the envelope is the operator's grant.
fn enabled(class: Class, envelope: &DetectionEnvelope) -> bool {
    envelope.permits(class.into_model())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::finding::DetectionClass;
    use crate::model::port::Service;
    use std::net::{IpAddr, Ipv4Addr};

    /// The default grant: what the scan already gathered, and nothing that opens
    /// a connection of its own.
    fn default_envelope() -> DetectionEnvelope {
        DetectionEnvelope::default()
    }

    /// The grant a `-d` scan runs under, which is what a flow needs: every flow
    /// speaks, so a test about one running names this rather than the default.
    fn benign_envelope() -> DetectionEnvelope {
        DetectionEnvelope::up_to(Class::ActiveBenign.into_model())
    }

    /// A socket that answers every send with one canned reply.
    struct Canned(&'static [u8]);
    impl Probe for Canned {
        fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
            Some(self.0.to_vec())
        }
    }

    fn host_with(port: Port) -> Host {
        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        host.add_port(port);
        host
    }

    fn open(number: u16, protocol: Protocol, service: &str) -> Port {
        Port::new(number, protocol, PortState::Open).with_service(Service::new(service, 100))
    }

    #[test]
    fn a_matching_flow_runs_and_records_its_finding_on_the_port() {
        let mut host = host_with(open(6379, Protocol::Tcp, "redis"));

        run_flows(&mut host, FlowDb::global(), &benign_envelope(), |_port| {
            Some(Box::new(Canned(b"# Server\r\nredis_version:7.2.4")))
        });

        let port = host.ports().find(|port| port.number() == 6379).unwrap();
        let findings: Vec<_> = port.findings().collect();
        assert_eq!(findings.len(), 1, "the redis flow fired");
        assert_eq!(findings[0].detection().id(), "redis-unauth-access");
        // Its provenance is the flow's real content hash, not an empty one.
        assert_eq!(findings[0].detection().content_hash().len(), 64);
    }

    #[test]
    fn the_envelope_decides_which_classes_run() {
        // The default reads what the scan gathered and withholds everything that
        // would open a connection of its own.
        let default = default_envelope();
        assert!(enabled(Class::Passive, &default));
        assert!(!enabled(Class::ActiveBenign, &default));
        assert!(!enabled(Class::ActiveMutating, &default));
        assert!(!enabled(Class::Exploit, &default));
        assert!(!enabled(Class::Dos, &default));

        // Raising the ceiling opens a class the default withheld.
        let permissive = DetectionEnvelope::up_to(DetectionClass::Exploit);
        assert!(enabled(Class::Exploit, &permissive));
    }

    #[test]
    fn a_flow_is_skipped_when_its_gate_or_the_port_does_not_fit() {
        // Wrong service: the redis flow's `when.service = "redis"` does not fit an
        // http port, so nothing fires even though the socket would answer.
        let mut http = host_with(open(6379, Protocol::Tcp, "http"));
        run_flows(&mut http, FlowDb::global(), &benign_envelope(), |_| {
            Some(Box::new(Canned(b"# Server\r\nredis_version:7.2.4")))
        });
        let port = http.ports().find(|port| port.number() == 6379).unwrap();
        assert_eq!(port.findings().count(), 0, "the service gate did not match");

        // A closed port is never probed, whatever runs on it.
        let mut closed = host_with(
            Port::new(6379, Protocol::Tcp, PortState::Closed)
                .with_service(Service::new("redis", 100)),
        );
        run_flows(&mut closed, FlowDb::global(), &benign_envelope(), |_| {
            Some(Box::new(Canned(b"# Server\r\nredis_version:7.2.4")))
        });
        let port = closed.ports().find(|port| port.number() == 6379).unwrap();
        assert_eq!(port.findings().count(), 0, "a closed port was probed");
    }

    #[test]
    fn an_intrusive_flow_does_not_run_under_the_default_policy() {
        use crate::detect::flow::db::CompiledFlow;
        use crate::detect::flow::schema::FlowDetection;

        // A flow whose class is off by default. Even on a matching port answering
        // just what its `expect` wants, the stage must refuse to run it.
        let source = r#"
            [detection]
            id      = "dangerous"
            version = "1.0.0"
            title   = "Dangerous"
            [detection.when]
            service = "redis"
            [detection.capabilities]
            class = "exploit"
            speak = "target"
            [[step]]
            send   = "ATTACK"
            expect = "ok"
            [[step.finding]]
            when     = "matched"
            severity = "critical"
            summary  = "the exploit fired"
        "#;
        let flow: FlowDetection = toml::from_str(source).expect("a valid flow");
        let corpus = FlowDb::from_flows(vec![CompiledFlow::from_parts(flow, "0".repeat(64))]);

        // Under the default envelope the exploit is withheld.
        let mut host = host_with(open(6379, Protocol::Tcp, "redis"));
        run_flows(&mut host, &corpus, &default_envelope(), |_| {
            Some(Box::new(Canned(b"ok")))
        });
        let port = host.ports().find(|port| port.number() == 6379).unwrap();
        assert_eq!(
            port.findings().count(),
            0,
            "an exploit-class flow ran under the default envelope"
        );

        // Raise the ceiling to exploit and the same flow now runs.
        let mut opened = host_with(open(6379, Protocol::Tcp, "redis"));
        let permissive = DetectionEnvelope::up_to(DetectionClass::Exploit);
        run_flows(&mut opened, &corpus, &permissive, |_| {
            Some(Box::new(Canned(b"ok")))
        });
        let port = opened.ports().find(|port| port.number() == 6379).unwrap();
        assert_eq!(
            port.findings().count(),
            1,
            "an exploit the operator opted into did not run"
        );
    }

    #[test]
    fn a_flow_whose_budget_cuts_it_short_is_returned_as_a_refusal() {
        // A probe that refuses every exchange on its byte budget, standing in for a
        // flow cut short. detect_port must return the refusal, not swallow it into a
        // silent empty result the way a quiet port would leave.
        struct Refusing;
        impl Probe for Refusing {
            fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
                None
            }
            fn last_refusal(&self) -> Option<ProbeRefusal> {
                Some(ProbeRefusal::Bytes)
            }
        }

        let (findings, refusals) = detect_port(
            FlowDb::global(),
            &benign_envelope(),
            "192.0.2.10",
            Some("redis"),
            6379,
            Protocol::Tcp,
            |_caps| Some(Box::new(Refusing)),
        );

        assert!(findings.is_empty(), "a refused flow drew no finding");
        assert!(
            refusals
                .iter()
                .any(|shortfall| shortfall.detection == "redis-unauth-access"
                    && matches!(
                        shortfall.stopped,
                        Stopped::Budget {
                            refusal: ProbeRefusal::Bytes,
                            ..
                        }
                    )),
            "the budget refusal was not surfaced: {refusals:?}"
        );
    }

    /// A flow the process had no socket for is reported as starved, not as a
    /// quiet port and not as a budget of its own: a question went unasked for
    /// a reason outside both the target and the detection. Starved wins over
    /// a budget refusal that came first, since it is the one with a remedy the
    /// operator holds.
    #[test]
    fn a_flow_refused_a_socket_is_reported_as_starved_whatever_came_first() {
        struct Starving {
            asked: u32,
        }
        impl Probe for Starving {
            fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
                self.asked += 1;
                None
            }
            fn last_refusal(&self) -> Option<ProbeRefusal> {
                match self.asked {
                    1 => Some(ProbeRefusal::Bytes),
                    _ => Some(ProbeRefusal::Descriptors),
                }
            }
        }
        let port = PortShare::default();
        let limits = Limits {
            millis: 1_000,
            bytes: 1_000,
            connections: 4,
        };
        let mut probe = CachingProbe::new(
            Box::new(Starving { asked: 0 }),
            &port,
            Duration::from_millis(750),
            1_000,
        );
        assert_eq!(probe.speak(b"first"), None);
        assert_eq!(probe.speak(b"second"), None);

        assert_eq!(probe.stopped(&limits), Some(Stopped::Starved));
        assert!(!probe.slow(), "a starved flow says nothing about the port");
    }

    /// A request a budget turned away is a question the flow did not get
    /// answered, even when a later, smaller one fitted and the flow ended on a
    /// reply. What the stage reports is the first refusal and how far the flow
    /// got, not whatever its last exchange happened to do.
    #[test]
    fn a_flow_refused_partway_is_reported_even_when_its_last_request_was_answered() {
        use crate::detect::flow::db::CompiledFlow;

        /// Turns the first request away on its byte budget and answers the
        /// rest, as a probe whose budget one large reply had nearly spent does.
        struct RefusesFirst {
            calls: u32,
            refused: Option<ProbeRefusal>,
        }
        impl Probe for RefusesFirst {
            fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
                self.calls += 1;
                if self.calls == 1 {
                    self.refused = Some(ProbeRefusal::Bytes);
                    return None;
                }
                self.refused = None;
                Some(b"no".to_vec())
            }
            fn last_refusal(&self) -> Option<ProbeRefusal> {
                self.refused
            }
        }

        let source = r#"
            [detection]
            id      = "three-questions"
            version = "1.0.0"
            title   = "Three questions"
            [detection.when]
            service = "redis"
            [detection.capabilities]
            class = "active-benign"
            speak = "target"
            max_bytes = 512
            [[step]]
            for_each    = { var = "q", in = ["first", "second", "third"] }
            on_no_match = "continue"
            send        = "{q}"
            expect      = "yes"
        "#;
        let flow: FlowDetection = toml::from_str(source).expect("a valid flow");
        let corpus = FlowDb::from_flows(vec![CompiledFlow::from_parts(flow, "0".repeat(64))]);

        let (_, shortfalls) = detect_port(
            &corpus,
            &benign_envelope(),
            "192.0.2.10",
            Some("redis"),
            6379,
            Protocol::Tcp,
            |_caps| {
                Some(Box::new(RefusesFirst {
                    calls: 0,
                    refused: None,
                }))
            },
        );

        assert_eq!(
            shortfalls,
            vec![Shortfall {
                detection: "three-questions".to_string(),
                stopped: Stopped::Budget {
                    refusal: ProbeRefusal::Bytes,
                    limit: 512,
                },
                answered: 2,
                requests: 3,
            }],
            "the refused first question was lost behind the answered last one"
        );
    }

    /// The count of exchanges a flow plans reaches the port's own probe through
    /// the cache that wraps it. A probe told nothing gives its first unanswered
    /// datagram the whole of the flow's time, so a wrapper that swallowed the
    /// plan would bring back the flow that never tries its second guess.
    #[test]
    fn a_flows_planned_exchanges_reach_the_probe_beneath_the_cache() {
        struct Planned(std::sync::Arc<Mutex<Vec<u32>>>);
        impl Probe for Planned {
            fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
                None
            }
            fn plan(&mut self, exchanges: u32) {
                self.0.lock().expect("uncontended").push(exchanges);
            }
        }

        let told = std::sync::Arc::new(Mutex::new(Vec::new()));
        detect_port(
            &four_question_flows(1, 2_000),
            &benign_envelope(),
            "192.0.2.10",
            Some("http"),
            80,
            Protocol::Tcp,
            |_caps| Some(Box::new(Planned(std::sync::Arc::clone(&told))) as Box<dyn Probe>),
        );

        assert_eq!(*told.lock().expect("uncontended"), vec![4]);
    }

    /// A probe that counts its socket exchanges, so a test can tell a cached hit
    /// from a real fetch, and can be told to answer with a complete reply or one
    /// a budget would have cut short.
    struct Counting {
        calls: std::sync::Arc<AtomicU32>,
        reply: Vec<u8>,
        complete: bool,
    }

    impl Probe for Counting {
        fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Some(self.reply.clone())
        }
        fn reply_complete(&self) -> bool {
            self.complete
        }
    }

    fn counting(reply: &[u8], complete: bool) -> (Box<Counting>, std::sync::Arc<AtomicU32>) {
        let calls = std::sync::Arc::new(AtomicU32::new(0));
        let probe = Box::new(Counting {
            calls: calls.clone(),
            reply: reply.to_vec(),
            complete,
        });
        (probe, calls)
    }

    #[test]
    fn a_complete_reply_is_served_from_the_cache_to_a_later_flow() {
        let request = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
        let port = PortShare::default();

        let (first, first_calls) = counting(b"the page", true);
        let (second, second_calls) = counting(b"never read", true);
        let mut a = CachingProbe::new(first, &port, Duration::from_millis(1500), 4096);
        let mut b = CachingProbe::new(second, &port, Duration::from_millis(1500), 4096);

        let from_a = a.speak(request);
        let from_b = b.speak(request);

        assert_eq!(from_a.as_deref(), Some(&b"the page"[..]));
        assert_eq!(from_b, from_a, "the second flow got the first flow's reply");
        assert_eq!(
            first_calls.load(Ordering::Relaxed),
            1,
            "the first flow did the one real fetch"
        );
        assert_eq!(
            second_calls.load(Ordering::Relaxed),
            0,
            "the second flow never touched the socket"
        );
    }

    /// What a flow's probe says about the completeness of a reply describes
    /// the reply it returned, whichever of the socket and the cache it came
    /// from. A cached reply is whole by construction, so after a hit the probe
    /// says so, even when its own last trip to the socket was cut short.
    #[test]
    fn a_reply_served_from_the_cache_is_reported_whole_after_a_truncated_fetch() {
        let port = PortShare::default();
        let (whole, _) = counting(b"the page", true);
        let mut first = CachingProbe::new(whole, &port, Duration::from_millis(1500), 4096);
        first.speak(b"GET / HTTP/1.1\r\n\r\n");

        let (cut, _) = counting(b"cut sho", false);
        let mut second = CachingProbe::new(cut, &port, Duration::from_millis(1500), 4096);
        second.speak(b"GET /big HTTP/1.1\r\n\r\n");
        assert!(
            !second.reply_complete(),
            "a truncated fetch was reported whole"
        );

        let served = second.speak(b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(served.as_deref(), Some(&b"the page"[..]));
        assert!(
            second.reply_complete(),
            "the cached reply was described by the truncated fetch before it"
        );
    }

    /// A request that drew nothing leaves no reply to call whole.
    #[test]
    fn an_unanswered_request_is_not_reported_whole() {
        struct Silent;
        impl Probe for Silent {
            fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
                None
            }
        }
        let port = PortShare::default();
        let mut probe =
            CachingProbe::new(Box::new(Silent), &port, Duration::from_millis(1500), 4096);
        assert!(probe.speak(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(!probe.reply_complete());
    }

    #[test]
    fn a_different_request_is_fetched_rather_than_served() {
        let port = PortShare::default();
        let (first, _) = counting(b"root", true);
        let (second, second_calls) = counting(b"login", true);
        let mut a = CachingProbe::new(first, &port, Duration::from_millis(1500), 4096);
        let mut b = CachingProbe::new(second, &port, Duration::from_millis(1500), 4096);

        a.speak(b"GET / HTTP/1.1\r\n\r\n");
        let from_b = b.speak(b"GET /login HTTP/1.1\r\n\r\n");

        assert_eq!(from_b.as_deref(), Some(&b"login"[..]));
        assert_eq!(
            second_calls.load(Ordering::Relaxed),
            1,
            "a request not in the cache is fetched"
        );
    }

    #[test]
    fn a_reply_larger_than_a_flow_budget_is_not_shared() {
        let request = b"GET / HTTP/1.1\r\n\r\n";
        let port = PortShare::default();

        // The first flow reads a large page under a large budget and caches it.
        let (first, _) = counting(&[b'x'; 100], true);
        let mut a = CachingProbe::new(first, &port, Duration::from_millis(1500), 4096);
        a.speak(request);

        // A flow whose budget could not have read the whole page fetches its own,
        // which its budget truncates exactly as it would without the cache.
        let (second, second_calls) = counting(&[b'y'; 40], true);
        let mut b = CachingProbe::new(second, &port, Duration::from_millis(1500), 40);
        let from_b = b.speak(request);

        assert_eq!(
            second_calls.load(Ordering::Relaxed),
            1,
            "the oversized cache entry was not served"
        );
        assert_eq!(
            from_b,
            Some(vec![b'y'; 40]),
            "the flow got its own budgeted reply"
        );
    }

    #[test]
    fn an_incomplete_reply_is_never_cached() {
        let request = b"GET / HTTP/1.1\r\n\r\n";
        let port = PortShare::default();

        let (first, _) = counting(b"cut short", false);
        let mut a = CachingProbe::new(first, &port, Duration::from_millis(1500), 4096);
        a.speak(request);
        assert!(
            port.cache.lock().expect("uncontended in a test").is_empty(),
            "a reply cut short by a budget was not cached"
        );

        let (second, second_calls) = counting(b"cut short", false);
        let mut b = CachingProbe::new(second, &port, Duration::from_millis(1500), 4096);
        b.speak(request);
        assert_eq!(
            second_calls.load(Ordering::Relaxed),
            1,
            "with nothing cached the next flow fetched"
        );
    }

    /// A port's flows run several at a time, so the findings they draw come back
    /// out of order, and the run puts them back into the order the corpus holds.
    ///
    /// A scan is written down and read back: a report whose findings arrive in
    /// whatever order the threads happened to finish is one that cannot be diffed
    /// against the same scan run twice.
    #[test]
    fn findings_come_back_in_corpus_order_however_the_flows_finish() {
        use crate::detect::flow::db::CompiledFlow;
        use crate::detect::flow::schema::FlowDetection;

        // More flows than there are workers, so the run fills more than one round
        // and the last of them cannot simply finish last.
        let corpus = FlowDb::from_flows(
            (0..DETECTION_FLOW_CONCURRENCY * 3)
                .map(|n| {
                    let source = format!(
                        r#"
                        [detection]
                        id      = "ordered-{n:02}"
                        version = "1.0.0"
                        title   = "ordered {n:02}"
                        [detection.when]
                        service = "redis"
                        [detection.capabilities]
                        class = "active-benign"
                        [[step]]
                        send   = "PING"
                        expect = "ok"
                        [[step.finding]]
                        when     = "matched"
                        severity = "low"
                        summary  = "flow {n:02} fired"
                        "#
                    );
                    let flow: FlowDetection = toml::from_str(&source).expect("a valid flow");
                    CompiledFlow::from_parts(flow, "0".repeat(64))
                })
                .collect(),
        );

        // Each flow sleeps for a different slice of a millisecond, so a run that
        // reported findings as the threads finished would come back shuffled.
        let answered = std::sync::atomic::AtomicU64::new(0);
        let ordered = || {
            let (findings, _) = detect_port(
                &corpus,
                &benign_envelope(),
                "192.0.2.10",
                Some("redis"),
                6379,
                Protocol::Tcp,
                |_caps| {
                    let nth = answered.fetch_add(1, Ordering::Relaxed);
                    std::thread::sleep(Duration::from_micros((nth * 37) % 900));
                    Some(Box::new(Canned(b"ok")))
                },
            );
            findings
                .iter()
                .map(|finding| finding.detection().id().to_string())
                .collect::<Vec<_>>()
        };

        let first = ordered();
        assert_eq!(
            first.len(),
            DETECTION_FLOW_CONCURRENCY * 3,
            "every flow should have fired: {first:?}"
        );
        let mut sorted = first.clone();
        sorted.sort();
        assert_eq!(first, sorted, "the findings are not in corpus order");

        for _ in 0..4 {
            assert_eq!(ordered(), first, "the order moved between runs");
        }
    }

    /// A port that stalls on the first flow is not then asked eight questions at
    /// once.
    ///
    /// The strike count only saves anything if the flows that follow a dead wait
    /// can be spared it, and flows launched together are all already waiting when
    /// the first strike lands. So the widening waits on one flow coming back
    /// clean, and a port that stalls stays on the serial path where the count
    /// does its work.
    #[test]
    fn a_stalling_port_is_not_widened_onto() {
        use crate::detect::flow::db::CompiledFlow;
        use crate::detect::flow::schema::FlowDetection;

        // Budgets in milliseconds rather than seconds, so a dead wait is a dead
        // wait at test speed: `dead_after` is three quarters of this.
        let corpus = FlowDb::from_flows(
            (0..DETECTION_FLOW_CONCURRENCY * 4)
                .map(|n| {
                    let source = format!(
                        r#"
                        [detection]
                        id      = "stalls-{n:02}"
                        version = "1.0.0"
                        title   = "stalls {n:02}"
                        [detection.when]
                        service = "redis"
                        [detection.capabilities]
                        class      = "active-benign"
                        max_millis = 40
                        [[step]]
                        send   = "PING"
                        expect = "ok"
                        "#
                    );
                    let flow: FlowDetection = toml::from_str(&source).expect("a valid flow");
                    CompiledFlow::from_parts(flow, "0".repeat(64))
                })
                .collect(),
        );

        // Every exchange holds past the dead-wait mark and answers nothing, which
        // is what a port that accepts a connection and then says nothing does.
        struct Stalling(std::sync::Arc<AtomicU32>);
        impl Probe for Stalling {
            fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
                self.0.fetch_add(1, Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(40));
                None
            }
        }

        let opened = std::sync::Arc::new(AtomicU32::new(0));
        let counted = std::sync::Arc::clone(&opened);
        detect_port(
            &corpus,
            &benign_envelope(),
            "192.0.2.10",
            Some("redis"),
            6379,
            Protocol::Tcp,
            move |_caps| Some(Box::new(Stalling(std::sync::Arc::clone(&counted))) as Box<dyn Probe>),
        );

        // The flow that earns each strike is the only flow that pays for it. A run
        // that widened first would have a worker already waiting for every one of
        // the eight it launched.
        let sockets = opened.load(Ordering::Relaxed);
        assert!(
            sockets <= DEAD_PORT_STRIKES + 1,
            "a stalling port was asked {sockets} times over, not {}",
            DEAD_PORT_STRIKES + 1
        );
    }

    /// A port served by one worker that takes its requests in turn, the way a
    /// small embedded web server or a single-threaded dev server does. Every
    /// exchange waits for the worker, so flows asked at once queue behind each
    /// other and each waits for all the requests ahead of it.
    struct OneWorker {
        worker: Mutex<()>,
        /// How long the worker takes over each request.
        service: Duration,
        /// Every request the worker served, in the order it served them.
        served: Mutex<Vec<String>>,
    }

    /// One flow's connection to a [`OneWorker`], holding the flow's clock the
    /// way the live socket probe does: a request still queued when the clock
    /// runs out is abandoned unserved and refused on the time budget.
    struct Queued {
        port: std::sync::Arc<OneWorker>,
        deadline: Instant,
        refused: Option<ProbeRefusal>,
    }

    impl Probe for Queued {
        fn speak(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
            self.refused = None;
            let _turn = self
                .port
                .worker
                .lock()
                .unwrap_or_else(|held| held.into_inner());
            if Instant::now() >= self.deadline {
                self.refused = Some(ProbeRefusal::Deadline);
                return None;
            }
            std::thread::sleep(self.port.service);
            self.port
                .served
                .lock()
                .unwrap_or_else(|held| held.into_inner())
                .push(String::from_utf8_lossy(bytes).into_owned());
            Some(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec())
        }
        fn last_refusal(&self) -> Option<ProbeRefusal> {
            self.refused
        }
    }

    /// `count` flows over one port, each asking four questions of its own and
    /// allowed `millis` for them.
    fn four_question_flows(count: usize, millis: u32) -> FlowDb {
        use crate::detect::flow::db::CompiledFlow;

        FlowDb::from_flows(
            (0..count)
                .map(|n| {
                    let source = format!(
                        r#"
                        [detection]
                        id      = "asks-{n:02}"
                        version = "1.0.0"
                        title   = "asks {n:02}"
                        [detection.when]
                        service = "http"
                        [detection.capabilities]
                        class      = "active-benign"
                        max_millis = {millis}
                        [[step]]
                        for_each    = {{ var = "q", in = ["a", "b", "c", "d"] }}
                        on_no_match = "continue"
                        send        = "GET /{n:02}/{{q}}"
                        expect      = "never"
                        "#
                    );
                    let flow: FlowDetection = toml::from_str(&source).expect("a valid flow");
                    CompiledFlow::from_parts(flow, "0".repeat(64))
                })
                .collect(),
        )
    }

    /// A port that answers every request, but one at a time, is asked every
    /// question its flows hold.
    ///
    /// Asked by several flows at once, such a port answers each of them only
    /// after everything queued ahead, so an exchange that takes a fraction of
    /// a flow's budget alone takes most of it in company. That wait is the
    /// scan's own doing, not the port's, and a port written off for it is a
    /// live service whose detections were silently never run. Asked one flow
    /// at a time, every question here is answered with its budget five times
    /// over.
    #[test]
    fn a_port_that_answers_one_request_at_a_time_is_asked_every_question() {
        let flows = 10;
        let corpus = four_question_flows(flows, 800);
        let port = std::sync::Arc::new(OneWorker {
            worker: Mutex::new(()),
            service: Duration::from_millis(40),
            served: Mutex::new(Vec::new()),
        });

        let (_, shortfalls) = detect_port(
            &corpus,
            &benign_envelope(),
            "192.0.2.10",
            Some("http"),
            80,
            Protocol::Tcp,
            |caps| {
                let millis = caps.max_millis.map_or(DEFAULT_MAX_MILLIS, u64::from);
                Some(Box::new(Queued {
                    port: std::sync::Arc::clone(&port),
                    deadline: Instant::now() + Duration::from_millis(millis),
                    refused: None,
                }) as Box<dyn Probe>)
            },
        );

        let served = port.served.lock().expect("uncontended after the run");
        let unasked: Vec<String> = (0..flows)
            .map(|n| format!("GET /{n:02}/"))
            .filter(|prefix| served.iter().filter(|r| r.starts_with(prefix)).count() < 4)
            .collect();
        assert!(
            unasked.is_empty(),
            "the worker never served every request of {unasked:?}; \
             shortfalls reported: {shortfalls:?}"
        );
        assert!(
            shortfalls.is_empty(),
            "a port that answered everything left shortfalls: {shortfalls:?}"
        );
    }

    #[test]
    fn a_port_that_never_answers_stops_being_probed() {
        struct Silent(std::sync::Arc<AtomicU32>);
        impl Probe for Silent {
            fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
                self.0.fetch_add(1, Ordering::Relaxed);
                None
            }
        }

        let port = PortShare::default();
        let calls = std::sync::Arc::new(AtomicU32::new(0));

        // Each flow over the port gets its own probe but shares the strike count,
        // as detect_port hands them out. Every probe answers nothing and, with a
        // dead_after of zero, does so only after the whole budget, the way a port
        // that accepts the connection and then stays silent holds a real socket.
        for n in 0..DEAD_PORT_STRIKES + 5 {
            let mut probe =
                CachingProbe::new(Box::new(Silent(calls.clone())), &port, Duration::ZERO, 4096);
            let request = format!("GET /{n} HTTP/1.1\r\n\r\n");
            assert!(probe.speak(request.as_bytes()).is_none());
        }

        assert_eq!(
            calls.load(Ordering::Relaxed),
            DEAD_PORT_STRIKES,
            "the socket was spared once the port had shown it will not answer"
        );
    }

    /// A flow the port stalled with nothing else waiting on it is reported
    /// as the port's shortfall, and one that merely outran its own budget as
    /// that budget's. Neither is dropped: both left a question unanswered, and
    /// a reader deciding whether to look again needs to know which it was.
    #[test]
    fn a_stalled_flow_is_reported_as_the_ports_shortfall_and_a_fast_refusal_as_its_budgets() {
        // A probe that gives nothing and always blames its own budget.
        struct Refuser;
        impl Probe for Refuser {
            fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
                None
            }
            fn last_refusal(&self) -> Option<ProbeRefusal> {
                Some(ProbeRefusal::Deadline)
            }
        }
        let limits = Limits {
            millis: 2_000,
            bytes: 4096,
            connections: 4,
        };

        // A fast refusal with no dead wait is the flow outrunning its own budget on
        // a port still answering.
        let port = PortShare::default();
        let mut live = CachingProbe::new(Box::new(Refuser), &port, Duration::from_secs(3600), 4096);
        live.speak(b"GET /a HTTP/1.1\r\n\r\n");
        assert!(!live.stalled);
        assert_eq!(
            live.stopped(&limits),
            Some(Stopped::Budget {
                refusal: ProbeRefusal::Deadline,
                limit: 2_000
            })
        );

        // The same refusal after a dead wait alone on the port is the port's
        // doing. A dead_after of zero makes the exchange count as having run the
        // clock out.
        let port = PortShare::default();
        let mut dead = CachingProbe::new(Box::new(Refuser), &port, Duration::ZERO, 4096);
        dead.speak(b"GET /b HTTP/1.1\r\n\r\n");
        assert!(dead.stalled);
        assert_eq!(dead.stopped(&limits), Some(Stopped::PortUnresponsive));

        // And a flow that came after the port was given up on, and so never had
        // its question sent, is the port's shortfall too.
        let (inner, calls) = counting(b"never read", true);
        let mut late = CachingProbe::new(inner, &port, Duration::ZERO, 4096);
        port.strikes.store(DEAD_PORT_STRIKES, Ordering::Relaxed);
        assert!(late.speak(b"GET /c HTTP/1.1\r\n\r\n").is_none());
        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "a written-off port was asked"
        );
        assert_eq!(late.stopped(&limits), Some(Stopped::PortUnresponsive));
    }

    /// A wait spent sharing the port with other flows' exchanges is not held
    /// against the port. It was the queue in front of the exchange as much as
    /// the port, and a port that answers one request at a time would otherwise
    /// be written off for the scan's own crowding.
    #[test]
    fn a_slow_exchange_in_company_is_not_a_strike() {
        /// Holds each exchange until every flow sharing the barrier has one in
        /// flight, so the two exchanges overlap whatever the scheduler does.
        struct Together(std::sync::Arc<std::sync::Barrier>);
        impl Probe for Together {
            fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
                self.0.wait();
                Some(b"late but here".to_vec())
            }
        }

        let port = PortShare::default();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let crowded: Vec<bool> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|n| {
                    let (port, barrier) = (&port, std::sync::Arc::clone(&barrier));
                    scope.spawn(move || {
                        // A dead_after of zero makes each exchange count as
                        // having run the clock out.
                        let mut probe = CachingProbe::new(
                            Box::new(Together(barrier)),
                            port,
                            Duration::ZERO,
                            4096,
                        );
                        probe.speak(format!("GET /{n} HTTP/1.1\r\n\r\n").as_bytes());
                        assert!(probe.stalled && probe.slow());
                        probe.crowded
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        });

        assert_eq!(crowded, vec![true, true], "the overlap went unnoticed");
        assert_eq!(
            port.strikes.load(Ordering::Relaxed),
            0,
            "a wait in company was counted against the port"
        );
    }

    /// A port that goes silent is given up on, and every flow it left without
    /// its answers says so. The cut saves the scan the dead waits; it must not
    /// also hide that the questions went unasked.
    #[test]
    fn every_flow_a_silent_port_left_unanswered_is_reported() {
        let flows = DETECTION_FLOW_CONCURRENCY * 2;
        let corpus = four_question_flows(flows, 40);

        struct Silent;
        impl Probe for Silent {
            fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
                std::thread::sleep(Duration::from_millis(40));
                None
            }
            fn last_refusal(&self) -> Option<ProbeRefusal> {
                Some(ProbeRefusal::Deadline)
            }
        }

        let (_, shortfalls) = detect_port(
            &corpus,
            &benign_envelope(),
            "192.0.2.10",
            Some("http"),
            80,
            Protocol::Tcp,
            |_caps| Some(Box::new(Silent) as Box<dyn Probe>),
        );

        let reported: Vec<&str> = shortfalls
            .iter()
            .filter(|shortfall| shortfall.stopped == Stopped::PortUnresponsive)
            .map(|shortfall| shortfall.detection.as_str())
            .collect();
        let expected: Vec<String> = (0..flows).map(|n| format!("asks-{n:02}")).collect();
        assert_eq!(
            reported, expected,
            "a flow the silent port left unanswered went unreported: {shortfalls:?}"
        );
    }

    #[test]
    fn a_port_that_answers_but_runs_out_the_clock_stops_being_probed() {
        let port = PortShare::default();

        // A dead_after of zero makes every exchange count as having run the clock
        // out, standing in for a port that dribbles a reply back only as its read
        // timeout expires. Such a reply is real but as slow as silence.
        for n in 0..DEAD_PORT_STRIKES + 5 {
            let (inner, calls) = counting(b"slow but complete", true);
            let mut probe = CachingProbe::new(inner, &port, Duration::ZERO, 4096);
            let request = format!("GET /{n} HTTP/1.1\r\n\r\n");
            probe.speak(request.as_bytes());
            let expected = if n < DEAD_PORT_STRIKES { 1 } else { 0 };
            assert_eq!(
                calls.load(Ordering::Relaxed),
                expected,
                "flow {n} {} touch the socket",
                if expected == 1 {
                    "should"
                } else {
                    "should not"
                }
            );
        }
    }
}
