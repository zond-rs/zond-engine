// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Running the flow corpus over a host
//!
//! The Tier-1 detection stage. For each open port, every flow the envelope
//! permits and whose `when` gate fits is run against it, and its findings are
//! recorded on the port.
//!
//! ## Reaching the port
//!
//! The caller supplies each flow's [`Probe`] per port, which is where the live
//! transport plugs in and what lets tests use a canned socket. A caller that
//! cannot reach a port returns [`None`], and the port is skipped.

// `run_flows` is used only by tests; the scanner drives `detect_port`.
#![allow(dead_code)]

use crate::config::DetectionEnvelope;
use crate::model::finding::Finding;
use crate::model::host::Host;
use crate::model::port::{Port, PortState, Protocol};

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::db::FlowDb;
use super::schema::FlowDetection;
use super::{FlowSeed, Probe, ProbeRefusal};
use crate::config::limits::DETECTION_FLOW_CONCURRENCY;
use crate::detect::contention::HostContention;
use crate::detect::manifest::{
    CapabilitySpec, Class, DEFAULT_MAX_BYTES, DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_MILLIS,
};
use crate::transport::dial::pacing::held_here;

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
    // One contention for the whole host; see `HostContention`.
    let contention = HostContention::default();
    // Collect first, then record: the two borrows cannot overlap.
    let mut hits: Vec<(u16, Protocol, Finding)> = Vec::new();
    for port in host.ports() {
        if port.state() != PortState::Open {
            continue;
        }
        let number = port.number();
        let protocol = port.protocol();
        let service = port.service().map(|service| service.name());
        // Shortfalls are discarded here; the scanner reports them.
        let (produced, _shortfalls) = detect_port(
            corpus,
            envelope,
            &host_addr,
            service,
            number,
            protocol,
            &contention,
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
/// or [`None`] to skip that flow. Holds no host and does no I/O of its own.
///
/// Also returns, in corpus order, a [`Shortfall`] for each flow that stopped
/// short of its questions, including one the port was given up on before it
/// could ask.
#[allow(clippy::too_many_arguments)]
pub(crate) fn detect_port(
    corpus: &FlowDb,
    envelope: &DetectionEnvelope,
    host: &str,
    service: Option<&str>,
    number: u16,
    protocol: Protocol,
    contention: &HostContention,
    probe_for: impl Fn(&CapabilitySpec) -> Option<Box<dyn Probe>> + Sync,
) -> (Vec<Finding>, Vec<Shortfall>) {
    // The applicable flows, settled first; the index restores corpus order later.
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

    // One seed for the port serves every flow.
    let seed = FlowSeed::new(host, number);
    // See `PortShare`.
    let port = PortShare::new(contention);

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

    // The first flow runs alone; the rest run concurrently only if the port was
    // not slow to it. Otherwise `DEAD_PORT_STRIKES` could not spare the later
    // flows: eight launched together would all be waiting when the first strike
    // landed.
    let mut runs: Vec<Run> = Vec::with_capacity(applicable.len());
    let first = run_one(0);
    let widen = first.as_ref().is_none_or(|run| !run.slow);
    runs.extend(first);

    let width = if widen {
        DETECTION_FLOW_CONCURRENCY.min(applicable.len() - 1)
    } else {
        1
    };

    // Flows to run serially, in corpus order: all the rest if not widened,
    // otherwise those the wide run left or must repeat.
    let mut alone: Vec<usize> = Vec::new();
    if width <= 1 {
        alone.extend(1..applicable.len());
    } else {
        // Stay wide only while the port keeps pace. Once a flow comes back slow
        // (a dead wait, or its clock ran out), no worker starts another flow and
        // the rest run serially below. A slow flow that shared the port is run
        // again alone, its complete answers served from the cache. A port
        // answering one request at a time is alive, so it is narrowed, not
        // struck.
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
    // Serially, so each strike is seen before the next flow opens a socket.
    runs.extend(alone.into_iter().filter_map(&run_one));

    // Back into corpus order, so repeated scans diff cleanly.
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
/// Only a flow that leaves the target as it found it: a repeated request that
/// changes the target may already have taken effect unheard. Other flows'
/// crowded runs stand as they came out.
fn repeatable(flow: &super::db::CompiledFlow) -> bool {
    matches!(
        flow.flow().detection.capabilities.class,
        Class::Derived | Class::Passive | Class::ActiveBenign
    )
}

/// A flow that stopped short of what it set out to ask: which flow, what
/// stopped it, and how far it had got.
///
/// Reported on its own: it is neither a clean run (its silence clears nothing)
/// nor a fault (a ceiling held, or the port stopped answering).
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
    /// The port stopped answering, with nothing else of the scan's waiting on
    /// it, and was given up on: this flow held one of the [`DEAD_PORT_STRIKES`]
    /// dead waits or came after them.
    PortUnresponsive,
    /// No socket was available for one of the flow's exchanges within its time.
    /// Raise the process's descriptor limit.
    Starved,
    /// The scan stopped, or the host's time ran out, while an exchange waited for
    /// its pacing slot.
    Withheld,
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
            ProbeRefusal::Descriptors | ProbeRefusal::Withheld => None,
        }
    }
}

/// How many requests `flow` makes when every step runs. See
/// [`exchanges`](super::interp::exchanges).
fn requests(flow: &FlowDetection) -> u32 {
    super::interp::exchanges(flow)
}

/// What the flows run against one port share: the replies it has given, and
/// the strikes it has drawn, over the host contention its exchanges join.
struct PortShare<'h> {
    /// Replies read to a clean end, by the request that drew them. See
    /// [`CachingProbe`].
    cache: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    /// Exchanges that had the host to themselves and still ran past the
    /// dead-wait mark. Per port; see [`DEAD_PORT_STRIKES`].
    strikes: AtomicU32,
    /// The host's exchanges, shared with its other ports. A slow exchange that
    /// overlapped another narrows the port instead of striking it, so a
    /// single-worker host's ports are asked in turn. See [`HostContention`].
    contention: &'h HostContention,
}

impl<'h> PortShare<'h> {
    /// A port's share over the host contention its exchanges join.
    fn new(contention: &'h HostContention) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            strikes: AtomicU32::new(0),
            contention,
        }
    }
}

/// A [`Probe`] that shares one port's replies across the flows run against it.
///
/// Many flows send the same bytes to one port (often a bare `GET /`). A request
/// already answered is served from a cache the port's flows share; only a new
/// request reaches the socket.
///
/// Only a reply read to a clean end is cached, and it is served only if it fits
/// within the flow's own `budget`, so a hit is byte-for-byte what a fresh fetch
/// would have read. A flow with a smaller budget fetches its own.
///
/// After [`DEAD_PORT_STRIKES`] exchanges that held the port alone past the
/// dead-wait mark, no new socket is opened: cached requests are still served,
/// new ones yield nothing. A wait shared with other exchanges does not count
/// (the stage narrows such a port; see [`detect_port`]), nor does a wait for a
/// socket the process could not give ([`Stopped::Starved`]).
///
/// A flow the port left short reports [`Stopped::PortUnresponsive`].
struct CachingProbe<'a> {
    inner: Box<dyn Probe>,
    port: &'a PortShare<'a>,
    /// How long a fresh exchange may run before it counts as a dead wait: three
    /// quarters of the flow's time budget.
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
    /// The first, since a refused request stays unasked whatever follows.
    refused: Option<ProbeRefusal>,
    /// Whether one of this flow's exchanges was refused a socket, whichever
    /// refusal came first.
    starved: bool,
    /// How many of this flow's requests drew a reply, from socket or cache.
    answered: u32,
    /// Whether the reply the last `speak` returned was read to a clean end,
    /// wherever it came from. See [`Probe::reply_complete`].
    last_complete: bool,
}

impl<'a> CachingProbe<'a> {
    /// A flow's view of the port: its own probe, what the port's flows share,
    /// and the two figures from its budget this wrapper reads.
    fn new(
        inner: Box<dyn Probe>,
        port: &'a PortShare<'a>,
        dead_after: Duration,
        budget: u64,
    ) -> Self {
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

    /// What left this flow short, or [`None`]. Starvation takes precedence, then
    /// the port (written off, or it stalled this flow alone before a budget ran
    /// out), then the flow's own budget.
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
            None if refusal == ProbeRefusal::Withheld => Stopped::Withheld,
            None => Stopped::Starved,
        })
    }

    /// Whether the port was slow to this flow: an exchange ran past the
    /// dead-wait mark, or the flow's clock ran out.
    fn slow(&self) -> bool {
        self.stalled || self.refused == Some(ProbeRefusal::Deadline)
    }
}

/// How many dead exchanges a port may cost before its remaining flows read only
/// from the shared cache. A live service answers in milliseconds, so two
/// exchanges held alone past three quarters of the budget mean the port is dead.
///
/// Strikes land on the serial path, so a silent port costs two dead exchanges,
/// plus at most [`DETECTION_FLOW_CONCURRENCY`] already running when a wide port
/// was narrowed.
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
                // Only whole replies are cached.
                self.last_complete = true;
                return Some(reply.clone());
            }
        }
        if self.port.strikes.load(Ordering::Relaxed) >= DEAD_PORT_STRIKES {
            self.written_off = true;
            return None;
        }

        // Alone: no other exchange overlapped this one.
        let visit = self.port.contention.enter();
        let started = Instant::now();
        let held = held_here();
        let reply = self.inner.speak(bytes);
        // Pacing waits are the scan's time, not the port's.
        let elapsed = started
            .elapsed()
            .saturating_sub(held_here().saturating_sub(held));
        let alone = visit.leave();

        self.crowded |= !alone;
        // An exchange refused a socket, or withheld by the scan, never reached
        // the port, so it is not a dead wait.
        let unasked = reply.is_none()
            && matches!(
                self.inner.last_refusal(),
                Some(ProbeRefusal::Descriptors | ProbeRefusal::Withheld)
            );
        let starved =
            reply.is_none() && self.inner.last_refusal() == Some(ProbeRefusal::Descriptors);
        if elapsed >= self.dead_after && !unasked {
            self.stalled = true;
            if alone {
                self.struck = true;
                self.port.strikes.fetch_add(1, Ordering::Relaxed);
            }
        }
        let Some(reply) = reply else {
            let refusal = self.inner.last_refusal();
            self.starved |= starved;
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

    fn reads_until(&mut self, pattern: Option<&str>) {
        self.inner.reads_until(pattern);
    }
}

/// Whether any enabled flow in `corpus` gates onto a port with these facts, so a
/// caller can skip opening a socket to a port no flow would probe.
///
/// `require_speak` limits the answer to flows that declare `speak`; see
/// [`interested_ports`](crate::scanner::detection).
pub(crate) fn interested(
    corpus: &FlowDb,
    envelope: &DetectionEnvelope,
    service: Option<&str>,
    number: u16,
    protocol: Protocol,
    require_speak: bool,
) -> bool {
    corpus.flows().any(|flow| {
        let manifest = &flow.flow().detection;
        enabled(manifest.capabilities.class, envelope)
            && (!require_speak || manifest.capabilities.speak.is_some())
            && manifest.when.applies(service, number, protocol)
    })
}

/// Whether `envelope` permits a flow of this class to run.
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

    /// Up to `active-benign`, which flows that speak need.
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
        // The flow's real content hash.
        assert_eq!(findings[0].detection().content_hash().len(), 64);
    }

    #[test]
    fn the_envelope_decides_which_classes_run() {
        // The default permits only passive classes.
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
        // Wrong service: the redis flow does not fit an http port.
        let mut http = host_with(open(6379, Protocol::Tcp, "http"));
        run_flows(&mut http, FlowDb::global(), &benign_envelope(), |_| {
            Some(Box::new(Canned(b"# Server\r\nredis_version:7.2.4")))
        });
        let port = http.ports().find(|port| port.number() == 6379).unwrap();
        assert_eq!(port.findings().count(), 0, "the service gate did not match");

        // A closed port is never probed.
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

        // A flow whose class is off by default does not run, even on a matching
        // port.
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
        // A probe refusing every exchange on its byte budget; the refusal must be
        // returned.
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
            &HostContention::default(),
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

    /// Starved is reported over a budget refusal that came first.
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
        let contention = HostContention::default();
        let port = PortShare::new(&contention);
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

    /// The first refusal is reported, even when a later request was answered.
    #[test]
    fn a_flow_refused_partway_is_reported_even_when_its_last_request_was_answered() {
        use crate::detect::flow::db::CompiledFlow;

        /// Refuses the first request on its byte budget and answers the rest.
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
            &HostContention::default(),
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

    /// The planned exchange count reaches the probe beneath the cache, which
    /// needs it to share the time between datagrams.
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
            &HostContention::default(),
            |_caps| Some(Box::new(Planned(std::sync::Arc::clone(&told))) as Box<dyn Probe>),
        );

        assert_eq!(*told.lock().expect("uncontended"), vec![4]);
    }

    /// A probe that counts its socket exchanges, answering with a complete or a
    /// truncated reply.
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
        let contention = HostContention::default();
        let port = PortShare::new(&contention);

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

    /// After a cache hit the reply is reported whole, even if the probe's own last
    /// fetch was truncated.
    #[test]
    fn a_reply_served_from_the_cache_is_reported_whole_after_a_truncated_fetch() {
        let contention = HostContention::default();
        let port = PortShare::new(&contention);
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
        let contention = HostContention::default();
        let port = PortShare::new(&contention);
        let mut probe =
            CachingProbe::new(Box::new(Silent), &port, Duration::from_millis(1500), 4096);
        assert!(probe.speak(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(!probe.reply_complete());
    }

    #[test]
    fn a_different_request_is_fetched_rather_than_served() {
        let contention = HostContention::default();
        let port = PortShare::new(&contention);
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
        let contention = HostContention::default();
        let port = PortShare::new(&contention);

        // A large page cached under a large budget.
        let (first, _) = counting(&[b'x'; 100], true);
        let mut a = CachingProbe::new(first, &port, Duration::from_millis(1500), 4096);
        a.speak(request);

        // A smaller budget fetches its own.
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
        let contention = HostContention::default();
        let port = PortShare::new(&contention);

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

    /// Concurrent flows' findings come back in corpus order.
    #[test]
    fn findings_come_back_in_corpus_order_however_the_flows_finish() {
        use crate::detect::flow::db::CompiledFlow;
        use crate::detect::flow::schema::FlowDetection;

        // More flows than workers.
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

        // Varied sleeps, so finishing order differs from corpus order.
        let answered = std::sync::atomic::AtomicU64::new(0);
        let ordered = || {
            let (findings, _) = detect_port(
                &corpus,
                &benign_envelope(),
                "192.0.2.10",
                Some("redis"),
                6379,
                Protocol::Tcp,
                &HostContention::default(),
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

    /// A port that stalls on the first flow stays on the serial path.
    #[test]
    fn a_stalling_port_is_not_widened_onto() {
        use crate::detect::flow::db::CompiledFlow;
        use crate::detect::flow::schema::FlowDetection;

        // Millisecond budgets; `dead_after` is three quarters of this.
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

        // Every exchange holds past the dead-wait mark and answers nothing.
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
            &HostContention::default(),
            move |_caps| Some(Box::new(Stalling(std::sync::Arc::clone(&counted))) as Box<dyn Probe>),
        );

        // Only the striking flows paid.
        let sockets = opened.load(Ordering::Relaxed);
        assert!(
            sockets <= DEAD_PORT_STRIKES + 1,
            "a stalling port was asked {sockets} times over, not {}",
            DEAD_PORT_STRIKES + 1
        );
    }

    /// A port served by one worker taking requests in turn, like a small
    /// embedded or single-threaded dev server.
    struct OneWorker {
        worker: Mutex<()>,
        /// How long the worker takes over each request.
        service: Duration,
        /// Every request the worker served, in the order it served them.
        served: Mutex<Vec<String>>,
    }

    /// One flow's connection to a [`OneWorker`]. A request still queued when the
    /// flow's clock runs out is refused on the time budget.
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
    /// In company each exchange waits behind the queue; asked one flow at a
    /// time, every question here is answered well within its budget.
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
            &HostContention::default(),
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

    /// A slow exchange on one of a host's ports that overlapped an exchange on
    /// another of them is crowded, not a strike against its port.
    ///
    /// Two ports whose exchanges overlap over one [`HostContention`] are not
    /// struck; the same wait alone on the host strikes.
    #[test]
    fn a_wait_behind_another_of_the_hosts_ports_is_crowded_not_a_strike() {
        // Answers once every exchange sharing its barrier is in flight. With a
        // dead_after of zero, whether an exchange strikes turns on company alone.
        struct Held(std::sync::Arc<std::sync::Barrier>);
        impl Probe for Held {
            fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
                self.0.wait();
                Some(b"ok".to_vec())
            }
        }

        // Two ports of one host, their exchanges overlapping.
        let contention = HostContention::default();
        let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
        let (port_a, port_b) = (PortShare::new(&contention), PortShare::new(&contention));
        let seen: Vec<(bool, bool, bool)> = std::thread::scope(|scope| {
            let handles: Vec<_> = [&port_a, &port_b]
                .into_iter()
                .map(|port| {
                    let gate = std::sync::Arc::clone(&gate);
                    scope.spawn(move || {
                        let mut probe =
                            CachingProbe::new(Box::new(Held(gate)), port, Duration::ZERO, 4096);
                        probe.speak(b"q");
                        (probe.stalled, probe.crowded, probe.struck)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        });
        assert_eq!(
            seen,
            vec![(true, true, false), (true, true, false)],
            "two overlapping exchanges on one host's ports were not both \
             stalled, crowded and unstruck (stalled, crowded, struck)"
        );
        assert_eq!(
            (
                port_a.strikes.load(Ordering::Relaxed),
                port_b.strikes.load(Ordering::Relaxed)
            ),
            (0, 0),
            "a wait behind another of the host's ports struck the port"
        );

        // The same wait, alone on the host, is the port's own and strikes it.
        let solo = HostContention::default();
        let port = PortShare::new(&solo);
        let gate = std::sync::Arc::new(std::sync::Barrier::new(1));
        let mut probe = CachingProbe::new(Box::new(Held(gate)), &port, Duration::ZERO, 4096);
        probe.speak(b"q");
        assert!(
            probe.struck && !probe.crowded,
            "a slow exchange alone on the host did not strike"
        );
        assert_eq!(port.strikes.load(Ordering::Relaxed), 1);
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

        let contention = HostContention::default();
        let port = PortShare::new(&contention);
        let calls = std::sync::Arc::new(AtomicU32::new(0));

        // Each flow gets its own probe over the shared strike count, as in
        // detect_port. With a dead_after of zero every silent exchange is dead.
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

    /// A flow the port stalled alone is reported as the port's shortfall, and
    /// one that outran its own budget as that budget's.
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

        // A fast refusal with no dead wait is the flow's budget.
        let contention = HostContention::default();
        let port = PortShare::new(&contention);
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

        // After a dead wait alone on the port (dead_after of zero), the port's.
        let contention = HostContention::default();
        let port = PortShare::new(&contention);
        let mut dead = CachingProbe::new(Box::new(Refuser), &port, Duration::ZERO, 4096);
        dead.speak(b"GET /b HTTP/1.1\r\n\r\n");
        assert!(dead.stalled);
        assert_eq!(dead.stopped(&limits), Some(Stopped::PortUnresponsive));

        // A flow after the port was given up on is the port's too.
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

    /// A wait spent sharing the port with other flows' exchanges is not a strike.
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

        let contention = HostContention::default();
        let port = PortShare::new(&contention);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let crowded: Vec<bool> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|n| {
                    let (port, barrier) = (&port, std::sync::Arc::clone(&barrier));
                    scope.spawn(move || {
                        // A dead_after of zero: every exchange is dead.
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
    /// its answers reports a shortfall.
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
            &HostContention::default(),
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

    /// A full descriptor table holds every exchange as long as a dead port does,
    /// but is not struck against the port.
    #[test]
    fn flows_a_full_file_table_starved_are_the_limits_shortfall_and_never_the_ports() {
        let flows = DETECTION_FLOW_CONCURRENCY * 2;
        let corpus = four_question_flows(flows, 40);

        /// Waits out the flow's time for a descriptor that never comes free,
        /// as an exchange does against a table filled from elsewhere.
        struct Starving;
        impl Probe for Starving {
            fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
                std::thread::sleep(Duration::from_millis(40));
                None
            }
            fn last_refusal(&self) -> Option<ProbeRefusal> {
                Some(ProbeRefusal::Descriptors)
            }
        }

        let (_, shortfalls) = detect_port(
            &corpus,
            &benign_envelope(),
            "192.0.2.10",
            Some("http"),
            80,
            Protocol::Tcp,
            &HostContention::default(),
            |_caps| Some(Box::new(Starving) as Box<dyn Probe>),
        );

        let stopped: Vec<(&str, Stopped)> = shortfalls
            .iter()
            .map(|shortfall| (shortfall.detection.as_str(), shortfall.stopped))
            .collect();
        let expected: Vec<(String, Stopped)> = (0..flows)
            .map(|n| (format!("asks-{n:02}"), Stopped::Starved))
            .collect();
        let expected: Vec<(&str, Stopped)> = expected
            .iter()
            .map(|(id, stopped)| (id.as_str(), *stopped))
            .collect();
        assert_eq!(stopped, expected, "a starved flow was blamed on the port");
    }

    #[test]
    fn a_port_that_answers_but_runs_out_the_clock_stops_being_probed() {
        let contention = HostContention::default();
        let port = PortShare::new(&contention);

        // A dead_after of zero stands in for a port that dribbles a reply back
        // only as its read timeout expires: real, but as slow as silence.
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
