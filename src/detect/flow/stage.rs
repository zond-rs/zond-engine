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
//! `active-benign` for now, the intrusive classes staying off until an operator
//! opts them in through an envelope. The [`Probe`] each flow
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
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::db::FlowDb;
use super::{FlowSeed, Probe, ProbeRefusal};
use crate::config::limits::DETECTION_FLOW_CONCURRENCY;
use crate::detect::manifest::{CapabilitySpec, Class, DEFAULT_MAX_BYTES, DEFAULT_MAX_MILLIS};

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
        // directly and surfaces the refusals this `.0` discards.
        let (produced, _refusals) = detect_port(
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
pub(crate) fn detect_port(
    corpus: &FlowDb,
    envelope: &DetectionEnvelope,
    host: &str,
    service: Option<&str>,
    number: u16,
    protocol: Protocol,
    probe_for: impl Fn(&CapabilitySpec) -> Option<Box<dyn Probe>> + Sync,
) -> (Vec<Finding>, Vec<(String, ProbeRefusal)>) {
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
    // One reply cache for the whole port. The many flows that gate onto an HTTP
    // port and send a byte-identical request, every one that opens with `GET /`,
    // share a single fetch instead of each opening its own connection. See
    // [`CachingProbe`].
    let cache = Mutex::new(HashMap::new());
    // A port that accepts a connection but then answers slowly or not at all costs
    // each flow its whole time budget for nothing. This counts those dead exchanges
    // across the port so the flows that follow can stop paying for them. See
    // [`CachingProbe`].
    let strikes = AtomicU32::new(0);

    let run_one = |index: usize| -> Option<Run> {
        let flow = applicable[index];
        let manifest = &flow.flow().detection;
        let inner = probe_for(&manifest.capabilities)?;
        let millis = manifest
            .capabilities
            .max_millis
            .map_or(DEFAULT_MAX_MILLIS, u64::from);
        let mut probe = CachingProbe {
            inner,
            cache: &cache,
            strikes: &strikes,
            stalled: false,
            dead_after: Duration::from_millis(millis / 4 * 3),
            budget: manifest
                .capabilities
                .max_bytes
                .map_or(DEFAULT_MAX_BYTES, u64::from),
        };
        let found = flow.run(&seed, &mut probe);
        // A flow that outran its own budget on a port still answering is recorded as
        // a coverage gap. One the probe withholds because a dead port stalled it is
        // not: that shortfall is the port's, the same as a clean run over a quiet one.
        let refusal = probe
            .last_refusal()
            .map(|refusal| (manifest.id.clone(), refusal));
        Some(Run {
            index,
            findings: found,
            refusal,
        })
    };

    // The first flow runs alone, and the rest widen out behind it only if that one
    // came back without stalling.
    //
    // Widening from the start defeats the very thing that makes a slow host
    // bearable. [`DEAD_PORT_STRIKES`] works because the flows that follow a dead
    // wait can be spared it, and eight flows launched together are all already
    // waiting when the first strike lands: a port that stalls costs eight dead
    // waits instead of two, and eight connections instead of two, for exactly the
    // wall clock it cost before. So the port answers one question first, and only
    // a port that answered is asked the rest at once.
    let mut runs: Vec<Run> = Vec::with_capacity(applicable.len());
    runs.extend(run_one(0));

    let widen = strikes.load(Ordering::Relaxed) == 0;
    let width = if widen {
        DETECTION_FLOW_CONCURRENCY.min(applicable.len() - 1)
    } else {
        1
    };

    if width <= 1 {
        // Serially, which is where the strike count does its work: each dead wait
        // is seen before the next flow decides whether to open a socket.
        runs.extend((1..applicable.len()).filter_map(&run_one));
    } else {
        let next = AtomicUsize::new(1);
        let done: Mutex<Vec<Run>> = Mutex::new(Vec::with_capacity(applicable.len()));
        std::thread::scope(|scope| {
            for _ in 0..width {
                scope.spawn(|| {
                    loop {
                        // Checked before a flow is taken up rather than only inside
                        // an exchange, so a port that went quiet partway through
                        // stops costing whole flows as well as whole exchanges.
                        if strikes.load(Ordering::Relaxed) >= DEAD_PORT_STRIKES {
                            break;
                        }
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        if index >= applicable.len() {
                            break;
                        }
                        if let Some(run) = run_one(index) {
                            done.lock()
                                .unwrap_or_else(|held| held.into_inner())
                                .push(run);
                        }
                    }
                });
            }
        });
        runs.extend(done.into_inner().unwrap_or_else(|held| held.into_inner()));
    }

    // Back into corpus order. A scan is written down and read back, and a report
    // whose findings are in whatever order the threads happened to finish is one
    // that cannot be diffed against the same scan run twice.
    runs.sort_by_key(|run| run.index);

    let mut findings = Vec::new();
    let mut refusals = Vec::new();
    for run in runs {
        findings.extend(run.findings);
        refusals.extend(run.refusal);
    }
    (findings, refusals)
}

/// What one flow left behind, carrying the position it holds in the corpus so a
/// run finished out of order can be put back into it.
struct Run {
    index: usize,
    findings: Vec<Finding>,
    refusal: Option<(String, ProbeRefusal)>,
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
/// A flow that hit a dead wait is also not reported as a coverage gap. When it runs
/// out of budget waiting on a silent port, the shortfall is the port's, not the
/// flow's, so its refusal is withheld. A flow that spends its budget on a port still
/// answering never stalls, so a genuine shortfall on a live port is still surfaced.
struct CachingProbe<'a> {
    inner: Box<dyn Probe>,
    cache: &'a Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    /// Fresh exchanges that answered nothing or ran out the clock, shared across
    /// the port's flows so one dead wait is not repeated by every one of them.
    strikes: &'a AtomicU32,
    /// How long a fresh exchange may run before it counts as a dead wait, three
    /// quarters of the flow's time budget. A real reply lands well inside this; a
    /// port that holds the socket to its read timeout does not.
    dead_after: Duration,
    /// Whether this flow itself hit a dead wait, so a refusal it then reports is the
    /// port's doing rather than the flow outrunning its own budget.
    stalled: bool,
    budget: u64,
}

/// How many dead exchanges a port may cost before its remaining flows stop opening
/// sockets to it and read only from the shared cache. A live service answers a
/// simple request in milliseconds, so holding one exchange past three quarters of a
/// detection's whole budget is already aberrant; two is the port, not the network,
/// and the rest of its flows are spared the same wait.
///
/// The count is a floor rather than an exact stop. The port's flows run
/// [`DETECTION_FLOW_CONCURRENCY`] at a time, so the ones already waiting when the
/// second strike lands still finish their own wait: a silent port costs that many
/// dead exchanges rather than two. It is bounded either way, and bounded by a
/// number far below the dozens of flows a web port attracts.
const DEAD_PORT_STRIKES: u32 = 2;

impl Probe for CachingProbe<'_> {
    fn speak(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
        {
            let cache = self.cache.lock().unwrap_or_else(|held| held.into_inner());
            if let Some(reply) = cache.get(bytes)
                && reply.len() as u64 <= self.budget
            {
                return Some(reply.clone());
            }
        }
        if self.strikes.load(Ordering::Relaxed) >= DEAD_PORT_STRIKES {
            return None;
        }
        let started = Instant::now();
        let reply = self.inner.speak(bytes);
        if started.elapsed() >= self.dead_after {
            self.strikes.fetch_add(1, Ordering::Relaxed);
            self.stalled = true;
        }
        let reply = reply?;
        if self.inner.reply_complete() {
            self.cache
                .lock()
                .unwrap_or_else(|held| held.into_inner())
                .entry(bytes.to_vec())
                .or_insert_with(|| reply.clone());
        }
        Some(reply)
    }

    fn reply_complete(&self) -> bool {
        self.inner.reply_complete()
    }

    fn last_refusal(&self) -> Option<ProbeRefusal> {
        if self.stalled {
            return None;
        }
        self.inner.last_refusal()
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
                .any(|(id, refusal)| id == "redis-unauth-access" && *refusal == ProbeRefusal::Bytes),
            "the budget refusal was not surfaced: {refusals:?}"
        );
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
        let cache = Mutex::new(HashMap::new());
        let strikes = AtomicU32::new(0);

        let (first, first_calls) = counting(b"the page", true);
        let (second, second_calls) = counting(b"never read", true);
        let mut a = CachingProbe {
            inner: first,
            cache: &cache,
            strikes: &strikes,
            stalled: false,
            dead_after: Duration::from_millis(1500),
            budget: 4096,
        };
        let mut b = CachingProbe {
            inner: second,
            cache: &cache,
            strikes: &strikes,
            stalled: false,
            dead_after: Duration::from_millis(1500),
            budget: 4096,
        };

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

    #[test]
    fn a_different_request_is_fetched_rather_than_served() {
        let cache = Mutex::new(HashMap::new());
        let strikes = AtomicU32::new(0);
        let (first, _) = counting(b"root", true);
        let (second, second_calls) = counting(b"login", true);
        let mut a = CachingProbe {
            inner: first,
            cache: &cache,
            strikes: &strikes,
            stalled: false,
            dead_after: Duration::from_millis(1500),
            budget: 4096,
        };
        let mut b = CachingProbe {
            inner: second,
            cache: &cache,
            strikes: &strikes,
            stalled: false,
            dead_after: Duration::from_millis(1500),
            budget: 4096,
        };

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
        let cache = Mutex::new(HashMap::new());
        let strikes = AtomicU32::new(0);

        // The first flow reads a large page under a large budget and caches it.
        let (first, _) = counting(&[b'x'; 100], true);
        let mut a = CachingProbe {
            inner: first,
            cache: &cache,
            strikes: &strikes,
            stalled: false,
            dead_after: Duration::from_millis(1500),
            budget: 4096,
        };
        a.speak(request);

        // A flow whose budget could not have read the whole page fetches its own,
        // which its budget truncates exactly as it would without the cache.
        let (second, second_calls) = counting(&[b'y'; 40], true);
        let mut b = CachingProbe {
            inner: second,
            cache: &cache,
            strikes: &strikes,
            stalled: false,
            dead_after: Duration::from_millis(1500),
            budget: 40,
        };
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
        let cache = Mutex::new(HashMap::new());
        let strikes = AtomicU32::new(0);

        let (first, _) = counting(b"cut short", false);
        let mut a = CachingProbe {
            inner: first,
            cache: &cache,
            strikes: &strikes,
            stalled: false,
            dead_after: Duration::from_millis(1500),
            budget: 4096,
        };
        a.speak(request);
        assert!(
            cache.lock().expect("uncontended in a test").is_empty(),
            "a reply cut short by a budget was not cached"
        );

        let (second, second_calls) = counting(b"cut short", false);
        let mut b = CachingProbe {
            inner: second,
            cache: &cache,
            strikes: &strikes,
            stalled: false,
            dead_after: Duration::from_millis(1500),
            budget: 4096,
        };
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

    #[test]
    fn a_port_that_never_answers_stops_being_probed() {
        struct Silent(std::sync::Arc<AtomicU32>);
        impl Probe for Silent {
            fn speak(&mut self, _bytes: &[u8]) -> Option<Vec<u8>> {
                self.0.fetch_add(1, Ordering::Relaxed);
                None
            }
        }

        let cache = Mutex::new(HashMap::new());
        let strikes = AtomicU32::new(0);
        let calls = std::sync::Arc::new(AtomicU32::new(0));

        // Each flow over the port gets its own probe but shares the strike count,
        // as detect_port hands them out. Every probe answers nothing and, with a
        // dead_after of zero, does so only after the whole budget, the way a port
        // that accepts the connection and then stays silent holds a real socket.
        for n in 0..DEAD_PORT_STRIKES + 5 {
            let mut probe = CachingProbe {
                inner: Box::new(Silent(calls.clone())),
                cache: &cache,
                strikes: &strikes,
                stalled: false,
                dead_after: Duration::ZERO,
                budget: 4096,
            };
            let request = format!("GET /{n} HTTP/1.1\r\n\r\n");
            assert!(probe.speak(request.as_bytes()).is_none());
        }

        assert_eq!(
            calls.load(Ordering::Relaxed),
            DEAD_PORT_STRIKES,
            "the socket was spared once the port had shown it will not answer"
        );
    }

    #[test]
    fn a_refusal_is_withheld_after_a_dead_wait_but_kept_otherwise() {
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

        let cache = Mutex::new(HashMap::new());

        // A fast refusal with no dead wait is the flow outrunning its own budget on
        // a port still answering, so it is reported.
        let strikes = AtomicU32::new(0);
        let mut live = CachingProbe {
            inner: Box::new(Refuser),
            cache: &cache,
            strikes: &strikes,
            stalled: false,
            dead_after: Duration::from_secs(3600),
            budget: 4096,
        };
        live.speak(b"GET /a HTTP/1.1\r\n\r\n");
        assert!(!live.stalled);
        assert_eq!(live.last_refusal(), Some(ProbeRefusal::Deadline));

        // The same refusal after a dead wait is the port's doing, so it is withheld.
        // A dead_after of zero makes the exchange count as having run the clock out.
        let strikes = AtomicU32::new(0);
        let mut dead = CachingProbe {
            inner: Box::new(Refuser),
            cache: &cache,
            strikes: &strikes,
            stalled: false,
            dead_after: Duration::ZERO,
            budget: 4096,
        };
        dead.speak(b"GET /b HTTP/1.1\r\n\r\n");
        assert!(dead.stalled);
        assert_eq!(dead.last_refusal(), None);
    }

    #[test]
    fn a_port_that_answers_but_runs_out_the_clock_stops_being_probed() {
        let cache = Mutex::new(HashMap::new());
        let strikes = AtomicU32::new(0);

        // A dead_after of zero makes every exchange count as having run the clock
        // out, standing in for a port that dribbles a reply back only as its read
        // timeout expires. Such a reply is real but as slow as silence.
        for n in 0..DEAD_PORT_STRIKES + 5 {
            let (inner, calls) = counting(b"slow but complete", true);
            let mut probe = CachingProbe {
                inner,
                cache: &cache,
                strikes: &strikes,
                stalled: false,
                dead_after: Duration::ZERO,
                budget: 4096,
            };
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
