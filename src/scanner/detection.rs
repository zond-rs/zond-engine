// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Detection phase
//!
//! Named apart from [`crate::detect`], which is the corpus itself. One is what
//! a detection *is*, the other is when it runs, and the two modules used to
//! have the same name.
//!
//! Runs the authored detection corpus, the Tier-1 [flows](crate::detect::flow)
//! and the Tier-2 [compute modules](crate::detect::compute), against the open
//! ports a scan has found and identified, recording a [`Finding`] wherever one
//! fires. It is the active counterpart to the [CVE correlator](crate::cve): the
//! correlator reads the service versions the scan gathered and joins them against
//! known vulnerabilities without touching the target, while this runs the corpus
//! over each port: a flow opening a fresh connection to decide, a module reading
//! the response the scan already drew or speaking its own.
//!
//! ## Compute modules over the same port
//!
//! Both tiers run on the blocking pool for each interested port. A compute module
//! is served through [`LiveCapabilities`], the same socket-backed budget a flow's
//! probe enforces, when it *speaks*, and reads the port's gathered responses when
//! it is *passive*. Those responses are what the pass that named the service
//! drew and [kept](crate::scanner::session) for this phase: the [service
//! phase](crate::scanner::service) after a raw scan, the [connect
//! scanner](crate::scanner::strategy::connect) inline while it still held the
//! stream. Either way a passive module adds no traffic of its own: it reads
//! what the scan already had.
//!
//! ## The socket a flow speaks through
//!
//! The flow interpreter is synchronous and interleaves I/O with its own logic (a
//! conditional step sends only after an earlier one matched), so it does not fit
//! the reactor's collect-then-analyse shape. It runs instead on the blocking pool
//! ([`spawn_blocking`](tokio::task::spawn_blocking)), where a blocking
//! [`SocketProbe`] serves its `speak`. The connection is to the scanned address,
//! as [service detection](crate::scanner::service) makes it, in the clear or
//! wrapped in TLS when the port answered inside a tunnel: the probe is bound to
//! the one port it was built for, so a flow can reach nothing else.
//!
//! ## What this module adds to the probe
//!
//! The probe belongs to [`detect::flow`](crate::detect::flow) and is public, so a
//! caller can run one detection against one port without a scan. What a scan
//! needs on top is the socket count: `Pooled` wraps the probe with one of the
//! phase's permits, held for the flow's whole run.
//!
//! The budget is the probe's own. A flow's declared `max_bytes`, `max_millis`
//! and `max_connections` become the [`Budget`] it is built with, and one that
//! declares none falls back to this runtime's default ceilings rather than to
//! no ceiling.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use crate::config::DetectionEnvelope;
use crate::config::ServiceDetection;
use crate::config::limits::CONNECT_CONCURRENCY;
use crate::detect::compute::stage as compute_stage;
use crate::detect::compute::{
    Budget, CapError, CapTapeRecord, Capabilities, DetectionRunRecord, LiveCapabilities,
    RunOutcome, ScanInstant,
};
use crate::detect::flow::{Probe, ProbeRefusal, SocketProbe, stage};
use crate::detect::host::stage as host_stage;
use crate::detect::manifest::{
    CapabilitySpec, DEFAULT_MAX_BYTES, DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_MILLIS,
};
use crate::fingerprint::{PortContext, Tunnel};
use crate::model::finding::Finding;
use crate::model::ip::scoped::ScopedIp;
use crate::model::port::{PortState, Protocol};
use crate::record::{DetectionIdRecord, wire};
use crate::report::ScannerKind;
use crate::scanner::pool::ProbePool;
use crate::scanner::session::{ScanContext, Tapes};

/// One port's detections as they travel off the blocking pool: the host key, the
/// port and protocol, the findings drawn, and the detections that did not finish
/// as `(id, reason)` pairs so the pool can record each as a failure.
type PortResult = (ScopedIp, u16, Protocol, Vec<Finding>, Vec<(String, String)>);

/// Runs the corpus against every open port a detection is interested in,
/// recording the findings it produces.
///
/// Gated on a service pass having run: a detection's `when` selects a port by its
/// service, so with nothing identified there is nothing to select, and the probes
/// are the same kind of active connection service detection already made.
/// `envelope` decides which detection classes the operator permits.
pub async fn detect(ctx: &ScanContext, detection: ServiceDetection, envelope: DetectionEnvelope) {
    if detection == ServiceDetection::Off {
        return;
    }

    // An envelope granting nothing is a scan that wants its ports and services
    // and no claims about them. Returned on here rather than left to the gates,
    // which would reach the same answer after walking every host's ports and
    // every detection in the corpus to establish that none of them may run.
    if envelope.ceiling().is_none() {
        return;
    }

    // Host-level detections correlate a host's ports into a Host finding. They read
    // only what the service phase already found, so they run independently of the
    // per-port pass below.
    detect_hosts(ctx);

    let targets = interested_ports(ctx, envelope);
    if targets.is_empty() {
        return;
    }

    // One budget for the phase, shared by every port in the pool and every flow
    // inside each. See [`Gate`].
    let gate = Arc::new(Gate::new(CONNECT_CONCURRENCY));

    let mut pool = ProbePool::new(
        CONNECT_CONCURRENCY,
        ctx.clone(),
        ScannerKind::Detection,
        |result: Option<PortResult>, _audit| {
            if let Some((key, number, protocol, findings, inconclusive)) = result {
                // A detection that trapped on a budget, faulted, or ran its socket
                // budget dry did not clear the port; record that it did not finish
                // so the report tells it apart from one that found nothing.
                for (id, reason) in &inconclusive {
                    ctx.record_failure(
                        ScannerKind::Detection,
                        format!("detection '{id}' on {key}:{number} {reason}"),
                    );
                }
                record(ctx, key, number, protocol, findings);
            }
        },
    );

    for target in targets {
        if ctx.handle.should_stop() {
            break;
        }
        // Nothing further is asked of a host that has spent its budget. A
        // detection is the most expensive thing this engine does to one port,
        // and a host already left early is the last place to spend it.
        if ctx.host_expired(target.address.addr()) {
            continue;
        }
        pool.admit(detect_one(
            target,
            ctx.detections.clone(),
            detection,
            envelope,
            Arc::clone(&ctx.tapes),
            Arc::clone(&gate),
        ))
        .await;
    }

    pool.drain().await;
}

/// One open port a detection would run over, lifted out of the store so the
/// exchanges that follow do not hold its lock. It carries the responses the service
/// phase gathered for a passive module to read.
struct PortTarget {
    address: ScopedIp,
    number: u16,
    protocol: Protocol,
    service: Option<String>,
    responses: Vec<String>,
}

/// Every open port some detection would run over, snapshotted so the store is not
/// borrowed across the exchanges that follow.
///
/// Pre-filtered by each tier's `interested` so a port no detection gates onto
/// costs nothing here rather than a blocking task that does nothing. The responses
/// are *taken* from the context, so they are freed as the snapshot is built rather
/// than held to the end of the scan.
fn interested_ports(ctx: &ScanContext, envelope: DetectionEnvelope) -> Vec<PortTarget> {
    let mut targets = Vec::new();
    for host in ctx.store.iter() {
        let address = host.value().scoped_ip();
        for port in host.value().ports() {
            if port.state() != PortState::Open {
                continue;
            }
            // No detection runs against an SCTP port. The scan holds no client
            // stack to speak over one, so an active detection is refused at the
            // seam, and an SCTP scan gathers no responses a passive one could read.
            // Skipping it here spares a blocking task both seams would only refuse.
            if port.protocol() == Protocol::Sctp {
                continue;
            }
            let number = port.number();
            let protocol = port.protocol();
            let service = port.service().map(|service| service.name().to_string());
            let wanted = stage::interested(
                ctx.detections.flows(),
                &envelope,
                service.as_deref(),
                number,
                protocol,
            ) || compute_stage::interested(
                ctx.detections.modules().detections(),
                &envelope,
                service.as_deref(),
                number,
                protocol,
            );
            if wanted {
                let responses = ctx.take_responses(&address, number, protocol);
                targets.push(PortTarget {
                    address: address.clone(),
                    number,
                    protocol,
                    service,
                    responses,
                });
            }
        }
    }
    targets
}

/// Runs one port's detections on the blocking pool and returns the findings, or
/// [`None`] if the port yielded nothing or has no reachable address.
async fn detect_one(
    target: PortTarget,
    detections: crate::detect::Detections,
    detection: ServiceDetection,
    envelope: DetectionEnvelope,
    tapes: Arc<Tapes>,
    gate: Arc<Gate>,
) -> Option<PortResult> {
    let PortTarget {
        address,
        number,
        protocol,
        service,
        responses,
    } = target;
    let addr = address.to_socket_addr(number)?;
    // The port's service label is the only record that it answered inside a
    // tunnel; both seams read it here so a detection speaks TLS to an `ssl/*`
    // service and plaintext to the rest. The address the flow reached seeds
    // `{host}` for a probe that has to name the endpoint it is talking to.
    let tunnel = service.as_deref().and_then(Tunnel::from_service_label);
    let host = addr.ip().to_string();

    // Both tiers are synchronous and hold a blocking socket, so they run off the
    // reactor. `spawn_blocking` fails only if the runtime is shutting down.
    let produced = tokio::task::spawn_blocking(move || {
        let flows = detections.flows();
        let modules = detections.modules();
        let (mut findings, flow_refusals) = stage::detect_port(
            flows,
            &envelope,
            &host,
            service.as_deref(),
            number,
            protocol,
            |caps| {
                Some(Box::new(Pooled {
                    inner: SocketProbe::new(addr, protocol, tunnel, &flow_budget(caps)),
                    _permit: gate.acquire(),
                }) as Box<dyn Probe>)
            },
        );

        // A passive module reads the gathered responses; an active one speaks
        // through a capability bound to this port, budgeted like a flow's probe.
        // The responses are kept for the run record so a replay feeds the same
        // input a passive detection read.
        let record_responses = responses.clone();
        let response_bytes: Vec<Vec<u8>> = responses.into_iter().map(String::into_bytes).collect();
        let response_slices: Vec<&[u8]> = response_bytes.iter().map(Vec::as_slice).collect();
        let port_context = PortContext {
            port: number,
            protocol,
            addr: Some(addr),
            tunnel,
            speaks_http: false,
            detection,
        };
        let computed = compute_stage::detect_port(
            modules.runtime(),
            modules.detections(),
            &envelope,
            service.as_deref(),
            &port_context,
            &response_slices,
            |grant| {
                // Acquire the permit before building `LiveCapabilities`, which
                // starts the flow's clock: the wait for a socket must not come
                // out of the flow's own time budget.
                let permit = gate.acquire();
                Some(Box::new(Permitted {
                    inner: LiveCapabilities::new(addr, protocol, tunnel, &grant.budget),
                    _permit: permit,
                }) as Box<dyn Capabilities>)
            },
            |grant, tape| {
                tapes.record(DetectionRunRecord {
                    host: addr.ip().to_string(),
                    port: number,
                    protocol: wire::protocol_name(protocol).to_string(),
                    detection: DetectionIdRecord::from(&grant.detection),
                    responses: record_responses.clone(),
                    tape: CapTapeRecord::from(&tape),
                });
            },
        );
        findings.extend(computed.findings);

        // Both tiers' inconclusive runs, phrased for the report: a compute run that
        // trapped or faulted, and a flow the socket budget cut short.
        let mut inconclusive: Vec<(String, String)> = computed
            .inconclusive
            .iter()
            .map(|run| {
                (
                    run.detection.id().to_string(),
                    describe_outcome(&run.outcome),
                )
            })
            .collect();
        inconclusive.extend(
            flow_refusals
                .into_iter()
                .map(|(id, refusal)| (id, describe_refusal(refusal))),
        );

        (findings, inconclusive)
    })
    .await
    .ok()?;

    let (findings, inconclusive) = produced;
    (!findings.is_empty() || !inconclusive.is_empty()).then_some((
        address,
        number,
        protocol,
        findings,
        inconclusive,
    ))
}

/// A human phrase for why a compute run did not finish, for the failure the report
/// carries. A reader needs which bound or fault ended the run, not the Rust
/// spelling of the outcome enum.
fn describe_outcome(outcome: &RunOutcome) -> String {
    match outcome {
        RunOutcome::BudgetExceeded(trap) => format!("hit its {trap:?} budget"),
        RunOutcome::Denied(denial) => {
            format!("was denied {:?}: {}", denial.capability, denial.reason)
        }
        RunOutcome::Faulted(fault) => format!("faulted: {fault:?}"),
        RunOutcome::HostReentered => "re-entered the runtime".to_string(),
    }
}

/// A human phrase for a socket budget that cut a flow short, for the failure the
/// report carries.
fn describe_refusal(refusal: ProbeRefusal) -> String {
    match refusal {
        ProbeRefusal::Bytes => "hit its byte budget",
        ProbeRefusal::Connections => "hit its connection budget",
        ProbeRefusal::Deadline => "hit its time budget",
    }
    .to_string()
}

/// Folds one port's findings back into its host.
fn record(
    ctx: &ScanContext,
    key: ScopedIp,
    number: u16,
    protocol: Protocol,
    findings: Vec<Finding>,
) {
    ctx.update_host(key, |host| {
        for finding in findings {
            host.add_port_finding(number, protocol, finding);
        }
    });
}

/// Runs the host-level detections over every host the scan found, drawing a Host
/// finding wherever a host's open ports and identified services fit a detection's
/// gate. It reads what the earlier phases recorded and sends nothing.
fn detect_hosts(ctx: &ScanContext) {
    let host_db = ctx.detections.hosts();
    if host_db.detections().is_empty() {
        return;
    }

    // Snapshot each host's open ports and service names first, so the store is not
    // borrowed while the findings are written back.
    let mut per_host: Vec<(ScopedIp, BTreeSet<u16>, Vec<String>)> = Vec::new();
    for host in ctx.store.iter() {
        let mut open_ports = BTreeSet::new();
        let mut services = Vec::new();
        for port in host.value().ports() {
            if port.state() == PortState::Open {
                open_ports.insert(port.number());
                if let Some(service) = port.service() {
                    services.push(service.name().to_string());
                }
            }
        }
        if !open_ports.is_empty() {
            per_host.push((host.value().scoped_ip(), open_ports, services));
        }
    }

    for (key, open_ports, service_names) in per_host {
        let services: BTreeSet<&str> = service_names.iter().map(String::as_str).collect();
        let findings = host_stage::detect_host(host_db.detections(), &open_ports, &services);
        if findings.is_empty() {
            continue;
        }
        ctx.update_host(key, |host| {
            for finding in findings {
                host.add_finding(finding);
            }
        });
    }
}

/// The socket budget the whole detection phase spends through.
///
/// A port's flows run several at a time now, and every port in the pool does the
/// same, so the two multiply: without a shared count a busy scan would open
/// [`CONNECT_CONCURRENCY`] ports times [`DETECTION_FLOW_CONCURRENCY`] flows at
/// once, hundreds of sockets against a ceiling written for fifty. This holds that
/// ceiling for the phase as a whole, so the concurrency is spent where the work
/// is: a host with four web ports gets most of the budget on those four, and a
/// scan with fifty ports in flight is bounded exactly as it was before.
///
/// A permit is taken when a flow's probe is built and given back when the probe
/// is dropped, which is the flow's whole run. Nothing here waits on a permit while
/// holding another, so the count cannot deadlock, and the wait happens before
/// [`SocketProbe::new`] starts the flow's clock rather than inside an exchange,
/// so queueing never counts against a detection's own time budget.
struct Gate {
    /// Permits still to be handed out.
    free: std::sync::Mutex<usize>,
    /// Woken as each is given back.
    returned: std::sync::Condvar,
}

impl Gate {
    /// A gate holding `permits` sockets.
    fn new(permits: usize) -> Self {
        Self {
            free: std::sync::Mutex::new(permits),
            returned: std::sync::Condvar::new(),
        }
    }

    /// Waits for a socket to come free and takes it.
    fn acquire(self: &Arc<Self>) -> Permit {
        let mut free = self.free.lock().unwrap_or_else(|held| held.into_inner());
        while *free == 0 {
            free = self
                .returned
                .wait(free)
                .unwrap_or_else(|held| held.into_inner());
        }
        *free -= 1;
        Permit {
            gate: Arc::clone(self),
        }
    }
}

/// One socket's worth of the phase's budget, given back when the flow holding it
/// is done.
struct Permit {
    gate: Arc<Gate>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut free = self
            .gate
            .free
            .lock()
            .unwrap_or_else(|held| held.into_inner());
        *free += 1;
        self.gate.returned.notify_one();
    }
}

/// A compute module's live capabilities, holding one of the phase's sockets for
/// as long as the module runs.
///
/// A passive module takes a permit it never spends, which costs nothing worth
/// avoiding: the compute tier runs one module at a time per port, so a passive
/// one holds its permit for the length of a pure computation. What it buys is one
/// count covering both tiers, so [`Gate`] is the whole answer to how many sockets
/// this phase has open.
struct Permitted {
    inner: LiveCapabilities,
    _permit: Permit,
}

impl Capabilities for Permitted {
    fn speak(&mut self, bytes: &[u8]) -> Result<Vec<u8>, CapError> {
        self.inner.speak(bytes)
    }

    fn resolve(&mut self, name: &str) -> Result<Vec<std::net::IpAddr>, CapError> {
        self.inner.resolve(name)
    }

    fn now(&mut self) -> ScanInstant {
        self.inner.now()
    }
}

/// A [`SocketProbe`] holding one of the phase's sockets for as long as the flow
/// it serves is running.
///
/// The probe itself is [`detect::flow`](crate::detect::flow)'s and knows nothing
/// about a scan's socket budget. This is the wrapper that adds it, so the count
/// covers both tiers: [`Permitted`] does the same for a compute module.
struct Pooled {
    inner: SocketProbe,
    _permit: Permit,
}

impl Probe for Pooled {
    fn speak(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
        self.inner.speak(bytes)
    }

    fn last_refusal(&self) -> Option<ProbeRefusal> {
        self.inner.last_refusal()
    }

    fn reply_complete(&self) -> bool {
        self.inner.reply_complete()
    }
}

/// The budget a flow's probe is held to, filled from what the detection declared
/// and from this runtime's ceilings for what it left open.
///
/// A flow spends bytes, wall clock and connections; the two ceilings a [`Budget`]
/// carries for a compute module's execution go unread. See
/// [`SocketProbe::new`].
fn flow_budget(caps: &CapabilitySpec) -> Budget {
    Budget::new(
        0,
        Duration::from_millis(caps.max_millis.map_or(DEFAULT_MAX_MILLIS, u64::from)),
    )
    .with_max_bytes(caps.max_bytes.map_or(DEFAULT_MAX_BYTES, u64::from))
    .with_max_connections(
        caps.max_connections
            .map_or(DEFAULT_MAX_CONNECTIONS, u32::from),
    )
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
    use crate::detect::manifest::{Class, Speak};
    use crate::model::host::Host;
    use crate::model::port::{Port, Service};
    use crate::scanner::session::ScanSession;
    use std::net::IpAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// An `active-benign` capability set with the given budgets, for building a
    /// `SocketProbe` a budget test can drive.
    fn caps(
        max_bytes: Option<u32>,
        max_millis: Option<u32>,
        max_connections: Option<u16>,
    ) -> CapabilitySpec {
        CapabilitySpec {
            class: Class::ActiveBenign,
            speak: Some(Speak::Target),
            resolve: false,
            max_bytes,
            max_millis,
            max_connections,
        }
    }

    #[tokio::test]
    async fn detect_runs_a_compute_module_over_the_gathered_response() {
        let (session, ctx) = ScanSession::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // An open http port, as the service phase would leave it, plus the
        // response that phase gathered: a page missing every baseline header.
        let mut host = Host::new(ip);
        host.add_port(
            Port::new(80, Protocol::Tcp, PortState::Open).with_service(Service::new("http", 100)),
        );
        session.hosts().insert(ip, host);
        ctx.record_responses(
            ScopedIp::from(ip),
            80,
            Protocol::Tcp,
            vec!["HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n".to_string()],
        );

        detect(
            &ctx,
            ServiceDetection::default(),
            DetectionEnvelope::default(),
        )
        .await;

        let host = session.hosts().get(ip).unwrap();
        let port = host.ports().find(|port| port.number() == 80).unwrap();
        assert!(
            port.findings()
                .any(|finding| finding.detection().id() == "http-missing-security-headers"),
            "the compute module did not fire over the gathered response"
        );
    }

    #[tokio::test]
    async fn a_detection_run_is_captured_as_a_tape() {
        // The same run, checked from the other side: the scan captures a tape of
        // what the detection read, with its subject and the responses it saw, so
        // the checkpoint task can journal it for an offline replay.
        let (session, ctx) = ScanSession::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let mut host = Host::new(ip);
        host.add_port(
            Port::new(80, Protocol::Tcp, PortState::Open).with_service(Service::new("http", 100)),
        );
        session.hosts().insert(ip, host);
        ctx.record_responses(
            ScopedIp::from(ip),
            80,
            Protocol::Tcp,
            vec!["HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n".to_string()],
        );

        detect(
            &ctx,
            ServiceDetection::default(),
            DetectionEnvelope::default(),
        )
        .await;

        let tapes = ctx.progress().take_tapes();
        let run = tapes
            .iter()
            .find(|run| run.detection.id == "http-missing-security-headers")
            .expect("the compute detection's run was not captured as a tape");
        assert_eq!(run.host, "127.0.0.1");
        assert_eq!(run.port, 80);
        assert!(
            !run.responses.is_empty(),
            "the run did not keep the responses it read"
        );
    }

    #[tokio::test]
    async fn detect_draws_a_host_finding_for_a_domain_controller() {
        // Kerberos, LDAP and SMB open together: the shipped host detection concludes
        // a domain controller, a finding no single port makes.
        let (session, ctx) = ScanSession::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let mut host = Host::new(ip);
        for number in [88u16, 389, 445] {
            host.add_port(Port::new(number, Protocol::Tcp, PortState::Open));
        }
        session.hosts().insert(ip, host);

        detect(
            &ctx,
            ServiceDetection::default(),
            DetectionEnvelope::default(),
        )
        .await;

        let host = session.hosts().get(ip).unwrap();
        assert!(
            host.findings()
                .any(|finding| finding.detection().id() == "domain-controller"),
            "the domain-controller host finding was not drawn"
        );
    }

    #[tokio::test]
    async fn detect_runs_a_flow_against_a_live_port_and_records_its_finding() {
        // A loopback "redis" that answers the flow's INFO probe with a version
        // banner, standing in for the real service the flow is written against.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut probe = [0u8; 64];
                let _ = sock.read(&mut probe).await;
                let _ = sock.write_all(b"# Server\r\nredis_version:7.2.4\r\n").await;
            }
        });

        // Seed the store as the earlier phases would: the port is open and
        // identified as redis, so the flow's `when` service gate fits.
        let (session, ctx) = ScanSession::new();
        let ip = addr.ip();
        let mut host = Host::new(ip);
        host.add_port(
            Port::new(addr.port(), Protocol::Tcp, PortState::Open)
                .with_service(Service::new("redis", 100)),
        );
        session.hosts().insert(ip, host);

        // The ceiling is named rather than defaulted: this test is about a
        // flow reaching a live socket, and the default grants no flow one.
        detect(
            &ctx,
            ServiceDetection::default(),
            DetectionEnvelope::up_to(crate::model::finding::DetectionClass::ActiveBenign),
        )
        .await;

        let host = session.hosts().get(ip).unwrap();
        let port = host
            .ports()
            .find(|port| port.number() == addr.port())
            .unwrap();
        let findings: Vec<_> = port.findings().collect();
        assert_eq!(
            findings.len(),
            1,
            "the redis flow fired against the live port"
        );
        assert_eq!(findings[0].detection().id(), "redis-unauth-access");
        // Its provenance is the flow's real content hash.
        assert_eq!(findings[0].detection().content_hash().len(), 64);
    }

    #[tokio::test]
    async fn detection_off_connects_to_nothing() {
        let (session, ctx) = ScanSession::new();
        // An open, identified port on an address nothing is listening at:
        // reaching the network would take the connect timeout, so a prompt
        // return is the observable form of "no connection was attempted".
        let unreachable: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        ctx.update_host(unreachable, |host| {
            host.add_port(
                Port::new(6379, Protocol::Tcp, PortState::Open)
                    .with_service(Service::new("redis", 100)),
            );
        });

        let started = std::time::Instant::now();
        detect(&ctx, ServiceDetection::Off, DetectionEnvelope::default()).await;

        assert!(
            started.elapsed() < crate::config::limits::CONNECT_PROBE_TIMEOUT,
            "a detection turned off cannot have waited on a connection"
        );
        drop(session);
    }

    /// The budget the probe is built with, which is this module's share of what
    /// used to live inside the probe: a declared ceiling is taken and one left
    /// open falls back to this runtime's default rather than to no ceiling.
    ///
    /// What the probe then does with it is tested where the probe lives, in
    /// `detect::flow::socket`.
    #[test]
    fn a_flow_budget_takes_what_was_declared_and_defaults_the_rest() {
        let declared = flow_budget(&caps(Some(20), Some(500), Some(1)));
        assert_eq!(declared.max_bytes, 20);
        assert_eq!(declared.deadline, Duration::from_millis(500));
        assert_eq!(declared.max_connections, 1);

        let open = flow_budget(&caps(None, None, None));
        assert_eq!(open.max_bytes, DEFAULT_MAX_BYTES);
        assert_eq!(
            open.deadline,
            Duration::from_millis(DEFAULT_MAX_MILLIS)
        );
        assert_eq!(open.max_connections, DEFAULT_MAX_CONNECTIONS);
    }
}
