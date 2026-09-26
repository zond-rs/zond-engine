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
//! a detection *is*, the other is when it runs, and one name for both would
//! leave a reader unable to tell which of the two is meant.
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
use crate::detect::compute::stage::InconclusiveRun;
use crate::detect::compute::{
    Budget, BudgetTrap, CapError, CapTapeRecord, Capabilities, DetectionRunRecord,
    LiveCapabilities, RunOutcome, ScanInstant,
};
use crate::detect::contention::HostContention;
use crate::detect::flow::stage::{Shortfall, Stopped};
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
use crate::report::{Pass, ScannerKind};
use crate::scanner::pool::ProbePool;
use crate::scanner::session::{ScanContext, Stage, Tapes};

/// One port's detections as they travel off the blocking pool: the host key, the
/// port and protocol, the findings drawn, and the detections that did not finish
/// with why, so the pool can file each.
type PortResult = (ScopedIp, u16, Protocol, Vec<Finding>, Vec<Unfinished>);

/// A detection that did not finish on a port, sorted by whether anything broke.
///
/// Both reach the report the same way, as work the phase did not complete, since
/// either leaves the port's question open and a report read for coverage has to
/// count both. What differs is the entry's mark and what the console calls them.
/// A budget that ran out is the detection's own declared ceiling holding against
/// a target that cost more than it allowed, and a socket refused is the
/// process's file limit: nothing failed, and calling it a failed scanner sends a
/// reader looking for a fault that is not there.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Unfinished {
    /// A limit the detection runs under, its budget or the process's file
    /// limit, was reached before it had its answer. Carries the detection's id
    /// and which limit, as a phrase.
    CutShort { id: String, why: String },
    /// The detection broke, or the runtime refused it something it asked for.
    Failed { id: String, why: String },
    /// The port stopped answering and was given up on before the detection
    /// had its answer. Carries the detection's id and how far it got, as a
    /// phrase.
    ///
    /// Apart from [`CutShort`](Self::CutShort) because it is the port's doing
    /// rather than the detection's, and so says the same thing about every
    /// detection gated onto the port: a web port given up on leaves dozens.
    PortGivenUp { id: String, why: String },
}

impl Unfinished {
    /// Files one port's unfinished detections against it.
    ///
    /// Each is its own report entry, since a report read for coverage counts
    /// the questions left open. The console hears a port given up on once,
    /// however many detections it left: what a reader acts on is the port,
    /// and a line per detection buries the rest of the run under dozens
    /// saying the same thing. Each detection's own line is kept for the
    /// verbosity that shows a line per exchange.
    fn file_all(unfinished: &[Unfinished], ctx: &ScanContext, endpoint: &str) {
        let mut given_up: u128 = 0;
        for detection in unfinished {
            match detection {
                Unfinished::PortGivenUp { id, why } => {
                    given_up += 1;
                    let reason = format!("{id} on {endpoint} cut short: {why}");
                    crate::warn!(verbosity = 2, "{reason}");
                    ctx.file_cut_short(ScannerKind::Detection, reason);
                }
                other => other.record(ctx, endpoint),
            }
        }
        if given_up > 0 {
            crate::warn!(
                "{endpoint} unresponsive, {} cut short",
                crate::logging::counted(given_up, "detection", "detections")
            );
        }
    }

    /// Files this against the port it happened on.
    fn record(&self, ctx: &ScanContext, endpoint: &str) {
        match self {
            Unfinished::CutShort { id, why } | Unfinished::PortGivenUp { id, why } => ctx
                .record_cut_short(
                    ScannerKind::Detection,
                    format!("{id} on {endpoint} cut short: {why}"),
                ),
            Unfinished::Failed { id, why } => {
                ctx.record_failure(ScannerKind::Detection, format!("{id} on {endpoint}: {why}"))
            }
        }
    }
}

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
    // A stopped scan runs nothing further, and the report names the pass it
    // left with ports in front of it.
    if ctx.stopping_before(Pass::Detections) {
        return;
    }

    ctx.enter_stage(Stage::Detections, Some(targets.len() as u64));

    // One budget for the phase, shared by every port in the pool and every flow
    // inside each. See [`Gate`].
    let gate = Arc::new(Gate::new(CONNECT_CONCURRENCY));

    let mut pool = ProbePool::new(
        CONNECT_CONCURRENCY,
        ctx.clone(),
        ScannerKind::Detection,
        |result: Option<PortResult>, _audit| {
            ctx.stage_advanced();

            if let Some((key, number, protocol, findings, unfinished)) = result {
                // A detection a budget cut short or that broke did not clear the
                // port; record that it did not finish so the report tells it
                // apart from one that found nothing.
                let endpoint = key.endpoint(number).to_string();
                Unfinished::file_all(&unfinished, ctx, &endpoint);
                record(ctx, key, number, protocol, findings);
            }
        },
    );

    // One contention per host, shared by every port of it the pool runs, so a
    // flow waiting behind another of the host's ports on a shared single-worker
    // process is seen for that rather than written off as a dead port. See
    // [`HostContention`].
    let mut contention: std::collections::HashMap<ScopedIp, Arc<HostContention>> =
        std::collections::HashMap::new();

    for target in targets {
        if ctx.stopping_before(Pass::Detections) {
            break;
        }
        // Nothing further is asked of a host that has spent its budget. A
        // detection is the most expensive thing this engine does to one port,
        // and a host already left early is the last place to spend it.
        if ctx.host_expired(target.address.addr()) {
            continue;
        }
        let egress = ctx.egress_toward(target.address.addr());
        let host_contention = Arc::clone(
            contention
                .entry(target.address.clone())
                .or_insert_with(|| Arc::new(HostContention::default())),
        );
        pool.admit(detect_one(
            target,
            egress,
            ctx.detections.clone(),
            detection,
            envelope,
            Arc::clone(&ctx.tapes),
            Arc::clone(&gate),
            host_contention,
        ))
        .await;
    }

    pool.drain().await;
}

/// One port a detection would run over, lifted out of the store so the
/// exchanges that follow do not hold its lock. It carries the responses the service
/// phase gathered for a passive module to read.
struct PortTarget {
    address: ScopedIp,
    /// The name a target reached the address by, which the port is asked for
    /// by; see [`ScanContext::target_name`].
    name: Option<Arc<str>>,
    number: u16,
    protocol: Protocol,
    service: Option<String>,
    responses: Vec<String>,
    /// Whether the scan only listens on this port, so that no detection that
    /// speaks may run over it; see [`ScanContext::listens_only`].
    listen_only: bool,
    /// Whether only a detection whose own first exchange is a probe may run
    /// here, because the port's state was never confirmed open; see
    /// [`interested_ports`].
    speak_only: bool,
}

/// Whether a port in this state carries a detection, and if so whether only a
/// speaking one may run against it.
///
/// A port confirmed open runs every detection gated onto it, passive readings
/// of the gathered responses included. A UDP port left open|filtered runs only
/// a detection that speaks: over UDP that state is the ordinary lot of a
/// service answering nothing but the request it recognises, so a detection
/// whose own first datagram is that request establishes what is there where the
/// service probe drew silence, while one that reads what the scan gathered has
/// nothing to read, a UDP port reaching the service pass only once open. Any
/// other state, and an open|filtered TCP port, carries no detection: a TCP port
/// that only might be open is settled by the connection a detection would make
/// rather than run against speculatively.
fn detection_reach(state: PortState, protocol: Protocol) -> Option<bool> {
    match (state, protocol) {
        (PortState::Open, _) => Some(false),
        (PortState::OpenFiltered, Protocol::Udp) => Some(true),
        _ => None,
    }
}

/// Every port some detection would run over, snapshotted so the store is not
/// borrowed across the exchanges that follow.
///
/// Pre-filtered by each tier's `interested` so a port no detection gates onto
/// costs nothing here rather than a blocking task that does nothing. The responses
/// are *taken* from the context, so they are freed as the snapshot is built rather
/// than held to the end of the scan.
fn interested_ports(ctx: &ScanContext, envelope: DetectionEnvelope) -> Vec<PortTarget> {
    let mut targets = Vec::new();
    for host in ctx.store.iter() {
        if !ctx.owes_passes(host.value()) {
            continue;
        }
        let address = host.value().scoped_ip();
        for port in host.value().ports() {
            let protocol = port.protocol();
            // No detection runs against an SCTP port. The scan holds no client
            // stack to speak over one, so an active detection is refused at the
            // seam, and an SCTP scan gathers no responses a passive one could read.
            // Skipping it here spares a blocking task both seams would only refuse.
            if protocol == Protocol::Sctp {
                continue;
            }
            let Some(speak_only) = detection_reach(port.state(), protocol) else {
                continue;
            };
            let number = port.number();
            let service = port.service().map(|service| service.name().to_string());
            let wanted = stage::interested(
                ctx.detections.flows(),
                &envelope,
                service.as_deref(),
                number,
                protocol,
                speak_only,
            ) || compute_stage::interested(
                ctx.detections.modules().detections(),
                &envelope,
                service.as_deref(),
                number,
                protocol,
                speak_only,
            );
            if wanted {
                let responses = ctx.take_responses(&address, number, protocol);
                targets.push(PortTarget {
                    address: address.clone(),
                    name: ctx.target_name(address.addr()),
                    number,
                    protocol,
                    service,
                    responses,
                    listen_only: ctx.listens_only(number, protocol),
                    speak_only,
                });
            }
        }
    }
    targets
}

/// Runs one port's detections on the blocking pool and returns the findings, or
/// [`None`] if the port yielded nothing or has no reachable address. Every
/// connection a detection opens leaves by `egress`, as the scan's probe did.
#[allow(clippy::too_many_arguments)]
async fn detect_one(
    target: PortTarget,
    egress: crate::transport::dial::Egress,
    detections: crate::detect::Detections,
    detection: ServiceDetection,
    envelope: DetectionEnvelope,
    tapes: Arc<Tapes>,
    gate: Arc<Gate>,
    contention: Arc<HostContention>,
) -> Option<PortResult> {
    let PortTarget {
        address,
        name,
        number,
        protocol,
        service,
        responses,
        listen_only,
        speak_only,
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
        let (mut findings, shortfalls) = stage::detect_port(
            flows,
            &envelope,
            &host,
            service.as_deref(),
            number,
            protocol,
            &contention,
            |caps| {
                // A detection that declares `speak` exists to send, and a port
                // the scan only listens on is sent nothing. Declined before a
                // socket is opened, so the flow simply does not apply here.
                if listen_only && caps.speak.is_some() {
                    return None;
                }
                // A port whose state was never confirmed open runs only a
                // detection whose own first exchange is its probe; a flow that
                // does not speak reads nothing the scan gathered there. See
                // `interested_ports`.
                if speak_only && caps.speak.is_none() {
                    return None;
                }
                // The permit first: building the probe starts the flow's clock,
                // and the wait for a socket must not come out of its budget.
                let permit = gate.acquire();
                Some(Box::new(Pooled {
                    inner: SocketProbe::new(addr, protocol, tunnel, &flow_budget(caps))
                        .via(egress)
                        .named(name.clone()),
                    _permit: permit,
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
            host_name: name.as_deref().map(str::to_string),
        };
        let computed = compute_stage::detect_port(
            modules.runtime(),
            modules.detections(),
            &envelope,
            service.as_deref(),
            &port_context,
            &response_slices,
            |grant| {
                // The same rule as a flow's: a module served `speak` is not run
                // on a port the scan only listens on. One that is not served it
                // reads the responses the scan already drew, which is safe
                // anywhere.
                if listen_only && grant.speak {
                    return None;
                }
                // And the converse on a port never confirmed open: only a
                // module whose own first exchange is its probe runs there, a
                // passive one having no gathered response to read. See
                // `interested_ports`.
                if speak_only && !grant.speak {
                    return None;
                }
                // Acquire the permit before building `LiveCapabilities`, which
                // starts the flow's clock: the wait for a socket must not come
                // out of the flow's own time budget.
                let permit = gate.acquire();
                Some(Box::new(Permitted {
                    inner: LiveCapabilities::new(addr, protocol, tunnel, &grant.budget)
                        .via(egress)
                        .named(name.clone()),
                    _permit: permit,
                }) as Box<dyn Capabilities>)
            },
            |grant, tape| {
                tapes.record(|| DetectionRunRecord {
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

        // Both tiers' unfinished runs, phrased for the report: a compute run that
        // trapped or faulted, and a flow a budget cut short.
        let mut unfinished: Vec<Unfinished> =
            computed.inconclusive.iter().map(describe_outcome).collect();
        unfinished.extend(shortfalls.iter().map(describe_shortfall));

        (findings, unfinished)
    })
    .await
    .ok()?;

    let (findings, unfinished) = produced;
    (!findings.is_empty() || !unfinished.is_empty())
        .then_some((address, number, protocol, findings, unfinished))
}

/// Why a compute run did not finish, phrased for the report. A reader needs
/// which bound or fault ended the run, not the Rust spelling of the outcome
/// enum.
///
/// A module's run is code rather than a list of requests, so unlike a flow's
/// there is no count of what it set out to ask to weigh the shortfall against;
/// the budget and its size are what there is to say.
fn describe_outcome(run: &InconclusiveRun) -> Unfinished {
    let id = run.detection.id().to_string();
    let budget = &run.budget;
    match &run.outcome {
        RunOutcome::BudgetExceeded(trap) => {
            let why = match trap {
                BudgetTrap::Deadline => {
                    format!("{} ms budget", budget.deadline.as_millis())
                }
                BudgetTrap::Bytes => format!("{}-byte budget", budget.max_bytes),
                BudgetTrap::Connections => {
                    format!("{}-connection budget", budget.max_connections)
                }
                BudgetTrap::Fuel => {
                    format!("{}-operation budget", budget.fuel)
                }
                BudgetTrap::Memory => format!("{}-element memory budget", budget.max_memory),
            };
            Unfinished::CutShort { id, why }
        }
        RunOutcome::Denied(denial) => Unfinished::Failed {
            id,
            why: format!("denied {:?}: {}", denial.capability, denial.reason),
        },
        RunOutcome::Faulted(fault) => Unfinished::Failed {
            id,
            why: format!("faulted: {fault:?}"),
        },
        RunOutcome::HostReentered => Unfinished::Failed {
            id,
            why: "re-entered the runtime".to_string(),
        },
    }
}

/// A flow left short of its questions, phrased for the report: what stopped
/// it, a budget and its size or the port going unresponsive, and how many of
/// the flow's requests had been answered by then.
///
/// A flow the process had no socket for is cut short by the process's file
/// limit, as every other connection refused a socket is: nothing about the
/// port or the detection held and nothing broke, and the entry names the
/// limit, whose remedy is the caller's.
fn describe_shortfall(shortfall: &Shortfall) -> Unfinished {
    let answered = format!("({}/{} answered)", shortfall.answered, shortfall.requests);
    let stopped = match shortfall.stopped {
        Stopped::Starved => return starved(shortfall),
        Stopped::Budget { refusal, limit } => match refusal {
            ProbeRefusal::Deadline => format!("{limit} ms budget"),
            ProbeRefusal::Bytes => format!("{limit}-byte budget"),
            ProbeRefusal::Connections => format!("{limit}-connection budget"),
            ProbeRefusal::Descriptors => return starved(shortfall),
        },
        Stopped::PortUnresponsive => {
            return Unfinished::PortGivenUp {
                id: shortfall.detection.clone(),
                why: format!("port unresponsive {answered}"),
            };
        }
    };
    Unfinished::CutShort {
        id: shortfall.detection.clone(),
        why: format!("{stopped} {answered}"),
    }
}

/// A flow the process had no socket for, cut short by the file limit.
fn starved(shortfall: &Shortfall) -> Unfinished {
    Unfinished::CutShort {
        id: shortfall.detection.clone(),
        why: format!(
            "no socket ({}/{} answered{})",
            shortfall.answered,
            shortfall.requests,
            crate::system::descriptors::soft_limit()
                .map(|limit| format!(", file limit {limit}"))
                .unwrap_or_default()
        ),
    }
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
        if !ctx.owes_passes(host.value()) {
            continue;
        }
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
/// A port's flows run several at a time, and every port in the pool does the
/// same, so the two multiply: without a shared count a busy scan would open
/// [`CONNECT_CONCURRENCY`] ports times
/// [`DETECTION_FLOW_CONCURRENCY`](crate::config::limits::DETECTION_FLOW_CONCURRENCY)
/// flows at once, hundreds of sockets against a ceiling written for fifty. This
/// holds that ceiling for the phase as a whole, so the concurrency is spent
/// where the work is: a host with four web ports gets most of the budget on
/// those four, and a scan with fifty ports in flight holds no more sockets than
/// one flow per port would.
///
/// A permit is taken when a flow's probe is built and given back when the probe
/// is dropped, which is the flow's whole run. The wait happens before
/// [`SocketProbe::new`] starts the flow's clock rather than inside an exchange,
/// so queueing never counts against a detection's own time budget.
///
/// Each permit also carries a share of the process's descriptor budget, the
/// one every connection a scan opens draws from, since a flow's exchanges open
/// their sockets one after another, each holding its one socket and no other
/// descriptor, and one share covers them; see
/// [`descriptors`](crate::system::descriptors). It is taken after the phase's
/// own permit and never the other way round, and nothing waiting on the
/// process's budget waits on this gate, so neither wait can close a cycle.
///
/// The share is the flow's rather than each exchange's. Taken per exchange,
/// the queue for it would fall between a flow's questions, inside its clock,
/// and a busy scan would read as a slow port: the flow would run out of time
/// on its own budget and count dead waits against a port that answered every
/// question it was asked. Held for the flow, the wait is before the clock,
/// and a table the rest of the process fills past its reserve is the only
/// wait left inside it, which the flow reports as the process's shortfall.
struct Gate {
    /// Permits still to be handed out.
    free: std::sync::Mutex<usize>,
    /// Woken as each is given back.
    returned: std::sync::Condvar,
    /// The runtime the process's descriptor budget is waited on through, from
    /// the threads a flow runs on, which carry none of their own.
    runtime: tokio::runtime::Handle,
}

impl Gate {
    /// A gate holding `permits` sockets. Built on the runtime, which it keeps
    /// a handle to.
    fn new(permits: usize) -> Self {
        Self {
            free: std::sync::Mutex::new(permits),
            returned: std::sync::Condvar::new(),
            runtime: tokio::runtime::Handle::current(),
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
        drop(free);
        Permit {
            gate: Arc::clone(self),
            _descriptor: crate::system::descriptors::descriptor_blocking(&self.runtime),
        }
    }
}

/// One socket's worth of the phase's budget, and of the process's, given back
/// when the flow holding it is done.
struct Permit {
    gate: Arc<Gate>,
    _descriptor: crate::system::descriptors::Descriptor,
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

    fn plan(&mut self, exchanges: u32) {
        self.inner.plan(exchanges);
    }

    fn reads_until(&mut self, pattern: Option<&str>) {
        self.inner.reads_until(pattern);
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

        // Taken before the phase runs, as a journalled scan takes it.
        let progress = ctx.progress();
        detect(
            &ctx,
            ServiceDetection::default(),
            DetectionEnvelope::default(),
        )
        .await;

        let tapes = progress.take_tapes();
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

    /// A tape is kept for a journal to write down, and a scan with no
    /// journal has nothing that would take one. Kept anyway, every run would
    /// hold a copy of its port's responses until the scan ended, a dozen for
    /// any HTTP port.
    #[tokio::test]
    async fn a_scan_nobody_journals_keeps_no_tapes() {
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

        let host = session.hosts().get(ip).unwrap();
        let port = host.ports().find(|port| port.number() == 80).unwrap();
        assert!(port.findings().next().is_some(), "the detections ran");
        assert!(ctx.progress().take_tapes().is_empty(), "a tape was kept");
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
            if let Ok(mut sock) =
                crate::testing::loopback::accept_from_this_process(&listener).await
            {
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

    /// A server holding its sites by name answers only a client naming one: a
    /// handshake naming nothing is refused, and a request for another site
    /// reads the default one. So a detection on a port whose address a target
    /// reached by name asks for that name, in the handshake and in the request,
    /// whatever stand-in its request was written with; otherwise it reports on
    /// a site nobody pointed it at, or on nothing.
    #[tokio::test]
    async fn a_detection_asks_a_named_port_for_the_site_the_target_named() {
        let addr = crate::testing::loopback::https_site("box.example", |request| {
            request
                .starts_with("GET /server-status ")
                .then_some("<title>Apache Status</title><h1>Apache Server Status</h1>")
        })
        .await;

        let (session, ctx) = ScanSession::builder()
            .naming(std::collections::BTreeMap::from([(
                addr.ip(),
                "box.example".to_string(),
            )]))
            .build();
        let mut host = Host::new(addr.ip());
        host.add_port(
            Port::new(addr.port(), Protocol::Tcp, PortState::Open)
                .with_service(Service::new("ssl/http", 100)),
        );
        session.hosts().insert(addr.ip(), host);

        // The shipped flow writes the address it was handed as its `Host`.
        detect(
            &ctx,
            ServiceDetection::default(),
            DetectionEnvelope::up_to(crate::model::finding::DetectionClass::ActiveBenign),
        )
        .await;

        let host = session.hosts().get(addr.ip()).unwrap();
        let port = host
            .ports()
            .find(|port| port.number() == addr.port())
            .unwrap();
        assert!(
            port.findings()
                .any(|finding| finding.detection().id() == "http-server-status"),
            "the flow did not reach the named site: {:?}",
            port.findings()
                .map(|finding| finding.title())
                .collect::<Vec<_>>()
        );
    }

    /// A UDP detection whose own first datagram is its probe runs against a
    /// port left open|filtered, the state a UDP service that answers only the
    /// request it knows is left in by a scan whose generic probe it ignored.
    ///
    /// The finding it draws is one nothing else could: the port never reached
    /// the service pass, which takes only confirmed-open ports, so a detection
    /// reading gathered responses has none, and the establishing question is
    /// the detection's own. Skipping every port not confirmed open left this
    /// detection unrun on exactly the ports it exists for.
    #[tokio::test]
    async fn a_speaking_udp_detection_runs_on_an_open_filtered_port() {
        // A responder that answers only its own probe word, as an agent answers
        // a request it accepts and ignores one it does not: silence to the
        // scan's generic probe is what left the port open|filtered.
        let agent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = agent.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            while let Ok((read, from)) = agent.recv_from(&mut buffer).await {
                if &buffer[..read] == b"WHORU" {
                    let _ = agent.send_to(b"i-am-here", from).await;
                }
            }
        });

        let flow = format!(
            r#"
            [detection]
            id      = "udp-speak-first"
            version = "1.0.0"
            title   = "A UDP detection whose probe is the question"
            [detection.when]
            protocol = "udp"
            port     = {}
            [detection.capabilities]
            class      = "active-benign"
            speak      = "target"
            max_millis = 1500
            [[step]]
            send   = "WHORU"
            expect = "i-am-here"
              [[step.finding]]
              when     = "matched"
              severity = "high"
              summary  = "the agent answered the probe"
            "#,
            addr.port()
        );
        let detections = crate::detect::Detections::builder()
            .without_embedded()
            .flow(&flow, &"a".repeat(64))
            .expect("a valid flow")
            .build();

        let (session, ctx) = ScanSession::builder().detections(detections).build();
        let ip = addr.ip();
        let mut host = Host::new(ip);
        // Open|filtered, not Open: the UDP port scan heard nothing back, which
        // over UDP settles neither open nor filtered.
        host.add_port(Port::new(
            addr.port(),
            Protocol::Udp,
            PortState::OpenFiltered,
        ));
        session.hosts().insert(ip, host);

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
        let ids: Vec<&str> = port
            .findings()
            .map(|finding| finding.detection().id())
            .collect();
        assert_eq!(
            ids,
            vec!["udp-speak-first"],
            "the speaking detection did not run on the open|filtered port"
        );
    }

    /// A detection level that opens no connection opens none, even to an open
    /// port identified as a service detections are written for. Counted on
    /// the port rather than read off how long the pass took, which says
    /// nothing about a connection that was made and answered at once.
    #[tokio::test]
    async fn detection_off_connects_to_nothing() {
        let (session, ctx) = ScanSession::new();
        let silent = crate::testing::loopback::SilentPort::open();
        let addr = silent.addr();
        ctx.update_host(addr.ip(), |host| {
            host.add_port(
                Port::new(addr.port(), Protocol::Tcp, PortState::Open)
                    .with_service(Service::new("redis", 100)),
            );
        });

        // A ceiling that grants the redis flow its socket, so the level is all
        // that keeps it off the port.
        detect(
            &ctx,
            ServiceDetection::Off,
            DetectionEnvelope::up_to(crate::model::finding::DetectionClass::ActiveBenign),
        )
        .await;

        assert_eq!(
            silent.connections(),
            0,
            "a detection turned off connected to the port"
        );
        drop(session);
    }

    /// The events a closure emits, as level and message, caught by a
    /// subscriber installed for the closure's thread alone.
    fn logged(run: impl FnOnce()) -> Vec<(tracing::Level, String)> {
        use std::sync::Mutex;
        use tracing::field::{Field, Visit};
        use tracing::span::{Attributes, Id, Record};

        struct Recorder(Arc<Mutex<Vec<(tracing::Level, String)>>>);
        struct Message(String);
        impl Visit for Message {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        impl tracing::Subscriber for Recorder {
            fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &Attributes<'_>) -> Id {
                Id::from_u64(1)
            }
            fn record(&self, _: &Id, _: &Record<'_>) {}
            fn record_follows_from(&self, _: &Id, _: &Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                let mut message = Message(String::new());
                event.record(&mut message);
                self.0
                    .lock()
                    .unwrap_or_else(|held| held.into_inner())
                    .push((*event.metadata().level(), message.0));
            }
            fn enter(&self, _: &Id) {}
            fn exit(&self, _: &Id) {}
        }

        let lines = Arc::new(Mutex::new(Vec::new()));
        tracing::subscriber::with_default(Recorder(Arc::clone(&lines)), run);
        lines
            .lock()
            .unwrap_or_else(|held| held.into_inner())
            .clone()
    }

    /// A flow its time budget stopped is filed with the work the phase did
    /// not complete, where a report read for coverage looks, in words naming
    /// the detection, the budget and how far it got. On the console it is a
    /// warning in those same words, not an error saying the scanner failed:
    /// nothing broke, the detection's own ceiling held.
    #[test]
    fn a_detection_cut_short_is_reported_as_unanswered_rather_than_as_a_failed_scanner() {
        let (session, ctx) = ScanSession::new();
        let shortfall = Shortfall {
            detection: "backup-files".to_string(),
            stopped: Stopped::Budget {
                refusal: ProbeRefusal::Deadline,
                limit: 3_000,
            },
            answered: 3,
            requests: 6,
        };

        let lines = logged(|| describe_shortfall(&shortfall).record(&ctx, "192.0.2.1:443"));

        let expected = "backup-files on 192.0.2.1:443 cut short: 3000 ms budget (3/6 answered)";
        let failures = ctx.failures_snapshot();
        assert_eq!(
            failures.len(),
            1,
            "the shortfall was not filed: {failures:?}"
        );
        assert_eq!(failures[0].scanner(), ScannerKind::Detection);
        assert_eq!(failures[0].reason(), expected);
        assert_eq!(lines, vec![(tracing::Level::WARN, expected.to_string())]);
        drop(session);
    }

    /// A flow the process had no socket for is filed naming the descriptor
    /// limit, so a scan that lost a detection this way is never read as one
    /// whose ports were cleared. Filed and warned as cut short, as every other
    /// connection refused a socket is: nothing broke, and a reader told a
    /// scanner failed looks for a fault rather than at the limit.
    #[test]
    fn a_detection_refused_a_socket_is_reported_as_cut_short_naming_the_limit() {
        let (session, ctx) = ScanSession::new();
        let shortfall = Shortfall {
            detection: "backup-files".to_string(),
            stopped: Stopped::Starved,
            answered: 1,
            requests: 6,
        };

        let lines = logged(|| describe_shortfall(&shortfall).record(&ctx, "192.0.2.1:443"));

        let failures = ctx.failures_snapshot();
        assert_eq!(failures.len(), 1, "the shortfall was not filed");
        let reason = failures[0].reason();
        assert!(
            reason.starts_with("backup-files on 192.0.2.1:443 cut short: no socket (1/6 answered"),
            "{reason}"
        );
        assert!(failures[0].is_cut_short(), "a limit, not a fault");
        assert!(
            matches!(lines.as_slice(), [(tracing::Level::WARN, _)]),
            "announced as a failure: {lines:?}"
        );
        drop(session);
    }

    /// A port given up on is one line on the console however many detections
    /// it left unfinished, while the report keeps an entry for each.
    ///
    /// A web port attracts dozens of detections, and a line apiece buried the
    /// rest of the run under dozens saying one thing, which the reader acts on
    /// once: the port stopped answering. The report is read for coverage, and
    /// there each question left open still counts. A detection its own budget
    /// stopped is not the port's doing and keeps its own line.
    #[test]
    fn a_port_given_up_on_is_one_console_line_and_an_entry_per_detection() {
        let (session, ctx) = ScanSession::new();
        let shortfall = |detection: &str, stopped| Shortfall {
            detection: detection.to_string(),
            stopped,
            answered: 0,
            requests: 4,
        };
        let budget = Stopped::Budget {
            refusal: ProbeRefusal::Deadline,
            limit: 3_000,
        };
        let unfinished: Vec<Unfinished> = [
            shortfall("admin-panels", Stopped::PortUnresponsive),
            shortfall("backup-files", budget),
            shortfall("git-exposed", Stopped::PortUnresponsive),
            shortfall("env-file", Stopped::PortUnresponsive),
        ]
        .iter()
        .map(describe_shortfall)
        .collect();

        let lines = crate::logging::logged(|| {
            Unfinished::file_all(&unfinished, &ctx, "192.0.2.1:80");
        });

        let console: Vec<&str> = lines
            .iter()
            .filter(|line| line.verbosity == 0)
            .map(|line| line.message.as_str())
            .collect();
        assert_eq!(
            console,
            vec![
                "backup-files on 192.0.2.1:80 cut short: 3000 ms budget (0/4 answered)",
                "192.0.2.1:80 unresponsive, 3 detections cut short",
            ]
        );
        let filed: Vec<String> = ctx
            .failures_snapshot()
            .iter()
            .map(|failure| failure.reason().to_string())
            .collect();
        assert_eq!(
            filed,
            vec![
                "admin-panels on 192.0.2.1:80 cut short: port unresponsive (0/4 answered)",
                "backup-files on 192.0.2.1:80 cut short: 3000 ms budget (0/4 answered)",
                "git-exposed on 192.0.2.1:80 cut short: port unresponsive (0/4 answered)",
                "env-file on 192.0.2.1:80 cut short: port unresponsive (0/4 answered)",
            ]
        );
        drop(session);
    }

    /// A detection that broke is a failure, and the console says so as one.
    #[test]
    fn a_detection_that_broke_is_still_reported_as_a_failure() {
        use crate::detect::compute::ModuleFault;
        use crate::model::finding::{DetectionId, Version};

        let (session, ctx) = ScanSession::new();
        let run = InconclusiveRun {
            detection: DetectionId::new("faulty", Version::new(1, 0, 0), "0".repeat(64))
                .expect("a valid detection id"),
            outcome: RunOutcome::Faulted(ModuleFault::Runtime("boom".to_string())),
            budget: Budget::new(1, Duration::from_millis(1)),
        };

        let lines = logged(|| describe_outcome(&run).record(&ctx, "192.0.2.1:80"));

        assert_eq!(ctx.failures_snapshot().len(), 1);
        assert!(
            matches!(lines.as_slice(), [(tracing::Level::ERROR, line)] if line.contains("failed")),
            "a broken detection was not announced as a failure: {lines:?}"
        );
        drop(session);
    }

    /// Each budget a compute module can run out of is named with its size, so
    /// a reader can tell a module the target starved of time from one that
    /// asked for more bytes than it declared.
    #[test]
    fn a_compute_module_cut_short_names_the_budget_it_ran_out_of() {
        use crate::model::finding::{DetectionId, Version};

        let budget = Budget::new(1, Duration::from_millis(2_000))
            .with_max_bytes(4_096)
            .with_max_connections(2);
        let cut = |trap| {
            describe_outcome(&InconclusiveRun {
                detection: DetectionId::new("module", Version::new(1, 0, 0), "0".repeat(64))
                    .expect("a valid detection id"),
                outcome: RunOutcome::BudgetExceeded(trap),
                budget,
            })
        };
        let why = |unfinished: Unfinished| match unfinished {
            Unfinished::CutShort { why, .. } => why,
            other => panic!("a spent budget read as something else: {other:?}"),
        };

        assert_eq!(why(cut(BudgetTrap::Deadline)), "2000 ms budget");
        assert_eq!(why(cut(BudgetTrap::Bytes)), "4096-byte budget");
        assert_eq!(why(cut(BudgetTrap::Connections)), "2-connection budget");
    }

    /// The budget the probe is built with, which is the part of the probe's
    /// limits this module decides: a declared ceiling is taken and one left
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
        assert_eq!(open.deadline, Duration::from_millis(DEFAULT_MAX_MILLIS));
        assert_eq!(open.max_connections, DEFAULT_MAX_CONNECTIONS);
    }
}
