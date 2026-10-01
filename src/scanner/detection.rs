// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Detection phase
//!
//! When the corpus in [`crate::detect`] runs during a scan.
//!
//! Runs the Tier-1 [flows](crate::detect::flow) and Tier-2
//! [compute modules](crate::detect::compute) against the open ports a scan has
//! found and identified, recording a [`Finding`] wherever one fires. The
//! [CVE correlator](crate::cve) joins gathered versions against known
//! vulnerabilities without touching the target; this module asks each port.
//!
//! ## Compute modules
//!
//! Both tiers run on the blocking pool for each interested port. A compute module
//! that speaks is served through [`LiveCapabilities`], budgeted like a flow's
//! probe. A passive one reads the responses the pass that named the service
//! [kept](crate::scanner::session) for this phase (the
//! [service phase](crate::scanner::service) after a raw scan, the
//! [connect scanner](crate::scanner::strategy::connect) inline), so it adds no
//! traffic.
//!
//! ## The socket a flow speaks through
//!
//! The flow interpreter is synchronous and interleaves I/O with its logic (a
//! conditional step sends only after an earlier one matched), so it runs on the
//! blocking pool ([`spawn_blocking`](tokio::task::spawn_blocking)) with a
//! blocking [`SocketProbe`]. The probe connects to the scanned address, in TLS
//! when the port answered inside a tunnel, and is bound to that one port.
//!
//! The probe is public in [`detect::flow`](crate::detect::flow), for running one
//! detection against one port without a scan. A scan adds the socket count:
//! `Pooled` holds one of the phase's permits for the flow's whole run.
//!
//! A flow's declared `max_bytes`, `max_millis` and `max_connections` become its
//! [`Budget`]; one that declares none gets this runtime's default ceilings.

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
use crate::model::ip::Exposure;
use crate::model::ip::scoped::ScopedIp;
use crate::model::port::{PortState, Protocol};
use crate::record::{DetectionIdRecord, wire};
use crate::report::{Pass, ScannerKind};
use crate::scanner::pool::ProbePool;
use crate::scanner::session::{ScanContext, Stage, Tapes};

/// One port's result off the blocking pool: host key, port, protocol, findings,
/// and the detections that did not finish.
type PortResult = (ScopedIp, u16, Protocol, Vec<Finding>, Vec<Unfinished>);

/// A detection that did not finish on a port, sorted by whether anything broke.
///
/// All reach the report as work the phase did not complete. They differ in the
/// entry's mark and the console line: a spent budget or a refused socket is not
/// a failure, and is not reported as one.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Unfinished {
    /// The detection's own budget (time, bytes, connections or fuel) ran out.
    /// Carries the detection's id and which budget, as a phrase.
    ///
    /// On the console only from verbosity 1: the reader cannot change the
    /// budget, and the closing count already says coverage fell short.
    CutShort { id: String, why: String },
    /// The process's file limit left the detection without a socket before it
    /// had its answer. Carries the detection's id and how far it got, as a
    /// phrase.
    ///
    /// Reported at every verbosity, because the caller can raise the limit. Kept
    /// apart from [`PortGivenUp`](Self::PortGivenUp) because the port was never
    /// asked, and blaming it would send the reader to the target.
    Starved { id: String, why: String },
    /// The detection broke, or the runtime refused it something it asked for.
    Failed { id: String, why: String },
    /// The port stopped answering and was given up on before the detection
    /// had its answer. Carries the detection's id and how far it got, as a
    /// phrase.
    ///
    /// The port's doing, so it applies to every detection gated onto the port; a
    /// web port given up on leaves dozens.
    PortGivenUp { id: String, why: String },
    /// The scan stopped, or the host ran out of the time the scan gave it,
    /// while one of the detection's exchanges waited for its turn under the
    /// scan's pacing.
    ///
    /// Filed as neither the detection's nor the port's shortfall: the scan's own
    /// record already names the stopped pass (this names it if nothing else has)
    /// or the host [`host_expired`](ScanContext::host_expired) filed as left
    /// early.
    Withheld,
}

impl Unfinished {
    /// Files one port's unfinished detections against it.
    ///
    /// Each is its own report entry. On the console, a port given up on and a
    /// port starved by the file limit get one line each, however many
    /// detections they left; per-detection lines appear at verbosity 2.
    fn file_all(unfinished: &[Unfinished], ctx: &ScanContext, endpoint: &str) {
        let (mut given_up, mut starved): (u128, u128) = (0, 0);
        for detection in unfinished {
            let (count, id, why) = match detection {
                Unfinished::PortGivenUp { id, why } => (&mut given_up, id, why),
                Unfinished::Starved { id, why } => (&mut starved, id, why),
                other => {
                    other.record(ctx, endpoint);
                    continue;
                }
            };
            *count += 1;
            let reason = format!("{id} on {endpoint} cut short: {why}");
            crate::warn!(verbosity = 2, "{reason}");
            ctx.file_cut_short(ScannerKind::Detection, reason);
        }
        let detections = |count| crate::logging::counted(count, "detection", "detections");
        if given_up > 0 {
            crate::warn!(
                "{endpoint} unresponsive, {} cut short",
                detections(given_up)
            );
        }
        if starved > 0 {
            crate::warn!(
                "{} on {endpoint} cut short ({})",
                detections(starved),
                crate::system::descriptors::starved_briefly()
            );
        }
    }

    /// Files this against the port it happened on.
    fn record(&self, ctx: &ScanContext, endpoint: &str) {
        match self {
            Unfinished::CutShort { id, why } => {
                let reason = format!("{id} on {endpoint} cut short: {why}");
                crate::warn!(verbosity = 1, "{reason}");
                ctx.file_cut_short(ScannerKind::Detection, reason);
            }
            Unfinished::Starved { id, why } | Unfinished::PortGivenUp { id, why } => ctx
                .record_cut_short(
                    ScannerKind::Detection,
                    format!("{id} on {endpoint} cut short: {why}"),
                ),
            Unfinished::Failed { id, why } => {
                ctx.record_failure(ScannerKind::Detection, format!("{id} on {endpoint}: {why}"))
            }
            Unfinished::Withheld => {
                ctx.stopping_before(Pass::Detections);
            }
        }
    }
}

/// Runs the corpus against every open port a detection is interested in,
/// recording the findings it produces.
///
/// Runs only when service detection is on, since a detection's `when` selects a
/// port by its service. `envelope` decides which detection classes the operator
/// permits.
pub async fn detect(ctx: &ScanContext, detection: ServiceDetection, envelope: DetectionEnvelope) {
    if detection == ServiceDetection::Off {
        return;
    }

    // An envelope granting nothing: return before walking every port and
    // detection only to find none may run.
    if envelope.ceiling().is_none() {
        return;
    }

    // Host-level detections read only what the service phase found, so they run
    // independently of the per-port pass below.
    detect_hosts(ctx);

    let targets = interested_ports(ctx, envelope);
    if targets.is_empty() {
        return;
    }
    // A stopped scan runs nothing further; the report names the pass.
    if ctx.stopping_before(Pass::Detections) {
        return;
    }

    ctx.enter_stage(Stage::Detections, Some(targets.len() as u64));

    // One socket budget for the whole phase. See `Gate`.
    let gate = Arc::new(Gate::new(CONNECT_CONCURRENCY));

    let mut pool = ProbePool::new(
        CONNECT_CONCURRENCY,
        ctx.clone(),
        ScannerKind::Detection,
        |result: Option<PortResult>, _audit| {
            ctx.stage_advanced();

            if let Some((key, number, protocol, findings, unfinished)) = result {
                // Record unfinished detections so the report tells them apart
                // from ones that found nothing.
                let endpoint = key.endpoint(number).to_string();
                Unfinished::file_all(&unfinished, ctx, &endpoint);
                record(ctx, key, number, protocol, findings);
            }
        },
    );

    // One contention per host, shared by its ports, so a flow waiting behind
    // another port on a single-worker server is not written off as a dead port.
    // See `HostContention`.
    let mut contention: std::collections::HashMap<ScopedIp, Arc<HostContention>> =
        std::collections::HashMap::new();

    for target in targets {
        if ctx.stopping_before(Pass::Detections) {
            break;
        }
        // Nothing further is asked of a host that has spent its budget.
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

/// One port a detection would run over, copied out of the store so the exchanges
/// do not hold its lock, with the responses the service phase gathered.
struct PortTarget {
    address: ScopedIp,
    /// The name the target reached the address by, used when asking the port;
    /// see [`ScanContext::target_name`].
    name: Option<Arc<str>>,
    number: u16,
    protocol: Protocol,
    service: Option<String>,
    responses: Vec<String>,
    /// Whether the scan only listens on this port, so no speaking detection may
    /// run; see [`ScanContext::listens_only`].
    listen_only: bool,
    /// Whether only a speaking detection may run, because the port was never
    /// confirmed open; see [`interested_ports`].
    speak_only: bool,
}

/// Whether a port in this state carries a detection, and if so whether only a
/// speaking one may run against it.
///
/// A port confirmed open runs every detection gated onto it. A UDP port left
/// `OpenOrNoReply` runs only speaking detections: a UDP service often answers
/// only the request it recognises, which a detection's own first datagram may
/// be, and there are no gathered responses to read. Any other state, including
/// an `OpenOrNoReply` TCP port, carries no detection.
fn detection_reach(state: PortState, protocol: Protocol) -> Option<bool> {
    match (state, protocol) {
        (PortState::Open, _) => Some(false),
        (PortState::OpenOrNoReply, Protocol::Udp) => Some(true),
        _ => None,
    }
}

/// Every port some detection would run over, snapshotted so the store is not
/// borrowed across the exchanges that follow.
///
/// Pre-filtered by each tier's `interested`, so an uninteresting port costs no
/// blocking task. The responses are taken from the context, so they are freed
/// as the snapshot is built.
fn interested_ports(ctx: &ScanContext, envelope: DetectionEnvelope) -> Vec<PortTarget> {
    let mut targets = Vec::new();
    for host in ctx.store.iter() {
        if !ctx.owes_passes(host.value()) {
            continue;
        }
        let address = host.value().scoped_ip();
        for port in host.value().ports() {
            let protocol = port.protocol();
            // No detection runs on SCTP: there is no client stack to speak over
            // it and an SCTP scan gathers no responses to read.
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
    // The service label is the only record of a tunnel: a detection speaks TLS
    // to an `ssl/*` service. The address seeds `{host}` in a flow's probes.
    let tunnel = service.as_deref().and_then(Tunnel::from_service_label);
    let host = addr.ip().to_string();

    // Both tiers hold a blocking socket. `spawn_blocking` fails only if the
    // runtime is shutting down.
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
                // A port the scan only listens on is sent nothing.
                if listen_only && caps.speak.is_some() {
                    return None;
                }
                // A port never confirmed open runs only speaking flows. See
                // `interested_ports`.
                if speak_only && caps.speak.is_none() {
                    return None;
                }
                // The permit first: building the probe starts the flow's clock,
                // and the wait for a socket must not count against its budget.
                let permit = gate.acquire();
                let probe = SocketProbe::new(addr, protocol, tunnel, &flow_budget(caps))
                    .via(egress.clone());
                Some(Box::new(Pooled {
                    inner: match &name {
                        Some(name) => probe.named(Arc::clone(name)),
                        None => probe,
                    },
                    _permit: permit,
                }) as Box<dyn Probe>)
            },
        );

        // The responses are kept for the run record, so a replay feeds a passive
        // detection the same input.
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
                // As for flows: no speaking module on a listen-only port.
                if listen_only && grant.speak {
                    return None;
                }
                // And only speaking modules on a port never confirmed open.
                if speak_only && !grant.speak {
                    return None;
                }
                // The permit first: `LiveCapabilities::new` starts the clock.
                let permit = gate.acquire();
                let caps = LiveCapabilities::new(addr, protocol, tunnel, &grant.budget)
                    .via(egress.clone());
                Some(Box::new(Permitted {
                    inner: match &name {
                        Some(name) => caps.named(Arc::clone(name)),
                        None => caps,
                    },
                    _permit: permit,
                }) as Box<dyn Capabilities>)
            },
            |grant, tape| {
                tapes.record(|| DetectionRunRecord {
                    host: addr.ip().to_string(),
                    host_name: name.as_deref().map(str::to_string),
                    port: number,
                    protocol: wire::protocol_name(protocol).to_string(),
                    detection: DetectionIdRecord::from(&grant.detection),
                    responses: record_responses.clone(),
                    tape: CapTapeRecord::from(&tape),
                });
            },
        );
        findings.extend(computed.findings);

        // Both tiers' unfinished runs, phrased for the report.
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

/// Why a compute run did not finish, phrased for the report: which bound or
/// fault ended it. A module's run is code, so unlike a flow's there is no count
/// of planned requests to report against, only the budget and its size.
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
        RunOutcome::OutOfDescriptors => Unfinished::Starved {
            id,
            why: no_socket(None),
        },
        RunOutcome::Withheld => Unfinished::Withheld,
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

/// A flow left short of its questions, phrased for the report: what stopped it
/// (a budget and its size, or the port going unresponsive) and how many of its
/// requests had been answered. A flow with no socket names the file limit.
fn describe_shortfall(shortfall: &Shortfall) -> Unfinished {
    let answered = format!("({}/{} answered)", shortfall.answered, shortfall.requests);
    let stopped = match shortfall.stopped {
        Stopped::Starved => return starved(shortfall),
        Stopped::Budget { refusal, limit } => match refusal {
            ProbeRefusal::Deadline => format!("{limit} ms budget"),
            ProbeRefusal::Bytes => format!("{limit}-byte budget"),
            ProbeRefusal::Connections => format!("{limit}-connection budget"),
            ProbeRefusal::Descriptors => return starved(shortfall),
            ProbeRefusal::Withheld => return Unfinished::Withheld,
        },
        Stopped::Withheld => return Unfinished::Withheld,
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
    Unfinished::Starved {
        id: shortfall.detection.clone(),
        why: no_socket(Some((shortfall.answered, shortfall.requests))),
    }
}

/// Why a detection the file limit starved was cut short, in the same words for
/// either tier: no socket, how far a flow got (where it has a request count),
/// and the limit.
fn no_socket(answered: Option<(u32, u32)>) -> String {
    let parts: Vec<String> = answered
        .map(|(answered, requests)| format!("{answered}/{requests} answered"))
        .into_iter()
        .chain(crate::system::descriptors::soft_limit().map(|limit| format!("file limit {limit}")))
        .collect();
    match parts.is_empty() {
        true => "no socket".to_string(),
        false => format!("no socket ({})", parts.join(", ")),
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

/// Runs the host-level detections over every host the scan found, drawing a host
/// finding wherever its open ports and services fit a detection's gate. Sends
/// nothing.
fn detect_hosts(ctx: &ScanContext) {
    let host_db = ctx.detections.hosts();
    if host_db.detections().is_empty() {
        return;
    }

    // Snapshot first, so the store is not borrowed while findings are written.
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
        // Exposure grades severity: RPC and SMB open together is a Windows
        // desktop on a LAN and an incident on a public address.
        let exposure = Exposure::of(key.addr());
        let findings =
            host_stage::detect_host(host_db.detections(), &open_ports, &services, exposure);
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
/// Ports run several flows at a time and the pool runs many ports, so without a
/// shared count a busy scan would open [`CONNECT_CONCURRENCY`] times
/// [`DETECTION_FLOW_CONCURRENCY`](crate::config::limits::DETECTION_FLOW_CONCURRENCY)
/// sockets at once. This holds [`CONNECT_CONCURRENCY`] for the whole phase, so a
/// host with four web ports gets most of the budget on those four.
///
/// A permit is held from when a flow's probe is built until it is dropped. The
/// wait happens before [`SocketProbe::new`] starts the flow's clock, so queueing
/// never counts against a detection's time budget.
///
/// Each permit also carries one share of the process's descriptor budget (see
/// [`descriptors`](crate::system::descriptors)), which covers the flow's
/// exchanges because they open their sockets one after another. The share is
/// taken after the phase permit, and nothing waiting on the process budget
/// waits on this gate, so the two waits cannot deadlock. Holding the share per
/// flow keeps the wait outside the flow's clock; per exchange, a busy scan
/// would make an answering port look slow.
struct Gate {
    /// Permits still to be handed out.
    free: std::sync::Mutex<usize>,
    /// Woken as each is given back.
    returned: std::sync::Condvar,
    /// The runtime to wait on the descriptor budget through, since the blocking
    /// threads a flow runs on have none of their own.
    runtime: tokio::runtime::Handle,
}

impl Gate {
    /// A gate holding `permits` sockets. Must be built on the runtime.
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
/// A passive module also takes a permit, held only for a short computation, so
/// one [`Gate`] count covers both tiers.
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
/// Adds the scan's socket budget to [`detect::flow`](crate::detect::flow)'s
/// probe, as [`Permitted`] does for a compute module.
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
/// A flow spends bytes, wall clock and connections; a [`Budget`]'s compute-only
/// ceilings go unread. See [`SocketProbe::new`].
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
        // The scan captures a tape of the run, with its subject and responses,
        // for the journal to keep for offline replay.
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

    /// Tapes are only for a journal. Without one, keeping them would hold every
    /// run's responses until the scan ended.
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
        // Kerberos, LDAP and SMB open together make a domain controller.
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
        // A loopback "redis" answering the flow's INFO probe with a version banner.
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

        // The port open and identified as redis, so the flow's `when` fits.
        let (session, ctx) = ScanSession::new();
        let ip = addr.ip();
        let mut host = Host::new(ip);
        host.add_port(
            Port::new(addr.port(), Protocol::Tcp, PortState::Open)
                .with_service(Service::new("redis", 100)),
        );
        session.hosts().insert(ip, host);

        // The default envelope grants no flow a live socket.
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

    /// A detection on a port whose address the target reached by name sends that
    /// name in the TLS handshake and the request, since a name-based server
    /// refuses or serves the default site otherwise.
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

    /// A speaking UDP detection runs on a port left `OpenOrNoReply`, where a
    /// service answering only the request it knows ignored the scan's probe.
    /// The port never reached the service pass, so only the detection's own
    /// probe can establish what is there.
    #[tokio::test]
    async fn a_speaking_udp_detection_runs_on_an_open_or_no_reply_port() {
        // A responder that answers only its own probe word.
        let agent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = agent.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            while let Ok((read, from)) =
                crate::testing::loopback::recv_from_this_process(&agent, &mut buffer).await
            {
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
        // The UDP port scan heard nothing back.
        host.add_port(Port::new(
            addr.port(),
            Protocol::Udp,
            PortState::OpenOrNoReply,
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
            "the speaking detection did not run on the open|no-reply port"
        );
    }

    /// Detection turned off opens no connection, even to an open port identified
    /// as a service detections are written for. Counted at the port.
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

        // The envelope grants the redis flow its socket, so only the level
        // keeps it off the port.
        detect(
            &ctx,
            ServiceDetection::Off,
            DetectionEnvelope::up_to(crate::model::finding::DetectionClass::ActiveBenign),
        )
        .await;

        assert_eq!(
            crate::transport::dial::dialled::to(addr),
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

    /// A flow its time budget stopped is filed as cut short, naming the
    /// detection, the budget and how far it got, and warned in the same words.
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

    /// A flow with no socket is filed and warned as cut short, naming the
    /// descriptor limit.
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

    /// A module the file limit left without a socket is filed as cut short,
    /// naming the limit, and not as a failed detection.
    #[test]
    fn a_module_refused_a_socket_is_filed_as_the_file_limit_and_not_as_a_failure() {
        use crate::detect::compute::{ComputeRuntime, Grant, ModuleBody, RhaiRuntime};
        use crate::model::finding::{DetectionClass, DetectionId, Version};

        /// Has no socket for any exchange, like a full descriptor table.
        struct NoSocket;
        impl Capabilities for NoSocket {
            fn speak(&mut self, _bytes: &[u8]) -> Result<Vec<u8>, CapError> {
                Err(CapError::OutOfDescriptors)
            }
            fn resolve(&mut self, _name: &str) -> Result<Vec<std::net::IpAddr>, CapError> {
                Ok(Vec::new())
            }
            fn now(&mut self) -> ScanInstant {
                ScanInstant::from_millis(0)
            }
        }

        let detection = DetectionId::new("speaks-once", Version::new(1, 0, 0), "0".repeat(64))
            .expect("a valid detection id");
        let budget = Budget::new(1_000_000, Duration::from_secs(2));
        let grant = Grant {
            group: None,
            detection: detection.clone(),
            class: DetectionClass::ActiveBenign,
            budget,
            speak: true,
            resolve: false,
        };
        let runtime = RhaiRuntime::new();
        let module = runtime
            .load(&ModuleBody::Rhai(
                "fn analyze(ctx, responses) { speak(blob()); [] }".to_string(),
            ))
            .expect("the module compiles");
        let mut instance = runtime
            .instantiate(&module, &grant)
            .expect("the module instantiates");
        let context = PortContext {
            port: 80,
            protocol: Protocol::Tcp,
            addr: None,
            tunnel: None,
            speaks_http: true,
            detection: ServiceDetection::default(),
            host_name: None,
        };
        let outcome = runtime
            .run(&mut instance, &context, &[], &mut NoSocket)
            .expect_err("a run with no socket did not finish");
        let unfinished = describe_outcome(&InconclusiveRun {
            detection,
            outcome,
            budget,
        });

        let (session, ctx) = ScanSession::new();
        let lines = crate::logging::logged(|| {
            Unfinished::file_all(std::slice::from_ref(&unfinished), &ctx, "192.0.2.1:80");
        });

        assert!(
            matches!(&unfinished, Unfinished::Starved { why, .. } if why.starts_with("no socket")),
            "{unfinished:?}"
        );
        let failures = ctx.failures_snapshot();
        assert!(
            failures.len() == 1 && failures[0].is_cut_short(),
            "filed as a failure: {failures:?}"
        );
        let console: Vec<&str> = lines
            .iter()
            .filter(|line| line.verbosity == 0)
            .map(|line| line.message.as_str())
            .collect();
        assert!(
            matches!(console.as_slice(), [line] if line.contains("file limit")),
            "{console:?}"
        );
        drop(session);
    }

    /// A port's starved detections are one console line naming the limit,
    /// however many there were, and the port is not called unresponsive. The
    /// report keeps an entry for each.
    #[test]
    fn a_ports_starved_detections_are_one_console_line_naming_the_file_limit() {
        let (session, ctx) = ScanSession::new();
        let unfinished: Vec<Unfinished> = ["admin-panels", "git-exposed", "env-file"]
            .iter()
            .map(|detection| {
                describe_shortfall(&Shortfall {
                    detection: detection.to_string(),
                    stopped: Stopped::Starved,
                    answered: 0,
                    requests: 1,
                })
            })
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
            vec![format!(
                "3 detections on 192.0.2.1:80 cut short ({})",
                crate::system::descriptors::starved_briefly()
            )]
        );
        let filed = ctx.failures_snapshot();
        assert_eq!(filed.len(), 3, "an entry per detection: {filed:?}");
        assert!(
            filed
                .iter()
                .all(|failure| failure.is_cut_short() && failure.reason().contains("no socket")),
            "{filed:?}"
        );
        drop(session);
    }

    /// A port given up on is one console line however many detections it left
    /// unfinished, while the report keeps an entry for each. A detection its own
    /// budget stopped keeps its own line at verbosity 1.
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
            vec!["192.0.2.1:80 unresponsive, 3 detections cut short"]
        );
        let verbose: Vec<&str> = lines
            .iter()
            .filter(|line| line.verbosity == 1)
            .map(|line| line.message.as_str())
            .collect();
        assert_eq!(
            verbose,
            vec!["backup-files on 192.0.2.1:80 cut short: 3000 ms budget (0/4 answered)"]
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

    /// Each budget a compute module can run out of is named with its size.
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

    /// A declared ceiling is taken and one left open gets the runtime default.
    /// The probe's enforcement is tested in `detect::flow::socket`.
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
