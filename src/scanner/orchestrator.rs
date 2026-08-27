// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Assembling and running a whole scan
//!
//! What [`discover`](super::discover) and [`scan`](super::scan) do once they
//! have been called: read what this host can do, turn a plan into running
//! strategies, back the plan's intent with what actually opened, drive the port
//! scan, and wait for the hostname tail.
//!
//! Nothing here is public. It is one implementation of the engine's own policy,
//! and the two entry points above are its only callers. A consumer who wants a
//! different policy does not need to reach in here: they build a
//! [`plan`](super::plan), edit it, and run the steps they want, which is the
//! second of the three altitudes the [`scanner`](super) module documents.
//!
//! ## Why it is a module of its own
//!
//! The two entry points are about ninety lines between them. Everything else a
//! scan needs to be assembled is another five hundred, and read together they
//! obscure the thing a reader opens `scanner.rs` to find. Split out, the facade
//! reads as a facade and the policy reads as policy.
//!
//! ## The one decision worth knowing before reading
//!
//! A plan says what should run; only the attempt discovers what could. Those are
//! separate steps here on purpose, and the seam between them is
//! [`ensure_coverage`], which backs the plan's intent with the sockets that
//! actually opened. A protocol left with no strategy at all is not a degraded
//! scan but a silent one, since nothing would route its targets anywhere.

use std::net::IpAddr;

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use crate::config::{OsDetection, ProbeTuning, ServiceDetection, ZondConfig};
use crate::fingerprint::os;
use crate::journal::cursor::Checkpoint;
use crate::model::ip::range::{IpRange, Ipv4Range, Ipv6Range};
use crate::model::ip::scoped::Zone;
use crate::model::{
    ip::set::IpSet,
    port::{Discovery as PortDiscovery, Port, PortState, Protocol, ScanResponse},
    target::{PlannedTarget, TargetMap, TargetSet},
    technique::TcpScanTechnique,
};
use crate::scanner::pacing::limits::CONNECT_CONCURRENCY;
use crate::scanner::pool::ProbePool;
use crate::scanner::resolver::HostnameResolver;
use crate::scanner::session::{ScanContext, ScannerKind};
use crate::scanner::strategy::local::Scope;
use crate::scanner::strategy::{HostScanner, PortScanner, StrategyError};
use crate::scanner::{pacing, plan, resolver, strategy};
use crate::system::interface;
use crate::system::privilege::is_elevated;
use crate::{error, info, success, warn};

/// The targets an unprivileged sweep can actually walk, refusing the rest.
///
/// The privileged path gets this from [`plan::DiscoveryPlan::build`], which
/// classifies every range against this host's interfaces and refuses the ones no
/// strategy can take. The unprivileged path has no plan: it hands the whole set
/// to `connect`, which probes addresses one at a time and would keep doing so
/// until the process is killed. So the same rule is applied here, and applied to
/// the same constant, because a `/64` that is refused with root and scanned
/// forever without it is the engine giving two different answers about one
/// range.
///
/// Filtered per range rather than all-or-nothing. A set holding a `/64` and
/// three literal addresses is three quarters scannable, and refusing the whole
/// of it would throw away addresses somebody named.
///
/// IPv4 is untouched. Every IPv4 range is finite in a way a person can reason
/// about, and a `/8` is an unreasonable request rather than an impossible one —
/// which is a judgement for whoever is driving the engine, not for the engine.
pub(super) fn walkable(targets: IpSet, ctx: &ScanContext) -> IpSet {
    let refused: Vec<_> = targets
        .v6()
        .iter()
        .filter(|range| !interface::is_enumerable(range))
        .copied()
        .collect();

    if refused.is_empty() {
        return targets;
    }

    let mut kept = IpSet::new();
    for range in targets.v4() {
        kept.push_v4_range(*range);
    }
    for range in targets.v6() {
        if interface::is_enumerable(range) {
            kept.push_v6_range(*range);
        }
    }
    kept.canonicalize();

    for range in &refused {
        let refusal = plan::Refusal::unprivileged_range_not_enumerable(range);
        ctx.record_failure(refusal.scanner, refusal.reason);
    }

    kept
}

/// The environment-derived facts that steer how a scan runs.
///
/// Both entry points face the same two questions: can the process open raw
/// sockets, and should it resolve hostnames. Answering them once, up front,
/// lets [`scan`] and [`discover`] branch on the same facts and keeps the
/// privileged-versus-unprivileged and DNS-on-versus-off policy from drifting
/// between phases.
#[derive(Clone, Copy)]
pub(super) struct ScanCapabilities {
    /// Whether raw-socket scanning is available, meaning the process is root.
    /// When false, every phase falls back to unprivileged TCP connect scanning.
    pub(super) privileged: bool,
    /// Whether hostname resolution is enabled, the inverse of `cfg.no_dns`.
    dns: bool,
}

impl ScanCapabilities {
    /// Reads the runtime capabilities from the environment and config, and
    /// announces the scanning mode they imply once, here, rather than from the
    /// code that later acts on them.
    pub(super) fn resolve(cfg: &ZondConfig) -> Self {
        let privileged = is_elevated();
        if privileged {
            success!("raw sockets available: probing with ARP, ICMPv6 and SYN");
        } else {
            warn!("no raw sockets: probing with TCP connect only");
        }
        Self {
            privileged,
            dns: !cfg.no_dns,
        }
    }
}

/// The privileged host-identification phase, shared by [`discover`] and
/// [`scan`].
///
/// It spawns the strategies discovery uses: per-interface [`LocalScanner`]s
/// (ARP and ICMPv6, yielding MAC and RTT), a [`RoutedScanner`] for off-link
/// targets (RTT), and the passive DNS and mDNS [`HostnameResolver`]. All of them
/// write into the shared store. [`discover`] runs this alone, while [`scan`]
/// runs it alongside the port scan. Keeping it in one place lets both surface
/// identical host detail without duplicating the orchestration.
pub(super) struct Enrichment {
    scanners: Vec<(ScannerKind, JoinHandle<Result<(), StrategyError>>)>,
    resolver: Option<JoinHandle<Option<HostnameResolver>>>,
}

impl Enrichment {
    /// Spawns every enrichment strategy for `targets`. They begin running
    /// immediately and concurrently. Call [`Enrichment::finish`] to await them.
    pub(super) async fn spawn(
        plan: plan::DiscoveryPlan,
        ctx: &ScanContext,
        caps: ScanCapabilities,
        tuning: ProbeTuning,
    ) -> Self {
        let (dns_tx, resolver) = if caps.dns {
            let (tx, rx) = mpsc::unbounded_channel();
            (Some(tx), Some(spawn_resolver(rx).await))
        } else {
            info!("DNS resolution skipped by user flag");
            (None, None)
        };

        let scanners = spawn_explorers(plan, ctx, dns_tx, tuning).await;
        Self { scanners, resolver }
    }

    /// Awaits every enrichment strategy, reports any that failed, then folds the
    /// resolver's collected hostnames and extra IPs into the store.
    async fn finish(self, ctx: &ScanContext) {
        for (kind, handle) in self.scanners {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => ctx.record_failure(kind, e.to_string()),
                Err(e) => ctx.record_failure(kind, format!("panicked: {e}")),
            }
        }

        if let Some(task) = self.resolver
            && let Ok(Some(mut resolver)) = task.await
        {
            resolver.resolve_hosts(ctx);
        }
    }
}

/// Turns a [`DiscoveryPlan`] into running tasks.
///
/// Every refusal the plan carries is recorded before anything is spawned, so the
/// distinction between "nothing is there" and "nobody looked" survives into the
/// report. Then each step is asked for its strategy: a step that cannot open
/// what it needs is recorded and skipped, and the rest of the scan proceeds
/// rather than being abandoned over one bad interface.
///
/// Each surviving strategy gets its own task, tagged with its own
/// [`ScannerKind`], so the caller can wait on all of them and react to failures
/// individually.
pub(super) async fn spawn_explorers(
    plan: plan::DiscoveryPlan,
    ctx: &ScanContext,
    dns_tx: Option<UnboundedSender<IpAddr>>,
    tuning: ProbeTuning,
) -> Vec<(ScannerKind, JoinHandle<Result<(), StrategyError>>)> {
    for refusal in plan.refusals() {
        ctx.record_failure(refusal.scanner, refusal.reason.clone());
    }

    let mut explorers: Vec<Box<dyn HostScanner>> = Vec::new();
    for step in plan.into_steps() {
        let kind = step.kind();
        info!(
            verbosity = 1,
            "spawning {:?} scanner for {} target(s)",
            kind,
            step.target_count()
        );
        match step.into_scanner(ctx.clone(), dns_tx.clone(), tuning.clone()) {
            Ok(scanner) => explorers.push(scanner),
            Err(e) => ctx.record_failure(kind, e.to_string()),
        }
    }

    explorers
        .into_iter()
        .map(|mut explorer| {
            // Read before the strategy moves into its task: once it is running,
            // the only thing left to attribute a failure to is the handle.
            let kind = explorer.kind();
            (
                kind,
                tokio::spawn(async move { explorer.discover_hosts().await }),
            )
        })
        .collect()
}

/// Turns a [`PortScanPlan`](plan::PortScanPlan) into the single strategy
/// [`run_port_scan`] drives.
///
/// Every refusal is recorded first, for the same reason discovery records its
/// own: a protocol nobody probed has to be distinguishable from a protocol with
/// nothing open. A step that cannot open its socket is recorded and dropped, and
/// whatever built is wrapped in a
/// [`CompositePortScanner`](strategy::composite::CompositePortScanner), which
/// routes each target to a strategy that covers its protocol. One scanner comes
/// back either way, so the fork stays confined here.
pub(super) fn build_port_scanner(
    plan: plan::PortScanPlan,
    ctx: &ScanContext,
    target_count: usize,
    tuning: ProbeTuning,
) -> BuiltPortScan {
    for refusal in plan.refusals() {
        ctx.record_failure(refusal.scanner, refusal.reason.clone());
    }

    let technique = plan.technique();
    // Read before the steps are consumed. A protocol the plan never intended to
    // cover has already been refused above, in the same words, and must not be
    // refused a second time by the coverage check below.
    let intended: Vec<Protocol> = [Protocol::Tcp, Protocol::Udp]
        .into_iter()
        .filter(|protocol| plan.covers(*protocol))
        .collect();

    let mut scanners: Vec<Box<dyn PortScanner>> = Vec::new();
    let mut opened = Vec::new();
    for step in plan.into_steps() {
        match step.into_scanner(ctx.clone(), target_count, tuning.clone()) {
            Ok(scanner) => {
                opened.push(step);
                scanners.push(scanner);
            }
            Err(e) => ctx.record_failure(step.kind(), e.to_string()),
        }
    }

    BuiltPortScan {
        scanner: Box::new(strategy::composite::CompositePortScanner::new(
            ensure_coverage(
                scanners,
                ctx,
                technique,
                &intended,
                tuning.service_detection,
            ),
            ctx.clone(),
        )),
        opened,
    }
}

/// Backs the plan's intent with what actually opened: any protocol left without
/// a strategy gets the unprivileged one, or is refused.
///
/// **The plan cannot do this on its own, and that is the point of separating
/// them.** A plan says a raw TCP scanner and a raw UDP scanner should run. Only
/// the attempt discovers that this host permitted one raw socket and not the
/// other — a sandbox can do exactly that — and a protocol left with no strategy
/// at all is not a degraded scan but a silent one:
/// [`CompositePortScanner`](strategy::composite::CompositePortScanner) has
/// nowhere to route those targets, so they are never probed and never reported.
/// Asking what actually built, rather than assuming a privileged scan covers
/// everything, is what keeps that from happening.
///
/// **A connect fallback substitutes for a SYN scan and for nothing else.** It
/// completes handshakes, so it answers roughly the question a SYN scan asks; it
/// cannot send a FIN, a flagless segment or a bare ACK, and so cannot answer
/// what any of those were asked. Where the caller chose one of those and no raw
/// scanner opened, the TCP half is reported as a failure and left undone. That
/// is worse for the caller and honest, where a silent substitution would hand
/// back verdicts from a technique they did not choose - and no field in the
/// report would say so.
///
/// **`intended` is what keeps this from repeating the plan.** A protocol the
/// plan never meant to cover was already refused, in the words
/// [`Refusal::technique_needs_raw_sockets`](plan::Refusal::technique_needs_raw_sockets)
/// supplies, and saying it again puts one cause in the report twice. What is
/// left for this function is the narrower case the plan could not foresee: a
/// protocol it did intend, whose socket would not open.
pub(super) fn ensure_coverage(
    mut scanners: Vec<Box<dyn PortScanner>>,
    ctx: &ScanContext,
    technique: TcpScanTechnique,
    intended: &[Protocol],
    detection: ServiceDetection,
) -> Vec<Box<dyn PortScanner>> {
    let covered: Vec<Protocol> = scanners
        .iter()
        .flat_map(|scanner| scanner.supported_protocols())
        .collect();

    let missing = |protocol: Protocol| intended.contains(&protocol) && !covered.contains(&protocol);

    if missing(Protocol::Tcp) {
        if technique.finds_open_ports() {
            scanners.push(Box::new(strategy::connect::ConnectPortScanner::new(
                ctx.clone(),
                pacing::limits::CONNECT_CONCURRENCY,
                detection,
            )));
        } else {
            let refusal = plan::Refusal::technique_needs_raw_sockets(technique);
            ctx.record_failure(refusal.scanner, refusal.reason);
        }
    }

    if missing(Protocol::Udp) {
        scanners.push(Box::new(strategy::connect::ConnectUdpPortScanner::new(
            ctx.clone(),
            pacing::limits::CONNECT_CONCURRENCY,
        )));
    }

    scanners
}

/// A port-scan strategy, and which of the planned steps actually opened.
///
/// The second half is not decoration. Host enrichment is worth running only
/// alongside a raw scan — it is the raw paths that yield a MAC and an RTT — and
/// whether a raw scan is happening is answerable only after the sockets were
/// asked for, not from the privilege the process holds.
///
/// The steps are kept rather than their [`ScannerKind`]s, because "did this
/// need raw sockets" is the question being asked and a strategy's name is a
/// different fact about it. Answered from the name, this silently stopped
/// enriching every scan whose technique was not a SYN.
pub(super) struct BuiltPortScan {
    pub(super) scanner: Box<dyn PortScanner>,
    opened: Vec<plan::PortScanStep>,
}

impl BuiltPortScan {
    /// Whether any raw-socket strategy is among what opened.
    pub(super) fn opened_raw(&self) -> bool {
        self.opened.iter().any(plan::PortScanStep::is_raw)
    }
}

/// Drives one port-scan strategy to completion. It streams targets through the
/// strategy, and when the strategy succeeds and the scan was not aborted, lets
/// the strategy run its own service-detection pass (a no-op for strategies that
/// fingerprint inline).
///
/// A strategy failure is reported on the event stream, tagged with the
/// strategy's own [`ScannerKind`], and otherwise swallowed so the surrounding
/// scan (host enrichment and DNS) still finishes.
pub(super) async fn run_port_scan(
    mut scanner: Box<dyn PortScanner>,
    rx: mpsc::Receiver<PlannedTarget>,
    ctx: &ScanContext,
) {
    let kind = scanner.kind();
    match scanner.scan(rx).await {
        Ok(()) => {
            if !ctx.handle.should_stop() {
                scanner.detect_services(ctx).await;
            }
        }
        Err(e) => ctx.record_failure(kind, e.to_string()),
    }
}

/// Completes the hostname-resolution tail of a scan.
///
/// A privileged scan spawns passive DNS and mDNS resolution as part of its
/// [`Enrichment`]; awaiting that here folds the collected hostnames and extra
/// IPs into the store along with the rest of the enrichment strategies. An
/// unprivileged scan has no enrichment, so it falls back to active reverse
/// lookups when DNS is enabled and does nothing when it is not. This is the
/// single place the "passive when privileged, active otherwise" policy lives.
pub(super) async fn finish_enrichment(
    enrichment: Option<Enrichment>,
    caps: ScanCapabilities,
    ctx: &ScanContext,
) {
    match enrichment {
        Some(enrichment) => enrichment.finish(ctx).await,
        None if caps.dns => resolver::resolve_hosts_async(ctx).await,
        None => {}
    }
}

/// Reads an operating system out of what the scan already knows, sending
/// nothing.
///
/// This is [`OsDetection::Passive`] applied to a phase that had no way to apply
/// it. The port scanner reads a stack off the segments it drew and the echo
/// prober reads one off a ping it sent, but host discovery draws neither — so
/// until now a discovery sweep concluded nothing about any host, however much it
/// had learned about it. A machine whose hardware address names its maker and
/// whose hostname is the one its system generated was sitting in the store,
/// unread.
///
/// Runs after enrichment and not before it: [`os::hostname_evidence`] reads a
/// name, and the name arrives on the resolver's tail. Ordering this earlier
/// would consult a store that has not been told the hostnames yet.
///
/// ## What it will and will not conclude
///
/// The two sources it has are each, deliberately, below the floor
/// [`os::resolve`] reports at — so neither names a host alone, and a sweep of a
/// network of randomly-addressed phones concludes nothing at all. Two agreeing
/// sources clear it: an Apple address under a default `MacBook-Pro` name is a
/// verdict, where either alone is a guess. That is the intended yield and it is
/// a small one. It is not a substitute for reading a stack off the wire; it is
/// the part of passive identification that costs nothing and was simply not
/// wired up.
pub(super) fn run_passive_os_identification(ctx: &ScanContext, os_detection: OsDetection) {
    // `Off` means identify nothing and record nothing about the stacks that
    // answered. It costs no packets to disobey that, which is exactly why it
    // has to be obeyed here: a caller who asked for a report containing only
    // what they requested would otherwise find a fingerprint in it.
    if matches!(os_detection, OsDetection::Off) {
        return;
    }

    let mut named = 0usize;
    for ip in ctx.host_addresses() {
        let mut identified = false;
        ctx.write_host(ip, |host| {
            identified = os::identify(host, []);
            identified
        });
        if identified {
            named += 1;
        }
    }

    if named > 0 {
        info!(
            verbosity = 1,
            "named {named} host(s) from what the sweep already knew"
        );
    }
}

/// Runs the active operating-system series probe, where the caller asked for it
/// and a host has a TCP port worth asking again.
///
/// # Why this runs before the echo probe
///
/// The two active probes reach different hosts and read different things, and
/// this one is the stronger of the pair wherever it applies. It revisits ports
/// whose state the port scan already settled, so it needs a host that answered
/// *something* over TCP — and for such a host it reads the identifier, sequence
/// and clock policies that no single reply carries. The echo probe is the route
/// to the host that answered nothing at all, where a hop counter and an echoed
/// code are all there is. Running the series first means the echo pass sees a
/// store in which everything reachable by TCP has already been read.
///
/// # What each level asks for
///
/// At [`OsDetection::Active`] this follows the hosts a scan could not settle:
/// every host that is up, has a TCP answer, and is not already named with high
/// confidence. At [`OsDetection::Aggressive`] it follows **every** host with a
/// TCP answer and takes twice the samples — which is what somebody measuring
/// hosts they already know the answer for wants, and is the reading a new rule
/// is authored from.
///
/// Declines quietly rather than failing when there is nothing to do.
pub(super) async fn run_active_os_series(
    ctx: &ScanContext,
    os_detection: OsDetection,
    tuning: ProbeTuning,
) {
    if !os_detection.is_active() {
        return;
    }
    let thorough = matches!(os_detection, OsDetection::Aggressive);

    let targets: Vec<strategy::routed::SeriesTarget> = ctx
        .host_addresses()
        .into_iter()
        .filter_map(|key| {
            let key = key.clone();
            ctx.read_host(&key, |host| {
                if !host.status().is_up() {
                    return None;
                }
                // A host already named with high confidence is not worth more
                // packets at `Active`: nothing this probe can read would change
                // the answer, and the level's whole premise is that its traffic
                // was asked for.
                let settled = host.os().is_some_and(|os| os.accuracy() >= 85);
                if settled && !thorough {
                    return None;
                }
                strategy::routed::SeriesTarget::for_host(key.clone(), host)
            })
            .flatten()
        })
        .collect();

    if targets.is_empty() {
        return;
    }

    let samples = if thorough {
        strategy::routed::AGGRESSIVE_SAMPLES
    } else {
        strategy::routed::ACTIVE_SAMPLES
    };
    info!("following {} host(s) over {samples} samples", targets.len());

    match strategy::routed::OsSeriesScanner::new(ctx.clone(), targets, samples, tuning.send_mode) {
        Ok(mut scanner) => {
            if let Err(e) = scanner.discover_hosts().await {
                ctx.record_failure(ScannerKind::OsSeries, e.to_string());
            }
        }
        // The raw TCP socket would not open, most likely for want of
        // privileges. One recorded line, not a per-host failure: every host
        // keeps the answer the passive sources gave it.
        Err(e) => ctx.record_failure(
            ScannerKind::OsSeries,
            format!("the active series probe could not open its transport: {e}"),
        ),
    }
}

/// Asks each host that has not said what kernel it runs, by SNMP.
///
/// One `GetRequest` for `sysDescr.0` per host, and on anything that answers, the
/// exact kernel — because on a Unix host `sysDescr` is the output of `uname -a`.
///
/// # Why this is worth a phase of its own
///
/// It is the only thing this engine can reach that states a kernel version. A
/// TCP stack's shape identifies a *family* and cannot do more: Debian 12
/// (kernel 6.1) and Debian 13 (kernel 6.12) answer this engine's probe with
/// byte-identical shapes, measured on both. A service banner names a
/// distribution release at best. An agent answering here answers outright, and a
/// kernel version is the single most actionable thing a scan can learn about a
/// Unix host, because it is what a known-vulnerability lookup keys on.
///
/// # What comes back from a box that has no kernel to name
///
/// An appliance answers with its own identity instead — `Brother NC-8700w,
/// Firmware Ver.ZL` — and that is not a failed probe. It is a make, a model, a
/// firmware and a device class off one datagram, on a host the rest of the scan
/// could only place as *something with an initial hop count of 255*. The phase
/// is named for the kernel because that is what justifies it; it is worth
/// running for either answer.
///
/// # Why it does not simply add a port to the scan
///
/// Because a detection *level* and a port *list* are different dials, and
/// crossing them would mean `--ports 80 -O` sending probes to a port the caller
/// excluded. It would also be slower for no gain: establishing UDP port state
/// means waiting on ICMP unreachables, which targets rate-limit, and this phase
/// needs no port state at all. It asks a question and reads the answer.
///
/// # It does record the port
///
/// A host that answers an SNMP request has proved something is listening, more
/// directly than a SYN+ACK proves it, and a scanner that knew a port was open
/// and did not say so would be withholding a finding. An open agent answering
/// the default `public` community is also a finding in its own right — arguably
/// a more actionable one than the kernel it just disclosed.
///
/// The port is filed with the evidence that found it —
/// [`ScanResponse::UdpResponse`] — so a report can distinguish it from one the
/// port scan established and never has to pretend it was asked for.
///
/// This is the *opposite* of widening `--ports`, not an exception to it. The
/// objection there is to sending traffic nobody requested; the traffic here was
/// requested, by `-O`, and what is at stake is only whether the answer is
/// reported or discarded.
///
/// # Who is asked
///
/// Every host that is up and whose kernel is still unknown — which is a
/// different and better test than "could not be named". A host already reported
/// as `Linux · Debian 13` has been named perfectly well and still has nothing to
/// say about its kernel, so it is exactly the host worth asking.
pub(super) async fn run_active_os_snmp(ctx: &ScanContext, os_detection: OsDetection) {
    if !os_detection.is_active() {
        return;
    }

    let targets: Vec<crate::model::ip::scoped::ScopedIp> = ctx
        .host_addresses()
        .into_iter()
        .filter_map(|ip| {
            ctx.read_host(&ip, |host| {
                let known = host.os().is_some_and(|os| os.kernel().is_some());
                (host.status().is_up() && !known).then(|| host.scoped_ip())
            })
            .flatten()
        })
        .collect();

    if targets.is_empty() {
        return;
    }

    info!("asking {} host(s) for their kernel", targets.len());

    let mut named = 0usize;
    let mut pool = ProbePool::new(
        CONNECT_CONCURRENCY,
        ctx.clone(),
        ScannerKind::OsSnmp,
        |found: Option<(
            crate::model::ip::scoped::ScopedIp,
            Port,
            Vec<os::OsEvidence>,
        )>,
         _audit| {
            if let Some((key, port, evidence)) = found {
                ctx.update_host(key, |host| {
                    host.add_port(port);
                    if os::identify(host, evidence) {
                        named += 1;
                    }
                });
            }
        },
    );

    for target in targets {
        if ctx.handle.should_stop() {
            break;
        }
        pool.admit(ask_for_kernel(target)).await;
    }
    pool.drain().await;

    if named > 0 {
        info!(verbosity = 1, "named {named} host(s) by SNMP");
    }
}

/// The port an SNMP agent listens on. Fixed: an agent elsewhere is one nothing
/// could have found without being told, and guessing at others would be a port
/// scan rather than a question.
const SNMP_PORT: u16 = 161;

/// Sends one SNMP request to `target` and returns what the answer said about the
/// machine.
///
/// A link-local address with no interface recorded against it yields no socket
/// address at all and is skipped: dialling it anyway would fail with an error
/// describing this host's routing rather than anything about the target.
async fn ask_for_kernel(
    target: crate::model::ip::scoped::ScopedIp,
) -> Option<(
    crate::model::ip::scoped::ScopedIp,
    Port,
    Vec<os::OsEvidence>,
)> {
    let addr = target.to_socket_addr(SNMP_PORT)?;

    let port = crate::fingerprint::baseline_port(SNMP_PORT, Protocol::Udp, PortState::Open);
    let (port, evidence) = crate::fingerprint::fingerprint_udp_detailed(addr, port).await?;

    // Recorded with what found it, so a report can tell this port from one the
    // port scan established — and never has to imply it was asked for.
    let port = port.with_discovery(PortDiscovery::new(ScanResponse::UdpResponse));
    // The key, not the address: an SNMP agent on a link-local neighbour is
    // reachable here — `to_socket_addr` put the scope id on the socket — and
    // writing the answer back bare would fork the host's record.
    Some((target, port, evidence))
}

/// Runs the active operating-system echo probe, where the caller asked for it
/// and the passive sources left hosts unnamed.
///
/// Target selection is from the store and not from the plan, deliberately: "the
/// passive sources concluded nothing" is only true once those sources have
/// finished, and the store is where that conclusion lives. Every host that
/// answered nothing a TCP rule could read — a stock Windows firewall drops
/// rather than refuses — is here, and an echo reply is the one packet such a
/// host still gives.
///
/// Runs after [`run_active_os_series`], which has by then read everything a
/// host with an open or closed TCP port can be made to say. What is left here is
/// the machine that answered no TCP probe at all, and one ping is the cheapest
/// thing that still reaches it.
///
/// Declines quietly rather than failing when there is nothing to do: a scan
/// where every host was already named, or where none were, has not lost
/// anything by not pinging.
/// Measures the route to every host the scan found alive, when asked to.
///
/// Runs last, after the ports are known, and that ordering is the whole reason
/// it is a separate phase rather than part of discovery. What reaches a host
/// decides what a trace to it should be made of, and the port scan is what
/// establishes that — a host with 443 open is traced with SYNs to 443, which
/// crosses filters no ping survives. Run before the ports were known, every
/// trace would fall back to echo and most of them would stop at the first
/// firewall.
///
/// Hosts that answered nothing are skipped rather than traced. A path is
/// measured backwards from its far end and the far end's distance comes out of
/// a reply, so there is nothing to measure from; see
/// [`traceroute`](crate::scanner::strategy::routed::traceroute).
pub(super) async fn run_traceroute(ctx: &ScanContext, cfg: &crate::config::ZondConfig) {
    if !cfg.traceroute {
        return;
    }

    let mut alive: Vec<IpAddr> = ctx
        .host_addresses()
        .into_iter()
        .filter(|key| {
            ctx.read_host(key, |host| host.status().is_up())
                .unwrap_or(false)
        })
        .filter_map(routable)
        .collect();
    alive.sort_unstable();
    alive.dedup();

    if alive.is_empty() {
        return;
    }

    info!("measuring the route to {} host(s)", alive.len());
    strategy::routed::traceroute::trace(ctx, alive).await;
}

pub(super) async fn run_active_os_probe(
    ctx: &ScanContext,
    os_detection: crate::config::OsDetection,
    tuning: ProbeTuning,
) {
    if !os_detection.is_active() {
        return;
    }

    // A host worth pinging is one the scan found and could not name. Hosts the
    // scan never recorded were never asked about, and pinging addresses nobody
    // named is a discovery sweep rather than identification.
    let mut unnamed: Vec<IpAddr> = ctx
        .host_addresses()
        .into_iter()
        .filter(|key| {
            ctx.read_host(key, |host| {
                host.status().is_up() && host.os().is_none_or(|os| os.accuracy() < 85)
            })
            .unwrap_or(false)
        })
        .filter_map(routable)
        .collect();
    unnamed.sort_unstable();
    unnamed.dedup();

    if unnamed.is_empty() {
        return;
    }

    info!(
        "probing {} host(s) the passive sources could not name, by echo",
        unnamed.len()
    );

    match strategy::routed::OsEchoScanner::new(ctx.clone(), unnamed, tuning) {
        Ok(mut scanner) => {
            if let Err(e) = scanner.discover_hosts().await {
                ctx.record_failure(ScannerKind::OsEcho, e.to_string());
            }
        }
        // The raw ICMP socket would not open, most likely for want of
        // privileges. One recorded line, not a per-host failure: every host
        // keeps the answer the passive sources gave it, which is the state the
        // caller was already looking at.
        Err(e) => ctx.record_failure(
            ScannerKind::OsEcho,
            format!("the active echo probe could not open its transport: {e}"),
        ),
    }
}

/// Collects every target address from a [`TargetMap`] into an [`IpSet`], so the
/// host-enrichment phase knows which addresses to identify.
pub(super) fn target_ips(target_map: &TargetMap) -> IpSet {
    let mut ips = IpSet::new();
    for unit in &target_map.units {
        for range in unit.ips().v4() {
            ips.insert_range(IpRange::V4(*range));
        }
        for range in unit.ips().v6() {
            ips.insert_range(IpRange::V6(*range));
        }
    }
    ips.canonicalize();
    ips
}

/// Starts the background hostname resolver as its own task.
///
/// The resolver listens for raw DNS and mDNS traffic and answers reverse lookups
/// for any IP sent down `dns_rx`, independent of and concurrent with whatever
/// scanning strategies are running. When it fails to start, most likely because
/// no usable network socket could be opened, the failure is logged and `None` is
/// returned rather than propagated, since a scan without hostname resolution is
/// still useful.
pub(super) async fn spawn_resolver(
    dns_rx: UnboundedReceiver<IpAddr>,
) -> JoinHandle<Option<HostnameResolver>> {
    tokio::spawn(async move {
        match HostnameResolver::new(dns_rx) {
            Ok(resolver) => {
                success!("successfully initialized hostname resolver");
                Some(resolver.run().await)
            }
            Err(e) => {
                error!("resolver failed to start: {e}");
                None
            }
        }
    })
}

/// Probes `target_map`'s ports, enriching the hosts as it goes.
///
/// Nothing is opened for an empty map. A liveness phase that found nothing is a
/// finished answer, and raw sockets held to probe no targets are a failure this
/// would report for no reason.
pub(super) async fn run_port_phase(
    target_map: TargetMap,
    live: Option<IpSet>,
    ctx: &ScanContext,
    caps: ScanCapabilities,
    cfg: &ZondConfig,
    settled: Checkpoint,
) {
    if target_map.is_empty() {
        return;
    }

    let target_count = target_map.gross_targets().unwrap_or(0) as usize;
    let built = build_port_scanner(
        super::plan::PortScanPlan::build(cfg, caps.privileged),
        ctx,
        target_count,
        cfg.probe_tuning(),
    );

    // Only when nothing has enriched these hosts already. With the liveness
    // phase on, it has: the pass that established they are there is the same one
    // that reads their hardware addresses and names.
    let enrichment = if cfg.assume_up && built.opened_raw() {
        let plan = super::plan::DiscoveryPlan::build(target_ips(&target_map), Scope::Targeted);
        Some(Enrichment::spawn(plan, ctx, caps, cfg.probe_tuning()).await)
    } else {
        None
    };

    // Numbered against the whole plan and filtered afterwards — to what an
    // earlier sitting did not settle, and to the hosts that answered. Both
    // filters run after the numbering, because both of them are properties of
    // this sitting and the numbering is a property of the job.
    let mut dispatcher = super::dispatcher::Dispatcher::new(target_map).resuming(settled);
    if let Some(live) = live {
        dispatcher = dispatcher.only_live(live);
    }
    let rx = dispatcher.run_shuffled(ctx);

    run_port_scan(built.scanner, rx, ctx).await;
    finish_enrichment(enrichment, caps, ctx).await;
    // Passive first, then active: the echo probe is aimed at the hosts the
    // passive sources could not name, and it can only know which those are once
    // they have run.
    run_passive_os_identification(ctx, cfg.os_detection);
}

/// The plan as the port phase actually probed it.
///
/// **Not what the dispatcher walks.** That is the whole plan, so that a position
/// means the same target in every sitting — see
/// [`live_addresses`]. This is what the phase *covered*, which is a different
/// number and the one a [`TargetScope`](crate::scanner::report::TargetScope)
/// records: a reader compares it against the liveness phase's to see how much of
/// what they asked about went unprobed, and a scope that claimed the whole plan
/// would report a scan that covered ground it deliberately skipped.
///
/// Narrows every unit rather than rebuilding one set against one port list,
/// because a unit may carry ports no other one does — `10.0.0.1:8080` names its
/// own, and a subset that dropped that would answer a different question.
pub(super) fn probed_subset(target_map: &TargetMap, live: &IpSet) -> TargetMap {
    let mut kept = TargetMap::new();
    for unit in &target_map.units {
        let mut ips = IpSet::new();
        for ip in live.iter() {
            if unit.ips().contains(&ip) {
                push_single(&mut ips, ip, None);
            }
        }
        ips.canonicalize();

        if !ips.is_empty() {
            kept.add_unit(TargetSet::new(ips, unit.ports().clone()));
        }
    }

    kept
}

/// Every address the liveness pass found a host at.
///
/// **A set rather than a narrowed plan.** The port phase used to be handed a
/// `TargetMap` rebuilt from these, and the dispatcher numbered *that* — so a
/// position was counted in a plan that depended on which hosts happened to
/// answer, and two sittings of one job could disagree about what position 400
/// meant. The addresses travel to
/// [`Dispatcher::only_live`](crate::scanner::dispatcher::Dispatcher::only_live)
/// instead, which filters after numbering.
///
/// Every address of a host is included, not only the one it is filed under. A
/// dual-stack machine found over IPv6 is still the machine whose IPv4 address
/// was asked about, and a unit naming either of them meant this host.
pub(super) fn live_addresses(ctx: &ScanContext) -> IpSet {
    let mut live = IpSet::new();
    for entry in ctx.store.iter() {
        let host = entry.value();
        if !host.is_alive() {
            continue;
        }
        for ip in host.ips() {
            push_single(&mut live, *ip, host.zone().and_then(Zone::index));
        }
    }
    live.canonicalize();
    live
}

/// Pushes one address into `set` as a range of itself.
///
/// The address a raw routed probe can be aimed at, or `None` for a host it
/// cannot reach.
///
/// **This is where the store's key becomes a bare address, and the one place a
/// key may be narrowed to one.** The strategies below it — the trace, the echo
/// probe — reach a host over the routing table and reason in addresses from end
/// to end: a socket takes one, a reply carries one, and a hop table is keyed by
/// one. Handing them a `ScopedIp` would key their reply matching on something no
/// reply carries.
///
/// So they are given what they can use, and a host whose address is meaningless
/// without an interface is not given at all. `fe80::1` cannot be routed — the
/// kernel needs a scope id and a raw routed probe has nowhere to put one, which
/// is the same refusal [`ScopedIp::to_socket_addr`] makes rather than attempting
/// a send that fails for a reason having nothing to do with the target. Those
/// hosts are the local scanner's, which reaches them at the link layer and
/// already holds them under the interface they were read on.
///
/// It also keeps the store honest. A routed strategy writes its finding back
/// under the address it probed, and an address that is not the whole key would
/// land in a second entry — one host in the report becoming two, each holding
/// half of what was found.
fn routable(key: crate::model::ip::scoped::ScopedIp) -> Option<IpAddr> {
    (!crate::model::ip::scoped::ScopedIp::needs_zone(&key.addr())).then(|| key.addr())
}

/// The zone is kept only for the addresses that cannot be reached without one:
/// `fe80::1` names a different machine on every segment.
fn push_single(set: &mut IpSet, ip: IpAddr, zone: Option<u32>) {
    match ip {
        IpAddr::V4(v4) => {
            if let Ok(range) = Ipv4Range::new(v4, v4) {
                set.push_v4_range(range);
            }
        }
        IpAddr::V6(v6) => {
            let zone = v6.is_unicast_link_local().then_some(zone).flatten();
            if let Ok(range) = Ipv6Range::scoped(v6, v6, zone) {
                set.push_v6_range(range);
            }
        }
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
    use crate::model::host::{Host, HostStatus};
    use crate::scanner::report::ScannerFailure;
    use crate::scanner::session::ScanSession;
    use tokio::sync::mpsc;

    /// A scanner that claims a protocol and does nothing, standing in for a
    /// privileged strategy that was built successfully.
    struct StubScanner(Vec<Protocol>);

    #[async_trait::async_trait]
    impl PortScanner for StubScanner {
        fn kind(&self) -> ScannerKind {
            ScannerKind::SynPort
        }

        fn supported_protocols(&self) -> Vec<Protocol> {
            self.0.clone()
        }

        async fn scan(
            &mut self,
            _targets: mpsc::Receiver<PlannedTarget>,
        ) -> Result<(), StrategyError> {
            Ok(())
        }
    }

    /// A plan that meant to cover both protocols, which is every plan except
    /// the one that refused a technique its fallback cannot express.
    const BOTH: &[Protocol] = &[Protocol::Tcp, Protocol::Udp];

    fn ip_set(exprs: &[&str]) -> IpSet {
        crate::model::parse::ip::to_set(exprs, None, None).expect("hand-written targets parse")
    }

    /// The defect this function exists for. A `/64` handed to the unprivileged
    /// path was probed one address at a time until the process was killed, while
    /// the same range with root was refused in the plan before a packet was
    /// sent — one engine giving two answers about one range.
    #[test]
    fn a_range_too_large_to_walk_is_refused_rather_than_started() {
        let (_session, ctx) = ScanSession::new();

        let kept = walkable(ip_set(&["2001:db8::/64"]), &ctx);

        assert!(kept.is_empty(), "nothing here can be walked");

        let failures = ctx.failures_snapshot();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].scanner(), ScannerKind::Connect);
        assert!(
            failures[0].reason().contains("18446744073709551616"),
            "the refusal quotes the size it is refusing: {}",
            failures[0].reason()
        );
    }

    /// Refusing the whole set over one unwalkable range in it would discard
    /// addresses somebody named and could have had.
    #[test]
    fn the_walkable_part_of_a_mixed_set_survives() {
        let (_session, ctx) = ScanSession::new();

        let kept = walkable(
            ip_set(&["2001:db8::/64", "10.0.0.0/30", "2001:db8:1::/126"]),
            &ctx,
        );

        // Four IPv4 addresses and the four in the /126; the /64 is gone.
        assert_eq!(kept.len(), 8);
        assert_eq!(ctx.failures_snapshot().len(), 1);
    }

    /// A set that is entirely walkable is handed back untouched, and — the part
    /// that matters — files no failure. A report claiming a refusal that never
    /// happened marks a complete scan as partial.
    #[test]
    fn a_set_that_can_be_walked_is_left_alone_and_files_nothing() {
        let (_session, ctx) = ScanSession::new();

        let kept = walkable(ip_set(&["10.0.0.0/24", "2001:db8::/120"]), &ctx);

        assert_eq!(kept.len(), 512);
        assert!(ctx.failures_snapshot().is_empty());
    }

    /// IPv4 is deliberately not bounded here. A `/8` is sixteen million probes,
    /// which is unreasonable rather than impossible, and which of those it is is
    /// a judgement for whoever is driving the engine.
    #[test]
    fn a_large_ipv4_range_is_not_this_functions_business() {
        let (_session, ctx) = ScanSession::new();

        let kept = walkable(ip_set(&["10.0.0.0/8"]), &ctx);

        assert_eq!(kept.len(), 1 << 24);
        assert!(ctx.failures_snapshot().is_empty());
    }

    fn covered(scanners: Vec<Box<dyn PortScanner>>) -> Vec<Protocol> {
        let (_session, ctx) = ScanSession::new();
        ensure_coverage(
            scanners,
            &ctx,
            TcpScanTechnique::Syn,
            BOTH,
            ServiceDetection::default(),
        )
        .iter()
        .flat_map(|scanner| scanner.supported_protocols())
        .collect()
    }

    /// The plan refuses what it can foresee and `ensure_coverage` catches what
    /// only the attempt reveals. Both had the same words for the same cause, so
    /// an unprivileged flag-probe scan recorded the identical failure twice:
    /// once from the plan's refusal and once from the coverage check that did
    /// not know the plan had already spoken.
    ///
    /// A consumer counting failures over-reports, and one rendering them shows
    /// the same paragraph to a user twice.
    #[test]
    fn a_refusal_the_plan_already_made_is_not_recorded_again() {
        let cfg = ZondConfig {
            tcp_technique: TcpScanTechnique::Fin,
            ..ZondConfig::default()
        };
        let (_session, ctx) = ScanSession::new();

        let _built = build_port_scanner(
            plan::PortScanPlan::build(&cfg, false),
            &ctx,
            0,
            cfg.probe_tuning(),
        );

        let failures = ctx.take_failures();
        assert_eq!(
            failures.len(),
            1,
            "one cause, one entry: {:?}",
            failures
                .iter()
                .map(ScannerFailure::reason)
                .collect::<Vec<_>>()
        );
        assert_eq!(failures[0].scanner(), ScannerKind::TcpPort);
        assert!(failures[0].reason().contains("fin"));
    }

    /// Host enrichment is keyed on whether a raw scan is happening, and a raw
    /// scan is one whatever segment its probes carry. Read off the strategy's
    /// name instead, a FIN scan stopped counting as raw the moment it stopped
    /// being called `syn_port`, and every non-SYN privileged scan quietly lost
    /// its MAC addresses and round trips.
    #[test]
    fn a_raw_scan_earns_enrichment_whichever_technique_it_carries() {
        for technique in TcpScanTechnique::ALL {
            let built = BuiltPortScan {
                scanner: Box::new(StubScanner(vec![Protocol::Tcp])),
                opened: vec![plan::PortScanStep::RawTcp { technique }],
            };
            assert!(built.opened_raw(), "a raw {technique} scan is still raw");
        }

        let unprivileged = BuiltPortScan {
            scanner: Box::new(StubScanner(vec![Protocol::Tcp])),
            opened: vec![
                plan::PortScanStep::ConnectTcp,
                plan::PortScanStep::ConnectUdp,
            ],
        };
        assert!(
            !unprivileged.opened_raw(),
            "a connect scan has no MAC or round trip to offer"
        );
    }

    /// With no privileged scanner at all, both connect fallbacks stand in.
    #[test]
    fn an_unprivileged_scan_covers_both_protocols() {
        let protocols = covered(Vec::new());
        assert!(protocols.contains(&Protocol::Tcp));
        assert!(protocols.contains(&Protocol::Udp));
    }

    /// The regression guard for the per-protocol fallback: a host that could
    /// build the raw UDP scanner but not the SYN one must still probe TCP.
    /// Gating on "any privileged scanner exists" left those targets with no
    /// route at all, so they were dropped without a record.
    #[test]
    fn a_protocol_without_a_privileged_scanner_still_gets_a_fallback() {
        let protocols = covered(vec![Box::new(StubScanner(vec![Protocol::Udp]))]);
        assert!(
            protocols.contains(&Protocol::Tcp),
            "TCP targets would be silently dropped"
        );
        assert!(protocols.contains(&Protocol::Udp));
    }

    /// A connect scan is a substitute for a SYN scan and for nothing else. Asked
    /// for a technique it cannot express, an unprivileged scan has to leave the
    /// TCP half undone and say so - a silent substitution would hand back
    /// verdicts from a technique nobody chose.
    ///
    /// The case is a plan that *did* intend TCP, whose raw socket then would
    /// not open. A plan that never intended it refused before reaching here;
    /// see `a_refusal_the_plan_already_made_is_not_recorded_again`.
    #[test]
    fn a_technique_the_fallback_cannot_express_is_reported_rather_than_substituted() {
        let (_session, ctx) = ScanSession::new();
        let scanners = ensure_coverage(
            Vec::new(),
            &ctx,
            TcpScanTechnique::Fin,
            BOTH,
            ServiceDetection::default(),
        );
        let protocols: Vec<Protocol> = scanners
            .iter()
            .flat_map(|scanner| scanner.supported_protocols())
            .collect();

        assert!(
            !protocols.contains(&Protocol::Tcp),
            "a connect scan cannot send a FIN and must not pretend to"
        );

        let failures = ctx.take_failures();
        assert_eq!(failures.len(), 1, "the caller has to be told");
        assert_eq!(failures[0].scanner(), ScannerKind::TcpPort);
        assert!(
            failures[0].reason().contains("fin"),
            "the failure has to name the technique: {}",
            failures[0].reason()
        );
    }

    /// And the mirror case: raw TCP available, raw UDP not.
    #[test]
    fn a_privileged_tcp_only_scan_falls_back_for_udp() {
        let protocols = covered(vec![Box::new(StubScanner(vec![Protocol::Tcp]))]);
        assert!(protocols.contains(&Protocol::Tcp));
        assert!(
            protocols.contains(&Protocol::Udp),
            "UDP targets would be silently dropped"
        );
    }

    /// When the privileged scanners already cover everything, no fallback is
    /// added - a connect scanner beside them would re-probe the same ports.
    #[test]
    fn fully_covered_protocols_gain_no_fallback() {
        let (_session, ctx) = ScanSession::new();
        let scanners = ensure_coverage(
            vec![
                Box::new(StubScanner(vec![Protocol::Tcp])),
                Box::new(StubScanner(vec![Protocol::Udp])),
            ],
            &ctx,
            TcpScanTechnique::Syn,
            BOTH,
            ServiceDetection::default(),
        );
        // Two scanners in, two scanners out: nothing was added beside them.
        assert_eq!(scanners.len(), 2);
    }

    /// The mirror of the double-record: a plan that never intended TCP gets no
    /// connect fallback for it either, however open-port-finding the technique
    /// would have been. Nothing intended it, so there is nothing to stand in
    /// for.
    #[test]
    fn a_protocol_the_plan_left_out_gains_no_fallback_and_no_second_refusal() {
        let (_session, ctx) = ScanSession::new();
        let scanners = ensure_coverage(
            Vec::new(),
            &ctx,
            TcpScanTechnique::Fin,
            &[Protocol::Udp],
            ServiceDetection::default(),
        );

        let protocols: Vec<Protocol> = scanners
            .iter()
            .flat_map(|scanner| scanner.supported_protocols())
            .collect();
        assert_eq!(protocols, vec![Protocol::Udp]);
        assert!(
            ctx.take_failures().is_empty(),
            "the plan already said why, in the same words"
        );
    }

    /// The gap this pass exists to close: a sweep that learned a host's hardware
    /// and its name, and concluded nothing from either.
    #[test]
    fn a_discovery_sweep_now_names_what_its_own_findings_imply() {
        let (_session, ctx) = ScanSession::new();
        let ip: IpAddr = "192.0.2.1".parse().expect("a valid address");

        ctx.update_host(ip, |host| {
            host.record_mac("a4:83:e7:00:00:01".parse().expect("an Apple address"));
            host.set_hostname(Some("MacBook-Pro".to_owned()));
        });

        run_passive_os_identification(&ctx, OsDetection::Passive);

        let named = ctx
            .read_host(ip, |host| host.os().map(ToString::to_string))
            .expect("the host is in the store");
        assert!(
            named.as_deref().is_some_and(|os| os.contains("macOS")),
            "{named:?}"
        );
    }

    /// `Off` means identify nothing. It costs no packets to disobey, which is
    /// exactly why obeying it has to be tested: a caller who asked for a report
    /// containing only what they requested must not find a fingerprint in it.
    #[test]
    fn detection_turned_off_identifies_nothing() {
        let (_session, ctx) = ScanSession::new();
        let ip: IpAddr = "192.0.2.1".parse().expect("a valid address");

        ctx.update_host(ip, |host| {
            host.record_mac("a4:83:e7:00:00:01".parse().expect("an Apple address"));
            host.set_hostname(Some("MacBook-Pro".to_owned()));
        });

        run_passive_os_identification(&ctx, OsDetection::Off);

        let named = ctx
            .read_host(ip, |host| host.os().is_some())
            .expect("the host is in the store");
        assert!(!named);
    }

    /// A host that has already said what kernel it runs is not asked again.
    ///
    /// The test is "is the kernel known", not "was the host named" — a host
    /// reported as `Linux · Debian 13` has been named perfectly well and still
    /// has nothing on record about its kernel, so it is exactly the host worth
    /// asking. Getting this backwards would skip the population the phase exists
    /// for.
    #[tokio::test(flavor = "current_thread")]
    async fn the_kernel_probe_skips_only_hosts_whose_kernel_is_known() {
        use crate::model::host::{HostStatus, OsFingerprint, StatusProtocol, StatusReason};

        let up = |host: &mut crate::model::host::Host| {
            host.record_evidence(
                HostStatus::Up,
                StatusReason::new(StatusProtocol::Arp, "an address resolution reply"),
            );
        };

        let (_session, ctx) = ScanSession::new();
        // Named, with no kernel: still worth asking.
        let named: IpAddr = "192.0.2.10".parse().expect("a valid address");
        ctx.update_host(named, |host| {
            up(host);
            host.set_os(OsFingerprint::new("Debian", 84).with_family("Linux"));
        });
        // Kernel already known: nothing left to ask for.
        let known: IpAddr = "192.0.2.11".parse().expect("a valid address");
        ctx.update_host(known, |host| {
            up(host);
            host.set_os(
                OsFingerprint::new("Debian", 84)
                    .with_family("Linux")
                    .with_kernel("6.1.0"),
            );
        });

        // TEST-NET-1 routes nowhere, so nothing answers and nothing is recorded.
        // What this pins is the selection: the phase must run at all, and must
        // not fail, for a store in exactly this state.
        run_active_os_snmp(&ctx, OsDetection::Active).await;

        assert!(ctx.take_failures().is_empty(), "declining is not failing");
        assert!(
            ctx.read_host(known, |host| host
                .os()
                .and_then(|os| os.kernel().map(ToOwned::to_owned)))
                .flatten()
                .as_deref()
                == Some("6.1.0"),
            "a kernel already on record is left as it was"
        );
    }

    /// A host that answers has proved a port open, and a scanner that knew and
    /// did not say would be withholding a finding.
    ///
    /// This was nearly built the other way, on the reasoning that 161 is not a
    /// port the caller asked to scan. That confuses two things: the objection to
    /// widening `--ports` is to sending traffic nobody requested, and this
    /// traffic *was* requested — by the detection level. Once it is sent, all
    /// that remains is whether the answer is reported or thrown away, and an
    /// open agent answering the default community is a finding in its own right.
    ///
    /// Recorded with the evidence that found it, so a report never has to imply
    /// it was asked for.
    #[test]
    fn a_port_the_kernel_probe_found_is_recorded_with_what_found_it() {
        let port = crate::fingerprint::baseline_port(161, Protocol::Udp, PortState::Open)
            .with_discovery(PortDiscovery::new(ScanResponse::UdpResponse));

        assert_eq!(port.number(), 161);
        assert_eq!(port.protocol(), Protocol::Udp);
        assert_eq!(port.state(), PortState::Open);
        assert_eq!(
            port.discovery().map(|found| found.reason().clone()),
            Some(ScanResponse::UdpResponse),
            "a report has to be able to tell this from a port the scan established"
        );
    }

    /// Below `Active` this sends nothing, like every other probe of its own.
    #[tokio::test(flavor = "current_thread")]
    async fn the_kernel_probe_sends_nothing_below_the_active_level() {
        for level in [OsDetection::Off, OsDetection::Passive] {
            let (_session, ctx) = ScanSession::new();
            let ip: IpAddr = "192.0.2.12".parse().expect("a valid address");
            ctx.update_host(ip, |host| {
                host.record_evidence(
                    crate::model::host::HostStatus::Up,
                    crate::model::host::StatusReason::new(
                        crate::model::host::StatusProtocol::Arp,
                        "an address resolution reply",
                    ),
                );
            });

            run_active_os_snmp(&ctx, level).await;

            assert!(
                ctx.take_probe_stats().is_empty(),
                "{level} put a probe on the wire"
            );
        }
    }

    /// The series probe opens a raw socket, so it must not open one to probe
    /// nothing. Every host here answered no TCP probe — which is the ordinary
    /// state after a discovery sweep — and the phase has to notice that from the
    /// store *before* reaching for a transport it would then have to report
    /// failing to get.
    #[tokio::test(flavor = "current_thread")]
    async fn the_series_probe_declines_when_no_host_has_a_port_to_ask_again() {
        let (_session, ctx) = ScanSession::new();
        let ip: IpAddr = "192.0.2.3".parse().expect("a valid address");
        ctx.update_host(ip, |host| {
            host.record_evidence(
                crate::model::host::HostStatus::Up,
                crate::model::host::StatusReason::new(
                    crate::model::host::StatusProtocol::Arp,
                    "an address resolution reply",
                ),
            );
        });

        run_active_os_series(&ctx, OsDetection::Active, ProbeTuning::default()).await;

        assert!(
            ctx.take_failures().is_empty(),
            "declining is not failing: there was nothing to follow, so nothing \
             should have been opened"
        );
        assert!(
            ctx.read_host(ip, |host| host.os().is_none())
                .expect("the host is in the store"),
            "and nothing may be concluded from probes that were never sent"
        );
    }

    /// Every level below `Active` sends nothing of its own, and this phase is
    /// the whole reason `is_active` exists. A caller at the default must find
    /// their scan byte-identical to one with detection off.
    #[tokio::test(flavor = "current_thread")]
    async fn the_series_probe_sends_nothing_below_the_active_level() {
        use crate::model::port::{Port, PortState, Protocol};

        for level in [OsDetection::Off, OsDetection::Passive] {
            let (_session, ctx) = ScanSession::new();
            let ip: IpAddr = "192.0.2.4".parse().expect("a valid address");
            // A host that *would* be followed, so the only thing declining the
            // phase is the level itself.
            ctx.update_host(ip, |host| {
                host.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
            });

            run_active_os_series(&ctx, level, ProbeTuning::default()).await;

            assert!(
                ctx.take_probe_stats().is_empty(),
                "{level} put a scanner on the wire"
            );
        }
    }

    /// The pass runs over every host a sweep found, and most of them have
    /// nothing to go on. That must leave them alone rather than guess.
    #[test]
    fn a_host_with_nothing_to_go_on_is_left_as_it_was() {
        let (_session, ctx) = ScanSession::new();
        let ip: IpAddr = "192.0.2.2".parse().expect("a valid address");

        ctx.update_host(ip, |host| {
            host.record_mac(
                "02:00:5e:00:53:04"
                    .parse()
                    .expect("a locally administered address"),
            );
        });

        run_passive_os_identification(&ctx, OsDetection::Passive);

        let named = ctx
            .read_host(ip, |host| host.os().is_some())
            .expect("the host is in the store");
        assert!(!named);
    }

    /// A context whose store already holds `hosts`, as a finished liveness phase
    /// would have left it.
    fn store_holding(hosts: Vec<Host>) -> (ScanSession, ScanContext) {
        let (session, ctx) = ScanSession::new();
        for host in hosts {
            ctx.store.insert(host.scoped_ip(), host);
        }
        (session, ctx)
    }

    fn host_at(ip: &str, status: HostStatus) -> Host {
        let mut host = Host::new(ip.parse().expect("an address"));
        host.set_status(status);
        host
    }

    /// A host the store holds but that never answered is not a host to spend a
    /// probe per port on.
    ///
    /// Worth testing rather than assuming: a target nothing answers for usually
    /// leaves *no* store entry at all, so this filter is only reached by a host
    /// that was recorded and still is not alive.
    #[test]
    fn a_host_that_did_not_answer_is_not_live() {
        for status in [HostStatus::Down, HostStatus::Unknown] {
            let (_session, ctx) = store_holding(vec![host_at("10.0.0.1", status)]);

            assert!(
                live_addresses(&ctx).is_empty(),
                "{status:?} was treated as alive"
            );
        }
    }

    #[test]
    fn a_host_that_answered_is_live() {
        let (_session, ctx) = store_holding(vec![host_at("10.0.0.1", HostStatus::Up)]);
        let live = live_addresses(&ctx);

        assert!(live.contains(&"10.0.0.1".parse::<IpAddr>().expect("an address")));
        assert_eq!(live.len(), 1);
    }

    /// A dual-stack machine is one host filed under one address. If it answered
    /// over IPv6, the IPv4 address somebody actually typed is still live — it is
    /// the same machine, and it is the one that was asked about.
    #[test]
    fn every_address_of_a_live_host_is_live() {
        let mut host = host_at("2001:db8::1", HostStatus::Up);
        host.add_ip("10.0.0.1".parse().expect("an address"));

        let (_session, ctx) = store_holding(vec![host]);
        let live = live_addresses(&ctx);

        assert!(
            live.contains(&"10.0.0.1".parse::<IpAddr>().expect("an address")),
            "the targeted address was lost because the host was filed elsewhere"
        );
        assert!(live.contains(&"2001:db8::1".parse::<IpAddr>().expect("an address")));
    }

    /// Nothing answered, so nothing is live. The plan is unchanged either way —
    /// what an empty answer costs is every one of its targets being settled as
    /// [`Skipped`](crate::journal::settle::Outcome::Skipped) rather than probed.
    #[test]
    fn an_empty_store_has_nothing_live() {
        let (_session, ctx) = store_holding(Vec::new());

        assert!(live_addresses(&ctx).is_empty());
    }
}
