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

use crate::config::{ProbeTuning, ZondConfig};
use crate::model::ip::range::IpRange;
use crate::model::{
    ip::set::IpSet,
    port::Protocol,
    target::{Target, TargetMap},
    technique::TcpScanTechnique,
};
use crate::scanner::resolver::HostnameResolver;
use crate::scanner::session::{ScanContext, ScannerKind};
use crate::scanner::strategy::{HostScanner, PortScanner, StrategyError};
use crate::scanner::{pacing, plan, resolver, strategy};
use crate::system::privilege::is_elevated;
use crate::{error, info, success, warn};

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
            success!("Root privileges detected, raw socket scan enabled");
        } else {
            warn!("Root privileges missing, defaulting to unprivileged TCP scan");
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
            "Spawning {:?} scanner for {} target(s)",
            kind,
            step.target_count()
        );
        match step.into_scanner(ctx.clone(), dns_tx.clone(), tuning) {
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
        match step.into_scanner(ctx.clone(), target_count, tuning) {
            Ok(scanner) => {
                opened.push(step);
                scanners.push(scanner);
            }
            Err(e) => ctx.record_failure(step.kind(), e.to_string()),
        }
    }

    BuiltPortScan {
        scanner: Box::new(strategy::composite::CompositePortScanner::new(
            ensure_coverage(scanners, ctx, technique, &intended),
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
    rx: mpsc::Receiver<Target>,
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
/// Declines quietly rather than failing when there is nothing to do: a scan
/// where every host was already named, or where none were, has not lost
/// anything by not pinging.
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
        .filter(|ip| {
            ctx.read_host(ip, |host| {
                host.status().is_up() && host.os().is_none_or(|os| os.accuracy() < 85)
            })
            .unwrap_or(false)
        })
        .collect();
    unnamed.sort_unstable();
    unnamed.dedup();

    if unnamed.is_empty() {
        return;
    }

    info!(
        "Probing {} host(s) the passive sources could not name, by echo",
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
                success!("Successfully initialized hostname resolver");
                Some(resolver.run().await)
            }
            Err(e) => {
                error!("Resolver failed to start: {e}");
                None
            }
        }
    })
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

        async fn scan(&mut self, _targets: mpsc::Receiver<Target>) -> Result<(), StrategyError> {
            Ok(())
        }
    }

    /// A plan that meant to cover both protocols, which is every plan except
    /// the one that refused a technique its fallback cannot express.
    const BOTH: &[Protocol] = &[Protocol::Tcp, Protocol::Udp];

    fn covered(scanners: Vec<Box<dyn PortScanner>>) -> Vec<Protocol> {
        let (_session, ctx) = ScanSession::new();
        ensure_coverage(scanners, &ctx, TcpScanTechnique::Syn, BOTH)
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
        let scanners = ensure_coverage(Vec::new(), &ctx, TcpScanTechnique::Fin, BOTH);
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
        let scanners = ensure_coverage(Vec::new(), &ctx, TcpScanTechnique::Fin, &[Protocol::Udp]);

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
}
