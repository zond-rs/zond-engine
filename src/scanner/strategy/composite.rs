// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Composite Port Scanner
//!
//! A port scanner that multiplexes targets across several underlying scanners.
//!
//! [`CompositePortScanner`] takes one stream of targets and routes each to the
//! first internal scanner whose [`PortScanner::supported_protocols`] claims its
//! protocol (TCP SYN, raw UDP, connect fallbacks, SCTP), so callers drive a single
//! scanner whatever the protocol mix.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::journal::settle::Outcome;
use crate::model::ip::set::IpSet;
use crate::model::port::Protocol;
use crate::model::target::PlannedTarget;
use crate::report::ScannerKind;
use crate::scanner::session::ScanContext;
use crate::scanner::strategy::{PortScanner, StrategyError, record_unasked};
use crate::{counted, info};

/// How many targets one route holds while its scanner is busy.
///
/// One buffer per protocol, so a slow scanner cannot stall the router for the
/// others. Deep enough to absorb a dispatcher batch arriving mid-send; memory
/// scales with the protocol count, not the plan size.
const ROUTE_DEPTH: usize = 1024;

/// Which addresses a scanner in a composite is handed.
///
/// Every scanner takes every address unless the scan's raw strategies send
/// frames alone: a frame reaches only what has Ethernet in front of it, and the
/// remaining targets go to a connect scanner beside it. See
/// [`beyond_frames`](crate::system::interface::beyond_frames).
#[derive(Debug, Clone, Default)]
pub(crate) enum Reach {
    /// Every address.
    #[default]
    Any,
    /// Only these.
    Only(Arc<IpSet>),
    /// Every address but these.
    Except(Arc<IpSet>),
}

impl Reach {
    /// Whether a scanner with this reach is handed `address`.
    fn admits(&self, address: &IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Only(set) => set.contains(address),
            Self::Except(set) => !set.contains(address),
        }
    }
}

/// A port scanner that multiplexes targets by protocol.
pub struct CompositePortScanner {
    /// Each scanner with the addresses it is handed. Every one is [`Reach::Any`]
    /// unless the composite was built by
    /// [`with_reach`](Self::with_reach).
    scanners: Vec<(Box<dyn PortScanner>, Reach)>,
    /// Each protocol the scan refused to probe, with the addresses the refusal
    /// covers. Empty unless the composite was built with
    /// [`refusing`](Self::refusing).
    refused: Vec<(Protocol, Reach)>,
    /// Where targets that never reached a scanner are reported.
    ///
    /// The router is the one place in a scan that can drop work without any
    /// strategy noticing, so it reports through the same channel as every other
    /// narrowing.
    ctx: ScanContext,
}

impl CompositePortScanner {
    /// Constructs a composite scanner from a collection of existing scanners.
    pub fn new(scanners: Vec<Box<dyn PortScanner>>, ctx: ScanContext) -> Self {
        Self::with_reach(
            scanners
                .into_iter()
                .map(|scanner| (scanner, Reach::Any))
                .collect(),
            ctx,
        )
    }

    /// Constructs a composite that routes by address as well as by protocol: a
    /// target goes to the first scanner that claims its protocol and whose
    /// [`Reach`] admits its address.
    pub(crate) fn with_reach(
        scanners: Vec<(Box<dyn PortScanner>, Reach)>,
        ctx: ScanContext,
    ) -> Self {
        Self {
            scanners,
            refused: Vec::new(),
            ctx,
        }
    }

    /// The same composite, told which targets the scan refused to probe: each
    /// protocol a refusal names, with the addresses it covers.
    ///
    /// A target the router can place nowhere was either refused, and a refusal in
    /// the report already says so, or lost by the scan. Both leave it unprobed and
    /// owed to a resume, but only a lost target is reported as a fault.
    pub(crate) fn refusing(mut self, refused: Vec<(Protocol, Reach)>) -> Self {
        self.refused = refused;
        self
    }
}

#[async_trait]
impl PortScanner for CompositePortScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::Composite
    }

    fn supported_protocols(&self) -> Vec<Protocol> {
        let mut protocols = Vec::new();
        for (scanner, _) in &self.scanners {
            for proto in scanner.supported_protocols() {
                if !protocols.contains(&proto) {
                    protocols.push(proto);
                }
            }
        }
        protocols
    }

    async fn scan(
        &mut self,
        mut targets: mpsc::Receiver<PlannedTarget>,
    ) -> Result<(), StrategyError> {
        struct Route {
            supported_protocols: Vec<Protocol>,
            reach: Reach,
            tx: mpsc::Sender<PlannedTarget>,
        }

        let mut routes = Vec::new();
        let mut handles = Vec::new();

        for (mut scanner, reach) in self.scanners.drain(..) {
            let (tx, rx) = mpsc::channel(ROUTE_DEPTH);
            let supported_protocols = scanner.supported_protocols();
            let kind = scanner.kind();

            let handle = tokio::spawn(async move {
                let res = scanner.scan(rx).await;
                (scanner, res)
            });

            handles.push((kind, reach.clone(), handle));
            routes.push(Route {
                supported_protocols,
                reach,
                tx,
            });
        }

        // Route each target to the first scanner that claims it. A target with no
        // route, or whose scanner has stopped listening, is counted so the scan can
        // say it covered less than asked; a refused target is covered by its refusal.
        //
        // A target whose scanner has stopped (its own deadline, or a dead transport)
        // is also recorded unasked on its host, or a truncated port list would read
        // the same as a complete one.
        let mut unroutable = 0usize;
        let mut undeliverable = 0usize;

        while let Some(target) = targets.recv().await {
            let (protocol, ip) = (target.protocol(), target.target.ip);
            match routes.iter().find(|route| {
                route.supported_protocols.contains(&protocol) && route.reach.admits(&ip)
            }) {
                Some(route) => {
                    if let Err(returned) = route.tx.send(target).await {
                        undeliverable += 1;
                        record_unasked(&self.ctx, &returned.0);
                    }
                }
                None => {
                    if !self
                        .refused
                        .iter()
                        .any(|(refused, reach)| *refused == protocol && reach.admits(&ip))
                    {
                        unroutable += 1;
                    }
                    self.ctx.record_outcome(Outcome::Unroutable);
                }
            }
        }

        // Recorded as a failure, not logged: a warning reaches neither the report
        // nor the event stream, so a consumer could not tell a narrowed scan from an
        // empty network. One entry carries both counts because they share a remedy.
        //
        // After a stop, undeliverable targets are what stopping means: the scanner
        // stopped reading. They still reach the report as uncovered, but not as a
        // failure, which would tell someone who pressed `^C` that something broke.
        let stopped = self.ctx.handle.should_stop();
        let reportable = if stopped {
            unroutable
        } else {
            unroutable + undeliverable
        };

        if reportable > 0 {
            self.ctx
                .record_failure(ScannerKind::Composite, missed(unroutable, undeliverable));
        } else if undeliverable > 0 {
            info!(
                verbosity = 1,
                "{} were still queued when the scan was stopped",
                counted(undeliverable as u128, "target", "targets")
            );
        }

        // Closing the routes signals EOF to the scanners.
        drop(routes);

        // Await every scanner and restore it for service detection. All handles are
        // awaited before any failure is returned, so one failure does not leave the
        // others unrestored and their tasks running against a finished store.
        let mut failure: Option<StrategyError> = None;

        for (kind, reach, handle) in handles {
            match handle.await {
                Ok((scanner, res)) => {
                    self.scanners.push((scanner, reach));
                    if let Err(e) = res {
                        failure.get_or_insert(e);
                    }
                }
                // The composite never aborts its tasks, so a `JoinError` means the scanner
                // panicked.
                Err(e) => {
                    failure.get_or_insert_with(|| StrategyError::Panicked {
                        scanner: kind,
                        detail: e.to_string(),
                    });
                }
            }
        }

        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    async fn detect_services(&mut self, ctx: &ScanContext) {
        for (scanner, _) in &mut self.scanners {
            scanner.detect_services(ctx).await;
        }
    }
}

/// How a router reports the work it could not place.
///
/// Unroutable targets mean the scan was assembled without a strategy for their
/// protocol and are missing from the results; undeliverable ones belong to a
/// scanner that stopped early (its own deadline, or a dead transport) and are on
/// their hosts as unasked. The message keeps them apart because the fixes
/// differ.
fn missed(unroutable: usize, undeliverable: usize) -> String {
    let reason = match (unroutable, undeliverable) {
        (_, 0) => "no scanner for their protocol".to_owned(),
        (0, _) => "their scanner had stopped".to_owned(),
        _ => format!("{unroutable} had no scanner, {undeliverable} found theirs stopped"),
    };
    format!(
        "{} never probed ({reason})",
        counted((unroutable + undeliverable) as u128, "target", "targets"),
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
    use crate::model::target::Target;
    use crate::scanner::session::ScanSession;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

    /// How a [`MockPortScanner`] behaves once it starts scanning.
    enum Behaviour {
        /// Drain the target stream, recording everything that arrives.
        Collect,
        /// Fail immediately, as a scanner whose transport died would.
        Fail(&'static str),
        /// Panic immediately, as a scanner with a bug in it would.
        Panic,
        /// Stop listening at once and say so, as a scanner that ran out of
        /// its own deadline does, with the rest of the plan still to come.
        Stop(Arc<tokio::sync::Notify>),
    }

    struct MockPortScanner {
        supported: Vec<Protocol>,
        received: Arc<Mutex<Vec<Target>>>,
        behaviour: Behaviour,
    }

    impl MockPortScanner {
        fn new(supported: Vec<Protocol>) -> (Self, Arc<Mutex<Vec<Target>>>) {
            Self::with_behaviour(supported, Behaviour::Collect)
        }

        fn with_behaviour(
            supported: Vec<Protocol>,
            behaviour: Behaviour,
        ) -> (Self, Arc<Mutex<Vec<Target>>>) {
            let received = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    supported,
                    received: received.clone(),
                    behaviour,
                },
                received,
            )
        }
    }

    #[async_trait]
    impl PortScanner for MockPortScanner {
        fn kind(&self) -> ScannerKind {
            ScannerKind::Composite
        }

        fn supported_protocols(&self) -> Vec<Protocol> {
            self.supported.clone()
        }

        async fn scan(
            &mut self,
            mut targets: mpsc::Receiver<PlannedTarget>,
        ) -> Result<(), StrategyError> {
            match &self.behaviour {
                Behaviour::Fail(reason) => return Err(StrategyError::Probe((*reason).into())),
                Behaviour::Panic => panic!("scanner bug"),
                Behaviour::Stop(stopped) => {
                    drop(targets);
                    stopped.notify_one();
                    return Ok(());
                }
                Behaviour::Collect => {}
            }

            while let Some(t) = targets.recv().await {
                self.received.lock().unwrap().push(t.target);
            }
            Ok(())
        }
    }

    fn target(protocol: Protocol, port: u16) -> Target {
        Target {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            protocol,
        }
    }

    /// Feeds `targets` through a composite over `scanners` and returns what the
    /// run reported.
    async fn run(
        scanners: Vec<Box<dyn PortScanner>>,
        targets: Vec<Target>,
    ) -> Result<(), StrategyError> {
        let (_session, ctx) = ScanSession::new();
        let mut composite = CompositePortScanner::new(scanners, ctx);
        let (tx, rx) = mpsc::channel(16);
        for (position, t) in targets.into_iter().enumerate() {
            tx.send(PlannedTarget::new(position as u64, t))
                .await
                .unwrap();
        }
        drop(tx);
        composite.scan(rx).await
    }

    #[tokio::test]
    async fn composite_routes_by_protocol() {
        let (tcp_scanner, tcp_rx) = MockPortScanner::new(vec![Protocol::Tcp]);
        let (udp_scanner, udp_rx) = MockPortScanner::new(vec![Protocol::Udp]);

        let (_session, ctx) = ScanSession::new();
        let mut composite =
            CompositePortScanner::new(vec![Box::new(tcp_scanner), Box::new(udp_scanner)], ctx);

        let (tx, rx) = mpsc::channel(10);

        let target_tcp = Target {
            ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 80,
            protocol: Protocol::Tcp,
        };

        let target_udp = Target {
            ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 53,
            protocol: Protocol::Udp,
        };

        tx.send(PlannedTarget::new(0, target_tcp)).await.unwrap();
        tx.send(PlannedTarget::new(1, target_udp)).await.unwrap();
        drop(tx);

        composite.scan(rx).await.unwrap();

        let tcp_received = tcp_rx.lock().unwrap();
        assert_eq!(tcp_received.len(), 1);
        assert_eq!(tcp_received[0].protocol, Protocol::Tcp);

        let udp_received = udp_rx.lock().unwrap();
        assert_eq!(udp_received.len(), 1);
        assert_eq!(udp_received[0].protocol, Protocol::Udp);
    }

    /// A scan whose raw strategies send frames alone splits one protocol by
    /// address: the raw scanner takes what a frame reaches, a connect scanner the
    /// rest, so loopback is still asked.
    #[tokio::test]
    async fn targets_are_routed_by_address_where_a_scanner_says_so() {
        let (raw, raw_rx) = MockPortScanner::new(vec![Protocol::Tcp]);
        let (connect, connect_rx) = MockPortScanner::new(vec![Protocol::Tcp]);

        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let neighbour = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8));
        let mut beyond = IpSet::new();
        beyond.insert(loopback);
        let beyond = Arc::new(beyond);

        let (_session, ctx) = ScanSession::new();
        let mut composite = CompositePortScanner::with_reach(
            vec![
                (Box::new(raw), Reach::Except(Arc::clone(&beyond))),
                (Box::new(connect), Reach::Only(beyond)),
            ],
            ctx.clone(),
        );

        let (tx, rx) = mpsc::channel(4);
        for (position, ip) in [loopback, neighbour].into_iter().enumerate() {
            let target = Target {
                ip,
                port: 22,
                protocol: Protocol::Tcp,
            };
            tx.send(PlannedTarget::new(position as u64, target))
                .await
                .unwrap();
        }
        drop(tx);
        composite.scan(rx).await.unwrap();

        let ips = |received: &Arc<Mutex<Vec<Target>>>| {
            received
                .lock()
                .unwrap()
                .iter()
                .map(|target| target.ip)
                .collect::<Vec<_>>()
        };
        assert_eq!(ips(&raw_rx), vec![neighbour]);
        assert_eq!(ips(&connect_rx), vec![loopback]);
        assert!(
            ctx.failures_snapshot().is_empty(),
            "every target found a route"
        );
    }

    /// A failing scanner does not lose its siblings' results: every scanner is
    /// restored for the service-detection pass.
    #[tokio::test]
    async fn a_failing_scanner_is_reported_without_losing_the_others() {
        let (failing, _) =
            MockPortScanner::with_behaviour(vec![Protocol::Tcp], Behaviour::Fail("transport died"));
        let (working, udp_rx) = MockPortScanner::new(vec![Protocol::Udp]);
        let (_session, ctx) = ScanSession::new();
        let mut composite =
            CompositePortScanner::new(vec![Box::new(failing), Box::new(working)], ctx);

        let (tx, rx) = mpsc::channel(16);
        tx.send(PlannedTarget::new(0, target(Protocol::Udp, 53)))
            .await
            .unwrap();
        drop(tx);

        let err = composite.scan(rx).await.expect_err("the failure surfaces");

        assert!(err.to_string().contains("transport died"));
        assert_eq!(udp_rx.lock().unwrap().len(), 1, "sibling still ran");
        assert_eq!(composite.scanners.len(), 2, "both scanners restored");
    }

    /// A panicking scanner surfaces as a failure.
    #[tokio::test]
    async fn a_panicking_scanner_surfaces_as_a_failure() {
        let (panicking, _) = MockPortScanner::with_behaviour(vec![Protocol::Tcp], Behaviour::Panic);
        let (working, udp_rx) = MockPortScanner::new(vec![Protocol::Udp]);

        let err = run(
            vec![Box::new(panicking), Box::new(working)],
            vec![target(Protocol::Udp, 53)],
        )
        .await
        .expect_err("a panic is a failure");

        assert!(err.to_string().contains("panicked"), "got: {err}");
        assert_eq!(udp_rx.lock().unwrap().len(), 1, "sibling still ran");
    }

    /// Targets nothing claims are counted, and the run carries on.
    #[tokio::test]
    async fn targets_with_no_route_do_not_stop_the_run() {
        let (tcp_scanner, tcp_rx) = MockPortScanner::new(vec![Protocol::Tcp]);

        run(
            vec![Box::new(tcp_scanner)],
            vec![target(Protocol::Tcp, 80), target(Protocol::Udp, 53)],
        )
        .await
        .expect("unroutable targets are not a failure");

        let received = tcp_rx.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].protocol, Protocol::Tcp);
    }

    /// Unprobed targets reach the report as a failure, since a library consumer
    /// never sees the log.
    #[tokio::test]
    async fn targets_that_went_unprobed_reach_the_report() {
        let (_session, ctx) = ScanSession::new();
        let (tcp_scanner, _) = MockPortScanner::new(vec![Protocol::Tcp]);

        let mut composite = CompositePortScanner::new(vec![Box::new(tcp_scanner)], ctx.clone());
        let (tx, rx) = mpsc::channel(16);
        for (position, t) in [target(Protocol::Udp, 53), target(Protocol::Udp, 161)]
            .into_iter()
            .enumerate()
        {
            tx.send(PlannedTarget::new(position as u64, t))
                .await
                .unwrap();
        }
        drop(tx);
        composite
            .scan(rx)
            .await
            .expect("not a failure, a narrowing");

        let failures = ctx.take_failures();
        assert_eq!(failures.len(), 1, "one cause, one entry");
        assert_eq!(failures[0].scanner(), ScannerKind::Composite);
        assert!(
            failures[0].reason().contains('2'),
            "the count is what says how much was missed: {}",
            failures[0].reason()
        );
    }

    /// A refused target is left to the refusal that names it; the same protocol
    /// at an address the refusal does not cover is reported as lost. Both stay
    /// owed to a resume.
    #[tokio::test]
    async fn a_refused_target_is_left_to_its_refusal_and_no_other_is() {
        let (_session, ctx) = ScanSession::new();
        let mut loopback = IpSet::new();
        loopback.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));

        let mut composite = CompositePortScanner::new(Vec::new(), ctx.clone())
            .refusing(vec![(Protocol::Tcp, Reach::Only(Arc::new(loopback)))]);
        let (tx, rx) = mpsc::channel(16);
        let elsewhere = Target {
            ip: "192.0.2.8".parse().expect("literal"),
            ..target(Protocol::Tcp, 80)
        };
        for (position, t) in [target(Protocol::Tcp, 80), elsewhere]
            .into_iter()
            .enumerate()
        {
            tx.send(PlannedTarget::new(position as u64, t))
                .await
                .unwrap();
        }
        drop(tx);
        composite.scan(rx).await.expect("a narrowing, not an error");

        let failures = ctx.take_failures();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(
            failures[0].reason().starts_with("1 target never probed"),
            "only the target the refusal does not cover is lost: {}",
            failures[0].reason()
        );
        assert_eq!(ctx.settlements().count(Outcome::Unroutable), 2);
    }

    /// A scan that probed everything reports no narrowing.
    #[tokio::test]
    async fn a_scan_that_probed_everything_reports_no_narrowing() {
        let (_session, ctx) = ScanSession::new();
        let (tcp_scanner, _) = MockPortScanner::new(vec![Protocol::Tcp]);

        let mut composite = CompositePortScanner::new(vec![Box::new(tcp_scanner)], ctx.clone());
        let (tx, rx) = mpsc::channel(16);
        tx.send(PlannedTarget::new(0, target(Protocol::Tcp, 80)))
            .await
            .unwrap();
        drop(tx);
        composite.scan(rx).await.unwrap();

        assert!(ctx.take_failures().is_empty());
    }

    /// The rest of a plan whose scanner stopped short of it is recorded on its
    /// hosts as unasked and owed to a resume, so a truncated port list does not
    /// read as complete.
    #[tokio::test]
    async fn the_plan_a_stopped_scanner_never_took_is_recorded_unasked() {
        let (session, ctx) = ScanSession::new();
        let stopped = Arc::new(tokio::sync::Notify::new());
        let (scanner, _) = MockPortScanner::with_behaviour(
            vec![Protocol::Tcp],
            Behaviour::Stop(Arc::clone(&stopped)),
        );
        let mut composite = CompositePortScanner::new(vec![Box::new(scanner)], ctx.clone());

        let (tx, rx) = mpsc::channel(16);
        let routing = tokio::spawn(async move {
            composite.scan(rx).await.expect("a narrowing, not an error");
        });
        // Send only after the scanner has stopped listening, so neither target is
        // buffered on its way to it.
        stopped.notified().await;
        for (position, port) in [80u16, 443].into_iter().enumerate() {
            tx.send(PlannedTarget::new(
                position as u64,
                target(Protocol::Tcp, port),
            ))
            .await
            .unwrap();
        }
        drop(tx);
        routing.await.expect("the router finishes");

        let host = session
            .hosts()
            .get(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .expect("the ports are on their host");
        for port in [80u16, 443] {
            assert_eq!(
                host.ports()
                    .find(|recorded| recorded.number() == port)
                    .map(|recorded| recorded.state()),
                Some(crate::model::port::PortState::Unasked),
                "port {port}"
            );
        }
        assert_eq!(ctx.settlements().count(Outcome::Unasked), 2);
        let failures = ctx.take_failures();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert_eq!(
            failures[0].reason(),
            "2 targets never probed (their scanner had stopped)"
        );
    }

    /// Stopping a scan is not a strategy failing. The targets the router still
    /// held stay uncovered and unsettled, so a resume asks about them again.
    #[tokio::test]
    async fn a_stopped_scan_does_not_report_a_failure() {
        let (session, ctx) = ScanSession::new();
        let (scanner, _received) = MockPortScanner::new(vec![Protocol::Tcp]);
        let mut composite = CompositePortScanner::new(vec![Box::new(scanner)], ctx.clone());

        // Stopped before anything is routed, so every target is undeliverable.
        session.handle().abort();

        let (tx, rx) = mpsc::channel(16);
        for (position, port) in [80u16, 443].into_iter().enumerate() {
            tx.send(PlannedTarget::new(
                position as u64,
                target(Protocol::Tcp, port),
            ))
            .await
            .unwrap();
        }
        drop(tx);
        composite.scan(rx).await.expect("a stop is not an error");

        assert!(
            ctx.take_failures().is_empty(),
            "a stop was reported as a strategy failure"
        );
        assert_eq!(
            ctx.settlements().settled_count(),
            0,
            "and nothing it could not hand over may be settled"
        );
    }
}
