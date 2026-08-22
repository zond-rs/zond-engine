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
//! Rather than forcing consumers of the scanning subsystem to juggle multiple
//! scanner instances for different protocols (e.g., TCP SYN vs. raw UDP vs.
//! connect fallbacks), the [`CompositePortScanner`] acts as a single router.
//! It accepts a unified stream of targets, consults each internal scanner's
//! [`PortScanner::supported_protocols`] capability, and routes the target to the
//! correct protocol-specific engine.
//!
//! This design allows the engine to handle targets across different protocols
//! concurrently without modifying the `PortScanner` consumer interface, and
//! makes it trivial to slot in support for new protocols (like SCTP) in the future.

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::journal::settle::Outcome;
use crate::model::port::Protocol;
use crate::model::target::PlannedTarget;
use crate::scanner::session::{ScanContext, ScannerKind};
use crate::scanner::strategy::{PortScanner, StrategyError};

/// A port scanner that multiplexes targets by protocol.
pub struct CompositePortScanner {
    scanners: Vec<Box<dyn PortScanner>>,
    /// Where targets that never reached a scanner are reported.
    ///
    /// The router is the one place in a scan that can drop work without any
    /// strategy noticing, so it is the one place that has to be able to say so
    /// through the same channel every other narrowing uses.
    ctx: ScanContext,
}

impl CompositePortScanner {
    /// Constructs a composite scanner from a collection of existing scanners.
    pub fn new(scanners: Vec<Box<dyn PortScanner>>, ctx: ScanContext) -> Self {
        Self { scanners, ctx }
    }
}

#[async_trait]
impl PortScanner for CompositePortScanner {
    fn kind(&self) -> ScannerKind {
        ScannerKind::Composite
    }

    fn supported_protocols(&self) -> Vec<Protocol> {
        let mut protocols = Vec::new();
        for scanner in &self.scanners {
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
            tx: mpsc::Sender<PlannedTarget>,
        }

        let mut routes = Vec::new();
        let mut handles = Vec::new();

        // Spin up an independent task for every scanner we own.
        for mut scanner in self.scanners.drain(..) {
            let (tx, rx) = mpsc::channel(1024);
            let supported_protocols = scanner.supported_protocols();
            let kind = scanner.kind();

            let handle = tokio::spawn(async move {
                let res = scanner.scan(rx).await;
                (scanner, res)
            });

            handles.push((kind, handle));
            routes.push(Route {
                supported_protocols,
                tx,
            });
        }

        // Route targets from the unified stream to the first scanner that
        // claims support. A target that finds no route, or whose scanner has
        // already stopped listening, is counted rather than dropped in silence:
        // either means ports the caller asked about are missing from the
        // results, and a scan that quietly answers a narrower question than it
        // was asked is worse than one that says so.
        let mut unroutable = 0usize;
        let mut undeliverable = 0usize;

        while let Some(target) = targets.recv().await {
            match routes
                .iter()
                .find(|route| route.supported_protocols.contains(&target.protocol()))
            {
                Some(route) => {
                    if route.tx.send(target).await.is_err() {
                        undeliverable += 1;
                        self.ctx.record_outcome(Outcome::Unroutable);
                    }
                }
                None => {
                    unroutable += 1;
                    self.ctx.record_outcome(Outcome::Unroutable);
                }
            }
        }

        // Recorded as a failure rather than logged. Both counts mean ports the
        // caller asked about are absent from the results, and every other
        // narrowing in the engine reaches the report and the event stream; a
        // warning reaches neither, so a consumer that awaits the scan and reads
        // what came back cannot tell a narrowed scan from an empty network.
        //
        // One entry carrying both counts, because they have one remedy between
        // them and a report listing them separately would suggest otherwise.
        if unroutable > 0 || undeliverable > 0 {
            self.ctx
                .record_failure(ScannerKind::Composite, missed(unroutable, undeliverable));
        }

        // Drop the sender ends to signal EOF to the underlying scanners.
        drop(routes);

        // Wait for all scanners to finish and restore them so they can be
        // interrogated for service detection.
        //
        // Every handle is awaited before any failure is returned. Bailing on
        // the first one would leave the remaining scanners unrestored, so the
        // service-detection pass would skip strategies that ran perfectly well,
        // and their tasks would be left running against a store the scan has
        // already moved on from.
        let mut failure: Option<StrategyError> = None;

        for (kind, handle) in handles {
            match handle.await {
                Ok((scanner, res)) => {
                    self.scanners.push(scanner);
                    if let Err(e) = res {
                        failure.get_or_insert(e);
                    }
                }
                // The composite never aborts its tasks, so a `JoinError` only
                // ever means the scanner panicked - a bug, and one that would
                // otherwise vanish along with the scanner it took down.
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
        for scanner in &mut self.scanners {
            scanner.detect_services(ctx).await;
        }
    }
}

/// How a router reports the work it could not place.
///
/// Two ways a target goes unprobed, kept apart in the message because they call
/// for different fixes. Nothing claiming the protocol is a scan assembled
/// without a strategy for it; a scanner that had already finished is one that
/// stopped early, most often because its own transport died mid-run.
fn missed(unroutable: usize, undeliverable: usize) -> String {
    let mut reasons = Vec::new();
    if unroutable > 0 {
        reasons.push(format!("{unroutable} had no scanner for their protocol"));
    }
    if undeliverable > 0 {
        reasons.push(format!(
            "{undeliverable} arrived after their scanner had finished"
        ));
    }

    format!(
        "{} target(s) were never probed and are missing from the results: {}",
        unroutable + undeliverable,
        reasons.join(", ")
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
            match self.behaviour {
                Behaviour::Fail(reason) => return Err(StrategyError::Probe(reason.into())),
                Behaviour::Panic => panic!("scanner bug"),
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

        // Send targets
        tx.send(PlannedTarget::new(0, target_tcp)).await.unwrap();
        tx.send(PlannedTarget::new(1, target_udp)).await.unwrap();
        drop(tx); // Signal EOF

        // Run scanner
        composite.scan(rx).await.unwrap();

        // Verify routing
        let tcp_received = tcp_rx.lock().unwrap();
        assert_eq!(tcp_received.len(), 1);
        assert_eq!(tcp_received[0].protocol, Protocol::Tcp);

        let udp_received = udp_rx.lock().unwrap();
        assert_eq!(udp_received.len(), 1);
        assert_eq!(udp_received[0].protocol, Protocol::Udp);
    }

    /// A scanner that fails must not take its siblings' results with it: every
    /// scanner is restored for the service-detection pass regardless.
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

    /// A panicking scanner used to vanish along with its task, leaving the run
    /// looking clean. It has to surface as a failure like any other.
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

    /// Targets nothing claims are counted rather than silently discarded - a
    /// scan that answers a narrower question than it was asked has to say so.
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

    /// Saying so has to mean saying so where a consumer will see it. Ports the
    /// caller asked about went unprobed, and a warning on the log is the one
    /// channel a library consumer never receives: they await the scan and read
    /// the report, where a scan that quietly covered less than it was asked
    /// looks exactly like one that found nothing there.
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

    /// And nothing to report when nothing was missed, or every clean scan ends
    /// with a failure describing zero targets.
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
}
