// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

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

use crate::core::models::port::Protocol;
use crate::core::models::target::Target;
use crate::core::session::{ScanContext, ScannerKind};
use crate::scanner::PortScanner;

/// A port scanner that multiplexes targets by protocol.
pub struct CompositePortScanner {
    scanners: Vec<Box<dyn PortScanner>>,
}

impl CompositePortScanner {
    /// Constructs a composite scanner from a collection of existing scanners.
    pub fn new(scanners: Vec<Box<dyn PortScanner>>) -> Self {
        Self { scanners }
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

    async fn scan(&mut self, mut targets: mpsc::Receiver<Target>) -> anyhow::Result<()> {
        struct Route {
            supported_protocols: Vec<Protocol>,
            tx: mpsc::Sender<Target>,
        }

        let mut routes = Vec::new();
        let mut handles = Vec::new();

        // Spin up an independent task for every scanner we own.
        for mut scanner in self.scanners.drain(..) {
            let (tx, rx) = mpsc::channel(1024);
            let supported_protocols = scanner.supported_protocols();

            let handle = tokio::spawn(async move {
                let res = scanner.scan(rx).await;
                (scanner, res)
            });

            handles.push(handle);
            routes.push(Route {
                supported_protocols,
                tx,
            });
        }

        // Route targets from the unified stream to the first scanner that claims support.
        while let Some(target) = targets.recv().await {
            for route in &routes {
                if route.supported_protocols.contains(&target.protocol) {
                    let _ = route.tx.send(target).await;
                    break;
                }
            }
        }

        // Drop the sender ends to signal EOF to the underlying scanners.
        drop(routes);

        // Wait for all scanners to finish and restore them so they can be
        // interrogated for service detection.
        for handle in handles {
            if let Ok((scanner, res)) = handle.await {
                self.scanners.push(scanner);
                res?;
            }
        }

        Ok(())
    }

    async fn detect_services(&mut self, ctx: &ScanContext) {
        for scanner in &mut self.scanners {
            scanner.detect_services(ctx).await;
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
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

    struct MockPortScanner {
        supported: Vec<Protocol>,
        received: Arc<Mutex<Vec<Target>>>,
    }

    impl MockPortScanner {
        fn new(supported: Vec<Protocol>) -> (Self, Arc<Mutex<Vec<Target>>>) {
            let received = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    supported,
                    received: received.clone(),
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

        async fn scan(&mut self, mut targets: mpsc::Receiver<Target>) -> anyhow::Result<()> {
            while let Some(t) = targets.recv().await {
                self.received.lock().unwrap().push(t);
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn composite_routes_by_protocol() {
        let (tcp_scanner, tcp_rx) = MockPortScanner::new(vec![Protocol::Tcp]);
        let (udp_scanner, udp_rx) = MockPortScanner::new(vec![Protocol::Udp]);

        let mut composite =
            CompositePortScanner::new(vec![Box::new(tcp_scanner), Box::new(udp_scanner)]);

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
        tx.send(target_tcp).await.unwrap();
        tx.send(target_udp).await.unwrap();
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
}
