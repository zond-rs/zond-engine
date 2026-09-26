// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ports a scan connects to and listens on, and sends nothing.
//!
//! A network printer prints whatever arrives on its raw-print ports, so a scan
//! that probes one prints a page per probe. The listener here stands in for
//! that printer: it volunteers nothing, as a printer's 9100 does, and counts
//! every byte any connection hands it. A scan asked for everything that puts
//! bytes on a port, identification at its most thorough, detections under the
//! widest envelope with two of them gated onto this very port, and TLS
//! enumeration, has to leave it with none.
//!
//! The listener sits on an ephemeral port named listen-only for the test rather
//! than on 9100 itself, so the suite never contends for a port another program
//! may hold; that 9100 to 9107 are the default is the config's own test. The
//! same scan with the set cleared is the other half: it has to reach the
//! listener, and with both detections, or the first half proves nothing about
//! the passes it claims to cover.

use std::collections::{BTreeMap, BTreeSet};

use crate::support::loopback::SilentPort;
use crate::support::*;
use zond_engine::config::{DetectionEnvelope, ServiceDetection, ZondConfig};
use zond_engine::detect::Detections;
use zond_engine::model::finding::DetectionClass;
use zond_engine::model::port::{PortState, Protocol};

/// Whether `printer` was sent `needle` by this process, on any connection.
fn saw(printer: &SilentPort, needle: &str) -> bool {
    String::from_utf8_lossy(&printer.received()).contains(needle)
}

/// A flow and a compute module, each gated onto `port` by number and each
/// sending a marker of its own, so the test can tell that a detection reached
/// the port and which one.
fn detections_on(port: u16) -> Detections {
    let flow = format!(
        r#"
        [detection]
        id      = "printer-flow"
        version = "1.0.0"
        title   = "Speaks to the printer"
        [detection.when]
        port = {port}
        [detection.capabilities]
        class = "active-benign"
        speak = "target"
        [[step]]
        send        = "FLOW-PAGE\r\n"
        expect      = "never"
        on_no_match = "continue"
        [[step.finding]]
        when     = "matched"
        severity = "info"
        summary  = "the printer answered"
    "#
    );
    let module = format!(
        r#"
        [detection]
        id      = "printer-module"
        version = "1.0.0"
        title   = "Speaks to the printer from code"
        [detection.when]
        port = {port}
        [detection.capabilities]
        class = "active-benign"
        speak = "target"
        [compute]
        language = "rhai"
        body     = "printer-module.rhai"
    "#
    );
    let body = r#"
        fn analyze(ctx, responses) {
            try { speak(bytes("MODULE-PAGE\r\n")); } catch (e) { }
            []
        }
    "#;

    let sources = BTreeMap::from([
        ("printer-flow.toml".to_string(), flow),
        ("printer-module.toml".to_string(), module),
        ("printer-module.rhai".to_string(), body.to_string()),
    ]);
    Detections::builder()
        .sources(&sources)
        .expect("the printer detections build")
        .build()
}

/// Everything that puts bytes on a port, at its most thorough.
fn everything(listen_only: BTreeSet<u16>) -> ZondConfig {
    let mut cfg = test_config();
    cfg.service_detection = ServiceDetection::Thorough;
    cfg.detection = DetectionEnvelope::up_to(DetectionClass::Dos);
    cfg.tls_enumeration = true;
    cfg.listen_only_ports = listen_only;
    cfg
}

/// **A port the scan only listens on is sent nothing by any pass, and the
/// report says it was held back.**
///
/// Found open, as the port-state probe carries no payload, and then left with
/// whatever it volunteered, which from a printer is nothing. A single byte
/// here is a byte of a print job.
#[tokio::test]
async fn a_listen_only_port_is_found_open_and_sent_nothing_by_any_pass() {
    let printer = SilentPort::open();
    let port = printer.addr().port();

    let outcome = run_scan_with(
        target_map(LOOPBACK, &port.to_string()),
        &everything(BTreeSet::from([port])),
        detections_on(port),
    )
    .await;

    assert_eq!(
        outcome.port_state(LOOPBACK, port),
        Some(PortState::Open),
        "the port-state probe is not held back"
    );
    let received = printer.received();
    assert!(
        received.is_empty(),
        "a listen-only port was sent {} bytes: {:?}",
        received.len(),
        String::from_utf8_lossy(&received)
    );

    let settings = outcome.report.phases().last().expect("a phase").settings();
    assert!(
        settings.listened_only_to(port, Protocol::Tcp),
        "the report does not say the port was held back: {:?}",
        settings.listen_only_ports
    );
}

/// **With the set cleared, the same scan reaches the port through every pass
/// the first test holds back.**
///
/// What keeps the first test honest: were the detections not applying to the
/// port, or identification not asking it anything, the silence there would
/// prove nothing.
#[tokio::test]
async fn the_same_scan_with_nothing_held_back_reaches_the_port() {
    let printer = SilentPort::open();
    let port = printer.addr().port();

    let outcome = run_scan_with(
        target_map(LOOPBACK, &port.to_string()),
        &everything(BTreeSet::new()),
        detections_on(port),
    )
    .await;

    assert_eq!(outcome.port_state(LOOPBACK, port), Some(PortState::Open));
    assert!(
        saw(&printer, "GET / HTTP/1.1"),
        "identification asked the port nothing: {:?}",
        String::from_utf8_lossy(&printer.received())
    );
    assert!(
        saw(&printer, "FLOW-PAGE"),
        "the flow did not reach the port"
    );
    assert!(
        saw(&printer, "MODULE-PAGE"),
        "the compute module did not reach the port"
    );

    let settings = outcome.report.phases().last().expect("a phase").settings();
    assert!(settings.listen_only_ports.is_empty());
}
