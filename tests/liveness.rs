// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a port scan establishes before it spends a probe on a port.
//!
//! [`scanner::scan`] probes its targets for liveness first and skips the ones
//! that answer nothing, because an address nothing lives at otherwise costs one
//! probe per port to learn that. These drive the real entry point, because the
//! thing worth checking is the sequencing — a gate that reads the store at the
//! wrong moment sees an empty one and turns every target away.
//!
//! `192.0.2.1` is TEST-NET-1 (RFC 5737) and belongs to nobody, so it is the
//! address that reliably answers nothing.

mod common;

use std::net::{IpAddr, Ipv4Addr};

use common::*;
use zond_engine::model::ip::set::IpSet;
use zond_engine::model::port::PortSet;
use zond_engine::model::target::{TargetMap, TargetSet};
use zond_engine::report::ScanKind;

/// Reserved for documentation, and therefore reliably dead.
const DEAD: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

/// The report says how the run was spent: what it took to establish anything
/// was there, and what it took to probe it.
#[tokio::test]
async fn a_port_scan_records_the_liveness_pass_as_its_own_phase() {
    let report = run_scan(target_map(LOOPBACK, "1,2"), &test_config())
        .await
        .report;

    let kinds: Vec<ScanKind> = report.phases().iter().map(|phase| phase.kind()).collect();
    assert_eq!(kinds, vec![ScanKind::Discovery, ScanKind::PortScan]);
}

/// The whole point. An address nothing answers for gets a handful of liveness
/// probes, not one per port.
#[tokio::test]
async fn an_address_nothing_answers_for_is_never_port_scanned() {
    let outcome = run_scan(target_map(DEAD, "1-64"), &test_config()).await;

    assert_eq!(
        outcome.host(DEAD).map_or(0, |host| host.port_count()),
        0,
        "a dead address was port-scanned anyway"
    );
    assert_eq!(
        outcome.report.summary().ports_total,
        0,
        "ports were recorded for a host that answered nothing"
    );
}

/// The second phase covers what survived the first, and the first covers what
/// was asked about. The gap between the two is what a front end reports as
/// hosts it skipped.
#[tokio::test]
async fn the_port_phase_covers_only_what_answered() {
    let report = run_scan(target_map(DEAD, "1,2"), &test_config())
        .await
        .report;

    let [liveness, ports, ..] = report.phases() else {
        panic!("a port scan records two phases");
    };
    assert_eq!(
        liveness.targets().addresses(),
        1,
        "one address was asked about"
    );
    assert_eq!(ports.targets().addresses(), 0, "and none of it answered");
}

/// `assume_up` is what reaches a host that is up and answering no knock. It
/// skips the phase entirely rather than running it and ignoring the result.
#[tokio::test]
async fn assume_up_probes_the_ports_without_asking_first() {
    let cfg = zond_engine::ZondConfig {
        assume_up: true,
        ..test_config()
    };
    let outcome = run_scan(target_map(DEAD, "1,2"), &cfg).await;

    let kinds: Vec<ScanKind> = outcome
        .report
        .phases()
        .iter()
        .map(|phase| phase.kind())
        .collect();
    assert_eq!(kinds, vec![ScanKind::PortScan], "no liveness phase ran");
    assert_eq!(
        outcome.report.summary().ports_total,
        2,
        "the ports were probed on trust"
    );
}

/// A host that is there is scanned exactly as it always was.
#[tokio::test]
async fn a_live_host_is_still_port_scanned() {
    if is_privileged() {
        eprintln!("SKIP: relies on the connect path reaching the loopback listener");
        return;
    }

    let server = spawn_banner_server(b"hi\r\n").await;
    let outcome = run_scan(
        target_map(LOOPBACK, &server.port.to_string()),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(LOOPBACK, server.port),
        Some(zond_engine::model::port::PortState::Open)
    );
}

/// Each unit keeps the ports it was given. A target may name its own —
/// `10.0.0.1:8080` — so a gate that rebuilt one set against one port list would
/// answer a different question from the one that was asked.
#[tokio::test]
async fn the_gate_keeps_each_unit_its_own_ports() {
    if is_privileged() {
        eprintln!("SKIP: relies on the connect path reaching the loopback listener");
        return;
    }

    let first = spawn_banner_server(b"one\r\n").await;
    let second = spawn_banner_server(b"two\r\n").await;

    // Two units over the same live address, each naming a different port.
    let mut map = TargetMap::new();
    for port in [first.port, second.port] {
        let mut ips = IpSet::new();
        ips.insert(LOOPBACK);
        map.add_unit(TargetSet::new(
            ips,
            PortSet::try_from(port.to_string().as_str()).expect("a port"),
        ));
    }

    let outcome = run_scan(map, &test_config()).await;
    let host = outcome.host(LOOPBACK).expect("loopback answered");

    for port in [first.port, second.port] {
        assert!(
            host.ports().any(|probed| probed.number() == port),
            "{port} was dropped by the liveness gate"
        );
    }
}
