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
//! The address that answers nothing is [`silent_loopback`], which never leaves
//! the machine. Where the machine has none, as on Linux, those tests skip, and
//! Tier 3's `liveness` asks the same questions of a silent host it builds.

use std::net::IpAddr;

use crate::support::*;
use zond_engine::model::ip::set::IpSet;
use zond_engine::model::port::PortSet;
use zond_engine::model::target::{TargetMap, TargetSet};
use zond_engine::report::ScanKind;

/// An address nothing answers for, or `None` with the reason already printed.
fn dead() -> Option<IpAddr> {
    let dead = silent_loopback();
    if dead.is_none() {
        eprintln!("SKIP: every loopback address answers here, so none is silent");
    }
    dead
}

/// The report says how the run was spent: what it took to establish anything
/// was there, and what it took to probe it.
///
/// A wide port list, so the liveness pass earns its place: it asks a handful of
/// ports where the port scan would ask sixty-four, so gating the second on the
/// first is the cheaper order. A narrow list is the other way round and skips
/// the pass; see [`a_scan_of_few_ports_lets_the_port_probes_stand_in`].
#[tokio::test]
async fn a_port_scan_records_the_liveness_pass_as_its_own_phase() {
    let report = run_scan(target_map(LOOPBACK, "1-64"), &test_config())
        .await
        .report;

    let kinds: Vec<ScanKind> = report.phases().iter().map(|phase| phase.kind()).collect();
    assert_eq!(kinds, vec![ScanKind::Discovery, ScanKind::PortScan]);
}

/// A scan naming no more ports than the liveness pass would ask skips the pass
/// and lets the port probes stand in for it.
///
/// The pass asks the common five and a few of the scan's own ports; a scan of
/// two ports would cost less probed directly than asked about first, so there
/// is one phase, not two, and an answer on either port, open or closed, is what
/// finds the host. Loopback is neither on this host's own segment nor a UDP
/// target, so the port count alone decides.
#[tokio::test]
async fn a_scan_of_few_ports_lets_the_port_probes_stand_in() {
    let report = run_scan(target_map(LOOPBACK, "1,2"), &test_config())
        .await
        .report;

    let kinds: Vec<ScanKind> = report.phases().iter().map(|phase| phase.kind()).collect();
    assert_eq!(
        kinds,
        vec![ScanKind::PortScan],
        "a two-port scan is cheaper probed than asked, so it runs no liveness pass"
    );
}

/// A scan naming a UDP port keeps its liveness pass however few ports it names,
/// because a UDP probe to a dead address is dear where a liveness probe is
/// cheap.
#[tokio::test]
async fn a_udp_scan_keeps_its_liveness_pass_even_for_one_port() {
    let mut map = TargetMap::new();
    let ports = PortSet::try_from("u:53").expect("a port specification");
    map.add_unit(TargetSet::new(IpSet::from(LOOPBACK), ports));

    let report = run_scan(map, &test_config()).await.report;

    let kinds: Vec<ScanKind> = report.phases().iter().map(|phase| phase.kind()).collect();
    assert_eq!(
        kinds,
        vec![ScanKind::Discovery, ScanKind::PortScan],
        "a UDP scan keeps the cheap liveness pass in front of its dear probes"
    );
}

/// The whole point. An address nothing answers for gets a handful of liveness
/// probes, not one per port.
#[tokio::test]
async fn an_address_nothing_answers_for_is_never_port_scanned() {
    let Some(dead) = dead() else { return };
    let outcome = run_scan(target_map(dead, "1-64"), &test_config()).await;

    assert_eq!(
        outcome.host(dead).map_or(0, |host| host.port_count()),
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
    let Some(dead) = dead() else { return };
    // A wide port list, so the liveness pass runs and the two phases exist to
    // compare; a narrow one skips the pass and there is only the port phase.
    let report = run_scan(target_map(dead, "1-64"), &test_config())
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
    let mut cfg = test_config();
    cfg.assume_up = true;
    let Some(dead) = dead() else { return };
    let outcome = run_scan(target_map(dead, "1,2"), &cfg).await;

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

/// **An idle scan asks the target nothing from this host.**
///
/// Every probe of an idle scan is forged from the zombie, and the verdict is
/// read off the zombie's counter, so the target never learns this host exists.
/// A liveness pass is this host asking the target directly, which is the one
/// thing the technique is for avoiding, so under an idle scan there is none.
///
/// The zombie is excluded, so the idle scan is refused whatever privilege runs
/// the test and nothing is forged. What is left to observe is whether anything
/// else asked the target, which the loopback host answers if it is asked.
#[tokio::test]
async fn an_idle_scan_runs_no_liveness_pass_against_its_target() {
    let zombie: IpAddr = "192.0.2.9".parse().expect("an address");
    let mut cfg = test_config();
    cfg.idle_scan = Some(zond_engine::config::IdleScan::new(zombie));
    cfg.exclusions = zond_engine::Exclusions::new(ip_set(zombie));

    let outcome = run_scan(target_map(LOOPBACK, "1,2"), &cfg).await;

    let kinds: Vec<ScanKind> = outcome
        .report
        .phases()
        .iter()
        .map(|phase| phase.kind())
        .collect();
    assert_eq!(kinds, vec![ScanKind::PortScan], "no liveness phase ran");
    assert!(
        outcome.host(LOOPBACK).is_none(),
        "the target heard from this host, and answered it"
    );
}

/// Under an idle scan, every pass that would contact the target directly is
/// declined, and the caller learns which and why.
///
/// The passes after the port phase — service detection, the detection corpus,
/// active operating-system probing, the route trace, filter characterisation,
/// IP-protocol probing and TLS enumeration — each open a connection to the
/// target or send it a probe from this host, which is the one thing an idle
/// scan exists to avoid. Turned off silently they would betray the scan or,
/// caught, leave the caller wondering why what they asked for did nothing. So
/// each the caller asked for is refused with a reason, on the port phase, which
/// is the only phase an idle scan has.
#[tokio::test]
async fn an_idle_scan_declines_every_pass_that_would_contact_the_target() {
    use zond_engine::config::{DetectionEnvelope, OsDetection};
    use zond_engine::model::finding::DetectionClass;

    let zombie: IpAddr = "192.0.2.9".parse().expect("an address");
    let mut cfg = test_config();
    cfg.idle_scan = Some(zond_engine::config::IdleScan::new(zombie));
    cfg.exclusions = zond_engine::Exclusions::new(ip_set(zombie));
    cfg.os_detection = OsDetection::Active;
    cfg.traceroute = true;
    cfg.characterise = true;
    cfg.tls_enumeration = true;
    cfg.ip_protocols = [47].into_iter().collect();
    cfg.detection = DetectionEnvelope::up_to(DetectionClass::ActiveBenign);

    let report = run_scan(target_map(LOOPBACK, "1,2"), &cfg).await.report;

    let kinds: Vec<ScanKind> = report.phases().iter().map(|phase| phase.kind()).collect();
    assert_eq!(
        kinds,
        vec![ScanKind::PortScan],
        "an idle scan has one phase, and it ran no pass that made another"
    );

    let reasons: Vec<&str> = report.refusals().map(|refusal| refusal.reason()).collect();
    for pass in [
        "active operating-system probing",
        "the route trace",
        "the filter characterisation",
        "the IP-protocol probe",
        "TLS enumeration",
        "active detection",
    ] {
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains(pass) && reason.contains("idle scan")),
            "no refusal names {pass}: {reasons:?}"
        );
    }
}

/// A host that is there is scanned exactly as it would be with no gate.
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
/// `192.0.2.1:8080` — so a gate that rebuilt one set against one port list
/// would answer a different question from the one that was asked.
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
