// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Comparing and folding reports two scans actually produced.
//!
//! `diff` and `merge` both take [`ScanReport`]s, and until this file neither
//! was driven from outside the crate. The unit tests beside them build the
//! reports they compare, which settles the rules and leaves one question open:
//! whether the record a scan writes is the record those rules were written
//! against. A host keyed under an address the sweep did not name, a scope
//! assembled from two phases rather than one, a port the discovery probe filed
//! before the port scanner ran: none of that appears in a hand-built fixture,
//! and all of it decides what a comparison says.
//!
//! So every report here comes out of a scanner. The simulated segment is what
//! makes that possible: a machine can arrive, go quiet, or answer at a new
//! address between two runs, which loopback cannot express, and the reports are
//! closed with [`PhaseRecorder`] exactly as `scanner::scan` closes its own.
//!
//! Tier 2, alongside `probe_classification` and `lan_discovery`, with one
//! borrowing from Tier 1: a service version only moves when something real
//! greets a real socket, so the two banners it takes are served on loopback.
//!
//! ## The one thing no scan here produces
//!
//! Neither loopback nor the simulated segment completes a TLS handshake, so the
//! certificate the expiry tests are about is stated by the test. Everything
//! around it stays the scan's: the phases, the scope they cover, and the clock
//! each report is placed at, which is what those tests are asking about.

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use pnet_base::MacAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use common::fake_lan::{FakeLan, LanHost};
use common::fake_net::{FakeNet, Layer4, Policy};
use common::*;

use zond_engine::diff::{
    CertificateChange, Coverage, DiffOptions, HostChange, HostDelta, HostIdentity, PortChange,
    Presence, ScanDiff, SecurityChange, ServiceChange,
};
use zond_engine::merge::{Merge, MergeOptions};
use zond_engine::model::exclusion::Exclusions;
use zond_engine::model::host::Host;
use zond_engine::model::ip::set::IpSet;
use zond_engine::model::port::security::{CertificateInfo, Security};
use zond_engine::model::port::{Port, PortSet, PortState, Protocol};
use zond_engine::model::target::{Target, TargetMap, TargetSet};
use zond_engine::model::technique::TcpScanTechnique;
use zond_engine::report::{PhaseOrigin, ScanKind, ScanReport, TargetScope};
use zond_engine::scanner::recorder::PhaseRecorder;
use zond_engine::scanner::session::ScanSession;
use zond_engine::scanner::strategy::HostScanner;
use zond_engine::scanner::strategy::local::{LocalScanner, Scope};
use zond_engine::scanner::strategy::routed::{RoutedScanner, TcpPortScanner};
use zond_engine::system::interface::RoutedTarget;

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// The port a routed sweep sends its SYN to, which is what decides whether a
/// simulated host is found at all.
const SWEEP_PORT: u16 = 443;

/// The ports every simulated port scan below walks.
const PORTS: &str = "22,80";

/// The machine that is there both times.
const STAYED: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
/// The machine the second scan does not hear from.
const WENT_QUIET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11));
/// The machine only the second scan hears from.
const ARRIVED: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 12));
/// The lease the machine on the segment held first, and the one it holds
/// after that lease rotated.
const RELEASED: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
const RENEWED: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 60));

const LEASE_HOLDER: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0xAA);

// ── Driving a scan ──────────────────────────────────────────────────────────

/// One scan of the simulated segment: a sweep, then a port scan of what the
/// sweep found.
///
/// The two phases and the order they run in are `scanner::scan`'s, and each is
/// closed with the recorder that entry point uses, so what comes back is the
/// same shape of document a real job leaves behind.
async fn scan_segment(net: &FakeNet, swept: &[IpAddr], ports: &str) -> ScanReport {
    let cfg = test_config();
    let (session, ctx) = ScanSession::new();

    let mut addresses = IpSet::new();
    for ip in swept {
        addresses.insert(*ip);
    }
    addresses.canonicalize();
    let sweep_scope = TargetScope::from_ip_set(&mut addresses, &Exclusions::none());
    let sweep = PhaseRecorder::start(ScanKind::Discovery, true, sweep_scope, &cfg);

    let mut scanner = RoutedScanner::with_transport(
        swept
            .iter()
            .map(|ip| RoutedTarget {
                target: *ip,
                source: SCANNER_V4.into(),
            })
            .collect(),
        ctx.clone(),
        None,
        net.transport(),
    );
    scanner
        .discover_hosts()
        .await
        .expect("the sweep runs to completion");

    let mut discovery = sweep.finish(&ctx);

    let alive: Vec<IpAddr> = discovery
        .hosts()
        .filter(|host| host.is_alive())
        .map(Host::primary_ip)
        .collect();

    let numbers = PortSet::try_from(ports).expect("a port specification");
    let mut found = IpSet::new();
    for ip in &alive {
        found.insert(*ip);
    }
    found.canonicalize();
    let mut asked = TargetMap::new();
    asked.add_unit(TargetSet::new(found, numbers.clone()));
    let port_scope = TargetScope::from_target_map(&mut asked, &Exclusions::none());
    let recorder = PhaseRecorder::start(ScanKind::PortScan, true, port_scope, &cfg);

    let endpoints: Vec<Target> = alive
        .iter()
        .flat_map(|ip| {
            numbers
                .to_vec()
                .into_iter()
                .map(move |(number, _)| tcp(*ip, number))
        })
        .collect();
    let mut scanner = TcpPortScanner::with_transport(
        scanner_resolver(),
        ctx.clone(),
        TcpScanTechnique::Syn,
        net.transport(),
        endpoints.len().max(1),
    );
    run_port_scanner(&mut scanner, endpoints).await;

    discovery.merge(recorder.finish(&ctx));
    drop(session);
    discovery
}

/// One sweep of the simulated segment at the link layer, which is the only
/// scan that learns a machine's hardware address.
async fn sweep_segment(lan: &FakeLan, targets: &[IpAddr]) -> ScanReport {
    let cfg = test_config();
    let (session, ctx) = ScanSession::new();

    let mut addresses = IpSet::new();
    for ip in targets {
        addresses.insert(*ip);
    }
    addresses.canonicalize();
    let scope = TargetScope::from_ip_set(&mut addresses.clone(), &Exclusions::none());
    let recorder = PhaseRecorder::start(ScanKind::Discovery, true, scope, &cfg);

    let mut scanner = LocalScanner::with_handle(
        scanner_interface(),
        addresses,
        ctx.clone(),
        None,
        Scope::Sweep,
        lan.handle(),
    )
    .expect("the scanner builds over the simulated segment");
    scanner
        .discover_hosts()
        .await
        .expect("the sweep runs to completion");

    let report = recorder.finish(&ctx);
    drop(session);
    report
}

/// The segment as the first scan finds it: two machines answering, a third
/// address with nothing on it.
///
/// Built fresh per scan rather than shared, because a simulated host remembers
/// which connections it is holding half open and a second SYN on one of them is
/// answered as the challenge it would draw on a real stack.
fn monday() -> FakeNet {
    FakeNet::new(Layer4::Tcp)
        .host(STAYED, SWEEP_PORT, Policy::closed())
        .host(STAYED, 22, Policy::open())
        .host(STAYED, 80, Policy::closed())
        .host(WENT_QUIET, SWEEP_PORT, Policy::closed())
        .host(WENT_QUIET, 22, Policy::closed())
        .host(WENT_QUIET, 80, Policy::closed())
}

/// The same segment a week later: 22 shut on the machine that stayed and 80
/// opened, one machine gone, one arrived.
fn tuesday() -> FakeNet {
    FakeNet::new(Layer4::Tcp)
        .host(STAYED, SWEEP_PORT, Policy::closed())
        .host(STAYED, 22, Policy::closed())
        .host(STAYED, 80, Policy::open())
        .host(ARRIVED, SWEEP_PORT, Policy::closed())
        .host(ARRIVED, 22, Policy::closed())
        .host(ARRIVED, 80, Policy::closed())
}

/// The addresses both scans walk, so that every appearance and disappearance
/// below is one the other scan is known to have looked for.
fn segment() -> [IpAddr; 3] {
    [STAYED, WENT_QUIET, ARRIVED]
}

/// The delta the diff holds for `address`.
fn delta_for(diff: &ScanDiff, address: IpAddr) -> &HostDelta {
    diff.hosts()
        .iter()
        .find(|delta| delta.address() == address)
        .unwrap_or_else(|| panic!("{address} is in the diff: {:?}", addresses(diff)))
}

fn addresses(diff: &ScanDiff) -> Vec<IpAddr> {
    diff.hosts().iter().map(|delta| delta.address()).collect()
}

// ── A diff over two scans of the segment ────────────────────────────────────

/// The whole of what a week did to the segment, and nothing else.
///
/// Every count the summary holds is asserted, including the seven that stayed
/// at zero, because the claim is not only that each change is named. It is that
/// a comparison of two documents a scanner wrote invents nothing around them,
/// and the counts nobody expects to move are the only place that shows.
#[tokio::test]
async fn a_week_of_the_segment_is_four_changes_and_no_others() {
    let before = scan_segment(&monday(), &segment(), PORTS).await;
    let after = scan_segment(&tuesday(), &segment(), PORTS).await;

    let diff = ScanDiff::between(&before, &after);
    let summary = diff.summary();

    assert_eq!(
        addresses(&diff),
        vec![STAYED, WENT_QUIET, ARRIVED],
        "three machines moved, ascending by address"
    );

    assert_eq!(summary.hosts_added.total, 1);
    assert_eq!(summary.hosts_added.confirmed, 1);
    assert_eq!(summary.hosts_removed.total, 1);
    assert_eq!(summary.hosts_removed.confirmed, 1);
    assert_eq!(summary.hosts_changed, 1);
    assert_eq!(summary.ports_opened.total, 1);
    assert_eq!(summary.ports_opened.confirmed, 1);
    assert_eq!(summary.ports_closed.total, 1);
    assert_eq!(summary.ports_closed.confirmed, 1);
    assert_eq!(summary.services_changed, 0);
    assert_eq!(summary.certificates_rotated, 0);
    assert_eq!(summary.certificates_expiring, 0);
    assert_eq!(summary.certificates_expired, 0);
}

/// A machine that arrived where the first scan looked, and one that stopped
/// answering where the second one did.
///
/// The coverage is the assertion that matters. Both scans walked all three
/// addresses, so each of these is a finding about the segment rather than about
/// how far the scan reached, and that is exactly the distinction the next test
/// takes away.
#[tokio::test]
async fn a_rescan_names_the_machine_that_arrived_and_the_one_that_went_quiet() {
    let before = scan_segment(&monday(), &segment(), PORTS).await;
    let after = scan_segment(&tuesday(), &segment(), PORTS).await;

    let diff = ScanDiff::between(&before, &after);

    let arrived = delta_for(&diff, ARRIVED);
    assert_eq!(
        arrived.presence(),
        Presence::Added {
            before: Coverage::Covered
        },
        "the first scan swept this address and found nothing on it"
    );
    assert!(arrived.presence().is_confirmed());
    assert!(arrived.baseline().is_none());
    assert!(arrived.current().is_some());

    let quiet = delta_for(&diff, WENT_QUIET);
    assert_eq!(
        quiet.presence(),
        Presence::Removed {
            after: Coverage::Covered
        },
        "the second scan swept it too, so the silence is the machine's"
    );
    assert!(quiet.presence().is_confirmed());
}

/// The endpoint that opened and the endpoint that shut, each named once and
/// against the machine that holds it.
#[tokio::test]
async fn a_rescan_names_the_port_that_opened_and_the_one_that_closed() {
    let before = scan_segment(&monday(), &segment(), PORTS).await;
    let after = scan_segment(&tuesday(), &segment(), PORTS).await;

    let diff = ScanDiff::between(&before, &after);
    let stayed = delta_for(&diff, STAYED);

    assert!(
        stayed.presence().is_in_both(),
        "the machine itself did not move"
    );
    assert!(!stayed.is_regrouped());
    assert_eq!(stayed.records(), (1, 1));

    let moved: Vec<(u16, bool, bool)> = stayed
        .ports()
        .iter()
        .map(|port| (port.number(), port.is_opened(), port.is_closed()))
        .collect();
    assert_eq!(
        moved,
        vec![(22, false, true), (80, true, false)],
        "22 shut and 80 opened, and nothing else on the machine moved"
    );

    let shut = &stayed.ports()[0];
    assert!(matches!(
        shut.changes().first(),
        Some(PortChange::State(state))
            if state.before == PortState::Open && state.after == PortState::Closed
    ));
}

/// Two scans that found the same segment report nothing.
///
/// The guard on every assertion above. A scan measures itself as well as the
/// network, and everything it measures moves between two runs: how long each
/// phase took, how many probes went out, how fast each host answered, when the
/// report was written. None of that is a finding, and a comparison that let any
/// of it through would report a changed network every night.
#[tokio::test]
async fn two_scans_that_found_the_same_segment_report_nothing() {
    let before = scan_segment(&monday(), &segment(), PORTS).await;
    let after = scan_segment(&monday(), &segment(), PORTS).await;

    let diff = ScanDiff::between(&before, &after);

    assert!(
        diff.is_empty(),
        "an unchanged segment is an empty diff, got {:?}",
        diff.hosts()
    );
    assert!(
        before.observed_at() < after.observed_at(),
        "the two reports really were written at different moments"
    );
    assert_eq!(diff.baseline().hosts(), 2);
    assert_eq!(diff.current().hosts(), 2);
    assert!(diff.baseline().states_scope());
}

// ── Which record continues which ────────────────────────────────────────────

/// A machine whose lease moved is one machine, and only the hardware policy can
/// see that.
///
/// The case pairing exists for. Nothing about the two records overlaps except
/// the address the segment answered from, so under the default policy a scan of
/// a DHCP network reports a host gone and another arrived every time a lease
/// rotates.
#[tokio::test]
async fn a_machine_that_changed_address_is_one_machine_under_the_hardware_policy() {
    let released = FakeLan::new().host(RELEASED, LanHost::at(LEASE_HOLDER));
    let renewed = FakeLan::new().host(RENEWED, LanHost::at(LEASE_HOLDER));

    let targets = [RELEASED, RENEWED];
    let before = sweep_segment(&released, &targets).await;
    let after = sweep_segment(&renewed, &targets).await;

    let by_address = ScanDiff::between(&before, &after);
    assert_eq!(
        by_address.summary().hosts_added.total,
        1,
        "nothing links the two addresses without the hardware policy"
    );
    assert_eq!(by_address.summary().hosts_removed.total, 1);

    let by_hardware = ScanDiff::compare(
        &before,
        &after,
        &DiffOptions::new().with_identity(HostIdentity::Hardware),
    );

    assert_eq!(by_hardware.hosts().len(), 1, "one machine, not two");
    let delta = &by_hardware.hosts()[0];
    assert!(delta.presence().is_in_both());
    assert_eq!(by_hardware.summary().hosts_added.total, 0);
    assert_eq!(by_hardware.summary().hosts_removed.total, 0);

    let addresses = delta
        .changes()
        .iter()
        .find_map(|change| match change {
            HostChange::Addresses { gained, lost } => Some((gained.clone(), lost.clone())),
            _ => None,
        })
        .expect("the address it moved to is the change");
    assert_eq!(addresses, (vec![RENEWED], vec![RELEASED]));
}

/// A machine answering at both addresses pairs on the one they share, and the
/// second address reads as gained rather than as a second machine.
///
/// A sweep records one host for two addresses off one hardware address, so this
/// is the pairing input a hand-built fixture has to be told to build and a real
/// segment produces on its own.
#[tokio::test]
async fn a_machine_answering_at_a_second_address_pairs_on_the_one_it_kept() {
    let before = sweep_segment(
        &FakeLan::new().host(RELEASED, LanHost::at(LEASE_HOLDER)),
        &[RELEASED, RENEWED],
    )
    .await;
    let after = sweep_segment(
        &FakeLan::new()
            .host(RELEASED, LanHost::at(LEASE_HOLDER))
            .host(RENEWED, LanHost::at(LEASE_HOLDER)),
        &[RELEASED, RENEWED],
    )
    .await;

    assert_eq!(
        after.host_count(),
        1,
        "the sweep read one hardware address, so it recorded one machine"
    );

    let diff = ScanDiff::between(&before, &after);

    assert_eq!(diff.hosts().len(), 1);
    let delta = &diff.hosts()[0];
    assert!(delta.presence().is_in_both());
    assert_eq!(diff.summary().hosts_added.total, 0);

    let gained = delta
        .changes()
        .iter()
        .find_map(|change| match change {
            HostChange::Addresses { gained, .. } => Some(gained.clone()),
            _ => None,
        })
        .expect("the address it gained is the change");
    assert_eq!(gained, vec![RENEWED]);
}

// ── Scope ───────────────────────────────────────────────────────────────────

/// A narrower second scan does not turn the addresses it skipped into machines
/// that went away.
///
/// The answer here is subtler than "they are left out", and the subtlety is the
/// feature. The record is still reported, because a consumer asking what is
/// different between two documents wants to know one of them has no word about
/// this host. What it is not is *confirmed*: the coverage travelling with the
/// presence says the second scan never walked the address, so nothing here is
/// evidence about the segment, and the confirmed count a front end leads with
/// stays at zero.
#[tokio::test]
async fn a_narrower_second_scan_confirms_no_disappearance() {
    let wide = scan_segment(&monday(), &segment(), PORTS).await;
    let narrow = scan_segment(&monday(), &[STAYED], PORTS).await;

    let diff = ScanDiff::between(&wide, &narrow);
    let skipped = delta_for(&diff, WENT_QUIET);

    assert_eq!(
        skipped.presence(),
        Presence::Removed {
            after: Coverage::OutOfScope
        },
        "the second scan was never pointed at this address"
    );
    assert!(!skipped.presence().is_confirmed());

    let summary = diff.summary();
    assert_eq!(summary.hosts_removed.total, 1, "the record is still shown");
    assert_eq!(
        summary.hosts_removed.confirmed, 0,
        "and none of it is a finding about the segment"
    );
}

// ── Certificates, and which clock they are judged against ───────────────────

/// A real scan's phases and hosts, with [`STAYED`] presenting a certificate
/// good until `until` on 8443.
///
/// The certificate is the one thing on this page a scan did not produce; see
/// the module documentation. Everything the tests below turn on stays the
/// scan's: the phases decide the report's clock and its scope, and the host it
/// is attached to is the one the sweep found.
fn presenting(report: &ScanReport, until: SystemTime) -> ScanReport {
    let issued = report.observed_at() - 90 * DAY;
    let hosts: Vec<Host> = report
        .hosts()
        .map(|found| {
            let mut host = found.clone();
            if host.primary_ip() == STAYED {
                host.add_port(
                    Port::new(8443, Protocol::Tcp, PortState::Open).with_security(
                        Security::new().with_certificate(CertificateInfo::new(
                            "segment.test",
                            "Test CA",
                            issued,
                            until,
                            "9f8e7d6c",
                        )),
                    ),
                );
            }
            host
        })
        .collect();

    ScanReport::recorded(report.engine_version(), report.phases().to_vec(), hosts)
}

/// Asked as of a later moment, a certificate nobody touched crosses the
/// threshold.
///
/// One scan's report stands on both sides, so the certificate's standing is
/// the only thing that can have moved. It has not: both clocks are the moment
/// the scan ran, when it had forty-five days of life left. `as_of` is what a
/// caller asking where a stored scan stands today has, and it moves the current
/// side only, because it is the two standings differing that makes a change.
#[tokio::test]
async fn a_stored_scan_asked_about_a_later_moment_reports_the_threshold_it_crossed() {
    let scanned = scan_segment(&monday(), &segment(), PORTS).await;
    let taken = scanned.observed_at();

    let before = presenting(&scanned, taken + 45 * DAY);
    let after = presenting(&scanned, taken + 45 * DAY);

    assert!(
        ScanDiff::between(&before, &after).is_empty(),
        "at the clocks the scans ran at, the certificate had forty-five days left"
    );

    let asked_later =
        ScanDiff::compare(&before, &after, &DiffOptions::new().as_of(taken + 20 * DAY));

    assert_eq!(
        asked_later.summary().certificates_expiring,
        1,
        "twenty-five days left is inside the default thirty-day threshold"
    );

    let changes = asked_later.hosts()[0].ports()[0].changes();
    let Some(PortChange::Security(SecurityChange::Certificate(certificate))) = changes.first()
    else {
        panic!("expected a certificate change, got {changes:?}");
    };
    assert!(
        matches!(
            certificate,
            CertificateChange::Expiring { remaining, .. }
                if *remaining == 25 * DAY
        ),
        "{certificate:?}"
    );
}

/// A tighter threshold is a shorter renewal queue, and the certificate above
/// then falls outside it.
///
/// The counterpart of the test above: the same certificate, asked about at the
/// same moment, with only the threshold different. A comparison that took the
/// default whatever it was told would report the crossing here too.
#[tokio::test]
async fn a_tighter_threshold_leaves_the_same_certificate_alone() {
    let scanned = scan_segment(&monday(), &segment(), PORTS).await;
    let taken = scanned.observed_at();

    let before = presenting(&scanned, taken + 45 * DAY);
    let after = presenting(&scanned, taken + 45 * DAY);

    let diff = ScanDiff::compare(
        &before,
        &after,
        &DiffOptions::new()
            .as_of(taken + 20 * DAY)
            .with_expiry_threshold(7 * DAY),
    );

    assert!(
        diff.is_empty(),
        "twenty-five days left is outside a seven-day threshold, so nothing crossed"
    );
}

// ── A service that moved a version ──────────────────────────────────────────

/// A speak-first server whose greeting the test can change between scans.
///
/// A daemon that was upgraded keeps its socket, and rebinding the port between
/// the two scans would leave them looking at two different listeners. What
/// comes back is the port and the handle, because the listener has to outlive
/// both scans and be closed once they are done.
async fn spawn_upgradable_server(banner: Arc<Mutex<&'static [u8]>>) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the loopback server");
    let port = listener.local_addr().expect("the server's address").port();

    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let greeting = *banner.lock().expect("the banner");
            let _ = socket.write_all(greeting).await;
            let _ = socket.flush().await;
        }
    });

    (port, task)
}

/// The daemon behind a port was upgraded, and that is the whole of what
/// changed.
///
/// The one finding on this page that needs a real socket: a version is read off
/// a banner, so nothing short of a server saying a different thing on the same
/// port produces one. Both reports come out of `scanner::scan`, which is what
/// puts the service through the connect, the grab and the analyzer rather than
/// through a constructor.
#[tokio::test]
async fn a_daemon_that_was_upgraded_reports_the_version_it_moved_to() {
    if is_privileged() {
        eprintln!("SKIP: relies on the connect path finding the loopback listener");
        return;
    }

    let banner: Arc<Mutex<&'static [u8]>> = Arc::new(Mutex::new(b"SSH-2.0-OpenSSH_8.9p1\r\n"));
    let (port, server) = spawn_upgradable_server(Arc::clone(&banner)).await;
    let targets = target_map(LOOPBACK, &port.to_string());

    let before = run_scan(targets.clone(), &test_config()).await.report;
    *banner.lock().expect("the banner") = b"SSH-2.0-OpenSSH_9.6p1\r\n";
    let after = run_scan(targets, &test_config()).await.report;

    server.abort();

    let diff = ScanDiff::between(&before, &after);

    assert_eq!(diff.hosts().len(), 1, "one host, and it did not move");
    let endpoint = &diff.hosts()[0].ports()[0];
    assert_eq!(endpoint.number(), port);
    assert!(
        endpoint.presence().is_in_both(),
        "the port was open in both scans"
    );
    assert!(!endpoint.is_opened() && !endpoint.is_closed());

    let version = endpoint
        .changes()
        .iter()
        .find_map(|change| match change {
            PortChange::Service(ServiceChange::Version(version)) => Some(version.clone()),
            _ => None,
        })
        .expect("the version it moved to is the change");
    assert_eq!(version.before.as_deref(), Some("8.9p1"));
    assert_eq!(version.after.as_deref(), Some("9.6p1"));

    assert_eq!(diff.summary().services_changed, 1);
    assert_eq!(diff.summary().ports_opened.total, 0);
}

// ── Folding two scans into one report ───────────────────────────────────────

/// A folded report holds every phase both scans wrote, and says which document
/// each came from.
///
/// The labels are what make a merged report accountable: without them a finding
/// in a report folded from five sources cannot be traced to the one that made
/// it, and a merged report is the only kind whose findings did not all come
/// from the same place.
#[tokio::test]
async fn a_folded_report_keeps_every_phase_and_names_where_each_came_from() {
    let first = scan_segment(&monday(), &segment(), PORTS).await;
    let second = scan_segment(&tuesday(), &segment(), PORTS).await;

    let phases = first.phases().len() + second.phases().len();

    let mut merge = Merge::new(MergeOptions::default());
    merge.add_from("monday.json", first);
    merge.add_from("tuesday.json", second);
    let folded = merge.finish();

    assert!(folded.is_merged());
    assert_eq!(folded.phases().len(), phases, "no phase was folded away");
    assert_eq!(
        folded
            .phases()
            .iter()
            .map(|phase| phase.kind())
            .collect::<Vec<_>>(),
        vec![
            ScanKind::Discovery,
            ScanKind::PortScan,
            ScanKind::Discovery,
            ScanKind::PortScan,
        ],
        "chronological, which for two jobs is each job's phases in order"
    );
    assert_eq!(
        folded
            .phases()
            .iter()
            .map(|phase| phase.origin().and_then(PhaseOrigin::label))
            .collect::<Vec<_>>(),
        vec![
            Some("monday.json"),
            Some("monday.json"),
            Some("tuesday.json"),
            Some("tuesday.json"),
        ]
    );
}

/// A machine both scans found is one machine in the folded report, and the
/// newest account of each endpoint is the one that stands.
#[tokio::test]
async fn a_machine_both_scans_found_is_one_machine_in_the_fold() {
    let first = scan_segment(&monday(), &segment(), PORTS).await;
    let second = scan_segment(&tuesday(), &segment(), PORTS).await;

    let mut merge = Merge::new(MergeOptions::default());
    merge.add(first);
    merge.add(second);
    let folded = merge.finish();

    assert_eq!(
        folded.host_count(),
        3,
        "two machines from the first scan and one from the second, none twice"
    );

    let stayed = folded
        .host(&STAYED)
        .expect("the machine both scans found survives the fold");
    let states: Vec<(u16, PortState)> = stayed
        .ports()
        .filter(|port| port.number() == 22 || port.number() == 80)
        .map(|port| (port.number(), port.state()))
        .collect();
    assert_eq!(
        states,
        vec![(22, PortState::Closed), (80, PortState::Open)],
        "the later scan probed both endpoints, so its verdicts stand"
    );

    let quiet = folded
        .host(&WENT_QUIET)
        .expect("silence in the later scan is not evidence the machine went away");
    assert!(quiet.is_alive());
}

/// A machine the two scans keyed under different addresses is still one
/// machine, and the identity policy is the only thing that can say so.
///
/// The half of "one host and not two" a report cannot settle for itself. Two
/// records under one address are one host by the document's own keying, so a
/// fold that grouped nothing at all would still look right there. Two records
/// under two addresses are one host only because something read the hardware
/// address off the segment and the fold was told to believe it.
#[tokio::test]
async fn a_machine_the_two_scans_keyed_differently_is_one_machine_in_the_fold() {
    let targets = [RELEASED, RENEWED];
    let before = sweep_segment(
        &FakeLan::new().host(RELEASED, LanHost::at(LEASE_HOLDER)),
        &targets,
    )
    .await;
    let after = sweep_segment(
        &FakeLan::new().host(RENEWED, LanHost::at(LEASE_HOLDER)),
        &targets,
    )
    .await;

    let mut by_address = Merge::new(MergeOptions::default());
    by_address.add(before.clone());
    by_address.add(after.clone());
    assert_eq!(
        by_address.finish().host_count(),
        2,
        "nothing links the two addresses without the hardware policy"
    );

    let mut by_hardware = Merge::new(MergeOptions::new().with_identity(HostIdentity::Hardware));
    by_hardware.add(before);
    by_hardware.add(after);
    let folded = by_hardware.finish();

    assert_eq!(folded.host_count(), 1, "one machine, two leases");
    let machine = folded.hosts().next().expect("the machine");
    assert_eq!(
        machine.ips().iter().copied().collect::<Vec<IpAddr>>(),
        vec![RELEASED, RENEWED],
        "and the fold keeps both addresses it was seen at"
    );
}

/// A report folded from two scans compares against a third as one scan.
///
/// The shape a caller of both modules is in: a baseline folded from what is
/// already on disk, and tonight's run to hold against it. The fold has to
/// produce a document the comparison can read the same way it reads a measured
/// one, which means keeping the scope of every source, since that is what turns
/// a missing host into a finding rather than a gap.
#[tokio::test]
async fn a_report_folded_from_two_scans_compares_against_a_third() {
    let first = scan_segment(&monday(), &segment(), PORTS).await;
    let second = scan_segment(&tuesday(), &segment(), PORTS).await;

    let mut merge = Merge::new(MergeOptions::default());
    merge.add_from("monday.json", first);
    merge.add_from("tuesday.json", second);
    let baseline = merge.finish();

    // A third scan of the same segment, on which the machine that arrived on
    // Tuesday is the only one still answering.
    let wednesday = FakeNet::new(Layer4::Tcp)
        .host(ARRIVED, SWEEP_PORT, Policy::closed())
        .host(ARRIVED, 22, Policy::open())
        .host(ARRIVED, 80, Policy::closed());
    let current = scan_segment(&wednesday, &segment(), PORTS).await;

    let diff = ScanDiff::between(&baseline, &current);

    assert_eq!(
        diff.baseline().kinds().len(),
        4,
        "the folded side reads as the four phases that went into it"
    );
    assert!(
        diff.baseline().states_scope(),
        "and it still says what its sources covered"
    );
    assert_eq!(diff.baseline().hosts(), 3);

    let summary = diff.summary();
    assert_eq!(
        summary.hosts_removed.total, 2,
        "the two machines the fold knew about and Wednesday did not hear from"
    );
    assert_eq!(summary.hosts_removed.confirmed, 2);

    let arrived = delta_for(&diff, ARRIVED);
    assert!(arrived.presence().is_in_both());
    let opened: Vec<u16> = arrived
        .ports()
        .iter()
        .filter(|port| port.is_opened())
        .map(|port| port.number())
        .collect();
    assert_eq!(
        opened,
        vec![22],
        "the fold recorded 22 closed on Tuesday and Wednesday found it open"
    );
}
