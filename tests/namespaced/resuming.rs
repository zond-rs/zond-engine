// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a resumed sitting of a raw scan puts on the wire.
//!
//! Tier 2 asserts that a finished job resumes without sending, over loopback,
//! and loopback cannot see the half of a raw scan that asks about hosts rather
//! than ports. A frame never reaches this machine's own address and no sweep
//! asks about one, since the host is recorded up without a probe. So the sweep
//! that finds which hosts are there, and the one that reads their hardware
//! addresses beside a scan that assumes them up, are only exercised against a
//! host on a link.

use crate::netns::{Segment, available};
use crate::support::{target_map, test_config};
use zond_engine::Exclusions;
use zond_engine::detect::Detections;
use zond_engine::journal::Journal;
use zond_engine::journal::manifest::Plan;
use zond_engine::model::technique::TcpScanTechnique;
use zond_engine::system::privilege::Privilege;

/// A resumed sitting of a finished raw port scan sends nothing, whether the
/// scan establishes which hosts are there first or assumes they are.
///
/// Both host passes are aimed at the addresses with a target left, and a job
/// whose first sitting settled every target leaves none. Observed as the probes
/// the second sitting's phases recorded, because a resume that swept the host
/// again produces the same report and only this count shows the difference.
#[tokio::test]
async fn a_finished_raw_scan_resumes_without_sending() {
    if !available() {
        return;
    }

    for assume_up in [false, true] {
        let mut segment = Segment::new();
        let closed = segment.closed_tcp_port();
        let plan = target_map(segment.peer(), &closed.to_string());
        let recorded = Plan::port_scan(&plan, &Exclusions::none(), TcpScanTechnique::Syn);

        let mut cfg = test_config();
        cfg.assume_up = assume_up;

        let root =
            std::env::temp_dir().join(format!("zond-resume-{}-{assume_up}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch root");

        let journal =
            Journal::create(&root, &recorded, Privilege::current(), "segment").expect("creates");
        let directory = journal.directory().to_path_buf();
        let (_session, task) = zond_engine::scanner::scan_with_journal(
            plan.clone(),
            &cfg,
            Detections::embedded(),
            journal,
        )
        .await
        .expect("the first sitting starts");
        let first = task.join().await.expect("the first sitting finishes");
        let first_phases = first.phases().len();

        let (journal, checkpoint) =
            Journal::resume(&directory, &recorded, Privilege::current()).expect("resumes");
        assert_eq!(
            checkpoint.remaining(plan.iter()).count(),
            0,
            "a closed port is an earned verdict, so the first sitting settled \
             the whole plan (assume_up: {assume_up})"
        );

        let (_session, task) = zond_engine::scanner::scan_with_journal(
            plan.clone(),
            &cfg,
            Detections::embedded(),
            journal,
        )
        .await
        .expect("the second sitting starts");
        let second = task.join().await.expect("the second sitting finishes");

        let sent: Vec<(String, u64)> = second.phases()[first_phases..]
            .iter()
            .flat_map(|phase| phase.probe_stats())
            .filter(|probes| probes.sends_attempted() > 0)
            .map(|probes| (format!("{:?}", probes.scanner()), probes.sends_attempted()))
            .collect();
        assert!(
            sent.is_empty(),
            "the first sitting settled every target, so the second must send \
             nothing (assume_up: {assume_up}), and sent {sent:?}"
        );

        std::fs::remove_dir_all(&root).ok();
    }
}

/// A journalled sweep or port scan of addresses this host has no route to
/// finishes its job in one sitting, so a resume asks none of them again.
///
/// Each is filed as one the host cannot reach, which is its routing answering
/// for it, and every target at it is settled there. Left unsettled, the job
/// was listed as resumable however often it ran, and every sitting asked all
/// of them again. A port scan settles them whichever phase files them: its
/// port probes where one port costs no more than asking, and its liveness pass
/// where twenty do.
#[tokio::test]
async fn a_job_of_addresses_with_no_route_finishes_in_one_sitting() {
    use std::net::IpAddr;
    use zond_engine::model::ip::set::IpSet;
    use zond_engine::model::port::PortSet;
    use zond_engine::model::target::{TargetMap, TargetSet};

    if !available() {
        return;
    }

    let segment = Segment::new();
    let mut addresses = IpSet::new();
    for address in segment.refused_routes() {
        addresses.insert(IpAddr::V4(address));
    }
    let cfg = test_config();
    let root = std::env::temp_dir().join(format!("zond-no-route-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch root");

    let recorded = Plan::discovery(&addresses, &Exclusions::none(), false);
    let journal =
        Journal::create(&root, &recorded, Privilege::current(), "no route").expect("creates");
    let directory = journal.directory().to_path_buf();
    let (_session, task) =
        zond_engine::scanner::discover_with_journal(addresses.clone(), &cfg, journal)
            .await
            .expect("the sweep starts");
    let _report = task.join().await.expect("the sweep finishes");
    let (_journal, checkpoint) =
        Journal::resume(&directory, &recorded, Privilege::current()).expect("resumes");
    assert_eq!(
        checkpoint.settled_count(),
        4,
        "the sweep left addresses owed"
    );

    for ports in ["22", "1-20"] {
        let mut plan = TargetMap::new();
        plan.add_unit(TargetSet::new(
            addresses.clone(),
            PortSet::try_from(ports).expect("ports"),
        ));
        let recorded = Plan::port_scan(&plan, &Exclusions::none(), TcpScanTechnique::Syn);
        let journal =
            Journal::create(&root, &recorded, Privilege::current(), "no route").expect("creates");
        let directory = journal.directory().to_path_buf();
        let (_session, task) = zond_engine::scanner::scan_with_journal(
            plan.clone(),
            &cfg,
            Detections::embedded(),
            journal,
        )
        .await
        .expect("the scan starts");
        let _report = task.join().await.expect("the scan finishes");
        let (_journal, checkpoint) =
            Journal::resume(&directory, &recorded, Privilege::current()).expect("resumes");
        let owed: Vec<_> = checkpoint.remaining(plan.iter()).collect();
        assert!(owed.is_empty(), "ports {ports}: still owed {owed:?}");
    }

    std::fs::remove_dir_all(&root).ok();
}
