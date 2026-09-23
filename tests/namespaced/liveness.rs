// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a port scan establishes before it spends a probe on a port, asked of
//! a host that is not there.
//!
//! Tier 1 asks the same of a loopback address nothing answers for, which macOS
//! has and Linux does not: Linux holds the whole of `127.0.0.0/8` and answers
//! every address in it. Here the silent host is built, as an address routed
//! through the peer that nothing holds, so the questions are asked on Linux
//! too and nothing leaves the machine to ask them.

use std::net::IpAddr;

use crate::netns::{Segment, available};
use crate::support::{run_scan, target_map, test_config};
use zond_engine::report::ScanKind;

/// An address nothing answers for gets a handful of liveness probes, not one
/// per port, and the report's second phase covers none of it.
#[tokio::test]
async fn an_address_nothing_answers_for_is_never_port_scanned() {
    if !available() {
        return;
    }

    let segment = Segment::new();
    let silent = IpAddr::V4(segment.silent_host());

    let outcome = run_scan(target_map(silent, "1-64"), &test_config()).await;

    assert_eq!(
        outcome.host(silent).map_or(0, |host| host.port_count()),
        0,
        "a silent address was port-scanned anyway"
    );
    let [liveness, ports, ..] = outcome.report.phases() else {
        panic!("a port scan records two phases");
    };
    assert_eq!(
        liveness.targets().addresses(),
        1,
        "one address was asked about"
    );
    assert_eq!(ports.targets().addresses(), 0, "and none of it answered");
}

/// `assume_up` probes the ports of a host that answers no knock, and skips the
/// liveness phase rather than running it and ignoring the result.
#[tokio::test]
async fn assume_up_probes_a_silent_hosts_ports_without_asking_first() {
    if !available() {
        return;
    }

    let segment = Segment::new();
    let silent = IpAddr::V4(segment.silent_host());
    let mut cfg = test_config();
    cfg.assume_up = true;

    let outcome = run_scan(target_map(silent, "1,2"), &cfg).await;

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
