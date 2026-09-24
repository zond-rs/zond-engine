// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! On-link addresses nothing answers address resolution for, scanned beside a
//! live host through the kernel's own resolution.
//!
//! Only a kernel shows this. Linux takes a raw socket's write to a neighbour it
//! is still asking for, queues it against the socket's buffer, and says nothing
//! when the asking fails, so what a scan makes of a dead neighbour, and what
//! the queued writes do to the live host beside it, cannot be asked of a
//! simulated network.

use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU32;

use crate::netns::{Segment, available};
use crate::support::{run_scan, test_config};
use zond_engine::model::host::HostStatus;
use zond_engine::model::ip::set::IpSet;
use zond_engine::model::port::{PortSet, PortState};
use zond_engine::model::target::{TargetMap, TargetSet};

/// Ten on-link addresses nobody holds read as ten unreachable addresses, every
/// port unasked, and the live host scanned beside them reads exactly as it
/// would alone.
///
/// The kernel accepts every write to a neighbour it is resolving and throws
/// the queue away when the resolution fails, so written freely the dead
/// addresses' probes read as sent and unanswered, and they stay charged to the
/// raw socket until then: enough of them and the kernel refuses the socket's
/// writes with `ENOBUFS`, which the scan reads as its own send path failing.
/// So the report must name each dead address as unreached, hold no failure,
/// and give the live host its open port and its closed ones.
///
/// And the ten must read alike. The kernel tells itself about each write it
/// threw away with a host unreachable over loopback, and whether the capture
/// there catches one is chance, so a status taken from those messages would
/// differ between identical addresses.
#[tokio::test]
async fn dead_neighbours_read_unreachable_and_leave_the_live_host_alone() {
    scan_beside_dead_neighbours(None).await;
}

/// The same under a rate ceiling, where every probe the scan puts on the wire
/// spends a share of a small budget.
///
/// A probe the scan holds while the kernel resolves a dead neighbour is not
/// on the wire, and must not spend that budget: held and re-checked for ten
/// dead addresses of forty ports each, it would take every share there is,
/// and the live host would reach the deadline with most of its ports never
/// asked.
#[tokio::test]
async fn dead_neighbours_spend_none_of_a_rate_ceiling_the_live_host_needs() {
    for rate in [100, 300] {
        scan_beside_dead_neighbours(NonZeroU32::new(rate)).await;
    }
}

/// Scans a live host and ten on-link addresses nobody holds, ports 1 to 40
/// and the live host's one open port, under `rate`, and checks everything
/// the tests above promise.
async fn scan_beside_dead_neighbours(rate: Option<NonZeroU32>) {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let live = segment.peer();
    let IpAddr::V4(peer) = live else {
        unreachable!("the segment is addressed in IPv4");
    };
    let open = segment.listen_tcp();
    let dead: Vec<IpAddr> = (75..85)
        .map(|offset| IpAddr::V4(Ipv4Addr::from(u32::from(peer) + offset)))
        .collect();

    let mut addresses = IpSet::new();
    addresses.insert(live);
    for address in &dead {
        addresses.insert(*address);
    }
    let ports = PortSet::try_from(format!("1-40,{open}").as_str()).expect("a port list");
    let mut map = TargetMap::new();
    map.add_unit(TargetSet::new(addresses, ports));
    let mut cfg = test_config();
    cfg.assume_up = true;
    cfg.max_probe_rate = rate;

    let outcome = run_scan(map, &cfg).await;

    let phase = outcome
        .report
        .phases()
        .last()
        .expect("the port scan recorded a phase");
    assert!(
        phase.failures().is_empty(),
        "nothing on this host failed at {rate:?}: {:?}",
        phase.failures()
    );
    for address in &dead {
        assert!(
            phase.unroutable().contains(address),
            "{address} is reported unreached: {:?}",
            phase.unroutable()
        );
        let host = outcome.host(*address).expect("a named address is recorded");
        assert!(
            host.ports().all(|port| port.state() == PortState::Unasked),
            "no probe reached {address}, so none of its ports was asked"
        );
    }
    let statuses: Vec<HostStatus> = dead
        .iter()
        .filter_map(|address| outcome.host(*address).map(|host| host.status()))
        .collect();
    assert!(
        statuses
            .iter()
            .all(|status| *status == statuses[0] && *status != HostStatus::Down),
        "ten identical dead addresses read alike, and not as down: {statuses:?}"
    );
    assert_eq!(
        outcome.port_state(live, open),
        Some(PortState::Open),
        "the live host's open port was found at {rate:?}"
    );
    for port in 1..=40 {
        assert_eq!(
            outcome.port_state(live, port),
            Some(PortState::Closed),
            "the live host's port {port} was answered at {rate:?}"
        );
    }
    assert!(!phase.unroutable().contains(&live));
}
