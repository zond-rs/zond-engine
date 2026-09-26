// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ports a scan may not probe on any target.
//!
//! Two listeners on loopback, both named in the port list and one of them
//! excluded. Each counts the connections it accepts, so the excluded one is
//! evidence of the promise on the connect path, where a probe is a connection;
//! on a raw path a probe completes no connection, and the port being absent
//! from the report is the evidence there. The same scan with nothing excluded
//! is the other half: it has to find the second listener, or the first scan's
//! silence proves nothing about the exclusion.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::support::*;
use zond_engine::model::port::{PortSet, PortState, Protocol};

/// A listener counting every connection it accepts, and closing each at once.
struct Counted {
    port: u16,
    accepted: Arc<AtomicUsize>,
    _task: JoinHandle<()>,
}

impl Counted {
    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

async fn spawn_counted() -> Counted {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind loopback listener");
    let port = listener.local_addr().expect("listener local addr").port();
    let accepted = Arc::new(AtomicUsize::new(0));

    let count = Arc::clone(&accepted);
    let task = tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            count.fetch_add(1, Ordering::SeqCst);
        }
    });

    Counted {
        port,
        accepted,
        _task: task,
    }
}

/// **An excluded port is sent nothing, reported nowhere among the ports, and
/// named in the settings as excluded.**
///
/// A connection to it is a probe the caller forbade, and a verdict for it is a
/// probe somebody sent. The port beside it is found as ever, so the exclusion
/// took one port out of the scan rather than the scan out of the run.
#[tokio::test]
async fn an_excluded_port_is_sent_nothing_and_the_report_says_it_was_excluded() {
    let kept = spawn_counted().await;
    let excluded = spawn_counted().await;

    let mut cfg = test_config();
    cfg.excluded_ports = PortSet::from_iter([(excluded.port, Protocol::Tcp)]);
    let outcome = run_scan(
        target_map(LOOPBACK, &format!("{},{}", kept.port, excluded.port)),
        &cfg,
    )
    .await;

    assert_eq!(
        outcome.port_state(LOOPBACK, kept.port),
        Some(PortState::Open)
    );
    assert_eq!(excluded.accepted(), 0, "the excluded port was connected to");
    assert_eq!(
        outcome.port_state(LOOPBACK, excluded.port),
        None,
        "the excluded port has a verdict, so something probed it"
    );

    let phase = outcome.report.phases().last().expect("a phase");
    assert!(
        phase.settings().excluded_ports.has_tcp(excluded.port),
        "the report does not say the port was excluded"
    );
    assert_eq!(
        phase.targets().ports().covers(excluded.port, Protocol::Tcp),
        Some(false),
        "the scope says the excluded port was walked"
    );
}

/// **With nothing excluded, the same scan finds the second listener.**
///
/// What keeps the first test honest: were the second port never probed for
/// some other reason, its silence there would prove nothing.
#[tokio::test]
async fn the_same_scan_with_nothing_excluded_finds_the_port() {
    let kept = spawn_counted().await;
    let other = spawn_counted().await;

    let outcome = run_scan(
        target_map(LOOPBACK, &format!("{},{}", kept.port, other.port)),
        &test_config(),
    )
    .await;

    assert_eq!(
        outcome.port_state(LOOPBACK, other.port),
        Some(PortState::Open)
    );
    assert!(
        outcome
            .report
            .phases()
            .last()
            .expect("a phase")
            .settings()
            .excluded_ports
            .is_empty()
    );
}
