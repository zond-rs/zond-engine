// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A loopback port scan sent as frames, read from the capture.
//!
//! On macOS a scan that chose the link layer writes its loopback probes to the
//! loopback interface and reads the replies off it, as it does for any other
//! link. That makes loopback the one place a Mac can watch its own capture path
//! answer a scan without sending anything past itself, with no more privilege
//! than the BPF devices. Where frames cannot be injected, or loopback takes no
//! frame, this has nothing to show.

use zond_engine::model::port::PortState;
use zond_engine::model::port::discovery::ScanResponse;
use zond_engine::system::privilege;
use zond_engine::transport::probe::SendMode;

use crate::support::*;

/// Whether a scan here that chose the link layer frames its loopback probes.
fn frames_reach_loopback() -> bool {
    cfg!(target_os = "macos") && privilege::can_inject_frames()
}

/// **An open and a closed loopback port are both read from a captured reply:
/// a SYN+ACK and a reset, rather than a connect's accepted or refused call.**
///
/// A closed port reached by connect says `ConnectionRefused`, the error the
/// operating system hands a socket, and one read from the capture says
/// `TcpRst`, the packet itself. So the reasons are what tell a scan that
/// framed its probes and heard the answers from one that did not, and a port
/// left unasked, which is what a loopback probe with no route to a frame came
/// to, has no reason at all.
#[tokio::test]
async fn a_loopback_scan_on_the_link_layer_reads_both_answers_off_the_capture() {
    if !frames_reach_loopback() {
        eprintln!("SKIP: frames reach loopback on macOS, with the BPF devices");
        return;
    }

    let open = spawn_banner_server(b"hi\r\n").await;
    let closed = closed_loopback_port().await;
    let mut cfg = test_config();
    cfg.send_mode = SendMode::Ethernet;
    let outcome = run_scan(
        target_map(LOOPBACK, &format!("{},{closed}", open.port)),
        &cfg,
    )
    .await;

    let host = outcome.host(LOOPBACK).expect("the loopback host");
    let reason = |number: u16| {
        host.ports()
            .find(|port| port.number() == number)
            .and_then(|port| port.discovery().map(|found| found.reason().clone()))
    };

    assert_eq!(
        outcome.port_state(LOOPBACK, open.port),
        Some(PortState::Open)
    );
    assert_eq!(reason(open.port), Some(ScanResponse::TcpSynAck));
    assert_eq!(
        outcome.port_state(LOOPBACK, closed),
        Some(PortState::Closed)
    );
    assert_eq!(
        reason(closed),
        Some(ScanResponse::TcpRst),
        "the closed port was not read from a captured reset"
    );
}
