// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Every TCP technique, against a kernel rather than a model of one.
//!
//! Tier 2 covers these too, and covers them more thoroughly: `FakeNet::stack`
//! can answer as a conformant stack, as a BSD-derived one, or as one of the
//! stacks that reset every flag probe. What it cannot do is disagree with
//! whoever wrote it. The verdicts below are Linux's own answers, so a
//! classifier that has drifted from the protocol fails here and passes there.
//!
//! The three techniques that read silence as an open port are the reason this
//! matters most. `Fin`, `Null` and `Xmas` conclude `OpenFiltered` from an
//! absence, and an absence is what a broken send path also produces.

use crate::netns::{Segment, available};
use crate::support::{run_scan, target_map, test_config};
use zond_engine::model::port::PortState;
use zond_engine::model::technique::TcpScanTechnique;

/// Scans one open and one closed port with `technique`, returning both verdicts.
async fn verdicts(
    segment: &mut Segment,
    technique: TcpScanTechnique,
) -> (Option<PortState>, Option<PortState>) {
    let open = segment.listen_tcp();
    let closed = segment.closed_tcp_port();
    let mut cfg = test_config();
    cfg.tcp_technique = technique;
    let outcome = run_scan(
        target_map(segment.peer(), &format!("{open},{closed}")),
        &cfg,
    )
    .await;
    (
        outcome.port_state(segment.peer(), open),
        outcome.port_state(segment.peer(), closed),
    )
}

/// A SYN scan reads a listener as open and a bare port as closed.
#[tokio::test]
async fn a_syn_scan_separates_open_from_closed() {
    if !available() {
        return;
    }
    let mut segment = Segment::new();
    assert_eq!(
        verdicts(&mut segment, TcpScanTechnique::Syn).await,
        (Some(PortState::Open), Some(PortState::Closed))
    );
}

/// The three flag probes read an open port as `OpenFiltered` and a closed one as
/// closed.
///
/// RFC 793 says a segment carrying neither SYN, RST nor ACK is dropped without
/// reply by a listening port and answered with a reset by one that is not
/// listening. So silence is the positive signal here, which is what makes these
/// three the techniques a broken send path would flatter: it produces the same
/// silence. The closed port's reset is the half that proves a probe was sent.
#[tokio::test]
async fn the_flag_probes_read_silence_as_open_and_a_reset_as_closed() {
    if !available() {
        return;
    }

    for technique in [
        TcpScanTechnique::Fin,
        TcpScanTechnique::Null,
        TcpScanTechnique::Xmas,
    ] {
        let mut segment = Segment::new();
        assert_eq!(
            verdicts(&mut segment, technique).await,
            (Some(PortState::OpenFiltered), Some(PortState::Closed)),
            "{technique:?} against a real kernel"
        );
    }
}

/// A Maimon scan finds both ports closed on Linux, which is not a defect.
///
/// The technique rests on the BSD-derived behaviour of dropping a FIN/ACK to an
/// open port where the RFC calls for a reset. Linux resets both, so the
/// technique cannot separate them here and says so rather than guessing. Worth
/// pinning because a classifier that reported `OpenFiltered` for the open port
/// would look more useful and be wrong.
#[tokio::test]
async fn a_maimon_scan_cannot_separate_the_two_on_linux() {
    if !available() {
        return;
    }
    let mut segment = Segment::new();
    assert_eq!(
        verdicts(&mut segment, TcpScanTechnique::Maimon).await,
        (Some(PortState::Closed), Some(PortState::Closed))
    );
}

/// An ACK scan reports both ports unfiltered, having asked about the filter.
///
/// It is not a port-state technique: a reset comes back either way, and what it
/// establishes is that nothing dropped the segment on the way. Reporting
/// `Closed` for an open port would be reading an answer the probe never asked
/// for.
#[tokio::test]
async fn an_ack_scan_reports_the_filter_rather_than_the_port() {
    if !available() {
        return;
    }
    let mut segment = Segment::new();
    assert_eq!(
        verdicts(&mut segment, TcpScanTechnique::Ack).await,
        (Some(PortState::Unfiltered), Some(PortState::Unfiltered))
    );
}

/// A window scan finds both closed on Linux, which is the honest answer.
///
/// The technique reads the window field of the reset a probe draws, on the
/// stacks that return a positive one from an open port. Linux returns zero from
/// both, so there is nothing to separate.
#[tokio::test]
async fn a_window_scan_finds_nothing_to_separate_on_linux() {
    if !available() {
        return;
    }
    let mut segment = Segment::new();
    assert_eq!(
        verdicts(&mut segment, TcpScanTechnique::Window).await,
        (Some(PortState::Closed), Some(PortState::Closed))
    );
}

/// A probe that goes unanswered is sent again, counted at the target.
///
/// The retry schedule is asserted in Tier 2 against a network told to drop; this
/// is the same claim where the silence is a real listener declining to answer
/// and the count is kept by the peer's own firewall rather than by the harness.
#[tokio::test]
async fn an_unanswered_flag_probe_is_retried_on_the_wire() {
    if !available() {
        return;
    }

    let mut segment = Segment::new();
    let open = segment.listen_tcp();
    segment.count_tcp(open);

    let mut cfg = test_config();
    cfg.tcp_technique = TcpScanTechnique::Fin;
    let outcome = run_scan(target_map(segment.peer(), &open.to_string()), &cfg).await;

    assert_eq!(
        outcome.port_state(segment.peer(), open),
        Some(PortState::OpenFiltered)
    );
    let arrived = segment.count_of(open);
    assert!(
        arrived >= 2,
        "a FIN nobody answers should be sent again, but the peer counted {arrived}"
    );
}
