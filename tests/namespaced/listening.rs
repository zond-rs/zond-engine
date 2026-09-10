// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The listening entry point, over a capture rather than a channel.
//!
//! Tier 2 drives `PassiveListener::from_parts`, handing the reader frames a
//! test built. Everything between that seam and a caller is untested by it:
//! `ListenScope`, `scanner::listen`, and the capture the scope's links are
//! opened as. That is most of what `scanner.rs` does not cover, and none of it
//! can be reached without a link somebody is allowed to capture on.

use std::time::Duration;

use crate::netns::{Segment, available};
use crate::support::test_config;
use zond_engine::scanner::{self, ListenScope};

/// A machine that speaks on the segment is heard, through the real capture.
///
/// The peer pings the near end, which puts an ARP request and three echoes on
/// the wire under its own hardware address. Nothing here pushes a frame: the
/// listener opens the link itself and reads what the kernel gives it.
#[tokio::test]
async fn a_machine_that_speaks_is_heard_over_a_real_capture() {
    if !available() {
        return;
    }

    let segment = Segment::new();
    let scope = ListenScope::on(vec![segment.zone()])
        .recording_everything()
        .for_at_most(Duration::from_secs(4));

    let (session, task) = scanner::listen(scope, &test_config())
        .await
        .expect("a watch starts on a link this process may capture on");

    // The capture threads open their devices on their own schedule, and a frame
    // put on the wire before they are listening is simply not seen.
    tokio::time::sleep(Duration::from_millis(700)).await;
    // Off the runtime, so the watch's own tasks keep draining the capture while
    // the peer is talking.
    let speaking = tokio::task::spawn_blocking(move || {
        segment.peer_speaks();
        segment
    });
    let segment = speaking.await.expect("the peer speaks");

    let report = task.await.expect("the watch ends when its span does");

    let heard: Vec<_> = session.hosts().snapshot();
    assert!(
        heard.iter().any(|host| host.primary_ip() == segment.peer()),
        "the peer spoke and should have been heard, but the watch holds {:?}",
        heard.iter().map(|h| h.primary_ip()).collect::<Vec<_>>()
    );
    assert!(
        report.host_count() >= 1,
        "the report should carry what the watch heard"
    );
}

/// A watch bounded by its scope ends on its own.
///
/// `Until::Elapsed` is the only way a watch stops without somebody aborting it,
/// and a scope that never ended would hang this tier rather than fail it.
#[tokio::test]
async fn a_bounded_watch_ends_without_being_aborted() {
    if !available() {
        return;
    }

    let segment = Segment::new();
    let scope = ListenScope::on(vec![segment.zone()]).for_at_most(Duration::from_millis(700));

    let (_session, task) = scanner::listen(scope, &test_config())
        .await
        .expect("a watch starts");

    let report = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("a bounded watch must end on its own")
        .expect("the watch task completes");
    assert!(
        report.elapsed() >= Duration::from_millis(500),
        "the watch should have run for about its span, not returned at once"
    );
}
