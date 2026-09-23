// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The capture layer on real links, where what it says and how long it waits
//! are decided by a kernel rather than by a test.
//!
//! Every question here needs a link this process may capture on, which is what
//! the namespace provides and no other tier has: whether a capture that fails
//! with the privilege to capture says why rather than blaming privilege, and
//! whether a wait for a frame that never comes ends when it said it would.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use crate::netns::{Segment, available, zone_holding};
use crate::support::{run_scan, target_map, test_config};
use zond_engine::transport::capture::{self, CaptureOptions, FrameChannel};
use zond_engine::transport::probe::SendMode;

/// A capture that fails for a reason other than privilege says what the reason
/// was, and does not say privilege.
///
/// This process may capture on every link in the namespace, so the filter is
/// the only thing that can refuse here: an Ethernet address means nothing on a
/// tunnel, and `libpcap` will not compile one for it. What a caller reads has
/// to name that, since it is what there is to fix, and has to leave privilege
/// out, since telling somebody who holds it to go and get it sends them
/// looking in the one place the fault is not.
#[test]
fn a_capture_refused_for_a_reason_other_than_privilege_names_that_reason() {
    if !available() {
        return;
    }

    let segment = Segment::new();
    let peer = segment.tunnel();
    let tunnel = zone_holding(Ipv4Addr::from(u32::from(peer) - 1));

    let refused = capture::frames(
        std::slice::from_ref(&tunnel),
        &CaptureOptions::for_replies("ether dst 02:00:00:00:00:01"),
        16,
    )
    .err()
    .expect("an Ethernet address cannot be compiled for a tunnel");
    let said = refused.to_string();

    assert!(
        said.contains(tunnel.name()),
        "the link that refused should be named: {said}"
    );
    assert!(
        said.contains("would not compile"),
        "the filter is what refused, and should be said to be: {said}"
    );
    assert!(
        !said.contains("root") && !said.contains("privilege"),
        "nothing here lacked privilege, so nothing should blame it: {said}"
    );
}

/// A frame channel's wait for a frame ends when its read timeout says it will,
/// on a link carrying nothing the filter admits.
///
/// The timeout is the whole of what lets a caller with a deadline honour it.
/// A wait that instead lasted until some admitted frame happened to arrive
/// would be bounded by the network's traffic rather than by anything the
/// caller chose, and on a quiet link by nothing at all.
#[test]
fn a_frame_channel_wait_ends_at_its_timeout_on_a_quiet_link() {
    if !available() {
        return;
    }

    let segment = Segment::new();
    let link = segment.link();
    let timeout = Duration::from_millis(50);

    let (done, waited) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut channel =
            FrameChannel::open(&link, "arp", timeout).expect("the link opens for frames");
        let started = Instant::now();
        let frame = channel.next_frame().map(<[u8]>::to_vec);
        let _ = done.send((frame, started.elapsed()));
    });

    let (frame, elapsed) = waited
        .recv_timeout(Duration::from_secs(5))
        .expect("the wait should end at its timeout, not wait for a frame");
    assert_eq!(frame, None, "nothing on this link sends ARP");
    assert!(
        elapsed < Duration::from_secs(1),
        "a {timeout:?} wait took {elapsed:?}"
    );
}

/// A scan that frames its own probes, aimed at an on-link address nobody
/// holds, gives up on the address after its resolution times out.
///
/// The probe cannot leave without the neighbour's hardware address, so the
/// sender asks for it and waits. Nothing will answer, and nothing else on this
/// link sends ARP, so a wait that ended only when an admitted frame arrived
/// would never end, and the scan with it.
///
/// On a thread and a runtime of its own, because the wait is a blocking one: a
/// scan stuck in it holds its runtime's thread, and a timeout on that runtime
/// would never get to fire.
#[test]
fn a_framed_scan_of_an_address_nobody_holds_finishes() {
    if !available() {
        return;
    }

    let segment = Segment::new();
    let IpAddr::V4(peer) = segment.peer() else {
        unreachable!("the segment is addressed in IPv4");
    };
    let nobody = IpAddr::V4(Ipv4Addr::from(u32::from(peer) + 75));

    let mut cfg = test_config();
    cfg.send_mode = SendMode::Ethernet;
    cfg.assume_up = true;

    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("a runtime starts");
        let started = Instant::now();
        let outcome = runtime.block_on(run_scan(target_map(nobody, "22"), &cfg));
        let _ = done.send((outcome, started.elapsed()));
    });

    let (outcome, elapsed) = finished
        .recv_timeout(Duration::from_secs(30))
        .expect("the scan should give the address up rather than wait on it forever");

    assert_ne!(
        outcome.port_state(nobody, 22),
        Some(zond_engine::model::port::PortState::Open),
        "an address nobody holds has nothing open"
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "the scan took {elapsed:?}"
    );
    drop(segment);
}
