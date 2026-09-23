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
//! with the privilege to capture says why rather than blaming privilege.

use std::net::{IpAddr, Ipv4Addr};

use crate::netns::{Segment, available};
use zond_engine::model::ip::scoped::Zone;
use zond_engine::transport::capture::{self, CaptureOptions};

/// The link holding `address`, as the engine names it.
fn link_holding(address: Ipv4Addr) -> Zone {
    zond_engine::system::interface::interfaces()
        .into_iter()
        .find(|link| {
            link.addresses()
                .iter()
                .any(|held| held.address() == IpAddr::V4(address))
        })
        .map(|link| link.zone())
        .unwrap_or_else(|| panic!("the engine can see the link holding {address}"))
}

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
    let tunnel = link_holding(Ipv4Addr::from(u32::from(peer) - 1));

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
