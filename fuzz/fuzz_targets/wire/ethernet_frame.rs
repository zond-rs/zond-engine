// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Every reader that takes a parsed frame, over bytes the fuzzer chose.
//!
//! This is the deepest entry point the engine has into somebody else's bytes: a
//! listening phase reads whatever crosses the segment, so each of these is
//! called on frames whose whole content is under the control of anyone on the
//! wire. `tests/wire_parsers.rs` covers the same ground with shaped generators;
//! this is the half that finds the shape nobody thought of.
//!
//! ## The oracles
//!
//! **A parser never hands out more than it was given.** A frame lending a
//! payload wider than the buffer it came from is the defect every reader behind
//! it inherits, and on its own it does not crash.
//!
//! **Reading more bytes only ever adds to what was read.** The property this
//! target exists for, and the one it did not have. Both announcement readers
//! walk a run of records whose lengths came off the wire, and both meet a run
//! that stops mid-record: a capture cut at its snapshot length, or equipment
//! that miscounted. What was already read has to survive that.
//!
//! `lldp::parse` did not survive it. A short tail discarded the whole
//! advertisement, chassis identifier and port identifier included, and this
//! target could not see it, because it called the reader and threw the result
//! away. `fuzz/README.md` names that exact failure: *a target that only calls
//! and discards finds a panic and nothing else.* It was written about the next
//! target and was already true of this one.
//!
//! Growth, not equality. A shorter run reports a *subset*: a field it never
//! reached is absent, and asserting the two agree outright would stop the run on
//! a frame that was never wrong. What must hold is that a field a shorter run
//! did report is the same field the longer one reports. That is `keep_first` in
//! both readers, and this is what holds it.
//!
//! ## Why the two are shortened differently
//!
//! An LLDP unit runs to the end of the frame, so a prefix of the bytes is a
//! shorter unit and nothing else has to move.
//!
//! A CDP announcement sits inside 802.3 framing that claims its own length, and
//! `cdp::parse` cuts to that claim before walking. A plain prefix therefore
//! claims more than arrived and is declined at the framing, which is correct and
//! reaches none of the record walk. Shortening the claim is what shortens the
//! announcement, so that is what this does.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zond_engine::protocols::{cdp, dhcp, ethernet, lldp, ndp};

/// How many shortenings of one frame are compared against the whole.
///
/// The walk is quadratic in this, and the cuts that prove something are near the
/// end: one landing inside the first record reads nothing either way.
const SHORTENINGS: usize = 24;

/// Where the 802.3 length field sits, which is what shortens a CDP
/// announcement.
const LENGTH_FIELD: std::ops::Range<usize> = 12..14;

fuzz_target!(|data: &[u8]| {
    let Ok(frame) = ethernet::parse(data) else {
        return;
    };

    // The frame's own accessors first: a parser handing out a slice wider than
    // the buffer it came from is a defect the readers below would inherit.
    let payload = frame.payload();
    assert!(payload.len() <= data.len());
    if let Some(claimed) = frame.payload_as_claimed() {
        assert!(claimed.len() <= payload.len());
    }
    let _ = frame.destination();
    let _ = frame.source();
    let _ = frame.vlans();

    let _ = ndp::advertisement(&frame);
    let _ = ndp::is_router_advertisement(&frame);

    if let Some(reply) = dhcp::server_reply(&frame) {
        let _ = reply.routers().count();
        let _ = reply.resolvers().count();
    }
    let _ = dhcp::client_request(&frame);

    let advertisement = lldp::parse(&frame);
    let announcement = cdp::parse(&frame);

    // Nothing below can hold for a frame that read as neither.
    if advertisement.is_none() && announcement.is_none() {
        return;
    }

    for cut in shortenings(data.len()) {
        if let Some(after) = advertisement.as_ref()
            && let Ok(shorter) = ethernet::parse(&data[..cut])
            && let Some(before) = lldp::parse(&shorter)
        {
            grew(before.chassis_id, after.chassis_id, "chassis identifier");
            grew(before.port_id, after.port_id, "port identifier");
            grew(before.ttl, after.ttl, "time to live");
            grew(before.system_name, after.system_name, "system name");
            grew(before.capabilities, after.capabilities, "capabilities");
            grew(before.port_vlan, after.port_vlan, "port VLAN");
        }

        if let Some(after) = announcement.as_ref()
            && data.len() >= LENGTH_FIELD.end
        {
            let mut shortened = data.to_vec();
            let claim = u16::try_from(cut.saturating_sub(LENGTH_FIELD.end)).unwrap_or(u16::MAX);
            shortened[LENGTH_FIELD].copy_from_slice(&claim.to_be_bytes());

            if let Ok(shorter) = ethernet::parse(&shortened)
                && let Some(before) = cdp::parse(&shorter)
            {
                grew(before.device_id, after.device_id, "device id");
                grew(before.port_id, after.port_id, "port id");
                grew(before.capabilities, after.capabilities, "capabilities");
                grew(before.native_vlan, after.native_vlan, "native VLAN");
                grew(before.full_duplex, after.full_duplex, "duplex");
                grew(before.address, after.address, "management address");
            }
        }
    }
});

/// Holds that reading more bytes did not change a field that was already read.
///
/// Absent before and present after is the ordinary case and says nothing. The
/// failure is a field read from bytes the longer run also holds, coming back
/// different or not at all.
fn grew<T: PartialEq + std::fmt::Debug>(before: Option<T>, after: Option<T>, field: &str) {
    if before.is_some() {
        assert_eq!(
            before, after,
            "reading further changed the {field} a shorter run had already read"
        );
    }
}

/// The lengths to shorten to, weighted to the end of the frame.
fn shortenings(len: usize) -> impl Iterator<Item = usize> {
    let step = (len / SHORTENINGS).max(1);
    (0..len).rev().step_by(step).take(SHORTENINGS)
}
