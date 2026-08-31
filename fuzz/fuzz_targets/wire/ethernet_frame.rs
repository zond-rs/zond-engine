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

#![no_main]

use libfuzzer_sys::fuzz_target;
use zond_engine::protocols::{cdp, dhcp, ethernet, lldp, ndp};

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

    let _ = lldp::parse(&frame);
    let _ = cdp::parse(&frame);
    let _ = ndp::advertisement(&frame);
    let _ = ndp::is_router_advertisement(&frame);

    if let Some(reply) = dhcp::server_reply(&frame) {
        let _ = reply.routers().count();
        let _ = reply.resolvers().count();
    }
    let _ = dhcp::client_request(&frame);
});
