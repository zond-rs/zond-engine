// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The readers that take a bare buffer: a segment off a capture, or a datagram a
//! resolver drew.
//!
//! Separate from the frame target because these are reached without an Ethernet
//! header in front of them, so a fuzzer spending its budget on framing would
//! never get here.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zond_engine::protocols::{dns, icmp, mdns, sctp, tcp};

fuzz_target!(|data: &[u8]| {
    // The identifier an echo scan matches on: taken from the input so the
    // fuzzer can find the value that makes a reply this scan's own.
    let identifier = u16::from_ne_bytes([
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
    ]);

    let _ = icmp::classify_echo_reply(data, identifier, false);
    let _ = icmp::classify_echo_reply(data, identifier, true);
    let _ = icmp::echo_token(data);
    let _ = dns::parse_ptr_response(data);
    let _ = dns::is_response(data);
    let _ = mdns::extract_hosts(data);

    if let Ok(segment) = tcp::parse(data) {
        let _ = tcp::classify_probe_response(&segment);
    }
    if let Ok(segment) = sctp::parse(data) {
        let _ = sctp::classify_probe_response(&segment);
    }
    let _ = tcp::quoted_probe(data);
    let _ = sctp::quoted_probe(data);
});
