// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The readers that take a bare buffer: a segment off a capture, or a datagram a
//! resolver drew.
//!
//! Separate from the frame target because these are reached without an Ethernet
//! header in front of them, so a fuzzer spending its budget on framing would
//! never get here.
//!
//! ## The oracles
//!
//! **A parser never hands out more than it was given.** A segment lending a
//! payload wider than the buffer it came from is the defect every reader behind
//! it inherits, and on its own it does not crash — it produces a slice into
//! whatever follows.
//!
//! **The two DNS entry points agree about what a response is.**
//! [`dns::is_response`] decides whether a host is a name server and
//! [`dns::parse_ptr_response`] reads the answer, and each computes "this parsed
//! and is not a query" for itself. They are one condition written down twice,
//! which is the arrangement where one gets a fix and the other does not.

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
    let _ = mdns::extract_hosts(data);

    // Both answer "this parsed and is not a query" and must answer it alike.
    assert_eq!(
        dns::parse_ptr_response(data).is_ok(),
        dns::is_response(data),
        "the two DNS readers disagree about whether this is a response"
    );

    if let Ok(segment) = tcp::parse(data) {
        assert!(
            segment.payload().len() <= data.len(),
            "a TCP segment lent a payload wider than the buffer it came from"
        );
        let _ = tcp::classify_probe_response(&segment);
    }

    if let Ok(segment) = sctp::parse(data) {
        for chunk in segment.chunks() {
            assert!(
                chunk.value.len() <= data.len(),
                "an SCTP chunk lent a value wider than the packet it came from"
            );
        }
        let _ = sctp::classify_probe_response(&segment);
    }

    let _ = tcp::quoted_probe(data);
    let _ = sctp::quoted_probe(data);
});
