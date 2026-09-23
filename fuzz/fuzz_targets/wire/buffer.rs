// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The readers that take a bare buffer: a segment off a capture, a datagram a
//! resolver drew, or a whole captured frame read as each link type a capture
//! comes up as, which puts the IP parse and its extension-header walk behind
//! every one of them.
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
use zond_engine::transport::frame::{self, LinkType};

/// Every link type a capture comes up as and the engine reads.
const LINKS: [LinkType; 5] = [
    LinkType::Ethernet,
    LinkType::NullLoop,
    LinkType::Raw,
    LinkType::LinuxSll,
    LinkType::LinuxSll2,
];

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

        // **Reading more bytes only ever adds to what was read**, the property
        // `wire/ethernet_frame` holds for the announcement readers and which
        // this target asserted for width alone. A chunk walk is the same shape:
        // lengths come off the wire and a capture can stop mid-chunk, so a
        // shorter read has to report a *prefix* of the longer one rather than a
        // different answer. The walk clamps both the value and the step to what
        // is present, which is what makes that true; asserting it is what would
        // notice if a later change made the clamp a wrap.
        for cut in sctp_cuts(data.len()) {
            let Ok(short) = sctp::parse(&data[..cut]) else {
                continue;
            };
            for (near, far) in short.chunks().zip(segment.chunks()) {
                assert_eq!(
                    near.chunk_type, far.chunk_type,
                    "a shorter SCTP read named a different chunk"
                );
                assert!(
                    far.value.starts_with(near.value),
                    "a shorter SCTP read reported a value the longer one contradicts"
                );
            }
            assert!(
                short.chunks().count() <= segment.chunks().count(),
                "a shorter SCTP read found more chunks than the whole packet"
            );
        }
    }

    let _ = tcp::quoted_probe(data);
    let _ = sctp::quoted_probe(data);
    // The INIT scan's nonce, which lives past the eight bytes RFC 792
    // guarantees and so is the field a short quotation does not reach.
    let _ = sctp::quoted_init_tag(data);

    // What every reply a scan hears passes through: the link header stripped,
    // then the IP header and any extension chain behind it, every length in
    // both chosen by the sender.
    for link in LINKS {
        if let Some((segment, _)) = frame::parse_captured(link, data) {
            let frame = data.as_ptr_range();
            let lent = segment.payload.as_ptr_range();
            assert!(
                segment.payload.is_empty() || (frame.start <= lent.start && lent.end <= frame.end),
                "a captured {link:?} frame lent a segment from outside the frame"
            );
        }
    }
});

/// The prefixes of a packet of `len` bytes worth re-reading.
///
/// Bounded, because the comparison is quadratic and a cut landing inside the
/// common header reads nothing either way. The cuts that prove something are
/// near the end, where a chunk is split rather than removed.
fn sctp_cuts(len: usize) -> impl Iterator<Item = usize> {
    const CUTS: usize = 16;
    (1..=CUTS)
        .filter_map(move |step| len.checked_sub(step))
        .filter(|cut| *cut >= 12)
}
