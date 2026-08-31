// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A reply off the wire, read as a statement about the stack that sent it.
//!
//! The TCP option walk is the part worth aiming at. It steps through a list
//! whose every length byte a remote host chose, and it has to terminate on any
//! input rather than merely on a well-formed one: a length that runs past the
//! header, an option shorter than its own header, an end-of-list marker with
//! data behind it, a list longer than the walk reads.
//!
//! ## The oracles
//!
//! **A reading never panics**, whatever the header claims.
//!
//! **What the walk read is consistent with what it says it read.** An
//! observation reporting a truncated layout must say so, because a rule keyed on
//! the layout would otherwise compare against a string that is not the whole one
//! and nothing downstream could tell.
//!
//! **Derived values agree with the values they are derived from.** The window in
//! units of the effective segment size is what a rule compares, and it is
//! arithmetic over two remote numbers.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zond_engine::fingerprint::os::{StackObservation, classify_reply};
use zond_engine::model::capture::{IpObservation, Ipv4Observation};

fuzz_target!(|data: &[u8]| {
    // A whole packet, for the caller who has bytes and nothing else.
    let _ = StackObservation::from_ip_packet(data);

    // And the segment on its own, which is what a capture hands over.
    let ip = IpObservation::V4(Ipv4Observation {
        ttl: data.first().copied().unwrap_or(64),
        identification: 0,
        dont_fragment: data.len() % 2 == 0,
        more_fragments: false,
        dscp: 0,
        ecn: 0,
    });

    let Some(observed) = StackObservation::from_tcp(ip, data) else {
        return;
    };

    // The layout string is what a rule compares, and a truncated one has to say
    // it is truncated.
    let rendered = observed.layout_string();
    let letters = rendered.split(',').filter(|part| !part.is_empty()).count();
    assert_eq!(
        letters,
        observed.option_layout.len(),
        "the rendered layout lost an option: {rendered:?}"
    );

    // Arithmetic over two remote numbers.
    if let Some((units, remainder)) = observed.window_in_units() {
        let unit = observed
            .effective_mss()
            .expect("units are only derived where there is a unit");
        assert_eq!(
            u32::from(units) * u32::from(unit) + u32::from(remainder),
            u32::from(observed.window),
            "the window does not reconstruct from the units it was reported in"
        );
    }

    // A bound, never a value: a reply cannot have started below what arrived.
    assert!(observed.initial_hops_at_least() >= observed.ip.remaining_hops());

    // The whole path, which is what a scan actually runs.
    let _ = classify_reply(ip, data);
});
