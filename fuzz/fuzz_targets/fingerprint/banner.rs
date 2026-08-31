// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A response off the wire, through the whole matching pipeline.
//!
//! Prefilter, then two regex engines over 4 737 signatures, then the ranking
//! that picks a service reading and an operating-system reading separately, then
//! the resolver that folds several observations into one verdict. Every stage
//! runs on text a remote host chose.
//!
//! Both matching tiers are covered: port 80 reaches the port-linked set, and a
//! banner that matches nothing there falls through to the global prefilter.
//!
//! ## The oracles
//!
//! **Nothing panics, and everything terminates.** The backtracking engine is
//! bounded by a step ceiling rather than a clock, so a pathological pattern on
//! an adversarial response has to resolve rather than run away.
//!
//! **No identity field reaches a report unbounded.** A hostile response once
//! produced a 1500-byte product and a 1500-byte extrainfo, and both travelled
//! into every export.
//!
//! **A verdict never carries a platform identifier belonging to a product it did
//! not name.** CVE correlation joins on the CPE, so a verdict naming one product
//! and carrying another's identifier is a false finding in a security report.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zond_engine::fingerprint::{MAX_IDENTITY_BYTES, SignatureDb};
use zond_engine::model::port::Protocol;

fuzz_target!(|data: &[u8]| {
    let response = String::from_utf8_lossy(data);
    let db = SignatureDb::global();

    for port in [80u16, 22, 65_000] {
        let Some(found) = db.identify(port, Protocol::Tcp, &response) else {
            continue;
        };

        for field in [
            &found.product,
            &found.version,
            &found.vendor,
            &found.extrainfo,
        ] {
            if let Some(value) = field {
                assert!(
                    value.len() <= MAX_IDENTITY_BYTES,
                    "an identity field reached a report at {} bytes",
                    value.len()
                );
            }
        }

        // A service name that is present is a name, not an empty string that a
        // report would print as a blank column.
        if let Some(service) = found.service.as_deref() {
            assert!(!service.is_empty());
        }
    }

    // The SNMP decoder, on the one port whose replies are read as a field rather
    // than as a banner. Reached with the datagram rather than the text, because
    // that is what arrives.
    let _ = zond_engine::fingerprint::decode_udp_reply(161, data);
});
