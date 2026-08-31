// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a journal is a journal of, and whether it still recognises it.
//!
//! A manifest holds the plan a cursor's positions are counted in, and a
//! fingerprint of that plan taken when the journal was created. `Journal::reopen`
//! is the caller that puts the two together: it reads the plan back out of the
//! manifest and hands it straight to the check that refuses a plan which has
//! moved. So there is a property nothing else in the crate states, and every
//! resume-by-id depends on it.
//!
//! ## The oracle: a manifest recognises the plan it wrote down
//!
//! Fingerprint a plan, record it, read the record back, and fingerprint that.
//! The two must agree, or `reopen` refuses a journal against the very plan it
//! is a journal of — and refuses it with a message saying the targets were
//! edited, which is the one thing that message must never say when they were
//! not.
//!
//! It is a round-trip property in fingerprint's clothing, and it is sharper than
//! comparing the records: the fingerprint reads the *structure that decides the
//! enumeration*, so anything the record loses about ranges, ports, order, the
//! technique or the phase shows up here, whether or not the two records happen
//! to be equal.
//!
//! ## And that the derivation reads only the plan
//!
//! Fingerprinting twice gives the same value, and fingerprinting under the other
//! privilege gives a different one for the two phases that enumerate. The first
//! is what a value written to disk has to be. The second is the bit that stops a
//! scan begun with raw sockets being continued with connect attempts, which
//! answer a different question about the same port.
//!
//! ## What is not asserted
//!
//! That the fuzzer's own `plan` field matches anything. It is eight arbitrary
//! bytes and will not be the fingerprint of anything; what is interesting about
//! the input is the *recorded plan*, whose ranges and port specification the
//! fuzzer does control.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zond_engine::journal::manifest::{JournalManifest, PlanFingerprint};
use zond_engine::report::ScanKind;
use zond_engine::system::privilege::Privilege;

fuzz_target!(|data: &[u8]| {
    let Ok(manifest) = serde_json::from_slice::<JournalManifest>(data) else {
        return;
    };

    let plan = manifest.recorded();

    // As this build would write it now, so the fingerprint is one it computed
    // rather than eight bytes the fuzzer chose.
    let written = JournalManifest::new(&manifest.id, &plan, manifest.privilege, "");

    assert_eq!(
        written.kind(),
        plan.kind(),
        "a manifest records a phase other than the one its plan belongs to"
    );

    written
        .covers(&written.recorded(), manifest.privilege)
        .unwrap_or_else(|moved| {
            panic!("a journal does not recognise the plan it wrote down: {moved}")
        });

    // A value that reaches a file has to be a function of what it describes and
    // of nothing else.
    assert_eq!(
        PlanFingerprint::of(&plan, manifest.privilege),
        PlanFingerprint::of(&plan, manifest.privilege),
        "the plan fingerprint is not a function of the plan"
    );

    // A raw technique and a connect attempt ask different questions of the same
    // port, so a journal half of each would be counting two things. A watch
    // sends nothing and is deliberately outside this.
    if plan.kind() != ScanKind::Listen {
        assert_ne!(
            PlanFingerprint::of(&plan, Privilege::Raw),
            PlanFingerprint::of(&plan, Privilege::Connect),
            "a plan fingerprints the same whether or not the scan could send raw"
        );
    }
});
