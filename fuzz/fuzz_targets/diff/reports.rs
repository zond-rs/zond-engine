// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Two scans of a network nobody arranged, compared.
//!
//! `import_report` and `export_report` already put a comparison under the fuzzer
//! one way: they ask whether a report equals *itself*, which is the answer a
//! nightly run gives almost every time and the one a false alarm would spoil.
//! Nothing yet asks what happens when the two sides genuinely differ, and that
//! is the whole of the module: pairing records that changed address, deciding
//! what a missing host means, and reporting a certificate that crossed a
//! threshold while nobody touched it.
//!
//! Two documents, each read into a report, under every pairing policy — the
//! policy decides which record continues which, and `Hardware` is the one whose
//! own documentation warns that a router answering for everything behind it
//! folds those records into one.
//!
//! ## What is asserted
//!
//! - **A delta is never empty.** The comparison filters them, so one that
//!   reached the output claims something moved and has to say what.
//! - **A change never holds two equal values.** `Change::between` returns
//!   nothing when they match, and the type's documentation promises a change
//!   list holds only changes. A rendered "80 -> 80" is that promise breaking.
//! - **The deltas are ordered and each host appears once.** A front end walks
//!   them as a list and a repeated address is a host reported twice.
//! - **The summary agrees with the deltas.** It is computed on demand precisely
//!   so it cannot disagree, and it is the part a consumer leads with;
//!   `confirmed` never exceeds `total`, and both are what the deltas say.
//! - **Comparing under a stricter identity never finds fewer hosts.**
//!   `PrimaryAddress` splits what `AnyAddress` pairs, and a split record is two
//!   deltas where there was one, never none.
//!
//! ## What is not asserted
//!
//! That comparing in the other order gives a mirrored answer. It nearly does and
//! the exceptions are real: a delta is keyed by the current side's address where
//! it has one, and a certificate's standing is read against each scan's own
//! clock, so a swap moves both. Asserting it would report the design as a crash.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zond_engine::diff::{Change, DiffOptions, HostChange, HostIdentity, PortChange, ScanDiff};
use zond_engine_fuzz::{report_is_coherent, reports};

fuzz_target!(|data: &[u8]| {
    let reports = reports(data, 2);
    let [baseline, current] = reports.as_slice() else {
        return;
    };

    report_is_coherent(baseline);
    report_is_coherent(current);

    let mut widest = 0;
    for identity in [
        HostIdentity::PrimaryAddress,
        HostIdentity::AnyAddress,
        HostIdentity::Hardware,
    ] {
        let options = DiffOptions::new().with_identity(identity);
        let diff = ScanDiff::compare(baseline, current, &options);
        check(&diff);

        if identity == HostIdentity::AnyAddress {
            widest = diff.hosts().len();
        }
    }

    // The strictest policy pairs least, and a pair it declines to make is two
    // records where a looser one had one.
    let split = ScanDiff::compare(
        baseline,
        current,
        &DiffOptions::new().with_identity(HostIdentity::PrimaryAddress),
    );
    assert!(
        split.hosts().len() >= widest,
        "pairing by primary address alone found fewer hosts than pairing by any address"
    );
});

/// Holds one comparison to what its own documentation promises.
fn check(diff: &ScanDiff) {
    let mut previous = None;
    for host in diff.hosts() {
        assert!(
            !host.is_empty(),
            "{} reached the output with nothing to report",
            host.address()
        );

        if let Some(previous) = previous {
            assert!(
                previous < host.address(),
                "the deltas are not ascending, or {} appears twice",
                host.address()
            );
        }
        previous = Some(host.address());

        for change in host.changes() {
            match change {
                HostChange::Status(moved) => differs(moved, "a status"),
                HostChange::Hostname(moved) => differs(moved, "a hostname"),
                HostChange::Vendor(moved) => differs(moved, "a vendor"),
                HostChange::Addresses { gained, lost } => moved(gained, lost, "addresses"),
                HostChange::Macs { gained, lost } => moved(gained, lost, "hardware addresses"),
                HostChange::Roles { gained, lost } => moved(gained, lost, "roles"),
                HostChange::Filtering { gained, lost } => moved(gained, lost, "filtering"),
                _ => {}
            }
        }

        for port in host.ports() {
            assert!(
                !port.is_empty(),
                "{}:{} reached the output with nothing to report",
                host.address(),
                port.number()
            );
            for change in port.changes() {
                if let PortChange::State(moved) = change {
                    differs(moved, "a port state");
                }
            }
        }
    }

    let summary = diff.summary();
    for (counted, what) in [
        (summary.hosts_added, "hosts added"),
        (summary.hosts_removed, "hosts removed"),
        (summary.ports_opened, "ports opened"),
        (summary.ports_closed, "ports closed"),
    ] {
        assert!(
            counted.confirmed <= counted.total,
            "{what}: {} of {} confirmed",
            counted.confirmed,
            counted.total
        );
    }

    let added = diff
        .hosts()
        .iter()
        .filter(|h| h.presence().is_added())
        .count();
    let removed = diff
        .hosts()
        .iter()
        .filter(|h| h.presence().is_removed())
        .count();
    assert_eq!(
        summary.hosts_added.total, added,
        "the summary counts hosts the deltas do not"
    );
    assert_eq!(
        summary.hosts_removed.total, removed,
        "the summary counts hosts the deltas do not"
    );

    assert_eq!(
        diff.is_empty(),
        diff.hosts().is_empty(),
        "a comparison disagrees with itself about whether anything moved"
    );
}

/// A set change reports something on one side or the other, or it is not one.
fn moved<T>(gained: &[T], lost: &[T], what: &str) {
    assert!(
        !gained.is_empty() || !lost.is_empty(),
        "{what} were reported as changed with nothing gained and nothing lost"
    );
}

/// A change holds two values that differ, which is what makes it one.
fn differs<T: PartialEq + std::fmt::Debug>(change: &Change<T>, what: &str) {
    assert_ne!(
        change.before, change.after,
        "{what} was reported as a change and did not change"
    );
}
