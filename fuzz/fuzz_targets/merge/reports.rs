// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Several scans of one network, folded into one report.
//!
//! A merge is where a `/16` scanned in eight chunks becomes one document, and
//! where a year of somebody else's nmap files becomes comparable with tonight's
//! run. Its rule is one sentence — a later source overrides only where it made a
//! claim — and the whole module is that sentence applied to every field of a
//! host and every field of a port, by hand, one at a time.
//!
//! **By hand is the point.** `fold_host` and `fold_port` name the fields they
//! carry, so a field neither names is one a merge silently discards, and nothing
//! about that fails to compile. It had already happened: what the filter in
//! front of a host was shown to be doing was produced by a scanner, journalled,
//! exported and imported, and dropped by every fold in the crate.
//!
//! ## The oracle: folding one report changes nothing
//!
//! A merge of a single source has nothing to arbitrate. Every rule in the module
//! is about which of two accounts wins, and with one account each of them is the
//! identity — so the result has to describe the same network the source did, and
//! `diff` is what says whether it does.
//!
//! That is exactly the check the missing field would have failed, and it fails
//! for any field either fold forgets from now on, including one added after this
//! target was written.
//!
//! ## And that nothing goes in without coming out
//!
//! Absence is never a claim, which is the rule the module is built on: a host
//! missing from tonight's scan did not go away, and an endpoint nothing listed
//! did not close. The other side of that is that a host *present* in any source
//! is present in the result, and a host in the result came from one of them. A
//! fold that dropped a record would be reading absence into a document that made
//! a claim, which is the same mistake pointing the other way.
//!
//! Checked by address rather than by identity, and against the whole address set
//! of each folded host, because which address a merged host is keyed under is
//! decided by a ranking over every account and need not be the one any single
//! source used.
//!
//! ## And that a merged report is a report
//!
//! It merges again, and folding it a second time is folding one source. A merge
//! is documented as closed over `ScanReport` — every writer takes the result,
//! every comparison takes it, the next merge takes it — and a result that could
//! not go round again would be a document only this module can read.
//!
//! ## What is not asserted
//!
//! **That the order sources are added in does not decide the outcome.** It was,
//! and it is wrong: records are ordered by when each was observed, the sort is
//! stable, and the module says what that means for a tie — "two sources that
//! stopped at the same instant stay in the order they were added and the fold
//! has one answer rather than two". Two documents written by one scan carry one
//! clock, which is not an exotic input, it is what a `/16` split into chunks
//! looks like. The property is true where the clocks differ and the harness
//! cannot tell the difference without restating `merge`'s own rule for
//! attributing a record to a moment, so it is left to the crate's own test,
//! where the clocks are chosen.
//!
//! That folding in rounds equals folding at once. It does not, the module
//! explains why at length, and there is a test in the crate holding it to *not*
//! being equal.

#![no_main]

use std::collections::BTreeSet;
use std::net::IpAddr;

use libfuzzer_sys::fuzz_target;
use zond_engine::diff::HostIdentity;
use zond_engine::merge::{Merge, MergeOptions};
use zond_engine::report::ScanReport;
use zond_engine_fuzz::{report_is_coherent, reports, same_network};

fuzz_target!(|data: &[u8]| {
    let sources = reports(data, 4);
    if sources.is_empty() {
        return;
    }

    // One source, where every rule about which account wins is the identity.
    let folded = fold(sources.iter().cloned(), MergeOptions::new());
    report_is_coherent(&folded);
    if sources.len() == 1 {
        same_network(&sources[0], &folded, "folding a single report");
    }

    // Closed over `ScanReport`: the result goes round again, and folding it
    // alone is folding one source.
    let again = fold(std::iter::once(folded.clone()), MergeOptions::new());
    same_network(&folded, &again, "folding a merged report");

    // Under a pairing policy that folds more records together as well, so what
    // holds below is not an accident of one identity.
    for identity in [HostIdentity::AnyAddress, HostIdentity::Hardware] {
        let result = fold(
            sources.iter().cloned(),
            MergeOptions::new().with_identity(identity),
        );
        report_is_coherent(&result);
        nothing_lost(&sources, &result);
        nothing_invented(&sources, &result);
    }
});

/// Every address any source reported is reachable in the result.
///
/// Not necessarily as the address it is keyed under: `consider_primary_ip` ranks
/// every account's address and leads with the one that names the host best, so a
/// machine a source filed under a link-local is filed under its global address
/// once both are in hand.
fn nothing_lost(sources: &[ScanReport], result: &ScanReport) {
    let held: BTreeSet<IpAddr> = result
        .hosts()
        .flat_map(|host| host.ips().iter().copied())
        .collect();

    for source in sources {
        for host in source.hosts() {
            for ip in host.ips() {
                assert!(
                    held.contains(ip),
                    "{ip} was reported by a source and is not in the merged report"
                );
            }
        }
    }
}

/// And nothing is in the result that no source reported.
fn nothing_invented(sources: &[ScanReport], result: &ScanReport) {
    let reported: BTreeSet<IpAddr> = sources
        .iter()
        .flat_map(|source| source.hosts())
        .flat_map(|host| host.ips().iter().copied())
        .collect();

    for host in result.hosts() {
        for ip in host.ips() {
            assert!(
                reported.contains(ip),
                "{ip} is in the merged report and no source reported it"
            );
        }
    }
}

/// Folds `sources` into one report.
fn fold(sources: impl Iterator<Item = ScanReport>, options: MergeOptions) -> ScanReport {
    let mut merge = Merge::new(options);
    for source in sources {
        merge.add(source);
    }
    merge.finish()
}
