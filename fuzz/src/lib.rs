// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What more than one target asserts.
//!
//! A fuzz target without an oracle finds a panic and nothing else. Three of
//! these read a document into a [`ScanReport`], and the questions worth asking
//! of one are the same whichever reader built it — so they are asked here, once,
//! rather than copied into each target and drifting.
//!
//! **Every check in this file has to hold for every report the readers can
//! build.** A property that is merely usually true is worse than no property at
//! all: it stops the run on a document that was never wrong, and the campaign
//! spends its night on the harness instead of on the engine.

use zond_engine::diff::ScanDiff;
use zond_engine::report::ScanReport;

/// Asks a report the questions that must hold however it was built.
///
/// ## A report compares equal to itself
///
/// [`ScanDiff`] is what a consumer runs nightly, and "nothing changed" is the
/// answer it gives on the overwhelming majority of those runs. A comparison that
/// finds a change between a report and itself is a false alarm in somebody's
/// alerting rule, and it is the one output of that module nobody would think to
/// check. It also puts `diff` under the fuzzer for free, over hosts and ports
/// nobody would have written by hand.
///
/// ## Every host answers to the address it is filed under
///
/// The readers key a host by its primary address, and
/// [`ScanReport::host`](zond_engine::report::ScanReport::host) is the lookup
/// every consumer uses to find one. A host in the map that its own address does
/// not reach is a record that exists and cannot be got at — which a count of
/// hosts still reports as present.
///
/// The host that comes back is deliberately not compared against the one asked
/// for: two link-locals at the same number on different segments are two hosts,
/// and a bare address cannot say which was meant.
pub fn report_is_coherent(report: &ScanReport) {
    assert!(
        ScanDiff::between(report, report).is_empty(),
        "a report compared against itself reported a change"
    );

    for host in report.hosts() {
        assert!(
            report.host(&host.primary_ip()).is_some(),
            "{} is in the report and cannot be looked up in it",
            host.primary_ip()
        );
    }
}
