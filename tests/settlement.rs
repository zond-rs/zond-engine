// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a resume is allowed to skip, against a real scanner and a fake network.
//!
//! The unit tests in `journal::settle` assert the rule; these assert that the
//! right fate actually reaches it from a scan that ran. The distinction cannot
//! be checked any other way, because the thing that makes it subtle is that
//! every fate produces the *same verdict* — so a test reading port states sees
//! nothing wrong with a scan that was cut off before it asked.
//!
//! The test that matters here is
//! [`a_cut_short_scan_gives_verdicts_it_has_not_earned`]. It is the regression
//! guard for the one failure this feature can have that nobody would notice: a
//! resumed scan skipping targets nobody ever probed, and reporting success.

mod common;

use common::fake_net::{FakeNet, Layer4, Policy};
use common::*;
use zond_engine::journal::settle::Fate;
use zond_engine::model::port::Protocol;
use zond_engine::model::technique::TcpScanTechnique;
use zond_engine::scanner::session::ScanSession;

/// Away from the low numbers, so a mistake that indexed rather than keyed would
/// produce visibly wrong ports.
const FIRST: u16 = 1_000;

/// Runs a SYN scan of `count` ports under one policy and hands back the session
/// and the context, so a caller can read both the verdicts and the fates.
///
/// `before_run` is given the session before the scan starts, which is how the
/// aborted case stops it without racing the loop.
async fn syn_scan(
    count: u16,
    policy: Policy,
    before_run: impl FnOnce(&ScanSession),
) -> (ScanSession, zond_engine::scanner::session::ScanContext) {
    let ports: Vec<u16> = (FIRST..FIRST + count).collect();

    let mut net = FakeNet::new(Layer4::Tcp);
    for &port in &ports {
        net = net.host(TARGET, port, policy);
    }

    let (session, ctx) = ScanSession::new();
    // Cloned before the scanner takes it: a context is cloned once per strategy
    // in the engine too, and every clone reads the same logs.
    let observer = ctx.clone();

    let mut scanner = zond_engine::scanner::strategy::routed::TcpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        TcpScanTechnique::Syn,
        net.transport(),
        ports.len(),
    );

    before_run(&session);

    let targets = ports.iter().map(|&port| tcp(TARGET, port)).collect();
    run_port_scanner(&mut scanner, targets).await;

    (session, observer)
}

/// A port that answered is settled, and settled positively. The base case.
#[tokio::test]
async fn an_answering_port_settles_as_answered() {
    let (_session, ctx) = syn_scan(8, Policy::open(), |_| {}).await;

    for port in FIRST..FIRST + 8 {
        assert_eq!(
            ctx.settlements().fate_of(TARGET, port, Protocol::Tcp),
            Some(Fate::Answered),
            "port {port} answered and must never be probed again"
        );
    }
}

/// Silence that spent the whole retry budget is *earned*, and is the one silence
/// a resume may skip. This is the fate the ledger calls
/// "the moment a verdict of 'filtered' is earned rather than assumed".
#[tokio::test]
async fn a_port_that_spent_its_budget_settles_as_exhausted() {
    let (_session, ctx) = syn_scan(8, Policy::silent(), |_| {}).await;

    for port in FIRST..FIRST + 8 {
        let fate = ctx
            .settlements()
            .fate_of(TARGET, port, Protocol::Tcp)
            .unwrap_or_else(|| panic!("port {port} was scanned and has no fate"));

        assert_eq!(
            fate,
            Fate::Exhausted,
            "port {port} was asked as often as the policy allows"
        );
        assert!(fate.is_settled());
    }
}

/// **The test this module exists for.**
///
/// A scan stopped before it could ask still gives every port a verdict — that is
/// the engine's deliberate choice, because an absent port is the one shortfall a
/// reader cannot see. Those verdicts must not read as coverage.
///
/// So this asserts the two halves together: the ports are all *present* with a
/// state, and not one of them is *settled*. A regression that hooked settlement
/// onto the verdict would pass every other test in this repository and fail
/// exactly here.
#[tokio::test]
async fn a_cut_short_scan_gives_verdicts_it_has_not_earned() {
    const COUNT: u16 = 64;

    // Aborted before the loop's first pass, so nothing is asked and the outcome
    // does not depend on how fast the fake network answers.
    let (session, ctx) = syn_scan(COUNT, Policy::silent(), |session| {
        session.handle().abort();
    })
    .await;

    let host = session
        .hosts()
        .get(&TARGET)
        .expect("an aborted scan still files the ports it was given");

    let with_a_verdict = host.ports().count();
    assert_eq!(
        with_a_verdict, COUNT as usize,
        "every port the scan was given must reach the report, asked or not"
    );

    // Reported as a count and a sample rather than the whole list: the failing
    // case is every target at once, and a panic message holding all of them
    // buries the number that says what happened.
    let settled = ctx.settlements().settled();
    assert!(
        settled.is_empty(),
        "a scan that asked nothing settled {} of {COUNT} targets, e.g. {:?}",
        settled.len(),
        &settled[..settled.len().min(3)]
    );

    // And say so specifically, so a failure names the confusion rather than a
    // count: every fate present must be one that re-probes.
    for settlement in ctx.settlements().snapshot() {
        assert!(
            matches!(settlement.fate, Fate::Unasked | Fate::Interrupted),
            "{settlement:?} claims a verdict this scan never earned"
        );
    }
}

/// A target nobody reported is not settled. The failure mode of a strategy that
/// forgets to call `settle` has to be redundant work, never a skipped target.
#[tokio::test]
async fn a_port_outside_the_scan_is_never_settled() {
    let (_session, ctx) = syn_scan(4, Policy::open(), |_| {}).await;

    assert_eq!(
        ctx.settlements().fate_of(TARGET, FIRST + 999, Protocol::Tcp),
        None,
        "a port the scan was never given must have no fate at all"
    );
    assert_eq!(
        ctx.settlements().fate_of(TARGET, FIRST, Protocol::Udp),
        None,
        "the UDP half of a scanned TCP port is a different target"
    );
}
