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
use zond_engine::journal::cursor::Checkpoint;
use zond_engine::journal::settle::Outcome;
use zond_engine::model::ip::set::IpSet;
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

/// A port that answered is settled, and the cursor advances over it. The base
/// case.
#[tokio::test]
async fn an_answering_port_settles_as_answered() {
    let (_session, ctx) = syn_scan(8, Policy::open(), |_| {}).await;
    let settlements = ctx.settlements();

    assert_eq!(settlements.count(Outcome::Answered { position: 0 }), 8);
    assert_eq!(settlements.settled_count(), 8);
    assert_eq!(
        settlements.checkpoint().watermark,
        8,
        "eight consecutive positions, all earned"
    );
}

/// Silence that spent the whole retry budget is *earned*, and is the one silence
/// a resume may skip — the moment the ledger calls "a verdict of 'filtered'
/// earned rather than assumed".
#[tokio::test]
async fn a_port_that_spent_its_budget_settles_as_exhausted() {
    let (_session, ctx) = syn_scan(8, Policy::silent(), |_| {}).await;
    let settlements = ctx.settlements();

    assert_eq!(settlements.count(Outcome::Exhausted { position: 0 }), 8);
    assert_eq!(settlements.checkpoint().watermark, 8);
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
        .get(TARGET)
        .expect("an aborted scan still files the ports it was given");

    let with_a_verdict = host.ports().count();
    assert_eq!(
        with_a_verdict, COUNT as usize,
        "every port the scan was given must reach the report, asked or not"
    );

    // Reported as a count and a sample rather than the whole list: the failing
    // case is every target at once, and a panic message holding all of them
    // buries the number that says what happened.
    let settlements = ctx.settlements();
    assert_eq!(
        settlements.settled_count(),
        0,
        "a scan that asked nothing settled {} of {COUNT} targets",
        settlements.settled_count()
    );
    assert_eq!(settlements.checkpoint(), Checkpoint::default());

    // Every target is accounted for, by an outcome that re-probes.
    let unsettled = settlements.count(Outcome::Unasked) + settlements.count(Outcome::Interrupted);
    assert_eq!(unsettled, u64::from(COUNT));
}

/// The cursor never runs past what the scan was given. A strategy that forgets
/// to report costs redundant work, never a skipped target.
#[tokio::test]
async fn the_cursor_never_exceeds_what_the_scan_was_given() {
    let (_session, ctx) = syn_scan(4, Policy::open(), |_| {}).await;

    assert_eq!(ctx.settlements().checkpoint().watermark, 4);
    assert!(!ctx.settlements().checkpoint().is_settled(4));
}

/// The unprivileged path settles too.
///
/// It has no retry ledger, so its positions travel with the probe rather than
/// inside one — and without this the connect fallback would resume by re-probing
/// everything, which is the path most users without root actually take.
#[tokio::test]
async fn the_connect_path_settles_what_it_probed() {
    use zond_engine::config::ServiceDetection;
    use zond_engine::model::target::{PlannedTarget, Target};

    let listener = spawn_banner_server(b"hi\r\n").await;
    let closed = closed_loopback_port().await;

    let (session, ctx) = ScanSession::new();
    let observer = ctx.clone();

    let (tx, rx) = tokio::sync::mpsc::channel(4);
    for (position, port) in [listener.port, closed].into_iter().enumerate() {
        tx.send(PlannedTarget::new(
            position as u64,
            Target {
                ip: LOOPBACK,
                port,
                protocol: zond_engine::model::port::Protocol::Tcp,
            },
        ))
        .await
        .expect("queue");
    }
    drop(tx);

    zond_engine::scanner::strategy::connect::scan(rx, 4, ctx, ServiceDetection::Off, &zond_engine::EvasionProfile::default())
        .await
        .expect("the connect scan runs");

    let settlements = observer.settlements();
    assert_eq!(
        settlements.checkpoint().watermark,
        2,
        "an open port and a refused one are both answers"
    );
    assert_eq!(settlements.count(Outcome::Answered { position: 0 }), 2);

    drop(session);
}

/// End to end: a scan journals as it runs, and a second sitting asks only about
/// what the first did not settle.
///
/// Every port here is closed, so the first sitting earns a verdict for all of
/// them and the second has nothing left — which is the case worth asserting at
/// this level, because it is the one where a mistake is invisible. A resume that
/// re-probed everything would still produce a correct report, just a wasteful
/// one, and only the cursor shows the difference.
///
/// Partial progress is exercised deterministically in `journal::store`, where a
/// checkpoint can be written by hand instead of raced for.
#[tokio::test]
async fn a_journalled_scan_resumes_where_it_stopped() {
    use zond_engine::Exclusions;
    use zond_engine::journal::Journal;
    use zond_engine::journal::manifest::Plan;
    use zond_engine::model::ip::set::IpSet;
    use zond_engine::model::port::PortSet;
    use zond_engine::model::target::{TargetMap, TargetSet};
    use zond_engine::model::technique::TcpScanTechnique;

    if is_privileged() {
        eprintln!("SKIP: drives the unprivileged connect path");
        return;
    }

    let root = std::env::temp_dir().join(format!("zond-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch root");

    // Four closed loopback ports: every probe earns a verdict, so a complete
    // sitting settles the whole plan.
    let mut ports = Vec::new();
    for _ in 0..4 {
        ports.push(closed_loopback_port().await);
    }
    let spec = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let mut plan = TargetMap::new();
    plan.add_unit(TargetSet::new(
        IpSet::from(LOOPBACK),
        spec.parse::<PortSet>().expect("ports"),
    ));

    let mut cfg = test_config();
    cfg.assume_up = true;

    // First sitting.
    let journal = Journal::create(
        &root,
        &Plan::port_scan(&plan, &Exclusions::none(), TcpScanTechnique::Syn),
        false,
        "loopback",
    )
    .expect("creates");
    let directory = journal.directory().to_path_buf();

    let (_session, task) = zond_engine::scanner::scan_with_journal(plan.clone(), &cfg, journal)
        .await
        .expect("the scan starts");
    let first = task.join().await.expect("the scan finishes");
    let first_phases = first.phases().len();

    // The journal outlived it, and records what was settled.
    let listed = zond_engine::journal::store::list(&root).expect("lists");
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0].settled(),
        Some(4),
        "four closed ports are four earned verdicts, and a finished sitting \
         must have checkpointed them"
    );
    assert!(listed[0].is_complete());

    // Second sitting over the same plan.
    let (journal, checkpoint) = Journal::resume(
        &directory,
        &Plan::port_scan(&plan, &Exclusions::none(), TcpScanTechnique::Syn),
        false,
    )
    .expect("resumes");

    assert_eq!(
        checkpoint.remaining(plan.iter()).count(),
        0,
        "the first sitting settled everything, so there is nothing to ask again"
    );
    let _ = &checkpoint;

    let (_session, task) = zond_engine::scanner::scan_with_journal(plan.clone(), &cfg, journal)
        .await
        .expect("the second sitting starts");
    let second = task.join().await.expect("it finishes");

    let listed = zond_engine::journal::store::list(&root).expect("lists");
    assert_eq!(
        listed[0].settled(),
        Some(4),
        "a sitting that asked nothing must still carry the first one's progress"
    );

    // **The two properties this feature exists for**, and neither is visible
    // from the report's host list alone.
    //
    // First: the second sitting asked about nothing. Observed as probes sent,
    // because a resumed scan that quietly re-probed everything would produce an
    // identical report and only this number would show it.
    // Sliced past the restored phases, which carry the first sitting's probes.
    let sent: u64 = second.phases()[first_phases..]
        .iter()
        .flat_map(|phase| phase.probe_stats())
        .map(|probes| probes.sends_attempted())
        .sum();
    assert_eq!(
        sent, 0,
        "the first sitting settled every target, so the second must send nothing"
    );

    // Second: it still reports what the first sitting found.
    assert_eq!(
        second.host_count(),
        1,
        "a resumed scan must report what earlier sittings found, not only its own"
    );

    // Third: the report says it ran in two sittings rather than presenting the
    // second as the whole job. Each phase keeps its own timings and settings, so
    // a reader can see how much of the work each one did.
    assert_eq!(
        second.phases().len(),
        first_phases * 2,
        "the second sitting's report must carry the first's phases as well as its own"
    );
    let started: Vec<_> = second.phases().iter().map(|p| p.started_at()).collect();
    assert!(
        started[0] <= started[1],
        "the earlier sitting must come first"
    );
    let host = second.hosts().next().expect("the host survived");
    assert_eq!(
        host.port_count(),
        4,
        "and their ports: {:?}",
        host.ports().map(|p| p.number()).collect::<Vec<_>>()
    );

    std::fs::remove_dir_all(&root).ok();
}

/// A journalled scan's event stream closes when the scan ends.
///
/// A caller watching a scan reads events until the stream closes and only then
/// asks for the report. If anything outside the scan holds the event sender —
/// the checkpoint task did, by holding a whole `ScanContext` — the stream never
/// closes, the caller never asks for the report, and the checkpoint task waits
/// to be told to stop by a caller that is itself waiting. Neither moves.
///
/// This is the shape a front end uses, which is why the earlier tests missed it:
/// they join the task directly and never wait on the stream.
#[tokio::test]
async fn a_journalled_scan_lets_a_watcher_finish() {
    use zond_engine::Exclusions;
    use zond_engine::journal::Journal;
    use zond_engine::journal::manifest::Plan;
    use zond_engine::model::ip::set::IpSet;
    use zond_engine::model::port::PortSet;
    use zond_engine::model::target::{TargetMap, TargetSet};
    use zond_engine::model::technique::TcpScanTechnique;

    if is_privileged() {
        eprintln!("SKIP: drives the unprivileged connect path");
        return;
    }

    let root = std::env::temp_dir().join(format!("zond-watch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch root");

    let mut plan = TargetMap::new();
    plan.add_unit(TargetSet::new(
        IpSet::from(LOOPBACK),
        closed_loopback_port()
            .await
            .to_string()
            .parse::<PortSet>()
            .expect("ports"),
    ));

    let mut cfg = test_config();
    cfg.assume_up = true;

    let journal = Journal::create(
        &root,
        &Plan::port_scan(&plan, &Exclusions::none(), TcpScanTechnique::Syn),
        false,
        "loopback",
    )
    .expect("creates");
    let (session, task) = zond_engine::scanner::scan_with_journal(plan, &cfg, journal)
        .await
        .expect("the scan starts");

    let (_hosts, mut events, _handle) = session.into_parts();

    // Exactly what a front end does: drain until the stream closes, then join.
    // Capped, because the failure this guards against is that it never does.
    let drained = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while events.recv().await.is_some() {}
    })
    .await;

    assert!(
        drained.is_ok(),
        "the event stream never closed: something outside the scan is holding it open"
    );

    let _ = task.join().await.expect("the scan finishes");
    std::fs::remove_dir_all(&root).ok();
}

/// A probe that was sent but never answered before the stop is asked again.
///
/// The case: a port is probed, the scan is interrupted, and the reply either
/// arrives too late to be read or never arrives at all. The engine still files a
/// verdict for that port — silence, so the report is not missing it — but the
/// verdict was *assigned* rather than earned, and a resume must ask again rather
/// than inherit it.
///
/// Asserted through the cursor, because that is what a resume reads. A port
/// still in flight is `Interrupted`, which carries no position, so nothing about
/// it can advance the watermark.
#[tokio::test]
async fn a_probe_outstanding_at_the_stop_is_asked_again() {
    use zond_engine::journal::settle::Outcome;
    use zond_engine::model::technique::TcpScanTechnique;
    use zond_engine::scanner::session::ScanSession;

    let ports: Vec<u16> = (20_000..20_400).collect();

    // Silent, so every probe stays outstanding on its retry schedule rather than
    // settling: whatever is in flight when the stop arrives is genuinely in
    // flight.
    let mut net = FakeNet::new(Layer4::Tcp);
    for &port in &ports {
        net = net.host(TARGET, port, Policy::silent());
    }

    let (session, ctx) = ScanSession::new();
    let observer = ctx.clone();
    let handle = session.handle().clone();

    let mut scanner = zond_engine::scanner::strategy::routed::TcpPortScanner::with_transport(
        scanner_resolver(),
        ctx,
        TcpScanTechnique::Syn,
        net.transport(),
        ports.len(),
    );

    let targets: Vec<_> = ports.iter().map(|&port| tcp(TARGET, port)).collect();
    let scanning = tokio::spawn(async move {
        run_port_scanner(&mut scanner, targets).await;
    });

    // Long enough for probes to be on the wire, short enough that none of them
    // has run out of retries.
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;
    handle.abort();
    scanning.await.expect("the scan winds down");

    let settlements = observer.settlements();

    assert!(
        settlements.count(Outcome::Interrupted) > 0,
        "no probe was in flight, so this test proved nothing"
    );
    assert_eq!(
        settlements.settled_count(),
        0,
        "a probe that was never answered must not be settled: {} interrupted, \
         {} exhausted",
        settlements.count(Outcome::Interrupted),
        settlements.count(Outcome::Exhausted { position: 0 })
    );

    // And so a resume asks about every one of them again.
    assert_eq!(settlements.checkpoint(), Checkpoint::default());
}

// ─── Sweeps settle addresses, and only where a sweep is what is running ──────

/// The addresses a sweep is counted in, written the way a plan is.
fn addresses(written: &str) -> IpSet {
    written.parse().expect("a valid address specification")
}

/// A sweep settles the address it earned a verdict for, at that address's
/// position in the plan. Without this the whole feature is inert: a journal
/// records a cursor nothing ever advances, and every sitting starts over.
///
/// Loopback rather than a fake network, because the unprivileged path is real
/// sockets by construction and refuses instantly on an unused port — which is a
/// TCP-layer answer and so proof the host is there.
#[tokio::test]
async fn a_sweep_settles_the_address_that_answered() {
    let plan = addresses("127.0.0.1");
    let (_session, ctx) = ScanSession::sweeping(
        zond_engine::Exclusions::none(),
        &Checkpoint::default(),
        plan.positions(),
    );

    let observer = ctx.clone();
    zond_engine::scanner::strategy::connect::discover(plan, ctx, &zond_engine::EvasionProfile::default())
        .await
        .expect("the connect sweep runs anywhere");

    let settlements = observer.settlements();
    assert_eq!(
        settlements.count(Outcome::Answered { position: 0 }),
        1,
        "loopback answers, and answering is what settles an address"
    );
    assert_eq!(
        settlements.checkpoint().watermark,
        1,
        "the one position in the plan, earned"
    );
}

/// **The isolation property, and the reason a sweep's numbering lives on the
/// context rather than being derived from the addresses.**
///
/// A port scan runs the discovery strategies too, as its liveness pass, against
/// a context counted in address-and-port pairs. If those strategies settled
/// addresses there, position 0 of the *port* plan would be marked covered by a
/// liveness probe — and the resumed scan would skip a port nothing ever asked
/// about, reporting success.
///
/// A context that does not number addresses is what prevents it. This asserts
/// the sweep records nothing at all against one.
#[tokio::test]
async fn a_sweep_inside_a_port_scan_settles_nothing() {
    // `new` is what `scan` builds: exclusions and a cursor, and no address
    // numbering, because a port scan counts something else.
    let (_session, ctx) = ScanSession::new();

    let observer = ctx.clone();
    zond_engine::scanner::strategy::connect::discover(addresses("127.0.0.1"), ctx, &zond_engine::EvasionProfile::default())
        .await
        .expect("the connect sweep runs anywhere");

    let settlements = observer.settlements();
    assert_eq!(
        settlements.settled_count(),
        0,
        "a liveness pass must not advance a port scan's cursor"
    );
    assert_eq!(settlements.checkpoint(), Checkpoint::default());
}

/// An address the plan does not name has no position. A sweep finds neighbours
/// it was never asked about — they are findings, and settling one would advance
/// the cursor over a position belonging to a different address.
#[tokio::test]
async fn an_address_outside_the_plan_settles_nothing() {
    // Numbered over a plan loopback is not in, then swept for loopback anyway,
    // which is the shape of a segment sweep finding a neighbour.
    let (_session, ctx) = ScanSession::sweeping(
        zond_engine::Exclusions::none(),
        &Checkpoint::default(),
        addresses("192.0.2.0/30").positions(),
    );

    let observer = ctx.clone();
    zond_engine::scanner::strategy::connect::discover(addresses("127.0.0.1"), ctx, &zond_engine::EvasionProfile::default())
        .await
        .expect("the connect sweep runs anywhere");

    assert_eq!(observer.settlements().settled_count(), 0);
}

/// **The exclusion policy decides the enumeration, so a resume under a different
/// one is refused.**
///
/// Withhold the first half of a range and every position after it names a
/// different target. Two sittings under different policies would then agree on a
/// plan fingerprint and disagree on what position 400 means — the resumed one
/// skipping targets nobody probed, and the merged report claiming them.
///
/// The refusal belongs to the engine rather than to whichever front end
/// remembered to check: a journal is handed over with the settings a scan is
/// about to run under, and those are the two things that have to agree.
#[tokio::test]
async fn a_resume_under_a_narrower_exclusion_policy_is_refused() {
    use zond_engine::journal::Journal;
    use zond_engine::journal::manifest::Plan;
    use zond_engine::{Exclusions, ZondConfig};

    let root = std::env::temp_dir().join(format!("zond-policy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("a scratch root");

    let plan: IpSet = "192.0.2.1-192.0.2.8".parse().expect("a range");
    let journal = Journal::create(
        &root,
        &Plan::discovery(&plan, &Exclusions::none(), false),
        false,
        "192.0.2.1 and 7 more",
    )
    .expect("creates");
    let directory = journal.directory().to_path_buf();
    journal.close().expect("closes");

    // The same record, continued by a run that would withhold part of it.
    let mut narrowed = ZondConfig::default();
    let mut withheld = IpSet::new();
    withheld.insert_range("192.0.2.1-192.0.2.4".parse().expect("a range"));
    narrowed.exclusions = Exclusions::new(withheld);

    let (journal, _, _) = Journal::reopen(&directory, false).expect("reopens");
    let refused = zond_engine::discover_with_journal(plan.clone(), &narrowed, journal)
        .await
        .err()
        .expect("a policy that narrows the recorded plan renumbers it");

    assert!(
        matches!(refused, zond_engine::scanner::ScanError::PlanChanged(_)),
        "{refused:?}"
    );

    // And the policy the record was written under is accepted, so the refusal
    // above is about the change rather than about there being a policy at all.
    let (journal, _, _) = Journal::reopen(&directory, false).expect("reopens");
    zond_engine::discover_with_journal(plan, &ZondConfig::default(), journal)
        .await
        .expect("the recorded policy still describes the recorded plan");

    let _ = std::fs::remove_dir_all(&root);
}
