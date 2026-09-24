// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Turning a running scan into the record it leaves behind
//!
//! [`crate::report`] holds the vocabulary a finished scan is described in.
//! This is the one piece that needs a scan to still be running: it opens when a
//! phase starts, holds what was asked for, and reads the findings out of a live
//! [`ScanContext`] when the phase ends.
//!
//! It lives with the scanner rather than with the report because it is the only
//! part of the record that touches the machinery. Everything else in
//! [`crate::report`] can be built, read and written with no scan in sight.

use std::time::{Instant, SystemTime};

use crate::config::ZondConfig;
use std::net::IpAddr;

use crate::model::host::HostStatus;
use crate::model::ip::range::IpRange;
use crate::model::ip::set::IpSet;
use crate::model::port::PortState;
use crate::report::{
    LivenessSkip, PhaseParts, ScanKind, ScanPhase, ScanReport, ScanSettings, TargetScope,
};
use crate::scanner::orchestrator::Liveness;
use crate::scanner::session::ScanContext;
use crate::system::privilege::Privilege;

/// Carries a phase's metadata from the moment a scan starts to the moment it
/// ends, and closes the record when it does.
///
/// The scope and settings of a scan are only knowable before it starts, because
/// the target set moves into the strategies that consume it, while the duration
/// and the failures are only knowable after it ends. This holds the first half
/// until the second is available, so both land in one [`ScanPhase`] rather than
/// leaving a half-built report somewhere for the closing code to find.
///
/// # Building a report from a caller's own orchestration
///
/// [`discover`](crate::scanner::discover) and [`scan`](crate::scanner::scan) use
/// this internally, and it is public so that a caller running strategies
/// themselves can produce the same [`ScanReport`] the engine does. Without it
/// a self-orchestrated scan could read its own findings but never write the
/// record of them, and so could never reach an
/// [`Exporter`](crate::export::Exporter).
///
/// Take it before the scan, hand it the context afterwards:
///
/// ```no_run
/// use zond_engine::ZondConfig;
/// use zond_engine::model::parse::ip::to_set;
/// use zond_engine::report::{ScanKind, TargetScope};
/// use zond_engine::scanner::recorder::PhaseRecorder;
/// use zond_engine::scanner::session::ScanSession;
/// use zond_engine::system::privilege::Privilege;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let cfg = ZondConfig::default();
///
/// // The policy has to reach the context as well as the targets. The
/// // subtraction below covers the addresses named in the target list, and a
/// // segment sweep does not confine itself to those; see `Exclusions`.
/// let (session, ctx) = ScanSession::builder().excluding(cfg.exclusions.clone()).build();
///
/// // Recorded before the targets move into a strategy, since what a scan was
/// // asked to cover is only knowable here. `targets` comes back narrowed by
/// // whatever the policy forbids, and the scope records what that cost.
/// let mut targets = to_set(&["192.0.2.0/24"], None, None)?;
/// let scope = TargetScope::from_ip_set(&mut targets, &cfg.exclusions);
/// let recorder = PhaseRecorder::start(ScanKind::Discovery, Privilege::Connect, scope, &cfg);
///
/// // ... build strategies against `ctx` and run them ...
///
/// let report = recorder.finish(&ctx);
/// println!("{} hosts", report.summary().hosts_total);
/// # let _ = session;
/// # Ok(())
/// # }
/// ```
pub struct PhaseRecorder {
    kind: ScanKind,
    started_at: SystemTime,
    started: Instant,
    privilege: Privilege,
    targets: TargetScope,
    settings: ScanSettings,
    liveness_skipped: Option<LivenessSkip>,
}

impl PhaseRecorder {
    /// Opens a phase record, taking the clock readings that bound it.
    ///
    /// Call this before the scan starts. `targets` is the scope the phase was
    /// asked to cover, which has to be read while the target set is still in
    /// hand; `privilege` is which sockets the strategies about to run hold.
    ///
    /// Both clocks are read because they answer different questions: the wall
    /// clock says when the scan happened, the monotonic one says how long it
    /// took. Deriving the second from the first would let an NTP correction
    /// during a long sweep report a duration that never elapsed.
    pub fn start(
        kind: ScanKind,
        privilege: Privilege,
        targets: TargetScope,
        cfg: &ZondConfig,
    ) -> Self {
        Self {
            kind,
            started_at: SystemTime::now(),
            started: Instant::now(),
            privilege,
            targets,
            settings: ScanSettings::from(cfg),
            liveness_skipped: None,
        }
    }

    /// Records that this port phase runs with no liveness pass in front of it,
    /// and why.
    ///
    /// For a caller orchestrating a port scan who skipped the pass, so the
    /// record says so rather than leaving a reader to infer it from the missing
    /// discovery phase. See [`ScanPhase::liveness_skipped`].
    #[must_use]
    pub fn skipping_liveness(mut self, why: LivenessSkip) -> Self {
        self.liveness_skipped = Some(why);
        self
    }

    /// Closes the record, snapshotting the hosts the scan wrote into `ctx`.
    ///
    /// Call this once, after every strategy has stopped writing, or the
    /// snapshot describes a scan that was still running.
    ///
    /// The failures and probe statistics filed against `ctx` are *taken* rather
    /// than copied, so a context reused for a second phase starts empty and
    /// cannot hand the same failure to two reports. Anything that needs to read
    /// them without closing a phase has
    /// [`ScanContext::failures_snapshot`](crate::scanner::session::ScanContext::failures_snapshot)
    /// and its probe-statistics counterpart.
    ///
    /// A [`Discovery`](ScanKind::Discovery) phase also names the addresses in
    /// its scope it reached no verdict on, read off what its strategies filed:
    /// see [`ScanPhase::undecided`](crate::report::ScanPhase::undecided).
    pub fn finish(self, ctx: &ScanContext) -> ScanReport {
        self.close(ctx).0
    }

    /// [`finish`](Self::finish), handing back as well what a discovery phase
    /// established about presence, for the port phase that follows it to act
    /// on. `None` for any other kind of phase.
    ///
    /// One reading serves both, so the port phase settles as found down exactly
    /// the addresses the report does not name as undecided.
    pub(super) fn close(self, ctx: &ScanContext) -> (ScanReport, Option<Liveness>) {
        // Which links the strategies reached is only knowable now: the scope was
        // fixed before the first probe went out, and a sweep of a segment covers
        // ground no target set named.
        let mut targets = self.targets;
        targets.record_sweeps(ctx.take_swept_links());

        let unroutable = ctx.take_unroutable();
        // Taken whatever the kind, so a context reused for another phase starts
        // with no silence it did not hear.
        let silent = ctx.take_silent();
        let liveness = (self.kind == ScanKind::Discovery).then(|| Liveness::found(ctx, silent));
        let undecided = liveness.as_ref().map_or_else(Vec::new, |liveness| {
            liveness.undecided(&targets, &unroutable)
        });
        let timed_out = ctx.take_timed_out();
        // Only where the port probes stood in for a liveness pass the engine
        // dropped: there an address they drew nothing from is what the pass
        // would have found silent. See `ScanPhase::silent`.
        let silent = match (self.kind, self.liveness_skipped) {
            (ScanKind::PortScan, Some(LivenessSkip::PortsNoDearer)) => {
                silent_on_every_port(ctx, &targets, &unroutable, &timed_out)
            }
            _ => Vec::new(),
        };

        let phase = ScanPhase::from_parts(PhaseParts {
            kind: self.kind,
            started_at: self.started_at,
            // Monotonic rather than the difference between two wall-clock
            // readings, which a clock correction mid-sweep would distort.
            elapsed: self.started.elapsed(),
            privilege: Some(self.privilege),
            targets,
            settings: self.settings,
            failures: ctx.take_failures(),
            refusals: ctx.take_refusals(),
            unroutable,
            timed_out,
            // Taken whatever the privilege, so a context reused for another
            // phase starts empty, and kept only for a raw phase: one at
            // `Connect` reached everything this way, and its privilege says so.
            reached_by_connect: match self.privilege {
                Privilege::Raw => ctx.take_reached_by_connect(),
                Privilege::Connect => {
                    let _ = ctx.take_reached_by_connect();
                    Vec::new()
                }
            },
            undecided,
            liveness_skipped: self.liveness_skipped,
            silent,
            probes: ctx.take_probe_stats(),
            origin: None,
            attachments: ctx.take_attachments(),
        });

        // Copied rather than taken: the store is shared with the `ScanSession`
        // the caller kept, which goes on answering after this returns.
        let hosts = ctx.store.iter().map(|entry| entry.value().clone());
        (ScanReport::new(phase, hosts), liveness)
    }
}

/// The addresses in `scope` a port phase asked on every port it named and
/// drew nothing from: no open port, no closed one, no ICMP error, so the host
/// record the scanners filed there is still [`Unknown`](HostStatus::Unknown).
///
/// A record with a port still [`Unasked`](PortState::Unasked) is left out,
/// since the phase did not finish asking that address and its silence is not
/// yet a verdict, and so are the addresses nothing could be sent to and the
/// ones a time budget left part-asked: each is already named for what it is.
fn silent_on_every_port(
    ctx: &ScanContext,
    scope: &TargetScope,
    unroutable: &[IpAddr],
    timed_out: &[IpAddr],
) -> Vec<IpRange> {
    let mut covered = IpSet::new();
    for range in scope.ranges() {
        covered.insert_range(*range);
    }
    covered.canonicalize();

    let mut silent = IpSet::new();
    for entry in ctx.store.iter() {
        let host = entry.value();
        let address = host.scoped_ip().addr();
        let heard_nothing = host.status() == HostStatus::Unknown
            && host.ports().all(|port| port.state() != PortState::Unasked);
        if heard_nothing
            && covered.contains(&address)
            && !unroutable.contains(&address)
            && !timed_out.contains(&address)
        {
            silent.insert(address);
        }
    }
    silent.canonicalize();

    let v4 = silent.v4().iter().copied().map(IpRange::V4);
    let v6 = silent.v6().iter().copied().map(IpRange::V6);
    v4.chain(v6).collect()
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {

    use super::*;
    use crate::model::exclusion::Exclusions;
    use crate::model::host::HostStatus;
    use crate::model::ip::set::IpSet;
    use crate::report::{BUCKET_BOUNDS_MS, ProbeStats, Refusal, ScannerKind, StopReason};
    use crate::scanner::session::ScanSession;

    /// A scope over two addresses, since `TargetScope` is built from a target
    /// set rather than defaulted.
    fn scope() -> TargetScope {
        let mut targets = IpSet::from_str("203.0.113.1-203.0.113.2").expect("a valid range");
        TargetScope::from_ip_set(&mut targets, &Exclusions::none())
    }

    /// A refusal and a failure are both the scan saying what it did not cover,
    /// and only one of them says something went wrong. They reached the report
    /// as one list, so a scan that declined an unenumerable prefix and a scan
    /// whose raw socket died were indistinguishable to a caller of `discover`
    /// or `scan`, which is the distinction `plan.rs` opens by saying a scanner
    /// may never lose.
    #[test]
    fn a_refusal_reaches_the_report_as_a_refusal_and_not_as_a_failure() {
        let cfg = ZondConfig::default();
        let (_session, ctx) = ScanSession::new();
        let recorder = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, scope(), &cfg);

        ctx.record_refusal(Refusal::new(
            ScannerKind::SctpPort,
            "no unprivileged init probe exists",
        ));
        ctx.record_failure(ScannerKind::Local, "the capture would not open".to_string());

        let report = recorder.finish(&ctx);
        let phase = &report.phases()[0];

        assert_eq!(phase.refusals().len(), 1, "the refusal is its own kind");
        assert_eq!(phase.refusals()[0].scanner(), ScannerKind::SctpPort);
        assert_eq!(
            phase.failures().len(),
            1,
            "and the failure is still a failure"
        );
        assert_eq!(phase.failures()[0].scanner(), ScannerKind::Local);
    }

    /// Taken rather than copied, on the same terms the failures are: a context
    /// reused for a second phase must not hand the same refusal to two reports.
    #[test]
    fn a_phase_takes_its_refusals_rather_than_copying_them() {
        let cfg = ZondConfig::default();
        let (_session, ctx) = ScanSession::new();
        ctx.record_refusal(Refusal::new(ScannerKind::SctpPort, "no init probe"));

        let first = PhaseRecorder::start(ScanKind::Discovery, Privilege::Connect, scope(), &cfg)
            .finish(&ctx);
        let second = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, scope(), &cfg)
            .finish(&ctx);

        assert_eq!(first.phases()[0].refusals().len(), 1);
        assert!(second.phases()[0].refusals().is_empty());
    }

    /// Filed once per distinct reason. A plan that declines the same range on
    /// two links has one thing to tell the caller, and saying it twice is how a
    /// report teaches a reader to skim past it.
    #[test]
    fn the_same_refusal_filed_twice_is_recorded_once() {
        let (_session, ctx) = ScanSession::new();
        let refusal = Refusal::new(ScannerKind::Local, "too large to walk");

        ctx.record_refusal(refusal.clone());
        ctx.record_refusal(refusal);

        assert_eq!(ctx.refusals_snapshot().len(), 1);
    }
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::time::Duration;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    /// A caller running strategies themselves has to be able to produce the
    /// report the engine produces, or the whole third altitude stops at the
    /// live store: findings readable, nothing exportable.
    ///
    /// This walks that path with no strategies in it, since what is being
    /// pinned is that every piece is reachable and the halves meet, not what a
    /// An address with no route reaches the record without making the scan
    /// partial.
    ///
    /// The whole point of keeping it apart from a failure. A dual-stack name on
    /// an IPv4-only network resolves to an address nobody here can reach, and
    /// reporting that as a scan which covered less than it was asked to made
    /// every such scan look broken, while the one detail a caller can act on,
    /// *which* address went uncovered, was not in the report at all.
    #[test]
    fn an_unroutable_address_is_recorded_without_making_the_scan_partial() {
        let cfg = ZondConfig::default();
        let (_session, ctx) = crate::scanner::session::ScanSession::new();

        let mut targets = IpSet::from_str("203.0.113.1-203.0.113.2").expect("a valid range");
        let scope = TargetScope::from_ip_set(&mut targets, &Exclusions::none());
        let recorder = PhaseRecorder::start(ScanKind::Discovery, Privilege::Connect, scope, &cfg);

        // Both addresses in scope asked and found silent, so the one thing
        // that could make this phase partial is the address with no route.
        for address in [ip(1), ip(2)] {
            ctx.settle_address(address, crate::journal::settle::Settled::Exhausted);
        }
        let unreachable: IpAddr = "2001:db8::1".parse().expect("literal");
        ctx.record_unroutable(unreachable);
        // Twice, as two probes to one address would: it is one fact about one
        // address however many times it was met.
        ctx.record_unroutable(unreachable);

        let report = recorder.finish(&ctx);

        assert_eq!(report.phases()[0].unroutable(), [unreachable]);
        assert!(
            !report.is_partial(),
            "no strategy failed; that address is simply not reachable from here"
        );
        assert_eq!(report.failures().count(), 0);
    }

    /// scanner would have written.
    #[test]
    fn a_self_orchestrated_scan_can_close_its_own_phase() {
        let cfg = ZondConfig::default();
        let (_session, ctx) = crate::scanner::session::ScanSession::new();

        let mut targets = IpSet::from_str("203.0.113.1-203.0.113.4").expect("a valid range");
        let scope = TargetScope::from_ip_set(&mut targets, &Exclusions::none());
        let recorder = PhaseRecorder::start(ScanKind::Discovery, Privilege::Connect, scope, &cfg);

        ctx.update_host(ip(1), |host| host.set_status(HostStatus::Up));
        ctx.record_failure(ScannerKind::Local, "eth0: no address".into());

        let report = recorder.finish(&ctx);

        assert_eq!(report.host_count(), 1);
        assert_eq!(report.phases()[0].targets().addresses(), 4);
        assert!(report.is_partial(), "the failure has to reach the record");
        assert_eq!(report.failures().count(), 1);
    }

    /// The counters a scanner files mid-scan have to reach the phase that
    /// finishes afterwards, and reach exactly the one that was running.
    #[test]
    fn probe_stats_filed_during_a_scan_land_in_its_phase() {
        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let recorder = PhaseRecorder::start(
            ScanKind::Discovery,
            Privilege::Raw,
            TargetScope::from_ip_set(&mut IpSet::new(), &Exclusions::none()),
            &ZondConfig::default(),
        );

        ctx.record_probe_stats(ProbeStats {
            window: None,
            scanner: ScannerKind::Routed,
            targets: 256,
            stop_reason: StopReason::AllResponded,
            elapsed: Duration::from_millis(40),
            sends_attempted: 300,
            sends_failed: 0,
            sends_witnessed: 0,
            segments_seen: 250,
            segments_off_target: 1,
            replies_without_rtt: 2,
            hosts_found: 9,
            answered_on: [7, 2, 0, 0, 0, 0],
            answered_unattributed: 0,
            first_reply: Some(Duration::from_millis(1)),
            last_reply: Some(Duration::from_millis(30)),
            found_at: [0; BUCKET_BOUNDS_MS.len() + 1],
            capture: None,
        });

        let report = recorder.finish(&ctx);
        let stats = report.phases()[0].probe_stats();

        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].scanner(), ScannerKind::Routed);
        assert_eq!(stats[0].hosts_found(), 9);
        assert_eq!(stats[0].answered_on()[1], 2);
        assert_eq!(report.probe_stats().count(), 1);

        // Draining is what stops a second phase inheriting the first's counters.
        assert!(ctx.take_probe_stats().is_empty());
    }

    /// A raw phase that reached some addresses by connect says which, merged,
    /// and a connect phase says nothing more than its privilege already does.
    /// Both drain the log, so a context reused for another phase starts empty.
    #[test]
    fn what_a_raw_phase_reached_by_connect_is_recorded_and_a_connect_phase_ignores_it() {
        let cfg = ZondConfig::default();
        let (_session, ctx) = ScanSession::new();
        let addresses = |list: &[&str]| {
            let mut set = IpSet::new();
            for address in list {
                set.insert(address.parse().expect("a literal"));
            }
            set
        };

        let raw = PhaseRecorder::start(ScanKind::PortScan, Privilege::Raw, scope(), &cfg);
        ctx.record_reached_by_connect(&addresses(&["127.0.0.1", "192.0.2.8"]));
        // Reported again by a second strategy, and adjacent to one already in.
        ctx.record_reached_by_connect(&addresses(&["127.0.0.1", "192.0.2.9"]));
        let report = raw.finish(&ctx);

        let reached: Vec<String> = report.phases()[0]
            .reached_by_connect()
            .iter()
            .map(|range| format!("{}-{}", range.start_addr(), range.end_addr()))
            .collect();
        assert_eq!(
            reached,
            ["127.0.0.1-127.0.0.1", "192.0.2.8-192.0.2.9"],
            "merged, ascending, and each address once"
        );

        let connect = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, scope(), &cfg);
        ctx.record_reached_by_connect(&addresses(&["127.0.0.1"]));
        let report = connect.finish(&ctx);
        assert!(
            report.phases()[0].reached_by_connect().is_empty(),
            "a connect phase reached everything this way, and says so once"
        );

        let after = PhaseRecorder::start(ScanKind::PortScan, Privilege::Raw, scope(), &cfg);
        assert!(
            after.finish(&ctx).phases()[0]
                .reached_by_connect()
                .is_empty(),
            "and what the connect phase was handed did not carry over"
        );
    }

    /// **A discovery phase names every address it reached no verdict on, and
    /// only those.** An address that answered and one asked to exhaustion both
    /// have a verdict, and one with no route is named apart; the fourth was
    /// never settled either way, which is what a stop, a failed strategy or a
    /// refusal leaves. Without the list a reader counts it among the silent.
    #[test]
    fn a_discovery_phase_names_the_addresses_it_reached_no_verdict_on() {
        use crate::journal::settle::Settled;

        let cfg = ZondConfig::default();
        let (_session, ctx) = ScanSession::new();
        let mut targets = IpSet::from_str("203.0.113.1-203.0.113.4").expect("a valid range");
        let scope = TargetScope::from_ip_set(&mut targets, &Exclusions::none());
        let recorder = PhaseRecorder::start(ScanKind::Discovery, Privilege::Connect, scope, &cfg);

        ctx.update_host(ip(1), |host| host.set_status(HostStatus::Up));
        ctx.settle_address(ip(2), Settled::Exhausted);
        ctx.record_unroutable(ip(3));

        let report = recorder.finish(&ctx);
        let undecided: Vec<String> = report.phases()[0]
            .undecided()
            .iter()
            .map(|range| format!("{}-{}", range.start_addr(), range.end_addr()))
            .collect();
        assert_eq!(undecided, ["203.0.113.4-203.0.113.4"]);
    }

    /// A port phase standing in for a dropped liveness pass names as silent
    /// exactly the addresses it asked on every port and heard nothing from, and
    /// the report does not list them. An address with a port the phase never
    /// got to ask, and one nothing could be sent to, are not silent: each is
    /// named for what it is. A phase whose caller asked for every address as a
    /// host names none and lists them all.
    #[test]
    fn a_port_phase_standing_in_for_liveness_names_its_silent_addresses() {
        use crate::model::port::{Port, Protocol};

        let unheard = |ctx: &ScanContext, last: u8, state: PortState| {
            ctx.update_host(ip(last), |host| {
                host.add_port(Port::new(443, Protocol::Tcp, state));
            });
        };
        let fill = |ctx: &ScanContext| {
            ctx.update_host(ip(1), |host| host.set_status(HostStatus::Up));
            unheard(ctx, 2, PortState::Filtered);
            unheard(ctx, 3, PortState::Unasked);
            unheard(ctx, 4, PortState::Filtered);
            ctx.record_unroutable(ip(4));
        };
        let cfg = ZondConfig::default();
        // Every address above inside the phase's scope, so what keeps one off
        // the list is the rule under test and not the scope.
        let asked = || {
            let mut targets = IpSet::from_str("203.0.113.1-203.0.113.4").expect("a valid range");
            TargetScope::from_ip_set(&mut targets, &Exclusions::none())
        };

        let (_session, ctx) = ScanSession::new();
        let recorder = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, asked(), &cfg)
            .skipping_liveness(LivenessSkip::PortsNoDearer);
        fill(&ctx);
        let report = recorder.finish(&ctx);
        let silent: Vec<String> = report.phases()[0]
            .silent()
            .iter()
            .map(|range| format!("{}-{}", range.start_addr(), range.end_addr()))
            .collect();
        assert_eq!(silent, ["203.0.113.2-203.0.113.2"]);
        assert!(report.host(&ip(2)).is_none(), "a silent address is no host");
        assert!(report.host(&ip(1)).is_some() && report.host(&ip(3)).is_some());

        let (_session, ctx) = ScanSession::new();
        let recorder = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, asked(), &cfg)
            .skipping_liveness(LivenessSkip::AssumeUp);
        fill(&ctx);
        let report = recorder.finish(&ctx);
        assert!(report.phases()[0].silent().is_empty());
        assert!(
            report.host(&ip(2)).is_some(),
            "a caller who asked for every address as a host gets this one"
        );
    }

    /// Silence is a discovery phase's evidence and nobody else's. A port phase
    /// names no address undecided, and silence a context heard in one phase is
    /// not carried into the next one's verdicts.
    #[test]
    fn only_a_discovery_phase_names_undecided_addresses_and_silence_does_not_carry() {
        use crate::journal::settle::Settled;

        let cfg = ZondConfig::default();
        let (_session, ctx) = ScanSession::new();

        let ports = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, scope(), &cfg);
        ctx.settle_address(ip(1), Settled::Exhausted);
        assert!(ports.finish(&ctx).phases()[0].undecided().is_empty());

        let sweep = PhaseRecorder::start(ScanKind::Discovery, Privilege::Connect, scope(), &cfg);
        assert_eq!(
            sweep.finish(&ctx).phases()[0].undecided().len(),
            1,
            "the port phase took the silence it was handed, so the sweep decided nothing"
        );
    }
}
