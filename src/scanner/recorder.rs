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
use crate::model::ip::range::IpRange;
use crate::model::ip::set::IpSet;
use crate::report::{
    LivenessSkip, PhaseParts, ScanKind, ScanPhase, ScanReport, ScanSettings, StopReason,
    TargetScope,
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
    opened: Opened,
}

/// What a phase is from the moment it opens: what it was asked to cover, under
/// what, with which sockets, and when it began.
///
/// Apart from [`PhaseRecorder`] so a journal can hold a copy while the phase
/// runs. A sitting killed outright never closes its phase, and this is what
/// its journal can still say of it; see [`Opened::standing`].
#[derive(Debug, Clone)]
pub(crate) struct Opened {
    kind: ScanKind,
    started_at: SystemTime,
    started: Instant,
    privilege: Privilege,
    targets: TargetScope,
    settings: ScanSettings,
    liveness_skipped: Option<LivenessSkip>,
}

impl Opened {
    /// The phase as it stands: what it opened with, how long it has run, and
    /// `failures`, the failures filed since it opened.
    ///
    /// What only its close can establish is left empty: the addresses it
    /// reached no verdict on, heard nothing from or left early, what it never
    /// reached, and its strategies' statistics. A record of a phase that never
    /// closed claims none of those rather than guessing at them, and none of
    /// them settles anything a resume would skip. Nor does it say it was
    /// stopped, since nothing stopped it that it could name.
    #[cfg(feature = "journal-format")]
    pub(crate) fn standing(&self, failures: Vec<crate::report::ScannerFailure>) -> ScanPhase {
        ScanPhase::from_parts(PhaseParts {
            kind: self.kind,
            started_at: self.started_at,
            elapsed: self.started.elapsed(),
            privilege: Some(self.privilege),
            targets: self.targets.clone(),
            settings: self.settings.clone(),
            failures,
            refusals: Vec::new(),
            unroutable: Vec::new(),
            timed_out: Vec::new(),
            icmp_rate_limited: Vec::new(),
            reached_by_connect: Vec::new(),
            undecided: Vec::new(),
            liveness_skipped: self.liveness_skipped,
            silent: Vec::new(),
            stopped: None,
            unreached: 0,
            unheard_probes: 0,
            probes: Vec::new(),
            origin: None,
            attachments: Vec::new(),
        })
    }
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
            opened: Opened {
                kind,
                started_at: SystemTime::now(),
                started: Instant::now(),
                privilege,
                targets,
                settings: ScanSettings::from(cfg),
                liveness_skipped: None,
            },
        }
    }

    /// Tells `ctx` this phase is open, so a journal checkpointing the scan
    /// can write down what the phase is before it closes. See
    /// [`Opened::standing`].
    ///
    /// Called once the phase is fully described, after
    /// [`skipping_liveness`](Self::skipping_liveness) where that applies.
    pub(crate) fn opening_in(self, ctx: &ScanContext) -> Self {
        ctx.open_phase(self.opened.clone());
        self
    }

    /// Records that this port phase runs with no liveness pass in front of it,
    /// and why.
    ///
    /// For a caller orchestrating a port scan who skipped the pass, so the
    /// record says so rather than leaving a reader to infer it from the missing
    /// discovery phase. See [`ScanPhase::liveness_skipped`].
    #[must_use]
    pub fn skipping_liveness(mut self, why: LivenessSkip) -> Self {
        self.opened.liveness_skipped = Some(why);
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
        let mut targets = self.opened.targets;
        targets.record_sweeps(ctx.take_swept_links());
        targets.record_withheld_machines(ctx.withheld_by_hardware());

        let unroutable = ctx.take_unroutable();
        // Taken whatever the kind, so a context reused for another phase starts
        // with no silence it did not hear.
        let heard_nothing = ctx.take_silent();
        // A port phase names what it filed only where its probes stood in for
        // a liveness pass the engine dropped: there an address they drew
        // nothing from is what the pass would have found silent. See
        // `ScanPhase::silent`.
        let silent = match (self.opened.kind, self.opened.liveness_skipped) {
            (ScanKind::PortScan, Some(LivenessSkip::PortsNoDearer)) => ranges_of(&heard_nothing),
            _ => Vec::new(),
        };
        // Taken whatever the kind, for the same reason. What a port phase
        // standing in for a liveness pass heard nothing from and did not
        // finish asking is what the pass leaves undecided; see
        // `ScanContext::forget_undecided`.
        let unfinished = ctx.take_undecided();
        // Taken whatever the kind, for the same reason, and kept where the
        // two lists above are: the ports asked at the addresses they name.
        let unheard_probes = ctx.take_unheard_probes();
        let liveness =
            (self.opened.kind == ScanKind::Discovery).then(|| Liveness::found(ctx, heard_nothing));
        let undecided = match (&liveness, self.opened.kind, self.opened.liveness_skipped) {
            (Some(liveness), _, _) => liveness.undecided(&targets, &unroutable),
            (None, ScanKind::PortScan, Some(LivenessSkip::PortsNoDearer)) => ranges_of(&unfinished),
            _ => Vec::new(),
        };

        let phase = ScanPhase::from_parts(PhaseParts {
            kind: self.opened.kind,
            started_at: self.opened.started_at,
            // Monotonic rather than the difference between two wall-clock
            // readings, which a clock correction mid-sweep would distort.
            elapsed: self.opened.started.elapsed(),
            privilege: Some(self.opened.privilege),
            targets,
            settings: self.opened.settings,
            failures: ctx.take_failures(),
            refusals: ctx.take_refusals(),
            unroutable,
            timed_out: ctx.take_timed_out(),
            icmp_rate_limited: ctx.take_icmp_rate_limited(),
            // Taken whatever the privilege, so a context reused for another
            // phase starts empty, and kept only for a raw phase: one at
            // `Connect` reached everything this way, and its privilege says so.
            reached_by_connect: match self.opened.privilege {
                Privilege::Raw => ctx.take_reached_by_connect(),
                Privilege::Connect => {
                    let _ = ctx.take_reached_by_connect();
                    Vec::new()
                }
            },
            undecided,
            liveness_skipped: self.opened.liveness_skipped,
            silent,
            // A watch runs until it is stopped, so that is its end rather than
            // anything that cut it short.
            stopped: match self.opened.kind {
                ScanKind::Listen => None,
                _ => ctx.handle.stopped().map(StopReason::from),
            },
            // Taken whatever the kind, so a context reused for another phase
            // starts from nothing.
            unreached: u128::from(ctx.take_unreached()),
            unheard_probes: match (self.opened.kind, self.opened.liveness_skipped) {
                (ScanKind::PortScan, Some(LivenessSkip::PortsNoDearer)) => {
                    u128::from(unheard_probes)
                }
                _ => 0,
            },
            probes: ctx.take_probe_stats(),
            origin: None,
            attachments: ctx.take_attachments(),
        });

        ctx.close_phase(&phase);

        // Copied rather than taken: the store is shared with the `ScanSession`
        // the caller kept, which goes on answering after this returns.
        let hosts = ctx.store.iter().map(|entry| entry.value().clone());
        (ScanReport::new(phase, hosts), liveness)
    }
}

/// `set` as the ranges a phase records, IPv4 first.
fn ranges_of(set: &IpSet) -> Vec<IpRange> {
    let v4 = set.v4().iter().copied().map(IpRange::V4);
    let v6 = set.v6().iter().copied().map(IpRange::V6);
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

    /// A port phase standing in for a dropped liveness pass names the
    /// addresses filed silent during it, and the report lists no host there. A
    /// phase whose caller asked for every address as a host names none: it
    /// files no silence, and silence filed anyway is not its to name.
    #[test]
    fn a_port_phase_standing_in_for_liveness_names_what_was_filed_silent() {
        use crate::model::ip::scoped::ScopedIp;

        let cfg = ZondConfig::default();

        let (session, ctx) = ScanSession::new();
        let recorder = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, scope(), &cfg)
            .skipping_liveness(LivenessSkip::PortsNoDearer);
        ctx.update_host(ip(1), |host| host.set_status(HostStatus::Up));
        ctx.update_host(ip(2), |_| {});
        ctx.forget_silent(vec![ScopedIp::from(ip(2))]);
        let report = recorder.finish(&ctx);

        let silent: Vec<String> = report.phases()[0]
            .silent()
            .iter()
            .map(|range| format!("{}-{}", range.start_addr(), range.end_addr()))
            .collect();
        assert_eq!(silent, ["203.0.113.2-203.0.113.2"]);
        assert!(report.host(&ip(2)).is_none(), "a silent address is no host");
        assert!(
            !session.hosts().contains(ip(2)),
            "and the live store agrees with the report"
        );
        assert!(report.host(&ip(1)).is_some());

        let (_session, ctx) = ScanSession::new();
        let recorder = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, scope(), &cfg)
            .skipping_liveness(LivenessSkip::AssumeUp);
        ctx.settle_address(ip(2), crate::journal::settle::Settled::Exhausted);
        assert!(recorder.finish(&ctx).phases()[0].silent().is_empty());
    }

    /// A port phase standing in for a dropped liveness pass names as undecided
    /// the addresses filed so during it, heard nothing from and not asked in
    /// full, and the report lists no host there, as the pass it stood in for
    /// would have listed none. A phase that did not stand in for one names
    /// none, and the filing is not carried into the next phase.
    #[test]
    fn a_port_phase_standing_in_for_liveness_names_what_it_left_undecided() {
        use crate::model::ip::scoped::ScopedIp;

        let cfg = ZondConfig::default();
        let (session, ctx) = ScanSession::new();
        let recorder = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, scope(), &cfg)
            .skipping_liveness(LivenessSkip::PortsNoDearer);
        ctx.update_host(ip(1), |host| host.set_status(HostStatus::Up));
        ctx.update_host(ip(3), |_| {});
        ctx.forget_undecided(vec![ScopedIp::from(ip(3))]);
        let report = recorder.finish(&ctx);

        let undecided: Vec<String> = report.phases()[0]
            .undecided()
            .iter()
            .map(|range| format!("{}-{}", range.start_addr(), range.end_addr()))
            .collect();
        assert_eq!(undecided, ["203.0.113.3-203.0.113.3"]);
        assert!(
            report.host(&ip(3)).is_none(),
            "an undecided address is no host"
        );
        assert!(!session.hosts().contains(ip(3)));
        assert!(report.host(&ip(1)).is_some());
        assert!(report.is_partial(), "and the report says it left one open");

        let (_session, ctx) = ScanSession::new();
        let ports = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, scope(), &cfg)
            .skipping_liveness(LivenessSkip::AssumeUp);
        ctx.forget_undecided(vec![ScopedIp::from(ip(3))]);
        assert!(ports.finish(&ctx).phases()[0].undecided().is_empty());
        let next = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, scope(), &cfg)
            .skipping_liveness(LivenessSkip::PortsNoDearer);
        assert!(next.finish(&ctx).phases()[0].undecided().is_empty());
    }

    /// **A port phase standing in for a liveness pass counts the ports it
    /// asked at the addresses it lists no host at.** Their records are
    /// dropped, so those ports are on no host, and a phase given differing
    /// ports for different addresses cannot say from its scope what any one
    /// of them was asked: without the count, a scan's tally of what it probed
    /// comes up short by every probe it spent on silence. Every port of a
    /// silent address counts, and only the ports reached of an undecided one.
    #[test]
    fn a_port_phase_standing_in_for_liveness_counts_what_it_asked_where_it_heard_nothing() {
        use crate::model::ip::scoped::ScopedIp;
        use crate::model::port::{Port, PortState, Protocol};

        let cfg = ZondConfig::default();
        let (_session, ctx) = ScanSession::new();
        let recorder = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, scope(), &cfg)
            .skipping_liveness(LivenessSkip::PortsNoDearer);
        let file = |ctx: &ScanContext, at: u8, ports: &[(u16, PortState)]| {
            ctx.update_host(ip(at), |host| {
                for &(port, state) in ports {
                    host.add_port(Port::new(port, Protocol::Tcp, state));
                }
            });
        };
        ctx.update_host(ip(1), |host| host.set_status(HostStatus::Up));
        file(
            &ctx,
            2,
            &[
                (22, PortState::Filtered),
                (80, PortState::Filtered),
                (443, PortState::Filtered),
            ],
        );
        file(
            &ctx,
            3,
            &[(22, PortState::Filtered), (80, PortState::Unasked)],
        );
        ctx.forget_silent(vec![ScopedIp::from(ip(2))]);
        ctx.forget_undecided(vec![ScopedIp::from(ip(3))]);

        assert_eq!(recorder.finish(&ctx).phases()[0].unheard_probes(), 4);

        let (_session, ctx) = ScanSession::new();
        let recorder = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, scope(), &cfg)
            .skipping_liveness(LivenessSkip::AssumeUp);
        file(&ctx, 2, &[(22, PortState::Filtered)]);
        ctx.forget_silent(vec![ScopedIp::from(ip(2))]);
        assert_eq!(
            recorder.finish(&ctx).phases()[0].unheard_probes(),
            0,
            "a phase that stood in for nothing names no silence to count"
        );
    }

    /// **The ports an undecided address was left unasked are counted with the
    /// targets the phase never reached.** Its record is dropped, so they are
    /// on no host as unasked, and a scan stopped part way through a range
    /// said how many ports it probed and nothing of the rest: `150 probed` of
    /// three thousand, and no count to add up to the plan.
    #[test]
    fn a_port_phase_counts_the_ports_it_left_unasked_where_it_heard_nothing() {
        use crate::model::ip::scoped::ScopedIp;
        use crate::model::port::{Port, PortState, Protocol};

        let cfg = ZondConfig::default();
        let (_session, ctx) = ScanSession::new();
        let recorder = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, scope(), &cfg)
            .skipping_liveness(LivenessSkip::PortsNoDearer);
        ctx.update_host(ip(3), |host| {
            host.add_port(Port::new(22, Protocol::Tcp, PortState::Filtered));
            host.add_port(Port::new(80, Protocol::Tcp, PortState::Unasked));
            host.add_port(Port::new(443, Protocol::Tcp, PortState::Unasked));
        });
        ctx.record_unreached(5);
        ctx.forget_undecided(vec![ScopedIp::from(ip(3))]);

        let report = recorder.finish(&ctx);
        let phase = &report.phases()[0];
        assert_eq!(phase.unheard_probes(), 1);
        assert_eq!(
            phase.unreached(),
            5 + 2,
            "the walk's five and the two left unasked"
        );
    }

    /// Silence is a discovery phase's evidence and nobody else's. A port phase
    /// that did not stand in for one names no address undecided, and silence a
    /// context heard in one phase is not carried into the next one's verdicts.
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
