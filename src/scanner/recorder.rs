// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Turning a running scan into the record it leaves behind
//!
//! [`crate::report`] holds the vocabulary a finished scan is described in. This
//! module is the part that needs a running scan: it opens when a phase starts,
//! holds what was asked for, and reads the findings out of a live
//! [`ScanContext`] when the phase ends.

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use crate::config::ZondConfig;
use crate::model::host::Host;
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
/// Scope and settings are only knowable before the scan starts (the target set
/// moves into the strategies), duration and failures only after it ends. This
/// holds the first until the second is available, so both land in one
/// [`ScanPhase`].
///
/// # Building a report from a caller's own orchestration
///
/// [`discover`](crate::scanner::discover) and [`scan`](crate::scanner::scan) use
/// this internally. A caller running strategies itself uses it to produce the
/// same [`ScanReport`], which an [`Exporter`](crate::export::Exporter) can then
/// write.
///
/// Start it before the scan, hand it the context afterwards:
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
/// // The exclusions go to the context as well as the targets, since a segment
/// // sweep reaches beyond the target list; see `Exclusions`.
/// let (session, ctx) = ScanSession::builder().excluding(cfg.exclusions.clone()).build();
///
/// // Record the scope before the targets move into a strategy. `targets` comes
/// // back narrowed by the exclusions, and the scope records what was removed.
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
/// Separate from [`PhaseRecorder`] so a journal can hold a copy while the phase
/// runs, for a sitting killed before it closes; see [`Opened::standing`].
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
    /// What only the close can establish is left empty: addresses left early,
    /// targets never reached, strategy statistics, and any stop. The phase is
    /// marked open instead, and a sitting that ends replaces it with the closed
    /// phase; see [`ScanPhase::is_open`].
    ///
    /// The exception is what a port phase standing in for a liveness pass has
    /// concluded so far (`so_far`; see
    /// [`ScanProgress::verdicts_so_far`](crate::scanner::session::ScanProgress::verdicts_so_far)).
    /// Addresses silent on every target they owe are named silent with their
    /// probe count, because their targets are settled and a resume skips them.
    /// Other awaiting records are named undecided, so the job's report makes no
    /// host of them.
    #[cfg(feature = "journal-format")]
    pub(crate) fn standing(
        &self,
        failures: Vec<crate::report::ScannerFailure>,
        so_far: &crate::scanner::session::SoFar,
    ) -> ScanPhase {
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
            refused_by_route: Vec::new(),
            timed_out: Vec::new(),
            icmp_rate_limited: Vec::new(),
            reached_by_connect: Vec::new(),
            undecided: crate::scanner::session::ranges_of(&so_far.awaiting),
            liveness_skipped: self.liveness_skipped,
            silent: so_far.silent.clone(),
            stopped: None,
            passes_cut: Vec::new(),
            unreached: 0,
            unheard_probes: u128::from(so_far.unheard_probes),
            probes: Vec::new(),
            origin: None,
            attachments: Vec::new(),
            open: true,
        })
    }
}

impl PhaseRecorder {
    /// Opens a phase record, taking the clock readings that bound it.
    ///
    /// Call this before the scan starts. `targets` is the scope the phase was
    /// asked to cover; `privilege` is which sockets the strategies hold.
    ///
    /// The wall clock records when the scan happened and the monotonic clock how
    /// long it took, so a clock correction mid-sweep cannot distort the duration.
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

    /// Tells `ctx` this phase is open, so a checkpointing journal can record it
    /// before it closes. See [`Opened::standing`].
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
    /// For a caller orchestrating a port scan without the pass, so the record
    /// says so explicitly. See [`ScanPhase::liveness_skipped`].
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
    /// The failures and probe statistics filed against `ctx` are taken, so a
    /// context reused for a second phase starts empty. To read them without
    /// closing a phase, use
    /// [`ScanContext::failures_snapshot`](crate::scanner::session::ScanContext::failures_snapshot)
    /// and its probe-statistics counterpart.
    ///
    /// A [`Discovery`](ScanKind::Discovery) phase also names the addresses in
    /// its scope it reached no verdict on, read off what its strategies filed:
    /// see [`ScanPhase::undecided`](crate::report::ScanPhase::undecided).
    pub fn finish(self, ctx: &ScanContext) -> ScanReport {
        self.close(ctx).0
    }

    /// [`finish`](Self::finish) for the last phase of a scan, which is handed
    /// the context to keep.
    ///
    /// The hosts are moved into the report when nothing else holds the store (no
    /// [`ScanSession`], no journal, no other part of the scan), since a
    /// full-range scan holds hundreds of megabytes of hosts. Otherwise they are
    /// copied.
    ///
    /// [`ScanSession`]: crate::scanner::session::ScanSession
    pub(crate) fn finish_last(self, ctx: ScanContext) -> ScanReport {
        let phase = self.close_phase(&ctx).0;
        let hosts: Vec<Host> = match Arc::try_unwrap(ctx.store) {
            Ok(store) => store.into_iter().map(|(_, host)| host).collect(),
            Err(shared) => shared.iter().map(|entry| entry.value().clone()).collect(),
        };
        ScanReport::new(phase, hosts)
    }

    /// [`finish`](Self::finish), handing back as well what a discovery phase
    /// established about presence, for the port phase that follows it to act
    /// on. `None` for any other kind of phase.
    ///
    /// One reading serves both, so the port phase treats as found exactly the
    /// addresses the report does not name as undecided.
    pub(super) fn close(self, ctx: &ScanContext) -> (ScanReport, Option<Liveness>) {
        let (phase, liveness) = self.close_phase(ctx);
        // Copied: the caller's `ScanSession` shares the store and keeps reading
        // it.
        let hosts = ctx.store.iter().map(|entry| entry.value().clone());
        (ScanReport::new(phase, hosts), liveness)
    }

    /// The phase this recorder describes, closed against what `ctx` holds,
    /// and what a discovery phase established about presence.
    fn close_phase(self, ctx: &ScanContext) -> (ScanPhase, Option<Liveness>) {
        // Which links were swept is only known now; a segment sweep covers
        // ground no target set named.
        let mut targets = self.opened.targets;
        targets.record_sweeps(ctx.take_swept_links());
        targets.record_withheld(ctx.withheld_by_hardware(), ctx.take_withheld_neighbours());

        let unroutable = ctx.take_unroutable();
        // Only addresses the phase actually filed as unroutable.
        let refused_by_route: Vec<std::net::IpAddr> = ctx
            .take_refused_by_route()
            .into_iter()
            .filter(|address| unroutable.binary_search(address).is_ok())
            .collect();
        // The `take_*` calls below drain the context whatever the phase kind,
        // so a context reused for another phase starts empty.
        let heard_nothing = ctx.take_silent();
        // A port phase names silent addresses only where it stood in for a
        // dropped liveness pass. See `ScanPhase::silent`.
        let silent = match (self.opened.kind, self.opened.liveness_skipped) {
            (ScanKind::PortScan, Some(LivenessSkip::PortsNoDearer)) => ranges_of(&heard_nothing),
            _ => Vec::new(),
        };
        // See `ScanContext::forget_undecided`.
        let unfinished = ctx.take_undecided();
        // The ports asked at the addresses in the two lists above.
        let unheard_probes = ctx.take_unheard_probes();
        let liveness =
            (self.opened.kind == ScanKind::Discovery).then(|| Liveness::found(ctx, heard_nothing));
        let undecided = match (&liveness, self.opened.kind, self.opened.liveness_skipped) {
            (Some(liveness), _, _) => liveness.undecided(&targets, &unroutable),
            (None, ScanKind::PortScan, Some(LivenessSkip::PortsNoDearer)) => ranges_of(&unfinished),
            _ => Vec::new(),
        };

        // Kept only for a raw phase; a `Connect` phase reached everything this
        // way, and its privilege says so.
        let reached_by_connect = match self.opened.privilege {
            Privilege::Raw => ctx.take_reached_by_connect(&unroutable),
            Privilege::Connect => {
                let _ = ctx.take_reached_by_connect(&[]);
                Vec::new()
            }
        };

        let phase = ScanPhase::from_parts(PhaseParts {
            kind: self.opened.kind,
            started_at: self.opened.started_at,
            elapsed: self.opened.started.elapsed(),
            privilege: Some(self.opened.privilege),
            targets,
            settings: self.opened.settings,
            failures: ctx.take_failures(),
            refusals: ctx.take_refusals(),
            unroutable,
            refused_by_route,
            timed_out: ctx.take_timed_out(),
            icmp_rate_limited: ctx.take_icmp_rate_limited(),
            reached_by_connect,
            undecided,
            liveness_skipped: self.opened.liveness_skipped,
            silent,
            // A watch runs until stopped, so a stop is its normal end.
            stopped: match self.opened.kind {
                ScanKind::Listen => None,
                _ => ctx.handle.stopped().map(StopReason::from),
            },
            passes_cut: ctx.take_passes_cut(),
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
            open: false,
        });

        ctx.close_phase(&phase);
        (phase, liveness)
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

    /// A scope over two addresses.
    fn scope() -> TargetScope {
        let mut targets = IpSet::from_str("203.0.113.1-203.0.113.2").expect("a valid range");
        TargetScope::from_ip_set(&mut targets, &Exclusions::none())
    }

    /// A refusal and a failure both say what the scan did not cover, but only a
    /// failure says something went wrong, so they are reported separately.
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

    /// A context reused for a second phase does not hand the same refusal to two
    /// reports.
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

    /// The last phase moves the hosts into the report when nothing else holds
    /// the store, and copies them when a session still reads it. The address of
    /// the host name's allocation tells a move from a copy.
    #[test]
    fn the_last_phase_moves_the_hosts_unless_a_session_still_reads_them() {
        let cfg = ZondConfig::default();
        let name_at = |host: &Host| host.hostname().expect("a name").as_ptr();
        let seeded = |ctx: &ScanContext| {
            let mut host = Host::new(ip(7));
            host.set_status(crate::model::host::HostStatus::Up);
            host.set_hostname(Some("gateway.example".to_string()));
            let name = name_at(&host);
            ctx.store.insert(ip(7).into(), host);
            name
        };

        let (session, ctx) = ScanSession::new();
        let name = seeded(&ctx);
        drop(session);
        let report = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, scope(), &cfg)
            .finish_last(ctx);
        let host = report.hosts().next().expect("the host is reported");
        assert_eq!(name_at(host), name, "moved, not copied");

        let (session, ctx) = ScanSession::new();
        let name = seeded(&ctx);
        let report = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, scope(), &cfg)
            .finish_last(ctx);
        let host = report.hosts().next().expect("the host is reported");
        assert_ne!(name_at(host), name, "copied for the session that reads it");
        assert!(
            session.hosts().contains(ip(7)),
            "and the session goes on answering"
        );
    }

    /// Filed once per distinct reason, such as the same range declined on two
    /// links.
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

    /// An address with no route is recorded without making the scan partial. A
    /// dual-stack name on an IPv4-only network resolves to such an address.
    #[test]
    fn an_unroutable_address_is_recorded_without_making_the_scan_partial() {
        let cfg = ZondConfig::default();
        let (_session, ctx) = crate::scanner::session::ScanSession::new();

        let mut targets = IpSet::from_str("203.0.113.1-203.0.113.2").expect("a valid range");
        let scope = TargetScope::from_ip_set(&mut targets, &Exclusions::none());
        let recorder = PhaseRecorder::start(ScanKind::Discovery, Privilege::Connect, scope, &cfg);

        // Both addresses in scope settled, so only the unroutable one could
        // make this phase partial.
        for address in [ip(1), ip(2)] {
            ctx.settle_address(address, crate::journal::settle::Settled::Exhausted);
        }
        let unreachable: IpAddr = "2001:db8::1".parse().expect("literal");
        ctx.record_unroutable(unreachable);
        // Twice, as two probes to one address would; recorded once.
        ctx.record_unroutable(unreachable);

        let report = recorder.finish(&ctx);

        assert_eq!(report.phases()[0].unroutable(), [unreachable]);
        assert!(
            !report.is_partial(),
            "no strategy failed; that address is simply not reachable from here"
        );
        assert_eq!(report.failures().count(), 0);
    }

    /// An unroutable address this machine's routing table refuses is also named
    /// as refused by a route, since the remedy is local. A refusal noted for an
    /// address the phase did not file as unroutable is not named.
    #[test]
    fn an_address_a_route_refuses_is_named_among_the_unreachable() {
        let cfg = ZondConfig::default();
        let (_session, ctx) = crate::scanner::session::ScanSession::new();
        let mut targets = IpSet::from_str("203.0.113.1-203.0.113.3").expect("a valid range");
        let scope = TargetScope::from_ip_set(&mut targets, &Exclusions::none());
        let recorder = PhaseRecorder::start(ScanKind::Discovery, Privilege::Raw, scope, &cfg);

        ctx.note_refused_by_route(ip(1));
        ctx.record_unroutable(ip(1));
        ctx.record_unroutable(ip(2));
        ctx.note_refused_by_route(ip(3));
        ctx.settle_address(ip(3), crate::journal::settle::Settled::Exhausted);

        let report = recorder.finish(&ctx);
        let phase = &report.phases()[0];

        assert_eq!(phase.unroutable(), [ip(1), ip(2)]);
        assert_eq!(phase.refused_by_route(), [ip(1)]);
        assert!(!report.is_partial());
    }

    /// An address the connect step could not reach because a local route
    /// refused it is named unreachable and not also reached by connect.
    #[test]
    fn an_address_a_connect_step_could_not_reach_is_not_named_reached_by_it() {
        let cfg = ZondConfig::default();
        let (_session, ctx) = ScanSession::new();
        let mut targets = IpSet::from_str("203.0.113.1-203.0.113.3").expect("a valid range");
        let scope = TargetScope::from_ip_set(&mut targets, &Exclusions::none());
        let recorder = PhaseRecorder::start(ScanKind::Discovery, Privilege::Raw, scope, &cfg);

        let mut handed = IpSet::new();
        handed.insert_range(IpRange::V4(
            crate::model::ip::range::Ipv4Range::new(
                std::net::Ipv4Addr::new(203, 0, 113, 1),
                std::net::Ipv4Addr::new(203, 0, 113, 3),
            )
            .expect("ordered"),
        ));
        ctx.record_reached_by_connect(&handed);
        ctx.note_refused_by_route(ip(2));
        ctx.record_unroutable(ip(2));

        let report = recorder.finish(&ctx);
        let phase = &report.phases()[0];
        assert_eq!(phase.unroutable(), [ip(2)]);
        assert_eq!(phase.refused_by_route(), [ip(2)]);
        let reached: Vec<String> = phase
            .reached_by_connect()
            .iter()
            .map(|range| format!("{}-{}", range.start_addr(), range.end_addr()))
            .collect();
        assert_eq!(
            reached,
            ["203.0.113.1-203.0.113.1", "203.0.113.3-203.0.113.3"]
        );
    }

    /// A caller running strategies itself can produce the engine's report. No
    /// strategies run; the test checks that the pieces are reachable and meet.
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

    /// Counters filed mid-scan reach the phase that was running, and only it.
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
            refusals_unattributed: 0,
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

        // Drained, so a second phase does not inherit them.
        assert!(ctx.take_probe_stats().is_empty());
    }

    /// A raw phase that reached some addresses by connect lists them, merged; a
    /// connect phase lists none. Both drain the log.
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

    /// A discovery phase names every address it reached no verdict on, and only
    /// those. Answered and exhausted addresses have a verdict, an unroutable one
    /// is named elsewhere, and the fourth was never settled.
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

    /// A port phase standing in for a dropped liveness pass names the addresses
    /// filed silent, and the report lists no host there. A phase that assumes
    /// every address up names none.
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
    /// the addresses filed so (heard nothing, not asked in full), and the report
    /// lists no host there. Any other phase names none, and the filing does not
    /// carry into the next phase.
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

    /// A port phase standing in for a liveness pass counts the ports it asked at
    /// the addresses it lists no host at, since their records are dropped. Every
    /// port of a silent address counts, and only the asked ports of an undecided
    /// one.
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
                (22, PortState::NoReply),
                (80, PortState::NoReply),
                (443, PortState::NoReply),
            ],
        );
        file(
            &ctx,
            3,
            &[(22, PortState::NoReply), (80, PortState::Unasked)],
        );
        ctx.forget_silent(vec![ScopedIp::from(ip(2))]);
        ctx.forget_undecided(vec![ScopedIp::from(ip(3))]);

        assert_eq!(recorder.finish(&ctx).phases()[0].unheard_probes(), 4);

        let (_session, ctx) = ScanSession::new();
        let recorder = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, scope(), &cfg)
            .skipping_liveness(LivenessSkip::AssumeUp);
        file(&ctx, 2, &[(22, PortState::NoReply)]);
        ctx.forget_silent(vec![ScopedIp::from(ip(2))]);
        assert_eq!(
            recorder.finish(&ctx).phases()[0].unheard_probes(),
            0,
            "a phase that stood in for nothing names no silence to count"
        );
    }

    /// The ports an undecided address was left unasked are counted with the
    /// targets the phase never reached, since its record is dropped.
    #[test]
    fn a_port_phase_counts_the_ports_it_left_unasked_where_it_heard_nothing() {
        use crate::model::ip::scoped::ScopedIp;
        use crate::model::port::{Port, PortState, Protocol};

        let cfg = ZondConfig::default();
        let (_session, ctx) = ScanSession::new();
        let recorder = PhaseRecorder::start(ScanKind::PortScan, Privilege::Connect, scope(), &cfg)
            .skipping_liveness(LivenessSkip::PortsNoDearer);
        ctx.update_host(ip(3), |host| {
            host.add_port(Port::new(22, Protocol::Tcp, PortState::NoReply));
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

    /// Only a discovery phase (or a port phase standing in for one) names
    /// undecided addresses, and silence heard in one phase does not carry into
    /// the next.
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
