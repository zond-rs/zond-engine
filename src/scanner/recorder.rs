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
use crate::report::{PhaseParts, ScanKind, ScanPhase, ScanReport, ScanSettings, TargetScope};
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
/// # Building a report from your own orchestration
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
/// let mut targets = to_set(&["192.168.1.0/24"], None, None)?;
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
        }
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
    pub fn finish(self, ctx: &ScanContext) -> ScanReport {
        // Which links the strategies reached is only knowable now: the scope was
        // fixed before the first probe went out, and a sweep of a segment covers
        // ground no target set named.
        let mut targets = self.targets;
        targets.record_sweeps(ctx.take_swept_links());

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
            unroutable: ctx.take_unroutable(),
            probes: ctx.take_probe_stats(),
            origin: None,
            attachments: ctx.take_attachments(),
        });

        // Copied rather than taken: the store is shared with the `ScanSession`
        // the caller kept, which goes on answering after this returns.
        let hosts = ctx.store.iter().map(|entry| entry.value().clone());
        ScanReport::new(phase, hosts)
    }
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
        let mut targets = IpSet::from_str("192.168.0.1-192.168.0.2").expect("a valid range");
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
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, last))
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

        let mut targets = IpSet::from_str("192.168.0.1-192.168.0.2").expect("a valid range");
        let scope = TargetScope::from_ip_set(&mut targets, &Exclusions::none());
        let recorder = PhaseRecorder::start(ScanKind::Discovery, Privilege::Connect, scope, &cfg);

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

        let mut targets = IpSet::from_str("192.168.0.1-192.168.0.4").expect("a valid range");
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
}
