// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A scan while it is running
//!
//! The live half of what a scan produces. [`ScanReport`](crate::report) is the
//! record afterwards; everything here describes the present moment and keeps no
//! history.
//!
//! It comes in two halves that share one store, handed out by
//! [`ScanSession::new`]:
//!
//! - [`ScanSession`] is the reading half, for whoever asked for the scan: the
//!   hosts found so far ([`HostStore`]), the stream saying when that changed
//!   ([`ScanEvents`]), and the means to stop
//!   ([`ScanHandle`]).
//! - [`ScanContext`] is the writing half, for the strategies. Every scanner is
//!   built with one, and it is how findings, failures and probe counters enter
//!   the scan.
//!
//! ## Why the writing half is not just the map
//!
//! [`ScanContext::write_host`] is the single door a host finding goes through,
//! and that is what lets the ordering it depends on be written once. It takes
//! the store's guard, runs the caller's edit under it, drops the guard, and
//! only then announces the change, so the map is never locked across a channel
//! send. Handing a strategy the raw map instead would hand it that ordering to
//! get wrong, and would make the version of a third-party concurrency crate
//! part of this crate's semver.
//!
//! ## What a host is keyed by
//!
//! By the address it is reported under, carrying the interface that address was
//! read on where it needs one: a [`ScopedIp`]. For every IPv4 address and every
//! routable IPv6 one that is the bare address and nothing more, because a
//! machine reachable at a global address is the same machine through whichever
//! interface answered it.
//!
//! An IPv6 link-local is the exception, and it is why the key exists.
//! `fe80::1` names a different machine on every segment, so a host watching two
//! of them finds two neighbours under one number. Keyed by the bare address, the
//! second write would land on the first's entry, and one machine's hardware
//! address, roles and round trips would be folded into another machine's record.
//!
//! Three rules follow, and between them they are the whole of it:
//!
//! - **A host takes its link from its key.** [`ScanContext::write_host`] records
//!   the zone when it creates a host, so no scanner has to remember to.
//! - **A key read from the store writes back to the store.**
//!   [`ScanContext::host_addresses`] hands out keys, and a strategy that reads a
//!   host and writes a finding back carries the key rather than rebuilding one
//!   from the address it probed. A bare address written back would land in a
//!   second entry, and one host would become two, each holding half of what was
//!   found.
//! - **A bare link-local finds nothing.** [`HostStore::get`] answers `None` for
//!   one, because it is a question with more than one answer. Consumers get the
//!   whole key from [`ScanEvent::HostUpdated`], which is the path that matters:
//!   the event exists to be handed straight back to the store.
//!
//! ## Why a failure is written down twice
//!
//! Once to the event stream, for a consumer watching, and once to a log the
//! report drains at the end. An event nobody listens for is an event that never
//! happened: a caller that simply awaits the scan and reads the hosts would
//! otherwise have no way to learn that a strategy died, and "the network is
//! empty" and "the raw scanner never started" would be the same answer.

use dashmap::DashMap;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tracing::error;

use crate::config::ServiceDetection;
use crate::detect::compute::DetectionRunRecord;
use crate::info;
use crate::journal::settle::{Outcome, Settled, Settlements};
use crate::model::exclusion::Exclusions;
use crate::model::host::Host;
use crate::model::ip::range::IpRange;
use crate::model::ip::scoped::{ScopedIp, Zone, ZoneMap};
use crate::model::ip::set::{IpSet, Positions};
use crate::model::mac::MacAddr;
use crate::model::port::{PortState, Protocol};
use crate::report::ScannerKind;
use crate::report::{Attachment, AttachmentSource, ProbeStats, Refusal, ScannerFailure};
use crate::scanner::handle::ScanHandle;

/// What a scan is working on.
///
/// A scan is not one uniform stretch of work. The sweep settles its plan, and
/// then a tail of quite different jobs runs over what it found: identifying the
/// services behind the open ports, running detections against those services,
/// reading a stack for an operating system, tracing a path. The tail routinely
/// takes several times as long as the sweep did, so a caller measuring the plan
/// alone shows a finished bar for most of a run.
///
/// Each stage announces itself as it begins, through [`ScanEvent::StageChanged`],
/// and [`Progress::stage`] answers which one is current. Some know their own
/// size the moment they start, the set of ports they will work over having been
/// decided before any of it was probed; the rest report only that they are
/// running.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Stage {
    /// Establishing which addresses are alive. Where every scan starts.
    #[default]
    Discovery,
    /// Classifying the ports of the hosts that answered.
    Ports,
    /// Identifying what is listening behind each open port.
    Services,
    /// Running the detection corpus over the services just identified.
    Detections,
    /// Asking what each TLS port accepts.
    Tls,
    /// Reading a stack, and asking what a host says about itself.
    Os,
    /// Tracing the path to each host.
    Traceroute,
    /// Reading a link, which ends when the caller says so rather than when the
    /// work runs out.
    Listening,
    /// The correlating and record keeping left once the probing is over.
    Finishing,
}

impl Stage {
    /// Every stage this build knows, in the order a scan runs them.
    ///
    /// Here for the reason [`ScanKind::ALL`](crate::report::ScanKind::ALL)
    /// gives: the enum is `#[non_exhaustive]`, so nothing outside this crate can
    /// match it exhaustively, and a front end that maps stages onto a protocol
    /// of its own has no other way to check that it covered them all. A variant
    /// added without a place in that protocol is a value this engine reports and
    /// no consumer can name.
    pub const ALL: [Stage; 9] = [
        Self::Discovery,
        Self::Ports,
        Self::Services,
        Self::Detections,
        Self::Tls,
        Self::Os,
        Self::Traceroute,
        Self::Listening,
        Self::Finishing,
    ];

    /// Its place in the atomic the tracker keeps.
    const fn code(self) -> u8 {
        match self {
            Stage::Discovery => 0,
            Stage::Ports => 1,
            Stage::Services => 2,
            Stage::Detections => 3,
            Stage::Tls => 4,
            Stage::Os => 5,
            Stage::Traceroute => 6,
            Stage::Listening => 7,
            Stage::Finishing => 8,
        }
    }

    /// The stage `code` stands for, and [`Discovery`](Stage::Discovery) for a
    /// number no stage claims, which is where a scan begins.
    const fn from_code(code: u8) -> Self {
        match code {
            1 => Stage::Ports,
            2 => Stage::Services,
            3 => Stage::Detections,
            4 => Stage::Tls,
            5 => Stage::Os,
            6 => Stage::Traceroute,
            7 => Stage::Listening,
            8 => Stage::Finishing,
            _ => Stage::Discovery,
        }
    }
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Stage::Discovery => "discovery",
            Stage::Ports => "ports",
            Stage::Services => "services",
            Stage::Detections => "detections",
            Stage::Tls => "tls",
            Stage::Os => "os",
            Stage::Traceroute => "traceroute",
            Stage::Listening => "listening",
            Stage::Finishing => "finishing",
        };

        f.write_str(name)
    }
}

/// Which stage a scan is in and how far through it.
///
/// Three atomics rather than one lock, because this is written from every
/// probing task and read eight times a second by whatever is drawing. The three
/// are not updated as a group, so a reader can catch a stage that has just
/// changed against a count that has not caught up. That costs one frame of a
/// progress line and is the reason this is not the thing a report is built from.
#[derive(Debug, Default)]
pub(crate) struct Stages {
    current: AtomicU8,
    done: AtomicU64,
    total: AtomicU64,
    /// The stages this scan expects to run, in the order it runs them.
    planned: Vec<Stage>,
    /// How many of those are behind it, which only ever grows.
    reached: AtomicUsize,
}

impl Stages {
    fn new(planned: Vec<Stage>) -> Self {
        Self {
            planned,
            ..Self::default()
        }
    }

    /// Where the scan stands across every stage it expects to run, as a
    /// position over a total.
    ///
    /// `within` is how far through the current stage it is, and the pair comes
    /// back scaled so both halves are whole numbers: a caller drawing a bar of a
    /// fixed number of cells divides in integers and gets cells and a percentage
    /// that agree.
    fn overall(&self, within: Option<(u64, u64)>) -> Option<(u64, u64)> {
        let stages = u64::try_from(self.planned.len()).ok().filter(|n| *n > 0)?;
        let reached = u64::try_from(self.reached.load(Ordering::Relaxed)).unwrap_or(0);

        // Past the last stage the scan expected: whatever it is doing now, the
        // work it was counting is behind it.
        let Some((done, total)) = within.filter(|_| self.planned.contains(&self.stage())) else {
            return Some((reached.min(stages), stages));
        };

        Some((reached * total + done.min(total), stages * total))
    }

    /// Moves to `stage`, answering whether that was a change worth announcing.
    ///
    /// Entering the stage already current adds to its total instead of starting
    /// it over, which is what service detection needs when it runs once per
    /// protocol.
    fn enter(&self, stage: Stage, total: Option<u64>) -> bool {
        let total = total.unwrap_or(0);

        // How many expected stages this one comes after, read from the order the
        // variants are declared in, which is the order a scan runs them. A stage
        // that was expected and had no work is stepped over rather than waited
        // for.
        let reached = self
            .planned
            .iter()
            .filter(|planned| planned.code() < stage.code())
            .count();
        self.reached.fetch_max(reached, Ordering::Relaxed);

        if self.current.swap(stage.code(), Ordering::Relaxed) == stage.code() {
            self.total.fetch_add(total, Ordering::Relaxed);
            return false;
        }

        self.done.store(0, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
        true
    }

    fn advance(&self) {
        self.done.fetch_add(1, Ordering::Relaxed);
    }

    fn stage(&self) -> Stage {
        Stage::from_code(self.current.load(Ordering::Relaxed))
    }

    fn done(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }

    fn total(&self) -> Option<u64> {
        match self.total.load(Ordering::Relaxed) {
            0 => None,
            total => Some(total),
        }
    }
}

/// Lightweight notifications for the status of an ongoing scan.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ScanEvent {
    /// Something was learned about the host at this address.
    ///
    /// The event carries only the address: a scan can emit
    /// thousands of these, and copying a whole [`Host`] into each one would cost
    /// more than the notification is worth. Read the current state back from
    /// [`ScanSession::hosts`], which is a single lookup and always up to date,
    /// where a host copied into an event is stale the moment the next probe
    /// answers.
    HostUpdated(ScopedIp),

    /// A scanning strategy failed to start or terminated abnormally. The scan
    /// continues with whatever strategies remain, so results may be incomplete
    /// rather than absent.
    ScannerFailed {
        /// The strategy that failed.
        scanner: ScannerKind,
        /// A human-readable description of the failure.
        reason: String,
    },

    /// The scan has moved on to another [`Stage`].
    ///
    /// A scan spends most of its time somewhere other than its plan, and this is
    /// what says where. Read [`ScanSession::progress`] for how far through the
    /// stage it is, on the same reasoning [`HostUpdated`](ScanEvent::HostUpdated)
    /// carries only an address: the figure moves far faster than the
    /// announcement does.
    StageChanged {
        /// What the scan is working on now.
        stage: Stage,
    },

    /// The stream ran ahead of this consumer, and `count` events were dropped
    /// to make room for newer ones.
    ///
    /// Delivered in the position the missing events would have had, so a
    /// consumer knows where its picture went incomplete rather than only that
    /// it did. [`ScanEvents`] says what the gap costs and what to do about it.
    EventsDropped {
        /// How many events were dropped.
        count: u64,
    },
}

/// What a scan has found so far, readable while it is still running.
///
/// A cheap, cloneable view of one shared store. Cloning it does not copy the
/// hosts; every clone reads the same live data, so a consumer can hand one to a
/// rendering task and keep another for itself.
///
/// Reads return owned snapshots. [`get`](Self::get) clones the host rather
/// than lending a reference into the map, because the alternative is a guard
/// held across whatever the caller does next, and a scanner writing to the same
/// key meanwhile is not a hypothetical, it is the normal case. A caller cannot
/// hold this wrong.
///
/// The concrete map behind it is not visible. It is an
/// implementation choice, and exposing it would make the version of a
/// third-party concurrency crate part of this crate's semver.
#[derive(Debug, Clone, Default)]
pub struct HostStore {
    inner: Arc<DashMap<ScopedIp, Host>>,
}

impl HostStore {
    fn new(inner: Arc<DashMap<ScopedIp, Host>>) -> Self {
        Self { inner }
    }

    /// The host recorded at `ip`, as it stands right now.
    ///
    /// Keyed by the address a scanner wrote it under, which for a host found at
    /// several addresses is whichever one it was first credited to. To look a
    /// host up by any of its addresses, search
    /// [`snapshot`](Self::snapshot) on [`Host::ips`].
    ///
    /// An IPv6 link-local needs the interface it was read on. `fe80::1`
    /// names a different machine on every segment, so a bare one names no host
    /// here and answers `None`; pass the [`ScopedIp`] the event carried. Every
    /// other address is its own whole key, and a plain [`IpAddr`] is accepted
    /// for exactly that reason.
    pub fn get(&self, ip: impl Into<ScopedIp>) -> Option<Host> {
        self.inner
            .get(&ip.into())
            .map(|entry| entry.value().clone())
    }

    /// Reads the host at `ip` without cloning it, if there is one.
    ///
    /// The live counterpart of [`get`](Self::get), and the one to reach for
    /// inside an event loop. A scan fires
    /// [`HostUpdated`](ScanEvent::HostUpdated) on every change, and a port scan
    /// changes a host once per port, so a consumer that answers each event with
    /// a [`get`](Self::get) clones a growing port map on every port of every
    /// host, which is quadratic in the size of the scan and invisible until the
    /// port count is large. Take what the event needs through this, and clone
    /// only once the answer is that the host is worth rendering.
    ///
    /// `read` runs under the store's own guard. It must not touch the store
    /// again, that deadlocks, and it should not block, since a scanner writing
    /// to the same host waits behind it.
    pub fn read<R>(&self, ip: impl Into<ScopedIp>, read: impl FnOnce(&Host) -> R) -> Option<R> {
        self.inner.get(&ip.into()).map(|entry| read(entry.value()))
    }

    /// Whether anything has been recorded at `ip`.
    ///
    /// Cheaper than [`get`](Self::get) when the host itself is not wanted, since
    /// nothing is cloned.
    pub fn contains(&self, ip: impl Into<ScopedIp>) -> bool {
        self.inner.contains_key(&ip.into())
    }

    /// How many hosts have been recorded.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether nothing has been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Every host recorded so far, ordered by the address each is keyed under.
    ///
    /// A point-in-time copy: the scan carries on writing, and this does not
    /// change afterwards. Ordered rather than in map order so two reads of the
    /// same data can be compared, for the reason
    /// [`ScanReport`](crate::report::ScanReport) orders its hosts.
    pub fn snapshot(&self) -> Vec<Host> {
        let mut hosts: Vec<Host> = self
            .inner
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        hosts.sort_by_cached_key(Host::scoped_ip);
        hosts
    }

    /// Puts a host in the store directly, replacing anything at that address.
    ///
    /// Test-only, and not how a scan records a finding, that is
    /// [`ScanContext::write_host`], which upserts, merges and announces the
    /// change. This exists for the tests that need a store already holding a
    /// particular host, standing in for the scanner that would have written it.
    #[cfg(test)]
    pub(crate) fn insert(&self, ip: impl Into<ScopedIp>, host: Host) {
        self.inner.insert(ip.into(), host);
    }
}

/// The live event stream of a scan.
///
/// Each event says that something changed; the detail is read back from the
/// [`HostStore`]. See [`ScanEvent`].
///
/// The stream is bounded, and the oldest events are the ones that go. It
/// holds [`CAPACITY`](Self::CAPACITY) events, and a scan that fills it
/// overwrites what has waited longest rather than growing or pausing. A caller
/// who never reads this costs the scan one fixed buffer, and a caller who reads
/// it slowly never holds the scan up.
///
/// A gap is announced where it happened. The read that follows one answers
/// [`ScanEvent::EventsDropped`], carrying how many events went missing, so a
/// consumer is never quietly out of date.
///
/// What a gap costs is the notice and not the finding. A dropped
/// [`HostUpdated`](ScanEvent::HostUpdated) named a host whose current state is
/// in the [`HostStore`], so the answer to a gap is to re-read the store rather
/// than to try to replay the stream. A dropped
/// [`ScannerFailed`](ScanEvent::ScannerFailed) still reaches the
/// [`ScanReport`](crate::report::ScanReport), which carries every failure
/// whether or not anybody was listening.
#[derive(Debug)]
pub struct ScanEvents {
    rx: broadcast::Receiver<ScanEvent>,
}

impl ScanEvents {
    /// How many events the stream holds for a consumer that has not caught up.
    ///
    /// The buffer is allocated when the scan starts, so an event stream costs
    /// the same whether or not anything reads it.
    pub const CAPACITY: usize = 1024;

    /// Waits for the next event. `None` once the scan has ended and every event
    /// it emitted has been taken, which is the definitive end of the stream.
    ///
    /// Falling behind is not an error here: a gap arrives as
    /// [`ScanEvent::EventsDropped`], in the position the missing events would
    /// have had, and the stream carries on with the oldest event it still
    /// holds.
    pub async fn recv(&mut self) -> Option<ScanEvent> {
        match self.rx.recv().await {
            Ok(event) => Some(event),
            Err(RecvError::Lagged(count)) => Some(ScanEvent::EventsDropped { count }),
            Err(RecvError::Closed) => None,
        }
    }

    /// The next event if one is already queued, without waiting.
    ///
    /// `None` covers both "nothing queued right now" and "the scan is over", so
    /// it drains a finished scan but cannot detect the end of a running one. Use
    /// [`recv`](Self::recv) for that. A gap reads the same way it does through
    /// [`recv`](Self::recv), as [`ScanEvent::EventsDropped`].
    pub fn try_recv(&mut self) -> Option<ScanEvent> {
        match self.rx.try_recv() {
            Ok(event) => Some(event),
            Err(TryRecvError::Lagged(count)) => Some(ScanEvent::EventsDropped { count }),
            Err(TryRecvError::Empty | TryRecvError::Closed) => None,
        }
    }
}

/// How far a scan has got through its plan.
///
/// A cheap, cloneable view of the counters the strategies settle their targets
/// against, so one can sit in a rendering task and be read as often as it
/// draws. A read is a pair of atomic loads and one short lock, never a walk of
/// the findings.
///
/// The two halves come from different places. [`settled`](Self::settled) counts
/// what the strategies have finished with, and it counts on every scan whether
/// or not the scan is journalled. [`planned`](Self::planned) is the size of the
/// plan, which a scan knows only where its targets can be numbered: an IPv6
/// range of a `/64` or wider cannot be, and a [`listen`](crate::listen) session
/// has no plan at all, having asked for nothing. Where the plan cannot be
/// counted, [`fraction`](Self::fraction) answers `None`, and a front end has a
/// running count to show in place of a bar.
///
/// A scan that runs to the end settles every target in its plan and the
/// fraction reaches 1.0. One stopped early leaves it short, which is the
/// accurate account of how much ground the run covered.
///
/// ```no_run
/// # fn example(session: &zond_engine::ScanSession) {
/// let progress = session.progress();
/// match progress.planned() {
///     Some(planned) => println!("{} of {planned} targets", progress.settled()),
///     None => println!("{} targets settled", progress.settled()),
/// }
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Progress {
    settlements: Arc<Settlements>,
    planned: Option<u64>,
    plan_stage: Stage,
    stages: Arc<Stages>,
}

impl Progress {
    fn new(
        settlements: Arc<Settlements>,
        planned: Option<u64>,
        plan_stage: Stage,
        stages: Arc<Stages>,
    ) -> Self {
        Self {
            settlements,
            planned,
            plan_stage,
            stages,
        }
    }

    /// What the scan is working on right now.
    pub fn stage(&self) -> Stage {
        self.stages.stage()
    }

    /// How many units of the current stage are finished.
    ///
    /// The unit is the stage's own: ports for [`Stage::Services`], detection
    /// runs for [`Stage::Detections`], TLS ports for [`Stage::Tls`]. Zero for a
    /// stage that does not count itself.
    ///
    /// A unit is counted once the stage is done with it, whatever it came to.
    /// One passed over before it began, because its host had spent its budget
    /// or the scan was stopped, is not, so a stage can end short of its total,
    /// and the shortfall is what it never asked.
    pub fn stage_done(&self) -> u64 {
        self.stages.done()
    }

    /// How many units the current stage holds, for one that knew its size when
    /// it began.
    pub fn stage_total(&self) -> Option<u64> {
        self.stages.total()
    }

    /// How many of the plan's targets the scan has finished with, counting
    /// those an earlier sitting settled and this one resumed past.
    ///
    /// A target is settled once no further probing could change its verdict: it
    /// answered, its retry budget was spent on silence, or its host was found
    /// down and no probe was owed. A target the scan stopped before reaching is
    /// not settled and is not counted here.
    pub fn settled(&self) -> u64 {
        self.settlements.settled_count()
    }

    /// How many targets the plan holds, or `None` for a plan whose targets
    /// cannot all be numbered.
    ///
    /// Fixed for the life of the scan. A resumed sitting reports the size of the
    /// whole job rather than what was left of it, so both halves of a fraction
    /// describe the same plan.
    pub const fn planned(&self) -> Option<u64> {
        self.planned
    }

    /// How many targets are still to settle, or `None` where the plan cannot be
    /// counted.
    pub fn remaining(&self) -> Option<u64> {
        self.planned
            .map(|planned| planned.saturating_sub(self.settled()))
    }

    /// How far through the current stage the scan is, from 0.0 to 1.0.
    ///
    /// A stage that counted itself answers for itself. The one the scan's plan
    /// was drawn for answers with what the plan has settled, which is what
    /// carries a resumed sitting's earlier work into the figure. Any other stage
    /// that never learned its size answers `None`, describing a stage running
    /// with no end in sight rather than one that has not started.
    ///
    /// A port scan's liveness pass is the interesting `None`: its plan counts
    /// address-and-port pairs and the pass settles none of them, so it reports
    /// that it is running rather than reporting nought percent of the wrong
    /// thing.
    ///
    /// An empty stage is complete, and one that somehow finishes more units than
    /// it counted reports 1.0 rather than overshooting.
    pub fn fraction(&self) -> Option<f64> {
        let (done, total) = self.counted()?;

        Some(ratio(done, total))
    }

    /// Where the scan stands across every stage it expects to run, as a position
    /// over a total.
    ///
    /// One figure for a whole run rather than one per stage, so a bar drawn from
    /// it fills once instead of refilling at every stage boundary. It only moves
    /// forward: a stage that was expected and turned out to have nothing to do
    /// is stepped over, which is why the figure can jump.
    ///
    /// The expected stages are a superset. Whether services, detections and TLS
    /// have anything to do depends on what the ports turn out to be, and none of
    /// that is knowable before the ports are read.
    ///
    /// `None` for a session that was never told which stages to expect. See
    /// [`SessionBuilder::staging`].
    pub fn overall(&self) -> Option<(u64, u64)> {
        self.stages.overall(self.counted())
    }

    /// The same reckoning as [`fraction`](Self::fraction), as the two figures it
    /// divides rather than the result.
    ///
    /// For a caller that would rather round the figures itself, or draw
    /// something a fraction cannot express. A bar of a fixed number of cells is
    /// the usual reason: dividing twice in integers keeps the cells and the
    /// percentage agreeing, where taking both off one `f64` can round a bar full
    /// beside a figure that reads 99%.
    pub fn counted(&self) -> Option<(u64, u64)> {
        match self.stage_total() {
            Some(total) => Some((self.stage_done(), total)),
            None if self.stage() == self.plan_stage => Some((self.settled(), self.planned?)),
            None => None,
        }
    }
}

/// `done` out of `total`, held between 0.0 and 1.0. Nothing to do is done.
fn ratio(done: u64, total: u64) -> f64 {
    if total == 0 {
        return 1.0;
    }

    (done as f64 / total as f64).min(1.0)
}

/// A handle to an active network scan: what it has found, what it is doing, and
/// the means to stop it.
///
/// Returned by [`discover`](crate::scanner::discover) and
/// [`scan`](crate::scanner::scan) alongside the
/// [`ScanTask`](crate::scanner::ScanTask) that resolves to the final report.
/// This is the live half of that pair: it describes the present moment and
/// keeps no history; the report is what answers a question asked afterwards.
///
/// ```no_run
/// # async fn example(mut session: zond_engine::ScanSession) {
/// use zond_engine::ScanEvent;
///
/// while let Some(event) = session.events().recv().await {
///     if let ScanEvent::HostUpdated(ip) = event
///         && let Some(host) = session.hosts().get(&ip)
///     {
///         println!("{host}");
///     }
/// }
/// # }
/// ```
pub struct ScanSession {
    store: HostStore,
    events: ScanEvents,
    handle: ScanHandle,
    progress: Progress,
}

impl ScanSession {
    /// What the scan has found so far.
    ///
    /// Once the scan is over this holds the hosts its report lists. While it
    /// runs it can hold more: a port scan that stood its probes in for a
    /// liveness pass files a record at every address it asks, and forgets the
    /// ones nothing answered when its ports are done, so an event naming such
    /// an address can find no host behind it by the time it is read. See
    /// [`ScanPhase::silent`](crate::report::ScanPhase::silent).
    pub fn hosts(&self) -> &HostStore {
        &self.store
    }

    /// The live event stream.
    ///
    /// Bounded: a consumer that reads it slowly, or not at all, loses the
    /// oldest events rather than accumulating them. See [`ScanEvents`].
    pub fn events(&mut self) -> &mut ScanEvents {
        &mut self.events
    }

    /// The control handle, which is how a scan is stopped early.
    pub fn handle(&self) -> &ScanHandle {
        &self.handle
    }

    /// How far the scan has got through its plan.
    ///
    /// Cloneable, so a caller rendering a scan elsewhere clones this rather than
    /// holding the session still. See [`Progress`].
    pub fn progress(&self) -> &Progress {
        &self.progress
    }

    /// Takes the session apart, for a caller that wants to watch the events from
    /// one task and read the hosts from another.
    ///
    /// [`HostStore`], [`ScanHandle`] and [`Progress`] are all cloneable and
    /// shareable, so this is only needed to move the event stream, which is not,
    /// there being exactly one of it.
    pub fn into_parts(self) -> (HostStore, ScanEvents, ScanHandle, Progress) {
        (self.store, self.events, self.handle, self.progress)
    }
}

/// Where an instrumented scanner leaves its counters for the final
/// [`ScanReport`](crate::report::ScanReport).
///
/// A scanner reports its audit as its receive loop exits, which is well before
/// the phase that spawned it knows the scan is over, and the strategy is
/// consumed by then. This is where those counters wait in the meantime.
#[derive(Debug, Default)]
pub(crate) struct ProbeStatsLog {
    entries: Mutex<Vec<ProbeStats>>,
}

impl ProbeStatsLog {
    fn push(&self, stats: ProbeStats) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.push(stats);
    }

    fn drain(&self) -> Vec<ProbeStats> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *entries)
    }

    fn snapshot(&self) -> Vec<ProbeStats> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// Each open port's gathered responses, held from the service phase to the
/// detection phase for a passive [detection](crate::detect) to read.
///
/// The service phase already draws a first-contact banner and any probe replies
/// to name the service; rather than a later phase redrawing them, they are kept
/// here, keyed by port, and *taken* by the detection phase, so a response body
/// is held only across the two adjacent phases and freed as it is read, not
/// retained through the whole paced scan.
#[derive(Default)]
pub(crate) struct Responses {
    inner: DashMap<(ScopedIp, u16, Protocol), Vec<String>>,
}

impl Responses {
    /// Records what the service phase gathered for one port. An empty set is not
    /// stored: there is nothing for a detection to read, and a passive detection
    /// over no bytes has nothing to do.
    fn record(&self, ip: ScopedIp, number: u16, protocol: Protocol, banners: Vec<String>) {
        if !banners.is_empty() {
            self.inner.insert((ip, number, protocol), banners);
        }
    }

    /// Takes one port's gathered responses, removing them so the memory is freed
    /// as the detection phase reads it. Empty if the port drew nothing.
    fn take(&self, ip: &ScopedIp, number: u16, protocol: Protocol) -> Vec<String> {
        self.inner
            .remove(&(ip.clone(), number, protocol))
            .map(|(_, banners)| banners)
            .unwrap_or_default()
    }
}

/// The hosts an earlier sitting finished every pass over, and what this one
/// still asks. See [`ScanContext::owes_passes`].
#[derive(Debug, Default)]
struct Finished {
    /// Each host as [`ScopedIp`]'s text names it, address and link.
    hosts: HashSet<String>,
    /// The addresses this sitting has a target at.
    asked: IpSet,
}

/// The tapes of detection runs, captured as the detection phase produces them and
/// drained into the journal by the checkpoint task. A plain queue: unlike the
/// responses, a tape is never looked up by port, only appended once and taken in a
/// batch.
///
/// Kept only once something will take them, which is whatever holds the scan's
/// [`ScanProgress`]. A scan nobody journals has no reader for a tape, and one
/// kept anyway would hold a copy of every port's responses for each detection
/// that read them until the scan ended.
#[derive(Debug, Default)]
pub(crate) struct Tapes {
    inner: Mutex<Vec<DetectionRunRecord>>,
    kept: AtomicBool,
}

impl Tapes {
    /// Records the tape `run` builds, where tapes are kept, and builds
    /// nothing where they are not.
    pub(crate) fn record(&self, run: impl FnOnce() -> DetectionRunRecord) {
        if !self.kept.load(Ordering::Acquire) {
            return;
        }
        let run = run();
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(run);
    }

    /// Keeps every tape recorded from here on, for a reader that will take
    /// them.
    fn keep(&self) {
        self.kept.store(true, Ordering::Release);
    }

    /// Takes every tape captured since the last call, freeing them as the journal
    /// writes them down.
    pub(crate) fn take(&self) -> Vec<DetectionRunRecord> {
        std::mem::take(
            &mut self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

/// Ground a phase declined to cover, gathered as it is decided.
///
/// Kept apart from [`FailureLog`] for the reason [`Refusal`] gives: a strategy
/// that could not run means something went wrong, and a refusal means the scan
/// as written cannot answer part of what it was asked. Both narrow the result
/// and only one of them is a fault, so a reader who cannot tell them apart
/// learns to ignore both.
///
/// Ordered by insertion rather than sorted: the plan decides these in the order
/// it works through the targets, and that order is the one a reader following
/// the plan expects.
#[derive(Debug, Default)]
pub(crate) struct RefusalLog {
    entries: Mutex<Vec<Refusal>>,
}

impl RefusalLog {
    fn push(&self, refusal: Refusal) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if !entries.contains(&refusal) {
            entries.push(refusal);
        }
    }

    fn drain(&self) -> Vec<Refusal> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *entries)
    }

    fn snapshot(&self) -> Vec<Refusal> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// Addresses this host could not reach, gathered across a phase.
///
/// A set, so a target probed several times is named once, and ordered so two
/// runs of the same scan report them the same way.
///
/// Kept apart from [`FailureLog`] because the two are different findings. A
/// strategy that could not run means the scan covered less than it was asked
/// to and its result is partial; an unreachable address means that address is
/// not reachable from this machine, which is an ordinary fact about a
/// dual-stack name on a single-stack network and says nothing about the rest of
/// the scan.
#[derive(Debug, Default)]
pub(crate) struct UnroutableLog {
    entries: Mutex<std::collections::BTreeSet<IpAddr>>,
}

impl UnroutableLog {
    fn insert(&self, address: IpAddr) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.insert(address);
    }

    fn contains(&self, address: IpAddr) -> bool {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.contains(&address)
    }

    fn drain(&self) -> Vec<IpAddr> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *entries).into_iter().collect()
    }
}

/// Addresses whose ICMP errors a phase found rate-limited, gathered across
/// it.
///
/// The same shape as [`TimedOutLog`] and for a related purpose: the phase
/// qualifying what it covered. A set, so a host two scanners read the same
/// way is named once.
#[derive(Debug, Default)]
pub(crate) struct RateLimitedLog {
    entries: Mutex<std::collections::BTreeSet<IpAddr>>,
}

impl RateLimitedLog {
    fn insert(&self, address: IpAddr) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.insert(address);
    }

    fn drain(&self) -> Vec<IpAddr> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *entries).into_iter().collect()
    }
}

/// Addresses whose own budget ran out, gathered across a phase.
///
/// The same shape as [`UnroutableLog`] and for a related purpose: both are the
/// phase saying what it did not finish covering, and neither is a fault. A set,
/// so a host left early by three passes is named once.
#[derive(Debug, Default)]
pub(crate) struct TimedOutLog {
    entries: Mutex<std::collections::BTreeSet<IpAddr>>,
}

impl TimedOutLog {
    fn insert(&self, address: IpAddr) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.insert(address);
    }

    fn contains(&self, address: IpAddr) -> bool {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.contains(&address)
    }

    fn drain(&self) -> Vec<IpAddr> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *entries).into_iter().collect()
    }
}

/// Addresses a discovery pass asked as many times as its policy allows and
/// heard nothing from.
///
/// Read to tell a host found down from one the pass never reached a verdict
/// on. A port scan's port phase settles only the first as
/// [`Skipped`](crate::journal::settle::Outcome::Skipped), and every discovery
/// phase names the second in
/// [`ScanPhase::undecided`](crate::report::ScanPhase::undecided). A host
/// missing from the live set proves neither, since a pass that stopped early,
/// had no strategy for a range or was refused it leaves hosts out of that set
/// too.
///
/// Positive evidence rather than a list of what went wrong, so a way of failing
/// to ask that nobody thought to record still fails in the safe direction: the
/// host is asked again on a resume rather than written off.
///
/// One range per address until merged, so it is merged whenever what was added
/// since the last merge outgrows what that merge left. A pass walking a
/// permutation settles addresses far apart and merges little until it is
/// nearly done, which bounds this at one range per silent address and no more.
#[derive(Debug, Default)]
pub(crate) struct SilenceLog {
    entries: Mutex<Silence>,
}

/// The set behind [`SilenceLog`], and what decides when it is next merged.
#[derive(Debug, Default)]
struct Silence {
    set: IpSet,
    /// How many ranges the last merge left, which is what the next one waits
    /// for the additions to outgrow.
    merged: usize,
    added: usize,
}

impl SilenceLog {
    /// The fewest additions worth a merge, so a small pass is merged once, on
    /// the way out, rather than every few addresses.
    const MERGE_AFTER: usize = 4096;

    fn insert(&self, address: IpAddr) {
        let mut silence = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        silence.set.insert(address);
        silence.added += 1;
        if silence.added >= Self::MERGE_AFTER.max(silence.merged) {
            silence.set.canonicalize();
            silence.merged = silence.set.v4().len() + silence.set.v6().len();
            silence.added = 0;
        }
    }

    fn drain(&self) -> IpSet {
        let mut silence = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut taken = std::mem::take(&mut *silence).set;
        taken.canonicalize();
        taken
    }
}

/// Addresses a raw phase reached by TCP connect, gathered across it.
///
/// Held as ranges rather than addresses, because what fills it is a whole group
/// a strategy was handed, and a tunnel's own subnet can be a `/23`. Merged on
/// the way out, so a range two strategies both reported is named once.
#[derive(Debug, Default)]
pub(crate) struct ConnectLog {
    entries: Mutex<IpSet>,
}

impl ConnectLog {
    fn extend(&self, targets: &IpSet) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        for range in targets.v4() {
            entries.push_v4_range(*range);
        }
        for range in targets.v6() {
            entries.push_v6_range(*range);
        }
    }

    fn drain(&self) -> Vec<IpRange> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut taken = std::mem::take(&mut *entries);
        taken.canonicalize();
        let v4 = taken.v4().iter().copied().map(IpRange::V4);
        let v6 = taken.v6().iter().copied().map(IpRange::V6);
        v4.chain(v6).collect()
    }
}

/// When each host's wall-clock budget started, for a scan given one.
///
/// A host's clock starts on the first probe aimed at it rather than when the
/// phase did, because a shuffled scan of a wide range reaches an address
/// whenever it reaches it, and a budget counted from the start of the run would
/// give the last address in the plan no time at all.
///
/// `budget` is `None` for a scan that set no per-host bound, which is the
/// ordinary case: the map is then never written to, and every question about a
/// host is a read of an `Option` and nothing more.
///
/// ## What it costs
///
/// One instant per address the scan probes. That is bounded by the same thing
/// the host store is bounded by, and each entry here is a fraction of the
/// [`Host`] the store already keeps for the same address, so a scan that can
/// afford its own findings can afford to time them.
#[derive(Debug, Default)]
pub(crate) struct HostClocks {
    budget: Option<Duration>,
    started: DashMap<IpAddr, Instant>,
}

/// The shortest gap the scan keeps between two probes aimed at one host.
///
/// The companion to [`HostClocks`], built the same way and for the same reason:
/// a bound on one host is a property of the scan rather than of whichever pass
/// happens to be probing, so it lives on the context every pass already holds.
/// A copy per strategy would be no bound at all, since
/// [`max_probe_rate`](crate::config::ZondConfig::max_probe_rate) is handed to
/// each strategy undivided and two passes probing one address would each allow
/// the whole gap.
///
/// `minimum` is `None` for a scan that set none, which is the ordinary case: the
/// map is then never touched and every question is a read of an `Option`.
///
/// ## Deciding, not enforcing
///
/// This answers *when* and records *that*, in two calls a caller makes in that
/// order. It cannot enforce anything on its own, because what to do with a probe
/// it turns away is not its business: the raw port scanner has a queue to hold
/// one in, and the sweep would rather ask the next host and come back. Folding a
/// wait in here would make the decision for both of them, and inside a lock.
///
/// ## What it costs
///
/// One instant per address the scan probes, on the same reasoning
/// [`HostClocks`] gives for its own map. The two are deliberately not one type:
/// a budget is read once per target and starts a clock, a gap is read once per
/// *probe* and moves one, and merging them would put both writes behind
/// whichever question was asked first.
#[derive(Debug, Default)]
pub(crate) struct HostSpacing {
    minimum: Option<Duration>,
    last_sent: DashMap<IpAddr, Instant>,
}

impl HostSpacing {
    /// When `address` may next be probed, or `None` if it may be probed now.
    ///
    /// Reads only. A caller that goes on to send says so with
    /// [`sent`](Self::sent), and one that defers the probe leaves nothing
    /// behind, so a target turned away does not push its own next slot back.
    fn ready_at(&self, address: IpAddr, now: Instant) -> Option<Instant> {
        let minimum = self.minimum?;
        let last = *self.last_sent.get(&address)?;
        let ready = crate::scanner::pacing::timer::later(last, minimum);
        (ready > now).then_some(ready)
    }

    /// Records a probe leaving for `address`.
    ///
    /// Called after the send rather than before it, so a probe the kernel
    /// refused does not spend the host's slot. Nothing is stored for a scan that
    /// set no minimum: without one there is no question for the instant to
    /// answer.
    fn sent(&self, address: IpAddr, now: Instant) {
        if self.minimum.is_none() {
            return;
        }
        self.last_sent.insert(address, now);
    }
}

impl HostClocks {
    /// Whether `address` has used up its budget, starting its clock if this is
    /// the first time it has been asked about.
    ///
    /// Always false for a scan with no budget, without touching the map.
    fn expired(&self, address: IpAddr) -> bool {
        let Some(budget) = self.budget else {
            return false;
        };
        // Read before writing. Only the first probe aimed at a host takes the
        // shard's write lock; the thousand after it are reads, and this is
        // asked once per target on the send path.
        if let Some(started) = self.started.get(&address) {
            return started.elapsed() >= budget;
        }
        let started = *self.started.entry(address).or_insert_with(Instant::now);
        started.elapsed() >= budget
    }
}

/// The links a phase swept, gathered as its strategies run.
///
/// A sweep of a local segment reaches every host on the link, not only the
/// addresses it was handed: an all-nodes solicitation is one probe every IPv6
/// neighbour is required to answer. That is coverage, and there is no address
/// range that expresses it: a link is named by the interface it is on.
///
/// Keyed by interface name, so a link swept by two strategies is recorded once.
#[derive(Debug, Default)]
pub(crate) struct SweptLinks {
    entries: Mutex<std::collections::BTreeMap<String, Zone>>,
}

impl SweptLinks {
    fn insert(&self, zone: Zone) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.insert(zone.name().to_owned(), zone);
    }

    fn drain(&self) -> Vec<Zone> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *entries).into_values().collect()
    }
}

/// The switch ports a phase found itself plugged into, gathered as its
/// strategies run.
///
/// Keyed by the link and the protocol the announcement came from, so a switch
/// re-announcing itself every thirty seconds, which is what they do, is
/// recorded once rather than once per frame. The *latest* announcement wins,
/// because the question is what this machine is plugged into now and a cable
/// somebody moved should not be reported as two attachments held at once.
///
/// A link answering on both LLDP and CDP keeps both: which
/// protocols a network speaks is itself a fact about what it is made of, and
/// the two carry different fields.
#[derive(Debug, Default)]
pub(crate) struct Attachments {
    entries: Mutex<std::collections::BTreeMap<(String, AttachmentSource), Attachment>>,
}

impl Attachments {
    fn insert(&self, attachment: Attachment) {
        let key = (attachment.link().name().to_owned(), attachment.source());
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.insert(key, attachment);
    }

    fn drain(&self) -> Vec<Attachment> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *entries).into_values().collect()
    }
}

/// Every host in `store`, cloned, ordered by the address each is keyed under.
///
/// Ordered because the one production consumer writes these to disk: a
/// compaction whose record order came out of a concurrent map's iteration
/// writes a different file every time it runs over the same findings.
///
/// A free function rather than a method, because both halves of the session
/// need it and neither owns the other. `ScanContext` writes and `ScanProgress`
/// is the narrow view a journal gets, and the three readings they have in
/// common would otherwise be three copies.
fn snapshot_of(store: &DashMap<ScopedIp, Host>) -> Vec<Host> {
    let mut hosts: Vec<Host> = store.iter().map(|entry| entry.value().clone()).collect();
    hosts.sort_by_cached_key(Host::scoped_ip);
    hosts
}

/// The hosts `changed` has marked since it was last drained, with their current
/// state, dropping any the store no longer holds.
fn changed_since(store: &DashMap<ScopedIp, Host>, changed: &ChangedHosts) -> Vec<Host> {
    changed
        .drain()
        .into_iter()
        .filter_map(|key| store.get(&key).map(|host| host.clone()))
        .collect()
}

/// Whether `host` is a record a port phase standing in for a liveness pass may
/// yet forget: one nothing has answered at. The phase decides these at its end,
/// and only these; see [`ScanContext::await_verdicts`].
#[cfg(feature = "journal-format")]
fn awaits_verdict(host: &Host) -> bool {
    host.status() == crate::model::host::HostStatus::Unknown
}

/// What a journal needs from a running scan, and nothing more.
///
/// See [`ScanContext::progress`] for why this exists rather than a context.
#[derive(Debug, Clone)]
pub struct ScanProgress {
    store: Arc<DashMap<ScopedIp, Host>>,
    changed: Arc<ChangedHosts>,
    settlements: Arc<Settlements>,
    failures: Arc<FailureLog>,
    tapes: Arc<Tapes>,
    /// Whether a port phase standing in for a liveness pass has yet to reach
    /// its verdicts, which only a journal's writer asks.
    #[cfg(feature = "journal-format")]
    verdicts_pending: Arc<AtomicBool>,
    #[cfg(feature = "journal-format")]
    sitting: Arc<Sitting>,
}

impl ScanProgress {
    /// How far the scan has got, and what became of what it did not settle.
    pub fn settlements(&self) -> &Settlements {
        &self.settlements
    }

    /// Takes the hosts whose findings have changed since this was last called.
    pub fn take_changed_hosts(&self) -> Vec<Host> {
        changed_since(&self.store, &self.changed)
    }

    /// Takes the detection tapes captured since this was last called, for the
    /// journal to write down.
    pub fn take_tapes(&self) -> Vec<DetectionRunRecord> {
        self.tapes.take()
    }

    /// Every host found so far, cloned, ordered by the address each is keyed
    /// under.
    ///
    /// Ordered because the one production consumer writes these to disk, and a
    /// compaction whose record order came out of a concurrent map's iteration
    /// writes a different file every time it runs over the same findings.
    pub fn hosts_snapshot(&self) -> Vec<Host> {
        snapshot_of(&self.store)
    }

    /// How many hosts have been found so far.
    pub fn host_count(&self) -> usize {
        self.store.len()
    }

    /// The key of every host found so far.
    pub(crate) fn host_keys(&self) -> Vec<ScopedIp> {
        self.store.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Takes the hosts whose findings have changed since this was last called
    /// and that are findings to write down, leaving the rest marked changed.
    ///
    /// What a journal appends as a scan runs. Every changed host, unless a
    /// port phase standing in for a liveness pass has yet to reach its
    /// verdicts: then a record nothing has answered at is held back until the
    /// phase decides it, since the phase may yet forget it as silent or
    /// undecided, and a sitting killed before it names which would leave the
    /// record on disk with nothing to drop it by. Held rather than taken, so
    /// the record is written once the phase keeps it or something answers.
    /// See [`ScanContext::await_verdicts`].
    #[cfg(feature = "journal-format")]
    pub(crate) fn take_changed_findings(&self) -> Vec<Host> {
        if !self.verdicts_pending.load(Ordering::Acquire) {
            return self.take_changed_hosts();
        }
        let (held, findings): (Vec<Host>, Vec<Host>) = self
            .take_changed_hosts()
            .into_iter()
            .partition(awaits_verdict);
        for host in held {
            self.changed.insert(host.scoped_ip());
        }
        findings
    }

    /// This sitting's phases as they stand: those closed, and the open one
    /// so far. See [`Sitting`].
    #[cfg(feature = "journal-format")]
    pub(crate) fn standing_phases(&self) -> Vec<crate::report::ScanPhase> {
        self.sitting.standing(self.failures.snapshot())
    }

    /// Marks `hosts` changed again, for a journal whose write of them failed.
    ///
    /// Taking the changed hosts clears their marks, so a write that fails
    /// after it would otherwise leave them on record nowhere: the next write
    /// takes only what changed since, and its cursor settles the targets
    /// behind the ones that were lost. Handed back, they go out with the next
    /// write that succeeds, in their state as of then.
    #[cfg(feature = "journal-format")]
    pub(crate) fn hand_back(&self, hosts: &[Host]) {
        for host in hosts {
            self.changed.insert(host.scoped_ip());
        }
    }

    /// Every host found so far that is a finding to write down, ordered by the
    /// address each is keyed under: all of them, less the records held back
    /// while a port phase standing in for a liveness pass has yet to decide
    /// them. What a journal compacts its findings to; see
    /// [`take_changed_findings`](Self::take_changed_findings).
    #[cfg(feature = "journal-format")]
    pub(crate) fn findings_snapshot(&self) -> Vec<Host> {
        let mut hosts = self.hosts_snapshot();
        if self.verdicts_pending.load(Ordering::Acquire) {
            hosts.retain(|host| !awaits_verdict(host));
        }
        hosts
    }

    /// Files a failure to the report. Not to the event stream; see
    /// [`ScanContext::progress`].
    ///
    /// Logged under the strategy that is failing, as
    /// [`ScanContext::record_failure`] logs it, rather than under a fixed word:
    /// the checkpoint task is not the only thing that reaches the report this
    /// way, and a line saying `journal` for all of them would tell a reader less
    /// than the name it already has.
    pub fn record_failure(&self, scanner: ScannerKind, reason: String) {
        error!(
            "{} failed: {reason}",
            crate::record::wire::scanner_kind_name(scanner)
        );
        self.failures.push(ScannerFailure::new(scanner, reason));
    }
}

/// The hosts whose findings a journal has yet to record.
#[derive(Debug, Default)]
pub(crate) struct ChangedHosts {
    entries: Mutex<std::collections::BTreeSet<ScopedIp>>,
}

impl ChangedHosts {
    fn insert(&self, ip: ScopedIp) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.insert(ip);
    }

    fn drain(&self) -> Vec<ScopedIp> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *entries).into_iter().collect()
    }
}

/// Where strategy failures accumulate for the final
/// [`ScanReport`](crate::report::ScanReport).
///
/// [`ScanEvent::ScannerFailed`] tells a live consumer about a failure the moment
/// it happens, but an event nobody listens for is an event that never happened:
/// a caller that simply awaits the scan and reads the store at the end has no
/// way to learn that a strategy died. The log keeps the same failures somewhere
/// the report can reach them afterwards, so "the network is empty" and "the raw
/// scanner never started" stay distinguishable however the caller chose to
/// consume the scan.
///
/// A plain [`Mutex`] rather than a lock-free structure: failures are rare
/// enough that contention is not a consideration, and the lock is never held
/// across an await.
#[derive(Debug, Default)]
pub(crate) struct FailureLog {
    entries: Mutex<Vec<ScannerFailure>>,
}

impl FailureLog {
    fn push(&self, failure: ScannerFailure) {
        // A poisoned lock means another thread panicked mid-push. The scan's
        // findings are still worth reporting, so recover the entries rather than
        // propagating the panic into an unrelated scanner.
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.push(failure);
    }

    fn drain(&self) -> Vec<ScannerFailure> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *entries)
    }

    fn snapshot(&self) -> Vec<ScannerFailure> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// The phases a context has run this sitting, closed and open, for a journal
/// to write down before the sitting ends.
///
/// A sitting's phases reach its journal whole when it stops cleanly. One
/// killed outright never gets there, and this is what its journal can write
/// down as it goes instead: what each closed phase turned out to be, and what
/// the open one is so far.
#[derive(Debug, Default)]
pub(crate) struct Sitting {
    phases: Mutex<SittingPhases>,
}

/// What [`Sitting`] holds behind its lock: the phases closed so far, and the
/// one open now, if any.
#[derive(Debug, Default)]
struct SittingPhases {
    closed: Vec<crate::report::ScanPhase>,
    open: Option<crate::scanner::recorder::Opened>,
}

impl Sitting {
    fn open(&self, opened: crate::scanner::recorder::Opened) {
        let mut phases = self.phases.lock().unwrap_or_else(|e| e.into_inner());
        phases.open = Some(opened);
    }

    fn close(&self, phase: &crate::report::ScanPhase) {
        let mut phases = self.phases.lock().unwrap_or_else(|e| e.into_inner());
        phases.open = None;
        phases.closed.push(phase.clone());
    }

    /// The closed phases, and the open one as it stands with `failures` filed
    /// against it.
    #[cfg(feature = "journal-format")]
    fn standing(&self, failures: Vec<ScannerFailure>) -> Vec<crate::report::ScanPhase> {
        let phases = self.phases.lock().unwrap_or_else(|e| e.into_inner());
        let mut standing = phases.closed.clone();
        standing.extend(phases.open.as_ref().map(|open| open.standing(failures)));
        standing
    }
}

/// The shared, cloneable handles that every scanning strategy needs: somewhere to
/// write discovered hosts, somewhere to announce updates, a way to check for abort,
/// and somewhere to record its own failure.
///
/// Bundling these avoids passing (and cloning) the same arguments individually
/// at every scanner construction site.
/// Every field is `pub(crate)`. A scanner is built with one of these and writes
/// findings through [`write_host`](Self::write_host), which is where the
/// lock-then-announce ordering lives; handing a consumer the raw map and the raw
/// event sender would hand them that ordering to get wrong, and would pin the
/// concurrency crate behind the map into this crate's semver. What a consumer
/// reads is [`ScanSession`].
#[derive(Clone)]
pub struct ScanContext {
    pub(crate) handle: ScanHandle,
    pub(crate) store: Arc<DashMap<ScopedIp, Host>>,
    pub(crate) events_tx: broadcast::Sender<ScanEvent>,
    pub(crate) failures: Arc<FailureLog>,
    /// Ground this scan declined to cover before sending anything.
    pub(crate) refusals: Arc<RefusalLog>,
    pub(crate) probe_stats: Arc<ProbeStatsLog>,
    /// Addresses this host could not reach, so no probe was sent to them.
    pub(crate) unroutable: Arc<UnroutableLog>,
    /// Addresses the scan stopped working on because their budget ran out.
    pub(crate) timed_out: Arc<TimedOutLog>,
    /// Addresses whose ICMP errors the scan found rate-limited.
    pub(crate) icmp_rate_limited: Arc<RateLimitedLog>,
    /// Addresses a raw phase reached by TCP connect instead.
    pub(crate) reached_by_connect: Arc<ConnectLog>,
    /// Addresses a discovery pass found silent, or that a port phase standing
    /// in for one asked on every port and heard nothing from.
    pub(crate) silent: Arc<SilenceLog>,
    /// Addresses a port phase standing in for a liveness pass heard nothing
    /// from without finishing asking them.
    pub(crate) undecided: Arc<SilenceLog>,
    /// How many of the plan's targets a port phase's walk stopped short of.
    pub(crate) unreached: Arc<AtomicU64>,
    /// How many targets a port phase asked at the addresses whose records it
    /// forgot as heard nothing from.
    pub(crate) unheard_probes: Arc<AtomicU64>,
    /// Whether a port phase standing in for a liveness pass has yet to decide
    /// which of its records are hosts. See
    /// [`await_verdicts`](Self::await_verdicts).
    pub(crate) verdicts_pending: Arc<AtomicBool>,
    /// The phases this context has run this sitting. See [`Sitting`].
    pub(crate) sitting: Arc<Sitting>,
    /// Which stage's unit the plan, and so the settlements, are counted in.
    pub(crate) plan_stage: Stage,
    /// When each host's budget started, for a scan that set one.
    pub(crate) clocks: Arc<HostClocks>,
    pub(crate) spacing: Arc<HostSpacing>,
    /// The interface each of this scan's link-local targets was named on.
    ///
    /// A link-local address is not a key on its own, and a scanner addressing
    /// its targets one at a time holds a bare one. Completing the key from this
    /// is what keeps a port scan's verdicts on the same record as the sweep's
    /// hardware address, rather than beside it under a keyless `fe80::…`.
    ///
    /// Learned once the port phase knows which targets it kept, and empty for
    /// every scan that named no zone.
    pub(crate) zones: Arc<OnceLock<ZoneMap>>,
    /// How a port scan numbers its targets, for settling every target at an
    /// address it files as unreachable; see
    /// [`record_unroutable`](Self::record_unroutable).
    ///
    /// Learned once the scan knows which targets it kept, before its liveness
    /// pass, since that pass files addresses too. Empty for a sweep, which
    /// numbers addresses in [`positions`](Self::positions), and for a caller
    /// orchestrating their own scan.
    pub(crate) numbering: Arc<OnceLock<crate::model::target::TargetIndex>>,
    pub(crate) swept_links: Arc<SweptLinks>,
    /// Where this machine turned out to be plugged in, as the equipment said.
    pub(crate) attachments: Arc<Attachments>,
    /// Addresses no finding may be recorded against.
    ///
    /// Behind an `Arc` because a context is cloned once per strategy and the
    /// policy is read, never written, by all of them.
    pub(crate) exclusions: Arc<Exclusions>,
    /// The machines `exclusions` names, by hardware address, and the other
    /// addresses they answer at; see [`Exclusions::hardware_in`].
    pub(crate) hardware: Arc<WithheldHardware>,
    /// Which hosts have findings a journal has not written down yet.
    ///
    /// Marked on every write, which is *not* the condition that
    /// fires [`ScanEvent::HostUpdated`]. A watcher is told about novelty and a
    /// journal records state, and the two part company exactly where it matters:
    /// an enrichment pass adding evidence to a host already announced has
    /// nothing new to say and a great deal to write down.
    ///
    /// Bounded by the number of distinct hosts, which the store holds anyway.
    pub(crate) changed: Arc<ChangedHosts>,
    /// What the scan is working on, and how far through it.
    pub(crate) stages: Arc<Stages>,
    /// What became of each target, for a resume that must not skip one.
    ///
    /// Separate from the verdict a target receives: the engine gives an
    /// exhausted probe, an interrupted one and one never sent the same verdict
    /// on purpose. See [`journal::settle`](crate::journal::settle).
    pub(crate) settlements: Arc<Settlements>,
    /// How this scan numbers an address, when it is counted in addresses.
    ///
    /// Empty for a scan counted in something else, which is every port scan:
    /// its positions pair an address with a port and arrive on the target
    /// stream. A sweep has no such stream, a
    /// [`HostScanner`](crate::scanner::strategy::HostScanner) owns its targets,
    /// so the numbering travels here instead.
    ///
    /// Empty is what keeps the two apart. A port scan's liveness pass runs
    /// the discovery strategies against a port scan's context, and those
    /// strategies settle addresses. Numbering them against the port plan would
    /// advance its watermark over probes nobody sent, so a context that does not
    /// count addresses answers `None` to every address and nothing is recorded.
    pub(crate) positions: Arc<Positions>,
    /// The key the order this scan asks its targets in is a function of.
    ///
    /// [`None`] for a scan that walks its plan in order, which is one whose
    /// caller asked for that; see [`SessionBuilder::ordering`]. Read by what
    /// decides what to ask next, the dispatcher and the sweeps that hold their
    /// own first attempts, and by nothing else, since it says nothing about
    /// what an answer means.
    pub(crate) order_seed: Option<u64>,
    /// Each open port's gathered responses, kept from the service phase for the
    /// detection phase to hand a passive detection.
    pub(crate) responses: Arc<Responses>,
    /// The tapes of detection runs, captured for the journal to write down so a
    /// recorded scan can be replayed offline.
    pub(crate) tapes: Arc<Tapes>,
    /// The hosts an earlier sitting finished every pass over, for a sitting
    /// continuing a job. See [`owes_passes`](Self::owes_passes).
    finished: Arc<Finished>,
    /// The corpus the detection phase runs, the shipped one unless a caller set
    /// their own on the config. Cheap to clone: the compiled tiers sit behind
    /// `Arc`s.
    pub(crate) detections: crate::detect::Detections,
    /// The sources the scan forced, which decide where each connection it
    /// opens leaves from. Empty for a scan that forced none.
    pub(crate) forced: Arc<crate::transport::dial::ForcedSources>,
    /// The TCP ports this scan connects to and listens on and sends nothing;
    /// see [`listens_only`](Self::listens_only).
    pub(crate) listen_only: Arc<BTreeSet<u16>>,
    /// The name each address was asked for by, where a target named a host;
    /// see [`ZondConfig::target_names`](crate::config::ZondConfig::target_names).
    target_names: Arc<BTreeMap<IpAddr, Arc<str>>>,
}

impl ScanContext {
    /// The name a target reached `ip` by, which its web ports are asked for
    /// by, or `None` where it was named by its address.
    pub(crate) fn target_name(&self, ip: IpAddr) -> Option<Arc<str>> {
        self.target_names.get(&ip).cloned()
    }

    /// Where a connection this scan opens to `target` leaves from.
    ///
    /// Asked by every phase that dials, once per destination, and handed to
    /// each connection it makes there, so a port the scan's probe reached from
    /// a forced source is spoken to from that source too.
    pub(crate) fn egress_toward(&self, target: IpAddr) -> crate::transport::dial::Egress {
        self.forced.toward(target)
    }

    /// Whether this scan may do no more than connect to `number` over
    /// `protocol` and read what it volunteers.
    ///
    /// Asked by every pass that would put bytes on a port: the service pass and
    /// the connect scanner's inline identification, through
    /// [`service_detection_on`](Self::service_detection_on), and the detection
    /// and TLS enumeration passes, which leave such a port alone. A pass that
    /// wrote to a port without asking would be the one that makes a printer
    /// print; see
    /// [`ZondConfig::listen_only_ports`](crate::config::ZondConfig::listen_only_ports).
    pub(crate) fn listens_only(&self, number: u16, protocol: Protocol) -> bool {
        protocol == Protocol::Tcp && self.listen_only.contains(&number)
    }

    /// How far identification goes on one port under a scan asking for
    /// `detection`: that far, or no further than listening on a port this scan
    /// [only listens on](Self::listens_only).
    ///
    /// A cap rather than a skip, because connecting and reading is safe on any
    /// port and names every service that greets on connect. Everything past
    /// [`ServiceDetection::Banner`] sends, a handshake's ClientHello and an
    /// analyzer's second connection as much as a probe.
    pub(crate) fn service_detection_on(
        &self,
        detection: ServiceDetection,
        number: u16,
        protocol: Protocol,
    ) -> ServiceDetection {
        if self.listens_only(number, protocol) {
            detection.min(ServiceDetection::Banner)
        } else {
            detection
        }
    }

    /// Records the responses the service phase gathered for one port, for the
    /// detection phase to hand a passive detection.
    pub(crate) fn record_responses(
        &self,
        ip: ScopedIp,
        number: u16,
        protocol: Protocol,
        banners: Vec<String>,
    ) {
        self.responses.record(ip, number, protocol, banners);
    }

    /// Takes a port's gathered responses, freeing them as the detection phase
    /// reads it.
    pub(crate) fn take_responses(
        &self,
        ip: &ScopedIp,
        number: u16,
        protocol: Protocol,
    ) -> Vec<String> {
        self.responses.take(ip, number, protocol)
    }

    /// Whether this scan may address a probe to `address`.
    ///
    /// The send-side half of what [`Exclusions`] promises, for the one kind of
    /// address the up-front withholding cannot reach: one a strategy learns while
    /// it runs. A segment sweep takes leads off the wire, from mDNS records and
    /// from advertisements nobody solicited, and asks each one directly. None of
    /// them was in the target list, so none was withheld from it, and
    /// [`write_host`](Self::write_host) sees only the answer: it can keep the
    /// report clean and cannot keep the question off the wire.
    ///
    /// Asked by whoever turns a learned address into a probe, at the moment it
    /// does. A target the caller named has been withheld by address before
    /// anything was opened, and is asked this only for the machine behind it,
    /// by the walk that hands a port scan its targets.
    ///
    /// An address a machine the policy names answers at is held to it as
    /// well, from the moment the neighbour tables or a reply tie the two; see
    /// [the machine an address names](crate::model::exclusion#an-address-names-a-machine).
    pub fn may_probe(&self, address: &IpAddr) -> bool {
        !self.exclusions.excludes(address) && !self.hardware.withholds(address)
    }

    /// The single place a host finding enters the store.
    ///
    /// Upserts the host at `ip`, runs `edit` against it while the store guard is
    /// held, then releases that guard *before* emitting
    /// [`ScanEvent::HostUpdated`] - so the DashMap lock is never held across the
    /// channel send. That ordering rule lives here, once, rather than being
    /// re-spelled (and eventually mis-spelled) at each scanner. Returns `true` if
    /// this call created the host.
    ///
    /// `edit` returns whether the change is worth announcing: `true` emits the
    /// event, `false` suppresses it - e.g. a duplicate reply from an already
    /// known host that revealed nothing new. A newly created host is always
    /// announced, regardless of what `edit` returns.
    ///
    /// Anything a caller must do *without* the guard held - hostname resolution,
    /// adaptive-deadline bookkeeping - keys off the returned flag and runs after
    /// this call, so no scanner has to reason about guard lifetime itself.
    /// Callers that always want to announce their change use the
    /// [`update_host`](Self::update_host) shorthand.
    ///
    /// # Exclusions
    ///
    /// A key the scan's [`Exclusions`] forbid is dropped here: `edit` is not run,
    /// no host is created, no event is emitted, and this returns `false`. Every
    /// other address `edit` attaches to the host is held to the same policy once
    /// it has run, the sweep's later replies from the same machine, a merged
    /// sighting, an mDNS record's other addresses, so none of them reaches the
    /// report either, and none can become the address the host is reached at.
    /// Every router on the host's path is held to it too, whether the trace
    /// measured it or spliced it in from another host's trace: one the policy
    /// names keeps its distance and loses its address, for the reason
    /// [`Hop::withheld`](crate::model::host::Hop::withheld) gives. So is the
    /// router or firewall that sent second-hand evidence about the host, an
    /// ICMP unreachable above all: one the policy names leaves its evidence on
    /// the host and its address off it, for the reason
    /// [`EvidenceSource::Withheld`](crate::model::host::EvidenceSource::Withheld)
    /// gives.
    ///
    /// This is the enforcement that a subtraction from the target list cannot
    /// perform, and putting it here rather than at each scanner is deliberate.
    /// Every finding in the engine reaches the store through this function, so
    /// this one branch covers the ARP and neighbour-advertisement replies a
    /// sweep learns addresses from, the host's own neighbour table, the mDNS
    /// records, and, transitively, because they read the store to decide who to
    /// probe, the service, OS-series and SNMP phases that run afterwards. A
    /// scanner cannot forget to apply the policy, because a scanner is not where
    /// it is applied.
    ///
    /// A host whose record, once `edit` has run, holds the hardware address of
    /// a machine the policy names is that machine at another address, and is
    /// dropped whole: its record leaves the store, no event is emitted, and
    /// every address it held is refused a probe from then on and listed with
    /// the phase's exclusions. See
    /// [the machine an address names](crate::model::exclusion#an-address-names-a-machine).
    ///
    /// A drop is logged rather than counted. The property worth checking is that
    /// no excluded address appears in the report, and a reader can confirm that
    /// against the ranges the report already records, which is a better
    /// guarantee than a number this engine reports about itself.
    pub fn write_host(
        &self,
        key: impl Into<ScopedIp>,
        edit: impl FnOnce(&mut Host) -> bool,
    ) -> bool {
        let key = self.key(key);
        let ip = key.addr();

        if self.exclusions.excludes(&ip) || self.hardware.withholds(&ip) {
            // Ordinary on a sweep, which cannot address its all-nodes echo away
            // from an excluded neighbour, and worth a line either way: it is the
            // record that the gate did something, on the one path where a
            // caller may be surprised that there was anything for it to do.
            info!(
                verbosity = 2,
                "excluded address {ip} answered a probe it was not addressed; dropping the finding"
            );
            return false;
        }

        let mut is_new = false;
        let mut host = self.store.entry(key.clone()).or_insert_with(|| {
            is_new = true;
            let mut host = Host::new(ip);
            // The key carries the interface where the address needs one, so the
            // host is born knowing which link it is on rather than waiting for a
            // scanner to remember to say. `Host::set_zone` keeps the first zone
            // it is given, which is the right rule only if the first one is
            // right, and the key is the one thing here that cannot be wrong
            // about it, since it is what the host was looked up by.
            if let Some(zone) = key.zone() {
                host.set_zone(zone.clone());
            }
            // Born named where a target named it, for the same reason: the
            // name is what the caller called this address, known before
            // anything answered, and a reverse lookup leaves a named host be.
            if let Some(name) = self.target_names.get(&ip) {
                host.set_hostname(Some(name.to_string()));
            }
            host
        });
        let announce = edit(&mut host);
        // The key passed the gate above, and what the edit attached under it
        // has not been asked. The key's own address is among what is kept, so
        // the host never runs out of addresses here.
        if !self.exclusions.is_empty() {
            let keep = |address: &IpAddr| !self.exclusions.excludes(address);
            let before = host.ips().len();
            host.retain_ips(keep);
            if host.ips().len() < before {
                info!(
                    verbosity = 2,
                    "an excluded address arrived beside {ip}; leaving it off the host"
                );
            }
            if host.withhold_intermediaries(keep) {
                info!(
                    verbosity = 2,
                    "an excluded router answered for a probe to {ip}; withholding its address"
                );
            }
            if self.hardware.names(&host) {
                let addresses = host.ips().clone();
                drop(host);
                self.store.remove(&key);
                info!(
                    verbosity = 2,
                    "{ip} answered from an excluded machine's hardware address; dropping it"
                );
                self.hardware.withhold(addresses);
                return false;
            }
        }
        drop(host);

        // Marked whether or not the edit asked to be announced. `edit` was
        // handed a `&mut Host` and may have moved the record however it
        // answered, and a journal that missed that would give back a quieter
        // host than the scan found.
        //
        // **These are two questions, and one boolean cannot answer both.** What
        // a watcher is told is about novelty: a host already announced does not
        // need announcing again, which is why the echo probe answers `false`
        // for a host that was already up. What a journal writes is about state,
        // and that probe has just added an `icmp_echo` reason and a round trip
        // to it. Sharing the boolean would silently drop both from every
        // recorded scan.
        self.changed.insert(key.clone());

        if announce || is_new {
            let _ = self.events_tx.send(ScanEvent::HostUpdated(key));
        }
        is_new
    }

    /// Reads the host at `ip`, if there is one, without cloning it.
    ///
    /// The counterpart of [`write_host`](Self::write_host), and a closure for
    /// the same reason: the store's guard is held for the duration of `read`
    /// and released before this returns, so a caller cannot keep it across an
    /// await. Take what is needed out of the host and let the guard go.
    ///
    /// `read` must not touch this context again. The guard it runs under is the
    /// store's own, and reaching back into the store from inside it deadlocks.
    pub fn read_host<R>(
        &self,
        ip: impl Into<ScopedIp>,
        read: impl FnOnce(&Host) -> R,
    ) -> Option<R> {
        self.store
            .get(&self.key(ip))
            .map(|entry| read(entry.value()))
    }

    /// `ip` as this scan keys a host under.
    ///
    /// A key that already names its interface is kept as it is. One that needs
    /// an interface and has none is completed from the zones the scan named its
    /// targets on, so a finding recorded against a bare `fe80::…` reaches the
    /// host it belongs to. An address needing no zone passes straight through.
    fn key(&self, ip: impl Into<ScopedIp>) -> ScopedIp {
        let key = ip.into();
        match key.is_unusable() {
            true => self
                .zones
                .get()
                .map_or(key.clone(), |zones| zones.key(key.addr())),
            false => key,
        }
    }

    /// Records which interface each of this scan's link-local targets was named
    /// on. The first call decides; later ones are ignored.
    pub(crate) fn learn_zones(&self, zones: ZoneMap) {
        let _ = self.zones.set(zones);
    }

    /// Whether anything is recorded under `ip`.
    ///
    /// Cheaper than [`read_host`](Self::read_host) when the host itself is not
    /// wanted: nothing is cloned and no closure runs. The writing half's name
    /// for what [`HostStore::contains`] answers on the reading half, and named
    /// to match it: one question should not have two names across the pair.
    ///
    /// A question about the key, not about the machine. A host is reachable
    /// at every address it holds and is recorded under one of them, so this
    /// answers "is there a record here" and never "is this machine known".
    pub fn contains_host(&self, ip: &ScopedIp) -> bool {
        self.store.contains_key(&self.key(ip.clone()))
    }

    /// Every address a host is currently recorded under.
    ///
    /// A snapshot, so a caller may write to the store while walking it.
    /// [`write_host`](Self::write_host) takes the store's own lock, and holding
    /// an iterator over the map while calling it would deadlock against
    /// whichever shard the iterator is on.
    pub fn host_addresses(&self) -> Vec<ScopedIp> {
        self.store.iter().map(|entry| entry.key().clone()).collect()
    }

    /// The single place a strategy failure enters the record.
    ///
    /// Logs it, files it for the final report, and announces it to any live
    /// consumer - in that order, so the durable copy exists before the
    /// notification that might be dropped. A scan continues with whatever
    /// strategies remain, so this narrows a result rather than ending it.
    ///
    /// Public because a caller running strategies themselves has to be able to
    /// file what went wrong the same way the engine's own orchestration does; a
    /// custom strategy that could not would produce a report claiming a clean
    /// run over a scan that lost half its work.
    ///
    /// The console line names the strategy as the report files it, then the
    /// reason, which is what a reader acts on and so is given the line.
    pub fn record_failure(&self, scanner: ScannerKind, reason: String) {
        error!(
            "{} failed: {reason}",
            crate::record::wire::scanner_kind_name(scanner)
        );
        self.failures
            .push(ScannerFailure::new(scanner, reason.clone()));
        let _ = self
            .events_tx
            .send(ScanEvent::ScannerFailed { scanner, reason });
    }

    /// Where a strategy files work it began and could not finish because a
    /// budget it runs under ran out: a detection whose declared time or bytes
    /// were spent before its question was answered.
    ///
    /// Filed exactly as [`record_failure`](Self::record_failure) files, as a
    /// [`ScannerFailure`] and a [`ScanEvent::ScannerFailed`], because the report
    /// has one account of work that did not complete and a consumer reading it
    /// for coverage has to find this there. The run did cover less than it was
    /// asked to. What differs is the console. Nothing broke, so this is a
    /// warning in the caller's own words rather than an error announcing that
    /// the scanner failed: a reader told a scanner failed looks for a fault,
    /// and here there is none to find, only a target that cost more than the
    /// budget allowed.
    pub(crate) fn record_cut_short(&self, scanner: ScannerKind, reason: String) {
        crate::warn!("{reason}");
        self.file_cut_short(scanner, reason);
    }

    /// [`record_cut_short`](Self::record_cut_short) without the console line,
    /// for a caller that announces many of these in one: a port given up on
    /// leaves every detection gated onto it unfinished, a report entry each,
    /// and the reader at the console acts on the port rather than on the count.
    pub(crate) fn file_cut_short(&self, scanner: ScannerKind, reason: String) {
        self.failures
            .push(ScannerFailure::new(scanner, reason.clone()));
        let _ = self
            .events_tx
            .send(ScanEvent::ScannerFailed { scanner, reason });
    }

    /// The single place a refusal enters the record.
    ///
    /// Not a failure, and this is the difference. A refusal is the engine
    /// working out, before anything is sent, that part of what it was asked for
    /// has no strategy behind it: an SCTP port on a host with no raw sockets, a
    /// prefix too large to walk, a technique a connect scan cannot express.
    /// Nothing broke, so it is not announced on the event stream and no
    /// strategy is blamed. It reaches the report as its own kind of thing, and
    /// [`Refusal`] has the argument for why that matters.
    ///
    /// Filed once per distinct refusal. A plan that declines the same range on
    /// two links says it once, because a reader acts on the reason rather than
    /// on the count.
    ///
    /// Not logged. The report is where a refusal is read, and a front end that
    /// prints the report's refusals beside its result, as it must at every
    /// verbosity since they are what explain a short count, would otherwise
    /// show each twice to a reader asking for detail.
    ///
    /// Public for the reason [`record_failure`](Self::record_failure) is: a
    /// caller assembling their own scan decides their own coverage, and one who
    /// could not say what they declined would produce a report claiming to have
    /// covered ground nobody looked at.
    pub fn record_refusal(&self, refusal: Refusal) {
        self.refusals.push(refusal);
    }

    /// Takes the refusals recorded so far, leaving the log empty.
    pub(crate) fn take_refusals(&self) -> Vec<Refusal> {
        self.refusals.drain()
    }

    /// The refusals filed so far, left in place.
    ///
    /// The reading counterpart of [`record_refusal`](Self::record_refusal), on
    /// the same terms [`failures_snapshot`](Self::failures_snapshot) is for
    /// failures: a caller driving strategies themselves never reaches the phase
    /// that drains these into a report.
    pub fn refusals_snapshot(&self) -> Vec<Refusal> {
        self.refusals.snapshot()
    }

    /// Files what an instrumented scanner observed about its own run.
    ///
    /// Called once per scanner, as its receive loop exits. Unlike a failure this
    /// is not announced on the event stream: it describes the run rather than
    /// changing what the scan found, and a live consumer has nothing to do with
    /// it mid-scan.
    ///
    /// Public for the same reason [`record_failure`](Self::record_failure) is: a
    /// strategy somebody else wrote should be able to account for its own run,
    /// and a report is worth less when only the built-in strategies appear in
    /// its audit.
    pub fn record_probe_stats(&self, stats: ProbeStats) {
        self.probe_stats.push(stats);
    }

    /// Takes the probe counters recorded so far, leaving the log empty.
    pub(crate) fn take_probe_stats(&self) -> Vec<ProbeStats> {
        self.probe_stats.drain()
    }

    /// The probe counters filed so far, left in place.
    ///
    /// The reading counterpart of [`record_probe_stats`](Self::record_probe_stats),
    /// for a caller driving strategies themselves: they never reach the phase
    /// that drains these into a [`ScanReport`](crate::report::ScanReport),
    /// so this is how they read what a strategy filed. Non-destructive on
    /// purpose: draining is the report's privilege, and a caller who could do
    /// it would leave the report describing a scan that recorded nothing.
    pub fn probe_stats_snapshot(&self) -> Vec<ProbeStats> {
        self.probe_stats.snapshot()
    }

    /// Takes the failures recorded so far, leaving the log empty.
    ///
    /// Called once, when a phase assembles its report. Draining rather than
    /// copying means a context that outlives its phase cannot hand the same
    /// failure to a second one.
    pub(crate) fn take_failures(&self) -> Vec<ScannerFailure> {
        self.failures.drain()
    }

    /// Records that this host could not reach `address`, so no probe was sent
    /// to it: no route or source address led there, or the neighbour never
    /// answered address resolution.
    ///
    /// Not a failure and not an event: no strategy broke and nothing about the
    /// scan's standing changes. It is recorded because the address was asked
    /// about and not covered, and a report that omitted it would leave the
    /// caller to work out from a host count why one of their targets is missing.
    ///
    /// Every target the plan numbers at the address is settled here as
    /// [`Unreachable`](Outcome::Unreachable), unless it earned a verdict of its
    /// own first: the address in a sweep's numbering, and each of its ports in
    /// a port scan's, whichever phase filed it. See
    /// [`Outcome::Unreachable`] for why that is settled.
    pub fn record_unroutable(&self, address: IpAddr) {
        self.unroutable.insert(address);
        if let Some(position) = self.positions.find(address) {
            self.settlements
                .record_unsettled(Outcome::Unreachable { position });
        }
        if let Some(index) = self.numbering.get() {
            for position in index.runs_at(address).flatten() {
                self.settlements
                    .record_unsettled(Outcome::Unreachable { position });
            }
        }
    }

    /// Sets how this port scan numbers its targets; see
    /// [`numbering`](Self::numbering). The first numbering set stands.
    pub(crate) fn number_targets(&self, index: crate::model::target::TargetIndex) {
        let _ = self.numbering.set(index);
    }

    /// Settles `address` as [`Withheld`](Outcome::Withheld), where this scan
    /// is counted in addresses and its plan numbers it: a target the policy
    /// forbids asking for the machine behind it, which a resume must not owe
    /// a question. Nothing for a scan counted otherwise, whose walk settles
    /// its own targets.
    pub(crate) fn settle_withheld(&self, address: IpAddr) {
        if let Some(position) = self.positions.find(address) {
            self.record_outcome(Outcome::Withheld { position });
        }
    }

    /// Every address withheld so far for answering from the hardware of a
    /// machine the exclusions name, ascending: the ones the neighbour tables
    /// tied to it when the scan started, and the ones heard since. Read rather
    /// than taken: the policy holds for the whole scan, and every phase after
    /// the one that heard an address lists it among its exclusions too.
    pub(crate) fn withheld_by_hardware(&self) -> Vec<IpAddr> {
        self.hardware.addresses()
    }

    /// The unroutable addresses filed so far, taken.
    pub(crate) fn take_unroutable(&self) -> Vec<IpAddr> {
        self.unroutable.drain()
    }

    /// Whether `address` has been filed as unroutable in this phase, left in
    /// place.
    pub(crate) fn is_unroutable(&self, address: IpAddr) -> bool {
        self.unroutable.contains(address)
    }

    /// Whether `address` has been filed as left early by its own budget in this
    /// phase, left in place.
    ///
    /// Unlike [`host_expired`](Self::host_expired), which is asked before a
    /// probe and files the host the moment its budget is found spent, this
    /// reads what was filed and files nothing: a host whose clock runs out
    /// after its last probe was answered for in full.
    pub(crate) fn left_early(&self, address: IpAddr) -> bool {
        self.timed_out.contains(address)
    }

    /// Holds back from the journal every record nothing has answered at, until
    /// [`verdicts_reached`](Self::verdicts_reached).
    ///
    /// For a port phase standing in for a liveness pass, which decides only
    /// at its end which of those records are hosts, forgetting the rest as
    /// silent or undecided. The report drops a record the phase forgot by the
    /// lists the phase is written down with, and a sitting killed outright is
    /// never written down: a record a checkpoint had already put on disk would
    /// come back on resume as a host nobody heard from, with nothing to drop
    /// it by. Held back, a record reaches the disk when something answers at
    /// it or the phase keeps it.
    pub(crate) fn await_verdicts(&self) {
        self.verdicts_pending.store(true, Ordering::Release);
    }

    /// Ends what [`await_verdicts`](Self::await_verdicts) began, once the phase
    /// has forgotten the records it heard nothing from. The ones it kept are
    /// still marked changed, so the next write takes them.
    pub(crate) fn verdicts_reached(&self) {
        self.verdicts_pending.store(false, Ordering::Release);
    }

    /// Files the host records at `keys` as addresses a port phase standing in
    /// for its liveness pass asked on every port and heard nothing from, and
    /// forgets those records.
    ///
    /// The pass it stood in for would have found each address silent and made
    /// no host of it, and forgetting the record here is what keeps the live
    /// store and the report the phase closes into saying the same: a caller
    /// reading [`ScanSession::hosts`] after the scan sees the hosts the report
    /// lists. The addresses go where a discovery pass files its silence, which
    /// is what the phase's
    /// [`silent`](crate::report::ScanPhase::silent) list is read from.
    ///
    /// A record a journal already wrote down is left out when the sitting's
    /// findings are written whole at its end, and dropped on read-back by the
    /// same list; see [`Unheard`](crate::report::Unheard). The ports it was
    /// asked are counted before it goes; see
    /// [`ScanPhase::unheard_probes`](crate::report::ScanPhase::unheard_probes).
    pub(crate) fn forget_silent(&self, keys: Vec<ScopedIp>) {
        for key in keys {
            self.silent.insert(key.addr());
            self.forget_unheard(&key);
        }
    }

    /// Files the host records at `keys` as addresses a port phase standing in
    /// for its liveness pass heard nothing from and did not finish asking, and
    /// forgets those records.
    ///
    /// The pass it stood in for would have reached no verdict on them either
    /// way: nothing answered, which is not a host found, and not every port
    /// was asked, which is not a silence. So no host is made of them, as the
    /// pass would have made none, and they are named where that pass names
    /// what it could not decide, the phase's
    /// [`undecided`](crate::report::ScanPhase::undecided) list. Their ports
    /// stay unsettled, so a resume asks them again, and the ones already asked
    /// are counted before the record goes, as a silent address's are.
    pub(crate) fn forget_undecided(&self, keys: Vec<ScopedIp>) {
        for key in keys {
            self.undecided.insert(key.addr());
            self.forget_unheard(&key);
        }
    }

    /// Drops the record at `key`, counting the ports it had been asked as
    /// [`unheard_probes`](crate::report::ScanPhase::unheard_probes) and the
    /// ones it had not with the targets the phase never reached: either way
    /// they are on no host once it goes, and the two counts are how the phase
    /// still accounts for every one. See
    /// [`ScanPhase::unreached`](crate::report::ScanPhase::unreached).
    fn forget_unheard(&self, key: &ScopedIp) {
        if let Some((_, host)) = self.store.remove(key) {
            let (unasked, asked): (Vec<_>, Vec<_>) = host
                .ports()
                .partition(|port| port.state() == PortState::Unasked);
            self.unheard_probes
                .fetch_add(asked.len() as u64, Ordering::Relaxed);
            self.record_unreached(unasked.len() as u64);
        }
    }

    /// The addresses [`forget_undecided`](Self::forget_undecided) filed,
    /// merged and taken.
    pub(crate) fn take_undecided(&self) -> IpSet {
        self.undecided.drain()
    }

    /// Records `count` of a port phase's targets as ones it never asked and
    /// holds on no host: passed by its walk undecided, left by a walk that
    /// stopped, or left unasked at an address whose record it dropped.
    ///
    /// A count rather than the targets: a walk stopped early on a wide plan
    /// leaves them scattered across all of it, and naming each would cost a
    /// record per target the scan never touched. They stay unsettled, so a
    /// resume asks them. See
    /// [`ScanPhase::unreached`](crate::report::ScanPhase::unreached).
    pub(crate) fn record_unreached(&self, count: u64) {
        self.unreached.fetch_add(count, Ordering::Relaxed);
    }

    /// The count [`record_unreached`](Self::record_unreached) filed, taken.
    pub(crate) fn take_unreached(&self) -> u64 {
        self.unreached.swap(0, Ordering::Relaxed)
    }

    /// How many targets the records [`forget_silent`](Self::forget_silent)
    /// and [`forget_undecided`](Self::forget_undecided) dropped had been
    /// asked, taken. See
    /// [`ScanPhase::unheard_probes`](crate::report::ScanPhase::unheard_probes).
    pub(crate) fn take_unheard_probes(&self) -> u64 {
        self.unheard_probes.swap(0, Ordering::Relaxed)
    }

    /// Whether `address` has spent the per-host budget this scan was given,
    /// starting its clock on the first probe aimed at it.
    ///
    /// The one question every pass that probes a host asks before probing it
    /// again, and the only place the answer is filed: a host that answers true
    /// here for the first time is written into the phase's
    /// [`timed_out`](crate::report::ScanPhase::timed_out) list by this call, so
    /// no strategy can leave a host early without the report saying it did.
    ///
    /// Always false for a scan with no budget, which is what keeps this cheap
    /// enough to ask per target. See
    /// [`ZondConfig::host_timeout`](crate::config::ZondConfig::host_timeout).
    pub fn host_expired(&self, address: IpAddr) -> bool {
        if !self.clocks.expired(address) {
            return false;
        }
        self.timed_out.insert(address);
        true
    }

    /// Whether the passes that follow a scan's probes are owed `host` in this
    /// sitting: service identification, the detections, TLS enumeration, the
    /// active OS probes, the route trace and the rest that ask something of a
    /// host the probes found, and the ones that read what the scan holds and
    /// write a conclusion back, since a host written to is one the journal
    /// writes down whole again.
    ///
    /// Every host is, except one an earlier sitting of the job ran to its end
    /// with, which ran each of those passes over every host it held. That
    /// host's answers are in its record, and asking again would put the job's
    /// questions to the network a second time: on a resume of a finished job,
    /// every one of them. It is owed them again where this sitting still has
    /// a target at one of its addresses, since what that target answers may be
    /// a port or a service the passes have not seen.
    ///
    /// A sitting killed or stopped before its end records nothing, so a host
    /// it found, or one whose passes it did not reach, is owed them by the
    /// next. That is the safe direction: a pass asked twice costs probes,
    /// where one never asked leaves a host's record short with nothing to say
    /// so.
    pub(crate) fn owes_passes(&self, host: &Host) -> bool {
        let finished = &self.finished;
        !finished.hosts.contains(&host.scoped_ip().to_string())
            || host.ips().iter().any(|ip| finished.asked.contains(ip))
    }

    /// The hosts owed the passes that follow the probes, keyed as
    /// [`host_addresses`](Self::host_addresses) keys them; see
    /// [`owes_passes`](Self::owes_passes).
    pub(crate) fn hosts_owed_passes(&self) -> Vec<ScopedIp> {
        self.host_addresses()
            .into_iter()
            .filter(|key| {
                self.read_host(key, |host| self.owes_passes(host))
                    .unwrap_or(false)
            })
            .collect()
    }

    /// When `address` may next be probed, or `None` if it may be probed now.
    ///
    /// The question every send site asks beside
    /// [`host_expired`](Self::host_expired), and the two are different in kind:
    /// an expired host is finished with and gets written into the phase's
    /// [`timed_out`](crate::report::ScanPhase::timed_out) list, while one asked
    /// too soon is fine and will be ready at the instant this returns.
    ///
    /// **A refusal here is not a verdict.** The probe has not been sent and the
    /// port has not been settled, so a caller that drops one on this answer
    /// reports a port nobody asked about as though the target had been silent.
    /// Hold it and send it at the instant returned, or file it
    /// [`Unasked`](crate::model::port::PortState::Unasked); a scanner with
    /// nowhere to hold one should be reading
    /// [`ZondConfig::host_probe_interval`](crate::config::ZondConfig::host_probe_interval)
    /// as a reason not to have taken the target off its queue yet.
    ///
    /// Always `None` for a scan that set no minimum, which is what keeps this
    /// cheap enough to ask once per probe rather than once per target. See
    /// [`ZondConfig::host_probe_interval`](crate::config::ZondConfig::host_probe_interval).
    pub fn host_ready_at(&self, address: IpAddr, now: Instant) -> Option<Instant> {
        self.spacing.ready_at(address, now)
    }

    /// Records a probe leaving for `address`, moving its next slot.
    ///
    /// Called after the send and only for one that reached the wire: a probe the
    /// kernel refused occupied nothing and must not spend the host's slot, on
    /// the same reasoning `RawProbeScan::record_send` gives for keeping it out
    /// of the congestion window.
    pub fn host_probed(&self, address: IpAddr, now: Instant) {
        self.spacing.sent(address, now);
    }

    /// The gap this scan keeps between two probes at one address, or `None`
    /// for a scan that set none. A scanner sizing its own deadline reads it,
    /// since every probe at one host waits it out in turn. See
    /// [`ZondConfig::host_probe_interval`](crate::config::ZondConfig::host_probe_interval).
    pub(crate) fn host_probe_interval(&self) -> Option<Duration> {
        self.spacing.minimum
    }

    /// The addresses left early so far, taken.
    pub(crate) fn take_timed_out(&self) -> Vec<IpAddr> {
        self.timed_out.drain()
    }

    /// Records that `address` rate-limited the ICMP errors a scanner reads
    /// its verdicts from, so the ports it had no allowance to answer for
    /// read as silent; see
    /// [`ScanPhase::icmp_rate_limited`](crate::report::ScanPhase::icmp_rate_limited).
    pub(crate) fn record_icmp_rate_limited(&self, address: IpAddr) {
        self.icmp_rate_limited.insert(address);
    }

    /// The addresses found rate-limiting their ICMP errors so far, taken.
    pub(crate) fn take_icmp_rate_limited(&self) -> Vec<IpAddr> {
        self.icmp_rate_limited.drain()
    }

    /// Records that `targets` were reached by TCP connect in a phase that held
    /// the privilege its raw strategies need.
    ///
    /// For a strategy that, inside a raw phase, reaches its targets the way an
    /// unprivileged one would: loopback in any raw phase, and whatever a
    /// process's self-built frames cannot reach when frames are all it has.
    /// What such a strategy finds is connect evidence, and the phase's privilege
    /// alone would present it as raw. Ignored by a phase recorded at
    /// [`Privilege::Connect`](crate::system::privilege::Privilege::Connect),
    /// which reached everything this way. See
    /// [`ScanPhase::reached_by_connect`](crate::report::ScanPhase::reached_by_connect).
    pub fn record_reached_by_connect(&self, targets: &IpSet) {
        self.reached_by_connect.extend(targets);
    }

    /// The addresses reached by connect so far, merged and taken.
    pub(crate) fn take_reached_by_connect(&self) -> Vec<IpRange> {
        self.reached_by_connect.drain()
    }

    /// Records that this phase swept a whole link, not merely the addresses on
    /// it that were named.
    ///
    /// Called by a strategy that put a probe on the segment which every host
    /// there is required to answer. What it buys is stated on
    /// [`TargetScope::links`](crate::report::TargetScope::links): a
    /// comparison can then tell a host that appeared on a link somebody was
    /// watching from one that turned up on ground nobody had covered.
    pub fn record_sweep(&self, zone: Zone) {
        self.swept_links.insert(zone);
    }

    /// Takes the links swept so far, leaving the log empty.
    pub(crate) fn take_swept_links(&self) -> Vec<Zone> {
        self.swept_links.drain()
    }

    /// Records which switch port this machine turned out to be plugged into.
    ///
    /// Called by whatever read an announcement off a link. see
    /// [`Attachment`] for why this is a fact
    /// about the phase rather than about any host in it. A device re-announcing
    /// itself replaces the previous reading for that link and protocol rather
    /// than adding to it.
    pub fn record_attachment(&self, attachment: Attachment) {
        self.attachments.insert(attachment);
    }

    /// Takes the attachments observed so far, leaving the log empty.
    pub(crate) fn take_attachments(&self) -> Vec<Attachment> {
        self.attachments.drain()
    }

    /// Records that a phase has opened, for a journal to write down what it
    /// is before it closes. See [`Sitting`].
    pub(crate) fn open_phase(&self, opened: crate::scanner::recorder::Opened) {
        self.sitting.open(opened);
    }

    /// Records that the open phase has closed as `phase`. See [`Sitting`].
    pub(crate) fn close_phase(&self, phase: &crate::report::ScanPhase) {
        self.sitting.close(phase);
    }

    /// Records what became of one target, for a later resume.
    ///
    /// Not the same question as the verdict: a target reaches the store with a
    /// port state, and this says whether the scan *earned* it or assigned it
    /// because the run ended. See [`Outcome`].
    ///
    /// Called once whatever the target produced is in the store, never
    /// before. A journal's checkpoint reads the settlements before it takes
    /// the changed hosts, so a settlement it reads has its finding in what it
    /// takes only where the finding was stored first. Settled the other way
    /// round, a checkpoint landing between the two writes a cursor that skips
    /// the target beside a findings file without it, and a scan killed then
    /// resumes past a finding it never reports. See
    /// [`checkpoint`](crate::scanner::checkpoint).
    pub fn record_outcome(&self, outcome: Outcome) {
        self.settlements.record(outcome);
    }

    /// Announces the stage the scan has moved into, with how much work it holds
    /// where that is known before any of it is done.
    ///
    /// Entering the stage that is already current adds to its total rather than
    /// starting it over, so service detection running once per protocol reports
    /// one stage the size of both runs rather than two stages that each restart
    /// the count.
    pub fn enter_stage(&self, stage: Stage, total: Option<u64>) {
        if self.stages.enter(stage, total) {
            let _ = self.events_tx.send(ScanEvent::StageChanged { stage });
        }
    }

    /// Counts one unit of the current stage as finished.
    ///
    /// Called where the work completes rather than where it is handed out. A
    /// stage that submits into a pool has given out all of its work long before
    /// any of it is done, and counting the handing out would fill the bar while
    /// the pool was still draining.
    pub fn stage_advanced(&self) {
        self.stages.advance();
    }

    /// Records `count` targets ending the same way, for the outcomes that carry
    /// no position. See [`Settlements::record_many`].
    pub fn record_many_outcomes(&self, outcome: Outcome, count: u64) {
        self.settlements.record_many(outcome, count);
    }

    /// Records `count` addresses a sweep left unsettled the same way, where the
    /// scan's settlements are counted in addresses.
    ///
    /// A port scan's plan is counted in address-and-port pairs, and its
    /// liveness pass asks about addresses that plan does not number. Counted
    /// beside the port targets, three hundred addresses the pass never asked
    /// would read as three hundred port targets never asked, in a tally whose
    /// unit is the port target. The pass's own account of those addresses is
    /// its phase's [`undecided`](crate::report::ScanPhase::undecided) list, so
    /// nothing is lost by leaving them out here.
    pub(crate) fn record_address_outcomes(&self, outcome: Outcome, count: u64) {
        if self.plan_stage != Stage::Ports {
            self.settlements.record_many(outcome, count);
        }
    }

    /// Records what became of one address, in a scan counted in addresses.
    ///
    /// The position comes from the plan this scan is numbered in, which the
    /// caller does not need to know: a strategy knows it asked an address and
    /// what came back, and this turns that into a position a resume can skip.
    ///
    /// Nothing is settled in two cases, and both are correct. A scan not
    /// counted in addresses has no numbering, so a port scan's liveness pass
    /// settles nothing. And an address the plan does not name has no position:
    /// a sweep finds neighbours it was never asked about, and those are findings
    /// rather than plan targets. Either way the address is asked again on the
    /// next sitting, which is the direction this has to fail in.
    ///
    /// Silence is kept whichever of those holds, because two readers need it
    /// that a position cannot serve. The port phase after a liveness pass
    /// settles the ports of a host found down, and silence the pass asked for
    /// is what earns that; see [`Outcome::Skipped`]. And every discovery phase
    /// names the addresses it reached no verdict on, which is its scope less
    /// what answered and what was asked to exhaustion; see
    /// [`ScanPhase::undecided`](crate::report::ScanPhase::undecided).
    ///
    /// Called once whatever the answer established is in the store, for the
    /// reason [`record_outcome`](Self::record_outcome) gives.
    pub fn settle_address(&self, ip: IpAddr, settled: Settled) {
        if let Some(position) = self.positions.find(ip) {
            self.record_outcome(settled.at(position));
        }
        if settled == Settled::Exhausted {
            self.silent.insert(ip);
        }
    }

    /// The addresses a discovery pass asked as many times as its policy allows
    /// and heard nothing from, merged and taken.
    ///
    /// Only these may have their ports settled as
    /// [`Skipped`](crate::journal::settle::Outcome::Skipped), and only these
    /// keep an address out of a phase's
    /// [`undecided`](crate::report::ScanPhase::undecided) list without a host
    /// found at it. An address the pass never reached a verdict on is not
    /// here, whatever kept it from one. See
    /// [`Dispatcher::screened`](crate::scanner::dispatcher::Dispatcher::screened).
    pub(crate) fn take_silent(&self) -> IpSet {
        self.silent.drain()
    }

    /// How far the scan has got, and what became of what it did not settle.
    pub fn settlements(&self) -> &Settlements {
        &self.settlements
    }

    /// Seeds the store with hosts an earlier sitting found.
    ///
    /// Merged rather than inserted, so a host this sitting has already seen
    /// keeps both readings.
    ///
    /// Each restored host is announced, because to a caller watching the stream
    /// these hosts have just appeared. They are not marked as *changed*, though:
    /// they came from the journal, and writing them straight back would be work
    /// with nothing new in it.
    ///
    /// The exclusions this sitting was given apply to what comes back, address
    /// by address, as they do in [`write_host`](Self::write_host): this is the
    /// one other way into the store, and a scan interrupted before an exclusion
    /// was added carries the addresses it now forbids in its journal. A host
    /// loses each of those, and is restored under its best remaining address
    /// where the one it was recorded under is among them. Only a host with no
    /// address left that this sitting may report is left out. A router the
    /// policy names on a restored host's path keeps its distance and loses its
    /// address, and one that sent evidence about the host keeps the evidence
    /// and loses its address, as each would have in `write_host`.
    ///
    /// The journal itself is left alone. It is an honest record of a sitting
    /// that was allowed to make it, and rewriting history to match a policy that
    /// arrived later would be the wrong repair. What changes is only what this
    /// sitting is willing to say.
    pub fn restore_hosts(&self, hosts: &[Host]) {
        let keep = |address: &IpAddr| !self.exclusions.excludes(address);
        for host in hosts {
            let mut host = host.clone();
            if !host.retain_ips(keep) {
                info!(
                    verbosity = 2,
                    "every address of {} in the journal is excluded; leaving it out of this sitting",
                    host.primary_ip()
                );
                continue;
            }
            host.withhold_intermediaries(keep);

            let key = host.scoped_ip();
            match self.store.get_mut(&key) {
                Some(mut existing) => existing.merge(host),
                None => {
                    self.store.insert(key.clone(), host);
                }
            }
            let _ = self.events_tx.send(ScanEvent::HostUpdated(key));
        }
    }

    /// What a journal needs from a running scan.
    ///
    /// Not a [`ScanContext`]. A context carries the event
    /// sender, and a checkpoint task holding one would keep the event stream
    /// open after the scan had ended, so a caller watching that stream to know
    /// when to stop would wait forever for a scan that was already over, and the
    /// checkpoint task would wait for the caller to stop it. Neither moves.
    ///
    /// A failure recorded through this reaches the report but not the stream,
    /// which is right: a checkpoint that could not be written is a fact about
    /// the journal, not about a scanning strategy.
    ///
    /// The detection phase keeps its runs' tapes from the first call on, for
    /// [`ScanProgress::take_tapes`] to hand over. Before it, and in a scan that
    /// never makes one, a tape has no reader and is not kept.
    pub fn progress(&self) -> ScanProgress {
        self.tapes.keep();
        ScanProgress {
            store: Arc::clone(&self.store),
            changed: Arc::clone(&self.changed),
            settlements: Arc::clone(&self.settlements),
            failures: Arc::clone(&self.failures),
            tapes: Arc::clone(&self.tapes),
            #[cfg(feature = "journal-format")]
            verdicts_pending: Arc::clone(&self.verdicts_pending),
            #[cfg(feature = "journal-format")]
            sitting: Arc::clone(&self.sitting),
        }
    }

    /// Every host found so far, cloned, ordered by the address each is keyed
    /// under.
    ///
    /// For a journal compacting its findings, which needs the whole state rather
    /// than what changed recently. Ordered for the reason
    /// [`HostStore::snapshot`] is: the one consumer writes these to disk, and a
    /// compaction whose record order came out of a concurrent map's iteration
    /// writes a different file every time it runs over the same findings.
    pub fn hosts_snapshot(&self) -> Vec<Host> {
        let mut hosts: Vec<Host> = self
            .store
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        hosts.sort_by_cached_key(Host::scoped_ip);
        hosts
    }

    /// How many hosts have been found so far.
    pub fn host_count(&self) -> usize {
        self.store.len()
    }

    /// Takes the hosts whose findings have changed since this was last called,
    /// with their current state.
    ///
    /// For a journal writing findings down as a scan produces them. Draining
    /// rather than reading, so a host is written once per change rather than
    /// once per checkpoint for the rest of the run.
    pub fn take_changed_hosts(&self) -> Vec<Host> {
        changed_since(&self.store, &self.changed)
    }

    /// The strategy failures filed so far, left in place.
    ///
    /// The reading counterpart of [`record_failure`](Self::record_failure), and
    /// the same shape as
    /// [`probe_stats_snapshot`](Self::probe_stats_snapshot) for the same
    /// reason: a caller driving strategies themselves needs to see what went
    /// wrong without waiting for a phase to close, and a live event stream only
    /// answers for a consumer that happened to be listening.
    ///
    /// Non-destructive on purpose. Draining belongs to
    /// [`PhaseRecorder::finish`](crate::scanner::recorder::PhaseRecorder::finish),
    /// and a caller who could do it here would leave the report claiming a
    /// clean run over a scan that lost work.
    pub fn failures_snapshot(&self) -> Vec<ScannerFailure> {
        self.failures.snapshot()
    }

    /// Upserts the host at `ip`, applies `update`, and unconditionally announces
    /// the change. The convenience form of [`write_host`](Self::write_host) for
    /// the paths that always record a finding worth emitting - a port state, a
    /// merged host. Returns `true` if this call created the host.
    pub fn update_host(&self, ip: impl Into<ScopedIp>, update: impl FnOnce(&mut Host)) -> bool {
        self.write_host(ip, |host| {
            update(host);
            true
        })
    }
}

/// The machines a scan's exclusions name, by hardware address, and every other
/// address one of them answers at.
///
/// Read once, when the scan starts, from the host's neighbour tables, and
/// fixed from then on: the hardware is how the policy's reach is decided, and
/// a scan that learned more of it partway through would hold its first and
/// last findings to different policies. The addresses start as the ones the
/// same tables tie to that hardware, which is what keeps a target named at
/// one of them from being asked anything, and grow as the scan hears more.
/// See [`Exclusions::hardware_in`] and [`Exclusions::tied_to`].
#[derive(Debug, Default)]
pub(crate) struct WithheldHardware {
    macs: BTreeSet<MacAddr>,
    addresses: Mutex<BTreeSet<IpAddr>>,
}

impl WithheldHardware {
    /// Withholds the machines `exclusions` names in `table`, a neighbour
    /// table's addresses and the hardware each resolved to, at every address
    /// the table ties to them.
    fn read(exclusions: &Exclusions, table: Vec<(IpAddr, Option<MacAddr>)>) -> Self {
        let macs = exclusions.hardware_in(table.iter().copied());
        let tied = exclusions.tied_to(&macs, table);
        if !macs.is_empty() {
            info!(
                verbosity = 1,
                "excluding {} by hardware address too",
                crate::counted(macs.len() as u128, "machine", "machines")
            );
        }
        Self {
            macs,
            addresses: Mutex::new(tied),
        }
    }

    /// Whether `host` answered from the hardware of a machine withheld here.
    fn names(&self, host: &Host) -> bool {
        !self.macs.is_empty()
            && host
                .hardware()
                .is_some_and(|hardware| hardware.macs().keys().any(|mac| self.macs.contains(mac)))
    }

    /// Whether `address` answers from such hardware, as the neighbour tables
    /// or a reply said.
    fn withholds(&self, address: &IpAddr) -> bool {
        !self.macs.is_empty()
            && self
                .addresses
                .lock()
                .expect("the withheld addresses are never poisoned")
                .contains(address)
    }

    /// Records `addresses` as heard from such hardware.
    fn withhold(&self, addresses: impl IntoIterator<Item = IpAddr>) {
        self.addresses
            .lock()
            .expect("the withheld addresses are never poisoned")
            .extend(addresses);
    }

    /// Every address tied to such hardware so far, ascending.
    fn addresses(&self) -> Vec<IpAddr> {
        self.addresses
            .lock()
            .expect("the withheld addresses are never poisoned")
            .iter()
            .copied()
            .collect()
    }
}

/// The order a session's scan asks its targets in, as its caller left it.
#[derive(Debug, Default, Clone, Copy)]
enum Order {
    /// Nothing said: a seed is drawn when the session is built.
    #[default]
    Drawn,
    /// The walk this seed names.
    Seeded(u64),
    /// Plan order, shuffled within a batch.
    Planned,
}

/// Builds a [`ScanSession`] and the [`ScanContext`] the strategies behind it
/// write into.
///
/// Everything a session can be given beyond its defaults, most of which a
/// caller leaves alone. A builder rather than constructors chaining into each
/// other, because such a chain puts the widest of them under the narrowest
/// name, and a caller who wants one setting without another has to know each
/// one's neutral value, such as `Checkpoint::default()` for no resume point.
/// Here each is named once and there is one neutral state.
///
/// ```no_run
/// use zond_engine::scanner::session::ScanSession;
///
/// let (session, ctx) = ScanSession::builder().build();
/// # let _ = (session, ctx);
/// ```
#[must_use]
#[derive(Debug, Default)]
pub struct SessionBuilder {
    exclusions: Exclusions,
    settled: crate::journal::cursor::Checkpoint,
    positions: Positions,
    planned: Option<u64>,
    plan_stage: Stage,
    staging: Vec<Stage>,
    detections: crate::detect::Detections,
    host_timeout: Option<Duration>,
    scan_timeout: Option<Duration>,
    host_probe_interval: Option<Duration>,
    order: Order,
    send_source: Vec<IpAddr>,
    /// `None` for the default, [`RAW_PRINT_PORTS`](crate::config::RAW_PRINT_PORTS).
    listen_only: Option<BTreeSet<u16>>,
    /// The neighbour tables the exclusions are read against for the machines
    /// they name, in place of the host's own; `None` to read the host's.
    neighbours: Option<Vec<(IpAddr, Option<MacAddr>)>>,
    finished: Finished,
    target_names: BTreeMap<IpAddr, String>,
}

impl SessionBuilder {
    /// Addresses the scan may not record a finding against.
    ///
    /// A caller orchestrating their own scan and honouring an exclusion policy
    /// has to set this rather than subtract the addresses from their own target
    /// list: the subtraction covers the addresses they named, and a segment
    /// sweep does not confine itself to those. See [`Exclusions`] for what each
    /// of the two enforcements is for.
    ///
    /// A policy naming an address on a segment this host has spoken to
    /// recently names the machine there too, whatever other addresses it
    /// answers at: [`build`](Self::build) reads the host's neighbour tables for
    /// its hardware address. See [`Exclusions`].
    pub fn excluding(mut self, exclusions: Exclusions) -> Self {
        self.exclusions = exclusions;
        self
    }

    /// The name each address was asked for by, where a target named a host.
    ///
    /// A host recorded at one of these addresses carries its name as its
    /// hostname from the moment it is recorded, and its web ports are asked
    /// for by it; see
    /// [`ZondConfig::target_names`](crate::config::ZondConfig::target_names).
    pub fn naming(mut self, names: BTreeMap<IpAddr, String>) -> Self {
        self.target_names = names;
        self
    }

    /// The neighbour tables the exclusions are read against, in place of the
    /// host's own: each address listed and the hardware address it resolved
    /// to.
    #[cfg(test)]
    pub(crate) fn with_neighbours(mut self, table: Vec<(IpAddr, Option<MacAddr>)>) -> Self {
        self.neighbours = Some(table);
        self
    }

    /// The cursor this scan checkpoints from, for one continuing an earlier
    /// sitting.
    ///
    /// Without it a resumed scan writes a cursor covering only its own sitting,
    /// and the journal forgets everything the first one settled.
    pub fn resuming(mut self, settled: &crate::journal::cursor::Checkpoint) -> Self {
        self.settled = settled.clone();
        self
    }

    /// The hosts an earlier sitting of this job finished every pass over,
    /// named as the journal writes them, and the addresses this sitting still
    /// has something to ask; see [`ScanContext::owes_passes`].
    pub(crate) fn finished(mut self, hosts: HashSet<String>, asked: IpSet) -> Self {
        self.finished = Finished { hosts, asked };
        self
    }

    /// How this scan numbers an address, for one counted in addresses.
    ///
    /// A sweep sets this so a strategy that has earned a verdict for an address
    /// can settle it without knowing where in the plan it sits; see
    /// [`ScanContext::settle_address`].
    ///
    /// A port scan leaves it alone. It is counted in address-and-port pairs and
    /// numbers them on its target stream, so the discovery strategies running
    /// inside its liveness pass settle nothing -- which is what keeps a port
    /// plan's watermark from advancing over probes nobody sent.
    pub fn counting(mut self, positions: Positions) -> Self {
        self.positions = positions;
        self
    }

    /// The key the order this scan asks its targets in is a function of.
    ///
    /// Set it and the scan walks its plan in a rearrangement of the whole index
    /// space rather than in address order, which is what keeps a sweep of a
    /// range from being the one shape every correlating sensor is written
    /// against. See [`Permutation`](crate::model::order::Permutation).
    ///
    /// Leave it alone and the session draws a seed of its own when it is
    /// built, so every scan walks one order whoever orchestrates it: the
    /// dispatcher's streams and the sweeps that hold their own first attempts
    /// alike. Unseeded, the first come out in plan order shuffled within a
    /// batch and the second in address order, which is two orders in one scan
    /// and the second the very signature a seed exists not to give.
    ///
    /// Pass [`None`] for plan order, shuffled within a batch, which is what a
    /// scan whose plan cannot be addressed by position falls back to anyway. A
    /// sitting continuing a journal that recorded no seed has to: its
    /// checkpoint counts along the plan, and a walk it never took would leave
    /// every answer waiting above the watermark.
    ///
    /// A caller journalling their scan should pass what the journal recorded, so
    /// a resumed sitting continues in the order the first one was going to use.
    /// [`scan_with_journal`](crate::scanner::scan_with_journal) does.
    pub fn ordering(mut self, seed: Option<u64>) -> Self {
        self.order = match seed {
            Some(seed) => Order::Seeded(seed),
            None => Order::Planned,
        };
        self
    }

    /// How many targets the plan holds, and which [`Stage`] does that work.
    ///
    /// This is the denominator [`Progress::fraction`] divides into while that
    /// stage is running, so it has to be counted in the same unit the stage
    /// settles in: addresses for a sweep, address-and-port pairs for a port
    /// scan. [`Positions::total`](crate::model::ip::set::Positions::total) and
    /// [`TargetIndex::total`](crate::model::target::TargetIndex::total) are
    /// those two counts, and each has a companion that says whether it covered
    /// the whole plan.
    ///
    /// Naming the stage is what keeps the figure honest in a scan that has more
    /// than one. A port scan runs a liveness pass first, and measuring that pass
    /// against a plan of address-and-port pairs would report nought percent for
    /// the whole of it.
    ///
    /// Leave it alone and a consumer reads a running count of what has settled
    /// with nothing to measure it against, which is all a scan of an
    /// uncountable plan can honestly offer.
    pub fn planning(mut self, stage: Stage, total: Option<u64>) -> Self {
        self.plan_stage = stage;
        self.planned = total;
        self
    }

    /// The stages this scan expects to run, in the order it will run them.
    ///
    /// What [`Progress::overall`] measures a whole run against. A superset is
    /// the right thing to pass: a stage listed here and skipped moves the figure
    /// forward over it, where a stage that runs without being listed leaves the
    /// figure sitting still until the next one that was listed.
    ///
    /// [`discover`](crate::scanner::discover) and [`scan`](crate::scanner::scan)
    /// derive this from the settings they were handed. A caller orchestrating
    /// their own scan lists the stages they mean to run, or leaves it alone and
    /// reads progress one stage at a time.
    pub fn staging(mut self, stages: Vec<Stage>) -> Self {
        self.staging = stages;
        self
    }

    /// The corpus the detection phase runs, the shipped one unless set otherwise.
    ///
    /// [`scan`](crate::scanner::scan) sets the corpus it was given here; a caller
    /// orchestrating their own scan sets it directly so their detections run in it.
    pub fn detections(mut self, detections: crate::detect::Detections) -> Self {
        self.detections = detections;
        self
    }

    /// The wall-clock budget each host gets before the scan leaves it.
    ///
    /// A caller orchestrating their own scan sets this to have the same bound
    /// [`scan`](crate::scanner::scan) applies from
    /// [`ZondConfig::host_timeout`](crate::config::ZondConfig::host_timeout).
    /// Every strategy that probes a host reads it through
    /// [`ScanContext::host_expired`].
    pub fn host_timeout(mut self, budget: Option<Duration>) -> Self {
        self.host_timeout = budget;
        self
    }

    /// The wall-clock budget the whole scan gets before it winds down.
    ///
    /// Starts when [`build`](Self::build) is called, and reaches every strategy
    /// through the [`ScanHandle`] they already read. See
    /// [`ZondConfig::scan_timeout`](crate::config::ZondConfig::scan_timeout).
    pub fn scan_timeout(mut self, budget: Option<Duration>) -> Self {
        self.scan_timeout = budget;
        self
    }

    /// The shortest gap the scan keeps between two probes aimed at one host.
    ///
    /// A caller orchestrating their own scan sets this to have the same spacing
    /// [`scan`](crate::scanner::scan) applies from
    /// [`ZondConfig::host_probe_interval`](crate::config::ZondConfig::host_probe_interval).
    /// Every pass that sends reads it through
    /// [`ScanContext::host_ready_at`], which is also where what the two words
    /// mean for a probe that arrives early is written down.
    ///
    /// `None` is no gap. `Some(Duration::MAX)` is the longest gap there is,
    /// one probe per host for the rest of the scan, and not a way to say no
    /// limit; see the config field for why.
    pub fn host_probe_interval(mut self, minimum: Option<Duration>) -> Self {
        self.host_probe_interval = minimum;
        self
    }

    /// The source addresses the connections this scan opens are forced to, one
    /// per family.
    ///
    /// A caller orchestrating their own scan sets this to have the same pinning
    /// [`scan`](crate::scanner::scan) applies from
    /// [`ZondConfig::send_source`](crate::config::ZondConfig::send_source):
    /// every connection to a routed target, the connect scan's and the service
    /// pass's alike, leaves from the forced source and by the interface holding
    /// it, as the raw probes before them do.
    pub fn send_source(mut self, sources: Vec<IpAddr>) -> Self {
        self.send_source = sources;
        self
    }

    /// The TCP ports this scan connects to and listens on, and sends nothing.
    ///
    /// Left unset, the printers' ports,
    /// [`RAW_PRINT_PORTS`](crate::config::RAW_PRINT_PORTS), as
    /// [`scan`](crate::scanner::scan) has them by default. A caller
    /// orchestrating their own scan sets this to what
    /// [`ZondConfig::listen_only_ports`](crate::config::ZondConfig::listen_only_ports)
    /// says, and an empty set probes every port alike.
    pub fn listening_only_to(mut self, ports: BTreeSet<u16>) -> Self {
        self.listen_only = Some(ports);
        self
    }

    /// Opens the session and the context.
    ///
    /// This is where a scan's own clock starts, so a caller holding a builder
    /// for a while and building later gets the budget they asked for rather
    /// than what is left of it.
    pub fn build(self) -> (ScanSession, ScanContext) {
        let store = Arc::new(DashMap::new());
        let handle = ScanHandle::bounded(self.scan_timeout);
        let (events_tx, rx) = broadcast::channel(ScanEvents::CAPACITY);
        // Counted along the walk the dispatcher takes, where it takes one: a
        // seed and a plan it can number whole. The two have to agree, or the
        // walk watermark follows an order nothing asks in and every answer
        // waits in the set, which is the cost it exists to avoid.
        let order_seed = match self.order {
            Order::Drawn => Some(rand::random()),
            Order::Seeded(seed) => Some(seed),
            Order::Planned => None,
        };
        let walk = order_seed
            .zip(self.planned)
            .map(|(seed, total)| crate::model::order::Permutation::new(seed, total));
        let settlements = Arc::new(Settlements::walking(&self.settled, walk));
        let stages = Arc::new(Stages::new(self.staging));

        let session = ScanSession {
            store: HostStore::new(store.clone()),
            events: ScanEvents { rx },
            handle: handle.clone(),
            progress: Progress::new(
                settlements.clone(),
                self.planned,
                self.plan_stage,
                stages.clone(),
            ),
        };

        let ctx = ScanContext {
            handle,
            store,
            events_tx,
            failures: Arc::new(FailureLog::default()),
            refusals: Arc::new(RefusalLog::default()),
            probe_stats: Arc::new(ProbeStatsLog::default()),
            unroutable: Arc::new(UnroutableLog::default()),
            timed_out: Arc::new(TimedOutLog::default()),
            icmp_rate_limited: Arc::new(RateLimitedLog::default()),
            reached_by_connect: Arc::new(ConnectLog::default()),
            silent: Arc::new(SilenceLog::default()),
            undecided: Arc::new(SilenceLog::default()),
            unreached: Arc::new(AtomicU64::new(0)),
            unheard_probes: Arc::new(AtomicU64::new(0)),
            verdicts_pending: Arc::new(AtomicBool::new(false)),
            sitting: Arc::new(Sitting::default()),
            plan_stage: self.plan_stage,
            clocks: Arc::new(HostClocks {
                budget: self.host_timeout,
                started: DashMap::new(),
            }),
            spacing: Arc::new(HostSpacing {
                minimum: self.host_probe_interval,
                last_sent: DashMap::new(),
            }),
            zones: Arc::new(OnceLock::new()),
            numbering: Arc::new(OnceLock::new()),
            swept_links: Arc::new(SweptLinks::default()),
            attachments: Arc::new(Attachments::default()),
            hardware: Arc::new(WithheldHardware::read(
                &self.exclusions,
                self.neighbours.unwrap_or_else(|| {
                    if self.exclusions.is_empty() {
                        return Vec::new();
                    }
                    let mut table = crate::system::neighbor_cache::ipv4_neighbors();
                    table.extend(crate::system::neighbor_cache::ipv6_neighbors());
                    table.iter().map(|entry| (entry.ip, entry.mac)).collect()
                }),
            )),
            exclusions: Arc::new(self.exclusions),
            changed: Arc::new(ChangedHosts::default()),
            stages,
            settlements,
            positions: Arc::new(self.positions),
            order_seed,
            responses: Arc::new(Responses::default()),
            tapes: Arc::new(Tapes::default()),
            finished: Arc::new(self.finished),
            detections: self.detections,
            forced: Arc::new(crate::transport::dial::ForcedSources::new(
                &self.send_source,
            )),
            listen_only: Arc::new(
                self.listen_only
                    .unwrap_or_else(|| crate::config::RAW_PRINT_PORTS.into_iter().collect()),
            ),
            target_names: Arc::new(
                self.target_names
                    .into_iter()
                    .map(|(ip, name)| (ip, Arc::from(name)))
                    .collect(),
            ),
        };

        (session, ctx)
    }
}

impl ScanSession {
    /// A session and the context the strategies behind it write into, with
    /// nothing excluded, nothing resumed, no address numbering, and a walk
    /// order of its own; see [`SessionBuilder::ordering`].
    ///
    /// A caller wrapping the engine normally receives the session already built,
    /// from [`discover`](crate::scanner::discover) or
    /// [`scan`](crate::scanner::scan), and never calls this. A caller
    /// orchestrating their own scan calls it first: every strategy in
    /// [`strategy`](crate::scanner::strategy) is constructed with a
    /// [`ScanContext`], and this is where one comes from.
    ///
    /// [`builder`](Self::builder) is the same thing with any of the three
    /// settings applied.
    pub fn new() -> (Self, ScanContext) {
        Self::builder().build()
    }

    /// A session with exclusions, a resume point or an address numbering.
    ///
    /// See [`SessionBuilder`].
    pub fn builder() -> SessionBuilder {
        SessionBuilder::default()
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
    use crate::model::host::{EvidenceSource, Hop, HostStatus, StatusProtocol, StatusReason};

    /// A whole run reads as one figure that only grows, rather than one per
    /// stage that starts over each time.
    #[test]
    fn a_whole_run_reads_as_one_figure_rather_than_one_per_stage() {
        let (session, ctx) = ScanSession::builder()
            .planning(Stage::Ports, Some(4))
            .staging(vec![Stage::Ports, Stage::Services, Stage::Detections])
            .build();

        ctx.enter_stage(Stage::Ports, None);
        ctx.record_outcome(Outcome::Answered { position: 0 });
        ctx.record_outcome(Outcome::Answered { position: 1 });

        // Half of the first stage of three, which is a sixth of the run.
        let (done, total) = session.progress().overall().expect("a staged run");
        assert_eq!(
            done * 6,
            total,
            "half of one stage in three: {done}/{total}"
        );

        ctx.enter_stage(Stage::Services, Some(2));
        ctx.stage_advanced();

        // One stage behind it and half way through the second, which is half the
        // run. The figure grew across the boundary rather than starting again.
        let (done, total) = session.progress().overall().expect("a staged run");
        assert_eq!(done * 2, total, "half the run: {done}/{total}");
    }

    /// A stage that turned out to have nothing to do is stepped over.
    ///
    /// Whether services, detections and TLS have any work depends on which ports
    /// are open, so the running order is a superset and some of it never
    /// announces itself. Waiting for a stage that will never arrive would park
    /// the figure for the rest of the run.
    #[test]
    fn a_stage_with_nothing_to_do_is_stepped_over_rather_than_waited_for() {
        let (session, ctx) = ScanSession::builder()
            .staging(vec![
                Stage::Ports,
                Stage::Services,
                Stage::Detections,
                Stage::Os,
            ])
            .build();

        ctx.enter_stage(Stage::Ports, Some(1));
        ctx.stage_advanced();

        // Neither services nor detections found anything to do, so neither
        // announced itself. The run is three stages further on all the same.
        ctx.enter_stage(Stage::Os, None);

        let (done, total) = session.progress().overall().expect("a staged run");
        assert_eq!(done * 4, total * 3, "three stages of four: {done}/{total}");
    }

    /// A session nobody told a running order reports no whole-run figure, rather
    /// than inventing one out of the stages it happens to see.
    #[test]
    fn a_session_with_no_running_order_reports_no_whole_run_figure() {
        let (session, ctx) = ScanSession::new();

        ctx.enter_stage(Stage::Services, Some(4));
        ctx.stage_advanced();

        let progress = session.progress();
        assert_eq!(progress.overall(), None, "nothing said how many stages");
        assert_eq!(
            progress.counted(),
            Some((1, 4)),
            "the stage still answers for itself"
        );
    }

    /// A stage that knows its own size answers for itself, and the plan is not
    /// consulted.
    ///
    /// This is the whole point of stages. The plan of a port scan is settled
    /// long before the scan is over, and measuring the detection stage against
    /// it would report a finished run for as long as the detections took.
    #[test]
    fn a_stage_that_counted_itself_answers_for_itself() {
        let (session, ctx) = ScanSession::builder()
            .planning(Stage::Ports, Some(4))
            .build();

        // The plan, settled in full. Nothing left by its own reckoning.
        ctx.enter_stage(Stage::Ports, None);
        ctx.record_outcome(Outcome::Answered { position: 0 });
        ctx.record_outcome(Outcome::Answered { position: 1 });
        ctx.record_outcome(Outcome::Answered { position: 2 });
        ctx.record_outcome(Outcome::Answered { position: 3 });
        assert_eq!(
            session.progress().fraction(),
            Some(1.0),
            "the ports are done"
        );

        ctx.enter_stage(Stage::Detections, Some(8));
        ctx.stage_advanced();
        ctx.stage_advanced();

        let progress = session.progress();
        assert_eq!(progress.stage(), Stage::Detections);
        assert_eq!(progress.stage_done(), 2);
        assert_eq!(progress.stage_total(), Some(8));
        assert_eq!(
            progress.fraction(),
            Some(0.25),
            "a quarter through the detections, not finished with the scan"
        );
        assert_eq!(progress.settled(), 4, "the plan is still settled in full");
    }

    /// A stage nobody could size reports that it is running, not that it is at
    /// nought.
    ///
    /// A port scan's liveness pass is the case worth naming: the plan counts
    /// address-and-port pairs, the pass settles none of them, and reporting the
    /// plan's figure would show nought percent for the whole of it.
    #[test]
    fn an_unsized_stage_that_is_not_the_plans_own_reports_nothing() {
        let (session, ctx) = ScanSession::builder()
            .planning(Stage::Ports, Some(1_000))
            .build();

        ctx.enter_stage(Stage::Discovery, None);
        let progress = session.progress();
        assert_eq!(progress.stage(), Stage::Discovery);
        assert_eq!(
            progress.fraction(),
            None,
            "a liveness pass is not nought percent of a port plan"
        );

        ctx.enter_stage(Stage::Ports, None);
        assert_eq!(
            session.progress().fraction(),
            Some(0.0),
            "the stage the plan was drawn for reads from the plan"
        );
    }

    /// Entering the stage that is already current adds to it.
    ///
    /// Service detection runs once per protocol, and two entries that each reset
    /// the count would send the bar back to the start half way through one
    /// stage.
    #[test]
    fn re_entering_a_stage_adds_to_it_rather_than_starting_it_over() {
        let (mut session, ctx) = ScanSession::new();

        ctx.enter_stage(Stage::Services, Some(3));
        ctx.stage_advanced();
        ctx.enter_stage(Stage::Services, Some(2));

        let progress = session.progress().clone();
        assert_eq!(progress.stage_total(), Some(5), "both runs' ports");
        assert_eq!(progress.stage_done(), 1, "and the one already finished");

        // One announcement, not two: the stage did not change the second time.
        let mut announced = 0;
        while let Some(event) = session.events().try_recv() {
            if matches!(event, ScanEvent::StageChanged { .. }) {
                announced += 1;
            }
        }
        assert_eq!(announced, 1, "one stage, announced once");
    }

    /// Every stage has a place in the list, and the list is in running order.
    ///
    /// The list is what a front end mapping stages onto a protocol of its own
    /// checks itself against, so a variant missing from it is a stage that
    /// front end never learns exists.
    #[test]
    fn the_list_of_stages_holds_every_one_of_them_in_running_order() {
        let codes: Vec<u8> = Stage::ALL.iter().map(|stage| stage.code()).collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();

        assert_eq!(codes, sorted, "the stages are listed in the order they run");
        assert_eq!(
            codes.len(),
            Stage::ALL.len(),
            "a stage is listed once and no stage twice"
        );

        for stage in Stage::ALL {
            assert_eq!(
                Stage::from_code(stage.code()),
                stage,
                "{stage} does not survive its own code"
            );
        }
    }

    /// Moving to a stage announces it, naming the stage moved to.
    #[test]
    fn a_stage_announces_itself_as_it_begins() {
        let (mut session, ctx) = ScanSession::new();

        ctx.enter_stage(Stage::Os, None);

        let Some(ScanEvent::StageChanged { stage }) = session.events().try_recv() else {
            panic!("entering a stage announces it");
        };
        assert_eq!(stage, Stage::Os);
    }

    /// A scan whose plan was never counted still counts what it settles.
    ///
    /// The two halves are independent, and this is the pairing a front end has
    /// to handle: a running total with nothing to divide it into. It is what a
    /// listener and a sweep of an IPv6 range too wide to number both look like.
    #[test]
    fn an_uncounted_plan_settles_targets_but_reports_no_fraction() {
        let (session, ctx) = ScanSession::new();

        ctx.record_outcome(Outcome::Answered { position: 0 });
        ctx.record_outcome(Outcome::Exhausted { position: 1 });

        let progress = session.progress();
        assert_eq!(progress.settled(), 2, "both targets settled");
        assert_eq!(
            progress.planned(),
            None,
            "nothing said how big the plan was"
        );
        assert_eq!(
            progress.fraction(),
            None,
            "so there is nothing to divide into"
        );
        assert_eq!(progress.remaining(), None);
    }

    /// The fraction is settled against the plan, and both move as the scan does.
    #[test]
    fn settling_targets_advances_the_fraction() {
        let (session, ctx) = ScanSession::builder()
            .planning(Stage::Discovery, Some(4))
            .build();

        assert_eq!(
            session.progress().fraction(),
            Some(0.0),
            "nothing settled yet"
        );

        ctx.record_outcome(Outcome::Answered { position: 0 });
        ctx.record_outcome(Outcome::Skipped { position: 1 });

        let progress = session.progress();
        assert_eq!(progress.settled(), 2);
        assert_eq!(progress.remaining(), Some(2));
        let fraction = progress.fraction().expect("a counted plan has a fraction");
        assert!(
            (fraction - 0.5).abs() < f64::EPSILON,
            "two of four settled is half the plan, got {fraction}"
        );
    }

    /// An outcome that settles nothing moves the scan no further through its
    /// plan.
    ///
    /// `Unasked` is what a scan that stopped early leaves behind, and counting
    /// it would draw a full bar over a run that did not finish. The short bar is
    /// the accurate one.
    #[test]
    fn an_unsettled_outcome_does_not_advance_the_plan() {
        let (session, ctx) = ScanSession::builder()
            .planning(Stage::Discovery, Some(2))
            .build();

        ctx.record_outcome(Outcome::Answered { position: 0 });
        ctx.record_many_outcomes(Outcome::Unasked, 1);

        let progress = session.progress();
        assert_eq!(progress.settled(), 1, "only the answered target settled");
        assert_eq!(
            progress.remaining(),
            Some(1),
            "the unasked one is still owed"
        );
    }

    /// A resumed sitting measures against the whole job rather than its own
    /// share of it.
    ///
    /// The numerator carries what earlier sittings settled, so the denominator
    /// has to be the whole plan or the bar would restart at zero every time a
    /// scan was continued.
    #[test]
    fn a_resumed_sitting_starts_part_way_through_the_plan() {
        let earlier = crate::journal::cursor::Checkpoint::new(6, []);
        let (session, ctx) = ScanSession::builder()
            .resuming(&earlier)
            .planning(Stage::Discovery, Some(8))
            .build();

        assert_eq!(
            session.progress().settled(),
            6,
            "what the earlier sitting settled is already covered"
        );

        ctx.record_outcome(Outcome::Answered { position: 6 });

        let fraction = session
            .progress()
            .fraction()
            .expect("a counted plan has a fraction");
        assert!(
            (fraction - 0.875).abs() < f64::EPSILON,
            "seven of eight, got {fraction}"
        );
    }

    /// An empty plan has nothing left to do, and a plan cannot be overshot.
    #[test]
    fn a_fraction_saturates_rather_than_passing_one() {
        let (empty, _ctx) = ScanSession::builder()
            .planning(Stage::Discovery, Some(0))
            .build();
        assert_eq!(
            empty.progress().fraction(),
            Some(1.0),
            "an empty plan is complete"
        );

        let (session, ctx) = ScanSession::builder()
            .planning(Stage::Discovery, Some(1))
            .build();
        ctx.record_outcome(Outcome::Answered { position: 0 });
        ctx.record_outcome(Outcome::Answered { position: 1 });
        assert_eq!(
            session.progress().fraction(),
            Some(1.0),
            "more settled than planned still reads as done"
        );
        assert_eq!(session.progress().remaining(), Some(0));
    }

    /// The gate, at the one place every finding in the engine passes through.
    ///
    /// Written against `write_host` directly rather than through a scan because
    /// the property is about this function and not about any scanner: a reply
    /// from an excluded address leaves no host, emits no event, and reports
    /// itself as having created nothing. What a scanner does with the `false` is
    /// the scanner's business; that it gets one is this test's.
    ///
    /// The `edit` closure panics on purpose. A drop that ran the caller's
    /// closure and then discarded the result would pass every assertion below
    /// while still letting a scanner's own bookkeeping, a deadline update, a
    /// counter, a hostname lookup keyed off the edit, run for a host nobody
    /// may look at.
    #[test]
    fn an_excluded_address_reaches_neither_the_store_nor_the_stream() {
        let excluded: IpAddr = "198.51.100.7".parse().expect("literal");
        let allowed: IpAddr = "203.0.113.7".parse().expect("literal");

        let mut ips = crate::model::ip::set::IpSet::new();
        ips.insert_range("198.51.100.0/24".parse().expect("a valid range"));
        let (mut session, ctx) = ScanSession::builder()
            .excluding(Exclusions::new(ips))
            .build();

        assert!(
            !ctx.write_host(excluded, |_| unreachable!(
                "an excluded address must not reach the caller's edit"
            )),
            "an excluded address is never reported as a new host"
        );
        assert!(ctx.write_host(allowed, |_| true));

        assert_eq!(ctx.store.len(), 1);
        assert!(!ctx.store.contains_key(&ScopedIp::unscoped(excluded)));

        // Exactly one announcement, for the address that was allowed to answer.
        let ScanEvent::HostUpdated(announced) =
            session.events().try_recv().expect("the allowed host")
        else {
            panic!("expected a host update");
        };
        assert_eq!(announced, ScopedIp::unscoped(allowed));
        assert!(session.events().try_recv().is_none());
    }

    /// The store's key, at the one address family where a bare address is not
    /// one. `fe80::1` names a different machine on every segment, so a host
    /// watching two of them finds two neighbours under one number.
    ///
    /// Keyed by the bare address, the second write would land on the first's
    /// entry, and one machine's hardware address, roles and round trips would be
    /// folded into another machine's record: under the wrong interface, since
    /// `Host::set_zone` keeps the first zone it is given.
    #[test]
    fn two_link_locals_on_different_segments_are_two_hosts() {
        let shared: IpAddr = "fe80::1".parse().expect("literal");
        let (_session, ctx) = ScanSession::new();

        ctx.write_host(ScopedIp::scoped(shared, Zone::new(1, "en0")), |host| {
            host.set_status(HostStatus::Up);
            true
        });
        ctx.write_host(ScopedIp::scoped(shared, Zone::new(2, "en1")), |host| {
            host.set_status(HostStatus::Up);
            true
        });

        assert_eq!(ctx.store.len(), 2, "two segments, two machines");

        // And each knows its own link, taken from the key it was created under
        // rather than from whichever scanner remembered to say.
        let mut zones: Vec<String> = ctx
            .store
            .iter()
            .filter_map(|entry| entry.value().zone().map(|zone| zone.name().to_owned()))
            .collect();
        zones.sort();
        assert_eq!(zones, ["en0", "en1"]);
    }

    /// A port scan addresses its targets one at a time and holds the address
    /// bare, so its verdicts arrive here with no interface on them. They belong
    /// to the host the sweep found on the interface the scan named, not to a
    /// second record beside it.
    ///
    /// Filed apart, a scoped link-local target would come back as two hosts,
    /// one carrying the hardware address and the NDP round trip, the other the
    /// ports.
    #[test]
    fn a_port_verdict_on_a_bare_link_local_lands_on_the_host_the_scan_named() {
        use crate::model::ip::range::Ipv6Range;

        let address: IpAddr = "fe80::1".parse().expect("literal");
        let (_session, ctx) = ScanSession::new();

        let mut zones = ZoneMap::new();
        let IpAddr::V6(v6) = address else {
            panic!("a v6 literal");
        };
        zones.insert(
            Ipv6Range::scoped(v6, v6, Some(1)).expect("a scoped range"),
            &[(1, "en0")],
        );
        ctx.learn_zones(zones);

        ctx.write_host(ScopedIp::scoped(address, Zone::new(1, "en0")), |host| {
            host.set_status(HostStatus::Up);
            true
        });
        ctx.write_host(address, |host| {
            host.set_status(HostStatus::Up);
            true
        });

        assert_eq!(ctx.store.len(), 1, "one machine, one record");
        assert!(
            ctx.read_host(address, |host| host.zone().is_some())
                .expect("the bare address reaches it too"),
            "and it is still the host on en0"
        );
    }

    /// A global address is the same machine through whichever interface answered
    /// it, so the zone is dropped from the key and two sightings are one host.
    ///
    /// The other half of the rule above: a key that carried the interface for
    /// *every* address would split every dual-homed host in two.
    #[test]
    fn one_global_address_seen_on_two_interfaces_is_one_host() {
        let global: IpAddr = "2001:db8::1".parse().expect("literal");
        let (_session, ctx) = ScanSession::new();

        ctx.write_host(ScopedIp::scoped(global, Zone::new(1, "en0")), |_| true);
        ctx.write_host(ScopedIp::scoped(global, Zone::new(2, "en1")), |_| true);

        assert_eq!(ctx.store.len(), 1, "one address, one machine");
    }

    /// The round trip every phase after discovery depends on: a strategy reads
    /// the addresses the store holds, decides something about one, and writes it
    /// back. Written back under anything but the key it was read by, the finding
    /// lands in a second entry and one host becomes two, each holding half of
    /// what was found.
    #[test]
    fn a_finding_written_back_under_a_key_from_the_store_lands_on_the_same_host() {
        let shared: IpAddr = "fe80::1".parse().expect("literal");
        let (_session, ctx) = ScanSession::new();

        ctx.write_host(ScopedIp::scoped(shared, Zone::new(1, "en0")), |host| {
            host.set_status(HostStatus::Up);
            true
        });

        for key in ctx.host_addresses() {
            ctx.write_host(key, |host| {
                host.add_reason(StatusReason::new(StatusProtocol::IcmpEcho, "echo answered"));
                true
            });
        }

        assert_eq!(ctx.store.len(), 1, "the same host, enriched");
        assert_eq!(
            ctx.store
                .iter()
                .next()
                .expect("the host")
                .value()
                .reasons()
                .len(),
            1,
            "and the finding reached it"
        );
    }

    #[test]
    fn a_failure_survives_a_consumer_that_never_listens() {
        let (session, ctx) = ScanSession::new();
        // The case this exists for: a caller that awaits the scan and reads the
        // store at the end, never touching the event stream.
        drop(session);

        ctx.record_failure(ScannerKind::Routed, "raw socket unavailable".into());

        let failures = ctx.take_failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].scanner(), ScannerKind::Routed);
        assert_eq!(failures[0].reason(), "raw socket unavailable");
    }

    #[test]
    fn a_failure_reaches_both_the_log_and_the_stream() {
        let (mut session, ctx) = ScanSession::new();

        ctx.record_failure(ScannerKind::Local, "eth0: no address".into());

        match session.events().try_recv() {
            Some(ScanEvent::ScannerFailed { scanner, reason }) => {
                assert_eq!(scanner, ScannerKind::Local);
                assert_eq!(reason, "eth0: no address");
            }
            other => panic!("expected a ScannerFailed event, got {other:?}"),
        }
        assert_eq!(ctx.take_failures().len(), 1);
    }

    /// A caller driving strategies themselves reads failures without closing a
    /// phase, so the snapshot has to leave the log alone. Draining here would
    /// take the failure out from under the report that is supposed to carry it.
    #[test]
    fn snapshotting_failures_leaves_them_for_the_report() {
        let (_session, ctx) = ScanSession::new();
        ctx.record_failure(ScannerKind::Local, "eth0: no address".into());

        assert_eq!(ctx.failures_snapshot().len(), 1);
        assert_eq!(ctx.failures_snapshot().len(), 1, "reading is not taking");
        assert_eq!(ctx.take_failures().len(), 1, "and the report still gets it");
    }

    /// A failure is said as the strategy's name in the report and the reason,
    /// with nothing between them a reader has to read past: the reason is
    /// what they act on, and a frame as long again pushes it off the line.
    #[test]
    fn a_failure_is_said_under_the_name_the_report_files_it_by() {
        let (_session, ctx) = ScanSession::new();
        let lines = crate::logging::logged(|| {
            ctx.record_failure(ScannerKind::SynPort, "the capture would not open".into());
        });

        let said: Vec<&str> = lines.iter().map(|line| line.message.as_str()).collect();
        assert_eq!(said, ["syn_port failed: the capture would not open"]);
    }

    #[test]
    fn taking_failures_empties_the_log() {
        let (_session, ctx) = ScanSession::new();
        ctx.record_failure(ScannerKind::Connect, "refused".into());

        assert_eq!(ctx.take_failures().len(), 1);
        // A context outliving its phase must not hand the same failure to a
        // second report.
        assert!(ctx.take_failures().is_empty());
    }

    #[test]
    fn failures_from_every_clone_land_in_one_log() {
        let (_session, ctx) = ScanSession::new();
        let clone = ctx.clone();

        ctx.record_failure(ScannerKind::Local, "eth0".into());
        clone.record_failure(ScannerKind::Routed, "gateway".into());

        // Each strategy gets its own clone of the context; the report is
        // assembled from one of them and must see all of it.
        assert_eq!(ctx.take_failures().len(), 2);
    }

    /// A session built to continue an earlier sitting starts from its progress.
    ///
    /// Without this the resumed scan's first checkpoint rolls the cursor back to
    /// what its own sitting settled, and everything the first one did is
    /// forgotten: silently, since both scans report success.
    #[test]
    fn a_resuming_session_starts_from_the_earlier_cursor() {
        use crate::journal::cursor::Checkpoint;

        let settled = Checkpoint {
            watermark: 12,
            settled_above: vec![14],
            walked: None,
        };
        let (_session, ctx) = ScanSession::builder()
            .excluding(Exclusions::none())
            .resuming(&settled)
            .build();

        assert_eq!(ctx.settlements().settled_count(), 13);
        assert_eq!(ctx.settlements().checkpoint(), settled);

        // A fresh session has nothing inherited.
        let (_session, fresh) = ScanSession::new();
        assert_eq!(fresh.settlements().settled_count(), 0);
    }

    /// A session whose caller said nothing of order walks a seed of its own,
    /// so a caller orchestrating their own scan gets the one order every phase
    /// asks in rather than address order from its sweeps and a batch shuffle
    /// from its dispatcher. Told there is no seed, which a sitting continuing
    /// a journal that recorded none has to be, it walks the plan.
    #[test]
    fn a_session_left_to_itself_draws_a_seed_and_one_told_otherwise_does_not() {
        let (_session, left) = ScanSession::new();
        let (_session, other) = ScanSession::builder().build();
        let (_session, told) = ScanSession::builder().ordering(None).build();
        let (_session, given) = ScanSession::builder().ordering(Some(0x5EED)).build();

        assert!(left.order_seed.is_some(), "no seed drawn");
        assert_ne!(left.order_seed, other.order_seed, "two sessions, one order");
        assert_eq!(told.order_seed, None);
        assert_eq!(given.order_seed, Some(0x5EED));
    }

    /// A scan walked in a seeded order keeps a checkpoint the size of what is
    /// in flight, whatever the size of the plan.
    ///
    /// Every scan the engine starts is given a seed, and its answers arrive
    /// scattered across the plan. Counted in plan order alone, the watermark
    /// stays near zero and nearly everything settled waits above it: half of a
    /// plan of any size at the halfway mark, copied under the settlements' lock
    /// and written out on every checkpoint. Settled here in the walk's order,
    /// each batch shuffled as the dispatcher shuffles it, what waits has to
    /// stay under a batch's worth.
    #[test]
    fn a_walked_scan_checkpoints_what_is_in_flight_rather_than_what_it_settled() {
        use crate::journal::settle::Outcome;
        use crate::model::order::Permutation;
        use rand::seq::SliceRandom;

        const PLAN: u64 = 1 << 16;
        const BATCH: usize = 256;
        let (_session, ctx) = ScanSession::builder()
            .planning(Stage::Ports, Some(PLAN))
            .ordering(Some(0x5EED))
            .build();

        let walk: Vec<u64> = Permutation::new(0x5EED, PLAN).iter().collect();
        let mut rng = rand::rng();
        let mut most_waiting = 0;
        for batch in walk[..walk.len() / 2].chunks(BATCH) {
            let mut batch = batch.to_vec();
            batch.shuffle(&mut rng);
            for position in batch {
                ctx.record_outcome(Outcome::Answered { position });
            }
            most_waiting = most_waiting.max(ctx.settlements().checkpoint().settled_above.len());
        }

        assert_eq!(ctx.settlements().settled_count(), PLAN / 2);
        assert!(
            most_waiting < BATCH,
            "{most_waiting} settled positions waited in the checkpoint at once, \
             where a batch is {BATCH}"
        );
    }

    /// What a watcher is told and what a journal writes are two questions.
    ///
    /// An enrichment pass adding evidence to a host already announced answers
    /// `false`: there is nothing new to tell somebody watching a scan, and the
    /// echo probe says exactly that for a host the liveness pass already found.
    /// The record still moved, and a journal that took the same answer would
    /// give back a host missing whatever the pass learned.
    #[test]
    fn a_write_nobody_needs_announcing_is_still_a_write() {
        let ip: IpAddr = "192.0.2.1".parse().expect("an address");
        let (mut session, ctx) = ScanSession::new();

        // Found, announced, and written down.
        ctx.update_host(ip, |host| host.set_status(HostStatus::Up));
        assert_eq!(ctx.take_changed_hosts().len(), 1);
        assert!(
            session.events().try_recv().is_some(),
            "a new host is announced"
        );

        // And then enriched, which is worth writing and not worth announcing.
        ctx.write_host(ip, |host| {
            host.record_evidence(
                HostStatus::Up,
                StatusReason::new(StatusProtocol::IcmpEcho, "echo reply to an OS probe"),
            );
            false
        });

        let changed = ctx.take_changed_hosts();
        assert_eq!(
            changed.len(),
            1,
            "the record moved, so a journal has something to write"
        );
        assert!(
            changed[0]
                .reasons()
                .iter()
                .any(|reason| reason.protocol == StatusProtocol::IcmpEcho),
            "and what it writes is what the pass learned"
        );
        assert!(
            session.events().try_recv().is_none(),
            "a host already announced is not announced again"
        );
    }

    /// The bound, at the size the stream is built with.
    ///
    /// A scan emits an event per meaningful change, so a host with a thousand
    /// open ports announces itself a thousand times. Nothing here reads the
    /// stream until the writing is over, which is the case the bound exists
    /// for: the scan runs to the end, the store holds everything it found, and
    /// what the buffer could not keep is declared rather than dropped in
    /// silence.
    #[test]
    fn a_stream_nobody_reads_drops_the_oldest_and_says_how_many() {
        let flooded: IpAddr = "192.0.2.1".parse().expect("literal");
        let last: IpAddr = "192.0.2.2".parse().expect("literal");
        let (mut session, ctx) = ScanSession::new();

        let overflow = 64;
        let sent = ScanEvents::CAPACITY + overflow;
        for _ in 0..sent - 1 {
            ctx.update_host(flooded, |host| host.set_status(HostStatus::Up));
        }
        ctx.update_host(last, |host| host.set_status(HostStatus::Up));

        assert_eq!(
            ctx.store.len(),
            2,
            "a full event buffer does not stop the scan writing findings"
        );

        let mut dropped = 0u64;
        let mut delivered = Vec::new();
        while let Some(event) = session.events().try_recv() {
            match event {
                ScanEvent::EventsDropped { count } => dropped += count,
                ScanEvent::HostUpdated(ip) => delivered.push(ip),
                other => panic!("unexpected event {other:?}"),
            }
        }

        assert_eq!(
            delivered.len(),
            ScanEvents::CAPACITY,
            "the stream holds its stated capacity and no more"
        );
        assert_eq!(
            dropped as usize + delivered.len(),
            sent,
            "every event is either delivered or declared missing"
        );
        assert_eq!(
            delivered.last(),
            Some(&ScopedIp::unscoped(last)),
            "the newest event survives, which is what drop-oldest means"
        );
    }

    /// A scan with no budget answers `false` for every host, however many times
    /// it is asked, and files nothing.
    #[test]
    fn a_scan_with_no_host_budget_leaves_no_host() {
        let (_session, ctx) = ScanSession::new();
        let ip: IpAddr = "192.0.2.1".parse().expect("an address");

        assert!(!ctx.host_expired(ip));
        assert!(!ctx.host_expired(ip));
        assert!(ctx.take_timed_out().is_empty());
    }

    /// A spent budget is answered for every pass that asks, and the address is
    /// filed once however many of them do.
    #[test]
    fn a_spent_host_budget_is_filed_once() {
        let (_session, ctx) = ScanSession::builder()
            .host_timeout(Some(Duration::ZERO))
            .build();
        let ip: IpAddr = "192.0.2.1".parse().expect("an address");

        assert!(ctx.host_expired(ip));
        assert!(ctx.host_expired(ip));
        assert_eq!(ctx.take_timed_out(), vec![ip]);
    }

    /// A scan with no gap set answers every question with "now" and never
    /// touches the map, which is what makes it cheap enough to ask per probe.
    #[test]
    fn a_scan_with_no_gap_never_holds_a_probe() {
        let (_session, ctx) = ScanSession::new();
        let ip: IpAddr = "192.0.2.1".parse().expect("an address");
        let now = Instant::now();

        assert!(ctx.host_ready_at(ip, now).is_none());
        ctx.host_probed(ip, now);
        assert!(
            ctx.host_ready_at(ip, now).is_none(),
            "a recorded send moves nothing while there is no gap to move it against"
        );
    }

    /// The longest gap a caller can write holds a host's next probe past the
    /// end of any scan, not a panic: `Duration::MAX` after the last probe is
    /// past what a clock can count to.
    #[test]
    fn the_longest_gap_holds_a_host_rather_than_panicking() {
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(Duration::MAX))
            .build();
        let ip: IpAddr = "192.0.2.1".parse().expect("an address");
        let now = Instant::now();

        ctx.host_probed(ip, now);
        let ready = ctx.host_ready_at(ip, now).expect("asked too recently");
        assert!(ready > now + Duration::from_secs(365 * 24 * 60 * 60));
    }

    /// A host is ready until it is probed, and then not until the gap has run.
    ///
    /// The first half is what lets a sweep send a first attempt without
    /// consulting anything: an address this scan has never asked about has no
    /// earlier probe to be too close to.
    #[test]
    fn a_gap_starts_at_the_first_probe_and_runs_from_the_last() {
        let gap = Duration::from_secs(3600);
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(gap))
            .build();
        let ip: IpAddr = "192.0.2.1".parse().expect("an address");
        let now = Instant::now();

        assert!(
            ctx.host_ready_at(ip, now).is_none(),
            "an address nothing has probed is ready"
        );

        ctx.host_probed(ip, now);
        let ready = ctx.host_ready_at(ip, now).expect("asked too recently");
        assert_eq!(ready, now + gap);

        assert!(
            ctx.host_ready_at(ip, now + gap).is_none(),
            "the gap having run, the host is ready again"
        );
    }

    /// One host's gap says nothing about another's.
    ///
    /// The bound is per source and destination, which is the whole reason it is
    /// not `max_probe_rate`: a scan spaced at one address must not be spaced
    /// across the range.
    #[test]
    fn a_gap_at_one_host_leaves_every_other_host_ready() {
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(Duration::from_secs(3600)))
            .build();
        let probed: IpAddr = "192.0.2.1".parse().expect("an address");
        let other: IpAddr = "192.0.2.2".parse().expect("an address");
        let now = Instant::now();

        ctx.host_probed(probed, now);

        assert!(ctx.host_ready_at(probed, now).is_some());
        assert!(ctx.host_ready_at(other, now).is_none());
    }

    /// The clock starts on the first probe aimed at a host rather than when the
    /// phase did, so a host the scan has not reached yet still has its whole
    /// budget when it gets there.
    #[test]
    fn a_budget_still_running_leaves_the_host_alone() {
        let (_session, ctx) = ScanSession::builder()
            .host_timeout(Some(Duration::from_secs(3600)))
            .build();
        let ip: IpAddr = "192.0.2.1".parse().expect("an address");

        assert!(!ctx.host_expired(ip));
        assert!(ctx.take_timed_out().is_empty());
    }

    /// **A resume does not restore what this sitting is forbidden to report.**
    ///
    /// `Exclusions` promises that no excluded address appears in the report, and
    /// names the two places it is enforced. `restore_hosts` is a third way into
    /// the store, and one going through neither would let a scan interrupted
    /// before an exclusion was added bring the forbidden addresses back with it
    /// — under the operator's *current* configuration, in the engine's own
    /// continuation of its own scan.
    #[test]
    fn a_resume_leaves_out_an_address_this_sitting_may_not_report() {
        let excluded: IpAddr = "198.51.100.7".parse().expect("literal");
        let allowed: IpAddr = "203.0.113.7".parse().expect("literal");

        let mut ips = crate::model::ip::set::IpSet::new();
        ips.insert_range("198.51.100.0/24".parse().expect("a valid range"));
        let (mut session, ctx) = ScanSession::builder()
            .excluding(Exclusions::new(ips))
            .build();

        let restored = |ip: IpAddr| {
            let mut host = Host::new(ip);
            host.set_status(HostStatus::Up);
            host
        };
        ctx.restore_hosts(&[restored(excluded), restored(allowed)]);

        assert!(
            !ctx.store.contains_key(&ScopedIp::unscoped(excluded)),
            "the journal's own record of an excluded address must not come back"
        );
        assert!(
            ctx.store.contains_key(&ScopedIp::unscoped(allowed)),
            "and everything else still does"
        );
        assert_eq!(ctx.store.len(), 1);

        // One announcement, for the one host that was restored.
        let Some(ScanEvent::HostUpdated(announced)) = session.events().try_recv() else {
            panic!("a restored host is announced");
        };
        assert_eq!(announced.addr(), allowed);
        assert!(
            session.events().try_recv().is_none(),
            "an excluded address is not announced either"
        );
    }

    /// A session forbidding exactly `address`.
    fn forbidding(address: IpAddr) -> (ScanSession, ScanContext) {
        let mut ips = crate::model::ip::set::IpSet::new();
        ips.insert(address);
        ScanSession::builder()
            .excluding(Exclusions::new(ips))
            .build()
    }

    /// **What an edit attaches under a permitted key is held to the policy
    /// too.**
    ///
    /// The gate tests the key, and four callers add addresses inside the edit:
    /// the local sweep as a host's other replies arrive, listen mode merging a
    /// later sighting, hostname resolution folding in an mDNS record's other
    /// addresses, and the resume path. Every one of them passes the key, so a
    /// test of the key alone let an excluded address into the report beside it.
    #[test]
    fn an_address_an_edit_attaches_is_held_to_the_exclusions() {
        let key: IpAddr = "192.0.2.60".parse().expect("literal");
        let excluded: IpAddr = "192.0.2.61".parse().expect("literal");
        let (_session, ctx) = forbidding(excluded);

        ctx.write_host(key, |host| host.add_ip(excluded));

        let ips = ctx
            .read_host(key, |host| host.ips().clone())
            .expect("the permitted key is recorded");
        assert!(!ips.contains(&excluded), "{ips:?}");
        assert!(ips.contains(&key));
    }

    /// **An address filed as unreachable settles every target of the plan at
    /// it.** No route leading there is this machine's routing answering for
    /// the address, and a sweep that left it unsettled was listed as
    /// resumable when it had finished, and asked it again every sitting. A
    /// sweep settles the address; a port scan settles each of its ports, and
    /// one that earned a verdict first keeps it and is not counted twice.
    #[test]
    fn an_address_filed_unreachable_settles_its_targets() {
        use crate::model::ip::set::Positions;
        use crate::model::target::{TargetIndex, TargetMap, TargetSet};

        let unreachable: IpAddr = "192.0.2.2".parse().expect("literal");

        let sweep: IpSet = "192.0.2.1-192.0.2.3".parse().expect("a range");
        let (_session, ctx) = ScanSession::builder()
            .counting(Positions::of(&sweep))
            .build();
        ctx.record_unroutable(unreachable);
        ctx.record_unroutable(unreachable);
        let settled = ctx.settlements();
        assert!(
            settled.checkpoint().is_settled(1),
            "the address is still owed"
        );
        assert_eq!(settled.checkpoint().settled_count(), 1);
        assert_eq!(settled.count(Outcome::Unreachable { position: 0 }), 1);

        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(sweep, "1-3".parse().expect("ports")));
        let (_session, ctx) = ScanSession::new();
        ctx.number_targets(TargetIndex::of(&map));
        ctx.record_outcome(Outcome::Exhausted { position: 4 });
        ctx.record_unroutable(unreachable);
        let checkpoint = ctx.settlements().checkpoint();
        assert_eq!(
            (0..9)
                .filter(|position| checkpoint.is_settled(*position))
                .collect::<Vec<_>>(),
            [3, 4, 5],
            "the three ports of the second address, and nothing else"
        );
        assert_eq!(
            ctx.settlements()
                .count(Outcome::Unreachable { position: 0 }),
            2
        );
    }

    /// **A machine an exclusion names is withheld at every address it answers
    /// from.** A sweep of a LAN excluding a device's IPv4 address still heard
    /// the device answer the all-nodes echo and neighbour discovery from its
    /// IPv6 addresses, which no exclusion can aim at, and listed it there. The
    /// hardware address its excluded one answers from is what ties them, so a
    /// finding carrying it is dropped whole, the address is asked nothing
    /// more, and the phase lists it among what the policy left out. A
    /// neighbour with other hardware is kept, and so is its address.
    #[test]
    fn a_machine_an_exclusion_names_is_withheld_at_its_other_addresses() {
        use crate::model::mac::MacAddr;
        use crate::report::{ScanKind, TargetScope};
        use crate::scanner::recorder::PhaseRecorder;

        let excluded: IpAddr = "192.0.2.30".parse().expect("literal");
        let machine = MacAddr::new(0x02, 0, 0, 0, 0, 0x30);
        let neighbour_mac = MacAddr::new(0x02, 0, 0, 0, 0, 0x31);
        let (link_local, global, neighbour): (IpAddr, IpAddr, IpAddr) = (
            "2001:db8::30".parse().expect("literal"),
            "2001:db8::3030".parse().expect("literal"),
            "2001:db8::31".parse().expect("literal"),
        );
        let mut ips = IpSet::new();
        ips.insert(excluded);
        let (session, ctx) = ScanSession::builder()
            .excluding(Exclusions::new(ips))
            .with_neighbours(vec![(excluded, Some(machine))])
            .build();
        let mut scope_ips = IpSet::new();
        scope_ips.insert(neighbour);
        let recorder = PhaseRecorder::start(
            ScanKind::Discovery,
            crate::system::privilege::Privilege::Raw,
            TargetScope::from_ip_set(&mut scope_ips, &ctx.exclusions),
            &crate::config::ZondConfig::default(),
        );

        // An echo reply off the segment: the source address, and the frame's.
        let answered = |address: IpAddr, mac: MacAddr| {
            ctx.write_host(address, |host| {
                host.set_status(crate::model::host::HostStatus::Up);
                host.record_mac(mac);
                true
            });
        };
        answered(link_local, machine);
        answered(neighbour, neighbour_mac);
        // Found by address first, its hardware arriving with a later frame.
        ctx.update_host(global, |host| {
            host.set_status(crate::model::host::HostStatus::Up)
        });
        answered(global, machine);

        for address in [link_local, global] {
            assert!(
                session.hosts().get(address).is_none(),
                "{address} answered from the excluded machine and was recorded"
            );
            assert!(!ctx.may_probe(&address), "{address} may still be asked");
        }
        assert!(session.hosts().get(neighbour).is_some());
        assert!(ctx.may_probe(&neighbour));

        let report = recorder.finish(&ctx);
        let listed: Vec<IpAddr> = report.phases()[0]
            .targets()
            .excluded()
            .iter()
            .map(|range| range.start_addr())
            .collect();
        for address in [excluded, link_local, global] {
            assert!(listed.contains(&address), "{address} not in {listed:?}");
        }
    }

    /// An excluded address never leads a host, which is the half that matters
    /// most: the address a host leads with is the one the service, SNMP, TLS
    /// and detection passes connect to. A global IPv6 address outranks a
    /// link-local, so one attached to a neighbour found at its link-local would
    /// take the lead from it.
    #[test]
    fn an_excluded_address_does_not_become_the_one_a_host_is_reached_at() {
        let key: IpAddr = "fe80::10".parse().expect("literal");
        let excluded: IpAddr = "2001:db8::5".parse().expect("literal");
        let (_session, ctx) = forbidding(excluded);

        ctx.write_host(key, |host| host.consider_primary_ip(excluded));

        let (primary, ips) = ctx
            .read_host(key, |host| (host.primary_ip(), host.ips().clone()))
            .expect("the permitted key is recorded");
        assert_eq!(primary, key, "led by the address the policy allows");
        assert!(!ips.contains(&excluded), "{ips:?}");
    }

    /// A path three routers long, whose second router is `router`.
    fn traced_through(target: IpAddr, router: IpAddr) -> [Hop; 3] {
        [
            Hop::answered(
                1,
                "203.0.113.1".parse().expect("literal"),
                Some(Duration::from_millis(1)),
            ),
            Hop::answered(2, router, Some(Duration::from_millis(4))),
            Hop::answered(3, target, None),
        ]
    }

    /// **A router the policy forbids keeps its distance on a traced host's
    /// path and loses its address.**
    ///
    /// A trace addresses nothing to the routers on the way: each hop is a
    /// router discarding a probe addressed to the host being traced. So the
    /// sending half of the policy holds for them without help, and the
    /// recording half is the one a path can break. The router answered, so
    /// the distance is not silent, and it is not dropped either, since a path
    /// with no entry where a router stood reads as though nothing were known
    /// there. What goes is everything that is about the router itself.
    #[test]
    fn a_router_the_exclusions_forbid_is_withheld_from_a_traced_hosts_path() {
        let target: IpAddr = "203.0.113.9".parse().expect("literal");
        let excluded: IpAddr = "198.51.100.1".parse().expect("literal");
        let (_session, ctx) = forbidding(excluded);

        ctx.write_host(target, |host| {
            for hop in traced_through(target, excluded) {
                host.record_hop(hop);
            }
            true
        });

        let path = ctx
            .read_host(target, |host| host.path().clone())
            .expect("the traced host is recorded");
        assert!(
            path.hops()
                .iter()
                .all(|hop| hop.address() != Some(excluded)),
            "{path:?}"
        );
        let at_two = path.hops()[1];
        assert_eq!(at_two.distance(), 2, "the router keeps its place");
        assert!(at_two.is_withheld(), "a router answered there: {at_two:?}");
        assert_eq!(at_two.rtt(), None, "its timing is a fact about the router");
        assert_eq!(path.length(), Some(3));
        assert_eq!(path.at(1), Some("203.0.113.1".parse().expect("literal")));
    }

    /// And a journal written before the router was excluded does not bring it
    /// back, since the resume path reaches the store without `write_host`.
    #[test]
    fn a_resume_withholds_a_router_this_sitting_may_not_report() {
        let target: IpAddr = "203.0.113.9".parse().expect("literal");
        let excluded: IpAddr = "198.51.100.1".parse().expect("literal");
        let (_session, ctx) = forbidding(excluded);

        let mut journalled = Host::new(target);
        for hop in traced_through(target, excluded) {
            journalled.record_hop(hop);
        }
        ctx.restore_hosts(&[journalled]);

        let path = ctx
            .read_host(target, |host| host.path().clone())
            .expect("the host is restored");
        assert!(
            path.hops()
                .iter()
                .all(|hop| hop.address() != Some(excluded)),
            "{path:?}"
        );
        assert!(path.hops()[1].is_withheld(), "{path:?}");
    }

    /// A host-down reason sent by `sender` rather than by the host it is about.
    fn unreachable_from(sender: IpAddr) -> StatusReason {
        StatusReason::new(StatusProtocol::IcmpUnreachable, "destination unreachable")
            .from_source(sender)
    }

    /// **A middlebox the policy forbids is withheld from the evidence it sent
    /// about a permitted host, and the evidence is kept.**
    ///
    /// An ICMP unreachable about a probed host arrives from whatever router or
    /// firewall stood in the way, which nothing addressed. Its sender is the
    /// same kind of claim as a router on a traced path, and the policy holds for
    /// it the same way: the finding is about the host and stays, and the address
    /// that sent it goes. Cleared rather than withheld, the reason would say the
    /// host answered for itself, which is the one reading a middlebox's message
    /// must never be given.
    #[test]
    fn an_excluded_middlebox_is_withheld_from_a_permitted_hosts_evidence() {
        let target: IpAddr = "203.0.113.9".parse().expect("literal");
        let excluded: IpAddr = "198.51.100.1".parse().expect("literal");
        let (_session, ctx) = forbidding(excluded);

        ctx.write_host(target, |host| {
            host.record_evidence(HostStatus::Down, unreachable_from(excluded));
            true
        });

        let (status, reasons) = ctx
            .read_host(target, |host| (host.status(), host.reasons().clone()))
            .expect("the host the evidence is about is recorded");
        assert_eq!(status, HostStatus::Down, "the evidence still counts");
        let sources: Vec<EvidenceSource> = reasons.iter().map(|reason| reason.source).collect();
        assert_eq!(sources, [EvidenceSource::Withheld], "{reasons:?}");
    }

    /// And a journal written before the middlebox was excluded does not bring
    /// its address back, since the resume path reaches the store without
    /// `write_host`.
    #[test]
    fn a_resume_withholds_a_middlebox_this_sitting_may_not_report() {
        let target: IpAddr = "203.0.113.9".parse().expect("literal");
        let excluded: IpAddr = "198.51.100.1".parse().expect("literal");
        let (_session, ctx) = forbidding(excluded);

        let mut journalled = Host::new(target);
        journalled.record_evidence(HostStatus::Down, unreachable_from(excluded));
        ctx.restore_hosts(&[journalled]);

        let sources: Vec<EvidenceSource> = ctx
            .read_host(target, |host| {
                host.reasons().iter().map(|reason| reason.source).collect()
            })
            .expect("the host is restored");
        assert_eq!(sources, [EvidenceSource::Withheld]);
    }

    /// The resume path, which writes into the store without going through
    /// `write_host`, holds a restored host's other addresses to the policy as
    /// well as the one it is keyed by.
    #[test]
    fn a_resume_brings_back_none_of_a_hosts_excluded_addresses() {
        let key: IpAddr = "192.0.2.60".parse().expect("literal");
        let excluded: IpAddr = "192.0.2.61".parse().expect("literal");
        let (_session, ctx) = forbidding(excluded);

        let mut host = Host::new(key);
        host.add_ip(excluded);
        ctx.restore_hosts(&[host]);

        let ips = ctx
            .read_host(key, |host| host.ips().clone())
            .expect("the host is restored");
        assert!(!ips.contains(&excluded), "{ips:?}");
    }

    /// And a host an earlier sitting recorded under an address excluded since
    /// is restored under its best remaining one, rather than dropped along with
    /// every address it was found at that the policy still allows.
    #[test]
    fn a_resumed_host_led_by_an_excluded_address_is_kept_at_its_others() {
        let other: IpAddr = "fe80::10".parse().expect("literal");
        let excluded: IpAddr = "2001:db8::5".parse().expect("literal");
        let (_session, ctx) = forbidding(excluded);

        let mut host = Host::new(other);
        host.consider_primary_ip(excluded);
        host.set_status(HostStatus::Up);
        assert_eq!(host.primary_ip(), excluded, "test premise");
        ctx.restore_hosts(&[host]);

        let (primary, ips) = ctx
            .read_host(other, |host| (host.primary_ip(), host.ips().clone()))
            .expect("the host is kept at the address the policy allows");
        assert_eq!(primary, other);
        assert!(!ips.contains(&excluded), "{ips:?}");
    }

    /// **A port scan's settlements count port targets, not the addresses its
    /// liveness pass left.** Its plan is numbered in address-and-port pairs, so
    /// three hundred addresses a stopped pass never asked are not three
    /// hundred port targets never asked. A sweep's plan is its addresses, and
    /// there they count.
    #[test]
    fn a_liveness_pass_leaves_a_port_scans_counters_alone() {
        let (_session, ports) = ScanSession::builder()
            .planning(Stage::Ports, Some(1_024))
            .build();
        ports.record_address_outcomes(Outcome::Unasked, 300);
        assert_eq!(ports.settlements().count(Outcome::Unasked), 0);

        let (_session, sweep) = ScanSession::builder()
            .planning(Stage::Discovery, Some(1_024))
            .build();
        sweep.record_address_outcomes(Outcome::Unasked, 300);
        assert_eq!(sweep.settlements().count(Outcome::Unasked), 300);
    }
}
