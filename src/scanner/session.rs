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
//! [`ScanSession::new`] hands out two halves that share one store:
//!
//! - [`ScanSession`] is the reading half, for whoever asked for the scan: the
//!   hosts found so far ([`HostStore`]), the stream saying when that changed
//!   ([`ScanEvents`]), and the means to stop ([`ScanHandle`]).
//! - [`ScanContext`] is the writing half, for the strategies. Every scanner is
//!   built with one, and findings, failures and probe counters enter the scan
//!   through it.
//!
//! ## The writing half
//!
//! Every host finding goes through [`ScanContext::write_host`]. It takes the
//! store's guard, runs the caller's edit under it, drops the guard, and only then
//! announces the change, so the map is never locked across a channel send. The
//! map itself stays private, which also keeps a third-party concurrency crate out
//! of this crate's semver.
//!
//! ## What a host is keyed by
//!
//! A [`ScopedIp`]: the address it is reported under, plus the interface it was
//! read on where it needs one. Every IPv4 address and every routable IPv6 one is
//! the bare address, since a machine at a global address is the same machine
//! through whichever interface answered.
//!
//! An IPv6 link-local is why the key exists. `fe80::1` names a different machine
//! on every segment, so a host watching two segments can find two neighbours
//! under one number. Keyed by the bare address, one machine's hardware address,
//! roles and round trips would be folded into the other's record.
//!
//! Three rules follow:
//!
//! - **A host takes its link from its key.** [`ScanContext::write_host`] records
//!   the zone when it creates a host.
//! - **A key read from the store writes back to the store.**
//!   [`ScanContext::host_addresses`] hands out keys, and a strategy that reads a
//!   host and writes a finding back carries the key. A bare address written back
//!   would create a second entry, splitting one host in two.
//! - **A bare link-local finds nothing.** [`HostStore::get`] answers `None` for
//!   one, since it is ambiguous. Consumers get the whole key from
//!   [`ScanEvent::HostUpdated`], which is meant to be handed straight back to the
//!   store.
//!
//! ## Failures are written down twice
//!
//! Once to the event stream for a consumer watching, and once to a log the
//! report drains at the end, so a caller that only awaits the scan can still
//! tell an empty network from a strategy that never started.

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
use crate::report::{Attachment, AttachmentSource, Pass, ProbeStats, Refusal, ScannerFailure};
use crate::scanner::handle::ScanHandle;

/// What a scan is working on.
///
/// After the sweep settles its plan, a tail of different jobs runs over what it
/// found: identifying services, running detections, reading a stack for an
/// operating system, tracing a path. The tail often takes several times as long
/// as the sweep, so progress measured on the plan alone would show a finished
/// bar for most of a run.
///
/// Each stage announces itself as it begins, through [`ScanEvent::StageChanged`],
/// and [`Progress::stage`] answers which one is current. Some know their size
/// when they start; the rest report only that they are running.
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
    /// Characterising the filter in front of each host that answered.
    Filters,
    /// Asking each host that answered which IP protocols its stack takes.
    IpProtocols,
    /// Reading a link, which ends when the caller says so.
    Listening,
    /// The correlating and record keeping left once the probing is over.
    Finishing,
}

impl Stage {
    /// Every stage this build knows, in the order a scan runs them.
    ///
    /// As with [`ScanKind::ALL`](crate::report::ScanKind::ALL), the enum is
    /// `#[non_exhaustive]`, so a front end that maps stages onto a protocol of
    /// its own uses this to check that it covered them all.
    pub const ALL: &'static [Self] = &[
        Self::Discovery,
        Self::Ports,
        Self::Services,
        Self::Detections,
        Self::Tls,
        Self::Os,
        Self::Traceroute,
        Self::Filters,
        Self::IpProtocols,
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
            Stage::Filters => 7,
            Stage::IpProtocols => 8,
            Stage::Listening => 9,
            Stage::Finishing => 10,
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
            7 => Stage::Filters,
            8 => Stage::IpProtocols,
            9 => Stage::Listening,
            10 => Stage::Finishing,
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
            Stage::Filters => "filters",
            Stage::IpProtocols => "ip protocols",
            Stage::Listening => "listening",
            Stage::Finishing => "finishing",
        };

        f.write_str(name)
    }
}

/// Which stage a scan is in and how far through it.
///
/// Atomics, because this is written from every probing task and read eight
/// times a second by whatever is drawing. They are not updated as a group, so a
/// reader can catch a new stage against a count that has not caught up. That
/// costs one frame of a progress line, and is why reports are not built from
/// this.
#[derive(Debug, Default)]
pub(crate) struct Stages {
    current: AtomicU8,
    done: AtomicU64,
    total: AtomicU64,
    /// The stages this scan expects to run, in the order it runs them.
    planned: Vec<Stage>,
    /// How many of those are behind it, which only ever grows.
    reached: AtomicUsize,
    /// The furthest [`overall`](Self::overall) has reported, as the position
    /// and total it reported it in.
    ///
    /// A stage's size is not always known when it begins: service detection
    /// learns the size of its second protocol's run only when that run starts,
    /// so a later reading can be lower than an earlier one. What a caller was
    /// shown stands until the work catches up with it, so the bar never steps
    /// back. Behind a lock, since only the readers touch it.
    shown: Mutex<(u64, u64)>,
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
    /// `within` is how far through the current stage it is. The pair comes back
    /// scaled to whole numbers, so a caller dividing in integers gets cells and a
    /// percentage that agree.
    fn overall(&self, within: Option<(u64, u64)>) -> Option<(u64, u64)> {
        let stages = u64::try_from(self.planned.len()).ok().filter(|n| *n > 0)?;
        let reached = u64::try_from(self.reached.load(Ordering::Relaxed)).unwrap_or(0);

        // In a stage the scan did not plan, every counted stage is behind it.
        let reading = match within.filter(|_| self.planned.contains(&self.stage())) {
            Some((done, total)) => (reached * total + done.min(total), stages * total),
            None => (reached.min(stages), stages),
        };

        let mut shown = self.shown.lock().unwrap_or_else(|held| held.into_inner());
        let behind = u128::from(reading.0) * u128::from(shown.1)
            < u128::from(shown.0) * u128::from(reading.1);
        if shown.1 == 0 || !behind {
            *shown = reading;
        }
        Some(*shown)
    }

    /// Moves to `stage`, answering whether that was a change worth announcing.
    ///
    /// Entering the stage already current adds to its total, for service
    /// detection, which runs once per protocol.
    fn enter(&self, stage: Stage, total: Option<u64>) -> bool {
        let total = total.unwrap_or(0);

        // How many planned stages this one comes after, by declaration order,
        // which is run order. A planned stage with no work is stepped over.
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
    /// The event carries only the address, since a scan can emit thousands.
    /// Read the current state back from [`ScanSession::hosts`], a single lookup
    /// that is always up to date.
    HostUpdated(ScopedIp),

    /// A scanning strategy failed to start or terminated abnormally. The scan
    /// continues with the strategies that remain, so results may be incomplete.
    ScannerFailed {
        /// The strategy that failed.
        scanner: ScannerKind,
        /// A human-readable description of the failure.
        reason: String,
    },

    /// The scan has moved on to another [`Stage`].
    ///
    /// Read [`ScanSession::progress`] for how far through the stage it is; that
    /// figure moves far faster than stages change.
    StageChanged {
        /// What the scan is working on now.
        stage: Stage,
    },

    /// The stream ran ahead of this consumer, and `count` events were dropped
    /// to make room for newer ones.
    ///
    /// Delivered in the position the missing events would have had, so a
    /// consumer knows where its picture went incomplete. [`ScanEvents`] says
    /// what the gap costs and what to do about it.
    EventsDropped {
        /// How many events were dropped.
        count: u64,
    },
}

/// What a scan has found so far, readable while it is still running.
///
/// A cheap, cloneable view of one shared store. Every clone reads the same live
/// data, so a consumer can hand one to a rendering task and keep another.
///
/// Reads return owned snapshots: [`get`](Self::get) clones the host, so no
/// guard is held while scanners keep writing to the same key.
/// [`read`](Self::read) borrows under the guard for cheap lookups.
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
    /// An IPv6 link-local needs the interface it was read on: `fe80::1` names a
    /// different machine on every segment, so a bare one answers `None`. Pass
    /// the [`ScopedIp`] the event carried. Any other address is a whole key on
    /// its own, so a plain [`IpAddr`] works.
    pub fn get(&self, ip: impl Into<ScopedIp>) -> Option<Host> {
        self.inner
            .get(&ip.into())
            .map(|entry| entry.value().clone())
    }

    /// Reads the host at `ip` without cloning it, if there is one.
    ///
    /// Use this inside an event loop. A port scan fires
    /// [`HostUpdated`](ScanEvent::HostUpdated) once per port, so answering each
    /// event with [`get`](Self::get) clones a growing port map every time, which
    /// is quadratic in the size of the scan. Read what the event needs here, and
    /// clone only a host worth rendering.
    ///
    /// `read` runs under the store's guard. It must not touch the store again,
    /// which deadlocks, and should not block, since a scanner writing to the
    /// same host waits behind it.
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
    /// A point-in-time copy. Ordered so two reads of the same data compare
    /// equal, as [`ScanReport`](crate::report::ScanReport) orders its hosts.
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
    /// For tests that need a store already holding a host. A scan records
    /// findings through [`ScanContext::write_host`], which merges and announces.
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
/// The stream holds [`CAPACITY`](Self::CAPACITY) events, and a scan that fills
/// it overwrites the oldest. A caller who never reads it costs the scan one
/// fixed buffer, and a slow reader never holds the scan up.
///
/// The read after a gap answers [`ScanEvent::EventsDropped`] with how many
/// events went missing.
///
/// A gap loses notices, not findings. A dropped
/// [`HostUpdated`](ScanEvent::HostUpdated) named a host whose current state is
/// in the [`HostStore`], so after a gap, re-read the store. A dropped
/// [`ScannerFailed`](ScanEvent::ScannerFailed) still reaches the
/// [`ScanReport`](crate::report::ScanReport), which carries every failure.
#[derive(Debug)]
pub struct ScanEvents {
    rx: broadcast::Receiver<ScanEvent>,
}

impl ScanEvents {
    /// How many events the stream holds for a consumer that has not caught up.
    ///
    /// The buffer is allocated when the scan starts.
    pub const CAPACITY: usize = 1024;

    /// Waits for the next event. `None` once the scan has ended and every event
    /// it emitted has been taken.
    ///
    /// Falling behind arrives as [`ScanEvent::EventsDropped`], in the position
    /// the missing events would have had, and the stream carries on with the
    /// oldest event it still holds.
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
/// against, cheap enough to read on every frame: a read is a pair of atomic
/// loads and one short lock.
///
/// [`settled`](Self::settled) counts what the strategies have finished with, on
/// every scan, journalled or not. [`planned`](Self::planned) is the size of the
/// plan, known only where the targets can be numbered: an IPv6 range of a `/64`
/// or wider cannot be, and a [`listen`](crate::listen) session has no plan.
/// Where the plan cannot be counted, [`fraction`](Self::fraction) answers
/// `None`, and a front end can show a running count.
///
/// A scan that runs to the end settles every target in its plan and the
/// fraction reaches 1.0. One stopped early leaves it short.
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
    /// A unit is counted once the stage is done with it, whatever the result.
    /// One passed over because its host had spent its budget or the scan was
    /// stopped is not, so a stage can end short of its total.
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
    /// not counted.
    pub fn settled(&self) -> u64 {
        self.settlements.settled_count()
    }

    /// How many targets the plan holds, or `None` for a plan whose targets
    /// cannot all be numbered.
    ///
    /// Fixed for the life of the scan. A resumed sitting reports the size of the
    /// whole job, matching [`settled`](Self::settled).
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
    /// A stage that counted itself answers for itself. The stage the plan was
    /// drawn for answers with what the plan has settled, including a resumed
    /// sitting's earlier work. Any other stage that never learned its size
    /// answers `None`. That includes a port scan's liveness pass, which settles
    /// none of the plan's address-and-port pairs.
    ///
    /// The plan's figure counts the work of probing, so a target settled without
    /// a probe counts on neither side: one whose host the liveness pass found
    /// silent, one the exclusions withhold, one no route leads to, and one on a
    /// host with no verdict, left for a later sitting. Those settle as fast as
    /// the walk passes them; counted as work, a range with five live hosts
    /// behind a thousand ports would read nearly finished within a second.
    ///
    /// An empty stage is complete, and the result is capped at 1.0.
    pub fn fraction(&self) -> Option<f64> {
        let (done, total) = self.counted()?;

        Some(ratio(done, total))
    }

    /// Where the scan stands across every stage it expects to run, as a position
    /// over a total.
    ///
    /// One figure for a whole run, so a bar drawn from it fills once. It only
    /// moves forward: an expected stage with nothing to do is stepped over, so
    /// the figure can jump, and a stage that grows after it began, as service
    /// detection does when its second protocol's run starts, holds the figure
    /// until the work catches up. It reads whole only once the last expected
    /// stage is behind the scan.
    ///
    /// The expected stages are a superset: whether services, detections and TLS
    /// have anything to do depends on the ports found.
    ///
    /// `None` for a session that was never told which stages to expect. See
    /// [`SessionBuilder::staging`].
    pub fn overall(&self) -> Option<(u64, u64)> {
        self.stages.overall(self.counted())
    }

    /// The two figures [`fraction`](Self::fraction) divides.
    ///
    /// For a bar of a fixed number of cells: dividing in integers keeps the cells
    /// and the percentage agreeing, where one `f64` can round a bar full beside
    /// a figure that reads 99%.
    pub fn counted(&self) -> Option<(u64, u64)> {
        match self.stage_total() {
            Some(total) => Some((self.stage_done(), total)),
            None if self.stage() == self.plan_stage => {
                let planned = self.planned?;
                let settlements = &self.settlements;
                let unprobed = settlements.count(Outcome::Skipped { position: 0 })
                    + settlements.count(Outcome::Withheld { position: 0 })
                    + settlements.count(Outcome::Unreachable { position: 0 });
                let undecided = settlements.count(Outcome::Undecided);
                Some((
                    self.settled().saturating_sub(unprobed),
                    planned.saturating_sub(unprobed + undecided),
                ))
            }
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
/// This describes the present moment and keeps no history.
///
/// Dropping it stops nothing. Dropping the task stops the scan; see
/// [`ScanTask`](crate::scanner::ScanTask#dropping-it-stops-the-scan).
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
    /// runs it can hold more: a port scan with no liveness pass files a record
    /// at every address it asks and drops the silent ones when its ports are
    /// done, so an event naming such an address may find no host. See
    /// [`ScanPhase::silent`](crate::report::ScanPhase::silent).
    pub fn hosts(&self) -> &HostStore {
        &self.store
    }

    /// The live event stream.
    ///
    /// Bounded: a consumer that reads it slowly, or not at all, loses the
    /// oldest events. See [`ScanEvents`].
    pub fn events(&mut self) -> &mut ScanEvents {
        &mut self.events
    }

    /// The control handle, which is how a scan is stopped early.
    pub fn handle(&self) -> &ScanHandle {
        &self.handle
    }

    /// How far the scan has got through its plan.
    ///
    /// Cloneable, so a caller rendering a scan elsewhere can take a copy. See
    /// [`Progress`].
    pub fn progress(&self) -> &Progress {
        &self.progress
    }

    /// Takes the session apart, for a caller that wants to watch the events from
    /// one task and read the hosts from another.
    ///
    /// [`HostStore`], [`ScanHandle`] and [`Progress`] are cloneable, so this is
    /// only needed to move the event stream, of which there is one.
    pub fn into_parts(self) -> (HostStore, ScanEvents, ScanHandle, Progress) {
        (self.store, self.events, self.handle, self.progress)
    }
}

/// Where an instrumented scanner leaves its counters for the final
/// [`ScanReport`](crate::report::ScanReport).
///
/// A scanner reports its audit as its receive loop exits, well before the scan
/// is over and after the strategy is consumed, so the counters wait here.
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
/// The service phase draws a first-contact banner and any probe replies to name
/// the service. They are kept here, keyed by port, and *taken* by the detection
/// phase, so a response body is held only across the two adjacent phases.
///
/// # A port a sitting inherits
///
/// Responses live in memory only and end with their sitting, while the port
/// comes back to the next sitting settled and is not probed again. Such a port
/// is [`lost`](Self::lost) here until this sitting identifies it again; a
/// passive detection run over it before then concludes nothing. A strategy that
/// identifies ports over the connection that finds them has no second pass, so
/// it asks the inherited ones in one; see
/// [`service::detect_inherited`](crate::scanner::service::detect_inherited).
///
/// Response bodies stay out of the journal, which records findings. A raw
/// scan's second pass identifies every open port of a host a resume owes its
/// passes anyway. Holding back the port's settlement until its detections ran
/// would make a sitting killed during its passes probe its whole plan again.
#[derive(Default)]
pub(crate) struct Responses {
    inner: DashMap<(ScopedIp, u16, Protocol), Vec<String>>,
    /// The open ports an earlier sitting identified that this one has not.
    lost: DashMap<(ScopedIp, u16, Protocol), ()>,
}

impl Responses {
    /// Records what the service phase gathered for one port. An empty set is not
    /// stored. Either way the port is identified in this sitting, and so no
    /// longer [`lost`](Self::lost).
    fn record(&self, ip: ScopedIp, number: u16, protocol: Protocol, banners: Vec<String>) {
        let key = (ip, number, protocol);
        self.lost.remove(&key);
        if !banners.is_empty() {
            self.inner.insert(key, banners);
        }
    }

    /// Notes that an earlier sitting drew this port's responses and they
    /// ended with it.
    fn inherit(&self, ip: ScopedIp, number: u16, protocol: Protocol) {
        self.lost.insert((ip, number, protocol), ());
    }

    /// Whether this port's responses ended with an earlier sitting and this
    /// one has drawn none since.
    fn lost(&self, ip: &ScopedIp, number: u16, protocol: Protocol) -> bool {
        self.lost.contains_key(&(ip.clone(), number, protocol))
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
/// drained into the journal by the checkpoint task. A plain queue: a tape is
/// appended once and taken in a batch.
///
/// Kept only once something will take them, which is whatever holds the scan's
/// [`ScanProgress`]. Otherwise every port's responses would be held for each
/// detection that read them until the scan ended.
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

    /// Puts back `runs` a journal took and could not write, ahead of any
    /// captured since, so the next take hands them over again in the order
    /// they ran.
    #[cfg(feature = "journal-format")]
    fn hand_back(&self, mut runs: Vec<DetectionRunRecord>) {
        if runs.is_empty() {
            return;
        }
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        runs.append(&mut inner);
        *inner = runs;
    }
}

/// Ground a phase declined to cover, gathered as it is decided.
///
/// Kept apart from [`FailureLog`]: a failure is a fault, while a refusal means
/// the scan as written cannot answer part of what it was asked. See
/// [`Refusal`].
///
/// Kept in insertion order, which is the order the plan works through the
/// targets.
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
/// Kept apart from [`FailureLog`]: a failed strategy makes the result partial,
/// while an unreachable address is an ordinary fact, such as a dual-stack name
/// on a single-stack network, and says nothing about the rest of the scan.
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
/// Like [`TimedOutLog`], it qualifies what the phase covered. A set, so a host
/// two scanners flag is named once.
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

/// The passes a stop skipped or cut short, gathered across a phase.
///
/// A set, since several strategies run the same pass: the OS pass is three
/// separate probes, and a stop that cuts all three cut one pass.
#[derive(Debug, Default)]
pub(crate) struct PassLog {
    entries: Mutex<std::collections::BTreeSet<Pass>>,
}

impl PassLog {
    fn insert(&self, pass: Pass) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.insert(pass);
    }

    fn drain(&self) -> Vec<Pass> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *entries).into_iter().collect()
    }
}

/// Addresses whose own budget ran out, gathered across a phase.
///
/// Like [`UnroutableLog`], it records what the phase did not finish covering
/// and is not a fault. A set, so a host left early by three passes is named
/// once.
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
/// Tells a host found down from one the pass reached no verdict on. A port
/// scan's port phase settles only the first as
/// [`Skipped`](crate::journal::settle::Outcome::Skipped), and every discovery
/// phase names the second in
/// [`ScanPhase::undecided`](crate::report::ScanPhase::undecided). A host
/// missing from the live set proves neither, since a pass that stopped early,
/// had no strategy for a range or was refused it also leaves hosts out.
///
/// It records positive evidence, so any unrecorded way of failing to ask
/// fails safe: the host is asked again on a resume.
///
/// One range per address until merged, so it is merged whenever the additions
/// since the last merge outgrow what that merge left. A pass walking a
/// permutation merges little until nearly done, which bounds this at one range
/// per silent address.
#[derive(Debug, Default)]
pub(crate) struct SilenceLog {
    entries: Mutex<Silence>,
}

/// The set behind [`SilenceLog`], and what decides when it is next merged.
#[derive(Debug, Default)]
struct Silence {
    set: IpSet,
    /// How many ranges the last merge left; the next merge waits for the
    /// additions to outgrow it.
    merged: usize,
    added: usize,
}

impl SilenceLog {
    /// The fewest additions worth a merge, so a small pass is merged once, on
    /// the way out.
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
/// Held as ranges, because it is filled with whole groups a strategy was
/// handed, and a tunnel's own subnet can be a `/23`. Merged on the way out, so
/// a range two strategies both reported is named once.
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

    fn drain(&self, unreached: &[IpAddr]) -> Vec<IpRange> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut taken = std::mem::take(&mut *entries);
        taken.canonicalize();
        if !unreached.is_empty() {
            let mut unreached_set = IpSet::new();
            for address in unreached {
                unreached_set.insert(*address);
            }
            unreached_set.canonicalize();
            taken.subtract(&unreached_set);
        }
        let v4 = taken.v4().iter().copied().map(IpRange::V4);
        let v6 = taken.v6().iter().copied().map(IpRange::V6);
        v4.chain(v6).collect()
    }
}

/// When each host's wall-clock budget started, for a scan given one.
///
/// A host's clock starts on the first probe aimed at it, since a shuffled scan
/// of a wide range may reach an address late, and a budget counted from the
/// start of the run would leave the last address no time.
///
/// `budget` is `None` for a scan that set no per-host bound, the usual case;
/// the map is then never written to.
///
/// ## What it costs
///
/// One instant per address the scan probes, a fraction of the [`Host`] the
/// store already keeps for that address.
#[derive(Debug, Default)]
pub(crate) struct HostClocks {
    budget: Option<Duration>,
    started: DashMap<IpAddr, Instant>,
}

/// The gaps the scan keeps between the probes it sends: between two aimed at
/// one host, and between any two at all.
///
/// Like [`HostClocks`], it lives on the context every pass holds, because a
/// bound on the scan's traffic belongs to the scan: with a copy per strategy,
/// two passes probing at once would each allow the whole gap.
///
/// Both gaps are `None` for a scan that set neither, the usual case; nothing is
/// then locked or stored.
///
/// ## Claiming
///
/// [`claim`](Self::claim) decides whether a probe may leave and records that it
/// did in one operation, under the locks both gaps are kept behind. A separate
/// check and record would let two concurrent senders (two port scanners on one
/// host, or a connect scan's probe tasks) both find the slot free and both send.
///
/// The clock is read after the locks are taken, so an instant recorded here is
/// never earlier than one recorded before it.
///
/// The gap is kept between the moments probes are released to the kernel. A
/// probe released late can land nearer the next one than the gap by the send's
/// own latency, which this gate cannot see.
///
/// ## Refunds
///
/// A probe the kernel refused reached nobody and must not spend a slot, as
/// `RawProbeScan::record_send` keeps it out of the congestion window.
/// [`refund`](Self::refund) puts back the slot a claim took, unless a later
/// claim has been recorded over it; then the only cost is a gap longer than
/// asked for.
///
/// ## What it costs
///
/// One instant pair per address the scan probes, as for [`HostClocks`]. The two
/// are separate types because a budget starts a clock once per target, while a
/// gap moves one on every probe.
#[derive(Debug, Default)]
pub(crate) struct ProbeSpacing {
    per_host: Option<Duration>,
    scan_wide: Option<Duration>,
    last_at_host: DashMap<IpAddr, Slot>,
    last_anywhere: Mutex<Option<Slot>>,
}

/// The last slot taken on one of [`ProbeSpacing`]'s clocks, and the one before
/// it, which is what a refund restores.
#[derive(Debug, Clone, Copy)]
struct Slot {
    at: Instant,
    before: Option<Instant>,
}

impl Slot {
    /// The slot taken at `at`, over whatever `previous` held.
    fn after(previous: Option<Slot>, at: Instant) -> Self {
        Self {
            at,
            before: previous.map(|slot| slot.at),
        }
    }

    /// When a probe may next leave under `gap`, or `None` if it may now.
    fn ready_at(slot: Option<Slot>, gap: Option<Duration>, now: Instant) -> Option<Instant> {
        let ready = crate::scanner::pacing::timer::later(slot?.at, gap?);
        (ready > now).then_some(ready)
    }

    /// What is left on the clock once the slot taken at `at` is given back:
    /// the one before it, or nothing. `None` for a slot recorded over since,
    /// which is kept.
    fn refunded(self, at: Instant) -> Option<Option<Slot>> {
        (self.at == at).then(|| {
            self.before.map(|before| Slot {
                at: before,
                before: None,
            })
        })
    }
}

/// A slot [`ScanContext::claim_probe`] or [`ScanContext::claim_group_probe`]
/// handed out: the address a probe may now be sent to, and the instant it was
/// allowed to leave.
///
/// A caller whose send the kernel refuses gives the slot back with
/// [`ScanContext::refund_probe`]. Dropping it spends the slot.
#[must_use = "a claim is a slot the scan has spent; a refused send gives it back with refund_probe"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeClaim {
    address: IpAddr,
    at: Instant,
    /// Whether the slot was taken on `address`'s own clock as well as the
    /// scan's. False for a frame sent to a group, which has no host clock.
    at_host: bool,
}

impl ProbeClaim {
    /// The address the claimed probe is aimed at: one host's, or for a
    /// [group probe](ScanContext::claim_group_probe) the group's.
    pub fn address(&self) -> IpAddr {
        self.address
    }
}

/// The scan's own gate, as the connections and datagrams it opens through
/// [`Egress`](crate::transport::dial::Egress) ask it; see
/// [`dial::pacing`](crate::transport::dial::pacing).
impl crate::transport::dial::pacing::Pacer for ScanContext {
    fn claim(&self, peer: IpAddr) -> Result<crate::transport::dial::pacing::Claim, Instant> {
        self.claim_probe(peer)
            .map(|claim| crate::transport::dial::pacing::Claim {
                address: claim.address,
                at: claim.at,
            })
    }

    fn refund(&self, claim: crate::transport::dial::pacing::Claim) {
        // A connection or datagram is aimed at one host, so its slot was taken
        // on that host's clock too.
        self.refund_probe(ProbeClaim {
            address: claim.address,
            at: claim.at,
            at_host: true,
        });
    }

    fn host_expired(&self, peer: IpAddr) -> bool {
        ScanContext::host_expired(self, peer)
    }

    fn should_stop(&self) -> bool {
        self.handle.should_stop()
    }

    fn stopping(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(self.handle.stopping())
    }
}

impl ProbeSpacing {
    /// Whether this scan keeps any gap at all. A scan that keeps none never
    /// locks or stores anything here.
    fn is_spaced(&self) -> bool {
        self.per_host.is_some() || self.scan_wide.is_some()
    }

    /// The longer of the two gaps, for a caller sizing a deadline: every probe
    /// at one host waits out the first, and every probe at all the second.
    fn longest(&self) -> Option<Duration> {
        self.per_host.max(self.scan_wide)
    }

    /// When a probe to `address` may next leave, or `None` if it may now.
    ///
    /// Reads only, so a concurrent pass may take the slot first. Use it to
    /// choose which probe to try; a claim decides.
    fn ready_at(&self, address: IpAddr, now: Instant) -> Option<Instant> {
        if !self.is_spaced() {
            return None;
        }
        let anywhere = self.scan_wide.and_then(|gap| {
            let slot = *self
                .last_anywhere
                .lock()
                .unwrap_or_else(|held| held.into_inner());
            Slot::ready_at(slot, Some(gap), now)
        });
        let at_host = self.per_host.and_then(|gap| {
            let slot = self.last_at_host.get(&address).map(|slot| *slot);
            Slot::ready_at(slot, Some(gap), now)
        });
        anywhere.max(at_host)
    }

    /// When a frame sent to a group may next leave, or `None` if it may now.
    /// Only the scan-wide gap applies.
    fn group_ready_at(&self, now: Instant) -> Option<Instant> {
        let gap = self.scan_wide?;
        let slot = *self
            .last_anywhere
            .lock()
            .unwrap_or_else(|held| held.into_inner());
        Slot::ready_at(slot, Some(gap), now)
    }

    /// Takes the next slot for a probe to `address` if both gaps allow one
    /// now, or says when they will.
    fn claim(&self, address: IpAddr) -> Result<ProbeClaim, Instant> {
        self.claim_with(address, Instant::now)
    }

    /// [`claim`](Self::claim), reading the time from `clock` once the locks
    /// are held.
    ///
    /// The scan-wide lock is always taken before the host's, here and in
    /// [`refund`](Self::refund), so two claims cannot deadlock.
    pub(crate) fn claim_with(
        &self,
        address: IpAddr,
        clock: impl FnOnce() -> Instant,
    ) -> Result<ProbeClaim, Instant> {
        self.claim_on(address, true, clock)
    }

    /// Takes the next slot for a frame sent to `group` if the scan-wide gap
    /// allows one now, or says when it will; no host's clock is read or moved.
    fn claim_group(&self, group: IpAddr) -> Result<ProbeClaim, Instant> {
        self.claim_group_with(group, Instant::now)
    }

    /// [`claim_group`](Self::claim_group), reading the time from `clock` once
    /// the lock is held.
    pub(crate) fn claim_group_with(
        &self,
        group: IpAddr,
        clock: impl FnOnce() -> Instant,
    ) -> Result<ProbeClaim, Instant> {
        self.claim_on(group, false, clock)
    }

    /// A claim on the scan-wide clock, and on `address`'s own where `at_host`.
    fn claim_on(
        &self,
        address: IpAddr,
        at_host: bool,
        clock: impl FnOnce() -> Instant,
    ) -> Result<ProbeClaim, Instant> {
        if !self.is_spaced() {
            return Ok(ProbeClaim {
                address,
                at: clock(),
                at_host,
            });
        }

        let mut anywhere = self.scan_wide.map(|_| {
            self.last_anywhere
                .lock()
                .unwrap_or_else(|held| held.into_inner())
        });
        let host_clock = self
            .per_host
            .filter(|_| at_host)
            .map(|_| self.last_at_host.entry(address));
        let now = clock();

        let wait_anywhere = anywhere
            .as_deref()
            .and_then(|slot| Slot::ready_at(*slot, self.scan_wide, now));
        let wait_at_host = host_clock.as_ref().and_then(|entry| match entry {
            dashmap::Entry::Occupied(slot) => Slot::ready_at(Some(*slot.get()), self.per_host, now),
            dashmap::Entry::Vacant(_) => None,
        });
        if let Some(ready) = wait_anywhere.max(wait_at_host) {
            return Err(ready);
        }

        if let Some(slot) = anywhere.as_deref_mut() {
            *slot = Some(Slot::after(*slot, now));
        }
        if let Some(entry) = host_clock {
            match entry {
                dashmap::Entry::Occupied(mut slot) => {
                    let previous = *slot.get();
                    slot.insert(Slot::after(Some(previous), now));
                }
                dashmap::Entry::Vacant(slot) => {
                    slot.insert(Slot::after(None, now));
                }
            }
        }
        Ok(ProbeClaim {
            address,
            at: now,
            at_host,
        })
    }

    /// Gives back the slot `claim` took, on either clock where nothing has
    /// been recorded over it since.
    fn refund(&self, claim: ProbeClaim) {
        if !self.is_spaced() {
            return;
        }
        if self.scan_wide.is_some() {
            let mut anywhere = self
                .last_anywhere
                .lock()
                .unwrap_or_else(|held| held.into_inner());
            if let Some(restored) = anywhere.and_then(|slot| slot.refunded(claim.at)) {
                *anywhere = restored;
            }
        }
        if self.per_host.is_some()
            && claim.at_host
            && let dashmap::Entry::Occupied(mut slot) = self.last_at_host.entry(claim.address)
        {
            match slot.get().refunded(claim.at) {
                Some(Some(restored)) => {
                    slot.insert(restored);
                }
                Some(None) => {
                    slot.remove();
                }
                None => {}
            }
        }
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
        // Read first, so only a host's first probe takes the shard's write
        // lock; this is on the send path once per target.
        if let Some(started) = self.started.get(&address) {
            return started.elapsed() >= budget;
        }
        let started = *self.started.entry(address).or_insert_with(Instant::now);
        started.elapsed() >= budget
    }
}

/// The links a phase swept, gathered as its strategies run.
///
/// A sweep of a local segment reaches every host on the link, beyond the
/// addresses it was handed: every IPv6 neighbour must answer an all-nodes
/// solicitation. No address range expresses that coverage, so the link is
/// named by its interface.
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
/// re-announcing itself every thirty seconds is recorded once. The latest
/// announcement wins, so a moved cable is not reported as two attachments.
///
/// A link answering on both LLDP and CDP keeps both, since the protocols a
/// network speaks are a fact about it and the two carry different fields.
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
/// Ordered because a journal compaction writes these to disk, and the same
/// findings should produce the same file.
///
/// A free function because both `ScanContext` and `ScanProgress` need it.
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
        .into_keys()
        .filter_map(|key| store.get(&key).map(|host| host.clone()))
        .collect()
}

/// [`changed_since`], each host carrying only the ports marked on it where
/// those were kept.
///
/// What a journal writes, costing what changed: a pass that identifies one
/// service on a host scanned on every port copies the host's own fields and
/// one port, under the lock every strategy writing that host waits on. See
/// [`Host::with_only_ports`].
#[cfg(feature = "journal-format")]
fn changes_since(store: &DashMap<ScopedIp, Host>, changed: &ChangedHosts) -> Vec<Host> {
    changed
        .drain()
        .into_iter()
        .filter_map(|(key, pending)| {
            let host = store.get(&key)?;
            Some(match pending {
                Pending::Ports(ports) => host.with_only_ports(&ports),
                Pending::Whole => host.clone(),
            })
        })
        .collect()
}

/// Whether `host` is a record a port phase standing in for a liveness pass may
/// yet forget: one nothing has answered at. The phase decides these at its end,
/// and only these; see [`ScanContext::await_verdicts`].
#[cfg(feature = "journal-format")]
fn awaits_verdict(host: &Host) -> bool {
    host.status() == crate::model::host::HostStatus::Unknown
}

/// What a port phase standing in for a liveness pass has concluded so far of
/// the records nothing has answered at; see
/// [`ScanProgress::verdicts_so_far`].
#[cfg(feature = "journal-format")]
#[derive(Debug, Clone, Default)]
pub(crate) struct SoFar {
    /// The addresses heard nothing from on every target, each settled.
    pub(crate) silent: Vec<IpRange>,
    /// The addresses of every other record nothing has answered at.
    pub(crate) awaiting: IpSet,
    /// How many targets the silent addresses were asked.
    pub(crate) unheard_probes: u64,
}

/// `set`'s ranges, IPv4 first.
#[cfg(feature = "journal-format")]
pub(crate) fn ranges_of(set: &IpSet) -> Vec<IpRange> {
    let v4 = set.v4().iter().copied().map(IpRange::V4);
    let v6 = set.v6().iter().copied().map(IpRange::V6);
    v4.chain(v6).collect()
}

/// What a journal needs from a running scan, and nothing more.
///
/// See [`ScanContext::progress`] for why a journal gets this and not a context.
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
    /// How the port phase numbers its targets, which says what an address
    /// is owed; see [`verdicts_so_far`](Self::verdicts_so_far).
    #[cfg(feature = "journal-format")]
    numbering: Arc<OnceLock<crate::model::target::TargetIndex>>,
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
    /// Ordered because a journal compaction writes these to disk, and the same
    /// findings should produce the same file.
    pub fn hosts_snapshot(&self) -> Vec<Host> {
        snapshot_of(&self.store)
    }

    /// How many hosts have been found so far.
    pub fn host_count(&self) -> usize {
        self.store.len()
    }

    /// The key of every host found so far.
    #[cfg(feature = "journal-format")]
    pub(crate) fn host_keys(&self) -> Vec<ScopedIp> {
        self.store.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Takes the hosts whose findings have changed since this was last
    /// called, for a journal to append as a scan runs.
    ///
    /// A record a port phase standing in for a liveness pass has yet to decide
    /// is taken too. Its targets are settled as they are asked, so holding it
    /// back until the verdict, which a killed sitting never reaches, would
    /// leave them settled with nothing on file. The job's report leaves it out
    /// while the phase names it undecided, and the next sitting restores and
    /// decides it; see [`verdicts_so_far`](Self::verdicts_so_far).
    ///
    /// Each host carries its own fields and only the ports marked on it since
    /// it was last taken; see `changes_since`.
    #[cfg(feature = "journal-format")]
    pub(crate) fn take_changed_findings(&self) -> Vec<Host> {
        changes_since(&self.store, &self.changed)
    }

    /// This sitting's phases as they stand: those closed, and the open one
    /// so far, as `so_far` has it. See [`Sitting`].
    #[cfg(feature = "journal-format")]
    pub(crate) fn standing_phases(&self, so_far: &SoFar) -> Vec<crate::report::ScanPhase> {
        self.sitting.standing(self.failures.snapshot(), so_far)
    }

    /// What a port phase standing in for a liveness pass has concluded so
    /// far of the records nothing has answered at, read against `cursor`.
    /// Empty for any other phase.
    ///
    /// For a checkpoint to write into the phase as it stands, so a sitting
    /// killed before its end still accounts for each record it wrote down.
    ///
    /// **Silent**, and counted: an address asked on every target the plan
    /// numbers there, each settled in `cursor`, and heard from on none. A
    /// resume asks nothing more of it and restores no record, so its probes are
    /// this sitting's to count. An address filed unreachable or withheld by the
    /// exclusions had its targets settled unasked and is not silent; nor is one
    /// whose own budget ran out, which left a target unasked.
    ///
    /// **Awaiting**: every other address of such a record, which the phase has
    /// not finished asking or decided. The phase names it undecided, so the
    /// job's report makes no host of it, and the next sitting restores and
    /// decides it, counting the probes sent to it then.
    #[cfg(feature = "journal-format")]
    pub(crate) fn verdicts_so_far(&self, cursor: &crate::journal::cursor::Checkpoint) -> SoFar {
        if !self.verdicts_pending.load(Ordering::Acquire) {
            return SoFar::default();
        }
        let Some(numbering) = self.numbering.get() else {
            return SoFar::default();
        };
        let mut silent = IpSet::new();
        let mut awaiting = IpSet::new();
        let mut unheard_probes = 0u64;
        for entry in self.store.iter() {
            let host = entry.value();
            if !awaits_verdict(host) {
                continue;
            }
            let address = entry.key().addr();
            let mut owed = 0u64;
            let mut settled = true;
            for run in numbering.runs_at(address) {
                owed += run.end - run.start;
                settled &= run.clone().all(|position| cursor.is_settled(position));
            }
            let asked = host
                .ports()
                .filter(|port| port.state() != PortState::Unasked)
                .count() as u64;
            if owed > 0 && settled && asked == owed {
                silent.insert(address);
                unheard_probes += asked;
            } else {
                awaiting.insert(address);
            }
        }
        silent.canonicalize();
        awaiting.canonicalize();
        SoFar {
            silent: ranges_of(&silent),
            awaiting,
            unheard_probes,
        }
    }

    /// Marks `hosts` changed again, for a journal whose write of them failed.
    ///
    /// Taking the changed hosts clears their marks, and the next write takes
    /// only what changed since, so without this a failed write would lose
    /// them while its cursor settled their targets. Handed back, they go out
    /// with the next write that succeeds, in their state as of then.
    #[cfg(feature = "journal-format")]
    pub(crate) fn hand_back(&self, hosts: &[Host]) {
        for host in hosts {
            self.changed.put_back(host);
        }
    }

    /// Puts back detection tapes a journal took and could not write, for the
    /// next write to take again.
    ///
    /// The counterpart of [`hand_back`](Self::hand_back) for tapes. A tape is
    /// captured only once, so one lost with a failed write could never be
    /// replayed.
    #[cfg(feature = "journal-format")]
    pub(crate) fn hand_back_tapes(&self, runs: Vec<DetectionRunRecord>) {
        self.tapes.hand_back(runs);
    }

    /// Every host found so far, ordered by the address each is keyed under,
    /// including records a port phase has yet to decide. What a journal
    /// compacts its findings to; see
    /// [`take_changed_findings`](Self::take_changed_findings).
    #[cfg(feature = "journal-format")]
    pub(crate) fn findings_snapshot(&self) -> Vec<Host> {
        self.hosts_snapshot()
    }

    /// Files a failure to the report, without an event; see
    /// [`ScanContext::progress`].
    ///
    /// Logged under the failing strategy's name, as
    /// [`ScanContext::record_failure`] logs it.
    pub fn record_failure(&self, scanner: ScannerKind, reason: String) {
        error!(
            "{} failed: {reason}",
            crate::record::wire::scanner_kind_name(scanner)
        );
        self.failures.push(ScannerFailure::new(scanner, reason));
    }
}

/// The hosts whose findings a journal has yet to record, and of each, which
/// ports.
///
/// Ports are kept only once something will take them, which is whatever
/// holds the scan's [`ScanProgress`], as with [`Tapes`]. Before that, and in a
/// scan nobody journals, a host is marked whole.
#[derive(Debug, Default)]
pub(crate) struct ChangedHosts {
    entries: Mutex<BTreeMap<ScopedIp, Pending>>,
    ports_kept: AtomicBool,
}

/// What a journal has yet to record of one host.
#[derive(Debug)]
enum Pending {
    /// Its own fields and these ports.
    Ports(BTreeSet<(u16, Protocol)>),
    /// Everything it holds, where the changed ports were not kept.
    Whole,
}

impl ChangedHosts {
    /// Marks the host at `ip` changed, on the ports `touched` names where
    /// they are known and on all of them where they are not.
    fn insert(&self, ip: ScopedIp, touched: Option<BTreeSet<(u16, Protocol)>>) {
        let touched = touched.filter(|_| self.keeps_ports());
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        match (entries.entry(ip), touched) {
            (std::collections::btree_map::Entry::Vacant(slot), touched) => {
                slot.insert(touched.map_or(Pending::Whole, Pending::Ports));
            }
            (std::collections::btree_map::Entry::Occupied(mut slot), Some(touched)) => {
                if let Pending::Ports(ports) = slot.get_mut() {
                    ports.extend(touched);
                }
            }
            (std::collections::btree_map::Entry::Occupied(mut slot), None) => {
                slot.insert(Pending::Whole);
            }
        }
    }

    /// Marks `host`, a record a journal took and did not write, changed on
    /// every port it carries.
    #[cfg(feature = "journal-format")]
    fn put_back(&self, host: &Host) {
        let ports = host
            .ports()
            .map(|port| (port.number(), port.protocol()))
            .collect();
        self.insert(host.scoped_ip(), Some(ports));
    }

    /// Keeps which ports change from here on, for a reader that will take
    /// them.
    fn keep_ports(&self) {
        self.ports_kept.store(true, Ordering::Release);
    }

    fn keeps_ports(&self) -> bool {
        self.ports_kept.load(Ordering::Acquire)
    }

    fn drain(&self) -> BTreeMap<ScopedIp, Pending> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *entries)
    }
}

/// Where strategy failures accumulate for the final
/// [`ScanReport`](crate::report::ScanReport).
///
/// [`ScanEvent::ScannerFailed`] tells a live consumer, and this log keeps the
/// same failures for the report, so a caller that only awaits the scan can
/// still tell an empty network from a scanner that never started.
///
/// A plain [`Mutex`]: failures are rare, and the lock is never held across an
/// await.
#[derive(Debug, Default)]
pub(crate) struct FailureLog {
    entries: Mutex<Vec<ScannerFailure>>,
}

impl FailureLog {
    fn push(&self, failure: ScannerFailure) {
        // A poisoned lock means another thread panicked mid-push. Recover the
        // entries so the panic does not spread into an unrelated scanner.
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
/// A sitting's phases reach its journal whole when it stops cleanly. For one
/// killed outright, the journal writes these as it goes: each closed phase,
/// and the open one so far.
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
    /// against it and what it has concluded as `so_far` has it.
    #[cfg(feature = "journal-format")]
    fn standing(
        &self,
        failures: Vec<ScannerFailure>,
        so_far: &SoFar,
    ) -> Vec<crate::report::ScanPhase> {
        let phases = self.phases.lock().unwrap_or_else(|e| e.into_inner());
        let mut standing = phases.closed.clone();
        standing.extend(
            phases
                .open
                .as_ref()
                .map(|open| open.standing(failures, so_far)),
        );
        standing
    }
}

/// The shared, cloneable handles that every scanning strategy needs: somewhere to
/// write discovered hosts, somewhere to announce updates, a way to check for abort,
/// and somewhere to record its own failure.
///
/// Every field is `pub(crate)`. A scanner writes findings through
/// [`write_host`](Self::write_host), which keeps the lock-then-announce
/// ordering. A consumer reads through [`ScanSession`].
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
    /// Addresses this host's routing table refuses. See
    /// [`note_refused_by_route`](Self::note_refused_by_route).
    pub(crate) refused_by_route: Arc<UnroutableLog>,
    /// Neighbour-table addresses the exclusions kept from a sweep. See
    /// [`note_withheld_neighbour`](Self::note_withheld_neighbour).
    pub(crate) withheld_neighbours: Arc<UnroutableLog>,
    /// Addresses the scan stopped working on because their budget ran out.
    pub(crate) timed_out: Arc<TimedOutLog>,
    /// The passes a stop skipped or cut short.
    pub(crate) passes_cut: Arc<PassLog>,
    /// Addresses whose ICMP errors the scan found rate-limited.
    pub(crate) icmp_rate_limited: Arc<RateLimitedLog>,
    /// Addresses a raw phase reached by TCP connect.
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
    /// The gaps kept between the probes this scan sends.
    pub(crate) spacing: Arc<ProbeSpacing>,
    /// The interface each of this scan's link-local targets was named on.
    ///
    /// A scanner addressing its targets one at a time holds a bare link-local
    /// address. Completing the key from this keeps a port scan's verdicts on
    /// the same record as the sweep's hardware address.
    ///
    /// Learned once the port phase knows which targets it kept, and empty for
    /// every scan that named no zone.
    pub(crate) zones: Arc<OnceLock<ZoneMap>>,
    /// The links a reply to this scan's probes can arrive by, which is where
    /// its captures listen; see
    /// [`capture_links_toward`](crate::transport::probe::capture_links_toward).
    ///
    /// Learned once the scan knows its targets, and unset for a caller
    /// orchestrating their own scan, whose captures listen on every link.
    pub(crate) capture_links: Arc<OnceLock<Vec<Zone>>>,
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
    /// Behind an `Arc` because a context is cloned once per strategy and every
    /// strategy only reads the policy.
    pub(crate) exclusions: Arc<Exclusions>,
    /// The machines `exclusions` names, by hardware address, and the other
    /// addresses they answer at; see [`Exclusions::hardware_in`].
    pub(crate) hardware: Arc<WithheldHardware>,
    /// Which hosts have findings a journal has not written down yet.
    ///
    /// Marked on every write, which is a different condition from the one that
    /// fires [`ScanEvent::HostUpdated`]: a watcher is told about novelty, while
    /// a journal records state. An enrichment pass adding evidence to a host
    /// already announced has nothing new to say and a lot to write down.
    ///
    /// Bounded by the number of distinct hosts, which the store holds anyway.
    pub(crate) changed: Arc<ChangedHosts>,
    /// What the scan is working on, and how far through it.
    pub(crate) stages: Arc<Stages>,
    /// What became of each target, for a resume that must not skip one.
    ///
    /// Separate from a target's verdict, which is the same for an exhausted
    /// probe, an interrupted one and one never sent. See
    /// [`journal::settle`](crate::journal::settle).
    pub(crate) settlements: Arc<Settlements>,
    /// How this scan numbers an address, when it is counted in addresses.
    ///
    /// Empty for every port scan, whose positions pair an address with a port
    /// and arrive on the target stream. A sweep has no such stream, since a
    /// [`HostScanner`](crate::scanner::strategy::HostScanner) owns its targets,
    /// so the numbering travels here.
    ///
    /// A port scan's liveness pass runs the discovery strategies, which settle
    /// addresses, against the port scan's context. Empty, this answers `None`
    /// to every address, so those settlements do not advance the port plan's
    /// watermark over probes nobody sent.
    pub(crate) positions: Arc<Positions>,
    /// The seed of the order this scan asks its targets in.
    ///
    /// [`None`] for a scan whose caller asked to walk the plan in order; see
    /// [`SessionBuilder::ordering`]. Read only by the dispatcher and the sweeps
    /// that hold their own first attempts.
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
    /// The TCP ports this scan only connects to and listens on, sending nothing;
    /// see [`listens_only`](Self::listens_only).
    pub(crate) listen_only: Arc<BTreeSet<u16>>,
    /// The ports a sitting continuing a job excludes beyond what the job's
    /// plan is numbered without; see [`may_ask`](Self::may_ask).
    withheld_ports: Arc<crate::model::port::PortSet>,
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

    /// Where a connection this scan opens to `target` leaves from, and when.
    ///
    /// Asked by every phase that dials, once per destination, so a port the
    /// probe reached from a forced source is spoken to from that source too,
    /// and every connection and datagram keeps the scan's probe gaps; see
    /// [`dial::pacing`](crate::transport::dial::pacing).
    pub(crate) fn egress_toward(&self, target: IpAddr) -> crate::transport::dial::Egress {
        let gate = self
            .probe_gap()
            .map(|_| crate::transport::dial::pacing::Gate::new(std::sync::Arc::new(self.clone())));
        self.forced.toward(target).paced_by(gate)
    }

    /// Whether this scan may do no more than connect to `number` over
    /// `protocol` and read what it volunteers.
    ///
    /// Asked by every pass that would put bytes on a port: the service pass and
    /// the connect scanner's inline identification, through
    /// [`service_detection_on`](Self::service_detection_on), and the detection
    /// and TLS enumeration passes, which leave such a port alone. Writing to
    /// such a port can make a printer print; see
    /// [`ZondConfig::listen_only_ports`](crate::config::ZondConfig::listen_only_ports).
    pub(crate) fn listens_only(&self, number: u16, protocol: Protocol) -> bool {
        protocol == Protocol::Tcp && self.listen_only.contains(&number)
    }

    /// How far identification goes on one port under a scan asking for
    /// `detection`: that far, or no further than listening on a port this scan
    /// [only listens on](Self::listens_only).
    ///
    /// A cap, because connecting and reading is safe on any port and names
    /// every service that greets on connect. Everything past
    /// [`ServiceDetection::Banner`] sends something, including a handshake's
    /// ClientHello and an analyzer's second connection.
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

    /// Whether an earlier sitting identified this port and this one has not;
    /// see [`Responses`] on a port a sitting inherits.
    pub(crate) fn responses_lost(&self, ip: &ScopedIp, number: u16, protocol: Protocol) -> bool {
        self.responses.lost(ip, number, protocol)
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
    /// The send-side half of what [`Exclusions`] promises, for addresses a
    /// strategy learns while it runs. A segment sweep takes leads off the wire,
    /// from mDNS records and unsolicited advertisements, and asks each directly.
    /// None was in the target list, and [`write_host`](Self::write_host) sees
    /// only the answer, so this check keeps the question off the wire.
    ///
    /// Asked by whoever turns a learned address into a probe. A target the
    /// caller named was withheld by address up front, and is asked this only
    /// for the machine behind it, by the walk that hands a port scan its
    /// targets.
    ///
    /// An address a machine the policy names answers at is held to it as
    /// well, from the moment the neighbour tables or a reply tie the two; see
    /// [the machine an address names](crate::model::exclusion#an-address-names-a-machine).
    pub fn may_probe(&self, address: &IpAddr) -> bool {
        !self.exclusions.excludes(address) && !self.hardware.withholds(address)
    }

    /// Whether this scan may send `target` its probe: [`may_probe`](Self::may_probe)
    /// its address, and its port is not one this sitting withholds.
    ///
    /// A port the caller excluded is out of the plan before anything numbers
    /// it. One a sitting continuing a job excludes beyond what the job did
    /// stays in the plan, since removing it would move every later target; the
    /// walk passes over its targets, settling each as withheld. See
    /// [`JobOptions`](crate::journal::manifest::JobOptions).
    pub(crate) fn may_ask(&self, target: &crate::model::target::Target) -> bool {
        self.may_probe(&target.ip) && !self.withheld_ports.contains(target.port, target.protocol)
    }

    /// The single place a host finding enters the store.
    ///
    /// Upserts the host at `ip`, runs `edit` against it while the store guard is
    /// held, then releases that guard *before* emitting
    /// [`ScanEvent::HostUpdated`], so the DashMap lock is never held across the
    /// channel send. Returns `true` if this call created the host.
    ///
    /// `edit` returns whether the change is worth announcing: `false` suppresses
    /// the event, e.g. for a duplicate reply that revealed nothing new. A newly
    /// created host is always announced.
    ///
    /// Anything a caller must do *without* the guard held, such as hostname
    /// resolution or adaptive-deadline bookkeeping, keys off the returned flag
    /// and runs after this call. Callers that always announce their change use
    /// [`update_host`](Self::update_host).
    ///
    /// # Exclusions
    ///
    /// A key the scan's [`Exclusions`] forbid is dropped here: `edit` is not run,
    /// no host is created, no event is emitted, and this returns `false`. Every
    /// other address `edit` attaches to the host (later replies from the same
    /// machine, a merged sighting, an mDNS record's other addresses) is held to
    /// the same policy once it has run, so none reaches the report or becomes
    /// the address the host is reached at. A router on the host's path that the
    /// policy names, measured or spliced in from another trace, keeps its
    /// distance and loses its address; see
    /// [`Hop::withheld`](crate::model::host::Hop::withheld). A router or
    /// firewall the policy names that sent second-hand evidence, such as an ICMP
    /// unreachable, leaves its evidence on the host and its address off it; see
    /// [`EvidenceSource::Withheld`](crate::model::host::EvidenceSource::Withheld).
    ///
    /// Every finding reaches the store through this function, so this one branch
    /// covers what a target-list subtraction cannot: ARP and
    /// neighbour-advertisement replies, the host's own neighbour table, mDNS
    /// records, and, since they read the store to decide what to probe, the
    /// service, OS-series and SNMP phases that run afterwards.
    ///
    /// A host whose record, once `edit` has run, holds the hardware address of a
    /// machine the policy names is that machine at another address, and is
    /// dropped whole: its record leaves the store, no event is emitted, and
    /// every address it held is refused a probe from then on and listed with
    /// the phase's exclusions. See
    /// [the machine an address names](crate::model::exclusion#an-address-names-a-machine).
    ///
    /// A drop is logged, not counted: a reader can check that no excluded
    /// address appears in the report against the ranges it records. The
    /// addresses a machine's drop withholds are counted once, when the phase
    /// closes; see [`TargetScope::withheld`](crate::report::TargetScope::withheld).
    pub fn write_host(
        &self,
        key: impl Into<ScopedIp>,
        edit: impl FnOnce(&mut Host) -> bool,
    ) -> bool {
        let key = self.key(key);
        let ip = key.addr();

        if self.exclusions.excludes(&ip) || self.hardware.withholds(&ip) {
            // Ordinary on a sweep, whose all-nodes echo also reaches excluded
            // neighbours; logged so the gate's work is visible.
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
            // `Host::set_zone` keeps the first zone it is given, and the key's
            // zone is certain, since it is what the host was looked up by.
            if let Some(zone) = key.zone() {
                host.set_zone(zone.clone());
            }
            // Named as the caller's target named it; a reverse lookup leaves a
            // named host be.
            if let Some(name) = self.target_names.get(&ip) {
                host.set_hostname(Some(name.to_string()));
            }
            host
        });
        if self.changed.keeps_ports() {
            host.track_touched_ports();
        }
        let announce = edit(&mut host);
        // The key passed the gate above; what the edit attached has not. The
        // key's own address is kept, so the host never runs out of addresses.
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
        let touched = host.take_touched_ports();
        drop(host);

        // Marked whether or not the edit asked to be announced: announcing is
        // about novelty, journalling about state. The echo probe answers
        // `false` for a host already up, yet has just added an `icmp_echo`
        // reason and a round trip that the journal must record.
        //
        // Marked with the ports the edit touched, so the journal copies and
        // compares only those, plus the host's own fields; an edit that
        // changed nothing writes nothing.
        self.changed.insert(key.clone(), touched);

        if announce || is_new {
            let _ = self.events_tx.send(ScanEvent::HostUpdated(key));
        }
        is_new
    }

    /// Reads the host at `ip`, if there is one, without cloning it.
    ///
    /// The store's guard is held for the duration of `read` and released before
    /// this returns, so a caller cannot keep it across an await.
    ///
    /// `read` must not touch this context again: reaching back into the store
    /// under its own guard deadlocks.
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

    /// Records the links a reply to this scan's probes can arrive by. The
    /// first call decides; later ones are ignored.
    pub(crate) fn capture_on(&self, links: Vec<Zone>) {
        let _ = self.capture_links.set(links);
    }

    /// The links this scan's captures listen on: those
    /// [`capture_on`](Self::capture_on) recorded, or every link that is up
    /// where nothing was.
    pub(crate) fn capture_links(&self) -> Vec<Zone> {
        self.capture_links
            .get()
            .cloned()
            .unwrap_or_else(crate::transport::probe::capturable_interfaces)
    }

    /// Records which interface each of this scan's link-local targets was named
    /// on. The first call decides; later ones are ignored.
    pub(crate) fn learn_zones(&self, zones: ZoneMap) {
        let _ = self.zones.set(zones);
    }

    /// Whether anything is recorded under `ip`.
    ///
    /// The writing half's [`HostStore::contains`].
    ///
    /// A question about the key: a host is recorded under one of its addresses,
    /// so this says whether there is a record here, not whether the machine is
    /// known.
    pub fn contains_host(&self, ip: &ScopedIp) -> bool {
        self.store.contains_key(&self.key(ip.clone()))
    }

    /// Every address a host is currently recorded under.
    ///
    /// A snapshot, so a caller may call [`write_host`](Self::write_host) while
    /// walking it; holding a live iterator over the map would deadlock.
    pub fn host_addresses(&self) -> Vec<ScopedIp> {
        self.store.iter().map(|entry| entry.key().clone()).collect()
    }

    /// The single place a strategy failure enters the record.
    ///
    /// Logs it, files it for the final report, and announces it to any live
    /// consumer, in that order, so the durable copy exists before the
    /// notification that might be dropped. The scan continues with the
    /// strategies that remain.
    ///
    /// Public so a caller running strategies themselves can file failures the
    /// way the engine's own orchestration does.
    ///
    /// The console line names the strategy as the report files it, then the
    /// reason.
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
    /// limit it runs under was reached: a detection whose declared time or
    /// bytes were spent before its question was answered, a connection the
    /// process had no descriptor for, a pinned source port still in use.
    ///
    /// Filed like [`record_failure`](Self::record_failure), as a
    /// [`ScannerFailure`] and a [`ScanEvent::ScannerFailed`], since the report
    /// keeps one account of incomplete work. Nothing broke, so the entry is
    /// marked [cut short](ScannerFailure::is_cut_short) and the console gets a
    /// warning naming the limit, not an error.
    pub(crate) fn record_cut_short(&self, scanner: ScannerKind, reason: String) {
        crate::warn!("{reason}");
        self.file_cut_short(scanner, reason);
    }

    /// [`record_cut_short`](Self::record_cut_short) without the console line,
    /// for a caller that announces many in one: a port given up on leaves every
    /// detection gated onto it unfinished, each with a report entry, under one
    /// line about the port.
    pub(crate) fn file_cut_short(&self, scanner: ScannerKind, reason: String) {
        self.failures
            .push(ScannerFailure::cut_short(scanner, reason.clone()));
        let _ = self
            .events_tx
            .send(ScanEvent::ScannerFailed { scanner, reason });
    }

    /// The single place a refusal enters the record.
    ///
    /// A refusal is the engine working out, before anything is sent, that part
    /// of what it was asked has no strategy behind it: an SCTP port on a host
    /// with no raw sockets, a prefix too large to walk, a technique a connect
    /// scan cannot express. Nothing broke, so it is not announced on the event
    /// stream and no strategy is blamed; see [`Refusal`].
    ///
    /// Filed once per distinct refusal, so a plan that declines the same range
    /// on two links says it once.
    ///
    /// Not logged: a front end prints the report's refusals at every verbosity,
    /// and logging would show each twice.
    ///
    /// Public, like [`record_failure`](Self::record_failure), so a caller
    /// assembling their own scan can say what they declined.
    pub fn record_refusal(&self, refusal: Refusal) {
        self.refusals.push(refusal);
    }

    /// Takes the refusals recorded so far, leaving the log empty.
    pub(crate) fn take_refusals(&self) -> Vec<Refusal> {
        self.refusals.drain()
    }

    /// The refusals filed so far, left in place.
    ///
    /// The reading counterpart of [`record_refusal`](Self::record_refusal), as
    /// [`failures_snapshot`](Self::failures_snapshot) is for failures, for a
    /// caller driving strategies themselves.
    pub fn refusals_snapshot(&self) -> Vec<Refusal> {
        self.refusals.snapshot()
    }

    /// Files what an instrumented scanner observed about its own run.
    ///
    /// Called once per scanner, as its receive loop exits. Not announced on the
    /// event stream, since it describes the run and changes no finding.
    ///
    /// Public, like [`record_failure`](Self::record_failure), so a custom
    /// strategy can account for its own run in the report's audit.
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
    /// for a caller driving strategies themselves, who never reaches the phase
    /// that drains these into a [`ScanReport`](crate::report::ScanReport).
    /// It leaves the log in place, so the report still gets them.
    pub fn probe_stats_snapshot(&self) -> Vec<ProbeStats> {
        self.probe_stats.snapshot()
    }

    /// Takes the failures recorded so far, leaving the log empty.
    ///
    /// Called once, when a phase assembles its report. Draining means a context
    /// that outlives its phase cannot hand the same failure to a second one.
    pub(crate) fn take_failures(&self) -> Vec<ScannerFailure> {
        self.failures.drain()
    }

    /// Records that this host could not reach `address`, so no probe was sent
    /// to it: no route or source address led there, or the neighbour never
    /// answered address resolution.
    ///
    /// Neither a failure nor an event. It is recorded so the report says why a
    /// target the caller asked about is missing.
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
    /// tied to it when the scan started, and the ones heard since. Left in
    /// place, since the policy holds for the whole scan and every later phase
    /// lists these among its exclusions too.
    pub(crate) fn withheld_by_hardware(&self) -> Vec<IpAddr> {
        self.hardware.addresses()
    }

    /// The unroutable addresses filed so far, taken.
    pub(crate) fn take_unroutable(&self) -> Vec<IpAddr> {
        self.unroutable.drain()
    }

    /// Notes that this host's own routing table refuses `address`, which is
    /// why whatever files it [unroutable](Self::record_unroutable) sent it
    /// nothing.
    ///
    /// Only a note on the reason: the strategy that meets the address files
    /// it, and a phase names an address refused by a route only where it also
    /// files it unroutable. See
    /// [`ScanPhase::refused_by_route`](crate::report::ScanPhase::refused_by_route).
    pub(crate) fn note_refused_by_route(&self, address: IpAddr) {
        self.refused_by_route.insert(address);
    }

    /// The addresses noted refused by a route so far, taken.
    pub(crate) fn take_refused_by_route(&self) -> Vec<IpAddr> {
        self.refused_by_route.drain()
    }

    /// Notes that the exclusions kept `address`, from this host's neighbour
    /// table, out of the phase's sweep. The phase counts it among the
    /// addresses its policy
    /// withheld; see
    /// [`TargetScope::withheld`](crate::report::TargetScope::withheld).
    pub(crate) fn note_withheld_neighbour(&self, address: IpAddr) {
        self.withheld_neighbours.insert(address);
    }

    /// The neighbour-table addresses noted withheld so far, taken.
    pub(crate) fn take_withheld_neighbours(&self) -> Vec<IpAddr> {
        self.withheld_neighbours.drain()
    }

    /// Whether `address` has been filed as unroutable in this phase, left in
    /// place.
    pub(crate) fn is_unroutable(&self, address: IpAddr) -> bool {
        self.unroutable.contains(address)
    }

    /// Whether `address` has been filed as left early by its own budget in this
    /// phase, left in place.
    ///
    /// Unlike [`host_expired`](Self::host_expired), this files nothing, so a
    /// host whose clock runs out after its last probe still counts as covered
    /// in full.
    pub(crate) fn left_early(&self, address: IpAddr) -> bool {
        self.timed_out.contains(address)
    }

    /// Marks every record nothing has answered at as one the phase has yet to
    /// decide, until [`verdicts_reached`](Self::verdicts_reached).
    ///
    /// For a port phase standing in for a liveness pass, which decides only at
    /// its end which of those records are hosts and forgets the rest as silent
    /// or undecided. A sitting killed outright never writes its closed phase,
    /// so the checkpoints write the phase as it stands, with what it has
    /// concluded so far; see [`ScanProgress::verdicts_so_far`].
    pub(crate) fn await_verdicts(&self) {
        self.verdicts_pending.store(true, Ordering::Release);
    }

    /// Ends what [`await_verdicts`](Self::await_verdicts) began, once the phase
    /// has forgotten the records it heard nothing from.
    pub(crate) fn verdicts_reached(&self) {
        self.verdicts_pending.store(false, Ordering::Release);
    }

    /// Files the host records at `keys` as addresses a port phase standing in
    /// for its liveness pass asked on every port and heard nothing from, and
    /// forgets those records.
    ///
    /// The liveness pass would have found each address silent and made no host
    /// of it. Forgetting the record keeps [`ScanSession::hosts`] after the scan
    /// in step with the report. The addresses go where a discovery pass files
    /// its silence, which the phase's
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
    /// Nothing answered, so no host was found, and not every port was asked, so
    /// this is not silence either. They are named in the phase's
    /// [`undecided`](crate::report::ScanPhase::undecided) list, as the liveness
    /// pass would name them. Their ports stay unsettled, so a resume asks them
    /// again, and the ones already asked are counted before the record goes.
    pub(crate) fn forget_undecided(&self, keys: Vec<ScopedIp>) {
        for key in keys {
            self.undecided.insert(key.addr());
            self.forget_unheard(&key);
        }
    }

    /// Drops the record at `key`, counting the ports it had been asked as
    /// [`unheard_probes`](crate::report::ScanPhase::unheard_probes) and the
    /// ones it had not with the targets the phase never reached, so the phase
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
    /// A count, since a walk stopped early on a wide plan leaves them scattered
    /// across all of it. They stay unsettled, so a resume asks them. See
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
    /// Every pass asks this before probing a host again. A host that answers
    /// true writes itself into the phase's
    /// [`timed_out`](crate::report::ScanPhase::timed_out) list, so no strategy
    /// can leave a host early without the report saying so.
    ///
    /// Always false, and cheap, for a scan with no budget. See
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
    /// host, and those that write a conclusion back, since a host written to
    /// is written to the journal whole again.
    ///
    /// Every host is owed them except one an earlier sitting ran to its end
    /// with, whose answers are already in its record. Such a host is owed them
    /// again where this sitting still has a target at one of its addresses,
    /// since that target may reveal a port or service the passes have not
    /// seen.
    ///
    /// A sitting killed or stopped before its end records nothing finished, so
    /// the next owes all its hosts the passes. A pass asked twice costs probes;
    /// one never asked leaves a record silently short.
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

    /// When a probe to `address` may next leave, or `None` if it may now.
    ///
    /// For choosing which probe to try: another pass may take the slot before
    /// the send. [`claim_probe`](Self::claim_probe) decides.
    ///
    /// **Being turned away is not a verdict.** The probe has not been sent, so
    /// a caller that drops it reports an unasked port as silent. Hold it and
    /// try again at the instant returned, or file it
    /// [`Unasked`](crate::model::port::PortState::Unasked).
    ///
    /// Always `None`, and cheap, for a scan that keeps no gap. See
    /// [`ZondConfig::host_probe_interval`](crate::config::ZondConfig::host_probe_interval)
    /// and [`ZondConfig::probe_interval`](crate::config::ZondConfig::probe_interval).
    pub fn probe_ready_at(&self, address: IpAddr, now: Instant) -> Option<Instant> {
        self.spacing.ready_at(address, now)
    }

    /// Takes the slot for one probe to `address`, or says when one will be
    /// free.
    ///
    /// Every send site asks this immediately before sending, beside
    /// [`host_expired`](Self::host_expired). An expired host is finished with
    /// and goes into the phase's
    /// [`timed_out`](crate::report::ScanPhase::timed_out) list; a host turned
    /// away here will be ready at the instant returned. As with
    /// [`probe_ready_at`](Self::probe_ready_at), a probe turned away is owed a
    /// send or an `Unasked`, never a silence.
    ///
    /// The decision and the record are one operation, so concurrent passes
    /// share one bound. A send the kernel refuses gives the slot back with
    /// [`refund_probe`](Self::refund_probe).
    ///
    /// Always granted for a scan that keeps no gap, and then nothing is locked
    /// or stored.
    pub fn claim_probe(&self, address: IpAddr) -> Result<ProbeClaim, Instant> {
        self.spacing.claim(address)
    }

    /// Gives back the slot `claim` took, for a probe that never reached the
    /// wire.
    ///
    /// A probe the kernel refused must not spend a slot, as
    /// `RawProbeScan::record_send` keeps it out of the congestion window. A
    /// slot another probe has been recorded over since stays spent, which can
    /// only lengthen a gap.
    pub fn refund_probe(&self, claim: ProbeClaim) {
        self.spacing.refund(claim);
    }

    /// Takes the slot for one frame sent to `group`, a broadcast or multicast
    /// address, or says when one will be free.
    ///
    /// A frame to a group spends the scan-wide gap like any probe, but moves no
    /// host's clock, since it singles out no machine. A frame that asks about
    /// one address, as a broadcast ARP request does, is aimed at that address
    /// and claims with [`claim_probe`](Self::claim_probe).
    ///
    /// Otherwise as [`claim_probe`](Self::claim_probe): taken immediately
    /// before the send, a frame turned away is owed a send later, and one the
    /// kernel refused gives its slot back with
    /// [`refund_probe`](Self::refund_probe).
    pub fn claim_group_probe(&self, group: IpAddr) -> Result<ProbeClaim, Instant> {
        self.spacing.claim_group(group)
    }

    /// When a frame sent to a group may next leave, or `None` if it may now;
    /// see [`claim_group_probe`](Self::claim_group_probe).
    ///
    /// This is also when *any* probe may next leave as far as the scan-wide gap
    /// goes. Always `None` for a scan that keeps no scan-wide gap.
    pub fn group_probe_ready_at(&self, now: Instant) -> Option<Instant> {
        self.spacing.group_ready_at(now)
    }

    /// The longer of the gaps this scan keeps between probes, or `None` for a
    /// scan that keeps neither.
    ///
    /// For a scanner sizing its own deadline. See
    /// [`ZondConfig::host_probe_interval`](crate::config::ZondConfig::host_probe_interval)
    /// and [`ZondConfig::probe_interval`](crate::config::ZondConfig::probe_interval).
    pub(crate) fn probe_gap(&self) -> Option<Duration> {
        self.spacing.longest()
    }

    /// The gap this scan keeps between any two probes, wherever they are
    /// aimed, or `None` for a scan that keeps none. A pass whose deadline is
    /// sized from its own send rate reads it as a cap on that rate.
    pub(crate) fn scan_probe_interval(&self) -> Option<Duration> {
        self.spacing.scan_wide
    }

    /// The addresses left early so far, taken.
    pub(crate) fn take_timed_out(&self) -> Vec<IpAddr> {
        self.timed_out.drain()
    }

    /// Whether the scan is stopping, recording `pass` as cut by the stop if
    /// it is.
    ///
    /// Asked by a pass that has work in front of it, before it begins and
    /// between items, so the report names the passes a stop cut; see
    /// [`ScanPhase::passes_cut`](crate::report::ScanPhase::passes_cut). A pass
    /// with nothing to do does not ask.
    pub(crate) fn stopping_before(&self, pass: Pass) -> bool {
        let stopping = self.handle.should_stop();
        if stopping {
            self.passes_cut.insert(pass);
        }
        stopping
    }

    /// The passes a stop has cut so far, taken, in the order a scan runs them.
    pub(crate) fn take_passes_cut(&self) -> Vec<Pass> {
        self.passes_cut.drain()
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
    /// For a strategy that, inside a raw phase, reaches its targets by connect:
    /// loopback in any raw phase, and whatever self-built frames cannot reach
    /// when frames are all the process has. Its findings are connect evidence,
    /// which the phase's privilege alone would present as raw. Ignored by a
    /// phase recorded at
    /// [`Privilege::Connect`](crate::system::privilege::Privilege::Connect),
    /// which reached everything this way. See
    /// [`ScanPhase::reached_by_connect`](crate::report::ScanPhase::reached_by_connect).
    pub fn record_reached_by_connect(&self, targets: &IpSet) {
        self.reached_by_connect.extend(targets);
    }

    /// The addresses reached by connect so far, merged and taken, less
    /// `unreached`: the addresses the phase filed unroutable.
    ///
    /// The log holds everything a strategy was handed, and an address a local
    /// route refused was never asked and holds no connect evidence.
    pub(crate) fn take_reached_by_connect(&self, unreached: &[IpAddr]) -> Vec<IpRange> {
        self.reached_by_connect.drain(unreached)
    }

    /// Records that this phase swept a whole link, beyond the addresses on it
    /// that were named.
    ///
    /// Called by a strategy that sent a probe every host on the segment must
    /// answer. See [`TargetScope::links`](crate::report::TargetScope::links):
    /// a comparison can then tell a new host on a watched link from one on
    /// ground nobody covered.
    pub fn record_sweep(&self, zone: Zone) {
        self.swept_links.insert(zone);
    }

    /// Takes the links swept so far, leaving the log empty.
    pub(crate) fn take_swept_links(&self) -> Vec<Zone> {
        self.swept_links.drain()
    }

    /// Records which switch port this machine turned out to be plugged into.
    ///
    /// Called by whatever read an announcement off a link; see [`Attachment`]
    /// for why this belongs to the phase. A device re-announcing itself
    /// replaces the previous reading for that link and protocol.
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
    /// Separate from the verdict: a target reaches the store with a port
    /// state, and this says whether the scan *earned* it or assigned it
    /// because the run ended. See [`Outcome`].
    ///
    /// Call this only once the target's finding is in the store. A checkpoint
    /// reads the settlements before it takes the changed hosts, so settling
    /// first could write a cursor that skips the target beside a findings file
    /// without it, and a resume would never report the finding. See
    /// [`checkpoint`](crate::scanner::checkpoint).
    pub fn record_outcome(&self, outcome: Outcome) {
        self.settlements.record(outcome);
    }

    /// Announces the stage the scan has moved into, with how much work it holds
    /// where that is known before any of it is done.
    ///
    /// Entering the stage that is already current adds to its total, so service
    /// detection running once per protocol reports one stage the size of both
    /// runs.
    pub fn enter_stage(&self, stage: Stage, total: Option<u64>) {
        if self.stages.enter(stage, total) {
            let _ = self.events_tx.send(ScanEvent::StageChanged { stage });
        }
    }

    /// Counts one unit of the current stage as finished.
    ///
    /// Called where the work completes. A stage that submits into a pool hands
    /// out all its work long before any of it is done.
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
    /// A port scan's plan counts address-and-port pairs, so its liveness pass's
    /// addresses are left out of the tally. The pass accounts for them in its
    /// phase's [`undecided`](crate::report::ScanPhase::undecided) list.
    pub(crate) fn record_address_outcomes(&self, outcome: Outcome, count: u64) {
        if self.plan_stage != Stage::Ports {
            self.settlements.record_many(outcome, count);
        }
    }

    /// Records what became of one address, in a scan counted in addresses.
    ///
    /// The position comes from the plan this scan is numbered in, so a
    /// strategy needs only the address and what came back.
    ///
    /// Nothing is settled in two cases. A scan not counted in addresses has no
    /// numbering, so a port scan's liveness pass settles nothing. An address
    /// the plan does not name, such as a neighbour a sweep found unasked, has
    /// no position. Either way the address is asked again on the next sitting,
    /// which is the safe direction.
    ///
    /// Silence is recorded in both cases, for two readers. The port phase after
    /// a liveness pass settles the ports of a host found down; see
    /// [`Outcome::Skipped`]. And every discovery phase names the addresses it
    /// reached no verdict on: its scope less what answered and what was asked
    /// to exhaustion; see
    /// [`ScanPhase::undecided`](crate::report::ScanPhase::undecided).
    ///
    /// Call this only once the answer's finding is in the store; see
    /// [`record_outcome`](Self::record_outcome).
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
    /// found at it. An address the pass reached no verdict on is not here. See
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
    /// Merged, so a host this sitting has already seen keeps both readings.
    ///
    /// Each restored host is announced, since to a caller watching the stream
    /// it has just appeared. It is not marked *changed*, since it came from the
    /// journal.
    ///
    /// This sitting's exclusions apply to what comes back, address by address,
    /// as in [`write_host`](Self::write_host), since a journal written before
    /// an exclusion was added may hold addresses it now forbids. A host loses
    /// each of those, and is restored under its best remaining address if its
    /// key was among them; a host with no address left is left out. Routers on
    /// its path and senders of evidence the policy names lose their addresses
    /// as they would in `write_host`.
    ///
    /// The journal itself is left as recorded; only what this sitting reports
    /// changes.
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
            host.withhold_ports(&self.withheld_ports);

            let key = host.scoped_ip();
            // What the earlier sitting drew identifying these ports ended
            // with it; see `Responses`.
            for port in host.ports() {
                if port.state() == PortState::Open {
                    self.responses
                        .inherit(key.clone(), port.number(), port.protocol());
                }
            }
            match self.store.get_mut(&key) {
                Some(mut existing) => {
                    existing.merge(host);
                    // The journal already holds what the merge touched.
                    let _ = existing.take_touched_ports();
                }
                None => {
                    self.store.insert(key.clone(), host);
                }
            }
            let _ = self.events_tx.send(ScanEvent::HostUpdated(key));
        }
    }

    /// What a journal needs from a running scan.
    ///
    /// A [`ScanContext`] carries the event sender, and a checkpoint task
    /// holding one would keep the event stream open after the scan ended: a
    /// caller waiting for the stream to end would wait for the checkpoint task,
    /// which waits for the caller to stop it.
    ///
    /// A failure recorded through this reaches the report but not the stream,
    /// since a checkpoint that could not be written is about the journal, not a
    /// scanning strategy.
    ///
    /// From the first call on, the detection phase keeps its runs' tapes for
    /// [`ScanProgress::take_tapes`], and which ports of a host changed is
    /// tracked too.
    pub fn progress(&self) -> ScanProgress {
        self.tapes.keep();
        self.changed.keep_ports();
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
            #[cfg(feature = "journal-format")]
            numbering: Arc::clone(&self.numbering),
        }
    }

    /// Every host found so far, cloned, ordered by the address each is keyed
    /// under.
    ///
    /// For a journal compacting its findings. Ordered so the same findings
    /// produce the same file.
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
    /// For a journal writing findings down as a scan produces them. Draining,
    /// so a host is written once per change.
    pub fn take_changed_hosts(&self) -> Vec<Host> {
        changed_since(&self.store, &self.changed)
    }

    /// The strategy failures filed so far, left in place.
    ///
    /// The reading counterpart of [`record_failure`](Self::record_failure), like
    /// [`probe_stats_snapshot`](Self::probe_stats_snapshot), for a caller
    /// driving strategies themselves who wants failures before a phase closes.
    ///
    /// Leaves the log in place for
    /// [`PhaseRecorder::finish`](crate::scanner::recorder::PhaseRecorder::finish)
    /// to drain into the report.
    pub fn failures_snapshot(&self) -> Vec<ScannerFailure> {
        self.failures.snapshot()
    }

    /// Upserts the host at `ip`, applies `update`, and unconditionally announces
    /// the change. The convenience form of [`write_host`](Self::write_host) for
    /// paths that always record a finding worth emitting, such as a port state
    /// or a merged host. Returns `true` if this call created the host.
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
/// The hardware is read once, when the scan starts, from the host's neighbour
/// tables, so every finding is held to the same policy. The addresses start as
/// the ones the same tables tie to that hardware, so a target named at one of
/// them is asked nothing, and grow as the scan hears more.
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
/// caller leaves alone. Each setting is named once, and an unset one keeps its
/// neutral value.
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
    probe_interval: Option<Duration>,
    order: Order,
    send_source: Vec<IpAddr>,
    /// `None` for the default, [`RAW_PRINT_PORTS`](crate::config::RAW_PRINT_PORTS).
    listen_only: Option<BTreeSet<u16>>,
    withheld_ports: crate::model::port::PortSet,
    /// The neighbour tables the exclusions are read against for the machines
    /// they name; `None` to read the host's own.
    neighbours: Option<Vec<(IpAddr, Option<MacAddr>)>>,
    finished: Finished,
    target_names: BTreeMap<IpAddr, String>,
}

impl SessionBuilder {
    /// Addresses the scan may not record a finding against.
    ///
    /// A caller orchestrating their own scan under an exclusion policy has to
    /// set this as well as subtracting the addresses from their target list,
    /// since a segment sweep reaches beyond the addresses named. See
    /// [`Exclusions`] for what each of the two enforcements is for.
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

    /// The neighbour tables the exclusions are read against, replacing the
    /// host's own: each address and the hardware address it resolved to.
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
    #[cfg(feature = "journal-format")]
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
    /// A port scan leaves it alone. It numbers address-and-port pairs on its
    /// target stream, so the discovery strategies in its liveness pass settle
    /// nothing, and the port plan's watermark does not advance over probes
    /// nobody sent.
    pub fn counting(mut self, positions: Positions) -> Self {
        self.positions = positions;
        self
    }

    /// The seed of the order this scan asks its targets in.
    ///
    /// With a seed, the scan walks a permutation of the whole index space, so a
    /// sweep of a range does not have the address-order shape correlating
    /// sensors look for. See [`Permutation`](crate::model::order::Permutation).
    ///
    /// Left unset, the session draws its own seed when built, so the
    /// dispatcher's streams and the sweeps that hold their own first attempts
    /// all walk one order.
    ///
    /// Pass [`None`] for plan order, shuffled within a batch, which is the
    /// fallback for a plan that cannot be addressed by position. A sitting
    /// continuing a journal that recorded no seed must pass it, since its
    /// checkpoint counts along the plan.
    ///
    /// A caller journalling their scan should pass the journal's seed, so a
    /// resumed sitting continues in the first one's order, as
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
    /// The stage matters in a scan with more than one: a port scan's liveness
    /// pass measured against address-and-port pairs would read nought percent
    /// throughout.
    ///
    /// Left unset, a consumer gets only a running count of what has settled,
    /// which is all an uncountable plan can offer.
    pub fn planning(mut self, stage: Stage, total: Option<u64>) -> Self {
        self.plan_stage = stage;
        self.planned = total;
        self
    }

    /// The stages this scan expects to run, in the order it will run them.
    ///
    /// What [`Progress::overall`] measures a whole run against. Pass a
    /// superset: a listed stage that is skipped moves the figure forward over
    /// it, while an unlisted stage that runs leaves the figure still until the
    /// next listed one.
    ///
    /// [`discover`](crate::scanner::discover) and [`scan`](crate::scanner::scan)
    /// derive this from their settings. A caller orchestrating their own scan
    /// lists the stages they mean to run, or reads progress one stage at a time.
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
    /// Every pass that sends claims its slots through
    /// [`ScanContext::claim_probe`], which says what being turned away means
    /// for a probe.
    ///
    /// `None` is no gap. `Some(Duration::MAX)` is the longest gap there is,
    /// one probe per host for the rest of the scan, not "no limit"; see the
    /// config field.
    pub fn host_probe_interval(mut self, minimum: Option<Duration>) -> Self {
        self.host_probe_interval = minimum;
        self
    }

    /// The shortest gap the scan keeps between any two probes it sends,
    /// whatever host each is aimed at.
    ///
    /// A caller orchestrating their own scan sets this to have the same spacing
    /// [`scan`](crate::scanner::scan) applies from
    /// [`ZondConfig::probe_interval`](crate::config::ZondConfig::probe_interval).
    /// Claimed through [`ScanContext::claim_probe`] alongside the per-host gap,
    /// on the same terms.
    pub fn probe_interval(mut self, minimum: Option<Duration>) -> Self {
        self.probe_interval = minimum;
        self
    }

    /// The source addresses the connections this scan opens are forced to, one
    /// per family.
    ///
    /// A caller orchestrating their own scan sets this to have the same pinning
    /// [`scan`](crate::scanner::scan) applies from
    /// [`ZondConfig::send_source`](crate::config::ZondConfig::send_source):
    /// every connection to a routed target, from the connect scan or the
    /// service pass, leaves from the forced source and its interface, as the
    /// raw probes do.
    pub fn send_source(mut self, sources: Vec<IpAddr>) -> Self {
        self.send_source = sources;
        self
    }

    /// The TCP ports this scan only connects to and listens on, sending
    /// nothing.
    ///
    /// Left unset, the printers' ports,
    /// [`RAW_PRINT_PORTS`](crate::config::RAW_PRINT_PORTS), as
    /// [`scan`](crate::scanner::scan) uses by default. A caller
    /// orchestrating their own scan sets this to what
    /// [`ZondConfig::listen_only_ports`](crate::config::ZondConfig::listen_only_ports)
    /// says, and an empty set probes every port alike.
    pub fn listening_only_to(mut self, ports: BTreeSet<u16>) -> Self {
        self.listen_only = Some(ports);
        self
    }

    /// The ports a sitting continuing a job sends nothing to beyond those the
    /// job's plan is numbered without; see [`ScanContext::may_ask`].
    #[cfg(feature = "journal-format")]
    pub(crate) fn withholding_ports(mut self, ports: crate::model::port::PortSet) -> Self {
        self.withheld_ports = ports;
        self
    }

    /// Opens the session and the context.
    ///
    /// The scan's own clock starts here, so building late still gets the full
    /// budget.
    pub fn build(self) -> (ScanSession, ScanContext) {
        let store = Arc::new(DashMap::new());
        let handle = ScanHandle::bounded(self.scan_timeout);
        let (events_tx, rx) = broadcast::channel(ScanEvents::CAPACITY);
        // Counted along the dispatcher's walk where there is one (a seed and a
        // plan it can number whole). The two must agree, or every answer waits
        // above the watermark. Without a plan the dispatcher names the walk
        // when it starts; see `Settlements::walk_along`.
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
            refused_by_route: Arc::new(UnroutableLog::default()),
            withheld_neighbours: Arc::new(UnroutableLog::default()),
            timed_out: Arc::new(TimedOutLog::default()),
            passes_cut: Arc::new(PassLog::default()),
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
            spacing: Arc::new(ProbeSpacing {
                per_host: self.host_probe_interval,
                scan_wide: self.probe_interval,
                ..ProbeSpacing::default()
            }),
            zones: Arc::new(OnceLock::new()),
            capture_links: Arc::new(OnceLock::new()),
            numbering: Arc::new(OnceLock::new()),
            swept_links: Arc::new(SweptLinks::default()),
            attachments: Arc::new(Attachments::default()),
            hardware: Arc::new(WithheldHardware::read(
                &self.exclusions,
                self.neighbours.unwrap_or_else(|| {
                    if self.exclusions.is_empty() {
                        return Vec::new();
                    }
                    crate::system::neighbor_cache::neighbour_table()
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
                    .unwrap_or_else(|| crate::config::RAW_PRINT_PORTS.iter().copied().collect()),
            ),
            withheld_ports: Arc::new(self.withheld_ports),
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
    /// [`discover`](crate::scanner::discover) and [`scan`](crate::scanner::scan)
    /// build their own session. A caller orchestrating their own scan calls
    /// this first, since every strategy in [`strategy`](crate::scanner::strategy)
    /// is constructed with a [`ScanContext`].
    ///
    /// [`builder`](Self::builder) takes further settings.
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

    /// A whole run reads as one figure that only grows.
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

        // One stage behind it and half way through the second: half the run.
        let (done, total) = session.progress().overall().expect("a staged run");
        assert_eq!(done * 2, total, "half the run: {done}/{total}");
    }

    /// Across a whole scan the figure only grows, and is whole only at the
    /// end. Walks a port scan's stages: a liveness pass, a port phase whose
    /// plan is mostly silent hosts, service detection once for TCP and again
    /// for UDP, the detections, and the later passes.
    #[test]
    fn a_scans_figure_only_grows_and_is_whole_only_at_its_end() {
        let (session, ctx) = ScanSession::builder()
            .planning(Stage::Ports, Some(1_000))
            .staging(vec![
                Stage::Discovery,
                Stage::Ports,
                Stage::Services,
                Stage::Detections,
                Stage::Os,
                Stage::Traceroute,
                Stage::Filters,
                Stage::IpProtocols,
            ])
            .build();
        let progress = session.progress().clone();
        let mut readings: Vec<(&str, (u64, u64))> = Vec::new();
        let mut read = |what| readings.push((what, progress.overall().expect("staged")));

        ctx.enter_stage(Stage::Discovery, None);
        read("liveness");
        ctx.enter_stage(Stage::Ports, None);
        for position in 10..1_000 {
            ctx.record_outcome(Outcome::Skipped { position });
        }
        read("silent hosts passed over");
        let passed_over = progress.fraction().expect("the plan's own stage");
        for position in 0..10 {
            ctx.record_outcome(Outcome::Answered { position });
        }
        read("ports probed");
        ctx.enter_stage(Stage::Services, Some(4));
        for _ in 0..4 {
            ctx.stage_advanced();
        }
        read("tcp services");
        ctx.enter_stage(Stage::Services, Some(4));
        read("udp services begun");
        for _ in 0..4 {
            ctx.stage_advanced();
        }
        read("udp services");
        for stage in [
            Stage::Detections,
            Stage::Os,
            Stage::Traceroute,
            Stage::Filters,
            Stage::IpProtocols,
        ] {
            ctx.enter_stage(stage, None);
            read("a later pass");
        }
        ctx.enter_stage(Stage::Finishing, None);
        read("finishing");

        let share = |(done, total): (u64, u64)| done as f64 / total as f64;
        assert_eq!(
            passed_over, 0.0,
            "silent hosts passed over read as ports probed"
        );
        for pair in readings.windows(2) {
            assert!(
                share(pair[1].1) >= share(pair[0].1),
                "the figure stepped back from {:?} to {:?}",
                pair[0],
                pair[1]
            );
        }
        let (last, others) = readings.split_last().expect("readings");
        assert_eq!(share(last.1), 1.0, "a finished scan reads whole");
        for (what, reading) in others {
            assert!(share(*reading) < 1.0, "{what} read whole: {reading:?}");
        }
    }

    /// A stage that turned out to have nothing to do is stepped over.
    ///
    /// The running order is a superset, and some stages never announce
    /// themselves.
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

        // Services and detections never announced themselves; the run is
        // still three stages on.
        ctx.enter_stage(Stage::Os, None);

        let (done, total) = session.progress().overall().expect("a staged run");
        assert_eq!(done * 4, total * 3, "three stages of four: {done}/{total}");
    }

    /// A session given no running order reports no whole-run figure.
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

    /// A stage that knows its own size answers for itself, ignoring the plan,
    /// which a port scan settles long before the detections end.
    #[test]
    fn a_stage_that_counted_itself_answers_for_itself() {
        let (session, ctx) = ScanSession::builder()
            .planning(Stage::Ports, Some(4))
            .build();

        // The plan, settled in full.
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

    /// An unsized stage other than the plan's own reports no fraction, as a
    /// port scan's liveness pass settles none of the plan's pairs.
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

    /// Entering the stage that is already current adds to it, as service
    /// detection does once per protocol.
    #[test]
    fn re_entering_a_stage_adds_to_it_rather_than_starting_it_over() {
        let (mut session, ctx) = ScanSession::new();

        ctx.enter_stage(Stage::Services, Some(3));
        ctx.stage_advanced();
        ctx.enter_stage(Stage::Services, Some(2));

        let progress = session.progress().clone();
        assert_eq!(progress.stage_total(), Some(5), "both runs' ports");
        assert_eq!(progress.stage_done(), 1, "and the one already finished");

        // The stage did not change the second time.
        let mut announced = 0;
        while let Some(event) = session.events().try_recv() {
            if matches!(event, ScanEvent::StageChanged { .. }) {
                announced += 1;
            }
        }
        assert_eq!(announced, 1, "one stage, announced once");
    }

    /// Every stage has a place in the list, and the list is in running order.
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

        for &stage in Stage::ALL {
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
    /// A running total with nothing to divide it into, as for a listener or a
    /// sweep of an IPv6 range too wide to number.
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
        ctx.record_outcome(Outcome::Exhausted { position: 1 });

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
    /// `Unasked` is what a scan that stopped early leaves behind, and the bar
    /// stays short.
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

    /// A resumed sitting measures against the whole job, since the numerator
    /// carries what earlier sittings settled.
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

    /// A reply from an excluded address leaves no host, emits no event, and
    /// `write_host` returns `false`.
    ///
    /// The `edit` closure panics, so the test also fails if the closure runs
    /// and its result is discarded, which would let a scanner's bookkeeping
    /// run for an excluded host.
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

        // One announcement, for the allowed address.
        let ScanEvent::HostUpdated(announced) =
            session.events().try_recv().expect("the allowed host")
        else {
            panic!("expected a host update");
        };
        assert_eq!(announced, ScopedIp::unscoped(allowed));
        assert!(session.events().try_recv().is_none());
    }

    /// `fe80::1` on two segments is two machines, and each keeps its own
    /// interface.
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

        // Each takes its link from the key it was created under.
        let mut zones: Vec<String> = ctx
            .store
            .iter()
            .filter_map(|entry| entry.value().zone().map(|zone| zone.name().to_owned()))
            .collect();
        zones.sort();
        assert_eq!(zones, ["en0", "en1"]);
    }

    /// A port scan holds its link-local targets bare, so its verdicts arrive
    /// with no interface. They land on the host the sweep found on the
    /// interface the scan named.
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
    #[test]
    fn one_global_address_seen_on_two_interfaces_is_one_host() {
        let global: IpAddr = "2001:db8::1".parse().expect("literal");
        let (_session, ctx) = ScanSession::new();

        ctx.write_host(ScopedIp::scoped(global, Zone::new(1, "en0")), |_| true);
        ctx.write_host(ScopedIp::scoped(global, Zone::new(2, "en1")), |_| true);

        assert_eq!(ctx.store.len(), 1, "one address, one machine");
    }

    /// A finding written back under a key read from the store lands on the
    /// same host, as every phase after discovery relies on.
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
        // A caller that never touches the event stream.
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

    /// The snapshot leaves the log for the report.
    #[test]
    fn snapshotting_failures_leaves_them_for_the_report() {
        let (_session, ctx) = ScanSession::new();
        ctx.record_failure(ScannerKind::Local, "eth0: no address".into());

        assert_eq!(ctx.failures_snapshot().len(), 1);
        assert_eq!(ctx.failures_snapshot().len(), 1, "reading is not taking");
        assert_eq!(ctx.take_failures().len(), 1, "and the report still gets it");
    }

    /// A failure is logged as the strategy's report name and the reason, with
    /// nothing else on the line.
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

        // Each strategy gets its own clone; the report is built from one.
        assert_eq!(ctx.take_failures().len(), 2);
    }

    /// A session built to continue an earlier sitting starts from its progress.
    ///
    /// Otherwise its first checkpoint would roll the cursor back to its own
    /// sitting's work.
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

    /// A session left unordered draws its own seed; one told there is no seed
    /// walks the plan.
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
    /// A seeded scan's answers arrive scattered across the plan. Counted in
    /// plan order, the watermark would stay near zero with half the plan
    /// waiting above it at the halfway mark. Counted along the walk, with each
    /// batch shuffled as the dispatcher does, what waits stays under a batch.
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

    /// An edit that asks not to be announced still marks the host changed for
    /// the journal, as when the echo probe adds evidence to a host already
    /// found.
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

        // Enriched: worth writing, not worth announcing.
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

    /// A stream nobody reads until the scan is over: the store holds
    /// everything, and what the buffer could not keep is counted in
    /// `EventsDropped`.
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

    /// A scan with no gap set grants every claim and never touches the map.
    #[test]
    fn a_scan_with_no_gap_never_holds_a_probe() {
        let (_session, ctx) = ScanSession::new();
        let ip: IpAddr = "192.0.2.1".parse().expect("an address");
        let now = Instant::now();

        assert!(ctx.spacing.claim_with(ip, || now).is_ok());
        assert!(
            ctx.spacing.claim_with(ip, || now).is_ok(),
            "a granted claim holds nothing back while there is no gap to hold it against"
        );
        assert!(ctx.probe_ready_at(ip, now).is_none());
        assert!(ctx.spacing.last_at_host.is_empty());
    }

    /// The longest gap a caller can write holds a host's next probe past the
    /// end of any scan without panicking, though `Duration::MAX` after the last
    /// probe is past what a clock can count to.
    #[test]
    fn the_longest_gap_holds_a_host_rather_than_panicking() {
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(Duration::MAX))
            .build();
        let ip: IpAddr = "192.0.2.1".parse().expect("an address");
        let now = Instant::now();

        let _ = ctx.spacing.claim_with(ip, || now).expect("the first probe");
        let ready = ctx
            .spacing
            .claim_with(ip, || now)
            .expect_err("asked too recently");
        assert!(ready > now + Duration::from_secs(365 * 24 * 60 * 60));
    }

    /// A host is ready until it is probed, and then not until the gap has run.
    #[test]
    fn a_gap_starts_at_the_first_probe_and_runs_from_the_last() {
        let gap = Duration::from_secs(3600);
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(gap))
            .build();
        let ip: IpAddr = "192.0.2.1".parse().expect("an address");
        let now = Instant::now();

        assert!(
            ctx.probe_ready_at(ip, now).is_none(),
            "an address nothing has probed is ready"
        );
        let _ = ctx.spacing.claim_with(ip, || now).expect("the first probe");

        assert_eq!(ctx.probe_ready_at(ip, now), Some(now + gap));
        assert_eq!(ctx.spacing.claim_with(ip, || now), Err(now + gap));
        assert!(
            ctx.spacing.claim_with(ip, || now + gap).is_ok(),
            "the gap having run, the host is ready again"
        );
    }

    /// One host's gap leaves every other host ready.
    #[test]
    fn a_gap_at_one_host_leaves_every_other_host_ready() {
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(Duration::from_secs(3600)))
            .build();
        let probed: IpAddr = "192.0.2.1".parse().expect("an address");
        let other: IpAddr = "192.0.2.2".parse().expect("an address");
        let now = Instant::now();

        let _ = ctx
            .spacing
            .claim_with(probed, || now)
            .expect("the first probe");

        assert!(ctx.spacing.claim_with(probed, || now).is_err());
        assert!(ctx.spacing.claim_with(other, || now).is_ok());
    }

    /// The scan-wide gap is the one that spaces a range: a probe at one host
    /// holds back the next probe at any other.
    #[test]
    fn a_scan_wide_gap_holds_every_host_behind_the_last_probe() {
        let gap = Duration::from_secs(3600);
        let (_session, ctx) = ScanSession::builder().probe_interval(Some(gap)).build();
        let first: IpAddr = "192.0.2.1".parse().expect("an address");
        let other: IpAddr = "192.0.2.2".parse().expect("an address");
        let now = Instant::now();

        let _ = ctx
            .spacing
            .claim_with(first, || now)
            .expect("the first probe");

        assert_eq!(ctx.probe_ready_at(other, now), Some(now + gap));
        assert_eq!(ctx.spacing.claim_with(other, || now), Err(now + gap));
        assert!(ctx.spacing.claim_with(other, || now + gap).is_ok());
    }

    /// With both gaps kept, a probe waits for whichever runs out later, and a
    /// claim turned away by one records nothing on the other.
    #[test]
    fn two_gaps_hold_a_probe_until_the_later_has_run() {
        let short = Duration::from_secs(60);
        let long = Duration::from_secs(3600);
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(long))
            .probe_interval(Some(short))
            .build();
        let ip: IpAddr = "192.0.2.1".parse().expect("an address");
        let other: IpAddr = "192.0.2.2".parse().expect("an address");
        let now = Instant::now();

        let _ = ctx.spacing.claim_with(ip, || now).expect("the first probe");
        assert_eq!(ctx.spacing.claim_with(ip, || now + short), Err(now + long));

        // Turned away at its host, so the scan-wide slot is still the first
        // probe's.
        assert!(ctx.spacing.claim_with(other, || now + short).is_ok());
    }

    /// A frame sent to a group spends the scan-wide gap and no host's, so a
    /// refund gives back only the scan's slot.
    #[test]
    fn a_group_probe_spends_the_scan_wide_gap_and_no_hosts() {
        let gap = Duration::from_secs(3600);
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(gap))
            .probe_interval(Some(gap))
            .build();
        let group: IpAddr = "ff02::2".parse().expect("an address");
        let host: IpAddr = "192.0.2.1".parse().expect("an address");
        let now = Instant::now();

        let claim = ctx
            .spacing
            .claim_group_with(group, || now)
            .expect("the first frame");
        assert_eq!(ctx.group_probe_ready_at(now), Some(now + gap));
        assert_eq!(ctx.spacing.claim_with(host, || now), Err(now + gap));
        assert!(
            ctx.spacing.last_at_host.is_empty(),
            "no host's clock was moved by a frame aimed at none of them"
        );

        ctx.refund_probe(claim);
        assert!(ctx.group_probe_ready_at(now).is_none());
        assert!(
            ctx.spacing.claim_with(host, || now).is_ok(),
            "the refunded frame's slot is free again"
        );
        assert_eq!(
            ctx.spacing.claim_group_with(group, || now),
            Err(now + gap),
            "and the host probe after it holds the scan's slot"
        );
    }

    /// A send the kernel refused gives its slot back, and the next probe may
    /// leave as though it had never been claimed.
    #[test]
    fn a_refunded_claim_frees_its_slot() {
        let gap = Duration::from_secs(3600);
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(gap))
            .probe_interval(Some(gap))
            .build();
        let ip: IpAddr = "192.0.2.1".parse().expect("an address");
        let now = Instant::now();

        let earlier = ctx.spacing.claim_with(ip, || now).expect("the first probe");
        let refused = ctx
            .spacing
            .claim_with(ip, || now + gap)
            .expect("the gap has run");
        ctx.refund_probe(refused);

        assert_eq!(
            ctx.probe_ready_at(ip, now + gap),
            None,
            "the refused probe's slot is free again"
        );
        assert_eq!(
            ctx.probe_ready_at(ip, now),
            Some(now + gap),
            "and the probe before it still holds its own"
        );
        let _ = earlier;
    }

    /// A refund arriving after a later claim leaves that claim's slot alone.
    #[test]
    fn a_refund_never_frees_a_later_probes_slot() {
        let gap = Duration::from_secs(3600);
        let (_session, ctx) = ScanSession::builder().probe_interval(Some(gap)).build();
        let first: IpAddr = "192.0.2.1".parse().expect("an address");
        let second: IpAddr = "192.0.2.2".parse().expect("an address");
        let now = Instant::now();

        let refused = ctx
            .spacing
            .claim_with(first, || now)
            .expect("the first probe");
        let sent = ctx
            .spacing
            .claim_with(second, || now + gap)
            .expect("the gap has run");
        ctx.refund_probe(refused);

        assert_eq!(
            ctx.probe_ready_at(first, now + gap),
            Some(now + gap + gap),
            "the probe that went out still holds the scan-wide slot"
        );
        let _ = sent;
    }

    /// Claims made at once from many threads grant one slot between them.
    #[test]
    fn concurrent_claims_share_one_slot() {
        let (_session, ctx) = ScanSession::builder()
            .host_probe_interval(Some(Duration::from_secs(3600)))
            .probe_interval(Some(Duration::from_secs(3600)))
            .build();
        let ip: IpAddr = "192.0.2.1".parse().expect("an address");
        let start = std::sync::Barrier::new(16);

        let granted = std::thread::scope(|scope| {
            let claims: Vec<_> = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        ctx.claim_probe(ip).is_ok()
                    })
                })
                .collect();
            claims
                .into_iter()
                .map(|claim| claim.join().expect("a claiming thread"))
                .filter(|granted| *granted)
                .count()
        });

        assert_eq!(granted, 1);
    }

    /// The clock starts on the first probe aimed at a host, so a host the scan
    /// reaches late still has its whole budget.
    #[test]
    fn a_budget_still_running_leaves_the_host_alone() {
        let (_session, ctx) = ScanSession::builder()
            .host_timeout(Some(Duration::from_secs(3600)))
            .build();
        let ip: IpAddr = "192.0.2.1".parse().expect("an address");

        assert!(!ctx.host_expired(ip));
        assert!(ctx.take_timed_out().is_empty());
    }

    /// A resume does not restore what this sitting is forbidden to report,
    /// including addresses excluded after the journal was written.
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

        // One announcement, for the restored host.
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

    /// What an edit attaches under a permitted key is held to the policy too.
    ///
    /// The local sweep, listen mode, mDNS hostname resolution and the resume
    /// path all add addresses inside the edit, under a key that passes the
    /// gate.
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

    /// An address filed as unreachable settles every target of the plan at
    /// it. A sweep settles the address; a port scan settles each of its ports,
    /// and one that earned a verdict first keeps it and is not counted twice.
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

    /// A machine an exclusion names is withheld at every address it answers
    /// from, such as the IPv6 addresses an excluded IPv4 device answers the
    /// all-nodes echo from. The shared hardware address ties them: a finding
    /// carrying it is dropped whole, the address is asked nothing more, and
    /// the phase lists it as excluded. A neighbour with other hardware is kept.
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

    /// An excluded address never leads a host, since the service, SNMP, TLS
    /// and detection passes connect to the leading address. A global IPv6
    /// address outranks a link-local, so it would otherwise take the lead.
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

    /// A router the policy forbids keeps its distance on a traced host's path
    /// and loses its address and timing.
    ///
    /// A trace sends nothing to the routers themselves, so only recording needs
    /// the policy. The hop stays as answered, since an empty entry would read
    /// as nothing known there.
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

    /// A host-down reason sent by `sender`, a middlebox in front of the host.
    fn unreachable_from(sender: IpAddr) -> StatusReason {
        StatusReason::new(StatusProtocol::IcmpUnreachable, "destination unreachable")
            .from_source(sender)
    }

    /// A middlebox the policy forbids is withheld from the evidence it sent
    /// about a permitted host, and the evidence is kept.
    ///
    /// The source is marked withheld, not cleared: a cleared source would say
    /// the host answered for itself.
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

    /// A host an earlier sitting recorded under an address excluded since is
    /// restored under its best remaining one.
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

    /// A port scan's settlements count port targets, so the addresses its
    /// liveness pass left are not counted. A sweep's plan is its addresses, and
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
