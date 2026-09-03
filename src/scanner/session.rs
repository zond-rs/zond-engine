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
//! of them finds two neighbours under one number. Keyed by the bare address the
//! second write landed on the first's entry, and one machine's hardware address,
//! roles and round trips were folded into another machine's record.
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
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tracing::error;

use crate::detect::compute::DetectionRunRecord;
use crate::info;
use crate::journal::settle::{Outcome, Settled, Settlements};
use crate::model::exclusion::Exclusions;
use crate::model::host::Host;
use crate::model::ip::scoped::{ScopedIp, Zone};
use crate::model::ip::set::Positions;
use crate::model::port::Protocol;
use crate::report::ScannerKind;
use crate::report::{Attachment, AttachmentSource, ProbeStats, Refusal, ScannerFailure};
use crate::scanner::handle::ScanHandle;

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
}

impl ScanSession {
    /// What the scan has found so far.
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

    /// Takes the session apart, for a caller that wants to watch the events from
    /// one task and read the hosts from another.
    ///
    /// [`HostStore`] and [`ScanHandle`] are both cloneable and shareable, so
    /// this is only needed to move the event stream, which is not, there being
    /// exactly one of it.
    pub fn into_parts(self) -> (HostStore, ScanEvents, ScanHandle) {
        (self.store, self.events, self.handle)
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

/// The tapes of detection runs, captured as the detection phase produces them and
/// drained into the journal by the checkpoint task. A plain queue: unlike the
/// responses, a tape is never looked up by port, only appended once and taken in a
/// batch.
#[derive(Debug, Default)]
pub(crate) struct Tapes {
    inner: Mutex<Vec<DetectionRunRecord>>,
}

impl Tapes {
    /// Records one detection run's tape.
    pub(crate) fn record(&self, run: DetectionRunRecord) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(run);
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

/// Addresses this host had no route to, gathered across a phase.
///
/// A set, so a target probed several times is named once, and ordered so two
/// runs of the same scan report them the same way.
///
/// Kept apart from [`FailureLog`] because the two are different findings. A
/// strategy that could not run means the scan covered less than it was asked
/// to and its result is partial; an address with no route means that address is
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

    fn drain(&self) -> Vec<IpAddr> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *entries).into_iter().collect()
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
        let ready = last + minimum;
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
/// is the narrow view a journal gets, and the three readings they had in common
/// were three copies before this.
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

    /// Files a failure to the report. Not to the event stream; see
    /// [`ScanContext::progress`].
    ///
    /// Logged under the strategy that is failing, as
    /// [`ScanContext::record_failure`] logs it, rather than under a fixed word:
    /// the checkpoint task is not the only thing that reaches the report this
    /// way any more, and a line saying `journal` for all of them told a reader
    /// less than the name it already had.
    pub fn record_failure(&self, scanner: ScannerKind, reason: String) {
        error!("{scanner:?} failed: {reason}");
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
    /// Addresses this host has no route to, so nothing could be sent to them.
    pub(crate) unroutable: Arc<UnroutableLog>,
    /// Addresses the scan stopped working on because their budget ran out.
    pub(crate) timed_out: Arc<TimedOutLog>,
    /// When each host's budget started, for a scan that set one.
    pub(crate) clocks: Arc<HostClocks>,
    pub(crate) spacing: Arc<HostSpacing>,
    pub(crate) swept_links: Arc<SweptLinks>,
    /// Where this machine turned out to be plugged in, as the equipment said.
    pub(crate) attachments: Arc<Attachments>,
    /// Addresses no finding may be recorded against.
    ///
    /// Behind an `Arc` because a context is cloned once per strategy and the
    /// policy is read, never written, by all of them.
    pub(crate) exclusions: Arc<Exclusions>,
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
    /// [`None`] for a scan that walks its plan in order. Read by the dispatcher
    /// and by nothing else, since it decides what to ask next rather than
    /// anything about what an answer means.
    pub(crate) order_seed: Option<u64>,
    /// Each open port's gathered responses, kept from the service phase for the
    /// detection phase to hand a passive detection.
    pub(crate) responses: Arc<Responses>,
    /// The tapes of detection runs, captured for the journal to write down so a
    /// recorded scan can be replayed offline.
    pub(crate) tapes: Arc<Tapes>,
    /// The corpus the detection phase runs, the shipped one unless a caller set
    /// their own on the config. Cheap to clone: the compiled tiers sit behind
    /// `Arc`s.
    pub(crate) detections: crate::detect::Detections,
}

impl ScanContext {
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
    /// An address the scan's [`Exclusions`] forbid is dropped here: `edit` is not
    /// run, no host is created, no event is emitted, and this returns `false`.
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
    /// A drop is logged rather than counted. The property worth checking is that
    /// no excluded address appears in the report, and a reader can confirm that
    /// against the ranges the report already records, which is a better
    /// guarantee than a number this engine reports about itself.
    pub fn write_host(
        &self,
        key: impl Into<ScopedIp>,
        edit: impl FnOnce(&mut Host) -> bool,
    ) -> bool {
        let key = key.into();
        let ip = key.addr();

        if self.exclusions.excludes(&ip) {
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
            host
        });
        let announce = edit(&mut host);
        drop(host);

        // Marked whether or not the edit asked to be announced. `edit` was
        // handed a `&mut Host` and may have moved the record however it
        // answered, and a journal that missed that would give back a quieter
        // host than the scan found.
        //
        // **These are two questions, and they were one for a while.** What a
        // watcher is told is about novelty: a host already announced does not
        // need announcing again, which is why the echo probe answers `false`
        // for a host that was already up. What a journal writes is about state,
        // and that probe had just added an `icmp_echo` reason and a round trip
        // to it. Sharing the boolean silently dropped both from every recorded
        // scan.
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
        self.store.get(&ip.into()).map(|entry| read(entry.value()))
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
        self.store.contains_key(ip)
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
    pub fn record_failure(&self, scanner: ScannerKind, reason: String) {
        error!("scanner {scanner:?} failed: {reason}");
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
    /// Public for the reason [`record_failure`](Self::record_failure) is: a
    /// caller assembling their own scan decides their own coverage, and one who
    /// could not say what they declined would produce a report claiming to have
    /// covered ground nobody looked at.
    pub fn record_refusal(&self, refusal: Refusal) {
        info!(verbosity = 1, "not covered: {}", refusal.reason());
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

    /// Records that this host has no route to `address`, so nothing was sent to
    /// it.
    ///
    /// Not a failure and not an event: no strategy broke and nothing about the
    /// scan's standing changes. It is recorded because the address was asked
    /// about and not covered, and a report that omitted it would leave the
    /// caller to work out from a host count why one of their targets is missing.
    pub fn record_unroutable(&self, address: IpAddr) {
        self.unroutable.insert(address);
    }

    /// The unroutable addresses filed so far, taken.
    pub(crate) fn take_unroutable(&self) -> Vec<IpAddr> {
        self.unroutable.drain()
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

    /// The addresses left early so far, taken.
    pub(crate) fn take_timed_out(&self) -> Vec<IpAddr> {
        self.timed_out.drain()
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

    /// Records what became of one target, for a later resume.
    ///
    /// Not the same question as the verdict: a target reaches the store with a
    /// port state, and this says whether the scan *earned* it or assigned it
    /// because the run ended. See [`Outcome`].
    pub fn record_outcome(&self, outcome: Outcome) {
        self.settlements.record(outcome);
    }

    /// Records `count` targets ending the same way, for the outcomes that carry
    /// no position. See [`Settlements::record_many`].
    pub fn record_many_outcomes(&self, outcome: Outcome, count: u64) {
        self.settlements.record_many(outcome, count);
    }

    /// Records what became of one address, in a scan counted in addresses.
    ///
    /// The position comes from the plan this scan is numbered in, which the
    /// caller does not need to know: a strategy knows it asked an address and
    /// what came back, and this turns that into a position a resume can skip.
    ///
    /// Nothing is recorded in two cases, and both are correct. A scan not
    /// counted in addresses has no numbering, so a port scan's liveness pass
    /// settles nothing. And an address the plan does not name has no position:
    /// a sweep finds neighbours it was never asked about, and those are findings
    /// rather than plan targets. Either way the address is asked again on the
    /// next sitting, which is the direction this has to fail in.
    pub fn settle_address(&self, ip: IpAddr, settled: Settled) {
        if let Some(position) = self.positions.find(ip) {
            self.record_outcome(settled.at(position));
        }
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
    /// The exclusions this sitting was given apply to what comes back.
    /// [`Exclusions`] promises that no excluded address appears in the report,
    /// and names two places it is enforced: before anything is opened, and at
    /// [`write_host`](Self::write_host) on every finding. This is a third way
    /// into the store, added for resume, and it went through neither, so a scan
    /// interrupted before an exclusion was added restored the addresses that
    /// exclusion now forbids, and reported them.
    ///
    /// The journal itself is left alone. It is an honest record of a sitting
    /// that was allowed to make it, and rewriting history to match a policy that
    /// arrived later would be the wrong repair. What changes is only what this
    /// sitting is willing to say.
    pub fn restore_hosts(&self, hosts: &[Host]) {
        for host in hosts {
            let key = host.scoped_ip();
            let ip = key.addr();

            if self.exclusions.excludes(&ip) {
                info!(
                    verbosity = 2,
                    "excluded address {ip} is in the journal from an earlier sitting; \
                     leaving it out of this one"
                );
                continue;
            }

            match self.store.get_mut(&key) {
                Some(mut existing) => existing.merge(host.clone()),
                None => {
                    self.store.insert(key.clone(), host.clone());
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
    pub fn progress(&self) -> ScanProgress {
        ScanProgress {
            store: Arc::clone(&self.store),
            changed: Arc::clone(&self.changed),
            settlements: Arc::clone(&self.settlements),
            failures: Arc::clone(&self.failures),
            tapes: Arc::clone(&self.tapes),
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

/// Builds a [`ScanSession`] and the [`ScanContext`] the strategies behind it
/// write into.
///
/// Six things a session can be given, five of which most callers leave alone.
/// They used to be four constructors chaining into each other, which put the
/// widest of them under the narrowest name: a caller who wanted exclusions
/// *and* a resume point *and* an address numbering had to call `sweeping`, and
/// one who wanted the numbering without the resume had to know that
/// `Checkpoint::default()` was the neutral value. Here each is named once and
/// there is one neutral state rather than three.
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
    detections: crate::detect::Detections,
    host_timeout: Option<Duration>,
    scan_timeout: Option<Duration>,
    host_probe_interval: Option<Duration>,
    order_seed: Option<u64>,
}

impl SessionBuilder {
    /// Addresses the scan may not record a finding against.
    ///
    /// A caller orchestrating their own scan and honouring an exclusion policy
    /// has to set this rather than subtract the addresses from their own target
    /// list: the subtraction covers the addresses they named, and a segment
    /// sweep does not confine itself to those. See [`Exclusions`] for what each
    /// of the two enforcements is for.
    pub fn excluding(mut self, exclusions: Exclusions) -> Self {
        self.exclusions = exclusions;
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
    /// against. See [`Permutation`](crate::scanner::order::Permutation).
    ///
    /// Leave it alone and the targets come out in plan order, shuffled within a
    /// batch, which is what a scan whose plan cannot be addressed by position
    /// falls back to anyway.
    ///
    /// A caller journalling their scan should pass what the journal recorded, so
    /// a resumed sitting continues in the order the first one was going to use.
    /// [`scan_with_journal`](crate::scanner::scan_with_journal) does.
    pub fn ordering(mut self, seed: Option<u64>) -> Self {
        self.order_seed = seed;
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
    pub fn host_probe_interval(mut self, minimum: Option<Duration>) -> Self {
        self.host_probe_interval = minimum;
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

        let session = ScanSession {
            store: HostStore::new(store.clone()),
            events: ScanEvents { rx },
            handle: handle.clone(),
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
            clocks: Arc::new(HostClocks {
                budget: self.host_timeout,
                started: DashMap::new(),
            }),
            spacing: Arc::new(HostSpacing {
                minimum: self.host_probe_interval,
                last_sent: DashMap::new(),
            }),
            swept_links: Arc::new(SweptLinks::default()),
            attachments: Arc::new(Attachments::default()),
            exclusions: Arc::new(self.exclusions),
            changed: Arc::new(ChangedHosts::default()),
            settlements: Arc::new(Settlements::resuming(&self.settled)),
            positions: Arc::new(self.positions),
            order_seed: self.order_seed,
            responses: Arc::new(Responses::default()),
            tapes: Arc::new(Tapes::default()),
            detections: self.detections,
        };

        (session, ctx)
    }
}

impl ScanSession {
    /// A session and the context the strategies behind it write into, with
    /// nothing excluded, nothing resumed and no address numbering.
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
    use crate::model::host::{HostStatus, StatusProtocol, StatusReason};

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
        let excluded: IpAddr = "10.0.5.7".parse().expect("literal");
        let allowed: IpAddr = "10.0.6.7".parse().expect("literal");

        let mut ips = crate::model::ip::set::IpSet::new();
        ips.insert_range("10.0.5.0/24".parse().expect("a valid range"));
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
    /// Keyed by the bare address the second write landed on the first's entry,
    /// and one machine's hardware address, roles and round trips were folded
    /// into another machine's record: under the wrong interface, since
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
    /// names the two places it is enforced. `restore_hosts` was a third way into
    /// the store and went through neither, so a scan interrupted before an
    /// exclusion was added brought the forbidden addresses back with it — under
    /// the operator's *current* configuration, in the engine's own continuation
    /// of its own scan.
    #[test]
    fn a_resume_leaves_out_an_address_this_sitting_may_not_report() {
        let excluded: IpAddr = "10.0.5.7".parse().expect("literal");
        let allowed: IpAddr = "10.0.6.7".parse().expect("literal");

        let mut ips = crate::model::ip::set::IpSet::new();
        ips.insert_range("10.0.5.0/24".parse().expect("a valid range"));
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
}
