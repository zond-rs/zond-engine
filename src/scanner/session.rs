// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A scan while it is running
//!
//! The live half of what a scan produces. [`ScanReport`](super::report) is the
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
//! read on where it needs one — a [`ScopedIp`]. For every IPv4 address and every
//! routable IPv6 one that is the bare address and nothing more, because a
//! machine reachable at a global address is the same machine through whichever
//! interface answered it.
//!
//! **An IPv6 link-local is the exception, and it is why the key exists.**
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
use tokio::sync::mpsc;
use tracing::error;

use crate::info;
use crate::journal::settle::{Outcome, Settled, Settlements};
use crate::model::exclusion::Exclusions;
use crate::model::host::Host;
use crate::model::ip::scoped::{ScopedIp, Zone};
use crate::model::ip::set::Positions;
use crate::model::technique::TcpScanTechnique;
use crate::scanner::handle::ScanHandle;
use crate::scanner::report::{Attachment, AttachmentSource, ProbeStats, ScannerFailure};

/// Which scanning strategy a [`ScanEvent::ScannerFailed`] refers to.
///
/// Marked `#[non_exhaustive]`: strategies are added as the engine learns to
/// probe in new ways, and a consumer matching on this enum should pay for that
/// with a recompile rather than a major version.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerKind {
    /// Layer-2 discovery (ARP/NDP) on a local segment.
    Local,
    /// Reading a link's own traffic, having sent nothing.
    ///
    /// The one strategy here that puts no packet on the wire, which changes
    /// what its counters mean. `sends_attempted` is zero for it and always
    /// will be; what it saw is bounded by what the network happened to carry
    /// rather than by anything this engine chose, so a quiet run says the
    /// segment was quiet and never that a host was absent.
    Passive,
    /// Raw TCP SYN discovery for gateway-routed targets.
    Routed,
    /// Raw TCP SYN port scanning (the port-scan phase, distinct from [`Routed`]
    /// host discovery).
    ///
    /// [`Routed`]: ScannerKind::Routed
    SynPort,
    /// Raw TCP port scanning with a probe that is not a SYN - a FIN, a flagless
    /// segment, a bare ACK.
    ///
    /// The same scanner as [`SynPort`], asking a different question. They are
    /// named apart because a report saying `syn_port` should mean a half-open
    /// connection attempt was made, and for these it was not; which technique
    /// ran is in the phase's settings.
    ///
    /// [`SynPort`]: ScannerKind::SynPort
    TcpPort,
    /// Unprivileged TCP connect fallback, for both host discovery and port
    /// scanning.
    Connect,
    /// Unprivileged UDP fallback.
    ///
    /// Named apart from [`Connect`] because a report has to be able to say which
    /// half of an unprivileged scan failed. The two send different datagrams,
    /// read different answers, and fail for different reasons — a host that
    /// refuses one may be perfectly happy with the other, and one name for both
    /// makes that indistinguishable.
    ///
    /// [`Connect`]: ScannerKind::Connect
    ConnectUdp,
    /// Privileged raw UDP port scanning.
    UdpPort,
    /// The active operating-system echo probe, sent at the hosts the passive
    /// sources could not name.
    ///
    /// Named apart from the port scanners because it answers a different
    /// question about a different dimension: not which ports a host has, but
    /// which stack answered the ping. A report attributing an echo probe to any
    /// other strategy would describe traffic nobody sent.
    OsEcho,
    /// The active operating-system series probe: one host asked the same
    /// question several times, so the policies behind its counters become
    /// visible.
    ///
    /// Named apart from [`SynPort`] though it sends the same segment, because
    /// what it is doing with the answers is a different activity and a report
    /// that filed it as a port scan would describe traffic nobody asked for:
    /// these probes revisit ports whose state is already settled, and none of
    /// their replies changes one.
    ///
    /// [`SynPort`]: ScannerKind::SynPort
    OsSeries,
    /// The active operating-system management probe: one SNMP `GetRequest` at a
    /// host whose kernel is not otherwise known.
    ///
    /// Named apart from the port scanners because it establishes no port state.
    /// It asks one question of one service and files the answer against the
    /// *host*; whether anything is listening on 161 is the port scan's to
    /// report, and this phase deliberately does not.
    OsSnmp,
    /// Composite scanner that delegates to protocol-specific scanners.
    Composite,
}

impl ScannerKind {
    /// What a raw TCP scan carrying `technique` reports itself as.
    ///
    /// One function because the answer has to be the same everywhere it is
    /// asked, and it is asked twice: once by the plan, to attribute a step that
    /// could not open its socket, and once by the running scanner, to attribute
    /// anything that went wrong afterwards. Two spellings meant one strategy
    /// filed its failures under two names depending on when it failed, and the
    /// planning half called every technique [`SynPort`](Self::SynPort) whether
    /// or not a SYN was involved.
    pub const fn for_raw_tcp(technique: TcpScanTechnique) -> Self {
        match technique {
            TcpScanTechnique::Syn => Self::SynPort,
            _ => Self::TcpPort,
        }
    }
}

/// Lightweight notifications for the status of an ongoing scan.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ScanEvent {
    /// Something was learned about the host at this address.
    ///
    /// The event carries only the address, deliberately: a scan can emit
    /// thousands of these, and copying a whole [`Host`] into each one would cost
    /// more than the notification is worth. Read the current state back from
    /// [`ScanSession::hosts`], which is a single lookup and always up to date —
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
}

/// What a scan has found so far, readable while it is still running.
///
/// A cheap, cloneable view of one shared store. Cloning it does not copy the
/// hosts; every clone reads the same live data, so a consumer can hand one to a
/// rendering task and keep another for itself.
///
/// **Reads return owned snapshots.** [`get`](Self::get) clones the host rather
/// than lending a reference into the map, because the alternative is a guard
/// held across whatever the caller does next — and a scanner writing to the same
/// key meanwhile is not a hypothetical, it is the normal case. A caller cannot
/// hold this wrong.
///
/// The concrete map behind it is deliberately not visible. It is an
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
    /// **An IPv6 link-local needs the interface it was read on.** `fe80::1`
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
    /// changes a host once per port — so a consumer that answers each event with
    /// a [`get`](Self::get) clones a growing port map on every port of every
    /// host, which is quadratic in the size of the scan and invisible until the
    /// port count is large. Take what the event needs through this, and clone
    /// only once the answer is that the host is worth rendering.
    ///
    /// `read` runs under the store's own guard. It must not touch the store
    /// again — that deadlocks — and it should not block, since a scanner writing
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
    /// [`ScanReport`](crate::scanner::report::ScanReport) orders its hosts.
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
    /// Test-only, and deliberately not how a scan records a finding — that is
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
#[derive(Debug)]
pub struct ScanEvents {
    rx: mpsc::UnboundedReceiver<ScanEvent>,
}

impl ScanEvents {
    /// Waits for the next event. `None` once the scan has ended and every event
    /// it emitted has been taken, which is the definitive end of the stream.
    pub async fn recv(&mut self) -> Option<ScanEvent> {
        self.rx.recv().await
    }

    /// The next event if one is already queued, without waiting.
    ///
    /// `None` covers both "nothing queued right now" and "the scan is over", so
    /// it drains a finished scan but cannot detect the end of a running one. Use
    /// [`recv`](Self::recv) for that.
    pub fn try_recv(&mut self) -> Option<ScanEvent> {
        self.rx.try_recv().ok()
    }
}

/// A handle to an active network scan: what it has found, what it is doing, and
/// the means to stop it.
///
/// Returned by [`discover`](crate::scanner::discover) and
/// [`scan`](crate::scanner::scan) alongside the
/// [`ScanTask`](crate::scanner::ScanTask) that resolves to the final report.
/// This is the live half of that pair — it describes the present moment and
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
    /// this is only needed to move the event stream — which is not, there being
    /// exactly one of it.
    pub fn into_parts(self) -> (HostStore, ScanEvents, ScanHandle) {
        (self.store, self.events, self.handle)
    }
}

/// Where an instrumented scanner leaves its counters for the final
/// [`ScanReport`](crate::scanner::report::ScanReport).
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

/// Where strategy failures accumulate for the final
/// [`ScanReport`](crate::scanner::report::ScanReport).
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

/// The links a phase swept, gathered as its strategies run.
///
/// A sweep of a local segment reaches every host on the link, not only the
/// addresses it was handed: an all-nodes solicitation is one probe every IPv6
/// neighbour is required to answer. That is coverage, and there is no address
/// range that expresses it — a link is named by the interface it is on.
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
/// re-announcing itself every thirty seconds — which is what they do — is
/// recorded once rather than once per frame. The *latest* announcement wins,
/// because the question is what this machine is plugged into now and a cable
/// somebody moved should not be reported as two attachments held at once.
///
/// A link answering on both LLDP and CDP keeps both, deliberately: which
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

/// What a journal needs from a running scan, and nothing more.
///
/// See [`ScanContext::progress`] for why this exists rather than a context.
#[derive(Debug, Clone)]
pub struct ScanProgress {
    store: Arc<DashMap<ScopedIp, Host>>,
    changed: Arc<ChangedHosts>,
    settlements: Arc<Settlements>,
    failures: Arc<FailureLog>,
}

impl ScanProgress {
    /// How far the scan has got, and what became of what it did not settle.
    pub fn settlements(&self) -> &Settlements {
        &self.settlements
    }

    /// Takes the hosts whose findings have changed since this was last called.
    pub fn take_changed_hosts(&self) -> Vec<Host> {
        self.changed
            .drain()
            .into_iter()
            .filter_map(|key| self.store.get(&key).map(|host| host.clone()))
            .collect()
    }

    /// Every host found so far, cloned.
    pub fn hosts_snapshot(&self) -> Vec<Host> {
        self.store
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// How many hosts have been found so far.
    pub fn host_count(&self) -> usize {
        self.store.len()
    }

    /// Files a failure to the report. Not to the event stream; see
    /// [`ScanContext::progress`].
    pub fn record_failure(&self, scanner: ScannerKind, reason: String) {
        error!("journal: {reason}");
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
    pub(crate) events_tx: mpsc::UnboundedSender<ScanEvent>,
    pub(crate) failures: Arc<FailureLog>,
    pub(crate) probe_stats: Arc<ProbeStatsLog>,
    /// Addresses this host has no route to, so nothing could be sent to them.
    pub(crate) unroutable: Arc<UnroutableLog>,
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
    /// Marked on every write, which is deliberately *not* the condition that
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
    /// stream. A sweep has no such stream — a
    /// [`HostScanner`](crate::scanner::strategy::HostScanner) owns its targets
    /// — so the numbering travels here instead.
    ///
    /// **Empty is what keeps the two apart.** A port scan's liveness pass runs
    /// the discovery strategies against a port scan's context, and those
    /// strategies settle addresses. Numbering them against the port plan would
    /// advance its watermark over probes nobody sent, so a context that does not
    /// count addresses answers `None` to every address and nothing is recorded.
    pub(crate) positions: Arc<Positions>,
}

impl ScanContext {
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
    /// **This is the enforcement that a subtraction from the target list cannot
    /// perform**, and putting it here rather than at each scanner is deliberate.
    /// Every finding in the engine reaches the store through this function, so
    /// this one branch covers the ARP and neighbour-advertisement replies a
    /// sweep learns addresses from, the host's own neighbour table, the mDNS
    /// records, and — transitively, because they read the store to decide who to
    /// probe — the service, OS-series and SNMP phases that run afterwards. A
    /// scanner cannot forget to apply the policy, because a scanner is not where
    /// it is applied.
    ///
    /// A drop is logged rather than counted. The property worth checking is that
    /// no excluded address appears in the report, and a reader can confirm that
    /// against the ranges the report already records — which is a better
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
            // right — and the key is the one thing here that cannot be wrong
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
        // watcher is told is about novelty — a host already announced does not
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
    /// await. Take what you need out of the host and let the guard go.
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
    /// that drains these into a [`ScanReport`](crate::scanner::report::ScanReport),
    /// so this is how they read what a strategy filed. Non-destructive on
    /// purpose — draining is the report's privilege, and a caller who could do
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

    /// Records that this phase swept a whole link, not merely the addresses on
    /// it that were named.
    ///
    /// Called by a strategy that put a probe on the segment which every host
    /// there is required to answer. What it buys is stated on
    /// [`TargetScope::links`](crate::scanner::report::TargetScope::links): a
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
    /// Called by whatever read an announcement off a link — see
    /// [`Attachment`](crate::scanner::report::Attachment) for why this is a fact
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
    pub fn record_many(&self, outcome: Outcome, count: u64) {
        self.settlements.record_many(outcome, count);
    }

    /// Records what became of one address, in a scan counted in addresses.
    ///
    /// The position comes from the plan this scan is numbered in, which the
    /// caller does not need to know: a strategy knows it asked an address and
    /// what came back, and this turns that into a position a resume can skip.
    ///
    /// **Nothing is recorded in two cases, and both are correct.** A scan not
    /// counted in addresses has no numbering, so a port scan's liveness pass
    /// settles nothing. And an address the plan does not name has no position —
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
    pub fn restore_hosts(&self, hosts: &[Host]) {
        for host in hosts {
            let key = host.scoped_ip();
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
    /// **Deliberately not a [`ScanContext`].** A context carries the event
    /// sender, and a checkpoint task holding one would keep the event stream
    /// open after the scan had ended — so a caller watching that stream to know
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
        }
    }

    /// Every host found so far, cloned.
    ///
    /// For a journal compacting its findings, which needs the whole state rather
    /// than what changed recently.
    pub fn hosts_snapshot(&self) -> Vec<Host> {
        self.store
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
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
        self.changed
            .drain()
            .into_iter()
            .filter_map(|ip| self.store.get(&ip).map(|host| host.clone()))
            .collect()
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
    /// [`PhaseRecorder::finish`](crate::scanner::report::PhaseRecorder::finish),
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

impl ScanSession {
    /// Opens a session and the context the strategies behind it write into.
    ///
    /// A caller wrapping the engine normally receives the session already
    /// built, from [`discover`](crate::scanner::discover) or
    /// [`scan`](crate::scanner::scan), and never calls this. A caller
    /// orchestrating their own scan calls it first: every strategy in
    /// [`strategy`](crate::scanner::strategy) is constructed with a
    /// [`ScanContext`], and this is where one comes from.
    pub fn new() -> (Self, ScanContext) {
        Self::with_exclusions(Exclusions::none())
    }

    /// [`new`](Self::new), with addresses the scan may not record.
    ///
    /// What [`discover`](crate::scanner::discover) and [`scan`](crate::scanner::scan)
    /// call, with [`ZondConfig::exclusions`](crate::config::ZondConfig::exclusions).
    /// A caller orchestrating their own scan and honouring an exclusion policy
    /// has to call this rather than `new`: subtracting the excluded addresses
    /// from their own target list covers the addresses they named, and a segment
    /// sweep does not confine itself to those. See [`Exclusions`] for what each
    /// of the two enforcements is for.
    pub fn with_exclusions(exclusions: Exclusions) -> (Self, ScanContext) {
        Self::resuming(exclusions, &crate::journal::cursor::Checkpoint::default())
    }

    /// [`with_exclusions`](Self::with_exclusions), continuing an earlier
    /// sitting's progress.
    ///
    /// `settled` seeds the cursor this scan checkpoints from. Without it a
    /// resumed scan would write a cursor covering only its own sitting, and the
    /// journal would forget everything the first one settled.
    pub fn resuming(
        exclusions: Exclusions,
        settled: &crate::journal::cursor::Checkpoint,
    ) -> (Self, ScanContext) {
        Self::sweeping(exclusions, settled, Positions::default())
    }

    /// [`resuming`](Self::resuming), for a scan counted in addresses.
    ///
    /// `positions` numbers the sweep's plan, so that a strategy which has
    /// earned a verdict for an address can settle it without knowing where in
    /// the plan it sits — see
    /// [`ScanContext::settle_address`](ScanContext::settle_address).
    ///
    /// This is the only constructor that supplies one. A port scan is counted
    /// in address-and-port pairs and numbers them on its target stream, so it
    /// leaves this empty and the discovery strategies running inside its
    /// liveness pass settle nothing.
    pub fn sweeping(
        exclusions: Exclusions,
        settled: &crate::journal::cursor::Checkpoint,
        positions: Positions,
    ) -> (Self, ScanContext) {
        let store = Arc::new(DashMap::new());
        let handle = ScanHandle::new();
        let (events_tx, rx) = mpsc::unbounded_channel();

        let session = Self {
            store: HostStore::new(store.clone()),
            events: ScanEvents { rx },
            handle: handle.clone(),
        };

        let ctx = ScanContext {
            handle,
            store,
            events_tx,
            failures: Arc::new(FailureLog::default()),
            probe_stats: Arc::new(ProbeStatsLog::default()),
            unroutable: Arc::new(UnroutableLog::default()),
            swept_links: Arc::new(SweptLinks::default()),
            attachments: Arc::new(Attachments::default()),
            exclusions: Arc::new(exclusions),
            changed: Arc::new(ChangedHosts::default()),
            settlements: Arc::new(Settlements::resuming(settled)),
            positions: Arc::new(positions),
        };

        (session, ctx)
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗██████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████╗   ██║   ███████║ ║
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
    /// while still letting a scanner's own bookkeeping — a deadline update, a
    /// counter, a hostname lookup keyed off the edit — run for a host nobody
    /// may look at.
    #[test]
    fn an_excluded_address_reaches_neither_the_store_nor_the_stream() {
        let excluded: IpAddr = "10.0.5.7".parse().expect("literal");
        let allowed: IpAddr = "10.0.6.7".parse().expect("literal");

        let mut ips = crate::model::ip::set::IpSet::new();
        ips.insert_range("10.0.5.0/24".parse().expect("a valid range"));
        let (mut session, ctx) = ScanSession::with_exclusions(Exclusions::new(ips));

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
    /// into another machine's record — under the wrong interface, since
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
    /// forgotten — silently, since both scans report success.
    #[test]
    fn a_resuming_session_starts_from_the_earlier_cursor() {
        use crate::journal::cursor::Checkpoint;

        let settled = Checkpoint {
            watermark: 12,
            settled_above: vec![14],
        };
        let (_session, ctx) = ScanSession::resuming(Exclusions::none(), &settled);

        assert_eq!(ctx.settlements().settled_count(), 13);
        assert_eq!(ctx.settlements().checkpoint(), settled);

        // A fresh session has nothing inherited.
        let (_session, fresh) = ScanSession::new();
        assert_eq!(fresh.settlements().settled_count(), 0);
    }

    /// **What a watcher is told and what a journal writes are two questions.**
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
}
