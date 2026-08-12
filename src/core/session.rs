// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::error;

use crate::core::handle::ScanHandle;
use crate::core::models::host::Host;
use crate::core::report::{ProbeStats, ScannerFailure};

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
    /// Composite scanner that delegates to protocol-specific scanners.
    Composite,
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
    HostUpdated(IpAddr),

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
    inner: Arc<DashMap<IpAddr, Host>>,
}

impl HostStore {
    fn new(inner: Arc<DashMap<IpAddr, Host>>) -> Self {
        Self { inner }
    }

    /// The host recorded at `ip`, as it stands right now.
    ///
    /// Keyed by the address a scanner wrote it under, which for a host found at
    /// several addresses is whichever one it was first credited to. To look a
    /// host up by any of its addresses, search
    /// [`snapshot`](Self::snapshot) on [`Host::ips`].
    pub fn get(&self, ip: &IpAddr) -> Option<Host> {
        self.inner.get(ip).map(|entry| entry.value().clone())
    }

    /// Whether anything has been recorded at `ip`.
    ///
    /// Cheaper than [`get`](Self::get) when the host itself is not wanted, since
    /// nothing is cloned.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.inner.contains_key(ip)
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
    /// [`ScanReport`](crate::core::report::ScanReport) orders its hosts.
    pub fn snapshot(&self) -> Vec<Host> {
        let mut hosts: Vec<Host> = self
            .inner
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        hosts.sort_by_key(Host::primary_ip);
        hosts
    }

    /// Puts a host in the store directly, replacing anything at that address.
    ///
    /// Test-only, and deliberately not how a scan records a finding — that is
    /// [`ScanContext::write_host`], which upserts, merges and announces the
    /// change. This exists for the tests that need a store already holding a
    /// particular host, standing in for the scanner that would have written it.
    #[cfg(test)]
    pub(crate) fn insert(&self, ip: IpAddr, host: Host) {
        self.inner.insert(ip, host);
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
/// [`ScanReport`](crate::core::report::ScanReport).
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

    #[cfg(feature = "test-support")]
    fn snapshot(&self) -> Vec<ProbeStats> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// Where strategy failures accumulate for the final
/// [`ScanReport`](crate::core::report::ScanReport).
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
    pub(crate) store: Arc<DashMap<IpAddr, Host>>,
    pub(crate) events_tx: mpsc::UnboundedSender<ScanEvent>,
    pub(crate) failures: Arc<FailureLog>,
    pub(crate) probe_stats: Arc<ProbeStatsLog>,
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
    pub fn write_host(&self, ip: IpAddr, edit: impl FnOnce(&mut Host) -> bool) -> bool {
        let mut is_new = false;
        let mut host = self.store.entry(ip).or_insert_with(|| {
            is_new = true;
            Host::new(ip)
        });
        let changed = edit(&mut host);
        drop(host);

        if changed || is_new {
            let _ = self.events_tx.send(ScanEvent::HostUpdated(ip));
        }
        is_new
    }

    /// The single place a strategy failure enters the record.
    ///
    /// Logs it, files it for the final report, and announces it to any live
    /// consumer - in that order, so the durable copy exists before the
    /// notification that might be dropped. A scan continues with whatever
    /// strategies remain, so this narrows a result rather than ending it.
    pub(crate) fn record_failure(&self, scanner: ScannerKind, reason: String) {
        error!("Scanner {scanner:?} failed: {reason}");
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
    pub(crate) fn record_probe_stats(&self, stats: ProbeStats) {
        self.probe_stats.push(stats);
    }

    /// Takes the probe counters recorded so far, leaving the log empty.
    pub(crate) fn take_probe_stats(&self) -> Vec<ProbeStats> {
        self.probe_stats.drain()
    }

    /// The probe counters filed so far, left in place.
    ///
    /// Not part of the supported API. A test that drives one scanner directly
    /// over a synthetic transport never reaches the phase that would drain
    /// these into a report, and this is how it reads what the scanner filed.
    /// Enable `test-support` for tests only, never for a release.
    #[cfg(feature = "test-support")]
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

    /// Upserts the host at `ip`, applies `update`, and unconditionally announces
    /// the change. The convenience form of [`write_host`](Self::write_host) for
    /// the paths that always record a finding worth emitting - a port state, a
    /// merged host. Returns `true` if this call created the host.
    pub fn update_host(&self, ip: IpAddr, update: impl FnOnce(&mut Host)) -> bool {
        self.write_host(ip, |host| {
            update(host);
            true
        })
    }
}

impl ScanSession {
    /// Opens a session and the context the strategies behind it write into.
    ///
    /// The engine's own entry points call this; a consumer normally receives the
    /// session already built, from [`discover`](crate::scanner::discover) or
    /// [`scan`](crate::scanner::scan). It is public because driving a single
    /// scanner directly — which is what the `test-support` feature is for —
    /// means supplying it a context.
    pub fn new() -> (Self, ScanContext) {
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
        };

        (session, ctx)
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
}
