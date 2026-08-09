use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::error;

use crate::core::handle::ScanHandle;
use crate::core::models::host::Host;
use crate::core::report::ScannerFailure;

/// Which scanning strategy a [`ScanEvent::ScannerFailed`] refers to.
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
    /// Unprivileged TCP connect fallback.
    Connect,
    /// Privileged raw UDP port scanning.
    UdpPort,
    /// Composite scanner that delegates to protocol-specific scanners.
    Composite,
}

/// Lightweight notifications for the status of an ongoing scan.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ScanEvent {
    /// Indicates that new data is available for a host.
    /// The consumer should read from `ScanSession::store` to get the latest state.
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

/// A handle to an active network scan.
pub struct ScanSession {
    /// Thread-safe, lock-free store of all hosts discovered so far.
    pub store: Arc<DashMap<IpAddr, Host>>,

    /// Receiver for lightweight update events.
    /// UI/Web interfaces can loop over this to react to changes in real-time.
    pub events: mpsc::UnboundedReceiver<ScanEvent>,

    /// Handle to control the active scan (e.g., to abort it).
    pub handle: ScanHandle,
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
#[derive(Clone)]
pub struct ScanContext {
    pub handle: ScanHandle,
    pub store: Arc<DashMap<IpAddr, Host>>,
    pub events_tx: mpsc::UnboundedSender<ScanEvent>,
    pub(crate) failures: Arc<FailureLog>,
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
    pub fn new() -> (Self, ScanContext) {
        let store = Arc::new(DashMap::new());
        let handle = ScanHandle::new();
        let (events_tx, rx) = mpsc::unbounded_channel();

        let session = Self {
            store: store.clone(),
            events: rx,
            handle: handle.clone(),
        };

        let ctx = ScanContext {
            handle,
            store,
            events_tx,
            failures: Arc::new(FailureLog::default()),
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

        match session.events.try_recv() {
            Ok(ScanEvent::ScannerFailed { scanner, reason }) => {
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
