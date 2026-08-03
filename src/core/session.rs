use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::core::handle::ScanHandle;
use crate::core::models::host::Host;

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

/// The shared, cloneable handles that every scanning strategy needs: somewhere to
/// write discovered hosts, somewhere to announce updates, and a way to check for abort.
///
/// Bundling these avoids passing (and cloning) the same three arguments individually
/// at every scanner construction site.
#[derive(Clone)]
pub struct ScanContext {
    pub handle: ScanHandle,
    pub store: Arc<DashMap<IpAddr, Host>>,
    pub events_tx: mpsc::UnboundedSender<ScanEvent>,
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
        };

        (session, ctx)
    }
}
