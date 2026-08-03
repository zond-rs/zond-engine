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
    /// Inserts or updates the host at `ip`, applies `update`, and announces the
    /// change on the event stream. Returns `true` if the host was newly created.
    ///
    /// This is the single choke point every simple scanning path funnels host
    /// findings through, so the "upsert into the shared store, then emit
    /// [`ScanEvent::HostUpdated`]" sequence - and the rule that the store guard
    /// is released before the event is sent - lives here rather than being
    /// re-spelled at each call site.
    ///
    /// Strategies whose emit is conditional or interleaved with other per-reply
    /// bookkeeping (the local and routed discovery scanners) drive the store
    /// directly instead; this serves the paths that unconditionally record a
    /// finding and notify.
    pub fn update_host(&self, ip: IpAddr, update: impl FnOnce(&mut Host)) -> bool {
        let mut is_new = false;
        let mut host = self.store.entry(ip).or_insert_with(|| {
            is_new = true;
            Host::new(ip)
        });
        update(&mut host);
        drop(host);
        let _ = self.events_tx.send(ScanEvent::HostUpdated(ip));
        is_new
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
