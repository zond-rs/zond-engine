use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::core::handle::ScanHandle;
use crate::core::models::host::Host;

/// Lightweight notifications for the status of an ongoing scan.
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// Indicates that new data is available for a host.
    /// The consumer should read from `ScanSession::store` to get the latest state.
    HostUpdated(IpAddr),
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
