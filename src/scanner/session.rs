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

impl ScanSession {
    pub fn new() -> (Self, ScanHandle, mpsc::UnboundedSender<ScanEvent>) {
        let store = Arc::new(DashMap::new());
        let handle = ScanHandle::new();
        let (tx, rx) = mpsc::unbounded_channel();

        let session = Self {
            store,
            events: rx,
            handle: handle.clone(),
        };

        (session, handle, tx)
    }
}
