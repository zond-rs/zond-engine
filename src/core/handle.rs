use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum ScanEvent {
    NewIp(IpAddr),
    NewHostname(String),
    PortOpen { ip: IpAddr, port: u16 },
}

#[derive(Debug, Clone)]
pub struct ScanHandle {
    abort: Arc<AtomicBool>,
    events: mpsc::UnboundedSender<ScanEvent>,
}

impl ScanHandle {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<ScanEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let abort = Arc::new(AtomicBool::new(false));
        let self_handle = Self { abort, events: tx };
        (self_handle, rx)
    }

    pub fn emit(&self, event: ScanEvent) {
        let _ = self.events.send(event);
    }

    pub fn abort(&self) {
        self.abort.store(true, Ordering::SeqCst);
    }

    pub fn should_stop(&self) -> bool {
        self.abort.load(Ordering::SeqCst)
    }
}
