use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone)]
pub struct ScanHandle {
    abort: Arc<AtomicBool>,
}

impl Default for ScanHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanHandle {
    pub fn new() -> Self {
        let abort = Arc::new(AtomicBool::new(false));
        Self { abort }
    }

    pub fn abort(&self) {
        self.abort.store(true, Ordering::SeqCst);
    }

    pub fn should_stop(&self) -> bool {
        self.abort.load(Ordering::SeqCst)
    }
}
