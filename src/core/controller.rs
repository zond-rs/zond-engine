use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone)]
pub struct InputHandle {
    abort: Arc<AtomicBool>,
}

impl InputHandle {
    pub fn new() -> Self {
        Self {
            abort: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn abort(&self) {
        self.abort.store(true, Ordering::SeqCst);
    }

    pub fn should_stop(&self) -> bool {
        self.abort.load(Ordering::SeqCst)
    }
}