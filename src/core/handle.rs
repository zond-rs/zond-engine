// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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
