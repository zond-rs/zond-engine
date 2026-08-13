// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Target Dispatch
//!
//! Turns a [`TargetMap`] into a shuffled stream of individual [`Target`]s for the
//! scanning strategies to consume. Rather than expand the whole address space into
//! memory and shuffle it in one pass, it fills a fixed-size batch, shuffles that,
//! and streams it out before moving on. Neighbouring addresses end up spread apart
//! in time, which avoids hammering one subnet in a tight burst, and the memory cost
//! stays bounded regardless of how large the target range is.

use crate::core::handle::ScanHandle;
use crate::core::models::target::{Target, TargetMap};
use rand::seq::SliceRandom;
use tokio::sync::mpsc;

/// Streams the targets of a [`TargetMap`] out in shuffled batches.
pub struct Dispatcher {
    target_map: TargetMap,
    batch_size: usize,
}

impl Dispatcher {
    /// Creates a dispatcher over `target_map` with a default batch size of 8192.
    pub fn new(target_map: TargetMap) -> Self {
        Self {
            target_map,
            batch_size: 8192,
        }
    }

    /// Overrides the batch size. A larger batch shuffles addresses over a wider
    /// window, at the cost of holding more of them in memory at once.
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// Spawns a background task that streams shuffled batches of targets and
    /// returns the [`mpsc::Receiver`] they arrive on.
    ///
    /// The channel holds up to twice the batch size, so the producer can prepare
    /// the next batch while the current one is still being consumed without letting
    /// the buffer grow without bound. The task stops early if the receiver is
    /// dropped or `scan_handle` signals a stop.
    pub fn run_shuffled(self, scan_handle: &ScanHandle) -> mpsc::Receiver<Target> {
        let (tx, rx) = mpsc::channel(self.batch_size * 2);
        let scan_handle = scan_handle.clone();

        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(self.batch_size);

            for unit in self.target_map.units {
                for target in unit.iter() {
                    batch.push(target);

                    if batch.len() >= self.batch_size {
                        batch.shuffle(&mut rand::rng());
                        for t in batch.drain(..) {
                            if tx.send(t).await.is_err() || scan_handle.should_stop() {
                                return;
                            }
                        }
                    }
                }
            }

            // Flush any remaining targets
            if !batch.is_empty() {
                batch.shuffle(&mut rand::rng());
                for t in batch {
                    if tx.send(t).await.is_err() || scan_handle.should_stop() {
                        return;
                    }
                }
            }
        });

        rx
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
    use crate::core::models::ip::set::IpSet;
    use crate::core::models::port::PortSet;
    use crate::core::models::target::TargetSet;
    use std::net::IpAddr;

    #[tokio::test]
    async fn dispatcher_emits_all_targets_shuffled() {
        let mut target_map = TargetMap::new();
        let ip_set: IpSet = "192.168.1.1-192.168.1.10".parse().unwrap();
        let port_set: PortSet = "80".parse().unwrap();
        let unit = TargetSet::new(ip_set, port_set);
        target_map.units.push(unit);

        let handle = ScanHandle::new();
        let dispatcher = Dispatcher::new(target_map).with_batch_size(4);
        let mut rx = dispatcher.run_shuffled(&handle);

        let mut received = Vec::new();
        while let Some(target) = rx.recv().await {
            received.push(target);
        }

        assert_eq!(received.len(), 10);
        let is_ordered = received.windows(2).all(|w| match (w[0].ip, w[1].ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => a.octets()[3] < b.octets()[3],
            _ => false,
        });
        assert!(!is_ordered, "Targets were not shuffled");
    }

    #[tokio::test]
    async fn dispatcher_stops_early_on_abort() {
        let mut target_map = TargetMap::new();
        let ip_set: IpSet = "192.168.1.1-192.168.1.100".parse().unwrap();
        let port_set: PortSet = "80".parse().unwrap();
        let unit = TargetSet::new(ip_set, port_set);
        target_map.units.push(unit);

        let handle = ScanHandle::new();
        let dispatcher = Dispatcher::new(target_map).with_batch_size(10);
        let mut rx = dispatcher.run_shuffled(&handle);

        let mut count = 0;
        while let Some(_target) = rx.recv().await {
            count += 1;
            if count == 15 {
                handle.abort();
            }
        }

        assert!((15..100).contains(&count));
    }
}
