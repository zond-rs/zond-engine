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

use crate::model::target::{Target, TargetMap};
use crate::scanner::handle::ScanHandle;
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

            // `TargetMap::iter` rather than the same two loops written out here.
            // The journal numbers targets by that enumeration and skips the
            // settled ones on a resume, so the walk that decides what is probed
            // and the walk that decides what was probed have to be one walk. Two
            // copies would not fail when they drifted — they would resume a scan
            // against positions meaning something else, which looks exactly like
            // a resume that worked. See `journal::cursor`.
            for target in self.target_map.iter() {
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
    use crate::model::ip::set::IpSet;
    use crate::model::port::PortSet;
    use crate::model::target::TargetSet;
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

    /// The dispatcher emits exactly the plan's own enumeration, as a set.
    ///
    /// The journal numbers targets by [`TargetMap::iter`] and a resume skips
    /// positions in that numbering, so a dispatcher that emitted a different
    /// collection — an extra target, a missed unit, a different pairing — would
    /// make every position mean something else. That does not fail loudly. It
    /// resumes a scan that skips the wrong targets and reports success, so it is
    /// asserted here rather than left to the two walks being the same by
    /// inspection.
    #[tokio::test]
    async fn the_dispatcher_emits_exactly_the_plans_enumeration() {
        let mut target_map = TargetMap::new();
        target_map.units.push(TargetSet::new(
            "192.168.1.1-192.168.1.10".parse().unwrap(),
            "80,443".parse().unwrap(),
        ));
        target_map.units.push(TargetSet::new(
            "10.0.0.1-10.0.0.3".parse().unwrap(),
            "22".parse().unwrap(),
        ));

        let expected: Vec<Target> = target_map.iter().collect();

        let handle = ScanHandle::new();
        let mut rx = Dispatcher::new(target_map.clone())
            .with_batch_size(4)
            .run_shuffled(&handle);

        let mut received = Vec::new();
        while let Some(target) = rx.recv().await {
            received.push(target);
        }

        // Sorted, because the dispatcher shuffles what it emits and not what it
        // numbers: the order targets are *asked* in is deliberately scrambled,
        // the order they are *numbered* in is not.
        let mut received_sorted = received.clone();
        let mut expected_sorted = expected.clone();
        let key = |t: &Target| (t.ip.to_string(), t.port, t.protocol);
        received_sorted.sort_by_key(key);
        expected_sorted.sort_by_key(key);

        assert_eq!(
            received_sorted, expected_sorted,
            "the dispatcher and the journal must walk one enumeration"
        );
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
