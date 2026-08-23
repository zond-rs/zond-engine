// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Target Dispatch
//!
//! Turns a [`TargetMap`] into a shuffled stream of individual
//! [`PlannedTarget`]s for the scanning strategies to consume. Rather than expand the whole address space into
//! memory and shuffle it in one pass, it fills a fixed-size batch, shuffles that,
//! and streams it out before moving on. Neighbouring addresses end up spread apart
//! in time, which avoids hammering one subnet in a tight burst, and the memory cost
//! stays bounded regardless of how large the target range is.

use std::net::IpAddr;

use crate::journal::cursor::Checkpoint;
use crate::model::ip::set::IpSet;
use crate::model::target::{PlannedTarget, TargetMap};
use crate::scanner::handle::ScanHandle;
use rand::seq::SliceRandom;
use tokio::sync::mpsc;

/// Streams an address set out in shuffled batches.
///
/// The sweep counterpart of [`Dispatcher`], and it yields bare addresses rather
/// than [`PlannedTarget`]s because a sweep is counted in addresses and numbers
/// them elsewhere: a [`HostScanner`](crate::scanner::strategy::HostScanner) owns
/// its targets, so its positions come from its context rather than off this
/// stream. See
/// [`ScanContext::settle_address`](crate::scanner::session::ScanContext::settle_address).
///
/// The shuffling is the same bargain the dispatcher makes — a fixed batch is
/// filled, shuffled and streamed before the next is drawn, so neighbouring
/// addresses end up spread apart in time and the memory cost stays bounded
/// however large the set.
pub fn shuffled_addresses(
    ips: IpSet,
    batch_size: usize,
    scan_handle: &ScanHandle,
) -> mpsc::Receiver<IpAddr> {
    let (tx, rx) = mpsc::channel(batch_size * 2);
    let scan_handle = scan_handle.clone();

    tokio::spawn(async move {
        let mut batch = Vec::with_capacity(batch_size);

        for ip in ips.iter() {
            batch.push(ip);
            if batch.len() < batch_size {
                continue;
            }
            if !drain(&mut batch, &tx, &scan_handle).await {
                return;
            }
        }

        drain(&mut batch, &tx, &scan_handle).await;
    });

    rx
}

/// Shuffles `batch` and sends it, reporting whether the receiver is still there
/// and the scan still wanted.
async fn drain(
    batch: &mut Vec<IpAddr>,
    tx: &mpsc::Sender<IpAddr>,
    scan_handle: &ScanHandle,
) -> bool {
    batch.shuffle(&mut rand::rng());
    for ip in batch.drain(..) {
        if tx.send(ip).await.is_err() || scan_handle.should_stop() {
            return false;
        }
    }
    true
}

/// Streams the targets of a [`TargetMap`] out in shuffled batches, each
/// numbered by its position in the plan.
pub struct Dispatcher {
    target_map: TargetMap,
    batch_size: usize,
    /// What an earlier sitting already settled, for a resumed scan.
    ///
    /// Skipped *after* numbering, never before: a resumed sitting scans a
    /// subset, and renumbering it would give position 0 to whatever happens to
    /// be left. The two sittings would then be counting different things.
    settled: Checkpoint,
}

impl Dispatcher {
    /// Creates a dispatcher over `target_map` with a default batch size of 8192.
    pub fn new(target_map: TargetMap) -> Self {
        Self {
            target_map,
            batch_size: 8192,
            settled: Checkpoint::default(),
        }
    }

    /// Skips what `settled` accounts for, for a scan continuing an earlier one.
    ///
    /// The checkpoint must have been written against this exact plan; see
    /// [`Manifest::covers`](crate::journal::manifest::Manifest::covers), which
    /// is what refuses one that was not.
    pub fn resuming(mut self, settled: Checkpoint) -> Self {
        self.settled = settled;
        self
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
    pub fn run_shuffled(self, scan_handle: &ScanHandle) -> mpsc::Receiver<PlannedTarget> {
        let (tx, rx) = mpsc::channel(self.batch_size * 2);
        let scan_handle = scan_handle.clone();

        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(self.batch_size);

            // Numbered here, where the plan is walked in order, so nothing
            // downstream has to re-derive a position. Shuffling below permutes
            // the order targets are *asked* in and never the numbering.
            for planned in self.settled.remaining(self.target_map.iter()) {
                batch.push(planned);

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
    use crate::model::target::Target;
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
        let is_ordered = received.windows(2).all(|w| match (w[0].ip(), w[1].ip()) {
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
        let key = |t: &Target| (t.ip.to_string(), t.port, t.protocol);
        let mut received_sorted: Vec<Target> =
            received.iter().map(|planned| planned.target).collect();
        let mut expected_sorted = expected.clone();
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
