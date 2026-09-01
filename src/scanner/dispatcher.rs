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
//! [`PlannedTarget`]s for the scanning strategies to consume. Rather than
//! expand the whole address space into memory and shuffle it in one pass, it
//! fills a fixed-size batch, shuffles that, and streams it out before moving on.
//! Neighbouring addresses end up spread apart in time, which avoids hammering
//! one subnet in a tight burst, and the memory cost stays bounded regardless of
//! how large the target range is.
//!
//! ## The batch size
//!
//! Both entry points here take one, and both hold it to at least one probe. A
//! batch of zero is a caller error rather than an instruction to send nothing:
//! it reaches `mpsc::channel`, which asserts on an empty buffer, so honouring
//! the number would end the scan in a panic rather than in an empty result. The
//! same reading `rate_or` gives a configured rate of zero.

use std::net::IpAddr;

use crate::journal::cursor::Checkpoint;
use crate::journal::settle::Outcome;
use crate::model::ip::set::IpSet;
use crate::model::target::{PlannedTarget, TargetMap};
use crate::scanner::handle::ScanHandle;
use crate::scanner::session::ScanContext;
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
/// The shuffling is the same bargain the dispatcher makes: a fixed batch is
/// filled, shuffled and streamed before the next is drawn, so neighbouring
/// addresses end up spread apart in time and the memory cost stays bounded
/// however large the set.
///
/// `batch_size` is held to at least one probe; see the module documentation.
pub fn shuffled_addresses(
    ips: IpSet,
    batch_size: usize,
    scan_handle: &ScanHandle,
) -> mpsc::Receiver<IpAddr> {
    let batch_size = batch_size.max(1);
    let (tx, rx) = mpsc::channel(batch_size.saturating_mul(2));
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
///
/// Generic over what the batch carries because both streams here draw the same
/// bargain and differ only in what they yield: a sweep is counted in addresses
/// and a port scan in numbered targets. The dispatcher used to spell this out
/// twice inline, once for a full batch and once for the flush, which is two
/// places for the stop check to be got wrong.
async fn drain<T>(batch: &mut Vec<T>, tx: &mpsc::Sender<T>, scan_handle: &ScanHandle) -> bool {
    batch.shuffle(&mut rand::rng());
    for item in batch.drain(..) {
        if tx.send(item).await.is_err() || scan_handle.should_stop() {
            return false;
        }
    }
    true
}

/// How many targets a [`Dispatcher`] shuffles together unless told otherwise.
///
/// Wide enough that neighbouring addresses of a `/24` land far apart in the
/// stream, and small enough that the buffer behind it is a few hundred kilobytes
/// rather than a function of the range.
pub const DEFAULT_BATCH: usize = 8192;

/// Streams the targets of a [`TargetMap`] out in shuffled batches, each
/// numbered by its position in the plan.
#[must_use]
pub struct Dispatcher {
    target_map: TargetMap,
    batch_size: usize,
    /// What an earlier sitting already settled, for a resumed scan.
    ///
    /// Skipped *after* numbering, never before: a resumed sitting scans a
    /// subset, and renumbering it would give position 0 to whatever happens to
    /// be left. The two sittings would then be counting different things.
    settled: Checkpoint,
    /// The addresses the liveness pass found something at, when one ran.
    ///
    /// Filtered here rather than by narrowing the plan, for the same reason
    /// `settled` is. Which hosts answer is a property of the network on the day,
    /// so a plan narrowed to them is a different plan every sitting, and a
    /// position counted in one of those means a different target in the next.
    live: Option<IpSet>,
}

impl Dispatcher {
    /// Creates a dispatcher over `target_map`, batched at [`DEFAULT_BATCH`].
    pub fn new(target_map: TargetMap) -> Self {
        Self {
            target_map,
            batch_size: DEFAULT_BATCH,
            settled: Checkpoint::default(),
            live: None,
        }
    }

    /// Skips what `settled` accounts for, for a scan continuing an earlier one.
    ///
    /// The checkpoint must have been written against this exact plan; see
    /// [`JournalManifest::covers`](crate::journal::manifest::JournalManifest::covers),
    /// which is what refuses one that was not.
    pub fn resuming(mut self, settled: Checkpoint) -> Self {
        self.settled = settled;
        self
    }

    /// Emits only the targets whose address is in `live`, settling the rest as
    /// [`Skipped`](crate::journal::settle::Outcome::Skipped).
    ///
    /// For the port phase of a scan that established which hosts are there
    /// first. A target whose host answered nothing is not one the scan failed
    /// to ask about: the scan asked whether the host was there, heard nothing,
    /// and declined to spend a probe on each of its ports. That decision is
    /// evidence, and a resume that had to re-derive it would ask the network a
    /// question it already answered.
    ///
    /// Without this the plan would have to be narrowed to the live hosts before
    /// numbering, which is what made a position mean something different in
    /// every sitting.
    pub fn only_live(mut self, live: IpSet) -> Self {
        self.live = Some(live);
        self
    }

    /// Overrides the batch size. A larger batch shuffles addresses over a wider
    /// window, at the cost of holding more of them in memory at once.
    ///
    /// Held to at least one probe; see the module documentation.
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
    pub fn run_shuffled(self, ctx: &ScanContext) -> mpsc::Receiver<PlannedTarget> {
        let batch_size = self.batch_size.max(1);
        let (tx, rx) = mpsc::channel(batch_size.saturating_mul(2));
        let scan_handle = ctx.handle.clone();
        let ctx = ctx.clone();

        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(batch_size);

            // Numbered here, where the plan is walked in order, so nothing
            // downstream has to re-derive a position. Shuffling below permutes
            // the order targets are *asked* in and never the numbering.
            for planned in self.settled.remaining(self.target_map.iter()) {
                // Settled where it stands rather than emitted: the position is
                // known here and nowhere downstream, and a target dropped
                // without one would stall the watermark on it for the rest of
                // the job.
                if let Some(live) = &self.live
                    && !live.contains(&planned.target.ip)
                {
                    ctx.record_outcome(Outcome::Skipped {
                        position: planned.position,
                    });
                    continue;
                }

                batch.push(planned);

                if batch.len() >= batch_size && !drain(&mut batch, &tx, &scan_handle).await {
                    return;
                }
            }

            drain(&mut batch, &tx, &scan_handle).await;
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

    /// A batch of zero reached `mpsc::channel`, which asserts on an empty
    /// buffer, so the mistake ended the scan in a panic rather than in an empty
    /// result. Both entry points take the size from the caller.
    #[tokio::test]
    async fn a_zero_batch_is_read_as_one_probe_rather_than_panicking() {
        use crate::scanner::session::ScanSession;

        let (_session, ctx) = ScanSession::new();
        let mut rx = Dispatcher::new(TargetMap::new())
            .with_batch_size(0)
            .run_shuffled(&ctx);

        assert!(rx.recv().await.is_none(), "an empty plan yields nothing");
    }

    /// The sweep stream takes its size the same way and holds it the same way.
    #[tokio::test]
    async fn the_address_stream_holds_a_zero_batch_to_one_too() {
        let handle = ScanHandle::new();
        let mut rx = shuffled_addresses(IpSet::new(), 0, &handle);

        assert!(rx.recv().await.is_none());
    }
    use super::*;
    use crate::model::ip::set::IpSet;
    use crate::model::port::PortSet;
    use crate::model::target::Target;
    use crate::model::target::TargetSet;
    use crate::scanner::session::ScanSession;
    use std::net::IpAddr;

    /// A context to dispatch against, and the session that keeps it alive.
    fn context() -> (ScanSession, ScanContext) {
        ScanSession::new()
    }

    #[tokio::test]
    async fn dispatcher_emits_all_targets_shuffled() {
        let mut target_map = TargetMap::new();
        let ip_set: IpSet = "192.168.1.1-192.168.1.10".parse().unwrap();
        let port_set: PortSet = "80".parse().unwrap();
        let unit = TargetSet::new(ip_set, port_set);
        target_map.units.push(unit);

        let (_session, ctx) = context();
        let dispatcher = Dispatcher::new(target_map).with_batch_size(4);
        let mut rx = dispatcher.run_shuffled(&ctx);

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
    /// collection, an extra target, a missed unit, a different pairing, would
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

        let (_session, ctx) = context();
        let mut rx = Dispatcher::new(target_map.clone())
            .with_batch_size(4)
            .run_shuffled(&ctx);

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

        let (_session, ctx) = context();
        let dispatcher = Dispatcher::new(target_map).with_batch_size(10);
        let mut rx = dispatcher.run_shuffled(&ctx);

        let mut count = 0;
        while let Some(_target) = rx.recv().await {
            count += 1;
            if count == 15 {
                ctx.handle.abort();
            }
        }

        assert!((15..100).contains(&count));
    }

    /// The property the liveness filter exists to keep.
    ///
    /// Which hosts answer is a fact about the network on the day, so a plan
    /// narrowed to them is a different plan every sitting. Numbering has to
    /// survive that: an address must hold the same position whether its
    /// neighbour answered or not, or a checkpoint written in one sitting names
    /// different targets in the next and the resume skips something nothing
    /// probed.
    #[tokio::test]
    async fn liveness_never_moves_a_position() {
        let plan = || {
            let mut map = TargetMap::new();
            map.add_unit(TargetSet::new(
                "192.0.2.1-192.0.2.4".parse::<IpSet>().expect("a range"),
                "80".parse::<PortSet>().expect("ports"),
            ));
            map
        };

        // Two sittings of one job, disagreeing about which hosts are there.
        let one = numbered(plan(), Some("192.0.2.4".parse().expect("a range"))).await;
        let two = numbered(
            plan(),
            Some("192.0.2.2-192.0.2.4".parse().expect("a range")),
        )
        .await;
        let all = numbered(plan(), None).await;

        for emitted in [&one, &two] {
            for (ip, position) in emitted {
                assert_eq!(
                    all.get(ip),
                    Some(position),
                    "{ip} moved when the liveness answer changed"
                );
            }
        }

        assert_eq!(one.len(), 1, "one host answered");
        assert_eq!(two.len(), 3);
    }

    /// A target whose host answered nothing is settled where it stands. Dropped
    /// without a position it would stall the watermark on itself for the rest of
    /// the job, and a scan of a range where most addresses are empty would stop
    /// being resumable past the out-of-order window.
    #[tokio::test]
    async fn a_target_whose_host_is_down_settles_rather_than_vanishing() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "192.0.2.1-192.0.2.4".parse::<IpSet>().expect("a range"),
            "80".parse::<PortSet>().expect("ports"),
        ));

        let (_session, ctx) = context();
        let mut rx = Dispatcher::new(map)
            .only_live("192.0.2.4".parse::<IpSet>().expect("a range"))
            .run_shuffled(&ctx);

        let mut emitted = 0;
        while rx.recv().await.is_some() {
            emitted += 1;
        }

        assert_eq!(emitted, 1, "only the live host is probed");
        assert_eq!(
            ctx.settlements().count(Outcome::Skipped { position: 0 }),
            3,
            "the three that were not probed have to be accounted for"
        );
        assert_eq!(
            ctx.settlements().checkpoint().watermark,
            3,
            "and their positions are the ones below the live host"
        );
    }

    /// Every target the dispatcher emitted, by address, with the position it
    /// carried. `live` narrows what is emitted and must never renumber it.
    async fn numbered(
        map: TargetMap,
        live: Option<IpSet>,
    ) -> std::collections::HashMap<IpAddr, u64> {
        let (_session, ctx) = context();
        let mut dispatcher = Dispatcher::new(map);
        if let Some(live) = live {
            dispatcher = dispatcher.only_live(live);
        }

        let mut rx = dispatcher.run_shuffled(&ctx);
        let mut found = std::collections::HashMap::new();
        while let Some(planned) = rx.recv().await {
            found.insert(planned.target.ip, planned.position);
        }
        found
    }
}
