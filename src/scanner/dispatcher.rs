// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Target Dispatch
//!
//! Turns a [`TargetMap`] into a stream of individual [`PlannedTarget`]s for the
//! scanning strategies, in a scrambled order.
//!
//! ## Order
//!
//! A scan given a seed walks a [`Permutation`] of the plan's whole index space,
//! so consecutive questions land in unrelated parts of the network. The plan is
//! addressed by position through [`TargetIndex`], so this costs a few words
//! whatever the range.
//!
//! Without a seed it falls back to a batch-local shuffle: fill a fixed-size batch
//! in plan order, shuffle it, and stream it out. That bounds memory but spreads
//! addresses only within a batch, so a `/16` is still walked in recognisable
//! address order at batch granularity. It exists for plans a permutation cannot
//! address.
//!
//! The batch also sizes the channel, so it stays either way, but only the
//! fallback shuffles it. Reshuffling a walk would produce answers out of the
//! order the journal [`cursor`](crate::journal::cursor) counts along, and they
//! would wait there until the walk caught up.
//!
//! Sweeps that hold their own targets (the ARP and neighbour sweep of a segment,
//! the SYN sweep through a gateway) arrange them in the same walk with
//! `WalkOrder`, so a seed names one order for every phase of a scan.
//!
//! ## Numbering
//!
//! Targets are numbered by their position in [`TargetMap::iter`], whatever order
//! they are emitted in. A journal records that number, a cursor advances over it
//! and a resumed sitting skips by it, so it must be the same in every sitting.
//! See [`cursor`](crate::journal::cursor).
//!
//! ## Batch size
//!
//! Both entry points hold the batch size to at least one. A batch of zero would
//! reach `mpsc::channel`, which panics on an empty buffer; `rate_within` reads a
//! rate of zero the same way.

use std::net::IpAddr;

use crate::journal::cursor::Checkpoint;
use crate::journal::settle::Outcome;
use crate::model::ip::set::{IpSet, Positions};
use crate::model::order::Permutation;
use crate::model::target::{PlannedTarget, TargetIndex, TargetMap};
use crate::scanner::handle::ScanHandle;
use crate::scanner::session::ScanContext;
use rand::seq::SliceRandom;
use tokio::sync::mpsc;

/// Streams an address set out in the order a scan asks about it.
///
/// The sweep counterpart of [`Dispatcher`]. It yields bare addresses because a
/// [`HostScanner`](crate::scanner::strategy::HostScanner) numbers its targets
/// through its context; see
/// [`ScanContext::settle_address`](crate::scanner::session::ScanContext::settle_address).
///
/// `seed` selects between the same two orders as the dispatcher; see the module
/// documentation.
///
/// The [`Positions`] over the given set only determine the order. A resumed sweep
/// is handed a subset, so these are not the positions a journal records.
///
/// Ranges too wide to number ([`Positions::unnumbered`]) are asked about last, in
/// order.
///
/// `batch_size` is held to at least one; see the module documentation.
pub fn dispatch_addresses(
    ips: IpSet,
    batch_size: usize,
    seed: Option<u64>,
    scan_handle: &ScanHandle,
) -> mpsc::Receiver<IpAddr> {
    dispatch_addresses_of(ips, batch_size, seed, None, scan_handle)
}

/// [`dispatch_addresses`], walking the order of the whole plan `plan` numbers,
/// for a sweep counted in addresses.
///
/// A resumed sweep is handed what it has left, and permuting only that would
/// give a different order from the first sitting's, leaving answers waiting in
/// the [`cursor`](crate::journal::cursor). So the plan's walk is taken and the
/// addresses not handed to this sitting are stepped over.
///
/// An empty numbering (a port scan's liveness pass) walks `ips` as
/// [`dispatch_addresses`] does.
pub(crate) fn dispatch_addresses_of(
    ips: IpSet,
    batch_size: usize,
    seed: Option<u64>,
    plan: Option<std::sync::Arc<Positions>>,
    scan_handle: &ScanHandle,
) -> mpsc::Receiver<IpAddr> {
    let batch_size = batch_size.max(1);
    let (tx, rx) = mpsc::channel(batch_size.saturating_mul(2));
    let scan_handle = scan_handle.clone();
    let plan = plan.filter(|plan| plan.total() > 0);

    tokio::spawn(async move {
        let mut batch = Vec::with_capacity(batch_size);

        // Built once, before the stream that borrows it.
        let numbered = seed.map(|seed| {
            let numbered = plan
                .clone()
                .unwrap_or_else(|| std::sync::Arc::new(Positions::of(&ips)));
            let order = Permutation::new(seed, numbered.total());
            (numbered, order)
        });

        // `None` for an address the walk passes over, so the loop below can
        // count it towards a yield: a resumed sweep of a wide plan can pass over
        // millions in a row. See `Passing`.
        let addresses: Box<dyn Iterator<Item = Option<IpAddr>> + Send + '_> = match &numbered {
            // Addresses the numbering cannot reach follow the numbered ones, so
            // each is emitted exactly once: for `ips`, its ranges too wide to
            // number; for the plan, every handed address no position names.
            Some((numbered, order)) => {
                let walked = order
                    .iter()
                    .map(|position| numbered.address_at(position).filter(|ip| ips.contains(ip)));
                if plan.is_some() {
                    Box::new(
                        walked.chain(
                            ips.iter()
                                .map(|ip| numbered.find(ip).is_none().then_some(ip)),
                        ),
                    )
                } else {
                    Box::new(
                        walked.chain(
                            numbered
                                .unnumbered()
                                .iter()
                                .flat_map(|range| range.iter())
                                .map(Some),
                        ),
                    )
                }
            }
            None => Box::new(ips.iter().map(Some)),
        };

        let mut passing = Passing::default();
        for ip in addresses {
            passing.passed().await;
            let Some(ip) = ip else {
                // Checked here too, or a stopped resume walks the rest of the
                // plan before noticing.
                if scan_handle.should_stop() {
                    return;
                }
                continue;
            };
            batch.push(ip);
            if batch.len() < batch_size {
                continue;
            }
            if !drain(&mut batch, &tx, &scan_handle, &mut 0, numbered.is_none()).await {
                return;
            }
        }

        drain(&mut batch, &tx, &scan_handle, &mut 0, numbered.is_none()).await;
    });

    rx
}

/// A seeded scan's walk order, for a sweep that holds its own first attempts:
/// addresses arranged by it leave in the order [`dispatch_addresses_of`] would
/// give them.
///
/// Each address's place is computed directly (its position in the plan, then
/// that position's index in the permutation), so arranging a sweep costs its own
/// size, not the plan's. A context numbering nothing has the set itself
/// numbered, as the stream does.
#[derive(Clone)]
pub(crate) struct WalkOrder {
    numbered: std::sync::Arc<Positions>,
    order: Permutation,
}

/// How many of the walk's positions a sweep may be drawn along per address it
/// owes, before it is cheaper to collect its addresses and sort them.
///
/// Drawing holds only a place in the walk; collecting holds twenty bytes per
/// address (a third of a gigabyte for an on-link `/8`) and sorts before the
/// first probe. Drawing costs one lookup per plan position, so sixteen keeps it
/// to a handful per probe; a sparser sweep is cheaper to collect.
const DRAWN_DENSITY: u128 = 16;

impl WalkOrder {
    /// The walk `ctx`'s seed names over `ips`, or `None` for a scan given no
    /// seed, which asks in the order its targets come.
    pub(crate) fn of(ips: &IpSet, ctx: &ScanContext) -> Option<Self> {
        let seed = ctx.order_seed?;
        let numbered = if ctx.positions.total() > 0 {
            std::sync::Arc::clone(&ctx.positions)
        } else {
            std::sync::Arc::new(Positions::of(ips))
        };
        let order = Permutation::new(seed, numbered.total());
        Some(Self { numbered, order })
    }

    /// Whether a sweep owing `count` addresses is drawn along this walk, or
    /// collected and sorted; see [`DRAWN_DENSITY`].
    pub(crate) fn draws(&self, count: u128) -> bool {
        count.saturating_mul(DRAWN_DENSITY) >= u128::from(self.numbered.total())
    }

    /// Every address the walk numbers, in its order, drawn one at a time.
    pub(crate) fn addresses(&self) -> impl Iterator<Item = IpAddr> + Send + 'static {
        let numbered = std::sync::Arc::clone(&self.numbered);
        self.order
            .iter()
            .filter_map(move |position| numbered.address_at(position))
    }

    /// Whether the walk numbers `address`, and so gives it a place in
    /// [`addresses`](Self::addresses).
    pub(crate) fn numbers(&self, address: IpAddr) -> bool {
        self.numbered.find(address).is_some()
    }

    /// Puts `addresses` in the order of this walk. An address no position
    /// names follows the rest, in the order it came, as it does on the stream.
    pub(crate) fn arrange<A: Copy + Into<IpAddr>>(&self, addresses: &mut [A]) {
        addresses.sort_by_cached_key(|address| {
            self.numbered
                .find((*address).into())
                .and_then(|position| self.order.index_of(position))
                .unwrap_or(u64::MAX)
        });
    }
}

/// Sends `batch`, shuffled first for the batch-local fallback, and returns
/// whether the receiver is still there and the scan still running.
///
/// Serves both streams (addresses and numbered targets), for full batches and
/// the final flush.
///
/// `sent` counts what reached the channel, so a port scan's walk knows what a
/// stop left of the batch.
async fn drain<T>(
    batch: &mut Vec<T>,
    tx: &mpsc::Sender<T>,
    scan_handle: &ScanHandle,
    sent: &mut u64,
    shuffle: bool,
) -> bool {
    if shuffle {
        batch.shuffle(&mut rand::rng());
    }
    for item in batch.drain(..) {
        if tx.send(item).await.is_err() {
            return false;
        }
        *sent += 1;
        if scan_handle.should_stop() {
            return false;
        }
    }
    true
}

/// How many targets a walk passes before it hands its worker back to the
/// runtime.
///
/// A walk awaits only on a send, and most targets it passes are never sent
/// (settled earlier, excluded, or at a silent host). A sparse `/16` behind a
/// thousand ports is sixty-five million such targets, enough to hold a worker
/// for tens of seconds and stall a single-threaded runtime, including whatever
/// would stop the scan.
const PASSES_PER_YIELD: u32 = 1024;

/// A walk's count of the targets it has passed since it last yielded.
#[derive(Default)]
struct Passing {
    since: u32,
}

impl Passing {
    /// Counts one target, yielding every [`PASSES_PER_YIELD`].
    ///
    /// The stop is read by the walk itself: on every target it passes over, so
    /// it does not settle targets after a stop, and after each send. A target
    /// the walk would emit is never withheld for a stop, since an empty stream
    /// would read to the consumer as a plan asked in full.
    async fn passed(&mut self) {
        self.since += 1;
        if self.since >= PASSES_PER_YIELD {
            self.since = 0;
            tokio::task::yield_now().await;
        }
    }
}

/// How many targets a [`Dispatcher`] holds in flight unless told otherwise.
///
/// Keeps the buffer to a few hundred kilobytes whatever the range, and wide
/// enough to keep the send path fed. Without a seed it is also the shuffle
/// window, wide enough to spread a `/24`.
pub const DEFAULT_BATCH: usize = 8192;

/// Streams the targets of a [`TargetMap`] out in shuffled batches, each
/// numbered by its position in the plan.
#[must_use]
pub struct Dispatcher {
    target_map: TargetMap,
    batch_size: usize,
    /// What an earlier sitting already settled, for a resumed scan.
    ///
    /// Skipped after numbering, so positions mean the same in every sitting.
    settled: Checkpoint,
    /// What the liveness pass found, when one ran.
    ///
    /// Filtered here and not by narrowing the plan, for the same reason as
    /// `settled`: which hosts answer changes between sittings.
    screen: Option<Screen>,
}

/// What a liveness pass established, in the two halves the port phase reads.
struct Screen {
    /// The addresses it found something at, which are probed.
    live: IpSet,
    /// The addresses it asked as many times as its policy allows and heard
    /// nothing from, whose targets are settled without a probe.
    ///
    /// Addresses in neither set got no verdict and are left for the next
    /// sitting.
    silent: IpSet,
}

impl Dispatcher {
    /// Creates a dispatcher over `target_map`, batched at [`DEFAULT_BATCH`].
    pub fn new(target_map: TargetMap) -> Self {
        Self {
            target_map,
            batch_size: DEFAULT_BATCH,
            settled: Checkpoint::default(),
            screen: None,
        }
    }

    /// Skips what `settled` accounts for, for a scan continuing an earlier one.
    ///
    /// The checkpoint must have been written against this exact plan; see
    /// [`JournalManifest::covers`](crate::journal::manifest::JournalManifest::covers).
    pub fn resuming(mut self, settled: Checkpoint) -> Self {
        self.settled = settled;
        self
    }

    /// Emits only the targets whose address is in `live`, settling those whose
    /// address is in `silent` as
    /// [`Skipped`](crate::journal::settle::Outcome::Skipped) and recording the
    /// rest as [`Undecided`](crate::journal::settle::Outcome::Undecided).
    ///
    /// For the port phase after a liveness pass. A silent host's ports are
    /// settled, since the pass asked and heard nothing, so a resume does not ask
    /// again. A host in neither set got no verdict, and its ports are left for a
    /// resume.
    pub fn screened(mut self, live: IpSet, silent: IpSet) -> Self {
        self.screen = Some(Screen { live, silent });
        self
    }

    /// Overrides the batch size. A larger batch shuffles over a wider window and
    /// holds more in memory. Held to at least one; see the module documentation.
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// Spawns a background task that streams the plan's targets, in the order
    /// the scan asks about them, and returns the [`mpsc::Receiver`] they arrive
    /// on.
    ///
    /// The order comes from
    /// [`SessionBuilder::ordering`](crate::scanner::session::SessionBuilder::ordering)
    /// through `ctx`; see the module documentation for what each of the two is.
    ///
    /// The channel holds up to twice the batch size, so the producer can prepare
    /// the next batch while the current one is consumed. The task stops early if
    /// the receiver is dropped or the scan stops, and counts on `ctx` the targets
    /// it neither emitted nor settled, recorded as
    /// [`unreached`](crate::report::ScanPhase::unreached).
    ///
    /// The task settles targets it skips as it walks, so a caller that
    /// checkpoints should drain the receiver before the last checkpoint;
    /// otherwise late settlements may miss it.
    pub fn run(self, ctx: &ScanContext) -> mpsc::Receiver<PlannedTarget> {
        self.spawn(ctx).0
    }

    /// [`run`](Self::run), handing back the task as well, for a caller that
    /// waits for every settlement the walk makes before it lets the scan end.
    pub(crate) fn spawn(
        self,
        ctx: &ScanContext,
    ) -> (mpsc::Receiver<PlannedTarget>, tokio::task::JoinHandle<()>) {
        let batch_size = self.batch_size.max(1);
        let (tx, rx) = mpsc::channel(batch_size.saturating_mul(2));
        let scan_handle = ctx.handle.clone();
        let order = self.order(ctx.order_seed);
        // Settlements count along this walk; set before the first target
        // leaves.
        if let Some((_, order)) = &order {
            ctx.settlements().walk_along(*order);
        }
        let ctx = ctx.clone();
        // Every target an earlier sitting did not settle. On an early stop, the
        // unreached count is this minus what was accounted for. A plan too large
        // to count has no total.
        let owed = match &order {
            Some((_, order)) => Some(order.len()),
            None => self
                .target_map
                .gross_targets()
                .ok()
                .and_then(|total| u64::try_from(total).ok()),
        }
        .map(|total| total.saturating_sub(self.settled.settled_count()));

        let walk = tokio::spawn(async move {
            let mut batch = Vec::with_capacity(batch_size);
            let mut accounted = 0u64;
            let stopped_short = |accounted: u64| {
                if let Some(owed) = owed {
                    ctx.record_unreached(owed.saturating_sub(accounted));
                }
            };

            // Numbered by plan position whatever the order.
            let stream: Box<dyn Iterator<Item = PlannedTarget> + Send> = match &order {
                // Resume from where an earlier sitting's walk of this order got
                // to; everything before it is settled.
                Some((index, order)) => Box::new(
                    order
                        .iter_from(self.walked_along(order))
                        .filter_map(|position| {
                            index
                                .target_at(position)
                                .map(|target| PlannedTarget::new(position, target))
                        }),
                ),
                None => Box::new(
                    self.target_map
                        .iter()
                        .enumerate()
                        .map(|(position, target)| PlannedTarget::new(position as u64, target)),
                ),
            };

            let mut passing = Passing::default();
            for planned in stream {
                passing.passed().await;
                // Checked on passed-over targets too: a resumed or screened walk
                // emits few targets and would otherwise walk the rest of the
                // plan before noticing. What it leaves is unsettled.
                let passes_over = self.settled.is_settled(planned.position)
                    || !ctx.may_ask(&planned.target)
                    || self
                        .screen
                        .as_ref()
                        .is_some_and(|screen| !screen.live.contains(&planned.target.ip));
                if passes_over && scan_handle.should_stop() {
                    return stopped_short(accounted);
                }

                // Settled by an earlier sitting; filtered after numbering.
                if self.settled.is_settled(planned.position) {
                    continue;
                }

                // Excluded beyond the plan's subtraction by address: tied to an
                // excluded machine (by the neighbour tables or an earlier reply),
                // or a port this sitting excludes. Settled, so a resume owes it
                // nothing, and before the screen, which never heard it.
                if !ctx.may_ask(&planned.target) {
                    ctx.record_outcome(Outcome::Withheld {
                        position: planned.position,
                    });
                    accounted += 1;
                    continue;
                }

                // Settled here, since the position is known only here; a target
                // dropped without it would stall the watermark for the rest of
                // the job.
                if let Some(screen) = &self.screen
                    && !screen.live.contains(&planned.target.ip)
                {
                    accounted += 1;
                    // Already settled if the pass filed the address unroutable.
                    if ctx.settlements().is_settled(planned.position) {
                        continue;
                    }
                    if screen.silent.contains(&planned.target.ip) {
                        ctx.record_outcome(Outcome::Skipped {
                            position: planned.position,
                        });
                    } else {
                        // Neither emitted nor settled: counted unreached so the
                        // phase's tally adds up to the plan.
                        ctx.record_outcome(Outcome::Undecided);
                        ctx.record_unreached(1);
                    }
                    continue;
                }

                batch.push(planned);

                if batch.len() >= batch_size
                    && !drain(
                        &mut batch,
                        &tx,
                        &scan_handle,
                        &mut accounted,
                        order.is_none(),
                    )
                    .await
                {
                    return stopped_short(accounted);
                }
            }

            if !drain(
                &mut batch,
                &tx,
                &scan_handle,
                &mut accounted,
                order.is_none(),
            )
            .await
            {
                stopped_short(accounted);
            }
        });

        (rx, walk)
    }

    /// How far an earlier sitting's walk along `order` got, or zero where it
    /// walked another or none.
    fn walked_along(&self, order: &Permutation) -> u64 {
        self.settled
            .walked
            .filter(|walked| walked.order() == *order)
            .map_or(0, |walked| walked.reached.min(order.len()))
    }

    /// The plan addressed by position, and the order to walk those positions in,
    /// for a scan that was given a seed and a plan that can be addressed.
    ///
    /// [`None`] where either is missing, which means the batch-shuffled walk. A
    /// plan [`TargetIndex`] cannot address whole also gets `None`, since a
    /// permutation of the part that fits would silently skip the rest.
    fn order(&self, seed: Option<u64>) -> Option<(TargetIndex, Permutation)> {
        let seed = seed?;
        let index = TargetIndex::of(&self.target_map);
        if !index.is_complete() {
            return None;
        }

        let order = Permutation::new(seed, index.total());
        Some((index, order))
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
    use crate::scanner::session::ScanSession;
    use std::net::IpAddr;

    /// A batch of zero would reach `mpsc::channel`, which panics on an empty
    /// buffer.
    #[tokio::test]
    async fn a_zero_batch_is_read_as_one_probe_rather_than_panicking() {
        let (_session, ctx) = ScanSession::new();
        let mut rx = Dispatcher::new(TargetMap::new())
            .with_batch_size(0)
            .run(&ctx);

        assert!(rx.recv().await.is_none(), "an empty plan yields nothing");
    }

    /// The sweep stream holds a zero batch to one too.
    #[tokio::test]
    async fn the_address_stream_holds_a_zero_batch_to_one_too() {
        let handle = ScanHandle::new();
        let mut rx = dispatch_addresses(IpSet::new(), 0, None, &handle);

        assert!(rx.recv().await.is_none());
    }

    /// A context to dispatch against, and the session that keeps it alive.
    fn context() -> (ScanSession, ScanContext) {
        ScanSession::new()
    }

    /// An unseeded dispatcher shuffles within each batch, and emits every
    /// target of the plan once.
    ///
    /// The plan is sized so the random shuffle cannot leave everything in order
    /// by chance: 1,000 targets in batches of 100 stay in plan order with
    /// probability (1/100!)^10.
    #[tokio::test]
    async fn dispatcher_emits_all_targets_shuffled() {
        let mut target_map = TargetMap::new();
        let ip_set: IpSet = "192.0.2.1-192.0.2.250".parse().unwrap();
        let port_set: PortSet = "80,443,8080,8443".parse().unwrap();
        target_map.units.push(TargetSet::new(ip_set, port_set));

        let (_session, ctx) = ScanSession::builder().ordering(None).build();
        let dispatcher = Dispatcher::new(target_map).with_batch_size(100);
        let mut rx = dispatcher.run(&ctx);

        let mut positions = Vec::new();
        while let Some(planned) = rx.recv().await {
            positions.push(planned.position);
        }

        assert_eq!(positions.len(), 1_000);
        assert!(
            positions.windows(2).any(|pair| pair[0] > pair[1]),
            "every target came out in plan order"
        );
        // Shuffled within a batch only: each run of 100 is the plan's batch.
        for (batch, chunk) in positions.chunks(100).enumerate() {
            let mut sorted = chunk.to_vec();
            sorted.sort_unstable();
            let first = batch as u64 * 100;
            assert_eq!(sorted, (first..first + 100).collect::<Vec<_>>());
        }
    }

    /// The dispatcher emits exactly the plan's own enumeration, as a set.
    ///
    /// The journal numbers targets by [`TargetMap::iter`] and a resume skips by
    /// that numbering, so any difference here would silently make a resume skip
    /// the wrong targets.
    #[tokio::test]
    async fn the_dispatcher_emits_exactly_the_plans_enumeration() {
        let mut target_map = TargetMap::new();
        target_map.units.push(TargetSet::new(
            "192.0.2.1-192.0.2.10".parse().unwrap(),
            "80,443".parse().unwrap(),
        ));
        target_map.units.push(TargetSet::new(
            "198.51.100.1-198.51.100.3".parse().unwrap(),
            "22".parse().unwrap(),
        ));

        let expected: Vec<Target> = target_map.iter().collect();

        let (_session, ctx) = context();
        let mut rx = Dispatcher::new(target_map.clone())
            .with_batch_size(4)
            .run(&ctx);

        let mut received = Vec::new();
        while let Some(target) = rx.recv().await {
            received.push(target);
        }

        // Sorted, because the emission order is scrambled.
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
        let ip_set: IpSet = "192.0.2.1-192.0.2.100".parse().unwrap();
        let port_set: PortSet = "80".parse().unwrap();
        let unit = TargetSet::new(ip_set, port_set);
        target_map.units.push(unit);

        let (_session, ctx) = context();
        let dispatcher = Dispatcher::new(target_map).with_batch_size(10);
        let mut rx = dispatcher.run(&ctx);

        let mut count = 0;
        while let Some(_target) = rx.recv().await {
            count += 1;
            if count == 15 {
                ctx.handle.abort();
            }
        }

        assert!((15..100).contains(&count));
    }

    /// An address holds the same position whichever hosts answered, or a
    /// checkpoint from one sitting would name different targets in the next.
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

    /// A target the neighbour tables tie to an excluded machine is never asked,
    /// though the plan only subtracts the excluded address. It is settled, and
    /// before the screen, which never heard it.
    #[tokio::test]
    async fn a_target_at_another_address_of_an_excluded_machine_is_not_emitted() {
        use crate::model::exclusion::Exclusions;
        use crate::model::mac::MacAddr;

        let machine = MacAddr::new(0x02, 0, 0, 0, 0, 0x30);
        let excluded: IpAddr = "192.0.2.30".parse().expect("literal");
        let other: IpAddr = "192.0.2.40".parse().expect("literal");
        let mut policy = IpSet::new();
        policy.insert(excluded);
        let (_session, ctx) = ScanSession::builder()
            .excluding(Exclusions::new(policy))
            .with_neighbours(vec![(excluded, Some(machine)), (other, Some(machine))])
            .build();

        let plan = || {
            let mut map = TargetMap::new();
            map.add_unit(TargetSet::new(
                "192.0.2.40-192.0.2.41".parse::<IpSet>().expect("a range"),
                "80".parse::<PortSet>().expect("ports"),
            ));
            map
        };
        let asked = |dispatcher: Dispatcher| {
            let mut rx = dispatcher.run(&ctx);
            async move {
                let mut emitted = Vec::new();
                while let Some(planned) = rx.recv().await {
                    emitted.push(planned.target.ip);
                }
                emitted
            }
        };
        let permitted: IpAddr = "192.0.2.41".parse().expect("literal");

        // Asked on trust, as a scan whose liveness pass did not run asks.
        assert_eq!(asked(Dispatcher::new(plan())).await, [permitted]);
        // And behind a liveness pass, which withheld it too.
        let live: IpSet = "192.0.2.41".parse().expect("a range");
        let screened = Dispatcher::new(plan()).screened(live, IpSet::new());
        assert_eq!(asked(screened).await, [permitted]);

        let settlements = ctx.settlements();
        assert_eq!(settlements.count(Outcome::Withheld { position: 0 }), 2);
        assert_eq!(settlements.count(Outcome::Undecided), 0);
    }

    /// A target the liveness pass left undecided is counted as never reached,
    /// so the tally adds up to the plan. An unroutable address's targets are
    /// already settled and not counted.
    #[tokio::test]
    async fn a_target_the_liveness_pass_left_undecided_is_counted_unreached() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "192.0.2.1-192.0.2.3".parse::<IpSet>().expect("a range"),
            "80,443".parse::<PortSet>().expect("ports"),
        ));
        let (_session, ctx) = context();
        // .1 answered, .2 no route leads to, .3 was never asked.
        ctx.number_targets(crate::model::target::TargetIndex::of(&map));
        ctx.record_unroutable("192.0.2.2".parse().expect("an address"));

        let mut rx = Dispatcher::new(map)
            .screened(
                "192.0.2.1".parse::<IpSet>().expect("an address"),
                IpSet::new(),
            )
            .run(&ctx);
        let mut emitted = 0;
        while rx.recv().await.is_some() {
            emitted += 1;
        }

        assert_eq!(emitted, 2);
        assert_eq!(ctx.take_unreached(), 2, "the undecided host's two ports");
        assert_eq!(ctx.settlements().count(Outcome::Undecided), 2);
    }

    /// A target whose host answered nothing is settled; dropped, it would stall
    /// the watermark for the rest of the job.
    #[tokio::test]
    async fn a_target_whose_host_is_down_settles_rather_than_vanishing() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "192.0.2.1-192.0.2.4".parse::<IpSet>().expect("a range"),
            "80".parse::<PortSet>().expect("ports"),
        ));

        let (_session, ctx) = context();
        let mut rx = Dispatcher::new(map)
            .screened(
                "192.0.2.4".parse::<IpSet>().expect("a range"),
                "192.0.2.1-192.0.2.3".parse::<IpSet>().expect("a range"),
            )
            .run(&ctx);

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

    /// Only silence the liveness pass heard settles a target. A host it reached
    /// no verdict on is left for the next sitting.
    #[tokio::test]
    async fn a_host_the_liveness_pass_reached_no_verdict_on_is_left_unsettled() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "192.0.2.1-192.0.2.4".parse::<IpSet>().expect("a range"),
            "80,443".parse::<PortSet>().expect("ports"),
        ));

        let (_session, ctx) = context();
        // .1 answered, .2 stayed silent, .3 and .4 were never asked.
        let mut rx = Dispatcher::new(map)
            .screened(
                "192.0.2.1".parse::<IpSet>().expect("an address"),
                "192.0.2.2".parse::<IpSet>().expect("an address"),
            )
            .run(&ctx);

        let mut emitted = Vec::new();
        while let Some(planned) = rx.recv().await {
            emitted.push(planned.target.ip);
        }

        let first: IpAddr = "192.0.2.1".parse().expect("an address");
        assert_eq!(emitted, vec![first, first], "only the live host is probed");
        let settlements = ctx.settlements();
        assert_eq!(
            settlements.count(Outcome::Skipped { position: 0 }),
            2,
            "the silent host's two ports are settled"
        );
        assert_eq!(
            settlements.count(Outcome::Undecided),
            4,
            "the two hosts never asked about keep their four ports unsettled"
        );
        assert_eq!(
            settlements.checkpoint().watermark,
            0,
            "the live host's ports were emitted rather than settled here"
        );
        assert_eq!(
            settlements.settled_count(),
            2,
            "and nothing but the silent host's ports is settled"
        );
    }

    /// A stopped walk notices between skipped targets, not only on a send.
    #[tokio::test]
    async fn a_stopped_scan_stops_walking_targets_it_would_skip() {
        let (session, ctx) = context();
        session.handle().abort();

        let mut rx = Dispatcher::new(wide(24))
            .screened(IpSet::new(), "192.0.2.0/24".parse().expect("a prefix"))
            .run(&ctx);
        while rx.recv().await.is_some() {}

        assert_eq!(
            ctx.settlements().count(Outcome::Skipped { position: 0 }),
            0,
            "a stopped scan walked on through targets nothing would probe"
        );
    }

    /// A walk passing over targets yields its worker. The stop comes from a task
    /// that can only run on this single-threaded runtime once the walk yields;
    /// a walk that never yielded would settle the whole plan first.
    #[tokio::test]
    async fn a_walk_passing_over_targets_lets_a_stop_in() {
        let (session, ctx) = context();
        let handle = session.handle().clone();
        let settled = ctx.clone();

        // A million targets at silent addresses: the walk settles each and
        // sends none.
        let silent: IpSet = "192.0.2.0/24".parse().expect("a prefix");
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            silent.clone(),
            "1-4096".parse::<PortSet>().expect("ports"),
        ));
        let (rx, walk) = Dispatcher::new(map)
            .screened(IpSet::new(), silent)
            .spawn(&ctx);

        // Asks for the stop once the walk has begun.
        let stopper = tokio::spawn(async move {
            while settled
                .settlements()
                .count(Outcome::Skipped { position: 0 })
                == 0
            {
                tokio::task::yield_now().await;
            }
            handle.abort();
        });

        walk.await.expect("the walk ends");
        stopper.await.expect("the stop was asked for");
        drop(rx);
        let skipped = ctx.settlements().count(Outcome::Skipped { position: 0 });
        assert!(
            skipped < 1 << 20,
            "the walk settled all {skipped} targets before anything else could run"
        );
    }

    /// Every settlement the walk makes is in once its task is awaited, even
    /// after the receiver was dropped early.
    #[tokio::test]
    async fn every_settlement_the_walk_makes_is_in_once_it_is_awaited() {
        let (_session, ctx) = context();
        let (rx, walk) = Dispatcher::new(wide(24))
            .screened(
                "192.0.2.255".parse::<IpSet>().expect("an address"),
                "192.0.2.0-192.0.2.254".parse::<IpSet>().expect("a range"),
            )
            .spawn(&ctx);
        drop(rx);

        walk.await.expect("the walk ends");
        assert_eq!(
            ctx.settlements().count(Outcome::Skipped { position: 0 }),
            255,
            "the walk passed every silent host's target before it ended"
        );
    }

    /// A context that asks its targets in the order `seed` names.
    fn ordered(seed: u64) -> (ScanSession, ScanContext) {
        ScanSession::builder().ordering(Some(seed)).build()
    }

    /// A plan of `count` consecutive addresses on one port.
    fn wide(count: u8) -> TargetMap {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            format!("192.0.2.0/{count}")
                .parse::<IpSet>()
                .expect("a prefix"),
            "80".parse::<PortSet>().expect("ports"),
        ));
        map
    }

    /// Everything the dispatcher emitted, in the order it arrived.
    async fn emitted(map: TargetMap, ctx: &ScanContext, batch: usize) -> Vec<PlannedTarget> {
        let mut rx = Dispatcher::new(map).with_batch_size(batch).run(ctx);
        let mut asked = Vec::new();
        while let Some(planned) = rx.recv().await {
            asked.push(planned);
        }
        asked
    }

    /// A seeded scan asks about every target exactly once.
    #[tokio::test]
    async fn a_seeded_scan_asks_about_every_target_exactly_once() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "192.0.2.0/26".parse::<IpSet>().expect("a prefix"),
            "80,443,u:53".parse::<PortSet>().expect("ports"),
        ));
        map.add_unit(TargetSet::new(
            "198.51.100.1-198.51.100.9"
                .parse::<IpSet>()
                .expect("a range"),
            "22".parse::<PortSet>().expect("ports"),
        ));

        let expected: Vec<Target> = map.iter().collect();
        let (_session, ctx) = ordered(0x5EED);
        let asked = emitted(map, &ctx, 32).await;

        assert_eq!(asked.len(), expected.len());

        let mut positions: Vec<u64> = asked.iter().map(|planned| planned.position).collect();
        positions.sort_unstable();
        assert!(
            positions.iter().copied().eq(0..expected.len() as u64),
            "a target was asked twice or not at all"
        );
    }

    /// A target's position is its place in the plan, not in the emission order;
    /// the journal depends on it.
    #[tokio::test]
    async fn a_seeded_scan_numbers_by_the_plan_and_not_by_the_order() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "192.0.2.0/28".parse::<IpSet>().expect("a prefix"),
            "80,443".parse::<PortSet>().expect("ports"),
        ));
        map.add_unit(TargetSet::new(
            "198.51.100.1-198.51.100.5"
                .parse::<IpSet>()
                .expect("a range"),
            "22,u:161".parse::<PortSet>().expect("ports"),
        ));

        let plan: std::collections::HashMap<Target, u64> = map
            .iter()
            .enumerate()
            .map(|(position, target)| (target, position as u64))
            .collect();

        let (_session, ctx) = ordered(0xC0FFEE);
        for planned in emitted(map, &ctx, 16).await {
            assert_eq!(
                plan.get(&planned.target),
                Some(&planned.position),
                "{:?} was numbered by when it was asked about",
                planned.target
            );
        }
    }

    /// The first batch out of a seeded scan is drawn from the whole plan, not
    /// from its lowest addresses as a batch-local shuffle's would be.
    #[tokio::test]
    async fn a_seeded_scan_does_not_walk_the_plan_a_batch_at_a_time() {
        const BATCH: usize = 64;

        let (_session, ctx) = ordered(0x5EED);
        let asked = emitted(wide(20), &ctx, BATCH).await;
        assert_eq!(asked.len(), 4_096);

        let beyond = asked[..BATCH]
            .iter()
            .filter(|planned| planned.position >= BATCH as u64)
            .count();

        assert!(
            beyond > BATCH / 2,
            "only {beyond} of the first {BATCH} targets came from beyond the \
             first batch of the plan, which is a walk rather than a rearrangement"
        );
    }

    /// A seeded scan asks in exactly the seed's order, whatever the batch, so a
    /// cursor counting along it never holds a position above its watermark.
    #[tokio::test]
    async fn a_seeded_scan_asks_in_the_seeds_order_and_its_cursor_stays_empty() {
        use crate::journal::cursor::Cursor;

        let (_session, ctx) = ordered(0x5EED);
        let asked = emitted(wide(20), &ctx, 64).await;

        let order = Permutation::new(0x5EED, 4_096);
        let positions: Vec<u64> = asked.iter().map(|planned| planned.position).collect();
        assert!(
            positions.iter().copied().eq(order.iter()),
            "not the seed's order"
        );

        let mut cursor = Cursor::walking(order);
        for position in positions {
            cursor.settle(position);
            assert_eq!(cursor.pending_count(), 0, "{position} waited in the set");
        }
    }

    /// A session built without a plan still counts its settlements along its
    /// dispatcher's walk; counted in plan order, nearly every answer would wait
    /// above the watermark.
    #[tokio::test]
    async fn a_session_told_no_plan_counts_along_the_walk_its_dispatcher_takes() {
        use crate::journal::settle::Outcome;

        let (_session, ctx) = ScanSession::builder().build();
        assert!(ctx.order_seed.is_some(), "a session left alone walks");

        let mut rx = Dispatcher::new(wide(20)).with_batch_size(64).run(&ctx);
        let mut most_waiting = 0;
        let mut asked = 0;
        while let Some(planned) = rx.recv().await {
            ctx.record_outcome(Outcome::Answered {
                position: planned.position,
            });
            asked += 1;
            most_waiting = most_waiting.max(ctx.settlements().checkpoint().settled_above.len());
        }

        assert_eq!(asked, 4_096);
        assert_eq!(ctx.settlements().settled_count(), 4_096);
        assert_eq!(most_waiting, 0, "answers waited above the watermark");
    }

    /// A resumed seeded sitting asks about exactly what is left.
    #[tokio::test]
    async fn a_resumed_seeded_scan_asks_only_what_is_left() {
        use crate::journal::cursor::Checkpoint;

        let settled = Checkpoint::new(1_000, [1_500, 2_000, 4_095]);
        let (_session, ctx) = ordered(0x1234);

        let mut rx = Dispatcher::new(wide(20))
            .resuming(settled.clone())
            .with_batch_size(64)
            .run(&ctx);

        let mut positions = Vec::new();
        while let Some(planned) = rx.recv().await {
            positions.push(planned.position);
        }
        positions.sort_unstable();

        let expected: Vec<u64> = (0..4_096).filter(|p| !settled.is_settled(*p)).collect();
        assert_eq!(positions, expected);
    }

    /// A sitting resumed from a checkpoint counted along its own walk picks the
    /// walk up where the earlier one left it, and asks exactly what is left.
    #[tokio::test]
    async fn a_resumed_walk_asks_exactly_what_the_earlier_one_left() {
        use crate::journal::cursor::Cursor;

        let order = Permutation::new(0x1234, 4_096);
        let mut earlier = Cursor::walking(order);
        for position in order.iter().take(2_500) {
            earlier.settle(position);
        }
        for index in [2_600, 3_000, 4_095] {
            earlier.settle(order.at(index).expect("inside the walk"));
        }
        let settled = earlier.checkpoint();
        assert!(settled.walked.is_some_and(|walked| walked.reached == 2_500));

        let (_session, ctx) = ordered(0x1234);
        let mut rx = Dispatcher::new(wide(20))
            .resuming(settled.clone())
            .with_batch_size(64)
            .run(&ctx);

        let mut positions = Vec::new();
        while let Some(planned) = rx.recv().await {
            positions.push(planned.position);
        }
        positions.sort_unstable();

        let expected: Vec<u64> = (0..4_096).filter(|p| !settled.is_settled(*p)).collect();
        assert_eq!(expected.len(), 4_096 - 2_503);
        assert_eq!(positions, expected);
    }

    /// Receives `take` of what `dispatcher` emits, stops the scan, and drains
    /// the rest, handing back how many it received and how many the walk says
    /// it never reached.
    async fn stopped_after(
        dispatcher: Dispatcher,
        session: &ScanSession,
        ctx: &ScanContext,
        take: usize,
    ) -> (u64, u64) {
        let (mut rx, walk) = dispatcher.spawn(ctx);
        let mut received = 0u64;
        while received < take as u64 && rx.recv().await.is_some() {
            received += 1;
        }
        session.handle().abort();
        while rx.recv().await.is_some() {
            received += 1;
        }
        walk.await.expect("the walk ends");
        (received, ctx.take_unreached())
    }

    /// A stopped walk counts what it never reached, so every target is emitted,
    /// settled or counted. In both orders.
    #[tokio::test]
    async fn a_stopped_walk_counts_the_targets_it_never_reached() {
        for seed in [Some(0x5EED), None] {
            let (session, ctx) = ScanSession::builder().ordering(seed).build();
            let dispatcher = Dispatcher::new(wide(20)).with_batch_size(64);

            let (received, unreached) = stopped_after(dispatcher, &session, &ctx, 1_000).await;

            assert!(unreached > 0, "{seed:?}: a stop a quarter in left nothing");
            assert_eq!(received + unreached, 4_096, "{seed:?}");
        }
    }

    /// A resumed, screened, stopped walk accounts for exactly what the earlier
    /// sitting left: emitted, settled for the screen, or unreached (undecided
    /// targets included).
    #[tokio::test]
    async fn a_stopped_resumed_walk_counts_only_what_it_owed() {
        use crate::journal::cursor::Cursor;

        let order = Permutation::new(0x1234, 4_096);
        let mut earlier = Cursor::walking(order);
        for position in order.iter().take(1_500) {
            earlier.settle(position);
        }
        let settled = earlier.checkpoint();

        let (session, ctx) = ordered(0x1234);
        // Half the addresses live, a quarter silent, the rest undecided.
        let live: IpSet = "192.0.0.0/21".parse().expect("a prefix");
        let silent: IpSet = "192.0.8.0/22".parse().expect("a prefix");
        let dispatcher = Dispatcher::new(wide(20))
            .resuming(settled)
            .screened(live, silent)
            .with_batch_size(64);

        let (received, unreached) = stopped_after(dispatcher, &session, &ctx, 300).await;

        let skipped = ctx.settlements().count(Outcome::Skipped { position: 0 });
        let undecided = ctx.settlements().count(Outcome::Undecided);
        assert!(unreached > undecided, "a stop part way left nothing");
        assert_eq!(received + skipped + unreached, 4_096 - 1_500);
    }

    /// A sweep of part of a plan walks the plan's order, so a resumed sweep asks
    /// its remainder in the first sitting's order.
    #[tokio::test]
    async fn a_sweep_of_part_of_a_plan_walks_the_plans_order() {
        let plan: IpSet = "192.0.2.0/24".parse().expect("a prefix");
        let numbering = std::sync::Arc::new(plan.positions());
        let handed: IpSet = "192.0.2.0/25,203.0.113.9".parse().expect("a set");

        let handle = ScanHandle::new();
        let mut rx = dispatch_addresses_of(
            handed.clone(),
            1,
            Some(0x5EED),
            Some(std::sync::Arc::clone(&numbering)),
            &handle,
        );
        let mut swept = Vec::new();
        while let Some(ip) = rx.recv().await {
            swept.push(ip);
        }

        let mut expected: Vec<IpAddr> = Permutation::new(0x5EED, numbering.total())
            .iter()
            .filter_map(|position| numbering.address_at(position))
            .filter(|ip| handed.contains(ip))
            .collect();
        // Handed but not in the plan: still asked, once, after the walk.
        expected.push("203.0.113.9".parse().expect("an address"));
        assert_eq!(swept, expected);
    }

    /// A plan whose addresses outrun the numbering is walked whole, in plan
    /// order.
    #[tokio::test]
    async fn a_plan_too_wide_to_address_is_still_walked_whole() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "192.0.2.0/30".parse::<IpSet>().expect("a prefix"),
            "80".parse::<PortSet>().expect("ports"),
        ));
        map.add_unit(TargetSet::new(
            "2001:db8::/48".parse::<IpSet>().expect("a prefix"),
            "80".parse::<PortSet>().expect("ports"),
        ));

        let (_session, ctx) = ordered(0x5EED);
        let mut rx = Dispatcher::new(map).with_batch_size(4).run(&ctx);

        // The wide unit never finishes, so read the first batch: the narrow
        // unit's four targets.
        let mut asked = Vec::new();
        for _ in 0..4 {
            asked.push(rx.recv().await.expect("the narrow unit is emitted"));
        }
        ctx.handle.abort();

        let mut positions: Vec<u64> = asked.iter().map(|planned| planned.position).collect();
        positions.sort_unstable();
        assert_eq!(positions, vec![0, 1, 2, 3]);
    }

    /// A seeded sweep covers the whole set once, in a scrambled order.
    #[tokio::test]
    async fn a_seeded_sweep_covers_the_whole_set_without_walking_it() {
        const BATCH: usize = 32;

        let set: IpSet = "192.0.2.0/24".parse().expect("a prefix");
        let expected: Vec<IpAddr> = set.iter().collect();

        let handle = ScanHandle::new();
        let mut rx = dispatch_addresses(set, BATCH, Some(0x5EED), &handle);

        let mut swept = Vec::new();
        while let Some(ip) = rx.recv().await {
            swept.push(ip);
        }

        assert_eq!(swept.len(), expected.len());

        // A batch-local shuffle draws its first batch only from the first
        // `BATCH` addresses.
        let beyond = swept[..BATCH]
            .iter()
            .filter(|ip| match ip {
                IpAddr::V4(v4) => v4.octets()[3] as usize >= BATCH,
                IpAddr::V6(_) => false,
            })
            .count();
        assert!(
            beyond > BATCH / 2,
            "only {beyond} of the first {BATCH} addresses came from beyond the \
             start of the range, which is a walk rather than a rearrangement"
        );

        let mut sorted = swept.clone();
        sorted.sort();
        assert_eq!(sorted, expected, "an address was swept twice or not at all");
    }

    /// Every target the dispatcher emitted, by address, with its position.
    async fn numbered(
        map: TargetMap,
        live: Option<IpSet>,
    ) -> std::collections::HashMap<IpAddr, u64> {
        let (_session, ctx) = context();
        let mut dispatcher = Dispatcher::new(map);
        if let Some(live) = live {
            dispatcher = dispatcher.screened(live, IpSet::new());
        }

        let mut rx = dispatcher.run(&ctx);
        let mut found = std::collections::HashMap::new();
        while let Some(planned) = rx.recv().await {
            found.insert(planned.target.ip, planned.position);
        }
        found
    }
}
