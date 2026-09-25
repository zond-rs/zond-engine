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
//! scanning strategies to consume, in an order that is not the plan's.
//!
//! ## Which order, and why it is not a shuffle
//!
//! A scan given a seed walks a [`Permutation`] of the plan's whole index space:
//! the nth target it asks about is somewhere else entirely in the plan, and
//! consecutive questions land in unrelated parts of the network. The plan is
//! addressed by position through [`TargetIndex`] rather than expanded, so this
//! costs a few words whatever the range.
//!
//! Without one it falls back to a batch-local shuffle: fill a fixed-size batch
//! in plan order, shuffle that, and stream it out before moving on.
//! Neighbouring addresses end up spread apart in time and the memory cost stays
//! bounded, but only within the batch. At batch granularity a `/16` is still
//! walked in address order, which is the most recognisable thing a scanner
//! emits, so the fallback is for the plans a permutation cannot address rather
//! than a setting anybody should want.
//!
//! The batch stays either way, because it has a second job: it is the unit the
//! channel is sized against, and a rearranged stream is filled and drained
//! through the same buffer.
//!
//! ## The numbering is not the order
//!
//! Targets are numbered by their position in [`TargetMap::iter`] whichever way
//! they are emitted. That is what a journal records, what a cursor advances over
//! and what a resumed sitting skips by, so it has to be a property of the job
//! rather than of the sitting: renumbering a permuted stream would give position
//! zero to whatever came out first, and two sittings would count different
//! things. See [`cursor`](crate::journal::cursor).
//!
//! ## The batch size
//!
//! Both entry points here take one, and both hold it to at least one probe. A
//! batch of zero is a caller error rather than an instruction to send nothing:
//! it reaches `mpsc::channel`, which asserts on an empty buffer, so honouring
//! the number would end the scan in a panic rather than in an empty result. The
//! same reading `rate_within` gives a configured rate of zero.

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
/// The sweep counterpart of [`Dispatcher`], and it yields bare addresses rather
/// than [`PlannedTarget`]s because a sweep is counted in addresses and numbers
/// them elsewhere: a [`HostScanner`](crate::scanner::strategy::HostScanner) owns
/// its targets, so its positions come from its context rather than off this
/// stream. See
/// [`ScanContext::settle_address`](crate::scanner::session::ScanContext::settle_address).
///
/// `seed` is the same bargain the dispatcher makes and gets the same two orders;
/// see the module documentation. A sweep is where the difference shows most,
/// since it is the phase that walks a whole range and the one an evaluator
/// watches on the wire.
///
/// The numbering here is [`Positions`] over the set it was handed, and it is only
/// ever the order: a resumed sweep is handed what it has left, so these positions
/// count a subset and are not the ones a journal records. What an address settles
/// against is the numbering on the context, which covers the whole plan. See
/// [`ScanContext::settle_address`](crate::scanner::session::ScanContext::settle_address).
///
/// Ranges too wide to number are asked about last and in order, because there is
/// no position to rearrange them by. They are the ranges
/// [`Positions::unnumbered`] names, and a sweep of one does not finish anyway.
///
/// `batch_size` is held to at least one probe; see the module documentation.
pub fn dispatch_addresses(
    ips: IpSet,
    batch_size: usize,
    seed: Option<u64>,
    scan_handle: &ScanHandle,
) -> mpsc::Receiver<IpAddr> {
    dispatch_addresses_of(ips, batch_size, seed, None, scan_handle)
}

/// [`dispatch_addresses`], walking the order of the plan `plan` numbers rather
/// than one of `ips` alone, for a sweep counted in addresses.
///
/// A resumed sweep is handed what it has left, and a permutation of that is a
/// different order from the one the first sitting walked. The settlements count
/// along the plan's walk, and answers arriving in some other order would wait in
/// their set, which is the growth the walk exists to prevent; see
/// [`cursor`](crate::journal::cursor). So the plan's walk is taken and what this
/// sitting was not handed is stepped over.
///
/// An empty numbering is a sweep counted in something else, a port scan's
/// liveness pass, and walks `ips` as [`dispatch_addresses`] does.
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

        // Built before the stream that borrows it, and once: numbering a set is
        // a table of its ranges rather than of its addresses, but it is still
        // work, and doing it per batch would do it again for every eight
        // thousand addresses.
        let numbered = seed.map(|seed| {
            let numbered = plan
                .clone()
                .unwrap_or_else(|| std::sync::Arc::new(Positions::of(&ips)));
            let order = Permutation::new(seed, numbered.total());
            (numbered, order)
        });

        let addresses: Box<dyn Iterator<Item = IpAddr> + Send + '_> = match &numbered {
            // What the numbering could not reach follows the numbered ones, as
            // it does in the set's own walk, so an address is emitted exactly
            // once either way. Numbering `ips` itself, that is its ranges too
            // wide to number. Numbering the plan, it is every address this
            // sitting was handed that no position names, those ranges among
            // them.
            Some((numbered, order)) => {
                let walked = order
                    .iter()
                    .filter_map(|position| numbered.address_at(position))
                    .filter(|ip| ips.contains(ip));
                if plan.is_some() {
                    Box::new(walked.chain(ips.iter().filter(|ip| numbered.find(*ip).is_none())))
                } else {
                    Box::new(
                        walked.chain(numbered.unnumbered().iter().flat_map(|range| range.iter())),
                    )
                }
            }
            None => ips.iter(),
        };

        for ip in addresses {
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
/// and a port scan in numbered targets. One function serves both the full batch
/// and the flush, because spelling it out twice inline would be two places for
/// the stop check to be got wrong.
async fn drain<T>(batch: &mut Vec<T>, tx: &mpsc::Sender<T>, scan_handle: &ScanHandle) -> bool {
    batch.shuffle(&mut rand::rng());
    for item in batch.drain(..) {
        if tx.send(item).await.is_err() || scan_handle.should_stop() {
            return false;
        }
    }
    true
}

/// How many targets a [`Dispatcher`] holds in flight unless told otherwise.
///
/// Small enough that the buffer behind it is a few hundred kilobytes rather than
/// a function of the range, and wide enough to keep the send path fed.
///
/// Without a seed it is the spread as well, since a batch is then what gets
/// shuffled, and at this size neighbouring addresses of a `/24` land far apart.
/// With one, a [`Permutation`] spreads the whole plan however this is set, so
/// what this decides is the memory bound.
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
    /// What the liveness pass found, when one ran.
    ///
    /// Filtered here rather than by narrowing the plan, for the same reason
    /// `settled` is. Which hosts answer is a property of the network on the day,
    /// so a plan narrowed to them is a different plan every sitting, and a
    /// position counted in one of those means a different target in the next.
    screen: Option<Screen>,
}

/// What a liveness pass established, in the two halves the port phase reads.
struct Screen {
    /// The addresses it found something at, which are probed.
    live: IpSet,
    /// The addresses it asked as many times as its policy allows and heard
    /// nothing from, whose targets are settled without a probe.
    ///
    /// Not every address outside `live`. The rest are the ones the pass never
    /// reached a verdict on, and those are left for the next sitting.
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
    /// [`JournalManifest::covers`](crate::journal::manifest::JournalManifest::covers),
    /// which is what refuses one that was not.
    pub fn resuming(mut self, settled: Checkpoint) -> Self {
        self.settled = settled;
        self
    }

    /// Emits only the targets whose address is in `live`, settling those whose
    /// address is in `silent` as
    /// [`Skipped`](crate::journal::settle::Outcome::Skipped) and recording the
    /// rest as [`Undecided`](crate::journal::settle::Outcome::Undecided).
    ///
    /// For the port phase of a scan that established which hosts are there
    /// first. A target whose host was asked and answered nothing is not one the
    /// scan failed to ask about: the scan asked whether the host was there,
    /// heard nothing, and declined to spend a probe on each of its ports. That
    /// decision is evidence, and a resume that had to re-derive it would ask the
    /// network a question it already answered.
    ///
    /// A host in neither set has no such evidence behind it. The pass stopped
    /// before it reached a verdict, or never could, and settling its ports would
    /// have a resume skip a host nobody asked about. So `silent` is what
    /// settles, and an address merely absent from `live` does not.
    ///
    /// Without this the plan would have to be narrowed to the live hosts before
    /// numbering, which would make a position mean something different in every
    /// sitting.
    pub fn screened(mut self, live: IpSet, silent: IpSet) -> Self {
        self.screen = Some(Screen { live, silent });
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

    /// Spawns a background task that streams the plan's targets, in the order
    /// the scan asks about them, and returns the [`mpsc::Receiver`] they arrive
    /// on.
    ///
    /// The order comes from
    /// [`SessionBuilder::ordering`](crate::scanner::session::SessionBuilder::ordering)
    /// through `ctx`; see the module documentation for what each of the two is.
    ///
    /// The channel holds up to twice the batch size, so the producer can prepare
    /// the next batch while the current one is still being consumed without letting
    /// the buffer grow without bound. The task stops early if the receiver is
    /// dropped or the scan signals a stop.
    ///
    /// The task settles the targets it does not emit as it walks past them, so
    /// a caller that checkpoints the scan should drain the receiver to its end
    /// before the last checkpoint: a receiver dropped early leaves the task
    /// winding down on its own, and what it settles then may land after the
    /// checkpoint was written.
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
        let ctx = ctx.clone();

        let walk = tokio::spawn(async move {
            let mut batch = Vec::with_capacity(batch_size);

            // Numbered by position in the plan whichever way they arrive, so
            // nothing downstream has to re-derive one and no sitting counts
            // differently from another.
            let stream: Box<dyn Iterator<Item = PlannedTarget> + Send> = match &order {
                // From where an earlier sitting's walk got to, where it walked
                // this same order: everything before that is settled, and
                // stepping over it one position at a time is the one cost of a
                // resume that grows with how far the first sitting got.
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

            for planned in stream {
                // Skipped rather than emitted, and skipped in both orders: what
                // an earlier sitting settled is a fact about the job, so it is
                // filtered after the numbering and never before.
                if self.settled.is_settled(planned.position) {
                    continue;
                }

                // Settled where it stands rather than emitted: the position is
                // known here and nowhere downstream, and a target dropped
                // without one would stall the watermark on it for the rest of
                // the job.
                if let Some(screen) = &self.screen
                    && !screen.live.contains(&planned.target.ip)
                {
                    // Checked here as well as on a send, because a scan whose
                    // liveness pass was stopped has few hosts to emit and would
                    // otherwise walk the rest of the plan before noticing. What
                    // it leaves is unsettled, and is asked again.
                    if scan_handle.should_stop() {
                        return;
                    }
                    ctx.record_outcome(if screen.silent.contains(&planned.target.ip) {
                        Outcome::Skipped {
                            position: planned.position,
                        }
                    } else {
                        Outcome::Undecided
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
    /// [`None`] where either is missing, which is the batch-shuffled walk. A plan
    /// [`TargetIndex`] cannot address whole is one whose addresses outrun the
    /// numbering, and walking a permutation of the part that fits would ask about
    /// a prefix of the job and report having asked about all of it.
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

    /// A batch of zero would reach `mpsc::channel`, which asserts on an empty
    /// buffer, so the mistake would end the scan in a panic rather than in an
    /// empty result. Both entry points take the size from the caller.
    #[tokio::test]
    async fn a_zero_batch_is_read_as_one_probe_rather_than_panicking() {
        use crate::scanner::session::ScanSession;

        let (_session, ctx) = ScanSession::new();
        let mut rx = Dispatcher::new(TargetMap::new())
            .with_batch_size(0)
            .run(&ctx);

        assert!(rx.recv().await.is_none(), "an empty plan yields nothing");
    }

    /// The sweep stream takes its size the same way and holds it the same way.
    #[tokio::test]
    async fn the_address_stream_holds_a_zero_batch_to_one_too() {
        let handle = ScanHandle::new();
        let mut rx = dispatch_addresses(IpSet::new(), 0, None, &handle);

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

    /// An unseeded dispatcher shuffles within each batch, and emits every
    /// target of the plan once.
    ///
    /// The shuffle is random, so whether it moved anything is a question of
    /// probability, and the plan is sized so the answer cannot come out wrong
    /// by chance: 1,000 targets in batches of 100 are all left in plan order
    /// with probability (1/100!)^10, where ten targets in batches of four were
    /// left in order about once in 1,150 runs and failed the suite for it.
    #[tokio::test]
    async fn dispatcher_emits_all_targets_shuffled() {
        let mut target_map = TargetMap::new();
        let ip_set: IpSet = "192.0.2.1-192.0.2.250".parse().unwrap();
        let port_set: PortSet = "80,443,8080,8443".parse().unwrap();
        target_map.units.push(TargetSet::new(ip_set, port_set));

        let (_session, ctx) = context();
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
        // Shuffled within a batch and never across one: each run of 100 is
        // exactly the batch the plan put there.
        for (batch, chunk) in positions.chunks(100).enumerate() {
            let mut sorted = chunk.to_vec();
            sorted.sort_unstable();
            let first = batch as u64 * 100;
            assert_eq!(sorted, (first..first + 100).collect::<Vec<_>>());
        }
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

    /// **Only silence the liveness pass heard settles a target.** A host
    /// missing from the live set that the pass never reached a verdict on, one
    /// it stopped before asking, had no strategy for or was refused, is left
    /// for the next sitting. Settled as down, a resume would skip a host
    /// nobody asked about and report it silent.
    #[tokio::test]
    async fn a_host_the_liveness_pass_reached_no_verdict_on_is_left_unsettled() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            "192.0.2.1-192.0.2.4".parse::<IpSet>().expect("a range"),
            "80,443".parse::<PortSet>().expect("ports"),
        ));

        let (_session, ctx) = context();
        // .1 answered, .2 was asked and stayed silent, .3 and .4 were never
        // asked.
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

    /// A stop arriving during the liveness pass leaves the port phase few hosts
    /// to emit, so the walk has to notice it between skipped targets as well as
    /// on a send, or it walks the rest of a wide plan after the caller asked it
    /// to stop.
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

    /// **Every settlement the walk makes is in once its task is awaited.** A
    /// scanner that stops early drops the receiver while the walk may still be
    /// settling the targets of hosts found down, and a scan that ended without
    /// waiting for it would write its last checkpoint without them.
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

    /// A rearrangement asks about every target and asks about none of them
    /// twice, which is the difference between an order and a sample.
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

    /// The property the journal rests on, and the one a rearrangement is most
    /// likely to break: a target's position is where the plan holds it, never
    /// where the scan got round to asking about it.
    ///
    /// Renumbering by emission order would leave every checkpoint naming a
    /// different target in the next sitting, and a resume would skip ground
    /// nothing probed while reporting the job done.
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

    /// A batch-local shuffle spreads neighbours within one batch, eight thousand
    /// targets by default, and walks everything above that in plan order, so the
    /// first batch of a range wider than a batch is always drawn from its lowest
    /// addresses and a sensor watching the range sees a monotonic sweep.
    ///
    /// The first batch out of a rearranged plan is drawn from all of it.
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

    /// A resumed sitting asks about what is left and nothing else, in whatever
    /// order the seed gives. The settled filter reads a position, so it does not
    /// care which order they arrive in, and this is what says so.
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

    /// A sitting resumed from a checkpoint counted along its own walk picks
    /// the walk up where the earlier one left it, and still asks exactly what
    /// is left: nothing the walk passed, nothing the list names, everything
    /// else.
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

    /// A sweep counted in a plan's addresses walks the plan's order over
    /// whatever part of it this sitting was handed, so a resumed sweep asks
    /// its remainder in the order the first sitting was asking the whole.
    ///
    /// That is what lets its answers be counted along the walk: a permutation
    /// of the remainder alone is another order, whose answers would wait in
    /// the settlements' set rather than moving a watermark.
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

    /// A plan whose addresses outrun the numbering cannot be addressed by
    /// position, so it is walked in plan order rather than part of it being
    /// rearranged and the rest quietly dropped.
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

        // The wide unit does not finish, so this reads the first batch and
        // stops. What it checks is that the four targets of the narrow unit are
        // all there, which the permuted path would have emitted alone.
        let mut asked = Vec::new();
        for _ in 0..4 {
            asked.push(rx.recv().await.expect("the narrow unit is emitted"));
        }
        ctx.handle.abort();

        let mut positions: Vec<u64> = asked.iter().map(|planned| planned.position).collect();
        positions.sort_unstable();
        assert_eq!(positions, vec![0, 1, 2, 3]);
    }

    /// The sweep gets the same two orders and the same guarantee about what it
    /// covers. It is also where the difference shows most, since a sweep walks a
    /// whole range and is the phase somebody watches on the wire.
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

        // The batch-shuffled walk draws its first batch from the first `BATCH`
        // addresses of the range and no others, so this is what tells the two
        // apart rather than merely showing the order is not ascending.
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

    /// Every target the dispatcher emitted, by address, with the position it
    /// carried. `live` narrows what is emitted and must never renumber it.
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
