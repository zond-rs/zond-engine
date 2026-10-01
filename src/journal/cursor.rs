// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How far a scan got
//!
//! A position in the plan below which everything is settled, and the positions above it
//! that settled out of order.
//!
//! ## A position needs nothing stored to name it
//!
//! [`TargetMap::iter`](crate::model::target::TargetMap::iter) walks its units in order and
//! each unit's addresses against its ports, and a
//! [`TargetSet`](crate::model::target::TargetSet) is canonical and immutable from
//! construction. So the same plan yields the same targets in the same order on every run,
//! and the nth target is a stable identity. The cursor holds integers, not addresses, and
//! its size depends on how far out of order the scan settled, not on the scan's size.
//!
//! The dispatcher and this module must use one numbering. The order targets are asked in
//! is separate: a scan given a seed walks a [`Permutation`] of the whole index space and
//! numbers what comes out by where the plan holds it, through [`TargetIndex`]. `model`'s
//! test `a_position_names_the_target_the_plans_own_walk_numbers_it` checks the index and
//! this walk agree at every position.
//!
//! ## The watermark chases the settled set
//!
//! [`Cursor::settle`] records a position and then advances the watermark over every
//! consecutive settled position above it. Anything settled out of order waits in
//! [`above`](Cursor::settled_above) until the gap below it fills, so the set holds only what
//! the watermark has not caught up to. How much that is depends on the walk order.
//!
//! Walked in plan order, it is bounded by how far the dispatcher runs ahead of the slowest
//! outstanding probe. A single tarpitting host stalls the watermark and the set grows to
//! the pipeline depth, then collapses when that host settles.
//!
//! Walked in a seeded [`Permutation`], as every scan the engine starts is, settled positions
//! are scattered across the plan and a plan-order watermark stays near zero until nearly
//! all are in. The set would be half the plan at the halfway mark.
//!
//! ## Two watermarks
//!
//! One counts in plan order, and one in the order the scan asks in: a [`Walk`](Walked)
//! says that every position the permutation names before a given index is settled. A
//! position is settled if either watermark has passed it or it waits in the set, and the
//! set holds only what neither has reached.
//!
//! One of the two follows whichever order a phase settles in. A port scan's dispatcher walks
//! the permutation, so the walk watermark keeps the set at pipeline size however large the
//! plan. A link-layer sweep asks in address order, so the plan watermark does. A phase
//! mixing the two also holds roughly the part of the plan the slower order has yet to reach.
//!
//! The walk (seed and length) is recorded beside the positions, so a checkpoint says on its
//! own which targets it accounts for. Positions are still plan positions.
//!
//! An engine that predates the walk reads such a checkpoint as having settled only what the
//! plan watermark and the set name, and asks again about what the walk covered. That costs
//! probes and skips nothing, so no format version is spent on it.
//!
//! ## Only settled positions are recorded
//!
//! A position arrives only from [`Outcome`](super::settle::Outcome)'s settled variants. A
//! target that was interrupted, never asked or never routed has no position, so the
//! watermark stalls behind it and the next sitting asks again.

use std::collections::BTreeSet;
use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::model::ip::set::{IpSet, Positions};
use crate::model::order::Permutation;
use crate::model::target::{PlannedTarget, Target, TargetIndex};

/// How far a scan has got, maintained as it runs.
///
/// Cheap to update. A snapshot holds what neither watermark has reached; see the
/// module documentation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cursor {
    watermark: u64,
    above: BTreeSet<u64>,
    walk: Option<Walked>,
}

impl Cursor {
    /// A cursor over a plan with nothing settled yet, counted in plan order alone.
    pub fn new() -> Self {
        Self::default()
    }

    /// A cursor over a plan with nothing settled yet, that also counts along `order`,
    /// the order the scan asks its targets in. Settled in that order, a plan of any size holds
    /// about a pipeline's worth of positions.
    pub fn walking(order: Permutation) -> Self {
        Self::new().along(order)
    }

    /// Resumes from a checkpoint, along the walk it recorded if any.
    pub fn from_checkpoint(checkpoint: &Checkpoint) -> Self {
        let walk = checkpoint
            .walked
            .map(|walked| walked.clamped(checkpoint.watermark));
        let mut cursor = Self {
            watermark: checkpoint.watermark,
            above: checkpoint
                .settled_above
                .iter()
                .copied()
                .filter(|position| *position >= checkpoint.watermark)
                .filter(|position| !walk.is_some_and(|walk| walk.covers(*position)))
                .collect(),
            walk,
        };
        // A checkpoint written by a newer build, or edited by hand, may name positions
        // already contiguous with a watermark; normalise so the invariants hold.
        cursor.catch_up();
        cursor
    }

    /// Counts along `order` as well, for a cursor not yet counting along any walk: one
    /// resumed from a checkpoint written before the scan was walked, or by a sitting that was
    /// not.
    ///
    /// A cursor already counting along a walk keeps it, since its positions were recorded
    /// against that walk and a resume under the same manifest asks in that order anyway.
    pub(crate) fn along(mut self, order: Permutation) -> Self {
        if self.walk.is_none() {
            self.walk = Some(Walked::start(order));
            self.catch_up();
        }
        self
    }

    /// Records that the target at `position` is settled.
    ///
    /// Idempotent: settling a position already passed or recorded changes nothing. A
    /// target can be reported twice, by a probe retired on its retry budget and then by a stop
    /// path that does not know it already had a verdict.
    pub fn settle(&mut self, position: u64) {
        if self.is_settled(position) {
            return;
        }

        self.above.insert(position);
        self.catch_up();
    }

    /// Advances both watermarks over every settled position they can reach.
    ///
    /// Each can let the other go further: a position the walk passed may be the one the
    /// plan watermark was waiting on, and vice versa. So they take turns until the walk stops
    /// moving.
    ///
    /// Saturating, because positions may come from a cursor file this process did not write.
    /// A planted `u64::MAX` would otherwise panic in debug or wrap to zero in release, silently
    /// un-settling every finished target. Saturating wedges the watermark at the ceiling, which
    /// errs towards re-probing.
    fn catch_up(&mut self) {
        let Self {
            watermark,
            above,
            walk,
        } = self;

        loop {
            loop {
                if above.remove(watermark) {
                    // Moves from the set to the watermark.
                } else if let Some(walk) = walk.as_mut()
                    && walk.covers(*watermark)
                {
                    // Counted as ahead when the walk passed it; now counted by the watermark.
                    walk.ahead = walk.ahead.saturating_sub(1);
                } else {
                    break;
                }
                *watermark = watermark.saturating_add(1);
            }

            let Some(walk) = walk.as_mut() else { return };
            let mut walked = false;
            while let Some(position) = walk.order().at(walk.reached) {
                if position < *watermark {
                    // Already counted, below the plan watermark.
                } else if above.remove(&position) {
                    walk.ahead = walk.ahead.saturating_add(1);
                } else {
                    break;
                }
                walk.reached += 1;
                walked = true;
            }

            if !walked {
                return;
            }
        }
    }

    /// The position below which every target is settled, in plan order.
    ///
    /// A resume starts here, and skips the positions above it that
    /// [`is_settled`](Self::is_settled) names.
    pub fn watermark(&self) -> u64 {
        self.watermark
    }

    /// The settled positions neither watermark has reached, ascending.
    pub fn settled_above(&self) -> impl Iterator<Item = u64> + '_ {
        self.above.iter().copied()
    }

    /// Whether the target at `position` may be skipped.
    pub fn is_settled(&self, position: u64) -> bool {
        position < self.watermark
            || self.above.contains(&position)
            || self.walk.is_some_and(|walk| walk.covers(position))
    }

    /// How many targets are settled in total.
    ///
    /// Saturating like the watermark's advance: a count that wrapped would report a
    /// nearly finished scan as barely started.
    pub fn settled_count(&self) -> u64 {
        self.watermark
            .saturating_add(self.walk.map_or(0, |walk| walk.ahead))
            .saturating_add(self.above.len() as u64)
    }

    /// How many settled positions are waiting on a gap below them in both orders.
    ///
    /// The size of the out-of-order window, and so of a checkpoint. A number that keeps growing
    /// means a target that never settles: a tarpit or a defect.
    pub fn pending_count(&self) -> usize {
        self.above.len()
    }

    /// A snapshot to write to disk.
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            watermark: self.watermark,
            settled_above: self.above.iter().copied().collect(),
            walked: self.walk,
        }
    }
}

/// How far along the order a scan asks in everything is settled.
///
/// Every position [`Permutation::new(seed, len)`](Permutation::new) names before
/// index `reached` is settled. Written down whole, so a checkpoint says on its own which
/// positions it accounts for.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Walked {
    /// The key of the order walked.
    pub seed: u64,
    /// How many positions it rearranges: the plan's total.
    pub len: u64,
    /// How many of its positions, in the order it names them, are settled.
    pub reached: u64,
    /// How many of those are at or past the plan watermark.
    ///
    /// Lets a total be read without walking; the rest of what the walk reached is below the
    /// watermark and already counted there. What a resume skips is decided by `reached`
    /// alone.
    pub ahead: u64,
}

impl Walked {
    /// The start of a walk along `order`: nothing reached.
    fn start(order: Permutation) -> Self {
        Self {
            seed: order.seed(),
            len: order.len(),
            reached: 0,
            ahead: 0,
        }
    }

    /// The order walked.
    pub fn order(&self) -> Permutation {
        Permutation::new(self.seed, self.len)
    }

    /// Whether the walk has passed `position`.
    pub fn covers(&self, position: u64) -> bool {
        self.order()
            .index_of(position)
            .is_some_and(|index| index < self.reached)
    }

    /// Clamped to what the numbers can mean, for values read from a file: no more
    /// reached than the walk holds, and no more ahead than was reached or than the plan has past
    /// `watermark`.
    fn clamped(mut self, watermark: u64) -> Self {
        self.reached = self.reached.min(self.len);
        self.ahead = self
            .ahead
            .min(self.reached)
            .min(self.len.saturating_sub(watermark));
        self
    }
}

/// A cursor as it is written down.
///
/// Two watermarks and the positions neither has reached. Settled in either order the
/// scan counts in, that is a handful of positions however large the plan.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// The position below which everything is settled.
    pub watermark: u64,
    /// Settled positions at or above the watermark that the walk has not reached,
    /// ascending.
    ///
    /// Ascending is an invariant: [`is_settled`](Self::is_settled) binary-searches it.
    /// [`new`](Self::new) establishes it, and [`read`](Self::read) re-establishes it on anything
    /// read from a file.
    #[serde(default)]
    pub settled_above: Vec<u64>,
    /// How far along the order the scan asks in everything is settled, for a scan that
    /// counted along one.
    ///
    /// Absent from a checkpoint of a scan that was not walked, or from an older engine. An
    /// older engine reads a checkpoint carrying one as having settled less, which costs probes
    /// and skips nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub walked: Option<Walked>,
}

impl Checkpoint {
    /// A checkpoint over `watermark` and the settled positions above it.
    ///
    /// Sorts and deduplicates the list, the invariant [`is_settled`](Self::is_settled)
    /// relies on. The fields are public, but this is the way that cannot build one wrong, and a
    /// caller storing journals somewhere other than a directory should use it.
    pub fn new(watermark: u64, settled_above: impl IntoIterator<Item = u64>) -> Self {
        let mut settled_above: Vec<u64> = settled_above
            .into_iter()
            .filter(|position| *position >= watermark)
            .collect();
        settled_above.sort_unstable();
        settled_above.dedup();

        Self {
            watermark,
            settled_above,
            walked: None,
        }
    }

    /// Whether the target at `position` may be skipped.
    ///
    /// Binary-searched, so [`settled_above`](Self::settled_above) must be ascending;
    /// [`new`](Self::new) guarantees that.
    pub fn is_settled(&self, position: u64) -> bool {
        position < self.watermark
            || self.settled_above.binary_search(&position).is_ok()
            || self.walked.is_some_and(|walked| walked.covers(position))
    }

    /// How many targets are settled in total.
    ///
    /// Read without walking: the watermark, what the walk counted past it, and the
    /// positions neither reached. A listed position a watermark has passed is counted once, as
    /// [`Cursor::from_checkpoint`] reads the same file.
    pub fn settled_count(&self) -> u64 {
        let walked = self.walked.map(|walked| walked.clamped(self.watermark));
        let above = self
            .settled_above
            .iter()
            .filter(|position| **position >= self.watermark)
            .filter(|position| !walked.is_some_and(|walked| walked.covers(**position)))
            .count();

        self.watermark
            .saturating_add(walked.map_or(0, |walked| walked.ahead))
            .saturating_add(above as u64)
    }

    /// The addresses a resumed sweep still has to ask about.
    ///
    /// The sweep counterpart of [`remaining`](Self::remaining). Returns a set because a
    /// [`HostScanner`](crate::scanner::strategy::HostScanner) owns its targets and its positions
    /// come from the context; see
    /// [`ScanContext::settle_address`](crate::scanner::session::ScanContext::settle_address),
    /// which numbers an address against this same plan.
    ///
    /// Computed from the ranges: everything below the watermark is one span to drop, and the
    /// positions settled out of order above it are taken out individually. Anything the plan
    /// was too large to number comes back whole.
    ///
    /// `positions` must number the plan this checkpoint was written against; the manifest's
    /// plan fingerprint refuses a mismatched resume before it gets here.
    pub fn remaining_addresses(&self, positions: &Positions) -> IpSet {
        let mut remaining = IpSet::new();

        for span in self.unsettled_spans(positions.total()) {
            for range in positions.ranges_in(span) {
                remaining.insert_range(range);
            }
        }

        // A range too large to number holds no position, so every sitting asks about it
        // again.
        for range in positions.unnumbered() {
            remaining.insert_range(*range);
        }

        remaining.canonicalize();
        remaining
    }

    /// The addresses a resumed port scan still has a target at.
    ///
    /// The port-plan counterpart of [`remaining_addresses`](Self::remaining_addresses),
    /// for the host-level passes beside a port scan: the liveness sweep and the one that reads
    /// hardware addresses and round trips. An address whose every target an earlier sitting
    /// settled is not swept again.
    ///
    /// An address with any target outstanding comes back whole: whether the host is up is a
    /// property of the network on the day, so this sitting establishes it for itself.
    ///
    /// Read host by host where that is cheaper, which for a partly finished scan it is by far;
    /// see [`left_along`](Self::left_along).
    ///
    /// `index` must number the plan this checkpoint was written against, as for
    /// [`remaining`](Self::remaining). Every address of a unit the index could not number comes
    /// back, since none of its targets can have been settled.
    pub(crate) fn remaining_hosts(&self, index: &TargetIndex) -> IpSet {
        let mut remaining = IpSet::new();

        for span in self.left_in(index) {
            for range in index.addresses_in(span) {
                remaining.insert_range(range);
            }
        }
        for range in index.unnumbered_addresses() {
            remaining.insert_range(*range);
        }

        remaining.canonicalize();
        remaining
    }

    /// The stretches of `0..total` this checkpoint leaves unsettled, ascending and
    /// non-empty, for a plan where each position is its own host, as in a sweep.
    fn unsettled_spans(&self, total: u64) -> Vec<Range<u64>> {
        self.left_in(&Alone(total))
    }

    /// Stretches of `runs`' positions, ascending and non-empty, holding every position
    /// this checkpoint leaves unsettled and touching only hosts with one.
    ///
    /// Below the watermark everything is settled. Above it, a checkpoint counted in plan order
    /// alone settled only the listed positions, so the stretches are the gaps between them. One
    /// counted along a walk is read by [`left_along`](Self::left_along).
    fn left_in(&self, runs: &impl HostRuns) -> Vec<Range<u64>> {
        match self.walked {
            Some(walked) => self.left_along(walked.clamped(self.watermark), runs),
            None => self.spans_between(runs.total()),
        }
    }

    /// The hosts of `runs` where a checkpoint counted along `walked` leaves a target,
    /// as stretches of their whole runs of positions.
    ///
    /// What the walk has not reached is scattered across the plan. There are two ways to find
    /// it, each cheap where the other is expensive.
    ///
    /// **Host by host.** Each host past the watermark is asked, one position at a time, whether
    /// that position is settled, and the first that is not answers for the host. A host with
    /// `u` positions left is answered after about `1 / u` of them, so with half the plan left it
    /// costs about two questions a host and holds nothing. The cost grows as the plan empties:
    /// a finished host is asked every position.
    ///
    /// **Along the walk's tail.** The positions not yet reached are exactly those the walk names
    /// from `reached` on, so reading them and marking each one's host costs the tail length and
    /// a bit a host. Cheap late in a scan and expensive early: a `/8` on a thousand ports
    /// resumed half way has eight billion tail positions and sixteen million hosts.
    ///
    /// With `h` hosts, `n` positions past the watermark and `t` in the tail, the first costs
    /// about `h * min(n / h, n / t)` and the second `t`, so the tail is cheaper exactly when
    /// `t * t < h * n`. At the crossing either costs `h` times the square root of a host's
    /// ports. Past [`MARKED_AT_MOST`] hosts no bitmap is built and the plan is read host by
    /// host.
    fn left_along(&self, walked: Walked, runs: &impl HostRuns) -> Vec<Range<u64>> {
        let total = runs.total();
        if self.watermark >= total {
            return Vec::new();
        }

        let first = runs.host_of(self.watermark);
        let hosts = runs.hosts() - first;
        let past = total - self.watermark;
        let tail = walked.len - walked.reached;

        let order = walked.order();
        let listed = |position: u64| self.settled_above.binary_search(&position).is_ok();

        if reads_the_tail(tail, hosts, past) {
            let reached = order
                .iter_from(walked.reached)
                .filter(|position| *position >= self.watermark && *position < total)
                .filter(|position| !listed(*position));
            // A plan longer than the walk, which only a damaged file describes: the walk
            // names nothing past its end, so only the list can have settled any of it.
            let unwalked = self
                .gaps_from(walked.len.max(self.watermark), total)
                .into_iter()
                .flatten();
            return marked(runs, first, hosts, reached.chain(unwalked));
        }

        let unsettled = |position: u64| {
            position >= self.watermark
                && !listed(position)
                && !order
                    .index_of(position)
                    .is_some_and(|index| index < walked.reached)
        };
        host_by_host(runs, first..runs.hosts(), unsettled)
    }

    /// The unsettled stretches of a checkpoint counted in plan order alone: the gaps
    /// between the listed positions.
    fn spans_between(&self, total: u64) -> Vec<Range<u64>> {
        self.gaps_from(self.watermark, total)
    }

    /// The gaps between the positions the list names, from `from` to `total`.
    fn gaps_from(&self, from: u64, total: u64) -> Vec<Range<u64>> {
        // A checkpoint from disk is only as ordered as the file was. Sorting a copy is
        // linear on an already sorted list.
        let mut above = self.settled_above.clone();
        above.sort_unstable();

        let mut spans = Vec::with_capacity(above.len() + 1);
        let mut from = from;
        for settled in above {
            if settled < from {
                continue;
            }
            spans.push(from..settled.min(total));
            from = settled.saturating_add(1);
        }
        spans.push(from..total);

        spans.retain(|span| span.start < span.end);
        spans
    }

    /// The targets a resumed scan still has to ask about, each carrying its
    /// position in the original plan.
    ///
    /// Takes the plan's enumeration,
    /// [`TargetMap::iter`](crate::model::target::TargetMap::iter), the walk the first sitting
    /// was numbered by, and yields only what this checkpoint does not account for.
    ///
    /// Yields [`PlannedTarget`] so the original numbering survives the filtering: numbering the
    /// subset afresh would give position 0 to whatever is left, and the two sittings' cursors
    /// would count different things.
    ///
    /// The plan must be the one this checkpoint was written against. A changed port list,
    /// exclusion policy or privilege level moves what each position refers to. Nothing here
    /// detects that; the manifest's plan fingerprint refuses the resume first.
    pub fn remaining<'a, I>(&'a self, targets: I) -> impl Iterator<Item = PlannedTarget> + 'a
    where
        I: IntoIterator<Item = Target> + 'a,
    {
        targets
            .into_iter()
            .enumerate()
            .map(|(position, target)| PlannedTarget::new(position as u64, target))
            .filter(move |planned| !self.is_settled(planned.position))
    }
}

/// The most hosts [`Checkpoint::left_along`] marks in a bitmap, a bit each: 128
/// MiB, every address of a quarter of IPv4.
///
/// A plan with more is read host by host. Only a plan with an IPv6 range comes near it.
const MARKED_AT_MOST: u64 = 1 << 30;

/// Whether [`Checkpoint::left_along`] reads the walk's tail of `tail` positions
/// instead of asking `hosts` hosts holding `past` positions one by one: where the tail is
/// cheaper and its bitmap is within [`MARKED_AT_MOST`].
fn reads_the_tail(tail: u64, hosts: u64, past: u64) -> bool {
    let tail = u128::from(tail);
    tail * tail < u128::from(hosts) * u128::from(past) && hosts <= MARKED_AT_MOST
}

/// A numbering of targets seen host by host: each host's targets hold a contiguous
/// run of positions, and the runs ascend.
///
/// In a port plan the hosts are addresses, each with a run of its ports, since the port
/// index runs fastest; see [`TargetIndex`]. In a sweep each address is a run of one.
trait HostRuns {
    /// How many positions are numbered.
    fn total(&self) -> u64;
    /// How many hosts hold them.
    fn hosts(&self) -> u64;
    /// The positions of host `host`, which is below [`hosts`](Self::hosts).
    fn run(&self, host: u64) -> Range<u64>;
    /// The host whose run holds `position`, which is below [`total`](Self::total).
    fn host_of(&self, position: u64) -> u64;
}

impl HostRuns for TargetIndex {
    fn total(&self) -> u64 {
        TargetIndex::total(self)
    }

    fn hosts(&self) -> u64 {
        TargetIndex::hosts(self)
    }

    fn run(&self, host: u64) -> Range<u64> {
        self.host_run(host)
    }

    fn host_of(&self, position: u64) -> u64 {
        TargetIndex::host_of(self, position)
    }
}

/// `0..n` with every position a host of its own, as a sweep numbers addresses.
struct Alone(u64);

impl HostRuns for Alone {
    fn total(&self) -> u64 {
        self.0
    }

    fn hosts(&self) -> u64 {
        self.0
    }

    fn run(&self, host: u64) -> Range<u64> {
        host..host + 1
    }

    fn host_of(&self, position: u64) -> u64 {
        position
    }
}

/// The runs of the hosts in `hosts` with a position `unsettled` answers for, merged
/// where they meet. Each host is asked one position at a time, in plan order; see
/// [`Checkpoint::left_along`].
fn host_by_host(
    runs: &impl HostRuns,
    hosts: Range<u64>,
    mut unsettled: impl FnMut(u64) -> bool,
) -> Vec<Range<u64>> {
    let mut spans = Vec::new();
    for host in hosts {
        let run = runs.run(host);
        if run.clone().any(&mut unsettled) {
            extend(&mut spans, run);
        }
    }
    spans
}

/// The runs of the hosts holding any of `positions`, merged where they meet, for
/// `hosts` hosts numbered from `first`. Marked in a bitmap in any order and read back in
/// plan order; see [`Checkpoint::left_along`].
fn marked(
    runs: &impl HostRuns,
    first: u64,
    hosts: u64,
    positions: impl Iterator<Item = u64>,
) -> Vec<Range<u64>> {
    // Within `MARKED_AT_MOST`, so the words fit in memory and their count in a
    // `usize`.
    let mut bits = vec![0u64; hosts.div_ceil(64) as usize];
    for position in positions {
        let host = runs.host_of(position) - first;
        bits[(host / 64) as usize] |= 1 << (host % 64);
    }

    let mut spans = Vec::new();
    for (at, word) in bits.iter().enumerate() {
        let mut word = *word;
        while word != 0 {
            let host = first + at as u64 * 64 + u64::from(word.trailing_zeros());
            extend(&mut spans, runs.run(host));
            word &= word - 1;
        }
    }
    spans
}

/// Appends `run` to `spans`, joining the last one where the two meet.
fn extend(spans: &mut Vec<Range<u64>>, run: Range<u64>) {
    match spans.last_mut() {
        Some(span) if span.end == run.start => span.end = run.end,
        _ => spans.push(run),
    }
}

#[cfg(feature = "journal-format")]
mod persistence {
    use std::io::Write;
    use std::path::Path;

    use super::Checkpoint;
    use crate::journal::file::replace;
    use crate::journal::format::JournalError;

    impl Checkpoint {
        /// Writes the checkpoint so that a process killed mid-write leaves the previous one
        /// intact.
        ///
        /// Writes a sibling temporary file and renames it over the destination, which is atomic on
        /// every filesystem this engine runs on, so a reader sees one whole checkpoint or the one
        /// before. No `fsync`: `^C`, a dropped session and an OOM kill are process deaths, and the
        /// page cache outlives the process. See [`journal`](crate::journal).
        pub fn write_atomically(&self, path: &Path) -> Result<(), JournalError> {
            let text = serde_json::to_string(self).map_err(JournalError::json)?;
            replace(path, &path.with_extension("tmp"), |mut file| {
                file.write_all(text.as_bytes())
            })?;
            Ok(())
        }

        /// Reads a checkpoint back.
        ///
        /// The `settled_above` list is sorted on read, since
        /// [`is_settled`](Checkpoint::is_settled) binary-searches it and an unsorted list would
        /// miss a position that is present and re-probe a settled target.
        pub fn read(path: &Path) -> Result<Self, JournalError> {
            let text = super::super::store::read_bounded(path, "a journal cursor")?;
            let mut checkpoint: Self = serde_json::from_str(&text).map_err(JournalError::json)?;
            checkpoint.settled_above.sort_unstable();
            checkpoint.settled_above.dedup();
            Ok(checkpoint)
        }
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

    // ─── Resuming a sweep ────────────────────────────────────────────────────

    use std::net::IpAddr;

    fn addresses(written: &str) -> IpSet {
        written.parse().expect("a valid address specification")
    }

    /// A resumed sweep asks about exactly what the first sitting did not settle. One
    /// address too few is a target silently skipped.
    #[test]
    fn a_resumed_sweep_asks_about_exactly_what_did_not_settle() {
        let plan = addresses("192.0.2.1-192.0.2.10");
        let positions = plan.positions();

        let checkpoint = Checkpoint {
            watermark: 3,
            settled_above: vec![5, 8],
            walked: None,
        };

        let remaining = checkpoint.remaining_addresses(&positions);
        let found: Vec<IpAddr> = remaining.iter().collect();
        let expected: Vec<IpAddr> = plan
            .iter()
            .enumerate()
            .filter(|(position, _)| !checkpoint.is_settled(*position as u64))
            .map(|(_, ip)| ip)
            .collect();

        assert_eq!(found, expected);
        assert_eq!(
            found.len(),
            5,
            "ten addresses, three settled below, two above"
        );
    }

    /// A sweep that settled nothing comes back whole.
    #[test]
    fn a_sweep_that_settled_nothing_resumes_over_the_whole_plan() {
        let plan = addresses("192.0.2.1-192.0.2.10,2001:db8::1-2001:db8::4");
        let remaining = Checkpoint::default().remaining_addresses(&plan.positions());

        assert_eq!(remaining, plan);
    }

    /// A range too large to number comes back whole, however far the numbered part got,
    /// so a resumed IPv6 sweep does not ask about nothing and report that it finished.
    #[test]
    fn a_sweep_of_an_unnumberable_plan_resumes_over_all_of_it() {
        let plan = addresses("192.0.2.0/30,2001:db8::/64");
        let positions = plan.positions();

        let checkpoint = Checkpoint {
            watermark: 4,
            settled_above: Vec::new(),
            walked: None,
        };
        let remaining = checkpoint.remaining_addresses(&positions);

        assert!(
            !remaining.is_empty(),
            "the /64 was never numbered and so was never settled"
        );
        assert_eq!(remaining.v4(), &[], "the numbered half did settle");
        assert_eq!(remaining.v6(), plan.v6());
    }

    /// A sweep that settled everything has nothing left to ask.
    #[test]
    fn a_finished_sweep_resumes_over_nothing() {
        let plan = addresses("192.0.2.1-192.0.2.4");
        let checkpoint = Checkpoint {
            watermark: 4,
            settled_above: Vec::new(),
            walked: None,
        };

        assert!(checkpoint.remaining_addresses(&plan.positions()).is_empty());
    }

    /// An address in the narrowed set numbers the same as it did in the first sitting.
    #[test]
    fn a_resumed_sweep_keeps_the_original_numbering() {
        let plan = addresses("192.0.2.1-192.0.2.10");
        let positions = plan.positions();
        let checkpoint = Checkpoint {
            watermark: 4,
            settled_above: Vec::new(),
            walked: None,
        };

        let remaining = checkpoint.remaining_addresses(&positions);
        let first = remaining.iter().next().expect("something is left");

        assert_eq!(
            positions.find(first),
            Some(4),
            "the fifth address is still the fifth, not the first of what is left"
        );
    }

    /// A checkpoint read from a file is only as ordered as the file was.
    #[test]
    fn an_unsorted_checkpoint_narrows_the_same_way() {
        let plan = addresses("192.0.2.1-192.0.2.10");
        let positions = plan.positions();

        let sorted = Checkpoint {
            watermark: 2,
            settled_above: vec![4, 6, 9],
            walked: None,
        };
        let shuffled = Checkpoint {
            watermark: 2,
            settled_above: vec![9, 4, 6],
            walked: None,
        };

        assert_eq!(
            sorted.remaining_addresses(&positions),
            shuffled.remaining_addresses(&positions)
        );
    }

    // ─── Resuming a port scan's host passes ──────────────────────────────────

    /// Several units, both families, and port counts that divide nothing, so an
    /// address's ports straddle every kind of boundary a span can end on.
    fn ports_plan() -> TargetMap {
        let mut map = TargetMap::new();
        for (range, ports) in [
            ("192.0.2.1-192.0.2.5", "22, 80, u:53"),
            ("198.51.100.7", "443"),
            ("203.0.113.0/30", "1-4, s:2905"),
            ("2001:db8::1-2001:db8::3", "80, u:161"),
        ] {
            map.add_unit(TargetSet::new(
                range.parse::<IpSet>().expect("a range"),
                ports.parse::<PortSet>().expect("ports"),
            ));
        }
        map
    }

    /// The addresses of what [`Checkpoint::remaining`] still yields, which
    /// `remaining_hosts` must agree with.
    fn hosts_of_remaining(checkpoint: &Checkpoint, map: &TargetMap) -> IpSet {
        let mut hosts = IpSet::new();
        for planned in checkpoint.remaining(map.iter()) {
            hosts.insert(planned.ip());
        }
        hosts.canonicalize();
        hosts
    }

    /// An address with a target left is swept, and one whose every target settled is
    /// not, however the settling fell across its ports.
    #[test]
    fn a_resumed_port_scan_sweeps_only_the_hosts_with_a_target_left() {
        // Three ports each: 192.0.2.1 is positions 0-2, .2 is 3-5, .3 is 6-8.
        let map = plan("192.0.2.1-192.0.2.3", "22, 80, 443");
        let index = TargetIndex::of(&map);

        let finished_second = Checkpoint::new(4, [4, 5]);
        assert_eq!(
            finished_second.remaining_hosts(&index),
            addresses("192.0.2.3"),
            "the first two settled every port between the watermark and the \
             positions above it"
        );

        let one_port_short = Checkpoint::new(4, [5]);
        assert_eq!(
            one_port_short.remaining_hosts(&index),
            addresses("192.0.2.2-192.0.2.3"),
            "the second host's port at position 4 is still outstanding"
        );
    }

    /// A walked checkpoint over `len` positions that reached `reached` of them, with
    /// `watermark` and `above` settled in plan order.
    fn walked(seed: u64, len: u64, reached: u64, watermark: u64, above: Vec<u64>) -> Checkpoint {
        Checkpoint {
            walked: Some(Walked {
                seed,
                len,
                reached,
                ahead: 0,
            }),
            ..Checkpoint::new(watermark, above)
        }
    }

    /// A scan resumed part way is read host by host, and one nearly done along its tail.
    /// Half way through a `/8` on a thousand ports the tail is eight billion positions, while
    /// host by host it is about two questions for each of sixteen million hosts. Near the end
    /// the tail is the short read. A sweep, whose hosts are its positions, reads whichever part
    /// is left.
    #[test]
    fn a_resume_reads_whichever_of_the_hosts_and_the_tail_is_shorter() {
        let hosts: u64 = 1 << 24;
        let plan = hosts * 1_000;

        assert!(!reads_the_tail(plan / 2, hosts, plan), "half way");
        assert!(!reads_the_tail(plan / 16, hosts, plan), "a sixteenth left");
        assert!(
            reads_the_tail(plan / 64, hosts, plan),
            "a sixty-fourth left"
        );
        assert!(reads_the_tail(plan / 10_000, hosts, plan), "nearly done");

        assert!(reads_the_tail(hosts / 2, hosts, hosts), "a sweep half way");
        assert!(
            !reads_the_tail(1, MARKED_AT_MOST + 1, MARKED_AT_MOST + 1),
            "more hosts than a bitmap is kept for"
        );
    }

    /// Half way through a `/16` on 1,024 ports every host still has a target left, and
    /// the answer comes back without reading the tail's 33 million positions.
    #[test]
    fn a_wide_port_scan_resumed_half_way_sweeps_every_host() {
        let map = plan("198.51.0.0/16", "1-1024");
        let index = TargetIndex::of(&map);
        let len = index.total();

        let remaining = walked(0x5EED, len, len / 2, 0, Vec::new()).remaining_hosts(&index);

        assert_eq!(remaining, addresses("198.51.0.0/16"));
    }

    /// A port scan whose first sitting settled everything has no host left to sweep.
    #[test]
    fn a_finished_port_scan_resumes_with_no_host_to_sweep() {
        let map = ports_plan();
        let index = TargetIndex::of(&map);
        let finished = Checkpoint::new(index.total(), []);

        assert!(finished.remaining_hosts(&index).is_empty());
    }

    /// A unit the numbering cannot reach is swept whole, since none of it can have been
    /// settled.
    #[test]
    fn a_port_scan_of_an_unnumberable_plan_sweeps_all_of_that_part() {
        let mut map = plan("192.0.2.1", "22");
        map.add_unit(TargetSet::new(
            addresses("2001:db8::/64"),
            "80".parse::<PortSet>().expect("ports"),
        ));
        let index = TargetIndex::of(&map);

        let remaining = Checkpoint::new(1, []).remaining_hosts(&index);

        assert_eq!(remaining, addresses("2001:db8::/64"));
    }

    proptest::proptest! {
        /// Whatever a walk reached, the hosts a resumed sitting sweeps are exactly the
        /// addresses of the targets it still probes, along the tail late in the walk and host by
        /// host early. A walk shorter than the plan (a damaged file) leaves the rest to the list.
        #[test]
        fn the_hosts_swept_after_a_walk_are_the_addresses_of_what_is_left(
            seed in proptest::prelude::any::<u64>(),
            reached in 0u64..=72,
            short in 0u64..4,
            watermark in 0u64..70,
            above in proptest::collection::vec(0u64..72, 0..24),
        ) {
            let map = ports_plan();
            let index = TargetIndex::of(&map);
            let len = index.total() - short;
            let checkpoint = walked(seed, len, reached.min(len), watermark, above);

            proptest::prop_assert_eq!(
                checkpoint.remaining_hosts(&index),
                hosts_of_remaining(&checkpoint, &map)
            );
        }

        /// Whatever an earlier sitting settled, the hosts a resumed sitting sweeps are
        /// exactly the addresses of the targets it still probes. Positions past the plan are
        /// included, as a checkpoint read from a file can hold them.
        #[test]
        fn the_hosts_swept_are_the_addresses_of_what_is_left(
            watermark in 0u64..70,
            above in proptest::collection::vec(0u64..72, 0..24),
        ) {
            let map = ports_plan();
            let index = TargetIndex::of(&map);
            let checkpoint = Checkpoint::new(watermark, above);

            proptest::prop_assert_eq!(
                checkpoint.remaining_hosts(&index),
                hosts_of_remaining(&checkpoint, &map)
            );
        }
    }

    use crate::model::ip::set::IpSet;
    use crate::model::port::PortSet;
    use crate::model::target::{TargetMap, TargetSet};

    fn plan(range: &str, ports: &str) -> TargetMap {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(
            range.parse::<IpSet>().expect("a range"),
            ports.parse::<PortSet>().expect("ports"),
        ));
        map
    }

    /// Settling in order: the watermark follows and nothing is held.
    #[test]
    fn settling_in_order_leaves_nothing_pending() {
        let mut cursor = Cursor::new();

        for position in 0..10 {
            cursor.settle(position);
            assert_eq!(cursor.watermark(), position + 1);
            assert_eq!(cursor.pending_count(), 0, "nothing should be held");
        }
    }

    /// One unsettled position stalls the watermark however much settles above it.
    /// Otherwise a resumed scan would skip a target nobody probed.
    #[test]
    fn one_unsettled_position_stalls_the_watermark() {
        let mut cursor = Cursor::new();

        cursor.settle(0);
        cursor.settle(1);
        // 2 is still outstanding: a tarpit, or a probe mid-retry.
        for position in 3..1_000 {
            cursor.settle(position);
        }

        assert_eq!(cursor.watermark(), 2, "the gap at 2 must hold the line");
        assert!(!cursor.is_settled(2));
        assert_eq!(cursor.settled_count(), 999);

        // It collapses when the gap fills.
        cursor.settle(2);
        assert_eq!(cursor.watermark(), 1_000);
        assert_eq!(cursor.pending_count(), 0);
    }

    /// Counted along the walk, a shuffled scan holds only what is in flight; counted in
    /// plan order alone, the set is most of what has settled. Both halves are asserted, so the
    /// order is shown to be the reason.
    #[test]
    fn a_shuffled_walk_holds_only_what_is_in_flight_when_counted_along_it() {
        const PLAN: u64 = 4_096;
        let order = Permutation::new(7, PLAN);
        let asked: Vec<u64> = order.iter().collect();

        let mut in_plan_order = Cursor::new();
        let mut along = Cursor::walking(order);
        for window in asked.chunks(16) {
            // Answers come back out of order within what is in flight.
            for position in window.iter().rev() {
                in_plan_order.settle(*position);
                along.settle(*position);
            }
            assert!(along.pending_count() < 16, "{}", along.pending_count());
            if along.settled_count() == PLAN / 2 {
                assert!(
                    in_plan_order.pending_count() as u64 > PLAN * 2 / 5,
                    "halfway, {} settled positions wait above a watermark of {}",
                    in_plan_order.pending_count(),
                    in_plan_order.watermark()
                );
            }
        }

        for cursor in [&in_plan_order, &along] {
            assert_eq!(cursor.settled_count(), PLAN);
            assert_eq!(cursor.pending_count(), 0);
            assert!((0..PLAN).all(|position| cursor.is_settled(position)));
        }
    }

    /// A cursor counting along a walk still follows a phase that settles in plan order.
    #[test]
    fn a_walked_cursor_settled_in_plan_order_holds_nothing_either() {
        let mut cursor = Cursor::walking(Permutation::new(7, 1_000));
        for position in 0..1_000 {
            cursor.settle(position);
            assert_eq!(cursor.pending_count(), 0, "at {position}");
        }
        assert_eq!(cursor.settled_count(), 1_000);
        assert_eq!(cursor.watermark(), 1_000);
    }

    proptest::proptest! {
        /// Whatever order positions settle in, the two watermarks and the set between them
        /// name exactly what settled, count it once, and say the same after a round trip through a
        /// checkpoint. A position named that did not settle is a target a resume skips unasked.
        #[test]
        fn two_watermarks_name_exactly_what_settled(
            seed in proptest::prelude::any::<u64>(),
            len in 1u64..300,
            settled in proptest::collection::vec(0u64..320, 0..400),
            walked_first in 0usize..300,
        ) {
            let order = Permutation::new(seed, len);
            let mut cursor = Cursor::walking(order);
            // Some of the walk in its own order, then the rest in any order, as a phase mixing
            // a dispatcher and a sweep would.
            let mut expected = BTreeSet::new();
            for position in order.iter().take(walked_first) {
                cursor.settle(position);
                expected.insert(position);
            }
            for position in settled {
                cursor.settle(position);
                expected.insert(position);
            }

            let checkpoint = cursor.checkpoint();
            let restored = Cursor::from_checkpoint(&checkpoint);
            for position in 0..330 {
                let want = expected.contains(&position);
                proptest::prop_assert_eq!(cursor.is_settled(position), want, "cursor, {}", position);
                proptest::prop_assert_eq!(checkpoint.is_settled(position), want, "checkpoint, {}", position);
                proptest::prop_assert_eq!(restored.is_settled(position), want, "restored, {}", position);
            }
            proptest::prop_assert_eq!(cursor.settled_count(), expected.len() as u64);
            proptest::prop_assert_eq!(checkpoint.settled_count(), expected.len() as u64);
            proptest::prop_assert_eq!(restored.settled_count(), expected.len() as u64);

            // A resume asks about exactly the rest.
            let total = len + 10;
            let spans: Vec<u64> = checkpoint
                .unsettled_spans(total)
                .into_iter()
                .flatten()
                .collect();
            let rest: Vec<u64> = (0..total).filter(|p| !expected.contains(p)).collect();
            proptest::prop_assert_eq!(spans, rest);
        }
    }

    /// A walk attached to a cursor resumed from a walkless checkpoint keeps everything
    /// that checkpoint settled.
    #[test]
    fn a_walk_joins_a_cursor_resumed_without_one() {
        let order = Permutation::new(11, 64);
        let earlier: Vec<u64> = order.iter().take(40).collect();
        let checkpoint = Checkpoint::new(0, earlier.iter().copied());

        let cursor = Cursor::from_checkpoint(&checkpoint).along(order);

        assert_eq!(cursor.pending_count(), 0, "the walk reached all of it");
        assert_eq!(cursor.settled_count(), 40);
        assert!(earlier.iter().all(|position| cursor.is_settled(*position)));
    }

    /// An engine that predates the walk reads a checkpoint carrying one as having
    /// settled less than it did, never more.
    #[cfg(feature = "journal-format")]
    #[test]
    fn an_older_reader_takes_a_walked_checkpoint_for_less_than_it_settled() {
        #[derive(Deserialize)]
        struct Older {
            watermark: u64,
            #[serde(default)]
            settled_above: Vec<u64>,
        }

        let order = Permutation::new(3, 500);
        let mut cursor = Cursor::walking(order);
        for position in order.iter().take(300) {
            cursor.settle(position);
        }
        cursor.settle(order.at(310).expect("inside the walk"));

        let written = serde_json::to_string(&cursor.checkpoint()).expect("serializes");
        let older: Older = serde_json::from_str(&written).expect("an older reader reads it");
        let older = Checkpoint::new(older.watermark, older.settled_above);

        assert!(older.settled_count() < cursor.settled_count());
        for position in 0..500 {
            assert!(
                !older.is_settled(position) || cursor.is_settled(position),
                "position {position} read as settled when it was not"
            );
        }
    }

    /// A seeded scan settles out of order, so the watermark is correct whatever order
    /// positions arrive in.
    #[test]
    fn the_watermark_is_independent_of_arrival_order() {
        let forwards = {
            let mut cursor = Cursor::new();
            for position in 0..64 {
                cursor.settle(position);
            }
            cursor
        };

        let backwards = {
            let mut cursor = Cursor::new();
            for position in (0..64).rev() {
                cursor.settle(position);
            }
            cursor
        };

        let scattered = {
            let mut cursor = Cursor::new();
            for position in [7, 3, 63, 0, 1, 2, 4, 5, 6] {
                cursor.settle(position);
            }
            for position in 8..63 {
                cursor.settle(position);
            }
            cursor
        };

        assert_eq!(forwards.watermark(), 64);
        assert_eq!(backwards.watermark(), 64);
        assert_eq!(scattered.watermark(), 64);
        assert_eq!(forwards, backwards);
        assert_eq!(forwards, scattered);
    }

    /// A target reported twice does not move the watermark twice.
    #[test]
    fn settling_the_same_position_twice_is_idempotent() {
        let mut cursor = Cursor::new();

        cursor.settle(0);
        cursor.settle(0);
        cursor.settle(0);
        assert_eq!(cursor.watermark(), 1);

        cursor.settle(5);
        cursor.settle(5);
        assert_eq!(cursor.pending_count(), 1);
        assert_eq!(cursor.settled_count(), 2);
    }

    /// A checkpoint round-trips through the cursor without moving.
    #[test]
    fn a_cursor_survives_a_checkpoint() {
        let mut cursor = Cursor::new();
        for position in [0, 1, 2, 9, 11, 12] {
            cursor.settle(position);
        }

        let restored = Cursor::from_checkpoint(&cursor.checkpoint());

        assert_eq!(restored, cursor);
        assert_eq!(restored.watermark(), 3);
        assert!(restored.is_settled(9));
        assert!(!restored.is_settled(3));
    }

    /// A resumed scan asks about exactly what the first sitting did not settle, in the
    /// plan's own order.
    #[test]
    fn remaining_yields_only_what_was_not_settled() {
        let map = plan("192.0.2.1-192.0.2.4", "80,443");
        let all: Vec<Target> = map.iter().collect();
        assert_eq!(all.len(), 8, "four addresses on two ports");

        let mut cursor = Cursor::new();
        for position in [0, 1, 2, 5] {
            cursor.settle(position);
        }

        let remaining: Vec<PlannedTarget> = cursor.checkpoint().remaining(map.iter()).collect();

        // The remaining targets still carry their positions in the whole plan.
        assert_eq!(
            remaining,
            vec![
                PlannedTarget::new(3, all[3]),
                PlannedTarget::new(4, all[4]),
                PlannedTarget::new(6, all[6]),
                PlannedTarget::new(7, all[7]),
            ]
        );
    }

    /// A checkpoint that settled nothing re-asks the whole plan, and one that settled
    /// everything asks nothing.
    #[test]
    fn the_empty_and_complete_cases_are_both_exact() {
        let map = plan("192.0.2.1-192.0.2.4", "80,443");
        let total = map.iter().count();

        let untouched = Cursor::new().checkpoint();
        assert_eq!(untouched.remaining(map.iter()).count(), total);

        let mut finished = Cursor::new();
        for position in 0..total as u64 {
            finished.settle(position);
        }
        assert_eq!(finished.checkpoint().remaining(map.iter()).count(), 0);
        assert_eq!(finished.watermark(), total as u64);
    }

    /// The cursor numbers targets by the same walk the dispatcher probes them by. The
    /// two live in different modules, and a divergence would resume a scan that skips the wrong
    /// targets.
    #[test]
    fn positions_follow_the_plans_own_enumeration() {
        let mut map = plan("192.0.2.1-192.0.2.2", "80,443");
        map.add_unit(TargetSet::new(
            "198.51.100.7".parse::<IpSet>().expect("a range"),
            "22".parse::<PortSet>().expect("ports"),
        ));

        let once: Vec<Target> = map.iter().collect();
        let twice: Vec<Target> = map.iter().collect();

        assert_eq!(once, twice, "the enumeration must be reproducible");
        assert_eq!(once.len(), 5, "two units, four targets then one");
        assert_eq!(
            once[4].ip,
            "198.51.100.7".parse::<std::net::IpAddr>().unwrap(),
            "units are walked in the order they were added"
        );
    }

    /// The checkpoint reaches disk whole, comes back identical, and replacing it leaves
    /// no temporary file.
    #[cfg(feature = "journal-format")]
    #[test]
    fn a_checkpoint_round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!(
            "zond-cursor-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        let path = dir.join("cursor.json");

        let mut cursor = Cursor::new();
        for position in [0, 1, 2, 9, 11, 12] {
            cursor.settle(position);
        }

        cursor.checkpoint().write_atomically(&path).expect("writes");
        assert_eq!(Checkpoint::read(&path).expect("reads"), cursor.checkpoint());

        // Written again over itself, as every checkpoint after the first is.
        cursor.settle(3);
        cursor
            .checkpoint()
            .write_atomically(&path)
            .expect("rewrites");

        let reread = Checkpoint::read(&path).expect("rereads");
        assert_eq!(reread.watermark, 4);
        assert!(
            !dir.join("cursor.tmp").exists(),
            "the temporary file must not survive the rename"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `is_settled` binary-searches, so the reader sorts a list that arrived unsorted.
    #[cfg(feature = "journal-format")]
    #[test]
    fn a_checkpoint_with_an_unsorted_list_is_sorted_on_read() {
        let dir = std::env::temp_dir().join(format!(
            "zond-cursor-unsorted-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        let path = dir.join("cursor.json");

        std::fs::write(&path, r#"{"watermark":2,"settled_above":[9,4,7,4]}"#).expect("writes");

        let checkpoint = Checkpoint::read(&path).expect("reads");

        assert_eq!(
            checkpoint.settled_above,
            vec![4, 7, 9],
            "sorted and deduped"
        );
        for position in [4, 7, 9] {
            assert!(checkpoint.is_settled(position), "{position} is in the file");
        }
        assert!(!checkpoint.is_settled(3));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A checkpoint naming positions below its own watermark normalises without
    /// double-counting.
    #[test]
    fn a_checkpoint_with_redundant_positions_normalises() {
        let checkpoint = Checkpoint {
            watermark: 5,
            settled_above: vec![1, 2, 5, 6],
            walked: None,
        };

        let cursor = Cursor::from_checkpoint(&checkpoint);

        assert_eq!(cursor.watermark(), 7, "5 and 6 are contiguous with 5");
        assert_eq!(cursor.pending_count(), 0);
        assert_eq!(cursor.settled_count(), 7);
    }
}
