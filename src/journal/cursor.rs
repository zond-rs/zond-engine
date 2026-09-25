// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How far a scan got
//!
//! A position in the plan below which everything is settled, and the positions
//! above it that settled out of order.
//!
//! ## A position needs nothing stored to name it
//!
//! [`TargetMap::iter`](crate::model::target::TargetMap::iter) walks its units in
//! order and each unit's addresses against its ports, and a
//! [`TargetSet`](crate::model::target::TargetSet) is canonical and immutable from
//! construction. So the same plan yields the same targets in the same order on
//! every run, and the nth target is a stable identity that costs nothing to
//! record.
//!
//! That is what makes a checkpoint of a plan walked in order affordable. The
//! cursor holds one integer and the positions settled above it, not a list of
//! addresses, so its size is a property of how far out of order the scan settled
//! rather than of how large the scan is. How far that is depends on the order
//! the targets are asked in, which the next section weighs.
//!
//! This enumeration is load-bearing. The dispatcher decides what to probe by it
//! and this decides what was probed by it, so the two have to be one numbering.
//! The order the targets are asked in is a different question and is nobody's
//! business here: a scan given a seed walks a
//! [`Permutation`] of the whole index space
//! and numbers what comes out by where the plan holds it, which it reads through
//! [`TargetIndex`]. That the index and this walk agree at every position is
//! `model`'s own test, `a_position_names_the_target_the_plans_own_walk_numbers_it`,
//! and it is what keeps the two from being two numberings.
//!
//! ## The watermark chases the settled set
//!
//! [`Cursor::settle`] records a position and then advances the watermark over
//! every consecutive settled position above it. Anything that settles out of
//! order waits in [`above`](Cursor::settled_above) until the gap below it fills.
//!
//! The set holds only what the watermark has not caught up to, with no window to
//! size and no eviction policy to get wrong. How much that is depends on the
//! order the plan is walked in.
//!
//! Walked in plan order, it is bounded by how far the dispatcher runs ahead of
//! the slowest outstanding probe. A single tarpitting host stalls the watermark
//! and the set grows to the pipeline depth, then collapses the moment that host
//! settles.
//!
//! Walked in a seeded [`Permutation`], which
//! is how every scan the engine starts walks it, the positions settled so far
//! are scattered across the whole plan, and a watermark counted in plan order
//! stays near zero until nearly all of them are in. Held that way, the set would
//! be half the plan at the halfway mark, in memory and in every checkpoint.
//!
//! ## So there are two watermarks
//!
//! One counted in plan order, and one counted in the order the scan asks in: a
//! [`Walk`](Walked) says that every position the permutation names before a
//! given index is settled. A position is settled if either watermark has passed
//! it or it waits in the set, and the set holds only what neither has reached.
//!
//! Whichever order a phase actually settles in, one of the two follows it. A
//! port scan's dispatcher walks the permutation, so the walk watermark chases
//! its answers and the set stays the size of the pipeline, however large the
//! plan. A link-layer sweep asks its segment in address order, so the plan
//! watermark does. A phase mixing the two holds, beyond the pipeline, roughly
//! the part of the plan the slower order has yet to reach.
//!
//! The walk is recorded beside the positions, seed and length, rather than
//! looked up in the manifest, so a checkpoint says on its own which targets it
//! accounts for. A position is still a position in the plan: the walk is only a
//! compact way of naming a great many of them.
//!
//! A checkpoint written this way is read by an engine that predates the walk as
//! one that settled only what the plan watermark and the set name. That engine
//! asks again about what the walk had covered, which costs probes and skips
//! nothing. So a newer file is safe in an older reader rather than readable by
//! it, and no format version is spent on the difference.
//!
//! ## Only settled positions are recorded
//!
//! A position reaches here only from [`Outcome`](super::settle::Outcome)'s
//! settled variants, the only ones that carry one. A target that was interrupted,
//! never asked or never routed has no position to offer, so the watermark stalls
//! behind it and the next sitting asks again.

use std::collections::BTreeSet;
use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::model::ip::set::{IpSet, Positions};
use crate::model::order::Permutation;
use crate::model::target::{PlannedTarget, Target, TargetIndex};

/// How far a scan has got, maintained as it runs.
///
/// Cheap to update. A snapshot costs what neither watermark has reached, which
/// the module documentation weighs for the orders a scan walks in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cursor {
    watermark: u64,
    above: BTreeSet<u64>,
    walk: Option<Walked>,
}

impl Cursor {
    /// A cursor over a plan nothing has been settled in yet, counted in plan
    /// order alone.
    pub fn new() -> Self {
        Self::default()
    }

    /// A cursor over a plan nothing has been settled in yet, that also counts
    /// along `order`, the order the scan asks its targets in.
    ///
    /// What that buys is the module documentation's subject: settled in the
    /// order it is asked in, a plan of any size holds a pipeline's worth of
    /// positions rather than most of what has settled.
    pub fn walking(order: Permutation) -> Self {
        Self::new().along(order)
    }

    /// Resumes from a checkpoint, along the walk it recorded if it recorded
    /// one.
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
        // A checkpoint written by a newer build, or edited by hand, may name
        // positions that are already contiguous with a watermark. Normalising
        // here means the invariant below holds however the values arrived.
        cursor.catch_up();
        cursor
    }

    /// Counts along `order` as well, for a cursor that does not yet count
    /// along any walk: one resumed from a checkpoint written before the scan
    /// was walked, or by a sitting that was not.
    ///
    /// A cursor already counting along a walk keeps it. The walk it has is the
    /// one its positions were recorded against, and a scan resumed under the
    /// same manifest asks in that order anyway.
    pub(crate) fn along(mut self, order: Permutation) -> Self {
        if self.walk.is_none() {
            self.walk = Some(Walked::start(order));
            self.catch_up();
        }
        self
    }

    /// Records that the target at `position` is settled.
    ///
    /// Idempotent: settling a position either watermark has passed, or one
    /// already recorded, changes nothing. A target can be reported twice, by a
    /// probe retired on its retry budget and then again by a stop path that
    /// does not know it already had a verdict.
    pub fn settle(&mut self, position: u64) {
        if self.is_settled(position) {
            return;
        }

        self.above.insert(position);
        self.catch_up();
    }

    /// Advances both watermarks over every settled position they can reach.
    ///
    /// Each can let the other go further: a position the walk passed may be the
    /// one the plan watermark was waiting on, and the other way about. So the
    /// two take turns until the walk stops, which is when neither can move: the
    /// plan's turn before it already saw everything the walk had reached.
    ///
    /// Saturating, because the positions come out of a cursor file this process
    /// may not have written. A planted `u64::MAX` reaches the increment, and an
    /// unchecked one panics in a debug build and wraps to zero in a release
    /// one, which silently un-settles every target the scan had finished.
    /// Saturating wedges the watermark at the ceiling instead, which is wrong
    /// in the safe direction: a resume re-probes rather than skips.
    fn catch_up(&mut self) {
        let Self {
            watermark,
            above,
            walk,
        } = self;

        loop {
            loop {
                if above.remove(watermark) {
                    // Counted in the set until now, and by the watermark from
                    // here on.
                } else if let Some(walk) = walk.as_mut()
                    && walk.covers(*watermark)
                {
                    // Counted as ahead of the watermark when the walk passed
                    // it, and by the watermark from here on.
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

    /// The position below which every target is settled, counted in plan
    /// order.
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
    /// Saturating for the same reason the watermark's own advance is: the
    /// watermark can come from a file this process did not write, and a count
    /// that wrapped would report a nearly-finished scan as barely started.
    pub fn settled_count(&self) -> u64 {
        self.watermark
            .saturating_add(self.walk.map_or(0, |walk| walk.ahead))
            .saturating_add(self.above.len() as u64)
    }

    /// How many settled positions are waiting on a gap below them in both
    /// orders.
    ///
    /// The size of the out-of-order window, and so the size of a checkpoint.
    /// Worth watching: settled in either order the scan counts in, a number
    /// that grows and does not fall is a target that never settles, which is a
    /// tarpit or a defect rather than a slow network.
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
/// index `reached` is settled. The walk is written down whole, rather than
/// taken from the manifest's seed, so a checkpoint says on its own which
/// positions it accounts for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Walked {
    /// The key of the order walked.
    pub seed: u64,
    /// How many positions it rearranges, which is the plan's total.
    pub len: u64,
    /// How many of its positions, in the order it names them, are settled.
    pub reached: u64,
    /// How many of those are at or past the plan watermark.
    ///
    /// Counted so a total can be read without walking: the rest of what the
    /// walk reached is below the watermark and already counted there. A count
    /// and nothing more. What a resume skips is decided by `reached` and never
    /// by this.
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

    /// Held to what the numbers can mean, for one read from a file: no more
    /// reached than the walk holds, and no more ahead than was reached or than
    /// the plan has past `watermark`.
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
/// Two watermarks and the positions neither has reached, each named. Settled in
/// either order the scan counts in, that is a handful of positions however
/// large the plan; see the module documentation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// The position below which everything is settled.
    pub watermark: u64,
    /// Settled positions at or above the watermark that the walk has not
    /// reached, ascending.
    ///
    /// Ascending is an invariant, not a description: [`is_settled`](Self::is_settled)
    /// binary-searches it. [`new`](Self::new) establishes it, and [`read`](Self::read)
    /// re-establishes it on anything that arrived from a file.
    #[serde(default)]
    pub settled_above: Vec<u64>,
    /// How far along the order the scan asks in everything is settled, for a
    /// scan that counted along one.
    ///
    /// Absent from a checkpoint written by a scan that was not walked, or by an
    /// engine that predates the walk. An engine that predates it reads a
    /// checkpoint carrying one as having settled less than it did, which costs
    /// probes and skips nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub walked: Option<Walked>,
}

impl Checkpoint {
    /// A checkpoint over `watermark` and the settled positions above it.
    ///
    /// The list is sorted and deduplicated here, which is the invariant
    /// [`is_settled`](Self::is_settled) binary-searches on. The fields are public
    /// and this is not the only way to build one, but it is the way that cannot be
    /// built wrong, and a caller keeping journals in something other than a
    /// directory should come through it.
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
    /// Binary-searched, so [`settled_above`](Self::settled_above) has to be
    /// ascending. Everything in this module that builds one keeps it that way,
    /// and [`new`](Self::new) is how a caller does.
    pub fn is_settled(&self, position: u64) -> bool {
        position < self.watermark
            || self.settled_above.binary_search(&position).is_ok()
            || self.walked.is_some_and(|walked| walked.covers(position))
    }

    /// How many targets are settled in total.
    ///
    /// Read without walking anything: the watermark, what the walk counted
    /// past it, and the positions neither reached. A position the list names
    /// that a watermark has passed is counted once, by the watermark, which is
    /// the reading [`Cursor::from_checkpoint`] gives the same file.
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
    /// The sweep counterpart of [`remaining`](Self::remaining). It gives back a
    /// set rather than a positioned stream because a
    /// [`HostScanner`](crate::scanner::strategy::HostScanner) owns its targets and
    /// is aimed at them, and its positions come from the context. See
    /// [`ScanContext::settle_address`](crate::scanner::session::ScanContext::settle_address),
    /// which numbers an address against this same plan.
    ///
    /// Computed from the ranges, so continuing a sweep of a `/8` costs what
    /// continuing a sweep of a `/24` does, for a sweep that settled in order.
    /// Everything below the watermark is one span to drop; above it, the
    /// positions that settled out of order are taken out individually, which
    /// for a shuffled sweep is most of what it settled. Anything the plan was
    /// too large to number comes back whole, since no checkpoint can have
    /// accounted for it.
    ///
    /// `positions` has to number the plan this checkpoint was written against. A
    /// position is an index into one enumeration, and the manifest's plan
    /// fingerprint is what refuses a resume before it reaches here.
    pub fn remaining_addresses(&self, positions: &Positions) -> IpSet {
        let mut remaining = IpSet::new();

        for span in self.unsettled_spans(positions.total()) {
            for range in positions.ranges_in(span) {
                remaining.insert_range(range);
            }
        }

        // A range too large to number holds no position, so nothing can ever
        // have been recorded against it. Every sitting asks about it again.
        for range in positions.unnumbered() {
            remaining.insert_range(*range);
        }

        remaining.canonicalize();
        remaining
    }

    /// The addresses a resumed port scan still has a target at.
    ///
    /// The port-plan counterpart of
    /// [`remaining_addresses`](Self::remaining_addresses), for the passes beside
    /// a port scan that ask about hosts rather than ports: the sweep that finds
    /// which of them are there, and the one that reads their hardware addresses
    /// and round trips. An address whose every target an earlier sitting settled
    /// has nothing left to be asked, and sweeping it again puts the network a
    /// question the job already put, which is what a resume exists not to do.
    ///
    /// An address with any target outstanding comes back whole. This sitting
    /// probes it, and whether the host is there is a property of the network on
    /// the day, so the answer that gates those probes is one the sitting has to
    /// establish for itself rather than inherit.
    ///
    /// `index` has to number the plan this checkpoint was written against, as
    /// for [`remaining`](Self::remaining). Every address of a unit the index
    /// could not number comes back, since no position names a target there and
    /// so none can have been settled.
    pub(crate) fn remaining_hosts(&self, index: &TargetIndex) -> IpSet {
        let mut remaining = IpSet::new();

        for span in self.unsettled_spans(index.total()) {
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

    /// The stretches of `0..total` this checkpoint leaves unsettled, ascending
    /// and never empty.
    ///
    /// Everything below the watermark is settled, and above it only the
    /// positions that settled out of order are, so the stretches are the gaps
    /// between those: one more span than there are such positions.
    fn unsettled_spans(&self, total: u64) -> Vec<Range<u64>> {
        match self.walked {
            Some(walked) => self.unwalked_spans(walked.clamped(self.watermark), total),
            None => self.spans_between(total),
        }
    }

    /// The unsettled stretches of a checkpoint counted along a walk.
    ///
    /// What the walk has not reached is scattered across the plan, so this
    /// costs what is left rather than what the list holds, read whichever way
    /// is shorter. Early in a scan that is the plan past the watermark, each
    /// position asked whether the walk passed it. Late in one it is the walk's
    /// own tail, which names exactly the positions it has yet to reach.
    fn unwalked_spans(&self, walked: Walked, total: u64) -> Vec<Range<u64>> {
        let past_watermark = total.saturating_sub(self.watermark);
        let tail = walked.len - walked.reached;

        let mut spans: Vec<Range<u64>> = Vec::new();
        let mut extend = |position: u64| match spans.last_mut() {
            Some(span) if span.end == position => span.end += 1,
            _ => spans.push(position..position + 1),
        };

        if past_watermark <= tail {
            for position in self.watermark..total {
                if !self.is_settled(position) {
                    extend(position);
                }
            }
            return spans;
        }

        let mut left: Vec<u64> = walked
            .order()
            .iter_from(walked.reached)
            .filter(|position| *position >= self.watermark && *position < total)
            .filter(|position| self.settled_above.binary_search(position).is_err())
            .collect();
        left.sort_unstable();
        for position in left {
            extend(position);
        }
        // A plan longer than the walk, which only a damaged file describes:
        // the walk names nothing past its end, so only the list can have
        // settled any of it.
        spans.extend(self.gaps_from(walked.len.max(self.watermark), total));
        spans
    }

    /// The unsettled stretches of a checkpoint counted in plan order alone:
    /// the gaps between the positions the list names.
    fn spans_between(&self, total: u64) -> Vec<Range<u64>> {
        self.gaps_from(self.watermark, total)
    }

    /// The gaps between the positions the list names, from `from` to `total`.
    fn gaps_from(&self, from: u64, total: u64) -> Vec<Range<u64>> {
        // `settled_above` is written ascending, and a checkpoint from disk is
        // only as ordered as the file said. Sorting a copy is linear in an
        // already sorted list and makes the walk below right either way.
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
    /// [`TargetMap::iter`](crate::model::target::TargetMap::iter), the same walk
    /// the first sitting was numbered by, and yields only what
    /// this checkpoint does not account for.
    ///
    /// The positions are why this yields [`PlannedTarget`] rather than
    /// [`Target`]. A resumed sitting scans a subset, so numbering it afresh would
    /// give position 0 to whatever happens to be left and the two sittings'
    /// cursors would count different things. The original numbering has to
    /// survive the filtering.
    ///
    /// The plan has to be the one this checkpoint was written against. A
    /// position is an index into a specific enumeration, so a changed port list,
    /// a changed exclusion policy or a changed privilege level all move what
    /// position 4,001,927 refers to. Nothing here detects that; the manifest's
    /// plan fingerprint refuses the resume before it gets this far.
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

#[cfg(feature = "journal-format")]
mod persistence {
    use std::fs;
    use std::io::Write;
    use std::path::Path;

    use super::Checkpoint;
    use crate::journal::file::create_staged;
    use crate::journal::format::JournalError;

    impl Checkpoint {
        /// Writes the checkpoint so that a process killed mid-write leaves the
        /// previous one intact.
        ///
        /// Writes a sibling temporary file and renames it over the destination,
        /// which is atomic on every filesystem this engine runs on. No `fsync`:
        /// the failures this exists for, `^C` and a dropped session and an OOM
        /// kill, are process deaths, and the page cache outlives the process. A
        /// flush per checkpoint would buy protection against machine power loss
        /// alone, at a cost on every scan that survives without it. See
        /// [`journal`](crate::journal) for what that policy promises.
        ///
        /// A torn write is impossible rather than tolerated. The destination only
        /// changes by rename, so a reader sees the whole of one checkpoint or the
        /// whole of the one before it.
        pub fn write_atomically(&self, path: &Path) -> Result<(), JournalError> {
            let temporary = path.with_extension("tmp");

            // Scoped so the handle is closed before the rename. Renaming over a
            // file still held open is a hazard on platforms this may yet reach.
            {
                let mut file = create_staged(&temporary)?;
                file.write_all(serde_json::to_string(self)?.as_bytes())?;
            }

            // The destination becomes the temporary's inode, which already
            // carries the mode and the ownership `create_staged` gave it.
            fs::rename(&temporary, path)?;
            Ok(())
        }

        /// Reads a checkpoint back.
        ///
        /// The `settled_above` list is sorted on read rather than trusted, since
        /// [`is_settled`](Checkpoint::is_settled) binary-searches it and an
        /// unsorted list would answer `false` for a position that is present. That
        /// re-probes a settled target, which is safe and quietly wrong.
        pub fn read(path: &Path) -> Result<Self, JournalError> {
            let text = super::super::store::read_bounded(path, "a journal cursor")?;
            let mut checkpoint: Self = serde_json::from_str(&text)?;
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

    /// What a resumed sweep asks about must be exactly what the first sitting
    /// did not settle. One address too few is a target silently skipped, which
    /// is the failure this whole module exists to prevent.
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

    /// A sweep that settled nothing comes back whole. A resume that quietly
    /// narrowed an untouched plan would lose the whole first sitting's ground.
    #[test]
    fn a_sweep_that_settled_nothing_resumes_over_the_whole_plan() {
        let plan = addresses("192.0.2.1-192.0.2.10,2001:db8::1-2001:db8::4");
        let remaining = Checkpoint::default().remaining_addresses(&plan.positions());

        assert_eq!(remaining, plan);
    }

    /// A plan holding a range too large to number comes back whole, however far
    /// the numbered part of it got. Anything else resumes a sweep of an IPv6
    /// subnet by asking about nothing and reporting that it finished.
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

    /// And a sweep that settled everything has nothing left to ask.
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

    /// The two halves have to agree: whatever a resumed sweep is aimed at, the
    /// positions it settles are still the original plan's. An address in the
    /// narrowed set must number the same as it did in the first sitting.
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

    /// A checkpoint read back from a file is only as ordered as the file said.
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

    /// Several units, both families, and port counts that divide nothing, so
    /// that an address's ports straddle every kind of boundary a span can end
    /// on.
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

    /// The addresses of what [`Checkpoint::remaining`] still yields, which is
    /// what `remaining_hosts` has to agree with.
    fn hosts_of_remaining(checkpoint: &Checkpoint, map: &TargetMap) -> IpSet {
        let mut hosts = IpSet::new();
        for planned in checkpoint.remaining(map.iter()) {
            hosts.insert(planned.ip());
        }
        hosts.canonicalize();
        hosts
    }

    /// An address with a target left is swept, and one whose every target
    /// settled is not, whichever way the settling fell across its ports.
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

    /// A port scan whose first sitting settled everything has no host left to
    /// sweep, so a resumed sitting puts nothing on the wire beside its (empty)
    /// port scan.
    #[test]
    fn a_finished_port_scan_resumes_with_no_host_to_sweep() {
        let map = ports_plan();
        let index = TargetIndex::of(&map);
        let finished = Checkpoint::new(index.total(), []);

        assert!(finished.remaining_hosts(&index).is_empty());
    }

    /// A unit the numbering cannot reach is swept whole however far the rest
    /// got, since nothing about it can have been settled.
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
        /// Whatever an earlier sitting settled, the hosts a resumed sitting
        /// sweeps are exactly the addresses of the targets it still probes.
        ///
        /// One fewer is a host whose ports are probed without the answer that
        /// gates them; one more is a question the job already put. Positions
        /// past the plan are included, as a checkpoint read from a file can
        /// hold them.
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

    /// Settling in order is the ordinary case: the watermark simply follows and
    /// nothing is ever held.
    #[test]
    fn settling_in_order_leaves_nothing_pending() {
        let mut cursor = Cursor::new();

        for position in 0..10 {
            cursor.settle(position);
            assert_eq!(cursor.watermark(), position + 1);
            assert_eq!(cursor.pending_count(), 0, "nothing should be held");
        }
    }

    /// The property the whole design rests on: one unsettled position stalls the
    /// watermark however much settles above it.
    ///
    /// If this ever passes with a higher watermark, a resumed scan skips a
    /// target nobody probed.
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

        // And it collapses the moment the gap fills.
        cursor.settle(2);
        assert_eq!(cursor.watermark(), 1_000);
        assert_eq!(cursor.pending_count(), 0);
    }

    /// **Counted along the walk, a shuffled scan holds what is in flight.**
    /// Counted in plan order alone, the same answers wait above a watermark
    /// that barely moves, and the set is most of what has settled. Both halves
    /// are asserted, since the second is the cost the walk exists to remove and
    /// the first is what says the order is the reason.
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

    /// A cursor counting along a walk still follows a phase that settles in
    /// plan order, since the plan watermark is still there to chase it.
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
        /// Whatever order positions settle in, the two watermarks and the set
        /// between them name exactly what settled, count it once, and say the
        /// same after a round trip through a checkpoint.
        ///
        /// A position named that did not settle is a target a resume skips
        /// without asking, and one settled that is not named is asked twice.
        /// The first is the failure the whole module exists to prevent.
        #[test]
        fn two_watermarks_name_exactly_what_settled(
            seed in proptest::prelude::any::<u64>(),
            len in 1u64..300,
            settled in proptest::collection::vec(0u64..320, 0..400),
            walked_first in 0usize..300,
        ) {
            let order = Permutation::new(seed, len);
            let mut cursor = Cursor::walking(order);
            // Some of the walk in its own order, then the rest in any order,
            // as a phase mixing a dispatcher and a sweep would.
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

            // And a resume asks about exactly the rest.
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

    /// A walk attached to a cursor resumed from a checkpoint that had none
    /// takes in what that checkpoint already settled, and loses none of it.
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

    /// An engine that predates the walk reads a checkpoint carrying one as
    /// having settled less than it did, never more.
    ///
    /// Reading more would have it skip targets nobody asked about. Reading less
    /// costs it probes, which is why a newer checkpoint needs no new format
    /// version to be safe in an older reader.
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

    /// Out-of-order settling is the normal case, since a seeded scan walks a
    /// permutation of the whole plan, so the watermark has to be correct
    /// whatever order positions arrive in.
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

    /// A target may be reported twice. Neither report may move the watermark
    /// twice, or the cursor claims a position it never heard about.
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

    /// The payoff: a resumed scan asks about exactly what the first sitting did
    /// not settle, in the plan's own order.
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

        // The targets that were left, still carrying their positions in the
        // whole plan rather than in the remainder.
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

    /// A checkpoint that settled nothing must re-ask the whole plan, and one
    /// that settled everything must ask nothing. The two ends of the range,
    /// where an off-by-one would hide.
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

    /// The cursor numbers targets by the same walk the dispatcher probes them by.
    /// Asserted rather than assumed: the two live in different modules, and a
    /// divergence would resume a scan against positions that mean something else,
    /// which looks like a working resume that skips the wrong targets.
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

    /// The checkpoint reaches disk whole, comes back identical, and replacing it
    /// leaves one file rather than a temporary beside it.
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

    /// `is_settled` binary-searches, so a list that arrived unsorted would answer
    /// `false` for a position that is present. That re-probes, which is safe and
    /// silently wrong, so the reader sorts rather than trusting the file.
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

    /// A checkpoint naming positions below its own watermark is redundant rather
    /// than wrong, and must normalise instead of double-counting.
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
