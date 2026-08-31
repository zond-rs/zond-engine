// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How far a scan got
//!
//! A position in the plan below which everything is settled, and the handful of
//! positions above it that settled out of order.
//!
//! ## A position needs nothing stored to name it
//!
//! [`TargetMap::iter`](crate::model::target::TargetMap::iter) walks its units in
//! order and each unit's addresses against its ports, and a
//! [`TargetSet`](crate::model::target::TargetSet) is canonical and immutable
//! from construction. So the same plan yields the same targets in the same order
//! on every run, and the *n*th target is a stable identity that costs nothing to
//! record.
//!
//! That is the whole reason this is affordable. The cursor holds one integer and
//! a small set, not a list of addresses, so its size is a property of how far
//! out of order the scan settled rather than of how large the scan is. A `/8` on
//! a thousand ports checkpoints in the same handful of bytes a `/24` does.
//!
//! **This enumeration is load-bearing.** The dispatcher walks it to decide what
//! to probe and this walks it to decide what was probed, so the two must be one
//! walk — see `Dispatcher::run_shuffled`, which calls the same method for
//! exactly that reason. Shuffling does not affect it: the dispatcher permutes
//! within a batch, which changes the order targets are *asked* in and not the
//! order they are *numbered* in.
//!
//! ## The watermark chases the settled set
//!
//! [`Cursor::settle`] records a position and then advances the watermark over
//! every consecutive settled position above it. Anything that settles out of
//! order waits in [`above`](Cursor::settled_above) until the gap below it fills.
//!
//! The set therefore stays small on its own, with no window to size and no
//! eviction policy to get wrong: it holds only what the watermark has not caught
//! up to, which is bounded by how far the dispatcher runs ahead of the slowest
//! outstanding probe. A single tarpitting host stalls the watermark and the set
//! grows to the pipeline depth — a few tens of thousands of integers, not a few
//! million — and collapses the moment that host settles.
//!
//! ## Only settled positions are recorded
//!
//! A position reaches here only from [`Outcome`](super::settle::Outcome)'s
//! settled variants — the only ones that carry one. A target that was
//! interrupted, never asked, or never routed has no position to offer, so the
//! watermark stalls behind it and the next sitting asks again.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::model::ip::set::{IpSet, Positions};
use crate::model::target::{PlannedTarget, Target};

/// How far a scan has got, maintained as it runs.
///
/// Cheap to update and cheap to snapshot. See the module documentation for why
/// the set stays small without being bounded explicitly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cursor {
    watermark: u64,
    above: BTreeSet<u64>,
}

impl Cursor {
    /// A cursor over a plan nothing has been settled in yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resumes from a checkpoint.
    pub fn from_checkpoint(checkpoint: &Checkpoint) -> Self {
        let mut cursor = Self {
            watermark: checkpoint.watermark,
            above: checkpoint
                .settled_above
                .iter()
                .copied()
                .filter(|position| *position >= checkpoint.watermark)
                .collect(),
        };
        // A checkpoint written by a newer build, or edited by hand, may name
        // positions that are already contiguous with the watermark. Normalising
        // here means the invariant below holds however the values arrived.
        cursor.catch_up();
        cursor
    }

    /// Records that the target at `position` is settled.
    ///
    /// Idempotent: settling a position already below the watermark, or already
    /// recorded, changes nothing. That matters because a target can be reported
    /// twice — a probe retired by its retry budget and then swept again by a
    /// stop path that does not know it already had a verdict.
    pub fn settle(&mut self, position: u64) {
        if position < self.watermark {
            return;
        }

        self.above.insert(position);
        self.catch_up();
    }

    /// Advances the watermark over every consecutive settled position.
    fn catch_up(&mut self) {
        while self.above.remove(&self.watermark) {
            self.watermark += 1;
        }
    }

    /// The position below which every target is settled.
    ///
    /// A resume starts here, and skips the positions above it that
    /// [`is_settled`](Self::is_settled) names.
    pub fn watermark(&self) -> u64 {
        self.watermark
    }

    /// The settled positions the watermark has not reached, ascending.
    pub fn settled_above(&self) -> impl Iterator<Item = u64> + '_ {
        self.above.iter().copied()
    }

    /// Whether the target at `position` may be skipped.
    pub fn is_settled(&self, position: u64) -> bool {
        position < self.watermark || self.above.contains(&position)
    }

    /// How many targets are settled in total.
    pub fn settled_count(&self) -> u64 {
        self.watermark + self.above.len() as u64
    }

    /// How many settled positions are waiting on a gap below them.
    ///
    /// The size of the out-of-order window, and so the size of a checkpoint.
    /// Worth watching: a number that grows and does not fall is a target that
    /// never settles, which is a tarpit or a defect rather than a slow network.
    pub fn pending_count(&self) -> usize {
        self.above.len()
    }

    /// A snapshot to write to disk.
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            watermark: self.watermark,
            settled_above: self.above.iter().copied().collect(),
        }
    }
}

/// A cursor as it is written down.
///
/// Sparse rather than a bitmap over a fixed window. Both are bounded by the same
/// thing — how far the dispatcher runs ahead — and the sparse form is far
/// smaller in the case that actually occurs, where a handful of positions are
/// out of order rather than tens of thousands. A bitmap only wins where the
/// window is nearly full, which is the pathological case and not one worth
/// optimising the ordinary one for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// The position below which everything is settled.
    pub watermark: u64,
    /// Settled positions at or above the watermark, ascending.
    #[serde(default)]
    pub settled_above: Vec<u64>,
}

impl Checkpoint {
    /// Whether the target at `position` may be skipped.
    pub fn is_settled(&self, position: u64) -> bool {
        position < self.watermark || self.settled_above.binary_search(&position).is_ok()
    }

    /// The addresses a resumed sweep still has to ask about.
    ///
    /// The sweep counterpart of [`remaining`](Self::remaining), and it gives
    /// back a set rather than a positioned stream because a
    /// [`HostScanner`](crate::scanner::strategy::HostScanner) owns its targets
    /// and is aimed at them. Its positions come from the context instead — see
    /// [`ScanContext::settle_address`](crate::scanner::session::ScanContext::settle_address),
    /// which numbers an address against this same plan.
    ///
    /// Computed from the ranges, so continuing a sweep of a `/8` costs what
    /// continuing a sweep of a `/24` does. Everything below the watermark is one
    /// span to drop; above it, only the few positions that settled out of order
    /// are taken out individually. Anything the plan was too large to number
    /// comes back whole, since no checkpoint can have accounted for it.
    ///
    /// **`positions` must number the plan this checkpoint was written against.**
    /// A position is an index into one enumeration, and the manifest's plan
    /// fingerprint is what refuses a resume before it reaches here.
    pub fn remaining_addresses(&self, positions: &Positions) -> IpSet {
        let mut remaining = IpSet::new();
        let total = positions.total();
        let mut from = self.watermark;

        // `settled_above` is written ascending, and a checkpoint that arrived
        // from disk is only as ordered as the file said. Sorting a copy costs
        // nothing on the window-sized list this holds and makes the walk below
        // right either way.
        let mut above = self.settled_above.clone();
        above.sort_unstable();

        for settled in above {
            if settled < from {
                continue;
            }
            for range in positions.ranges_in(from..settled) {
                remaining.insert_range(range);
            }
            from = settled.saturating_add(1);
        }

        for range in positions.ranges_in(from..total) {
            remaining.insert_range(range);
        }

        // A range too large to number holds no position, so nothing can ever
        // have been recorded against it. Every sitting asks about it again.
        for range in positions.unnumbered() {
            remaining.insert_range(*range);
        }

        remaining.canonicalize();
        remaining
    }

    /// The targets a resumed scan still has to ask about, each carrying its
    /// position in the **original** plan.
    ///
    /// Takes the plan's enumeration — [`TargetMap::iter`](crate::model::target::TargetMap::iter),
    /// the same walk the first sitting was numbered by — and yields only what
    /// this checkpoint does not account for.
    ///
    /// The positions are why this yields [`PlannedTarget`] rather than
    /// [`Target`]. A resumed sitting is scanning a
    /// *subset*, so numbering it afresh would give position 0 to whatever
    /// happens to be left — and the two sittings' cursors would then count
    /// different things. The original numbering has to survive the filtering.
    ///
    /// **The plan must be the one this checkpoint was written against.** A
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
    use crate::journal::file::create_private;
    use crate::journal::format::JournalError;

    impl Checkpoint {
        /// Writes the checkpoint so that a process killed mid-write leaves the
        /// previous one intact.
        ///
        /// Writes a sibling temporary file and renames it over the destination,
        /// which is atomic on every filesystem this engine runs on. **No
        /// `fsync`**, deliberately: the failures this exists for — `^C`, a
        /// dropped session, an OOM kill — are process deaths, and the page cache
        /// outlives the process. Paying a flush on every checkpoint would buy
        /// protection against machine power loss alone, at a cost on every scan
        /// that survives without it. See [`journal`](crate::journal) for what
        /// that policy does and does not promise.
        ///
        /// A torn write is impossible rather than tolerated: the destination
        /// only ever changes by rename, so a reader sees the whole of one
        /// checkpoint or the whole of the one before it.
        pub fn write_atomically(&self, path: &Path) -> Result<(), JournalError> {
            let temporary = path.with_extension("tmp");

            // Scoped so the handle is closed before the rename: renaming over a
            // file still held open is a footgun on the platforms this may yet
            // reach, and costs nothing to avoid.
            {
                let mut file = create_private(&temporary)?;
                file.write_all(serde_json::to_string(self)?.as_bytes())?;
            }

            // The destination becomes the temporary's inode, which already
            // carries the mode and the ownership `create_private` gave it.
            fs::rename(&temporary, path)?;
            Ok(())
        }

        /// Reads a checkpoint back.
        ///
        /// The `settled_above` list is sorted on read rather than trusted,
        /// because [`is_settled`](Checkpoint::is_settled) binary-searches it and
        /// an unsorted list would silently answer `false` for a position that is
        /// present — re-probing a settled target, which is safe, but also
        /// quietly wrong in a way no test would catch.
        pub fn read(path: &Path) -> Result<Self, JournalError> {
            let text = fs::read_to_string(path)?;
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
        };
        let shuffled = Checkpoint {
            watermark: 2,
            settled_above: vec![9, 4, 6],
        };

        assert_eq!(
            sorted.remaining_addresses(&positions),
            shuffled.remaining_addresses(&positions)
        );
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
        // 2 is still outstanding — a tarpit, or a probe mid-retry.
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

    /// Out-of-order settling is the normal case — the dispatcher shuffles within
    /// a batch — so the watermark must be correct whatever order positions
    /// arrive in.
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

    /// The cursor numbers targets by the same walk the dispatcher probes them
    /// by. Asserted rather than assumed: the two live in different modules, and
    /// a divergence would resume a scan against positions that mean something
    /// else — which looks like a working resume that skips the wrong targets.
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

    /// `is_settled` binary-searches, so a list that arrived unsorted would
    /// answer `false` for a position that is present. Safe — it re-probes — but
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
        };

        let cursor = Cursor::from_checkpoint(&checkpoint);

        assert_eq!(cursor.watermark(), 7, "5 and 6 are contiguous with 5");
        assert_eq!(cursor.pending_count(), 0);
        assert_eq!(cursor.settled_count(), 7);
    }
}
