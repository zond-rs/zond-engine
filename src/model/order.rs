// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The order a plan's targets are asked in
//!
//! A scan that walks its plan in order emits the most recognisable signature it
//! has. Every other thing this engine does to make a probe look ordinary, the
//! decoys, the fragments, the deliberately wrong checksum, the spoofed hardware
//! address, is spent on one packet at a time; the shape of the whole run is a
//! monotonic sweep across an address range, and that is what a correlating sensor
//! keys on.
//!
//! [`Permutation`] is the answer: a keyed rearrangement of the plan's whole index
//! space, so the nth target the scan asks about is somewhere else entirely in
//! the plan, and consecutive questions land in unrelated parts of the network.
//!
//! ## Why not shuffle a list
//!
//! Because the list does not fit. A `/8` on a thousand ports is sixteen billion
//! targets, which is why
//! [`TargetSet`](crate::model::target::TargetSet) describes a plan rather than
//! holding one. Shuffling needs the whole list in memory, so a scanner that
//! shuffles is a scanner with a window, and the window is the signature again at
//! a coarser grain: this engine filled batches of eight thousand and shuffled
//! those, which spread a `/24` nicely and walked a `/16` in address order.
//!
//! A permutation computed rather than stored has no window. It costs three words
//! and a handful of arithmetic per target, whatever the plan.
//!
//! ## Why it can be keyed at all
//!
//! Because the plan's numbering is stable. A
//! [`TargetSet`](crate::model::target::TargetSet) is canonical from
//! construction, so the nth target is the same target on every run, and
//! [`TargetIndex`](crate::model::target::TargetIndex) resolves a position back to
//! it. That is what lets the order be a pure function of a seed: a journal
//! records the seed, and a resumed sitting asks the targets it has left in the
//! same relative order the first sitting would have. A resume that switched to a
//! fresh order would be a signature of its own.
//!
//! ## What this is not
//!
//! Cryptography. The construction below is a small Feistel network over the
//! index space, which is a permutation by its shape rather than by any argument
//! about its strength, and the round function is a bit mixer rather than a keyed
//! hash anybody has attacked. It is built to defeat a sensor correlating a
//! monotonic walk, which needs the order to be unpredictable to something not
//! looking for it. It would not survive somebody who was.
//!
//! Nothing here is load-bearing for a verdict either. Getting the order wrong
//! costs a recognisable scan; the one thing it must not do is skip or repeat a
//! target, which is what makes [`Permutation`] a bijection and not merely a
//! scramble, and what `is_a_permutation_of_the_whole_domain` holds it to.

/// How many rounds the network runs.
///
/// Four is where a Feistel construction becomes a permutation that does not
/// visibly resemble its input: three leaves the low half of the output correlated
/// with the low half of the index, which for a scan means neighbouring targets
/// still arriving near each other, which is the whole thing this exists to stop.
const ROUNDS: u32 = 4;

/// Knuth's golden-ratio constant, which separates the rounds from each other.
///
/// Without it every round mixes the same key with the same value and the network
/// collapses to a much weaker function of two rounds.
const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;

/// A keyed rearrangement of `0..len`.
///
/// Every index in the range maps to a distinct value in the range, and the whole
/// range is covered: the order a scan asks its plan in is a rearrangement of the
/// plan, never a sample of it.
///
/// ```
/// use zond_engine::model::order::Permutation;
///
/// let order = Permutation::new(0x5EED, 1_000);
///
/// let mut asked: Vec<u64> = order.iter().collect();
/// assert_eq!(asked.len(), 1_000);
///
/// asked.sort_unstable();
/// assert!(asked.iter().copied().eq(0..1_000), "every target, asked once");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permutation {
    /// The key the order is a function of.
    seed: u64,
    /// How many positions are rearranged.
    len: u64,
    /// Half the width of the domain the network runs over, in bits.
    ///
    /// Zero for a domain of one position or none, where there is nothing to
    /// rearrange and the permutation is the identity.
    half: u32,
}

impl Permutation {
    /// The rearrangement of `0..len` that `seed` names.
    ///
    /// Two calls with the same pair produce the same order, on any build: the
    /// mixing below is written out here rather than taken from a hasher whose
    /// output is free to change between releases, because a seed recorded in a
    /// journal has to mean the same order when the scan is continued next week.
    pub fn new(seed: u64, len: u64) -> Self {
        Self {
            seed,
            len,
            half: half_width(len),
        }
    }

    /// How many positions are rearranged.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether nothing is.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The position asked about `index`th, or [`None`] for an index outside the
    /// range this rearranges.
    ///
    /// The bound is not a formality. The walk below lands inside `0..len` from
    /// anywhere in the domain, so an index past the end would answer a position
    /// some index inside it also answers, and a caller would ask one target
    /// twice while never asking another.
    pub fn at(&self, index: u64) -> Option<u64> {
        (index < self.len).then(|| self.walk(index))
    }

    /// The key this order is a function of.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// When `position` is asked about: the index [`at`](Self::at) names it
    /// at, or [`None`] for a position outside the range.
    ///
    /// The inverse of [`at`](Self::at), and as cheap. It is what lets a count
    /// of how far a scan has got be kept in the order it asks in while its
    /// answers arrive numbered by where the plan holds them.
    ///
    /// ```
    /// use zond_engine::model::order::Permutation;
    ///
    /// let order = Permutation::new(0x5EED, 1_000);
    /// let position = order.at(417).expect("inside the range");
    ///
    /// assert_eq!(order.index_of(position), Some(417));
    /// assert_eq!(order.index_of(1_000), None);
    /// ```
    pub fn index_of(&self, position: u64) -> Option<u64> {
        (position < self.len).then(|| self.unwalk(position))
    }

    /// Every position, in the order the scan asks about them.
    pub fn iter(&self) -> impl Iterator<Item = u64> + Send + 'static {
        self.iter_from(0)
    }

    /// The positions from the `start`th on, in the order the scan asks about
    /// them: the rest of a walk an earlier sitting got `start` positions into.
    pub(crate) fn iter_from(&self, start: u64) -> impl Iterator<Item = u64> + Send + 'static {
        let order = *self;
        (start.min(order.len)..order.len).map(move |index| order.walk(index))
    }

    /// [`at`](Self::at) without the bound, for an index already known to be
    /// inside the range.
    ///
    /// Walks the network until it lands on a position the range holds, which is
    /// the standard way to cut a permutation of a power of two down to a
    /// permutation of an arbitrary count. It terminates, and not on average: the
    /// network is a bijection over the whole domain, so repeated application
    /// traces the cycle `index` sits on, and that cycle contains `index` itself,
    /// which is inside the range. The loop cannot run past the cycle without
    /// finding one.
    ///
    /// The domain is under four times the range by construction, so it lands on
    /// the first try more often than not and on the fourth essentially always.
    fn walk(&self, index: u64) -> u64 {
        if self.half == 0 {
            return index;
        }

        let mut position = index;
        loop {
            position = self.round_trip(position);
            if position < self.len {
                return position;
            }
        }
    }

    /// [`walk`](Self::walk) backwards: the index whose walk lands on
    /// `position`, for a position already known to be inside the range.
    ///
    /// The same cycle traced the other way. The walk from an index passes
    /// through values outside the range and stops at the first inside it, so
    /// stepping back from that position through the values outside the range
    /// arrives at the index, which is the first inside it going that way.
    fn unwalk(&self, position: u64) -> u64 {
        if self.half == 0 {
            return position;
        }

        let mut index = position;
        loop {
            index = self.round_trip_back(index);
            if index < self.len {
                return index;
            }
        }
    }

    /// [`round_trip`](Self::round_trip) undone: the rounds in reverse, each
    /// `(l, r) -> (r ^ f(l), l)`.
    fn round_trip_back(&self, value: u64) -> u64 {
        let mask = (1u64 << self.half) - 1;
        let mut left = (value >> self.half) & mask;
        let mut right = value & mask;

        for round in (0..ROUNDS).rev() {
            let earlier_right = left;
            left = right ^ (mix(self.seed, round, earlier_right) & mask);
            right = earlier_right;
        }

        (left << self.half) | right
    }

    /// One pass of the network: [`ROUNDS`] rounds of `(l, r) -> (r, l ^ f(r))`.
    ///
    /// A bijection over `0..2^(2 * half)` whatever the round function does, which
    /// is the property the whole thing rests on: each round is undone by running
    /// it backwards, so no two inputs can collide.
    fn round_trip(&self, value: u64) -> u64 {
        let mask = (1u64 << self.half) - 1;
        let mut left = (value >> self.half) & mask;
        let mut right = value & mask;

        for round in 0..ROUNDS {
            let mixed = left ^ (mix(self.seed, round, right) & mask);
            left = right;
            right = mixed;
        }

        (left << self.half) | right
    }
}

/// Half the width of the smallest domain that holds `len`, in bits.
///
/// Rounded up to an even number of bits so the network's two halves are the same
/// width, which is what lets a round exclusive-or one into the other. That costs
/// at most one extra bit of domain, so the walk in [`Permutation::walk`] discards
/// under three quarters of its landings in the worst case and none in the best.
///
/// Zero for a range of one position or none, which has one arrangement.
fn half_width(len: u64) -> u32 {
    if len <= 1 {
        return 0;
    }

    // The smallest width whose domain holds `len`, then rounded up to even.
    let width = u64::BITS - (len - 1).leading_zeros();
    (width + (width & 1)) / 2
}

/// The round function: the key, the round and the half, mixed into a value the
/// round exclusive-ors into the other half.
///
/// The mixing is a well-known 64-bit avalanche step, written out rather than
/// pulled from a dependency for the reason [`Permutation::new`] gives: the order
/// a journal recorded has to be the order a later build reproduces, and a
/// hasher's output is not a promise anybody made.
const fn mix(seed: u64, round: u32, value: u64) -> u64 {
    let mut mixed = value
        .wrapping_add(seed)
        .wrapping_add((round as u64).wrapping_mul(GOLDEN));

    mixed ^= mixed >> 30;
    mixed = mixed.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    mixed ^= mixed >> 27;
    mixed = mixed.wrapping_mul(0x94D0_49BB_1331_11EB);
    mixed ^ (mixed >> 31)
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

    /// The one property everything else rests on, over every awkward length
    /// there is: one either side of each power of two, where the domain is
    /// widest relative to the range and the walk discards the most.
    #[test]
    fn is_a_permutation_of_the_whole_domain() {
        let mut lengths: Vec<u64> = (0..=64).collect();
        for power in 3..14u32 {
            let size = 1u64 << power;
            lengths.extend([size - 1, size, size + 1]);
        }

        for len in lengths {
            for seed in [0, 1, 0x5EED, u64::MAX] {
                let order = Permutation::new(seed, len);
                let mut asked: Vec<u64> = order.iter().collect();

                assert_eq!(asked.len() as u64, len, "len {len}, seed {seed}");
                asked.sort_unstable();
                assert!(
                    asked.iter().copied().eq(0..len),
                    "len {len}, seed {seed}: a target was asked twice or not at all"
                );
            }
        }
    }

    /// A seed names one order and keeps naming it, which is what a journal
    /// records it for.
    #[test]
    fn a_seed_names_the_same_order_every_time() {
        let once: Vec<u64> = Permutation::new(0xC0FFEE, 5_000).iter().collect();
        let again: Vec<u64> = Permutation::new(0xC0FFEE, 5_000).iter().collect();

        assert_eq!(once, again);
    }

    /// And two seeds name different ones, or the key is decoration.
    #[test]
    fn two_seeds_name_different_orders() {
        let one: Vec<u64> = Permutation::new(1, 5_000).iter().collect();
        let other: Vec<u64> = Permutation::new(2, 5_000).iter().collect();

        assert_ne!(one, other);
    }

    /// The reason the feature exists. A scan asking positions 0, 1, 2 in turn
    /// must not be walking the plan in address order at any grain, so
    /// consecutive questions have to land far apart.
    ///
    /// The bound is loose. What it rules out is the failure that matters, an
    /// order that is the identity or a local rearrangement of it; pinning the
    /// number tighter would be testing the mixer rather than the property.
    #[test]
    fn consecutive_questions_land_in_unrelated_parts_of_the_plan() {
        const LEN: u64 = 65_536;
        const NEAR: u64 = 256;

        let asked: Vec<u64> = Permutation::new(0x5EED, LEN).iter().collect();
        let near = asked
            .windows(2)
            .filter(|pair| pair[0].abs_diff(pair[1]) < NEAR)
            .count();

        // A uniform order lands within 256 of its predecessor about 0.8% of the
        // time, which on 65,535 pairs is around 500.
        assert!(
            near < 2_000,
            "{near} of {} consecutive pairs landed within {NEAR} of each other, \
             which is a walk rather than a rearrangement",
            asked.len() - 1
        );
    }

    /// A range of one position or none has one arrangement, and asking for it
    /// answers rather than dividing by anything.
    #[test]
    fn a_range_too_small_to_rearrange_is_the_identity() {
        assert!(Permutation::new(7, 0).iter().next().is_none());
        assert_eq!(Permutation::new(7, 1).iter().collect::<Vec<_>>(), vec![0]);
        assert!(Permutation::new(7, 0).is_empty());
    }

    /// An index outside the range answers nothing rather than a position some
    /// index inside it already owns.
    #[test]
    fn an_index_past_the_end_names_no_position() {
        let order = Permutation::new(3, 10);

        assert!(order.at(9).is_some());
        assert_eq!(order.at(10), None);
        assert_eq!(order.at(u64::MAX), None);
    }

    /// Asking when a position comes up answers the index it came up at, for
    /// every position, so a count kept in the order a scan asks in and one
    /// kept in the plan's own order name the same targets.
    #[test]
    fn index_of_undoes_at_over_every_awkward_length() {
        for len in [0u64, 1, 2, 3, 7, 8, 9, 255, 256, 257, 1_000, 4_097] {
            for seed in [0, 0x5EED, u64::MAX] {
                let order = Permutation::new(seed, len);
                for index in 0..len {
                    let position = order.at(index).expect("inside the range");
                    assert_eq!(
                        order.index_of(position),
                        Some(index),
                        "len {len}, seed {seed}, index {index}"
                    );
                }
                assert_eq!(order.index_of(len), None, "len {len}: past the end");
            }
        }
    }

    /// And the inverse holds across the widest domain too.
    #[test]
    fn index_of_undoes_at_in_the_widest_range() {
        let order = Permutation::new(0x5EED, u64::MAX);
        for index in [0, 1, 2, u64::MAX / 2, u64::MAX - 1] {
            let position = order.at(index).expect("inside the range");
            assert_eq!(order.index_of(position), Some(index));
        }
    }

    /// A walk resumed part way through asks what the whole walk had left, in
    /// the same order.
    #[test]
    fn a_walk_resumed_part_way_asks_the_rest_in_the_same_order() {
        let order = Permutation::new(0xC0FFEE, 1_000);
        let whole: Vec<u64> = order.iter().collect();

        assert_eq!(order.iter_from(417).collect::<Vec<_>>(), whole[417..]);
        assert_eq!(order.iter_from(5_000).count(), 0);
    }

    /// The widest domain there is, where the halves are 32 bits each and the
    /// shifts are one step from overflowing.
    #[test]
    fn the_widest_range_rearranges_without_overflowing_a_shift() {
        let order = Permutation::new(0x5EED, u64::MAX);

        assert_eq!(order.len(), u64::MAX);
        for index in [0, 1, 2, u64::MAX / 2, u64::MAX - 1] {
            let position = order.at(index).expect("inside the range");
            assert!(position < u64::MAX);
        }
    }
}
