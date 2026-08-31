// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # IP address sets
//!
//! [`IpSet`] holds the addresses a scan is about, as sorted non-overlapping
//! ranges. In that form a `/8` costs one range rather than sixteen million
//! addresses.
//!
//! ## Merging is lazy
//!
//! Insertion is constant time, because it only appends. Sorting and merging is
//! `O(n log n)` and happens once, when you call [`IpSet::canonicalize`]. The
//! split exists because a target file can name tens of thousands of ranges, and
//! merging after each one would make loading it quadratic.
//!
//! You do not have to track which state a set is in. Every query is correct
//! either way: [`contains`](IpSet::contains) and [`len`](IpSet::len) take a fast
//! path over merged ranges when they can and a slower one when they cannot.
//! Canonicalizing is a performance decision, not a correctness one, and the
//! right moment for it is when a set stops being built and starts being read.
//!
//! Most callers never need to think about it at all, because
//! [`TargetSet::new`](crate::model::target::TargetSet::new) canonicalizes what
//! it is given and never mutates it again. Everything downstream of a
//! `TargetSet` reads merged ranges by construction.

use super::range::{IpError, IpRange, Ipv4Range, Ipv6Range};
use std::cmp::Ordering;
use std::ops::Range;
use std::{
    borrow::Cow,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

/// Why a written address specification could not be read as a set.
///
/// One variant, wrapping the range grammar's own error, and deliberately less
/// than [`IpParseError`](crate::model::parse::ip::IpParseError) says about the
/// same input. That type distinguishes "this is not a range" from "this is a
/// range and it is wrong", names both prefix bounds, and carries the expression
/// as the caller wrote it, all of which a person reading a refused target wants.
///
/// It is not available here. `parse` is built on `ip` and reaching the other way
/// would put the two modules in a cycle, which `tests/architecture.rs` refuses
/// and `lib.rs` sets out the order to avoid. So the richer reading belongs to
/// the layer that has both, and a caller wanting it goes through
/// [`to_set`](crate::model::parse::ip::to_set) rather than through this type's
/// [`FromStr`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IpSetError {
    /// The text named something that is not an address or a range.
    #[error("Invalid target in set: {0}")]
    InvalidTarget(#[from] IpError),
}

// ══════════════════════════════════════════════════════════════════════════════
// IpSet core model
// ══════════════════════════════════════════════════════════════════════════════

/// A collection of unique IP addresses stored as sorted, non-overlapping ranges.
///
/// Handles automatic merging of overlapping and adjacent ranges lazily.
///
/// Equality is over the addresses held, not over how the set was built: see the
/// hand-written [`PartialEq`].
#[derive(Debug, Clone, Default, Eq)]
pub struct IpSet {
    v4: Vec<Ipv4Range>,
    v6: Vec<Ipv6Range>,
    v4_dirty: bool,
    v6_dirty: bool,
}

impl IpSet {
    /// Creates a new, empty `IpSet`.
    pub fn new() -> Self {
        Self::default()
    }

    // ─── Insertion API ───────────────────────────────────────────────────────

    /// Adds a single IP address to the set.
    ///
    /// Constant time: it appends and defers the merge. See the module
    /// documentation for why.
    pub fn insert(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(v4) => self.push_v4_range(Ipv4Range::single(v4)),
            IpAddr::V6(v6) => self.push_v6_range(Ipv6Range::single(v6)),
        }
    }

    /// Adds a unified IP range to the set.
    pub fn insert_range(&mut self, range: IpRange) {
        match range {
            IpRange::V4(r) => self.push_v4_range(r),
            IpRange::V6(r) => self.push_v6_range(r),
        }
    }

    /// Appends an IPv4 range without immediate merging.
    pub fn push_v4_range(&mut self, range: Ipv4Range) {
        self.v4.push(range);
        self.v4_dirty = true;
    }

    /// Appends an IPv6 range without immediate merging.
    pub fn push_v6_range(&mut self, range: Ipv6Range) {
        self.v6.push(range);
        self.v6_dirty = true;
    }

    /// Sorts and merges the ranges, so that every read afterwards takes its
    /// fast path.
    ///
    /// Call it once, at the point the set stops being built and starts being
    /// read. It is not required for correctness, since every query answers
    /// correctly either way, but an unmerged set answers by scanning, and a set
    /// read once per received packet should not be.
    pub fn canonicalize(&mut self) {
        if self.v4_dirty {
            if !self.v4.is_empty() {
                self.merge_v4();
            }
            self.v4_dirty = false;
        }
        if self.v6_dirty {
            if !self.v6.is_empty() {
                self.merge_v6();
            }
            self.v6_dirty = false;
        }
    }

    fn merge_v4(&mut self) {
        self.v4.sort_by_key(|r| r.start_addr());
        let mut merged: Vec<Ipv4Range> = Vec::with_capacity(self.v4.len());
        let mut current = self.v4[0];

        for next in self.v4.drain(1..) {
            let curr_end = u32::from(current.end_addr());
            let next_start = u32::from(next.start_addr());

            if next_start <= curr_end.saturating_add(1) {
                current.extend_end_to(next.end_addr());
            } else {
                merged.push(current);
                current = next;
            }
        }
        merged.push(current);
        self.v4 = merged;
    }

    /// Sorts and merges the IPv6 ranges, keeping ranges on different interfaces
    /// apart.
    ///
    /// Two link-local ranges spanning the same numbers on two interfaces are two
    /// different sets of machines, and merging them would produce a range that
    /// means one thing at one end and something else at the other. So adjacency
    /// alone is not enough to combine two ranges; they have to agree on scope.
    ///
    /// **The sort is keyed on the zone first.** That leaves the vector as one
    /// run per interface, each sorted by address and disjoint within itself,
    /// which is what [`v6_runs`](Self::v6_runs) hands the binary search. Sorted
    /// by address first the runs interleave, and two ranges that overlap
    /// numerically while disagreeing on zone both survive the merge — a vector
    /// a binary search steps straight past.
    ///
    /// Grouping also merges strictly more than address-first ordering did: two
    /// ranges sharing a zone are now always adjacent, where before a
    /// differently-zoned range between them left both in place.
    fn merge_v6(&mut self) {
        self.v6.sort_by_key(|r| (r.zone(), r.start_addr()));
        let mut merged: Vec<Ipv6Range> = Vec::with_capacity(self.v6.len());
        let mut current = self.v6[0];

        for next in self.v6.drain(1..) {
            let curr_end = u128::from(current.end_addr());
            let next_start = u128::from(next.start_addr());

            if next.zone() == current.zone() && next_start <= curr_end.saturating_add(1) {
                current.extend_end_to(next.end_addr());
            } else {
                merged.push(current);
                current = next;
            }
        }
        merged.push(current);
        self.v6 = merged;
    }

    // ─── Set arithmetic ──────────────────────────────────────────────────────

    /// Removes every address `other` holds from this set.
    ///
    /// This set is canonicalized first and left that way, so every read after it
    /// takes its fast path. `other` is read in whatever state it is in — the
    /// subtrahend is sorted and coalesced on the way through, which a set being
    /// subtracted *from* cannot be, since the difference has to write back into
    /// it. Afterwards [`contains`](Self::contains) answers `false` for every
    /// address `other` contained, and that property is what makes this usable as
    /// a policy rather than merely as an optimisation.
    ///
    /// **Blind to zones, exactly as [`contains`](Self::contains) is.** A range in
    /// `other` removes those addresses from every interface, whether or not
    /// either side named one. The two have to agree: a difference that kept
    /// `fe80::5%en1` while `contains` reported `fe80::5` present would leave a
    /// set that says one thing when asked and another when walked, and the caller
    /// most likely to meet the discrepancy is the one filtering received replies
    /// — which arrive as bare addresses with no interface attached, and so can
    /// only ever be tested the blind way.
    ///
    /// Where the two readings differ this is the one that removes more, which is
    /// the direction a subtraction used to withhold addresses from a scan has to
    /// err in. Deciding it here rather than per caller is the point.
    ///
    /// Linear in the *ranges* of both sides and never in their addresses:
    /// subtracting a `/24` from a `/8` is a handful of comparisons, not sixteen
    /// million.
    pub fn subtract(&mut self, other: &IpSet) {
        if other.is_empty() || self.is_empty() {
            return;
        }
        self.canonicalize();

        if !self.v4.is_empty() {
            let cuts = merged_intervals(other.v4.iter().map(v4_bounds));
            if !cuts.is_empty() {
                self.v4 = subtract_run(&self.v4, &cuts, v4_bounds, |_, start, end| {
                    // Both ends came out of a `u32`-derived range and the
                    // difference only ever narrows one, so the casts are exact.
                    Ipv4Range::new(Ipv4Addr::from(start as u32), Ipv4Addr::from(end as u32))
                        .unwrap_or_else(|_| unreachable!("a narrowed range keeps start <= end"))
                });
            }
        }

        if !self.v6.is_empty() {
            let cuts = merged_intervals(other.v6.iter().map(v6_bounds));
            if !cuts.is_empty() {
                // One run per interface, because only within a run are the
                // ranges disjoint — the precondition the difference needs. The
                // zone travels with every piece a range is cut into, so the
                // result stays grouped and sorted the way `merge_v6` left it.
                let mut kept = Vec::with_capacity(self.v6.len());
                for run in self.v6_runs() {
                    kept.extend(subtract_run(run, &cuts, v6_bounds, |range, start, end| {
                        Ipv6Range::scoped(Ipv6Addr::from(start), Ipv6Addr::from(end), range.zone())
                            .unwrap_or_else(|_| unreachable!("a narrowed range keeps start <= end"))
                    }));
                }
                self.v6 = kept;
            }
        }
    }

    /// The merged IPv6 ranges, one slice per interface.
    ///
    /// Each slice is sorted by address and holds no two ranges that overlap,
    /// which is the precondition [`holds`] needs and which the vector as a
    /// whole does not meet. There is one slice per distinct zone, so this
    /// yields once for the sets that name no interface at all and otherwise as
    /// many times as the host has interfaces in the set.
    fn v6_runs(&self) -> impl Iterator<Item = &[Ipv6Range]> {
        let mut rest = self.v6.as_slice();

        std::iter::from_fn(move || {
            let zone = rest.first()?.zone();
            // Sorted by zone first, so this run is a prefix of what is left.
            let (run, tail) = rest.split_at(rest.partition_point(|r| r.zone() == zone));
            rest = tail;
            Some(run)
        })
    }

    // ─── Query API (Lazy) ────────────────────────────────────────────────────

    /// Checks if the set contains the given IP address, on any interface.
    ///
    /// Deliberately blind to zones: the callers are filtering received replies
    /// against the targets they asked about, and a reply arrives as a bare
    /// address with no interface attached to compare. The strategy that receives
    /// it is bound to one segment already, so the scope is established by which
    /// scanner is asking rather than by this test.
    ///
    /// Correct whatever state the set is in: a binary search when the address's
    /// own family is merged, and a linear scan of that family's unmerged ranges
    /// when it is not. The slow path allocates nothing, because a membership
    /// test is not a reason to merge a set the caller has not finished building.
    ///
    /// **Per family, because the merge is.** Asking about both put every IPv6
    /// lookup on the linear path for as long as one unmerged IPv4 range sat
    /// beside it, which is the path a received reply takes.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        if self.is_merged(ip) {
            return self.contains_canonical(ip);
        }
        match ip {
            IpAddr::V4(v4) => self.v4.iter().any(|range| range.contains(v4)),
            IpAddr::V6(v6) => self.v6.iter().any(|range| range.contains(v6)),
        }
    }

    /// The number of distinct addresses the set covers.
    ///
    /// Overlapping ranges are counted once, so an unmerged set is merged before
    /// answering. That happens on a clone, which keeps counting a read.
    /// [`len_gross`](Self::len_gross) is the cheap over-estimate for a caller
    /// that asks often.
    pub fn len(&self) -> u128 {
        if !self.v4_dirty && !self.v6_dirty {
            self.len_canonical()
        } else {
            let mut temp = self.clone();
            temp.canonicalize();
            temp.len_canonical()
        }
    }

    /// Returns `true` if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// How many addresses the ranges cover, counting overlaps once per range
    /// they appear in.
    ///
    /// [`len`](Self::len) clones and merges the whole set when it is dirty,
    /// which is the right answer to give a person and the wrong one to ask on
    /// every insertion. This costs one pass and no allocation, and it is never
    /// lower than the true count - so a budget checked against it refuses early
    /// rather than late.
    pub fn len_gross(&self) -> u128 {
        self.v4_len().saturating_add(self.v6_len())
    }

    /// Every address the set covers, one at a time, IPv4 before IPv6.
    ///
    /// Each address is yielded once, however many ranges named it. That needs
    /// merged ranges, so an unmerged set is merged on a clone and iteration
    /// stays a read. If you own the set, call
    /// [`canonicalize`](Self::canonicalize) first and skip the copy.
    ///
    /// Yields lazily. A `/8` is sixteen million addresses and an IPv6 range can
    /// hold far more than that, so nothing here is materialized.
    pub fn iter(&self) -> Box<dyn Iterator<Item = IpAddr> + Send + '_> {
        if self.v4_dirty || self.v6_dirty {
            let mut temp = self.clone();
            temp.canonicalize();
            temp.into_iter()
        } else {
            let v4_iter = self.v4.iter().flat_map(|range| range.iter());
            let v6_iter = self.v6.iter().flat_map(|range| range.iter());
            Box::new(v4_iter.chain(v6_iter))
        }
    }

    // ─── Query API (Read-Only / Sync) ────────────────────────────────────────

    /// Whether the family `ip` belongs to has been merged.
    ///
    /// The question [`contains`](Self::contains) asks before taking its fast
    /// path, and it is per family because the merge is. A set that has just
    /// gained an IPv4 range holds an IPv6 half as canonical as it was a moment
    /// earlier, and a binary search over that half is as valid as it ever was;
    /// [`canonicalize`](Self::canonicalize) has always known this and merged
    /// only the family that needed it.
    ///
    /// Asking `!v4_dirty && !v6_dirty` instead put every IPv6 membership test on
    /// a linear scan for as long as one unmerged IPv4 range sat beside it, which
    /// is the path a received reply takes. Over a thousand merged IPv6 ranges
    /// with one IPv4 address pushed after canonicalizing, twenty thousand
    /// lookups took 276 ms where the merged set took 6.5 ms.
    fn is_merged(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => !self.v4_dirty,
            IpAddr::V6(_) => !self.v6_dirty,
        }
    }

    /// The fast path [`contains`](Self::contains) takes on a merged family.
    ///
    /// Private, because the assertion below is the only thing separating a
    /// binary search over sorted ranges from a binary search over unsorted
    /// ones, and a release build compiles it out. Whether an address is in
    /// scope decides whether a reply is credited or discarded, so that choice
    /// is not one to leave to a caller who cannot see the set's state.
    ///
    /// # Panics
    ///
    /// In debug builds, if the address's own family has unmerged ranges
    /// pending. The other family's state is not its business, for the reason
    /// [`is_merged`](Self::is_merged) gives.
    fn contains_canonical(&self, ip: &IpAddr) -> bool {
        debug_assert!(
            self.is_merged(ip),
            "IpSet must be canonicalized before calling contains_canonical"
        );
        match ip {
            IpAddr::V4(v4) => holds(&self.v4, u128::from(u32::from(*v4)), |range| {
                (
                    u128::from(u32::from(range.start_addr())),
                    u128::from(u32::from(range.end_addr())),
                )
            }),
            IpAddr::V6(v6) => {
                let target = u128::from(*v6);
                self.v6_runs().any(|run| {
                    holds(run, target, |range| {
                        (u128::from(range.start_addr()), u128::from(range.end_addr()))
                    })
                })
            }
        }
    }

    /// The fast path [`len`](Self::len) takes on a merged set. Private for the
    /// same reason [`contains_canonical`](Self::contains_canonical) is.
    ///
    /// # Panics
    ///
    /// In debug builds, if the set has unmerged ranges pending.
    fn len_canonical(&self) -> u128 {
        debug_assert!(
            !self.v4_dirty && !self.v6_dirty,
            "IpSet must be canonicalized before calling len_canonical"
        );
        self.v4_len().saturating_add(self.v6_len())
    }

    /// How many addresses the IPv4 ranges cover, and how many the IPv6 ones do.
    ///
    /// Counted per family rather than as one total because a caller that emits
    /// a different probe per family needs to know the ratio between them - a
    /// sweep interleaving ARP with neighbor solicitation has to space each
    /// against the other's volume. Overlapping ranges are counted twice, which
    /// merging is what would fix: these steer pacing, and a pacing decision does
    /// not warrant canonicalizing a clone of the set to make them exact.
    ///
    /// Saturates rather than wrapping, for the reason
    /// [`Ipv6Range::len`](crate::model::ip::range::Ipv6Range::len) gives:
    /// a count too large to represent is still enormous, and a wrapped one reads
    /// as small.
    pub fn v4_len(&self) -> u128 {
        self.v4
            .iter()
            .fold(0u128, |total, r| total.saturating_add(r.len() as u128))
    }

    /// The IPv6 half of [`v4_len`](Self::v4_len).
    pub fn v6_len(&self) -> u128 {
        self.v6
            .iter()
            .fold(0u128, |total, r| total.saturating_add(r.len()))
    }

    /// Returns the underlying IPv4 ranges. If dirty, these ranges may be overlapping and un-merged.
    pub fn v4(&self) -> &[Ipv4Range] {
        &self.v4
    }

    /// Returns the underlying IPv6 ranges. If dirty, these ranges may be overlapping and un-merged.
    pub fn v6(&self) -> &[Ipv6Range] {
        &self.v6
    }
}

impl PartialEq for IpSet {
    /// Whether the two sets hold the same addresses.
    ///
    /// Written by hand rather than derived because the derive compared the
    /// range vectors as written and the dirty flags beside them, so one address
    /// inserted twice and the same address inserted once were different sets.
    /// What a caller means by `==` here is the addresses.
    ///
    /// Merged ranges are the only comparable form, so a set that is not in one
    /// is merged on a clone — the same trade [`len`](Self::len) makes, and for
    /// the same reason: comparing is a read, and a read does not mutate its
    /// operand. Two sets that have both been canonicalized, which is every set
    /// that reached a `TargetSet`, compare without allocating.
    fn eq(&self, other: &Self) -> bool {
        fn merged(set: &IpSet) -> Cow<'_, IpSet> {
            if set.v4_dirty || set.v6_dirty {
                let mut owned = set.clone();
                owned.canonicalize();
                Cow::Owned(owned)
            } else {
                Cow::Borrowed(set)
            }
        }

        let (this, that) = (merged(self), merged(other));
        this.v4 == that.v4 && this.v6 == that.v6
    }
}

/// Where each of an [`IpSet`]'s addresses falls in its enumeration.
///
/// [`IpSet::iter`] walks the merged IPv4 ranges in ascending order and then the
/// IPv6 ones, and the index an address holds in that walk is its **position**.
/// A sweep is counted in positions the way a port scan is counted in
/// [`PlannedTarget`](crate::model::target::PlannedTarget)s, so that a journal
/// can record how far one got without writing down an address per target.
///
/// Built from the ranges rather than the addresses: a `/8` costs one entry
/// here, and a lookup is a binary search over the ranges however many addresses
/// they hold. Nothing is enumerated, so this is affordable to consult once per
/// probe.
///
/// # A set larger than a position can count
///
/// A position is a `u64`, and an IPv6 range can hold more addresses than that.
/// A `/64` is the first size that does not fit, being one address past what a
/// `u64` counts. Ranges are numbered in order until one would not fit, and
/// everything from there on is **unnumbered**: [`find`](Self::find) answers
/// `None` for it and [`unnumbered`](Self::unnumbered) hands it back whole.
///
/// An unnumbered address can never settle, so it is asked again on every
/// sitting, which is the fail-safe an unreported outcome also takes. IPv4 is
/// numbered first and so is never the half that is lost, which matters because
/// it is the half that is walked address by address.
#[derive(Debug, Clone, Default)]
pub struct Positions {
    /// The ranges in enumeration order, each with the position of its first
    /// address. IPv4 before IPv6, ascending within each.
    spans: Vec<Span>,
    /// The stretches of `spans` that are sorted and disjoint *by address*, so
    /// that a binary search inside one is valid.
    ///
    /// IPv4 is one. IPv6 is one per interface, because the set sorts by zone
    /// before address — `fe80::1` on two interfaces is two different machines
    /// and two separate ranges, which together are not one ascending sequence.
    /// [`contains`](IpSet::contains) walks the same runs for the same reason.
    runs: Vec<Run>,
    /// How many addresses are numbered, which is every address of every span.
    total: u64,
    /// The ranges the numbering could not reach, in enumeration order.
    unnumbered: Vec<IpRange>,
}

/// One stretch of [`Positions::spans`] that a binary search may be run over.
#[derive(Debug, Clone, Copy)]
struct Run {
    /// Where the stretch starts in `spans`.
    from: usize,
    /// Where it ends, exclusive.
    to: usize,
    /// Whether these are IPv6 ranges. The families never share a run.
    v6: bool,
}

/// One range, and where its addresses sit in the enumeration.
#[derive(Debug, Clone, Copy)]
struct Span {
    range: IpRange,
    /// The position of the range's first address.
    start: u64,
    /// How many addresses it holds. Never zero: a range holds at least one.
    len: u64,
}

impl Positions {
    /// Numbers `set`'s addresses.
    ///
    /// The set is merged first if it is not already, on a clone, since an
    /// unmerged set enumerates differently from the canonical one every
    /// position is counted in. That is the same trade [`IpSet::len`] makes.
    pub fn of(set: &IpSet) -> Self {
        if set.v4_dirty || set.v6_dirty {
            let mut merged = set.clone();
            merged.canonicalize();
            return Self::of_canonical(&merged);
        }
        Self::of_canonical(set)
    }

    fn of_canonical(set: &IpSet) -> Self {
        let ranges = set
            .v4
            .iter()
            .copied()
            .map(IpRange::V4)
            .chain(set.v6.iter().copied().map(IpRange::V6));

        let mut spans = Vec::new();
        let mut runs: Vec<Run> = Vec::new();
        let mut total: u64 = 0;
        let mut group: Option<(bool, Option<u32>)> = None;
        let mut unnumbered = Vec::new();

        for range in ranges {
            // The first range that will not fit ends the numbering, and so does
            // every range after it: positions have to stay contiguous, or the
            // ones already handed out would move. What is left is kept rather
            // than dropped, so a resumed sitting still asks about it.
            if !unnumbered.is_empty() {
                unnumbered.push(range);
                continue;
            }
            let Ok(len) = u64::try_from(range.len()) else {
                unnumbered.push(range);
                continue;
            };
            let Some(next) = total.checked_add(len) else {
                unnumbered.push(range);
                continue;
            };

            let here = match range {
                IpRange::V4(_) => (false, None),
                IpRange::V6(v6) => (true, v6.zone()),
            };
            match runs.last_mut() {
                Some(run) if group == Some(here) => run.to = spans.len() + 1,
                _ => runs.push(Run {
                    from: spans.len(),
                    to: spans.len() + 1,
                    v6: here.0,
                }),
            }
            group = Some(here);

            spans.push(Span {
                range,
                start: total,
                len,
            });
            total = next;
        }

        Self {
            spans,
            runs,
            total,
            unnumbered,
        }
    }

    /// How many addresses are numbered.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Whether nothing is numbered at all.
    ///
    /// A plan whose first range is already too large is empty by this and still
    /// holds every address it was built from; see
    /// [`unnumbered`](Self::unnumbered).
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// The ranges the numbering could not reach, in enumeration order.
    ///
    /// Empty for every plan that fits, which is every IPv4 plan and every IPv6
    /// one written narrower than a `/64`. A resumed sweep asks about these
    /// alongside whatever its checkpoint says is left, because a range with no
    /// positions has nothing recorded against it and asking again is the only
    /// reading that cannot skip an address.
    pub fn unnumbered(&self) -> &[IpRange] {
        &self.unnumbered
    }

    /// Where `ip` falls in the enumeration, or `None` when the set does not hold
    /// it or holds it beyond what a position can count.
    ///
    /// A sweep finds addresses it was never asked about, and those have no
    /// position: they are findings rather than plan targets, and nothing about
    /// them advances a cursor.
    pub fn find(&self, ip: IpAddr) -> Option<u64> {
        let span = self.span_holding(ip)?;
        let offset = offset_within(&span.range, ip)?;
        Some(span.start + offset)
    }

    /// The address at `position`, or `None` past the end of the numbering.
    pub fn address_at(&self, position: u64) -> Option<IpAddr> {
        let index = self.span_at(position)?;
        let span = &self.spans[index];
        address_within(&span.range, position - span.start)
    }

    /// The addresses at every position in `wanted`, as ranges.
    ///
    /// For narrowing a plan to what a resumed sweep still has to ask about:
    /// the answer is a handful of ranges however many addresses they cover, so
    /// continuing a sweep of a `/8` costs no more than continuing one of a
    /// `/24`.
    pub fn ranges_in(&self, wanted: Range<u64>) -> Vec<IpRange> {
        let end = wanted.end.min(self.total);
        if wanted.start >= end {
            return Vec::new();
        }

        let mut found = Vec::new();
        let mut index = match self.span_at(wanted.start) {
            Some(index) => index,
            None => return found,
        };

        while index < self.spans.len() {
            let span = &self.spans[index];
            if span.start >= end {
                break;
            }

            let from = wanted.start.saturating_sub(span.start);
            let to = (end - span.start).min(span.len) - 1;
            if let Some(part) = slice_of(&span.range, from, to) {
                found.push(part);
            }
            index += 1;
        }

        found
    }

    /// The span holding `ip`, or `None` where no run holds it or more than one
    /// does.
    ///
    /// **Two runs holding it is refused rather than resolved.** An `IpAddr`
    /// carries no interface, so an address two segments both hold cannot say
    /// which of its two positions it means — and picking one would settle a
    /// position belonging to the other, which is a resume skipping an address
    /// nothing ever probed. Answering `None` costs that address being asked
    /// again, which is the direction this has to fail in.
    fn span_holding(&self, ip: IpAddr) -> Option<&Span> {
        let v6 = ip.is_ipv6();
        let key = widen(ip);
        let mut found: Option<&Span> = None;

        for run in self.runs.iter().filter(|run| run.v6 == v6) {
            let spans = &self.spans[run.from..run.to];
            let Ok(index) = spans.binary_search_by(|span| {
                let (start, end) = bounds(&span.range);
                if end < key {
                    Ordering::Less
                } else if start > key {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                }
            }) else {
                continue;
            };

            if found.is_some() {
                return None;
            }
            found = Some(&spans[index]);
        }

        found
    }

    /// The index of the span holding `position`.
    fn span_at(&self, position: u64) -> Option<usize> {
        if position >= self.total {
            return None;
        }

        self.spans
            .binary_search_by(|span| {
                if span.start + span.len <= position {
                    Ordering::Less
                } else if span.start > position {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                }
            })
            .ok()
    }
}

impl IpSet {
    /// Numbers this set's addresses, for counting how far a sweep of it got.
    ///
    /// See [`Positions`], which is where the numbering and its one limit are
    /// described.
    pub fn positions(&self) -> Positions {
        Positions::of(self)
    }
}

/// One address as a `u128`, so the two families compare the same way.
fn widen(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// A range's inclusive bounds, widened.
fn bounds(range: &IpRange) -> (u128, u128) {
    match range {
        IpRange::V4(v4) => v4_bounds(v4),
        IpRange::V6(v6) => (u128::from(v6.start_addr()), u128::from(v6.end_addr())),
    }
}

/// How far into `range` the address `ip` sits, or `None` if it is not in it or
/// belongs to the other family.
fn offset_within(range: &IpRange, ip: IpAddr) -> Option<u64> {
    let same_family = matches!(
        (range, ip),
        (IpRange::V4(_), IpAddr::V4(_)) | (IpRange::V6(_), IpAddr::V6(_))
    );
    if !same_family {
        return None;
    }

    let (start, end) = bounds(range);
    let key = widen(ip);
    if key < start || key > end {
        return None;
    }
    u64::try_from(key - start).ok()
}

/// The address `offset` addresses into `range`.
fn address_within(range: &IpRange, offset: u64) -> Option<IpAddr> {
    let (start, end) = bounds(range);
    let at = start.checked_add(u128::from(offset))?;
    if at > end {
        return None;
    }

    Some(match range {
        IpRange::V4(_) => IpAddr::V4(Ipv4Addr::from(u32::try_from(at).ok()?)),
        IpRange::V6(_) => IpAddr::V6(Ipv6Addr::from(at)),
    })
}

/// The part of `range` from its `from`th address to its `to`th, inclusive.
fn slice_of(range: &IpRange, from: u64, to: u64) -> Option<IpRange> {
    let start = address_within(range, from)?;
    let end = address_within(range, to)?;

    match (range, start, end) {
        (IpRange::V4(_), IpAddr::V4(start), IpAddr::V4(end)) => {
            Ipv4Range::new(start, end).ok().map(IpRange::V4)
        }
        // The zone travels with the slice: `fe80::1` names a different machine
        // on every segment, so a piece of a zoned range is still zoned.
        (IpRange::V6(v6), IpAddr::V6(start), IpAddr::V6(end)) => {
            Ipv6Range::scoped(start, end, v6.zone())
                .ok()
                .map(IpRange::V6)
        }
        _ => None,
    }
}

/// The inclusive bounds of an IPv4 range, widened so one difference serves both
/// address families — the same widening [`holds`] does, for the same reason.
fn v4_bounds(range: &Ipv4Range) -> (u128, u128) {
    (
        u128::from(u32::from(range.start_addr())),
        u128::from(u32::from(range.end_addr())),
    )
}

/// The IPv6 half of [`v4_bounds`]. Drops the zone, which is what makes
/// [`IpSet::subtract`] blind to it.
fn v6_bounds(range: &Ipv6Range) -> (u128, u128) {
    (u128::from(range.start_addr()), u128::from(range.end_addr()))
}

/// Sorts and coalesces `intervals` into ascending, non-overlapping, non-adjacent
/// inclusive pairs.
///
/// The subtrahend, flattened. It comes from the other set's range vector, which
/// is merged *within* each IPv6 zone and so may still overlap across zones —
/// and [`IpSet::subtract`] reads it blind to zones, so those overlaps have to be
/// coalesced before the difference can walk both sides once.
fn merged_intervals(intervals: impl Iterator<Item = (u128, u128)>) -> Vec<(u128, u128)> {
    let mut cuts: Vec<(u128, u128)> = intervals.collect();
    cuts.sort_unstable();

    let mut merged: Vec<(u128, u128)> = Vec::with_capacity(cuts.len());
    for (start, end) in cuts {
        match merged.last_mut() {
            // Adjacent as well as overlapping: two cuts that meet end to end
            // remove the same addresses as one spanning both, and coalescing
            // them here saves the difference below a step.
            Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Every part of `run` that no interval in `cuts` covers, in ascending order.
///
/// **Both slices must be sorted by start and free of overlap**, which is what
/// lets this advance through each exactly once rather than testing every pair.
/// `run` is one address family's merged ranges — for IPv6, one zone's run of
/// them, since only within a run are they disjoint — and `cuts` is what
/// [`merged_intervals`] produced.
///
/// `bounds` reads a range's inclusive ends, widened to `u128` so one difference
/// serves both families, exactly as [`holds`] does. `rebuild` turns a surviving
/// `[start, end]` back into a range of the caller's type; it is handed the range
/// being cut so a piece can carry across what its bounds do not say, which for
/// IPv6 is the zone.
fn subtract_run<R: Copy>(
    run: &[R],
    cuts: &[(u128, u128)],
    bounds: impl Fn(&R) -> (u128, u128),
    rebuild: impl Fn(&R, u128, u128) -> R,
) -> Vec<R> {
    let mut kept = Vec::with_capacity(run.len());
    let mut first_live = 0usize;

    for range in run {
        let (start, end) = bounds(range);

        // A cut entirely left of this range is left of every later one too,
        // both slices ascending, so this index only ever moves forward — which
        // is what makes the whole pass linear rather than quadratic.
        while first_live < cuts.len() && cuts[first_live].1 < start {
            first_live += 1;
        }

        let mut cursor = start;
        let mut consumed = false;

        // Not advancing `first_live` here: one cut may span several ranges, and
        // it has to still be in front of the next one.
        let mut cut = first_live;
        while cut < cuts.len() && cuts[cut].0 <= end {
            let (cut_start, cut_end) = cuts[cut];

            // The gap in front of this cut survives. Nothing to emit when the
            // cut starts at or before the cursor, which is what an overlap with
            // the previous cut or with the range's own start looks like.
            if cut_start > cursor {
                kept.push(rebuild(range, cursor, cut_start - 1));
            }

            // A cut reaching the range's end takes the tail with it, and stays
            // in front of the range after this one.
            if cut_end >= end {
                consumed = true;
                break;
            }

            // `cut_end < end <= u128::MAX`, so this cannot overflow.
            cursor = cut_end + 1;
            cut += 1;
        }

        if !consumed {
            kept.push(rebuild(range, cursor, end));
        }
    }

    kept
}

/// Whether any range in `ranges` holds `target`, by binary search.
///
/// `bounds` reads a range's inclusive ends, widened to `u128` so that one
/// search serves both families.
///
/// **`ranges` must be sorted by start address and free of overlap.** Against
/// overlapping ranges the search can land on one that ends before the target,
/// conclude the target lies further right, and never look at the range on its
/// left that holds it. Each family reaches that precondition its own way: the
/// IPv4 vector is disjoint once merged, and the IPv6 vector only within a
/// single zone's run — see [`IpSet::v6_runs`].
fn holds<R>(ranges: &[R], target: u128, bounds: impl Fn(&R) -> (u128, u128)) -> bool {
    ranges
        .binary_search_by(|range| {
            let (start, end) = bounds(range);
            if target < start {
                std::cmp::Ordering::Greater
            } else if target > end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

// ══════════════════════════════════════════════════════════════════════════════
// Conversion Traits
// ══════════════════════════════════════════════════════════════════════════════

impl IntoIterator for IpSet {
    type Item = IpAddr;
    type IntoIter = Box<dyn Iterator<Item = IpAddr> + Send>;

    /// Consumes the `IpSet` and returns an iterator over its individual IP addresses.
    fn into_iter(mut self) -> Self::IntoIter {
        self.canonicalize();
        let v4_iter = self.v4.into_iter().flat_map(|range| {
            let start: u32 = range.start_addr().into();
            let end: u32 = range.end_addr().into();
            (start..=end).map(|ip| IpAddr::V4(Ipv4Addr::from(ip)))
        });

        let v6_iter = self.v6.into_iter().flat_map(|range| {
            let start: u128 = range.start_addr().into();
            let end: u128 = range.end_addr().into();
            (start..=end).map(|ip| IpAddr::V6(Ipv6Addr::from(ip)))
        });

        Box::new(v4_iter.chain(v6_iter))
    }
}

impl Extend<IpAddr> for IpSet {
    /// Marks only the families that actually gained a range.
    ///
    /// A set is merged per family, so extending with IPv4 addresses alone must
    /// not put IPv6 membership back on its slow path, and extending with
    /// nothing must not undo a `canonicalize` that has already run.
    ///
    /// Marking the family is half of that; the other half is that every read
    /// asks about the family it is reading, which is
    /// [`IpSet::contains`]'s to do and was the half that was missing.
    fn extend<T: IntoIterator<Item = IpAddr>>(&mut self, iter: T) {
        for ip in iter {
            match ip {
                IpAddr::V4(v4) => self.push_v4_range(Ipv4Range::single(v4)),
                IpAddr::V6(v6) => self.push_v6_range(Ipv6Range::single(v6)),
            }
        }
    }
}

impl FromIterator<IpAddr> for IpSet {
    fn from_iter<I: IntoIterator<Item = IpAddr>>(iter: I) -> Self {
        let mut set = IpSet::new();
        set.extend(iter);
        set.canonicalize();
        set
    }
}

impl FromIterator<IpRange> for IpSet {
    fn from_iter<I: IntoIterator<Item = IpRange>>(iter: I) -> Self {
        let mut set = IpSet::new();
        for range in iter {
            set.insert_range(range);
        }
        set.canonicalize();
        set
    }
}

impl FromIterator<IpSet> for IpSet {
    fn from_iter<I: IntoIterator<Item = IpSet>>(iter: I) -> Self {
        let mut master = IpSet::new();
        for set in iter {
            if !set.v4.is_empty() {
                master.v4.extend(set.v4);
                master.v4_dirty = true;
            }
            if !set.v6.is_empty() {
                master.v6.extend(set.v6);
                master.v6_dirty = true;
            }
        }
        master.canonicalize();
        master
    }
}

impl From<IpAddr> for IpSet {
    fn from(ip: IpAddr) -> Self {
        let mut set = Self::new();
        set.insert(ip);
        set
    }
}

impl From<IpRange> for IpSet {
    fn from(range: IpRange) -> Self {
        let mut set = Self::new();
        set.insert_range(range);
        set
    }
}

impl TryFrom<&str> for IpSet {
    type Error = IpSetError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut set = IpSet::new();
        for part in value
            .split([',', ' '])
            .filter(|part| !part.trim().is_empty())
        {
            let range = part.parse::<IpRange>()?;
            set.insert_range(range);
        }
        set.canonicalize();
        Ok(set)
    }
}

impl FromStr for IpSet {
    type Err = IpSetError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
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

    /// The lazy state, seen from outside: two adjacent addresses stay two
    /// ranges until canonicalized, then become one, and the count is right
    /// either way.
    #[test]
    fn adjacent_addresses_merge_when_the_set_is_canonicalized() {
        let mut set = IpSet::new();
        set.insert(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        set.insert(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)));

        // Before canonicalization, they stay as individual pushes
        assert_eq!(set.v4.len(), 2);
        assert!(set.v4_dirty);

        // Explicitly canonicalize since queries are now immutable
        set.canonicalize();
        assert_eq!(set.len(), 2);
        assert!(!set.v4_dirty);
        assert_eq!(set.v4.len(), 1);
    }

    /// Every arrangement two ranges can be in — overlapping at the start, at
    /// the end, disjoint, and one subsuming the rest — collapsing to the single
    /// range that covers them. Counted once each, which is what makes `len` a
    /// number a budget can be checked against.
    #[test]
    fn every_kind_of_overlap_collapses_to_one_range() {
        let mut set = IpSet::new();
        // Insert: [10-20]
        set.insert_range("10.0.0.10-10.0.0.20".parse().unwrap());
        // Insert: [5-15] (overlap start)
        set.insert_range("10.0.0.5-10.0.0.15".parse().unwrap());
        // Insert: [15-25] (overlap end)
        set.insert_range("10.0.0.15-10.0.0.25".parse().unwrap());
        // Insert: [30-40] (disjoint)
        set.insert_range("10.0.0.30-10.0.0.40".parse().unwrap());
        // Insert: [0-50] (subsume all)
        set.insert_range("10.0.0.0-10.0.0.50".parse().unwrap());

        set.canonicalize();
        assert_eq!(set.len(), 51);
        assert_eq!(set.v4().len(), 1);
    }

    /// Adjacency is tested with a saturating add, so two addresses at the very
    /// top of the IPv6 space still merge rather than overflowing into a
    /// comparison that fails.
    #[test]
    fn the_top_of_the_ipv6_space_merges_without_overflowing() {
        let mut set = IpSet::new();
        // ::f...f (max)
        let max_v6 = Ipv6Addr::from(u128::MAX);
        let max_minus_1 = Ipv6Addr::from(u128::MAX - 1);

        set.insert(IpAddr::V6(max_minus_1));
        set.insert(IpAddr::V6(max_v6));

        set.canonicalize();
        assert_eq!(set.len(), 2);
        assert_eq!(set.v6().len(), 1);
    }

    /// Iterating is a read: it yields every address once and leaves the set in
    /// the state it found it, so a caller can iterate a set it is still
    /// building.
    #[test]
    fn iterating_yields_each_address_without_mutating_the_set() {
        let mut set = IpSet::new();
        set.insert(IpAddr::V4(Ipv4Addr::from(1)));
        set.insert(IpAddr::V4(Ipv4Addr::from(2)));

        set.canonicalize();
        let ips: Vec<IpAddr> = set.iter().collect();
        assert_eq!(ips.len(), 2);
        assert!(!set.v4_dirty);
    }

    /// Canonicalizing an empty set is a no-op rather than an error, so a caller
    /// that built nothing does not have to check before reading.
    #[test]
    fn an_empty_set_canonicalizes_and_counts_as_zero() {
        let mut set = IpSet::new();
        set.canonicalize();
        assert_eq!(set.len_canonical(), 0);
        assert!(set.v4().is_empty());
    }

    /// A set is merged per family, so work on one must not undo the other's
    /// canonical state. Marking both put IPv6 membership back on its linear
    /// path every time an IPv4 address arrived.
    ///
    /// The flags are half of it and were the half that already worked. The
    /// assertion that matters is the last one: that a read of the untouched
    /// family still takes its fast path. Marking the family and then asking
    /// about both is the same linear scan by a longer route, and it is what
    /// this test used to allow, because it checked the bookkeeping and never
    /// the thing the bookkeeping is for.
    #[test]
    fn extending_one_family_leaves_the_other_canonical() {
        let mut set = IpSet::from_iter(vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);
        assert!(!set.v4_dirty && !set.v6_dirty, "from_iter canonicalizes");

        set.extend([IpAddr::V4(Ipv4Addr::LOCALHOST)]);

        assert!(set.v4_dirty, "the family that gained a range");
        assert!(!set.v6_dirty, "and only that one");

        // And extending with nothing does not undo a merge that already ran.
        let mut untouched = IpSet::from_iter(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        untouched.extend([]);
        assert!(!untouched.v4_dirty && !untouched.v6_dirty);

        // The point of marking one family: the other keeps its binary search.
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(set.is_merged(&v6), "an unmerged IPv4 range is not IPv6's");
        assert!(!set.is_merged(&v4), "and IPv4's own half is not merged");

        // Which the guarded fast path is entitled to be handed, and answers.
        assert!(set.contains_canonical(&v6));
        assert!(set.contains(&v6));
        assert!(set.contains(&v4), "the slow path is still correct");
    }

    /// One string naming both families, with a duplicate across two spellings
    /// that has to be counted once.
    #[test]
    fn a_written_set_may_mix_both_families_and_still_counts_distinctly() {
        let set = IpSet::from_str("1.1.1.1/32, 1.1.1.1, ::1-::1, 10.0.0.1-10.0.0.2").unwrap();
        // 1.1.1.1 (v4) + ::1 (v6) + 10.0.0.1, 10.0.0.2 (v4)
        assert_eq!(set.len(), 4);
    }

    /// Insertion appends and defers the merge, so a hundred addresses are a
    /// hundred ranges until `canonicalize` runs. That is the whole point of the
    /// split — merging on each insertion makes loading a target file quadratic.
    #[test]
    fn insertion_defers_the_merge_until_it_is_asked_for() {
        let mut set = IpSet::new();
        let ips = (0..100).map(|i| IpAddr::V4(Ipv4Addr::from(i)));
        set.extend(ips);

        assert_eq!(set.v4.len(), 100);
        set.canonicalize();
        assert_eq!(set.v4.len(), 1);
        assert_eq!(set.len(), 100);
    }

    /// The guard is the only thing that makes the private fast paths safe to
    /// have at all: `contains_canonical` binary-searches a vector that is
    /// sorted only once `canonicalize` has run, and against an unmerged one it
    /// silently misses. A wrong answer about whether an address is in scope
    /// decides whether a reply is credited or discarded, so a test that never
    /// trips the assertion is testing nothing, and would pass with the
    /// `debug_assert!` deleted.
    ///
    /// Debug-only because that is where the assertion exists; a release build
    /// compiles it out and takes the silently-wrong path this pins.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "must be canonicalized")]
    fn a_membership_query_on_an_unmerged_set_trips_the_guard() {
        let mut set = IpSet::new();
        set.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
        // Deliberately not canonicalized.
        set.contains_canonical(&IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    /// And the same for the count, which has its own guard for its own reason.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "must be canonicalized")]
    fn a_count_on_an_unmerged_set_trips_the_guard() {
        let mut set = IpSet::new();
        set.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
        set.len_canonical();
    }

    /// The case the guards let through, and the one the public `contains`
    /// delegates to once the set is merged.
    #[test]
    fn a_membership_query_on_a_merged_set_answers() {
        let set = IpSet::from_iter(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        assert!(!set.v4_dirty, "from_iter canonicalizes");
        assert!(set.contains_canonical(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(set.len_canonical(), 1);
    }

    /// Two link-local ranges spanning the same numbers on two interfaces are
    /// two different sets of machines. Merged on adjacency alone they would
    /// produce one range that means one thing at one end and something else at
    /// the other. Every interface holds an `fe80::/64`, so the mistake is
    /// available on any host with two of them.
    #[test]
    fn ranges_on_different_interfaces_never_merge_however_adjacent() {
        let one: Ipv6Addr = "fe80::1".parse().unwrap();
        let five: Ipv6Addr = "fe80::5".parse().unwrap();
        let six: Ipv6Addr = "fe80::6".parse().unwrap();
        let ten: Ipv6Addr = "fe80::a".parse().unwrap();

        let mut split = IpSet::new();
        split.push_v6_range(Ipv6Range::scoped(one, five, Some(4)).unwrap());
        split.push_v6_range(Ipv6Range::scoped(six, ten, Some(9)).unwrap());
        split.canonicalize();

        assert_eq!(split.v6().len(), 2, "adjacent, but on two segments");

        // The same numbers on one interface are one segment's worth of
        // machines, and do merge — or the zone check would be refusing
        // everything rather than refusing the right thing.
        let mut joined = IpSet::new();
        joined.push_v6_range(Ipv6Range::scoped(one, five, Some(4)).unwrap());
        joined.push_v6_range(Ipv6Range::scoped(six, ten, Some(4)).unwrap());
        joined.canonicalize();

        assert_eq!(joined.v6().len(), 1);

        // Membership still answers across the split.
        assert!(split.contains(&IpAddr::V6(five)));
        assert!(split.contains(&IpAddr::V6(six)));
    }

    /// Equality is about the addresses a set holds, not about whether it has
    /// been merged yet. Derived, it compared the dirty flags and the range
    /// vectors as written, so the same one address inserted two ways compared
    /// unequal — and `assert_eq!` on two sets was answering a question about
    /// bookkeeping.
    #[test]
    fn two_sets_holding_the_same_addresses_are_equal_however_they_were_built() {
        let canonical = IpSet::try_from("10.0.0.1-10.0.0.2, ::1").expect("parses");

        let mut piecemeal = IpSet::new();
        piecemeal.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
        piecemeal.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        piecemeal.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        assert_eq!(canonical, piecemeal, "same addresses, different order");
        assert_ne!(canonical, IpSet::try_from("10.0.0.1, ::1").expect("parses"));
    }

    /// Refusing to merge across zones leaves ranges that *overlap* as well as
    /// ranges that abut, and a binary search cannot navigate an overlapping
    /// vector: it lands on a range that ends before the target, concludes the
    /// target lies further right, and never examines the range on its left
    /// that holds it.
    ///
    /// Two interfaces each carrying a slice of `fe80::/64` is the ordinary
    /// shape of a dual-homed segment, and a missed membership test there
    /// discards a reply from a host that did answer.
    #[test]
    fn membership_answers_when_ranges_on_different_interfaces_overlap() {
        let one: Ipv6Addr = "fe80::1".parse().unwrap();
        let two: Ipv6Addr = "fe80::2".parse().unwrap();
        let three: Ipv6Addr = "fe80::3".parse().unwrap();
        let ten: Ipv6Addr = "fe80::a".parse().unwrap();

        let mut set = IpSet::new();
        set.push_v6_range(Ipv6Range::scoped(one, ten, Some(4)).unwrap());
        set.push_v6_range(Ipv6Range::scoped(two, three, Some(9)).unwrap());
        set.canonicalize();

        for address in [one, two, three, ten] {
            assert!(
                set.contains(&IpAddr::V6(address)),
                "{address} is covered by the range on interface 4"
            );
        }
        assert!(!set.contains(&IpAddr::V6("fe80::b".parse().unwrap())));
    }
    // ─── Positions ───────────────────────────────────────────────────────────

    fn set(written: &str) -> IpSet {
        written.parse().expect("a valid address specification")
    }

    /// The one property everything else rests on: a position is an index into
    /// `iter`, and the two must agree address for address. If they drift, a
    /// resumed sweep skips addresses it never asked about and reports success.
    #[test]
    fn a_position_is_the_index_the_set_enumerates_at() {
        let set = set("192.0.2.1-192.0.2.10,198.51.100.0/30,2001:db8::1-2001:db8::5");
        let positions = set.positions();

        // `try_from` rather than `as`: the cast truncates a count too large to
        // number down to a total that matches the truncated numbering, so the
        // assertion held for exactly the sets it exists to catch.
        assert_eq!(positions.total(), u64::try_from(set.len()).unwrap());
        assert!(positions.unnumbered().is_empty());

        for (index, ip) in set.iter().enumerate() {
            let index = index as u64;
            assert_eq!(positions.find(ip), Some(index), "{ip} is not at {index}");
            assert_eq!(positions.address_at(index), Some(ip), "{index} is not {ip}");
        }
    }

    /// A `/64` holds one address more than a `u64` counts, so it is the first
    /// prefix the numbering cannot reach, and it is also the ordinary size of
    /// an IPv6 subnet.
    #[test]
    fn a_range_too_large_to_number_is_kept_rather_than_dropped() {
        let positions = set("2001:db8::/64").positions();

        assert_eq!(positions.total(), 0);
        assert_eq!(positions.unnumbered().len(), 1);
    }

    /// A sweep finds neighbours it was never asked about. They are findings,
    /// not plan targets, and numbering one would advance a cursor over a
    /// position belonging to something else.
    #[test]
    fn an_address_outside_the_plan_has_no_position() {
        let positions = set("192.0.2.1-192.0.2.10").positions();

        assert_eq!(
            positions.find("192.0.2.11".parse().expect("an address")),
            None
        );
        assert_eq!(
            positions.find("198.51.100.1".parse().expect("an address")),
            None
        );
        assert_eq!(
            positions.find("2001:db8::1".parse().expect("an address")),
            None,
            "the other family is not in the set either"
        );
        assert_eq!(positions.address_at(10), None, "past the end of the plan");
    }

    /// IPv4 is numbered before IPv6, which is what the enumeration does.
    #[test]
    fn the_families_are_numbered_in_the_order_they_are_walked() {
        let set = set("2001:db8::1,192.0.2.1");
        let positions = set.positions();

        assert_eq!(
            positions.find("192.0.2.1".parse().expect("an address")),
            Some(0)
        );
        assert_eq!(
            positions.find("2001:db8::1".parse().expect("an address")),
            Some(1)
        );
    }

    /// Narrowing a plan to what is left has to give back exactly the addresses
    /// at those positions — no more, since a re-probed address is waste, and no
    /// fewer, since a dropped one is a target silently skipped.
    #[test]
    fn the_addresses_in_a_span_of_positions_are_exactly_those_positions() {
        let set = set("192.0.2.1-192.0.2.10,2001:db8::1-2001:db8::4");
        let positions = set.positions();

        for (from, to) in [(0u64, 14u64), (0, 5), (3, 9), (9, 12), (13, 14), (7, 8)] {
            let mut narrowed = IpSet::new();
            for range in positions.ranges_in(from..to) {
                narrowed.insert_range(range);
            }
            narrowed.canonicalize();

            let expected: Vec<IpAddr> = set
                .iter()
                .skip(from as usize)
                .take((to - from) as usize)
                .collect();
            let found: Vec<IpAddr> = narrowed.iter().collect();

            assert_eq!(found, expected, "positions {from}..{to}");
        }
    }

    /// A span that runs past the end is clamped rather than refused, and an
    /// empty one gives back nothing.
    #[test]
    fn a_span_outside_the_plan_yields_nothing() {
        let positions = set("192.0.2.1-192.0.2.4").positions();

        assert!(positions.ranges_in(4..99).is_empty());
        assert!(positions.ranges_in(2..2).is_empty());
        assert_eq!(positions.ranges_in(0..99).len(), 1, "clamped to the plan");
    }

    /// An IPv6 range can hold more addresses than a position can count. The
    /// numbering stops there rather than wrapping, and IPv4, the half that is
    /// actually walked address by address, keeps its positions.
    #[test]
    fn a_range_too_large_to_number_ends_the_numbering_without_losing_ipv4() {
        let set = set("192.0.2.1-192.0.2.4,2001:db8::/64,2001:db9::1");
        let positions = set.positions();

        assert_eq!(positions.total(), 4, "only the IPv4 half is numbered");
        assert_eq!(
            positions.find("192.0.2.4".parse().expect("an address")),
            Some(3)
        );
        assert_eq!(
            positions.find("2001:db8::1".parse().expect("an address")),
            None,
            "an unnumbered address never settles, so it is asked again"
        );
        assert_eq!(
            positions.find("2001:db9::1".parse().expect("an address")),
            None,
            "and so is everything after it: positions have to stay contiguous"
        );
        assert_eq!(
            positions.unnumbered().len(),
            2,
            "both are kept, or a resumed sweep would never ask about them"
        );
    }

    /// A zoned range names one segment. A slice of it has to keep saying so,
    /// or a resumed sweep aims at `fe80::` on whichever interface comes first.
    #[test]
    fn a_slice_of_a_zoned_range_keeps_its_zone() {
        let mut set = IpSet::new();
        set.insert_range(IpRange::V6(
            Ipv6Range::scoped(
                "fe80::1".parse().expect("an address"),
                "fe80::8".parse().expect("an address"),
                Some(7),
            )
            .expect("a range"),
        ));
        set.canonicalize();

        let sliced = set.positions().ranges_in(2..5);
        assert_eq!(sliced.len(), 1);
        match sliced[0] {
            IpRange::V6(range) => assert_eq!(range.zone(), Some(7)),
            IpRange::V4(_) => panic!("an IPv6 range came back as IPv4"),
        }
    }

    /// `fe80::1` names a different machine on every segment, and the set keeps
    /// the two apart — sorted by zone first, so the IPv6 ranges are *not* one
    /// ascending sequence. A lookup that treated them as one would answer with
    /// whichever run it landed on, and settling an address at another
    /// interface's position lets a resume skip one nothing ever probed.
    ///
    /// A bare address cannot say which segment it came from, so the honest
    /// answer where two runs hold it is no position at all.
    #[test]
    fn an_address_two_interfaces_both_hold_has_no_position() {
        let mut both = IpSet::new();
        for zone in [5u32, 7] {
            both.insert_range(IpRange::V6(
                Ipv6Range::scoped(
                    "fe80::1".parse().expect("an address"),
                    "fe80::4".parse().expect("an address"),
                    Some(zone),
                )
                .expect("a range"),
            ));
        }
        both.canonicalize();

        let positions = both.positions();
        assert_eq!(
            positions.total(),
            8,
            "four addresses on each of two segments"
        );
        assert_eq!(
            positions.find("fe80::1".parse().expect("an address")),
            None,
            "two segments hold it and the address cannot say which"
        );
    }

    /// One interface holding it is not ambiguous, and must still resolve —
    /// otherwise a link-local sweep settles nothing at all.
    #[test]
    fn an_address_one_interface_holds_keeps_its_position() {
        let mut set = IpSet::new();
        set.insert_range(IpRange::V6(
            Ipv6Range::scoped(
                "fe80::1".parse().expect("an address"),
                "fe80::4".parse().expect("an address"),
                Some(7),
            )
            .expect("a range"),
        ));
        set.insert_range(IpRange::V6(
            Ipv6Range::scoped(
                "fe80::9".parse().expect("an address"),
                "fe80::a".parse().expect("an address"),
                Some(5),
            )
            .expect("a range"),
        ));
        set.canonicalize();

        let positions = set.positions();
        for (index, ip) in set.iter().enumerate() {
            assert_eq!(
                positions.find(ip),
                Some(index as u64),
                "{ip} is at {index} and no run but its own holds it"
            );
        }
    }

    /// An unmerged set enumerates differently from the canonical one every
    /// position is counted in, so numbering one has to merge it first.
    #[test]
    fn an_unmerged_set_is_numbered_as_the_canonical_one() {
        let mut lazy = IpSet::new();
        lazy.insert("192.0.2.2".parse().expect("an address"));
        lazy.insert("192.0.2.1".parse().expect("an address"));
        lazy.insert("192.0.2.2".parse().expect("an address"));

        let positions = lazy.positions();
        assert_eq!(positions.total(), 2, "the duplicate is one address");
        assert_eq!(
            positions.find("192.0.2.1".parse().expect("an address")),
            Some(0)
        );
        assert_eq!(
            positions.find("192.0.2.2".parse().expect("an address")),
            Some(1)
        );
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn any_ipv4() -> impl Strategy<Value = Ipv4Addr> {
        any::<u32>().prop_map(Ipv4Addr::from)
    }

    fn any_ipv6() -> impl Strategy<Value = Ipv6Addr> {
        any::<u128>().prop_map(Ipv6Addr::from)
    }

    /// Zoned ranges drawn from one narrow band of `fe80::/64`, so that
    /// generated ranges overlap each other often rather than by luck. Four
    /// zones, which is the shape of a multi-homed host.
    fn any_zoned_v6_range() -> impl Strategy<Value = Ipv6Range> {
        (0..64u128, 0..64u128, prop::option::of(0..4u32)).prop_map(|(a, b, zone)| {
            let base = u128::from(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0));
            let (low, high) = if a <= b { (a, b) } else { (b, a) };
            Ipv6Range::scoped(
                Ipv6Addr::from(base + low),
                Ipv6Addr::from(base + high),
                zone,
            )
            .expect("low <= high")
        })
    }

    // ─── Set difference ──────────────────────────────────────────────────────

    /// Builds a v4 set from `[start, end]` pairs written as last octets of
    /// `10.0.0.0/24`, which is enough address space to arrange every overlap a
    /// difference has to handle and short enough to read.
    /// A canonical set of both families, small enough to walk in a test but
    /// varied enough to put more than one range in each family — and to put the
    /// same IPv6 address on more than one interface, which is the shape that
    /// stops the ranges being one ascending sequence.
    fn any_ipset() -> impl Strategy<Value = IpSet> {
        (
            prop::collection::vec((0u8..40, 0u8..6), 0..4),
            prop::collection::vec((0u16..40, 0u16..6, prop::option::of(1u32..3)), 0..4),
        )
            .prop_map(|(v4, v6)| {
                let mut set = IpSet::new();
                for (start, span) in v4 {
                    let first = Ipv4Addr::new(192, 0, 2, start);
                    let last = Ipv4Addr::new(192, 0, 2, start.saturating_add(span));
                    set.insert_range(IpRange::V4(
                        Ipv4Range::new(first, last).expect("ordered by construction"),
                    ));
                }
                for (start, span, zone) in v6 {
                    let first = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, start);
                    let last =
                        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, start.saturating_add(span));
                    set.insert_range(IpRange::V6(
                        Ipv6Range::scoped(first, last, zone).expect("ordered by construction"),
                    ));
                }
                set.canonicalize();
                set
            })
    }

    fn v4_set(spans: &[(u8, u8)]) -> IpSet {
        let mut set = IpSet::new();
        for &(start, end) in spans {
            set.push_v4_range(
                Ipv4Range::new(Ipv4Addr::new(10, 0, 0, start), Ipv4Addr::new(10, 0, 0, end))
                    .expect("start <= end"),
            );
        }
        set.canonicalize();
        set
    }

    /// The same shorthand, read back out.
    fn v4_spans(set: &IpSet) -> Vec<(u8, u8)> {
        set.v4()
            .iter()
            .map(|r| (r.start_addr().octets()[3], r.end_addr().octets()[3]))
            .collect()
    }

    /// Every way one cut can meet one range: through the middle, off each end,
    /// swallowing it whole, and missing entirely.
    ///
    /// Split out one arrangement per case because the middle cut is the only
    /// one that produces *more* ranges than it started with, and a difference
    /// that quietly drops either side of it still passes a count check.
    #[test]
    fn a_cut_takes_exactly_what_it_covers() {
        /// A target, what is cut from it, and what should be left: last octets
        /// of `10.0.0.0/24`, which is enough room for every arrangement and
        /// short enough to read down the column.
        type Case = (
            &'static [(u8, u8)],
            &'static [(u8, u8)],
            &'static [(u8, u8)],
        );

        let cases: [Case; 6] = [
            // Through the middle: one range becomes two.
            (&[(10, 20)], &[(14, 16)], &[(10, 13), (17, 20)]),
            // Off the front, off the back.
            (&[(10, 20)], &[(5, 12)], &[(13, 20)]),
            (&[(10, 20)], &[(18, 25)], &[(10, 17)]),
            // Swallowed whole, and exactly.
            (&[(10, 20)], &[(5, 25)], &[]),
            (&[(10, 20)], &[(10, 20)], &[]),
            // Adjacent but not overlapping, which must remove nothing.
            (&[(10, 20)], &[(21, 30)], &[(10, 20)]),
        ];

        for (target, cut, expected) in cases {
            let mut set = v4_set(target);
            set.subtract(&v4_set(cut));
            assert_eq!(v4_spans(&set), expected, "{target:?} minus {cut:?}");
        }
    }

    /// One cut spanning several ranges, and several cuts inside one range.
    ///
    /// Both directions of the walk at once: the first needs a cut to stay in
    /// front of the range after the one it just consumed, the second needs the
    /// cursor to survive being moved repeatedly inside a single range. Each is
    /// an index the pass could advance one step too far.
    #[test]
    fn the_difference_walks_both_sides_once() {
        let mut set = v4_set(&[(10, 20), (30, 40), (50, 60)]);
        set.subtract(&v4_set(&[(15, 55)]));
        assert_eq!(v4_spans(&set), vec![(10, 14), (56, 60)]);

        let mut set = v4_set(&[(10, 40)]);
        set.subtract(&v4_set(&[(12, 14), (20, 22), (30, 32)]));
        assert_eq!(v4_spans(&set), vec![(10, 11), (15, 19), (23, 29), (33, 40)]);
    }

    /// A range ending at the last address of its family, cut from below.
    ///
    /// The arithmetic walking a cut forward is `cut_end + 1`, and the tail
    /// emission is the branch that must not compute `end + 1`. Both families,
    /// because only the v6 one is a `u128` where the overflow is unrepresentable
    /// rather than merely wrong.
    #[test]
    fn a_range_ending_at_the_last_address_survives_a_cut() {
        let mut set = IpSet::new();
        set.push_v4_range(
            Ipv4Range::new(
                Ipv4Addr::new(255, 255, 255, 250),
                Ipv4Addr::new(255, 255, 255, 255),
            )
            .expect("start <= end"),
        );
        set.push_v6_range(
            Ipv6Range::new(Ipv6Addr::from(u128::MAX - 5), Ipv6Addr::from(u128::MAX))
                .expect("start <= end"),
        );
        set.canonicalize();

        let mut cuts = IpSet::new();
        cuts.insert(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 252)));
        cuts.insert(IpAddr::V6(Ipv6Addr::from(u128::MAX - 2)));

        set.subtract(&cuts);

        assert!(!set.contains(&IpAddr::V4(Ipv4Addr::new(255, 255, 255, 252))));
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
        assert!(!set.contains(&IpAddr::V6(Ipv6Addr::from(u128::MAX - 2))));
        assert!(set.contains(&IpAddr::V6(Ipv6Addr::from(u128::MAX))));
    }

    /// A subtraction cuts an address out of every interface it appears on, and
    /// leaves the zones of what survives intact.
    ///
    /// The blindness is deliberate and documented on `subtract`: it is the
    /// direction that removes more, and it is the only reading that agrees with
    /// `contains`, which cannot see a zone either. The second half is the part
    /// that would break silently — a difference that rebuilt the surviving
    /// pieces without their zone would leave link-local ranges naming no
    /// interface, and those cannot be probed at all.
    #[test]
    fn subtracting_a_link_local_address_clears_it_from_every_interface() {
        let base = u128::from(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0));
        let mut set = IpSet::new();
        for zone in [1u32, 2u32] {
            set.push_v6_range(
                Ipv6Range::scoped(
                    Ipv6Addr::from(base + 10),
                    Ipv6Addr::from(base + 20),
                    Some(zone),
                )
                .expect("start <= end"),
            );
        }
        set.canonicalize();

        // Named on one interface only, and still removed from both.
        let mut cuts = IpSet::new();
        cuts.push_v6_range(
            Ipv6Range::scoped(
                Ipv6Addr::from(base + 15),
                Ipv6Addr::from(base + 15),
                Some(1),
            )
            .expect("start <= end"),
        );
        cuts.canonicalize();

        set.subtract(&cuts);

        assert!(!set.contains(&IpAddr::V6(Ipv6Addr::from(base + 15))));
        assert_eq!(set.len(), 20);
        assert_eq!(
            set.v6().iter().filter(|r| r.zone().is_none()).count(),
            0,
            "every surviving piece keeps the interface of the range it came from"
        );
    }

    proptest::proptest! {
        /// The numbering and the enumeration must agree over *any* set, not
        /// only the hand-written ones. A position is an index into `iter`, and
        /// a resumed sweep subtracts positions from a plan — so a set where the
        /// two disagree is one where addresses are silently skipped.
        ///
        /// The exception is an address more than one interface holds. A bare
        /// address cannot say which of its positions it means, so `find`
        /// answers `None` and it is asked again. That is allowed; answering
        /// with the *wrong* one of them is not, which is what the equality
        /// below rules out.
        #[test]
        fn a_position_is_the_enumeration_index_for_any_set(
            set in any_ipset(),
        ) {
            let positions = set.positions();
            let walked: Vec<IpAddr> = set.iter().collect();

            prop_assert_eq!(positions.total() as usize, walked.len());
            for (index, ip) in walked.iter().enumerate() {
                // `address_at` is unambiguous in this direction: a position
                // names one address however many positions the address has.
                prop_assert_eq!(positions.address_at(index as u64), Some(*ip));

                let held_twice = walked.iter().filter(|other| *other == ip).count() > 1;
                match positions.find(*ip) {
                    Some(found) => prop_assert_eq!(found, index as u64),
                    None => prop_assert!(held_twice, "{} has one position and no answer", ip),
                }
            }
        }

        /// Narrowing to a span of positions gives back exactly those addresses,
        /// whatever the set's shape. Too few is a target skipped; too many is
        /// work repeated.
        #[test]
        fn a_span_of_positions_narrows_to_exactly_those_addresses(
            set in any_ipset(),
            from in 0usize..40,
            span in 0usize..40,
        ) {
            let positions = set.positions();
            let walked: Vec<IpAddr> = set.iter().collect();

            let mut narrowed = IpSet::new();
            for range in positions.ranges_in(from as u64..(from + span) as u64) {
                narrowed.insert_range(range);
            }
            narrowed.canonicalize();

            let expected: Vec<IpAddr> = walked.into_iter().skip(from).take(span).collect();
            let found: Vec<IpAddr> = narrowed.iter().collect();
            prop_assert_eq!(found, expected);
        }

        /// Membership has to agree with a linear scan of the same ranges.
        ///
        /// The fast path is a binary search, which is only valid over ranges
        /// that do not overlap. Zones are what put overlapping ranges in one
        /// vector — `merge_v6` refuses to combine ranges from two interfaces —
        /// so this is where a search that steps past the range holding the
        /// target shows up. An example of that is pinned in
        /// `membership_answers_when_ranges_on_different_interfaces_overlap`;
        /// this covers the arrangements nobody thought to write down.
        #[test]
        fn zoned_membership_agrees_with_a_linear_scan(
            ranges in prop::collection::vec(any_zoned_v6_range(), 1..12),
            offsets in prop::collection::vec(0..80u128, 1..20),
        ) {
            let mut set = IpSet::new();
            for range in &ranges {
                set.push_v6_range(*range);
            }
            set.canonicalize();

            let base = u128::from(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0));
            for offset in offsets {
                let probe = Ipv6Addr::from(base + offset);
                let expected = ranges.iter().any(|range| range.contains(&probe));
                prop_assert_eq!(
                    set.contains(&IpAddr::V6(probe)),
                    expected,
                    "{} in {:?}", probe, ranges
                );
            }
        }

        /// Membership after a difference, against the definition of one.
        ///
        /// The pass is a single walk of two ascending slices with an index that
        /// only moves forward, which is fast and has several places to be off by
        /// one that no hand-written arrangement is likely to visit. So this
        /// asserts the property itself — an address survives exactly when it was
        /// there and was not cut — probed at the boundaries, which is where a
        /// difference goes wrong if it goes wrong at all.
        #[test]
        fn a_difference_keeps_exactly_what_was_not_cut(
            target in prop::collection::vec((0..64u8, 0..64u8), 1..8),
            cuts in prop::collection::vec((0..64u8, 0..64u8), 0..8),
        ) {
            let spans = |raw: &[(u8, u8)]| -> Vec<(u8, u8)> {
                raw.iter()
                    .map(|&(a, b)| if a <= b { (a, b) } else { (b, a) })
                    .collect()
            };
            let target = spans(&target);
            let cuts = spans(&cuts);

            let before = v4_set(&target);
            let cut_set = v4_set(&cuts);
            let mut after = before.clone();
            after.subtract(&cut_set);

            for probe in 0..=65u8 {
                let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, probe));
                prop_assert_eq!(
                    after.contains(&ip),
                    before.contains(&ip) && !cut_set.contains(&ip),
                    "{} after {:?} minus {:?}", ip, target, cuts
                );
            }

            // The result has to be canonical, or every read after it silently
            // takes the slow path and `holds` may search a vector it cannot.
            let mut recanonicalized = after.clone();
            recanonicalized.canonicalize();
            prop_assert_eq!(after.v4(), recanonicalized.v4());
        }

        #[test]
        fn v4_membership_invariant(ips in proptest::collection::vec(any_ipv4(), 1..50)) {
            let mut set = IpSet::new();
            for &ip in &ips {
                set.insert(IpAddr::V4(ip));
            }
            for ip in ips {
                prop_assert!(set.contains(&IpAddr::V4(ip)));
            }
        }

        #[test]
        fn v6_membership_invariant(ips in proptest::collection::vec(any_ipv6(), 1..50)) {
            let mut set = IpSet::new();
            for &ip in &ips {
                set.insert(IpAddr::V6(ip));
            }
            for ip in ips {
                prop_assert!(set.contains(&IpAddr::V6(ip)));
            }
        }

        #[test]
        fn order_independence_mixed(
            ips in proptest::collection::vec(
                prop_oneof![
                    any_ipv4().prop_map(IpAddr::V4),
                    any_ipv6().prop_map(IpAddr::V6),
                ],
                0..50
            )
        ) {
            let mut set1 = IpSet::new();
            let mut set2 = IpSet::new();

            for &ip in &ips { set1.insert(ip); }
            let mut ips_rev = ips.clone();
            ips_rev.reverse();
            for &ip in &ips_rev { set2.insert(ip); }

            set1.canonicalize();
            set2.canonicalize();
            prop_assert_eq!(set1, set2);
        }
    }
}
