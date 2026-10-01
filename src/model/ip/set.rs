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
//! Insertion appends in constant time; sorting and merging is `O(n log n)` and happens
//! once, at [`IpSet::canonicalize`]. A target file can name tens of thousands of ranges,
//! and merging after each would make loading quadratic.
//!
//! Every query is correct either way: [`contains`](IpSet::contains) and
//! [`len`](IpSet::len) take a fast path over merged ranges and a slower one otherwise.
//! Canonicalize when a set stops being built and starts being read.
//!
//! [`TargetSet::new`](crate::model::target::TargetSet::new) canonicalizes what it is
//! given, so everything downstream of a `TargetSet` reads merged ranges.

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
/// Wraps the range grammar's error. For the richer
/// [`IpParseError`](crate::model::parse::ip::IpParseError), which names both prefix
/// bounds and quotes the expression, use [`to_set`](crate::model::parse::ip::to_set);
/// `parse` depends on `ip`, so this module cannot use it.
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
/// Merges overlapping and adjacent ranges lazily.
///
/// Equality is over the addresses held; see the hand-written [`PartialEq`].
#[derive(Debug, Clone, Default, Eq)]
pub struct IpSet {
    v4: Vec<Ipv4Range>,
    v6: Vec<Ipv6Range>,
    v4_dirty: bool,
    v6_dirty: bool,
}

/// How many ranges this thread has added to a set, a single address being a
/// range of one, for a test that has to know a set was built from only what
/// it needed to hold.
///
/// Counted where a range first enters a set. Per thread, so concurrent tests do not
/// interfere.
#[cfg(test)]
pub(crate) mod ranges_added {
    use std::cell::Cell;

    thread_local! {
        static ADDED: Cell<usize> = const { Cell::new(0) };
    }

    /// Counts one range added.
    pub(super) fn note() {
        ADDED.with(|added| added.set(added.get() + 1));
    }

    /// How many ranges this thread has added.
    pub(crate) fn so_far() -> usize {
        ADDED.with(Cell::get)
    }
}

impl IpSet {
    /// Creates a new, empty `IpSet`.
    pub fn new() -> Self {
        Self::default()
    }

    // ─── Insertion API ───────────────────────────────────────────────────────

    /// Adds a single IP address to the set.
    ///
    /// Constant time: it appends and defers the merge.
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
        #[cfg(test)]
        ranges_added::note();
        self.v4.push(range);
        self.v4_dirty = true;
    }

    /// Appends an IPv6 range without immediate merging.
    pub fn push_v6_range(&mut self, range: Ipv6Range) {
        #[cfg(test)]
        ranges_added::note();
        self.v6.push(range);
        self.v6_dirty = true;
    }

    /// Sorts and merges the ranges, so that every read afterwards takes its
    /// fast path.
    ///
    /// Call it once the set stops being built. Not required for correctness, but an
    /// unmerged set answers by scanning, which a set read per received packet should
    /// not.
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
    /// The same link-local numbers on two interfaces are two sets of machines, so
    /// ranges merge only when their zones agree.
    ///
    /// Sorted by zone first, leaving one run per interface, each sorted and disjoint,
    /// which [`v6_runs`](Self::v6_runs) hands the binary search. Grouping by zone also
    /// keeps same-zone ranges adjacent, so they always merge.
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
    /// This set is canonicalized first and left that way; `other` is read in whatever
    /// state it is in. Afterwards [`contains`](Self::contains) answers `false` for every
    /// address `other` contained, which makes this usable as a policy.
    ///
    /// Ignores zones, as [`contains`](Self::contains) does: a range in `other` removes
    /// those addresses from every interface. The two must agree, since received replies
    /// arrive as bare addresses. This errs toward removing more, which is the safe
    /// direction for withholding addresses from a scan.
    ///
    /// Linear in the *ranges* of both sides: subtracting a `/24` from a `/8` is a
    /// handful of comparisons.
    pub fn subtract(&mut self, other: &IpSet) {
        if other.is_empty() || self.is_empty() {
            return;
        }
        self.canonicalize();

        if !self.v4.is_empty() {
            let cuts = merged_intervals(other.v4.iter().map(v4_bounds));
            if !cuts.is_empty() {
                self.v4 = subtract_run(&self.v4, &cuts, v4_bounds, |_, start, end| {
                    // Both ends came from a `u32`-derived range and only narrow, so
                    // the casts are exact.
                    Ipv4Range::new(Ipv4Addr::from(start as u32), Ipv4Addr::from(end as u32))
                        .unwrap_or_else(|_| unreachable!("a narrowed range keeps start <= end"))
                });
            }
        }

        if !self.v6.is_empty() {
            let cuts = merged_intervals(other.v6.iter().map(v6_bounds));
            if !cuts.is_empty() {
                // One run per interface, since only within a run are the ranges
                // disjoint. Each piece keeps its zone, so the result stays grouped
                // as `merge_v6` left it.
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
    /// Each slice is sorted and disjoint, as [`holds`] needs; the vector as a whole is
    /// not. One slice per distinct zone.
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
    /// Ignores zones: callers filter received replies, which arrive as bare addresses,
    /// and the receiving strategy is already bound to one segment.
    ///
    /// Correct in any state: a binary search when the address's family is merged, a
    /// non-allocating linear scan when it is not. Checked per family, so an unmerged
    /// IPv4 range does not slow IPv6 lookups.
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
    /// Overlaps count once, so an unmerged set is merged on a clone first.
    /// [`len_gross`](Self::len_gross) is the cheap over-estimate.
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
    /// One pass and no allocation, unlike [`len`](Self::len) on an unmerged set. Never
    /// lower than the true count, so a budget check errs early.
    pub fn len_gross(&self) -> u128 {
        self.v4_len().saturating_add(self.v6_len())
    }

    /// Every address the set covers, one at a time, IPv4 before IPv6.
    ///
    /// Each address once, however many ranges named it, so an unmerged set is merged
    /// on a clone; call [`canonicalize`](Self::canonicalize) first to skip the copy.
    ///
    /// Lazy: nothing is materialized.
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

    /// Every address the set covers, each paired with the interface index it is
    /// only meaningful on.
    ///
    /// The zone lives on the range, so [`iter`](Self::iter) cannot report it. An IPv6
    /// address yields its range's zone; IPv4 always yields `None`.
    ///
    /// ```
    /// use zond_engine::model::ip::{IpRange, set::IpSet};
    /// use zond_engine::model::ip::range::Ipv6Range;
    /// use std::net::{IpAddr, Ipv6Addr};
    ///
    /// let addr: Ipv6Addr = "fe80::1".parse().unwrap();
    /// let mut set = IpSet::new();
    /// set.insert_range(IpRange::V6(Ipv6Range::scoped(addr, addr, Some(7)).unwrap()));
    ///
    /// let held: Vec<_> = set.iter_scoped().collect();
    /// assert_eq!(held, vec![(IpAddr::V6(addr), Some(7))]);
    /// ```
    pub fn iter_scoped(&self) -> Box<dyn Iterator<Item = (IpAddr, Option<u32>)> + Send> {
        let (v4, v6) = if self.v4_dirty || self.v6_dirty {
            let mut merged = self.clone();
            merged.canonicalize();
            (merged.v4, merged.v6)
        } else {
            (self.v4.clone(), self.v6.clone())
        };

        let v4 = v4.into_iter().flat_map(|range| {
            let start: u32 = range.start_addr().into();
            let end: u32 = range.end_addr().into();
            (start..=end).map(|ip| (IpAddr::V4(Ipv4Addr::from(ip)), None))
        });
        let v6 = v6.into_iter().flat_map(|range| {
            let zone = range.zone();
            let start: u128 = range.start_addr().into();
            let end: u128 = range.end_addr().into();
            (start..=end).map(move |ip| (IpAddr::V6(Ipv6Addr::from(ip)), zone))
        });

        Box::new(v4.chain(v6))
    }

    // ─── Query API (Read-Only / Sync) ────────────────────────────────────────

    /// Whether the family `ip` belongs to has been merged.
    ///
    /// What [`contains`](Self::contains) checks before its fast path, per family. Over a
    /// thousand merged IPv6 ranges with one IPv4 address pushed afterwards, twenty
    /// thousand lookups took 276 ms on the linear path and 6.5 ms on the merged one.
    fn is_merged(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => !self.v4_dirty,
            IpAddr::V6(_) => !self.v6_dirty,
        }
    }

    /// The fast path [`contains`](Self::contains) takes on a merged family.
    ///
    /// Private, since only a debug assertion guards against searching unsorted ranges,
    /// and a wrong answer decides whether a reply is credited.
    ///
    /// # Panics
    ///
    /// In debug builds, if the address's own family has unmerged ranges pending.
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
    /// Per family, for a sweep that spaces ARP against neighbour solicitation by their
    /// relative volume. Overlaps count twice; these only steer pacing.
    ///
    /// Saturating, as [`Ipv6Range::len`](crate::model::ip::range::Ipv6Range::len) is.
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
    /// Hand-written, since a derive would compare the raw range vectors and dirty
    /// flags.
    ///
    /// An unmerged set is merged on a clone, as in [`len`](Self::len). Two
    /// canonicalized sets compare without allocating.
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
/// An address's index in [`IpSet::iter`]'s walk (merged IPv4 ranges ascending, then
/// IPv6) is its **position**. A sweep is counted in positions, as a port scan is in
/// [`PlannedTarget`](crate::model::target::PlannedTarget)s, so a journal records
/// progress without listing addresses.
///
/// Built from the ranges: a `/8` costs one entry and a lookup is a binary search, so
/// this is cheap enough to consult per probe.
///
/// # A set larger than a position can count
///
/// A position is a `u64`, and a `/64` is one address past what that counts. Ranges are
/// numbered in order until one would not fit, and the rest is **unnumbered**:
/// [`find`](Self::find) answers `None` and [`unnumbered`](Self::unnumbered) returns it
/// whole. Unnumbered addresses are asked again on every sitting. IPv4 is numbered first,
/// so it is never lost.
#[derive(Debug, Clone, Default)]
pub struct Positions {
    /// The ranges in enumeration order, each with the position of its first
    /// address. IPv4 before IPv6, ascending within each.
    spans: Vec<Span>,
    /// The stretches of `spans` that are sorted and disjoint *by address*, so
    /// that a binary search inside one is valid.
    ///
    /// IPv4 is one run; IPv6 is one per interface, since the set sorts by zone first.
    /// [`contains`](IpSet::contains) walks the same runs.
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
    /// An unmerged set is merged on a clone first, since positions count the canonical
    /// enumeration.
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
            // The first range that will not fit ends the numbering, since positions
            // must stay contiguous. The rest is kept so a resumed sitting asks
            // about it.
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
    /// A plan whose first range is too large is empty by this; see
    /// [`unnumbered`](Self::unnumbered).
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// The ranges the numbering could not reach, in enumeration order.
    ///
    /// Empty for every IPv4 plan and every IPv6 plan narrower than a `/64`. A resumed
    /// sweep asks about these again, since nothing is recorded against them.
    pub fn unnumbered(&self) -> &[IpRange] {
        &self.unnumbered
    }

    /// Where `ip` falls in the enumeration, or `None` when the set does not hold
    /// it or holds it beyond what a position can count.
    ///
    /// Addresses a sweep finds without being asked have no position.
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
    /// For narrowing a plan to what a resumed sweep still has to ask, as a handful of
    /// ranges.
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
    /// An `IpAddr` carries no interface, so an address two segments hold cannot say
    /// which position it means. `None` means it is asked again, which is safe; picking
    /// one could skip an address nothing probed.
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
    /// See [`Positions`].
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
        // A slice of a zoned range keeps its zone.
        (IpRange::V6(v6), IpAddr::V6(start), IpAddr::V6(end)) => {
            Ipv6Range::scoped(start, end, v6.zone())
                .ok()
                .map(IpRange::V6)
        }
        _ => None,
    }
}

/// The inclusive bounds of an IPv4 range, widened so one difference serves both
/// families, as in [`holds`].
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
/// The subtrahend, flattened. IPv6 ranges may overlap across zones, and
/// [`IpSet::subtract`] ignores zones, so they are coalesced first.
fn merged_intervals(intervals: impl Iterator<Item = (u128, u128)>) -> Vec<(u128, u128)> {
    let mut cuts: Vec<(u128, u128)> = intervals.collect();
    cuts.sort_unstable();

    let mut merged: Vec<(u128, u128)> = Vec::with_capacity(cuts.len());
    for (start, end) in cuts {
        match merged.last_mut() {
            // Adjacent cuts coalesce too.
            Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Every part of `run` that no interval in `cuts` covers, in ascending order.
///
/// Both slices must be sorted by start and disjoint, so each is walked once. `run` is
/// one family's merged ranges (for IPv6, one zone's run); `cuts` comes from
/// [`merged_intervals`].
///
/// `bounds` reads a range's inclusive ends widened to `u128`, as in [`holds`].
/// `rebuild` turns a surviving `[start, end]` back into a range, given the range being
/// cut so a piece keeps its zone.
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

        // A cut left of this range is left of every later one, so this index only
        // moves forward and the pass is linear.
        while first_live < cuts.len() && cuts[first_live].1 < start {
            first_live += 1;
        }

        let mut cursor = start;
        let mut consumed = false;

        // `first_live` stays: one cut may span several ranges.
        let mut cut = first_live;
        while cut < cuts.len() && cuts[cut].0 <= end {
            let (cut_start, cut_end) = cuts[cut];

            // The gap in front of this cut survives, if there is one.
            if cut_start > cursor {
                kept.push(rebuild(range, cursor, cut_start - 1));
            }

            // A cut reaching the range's end takes the tail, and stays for the next
            // range.
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
/// `ranges` must be sorted by start and disjoint, or the search can step past the
/// range holding the target. The IPv4 vector is disjoint once merged; the IPv6 vector
/// only within one zone's run (see [`IpSet::v6_runs`]).
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
    /// Extending with IPv4 alone keeps IPv6 on its fast path, and extending with
    /// nothing keeps a completed `canonicalize`.
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

    /// Two adjacent addresses stay two ranges until canonicalized, and the count is
    /// right either way.
    #[test]
    fn adjacent_addresses_merge_when_the_set_is_canonicalized() {
        let mut set = IpSet::new();
        set.insert(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        set.insert(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)));

        // Before canonicalization they stay separate.
        assert_eq!(set.v4.len(), 2);
        assert!(set.v4_dirty);

        // A query never merges the set it reads.
        set.canonicalize();
        assert_eq!(set.len(), 2);
        assert!(!set.v4_dirty);
        assert_eq!(set.v4.len(), 1);
    }

    /// Every arrangement of two ranges collapses to the single covering range.
    #[test]
    fn every_kind_of_overlap_collapses_to_one_range() {
        let mut set = IpSet::new();
        // Insert: [10-20]
        set.insert_range("198.51.100.10-198.51.100.20".parse().unwrap());
        // Insert: [5-15] (overlap start)
        set.insert_range("198.51.100.5-198.51.100.15".parse().unwrap());
        // Insert: [15-25] (overlap end)
        set.insert_range("198.51.100.15-198.51.100.25".parse().unwrap());
        // Insert: [30-40] (disjoint)
        set.insert_range("198.51.100.30-198.51.100.40".parse().unwrap());
        // Insert: [0-50] (subsume all)
        set.insert_range("198.51.100.0-198.51.100.50".parse().unwrap());

        set.canonicalize();
        assert_eq!(set.len(), 51);
        assert_eq!(set.v4().len(), 1);
    }

    /// Adjacency uses a saturating add, so addresses at the top of IPv6 still merge.
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

    /// Iterating yields every address once and leaves the set unchanged.
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

    /// Canonicalizing an empty set is a no-op.
    #[test]
    fn an_empty_set_canonicalizes_and_counts_as_zero() {
        let mut set = IpSet::new();
        set.canonicalize();
        assert_eq!(set.len_canonical(), 0);
        assert!(set.v4().is_empty());
    }

    /// Work on one family keeps the other's canonical state, and a read of the
    /// untouched family still takes its fast path.
    #[test]
    fn extending_one_family_leaves_the_other_canonical() {
        let mut set = IpSet::from_iter(vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);
        assert!(!set.v4_dirty && !set.v6_dirty, "from_iter canonicalizes");

        set.extend([IpAddr::V4(Ipv4Addr::LOCALHOST)]);

        assert!(set.v4_dirty, "the family that gained a range");
        assert!(!set.v6_dirty, "and only that one");

        // Extending with nothing keeps a completed merge.
        let mut untouched = IpSet::from_iter(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        untouched.extend([]);
        assert!(!untouched.v4_dirty && !untouched.v6_dirty);

        // The other family keeps its binary search.
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(set.is_merged(&v6), "an unmerged IPv4 range is not IPv6's");
        assert!(!set.is_merged(&v4), "and IPv4's own half is not merged");

        // The guarded fast path accepts it.
        assert!(set.contains_canonical(&v6));
        assert!(set.contains(&v6));
        assert!(set.contains(&v4), "the slow path is still correct");
    }

    /// One string naming both families, with a duplicate across two spellings
    /// that has to be counted once.
    #[test]
    fn a_written_set_may_mix_both_families_and_still_counts_distinctly() {
        let set =
            IpSet::from_str("1.1.1.1/32, 1.1.1.1, ::1-::1, 198.51.100.1-198.51.100.2").unwrap();
        // 1.1.1.1 (v4) + ::1 (v6) + 198.51.100.1, 198.51.100.2 (v4)
        assert_eq!(set.len(), 4);
    }

    /// A hundred inserted addresses are a hundred ranges until `canonicalize` runs.
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

    /// The debug assertion trips when `contains_canonical` is handed an unmerged set.
    /// Debug-only, as the assertion is.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "must be canonicalized")]
    fn a_membership_query_on_an_unmerged_set_trips_the_guard() {
        let mut set = IpSet::new();
        set.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
        // Deliberately not canonicalized.
        set.contains_canonical(&IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    /// The same for the count.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "must be canonicalized")]
    fn a_count_on_an_unmerged_set_trips_the_guard() {
        let mut set = IpSet::new();
        set.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
        set.len_canonical();
    }

    /// A merged set passes the guards.
    #[test]
    fn a_membership_query_on_a_merged_set_answers() {
        let set = IpSet::from_iter(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        assert!(!set.v4_dirty, "from_iter canonicalizes");
        assert!(set.contains_canonical(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(set.len_canonical(), 1);
    }

    /// The same link-local numbers on two interfaces do not merge.
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

        // On one interface they do merge.
        let mut joined = IpSet::new();
        joined.push_v6_range(Ipv6Range::scoped(one, five, Some(4)).unwrap());
        joined.push_v6_range(Ipv6Range::scoped(six, ten, Some(4)).unwrap());
        joined.canonicalize();

        assert_eq!(joined.v6().len(), 1);

        // Membership still answers.
        assert!(split.contains(&IpAddr::V6(five)));
        assert!(split.contains(&IpAddr::V6(six)));
    }

    /// Equality compares the addresses held, merged or not.
    #[test]
    fn two_sets_holding_the_same_addresses_are_equal_however_they_were_built() {
        let canonical = IpSet::try_from("198.51.100.1-198.51.100.2, ::1").expect("parses");

        let mut piecemeal = IpSet::new();
        piecemeal.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
        piecemeal.insert(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)));
        piecemeal.insert(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));

        assert_eq!(canonical, piecemeal, "same addresses, different order");
        assert_ne!(
            canonical,
            IpSet::try_from("198.51.100.1, ::1").expect("parses")
        );
    }

    /// Ranges on different interfaces can overlap, which a single binary search cannot
    /// navigate; the search runs per zone.
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

    /// A position is an index into `iter`, and the two agree address for address.
    #[test]
    fn a_position_is_the_index_the_set_enumerates_at() {
        let set = set("192.0.2.1-192.0.2.10,198.51.100.0/30,2001:db8::1-2001:db8::5");
        let positions = set.positions();

        // `try_from`, since `as` would truncate to match a truncated numbering.
        assert_eq!(positions.total(), u64::try_from(set.len()).unwrap());
        assert!(positions.unnumbered().is_empty());

        for (index, ip) in set.iter().enumerate() {
            let index = index as u64;
            assert_eq!(positions.find(ip), Some(index), "{ip} is not at {index}");
            assert_eq!(positions.address_at(index), Some(ip), "{index} is not {ip}");
        }
    }

    /// A `/64`, the ordinary IPv6 subnet, is the first prefix the numbering cannot
    /// reach.
    #[test]
    fn a_range_too_large_to_number_is_kept_rather_than_dropped() {
        let positions = set("2001:db8::/64").positions();

        assert_eq!(positions.total(), 0);
        assert_eq!(positions.unnumbered().len(), 1);
    }

    /// An address outside the set has no position.
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

    /// Narrowing a plan gives back exactly the addresses at those positions.
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

    /// A span past the end is clamped, and an empty one gives back nothing.
    #[test]
    fn a_span_outside_the_plan_yields_nothing() {
        let positions = set("192.0.2.1-192.0.2.4").positions();

        assert!(positions.ranges_in(4..99).is_empty());
        assert!(positions.ranges_in(2..2).is_empty());
        assert_eq!(positions.ranges_in(0..99).len(), 1, "clamped to the plan");
    }

    /// The numbering stops at an IPv6 range too large to count, and IPv4 keeps its
    /// positions.
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

    /// A slice of a zoned range keeps its zone.
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

    /// An address two interfaces hold has no position, since a bare address cannot
    /// say which it means.
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

    /// An address one interface holds still resolves.
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

    /// Numbering an unmerged set merges it first.
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

    /// Zoned ranges from a narrow band of `fe80::/64`, so they often overlap, across
    /// four zones.
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

    /// A small canonical set of both families, with several ranges in each and some
    /// IPv6 addresses on more than one interface.
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

    /// Builds a v4 set from `[start, end]` pairs written as last octets of
    /// `198.51.100.0/24`.
    fn v4_set(spans: &[(u8, u8)]) -> IpSet {
        let mut set = IpSet::new();
        for &(start, end) in spans {
            set.push_v4_range(
                Ipv4Range::new(
                    Ipv4Addr::new(198, 51, 100, start),
                    Ipv4Addr::new(198, 51, 100, end),
                )
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
    /// One arrangement per case; the middle cut is the one that produces more ranges.
    #[test]
    fn a_cut_takes_exactly_what_it_covers() {
        /// A target, what is cut from it, and what should be left, as last octets of
        /// `198.51.100.0/24`.
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
            // Adjacent but not overlapping: nothing removed.
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
    /// The first needs a cut to stay for the next range; the second moves the cursor
    /// repeatedly inside one range.
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
    /// The tail emission must not compute `end + 1`. Both families; for v6 the
    /// overflow would be in a `u128`.
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
    /// See `subtract`. Surviving pieces must keep their zone, or they could not be
    /// probed.
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

        // Named on one interface, removed from both.
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
        /// The numbering and the enumeration agree over any set. An address several
        /// interfaces hold may answer `None` from `find`, never the wrong position.
        #[test]
        fn a_position_is_the_enumeration_index_for_any_set(
            set in any_ipset(),
        ) {
            let positions = set.positions();
            let walked: Vec<IpAddr> = set.iter().collect();

            prop_assert_eq!(positions.total() as usize, walked.len());
            for (index, ip) in walked.iter().enumerate() {
                // A position names one address.
                prop_assert_eq!(positions.address_at(index as u64), Some(*ip));

                let held_twice = walked.iter().filter(|other| *other == ip).count() > 1;
                match positions.find(*ip) {
                    Some(found) => prop_assert_eq!(found, index as u64),
                    None => prop_assert!(held_twice, "{} has one position and no answer", ip),
                }
            }
        }

        /// Narrowing to a span of positions gives back exactly those addresses.
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
        /// Zones put overlapping ranges in one vector, which a binary search could step
        /// past; see also
        /// `membership_answers_when_ranges_on_different_interfaces_overlap`.
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
        /// An address survives exactly when it was there and was not cut, probed at
        /// the boundaries.
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
                let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, probe));
                prop_assert_eq!(
                    after.contains(&ip),
                    before.contains(&ip) && !cut_set.contains(&ip),
                    "{} after {:?} minus {:?}", ip, target, cuts
                );
            }

            // The result must be canonical.
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
