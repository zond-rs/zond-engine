// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a scan was asked to cover
//!
//! A [`Target`] is one address, one port, one protocol: the smallest thing a
//! scan can ask about, and what a probe is built from. The two types above it
//! exist so that nothing has to hold the whole list.
//!
//! [`TargetSet`] pairs an [`IpSet`] with a [`PortSet`] and yields their cross
//! product lazily. A `/8` on a thousand ports is sixteen billion targets, which
//! is a few words to describe and more than any machine can hold; the set
//! describes it and the iterator produces them one at a time.
//!
//! [`TargetMap`] is several of those, since one scan can ask different questions
//! of different hosts: `10.0.0.1:22` and `10.0.0.0/24:80` are one job with two
//! shapes. Each unit is a set of addresses paired with a set of ports, which is
//! why the counts here are gross rather than net. Two units naming one address
//! are two questions about it, and both get asked.

use crate::model::ip::range::IpRange;
use crate::model::ip::set::{IpSet, Positions};
use crate::model::port::{PortSet, Protocol};
use std::{net::IpAddr, ops::Range, sync::Arc};
use thiserror::Error;

/// Errors that can occur during target composition and calculation.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TargetError {
    /// The number of targets is too large to represent in a `u128`.
    ///
    /// Reachable: `::/0` is already `u128::MAX` addresses, so any second port
    /// overflows. Reported rather than wrapped, because a scan of the entire
    /// address space reported as a small number is the one answer a budget
    /// check must never be handed.
    #[error("Target calculation resulted in an integer overflow")]
    CapacityOverflow,
}

/// One address, one port, one protocol: the smallest thing a scan can ask
/// about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target {
    /// The address to probe.
    ///
    /// Bare, with no zone. A link-local address needs one, and it travels
    /// beside the targets rather than on each of them: the zone is written on
    /// the range a target came from, and a scan holds the pairing in a
    /// [`ZoneMap`](crate::model::ip::scoped::ZoneMap) for the phases that open a
    /// socket or send a frame. See
    /// [`ScopedIp`](crate::model::ip::scoped::ScopedIp) for an address that
    /// carries its own.
    pub ip: IpAddr,
    /// The port to probe.
    pub port: u16,
    /// Which transport to probe it over.
    pub protocol: Protocol,
}

/// A target together with its position in the plan it came from.
///
/// The position is the target's index in [`TargetMap::iter`], which is
/// reproducible for a given plan, so it names the target without storing an
/// address and a journal records how far a scan got in a few bytes.
///
/// Carried alongside [`Target`] rather than folded into it, because a target
/// that came from a file or a hand-built set belongs to no plan and has no
/// position. Only the dispatcher numbers targets, and only what it emits is
/// wrapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlannedTarget {
    /// Where in the plan's enumeration this target sits.
    pub position: u64,
    /// What to probe.
    pub target: Target,
}

impl PlannedTarget {
    /// Pairs `target` with its position.
    pub fn new(position: u64, target: Target) -> Self {
        Self { position, target }
    }

    /// The address to probe.
    pub fn ip(&self) -> IpAddr {
        self.target.ip
    }

    /// The port to probe.
    pub fn port(&self) -> u16 {
        self.target.port
    }

    /// The transport to probe it over.
    pub fn protocol(&self) -> Protocol {
        self.target.protocol
    }
}

/// A set of addresses paired with the ports to try on each of them.
///
/// The addresses are merged for this type's whole life. [`new`](Self::new)
/// canonicalizes them and there is no way to mutate them afterwards, so a
/// `TargetSet` never holds overlapping ranges and never miscounts them. Every
/// method that reads one takes `&self`, since counting is not a mutation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetSet {
    /// Internal IP set, canonical by construction.
    ips: IpSet,
    /// The ports to try on each of them.
    ///
    /// Private for symmetry with the addresses rather than to protect anything:
    /// a [`PortSet`] is canonical from construction and has no lazy state, which
    /// is what the note here used to claim it had. [`ports`](Self::ports) hands
    /// out a reference and [`into_parts`](Self::into_parts) the value, so what
    /// privacy buys is that nobody replaces it under a set that has been counted.
    ports: PortSet,
}

impl TargetSet {
    /// Creates a scan blueprint over `ips` and `ports`.
    ///
    /// Merges `ips` once, here, which is what lets every read below take
    /// `&self`. The work is the same either way, since a set has to be merged
    /// before it can be counted or iterated. Doing it at one known point rather
    /// than at whichever read happens first is the whole of the difference.
    pub fn new(mut ips: IpSet, ports: PortSet) -> Self {
        ips.canonicalize();
        Self { ips, ports }
    }

    /// Returns a read-only reference to the underlying IP set.
    pub fn ips(&self) -> &IpSet {
        &self.ips
    }

    /// Takes the IP set, discarding the ports.
    ///
    /// For moving targets to a phase that has no use for ports, such as
    /// [`discover`](crate::scanner::discover), which only asks whether a host is
    /// there at all. Cloning the addresses in order to drop the ports beside
    /// them would be the wrong shape for a set that may hold a `/8`.
    pub fn into_ips(self) -> IpSet {
        self.ips
    }

    /// Takes the set apart into the two halves it was built from.
    ///
    /// For rebuilding one. A unit is immutable once constructed, so narrowing the
    /// addresses of an existing set, which is what withholding an excluded range
    /// amounts to, means taking it apart and building a new one through
    /// [`new`](Self::new). Handing out a `&mut IpSet` would let a caller leave
    /// the addresses unmerged, and every count and membership test downstream
    /// assumes they are not.
    pub fn into_parts(self) -> (IpSet, PortSet) {
        (self.ips, self.ports)
    }

    /// Returns a read-only reference to the underlying Port set.
    pub fn ports(&self) -> &PortSet {
        &self.ports
    }

    /// Returns the number of unique IP addresses in this set.
    pub fn ip_count(&self) -> u128 {
        self.ips.len()
    }

    /// Returns the number of unique ports in this set.
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// Returns the total number of targets.
    ///
    /// Returns a `TargetError::CapacityOverflow` if the calculation exceeds `u128::MAX`.
    pub fn total_targets(&self) -> Result<u128, TargetError> {
        let port_len = self.ports.len() as u128;
        self.ips
            .len()
            .checked_mul(port_len)
            .ok_or(TargetError::CapacityOverflow)
    }

    /// Every address paired with every port, lazily.
    ///
    /// The addresses were merged when the set was constructed, so there is
    /// nothing to normalize. Nothing is materialized either. A `/8` on a
    /// thousand ports is 16 billion targets, so they are produced one at a time
    /// and the port list is shared behind an `Arc` rather than cloned for every
    /// address.
    pub fn iter(&self) -> impl Iterator<Item = Target> + Send + '_ {
        let ports_arc: Arc<[(u16, Protocol)]> = self.ports.to_vec().into();

        self.ips.iter().flat_map(move |ip| {
            let ports = Arc::clone(&ports_arc);
            (0..ports.len()).map(move |i| {
                let (port, protocol) = ports[i];
                Target { ip, port, protocol }
            })
        })
    }

    /// Returns true if either the IP set or the Port set is completely empty.
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() || self.ports.is_empty()
    }
}

/// A collection of multiple [`TargetSet`] units.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetMap {
    /// The units, in the order they were added.
    ///
    /// Public because there is no invariant over the vector for an accessor to
    /// protect: a [`TargetSet`] is canonical and immutable from the moment it
    /// is built, this type caches nothing derived from them, and a scanner
    /// splitting work across units needs to iterate and partition them freely.
    pub units: Vec<TargetSet>,
}

impl TargetMap {
    /// Creates a new, empty `TargetMap`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a new unit definition to the map.
    pub fn add_unit(&mut self, unit: TargetSet) {
        self.units.push(unit);
    }

    /// Whether any unit names a port on `protocol`.
    ///
    /// Read when a scan is assembled, to decide whether a transport nothing is
    /// probed on by default is worth opening a socket for.
    pub fn names(&self, protocol: Protocol) -> bool {
        self.units
            .iter()
            .any(|unit| !unit.ports().ranges(protocol).is_empty())
    }

    /// Returns the gross total of target connections across all units.
    ///
    /// Gross rather than net: two units naming the same address each count it,
    /// because a unit is a set of addresses *paired with a set of ports* and two
    /// units are two different questions about that address.
    pub fn gross_targets(&self) -> Result<u128, TargetError> {
        let mut total: u128 = 0;
        for unit in &self.units {
            let unit_total = unit.total_targets()?;
            total = total
                .checked_add(unit_total)
                .ok_or(TargetError::CapacityOverflow)?;
        }
        Ok(total)
    }

    /// Returns the gross number of IP addresses across all units.
    pub fn gross_ips(&self) -> Result<u128, TargetError> {
        let mut total: u128 = 0;
        for unit in &self.units {
            total = total
                .checked_add(unit.ip_count())
                .ok_or(TargetError::CapacityOverflow)?;
        }
        Ok(total)
    }

    /// Returns true if no targets are defined across any unit.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty() || self.units.iter().all(|u| u.is_empty())
    }

    /// Creates a flattened iterator over every target in every unit.
    pub fn iter(&self) -> impl Iterator<Item = Target> + Send + '_ {
        self.units.iter().flat_map(|unit| unit.iter())
    }
}

/// The same targets [`TargetMap::iter`] yields, addressed by position instead of
/// walked in order.
///
/// [`iter`](TargetMap::iter) is what numbers a plan: the nth target it yields is
/// position n, and a journal records how far a scan got as one of those numbers.
/// That is enough for a scan that asks its targets in plan order and not enough
/// for one that does not, which needs to go the other way and ask what target a
/// position names. This is that direction.
///
/// The two are one numbering or they are nothing, since the dispatcher decides
/// what to probe by one and the cursor decides what was probed by the other. The
/// property is stated as [`target_at`](Self::target_at) agreeing with
/// `iter().nth()` for every position, and `model`'s own tests hold it there.
///
/// Costs a few words per unit and nothing per target. A unit's addresses are
/// numbered by [`Positions`], which is a table of its ranges, and its ports are
/// the list it already holds; a position is resolved by one binary search and two
/// divisions.
#[derive(Debug, Clone)]
pub struct TargetIndex {
    /// The numbered units, in the order [`TargetMap::iter`] walks them.
    units: Vec<UnitIndex>,
    /// How many targets are numbered.
    total: u64,
    /// Whether that is every target the map holds.
    complete: bool,
    /// The addresses of the units the numbering stopped at and after, which is
    /// every unit it left out. Empty exactly when `complete` is true.
    unnumbered: Vec<IpRange>,
}

/// One unit of a [`TargetIndex`], and where its targets sit in the numbering.
#[derive(Debug, Clone)]
struct UnitIndex {
    /// The unit's addresses, numbered.
    addresses: Positions,
    /// The unit's ports, in the order its iterator pairs them with an address.
    ports: Arc<[(u16, Protocol)]>,
    /// The position of the unit's first target.
    start: u64,
    /// How many targets it holds: its addresses times its ports.
    len: u64,
}

impl TargetIndex {
    /// Numbers `map`'s targets.
    ///
    /// Numbering stops at the first unit that cannot be counted whole, and every
    /// unit after it is left out for the reason [`Positions`] leaves out a range
    /// it cannot number: positions have to stay contiguous, and a gap in the
    /// middle would move every position above it. What that costs is
    /// [`is_complete`](Self::is_complete) answering false, and a caller that
    /// needs the whole plan addressed reads that before it reads anything else.
    ///
    /// A unit is uncountable when its addresses are, which is an IPv6 range of a
    /// `/64` or wider, or when its address count times its port count overflows
    /// the numbering. Both describe a plan no scan finishes.
    pub fn of(map: &TargetMap) -> Self {
        let mut units = Vec::with_capacity(map.units.len());
        let mut total: u64 = 0;
        let mut complete = true;
        let mut unnumbered = Vec::new();

        for (at, unit) in map.units.iter().enumerate() {
            let addresses = Positions::of(unit.ips());
            let ports: Arc<[(u16, Protocol)]> = unit.ports().to_vec().into();

            // A unit with no ports yields no targets, so it takes no positions
            // and does not interrupt the numbering. `iter` skips it the same way.
            if ports.is_empty() {
                continue;
            }

            let counted = u64::try_from(ports.len())
                .ok()
                .and_then(|ports| addresses.total().checked_mul(ports))
                .filter(|_| addresses.unnumbered().is_empty());

            let Some(len) = counted.filter(|len| total.checked_add(*len).is_some()) else {
                complete = false;
                // A unit without ports is skipped here as it is above: it has
                // no target, so there is nothing at its addresses to ask.
                for left_out in map.units[at..]
                    .iter()
                    .filter(|unit| !unit.ports().is_empty())
                {
                    let ips = left_out.ips();
                    unnumbered.extend(ips.v4().iter().copied().map(IpRange::V4));
                    unnumbered.extend(ips.v6().iter().copied().map(IpRange::V6));
                }
                break;
            };

            units.push(UnitIndex {
                addresses,
                ports,
                start: total,
                len,
            });
            total += len;
        }

        Self {
            units,
            total,
            complete,
            unnumbered,
        }
    }

    /// How many targets are numbered.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Whether every target the map holds is numbered.
    ///
    /// False for a plan whose addresses outrun the numbering, where
    /// [`total`](Self::total) counts a prefix of what
    /// [`TargetMap::iter`] yields rather than all of it. A caller walking
    /// positions rather than the iterator has to read this, or it asks about
    /// part of the plan and reports having asked about all of it.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// The target at `position`, or [`None`] past the end of the numbering.
    pub fn target_at(&self, position: u64) -> Option<Target> {
        let unit = self.unit_at(position)?;
        let local = position - unit.start;

        // The unit's iterator pairs each address with every port before moving
        // to the next address, so the port index runs fastest.
        let ports = unit.ports.len() as u64;
        let (port, protocol) = unit.ports[(local % ports) as usize];
        let ip = unit.addresses.address_at(local / ports)?;

        Some(Target { ip, port, protocol })
    }

    /// The addresses holding at least one of the targets numbered `positions`,
    /// as ranges.
    ///
    /// The numbering seen host by host, for a pass that asks about an address
    /// rather than about its ports. Such a pass has business with an address
    /// while any one of its targets is in the span, so the span's partial
    /// addresses at either end come back whole: the port index runs fastest, and
    /// a span starting on an address's third port still holds that address.
    ///
    /// Positions past [`total`](Self::total) name nothing and are ignored. What
    /// they would have named, had the numbering reached that far, is
    /// [`unnumbered_addresses`](Self::unnumbered_addresses).
    pub(crate) fn addresses_in(&self, positions: Range<u64>) -> Vec<IpRange> {
        let end = positions.end.min(self.total);
        let mut found = Vec::new();

        // Units are contiguous and ascending, so the first one worth reading is
        // the first that ends past the start of the span.
        let first = self
            .units
            .partition_point(|unit| unit.start + unit.len <= positions.start);

        for unit in &self.units[first..] {
            if unit.start >= end {
                break;
            }
            let from = positions.start.max(unit.start) - unit.start;
            let to = end.min(unit.start + unit.len) - unit.start;
            if from >= to {
                continue;
            }

            let ports = unit.ports.len() as u64;
            let addresses = from / ports..(to - 1) / ports + 1;
            found.extend(unit.addresses.ranges_in(addresses));
        }

        found
    }

    /// The addresses of every unit the numbering could not reach, which is
    /// empty exactly when the index [is complete](Self::is_complete).
    ///
    /// No position names a target at these, so nothing recorded against the
    /// numbering can have settled one of them. A caller asking which addresses
    /// still have work outstanding has to count every one of them as having
    /// some.
    pub(crate) fn unnumbered_addresses(&self) -> &[IpRange] {
        &self.unnumbered
    }

    /// The unit holding `position`.
    fn unit_at(&self, position: u64) -> Option<&UnitIndex> {
        if position >= self.total {
            return None;
        }
        let index = match self
            .units
            .binary_search_by_key(&position, |unit| unit.start)
        {
            Ok(index) => index,
            // The unit before the first one starting above `position`, which is
            // the one holding it: units are contiguous and ascending by `start`.
            Err(0) => return None,
            Err(index) => index - 1,
        };
        self.units
            .get(index)
            .filter(|unit| position < unit.start + unit.len)
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

    fn ips(written: &str) -> IpSet {
        written.parse().expect("a valid address specification")
    }

    fn ports(written: &str) -> PortSet {
        written.parse().expect("a valid port specification")
    }

    /// A plan that runs several units, of both families, with ports that do not
    /// divide evenly into anything.
    ///
    /// Awkward on purpose. Every off-by-one available lives at a unit boundary or
    /// at the wrap from one address's last port to the next address's first, so a
    /// fixture whose units are the same size and whose port counts are powers of
    /// two would pass while getting both wrong.
    fn awkward() -> TargetMap {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(ips("192.0.2.0/29"), ports("22, 80, u:53")));
        map.add_unit(TargetSet::new(ips("198.51.100.7"), ports("443")));
        map.add_unit(TargetSet::new(
            ips("203.0.113.0/30, 192.0.2.200-192.0.2.203"),
            ports("1-5, s:2905"),
        ));
        map.add_unit(TargetSet::new(ips("2001:db8::/126"), ports("80, u:161")));
        map
    }

    /// The whole of what an index promises. A position names the target the
    /// plan's own walk gives it, or the dispatcher and the cursor are counting
    /// two different things and a resume skips ground nobody probed.
    #[test]
    fn a_position_names_the_target_the_plans_own_walk_numbers_it() {
        let map = awkward();
        let index = TargetIndex::of(&map);

        let walked: Vec<Target> = map.iter().collect();
        assert!(index.is_complete());
        assert_eq!(index.total(), walked.len() as u64);

        for (position, expected) in walked.iter().enumerate() {
            assert_eq!(
                index.target_at(position as u64).as_ref(),
                Some(expected),
                "position {position}"
            );
        }
        assert_eq!(index.target_at(index.total()), None, "past the end");
    }

    /// A unit naming no port yields no target, so it takes no positions. It used
    /// to be the case that skipping it and counting it were the same thing;
    /// they are not, and counting it would put a gap in the middle of the
    /// numbering that moves every position above it.
    #[test]
    fn a_unit_with_no_ports_takes_no_positions() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(ips("192.0.2.1"), ports("22")));
        map.add_unit(TargetSet::new(ips("192.0.2.0/24"), PortSet::new()));
        map.add_unit(TargetSet::new(ips("192.0.2.2"), ports("80")));

        let index = TargetIndex::of(&map);
        let walked: Vec<Target> = map.iter().collect();

        assert_eq!(index.total(), 2);
        assert_eq!(index.total(), walked.len() as u64);
        assert_eq!(index.target_at(0).as_ref(), walked.first());
        assert_eq!(index.target_at(1).as_ref(), walked.get(1));
    }

    /// An address range the numbering cannot reach makes the whole index
    /// incomplete, and it says so rather than numbering the part that fits and
    /// leaving a caller to walk a prefix believing it walked a plan.
    #[test]
    fn a_plan_wider_than_the_numbering_is_incomplete_and_says_so() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(ips("192.0.2.1"), ports("22")));
        map.add_unit(TargetSet::new(ips("2001:db8::/48"), ports("80")));
        map.add_unit(TargetSet::new(ips("198.51.100.1"), ports("443")));

        let index = TargetIndex::of(&map);

        assert!(!index.is_complete());
        assert_eq!(index.total(), 1, "only the units before the wide one");
        assert_eq!(
            index.target_at(1),
            None,
            "a position the numbering never reached names nothing"
        );
    }

    /// Where the numbering gives out, checked rather than asserted from the
    /// documentation of the thing that does it. A `/64` holds one address more
    /// than a position can count, so it is the first prefix that cannot be
    /// addressed and a `/65` is the first that can be split.
    #[test]
    fn a_sixty_four_is_the_first_prefix_the_numbering_cannot_reach() {
        let indexed = |prefix: &str| {
            let mut map = TargetMap::new();
            map.add_unit(TargetSet::new(ips(prefix), ports("80")));
            TargetIndex::of(&map).is_complete()
        };

        assert!(indexed("2001:db8::/65"), "a /65 fits");
        assert!(!indexed("2001:db8::/64"), "a /64 is one address too many");
        assert!(!indexed("2001:db8::/48"), "and anything wider is too");
    }

    /// An empty plan numbers nothing and is still complete: there is nothing it
    /// failed to reach.
    #[test]
    fn an_empty_plan_numbers_nothing() {
        let index = TargetIndex::of(&TargetMap::new());

        assert!(index.is_complete());
        assert_eq!(index.total(), 0);
        assert_eq!(index.target_at(0), None);
    }

    /// Every span of the numbering names exactly the addresses its targets are
    /// at, checked against the plan's own walk for every span there is.
    ///
    /// Exhaustive because the fixture is small and the mistakes are all at the
    /// edges: a span starting or ending partway through an address's ports, one
    /// crossing from a unit into the next, one ending on a unit boundary. An
    /// address left out is a host a resumed pass never asks about while one of
    /// its ports is still waiting on the answer.
    #[test]
    fn every_span_names_exactly_the_addresses_its_targets_are_at() {
        let map = awkward();
        let index = TargetIndex::of(&map);
        let walked: Vec<Target> = map.iter().collect();
        let total = walked.len();

        for start in 0..=total {
            for end in start..=total + 2 {
                let mut expected = IpSet::new();
                for target in &walked[start..end.min(total)] {
                    expected.insert(target.ip);
                }
                expected.canonicalize();

                let mut named = IpSet::new();
                for range in index.addresses_in(start as u64..end as u64) {
                    named.insert_range(range);
                }
                named.canonicalize();

                assert_eq!(named, expected, "positions {start}..{end}");
            }
        }
        assert!(index.unnumbered_addresses().is_empty(), "a complete index");
    }

    /// The units the numbering never reached come back as addresses, since a
    /// caller asking what is outstanding has to count all of them. A unit naming
    /// no port has no targets to be outstanding and is left out wherever it
    /// sits.
    #[test]
    fn the_units_past_the_numbering_are_left_out_whole() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(ips("192.0.2.1"), ports("22")));
        map.add_unit(TargetSet::new(ips("2001:db8::/64"), ports("80")));
        map.add_unit(TargetSet::new(ips("198.51.100.0/24"), PortSet::new()));
        map.add_unit(TargetSet::new(ips("203.0.113.9"), ports("443")));

        let index = TargetIndex::of(&map);
        let mut unnumbered = IpSet::new();
        for range in index.unnumbered_addresses() {
            unnumbered.insert_range(*range);
        }
        unnumbered.canonicalize();

        assert!(!index.is_complete());
        assert_eq!(unnumbered, ips("2001:db8::/64, 203.0.113.9"));
    }

    /// What decides whether a scan opens a socket for SCTP, which nothing
    /// probes unless a port specification asks for it.
    #[test]
    fn a_map_says_which_transports_its_units_name() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(ips("192.0.2.1"), ports("80, u:53")));

        assert!(map.names(Protocol::Tcp));
        assert!(map.names(Protocol::Udp));
        assert!(!map.names(Protocol::Sctp));

        map.add_unit(TargetSet::new(ips("192.0.2.2"), ports("s:2905")));
        assert!(map.names(Protocol::Sctp));
    }

    /// The cross product's size, which is what a caller checks a scan budget
    /// against before anything is sent.
    #[test]
    fn a_sets_target_count_is_its_addresses_times_its_ports() {
        let ts = TargetSet::new(ips("192.168.1.0/24"), ports("80, 443"));
        assert_eq!(ts.total_targets().unwrap(), 256 * 2);
    }

    /// A set is merged the moment it becomes a `TargetSet`, so nothing
    /// downstream can read one that is not. Overlapping ranges counted twice is
    /// the failure that makes this matter, so that is what it checks.
    #[test]
    fn a_target_set_merges_its_addresses_on_construction() {
        let mut overlapping = ips("192.168.1.0/24");
        overlapping.insert_range("192.168.1.128/25".parse().expect("valid range"));

        let ts = TargetSet::new(overlapping, ports("80"));

        // 256, not the 384 the two arguments add up to.
        assert_eq!(ts.ip_count(), 256);
        assert_eq!(ts.total_targets().unwrap(), 256);
    }

    /// The cross product is the whole purpose of the type, and a count alone
    /// does not pin it: two different pairings of the same addresses and ports
    /// produce the same total. This pins the triples.
    #[test]
    fn a_set_yields_every_address_paired_with_every_port() {
        let ts = TargetSet::new(ips("10.0.0.1-10.0.0.2"), ports("80, u:53"));

        let mut targets: Vec<(String, u16, Protocol)> = ts
            .iter()
            .map(|target| (target.ip.to_string(), target.port, target.protocol))
            .collect();
        targets.sort();

        assert_eq!(
            targets,
            vec![
                ("10.0.0.1".to_string(), 53, Protocol::Udp),
                ("10.0.0.1".to_string(), 80, Protocol::Tcp),
                ("10.0.0.2".to_string(), 53, Protocol::Udp),
                ("10.0.0.2".to_string(), 80, Protocol::Tcp),
            ]
        );
    }

    /// A map's iterator is a flattening of its units, in the order they were
    /// added, which is what makes two runs over one input scan in one order.
    #[test]
    fn a_map_iterates_its_units_in_the_order_they_were_added() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(ips("10.0.0.1"), ports("80")));
        map.add_unit(TargetSet::new(ips("10.0.0.2"), ports("u:53")));

        let targets: Vec<(String, u16, Protocol)> = map
            .iter()
            .map(|target| (target.ip.to_string(), target.port, target.protocol))
            .collect();

        assert_eq!(
            targets,
            vec![
                ("10.0.0.1".to_string(), 80, Protocol::Tcp),
                ("10.0.0.2".to_string(), 53, Protocol::Udp),
            ]
        );
    }

    /// `::/0` is 2^128 addresses, which [`IpSet::len`] already saturates to
    /// `u128::MAX`. One port still fits; two do not, and the multiplication has
    /// to refuse rather than wrap. A scan of the entire address space reported
    /// as a small number is the one answer a budget check must never be given.
    #[test]
    fn a_target_count_too_large_to_represent_is_refused_rather_than_wrapped() {
        let two_ports = TargetSet::new(ips("::/0"), ports("80, 443"));
        assert_eq!(
            two_ports.total_targets(),
            Err(TargetError::CapacityOverflow)
        );

        let one_port = TargetSet::new(ips("::/0"), ports("80"));
        assert_eq!(one_port.total_targets().unwrap(), u128::MAX);
    }

    /// A map's total is the sum of its units', so a caller can budget the whole
    /// job from one number rather than walking the units itself.
    #[test]
    fn a_maps_total_is_the_sum_of_its_units() {
        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(ips("10.0.0.1-10.0.0.5"), ports("80,443")));
        assert_eq!(map.gross_targets().unwrap(), 10);
    }
}
