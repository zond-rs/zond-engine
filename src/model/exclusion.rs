// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Addresses a scan may not touch
//!
//! [`Exclusions`] is the one thing in this engine that makes a scan cover
//! *less* than it was asked to, and the only one whose failure mode is a packet
//! somebody was told would not be sent.
//!
//! ## Why this is not a filter on a list
//!
//! The obvious implementation is to subtract the excluded addresses from the
//! target set and be done. That is necessary and it is not sufficient, because
//! **the target list is not the only way an address enters a scan.** A segment
//! sweep takes leads from the host's own IPv6 neighbour table, learns addresses
//! from mDNS records and from ARP and neighbour-advertisement replies, and
//! probes what it finds. None of those addresses was ever in the list, so none
//! of them was ever subtracted from it.
//!
//! An exclusion that holds for the list and not for what the sweep discovers is
//! worse than no exclusion at all, because it is relied upon. So the policy is
//! enforced twice, and the two enforcements answer different questions:
//!
//! | Where | What it guarantees |
//! |---|---|
//! | [`withhold`](Exclusions::withhold) and [`withhold_targets`](Exclusions::withhold_targets), before anything is opened | No probe is *addressed* to an excluded address, and the scope the report states is the scope that was actually walked |
//! | [`ScanContext::write_host`](crate::scanner::session::ScanContext::write_host), on every finding | Nothing about an excluded address is recorded, whichever path it arrived by |
//!
//! Subtracting up front is also what keeps the second cheap. Without it a `/8`
//! minus a `/24` would enumerate sixteen million addresses in order to discard
//! two hundred and fifty-four of them.
//!
//! ## What it can and cannot promise
//!
//! **It promises that no packet is addressed to an excluded address, and that no
//! excluded address appears in the report.** That second one is worth stating
//! plainly because it is checkable: a reader with the report in hand can
//! confirm it against the ranges the report itself records, without trusting
//! this module.
//!
//! **It does not promise that an excluded host never receives a packet.** A
//! segment sweep's all-nodes echo is one datagram to `ff02::1` and an ARP
//! request goes to the broadcast address; every machine on the link sees them,
//! including the excluded one, and nothing this engine does after the fact can
//! un-send them. What the gate does with the reply is drop it.
//!
//! That is the honest boundary, and a caller who needs the stronger property —
//! that an excluded machine sees nothing at all — needs to not sweep the segment
//! it is on, which is a decision about the scan rather than about this type.
//!
//! ## Zones
//!
//! Exclusion is blind to interfaces, in both enforcements, for the reason
//! [`IpSet::subtract`] gives: a reply arrives as a bare address with no
//! interface attached to compare against, so a zone-aware test could not be
//! applied at the gate even if it were wanted. Excluding `fe80::5` excludes it
//! on every link, and writing `fe80::5%en0` excludes it on every link too. Where
//! the two readings differ this is the one that withholds more, which is the
//! only direction a safety control may err in.

use std::net::IpAddr;

use crate::model::ip::range::IpRange;
use crate::model::ip::set::IpSet;
use crate::model::target::{TargetMap, TargetSet};

/// The addresses a scan is forbidden to probe or to record.
///
/// Canonical from the moment it is built and never mutated in place except by
/// [`extend`](Self::extend), which canonicalizes again. That invariant is not
/// cosmetic: [`excludes`](Self::excludes) is consulted at every host finding, and
/// an unmerged set answers that by scanning its ranges rather than by binary
/// search. The type exists largely to make the fast path unconditional — the
/// same argument [`TargetSet::new`](crate::model::target::TargetSet::new) makes
/// for targets.
///
/// It is also a distinct type from the [`IpSet`] it holds so that the two
/// cannot be confused at a call site. Passing targets where exclusions belong,
/// or the reverse, is a mistake that produces a scan rather than an error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exclusions {
    set: IpSet,
}

impl Exclusions {
    /// A policy that excludes nothing.
    ///
    /// The default, and what every scan runs under unless a caller says
    /// otherwise. Costs nothing to carry: every operation below returns
    /// immediately on an empty policy.
    pub fn none() -> Self {
        Self::default()
    }

    /// A policy over `ips`.
    ///
    /// Canonicalizes them once, here, which is what lets every read afterwards
    /// take `&self` and its fast path.
    pub fn new(mut ips: IpSet) -> Self {
        ips.canonicalize();
        Self { set: ips }
    }

    /// Whether the policy names any address at all.
    ///
    /// Worth testing before reporting one: "excluded nothing" and "no exclusion
    /// policy" are the same scan, and a front end that prints the first reads as
    /// though something was withheld.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Whether `ip` may not be probed or recorded.
    ///
    /// The whole of the policy, asked one address at a time. A binary search
    /// over merged ranges, and a bare `is_empty` check when no policy is in
    /// force — which is the case on the overwhelming majority of scans and is
    /// why this is affordable on the path every finding takes.
    pub fn excludes(&self, ip: &IpAddr) -> bool {
        !self.set.is_empty() && self.set.contains(ip)
    }

    /// Every excluded range, ascending, IPv4 before IPv6.
    ///
    /// The merged form rather than what a caller wrote, so a report quoting
    /// these quotes what was actually enforced. Two overlapping `--exclude`
    /// arguments appear here as the one range they amount to.
    pub fn ranges(&self) -> Vec<IpRange> {
        let v4 = self.set.v4().iter().copied().map(IpRange::V4);
        let v6 = self.set.v6().iter().copied().map(IpRange::V6);
        v4.chain(v6).collect()
    }

    /// Adds everything `other` excludes to this policy.
    ///
    /// **Union, never replacement, and that is the whole reason this exists as a
    /// method rather than as an assignment.** Exclusions arrive in layers — a
    /// system-wide settings file, a user's own, a profile, the command line —
    /// and every other setting in that stack is overridden by the layer above
    /// it. Applying that rule here would let a user's file silently drop the
    /// range an administrator put in `/etc/zond/engine.toml`, which is the one
    /// key in the whole document where being overridden defeats the point of
    /// setting it.
    ///
    /// Narrowing composes safely in a way that widening does not: layering
    /// exclusions can only ever make a scan smaller, so no combination of them
    /// can produce traffic no layer asked for.
    pub fn extend(&mut self, other: &Exclusions) {
        if other.is_empty() {
            return;
        }
        for range in other.set.v4() {
            self.set.push_v4_range(*range);
        }
        for range in other.set.v6() {
            self.set.push_v6_range(*range);
        }
        self.set.canonicalize();
    }

    /// Removes every excluded address from `ips`, returning how many it lost.
    ///
    /// The planning-time half of the enforcement. Call it before the target set
    /// is measured, so that what a report states as its scope is the scope that
    /// was walked rather than the one that was asked for.
    ///
    /// The count is the *overlap*, not the size of the policy: a policy naming a
    /// range the scan was never going to reach withholds nothing and returns
    /// zero. That distinction is the whole value of recording it. A policy that
    /// was configured and did nothing looks identical to one that was configured
    /// and worked, and only one of those means the scope document was
    /// understood.
    pub fn withhold(&self, ips: &mut IpSet) -> u128 {
        if self.is_empty() {
            return 0;
        }
        let before = ips.len();
        ips.subtract(&self.set);
        before.saturating_sub(ips.len())
    }

    /// [`withhold`](Self::withhold), for a map that pairs addresses with ports.
    ///
    /// Each unit is narrowed on its own and rebuilt, and a unit left with no
    /// address is dropped rather than kept as an empty question — a unit naming
    /// only excluded addresses no longer asks anything. Rebuilding rather than
    /// editing in place is not a choice: a [`TargetSet`] is immutable once
    /// built, for the reason [`TargetSet::into_parts`] gives.
    ///
    /// The count is gross, as every count on a [`TargetMap`] is. Two units
    /// naming the same excluded address are two questions withheld, and the
    /// number has to be subtractable from the
    /// [`gross_ips`](TargetMap::gross_ips) it is reported beside.
    ///
    /// It saturates where `gross_ips` refuses, which is a difference only a plan
    /// too large to count reaches: `gross_ips` has already answered
    /// [`CapacityOverflow`](crate::model::target::TargetError::CapacityOverflow)
    /// by then, so there is nothing for this to be subtracted from and no pair
    /// to disagree.
    pub fn withhold_targets(&self, map: &mut TargetMap) -> u128 {
        if self.is_empty() {
            return 0;
        }

        let mut withheld: u128 = 0;
        let mut kept = Vec::with_capacity(map.units.len());

        for unit in std::mem::take(&mut map.units) {
            let (mut ips, ports) = unit.into_parts();
            withheld = withheld.saturating_add(self.withhold(&mut ips));

            if !ips.is_empty() {
                kept.push(TargetSet::new(ips, ports));
            }
        }

        map.units = kept;
        withheld
    }
}

impl From<IpSet> for Exclusions {
    fn from(ips: IpSet) -> Self {
        Self::new(ips)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::model::ip::range::Ipv6Range;
    use crate::model::port::PortSet;

    fn ips(spec: &str) -> IpSet {
        spec.parse().expect("a valid address expression")
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// The engagement case: a range excluded out of the middle of the scope.
    ///
    /// Both halves at once, because they are what the two enforcements each
    /// guarantee and neither implies the other — the count says the plan shrank,
    /// `excludes` says the gate will hold for an address the plan never held.
    #[test]
    fn an_excluded_range_leaves_the_scope_and_stays_out_of_the_gate() {
        let policy = Exclusions::new(ips("10.0.5.0/24"));
        let mut scope = ips("10.0.0.0/16");

        assert_eq!(policy.withhold(&mut scope), 256);
        assert_eq!(scope.len(), 65536 - 256);
        assert!(!scope.contains(&v4(10, 0, 5, 7)));
        assert!(scope.contains(&v4(10, 0, 6, 7)));

        assert!(policy.excludes(&v4(10, 0, 5, 7)));
        assert!(!policy.excludes(&v4(10, 0, 6, 7)));
    }

    /// A policy that names ground the scan was never going to walk withholds
    /// nothing, and says so.
    ///
    /// The zero is the finding. A front end that reports "254 addresses
    /// withheld" when the answer is none has told the operator their scope
    /// document was applied when nothing about it was.
    #[test]
    fn a_policy_that_does_not_overlap_withholds_nothing() {
        let policy = Exclusions::new(ips("192.168.9.0/24"));
        let mut scope = ips("10.0.0.0/24");

        assert_eq!(policy.withhold(&mut scope), 0);
        assert_eq!(scope.len(), 256);
    }

    /// Layering unions rather than replaces, and a unit reduced to nothing is
    /// dropped instead of being carried as an empty question.
    ///
    /// The union is the point: were `extend` an assignment, the administrator's
    /// range would be gone the moment a user's file named one of their own, and
    /// the resulting scan would look exactly like a correct one.
    #[test]
    fn layers_accumulate_and_emptied_units_are_dropped() {
        let mut policy = Exclusions::new(ips("10.0.5.0/24"));
        policy.extend(&Exclusions::new(ips("10.0.7.0/24")));

        assert!(policy.excludes(&v4(10, 0, 5, 1)));
        assert!(policy.excludes(&v4(10, 0, 7, 1)));

        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(ips("10.0.5.0/24"), PortSet::top_tcp(2)));
        map.add_unit(TargetSet::new(ips("10.0.6.0/24"), PortSet::top_tcp(2)));

        let withheld = policy.withhold_targets(&mut map);

        assert_eq!(withheld, 256);
        assert_eq!(map.units.len(), 1, "the fully excluded unit is dropped");
        assert_eq!(map.gross_ips().expect("small"), 256);
    }

    /// An exclusion written against one interface withholds the address on every
    /// interface.
    ///
    /// Deliberate over-exclusion, and the only reading the gate can implement:
    /// see the module documentation. Pinned because the safe direction is not
    /// the obvious one, and a later change to `subtract` that made zones
    /// significant would be a silent narrowing of a safety control.
    #[test]
    fn a_zoned_exclusion_withholds_the_address_everywhere() {
        let address: Ipv6Addr = "fe80::5".parse().expect("literal");

        let mut named_on_one_interface = IpSet::new();
        named_on_one_interface
            .push_v6_range(Ipv6Range::scoped(address, address, Some(1)).expect("start <= end"));
        let policy = Exclusions::new(named_on_one_interface);

        assert!(policy.excludes(&IpAddr::V6(address)));

        // And it comes out of a scope that named the same address on another.
        let mut scope = IpSet::new();
        scope.push_v6_range(Ipv6Range::scoped(address, address, Some(2)).expect("start <= end"));
        scope.canonicalize();

        assert_eq!(policy.withhold(&mut scope), 1);
        assert!(scope.is_empty());
    }
}
