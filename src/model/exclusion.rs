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
//! the target list is not the only way an address enters a scan. A segment
//! sweep takes leads from the host's own IPv6 neighbour table, learns addresses
//! from mDNS records and from ARP and neighbour-advertisement replies, and
//! probes what it finds. None of those addresses was ever in the list, so none
//! of them was ever subtracted from it.
//!
//! An exclusion that holds for the list and not for what the sweep discovers is
//! worse than no exclusion at all, because it is relied upon. So the policy is
//! enforced at three points, and they answer different questions:
//!
//! | Where | What it guarantees |
//! |---|---|
//! | [`withhold`](Exclusions::withhold) and [`withhold_targets`](Exclusions::withhold_targets), before anything is opened, and [`PortScanPlan::build`](crate::scanner::plan::PortScanPlan::build) for the zombie an idle scan reads | No probe is *addressed* to an excluded address the caller named, and the scope the report states is the scope that was actually walked |
//! | [`ScanContext::may_probe`](crate::scanner::session::ScanContext::may_probe), where a strategy turns an address it learned into a probe | No probe is addressed to an excluded address the scan found for itself, which the list never held |
//! | [`ScanContext::write_host`](crate::scanner::session::ScanContext::write_host), on every finding, and [`ScanContext::restore_hosts`](crate::scanner::session::ScanContext::restore_hosts), on every host a resumed scan brings back | Nothing about an excluded address is recorded, whichever path it arrived by. A router on a permitted host's path keeps its distance, which is a fact about that host's route, and loses its address: see [`Hop::withheld`](crate::model::host::Hop::withheld). A middlebox that sent evidence about a permitted host, an ICMP unreachable above all, leaves the evidence and loses its address: see [`EvidenceSource::Withheld`](crate::model::host::EvidenceSource::Withheld) |
//!
//! Subtracting up front is also what keeps the second cheap. Without it a `/8`
//! minus a `/24` would enumerate sixteen million addresses in order to discard
//! two hundred and fifty-four of them.
//!
//! ## An address names a machine
//!
//! On a segment a machine answers at several addresses, and a sweep hears the
//! IPv6 ones from the all-nodes echo and neighbour discovery, which no
//! exclusion can aim at. Held to its addresses alone, a policy excluding a
//! machine's IPv4 address would still report it under its link-local one. So
//! a scan reads the host's own neighbour tables when it starts, learns which
//! hardware address answers for each excluded address there without sending
//! it anything, and holds every address answering from that hardware to the
//! policy as well. Every other address the tables list at that hardware is
//! held to it from the start: a target named at one is withheld from the
//! phase's targets beside the excluded address, or passed over unasked where
//! a port scan's walk reaches it, since that walk is numbered in the plan
//! subtracted by address. An address heard answering from the hardware later
//! has its finding dropped at the third point above and is refused a probe at
//! the second from then on. Either way the phase lists it among its
//! [`excluded`](crate::report::TargetScope::excluded) ranges, so the report
//! still accounts for everything it left out.
//!
//! The tables are the only source. A machine this host has not spoken to
//! recently has no entry there, and nothing else ties its addresses together
//! before a packet to the excluded one would; it stays excluded by the address
//! alone. The IPv6 table is not read on Linux, and neither table on Windows.
//!
//! ## What it can and cannot promise
//!
//! It promises that no packet is addressed to an excluded address, and that no
//! excluded address appears in the report. That second one is worth stating
//! plainly because it is checkable: a reader with the report in hand can
//! confirm it against the ranges the report itself records, without trusting
//! this module.
//!
//! It does not promise that an excluded host never receives a packet. A segment
//! sweep's all-nodes echo is one datagram to `ff02::1` and an ARP request goes to
//! the broadcast address, so every machine on the link sees them, the excluded
//! one included, and nothing done afterwards can un-send them. What the gate does
//! with the reply is drop it.
//!
//! A caller who needs an excluded machine to see nothing at all has to not sweep
//! the segment it is on, which is a decision about the scan rather than about
//! this type.
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

use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::model::ip::range::{IpRange, Ipv6Range};
use crate::model::ip::set::IpSet;
use crate::model::mac::MacAddr;
use crate::model::target::{TargetMap, TargetSet};

/// The addresses a scan is forbidden to probe or to record.
///
/// Canonical from the moment it is built and never mutated in place except by
/// [`extend`](Self::extend), which canonicalizes again. That invariant is not
/// cosmetic: [`excludes`](Self::excludes) is consulted at every host finding, and
/// an unmerged set answers that by scanning its ranges rather than by binary
/// search. The type exists largely to make the fast path unconditional, which is
/// the argument [`TargetSet::new`](crate::model::target::TargetSet::new) makes
/// for targets.
///
/// It is also a distinct type from the [`IpSet`] it holds so that the two
/// cannot be confused at a call site. Passing targets where exclusions belong,
/// or the reverse, is a mistake that produces a scan rather than an error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exclusions {
    set: IpSet,
    /// The same addresses in their other spelling: each excluded IPv4 range as
    /// the IPv4-mapped IPv6 range naming it, and each range written inside
    /// `::ffff:0:0/96` as the IPv4 range it spells. Derived from `set` whenever
    /// that changes, enforced beside it, and never quoted, since nobody wrote it.
    ///
    /// `::ffff:192.0.2.1` is not an address in its own right: RFC 4291
    /// §2.5.5.2 makes it the way an IPv4 address is written inside an IPv6
    /// one, and a dual-stack socket handed it opens a connection to
    /// `192.0.2.1`. An [`IpSet`] keeps the two apart, correctly, since they are
    /// different values, so a policy held only to what was written covers one
    /// spelling of a machine and not the other.
    ///
    /// Only a range written wholly inside the mapped block speaks for IPv4.
    /// `::/0` holds that block as it holds every IPv6 address, and whoever
    /// writes it means "no IPv6"; read as a policy over all of IPv4 it would
    /// withhold a whole scan nobody excluded.
    twins: IpSet,
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
        let twins = twins_of(&ips);
        Self { set: ips, twins }
    }

    /// Whether the policy names any address at all.
    ///
    /// Worth testing before reporting one: "excluded nothing" and "no exclusion
    /// policy" are the same scan, and a front end that prints the first reads as
    /// though something was withheld.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Whether `ip` may not be probed or recorded, in either of the spellings a
    /// machine with an IPv4 address has.
    ///
    /// The whole of the policy, asked one address at a time. A binary search over
    /// merged ranges, and a bare `is_empty` check when no policy is in force,
    /// which is the case on most scans and is why this is affordable on the path
    /// every finding takes.
    ///
    /// Seeing through the mapping only ever widens what is excluded, so it
    /// cannot cause a probe that was not going to happen. It is done here and in
    /// [`withhold`](Self::withhold) rather than by normalising addresses at the
    /// parser, because these are the two places getting it wrong sends a packet.
    pub fn excludes(&self, ip: &IpAddr) -> bool {
        if self.set.is_empty() {
            return false;
        }
        self.set.contains(ip) || self.twins.contains(ip)
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
    /// Union rather than replacement, which is why this is a method and not an
    /// assignment. Exclusions arrive in layers, from a system-wide settings file
    /// and a user's own and a profile and the command line, and every other
    /// setting in that stack is overridden by the layer above it. Applying that
    /// rule here would let a user's file drop the range an administrator put in
    /// `/etc/zond/engine.toml`, which is the one key in the document where being
    /// overridden defeats the point of setting it.
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
        self.twins = twins_of(&self.set);
    }

    /// The hardware addresses `table` says answer for an address this policy
    /// excludes: the machines it names, as a link sees them. Each entry of
    /// `table` is an address a neighbour table lists and the hardware address
    /// it resolved to, `None` where it has not.
    ///
    /// An exclusion names an address and means a machine. On a segment a
    /// machine answers at several addresses, an IPv4 one and a link-local and
    /// global IPv6 or two, and a sweep hears the ones nobody could name in
    /// advance from the all-nodes echo and neighbour discovery, which no
    /// exclusion can aim at. What ties those to the excluded one is the
    /// hardware address, and the host's own neighbour table is where it is
    /// learned without a packet to the excluded address, which the policy
    /// forbids. A scan holds every address answering from one of these to the
    /// policy as it holds the excluded one; see
    /// [`ScanContext::write_host`](crate::scanner::session::ScanContext::write_host).
    ///
    /// An entry still being resolved has no hardware address and gives none,
    /// and neither does a group address, which answers for no one machine. A
    /// device several addresses share, a router answering ARP for what stands
    /// behind it, is withheld whole, which errs the one way a safety control
    /// may.
    pub(crate) fn hardware_in(
        &self,
        table: impl IntoIterator<Item = (IpAddr, Option<MacAddr>)>,
    ) -> BTreeSet<MacAddr> {
        if self.is_empty() {
            return BTreeSet::new();
        }
        table
            .into_iter()
            .filter(|(ip, _)| self.excludes(ip))
            .filter_map(|(_, mac)| mac)
            .filter(|mac| !mac.is_multicast() && <[u8; 6]>::from(*mac) != [0; 6])
            .collect()
    }

    /// The addresses `table` says answer from one of `machines` that this
    /// policy does not name itself: the rest of each machine it excludes, as
    /// far as the neighbour tables know it. `machines` is what
    /// [`hardware_in`](Self::hardware_in) read off the same table.
    ///
    /// Known before a packet is sent, which is what lets a scan hold a target
    /// it was handed at one of these to the policy before asking it anything,
    /// rather than dropping what it answers afterwards.
    pub(crate) fn tied_to(
        &self,
        machines: &BTreeSet<MacAddr>,
        table: impl IntoIterator<Item = (IpAddr, Option<MacAddr>)>,
    ) -> BTreeSet<IpAddr> {
        if machines.is_empty() {
            return BTreeSet::new();
        }
        table
            .into_iter()
            .filter(|(_, mac)| mac.is_some_and(|mac| machines.contains(&mac)))
            .map(|(ip, _)| ip)
            .filter(|ip| !self.excludes(ip))
            .collect()
    }

    /// This policy and `addresses` beside it, as one policy.
    ///
    /// For holding a phase's targets to a machine the policy names at the
    /// addresses it has been tied to as well as at the one written. What a
    /// report quotes from the result is its [`ranges`](Self::ranges), which
    /// then list those addresses among the excluded, so the report still
    /// accounts for everything the scan left out.
    pub(crate) fn widened(&self, addresses: impl IntoIterator<Item = IpAddr>) -> Self {
        let mut addresses = addresses.into_iter().peekable();
        if addresses.peek().is_none() {
            return self.clone();
        }
        let mut set = self.set.clone();
        for address in addresses {
            set.insert(address);
        }
        Self::new(set)
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
        ips.subtract(&self.twins);
        before.saturating_sub(ips.len())
    }

    /// [`withhold`](Self::withhold), for a map that pairs addresses with ports.
    ///
    /// Each unit is narrowed on its own and rebuilt, and a unit left with no
    /// address is dropped rather than kept as an empty question, since a unit
    /// naming only excluded addresses asks nothing. Rebuilding rather than editing
    /// in place is not a choice: a [`TargetSet`] is immutable once built, for the
    /// reason [`TargetSet::into_parts`] gives.
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

/// The other spelling of every range in `set` that has one. See
/// [`Exclusions::twins`].
fn twins_of(set: &IpSet) -> IpSet {
    let mut twins = IpSet::new();
    for range in set.v4() {
        let mapped = Ipv6Range::new(
            range.start_addr().to_ipv6_mapped(),
            range.end_addr().to_ipv6_mapped(),
        );
        if let Ok(mapped) = mapped {
            twins.push_v6_range(mapped);
        }
    }
    for range in set.v6() {
        if let Some(spelled) = range.spelled_ipv4() {
            twins.push_v4_range(spelled);
        }
    }
    twins.canonicalize();
    twins
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

    /// **An exclusion names the machine its address answers from.** The
    /// neighbour table ties an excluded address to a hardware address, and
    /// every other address the machine holds to the same one. An entry the
    /// kernel is still resolving ties nothing, nor does a group address, and
    /// an address the policy does not name gives its machine nothing to
    /// answer for.
    #[test]
    fn an_exclusion_names_the_hardware_its_address_answers_from() {
        let at = |ip: &str, mac: Option<MacAddr>| (ip.parse().expect("literal"), mac);
        let machine = MacAddr::new(0x02, 0, 0, 0, 0, 0x30);
        let table = [
            at("192.0.2.30", Some(machine)),
            at("192.0.2.31", Some(MacAddr::new(0x02, 0, 0, 0, 0, 0x31))),
            at("192.0.2.32", None),
            at(
                "192.0.2.255",
                Some(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)),
            ),
            at("2001:db8::30", Some(machine)),
        ];
        let mut ips = IpSet::new();
        for excluded in ["192.0.2.30", "192.0.2.32", "192.0.2.255"] {
            ips.insert(excluded.parse().expect("literal"));
        }

        assert_eq!(
            Exclusions::new(ips).hardware_in(table),
            BTreeSet::from([machine])
        );
        assert!(Exclusions::none().hardware_in(table).is_empty());
    }

    /// **The table names the rest of the machine before anything is sent.**
    /// Every address it lists at an excluded machine's hardware is tied to
    /// the policy, whether or not anyone named it, and an address with other
    /// hardware, or none resolved yet, is not. The excluded address itself is
    /// already the policy's and is not repeated.
    #[test]
    fn the_table_ties_every_other_address_of_an_excluded_machine() {
        let at = |ip: &str, mac: Option<MacAddr>| (ip.parse().expect("literal"), mac);
        let machine = MacAddr::new(0x02, 0, 0, 0, 0, 0x30);
        let table = [
            at("192.0.2.30", Some(machine)),
            at("192.0.2.40", Some(machine)),
            at("192.0.2.31", Some(MacAddr::new(0x02, 0, 0, 0, 0, 0x31))),
            at("192.0.2.32", None),
            at("2001:db8::30", Some(machine)),
        ];
        let policy = Exclusions::new(ips("192.0.2.30"));
        let machines = policy.hardware_in(table);

        let tied: Vec<IpAddr> = policy.tied_to(&machines, table).into_iter().collect();
        assert_eq!(
            tied,
            [v4(192, 0, 2, 40), "2001:db8::30".parse().expect("literal")]
        );
        assert!(policy.tied_to(&BTreeSet::new(), table).is_empty());

        let widened = policy.widened(tied);
        assert!(widened.excludes(&v4(192, 0, 2, 40)));
        assert!(widened.excludes(&v4(192, 0, 2, 30)));
        assert!(!widened.excludes(&v4(192, 0, 2, 31)));
    }
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
    /// Both halves at once, since they are what the two enforcements each
    /// guarantee and neither implies the other. The count says the plan shrank,
    /// and `excludes` says the gate holds for an address the plan never held.
    #[test]
    fn an_excluded_range_leaves_the_scope_and_stays_out_of_the_gate() {
        let policy = Exclusions::new(ips("198.51.100.64/26"));
        let mut scope = ips("198.51.100.0/24");

        assert_eq!(policy.withhold(&mut scope), 64);
        assert_eq!(scope.len(), 256 - 64);
        assert!(!scope.contains(&v4(198, 51, 100, 70)));
        assert!(scope.contains(&v4(198, 51, 100, 7)));

        assert!(policy.excludes(&v4(198, 51, 100, 70)));
        assert!(!policy.excludes(&v4(198, 51, 100, 7)));
    }

    /// A policy that names ground the scan was never going to walk withholds
    /// nothing, and says so.
    ///
    /// The zero is the finding. A front end that reports "254 addresses
    /// withheld" when the answer is none has told the operator their scope
    /// document was applied when nothing about it was.
    #[test]
    fn a_policy_that_does_not_overlap_withholds_nothing() {
        let policy = Exclusions::new(ips("203.0.113.0/24"));
        let mut scope = ips("198.51.100.0/24");

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
        let mut policy = Exclusions::new(ips("192.0.2.0/24"));
        policy.extend(&Exclusions::new(ips("203.0.113.0/24")));

        assert!(policy.excludes(&v4(192, 0, 2, 1)));
        assert!(policy.excludes(&v4(203, 0, 113, 1)));
        assert!(
            policy.excludes(&"::ffff:203.0.113.1".parse().expect("literal")),
            "a layer's other spelling arrives with it"
        );

        let mut map = TargetMap::new();
        map.add_unit(TargetSet::new(ips("192.0.2.0/24"), PortSet::top_tcp(2)));
        map.add_unit(TargetSet::new(ips("198.51.100.0/24"), PortSet::top_tcp(2)));

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

    /// The same rule before anything is opened, which is where it keeps a packet
    /// off the wire.
    ///
    /// A target written the mapped way is withheld from the plan by a policy
    /// naming the IPv4 form, and one written the IPv4 way by a policy naming the
    /// mapped form. Surviving withholding, such a target lands in a connect
    /// step, the dual-stack socket reaches the machine the policy forbade, and
    /// the gate drops the reply: a probe the report never shows.
    #[test]
    fn a_target_is_withheld_in_either_spelling() {
        let v4_policy = Exclusions::new(ips("192.0.2.0/24"));
        let mut mapped = ips("::ffff:192.0.2.1");
        assert_eq!(v4_policy.withhold(&mut mapped), 1);
        assert!(mapped.is_empty());

        let mapped_policy = Exclusions::new(ips("::ffff:192.0.2.0/120"));
        let mut plain = ips("192.0.2.1");
        assert_eq!(mapped_policy.withhold(&mut plain), 1);
        assert!(plain.is_empty());
        assert!(mapped_policy.excludes(&v4(192, 0, 2, 1)));
    }

    /// Only an exclusion written inside the mapped block speaks for IPv4.
    ///
    /// `::/0` holds that block as it holds every IPv6 address, and whoever
    /// writes it means "no IPv6", not "nothing at all". Read as a policy over
    /// every IPv4 address it would withhold a whole scan nobody excluded, so the
    /// mapped addresses it covers are excluded as written and no further.
    #[test]
    fn an_ipv6_range_that_only_contains_the_mapped_block_leaves_ipv4_alone() {
        let policy = Exclusions::new(ips("::/0"));

        let mut plain = ips("192.0.2.1");
        assert_eq!(policy.withhold(&mut plain), 0);
        assert!(!policy.excludes(&v4(192, 0, 2, 1)));
        assert!(
            policy.excludes(&"::ffff:192.0.2.1".parse().expect("literal")),
            "the mapped spelling is inside ::/0 as written"
        );
    }

    /// What a report quotes as the policy is what was written. The other
    /// spelling is enforced beside it, and quoting it too would list a range
    /// nobody asked for.
    #[test]
    fn the_other_spelling_is_enforced_without_being_quoted() {
        let policy = Exclusions::new(ips("192.0.2.0/24"));
        assert_eq!(
            policy.ranges(),
            vec![IpRange::V4(
                "192.0.2.0/24"
                    .parse::<IpRange>()
                    .map(|range| match range {
                        IpRange::V4(v4) => v4,
                        IpRange::V6(_) => unreachable!("an IPv4 literal"),
                    })
                    .expect("a valid range")
            )]
        );
    }

    /// **A machine written the other way round is still the machine.**
    ///
    /// `::ffff:192.0.2.1` is not an address in its own right — RFC 4291
    /// §2.5.5.2 makes it the way an IPv4 address is spelled inside an IPv6 one —
    /// and the unprivileged connect path hands it to the operating system, which
    /// opens a connection to `192.0.2.1`. So a policy naming the v4 form has to
    /// cover a target written the other way, or the packet the policy forbade
    /// goes out.
    #[test]
    fn an_excluded_address_is_excluded_in_either_spelling() {
        let mut forbidden = IpSet::new();
        forbidden.insert_range("192.0.2.0/24".parse().expect("a valid range"));
        let exclusions = Exclusions::new(forbidden);

        assert!(exclusions.excludes(&"192.0.2.1".parse().expect("literal")));
        assert!(
            exclusions.excludes(&"::ffff:192.0.2.1".parse().expect("literal")),
            "the mapped spelling reaches the same machine and must be refused too"
        );
        assert!(
            exclusions.excludes(&"::ffff:c000:201".parse().expect("literal")),
            "including written in hextets, which is the same address again"
        );
    }

    /// And seeing through the mapping only ever widens what is excluded.
    ///
    /// An IPv6 address that is not a mapped one is untouched, and a v4 policy
    /// does not start refusing IPv6 traffic it was never asked about.
    #[test]
    fn seeing_through_the_mapping_refuses_nothing_it_was_not_asked_to() {
        let mut forbidden = IpSet::new();
        forbidden.insert_range("192.0.2.0/24".parse().expect("a valid range"));
        let exclusions = Exclusions::new(forbidden);

        for allowed in ["198.51.100.1", "2001:db8::1", "::ffff:198.51.100.1", "::1"] {
            assert!(
                !exclusions.excludes(&allowed.parse().expect("literal")),
                "{allowed} is outside the policy and must stay outside it"
            );
        }

        // And an empty policy still excludes nothing at all.
        let none = Exclusions::none();
        assert!(!none.excludes(&"::ffff:192.0.2.1".parse().expect("literal")));
    }
}
