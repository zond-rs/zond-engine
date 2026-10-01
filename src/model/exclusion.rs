// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Addresses a scan may not touch
//!
//! [`Exclusions`] makes a scan cover *less* than it was asked to. Its failure mode is a
//! packet somebody was told would not be sent.
//!
//! ## More than a filter on the target list
//!
//! Subtracting excluded addresses from the target set is necessary but not sufficient,
//! because the list is not the only way an address enters a scan. A segment sweep takes
//! leads from the host's IPv6 neighbour table, learns addresses from mDNS records and
//! from ARP and neighbour-advertisement replies, and probes what it finds; none of those
//! were in the list.
//!
//! So the policy is enforced at three points:
//!
//! | Where | What it guarantees |
//! |---|---|
//! | [`withhold`](Exclusions::withhold) and [`withhold_targets`](Exclusions::withhold_targets), before anything is opened, and [`PortScanPlan::build`](crate::scanner::plan::PortScanPlan::build) for the zombie an idle scan reads | No probe is *addressed* to an excluded address the caller named, and the scope the report states is the scope that was actually walked |
//! | [`ScanContext::may_probe`](crate::scanner::session::ScanContext::may_probe), where a strategy turns an address it learned into a probe | No probe is addressed to an excluded address the scan found for itself, which the list never held |
//! | [`ScanContext::write_host`](crate::scanner::session::ScanContext::write_host), on every finding, and [`ScanContext::restore_hosts`](crate::scanner::session::ScanContext::restore_hosts), on every host a resumed scan brings back | Nothing about an excluded address is recorded, whichever path it arrived by. A router on a permitted host's path keeps its distance, which is a fact about that host's route, and loses its address: see [`Hop::withheld`](crate::model::host::Hop::withheld). A middlebox that sent evidence about a permitted host, an ICMP unreachable above all, leaves the evidence and loses its address: see [`EvidenceSource::Withheld`](crate::model::host::EvidenceSource::Withheld) |
//!
//! Subtracting up front also keeps the second check cheap: otherwise a `/8` minus a
//! `/24` would enumerate sixteen million addresses to discard 254.
//!
//! ## An address names a machine
//!
//! A machine on a segment answers at several addresses, and a sweep hears the IPv6 ones
//! from the all-nodes echo and neighbour discovery, which no exclusion can aim at. So a
//! scan reads the host's neighbour tables when it starts, learns (without sending
//! anything) which hardware address answers for each excluded address, and holds every
//! address answering from that hardware to the policy too. Addresses the tables already
//! list at that hardware are held from the start: a target named at one is withheld
//! from the phase's targets, or passed over unasked where a port scan's walk reaches
//! it. An address heard from that hardware later has its finding dropped at the third
//! point above and is refused probes at the second. Either way the phase lists it among
//! its [`excluded`](crate::report::TargetScope::excluded) ranges.
//!
//! The tables are the only source. A machine this host has not spoken to recently has
//! no entry, and stays excluded by address alone. The IPv6 table is not read on Linux,
//! and neither table on Windows.
//!
//! ## What it promises
//!
//! No packet is addressed to an excluded address, and no excluded address appears in
//! the report. The second is checkable against the ranges the report itself records.
//!
//! It does not promise that an excluded host receives nothing. A segment sweep's
//! all-nodes echo to `ff02::1` and an ARP request to the broadcast address reach every
//! machine on the link; the gate drops the excluded one's reply. To keep a machine from
//! seeing anything, do not sweep its segment.
//!
//! ## Zones
//!
//! Exclusion ignores interfaces, for the reason [`IpSet::subtract`] gives: a reply
//! arrives as a bare address with no interface to compare against. Excluding `fe80::5`
//! or `fe80::5%en0` excludes it on every link, which errs toward withholding more.

use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::model::ip::range::{IpRange, Ipv6Range};
use crate::model::ip::set::IpSet;
use crate::model::mac::MacAddr;
use crate::model::target::{TargetMap, TargetSet};

/// The addresses a scan is forbidden to probe or to record.
///
/// Canonical from construction, and mutated only by [`extend`](Self::extend), which
/// canonicalizes again. [`excludes`](Self::excludes) runs at every host finding and
/// relies on that for its binary search (as
/// [`TargetSet::new`](crate::model::target::TargetSet::new) does for targets).
///
/// A distinct type from the [`IpSet`] it holds, so targets and exclusions cannot be
/// swapped at a call site.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exclusions {
    set: IpSet,
    /// The same addresses in their other spelling: each excluded IPv4 range as
    /// the IPv4-mapped IPv6 range naming it, and each range written inside
    /// `::ffff:0:0/96` as the IPv4 range it spells. Derived from `set` whenever
    /// that changes, enforced beside it, and never quoted, since nobody wrote it.
    ///
    /// `::ffff:192.0.2.1` is how RFC 4291 §2.5.5.2 writes an IPv4 address inside an
    /// IPv6 one, and a dual-stack socket handed it connects to `192.0.2.1`. An
    /// [`IpSet`] treats them as different values, so without this a policy would cover
    /// only one spelling of a machine.
    ///
    /// Only a range written wholly inside the mapped block speaks for IPv4. `::/0`
    /// contains that block, but whoever writes it means "no IPv6".
    twins: IpSet,
}

impl Exclusions {
    /// A policy that excludes nothing.
    ///
    /// The default. Every operation returns immediately on an empty policy.
    pub fn none() -> Self {
        Self::default()
    }

    /// A policy over `ips`.
    ///
    /// Canonicalizes them once, so every read afterwards takes `&self` and the fast
    /// path.
    pub fn new(mut ips: IpSet) -> Self {
        ips.canonicalize();
        let twins = twins_of(&ips);
        Self { set: ips, twins }
    }

    /// Whether the policy names any address at all.
    ///
    /// An empty policy is the same scan as no policy; check this before reporting one.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Whether `ip` may not be probed or recorded, in either of the spellings a
    /// machine with an IPv4 address has.
    ///
    /// A binary search over merged ranges, or just an `is_empty` check when no policy
    /// is in force, which is cheap enough for the path every finding takes.
    ///
    /// Seeing through the IPv4 mapping only widens what is excluded. It is done here
    /// and in [`withhold`](Self::withhold), the two places where getting it wrong sends
    /// a packet.
    pub fn excludes(&self, ip: &IpAddr) -> bool {
        if self.set.is_empty() {
            return false;
        }
        self.set.contains(ip) || self.twins.contains(ip)
    }

    /// Every excluded range, ascending, IPv4 before IPv6.
    ///
    /// The merged form, so a report quotes what was enforced: two overlapping
    /// exclusions appear as the one range they amount to.
    pub fn ranges(&self) -> Vec<IpRange> {
        let v4 = self.set.v4().iter().copied().map(IpRange::V4);
        let v6 = self.set.v6().iter().copied().map(IpRange::V6);
        v4.chain(v6).collect()
    }

    /// Adds everything `other` excludes to this policy.
    ///
    /// A union. Exclusions arrive in layers (a system-wide settings file, a user's
    /// own, a profile, the command line) where every other setting is overridden by
    /// the layer above; overriding here would let a user's file drop a range an
    /// administrator put in `/etc/zond/engine.toml`. Layered exclusions can only make a
    /// scan smaller.
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
    /// An exclusion names an address and means a machine. The hardware address ties a
    /// machine's other addresses to the excluded one, and the host's neighbour table
    /// supplies it without sending a packet. A scan holds every address answering from
    /// one of these to the policy; see
    /// [`ScanContext::write_host`](crate::scanner::session::ScanContext::write_host).
    ///
    /// An entry still being resolved gives none, and neither does a group address. A
    /// device answering for several addresses, such as a router answering ARP for what
    /// stands behind it, is withheld whole.
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
    /// Known before a packet is sent, so a target at one of these is withheld before
    /// it is asked anything.
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

    /// This policy plus every address `table` (a neighbour table's addresses and the
    /// hardware each resolved to) ties to a machine it names: the policy as a scan
    /// reading that table will enforce it. A front end calls this through the
    /// neighbour cache before a scan starts.
    pub(crate) fn tied_in(&self, table: Vec<(IpAddr, Option<MacAddr>)>) -> Self {
        let machines = self.hardware_in(table.iter().copied());
        self.widened(self.tied_to(&machines, table))
    }

    /// This policy and `addresses` beside it, as one policy.
    ///
    /// Holds a phase's targets to a machine's tied addresses as well as the written
    /// one. The result's [`ranges`](Self::ranges) list those addresses among the
    /// excluded, so the report accounts for everything left out.
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
    /// The planning-time half of the enforcement. Call it before the target set is
    /// measured, so the scope a report states is the scope that was walked.
    ///
    /// The count is the *overlap*, not the size of the policy: a policy naming a range
    /// the scan would never reach returns zero, which tells a configured policy that
    /// did nothing from one that worked.
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
    /// Each unit is narrowed and rebuilt (a [`TargetSet`] is immutable; see
    /// [`TargetSet::into_parts`]), and a unit left with no address is dropped.
    ///
    /// The count is gross, like every count on a [`TargetMap`]: two units naming the
    /// same excluded address count twice, so the number can be subtracted from
    /// [`gross_ips`](TargetMap::gross_ips).
    ///
    /// It saturates where `gross_ips` returns
    /// [`CapacityOverflow`](crate::model::target::TargetError::CapacityOverflow); at
    /// that size there is nothing to subtract it from.
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

    /// **An exclusion names the machine its address answers from.** The neighbour
    /// table ties an excluded address to a hardware address. An unresolved entry, a
    /// group address, or an address the policy does not name ties nothing.
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

    /// **A count taken before a scan starts withholds what the scan will**, including a
    /// target named at another address of an excluded machine.
    #[test]
    fn a_target_at_another_address_of_an_excluded_machine_is_counted_withheld() {
        let at = |ip: &str, mac: Option<MacAddr>| (ip.parse().expect("literal"), mac);
        let machine = MacAddr::new(0x02, 0, 0, 0, 0, 0x30);
        let table = vec![
            at("192.0.2.30", Some(machine)),
            at("192.0.2.40", Some(machine)),
            at("192.0.2.41", Some(MacAddr::new(0x02, 0, 0, 0, 0, 0x41))),
        ];
        let policy = Exclusions::new(ips("192.0.2.30"));
        let named = || ips("192.0.2.40-192.0.2.41");

        assert_eq!(policy.withhold(&mut named()), 0, "the policy alone");
        let mut targets = named();
        assert_eq!(policy.tied_in(table).withhold(&mut targets), 1);
        assert_eq!(targets, ips("192.0.2.41"), "the other machine is asked");
    }

    /// **The table names the rest of the machine before anything is sent.** Every
    /// address listed at an excluded machine's hardware is tied to the policy; other
    /// hardware or unresolved entries are not, and the excluded address is not
    /// repeated.
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
    /// The count says the plan shrank, and `excludes` says the gate holds for an
    /// address the plan never held.
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

    /// A policy naming ground the scan would never walk withholds nothing, and the
    /// count says zero.
    #[test]
    fn a_policy_that_does_not_overlap_withholds_nothing() {
        let policy = Exclusions::new(ips("203.0.113.0/24"));
        let mut scope = ips("198.51.100.0/24");

        assert_eq!(policy.withhold(&mut scope), 0);
        assert_eq!(scope.len(), 256);
    }

    /// Layering takes the union, so an administrator's range survives a user's file
    /// naming its own, and a unit reduced to nothing is dropped.
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
    /// Over-exclusion, the only reading the gate can implement; see the module
    /// documentation. Making zones significant in `subtract` would silently narrow a
    /// safety control.
    #[test]
    fn a_zoned_exclusion_withholds_the_address_everywhere() {
        let address: Ipv6Addr = "fe80::5".parse().expect("literal");

        let mut named_on_one_interface = IpSet::new();
        named_on_one_interface
            .push_v6_range(Ipv6Range::scoped(address, address, Some(1)).expect("start <= end"));
        let policy = Exclusions::new(named_on_one_interface);

        assert!(policy.excludes(&IpAddr::V6(address)));

        // It also comes out of a scope naming the address on another link.
        let mut scope = IpSet::new();
        scope.push_v6_range(Ipv6Range::scoped(address, address, Some(2)).expect("start <= end"));
        scope.canonicalize();

        assert_eq!(policy.withhold(&mut scope), 1);
        assert!(scope.is_empty());
    }

    /// The same rule at planning time, where it keeps a packet off the wire. A target
    /// in either spelling is withheld by a policy naming the other; otherwise a
    /// dual-stack connect would reach the forbidden machine.
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
    /// `::/0` means "no IPv6", so the mapped addresses it covers are excluded as
    /// written and IPv4 is untouched.
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

    /// A report quotes the policy as written; the other spelling is enforced but not
    /// quoted.
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
    /// `::ffff:192.0.2.1` is `192.0.2.1` spelled inside IPv6 (RFC 4291 §2.5.5.2), and
    /// the unprivileged connect path would connect to it, so a policy naming the v4
    /// form has to cover it.
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

    /// Seeing through the mapping only widens what is excluded: a v4 policy refuses no
    /// unmapped IPv6 address.
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

        // An empty policy still excludes nothing.
        let none = Exclusions::none();
        assert!(!none.excludes(&"::ffff:192.0.2.1".parse().expect("literal")));
    }
}
