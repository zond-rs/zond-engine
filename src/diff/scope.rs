// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a report says it looked at
//!
//! One report's [`TargetScope`]s, flattened across its phases and turned into the
//! question a comparison asks: was this target covered? Every [`Coverage`] answer
//! in a diff comes from here.

use std::net::IpAddr;

use crate::diff::change::Coverage;
use crate::model::host::Host;
use crate::model::ip::set::IpSet;
use crate::model::port::Protocol;
use crate::report::{PortScope, ScanReport, TargetScope};

/// The ranges and port sets a report says it walked, gathered once so an address
/// can be placed without walking the phases again.
///
/// A set rather than a list. Held as two `Vec<IpRange>`, placing one address
/// asked every range of every phase in turn, once per address of every host, and
/// a report merged from a `/16` scanned in chunks carries hundreds of ranges
/// against tens of thousands of questions. [`IpSet`] canonicalises on
/// construction and answers by binary search over disjoint ranges.
pub(crate) struct ScopeIndex {
    covered: IpSet,
    withheld: IpSet,
    stated: bool,
    ports: Vec<PortScope>,
    /// The phases' scopes, kept whole because a link sweep is not a range and
    /// cannot be flattened into one.
    scopes: Vec<TargetScope>,
}

impl ScopeIndex {
    pub(crate) fn of(report: &ScanReport) -> Self {
        let mut covered = IpSet::new();
        let mut withheld = IpSet::new();
        let mut ports = Vec::new();
        let mut scopes = Vec::new();

        for phase in report.phases() {
            let scope = phase.targets();
            for range in scope.ranges() {
                covered.insert_range(*range);
            }
            for range in scope.excluded() {
                withheld.insert_range(*range);
            }
            ports.push(scope.ports().clone());
            scopes.push(scope.clone());
        }

        // Both are searched and never extended again, so the ordering the
        // search needs is established once here.
        covered.canonicalize();
        withheld.canonicalize();

        let stated = !covered.is_empty()
            || !withheld.is_empty()
            || scopes.iter().any(|scope| !scope.links().is_empty());
        Self {
            covered,
            withheld,
            stated,
            ports,
            scopes,
        }
    }

    /// Whether the report says anything about which addresses it walked.
    pub(crate) fn states_scope(&self) -> bool {
        self.stated
    }

    /// What the report says about having covered a host.
    ///
    /// Asked of every address the host is known at rather than only the one it
    /// is keyed by. A host is covered if the scan walked ground it was standing
    /// on, and which address a report keys it under is the report's business
    /// rather than the network's: a dual-stack machine keyed under IPv6 in one
    /// scan and IPv4 in the other was in reach of a sweep of the IPv4 range both
    /// times.
    ///
    /// The strongest answer over those addresses wins, on the same reasoning
    /// that makes covered beat withheld for one of them.
    pub(crate) fn of_host(&self, host: &Host) -> Coverage {
        // A sweep of the link the host was found on covers it whatever
        // addresses it holds, so this is asked first and once rather than per
        // address. See `TargetScope::swept`.
        if self.scopes.iter().any(|scope| scope.swept(host.zone())) {
            return Coverage::Covered;
        }

        let mut best = Coverage::Unstated;

        for ip in host.ips() {
            match self.address(ip) {
                Coverage::Covered => return Coverage::Covered,
                Coverage::Withheld => best = Coverage::Withheld,
                Coverage::OutOfScope if best != Coverage::Withheld => {
                    best = Coverage::OutOfScope;
                }
                _ => {}
            }
        }

        best
    }

    /// What the report says about having walked one address, on `zone`.
    ///
    /// Covered wins over withheld, since a job's two phases can disagree: a
    /// discovery sweep that walked an address and a port scan that was forbidden
    /// it still means somebody looked.
    ///
    /// Whether a link was swept is a separate question, asked by
    /// [`of_host`](Self::of_host), since it is about the host rather than about
    /// any one of its addresses.
    pub(crate) fn address(&self, ip: &IpAddr) -> Coverage {
        if self.covered.contains(ip) {
            Coverage::Covered
        } else if self.withheld.contains(ip) {
            Coverage::Withheld
        } else if self.stated {
            Coverage::OutOfScope
        } else {
            Coverage::Unstated
        }
    }

    /// What the report says about having probed one endpoint of an address whose
    /// own coverage is `address`.
    ///
    /// An address nothing walked has no endpoint anything walked, so a withheld
    /// or out-of-scope address carries its answer straight down. Otherwise the
    /// phases decide and any phase that cannot say vetoes the rest: a job whose
    /// sweep walked no ports and whose port scan did not record which ports it
    /// walked knows nothing about this endpoint, and the sweep's certainty about
    /// its own half is not the job's.
    pub(crate) fn endpoint(&self, address: Coverage, port: u16, protocol: Protocol) -> Coverage {
        if address.is_excluded() {
            return address;
        }

        let mut stated = false;
        let mut cannot_say = false;

        for scope in &self.ports {
            match scope.covers(port, protocol) {
                Some(true) => return Coverage::Covered,
                Some(false) => stated = true,
                None => cannot_say = true,
            }
        }

        if cannot_say {
            Coverage::Unstated
        } else if stated {
            Coverage::OutOfScope
        } else {
            Coverage::Unstated
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
    use crate::system::privilege::Privilege;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::config::ZondConfig;
    use crate::model::exclusion::Exclusions;
    use crate::model::ip::set::IpSet;
    use crate::model::parse::ip::to_set;
    use crate::report::{PhaseParts, ScanKind, ScanPhase, ScanSettings, ScopeParts};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, last))
    }

    /// A report stating what it walked and what its policy withheld.
    ///
    /// Built through [`TargetScope::from_ip_set`] with real [`Exclusions`], so
    /// the withheld ranges are subtracted from the walked ones the way a scan
    /// subtracts them. Listing a range as both walked and excluded would make a
    /// fixture no scan can produce.
    fn report(covered: &[&str], excluded: &[&str], ports: PortScope) -> ScanReport {
        let exclusions = if excluded.is_empty() {
            Exclusions::none()
        } else {
            Exclusions::new(to_set(excluded, None, None).expect("parseable ranges"))
        };

        let mut targets = if covered.is_empty() {
            IpSet::new()
        } else {
            to_set(covered, None, None).expect("parseable ranges")
        };
        let walked = TargetScope::from_ip_set(&mut targets, &exclusions);

        let scope = TargetScope::from_parts(ScopeParts {
            listened: Vec::new(),
            ranges: walked.ranges().to_vec(),
            links: Vec::new(),
            addresses: walked.addresses(),
            probes: None,
            ports,
            protocols: Vec::new(),
            excluded: walked.excluded().to_vec(),
            withheld: walked.withheld(),
        });

        let phase = ScanPhase::from_parts(PhaseParts {
            attachments: Vec::new(),
            kind: ScanKind::Discovery,
            started_at: SystemTime::UNIX_EPOCH,
            elapsed: Duration::from_secs(1),
            privilege: Some(Privilege::Raw),
            targets: scope,
            settings: ScanSettings::from(&ZondConfig::default()),
            failures: Vec::new(),
            refusals: Vec::new(),
            unroutable: Vec::new(),
            probes: Vec::new(),
            origin: None,
        });

        ScanReport::recorded("test", vec![phase], Vec::new())
    }

    #[test]
    fn an_address_inside_a_walked_range_is_covered() {
        let index = ScopeIndex::of(&report(&["192.168.0.0/24"], &[], PortScope::NoPorts));
        assert_eq!(index.address(&ip(7)), Coverage::Covered);
    }

    /// A range the policy withheld is not the same as one the scan never named:
    /// the report says it was told not to look.
    #[test]
    fn an_address_the_policy_withheld_is_reported_as_withheld() {
        let index = ScopeIndex::of(&report(
            &["192.168.0.0/24"],
            &["192.168.0.64/26"],
            PortScope::NoPorts,
        ));
        assert_eq!(index.address(&ip(100)), Coverage::Withheld);
        assert_eq!(index.address(&ip(7)), Coverage::Covered);
    }

    #[test]
    fn an_address_outside_a_stated_scope_is_out_of_scope() {
        let index = ScopeIndex::of(&report(&["192.168.0.0/25"], &[], PortScope::NoPorts));
        assert_eq!(index.address(&ip(200)), Coverage::OutOfScope);
    }

    /// A report that states no scope cannot answer the question, and says so
    /// rather than guessing.
    #[test]
    fn a_report_that_states_no_scope_answers_unstated() {
        let index = ScopeIndex::of(&report(&[], &[], PortScope::NoPorts));
        assert!(!index.states_scope());
        assert_eq!(index.address(&ip(7)), Coverage::Unstated);
    }

    #[test]
    fn an_endpoint_is_no_better_covered_than_its_address() {
        let index = ScopeIndex::of(&report(&["192.168.0.0/24"], &[], PortScope::NoPorts));
        assert_eq!(
            index.endpoint(Coverage::OutOfScope, 22, Protocol::Tcp),
            Coverage::OutOfScope,
            "a port on an address nobody walked is not covered"
        );
    }
}
