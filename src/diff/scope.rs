// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a report says it looked at
//!
//! One report's [`TargetScope`]s, flattened across its phases and turned into
//! the question a comparison actually asks: was *this* target covered? Every
//! [`Coverage`] answer in a diff comes from here.

use std::net::IpAddr;

use crate::diff::change::Coverage;
use crate::model::host::Host;
use crate::model::ip::range::IpRange;
use crate::model::ip::scoped::Zone;
use crate::model::port::Protocol;
use crate::scanner::report::{PortScope, ScanReport, TargetScope};

/// The ranges and port sets a report says it walked, gathered once so an address
/// can be placed without walking the phases again.
pub(crate) struct ScopeIndex {
    covered: Vec<IpRange>,
    withheld: Vec<IpRange>,
    stated: bool,
    ports: Vec<PortScope>,
    /// The phases' scopes, kept whole because a link sweep is not a range and
    /// cannot be flattened into one.
    scopes: Vec<TargetScope>,
}

impl ScopeIndex {
    pub(crate) fn of(report: &ScanReport) -> Self {
        let mut covered = Vec::new();
        let mut withheld = Vec::new();
        let mut ports = Vec::new();
        let mut scopes = Vec::new();

        for phase in report.phases() {
            let scope = phase.targets();
            covered.extend_from_slice(scope.ranges());
            withheld.extend_from_slice(scope.excluded());
            ports.push(scope.ports().clone());
            scopes.push(scope.clone());
        }

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
    /// **Asked of every address the host is known at, not only the one it is
    /// keyed by.** A host is covered if the scan walked ground it was standing
    /// on, and which of its addresses a report happens to key it under is the
    /// report's business rather than the network's — a dual-stack machine keyed
    /// under IPv6 in one scan and IPv4 in the other was equally in reach of a
    /// sweep of the IPv4 range both times.
    ///
    /// The strongest answer over those addresses wins, on the same reasoning
    /// that makes covered beat withheld for one of them.
    pub(crate) fn of_host(&self, host: &Host) -> Coverage {
        let zone = host.zone();
        let mut best = Coverage::Unstated;

        for ip in host.ips() {
            match self.address(ip, zone) {
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
    /// Covered wins over withheld, because a job's two phases can disagree: a
    /// discovery sweep that walked an address and a port scan that was forbidden
    /// it still means somebody looked.
    ///
    /// A link-local address is covered by a phase that swept its link, whether
    /// or not any range named it — which is the only way an address nobody could
    /// have named in advance is ever covered. See
    /// [`TargetScope::links`](crate::scanner::report::TargetScope::links).
    pub(crate) fn address(&self, ip: &IpAddr, zone: Option<&Zone>) -> Coverage {
        if self.covered.iter().any(|range| range.contains(ip))
            || self.scopes.iter().any(|scope| scope.sweeps(ip, zone))
        {
            Coverage::Covered
        } else if self.withheld.iter().any(|range| range.contains(ip)) {
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
    /// phases decide, and **any phase that cannot say vetoes the rest**: a job
    /// whose sweep walked no ports and whose port scan did not record which
    /// ports it walked knows nothing about this endpoint, and the sweep's
    /// certainty about its own half must not be read as the job's.
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
