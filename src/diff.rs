// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Comparing two scans
//!
//! Scan a network, scan it again a week later, and ask what changed. A host that
//! was not there before, a port that opened, a service that moved a version, a
//! certificate that rotated or is about to lapse: [`ScanDiff`] is all of that as
//! a structure, computed from two [`ScanReport`]s and holding no opinion about
//! how any of it is shown.
//!
//! ```no_run
//! use zond_engine::diff::ScanDiff;
//! # use zond_engine::report::ScanReport;
//! # fn example(last_week: &ScanReport, today: &ScanReport) {
//! let diff = ScanDiff::between(last_week, today);
//!
//! let summary = diff.summary();
//! println!(
//!     "{} hosts appeared, {} gone, {} ports opened",
//!     summary.hosts_added.total, summary.hosts_removed.total, summary.ports_opened.total,
//! );
//!
//! for host in diff.hosts() {
//!     for port in host.ports() {
//!         if port.is_opened() {
//!             println!("{}:{} is open", host.address(), port.number());
//!         }
//!     }
//! }
//! # }
//! ```
//!
//! ## Two scans, not two of this engine's scans
//!
//! The comparison takes [`ScanReport`]s and asks nothing about where they came
//! from. One can be a scan this process just ran, one can be read back from a
//! [`journal`](crate::journal), and one can be a report some other scanner
//! produced and something built a `ScanReport` out of. Comparing last quarter's
//! nmap output against tonight's scan is the same call as comparing two of this
//! engine's own runs.
//!
//! That is why nothing here reaches for a field only this engine fills in. A
//! report with no phases, no scope, no probe statistics and no hardware
//! addresses still compares; it just answers "unstated" to the questions its
//! record cannot answer, which is covered below.
//!
//! ## Verdicts are compared. Evidence is not.
//!
//! A report carries two kinds of record, and the
//! [`report`](crate::report) module keeps them apart on purpose:
//! findings about the network, and measurements about the scan. **Only the
//! findings are compared.**
//!
//! So a host's status is compared and the probe that established it is not. A
//! port's state is compared and the packet that settled it is not. A service's
//! identity is compared and the confidence behind it is not. An operating system
//! is compared by what it names, not by how sure the fingerprinter was.
//!
//! Left out entirely, and deliberately: round-trip times, hop counters, measured
//! routes, capture counters, per-scanner probe statistics, first- and last-seen
//! timestamps, and strategy failures. Every one of them moves between two scans
//! of an unchanged network, and a diff that reported them would drown the one
//! line that mattered.
//!
//! ## What "gone" is allowed to mean
//!
//! A host in last week's report and not in tonight's has two very different
//! explanations, and a monitoring tool that cannot tell them apart raises an
//! alarm every time somebody narrows a scan. So every appearance and every
//! disappearance carries [`Coverage`]: what the *other* scan says about whether
//! it covered that target at all.
//!
//! [`TargetScope`](crate::report::TargetScope) is where that comes
//! from. Each phase of a report records the ranges it walked after exclusions and
//! the ranges its policy withheld, so an address can be placed in one, the other,
//! or neither. A report carrying no scope answers [`Coverage::Unstated`], and
//! [`Presence::is_confirmed`] is the one test that separates a host that went
//! away from a host nobody asked about.
//!
//! Ports are a weaker case and say so. A scope records the addresses a phase
//! walked, not the ports it walked on each, so an endpoint of a covered address
//! answers `Unstated` too. Where the address itself was withheld or out of scope
//! the endpoint inherits that, since nothing was probed there at all.
//!
//! ## Which record continues which
//!
//! Hosts do not pair by address alone: a machine can change address between two
//! scans, and one scan can see as a single host what another sees as two. That
//! decision is [`HostIdentity`]'s, it is a field of [`DiffOptions`], and
//! [`pairing`] is the whole argument for how it is made.
//!
//! ## Which clock a certificate is judged against
//!
//! "Expires within thirty days" is a question about a moment, and the moment a
//! diff is *taken* is not the moment either scan ran. So each side is judged
//! against its own scan's clock: the baseline's standing at the baseline's start
//! time, the current standing at the current scan's. A certificate nobody touched
//! then crosses the threshold exactly once, between the two scans that straddle
//! it, which is what makes it a change rather than a property.
//!
//! A report with no phases has no start time to take, and the latest sighting
//! among its hosts is used instead. [`DiffOptions::as_of`] overrides the current
//! side, for a caller asking where things stand now rather than where they stood
//! when the scan ran.

pub mod change;
pub mod host;
pub mod pairing;
pub mod port;
mod scope;

use std::time::{Duration, SystemTime};

use crate::model::host::Host;
use crate::report::{ScanKind, ScanReport};

pub use crate::diff::change::{Change, Coverage, Presence};
pub use crate::diff::host::{HostChange, HostDelta};
pub use crate::diff::pairing::HostIdentity;
pub use crate::diff::port::{
    CertificateChange, PortChange, PortDelta, SecurityChange, ServiceChange,
};

use crate::diff::port::Clocks;
use crate::diff::scope::ScopeIndex;

/// How long before a certificate lapses it counts as expiring, when a caller
/// does not say.
///
/// Thirty days is the interval the public web has settled on: it is what the
/// major certificate authorities send their first renewal notice at, and what
/// most monitoring templates ship with.
pub const DEFAULT_EXPIRY_THRESHOLD: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// What a comparison is allowed to assume.
///
/// The defaults suit two scans of the same network by the same tool. Change
/// [`identity`](Self::with_identity) when addresses are not stable between the
/// two, and [`as_of`](Self::as_of) when the question is where certificates stand
/// now rather than when the scan ran.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffOptions {
    identity: HostIdentity,
    expiry_threshold: Duration,
    as_of: Option<SystemTime>,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            identity: HostIdentity::default(),
            expiry_threshold: DEFAULT_EXPIRY_THRESHOLD,
            as_of: None,
        }
    }
}

impl DiffOptions {
    /// The defaults: hosts pair by any shared address, certificates are expiring
    /// within [`DEFAULT_EXPIRY_THRESHOLD`], and each side is judged against its
    /// own scan's clock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets what makes two records the same host.
    pub fn with_identity(mut self, identity: HostIdentity) -> Self {
        self.identity = identity;
        self
    }

    /// Sets how long before it lapses a certificate counts as expiring.
    pub fn with_expiry_threshold(mut self, threshold: Duration) -> Self {
        self.expiry_threshold = threshold;
        self
    }

    /// Judges the current scan's certificates as of `at` rather than as of when
    /// that scan ran.
    ///
    /// For asking where a stored scan's certificates stand today. The baseline is
    /// still judged at its own clock, because it is the two standings differing
    /// that makes the change.
    pub fn as_of(mut self, at: SystemTime) -> Self {
        self.as_of = Some(at);
        self
    }

    /// What makes two records the same host.
    pub fn identity(&self) -> HostIdentity {
        self.identity
    }

    /// How long before it lapses a certificate counts as expiring.
    pub fn expiry_threshold(&self) -> Duration {
        self.expiry_threshold
    }

    /// The moment the current scan's certificates are judged at, if the caller
    /// set one.
    pub fn as_of_time(&self) -> Option<SystemTime> {
        self.as_of
    }
}

/// Which scan one side of a comparison was.
///
/// Carried so a diff can be rendered on its own, without the reports it was
/// taken from still being in hand — which is what a front end that computed the
/// diff on a server and sent it to a browser has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    engine_version: String,
    at: SystemTime,
    hosts: usize,
    kinds: Vec<ScanKind>,
    scope_stated: bool,
}

impl Provenance {
    /// The engine that produced the report, as it attributed itself.
    ///
    /// A report built out of another scanner's output says whatever the thing
    /// that built it recorded, so this is not a guarantee that this crate ran the
    /// scan.
    pub fn engine_version(&self) -> &str {
        &self.engine_version
    }

    /// The moment the scan is judged to have happened, which is what
    /// certificates were judged against.
    pub fn at(&self) -> SystemTime {
        self.at
    }

    /// How many hosts the report held.
    pub fn hosts(&self) -> usize {
        self.hosts
    }

    /// Which phases the report recorded, in the order they ran. Empty for a
    /// report that carries none.
    pub fn kinds(&self) -> &[ScanKind] {
        &self.kinds
    }

    /// Whether the report says what it covered.
    ///
    /// False makes every [`Coverage`] answer about this side
    /// [`Unstated`](Coverage::Unstated), so an appearance or a disappearance
    /// against it cannot be confirmed.
    pub fn states_scope(&self) -> bool {
        self.scope_stated
    }
}

/// What changed between two scans.
///
/// Built by [`between`](Self::between) or [`compare`](Self::compare). Holds one
/// [`HostDelta`] per host that differs, ascending by address, and nothing for
/// the hosts that did not.
#[derive(Debug, Clone)]
#[must_use = "a diff is the answer to what changed; dropping it discards it"]
pub struct ScanDiff {
    baseline: Provenance,
    current: Provenance,
    hosts: Vec<HostDelta>,
}

impl ScanDiff {
    /// Compares two scans under the default [`DiffOptions`].
    pub fn between(baseline: &ScanReport, current: &ScanReport) -> Self {
        Self::compare(baseline, current, &DiffOptions::default())
    }

    /// Compares two scans.
    ///
    /// `baseline` is the earlier scan and `current` the later one. Nothing
    /// enforces that: two reports compare in whichever order they are given, and
    /// a caller who hands them over the other way round gets a diff that reads
    /// backwards rather than an error.
    pub fn compare(baseline: &ScanReport, current: &ScanReport, options: &DiffOptions) -> Self {
        let baseline_hosts: Vec<&Host> = baseline.hosts().collect();
        let current_hosts: Vec<&Host> = current.hosts().collect();

        let baseline_scope = ScopeIndex::of(baseline);
        let current_scope = ScopeIndex::of(current);

        let clocks = Clocks {
            baseline: baseline.observed_at(),
            current: options.as_of.unwrap_or_else(|| current.observed_at()),
            expiry_threshold: options.expiry_threshold,
        };

        let components = pairing::components(&baseline_hosts, &current_hosts, options.identity);

        let mut hosts: Vec<HostDelta> = components
            .into_iter()
            .map(|component| {
                let before = merged(&baseline_hosts, &component.baseline);
                let after = merged(&current_hosts, &component.current);

                // The address each side's coverage is asked about is the one the
                // delta is keyed by, which is the record that exists.
                let address = after
                    .as_ref()
                    .or(before.as_ref())
                    .map(Host::primary_ip)
                    .expect("a component holds a record on at least one side");

                host::compare(
                    before.as_ref(),
                    after.as_ref(),
                    component.baseline.len(),
                    component.current.len(),
                    &baseline_scope,
                    &current_scope,
                    &address,
                    &clocks,
                )
            })
            .filter(|delta| !delta.is_empty())
            .collect();

        hosts.sort_by_key(HostDelta::address);

        Self {
            baseline: Provenance {
                engine_version: baseline.engine_version().to_owned(),
                at: clocks.baseline,
                hosts: baseline_hosts.len(),
                kinds: baseline.phases().iter().map(|phase| phase.kind()).collect(),
                scope_stated: baseline_scope.states_scope(),
            },
            current: Provenance {
                engine_version: current.engine_version().to_owned(),
                at: clocks.current,
                hosts: current_hosts.len(),
                kinds: current.phases().iter().map(|phase| phase.kind()).collect(),
                scope_stated: current_scope.states_scope(),
            },
            hosts,
        }
    }

    /// Which scan the baseline side was.
    pub fn baseline(&self) -> &Provenance {
        &self.baseline
    }

    /// Which scan the current side was.
    pub fn current(&self) -> &Provenance {
        &self.current
    }

    /// Every host that differs, ascending by address.
    pub fn hosts(&self) -> &[HostDelta] {
        &self.hosts
    }

    /// Whether the two scans describe the same network.
    ///
    /// True means nothing this module compares moved. It does not mean the two
    /// reports are identical: the measurements about each scan are not compared,
    /// so two runs that timed differently and found the same things are equal
    /// here.
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// Counts derived from the deltas.
    ///
    /// Computed on demand rather than stored, so a summary cannot disagree with
    /// the deltas it describes.
    pub fn summary(&self) -> DiffSummary {
        let mut summary = DiffSummary::default();

        for host in &self.hosts {
            match host.presence() {
                Presence::Added { .. } => summary.hosts_added.count(host.presence()),
                Presence::Removed { .. } => summary.hosts_removed.count(host.presence()),
                Presence::Both => {
                    if !host.changes().is_empty() || !host.ports().is_empty() {
                        summary.hosts_changed += 1;
                    }
                }
            }

            for port in host.ports() {
                if port.is_opened() {
                    summary.ports_opened.count(port.presence());
                }
                if port.is_closed() {
                    summary.ports_closed.count(port.presence());
                }
                if port.presence().is_in_both() && !port.changes().is_empty() {
                    summary.ports_changed += 1;
                }

                let mut service_moved = false;
                for change in port.changes() {
                    match change {
                        PortChange::Service(_) => service_moved = true,
                        PortChange::Security(SecurityChange::Certificate(certificate)) => {
                            match certificate {
                                CertificateChange::Rotated { .. } => {
                                    summary.certificates_rotated += 1;
                                }
                                CertificateChange::Expiring { .. } => {
                                    summary.certificates_expiring += 1;
                                }
                                CertificateChange::Expired { .. } => {
                                    summary.certificates_expired += 1;
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
                if service_moved {
                    summary.services_changed += 1;
                }
            }
        }

        summary
    }
}

/// A count of records, and how many of them the other scan is known to have
/// looked for.
///
/// The two are not the same number and the difference is the whole point. Three
/// hosts appearing is a finding when the baseline covered all three addresses,
/// and is a wider scan when it covered none of them. A front end that prints
/// only one of these should print [`confirmed`](Self::confirmed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Confirmed {
    /// How many records, whatever the other scan covered.
    pub total: usize,
    /// How many of them the other scan is known to have covered, which are the
    /// ones that are findings about the network rather than about the scan.
    pub confirmed: usize,
}

impl Confirmed {
    fn count(&mut self, presence: Presence) {
        self.total += 1;
        if presence.is_confirmed() {
            self.confirmed += 1;
        }
    }
}

/// Counts derived from a comparison.
///
/// The numbers a front end leads with. Everything here is derived from
/// [`ScanDiff::hosts`], so a consumer wanting the detail behind any of these
/// walks the deltas instead.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiffSummary {
    /// Hosts only the current scan has a record for.
    pub hosts_added: Confirmed,
    /// Hosts only the baseline has a record for.
    pub hosts_removed: Confirmed,
    /// Hosts both scans have, that differ.
    pub hosts_changed: usize,
    /// Endpoints accepting connections now that were not before, whether by
    /// changing state or by appearing.
    pub ports_opened: Confirmed,
    /// Endpoints that were accepting connections and are not now, whether by
    /// changing state or by disappearing.
    pub ports_closed: Confirmed,
    /// Endpoints both scans have, that differ.
    pub ports_changed: usize,
    /// Endpoints where what is listening changed, or was identified where it was
    /// not.
    pub services_changed: usize,
    /// Endpoints presenting a different certificate than before.
    pub certificates_rotated: usize,
    /// Endpoints whose certificate is now inside the expiry threshold and was not
    /// at the baseline's clock.
    pub certificates_expiring: usize,
    /// Endpoints whose certificate has lapsed since the baseline ran.
    pub certificates_expired: usize,
}

/// One side of a component as a single host: the record itself where there is
/// one, and the records folded together where there are several.
fn merged(hosts: &[&Host], indices: &[usize]) -> Option<Host> {
    let (first, rest) = indices.split_first()?;

    let mut merged = hosts[*first].clone();
    for index in rest {
        merged.merge(hosts[*index].clone());
    }
    Some(merged)
}

#[cfg(test)]
mod tests {
    use crate::system::privilege::Privilege;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use super::*;
    use crate::config::ZondConfig;
    use crate::model::exclusion::Exclusions;
    use crate::model::host::os::OsFingerprint;
    use crate::model::host::{Host, HostStatus};
    use crate::model::parse::ip::to_set;
    use crate::model::port::security::CertificateInfo;
    use crate::model::port::{Port, PortSet, PortState, Protocol, Security, Service};
    use crate::report::{
        PhaseParts, PortScope, ScanKind, ScanPhase, ScanReport, ScanSettings, ScopeParts,
        TargetScope,
    };

    const DAY: Duration = Duration::from_secs(24 * 60 * 60);

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, last))
    }

    fn host(last: u8) -> Host {
        let mut host = Host::new(ip(last));
        host.set_status(HostStatus::Up);
        host
    }

    /// How long the phases these helpers build ran for.
    ///
    /// Zero, so that the moment a report is placed at is the `at` each helper
    /// was given. A report is placed by when it *finished* looking, and a
    /// duration would put its clock somewhere no test named — which the
    /// certificate tests below would then read as a threshold crossed a second
    /// early. How long a scan took is not what any of them is about.
    const PROMPT: Duration = Duration::ZERO;

    /// A report that says nothing about what it covered, which is what a foreign
    /// scanner's output reads as.
    fn unscoped(hosts: Vec<Host>) -> ScanReport {
        ScanReport::recorded("test", Vec::new(), hosts)
    }

    /// A report whose single phase walked `covered` and was forbidden `excluded`.
    fn scoped(hosts: Vec<Host>, covered: &str, excluded: &[&str], at: SystemTime) -> ScanReport {
        let mut targets = to_set(&[covered], None, None).expect("a parseable range");
        let exclusions = if excluded.is_empty() {
            Exclusions::none()
        } else {
            Exclusions::new(to_set(excluded, None, None).expect("a parseable range"))
        };
        let scope = TargetScope::from_ip_set(&mut targets, &exclusions);

        let phase = ScanPhase::from_parts(PhaseParts {
            attachments: Vec::new(),
            kind: ScanKind::Discovery,
            started_at: at,
            elapsed: PROMPT,
            privilege: Some(Privilege::Raw),
            targets: scope,
            settings: ScanSettings::from(&ZondConfig::default()),
            failures: Vec::new(),
            unroutable: Vec::new(),
            probes: Vec::new(),
            origin: None,
        });

        ScanReport::recorded("test", vec![phase], hosts)
    }

    /// A report whose phase walked `covered` and probed `ports` on it.
    fn port_scanned(
        hosts: Vec<Host>,
        covered: &str,
        ports: PortScope,
        at: SystemTime,
    ) -> ScanReport {
        let mut targets = to_set(&[covered], None, None).expect("a parseable range");
        let scope = TargetScope::from_ip_set(&mut targets, &Exclusions::none());
        let scope = TargetScope::from_parts(ScopeParts {
            listened: Vec::new(),
            ranges: scope.ranges().to_vec(),
            links: Vec::new(),
            addresses: scope.addresses(),
            probes: None,
            ports,
            protocols: vec![Protocol::Tcp],
            excluded: Vec::new(),
            withheld: 0,
        });

        let phase = ScanPhase::from_parts(PhaseParts {
            attachments: Vec::new(),
            kind: ScanKind::PortScan,
            started_at: at,
            elapsed: PROMPT,
            privilege: Some(Privilege::Raw),
            targets: scope,
            settings: ScanSettings::from(&ZondConfig::default()),
            failures: Vec::new(),
            unroutable: Vec::new(),
            probes: Vec::new(),
            origin: None,
        });

        ScanReport::recorded("test", vec![phase], hosts)
    }

    /// A report whose phase swept `covered` and also swept the link on `link`.
    fn swept(hosts: Vec<Host>, covered: &str, link: &str, at: SystemTime) -> ScanReport {
        use crate::model::ip::scoped::Zone;

        let mut targets = to_set(&[covered], None, None).expect("a parseable range");
        let scope = TargetScope::from_ip_set(&mut targets, &Exclusions::none());
        let scope = TargetScope::from_parts(ScopeParts {
            listened: Vec::new(),
            ranges: scope.ranges().to_vec(),
            links: vec![Zone::new(1, link)],
            addresses: scope.addresses(),
            probes: None,
            ports: PortScope::NoPorts,
            protocols: Vec::new(),
            excluded: Vec::new(),
            withheld: 0,
        });

        let phase = ScanPhase::from_parts(PhaseParts {
            attachments: Vec::new(),
            kind: ScanKind::Discovery,
            started_at: at,
            elapsed: PROMPT,
            privilege: Some(Privilege::Raw),
            targets: scope,
            settings: ScanSettings::from(&ZondConfig::default()),
            failures: Vec::new(),
            unroutable: Vec::new(),
            probes: Vec::new(),
            origin: None,
        });

        ScanReport::recorded("test", vec![phase], hosts)
    }

    /// A host reachable only at a link-local address on `link`.
    fn neighbour(last: u16, link: &str) -> Host {
        use crate::model::ip::scoped::Zone;
        use std::net::Ipv6Addr;

        let mut host = Host::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, last)));
        host.set_status(HostStatus::Up);
        host.set_zone(Zone::new(1, link));
        host
    }

    fn ports(spec: &str) -> PortSet {
        PortSet::try_from(spec).expect("a port specification")
    }

    fn certificate(fingerprint: &str, start: SystemTime, end: SystemTime) -> Security {
        Security::new().with_certificate(CertificateInfo::new(
            "example.test",
            "Test CA",
            start,
            end,
            fingerprint,
        ))
    }

    // -----------------------------------------------------------------------
    // Nothing changed
    // -----------------------------------------------------------------------

    #[test]
    fn two_scans_that_found_the_same_things_report_nothing() {
        let build = || {
            let mut h = host(10);
            h.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
            unscoped(vec![h])
        };

        let diff = ScanDiff::between(&build(), &build());

        assert!(diff.is_empty(), "an unchanged network is an empty diff");
        assert_eq!(diff.summary(), DiffSummary::default());
    }

    #[test]
    fn a_round_trip_time_is_not_a_change() {
        let mut before = host(10);
        before.add_rtt(Duration::from_millis(4));
        let mut after = host(10);
        after.add_rtt(Duration::from_millis(91));

        let diff = ScanDiff::between(&unscoped(vec![before]), &unscoped(vec![after]));

        assert!(
            diff.is_empty(),
            "how fast the host answered is a measurement of the scan, not a finding"
        );
    }

    #[test]
    fn a_more_confident_reading_of_the_same_system_is_not_a_change() {
        let mut before = host(10);
        before.set_os(OsFingerprint::new("Linux", 74).with_family("Unix-like"));
        let mut after = host(10);
        after.set_os(OsFingerprint::new("Linux", 98).with_family("Unix-like"));

        let diff = ScanDiff::between(&unscoped(vec![before]), &unscoped(vec![after]));

        assert!(
            diff.is_empty(),
            "the fingerprinter growing surer of the same answer is not a change"
        );
    }

    #[test]
    fn a_different_system_is_a_change() {
        let mut before = host(10);
        before.set_os(OsFingerprint::new("Linux", 90));
        let mut after = host(10);
        after.set_os(OsFingerprint::new("Windows", 90));

        let diff = ScanDiff::between(&unscoped(vec![before]), &unscoped(vec![after]));

        let changes = diff.hosts()[0].changes();
        assert!(matches!(changes[0], HostChange::Os(_)), "{changes:?}");
    }

    // -----------------------------------------------------------------------
    // Coverage: what a missing record is allowed to mean
    // -----------------------------------------------------------------------

    #[test]
    fn a_host_that_appeared_where_the_baseline_looked_is_confirmed() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let before = scoped(vec![host(10)], "192.168.0.0/24", &[], at);
        let after = scoped(vec![host(10), host(11)], "192.168.0.0/24", &[], at + DAY);

        let diff = ScanDiff::compare(&before, &after, &DiffOptions::default());

        let appeared = diff
            .hosts()
            .iter()
            .find(|delta| delta.address() == ip(11))
            .expect("the new host is in the diff");

        assert_eq!(
            appeared.presence(),
            Presence::Added {
                before: Coverage::Covered
            }
        );
        assert!(appeared.presence().is_confirmed());
        assert_eq!(diff.summary().hosts_added.confirmed, 1);
    }

    #[test]
    fn a_host_that_appeared_where_the_baseline_never_looked_is_not_confirmed() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        // The baseline walked a quarter of the segment. The host that turns up
        // in the wider scan was never in reach of the first one.
        let before = scoped(vec![host(10)], "192.168.0.0/26", &[], at);
        let after = scoped(vec![host(10), host(200)], "192.168.0.0/24", &[], at + DAY);

        let diff = ScanDiff::between(&before, &after);

        let appeared = diff
            .hosts()
            .iter()
            .find(|delta| delta.address() == ip(200))
            .expect("the new host is in the diff");

        assert_eq!(
            appeared.presence(),
            Presence::Added {
                before: Coverage::OutOfScope
            }
        );
        assert!(!appeared.presence().is_confirmed());

        let summary = diff.summary();
        assert_eq!(summary.hosts_added.total, 1);
        assert_eq!(
            summary.hosts_added.confirmed, 0,
            "a host nobody had looked for is not a host that appeared"
        );
    }

    #[test]
    fn a_host_the_current_scan_was_forbidden_reads_as_withheld() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let before = scoped(vec![host(10), host(11)], "192.168.0.0/24", &[], at);
        let after = scoped(
            vec![host(10)],
            "192.168.0.0/24",
            &["192.168.0.11"],
            at + DAY,
        );

        let diff = ScanDiff::between(&before, &after);

        let gone = diff
            .hosts()
            .iter()
            .find(|delta| delta.address() == ip(11))
            .expect("the missing host is in the diff");

        assert_eq!(
            gone.presence(),
            Presence::Removed {
                after: Coverage::Withheld
            },
            "an address a policy forbade is not an address that went quiet"
        );
        assert!(!gone.presence().is_confirmed());
    }

    #[test]
    fn a_report_that_states_no_scope_answers_unstated() {
        let before = unscoped(vec![host(10), host(11)]);
        let after = unscoped(vec![host(10)]);

        let diff = ScanDiff::between(&before, &after);

        let gone = diff
            .hosts()
            .iter()
            .find(|delta| delta.address() == ip(11))
            .expect("the missing host is in the diff");

        assert_eq!(
            gone.presence(),
            Presence::Removed {
                after: Coverage::Unstated
            },
            "a report that does not say what it walked cannot confirm a disappearance"
        );
        assert!(!gone.presence().is_confirmed());
        assert_eq!(diff.summary().hosts_removed.confirmed, 0);
    }

    #[test]
    fn a_host_that_went_quiet_where_the_scan_looked_is_confirmed() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let before = scoped(vec![host(10), host(11)], "192.168.0.0/24", &[], at);
        let after = scoped(vec![host(10)], "192.168.0.0/24", &[], at + DAY);

        let diff = ScanDiff::between(&before, &after);
        let summary = diff.summary();

        assert_eq!(summary.hosts_removed.total, 1);
        assert_eq!(summary.hosts_removed.confirmed, 1);
    }

    // -----------------------------------------------------------------------
    // Ports
    // -----------------------------------------------------------------------

    #[test]
    fn a_port_that_opened_is_counted_once() {
        let mut before = host(10);
        before.add_port(Port::new(8080, Protocol::Tcp, PortState::Closed));
        let mut after = host(10);
        after.add_port(Port::new(8080, Protocol::Tcp, PortState::Open));

        let diff = ScanDiff::between(&unscoped(vec![before]), &unscoped(vec![after]));

        let delta = &diff.hosts()[0].ports()[0];
        assert!(delta.is_opened());
        assert!(!delta.is_closed());
        assert!(matches!(
            delta.changes()[0],
            PortChange::State(Change {
                before: PortState::Closed,
                after: PortState::Open
            })
        ));

        let summary = diff.summary();
        assert_eq!(summary.ports_opened.total, 1);
        assert_eq!(
            summary.ports_opened.confirmed, 1,
            "both scans hold a record, so nothing is being assumed"
        );
        assert_eq!(summary.ports_closed.total, 0);
    }

    #[test]
    fn a_port_only_the_later_scan_recorded_is_not_a_confirmed_opening() {
        let before = host(10);
        let mut after = host(10);
        after.add_port(Port::new(8080, Protocol::Tcp, PortState::Open));

        let diff = ScanDiff::between(&unscoped(vec![before]), &unscoped(vec![after]));

        let delta = &diff.hosts()[0].ports()[0];
        assert!(delta.is_opened());
        assert_eq!(
            delta.presence(),
            Presence::Added {
                before: Coverage::Unstated
            },
            "a scope records addresses, not the ports walked on each"
        );

        let summary = diff.summary();
        assert_eq!(summary.ports_opened.total, 1);
        assert_eq!(summary.ports_opened.confirmed, 0);
    }

    #[test]
    fn an_endpoint_identical_in_both_scans_is_left_out() {
        let mut before = host(10);
        before.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
        before.add_port(Port::new(80, Protocol::Tcp, PortState::Closed));
        let mut after = host(10);
        after.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
        after.add_port(Port::new(80, Protocol::Tcp, PortState::Open));

        let diff = ScanDiff::between(&unscoped(vec![before]), &unscoped(vec![after]));

        let ports = diff.hosts()[0].ports();
        assert_eq!(ports.len(), 1, "only the endpoint that moved: {ports:?}");
        assert_eq!(ports[0].number(), 80);
    }

    #[test]
    fn a_service_version_change_is_reported() {
        let mut before = host(10);
        before.add_port(
            Port::new(80, Protocol::Tcp, PortState::Open)
                .with_service(Service::new("http", 90).with_version("1.18.0")),
        );
        let mut after = host(10);
        after.add_port(
            Port::new(80, Protocol::Tcp, PortState::Open)
                .with_service(Service::new("http", 90).with_version("1.24.0")),
        );

        let diff = ScanDiff::between(&unscoped(vec![before]), &unscoped(vec![after]));

        let changes = diff.hosts()[0].ports()[0].changes();
        let PortChange::Service(ServiceChange::Version(version)) = &changes[0] else {
            panic!("expected a version change, got {changes:?}");
        };
        assert_eq!(version.before.as_deref(), Some("1.18.0"));
        assert_eq!(version.after.as_deref(), Some("1.24.0"));
        assert_eq!(diff.summary().services_changed, 1);
    }

    #[test]
    fn a_service_identified_at_a_different_confidence_is_not_a_change() {
        let mut before = host(10);
        before.add_port(
            Port::new(80, Protocol::Tcp, PortState::Open)
                .with_service(Service::new("http", 60).with_version("1.18.0")),
        );
        let mut after = host(10);
        after.add_port(
            Port::new(80, Protocol::Tcp, PortState::Open)
                .with_service(Service::new("http", 99).with_version("1.18.0")),
        );

        let diff = ScanDiff::between(&unscoped(vec![before]), &unscoped(vec![after]));

        assert!(
            diff.is_empty(),
            "how sure the fingerprinter was is not a finding about the service"
        );
    }

    // -----------------------------------------------------------------------
    // Endpoint coverage: which ports each scan says it walked
    // -----------------------------------------------------------------------

    #[test]
    fn a_port_that_opened_where_the_baseline_walked_it_is_confirmed() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut after = host(10);
        after.add_port(Port::new(443, Protocol::Tcp, PortState::Open));

        let diff = ScanDiff::between(
            &port_scanned(
                vec![host(10)],
                "192.168.0.0/24",
                PortScope::Every(ports("1-1024")),
                at,
            ),
            &port_scanned(
                vec![after],
                "192.168.0.0/24",
                PortScope::Every(ports("1-1024")),
                at + DAY,
            ),
        );

        let delta = &diff.hosts()[0].ports()[0];
        assert_eq!(
            delta.presence(),
            Presence::Added {
                before: Coverage::Covered
            },
            "the baseline walked 443 and recorded nothing there, so it opened"
        );
        assert_eq!(diff.summary().ports_opened.confirmed, 1);
    }

    #[test]
    fn a_port_the_baseline_never_walked_is_not_a_confirmed_opening() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut after = host(10);
        after.add_port(Port::new(8080, Protocol::Tcp, PortState::Open));

        let diff = ScanDiff::between(
            &port_scanned(
                vec![host(10)],
                "192.168.0.0/24",
                PortScope::Every(ports("1-1024")),
                at,
            ),
            &port_scanned(
                vec![after],
                "192.168.0.0/24",
                PortScope::Every(ports("1-1024,8080")),
                at + DAY,
            ),
        );

        let delta = &diff.hosts()[0].ports()[0];
        assert_eq!(
            delta.presence(),
            Presence::Added {
                before: Coverage::OutOfScope
            },
            "8080 was outside the baseline's port set, so nothing there is news"
        );
        let summary = diff.summary();
        assert_eq!(summary.ports_opened.total, 1);
        assert_eq!(summary.ports_opened.confirmed, 0);
    }

    #[test]
    fn a_baseline_that_only_swept_never_walked_any_port() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut after = host(10);
        after.add_port(Port::new(443, Protocol::Tcp, PortState::Open));

        let diff = ScanDiff::between(
            &scoped(vec![host(10)], "192.168.0.0/24", &[], at),
            &port_scanned(
                vec![after],
                "192.168.0.0/24",
                PortScope::Every(ports("1-1024")),
                at + DAY,
            ),
        );

        assert_eq!(
            diff.hosts()[0].ports()[0].presence(),
            Presence::Added {
                before: Coverage::OutOfScope
            },
            "a sweep walks addresses; it did not probe this endpoint and can say so"
        );
    }

    #[test]
    fn a_baseline_whose_addresses_disagreed_about_ports_cannot_confirm_one() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut after = host(10);
        after.add_port(Port::new(443, Protocol::Tcp, PortState::Open));

        let diff = ScanDiff::between(
            &port_scanned(
                vec![host(10)],
                "192.168.0.0/24",
                PortScope::Mixed(ports("80,443")),
                at,
            ),
            &port_scanned(
                vec![after],
                "192.168.0.0/24",
                PortScope::Every(ports("80,443")),
                at + DAY,
            ),
        );

        assert_eq!(
            diff.hosts()[0].ports()[0].presence(),
            Presence::Added {
                before: Coverage::Unstated
            },
            "443 was walked for some addresses; the scope cannot say it was for this one"
        );
    }

    #[test]
    fn a_phase_that_cannot_say_vetoes_one_that_can() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut after = host(10);
        after.add_port(Port::new(443, Protocol::Tcp, PortState::Open));

        // A job of two phases: a sweep that certainly walked no ports, and a
        // port scan from a record that does not say which ports it walked.
        let sweep = scoped(vec![host(10)], "192.168.0.0/24", &[], at);
        let unstated = port_scanned(vec![host(10)], "192.168.0.0/24", PortScope::Unstated, at);
        let mut phases = sweep.phases().to_vec();
        phases.extend(unstated.phases().iter().cloned());
        let baseline = ScanReport::recorded("test", phases, vec![host(10)]);

        let diff = ScanDiff::between(
            &baseline,
            &port_scanned(
                vec![after],
                "192.168.0.0/24",
                PortScope::Every(ports("1-1024")),
                at + DAY,
            ),
        );

        assert_eq!(
            diff.hosts()[0].ports()[0].presence(),
            Presence::Added {
                before: Coverage::Unstated
            },
            "the sweep's certainty about its own half is not the job's"
        );
    }

    // -----------------------------------------------------------------------
    // A link is covered ground, and no range says so
    // -----------------------------------------------------------------------

    /// A sweep of a local segment reaches every IPv6 neighbour on the link,
    /// holding addresses no target set could have named. Without this the
    /// neighbours read as ground nobody covered, and a new device on a watched
    /// segment never counts as having appeared.
    #[test]
    fn a_neighbour_on_a_swept_link_is_covered_ground() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);

        let diff = ScanDiff::between(
            &swept(vec![host(10)], "192.168.0.0/24", "en1", at),
            &swept(
                vec![host(10), neighbour(0x41a, "en1")],
                "192.168.0.0/24",
                "en1",
                at + DAY,
            ),
        );

        let appeared = diff
            .hosts()
            .iter()
            .find(|delta| delta.address().is_ipv6())
            .expect("the neighbour is in the diff");

        assert_eq!(
            appeared.presence(),
            Presence::Added {
                before: Coverage::Covered
            },
            "the earlier scan swept this link and did not find it"
        );
        assert!(appeared.presence().is_confirmed());
        assert_eq!(diff.summary().hosts_added.confirmed, 1);
    }

    /// And a link nobody swept claims nothing.
    #[test]
    fn a_neighbour_on_a_link_that_was_not_swept_is_not_confirmed() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);

        let diff = ScanDiff::between(
            // The earlier scan swept a different interface's link.
            &swept(vec![host(10)], "192.168.0.0/24", "en0", at),
            &swept(
                vec![host(10), neighbour(0x41a, "en1")],
                "192.168.0.0/24",
                "en1",
                at + DAY,
            ),
        );

        let appeared = diff
            .hosts()
            .iter()
            .find(|delta| delta.address().is_ipv6())
            .expect("the neighbour is in the diff");

        assert_eq!(
            appeared.presence(),
            Presence::Added {
                before: Coverage::OutOfScope
            },
            "fe80::1 on two interfaces is two machines"
        );
        assert_eq!(diff.summary().hosts_added.confirmed, 0);
    }

    /// A host found on a swept link is covered whatever address it is keyed by.
    ///
    /// The case a real segment produced, and the one an earlier version of this
    /// got wrong by asking whether the *address* was link-local. A neighbour
    /// that answers an all-nodes solicitation is routinely keyed under a global
    /// address, because this engine prefers a routable one when both are known.
    /// The sweep still reached it, on the link.
    #[test]
    fn a_host_on_a_swept_link_is_covered_whatever_it_is_keyed_by() {
        use crate::model::ip::scoped::Zone;

        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut routable = Host::new("2a02:908:8c1:b880::4".parse::<IpAddr>().expect("valid"));
        routable.set_status(HostStatus::Up);
        routable.set_zone(Zone::new(1, "en1"));

        let diff = ScanDiff::between(
            &swept(vec![host(10), routable], "192.168.0.0/24", "en1", at),
            &swept(vec![host(10)], "192.168.0.0/24", "en1", at + DAY),
        );

        let gone = diff
            .hosts()
            .iter()
            .find(|delta| delta.address().is_ipv6())
            .expect("the host is in the diff");

        assert_eq!(
            gone.presence(),
            Presence::Removed {
                after: Coverage::Covered
            },
            "the later scan swept the link this host was found on"
        );
        assert_eq!(diff.summary().hosts_removed.confirmed, 1);
    }

    /// A host nothing found on a link is not covered by having swept one.
    #[test]
    fn a_host_with_no_link_is_not_covered_by_a_sweep() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut routable = Host::new("2001:db8::1".parse::<IpAddr>().expect("valid"));
        routable.set_status(HostStatus::Up);

        let diff = ScanDiff::between(
            &swept(vec![host(10)], "192.168.0.0/24", "en1", at),
            &swept(vec![host(10), routable], "192.168.0.0/24", "en1", at + DAY),
        );

        let appeared = diff
            .hosts()
            .iter()
            .find(|delta| delta.address().is_ipv6())
            .expect("the host is in the diff");

        assert!(
            !appeared.presence().is_confirmed(),
            "a host with no zone was not found on any link"
        );
    }

    // -----------------------------------------------------------------------
    // A host is covered if the scan walked ground it stood on
    // -----------------------------------------------------------------------

    /// Which address a report keys a host under is the report's business. A
    /// dual-stack machine keyed under IPv6 was in reach of a sweep of the IPv4
    /// range all the same.
    #[test]
    fn a_host_is_covered_by_any_address_it_answers_at() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);

        // Keyed under IPv6, and also holding an address the sweep walked.
        let mut dual = Host::new("2001:db8::5".parse::<IpAddr>().expect("valid"));
        dual.set_status(HostStatus::Up);
        dual.add_ip(ip(11));

        let diff = ScanDiff::between(
            &scoped(vec![host(10)], "192.168.0.0/24", &[], at),
            &scoped(vec![host(10), dual], "192.168.0.0/24", &[], at + DAY),
        );

        let appeared = diff
            .hosts()
            .iter()
            .find(|delta| delta.address().is_ipv6())
            .expect("the host is in the diff");

        assert_eq!(
            appeared.presence(),
            Presence::Added {
                before: Coverage::Covered
            },
            "the earlier scan walked 192.168.0.11 and found nothing there"
        );
    }

    // -----------------------------------------------------------------------
    // Certificates
    // -----------------------------------------------------------------------

    #[test]
    fn a_rotated_certificate_is_reported() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let mut before = host(10);
        before.add_port(
            Port::new(443, Protocol::Tcp, PortState::Open).with_security(certificate(
                "aaaa",
                at - 90 * DAY,
                at + 300 * DAY,
            )),
        );
        let mut after = host(10);
        after.add_port(
            Port::new(443, Protocol::Tcp, PortState::Open).with_security(certificate(
                "bbbb",
                at,
                at + 365 * DAY,
            )),
        );

        let diff = ScanDiff::between(
            &scoped(vec![before], "192.168.0.0/24", &[], at),
            &scoped(vec![after], "192.168.0.0/24", &[], at + DAY),
        );

        let changes = diff.hosts()[0].ports()[0].changes();
        assert!(
            changes.iter().any(|change| matches!(
                change,
                PortChange::Security(SecurityChange::Certificate(
                    CertificateChange::Rotated { .. }
                ))
            )),
            "{changes:?}"
        );
        assert_eq!(diff.summary().certificates_rotated, 1);
    }

    #[test]
    fn a_certificate_nobody_touched_reports_the_threshold_it_crossed() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        // Ninety days of life left when the baseline ran, ten when the second
        // scan did. Nothing about the certificate moved; the clock did.
        let expires = at + 90 * DAY;
        let same = || certificate("aaaa", at - 90 * DAY, expires);

        let mut before = host(10);
        before.add_port(Port::new(443, Protocol::Tcp, PortState::Open).with_security(same()));
        let mut after = host(10);
        after.add_port(Port::new(443, Protocol::Tcp, PortState::Open).with_security(same()));

        let diff = ScanDiff::between(
            &scoped(vec![before], "192.168.0.0/24", &[], at),
            &scoped(vec![after], "192.168.0.0/24", &[], at + 80 * DAY),
        );

        let changes = diff.hosts()[0].ports()[0].changes();
        let Some(PortChange::Security(SecurityChange::Certificate(CertificateChange::Expiring {
            remaining,
            ..
        }))) = changes.first()
        else {
            panic!("expected an expiry crossing, got {changes:?}");
        };
        assert_eq!(*remaining, 10 * DAY);
        assert_eq!(diff.summary().certificates_expiring, 1);
    }

    /// A renewal that lands on a certificate which is *itself* expiring is the
    /// case a standing read off "whatever each side presented" cancels out.
    ///
    /// Both sides answer `Expiring`, so nothing appears to have moved, and the
    /// endpoint that most needs renewing reports a rotation and no expiry. The
    /// standing belongs to one certificate at two moments, and the baseline was
    /// never shown this one.
    #[test]
    fn a_rotation_onto_an_expiring_certificate_still_reports_the_expiry() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);

        // Twenty days left when the baseline ran, and the replacement installed
        // a week later has fifteen. Inside the threshold both times.
        let mut before = host(10);
        before.add_port(
            Port::new(443, Protocol::Tcp, PortState::Open).with_security(certificate(
                "aaaa",
                at - 90 * DAY,
                at + 20 * DAY,
            )),
        );
        let mut after = host(10);
        after.add_port(
            Port::new(443, Protocol::Tcp, PortState::Open).with_security(certificate(
                "bbbb",
                at,
                at + 22 * DAY,
            )),
        );

        let diff = ScanDiff::between(
            &scoped(vec![before], "192.168.0.0/24", &[], at),
            &scoped(vec![after], "192.168.0.0/24", &[], at + 7 * DAY),
        );

        let changes = diff.hosts()[0].ports()[0].changes();
        assert!(
            changes.iter().any(|change| matches!(
                change,
                PortChange::Security(SecurityChange::Certificate(
                    CertificateChange::Rotated { .. }
                ))
            )),
            "{changes:?}"
        );
        assert_eq!(diff.summary().certificates_rotated, 1);
        assert_eq!(
            diff.summary().certificates_expiring,
            1,
            "the certificate presented now is inside the threshold and the \
             baseline never saw it: {changes:?}"
        );
    }

    /// The same, one step worse: a renewal that installs a certificate which had
    /// already lapsed. `certificates_expired` counted none of these.
    #[test]
    fn a_rotation_onto_an_already_lapsed_certificate_still_reports_it() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);

        let mut before = host(10);
        before.add_port(
            Port::new(443, Protocol::Tcp, PortState::Open).with_security(certificate(
                "aaaa",
                at - 400 * DAY,
                at - DAY,
            )),
        );
        let mut after = host(10);
        after.add_port(
            Port::new(443, Protocol::Tcp, PortState::Open).with_security(certificate(
                "bbbb",
                at - 400 * DAY,
                at - 2 * DAY,
            )),
        );

        let diff = ScanDiff::between(
            &scoped(vec![before], "192.168.0.0/24", &[], at),
            &scoped(vec![after], "192.168.0.0/24", &[], at + DAY),
        );

        assert_eq!(diff.summary().certificates_rotated, 1);
        assert_eq!(
            diff.summary().certificates_expired,
            1,
            "{:?}",
            diff.hosts()[0].ports()[0].changes()
        );
    }

    #[test]
    fn a_certificate_that_was_already_expiring_is_not_reported_again() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        // Twenty days left at the baseline, fifteen at the second scan: inside
        // the threshold both times, so nothing crossed it.
        let expires = at + 20 * DAY;
        let same = || certificate("aaaa", at - 90 * DAY, expires);

        let mut before = host(10);
        before.add_port(Port::new(443, Protocol::Tcp, PortState::Open).with_security(same()));
        let mut after = host(10);
        after.add_port(Port::new(443, Protocol::Tcp, PortState::Open).with_security(same()));

        let diff = ScanDiff::between(
            &scoped(vec![before], "192.168.0.0/24", &[], at),
            &scoped(vec![after], "192.168.0.0/24", &[], at + 5 * DAY),
        );

        assert!(
            diff.is_empty(),
            "a renewal queue reports a certificate once, not on every scan"
        );
    }

    #[test]
    fn a_certificate_that_lapsed_between_the_scans_is_reported() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let expires = at + 10 * DAY;
        let same = || certificate("aaaa", at - 90 * DAY, expires);

        let mut before = host(10);
        before.add_port(Port::new(443, Protocol::Tcp, PortState::Open).with_security(same()));
        let mut after = host(10);
        after.add_port(Port::new(443, Protocol::Tcp, PortState::Open).with_security(same()));

        let diff = ScanDiff::between(
            &scoped(vec![before], "192.168.0.0/24", &[], at),
            &scoped(vec![after], "192.168.0.0/24", &[], at + 40 * DAY),
        );

        let changes = diff.hosts()[0].ports()[0].changes();
        let Some(PortChange::Security(SecurityChange::Certificate(CertificateChange::Expired {
            since,
            ..
        }))) = changes.first()
        else {
            panic!("expected a lapse, got {changes:?}");
        };
        assert_eq!(*since, 30 * DAY);
        assert_eq!(diff.summary().certificates_expired, 1);
    }

    #[test]
    fn asking_where_a_stored_scan_stands_today_moves_only_the_current_clock() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let expires = at + 90 * DAY;
        let same = || certificate("aaaa", at - 90 * DAY, expires);

        let mut before = host(10);
        before.add_port(Port::new(443, Protocol::Tcp, PortState::Open).with_security(same()));
        let mut after = host(10);
        after.add_port(Port::new(443, Protocol::Tcp, PortState::Open).with_security(same()));

        // Both scans ran while the certificate had plenty of life left, so at
        // their own clocks nothing crossed.
        let baseline = scoped(vec![before], "192.168.0.0/24", &[], at);
        let current = scoped(vec![after], "192.168.0.0/24", &[], at + DAY);
        assert!(ScanDiff::between(&baseline, &current).is_empty());

        let asked_later = ScanDiff::compare(
            &baseline,
            &current,
            &DiffOptions::new().as_of(at + 85 * DAY),
        );

        assert_eq!(
            asked_later.summary().certificates_expiring,
            1,
            "asked as of a later moment, the certificate is inside the threshold"
        );
    }

    // -----------------------------------------------------------------------
    // Which record continues which
    // -----------------------------------------------------------------------

    #[test]
    fn a_host_whose_primary_address_moved_pairs_by_a_shared_one() {
        let mut before = host(10);
        before.add_ip(ip(11));
        let mut after = Host::new(ip(11));
        after.set_status(HostStatus::Up);
        after.add_ip(ip(10));
        after.add_port(Port::new(22, Protocol::Tcp, PortState::Open));

        let diff = ScanDiff::between(&unscoped(vec![before]), &unscoped(vec![after]));

        assert_eq!(diff.hosts().len(), 1, "one machine, not two");
        let delta = &diff.hosts()[0];
        assert!(delta.presence().is_in_both());
        assert!(!delta.is_regrouped());

        let summary = diff.summary();
        assert_eq!(summary.hosts_added.total, 0);
        assert_eq!(summary.hosts_removed.total, 0);
    }

    #[test]
    fn the_strict_policy_reads_the_same_pair_as_two_hosts() {
        let mut before = host(10);
        before.add_ip(ip(11));
        let mut after = Host::new(ip(11));
        after.set_status(HostStatus::Up);
        after.add_ip(ip(10));

        let diff = ScanDiff::compare(
            &unscoped(vec![before]),
            &unscoped(vec![after]),
            &DiffOptions::new().with_identity(HostIdentity::PrimaryAddress),
        );

        let summary = diff.summary();
        assert_eq!(summary.hosts_added.total, 1);
        assert_eq!(
            summary.hosts_removed.total, 1,
            "under this policy the address is the asset"
        );
    }

    #[test]
    fn one_host_seen_as_two_is_reported_as_a_regrouping() {
        // The baseline reached the link layer and knew the two addresses were
        // one machine. The second scan did not.
        let mut before = host(10);
        before.add_ip(ip(11));

        let mut first = host(10);
        first.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
        let mut second = Host::new(ip(11));
        second.set_status(HostStatus::Up);
        second.add_port(Port::new(80, Protocol::Tcp, PortState::Open));

        let diff = ScanDiff::between(&unscoped(vec![before]), &unscoped(vec![first, second]));

        assert_eq!(diff.hosts().len(), 1, "one component, however it was keyed");
        let delta = &diff.hosts()[0];
        assert!(delta.is_regrouped());
        assert_eq!(delta.records(), (1, 2));
        assert!(
            delta.presence().is_in_both(),
            "both scans saw the machine; they disagreed about how to key it"
        );

        // The two records were folded, so both endpoints are compared against
        // the baseline rather than one of them being lost.
        let numbers: Vec<u16> = delta.ports().iter().map(PortDelta::number).collect();
        assert_eq!(numbers, vec![22, 80]);
    }

    #[test]
    fn a_shared_hardware_address_pairs_a_host_that_moved_address() {
        use crate::model::mac::MacAddr;

        let mac = MacAddr::new(0x2c, 0xcf, 0x67, 0xf2, 0x51, 0xe3);
        let mut before = host(10);
        before.record_mac(mac);
        let mut after = host(60);
        after.record_mac(mac);

        let by_address = ScanDiff::between(
            &unscoped(vec![before.clone()]),
            &unscoped(vec![after.clone()]),
        );
        assert_eq!(
            by_address.summary().hosts_added.total,
            1,
            "nothing links the two addresses without the hardware policy"
        );

        let by_hardware = ScanDiff::compare(
            &unscoped(vec![before]),
            &unscoped(vec![after]),
            &DiffOptions::new().with_identity(HostIdentity::Hardware),
        );

        assert_eq!(by_hardware.hosts().len(), 1);
        let delta = &by_hardware.hosts()[0];
        assert!(delta.presence().is_in_both());
        let changes = delta.changes();
        assert!(
            changes
                .iter()
                .any(|change| matches!(change, HostChange::Addresses { .. })),
            "the address it moved to is the change: {changes:?}"
        );
    }

    #[test]
    fn hosts_come_back_ascending_by_address() {
        let before = unscoped(vec![host(10)]);
        let after = unscoped(vec![host(30), host(10), host(20)]);

        let diff = ScanDiff::between(&before, &after);
        let addresses: Vec<IpAddr> = diff.hosts().iter().map(HostDelta::address).collect();

        assert_eq!(
            addresses,
            vec![ip(20), ip(30)],
            "two runs over the same reports produce the same diff"
        );
    }

    // -----------------------------------------------------------------------
    // Provenance
    // -----------------------------------------------------------------------

    #[test]
    fn a_report_with_no_phases_is_placed_by_its_latest_sighting() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let mut old = host(10);
        old.restore_seen(at - DAY, at);

        let diff = ScanDiff::between(&unscoped(vec![old]), &unscoped(vec![host(11)]));

        assert_eq!(diff.baseline().at(), at);
        assert!(!diff.baseline().states_scope());
        assert_eq!(diff.baseline().hosts(), 1);
        assert!(diff.baseline().kinds().is_empty());
    }
}
