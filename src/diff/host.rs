// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What changed about one host
//!
//! A [`HostDelta`] is one machine as the two scans between them describe it: the
//! record each side holds, what moved between them, and every endpoint that
//! moved with it.
//!
//! ## Only the verdicts
//!
//! The status is compared and the evidence behind it is not. A host that was up
//! by ARP and is up by TCP has not changed, and a diff reporting it would bury
//! the host that went from up to unreachable. The same rule leaves out round-trip
//! times, hop counters, measured routes and the per-source operating-system
//! evidence: all of them are how well the scan saw the host rather than what the
//! host is.
//!
//! Operating-system identification follows the rule one step further. Two
//! fingerprints are the same finding when they name the same system, whatever
//! confidence each was recorded at, so a second scan that grew more certain of
//! the same answer reports nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::diff::change::{Change, Presence};
use crate::diff::port::{self, Clocks, PortDelta, PresenceFor};
use crate::diff::scope::ScopeIndex;
use crate::model::finding::{ClaimId, Finding, Severity};
use crate::model::host::os::OsFingerprint;
use crate::model::host::{Host, HostStatus, NetworkRole};
use crate::model::mac::MacAddr;

/// One host, as the two scans hold it.
///
/// Keyed by [`address`](Self::address), which is the current scan's primary
/// address where it has a record and the baseline's where it does not.
#[derive(Debug, Clone)]
pub struct HostDelta {
    address: IpAddr,
    presence: Presence,
    baseline: Option<Host>,
    current: Option<Host>,
    baseline_records: usize,
    current_records: usize,
    changes: Vec<HostChange>,
    ports: Vec<PortDelta>,
}

impl HostDelta {
    /// The address this host is reported under.
    pub fn address(&self) -> IpAddr {
        self.address
    }

    /// Which scans hold a record for this host, and what the other one says
    /// about having covered its address.
    pub fn presence(&self) -> Presence {
        self.presence
    }

    /// The baseline scan's view of this host, if it has one.
    ///
    /// Where the baseline held more than one record for it, this is the records
    /// merged with [`Host::merge`]. See [`is_regrouped`](Self::is_regrouped).
    pub fn baseline(&self) -> Option<&Host> {
        self.baseline.as_ref()
    }

    /// The current scan's view of this host, if it has one, merged the same way.
    pub fn current(&self) -> Option<&Host> {
        self.current.as_ref()
    }

    /// How many records the baseline held for this host, and how many the
    /// current scan holds.
    ///
    /// `(1, 1)` in the ordinary case, and `(0, 1)` or `(1, 0)` for a host only
    /// one scan has. Anything else is a regrouping.
    pub fn records(&self) -> (usize, usize) {
        (self.baseline_records, self.current_records)
    }

    /// Whether the two scans grouped this host's addresses differently: what one
    /// holds as a single record the other holds as several.
    ///
    /// It happens when one scan reached the link layer and the other did not,
    /// since the evidence that two addresses are one machine is what a privileged
    /// scan has and an unprivileged one does not. Both sides are still compared,
    /// merged; this says the comparison had to do that.
    pub fn is_regrouped(&self) -> bool {
        self.baseline_records > 1 || self.current_records > 1
    }

    /// Everything that moved about the host itself, in a fixed order.
    pub fn changes(&self) -> &[HostChange] {
        &self.changes
    }

    /// Every endpoint that moved, ascending by number and then transport.
    ///
    /// Endpoints identical in both scans are not here.
    pub fn ports(&self) -> &[PortDelta] {
        &self.ports
    }

    /// Whether anything is reported for this host at all.
    pub fn is_empty(&self) -> bool {
        self.presence.is_in_both() && self.changes.is_empty() && self.ports.is_empty()
    }
}

/// Something that moved about a host.
///
/// `#[non_exhaustive]`: a scan learns to establish more about a host as it
/// learns to speak more protocols, and a consumer matching on this should pay
/// for that with a recompile rather than with a major version.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum HostChange {
    /// Whether the host answers changed. The four states are
    /// [`HostStatus`]'s own documentation, and silence is
    /// [`Unknown`](HostStatus::Unknown) rather than
    /// [`Down`](HostStatus::Down): a host that stopped answering has moved to
    /// `Unknown`, and only an intermediary saying so produces `Down`.
    Status(Change<HostStatus>),
    /// The resolved name changed.
    Hostname(Change<Option<String>>),
    /// The addresses the host answers at changed, each list ascending.
    Addresses {
        /// Addresses the current scan found it at and the baseline did not.
        gained: Vec<IpAddr>,
        /// Addresses the baseline found it at and the current scan does not.
        lost: Vec<IpAddr>,
    },
    /// What the host was identified as running changed, or was identified where
    /// it was not.
    ///
    /// Only the identification moved. A fingerprint recorded at a different
    /// confidence for the same system is not a change and is not reported.
    ///
    /// Boxed because a pair of fingerprints is several times the size of any
    /// other variant, and a change list is mostly the other variants: unboxed,
    /// every hostname change in a diff would be stored in a slot wide enough for
    /// two operating systems. A reader dereferences it like any other change.
    Os(Box<Change<Option<OsFingerprint>>>),
    /// The hardware addresses the host was seen at changed, each list ascending.
    ///
    /// Only a scan that reached the link layer sees these at all, so both lists
    /// are empty between two scans where one of them did not.
    Macs {
        /// Addresses the current scan saw and the baseline did not.
        gained: Vec<MacAddr>,
        /// Addresses the baseline saw and the current scan does not.
        lost: Vec<MacAddr>,
    },
    /// The hardware vendor the address resolves to changed.
    Vendor(Change<Option<String>>),
    /// The roles inferred for the host changed, each list ascending.
    Roles {
        /// Roles the current scan inferred and the baseline did not.
        gained: Vec<NetworkRole>,
        /// Roles the baseline inferred and the current scan does not.
        lost: Vec<NetworkRole>,
    },
    /// Findings that appeared on the host, and findings no longer claimed about
    /// it.
    ///
    /// Paired by [`ClaimId`], which is what keeps a detection's own version bump
    /// from reading as the old finding going away and a new one arriving. A
    /// finding whose severity moved under the same claim is not reported here.
    Findings {
        /// Findings the current scan claims and the baseline did not.
        appeared: Vec<Finding>,
        /// Findings the baseline claimed and the current scan does not.
        resolved: Vec<Finding>,
        /// Findings both scans claim, where the severity moved.
        reassessed: Vec<Reassessment>,
    },
}

/// One claim both scans make, graded differently.
///
/// A finding going from `Medium` to `Critical` is the most consequential thing a
/// rescan can say about a host it already knew, and it is invisible in
/// `appeared` and `resolved`: the claim is on both sides.
///
/// Only the severity is compared. A detection re-running writes a fresh excerpt
/// almost every time, so treating any difference as a reassessment would report
/// every finding on every scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reassessment {
    /// The finding as the current scan states it.
    pub finding: Finding,
    /// Where the severity moved.
    pub severity: Change<Severity>,
}

/// Compares one host's two records, either of which may be absent.
///
/// `baseline_coverage` and `current_coverage` are what each report says about
/// having walked this address, and they are what turns "no record" into either a
/// host that went away or a host nobody asked about.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compare(
    baseline: Option<&Host>,
    current: Option<&Host>,
    baseline_records: usize,
    current_records: usize,
    baseline_scope: &ScopeIndex,
    current_scope: &ScopeIndex,
    address: &IpAddr,
    clocks: &Clocks,
) -> HostDelta {
    let address = *address;

    // Each scope is asked about the record the *other* side holds, because that
    // is the host whose absence is in question. Where only one side has a
    // record, both questions are about it.
    let known = current
        .or(baseline)
        .expect("a delta has a record on one side");
    let baseline_coverage = baseline_scope.of_host(known);
    let current_coverage = current_scope.of_host(baseline.or(current).expect("likewise"));

    let presence = match (baseline, current) {
        (Some(_), Some(_)) => Presence::Both,
        (None, Some(_)) => Presence::Added {
            before: baseline_coverage,
        },
        (Some(_), None) => Presence::Removed {
            after: current_coverage,
        },
        (None, None) => unreachable!("a host delta has a record on at least one side"),
    };

    let changes = match (baseline, current) {
        (Some(before), Some(after)) => changes_between(before, after),
        _ => Vec::new(),
    };

    let ports = port::compare(
        &baseline.map(collect_ports).unwrap_or_default(),
        &current.map(collect_ports).unwrap_or_default(),
        PresenceFor {
            baseline: &|number, protocol| {
                baseline_scope.endpoint(baseline_coverage, number, protocol)
            },
            current: &|number, protocol| current_scope.endpoint(current_coverage, number, protocol),
        },
        clocks,
    );

    HostDelta {
        address,
        presence,
        baseline: baseline.cloned(),
        current: current.cloned(),
        baseline_records,
        current_records,
        changes,
        ports,
    }
}

fn collect_ports(host: &Host) -> Vec<&crate::model::port::Port> {
    host.ports().collect()
}

/// Everything that moved between two records of the same host.
fn changes_between(before: &Host, after: &Host) -> Vec<HostChange> {
    let mut changes = Vec::new();

    if let Some(status) = Change::between(before.status(), after.status()) {
        changes.push(HostChange::Status(status));
    }

    if let Some(hostname) = Change::between(
        before.hostname().map(str::to_owned),
        after.hostname().map(str::to_owned),
    ) {
        changes.push(HostChange::Hostname(hostname));
    }

    let (gained, lost) = difference(before.ips().iter().copied(), after.ips().iter().copied());
    if !gained.is_empty() || !lost.is_empty() {
        changes.push(HostChange::Addresses { gained, lost });
    }

    if !same_system(before.os(), after.os()) {
        changes.push(HostChange::Os(Box::new(Change::new(
            before.os().cloned(),
            after.os().cloned(),
        ))));
    }

    let (gained, lost) = difference(
        before
            .hardware()
            .into_iter()
            .flat_map(|hardware| hardware.macs().keys().copied()),
        after
            .hardware()
            .into_iter()
            .flat_map(|hardware| hardware.macs().keys().copied()),
    );
    if !gained.is_empty() || !lost.is_empty() {
        changes.push(HostChange::Macs { gained, lost });
    }

    if let Some(vendor) = Change::between(
        before.vendor().map(str::to_owned),
        after.vendor().map(str::to_owned),
    ) {
        changes.push(HostChange::Vendor(vendor));
    }

    let (gained, lost) = difference(
        before.network_roles().iter().copied(),
        after.network_roles().iter().copied(),
    );
    if !gained.is_empty() || !lost.is_empty() {
        changes.push(HostChange::Roles { gained, lost });
    }

    let (appeared, resolved, reassessed) = findings_between(before.findings(), after.findings());
    if !appeared.is_empty() || !resolved.is_empty() || !reassessed.is_empty() {
        changes.push(HostChange::Findings {
            appeared,
            resolved,
            reassessed,
        });
    }

    changes
}

/// The findings one subject gained and lost between two scans.
///
/// Paired on [`ClaimId`] rather than on the whole finding, so that a detection
/// re-running and producing the same claim with a fresh excerpt is not a change.
pub(super) fn findings_between<'a>(
    before: impl Iterator<Item = &'a Finding>,
    after: impl Iterator<Item = &'a Finding>,
) -> (Vec<Finding>, Vec<Finding>, Vec<Reassessment>) {
    let before: BTreeMap<ClaimId, &Finding> = before.map(|f| (f.claim_id(), f)).collect();
    let after: BTreeMap<ClaimId, &Finding> = after.map(|f| (f.claim_id(), f)).collect();

    let appeared = after
        .iter()
        .filter(|(claim, _)| !before.contains_key(*claim))
        .map(|(_, finding)| (*finding).clone())
        .collect();
    let resolved = before
        .iter()
        .filter(|(claim, _)| !after.contains_key(*claim))
        .map(|(_, finding)| (*finding).clone())
        .collect();
    let reassessed = after
        .iter()
        .filter_map(|(claim, finding)| {
            let was = before.get(claim)?;
            Change::between(was.severity(), finding.severity()).map(|severity| Reassessment {
                finding: (*finding).clone(),
                severity,
            })
        })
        .collect();

    (appeared, resolved, reassessed)
}

/// Whether two fingerprints name the same system.
///
/// Everything the identification consists of, and nothing about how sure of it
/// the scan was: the accuracy figures and the evidence string are the
/// fingerprinter describing itself.
fn same_system(before: Option<&OsFingerprint>, after: Option<&OsFingerprint>) -> bool {
    match (before, after) {
        (None, None) => true,
        (Some(before), Some(after)) => {
            before.name() == after.name()
                && before.family() == after.family()
                && before.device() == after.device()
                && before.generation() == after.generation()
                && before.vendor() == after.vendor()
                && before.kernel() == after.kernel()
                && before.cpes() == after.cpes()
        }
        _ => false,
    }
}

/// What one set gained and lost against another, both ascending.
fn difference<T: Ord + Clone>(
    before: impl Iterator<Item = T>,
    after: impl Iterator<Item = T>,
) -> (Vec<T>, Vec<T>) {
    let before: BTreeSet<T> = before.collect();
    let after: BTreeSet<T> = after.collect();

    let gained = after.difference(&before).cloned().collect();
    let lost = before.difference(&after).cloned().collect();
    (gained, lost)
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗██║  ██║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::model::confidence::Confidence;
    use crate::model::finding::{DetectionClass, DetectionId, Reference, Severity, Version};

    fn host(last: u8) -> Host {
        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, last)));
        host.set_status(HostStatus::Up);
        host
    }

    fn finding(id: &str, title: &str, severity: Severity) -> Finding {
        Finding::new(
            DetectionId::new(id, Version::new(1, 0, 0), "hash").expect("a valid detection id"),
            title,
            severity,
            Confidence::Certain,
            DetectionClass::Passive,
        )
        .expect("a titled finding")
    }

    fn findings_change(
        changes: &[HostChange],
    ) -> Option<(&[Finding], &[Finding], &[Reassessment])> {
        changes.iter().find_map(|change| match change {
            HostChange::Findings {
                appeared,
                resolved,
                reassessed,
            } => Some((
                appeared.as_slice(),
                resolved.as_slice(),
                reassessed.as_slice(),
            )),
            _ => None,
        })
    }

    #[test]
    fn a_host_that_did_not_move_reports_nothing() {
        let before = host(1);
        let after = host(1);
        assert!(changes_between(&before, &after).is_empty());
    }

    /// The property ZA-4-008 was filed for: a finding arriving is a change.
    #[test]
    fn a_finding_that_appeared_is_reported() {
        let before = host(1);
        let mut after = host(1);
        after.add_finding(finding("cve", "Log4Shell", Severity::Critical));

        let changes = changes_between(&before, &after);
        let (appeared, resolved, _) = findings_change(&changes).expect("a findings change");
        assert_eq!(appeared.len(), 1);
        assert_eq!(appeared[0].title(), "Log4Shell");
        assert!(resolved.is_empty());
    }

    #[test]
    fn a_finding_that_went_away_is_reported_as_resolved() {
        let mut before = host(1);
        before.add_finding(finding("cve", "Log4Shell", Severity::Critical));
        let after = host(1);

        let changes = changes_between(&before, &after);
        let (appeared, resolved, _) = findings_change(&changes).expect("a findings change");
        assert!(appeared.is_empty());
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].title(), "Log4Shell");
    }

    #[test]
    fn the_same_finding_on_both_sides_is_not_a_change() {
        let mut before = host(1);
        before.add_finding(finding("cve", "Log4Shell", Severity::Critical));
        let mut after = host(1);
        after.add_finding(finding("cve", "Log4Shell", Severity::Critical));

        assert!(findings_change(&changes_between(&before, &after)).is_none());
    }

    /// A detection publishing a new version of itself is the same claim, not a
    /// finding that went away and another that arrived. This is what
    /// [`ClaimId`] is for.
    #[test]
    fn a_detection_version_bump_is_not_a_finding_appearing() {
        let mut before = host(1);
        before.add_finding(
            Finding::new(
                DetectionId::new("cve", Version::new(1, 0, 0), "hash").unwrap(),
                "Log4Shell",
                Severity::Critical,
                Confidence::Certain,
                DetectionClass::Passive,
            )
            .unwrap()
            .with_reference(Reference::cve("CVE-2021-44228").unwrap()),
        );
        let mut after = host(1);
        after.add_finding(
            Finding::new(
                DetectionId::new("cve", Version::new(2, 0, 0), "other").unwrap(),
                "Log4Shell, restated",
                Severity::Critical,
                Confidence::Certain,
                DetectionClass::Passive,
            )
            .unwrap()
            .with_reference(Reference::cve("CVE-2021-44228").unwrap()),
        );

        assert!(
            findings_change(&changes_between(&before, &after)).is_none(),
            "the same CVE under one detection is one claim across versions"
        );
    }

    #[test]
    fn a_severity_that_moved_under_one_claim_is_reported_as_a_reassessment() {
        let mut before = host(1);
        before.add_finding(finding("audit", "Deprecated TLS", Severity::Medium));
        let mut after = host(1);
        after.add_finding(finding("audit", "Deprecated TLS", Severity::Critical));

        let changes = changes_between(&before, &after);
        let (appeared, resolved, reassessed) =
            findings_change(&changes).expect("a findings change");
        assert!(
            appeared.is_empty() && resolved.is_empty(),
            "the claim is on both sides, so it neither appeared nor resolved"
        );
        assert_eq!(reassessed.len(), 1);
        assert_eq!(reassessed[0].severity.before, Severity::Medium);
        assert_eq!(reassessed[0].severity.after, Severity::Critical);
        assert_eq!(reassessed[0].finding.title(), "Deprecated TLS");
    }

    /// A detection re-running writes a fresh excerpt almost every time. Only the
    /// severity is compared, so that is not a change.
    #[test]
    fn an_excerpt_that_changed_under_one_claim_is_not_a_reassessment() {
        use crate::model::finding::Excerpt;

        let mut before = host(1);
        before.add_finding(
            finding("audit", "Deprecated TLS", Severity::Medium).with_excerpt(Excerpt::new("one")),
        );
        let mut after = host(1);
        after.add_finding(
            finding("audit", "Deprecated TLS", Severity::Medium).with_excerpt(Excerpt::new("two")),
        );

        assert!(findings_change(&changes_between(&before, &after)).is_none());
    }

    #[test]
    fn two_findings_from_one_detection_are_told_apart_by_subject() {
        let before = host(1);
        let mut after = host(1);
        after.add_finding(finding("audit", "Weak cipher", Severity::Medium));
        after.add_finding(finding("audit", "Expired certificate", Severity::High));

        let changes = changes_between(&before, &after);
        let (appeared, _, _) = findings_change(&changes).expect("a findings change");
        assert_eq!(appeared.len(), 2);
    }
}
