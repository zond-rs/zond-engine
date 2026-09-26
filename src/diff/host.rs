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
//! the same answer reports nothing. A current scan that identified no system at
//! all reports nothing either: it was run without the probes, or answered too
//! thinly to match, and says nothing about what runs there now. The hardware
//! addresses and the vendor read off them follow the same rule, since a scan
//! that did not reach the host's segment sees neither.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::diff::change::{Change, Presence};
use crate::diff::port::{self, Clocks, PortDelta, PresenceFor};
use crate::diff::scope::ScopeIndex;
use crate::model::finding::{ClaimId, Finding, Severity};
use crate::model::host::os::OsFingerprint;
use crate::model::host::{
    Filtering, Host, HostName, HostStatus, IpProtocolState, NameSource, NetworkRole,
};
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
/// `#[non_exhaustive]`, since a scan learns to establish more about a host as it
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
    /// The names the host gave for itself changed, each list in the model's
    /// order.
    ///
    /// Compared only within the protocols the current scan heard names in. A
    /// scan that asked no SMB server for a session, or read no directory,
    /// established nothing about the names those state, and reporting them lost
    /// on its word would have a quick scan compared against a thorough one
    /// announce every domain controller renamed. The rule
    /// [`Os`](Self::Os) follows, for the same reason.
    Names {
        /// Names the current scan heard and the baseline did not.
        gained: Vec<HostName>,
        /// Names the baseline heard, in a protocol the current scan also heard
        /// names in, and the current scan did not.
        lost: Vec<HostName>,
    },
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
    /// confidence for the same system is not a change and is not reported, and
    /// neither is a current scan that identified nothing: it did not say what
    /// runs there now, so `after` is never `None`.
    ///
    /// Boxed because a pair of fingerprints is several times the size of any
    /// other variant and a change list is mostly the other variants. Unboxed,
    /// every hostname change in a diff would sit in a slot wide enough for
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
    /// The hardware vendor the address resolves to changed, or was named where
    /// it was not. A current scan that named none established nothing about
    /// it, so `after` is never `None`.
    Vendor(Change<Option<String>>),
    /// The roles inferred for the host changed, each list ascending.
    Roles {
        /// Roles the current scan inferred and the baseline did not.
        gained: Vec<NetworkRole>,
        /// Roles the baseline inferred and the current scan does not.
        lost: Vec<NetworkRole>,
    },
    /// What the filter in front of the host was shown to be doing changed, each
    /// list ascending.
    ///
    /// A verdict about the network rather than a measurement of the scan, which
    /// is why it is compared where round-trip times and probe counts are not. A
    /// stateful filter appearing in front of a host, or one that stopped
    /// reassembling fragments, is a change to the path somebody has to know
    /// about.
    ///
    /// Each conclusion is drawn by a comparative probe that only a scan asking
    /// for it runs, so both lists are empty between two scans where
    /// [`characterise`](crate::report::ScanSettings::characterise) was off, the
    /// same reading [`Macs`](Self::Macs) has between two scans that never
    /// reached the link layer.
    Filtering {
        /// Conclusions the current scan drew and the baseline did not.
        gained: Vec<Filtering>,
        /// Conclusions the baseline drew and the current scan does not.
        lost: Vec<Filtering>,
    },
    /// The IP protocols whose verdict moved, ascending by number.
    ///
    /// Only the protocols *both* scans established something about. One that
    /// only one of them asked about is a difference in what was asked rather
    /// than in the network, which is the same reading
    /// [`PortState::Unasked`](crate::model::port::PortState::Unasked) gets in
    /// [`port`]: a scan that named a protocol and never
    /// reached it holds
    /// [`IpProtocolState::Unasked`] there, and comparing that against a verdict would report the second scan
    /// having looked as the host having changed.
    IpProtocols {
        /// What moved, ascending by protocol number.
        changed: Vec<IpProtocolChange>,
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

/// One IP protocol both scans established something about, graded differently.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpProtocolChange {
    /// The protocol number.
    pub protocol: u8,
    /// Where the verdict moved.
    pub state: Change<IpProtocolState>,
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
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reassessment {
    /// The finding as the current scan states it.
    pub finding: Finding,
    /// Where the severity moved.
    pub severity: Change<Severity>,
}

impl Reassessment {
    /// `finding`, whose severity moved as `severity` says.
    pub fn new(finding: Finding, severity: Change<Severity>) -> Self {
        Self { finding, severity }
    }
}

/// Compares one host's two records, either of which may be absent.
///
/// `baseline_coverage` and `current_coverage` are what each report says about
/// having walked this address, and they turn an absent record into either a
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

/// A host's ports as a slice, so both sides of a comparison can be walked
/// without re-running the iterator.
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

    // Only the protocols the current scan heard names in, so a scan that never
    // asked reports nothing lost. See `HostChange::Names`.
    let heard: BTreeSet<NameSource> = after.names().map(HostName::source).collect();
    let (gained, lost) = difference(
        before
            .names()
            .filter(|name| heard.contains(&name.source()))
            .cloned(),
        after.names().cloned(),
    );
    if !gained.is_empty() || !lost.is_empty() {
        changes.push(HostChange::Names { gained, lost });
    }

    let (gained, lost) = difference(before.ips().iter().copied(), after.ips().iter().copied());
    if !gained.is_empty() || !lost.is_empty() {
        changes.push(HostChange::Addresses { gained, lost });
    }

    // Only a current scan that identified the system can say it changed. One
    // that identified nothing, run without the probes or answered too thinly to
    // match, said nothing about what runs there now, and reporting the system
    // gone on its word would have a quick scan compared against a thorough one
    // announce every machine's operating system lost. The baseline's
    // identification stays readable on the delta's baseline record.
    if let Some(now) = after.os()
        && !same_system(before.os(), Some(now))
    {
        changes.push(HostChange::Os(Box::new(Change::new(
            before.os().cloned(),
            Some(now.clone()),
        ))));
    }

    // Hardware addresses are seen at the link layer or not at all, so a record
    // holding none is a scan that did not reach the host's segment, and its
    // silence is not the host losing them.
    let seen_on_link = |host: &Host| {
        host.hardware()
            .is_some_and(|hardware| !hardware.macs().is_empty())
    };
    if seen_on_link(before) && seen_on_link(after) {
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
    }

    // The vendor is read off the hardware, and held to the rule the operating
    // system is: a current scan that named none established nothing about it.
    if let Some(now) = after.vendor()
        && before.vendor() != Some(now)
    {
        changes.push(HostChange::Vendor(Change::new(
            before.vendor().map(str::to_owned),
            Some(now.to_owned()),
        )));
    }

    let (gained, lost) = difference(
        before.network_roles().iter().copied(),
        after.network_roles().iter().copied(),
    );
    if !gained.is_empty() || !lost.is_empty() {
        changes.push(HostChange::Roles { gained, lost });
    }

    let (gained, lost) = difference(
        before.filtering().iter().copied(),
        after.filtering().iter().copied(),
    );
    if !gained.is_empty() || !lost.is_empty() {
        changes.push(HostChange::Filtering { gained, lost });
    }

    let changed = ip_protocols_between(before, after);
    if !changed.is_empty() {
        changes.push(HostChange::IpProtocols { changed });
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

/// The IP protocols whose verdict moved between two records of one host.
///
/// A protocol either scan holds at
/// [`Unasked`](crate::model::host::IpProtocolState::Unasked), or does not hold at
/// all, is left out: that scan established nothing about it, and a verdict
/// compared against nothing is the second scan having looked rather than the
/// host having changed.
fn ip_protocols_between(before: &Host, after: &Host) -> Vec<IpProtocolChange> {
    let established = |host: &Host, number: &u8| {
        host.ip_protocols()
            .get(number)
            .copied()
            .filter(IpProtocolState::is_established)
    };

    before
        .ip_protocols()
        .keys()
        .filter_map(|number| {
            let was = established(before, number)?;
            let is = established(after, number)?;
            Change::between(was, is).map(|state| IpProtocolChange {
                protocol: *number,
                state,
            })
        })
        .collect()
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
                && before.arch() == after.arch()
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
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::model::confidence::Confidence;
    use crate::model::finding::{DetectionClass, DetectionId, Reference, Severity, Version};

    fn host(last: u8) -> Host {
        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)));
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

    /// A filter that appeared in front of a host is a change to the network, and
    /// was the one host verdict this module never looked at.
    ///
    /// It reads like a measurement and is not: `characterise` draws each
    /// conclusion from a comparative probe, so what is recorded is a fact about
    /// the path rather than about how well the scan saw it. A stateful filter
    /// standing where none stood last week is exactly the line a rescan exists
    /// to surface.
    #[test]
    fn a_filter_that_appeared_in_front_of_a_host_is_reported() {
        use crate::model::host::Filtering;

        let before = host(1);
        let mut after = host(1);
        after.add_filtering(Filtering::StatefulFilter);

        let changes = changes_between(&before, &after);
        let filtering = changes
            .iter()
            .find_map(|change| match change {
                HostChange::Filtering { gained, lost } => Some((gained, lost)),
                _ => None,
            })
            .expect("a filtering change");

        assert_eq!(filtering.0, &[Filtering::StatefulFilter]);
        assert!(filtering.1.is_empty());

        // And two scans that both went without the probe report nothing, the way
        // two scans that never reached the link layer report no hardware.
        assert!(
            changes_between(&host(1), &host(1))
                .iter()
                .all(|change| !matches!(change, HostChange::Filtering { .. }))
        );
    }

    /// **A name is compared only in a protocol the current scan heard.** A
    /// domain controller renamed is the change a rescan exists to surface, and
    /// a rescan that asked no directory said nothing about what the directory
    /// calls itself: reported as lost, every name a thorough baseline heard
    /// would read as gone after a quick scan.
    #[test]
    fn a_name_is_compared_only_in_a_protocol_the_current_scan_heard() {
        use crate::model::host::NameKind;

        let name = |kind, source, name| HostName::new(kind, source, name).expect("a name");
        let old_host = name(NameKind::Host, NameSource::Ntlm, "dc01.corp.example");
        let new_host = name(NameKind::Host, NameSource::Ntlm, "dc02.corp.example");
        let directory = name(NameKind::Domain, NameSource::Ldap, "corp.example");

        let mut before = host(1);
        before.record_name(old_host.clone());
        before.record_name(directory);
        let mut after = host(1);
        after.record_name(new_host.clone());

        let changes = changes_between(&before, &after);
        let names = changes
            .iter()
            .find_map(|change| match change {
                HostChange::Names { gained, lost } => Some((gained, lost)),
                _ => None,
            })
            .expect("the renamed machine is a change");
        assert_eq!(names.0, &[new_host]);
        assert_eq!(
            names.1,
            &[old_host],
            "the directory's domain is not lost: nothing asked it"
        );

        assert!(
            changes_between(&before, &host(1))
                .iter()
                .all(|change| !matches!(change, HostChange::Names { .. })),
            "a scan that heard no names says nothing about them"
        );
    }

    /// **A system the current scan did not identify is not a change.** A scan
    /// run without operating-system probes, or one whose probes were answered
    /// too thinly to match, records no fingerprint, and reported as a change a
    /// quick scan compared against a thorough one would say every machine on
    /// the network stopped running what it ran. A different system named is
    /// still the change it is.
    #[test]
    fn a_system_the_current_scan_did_not_identify_is_not_a_change() {
        let mut before = host(1);
        before.set_os(OsFingerprint::new("Linux", 90).with_family("Linux"));

        let unidentified = host(1);
        assert!(
            changes_between(&before, &unidentified)
                .iter()
                .all(|change| !matches!(change, HostChange::Os(_))),
            "{:?}",
            changes_between(&before, &unidentified)
        );

        let mut other = host(1);
        other.set_os(OsFingerprint::new("Windows", 90).with_family("Windows"));
        assert!(
            changes_between(&before, &other)
                .iter()
                .any(|change| matches!(change, HostChange::Os(_)))
        );
        assert!(
            changes_between(&unidentified, &before)
                .iter()
                .any(|change| matches!(change, HostChange::Os(_))),
            "a system identified where none was is still reported"
        );
    }

    /// **A current scan that did not reach the host's segment loses none of
    /// its hardware.** Hardware addresses are seen at the link layer or not at
    /// all, so a scan from beyond a router records none, and reading that as
    /// the host losing them, and its vendor with them, would report every
    /// machine on a LAN changed when the same LAN is scanned from elsewhere.
    #[test]
    fn a_scan_that_did_not_reach_the_segment_loses_no_hardware() {
        let mac = MacAddr::new(0x02, 0, 0, 0, 0, 1);
        use crate::model::host::hardware::{HardwareDescription, HardwareInfo};

        let mut hardware = HardwareInfo::new(mac);
        hardware.merge(
            HardwareInfo::described(HardwareDescription {
                vendor: Some("Example Devices"),
                ..HardwareDescription::default()
            })
            .expect("a vendor is a description"),
        );
        let mut before = host(1);
        before.set_hardware(hardware);
        assert_eq!(before.vendor(), Some("Example Devices"), "the fixture");

        let changes = changes_between(&before, &host(1));
        assert!(
            changes
                .iter()
                .all(|change| !matches!(change, HostChange::Macs { .. } | HostChange::Vendor(_))),
            "{changes:?}"
        );

        let mut replaced = host(1);
        replaced.record_mac(MacAddr::new(0x02, 0, 0, 0, 0, 2));
        let changes = changes_between(&before, &replaced);
        assert!(
            changes
                .iter()
                .any(|change| matches!(change, HostChange::Macs { .. })),
            "another address seen on the segment is still a change: {changes:?}"
        );
    }

    #[test]
    fn a_host_that_did_not_move_reports_nothing() {
        let before = host(1);
        let after = host(1);
        assert!(changes_between(&before, &after).is_empty());
    }

    /// A finding arriving is a change.
    ///
    /// This comparison reported hosts, ports and services that moved and said
    /// nothing when a finding appeared on one that had not, so a host that gained
    /// a critical vulnerability between two runs compared as unchanged.
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
