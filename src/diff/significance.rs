// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How much a change is worth somebody's attention
//!
//! A comparison of two scans of a live network is never empty. Reverse names
//! move, a load balancer hands out a different certificate, a service reports a
//! patch level one release further on. Somewhere in that is the line a person
//! actually needed: a port that opened, a certificate that lapsed, a host that
//! started answering DNS. [`Significance`] is the grade that tells them apart,
//! and this module is the whole of the policy behind it.
//!
//! Every ranking in the crate is here rather than beside the type it grades, so
//! that changing what counts as urgent is one file rather than four, and so that
//! the table can be read as a table.
//!
//! ## What it does not rank
//!
//! Whether the change happened at all. That is
//! [`Presence::is_confirmed`](crate::diff::Presence), and it is a different
//! question with a different answer: a port that appeared on ground the earlier
//! scan never walked is not a weak finding, it is not a finding. The two axes are
//! kept apart the way a [`Finding`] keeps its severity apart from its
//! confidence.
//!
//! They meet in one place. A delta's own grade is the one number a caller sorts
//! by, so [`PortDelta::significance`](crate::diff::PortDelta::significance) and
//! [`HostDelta::significance`](crate::diff::HostDelta::significance) answer
//! [`Routine`](Significance::Routine) for an appearance or a disappearance the
//! other scan cannot be shown to have looked for, whatever it would have meant.
//! The grade of each change is still there to be read, and so is the reason.
//!
//! ## What it does not know
//!
//! Which host matters. A new listener on a payment terminal and a new listener on
//! a spare laptop are the same change here, because nothing in two scan reports
//! says which is which. What is graded is what a change means on any network: an
//! endpoint that started accepting connections is more attack surface wherever it
//! is, and a certificate that has lapsed is breaking something now. A policy
//! about one particular network, which hosts are allowed to serve DHCP and which
//! segments are production, belongs to the caller holding it and is applied on
//! top.
//!
//! ## The table
//!
//! [`Urgent`](Significance::Urgent) is a short list, since a grade everything
//! reaches sorts nothing:
//!
//! - an endpoint that is accepting connections and was not,
//! - a certificate that has lapsed,
//! - a finding at [`High`](crate::model::finding::Severity::High) or
//!   [`Critical`](crate::model::finding::Severity::Critical).
//!
//! [`Notable`](Significance::Notable) is what a person reads in the morning: an
//! endpoint that stopped accepting connections, a host that appeared or went
//! away, a service that changed name or version, an operating system that changed
//! under an address, a hardware address, an inferred role, a conclusion about the
//! filter in front of a host, an IP protocol its stack started or stopped taking
//! delivery of, a negotiated TLS version, a certificate presented,
//! withdrawn or now inside its expiry threshold, and a finding at
//! [`Medium`](crate::model::finding::Severity::Medium).
//!
//! [`Routine`](Significance::Routine) is everything else, and everything else is
//! most of a diff: reverse names, address lists, hardware vendors, platform
//! identifiers, product and version detail below the version itself, cipher
//! suites, offered application protocols, a certificate rotated onto a fresh one,
//! a service identified where the earlier scan had not asked, a port state moving
//! between two verdicts that are neither of them open, and a finding that was
//! resolved or graded down.

use crate::diff::ScanDiff;
use crate::diff::change::{Change, Presence};
use crate::diff::host::{HostChange, HostDelta, Reassessment};
use crate::diff::port::{CertificateChange, PortChange, PortDelta, SecurityChange, ServiceChange};
use crate::model::finding::{Finding, Severity};
use crate::model::host::HostStatus;
use crate::model::port::PortState;

/// How much a change is worth somebody's attention.
///
/// Three grades, ordered, so a caller sorts a change list or filters it with a
/// comparison. The module documentation is the argument for which change lands
/// where, and for the question it leaves to somebody else.
///
/// ```
/// use zond_engine::diff::{ScanDiff, Significance};
/// # use zond_engine::report::ScanReport;
/// # fn example(last_night: &ScanReport, tonight: &ScanReport) {
/// let diff = ScanDiff::between(last_night, tonight);
///
/// for host in diff.hosts() {
///     if host.significance() >= Significance::Notable {
///         println!("{} {}", host.address(), host.significance().label());
///     }
/// }
/// # }
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Significance {
    /// A change a live network makes on its own, and the grade of anything the
    /// comparison cannot vouch for.
    Routine,
    /// Worth a person reading.
    Notable,
    /// Worth a person acting on.
    Urgent,
}

impl Significance {
    /// Every grade, in declaration order, which is least first and is the order
    /// this type's [`Ord`] ranks by.
    ///
    /// Here for the reason [`PortState::ALL`](crate::model::port::PortState::ALL)
    /// gives, and read by the gate holding the exported comparison schema to what
    /// this build can write.
    pub const ALL: &'static [Self] = &[Self::Routine, Self::Notable, Self::Urgent];

    /// The human label, capitalised for a report a person reads.
    ///
    /// Kept apart from the wire name for the reason every vocabulary in this
    /// crate keeps them apart: the label may be reworded whenever it reads
    /// better, and the wire name may never change without breaking every
    /// consumer already keying on it.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Routine => "Routine",
            Self::Notable => "Notable",
            Self::Urgent => "Urgent",
        }
    }

    /// What a finding of this severity amounts to as a change.
    ///
    /// The one grade read off another scale rather than decided here, since a
    /// detection has already answered how bad its claim is and a second opinion
    /// about the same claim would be this module inventing one.
    pub const fn of_severity(severity: Severity) -> Self {
        match severity {
            Severity::Info | Severity::Low => Self::Routine,
            Severity::Medium => Self::Notable,
            Severity::High | Severity::Critical => Self::Urgent,
        }
    }

    /// The stronger of two grades.
    const fn max(self, other: Self) -> Self {
        if (self as u8) >= (other as u8) {
            self
        } else {
            other
        }
    }
}

impl HostChange {
    /// How much this change is worth somebody's attention.
    ///
    /// Matched with no wildcard, so a change this crate learns to report fails to
    /// compile here until somebody has decided what it is worth. A `_` arm would
    /// silently grade it routine, which is the answer that gets a finding missed.
    pub fn significance(&self) -> Significance {
        match self {
            // Present and answering, or not: that is what moved. A host that went
            // from filtered to up gained no ground, it answered for itself where
            // something else had been answering, and `Filtering` is where that is
            // reported.
            HostChange::Status(status) => match answers(status.before) == answers(status.after) {
                true => Significance::Routine,
                false => Significance::Notable,
            },

            // A different system under an address, a different card answering for
            // it, a machine renamed or joined to another domain, a role it did
            // not have, a filter in front of it that changed behaviour, or a
            // protocol its stack takes delivery of that it did not. Each is
            // somebody having changed something. A name the machine states is
            // set on the machine, unlike a reverse name, which is DNS's.
            HostChange::Os(_)
            | HostChange::Macs { .. }
            | HostChange::Names { .. }
            | HostChange::Roles { .. }
            | HostChange::Filtering { .. }
            | HostChange::IpProtocols { .. } => Significance::Notable,

            // A reverse name is DNS, an address list is DHCP, and a vendor is
            // whatever the hardware address already said. None of them is the
            // machine behaving differently.
            HostChange::Hostname(_) | HostChange::Addresses { .. } | HostChange::Vendor(_) => {
                Significance::Routine
            }

            HostChange::Findings {
                appeared,
                resolved,
                reassessed,
            } => of_findings(appeared, resolved, reassessed),
        }
    }
}

impl PortChange {
    /// How much this change is worth somebody's attention.
    ///
    /// Matched with no wildcard, for the reason
    /// [`HostChange::significance`] gives.
    pub fn significance(&self) -> Significance {
        match self {
            PortChange::State(state) => of_state(state),
            PortChange::Service(service) => of_service(service),
            PortChange::Security(security) => of_security(security),
            // A claim the current scan did not settle says how far the scan
            // got rather than anything about the endpoint, so it grades as
            // nothing having moved, the way an unreached port does.
            PortChange::Findings {
                appeared,
                resolved,
                unsettled: _,
                reassessed,
            } => of_findings(appeared, resolved, reassessed),
        }
    }
}

impl PortDelta {
    /// How much this endpoint is worth somebody's attention.
    ///
    /// The strongest of what moved, and [`Routine`](Significance::Routine) for an
    /// endpoint whose appearance or disappearance the other scan cannot be shown
    /// to have looked for. That is the one place the two axes meet, and the
    /// module documentation is the argument for it;
    /// [`presence`](Self::presence) is where the reason stays readable.
    pub fn significance(&self) -> Significance {
        // An endpoint that changed state carries a `State` change graded the same
        // way, so this adds nothing there. What it covers is the endpoint that
        // appeared or went away, which carries no changes at all.
        let presence = if !self.presence().is_confirmed() {
            Significance::Routine
        } else if self.is_opened() {
            Significance::Urgent
        } else if self.is_closed() {
            Significance::Notable
        } else {
            Significance::Routine
        };

        self.changes()
            .iter()
            .map(PortChange::significance)
            .fold(presence, Significance::max)
    }
}

impl HostDelta {
    /// How much this host is worth somebody's attention.
    ///
    /// The strongest of what moved about the host itself and of what moved on any
    /// of its endpoints, so a host is graded by the worst thing on it. A host
    /// whose appearance or disappearance the other scan cannot be shown to have
    /// looked for contributes [`Routine`](Significance::Routine) of its own, the
    /// way an endpoint's does.
    ///
    /// Its endpoints are still folded in, each answering the coverage question
    /// for itself. A scope places an address and a port set separately, so a host
    /// the other scan cannot be shown to have looked for can carry an endpoint it
    /// can, and grading the host by its presence alone would drop that.
    pub fn significance(&self) -> Significance {
        let presence = match self.presence() {
            // A host both scans hold has no appearance to grade, so what it is
            // worth is entirely what moved on it.
            Presence::Both => Significance::Routine,
            // And one only one scan holds is graded by what the other says about
            // having looked.
            presence if !presence.is_confirmed() => Significance::Routine,
            Presence::Added { .. } | Presence::Removed { .. } => Significance::Notable,
        };

        let own = self
            .changes()
            .iter()
            .map(HostChange::significance)
            .fold(presence, Significance::max);

        self.ports()
            .iter()
            .map(PortDelta::significance)
            .fold(own, Significance::max)
    }
}

impl ScanDiff {
    /// How much this comparison is worth somebody's attention: the grade of the
    /// host that carries the strongest change.
    ///
    /// [`Routine`](Significance::Routine) for a comparison that found nothing,
    /// since nothing to do and nothing worth doing rank the same here.
    /// [`is_empty`](Self::is_empty) is the question that separates them.
    pub fn significance(&self) -> Significance {
        self.hosts()
            .iter()
            .map(HostDelta::significance)
            .fold(Significance::Routine, Significance::max)
    }
}

/// Whether a status means the host is there.
///
/// [`Filtered`](HostStatus::Filtered) counts: something is enforcing a perimeter
/// around the address, which is a thing being there.
const fn answers(status: HostStatus) -> bool {
    matches!(status, HostStatus::Up | HostStatus::Filtered)
}

/// What a port's verdict moving amounts to.
///
/// Only openness is graded, because only openness is a fact about what the
/// network offers. The other five verdicts differ in what the probe could
/// establish, and moving between two of them is a firewall or a retry budget
/// rather than a service.
fn of_state(state: &Change<PortState>) -> Significance {
    let was_open = state.before == PortState::Open;
    let is_open = state.after == PortState::Open;

    match (was_open, is_open) {
        (false, true) => Significance::Urgent,
        (true, false) => Significance::Notable,
        _ => Significance::Routine,
    }
}

/// What a change to the thing listening amounts to.
fn of_service(change: &ServiceChange) -> Significance {
    match change {
        // Something else is listening, or the same thing at a different release.
        // The second is what a patch looks like from outside, and it is what
        // makes a rollback visible.
        ServiceChange::Name(_) | ServiceChange::Version(_) => Significance::Notable,

        // An identification appearing or going away usually says the two scans
        // asked differently, which `service_detection` records per phase. The
        // remaining fields are detail hanging off an identity that did not move.
        ServiceChange::Identified(_)
        | ServiceChange::Unidentified(_)
        | ServiceChange::Product(_)
        | ServiceChange::Vendor(_)
        | ServiceChange::ExtraInfo(_)
        | ServiceChange::Cpes { .. } => Significance::Routine,
    }
}

/// What a change to an endpoint's transport security amounts to.
fn of_security(change: &SecurityChange) -> Significance {
    match change {
        SecurityChange::TlsVersion(_) => Significance::Notable,
        SecurityChange::CipherSuite(_) | SecurityChange::Alpn { .. } => Significance::Routine,
        SecurityChange::Certificate(certificate) => match certificate {
            // Serving an expired certificate is breaking somebody's client right
            // now, which nothing else on this list is.
            CertificateChange::Expired { .. } => Significance::Urgent,
            CertificateChange::Expiring { .. }
            | CertificateChange::Presented(_)
            | CertificateChange::Withdrawn(_) => Significance::Notable,
            // Renewal. A certificate that rotates is a certificate somebody is
            // looking after, and grading it would put every well-run endpoint on
            // the list every ninety days.
            CertificateChange::Rotated { .. } => Significance::Routine,
        },
    }
}

/// What a subject's findings moving amounts to.
///
/// Graded off the findings' own severities rather than off a scale of this
/// module's. A claim that went away and one that was graded down are both good
/// news, and neither is something to act on.
fn of_findings(
    appeared: &[Finding],
    _resolved: &[Finding],
    reassessed: &[Reassessment],
) -> Significance {
    let raised = reassessed
        .iter()
        .filter(|shift| shift.severity.after > shift.severity.before)
        .map(|shift| Significance::of_severity(shift.severity.after));

    appeared
        .iter()
        .map(|finding| Significance::of_severity(finding.severity()))
        .chain(raised)
        .fold(Significance::Routine, Significance::max)
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
    use crate::model::confidence::Confidence;
    use crate::model::finding::{DetectionClass, DetectionId, Version};

    fn finding(severity: Severity) -> Finding {
        Finding::new(
            DetectionId::new("test", Version::new(1, 0, 0), "hash").expect("a detection id"),
            "A finding",
            severity,
            Confidence::Certain,
            DetectionClass::ActiveBenign,
        )
        .expect("a finding")
    }

    #[test]
    fn the_grades_are_ordered_least_first() {
        assert!(Significance::Routine < Significance::Notable);
        assert!(Significance::Notable < Significance::Urgent);
        assert_eq!(
            Significance::ALL,
            [
                Significance::Routine,
                Significance::Notable,
                Significance::Urgent
            ]
        );
    }

    /// The one change the whole grade exists to surface, and its mirror, which is
    /// news but not an emergency.
    #[test]
    fn a_port_that_opened_outranks_one_that_closed() {
        let opened = PortChange::State(Change::new(PortState::Filtered, PortState::Open));
        let closed = PortChange::State(Change::new(PortState::Open, PortState::Filtered));

        assert_eq!(opened.significance(), Significance::Urgent);
        assert_eq!(closed.significance(), Significance::Notable);
        assert!(opened.significance() > closed.significance());
    }

    /// Two verdicts that are neither of them open differ in what the probe could
    /// establish, which is about the scan and the firewall rather than about what
    /// the network offers.
    #[test]
    fn a_verdict_moving_between_two_closed_states_is_routine() {
        for (before, after) in [
            (PortState::Filtered, PortState::Closed),
            (PortState::Closed, PortState::Unfiltered),
            (PortState::ClosedFiltered, PortState::Filtered),
        ] {
            assert_eq!(
                PortChange::State(Change::new(before, after)).significance(),
                Significance::Routine,
                "{before:?} to {after:?}"
            );
        }
    }

    #[test]
    fn a_lapsed_certificate_is_the_one_urgent_thing_about_transport_security() {
        use crate::model::port::security::CertificateInfo;
        use std::time::{Duration, SystemTime};

        let certificate = CertificateInfo::new(
            "example.test",
            "Test CA",
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            "fingerprint",
        );

        let expired =
            PortChange::Security(SecurityChange::Certificate(CertificateChange::Expired {
                certificate: Box::new(certificate.clone()),
                since: Duration::from_secs(60),
            }));
        let expiring =
            PortChange::Security(SecurityChange::Certificate(CertificateChange::Expiring {
                certificate: Box::new(certificate.clone()),
                remaining: Duration::from_secs(60),
            }));
        let rotated =
            PortChange::Security(SecurityChange::Certificate(CertificateChange::Rotated {
                before: Box::new(certificate.clone()),
                after: Box::new(certificate),
            }));

        assert_eq!(expired.significance(), Significance::Urgent);
        assert_eq!(expiring.significance(), Significance::Notable);
        assert_eq!(rotated.significance(), Significance::Routine);
    }

    /// A detection has already graded its own claim, and this reads that grade
    /// rather than forming a second opinion about it.
    #[test]
    fn a_finding_is_graded_by_its_own_severity() {
        for (severity, expected) in [
            (Severity::Info, Significance::Routine),
            (Severity::Low, Significance::Routine),
            (Severity::Medium, Significance::Notable),
            (Severity::High, Significance::Urgent),
            (Severity::Critical, Significance::Urgent),
        ] {
            let change = HostChange::Findings {
                appeared: vec![finding(severity)],
                resolved: Vec::new(),
                reassessed: Vec::new(),
            };
            assert_eq!(change.significance(), expected, "{severity:?}");
        }
    }

    /// Good news is not news to act on, however bad the claim was.
    #[test]
    fn a_finding_that_went_away_or_was_graded_down_is_routine() {
        let resolved = HostChange::Findings {
            appeared: Vec::new(),
            resolved: vec![finding(Severity::Critical)],
            reassessed: Vec::new(),
        };
        assert_eq!(resolved.significance(), Significance::Routine);

        let downgraded = HostChange::Findings {
            appeared: Vec::new(),
            resolved: Vec::new(),
            reassessed: vec![Reassessment {
                finding: finding(Severity::Low),
                severity: Change::new(Severity::Critical, Severity::Low),
            }],
        };
        assert_eq!(downgraded.significance(), Significance::Routine);

        let raised = HostChange::Findings {
            appeared: Vec::new(),
            resolved: Vec::new(),
            reassessed: vec![Reassessment {
                finding: finding(Severity::Critical),
                severity: Change::new(Severity::Low, Severity::Critical),
            }],
        };
        assert_eq!(raised.significance(), Significance::Urgent);
    }

    /// A host that answers where it did not is the change; a host that answered
    /// and is now answering from behind a filter is the same host.
    #[test]
    fn a_status_change_is_graded_by_whether_the_host_is_there() {
        let arrived = HostChange::Status(Change::new(HostStatus::Unknown, HostStatus::Up));
        let went = HostChange::Status(Change::new(HostStatus::Up, HostStatus::Unknown));
        let filtered = HostChange::Status(Change::new(HostStatus::Up, HostStatus::Filtered));
        let quiet = HostChange::Status(Change::new(HostStatus::Unknown, HostStatus::Down));

        assert_eq!(arrived.significance(), Significance::Notable);
        assert_eq!(went.significance(), Significance::Notable);
        assert_eq!(filtered.significance(), Significance::Routine);
        assert_eq!(quiet.significance(), Significance::Routine);
    }
}
