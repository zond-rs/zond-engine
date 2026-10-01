// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How much a change is worth somebody's attention
//!
//! Two scans of a live network always differ: reverse names move, a load balancer
//! hands out a different certificate, a service reports a newer patch level. Among
//! that is what a person needs to see: a port that opened, a certificate that
//! lapsed, a host that started answering DNS. [`Significance`] grades changes to
//! tell them apart, and every ranking in the crate lives in this module, so the
//! policy reads as one table.
//!
//! ## What it does not rank
//!
//! Whether the change happened at all. That is
//! [`Presence::is_confirmed`](crate::diff::Presence): a port that appeared on
//! ground the earlier scan never walked is not a finding. The two axes are kept
//! apart the way a [`Finding`] keeps its severity apart from its confidence.
//!
//! They meet in one place. A delta's own grade is the number a caller sorts by, so
//! [`PortDelta::significance`](crate::diff::PortDelta::significance) and
//! [`HostDelta::significance`](crate::diff::HostDelta::significance) answer
//! [`Routine`](Significance::Routine) for an appearance or disappearance the other
//! scan cannot be shown to have looked for. Each change's own grade, and the
//! presence, remain readable.
//!
//! ## What it does not know
//!
//! Which host matters. A new listener on a payment terminal and on a spare laptop
//! are the same change here, since nothing in two scan reports says which is
//! which. The grade is what a change means on any network. Policy about one
//! particular network, such as which hosts may serve DHCP or which segments are
//! production, is the caller's to apply on top.
//!
//! ## The table
//!
//! [`Urgent`](Significance::Urgent) is a short list:
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
//! delivery of, a negotiated TLS version, a certificate presented, withdrawn or
//! newly inside its expiry threshold, and a finding at
//! [`Medium`](crate::model::finding::Severity::Medium).
//!
//! [`Routine`](Significance::Routine) is everything else, which is most of a diff:
//! reverse names, address lists, hardware vendors, platform identifiers, product
//! and version detail below the version itself, cipher suites, offered application
//! protocols, a certificate rotated onto a fresh one, a service identified where
//! the earlier scan had not asked, a port state moving between two verdicts that
//! are neither of them open, and a finding that was resolved or graded down.

use crate::diff::ScanDiff;
use crate::diff::change::{Change, Presence};
use crate::diff::host::{HostChange, HostDelta, Reassessment};
use crate::diff::port::{CertificateChange, PortChange, PortDelta, SecurityChange, ServiceChange};
use crate::model::finding::{Finding, Severity};
use crate::model::host::HostStatus;
use crate::model::port::PortState;

/// How much a change is worth somebody's attention.
///
/// Three grades, ordered, so a caller can sort a change list or filter it with a
/// comparison. The module documentation lists which change lands where.
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
    /// Every grade, least first, which is the order [`Ord`] ranks by.
    ///
    /// The export conformance suite checks this against the exported comparison
    /// schema.
    pub const ALL: &'static [Self] = &[Self::Routine, Self::Notable, Self::Urgent];

    /// The human label, capitalised for a report a person reads.
    ///
    /// Separate from the wire name: the label may be reworded, the wire name may
    /// not.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Routine => "Routine",
            Self::Notable => "Notable",
            Self::Urgent => "Urgent",
        }
    }

    /// What a finding of this severity amounts to as a change.
    ///
    /// Read off the detection's own severity, since the detection has already
    /// judged how bad its claim is.
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
    /// Matched with no wildcard, so a new kind of change fails to compile here
    /// until somebody decides what it is worth.
    pub fn significance(&self) -> Significance {
        match self {
            // Only there-or-not is graded. Blocked to up means the host answered
            // for itself where something else had, which `Filtering` reports.
            HostChange::Status(status) => match answers(status.before) == answers(status.after) {
                true => Significance::Routine,
                false => Significance::Notable,
            },

            // Each is somebody changing the machine or its path. A name the
            // machine states is set on the machine; a reverse name is DNS's.
            HostChange::Os(_)
            | HostChange::Macs { .. }
            | HostChange::Names { .. }
            | HostChange::Roles { .. }
            | HostChange::Filtering { .. }
            | HostChange::IpProtocols { .. } => Significance::Notable,

            // A reverse name is DNS, an address list is DHCP, and a vendor follows
            // from the hardware address.
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
    /// Matched with no wildcard, like [`HostChange::significance`].
    pub fn significance(&self) -> Significance {
        match self {
            PortChange::State(state) => of_state(state),
            PortChange::Service(service) => of_service(service),
            PortChange::Security(security) => of_security(security),
            // An unsettled claim says how far the scan got, so it grades as
            // nothing moved, like an unreached port.
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
    /// to have looked for; [`presence`](Self::presence) keeps the reason.
    pub fn significance(&self) -> Significance {
        // For an endpoint that changed state this repeats its `State` grade. It
        // matters for one that appeared or went away, which carries no changes.
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
    /// The strongest of what moved on the host and on any of its endpoints. An
    /// unconfirmed appearance or disappearance contributes
    /// [`Routine`](Significance::Routine) of its own, as an endpoint's does.
    ///
    /// Its endpoints are still folded in, each answering the coverage question for
    /// itself, since a scope places addresses and port sets separately.
    pub fn significance(&self) -> Significance {
        let presence = match self.presence() {
            Presence::Both => Significance::Routine,
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
    /// [`Routine`](Significance::Routine) for a comparison that found nothing;
    /// [`is_empty`](Self::is_empty) tells that apart from only routine changes.
    pub fn significance(&self) -> Significance {
        self.hosts()
            .iter()
            .map(HostDelta::significance)
            .fold(Significance::Routine, Significance::max)
    }
}

/// Whether a status means the host is there.
///
/// [`Blocked`](HostStatus::Blocked) counts: something is enforcing a perimeter
/// around the address.
const fn answers(status: HostStatus) -> bool {
    matches!(status, HostStatus::Up | HostStatus::Blocked)
}

/// What a port's verdict moving amounts to.
///
/// Only openness is graded, since only openness says what the network offers. The
/// other verdicts differ in what the probe could establish, which is down to a
/// firewall or a retry budget.
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
        // Something else is listening, or the same thing at a different release
        // or build, which is how a patch or rollback looks from outside.
        ServiceChange::Name(_) | ServiceChange::Version(_) | ServiceChange::Build(_) => {
            Significance::Notable
        }

        // An identification appearing or going away usually means the scans
        // asked differently (`service_detection` is recorded per phase). The rest
        // is detail under an identity that did not move.
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
            // An expired certificate is breaking clients right now.
            CertificateChange::Expired { .. } => Significance::Urgent,
            CertificateChange::Expiring { .. }
            | CertificateChange::Presented(_)
            | CertificateChange::Withdrawn(_) => Significance::Notable,
            // Renewal, which a well-run endpoint does every ninety days or so.
            CertificateChange::Rotated { .. } => Significance::Routine,
        },
    }
}

/// What a subject's findings moving amounts to.
///
/// Graded by the findings' own severities. A resolved or downgraded claim is
/// good news and grades routine.
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

    /// An opened port is urgent; a closed one is notable.
    #[test]
    fn a_port_that_opened_outranks_one_that_closed() {
        let opened = PortChange::State(Change::new(PortState::NoReply, PortState::Open));
        let closed = PortChange::State(Change::new(PortState::Open, PortState::NoReply));

        assert_eq!(opened.significance(), Significance::Urgent);
        assert_eq!(closed.significance(), Significance::Notable);
        assert!(opened.significance() > closed.significance());
    }

    /// Two verdicts that are neither of them open differ only in what the probe
    /// could establish.
    #[test]
    fn a_verdict_moving_between_two_closed_states_is_routine() {
        for (before, after) in [
            (PortState::NoReply, PortState::Closed),
            (PortState::Closed, PortState::Reachable),
            (PortState::ClosedOrNoReply, PortState::NoReply),
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

    /// A finding's grade follows the detection's own severity.
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

    /// A resolved or downgraded finding is routine, however bad the claim was.
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

    /// A host that answers where it did not is the change; a host now answering
    /// from behind a filter is the same host.
    #[test]
    fn a_status_change_is_graded_by_whether_the_host_is_there() {
        let arrived = HostChange::Status(Change::new(HostStatus::Unknown, HostStatus::Up));
        let went = HostChange::Status(Change::new(HostStatus::Up, HostStatus::Unknown));
        let blocked = HostChange::Status(Change::new(HostStatus::Up, HostStatus::Blocked));
        let quiet = HostChange::Status(Change::new(HostStatus::Unknown, HostStatus::Down));

        assert_eq!(arrived.significance(), Significance::Notable);
        assert_eq!(went.significance(), Significance::Notable);
        assert_eq!(blocked.significance(), Significance::Routine);
        assert_eq!(quiet.significance(), Significance::Routine);
    }
}
