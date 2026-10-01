// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What changed about one endpoint
//!
//! Ports pair by number and transport, which needs no policy: 443 over TCP is 443
//! over TCP in both scans. This module holds the vocabulary for what moved: the
//! state, what is listening, and what it presents at the TLS handshake.
//!
//! ## Only the verdicts
//!
//! A port carries its verdict and the evidence behind it, and only the verdict is
//! compared. [`Discovery`](crate::model::port::Discovery) (which packet settled
//! the state, when, how long it took, who sent it) changes whenever a reply is a
//! millisecond slower or a different router answers for a blocked port. A
//! service's confidence score is left out for the same reason.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use std::time::SystemTime;

use crate::diff::change::{Change, Coverage, Presence};
use crate::diff::host::Reassessment;
use crate::model::finding::{Finding, Standing};
use crate::model::port::security::CertificateInfo;
use crate::model::port::{Build, Port, PortState, Protocol, Security, Service};

/// One endpoint, as the two scans hold it.
///
/// The number and transport identify it in both. What moved is in
/// [`changes`](Self::changes), and the whole record from each side is kept
/// alongside for context.
#[derive(Debug, Clone, PartialEq)]
pub struct PortDelta {
    number: u16,
    protocol: Protocol,
    presence: Presence,
    baseline: Option<Port>,
    current: Option<Port>,
    changes: Vec<PortChange>,
}

impl PortDelta {
    /// The port number, which is the same in both scans.
    pub fn number(&self) -> u16 {
        self.number
    }

    /// The transport, which is the same in both scans.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Which scans hold a record for this endpoint, and what the other one says
    /// about having looked.
    pub fn presence(&self) -> Presence {
        self.presence
    }

    /// The baseline scan's record, if it has one.
    ///
    /// [`None`] also where the baseline's record is [`PortState::Unasked`]: a
    /// port nobody probed holds no finding. See [`diff`](crate::diff).
    pub fn baseline(&self) -> Option<&Port> {
        self.baseline.as_ref()
    }

    /// The current scan's record, if it has one, read the same way.
    pub fn current(&self) -> Option<&Port> {
        self.current.as_ref()
    }

    /// Everything that moved, in a fixed order: state, then service, then
    /// transport security.
    pub fn changes(&self) -> &[PortChange] {
        &self.changes
    }

    /// Whether anything is reported for this endpoint at all.
    ///
    /// False only for an endpoint both scans hold identically, which the
    /// comparison does not emit.
    pub fn is_empty(&self) -> bool {
        self.presence.is_in_both() && self.changes.is_empty()
    }

    /// Whether this endpoint accepts connections now and did not before.
    ///
    /// Reads the records only. An endpoint the baseline has no record for counts,
    /// as does one it recorded [`Unasked`](PortState::Unasked). Whether the
    /// baseline looked at all is [`presence`](Self::presence)'s question:
    /// [`Presence::is_confirmed`] separates a port that opened from one nobody had
    /// checked.
    pub fn is_opened(&self) -> bool {
        self.state_of(self.current.as_ref()) == Some(PortState::Open)
            && self.state_of(self.baseline.as_ref()) != Some(PortState::Open)
    }

    /// Whether this endpoint accepted connections before and does not now.
    ///
    /// The mirror of [`is_opened`](Self::is_opened), with the same reading.
    pub fn is_closed(&self) -> bool {
        self.state_of(self.baseline.as_ref()) == Some(PortState::Open)
            && self.state_of(self.current.as_ref()) != Some(PortState::Open)
    }

    fn state_of(&self, port: Option<&Port>) -> Option<PortState> {
        port.map(Port::state)
    }
}

/// Something that moved about one endpoint.
///
/// `#[non_exhaustive]` because new protocols let a scan establish more about a
/// port, and adding a variant should not need a major version.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum PortChange {
    /// The verdict moved. States are not ordered by how alarming they are:
    /// `NoReply` to `Closed` is a firewall that stopped dropping probes, not a
    /// port that shut.
    State(Change<PortState>),
    /// What is listening changed or was first identified.
    Service(ServiceChange),
    /// What the endpoint presents at the TLS handshake changed.
    Security(SecurityChange),
    /// Findings that appeared on the port, findings the current scan stopped
    /// claiming, and findings whose severity moved. Paired as
    /// [`HostChange::Findings`](super::host::HostChange::Findings) pairs its own.
    ///
    /// A claim the current scan does not make is resolved only where that scan
    /// settled what the claim rests on; otherwise it goes under `unsettled`, the
    /// finding-level [`Coverage::Unreached`]. That covers:
    ///
    /// - a claim drawn from what the endpoint accepts, where the current scan cut
    ///   a version walk it rests on short, or made none;
    /// - a claim drawn from the certificate's posture, where the current scan
    ///   recorded no certificate (reported beside the
    ///   [`Withdrawn`](CertificateChange::Withdrawn) for the absence);
    /// - a vulnerability correlation, where the current scan identified nothing
    ///   there or named the software without a version.
    Findings {
        /// Findings the current scan claims and the baseline did not.
        appeared: Vec<Finding>,
        /// Findings the baseline claimed and the current scan does not, other
        /// than those under `unsettled`.
        resolved: Vec<Finding>,
        /// Findings the baseline claimed that the current scan neither claims
        /// nor settled.
        unsettled: Vec<Finding>,
        /// Findings both scans claim, where the severity moved.
        reassessed: Vec<Reassessment>,
    },
}

/// Something that moved about what is listening on an endpoint.
///
/// [`Version`](Self::Version) is the one most monitoring looks for: 1.18.0 to
/// 1.24.0 is a patch that landed, and the other way is a rollback.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceChange {
    /// Nothing was identified here before, and something is now.
    Identified(Service),
    /// Something was identified here before and nothing is now. The service is
    /// not necessarily gone: the endpoint may not have been asked, which the
    /// phase's [`service_detection`](crate::report::ScanSettings::service_detection)
    /// setting records.
    Unidentified(Service),
    /// The service is called something else.
    Name(Change<String>),
    /// The product behind it changed.
    Product(Change<Option<String>>),
    /// The vendor changed.
    Vendor(Change<Option<String>>),
    /// The version changed.
    Version(Change<Option<String>>),
    /// The trailing detail the fingerprint carried changed.
    ExtraInfo(Change<Option<String>>),
    /// Whose build it is, or which build, changed. A new package revision of the
    /// same upstream version is how a distribution's security update looks from
    /// outside.
    Build(Change<Option<Build>>),
    /// The platform identifiers changed, each list ascending.
    Cpes {
        /// Identifiers the current scan has and the baseline did not.
        gained: Vec<String>,
        /// Identifiers the baseline had and the current scan does not.
        lost: Vec<String>,
    },
}

/// Something that moved about an endpoint's transport security.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityChange {
    /// The negotiated protocol version changed.
    TlsVersion(Change<Option<String>>),
    /// The negotiated cipher suite changed.
    CipherSuite(Change<Option<String>>),
    /// The application protocols offered changed, each list ascending.
    Alpn {
        /// Protocols the current scan saw offered and the baseline did not.
        gained: Vec<String>,
        /// Protocols the baseline saw offered and the current scan does not.
        lost: Vec<String>,
    },
    /// The certificate changed, or its standing did.
    Certificate(CertificateChange),
}

/// Something that moved about the certificate an endpoint presents.
///
/// Identity is the SHA-256 fingerprint, so there are no field-level variants: a
/// certificate whose issuer or validity differs is a different certificate, and
/// [`Rotated`](Self::Rotated).
///
/// [`Expiring`](Self::Expiring) and [`Expired`](Self::Expired) can happen to an
/// unchanged certificate: the clock crossed a threshold between the two scans.
/// See [`diff`](crate::diff) for which clock is used.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum CertificateChange {
    /// A certificate is presented where none was before.
    Presented(CertificateInfo),
    /// No certificate is presented where one was before.
    Withdrawn(CertificateInfo),
    /// A different certificate is presented.
    Rotated {
        /// What the baseline scan was shown.
        before: Box<CertificateInfo>,
        /// What the current scan was shown.
        after: Box<CertificateInfo>,
    },
    /// The certificate is still valid and inside the expiry threshold at the
    /// current clock, and was outside it at the baseline's.
    Expiring {
        /// The certificate now inside the threshold.
        certificate: Box<CertificateInfo>,
        /// How long it has left, at the current scan's clock.
        remaining: Duration,
    },
    /// The certificate is past its validity end at the current clock, and was
    /// not at the baseline's.
    Expired {
        /// The certificate that lapsed.
        certificate: Box<CertificateInfo>,
        /// How long ago it lapsed, at the current scan's clock.
        since: Duration,
    },
}

/// Where a certificate stands at one moment.
///
/// Unordered. A comparison reports transitions into [`Expiring`](Self::Expiring)
/// or [`Expired`](Self::Expired), the two a person has to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Validity {
    /// Nothing was presented, or the baseline was shown a different certificate,
    /// so there is no earlier standing to move from.
    Absent,
    NotYetValid,
    Valid,
    Expiring,
    Expired,
}

/// When the two clocks are used and what they are is documented on
/// [`DiffOptions`](crate::diff::DiffOptions).
pub(crate) struct Clocks {
    pub(crate) baseline: SystemTime,
    pub(crate) current: SystemTime,
    pub(crate) expiry_threshold: Duration,
}

/// Compares the endpoints of two hosts, ascending by number and then transport.
///
/// Endpoints identical in both scans are left out.
///
/// ## An unasked port is not a record
///
/// A port a scan named and never probed is on its host at [`PortState::Unasked`],
/// and is indexed here as that side holding no record for the endpoint, with
/// coverage [`Coverage::Unreached`]. See [`diff`](crate::diff).
pub(crate) fn compare<'a>(
    baseline: &[&'a Port],
    current: &[&'a Port],
    presence: PresenceFor<'_>,
    clocks: &Clocks,
) -> Vec<PortDelta> {
    // Indexed: a host from a full-port scan carries tens of thousands of ports,
    // and a linear find per endpoint would be quadratic. The maps also give the
    // ascending order the result promises.
    let index = |ports: &[&'a Port]| -> BTreeMap<(u16, Protocol), &'a Port> {
        ports
            .iter()
            .filter(|port| port.state() != PortState::Unasked)
            .map(|port| ((port.number(), port.protocol()), *port))
            .collect()
    };
    let unreached = |ports: &[&'a Port]| -> BTreeSet<(u16, Protocol)> {
        ports
            .iter()
            .filter(|port| port.state() == PortState::Unasked)
            .map(|port| (port.number(), port.protocol()))
            .collect()
    };

    let baseline_unreached = unreached(baseline);
    let current_unreached = unreached(current);
    let baseline = index(baseline);
    let current = index(current);

    let keys: BTreeSet<(u16, Protocol)> = baseline.keys().chain(current.keys()).copied().collect();

    let mut deltas = Vec::new();
    for (number, protocol) in keys {
        let before = baseline.get(&(number, protocol)).copied();
        let after = current.get(&(number, protocol)).copied();

        let (presence, changes) = match (before, after) {
            (Some(_), Some(_)) => (Presence::Both, changes_between(before, after, clocks)),
            (Some(_), None) => (
                presence.removed(number, protocol, &current_unreached),
                Vec::new(),
            ),
            (None, Some(_)) => (
                presence.added(number, protocol, &baseline_unreached),
                Vec::new(),
            ),
            (None, None) => unreachable!("a key comes from one side or the other"),
        };

        if presence.is_in_both() && changes.is_empty() {
            continue;
        }

        deltas.push(PortDelta {
            number,
            protocol,
            presence,
            baseline: before.cloned(),
            current: after.cloned(),
            changes,
        });
    }

    deltas
}

/// What each report says about having probed a given endpoint.
///
/// Asked per endpoint, since a scope names the ports it walked and the answer can
/// differ between 443 and 8080 on the same address.
pub(crate) struct PresenceFor<'a> {
    pub(crate) baseline: &'a dyn Fn(u16, Protocol) -> Coverage,
    pub(crate) current: &'a dyn Fn(u16, Protocol) -> Coverage,
}

impl PresenceFor<'_> {
    fn added(
        &self,
        number: u16,
        protocol: Protocol,
        unreached: &BTreeSet<(u16, Protocol)>,
    ) -> Presence {
        Presence::Added {
            before: Self::coverage(self.baseline, number, protocol, unreached),
        }
    }

    fn removed(
        &self,
        number: u16,
        protocol: Protocol,
        unreached: &BTreeSet<(u16, Protocol)>,
    ) -> Presence {
        Presence::Removed {
            after: Self::coverage(self.current, number, protocol, unreached),
        }
    }

    /// What one side says about having probed an endpoint it holds no record
    /// for.
    ///
    /// The side's own record answers first: a port it wrote down as
    /// [`PortState::Unasked`] is unreached however wide its declared scope.
    fn coverage(
        scope: &dyn Fn(u16, Protocol) -> Coverage,
        number: u16,
        protocol: Protocol,
        unreached: &BTreeSet<(u16, Protocol)>,
    ) -> Coverage {
        if unreached.contains(&(number, protocol)) {
            Coverage::Unreached
        } else {
            scope(number, protocol)
        }
    }
}

/// Everything that moved between two records of the same endpoint.
fn changes_between(
    before: Option<&Port>,
    after: Option<&Port>,
    clocks: &Clocks,
) -> Vec<PortChange> {
    let (Some(before), Some(after)) = (before, after) else {
        return Vec::new();
    };

    let mut changes = Vec::new();

    if let Some(state) = Change::between(before.state(), after.state()) {
        changes.push(PortChange::State(state));
    }

    changes.extend(
        service_changes(before.service(), after.service())
            .into_iter()
            .map(PortChange::Service),
    );

    changes.extend(
        security_changes(before.security(), after.security(), clocks)
            .into_iter()
            .map(PortChange::Security),
    );

    let (appeared, gone, reassessed) =
        super::host::findings_between(before.findings(), after.findings());

    // The claim's evidence is in the baseline's record; whether the current scan
    // settled it is in the current one's.
    let (unsettled, resolved): (Vec<Finding>, Vec<Finding>) = gone
        .into_iter()
        .partition(|finding| standing(finding, before, after) == Some(Standing::Unsettled));

    if !appeared.is_empty()
        || !resolved.is_empty()
        || !unsettled.is_empty()
        || !reassessed.is_empty()
    {
        changes.push(PortChange::Findings {
            appeared,
            resolved,
            unsettled,
            reassessed,
        });
    }

    changes
}

/// Where the current account of an endpoint, `after`, leaves a claim the
/// baseline's account, `before`, carried, or `None` where the claim is not
/// one drawn from evidence either record holds.
///
/// A claim drawn from the TLS handshake asks the current record's security; a
/// scan that made no enumeration is treated as an empty one. See
/// [`Security::standing`].
///
/// A vulnerability correlation asks [`correlation_standing`].
fn standing(finding: &Finding, before: &Port, after: &Port) -> Option<Standing> {
    if finding.is_correlation() {
        return correlation_standing(finding, before.service()?, after.service());
    }
    let silent = Security::new();
    let now = after.security().unwrap_or(&silent);
    now.standing(finding, before.security()?)
}

/// Where the service `now` identified leaves a correlation `basis`'s
/// identification drew, or `None` where `basis` carries none of the
/// identifiers the claim names and so is not what the claim rests on.
///
/// Upheld where `now` carries one of them, and overturned where it says something
/// else runs there: another service, product, or version. That is the upgrade or
/// replacement the comparison exists to see.
///
/// Unsettled where `now` says nothing that tells: no service, a label read off the
/// port number, or the same software named without a version. A scan without
/// service detection, or one that matched a product but not its release, did not
/// say what runs there now. A merge reads it the same way, keeping an older
/// identification's identifiers beside a newer one that states no version.
fn correlation_standing(
    finding: &Finding,
    basis: &Service,
    now: Option<&Service>,
) -> Option<Standing> {
    let backs = |service: &Service| finding.cpes().any(|cpe| service.cpes().contains(cpe));
    if !backs(basis) {
        return None;
    }
    let Some(now) = now.filter(|service| !service.is_inferred()) else {
        return Some(Standing::Unsettled);
    };
    if backs(now) {
        return Some(Standing::Upheld);
    }

    let differs = |stated: Option<&str>, then: Option<&str>| {
        stated.is_some_and(|stated| then.is_none_or(|then| stated != then))
    };
    let contradicts = now.name() != basis.name()
        || differs(now.product(), basis.product())
        || differs(now.version(), basis.version());
    Some(if contradicts {
        Standing::Overturned
    } else {
        Standing::Unsettled
    })
}

/// What moved about the service on an endpoint.
///
/// A service *inferred* from the port number is read as no service. Scanners seed
/// one on every classified port from their own catalogue, so comparing them would
/// report every catalogue difference between tools or releases.
fn service_changes(before: Option<&Service>, after: Option<&Service>) -> Vec<ServiceChange> {
    let before = before.filter(|service| !service.is_inferred());
    let after = after.filter(|service| !service.is_inferred());

    match (before, after) {
        (None, None) => Vec::new(),
        (None, Some(after)) => vec![ServiceChange::Identified(after.clone())],
        (Some(before), None) => vec![ServiceChange::Unidentified(before.clone())],
        (Some(before), Some(after)) => {
            let mut changes = Vec::new();

            if let Some(name) = Change::between(before.name().to_owned(), after.name().to_owned()) {
                changes.push(ServiceChange::Name(name));
            }
            if let Some(product) = optional(before.product(), after.product()) {
                changes.push(ServiceChange::Product(product));
            }
            if let Some(vendor) = optional(before.vendor(), after.vendor()) {
                changes.push(ServiceChange::Vendor(vendor));
            }
            if let Some(version) = optional(before.version(), after.version()) {
                changes.push(ServiceChange::Version(version));
            }
            if let Some(extra) = optional(before.extrainfo(), after.extrainfo()) {
                changes.push(ServiceChange::ExtraInfo(extra));
            }
            if let Some(build) = Change::between(before.build().cloned(), after.build().cloned()) {
                changes.push(ServiceChange::Build(build));
            }

            let (gained, lost) = set_change(
                before.cpes().iter().map(|cpe| cpe.to_string()),
                after.cpes().iter().map(|cpe| cpe.to_string()),
            );
            if !gained.is_empty() || !lost.is_empty() {
                changes.push(ServiceChange::Cpes { gained, lost });
            }

            changes
        }
    }
}

/// What moved about the transport security on an endpoint.
fn security_changes(
    before: Option<&Security>,
    after: Option<&Security>,
    clocks: &Clocks,
) -> Vec<SecurityChange> {
    let mut changes = Vec::new();

    let before_version = before.and_then(Security::tls_version);
    let after_version = after.and_then(Security::tls_version);
    if let Some(version) = optional(before_version, after_version) {
        changes.push(SecurityChange::TlsVersion(version));
    }

    let before_cipher = before.and_then(Security::cipher_suite);
    let after_cipher = after.and_then(Security::cipher_suite);
    if let Some(cipher) = optional(before_cipher, after_cipher) {
        changes.push(SecurityChange::CipherSuite(cipher));
    }

    let (gained, lost) = set_change(
        before
            .map(Security::alpn)
            .unwrap_or_default()
            .iter()
            .map(|p| p.to_string()),
        after
            .map(Security::alpn)
            .unwrap_or_default()
            .iter()
            .map(|p| p.to_string()),
    );
    if !gained.is_empty() || !lost.is_empty() {
        changes.push(SecurityChange::Alpn { gained, lost });
    }

    changes.extend(
        certificate_changes(before, after, clocks)
            .into_iter()
            .map(SecurityChange::Certificate),
    );

    changes
}

/// What moved about the certificate, including the expiry crossings that happen to
/// a certificate nobody touched.
fn certificate_changes(
    before: Option<&Security>,
    after: Option<&Security>,
    clocks: &Clocks,
) -> Vec<CertificateChange> {
    let before_cert = before.and_then(Security::certificate);
    let after_cert = after.and_then(Security::certificate);

    let mut changes = Vec::new();

    match (before_cert, after_cert) {
        (None, None) => return changes,
        (None, Some(after)) => changes.push(CertificateChange::Presented(after.clone())),
        (Some(before), None) => {
            changes.push(CertificateChange::Withdrawn(before.clone()));
            return changes;
        }
        (Some(before), Some(after)) => {
            if before.fingerprint_sha256() != after.fingerprint_sha256() {
                changes.push(CertificateChange::Rotated {
                    before: Box::new(before.clone()),
                    after: Box::new(after.clone()),
                });
            }
        }
    }

    // The standing of one certificate at two moments: where the certificate
    // presented now stood when the baseline ran. A certificate the baseline was
    // not shown stood nowhere, so a rotation onto one that is itself expiring
    // still reports the expiry.
    let same_certificate = matches!(
        (before_cert, after_cert),
        (Some(before), Some(after))
            if before.fingerprint_sha256() == after.fingerprint_sha256()
    );
    let was = if same_certificate {
        validity(after, clocks.expiry_threshold, clocks.baseline)
    } else {
        Validity::Absent
    };
    let is = validity(after, clocks.expiry_threshold, clocks.current);

    if let Some(certificate) = after_cert {
        match is {
            Validity::Expiring if was != Validity::Expiring => {
                let remaining = certificate
                    .validity_end()
                    .duration_since(clocks.current)
                    .unwrap_or_default();
                changes.push(CertificateChange::Expiring {
                    certificate: Box::new(certificate.clone()),
                    remaining,
                });
            }
            Validity::Expired if was != Validity::Expired => {
                let since = clocks
                    .current
                    .duration_since(certificate.validity_end())
                    .unwrap_or_default();
                changes.push(CertificateChange::Expired {
                    certificate: Box::new(certificate.clone()),
                    since,
                });
            }
            _ => {}
        }
    }

    changes
}

/// Where a certificate stands at `at`.
fn validity(security: Option<&Security>, threshold: Duration, at: SystemTime) -> Validity {
    let Some(security) = security else {
        return Validity::Absent;
    };
    let Some(certificate) = security.certificate() else {
        return Validity::Absent;
    };

    // `is_cert_expiring_at` checks the bounds again; they are read here only to
    // tell `NotYetValid` and `Expired` apart.
    if at < certificate.validity_start() {
        Validity::NotYetValid
    } else if at > certificate.validity_end() {
        Validity::Expired
    } else if security.is_cert_expiring_at(threshold, at) {
        Validity::Expiring
    } else {
        Validity::Valid
    }
}

/// A change between two optional strings, owned so the diff outlives the reports
/// it was taken from.
fn optional(before: Option<&str>, after: Option<&str>) -> Option<Change<Option<String>>> {
    Change::between(before.map(str::to_owned), after.map(str::to_owned))
}

/// What one set gained and lost against another, both ascending.
fn set_change(
    before: impl Iterator<Item = String>,
    after: impl Iterator<Item = String>,
) -> (Vec<String>, Vec<String>) {
    let before: std::collections::BTreeSet<String> = before.collect();
    let after: std::collections::BTreeSet<String> = after.collect();

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
    use super::*;
    use crate::model::confidence::Confidence;
    use crate::model::finding::{DetectionClass, DetectionId, Severity, Version};
    use crate::model::tls::{
        CipherSuite, Interruption, TlsSupport, TlsVersion, UnfinishedVersion, VersionSupport,
    };

    fn clocks() -> Clocks {
        Clocks {
            baseline: SystemTime::UNIX_EPOCH,
            current: SystemTime::UNIX_EPOCH,
            expiry_threshold: Duration::from_secs(30 * 24 * 60 * 60),
        }
    }

    fn port(state: PortState) -> Port {
        Port::new(443, Protocol::Tcp, state)
    }

    fn finding(title: &str) -> Finding {
        Finding::new(
            DetectionId::new("audit", Version::new(1, 0, 0), "hash").expect("a detection id"),
            title,
            Severity::High,
            Confidence::Certain,
            DetectionClass::Passive,
        )
        .expect("a titled finding")
    }

    /// A findings change's four lists: appeared, resolved, unsettled and
    /// reassessed.
    type Moved<'a> = (
        &'a [Finding],
        &'a [Finding],
        &'a [Finding],
        &'a [Reassessment],
    );

    fn findings_change(changes: &[PortChange]) -> Option<Moved<'_>> {
        changes.iter().find_map(|change| match change {
            PortChange::Findings {
                appeared,
                resolved,
                unsettled,
                reassessed,
            } => Some((
                appeared.as_slice(),
                resolved.as_slice(),
                unsettled.as_slice(),
                reassessed.as_slice(),
            )),
            _ => None,
        })
    }

    #[test]
    fn an_endpoint_that_did_not_move_reports_nothing() {
        let before = port(PortState::Open);
        let after = port(PortState::Open);
        assert!(changes_between(Some(&before), Some(&after), &clocks()).is_empty());
    }

    #[test]
    fn a_state_change_is_reported() {
        let before = port(PortState::Open);
        let after = port(PortState::Closed);

        let changes = changes_between(Some(&before), Some(&after), &clocks());
        assert!(changes.iter().any(|change| matches!(
            change,
            PortChange::State(state)
                if state.before == PortState::Open && state.after == PortState::Closed
        )));
    }

    /// A finding arriving on an endpoint is a change, as on a host.
    #[test]
    fn a_finding_that_appeared_on_the_endpoint_is_reported() {
        let before = port(PortState::Open);
        let mut after = port(PortState::Open);
        after.add_finding(finding("Weak cipher"));

        let changes = changes_between(Some(&before), Some(&after), &clocks());
        let (appeared, resolved, _, _) = findings_change(&changes).expect("a findings change");
        assert_eq!(appeared.len(), 1);
        assert_eq!(appeared[0].title(), "Weak cipher");
        assert!(resolved.is_empty());
    }

    #[test]
    fn a_finding_that_went_away_from_the_endpoint_is_reported_as_resolved() {
        let mut before = port(PortState::Open);
        before.add_finding(finding("Weak cipher"));
        let after = port(PortState::Open);

        let changes = changes_between(Some(&before), Some(&after), &clocks());
        let (appeared, resolved, _, _) = findings_change(&changes).expect("a findings change");
        assert!(appeared.is_empty());
        assert_eq!(resolved.len(), 1);
    }

    /// An endpoint enumerated as `support` says, carrying the findings drawn
    /// from it, as a scan records one.
    fn enumerated(support: TlsSupport) -> Port {
        let findings = support.findings();
        let mut port = port(PortState::Open).with_security(Security::new().with_support(support));
        for finding in findings {
            port.add_finding(finding);
        }
        port
    }

    /// TLS 1.0 accepted under AES-128-CBC with RSA key exchange, walked to the
    /// end.
    fn ten_accepted() -> TlsSupport {
        TlsSupport::new().accepting(VersionSupport::new(
            TlsVersion::Tls10,
            vec![CipherSuite::from_code(0x002F).expect("a registered suite")],
            vec![],
        ))
    }

    fn titles(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(Finding::title).collect()
    }

    /// A walk the current scan did not finish settled nothing the baseline's
    /// claim rests on, so the claim's absence is not a fix. A scan whose budget
    /// ran out during the TLS 1.0 walk must not report TLS 1.0 switched off.
    #[test]
    fn a_finding_a_cut_short_walk_did_not_get_back_to_is_not_resolved() {
        let before = enumerated(ten_accepted());
        let after = enumerated(TlsSupport::new().leaving_unfinished(UnfinishedVersion::new(
            TlsVersion::Tls10,
            Interruption::Stopped,
        )));
        assert!(
            titles(&before.findings().cloned().collect::<Vec<_>>())
                .contains(&"TLSv1.0 is still accepted"),
            "the baseline's walk draws the claim this is about"
        );

        let changes = changes_between(Some(&before), Some(&after), &clocks());
        let (_, resolved, unsettled, _) = findings_change(&changes).expect("a findings change");
        assert!(
            resolved.is_empty(),
            "a walk that never finished reported {:?} resolved",
            titles(resolved)
        );
        assert_eq!(
            titles(unsettled),
            titles(&before.findings().cloned().collect::<Vec<_>>()),
            "every claim the baseline drew from TLS 1.0 is said to be unsettled"
        );
    }

    /// The counterpart: a walk that finished and found TLS 1.0 refused is the
    /// fix.
    #[test]
    fn a_finding_a_finished_walk_refuted_is_resolved() {
        let before = enumerated(ten_accepted());
        let after = enumerated(TlsSupport::new().accepting(VersionSupport::new(
            TlsVersion::Tls13,
            vec![CipherSuite::from_code(0x1301).expect("a registered suite")],
            vec![],
        )));

        let changes = changes_between(Some(&before), Some(&after), &clocks());
        let (_, resolved, unsettled, _) = findings_change(&changes).expect("a findings change");
        assert!(unsettled.is_empty(), "{:?}", titles(unsettled));
        assert!(titles(resolved).contains(&"TLSv1.0 is still accepted"));
    }

    /// An endpoint that completed a handshake and was shown a self-signed
    /// certificate with `fingerprint`, carrying the posture findings the scan
    /// draws from it.
    fn presenting(fingerprint: &str) -> Port {
        let certificate = CertificateInfo::new(
            "www.example.test",
            "www.example.test",
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH + Duration::from_secs(365 * 24 * 60 * 60),
            fingerprint,
        )
        .with_public_key("RSA", 2048);
        let findings = certificate.findings(SystemTime::UNIX_EPOCH);
        let mut port = port(PortState::Open).with_security(
            Security::new()
                .with_tls_version("TLSv1.3")
                .with_certificate(certificate),
        );
        for finding in findings {
            port.add_finding(finding);
        }
        port
    }

    /// A handshake the current scan did not complete settled nothing about the
    /// certificate a posture claim rests on, so the claim's absence is not a
    /// fix. The service pass records no security for an endpoint whose handshake
    /// failed, and no certificate for one whose leaf would not parse.
    #[test]
    fn a_posture_finding_the_current_scan_saw_no_certificate_for_is_not_resolved() {
        let before = presenting("aaaa");
        let unparsed =
            port(PortState::Open).with_security(Security::new().with_tls_version("TLSv1.3"));
        assert_eq!(
            titles(&before.findings().cloned().collect::<Vec<_>>()),
            ["TLS certificate is self-signed"],
            "the baseline's certificate draws the claim this is about"
        );

        for after in [port(PortState::Open), unparsed] {
            let changes = changes_between(Some(&before), Some(&after), &clocks());
            assert!(
                changes.iter().any(|change| matches!(
                    change,
                    PortChange::Security(SecurityChange::Certificate(
                        CertificateChange::Withdrawn(_)
                    ))
                )),
                "the certificate's absence is still reported as such"
            );
            let (_, resolved, unsettled, _) = findings_change(&changes).expect("a findings change");
            assert!(
                resolved.is_empty(),
                "a scan shown no certificate reported {:?} resolved",
                titles(resolved)
            );
            assert_eq!(titles(unsettled), ["TLS certificate is self-signed"]);
        }
    }

    /// The counterpart: a scan shown a different certificate settled the claim,
    /// since the posture belonged to a certificate the endpoint stopped
    /// presenting.
    #[test]
    fn a_posture_finding_the_current_scan_was_shown_another_certificate_for_is_resolved() {
        let before = presenting("aaaa");
        let after = port(PortState::Open).with_security(
            Security::new()
                .with_tls_version("TLSv1.3")
                .with_certificate(
                    CertificateInfo::new(
                        "www.example.test",
                        "Example CA",
                        SystemTime::UNIX_EPOCH,
                        SystemTime::UNIX_EPOCH + Duration::from_secs(365 * 24 * 60 * 60),
                        "bbbb",
                    )
                    .with_public_key("RSA", 2048),
                ),
        );

        let changes = changes_between(Some(&before), Some(&after), &clocks());
        let (_, resolved, unsettled, _) = findings_change(&changes).expect("a findings change");
        assert!(unsettled.is_empty(), "{:?}", titles(unsettled));
        assert_eq!(titles(resolved), ["TLS certificate is self-signed"]);
    }

    /// An endpoint identified as Apache httpd 2.4.49, carrying the CVE
    /// correlation drawn from its CPE.
    fn correlated() -> Port {
        const CPE: &str = "cpe:/a:apache:http_server:2.4.49";
        let mut port = port(PortState::Open);
        port.set_service(
            Service::new("http", 90)
                .with_product("Apache httpd")
                .with_version("2.4.49")
                .with_cpe(CPE),
        );
        port.add_finding(
            finding("Apache httpd 2.4.49: path traversal")
                .with_reference(crate::model::finding::Reference::Cve(
                    "CVE-2021-41773".into(),
                ))
                .with_cpe(CPE),
        );
        port
    }

    /// A correlation is not resolved by a scan that ran without service
    /// detection, labelled the port by its number alone, or named the software
    /// without a version: none of them said what runs there now.
    #[test]
    fn a_correlation_the_current_scan_identified_nothing_to_test_is_not_resolved() {
        let before = correlated();

        let mut labelled = port(PortState::Open);
        labelled.set_service(Service::new("http", 0));
        let mut unversioned = port(PortState::Open);
        unversioned.set_service(Service::new("http", 90).with_product("Apache httpd"));

        for (case, after) in [
            ("no service at all", port(PortState::Open)),
            ("a port-number label", labelled),
            ("the same software without a version", unversioned),
        ] {
            let changes = changes_between(Some(&before), Some(&after), &clocks());
            let (_, resolved, unsettled, _) = findings_change(&changes).expect("a findings change");
            assert!(
                resolved.is_empty(),
                "{case}: reported {:?} resolved",
                titles(resolved)
            );
            assert_eq!(
                titles(unsettled),
                ["Apache httpd 2.4.49: path traversal"],
                "{case}"
            );
        }
    }

    /// The counterpart: a newer identification without the identifier the claim
    /// was drawn from settles it, as an upgrade.
    #[test]
    fn a_correlation_a_newer_identification_no_longer_backs_is_resolved() {
        let before = correlated();
        let mut upgraded = port(PortState::Open);
        upgraded.set_service(
            Service::new("http", 90)
                .with_product("Apache httpd")
                .with_version("2.4.58")
                .with_cpe("cpe:/a:apache:http_server:2.4.58"),
        );
        let mut replaced = port(PortState::Open);
        replaced.set_service(Service::new("http", 90).with_product("nginx"));

        for (case, after) in [("upgraded", upgraded), ("replaced", replaced)] {
            let changes = changes_between(Some(&before), Some(&after), &clocks());
            let (_, resolved, unsettled, _) = findings_change(&changes).expect("a findings change");
            assert!(unsettled.is_empty(), "{case}: {:?}", titles(unsettled));
            assert_eq!(
                titles(resolved),
                ["Apache httpd 2.4.49: path traversal"],
                "{case}"
            );
        }
    }

    /// One side missing is an endpoint that appeared or went away, which the
    /// delta's presence already says, so no field changes are listed.
    #[test]
    fn an_endpoint_present_on_one_side_only_reports_no_field_changes() {
        let only = port(PortState::Open);
        assert!(changes_between(Some(&only), None, &clocks()).is_empty());
        assert!(changes_between(None, Some(&only), &clocks()).is_empty());
    }
}
