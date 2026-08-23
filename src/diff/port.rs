// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What changed about one endpoint
//!
//! A port pairs with a port by number and transport, which needs no policy: 443
//! over TCP is 443 over TCP in both scans. What is left is reporting what moved,
//! and this module holds the vocabulary for it — the state, what is listening,
//! and what it presents at the TLS handshake.
//!
//! ## Only the verdicts
//!
//! A port carries its verdict and the evidence behind it, and only the verdict
//! is compared. [`Discovery`](crate::model::port::Discovery) says which packet
//! settled the state, when it arrived, how long it took and on which interface;
//! none of that is a fact about the network, and a diff carrying it would report
//! a change every time a reply came back on a different interface. The same
//! reasoning excludes a service's confidence score, which measures how sure the
//! fingerprinter is rather than what is running.

use std::time::Duration;
use std::time::SystemTime;

use crate::diff::change::{Change, Coverage, Presence};
use crate::model::port::security::CertificateInfo;
use crate::model::port::{Port, PortState, Protocol, Security, Service};

/// One endpoint, as the two scans hold it.
///
/// The number and transport identify it in both. Everything else is what moved,
/// in [`changes`](Self::changes), with the whole record from each side kept
/// alongside so a consumer rendering the change has the context around it
/// without going back to the reports.
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
    pub fn baseline(&self) -> Option<&Port> {
        self.baseline.as_ref()
    }

    /// The current scan's record, if it has one.
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
    /// Reads the records: an endpoint the baseline has no record for counts,
    /// because a report is the whole of what a scan wrote down. Whether the
    /// baseline looked at all is [`presence`](Self::presence)'s question, and
    /// [`Presence::is_confirmed`] is the test that separates a port that opened
    /// from one nobody had checked.
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
/// `#[non_exhaustive]`: a scan learns to establish more about a port as it
/// learns to speak more protocols, and a consumer matching on this should pay
/// for that with a recompile rather than with a major version.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum PortChange {
    /// The verdict moved. What each state means is
    /// [`PortState`]'s own documentation, and the two are not ordered by how
    /// alarming they are: `Filtered` to `Closed` is a firewall that stopped
    /// dropping probes, not a port that shut.
    State(Change<PortState>),
    /// What is listening changed, or was identified where it was not.
    Service(ServiceChange),
    /// What the endpoint presents at the TLS handshake changed.
    Security(SecurityChange),
}

/// Something that moved about what is listening on an endpoint.
///
/// [`Version`](Self::Version) is the one most monitoring is looking for: a
/// service that moved from 1.18.0 to 1.24.0 is a patch that landed, and one that
/// moved the other way is a rollback worth asking about.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceChange {
    /// Nothing was identified here before, and something is now.
    Identified(Service),
    /// Something was identified here before, and nothing is now. Not the same as
    /// the service being gone: the endpoint may simply not have been asked, which
    /// the phase's
    /// [`service_detection`](crate::scanner::report::ScanSettings::service_detection)
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
/// Identity is the SHA-256 fingerprint, so two certificates are the same one
/// exactly when they are byte for byte the same. That is why there are no
/// field-level variants here: a certificate whose issuer or validity differs is
/// a different certificate, and [`Rotated`](Self::Rotated) is what that is.
///
/// [`Expiring`](Self::Expiring) and [`Expired`](Self::Expired) are the two
/// changes an unchanged certificate can undergo. Nothing about it moved; the
/// clock did, and a threshold was crossed between the two scans. See the module
/// documentation of [`diff`](crate::diff) for which clock is used.
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
    /// The certificate is still valid and now falls inside the expiry threshold,
    /// where at the baseline's clock it did not.
    Expiring {
        /// The certificate now inside the threshold.
        certificate: Box<CertificateInfo>,
        /// How long it has left, at the current scan's clock.
        remaining: Duration,
    },
    /// The certificate is past its validity end, where at the baseline's clock
    /// it was not.
    Expired {
        /// The certificate that lapsed.
        certificate: Box<CertificateInfo>,
        /// How long ago it lapsed, at the current scan's clock.
        since: Duration,
    },
}

/// Where a certificate stands at one moment.
///
/// The five states are exhaustive and ordered by nothing: a comparison reads
/// them as labels, and reports a transition into [`Expiring`](Self::Expiring) or
/// [`Expired`](Self::Expired) because those are the two a person has to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Validity {
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
/// Endpoints that are identical in both scans are left out entirely, so the
/// result is what moved and nothing else.
pub(crate) fn compare(
    baseline: &[&Port],
    current: &[&Port],
    presence: PresenceFor<'_>,
    clocks: &Clocks,
) -> Vec<PortDelta> {
    let mut keys: Vec<(u16, Protocol)> = baseline
        .iter()
        .chain(current.iter())
        .map(|port| (port.number(), port.protocol()))
        .collect();
    keys.sort_unstable();
    keys.dedup();

    let mut deltas = Vec::new();
    for (number, protocol) in keys {
        let before = baseline
            .iter()
            .find(|port| port.number() == number && port.protocol() == protocol)
            .copied();
        let after = current
            .iter()
            .find(|port| port.number() == number && port.protocol() == protocol)
            .copied();

        let (presence, changes) = match (before, after) {
            (Some(_), Some(_)) => (Presence::Both, changes_between(before, after, clocks)),
            (Some(_), None) => (presence.removed(number, protocol), Vec::new()),
            (None, Some(_)) => (presence.added(number, protocol), Vec::new()),
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
/// Asked per endpoint rather than once per host, because a scope names the ports
/// it walked and the answer differs between 443 and 8080 on the same address.
pub(crate) struct PresenceFor<'a> {
    pub(crate) baseline: &'a dyn Fn(u16, Protocol) -> Coverage,
    pub(crate) current: &'a dyn Fn(u16, Protocol) -> Coverage,
}

impl PresenceFor<'_> {
    fn added(&self, number: u16, protocol: Protocol) -> Presence {
        Presence::Added {
            before: (self.baseline)(number, protocol),
        }
    }

    fn removed(&self, number: u16, protocol: Protocol) -> Presence {
        Presence::Removed {
            after: (self.current)(number, protocol),
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

    changes
}

/// What moved about the service on an endpoint.
fn service_changes(before: Option<&Service>, after: Option<&Service>) -> Vec<ServiceChange> {
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

/// What moved about the certificate, including the two changes that happen to a
/// certificate nobody touched.
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

    // The standing of whatever is presented now, against the standing of
    // whatever was presented before. A certificate nobody touched still crosses
    // a threshold when enough time passes between the two scans, and that is the
    // change a renewal queue is built from.
    let was = validity(before, clocks.expiry_threshold, clocks.baseline);
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
