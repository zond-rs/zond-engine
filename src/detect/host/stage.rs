// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Drawing host-level findings
//!
//! The host detection stage, the counterpart to the port-level [flow] and
//! [compute] stages. It runs once per host over what the port scan left behind, the
//! numbers of its open ports and the services named on them, and draws a
//! [`Finding`] for each detection whose gate fits. It sends nothing: a host
//! correlation reads only facts the scan already holds.
//!
//! The host's [`Exposure`] is one of those facts, and this tier is the one that
//! reads it most. A correlation names a shape rather than a flaw, and a shape is
//! read differently depending on who can see it, so a detection here often states
//! a severity per rung; see
//! [`SeveritySpec`](crate::detect::authoring::SeveritySpec).
//!
//! [flow]: crate::detect::flow::stage
//! [compute]: crate::detect::compute::stage

use std::collections::BTreeSet;

use crate::model::confidence::Confidence;
use crate::model::finding::{DetectionClass, DetectionId, Excerpt, Finding, Version};
use crate::model::ip::Exposure;
use crate::record::wire;

use crate::detect::manifest::GroupSpec;

use super::schema::{FindingSpec, HostDetection, HostManifest};

/// A host detection compiled and ready to run: its authoring form and the content
/// hash of the file it came from, stamped on the findings it draws as provenance.
pub struct LoadedHostDetection {
    detection: HostDetection,
    content_hash: String,
}

impl LoadedHostDetection {
    /// A loaded host detection from its parts.
    pub fn new(detection: HostDetection, content_hash: impl Into<String>) -> Self {
        Self {
            detection,
            content_hash: content_hash.into(),
        }
    }

    /// The detection's author-chosen id. The scan path reads the id through the
    /// finding's provenance instead; this is for a corpus listing and for tests
    /// looking a shipped detection up by name.
    pub(crate) fn id(&self) -> &str {
        &self.detection.detection.id
    }

    /// The one-line human name a report prints for it.
    pub(crate) fn title(&self) -> &str {
        &self.detection.detection.title
    }

    /// Its own version, as the detection declares it.
    pub(crate) fn version(&self) -> &str {
        &self.detection.detection.version
    }

    /// The ports its gate needs open.
    pub(crate) fn ports_open(&self) -> &[u16] {
        &self.detection.detection.host.ports_open
    }

    /// The services its gate needs identified.
    pub(crate) fn services(&self) -> &[String] {
        &self.detection.detection.host.services
    }

    /// The SHA-256 of its source, its provenance.
    pub(crate) fn content_hash(&self) -> &str {
        &self.content_hash
    }
}

/// Runs the host detections over one host, returning the findings whose gate fit.
///
/// `open_ports` and `services` are what the host presents after the port scan: the
/// numbers of its open ports and the names of the services identified on them. A
/// detection whose gate fits draws each of its findings; one whose gate does not is
/// skipped, having concluded nothing.
///
/// `exposure` grades the findings that stated a severity per rung. It gates
/// nothing: a correlation that fits is a correlation that fits wherever the host
/// sits, and suppressing it would leave a reader unable to tell a shape that was
/// looked for and absent from one that was never reported.
pub(crate) fn detect_host(
    detections: &[LoadedHostDetection],
    open_ports: &BTreeSet<u16>,
    services: &BTreeSet<&str>,
    exposure: Exposure,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for loaded in detections {
        let manifest = &loaded.detection.detection;
        if !manifest.host.matches(open_ports, services) {
            continue;
        }

        let version = manifest.version.parse().unwrap_or(Version::new(0, 0, 0));
        let Ok(id) = DetectionId::new(manifest.id.clone(), version, &loaded.content_hash) else {
            continue;
        };
        for spec in &loaded.detection.finding {
            if let Some(finding) = build_finding(spec, &id, manifest, exposure) {
                findings.push(finding);
            }
        }
    }
    findings
}

/// Builds one model [`Finding`] from a spec. Provenance and class are the
/// detection's: a host correlation reads only what the scan already gathered, so
/// it declares [`Derived`](super::super::manifest::Class::Derived) and runs at
/// [`DetectionClass::Passive`], which is what a finding records — the
/// intrusiveness it ran at, rather than where its conclusion came from.
fn build_finding(
    spec: &FindingSpec,
    id: &DetectionId,
    manifest: &HostManifest,
    exposure: Exposure,
) -> Option<Finding> {
    let title = spec
        .title
        .as_deref()
        .filter(|title| !title.trim().is_empty())
        .or_else(|| Some(spec.summary.as_str()).filter(|summary| !summary.trim().is_empty()))
        .unwrap_or(manifest.title.as_str())
        .to_string();
    let confidence = spec
        .confidence
        .as_deref()
        .and_then(wire::confidence)
        .unwrap_or(Confidence::Certain);

    let mut finding = Finding::new(
        id.clone(),
        title,
        spec.severity.into_model_at(exposure),
        confidence,
        DetectionClass::Passive,
    )
    .ok()?;

    if let Some(detail) = spec.detail.as_deref().filter(|d| !d.trim().is_empty()) {
        finding = finding.with_excerpt(Excerpt::new(detail.to_owned()));
    }
    for reference in &spec.references {
        if let Some(reference) = reference.to_model() {
            finding = finding.with_reference(reference);
        }
    }
    if let Some(remediation) = spec.remediation.as_deref().filter(|r| !r.trim().is_empty()) {
        finding = finding.with_remediation(remediation.to_owned());
    }
    // From the manifest, for the reason the flow tier takes it from there: which
    // detections cover a weakness together is not a thing one finding of one of
    // them can say.
    if let Some(group) = manifest.group.as_ref().and_then(GroupSpec::to_model) {
        finding = finding.with_group(group);
    }

    Some(finding)
}

#[cfg(test)]
mod tests {
    use super::super::authoring::{Severity, SeverityByExposure, SeveritySpec};
    use super::super::schema::{FindingSpec, HostGate, HostManifest};
    use super::*;
    use crate::model::finding::Severity as ModelSeverity;

    /// The shipped domain-controller shape, with whatever severity a test needs
    /// to grade.
    fn domain_controller(severity: SeveritySpec) -> LoadedHostDetection {
        LoadedHostDetection::new(
            HostDetection {
                detection: HostManifest {
                    group: None,
                    id: "domain-controller".to_string(),
                    version: "1.0.0".to_string(),
                    title: "Windows domain controller".to_string(),
                    host: HostGate {
                        ports_open: vec![88, 389, 445],
                        services: Vec::new(),
                    },
                },
                finding: vec![FindingSpec {
                    severity,
                    summary: "Kerberos, LDAP and SMB open together: a domain controller"
                        .to_string(),
                    title: None,
                    detail: None,
                    confidence: None,
                    references: Vec::new(),
                    remediation: None,
                }],
            },
            "hash",
        )
    }

    #[test]
    fn a_host_presenting_every_gate_port_draws_the_finding() {
        // 88, 389 and 445 open, among other ports: the gate fits.
        let open: BTreeSet<u16> = [53, 88, 135, 389, 445].into_iter().collect();
        let findings = detect_host(
            &[domain_controller(SeveritySpec::Flat(Severity::Info))],
            &open,
            &BTreeSet::new(),
            Exposure::Internet,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detection().id(), "domain-controller");
        assert_eq!(findings[0].severity(), ModelSeverity::Info);
    }

    #[test]
    fn a_host_missing_one_gate_port_draws_nothing() {
        // 445 closed: not a domain controller, whatever else is open.
        let open: BTreeSet<u16> = [88, 389].into_iter().collect();
        let findings = detect_host(
            &[domain_controller(SeveritySpec::Flat(Severity::Info))],
            &open,
            &BTreeSet::new(),
            Exposure::Internet,
        );
        assert!(
            findings.is_empty(),
            "a host missing SMB was still called a domain controller"
        );
    }

    /// A shape stated per rung is graded by the exposure of the address the host
    /// was reached at, which is this tier's whole reason for reading one: the
    /// same three open ports are an incident on a public address and a desktop on
    /// a LAN.
    #[test]
    fn a_severity_stated_per_rung_is_graded_by_the_hosts_exposure() {
        let per_rung = SeveritySpec::PerExposure(SeverityByExposure {
            internet: Severity::High,
            internal: Some(Severity::Info),
            local: None,
        });
        let open: BTreeSet<u16> = [88, 389, 445].into_iter().collect();

        let graded = |exposure| {
            let findings = detect_host(
                &[domain_controller(per_rung)],
                &open,
                &BTreeSet::new(),
                exposure,
            );
            findings[0].severity()
        };

        assert_eq!(graded(Exposure::Internet), ModelSeverity::High);
        assert_eq!(graded(Exposure::Internal), ModelSeverity::Info);
        // `local` was left unstated, so it reads whatever `internal` says.
        assert_eq!(graded(Exposure::Local), ModelSeverity::Info);
    }

    /// The exposure grades a finding and never gates one. A correlation that fits
    /// is reported wherever the host sits, so a reader can tell a shape that was
    /// looked for and found from one that was never reported.
    #[test]
    fn a_correlation_that_fits_is_drawn_at_every_exposure() {
        let open: BTreeSet<u16> = [88, 389, 445].into_iter().collect();
        for exposure in Exposure::ALL {
            let findings = detect_host(
                &[domain_controller(SeveritySpec::Flat(Severity::Info))],
                &open,
                &BTreeSet::new(),
                *exposure,
            );
            assert_eq!(findings.len(), 1, "{}", exposure.label());
        }
    }
}
