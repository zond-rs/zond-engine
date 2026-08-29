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
//! [flow]: crate::detect::flow::stage
//! [compute]: crate::detect::compute::stage

use std::collections::BTreeSet;

use crate::fingerprint::Confidence;
use crate::model::finding::{DetectionClass, DetectionId, Excerpt, Finding, Version};
use crate::record::wire;

use super::schema::{FindingSpec, HostDetection};

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
}

/// Runs the host detections over one host, returning the findings whose gate fit.
///
/// `open_ports` and `services` are what the host presents after the port scan: the
/// numbers of its open ports and the names of the services identified on them. A
/// detection whose gate fits draws each of its findings; one whose gate does not is
/// skipped, having concluded nothing.
pub(crate) fn detect_host(
    detections: &[LoadedHostDetection],
    open_ports: &BTreeSet<u16>,
    services: &BTreeSet<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for loaded in detections {
        let manifest = &loaded.detection.detection;
        if !manifest.host.matches(open_ports, services) {
            continue;
        }

        let version = Version::parse(&manifest.version).unwrap_or(Version::new(0, 0, 0));
        let Ok(id) = DetectionId::new(manifest.id.clone(), version, &loaded.content_hash) else {
            continue;
        };
        for spec in &loaded.detection.finding {
            if let Some(finding) = build_finding(spec, &id, &manifest.title) {
                findings.push(finding);
            }
        }
    }
    findings
}

/// Builds one model [`Finding`] from a spec. Provenance and class are the
/// detection's: a host correlation reads only what the scan already gathered, so it
/// runs at [`DetectionClass::Passive`].
fn build_finding(spec: &FindingSpec, id: &DetectionId, fallback_title: &str) -> Option<Finding> {
    let title = spec
        .title
        .as_deref()
        .filter(|title| !title.trim().is_empty())
        .or_else(|| Some(spec.summary.as_str()).filter(|summary| !summary.trim().is_empty()))
        .unwrap_or(fallback_title)
        .to_string();
    let confidence = spec
        .confidence
        .as_deref()
        .and_then(wire::confidence)
        .unwrap_or(Confidence::Certain);

    let mut finding = Finding::new(
        id.clone(),
        title,
        spec.severity.into_model(),
        confidence,
        DetectionClass::Passive,
    )
    .ok()?;

    if let Some(detail) = spec.detail.as_deref().filter(|d| !d.trim().is_empty()) {
        finding = finding.with_excerpt(Excerpt::new(detail.to_owned()));
    }
    for reference in &spec.references {
        if let Some(reference) = reference.clone().into_model() {
            finding = finding.with_reference(reference);
        }
    }
    if let Some(remediation) = spec.remediation.as_deref().filter(|r| !r.trim().is_empty()) {
        finding = finding.with_remediation(remediation.to_owned());
    }

    Some(finding)
}

#[cfg(test)]
mod tests {
    use super::super::schema::{FindingSpec, HostGate, HostManifest, Severity};
    use super::*;
    use crate::model::finding::Severity as ModelSeverity;

    fn domain_controller() -> LoadedHostDetection {
        LoadedHostDetection::new(
            HostDetection {
                detection: HostManifest {
                    id: "domain-controller".to_string(),
                    version: "1.0.0".to_string(),
                    title: "Windows domain controller".to_string(),
                    host: HostGate {
                        ports_open: vec![88, 389, 445],
                        services: Vec::new(),
                    },
                },
                finding: vec![FindingSpec {
                    severity: Severity::Info,
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
        let findings = detect_host(&[domain_controller()], &open, &BTreeSet::new());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detection().id(), "domain-controller");
        assert_eq!(findings[0].severity(), ModelSeverity::Info);
    }

    #[test]
    fn a_host_missing_one_gate_port_draws_nothing() {
        // 445 closed: not a domain controller, whatever else is open.
        let open: BTreeSet<u16> = [88, 389].into_iter().collect();
        let findings = detect_host(&[domain_controller()], &open, &BTreeSet::new());
        assert!(
            findings.is_empty(),
            "a host missing SMB was still called a domain controller"
        );
    }
}
