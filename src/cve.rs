// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Known vulnerabilities, matched to what a scan found
//!
//! A report-level pass that reads the CPE a service identification produced and,
//! where a known vulnerability names the same software at an affected version,
//! records a [`Finding`] on the port. It answers the question most people run a
//! scan to answer — not "what is listening" but "what is listening that I need to
//! fix" — from data the engine already produces, with no probe of its own.
//!
//! ## The one number two ways
//!
//! Every finding this pass records is [`Confidence::Probable`], never certain,
//! and the reason is the case the [two-axis finding](crate::model::finding) was
//! built for: a distribution can backport a security fix without moving the
//! version string, so a version-matched vulnerability is genuinely
//! [`Critical`](crate::model::finding::Severity::Critical) *and* genuinely
//! unsure. The severity says how bad it is if true; the confidence says the match
//! is a version string, not a confirmed exploit. A report that fused the two
//! could not say both.
//!
//! ## The dataset
//!
//! The matches come from an embedded seed — a hand-picked set of well-known,
//! network-reachable vulnerabilities in `assets/cve/seed.toml`. It is a starting
//! corpus, not a complete one: the full CISA KEV catalogue is meant to compile in
//! here the way the fingerprint corpus does, once its data is on hand. Each entry
//! matches a service CPE whose vendor and product equal its own and whose version
//! satisfies a small predicate grammar (`<`, `<=`, `>`, `>=`, `==`, joined by
//! `,`, or `*` for any).
//!
//! ## How it runs
//!
//! [`correlate`] takes a finished [`Host`] and records findings on its ports. It
//! is a caller's to run — the library performs no pass a caller did not ask for —
//! and it is idempotent, because a finding deduplicates by claim, so a second run
//! corroborates rather than doubles.

use std::cmp::Ordering;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::fingerprint::Confidence;
use crate::model::finding::{DetectionClass, DetectionId, Excerpt, Finding, Reference, Version};
use crate::model::host::Host;
use crate::model::port::Protocol;
use crate::record::wire;
use crate::version::version_cmp;

/// The reserved identity the engine's built-in correlator stamps on every finding
/// it produces, so a report can say exactly what concluded a vulnerability. A
/// third-party detection may not claim the `zond:` namespace.
const CORRELATOR_ID: &str = "zond:cve-kev";

/// The seed dataset's version, carried on every finding for provenance.
const DATASET_VERSION: Version = Version::new(0, 1, 0);

/// A content label for the dataset. The full, build-compiled catalogue will carry
/// a real content hash; the seed names itself.
const DATASET_HASH: &str = "seed";

/// Correlates a finished host's services against the known-vulnerability dataset,
/// recording a [`Finding`] on each port whose software an entry matches.
///
/// Reads each port's service CPE, matches vendor, product and version against the
/// dataset, and hands each match back to the port it concerns. Idempotent: a
/// finding deduplicates by claim, so a re-run corroborates rather than doubles.
pub fn correlate(host: &mut Host) {
    let dataset = dataset();

    // Collect first, mutate second: the read borrows the host's ports and the
    // write needs them mutably, so the two cannot overlap.
    let hits: Vec<(u16, Protocol, Finding)> = host
        .ports()
        .flat_map(|port| {
            let number = port.number();
            let protocol = port.protocol();
            port.service()
                .into_iter()
                .flat_map(|service| service.cpes())
                .flat_map(|cpe| dataset.findings_for(cpe))
                .map(move |finding| (number, protocol, finding))
                .collect::<Vec<_>>()
        })
        .collect();

    for (number, protocol, finding) in hits {
        host.add_port_finding(number, protocol, finding);
    }
}

/// The embedded seed, parsed once on first use.
fn dataset() -> &'static Dataset {
    static DATASET: OnceLock<Dataset> = OnceLock::new();
    DATASET.get_or_init(|| {
        toml::from_str(include_str!("../assets/cve/seed.toml"))
            .expect("the embedded CVE seed is valid TOML")
    })
}

/// The vulnerability dataset, as the seed file is written.
#[derive(Debug, Clone, Default, Deserialize)]
struct Dataset {
    #[serde(default)]
    vulnerability: Vec<Vulnerability>,
}

impl Dataset {
    /// Every finding this dataset has for a service CPE.
    fn findings_for(&self, cpe: &str) -> Vec<Finding> {
        let Some(parsed) = Cpe::parse(cpe) else {
            return Vec::new();
        };
        self.vulnerability
            .iter()
            .filter(|vulnerability| vulnerability.matches(&parsed))
            .filter_map(|vulnerability| vulnerability.to_finding(cpe))
            .collect()
    }
}

/// One known vulnerability, keyed by the CPE identity it affects.
#[derive(Debug, Clone, Deserialize)]
struct Vulnerability {
    cve: String,
    title: String,
    severity: String,
    vendor: String,
    product: String,
    affected: String,
    #[serde(default)]
    cwe: Option<u32>,
    #[serde(default)]
    remediation: Option<String>,
}

impl Vulnerability {
    /// Whether this vulnerability names `cpe`'s software at an affected version.
    fn matches(&self, cpe: &Cpe) -> bool {
        self.vendor.eq_ignore_ascii_case(&cpe.vendor)
            && self.product.eq_ignore_ascii_case(&cpe.product)
            && version_matches(&cpe.version, &self.affected)
    }

    /// The finding this vulnerability produces for a matched `cpe`, or [`None`]
    /// if the entry is malformed — an unknown severity, a bad CVE identifier.
    fn to_finding(&self, cpe: &str) -> Option<Finding> {
        let severity = wire::severity(&self.severity)?;
        let detection = DetectionId::new(CORRELATOR_ID, DATASET_VERSION, DATASET_HASH).ok()?;

        let mut finding = Finding::new(
            detection,
            self.title.clone(),
            severity,
            Confidence::Probable,
            DetectionClass::Passive,
        )
        .ok()?
        .with_reference(Reference::cve(&self.cve)?)
        .with_excerpt(Excerpt::new(format!(
            "{cpe} matches {} {} {}",
            self.vendor, self.product, self.affected
        )));

        if let Some(cwe) = self.cwe {
            finding = finding.with_reference(Reference::cwe(cwe));
        }
        if let Some(remediation) = &self.remediation {
            finding = finding.with_remediation(remediation.clone());
        }
        Some(finding)
    }
}

/// A CPE split into the three fields the correlator matches on, lower-cased.
struct Cpe {
    vendor: String,
    product: String,
    version: String,
}

impl Cpe {
    /// Parses the vendor, product and version out of a CPE in either the URI form
    /// (`cpe:/a:vendor:product:version`) or the 2.3 form
    /// (`cpe:2.3:a:vendor:product:version:…`). [`None`] for anything else.
    fn parse(cpe: &str) -> Option<Self> {
        let body = cpe
            .strip_prefix("cpe:/")
            .or_else(|| cpe.strip_prefix("cpe:2.3:"))?;
        let mut fields = body.split(':');
        let _part = fields.next()?; // a / o / h — application, os, hardware
        let vendor = fields.next()?;
        let product = fields.next()?;
        let version = fields.next().unwrap_or("");
        Some(Self {
            vendor: vendor.to_ascii_lowercase(),
            product: product.to_ascii_lowercase(),
            version: version.to_string(),
        })
    }
}

/// Whether `version` satisfies `predicate` — a comma-joined list of
/// `<op> <version>` clauses, all of which must hold, or `*` for any version.
///
/// A version that was never learned (`-`, `*`, or empty) satisfies only `*`: a
/// bounded clause cannot be confirmed against a version nobody read.
fn version_matches(version: &str, predicate: &str) -> bool {
    let predicate = predicate.trim();
    if predicate == "*" {
        return true;
    }
    if version.is_empty() || version == "-" || version == "*" {
        return false;
    }
    predicate
        .split(',')
        .all(|clause| clause_holds(version, clause.trim()))
}

/// Whether `version` satisfies one `<op> <bound>` clause. A clause with no
/// operator is an exact-version match.
fn clause_holds(version: &str, clause: &str) -> bool {
    let (op, bound) = ["<=", ">=", "==", "<", ">", "="]
        .into_iter()
        .find_map(|op| clause.strip_prefix(op).map(|rest| (op, rest.trim())))
        .unwrap_or(("==", clause));

    let ordering = version_cmp(version, bound);
    match op {
        "<" => ordering == Ordering::Less,
        "<=" => ordering != Ordering::Greater,
        ">" => ordering == Ordering::Greater,
        ">=" => ordering != Ordering::Less,
        "==" | "=" => ordering == Ordering::Equal,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::finding::Severity;

    #[test]
    fn version_predicates_hold_and_fail_at_the_boundaries() {
        assert!(version_matches("2.4.49", "== 2.4.49"));
        assert!(!version_matches("2.4.50", "== 2.4.49"));

        assert!(version_matches("9.6", ">= 8.5, < 9.8"));
        assert!(!version_matches("9.8", ">= 8.5, < 9.8")); // the fixed release is not affected
        assert!(!version_matches("8.4", ">= 8.5, < 9.8"));

        assert!(version_matches("anything", "*"));
        // A version nobody read cannot confirm a bounded clause.
        assert!(!version_matches("", ">= 1.0"));
        assert!(!version_matches("-", ">= 1.0"));
    }

    #[test]
    fn the_embedded_seed_parses_and_is_non_empty() {
        assert!(!dataset().vulnerability.is_empty());
    }

    #[test]
    fn a_matching_cpe_yields_a_probable_finding_a_safe_version_does_not() {
        // Apache 2.4.49 is the vulnerable build; 2.4.51 carries the fix.
        let hits = dataset().findings_for("cpe:/a:apache:http_server:2.4.49");
        assert_eq!(hits.len(), 1);
        let finding = &hits[0];
        assert_eq!(finding.severity(), Severity::Critical);
        assert_eq!(
            finding.confidence(),
            Confidence::Probable,
            "a version match is potentially affected, unverified — never certain"
        );
        assert_eq!(finding.detection().id(), "zond:cve-kev");
        assert!(
            finding
                .references()
                .any(|r| matches!(r, Reference::Cve(id) if id == "CVE-2021-41773"))
        );

        assert!(
            dataset()
                .findings_for("cpe:/a:apache:http_server:2.4.51")
                .is_empty(),
            "the fixed version is not reported"
        );
        assert!(
            dataset()
                .findings_for("cpe:/a:nginx:nginx:1.24.0")
                .is_empty(),
            "an unrelated product does not match"
        );

        // The curated identities fire against the shapes the corpus actually
        // emits: OpenSSH banners carry a `p` suffix, and vsftpd is an exact match.
        assert_eq!(
            dataset()
                .findings_for("cpe:/a:openbsd:openssh:9.6p1")
                .len(),
            1
        );
        assert!(
            dataset()
                .findings_for("cpe:/a:openbsd:openssh:9.8p1")
                .is_empty(),
            "the fixed OpenSSH release is not reported"
        );
        assert_eq!(
            dataset()
                .findings_for("cpe:/a:vsftpd_project:vsftpd:2.3.4")
                .len(),
            1
        );
        assert!(
            dataset()
                .findings_for("cpe:/a:vsftpd_project:vsftpd:3.0.5")
                .is_empty()
        );
    }

    #[test]
    fn correlate_records_a_finding_on_the_matching_port_and_does_not_double() {
        use crate::model::host::Host;
        use crate::model::port::{Port, PortState, Service};
        use std::net::{IpAddr, Ipv4Addr};

        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let service = Service::new("http", 90).with_cpe("cpe:/a:apache:http_server:2.4.49");
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Open).with_service(service));

        correlate(&mut host);
        let port = host.ports().find(|p| p.number() == 80).unwrap();
        assert_eq!(port.findings().count(), 1, "the vulnerable service got one");

        // A second pass corroborates the same claim rather than adding a second.
        correlate(&mut host);
        let port = host.ports().find(|p| p.number() == 80).unwrap();
        assert_eq!(port.findings().count(), 1);
    }
}
