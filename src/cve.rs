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
//! ## The dataset is a parameter
//!
//! Every other corpus in this engine changes when its understanding of the world
//! changes, and shipping it with the release is right. This one changes on
//! somebody else's schedule: the KEV catalogue gains entries weekly, and a
//! scanner whose vulnerability data can only move when the crate is rebuilt
//! reports last release's vulnerabilities however long ago that was.
//!
//! So [`Catalogue`] is a value. [`Catalogue::embedded`] is the one this crate
//! ships and what [`correlate`] uses, and [`Catalogue::read`] takes a caller's
//! own — a refreshed KEV dump, or the internal advisory feed an enterprise
//! already maintains — for [`correlate_with`].
//!
//! A catalogue carries its own identity and version, and every finding it
//! produces is stamped with them, so a report says which dataset concluded what
//! and a reader can tell a finding from the shipped seed apart from one an
//! operator's own feed drew. The `zond:` namespace is refused to a catalogue
//! read from outside, which is the authoring path the reservation is for.
//!
//! ## The shipped one
//!
//! `assets/cve/seed.toml`: a hand-picked set of well-known, network-reachable
//! vulnerabilities. A starting corpus and not a complete one. Each entry matches
//! a service CPE whose vendor and product equal its own and whose version
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
use std::io::BufRead;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::model::confidence::Confidence;
use crate::model::finding::{DetectionClass, DetectionId, Excerpt, Finding, Reference, Version};
use crate::model::host::Host;
use crate::model::port::Protocol;
use crate::record::wire;
use crate::report::ScanReport;
use crate::version::version_cmp;

/// The reserved identity the engine's built-in correlator stamps on every finding
/// it produces, so a report can say exactly what concluded a vulnerability. A
/// third-party detection may not claim the `zond:` namespace.
const CORRELATOR_ID: &str = "zond:cve-kev";

/// The prefix a catalogue read from outside this crate may not claim.
const RESERVED_PREFIX: &str = "zond:";

/// The shipped seed's version, carried on every finding it produces.
const SEED_VERSION: Version = Version::new(0, 1, 0);

/// Why a catalogue could not be read.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum CatalogueError {
    /// The bytes could not be read.
    #[error("the catalogue could not be read: {0}")]
    Io(#[from] std::io::Error),

    /// The document is not a catalogue this engine understands.
    #[error("the catalogue is malformed: {0}")]
    Malformed(String),

    /// The document names itself in the namespace this engine reserves.
    ///
    /// A report says which detection concluded a finding, and `zond:` is how it
    /// says the engine's own correlator did. A catalogue somebody else wrote
    /// claiming that prefix would make its findings indistinguishable from the
    /// shipped seed's, which is the whole thing the identity exists to answer.
    #[error("a catalogue may not name itself '{id}': '{RESERVED_PREFIX}' is reserved")]
    ReservedId {
        /// What the document called itself.
        id: String,
    },

    /// The document's `version` is not `major.minor.patch`.
    #[error("'{version}' is not a version: expected major.minor.patch")]
    UnreadableVersion {
        /// What the document called its version.
        version: String,
    },
}

/// Correlates a finished host's services against the known-vulnerability dataset,
/// recording a [`Finding`] on each port whose software an entry matches.
///
/// Reads each port's service CPE, matches vendor, product and version against the
/// dataset, and hands each match back to the port it concerns. Idempotent: a
/// finding deduplicates by claim, so a re-run corroborates rather than doubles.
///
/// A scan runs this as its own step, after the service pass and before the
/// report is built. It is public because it is worth running anywhere a host
/// carries a CPE, which includes a host that came out of a file rather than off
/// a network: an archived report correlates against today's dataset without
/// rescanning anything.
///
/// ```
/// use zond_engine::model::host::Host;
/// use zond_engine::model::port::{Port, PortState, Protocol, Service};
///
/// let mut host = Host::new("192.0.2.1".parse().unwrap());
/// let service = Service::new("http", 90).with_cpe("cpe:/a:apache:http_server:2.4.49");
/// host.add_port(Port::new(80, Protocol::Tcp, PortState::Open).with_service(service));
///
/// zond_engine::cve::correlate(&mut host);
///
/// let port = host.ports().find(|port| port.number() == 80).unwrap();
/// assert!(port.findings().any(|finding| finding.detection().id() == "zond:cve-kev"));
/// ```
pub fn correlate(host: &mut Host) {
    correlate_with(host, Catalogue::embedded());
}

/// [`correlate`], against a catalogue the caller supplied.
///
/// The call for anybody whose vulnerability data moves faster than this crate's
/// releases, which is everybody: a refreshed KEV dump, or the advisory feed an
/// organisation already keeps. Every finding is stamped with `catalogue`'s
/// identity and version, so a report says which dataset drew it.
///
/// ```
/// use std::io::Cursor;
/// use zond_engine::cve::Catalogue;
/// use zond_engine::model::host::Host;
/// use zond_engine::model::port::{Port, PortState, Protocol, Service};
///
/// let document = r#"
/// id = "acme:advisories"
/// version = "2026.8.30"
///
/// [[vulnerability]]
/// cve      = "CVE-2021-41773"
/// title    = "Apache HTTP Server path traversal and RCE"
/// severity = "critical"
/// vendor   = "apache"
/// product  = "http_server"
/// affected = "== 2.4.49"
/// "#;
///
/// let catalogue = Catalogue::read(&mut Cursor::new(document))?;
///
/// let mut host = Host::new("192.0.2.1".parse().unwrap());
/// let service = Service::new("http", 90).with_cpe("cpe:/a:apache:http_server:2.4.49");
/// host.add_port(Port::new(80, Protocol::Tcp, PortState::Open).with_service(service));
///
/// zond_engine::cve::correlate_with(&mut host, &catalogue);
///
/// let port = host.ports().find(|port| port.number() == 80).unwrap();
/// assert!(port.findings().any(|finding| finding.detection().id() == "acme:advisories"));
/// # Ok::<(), zond_engine::cve::CatalogueError>(())
/// ```
pub fn correlate_with(host: &mut Host, catalogue: &Catalogue) {
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
                .flat_map(|cpe| catalogue.findings_for(cpe))
                .map(move |finding| (number, protocol, finding))
                .collect::<Vec<_>>()
        })
        .collect();

    for (number, protocol, finding) in hits {
        host.add_port_finding(number, protocol, finding);
    }
}

/// [`correlate_with`], over every host in a finished report.
///
/// The call for a caller whose vulnerability data is their own. A scan
/// correlates against [`Catalogue::embedded`] as it runs, because that is the
/// only catalogue it has; this is how a report gets joined against a feed the
/// operator keeps, without rescanning anything.
///
/// Findings deduplicate by claim and each carries the catalogue that drew it, so
/// a report joined against two datasets says so rather than double-counting.
///
/// ```no_run
/// use std::fs::File;
/// use std::io::BufReader;
/// use zond_engine::cve::{self, Catalogue};
/// # fn example(report: &mut zond_engine::ScanReport) -> Result<(), Box<dyn std::error::Error>> {
/// let mut feed = BufReader::new(File::open("advisories.toml")?);
/// cve::correlate_report(report, &Catalogue::read(&mut feed)?);
/// # Ok(())
/// # }
/// ```
pub fn correlate_report(report: &mut ScanReport, catalogue: &Catalogue) {
    for host in report.hosts_mut() {
        correlate_with(host, catalogue);
    }
}

/// A set of known vulnerabilities, keyed by the software each affects.
///
/// [`embedded`](Self::embedded) is the one this crate ships and
/// [`read`](Self::read) takes anybody else's. See the
/// [module documentation](self) for why this is a value rather than a constant.
///
/// A catalogue names itself and its version, and both travel onto every finding
/// it produces, because "which dataset said this" is a question a report has to
/// be able to answer once more than one dataset exists.
#[derive(Debug, Clone)]
pub struct Catalogue {
    id: String,
    version: Version,
    content_hash: String,
    vulnerability: Vec<Vulnerability>,
}

impl Catalogue {
    /// The catalogue this crate ships, parsed once on first use.
    ///
    /// A starting corpus rather than a complete one; see the
    /// [module documentation](self).
    pub fn embedded() -> &'static Self {
        static EMBEDDED: OnceLock<Catalogue> = OnceLock::new();
        EMBEDDED.get_or_init(|| {
            const SOURCE: &str = include_str!("../assets/cve/seed.toml");

            let document: CatalogueDocument =
                toml::from_str(SOURCE).expect("the embedded CVE seed is valid TOML");

            Catalogue {
                id: CORRELATOR_ID.to_string(),
                version: SEED_VERSION,
                content_hash: content_hash(SOURCE.as_bytes()),
                vulnerability: document.vulnerability,
            }
        })
    }

    /// Reads a catalogue from a TOML document.
    ///
    /// Takes a reader rather than a path, as every other reading surface in this
    /// crate does: where the bytes come from is the caller's business.
    ///
    /// The document names itself in `id` and `version`, and those reach every
    /// finding it produces. Its content hash is computed here from the bytes, so
    /// two runs against the same feed are traceable to the same document and a
    /// refreshed one is visibly different.
    ///
    /// # Errors
    ///
    /// [`CatalogueError::Malformed`] for a document this does not understand,
    /// [`CatalogueError::UnreadableVersion`] for a version that is not
    /// `major.minor.patch`, and [`CatalogueError::ReservedId`] for one naming
    /// itself in this engine's own namespace.
    pub fn read(input: &mut dyn BufRead) -> Result<Self, CatalogueError> {
        let mut source = String::new();
        input.read_to_string(&mut source)?;

        let document: CatalogueDocument = toml::from_str(&source)
            .map_err(|error| CatalogueError::Malformed(error.to_string()))?;

        let id = document
            .id
            .ok_or_else(|| CatalogueError::Malformed("the document names no 'id'".to_string()))?;
        if id.starts_with(RESERVED_PREFIX) {
            return Err(CatalogueError::ReservedId { id });
        }

        let version = document.version.ok_or_else(|| {
            CatalogueError::Malformed("the document names no 'version'".to_string())
        })?;
        let parsed =
            Version::parse(&version).ok_or(CatalogueError::UnreadableVersion { version })?;

        Ok(Self {
            id,
            version: parsed,
            content_hash: content_hash(source.as_bytes()),
            vulnerability: document.vulnerability,
        })
    }

    /// What a finding from this catalogue says produced it.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The version this catalogue names itself at.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The digest of the bytes this catalogue was read from, as hex.
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    /// How many vulnerabilities it holds.
    pub fn len(&self) -> usize {
        self.vulnerability.len()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.vulnerability.is_empty()
    }

    /// Every finding this catalogue has for a service CPE.
    fn findings_for(&self, cpe: &str) -> Vec<Finding> {
        let Some(parsed) = Cpe::parse(cpe) else {
            return Vec::new();
        };
        self.vulnerability
            .iter()
            .filter(|vulnerability| vulnerability.matches(&parsed))
            .filter_map(|vulnerability| vulnerability.to_finding(cpe, self))
            .collect()
    }
}

/// A catalogue as a document holds it.
#[derive(Debug, Default, Deserialize)]
struct CatalogueDocument {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    vulnerability: Vec<Vulnerability>,
}

/// The SHA-256 of a catalogue's bytes, as lowercase hex.
///
/// Computed rather than declared, so a document cannot claim to be a version of
/// itself it is not.
fn content_hash(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut hex = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
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
    fn to_finding(&self, cpe: &str, catalogue: &Catalogue) -> Option<Finding> {
        let severity = wire::severity(&self.severity)?;
        let detection = DetectionId::new(
            catalogue.id.clone(),
            catalogue.version,
            catalogue.content_hash.clone(),
        )
        .ok()?;

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
        assert!(!Catalogue::embedded().vulnerability.is_empty());
    }

    #[test]
    fn a_matching_cpe_yields_a_probable_finding_a_safe_version_does_not() {
        // Apache 2.4.49 is the vulnerable build; 2.4.51 carries the fix.
        let hits = Catalogue::embedded().findings_for("cpe:/a:apache:http_server:2.4.49");
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
            Catalogue::embedded()
                .findings_for("cpe:/a:apache:http_server:2.4.51")
                .is_empty(),
            "the fixed version is not reported"
        );
        assert!(
            Catalogue::embedded()
                .findings_for("cpe:/a:nginx:nginx:1.24.0")
                .is_empty(),
            "an unrelated product does not match"
        );

        // The curated identities fire against the shapes the corpus actually
        // emits: OpenSSH banners carry a `p` suffix, and vsftpd is an exact match.
        assert_eq!(
            Catalogue::embedded()
                .findings_for("cpe:/a:openbsd:openssh:9.6p1")
                .len(),
            1
        );
        assert!(
            Catalogue::embedded()
                .findings_for("cpe:/a:openbsd:openssh:9.8p1")
                .is_empty(),
            "the fixed OpenSSH release is not reported"
        );
        assert_eq!(
            Catalogue::embedded()
                .findings_for("cpe:/a:vsftpd_project:vsftpd:2.3.4")
                .len(),
            1
        );
        assert!(
            Catalogue::embedded()
                .findings_for("cpe:/a:vsftpd_project:vsftpd:3.0.5")
                .is_empty()
        );
    }

    /// A caller's own feed is read, stamped onto its findings, and told apart
    /// from the shipped seed's by every field a report carries.
    #[test]
    fn a_catalogue_read_from_outside_stamps_its_own_identity_on_what_it_finds() {
        use crate::model::host::Host;
        use crate::model::port::{Port, PortState, Service};
        use std::io::Cursor;

        let document = r#"
id = "acme:advisories"
version = "3.2.1"

[[vulnerability]]
cve      = "CVE-2021-41773"
title    = "Apache HTTP Server path traversal and RCE"
severity = "critical"
vendor   = "apache"
product  = "http_server"
affected = "== 2.4.49"
"#;

        let catalogue =
            Catalogue::read(&mut Cursor::new(document)).expect("a well-formed catalogue");
        assert_eq!(catalogue.id(), "acme:advisories");
        assert_eq!(catalogue.version(), Version::new(3, 2, 1));
        assert_eq!(catalogue.len(), 1);

        let mut host = Host::new("192.0.2.1".parse().expect("an address"));
        let service = Service::new("http", 90).with_cpe("cpe:/a:apache:http_server:2.4.49");
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Open).with_service(service));

        correlate_with(&mut host, &catalogue);

        let port = host
            .ports()
            .find(|port| port.number() == 80)
            .expect("the port survives");
        let finding = port.findings().next().expect("the catalogue matched");

        assert_eq!(finding.detection().id(), "acme:advisories");
        assert_eq!(finding.detection().version(), Version::new(3, 2, 1));
        assert_eq!(
            finding.detection().content_hash(),
            catalogue.content_hash(),
            "the finding names the bytes it was drawn from"
        );
        assert_ne!(
            catalogue.content_hash(),
            Catalogue::embedded().content_hash(),
            "two catalogues are two documents"
        );
    }

    /// A report joined against a second catalogue keeps both sets of findings,
    /// each naming the dataset that drew it. That is the whole reason the
    /// identity travels: a report says which feed concluded what.
    #[test]
    fn a_report_correlated_against_a_second_catalogue_carries_both_attributions() {
        use crate::model::host::Host;
        use crate::model::port::{Port, PortState, Service};
        use crate::report::ScanReport;
        use std::io::Cursor;

        let document = r#"
id = "acme:advisories"
version = "3.2.1"

[[vulnerability]]
cve      = "CVE-2021-41773"
title    = "Apache, as our own analysts wrote it up"
severity = "high"
vendor   = "apache"
product  = "http_server"
affected = "== 2.4.49"
"#;

        let mut host = Host::new("192.0.2.1".parse().expect("an address"));
        let service = Service::new("http", 90).with_cpe("cpe:/a:apache:http_server:2.4.49");
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Open).with_service(service));
        correlate(&mut host);

        let mut report =
            ScanReport::new(crate::export::fixture::report().phases()[0].clone(), [host]);

        let catalogue =
            Catalogue::read(&mut Cursor::new(document)).expect("a well-formed catalogue");
        correlate_report(&mut report, &catalogue);

        let attributions: Vec<&str> = report
            .hosts()
            .flat_map(|host| host.ports())
            .flat_map(|port| port.findings())
            .map(|finding| finding.detection().id())
            .collect();

        assert!(attributions.contains(&CORRELATOR_ID), "{attributions:?}");
        assert!(
            attributions.contains(&"acme:advisories"),
            "{attributions:?}"
        );
    }

    /// The one namespace a catalogue may not claim, refused where the document
    /// is read because that is the authoring path."""
    #[test]
    fn a_catalogue_may_not_name_itself_in_this_engines_namespace() {
        use std::io::Cursor;

        let document = "id = \"zond:cve-kev\"\nversion = \"1.0.0\"\n";
        let error = Catalogue::read(&mut Cursor::new(document))
            .expect_err("the reserved prefix is refused");

        assert!(
            matches!(&error, CatalogueError::ReservedId { id } if id == "zond:cve-kev"),
            "got {error:?}"
        );
    }

    /// A document that says nothing about itself cannot stamp a finding, so it
    /// is refused rather than given a default nobody chose.
    #[test]
    fn a_catalogue_that_does_not_name_itself_is_refused() {
        use std::io::Cursor;

        for document in [
            "version = \"1.0.0\"\n",
            "id = \"acme:advisories\"\n",
            "id = \"acme:advisories\"\nversion = \"today\"\n",
        ] {
            assert!(
                Catalogue::read(&mut Cursor::new(document)).is_err(),
                "accepted {document:?}"
            );
        }
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
