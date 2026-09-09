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
//! scan to answer, not "what is listening" but "what is listening that I need to
//! fix", from data the engine already produces, with no probe of its own.
//!
//! ## The one number two ways
//!
//! No finding this pass records is certain, and the reason is the case the
//! [two-axis finding](crate::model::finding) was built for: a distribution can
//! backport a security fix without moving the version string, so a
//! version-matched vulnerability is genuinely
//! [`Critical`](crate::model::finding::Severity::Critical) *and* genuinely
//! unsure. The severity says how bad it is if true; the confidence says the match
//! is a version string, not a confirmed exploit. A report that fused the two
//! could not say both.
//!
//! How unsure depends on what the entry actually constrained, and the difference
//! matters more than it looks. An entry naming a version range was checked
//! against the version found, which is [`Confidence::Probable`]. An entry whose
//! `affected` is `*` names a product and no version at all, so it matches a
//! patched installation exactly as readily as a vulnerable one; that is
//! [`Confidence::Weak`], and the excerpt says the version was never in question.
//!
//! The distinction is not academic. A feed like CISA's KEV catalogue carries no
//! version data whatsoever, so every entry converted from it is an unconstrained
//! one. Reporting those at the same confidence as a version match would mean a
//! fully patched server carrying the same finding as a vulnerable one, with
//! nothing in the report to separate them.
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
//! own, a refreshed KEV dump, or the internal advisory feed an enterprise
//! already maintains, for [`correlate_with`].
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
//! is a caller's to run, the library performs no pass a caller did not ask for,
//! and it is idempotent, because a finding deduplicates by claim, so a second run
//! corroborates rather than doubles.

use std::cmp::Ordering;
use std::io::BufRead;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::model::confidence::Confidence;
use crate::model::finding::{
    DetectionClass, DetectionId, Excerpt, Finding, Reference, Severity, Version,
};
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

/// The shipped catalogue's version, carried on every finding it produces.
///
/// Moved to `0.2.0` when the catalogue stopped being five hand-picked entries
/// and became the converted feed beside them. A report from before the change
/// and one from after are distinguishable by it, which is the whole reason a
/// dataset carries a version.
const SEED_VERSION: Version = Version::new(0, 2, 0);

/// The catalogue compiled from `assets/cve/` by `build.rs`: a string pool and
/// the entries that index into it.
///
/// Compiled rather than parsed because the documents are twenty megabytes of
/// TOML and parsing them costs a tenth of a second on the first correlation of
/// every process. See `compile_cve_catalogue` in `build.rs`.
const EMBEDDED_DB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/cve_catalogue.bin"));

/// The most a catalogue document may be.
///
/// A ceiling in the shape [`import::settings`](crate::import::settings) already
/// uses, and for a stronger reason. `read` takes a [`BufRead`] precisely so the
/// bytes can come from a socket, and a CVE catalogue is by definition a feed:
/// fetched from somewhere else, refreshed on a schedule, pointed at by an
/// operator who did not write it. A feed that answers with a stream that does not
/// end would otherwise take the process's memory with it, and `toml::from_str`
/// then takes several times the document again to parse it.
///
/// Sixteen megabytes because the shipped seed is a few kilobytes and a catalogue
/// two thousand times that is a mistake rather than a large feed.
pub const MAX_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;

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

    /// The document was longer than [`MAX_DOCUMENT_BYTES`].
    #[error("the catalogue is longer than the {limit} byte limit")]
    TooLarge {
        /// The limit it passed.
        limit: u64,
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
    /// Every distinct string the entries below are built from, written once.
    ///
    /// A real feed repeats itself enormously: seventy-two thousand entries are
    /// backed by eight thousand advisories, because NVD states one entry per
    /// affected version rather than one per vulnerability, and every one of them
    /// carries the same title. Six and a half thousand distinct titles, a
    /// hundred and sixty-one distinct products.
    ///
    /// Stored flat with the entries holding indices, which is what makes the
    /// shipped catalogue two megabytes rather than sixteen. The saving is the
    /// same in memory as on disk, so a scan pays it once either way.
    pool: Vec<String>,
    vulnerability: Vec<Entry>,
}

/// One catalogue entry, as indices into [`Catalogue::pool`].
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
struct Entry {
    cve: u32,
    title: u32,
    severity: u32,
    vendor: u32,
    product: u32,
    affected: u32,
    cwe: Option<u32>,
    remediation: Option<u32>,
}

/// One entry with its strings resolved, which is what everything that reads a
/// catalogue actually wants.
///
/// Borrowed from the pool rather than copied out of it: an entry is looked at
/// once per matching CPE and never outlives the catalogue it came from.
struct Vulnerability<'a> {
    cve: &'a str,
    title: &'a str,
    severity: &'a str,
    vendor: &'a str,
    product: &'a str,
    affected: &'a str,
    cwe: Option<u32>,
    remediation: Option<&'a str>,
}

/// Builds a pool and hands back indices, so a string written a thousand times is
/// stored once.
#[derive(Default)]
struct Interner {
    pool: Vec<String>,
    seen: std::collections::HashMap<String, u32>,
}

impl Interner {
    fn intern(&mut self, value: &str) -> u32 {
        if let Some(index) = self.seen.get(value) {
            return *index;
        }
        let index = self.pool.len() as u32;
        self.pool.push(value.to_string());
        self.seen.insert(value.to_string(), index);
        index
    }

    fn maybe(&mut self, value: Option<&str>) -> Option<u32> {
        value.map(|value| self.intern(value))
    }
}

impl Catalogue {
    /// The catalogue this crate ships, parsed once on first use.
    ///
    /// A starting corpus rather than a complete one; see the
    /// [module documentation](self).
    pub fn embedded() -> &'static Self {
        static EMBEDDED: OnceLock<Catalogue> = OnceLock::new();
        EMBEDDED.get_or_init(|| {
            let (pool, vulnerability) = bincode::deserialize(EMBEDDED_DB)
                .expect("the embedded CVE catalogue is the shape build.rs writes");

            Catalogue {
                id: CORRELATOR_ID.to_string(),
                version: SEED_VERSION,
                // Of the compiled bytes rather than of the documents they came
                // from. It answers the same question — which dataset concluded
                // this — and it is the only thing the running process has.
                content_hash: content_hash(EMBEDDED_DB),
                pool,
                vulnerability,
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
    /// `major.minor.patch`, [`CatalogueError::ReservedId`] for one naming itself
    /// in this engine's own namespace, and [`CatalogueError::TooLarge`] for one
    /// past [`MAX_DOCUMENT_BYTES`].
    pub fn read(input: &mut dyn BufRead) -> Result<Self, CatalogueError> {
        // Bounded before the read rather than measured after: a feed with no end
        // must not be held in memory to discover it had none. One byte past the
        // ceiling is read so a document exactly at it is still accepted.
        let mut source = String::new();
        let read = {
            use std::io::Read as _;
            std::io::Read::take(input, MAX_DOCUMENT_BYTES.saturating_add(1))
                .read_to_string(&mut source)?
        };
        if read as u64 > MAX_DOCUMENT_BYTES {
            return Err(CatalogueError::TooLarge {
                limit: MAX_DOCUMENT_BYTES,
            });
        }

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
        let parsed = version
            .parse()
            .map_err(|_| CatalogueError::UnreadableVersion { version })?;

        let (pool, vulnerability) = intern_all(&document.vulnerability);
        Ok(Self {
            id,
            version: parsed,
            content_hash: content_hash(source.as_bytes()),
            pool,
            vulnerability,
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

    /// One entry with its strings resolved.
    fn view(&self, entry: &Entry) -> Vulnerability<'_> {
        let at = |index: u32| self.pool[index as usize].as_str();
        Vulnerability {
            cve: at(entry.cve),
            title: at(entry.title),
            severity: at(entry.severity),
            vendor: at(entry.vendor),
            product: at(entry.product),
            affected: at(entry.affected),
            cwe: entry.cwe,
            remediation: entry.remediation.map(at),
        }
    }

    /// Every finding this catalogue has for a service CPE.
    fn findings_for(&self, cpe: &str) -> Vec<Finding> {
        let Some(parsed) = Cpe::parse(cpe) else {
            return Vec::new();
        };

        let mut matched: Vec<Vulnerability<'_>> = self
            .vulnerability
            .iter()
            .map(|entry| self.view(entry))
            .filter(|vulnerability| vulnerability.matches(&parsed))
            .collect();

        // Worst first, and by identifier where two are equally bad, so the
        // entries a summary names are the ones worth naming and two runs over
        // the same catalogue name the same ones.
        matched.sort_by(|a, b| {
            wire::severity(b.severity)
                .cmp(&wire::severity(a.severity))
                .then_with(|| a.cve.cmp(b.cve))
        });

        // One vulnerability, however many ways it is stated. A CVE with disjoint
        // ranges is two entries and matches through whichever range covers the
        // version found, and a report saying a host has nineteen when eighteen
        // identifiers back them is a report a reader cannot reconcile. Adjacent
        // after the sort, since equal severity orders by identifier.
        matched.dedup_by(|a, b| a.cve == b.cve);

        // Split before summarising, because the two halves are different claims
        // and a summary may not average them. An entry naming a version range was
        // checked against the version found; one naming the product at any
        // version was not, and matches a patched host just as readily. Folding
        // them together would report the second at the first's confidence, which
        // is the distinction the whole two-axis model exists to keep.
        let (checked, unchecked): (Vec<_>, Vec<_>) = matched
            .into_iter()
            .partition(|vulnerability| vulnerability.constrains_the_version());

        [checked, unchecked]
            .into_iter()
            .filter_map(|group| match group.as_slice() {
                [] => None,
                // One match is its own best description. This is the whole of
                // what a hand-written catalogue or a converted KEV produces for
                // most products, and it reads exactly as it did before
                // summarising existed.
                [only] => only.to_finding(cpe, self),
                many => self.summary_of(cpe, &parsed, many),
            })
            .collect()
    }

    /// The single finding a run of matches produces.
    ///
    /// A version-matched CPE against a real feed draws dozens: Apache 2.4.49 has
    /// sixty-eight, MySQL 8.0.32 a hundred and eighteen. Recorded one by one they
    /// are not a report, they are a wall — and they push past
    /// [`MAX_FINDINGS_PER_SUBJECT`](crate::model::finding::MAX_FINDINGS_PER_SUBJECT)
    /// on a host running a handful of identifiable services, at which point the
    /// ones that survive are decided by arrival order rather than by severity.
    ///
    /// So they arrive as one finding that says how many and how bad, carrying
    /// the worst of them as references. A reader scanning a port table sees one
    /// row per affected service; a reader with the report open has the
    /// identifiers.
    fn summary_of(
        &self,
        cpe: &str,
        parsed: &Cpe,
        matched: &[Vulnerability<'_>],
    ) -> Option<Finding> {
        let worst = matched.first()?;
        let severity = wire::severity(worst.severity)?;
        let detection =
            DetectionId::new(self.id.clone(), self.version, self.content_hash.clone()).ok()?;

        // Uniform by construction: `findings_for` splits on this before calling
        // here, so every entry in the group makes the same kind of claim and the
        // summary can state it without qualifying.
        let checked = worst.constrains_the_version();
        let confidence = match checked {
            true => Confidence::Probable,
            false => Confidence::Weak,
        };

        let counted = |wanted: Severity| {
            matched
                .iter()
                .filter(|entry| wire::severity(entry.severity) == Some(wanted))
                .count()
        };
        let critical = counted(Severity::Critical);
        let high = counted(Severity::High);

        // Named the way the port table names it — `tomcat 9.0.71`, not
        // `apache tomcat` — so a reader matching the row to the port above it
        // does not have to translate. The vendor is in the CPE the excerpt
        // quotes, for anyone who needs to tell two products of the same name
        // apart.
        let software = match parsed.version.is_empty() {
            true => worst.product.to_string(),
            false => format!("{} {}", worst.product, parsed.version),
        };
        let title = format!("{software} has {} known vulnerabilities", matched.len());

        let named: Vec<&str> = matched
            .iter()
            .take(MAX_NAMED_IN_EXCERPT)
            .map(|entry| entry.cve)
            .collect();
        let excerpt = match checked {
            true => format!(
                "{cpe} matches {} known vulnerabilities, {critical} critical and {high} high. The worst are {}",
                matched.len(),
                named.join(", ")
            ),
            false => format!(
                "{cpe} matches {} entries naming this software at any version: the version found was not checked against anything. They include {}",
                matched.len(),
                named.join(", ")
            ),
        };

        let mut finding = Finding::new(
            detection,
            title,
            severity,
            confidence,
            DetectionClass::Passive,
        )
        .ok()?
        .with_excerpt(Excerpt::new(excerpt));

        // Every one of them, because this is the record: a summary that says
        // forty-four and cites twenty is a report a reader cannot reconcile, and
        // the presentation is the right place to decide how many of them fit on
        // a line. The severity sort above still decides the order, so a front
        // end showing the first few shows the worst few.
        for entry in matched.iter() {
            if let Some(reference) = Reference::cve(entry.cve) {
                finding = finding.with_reference(reference);
            }
        }
        if let Some(cwe) = worst.cwe {
            finding = finding.with_reference(Reference::cwe(cwe));
        }
        Some(finding)
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
    vulnerability: Vec<DocumentEntry>,
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

/// How many identifiers a summary spells out in its excerpt.
///
/// Fewer than it carries as references: the excerpt is a sentence somebody
/// reads, and a sentence listing twenty identifiers is not one.
const MAX_NAMED_IN_EXCERPT: usize = 3;

/// Turns the entries a document states into a pool and a list of indices.
fn intern_all(entries: &[DocumentEntry]) -> (Vec<String>, Vec<Entry>) {
    let mut interner = Interner::default();
    let interned = entries
        .iter()
        .map(|entry| Entry {
            cve: interner.intern(&entry.cve),
            title: interner.intern(&entry.title),
            severity: interner.intern(&entry.severity),
            vendor: interner.intern(&entry.vendor),
            product: interner.intern(&entry.product),
            affected: interner.intern(&entry.affected),
            cwe: entry.cwe,
            remediation: interner.maybe(entry.remediation.as_deref()),
        })
        .collect();
    (interner.pool, interned)
}

/// One known vulnerability as a document states it, before interning.
#[derive(Debug, Clone, Deserialize)]
struct DocumentEntry {
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

impl Vulnerability<'_> {
    /// Whether this vulnerability names `cpe`'s software at an affected version.
    fn matches(&self, cpe: &Cpe) -> bool {
        self.vendor.eq_ignore_ascii_case(&cpe.vendor)
            && self.product.eq_ignore_ascii_case(&cpe.product)
            && version_matches(&cpe.version, self.affected)
    }

    /// Whether this entry constrains the version at all, or names a product and
    /// leaves the version open.
    ///
    /// Read off `affected` rather than stored beside it, so an entry cannot
    /// claim to have checked something it did not. `*` is the grammar's own way
    /// of saying "any version", which is what a feed carrying no version data
    /// converts to.
    fn constrains_the_version(&self) -> bool {
        self.affected.trim() != "*"
    }

    /// The finding this vulnerability produces for a matched `cpe`, or [`None`]
    /// if the entry is malformed: an unknown severity, a bad CVE identifier.
    fn to_finding(&self, cpe: &str, catalogue: &Catalogue) -> Option<Finding> {
        let severity = wire::severity(self.severity)?;
        let detection = DetectionId::new(
            catalogue.id.clone(),
            catalogue.version,
            catalogue.content_hash.clone(),
        )
        .ok()?;

        // An entry that named no version matched on the software alone, and a
        // patched installation answers that description as well as a vulnerable
        // one does. The confidence carries the difference, and the excerpt says
        // it in words for a reader who is not reading confidences.
        let (confidence, excerpt) = match self.constrains_the_version() {
            true => (
                Confidence::Probable,
                format!(
                    "{cpe} matches {} {} {}",
                    self.vendor, self.product, self.affected
                ),
            ),
            false => (
                Confidence::Weak,
                format!(
                    "{cpe} is {} {}, which this entry names at any version: \
                     the version found was not checked against anything",
                    self.vendor, self.product
                ),
            ),
        };

        let mut finding = Finding::new(
            detection,
            self.title,
            severity,
            confidence,
            DetectionClass::Passive,
        )
        .ok()?
        .with_reference(Reference::cve(self.cve)?)
        .with_excerpt(Excerpt::new(excerpt));

        if let Some(cwe) = self.cwe {
            finding = finding.with_reference(Reference::cwe(cwe));
        }
        if let Some(remediation) = self.remediation {
            finding = finding.with_remediation(remediation);
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
        let _part = fields.next()?; // a, o or h: application, os, hardware
        let vendor = fields.next()?;
        let product = fields.next()?;
        let version = fields.next().unwrap_or("");

        // The 2.3 form puts a patch level in its own `update` field, where the
        // URI form and every service banner run it onto the version: OpenSSH is
        // `9.6:p1` in one and `9.6p1` in the other. Joined here so the two
        // spellings of one release compare equal, since a predicate is written
        // against whichever the author happened to have.
        //
        // `*` is "any" and `-` is "not applicable" in this grammar, and neither
        // is a patch level.
        let update = fields
            .next()
            .filter(|value| !value.is_empty() && *value != "*" && *value != "-");

        Some(Self {
            vendor: vendor.to_ascii_lowercase(),
            product: product.to_ascii_lowercase(),
            version: match update {
                Some(update) => format!("{version}{update}"),
                None => version.to_string(),
            },
        })
    }
}

/// Whether `version` satisfies `predicate`: a comma-joined list of
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
///
/// The ordering is [`version_cmp`]'s, which reads a hyphen two ways: a
/// pre-release precedes the version it is a candidate for and a package
/// revision follows it. Both matter to a bound written `<1.0.0`, and they
/// matter in opposite directions.
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
    use std::collections::BTreeSet;

    /// Every product a scan can put a version to either has entries here or is
    /// listed below with the reason it does not.
    ///
    /// Fourteen names were on this list until the catalogue was regenerated on
    /// 2026-09-09 and are not any more, which is what the second test below is
    /// for: a stale exemption is as quiet a defect as the gap it was recording.
    ///
    /// The join is `vendor:product` and a mismatch is silent in both directions:
    /// a scan identifies the software, the catalogue holds records for it, and
    /// nothing correlates because the two spell it differently. That is how
    /// `microsoft:iis` shipped, emitted by twenty-seven rules and matching a
    /// vocabulary NVD has never used.
    ///
    /// The list is checked in both directions. An entry that gains rows has to
    /// be removed from it, which is what turns a regeneration into a visible
    /// event rather than something nobody notices.
    const UNCOVERED: &[(&str, &str)] = &[
        // Nothing has published a record against these names, under any spelling
        // that could be found. The corpus identifies the software and there is
        // no vulnerability data to join to.
        ("avocent:dsview", "no records in NVD"),
        ("darkhttpd_project:darkhttpd", "no records in NVD"),
        ("mcafee:webshield", "no records in NVD"),
        ("novell:netware_enterprise_web_server", "no records in NVD"),
        ("zaphoyd:websocketpp", "no records in NVD"),
        // The separator arrived URL-encoded from the imported corpus and no
        // spelling of it can be queried. The product is the Ripple20 stack.
        (
            "treck:tcp%2fip",
            "import artifact in the identifier, and no reachable records",
        ),
    ];

    /// The distinct `vendor:product` the shipped catalogue holds rows for.
    fn covered() -> BTreeSet<String> {
        let catalogue = Catalogue::embedded();
        catalogue
            .vulnerability
            .iter()
            .map(|entry| {
                format!(
                    "{}:{}",
                    catalogue.pool[entry.vendor as usize], catalogue.pool[entry.product as usize]
                )
            })
            .collect()
    }

    #[test]
    fn every_versioned_product_is_covered_or_listed() {
        let covered = covered();
        let listed: BTreeSet<&str> = UNCOVERED.iter().map(|(key, _)| *key).collect();

        let unexplained: Vec<&String> = crate::fingerprint::SignatureDb::global()
            .versioned_products()
            .iter()
            .filter(|key| !covered.contains(*key) && !listed.contains(key.as_str()))
            .collect();

        assert!(
            unexplained.is_empty(),
            "a scan can put a version to these and the catalogue has no row for any of them: \
             {unexplained:?}. Regenerate the catalogue, correct the identifier, or add it to \
             UNCOVERED with the reason."
        );
    }

    /// And the other direction, so the list cannot outlive what put it there.
    #[test]
    fn nothing_listed_as_uncovered_is_covered() {
        let covered = covered();
        let stale: Vec<&str> = UNCOVERED
            .iter()
            .map(|(key, _)| *key)
            .filter(|key| covered.contains(*key))
            .collect();

        assert!(
            stale.is_empty(),
            "these are listed as having no rows and the catalogue has rows for them: {stale:?}. \
             Remove them from UNCOVERED."
        );
    }

    /// The 2.3 grammar puts a patch level in a field of its own and the URI
    /// form runs it onto the version, so one release has two spellings. A
    /// predicate is written against whichever the author had in front of them,
    /// and the two have to compare equal.
    #[test]
    fn the_two_cpe_forms_of_one_release_read_the_same_version() {
        let uri = Cpe::parse("cpe:/a:openbsd:openssh:9.6p1").expect("the URI form");
        let two_three =
            Cpe::parse("cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*").expect("the 2.3 form");

        assert_eq!(uri.version, two_three.version);
        assert_eq!(two_three.version, "9.6p1");
    }

    /// `*` is "any" and `-` is "not applicable" in that grammar, and neither is
    /// a patch level to run onto the end of a version.
    #[test]
    fn an_unset_update_field_is_not_appended() {
        for cpe in [
            "cpe:2.3:a:nginx:nginx:1.21.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:nginx:nginx:1.21.0:-:*:*:*:*:*:*",
            "cpe:2.3:a:nginx:nginx:1.21.0",
        ] {
            assert_eq!(Cpe::parse(cpe).expect("parses").version, "1.21.0", "{cpe}");
        }
    }

    /// The correlator's end of T2: a pre-release is below the version it is a
    /// candidate for, so a bound written `<1.0.0` catches it.
    #[test]
    fn a_pre_release_satisfies_a_bound_written_against_its_release() {
        assert!(version_matches("1.0.0-rc1", "<1.0.0"));
        assert!(version_matches("0.9.9", "<1.0.0"));
        assert!(!version_matches("1.0.0", "<1.0.0"));

        // And a distribution rebuild is a later build, not an earlier one.
        assert!(!version_matches("1.21.0-1ubuntu2", "<1.21.0"));
    }
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

    /// The rule that makes an unversioned feed safe to load, tested where it
    /// lives rather than only where KEV exercises it.
    ///
    /// An entry whose `affected` is `*` matched on the software and checked no
    /// version, so it describes a patched installation exactly as well as a
    /// vulnerable one. Reporting it beside a version match, at the same
    /// Many matches against one service become one finding, not many.
    ///
    /// A real feed gives a version-matched CPE dozens of entries. Recorded one by
    /// one they crowd out everything else a scan found and, past
    /// `MAX_FINDINGS_PER_SUBJECT`, the survivors are chosen by arrival order
    /// rather than by severity. The summary says how many and how bad, and
    /// carries the identifiers.
    #[test]
    fn many_matches_become_one_finding_that_counts_them() {
        let mut document = String::from("id = \"acme:advisories\"\nversion = \"1.0.0\"\n");
        // One critical, one high, and twenty-four mediums behind them.
        for (index, severity) in std::iter::once("critical")
            .chain(std::iter::once("high"))
            .chain(std::iter::repeat_n("medium", 24))
            .enumerate()
        {
            document.push_str(&format!(
                "\n[[vulnerability]]\ncve = \"CVE-2024-{:04}\"\ntitle = \"Something {index}\"\n\
                 severity = \"{severity}\"\nvendor = \"apache\"\nproduct = \"tomcat\"\n\
                 affected = \"== 9.0.71\"\n",
                index + 1
            ));
        }
        let catalogue = Catalogue::read(&mut document.as_bytes()).expect("a valid document");

        let hits = catalogue.findings_for("cpe:/a:apache:tomcat:9.0.71");
        assert_eq!(hits.len(), 1, "twenty-six entries, one finding");

        let summary = &hits[0];
        assert_eq!(
            summary.title(),
            "tomcat 9.0.71 has 26 known vulnerabilities"
        );
        assert_eq!(
            summary.severity(),
            Severity::Critical,
            "the summary is as bad as the worst of them"
        );
        assert!(summary.excerpt().as_str().contains("1 critical and 1 high"));

        // Every entry is cited, so a reader can reconcile the count in the title
        // against the references beside it.
        let cves: Vec<&str> = summary
            .references()
            .filter_map(|reference| match reference {
                Reference::Cve(id) => Some(id.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(cves.len(), 26, "the title says 26 and 26 are cited");
        assert!(cves.contains(&"CVE-2024-0001"), "the critical one is named");
        assert!(cves.contains(&"CVE-2024-0002"), "and the high one");
    }

    /// The split survives summarising. A service matched by many entries of both
    /// kinds gets one finding per kind, never one averaging them.
    #[test]
    fn a_summary_never_averages_the_two_kinds_of_claim() {
        let mut document = String::from("id = \"acme:advisories\"\nversion = \"1.0.0\"\n");
        for (index, affected) in ["== 2.4.49", "== 2.4.49", "*", "*"].iter().enumerate() {
            document.push_str(&format!(
                "\n[[vulnerability]]\ncve = \"CVE-2021-{:04}\"\ntitle = \"Entry {index}\"\n\
                 severity = \"high\"\nvendor = \"apache\"\nproduct = \"http_server\"\n\
                 affected = \"{affected}\"\n",
                index + 1
            ));
        }
        let catalogue = Catalogue::read(&mut document.as_bytes()).expect("a valid document");

        let hits = catalogue.findings_for("cpe:/a:apache:http_server:2.4.49");
        assert_eq!(hits.len(), 2, "one summary per kind of claim");

        let checked = hits
            .iter()
            .find(|finding| finding.confidence() == Confidence::Probable)
            .expect("the version-checked summary");
        assert!(
            checked
                .excerpt()
                .as_str()
                .contains("2 known vulnerabilities")
        );

        let unchecked = hits
            .iter()
            .find(|finding| finding.confidence() == Confidence::Weak)
            .expect("the unchecked summary");
        assert!(
            unchecked.excerpt().as_str().contains("not checked"),
            "a summary of unbounded entries still says the version was never in question"
        );
    }

    /// confidence, would put the two in the same row of a report with nothing to
    /// separate them.
    #[test]
    fn an_entry_that_names_no_version_is_weaker_than_one_that_does() {
        use crate::model::confidence::Confidence;

        let document = r#"
id = "acme:advisories"
version = "1.0.0"

[[vulnerability]]
cve      = "CVE-2021-41773"
title    = "Bounded to the affected releases"
severity = "critical"
vendor   = "apache"
product  = "http_server"
affected = "== 2.4.49"

[[vulnerability]]
cve      = "CVE-2021-44228"
title    = "Named at any version"
severity = "critical"
vendor   = "apache"
product  = "http_server"
affected = "*"
"#;
        let catalogue = Catalogue::read(&mut document.as_bytes()).expect("a valid document");

        // The vulnerable build answers both entries, which is what makes the two
        // comparable: same software, same version, different claims about it.
        let hits = catalogue.findings_for("cpe:/a:apache:http_server:2.4.49");
        assert_eq!(hits.len(), 2);

        let bounded = hits
            .iter()
            .find(|finding| finding.title().contains("Bounded"))
            .expect("the version-bounded entry matched");
        assert_eq!(bounded.confidence(), Confidence::Probable);
        assert!(bounded.excerpt().as_str().contains("2.4.49"));

        let unbounded = hits
            .iter()
            .find(|finding| finding.title().contains("any version"))
            .expect("the unbounded entry matched");
        assert_eq!(unbounded.confidence(), Confidence::Weak);
        assert!(
            unbounded.excerpt().as_str().contains("not checked"),
            "the excerpt has to say the version was never in question"
        );

        // And the patched build answers only the unbounded one, which is the
        // whole reason it cannot be reported as confidently.
        let patched = catalogue.findings_for("cpe:/a:apache:http_server:2.4.62");
        assert_eq!(patched.len(), 1);
        assert_eq!(patched[0].confidence(), Confidence::Weak);
    }

    #[test]
    fn the_embedded_seed_parses_and_is_non_empty() {
        assert!(!Catalogue::embedded().vulnerability.is_empty());
    }

    /// Every CVE identifier the embedded catalogue reports for one CPE.
    fn embedded_cves(cpe: &str) -> Vec<String> {
        Catalogue::embedded()
            .findings_for(cpe)
            .iter()
            .flat_map(|finding| finding.references())
            .filter_map(|reference| match reference {
                Reference::Cve(id) => Some(id.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_matching_cpe_yields_a_probable_finding_a_safe_version_does_not() {
        let hits = Catalogue::embedded().findings_for("cpe:/a:apache:http_server:2.4.49");
        let finding = hits.first().expect("2.4.49 is a vulnerable build");
        assert_eq!(finding.severity(), Severity::Critical);
        assert_eq!(
            finding.confidence(),
            Confidence::Probable,
            "a version match is potentially affected, unverified — never certain"
        );
        assert_eq!(finding.detection().id(), "zond:cve-kev");
        assert!(
            embedded_cves("cpe:/a:apache:http_server:2.4.49")
                .contains(&"CVE-2021-41773".to_string())
        );

        // 2.4.51 carries the fix for that one. It is not a clean build — a real
        // catalogue knows plenty about it — so the claim is the narrow one the
        // version range actually makes, and asserting emptiness here would only
        // hold while the catalogue was five entries long.
        assert!(
            !embedded_cves("cpe:/a:apache:http_server:2.4.51")
                .contains(&"CVE-2021-41773".to_string()),
            "the range stops at 2.4.49 and the fixed build is outside it"
        );
        assert!(
            Catalogue::embedded()
                .findings_for("cpe:/a:nginx:nginx:1.24.0")
                .is_empty(),
            "a vendor nothing is keyed under does not match: nginx is `f5:nginx`"
        );

        // The curated identities fire against the shapes the corpus actually
        // emits: OpenSSH banners carry a `p` suffix, and vsftpd is an exact match.
        // regreSSHion is `>= 8.5, < 9.8`, so it is reported for 9.6p1 and not for
        // 9.8p1. The `p` suffix is the shape the corpus emits and has to compare
        // correctly against a range that carries none.
        assert!(
            embedded_cves("cpe:/a:openbsd:openssh:9.6p1").contains(&"CVE-2024-6387".to_string())
        );
        assert!(
            !embedded_cves("cpe:/a:openbsd:openssh:9.8p1").contains(&"CVE-2024-6387".to_string()),
            "the fixed OpenSSH release is outside the range"
        );

        // The backdoored vsftpd tarball, which is an exact version rather than a
        // range and is the one every CTF host runs.
        assert!(
            embedded_cves("cpe:/a:vsftpd_project:vsftpd:2.3.4")
                .contains(&"CVE-2011-2523".to_string())
        );
        assert!(
            !embedded_cves("cpe:/a:vsftpd_project:vsftpd:3.0.5")
                .contains(&"CVE-2011-2523".to_string())
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
    /// A catalogue is a feed, and `read` takes a reader so the bytes can come off
    /// a socket. The ceiling has to refuse before the read rather than after it,
    /// or a feed with no end is discovered to have none by running out of memory.
    #[test]
    fn a_catalogue_longer_than_the_ceiling_is_refused_without_being_held() {
        use std::io::Cursor;

        // A document one byte over, which is the boundary the `+ 1` in `read` is
        // there to make exact.
        let mut over = String::from("id = \"oversize\"\nversion = \"1.0.0\"\n");
        let filler = MAX_DOCUMENT_BYTES as usize + 1 - over.len();
        over.push_str(&"#".repeat(filler));
        assert_eq!(over.len() as u64, MAX_DOCUMENT_BYTES + 1);

        let error =
            Catalogue::read(&mut Cursor::new(&over)).expect_err("an oversize document is refused");
        assert!(
            matches!(error, CatalogueError::TooLarge { limit } if limit == MAX_DOCUMENT_BYTES),
            "got {error:?}"
        );

        // And one exactly at the ceiling still reads.
        let at = &over[..MAX_DOCUMENT_BYTES as usize];
        assert!(
            Catalogue::read(&mut Cursor::new(at)).is_ok(),
            "a document exactly at the ceiling was refused"
        );
    }

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
